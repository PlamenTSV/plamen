"""Terminal legacy-Claude audit preparation contracts.

These tests deliberately stop at preparation.  The shared driver remains the
only component permitted to launch or sequence an audit.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

import terminal_audit_launch as T


def _tree_bytes(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def _driver(path: Path) -> Path:
    del path
    return Path(T.__file__).with_name("plamen_driver.py")


def _symlink_or_skip(target: str | Path, link: Path, *, directory: bool = False) -> None:
    try:
        os.symlink(target, link, target_is_directory=directory)
    except OSError as exc:
        pytest.skip(f"symlinks unavailable in fixture filesystem: {exc}")


def test_prior_run_seal_is_external_read_only_and_detects_later_drift(tmp_path: Path):
    source = tmp_path / "source"
    scratch = source / ".scratchpad"
    archived = source / ".plamen-stale-snapshots" / "stale-a"
    scratch.mkdir(parents=True)
    archived.mkdir(parents=True)
    (source / "src").mkdir()
    (source / "src" / "Protocol.sol").write_text("contract Protocol {}\n")
    (scratch / "config.json").write_text('{"mode":"thorough"}\n')
    (scratch / "AUDIT_REPORT.md").write_text("prior report\n")
    (archived / "_v2_checkpoint.json").write_text('{"completed":["recon"]}\n')
    before = _tree_bytes(source)

    receipt_path = tmp_path / "receipts" / "prior-evidence.json"
    receipt = T.seal_prior_audit_evidence(source, receipt_path)

    assert _tree_bytes(source) == before
    assert receipt_path.is_file()
    assert receipt["schema_version"] == "plamen.prior-audit-evidence-seal.v1"
    assert receipt["evidence_root_count"] == 2
    assert T.verify_prior_audit_evidence_seal(receipt_path) == ()

    (scratch / "AUDIT_REPORT.md").write_text("changed after seal\n")
    issues = T.verify_prior_audit_evidence_seal(receipt_path)
    assert any("manifest" in issue or "drift" in issue for issue in issues)


def test_seal_receipt_must_be_outside_source_and_never_overwrites(tmp_path: Path):
    source = tmp_path / "source"
    (source / ".scratchpad").mkdir(parents=True)
    (source / ".scratchpad" / "config.json").write_text("{}\n")

    with pytest.raises(T.TerminalAuditPreparationError, match="outside"):
        T.seal_prior_audit_evidence(source, source / "seal.json")

    receipt_path = tmp_path / "seal.json"
    first = T.seal_prior_audit_evidence(source, receipt_path)
    second = T.seal_prior_audit_evidence(source, receipt_path)
    assert first == second
    receipt_path.write_text("{}\n", encoding="utf-8")
    with pytest.raises(T.TerminalAuditPreparationError, match="different"):
        T.seal_prior_audit_evidence(source, receipt_path)


def test_prepare_fresh_isolated_legacy_claude_thorough_run_without_launch(
    tmp_path: Path,
):
    source = tmp_path / "source"
    (source / "contracts").mkdir(parents=True)
    (source / "contracts" / "Protocol.sol").write_text("contract Protocol {}\n")
    (source / ".scratchpad").mkdir()
    (source / ".scratchpad" / "config.json").write_text('{"old":true}\n')
    (source / ".scratchpad" / "old.md").write_text("old findings\n")
    (source / "AUDIT_REPORT.md").write_text("old answer key\n")
    before = _tree_bytes(source)

    workspace = tmp_path / "isolated" / "project"
    seal_path = tmp_path / "receipts" / "prior.json"
    prep_path = tmp_path / "receipts" / "prepared.json"
    driver = _driver(tmp_path / "plamen_driver.py")

    prepared = T.prepare_legacy_claude_run(
        source_project=source,
        workspace_project=workspace,
        prior_evidence_receipt=seal_path,
        preparation_receipt=prep_path,
        driver_path=driver,
        language="evm",
        mode="thorough",
    )

    assert _tree_bytes(source) == before
    assert (workspace / "contracts" / "Protocol.sol").read_bytes() == (
        source / "contracts" / "Protocol.sol"
    ).read_bytes()
    assert not (workspace / "AUDIT_REPORT.md").exists()
    assert not (workspace / ".scratchpad" / "old.md").exists()

    config_path = workspace / ".scratchpad" / "config.json"
    config = json.loads(config_path.read_text(encoding="utf-8"))
    assert config == {
        "claude_exec_mode": "headless",
        "cli_backend": "claude",
        "docs_path": "",
        "language": "evm",
        "mode": "thorough",
        "pipeline": "sc",
        "project_root": str(workspace.resolve()),
        "proven_only": False,
        "scope_file": "",
        "scope_notes": "",
        "scratchpad": str((workspace / ".scratchpad").resolve()),
    }
    assert prepared["config_sha256"] == hashlib.sha256(config_path.read_bytes()).hexdigest()
    assert prepared["fresh_argv"] == [
        prepared["python_executable"],
        str(driver.resolve()),
        "--startup-intent",
        "START_NEW_RUN",
        str(config_path.resolve()),
    ]
    assert prepared["resume_argv"] == [
        prepared["python_executable"],
        str(driver.resolve()),
        "--startup-intent",
        "RESUME_EXISTING",
        str(config_path.resolve()),
    ]
    assert "--fresh" not in prepared["fresh_argv"]
    assert "--fresh" not in prepared["resume_argv"]
    assert prep_path.is_file()
    assert T.verify_preparation_receipt(prep_path) == ()


@pytest.mark.parametrize(
    ("cli_backend", "claude_exec_mode"),
    (("claude", "headless"), ("claude-headless", "headless")),
)
def test_explicit_headless_launch_authority_is_sealed_and_verified(
    tmp_path: Path,
    cli_backend: str,
    claude_exec_mode: str,
) -> None:
    source = tmp_path / "source"
    (source / "contracts").mkdir(parents=True)
    (source / "contracts" / "Protocol.sol").write_text(
        "contract Protocol {}\n", encoding="utf-8"
    )
    workspace = tmp_path / "isolated" / "project"
    receipt = tmp_path / "receipts" / "prepared.json"

    prepared = T.prepare_legacy_claude_run(
        source_project=source,
        workspace_project=workspace,
        prior_evidence_receipt=tmp_path / "receipts" / "prior.json",
        preparation_receipt=receipt,
        driver_path=_driver(tmp_path / "driver.py"),
        language="evm",
        mode="thorough",
        cli_backend=cli_backend,
        claude_exec_mode=claude_exec_mode,
    )

    config = json.loads(
        (workspace / ".scratchpad" / "config.json").read_text(encoding="utf-8")
    )
    assert config["cli_backend"] == cli_backend
    assert config["claude_exec_mode"] == "headless"
    assert prepared["backend"] == "claude"
    assert prepared["cli_backend"] == cli_backend
    assert prepared["claude_exec_mode"] == "headless"
    assert prepared["phase_orchestration"] == "DRIVER_ONLY"
    assert T.verify_preparation_receipt(receipt) == ()


@pytest.mark.parametrize(
    ("cli_backend", "claude_exec_mode"),
    (("claude-headless", "pty"), ("codex", "headless"), ("claude", "unknown")),
)
def test_invalid_terminal_launch_authority_is_rejected_before_workspace_write(
    tmp_path: Path,
    cli_backend: str,
    claude_exec_mode: str,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    workspace = tmp_path / "isolated" / "project"
    with pytest.raises(T.TerminalAuditPreparationError, match="launch authority"):
        T.prepare_legacy_claude_run(
            source_project=source,
            workspace_project=workspace,
            prior_evidence_receipt=tmp_path / "prior.json",
            preparation_receipt=tmp_path / "prepared.json",
            driver_path=_driver(tmp_path / "driver.py"),
            language="evm",
            cli_backend=cli_backend,
            claude_exec_mode=claude_exec_mode,
        )
    assert not workspace.exists()


@pytest.mark.parametrize("mode", ("light", "core"))
def test_terminal_claude_non_thorough_route_fails_before_workspace_write(
    tmp_path: Path, mode: str,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    workspace = tmp_path / "isolated" / "project"
    with pytest.raises(
        T.TerminalAuditPreparationError,
        match="supported only for Smart Contract Thorough",
    ):
        T.prepare_legacy_claude_run(
            source_project=source,
            workspace_project=workspace,
            prior_evidence_receipt=tmp_path / "prior.json",
            preparation_receipt=tmp_path / "prepared.json",
            driver_path=_driver(tmp_path / "driver.py"),
            language="evm",
            mode=mode,
        )
    assert not workspace.exists()
    assert not (tmp_path / "prior.json").exists()
    assert not (tmp_path / "prepared.json").exists()


def test_preparation_refuses_existing_or_nested_destination_without_mutating_source(
    tmp_path: Path,
):
    source = tmp_path / "source"
    source.mkdir()
    (source / "Protocol.sol").write_text("contract Protocol {}\n")
    before = _tree_bytes(source)
    driver = _driver(tmp_path / "plamen_driver.py")

    existing = tmp_path / "existing"
    existing.mkdir()
    (existing / "keep.txt").write_text("user-owned\n")
    with pytest.raises(T.TerminalAuditPreparationError, match="must not exist"):
        T.prepare_legacy_claude_run(
            source_project=source,
            workspace_project=existing,
            prior_evidence_receipt=tmp_path / "seal-existing.json",
            preparation_receipt=tmp_path / "prep-existing.json",
            driver_path=driver,
            language="evm",
        )
    assert (existing / "keep.txt").read_text() == "user-owned\n"

    with pytest.raises(T.TerminalAuditPreparationError, match="nested"):
        T.prepare_legacy_claude_run(
            source_project=source,
            workspace_project=source / "new-run",
            prior_evidence_receipt=tmp_path / "seal-nested.json",
            preparation_receipt=tmp_path / "prep-nested.json",
            driver_path=driver,
            language="evm",
        )
    assert _tree_bytes(source) == before


def test_l1_preparation_fails_closed_before_workspace_mutation(
    tmp_path: Path,
):
    source = tmp_path / "l1-source"
    source.mkdir()
    (source / "go.mod").write_text("module example.invalid/node\n")
    (source / "node.go").write_text("package node\n")
    workspace = tmp_path / "isolated-l1"
    driver = _driver(tmp_path / "plamen_driver.py")

    with pytest.raises(
        T.TerminalAuditPreparationError,
        match="supported only for Smart Contract Thorough",
    ):
        T.prepare_legacy_claude_run(
            source_project=source,
            workspace_project=workspace,
            prior_evidence_receipt=tmp_path / "l1-prior.json",
            preparation_receipt=tmp_path / "l1-prepared.json",
            driver_path=driver,
            language="go",
            mode="thorough",
            pipeline="l1",
            tier="t2",
            subsystem_scope="consensus,network",
            fork_mode="both",
        )
    assert not workspace.exists()
    assert not (tmp_path / "l1-prior.json").exists()
    assert not (tmp_path / "l1-prepared.json").exists()


def test_all_named_prior_roots_are_sealed_and_omitted_deterministically(
    tmp_path: Path,
):
    source = tmp_path / "source"
    roots = (
        source / ".scratchpad",
        source / "nested" / ".scratchpad",
        source / ".plamen-stale-snapshots",
        source / ".scratchpad-stale-snapshot-old",
        source / ".plamen_archive_123",
        source / ".medusa-tests",
    )
    for index, root in enumerate(roots):
        root.mkdir(parents=True, exist_ok=True)
        (root / f"evidence-{index}.txt").write_text(f"old-{index}\n")
    (source / "src").mkdir()
    (source / "src" / "Node.rs").write_text("pub struct Node;\n")
    (source / "nested" / "AUDIT_REPORT.previous.md").write_text("old report\n")
    discovered = T.discover_prior_audit_evidence(source)
    discovered_names = {path.name for path in discovered}
    assert {
        ".scratchpad",
        ".plamen-stale-snapshots",
        ".scratchpad-stale-snapshot-old",
        ".plamen_archive_123",
        ".medusa-tests",
        "AUDIT_REPORT.previous.md",
    } <= discovered_names

    driver = _driver(tmp_path / "plamen_driver.py")
    workspace = tmp_path / "isolated"
    prepared = T.prepare_legacy_claude_run(
        source_project=source,
        workspace_project=workspace,
        prior_evidence_receipt=tmp_path / "prior.json",
        preparation_receipt=tmp_path / "prepared.json",
        driver_path=driver,
        language="soroban",
    )
    assert (workspace / "src" / "Node.rs").is_file()
    assert not (workspace / "nested" / "AUDIT_REPORT.previous.md").exists()
    old_markers = {f"evidence-{index}.txt" for index in range(len(roots))}
    assert not old_markers & {path.name for path in workspace.rglob("*")}
    assert T.verify_prior_audit_evidence_seal(tmp_path / "prior.json") == ()


def test_alternate_scratchpad_prefix_is_sealed_and_omitted(tmp_path: Path):
    source = tmp_path / "source"
    alternate = source / ".scratchpad-run-2"
    alternate.mkdir(parents=True)
    (alternate / "findings_inventory.md").write_text("prior findings\n")
    (source / "Protocol.sol").write_text("contract Protocol {}\n")

    workspace = tmp_path / "isolated"
    T.prepare_legacy_claude_run(
        source_project=source,
        workspace_project=workspace,
        prior_evidence_receipt=tmp_path / "prior.json",
        preparation_receipt=tmp_path / "prepared.json",
        driver_path=_driver(tmp_path / "plamen_driver.py"),
        language="evm",
    )
    assert not (workspace / ".scratchpad-run-2").exists()
    seal = json.loads((tmp_path / "prior.json").read_text(encoding="utf-8"))
    assert str(alternate.resolve()) in {row["path"] for row in seal["evidence_roots"]}


def test_prior_report_hardlink_alias_is_omitted_from_isolated_input(tmp_path: Path):
    source = tmp_path / "source"
    source.mkdir()
    report = source / "AUDIT_REPORT.md"
    report.write_text("prior answer key\n")
    alias = source / "innocent-context.md"
    try:
        os.link(report, alias)
    except OSError as exc:
        pytest.skip(f"hardlinks unavailable in fixture filesystem: {exc}")
    (source / "Protocol.sol").write_text("contract Protocol {}\n")

    workspace = tmp_path / "isolated"
    prepared = T.prepare_legacy_claude_run(
        source_project=source,
        workspace_project=workspace,
        prior_evidence_receipt=tmp_path / "prior.json",
        preparation_receipt=tmp_path / "prepared.json",
        driver_path=_driver(tmp_path / "plamen_driver.py"),
        language="evm",
    )
    assert not (workspace / "AUDIT_REPORT.md").exists()
    assert not (workspace / "innocent-context.md").exists()
    assert "innocent-context.md" in prepared["source_copy"]["omitted_prior_evidence"]


def test_legacy_sibling_archives_are_included_in_the_prior_evidence_seal(tmp_path: Path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "Protocol.sol").write_text("contract Protocol {}\n")
    sibling_archive = tmp_path / ".plamen_archive_12345"
    sibling_archive.mkdir()
    (sibling_archive / "AUDIT_REPORT.md").write_text("legacy report\n")

    discovered = T.discover_prior_audit_evidence(source)
    assert sibling_archive.resolve() in {path.resolve() for path in discovered}
    receipt = T.seal_prior_audit_evidence(source, tmp_path / "seal.json")
    assert str(sibling_archive.resolve()) in {
        str(Path(row["path"]).resolve()) for row in receipt["evidence_roots"]
    }


def test_forbidden_evaluation_inputs_are_never_read_copied_or_named_in_receipts(
    tmp_path: Path,
):
    source = tmp_path / "source"
    source.mkdir()
    (source / "Protocol.sol").write_text("contract Protocol {}\n")
    forbidden = tmp_path / "private-evaluation.pdf"
    secret = b"GROUND-TRUTH-CONTENT-MUST-NOT-ENTER-AUDIT"
    forbidden.write_bytes(secret)
    workspace = tmp_path / "isolated"
    driver = _driver(tmp_path / "plamen_driver.py")

    prepared = T.prepare_legacy_claude_run(
        source_project=source,
        workspace_project=workspace,
        prior_evidence_receipt=tmp_path / "prior.json",
        preparation_receipt=tmp_path / "prepared.json",
        driver_path=driver,
        language="evm",
        forbidden_input_paths=(forbidden,),
    )

    assert all(secret not in path.read_bytes() for path in workspace.rglob("*") if path.is_file())
    receipt_bytes = (tmp_path / "prepared.json").read_bytes()
    assert secret not in receipt_bytes
    assert str(forbidden) not in receipt_bytes.decode("utf-8")
    assert prepared["forbidden_input_count"] == 1
    assert "forbidden_input_path_sha256" not in prepared
    assert json.loads((workspace / ".scratchpad" / "config.json").read_text())[
        "docs_path"
    ] == ""


def test_forbidden_input_inside_source_fails_before_any_seal_or_copy(tmp_path: Path):
    source = tmp_path / "source"
    source.mkdir()
    forbidden = source / "evaluation.pdf"
    forbidden.write_bytes(b"not for audit")
    driver = _driver(tmp_path / "plamen_driver.py")
    with pytest.raises(T.TerminalAuditPreparationError, match="forbidden evaluation"):
        T.prepare_legacy_claude_run(
            source_project=source,
            workspace_project=tmp_path / "isolated",
            prior_evidence_receipt=tmp_path / "prior.json",
            preparation_receipt=tmp_path / "prepared.json",
            driver_path=driver,
            language="evm",
            forbidden_input_paths=(forbidden,),
        )
    assert not (tmp_path / "prior.json").exists()
    assert not (tmp_path / "isolated").exists()


def test_forbidden_external_hardlink_alias_is_rejected_before_content_hashing(
    tmp_path: Path, monkeypatch
):
    source = tmp_path / "source"
    source.mkdir()
    forbidden = tmp_path / "evaluation.pdf"
    forbidden.write_bytes(b"private evaluator bytes")
    alias = source / "innocent-name.pdf"
    try:
        os.link(forbidden, alias)
    except OSError as exc:
        pytest.skip(f"hardlinks unavailable in fixture filesystem: {exc}")
    driver = _driver(tmp_path / "plamen_driver.py")
    original_hash = T._sha256_file

    def guarded_hash(path: Path) -> str:
        if path.exists() and os.path.samefile(path, forbidden):
            raise AssertionError("forbidden evaluation bytes were read")
        return original_hash(path)

    monkeypatch.setattr(T, "_sha256_file", guarded_hash)
    with pytest.raises(T.TerminalAuditPreparationError, match="forbidden evaluation"):
        T.prepare_legacy_claude_run(
            source_project=source,
            workspace_project=tmp_path / "isolated",
            prior_evidence_receipt=tmp_path / "prior.json",
            preparation_receipt=tmp_path / "prepared.json",
            driver_path=driver,
            language="evm",
            forbidden_input_paths=(forbidden,),
        )
    assert not (tmp_path / "isolated").exists()


def test_source_symlink_that_escapes_project_fails_before_seal_or_copy(tmp_path: Path):
    source = tmp_path / "source"
    source.mkdir()
    external = tmp_path / "external.sol"
    external.write_text("contract External {}\n")
    _symlink_or_skip(external, source / "Alias.sol")
    driver = _driver(tmp_path / "plamen_driver.py")

    with pytest.raises(T.TerminalAuditPreparationError, match="escapes source"):
        T.prepare_legacy_claude_run(
            source_project=source,
            workspace_project=tmp_path / "isolated",
            prior_evidence_receipt=tmp_path / "prior.json",
            preparation_receipt=tmp_path / "prepared.json",
            driver_path=driver,
            language="evm",
        )
    assert not (tmp_path / "prior.json").exists()
    assert not (tmp_path / "isolated").exists()


def test_source_symlink_into_excluded_prior_tree_fails_closed(tmp_path: Path):
    source = tmp_path / "source"
    scratch = source / ".scratchpad"
    scratch.mkdir(parents=True)
    (scratch / "old.md").write_text("old answer\n")
    _symlink_or_skip(Path(".scratchpad") / "old.md", source / "OldAlias.md")
    driver = _driver(tmp_path / "plamen_driver.py")

    with pytest.raises(T.TerminalAuditPreparationError, match="prior-audit"):
        T.prepare_legacy_claude_run(
            source_project=source,
            workspace_project=tmp_path / "isolated",
            prior_evidence_receipt=tmp_path / "prior.json",
            preparation_receipt=tmp_path / "prepared.json",
            driver_path=driver,
            language="evm",
        )


def test_relative_in_tree_file_symlink_is_preserved_after_exact_validation(tmp_path: Path):
    source = tmp_path / "source"
    real = source / "src" / "Protocol.sol"
    real.parent.mkdir(parents=True)
    real.write_text("contract Protocol {}\n")
    _symlink_or_skip(Path("src") / "Protocol.sol", source / "ProtocolAlias.sol")
    driver = _driver(tmp_path / "plamen_driver.py")
    workspace = tmp_path / "isolated"

    T.prepare_legacy_claude_run(
        source_project=source,
        workspace_project=workspace,
        prior_evidence_receipt=tmp_path / "prior.json",
        preparation_receipt=tmp_path / "prepared.json",
        driver_path=driver,
        language="evm",
    )
    copied = workspace / "ProtocolAlias.sol"
    assert copied.is_symlink()
    assert os.readlink(copied) == os.readlink(source / "ProtocolAlias.sol")
    assert copied.resolve() == (workspace / "src" / "Protocol.sol").resolve()


def test_seal_records_but_never_follows_link_inside_excluded_prior_tree(
    tmp_path: Path, monkeypatch
):
    source = tmp_path / "source"
    scratch = source / ".scratchpad"
    scratch.mkdir(parents=True)
    external = tmp_path / "private-evaluation.pdf"
    external.write_bytes(b"private evaluator bytes")
    _symlink_or_skip(external, scratch / "external-link.pdf")
    original_hash = T._sha256_file

    def guarded_hash(path: Path) -> str:
        if path.exists() and os.path.samefile(path, external):
            raise AssertionError("sealer followed an unsafe evidence link")
        return original_hash(path)

    monkeypatch.setattr(T, "_sha256_file", guarded_hash)
    receipt = T.seal_prior_audit_evidence(source, tmp_path / "prior.json")
    link_rows = [
        entry
        for root in receipt["evidence_roots"]
        for entry in root["entries"]
        if entry["relative_path"].endswith("external-link.pdf")
    ]
    assert len(link_rows) == 1
    assert link_rows[0]["type"] == "link"


def test_receipt_parent_link_is_rejected_without_writing_through_it(tmp_path: Path):
    source = tmp_path / "source"
    (source / ".scratchpad").mkdir(parents=True)
    (source / ".scratchpad" / "old.md").write_text("old\n")
    real_receipts = tmp_path / "real-receipts"
    real_receipts.mkdir()
    alias = tmp_path / "receipt-alias"
    _symlink_or_skip(real_receipts, alias, directory=True)

    with pytest.raises(T.TerminalAuditPreparationError, match="link component"):
        T.seal_prior_audit_evidence(source, alias / "prior.json")
    assert not (real_receipts / "prior.json").exists()


def test_atomic_receipt_publish_never_overwrites_a_racing_writer(
    tmp_path: Path, monkeypatch
):
    destination = tmp_path / "receipt.json"
    competing = b"competing writer\n"

    def racing_link(_source, target, **_kwargs):
        Path(target).write_bytes(competing)
        raise FileExistsError(str(target))

    monkeypatch.setattr(os, "link", racing_link)
    with pytest.raises(T.TerminalAuditPreparationError, match="different evidence"):
        T._atomic_write_new_or_same(destination, b"our receipt\n")
    assert destination.read_bytes() == competing


def test_preparation_verifier_rejects_workspace_addition_and_config_escape(tmp_path: Path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "Protocol.sol").write_text("contract Protocol {}\n")
    workspace = tmp_path / "isolated"
    receipt = tmp_path / "prepared.json"
    T.prepare_legacy_claude_run(
        source_project=source,
        workspace_project=workspace,
        prior_evidence_receipt=tmp_path / "prior.json",
        preparation_receipt=receipt,
        driver_path=_driver(tmp_path / "plamen_driver.py"),
        language="evm",
    )
    assert T.verify_preparation_receipt(receipt) == ()

    (workspace / "unsealed-answer-key.md").write_text("late input\n")
    assert any("workspace" in issue for issue in T.verify_preparation_receipt(receipt))
    (workspace / "unsealed-answer-key.md").unlink()

    payload = json.loads(receipt.read_text(encoding="utf-8"))
    payload["config_path"] = str(tmp_path / "outside-config.json")
    unsigned = {key: value for key, value in payload.items() if key != "preparation_sha256"}
    payload["preparation_sha256"] = T._sha256_bytes(T._canonical_bytes(unsigned))
    receipt.write_bytes(T._render_json(payload))
    assert any("config path" in issue for issue in T.verify_preparation_receipt(receipt))


def test_preparation_verifier_replays_prior_evidence_seal(tmp_path: Path):
    source = tmp_path / "source"
    scratch = source / ".scratchpad"
    scratch.mkdir(parents=True)
    (scratch / "old.md").write_text("prior\n")
    (source / "Protocol.sol").write_text("contract Protocol {}\n")
    receipt = tmp_path / "prepared.json"
    T.prepare_legacy_claude_run(
        source_project=source,
        workspace_project=tmp_path / "isolated",
        prior_evidence_receipt=tmp_path / "prior.json",
        preparation_receipt=receipt,
        driver_path=_driver(tmp_path / "plamen_driver.py"),
        language="evm",
    )
    (scratch / "old.md").write_text("changed\n")
    assert any("prior-evidence" in issue for issue in T.verify_preparation_receipt(receipt))


def test_preparation_rejects_noncanonical_same_named_driver(tmp_path: Path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "Protocol.sol").write_text("contract Protocol {}\n")
    impostor = tmp_path / "other" / "plamen_driver.py"
    impostor.parent.mkdir()
    impostor.write_text("raise SystemExit('not shared driver')\n")
    with pytest.raises(T.TerminalAuditPreparationError, match="canonical shared"):
        T.prepare_legacy_claude_run(
            source_project=source,
            workspace_project=tmp_path / "isolated",
            prior_evidence_receipt=tmp_path / "prior.json",
            preparation_receipt=tmp_path / "prepared.json",
            driver_path=impostor,
            language="evm",
        )


def test_preparation_fails_if_evidence_drifts_after_copy(tmp_path: Path, monkeypatch):
    source = tmp_path / "source"
    scratch = source / ".scratchpad"
    scratch.mkdir(parents=True)
    evidence = scratch / "old.md"
    evidence.write_text("prior\n")
    (source / "Protocol.sol").write_text("contract Protocol {}\n")
    original = T._copy_isolated_project

    def drifting_copy(*args, **kwargs):
        copied = original(*args, **kwargs)
        evidence.write_text("changed during preparation\n")
        return copied

    monkeypatch.setattr(T, "_copy_isolated_project", drifting_copy)
    with pytest.raises(T.TerminalAuditPreparationError, match="drifted during preparation"):
        T.prepare_legacy_claude_run(
            source_project=source,
            workspace_project=tmp_path / "isolated",
            prior_evidence_receipt=tmp_path / "prior.json",
            preparation_receipt=tmp_path / "prepared.json",
            driver_path=_driver(tmp_path / "plamen_driver.py"),
            language="evm",
        )


def test_preparation_rejects_codex_backend_and_never_contains_phase_orchestration():
    source = (Path(__file__).parent / "terminal_audit_launch.py").read_text(
        encoding="utf-8", errors="strict"
    )
    assert "spawn_agent" not in source
    assert "run_phase" not in source
    assert "subprocess.Popen" not in source
    assert "subprocess.run" not in source
    assert "os.system(" not in source
    assert "os.exec" not in source
    assert '("claude", "pty")' not in source
    assert '("claude", "headless")' in source
    assert '("claude-headless", "headless")' in source


def test_repository_guidance_uses_only_the_shared_driver_and_safe_resume_contract():
    guide = (
        Path(__file__).resolve().parents[1]
        / "docs"
        / "terminal-legacy-claude-audits.md"
    ).read_text(encoding="utf-8", errors="strict")
    for marker in (
        "scripts/terminal_audit_launch.py",
        '"cli_backend": "claude-headless"',
        '"claude_exec_mode": "headless"',
        "--startup-intent START_NEW_RUN",
        "resume_argv",
        "plamen_driver.py",
        "ground truth",
    ):
        assert marker in guide
    assert "spawn_agent" not in guide
    assert "manually orchestrate" not in guide
    assert "plamen_driver.py --fresh" not in guide
