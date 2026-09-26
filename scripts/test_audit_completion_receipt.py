from __future__ import annotations

import json
from pathlib import Path

import pytest

import audit_completion_receipt as C
import e2e_acceptance_verifier as V
import test_e2e_acceptance_verifier as F


def _write_json(path: Path, value) -> None:
    path.write_bytes(F._canonical(value) + b"\n")


def _producer_fixture(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, remove_existing: bool = True
) -> tuple[dict[str, Path], C.ExpectedCompletionIdentity]:
    paths = F._fixture(tmp_path, monkeypatch)
    if remove_existing:
        (paths["scratchpad"] / C.RECEIPT_NAME).unlink()
    expected = json.loads(paths["identity"].read_text())
    identity = C.ExpectedCompletionIdentity.from_mapping(
        {
            key: expected[key]
            for key in (
                "run_id", "installed_package_root", "installed_package_receipt",
                "installed_package_receipt_sha256", "installed_generation_receipt",
                "installed_generation_receipt_sha256", "installed_package_generation_sha256",
                "plamen_source_root", "plamen_source_commit", "target_repository_root",
                "target_commit",
            )
        }
    )
    target = Path(identity.target_repository_root).resolve()
    monkeypatch.setattr(
        C,
        "_git_head",
        lambda root: F.TARGET_COMMIT if root.resolve() == target else F.SOURCE_COMMIT,
    )
    monkeypatch.setattr(C, "_git_tracked_clean", lambda root, scope=None: True)
    return paths, identity


def _publish(paths: dict[str, Path], identity: C.ExpectedCompletionIdentity):
    return C.publish_audit_completion_receipt(
        scratchpad=paths["scratchpad"],
        project_root=paths["project"],
        terminal_exit_code=0,
        identity=identity,
        completed_at="2026-09-14T02:00:00+00:00",
    )


def test_producer_and_acceptance_verifier_interoperate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths, identity = _producer_fixture(tmp_path, monkeypatch)
    published = _publish(paths, identity)
    assert published.path == paths["scratchpad"] / C.RECEIPT_NAME
    assert published.receipt_sha256 == published.payload["receipt_sha256"]
    assert published.payload["realized_phase_plan_sha256"] == C.phase_names_sha256()
    assert C.validate_terminal_closure(published.payload["terminal_closure"])
    assert V.verify_sc_thorough_e2e(
        scratchpad=paths["scratchpad"],
        config_path=paths["config"],
        project_root=paths["project"],
        expected_identity_path=paths["identity"],
    ).accepted is True


def test_base_phase_denominator_is_exactly_shared_with_verifier() -> None:
    assert C.SC_THOROUGH_PHASES == V.EXPECTED_SC_THOROUGH_PHASES
    assert len(C.SC_THOROUGH_PHASES) == 75


def test_completion_run_id_consumes_fresh_and_matching_resume_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _paths, identity = _producer_fixture(tmp_path, monkeypatch)
    raw = {
        name: str(getattr(identity, name))
        for name in identity.__dataclass_fields__
    }
    config = {
        "pipeline": "sc", "mode": "thorough",
        "_audit_completion_identity": raw,
    }
    assert C.completion_identity_run_id(config, None) == identity.run_id
    assert C.completion_identity_run_id(config, identity.run_id) == identity.run_id


def test_completion_run_id_rejects_resume_mismatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _paths, identity = _producer_fixture(tmp_path, monkeypatch)
    config = {
        "pipeline": "sc", "mode": "thorough",
        "_audit_completion_identity": {
            name: str(getattr(identity, name))
            for name in identity.__dataclass_fields__
        },
    }
    with pytest.raises(C.CompletionReceiptError, match="checkpoint run_id"):
        C.completion_identity_run_id(
            config, "ffffffff-ffff-4fff-8fff-ffffffffffff",
        )


def test_start_capture_builds_exact_compat_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths, identity = _producer_fixture(tmp_path, monkeypatch)
    captured = C.capture_start_completion_identity(
        run_id=identity.run_id,
        installed_package_root=identity.installed_package_root,
        installed_package_receipt=Path(identity.installed_package_receipt),
        installed_generation_receipt=None,
        plamen_source_root=identity.plamen_source_root,
        target_repository_root=identity.target_repository_root,
        project_root=paths["project"],
    )
    assert captured == {
        "run_id": identity.run_id,
        "installed_package_root": str(Path(identity.installed_package_root).resolve()),
        "installed_package_receipt": identity.installed_package_receipt,
        "installed_package_receipt_sha256": identity.installed_package_receipt_sha256,
        "installed_generation_receipt": identity.installed_generation_receipt,
        "installed_generation_receipt_sha256": identity.installed_generation_receipt_sha256,
        "installed_package_generation_sha256": identity.installed_package_generation_sha256,
        "plamen_source_root": str(Path(identity.plamen_source_root).resolve()),
        "plamen_source_commit": identity.plamen_source_commit,
        "target_repository_root": str(Path(identity.target_repository_root).resolve()),
        "target_commit": identity.target_commit,
    }


def test_start_capture_parses_native_generation_authority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    installed = tmp_path / "installed"
    source = tmp_path / "source"
    target = tmp_path / "target"
    project = target / "project"
    for path in (installed, source, project):
        path.mkdir(parents=True)
    package = tmp_path / "codex-install.json"
    rows = [{"source_path": "scripts/plamen_driver.py", "size": 7, "sha256": "d" * 64}]
    manifest = F._sha(b"scripts/plamen_driver.py|7|" + ("d" * 64).encode() + b"\n")
    _write_json(
        package,
        {
            "schema": "plamen.codex_install.v2",
            "state": "COMMITTED",
            "transaction_id": "a" * 32,
            "source_count": 1,
            "source_manifest_sha256": manifest,
            "rows": rows,
            "plamen_root": str(installed.resolve()),
        },
    )
    generation = bytearray(16384)
    generation[:8] = b"PLMINS2\x00"
    generation[16:48] = bytes.fromhex("c" * 64)
    generation_path = tmp_path / "native-install-receipt-v2.bin"
    generation_path.write_bytes(generation)
    monkeypatch.setattr(
        C, "_git_head",
        lambda root: F.TARGET_COMMIT if root.resolve() == target.resolve() else F.SOURCE_COMMIT,
    )
    monkeypatch.setattr(C, "_git_tracked_clean", lambda root, scope=None: True)
    captured = C.capture_start_completion_identity(
        run_id=F.RUN_ID,
        installed_package_root=installed,
        installed_package_receipt=package,
        installed_generation_receipt=generation_path,
        plamen_source_root=source,
        target_repository_root=target,
        project_root=project,
    )
    assert captured["installed_package_generation_sha256"] == "c" * 64
    assert captured["installed_package_receipt_sha256"] == F._sha(package.read_bytes())
    assert captured["installed_generation_receipt_sha256"] == F._sha(bytes(generation))


def _windows_install_authority_fixture(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> tuple[Path, Path, Path, str, tuple[int, int]]:
    installed = tmp_path / "installed"
    codex = tmp_path / ".codex"
    installed.mkdir()
    codex.mkdir()
    anchor = codex / ".plamen-install.admission.lock"
    anchor.write_bytes(b"plamen-install-admission-v1\n")
    anchor_identity = (17, 23)
    rows = [
        {"source_path": "plamen.py", "size": 3, "sha256": "a" * 64},
        {"source_path": "scripts/plamen_driver.py", "size": 7, "sha256": "d" * 64},
    ]
    manifest = F._sha(b"".join(
        f"{row['source_path']}|{row['size']}|{row['sha256']}\n".encode()
        for row in sorted(rows, key=lambda value: value["source_path"])
    ))
    package = codex / ".plamen-codex-install.json"
    _write_json(
        package,
        {
            "schema": "plamen.codex_install.v2",
            "state": "COMMITTED",
            "transaction_id": "a" * 32,
            "source_count": len(rows),
            "source_manifest_sha256": manifest,
            "rows": rows,
            "plamen_root": str(installed.resolve()),
            "codex_root": str(codex.resolve()),
            "lock_identity": list(anchor_identity),
        },
    )
    monkeypatch.setattr(C, "_is_windows_host", lambda: True)

    def open_anchor(path: Path):
        assert path == anchor.resolve()
        return path.read_bytes(), anchor_identity, lambda: None

    monkeypatch.setattr(C, "_open_windows_admission_anchor", open_anchor)
    return installed, package, anchor, manifest, anchor_identity


def test_windows_package_uses_exact_admission_anchor_as_generation_authority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    installed, package, anchor, manifest, _identity = (
        _windows_install_authority_fixture(tmp_path, monkeypatch)
    )
    package_digest, anchor_digest, generation = C._installed_authority(
        installed_root=installed.resolve(),
        package_receipt_path=package.resolve(),
        generation_receipt_path=anchor.resolve(),
    )
    assert package_digest == F._sha(package.read_bytes())
    assert anchor_digest == F._sha(anchor.read_bytes())
    assert generation == manifest


def test_windows_start_capture_uses_existing_generation_receipt_argument_for_anchor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    installed, package, anchor, manifest, _identity = (
        _windows_install_authority_fixture(tmp_path, monkeypatch)
    )
    source = tmp_path / "source"
    target = tmp_path / "target"
    project = target / "project"
    source.mkdir()
    project.mkdir(parents=True)
    monkeypatch.setattr(
        C, "_git_head",
        lambda root: F.TARGET_COMMIT if root.resolve() == target.resolve() else F.SOURCE_COMMIT,
    )
    monkeypatch.setattr(C, "_git_tracked_clean", lambda root, scope=None: True)
    captured = C.capture_start_completion_identity(
        run_id=F.RUN_ID,
        installed_package_root=installed,
        installed_package_receipt=package,
        installed_generation_receipt=anchor,
        plamen_source_root=source,
        target_repository_root=target,
        project_root=project,
    )
    assert captured["installed_generation_receipt"] == str(anchor.resolve())
    assert captured["installed_generation_receipt_sha256"] == F._sha(anchor.read_bytes())
    assert captured["installed_package_generation_sha256"] == manifest


@pytest.mark.parametrize(
    ("mutation", "error"),
    (
        ("lock", "anchor identity differs"),
        ("anchor_bytes", "anchor bytes differ"),
        ("package_name", "not exact Codex authorities"),
        ("duplicate_source", "rows are malformed"),
    ),
)
def test_windows_package_rejects_substituted_or_malformed_authority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutation: str, error: str,
) -> None:
    installed, package, anchor, _manifest, _identity = (
        _windows_install_authority_fixture(tmp_path, monkeypatch)
    )
    if mutation == "anchor_bytes":
        anchor.write_bytes(b"plamen-install-admission-v2\n")
    else:
        payload = json.loads(package.read_text())
        if mutation == "lock":
            payload["lock_identity"] = [17, 24]
        elif mutation == "duplicate_source":
            payload["rows"][1]["source_path"] = payload["rows"][0]["source_path"]
        else:
            renamed = package.with_name("receipt-copy.json")
            package.rename(renamed)
            package = renamed
        if mutation != "package_name":
            rows = payload["rows"]
            payload["source_manifest_sha256"] = F._sha(b"".join(
                f"{row['source_path']}|{row['size']}|{row['sha256']}\n".encode()
                for row in sorted(rows, key=lambda value: value["source_path"])
            ))
            _write_json(package, payload)
    with pytest.raises(C.CompletionReceiptError, match=error):
        C._installed_authority(
            installed_root=installed.resolve(),
            package_receipt_path=package.resolve(),
            generation_receipt_path=anchor.resolve(),
        )


def test_windows_package_rejects_posix_generation_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    installed, package, _anchor, _manifest, _identity = (
        _windows_install_authority_fixture(tmp_path, monkeypatch)
    )
    generation = tmp_path / "native-install-receipt-v2.bin"
    generation.write_bytes(b"PLMINS2\x00" + b"\x00" * (16384 - 8))
    with pytest.raises(C.CompletionReceiptError, match="requires its install admission anchor"):
        C._installed_authority(
            installed_root=installed.resolve(),
            package_receipt_path=package.resolve(),
            generation_receipt_path=generation.resolve(),
        )


def test_posix_package_does_not_accept_windows_anchor_substitute(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    installed, package, anchor, _manifest, _identity = (
        _windows_install_authority_fixture(tmp_path, monkeypatch)
    )
    monkeypatch.setattr(C, "_is_windows_host", lambda: False)
    with pytest.raises(C.CompletionReceiptError, match="generation receipt framing"):
        C._installed_authority(
            installed_root=installed.resolve(),
            package_receipt_path=package.resolve(),
            generation_receipt_path=anchor.resolve(),
        )


def test_windows_receipt_drift_while_anchor_is_retained_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    installed, package, anchor, _manifest, _identity = (
        _windows_install_authority_fixture(tmp_path, monkeypatch)
    )
    real_read = C._read_json
    calls = 0

    def drifting_read(path: Path):
        nonlocal calls
        value, raw = real_read(path)
        calls += 1
        if calls == 2:
            return value, raw + b" "
        return value, raw

    monkeypatch.setattr(C, "_read_json", drifting_read)
    with pytest.raises(C.CompletionReceiptError, match="changed during admission"):
        C._installed_authority(
            installed_root=installed.resolve(),
            package_receipt_path=package.resolve(),
            generation_receipt_path=anchor.resolve(),
        )


def test_thin_driver_adapter_uses_only_start_bound_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths, identity = _producer_fixture(tmp_path, monkeypatch)
    config = json.loads(paths["config"].read_text())
    config["_audit_completion_identity"] = {
        "run_id": identity.run_id,
        "installed_package_root": str(identity.installed_package_root),
        "installed_package_receipt": identity.installed_package_receipt,
        "installed_package_receipt_sha256": identity.installed_package_receipt_sha256,
        "installed_generation_receipt": identity.installed_generation_receipt,
        "installed_generation_receipt_sha256": identity.installed_generation_receipt_sha256,
        "installed_package_generation_sha256": identity.installed_package_generation_sha256,
        "plamen_source_root": str(identity.plamen_source_root),
        "plamen_source_commit": identity.plamen_source_commit,
        "target_repository_root": str(identity.target_repository_root),
        "target_commit": identity.target_commit,
    }
    published = C.publish_from_driver_terminal_state(
        scratchpad=paths["scratchpad"], config=config, terminal_exit_code=0,
    )
    assert published.path.is_file()


def test_thin_driver_adapter_refuses_missing_start_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths, _identity = _producer_fixture(tmp_path, monkeypatch)
    config = json.loads(paths["config"].read_text())
    with pytest.raises(C.CompletionReceiptError, match="start-bound"):
        C.publish_from_driver_terminal_state(
            scratchpad=paths["scratchpad"], config=config, terminal_exit_code=0,
        )


def test_nonzero_or_boolean_exit_never_publishes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    for value in (1, True, -1):
        case = tmp_path / str(value)
        paths, identity = _producer_fixture(case, monkeypatch)
        with pytest.raises(C.CompletionReceiptError, match="integer zero"):
            C.publish_audit_completion_receipt(
                scratchpad=paths["scratchpad"], project_root=paths["project"],
                terminal_exit_code=value, identity=identity,
            )
        assert not (paths["scratchpad"] / C.RECEIPT_NAME).exists()


@pytest.mark.parametrize("mutation", ["partial", "degraded", "retry", "report", "package"])
def test_partial_or_drifted_evidence_never_publishes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutation: str
) -> None:
    paths, identity = _producer_fixture(tmp_path, monkeypatch)
    if mutation in {"partial", "degraded", "retry"}:
        checkpoint = json.loads(paths["checkpoint"].read_text())
        if mutation == "partial":
            checkpoint["completed"].pop()
        elif mutation == "degraded":
            checkpoint["degraded"] = ["depth"]
        else:
            checkpoint["config"]["_active_model_attempts"]["depth"] = 2
        _write_json(paths["checkpoint"], checkpoint)
    elif mutation == "report":
        (paths["project"] / "AUDIT_REPORT.md").write_bytes(b"")
    else:
        receipt = Path(identity.installed_package_receipt)
        receipt.write_bytes(receipt.read_bytes() + b" ")
    with pytest.raises(C.CompletionReceiptError):
        _publish(paths, identity)
    assert not (paths["scratchpad"] / C.RECEIPT_NAME).exists()


def test_commit_or_worktree_drift_never_publishes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths, identity = _producer_fixture(tmp_path, monkeypatch)
    monkeypatch.setattr(C, "_git_tracked_clean", lambda root, scope=None: False)
    with pytest.raises(C.CompletionReceiptError, match="not frozen"):
        _publish(paths, identity)
    assert not (paths["scratchpad"] / C.RECEIPT_NAME).exists()


def test_existing_receipt_is_replay_rejected_without_overwrite(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths, identity = _producer_fixture(tmp_path, monkeypatch, remove_existing=False)
    receipt = paths["scratchpad"] / C.RECEIPT_NAME
    before = receipt.read_bytes()
    with pytest.raises(C.CompletionReceiptError, match="replay"):
        _publish(paths, identity)
    assert receipt.read_bytes() == before


def test_atomic_failure_leaves_no_receipt_or_staging_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths, identity = _producer_fixture(tmp_path, monkeypatch)

    def fail_link(source, destination):
        raise OSError("injected link failure")

    monkeypatch.setattr(C.os, "link", fail_link)
    with pytest.raises(OSError, match="injected"):
        _publish(paths, identity)
    assert not (paths["scratchpad"] / C.RECEIPT_NAME).exists()
    assert not list(paths["scratchpad"].glob(f".{C.RECEIPT_NAME}.*.tmp"))


def test_tampered_terminal_receipt_is_rejected_by_verifier(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths, identity = _producer_fixture(tmp_path, monkeypatch)
    published = _publish(paths, identity)
    receipt = json.loads(published.path.read_text())
    receipt["exit_code"] = 1
    _write_json(published.path, receipt)
    verdict = V.verify_sc_thorough_e2e(
        scratchpad=paths["scratchpad"], config_path=paths["config"],
        project_root=paths["project"], expected_identity_path=paths["identity"],
    )
    assert verdict.accepted is False
    assert "DRIVER_TERMINAL_RECEIPT_INVALID" in {issue.code for issue in verdict.issues}
