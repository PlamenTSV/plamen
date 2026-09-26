from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

import audit_completion_receipt as C
import e2e_acceptance_verifier as V


RUN_ID = "a0b1c2d3-e4f5-4a67-89ab-0123456789ab"
TARGET_COMMIT = "1" * 40
SOURCE_COMMIT = "2" * 40


def _canonical(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode()


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _write_json(path: Path, value) -> None:
    path.write_bytes(_canonical(value) + b"\n")


def _synthetic_terminal_closure() -> dict:
    """Minimal schema-valid closure used only to isolate envelope tests."""

    return C.build_terminal_closure_projection(
        run_id=RUN_ID,
        candidate_rows=[],
        candidate_authority={
            "base_queue_binding": {"artifact": "verification_queue.work_items.json"},
            "delta_binding": None,
            "union_record_count": 0,
            "union_record_set_digest": "0" * 64,
            "source_bindings": [
                {
                    "artifact": "verification_queue.work_items.json",
                    "sha256": "9" * 64,
                }
            ],
        },
        provenance_ids=[],
        verifier_dispositions=[],
        report_bundle={
            "expected_report_ids": [],
            "records": [],
            "bundle_digest": "a" * 64,
        },
        report_bundle_sha256="b" * 64,
        report_quality={
            "receipt_digest": "c" * 64,
            "delivery_state": "SEMANTICALLY_COMPLETE",
            "structurally_delivered": True,
            "semantically_complete": True,
            "missing_semantic_fields": {},
            "evidence_limitations": {},
            "hidden_quality_debt_report_ids": [],
            "unauthorized_proof_grade_report_ids": [],
            "expected_report_ids": [],
            "delivered_report_ids": [],
        },
        report_quality_sha256="d" * 64,
        report_disposition={"rows": [], "receipt_sha256": "e" * 64},
        report_disposition_sha256="f" * 64,
        artifact_ledger_sha256="1" * 64,
        artifact_ledger_digest="2" * 64,
        artifact_ledger_work_units={
            "terminal/test": {
                "run_id": RUN_ID,
                "semantic_status": "ACTIVE",
                "execution_state": "OUTPUT_COMMITTED",
                "contract_digest": "3" * 64,
                "launch_digest": "4" * 64,
            }
        },
        artifact_ledger_binding_count=1,
    )


def _fixture(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, legacy_terminal: bool = False,
) -> dict[str, Path]:
    target = tmp_path / "target"
    project = target / "project"
    scratchpad = project / ".scratchpad"
    installed = tmp_path / "installed"
    source = tmp_path / "source"
    for directory in (scratchpad, installed, source):
        directory.mkdir(parents=True)

    monkeypatch.setattr(
        V,
        "_git_head",
        lambda root: TARGET_COMMIT if root.resolve() == target.resolve() else SOURCE_COMMIT,
    )
    monkeypatch.setattr(V, "_git_tracked_clean", lambda root, scope=None: True)
    receipt = {"schema": "plamen.posix_compat_v2.install.v2", "generation_sha256": "3" * 64}
    receipt_path = installed / "install-receipt.json"
    _write_json(receipt_path, receipt)
    (project / "AUDIT_REPORT.md").write_text("# Audit Report\n\nTerminal report.\n", encoding="utf-8")

    config = {
        "allow_model_fallback": False,
        "cli_backend": "codex",
        "docs_path": "",
        "language": "evm",
        "mode": "thorough",
        "pipeline": "sc",
        "project_root": str(project.resolve()),
        "proven_only": False,
        "scope_file": "",
        "scope_notes": "",
        "scratchpad": str(scratchpad.resolve()),
    }
    config_path = scratchpad / "config.json"
    _write_json(config_path, config)
    components = {
        "audit_config": {
            "digest": _sha(_canonical(V._semantic_config(config))),
            "field_count": len(V._semantic_config(config)),
        },
        "methodology": {"digest": "4" * 64, "path_set_digest": "5" * 64, "file_count": 1, "byte_count": 1},
        "source_scope": {
            "digest": "6" * 64,
            "path_set_digest": "7" * 64,
            "file_count": 1,
            "byte_count": 1,
            "language": "evm",
            "pipeline": "sc",
            "git_head": TARGET_COMMIT,
            "coverage_limitations": [],
        },
        "toolchain": {"digest": "8" * 64, "path_set_digest": "9" * 64, "file_count": 1, "byte_count": 1},
    }
    snapshot = {"schema": "plamen.audit-input-snapshot.v1", "components": components}
    snapshot["snapshot_digest"] = _sha(_canonical(snapshot))
    internal_config = dict(config)
    internal_config.update(
        {
            "_active_phase_names": list(V.EXPECTED_SC_THOROUGH_PHASES),
            "_active_model_attempts": {"breadth": 1, "depth": 1},
            "_phase_io_model_attempts": {"breadth": 1, "depth": 1},
        }
    )
    commits = {}
    for phase in V.EXPECTED_SC_THOROUGH_PHASES:
        commits[phase] = {
            "phase_name": phase,
            "state": "CLEAN",
            "run_id": RUN_ID,
            "work_unit_id": "phase",
            "contract_digest": "a" * 64,
            "launch_digest": "b" * 64,
            "artifact_digest": "c" * 64,
            "unresolved_failures": [],
            "clearance_events": [],
            "committed_at": "2026-09-14T00:00:00+00:00",
        }
    checkpoint = {
        "audit_snapshot": snapshot,
        "completed": list(V.EXPECTED_SC_THOROUGH_PHASES),
        "config": internal_config,
        "degraded": [],
        "phase_commits": commits,
        "rate_limited_at": None,
        "run_id": RUN_ID,
        "runtime_debts": {},
        "semantic_mutation_acks": {},
    }
    checkpoint_path = scratchpad / "_v2_checkpoint.json"
    _write_json(checkpoint_path, checkpoint)
    closure = _synthetic_terminal_closure()
    monkeypatch.setattr(
        C,
        "recompute_terminal_closure",
        lambda **_kwargs: closure,
    )
    _write_json(
        scratchpad / "_audit_started_with_markers.json",
        {"schema_version": 1, "started_at": "2026-09-14T00:00:00+00:00", "driver_version": "3.0.0", "mode": "thorough", "pipeline": "sc"},
    )
    _write_json(
        scratchpad / "obligation_ledger.json",
        {"schema_version": "plamen.obligation_ledger.v1", "active_count": 0, "mode": "thorough", "obligations": [], "row_count": 0},
    )
    identity = {
        "schema_version": V.IDENTITY_SCHEMA,
        "run_id": RUN_ID,
        "installed_package_root": str(installed.resolve()),
        "installed_package_receipt": str(receipt_path.resolve()),
        "installed_package_receipt_sha256": _sha(receipt_path.read_bytes()),
        "installed_generation_receipt": str(receipt_path.resolve()),
        "installed_generation_receipt_sha256": _sha(receipt_path.read_bytes()),
        "installed_package_generation_sha256": "3" * 64,
        "plamen_source_root": str(source.resolve()),
        "plamen_source_commit": SOURCE_COMMIT,
        "target_repository_root": str(target.resolve()),
        "target_commit": TARGET_COMMIT,
        "audit_snapshot_digest": snapshot["snapshot_digest"],
        "methodology_digest": "4" * 64,
        "toolchain_digest": "8" * 64,
    }
    identity_path = tmp_path / "expected-identity.json"
    _write_json(identity_path, identity)
    terminal = {
        "schema_version": (
            V.LEGACY_DRIVER_TERMINAL_SCHEMA
            if legacy_terminal else V.DRIVER_TERMINAL_SCHEMA
        ),
        "run_id": RUN_ID,
        "pipeline": "sc",
        "mode": "thorough",
        "exit_code": 0,
        "phase_count": len(V.EXPECTED_SC_THOROUGH_PHASES),
        "realized_phase_plan_sha256": C.phase_names_sha256(
            V.EXPECTED_SC_THOROUGH_PHASES
        ),
        "checkpoint_sha256": _sha(checkpoint_path.read_bytes()),
        "report_sha256": _sha((project / "AUDIT_REPORT.md").read_bytes()),
        "audit_snapshot_digest": snapshot["snapshot_digest"],
        "plamen_source_commit": SOURCE_COMMIT,
        "installed_package_receipt_sha256": identity["installed_package_receipt_sha256"],
        "installed_generation_receipt_sha256": identity["installed_generation_receipt_sha256"],
        "installed_package_generation_sha256": identity["installed_package_generation_sha256"],
        "target_commit": TARGET_COMMIT,
        "terminal_closure": closure,
        "completed_at": "2026-09-14T01:00:00+00:00",
    }
    if legacy_terminal:
        terminal["ordered_phase_names_sha256"] = terminal.pop(
            "realized_phase_plan_sha256"
        )
        terminal.pop("terminal_closure")
    terminal["receipt_sha256"] = _sha(_canonical(terminal))
    _write_json(scratchpad / "_driver_terminal_receipt.json", terminal)
    _write_json(
        scratchpad / "closed_debt.json",
        {"schema_version": "plamen.synthetic_debt.v1", "count": 0, "status": "CLOSED"},
    )
    return {
        "scratchpad": scratchpad,
        "config": config_path,
        "project": project,
        "identity": identity_path,
        "checkpoint": checkpoint_path,
    }


def _verify(paths: dict[str, Path]) -> V.AcceptanceVerdict:
    return V.verify_sc_thorough_e2e(
        scratchpad=paths["scratchpad"],
        config_path=paths["config"],
        project_root=paths["project"],
        expected_identity_path=paths["identity"],
    )


def _codes(verdict: V.AcceptanceVerdict) -> set[str]:
    return {row.code for row in verdict.issues}


def _replace_with_windows_install_authority(
    paths: dict[str, Path], monkeypatch: pytest.MonkeyPatch,
) -> tuple[Path, Path]:
    identity_path = paths["identity"]
    identity = json.loads(identity_path.read_text())
    installed = Path(identity["installed_package_root"])
    codex = identity_path.parent / ".codex"
    codex.mkdir()
    anchor = codex / ".plamen-install.admission.lock"
    anchor.write_bytes(b"plamen-install-admission-v1\n")
    anchor_identity = (17, 23)
    rows = [
        {"source_path": "plamen.py", "size": 3, "sha256": "a" * 64},
        {"source_path": "scripts/plamen_driver.py", "size": 7, "sha256": "d" * 64},
    ]
    manifest = _sha(b"".join(
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
    identity.update(
        {
            "installed_package_receipt": str(package.resolve()),
            "installed_package_receipt_sha256": _sha(package.read_bytes()),
            "installed_generation_receipt": str(anchor.resolve()),
            "installed_generation_receipt_sha256": _sha(anchor.read_bytes()),
            "installed_package_generation_sha256": manifest,
        }
    )
    _write_json(identity_path, identity)
    terminal_path = paths["scratchpad"] / "_driver_terminal_receipt.json"
    terminal = json.loads(terminal_path.read_text())
    terminal.update(
        {
            "installed_package_receipt_sha256": identity["installed_package_receipt_sha256"],
            "installed_generation_receipt_sha256": identity["installed_generation_receipt_sha256"],
            "installed_package_generation_sha256": manifest,
        }
    )
    terminal.pop("receipt_sha256")
    terminal["receipt_sha256"] = _sha(_canonical(terminal))
    _write_json(terminal_path, terminal)
    return package, anchor


def test_exact_clean_strict_v3_run_is_accepted(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    verdict = _verify(_fixture(tmp_path, monkeypatch))
    assert verdict.accepted is True
    assert verdict.issues == ()
    assert len(verdict.report_sha256) == 64
    assert len(verdict.evidence_sha256) == 64


def test_legacy_trivial_arbitrary_digest_fixture_is_non_accepting(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    verdict = _verify(_fixture(tmp_path, monkeypatch, legacy_terminal=True))
    assert verdict.accepted is False
    assert "LEGACY_DRIVER_TERMINAL_RECEIPT_NON_ACCEPTING" in _codes(verdict)


def test_exact_clean_windows_install_authority_is_accepted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths = _fixture(tmp_path, monkeypatch)
    _replace_with_windows_install_authority(paths, monkeypatch)
    verdict = _verify(paths)
    assert verdict.accepted is True
    assert verdict.issues == ()


@pytest.mark.parametrize("mutation", ("lock", "anchor", "manifest"))
def test_windows_substituted_install_authority_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutation: str,
) -> None:
    paths = _fixture(tmp_path, monkeypatch)
    package, anchor = _replace_with_windows_install_authority(paths, monkeypatch)
    if mutation == "anchor":
        anchor.write_bytes(b"plamen-install-admission-v2\n")
    else:
        receipt = json.loads(package.read_text())
        if mutation == "lock":
            receipt["lock_identity"] = [17, 24]
        else:
            receipt["source_manifest_sha256"] = "f" * 64
        _write_json(package, receipt)
    verdict = _verify(paths)
    assert verdict.accepted is False
    assert "INSTALLED_PACKAGE_IDENTITY_INVALID" in _codes(verdict)


def test_standalone_cli_emits_machine_verdict_and_exit_zero(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    paths = _fixture(tmp_path, monkeypatch)
    result = V.main(
        [
            "--scratchpad", str(paths["scratchpad"]),
            "--config", str(paths["config"]),
            "--project", str(paths["project"]),
            "--expected-identity", str(paths["identity"]),
        ]
    )
    output = json.loads(capsys.readouterr().out)
    assert result == 0
    assert output["schema_version"] == V.VERDICT_SCHEMA
    assert output["accepted"] is True


@pytest.mark.parametrize(
    ("mutation", "expected_code"),
    [
        ("missing_commit", "PHASE_COMMITS_INCOMPLETE"),
        ("dirty_commit", "PHASE_COMMIT_NOT_CLEAN"),
        ("incomplete", "TERMINAL_EXIT_NOT_PROVEN"),
        ("degraded", "DEGRADATION_REMAINS"),
        ("retry", "RETRY_REMAINS"),
        ("runtime_debt", "RUNTIME_DEBT_REMAINS"),
    ],
)
def test_checkpoint_failures_are_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutation: str, expected_code: str
) -> None:
    paths = _fixture(tmp_path, monkeypatch)
    checkpoint = json.loads(paths["checkpoint"].read_text())
    if mutation == "missing_commit":
        checkpoint["phase_commits"].pop("report_floor")
    elif mutation == "dirty_commit":
        checkpoint["phase_commits"]["breadth"]["state"] = "COMPLETED_WITH_DEBT"
    elif mutation == "incomplete":
        checkpoint["completed"].pop()
    elif mutation == "degraded":
        checkpoint["degraded"] = ["breadth"]
    elif mutation == "retry":
        checkpoint["config"]["_active_model_attempts"]["breadth"] = 2
    elif mutation == "runtime_debt":
        checkpoint["runtime_debts"] = {"X": {"reason": "x"}}
    _write_json(paths["checkpoint"], checkpoint)
    verdict = _verify(paths)
    assert verdict.accepted is False
    assert expected_code in _codes(verdict)


def test_residual_debt_obligation_and_provider_failure_are_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = _fixture(tmp_path, monkeypatch)
    _write_json(
        paths["scratchpad"] / "axis_assurance_debt.json",
        {"schema_version": "plamen.axis_assurance_debt.v2", "count": 1},
    )
    _write_json(
        paths["scratchpad"] / "security_obligations.json",
        {
            "schema_version": "plamen.security_obligations.v1",
            "active_count": 2,
            "status": "DEGRADED_HUMAN_REVIEW",
        },
    )
    _write_json(
        paths["scratchpad"] / "axis_repair_execution_receipt.json",
        {"state": "FAILED", "return_code": 1, "issues": ["provider failed"]},
    )
    verdict = _verify(paths)
    assert verdict.accepted is False
    assert {
        "DEBT_ARTIFACT_REMAINS",
        "UNRESOLVED_OBLIGATION_REMAINS",
        "REPAIR_PROVIDER_FAILURE_REMAINS",
    } <= _codes(verdict)


def test_covered_obligation_rows_and_closed_typed_debt_are_accepted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = _fixture(tmp_path, monkeypatch)
    _write_json(
        paths["scratchpad"] / "obligation_ledger.json",
        {
            "schema_version": "plamen.obligation_ledger.v1",
            "active_count": 0,
            "mode": "thorough",
            "obligations": [
                {
                    "id": "OBL-CHAIN-CH-1",
                    "class": "chain_upgrade_retention",
                    "status": "covered",
                    "closure_reason": "rendered as deferred chain note",
                }
            ],
            "row_count": 1,
        },
    )
    assert _verify(paths).accepted is True


def test_terminal_receipt_is_required_and_bound(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = _fixture(tmp_path, monkeypatch)
    (paths["scratchpad"] / "_driver_terminal_receipt.json").unlink()
    verdict = _verify(paths)
    assert verdict.accepted is False
    assert "DRIVER_TERMINAL_RECEIPT_MISSING_OR_INVALID" in _codes(verdict)


def test_missing_report_and_identity_mismatch_are_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = _fixture(tmp_path, monkeypatch)
    (paths["project"] / "AUDIT_REPORT.md").unlink()
    identity = json.loads(paths["identity"].read_text())
    identity["plamen_source_commit"] = "f" * 40
    _write_json(paths["identity"], identity)
    verdict = _verify(paths)
    assert verdict.accepted is False
    assert "TERMINAL_REPORT_INVALID" in _codes(verdict)
    assert "PLAMEN_SOURCE_COMMIT_MISMATCH" in _codes(verdict)


def test_duplicate_json_key_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    paths = _fixture(tmp_path, monkeypatch)
    paths["config"].write_text('{"mode":"thorough","mode":"thorough"}', encoding="utf-8")
    verdict = _verify(paths)
    assert verdict.accepted is False
    assert "CONFIG_INVALID" in _codes(verdict)


def test_provider_live_degraded_run_is_not_accepted(tmp_path: Path) -> None:
    """Optionally replay explicitly supplied, host-local degraded-run evidence.

    This is intentionally separate from the hermetic fixtures above.  CI and
    downstream contributors must never inherit one developer's home-directory
    layout or accidentally consume whatever audit happens to exist there.
    """

    required = {
        "project": "PLAMEN_E2E_DEGRADED_PROJECT",
        "installed": "PLAMEN_E2E_INSTALLED_ROOT",
        "source": "PLAMEN_E2E_SOURCE_ROOT",
    }
    supplied = {
        name: os.environ.get(variable, "").strip()
        for name, variable in required.items()
    }
    if not all(supplied.values()):
        pytest.skip(
            "provider-live degraded-run replay requires explicit "
            + ", ".join(required.values())
        )
    project = Path(supplied["project"]).expanduser().resolve(strict=True)
    scratchpad = project / ".scratchpad"
    if not scratchpad.is_dir():
        pytest.fail(f"explicit provider-live scratchpad is absent: {scratchpad}")
    checkpoint = json.loads((scratchpad / "_v2_checkpoint.json").read_text())
    snapshot = checkpoint["audit_snapshot"]
    components = snapshot["components"]
    installed = Path(supplied["installed"]).expanduser().resolve(strict=True)
    receipt = installed / ".plamen-posix-compat-v2-provenance.json"
    source = Path(supplied["source"]).expanduser().resolve(strict=True)
    target = project.parent
    receipt_obj = json.loads(receipt.read_text())
    identity = {
        "schema_version": V.IDENTITY_SCHEMA,
        "run_id": checkpoint["run_id"],
        "installed_package_root": str(installed),
        "installed_package_receipt": str(receipt.resolve()),
        "installed_package_receipt_sha256": _sha(receipt.read_bytes()),
        "installed_generation_receipt": str(receipt.resolve()),
        "installed_generation_receipt_sha256": _sha(receipt.read_bytes()),
        "installed_package_generation_sha256": receipt_obj["generation_sha256"],
        "plamen_source_root": str(source),
        "plamen_source_commit": V._git_head(source),
        "target_repository_root": str(target),
        "target_commit": V._git_head(target),
        "audit_snapshot_digest": snapshot["snapshot_digest"],
        "methodology_digest": components["methodology"]["digest"],
        "toolchain_digest": components["toolchain"]["digest"],
    }
    identity_path = tmp_path / "run-c-identity.json"
    _write_json(identity_path, identity)
    verdict = V.verify_sc_thorough_e2e(
        scratchpad=scratchpad,
        config_path=scratchpad / "config.json",
        project_root=project,
        expected_identity_path=identity_path,
    )
    assert verdict.accepted is False
    assert {
        "TERMINAL_EXIT_NOT_PROVEN",
        "PHASE_COMMITS_INCOMPLETE",
        "DEGRADATION_REMAINS",
        "RUNTIME_DEBT_REMAINS",
        "TARGET_SNAPSHOT_COMMIT_MISMATCH",
    } <= _codes(verdict)
