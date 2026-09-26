"""Registered present-source context survives later checkpoint progression.

This is a genuine deterministic DRIVER source/lifecycle transaction fixture.
It does not execute a depth MODEL or claim semantic audit completeness; the
real graph creates open lifecycle aliases, which must remain visible.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from artifact_ledger import read_artifact_ledger, write_artifact_ledger
import plamen_driver as D
import plamen_mechanical as M
import security_obligation_authority as A
import security_obligation_lifecycle as L
import security_obligation_phaseio_authority as C
from test_security_obligation_live_cutover_p1_c import (
    RUN_ID,
    SIDECARS,
    SNAPSHOT,
    _checkpoint,
    _config,
    _graph,
)


def _genuine_source(
    tmp_path: Path, *, backend: str = "claude"
):
    tmp_path.mkdir(parents=True, exist_ok=True)
    root = tmp_path / ".scratchpad"
    root.mkdir()
    _checkpoint(root)
    _graph(root)
    (root / A.RECON_FEATURE_FILE).write_text(
        json.dumps(
            {
                "schema_version": A.RECON_FEATURE_SCHEMA,
                "run_id": RUN_ID,
                "source_snapshot_digest": SNAPSHOT,
                "ecosystem": "evm",
                "facts": [],
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    checkpoint_payload = json.loads(
        (root / "_v2_checkpoint.json").read_text(
            encoding="utf-8", errors="strict"
        )
    )
    config = _config(root)
    config["cli_backend"] = backend
    config["_audit_snapshot"] = checkpoint_payload["audit_snapshot"]
    assert D._record_security_obligation_phase_io(
        root, config, stage=A.POST_DEPTH_STAGE
    ) == []
    assert D._validate_security_obligation_phase_io(
        root, config, stage=A.POST_DEPTH_STAGE
    ) == []
    return root, config


def _genuine_source_and_lifecycle(
    tmp_path: Path, *, backend: str = "claude"
):
    root, config = _genuine_source(tmp_path, backend=backend)
    assert D._record_security_obligation_lifecycle_phase_io(root, config) == [
        "security-obligation lifecycle retained unresolved/debt aliases "
        "for human review"
    ]
    assert D._validate_security_obligation_lifecycle_phase_io(root, config) == []
    authority = json.loads(
        (root / L.AUTHORITY_FILE).read_text(
            encoding="utf-8", errors="strict"
        )
    )
    assert authority["run_id"] == RUN_ID
    assert authority["rows"]
    assert authority["denominator_complete"] is False
    return root, config


def _observations(root: Path, names: tuple[str, ...]):
    paths = (*(root / name for name in names), root / "_artifact_state.json")
    return {
        path: (
            path.read_bytes(),
            path.stat().st_ino,
            path.stat().st_mtime_ns,
        )
        for path in paths
    }


@pytest.mark.parametrize("backend", ("codex", "claude"))
@pytest.mark.parametrize("snapshot_state", ("admitted", "missing", "changed"))
def test_reconciliation_transports_admitted_snapshot_to_lifecycle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    backend: str,
    snapshot_state: str,
) -> None:
    """Exercise config transport with genuine committed lifecycle validation.

    Only unrelated report-content gates are stubbed. The actual reconciliation,
    semantic dispatch, report-index branch, and lifecycle validator all run.
    Never recover missing context from checkpoint.
    """
    root, config = _genuine_source_and_lifecycle(tmp_path, backend=backend)
    checkpoint = D.Checkpoint.load(root)
    phase = D.Phase("report_index", [], [], base_timeout_s=60)
    checkpoint.completed = [phase.name]
    config["_active_model_attempts"] = {phase.name: 99}
    original_snapshot = json.loads(json.dumps(config["_audit_snapshot"]))
    if snapshot_state == "missing":
        config.pop("_audit_snapshot")
    elif snapshot_state == "changed":
        config["_audit_snapshot"] = json.loads(json.dumps(original_snapshot))
        config["_audit_snapshot"]["snapshot_digest"] = "c" * 64
    observed = []

    real_validator = D._validate_security_obligation_lifecycle_phase_io

    def validate_lifecycle(scratchpad, resume_config):
        assert "_active_model_attempts" not in resume_config
        assert resume_config["_run_id"] == RUN_ID
        observed.append(resume_config)
        return real_validator(scratchpad, resume_config)

    monkeypatch.setattr(
        D, "_validate_security_obligation_lifecycle_phase_io", validate_lifecycle
    )
    for name in (
        "_validate_report_index_inputs", "_check_index_completeness",
        "_validate_report_coverage_accounting",
    ):
        monkeypatch.setattr(D, name, lambda *_args, **_kwargs: [])
    removed = D._reconcile_completed_checkpoint_artifacts(
        root, config["project_root"], checkpoint, [phase], config["mode"],
        config["language"], config["pipeline"], backend, current_config=config,
    )
    assert observed
    if snapshot_state == "admitted":
        assert removed == []
        assert checkpoint.completed == [phase.name]
        transported = observed[0]["_audit_snapshot"]
        assert transported == original_snapshot
        assert transported is not config["_audit_snapshot"]
        assert transported["components"] is not config["_audit_snapshot"]["components"]
    else:
        assert removed == [phase.name]
        assert checkpoint.completed == []


@pytest.mark.parametrize("snapshot_state", ("admitted", "missing", "changed"))
def test_depth_resume_uses_current_context_not_checkpoint_fallback(
    tmp_path: Path, snapshot_state: str,
) -> None:
    root, config = _genuine_source(tmp_path)
    phase = D.Phase("depth", [], [], base_timeout_s=60)
    if snapshot_state == "missing":
        config.pop("_audit_snapshot")
    elif snapshot_state == "changed":
        config["_audit_snapshot"] = json.loads(json.dumps(config["_audit_snapshot"]))
        config["_audit_snapshot"]["snapshot_digest"] = "c" * 64
    issues = D._resume_semantic_issues(phase, config, root, tmp_path)
    if snapshot_state == "admitted":
        assert issues == []
    else:
        assert issues
        assert issues == sorted(set(D._validate_security_obligation_phase_io(
            root, config, stage=A.POST_DEPTH_STAGE
        )))


@pytest.mark.parametrize("backend", ("codex", "claude"))
def test_present_source_and_lifecycle_survive_later_checkpoint_save(
    tmp_path: Path,
    backend: str,
) -> None:
    root, config = _genuine_source_and_lifecycle(tmp_path, backend=backend)
    context = C.build_run_context_from_config(config, run_id=RUN_ID)
    source_inputs = A.security_obligation_input_artifacts(
        root,
        stage=A.POST_DEPTH_STAGE,
        run_context_authority=context,
    )
    lifecycle_inputs = L.security_obligation_lifecycle_input_artifacts(
        root, run_context_authority=context
    )
    assert "_v2_checkpoint.json" not in source_inputs
    assert "_v2_checkpoint.json" not in lifecycle_inputs
    source_contract, _ = D._security_obligation_contract_and_launch(
        root,
        config,
        stage=A.POST_DEPTH_STAGE,
        run_context=context,
    )
    lifecycle_contract, _ = D._security_obligation_lifecycle_contract_and_launch(
        root, config, run_context=context
    )
    ledger = read_artifact_ledger(root)
    for contract in (source_contract, lifecycle_contract):
        unit = ledger["work_units"][contract.key]
        assert unit["semantic_status"] == "ACTIVE"
        assert unit["execution_state"] == "OUTPUT_COMMITTED"
        assert unit["preexecution_authority"]["run_context"] == context

    retained = _observations(
        root,
        (*SIDECARS, L.AUTHORITY_FILE, L.PROJECTION_FILE, L.REPORT_RETENTION_FILE),
    )
    checkpoint = D.Checkpoint.load(root)
    assert "report_index" not in checkpoint.completed
    checkpoint.completed.append("report_index")
    checkpoint.save(root)

    assert D._validate_security_obligation_phase_io(
        root, config, stage=A.POST_DEPTH_STAGE
    ) == []
    assert D._validate_security_obligation_lifecycle_phase_io(root, config) == []
    appendix = M._security_obligation_appendix_projection(root)
    assert "security obligation lifecycle retention" in appendix.lower()
    assert "SOT-" not in appendix
    assert _observations(root, tuple(path.name for path in retained if path.name != "_artifact_state.json")) == retained


@pytest.mark.parametrize(
    "input_name", ("_mechanical_graph.json", A.RECON_FEATURE_FILE)
)
def test_present_source_context_rejects_semantic_input_drift(
    tmp_path: Path,
    input_name: str,
) -> None:
    root, config = _genuine_source_and_lifecycle(tmp_path)
    selected = root / input_name
    selected.write_bytes(selected.read_bytes() + b"\n")
    source_issues = D._validate_security_obligation_phase_io(
        root, config, stage=A.POST_DEPTH_STAGE
    )
    lifecycle_issues = D._validate_security_obligation_lifecycle_phase_io(
        root, config
    )
    assert source_issues
    assert lifecycle_issues
    assert "**Status**: UNKNOWN" in M._security_obligation_appendix_projection(root)


def test_present_source_context_rejects_stripped_extension(
    tmp_path: Path,
) -> None:

    root2, config2 = _genuine_source_and_lifecycle(tmp_path / "stripped")
    context = C.build_run_context_from_config(config2, run_id=RUN_ID)
    contract, _ = D._security_obligation_lifecycle_contract_and_launch(
        root2, config2, run_context=context
    )
    ledger = read_artifact_ledger(root2)
    unit = ledger["work_units"][contract.key]
    unit.pop("preexecution_authority")
    unit.pop("preexecution_authority_digest")
    write_artifact_ledger(root2, ledger)
    issues = D._validate_security_obligation_lifecycle_phase_io(root2, config2)
    assert issues
    assert any("preexecution authority" in issue for issue in issues)


def test_present_source_context_rejects_dimension_and_source_byte_drift(
    tmp_path: Path,
) -> None:
    root, config = _genuine_source_and_lifecycle(tmp_path)
    wrong = dict(config)
    wrong["mode"] = "core"
    assert D._validate_security_obligation_phase_io(
        root, wrong, stage=A.POST_DEPTH_STAGE
    )

    wrong_snapshot = dict(config)
    wrong_snapshot["_audit_snapshot"] = {
        "snapshot_digest": "c" * 64,
        "components": {"source_scope": {"digest": "d" * 64}},
    }
    assert D._validate_security_obligation_phase_io(
        root, wrong_snapshot, stage=A.POST_DEPTH_STAGE
    )

    wrong_backend = dict(config)
    wrong_backend["cli_backend"] = "codex"
    wrong_backend_issues = D._validate_security_obligation_phase_io(
        root, wrong_backend, stage=A.POST_DEPTH_STAGE
    )
    assert wrong_backend_issues
    assert any(
        "/codex/depth/security_obligations.post_depth" in issue
        and "no exact work-unit input record" in issue
        for issue in wrong_backend_issues
    )

    source = root / A.AUTHORITY_FILE
    source.write_bytes(source.read_bytes() + b"\n")
    assert D._validate_security_obligation_lifecycle_phase_io(root, config)


def test_unregistered_source_appearance_is_not_adopted_by_lifecycle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / ".scratchpad"
    root.mkdir()
    _checkpoint(root)
    _graph(root)
    checkpoint_payload = json.loads(
        (root / "_v2_checkpoint.json").read_text(
            encoding="utf-8", errors="strict"
        )
    )
    config = _config(root)
    config["_audit_snapshot"] = checkpoint_payload["audit_snapshot"]
    original = L.write_security_obligation_lifecycle
    invoked = False

    def source_appears_during_derivation(*args, **kwargs):
        nonlocal invoked
        if not invoked:
            invoked = True
            context = C.build_run_context_from_config(config, run_id=RUN_ID)
            A.write_security_obligation_authority(
                root,
                mode="thorough",
                ecosystem="evm",
                run_id=RUN_ID,
                source_snapshot_digest=SNAPSHOT,
                stage=A.POST_DEPTH_STAGE,
                run_context_authority=context,
            )
        return original(*args, **kwargs)

    monkeypatch.setattr(
        L, "write_security_obligation_lifecycle", source_appears_during_derivation
    )
    issues = D._record_security_obligation_lifecycle_phase_io(root, config)
    assert invoked is True
    assert any("registered security-obligation source is invalid" in issue for issue in issues)
    contract, _ = D._security_obligation_lifecycle_contract_and_launch(
        root,
        config,
        run_context=C.build_run_context_from_config(config, run_id=RUN_ID),
    )
    unit = read_artifact_ledger(root)["work_units"][contract.key]
    assert unit["semantic_status"] == "INPUTS_BOUND"
    assert unit["execution_state"] == "INPUTS_BOUND_PREEXECUTION"
    assert unit["artifacts"] == {}
    for name in (L.AUTHORITY_FILE, L.PROJECTION_FILE, L.REPORT_RETENTION_FILE):
        identity = f"scratchpad:{name}"
        assert identity not in read_artifact_ledger(root)["artifact_bindings"]


def test_source_output_before_commit_resume_preserves_armed_prestates(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / ".scratchpad"
    root.mkdir()
    _checkpoint(root)
    _graph(root)
    checkpoint_payload = json.loads(
        (root / "_v2_checkpoint.json").read_text(
            encoding="utf-8", errors="strict"
        )
    )
    config = _config(root)
    config["_audit_snapshot"] = checkpoint_payload["audit_snapshot"]
    original_commit = C.record_work_unit_artifacts

    def crash_before_commit(*_args, **_kwargs):
        raise OSError("fixture crash after source outputs")

    monkeypatch.setattr(C, "record_work_unit_artifacts", crash_before_commit)
    issues = D._record_security_obligation_phase_io(
        root, config, stage=A.POST_DEPTH_STAGE
    )
    assert any("fixture crash after source outputs" in issue for issue in issues)
    context = C.build_run_context_from_config(config, run_id=RUN_ID)
    contract, _ = D._security_obligation_contract_and_launch(
        root, config, stage=A.POST_DEPTH_STAGE, run_context=context
    )
    armed = read_artifact_ledger(root)["work_units"][contract.key]
    assert armed["execution_state"] == "INPUTS_BOUND_PREEXECUTION"
    assert all(
        row["status"] == "ABSENT"
        and row["existed"] is False
        and row["sha256"] == ""
        and row["size"] == 0
        for row in armed["output_prestates"].values()
    )
    retained_prestates = armed["output_prestates"]
    retained_bytes = {name: (root / name).read_bytes() for name in SIDECARS}

    monkeypatch.setattr(C, "record_work_unit_artifacts", original_commit)

    def reject_rearm(*_args, **_kwargs):
        raise AssertionError("exact armed recovery must not re-arm inputs")

    monkeypatch.setattr(C, "record_work_unit_inputs", reject_rearm)
    assert D._record_security_obligation_phase_io(
        root, config, stage=A.POST_DEPTH_STAGE
    ) == []
    committed = read_artifact_ledger(root)["work_units"][contract.key]
    assert committed["execution_state"] == "OUTPUT_COMMITTED"
    assert committed["output_prestates"] == retained_prestates
    assert {name: (root / name).read_bytes() for name in SIDECARS} == retained_bytes


def test_lifecycle_output_before_commit_resume_preserves_armed_prestates(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, config = _genuine_source(tmp_path / "seed")
    lifecycle_names = (
        L.AUTHORITY_FILE,
        L.PROJECTION_FILE,
        L.REPORT_RETENTION_FILE,
    )
    lifecycle_contract, _ = D._security_obligation_lifecycle_contract_and_launch(
        root,
        config,
        run_context=C.build_run_context_from_config(config, run_id=RUN_ID),
    )
    original_commit = C.record_work_unit_artifacts

    def crash_before_commit(*_args, **_kwargs):
        raise OSError("fixture crash after lifecycle outputs")

    monkeypatch.setattr(C, "record_work_unit_artifacts", crash_before_commit)
    issues = D._record_security_obligation_lifecycle_phase_io(root, config)
    assert any("fixture crash after lifecycle outputs" in issue for issue in issues)
    armed = read_artifact_ledger(root)["work_units"][lifecycle_contract.key]
    retained_prestates = armed["output_prestates"]
    retained_bytes = {
        name: (root / name).read_bytes() for name in lifecycle_names
    }
    assert armed["execution_state"] == "INPUTS_BOUND_PREEXECUTION"
    assert all(
        row["status"] == "ABSENT"
        and row["existed"] is False
        and row["sha256"] == ""
        and row["size"] == 0
        for row in retained_prestates.values()
    )

    monkeypatch.setattr(C, "record_work_unit_artifacts", original_commit)

    def reject_rearm(*_args, **_kwargs):
        raise AssertionError("exact armed recovery must not re-arm inputs")

    monkeypatch.setattr(C, "record_work_unit_inputs", reject_rearm)
    assert D._record_security_obligation_lifecycle_phase_io(root, config) == [
        "security-obligation lifecycle retained unresolved/debt aliases "
        "for human review"
    ]
    committed = read_artifact_ledger(root)["work_units"][lifecycle_contract.key]
    assert committed["execution_state"] == "OUTPUT_COMMITTED"
    assert committed["output_prestates"] == retained_prestates
    assert {
        name: (root / name).read_bytes() for name in lifecycle_names
    } == retained_bytes
