"""P1-C live-cutover acceptance fixtures for security obligations.

The typed feature/obligation authority is covered independently by
``test_typed_feature_facts_p1_c.py``.  These fixtures specify only the missing
runtime cutover: explicit live bindings, exact driver-owned PhaseIO
transactions, ownership transfer, read-only consumers, resume validation, and
write containment.  They are expected to remain red until that wiring lands.
"""
from __future__ import annotations

import inspect
import json
from pathlib import Path

import pytest

from artifact_ledger import (
    read_artifact_ledger,
    record_work_unit_artifacts,
    record_work_unit_inputs,
    validate_work_unit_artifacts,
)
from phase_io_contracts import (
    LaunchSpec,
    WriteObservation,
    resolve_phase_io_contract,
)
import plamen_driver as D
import plamen_mechanical as M
import plamen_prompt as P
import security_obligation_authority as A


RUN_ID = "12345678-1234-4234-9234-123456789abc"
SNAPSHOT = "a" * 64
SOURCE_SCOPE = "b" * 64
SIDECARS = (
    "security_feature_facts.json",
    "security_obligation_authority.json",
    "security_obligations.md",
)
SIDECAR_IDENTITIES = {f"scratchpad:{name}" for name in SIDECARS}
BASE = {
    "pipeline": "sc",
    "mode": "thorough",
    "ecosystem": "evm",
    "backend": "claude",
}


def _checkpoint(root: Path) -> None:
    payload = {
        "completed": ["recon", "instantiate", "breadth", "inventory"],
        "degraded": [],
        "rate_limited_at": None,
        "run_id": RUN_ID,
        "config": {
            "pipeline": "sc",
            "language": "evm",
            "mode": "thorough",
        },
        "audit_snapshot": {
            "schema": "plamen.audit-input-snapshot.v1",
            "snapshot_digest": SNAPSHOT,
            "components": {"source_scope": {"digest": SOURCE_SCOPE}},
        },
    }
    (root / "_v2_checkpoint.json").write_text(
        json.dumps(payload, sort_keys=True), encoding="utf-8"
    )


def _graph(root: Path) -> None:
    payload = {
        "schema_version": "plamen.mechanical-graph.v2",
        "source": "evm-source",
        "functions": {
            "bridge::refund_transfer_asset_to_recipient": {
                "bare": "refund_transfer_asset_to_recipient",
                "loc": "src/Bridge.sol:L21",
                "callers": [],
                "callees": ["token.transfer (src/Token.sol:L4)"],
            }
        },
        "var_refs": {
            "bridge.asset_balance": {
                "bare": "asset_balance",
                "refs": [
                    "refund_transfer_asset_to_recipient (src/Bridge.sol:L21)"
                ],
            }
        },
        "state_symbols": [],
    }
    (root / "_mechanical_graph.json").write_text(
        json.dumps(payload, sort_keys=True), encoding="utf-8"
    )


def _config(root: Path) -> dict[str, object]:
    return {
        "pipeline": "sc",
        "mode": "thorough",
        "language": "evm",
        "cli_backend": "claude",
        "scratchpad": str(root),
        "project_root": str(root.parent),
        "_run_id": RUN_ID,
        "_audit_snapshot": {"snapshot_digest": SNAPSHOT},
    }


def _contract(stage: str, *, exact_inputs: tuple[str, ...] = ()):
    return resolve_phase_io_contract(
        **BASE,
        phase="depth",
        work_unit_id=f"security_obligations.{stage}",
        exact_inputs=exact_inputs,
    )


def _launch(contract) -> LaunchSpec:
    return LaunchSpec(
        work_unit_key=contract.key,
        pipeline=contract.pipeline,
        mode=contract.mode,
        ecosystem=contract.ecosystem,
        backend=contract.backend,
        model="driver",
        timeout_s=120,
        exec_mode="python",
        tool_policy=("filesystem",),
    )


def test_wrapper_requires_and_forwards_explicit_live_bindings(
    tmp_path: Path, monkeypatch,
) -> None:
    captured: dict[str, object] = {}

    def fake_writer(scratchpad: Path, **kwargs: object) -> dict[str, object]:
        captured["scratchpad"] = Path(scratchpad)
        captured.update(kwargs)
        return {"obligations": [{"display_id": "SO-001"}]}

    monkeypatch.setattr(M, "_write_security_obligation_authority", fake_writer)

    count = M._write_security_obligations(
        tmp_path,
        "thorough",
        ecosystem="evm",
        run_id=RUN_ID,
        source_snapshot_digest=SNAPSHOT,
        stage="pre_depth",
    )

    assert count == 1
    assert captured == {
        "scratchpad": tmp_path,
        "mode": "thorough",
        "ecosystem": "evm",
        "run_id": RUN_ID,
        "source_snapshot_digest": SNAPSHOT,
        "stage": "pre_depth",
    }


def test_pre_and_post_depth_are_two_exact_driver_only_phase_io_units() -> None:
    pre = _contract(
        "pre_depth",
        exact_inputs=("_mechanical_graph.json", "recon_feature_facts.json"),
    )
    post = _contract(
        "post_depth",
        exact_inputs=(
            "_mechanical_graph.json",
            "recon_feature_facts.json",
            "_depth_worker_pool_contract.json",
            "depth_state_trace_findings.md",
            "security_obligation_application_receipt.json",
        ),
    )

    assert pre.key.endswith("/depth/security_obligations.pre_depth")
    assert post.key.endswith("/depth/security_obligations.post_depth")
    assert pre.key != post.key
    for contract in (pre, post):
        assert contract.model_invoked is False
        assert {spec.identity for spec in contract.outputs} == SIDECAR_IDENTITIES
        assert {spec.writer for spec in contract.outputs} == {"DRIVER"}
        assert {spec.artifact_class for spec in contract.outputs} == {
            "DRIVER_GENERATED"
        }
        assert {spec.write_mode for spec in contract.outputs} == {"REPLACE"}

    expected_schema = {
        "security_feature_facts.json": A.FEATURE_FACT_SCHEMA,
        "security_obligation_authority.json": A.OBLIGATION_SCHEMA,
        "security_obligations.md": "plamen.security_obligation_projection.v1",
    }
    expected_gate = {
        "security_feature_facts.json": "EXACT_TYPED_FACT_REDERIVATION",
        "security_obligation_authority.json": (
            "EXACT_OBLIGATION_RECEIPT_RECONCILIATION"
        ),
        "security_obligations.md": "EXACT_AUTHORITY_PROJECTION",
    }
    assert {spec.path: spec.schema_version for spec in post.outputs} == expected_schema
    assert {spec.path: spec.minimum_gate for spec in post.outputs} == expected_gate
    assert set(pre.immutable_inputs) == {
        "scratchpad:_mechanical_graph.json",
        "scratchpad:recon_feature_facts.json",
    }
    assert set(post.immutable_inputs) == {
        "scratchpad:_mechanical_graph.json",
        "scratchpad:recon_feature_facts.json",
        "scratchpad:_depth_worker_pool_contract.json",
        "scratchpad:depth_state_trace_findings.md",
        "scratchpad:security_obligation_application_receipt.json",
    }
    with pytest.raises(ValueError, match="selected artifact-state rows"):
        _contract(
            "post_depth",
            exact_inputs=("_artifact_state.json",),
        )


def test_post_depth_ownership_transfer_preserves_pre_depth_history(
    tmp_path: Path,
) -> None:
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()

    pre = _contract("pre_depth")
    record_work_unit_inputs(
        scratchpad,
        tmp_path,
        pre,
        _launch(pre),
        run_id=RUN_ID,
    )
    for name in SIDECARS:
        (scratchpad / name).write_text(f"pre:{name}\n", encoding="utf-8")

    record_work_unit_artifacts(
        scratchpad,
        tmp_path,
        pre,
        _launch(pre),
        run_id=RUN_ID,
        actor="DRIVER",
    )

    post = _contract("post_depth")
    record_work_unit_inputs(
        scratchpad,
        tmp_path,
        post,
        _launch(post),
        run_id=RUN_ID,
    )
    for name in SIDECARS:
        (scratchpad / name).write_text(f"post:{name}\n", encoding="utf-8")
    record_work_unit_artifacts(
        scratchpad,
        tmp_path,
        post,
        _launch(post),
        run_id=RUN_ID,
        actor="DRIVER",
    )

    ledger = read_artifact_ledger(scratchpad)
    assert {pre.key, post.key} <= set(ledger["work_units"])
    for identity in SIDECAR_IDENTITIES:
        binding = ledger["artifact_bindings"][identity]
        assert binding["owner_key"] == post.key
        assert any(row["owner_key"] == pre.key for row in binding["history"])
    assert validate_work_unit_artifacts(
        scratchpad,
        tmp_path,
        post,
        _launch(post),
        run_id=RUN_ID,
        actor="DRIVER",
    ) == []


def test_depth_attention_and_report_model_contracts_treat_sidecars_as_immutable() -> None:
    depth = resolve_phase_io_contract(
        **BASE,
        phase="depth",
        work_unit_id="worker.state_trace",
        exact_outputs=("depth_state_trace_findings.md",),
    )
    attention = resolve_phase_io_contract(
        **BASE,
        phase="attention_repair",
        work_unit_id="model",
        exact_outputs=(
            "attention_repair_summary.md",
            "attention_repair_findings.md",
        ),
        conditional_output_ids=("attention_repair_findings.md",),
        condition_id="attention_repair_confirmed_findings_present",
    )
    report = resolve_phase_io_contract(
        **BASE,
        phase="report_index",
        work_unit_id="model",
    )

    for contract in (depth, attention, report):
        assert SIDECAR_IDENTITIES <= set(contract.immutable_inputs)
        assert not (SIDECAR_IDENTITIES & {spec.identity for spec in contract.outputs})
        result = contract.validate_writes(
            tuple(
                WriteObservation.changed("scratchpad", name)
                for name in SIDECARS
            ),
            actor="MODEL",
        )
        assert not result.ok
        assert {
            violation.identity
            for violation in result.violations
            if violation.code == "IMMUTABLE_INPUT_WRITE"
        } == SIDECAR_IDENTITIES


def test_post_depth_live_helper_validates_exact_authority_and_tamper_on_resume(
    tmp_path: Path,
) -> None:
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    _checkpoint(scratchpad)
    _graph(scratchpad)
    config = _config(scratchpad)

    record = getattr(D, "_record_security_obligation_phase_io")
    validate = getattr(D, "_validate_security_obligation_phase_io")
    assert record(scratchpad, config, stage="post_depth") == []
    assert validate(scratchpad, config, stage="post_depth") == []

    authority_path = scratchpad / A.AUTHORITY_FILE
    payload = json.loads(authority_path.read_text(encoding="utf-8"))
    payload["status"] = "TAMPERED"
    authority_path.write_text(json.dumps(payload), encoding="utf-8")

    issues = validate(scratchpad, config, stage="post_depth")
    assert issues
    assert any(
        "differs from current inputs" in issue
        or "content hash changed" in issue
        for issue in issues
    )
    resume_source = inspect.getsource(D._resume_phase_contract_issues)
    assert "_validate_security_obligation_phase_io" in resume_source
    assert "phase.name == \"depth\"" in resume_source


def test_post_depth_crash_after_output_before_commit_reuses_armed_receipt(
    tmp_path: Path,
) -> None:
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    _checkpoint(scratchpad)
    _graph(scratchpad)
    config = _config(scratchpad)
    exact_inputs = A.security_obligation_input_artifacts(
        scratchpad, stage="post_depth"
    )
    contract, launch = D._security_obligation_contract_and_launch(
        scratchpad,
        config,
        stage="post_depth",
        exact_inputs=exact_inputs,
    )
    record_work_unit_inputs(
        scratchpad,
        tmp_path,
        contract,
        launch,
        run_id=RUN_ID,
    )
    A.write_security_obligation_authority(
        scratchpad,
        mode="thorough",
        ecosystem="evm",
        run_id=RUN_ID,
        source_snapshot_digest=SNAPSHOT,
        stage="post_depth",
    )

    assert D._record_security_obligation_phase_io(
        scratchpad, config, stage="post_depth"
    ) == []
    first = read_artifact_ledger(scratchpad)["work_units"][contract.key]
    assert first["semantic_status"] == "ACTIVE"
    assert D._record_security_obligation_phase_io(
        scratchpad, config, stage="post_depth"
    ) == []
    second = read_artifact_ledger(scratchpad)["work_units"][contract.key]
    assert second == first


def test_live_writer_is_pre_depth_and_post_depth_only_not_attention_or_report() -> None:
    source = inspect.getsource(D.run_phase)
    assert 'phase.name in {"depth", "attention_repair", "report_index"}' not in source
    assert source.count("_write_security_obligations(") == 0

    main_source = inspect.getsource(D.main)
    assert "_record_security_obligation_phase_io" in main_source
    assert 'stage="pre_depth"' in main_source
    assert 'stage="post_depth"' in main_source
    for phase_name in ("attention_repair", "report_index"):
        phase_at = main_source.find(f'phase.name == "{phase_name}"')
        if phase_at >= 0:
            nearby = main_source[phase_at : phase_at + 1200]
            assert "_write_security_obligations(" not in nearby


def test_sidecars_are_explicitly_known_and_protected_from_model_outputs() -> None:
    legitimate = P._LEGITIMATE_SUBPRODUCER_PATTERNS
    assert set(SIDECARS) <= set(legitimate)

    depth = resolve_phase_io_contract(
        **BASE,
        phase="depth",
        work_unit_id="worker.validation_sweep",
        exact_outputs=("validation_sweep_findings.md",),
    )
    result = depth.validate_writes(
        (
            WriteObservation.changed(
                "scratchpad", "security_obligation_authority.json"
            ),
            WriteObservation.changed("scratchpad", "validation_sweep_findings.md"),
        ),
        actor="MODEL",
    )
    assert {violation.code for violation in result.violations} == {
        "IMMUTABLE_INPUT_WRITE"
    }
    assert result.allowed == ("scratchpad:validation_sweep_findings.md",)
