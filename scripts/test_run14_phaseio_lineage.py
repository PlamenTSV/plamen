"""Focused regressions for Run14 producer and launch lineage failures."""
from __future__ import annotations

from pathlib import Path
import hashlib

import pytest

import artifact_ledger as AL
import phase_io_contracts as P
import plamen_driver as D
import posix_v2_compat_runtime as compat
from plamen_types import Phase


_PROJECTION_OUTPUTS = (
    "evm_analysis_projection_receipt.v1.json",
    "evm_tool_materialization_lineage.v2.json",
)


def _projection_contract(
    *,
    exact_outputs: tuple[str, ...] = _PROJECTION_OUTPUTS,
    **overrides: str,
) -> P.PhaseIOContract:
    dimensions = {
        "pipeline": "sc",
        "mode": "thorough",
        "ecosystem": "evm",
        "backend": "codex",
    }
    dimensions.update(overrides)
    return P.resolve_phase_io_contract(
        **dimensions,
        phase="recon",
        work_unit_id="evm_analysis_projection_capture",
        exact_inputs=(),
        exact_outputs=exact_outputs,
        exact_writer="DRIVER",
    )


def test_evm_projection_capture_has_closed_driver_contract_and_launch() -> None:
    contract = _projection_contract()
    assert contract.model_invoked is False
    assert contract.launch_profile == "DRIVER_PYTHON_NO_TOOLS"
    assert contract.required_commit_actor == "DRIVER"
    assert contract.immutable_inputs == ()
    assert tuple(output.path for output in contract.outputs) == _PROJECTION_OUTPUTS
    assert tuple(output.schema_version for output in contract.outputs) == (
        "plamen.private-analysis-projection-custody.v1",
        "plamen.evm-tool-materialization-lineage.v2",
    )
    for output in contract.outputs:
        assert (
            output.artifact_class,
            output.writer,
            output.write_mode,
            output.minimum_gate,
            output.consumers,
        ) == (
            "DRIVER_GENERATED",
            "DRIVER",
            "CREATE",
            "NATIVE_PROJECTION_SNAPSHOT_AND_DESCRIPTOR_LINEAGE_BOUND",
            (
                "recon/evm_analysis_workspace_capture",
                "recon/prepass",
                "recon/program_facts_bake",
            ),
        )

    launch = P.resolve_program_facts_registered_launch(contract)
    assert (launch.model, launch.timeout_s, launch.exec_mode, launch.tool_policy) == (
        "driver", 30, "python", (),
    )
    replayed_contract, replayed_launch = P.replay_phase_io_authority_pair(
        contract, launch
    )
    assert replayed_contract.digest == contract.digest
    assert replayed_launch.digest == launch.digest

    drifted = P.LaunchSpec(
        work_unit_key=contract.key,
        pipeline=contract.pipeline,
        mode=contract.mode,
        ecosystem=contract.ecosystem,
        backend=contract.backend,
        model="driver",
        timeout_s=31,
        exec_mode="python",
        tool_policy=(),
    )
    with pytest.raises(ValueError, match="closed model-free launch"):
        P.replay_phase_io_authority_pair(contract, drifted)
    with pytest.raises(ValueError, match="SC/EVM"):
        _projection_contract(ecosystem="solana")


@pytest.mark.parametrize(
    "outputs",
    (
        ("evm_analysis_projection_receipt.v1.json",),
        ("evm_tool_materialization_lineage.v2.json",),
        (*_PROJECTION_OUTPUTS, "unregistered.json"),
        (*_PROJECTION_OUTPUTS, _PROJECTION_OUTPUTS[0]),
    ),
)
def test_evm_projection_capture_rejects_missing_extra_or_duplicate_output(
    outputs: tuple[str, ...],
) -> None:
    with pytest.raises(ValueError, match="exact output denominator|duplicate"):
        _projection_contract(exact_outputs=outputs)


def _projection_launch(contract: P.PhaseIOContract) -> P.LaunchSpec:
    return P.resolve_program_facts_registered_launch(contract)


def _projection_records(payloads: dict[str, bytes]) -> dict[str, dict[str, object]]:
    return {
        f"scratchpad:{name}": {
            "sha256": hashlib.sha256(raw).hexdigest(),
            "size": len(raw),
        }
        for name, raw in payloads.items()
    }


def test_evm_projection_atomic_vector_rejects_postcommit_sibling_tamper(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    scratch = project / ".scratchpad"
    scratch.mkdir(parents=True)
    contract = _projection_contract()
    launch = _projection_launch(contract)
    run_id = "projection-tamper"
    payloads = {
        _PROJECTION_OUTPUTS[0]: b'{"receipt":"bound"}',
        _PROJECTION_OUTPUTS[1]: b'{"lineage":"bound"}',
    }
    AL.record_work_unit_inputs(
        scratch, project, contract, launch, run_id=run_id
    )
    for name, raw in payloads.items():
        (scratch / name).write_bytes(raw)
    AL.record_work_unit_artifacts(
        scratch,
        project,
        contract,
        launch,
        run_id=run_id,
        actor="DRIVER",
        expected_output_records=_projection_records(payloads),
    )
    assert AL.validate_work_unit_artifacts(
        scratch, project, contract, launch, run_id=run_id, actor="DRIVER"
    ) == []

    (scratch / _PROJECTION_OUTPUTS[1]).write_bytes(b'{"lineage":"tampered"}')
    issues = AL.validate_work_unit_artifacts(
        scratch, project, contract, launch, run_id=run_id, actor="DRIVER"
    )
    assert any(
        _PROJECTION_OUTPUTS[1] in issue and "differ" in issue.lower()
        for issue in issues
    )


def test_evm_projection_crash_after_first_output_resumes_same_armed_vector(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    scratch = project / ".scratchpad"
    scratch.mkdir(parents=True)
    contract = _projection_contract()
    launch = _projection_launch(contract)
    run_id = "projection-crash-resume"
    payloads = {
        _PROJECTION_OUTPUTS[0]: b'{"receipt":"bound"}',
        _PROJECTION_OUTPUTS[1]: b'{"lineage":"bound"}',
    }
    AL.record_work_unit_inputs(
        scratch, project, contract, launch, run_id=run_id
    )
    (scratch / _PROJECTION_OUTPUTS[0]).write_bytes(payloads[_PROJECTION_OUTPUTS[0]])

    # Simulated process death: the first exact output exists but no output
    # commit was attempted.  Replay retains the same INPUTS_BOUND row.
    row = AL.read_artifact_ledger(scratch)["work_units"][contract.key]
    assert row["semantic_status"] == "INPUTS_BOUND"
    assert row["artifacts"] == {}
    assert AL.validate_work_unit_inputs(
        scratch, project, contract, launch, run_id=run_id
    ) == []

    (scratch / _PROJECTION_OUTPUTS[1]).write_bytes(payloads[_PROJECTION_OUTPUTS[1]])
    committed = AL.record_work_unit_artifacts(
        scratch,
        project,
        contract,
        launch,
        run_id=run_id,
        actor="DRIVER",
        expected_output_records=_projection_records(payloads),
    )
    assert (committed["semantic_status"], committed["execution_state"]) == (
        "ACTIVE", "OUTPUT_COMMITTED",
    )
    assert set(committed["artifacts"]) == {
        f"scratchpad:{name}" for name in _PROJECTION_OUTPUTS
    }


def test_depth_transaction_debt_demotes_phase_gate() -> None:
    passed, missing = D._enforce_depth_additive_transaction_gate(
        True,
        ["prior telemetry"],
        {
            "status": "DEGRADED_HUMAN_REVIEW",
            "failed_processors": ["transaction"],
            "transaction_issues": ["injected after_output_2"],
        },
    )
    assert passed is False
    assert missing == [
        "prior telemetry",
        "depth additive successor transaction: injected after_output_2",
    ]

    passed, missing = D._enforce_depth_additive_transaction_gate(
        True,
        [],
        {"status": "FINALIZED", "failed_processors": []},
    )
    assert passed is True
    assert missing == []


@pytest.mark.skipif(D.os.name != "posix", reason="POSIX compatibility lane")
def test_posix_codex_exec_uses_sealed_leaf_model_and_timeout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Parent-policy drift cannot alter an already INPUTS_BOUND launch."""

    project = tmp_path / "project"
    scratch = project / ".scratchpad"
    scratch.mkdir(parents=True)
    for name in (
        "exploration_clear_repair_plan.json",
        "exploration_clear_repair_attempt.json",
    ):
        (scratch / name).write_text("{}\n", encoding="utf-8")
    config = {
        "project_root": str(project),
        "pipeline": "sc",
        "mode": "thorough",
        "language": "evm",
        "cli_backend": "codex",
        "_run_id": "12345678-1234-4567-8abc-1234567890ab",
    }
    phase = Phase(
        "exploration_clear",
        ["repair"],
        ["exploration_clear_repair_response.md"],
        base_timeout_s=3600,
        model="gpt-5.6-terra",
        needs_mcp=False,
        modes={"thorough"},
        critical=False,
    )
    contract, launch = D._exploration_clear_contract_launch(
        phase=phase,
        config=config,
        work_unit_id="worker.0001",
        exact_outputs=("exploration_clear_repair_response.md",),
        exact_inputs=(
            "exploration_clear_repair_plan.json",
            "exploration_clear_repair_attempt.json",
        ),
        actor="MODEL",
        model="gpt-5.6-terra",
        timeout_s=3600,
    )
    AL.record_work_unit_inputs(
        scratch, project, contract, launch, run_id=config["_run_id"]
    )

    observed: dict[str, object] = {}

    def fake_compat(**kwargs: object) -> int:
        observed.update(kwargs)
        (scratch / "_stdio_exploration_clear_repair.attempt1.log").write_text(
            "sealed launch reached compatibility runtime\n", encoding="utf-8"
        )
        return 0

    monkeypatch.setattr(D, "_posix_v2_compat_process_active", lambda: True)
    monkeypatch.setattr(D, "_posix_v2_compat_session_for_launch", object)
    monkeypatch.setattr(compat, "run_codex_exec", fake_compat)
    rc = D._run_one_codex_exec(
        prompt="repair",
        phase=phase,
        config=config,
        scratchpad=scratch,
        attempt=1,
        label="exploration_clear_repair",
        expected_outputs=["exploration_clear_repair_response.md"],
        # Fault injection: these parent/caller values disagree with the leaf.
        timeout=77,
        effective_model="parent-policy-drift",
        phase_io_contract=contract,
        phase_io_launch=launch,
    )
    assert rc == 0
    assert observed["phase_name"] == "exploration_clear"
    assert observed["effective_model"] == launch.model
    assert observed["timeout"] == float(launch.timeout_s)
    assert observed["phase_io_contract"] is contract
    assert observed["phase_io_launch"] is launch
