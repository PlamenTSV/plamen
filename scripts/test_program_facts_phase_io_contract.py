from __future__ import annotations

from dataclasses import replace
import hashlib
import os
from pathlib import Path

import pytest

from artifact_ledger import (
    ArtifactLedgerError,
    read_artifact_ledger,
    record_work_unit_artifacts,
    record_work_unit_inputs,
    semantic_input_prebind_producer_authority_issues,
    validate_work_unit_artifacts,
)
from phase_io_contracts import (
    ArtifactSpec,
    LaunchSpec,
    PhaseIOContract,
    canonical_work_unit_key,
    resolve_phase_io_contract,
)


OUTPUTS = (
    "mechanical_program_facts.v1.json",
    "mechanical_program_facts_receipt.v1.json",
    "mechanical_program_facts_debt.v1.json",
)

CHECKPOINT_CAPTURE = "_program_facts_inputs/checkpoint_capture.v1.json"
CORE_INPUTS = (
    CHECKPOINT_CAPTURE,
    "_program_facts_methodology/program-facts-methodology-package.v1.json",
    "_program_facts_methodology/program-facts-provider-registry.v1.json",
    "_program_facts_methodology/schemas/mechanical_program_facts.v1.schema.json",
    "_program_facts_methodology/schemas/mechanical_program_facts_receipt.v1.schema.json",
    "_program_facts_methodology/schemas/mechanical_program_facts_debt.v1.schema.json",
    "_program_facts_methodology/schemas/program_facts_provider_registry.v1.schema.json",
    "_program_facts_methodology/schemas/program_facts_disagreement.v1.schema.json",
    "_program_facts_methodology/schemas/program_facts_slice.v1.schema.json",
)
METHODOLOGY_OUTPUTS = CORE_INPUTS[1:]


def _resolve(
    *,
    pipeline: str = "sc",
    ecosystem: str = "evm",
    backend: str = "claude",
    exact_inputs: tuple[str, ...] = CORE_INPUTS,
    exact_outputs: tuple[str, ...] = OUTPUTS,
    **overrides: object,
):
    values: dict[str, object] = {
        "pipeline": pipeline,
        "mode": "thorough",
        "ecosystem": ecosystem,
        "backend": backend,
        "phase": "recon",
        "work_unit_id": "program_facts_bake",
        "exact_inputs": exact_inputs,
        "exact_outputs": exact_outputs,
    }
    values.update(overrides)
    return resolve_phase_io_contract(**values)


def _resolve_methodology_capture(
    *,
    pipeline: str = "sc",
    ecosystem: str = "evm",
    backend: str = "claude",
    exact_inputs: tuple[str, ...] = (CHECKPOINT_CAPTURE,),
    exact_outputs: tuple[str, ...] = METHODOLOGY_OUTPUTS,
    **overrides: object,
):
    values: dict[str, object] = {
        "pipeline": pipeline,
        "mode": "thorough",
        "ecosystem": ecosystem,
        "backend": backend,
        "phase": "recon",
        "work_unit_id": "program_facts_methodology_capture",
        "exact_inputs": exact_inputs,
        "exact_outputs": exact_outputs,
    }
    values.update(overrides)
    return resolve_phase_io_contract(**values)


def _resolve_checkpoint_capture(
    *,
    pipeline: str = "sc",
    ecosystem: str = "evm",
    backend: str = "claude",
    mode: str = "thorough",
):
    return resolve_phase_io_contract(
        pipeline=pipeline,
        mode=mode,
        ecosystem=ecosystem,
        backend=backend,
        phase="recon",
        work_unit_id="program_facts_checkpoint_capture",
        exact_inputs=(),
        exact_outputs=(CHECKPOINT_CAPTURE,),
        exact_writer="DRIVER",
    )


def _launch(contract) -> LaunchSpec:
    return LaunchSpec(
        work_unit_key=contract.key,
        pipeline=contract.pipeline,
        mode=contract.mode,
        ecosystem=contract.ecosystem,
        backend=contract.backend,
        model="driver",
        timeout_s=30,
        exec_mode="python",
    )


def _write_inputs(scratchpad: Path, paths: tuple[str, ...]) -> None:
    for path in paths:
        target = scratchpad / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(b"{}\n")


def _expected_output_records(
    scratchpad: Path,
    contract: PhaseIOContract,
) -> dict[str, dict[str, object]]:
    records: dict[str, dict[str, object]] = {}
    for output in contract.outputs:
        assert output.root == "scratchpad"
        raw = (scratchpad / output.path).read_bytes()
        records[output.identity] = {
            "sha256": hashlib.sha256(raw).hexdigest(),
            "size": len(raw),
        }
    return records


def _commit_capture(
    scratchpad: Path,
    project_root: Path,
    *,
    run_id: str,
):
    _commit_checkpoint_capture(
        scratchpad,
        project_root,
        run_id=run_id,
    )
    capture = _resolve_methodology_capture()
    launch = _launch(capture)
    record_work_unit_inputs(
        scratchpad,
        project_root,
        capture,
        launch,
        run_id=run_id,
    )
    _write_inputs(scratchpad, METHODOLOGY_OUTPUTS)
    unit = record_work_unit_artifacts(
        scratchpad,
        project_root,
        capture,
        launch,
        run_id=run_id,
        actor="DRIVER",
        expected_output_records=_expected_output_records(
            scratchpad, capture
        ),
    )
    assert unit["semantic_status"] == "ACTIVE", unit[
        "commit_authority"
    ]["reason_codes"]
    return capture, launch


def _commit_checkpoint_capture(
    scratchpad: Path,
    project_root: Path,
    *,
    run_id: str,
):
    capture = _resolve_checkpoint_capture()
    launch = _launch(capture)
    record_work_unit_inputs(
        scratchpad,
        project_root,
        capture,
        launch,
        run_id=run_id,
    )
    _write_inputs(scratchpad, (CHECKPOINT_CAPTURE,))
    unit = record_work_unit_artifacts(
        scratchpad,
        project_root,
        capture,
        launch,
        run_id=run_id,
        actor="DRIVER",
        expected_output_records=_expected_output_records(
            scratchpad,
            capture,
        ),
    )
    assert unit["semantic_status"] == "ACTIVE", unit[
        "commit_authority"
    ]["reason_codes"]
    return capture, launch


def _claim_inputs(
    scratchpad: Path,
    project_root: Path,
    paths: tuple[str, ...],
    *,
    run_id: str,
    writer: str,
) -> tuple[PhaseIOContract, LaunchSpec]:
    owner = canonical_work_unit_key(
        "sc",
        "thorough",
        "evm",
        "claude",
        "recon",
        f"fixture_{writer.lower()}_input_producer",
    )
    contract = PhaseIOContract(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        phase="recon",
        work_unit_id=f"fixture_{writer.lower()}_input_producer",
        outputs=tuple(
            ArtifactSpec(
                root="scratchpad",
                path=path,
                owner_key=owner,
                artifact_class=(
                    "DRIVER_GENERATED" if writer == "DRIVER" else "REQUIRED"
                ),
                writer=writer,
                write_mode="CREATE",
            )
            for path in paths
        ),
        model_invoked=writer == "MODEL",
    )
    launch = LaunchSpec(
        work_unit_key=contract.key,
        pipeline=contract.pipeline,
        mode=contract.mode,
        ecosystem=contract.ecosystem,
        backend=contract.backend,
        model="fixture-model" if writer == "MODEL" else "fixture-driver",
        timeout_s=30,
        exec_mode="pty" if writer == "MODEL" else "python",
        tool_policy=("filesystem",),
    )
    record_work_unit_inputs(
        scratchpad,
        project_root,
        contract,
        launch,
        run_id=run_id,
    )
    _write_inputs(scratchpad, paths)
    unit = record_work_unit_artifacts(
        scratchpad,
        project_root,
        contract,
        launch,
        run_id=run_id,
        actor=writer,
        expected_output_records=_expected_output_records(
            scratchpad, contract
        ),
    )
    assert unit["semantic_status"] == "ACTIVE", unit[
        "commit_authority"
    ]["reason_codes"]
    return contract, launch


@pytest.mark.parametrize(
    ("pipeline", "ecosystem", "backend"),
    (
        ("sc", "evm", "claude"),
        ("sc", "solana", "codex"),
        ("sc", "soroban", "claude"),
        ("sc", "aptos", "codex"),
        ("sc", "sui", "claude"),
        ("l1", "go", "codex"),
        ("l1", "rust", "claude"),
        ("l1", "daml", "codex"),
    ),
)
def test_methodology_capture_is_exact_driver_owned_bake_predecessor(
    pipeline: str,
    ecosystem: str,
    backend: str,
) -> None:
    contract = _resolve_methodology_capture(
        pipeline=pipeline,
        ecosystem=ecosystem,
        backend=backend,
    )
    assert contract.model_invoked is False
    assert contract.immutable_inputs == (
        f"scratchpad:{CHECKPOINT_CAPTURE}",
    )
    assert tuple(output.path for output in contract.outputs) == (
        METHODOLOGY_OUTPUTS
    )
    assert {output.artifact_class for output in contract.outputs} == {
        "DRIVER_GENERATED"
    }
    assert {output.writer for output in contract.outputs} == {"DRIVER"}
    assert {output.write_mode for output in contract.outputs} == {"CREATE"}
    assert all(
        "recon/program_facts_bake" in output.consumers
        for output in contract.outputs
    )
    assert contract.launch_profile == "DRIVER_PYTHON_NO_TOOLS"
    assert contract.required_commit_actor == "DRIVER"
    assert len(contract.input_authority_requirements) == 1
    checkpoint = contract.input_authority_requirements[0]
    assert checkpoint.identity == f"scratchpad:{CHECKPOINT_CAPTURE}"
    assert checkpoint.allow_raw is False
    checkpoint_capture = _resolve_checkpoint_capture(
        pipeline=pipeline,
        ecosystem=ecosystem,
        backend=backend,
    )
    assert checkpoint.expected_producer_work_unit_key == (
        checkpoint_capture.key
    )
    assert checkpoint.expected_writer == "DRIVER"
    assert checkpoint.require_same_run is True
    assert checkpoint.expected_contract_digest == checkpoint_capture.digest
    assert checkpoint.expected_launch_digest == (
        _launch(checkpoint_capture).digest
    )


@pytest.mark.parametrize(
    ("exact_inputs", "exact_outputs"),
    (
        ((), METHODOLOGY_OUTPUTS),
        ((CHECKPOINT_CAPTURE, "unowned.json"), METHODOLOGY_OUTPUTS),
        ((CHECKPOINT_CAPTURE,), METHODOLOGY_OUTPUTS[:-1]),
        (
            (CHECKPOINT_CAPTURE,),
            METHODOLOGY_OUTPUTS + ("_program_facts_methodology/extra.json",),
        ),
    ),
)
def test_methodology_capture_rejects_denominator_drift(
    exact_inputs: tuple[str, ...],
    exact_outputs: tuple[str, ...],
) -> None:
    with pytest.raises(
        ValueError,
        match="registered immutable|exact output",
    ):
        _resolve_methodology_capture(
            exact_inputs=exact_inputs,
            exact_outputs=exact_outputs,
        )


def test_methodology_capture_rejects_model_or_conditional_authority() -> None:
    with pytest.raises(ValueError, match="registered writer authority"):
        _resolve_methodology_capture(exact_writer="MODEL")
    with pytest.raises(ValueError, match="conditional"):
        _resolve_methodology_capture(
            conditional_output_ids=(METHODOLOGY_OUTPUTS[0],),
            condition_id="installed",
        )


def test_bake_methodology_inputs_have_exact_current_run_phaseio_producer(
    tmp_path: Path,
) -> None:
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    run_id = "program-facts-phaseio-fixture"
    _commit_checkpoint_capture(
        scratchpad,
        tmp_path,
        run_id=run_id,
    )
    capture = _resolve_methodology_capture()
    capture_launch = _launch(capture)
    methodology_identities = tuple(
        f"scratchpad:{path}" for path in METHODOLOGY_OUTPUTS
    )

    before = semantic_input_prebind_producer_authority_issues(
        scratchpad,
        tmp_path,
        methodology_identities,
        run_id=run_id,
    )
    assert before

    record_work_unit_inputs(
        scratchpad,
        tmp_path,
        capture,
        capture_launch,
        run_id=run_id,
    )
    for path in METHODOLOGY_OUTPUTS:
        target = scratchpad / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(b"{}\n")
    record_work_unit_artifacts(
        scratchpad,
        tmp_path,
        capture,
        capture_launch,
        run_id=run_id,
        actor="DRIVER",
        expected_output_records=_expected_output_records(
            scratchpad, capture
        ),
    )

    assert semantic_input_prebind_producer_authority_issues(
        scratchpad,
        tmp_path,
        methodology_identities,
        run_id=run_id,
    ) == []

    bake = _resolve()
    bake_launch = _launch(bake)
    record_work_unit_inputs(
        scratchpad,
        tmp_path,
        bake,
        bake_launch,
        run_id=run_id,
    )
    for path in OUTPUTS:
        (scratchpad / path).write_bytes(b"{}\n")
    record_work_unit_artifacts(
        scratchpad,
        tmp_path,
        bake,
        bake_launch,
        run_id=run_id,
        actor="DRIVER",
        expected_output_records=_expected_output_records(
            scratchpad, bake
        ),
    )
    assert validate_work_unit_artifacts(
        scratchpad,
        tmp_path,
        bake,
        bake_launch,
        run_id=run_id,
        actor="DRIVER",
    ) == []


@pytest.mark.parametrize(
    ("pipeline", "ecosystem", "backend"),
    (
        ("sc", "evm", "claude"),
        ("sc", "solana", "codex"),
        ("sc", "soroban", "claude"),
        ("sc", "aptos", "codex"),
        ("sc", "sui", "claude"),
        ("l1", "go", "codex"),
        ("l1", "rust", "claude"),
        ("l1", "daml", "codex"),
    ),
)
def test_program_facts_bake_is_one_backend_neutral_model_free_contract(
    pipeline: str,
    ecosystem: str,
    backend: str,
) -> None:
    contract = _resolve(
        pipeline=pipeline,
        ecosystem=ecosystem,
        backend=backend,
    )

    assert contract.phase == "recon"
    assert contract.work_unit_id == "program_facts_bake"
    assert contract.model_invoked is False
    assert contract.immutable_inputs == tuple(
        sorted(f"scratchpad:{path}" for path in CORE_INPUTS)
    )
    assert tuple(output.path for output in contract.outputs) == OUTPUTS
    assert {output.owner_key for output in contract.outputs} == {
        (
            f"{pipeline}/thorough/{ecosystem}/{backend}"
            "/recon/program_facts_bake"
        )
    }
    assert {output.artifact_class for output in contract.outputs} == {
        "DRIVER_GENERATED"
    }
    assert {output.writer for output in contract.outputs} == {"DRIVER"}
    assert {output.write_mode for output in contract.outputs} == {"CREATE"}
    assert contract.launch_profile == "DRIVER_PYTHON_NO_TOOLS"
    assert contract.required_commit_actor == "DRIVER"
    requirements = {
        requirement.identity: requirement
        for requirement in contract.input_authority_requirements
    }
    assert set(requirements) == set(contract.immutable_inputs)
    checkpoint_requirement = requirements[
        f"scratchpad:{CHECKPOINT_CAPTURE}"
    ]
    checkpoint_capture = _resolve_checkpoint_capture(
        pipeline=pipeline,
        ecosystem=ecosystem,
        backend=backend,
    )
    assert checkpoint_requirement.allow_raw is False
    assert checkpoint_requirement.expected_producer_work_unit_key == (
        checkpoint_capture.key
    )
    assert checkpoint_requirement.expected_writer == "DRIVER"
    assert checkpoint_requirement.require_same_run is True
    capture = _resolve_methodology_capture(
        pipeline=pipeline,
        ecosystem=ecosystem,
        backend=backend,
    )
    for path in METHODOLOGY_OUTPUTS:
        requirement = requirements[f"scratchpad:{path}"]
        assert requirement.allow_raw is False
        assert requirement.expected_producer_work_unit_key == capture.key
        assert requirement.expected_writer == "DRIVER"
        assert requirement.require_same_run is True
        assert requirement.expected_contract_digest == capture.digest
        assert requirement.expected_launch_digest == _launch(capture).digest
        assert requirement.require_exact_launch is True


def test_program_facts_bake_binds_explicit_build_and_config_inputs() -> None:
    extra = (
        "_program_facts_inputs/build-plan.v1.json",
        "_program_facts_inputs/provider-config.v1.json",
    )
    contract = _resolve(exact_inputs=CORE_INPUTS + extra)
    assert contract.immutable_inputs == tuple(
        sorted(f"scratchpad:{path}" for path in CORE_INPUTS + extra)
    )
    requirements = {
        requirement.identity: requirement
        for requirement in contract.input_authority_requirements
    }
    for path in extra:
        requirement = requirements[f"scratchpad:{path}"]
        assert requirement.allow_raw is False
        assert requirement.expected_writer == "DRIVER"
        assert requirement.require_same_run is True
        assert requirement.require_exact_contract is True
        assert requirement.require_exact_launch is True


@pytest.mark.parametrize("missing", CORE_INPUTS)
def test_program_facts_bake_rejects_any_missing_core_input(
    missing: str,
) -> None:
    with pytest.raises(ValueError, match="missing"):
        _resolve(
            exact_inputs=tuple(
                path for path in CORE_INPUTS if path != missing
            )
        )


@pytest.mark.parametrize(
    "exact_outputs",
    (
        OUTPUTS[:-1],
        OUTPUTS + ("unreviewed.json",),
    ),
)
def test_program_facts_bake_rejects_output_denominator_drift(
    exact_outputs: tuple[str, ...],
) -> None:
    with pytest.raises(ValueError, match="exact output"):
        _resolve(exact_outputs=exact_outputs)


def test_program_facts_bake_canonicalizes_equivalent_output_order() -> None:
    contract = _resolve(
        exact_outputs=(OUTPUTS[1], OUTPUTS[0], OUTPUTS[2])
    )
    assert tuple(output.path for output in contract.outputs) == OUTPUTS


def test_program_facts_bake_rejects_duplicate_or_conditional_inputs() -> None:
    with pytest.raises(ValueError, match="duplicate"):
        _resolve(exact_inputs=CORE_INPUTS + (CORE_INPUTS[-1],))
    with pytest.raises(ValueError, match="conditional"):
        _resolve(
            conditional_output_ids=(OUTPUTS[0],),
            condition_id="provider_available",
        )


@pytest.mark.parametrize(
    "extra",
    (
        "verification_queue.md",
        "program-facts-config.json",
        "_program_facts_inputs/unreviewed.txt",
    ),
)
def test_program_facts_bake_rejects_unscoped_additional_inputs(
    extra: str,
) -> None:
    with pytest.raises(ValueError, match="driver-produced JSON"):
        _resolve(exact_inputs=CORE_INPUTS + (extra,))


def test_program_facts_bake_rejects_model_writer_or_wrong_phase() -> None:
    with pytest.raises(ValueError, match="registered writer authority"):
        _resolve(exact_writer="MODEL")
    with pytest.raises(ValueError, match="no P0-AE resolver shape"):
        _resolve(phase="bake")


def test_raw_unowned_core_inputs_cannot_publish_program_facts(
    tmp_path: Path,
) -> None:
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    _write_inputs(scratchpad, CORE_INPUTS)
    contract = _resolve()
    launch = _launch(contract)
    record_work_unit_inputs(
        scratchpad,
        tmp_path,
        contract,
        launch,
        run_id="raw-core",
    )
    _write_inputs(scratchpad, OUTPUTS)
    unit = record_work_unit_artifacts(
        scratchpad,
        tmp_path,
        contract,
        launch,
        run_id="raw-core",
        actor="DRIVER",
    )
    assert unit["semantic_status"] == "QUARANTINED"
    assert "INPUT_RAW_AUTHORITY_FORBIDDEN" in unit[
        "commit_authority"
    ]["reason_codes"]


def test_unrelated_model_producer_cannot_substitute_methodology_inputs(
    tmp_path: Path,
) -> None:
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    run_id = "unrelated-model"
    _commit_checkpoint_capture(scratchpad, tmp_path, run_id=run_id)
    _claim_inputs(
        scratchpad,
        tmp_path,
        METHODOLOGY_OUTPUTS,
        run_id=run_id,
        writer="MODEL",
    )
    contract = _resolve()
    launch = _launch(contract)
    record_work_unit_inputs(
        scratchpad,
        tmp_path,
        contract,
        launch,
        run_id=run_id,
    )
    _write_inputs(scratchpad, OUTPUTS)
    unit = record_work_unit_artifacts(
        scratchpad,
        tmp_path,
        contract,
        launch,
        run_id=run_id,
        actor="DRIVER",
        expected_output_records=_expected_output_records(
            scratchpad, contract
        ),
    )
    assert unit["semantic_status"] == "QUARANTINED"
    assert {
        "INPUT_EXPECTED_PRODUCER_MISMATCH",
        "INPUT_EXPECTED_WRITER_MISMATCH",
    } <= set(unit["commit_authority"]["reason_codes"])


def test_same_key_wrong_contract_is_rejected_before_methodology_capture(
    tmp_path: Path,
) -> None:
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    run_id = "wrong-capture-contract"
    _commit_checkpoint_capture(scratchpad, tmp_path, run_id=run_id)
    expected = _resolve_methodology_capture()
    impostor = PhaseIOContract(
        pipeline=expected.pipeline,
        mode=expected.mode,
        ecosystem=expected.ecosystem,
        backend=expected.backend,
        phase=expected.phase,
        work_unit_id=expected.work_unit_id,
        outputs=tuple(
            replace(
                output,
                schema_version="impostor.unreviewed.v1",
                minimum_gate="PRESENCE",
            )
            for output in expected.outputs
        ),
        immutable_inputs=expected.immutable_inputs,
        model_invoked=False,
    )
    impostor_launch = _launch(impostor)
    with pytest.raises(
        ArtifactLedgerError,
        match="registered canonical manifest",
    ):
        record_work_unit_inputs(
            scratchpad,
            tmp_path,
            impostor,
            impostor_launch,
            run_id=run_id,
        )
    assert expected.key not in read_artifact_ledger(
        scratchpad
    )["work_units"]


@pytest.mark.parametrize(
    "bad_launch",
    (
        {"model": "claude"},
        {"exec_mode": "pty"},
        {"tool_policy": ("MODEL_INVOKE",)},
    ),
)
def test_model_free_program_facts_rejects_model_capable_launch(
    tmp_path: Path,
    bad_launch: dict[str, object],
) -> None:
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    run_id = "model-launch-smuggle"
    _commit_checkpoint_capture(scratchpad, tmp_path, run_id=run_id)
    contract = _resolve_methodology_capture()
    launch = replace(_launch(contract), **bad_launch)
    with pytest.raises(
        ArtifactLedgerError,
        match="closed model-free launch profile",
    ):
        record_work_unit_inputs(
            scratchpad,
            tmp_path,
            contract,
            launch,
            run_id=run_id,
        )


@pytest.mark.parametrize(
    ("pipeline", "ecosystem"),
    (
        ("bogus", "evm"),
        ("sc", "go"),
        ("l1", "evm"),
        ("l1", "solana"),
    ),
)
def test_program_facts_rejects_unregistered_dimension_pair(
    pipeline: str,
    ecosystem: str,
) -> None:
    with pytest.raises(ValueError, match="registered dimension"):
        _resolve(pipeline=pipeline, ecosystem=ecosystem)
    with pytest.raises(ValueError, match="registered dimension"):
        _resolve_methodology_capture(
            pipeline=pipeline,
            ecosystem=ecosystem,
        )


@pytest.mark.parametrize(
    "overrides",
    (
        {"pipeline": "SC"},
        {"ecosystem": "EVM"},
        {"backend": "CLAUDE"},
        {"mode": "THOROUGH"},
        {"phase": "RECON"},
    ),
)
def test_program_facts_rejects_casefold_dimension_aliases(
    overrides: dict[str, str],
) -> None:
    with pytest.raises(ValueError, match="canonical alias"):
        _resolve(**overrides)


@pytest.mark.parametrize(
    "extra_inputs",
    (
        (
            "_program_facts_inputs/build-plan.v1.json",
            "_program_facts_inputs/BUILD-PLAN.V1.JSON",
        ),
        ("_program_facts_inputs/cafe\u0301.json",),
    ),
)
def test_program_facts_rejects_casefold_or_nfc_input_aliases(
    extra_inputs: tuple[str, ...],
) -> None:
    with pytest.raises(ValueError, match="alias|NFC"):
        _resolve(exact_inputs=CORE_INPUTS + extra_inputs)


def test_methodology_capture_rejects_physical_output_aliases(
    tmp_path: Path,
) -> None:
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    run_id = "physical-alias"
    _commit_checkpoint_capture(scratchpad, tmp_path, run_id=run_id)
    contract = _resolve_methodology_capture()
    launch = _launch(contract)
    record_work_unit_inputs(
        scratchpad,
        tmp_path,
        contract,
        launch,
        run_id=run_id,
    )
    first = scratchpad / METHODOLOGY_OUTPUTS[0]
    first.parent.mkdir(parents=True, exist_ok=True)
    first.write_bytes(b"{}\n")
    second = scratchpad / METHODOLOGY_OUTPUTS[1]
    os.link(first, second)
    _write_inputs(scratchpad, METHODOLOGY_OUTPUTS[2:])
    unit = record_work_unit_artifacts(
        scratchpad,
        tmp_path,
        contract,
        launch,
        run_id=run_id,
        actor="DRIVER",
    )
    assert unit["semantic_status"] == "QUARANTINED"
    assert "OUTPUT_PHYSICAL_ALIAS_CONFLICT" in unit[
        "commit_authority"
    ]["reason_codes"]


def test_bake_rechecks_live_physical_input_aliases_after_arm(
    tmp_path: Path,
) -> None:
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    run_id = "live-input-alias"
    _commit_capture(scratchpad, tmp_path, run_id=run_id)
    dynamic = ("_program_facts_inputs/provider-config.v1.json",)
    _claim_inputs(
        scratchpad,
        tmp_path,
        dynamic,
        run_id=run_id,
        writer="DRIVER",
    )
    contract = _resolve(exact_inputs=CORE_INPUTS + dynamic)
    launch = _launch(contract)
    record_work_unit_inputs(
        scratchpad,
        tmp_path,
        contract,
        launch,
        run_id=run_id,
    )

    dynamic_path = scratchpad / dynamic[0]
    dynamic_path.unlink()
    os.link(scratchpad / CHECKPOINT_CAPTURE, dynamic_path)
    _write_inputs(scratchpad, OUTPUTS)
    unit = record_work_unit_artifacts(
        scratchpad,
        tmp_path,
        contract,
        launch,
        run_id=run_id,
        actor="DRIVER",
        expected_output_records=_expected_output_records(
            scratchpad, contract
        ),
    )
    assert unit["semantic_status"] == "QUARANTINED"
    assert "INPUT_PHYSICAL_ALIAS_CONFLICT" in unit[
        "commit_authority"
    ]["reason_codes"]


@pytest.mark.parametrize("actor", (None, "MODEL"))
def test_program_facts_commit_requires_explicit_agreeing_actor(
    tmp_path: Path,
    actor: str | None,
) -> None:
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    run_id = f"actor-{actor or 'missing'}"
    contract, launch = _commit_capture(
        scratchpad,
        tmp_path,
        run_id=run_id,
    )
    assert contract.required_commit_actor == "DRIVER"

    bake = _resolve()
    bake_launch = _launch(bake)
    record_work_unit_inputs(
        scratchpad,
        tmp_path,
        bake,
        bake_launch,
        run_id=run_id,
    )
    _write_inputs(scratchpad, OUTPUTS)
    unit = record_work_unit_artifacts(
        scratchpad,
        tmp_path,
        bake,
        bake_launch,
        run_id=run_id,
        actor=actor,
    )
    assert unit["semantic_status"] == "QUARANTINED"
    expected = (
        "COMMIT_ACTOR_REQUIRED"
        if actor is None
        else "COMMIT_ACTOR_MISMATCH"
    )
    assert expected in unit["commit_authority"]["reason_codes"]


@pytest.mark.parametrize("writer", ("MODEL", None))
def test_dynamic_program_facts_inputs_require_current_run_driver_producer(
    tmp_path: Path,
    writer: str | None,
) -> None:
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    run_id = f"dynamic-{writer or 'raw'}"
    _commit_capture(scratchpad, tmp_path, run_id=run_id)
    dynamic = ("_program_facts_inputs/build-plan.v1.json",)
    if writer is None:
        _write_inputs(scratchpad, dynamic)
    else:
        _claim_inputs(
            scratchpad,
            tmp_path,
            dynamic,
            run_id=run_id,
            writer=writer,
        )
    contract = _resolve(exact_inputs=CORE_INPUTS + dynamic)
    launch = _launch(contract)
    record_work_unit_inputs(
        scratchpad,
        tmp_path,
        contract,
        launch,
        run_id=run_id,
    )
    _write_inputs(scratchpad, OUTPUTS)
    unit = record_work_unit_artifacts(
        scratchpad,
        tmp_path,
        contract,
        launch,
        run_id=run_id,
        actor="DRIVER",
    )
    assert unit["semantic_status"] == "QUARANTINED"
    expected = (
        "INPUT_EXPECTED_WRITER_MISMATCH"
        if writer == "MODEL"
        else "INPUT_RAW_AUTHORITY_FORBIDDEN"
    )
    assert expected in unit["commit_authority"]["reason_codes"]


def test_current_run_driver_can_supply_dynamic_program_facts_input(
    tmp_path: Path,
) -> None:
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    run_id = "dynamic-driver"
    _commit_capture(scratchpad, tmp_path, run_id=run_id)
    dynamic = ("_program_facts_inputs/provider-config.v1.json",)
    _claim_inputs(
        scratchpad,
        tmp_path,
        dynamic,
        run_id=run_id,
        writer="DRIVER",
    )
    contract = _resolve(exact_inputs=CORE_INPUTS + dynamic)
    launch = _launch(contract)
    record_work_unit_inputs(
        scratchpad,
        tmp_path,
        contract,
        launch,
        run_id=run_id,
    )
    _write_inputs(scratchpad, OUTPUTS)
    record_work_unit_artifacts(
        scratchpad,
        tmp_path,
        contract,
        launch,
        run_id=run_id,
        actor="DRIVER",
        expected_output_records=_expected_output_records(
            scratchpad, contract
        ),
    )
    assert validate_work_unit_artifacts(
        scratchpad,
        tmp_path,
        contract,
        launch,
        run_id=run_id,
        actor="DRIVER",
    ) == []


def test_prior_run_methodology_capture_cannot_feed_current_bake(
    tmp_path: Path,
) -> None:
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    _commit_capture(
        scratchpad,
        tmp_path,
        run_id="prior-run",
    )
    contract = _resolve()
    launch = _launch(contract)
    record_work_unit_inputs(
        scratchpad,
        tmp_path,
        contract,
        launch,
        run_id="current-run",
    )
    _write_inputs(scratchpad, OUTPUTS)
    unit = record_work_unit_artifacts(
        scratchpad,
        tmp_path,
        contract,
        launch,
        run_id="current-run",
        actor="DRIVER",
    )
    assert unit["semantic_status"] == "QUARANTINED"
    assert "INPUT_PRODUCER_RUN_MISMATCH" in unit[
        "commit_authority"
    ]["reason_codes"]
