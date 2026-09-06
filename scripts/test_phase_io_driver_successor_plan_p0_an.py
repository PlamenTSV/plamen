"""Sealed PhaseIO contracts for transaction-bound DRIVER successors."""
from __future__ import annotations

import hashlib
import copy

import pytest

from phase_io_contracts import (
    ArtifactSpec,
    DriverMergeEvent,
    DriverOutputTransition,
    DriverSuccessorPlan,
    LaunchSpec,
    PhaseIOContract,
    registered_projection_handoff,
    driver_successor_plan_from_dict,
    replay_driver_output_transition_authority,
    replay_driver_successor_plan_authority,
    resolve_phase_io_contract,
)


BASE = {
    "pipeline": "sc",
    "mode": "thorough",
    "ecosystem": "evm",
    "backend": "claude",
}
RUN_ID = "run-driver-successor-plan"
_A = hashlib.sha256(b"a").hexdigest()
_B = hashlib.sha256(b"bb").hexdigest()
_C = hashlib.sha256(b"ccc").hexdigest()
_D = hashlib.sha256(b"dddd").hexdigest()
_E = hashlib.sha256(b"eeeee").hexdigest()


def _contract() -> PhaseIOContract:
    owner = "sc/thorough/evm/claude/inventory/successor_fixture"
    return PhaseIOContract(
        **BASE,
        phase="inventory",
        work_unit_id="successor_fixture",
        outputs=(
            ArtifactSpec(
                root="scratchpad",
                path="intent.json",
                owner_key=owner,
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                write_mode="CREATE",
            ),
            ArtifactSpec(
                root="scratchpad",
                path="inventory.md",
                owner_key=owner,
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                write_mode="MERGE",
            ),
            ArtifactSpec(
                root="scratchpad",
                path="receipt.json",
                owner_key=owner,
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                write_mode="REPLACE",
            ),
        ),
        immutable_inputs=("scratchpad:source.json",),
        model_invoked=False,
    )


def _launch(contract: PhaseIOContract) -> LaunchSpec:
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


def _merge(contract: PhaseIOContract) -> DriverMergeEvent:
    return DriverMergeEvent(
        work_unit_key=contract.key,
        contract_digest=contract.digest,
        artifact_identity="scratchpad:inventory.md",
        before_sha256=_B,
        after_sha256=_C,
        source_identities=("scratchpad:source.json",),
        identities_before=("INV-001",),
        identities_after=("INV-001", "INV-002"),
    )


def _transitions(
    contract: PhaseIOContract,
) -> tuple[DriverOutputTransition, ...]:
    return (
        DriverOutputTransition(
            work_unit_key=contract.key,
            contract_digest=contract.digest,
            ordinal=1,
            artifact_identity="scratchpad:intent.json",
            before_status="MISSING",
            before_sha256="",
            before_size=0,
            after_sha256=_A,
            after_size=1,
        ),
        DriverOutputTransition(
            work_unit_key=contract.key,
            contract_digest=contract.digest,
            ordinal=2,
            artifact_identity="scratchpad:inventory.md",
            before_status="ACTIVE",
            before_sha256=_B,
            before_size=2,
            after_sha256=_C,
            after_size=3,
            merge_event=_merge(contract),
        ),
        DriverOutputTransition(
            work_unit_key=contract.key,
            contract_digest=contract.digest,
            ordinal=3,
            artifact_identity="scratchpad:receipt.json",
            before_status="ACTIVE",
            before_sha256=_D,
            before_size=4,
            after_sha256=_E,
            after_size=5,
        ),
    )


def _plan(
    contract: PhaseIOContract,
    launch: LaunchSpec,
    *,
    transitions: tuple[DriverOutputTransition, ...] | None = None,
) -> DriverSuccessorPlan:
    return DriverSuccessorPlan(
        run_id=RUN_ID,
        work_unit_key=contract.key,
        contract_digest=contract.digest,
        launch_digest=launch.digest,
        output_prestate_digest="f" * 64,
        transitions=transitions or _transitions(contract),
    )


def test_successor_plan_is_canonical_sealed_and_exactly_replayable() -> None:
    contract = _contract()
    launch = _launch(contract)
    transitions = _transitions(contract)
    plan = _plan(contract, launch, transitions=transitions)

    assert plan.output_order == (
        "scratchpad:intent.json",
        "scratchpad:inventory.md",
        "scratchpad:receipt.json",
    )
    assert plan.expected_output_records == {
        "scratchpad:intent.json": {"sha256": _A, "size": 1},
        "scratchpad:inventory.md": {"sha256": _C, "size": 3},
        "scratchpad:receipt.json": {"sha256": _E, "size": 5},
    }
    assert plan.to_dict() == {
        "plan_version": "plamen.driver_successor_plan.v1",
        "run_id": RUN_ID,
        "work_unit_key": contract.key,
        "contract_digest": contract.digest,
        "launch_digest": launch.digest,
        "output_prestate_digest": "f" * 64,
        "output_order": list(plan.output_order),
        "expected_output_records": plan.expected_output_records,
        "transitions": [row.to_dict() for row in transitions],
    }
    assert plan.digest == hashlib.sha256(
        __import__("json").dumps(
            plan.to_dict(),
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()

    replayed = replay_driver_successor_plan_authority(
        plan, contract=contract, launch=launch
    )
    assert replayed is not plan
    assert replayed.to_dict() == plan.to_dict()
    assert replayed.digest == plan.digest
    replayed_transition = replay_driver_output_transition_authority(
        transitions[1], contract=contract
    )
    assert replayed_transition is not transitions[1]
    assert replayed_transition.to_dict() == transitions[1].to_dict()

    object.__setattr__(plan, "run_id", "mutated-after-seal")
    with pytest.raises(ValueError, match="seal|mutated"):
        replay_driver_successor_plan_authority(
            plan, contract=contract, launch=launch
        )


@pytest.mark.parametrize(
    "overrides,match",
    (
        ({"ordinal": 0}, "ordinal"),
        ({"ordinal": True}, "ordinal"),
        ({"before_status": "ABSENT"}, "before_status"),
        (
            {
                "before_status": "MISSING",
                "before_sha256": _A,
                "before_size": 0,
            },
            "MISSING",
        ),
        (
            {
                "before_status": "ACTIVE",
                "before_sha256": "",
                "before_size": 1,
            },
            "before_sha256",
        ),
        ({"before_size": -1}, "before_size"),
        ({"after_sha256": ""}, "after_sha256"),
        ({"after_size": -1}, "after_size"),
    ),
)
def test_transition_rejects_noncanonical_byte_authority(
    overrides: dict[str, object],
    match: str,
) -> None:
    contract = _contract()
    values: dict[str, object] = {
        "work_unit_key": contract.key,
        "contract_digest": contract.digest,
        "ordinal": 1,
        "artifact_identity": "scratchpad:receipt.json",
        "before_status": "ACTIVE",
        "before_sha256": _D,
        "before_size": 4,
        "after_sha256": _E,
        "after_size": 5,
    }
    values.update(overrides)
    with pytest.raises(ValueError, match=match):
        DriverOutputTransition(**values)


def test_plan_rejects_gaps_duplicates_and_incomplete_output_denominators() -> None:
    contract = _contract()
    launch = _launch(contract)
    transitions = _transitions(contract)
    gap = (
        transitions[0],
        DriverOutputTransition(
            **{
                **transitions[1].__dict__,
                "ordinal": 3,
            }
        ),
        DriverOutputTransition(
            **{
                **transitions[2].__dict__,
                "ordinal": 4,
            }
        ),
    )
    with pytest.raises(ValueError, match="contiguous"):
        _plan(contract, launch, transitions=gap)
    with pytest.raises(ValueError, match="duplicate"):
        _plan(
            contract,
            launch,
            transitions=(transitions[0], transitions[0], transitions[2]),
        )
    incomplete = _plan(
        contract, launch, transitions=transitions[:2]
    )
    with pytest.raises(ValueError, match="output denominator"):
        replay_driver_successor_plan_authority(
            incomplete, contract=contract, launch=launch
        )


def test_merge_evidence_is_exact_and_only_valid_for_driver_merge_outputs() -> None:
    contract = _contract()
    launch = _launch(contract)
    transitions = _transitions(contract)
    wrong_after = DriverMergeEvent(
        work_unit_key=contract.key,
        contract_digest=contract.digest,
        artifact_identity="scratchpad:inventory.md",
        before_sha256=_B,
        after_sha256=_E,
        source_identities=("scratchpad:source.json",),
        identities_before=("INV-001",),
        identities_after=("INV-001", "INV-002"),
    )
    mismatched = DriverOutputTransition(
        **{
            **transitions[1].__dict__,
            "merge_event": wrong_after,
        }
    )
    plan = _plan(
        contract,
        launch,
        transitions=(transitions[0], mismatched, transitions[2]),
    )
    with pytest.raises(ValueError, match="after_sha256"):
        replay_driver_successor_plan_authority(
            plan, contract=contract, launch=launch
        )

    non_merge = DriverOutputTransition(
        **{
            **transitions[2].__dict__,
            "merge_event": _merge(contract),
        }
    )
    plan = _plan(
        contract,
        launch,
        transitions=(transitions[0], transitions[1], non_merge),
    )
    with pytest.raises(ValueError, match="DRIVER/MERGE"):
        replay_driver_successor_plan_authority(
            plan, contract=contract, launch=launch
        )


def test_successor_plan_refuses_model_or_launch_and_prestate_substitution() -> None:
    contract = _contract()
    launch = _launch(contract)
    plan = _plan(contract, launch)
    wrong_launch = LaunchSpec(
        work_unit_key=contract.key,
        pipeline=contract.pipeline,
        mode=contract.mode,
        ecosystem=contract.ecosystem,
        backend=contract.backend,
        model="driver",
        timeout_s=31,
        exec_mode="python",
    )
    with pytest.raises(ValueError, match="launch"):
        replay_driver_successor_plan_authority(
            plan, contract=contract, launch=wrong_launch
        )

    with pytest.raises(ValueError, match="output_prestate_digest"):
        DriverSuccessorPlan(
            run_id=plan.run_id,
            work_unit_key=plan.work_unit_key,
            contract_digest=plan.contract_digest,
            launch_digest=plan.launch_digest,
            output_prestate_digest="",
            transitions=plan.transitions,
        )

    owner = "sc/thorough/evm/claude/inventory/model_fixture"
    model_contract = PhaseIOContract(
        **BASE,
        phase="inventory",
        work_unit_id="model_fixture",
        outputs=(
            ArtifactSpec(
                root="scratchpad",
                path="model.md",
                    owner_key=owner,
                    artifact_class="REQUIRED",
                    writer="MODEL",
                    write_mode="CREATE",
                ),
        ),
        model_invoked=True,
    )
    model_launch = LaunchSpec(
        work_unit_key=model_contract.key,
        pipeline=model_contract.pipeline,
        mode=model_contract.mode,
        ecosystem=model_contract.ecosystem,
        backend=model_contract.backend,
        model="opus",
        timeout_s=30,
        exec_mode="pty",
    )
    model_plan = DriverSuccessorPlan(
        run_id=RUN_ID,
        work_unit_key=model_contract.key,
        contract_digest=model_contract.digest,
        launch_digest=model_launch.digest,
        output_prestate_digest="f" * 64,
        transitions=(
            DriverOutputTransition(
                work_unit_key=model_contract.key,
                contract_digest=model_contract.digest,
                ordinal=1,
                artifact_identity="scratchpad:model.md",
                before_status="MISSING",
                before_sha256="",
                before_size=0,
                after_sha256=_A,
                after_size=1,
            ),
        ),
    )
    with pytest.raises(ValueError, match="DRIVER"):
        replay_driver_successor_plan_authority(
            model_plan, contract=model_contract, launch=model_launch
        )


@pytest.mark.parametrize("backend", ("claude", "codex"))
def test_inventory_successor_metadata_and_handoffs_are_exact(
    backend: str,
) -> None:
    dimensions = {
        "pipeline": "sc",
        "mode": "thorough",
        "ecosystem": "evm",
        "backend": backend,
    }
    canonical = resolve_phase_io_contract(
        **dimensions,
        phase="inventory",
        work_unit_id="canonical_aggregate",
        exact_inputs=("inventory_aggregate_derivation.json",),
        exact_outputs=(
            "findings_inventory.md",
            "finding_records.json",
            "inventory_merge_receipt.md",
            "inventory_id_allocation_delta.json",
        ),
    )
    id_merge = resolve_phase_io_contract(
        **dimensions,
        phase="inventory",
        work_unit_id="id_ledger_merge",
        exact_inputs=(
            "inventory_aggregate_derivation.json",
            "inventory_id_allocation_delta.json",
            "findings_inventory.md",
            "finding_records.json",
        ),
        exact_outputs=(
            "_id_ledger.json",
            "inventory_id_ledger_merge_receipt.json",
        ),
    )
    additive_key = canonical.key.rsplit("/", 1)[0] + "/additive_reemit"
    delta = canonical.output(
        "scratchpad:inventory_id_allocation_delta.json"
    )
    merge_receipt = id_merge.output(
        "scratchpad:inventory_id_ledger_merge_receipt.json"
    )
    assert set(delta.consumers) == {
        "inventory/id_ledger_merge",
        "inventory/additive_reemit",
    }
    assert set(merge_receipt.consumers) == {
        "inventory/additive_reemit",
    }
    assert registered_projection_handoff(
        canonical.key,
        additive_key,
        "scratchpad:findings_inventory.md",
    )
    assert registered_projection_handoff(
        canonical.key,
        additive_key,
        "scratchpad:finding_records.json",
    )
    assert registered_projection_handoff(
        id_merge.key,
        additive_key,
        "scratchpad:_id_ledger.json",
    )
    assert not registered_projection_handoff(
        canonical.key,
        additive_key,
        "scratchpad:inventory_id_allocation_delta.json",
    )
    assert not registered_projection_handoff(
        id_merge.key,
        additive_key,
        "scratchpad:inventory_id_ledger_merge_receipt.json",
    )


def test_successor_plan_restart_decoder_is_exact_and_drift_rejecting() -> None:
    contract = _contract()
    launch = _launch(contract)
    plan = _plan(contract, launch)
    payload = plan.to_dict()

    decoded = driver_successor_plan_from_dict(
        payload,
        contract=contract,
        launch=launch,
    )
    assert decoded is not plan
    assert decoded.to_dict() == payload
    assert decoded.digest == plan.digest

    cases: tuple[tuple[dict[str, object], str], ...] = (
        ({**payload, "extra": True}, "fields"),
        (
            {key: value for key, value in payload.items() if key != "run_id"},
            "fields",
        ),
        (
            {
                **payload,
                "output_order": list(reversed(payload["output_order"])),
            },
            "canonical|output_order",
        ),
        (
            {
                **payload,
                "expected_output_records": {
                    **payload["expected_output_records"],
                    "scratchpad:intent.json": {"sha256": _B, "size": 2},
                },
            },
            "canonical|expected_output_records",
        ),
    )
    for changed, match in cases:
        with pytest.raises(ValueError, match=match):
            driver_successor_plan_from_dict(
                changed,
                contract=contract,
                launch=launch,
            )

    nested_extra = copy.deepcopy(payload)
    nested_extra["transitions"][0]["extra"] = "forbidden"
    with pytest.raises(ValueError, match="fields"):
        driver_successor_plan_from_dict(
            nested_extra,
            contract=contract,
            launch=launch,
        )

    nested_drift = copy.deepcopy(payload)
    nested_drift["transitions"][0]["before_status"] = "missing"
    with pytest.raises(ValueError, match="before_status|canonical"):
        driver_successor_plan_from_dict(
            nested_drift,
            contract=contract,
            launch=launch,
        )

    merge_extra = copy.deepcopy(payload)
    merge_extra["transitions"][1]["merge_event"]["extra"] = "forbidden"
    with pytest.raises(ValueError, match="fields"):
        driver_successor_plan_from_dict(
            merge_extra,
            contract=contract,
            launch=launch,
        )
