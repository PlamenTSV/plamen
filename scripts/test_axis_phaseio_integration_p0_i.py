"""P0-I contract-first integration tests for the axis-disposition boundary."""
from __future__ import annotations

from pathlib import Path

import pytest

from phase_io_contracts import (
    canonical_work_unit_key,
    registered_projection_handoff,
    resolve_phase_io_contract,
)
from plamen_types import L1_PHASES, SC_PHASES


BACKENDS = ("claude", "codex")
ECOSYSTEMS = ("evm", "solana", "aptos", "sui", "soroban")

PLANNING_INPUTS = (
    "_hot_function_axes.json",
    "_hot_function_cap_receipt.json",
    "_coverage_shortfalls.json",
    "reference_graph.json",
    "project::contracts/Unit.sol",
)
PRIOR_INPUTS = ("axis_disposition_worklist.json",)
MODEL_INPUTS = (
    "axis_disposition_worklist.json",
    "axis_execution_evidence_authority.json",
    "findings_inventory.md",
    "axis_canonical_prior_snapshot.json",
    "axis_canonical_prior_authority.json",
    "project::contracts/Unit.sol",
)
INITIAL_INPUTS = (
    "axis_disposition_worklist.json",
    "axis_execution_evidence_authority.json",
    "axis_coverage_findings.md",
    "axis_coverage_dispositions.json",
    "axis_canonical_prior_snapshot.json",
    "axis_canonical_prior_authority.json",
    "project::contracts/Unit.sol",
)
REPAIR_INPUTS = (
    "axis_repair_plan.json",
    "axis_disposition_worklist.json",
    "axis_execution_evidence_authority.json",
    "axis_coverage_findings.md",
    "axis_coverage_dispositions.json",
    "axis_canonical_prior_snapshot.json",
    "axis_canonical_prior_authority.json",
    "project::contracts/Unit.sol",
)
REPAIR_EXECUTION_INPUTS = (
    "axis_repair_plan.json",
    "axis_coverage_repair_findings.md",
    "axis_coverage_repair_dispositions.json",
)
FINAL_INPUTS = (
    "axis_disposition_worklist.json",
    "axis_execution_evidence_authority.json",
    "axis_coverage_findings.md",
    "axis_coverage_dispositions.json",
    "axis_disposition_initial_receipt.json",
    "axis_repair_plan.json",
    "axis_repair_execution_receipt.json",
    "axis_coverage_repair_findings.md",
    "axis_coverage_repair_dispositions.json",
    "axis_canonical_prior_snapshot.json",
    "axis_canonical_prior_authority.json",
    "project::contracts/Unit.sol",
)
PROMOTION_PLAN_INPUTS = (
    "axis_disposition_receipt.json",
    "axis_coverage_findings.md",
    "axis_coverage_dispositions.json",
    "axis_coverage_repair_findings.md",
    "axis_coverage_repair_dispositions.json",
    "findings_inventory.md",
)
PROMOTION_INPUTS = (
    "axis_coverage_promotion_plan.json",
    "axis_disposition_receipt.json",
    "axis_coverage_findings.md",
    "axis_coverage_dispositions.json",
    "axis_coverage_repair_findings.md",
    "axis_coverage_repair_dispositions.json",
)


def _resolve(
    backend: str,
    *,
    phase: str,
    work_unit_id: str,
    exact_inputs: tuple[str, ...],
    ecosystem: str = "evm",
):
    return resolve_phase_io_contract(
        pipeline="sc",
        mode="thorough",
        ecosystem=ecosystem,
        backend=backend,
        phase=phase,
        work_unit_id=work_unit_id,
        exact_inputs=exact_inputs,
    )


def _semantic_snapshot(contract) -> dict:
    """Remove only backend-qualified owner identities from a contract."""

    return {
        "phase": contract.phase,
        "work_unit_id": contract.work_unit_id,
        "model_invoked": contract.model_invoked,
        "immutable_inputs": tuple(
            identity.split(":", 1) for identity in contract.immutable_inputs
        ),
        "bounded_lookup_inputs": tuple(
            identity.split(":", 1) for identity in contract.bounded_lookup_inputs
        ),
        "outputs": tuple(
            sorted(
                (
                    item.root,
                    item.path,
                    item.artifact_class,
                    item.writer,
                    item.write_mode,
                    item.schema_version,
                    item.minimum_gate,
                    item.consumers,
                    item.external_preimage_validator,
                )
                for item in contract.outputs
            )
        ),
    }


def _all_contracts(backend: str):
    return (
        _resolve(
            backend,
            phase="axis_disposition",
            work_unit_id="planning",
            exact_inputs=PLANNING_INPUTS,
        ),
        _resolve(
            backend,
            phase="axis_disposition",
            work_unit_id="prior.snapshot",
            exact_inputs=PRIOR_INPUTS,
        ),
        _resolve(
            backend,
            phase="axis_coverage",
            work_unit_id="model",
            exact_inputs=MODEL_INPUTS,
        ),
        _resolve(
            backend,
            phase="axis_disposition",
            work_unit_id="reconcile.initial",
            exact_inputs=INITIAL_INPUTS,
        ),
        _resolve(
            backend,
            phase="axis_coverage",
            work_unit_id="repair.worker.0001",
            exact_inputs=REPAIR_INPUTS,
        ),
        _resolve(
            backend,
            phase="axis_disposition",
            work_unit_id="repair.execution",
            exact_inputs=REPAIR_EXECUTION_INPUTS,
        ),
        _resolve(
            backend,
            phase="axis_disposition",
            work_unit_id="reconcile.final",
            exact_inputs=FINAL_INPUTS,
        ),
        _resolve(
            backend,
            phase="axis_disposition",
            work_unit_id="promotion.plan",
            exact_inputs=PROMOTION_PLAN_INPUTS,
        ),
        _resolve(
            backend,
            phase="axis_disposition",
            work_unit_id="promotion",
            exact_inputs=PROMOTION_INPUTS,
        ),
    )


def test_axis_phase_is_thorough_sc_only_and_precedes_negative_challenge() -> None:
    names = [phase.name for phase in SC_PHASES]
    axis = next(phase for phase in SC_PHASES if phase.name == "axis_coverage")
    assert axis.modes == {"thorough"}
    assert axis.critical is False
    assert axis.expected_artifacts == [
        "axis_coverage_findings.md",
        "axis_coverage_dispositions.json",
    ]
    assert names.index("enumgap_exploration") < names.index("axis_coverage")
    assert names.index("axis_coverage") < names.index("application_skeptic")
    assert names.index("application_skeptic") < names.index("sc_semantic_dedup")
    assert "axis_coverage" not in {phase.name for phase in L1_PHASES}


@pytest.mark.parametrize("ecosystem", ECOSYSTEMS)
def test_axis_contracts_are_ecosystem_neutral(ecosystem: str) -> None:
    contracts = (
        _resolve(
            "claude",
            phase="axis_disposition",
            work_unit_id="planning",
            exact_inputs=PLANNING_INPUTS,
            ecosystem=ecosystem,
        ),
        _resolve(
            "claude",
            phase="axis_disposition",
            work_unit_id="prior.snapshot",
            exact_inputs=PRIOR_INPUTS,
            ecosystem=ecosystem,
        ),
        _resolve(
            "claude",
            phase="axis_coverage",
            work_unit_id="model",
            exact_inputs=MODEL_INPUTS,
            ecosystem=ecosystem,
        ),
    )
    assert all(contract.ecosystem == ecosystem for contract in contracts)


def test_axis_contracts_are_backend_neutral_except_owner_namespace() -> None:
    claude = tuple(_semantic_snapshot(item) for item in _all_contracts("claude"))
    codex = tuple(_semantic_snapshot(item) for item in _all_contracts("codex"))
    assert claude == codex


@pytest.mark.parametrize(
    ("pipeline", "mode"),
    (("l1", "thorough"), ("sc", "core"), ("sc", "light")),
)
def test_axis_contracts_reject_unscheduled_pipeline_modes(
    pipeline: str, mode: str,
) -> None:
    with pytest.raises(ValueError, match="SC Thorough"):
        resolve_phase_io_contract(
            pipeline=pipeline,
            mode=mode,
            ecosystem="evm",
            backend="claude",
            phase="axis_disposition",
            work_unit_id="planning",
            exact_inputs=PLANNING_INPUTS,
        )


def test_axis_planning_accepts_absent_clean_shortfall_ledger() -> None:
    """A clean shortfall producer intentionally emits no ceremonial file."""

    inputs = tuple(
        value for value in PLANNING_INPUTS
        if value != "_coverage_shortfalls.json"
    )
    contract = resolve_phase_io_contract(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        phase="axis_disposition",
        work_unit_id="planning",
        exact_inputs=inputs,
    )
    assert "scratchpad:_coverage_shortfalls.json" not in contract.immutable_inputs


def test_axis_resolver_shapes_have_exclusive_writer_authority() -> None:
    contracts = _all_contracts("claude")
    by_unit = {(item.phase, item.work_unit_id): item for item in contracts}

    planning = by_unit[("axis_disposition", "planning")]
    assert planning.model_invoked is False
    assert {
        item.path: (item.writer, item.schema_version)
        for item in planning.outputs
    } == {
        "axis_disposition_worklist.json": (
            "DRIVER",
            "plamen.axis_disposition_worklist.v2",
        ),
        "axis_execution_evidence_authority.json": (
            "DRIVER",
            "plamen.axis_execution_evidence_authority.v1",
        ),
    }

    prior = by_unit[("axis_disposition", "prior.snapshot")]
    assert prior.model_invoked is False
    assert {
        item.path: (item.writer, item.schema_version)
        for item in prior.outputs
    } == {
        "axis_canonical_prior_snapshot.json": (
            "DRIVER",
            "plamen.axis_canonical_prior_snapshot.v1",
        ),
        "axis_canonical_prior_authority.json": (
            "DRIVER",
            "plamen.axis_canonical_prior_authority.v1",
        ),
    }

    model = by_unit[("axis_coverage", "model")]
    assert model.model_invoked is True
    assert {
        item.path: (item.writer, item.schema_version)
        for item in model.outputs
    } == {
        "axis_coverage_findings.md": ("MODEL", "unstructured.v1"),
        "axis_coverage_dispositions.json": (
            "MODEL",
            "plamen.axis_model_dispositions.v1",
        ),
    }

    repair = by_unit[("axis_coverage", "repair.worker.0001")]
    assert repair.model_invoked is True
    assert {item.writer for item in repair.outputs} == {"MODEL"}
    assert {item.path for item in repair.outputs} == {
        "axis_coverage_repair_findings.md",
        "axis_coverage_repair_dispositions.json",
    }
    assert next(
        item for item in repair.outputs
        if item.path == "axis_coverage_repair_dispositions.json"
    ).schema_version == "plamen.axis_repair_model_dispositions.v1"

    repair_execution = by_unit[("axis_disposition", "repair.execution")]
    assert repair_execution.model_invoked is False
    assert {item.writer for item in repair_execution.outputs} == {"DRIVER"}
    assert {item.path for item in repair_execution.outputs} == {
        "axis_repair_execution_receipt.json"
    }

    initial = by_unit[("axis_disposition", "reconcile.initial")]
    assert initial.model_invoked is False
    assert {
        item.path: item.schema_version for item in initial.outputs
    } == {
        "axis_disposition_initial_receipt.json": (
            "plamen.axis_disposition_initial_receipt.v1"
        ),
        "axis_repair_plan.json": "plamen.axis_repair_plan.v1",
    }

    final = by_unit[("axis_disposition", "reconcile.final")]
    assert final.model_invoked is False
    assert {item.path for item in final.outputs} == {
        "axis_disposition_receipt.json",
        "axis_repair_work.json",
        "axis_assurance_debt.json",
        "axis_assurance_limitations.md",
    }
    assert next(
        item for item in final.outputs
        if item.path == "axis_disposition_receipt.json"
    ).schema_version == "plamen.axis_disposition_application_receipt.v2"

    promotion_plan = by_unit[("axis_disposition", "promotion.plan")]
    assert promotion_plan.model_invoked is False
    assert {
        item.path: (item.writer, item.schema_version)
        for item in promotion_plan.outputs
    } == {
        "axis_coverage_promotion_plan.json": (
            "DRIVER",
            "plamen.axis_coverage_promotion_plan.v1",
        )
    }

    promotion = by_unit[("axis_disposition", "promotion")]
    assert promotion.model_invoked is False
    outputs = {item.path: item for item in promotion.outputs}
    assert outputs["findings_inventory.md"].writer == "DRIVER"
    assert outputs["findings_inventory.md"].write_mode == "MERGE"
    assert (
        outputs["findings_inventory.md"].external_preimage_validator
        == "plamen.axis_inventory_prestate.v1"
    )
    assert outputs["axis_coverage_promotion_receipt.json"].schema_version == (
        "plamen.axis_coverage_promotion_receipt.v2"
    )

    owned = [
        output.identity for contract in contracts for output in contract.outputs
    ]
    assert len(owned) == len(set(owned))


def test_axis_dynamic_contracts_require_exact_denominators() -> None:
    with pytest.raises(ValueError, match="exact input denominator"):
        _resolve(
            "claude",
            phase="axis_disposition",
            work_unit_id="planning",
            exact_inputs=(),
        )
    with pytest.raises(ValueError, match="axis_disposition_worklist.json"):
        _resolve(
            "claude",
            phase="axis_coverage",
            work_unit_id="model",
            exact_inputs=("axis_execution_evidence_authority.json",),
        )
    with pytest.raises(ValueError, match="exact input denominator"):
        _resolve(
            "claude",
            phase="axis_disposition",
            work_unit_id="prior.snapshot",
            exact_inputs=(),
        )
    with pytest.raises(ValueError, match="paired repair outputs"):
        _resolve(
            "claude",
            phase="axis_disposition",
            work_unit_id="reconcile.final",
            exact_inputs=tuple(
                name
                for name in FINAL_INPUTS
                if name != "axis_coverage_repair_dispositions.json"
            ),
        )
    with pytest.raises(ValueError, match="exact output denominator"):
        resolve_phase_io_contract(
            pipeline="sc",
            mode="thorough",
            ecosystem="evm",
            backend="claude",
            phase="axis_disposition",
            work_unit_id="planning",
            exact_inputs=PLANNING_INPUTS,
            exact_outputs=("rogue-axis-output.json",),
        )


def test_axis_inventory_projection_handoffs_are_explicit() -> None:
    dimensions = ("sc", "thorough", "evm", "claude")
    inventory = "scratchpad:findings_inventory.md"
    canonical = canonical_work_unit_key(
        *dimensions, "inventory", "canonical_aggregate"
    )
    enumgap = canonical_work_unit_key(
        *dimensions, "enumgap_delivery", "inventory_append"
    )
    axis = canonical_work_unit_key(
        *dimensions, "axis_disposition", "promotion"
    )
    prequeue = canonical_work_unit_key(
        *dimensions, "semantic_dedup", "prequeue_apply"
    )
    assert registered_projection_handoff(canonical, axis, inventory)
    assert registered_projection_handoff(enumgap, axis, inventory)
    assert registered_projection_handoff(axis, axis, inventory)
    assert registered_projection_handoff(axis, prequeue, inventory)


def test_axis_prompt_uses_axw_json_authority_not_markdown_denominator() -> None:
    prompt = (
        Path(__file__).parents[1]
        / "prompts"
        / "shared"
        / "v2"
        / "phase4b8-axis-coverage.md"
    ).read_text(encoding="utf-8")
    assert "axis_disposition_worklist.json" in prompt
    assert "axis_coverage_dispositions.json" in prompt
    assert "plamen.axis_model_dispositions.v1" in prompt
    assert "work_item_id" in prompt
    assert "worklist_hash" in prompt
    assert "exactly one" in prompt.casefold()
    assert "Markdown" in prompt and "not authority" in prompt
    assert "Do not reconstruct" in prompt
    assert "FINDING" in prompt and "UNRESOLVED" in prompt and "CLEAR" in prompt
    assert "CLEAR" in prompt and "must not reference an action" in prompt


def test_axis_v2_artifacts_are_known_prompt_paths() -> None:
    import plamen_prompt

    known = set(plamen_prompt._LEGITIMATE_SUBPRODUCER_PATTERNS)
    for name in (
        "axis_disposition_worklist.json",
        "axis_execution_evidence_authority.json",
        "axis_coverage_findings.md",
        "axis_coverage_dispositions.json",
        "axis_repair_plan.json",
        "axis_coverage_repair_findings.md",
        "axis_coverage_repair_dispositions.json",
        "axis_repair_execution_receipt.json",
        "axis_disposition_initial_receipt.json",
        "axis_disposition_receipt.json",
        "axis_repair_work.json",
        "axis_assurance_debt.json",
        "axis_assurance_limitations.md",
        "axis_coverage_promotion_receipt.json",
    ):
        assert name in known
