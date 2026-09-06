from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
import json

import pytest

from plamen_types import L1_PHASES, SC_PHASES
from semantic_work_plan import (
    BackendArmExecutionIdentity,
    ExecutionAttemptIdentity,
    SemanticRoster,
    SemanticSchemaError,
    SemanticWorkPlan,
    fork_backend_generation,
)


D = {
    name: format(index, "064x")
    for index, name in enumerate(
        (
            "source",
            "facts",
            "inputs",
            "prompt",
            "methodology",
            "obligations",
            "outputs",
            "tools",
            "resources",
            "capability",
        ),
        start=1,
    )
}


# Blueprint section 4 labels this the complete current registry inventory.
# Keep the denominator proof fixture-only: these tuples are not a production
# roster compiler and deliberately do not import the live phase registry.
SC_PHASE_FIXTURE = (
    "recon",
    "instantiate",
    "breadth",
    "rescan_prepare",
    "rescan",
    "inventory_prepare",
    "inventory_chunk_a",
    "inventory_chunk_b",
    "inventory_chunk_c",
    "inventory",
    "invariants",
    "invariants_p2",
    "depth",
    "attention_repair",
    "exploration_skeptic",
    "enumgap_exploration",
    "axis_coverage",
    "application_skeptic",
    "sc_semantic_dedup",
    "rag_sweep",
    "chain",
    "chain_agent2",
    "chain_iter2",
    "sc_verify_queue",
    "sc_verify_crithigh",
    "sc_verify_high_b",
    "sc_verify_high_c",
    "sc_verify_high_d",
    "sc_verify_high_e",
    "sc_verify_high_f",
    "sc_verify_high_g",
    "sc_verify_high_h",
    "sc_verify_high_i",
    "sc_verify_high_j",
    "sc_verify_medium_a",
    "sc_verify_medium_b",
    "sc_verify_medium_c",
    "sc_verify_medium_d",
    "sc_verify_medium_e",
    "sc_verify_medium_f",
    "sc_verify_medium_g",
    "sc_verify_medium_h",
    "sc_verify_medium_i",
    "sc_verify_medium_j",
    "sc_verify_low_a",
    "sc_verify_low_b",
    "sc_verify_low_c",
    "sc_verify_low_d",
    "sc_verify_low_e",
    "sc_verify_low_f",
    "sc_verify_low_g",
    "sc_verify_low_h",
    "sc_verify_low_i",
    "sc_verify_low_j",
    "sc_verify_aggregate",
    "sc_mechanical_verify",
    "post_verify_extract",
    "skeptic",
    "crossbatch",
    "severity_adjudication_shadow",
    "report_index",
    "report_body_writer_critical_high",
    "report_body_writer_medium",
    "report_body_writer_low_info",
    "report_critical_high",
    "report_critical_high_merge",
    "report_medium",
    "report_medium_merge",
    "report_low_info",
    "report_low_info_merge",
    "report_assemble",
    "report_dedup_agent",
    "report_dedup",
    "report_disposition",
    "report_floor",
)

L1_PHASE_FIXTURE = (
    "bake",
    "recon",
    "breadth",
    "graph_sweeps",
    "inventory_prepare",
    "inventory_chunk_a",
    "inventory_chunk_b",
    "inventory_chunk_c",
    "inventory",
    "location_recovery",
    "invariants",
    "invariants_p2",
    "depth",
    "attention_repair",
    "enumgap_exploration",
    "application_skeptic",
    "semantic_dedup",
    "rag_sweep",
    "verify_queue",
    "verify_crithigh",
    "verify_high_b",
    "verify_high_c",
    "verify_high_d",
    "verify_high_e",
    "verify_high_f",
    "verify_high_g",
    "verify_high_h",
    "verify_high_i",
    "verify_high_j",
    "verify_medium_a",
    "verify_medium_b",
    "verify_medium_c",
    "verify_medium_d",
    "verify_medium_e",
    "verify_medium_f",
    "verify_low_a",
    "verify_low_b",
    "verify_low_c",
    "verify_low_d",
    "verify_aggregate",
    "mechanical_verify",
    "post_verify_extract",
    "skeptic",
    "crossbatch",
    "severity_adjudication_shadow",
    "report_index",
    "report_body_writer_critical_high",
    "report_body_writer_medium",
    "report_body_writer_low_info",
    "report_critical_high",
    "report_critical_high_merge",
    "report_medium",
    "report_medium_merge",
    "report_low_info",
    "report_low_info_merge",
    "report_assemble",
    "report_dedup",
    "report_disposition",
    "report_floor",
)


def _plan(
    *,
    position: int = 1,
    denominator: int = 2,
    unit: str = "depth.token-flow.001",
) -> SemanticWorkPlan:
    return SemanticWorkPlan.create(
        run_id="run-fixture-001",
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        semantic_generation=1,
        phase_semantic_id="depth",
        roster_id="depth.g1",
        roster_position=position,
        roster_denominator=denominator,
        semantic_work_unit_id=unit,
        role_id="depth.token-flow",
        assignment_id="depth-findings-token-flow",
        semantic_template_id=(
            "BOUND_METHODOLOGY_OBLIGATION_ANALYSIS_V1"
        ),
        source_snapshot_digest=D["source"],
        deterministic_fact_snapshot_digests=(D["facts"],),
        semantic_input_manifest_digest=D["inputs"],
        semantic_prompt_snapshot_digest=D["prompt"],
        methodology_bundle_digest=D["methodology"],
        obligation_bundle_digest=D["obligations"],
        output_contract_digest=D["outputs"],
        tool_capability_manifest_digest=D["tools"],
        resource_grant_digest=D["resources"],
        model_capability_tier="R3_FRONTIER_REASONING",
        required_capabilities=(
            "SOURCE_READ",
            "SOURCE_SEARCH",
            "METHODOLOGY_READ",
            "ASSIGNED_OUTPUT_WRITE",
        ),
        retry_policy={
            "max_attempts": 2,
            "same_prompt": True,
            "same_model_capability_tier": True,
            "same_tools": True,
            "model_change_requires_new_generation": True,
        },
        completion_policy={
            "requires_process_scope_empty": True,
            "requires_stream_eof": True,
            "requires_parser_acceptance": True,
            "requires_exact_output_denominator": True,
            "requires_phase_io_incorporation": True,
        },
    )


def test_blueprint_phase_inventory_fixtures_cover_declared_denominators() -> None:
    assert len(SC_PHASE_FIXTURE) == len(set(SC_PHASE_FIXTURE)) == 75
    assert len(L1_PHASE_FIXTURE) == len(set(L1_PHASE_FIXTURE)) == 59
    assert SC_PHASE_FIXTURE == tuple(phase.name for phase in SC_PHASES)
    assert L1_PHASE_FIXTURE == tuple(phase.name for phase in L1_PHASES)


def test_plan_round_trip_is_canonical_digest_bound_and_immutable() -> None:
    plan = _plan()
    assert SemanticWorkPlan.from_bytes(plan.to_bytes()) == plan
    assert plan.to_bytes().endswith(b"\n")
    assert plan.semantic_digest == json.loads(plan.to_bytes())["semantic_digest"]
    with pytest.raises(FrozenInstanceError):
        plan.role_id = "changed"  # type: ignore[misc]

    tampered = json.loads(plan.to_bytes())
    tampered["role_id"] = "depth.external"
    with pytest.raises(SemanticSchemaError, match="semantic_digest"):
        SemanticWorkPlan.from_dict(tampered)


def test_roster_digest_and_order_are_stable_under_input_reordering() -> None:
    first = _plan(position=1, unit="depth.token-flow.001")
    second = _plan(position=2, unit="depth.external.002")
    a = SemanticRoster.create((first, second))
    b = SemanticRoster.create((second, first))
    assert a == b
    assert a.roster_digest == b.roster_digest
    assert a.ordered_semantic_work_unit_ids == (
        "depth.token-flow.001",
        "depth.external.002",
    )


@pytest.mark.parametrize(
    "mutation",
    (
        {"backend": "claude"},
        {"model": "opus"},
        {"tool": "Bash"},
        {"capability": "filesystem"},
        {"retry": 3},
        {"path": "C:/workspace"},
        {"timestamp": "2026-07-28T00:00:00Z"},
        {"host": "builder-01"},
    ),
)
def test_semantic_plan_rejects_backend_model_tool_retry_path_time_and_host_fields(
    mutation: dict[str, object],
) -> None:
    payload = _plan().to_dict()
    payload.update(mutation)
    with pytest.raises(SemanticSchemaError, match="unexpected"):
        SemanticWorkPlan.from_dict(payload)


def test_unknown_nested_model_tool_retry_and_capability_values_fail_closed() -> None:
    payload = _plan().to_dict()
    payload["model_capability_tier"] = "opus"
    with pytest.raises(SemanticSchemaError, match="model_capability_tier"):
        SemanticWorkPlan.from_dict(payload)

    payload = _plan().to_dict()
    payload["required_capabilities"] = [*payload["required_capabilities"], "Bash"]
    with pytest.raises(SemanticSchemaError, match="required_capabilities"):
        SemanticWorkPlan.from_dict(payload)

    payload = _plan().to_dict()
    payload["retry_policy"]["capacity_fallback_model"] = "other"
    with pytest.raises(SemanticSchemaError, match="unexpected"):
        SemanticWorkPlan.from_dict(payload)


def test_backend_change_preserves_semantic_key_but_changes_arm_and_generation() -> None:
    plan = _plan()
    claude = BackendArmExecutionIdentity.bind(
        plan,
        backend_arm_id="arm-claude",
        backend="claude",
        execution_generation=1,
        exact_model_id="claude-opus-exact",
        model_capability_tier="R3_FRONTIER_REASONING",
        capability_receipt_digest=D["capability"],
    )
    codex = fork_backend_generation(
        claude,
        backend_arm_id="arm-codex",
        backend="codex",
        exact_model_id="gpt-exact",
        capability_receipt_digest=format(11, "064x"),
    )
    assert claude.semantic_work_unit_key == plan.semantic_work_unit_key
    assert codex.semantic_work_unit_key == plan.semantic_work_unit_key
    assert codex.backend_arm_id != claude.backend_arm_id
    assert codex.execution_generation == claude.execution_generation + 1
    assert codex.execution_work_unit_key != claude.execution_work_unit_key
    assert not claude.is_exact_resume_of(codex)


def test_backend_switch_never_validates_as_identical_resume() -> None:
    plan = _plan()
    old = BackendArmExecutionIdentity.bind(
        plan,
        backend_arm_id="arm-a",
        backend="claude",
        execution_generation=7,
        exact_model_id="claude-exact",
        model_capability_tier="R3_FRONTIER_REASONING",
        capability_receipt_digest=D["capability"],
    )
    with pytest.raises(SemanticSchemaError, match="new backend arm"):
        fork_backend_generation(
            old,
            backend_arm_id="arm-a",
            backend="codex",
            exact_model_id="gpt-exact",
            capability_receipt_digest=format(12, "064x"),
        )
    with pytest.raises(SemanticSchemaError, match="backend must change"):
        fork_backend_generation(
            old,
            backend_arm_id="arm-b",
            backend="claude",
            exact_model_id="claude-exact",
            capability_receipt_digest=format(12, "064x"),
        )


def test_attempt_identity_is_bound_to_execution_generation_and_exact_ordinal() -> None:
    plan = _plan()
    execution = BackendArmExecutionIdentity.bind(
        plan,
        backend_arm_id="arm-claude",
        backend="claude",
        execution_generation=1,
        exact_model_id="claude-exact",
        model_capability_tier="R3_FRONTIER_REASONING",
        capability_receipt_digest=D["capability"],
    )
    first = ExecutionAttemptIdentity.bind(
        execution, plan=plan, attempt_number=1
    )
    second = ExecutionAttemptIdentity.bind(
        execution, plan=plan, attempt_number=2
    )
    assert first.execution_work_unit_key == execution.execution_work_unit_key
    assert first.attempt_key != second.attempt_key
    assert ExecutionAttemptIdentity.from_bytes(first.to_bytes()) == first


def test_digest_rejects_floats_and_plan_rejects_noncontiguous_roster() -> None:
    payload = _plan().to_dict()
    payload["semantic_generation"] = 1.0
    with pytest.raises(SemanticSchemaError, match="integer|float"):
        SemanticWorkPlan.from_dict(payload)

    first = _plan(
        position=1, unit="depth.token-flow.001", denominator=3
    )
    gap = _plan(position=3, unit="depth.external.003", denominator=3)
    with pytest.raises(SemanticSchemaError, match="roster_position"):
        SemanticRoster.create((first, gap))


def test_semantic_digest_changes_for_every_semantic_grant() -> None:
    plan = _plan()
    changed = replace(plan, resource_grant_digest=format(99, "064x"))
    assert changed.semantic_digest != plan.semantic_digest
    assert changed.semantic_work_unit_key == plan.semantic_work_unit_key
