from __future__ import annotations

from dataclasses import replace

import pytest

from semantic_prompt_snapshot import (
    MethodologyFileIdentity,
    PromptSnapshotError,
    SEMANTIC_COMPLETION_LANGUAGE,
    SemanticPlanPromptBundle,
    bind_semantic_prompt_snapshot,
    capture_methodology_files,
    compile_semantic_prompt_snapshot,
    methodology_bundle_digest,
    obligation_bundle_digest,
    output_contract_digest,
    semantic_input_manifest_digest,
)
from semantic_work_plan import SemanticSchemaError, SemanticWorkPlan


def _digest(number: int) -> str:
    return format(number, "064x")


def _plan(prompt_digest: str) -> SemanticWorkPlan:
    plan = SemanticWorkPlan.create(
        run_id="run-bundle-fixture",
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        semantic_generation=1,
        phase_semantic_id="depth",
        roster_id="depth.g1",
        roster_position=1,
        roster_denominator=1,
        semantic_work_unit_id="depth.token-flow.001",
        role_id="depth.token-flow",
        assignment_id="depth-findings-token-flow",
        semantic_template_id=(
            "BOUND_METHODOLOGY_OBLIGATION_ANALYSIS_V1"
        ),
        source_snapshot_digest=_digest(1),
        deterministic_fact_snapshot_digests=(_digest(2),),
        semantic_input_manifest_digest=_digest(3),
        semantic_prompt_snapshot_digest=prompt_digest,
        methodology_bundle_digest=_digest(4),
        obligation_bundle_digest=_digest(5),
        output_contract_digest=_digest(6),
        tool_capability_manifest_digest=_digest(7),
        resource_grant_digest=_digest(8),
        model_capability_tier="R3_FRONTIER_REASONING",
        required_capabilities=(
            "SOURCE_READ",
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
    return replace(
        plan,
        methodology_bundle_digest=methodology_bundle_digest(
            capture_methodology_files(
                {
                    "methodology://evm/token-flow/SKILL.md": (
                        b"trace token flow\n"
                    ),
                }
            )
        ),
        obligation_bundle_digest=obligation_bundle_digest(
            ("OB-TOKEN-1",)
        ),
        semantic_input_manifest_digest=semantic_input_manifest_digest(
            ("workspace://source/src/Vault.sol",)
        ),
        output_contract_digest=output_contract_digest(
            logical_output_uris=(
                "artifact://output/depth_token_flow_findings.md",
            ),
            output_schema="plamen.finding-output.v1",
            completion_language=SEMANTIC_COMPLETION_LANGUAGE,
        ),
    )


def _snapshot(
    seed: SemanticWorkPlan,
    *,
    role_id: str | None = None,
    assignment_id: str | None = None,
):
    compile_plan = replace(
        seed,
        role_id=role_id or seed.role_id,
        assignment_id=assignment_id or seed.assignment_id,
    )
    return compile_semantic_prompt_snapshot(
        plan=compile_plan,
        methodology_sources={
            "methodology://evm/token-flow/SKILL.md": b"trace token flow\n",
        },
        obligation_ids=("OB-TOKEN-1",),
        logical_input_uris=("workspace://source/src/Vault.sol",),
        logical_output_uris=(
            "artifact://output/depth_token_flow_findings.md",
        ),
        output_schema="plamen.finding-output.v1",
    )


def _bound_pair() -> tuple[SemanticWorkPlan, object]:
    seed = _plan(_digest(99))
    snapshot = _snapshot(seed)
    return (
        _plan(snapshot.snapshot_digest),
        snapshot,
    )


def test_bundle_closes_the_plan_snapshot_digest_cycle() -> None:
    seed = _plan(_digest(99))
    snapshot = _snapshot(seed)
    bundle = bind_semantic_prompt_snapshot(seed, snapshot)
    plan = bundle.plan
    assert bundle.plan == plan
    assert bundle.snapshot == snapshot
    assert len(bundle.bundle_digest) == 64


def test_public_compiler_does_not_accept_caller_supplied_plan_binding() -> None:
    plan, _ = _bound_pair()
    with pytest.raises(TypeError, match="unexpected keyword"):
        compile_semantic_prompt_snapshot(
            plan=plan,
            plan_prompt_binding_digest=_digest(77),  # type: ignore[call-arg]
            methodology_sources={
                "methodology://evm/token-flow/SKILL.md": (
                    b"trace token flow\n"
                ),
            },
            obligation_ids=("OB-TOKEN-1",),
            logical_input_uris=("workspace://source/src/Vault.sol",),
            logical_output_uris=("artifact://output/findings.md",),
            output_schema="plamen.finding-output.v1",
        )


def test_template_selection_is_bound_and_derived_by_the_plan() -> None:
    plan, _ = _bound_pair()
    with pytest.raises(SemanticSchemaError, match="semantic_template_id"):
        replace(
            plan,
            semantic_template_id="BOUND_REPORT_PROJECTION_V1",
        )
    with pytest.raises(TypeError, match="unexpected keyword"):
        compile_semantic_prompt_snapshot(
            plan=plan,
            semantic_template_id="BOUND_REPORT_PROJECTION_V1",  # type: ignore[call-arg]
            methodology_sources={
                "methodology://evm/token-flow/SKILL.md": (
                    b"trace token flow\n"
                ),
            },
            obligation_ids=("OB-TOKEN-1",),
            logical_input_uris=("workspace://source/src/Vault.sol",),
            logical_output_uris=(
                "artifact://output/depth_token_flow_findings.md",
            ),
            output_schema="plamen.finding-output.v1",
        )


def test_plan_must_bind_the_exact_snapshot_digest() -> None:
    plan, snapshot = _bound_pair()
    with pytest.raises(PromptSnapshotError, match="snapshot_digest"):
        SemanticPlanPromptBundle(
            plan=replace(plan, semantic_prompt_snapshot_digest=_digest(88)),
            snapshot=snapshot,
        )


@pytest.mark.parametrize("field", ["role_id", "assignment_id"])
def test_shared_semantic_identity_cannot_drift(field: str) -> None:
    plan, snapshot = _bound_pair()
    forged = _snapshot(
        plan,
        **{field: f"{getattr(snapshot, field)}.other"},
    )
    with pytest.raises(PromptSnapshotError, match="prompt binding"):
        SemanticPlanPromptBundle(
            plan=replace(
                plan,
                semantic_prompt_snapshot_digest=forged.snapshot_digest,
            ),
            snapshot=forged,
        )


def test_prompt_binding_ignores_only_the_snapshot_edge() -> None:
    plan, _ = _bound_pair()
    assert plan.prompt_binding_digest == replace(
        plan,
        semantic_prompt_snapshot_digest=_digest(44),
    ).prompt_binding_digest
    assert plan.prompt_binding_digest != replace(
        plan,
        obligation_bundle_digest=_digest(45),
    ).prompt_binding_digest


def test_bundle_rejects_forged_compiler_identity() -> None:
    plan, snapshot = _bound_pair()
    forged = replace(snapshot, compiler_code_digest=_digest(46))
    forged_plan = replace(
        plan,
        semantic_prompt_snapshot_digest=forged.snapshot_digest,
    )
    with pytest.raises(PromptSnapshotError, match="compiler_code_digest"):
        SemanticPlanPromptBundle(plan=forged_plan, snapshot=forged)


def test_public_compiler_reconciles_obligations_inputs_and_outputs() -> None:
    plan, _ = _bound_pair()
    with pytest.raises(PromptSnapshotError, match="obligation"):
        compile_semantic_prompt_snapshot(
            plan=plan,
            methodology_sources={
                "methodology://evm/token-flow/SKILL.md": (
                    b"trace token flow\n"
                ),
            },
            obligation_ids=("OB-DIFFERENT",),
            logical_input_uris=("workspace://source/src/Vault.sol",),
            logical_output_uris=(
                "artifact://output/depth_token_flow_findings.md",
            ),
            output_schema="plamen.finding-output.v1",
        )
