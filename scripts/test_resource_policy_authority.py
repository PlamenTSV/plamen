from __future__ import annotations

from dataclasses import replace
import inspect
from types import SimpleNamespace

import pytest

from resource_grant import (
    ResourceGrantError,
    compile_structural_test_resource_grant_from_policy,
    replay_structural_test_resource_grant_from_policy,
    validate_structural_test_resource_grant_against_semantic_work_plan,
)
from resource_policy_authority import (
    ReservationAllocation,
    ResourcePolicyAuthority,
    ResourcePolicyError,
    capture_resource_policy_source_snapshot,
    compile_resource_policy_authority,
)
from semantic_work_plan import RetryPolicy, SemanticWorkPlan
from test_resource_grant import (
    _RESOURCE_POLICY_SOURCE_RAW,
    _bundle,
    _digest,
)

compile_resource_grant_from_policy = (
    compile_structural_test_resource_grant_from_policy
)
replay_resource_grant_from_policy = (
    replay_structural_test_resource_grant_from_policy
)
validate_resource_grant_against_semantic_work_plan = (
    validate_structural_test_resource_grant_against_semantic_work_plan
)


def _plan(grant, *, attempts: int = 2) -> SemanticWorkPlan:
    return SemanticWorkPlan.create(
        run_id="run-001",
        pipeline="sc",
        mode=grant.audit_mode,
        ecosystem="evm",
        semantic_generation=1,
        phase_semantic_id=grant.phase_semantic_id,
        roster_id="depth-g1",
        roster_position=1,
        roster_denominator=1,
        semantic_work_unit_id=grant.semantic_work_unit_id,
        role_id="depth-token-flow",
        assignment_id="depth-token-flow-assignment",
        semantic_template_id="BOUND_METHODOLOGY_OBLIGATION_ANALYSIS_V1",
        source_snapshot_digest=_digest(1),
        deterministic_fact_snapshot_digests=(_digest(2),),
        semantic_input_manifest_digest=_digest(3),
        semantic_prompt_snapshot_digest=_digest(4),
        methodology_bundle_digest=_digest(5),
        obligation_bundle_digest=_digest(6),
        output_contract_digest=_digest(7),
        tool_capability_manifest_digest=_digest(8),
        resource_grant_digest=grant.resource_grant_digest,
        model_capability_tier="R3_FRONTIER_REASONING",
        required_capabilities=(
            "SOURCE_READ",
            "SOURCE_SEARCH",
            "METHODOLOGY_READ",
            "ASSIGNED_OUTPUT_WRITE",
        ),
        retry_policy={
            "max_attempts": attempts,
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


def test_resource_policy_authority_and_global_reservation_are_replayed_not_opaque() -> None:
    grant, policy, reservation, _ = _bundle()
    assert (
        ResourcePolicyAuthority.from_bytes(
            policy.to_bytes(),
            source_snapshot=capture_resource_policy_source_snapshot(
                _RESOURCE_POLICY_SOURCE_RAW
            ),
            global_reservation=reservation,
            parity_policy=policy.parity_policy,
            ceilings=policy.ceilings,
        )
        == policy
    )
    assert (
        replay_resource_grant_from_policy(
            grant.to_bytes(),
            policy_authority=policy,
            global_reservation=reservation,
            semantic_work_unit_id=grant.semantic_work_unit_id,
            audit_mode=grant.audit_mode,
            phase_semantic_id=grant.phase_semantic_id,
            workload_class=grant.workload_class,
        )
        == grant
    )
    opaque_mutation = replace(grant, resource_policy_digest=_digest(999))
    with pytest.raises(ResourceGrantError, match="replay"):
        replay_resource_grant_from_policy(
            opaque_mutation.to_bytes(),
            policy_authority=policy,
            global_reservation=reservation,
            semantic_work_unit_id=grant.semantic_work_unit_id,
            audit_mode=grant.audit_mode,
            phase_semantic_id=grant.phase_semantic_id,
            workload_class=grant.workload_class,
        )
    with pytest.raises(ResourcePolicyError, match="trusted"):
        ResourcePolicyAuthority(
            policy_id=policy.policy_id,
            policy_generation=policy.policy_generation,
            profile=policy.profile,
            source_authority_digest=policy.source_authority_digest,
            global_reservation_digest=policy.global_reservation_digest,
            parity_policy=policy.parity_policy,
            ceilings=policy.ceilings,
        )


def test_worst_case_totals_and_retry_policy_replay_are_exact() -> None:
    grant, policy, reservation, _ = _bundle()
    assert grant.worst_case_totals == {
        "reserved_analysis_units": 2,
        "input_tokens": 131_072,
        "output_tokens": 16_384,
        "tool_calls": 48,
        "native_commands": 0,
        "native_wall_time_seconds": 0,
        "semantic_timeout_seconds": 7_200,
        "stdout_bytes": 4_000_000,
        "stderr_bytes": 2_000_000,
    }
    plan = _plan(grant)
    validate_resource_grant_against_semantic_work_plan(
        grant,
        plan,
        policy_authority=policy,
        global_reservation=reservation,
    )
    assert (
        replay_resource_grant_from_policy(
            grant.to_bytes(),
            policy_authority=policy,
            global_reservation=reservation,
            semantic_work_unit_id=grant.semantic_work_unit_id,
            audit_mode=grant.audit_mode,
            phase_semantic_id=grant.phase_semantic_id,
            workload_class=grant.workload_class,
            semantic_work_plan=plan,
        )
        == grant
    )
    mismatched = replace(
        plan,
        retry_policy=RetryPolicy(
            max_attempts=1,
            same_prompt=True,
            same_model_capability_tier=True,
            same_tools=True,
            model_change_requires_new_generation=True,
        ),
    )
    with pytest.raises(ResourceGrantError, match="retry-policy"):
        validate_resource_grant_against_semantic_work_plan(
            grant,
            mismatched,
            policy_authority=policy,
            global_reservation=reservation,
        )


def test_work_plan_authority_is_exact_typed_strict_and_reservation_bound() -> None:
    grant, policy, reservation, _ = _bundle()
    plan = _plan(grant)

    with pytest.raises(ResourceGrantError, match="typed|exact"):
        validate_resource_grant_against_semantic_work_plan(
            grant,
            SimpleNamespace(
                **{
                    **plan.to_dict(),
                    "retry_policy": SimpleNamespace(
                        max_attempts=grant.max_execution_attempts,
                        same_prompt="yes",
                        same_model_capability_tier="yes",
                        same_tools="yes",
                        model_change_requires_new_generation="yes",
                    ),
                }
            ),
            policy_authority=policy,
            global_reservation=reservation,
        )

    for drifted in (
        replace(plan, run_id="different-run"),
        replace(plan, semantic_generation=77),
    ):
        with pytest.raises(ResourceGrantError, match="reservation|run|generation"):
            validate_resource_grant_against_semantic_work_plan(
                grant,
                drifted,
                policy_authority=policy,
                global_reservation=reservation,
            )


def test_resource_policy_compiler_has_no_same_caller_expected_digest() -> None:
    from resource_policy_authority import compile_resource_policy_authority

    assert "expected_source_authority_digest" not in inspect.signature(
        compile_resource_policy_authority
    ).parameters


def test_unreviewed_resource_policy_source_is_explicitly_unavailable() -> None:
    with pytest.raises(ResourcePolicyError, match="reviewed|unavailable|source"):
        capture_resource_policy_source_snapshot(
            b'{"schema":"fixture.resource-policy-source.v1"}\n'
        )


@pytest.mark.parametrize(
    "identity",
    (
        "xox" + "b-123456789012-abcdefghijklmnop",
        "sk-proj-abcdefghijklmnopqrstuv",
        "../resource-policy",
        "policy\u202ehidden",
    ),
)
def test_resource_policy_identity_grammar_rejects_secrets_and_ambiguity(
    identity: str,
) -> None:
    _, policy, _, _ = _bundle()
    with pytest.raises(ResourcePolicyError, match="privacy-safe|identity"):
        replace(policy.parity_policy, policy_id=identity)


def test_resource_policy_authority_rejects_post_construction_ceiling_expansion() -> None:
    _, policy, reservation, _ = _bundle()
    expanded = replace(
        policy.ceilings[0],
        max_input_tokens_per_attempt=65_537,
    )
    object.__setattr__(policy, "ceilings", (expanded,))
    object.__setattr__(policy, "_sealed_authority_bytes", policy.to_bytes())

    with pytest.raises(
        (ResourcePolicyError, ResourceGrantError),
        match="seal|replay|source|drift",
    ):
        compile_resource_grant_from_policy(
            policy_authority=policy,
            global_reservation=reservation,
            semantic_work_unit_id="work-depth-001",
            audit_mode="thorough",
            phase_semantic_id="depth",
            workload_class="STANDARD_ANALYSIS",
        )


def test_resource_policy_authority_subclass_cannot_override_replay_checks() -> None:
    _, policy, reservation, _ = _bundle()

    class ForgedResourcePolicyAuthority(ResourcePolicyAuthority):
        def __post_init__(
            self,
            _authority_token: object,
            _source_snapshot: object,
        ) -> None:
            pass

        def require_exact_replay(self) -> None:
            pass

    forged = ForgedResourcePolicyAuthority(
        policy_id=policy.policy_id,
        policy_generation=policy.policy_generation,
        profile=policy.profile,
        source_authority_digest=policy.source_authority_digest,
        global_reservation_digest=policy.global_reservation_digest,
        parity_policy=policy.parity_policy,
        ceilings=policy.ceilings,
    )
    with pytest.raises(ResourceGrantError, match="typed|exact"):
        compile_resource_grant_from_policy(
            policy_authority=forged,
            global_reservation=reservation,
            semantic_work_unit_id="work-depth-001",
            audit_mode="thorough",
            phase_semantic_id="depth",
            workload_class="STANDARD_ANALYSIS",
        )


def test_runtime_allocation_spoof_cannot_mint_grant_or_launch_authority() -> None:
    import backend_capability_registry as BCR

    grant, policy, reservation, _ = _bundle()
    original_bytes = reservation.to_bytes()

    class RuntimeAllocationSpoof(ReservationAllocation):
        def to_dict(self) -> dict[str, object]:
            return {
                "semantic_work_unit_id": "work-depth-001",
                "reserved_analysis_units": 2,
            }

        def __eq__(self, _other: object) -> bool:
            return True

    evil = RuntimeAllocationSpoof(
        semantic_work_unit_id="work-evil",
        reserved_analysis_units=2,
    )
    object.__setattr__(reservation, "allocations", (evil,))

    assert reservation.to_bytes() == original_bytes
    with pytest.raises(ResourcePolicyError, match="exact|seal|replay|typed"):
        reservation.allocation_for("work-evil")
    with pytest.raises(ResourceGrantError, match="exact|seal|replay|typed"):
        compile_resource_grant_from_policy(
            policy_authority=policy,
            global_reservation=reservation,
            semantic_work_unit_id="work-evil",
            audit_mode="thorough",
            phase_semantic_id="depth",
            workload_class="STANDARD_ANALYSIS",
        )

    plan = replace(
        _plan(grant),
        semantic_work_unit_id="work-evil",
    )
    intent = BCR.BackendLaunchIntent(
        backend="codex",
        adapter_id="codex-exec-v1",
        adapter_version="1.0.0",
        provider_cli_name="codex-cli",
        provider_cli_version="1.2.3",
        executable_sha256=_digest(801),
        executable_size_bytes=123,
        os_family="windows",
        account_mode="CHATGPT_ENTITLEMENT",
        transport_capability="HEADLESS_TRANSPORT",
    )
    with pytest.raises(
        BCR.CapabilityRegistryError,
        match="exact|seal|replay|reservation",
    ):
        BCR.bind_structural_test_provider_launch_generation_authority(
            semantic_work_plan=plan,
            global_reservation=reservation,
            launch_intent=intent,
        )


def test_policy_ceiling_and_parity_are_derived_from_exact_reviewed_source() -> None:
    _, policy, reservation, parity = _bundle()
    source_snapshot = capture_resource_policy_source_snapshot(
        _RESOURCE_POLICY_SOURCE_RAW
    )
    narrowed = replace(
        policy.ceilings[0],
        max_input_tokens_per_attempt=32_768,
    )

    with pytest.raises(
        ResourcePolicyError,
        match="source|reviewed|ceiling|replay",
    ):
        compile_resource_policy_authority(
            policy_id=policy.policy_id,
            policy_generation=policy.policy_generation,
            profile=policy.profile,
            source_snapshot=source_snapshot,
            global_reservation=reservation,
            parity_policy=parity,
            ceilings=(narrowed,),
        )

    unrelated_parity = replace(
        parity,
        source_authority_digest=_digest(9_991),
    )
    with pytest.raises(
        ResourcePolicyError,
        match="source|reviewed|parity|replay",
    ):
        compile_resource_policy_authority(
            policy_id=policy.policy_id,
            policy_generation=policy.policy_generation,
            profile=policy.profile,
            source_snapshot=source_snapshot,
            global_reservation=reservation,
            parity_policy=unrelated_parity,
            ceilings=policy.ceilings,
        )


def test_arbitrary_rootless_global_reservation_cannot_mint_large_budget() -> None:
    from resource_policy_authority import GlobalResourceReservation

    with pytest.raises(
        ResourcePolicyError,
        match="roster|scheduler|budget|authority|trusted",
    ):
        GlobalResourceReservation(
            reservation_id="self-minted-reservation",
            run_id="self-minted-run",
            generation=1,
            total_analysis_units=1_000_000,
            allocations=(
                ReservationAllocation(
                    semantic_work_unit_id="work-evil",
                    reserved_analysis_units=2,
                ),
            ),
        )
