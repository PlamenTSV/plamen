"""Independent red fixtures for the frozen backend/resource R3 tranche.

These tests state production-boundary invariants, not implementation details.
They intentionally remain red until every authority is replayed from its
independent parent at the consuming sink.
"""

from __future__ import annotations

from dataclasses import replace
from concurrent.futures import ThreadPoolExecutor
import gc
import inspect

import pytest

import backend_capability_registry as BCR
import resource_grant as RG
import resource_policy_authority as RPA
from backend_capability_registry import CapabilityRegistryError
from resource_grant import (
    ResourceGrant,
    ResourceGrantError,
    compile_resource_grant_from_policy,
    compile_resume_requirement_authority,
    compile_structural_test_preflight_request_from_resource_grant,
    validate_structural_test_resource_grant_against_semantic_work_plan,
)
from semantic_work_plan import (
    BackendArmExecutionIdentity,
    ExecutionAttemptIdentity,
    SemanticAttemptBundle,
    SemanticExecutionBundle,
)
from test_backend_capability_registry import (
    _compiled_bundle,
    _digest,
    _observation_authority,
    _receipt,
    _test_launch_context,
)
from test_resource_grant import _bundle, _model_registry
from test_resource_policy_authority import _plan


def _copy_grant_with(
    grant: ResourceGrant,
    *,
    max_concurrency: int,
) -> ResourceGrant:
    return ResourceGrant.create(
        profile=grant.profile,
        audit_mode=grant.audit_mode,
        semantic_work_unit_id=grant.semantic_work_unit_id,
        phase_semantic_id=grant.phase_semantic_id,
        resource_policy_digest=grant.resource_policy_digest,
        global_reservation_digest=grant.global_reservation_digest,
        parity_policy_digest=grant.parity_policy_digest,
        parity_mode=grant.parity_mode,
        workload_class=grant.workload_class,
        analysis_units=grant.analysis_units,
        max_input_tokens=grant.max_input_tokens,
        max_output_tokens=grant.max_output_tokens,
        tool_call_limits=grant.tool_call_limits,
        max_native_commands=grant.max_native_commands,
        max_native_wall_time_seconds=grant.max_native_wall_time_seconds,
        max_model_attempts=grant.max_model_attempts,
        semantic_timeout_seconds=grant.semantic_timeout_seconds,
        max_stdout_bytes=grant.max_stdout_bytes,
        max_stderr_bytes=grant.max_stderr_bytes,
        max_stream_line_bytes=grant.max_stream_line_bytes,
        scheduler_concurrency_class=grant.scheduler_concurrency_class,
        max_concurrency=max_concurrency,
        cache_policy=grant.cache_policy,
    )


def test_validation_sink_replays_policy_and_rejects_scheduler_expansion() -> None:
    grant, policy, reservation, _ = _bundle(max_concurrency=1)
    assert policy.parity_policy.max_concurrency == 1
    forged = _copy_grant_with(grant, max_concurrency=4)
    assert forged.parity_policy_digest == grant.parity_policy_digest

    with pytest.raises(
        ResourceGrantError,
        match="policy|parity|scheduler|replay",
    ):
        validate_structural_test_resource_grant_against_semantic_work_plan(
            forged,
            _plan(forged),
            policy_authority=policy,
            global_reservation=reservation,
        )


def test_module_private_token_cannot_mint_production_reservation_and_grant() -> None:
    grant, old_policy, old_reservation, parity = _bundle(
        max_concurrency=1
    )
    allocations = old_reservation.allocations

    with pytest.raises(
        (RPA.ResourcePolicyError, ResourceGrantError),
        match="production|issuer|scheduler|authority|opaque",
    ):
        forged_budget = RPA.ReservationBudgetAuthority(
            reservation_id=old_reservation.reservation_id,
            run_id=old_reservation.run_id,
            generation=old_reservation.generation,
            total_analysis_units=(
                old_reservation.total_analysis_units
            ),
            allocations_digest=RPA._reservation_allocations_digest(
                allocations
            ),
            phase_roster_digest=_digest(9_111),
            scheduler_budget_digest=_digest(9_112),
            authority_class="PRODUCTION_PHASE_ROSTER_SCHEDULER_V1",
            _promotion_token=RPA._RESERVATION_BUDGET_TOKEN,
        )
        forged_reservation = RPA.GlobalResourceReservation(
            reservation_id=old_reservation.reservation_id,
            run_id=old_reservation.run_id,
            generation=old_reservation.generation,
            total_analysis_units=(
                old_reservation.total_analysis_units
            ),
            allocations=allocations,
            budget_authority=forged_budget,
        )
        source = RPA.capture_resource_policy_source_snapshot(
            RPA.reviewed_resource_policy_source_bytes(
                "adaptive-au-v1-standard-strict-c1"
            )
        )
        forged_policy = RPA.compile_resource_policy_authority(
            policy_id=old_policy.policy_id,
            policy_generation=old_policy.policy_generation,
            profile=old_policy.profile,
            source_snapshot=source,
            global_reservation=forged_reservation,
            parity_policy=parity,
            ceilings=old_policy.ceilings,
        )
        compile_resource_grant_from_policy(
            policy_authority=forged_policy,
            global_reservation=forged_reservation,
            semantic_work_unit_id=grant.semantic_work_unit_id,
            audit_mode=grant.audit_mode,
            phase_semantic_id=grant.phase_semantic_id,
            workload_class=grant.workload_class,
        )


def test_capability_arm_rejects_same_process_self_resealed_authority() -> None:
    receipt = _receipt()
    request, request_authority, authority, *_ = _compiled_bundle(receipt)
    object.__setattr__(
        authority,
        "trusted_observation_root_digest",
        _digest(9_201),
    )
    object.__setattr__(
        authority,
        "provider_observation_authority_digest",
        _digest(9_202),
    )
    object.__setattr__(
        authority,
        "launch_generation_authority_digest",
        _digest(9_203),
    )
    object.__setattr__(
        authority,
        "_seal",
        authority.capability_authority_digest,
    )
    BCR._BACKEND_CAPABILITY_AUTHORITY_SEALS.issue(
        authority,
        authority.to_bytes(),
    )

    with pytest.raises(
        CapabilityRegistryError,
        match="promotion|observation|generation|seal|replay",
    ):
        BCR.CapabilityArm(
            request=request,
            request_authority=request_authority,
            receipt=receipt,
            capability_authority=authority,
        ).decision


def test_capability_arm_replays_bound_launch_generation_not_class_label() -> None:
    receipt = _receipt()
    request, request_authority, authority, *_ = _compiled_bundle(receipt)
    parents = authority._bound_parents
    assert type(parents) is BCR.BackendCapabilityPromotionParents
    launch_generation = parents.launch_generation_authority
    object.__setattr__(
        launch_generation,
        "resource_authority_class",
        "PRODUCTION_RESOURCE_AUTHORIZED",
    )
    object.__setattr__(
        launch_generation,
        "_seal",
        launch_generation.launch_generation_authority_digest,
    )
    BCR._LAUNCH_GENERATION_SEALS.issue(
        launch_generation,
        launch_generation.launch_generation_authority_digest.encode(
            "ascii"
        ),
    )

    with pytest.raises(
        CapabilityRegistryError,
        match="production|reservation|generation|parent|replay",
    ):
        BCR.CapabilityArm(
            request=request,
            request_authority=request_authority,
            receipt=receipt,
            capability_authority=authority,
        )


def test_resume_authority_from_foreign_run_is_rejected_at_preflight() -> None:
    grant, policy, reservation, _ = _bundle()
    registry, entry, intent = _model_registry()
    foreign_plan = replace(
        _plan(grant),
        run_id="foreign-run",
        tool_capability_manifest_digest=_digest(3),
    )
    foreign_execution = BackendArmExecutionIdentity.bind(
        foreign_plan,
        backend_arm_id="foreign-arm",
        backend="codex",
        execution_generation=1,
        exact_model_id="gpt-5.6-sol",
        model_capability_tier="R3_FRONTIER_REASONING",
        capability_receipt_digest=_digest(9_301),
    )
    foreign_attempt = ExecutionAttemptIdentity.bind(
        foreign_execution,
        plan=foreign_plan,
        attempt_number=2,
    )
    foreign_resume = compile_resume_requirement_authority(
        semantic_attempt_bundle=SemanticAttemptBundle(
            execution_bundle=SemanticExecutionBundle(
                plan=foreign_plan,
                execution=foreign_execution,
            ),
            attempt=foreign_attempt,
        ),
        grant=grant,
    )
    assert foreign_plan.run_id != reservation.run_id

    with pytest.raises(
        ResourceGrantError,
        match="run|attempt|execution|resume|reservation",
    ):
        compile_structural_test_preflight_request_from_resource_grant(
            grant=grant,
            registry=registry,
            policy_entry=entry,
            launch_intent=intent,
            expected_model_policy_registry_digest=(
                registry.registry_digest
            ),
            expected_policy_entry_digest=entry.policy_entry_digest,
            expected_launch_intent_digest=intent.launch_intent_digest,
            resource_policy_authority=policy,
            global_reservation=reservation,
            semantic_requirement_digest=_digest(2),
            tool_capability_manifest_digest=_digest(3),
            resume_requirement_authority=foreign_resume,
        )


def test_backend_promotion_rejects_structural_test_reservation_root() -> None:
    receipt = _receipt()
    (
        request,
        request_authority,
        _,
        registry,
        entry,
        intent,
        semantic_digest,
        resource_digest,
        tool_digest,
    ) = _compiled_bundle(receipt)
    plan, reservation, launch_generation = _test_launch_context(
        intent,
        resource_grant_digest=resource_digest,
        tool_capability_manifest_digest=tool_digest,
        model_capability_tier=receipt.semantic_model_capability_tier,
    )
    structural_grant, structural_policy, _, _ = _bundle()
    with pytest.raises(
        CapabilityRegistryError,
        match="production|structural|scheduler|reservation",
    ):
        BCR.promote_backend_capability_receipt(
            request=request,
            request_authority=request_authority,
            receipt=receipt,
            registry=registry,
            policy_entry=entry,
            launch_intent=intent,
            expected_model_policy_registry_digest=(
                registry.registry_digest
            ),
            expected_policy_entry_digest=entry.policy_entry_digest,
            expected_launch_intent_digest=intent.launch_intent_digest,
            expected_semantic_requirement_digest=semantic_digest,
            expected_resource_grant_digest=resource_digest,
            expected_tool_capability_manifest_digest=tool_digest,
            observation_authority=_observation_authority(
                receipt,
                intent,
            ),
            semantic_work_plan=plan,
            global_reservation=reservation,
            launch_generation_authority=launch_generation,
            resource_grant=structural_grant,
            resource_policy_authority=structural_policy,
        )


def test_reservation_denominator_and_aggregate_budget_are_bounded() -> None:
    oversized_denominator = tuple(
        RPA.ReservationAllocation(
            semantic_work_unit_id=f"work-{index:04d}",
            reserved_analysis_units=1,
        )
        for index in range(4_097)
    )
    with pytest.raises(
        RPA.ResourcePolicyError,
        match="allocation|denominator|count|bound",
    ):
        RPA.compile_structural_test_reservation_budget_authority(
            reservation_id="reservation-oversized",
            run_id="run-oversized",
            generation=1,
            total_analysis_units=len(oversized_denominator),
            allocations=oversized_denominator,
            phase_roster_digest=_digest(9_401),
            scheduler_budget_digest=_digest(9_402),
        )

    with pytest.raises(
        RPA.ResourcePolicyError,
        match="analysis|aggregate|total|bound",
    ):
        one = (
            RPA.ReservationAllocation(
                semantic_work_unit_id="work-oversized",
                reserved_analysis_units=1_000_001,
            ),
        )
        RPA.compile_structural_test_reservation_budget_authority(
            reservation_id="reservation-aggregate",
            run_id="run-aggregate",
            generation=1,
            total_analysis_units=1_000_001,
            allocations=one,
            phase_roster_digest=_digest(9_403),
            scheduler_budget_digest=_digest(9_404),
        )


def test_reservation_replay_bounds_bytes_and_rows_before_materialization(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, _, reservation, _ = _bundle()
    budget = reservation._budget_authority

    class OverconsumeList(list):
        def __len__(self) -> int:
            return 4_097

        def __iter__(self):  # type: ignore[no-untyped-def]
            raise AssertionError("allocation rows were over-consumed")

    decoded = reservation.to_dict()
    decoded["allocations"] = OverconsumeList()
    monkeypatch.setattr(RPA, "_decode", lambda _raw: decoded)
    with pytest.raises(
        RPA.ResourcePolicyError,
        match="allocation|denominator|count|bound",
    ):
        RPA.GlobalResourceReservation.from_bytes(
            b"{}\n",
            budget_authority=budget,
        )

    def must_not_decode(_raw: bytes):  # type: ignore[no-untyped-def]
        raise AssertionError("oversized reservation bytes were decoded")

    monkeypatch.setattr(RPA, "_decode", must_not_decode)
    with pytest.raises(
        RPA.ResourcePolicyError,
        match="byte|size|bound|large",
    ):
        RPA.GlobalResourceReservation.from_bytes(
            b"x" * (RPA.MAX_RESERVATION_CANONICAL_BYTES + 1),
            budget_authority=budget,
        )


def test_missing_production_scheduler_raises_canonical_typed_debt() -> None:
    grant, policy, reservation, _ = _bundle()
    with pytest.raises(ResourceGrantError) as caught:
        compile_resource_grant_from_policy(
            policy_authority=policy,
            global_reservation=reservation,
            semantic_work_unit_id=grant.semantic_work_unit_id,
            audit_mode=grant.audit_mode,
            phase_semantic_id=grant.phase_semantic_id,
            workload_class=grant.workload_class,
        )
    debt = getattr(caught.value, "debt", None)
    assert type(debt) is RPA.ResourceAuthorityDebt
    assert (
        RPA.ResourceAuthorityDebt.from_bytes(debt.to_bytes()).to_bytes()
        == debt.to_bytes()
    )
    assert debt.debt_code == "PRODUCTION_SCHEDULER_AUTHORITY_UNAVAILABLE"


def test_authority_seal_stores_are_not_permanent_raw_id_maps() -> None:
    assert not isinstance(
        RPA._RESOURCE_POLICY_AUTHORITY_SEALS,
        dict,
    )
    assert not isinstance(
        RPA._GLOBAL_RESOURCE_RESERVATION_SEALS,
        dict,
    )
    assert not isinstance(
        BCR._PROVIDER_OBSERVATION_AUTHORITY_SEALS,
        dict,
    )
    assert not isinstance(
        BCR._BACKEND_CAPABILITY_AUTHORITY_SEALS,
        dict,
    )


def test_seal_registry_lifetime_and_concurrent_replay_are_safe() -> None:
    receipt = _receipt()
    *_, intent, _, _, _ = _compiled_bundle(receipt)
    observation = _observation_authority(receipt, intent)
    identity = id(observation)
    registry = BCR._PROVIDER_OBSERVATION_AUTHORITY_SEALS
    assert identity in registry._entries

    with ThreadPoolExecutor(max_workers=16) as pool:
        results = tuple(
            pool.map(
                lambda _index: observation.require_exact_replay(),
                range(512),
            )
        )
    assert results == (None,) * 512

    del observation
    gc.collect()
    assert identity not in registry._entries


def test_structural_apis_are_explicit_and_never_production_authority() -> None:
    assert (
        "structural_test"
        in BCR.bind_structural_test_provider_launch_generation_authority.__name__
    )
    assert (
        "structural_test"
        in BCR.promote_structural_test_backend_capability_receipt.__name__
    )
    assert (
        "structural_test"
        in BCR.evaluate_structural_test_capability_preflight.__name__
    )
    assert (
        "structural_test"
        in RG.compile_structural_test_transport_plan.__name__
    )
    assert (
        "structural_test"
        in RG.compare_structural_test_paired_resource_grants.__name__
    )
    assert (
        "structural_test"
        in BCR.BackendCapabilityAuthority
        .validate_structural_test_bound_parents.__name__
    )
    assert (
        "structural_test"
        in BCR.BackendCapabilityAuthority
        .validate_structural_test_against.__name__
    )
    for production in (
        BCR.bind_provider_launch_generation_authority,
        BCR.promote_backend_capability_receipt,
        BCR.evaluate_capability_preflight,
        RG.compile_transport_plan,
        RG.compare_paired_resource_grants,
        BCR.BackendCapabilityAuthority.validate_bound_parents,
        BCR.BackendCapabilityAuthority.validate_against,
    ):
        assert "_structural_test_token" not in inspect.signature(
            production
        ).parameters

    receipt = _receipt()
    request, _, authority, *_ = _compiled_bundle(receipt)
    assert authority.resource_authority_class == "STRUCTURAL_TEST_ONLY"
    assert BCR.evaluate_structural_test_capability_preflight(
        request,
        receipt,
        authority=authority,
    ).eligible
    with pytest.raises(
        CapabilityRegistryError,
        match="production|structural|token",
    ):
        authority.validate_against(
            **authority._bound_parents.as_validation_kwargs(),
            _structural_test_token=BCR._STRUCTURAL_TEST_BACKEND_TOKEN,
        )
    with pytest.raises(
        CapabilityRegistryError,
        match="production|structural|resource class|replay",
    ):
        BCR.evaluate_capability_preflight(
            request,
            receipt,
            authority=authority,
        )


def test_budget_authority_cannot_be_mutated_and_resealed_as_production() -> None:
    _, _, reservation, _ = _bundle()
    budget = reservation._budget_authority
    object.__setattr__(
        budget,
        "authority_class",
        "PRODUCTION_PHASE_ROSTER_SCHEDULER_V1",
    )
    RPA._RESERVATION_BUDGET_AUTHORITY_SEALS.issue(
        budget,
        budget.to_bytes(),
    )
    resealed = reservation.to_bytes()
    object.__setattr__(
        reservation,
        "_sealed_reservation_bytes",
        resealed,
    )
    RPA._GLOBAL_RESOURCE_RESERVATION_SEALS.issue(
        reservation,
        resealed,
    )

    with pytest.raises(
        RPA.ResourcePolicyError,
        match="production|issuer|structural|proof|authority",
    ):
        reservation.require_production_budget_authority()


def test_transport_and_pair_sinks_replay_production_resource_parents() -> None:
    grant, policy, reservation, parity = _bundle()

    with pytest.raises(
        ResourceGrantError,
        match="production|structural|scheduler|reservation|authority",
    ) as transport_error:
        RG.compile_transport_plan(
            grant=grant,
            parity_policy=parity,
            grace_uses=(),
            resource_policy_authority=policy,
            global_reservation=reservation,
        )
    assert type(transport_error.value.debt) is RPA.ResourceAuthorityDebt

    with pytest.raises(
        ResourceGrantError,
        match="production|structural|scheduler|reservation|authority",
    ) as paired_error:
        RG.compare_paired_resource_grants(
            grant,
            grant,
            left_policy_authority=policy,
            left_global_reservation=reservation,
            right_policy_authority=policy,
            right_global_reservation=reservation,
        )
    assert type(paired_error.value.debt) is RPA.ResourceAuthorityDebt

    structural_plan = RG.compile_structural_test_transport_plan(
        grant=grant,
        parity_policy=parity,
        grace_uses=(),
    )
    comparison = RG.compare_structural_test_paired_resource_grants(
        grant,
        grant,
        left_transport_plan=structural_plan,
        right_transport_plan=structural_plan,
    )
    assert comparison.equal
    assert "CONCURRENCY_LEASE_AUTHORITY_MISSING" in (
        comparison.eligibility_debts
    )


def test_transport_use_denominator_is_bounded_before_materialization() -> None:
    grant, _, _, parity = _bundle(
        parity_mode="NON_PAIRED_OPERATIONAL",
        scheduler_concurrency_class="BOUNDED_POOL",
    )
    uses = tuple(
        RG.TransportGrace(
            resource_grant_digest=grant.resource_grant_digest,
            parity_policy_digest=parity.parity_policy_digest,
            semantic_work_unit_id=grant.semantic_work_unit_id,
            attempt_number=attempt,
            use_id=f"bounded-use-{attempt:03d}",
            authorized_max_grace_seconds=30,
            parity_mode=parity.parity_mode,
            grace_seconds=0,
            reason_code="PROCESS_STARTUP_ONLY",
        )
        for attempt in (1, 2, 3)
    )

    class FailIfOverConsumed:
        def __iter__(self):  # type: ignore[no-untyped-def]
            yield from uses
            raise AssertionError("transport iterable was over-consumed")

    with pytest.raises(ResourceGrantError, match="transport|use|attempt|bound"):
        RG.compile_structural_test_transport_plan(
            grant=grant,
            parity_policy=parity,
            grace_uses=FailIfOverConsumed(),
        )
