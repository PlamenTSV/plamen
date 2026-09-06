from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
import json

import pytest

from backend_capability_registry import (
    BackendLaunchIntent,
    CapabilityPreflightRequest,
    CapabilityRegistryError,
    ModelPolicyEntry,
    ModelPolicyRegistry,
)
from resource_grant import (
    PairedResourceComparison,
    ResourceGrant,
    ResourceGrantError,
    ResumeRequirementAuthority,
    ToolCallLimit,
    TransportGrace,
    TransportPlan,
    compile_resource_grant_from_policy,
    compile_structural_test_resource_grant_from_policy,
    compile_structural_test_preflight_request_from_resource_grant,
    compile_structural_test_transport_plan,
    compile_transport_plan,
    compile_resume_requirement_authority,
    replay_resource_grant_from_policy,
    replay_structural_test_preflight_request_authority_from_resource_grant,
    compare_paired_resource_grants,
    compare_structural_test_paired_resource_grants,
)
from semantic_work_plan import (
    ANALYSIS_TEMPLATE_ID,
    NATIVE_TEMPLATE_ID,
    BackendArmExecutionIdentity,
    CompletionPolicy,
    ExecutionAttemptIdentity,
    RetryPolicy,
    SemanticAttemptBundle,
    SemanticExecutionBundle,
    SemanticWorkPlan,
)
from resource_policy_authority import (
    GlobalResourceReservation,
    ParityPolicyAuthority,
    PolicyToolLimit,
    ReservationAllocation,
    ResourceCeiling,
    ResourcePolicyAuthority,
    ResourcePolicyError,
    capture_resource_policy_source_snapshot,
    compile_resource_policy_authority,
    compile_structural_test_reservation_budget_authority,
    reviewed_resource_policy_source_bytes,
)

compile_preflight_request_from_resource_grant = (
    compile_structural_test_preflight_request_from_resource_grant
)
replay_preflight_request_authority_from_resource_grant = (
    replay_structural_test_preflight_request_authority_from_resource_grant
)
compile_transport_plan = compile_structural_test_transport_plan
compare_paired_resource_grants = (
    compare_structural_test_paired_resource_grants
)


_RESOURCE_POLICY_SOURCE_RAW = reviewed_resource_policy_source_bytes(
    "adaptive-au-v1-standard-strict-c2"
)


def _digest(number: int) -> str:
    return format(number, "064x")


def _model_registry() -> tuple[
    ModelPolicyRegistry,
    ModelPolicyEntry,
    BackendLaunchIntent,
]:
    entry = ModelPolicyEntry(
        policy_id="codex-r3",
        backend="codex",
        semantic_model_capability_tier="R3_FRONTIER_REASONING",
        exact_model_id="gpt-5.6-sol",
        reasoning_mode="xhigh",
    )
    registry = ModelPolicyRegistry.create((entry,))
    intent = BackendLaunchIntent(
        backend="codex",
        adapter_id="codex-exec-v1",
        adapter_version="1.0.0",
        provider_cli_name="codex-cli",
        provider_cli_version="1.2.3",
        executable_sha256=_digest(1),
        executable_size_bytes=123,
        os_family="windows",
        account_mode="CHATGPT_ENTITLEMENT",
        transport_capability="HEADLESS_TRANSPORT",
    )
    return registry, entry, intent


def _resume_authority(
    grant: ResourceGrant,
    entry: ModelPolicyEntry,
    *,
    tool_capability_manifest_digest: str = _digest(3),
    attempt_number: int = 1,
) -> ResumeRequirementAuthority:
    plan = SemanticWorkPlan.create(
        run_id="run-001",
        pipeline="sc",
        mode=grant.audit_mode,
        ecosystem="evm",
        semantic_generation=1,
        phase_semantic_id=grant.phase_semantic_id,
        roster_id="roster-001",
        roster_position=1,
        roster_denominator=1,
        semantic_work_unit_id=grant.semantic_work_unit_id,
        role_id="depth",
        assignment_id="assignment-001",
        semantic_template_id=(
            NATIVE_TEMPLATE_ID
            if entry.semantic_model_capability_tier
            == "N0_NATIVE_DETERMINISTIC"
            else ANALYSIS_TEMPLATE_ID
        ),
        source_snapshot_digest=_digest(801),
        deterministic_fact_snapshot_digests=(_digest(802),),
        semantic_input_manifest_digest=_digest(803),
        semantic_prompt_snapshot_digest=_digest(804),
        methodology_bundle_digest=_digest(805),
        obligation_bundle_digest=_digest(806),
        output_contract_digest=_digest(807),
        tool_capability_manifest_digest=(
            tool_capability_manifest_digest
        ),
        resource_grant_digest=grant.resource_grant_digest,
        model_capability_tier=entry.semantic_model_capability_tier,
        required_capabilities=tuple(
            row.tool_capability for row in grant.tool_call_limits
        ),
        retry_policy=RetryPolicy(
            max_attempts=grant.max_execution_attempts,
            same_prompt=True,
            same_model_capability_tier=True,
            same_tools=True,
            model_change_requires_new_generation=True,
        ),
        completion_policy=CompletionPolicy(
            requires_process_scope_empty=True,
            requires_stream_eof=True,
            requires_parser_acceptance=True,
            requires_exact_output_denominator=True,
            requires_phase_io_incorporation=True,
        ),
    )
    execution = BackendArmExecutionIdentity.bind(
        plan,
        backend_arm_id=f"{entry.backend}-arm-001",
        backend=entry.backend,
        execution_generation=1,
        exact_model_id=entry.exact_model_id.replace(":", "-"),
        model_capability_tier=entry.semantic_model_capability_tier,
        capability_receipt_digest=_digest(808),
    )
    attempt = ExecutionAttemptIdentity.bind(
        execution,
        plan=plan,
        attempt_number=attempt_number,
    )
    return compile_resume_requirement_authority(
        semantic_attempt_bundle=SemanticAttemptBundle(
            execution_bundle=SemanticExecutionBundle(
                plan=plan,
                execution=execution,
            ),
            attempt=attempt,
        ),
        grant=grant,
    )


def _bundle(
    *,
    workload_class: str = "STANDARD_ANALYSIS",
    **overrides: object,
) -> tuple[
    ResourceGrant,
    ResourcePolicyAuthority,
    GlobalResourceReservation,
    ParityPolicyAuthority,
]:
    kwargs: dict[str, object] = {
        "profile": "adaptive-au-v1",
        "audit_mode": "thorough",
        "semantic_work_unit_id": "work-depth-001",
        "phase_semantic_id": "depth",
        "workload_class": workload_class,
        "analysis_units": 1,
        "max_input_tokens": 65_536,
        "max_output_tokens": 8_192,
        "tool_call_limits": (
            ToolCallLimit("SOURCE_READ", 12),
            ToolCallLimit("SOURCE_SEARCH", 8),
            ToolCallLimit("METHODOLOGY_READ", 3),
            ToolCallLimit("ASSIGNED_OUTPUT_WRITE", 1),
        ),
        "max_native_commands": 0,
        "max_native_wall_time_seconds": 0,
        "max_model_attempts": 2,
        "semantic_timeout_seconds": 3_600,
        "max_stdout_bytes": 2_000_000,
        "max_stderr_bytes": 1_000_000,
        "max_stream_line_bytes": 65_536,
        "scheduler_concurrency_class": "STRICT_PAIRED",
        "max_concurrency": 2,
        "cache_policy": "COLD_REQUIRED",
        "parity_mode": "STRICT_PAIRED",
    }
    kwargs.update(overrides)
    workload_class = str(kwargs["workload_class"])
    tools = tuple(kwargs["tool_call_limits"])
    max_model_attempts = int(kwargs["max_model_attempts"])
    policy_attempts = (
        1 if workload_class == "NATIVE_DETERMINISTIC" else max_model_attempts
    )
    if workload_class == "PROOF_CAPABLE":
        source_id = "adaptive-au-v1-proof-strict-c2"
    elif workload_class == "NATIVE_DETERMINISTIC":
        source_id = "adaptive-au-v1-native-operational-c1"
    elif kwargs["parity_mode"] == "NON_PAIRED_OPERATIONAL":
        source_id = "adaptive-au-v1-standard-operational-c2"
    elif kwargs["max_concurrency"] == 1:
        source_id = "adaptive-au-v1-standard-strict-c1"
    else:
        source_id = "adaptive-au-v1-standard-strict-c2"
    source_snapshot = capture_resource_policy_source_snapshot(
        reviewed_resource_policy_source_bytes(source_id)
    )
    parity = ParityPolicyAuthority(
        policy_id="parity-policy-001",
        policy_generation=1,
        parity_mode=str(kwargs["parity_mode"]),
        scheduler_concurrency_class=str(
            kwargs["scheduler_concurrency_class"]
        ),
        max_concurrency=int(kwargs["max_concurrency"]),
        cache_policy=str(kwargs["cache_policy"]),
        max_transport_grace_seconds_per_use=(
            0
            if kwargs["parity_mode"] == "STRICT_PAIRED"
            else 30
        ),
        source_authority_digest=source_snapshot.source_authority_digest,
    )
    reserved = int(kwargs["analysis_units"]) * policy_attempts
    allocations = (
        ReservationAllocation(
            semantic_work_unit_id=str(
                kwargs["semantic_work_unit_id"]
            ),
            reserved_analysis_units=reserved,
        ),
    )
    reservation_budget_authority = (
        compile_structural_test_reservation_budget_authority(
            reservation_id="reservation-001",
            run_id="run-001",
            generation=1,
            total_analysis_units=max(reserved, 1),
            allocations=allocations,
            phase_roster_digest=_digest(710),
            scheduler_budget_digest=_digest(711),
        )
    )
    reservation = GlobalResourceReservation(
        reservation_id="reservation-001",
        run_id="run-001",
        generation=1,
        total_analysis_units=max(reserved, 1),
        allocations=allocations,
        budget_authority=reservation_budget_authority,
    )
    ceiling = ResourceCeiling(
        audit_mode=str(kwargs["audit_mode"]),
        phase_semantic_id=str(kwargs["phase_semantic_id"]),
        workload_class=workload_class,
        analysis_units_per_attempt=int(kwargs["analysis_units"]),
        max_attempts=policy_attempts,
        max_input_tokens_per_attempt=int(kwargs["max_input_tokens"]),
        max_output_tokens_per_attempt=int(kwargs["max_output_tokens"]),
        tool_limits=tuple(
            PolicyToolLimit(row.tool_capability, row.max_calls)
            for row in tools
        ),
        max_native_commands_per_attempt=int(
            kwargs["max_native_commands"]
        ),
        max_native_wall_time_seconds_per_attempt=int(
            kwargs["max_native_wall_time_seconds"]
        ),
        semantic_timeout_seconds_per_attempt=int(
            kwargs["semantic_timeout_seconds"]
        ),
        max_stdout_bytes_per_attempt=int(kwargs["max_stdout_bytes"]),
        max_stderr_bytes_per_attempt=int(kwargs["max_stderr_bytes"]),
        max_stream_line_bytes=int(kwargs["max_stream_line_bytes"]),
    )
    authority = compile_resource_policy_authority(
        policy_id="resource-policy-001",
        policy_generation=1,
        profile=str(kwargs["profile"]),
        source_snapshot=source_snapshot,
        global_reservation=reservation,
        parity_policy=parity,
        ceilings=(ceiling,),
    )
    grant = compile_structural_test_resource_grant_from_policy(
        policy_authority=authority,
        global_reservation=reservation,
        semantic_work_unit_id=str(kwargs["semantic_work_unit_id"]),
        audit_mode=str(kwargs["audit_mode"]),
        phase_semantic_id=str(kwargs["phase_semantic_id"]),
        workload_class=workload_class,
    )
    return grant, authority, reservation, parity


def _standard(**overrides: object) -> ResourceGrant:
    try:
        return _bundle(**overrides)[0]
    except ResourcePolicyError:
        kwargs: dict[str, object] = {
            "profile": "adaptive-au-v1",
            "audit_mode": "thorough",
            "semantic_work_unit_id": "work-depth-001",
            "phase_semantic_id": "depth",
            "resource_policy_digest": _digest(101),
            "global_reservation_digest": _digest(102),
            "parity_policy_digest": _digest(103),
            "parity_mode": "STRICT_PAIRED",
            "workload_class": "STANDARD_ANALYSIS",
            "analysis_units": 1,
            "max_input_tokens": 65_536,
            "max_output_tokens": 8_192,
            "tool_call_limits": (
                ToolCallLimit("SOURCE_READ", 12),
                ToolCallLimit("SOURCE_SEARCH", 8),
                ToolCallLimit("METHODOLOGY_READ", 3),
                ToolCallLimit("ASSIGNED_OUTPUT_WRITE", 1),
            ),
            "max_native_commands": 0,
            "max_native_wall_time_seconds": 0,
            "max_model_attempts": 2,
            "semantic_timeout_seconds": 3_600,
            "max_stdout_bytes": 2_000_000,
            "max_stderr_bytes": 1_000_000,
            "max_stream_line_bytes": 65_536,
            "scheduler_concurrency_class": "STRICT_PAIRED",
            "max_concurrency": 2,
            "cache_policy": "COLD_REQUIRED",
        }
        kwargs.update(overrides)
        return ResourceGrant.create(**kwargs)


def _proof(**overrides: object) -> ResourceGrant:
    kwargs: dict[str, object] = {
        "profile": "adaptive-au-v1",
        "audit_mode": "thorough",
        "analysis_units": 2,
        "max_input_tokens": 131_072,
        "max_output_tokens": 12_288,
        "tool_call_limits": (
            ToolCallLimit("SOURCE_READ", 24),
            ToolCallLimit("SOURCE_SEARCH", 12),
            ToolCallLimit("METHODOLOGY_READ", 6),
            ToolCallLimit("ASSIGNED_OUTPUT_WRITE", 2),
            ToolCallLimit("NATIVE_TEST", 4),
        ),
        "max_native_commands": 4,
        "max_native_wall_time_seconds": 1_200,
        "max_model_attempts": 2,
        "semantic_timeout_seconds": 7_200,
        "max_stdout_bytes": 4_000_000,
        "max_stderr_bytes": 2_000_000,
        "max_stream_line_bytes": 131_072,
        "scheduler_concurrency_class": "STRICT_PAIRED",
        "max_concurrency": 2,
        "cache_policy": "COLD_REQUIRED",
    }
    kwargs.update(overrides)
    try:
        return _bundle(workload_class="PROOF_CAPABLE", **kwargs)[0]
    except ResourcePolicyError:
        return ResourceGrant.create(
            resource_policy_digest=_digest(201),
            global_reservation_digest=_digest(202),
            parity_policy_digest=_digest(203),
            parity_mode="STRICT_PAIRED",
            semantic_work_unit_id="work-depth-001",
            phase_semantic_id="depth",
            workload_class="PROOF_CAPABLE",
            **kwargs,
        )


def test_standard_and_proof_au_boundaries_match_blueprint() -> None:
    standard = _standard()
    proof = _proof()
    assert (
        standard.analysis_units,
        standard.max_input_tokens,
        standard.max_output_tokens,
        standard.max_tool_calls,
    ) == (1, 65_536, 8_192, 24)
    assert (
        proof.analysis_units,
        proof.max_input_tokens,
        proof.max_output_tokens,
        proof.max_tool_calls,
    ) == (2, 131_072, 12_288, 48)


def test_grant_is_canonical_digest_bound_immutable_and_reorder_stable() -> None:
    grant = _standard()
    reordered = _standard(
        tool_call_limits=tuple(reversed(grant.tool_call_limits))
    )
    assert grant == reordered
    assert grant.to_bytes() == reordered.to_bytes()
    assert ResourceGrant.from_bytes(grant.to_bytes()) == grant
    assert json.loads(grant.to_bytes())["resource_grant_digest"] == (
        grant.resource_grant_digest
    )
    with pytest.raises(FrozenInstanceError):
        grant.max_input_tokens = 1  # type: ignore[misc]


@pytest.mark.parametrize(
    "field",
    (
        "analysis_units",
        "max_input_tokens",
        "max_output_tokens",
        "max_native_commands",
        "max_native_wall_time_seconds",
        "max_model_attempts",
        "semantic_timeout_seconds",
        "max_stdout_bytes",
        "max_stderr_bytes",
        "max_stream_line_bytes",
        "max_concurrency",
    ),
)
def test_every_numeric_authority_rejects_floats(field: str) -> None:
    payload = _standard().to_dict()
    payload[field] = float(payload[field])
    with pytest.raises(ResourceGrantError, match="integer|float"):
        ResourceGrant.from_dict(payload)


@pytest.mark.parametrize(
    "mutation",
    (
        {"backend": "codex"},
        {"model": "gpt-5.6-sol"},
        {"retry_policy": {"fallback": True}},
        {"transport_timeout_multiplier": 3},
        {"path": "C:/workspace"},
        {"host": "builder-01"},
        {"timestamp": "2026-07-28T00:00:00Z"},
    ),
)
def test_semantic_grant_rejects_backend_model_retry_transport_path_host_time(
    mutation: dict[str, object],
) -> None:
    payload = _standard().to_dict()
    payload.update(mutation)
    with pytest.raises(ResourceGrantError, match="unexpected"):
        ResourceGrant.from_dict(payload)


def test_minimum_runnable_channel_and_au_maxima_fail_closed() -> None:
    with pytest.raises(ResourceGrantError, match="minimum runnable"):
        _standard(max_input_tokens=32_767)
    with pytest.raises(ResourceGrantError, match="minimum runnable"):
        _standard(max_output_tokens=2_047)
    with pytest.raises(ResourceGrantError, match="STANDARD_ANALYSIS"):
        _standard(max_input_tokens=65_537)
    with pytest.raises(ResourceGrantError, match="PROOF_CAPABLE"):
        _proof(max_output_tokens=12_289)
    with pytest.raises(ResourceGrantError, match="tool"):
        _standard(
            tool_call_limits=(
                ToolCallLimit("SOURCE_READ", 25),
            )
        )


def test_unknown_tool_cache_concurrency_and_workload_values_fail_closed() -> None:
    with pytest.raises(ResourceGrantError, match="tool_capability"):
        ToolCallLimit("Bash", 1)
    with pytest.raises(
        (ResourceGrantError, ResourcePolicyError), match="cache_policy"
    ):
        _standard(cache_policy="provider-default")
    with pytest.raises(
        (ResourceGrantError, ResourcePolicyError),
        match="scheduler|strict parity",
    ):
        _standard(scheduler_concurrency_class="backend-decides")
    with pytest.raises(
        (ResourceGrantError, ResourcePolicyError), match="workload_class"
    ):
        _standard(workload_class="UNBOUNDED")


def test_native_count_and_wall_time_denominators_cannot_diverge() -> None:
    with pytest.raises(
        (ResourceGrantError, ResourcePolicyError),
        match="both be zero|must agree",
    ):
        _standard(
            max_native_commands=1,
            max_native_wall_time_seconds=0,
        )
    with pytest.raises(
        (ResourceGrantError, ResourcePolicyError),
        match="both be zero|must agree",
    ):
        _standard(
            max_native_commands=0,
            max_native_wall_time_seconds=1,
        )


def test_strict_paired_comparator_accepts_only_exact_semantic_grant() -> None:
    left = _standard()
    matched = compare_paired_resource_grants(
        left,
        _standard(
            tool_call_limits=tuple(reversed(left.tool_call_limits))
        ),
    )
    assert isinstance(matched, PairedResourceComparison)
    assert matched.state == "MATCHED"
    assert matched.mismatch_fields == ()
    matched.require_equal()

    changed = compare_paired_resource_grants(
        left, replace(left, semantic_timeout_seconds=3_601)
    )
    assert changed.state == "UNMATCHED"
    assert changed.mismatch_fields == (
        "semantic_timeout_seconds",
        "worst_case_totals",
    )
    with pytest.raises(ResourceGrantError, match="semantic_timeout_seconds"):
        changed.require_equal()


def test_grant_digest_changes_for_each_separate_resource_axis() -> None:
    grant = _standard()
    variants = (
        replace(grant, max_input_tokens=65_535),
        replace(grant, max_output_tokens=8_191),
        replace(
            grant,
                tool_call_limits=(
                    ToolCallLimit("SOURCE_READ", 11),
                    ToolCallLimit("SOURCE_SEARCH", 8),
                    ToolCallLimit("METHODOLOGY_READ", 3),
                    ToolCallLimit("ASSIGNED_OUTPUT_WRITE", 1),
                    ToolCallLimit("NATIVE_TEST", 1),
                ),
            max_native_commands=1,
            max_native_wall_time_seconds=600,
        ),
        replace(grant, max_model_attempts=1),
        replace(grant, semantic_timeout_seconds=3_599),
        replace(grant, max_stdout_bytes=1_999_999),
        replace(grant, max_concurrency=1),
        replace(grant, cache_policy="CACHE_DISABLED"),
    )
    assert len({grant.resource_grant_digest, *(v.resource_grant_digest for v in variants)}) == (
        len(variants) + 1
    )


def test_transport_grace_is_separate_digest_bound_and_non_expanding() -> None:
    grant, _, _, parity = _bundle(
        parity_mode="NON_PAIRED_OPERATIONAL",
        scheduler_concurrency_class="BOUNDED_POOL",
    )
    grace = TransportGrace.create(
        grant=grant,
        parity_policy=parity,
        semantic_work_unit_id=grant.semantic_work_unit_id,
        attempt_number=1,
        use_id="grace-use-001",
        grace_seconds=30,
        reason_code="PROCESS_DRAIN_ONLY",
    )
    assert grace.validate_against(
        grant,
        parity_policy=parity,
    ) is None
    assert (
        TransportGrace.from_bytes(
            grace.to_bytes(),
            grant=grant,
            parity_policy=parity,
        )
        == grace
    )
    assert "semantic_timeout_seconds" not in grace.to_dict()
    assert "max_input_tokens" not in grace.to_dict()

    stale = replace(grace, resource_grant_digest="0" * 64)
    with pytest.raises(ResourceGrantError, match="resource_grant_digest"):
        stale.validate_against(
            grant,
            parity_policy=parity,
        )

    for forbidden in (
        "extra_input_tokens",
        "extra_output_tokens",
        "extra_tool_calls",
        "extra_native_commands",
        "extra_attempts",
        "semantic_timeout_multiplier",
        "backend",
        "path",
        "host",
        "timestamp",
    ):
        payload = grace.to_dict()
        payload[forbidden] = 1
        with pytest.raises(ResourceGrantError, match="unexpected"):
            TransportGrace.from_dict(payload)


def test_tool_limit_unknown_fields_and_tampered_grant_digest_fail_closed() -> None:
    payload = _standard().to_dict()
    payload["tool_call_limits"][0]["provider_tool"] = "Read"
    with pytest.raises(ResourceGrantError, match="unexpected"):
        ResourceGrant.from_dict(payload)

    payload = _standard().to_dict()
    payload["max_output_tokens"] -= 1
    with pytest.raises(
        ResourceGrantError,
        match="resource_grant_digest|worst_case_totals",
    ):
        ResourceGrant.from_dict(payload)


def test_duplicate_json_keys_and_cross_os_serialization_are_deterministic() -> None:
    grant = _standard()
    raw = grant.to_bytes()
    duplicate = raw[:-2] + b',"profile":"other"}\n'
    with pytest.raises(ResourceGrantError, match="duplicate"):
        ResourceGrant.from_bytes(duplicate)

    # No host/OS field exists, so the same semantic fixture serializes to the
    # same canonical bytes on every host.
    assert grant.to_bytes() == _standard().to_bytes()


def test_retry_reservation_is_full_au_per_attempt_and_attempts_are_bounded() -> None:
    grant = _standard()
    assert grant.max_reserved_analysis_units == (
        grant.analysis_units * grant.max_model_attempts
    )
    with pytest.raises(ResourceGrantError, match="attempt"):
        _standard(max_model_attempts=3)


def test_report_body_one_au_keeps_au_token_ceilings() -> None:
    kwargs = {
        key: value
        for key, value in _standard().to_dict().items()
        if key
        not in {
            "schema",
            "resource_grant_digest",
            "max_tool_calls",
                "max_reserved_analysis_units",
                "max_execution_attempts",
                "budget_scope",
                "worst_case_totals",
            "max_input_tokens",
            "max_output_tokens",
        }
    }
    kwargs.update(
        workload_class="REPORT_BODY",
        analysis_units=1,
        tool_call_limits=(),
        max_native_commands=0,
        max_native_wall_time_seconds=0,
    )
    with pytest.raises(ResourceGrantError, match="REPORT_BODY"):
        ResourceGrant.create(
            **kwargs,
            max_input_tokens=65_537,
            max_output_tokens=8_192,
        )
    with pytest.raises(ResourceGrantError, match="REPORT_BODY"):
        ResourceGrant.create(
            **kwargs,
            max_input_tokens=65_536,
            max_output_tokens=8_193,
        )


def test_scheduler_native_timeout_cache_and_stream_equations_fail_closed() -> None:
    with pytest.raises(
        (ResourceGrantError, ResourcePolicyError),
        match="SERIAL|strict parity",
    ):
        _standard(
            scheduler_concurrency_class="SERIAL",
            max_concurrency=2,
        )
    with pytest.raises(
        (ResourceGrantError, ResourcePolicyError), match="light|concurrency"
    ):
        _standard(audit_mode="light", max_concurrency=3)
    with pytest.raises(ResourceGrantError, match="native.*semantic"):
        _proof(
            max_native_wall_time_seconds=7_201,
            semantic_timeout_seconds=7_200,
        )
    with pytest.raises(ResourceGrantError, match="native.*tool"):
        _standard(
            max_native_commands=1,
            max_native_wall_time_seconds=60,
        )
    with pytest.raises(ResourceGrantError, match="native.*budget"):
        _standard(
            tool_call_limits=(ToolCallLimit("NATIVE_TEST", 1),),
            max_native_commands=0,
            max_native_wall_time_seconds=0,
        )
    with pytest.raises(
        (ResourceGrantError, ResourcePolicyError), match="cache"
    ):
        _standard(cache_policy="PROVIDER_DEFAULT_BOUND")
    with pytest.raises(
        (ResourceGrantError, ResourcePolicyError), match="stream"
    ):
        _standard(
            max_stdout_bytes=1,
            max_stderr_bytes=100,
            max_stream_line_bytes=100,
        )


def test_native_command_budget_covers_command_bearing_tool_requests() -> None:
    with pytest.raises(ResourceGrantError, match="native command"):
        _proof(max_native_commands=3)


def test_transport_grace_is_policy_bounded_and_strict_pair_cannot_expand() -> None:
    grant, _, _, operational = _bundle(
        parity_mode="NON_PAIRED_OPERATIONAL",
        scheduler_concurrency_class="BOUNDED_POOL",
    )
    with pytest.raises(ResourceGrantError, match="authorized"):
        TransportGrace.create(
            grant=grant,
            parity_policy=operational,
            semantic_work_unit_id=grant.semantic_work_unit_id,
            attempt_number=1,
            use_id="grace-use-over",
            grace_seconds=31,
            reason_code="PROCESS_DRAIN_ONLY",
        )
    strict_grant, _, _, strict = _bundle()
    with pytest.raises(ResourceGrantError, match="paired|authorized"):
        TransportGrace.create(
            grant=strict_grant,
            parity_policy=strict,
            semantic_work_unit_id=strict_grant.semantic_work_unit_id,
            attempt_number=1,
            use_id="grace-use-strict",
            grace_seconds=1,
            reason_code="PROCESS_DRAIN_ONLY",
        )


def test_paired_comparison_requires_replay_against_exact_parent_grants() -> None:
    with pytest.raises(ResourceGrantError, match="replay"):
        PairedResourceComparison(
            left_resource_grant_digest="a" * 64,
            right_resource_grant_digest="b" * 64,
            state="MATCHED",
            equal=True,
            strict_paired_eligible=False,
            eligibility_debts=("TRANSPORT_PLAN_MISSING",),
            left_transport_plan_digest=None,
            right_transport_plan_digest=None,
            mismatch_fields=(),
        )
    valid = compare_paired_resource_grants(_standard(), _standard())
    assert (
        PairedResourceComparison.from_structural_test_bytes(
            valid.to_bytes(),
            left=_standard(),
            right=_standard(),
        )
        == valid
    )


def test_preflight_request_is_compiled_from_exact_resource_grant() -> None:
    grant, policy, reservation, _ = _bundle()
    entry = ModelPolicyEntry(
        policy_id="codex-r3",
        backend="codex",
        semantic_model_capability_tier="R3_FRONTIER_REASONING",
        exact_model_id="gpt-5.6-sol",
        reasoning_mode="xhigh",
    )
    registry = ModelPolicyRegistry.create((entry,))
    intent = BackendLaunchIntent(
        backend="codex",
        adapter_id="codex-exec-v1",
        adapter_version="1.0.0",
        provider_cli_name="codex-cli",
        provider_cli_version="1.2.3",
        executable_sha256=_digest(1),
        executable_size_bytes=123,
        os_family="windows",
        account_mode="CHATGPT_ENTITLEMENT",
        transport_capability="HEADLESS_TRANSPORT",
    )
    request, authority = compile_preflight_request_from_resource_grant(
        grant=grant,
        registry=registry,
        policy_entry=entry,
        launch_intent=intent,
        expected_model_policy_registry_digest=registry.registry_digest,
        expected_policy_entry_digest=entry.policy_entry_digest,
        expected_launch_intent_digest=intent.launch_intent_digest,
        resource_policy_authority=policy,
        global_reservation=reservation,
        semantic_requirement_digest=_digest(2),
        tool_capability_manifest_digest=_digest(3),
        resume_requirement_authority=_resume_authority(grant, entry),
    )
    assert request.minimum_context_window_tokens == grant.max_input_tokens
    assert request.minimum_output_tokens == grant.max_output_tokens
    assert request.maximum_tool_calls_required == grant.max_tool_calls
    assert tuple(
        (row.tool_capability, row.required_calls)
        for row in request.required_tools
    ) == tuple(
        (row.tool_capability, row.max_calls)
        for row in grant.tool_call_limits
    )
    assert authority.resource_grant_digest == grant.resource_grant_digest
    assert (
        replay_preflight_request_authority_from_resource_grant(
            authority.to_bytes(),
            request=request,
            grant=grant,
            registry=registry,
            policy_entry=entry,
            launch_intent=intent,
            expected_model_policy_registry_digest=registry.registry_digest,
            expected_policy_entry_digest=entry.policy_entry_digest,
            expected_launch_intent_digest=intent.launch_intent_digest,
            resource_policy_authority=policy,
            global_reservation=reservation,
            semantic_requirement_digest=_digest(2),
            tool_capability_manifest_digest=_digest(3),
            resume_requirement_authority=_resume_authority(grant, entry),
        )
        == authority
    )
    other_grant, other_policy, other_reservation, _ = _bundle(
        semantic_work_unit_id="work-other-001"
    )
    with pytest.raises(ResourceGrantError, match="policy|reservation|replay"):
        compile_preflight_request_from_resource_grant(
            grant=grant,
            registry=registry,
            policy_entry=entry,
            launch_intent=intent,
            expected_model_policy_registry_digest=registry.registry_digest,
            expected_policy_entry_digest=entry.policy_entry_digest,
            expected_launch_intent_digest=intent.launch_intent_digest,
            resource_policy_authority=other_policy,
            global_reservation=other_reservation,
            semantic_requirement_digest=_digest(2),
            tool_capability_manifest_digest=_digest(3),
            resume_requirement_authority=_resume_authority(grant, entry),
        )


def test_native_resource_grant_compiles_honest_n0_request() -> None:
    grant, policy, reservation, _ = _bundle(
        workload_class="NATIVE_DETERMINISTIC",
        analysis_units=0,
        max_input_tokens=0,
        max_output_tokens=0,
        tool_call_limits=(),
        max_native_commands=1,
        max_native_wall_time_seconds=60,
        max_model_attempts=0,
        semantic_timeout_seconds=60,
        max_stdout_bytes=1_024,
        max_stderr_bytes=1_024,
        max_stream_line_bytes=1_024,
        scheduler_concurrency_class="SERIAL",
        max_concurrency=1,
        cache_policy="CACHE_DISABLED",
        parity_mode="NON_PAIRED_OPERATIONAL",
    )
    entry = ModelPolicyEntry(
        policy_id="native-n0",
        backend="native",
        semantic_model_capability_tier="N0_NATIVE_DETERMINISTIC",
        exact_model_id="native-toolchain:v1",
        reasoning_mode="not_applicable",
    )
    registry = ModelPolicyRegistry.create((entry,))
    intent = BackendLaunchIntent(
        backend="native",
        adapter_id="native-command-v1",
        adapter_version="1.0.0",
        provider_cli_name="native-runner",
        provider_cli_version="1.0.0",
        executable_sha256=_digest(4),
        executable_size_bytes=1_024,
        os_family="linux",
        account_mode="NATIVE",
        transport_capability="HEADLESS_TRANSPORT",
    )
    request, authority = compile_preflight_request_from_resource_grant(
        grant=grant,
        registry=registry,
        policy_entry=entry,
        launch_intent=intent,
        expected_model_policy_registry_digest=registry.registry_digest,
        expected_policy_entry_digest=entry.policy_entry_digest,
        expected_launch_intent_digest=intent.launch_intent_digest,
        resource_policy_authority=policy,
        global_reservation=reservation,
        semantic_requirement_digest=_digest(5),
        tool_capability_manifest_digest=_digest(6),
        resume_requirement_authority=_resume_authority(
            grant,
            entry,
            tool_capability_manifest_digest=_digest(6),
        ),
    )
    assert request.minimum_context_window_tokens == 0
    assert request.minimum_output_tokens == 0
    assert request.maximum_tool_calls_required == 0
    assert request.minimum_native_commands == 1
    assert authority.resource_grant_digest == grant.resource_grant_digest


def test_equal_grants_are_not_strict_paired_eligible_without_transport_plans() -> None:
    left = _standard()
    comparison = compare_paired_resource_grants(left, _standard())
    assert comparison.equal
    assert comparison.state == "MATCHED"
    assert not comparison.strict_paired_eligible
    assert comparison.eligibility_debts == (
        "CONCURRENCY_LEASE_AUTHORITY_MISSING",
        "TRANSPORT_PLAN_MISSING",
    )


def test_strict_paired_resources_still_require_concurrency_lease_authority() -> None:
    left, _, _, parity = _bundle()
    right = _standard()
    left_use = TransportGrace.create(
        grant=left,
        parity_policy=parity,
        semantic_work_unit_id=left.semantic_work_unit_id,
        attempt_number=1,
        use_id="left-use-001",
        grace_seconds=0,
        reason_code="PROCESS_STARTUP_ONLY",
    )
    right_use = TransportGrace.create(
        grant=right,
        parity_policy=parity,
        semantic_work_unit_id=right.semantic_work_unit_id,
        attempt_number=1,
        use_id="right-use-001",
        grace_seconds=0,
        reason_code="PROCESS_STARTUP_ONLY",
    )
    left_plan = compile_transport_plan(
        grant=left, parity_policy=parity, grace_uses=(left_use,)
    )
    right_plan = compile_transport_plan(
        grant=right, parity_policy=parity, grace_uses=(right_use,)
    )
    comparison = compare_paired_resource_grants(
        left,
        right,
        left_transport_plan=left_plan,
        right_transport_plan=right_plan,
    )
    assert comparison.equal
    assert not comparison.strict_paired_eligible
    assert comparison.eligibility_debts == (
        "CONCURRENCY_LEASE_AUTHORITY_MISSING",
    )
    with pytest.raises(ResourceGrantError, match="CONCURRENCY_LEASE"):
        comparison.require_strict_paired_eligible()


def test_strict_paired_eligibility_rejects_transport_plan_lookalikes() -> None:
    left, _, _, parity = _bundle()
    right = _standard()
    left_plan = compile_transport_plan(
        grant=left, parity_policy=parity, grace_uses=()
    )
    right_plan = compile_transport_plan(
        grant=right, parity_policy=parity, grace_uses=()
    )

    class PlanLookalike:
        def __init__(self, plan: TransportPlan) -> None:
            self.resource_grant_digest = plan.resource_grant_digest
            self.parity_policy_digest = plan.parity_policy_digest
            self.usage_signature = plan.usage_signature
            self.total_grace_seconds = plan.total_grace_seconds
            self.transport_plan_digest = plan.transport_plan_digest

    comparison = compare_paired_resource_grants(
        left,
        right,
        left_transport_plan=PlanLookalike(left_plan),
        right_transport_plan=PlanLookalike(right_plan),
    )
    assert comparison.equal
    assert not comparison.strict_paired_eligible
    assert comparison.eligibility_debts == (
        "CONCURRENCY_LEASE_AUTHORITY_MISSING",
        "TRANSPORT_PLAN_TYPE_REQUIRED",
    )
    assert comparison.left_transport_plan_digest is None
    assert comparison.right_transport_plan_digest is None


def test_strict_pair_requires_two_feasible_concurrent_slots() -> None:
    left, _, _, parity = _bundle(max_concurrency=1)
    right = _standard(max_concurrency=1)
    left_plan = compile_transport_plan(
        grant=left, parity_policy=parity, grace_uses=()
    )
    right_plan = compile_transport_plan(
        grant=right, parity_policy=parity, grace_uses=()
    )
    comparison = compare_paired_resource_grants(
        left,
        right,
        left_transport_plan=left_plan,
        right_transport_plan=right_plan,
    )
    assert not comparison.strict_paired_eligible
    assert "INSUFFICIENT_CONCURRENT_CAPACITY" in (
        comparison.eligibility_debts
    )


def test_strict_pair_cannot_claim_eligibility_without_concurrency_lease() -> None:
    left, _, _, parity = _bundle()
    right = _standard()
    left_plan = compile_transport_plan(
        grant=left, parity_policy=parity, grace_uses=()
    )
    right_plan = compile_transport_plan(
        grant=right, parity_policy=parity, grace_uses=()
    )
    comparison = compare_paired_resource_grants(
        left,
        right,
        left_transport_plan=left_plan,
        right_transport_plan=right_plan,
    )
    assert comparison.equal
    assert not comparison.strict_paired_eligible
    assert "CONCURRENCY_LEASE_AUTHORITY_MISSING" in (
        comparison.eligibility_debts
    )


def test_transport_plan_exact_type_replay_resists_class_spoof_and_mutation() -> None:
    left, _, _, parity = _bundle()
    right = _standard()
    left_plan = compile_transport_plan(
        grant=left, parity_policy=parity, grace_uses=()
    )
    right_plan = compile_transport_plan(
        grant=right, parity_policy=parity, grace_uses=()
    )

    class ClassSpoof:
        @property
        def __class__(self):  # type: ignore[no-untyped-def]
            return TransportPlan

        def __init__(self, plan: TransportPlan) -> None:
            self.resource_grant_digest = plan.resource_grant_digest
            self.parity_policy_digest = plan.parity_policy_digest
            self.usage_signature = plan.usage_signature
            self.total_grace_seconds = plan.total_grace_seconds
            self.transport_plan_digest = plan.transport_plan_digest

    spoofed = compare_paired_resource_grants(
        left,
        right,
        left_transport_plan=ClassSpoof(left_plan),
        right_transport_plan=ClassSpoof(right_plan),
    )
    assert not spoofed.strict_paired_eligible
    assert "TRANSPORT_PLAN_TYPE_REQUIRED" in spoofed.eligibility_debts

    object.__setattr__(
        left_plan,
        "max_execution_attempts",
        left.max_execution_attempts - 1,
    )
    mutated = compare_paired_resource_grants(
        left,
        right,
        left_transport_plan=left_plan,
        right_transport_plan=right_plan,
    )
    assert not mutated.strict_paired_eligible
    assert "TRANSPORT_PLAN_MISMATCH" in mutated.eligibility_debts


def test_transport_plan_binds_attempt_use_and_aggregate_one_use_accounting() -> None:
    grant, _, _, parity = _bundle(
        parity_mode="NON_PAIRED_OPERATIONAL",
        scheduler_concurrency_class="BOUNDED_POOL",
    )
    uses = tuple(
        TransportGrace.create(
            grant=grant,
            parity_policy=parity,
            semantic_work_unit_id=grant.semantic_work_unit_id,
            attempt_number=attempt,
            use_id=f"grace-use-{attempt:03d}",
            grace_seconds=30,
            reason_code="PROCESS_DRAIN_ONLY",
        )
        for attempt in (1, 2)
    )
    plan = compile_transport_plan(
        grant=grant, parity_policy=parity, grace_uses=uses
    )
    assert plan.total_grace_seconds == 60
    assert (
        TransportPlan.from_structural_test_bytes(
            plan.to_bytes(), grant=grant, parity_policy=parity
        )
        == plan
    )
    duplicate_attempt = replace(uses[1], attempt_number=1)
    with pytest.raises(ResourceGrantError, match="only once"):
        compile_transport_plan(
            grant=grant,
            parity_policy=parity,
            grace_uses=(uses[0], duplicate_attempt),
        )
    with pytest.raises(ResourceGrantError, match="attempt"):
        TransportGrace.create(
            grant=grant,
            parity_policy=parity,
            semantic_work_unit_id=grant.semantic_work_unit_id,
            attempt_number=3,
            use_id="grace-use-003",
            grace_seconds=0,
            reason_code="PROCESS_DRAIN_ONLY",
        )


def test_preflight_rejects_resource_grant_equality_spoof_and_mutation() -> None:
    grant, policy, reservation, _ = _bundle()

    class EqualitySpoofResourceGrant(ResourceGrant):
        def __eq__(self, other: object) -> bool:
            return True

    with pytest.raises(ResourceGrantError, match="exact|seal|replay"):
        EqualitySpoofResourceGrant.from_bytes(grant.to_bytes())


def test_resource_grant_rejects_object_mutation_even_if_instance_seal_rewritten() -> None:
    grant, _, _, _ = _bundle()
    object.__setattr__(
        grant,
        "max_input_tokens",
        grant.max_input_tokens // 2,
    )
    object.__setattr__(grant, "_seal", grant.resource_grant_digest)

    with pytest.raises(ResourceGrantError, match="seal|replay"):
        grant.require_exact_replay()


def test_preflight_replay_rejects_request_equality_spoof() -> None:
    grant, policy, reservation, _ = _bundle()
    entry = ModelPolicyEntry(
        policy_id="codex-r3",
        backend="codex",
        semantic_model_capability_tier="R3_FRONTIER_REASONING",
        exact_model_id="gpt-5.6-sol",
        reasoning_mode="xhigh",
    )
    registry = ModelPolicyRegistry.create((entry,))
    intent = BackendLaunchIntent(
        backend="codex",
        adapter_id="codex-exec-v1",
        adapter_version="1.0.0",
        provider_cli_name="codex-cli",
        provider_cli_version="1.2.3",
        executable_sha256=_digest(1),
        executable_size_bytes=123,
        os_family="windows",
        account_mode="CHATGPT_ENTITLEMENT",
        transport_capability="HEADLESS_TRANSPORT",
    )
    request, authority = compile_preflight_request_from_resource_grant(
        grant=grant,
        registry=registry,
        policy_entry=entry,
        launch_intent=intent,
        expected_model_policy_registry_digest=registry.registry_digest,
        expected_policy_entry_digest=entry.policy_entry_digest,
        expected_launch_intent_digest=intent.launch_intent_digest,
        resource_policy_authority=policy,
        global_reservation=reservation,
        semantic_requirement_digest=_digest(2),
        tool_capability_manifest_digest=_digest(3),
        resume_requirement_authority=_resume_authority(grant, entry),
    )

    class EqualitySpoofRequest(CapabilityPreflightRequest):
        def __eq__(self, other: object) -> bool:
            return True

    with pytest.raises(
        (ResourceGrantError, CapabilityRegistryError),
        match="exact|replay",
    ):
        EqualitySpoofRequest.from_bytes(request.to_bytes())


def test_tool_limit_context_spoof_cannot_narrow_preflight_projection() -> None:
    import inspect

    grant, policy, reservation, _ = _bundle()
    registry, entry, intent = _model_registry()
    resume_authority = _resume_authority(grant, entry)
    original = grant.to_bytes()

    class ContextCallsSpoof(ToolCallLimit):
        def __getattribute__(self, name: str):
            if name == "max_calls":
                frame = inspect.currentframe()
                caller = None if frame is None else frame.f_back
                if caller is not None and caller.f_code.co_name == "<genexpr>":
                    parent = caller.f_back
                    if (
                        parent is not None
                        and parent.f_code.co_name
                        == "compile_preflight_request_from_resource_grant"
                    ):
                        return 1
                return 12
            return super().__getattribute__(name)

        def to_dict(self) -> dict[str, object]:
            return {
                "tool_capability": "SOURCE_READ",
                "max_calls": 12,
            }

    object.__setattr__(
        grant,
        "tool_call_limits",
        tuple(
            ContextCallsSpoof("SOURCE_READ", 12)
            if row.tool_capability == "SOURCE_READ"
            else row
            for row in grant.tool_call_limits
        ),
    )
    assert grant.to_bytes() == original
    with pytest.raises(ResourceGrantError, match="exact|nested|seal|replay"):
        compile_preflight_request_from_resource_grant(
            grant=grant,
            registry=registry,
            policy_entry=entry,
            launch_intent=intent,
            expected_model_policy_registry_digest=(
                registry.registry_digest
            ),
            expected_policy_entry_digest=(
                entry.policy_entry_digest
            ),
            expected_launch_intent_digest=(
                intent.launch_intent_digest
            ),
            resource_policy_authority=policy,
            global_reservation=reservation,
            semantic_requirement_digest=_digest(2),
            tool_capability_manifest_digest=_digest(3),
            resume_requirement_authority=resume_authority,
        )


def test_resume_requirement_cannot_be_selected_by_free_boolean() -> None:
    grant, policy, reservation, _ = _bundle()
    registry, entry, intent = _model_registry()
    kwargs = {
        "grant": grant,
        "registry": registry,
        "policy_entry": entry,
        "launch_intent": intent,
        "expected_model_policy_registry_digest": registry.registry_digest,
        "expected_policy_entry_digest": entry.policy_entry_digest,
        "expected_launch_intent_digest": intent.launch_intent_digest,
        "resource_policy_authority": policy,
        "global_reservation": reservation,
        "semantic_requirement_digest": _digest(2),
        "tool_capability_manifest_digest": _digest(3),
    }
    for caller_choice in (False, True):
        with pytest.raises(
            ResourceGrantError, match="resume.*authority|authority.*resume"
        ):
            compile_preflight_request_from_resource_grant(
                **kwargs,
                requires_resume_session=caller_choice,
            )


def test_typed_attempt_authority_is_the_only_resume_selector() -> None:
    grant, policy, reservation, _ = _bundle()
    registry, entry, intent = _model_registry()
    common = {
        "grant": grant,
        "registry": registry,
        "policy_entry": entry,
        "launch_intent": intent,
        "expected_model_policy_registry_digest": registry.registry_digest,
        "expected_policy_entry_digest": entry.policy_entry_digest,
        "expected_launch_intent_digest": intent.launch_intent_digest,
        "resource_policy_authority": policy,
        "global_reservation": reservation,
        "semantic_requirement_digest": _digest(2),
        "tool_capability_manifest_digest": _digest(3),
    }
    first, _ = compile_preflight_request_from_resource_grant(
        **common,
        resume_requirement_authority=_resume_authority(
            grant, entry, attempt_number=1
        ),
    )
    resumed, _ = compile_preflight_request_from_resource_grant(
        **common,
        resume_requirement_authority=_resume_authority(
            grant, entry, attempt_number=2
        ),
    )
    assert "RESUME_SESSION" not in first.required_capabilities
    assert "RESUME_SESSION" in resumed.required_capabilities

    authority = _resume_authority(grant, entry, attempt_number=1)
    object.__setattr__(authority, "requires_resume_session", True)
    with pytest.raises(ResourceGrantError, match="seal|replay|resume"):
        compile_preflight_request_from_resource_grant(
            **common,
            resume_requirement_authority=authority,
        )


def test_structural_reservation_never_mints_production_grant() -> None:
    grant, policy, reservation, _ = _bundle()
    with pytest.raises(
        ResourceGrantError,
        match="reservation|production|structural|replay",
    ):
        compile_resource_grant_from_policy(
            policy_authority=policy,
            global_reservation=reservation,
            semantic_work_unit_id=grant.semantic_work_unit_id,
            audit_mode=grant.audit_mode,
            phase_semantic_id=grant.phase_semantic_id,
            workload_class=grant.workload_class,
        )
