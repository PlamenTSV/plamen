from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
import inspect
import json

import pytest

import backend_capability_registry as BCR
from backend_capability_registry import (
    BackendLaunchIntent,
    BackendCapabilityAuthority,
    BackendCapabilityReceipt,
    StructuralTestCapabilityArm,
    CapabilityObservation,
    CapabilityPreflightRequest,
    CapabilityRequestAuthority,
    CapabilityRegistryError,
    ModelPolicyEntry,
    ModelPolicyRegistry,
    ProviderObservationAuthority,
    ProviderObservationRecord,
    ToolCapabilityObservation,
    ToolCapabilityRequirement,
    compare_structural_test_paired_capability_arms,
    _compile_capability_preflight_request,
    evaluate_structural_test_capability_preflight,
    promote_structural_test_backend_capability_receipt,
    replay_provider_observation_authority,
)

CapabilityArm = StructuralTestCapabilityArm
compare_paired_capability_arms = (
    compare_structural_test_paired_capability_arms
)
evaluate_capability_preflight = (
    evaluate_structural_test_capability_preflight
)
promote_backend_capability_receipt = (
    promote_structural_test_backend_capability_receipt
)


def _digest(number: int) -> str:
    return format(number, "064x")


def _test_launch_context(
    intent: BackendLaunchIntent,
    *,
    resource_grant_digest: str = _digest(301),
    tool_capability_manifest_digest: str = _digest(302),
    model_capability_tier: str = "R3_FRONTIER_REASONING",
):
    from test_resource_grant import _bundle
    from test_resource_policy_authority import _plan
    from semantic_work_plan import derive_semantic_template_id

    grant, _, reservation, _ = _bundle()
    plan = replace(
        _plan(grant),
        resource_grant_digest=resource_grant_digest,
        tool_capability_manifest_digest=tool_capability_manifest_digest,
        model_capability_tier=model_capability_tier,
        semantic_template_id=derive_semantic_template_id(
            phase_semantic_id=grant.phase_semantic_id,
            model_capability_tier=model_capability_tier,
        ),
    )
    launch_generation = BCR.bind_structural_test_provider_launch_generation_authority(
        semantic_work_plan=plan,
        global_reservation=reservation,
        launch_intent=intent,
    )
    return plan, reservation, launch_generation


REQUIRED_CAPABILITIES = (
    "EXACT_MODEL_AVAILABILITY",
    "PROVIDER_PREPARATION_AUTHORITY",
    "CONTEXT_CEILING",
    "OUTPUT_CEILING",
    "REASONING_CONTROL",
    "TOOL_EVENT_OBSERVABILITY",
    "FILESYSTEM_ENFORCEMENT",
    "NETWORK_ENFORCEMENT",
    "MCP_PROVIDER_AVAILABILITY",
    "NATIVE_COMMAND_BROKER",
    "PTY_TRANSPORT",
    "HEADLESS_TRANSPORT",
    "STREAM_USAGE_TELEMETRY",
    "PROCESS_TREE_CONTAINMENT",
    "RESUME_SESSION",
)


def _capabilities(
    mutations: dict[str, tuple[str, str | None]] | None = None,
) -> tuple[CapabilityObservation, ...]:
    mutations = mutations or {}
    rows = []
    for index, name in enumerate(REQUIRED_CAPABILITIES, start=1):
        state, debt = mutations.get(
            name, ("SUPPORTED_AND_ENFORCED", None)
        )
        rows.append(
            CapabilityObservation(
                capability=name,
                state=state,
                evidence_digest=_digest(100 + index),
                debt_code=debt,
            )
        )
    return tuple(rows)


def _tools(
    mutations: dict[str, tuple[str, str | None]] | None = None,
) -> tuple[ToolCapabilityObservation, ...]:
    mutations = mutations or {}
    rows = []
    for index, (name, calls) in enumerate(
        (
            ("SOURCE_READ", 12),
            ("SOURCE_SEARCH", 8),
            ("METHODOLOGY_READ", 3),
            ("ASSIGNED_OUTPUT_WRITE", 1),
        ),
        start=1,
    ):
        state, debt = mutations.get(
            name, ("SUPPORTED_AND_ENFORCED", None)
        )
        if state not in {
            "SUPPORTED_AND_ENFORCED",
            "SUPPORTED_OBSERVED_ONLY",
        }:
            calls = 0
        rows.append(
            ToolCapabilityObservation(
                tool_capability=name,
                state=state,
                max_calls=calls,
                evidence_digest=_digest(200 + index),
                debt_code=debt,
            )
        )
    return tuple(rows)


def _receipt(
    *,
    backend: str = "codex",
    adapter_id: str | None = None,
    adapter_version: str = "1.0.0",
    provider_cli_name: str | None = None,
    model: str = "gpt-5.6-sol",
    tier: str = "R3_FRONTIER_REASONING",
    reasoning: str = "xhigh",
    os_family: str = "windows",
    context_window_tokens: int = 131_072,
    max_output_tokens: int = 12_288,
    capabilities: tuple[CapabilityObservation, ...] | None = None,
    tools: tuple[ToolCapabilityObservation, ...] | None = None,
) -> BackendCapabilityReceipt:
    resolved_adapter_id = adapter_id or f"{backend}-exec-v1"
    resolved_provider_cli_name = provider_cli_name or f"{backend}-cli"
    resolved_tools = _tools() if tools is None else tools
    resolved_capabilities = capabilities or _capabilities()
    intent = BackendLaunchIntent(
        backend=backend,
        adapter_id=resolved_adapter_id,
        adapter_version=adapter_version,
        provider_cli_name=resolved_provider_cli_name,
        provider_cli_version="1.2.3",
        executable_sha256=_digest(1),
        executable_size_bytes=123_456,
        os_family=os_family,
        account_mode=(
            "CHATGPT_ENTITLEMENT"
            if backend == "codex"
            else (
                "SUBSCRIPTION_OAUTH"
                if backend == "claude"
                else "NATIVE"
            )
        ),
        transport_capability="HEADLESS_TRANSPORT",
    )
    _, _, launch_generation = _test_launch_context(
        intent,
        model_capability_tier=tier,
    )
    observation_authority = _observation_authority_from_rows(
        intent=intent,
        prepared_exact_model_id=model,
        capabilities=resolved_capabilities,
        tools=resolved_tools,
        context_window_tokens=context_window_tokens,
        max_output_tokens=max_output_tokens,
        max_native_commands=0,
        max_native_wall_time_seconds=0,
        launch_generation_authority=launch_generation,
    )
    return BackendCapabilityReceipt.create(
        backend=backend,
        adapter_id=resolved_adapter_id,
        adapter_version=adapter_version,
        semantic_model_capability_tier=tier,
        exact_model_id=model,
        reasoning_mode=reasoning,
        provider_cli_name=resolved_provider_cli_name,
        provider_cli_version="1.2.3",
        executable_sha256=_digest(1),
        executable_size_bytes=123_456,
        observation_root_digest=(
            observation_authority.observation_root_digest
        ),
        os_family=os_family,
        account_mode=(
            "CHATGPT_ENTITLEMENT" if backend == "codex" else "SUBSCRIPTION_OAUTH"
        ),
        context_window_tokens=context_window_tokens,
        max_output_tokens=max_output_tokens,
        max_tool_calls_total=sum(row.max_calls for row in resolved_tools),
        max_native_commands=0,
        max_native_wall_time_seconds=0,
        capabilities=resolved_capabilities,
        tool_capabilities=resolved_tools,
    )


def _observation_authority_from_rows(
    *,
    intent: BackendLaunchIntent,
    prepared_exact_model_id: str | None,
    capabilities: tuple[CapabilityObservation, ...],
    tools: tuple[ToolCapabilityObservation, ...],
    context_window_tokens: int,
    max_output_tokens: int,
    max_native_commands: int,
    max_native_wall_time_seconds: int,
    launch_generation_authority: (
        BCR.ProviderLaunchGenerationAuthority | None
    ) = None,
    generation: int = 1,
    valid_through_generation: int = 3,
) -> ProviderObservationAuthority:
    preparation = next(
        row
        for row in capabilities
        if row.capability == "PROVIDER_PREPARATION_AUTHORITY"
    )
    if preparation.state == "SUPPORTED_AND_ENFORCED":
        preparation_state = "READY"
        source_contract = "PROVIDER_PREPARATION_PUBLIC_V1"
    elif intent.backend == "native":
        preparation_state = "NOT_APPLICABLE"
        source_contract = "GENERIC_OBSERVATION_AUTHORITY_V1"
    else:
        preparation_state = "UNKNOWN_BLOCKED"
        source_contract = "GENERIC_OBSERVATION_AUTHORITY_V1"
    # Policy-unit fixtures intentionally cross the module-private boundary so
    # they can exercise a positive discriminator path without pretending that
    # a real Codex/Claude provider preparation ran.
    preparation_authority = (
        BCR.ProviderPreparationAuthority(
            source_contract=source_contract,
            source_authority_digest=preparation.evidence_digest,
            launch_intent_digest=intent.launch_intent_digest,
            launch_generation_authority_digest=(
                launch_generation_authority
                .launch_generation_authority_digest
                if launch_generation_authority is not None
                else _digest(997)
            ),
            prepared_exact_model_id=prepared_exact_model_id,
            observation_generation=generation,
            valid_through_generation=valid_through_generation,
            preparation_state=preparation_state,
            _promotion_token=BCR._PROVIDER_PREPARATION_TOKEN,
        )
        if preparation_state == "READY"
        else None
    )
    observed_capabilities = tuple(
        row
        for row in capabilities
        if row.capability != "PROVIDER_PREPARATION_AUTHORITY"
    )
    observation_root_authority = None
    if preparation_authority is not None:
        payload_digest = BCR._provider_observation_payload_digest(
            source_contract=source_contract,
            source_authority_digest=preparation.evidence_digest,
            provider_preparation_authority_digest=(
                preparation_authority
                .provider_preparation_authority_digest
            ),
            launch_intent_digest=intent.launch_intent_digest,
            observation_generation=generation,
            valid_through_generation=valid_through_generation,
            preparation_state=preparation_state,
            context_window_tokens=context_window_tokens,
            max_output_tokens=max_output_tokens,
            max_tool_calls_total=sum(row.max_calls for row in tools),
            max_native_commands=max_native_commands,
            max_native_wall_time_seconds=max_native_wall_time_seconds,
            capabilities=observed_capabilities,
            tool_capabilities=tools,
        )
        observation_root_authority = BCR.ProviderObservationRootAuthority(
            provider_preparation_authority_digest=(
                preparation_authority
                .provider_preparation_authority_digest
            ),
            launch_generation_authority_digest=(
                preparation_authority
                .launch_generation_authority_digest
            ),
            prepared_exact_model_id=(
                preparation_authority.prepared_exact_model_id
            ),
            observation_generation=generation,
            observation_payload_digest=payload_digest,
            _promotion_token=BCR._PROVIDER_OBSERVATION_ROOT_TOKEN,
        )
    record = ProviderObservationRecord(
        source_contract=source_contract,
        source_authority_digest=preparation.evidence_digest,
        provider_preparation_authority_digest=(
            preparation_authority.provider_preparation_authority_digest
            if preparation_authority is not None
            else None
        ),
        provider_observation_root_authority_digest=(
            observation_root_authority
            .provider_observation_root_authority_digest
            if observation_root_authority is not None
            else None
        ),
        launch_intent_digest=intent.launch_intent_digest,
        observation_generation=generation,
        valid_through_generation=valid_through_generation,
        preparation_state=preparation_state,
        context_window_tokens=context_window_tokens,
        max_output_tokens=max_output_tokens,
        max_tool_calls_total=sum(row.max_calls for row in tools),
        max_native_commands=max_native_commands,
        max_native_wall_time_seconds=max_native_wall_time_seconds,
        capabilities=observed_capabilities,
        tool_capabilities=tools,
        preparation_authority=preparation_authority,
        observation_root_authority=observation_root_authority,
    )
    return replay_provider_observation_authority(
        record=record,
        preparation_authority=preparation_authority,
        observation_root_authority=observation_root_authority,
        launch_intent=intent,
        evaluation_generation=generation,
    )


def _observation_authority(
    receipt: BackendCapabilityReceipt,
    intent: BackendLaunchIntent,
) -> ProviderObservationAuthority:
    _, _, launch_generation = _test_launch_context(
        intent,
        model_capability_tier=receipt.semantic_model_capability_tier,
    )
    return _observation_authority_from_rows(
        intent=intent,
        prepared_exact_model_id=receipt.exact_model_id,
        capabilities=receipt.capabilities,
        tools=receipt.tool_capabilities,
        context_window_tokens=receipt.context_window_tokens,
        max_output_tokens=receipt.max_output_tokens,
        max_native_commands=receipt.max_native_commands,
        max_native_wall_time_seconds=(
            receipt.max_native_wall_time_seconds
        ),
        launch_generation_authority=launch_generation,
    )


def _request(
    *,
    model: str = "gpt-5.6-sol",
    reasoning: str = "xhigh",
) -> CapabilityPreflightRequest:
    return CapabilityPreflightRequest.create(
        semantic_model_capability_tier="R3_FRONTIER_REASONING",
        exact_model_id=model,
        reasoning_mode=reasoning,
        minimum_context_window_tokens=65_536,
        minimum_output_tokens=8_192,
        maximum_tool_calls_required=24,
        required_capabilities=(
            "EXACT_MODEL_AVAILABILITY",
            "PROVIDER_PREPARATION_AUTHORITY",
            "CONTEXT_CEILING",
            "OUTPUT_CEILING",
            "REASONING_CONTROL",
            "TOOL_EVENT_OBSERVABILITY",
            "FILESYSTEM_ENFORCEMENT",
            "NETWORK_ENFORCEMENT",
            "PROCESS_TREE_CONTAINMENT",
            "STREAM_USAGE_TELEMETRY",
            "HEADLESS_TRANSPORT",
        ),
        required_tools=(
            ToolCapabilityRequirement("SOURCE_READ", 12),
            ToolCapabilityRequirement("SOURCE_SEARCH", 8),
            ToolCapabilityRequirement("METHODOLOGY_READ", 3),
            ToolCapabilityRequirement("ASSIGNED_OUTPUT_WRITE", 1),
        ),
    )


def _authority(
    request: CapabilityPreflightRequest,
    receipt: BackendCapabilityReceipt,
):
    entry = ModelPolicyEntry(
        policy_id=f"{receipt.backend}-policy",
        backend=receipt.backend,
        semantic_model_capability_tier=(
            receipt.semantic_model_capability_tier
        ),
        exact_model_id=receipt.exact_model_id,
        reasoning_mode=receipt.reasoning_mode,
    )
    registry = ModelPolicyRegistry.create((entry,))
    intent = BackendLaunchIntent(
        backend=receipt.backend,
        adapter_id=receipt.adapter_id,
        adapter_version=receipt.adapter_version,
        provider_cli_name=receipt.provider_cli_name,
        provider_cli_version=receipt.provider_cli_version,
        executable_sha256=receipt.executable_sha256,
        executable_size_bytes=receipt.executable_size_bytes,
        os_family=receipt.os_family,
        account_mode=receipt.account_mode,
        transport_capability="HEADLESS_TRANSPORT",
    )
    compiled, request_authority = _compile_capability_preflight_request(
        registry=registry,
        policy_entry=entry,
        launch_intent=intent,
        expected_model_policy_registry_digest=registry.registry_digest,
        expected_policy_entry_digest=entry.policy_entry_digest,
        expected_launch_intent_digest=intent.launch_intent_digest,
        semantic_requirement_digest=_digest(300),
        resource_grant_digest=_digest(301),
        tool_capability_manifest_digest=_digest(302),
        minimum_context_window_tokens=(
            request.minimum_context_window_tokens
        ),
        minimum_output_tokens=request.minimum_output_tokens,
        required_tools=request.required_tools,
        minimum_native_commands=request.minimum_native_commands,
        minimum_native_wall_time_seconds=(
            request.minimum_native_wall_time_seconds
        ),
        requires_resume_session=(
            "RESUME_SESSION" in request.required_capabilities
        ),
    )
    if compiled != request:
        raise CapabilityRegistryError(
            "test request is not mechanically compiled"
        )
    plan, reservation, launch_generation = _test_launch_context(
        intent,
        resource_grant_digest=_digest(301),
        tool_capability_manifest_digest=_digest(302),
        model_capability_tier=receipt.semantic_model_capability_tier,
    )
    return promote_backend_capability_receipt(
        request=request,
        request_authority=request_authority,
        receipt=receipt,
        registry=registry,
        policy_entry=entry,
        launch_intent=intent,
        expected_model_policy_registry_digest=registry.registry_digest,
        expected_policy_entry_digest=entry.policy_entry_digest,
        expected_launch_intent_digest=intent.launch_intent_digest,
        expected_semantic_requirement_digest=_digest(300),
        expected_resource_grant_digest=_digest(301),
        expected_tool_capability_manifest_digest=_digest(302),
        observation_authority=_observation_authority(receipt, intent),
        semantic_work_plan=plan,
        global_reservation=reservation,
        launch_generation_authority=launch_generation,
    )


def _evaluate(
    request: CapabilityPreflightRequest,
    receipt: BackendCapabilityReceipt,
):
    return evaluate_capability_preflight(
        request,
        receipt,
        authority=_authority(request, receipt),
    )


def _compiled_bundle(
    receipt: BackendCapabilityReceipt,
    *,
    registry: ModelPolicyRegistry | None = None,
    semantic_requirement_digest: str | None = None,
    resource_grant_digest: str | None = None,
    tool_manifest_digest: str | None = None,
):
    entry = ModelPolicyEntry(
        policy_id=f"{receipt.backend}-policy",
        backend=receipt.backend,
        semantic_model_capability_tier=(
            receipt.semantic_model_capability_tier
        ),
        exact_model_id=receipt.exact_model_id,
        reasoning_mode=receipt.reasoning_mode,
    )
    registry = registry or ModelPolicyRegistry.create((entry,))
    entry = next(
        row
        for row in registry.entries
        if row.backend == receipt.backend
        and row.semantic_model_capability_tier
        == receipt.semantic_model_capability_tier
    )
    intent = BackendLaunchIntent(
        backend=receipt.backend,
        adapter_id=receipt.adapter_id,
        adapter_version=receipt.adapter_version,
        provider_cli_name=receipt.provider_cli_name,
        provider_cli_version=receipt.provider_cli_version,
        executable_sha256=receipt.executable_sha256,
        executable_size_bytes=receipt.executable_size_bytes,
        os_family=receipt.os_family,
        account_mode=receipt.account_mode,
        transport_capability="HEADLESS_TRANSPORT",
    )
    semantic_digest = semantic_requirement_digest or _digest(300)
    resource_digest = resource_grant_digest or _digest(301)
    tool_digest = tool_manifest_digest or _digest(302)
    request, request_authority = _compile_capability_preflight_request(
        registry=registry,
        policy_entry=entry,
        launch_intent=intent,
        expected_model_policy_registry_digest=registry.registry_digest,
        expected_policy_entry_digest=entry.policy_entry_digest,
        expected_launch_intent_digest=intent.launch_intent_digest,
        semantic_requirement_digest=semantic_digest,
        resource_grant_digest=resource_digest,
        tool_capability_manifest_digest=tool_digest,
        minimum_context_window_tokens=(
            0
            if receipt.semantic_model_capability_tier
            == "N0_NATIVE_DETERMINISTIC"
            else 65_536
        ),
        minimum_output_tokens=(
            0
            if receipt.semantic_model_capability_tier
            == "N0_NATIVE_DETERMINISTIC"
            else 8_192
        ),
        required_tools=(
            ()
            if receipt.semantic_model_capability_tier
            == "N0_NATIVE_DETERMINISTIC"
            else tuple(
                ToolCapabilityRequirement(
                    row.tool_capability, row.max_calls
                )
                for row in receipt.tool_capabilities
            )
        ),
        minimum_native_commands=receipt.max_native_commands,
        minimum_native_wall_time_seconds=(
            receipt.max_native_wall_time_seconds
        ),
    )
    plan, reservation, launch_generation = _test_launch_context(
        intent,
        resource_grant_digest=resource_digest,
        tool_capability_manifest_digest=tool_digest,
        model_capability_tier=receipt.semantic_model_capability_tier,
    )
    authority = promote_backend_capability_receipt(
        request=request,
        request_authority=request_authority,
        receipt=receipt,
        registry=registry,
        policy_entry=entry,
        launch_intent=intent,
        expected_model_policy_registry_digest=registry.registry_digest,
        expected_policy_entry_digest=entry.policy_entry_digest,
        expected_launch_intent_digest=intent.launch_intent_digest,
        expected_semantic_requirement_digest=semantic_digest,
        expected_resource_grant_digest=resource_digest,
        expected_tool_capability_manifest_digest=tool_digest,
        observation_authority=_observation_authority(receipt, intent),
        semantic_work_plan=plan,
        global_reservation=reservation,
        launch_generation_authority=launch_generation,
    )
    return (
        request,
        request_authority,
        authority,
        registry,
        entry,
        intent,
        semantic_digest,
        resource_digest,
        tool_digest,
    )


def _native_receipt() -> BackendCapabilityReceipt:
    capabilities = _capabilities(
        {
            "EXACT_MODEL_AVAILABILITY": (
                "UNSUPPORTED",
                "MODEL_EXACT_UNAVAILABLE",
            ),
            "PROVIDER_PREPARATION_AUTHORITY": (
                "UNSUPPORTED",
                "PROVIDER_PREPARATION_AUTHORITY_MISSING",
            ),
            "CONTEXT_CEILING": (
                "UNSUPPORTED",
                "CAPABILITY_UNSUPPORTED",
            ),
            "OUTPUT_CEILING": (
                "UNSUPPORTED",
                "CAPABILITY_UNSUPPORTED",
            ),
            "REASONING_CONTROL": (
                "UNSUPPORTED",
                "CX_REASONING_CONTROL_UNKNOWN",
            ),
            "PTY_TRANSPORT": (
                "UNSUPPORTED",
                "CAPABILITY_UNSUPPORTED",
            ),
        }
    )
    intent = BackendLaunchIntent(
        backend="native",
        adapter_id="native-command-v1",
        adapter_version="1.0.0",
        provider_cli_name="native-runner",
        provider_cli_version="1.0.0",
        executable_sha256=_digest(400),
        executable_size_bytes=1_024,
        os_family="windows",
        account_mode="NATIVE",
        transport_capability="HEADLESS_TRANSPORT",
    )
    _, _, launch_generation = _test_launch_context(
        intent,
        model_capability_tier="N0_NATIVE_DETERMINISTIC",
    )
    observation_authority = _observation_authority_from_rows(
        intent=intent,
        prepared_exact_model_id=None,
        capabilities=capabilities,
        tools=(),
        context_window_tokens=0,
        max_output_tokens=0,
        max_native_commands=2,
        max_native_wall_time_seconds=60,
        launch_generation_authority=launch_generation,
    )
    return BackendCapabilityReceipt.create(
        backend="native",
        adapter_id="native-command-v1",
        adapter_version="1.0.0",
        semantic_model_capability_tier="N0_NATIVE_DETERMINISTIC",
        exact_model_id="native-toolchain:v1",
        reasoning_mode="not_applicable",
        provider_cli_name="native-runner",
        provider_cli_version="1.0.0",
        executable_sha256=_digest(400),
        executable_size_bytes=1_024,
        observation_root_digest=(
            observation_authority.observation_root_digest
        ),
        os_family="windows",
        account_mode="NATIVE",
        context_window_tokens=0,
        max_output_tokens=0,
        max_tool_calls_total=0,
        max_native_commands=2,
        max_native_wall_time_seconds=60,
        capabilities=capabilities,
        tool_capabilities=(),
    )


def test_model_policy_examples_are_configuration_not_availability_claims() -> None:
    registry = ModelPolicyRegistry.create(
        (
            ModelPolicyEntry(
                policy_id="claude-opus-5-legacy",
                backend="claude",
                semantic_model_capability_tier="R3_FRONTIER_REASONING",
                exact_model_id="claude-opus-5",
                reasoning_mode="provider_default_bound",
            ),
            ModelPolicyEntry(
                policy_id="codex-gpt-5-6-sol",
                backend="codex",
                semantic_model_capability_tier="R3_FRONTIER_REASONING",
                exact_model_id="gpt-5.6-sol",
                reasoning_mode="xhigh",
            ),
        )
    )
    assert registry.resolve(
        semantic_model_capability_tier="R3_FRONTIER_REASONING",
        backend="claude",
    ).exact_model_id == "claude-opus-5"
    assert registry.resolve(
        semantic_model_capability_tier="R3_FRONTIER_REASONING",
        backend="codex",
    ).exact_model_id == "gpt-5.6-sol"
    assert "available" not in registry.to_dict()["entries"][0]


def test_backend_mapping_occurs_only_after_closed_semantic_tier_is_fixed() -> None:
    registry = ModelPolicyRegistry.create(
        (
            ModelPolicyEntry(
                policy_id="codex-r3",
                backend="codex",
                semantic_model_capability_tier="R3_FRONTIER_REASONING",
                exact_model_id="gpt-5.6-sol",
                reasoning_mode="xhigh",
            ),
        )
    )
    with pytest.raises(CapabilityRegistryError, match="semantic_model"):
        registry.resolve(
            semantic_model_capability_tier="opus",
            backend="codex",
        )
    with pytest.raises(CapabilityRegistryError, match="exact model"):
        registry.resolve(
            semantic_model_capability_tier="R3_FRONTIER_REASONING",
            backend="codex",
            required_exact_model_id="gpt-account-default",
        )


@pytest.mark.parametrize("reasoning", ("max", "ultra", "MAX"))
def test_reasoning_is_capped_at_xhigh_and_never_accepts_max(
    reasoning: str,
) -> None:
    with pytest.raises(CapabilityRegistryError, match="reasoning_mode"):
        ModelPolicyEntry(
            policy_id="bad-reasoning",
            backend="codex",
            semantic_model_capability_tier="R3_FRONTIER_REASONING",
            exact_model_id="gpt-5.6-sol",
            reasoning_mode=reasoning,
        )


def test_capability_receipt_is_canonical_digest_bound_and_immutable() -> None:
    receipt = _receipt()
    assert BackendCapabilityReceipt.from_bytes(receipt.to_bytes()) == receipt
    assert receipt.to_bytes().endswith(b"\n")
    assert json.loads(receipt.to_bytes())["receipt_digest"] == receipt.receipt_digest
    with pytest.raises(FrozenInstanceError):
        receipt.exact_model_id = "changed"  # type: ignore[misc]

    tampered = json.loads(receipt.to_bytes())
    tampered["max_output_tokens"] += 1
    with pytest.raises(CapabilityRegistryError, match="receipt_digest"):
        BackendCapabilityReceipt.from_dict(tampered)


def test_observation_and_tool_reordering_does_not_change_receipt() -> None:
    forward = _receipt()
    reverse = _receipt(
        capabilities=tuple(reversed(_capabilities())),
        tools=tuple(reversed(_tools())),
    )
    assert forward == reverse
    assert forward.to_bytes() == reverse.to_bytes()


@pytest.mark.parametrize(
    "mutation",
    (
        {"executable_path": "C:/bin/codex.exe"},
        {"cwd": "C:/workspace"},
        {"host": "builder-01"},
        {"timestamp": "2026-07-28T00:00:00Z"},
        {"api_key": "secret"},
        {"environment_values": {"TOKEN": "secret"}},
        {"model_alias": "frontier"},
        {"fallback_model": "default"},
    ),
)
def test_receipt_rejects_paths_hosts_timestamps_secrets_aliases_and_fallbacks(
    mutation: dict[str, object],
) -> None:
    payload = _receipt().to_dict()
    payload.update(mutation)
    with pytest.raises(CapabilityRegistryError, match="unexpected"):
        BackendCapabilityReceipt.from_dict(payload)


def test_supported_and_enforced_receipt_satisfies_strict_request() -> None:
    decision = _evaluate(_request(), _receipt())
    assert decision.eligible
    assert decision.debts == ()
    assert decision.request_digest
    assert decision.receipt_digest == _receipt().receipt_digest


def test_observed_only_capability_is_debt_not_strict_support() -> None:
    capabilities = _capabilities(
        {
            "NETWORK_ENFORCEMENT": (
                "SUPPORTED_OBSERVED_ONLY",
                "CAPABILITY_OBSERVED_ONLY",
            )
        }
    )
    decision = _evaluate(
        _request(), _receipt(capabilities=capabilities)
    )
    assert not decision.eligible
    assert tuple(debt.debt_code for debt in decision.debts) == (
        "CAPABILITY_OBSERVED_ONLY",
    )


def test_unsupported_os_tool_and_model_emit_typed_debt() -> None:
    capabilities = _capabilities(
        {
            "EXACT_MODEL_AVAILABILITY": (
                "UNAVAILABLE_AT_PREFLIGHT",
                "MODEL_EXACT_UNAVAILABLE",
            ),
            "PROCESS_TREE_CONTAINMENT": (
                "UNSUPPORTED",
                "PROCESS_CONTAINMENT_PLATFORM_DEBT",
            ),
        }
    )
    tools = _tools(
        {
            "SOURCE_READ": (
                "UNSUPPORTED",
                "CX_TOOL_POLICY_UNENFORCED",
            )
        }
    )
    decision = _evaluate(
        _request(),
        _receipt(
            os_family="unsupported",
            capabilities=capabilities,
            tools=tools,
        ),
    )
    assert not decision.eligible
    assert {debt.debt_code for debt in decision.debts} == {
        "MODEL_EXACT_UNAVAILABLE",
        "PROCESS_CONTAINMENT_PLATFORM_DEBT",
        "CX_TOOL_POLICY_UNENFORCED",
        "TOOL_LIMIT_INSUFFICIENT",
    }


def test_model_or_reasoning_mismatch_is_debt_and_never_fallback() -> None:
    with pytest.raises(
        (CapabilityRegistryError, AssertionError),
        match="policy|compiled",
    ):
        _evaluate(
            _request(model="gpt-5.6-sol"),
            _receipt(model="gpt-5.6-sol-other"),
        )

    with pytest.raises(
        (CapabilityRegistryError, AssertionError),
        match="policy|compiled",
    ):
        _evaluate(
            _request(reasoning="xhigh"),
            _receipt(reasoning="high"),
        )


def test_unknown_capability_tool_state_or_debt_fails_closed() -> None:
    with pytest.raises(CapabilityRegistryError, match="capability"):
        CapabilityObservation(
            capability="MAGIC_SHELL",
            state="SUPPORTED_AND_ENFORCED",
            evidence_digest=_digest(1),
            debt_code=None,
        )
    with pytest.raises(CapabilityRegistryError, match="state"):
        ToolCapabilityObservation(
            tool_capability="SOURCE_READ",
            state="MAYBE",
            max_calls=1,
            evidence_digest=_digest(1),
            debt_code=None,
        )
    with pytest.raises(CapabilityRegistryError, match="debt_code"):
        CapabilityObservation(
            capability="NETWORK_ENFORCEMENT",
            state="UNSUPPORTED",
            evidence_digest=_digest(1),
            debt_code="MAKE_IT_WORK",
        )


def test_unsupported_os_cannot_claim_enforced_process_containment() -> None:
    with pytest.raises(CapabilityRegistryError, match="unsupported os_family"):
        _receipt(os_family="unsupported")


def test_cli_version_cannot_smuggle_a_physical_path() -> None:
    with pytest.raises(
        CapabilityRegistryError, match="provider_cli_version|physical path"
    ):
        BackendCapabilityReceipt.create(
            **{
                key: value
                for key, value in _receipt().to_dict().items()
                if key
                not in {
                    "schema",
                    "receipt_digest",
                    "provider_cli_version",
                    "capabilities",
                    "tool_capabilities",
                }
            },
            provider_cli_version="C:/bin/codex.exe",
            capabilities=_capabilities(),
            tool_capabilities=_tools(),
        )


def test_exact_limits_are_checked_without_inventing_provider_capacity() -> None:
    limited_tools = list(_tools())
    limited_tools[0] = replace(limited_tools[0], max_calls=11)
    insufficient = _receipt(
        context_window_tokens=32_768,
        max_output_tokens=2_048,
        tools=tuple(limited_tools),
    )
    decision = _evaluate(_request(), insufficient)
    assert not decision.eligible
    assert {debt.debt_code for debt in decision.debts} == {
        "CONTEXT_LIMIT_INSUFFICIENT",
        "OUTPUT_LIMIT_INSUFFICIENT",
        "TOOL_LIMIT_INSUFFICIENT",
    }


def test_cross_os_serialization_is_deterministic_and_os_truth_is_bound() -> None:
    windows_a = _receipt(os_family="windows")
    windows_b = _receipt(
        os_family="windows",
        capabilities=tuple(reversed(_capabilities())),
        tools=tuple(reversed(_tools())),
    )
    linux = _receipt(os_family="linux")
    assert windows_a.to_bytes() == windows_b.to_bytes()
    assert windows_a.receipt_digest != linux.receipt_digest


def test_duplicate_json_keys_and_float_limits_fail_closed() -> None:
    raw = _receipt().to_bytes()
    duplicate = raw[:-2] + b',"backend":"claude"}\n'
    with pytest.raises(CapabilityRegistryError, match="duplicate"):
        BackendCapabilityReceipt.from_bytes(duplicate)

    payload = _receipt().to_dict()
    payload["context_window_tokens"] = 131_072.0
    with pytest.raises(CapabilityRegistryError, match="integer|float"):
        BackendCapabilityReceipt.from_dict(payload)


def test_raw_self_authored_receipt_cannot_be_evaluated_as_authority() -> None:
    """A content hash is integrity, not trusted preflight provenance."""

    with pytest.raises(CapabilityRegistryError, match="authority"):
        evaluate_capability_preflight(_request(), _receipt())


def test_request_cannot_omit_mandatory_model_and_containment_denominator() -> None:
    weak_request = CapabilityPreflightRequest.create(
        semantic_model_capability_tier="R3_FRONTIER_REASONING",
        exact_model_id="gpt-5.6-sol",
        reasoning_mode="xhigh",
        minimum_context_window_tokens=1,
        minimum_output_tokens=1,
        maximum_tool_calls_required=0,
        required_capabilities=("EXACT_MODEL_AVAILABILITY",),
        required_tools=(),
    )
    with pytest.raises(CapabilityRegistryError, match="denominator|compiled"):
        _authority(weak_request, _receipt())


def test_model_tiers_reject_not_applicable_reasoning_and_empty_accounts() -> None:
    with pytest.raises(CapabilityRegistryError, match="not_applicable"):
        ModelPolicyEntry(
            policy_id="codex-r3-na",
            backend="codex",
            semantic_model_capability_tier="R3_FRONTIER_REASONING",
            exact_model_id="gpt-5.6-sol",
            reasoning_mode="not_applicable",
        )
    with pytest.raises(CapabilityRegistryError, match="account"):
        replace(_receipt(), account_mode="NONE")


def test_native_request_is_zero_model_budget_and_model_caps_are_not_claimed() -> None:
    request = CapabilityPreflightRequest.create(
        semantic_model_capability_tier="N0_NATIVE_DETERMINISTIC",
        exact_model_id="native-tool",
        reasoning_mode="not_applicable",
        minimum_context_window_tokens=0,
        minimum_output_tokens=0,
        maximum_tool_calls_required=0,
        minimum_native_commands=1,
        minimum_native_wall_time_seconds=1,
        required_capabilities=(
            "FILESYSTEM_ENFORCEMENT",
            "NETWORK_ENFORCEMENT",
            "NATIVE_COMMAND_BROKER",
            "PROCESS_TREE_CONTAINMENT",
            "STREAM_USAGE_TELEMETRY",
        ),
        required_tools=(),
    )
    assert request.minimum_context_window_tokens == 0
    assert request.minimum_output_tokens == 0
    with pytest.raises(CapabilityRegistryError, match="native.*zero"):
        replace(
            _receipt(),
            backend="native",
            adapter_id="native-v1",
            semantic_model_capability_tier="N0_NATIVE_DETERMINISTIC",
            exact_model_id="native-tool",
            reasoning_mode="not_applicable",
            provider_cli_name="native-runner",
            account_mode="NATIVE",
        )


def test_tool_total_requires_exact_per_capability_conservation() -> None:
    with pytest.raises(CapabilityRegistryError, match="exact|total"):
        CapabilityPreflightRequest.create(
            semantic_model_capability_tier="R3_FRONTIER_REASONING",
            exact_model_id="gpt-5.6-sol",
            reasoning_mode="xhigh",
            minimum_context_window_tokens=65_536,
            minimum_output_tokens=8_192,
            maximum_tool_calls_required=24,
            required_capabilities=(
                "EXACT_MODEL_AVAILABILITY",
                "PROVIDER_PREPARATION_AUTHORITY",
                "CONTEXT_CEILING",
                "OUTPUT_CEILING",
                "REASONING_CONTROL",
                "TOOL_EVENT_OBSERVABILITY",
                "FILESYSTEM_ENFORCEMENT",
                "NETWORK_ENFORCEMENT",
                "PROCESS_TREE_CONTAINMENT",
                "STREAM_USAGE_TELEMETRY",
            ),
            required_tools=(
                ToolCapabilityRequirement("SOURCE_READ", 12),
            ),
        )


def test_capability_debt_code_must_match_subject_and_state() -> None:
    with pytest.raises(CapabilityRegistryError, match="debt_code"):
        CapabilityObservation(
            capability="NETWORK_ENFORCEMENT",
            state="UNSUPPORTED",
            evidence_digest=_digest(1),
            debt_code="MODEL_UNAVAILABLE",
        )


def test_exact_model_identity_supports_namespace_but_rejects_aliases() -> None:
    namespaced = ModelPolicyEntry(
        policy_id="cloud-r3",
        backend="codex",
        semantic_model_capability_tier="R3_FRONTIER_REASONING",
        exact_model_id="provider/model:v1",
        reasoning_mode="xhigh",
    )
    assert namespaced.exact_model_id == "provider/model:v1"
    for alias in ("default", "auto", "latest", "account-default"):
        with pytest.raises(CapabilityRegistryError, match="exact_model_id"):
            replace(namespaced, exact_model_id=alias)


def test_cli_version_rejects_relative_paths_and_display_controls() -> None:
    for value in ("../../private/token.txt", "1.2.3\tsecret", "1.2.3\u202e"):
        with pytest.raises(CapabilityRegistryError, match="provider_cli_version"):
            replace(_receipt(), provider_cli_version=value)


def test_request_and_receipt_authorities_replay_exact_trusted_parents() -> None:
    receipt = _receipt()
    (
        request,
        request_authority,
        authority,
        registry,
        entry,
        intent,
        semantic_digest,
        resource_digest,
        tool_digest,
    ) = _compiled_bundle(receipt)
    replayed_request_authority = CapabilityRequestAuthority.from_bytes(
        request_authority.to_bytes(),
        request=request,
        registry=registry,
        policy_entry=entry,
        launch_intent=intent,
        expected_model_policy_registry_digest=registry.registry_digest,
        expected_policy_entry_digest=entry.policy_entry_digest,
        expected_launch_intent_digest=intent.launch_intent_digest,
        expected_semantic_requirement_digest=semantic_digest,
        expected_resource_grant_digest=resource_digest,
        expected_tool_capability_manifest_digest=tool_digest,
    )
    assert replayed_request_authority == request_authority
    plan, reservation, launch_generation = _test_launch_context(
        intent,
        resource_grant_digest=resource_digest,
        tool_capability_manifest_digest=tool_digest,
        model_capability_tier=receipt.semantic_model_capability_tier,
    )
    replayed_authority = (
        BackendCapabilityAuthority.from_structural_test_bytes(
        authority.to_bytes(),
        request=request,
        request_authority=request_authority,
        receipt=receipt,
        registry=registry,
        policy_entry=entry,
        launch_intent=intent,
        expected_model_policy_registry_digest=registry.registry_digest,
        expected_policy_entry_digest=entry.policy_entry_digest,
        expected_launch_intent_digest=intent.launch_intent_digest,
        expected_semantic_requirement_digest=semantic_digest,
        expected_resource_grant_digest=resource_digest,
        expected_tool_capability_manifest_digest=tool_digest,
        observation_authority=_observation_authority(receipt, intent),
        semantic_work_plan=plan,
        global_reservation=reservation,
        launch_generation_authority=launch_generation,
        )
    )
    assert replayed_authority == authority

    swapped = replace(
        receipt,
        executable_sha256=_digest(999),
        observation_root_digest=_digest(998),
    )
    with pytest.raises(CapabilityRegistryError, match="bind|authority"):
        evaluate_capability_preflight(
            request, swapped, authority=authority
        )


def test_authority_and_decision_objects_cannot_be_self_certified() -> None:
    with pytest.raises(CapabilityRegistryError, match="promotion"):
        CapabilityRequestAuthority(
            request_digest=_digest(1),
            model_policy_registry_digest=_digest(2),
            policy_entry_digest=_digest(3),
            launch_intent_digest=_digest(4),
            semantic_requirement_digest=_digest(5),
            resource_grant_digest=_digest(6),
            tool_capability_manifest_digest=_digest(7),
        )
    with pytest.raises(CapabilityRegistryError, match="promotion"):
        BackendCapabilityAuthority(
            request_digest=_digest(1),
            request_authority_digest=_digest(2),
            receipt_digest=_digest(3),
            launch_intent_digest=_digest(4),
            model_policy_registry_digest=_digest(5),
            policy_entry_digest=_digest(6),
            trusted_observation_root_digest=_digest(7),
            provider_observation_authority_digest=_digest(8),
            launch_generation_authority_digest=_digest(9),
            observation_generation=1,
        )

    receipt = _receipt()
    request, _, authority, *_ = _compiled_bundle(receipt)
    decision = evaluate_capability_preflight(
        request, receipt, authority=authority
    )
    assert (
        type(decision).from_structural_test_bytes(
            decision.to_bytes(),
            request=request,
            receipt=receipt,
            authority=authority,
        )
        == decision
    )


def test_compiler_derives_exact_platform_and_tool_denominators() -> None:
    receipt = _receipt()
    request, request_authority, *_ = _compiled_bundle(receipt)
    assert request.maximum_tool_calls_required == sum(
        row.required_calls for row in request.required_tools
    )
    assert request.required_capabilities == tuple(
        sorted(
            {
                "EXACT_MODEL_AVAILABILITY",
                "PROVIDER_PREPARATION_AUTHORITY",
                "CONTEXT_CEILING",
                "OUTPUT_CEILING",
                "REASONING_CONTROL",
                "TOOL_EVENT_OBSERVABILITY",
                "FILESYSTEM_ENFORCEMENT",
                "NETWORK_ENFORCEMENT",
                "PROCESS_TREE_CONTAINMENT",
                "STREAM_USAGE_TELEMETRY",
                "HEADLESS_TRANSPORT",
            }
        )
    )
    assert request_authority.request_digest == request.request_digest


def test_model_preflight_fails_closed_without_provider_preparation_authority() -> None:
    """A WER caller may not synthesize split provider launch authorities."""

    capabilities = _capabilities(
        {
            "PROVIDER_PREPARATION_AUTHORITY": (
                "UNKNOWN_BLOCKED",
                "PROVIDER_PREPARATION_AUTHORITY_MISSING",
            )
        }
    )
    receipt = _receipt(capabilities=capabilities)
    request, _, authority, *_ = _compiled_bundle(receipt)

    assert "PROVIDER_PREPARATION_AUTHORITY" in (
        request.required_capabilities
    )
    decision = evaluate_capability_preflight(
        request,
        receipt,
        authority=authority,
    )
    assert not decision.eligible
    assert tuple(
        (debt.debt_code, debt.subject) for debt in decision.debts
    ) == (
        (
            "PROVIDER_PREPARATION_AUTHORITY_MISSING",
            "PROVIDER_PREPARATION_AUTHORITY",
        ),
    )


def test_honest_native_n0_bundle_has_zero_model_budget_and_is_eligible() -> None:
    receipt = _native_receipt()
    request, _, authority, *_ = _compiled_bundle(receipt)
    assert request.minimum_context_window_tokens == 0
    assert request.minimum_output_tokens == 0
    assert request.maximum_tool_calls_required == 0
    assert request.minimum_native_commands == 2
    decision = evaluate_capability_preflight(
        request, receipt, authority=authority
    )
    assert decision.eligible
    assert decision.debts == ()


def test_paired_capability_intersection_is_replay_derived_and_parent_bound() -> None:
    codex_receipt = _receipt(reasoning="high")
    claude_receipt = _receipt(
        backend="claude",
        model="claude-opus-5",
        reasoning="high",
    )
    registry = ModelPolicyRegistry.create(
        (
            ModelPolicyEntry(
                policy_id="codex-policy",
                backend="codex",
                semantic_model_capability_tier="R3_FRONTIER_REASONING",
                exact_model_id="gpt-5.6-sol",
                reasoning_mode="high",
            ),
            ModelPolicyEntry(
                policy_id="claude-policy",
                backend="claude",
                semantic_model_capability_tier="R3_FRONTIER_REASONING",
                exact_model_id="claude-opus-5",
                reasoning_mode="high",
            ),
        )
    )
    left_bundle = _compiled_bundle(codex_receipt, registry=registry)
    right_bundle = _compiled_bundle(claude_receipt, registry=registry)
    left = CapabilityArm(
        request=left_bundle[0],
        request_authority=left_bundle[1],
        receipt=codex_receipt,
        capability_authority=left_bundle[2],
    )
    right = CapabilityArm(
        request=right_bundle[0],
        request_authority=right_bundle[1],
        receipt=claude_receipt,
        capability_authority=right_bundle[2],
    )
    comparison = compare_paired_capability_arms(left, right)
    assert comparison.state == "MATCHED"
    assert type(comparison).from_structural_test_bytes(
        comparison.to_bytes(), left=left, right=right
    ) == comparison

    drifted_bundle = _compiled_bundle(
        claude_receipt,
        registry=registry,
        semantic_requirement_digest=_digest(777),
    )
    drifted = CapabilityArm(
        request=drifted_bundle[0],
        request_authority=drifted_bundle[1],
        receipt=claude_receipt,
        capability_authority=drifted_bundle[2],
    )
    unmatched = compare_paired_capability_arms(left, drifted)
    assert unmatched.state == "UNMATCHED"
    assert "semantic_requirement_digest" in unmatched.mismatch_fields


def test_capability_promotion_requires_independent_typed_observation_authority() -> None:
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
    with pytest.raises(
        CapabilityRegistryError,
        match="independent provider observation authority|self-assert",
    ):
        promote_backend_capability_receipt(
            request=request,
            request_authority=request_authority,
            receipt=receipt,
            registry=registry,
            policy_entry=entry,
            launch_intent=intent,
            expected_model_policy_registry_digest=registry.registry_digest,
            expected_policy_entry_digest=entry.policy_entry_digest,
            expected_launch_intent_digest=intent.launch_intent_digest,
            expected_semantic_requirement_digest=semantic_digest,
            expected_resource_grant_digest=resource_digest,
            expected_tool_capability_manifest_digest=tool_digest,
            observation_authority=None,  # type: ignore[arg-type]
            semantic_work_plan=plan,
            global_reservation=reservation,
            launch_generation_authority=launch_generation,
        )


def test_provider_observation_replay_binds_denominator_evidence_and_freshness() -> None:
    receipt = _receipt()
    *_, intent, _, _, _ = _compiled_bundle(receipt)
    authority = _observation_authority(receipt, intent)
    assert (
        ProviderObservationAuthority.from_bytes(
            authority.to_bytes(),
            record=authority.record,
            preparation_authority=authority.preparation_authority,
            observation_root_authority=(
                authority.observation_root_authority
            ),
            launch_intent=intent,
            evaluation_generation=authority.evaluation_generation,
        )
        == authority
    )
    with pytest.raises(CapabilityRegistryError, match="stale"):
        replay_provider_observation_authority(
            record=authority.record,
            preparation_authority=authority.preparation_authority,
            observation_root_authority=(
                authority.observation_root_authority
            ),
            launch_intent=intent,
            evaluation_generation=(
                authority.record.valid_through_generation + 1
            ),
        )
    with pytest.raises(CapabilityRegistryError, match="denominator"):
            replace(
                authority.record,
                capabilities=authority.record.capabilities[:-1],
                preparation_authority=authority.preparation_authority,
                observation_root_authority=(
                    authority.observation_root_authority
                ),
            )


def test_provider_preparation_support_is_derived_not_receipt_asserted() -> None:
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
    prepared = _observation_authority(receipt, intent)
    generic_record = replace(
        prepared.record,
        source_contract="GENERIC_OBSERVATION_AUTHORITY_V1",
        preparation_state="UNKNOWN_BLOCKED",
        provider_preparation_authority_digest=None,
        provider_observation_root_authority_digest=None,
    )
    generic = replay_provider_observation_authority(
        record=generic_record,
        preparation_authority=None,
        observation_root_authority=None,
        launch_intent=intent,
        evaluation_generation=generic_record.observation_generation,
    )
    plan, reservation, launch_generation = _test_launch_context(
        intent,
        resource_grant_digest=resource_digest,
        tool_capability_manifest_digest=tool_digest,
        model_capability_tier=receipt.semantic_model_capability_tier,
    )
    self_asserted = replace(
        receipt, observation_root_digest=generic.observation_root_digest
    )
    with pytest.raises(CapabilityRegistryError, match="states/evidence"):
        promote_backend_capability_receipt(
            request=request,
            request_authority=request_authority,
            receipt=self_asserted,
            registry=registry,
            policy_entry=entry,
            launch_intent=intent,
            expected_model_policy_registry_digest=registry.registry_digest,
            expected_policy_entry_digest=entry.policy_entry_digest,
            expected_launch_intent_digest=intent.launch_intent_digest,
            expected_semantic_requirement_digest=semantic_digest,
            expected_resource_grant_digest=resource_digest,
            expected_tool_capability_manifest_digest=tool_digest,
            observation_authority=generic,
            semantic_work_plan=plan,
            global_reservation=reservation,
            launch_generation_authority=launch_generation,
        )


def test_ready_provider_observation_cannot_be_minted_from_caller_digests() -> None:
    """A caller-controlled record plus a repeated digest is not readiness."""

    intent = BackendLaunchIntent(
        backend="claude",
        adapter_id="claude-exec-v1",
        adapter_version="1.0.0",
        provider_cli_name="claude-cli",
        provider_cli_version="1.2.3",
        executable_sha256=_digest(1),
        executable_size_bytes=123_456,
        os_family="windows",
        account_mode="SUBSCRIPTION_OAUTH",
        transport_capability="HEADLESS_TRANSPORT",
    )
    rows = _capabilities()
    preparation = next(
        row
        for row in rows
        if row.capability == "PROVIDER_PREPARATION_AUTHORITY"
    )
    with pytest.raises(
        CapabilityRegistryError,
        match="opaque|preparation authority|caller",
    ):
        ProviderObservationRecord(
            source_contract="PROVIDER_PREPARATION_PUBLIC_V1",
            source_authority_digest=preparation.evidence_digest,
            provider_preparation_authority_digest=None,
            provider_observation_root_authority_digest=None,
            launch_intent_digest=intent.launch_intent_digest,
            observation_generation=7,
            valid_through_generation=7,
            preparation_state="READY",
            context_window_tokens=131_072,
            max_output_tokens=12_288,
            max_tool_calls_total=sum(row.max_calls for row in _tools()),
            max_native_commands=0,
            max_native_wall_time_seconds=0,
            capabilities=tuple(
                row
                for row in rows
                if row.capability != "PROVIDER_PREPARATION_AUTHORITY"
            ),
            tool_capabilities=_tools(),
        )
    preparation_authority = BCR.ProviderPreparationAuthority(
        source_contract="PROVIDER_PREPARATION_PUBLIC_V1",
        source_authority_digest=preparation.evidence_digest,
        launch_intent_digest=intent.launch_intent_digest,
        launch_generation_authority_digest=_digest(997),
        prepared_exact_model_id="claude-opus-5",
        observation_generation=7,
        valid_through_generation=7,
        preparation_state="READY",
        _promotion_token=BCR._PROVIDER_PREPARATION_TOKEN,
    )
    with pytest.raises(
        CapabilityRegistryError,
        match="observation root",
    ):
        ProviderObservationRecord(
            source_contract="PROVIDER_PREPARATION_PUBLIC_V1",
            source_authority_digest=preparation.evidence_digest,
            provider_preparation_authority_digest=(
                preparation_authority
                .provider_preparation_authority_digest
            ),
            provider_observation_root_authority_digest=None,
            launch_intent_digest=intent.launch_intent_digest,
            observation_generation=7,
            valid_through_generation=7,
            preparation_state="READY",
            context_window_tokens=131_072,
            max_output_tokens=12_288,
            max_tool_calls_total=sum(row.max_calls for row in _tools()),
            max_native_commands=0,
            max_native_wall_time_seconds=0,
            capabilities=tuple(
                row
                for row in rows
                if row.capability != "PROVIDER_PREPARATION_AUTHORITY"
            ),
            tool_capabilities=_tools(),
            preparation_authority=preparation_authority,
            observation_root_authority=None,
        )


def test_provider_launch_generation_and_unavailable_adapter_are_typed() -> None:
    from types import SimpleNamespace

    from test_resource_grant import _bundle
    from test_resource_policy_authority import _plan

    grant, _, reservation, _ = _bundle()
    plan = _plan(grant)
    intent = BackendLaunchIntent(
        backend="codex",
        adapter_id="codex-exec-v1",
        adapter_version="1.0.0",
        provider_cli_name="codex-cli",
        provider_cli_version="1.2.3",
        executable_sha256=_digest(1),
        executable_size_bytes=123_456,
        os_family="windows",
        account_mode="CHATGPT_ENTITLEMENT",
        transport_capability="HEADLESS_TRANSPORT",
    )
    launch_generation = BCR.bind_structural_test_provider_launch_generation_authority(
        semantic_work_plan=plan,
        global_reservation=reservation,
        launch_intent=intent,
    )
    assert launch_generation.semantic_generation == reservation.generation
    assert launch_generation.run_id == reservation.run_id

    blocked = BCR.bind_unavailable_provider_preparation_authority(
        launch_generation_authority=launch_generation,
        launch_intent=intent,
        preparation_state="UNKNOWN_BLOCKED",
    )
    assert blocked.preparation_state == "UNKNOWN_BLOCKED"
    assert blocked.observation_generation == reservation.generation

    with pytest.raises(CapabilityRegistryError, match="exact typed"):
        BCR.bind_structural_test_provider_launch_generation_authority(
            semantic_work_plan=SimpleNamespace(**plan.to_dict()),
            global_reservation=reservation,
            launch_intent=intent,
        )
    with pytest.raises(CapabilityRegistryError, match="opaque"):
        BCR.ProviderPreparationAuthority(
            source_contract="PROVIDER_PREPARATION_PUBLIC_V1",
            source_authority_digest=_digest(1),
            launch_intent_digest=intent.launch_intent_digest,
            launch_generation_authority_digest=_digest(2),
            prepared_exact_model_id="gpt-5.6-sol",
            observation_generation=1,
            valid_through_generation=1,
            preparation_state="READY",
        )


def test_provider_observation_rejects_cross_generation_root_splice() -> None:
    receipt = _receipt()
    *_, intent, _, _, _ = _compiled_bundle(receipt)
    authority = _observation_authority(receipt, intent)
    original = authority.preparation_authority
    assert type(original) is BCR.ProviderPreparationAuthority
    spliced = BCR.ProviderPreparationAuthority(
        source_contract=original.source_contract,
        source_authority_digest=original.source_authority_digest,
        launch_intent_digest=original.launch_intent_digest,
        launch_generation_authority_digest=_digest(998),
        prepared_exact_model_id=original.prepared_exact_model_id,
        observation_generation=original.observation_generation,
        valid_through_generation=original.valid_through_generation,
        preparation_state=original.preparation_state,
        _promotion_token=BCR._PROVIDER_PREPARATION_TOKEN,
    )
    with pytest.raises(CapabilityRegistryError, match="root|preparation"):
        replay_provider_observation_authority(
            record=authority.record,
            preparation_authority=spliced,
            observation_root_authority=(
                authority.observation_root_authority
            ),
            launch_intent=intent,
            evaluation_generation=authority.evaluation_generation,
        )
    with pytest.raises(CapabilityRegistryError, match="exact model"):
        authority.validate_receipt(
            replace(receipt, exact_model_id="gpt-5.6-sol-other"),
            launch_intent=intent,
        )


@pytest.mark.parametrize(
    "identity",
    (
        "provider/latest",
        "provider/model:default",
        "provider/account-default",
        "sk-proj-abcdefghijklmnopqrstuv",
        "xox" + "b-123456789012-abcdefghijklmnop",
    ),
)
def test_identity_grammar_rejects_nested_aliases_and_credential_material(
    identity: str,
) -> None:
    with pytest.raises(
        CapabilityRegistryError, match="alias|credential|identity"
    ):
        replace(
            ModelPolicyEntry(
                policy_id="identity-policy",
                backend="codex",
                semantic_model_capability_tier="R3_FRONTIER_REASONING",
                exact_model_id="provider/model:v1",
                reasoning_mode="xhigh",
            ),
            exact_model_id=identity,
        )


def test_provider_observation_authority_subclass_cannot_override_promotion_checks() -> None:
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
    honest = _observation_authority(receipt, intent)

    class ForgedProviderObservationAuthority(ProviderObservationAuthority):
        def __post_init__(self, _promotion_token: object) -> None:
            pass

        def validate_receipt(
            self,
            receipt: BackendCapabilityReceipt,
            *,
            launch_intent: BackendLaunchIntent,
        ) -> None:
            pass

    forged = ForgedProviderObservationAuthority(
        record=honest.record,
        evaluation_generation=honest.evaluation_generation,
        preparation_authority=honest.preparation_authority,
        observation_root_authority=honest.observation_root_authority,
    )
    plan, reservation, launch_generation = _test_launch_context(
        intent,
        resource_grant_digest=resource_digest,
        tool_capability_manifest_digest=tool_digest,
        model_capability_tier=receipt.semantic_model_capability_tier,
    )
    with pytest.raises(CapabilityRegistryError, match="exact|seal|authority"):
        promote_backend_capability_receipt(
            request=request,
            request_authority=request_authority,
            receipt=receipt,
            registry=registry,
            policy_entry=entry,
            launch_intent=intent,
            expected_model_policy_registry_digest=registry.registry_digest,
            expected_policy_entry_digest=entry.policy_entry_digest,
            expected_launch_intent_digest=intent.launch_intent_digest,
            expected_semantic_requirement_digest=semantic_digest,
            expected_resource_grant_digest=resource_digest,
            expected_tool_capability_manifest_digest=tool_digest,
            observation_authority=forged,
            semantic_work_plan=plan,
            global_reservation=reservation,
            launch_generation_authority=launch_generation,
        )


def test_provider_observation_authority_rejects_object_mutation_at_promotion() -> None:
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
    authority = _observation_authority(receipt, intent)
    object.__setattr__(
        authority,
        "evaluation_generation",
        authority.evaluation_generation + 1,
    )
    object.__setattr__(
        authority,
        "_seal",
        authority.provider_observation_authority_digest,
    )
    with pytest.raises(CapabilityRegistryError, match="seal|replay|authority"):
        authority.require_exact_replay()
    plan, reservation, launch_generation = _test_launch_context(
        intent,
        resource_grant_digest=resource_digest,
        tool_capability_manifest_digest=tool_digest,
        model_capability_tier=receipt.semantic_model_capability_tier,
    )

    with pytest.raises(CapabilityRegistryError, match="seal|replay|authority"):
        promote_backend_capability_receipt(
            request=request,
            request_authority=request_authority,
            receipt=receipt,
            registry=registry,
            policy_entry=entry,
            launch_intent=intent,
            expected_model_policy_registry_digest=registry.registry_digest,
            expected_policy_entry_digest=entry.policy_entry_digest,
            expected_launch_intent_digest=intent.launch_intent_digest,
            expected_semantic_requirement_digest=semantic_digest,
            expected_resource_grant_digest=resource_digest,
            expected_tool_capability_manifest_digest=tool_digest,
            observation_authority=authority,
            semantic_work_plan=plan,
            global_reservation=reservation,
            launch_generation_authority=launch_generation,
        )


def test_backend_capability_authority_rejects_subclass_and_object_mutation() -> None:
    receipt = _receipt()
    request, _, authority, *_ = _compiled_bundle(receipt)

    class ForgedBackendCapabilityAuthority(BackendCapabilityAuthority):
        def __post_init__(self, _promotion_token: object) -> None:
            pass

        def validate_against(self, **parents: object) -> None:
            pass

    forged = ForgedBackendCapabilityAuthority(
        request_digest=request.request_digest,
        request_authority_digest=authority.request_authority_digest,
        receipt_digest=receipt.receipt_digest,
        launch_intent_digest=authority.launch_intent_digest,
        model_policy_registry_digest=authority.model_policy_registry_digest,
        policy_entry_digest=authority.policy_entry_digest,
        trusted_observation_root_digest=(
            authority.trusted_observation_root_digest
        ),
        provider_observation_authority_digest=(
            authority.provider_observation_authority_digest
        ),
        launch_generation_authority_digest=(
            authority.launch_generation_authority_digest
        ),
        observation_generation=authority.observation_generation,
    )
    with pytest.raises(CapabilityRegistryError, match="exact|seal|authority"):
        evaluate_capability_preflight(request, receipt, authority=forged)

    object.__setattr__(
        authority,
        "trusted_observation_root_digest",
        _digest(8_881),
    )
    object.__setattr__(
        authority,
        "_seal",
        authority.capability_authority_digest,
    )
    with pytest.raises(CapabilityRegistryError, match="seal|replay|authority"):
        evaluate_capability_preflight(request, receipt, authority=authority)


def test_preflight_evaluator_rejects_narrowed_subclass_with_spoofed_digest() -> None:
    receipt = _receipt(context_window_tokens=32_768)
    request, _, authority, *_ = _compiled_bundle(receipt)
    authorized_digest = request.request_digest

    class NarrowedDigestSpoof(CapabilityPreflightRequest):
        @property
        def request_digest(self) -> str:
            return authorized_digest

    with pytest.raises(CapabilityRegistryError, match="exact|replay|request"):
        spoofed = NarrowedDigestSpoof.from_bytes(request.to_bytes())
        object.__setattr__(
            spoofed,
            "minimum_context_window_tokens",
            receipt.context_window_tokens,
        )
        assert spoofed.request_digest == authorized_digest
        evaluate_capability_preflight(spoofed, receipt, authority=authority)


def test_claude_ready_preparation_cannot_self_certify_startup_and_source(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from test_claude_provider_preparation import _prepare

    binder_source = inspect.getsource(
        BCR.bind_claude_provider_preparation_authority
    )
    assert "expected_startup_authority_sha256=record[" not in binder_source
    assert "expected_source_snapshot_sha256=record[" not in binder_source

    provider_preparation = _prepare(monkeypatch, tmp_path)
    record = provider_preparation.record
    executable = record["executable_observation"]
    executable_file = executable["implementation_files"][0]
    intent = BackendLaunchIntent(
        backend="claude",
        adapter_id="claude-exec-v1",
        adapter_version="1.0.0",
        provider_cli_name="claude-cli",
        provider_cli_version=executable["claude_code_version"],
        executable_sha256=executable_file["sha256"],
        executable_size_bytes=executable_file["size"],
        os_family="windows",
        account_mode="SUBSCRIPTION_OAUTH",
        transport_capability="HEADLESS_TRANSPORT",
    )
    _, _, launch_generation = _test_launch_context(intent)

    # No argument or launch-generation field supplies current startup/source
    # authority.  Reading both expectations back from the preparation record
    # would let stale/cross-process bytes self-certify READY.
    with pytest.raises(
        CapabilityRegistryError,
        match="startup|source|current|unavailable",
    ):
        BCR.bind_claude_provider_preparation_authority(
            provider_preparation=provider_preparation,
            launch_generation_authority=launch_generation,
            launch_intent=intent,
        )


def test_capability_promotion_rejects_stale_launch_generation_parents() -> None:
    from test_resource_grant import _bundle
    from test_resource_policy_authority import _plan
    from resource_policy_authority import (
        GlobalResourceReservation,
        compile_structural_test_reservation_budget_authority,
    )

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
    grant, _, baseline_reservation, _ = _bundle()
    reservation_budget = (
        compile_structural_test_reservation_budget_authority(
            reservation_id=baseline_reservation.reservation_id,
            run_id=baseline_reservation.run_id,
            generation=2,
            total_analysis_units=(
                baseline_reservation.total_analysis_units
            ),
            allocations=baseline_reservation.allocations,
            phase_roster_digest=_digest(7_001),
            scheduler_budget_digest=_digest(7_002),
        )
    )
    reservation = GlobalResourceReservation(
        reservation_id=baseline_reservation.reservation_id,
        run_id=baseline_reservation.run_id,
        generation=2,
        total_analysis_units=baseline_reservation.total_analysis_units,
        allocations=baseline_reservation.allocations,
        budget_authority=reservation_budget,
    )
    current_plan = replace(
        _plan(grant),
        semantic_generation=2,
        resource_grant_digest=resource_digest,
        tool_capability_manifest_digest=tool_digest,
    )
    current_launch_generation = (
        BCR.bind_structural_test_provider_launch_generation_authority(
            semantic_work_plan=current_plan,
            global_reservation=reservation,
            launch_intent=intent,
        )
    )
    stale_observation = _observation_authority(receipt, intent)

    with pytest.raises(
        CapabilityRegistryError,
        match="generation|reservation|launch",
    ):
        promote_backend_capability_receipt(
            request=request,
            request_authority=request_authority,
            receipt=receipt,
            registry=registry,
            policy_entry=entry,
            launch_intent=intent,
            expected_model_policy_registry_digest=registry.registry_digest,
            expected_policy_entry_digest=entry.policy_entry_digest,
            expected_launch_intent_digest=intent.launch_intent_digest,
            expected_semantic_requirement_digest=semantic_digest,
            expected_resource_grant_digest=resource_digest,
            expected_tool_capability_manifest_digest=tool_digest,
            observation_authority=stale_observation,
            semantic_work_plan=current_plan,
            global_reservation=reservation,
            launch_generation_authority=current_launch_generation,
        )


def test_ready_promotion_rejects_unreviewed_adapter_identity() -> None:
    receipt = _receipt(
        adapter_id="unsupported-adapter-v999",
        provider_cli_name="unsupported-provider-v999",
    )
    with pytest.raises(CapabilityRegistryError, match="adapter|reviewed|closed"):
        _compiled_bundle(receipt)


def test_ready_promotion_rejects_unreviewed_adapter_version() -> None:
    receipt = _receipt(adapter_version="999.0.0")
    with pytest.raises(CapabilityRegistryError, match="adapter|reviewed|closed"):
        _compiled_bundle(receipt)


def test_exact_request_and_requirement_cannot_be_narrowed_after_compilation() -> None:
    low_tools = tuple(
        replace(row, max_calls=1)
        if row.tool_capability == "SOURCE_READ"
        else row
        for row in _tools()
    )
    receipt = _receipt(tools=low_tools)
    entry = ModelPolicyEntry(
        policy_id="codex-policy",
        backend="codex",
        semantic_model_capability_tier=receipt.semantic_model_capability_tier,
        exact_model_id=receipt.exact_model_id,
        reasoning_mode=receipt.reasoning_mode,
    )
    registry = ModelPolicyRegistry.create((entry,))
    intent = BackendLaunchIntent(
        backend=receipt.backend,
        adapter_id=receipt.adapter_id,
        adapter_version=receipt.adapter_version,
        provider_cli_name=receipt.provider_cli_name,
        provider_cli_version=receipt.provider_cli_version,
        executable_sha256=receipt.executable_sha256,
        executable_size_bytes=receipt.executable_size_bytes,
        os_family=receipt.os_family,
        account_mode=receipt.account_mode,
        transport_capability="HEADLESS_TRANSPORT",
    )
    semantic_digest = _digest(300)
    resource_digest = _digest(301)
    tool_digest = _digest(302)
    template = _request()
    request, request_authority = _compile_capability_preflight_request(
        registry=registry,
        policy_entry=entry,
        launch_intent=intent,
        expected_model_policy_registry_digest=registry.registry_digest,
        expected_policy_entry_digest=entry.policy_entry_digest,
        expected_launch_intent_digest=intent.launch_intent_digest,
        semantic_requirement_digest=semantic_digest,
        resource_grant_digest=resource_digest,
        tool_capability_manifest_digest=tool_digest,
        minimum_context_window_tokens=(
            template.minimum_context_window_tokens
        ),
        minimum_output_tokens=template.minimum_output_tokens,
        required_tools=template.required_tools,
        minimum_native_commands=0,
        minimum_native_wall_time_seconds=0,
    )
    source_read = next(
        row
        for row in request.required_tools
        if row.tool_capability == "SOURCE_READ"
    )
    object.__setattr__(source_read, "required_calls", 1)
    object.__setattr__(request, "maximum_tool_calls_required", 13)
    object.__setattr__(
        request_authority, "request_digest", request.request_digest
    )
    plan, reservation, launch_generation = _test_launch_context(
        intent,
        resource_grant_digest=resource_digest,
        tool_capability_manifest_digest=tool_digest,
        model_capability_tier=receipt.semantic_model_capability_tier,
    )
    with pytest.raises(
        CapabilityRegistryError, match="seal|replay|request|issued"
    ):
        promote_backend_capability_receipt(
            request=request,
            request_authority=request_authority,
            receipt=receipt,
            registry=registry,
            policy_entry=entry,
            launch_intent=intent,
            expected_model_policy_registry_digest=registry.registry_digest,
            expected_policy_entry_digest=entry.policy_entry_digest,
            expected_launch_intent_digest=intent.launch_intent_digest,
            expected_semantic_requirement_digest=semantic_digest,
            expected_resource_grant_digest=resource_digest,
            expected_tool_capability_manifest_digest=tool_digest,
            observation_authority=_observation_authority(receipt, intent),
            semantic_work_plan=plan,
            global_reservation=reservation,
            launch_generation_authority=launch_generation,
        )


def test_exact_request_context_cannot_be_narrowed_with_authority_rewrite() -> None:
    receipt = _receipt(context_window_tokens=32_768)
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
    object.__setattr__(
        request,
        "minimum_context_window_tokens",
        receipt.context_window_tokens,
    )
    object.__setattr__(
        request_authority, "request_digest", request.request_digest
    )
    plan, reservation, launch_generation = _test_launch_context(
        intent,
        resource_grant_digest=resource_digest,
        tool_capability_manifest_digest=tool_digest,
        model_capability_tier=receipt.semantic_model_capability_tier,
    )
    with pytest.raises(
        CapabilityRegistryError, match="seal|replay|request|issued"
    ):
        promote_backend_capability_receipt(
            request=request,
            request_authority=request_authority,
            receipt=receipt,
            registry=registry,
            policy_entry=entry,
            launch_intent=intent,
            expected_model_policy_registry_digest=registry.registry_digest,
            expected_policy_entry_digest=entry.policy_entry_digest,
            expected_launch_intent_digest=intent.launch_intent_digest,
            expected_semantic_requirement_digest=semantic_digest,
            expected_resource_grant_digest=resource_digest,
            expected_tool_capability_manifest_digest=tool_digest,
            observation_authority=_observation_authority(receipt, intent),
            semantic_work_plan=plan,
            global_reservation=reservation,
            launch_generation_authority=launch_generation,
        )


def test_receipt_subclass_digest_spoof_and_nested_observation_are_rejected() -> None:
    receipt = _receipt(context_window_tokens=32_768)
    request, _, authority, *_ = _compiled_bundle(receipt)
    authorized_digest = receipt.receipt_digest

    class ReceiptDigestSpoof(BackendCapabilityReceipt):
        @property
        def receipt_digest(self) -> str:
            return authorized_digest

    with pytest.raises(
        CapabilityRegistryError, match="exact|subclass|receipt|replay"
    ):
        spoofed = ReceiptDigestSpoof.from_bytes(receipt.to_bytes())
        object.__setattr__(
            spoofed,
            "context_window_tokens",
            request.minimum_context_window_tokens,
        )
        object.__setattr__(
            spoofed.capabilities[0],
            "evidence_digest",
            _digest(8_765),
        )
        evaluate_capability_preflight(
            request,
            spoofed,
            authority=authority,
        )


def test_request_authority_subclass_factory_cannot_receive_private_token() -> None:
    receipt = _receipt()
    (
        request,
        authority,
        _,
        registry,
        entry,
        intent,
        semantic_digest,
        resource_digest,
        tool_digest,
    ) = _compiled_bundle(receipt)
    authorized_digest = authority.request_authority_digest

    class RequestAuthorityDigestSpoof(CapabilityRequestAuthority):
        @property
        def request_authority_digest(self) -> str:
            return authorized_digest

        def validate_against(self, **_parents: object) -> None:
            return None

    with pytest.raises(
        CapabilityRegistryError, match="exact|subclass|authority|replay"
    ):
        RequestAuthorityDigestSpoof.from_bytes(
            authority.to_bytes(),
            request=request,
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
        )


def test_preparation_and_observation_root_cannot_be_mutated_and_resealed() -> None:
    receipt = _receipt()
    *_, intent, _, _, _ = _compiled_bundle(receipt)
    observation = _observation_authority(receipt, intent)
    preparation = observation.preparation_authority
    root = observation.observation_root_authority
    assert preparation is not None
    assert root is not None

    object.__setattr__(
        preparation, "source_authority_digest", _digest(9_999)
    )
    object.__setattr__(
        preparation,
        "_seal",
        preparation.provider_preparation_authority_digest,
    )
    with pytest.raises(
        CapabilityRegistryError, match="seal|replay|issued"
    ):
        preparation.require_exact_replay()

    object.__setattr__(
        root, "observation_payload_digest", _digest(9_998)
    )
    object.__setattr__(
        root,
        "_seal",
        root.provider_observation_root_authority_digest,
    )
    with pytest.raises(
        CapabilityRegistryError, match="seal|replay|issued"
    ):
        root.require_exact_replay()
