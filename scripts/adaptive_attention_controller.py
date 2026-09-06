"""Deterministic, graph-off-safe adaptive-attention compiler.

All functions are pure transformations over typed records.  Runtime dispatch,
filesystem publication, provider calls, and closure authority live outside
this module.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import replace
from typing import Any, Iterable, Mapping, Sequence

from adaptive_attention_authority import (
    AdaptiveAttentionAuthorityError,
    AttentionAuthorityResolution,
    AttentionAuthorityResolver,
    AttentionLineageCommitRequest,
    ChannelAttemptAuthorityRequest,
    ClosurePolicyAuthorityRequest,
    UnresolvedAttentionAuthorityResolver,
)
from adaptive_attention_sources import AdaptedAttentionSources
from adaptive_attention_types import (
    AdaptiveAttentionError,
    AcceptedEvidenceReceipt,
    AmendmentObligationOperation,
    AttentionBudget,
    AttentionClosureAuthority,
    AttentionDebt,
    AttentionDenominator,
    AttentionGenesisAuthority,
    AttentionJoinProjection,
    AttentionObligation,
    AttentionPlan,
    AttentionRoster,
    AttentionScope,
    AttentionStopBindings,
    AttentionStopReceipt,
    ChannelAttemptAuthority,
    ChannelTerminalReceipt,
    ChannelTemplate,
    EvidenceChannel,
    EvidenceSlice,
    ResourceReservation,
    RosterAmendment,
    RuntimeCapabilityPolicy,
    SourceBinding,
    WorkerReceipt,
    channels_have_independent_evidence,
    digest_json,
    effective_roster_digest,
    effective_roster_material,
    transition_obligation,
)


_UNCERTAINTY_ORDER = {
    "CONFLICT": 0,
    "UNKNOWN_DENOMINATOR": 1,
    "MISSING_EVIDENCE": 2,
    "KNOWN_GAP": 3,
    "NONE": 4,
}
_OPEN_STATE_ORDER = {
    "UNCOVERED": 0,
    "DISPUTED": 1,
    "DEBT": 2,
    "ASSIGNED": 3,
    "EVIDENCED": 4,
    "CLOSED": 5,
}
# Baseline work is reserved before additive graph work.  Graph facts may add
# work and rank within their additive tranche, but can never consume capacity
# that would otherwise execute a baseline obligation.
_GRAPH_ORDER = {"BASELINE": 0, "NONE": 0, "TYPED_ADDITIVE": 1}


def _exact_authority_resolution(
    request: (
        ChannelAttemptAuthorityRequest
        | ClosurePolicyAuthorityRequest
        | AttentionLineageCommitRequest
    ),
    resolution: AttentionAuthorityResolution,
) -> AttentionAuthorityResolution:
    if not isinstance(resolution, AttentionAuthorityResolution):
        raise AdaptiveAttentionError(
            "authority resolver returned an untyped resolution"
        )
    if resolution.request_digest != request.request_digest:
        raise AdaptiveAttentionError(
            "authority resolver returned a stale or substituted resolution"
        )
    try:
        return resolution.replay_for(request)
    except AdaptiveAttentionAuthorityError as exc:
        raise AdaptiveAttentionError(str(exc)) from exc


def _attempt_authority_request(
    authority: ChannelAttemptAuthority,
) -> ChannelAttemptAuthorityRequest:
    terminal = authority.terminal_receipt
    try:
        return ChannelAttemptAuthorityRequest.create(
            scope_digest=authority.scope_digest,
            effective_roster_digest=(
                authority.effective_roster_digest
            ),
            authority_digest=authority.authority_digest,
            channel_id=authority.channel_id,
            channel_row_digest=authority.channel_row_digest,
            current_attempt=authority.current_attempt,
            lease_id=authority.lease_id,
            phase_io_commit_digest=authority.phase_io_commit_digest,
            transaction_commit_digest=(
                authority.transaction_commit_digest
            ),
            terminal_receipt_digest=terminal.receipt_digest,
            output_digest=terminal.output_digest,
        )
    except AdaptiveAttentionAuthorityError as exc:
        raise AdaptiveAttentionError(str(exc)) from exc


def _policy_authority_request(
    parent: Any,
) -> ClosurePolicyAuthorityRequest:
    try:
        return ClosurePolicyAuthorityRequest.create(
            parent_digest=parent.parent_digest,
            obligation_id=parent.obligation_id,
            obligation_row_digest=parent.obligation_row_digest,
            closure_policy=parent.closure_policy,
            authority_class=parent.authority_class,
            join_digest=parent.join_digest,
            provider_receipt_digest=parent.provider_receipt_digest,
        )
    except AdaptiveAttentionAuthorityError as exc:
        raise AdaptiveAttentionError(str(exc)) from exc


def _lineage_authority_request(
    *,
    scope: AttentionScope,
    roster: AttentionRoster,
    effective_digest: str,
    projection: AttentionJoinProjection,
) -> AttentionLineageCommitRequest:
    try:
        return AttentionLineageCommitRequest.create(
            scope_digest=scope.scope_digest,
            base_roster_digest=roster.roster_digest,
            effective_roster_digest=effective_digest,
            expected_parent_join_digest=(
                projection.parent_join_digest
            ),
            proposed_join_digest=projection.join_digest,
            join_sequence=projection.join_sequence,
            genesis_authority_digest=(
                projection.genesis_authority_digest
            ),
        )
    except AdaptiveAttentionAuthorityError as exc:
        raise AdaptiveAttentionError(str(exc)) from exc
def compile_attention_denominator(
    *,
    scope: AttentionScope,
    sources: AdaptedAttentionSources,
) -> AttentionDenominator:
    """Compile the exact known rows and preserve denominator uncertainty."""

    if not isinstance(scope, AttentionScope):
        raise TypeError("scope must be an AttentionScope")
    if not isinstance(sources, AdaptedAttentionSources):
        raise TypeError(
            "sources must be an AdaptedAttentionSources record"
        )
    return AttentionDenominator.create(
        scope=scope,
        coverage_kind=sources.coverage_kind,
        obligations=sources.obligations,
        provider_debt_ids=sources.provider_debt_ids,
    )


def _closure_policy_family(policy: str) -> str:
    # The named policy is already stable authority.  Keeping it exact avoids
    # packing obligations whose central closure prerequisites only look alike.
    return policy


def _template_compatibility_for_obligation(
    row: AttentionObligation,
) -> tuple[Any, ...]:
    return (
        row.kind,
        row.role_family,
        row.methodology_family,
        row.source_class,
        row.proof_environment,
        row.required_tool_classes,
        row.dependency_generation,
        _closure_policy_family(row.closure_policy),
    )


def compile_channel_templates(
    *,
    denominator: AttentionDenominator,
    obligations_per_channel: int = 4,
) -> tuple[ChannelTemplate, ...]:
    """Derive one stable template for each exact compatibility class."""

    if not isinstance(denominator, AttentionDenominator):
        raise TypeError(
            "denominator must be an AttentionDenominator"
        )
    if (
        isinstance(obligations_per_channel, bool)
        or not isinstance(obligations_per_channel, int)
    ):
        raise AdaptiveAttentionError(
            "obligations_per_channel must be an integer"
        )
    payload_cap = obligations_per_channel
    if payload_cap <= 0:
        raise AdaptiveAttentionError(
            "obligations_per_channel must be positive"
        )
    templates: dict[tuple[Any, ...], ChannelTemplate] = {}
    for obligation in denominator.obligations:
        if obligation.kind in {"PROVIDER_DEBT", "MERGE_ITEM"}:
            continue
        key = _template_compatibility_for_obligation(obligation)
        attention_units = (
            2 if obligation.kind == "VERIFIER_ITEM" else 1
        )
        template = ChannelTemplate.create(
            obligation_kind=obligation.kind,
            role_id=(
                f"attention-{obligation.role_family}-"
                f"{obligation.kind.lower()}"
            ),
            role_family=obligation.role_family,
            methodology_family=obligation.methodology_family,
            source_class=obligation.source_class,
            proof_environment=obligation.proof_environment,
            required_tool_classes=obligation.required_tool_classes,
            dependency_generation=obligation.dependency_generation,
            closure_policy_family=_closure_policy_family(
                obligation.closure_policy
            ),
            max_obligations=payload_cap,
            attention_units=attention_units,
        )
        existing = templates.get(key)
        if (
            existing is not None
            and existing.template_digest != template.template_digest
        ):
            raise AdaptiveAttentionError(
                "template compatibility key is ambiguous"
            )
        templates[key] = template
    return tuple(
        sorted(templates.values(), key=lambda row: row.template_id)
    )


def _obligation_rank(row: AttentionObligation) -> tuple[Any, ...]:
    return (
        _GRAPH_ORDER[row.graph_origin],
        0 if row.mandatory else 1,
        0 if row.closure_blocking else 1,
        -row.impact_rank,
        _UNCERTAINTY_ORDER[row.uncertainty_class],
        -row.dependency_fanout,
        _OPEN_STATE_ORDER[row.state],
        row.obligation_id,
    )


def _obligation_work_binding_digest(row: AttentionObligation) -> str:
    """Bind immutable work inputs while excluding controller lifecycle state."""

    payload = row.to_dict()
    payload.pop("row_digest")
    payload.pop("state")
    payload.pop("closure_authority_digest")
    return digest_json(payload)


def _debt_for_obligation(
    row: AttentionObligation,
    *,
    reason_code: str,
    provider: str = "attention-controller",
    failed_channel_ids: Iterable[str] = (),
    reserved_attention_units: int = 0,
    clearing_condition: str,
) -> AttentionDebt:
    return AttentionDebt.create(
        obligation_id=row.obligation_id,
        phase=row.phase,
        dependency_generation=row.dependency_generation,
        provider=provider,
        reason_code=reason_code,
        failed_channel_ids=failed_channel_ids,
        reserved_attention_units=reserved_attention_units,
        consumed_attention_units=0,
        affected_identities=row.subject_ids,
        clean_assurance_forbidden=not row.enrichment_only,
        clearing_condition=clearing_condition,
    )


def _pack_channel(
    *,
    scope: AttentionScope,
    rows: Sequence[AttentionObligation],
    template: ChannelTemplate,
    runtime_policy: RuntimeCapabilityPolicy,
    graph_treatment_digest: str,
) -> EvidenceChannel:
    source_bindings = {
        binding for row in rows for binding in row.source_bindings
    }
    methodology_bindings = {
        binding for row in rows for binding in row.methodology_bindings
    }
    method_step_ids = {
        binding.step_id for binding in methodology_bindings
    }
    predecessor_digests = {
        digest
        for row in rows
        for digest in row.predecessor_receipt_digests
    }
    subjects = {
        subject for row in rows for subject in row.subject_ids
    }
    max_prompt_projection_digest = digest_json(
        {
            "schema": "plamen.attention_prompt_projection.v1",
            "template_digest": template.template_digest,
            "obligation_row_digests": [
                row.row_digest
                for row in sorted(
                    rows, key=lambda item: item.obligation_id
                )
            ],
        }
    )
    evidence_slice = EvidenceSlice.create(
        scope=scope,
        source_bindings=source_bindings,
        subject_ids=subjects,
        method_step_ids=method_step_ids,
        graph_marker=(
            "GRAPH_OFF"
            if scope.graph_treatment == "legacy_off"
            else "TYPED_ADDITIVE"
        ),
        predecessor_receipt_digests=predecessor_digests,
        permitted_tool_classes=template.required_tool_classes,
        max_prompt_projection_digest=max_prompt_projection_digest,
    )
    requested_reservation = ResourceReservation.model_channel(
        attention_units=template.attention_units
    )
    reservation = ResourceReservation.create(
        attention_units=requested_reservation.attention_units,
        max_input_tokens=min(
            requested_reservation.max_input_tokens,
            runtime_policy.context_floor,
        ),
        max_output_tokens=min(
            requested_reservation.max_output_tokens,
            runtime_policy.output_ceiling,
        ),
        max_tool_invocations=requested_reservation.max_tool_invocations,
        timeout_slots=requested_reservation.timeout_slots,
    )
    return EvidenceChannel.create(
        scope=scope,
        obligation_ids=(row.obligation_id for row in rows),
        evidence_slice=evidence_slice,
        role_id=template.role_id,
        role_family=template.role_family,
        source_class=template.source_class,
        methodology_bindings=methodology_bindings,
        graph_treatment_digest=graph_treatment_digest,
        runtime_policy=runtime_policy,
        independence_signature=(
            template.role_family,
            template.methodology_family,
            template.source_class,
            template.proof_environment,
            evidence_slice.slice_id,
        ),
        resource_reservation=reservation,
        prerequisite_ids=predecessor_digests,
    )


def compile_attention_plan(
    *,
    scope: AttentionScope,
    denominator: AttentionDenominator,
    templates: Iterable[ChannelTemplate],
    budget: AttentionBudget,
    runtime_policy: RuntimeCapabilityPolicy,
    graph_treatment_digest: str,
    base_roster: AttentionRoster | None = None,
    prior_amendments: Sequence[RosterAmendment] = (),
    prior_denominator: AttentionDenominator | None = None,
    prior_channels: Iterable[EvidenceChannel] = (),
) -> AttentionPlan:
    """Rank, pack, reserve, and publish one immutable semantic roster."""

    if denominator.scope_digest != scope.scope_digest:
        raise AdaptiveAttentionError(
            "denominator and compiler scope differ"
        )
    if AttentionDenominator.from_dict(
        denominator.to_dict()
    ) != denominator:
        raise AdaptiveAttentionError(
            "denominator does not replay"
        )
    if not isinstance(budget, AttentionBudget):
        raise TypeError("budget must be an AttentionBudget")
    if not isinstance(runtime_policy, RuntimeCapabilityPolicy):
        raise TypeError(
            "runtime_policy must be a RuntimeCapabilityPolicy"
        )
    known_obligation_ids: set[str] = set()
    existing_channels: list[EvidenceChannel] = []
    prior_debt: list[AttentionDebt] = []
    if base_roster is not None:
        if not isinstance(base_roster, AttentionRoster):
            raise TypeError("base_roster must be an AttentionRoster")
        if prior_denominator is None:
            raise AdaptiveAttentionError(
                "prior_denominator is required for continuation"
            )
        if not isinstance(prior_denominator, AttentionDenominator):
            raise TypeError(
                "prior_denominator must be an AttentionDenominator"
            )
        effective_roster_digest(base_roster, prior_amendments)
        if AttentionDenominator.from_dict(
            prior_denominator.to_dict()
        ) != prior_denominator:
            raise AdaptiveAttentionError(
                "prior_denominator does not replay"
            )
        if (
            prior_denominator.denominator_digest
            != base_roster.denominator_digest
        ):
            if prior_amendments:
                _active_channels, _active_debt, active_rows = (
                    effective_roster_material(
                        base_roster, prior_amendments
                    )
                )
                supplied_rows = tuple(
                    (row.obligation_id, row.row_digest)
                    for row in prior_denominator.obligations
                )
                if supplied_rows != active_rows:
                    raise AdaptiveAttentionError(
                        "prior_denominator is not the exact effective "
                        "roster parent"
                    )
            else:
                raise AdaptiveAttentionError(
                    "prior_denominator is not the exact base roster parent"
                )
        (
            effective_channels,
            effective_debt,
            effective_rows,
        ) = effective_roster_material(base_roster, prior_amendments)
        known_obligation_ids.update(
            obligation_id
            for obligation_id, _row_digest in effective_rows
        )
        existing_channels.extend(effective_channels)
        prior_debt.extend(effective_debt)
    existing_channels.extend(prior_channels)
    invalidated: set[str] = set()
    if prior_denominator is not None:
        if not isinstance(prior_denominator, AttentionDenominator):
            raise TypeError(
                "prior_denominator must be an AttentionDenominator"
            )
        old_rows = {
            row.obligation_id: _obligation_work_binding_digest(row)
            for row in prior_denominator.obligations
        }
        invalidated.update(
            row.obligation_id
            for row in denominator.obligations
            if row.obligation_id in old_rows
            and _obligation_work_binding_digest(row)
            != old_rows[row.obligation_id]
        )
    for channel in existing_channels:
        if (
            channel.runtime_policy.runtime_policy_digest
            != runtime_policy.runtime_policy_digest
            or channel.graph_treatment_digest != graph_treatment_digest
        ):
            invalidated.update(channel.obligation_ids)
    current_rows_by_id = {
        row.obligation_id: row for row in denominator.obligations
    }
    for debt_row in prior_debt:
        row = current_rows_by_id.get(debt_row.obligation_id)
        if row is not None:
            invalidated.add(row.obligation_id)
    known_obligation_ids.difference_update(invalidated)
    template_by_key: dict[tuple[Any, ...], list[ChannelTemplate]] = (
        defaultdict(list)
    )
    for template in templates:
        if not isinstance(template, ChannelTemplate):
            raise TypeError("channel template has an invalid type")
        template_by_key[template.compatibility_key()].append(template)
    for values in template_by_key.values():
        values.sort(key=lambda row: row.template_id)

    debt: list[AttentionDebt] = []
    schedulable: list[AttentionObligation] = []
    for row in denominator.obligations:
        if row.obligation_id in known_obligation_ids:
            continue
        if row.kind == "PROVIDER_DEBT":
            debt.append(
                _debt_for_obligation(
                    row,
                    reason_code=(
                        row.debt_reason_code or "MISSING_PROVIDER"
                    ),
                    provider=row.provider or "source-provider",
                    clearing_condition=(
                        row.clearing_condition
                        or "provider becomes current and denominator recompiles"
                    ),
                )
            )
            continue
        if row.kind == "MERGE_ITEM":
            if row.state != "CLOSED":
                debt.append(
                    _debt_for_obligation(
                        row,
                        reason_code="CENTRAL_AUTHORITY_REQUIRED",
                        clearing_condition=(
                            "central join reconciles the exact denominator"
                        ),
                    )
                )
            continue
        if row.state in {"CLOSED", "EVIDENCED"}:
            continue
        key = _template_compatibility_for_obligation(row)
        candidates = template_by_key.get(key, ())
        if not candidates:
            debt.append(
                _debt_for_obligation(
                    row,
                    reason_code="NO_ADMISSIBLE_TEMPLATE",
                    clearing_condition=(
                        "publish a compatible typed channel template"
                    ),
                )
            )
            continue
        template = candidates[0]
        missing_tools = sorted(
            set(template.required_tool_classes)
            - set(runtime_policy.allowed_tool_classes)
        )
        if missing_tools:
            debt.append(
                _debt_for_obligation(
                    row,
                    reason_code="MISSING_CAPABILITY",
                    provider=runtime_policy.provider_family,
                    clearing_condition=(
                        "provide required tool classes: "
                        + ",".join(missing_tools)
                    ),
                )
            )
            continue
        schedulable.append(row)

    remaining = sorted(schedulable, key=_obligation_rank)
    packed: list[tuple[EvidenceChannel, tuple[AttentionObligation, ...]]] = []
    while remaining:
        highest = remaining[0]
        key = _template_compatibility_for_obligation(highest)
        template = template_by_key[key][0]
        compatible = [
            row
            for row in remaining
            if _template_compatibility_for_obligation(row) == key
        ][: template.max_obligations]
        selected_ids = {row.obligation_id for row in compatible}
        remaining = [
            row
            for row in remaining
            if row.obligation_id not in selected_ids
        ]
        packed.append(
            (
                _pack_channel(
                scope=scope,
                rows=compatible,
                template=template,
                runtime_policy=runtime_policy,
                graph_treatment_digest=graph_treatment_digest,
                ),
                tuple(compatible),
            )
        )

    accepted: list[EvidenceChannel] = []
    chain_reserved_channels = len(
        {channel.channel_id for channel in existing_channels}
    )
    chain_reserved_au = sum(
        channel.resource_reservation.attention_units
        for channel in {
            channel.channel_id: channel for channel in existing_channels
        }.values()
    )
    reserved_channels = max(
        budget.reserved_channels, chain_reserved_channels
    )
    reserved_au = max(
        budget.reserved_attention_units, chain_reserved_au
    )
    obligations_by_id = {
        row.obligation_id: row for row in denominator.obligations
    }
    origin_channels = {
        channel.channel_id: channel for channel in existing_channels
    }
    for channel, channel_rows in packed:
        reservation = channel.resource_reservation.attention_units
        invalid_challenges = []
        for obligation in channel_rows:
            if obligation.kind != "CANDIDATE_CHALLENGE":
                continue
            origin = next(
                (
                    origin_channels[value]
                    for value in obligation.subject_ids
                    if value in origin_channels
                ),
                None,
            )
            if (
                origin is None
                or not channels_have_independent_evidence(origin, channel)
            ):
                invalid_challenges.append(obligation)
        if invalid_challenges:
            for obligation in invalid_challenges:
                debt.append(
                    _debt_for_obligation(
                        obligation,
                        reason_code=(
                            "NO_ADMISSIBLE_INDEPENDENT_CHANNEL"
                        ),
                        failed_channel_ids=(channel.channel_id,),
                        clearing_condition=(
                            "publish a challenge channel with a distinct "
                            "slice and at least two independent dimensions"
                        ),
                    )
                )
            continue
        if reserved_channels + 1 > budget.max_total_channels:
            for obligation_id in channel.obligation_ids:
                debt.append(
                    _debt_for_obligation(
                        obligations_by_id[obligation_id],
                        reason_code="PHASE_CHANNEL_CAP",
                        failed_channel_ids=(channel.channel_id,),
                        clearing_condition=(
                            "start a newly authorized run with a higher "
                            "channel ceiling"
                        ),
                    )
                )
            continue
        if reserved_au + reservation > budget.max_attention_units:
            for obligation_id in channel.obligation_ids:
                debt.append(
                    _debt_for_obligation(
                        obligations_by_id[obligation_id],
                        reason_code="ATTENTION_UNIT_CAP",
                        failed_channel_ids=(channel.channel_id,),
                        reserved_attention_units=reservation,
                        clearing_condition=(
                            "start a newly authorized run with a higher "
                            "attention-unit ceiling"
                        ),
                    )
                )
            continue
        accepted.append(channel)
        reserved_channels += 1
        reserved_au += reservation

    roster = AttentionRoster.create(
        scope=scope,
        denominator=denominator,
        budget_policy_digest=digest_json(budget.semantic_view()),
        max_attempts_per_channel=budget.max_attempts_per_channel,
        graph_treatment_digest=graph_treatment_digest,
        channels=accepted,
        debt=debt,
    )
    return AttentionPlan.create(
        denominator=denominator,
        roster=roster,
        debt=debt,
    )


def _receipt_disposition(value: Any) -> tuple[str, bool]:
    if not isinstance(value, str):
        raise AdaptiveAttentionError(
            "worker receipt disposition must be exact text"
        )
    canonical = value.strip().upper()
    if canonical not in {
        "EVIDENCE_PROPOSED",
        "CANDIDATE_PROPOSED",
        "NO_EVIDENCE_WITH_TRACE",
        "INCONCLUSIVE",
        "BLOCKED",
    }:
        raise AdaptiveAttentionError(
            "unsupported exact worker disposition: " + canonical
        )
    return canonical, canonical == "NO_EVIDENCE_WITH_TRACE"


def _advance_to(
    row: AttentionObligation, target: str
) -> AttentionObligation:
    if row.state == target:
        return row
    if target == "EVIDENCED":
        if row.state == "CLOSED":
            return row
        if row.state in {"UNCOVERED", "DISPUTED", "DEBT"}:
            row = transition_obligation(row, "ASSIGNED")
        return transition_obligation(row, "EVIDENCED")
    if target == "DISPUTED":
        if row.state in {"UNCOVERED", "DEBT"}:
            row = transition_obligation(row, "ASSIGNED")
        if row.state == "ASSIGNED":
            return transition_obligation(row, "DISPUTED")
        if row.state == "EVIDENCED":
            return transition_obligation(row, "DISPUTED")
        if row.state == "CLOSED":
            return transition_obligation(row, "DISPUTED")
        return row
    if target == "DEBT":
        if row.state == "CLOSED":
            row = transition_obligation(row, "DISPUTED")
        if row.state == "UNCOVERED":
            row = transition_obligation(row, "ASSIGNED")
        if row.state == "DEBT":
            return row
        return transition_obligation(row, "DEBT")
    raise AdaptiveAttentionError("unsupported receipt state target")


def _iter_ids(value: Any, field: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, (str, bytes)) or not isinstance(
        value, Iterable
    ):
        raise AdaptiveAttentionError(f"{field} must be an array")
    result: set[str] = set()
    for item in value:
        if not isinstance(item, str) or not item.strip():
            raise AdaptiveAttentionError(
                f"{field} must contain only non-empty text identities"
            )
        result.add(item.strip())
    return tuple(sorted(result))


def _negative_challenge(
    *,
    scope: AttentionScope,
    original: AttentionObligation,
    output_digest: str,
    channel_id: str,
) -> AttentionObligation:
    receipt_binding = SourceBinding.create(
        f"receipt:{original.obligation_id}", output_digest
    )
    return AttentionObligation.create(
        scope=scope,
        kind="CANDIDATE_CHALLENGE",
        subject_ids=(
            original.obligation_id,
            "negative-proposal",
            channel_id,
        ),
        source_bindings=(
            *original.source_bindings,
            receipt_binding,
        ),
        methodology_bindings=original.methodology_bindings,
        predecessor_receipt_digests=(
            *original.predecessor_receipt_digests,
            output_digest,
        ),
        closure_policy="independent-negative-closure",
        mandatory=True,
        impact_rank=max(1, original.impact_rank),
        uncertainty_class="CONFLICT",
        graph_origin=original.graph_origin,
        state="UNCOVERED",
        role_family="challenge",
        methodology_family="independent-challenge",
        source_class=original.source_class,
        proof_environment=original.proof_environment,
        required_tool_classes=original.required_tool_classes,
        dependency_fanout=original.dependency_fanout,
        closure_blocking=True,
        enrichment_only=False,
        provider=original.provider,
    )


def apply_attention_receipts(
    *,
    scope: AttentionScope,
    obligations: Iterable[AttentionObligation],
    roster: AttentionRoster,
    amendments: Sequence[RosterAmendment] = (),
    accepted_receipts: Iterable[
        AcceptedEvidenceReceipt | Mapping[str, Any]
    ],
    genesis_authority: AttentionGenesisAuthority | None = None,
    prior_projection: AttentionJoinProjection | None = None,
    authority_resolver: AttentionAuthorityResolver | None = None,
) -> AttentionJoinProjection:
    """Replay authenticated current-attempt evidence without closure power."""

    obligation_rows = tuple(obligations)
    resolver = (
        authority_resolver
        if authority_resolver is not None
        else UnresolvedAttentionAuthorityResolver()
    )
    if (genesis_authority is None) == (prior_projection is None):
        raise AdaptiveAttentionError(
            "select exactly one continuation parent: genesis_authority or "
            "prior_projection"
        )
    if not isinstance(roster, AttentionRoster):
        raise TypeError("roster must be an AttentionRoster")
    effective_digest = effective_roster_digest(roster, amendments)
    active_channels, _active_debt, active_row_bindings = (
        effective_roster_material(roster, amendments)
    )
    exact_rows = tuple(
        (row.obligation_id, row.row_digest) for row in obligation_rows
    )
    if prior_projection is not None:
        if tuple(
            obligation_id
            for obligation_id, _row_digest in exact_rows
        ) != tuple(
            obligation_id
            for obligation_id, _row_digest in active_row_bindings
        ):
            raise AdaptiveAttentionError(
                "continuation obligations differ from the effective "
                "roster denominator"
            )
        if not isinstance(prior_projection, AttentionJoinProjection):
            raise TypeError(
                "prior_projection must be AttentionJoinProjection"
            )
        replayed_parent = AttentionJoinProjection.from_dict(
            prior_projection.to_dict()
        )
        if replayed_parent != prior_projection:
            raise AdaptiveAttentionError(
                "prior_projection does not replay"
            )
        if obligation_rows != prior_projection.denominator_obligations:
            raise AdaptiveAttentionError(
                "continuation obligations must equal the exact prior "
                "projection denominator"
            )
        if prior_projection.scope_digest != scope.scope_digest:
            raise AdaptiveAttentionError(
                "continuation projection scope binding is stale"
            )
        candidates = set(prior_projection.candidate_union)
        evidence = set(prior_projection.evidence_union)
        alias_sets: dict[str, set[str]] = defaultdict(set)
        for alias, roots in prior_projection.alias_map:
            alias_sets[alias].update(roots)
        retained_negatives: set[str] = set(
            prior_projection.retained_negative_proposal_ids
        )
        accepted_terminal_by_channel = {
            receipt.channel_id: receipt
            for receipt in prior_projection.accepted_terminal_receipts
        }
        accepted_digest_union = list(
            prior_projection.accepted_receipt_digests
        )
        parent_join_digest = prior_projection.join_digest
        genesis_digest = ""
        join_sequence = prior_projection.join_sequence + 1
    else:
        if exact_rows != active_row_bindings:
            raise AdaptiveAttentionError(
                "genesis obligations differ from the effective roster "
                "denominator"
            )
        if not isinstance(
            genesis_authority, AttentionGenesisAuthority
        ):
            raise TypeError(
                "genesis_authority must be an AttentionGenesisAuthority"
            )
        genesis_parent = AttentionGenesisAuthority.from_dict(
            genesis_authority.to_dict()
        )
        if (
            genesis_parent.scope_digest != scope.scope_digest
            or genesis_parent.effective_roster_digest
            != effective_digest
            or genesis_parent.denominator_rows != exact_rows
        ):
            raise AdaptiveAttentionError(
                "genesis authority differs from the exact receipt "
                "denominator or roster"
            )
        candidates = set()
        evidence = set()
        alias_sets = defaultdict(set)
        retained_negatives = set()
        accepted_terminal_by_channel = {}
        accepted_digest_union = []
        parent_join_digest = ""
        genesis_digest = genesis_parent.genesis_digest
        join_sequence = 1
    rows = {row.obligation_id: row for row in obligation_rows}
    if len(rows) != len(obligation_rows):
        raise AdaptiveAttentionError(
            "duplicate obligation identity in receipt denominator"
        )
    for row in obligation_rows:
        AttentionObligation.from_dict(row.to_dict())
    challenges: dict[str, AttentionObligation] = {
        row.obligation_id: row
        for row in obligation_rows
        if row.kind == "CANDIDATE_CHALLENGE"
    }
    channels_by_id = {
        channel.channel_id: channel for channel in active_channels
    }
    authority_debt_reasons: set[str] = set()
    authority_debt_obligation_ids: set[str] = set()
    normalized_accepted: dict[str, AcceptedEvidenceReceipt] = {}
    for raw_receipt in accepted_receipts:
        if isinstance(raw_receipt, AcceptedEvidenceReceipt):
            accepted = AcceptedEvidenceReceipt.from_dict(
                raw_receipt.to_dict()
            )
        elif isinstance(raw_receipt, Mapping):
            accepted = AcceptedEvidenceReceipt.from_dict(raw_receipt)
        else:
            raise TypeError(
                "accepted receipt must be an AcceptedEvidenceReceipt"
            )
        existing = normalized_accepted.get(
            accepted.accepted_receipt_digest
        )
        if existing is not None and existing != accepted:
            raise AdaptiveAttentionError(
                "duplicate accepted receipt identity has divergent content"
            )
        normalized_accepted[
            accepted.accepted_receipt_digest
        ] = accepted
    by_channel: dict[str, list[AcceptedEvidenceReceipt]] = defaultdict(
        list
    )
    for accepted in normalized_accepted.values():
        authority = accepted.attempt_authority
        receipt = accepted.worker_receipt
        channel = channels_by_id.get(authority.channel_id)
        if channel is None:
            raise AdaptiveAttentionError(
                "accepted receipt channel is outside the active roster"
            )
        if (
            authority.scope_digest != scope.scope_digest
            or authority.effective_roster_digest != effective_digest
            or authority.channel_row_digest != channel.row_digest
            or receipt.obligation_id not in channel.obligation_ids
        ):
            raise AdaptiveAttentionError(
                "accepted receipt authority or obligation binding is stale"
            )
        if authority.current_attempt > roster.max_attempts_per_channel:
            raise AdaptiveAttentionError(
                "accepted receipt current attempt exceeds the typed "
                "per-channel attempt cap"
            )
        request = _attempt_authority_request(authority)
        try:
            resolution = _exact_authority_resolution(
                request,
                resolver.resolve_channel_attempt(request),
            )
        except AttributeError as exc:
            raise AdaptiveAttentionError(
                "authority resolver lacks channel-attempt resolution"
            ) from exc
        if resolution.state == "DEBT":
            authority_debt_reasons.update(resolution.reason_codes)
            authority_debt_obligation_ids.add(
                receipt.obligation_id
            )
            continue
        by_channel[channel.channel_id].append(accepted)
    ordered_accepted: list[AcceptedEvidenceReceipt] = []
    for channel_id, accepted_rows in sorted(by_channel.items()):
        authority_digests = {
            row.attempt_authority.authority_digest
            for row in accepted_rows
        }
        if len(authority_digests) != 1:
            raise AdaptiveAttentionError(
                "accepted receipts mix current attempts or leases"
            )
        ordered = sorted(
            accepted_rows,
            key=lambda row: (
                row.worker_receipt.sequence,
                row.accepted_receipt_digest,
            ),
        )
        sequences = [
            row.worker_receipt.sequence for row in ordered
        ]
        if sequences != list(range(1, len(ordered) + 1)):
            raise AdaptiveAttentionError(
                "accepted receipt sequence is not contiguous from one"
            )
        previous_digest = ""
        for accepted in ordered:
            if (
                accepted.previous_accepted_receipt_digest
                != previous_digest
            ):
                raise AdaptiveAttentionError(
                    "accepted receipt sequence parent is torn or forked"
                )
            previous_digest = accepted.accepted_receipt_digest
        ordered_accepted.extend(ordered)
        accepted_terminal_by_channel[channel_id] = (
            ordered[0].attempt_authority.terminal_receipt
        )
    accepted_digest_union.extend(
        row.accepted_receipt_digest for row in ordered_accepted
    )

    by_obligation: dict[str, list[tuple[WorkerReceipt, str, bool]]] = (
        defaultdict(list)
    )
    for accepted in ordered_accepted:
        receipt = accepted.worker_receipt
        obligation_id = receipt.obligation_id
        if obligation_id not in rows:
            raise AdaptiveAttentionError(
                "worker receipt obligation is outside the denominator: "
                + obligation_id
            )
        disposition, is_negative = _receipt_disposition(
            receipt.disposition
        )
        by_obligation[obligation_id].append(
            (receipt, disposition, is_negative)
        )
        # Identity retention is disposition-independent.  Contradictory,
        # blocked, or negative rows affect state but cannot erase identities
        # present in the exact worker output.
        candidates.update(receipt.candidate_ids)
        evidence.update(receipt.evidence_ids)
        for alias, roots in receipt.aliases:
            alias_sets[alias].update(roots)
            candidates.update(roots)

    for obligation_id, receipt_rows in sorted(by_obligation.items()):
        row = rows[obligation_id]
        negatives = [item for item in receipt_rows if item[2]]
        blockers = [
            item
            for item in receipt_rows
            if item[1] in {"BLOCKED", "INCONCLUSIVE"}
        ]
        positives = [
            item
            for item in receipt_rows
            if item[1] in {"EVIDENCE_PROPOSED", "CANDIDATE_PROPOSED"}
        ]
        if negatives:
            rows[obligation_id] = _advance_to(row, "DISPUTED")
        elif blockers:
            rows[obligation_id] = _advance_to(row, "DEBT")
        elif positives:
            rows[obligation_id] = _advance_to(row, "EVIDENCED")
        for receipt, _disposition, _is_negative in negatives:
            output_digest = receipt.output_digest
            challenge = _negative_challenge(
                scope=scope,
                original=row,
                output_digest=output_digest,
                channel_id=receipt.channel_id,
            )
            challenges[challenge.obligation_id] = challenge
            retained_negatives.add(obligation_id)
    for obligation_id in sorted(authority_debt_obligation_ids):
        rows[obligation_id] = _advance_to(
            rows[obligation_id], "DEBT"
        )
    for row in rows.values():
        if row.kind == "CANDIDATE_CHALLENGE":
            challenges[row.obligation_id] = row
    projection = AttentionJoinProjection.create(
        scope_digest=scope.scope_digest,
        effective_roster_digest=effective_digest,
        parent_join_digest=parent_join_digest,
        genesis_authority_digest=genesis_digest,
        join_sequence=join_sequence,
        accepted_receipt_digests=accepted_digest_union,
        accepted_terminal_receipts=(
            accepted_terminal_by_channel[channel_id]
            for channel_id in sorted(accepted_terminal_by_channel)
        ),
        obligations=rows.values(),
        challenge_obligations=challenges.values(),
        candidate_union=candidates,
        evidence_union=evidence,
        alias_map=alias_sets,
        retained_negative_proposal_ids=retained_negatives,
        authority_debt_reason_codes=authority_debt_reasons,
    )
    lineage_request = _lineage_authority_request(
        scope=scope,
        roster=roster,
        effective_digest=effective_digest,
        projection=projection,
    )
    try:
        lineage_resolution = _exact_authority_resolution(
            lineage_request,
            resolver.commit_lineage(lineage_request),
        )
    except AttributeError as exc:
        raise AdaptiveAttentionError(
            "authority resolver lacks checked lineage commit"
        ) from exc
    if lineage_resolution.state == "AUTHENTICATED":
        return projection
    if "ATTENTION_LINEAGE_CONFLICT" in (
        lineage_resolution.reason_codes
    ):
        raise AdaptiveAttentionError(
            "attention lineage conflicting branch was rejected"
        )
    authority_debt_reasons.update(
        lineage_resolution.reason_codes
    )
    return AttentionJoinProjection.create(
        scope_digest=projection.scope_digest,
        effective_roster_digest=projection.effective_roster_digest,
        parent_join_digest=projection.parent_join_digest,
        genesis_authority_digest=(
            projection.genesis_authority_digest
        ),
        join_sequence=projection.join_sequence,
        accepted_receipt_digests=(
            projection.accepted_receipt_digests
        ),
        accepted_terminal_receipts=(
            projection.accepted_terminal_receipts
        ),
        obligations=projection.obligations,
        challenge_obligations=projection.challenge_obligations,
        candidate_union=projection.candidate_union,
        evidence_union=projection.evidence_union,
        alias_map=projection.alias_map_dict(),
        retained_negative_proposal_ids=(
            projection.retained_negative_proposal_ids
        ),
        authority_debt_reason_codes=authority_debt_reasons,
    )


def compile_roster_amendment(
    *,
    base_roster: AttentionRoster,
    prior_amendments: Sequence[RosterAmendment],
    denominator: AttentionDenominator,
    plan: AttentionPlan,
    triggering_event_digest: str,
    prior_denominator: AttentionDenominator | None = None,
) -> RosterAmendment:
    """Append typed NEW, REOPEN, or RETRY work to the active roster."""

    if not isinstance(base_roster, AttentionRoster):
        raise TypeError("base_roster must be an AttentionRoster")
    if not isinstance(denominator, AttentionDenominator):
        raise TypeError(
            "denominator must be an AttentionDenominator"
        )
    if not isinstance(plan, AttentionPlan):
        raise TypeError("plan must be an AttentionPlan")
    if AttentionPlan.from_dict(plan.to_dict()) != plan:
        raise AdaptiveAttentionError(
            "amendment plan does not replay"
        )
    if plan.denominator_digest != denominator.denominator_digest:
        raise AdaptiveAttentionError(
            "amendment plan does not bind the new denominator"
        )
    prior_digest = effective_roster_digest(
        base_roster, prior_amendments
    )
    active_channels, active_debt, active_row_bindings = (
        effective_roster_material(base_roster, prior_amendments)
    )
    prior_rows = dict(active_row_bindings)
    prior_work_bindings: dict[str, str] = {}
    if prior_denominator is not None:
        if not isinstance(prior_denominator, AttentionDenominator):
            raise TypeError(
                "prior_denominator must be an AttentionDenominator"
            )
        AttentionDenominator.from_dict(prior_denominator.to_dict())
        supplied_prior_rows = {
            row.obligation_id: row.row_digest
            for row in prior_denominator.obligations
        }
        if supplied_prior_rows != prior_rows:
            raise AdaptiveAttentionError(
                "prior_denominator differs from the effective roster "
                "obligation bindings"
            )
        prior_work_bindings = {
            row.obligation_id: _obligation_work_binding_digest(row)
            for row in prior_denominator.obligations
        }
    current_rows = {
        row.obligation_id: row for row in denominator.obligations
    }
    represented_by_plan = {
        obligation_id
        for channel in plan.roster.channels
        for obligation_id in channel.obligation_ids
    } | {row.obligation_id for row in plan.debt}
    represented_by_plan.update(
        obligation_id
        for obligation_id in current_rows
        if obligation_id not in prior_rows
    )
    represented_by_plan.update(
        obligation_id
        for obligation_id, row in current_rows.items()
        if obligation_id in prior_rows
        and (
            (
                prior_work_bindings
                and _obligation_work_binding_digest(row)
                != prior_work_bindings[obligation_id]
            )
            or (
                not prior_work_bindings
                and row.row_digest != prior_rows[obligation_id]
            )
        )
    )
    if not represented_by_plan:
        raise AdaptiveAttentionError(
            "roster amendment must not be a no-op"
        )
    if not represented_by_plan <= set(current_rows):
        raise AdaptiveAttentionError(
            "amendment plan contains work outside the denominator"
        )
    new_channels = tuple(
        channel
        for channel in plan.roster.channels
        if set(channel.obligation_ids) <= represented_by_plan
    )
    if {
        obligation_id
        for channel in plan.roster.channels
        for obligation_id in channel.obligation_ids
    } != {
        obligation_id
        for channel in new_channels
        for obligation_id in channel.obligation_ids
    }:
        raise AdaptiveAttentionError(
            "amendment channel mixes affected and prior obligations"
        )
    new_debt = tuple(
        row
        for row in plan.debt
        if row.obligation_id in represented_by_plan
    )
    represented = {
        obligation_id
        for channel in new_channels
        for obligation_id in channel.obligation_ids
    } | {row.obligation_id for row in new_debt}
    if represented != represented_by_plan:
        missing = sorted(represented_by_plan - represented)
        raise AdaptiveAttentionError(
            "amendment omits affected obligations: " + ",".join(missing)
        )
    operations: list[AmendmentObligationOperation] = []
    for obligation_id in sorted(represented_by_plan):
        prior_row_digest = prior_rows.get(obligation_id, "")
        if not prior_row_digest:
            operation = "NEW"
        else:
            work_changed = (
                _obligation_work_binding_digest(
                    current_rows[obligation_id]
                )
                != prior_work_bindings.get(
                    obligation_id,
                    _obligation_work_binding_digest(
                        current_rows[obligation_id]
                    ),
                )
                if prior_work_bindings
                else (
                    current_rows[obligation_id].row_digest
                    != prior_row_digest
                )
            )
            operation = "REOPEN" if work_changed else "RETRY"
        resulting_digest = (
            current_rows[obligation_id].row_digest
            if operation in {"NEW", "REOPEN"}
            else prior_row_digest
        )
        superseded = (
            tuple(
                channel.channel_id
                for channel in active_channels
                if obligation_id in channel.obligation_ids
            )
            if operation != "NEW"
            else ()
        )
        cleared = tuple(
            row.debt_digest
            for row in active_debt
            if row.obligation_id == obligation_id
        )
        operations.append(
            AmendmentObligationOperation.create(
                operation=operation,
                obligation_id=obligation_id,
                prior_row_digest=prior_row_digest,
                resulting_row_digest=resulting_digest,
                superseded_channel_ids=superseded,
                cleared_debt_digests=cleared,
            )
        )
    return RosterAmendment.create(
        sequence=len(prior_amendments) + 1,
        prior_effective_roster_digest=prior_digest,
        triggering_event_digest=triggering_event_digest,
        obligation_operations=operations,
        new_channels=new_channels,
        uncovered_debt=new_debt,
    )


def classify_attention_stop(
    *,
    scope: AttentionScope,
    denominator: AttentionDenominator,
    obligations: Iterable[AttentionObligation],
    roster: AttentionRoster,
    amendments: Sequence[RosterAmendment],
    bindings: AttentionStopBindings,
    join_projection: AttentionJoinProjection,
    closure_authority: AttentionClosureAuthority | None,
    authority_resolver: AttentionAuthorityResolver | None = None,
    bounded_reason_codes: Iterable[str] = (),
    halt_reason_codes: Iterable[str] = (),
) -> AttentionStopReceipt:
    """Classify clean, bounded, and failed-authority stopping exactly."""

    if not isinstance(scope, AttentionScope):
        raise TypeError("scope must be an AttentionScope")
    if not isinstance(bindings, AttentionStopBindings):
        raise TypeError("bindings must be AttentionStopBindings")
    if not isinstance(join_projection, AttentionJoinProjection):
        raise TypeError(
            "join_projection must be AttentionJoinProjection"
        )
    resolver = (
        authority_resolver
        if authority_resolver is not None
        else UnresolvedAttentionAuthorityResolver()
    )
    rows = tuple(sorted(obligations, key=lambda row: row.obligation_id))
    base_denominator_ids = {
        row.obligation_id for row in denominator.obligations
    }
    denominator_ids = {
        row.obligation_id
        for row in join_projection.denominator_obligations
    }
    if len({row.obligation_id for row in rows}) != len(rows):
        halts = {"STOP_DUPLICATE_OBLIGATION"}
    else:
        halts = set()
    unresolved = tuple(
        row.obligation_id for row in rows if row.state != "CLOSED"
    )
    reasons = {
        reason.strip().upper()
        for reason in bounded_reason_codes
        if isinstance(reason, str) and reason.strip()
    }
    reasons.update(join_projection.authority_debt_reason_codes)
    halts.update({
        reason.strip().upper()
        for reason in halt_reason_codes
        if isinstance(reason, str) and reason.strip()
    })
    try:
        AttentionDenominator.from_dict(denominator.to_dict())
    except (AdaptiveAttentionError, TypeError):
        halts.add("DENOMINATOR_INVALID")
    try:
        replayed_join = AttentionJoinProjection.from_dict(
            join_projection.to_dict()
        )
    except (AdaptiveAttentionError, TypeError):
        halts.add("JOIN_PROJECTION_INVALID")
    else:
        if replayed_join != join_projection:
            halts.add("JOIN_PROJECTION_INVALID")
    if {row.obligation_id for row in rows} != denominator_ids:
        halts.add("STOP_JOIN_DENOMINATOR_MISMATCH")
    expected_denominator_rows = tuple(
        (
            row.obligation_id,
            row.row_digest,
            tuple(
                binding.binding_digest
                for binding in row.source_bindings
            ),
        )
        for row in denominator.obligations
    )
    if bindings.denominator_rows != expected_denominator_rows:
        halts.add("DENOMINATOR_ROW_BINDING_MISMATCH")
    projected_by_id = {
        row.obligation_id: row
        for row in join_projection.denominator_obligations
    }
    for base_row in denominator.obligations:
        projected = projected_by_id.get(base_row.obligation_id)
        if projected is None:
            halts.add("JOIN_OMITS_BASE_DENOMINATOR")
            continue
        provenance_replay = replace(
            projected,
            state=base_row.state,
            closure_authority_digest=(
                base_row.closure_authority_digest
            ),
            row_digest=base_row.row_digest,
        )
        if provenance_replay != base_row:
            halts.add("JOIN_REWRITES_DENOMINATOR_ROW")
    if (
        tuple(bindings.candidate_union)
        != tuple(join_projection.candidate_union)
        or tuple(bindings.evidence_union)
        != tuple(join_projection.evidence_union)
        or tuple(bindings.alias_map) != tuple(join_projection.alias_map)
    ):
        halts.add("JOIN_UNION_BINDING_MISMATCH")
    if closure_authority is None:
        if any(row.state == "CLOSED" for row in rows):
            halts.add("UNAUTHORIZED_CLOSURE")
        else:
            reasons.add("CLOSURE_AUTHORITY_ABSENT")
    else:
        try:
            replayed_authority = AttentionClosureAuthority.from_dict(
                closure_authority.to_dict()
            )
        except (AdaptiveAttentionError, TypeError):
            halts.add("CLOSURE_AUTHORITY_INVALID")
        else:
            if replayed_authority != closure_authority:
                halts.add("CLOSURE_AUTHORITY_INVALID")
        try:
            expected_authority = AttentionClosureAuthority.create(
                scope=scope,
                denominator=denominator,
                join_projection=join_projection,
                stop_bindings=bindings,
                roster=roster,
                amendments=amendments,
                closure_policy_parents=(
                    closure_authority.closure_policy_parents
                ),
            )
        except (AdaptiveAttentionError, TypeError):
            halts.add("CLOSURE_AUTHORITY_PARENT_REPLAY_INVALID")
        else:
            if expected_authority != closure_authority:
                halts.add("CLOSURE_AUTHORITY_PARENT_REPLAY_MISMATCH")
        if (
            closure_authority.scope_digest != scope.scope_digest
            or closure_authority.denominator_digest
            != denominator.denominator_digest
            or closure_authority.join_digest
            != join_projection.join_digest
            or closure_authority.stop_bindings_digest
            != bindings.bindings_digest
        ):
            halts.add("CLOSURE_AUTHORITY_PARENT_MISMATCH")
        for policy_parent in closure_authority.closure_policy_parents:
            request = _policy_authority_request(policy_parent)
            try:
                resolution = _exact_authority_resolution(
                    request,
                    resolver.resolve_closure_policy(request),
                )
            except (
                AdaptiveAttentionError,
                AdaptiveAttentionAuthorityError,
                AttributeError,
            ):
                halts.add("CLOSURE_POLICY_RESOLVER_INVALID")
                continue
            if resolution.state == "DEBT":
                reasons.update(resolution.reason_codes)
        expected_authorized_rows = tuple(
            (
                row.obligation_id,
                row.row_digest,
            )
            for row in join_projection.denominator_obligations
        )
        if (
            closure_authority.authorized_obligation_rows
            != expected_authorized_rows
        ):
            halts.add("CLOSURE_AUTHORITY_ROWS_MISMATCH")
        for row in rows:
            parent = projected_by_id.get(row.obligation_id)
            if parent is None:
                continue
            if row.state == "CLOSED":
                try:
                    expected_closed = transition_obligation(
                        parent,
                        "CLOSED",
                        closure_authority=closure_authority,
                    )
                except (AdaptiveAttentionError, TypeError):
                    halts.add("CLOSURE_TRANSITION_INVALID")
                else:
                    if expected_closed != row:
                        halts.add("CLOSURE_TRANSITION_FORGED")
    try:
        replayed_bindings = AttentionStopBindings.from_dict(
            bindings.to_dict()
        )
    except (AdaptiveAttentionError, TypeError):
        halts.add("STOP_BINDINGS_INVALID")
    else:
        if replayed_bindings != bindings:
            halts.add("STOP_BINDINGS_INVALID")
    try:
        effective_digest = effective_roster_digest(
            roster, amendments
        )
    except AdaptiveAttentionError:
        effective_digest = roster.roster_digest
        halts.add("ROSTER_CHAIN_INVALID")
    if join_projection.scope_digest:
        try:
            lineage_request = _lineage_authority_request(
                scope=scope,
                roster=roster,
                effective_digest=effective_digest,
                projection=join_projection,
            )
            lineage_resolution = _exact_authority_resolution(
                lineage_request,
                resolver.resolve_lineage(lineage_request),
            )
        except (
            AdaptiveAttentionError,
            AdaptiveAttentionAuthorityError,
            AttributeError,
        ):
            halts.add("ATTENTION_LINEAGE_RESOLVER_INVALID")
        else:
            if lineage_resolution.state == "DEBT":
                reasons.update(lineage_resolution.reason_codes)
    if bindings.scope_digest != scope.scope_digest:
        halts.add("SCOPE_BINDING_MISMATCH")
    if denominator.scope_digest != scope.scope_digest:
        halts.add("DENOMINATOR_SCOPE_MISMATCH")
    if bindings.denominator_digest != denominator.denominator_digest:
        halts.add("DENOMINATOR_BINDING_MISMATCH")
    if bindings.effective_roster_digest != effective_digest:
        halts.add("ROSTER_BINDING_MISMATCH")
    if not set(bindings.prior_candidate_union) <= set(
        bindings.candidate_union
    ):
        halts.add("CANDIDATE_UNION_REGRESSION")
    if not set(bindings.prior_evidence_union) <= set(
        bindings.evidence_union
    ):
        halts.add("EVIDENCE_UNION_REGRESSION")
    prior_aliases = dict(bindings.prior_alias_map)
    current_aliases = dict(bindings.alias_map)
    if any(
        alias not in current_aliases
        or not set(roots) <= set(current_aliases[alias])
        for alias, roots in prior_aliases.items()
    ):
        halts.add("ALIAS_UNION_REGRESSION")
    halts.update(bindings.integrity_violations)

    try:
        (
            effective_channels_tuple,
            effective_debt_tuple,
            effective_row_bindings,
        ) = effective_roster_material(roster, amendments)
    except AdaptiveAttentionError:
        effective_channels_tuple = ()
        effective_debt_tuple = ()
        effective_row_bindings = ()
        halts.add("ROSTER_MATERIAL_INVALID")
    effective_channels = list(effective_channels_tuple)
    effective_debt = list(effective_debt_tuple)
    chain_obligation_ids = {
        obligation_id
        for obligation_id, _row_digest in effective_row_bindings
    }
    if chain_obligation_ids != denominator_ids:
        halts.add("ROSTER_DENOMINATOR_COVERAGE_MISMATCH")
    channel_by_id = {
        channel.channel_id: channel for channel in effective_channels
    }
    if len(channel_by_id) != len(effective_channels):
        halts.add("DUPLICATE_CHANNEL_IDENTITY")
    if any(
        channel.scope_digest != scope.scope_digest
        for channel in effective_channels
    ):
        halts.add("CHANNEL_SCOPE_MISMATCH")
    if any(
        debt.phase != scope.phase
        or debt.dependency_generation != scope.dependency_generation
        for debt in effective_debt
    ):
        halts.add("DEBT_SCOPE_MISMATCH")
    terminal_by_id = {
        receipt.channel_id: receipt
        for receipt in bindings.terminal_receipts
    }
    if set(terminal_by_id) - set(channel_by_id):
        halts.add("TERMINAL_RECEIPT_OUTSIDE_ROSTER")
    for channel_id, receipt in terminal_by_id.items():
        channel = channel_by_id.get(channel_id)
        if channel is not None and (
            receipt.channel_row_digest != channel.row_digest
        ):
            halts.add("STALE_TERMINAL_RECEIPT")
    missing_terminal = set(channel_by_id) - set(terminal_by_id)
    if missing_terminal:
        reasons.add("ACTIVE_OR_NONTERMINAL_CHANNEL")
    committed_ids = {
        channel_id
        for channel_id, receipt in terminal_by_id.items()
        if receipt.terminal_state == "COMMITTED"
    }
    if set(bindings.joined_channel_ids) != committed_ids:
        reasons.add("JOIN_NOT_RECONCILED")
    scheduled_obligation_ids = {
        obligation_id
        for channel in effective_channels
        for obligation_id in channel.obligation_ids
    }
    debt_obligation_ids = {
        debt.obligation_id for debt in effective_debt
    }
    if scheduled_obligation_ids & debt_obligation_ids:
        halts.add("OBLIGATION_WORK_DEBT_OVERLAP")
    if (
        scheduled_obligation_ids | debt_obligation_ids
    ) != denominator_ids:
        halts.add("OBLIGATION_COVERAGE_MISMATCH")
    if set(bindings.reconciled_obligation_ids) != (
        scheduled_obligation_ids
    ):
        reasons.add("OBLIGATION_JOIN_NOT_RECONCILED")
    for receipt in terminal_by_id.values():
        if receipt.terminal_state != "COMMITTED":
            reasons.add(receipt.reason_code)
    if halts:
        return AttentionStopReceipt.create(
            classification="HALT",
            denominator_digest=denominator.denominator_digest,
            effective_roster_digest_value=effective_digest,
            unresolved_obligation_ids=unresolved,
            reason_codes=halts,
            clean_full_assurance_claim_allowed=False,
        )

    if denominator.coverage_kind != "EXACT":
        reasons.add("DENOMINATOR_NOT_EXACT")
    for row in rows:
        if row.state != "CLOSED":
            reasons.add("OBLIGATION_" + row.state)
        if row.kind == "PROVIDER_DEBT" and row.debt_reason_code:
            reasons.add(row.debt_reason_code)
    for debt in effective_debt:
        reasons.add(debt.reason_code)

    if not unresolved and not reasons:
        return AttentionStopReceipt.create(
            classification="CLEAN_STOP",
            denominator_digest=denominator.denominator_digest,
            effective_roster_digest_value=effective_digest,
            unresolved_obligation_ids=(),
            reason_codes=(),
            clean_full_assurance_claim_allowed=True,
        )
    return AttentionStopReceipt.create(
        classification="BOUNDED_STOP_WITH_DEBT",
        denominator_digest=denominator.denominator_digest,
        effective_roster_digest_value=effective_digest,
        unresolved_obligation_ids=unresolved,
        reason_codes=reasons or {"UNRESOLVED_OBLIGATION"},
        clean_full_assurance_claim_allowed=False,
    )


__all__ = [
    "apply_attention_receipts",
    "classify_attention_stop",
    "compile_attention_denominator",
    "compile_attention_plan",
    "compile_channel_templates",
    "compile_roster_amendment",
]
