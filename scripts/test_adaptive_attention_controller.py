"""Fixture-first contracts for the pure deterministic attention compiler."""
from __future__ import annotations

from dataclasses import replace

import pytest

from adaptive_attention_controller import (
    apply_attention_receipts as _apply_attention_receipts,
    classify_attention_stop as _classify_attention_stop,
    compile_attention_denominator,
    compile_attention_plan,
    compile_channel_templates,
    compile_roster_amendment,
)
from adaptive_attention_authority import AttentionAuthorityResolution
from adaptive_attention_sources import adapt_attention_sources
from adaptive_attention_types import (
    AcceptedEvidenceReceipt,
    AmendmentObligationOperation,
    AttentionBudget,
    AttentionClosureAuthority,
    AttentionGenesisAuthority,
    AttentionJoinProjection,
    AttentionScope,
    AttentionStopBindings,
    ChannelAttemptAuthority,
    ChannelTerminalReceipt,
    ClosurePolicyParent,
    RuntimeCapabilityPolicy,
    RosterAmendment,
    WorkerReceipt,
    AttentionDenominator,
    AttentionObligation,
    AttentionPlan,
    SourceBinding,
    digest_json,
    effective_roster_digest,
    effective_roster_material,
    transition_obligation,
)


H1 = "1" * 64
H2 = "2" * 64
H3 = "3" * 64


class _FixtureAuthorityResolver:
    """Structural-test authority; real success providers live in integration."""

    def resolve_channel_attempt(self, request):
        return AttentionAuthorityResolution.authenticated(request)

    def resolve_closure_policy(self, request):
        return AttentionAuthorityResolution.authenticated(request)

    def commit_lineage(self, request):
        return AttentionAuthorityResolution.authenticated(request)

    def resolve_lineage(self, request):
        return AttentionAuthorityResolution.authenticated(request)


_FIXTURE_AUTHORITY_RESOLVER = _FixtureAuthorityResolver()


def apply_attention_receipts(**kwargs):
    kwargs.setdefault(
        "authority_resolver", _FIXTURE_AUTHORITY_RESOLVER
    )
    return _apply_attention_receipts(**kwargs)


def classify_attention_stop(**kwargs):
    kwargs.setdefault(
        "authority_resolver", _FIXTURE_AUTHORITY_RESOLVER
    )
    return _classify_attention_stop(**kwargs)


def _scope() -> AttentionScope:
    return AttentionScope.create(
        snapshot_digest=H1,
        pipeline="analysis",
        mode="core",
        ecosystem="fixture",
        phase="breadth",
        dependency_generation=0,
        phase_graph_digest=H2,
        active_phases=("breadth",),
        graph_treatment="legacy_off",
    )


def _row(index: int, *, tool: str = "read", impact: int = 2) -> dict:
    return {
        "provider": "component-authority",
        "kind": "COMPONENT",
        "canonical_id": f"COMPONENT-{index:03d}",
        "subject_ids": [f"component-{index:03d}"],
        "artifact_identity": f"scratchpad:component-{index:03d}.json",
        "artifact_sha256": f"{index + 10:064x}",
        "closure_policy": "driver-evidence-closure",
        "mandatory": True,
        "impact_rank": impact,
        "role_family": "analysis",
        "methodology_family": "baseline",
        "source_class": "source",
        "proof_environment": "static",
        "required_tool_classes": [tool],
        "dependency_fanout": index % 3,
    }


def _denominator(rows: list[dict]):
    sources = adapt_attention_sources(scope=_scope(), rows=rows)
    return compile_attention_denominator(scope=_scope(), sources=sources)


def _policy(backend: str = "alpha", tools: tuple[str, ...] = ("read",)):
    return RuntimeCapabilityPolicy.create(
        backend_family=backend,
        provider_family=f"{backend}-provider",
        model_capability_tier="standard",
        allowed_tool_classes=tools,
    )


def _budget(
    *,
    channels: int = 96,
    attention_units: int = 128,
    concurrency: int = 4,
):
    return AttentionBudget.create(
        max_total_channels=channels,
        max_attention_units=attention_units,
        max_concurrency=concurrency,
        max_attempts_per_channel=2,
    )


def _plan(
    rows: list[dict],
    *,
    backend: str = "alpha",
    channels: int = 96,
    attention_units: int = 128,
    concurrency: int = 4,
    tools: tuple[str, ...] = ("read",),
    obligations_per_channel: int = 4,
):
    denominator = _denominator(rows)
    templates = compile_channel_templates(
        denominator=denominator,
        obligations_per_channel=obligations_per_channel,
    )
    return compile_attention_plan(
        scope=_scope(),
        denominator=denominator,
        templates=templates,
        budget=_budget(
            channels=channels,
            attention_units=attention_units,
            concurrency=concurrency,
        ),
        runtime_policy=_policy(backend, tools),
        graph_treatment_digest=H3,
    )


def _stop_bindings(denominator, plan, *, terminal: bool = True):
    terminal_receipts = tuple(
        ChannelTerminalReceipt.create(
            channel=channel,
            terminal_state="COMMITTED",
            output_digest=H1,
        )
        for channel in plan.roster.channels
    ) if terminal else ()
    scheduled = {
        obligation_id
        for channel in plan.roster.channels
        for obligation_id in channel.obligation_ids
    }
    return AttentionStopBindings.create(
        scope=_scope(),
        denominator=denominator,
        effective_roster_digest_value=effective_roster_digest(
            plan.roster, ()
        ),
        terminal_receipts=terminal_receipts,
        joined_channel_ids=(
            (channel.channel_id for channel in plan.roster.channels)
            if terminal
            else ()
        ),
        reconciled_obligation_ids=scheduled,
    )


def _genesis(denominator, roster, amendments=()):
    return AttentionGenesisAuthority.create(
        scope=_scope(),
        denominator=denominator,
        roster=roster,
        amendments=amendments,
    )


def _accepted(roster, workers, amendments=()):
    workers = tuple(workers)
    channels, _debt, _rows = effective_roster_material(
        roster, amendments
    )
    channels_by_id = {
        channel.channel_id: channel for channel in channels
    }
    unique_workers = {
        worker.receipt_id: worker for worker in workers
    }
    grouped = {}
    for worker in unique_workers.values():
        grouped.setdefault(worker.channel_id, []).append(worker)
    accepted_by_worker = {}
    effective_digest = effective_roster_digest(roster, amendments)
    for channel_id, rows in grouped.items():
        channel = channels_by_id[channel_id]
        rows = sorted(rows, key=lambda row: row.sequence)
        assert len({row.attempt for row in rows}) == 1
        assert len({row.output_digest for row in rows}) == 1
        terminal = ChannelTerminalReceipt.create(
            channel=channel,
            terminal_state="COMMITTED",
            output_digest=rows[0].output_digest,
        )
        authority = ChannelAttemptAuthority.create(
            scope=_scope(),
            effective_roster_digest_value=effective_digest,
            channel=channel,
            current_attempt=rows[0].attempt,
            lease_id="LEASE-" + channel.channel_id[-12:],
            phase_io_commit_digest=H2,
            transaction_commit_digest=H3,
            terminal_receipt=terminal,
        )
        previous = None
        for worker in rows:
            accepted = AcceptedEvidenceReceipt.create(
                attempt_authority=authority,
                worker_receipt=worker,
                previous_receipt=previous,
            )
            accepted_by_worker[worker.receipt_id] = accepted
            previous = accepted
    return tuple(
        accepted_by_worker[worker.receipt_id] for worker in workers
    )


def _policy_parents(projection):
    authority_by_kind = {
        "METHOD_STEP": "METHODOLOGY_APPLICATION",
        "CANDIDATE_CHALLENGE": "CENTRAL_NEGATIVE_CLOSURE",
        "VERIFIER_ITEM": "VERIFIER_COMPLETION",
        "REPORT_ITEM": "REPORT_AUTHORITY",
        "MERGE_ITEM": "CENTRAL_JOIN",
    }
    return tuple(
        ClosurePolicyParent.create(
            obligation=row,
            join_projection=projection,
            authority_class=authority_by_kind.get(
                row.kind, "EVIDENCE_CLOSURE_BROKER"
            ),
            provider_receipt_digest=H3,
        )
        for row in projection.denominator_obligations
    )


def _joined_projection(denominator, plan, amendments=()):
    channels, _debt, _rows = effective_roster_material(
        plan.roster, amendments
    )
    channel_for_obligation = {
        obligation_id: channel
        for channel in channels
        for obligation_id in channel.obligation_ids
    }
    sequences = {}
    workers = []
    for row in denominator.obligations:
        channel = channel_for_obligation[row.obligation_id]
        sequences[channel.channel_id] = (
            sequences.get(channel.channel_id, 0) + 1
        )
        workers.append(
            WorkerReceipt.create(
                sequence=sequences[channel.channel_id],
                channel_id=channel.channel_id,
                obligation_id=row.obligation_id,
                disposition="EVIDENCE_PROPOSED",
                output_digest=H1,
            )
        )
    return apply_attention_receipts(
        scope=_scope(),
        obligations=denominator.obligations,
        roster=plan.roster,
        amendments=amendments,
        accepted_receipts=_accepted(
            plan.roster, workers, amendments
        ),
        genesis_authority=_genesis(
            denominator, plan.roster, amendments
        ),
    )


def _structural_projection(denominator):
    return AttentionJoinProjection.create(
        obligations=denominator.obligations,
        challenge_obligations=(),
        candidate_union=(),
        evidence_union=(),
        alias_map={},
        retained_negative_proposal_ids=(),
    )


def _close_with_authority(denominator, plan):
    projection = _joined_projection(denominator, plan)
    bindings = _stop_bindings(denominator, plan)
    authority = AttentionClosureAuthority.create(
        scope=_scope(),
        denominator=denominator,
        join_projection=projection,
        stop_bindings=bindings,
        roster=plan.roster,
        amendments=(),
        closure_policy_parents=_policy_parents(projection),
    )
    closed = tuple(
        transition_obligation(
            row,
            "CLOSED",
            closure_authority=authority,
        )
        for row in projection.denominator_obligations
    )
    return projection, bindings, authority, closed


def test_reorder_concurrency_and_backend_do_not_change_semantic_roster():
    rows = [_row(index) for index in range(9)]
    left = _plan(rows, backend="alpha", concurrency=1)
    reordered = _plan(list(reversed(rows)), backend="alpha", concurrency=4)
    other_backend = _plan(rows, backend="beta", concurrency=4)
    assert left.roster.semantic_roster_digest == reordered.roster.semantic_roster_digest
    assert left.roster.semantic_roster_digest == other_backend.roster.semantic_roster_digest
    assert left.total_reserved_attention_units == 3
    assert reordered.total_reserved_attention_units == 3
    assert other_backend.total_reserved_attention_units == 3
    assert [c.channel_id for c in left.roster.channels] != [
        c.channel_id for c in other_backend.roster.channels
    ]


def test_unrelated_new_row_appends_one_amendment_without_touching_siblings():
    base_rows = [_row(1), _row(2)]
    base_plan = _plan(base_rows, obligations_per_channel=1)
    new_denominator = _denominator([*base_rows, _row(3, impact=4)])
    templates = compile_channel_templates(
        denominator=new_denominator,
        obligations_per_channel=1,
    )
    new_plan = compile_attention_plan(
        scope=_scope(),
        denominator=new_denominator,
        templates=templates,
        budget=_budget(),
        runtime_policy=_policy(),
        graph_treatment_digest=H3,
        base_roster=base_plan.roster,
        prior_denominator=_denominator(base_rows),
    )
    amendment = compile_roster_amendment(
        base_roster=base_plan.roster,
        prior_amendments=(),
        denominator=new_denominator,
        plan=new_plan,
        triggering_event_digest=H3,
    )
    assert amendment.sequence == 1
    assert amendment.new_obligation_ids == ("COMPONENT-003",)
    assert len(amendment.new_channels) == 1
    assert {
        channel.channel_semantic_id for channel in base_plan.roster.channels
    }.isdisjoint(
        channel.channel_semantic_id for channel in amendment.new_channels
    )
    assert tuple(base_plan.roster.channels) == base_plan.roster.channels


def test_torn_or_forked_amendment_chain_fails_closed():
    base_plan = _plan([_row(1)], obligations_per_channel=1)
    new_denominator = _denominator([_row(1), _row(2)])
    templates = compile_channel_templates(
        denominator=new_denominator,
        obligations_per_channel=1,
    )
    new_plan = compile_attention_plan(
        scope=_scope(),
        denominator=new_denominator,
        templates=templates,
        budget=_budget(),
        runtime_policy=_policy(),
        graph_treatment_digest=H3,
        base_roster=base_plan.roster,
        prior_denominator=_denominator([_row(1)]),
    )
    amendment = compile_roster_amendment(
        base_roster=base_plan.roster,
        prior_amendments=(),
        denominator=new_denominator,
        plan=new_plan,
        triggering_event_digest=H3,
    )
    with pytest.raises(ValueError, match="content does not replay"):
        compile_roster_amendment(
            base_roster=base_plan.roster,
            prior_amendments=(
                replace(amendment, new_obligation_ids=("COMPONENT-999",)),
            ),
            denominator=_denominator([_row(4)]),
            plan=_plan([_row(4)], obligations_per_channel=1),
            triggering_event_digest=H2,
        )


def test_safe_and_no_finding_worker_receipts_never_close_obligations():
    denominator = _denominator([_row(1), _row(2)])
    plan = _plan(
        [_row(1), _row(2)], obligations_per_channel=1
    )
    channel_by_obligation = {
        obligation_id: channel
        for channel in plan.roster.channels
        for obligation_id in channel.obligation_ids
    }
    workers = tuple(
        WorkerReceipt.create(
            sequence=1,
            channel_id=channel_by_obligation[
                row.obligation_id
            ].channel_id,
            obligation_id=row.obligation_id,
            disposition="NO_EVIDENCE_WITH_TRACE",
            output_digest=H1 if index == 0 else H2,
        )
        for index, row in enumerate(denominator.obligations)
    )
    applied = apply_attention_receipts(
        scope=_scope(),
        obligations=denominator.obligations,
        roster=plan.roster,
        accepted_receipts=_accepted(plan.roster, workers),
        genesis_authority=_genesis(denominator, plan.roster),
    )
    assert {row.state for row in applied.obligations} == {"DISPUTED"}
    assert len(applied.challenge_obligations) == 2
    assert not any(row.state == "CLOSED" for row in applied.obligations)


def test_candidate_evidence_and_alias_unions_are_monotonic():
    denominator = _denominator([_row(1)])
    plan = _plan([_row(1)], obligations_per_channel=1)
    channel_id = plan.roster.channels[0].channel_id
    first_worker = WorkerReceipt.create(
        sequence=1,
        attempt=1,
        channel_id=channel_id,
        obligation_id="COMPONENT-001",
        disposition="CANDIDATE_PROPOSED",
        output_digest=H1,
        candidate_ids=("CANDIDATE-A",),
        evidence_ids=("EVIDENCE-A",),
        aliases={"ALIAS-A": "CANDIDATE-A"},
    )
    first = apply_attention_receipts(
        scope=_scope(),
        obligations=denominator.obligations,
        roster=plan.roster,
        accepted_receipts=_accepted(
            plan.roster, (first_worker,)
        ),
        genesis_authority=_genesis(denominator, plan.roster),
    )
    second_worker = WorkerReceipt.create(
        sequence=1,
        attempt=2,
        channel_id=channel_id,
        obligation_id="COMPONENT-001",
        disposition="EVIDENCE_PROPOSED",
        output_digest=H2,
        candidate_ids=("CANDIDATE-B",),
        evidence_ids=("EVIDENCE-B",),
        aliases={"ALIAS-A": "CANDIDATE-B"},
    )
    second = apply_attention_receipts(
        scope=_scope(),
        obligations=first.denominator_obligations,
        roster=plan.roster,
        accepted_receipts=_accepted(
            plan.roster, (second_worker,)
        ),
        prior_projection=first,
    )
    assert set(second.candidate_union) == {"CANDIDATE-A", "CANDIDATE-B"}
    assert set(second.evidence_union) == {"EVIDENCE-A", "EVIDENCE-B"}
    assert second.alias_map_dict()["ALIAS-A"] == (
        "CANDIDATE-A",
        "CANDIDATE-B",
    )


def test_channel_and_au_cap_debt_is_lossless_even_above_32_items():
    rows = [_row(index) for index in range(41)]
    plan = _plan(
        rows,
        channels=3,
        attention_units=3,
        obligations_per_channel=4,
    )
    scheduled = {
        obligation_id
        for channel in plan.roster.channels
        for obligation_id in channel.obligation_ids
    }
    debt_ids = {row.obligation_id for row in plan.debt}
    assert len(scheduled) == 12
    assert len(debt_ids) == 29
    assert scheduled.isdisjoint(debt_ids)
    assert scheduled | debt_ids == {f"COMPONENT-{i:03d}" for i in range(41)}
    assert all(
        row.reason_code in {"PHASE_CHANNEL_CAP", "ATTENTION_UNIT_CAP"}
        for row in plan.debt
    )


def test_missing_required_tool_becomes_capability_debt_not_hidden_work():
    plan = _plan(
        [_row(1, tool="prove"), _row(2)],
        tools=("read",),
        obligations_per_channel=1,
    )
    scheduled = {
        obligation_id
        for channel in plan.roster.channels
        for obligation_id in channel.obligation_ids
    }
    assert scheduled == {"COMPONENT-002"}
    assert [(row.obligation_id, row.reason_code) for row in plan.debt] == [
        ("COMPONENT-001", "MISSING_CAPABILITY")
    ]


def test_clean_stop_requires_exact_central_closure_and_debt_is_bounded():
    denominator = _denominator([_row(1), _row(2)])
    plan = _plan([_row(1), _row(2)])
    projection, bindings, authority, closed = _close_with_authority(
        denominator, plan
    )
    clean = classify_attention_stop(
        scope=_scope(),
        denominator=denominator,
        obligations=closed,
        roster=plan.roster,
        amendments=(),
        bindings=bindings,
        join_projection=projection,
        closure_authority=authority,
    )
    assert clean.classification == "CLEAN_STOP"
    assert clean.clean_full_assurance_claim_allowed
    bounded = classify_attention_stop(
        scope=_scope(),
        denominator=denominator,
        obligations=denominator.obligations,
        roster=plan.roster,
        amendments=(),
        bindings=_stop_bindings(denominator, plan),
        join_projection=_joined_projection(denominator, plan),
        closure_authority=None,
        bounded_reason_codes=("USER_CANCELLED",),
    )
    assert bounded.classification == "BOUNDED_STOP_WITH_DEBT"
    assert set(bounded.unresolved_obligation_ids) == {
        "COMPONENT-001",
        "COMPONENT-002",
    }
    assert not bounded.clean_full_assurance_claim_allowed


def test_lower_bound_denominator_can_never_stop_cleanly():
    baseline = adapt_attention_sources(scope=_scope(), rows=[_row(1)])
    graph_missing = adapt_attention_sources(
        scope=_scope(),
        rows=(),
        provider_statuses=(
            {
                "provider": "graph-authority",
                "available": False,
                "required": True,
                "count_semantics": "LOWER_BOUND",
                "reason_code": "MISSING_GRAPH_AUTHORITY",
                "clearing_condition": "publish a current graph binding",
            },
        ),
    )
    sources = adapt_attention_sources(
        scope=_scope(),
        rows=[_row(1)],
        supplemental=(graph_missing,),
    )
    denominator = compile_attention_denominator(scope=_scope(), sources=sources)
    templates = compile_channel_templates(denominator=denominator)
    plan = compile_attention_plan(
        scope=_scope(),
        denominator=denominator,
        templates=templates,
        budget=_budget(),
        runtime_policy=_policy(),
        graph_treatment_digest=H3,
    )
    receipt = classify_attention_stop(
        scope=_scope(),
        denominator=denominator,
        obligations=denominator.obligations,
        roster=plan.roster,
        amendments=(),
        bindings=_stop_bindings(denominator, plan),
        join_projection=_structural_projection(denominator),
        closure_authority=None,
    )
    assert baseline.coverage_kind == "EXACT"
    assert denominator.coverage_kind == "LOWER_BOUND"
    assert receipt.classification == "BOUNDED_STOP_WITH_DEBT"
    assert not receipt.clean_full_assurance_claim_allowed


def test_receipt_replay_is_permutation_and_duplicate_independent():
    denominator = _denominator([_row(1)])
    plan = _plan([_row(1)], obligations_per_channel=1)
    channel_id = plan.roster.channels[0].channel_id
    evidence = WorkerReceipt.create(
        sequence=2,
        channel_id=channel_id,
        obligation_id="COMPONENT-001",
        disposition="EVIDENCE_PROPOSED",
        output_digest=H1,
        evidence_ids=("EVIDENCE-A",),
    )
    blocked = WorkerReceipt.create(
        sequence=1,
        channel_id=channel_id,
        obligation_id="COMPONENT-001",
        disposition="BLOCKED",
        output_digest=H1,
        candidate_ids=("POISON",),
        evidence_ids=("POISON",),
        aliases={"POISON": "POISON"},
    )
    left = apply_attention_receipts(
        scope=_scope(),
        obligations=denominator.obligations,
        roster=plan.roster,
        accepted_receipts=_accepted(
            plan.roster, (evidence, blocked, evidence)
        ),
        genesis_authority=_genesis(denominator, plan.roster),
    )
    right = apply_attention_receipts(
        scope=_scope(),
        obligations=denominator.obligations,
        roster=plan.roster,
        accepted_receipts=_accepted(
            plan.roster, (blocked, evidence)
        ),
        genesis_authority=_genesis(denominator, plan.roster),
    )
    assert left.join_digest == right.join_digest
    assert left.obligations[0].state == "DEBT"
    assert "POISON" in left.candidate_union
    assert "POISON" in left.evidence_union


def test_negative_challenge_persists_and_blocks_later_positive_receipt():
    denominator = _denominator([_row(1)])
    plan = _plan([_row(1)], obligations_per_channel=1)
    channel_id = plan.roster.channels[0].channel_id
    negative = WorkerReceipt.create(
        sequence=1,
        channel_id=channel_id,
        obligation_id="COMPONENT-001",
        disposition="NO_EVIDENCE_WITH_TRACE",
        output_digest=H1,
    )
    first = apply_attention_receipts(
        scope=_scope(),
        obligations=denominator.obligations,
        roster=plan.roster,
        accepted_receipts=_accepted(plan.roster, (negative,)),
        genesis_authority=_genesis(denominator, plan.roster),
    )
    positive = WorkerReceipt.create(
        sequence=1,
        attempt=2,
        channel_id=channel_id,
        obligation_id="COMPONENT-001",
        disposition="EVIDENCE_PROPOSED",
        output_digest=H2,
    )
    with pytest.raises(ValueError, match="roster denominator"):
        apply_attention_receipts(
            scope=_scope(),
            obligations=first.denominator_obligations,
            roster=plan.roster,
            accepted_receipts=_accepted(plan.roster, (positive,)),
            prior_projection=first,
        )
    assert first.retained_negative_proposal_ids == ("COMPONENT-001",)


def test_caps_preserve_priority_and_are_cumulative_on_resume():
    rows = [
        _row(1, impact=1),
        _row(2, impact=4),
        _row(3, impact=3),
    ]
    plan = _plan(rows, channels=2, attention_units=2, obligations_per_channel=1)
    scheduled = {
        item for channel in plan.roster.channels
        for item in channel.obligation_ids
    }
    assert scheduled == {"COMPONENT-002", "COMPONENT-003"}
    base = _plan(rows[:2], channels=2, attention_units=2, obligations_per_channel=1)
    denominator = _denominator(rows)
    resumed = compile_attention_plan(
        scope=_scope(),
        denominator=denominator,
        templates=compile_channel_templates(
            denominator=denominator, obligations_per_channel=1
        ),
        budget=_budget(channels=2, attention_units=2),
        runtime_policy=_policy(),
        graph_treatment_digest=H3,
        base_roster=base.roster,
        prior_denominator=_denominator(rows[:2]),
    )
    assert not resumed.roster.channels
    assert [(row.obligation_id, row.reason_code) for row in resumed.debt] == [
        ("COMPONENT-003", "PHASE_CHANNEL_CAP")
    ]


def test_changed_dependency_or_runtime_policy_reopens_known_obligation():
    old_row = _row(1)
    base_denominator = _denominator([old_row])
    base = _plan([old_row], obligations_per_channel=1)
    changed = {**old_row, "artifact_sha256": H3}
    new_denominator = _denominator([changed])
    resumed = compile_attention_plan(
        scope=_scope(),
        denominator=new_denominator,
        templates=compile_channel_templates(
            denominator=new_denominator, obligations_per_channel=1
        ),
        budget=_budget(),
        runtime_policy=_policy("beta"),
        graph_treatment_digest=H3,
        base_roster=base.roster,
        prior_denominator=base_denominator,
    )
    assert {
        item for channel in resumed.roster.channels
        for item in channel.obligation_ids
    } == {"COMPONENT-001"}


def test_planned_channels_without_terminal_receipts_cannot_stop_clean():
    denominator = _denominator([_row(1)])
    plan = _plan([_row(1)])
    projection = _joined_projection(denominator, plan)
    receipt = classify_attention_stop(
        scope=_scope(),
        denominator=denominator,
        obligations=projection.denominator_obligations,
        roster=plan.roster,
        amendments=(),
        bindings=_stop_bindings(denominator, plan, terminal=False),
        join_projection=projection,
        closure_authority=None,
    )
    assert receipt.classification == "BOUNDED_STOP_WITH_DEBT"
    assert "ACTIVE_OR_NONTERMINAL_CHANNEL" in receipt.reason_codes


def test_cleared_capability_debt_is_retried_on_resume():
    rows = [_row(1, tool="prove")]
    denominator = _denominator(rows)
    base = _plan(rows, tools=("read",), obligations_per_channel=1)
    resumed = compile_attention_plan(
        scope=_scope(),
        denominator=denominator,
        templates=compile_channel_templates(
            denominator=denominator, obligations_per_channel=1
        ),
        budget=_budget(),
        runtime_policy=_policy(tools=("read", "prove")),
        graph_treatment_digest=H3,
        base_roster=base.roster,
        prior_denominator=denominator,
    )
    assert len(resumed.roster.channels) == 1
    assert not resumed.debt


def test_challenge_without_independent_dimensions_becomes_typed_debt():
    base = _plan([_row(1)], obligations_per_channel=1)
    origin = base.roster.channels[0]
    challenge = AttentionObligation.create(
        scope=_scope(),
        kind="CANDIDATE_CHALLENGE",
        subject_ids=(
            "COMPONENT-001",
            origin.channel_id,
            "negative-proposal",
        ),
        source_bindings=(
            SourceBinding.create("receipt:COMPONENT-001", H1),
        ),
        predecessor_receipt_digests=(H1,),
        closure_policy="independent-negative-closure",
        mandatory=True,
        impact_rank=4,
        uncertainty_class="CONFLICT",
        graph_origin="BASELINE",
        role_family="analysis",
        methodology_family="baseline",
        source_class="source",
        proof_environment="static",
        required_tool_classes=("read",),
    )
    denominator = AttentionDenominator.create(
        scope=_scope(),
        coverage_kind="EXACT",
        obligations=(challenge,),
    )
    plan = compile_attention_plan(
        scope=_scope(),
        denominator=denominator,
        templates=compile_channel_templates(
            denominator=denominator, obligations_per_channel=1
        ),
        budget=_budget(),
        runtime_policy=_policy(),
        graph_treatment_digest=H3,
        prior_channels=(origin,),
    )
    assert not plan.roster.channels
    assert [row.reason_code for row in plan.debt] == [
        "NO_ADMISSIBLE_INDEPENDENT_CHANNEL"
    ]


def test_noop_amendment_is_rejected():
    base = _plan([_row(1)], obligations_per_channel=1)
    with pytest.raises(ValueError, match="no-op"):
        compile_roster_amendment(
            base_roster=base.roster,
            prior_amendments=(),
            denominator=_denominator([_row(1)]),
            plan=compile_attention_plan(
                scope=_scope(),
                denominator=_denominator([_row(1)]),
                templates=compile_channel_templates(
                    denominator=_denominator([_row(1)])
                ),
                budget=_budget(),
                runtime_policy=_policy(),
                graph_treatment_digest=H3,
                base_roster=base.roster,
                prior_denominator=_denominator([_row(1)]),
            ),
            triggering_event_digest=H2,
        )


def test_public_compiler_artifacts_round_trip_closed_json():
    denominator = _denominator([_row(1)])
    plan = _plan([_row(1)])
    assert type(denominator).from_json(denominator.to_json()) == denominator
    assert type(plan.roster).from_json(plan.roster.to_json()) == plan.roster
    assert type(plan).from_json(plan.to_json()) == plan
    bindings = _stop_bindings(denominator, plan)
    assert type(bindings).from_json(bindings.to_json()) == bindings
    worker = WorkerReceipt.create(
        sequence=1,
        channel_id=plan.roster.channels[0].channel_id,
        obligation_id="COMPONENT-001",
        disposition="EVIDENCE_PROPOSED",
        output_digest=H1,
    )
    genesis_authority = _genesis(denominator, plan.roster)
    accepted = _accepted(plan.roster, (worker,))[0]
    assert (
        AttentionGenesisAuthority.from_json(
            genesis_authority.to_json()
        )
        == genesis_authority
    )
    assert (
        AcceptedEvidenceReceipt.from_json(accepted.to_json())
        == accepted
    )
    joined = apply_attention_receipts(
        scope=_scope(),
        obligations=denominator.obligations,
        roster=plan.roster,
        accepted_receipts=(accepted,),
        genesis_authority=genesis_authority,
    )
    assert type(joined).from_json(joined.to_json()) == joined


def test_continuation_requires_exact_parent_projection():
    denominator = _denominator([_row(1)])
    plan = _plan([_row(1)])
    with pytest.raises(ValueError, match="genesis|prior_projection"):
        apply_attention_receipts(
            scope=_scope(),
            obligations=denominator.obligations,
            roster=plan.roster,
            accepted_receipts=(),
        )
    genesis = apply_attention_receipts(
        scope=_scope(),
        obligations=denominator.obligations,
        roster=plan.roster,
        accepted_receipts=(),
        genesis_authority=_genesis(denominator, plan.roster),
    )
    continued = apply_attention_receipts(
        scope=_scope(),
        obligations=genesis.obligations,
        roster=plan.roster,
        accepted_receipts=(),
        prior_projection=genesis,
    )
    assert continued.candidate_union == genesis.candidate_union


def test_negative_challenge_enters_exact_join_denominator_and_blocks_authority():
    denominator = _denominator([_row(1)])
    plan = _plan([_row(1)], obligations_per_channel=1)
    negative = WorkerReceipt.create(
        sequence=1,
        attempt=1,
        channel_id=plan.roster.channels[0].channel_id,
        obligation_id="COMPONENT-001",
        disposition="NO_EVIDENCE_WITH_TRACE",
        output_digest=H1,
    )
    projection = apply_attention_receipts(
        scope=_scope(),
        obligations=denominator.obligations,
        roster=plan.roster,
        accepted_receipts=_accepted(plan.roster, (negative,)),
        genesis_authority=_genesis(denominator, plan.roster),
    )
    assert {
        row.kind for row in projection.denominator_obligations
    } == {"COMPONENT", "CANDIDATE_CHALLENGE"}
    with pytest.raises(ValueError, match="challenge|EVIDENCED"):
        AttentionClosureAuthority.create(
            scope=_scope(),
            denominator=denominator,
            join_projection=projection,
            stop_bindings=_stop_bindings(denominator, plan),
            roster=plan.roster,
            amendments=(),
            closure_policy_parents=_policy_parents(projection),
        )


def test_public_central_string_and_direct_replace_cannot_stop_clean():
    denominator = _denominator([_row(1)])
    plan = _plan([_row(1)])
    projection = _joined_projection(denominator, plan)
    evidenced = projection.obligations[0]
    with pytest.raises(ValueError, match="closure_authority"):
        transition_obligation(
            evidenced,
            "CLOSED",
            authority_class="CENTRAL_CLOSURE",
        )
    authority = AttentionClosureAuthority.create(
        scope=_scope(),
        denominator=denominator,
        join_projection=projection,
        stop_bindings=_stop_bindings(denominator, plan),
        roster=plan.roster,
        amendments=(),
        closure_policy_parents=_policy_parents(projection),
    )
    forged = (replace(evidenced, state="CLOSED"),)
    receipt = classify_attention_stop(
        scope=_scope(),
        denominator=denominator,
        obligations=forged,
        roster=plan.roster,
        amendments=(),
        bindings=_stop_bindings(denominator, plan),
        join_projection=projection,
        closure_authority=authority,
    )
    assert receipt.classification == "HALT"


def test_receipt_sequence_is_scoped_by_channel_and_current_attempt():
    denominator = _denominator([_row(1), _row(2)])
    plan = _plan(
        [_row(1), _row(2)], obligations_per_channel=1
    )
    channel_by_obligation = {
        obligation_id: channel
        for channel in plan.roster.channels
        for obligation_id in channel.obligation_ids
    }
    first = WorkerReceipt.create(
        sequence=1,
        attempt=1,
        channel_id=channel_by_obligation[
            "COMPONENT-001"
        ].channel_id,
        obligation_id="COMPONENT-001",
        disposition="EVIDENCE_PROPOSED",
        output_digest=H1,
    )
    second = WorkerReceipt.create(
        sequence=1,
        attempt=1,
        channel_id=channel_by_obligation[
            "COMPONENT-002"
        ].channel_id,
        obligation_id="COMPONENT-002",
        disposition="EVIDENCE_PROPOSED",
        output_digest=H2,
    )
    applied = apply_attention_receipts(
        scope=_scope(),
        obligations=denominator.obligations,
        roster=plan.roster,
        accepted_receipts=_accepted(
            plan.roster, (first, second)
        ),
        genesis_authority=_genesis(denominator, plan.roster),
    )
    assert {row.state for row in applied.obligations} == {"EVIDENCED"}
    later_attempt = WorkerReceipt.create(
        sequence=1,
        attempt=2,
        channel_id=channel_by_obligation[
            "COMPONENT-001"
        ].channel_id,
        obligation_id="COMPONENT-001",
        disposition="EVIDENCE_PROPOSED",
        output_digest=H3,
    )
    with pytest.raises(ValueError, match="attempt|lease"):
        apply_attention_receipts(
            scope=_scope(),
            obligations=denominator.obligations,
            roster=plan.roster,
            accepted_receipts=(
                *_accepted(plan.roster, (first,)),
                *_accepted(plan.roster, (later_attempt,)),
            ),
            genesis_authority=_genesis(denominator, plan.roster),
        )


def test_resume_requires_prior_denominator_and_retries_cap_debt():
    rows = [_row(1)]
    denominator = _denominator(rows)
    capped = _plan(
        rows,
        channels=0,
        attention_units=0,
        obligations_per_channel=1,
    )
    with pytest.raises(ValueError, match="prior_denominator"):
        compile_attention_plan(
            scope=_scope(),
            denominator=denominator,
            templates=compile_channel_templates(
                denominator=denominator, obligations_per_channel=1
            ),
            budget=_budget(),
            runtime_policy=_policy(),
            graph_treatment_digest=H3,
            base_roster=capped.roster,
        )
    with pytest.raises(ValueError, match="exact base roster parent"):
        compile_attention_plan(
            scope=_scope(),
            denominator=denominator,
            templates=compile_channel_templates(
                denominator=denominator, obligations_per_channel=1
            ),
            budget=_budget(),
            runtime_policy=_policy(),
            graph_treatment_digest=H3,
            base_roster=capped.roster,
            prior_denominator=_denominator([_row(2)]),
        )
    resumed = compile_attention_plan(
        scope=_scope(),
        denominator=denominator,
        templates=compile_channel_templates(
            denominator=denominator, obligations_per_channel=1
        ),
        budget=_budget(channels=1, attention_units=1),
        runtime_policy=_policy(),
        graph_treatment_digest=H3,
        base_roster=capped.roster,
        prior_denominator=denominator,
    )
    assert len(resumed.roster.channels) == 1


def test_stop_rejects_same_id_denominator_row_and_source_swap():
    denominator = _denominator([_row(1)])
    plan = _plan([_row(1)])
    projection, bindings, authority, closed = _close_with_authority(
        denominator, plan
    )
    swapped = _denominator(
        [{**_row(1), "artifact_sha256": H2}]
    )
    forged_denominator = replace(
        denominator,
        obligations=swapped.obligations,
    )
    receipt = classify_attention_stop(
        scope=_scope(),
        denominator=forged_denominator,
        obligations=closed,
        roster=plan.roster,
        amendments=(),
        bindings=bindings,
        join_projection=projection,
        closure_authority=authority,
    )
    assert receipt.classification == "HALT"
    assert {
        "DENOMINATOR_INVALID",
        "DENOMINATOR_ROW_BINDING_MISMATCH",
    } & set(receipt.reason_codes)


def test_resume_retries_no_template_debt_when_template_appears():
    denominator = _denominator([_row(1)])
    base = compile_attention_plan(
        scope=_scope(),
        denominator=denominator,
        templates=(),
        budget=_budget(),
        runtime_policy=_policy(),
        graph_treatment_digest=H3,
    )
    assert [row.reason_code for row in base.debt] == [
        "NO_ADMISSIBLE_TEMPLATE"
    ]
    resumed = compile_attention_plan(
        scope=_scope(),
        denominator=denominator,
        templates=compile_channel_templates(
            denominator=denominator, obligations_per_channel=1
        ),
        budget=_budget(),
        runtime_policy=_policy(),
        graph_treatment_digest=H3,
        base_roster=base.roster,
        prior_denominator=denominator,
    )
    assert len(resumed.roster.channels) == 1
    assert not resumed.debt


def test_amendment_rejects_runtime_variants_with_same_semantic_channel():
    denominator = _denominator([_row(1)])
    alpha = _plan([_row(1)], backend="alpha", obligations_per_channel=1)
    beta = _plan([_row(1)], backend="beta", obligations_per_channel=1)
    assert (
        alpha.roster.channels[0].channel_semantic_id
        == beta.roster.channels[0].channel_semantic_id
    )
    with pytest.raises(ValueError, match="semantic"):
        RosterAmendment.create(
            sequence=1,
            prior_effective_roster_digest=H1,
            triggering_event_digest=H2,
            obligation_operations=(
                AmendmentObligationOperation.create(
                    operation="NEW",
                    obligation_id=(
                        denominator.obligations[0].obligation_id
                    ),
                    resulting_row_digest=(
                        denominator.obligations[0].row_digest
                    ),
                ),
            ),
            new_channels=(
                alpha.roster.channels[0],
                beta.roster.channels[0],
            ),
            uncovered_debt=(),
        )


def test_recomputed_noncanonical_plan_and_terminal_rows_fail_replay():
    denominator = _denominator([_row(1)])
    plan = _plan([_row(1)])
    forged_plan = plan.to_dict()
    forged_plan["unscheduled_obligation_ids"] = ["COMPONENT-999"]
    forged_plan["plan_digest"] = digest_json(
        {
            "schema_version": forged_plan["schema_version"],
            "denominator_digest": forged_plan["denominator_digest"],
            "roster_digest": plan.roster.roster_digest,
            "debt_digests": [
                row.debt_digest for row in plan.debt
            ],
            "unscheduled_obligation_ids": ["COMPONENT-999"],
            "total_reserved_attention_units": (
                forged_plan["total_reserved_attention_units"]
            ),
            "total_reserved_channels": (
                forged_plan["total_reserved_channels"]
            ),
        }
    )
    with pytest.raises(ValueError, match="unscheduled"):
        AttentionPlan.from_dict(forged_plan)

    bindings = _stop_bindings(denominator, plan)
    forged_bindings = bindings.to_dict()
    forged_bindings["terminal_receipts"].append(
        dict(forged_bindings["terminal_receipts"][0])
    )
    binding_payload = dict(forged_bindings)
    binding_payload.pop("bindings_digest")
    forged_bindings["bindings_digest"] = digest_json(binding_payload)
    with pytest.raises(ValueError, match="terminal receipts.*unique"):
        AttentionStopBindings.from_dict(forged_bindings)


def test_recomputed_duplicate_closure_rows_fail_replay():
    denominator = _denominator([_row(1)])
    plan = _plan([_row(1)])
    _projection, _bindings, authority, _closed = (
        _close_with_authority(denominator, plan)
    )
    forged = authority.to_dict()
    forged["authorized_obligation_rows"].append(
        list(forged["authorized_obligation_rows"][0])
    )
    payload = dict(forged)
    payload.pop("authority_digest")
    forged["authority_digest"] = digest_json(payload)
    with pytest.raises(ValueError, match="canonical and unique"):
        AttentionClosureAuthority.from_dict(forged)


def test_stop_requires_unique_exact_join_denominator_rows():
    denominator = _denominator([_row(1)])
    plan = _plan([_row(1)])
    projection, bindings, authority, closed = _close_with_authority(
        denominator, plan
    )
    receipt = classify_attention_stop(
        scope=_scope(),
        denominator=denominator,
        obligations=(*closed, *closed),
        roster=plan.roster,
        amendments=(),
        bindings=bindings,
        join_projection=projection,
        closure_authority=authority,
    )
    assert receipt.classification == "HALT"
    assert "STOP_DUPLICATE_OBLIGATION" in receipt.reason_codes


def test_retained_challenge_disposal_extends_denominator_before_clean_stop():
    base_denominator = _denominator([_row(1)])
    base_plan = _plan([_row(1)], obligations_per_channel=1)
    base_channel = base_plan.roster.channels[0]
    negative = WorkerReceipt.create(
        sequence=1,
        channel_id=base_channel.channel_id,
        obligation_id="COMPONENT-001",
        disposition="NO_EVIDENCE_WITH_TRACE",
        output_digest=H1,
    )
    disputed = apply_attention_receipts(
        scope=_scope(),
        obligations=base_denominator.obligations,
        roster=base_plan.roster,
        accepted_receipts=_accepted(
            base_plan.roster, (negative,)
        ),
        genesis_authority=_genesis(
            base_denominator, base_plan.roster
        ),
    )
    extended_denominator = AttentionDenominator.create(
        scope=_scope(),
        coverage_kind="EXACT",
        obligations=disputed.denominator_obligations,
    )
    challenge_plan = compile_attention_plan(
        scope=_scope(),
        denominator=extended_denominator,
        templates=compile_channel_templates(
            denominator=extended_denominator,
            obligations_per_channel=1,
        ),
        budget=_budget(),
        runtime_policy=_policy(),
        graph_treatment_digest=H3,
        base_roster=base_plan.roster,
        prior_denominator=base_denominator,
    )
    amendment = compile_roster_amendment(
        base_roster=base_plan.roster,
        prior_amendments=(),
        denominator=extended_denominator,
        plan=challenge_plan,
        triggering_event_digest=H2,
        prior_denominator=base_denominator,
    )
    challenge = next(
        row
        for row in disputed.denominator_obligations
        if row.kind == "CANDIDATE_CHALLENGE"
    )
    resolved_workers = (
        WorkerReceipt.create(
            sequence=1,
            attempt=2,
            channel_id=base_channel.channel_id,
            obligation_id="COMPONENT-001",
            disposition="EVIDENCE_PROPOSED",
            output_digest=H2,
            evidence_ids=("EVIDENCE-BASE",),
        ),
        WorkerReceipt.create(
            sequence=1,
            channel_id=amendment.new_channels[0].channel_id,
            obligation_id=challenge.obligation_id,
            disposition="EVIDENCE_PROPOSED",
            output_digest=H3,
            evidence_ids=("EVIDENCE-CHALLENGE",),
        ),
    )
    resolved = apply_attention_receipts(
        scope=_scope(),
        obligations=disputed.denominator_obligations,
        roster=base_plan.roster,
        amendments=(amendment,),
        accepted_receipts=_accepted(
            base_plan.roster,
            resolved_workers,
            (amendment,),
        ),
        prior_projection=disputed,
    )
    channels = (
        *base_plan.roster.channels,
        *amendment.new_channels,
    )
    bindings = AttentionStopBindings.create(
        scope=_scope(),
        denominator=extended_denominator,
        effective_roster_digest_value=effective_roster_digest(
            base_plan.roster, (amendment,)
        ),
        terminal_receipts=(
            ChannelTerminalReceipt.create(
                channel=channel,
                terminal_state="COMMITTED",
                output_digest=(
                    H2
                    if channel.channel_id == base_channel.channel_id
                    else H3
                ),
            )
            for channel in channels
        ),
        joined_channel_ids=(
            channel.channel_id for channel in channels
        ),
        reconciled_obligation_ids=(
            row.obligation_id
            for row in resolved.denominator_obligations
        ),
        prior_candidate_union=disputed.candidate_union,
        candidate_union=resolved.candidate_union,
        prior_evidence_union=disputed.evidence_union,
        evidence_union=resolved.evidence_union,
        prior_alias_map=disputed.alias_map_dict(),
        alias_map=resolved.alias_map_dict(),
    )
    authority = AttentionClosureAuthority.create(
        scope=_scope(),
        denominator=extended_denominator,
        join_projection=resolved,
        stop_bindings=bindings,
        roster=base_plan.roster,
        amendments=(amendment,),
        closure_policy_parents=_policy_parents(resolved),
    )
    closed = tuple(
        transition_obligation(
            row, "CLOSED", closure_authority=authority
        )
        for row in resolved.denominator_obligations
    )
    stop = classify_attention_stop(
        scope=_scope(),
        denominator=extended_denominator,
        obligations=closed,
        roster=base_plan.roster,
        amendments=(amendment,),
        bindings=bindings,
        join_projection=resolved,
        closure_authority=authority,
    )
    assert stop.classification == "CLEAN_STOP"


def test_unrostered_worker_receipt_cannot_supply_clean_closure_evidence():
    denominator = _denominator([_row(1)])
    plan = _plan([_row(1)], obligations_per_channel=1)
    foreign_plan = _plan([_row(2)], obligations_per_channel=1)
    foreign_worker = WorkerReceipt.create(
        sequence=1,
        attempt=1,
        channel_id=foreign_plan.roster.channels[0].channel_id,
        obligation_id="COMPONENT-001",
        disposition="EVIDENCE_PROPOSED",
        output_digest=H1,
    )
    with pytest.raises(ValueError, match="roster|channel|accepted"):
        apply_attention_receipts(
            scope=_scope(),
            obligations=denominator.obligations,
            roster=plan.roster,
            accepted_receipts=_accepted(
                foreign_plan.roster, (foreign_worker,)
            ),
            genesis_authority=_genesis(denominator, plan.roster),
        )


def test_retained_negative_requires_an_exact_challenge_denominator_row():
    from adaptive_attention_types import AttentionJoinProjection

    denominator = _denominator([_row(1)])
    evidenced = transition_obligation(
        transition_obligation(
            denominator.obligations[0], "ASSIGNED"
        ),
        "EVIDENCED",
    )
    with pytest.raises(ValueError, match="negative.*challenge|challenge.*negative"):
        AttentionJoinProjection.create(
            obligations=(evidenced,),
            challenge_obligations=(),
            candidate_union=(),
            evidence_union=(),
            alias_map={},
            retained_negative_proposal_ids=("COMPONENT-001",),
        )


def test_join_projection_rejects_duplicate_rows_before_count_contraction():
    from adaptive_attention_types import AttentionJoinProjection

    row = _denominator([_row(1)]).obligations[0]
    with pytest.raises(ValueError, match="duplicate"):
        AttentionJoinProjection.create(
            obligations=(row, row),
            challenge_obligations=(),
            candidate_union=(),
            evidence_union=(),
            alias_map={},
            retained_negative_proposal_ids=(),
        )


def test_retry_and_reopen_are_typed_amendment_operations():
    capability_row = _row(1, tool="prove")
    denominator = _denominator([capability_row])
    base = _plan(
        [capability_row],
        tools=("read",),
        obligations_per_channel=1,
    )
    retry = compile_attention_plan(
        scope=_scope(),
        denominator=denominator,
        templates=compile_channel_templates(
            denominator=denominator, obligations_per_channel=1
        ),
        budget=_budget(),
        runtime_policy=_policy(tools=("read", "prove")),
        graph_treatment_digest=H3,
        base_roster=base.roster,
        prior_denominator=denominator,
    )
    amendment = compile_roster_amendment(
        base_roster=base.roster,
        prior_amendments=(),
        denominator=denominator,
        plan=retry,
        triggering_event_digest=H2,
        prior_denominator=denominator,
    )
    assert {
        operation.operation for operation in amendment.obligation_operations
    } == {"RETRY"}
    active_channels, active_debt, active_rows = (
        effective_roster_material(base.roster, (amendment,))
    )
    assert not active_debt
    assert {
        obligation_id
        for channel in active_channels
        for obligation_id in channel.obligation_ids
    } == {"COMPONENT-001"}
    assert active_rows == base.roster.denominator_obligation_rows

    old_row = _row(2)
    old_denominator = _denominator([old_row])
    old_plan = _plan([old_row], obligations_per_channel=1)
    changed_denominator = _denominator(
        [{**old_row, "artifact_sha256": H3}]
    )
    reopened = compile_attention_plan(
        scope=_scope(),
        denominator=changed_denominator,
        templates=compile_channel_templates(
            denominator=changed_denominator,
            obligations_per_channel=1,
        ),
        budget=_budget(),
        runtime_policy=_policy(),
        graph_treatment_digest=H3,
        base_roster=old_plan.roster,
        prior_denominator=old_denominator,
    )
    amendment = compile_roster_amendment(
        base_roster=old_plan.roster,
        prior_amendments=(),
        denominator=changed_denominator,
        plan=reopened,
        triggering_event_digest=H2,
        prior_denominator=old_denominator,
    )
    assert {
        operation.operation for operation in amendment.obligation_operations
    } == {"REOPEN"}


def test_receipt_sequence_must_start_at_one_for_current_attempt():
    denominator = _denominator([_row(1)])
    plan = _plan([_row(1)], obligations_per_channel=1)
    channel = plan.roster.channels[0]
    terminal = ChannelTerminalReceipt.create(
        channel=channel,
        terminal_state="COMMITTED",
        output_digest=H1,
    )
    authority = ChannelAttemptAuthority.create(
        scope=_scope(),
        effective_roster_digest_value=effective_roster_digest(
            plan.roster, ()
        ),
        channel=channel,
        current_attempt=7,
        lease_id="LEASE-SEQUENCE-GAP",
        phase_io_commit_digest=H2,
        transaction_commit_digest=H3,
        terminal_receipt=terminal,
    )
    with pytest.raises(ValueError, match="sequence|attempt"):
        AcceptedEvidenceReceipt.create(
            attempt_authority=authority,
            worker_receipt=WorkerReceipt.create(
                sequence=99,
                attempt=7,
                channel_id=channel.channel_id,
                obligation_id="COMPONENT-001",
                disposition="EVIDENCE_PROPOSED",
                output_digest=H1,
            ),
        )


def test_disposition_is_exact_and_never_drops_embedded_candidate_identity():
    denominator = _denominator([_row(1)])
    with pytest.raises(ValueError, match="disposition"):
        WorkerReceipt.create(
            sequence=1,
            channel_id="ACH-FIXTURE-1",
            obligation_id="COMPONENT-001",
            disposition="CANDIDATE_PROPOSED_UNSAFE",
            output_digest=H1,
            candidate_ids=("CANDIDATE-MUST-NOT-VANISH",),
        )


def test_budget_policy_is_bound_even_when_selected_work_is_identical():
    small = _plan(
        [_row(1)],
        channels=1,
        attention_units=1,
        obligations_per_channel=1,
    )
    large = _plan(
        [_row(1)],
        channels=96,
        attention_units=128,
        obligations_per_channel=1,
    )
    assert small.plan_digest != large.plan_digest
    assert small.roster.roster_digest != large.roster.roster_digest


def test_channel_reservation_never_exceeds_runtime_capability_ceiling():
    denominator = _denominator([_row(1)])
    policy = RuntimeCapabilityPolicy.create(
        backend_family="alpha",
        provider_family="alpha-provider",
        model_capability_tier="standard",
        allowed_tool_classes=("read",),
        context_floor=32_768,
        output_ceiling=2_048,
    )
    plan = compile_attention_plan(
        scope=_scope(),
        denominator=denominator,
        templates=compile_channel_templates(
            denominator=denominator, obligations_per_channel=1
        ),
        budget=_budget(),
        runtime_policy=policy,
        graph_treatment_digest=H3,
    )
    reservation = plan.roster.channels[0].resource_reservation
    assert reservation.max_input_tokens <= policy.context_floor
    assert reservation.max_output_tokens <= policy.output_ceiling


def test_genesis_authority_cannot_be_rebound_to_an_identical_work_roster():
    denominator = _denominator([_row(1)])
    small = _plan(
        [_row(1)],
        channels=1,
        attention_units=1,
        obligations_per_channel=1,
    )
    large = _plan(
        [_row(1)],
        channels=96,
        attention_units=128,
        obligations_per_channel=1,
    )
    assert (
        small.roster.denominator_obligation_rows
        == large.roster.denominator_obligation_rows
    )
    with pytest.raises(ValueError, match="genesis authority"):
        apply_attention_receipts(
            scope=_scope(),
            obligations=denominator.obligations,
            roster=large.roster,
            accepted_receipts=(),
            genesis_authority=_genesis(
                denominator, small.roster
            ),
        )


def test_accepted_evidence_requires_the_committed_transaction_output():
    plan = _plan([_row(1)], obligations_per_channel=1)
    channel = plan.roster.channels[0]
    terminal = ChannelTerminalReceipt.create(
        channel=channel,
        terminal_state="COMMITTED",
        output_digest=H1,
    )
    authority = ChannelAttemptAuthority.create(
        scope=_scope(),
        effective_roster_digest_value=effective_roster_digest(
            plan.roster, ()
        ),
        channel=channel,
        current_attempt=1,
        lease_id="LEASE-OUTPUT-BINDING",
        phase_io_commit_digest=H2,
        transaction_commit_digest=H3,
        terminal_receipt=terminal,
    )
    with pytest.raises(ValueError, match="output"):
        AcceptedEvidenceReceipt.create(
            attempt_authority=authority,
            worker_receipt=WorkerReceipt.create(
                sequence=1,
                channel_id=channel.channel_id,
                obligation_id="COMPONENT-001",
                disposition="EVIDENCE_PROPOSED",
                output_digest=H2,
            ),
        )


def test_closure_requires_one_policy_specific_parent_per_obligation():
    denominator = _denominator([_row(1)])
    plan = _plan([_row(1)], obligations_per_channel=1)
    projection = _joined_projection(denominator, plan)
    with pytest.raises(ValueError, match="policy parent"):
        AttentionClosureAuthority.create(
            scope=_scope(),
            denominator=denominator,
            join_projection=projection,
            stop_bindings=_stop_bindings(denominator, plan),
            roster=plan.roster,
            amendments=(),
            closure_policy_parents=(),
        )
    with pytest.raises(ValueError, match="authority class"):
        ClosurePolicyParent.create(
            obligation=projection.denominator_obligations[0],
            join_projection=projection,
            authority_class="CENTRAL_NEGATIVE_CLOSURE",
            provider_receipt_digest=H3,
        )


def test_closure_terminal_must_equal_the_accepted_attempt_terminal():
    denominator = _denominator([_row(1)])
    plan = _plan([_row(1)], obligations_per_channel=1)
    projection = _joined_projection(denominator, plan)
    channel = plan.roster.channels[0]
    mismatched_bindings = AttentionStopBindings.create(
        scope=_scope(),
        denominator=denominator,
        effective_roster_digest_value=effective_roster_digest(
            plan.roster, ()
        ),
        terminal_receipts=(
            ChannelTerminalReceipt.create(
                channel=channel,
                terminal_state="COMMITTED",
                output_digest=H2,
            ),
        ),
        joined_channel_ids=(channel.channel_id,),
        reconciled_obligation_ids=("COMPONENT-001",),
    )
    with pytest.raises(ValueError, match="terminal|transaction"):
        AttentionClosureAuthority.create(
            scope=_scope(),
            denominator=denominator,
            join_projection=projection,
            stop_bindings=mismatched_bindings,
            roster=plan.roster,
            amendments=(),
            closure_policy_parents=_policy_parents(projection),
        )
