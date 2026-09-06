"""Adversarial contracts for adaptive-attention runtime authority and lineage."""
from __future__ import annotations

import pytest

import test_adaptive_attention_controller as fixture
from adaptive_attention_authority import (
    AttentionAuthorityResolution,
    AttentionLineageCommitRequest,
    AttentionLineageHead,
    evaluate_lineage_checked_commit,
)
from adaptive_attention_controller import (
    apply_attention_receipts,
    classify_attention_stop,
)
from adaptive_attention_types import (
    AdaptiveAttentionError,
    AttentionClosureAuthority,
    WorkerReceipt,
    transition_obligation,
)


class _CheckedFixtureResolver:
    """Test-only stand-in for the out-of-scope checked-commit providers."""

    def __init__(self) -> None:
        self._heads: dict[str, AttentionLineageHead] = {}
        self._committed: dict[
            str, AttentionLineageCommitRequest
        ] = {}

    def resolve_channel_attempt(self, request):
        return AttentionAuthorityResolution.authenticated(request)

    def resolve_closure_policy(self, request):
        return AttentionAuthorityResolution.authenticated(request)

    def commit_lineage(self, request):
        decision, next_head = evaluate_lineage_checked_commit(
            current_head=self._heads.get(request.lineage_id),
            committed_requests=self._committed,
            request=request,
        )
        if decision.state == "CONFLICT":
            return AttentionAuthorityResolution.debt(
                request, "ATTENTION_LINEAGE_CONFLICT"
            )
        self._heads[request.lineage_id] = next_head
        self._committed[request.request_digest] = request
        return AttentionAuthorityResolution.authenticated(request)

    def resolve_lineage(self, request):
        committed = self._committed.get(request.request_digest)
        if committed == request:
            return AttentionAuthorityResolution.authenticated(request)
        return AttentionAuthorityResolution.debt(
            request, "ATTENTION_LINEAGE_CHECKED_COMMIT_UNRESOLVED"
        )


def _one_row():
    denominator = fixture._denominator([fixture._row(1)])
    plan = fixture._plan(
        [fixture._row(1)], obligations_per_channel=1
    )
    return denominator, plan, plan.roster.channels[0]


def _worker(channel, *, attempt=1, output_digest=fixture.H1):
    return WorkerReceipt.create(
        sequence=1,
        attempt=attempt,
        channel_id=channel.channel_id,
        obligation_id="COMPONENT-001",
        disposition="EVIDENCE_PROPOSED",
        output_digest=output_digest,
    )


def test_receipt_attempt_above_typed_roster_cap_is_rejected_pretransition():
    denominator, plan, channel = _one_row()
    resolver = _CheckedFixtureResolver()
    with pytest.raises(
        AdaptiveAttentionError, match="attempt.*cap|cap.*attempt"
    ):
        apply_attention_receipts(
            scope=fixture._scope(),
            obligations=denominator.obligations,
            roster=plan.roster,
            accepted_receipts=fixture._accepted(
                plan.roster, (_worker(channel, attempt=3),)
            ),
            genesis_authority=fixture._genesis(
                denominator, plan.roster
            ),
            authority_resolver=resolver,
        )
    assert plan.roster.max_attempts_per_channel == 2
    assert denominator.obligations[0].state == "UNCOVERED"


def test_unresolved_opaque_attempt_hashes_become_explicit_debt():
    denominator, plan, channel = _one_row()
    projection = apply_attention_receipts(
        scope=fixture._scope(),
        obligations=denominator.obligations,
        roster=plan.roster,
        accepted_receipts=fixture._accepted(
            plan.roster, (_worker(channel),)
        ),
        genesis_authority=fixture._genesis(
            denominator, plan.roster
        ),
    )
    assert projection.obligations[0].state == "DEBT"
    assert projection.accepted_receipt_digests == ()
    assert set(projection.authority_debt_reason_codes) == {
        "ATTENTION_LINEAGE_CHECKED_COMMIT_UNRESOLVED",
        "PHASE_IO_COMMIT_AUTHORITY_UNRESOLVED",
        "TRANSACTION_COMMIT_AUTHORITY_UNRESOLVED",
    }


def test_unresolved_provider_receipt_cannot_preserve_clean_stop():
    denominator, plan, channel = _one_row()
    resolver = _CheckedFixtureResolver()
    projection = apply_attention_receipts(
        scope=fixture._scope(),
        obligations=denominator.obligations,
        roster=plan.roster,
        accepted_receipts=fixture._accepted(
            plan.roster, (_worker(channel),)
        ),
        genesis_authority=fixture._genesis(
            denominator, plan.roster
        ),
        authority_resolver=resolver,
    )
    bindings = fixture._stop_bindings(denominator, plan)
    closure = AttentionClosureAuthority.create(
        scope=fixture._scope(),
        denominator=denominator,
        join_projection=projection,
        stop_bindings=bindings,
        roster=plan.roster,
        amendments=(),
        closure_policy_parents=fixture._policy_parents(projection),
    )
    closed = tuple(
        transition_obligation(
            row, "CLOSED", closure_authority=closure
        )
        for row in projection.denominator_obligations
    )
    stop = classify_attention_stop(
        scope=fixture._scope(),
        denominator=denominator,
        obligations=closed,
        roster=plan.roster,
        amendments=(),
        bindings=bindings,
        join_projection=projection,
        closure_authority=closure,
    )
    assert stop.classification == "BOUNDED_STOP_WITH_DEBT"
    assert set(stop.reason_codes) >= {
        "ATTENTION_LINEAGE_CHECKED_COMMIT_UNRESOLVED",
        "PROVIDER_RECEIPT_AUTHORITY_UNRESOLVED",
    }


def test_lineage_exact_replay_is_idempotent_but_genesis_fork_is_rejected():
    denominator, plan, channel = _one_row()
    resolver = _CheckedFixtureResolver()
    genesis = fixture._genesis(denominator, plan.roster)
    first_kwargs = {
        "scope": fixture._scope(),
        "obligations": denominator.obligations,
        "roster": plan.roster,
        "accepted_receipts": fixture._accepted(
            plan.roster, (_worker(channel),)
        ),
        "genesis_authority": genesis,
        "authority_resolver": resolver,
    }
    first = apply_attention_receipts(**first_kwargs)
    assert apply_attention_receipts(**first_kwargs) == first

    conflicting = _worker(channel, output_digest=fixture.H2)
    with pytest.raises(
        AdaptiveAttentionError, match="lineage.*conflict"
    ):
        apply_attention_receipts(
            scope=fixture._scope(),
            obligations=denominator.obligations,
            roster=plan.roster,
            accepted_receipts=fixture._accepted(
                plan.roster, (conflicting,)
            ),
            genesis_authority=genesis,
            authority_resolver=resolver,
        )


def test_lineage_continuation_advances_once_and_rejects_stale_sibling():
    denominator, plan, channel = _one_row()
    resolver = _CheckedFixtureResolver()
    first = apply_attention_receipts(
        scope=fixture._scope(),
        obligations=denominator.obligations,
        roster=plan.roster,
        accepted_receipts=fixture._accepted(
            plan.roster, (_worker(channel),)
        ),
        genesis_authority=fixture._genesis(
            denominator, plan.roster
        ),
        authority_resolver=resolver,
    )
    second_worker = _worker(
        channel, attempt=2, output_digest=fixture.H2
    )
    second_kwargs = {
        "scope": fixture._scope(),
        "obligations": first.denominator_obligations,
        "roster": plan.roster,
        "accepted_receipts": fixture._accepted(
            plan.roster, (second_worker,)
        ),
        "prior_projection": first,
        "authority_resolver": resolver,
    }
    second = apply_attention_receipts(**second_kwargs)
    assert second.join_sequence == 2
    assert second.parent_join_digest == first.join_digest
    assert apply_attention_receipts(**second_kwargs) == second

    stale_sibling = _worker(
        channel, attempt=2, output_digest=fixture.H3
    )
    with pytest.raises(
        AdaptiveAttentionError, match="lineage.*conflict"
    ):
        apply_attention_receipts(
            scope=fixture._scope(),
            obligations=first.denominator_obligations,
            roster=plan.roster,
            accepted_receipts=fixture._accepted(
                plan.roster, (stale_sibling,)
            ),
            prior_projection=first,
            authority_resolver=resolver,
        )
