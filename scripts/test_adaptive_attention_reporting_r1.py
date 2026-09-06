"""Fixture-first contracts for lossless Adaptive Attention R1 reporting."""
from __future__ import annotations

from dataclasses import replace

import pytest

import test_adaptive_attention_controller as fixture
from adaptive_attention_reporting import (
    AdaptiveAttentionReportingError,
    build_attention_reporting_artifacts,
    validate_attention_reporting_artifacts,
)
from adaptive_attention_types import (
    AttentionDebt,
    AttentionJoinProjection,
    AttentionStopReceipt,
)


def _projection(denominator):
    return AttentionJoinProjection.create(
        obligations=denominator.obligations,
        challenge_obligations=(),
        candidate_union=(),
        evidence_union=(),
        alias_map={},
        retained_negative_proposal_ids=(),
    )


def test_reporting_is_lossless_for_more_than_32_rows_and_cap_debt():
    rows = [fixture._row(index) for index in range(1, 41)]
    denominator = fixture._denominator(rows)
    plan = fixture._plan(
        rows,
        channels=1,
        attention_units=1,
        obligations_per_channel=1,
    )
    projection = _projection(denominator)
    stop = AttentionStopReceipt.create(
        classification="BOUNDED_STOP_WITH_DEBT",
        denominator_digest=denominator.denominator_digest,
        effective_roster_digest_value=plan.roster.roster_digest,
        unresolved_obligation_ids=(
            row.obligation_id for row in denominator.obligations
        ),
        reason_codes=("PHASE_CHANNEL_CAP",),
        clean_full_assurance_claim_allowed=False,
    )
    artifacts = build_attention_reporting_artifacts(
        denominator=denominator,
        roster=plan.roster,
        amendments=(),
        join_projection=projection,
        stop_receipt=stop,
        terminal_receipts=(),
        runtime_debt=(),
        usage_receipts=(),
    )
    assert artifacts.coverage.denominator_count == 40
    assert len(artifacts.debt.rows) == 40
    assert {
        row.obligation_id for row in artifacts.debt.rows
    } == {
        row.obligation_id for row in denominator.obligations
    }
    assert artifacts.assurance.clean_full_audit_claim_allowed is False
    validate_attention_reporting_artifacts(artifacts)


def test_debt_is_not_evidence_coverage_and_lower_bound_is_preserved():
    denominator = replace(
        fixture._denominator([fixture._row(1)]),
        coverage_kind="UNKNOWN",
        exact_obligation_count=None,
    )
    # Replacement is deliberately stale and must fail closed.
    with pytest.raises(AdaptiveAttentionReportingError):
        build_attention_reporting_artifacts(
            denominator=denominator,
            roster=fixture._plan([fixture._row(1)]).roster,
            amendments=(),
            join_projection=_projection(denominator),
            stop_receipt=None,
            terminal_receipts=(),
            runtime_debt=(),
            usage_receipts=(),
        )


def test_disputed_negative_is_verification_debt_and_forbids_clean_claim():
    denominator = fixture._denominator([fixture._row(1)])
    plan = fixture._plan(
        [fixture._row(1)], obligations_per_channel=1
    )
    channel = plan.roster.channels[0]
    worker = fixture.WorkerReceipt.create(
        sequence=1,
        channel_id=channel.channel_id,
        obligation_id="COMPONENT-001",
        disposition="NO_EVIDENCE_WITH_TRACE",
        output_digest=fixture.H1,
        evidence_ids=("TRACE-001",),
    )
    projection = fixture.apply_attention_receipts(
        scope=fixture._scope(),
        obligations=denominator.obligations,
        roster=plan.roster,
        accepted_receipts=fixture._accepted(plan.roster, (worker,)),
        genesis_authority=fixture._genesis(
            denominator, plan.roster
        ),
    )
    stop = AttentionStopReceipt.create(
        classification="BOUNDED_STOP_WITH_DEBT",
        denominator_digest=denominator.denominator_digest,
        effective_roster_digest_value=plan.roster.roster_digest,
        unresolved_obligation_ids=(
            row.obligation_id
            for row in projection.denominator_obligations
        ),
        reason_codes=("OBLIGATION_DISPUTED",),
        clean_full_assurance_claim_allowed=False,
    )
    artifacts = build_attention_reporting_artifacts(
        denominator=denominator,
        roster=plan.roster,
        amendments=(),
        join_projection=projection,
        stop_receipt=stop,
        terminal_receipts=projection.accepted_terminal_receipts,
        runtime_debt=(),
        usage_receipts=(),
    )
    challenge_rows = [
        row
        for row in artifacts.assurance.rows
        if row.category == "VERIFICATION_CONFIDENCE"
    ]
    assert challenge_rows
    assert artifacts.assurance.clean_full_audit_claim_allowed is False
    assert artifacts.coverage.disputed_count >= 1


def test_reporting_validator_rejects_omitted_debt_and_digest_tamper():
    denominator = fixture._denominator([fixture._row(1)])
    plan = fixture._plan(
        [fixture._row(1)], channels=0, attention_units=0
    )
    projection = _projection(denominator)
    artifacts = build_attention_reporting_artifacts(
        denominator=denominator,
        roster=plan.roster,
        amendments=(),
        join_projection=projection,
        stop_receipt=None,
        terminal_receipts=(),
        runtime_debt=(),
        usage_receipts=(),
    )
    with pytest.raises(AdaptiveAttentionReportingError):
        validate_attention_reporting_artifacts(
            replace(
                artifacts,
                debt=replace(
                    artifacts.debt,
                    rows=(),
                ),
            )
        )


def test_reporting_rejects_runtime_debt_outside_join_denominator():
    denominator = fixture._denominator([fixture._row(1)])
    plan = fixture._plan(
        [fixture._row(1)], channels=0, attention_units=0
    )
    outside = AttentionDebt.create(
        obligation_id="COMPONENT-999",
        phase="breadth",
        dependency_generation=0,
        provider="fixture",
        reason_code="EXECUTOR_FAILURE",
        clearing_condition="retry",
    )
    with pytest.raises(
        AdaptiveAttentionReportingError, match="outside"
    ):
        build_attention_reporting_artifacts(
            denominator=denominator,
            roster=plan.roster,
            amendments=(),
            join_projection=_projection(denominator),
            stop_receipt=None,
            terminal_receipts=(),
            runtime_debt=(outside,),
            usage_receipts=(),
        )


def test_global_authority_debt_reaches_debt_and_assurance_artifacts():
    denominator = fixture._denominator([fixture._row(1)])
    plan = fixture._plan(
        [fixture._row(1)], channels=0, attention_units=0
    )
    base = _projection(denominator)
    projection = AttentionJoinProjection.create(
        obligations=base.obligations,
        challenge_obligations=(),
        candidate_union=(),
        evidence_union=(),
        alias_map={},
        retained_negative_proposal_ids=(),
        authority_debt_reason_codes=(
            "ATTENTION_LINEAGE_CHECKED_COMMIT_UNRESOLVED",
        ),
    )
    artifacts = build_attention_reporting_artifacts(
        denominator=denominator,
        roster=plan.roster,
        amendments=(),
        join_projection=projection,
        stop_receipt=None,
        terminal_receipts=(),
        runtime_debt=(),
        usage_receipts=(),
    )
    assert artifacts.debt.global_reason_codes == (
        "ATTENTION_LINEAGE_CHECKED_COMMIT_UNRESOLVED",
    )
    assert artifacts.assurance.global_reason_codes == (
        "ATTENTION_LINEAGE_CHECKED_COMMIT_UNRESOLVED",
    )
    assert artifacts.assurance.clean_full_audit_claim_allowed is False
    with pytest.raises(AdaptiveAttentionReportingError):
        validate_attention_reporting_artifacts(
            replace(
                artifacts,
                telemetry=replace(
                    artifacts.telemetry,
                    artifact_digest="0" * 64,
                ),
            )
        )


def test_reporting_artifact_names_and_cross_digests_are_stable():
    denominator = fixture._denominator([fixture._row(1)])
    plan = fixture._plan(
        [fixture._row(1)], channels=0, attention_units=0
    )
    kwargs = {
        "denominator": denominator,
        "roster": plan.roster,
        "amendments": (),
        "join_projection": _projection(denominator),
        "stop_receipt": None,
        "terminal_receipts": (),
        "runtime_debt": (),
        "usage_receipts": (),
    }
    left = build_attention_reporting_artifacts(**kwargs)
    right = build_attention_reporting_artifacts(**kwargs)
    assert left == right
    assert left.filenames() == (
        "adaptive_attention_coverage.json",
        "adaptive_attention_debt.json",
        "adaptive_attention_telemetry.json",
        "adaptive_attention_assurance.json",
    )
