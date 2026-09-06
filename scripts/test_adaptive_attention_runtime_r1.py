"""Fixture-first contracts for the Adaptive Attention R1 runtime boundary."""
from __future__ import annotations

from dataclasses import replace

import pytest

import test_adaptive_attention_controller as fixture
from adaptive_attention_controller import apply_attention_receipts
from adaptive_attention_types import (
    AdaptiveAttentionError,
    AttentionDebt,
    AttentionGenesisAuthority,
    ChannelTerminalReceipt,
    digest_json,
)
from adaptive_attention_runtime import (
    AttentionChannelCancelled,
    AttentionExecutionResult,
    AttentionUsageReceipt,
    compile_backend_launch_prompt,
    compile_ready_queue,
    compile_semantic_prompt,
    compile_worker_receipts,
    execute_ready_batch,
    finalize_attention_stop,
    join_authenticated_receipts,
    normalize_worker_disposition,
    reserve_attention_runtime,
)


def _one_channel():
    denominator = fixture._denominator([fixture._row(1)])
    plan = fixture._plan(
        [fixture._row(1)], obligations_per_channel=1
    )
    return denominator, plan, plan.roster.channels[0]


def test_semantic_prompt_is_backend_and_concurrency_neutral():
    denominator, plan_alpha, channel_alpha = _one_channel()
    plan_beta = fixture._plan(
        [fixture._row(1)],
        backend="beta",
        obligations_per_channel=1,
    )
    channel_beta = plan_beta.roster.channels[0]
    alpha_prompt = compile_semantic_prompt(
        scope=fixture._scope(),
        denominator=denominator,
        channel=channel_alpha,
    )
    beta_prompt = compile_semantic_prompt(
        scope=fixture._scope(),
        denominator=denominator,
        channel=channel_beta,
    )
    alpha = compile_backend_launch_prompt(
        semantic_prompt=alpha_prompt,
        channel=channel_alpha,
        backend_family="alpha",
        adapter_instructions="Return the exact JSON artifact.",
    )
    beta = compile_backend_launch_prompt(
        semantic_prompt=beta_prompt,
        channel=channel_beta,
        backend_family="beta",
        adapter_instructions="Write only the assigned output.",
    )
    assert (
        alpha_prompt.semantic_prompt_digest
        == beta_prompt.semantic_prompt_digest
    )
    assert (
        channel_alpha.channel_semantic_id
        == channel_beta.channel_semantic_id
    )
    assert channel_alpha.channel_id != channel_beta.channel_id
    assert alpha.semantic_prompt_digest == beta.semantic_prompt_digest
    assert alpha.final_launch_prompt_digest != beta.final_launch_prompt_digest
    assert channel_alpha.obligation_ids == alpha_prompt.obligation_ids
    assert "yield" not in alpha_prompt.semantic_prompt.lower()
    assert "finding_count" not in alpha_prompt.semantic_prompt.lower()
    assert "safe" not in alpha_prompt.allowed_dispositions


@pytest.mark.parametrize(
    "raw",
    ["SAFE", "no issue", "NOT VULNERABLE", " no-issue. "],
)
def test_generic_negative_is_retained_as_disputed_not_closure(raw):
    denominator, plan, channel = _one_channel()
    normalized = normalize_worker_disposition(raw)
    assert normalized.disposition == "NO_EVIDENCE_WITH_TRACE"
    assert normalized.retained_negative_proposal is True
    receipts = compile_worker_receipts(
        channel=channel,
        attempt=1,
        output_digest=fixture.H1,
        rows=(
            {
                "obligation_id": "COMPONENT-001",
                "disposition": raw,
                "candidate_ids": (),
                "evidence_ids": ("TRACE-001",),
                "aliases": {},
            },
        ),
    )
    projection = apply_attention_receipts(
        scope=fixture._scope(),
        obligations=denominator.obligations,
        roster=plan.roster,
        accepted_receipts=fixture._accepted(plan.roster, receipts),
        genesis_authority=AttentionGenesisAuthority.create(
            scope=fixture._scope(),
            denominator=denominator,
            roster=plan.roster,
        ),
        authority_resolver=fixture._FIXTURE_AUTHORITY_RESOLVER,
    )
    assert projection.obligations[0].state == "DISPUTED"
    assert projection.retained_negative_proposal_ids == ("COMPONENT-001",)
    assert len(projection.challenge_obligations) == 1


def test_ready_queue_is_deterministic_and_concurrency_changes_only_window():
    rows = [fixture._row(index) for index in range(1, 9)]
    denominator = fixture._denominator(rows)
    plan = fixture._plan(rows, obligations_per_channel=1)
    channel_ids = tuple(
        channel.channel_id for channel in plan.roster.channels
    )
    active = (channel_ids[0],)
    queue_one = compile_ready_queue(
        roster=plan.roster,
        amendments=(),
        terminal_receipts=(),
        active_channel_ids=active,
        satisfied_prerequisite_ids=(),
        max_concurrency=1,
    )
    queue_four = compile_ready_queue(
        roster=plan.roster,
        amendments=(),
        terminal_receipts=(),
        active_channel_ids=active,
        satisfied_prerequisite_ids=(),
        max_concurrency=4,
    )
    assert queue_one.semantic_roster_digest == queue_four.semantic_roster_digest
    assert queue_one.ready_channel_ids == queue_four.ready_channel_ids
    assert len(queue_one.dispatch_channel_ids) == 0
    assert len(queue_four.dispatch_channel_ids) == 3
    assert channel_ids[0] not in queue_four.ready_channel_ids
    assert denominator.denominator_digest == plan.denominator_digest


def test_prerequisites_and_terminal_rows_fence_dispatch():
    denominator, plan, channel = _one_channel()
    prerequisite = "a" * 64
    channel = replace(
        channel,
        prerequisite_ids=(prerequisite,),
        row_digest="",
    )
    # A forged dataclass replacement must fail replay rather than becoming work.
    with pytest.raises(AdaptiveAttentionError):
        compile_ready_queue(
            roster=replace(plan.roster, channels=(channel,)),
            amendments=(),
            terminal_receipts=(),
            active_channel_ids=(),
            satisfied_prerequisite_ids=(),
            max_concurrency=1,
        )
    terminal = ChannelTerminalReceipt.create(
        channel=plan.roster.channels[0],
        terminal_state="COMMITTED",
        output_digest=fixture.H1,
    )
    queue = compile_ready_queue(
        roster=plan.roster,
        amendments=(),
        terminal_receipts=(terminal,),
        active_channel_ids=(),
        satisfied_prerequisite_ids=(),
        max_concurrency=1,
    )
    assert queue.ready_channel_ids == ()
    assert queue.terminal_channel_ids == (
        plan.roster.channels[0].channel_id,
    )


def test_resource_reservations_do_not_refund_without_typed_usage():
    _denominator, plan, _channel = _one_channel()
    reserved = reserve_attention_runtime(
        roster=plan.roster,
        amendments=(),
        usage_receipts=(),
    )
    assert reserved.refunded_attention_units == 0
    assert reserved.unrefunded_channel_ids == (
        plan.roster.channels[0].channel_id,
    )
    usage = AttentionUsageReceipt.create(
        channel=plan.roster.channels[0],
        observed_input_tokens=1,
        observed_output_tokens=1,
        observed_tool_invocations=0,
        observed_timeout_slots=0,
        provider_receipt_digest=fixture.H2,
    )
    accounted = reserve_attention_runtime(
        roster=plan.roster,
        amendments=(),
        usage_receipts=(usage,),
    )
    assert accounted.unrefunded_channel_ids == ()
    assert accounted.refunded_attention_units == 0


def test_executor_failure_is_lossless_terminal_debt():
    _denominator, plan, channel = _one_channel()
    queue = compile_ready_queue(
        roster=plan.roster,
        amendments=(),
        terminal_receipts=(),
        active_channel_ids=(),
        satisfied_prerequisite_ids=(),
        max_concurrency=1,
    )

    def fail(_channel, _prompt):
        raise RuntimeError("fixture crash")

    result = execute_ready_batch(
        scope=fixture._scope(),
        denominator=fixture._denominator([fixture._row(1)]),
        roster=plan.roster,
        amendments=(),
        queue=queue,
        executor=fail,
    )
    assert isinstance(result, AttentionExecutionResult)
    assert result.accepted_receipts == ()
    assert result.terminal_receipts[0].terminal_state == "DEBT"
    assert result.execution_debt[0].obligation_id == "COMPONENT-001"
    assert result.execution_debt[0].failed_channel_ids == (
        channel.channel_id,
    )
    assert result.execution_debt[0].consumed_attention_units == 1


def test_cancellation_is_typed_terminal_debt_not_executor_success():
    denominator, plan, _channel = _one_channel()
    queue = compile_ready_queue(
        roster=plan.roster,
        amendments=(),
        terminal_receipts=(),
        active_channel_ids=(),
        satisfied_prerequisite_ids=(),
        max_concurrency=1,
    )

    def cancel(_channel, _prompt):
        raise AttentionChannelCancelled()

    result = execute_ready_batch(
        scope=fixture._scope(),
        denominator=denominator,
        roster=plan.roster,
        amendments=(),
        queue=queue,
        executor=cancel,
    )
    assert result.terminal_receipts[0].terminal_state == "CANCELLED"
    assert result.execution_debt[0].reason_code == "USER_CANCELLED"
    assert result.execution_debt[0].consumed_attention_units == 1


def test_join_defaults_to_unresolved_authority_and_cannot_self_certify():
    denominator, plan, channel = _one_channel()
    receipts = compile_worker_receipts(
        channel=channel,
        attempt=1,
        output_digest=fixture.H1,
        rows=(
            {
                "obligation_id": "COMPONENT-001",
                "disposition": "EVIDENCE_PROPOSED",
                "candidate_ids": (),
                "evidence_ids": ("EVIDENCE-001",),
                "aliases": {},
            },
        ),
    )
    accepted = fixture._accepted(plan.roster, receipts)
    projection = join_authenticated_receipts(
        scope=fixture._scope(),
        denominator=denominator,
        roster=plan.roster,
        amendments=(),
        accepted_receipts=accepted,
        genesis_authority=fixture._genesis(
            denominator, plan.roster
        ),
    )
    assert projection.obligations[0].state == "DEBT"
    assert "TRANSACTION_COMMIT_AUTHORITY_UNRESOLVED" in (
        projection.authority_debt_reason_codes
    )


def test_negative_join_requires_amendment_before_stop():
    denominator, plan, channel = _one_channel()
    receipts = compile_worker_receipts(
        channel=channel,
        attempt=1,
        output_digest=fixture.H1,
        rows=(
            {
                "obligation_id": "COMPONENT-001",
                "disposition": "SAFE",
                "candidate_ids": (),
                "evidence_ids": ("TRACE-001",),
                "aliases": {},
            },
        ),
    )
    projection = fixture.apply_attention_receipts(
        scope=fixture._scope(),
        obligations=denominator.obligations,
        roster=plan.roster,
        accepted_receipts=fixture._accepted(plan.roster, receipts),
        genesis_authority=fixture._genesis(
            denominator, plan.roster
        ),
    )
    with pytest.raises(AdaptiveAttentionError, match="amendment"):
        finalize_attention_stop(
            scope=fixture._scope(),
            denominator=denominator,
            roster=plan.roster,
            amendments=(),
            join_projection=projection,
            terminal_receipts=projection.accepted_terminal_receipts,
            closure_authority=None,
        )


def test_unclosed_exact_join_stops_bounded_under_fail_closed_authority():
    denominator, plan, channel = _one_channel()
    receipts = compile_worker_receipts(
        channel=channel,
        attempt=1,
        output_digest=fixture.H1,
        rows=(
            {
                "obligation_id": "COMPONENT-001",
                "disposition": "EVIDENCE_PROPOSED",
                "candidate_ids": (),
                "evidence_ids": ("EVIDENCE-001",),
                "aliases": {},
            },
        ),
    )
    projection = fixture.apply_attention_receipts(
        scope=fixture._scope(),
        obligations=denominator.obligations,
        roster=plan.roster,
        accepted_receipts=fixture._accepted(plan.roster, receipts),
        genesis_authority=fixture._genesis(
            denominator, plan.roster
        ),
    )
    _bindings, stop = finalize_attention_stop(
        scope=fixture._scope(),
        denominator=denominator,
        roster=plan.roster,
        amendments=(),
        join_projection=projection,
        terminal_receipts=projection.accepted_terminal_receipts,
        closure_authority=None,
    )
    assert stop.classification == "BOUNDED_STOP_WITH_DEBT"
    assert stop.clean_full_assurance_claim_allowed is False
    assert "CLOSURE_AUTHORITY_ABSENT" in stop.reason_codes


def test_worker_receipt_compiler_rejects_omission_and_cross_channel_rows():
    _denominator, _plan, channel = _one_channel()
    with pytest.raises(AdaptiveAttentionError, match="exact obligation"):
        compile_worker_receipts(
            channel=channel,
            attempt=1,
            output_digest=fixture.H1,
            rows=(),
        )
    with pytest.raises(AdaptiveAttentionError, match="exact obligation"):
        compile_worker_receipts(
            channel=channel,
            attempt=1,
            output_digest=fixture.H1,
            rows=(
                {
                    "obligation_id": "COMPONENT-999",
                    "disposition": "BLOCKED",
                    "candidate_ids": (),
                    "evidence_ids": (),
                    "aliases": {},
                },
            ),
        )


def test_execution_result_digest_replays():
    _denominator, plan, channel = _one_channel()
    debt_terminal = ChannelTerminalReceipt.create(
        channel=channel,
        terminal_state="DEBT",
        output_digest=digest_json({"channel": channel.channel_id}),
        reason_code="EXECUTOR_FAILURE",
    )
    result = AttentionExecutionResult.create(
        effective_roster_digest=plan.roster.roster_digest,
        accepted_receipts=(),
        terminal_receipts=(debt_terminal,),
        execution_debt=(
            AttentionDebt.create(
                obligation_id="COMPONENT-001",
                phase="breadth",
                dependency_generation=0,
                provider="fixture",
                reason_code="EXECUTOR_FAILURE",
                failed_channel_ids=(channel.channel_id,),
                clearing_condition="retry",
            ),
        ),
    )
    assert AttentionExecutionResult.from_dict(result.to_dict()) == result


def test_usage_above_channel_reservation_is_rejected_even_with_valid_digest():
    _denominator, plan, channel = _one_channel()
    usage = AttentionUsageReceipt.create(
        channel=channel,
        observed_input_tokens=1,
        observed_output_tokens=1,
        observed_tool_invocations=0,
        observed_timeout_slots=0,
        provider_receipt_digest=fixture.H2,
    )
    forged_payload = usage.to_dict()
    forged_payload["observed_input_tokens"] = (
        channel.resource_reservation.max_input_tokens + 1
    )
    forged_payload["usage_digest"] = digest_json(
        {
            key: value
            for key, value in forged_payload.items()
            if key != "usage_digest"
        }
    )
    forged = AttentionUsageReceipt.from_dict(forged_payload)
    with pytest.raises(AdaptiveAttentionError, match="reservation"):
        reserve_attention_runtime(
            roster=plan.roster,
            amendments=(),
            usage_receipts=(forged,),
        )
