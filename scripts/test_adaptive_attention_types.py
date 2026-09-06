"""Fixture-first contracts for the adaptive-attention value types."""
from __future__ import annotations

from dataclasses import FrozenInstanceError
from dataclasses import replace

import pytest

from adaptive_attention_types import (
    AttentionBudget,
    AttentionObligation,
    AttentionScope,
    EvidenceChannel,
    EvidenceSlice,
    MethodologyBinding,
    ResourceReservation,
    RuntimeCapabilityPolicy,
    SourceBinding,
    channels_have_independent_evidence,
    strict_json_loads,
    validate_obligation_transition,
)


H1 = "1" * 64
H2 = "2" * 64
H3 = "3" * 64


def _scope() -> AttentionScope:
    return AttentionScope.create(
        snapshot_digest=H1,
        pipeline="analysis",
        mode="core",
        ecosystem="fixture",
        phase="breadth",
        dependency_generation=3,
        phase_graph_digest=H2,
        active_phases=("breadth", "join"),
        graph_treatment="legacy_off",
    )


def _obligation(*, subjects: tuple[str, ...] = ("component-b", "component-a")):
    return AttentionObligation.create(
        scope=_scope(),
        kind="COMPONENT",
        subject_ids=subjects,
        source_bindings=(
            SourceBinding.create("scratchpad:components-b.json", H2),
            SourceBinding.create("scratchpad:components-a.json", H1),
        ),
        methodology_bindings=(
            MethodologyBinding.create(
                method_path="methods/review.md",
                file_digest=H3,
                step_id="step-2",
                step_text_digest=H2,
                application_authority_id="MAO-STEP-2",
            ),
        ),
        predecessor_receipt_digests=(H3, H2),
        closure_policy="driver-evidence-closure",
        mandatory=True,
        impact_rank=3,
        uncertainty_class="NONE",
        graph_origin="BASELINE",
        role_family="analysis",
        methodology_family="review",
        source_class="source",
        proof_environment="static",
        required_tool_classes=("read",),
        dependency_fanout=2,
    )


def test_obligation_identity_is_order_independent_and_rows_are_frozen():
    left = _obligation()
    right = AttentionObligation.create(
        scope=_scope(),
        kind="COMPONENT",
        subject_ids=("component-a", "component-b"),
        source_bindings=tuple(reversed(left.source_bindings)),
        methodology_bindings=left.methodology_bindings,
        predecessor_receipt_digests=tuple(
            reversed(left.predecessor_receipt_digests)
        ),
        closure_policy=left.closure_policy,
        mandatory=True,
        impact_rank=3,
        uncertainty_class="NONE",
        graph_origin="BASELINE",
        role_family="analysis",
        methodology_family="review",
        source_class="source",
        proof_environment="static",
        required_tool_classes=("read",),
        dependency_fanout=2,
    )
    assert left.obligation_id == right.obligation_id
    assert left.row_digest == right.row_digest
    assert left.to_dict() == right.to_dict()
    with pytest.raises(FrozenInstanceError):
        left.state = "CLOSED"  # type: ignore[misc]


def test_existing_canonical_identity_is_preserved_but_bound_row_is_validated():
    row = AttentionObligation.create(
        scope=_scope(),
        canonical_id="MAO-EXACT-7",
        kind="METHOD_STEP",
        subject_ids=("step-7",),
        source_bindings=(SourceBinding.create("method:catalog", H1),),
        closure_policy="application-receipt",
        mandatory=True,
        impact_rank=2,
    )
    assert row.obligation_id == "MAO-EXACT-7"
    assert AttentionObligation.from_json(row.to_json()) == row
    with pytest.raises(ValueError, match="row_digest"):
        changed = row.to_dict()
        changed["mandatory"] = False
        AttentionObligation.from_dict(changed)


def test_strict_json_and_worker_state_transition_rules():
    with pytest.raises(ValueError, match="duplicate JSON object key"):
        strict_json_loads('{"schema":"x","schema":"y"}')
    assert validate_obligation_transition("UNCOVERED", "ASSIGNED")
    with pytest.raises(ValueError, match="closure_authority"):
        validate_obligation_transition(
            "EVIDENCED",
            "CLOSED",
            authority_class="CENTRAL_CLOSURE",
        )
    with pytest.raises(ValueError, match="worker"):
        validate_obligation_transition(
            "EVIDENCED", "CLOSED", authority_class="WORKER"
        )
    with pytest.raises(ValueError, match="invalid obligation transition"):
        validate_obligation_transition("UNCOVERED", "CLOSED")
    with pytest.raises(ValueError, match="closure_authority"):
        validate_obligation_transition(
            "CLOSED",
            "CLOSED",
            authority_class="CENTRAL_CLOSURE",
        )


def test_semantic_channel_identity_and_reservation_are_backend_neutral():
    obligation = _obligation()
    evidence_slice = EvidenceSlice.create(
        scope=_scope(),
        source_bindings=obligation.source_bindings,
        subject_ids=obligation.subject_ids,
        method_step_ids=("step-2",),
        graph_marker="GRAPH_OFF",
        predecessor_receipt_digests=(H3,),
        permitted_tool_classes=("read",),
        max_prompt_projection_digest=H1,
    )
    reservation = ResourceReservation.model_channel(attention_units=1)
    common = dict(
        scope=_scope(),
        obligation_ids=(obligation.obligation_id,),
        evidence_slice=evidence_slice,
        role_id="component-review",
        role_family="analysis",
        source_class="source",
        methodology_bindings=obligation.methodology_bindings,
        graph_treatment_digest=H2,
        independence_signature=(
            "analysis",
            "review",
            "source",
            "static",
            evidence_slice.slice_id,
        ),
        resource_reservation=reservation,
        prerequisite_ids=(),
    )
    alpha = EvidenceChannel.create(
        **common,
        runtime_policy=RuntimeCapabilityPolicy.create(
            backend_family="alpha",
            provider_family="provider-a",
            model_capability_tier="standard",
            allowed_tool_classes=("read",),
        ),
    )
    beta = EvidenceChannel.create(
        **common,
        runtime_policy=RuntimeCapabilityPolicy.create(
            backend_family="beta",
            provider_family="provider-b",
            model_capability_tier="standard",
            allowed_tool_classes=("read",),
        ),
    )
    assert alpha.channel_semantic_id == beta.channel_semantic_id
    assert alpha.semantic_view() == beta.semantic_view()
    assert alpha.channel_id != beta.channel_id
    assert alpha.resource_reservation == beta.resource_reservation
    assert EvidenceChannel.from_dict(alpha.to_dict()) == alpha
    stale = alpha.to_dict()
    stale["resource_reservation"]["attention_units"] = 2
    with pytest.raises(ValueError):
        EvidenceChannel.from_dict(stale)
    duplicate_obligation = replace(
        alpha,
        obligation_ids=(
            obligation.obligation_id,
            obligation.obligation_id,
        ),
    )
    with pytest.raises(ValueError, match="unique"):
        EvidenceChannel.from_dict(duplicate_obligation.to_dict())


def test_independence_requires_distinct_slice_and_two_dimensions():
    obligation = _obligation()
    policy = RuntimeCapabilityPolicy.create(
        backend_family="alpha",
        provider_family="provider-a",
        model_capability_tier="standard",
        allowed_tool_classes=("read", "prove"),
    )
    reservation = ResourceReservation.model_channel(attention_units=1)

    def channel(
        subject: str,
        *,
        role: str,
        methodology: str,
        source: str,
        proof: str,
    ) -> EvidenceChannel:
        evidence_slice = EvidenceSlice.create(
            scope=_scope(),
            source_bindings=obligation.source_bindings,
            subject_ids=(subject,),
            method_step_ids=(methodology,),
            graph_marker="GRAPH_OFF",
            predecessor_receipt_digests=(),
            permitted_tool_classes=("read",),
            max_prompt_projection_digest=H1,
        )
        return EvidenceChannel.create(
            scope=_scope(),
            obligation_ids=(obligation.obligation_id,),
            evidence_slice=evidence_slice,
            role_id=role,
            role_family=role,
            source_class=source,
            methodology_bindings=(),
            graph_treatment_digest=H2,
            runtime_policy=policy,
            independence_signature=(
                role,
                methodology,
                source,
                proof,
                evidence_slice.slice_id,
            ),
            resource_reservation=reservation,
            prerequisite_ids=(),
        )

    baseline = channel(
        "component-a",
        role="analysis",
        methodology="review",
        source="source",
        proof="static",
    )
    one_difference = channel(
        "component-c",
        role="challenge",
        methodology="review",
        source="source",
        proof="static",
    )
    independent = channel(
        "component-d",
        role="challenge",
        methodology="proof",
        source="source",
        proof="static",
    )
    assert not channels_have_independent_evidence(baseline, baseline)
    assert not channels_have_independent_evidence(baseline, one_difference)
    assert channels_have_independent_evidence(baseline, independent)


def test_budget_separates_semantic_caps_from_concurrency():
    low = AttentionBudget.create(
        max_total_channels=7,
        max_attention_units=9,
        max_concurrency=1,
        max_attempts_per_channel=2,
    )
    high = AttentionBudget.create(
        max_total_channels=7,
        max_attention_units=9,
        max_concurrency=4,
        max_attempts_per_channel=2,
    )
    assert low.semantic_view() == high.semantic_view()
    assert low.budget_digest != high.budget_digest


def test_graph_treatment_and_public_replay_are_strict_and_noncoercive():
    with pytest.raises(ValueError, match="graph_treatment"):
        AttentionScope.create(
            snapshot_digest=H1,
            pipeline="analysis",
            mode="core",
            ecosystem="fixture",
            phase="breadth",
            dependency_generation=0,
            phase_graph_digest=H2,
            active_phases=("breadth",),
            graph_treatment="best-effort",
        )
    budget = AttentionBudget.create(
        max_total_channels=3,
        max_attention_units=4,
        max_concurrency=1,
        max_attempts_per_channel=2,
    )
    assert AttentionBudget.from_dict(budget.to_dict()) == budget
    coercive = budget.to_dict()
    coercive["max_total_channels"] = "3"
    with pytest.raises(ValueError, match="integer"):
        AttentionBudget.from_dict(coercive)
    extra = budget.to_dict()
    extra["caller_hint"] = True
    with pytest.raises(ValueError, match="unexpected"):
        AttentionBudget.from_dict(extra)


@pytest.mark.parametrize("state", ["EVIDENCED", "DEBT", "CLOSED"])
def test_public_obligation_creation_cannot_mint_controller_state(state):
    with pytest.raises(ValueError, match="controller-owned"):
        AttentionObligation.create(
            scope=_scope(),
            kind="COMPONENT",
            subject_ids=("component-a",),
            source_bindings=(
                SourceBinding.create("scratchpad:components.json", H1),
            ),
            closure_policy="driver-evidence-closure",
            mandatory=True,
            impact_rank=2,
            state=state,
        )


def test_denominator_and_channel_replay_reject_stale_nested_rows():
    obligation = _obligation()
    stale = replace(obligation, row_digest=H3)
    from adaptive_attention_types import AttentionDenominator

    with pytest.raises(ValueError, match="row_digest|obligation"):
        AttentionDenominator.create(
            scope=_scope(),
            coverage_kind="EXACT",
            obligations=(stale,),
        )
