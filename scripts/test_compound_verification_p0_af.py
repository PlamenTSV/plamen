"""P0-AF contracts for independently verified compound-chain claims."""

from __future__ import annotations

import pytest

from compound_verification import (
    AliasKind,
    CompoundCandidate,
    CompoundEvidence,
    CompoundVerdict,
    EvidenceOrigin,
    EvidenceOutcome,
    ProofScope,
    ReportDisposition,
    WorkReadiness,
    bind_compound_report,
    compile_compound_work_plan,
    diff_compound_work_plans,
    evaluate_compound_work_item,
    validate_compound_report_bindings,
)


def _candidate(
    chain_id: str = "CH-01",
    constituents: tuple[str, ...] = ("M-01", "M-02"),
    *,
    justified: bool = True,
    claim: str = "The ordered composition creates a distinct combined impact.",
    pipeline: str = "SC",
    mode: str = "core",
) -> CompoundCandidate:
    return CompoundCandidate.create(
        chain_id=chain_id,
        constituents=constituents,
        severity_upgrade_justified=justified,
        ordering_edges=((constituents[0], constituents[1], "precedes"),),
        preconditions=("shared-state prerequisite",),
        postconditions=("combined state transition",),
        combined_impact_claim=claim,
        proposed_severity="High",
        source_lineage=("chain_agent2:row-1",),
        coverage_lineage=("inventory:M-01", "inventory:M-02"),
        pipeline=pipeline,
        mode=mode,
    )


def _compound_evidence(
    candidate: CompoundCandidate,
    *,
    outcome: EvidenceOutcome = EvidenceOutcome.CONFIRMS,
    scopes: frozenset[ProofScope] = frozenset(
        {ProofScope.COMPOSITION, ProofScope.HARM}
    ),
    origin: EvidenceOrigin = EvidenceOrigin.COMPOUND_EXECUTION,
    executed: bool = True,
    ordering_reachable: bool | None = True,
    both_mechanisms_required: bool | None = True,
    combined_harm_observed: bool | None = True,
) -> CompoundEvidence:
    return CompoundEvidence.create(
        evidence_id="E-COMPOUND-01",
        subject_id=candidate.chain_id,
        constituent_ids=candidate.constituents,
        origin=origin,
        outcome=outcome,
        proof_scopes=scopes,
        executed=executed,
        ordering_reachable=ordering_reachable,
        both_mechanisms_required=both_mechanisms_required,
        combined_harm_observed=combined_harm_observed,
        command_digest="cmd-sha256" if executed else "",
        result_digest="result-sha256" if executed else "",
    )


@pytest.mark.parametrize(
    ("pipeline", "mode"),
    [("SC", "core"), ("SC", "thorough"), ("L1", "core"), ("L1", "thorough")],
)
def test_justified_chain_gets_distinct_compound_work_identity(
    pipeline: str, mode: str
) -> None:
    candidate = _candidate(pipeline=pipeline, mode=mode)
    plan = compile_compound_work_plan([candidate], {"M-01", "M-02"})

    assert not plan.issues
    assert len(plan.work_items) == 1
    work = plan.work_items[0]
    assert work.subject_id == "CH-01"
    assert work.verification_identity == "verify_CH-01"
    assert work.verification_identity not in candidate.constituents
    assert work.required_proof_scopes == frozenset(
        {ProofScope.COMPOSITION, ProofScope.HARM}
    )
    assert work.readiness is WorkReadiness.READY
    assert work.pipeline == pipeline
    assert work.mode == mode


def test_same_tier_combined_impact_is_still_independent_work() -> None:
    candidate = _candidate(constituents=("H-01", "H-02"))
    plan = compile_compound_work_plan([candidate], {"H-01", "H-02"})
    assert [work.subject_id for work in plan.work_items] == ["CH-01"]


def test_unjustified_restatement_is_alias_not_redundant_verifier() -> None:
    candidate = _candidate(justified=False)
    plan = compile_compound_work_plan([candidate], {"M-01", "M-02"})

    assert not plan.work_items
    assert len(plan.alias_relations) == 1
    alias = plan.alias_relations[0]
    assert alias.alias_id == "CH-01"
    assert alias.target_ids == ("M-01", "M-02")
    assert alias.kind is AliasKind.RESTATEMENT


def test_missing_constituent_and_identity_collision_remain_visible() -> None:
    missing = _candidate()
    collision = _candidate(chain_id="CH-02", constituents=("M-02", "M-03"))
    plan = compile_compound_work_plan(
        [missing, collision],
        {"M-01", "M-03", "CH-02"},
    )

    by_id = {work.subject_id: work for work in plan.work_items}
    assert by_id["CH-01"].readiness is WorkReadiness.BLOCKED_MISSING_CONSTITUENT
    assert by_id["CH-01"].missing_constituents == ("M-02",)
    assert by_id["CH-02"].readiness is WorkReadiness.BLOCKED_IDENTITY_COLLISION
    assert any(issue.code == "MISSING_CONSTITUENT" for issue in plan.issues)
    assert any(issue.code == "IDENTITY_COLLISION" for issue in plan.issues)


def test_duplicate_chain_id_is_not_silently_collapsed() -> None:
    first = _candidate()
    second = _candidate(constituents=("M-03", "M-04"), claim="Different composition")
    plan = compile_compound_work_plan(
        [first, second], {"M-01", "M-02", "M-03", "M-04"}
    )

    assert not plan.work_items
    assert len(plan.blocked_candidates) == 2
    issue = next(issue for issue in plan.issues if issue.code == "DUPLICATE_CHAIN_ID")
    assert issue.subject_id == "CH-01"
    assert len(issue.candidate_digests) == 2


def test_equivalent_distinct_chain_ids_alias_without_double_counting() -> None:
    first = _candidate(chain_id="CH-01")
    second = _candidate(chain_id="CH-02")
    plan = compile_compound_work_plan([second, first], {"M-01", "M-02"})

    assert [work.subject_id for work in plan.work_items] == ["CH-01"]
    assert [(alias.alias_id, alias.target_ids) for alias in plan.alias_relations] == [
        ("CH-02", ("CH-01",))
    ]


def test_constituent_execution_cannot_prove_composition() -> None:
    candidate = _candidate()
    work = compile_compound_work_plan([candidate], set(candidate.constituents)).work_items[0]
    borrowed = _compound_evidence(
        candidate,
        origin=EvidenceOrigin.CONSTITUENT_EXECUTION,
    )

    result = evaluate_compound_work_item(
        candidate,
        work,
        [borrowed],
        {"M-01": "CONFIRMED", "M-02": "CONFIRMED"},
    )

    assert result.verdict is CompoundVerdict.UNVERIFIED_COMPOUND
    assert not result.proof_grade
    assert result.accepted_evidence_ids == ()
    assert "NO_COMPOSITION_EVIDENCE" in result.debt_codes


@pytest.mark.parametrize(
    "constituent_verdicts",
    [
        {"M-01": "CONFIRMED", "M-02": "CONFIRMED"},
        {"M-01": "REFUTED", "M-02": "CONFIRMED"},
    ],
)
def test_constituent_verdicts_are_inputs_never_terminal_proof(
    constituent_verdicts: dict[str, str]
) -> None:
    candidate = _candidate()
    work = compile_compound_work_plan([candidate], set(candidate.constituents)).work_items[0]
    result = evaluate_compound_work_item(
        candidate, work, [], constituent_verdicts
    )
    assert result.verdict is CompoundVerdict.UNVERIFIED_COMPOUND
    assert not result.proof_grade


def test_composition_refutation_and_unreachable_ordering_are_explicit() -> None:
    candidate = _candidate()
    work = compile_compound_work_plan([candidate], set(candidate.constituents)).work_items[0]
    refutation = _compound_evidence(
        candidate,
        outcome=EvidenceOutcome.REFUTES,
        scopes=frozenset({ProofScope.COMPOSITION}),
        executed=True,
        ordering_reachable=False,
        both_mechanisms_required=True,
        combined_harm_observed=False,
    )
    result = evaluate_compound_work_item(
        candidate,
        work,
        [refutation],
        {"M-01": "CONFIRMED", "M-02": "CONFIRMED"},
    )
    assert result.verdict is CompoundVerdict.REFUTED
    assert result.ordering_reachable is False


def test_only_composed_execution_with_composition_and_harm_is_proof_grade() -> None:
    candidate = _candidate()
    work = compile_compound_work_plan([candidate], set(candidate.constituents)).work_items[0]

    mechanism_only = _compound_evidence(
        candidate,
        scopes=frozenset({ProofScope.COMPOSITION}),
        combined_harm_observed=None,
    )
    partial = evaluate_compound_work_item(
        candidate,
        work,
        [mechanism_only],
        {"M-01": "CONFIRMED", "M-02": "CONFIRMED"},
    )
    assert partial.verdict is CompoundVerdict.PARTIAL
    assert not partial.proof_grade

    confirmed = evaluate_compound_work_item(
        candidate,
        work,
        [_compound_evidence(candidate)],
        {"M-01": "CONFIRMED", "M-02": "CONFIRMED"},
    )
    assert confirmed.verdict is CompoundVerdict.CONFIRMED
    assert confirmed.proof_grade
    assert confirmed.subject_id == "CH-01"

    confirmed_binding = bind_compound_report(
        candidate, confirmed, evidence=[_compound_evidence(candidate)]
    )
    assert confirmed_binding.disposition is ReportDisposition.BODY
    assert confirmed_binding.evidence_identity == "CH-01"

    missing_evidence_binding = bind_compound_report(candidate, confirmed)
    assert missing_evidence_binding.disposition is ReportDisposition.HUMAN_REVIEW
    assert missing_evidence_binding.verdict is CompoundVerdict.UNVERIFIED_COMPOUND


def test_no_executed_harness_cannot_enter_proof_grade_body() -> None:
    candidate = _candidate()
    work = compile_compound_work_plan([candidate], set(candidate.constituents)).work_items[0]
    not_executed = _compound_evidence(candidate, executed=False)
    result = evaluate_compound_work_item(
        candidate,
        work,
        [not_executed],
        {"M-01": "CONFIRMED", "M-02": "CONFIRMED"},
    )
    binding = bind_compound_report(candidate, result, evidence=[not_executed])

    assert result.verdict is CompoundVerdict.PARTIAL
    assert not result.proof_grade
    assert binding.disposition is ReportDisposition.HUMAN_REVIEW


def test_constituent_status_disagreement_is_preserved_not_first_file_inherited() -> None:
    candidate = _candidate()
    work = compile_compound_work_plan([candidate], set(candidate.constituents)).work_items[0]
    result = evaluate_compound_work_item(
        candidate,
        work,
        [],
        {"M-01": "CONFIRMED", "M-02": "REFUTED"},
    )
    assert result.constituent_verdicts == (
        ("M-01", "CONFIRMED"),
        ("M-02", "REFUTED"),
    )
    assert result.verdict is CompoundVerdict.UNVERIFIED_COMPOUND


def test_unavailable_verifier_stays_visible_at_proposed_severity() -> None:
    candidate = _candidate()
    work = compile_compound_work_plan([candidate], set(candidate.constituents)).work_items[0]
    result = evaluate_compound_work_item(
        candidate,
        work,
        [],
        {"M-01": "CONFIRMED", "M-02": "CONFIRMED"},
        verifier_available=False,
    )
    binding = bind_compound_report(candidate, result)

    assert result.verdict is CompoundVerdict.UNVERIFIED_COMPOUND
    assert binding.report_identity == "CH-01"
    assert binding.proposed_severity == "High"
    assert binding.disposition is ReportDisposition.HUMAN_REVIEW
    assert not binding.proof_grade


def test_report_binding_never_substitutes_constituent_or_defaults_confirmed() -> None:
    candidate = _candidate()
    absent = bind_compound_report(candidate, None)

    assert absent.report_identity == "CH-01"
    assert absent.evidence_identity == "CH-01"
    assert absent.verdict is CompoundVerdict.UNVERIFIED_COMPOUND
    assert absent.disposition is ReportDisposition.HUMAN_REVIEW

    # A constituent remains independently countable while the compound uses
    # its own primary identity; supporting IDs do not collide with primaries.
    issues = validate_compound_report_bindings(
        [absent], standalone_report_identities={"M-01", "M-02"}
    )
    assert not issues

    tampered = absent.with_evidence_identity("M-01")
    issues = validate_compound_report_bindings(
        [tampered], standalone_report_identities={"M-01"}
    )
    assert any(issue.code == "CONSTITUENT_PROOF_SUBSTITUTION" for issue in issues)
    assert any(issue.code == "REPORT_IDENTITY_COLLISION" for issue in issues)


def test_iteration_two_addition_changes_plan_digest_and_is_targetable() -> None:
    initial = compile_compound_work_plan([_candidate()], {"M-01", "M-02", "M-03"})
    later_candidate = _candidate(
        chain_id="CH-02",
        constituents=("M-02", "M-03"),
        claim="A later iteration adds a distinct combined impact.",
    )
    later = compile_compound_work_plan(
        [_candidate(), later_candidate], {"M-01", "M-02", "M-03"}
    )
    delta = diff_compound_work_plans(initial, later)

    assert initial.digest != later.digest
    assert delta.added_verification_identities == ("verify_CH-02",)
    assert delta.requires_descendant_invalidation
