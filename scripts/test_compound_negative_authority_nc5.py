"""NC-5 recall-safety contracts for compound/composition refutations.

Compound execution can support a negative assessment, but this module has no
independent, replayable terminal-negative closure authority.  Consequently a
refutation must remain visible for human review and cannot exclude a compound
candidate from reporting.
"""

from __future__ import annotations

from dataclasses import replace

import pytest

from compound_verification import (
    CompoundCandidate,
    CompoundEvidence,
    CompoundReportBinding,
    CompoundVerdict,
    EvidenceOrigin,
    EvidenceOutcome,
    ProofScope,
    ReportDisposition,
    bind_compound_report,
    compile_compound_work_plan,
    evaluate_compound_work_item,
    validate_compound_report_bindings,
)


def _candidate(chain_id: str = "CH-501") -> CompoundCandidate:
    return CompoundCandidate.create(
        chain_id=chain_id,
        constituents=("INV-501", "INV-502"),
        severity_upgrade_justified=True,
        ordering_edges=(("INV-501", "INV-502", "precedes"),),
        preconditions=("Both constituent mechanisms are reachable.",),
        postconditions=("The combined effect requires independent verification.",),
        combined_impact_claim="A distinct composition claim remains to be verified.",
        proposed_severity="High",
        source_lineage=("chain_analysis.md:row-501",),
        coverage_lineage=("INV-501", "INV-502"),
        pipeline="SC",
        mode="thorough",
    )


def _refutation(
    candidate: CompoundCandidate,
    *,
    evidence_id: str = "E-COMPOUND-REFUTE-501",
    origin: EvidenceOrigin = EvidenceOrigin.COMPOUND_EXECUTION,
    outcome: EvidenceOutcome = EvidenceOutcome.REFUTES,
    scopes: tuple[ProofScope, ...] = (ProofScope.COMPOSITION,),
    executed: bool = True,
    command_digest: str = "c" * 64,
    result_digest: str = "d" * 64,
    subject_id: str | None = None,
    ordering_reachable: bool | None = False,
    both_mechanisms_required: bool | None = True,
    combined_harm_observed: bool | None = False,
) -> CompoundEvidence:
    return CompoundEvidence.create(
        evidence_id=evidence_id,
        subject_id=subject_id or candidate.chain_id,
        constituent_ids=candidate.constituents,
        origin=origin,
        outcome=outcome,
        proof_scopes=scopes,
        executed=executed,
        ordering_reachable=ordering_reachable,
        both_mechanisms_required=both_mechanisms_required,
        combined_harm_observed=combined_harm_observed,
        command_digest=command_digest,
        result_digest=result_digest,
    )


def _evaluate(candidate: CompoundCandidate, evidence: CompoundEvidence):
    work = compile_compound_work_plan(
        (candidate,), candidate.constituents
    ).work_items[0]
    return evaluate_compound_work_item(
        candidate,
        work,
        (evidence,),
        {identity: "CONFIRMED" for identity in candidate.constituents},
    )


@pytest.mark.parametrize(
    ("executed", "command_digest", "result_digest"),
    [
        (False, "", ""),
        (True, "", "d" * 64),
        (True, "c" * 64, ""),
    ],
)
def test_unexecuted_or_unreceipted_refutation_is_not_accepted_negative_evidence(
    executed: bool,
    command_digest: str,
    result_digest: str,
) -> None:
    candidate = _candidate()
    evidence = _refutation(
        candidate,
        executed=executed,
        command_digest=command_digest,
        result_digest=result_digest,
    )

    assert evidence.is_typed_composition_refutation(candidate) is False
    result = _evaluate(candidate, evidence)
    binding = bind_compound_report(candidate, result, evidence=(evidence,))

    assert result.verdict is CompoundVerdict.UNVERIFIED_COMPOUND
    assert result.proof_grade is False
    assert "REFUTATION_EXECUTION_AUTHORITY_MISSING" in result.debt_codes
    assert binding.disposition is ReportDisposition.HUMAN_REVIEW
    assert binding.proposed_severity == "High"


def test_prose_refutation_cannot_become_composition_negative_evidence() -> None:
    candidate = _candidate()
    evidence = _refutation(candidate, origin=EvidenceOrigin.VERIFIER_PROSE)
    result = _evaluate(candidate, evidence)

    assert evidence.is_typed_composition_refutation(candidate) is False
    assert result.verdict is CompoundVerdict.UNVERIFIED_COMPOUND
    assert result.accepted_evidence_ids == ()
    assert "NO_COMPOSITION_EVIDENCE" in result.debt_codes


@pytest.mark.parametrize(
    "evidence",
    [
        _refutation(
            _candidate(),
            evidence_id="E-COMPOUND-INCONCLUSIVE-501",
            outcome=EvidenceOutcome.INCONCLUSIVE,
        ),
        _refutation(
            _candidate(),
            evidence_id="E-COMPOUND-PARTIAL-501",
            ordering_reachable=None,
            both_mechanisms_required=None,
            combined_harm_observed=None,
        ),
        _refutation(
            _candidate(),
            evidence_id="E-COMPOUND-WRONG-SCOPE-501",
            scopes=(ProofScope.HARM,),
        ),
    ],
)
def test_uncertain_partial_or_wrong_scope_negative_evidence_stays_visible(
    evidence: CompoundEvidence,
) -> None:
    candidate = _candidate()
    result = _evaluate(candidate, evidence)
    binding = bind_compound_report(candidate, result, evidence=(evidence,))

    assert evidence.is_typed_composition_refutation(candidate) is False
    assert result.verdict is CompoundVerdict.UNVERIFIED_COMPOUND
    assert result.proof_grade is False
    assert binding.disposition is ReportDisposition.HUMAN_REVIEW
    assert binding.proposed_severity == "High"


def test_exact_executed_refutation_remains_review_only_without_closure_authority() -> None:
    candidate = _candidate()
    evidence = _refutation(candidate)
    result = _evaluate(candidate, evidence)
    binding = bind_compound_report(candidate, result, evidence=(evidence,))

    assert evidence.is_typed_composition_refutation(candidate) is True
    assert result.verdict is CompoundVerdict.REFUTED
    assert result.proof_grade is False
    assert "TERMINAL_NEGATIVE_CLOSURE_AUTHORITY_MISSING" in result.debt_codes
    assert binding.verdict is CompoundVerdict.REFUTED
    assert binding.disposition is ReportDisposition.HUMAN_REVIEW
    assert binding.proof_grade is False
    assert binding.composition_evidence_ids == (evidence.evidence_id,)
    assert binding.proposed_severity == "High"


def test_forged_proof_grade_flag_cannot_turn_refutation_into_exclusion() -> None:
    candidate = _candidate()
    evidence = _refutation(candidate)
    result = replace(_evaluate(candidate, evidence), proof_grade=True)

    binding = bind_compound_report(candidate, result, evidence=(evidence,))

    assert binding.disposition is ReportDisposition.HUMAN_REVIEW
    assert binding.proof_grade is False
    assert binding.verdict is CompoundVerdict.REFUTED


def test_mismatched_or_stale_refutation_does_not_bind_to_candidate() -> None:
    candidate = _candidate()
    foreign = _candidate("CH-502")
    evidence = _refutation(candidate)
    result = _evaluate(candidate, evidence)
    stale_evidence = _refutation(
        foreign,
        evidence_id=evidence.evidence_id,
    )

    binding = bind_compound_report(candidate, result, evidence=(stale_evidence,))

    assert binding.disposition is ReportDisposition.HUMAN_REVIEW
    assert binding.verdict is CompoundVerdict.UNVERIFIED_COMPOUND
    assert binding.composition_evidence_ids == ()


def test_excluded_refuted_binding_without_central_authority_is_invalid() -> None:
    candidate = _candidate()
    binding = CompoundReportBinding(
        report_identity=candidate.chain_id,
        evidence_identity=candidate.chain_id,
        supporting_constituent_ids=candidate.constituents,
        composition_evidence_ids=("E-COMPOUND-REFUTE-501",),
        proposed_severity=candidate.proposed_severity,
        verdict=CompoundVerdict.REFUTED,
        disposition=ReportDisposition.EXCLUDED_REFUTED,
        proof_grade=True,
    )

    issues = validate_compound_report_bindings((binding,))

    assert any(issue.code == "UNAUTHORIZED_NEGATIVE_CLOSURE" for issue in issues)


def test_positive_compound_execution_remains_proof_grade_body_evidence() -> None:
    candidate = _candidate()
    evidence = CompoundEvidence.create(
        evidence_id="E-COMPOUND-CONFIRM-501",
        subject_id=candidate.chain_id,
        constituent_ids=candidate.constituents,
        origin=EvidenceOrigin.COMPOUND_EXECUTION,
        outcome=EvidenceOutcome.CONFIRMS,
        proof_scopes=(ProofScope.COMPOSITION, ProofScope.HARM),
        executed=True,
        ordering_reachable=True,
        both_mechanisms_required=True,
        combined_harm_observed=True,
        command_digest="a" * 64,
        result_digest="b" * 64,
    )
    result = _evaluate(candidate, evidence)
    binding = bind_compound_report(candidate, result, evidence=(evidence,))

    assert result.verdict is CompoundVerdict.CONFIRMED
    assert result.proof_grade is True
    assert binding.disposition is ReportDisposition.BODY
    assert binding.proof_grade is True
