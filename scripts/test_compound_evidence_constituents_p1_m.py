"""P1-M/P0-AF contracts for immutable evidence-fact constituents.

Role facts are evidence inputs to a distinct compound claim.  They must never
be laundered into standalone findings merely to satisfy the legacy planner.
"""

from __future__ import annotations

from compound_verification import (
    CompoundCandidate,
    CompoundEvidence,
    EvidenceOrigin,
    EvidenceOutcome,
    ProofScope,
    WorkReadiness,
    compile_compound_work_plan,
)


FACT_A = "MZO-FACT-ANCHOR"
FACT_B = "MZO-FACT-DERIVED"
DIGEST_A = "a" * 64
DIGEST_B = "b" * 64
AUTHORITY = "c" * 64


def _binding(identity: str, fact_digest: str) -> dict[str, str]:
    return {
        "constituent_id": identity,
        "constituent_kind": "EVIDENCE_FACT",
        "fact_digest": fact_digest,
        "authority_digest": AUTHORITY,
        "source_artifact": "authentication_role_facts.json",
    }


def _candidate() -> CompoundCandidate:
    return CompoundCandidate.create(
        chain_id="CH-9001",
        constituents=(FACT_A, FACT_B),
        evidence_constituent_bindings=(
            _binding(FACT_A, DIGEST_A),
            _binding(FACT_B, DIGEST_B),
        ),
        severity_upgrade_justified=True,
        ordering_edges=(),
        preconditions=("Both typed roles are reachable in one execution.",),
        postconditions=("Composition and material harm require verification.",),
        combined_impact_claim="Unverified combined authentication-boundary claim.",
        proposed_severity="Medium",
        source_lineage=("arm_before_trust_composition_obligations.json",),
        coverage_lineage=("MZO-1", FACT_A, FACT_B),
        pipeline="SC",
        mode="thorough",
    )


def _known() -> tuple[dict[str, str], ...]:
    return (
        _binding(FACT_A, DIGEST_A),
        _binding(FACT_B, DIGEST_B),
    )


def test_exact_evidence_fact_bindings_make_distinct_compound_work_ready():
    plan = compile_compound_work_plan(
        (_candidate(),),
        known_constituent_identities=(),
        known_evidence_constituents=_known(),
    )

    item = plan.work_items[0]
    assert item.readiness is WorkReadiness.READY
    assert item.missing_constituents == ()
    assert item.constituent_ids == (FACT_A, FACT_B)
    assert {scope.value for scope in item.required_proof_scopes} == {
        "COMPOSITION",
        "HARM",
    }
    record = plan.to_record()
    assert record["schema_version"] == "plamen.compound_work_plan.v2"
    assert record["work_items"][0]["constituent_authority_bindings"] == [
        _binding(FACT_A, DIGEST_A),
        _binding(FACT_B, DIGEST_B),
    ]


def test_missing_or_digest_mismatched_fact_is_visible_and_blocks_readiness():
    missing = compile_compound_work_plan(
        (_candidate(),),
        known_constituent_identities=(),
        known_evidence_constituents=(_binding(FACT_A, DIGEST_A),),
    )
    assert missing.work_items[0].readiness is WorkReadiness.BLOCKED_MISSING_CONSTITUENT
    assert missing.work_items[0].missing_constituents == (FACT_B,)
    assert any(issue.code == "MISSING_EVIDENCE_CONSTITUENT" for issue in missing.issues)

    mismatched = compile_compound_work_plan(
        (_candidate(),),
        known_constituent_identities=(),
        known_evidence_constituents=(
            _binding(FACT_A, DIGEST_A),
            _binding(FACT_B, "d" * 64),
        ),
    )
    assert mismatched.work_items[0].readiness is WorkReadiness.BLOCKED_MISSING_CONSTITUENT
    assert mismatched.work_items[0].missing_constituents == (FACT_B,)
    assert any(issue.code == "EVIDENCE_CONSTITUENT_BINDING_MISMATCH" for issue in mismatched.issues)


def test_declared_fact_cannot_be_satisfied_by_standalone_finding_namespace():
    plan = compile_compound_work_plan(
        (_candidate(),),
        known_constituent_identities=(FACT_A, FACT_B),
        known_evidence_constituents=(),
    )

    assert plan.work_items[0].readiness is WorkReadiness.BLOCKED_MISSING_CONSTITUENT
    assert plan.work_items[0].missing_constituents == (FACT_A, FACT_B)


def test_legacy_finding_constituents_keep_v1_bytes_and_readiness():
    candidate = CompoundCandidate.create(
        chain_id="CH-9",
        constituents=("INV-1", "INV-2"),
        severity_upgrade_justified=True,
        ordering_edges=(("INV-1", "INV-2", "enables"),),
        preconditions=("Both constituent mechanisms are reachable.",),
        postconditions=("Combined harm remains to be proved.",),
        combined_impact_claim="Unverified composition.",
        proposed_severity="High",
        source_lineage=("chain_analysis.md",),
        coverage_lineage=("INV-1", "INV-2"),
        pipeline="SC",
        mode="thorough",
    )
    plan = compile_compound_work_plan(
        (candidate,), known_constituent_identities=("INV-1", "INV-2")
    )

    assert plan.work_items[0].readiness is WorkReadiness.READY
    assert plan.to_record()["schema_version"] == "plamen.compound_work_plan.v1"
    assert "constituent_authority_bindings" not in plan.to_record()["work_items"][0]


def test_constituent_execution_cannot_self_certify_fact_composition_or_harm():
    candidate = _candidate()
    evidence = CompoundEvidence.create(
        evidence_id="EV-CONSTITUENTS",
        subject_id=candidate.chain_id,
        constituent_ids=candidate.constituents,
        origin=EvidenceOrigin.CONSTITUENT_EXECUTION,
        outcome=EvidenceOutcome.CONFIRMS,
        proof_scopes=(ProofScope.CONSTITUENT_MECHANISM,),
        executed=True,
        ordering_reachable=None,
        both_mechanisms_required=None,
        combined_harm_observed=None,
        command_digest="1" * 64,
        result_digest="2" * 64,
    )

    assert evidence.is_exact_compound_evidence(candidate) is False
    assert evidence.is_proof_grade_confirmation(candidate) is False
