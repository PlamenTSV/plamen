from __future__ import annotations

import hashlib

import pytest

from report_evidence_authority import (
    ReportEvidenceError,
    apply_semantic_repair_delta,
    build_report_evidence_bundle,
    derive_quality_receipt,
    evidence_fields_from_execution_assessment,
    normalize_report_evidence_record,
    required_semantic_fields,
    validate_report_evidence_bundle,
    validate_report_evidence_record,
)
from test_execution_proof_scope_p1_e import _record as _execution_record
from evidence_capabilities import issue_executed_poc_scope_assessment


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _record(**updates: object) -> dict[str, object]:
    row: dict[str, object] = {
        "report_id": "H-01",
        "candidate_ids": ["INV-001"],
        "severity": "High",
        "title": "State transition violates the declared accounting relation",
        "verdict": "CONFIRMED",
        "mechanism": "One transition updates the credited amount without updating its paired liability.",
        "preconditions": ["The affected transition is reachable", "A non-zero amount is processed"],
        "impact": "The recorded assets and liabilities can diverge, exposing value to incorrect settlement.",
        "affected_locations": ["src/Module.sol:L10-L30"],
        "recommendation": "Update both accounting legs atomically and assert their relation after the transition.",
        "evidence_authenticity": "AUTHENTICATED_EXECUTION",
        "evidence_result": "ESTABLISHED",
        "proof_scope": "HARM",
        "capabilities": ["EXECUTION", "MECHANISM", "HARM"],
        "evidence_sources": [
            {"artifact": "verify_INV-001.md", "sha256": _sha("verify")}
        ],
        "limitations": [],
    }
    row.update(updates)
    return normalize_report_evidence_record(row)


def test_harm_scoped_authenticated_execution_is_the_only_execution_proof_grade_case():
    record = _record()
    assert record["presentation_assurance"] == "PROOF_GRADE_HARM"
    assert required_semantic_fields(record) == []
    assert validate_report_evidence_record(record) == record


@pytest.mark.parametrize(
    "updates",
    [
        {"evidence_authenticity": "CODE_TRACE", "capabilities": ["MECHANISM"]},
        {"proof_scope": "MECHANISM_ONLY", "capabilities": ["EXECUTION", "MECHANISM"]},
        {"capabilities": ["EXECUTION", "MECHANISM"]},
        {"evidence_result": "NOT_ESTABLISHED"},
        {"limitations": ["EXTERNAL_PREMISE_UNRESOLVED"]},
    ],
)
def test_labels_or_partial_scope_cannot_mint_harm_proof(updates):
    record = _record(**updates)
    assert record["presentation_assurance"] != "PROOF_GRADE_HARM"


def test_code_trace_confirmation_is_presented_as_mechanism_not_execution():
    record = _record(
        evidence_authenticity="CODE_TRACE",
        proof_scope="MECHANISM_ONLY",
        capabilities=["MECHANISM"],
        evidence_sources=[{"artifact": "depth_findings.md", "sha256": _sha("trace")}],
    )
    assert record["presentation_assurance"] == "CONFIRMED_MECHANISM"


def test_p1e_assessment_not_markdown_tags_is_report_proof_authority():
    assessment = issue_executed_poc_scope_assessment(_execution_record())
    fields = evidence_fields_from_execution_assessment(assessment)
    record = _record(**fields)
    assert record["presentation_assurance"] == "PROOF_GRADE_HARM"

    limited = issue_executed_poc_scope_assessment(
        _execution_record(
            oracle_provenance="MODEL_GENERATED_ORACLE",
            oracle_derivation="IN_SCOPE_CLAIM_BOUND",
            oracle_author_identity="verification-worker",
            oracle_author_invocation_id="verification-worker-run-1",
            proof_scope="MECHANISM_ONLY",
        )
    )
    limited_record = _record(**evidence_fields_from_execution_assessment(limited))
    assert limited_record["presentation_assurance"] == "CONFIRMED_MECHANISM"
    assert limited_record["proof_scope"] == "MECHANISM_ONLY"


def test_missing_chm_fields_produce_exact_visible_repair_delta():
    record = _record(preconditions=[], impact="N/A", recommendation="TODO")
    assert required_semantic_fields(record) == [
        "impact",
        "preconditions",
        "recommendation",
    ]
    assert {
        "REPORT_FIELD_MISSING:impact",
        "REPORT_FIELD_MISSING:preconditions",
        "REPORT_FIELD_MISSING:recommendation",
    }.issubset(record["limitations"])


def test_generic_paraphrased_impact_is_repair_debt_not_semantic_completion():
    record = _record(impact="This issue may lead to a security impact.")
    assert required_semantic_fields(record) == ["impact"]
    assert record["presentation_assurance"] == "PROOF_GRADE_HARM"
    assert "REPORT_FIELD_MISSING:impact" in record["limitations"]


def test_one_bounded_delta_cannot_rewrite_identity_or_existing_claims():
    record = _record(impact="")
    repaired = apply_semantic_repair_delta(
        record,
        {"impact": "A reachable transition can cause an incorrect settlement amount."},
    )
    assert required_semantic_fields(repaired) == []
    assert repaired["report_id"] == record["report_id"]
    with pytest.raises(ReportEvidenceError):
        apply_semantic_repair_delta(record, {"severity": "Critical"})


def test_informational_record_allows_concise_reduced_schema():
    record = _record(
        report_id="I-01",
        severity="Informational",
        preconditions=[],
        impact="",
        recommendation="",
        proof_scope="NONE",
        evidence_authenticity="CODE_TRACE",
        capabilities=["MECHANISM"],
    )
    assert required_semantic_fields(record) == []


def test_low_security_impact_cannot_be_erased_for_brevity():
    record = _record(
        report_id="L-01",
        severity="Low",
        impact="",
        recommendation="",
    )
    assert required_semantic_fields(record) == ["impact", "recommendation"]


def test_bundle_exact_coverage_and_digest_detect_tampering():
    bundle = build_report_evidence_bundle(
        [_record()], expected_report_ids=["H-01", "M-01"]
    )
    assert bundle["missing_report_ids"] == ["M-01"]
    assert validate_report_evidence_bundle(bundle) == bundle
    bundle["records"][0]["impact"] = "tampered"
    with pytest.raises(ReportEvidenceError):
        validate_report_evidence_bundle(bundle)


def test_duplicate_report_identity_is_rejected_without_dedup_loss():
    with pytest.raises(ReportEvidenceError):
        build_report_evidence_bundle(
            [_record(), _record()], expected_report_ids=["H-01"]
        )


def test_repair_failure_delivers_visible_limitation_not_false_pass():
    incomplete = _record(impact="")
    bundle = build_report_evidence_bundle(
        [incomplete], expected_report_ids=["H-01"]
    )
    receipt = derive_quality_receipt(
        bundle,
        delivered_report_ids=["H-01"],
        limitation_visible_report_ids=["H-01"],
        repair_attempts={"H-01": 1},
    )
    assert receipt["structurally_delivered"] is True
    assert receipt["semantically_complete"] is False
    assert receipt["delivery_state"] == "DEGRADED_DELIVERY"
    assert receipt["hidden_quality_debt_report_ids"] == []


def test_hidden_quality_debt_is_not_called_degraded_delivery():
    incomplete = _record(impact="")
    bundle = build_report_evidence_bundle(
        [incomplete], expected_report_ids=["H-01"]
    )
    receipt = derive_quality_receipt(
        bundle,
        delivered_report_ids=["H-01"],
        limitation_visible_report_ids=[],
    )
    assert receipt["delivery_state"] == "STRUCTURAL_DELIVERY_INCOMPLETE"
    assert receipt["hidden_quality_debt_report_ids"] == ["H-01"]


def test_complete_receipt_separates_semantic_from_structural_delivery():
    bundle = build_report_evidence_bundle(
        [_record()], expected_report_ids=["H-01"]
    )
    receipt = derive_quality_receipt(
        bundle,
        delivered_report_ids=["H-01"],
        limitation_visible_report_ids=[],
        repair_attempts={"H-01": 1},
    )
    assert receipt["delivery_state"] == "SEMANTICALLY_COMPLETE"
    assert receipt["structurally_delivered"] is True
    assert receipt["semantically_complete"] is True
