"""R0 acceptance fixtures for report evidence/disposition separation."""

from __future__ import annotations

from pathlib import Path
import json

import pytest

import report_evidence_authority as authority
from test_report_evidence_runtime_p1_k import _write_inputs


def _proof_record(**updates: object) -> dict[str, object]:
    row: dict[str, object] = {
        "report_id": "H-01",
        "candidate_ids": ["INV-001"],
        "severity": "High",
        "title": "A reachable transition violates the accounting relation",
        "verdict": "CONFIRMED",
        "mechanism": "One transition updates only one side of a paired relation.",
        "preconditions": ["The transition is reachable."],
        "impact": "The inconsistent relation can cause incorrect settlement.",
        "affected_locations": ["src/Module.sol:L10-L30"],
        "recommendation": "Update both sides atomically.",
        "evidence_authenticity": "AUTHENTICATED_EXECUTION",
        "evidence_result": "ESTABLISHED",
        "proof_scope": "HARM",
        "capabilities": ["EXECUTION", "MECHANISM", "HARM"],
        "evidence_sources": [],
        "limitations": [],
    }
    row.update(updates)
    return authority.normalize_report_evidence_record(row)


@pytest.mark.parametrize(
    "label",
    ("Preconditions", "Precondition", "Precondition Analysis"),
)
def test_canonical_precondition_parser_accepts_verifier_and_report_labels(
    label: str,
) -> None:
    markdown = f"### {label}\n- Caller reaches the transition.\n- Amount is non-zero.\n"
    assert authority._precondition_list(markdown) == [
        "Caller reaches the transition.",
        "Amount is non-zero.",
    ]


def test_authenticated_harm_proof_is_independent_from_report_prose_debt() -> None:
    record = _proof_record(impact="")
    assert record["evidence_authenticity"] == "AUTHENTICATED_EXECUTION"
    assert record["evidence_result"] == "ESTABLISHED"
    assert record["proof_scope"] == "HARM"
    assert record["presentation_assurance"] == "PROOF_GRADE_HARM"
    assert "REPORT_FIELD_MISSING:impact" in record["limitations"]
    assert authority.required_semantic_fields(record) == ["impact"]


def test_proof_authority_and_report_completeness_have_separate_states() -> None:
    record = _proof_record(impact="")
    bundle = authority.build_report_evidence_bundle(
        [record], expected_report_ids=["H-01"]
    )
    receipt = authority.derive_quality_receipt(
        bundle,
        delivered_report_ids=["H-01"],
        limitation_visible_report_ids=["H-01"],
    )
    assert record["presentation_assurance"] == "PROOF_GRADE_HARM"
    assert receipt["semantically_complete"] is False
    assert receipt["delivery_state"] == "DEGRADED_DELIVERY"
    assert receipt["missing_semantic_fields"] == {"H-01": ["impact"]}


@pytest.mark.parametrize(
    ("upstream", "verdict", "debt"),
    (
        ("VERIFIED", "VERIFIED", None),
        ("CONFIRMED", "CONFIRMED", None),
        ("CONTESTED", "CONTESTED", None),
        ("UNRESOLVED", "UNRESOLVED", None),
        ("UNVERIFIED", "UNVERIFIED", None),
        ("TRUE_POSITIVE", "CONFIRMED", None),
        ("VALID", "CONFIRMED", None),
        ("CONFIRMED_MECHANISM", "CONFIRMED", None),
        ("PARTIAL", "UNRESOLVED", "UPSTREAM_DISPOSITION:PARTIAL"),
        ("INCONCLUSIVE", "UNRESOLVED", "UPSTREAM_DISPOSITION:INCONCLUSIVE"),
        ("NEEDS_REVIEW", "UNRESOLVED", "UPSTREAM_DISPOSITION:NEEDS_REVIEW"),
        ("NEEDS_VERIFICATION", "UNRESOLVED", "UPSTREAM_DISPOSITION:NEEDS_VERIFICATION"),
        ("LOW_CONFIDENCE", "CONTESTED", "UPSTREAM_DISPOSITION:LOW_CONFIDENCE"),
        ("UNCONFIRMED", "CONTESTED", "UPSTREAM_DISPOSITION:UNCONFIRMED"),
        ("APPENDIX_ONLY", "CONTESTED", "UPSTREAM_DISPOSITION:APPENDIX_ONLY"),
        ("DROP_FALSE_POSITIVE", "CONTESTED", "UPSTREAM_DISPOSITION:DROP_FALSE_POSITIVE"),
        ("DROP_NON_SECURITY", "CONTESTED", "UPSTREAM_DISPOSITION:DROP_NON_SECURITY"),
        (
            "DROP_DESIGN_CONFIRMATION",
            "CONTESTED",
            "UPSTREAM_DISPOSITION:DROP_DESIGN_CONFIRMATION",
        ),
        (
            "DROP_UNACTIONABLE_SPECULATION",
            "CONTESTED",
            "UPSTREAM_DISPOSITION:DROP_UNACTIONABLE_SPECULATION",
        ),
        ("FALSE_POSITIVE", "CONTESTED", "UPSTREAM_DISPOSITION:FALSE_POSITIVE"),
        ("REFUTED", "CONTESTED", "UPSTREAM_DISPOSITION:REFUTED"),
        ("INFEASIBLE", "CONTESTED", "UPSTREAM_DISPOSITION:INFEASIBLE"),
        ("CLEAR", "CONTESTED", "UPSTREAM_DISPOSITION:CLEAR"),
        ("SCHEMA_INVALID", "CONTESTED", "UPSTREAM_DISPOSITION:SCHEMA_INVALID"),
        ("LOCATION_INVALID", "CONTESTED", "UPSTREAM_DISPOSITION:LOCATION_INVALID"),
        ("DUPLICATE", "UNRESOLVED", "UPSTREAM_DISPOSITION:DUPLICATE"),
        ("CONSOLIDATED", "UNRESOLVED", "UPSTREAM_DISPOSITION:CONSOLIDATED"),
        ("unexpected-new-value", "UNRESOLVED", "REPORT_VERDICT_SCHEMA_UNKNOWN:UNEXPECTED_NEW_VALUE"),
        ("**APPENDIX-ONLY**", "CONTESTED", "UPSTREAM_DISPOSITION:APPENDIX_ONLY"),
        ("CLEAR (NO FINDING)", "CONTESTED", "UPSTREAM_DISPOSITION:CLEAR"),
    ),
)
def test_closed_upstream_disposition_lattice_preserves_semantics_and_debt(
    upstream: str, verdict: str, debt: str | None,
) -> None:
    assert authority._verdict_disposition(upstream) == (
        verdict,
        [] if debt is None else [debt],
    )


@pytest.mark.parametrize(
    ("body", "authenticity", "result", "debt"),
    (
        (
            "**Evidence Tag**: [CODE-TRACE]\n\n### Code Trace\n"
            "The cited transition writes the credit but not the liability.\n",
            "CODE_TRACE",
            "ESTABLISHED",
            None,
        ),
        (
            "### Analysis\nThe prose happens to mention [CODE-TRACE] incidentally.\n",
            "NOT_EXECUTED",
            "NOT_EXECUTED",
            None,
        ),
        (
            "**Evidence Tag**: result is [CODE-TRACE]\n\n### Code Trace\n"
            "The cited transition writes the credit but not the liability.\n",
            "CODE_TRACE",
            "ESTABLISHED",
            "EVIDENCE_TAG_SCHEMA_INVALID",
        ),
        (
            "### Code Trace\nThe cited transition writes the credit but not the liability.\n",
            "CODE_TRACE",
            "ESTABLISHED",
            None,
        ),
        (
            "**Evidence Tag**: [CODE-TRACE]\n\n### Impact\nValue can diverge.\n",
            "CODE_TRACE",
            "INCONCLUSIVE",
            "CODE_TRACE_EXPLANATION_MISSING",
        ),
    ),
)
def test_code_trace_authority_requires_exact_finding_bounded_structured_tag(
    tmp_path: Path,
    body: str,
    authenticity: str,
    result: str,
    debt: str | None,
) -> None:
    path = tmp_path / "verify_INV-001.md"
    path.write_text(body, encoding="utf-8")
    fields, limitations, _sources = authority._best_evidence_fields(
        tmp_path,
        [path.name],
        ["INV-001"],
        [body],
    )
    assert fields["evidence_authenticity"] == authenticity
    assert fields["evidence_result"] == result
    if debt is None:
        assert limitations == []
    else:
        assert debt in limitations


def test_code_trace_tag_in_an_unbound_verifier_cannot_cross_bind(
    tmp_path: Path,
) -> None:
    body = (
        "**Evidence Tag**: [CODE-TRACE]\n\n### Code Trace\n"
        "A different finding has a concrete manual trace.\n"
    )
    path = tmp_path / "verify_INV-999.md"
    path.write_text(body, encoding="utf-8")
    fields, limitations, _sources = authority._best_evidence_fields(
        tmp_path,
        [path.name],
        ["INV-001"],
        [body],
    )
    assert fields["evidence_authenticity"] == "NOT_EXECUTED"
    assert fields["evidence_result"] == "NOT_EXECUTED"
    assert limitations == []


@pytest.mark.parametrize(
    "body",
    (
        "### Analysis\nThe prose mentions [CODE-TRACE] but has no field.\n",
        "```markdown\n**Evidence Tag**: [CODE-TRACE]\n```\n",
        "<!-- **Evidence Tag**: [CODE-TRACE] -->\n",
        (
            "**Evidence Tag**: [CODE-TRACE]\n"
            "**Evidence Tag**: [CODE-TRACE]\n"
        ),
    ),
)
def test_incidental_or_ambiguous_code_trace_text_never_mints_authority(
    tmp_path: Path, body: str,
) -> None:
    path = tmp_path / "verify_INV-001.md"
    path.write_text(body, encoding="utf-8")
    fields, limitations, _sources = authority._best_evidence_fields(
        tmp_path, [path.name], ["INV-001"], [body]
    )
    assert fields["evidence_authenticity"] == "NOT_EXECUTED"
    if body.count("**Evidence Tag**:") > 1:
        assert "EVIDENCE_TAG_SCHEMA_INVALID" in limitations


def test_projection_recognizes_precondition_analysis_without_duplicate_field() -> None:
    record = _proof_record()
    bundle = authority.build_report_evidence_bundle(
        [record], expected_report_ids=["H-01"]
    )
    markdown = """### [H-01] A reachable transition violates the accounting relation

**Severity**: High
**Verdict**: CONFIRMED
**Mechanism**: One transition updates only one side of a paired relation.
**Impact**: The inconsistent relation can cause incorrect settlement.
**Location**: src/Module.sol:L10-L30
**Recommendation**: Update both sides atomically.

### Precondition Analysis
- The transition is reachable.
"""
    projected = authority.project_report_evidence_markdown(markdown, bundle)
    assert projected.count("Precondition Analysis") == 1
    assert "**Preconditions**:" not in projected


def test_live_adapter_reads_canonical_precondition_analysis(tmp_path: Path) -> None:
    _write_inputs(tmp_path, execution_tag="[CODE-TRACE]")
    verify = tmp_path / "verify_INV-001.md"
    verify.write_text(
        verify.read_text(encoding="utf-8").replace(
            "### Preconditions", "### Precondition Analysis"
        ),
        encoding="utf-8",
    )
    record = authority.materialize_report_evidence_runtime(tmp_path)["bundle"][
        "records"
    ][0]
    assert record["preconditions"] == [
        "The affected transition is reachable.",
        "A non-zero amount is processed.",
    ]
    assert "REPORT_FIELD_MISSING:preconditions" not in record["limitations"]


@pytest.mark.parametrize(
    ("upstream", "expected", "debt"),
    (
        ("APPENDIX_ONLY", "CONTESTED", "UPSTREAM_DISPOSITION:APPENDIX_ONLY"),
        (
            "DROP_UNACTIONABLE_SPECULATION",
            "CONTESTED",
            "UPSTREAM_DISPOSITION:DROP_UNACTIONABLE_SPECULATION",
        ),
        ("SCHEMA_INVALID", "CONTESTED", "UPSTREAM_DISPOSITION:SCHEMA_INVALID"),
        ("LOCATION_INVALID", "CONTESTED", "UPSTREAM_DISPOSITION:LOCATION_INVALID"),
        ("DUPLICATE", "UNRESOLVED", "UPSTREAM_DISPOSITION:DUPLICATE"),
        (
            "NEEDS_VERIFICATION",
            "UNRESOLVED",
            "UPSTREAM_DISPOSITION:NEEDS_VERIFICATION",
        ),
        ("LOW_CONFIDENCE", "CONTESTED", "UPSTREAM_DISPOSITION:LOW_CONFIDENCE"),
        ("UNCONFIRMED", "CONTESTED", "UPSTREAM_DISPOSITION:UNCONFIRMED"),
        (
            "future-disposition",
            "UNRESOLVED",
            "REPORT_VERDICT_SCHEMA_UNKNOWN:FUTURE_DISPOSITION",
        ),
    ),
)
def test_live_adapter_carries_procedural_and_schema_debt_into_typed_record(
    tmp_path: Path, upstream: str, expected: str, debt: str,
) -> None:
    _write_inputs(tmp_path, execution_tag="[CODE-TRACE]")
    path = tmp_path / "report_records.json"
    records = json.loads(path.read_text(encoding="utf-8"))
    records["active"][0]["verdict"] = upstream
    path.write_text(json.dumps(records, indent=2) + "\n", encoding="utf-8")
    record = authority.materialize_report_evidence_runtime(tmp_path)["bundle"][
        "records"
    ][0]
    assert record["verdict"] == expected
    assert debt in record["limitations"]
