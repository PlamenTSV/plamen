from pathlib import Path

import pytest

import plamen_driver as D
from plamen_parsers import extract_unambiguous_internal_ids
from plamen_types import plamen_home


def _write_single_high_report(project: Path, scratch: Path, description: str) -> None:
    (project / "AUDIT_REPORT.md").write_text(
        "# Audit Report\n\n"
        "## Summary\n"
        "| Severity | Count |\n|---|---:|\n| High | 1 |\n\n"
        "## High Findings\n"
        "### [H-01] Report-safe title\n"
        "**Severity**: High\n"
        "**Location**: src/F.sol:1\n"
        f"**Description**: {description} This section contains sufficient "
        "client-facing explanation to keep the privacy fixture independent "
        "from the report thinness telemetry and other structural checks.\n"
        "**Impact**: Funds can be affected under the described condition.\n"
        "**PoC Result**: Code trace reviewed.\n"
        "**Recommendation**: Apply validation before state mutation.\n",
        encoding="utf-8",
    )
    (scratch / "report_index.md").write_text(
        "## Master Finding Index\n"
        "| Report ID | Title | Severity | Internal Hypothesis |\n"
        "|-----------|-------|----------|---------------------|\n"
        "| H-01 | Report-safe title | High | INV-001 |\n",
        encoding="utf-8",
    )


def test_quality_gate_does_not_match_internal_id_inside_hyphenated_prose(
    tmp_path: Path,
):
    """P0-AL red fixture from the frozen Claude report.

    ``\bOF-1\b`` incorrectly matched the ``of-1`` suffix in ``price-of-1``.
    Ordinary hyphenated prose must not be reinterpreted as a pipeline identity.
    """
    project = tmp_path / "project"
    project.mkdir()
    scratch = project / ".scratchpad"
    scratch.mkdir()
    _write_single_high_report(
        project,
        scratch,
        "The price-of-1 unit and proof-of-2 cases are ordinary domain prose.",
    )

    issues = D._run_report_quality_gate(scratch, str(project))

    assert not any("internal IDs leaked" in issue for issue in issues)
    quality = (scratch / "report_quality.md").read_text(encoding="utf-8")
    assert "| internal_id_leak | PASS |" in quality


def test_quality_gate_still_matches_exact_niche_id_with_ascii_boundaries(
    tmp_path: Path,
):
    project = tmp_path / "project"
    project.mkdir()
    scratch = project / ".scratchpad"
    scratch.mkdir()
    _write_single_high_report(
        project,
        scratch,
        "The private token `of-1` leaked through a client-facing code name.",
    )

    issues = D._run_report_quality_gate(scratch, str(project))

    assert any("internal IDs leaked" in issue and "of-1" in issue for issue in issues)


@pytest.mark.parametrize(
    "text",
    [
        "price-of-1",
        "proof-of-2",
        "out-of-3",
        "state-of-4",
        "prefixof-1",
        "of-1suffix",
        "of-1-extra",
    ],
)
def test_internal_id_boundary_rejects_embedded_ascii_tokens(text: str):
    assert extract_unambiguous_internal_ids(text) == []


@pytest.mark.parametrize(
    "text",
    [
        "OF-1",
        "of-1",
        "`OF-1`",
        "[OF-1]",
        "/OF-1",
        "_OF-1_",
        "name_OF-1_test",
        "\N{EN DASH}OF-1\N{EN DASH}",
    ],
)
def test_internal_id_boundary_accepts_exact_identity_at_nonhyphen_delimiters(
    text: str,
):
    assert [item.upper() for item in extract_unambiguous_internal_ids(text)] == [
        "OF-1"
    ]


def test_client_sanitizers_remove_mixed_case_internal_ids():
    title = "Bug from depth validation of inv-002 and SlItHeR-7"
    body = (
        "This was found by cs-1, depth-st-2, l1-h-3, H-1, H-C06, and CH-7 during "
        "analysis. Keep client report ID H-01 intact."
    )

    clean_title = D._sanitize_client_title(title)
    clean_body = D._sanitize_client_body(body)

    assert "inv-002" not in clean_title.lower()
    assert "slither-7" not in clean_title.lower()
    assert "cs-1" not in clean_body.lower()
    assert "depth-st-2" not in clean_body.lower()
    assert "l1-h-3" not in clean_body.lower()
    assert "h-1" not in clean_body.lower()
    assert "h-c06" not in clean_body.lower()
    assert "ch-7" not in clean_body.lower()
    assert "H-01" in clean_body


def test_client_sanitizers_remove_verifier_filenames():
    body = "The duplicate was absorbed after reviewing verify_INV-125.md and verify_H-10.md."

    clean_body = D._sanitize_client_body(body)

    assert "verify_INV-125.md" not in clean_body
    assert "verify_H-10.md" not in clean_body
    assert clean_body.count("verifier artifact") == 2


def test_client_sanitizers_remove_verifier_filenames():
    body = "The duplicate was absorbed after reviewing verify_INV-125.md and verify_H-10.md."

    clean_body = D._sanitize_client_body(body)

    assert "verify_INV-125.md" not in clean_body
    assert "verify_H-10.md" not in clean_body
    assert clean_body.count("verifier artifact") == 2


def test_report_template_keeps_internal_traceability_out_of_client_appendix():
    template = (plamen_home() / "rules" / "report-template.md").read_text(
        encoding="utf-8"
    )
    appendix = template.split("## Appendix A:", 1)[1]

    assert "Internal Audit Traceability" not in appendix
    assert "| Internal ID |" not in appendix
    assert "report_index.md" in appendix
    assert "report_coverage.md" in appendix


def test_quality_gate_flags_internal_ids_in_appendix(tmp_path: Path):
    project = tmp_path / "project"
    project.mkdir()
    scratch = project / ".scratchpad"
    scratch.mkdir()
    (project / "AUDIT_REPORT.md").write_text(
        """# Audit Report

## Summary
| Severity | Count |
|---|---:|
| High | 1 |

## High Findings
### [H-01] Report-safe title
Severity: High
Location: src/F.sol:1
Description: This section is intentionally long enough to avoid the stub
guard while keeping the test focused on Appendix privacy. It describes the
client-facing issue without using any internal pipeline identifiers in the
body and continues with additional neutral prose so the section length passes
the minimum quality threshold expected by the report gate.
Impact: Funds can be affected under the described condition.
Recommendation: Apply the described validation before state mutation.

## Appendix A: Excluded Findings
| Internal ID | Severity | Title | Exclusion Reason |
|---|---|---|---|
| inv-002 | Low | internal leak | duplicate |
""",
        encoding="utf-8",
    )
    (scratch / "report_index.md").write_text(
        """## Master Finding Index
| Report ID | Title | Severity | Location | Verification | Trust Adj. | Internal Hypothesis |
|---|---|---|---|---|---|---|
| H-01 | Report-safe title | High | src/F.sol:1 | VERIFIED | - | H-1 |
""",
        encoding="utf-8",
    )

    issues = D._run_report_quality_gate(scratch, str(project))

    assert any("internal IDs leaked" in issue for issue in issues)


def test_quality_gate_flags_internal_hypothesis_and_chain_ids(tmp_path: Path):
    project = tmp_path / "project"
    project.mkdir()
    scratch = project / ".scratchpad"
    scratch.mkdir()
    (project / "AUDIT_REPORT.md").write_text(
        """# Audit Report

## Summary
| Severity | Count |
|---|---:|
| High | 1 |

## High Findings
### [H-01] Report-safe title
**Severity**: High
**Location**: src/F.sol:1
**Description**: This section leaks internal H-1 and CH-7 traceability IDs
while otherwise looking like a normal client finding. It continues with enough
substantive prose to avoid the thin-section guard and keeps the test focused on
privacy scanning rather than content length.
**Impact**: Funds can be affected under the described condition.
**PoC Result**: Code trace reviewed.
**Recommendation**: Apply the described validation before state mutation.
""",
        encoding="utf-8",
    )
    (scratch / "report_index.md").write_text(
        """## Master Finding Index
| Report ID | Title | Severity | Location | Verification | Trust Adj. | Internal Hypothesis |
|---|---|---|---|---|---|---|
| H-01 | Report-safe title | High | src/F.sol:1 | VERIFIED | - | H-1 |
""",
        encoding="utf-8",
    )

    issues = D._run_report_quality_gate(scratch, str(project))

    assert any("internal IDs leaked" in issue for issue in issues)


def test_mechanical_assembler_writes_internal_traceability_outside_client_report(tmp_path: Path):
    project = tmp_path / "project"
    project.mkdir()
    scratch = project / ".scratchpad"
    scratch.mkdir()
    (scratch / "report_index.md").write_text(
        """# Report Index

## Summary

| Severity | Count |
|----------|-------|
| Critical | 0 |
| High | 0 |
| Medium | 1 |
| Low | 0 |
| Informational | 0 |
| Total | 1 |

## Master Finding Index

| Report ID | Title | Severity | Location | Evidence Tag | Verdict | Trust Adj. | Internal Hypothesis ID |
|-----------|-------|----------|----------|--------------|---------|------------|------------------------|
| M-01 | Client title | Medium | src/F.sol:1 | CODE-TRACE | CONFIRMED | | INV-001 |
""",
        encoding="utf-8",
    )
    (scratch / "report_records.json").write_text(
        """{
  "active": [
    {
      "report_id": "M-01",
      "finding_id": "INV-001",
      "absorbed_finding_ids": ["INV-001"],
      "title": "Client title",
      "severity": "Medium"
    }
  ],
  "excluded": [
    {
      "finding_id": "INV-002",
      "title": "Duplicate of INV-002",
      "severity": "Low",
      "reason": "Duplicate of H-1 and CH-7"
    }
  ]
}
""",
        encoding="utf-8",
    )
    (scratch / "report_medium.md").write_text(
        """## Medium Findings

### [M-01] Client title
**Severity**: Medium
**Location**: src/F.sol:1
**Description**: This client-facing section avoids internal pipeline IDs and
contains enough prose to look like a real finding body for assembly tests.
**Impact**: Funds can be affected.
**PoC Result**: Code trace reviewed.
**Recommendation**: Add the missing validation before state mutation.
""",
        encoding="utf-8",
    )

    assert D._assemble_report_python(scratch, str(project)) is True
    report = (project / "AUDIT_REPORT.md").read_text(encoding="utf-8")
    trace = (scratch / "report_traceability_internal.md").read_text(encoding="utf-8")

    assert "Internal Audit Traceability" not in report
    assert "INV-001" not in report
    assert "INV-002" not in report
    assert "H-1" not in report
    assert "CH-7" not in report
    assert "INV-001" in trace


def test_mechanical_assembler_excludes_appendix_ids_from_remediation_order(tmp_path: Path):
    project = tmp_path / "project"
    project.mkdir()
    scratch = project / ".scratchpad"
    scratch.mkdir()
    (scratch / "report_index.md").write_text(
        """# Report Index

## Summary

| Severity | Count |
|----------|-------|
| Critical | 0 |
| High | 0 |
| Medium | 1 |
| Low | 0 |
| Informational | 0 |
| Total | 1 |

## Master Finding Index

| Report ID | Title | Severity | Location | Evidence Tag | Verdict | Trust Adj. | Internal Hypothesis ID |
|-----------|-------|----------|----------|--------------|---------|------------|------------------------|
| M-10 | Active client finding | Medium | src/F.sol:1 | CODE-TRACE | CONFIRMED | | INV-010 |

## Excluded Findings

| Internal ID | Severity | Title | Exclusion Reason |
|-------------|----------|-------|------------------|
| H-20 | Medium | Merged duplicate | Duplicate of M-10 |
""",
        encoding="utf-8",
    )
    (scratch / "report_records.json").write_text(
        """{
  "active": [
    {
      "report_id": "M-10",
      "finding_id": "INV-010",
      "absorbed_finding_ids": ["INV-010"],
      "title": "Active client finding",
      "severity": "Medium"
    }
  ],
  "excluded": [
    {
      "finding_id": "H-20",
      "title": "Merged duplicate",
      "severity": "Medium",
      "reason": "Duplicate of M-10"
    }
  ]
}
""",
        encoding="utf-8",
    )
    (scratch / "report_medium.md").write_text(
        """## Medium Findings

### [M-10] Active client finding
**Severity**: Medium
**Location**: src/F.sol:1
**Description**: This client-facing section contains enough detail to assemble
the report and should be the only remediation-order row from the index.
**Impact**: Funds can be affected.
**PoC Result**: Code trace reviewed.
**Recommendation**: Add the missing validation before state mutation.
""",
        encoding="utf-8",
    )

    assert D._assemble_report_python(scratch, str(project)) is True
    report = (project / "AUDIT_REPORT.md").read_text(encoding="utf-8")
    remediation = report.split("## Priority Remediation Order", 1)[1].split(
        "## Appendix A", 1
    )[0]

    assert "**M-10**" in remediation
    assert "H-20" not in remediation
    assert remediation.count("\n1. ") + remediation.startswith("1. ") == 1


def test_report_coverage_gate_blocks_unaccounted_candidates(tmp_path: Path):
    scratch = tmp_path / ".scratchpad"
    scratch.mkdir()
    (scratch / "report_coverage.md").write_text(
        """# Report Coverage

## Raw Candidate Ledger

| Source Artifact | Candidate ID | Disposition |
|-----------------|--------------|-------------|
| findings_inventory.md | INV-404 | UNACCOUNTED |
""",
        encoding="utf-8",
    )

    issues = D._validate_report_coverage_accounting(scratch)

    assert any("UNACCOUNTED" in issue and "INV-404" in issue for issue in issues)


def test_report_coverage_gate_blocks_unaccounted_prompt_ledger_shape(tmp_path: Path):
    scratch = tmp_path / ".scratchpad"
    scratch.mkdir()
    (scratch / "report_coverage.md").write_text(
        """# Report Coverage

## Raw Candidate Ledger

| Source File | Candidate ID / Label | Severity Signal | Status | Report ID / Refutation / Reason |
|-------------|----------------------|-----------------|--------|---------------------------------|
| findings_inventory.md | INV-404 | High | UNACCOUNTED | n/a |
""",
        encoding="utf-8",
    )

    issues = D._validate_report_coverage_accounting(scratch)

    assert any("UNACCOUNTED" in issue and "INV-404" in issue for issue in issues)


def test_mechanical_report_index_rejects_legacy_poc_demotion_caps(tmp_path: Path):
    scratch = tmp_path / ".scratchpad"
    scratch.mkdir()
    (scratch / "verification_queue.md").write_text(
        """# Verification Queue

| Queue # | Finding ID | Severity | Title | Bug Class | Preferred Tag | Location | Primary Artifact |
|---------|------------|----------|-------|-----------|---------------|----------|------------------|
| 1 | INV-001 | High | Harm disproved | Access Control | CODE-TRACE | src/F.sol:1 | verify_INV-001.md |
""",
        encoding="utf-8",
    )
    (scratch / "verify_INV-001.md").write_text(
        """# Verify INV-001

**Verdict**: CONFIRMED
**Severity**: High
**Location**: src/F.sol:1
**Impact**: Funds can be affected.
""",
        encoding="utf-8",
    )
    (scratch / "poc_demotions.md").write_text(
        """# PoC Fail Demotions

| Finding ID | Original Severity | Capped At | PoC Class | Reason |
|-----------|-------------------|-----------|-----------|--------|
| INV-001 | High | Low | property | invariant violation not reproduced |
""",
        encoding="utf-8",
    )

    assert D._write_mechanical_report_index(scratch) == 1
    index = (scratch / "report_index.md").read_text(encoding="utf-8")

    assert "| H-01 |" in index
    assert "| High |" in index
    assert "POC_FAIL_CAP" not in index


def test_promotion_receipts_accept_lowercase_confirmed_verdict(tmp_path: Path):
    scratch = tmp_path / ".scratchpad"
    scratch.mkdir()
    (scratch / "verify_INV-001.md").write_text(
        """# Verify INV-001

**verdict**: confirmed
Finding INV-001 is confirmed by the verifier.
""",
        encoding="utf-8",
    )

    assert "INV-001" in D._collect_verify_promotion_receipts(scratch)


def test_quality_gate_flags_unbracketed_report_cross_reference(tmp_path: Path):
    project = tmp_path / "project"
    project.mkdir()
    scratch = project / ".scratchpad"
    scratch.mkdir()
    (project / "AUDIT_REPORT.md").write_text(
        """# Audit Report

## Summary
| Severity | Count |
|---|---:|
| High | 1 |

## High Findings
### [H-01] Report-safe title
**Severity**: High
**Location**: src/F.sol:1
**Description**: This section references a related issue; see H-02 for the
other side of the same missing validation. The prose continues long enough to
avoid the thin-section guard while keeping focus on cross-reference parsing.
It contains no internal pipeline identifiers and no stub boilerplate.
**Impact**: Funds can be affected under the described condition.
**PoC Result**: Code trace reviewed.
**Recommendation**: Apply the described validation before state mutation.
""",
        encoding="utf-8",
    )
    (scratch / "report_index.md").write_text(
        """## Master Finding Index
| Report ID | Title | Severity | Location | Verification | Trust Adj. | Internal Hypothesis |
|---|---|---|---|---|---|---|
| H-01 | Report-safe title | High | src/F.sol:1 | VERIFIED | - | H-1 |
""",
        encoding="utf-8",
    )

    issues = D._run_report_quality_gate(scratch, str(project))

    # v2.8.5: dangling cross-references are WARN-only, not halt.
    # Verify the check doesn't halt the pipeline.
    assert not any("undefined report IDs" in issue for issue in issues), (
        "Dangling cross-refs should be WARN, not FAIL after v2.8.5"
    )
