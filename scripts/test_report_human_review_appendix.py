"""Degrade-with-flag items (report_semantic_*.md) must be DELIVERED in the report.

The late-stage gates that degrade-with-flag instead of halting
(obligation/retention via _validate_report_coverage_semantic_contract, shared by
SC + L1; severity-provenance via the L1 report-parity fix) write deferred items
to report_semantic_*.md "for human review". But the scratchpad is cleaned on
success and the client never reads it, so the flag never reached the human.

_build_human_review_appendix folds any report_semantic_*.md into
"## Appendix B: Flagged for Human Review" in AUDIT_REPORT.md. The assembler is
shared, so this covers SC and L1 in one place.
"""
from pathlib import Path

import plamen_mechanical as M


def test_appendix_built_from_known_semantic_files(tmp_path: Path):
    (tmp_path / "report_semantic_retention_risks.md").write_text(
        "# Retention Risks\n\n| Candidate | Status | Reason |\n|---|---|---|\n"
        "| msg.value<->amount binding | DEFERRED | exact value binding remained "
        "uncovered in the promoted set |\n",
        encoding="utf-8",
    )
    (tmp_path / "report_semantic_severity_repairs.md").write_text(
        "# Severity Repairs\n\nH-02 severity inflation could not be auto-resolved "
        "by the provenance repair; reviewer should confirm the final tier.\n",
        encoding="utf-8",
    )
    out = M._build_human_review_appendix(tmp_path)
    assert "Retention / obligation coverage" in out
    assert "Severity-provenance adjustments" in out
    assert "msg.value" in out
    assert "inflation" in out
    # the source files' leading H1 is dropped, body retained
    assert "# Retention Risks" not in out
    assert "# Severity Repairs" not in out


def test_appendix_empty_when_no_semantic_files(tmp_path: Path):
    assert M._build_human_review_appendix(tmp_path) == ""


def test_appendix_skips_trivial_body(tmp_path: Path):
    # H1 only, no substantive body -> skipped (not a hollow appendix entry)
    (tmp_path / "report_semantic_retention_risks.md").write_text(
        "# Retention Risks\n", encoding="utf-8"
    )
    assert M._build_human_review_appendix(tmp_path) == ""


def test_appendix_includes_unknown_semantic_file(tmp_path: Path):
    (tmp_path / "report_semantic_custom_flags.md").write_text(
        "# Custom\n\nSomething substantive was flagged for review here, well over "
        "the twenty-character minimum body length.\n",
        encoding="utf-8",
    )
    out = M._build_human_review_appendix(tmp_path)
    assert "Custom Flags" in out
    assert "substantive was flagged" in out


def test_appendix_delivers_depth_finalization_failure(tmp_path: Path):
    (tmp_path / "depth_finalization_human_review.md").write_text(
        "# Depth Finalization — Human Review Required\n\n"
        "**Status**: DEGRADED_HUMAN_REVIEW\n\n"
        "| Processor | Error |\n|---|---|\n"
        "| enumeration_gate | RuntimeError: graph parser failed |\n",
        encoding="utf-8",
    )

    out = M._build_human_review_appendix(tmp_path)

    assert "Depth recall-postprocessor finalization" in out
    assert "enumeration_gate" in out
    assert "graph parser failed" in out


def test_appendix_uses_authoritative_finalization_json_when_markdown_missing(
    tmp_path: Path,
):
    (tmp_path / "depth_finalization_receipt.json").write_text(
        '{"status":"DEGRADED_HUMAN_REVIEW","processors":{'
        '"variant_gate":{"status":"FAILED","error":"structural output vanished"}}}',
        encoding="utf-8",
    )

    out = M._build_human_review_appendix(tmp_path)

    assert "Depth recall-postprocessor finalization" in out
    assert "variant_gate" in out
    assert "structural output vanished" in out


def test_appendix_delivered_in_assembled_report(tmp_path: Path):
    """End-to-end: the appendix actually reaches AUDIT_REPORT.md."""
    sp = tmp_path / "sp"
    sp.mkdir()
    (sp / "report_index.md").write_text(
        "## Summary\n\n"
        "| Severity | Count |\n|----------|-------|\n"
        "| High | 1 |\n| Medium | 0 |\n\n"
        "## Master Finding Index\n\n"
        "| Report ID | Title | Severity | Internal ID |\n"
        "|-----------|-------|----------|-------------|\n"
        "| H-01 | example replay finding | High | INV-01 |\n",
        encoding="utf-8",
    )
    (sp / "report_critical_high.md").write_text(
        "## High Findings\n\n"
        "### [H-01] example replay finding\n\n"
        "**Severity**: High\n\n"
        "Body describing the issue in adequate detail for the quality gate.\n\n"
        "**Impact**:\nReplay can invalidate accounting.\n\n"
        "**PoC Result**:\nCode trace confirms the replay path.\n",
        encoding="utf-8",
    )
    (sp / "report_medium.md").write_text("", encoding="utf-8")
    (sp / "report_semantic_retention_risks.md").write_text(
        "# Retention Risks\n\nmsg.value<->amount exact-value binding remained "
        "uncovered in the promoted set; reviewer should confirm coverage.\n",
        encoding="utf-8",
    )
    project = tmp_path / "proj"
    project.mkdir()
    ok = M._assemble_report_python(sp, str(project))
    assert ok is True, "assembler returned False on the minimal fixture"
    report = (project / "AUDIT_REPORT.md").read_text(encoding="utf-8")
    assert "## Appendix B: Flagged for Human Review" in report
    assert ("msg.value" in report) or ("exact-value binding" in report)
