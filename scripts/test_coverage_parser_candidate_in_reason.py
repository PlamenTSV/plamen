"""Regression: coverage-ledger parser must not treat prose containing the word
"candidate" as a table header.

Live failure (a prior Opus rerun): the LLM coverage ledger had data rows whose
Reason column said e.g. "auto-mapped depth candidate, no verifier verdict".
_collect_report_coverage_acknowledged_ids detected "candidate" anywhere in a
row and treated that DATA row as a header, flipping id_col to the reason
column. Every following row's ID was then read from the wrong column, so real
acknowledgments (INV-139 -> H-115, etc.) were lost -> the completeness gate
falsely reported dropped IDs -> report_index halted. Fix: only treat a cell as
an ID header when it is an actual header LABEL, not prose containing the word.
"""
import tempfile
import json
from pathlib import Path

import plamen_validators as V


def _write(sp, body):
    (sp / "report_coverage.md").write_text(body, encoding="utf-8")


def _authorize_human_review(sp: Path, *ids: str) -> None:
    for fid in ids:
        (sp / f"verify_{fid}.md").write_text(
            f"# Verification: {fid}\n\n**Verdict**: CONTESTED\n",
            encoding="utf-8",
        )
    V._materialize_report_dropout_retention(sp, list(ids))


def test_data_row_reason_with_candidate_word_is_not_a_header():
    with tempfile.TemporaryDirectory() as d:
        sp = Path(d)
        _authorize_human_review(sp, "DX-1", "INV-139", "INV-001")
        _write(sp,
            "# Report Coverage\n\n"
            "## Raw Candidate Ledger\n"
            "| Source File | Candidate ID / Label | Severity Signal | Status | Report ID / Refutation / Reason |\n"
            "|---|---|---|---|---|\n"
            "| finding_mapping.md | DX-1 | (none) | HUMAN_REVIEW_DELIVERED | auto-mapped depth candidate, no verdict |\n"
            "| finding_mapping.md | INV-139 | - | HUMAN_REVIEW_DELIVERED | retained |\n"
            "| finding_mapping.md | INV-001 | - | HUMAN_REVIEW_DELIVERED | retained |\n"
        )
        ack = V._collect_report_coverage_acknowledged_ids(sp)
        # The row whose Reason contains "candidate" must NOT corrupt parsing:
        # INV-139 and INV-001 (in the real Candidate-ID column) must be acknowledged.
        assert "INV-139" in ack, ack
        assert "INV-001" in ack, ack
        assert "DX-1" in ack, ack


def test_real_header_still_detected():
    with tempfile.TemporaryDirectory() as d:
        sp = Path(d)
        _authorize_human_review(sp, "INV-7")
        _write(sp,
            "## Coverage Ledger\n"
            "| Candidate ID | Status | Reason |\n"
            "|---|---|---|\n"
            "| INV-7 | HUMAN_REVIEW_DELIVERED | retained |\n"
        )
        ack = V._collect_report_coverage_acknowledged_ids(sp)
        assert "INV-7" in ack, ack


def test_unaccounted_still_excluded():
    with tempfile.TemporaryDirectory() as d:
        sp = Path(d)
        _authorize_human_review(sp, "INV-8", "INV-9")
        _write(sp,
            "## Raw Candidate Ledger\n"
            "| Source File | Candidate ID / Label | Severity Signal | Status | Reason |\n"
            "|---|---|---|---|---|\n"
            "| x | INV-9 | - | UNACCOUNTED | not handled |\n"
            "| x | INV-8 | - | HUMAN_REVIEW_DELIVERED | retained |\n"
        )
        ack = V._collect_report_coverage_acknowledged_ids(sp)
        assert "INV-8" in ack
        assert "INV-9" not in ack  # UNACCOUNTED is not an acknowledgment


def test_backfill_into_midfile_ledger_is_parser_visible():
    """When a ledger section already exists mid-file (followed by later
    sections), backfilled rows must land INSIDE that section so the parser
    reads them. (The EOF-append bug put them after later sections -> invisible.)
    Validated directly on the acknowledged-ID parser rather than the seed path.
    """
    with tempfile.TemporaryDirectory() as d:
        sp = Path(d)
        (sp / "verify_INV-50.md").write_text(
            "# Verification: INV-50\n\n**Verdict**: CONTESTED\n",
            encoding="utf-8",
        )
        _write(sp,
            "## Raw Candidate Ledger\n"
            "| Source File | Candidate ID / Label | Severity Signal | Status | Reason |\n"
            "|---|---|---|---|---|\n"
            "| m | H-1 | High | PROMOTED | depth candidate discussed |\n"
            "## Promotion Failures Repaired\n| a | b | c |\n|---|---|---|\n"
        )
        assert V._backfill_report_coverage_dropouts(sp) == 1
        text = (sp / "report_coverage.md").read_text(encoding="utf-8")
        assert text.index("INV-50") < text.index("## Promotion Failures Repaired")
        ack = V._collect_report_coverage_acknowledged_ids(sp)
        assert "INV-50" in ack, ack  # row inside the ledger is parser-visible


def test_renderer_merged_prose_is_not_consolidation_authority():
    """A coverage row cannot replace an applied-alias receipt."""

    with tempfile.TemporaryDirectory() as d:
        sp = Path(d)
        (sp / "report_records.json").write_text(
            json.dumps({
                "active": [{
                    "report_id": "H-01",
                    "finding_id": "INV-001",
                    "title": "live survivor",
                }],
                "excluded": [],
            }),
            encoding="utf-8",
        )
        _write(
            sp,
            "# Report Coverage\n\n"
            "| Candidate ID | Status | Reason |\n"
            "|---|---|---|\n"
            "| INV-002 | MERGED | consolidated into H-01 |\n",
        )

        mapped = V._ensure_report_consolidation_map(sp, str(sp))

        assert mapped == 0
        assert not (sp / "report_consolidation_internal.md").exists()


if __name__ == "__main__":
    import pytest, sys
    sys.exit(pytest.main([__file__, "-q"]))
