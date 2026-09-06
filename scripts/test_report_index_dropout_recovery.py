"""Regression: report_index dropout recovery must never halt a finished audit.

When the LLM Index Agent drops findings from the Master Finding Index (the live
failure mode that halted a Stellar SC Thorough audit after dropping 91
verify_*.md / coverage-seed IDs), the completeness gate reports a dropout. The
driver's recovery path rebuilds the index deterministically and backfills any
residual non-queue reference IDs into report_coverage.md so the gate passes
instead of halting. These tests cover the two recall-safe helpers that back
that recovery.
"""
import tempfile
from pathlib import Path

import plamen_validators as V


def _write_verify_file(sp: Path, fid: str, location: str = "src/Vault.sol:L42"):
    (sp / f"verify_{fid}.md").write_text(
        f"# Verification: {fid}\n\n"
        "**Verdict**: CONFIRMED\n"
        "**Evidence Tag**: [POC-PASS]\n"
        f"**Location**: {location}\n"
        f"**Description**: Test vulnerability for {fid}.\n"
        "**Recommendation**: Add validation.\n",
        encoding="utf-8",
    )


def _write_partial_master_index(sp: Path, acknowledged: list[str]):
    rows = [
        "# Report Index",
        "",
        "## Master Finding Index",
        "",
        "| Report ID | Title | Severity | Location | Verification | "
        "Trust Adj. | Internal Hypothesis |",
        "|-----------|-------|----------|----------|--------------|"
        "-----------|--------------------|",
    ]
    for i, fid in enumerate(acknowledged, 1):
        rows.append(
            f"| M-0{i} | Bug {fid} | Medium | src/A.sol:L{i} | VERIFIED | - | {fid} |"
        )
    rows += ["", "## Excluded Findings", "", "| Internal ID | Severity | Title | Reason |",
             "|-------------|----------|-------|--------|"]
    (sp / "report_index.md").write_text("\n".join(rows) + "\n", encoding="utf-8")


def test_dropped_ids_detected_exactly():
    with tempfile.TemporaryDirectory() as d:
        sp = Path(d)
        for fid in ("H-1", "H-2", "H-3", "H-4", "H-5"):
            _write_verify_file(sp, fid)
        # LLM index acknowledged only 2 of 5 → 3 dropped.
        _write_partial_master_index(sp, ["H-1", "H-2"])

        # gate sees the dropout
        issues = V._check_index_completeness(sp, write_retry_hint=False)
        assert issues, "gate should flag the dropout"

        dropped = V._report_index_dropped_ids(sp)
        assert set(dropped) == {"H-3", "H-4", "H-5"}, dropped


def test_backfill_makes_gate_pass():
    with tempfile.TemporaryDirectory() as d:
        sp = Path(d)
        for fid in ("H-1", "H-2", "H-3", "H-4", "H-5"):
            _write_verify_file(sp, fid)
        _write_partial_master_index(sp, ["H-1", "H-2"])

        n = V._backfill_report_coverage_dropouts(sp)
        assert n == 3, n

        cov = (sp / "report_coverage.md").read_text(encoding="utf-8")
        for fid in ("H-3", "H-4", "H-5"):
            assert fid in cov
        assert "HUMAN_REVIEW_DELIVERED" in cov
        assert "DEFERRED" not in cov
        assert (sp / "report_dropout_retention.json").is_file()
        assert (sp / "report_semantic_report_dropouts.md").is_file()
        # nothing left UNACCOUNTED → gate passes
        assert "UNACCOUNTED" not in cov

        # after backfill the completeness gate is clean (no halt)
        assert V._report_index_dropped_ids(sp) == []
        assert V._check_index_completeness(sp, write_retry_hint=False) == []


def test_backfill_idempotent_and_noop_when_complete():
    with tempfile.TemporaryDirectory() as d:
        sp = Path(d)
        for fid in ("H-1", "H-2"):
            _write_verify_file(sp, fid)
        _write_partial_master_index(sp, ["H-1", "H-2"])  # fully acknowledged

        # nothing dropped → no backfill rows written
        assert V._report_index_dropped_ids(sp) == []
        assert V._backfill_report_coverage_dropouts(sp) == 0
        # second call on a recovered scratchpad is also a no-op
        assert V._backfill_report_coverage_dropouts(sp) == 0


def test_backfill_noop_without_reference_set():
    with tempfile.TemporaryDirectory() as d:
        sp = Path(d)
        # no verify files, no seed → no reference set → nothing to do
        assert V._report_index_dropped_ids(sp) == []
        assert V._backfill_report_coverage_dropouts(sp) == 0


if __name__ == "__main__":
    test_dropped_ids_detected_exactly()
    test_backfill_makes_gate_pass()
    test_backfill_idempotent_and_noop_when_complete()
    test_backfill_noop_without_reference_set()
    print("all report_index dropout recovery tests passed")
