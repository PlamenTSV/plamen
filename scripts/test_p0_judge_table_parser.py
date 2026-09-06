"""Tests for v2.0.5 P0 — judge table parser + judge_decisions.json sidecar.

Covers:
  P0.1  _parse_skeptic_judge_table (in plamen_parsers)
        _collect_judge_unresolved_ids table-parse strategy
        _collect_judge_downgrade_map shared-parser refactor
  P0.2  write_judge_decisions_json_sidecar (in plamen_parsers)
        read_judge_decisions_json_sidecar
        consumer precedence (JSON-when-fresh, MD-fallback)

An observed halt was caused by the parser/prompt schema drift —
prompt produced table format; parser required H2 sections; UNRESOLVED set
was empty; report_index authenticity gate halted. Fixtures here are
synthetic (NOT past-audit scratchpad copies) to avoid overfitting.
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS_DIR))

from plamen_parsers import (  # noqa: E402
    _parse_skeptic_judge_table,
    read_judge_decisions_json_sidecar,
    write_judge_decisions_json_sidecar,
)
from plamen_validators import (  # noqa: E402
    _collect_judge_downgrade_map,
    _collect_judge_unresolved_ids,
)


_TABLE_FIXTURE = """# Skeptic-Judge Decisions

> Phase 5.1 — Adversarial Verification Output

| Finding ID | Original Severity | Final Severity | Decision | Rationale |
|------------|-------------------|----------------|----------|-----------|
| H-01 | High | High | KEEP | Mechanical [POC-PASS]; verifier wins. |
| H-02 | High | Medium | UNRESOLVED | Skeptic disagrees on threat model. |
| H-03 | High | Medium | DOWNGRADE | Verifier overstated severity. |
| H-04 | Critical | Critical | KEEP | [POC-PASS] confirmed direct loss. |
| H-05 | Medium | Low | PARTIAL | Conditional impact; demote one tier. |

## Summary Statistics

| Decision | Count |
|----------|-------|
| KEEP | 2 |
| UNRESOLVED | 1 |
| DOWNGRADE | 1 |
| PARTIAL | 1 |
"""


_LEGACY_H2_FIXTURE = """# Skeptic Judge Decisions (legacy format)

## H-10

**Verdict**: UNRESOLVED
Skeptic and verifier disagree on the cross-chain trust model.

## H-11

**Verdict**: KEEP
Mechanical evidence is decisive.

## H-12

**Verdict**: PARTIAL
Only the on-chain side is testable.
"""


# ---------------------------------------------------------------------------
# P0.1 — table parser
# ---------------------------------------------------------------------------


def test_p01_parse_table_returns_all_rows():
    """Shared parser returns every data row with normalized fields."""
    rows = _parse_skeptic_judge_table(_TABLE_FIXTURE)
    assert len(rows) == 5
    ids = [r["finding_id"] for r in rows]
    assert ids == ["H-01", "H-02", "H-03", "H-04", "H-05"]
    decisions = [r["decision"] for r in rows]
    assert decisions == ["KEEP", "UNRESOLVED", "DOWNGRADE", "KEEP", "PARTIAL"]


def test_p01_parse_table_skips_header_and_separator():
    """Header row 'Finding ID' and '|---|---|...' separator are skipped."""
    rows = _parse_skeptic_judge_table(_TABLE_FIXTURE)
    # No row should have 'Finding ID' as its finding_id.
    assert not any(r["finding_id"].lower().startswith("finding") for r in rows)
    # No row should have a dash-only first cell.
    assert not any(r["finding_id"].startswith("-") for r in rows)


def test_p01_parse_table_returns_empty_on_no_table():
    """Files with NO pipe-table rows return [] (caller falls back)."""
    assert _parse_skeptic_judge_table("# Just a title\n\nSome prose.\n") == []
    assert _parse_skeptic_judge_table(_LEGACY_H2_FIXTURE) == []


def test_p01_parse_table_tolerates_bold_decoration():
    """`| H-X | High | Medium | **UNRESOLVED** | ... |` still parses."""
    text = (
        "| Finding ID | OS | FS | Decision | R |\n"
        "|---|---|---|---|---|\n"
        "| H-99 | High | Medium | **UNRESOLVED** | bold case |\n"
    )
    rows = _parse_skeptic_judge_table(text)
    assert len(rows) == 1
    assert rows[0]["decision"] == "UNRESOLVED"


# ---------------------------------------------------------------------------
# P0.1 — _collect_judge_unresolved_ids
# ---------------------------------------------------------------------------


def test_p01_collect_unresolved_from_table(tmp_path):
    """v2 prompt's table format: parser returns UNRESOLVED + PARTIAL IDs."""
    (tmp_path / "skeptic_judge_decisions.md").write_text(
        _TABLE_FIXTURE, encoding="utf-8"
    )
    ids = _collect_judge_unresolved_ids(tmp_path)
    # H-02 UNRESOLVED + H-05 PARTIAL remain visible disagreement states.
    assert ids == {"H-02", "H-05"}


def test_p01_collect_unresolved_from_legacy_h2(tmp_path):
    """Non-regression: pre-table H2-section format still works."""
    (tmp_path / "skeptic_judge_decisions.md").write_text(
        _LEGACY_H2_FIXTURE, encoding="utf-8"
    )
    ids = _collect_judge_unresolved_ids(tmp_path)
    # H-10 UNRESOLVED + H-12 PARTIAL.
    assert ids == {"H-10", "H-12"}


def test_p01_collect_unresolved_empty_when_no_file(tmp_path):
    """No skeptic_judge_decisions.md and no judge_*.md → empty set."""
    assert _collect_judge_unresolved_ids(tmp_path) == set()


def test_p01_collect_downgrade_map_from_table(tmp_path):
    """Legacy DOWNGRADE rows are proposals, never severity authority."""
    (tmp_path / "skeptic_judge_decisions.md").write_text(
        _TABLE_FIXTURE, encoding="utf-8"
    )
    dm = _collect_judge_downgrade_map(tmp_path)
    assert dm == {}


# ---------------------------------------------------------------------------
# P0.2 — judge_decisions.json sidecar
# ---------------------------------------------------------------------------


def test_p02_sidecar_writer_round_trip(tmp_path):
    """Write JSON from MD; read back; semantic equivalence."""
    (tmp_path / "skeptic_judge_decisions.md").write_text(
        _TABLE_FIXTURE, encoding="utf-8"
    )
    n = write_judge_decisions_json_sidecar(tmp_path)
    assert n == 5
    assert (tmp_path / "judge_decisions.json").exists()
    rows = read_judge_decisions_json_sidecar(tmp_path)
    assert len(rows) == 5
    assert [r["finding_id"] for r in rows] == [
        "H-01", "H-02", "H-03", "H-04", "H-05"
    ]


def test_p02_sidecar_idempotent_rewrite(tmp_path):
    """Re-writing the sidecar with the same content does NOT bump mtime."""
    (tmp_path / "skeptic_judge_decisions.md").write_text(
        _TABLE_FIXTURE, encoding="utf-8"
    )
    write_judge_decisions_json_sidecar(tmp_path)
    sidecar = tmp_path / "judge_decisions.json"
    mtime_1 = sidecar.stat().st_mtime_ns
    time.sleep(0.05)
    write_judge_decisions_json_sidecar(tmp_path)
    mtime_2 = sidecar.stat().st_mtime_ns
    assert mtime_1 == mtime_2, "Idempotent re-write bumped mtime"


def test_p02_sidecar_preferred_when_fresh(tmp_path):
    """Sidecar fresher than MD → consumer uses sidecar (faster path)."""
    (tmp_path / "skeptic_judge_decisions.md").write_text(
        _TABLE_FIXTURE, encoding="utf-8"
    )
    write_judge_decisions_json_sidecar(tmp_path)
    # Both consumers should now use the JSON path.
    ids = _collect_judge_unresolved_ids(tmp_path)
    assert ids == {"H-02", "H-05"}
    dm = _collect_judge_downgrade_map(tmp_path)
    assert dm == {}


def test_p02_sidecar_skipped_when_md_newer(tmp_path):
    """MD modified after sidecar → reader returns [] so caller falls back."""
    md = tmp_path / "skeptic_judge_decisions.md"
    md.write_text(_TABLE_FIXTURE, encoding="utf-8")
    write_judge_decisions_json_sidecar(tmp_path)
    time.sleep(1.2)  # mtime granularity safety
    md.touch()
    rows = read_judge_decisions_json_sidecar(tmp_path)
    assert rows == [], "Stale sidecar should be ignored"
    # _collect_judge_unresolved_ids falls back to MD parser and STILL works.
    ids = _collect_judge_unresolved_ids(tmp_path)
    assert ids == {"H-02", "H-05"}


def test_p02_sidecar_schema_version(tmp_path):
    """Sidecar carries the documented schema_version."""
    (tmp_path / "skeptic_judge_decisions.md").write_text(
        _TABLE_FIXTURE, encoding="utf-8"
    )
    write_judge_decisions_json_sidecar(tmp_path)
    payload = json.loads(
        (tmp_path / "judge_decisions.json").read_text(encoding="utf-8")
    )
    assert payload["schema_version"] == "plamen.judge_decisions.v1"
    assert payload["row_count"] == 5
    assert payload["source_markdown"] == "skeptic_judge_decisions.md"


def test_p02_sidecar_writer_returns_zero_on_no_table(tmp_path):
    """File exists but has no table → writer returns 0, no sidecar written."""
    (tmp_path / "skeptic_judge_decisions.md").write_text(
        "# Just prose\nNo tables here.\n", encoding="utf-8"
    )
    n = write_judge_decisions_json_sidecar(tmp_path)
    assert n == 0
    assert not (tmp_path / "judge_decisions.json").exists()


# ---------------------------------------------------------------------------
# Codex-required hardening tests (P0.1 cell validation + P0.2 source hash)
# ---------------------------------------------------------------------------

_ADVERSARIAL_FIXTURE = """# Skeptic Judge Decisions

| Finding ID | Original Severity | Final Severity | Decision | Rationale |
|------------|-------------------|----------------|----------|-----------|
| H-01 | High | High | KEEP | mechanical proof |
| H-02 | High | Medium | UNRESOLVED | skeptic disagrees |

## Evidence Integrity Notes

Some prose...

| Category | Source | Tag | Summary | Detail |
|----------|--------|-----|---------|--------|
| code-trace | verify_H-01.md | [POC-PASS] | TestSuite | full trace |
| poc-pass | verify_H-02.md | KEEP | OtherTest | run passed |

## Severity Changes

| Component | Action | Note | Owner | Rationale |
|---|---|---|---|---|
| Pricing | adjust | UNRESOLVED | team | scope creep |
"""


def test_parse_judge_table_ignores_non_finding_tables():
    """Codex fix 1: a 4+ column table whose first cell is prose (not a
    valid finding ID) must NOT contribute rows. Otherwise an unrelated
    later table can invent fake UNRESOLVED rows.
    """
    rows = _parse_skeptic_judge_table(_ADVERSARIAL_FIXTURE)
    # Only H-01 (KEEP) and H-02 (UNRESOLVED) from the real decision table.
    assert len(rows) == 2
    finding_ids = {r["finding_id"] for r in rows}
    assert finding_ids == {"H-01", "H-02"}
    # No "Category", "code-trace", "poc-pass", "Pricing" — those are
    # cells from the unrelated tables.
    for noise in ("Category", "code-trace", "poc-pass", "Pricing", "Summary"):
        assert noise not in finding_ids


def test_parse_judge_table_requires_allowed_decision():
    """Codex fix 1: a 4+ column table whose Decision cell is not in the
    allowed token set must NOT contribute rows.
    """
    bad_decision_table = (
        "| Finding ID | OS | FS | Decision | R |\n"
        "|---|---|---|---|---|\n"
        "| H-50 | High | High | SUMMARY | not a real decision |\n"
        "| H-51 | High | High | TestSuite | also not a decision |\n"
        "| H-52 | High | Medium | UNRESOLVED | this one IS valid |\n"
    )
    rows = _parse_skeptic_judge_table(bad_decision_table)
    # Only H-52 should survive — H-50 and H-51 have invalid decisions.
    assert len(rows) == 1
    assert rows[0]["finding_id"] == "H-52"
    assert rows[0]["decision"] == "UNRESOLVED"


def test_judge_sidecar_rejected_when_source_hash_changes(tmp_path):
    """Codex fix 2: source rewritten with different content but identical
    mtime_ns (or within mtime tolerance) must invalidate the sidecar via
    the sha256 fingerprint mismatch.
    """
    md = tmp_path / "skeptic_judge_decisions.md"
    md.write_text(
        "| Finding ID | OS | FS | Decision | R |\n"
        "|---|---|---|---|---|\n"
        "| H-99 | High | Medium | UNRESOLVED | original |\n",
        encoding="utf-8",
    )
    write_judge_decisions_json_sidecar(tmp_path)
    # Rewrite source with DIFFERENT content (different hash).
    md.write_text(
        "| Finding ID | OS | FS | Decision | R |\n"
        "|---|---|---|---|---|\n"
        "| H-99 | High | High | KEEP | content changed |\n",
        encoding="utf-8",
    )
    # Reader must reject the stale sidecar (sha256 mismatch).
    rows = read_judge_decisions_json_sidecar(tmp_path)
    assert rows == [], f"Sidecar should be rejected on hash mismatch, got: {rows}"


def test_judge_sidecar_rejected_when_source_mtime_ns_changes(tmp_path):
    """Codex fix 2: even if hash content is unchanged, an explicit mtime_ns
    bump (touch) should reject the stale sidecar. This catches the case
    where the source is "modified" (e.g., re-saved by an editor) with
    identical bytes.
    """
    md = tmp_path / "skeptic_judge_decisions.md"
    md.write_text(
        "| Finding ID | OS | FS | Decision | R |\n"
        "|---|---|---|---|---|\n"
        "| H-99 | High | Medium | UNRESOLVED | original |\n",
        encoding="utf-8",
    )
    write_judge_decisions_json_sidecar(tmp_path)
    # Re-write IDENTICAL content but the rewrite bumps mtime_ns.
    import time as _t
    _t.sleep(0.05)
    md.write_text(
        "| Finding ID | OS | FS | Decision | R |\n"
        "|---|---|---|---|---|\n"
        "| H-99 | High | Medium | UNRESOLVED | original |\n",
        encoding="utf-8",
    )
    # Hash will be identical, but mtime_ns will differ. The reader should
    # reject because mtime_ns is part of the fingerprint contract.
    rows = read_judge_decisions_json_sidecar(tmp_path)
    assert rows == [], (
        "Sidecar should be rejected when source mtime_ns differs even with "
        f"identical content: got {rows}"
    )


def test_judge_sidecar_legacy_format_rejected(tmp_path):
    """Pre-Codex-hardening sidecars (no source_mtime_ns/source_sha256
    fields) must be rejected so the writer re-creates a hardened sidecar.
    """
    md = tmp_path / "skeptic_judge_decisions.md"
    md.write_text(
        "| Finding ID | OS | FS | Decision | R |\n"
        "|---|---|---|---|---|\n"
        "| H-99 | High | Medium | UNRESOLVED | r |\n",
        encoding="utf-8",
    )
    # Write a legacy-format sidecar (no fingerprint fields).
    legacy = {
        "schema_version": "plamen.judge_decisions.v1",
        "source_markdown": "skeptic_judge_decisions.md",
        "generated_at": "2026-01-01T00:00:00+00:00",
        "row_count": 1,
        "decisions": [{
            "finding_id": "H-99", "original_severity": "High",
            "final_severity": "Medium", "decision": "UNRESOLVED",
            "rationale": "r",
        }],
    }
    (tmp_path / "judge_decisions.json").write_text(
        json.dumps(legacy, indent=2), encoding="utf-8"
    )
    # Reader should reject (missing fingerprint).
    rows = read_judge_decisions_json_sidecar(tmp_path)
    assert rows == [], f"Legacy sidecar should be rejected, got: {rows}"
