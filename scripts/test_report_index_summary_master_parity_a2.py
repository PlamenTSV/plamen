"""A2 report_index Summary <-> Master Finding Index reconciliation.

Observed failure shape: the Index Agent `## Summary` count table claimed 45
findings while the Master Finding Index actually listed 74 distinct report IDs.
Tier writers dispatched against that inconsistent index then hallucinated ghost
IDs to fill the 45->74 gap, producing report findings with no backing section.

The pure derivation is the upstream root fix at report_index: the Master
Finding Index is the cardinality contract, so the canonical DRIVER successor
publishes a derived `## Summary` table that matches the distinct Master
report-ID set. The observational validator never writes raw or canonical
artifacts. A consistent index is a byte-identical derivation.

Run: pytest scripts/test_report_index_summary_master_parity_a2.py -q
"""
from __future__ import annotations

import re
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import plamen_validators as V  # noqa: E402


def _mk_index(
    scratchpad: Path,
    *,
    summary: dict[str, int],
    master: dict[str, int],
) -> None:
    """Write a report_index.md whose `## Summary` reflects `summary` and whose
    Master Finding Index lists `master[tier]` distinct report rows per tier."""
    sev_names = {
        "C": "Critical", "H": "High", "M": "Medium", "L": "Low", "I": "Informational"
    }
    summary_total = sum(summary.values())
    lines = [
        "# Report Index", "",
        "## Summary Counts", "",
        "| Severity | Count |", "|----------|-------|",
    ]
    for char in ("C", "H", "M", "L", "I"):
        lines.append(f"| {sev_names[char]} | {summary.get(char, 0)} |")
    lines += [f"| Total | {summary_total} |", "",
              "## Master Finding Index", "",
              "| Report ID | Title | Severity | Location | Verification | "
              "Trust Adj. | Internal Hypothesis |",
              "|-----------|-------|----------|----------|--------------|"
              "-----------|--------------------|"]
    for char in ("C", "H", "M", "L", "I"):
        for i in range(1, master.get(char, 0) + 1):
            lines.append(
                f"| {char}-{i:02d} | finding {char}{i} | {sev_names[char]} | "
                f"src/F.sol:L{i} | VERIFIED | - | H-{char}{i} |"
            )
    lines.append("")
    (scratchpad / "report_index.md").write_text("\n".join(lines), encoding="utf-8")


def _summary_count(scratchpad: Path, sev_name: str) -> int:
    txt = (scratchpad / "report_index.md").read_text(encoding="utf-8")
    m = re.search(rf"\|\s*{sev_name}\s*\|\s*(\d+)\s*\|", txt)
    return int(m.group(1)) if m else -1


def _summary_count_bytes(raw: bytes, sev_name: str) -> int:
    txt = raw.decode("utf-8", errors="strict")
    m = re.search(rf"\|\s*{sev_name}\s*\|\s*(\d+)\s*\|", txt)
    return int(m.group(1)) if m else -1


def _master_row_count(scratchpad: Path) -> int:
    return len(V._parse_master_finding_index_rows(scratchpad))


# --------------------------------------------------------------------------- #
# A2: drift shape — Summary disagrees with Master -> repair to Master.
# --------------------------------------------------------------------------- #
def test_a2_drift_shape_summary_repaired_to_master_cardinality():
    """Summary=45 Medium but Master lists 74 distinct Medium IDs -> the gate
    rewrites the Summary to 74 and flags the inconsistency."""
    d = Path(tempfile.mkdtemp())
    _mk_index(d, summary={"M": 45}, master={"M": 74})

    master_before = _master_row_count(d)
    raw = (d / "report_index.md").read_bytes()
    derivation = V.derive_report_index_summary_master_parity(raw)
    notes = V.validate_report_index_summary_master_parity(d)

    assert notes, "drift must be flagged"
    assert any("Master" in n for n in notes)
    assert derivation.repair_required
    assert _summary_count_bytes(derivation.output_bytes, "Medium") == 74
    assert _summary_count_bytes(derivation.output_bytes, "Total") == 74
    # Observation cannot rewrite the raw MODEL/canonical pointer.
    assert (d / "report_index.md").read_bytes() == raw
    # Master rows themselves are untouched (no findings added/dropped).
    assert _master_row_count(d) == master_before == 74


def test_a2_multi_tier_drift_all_repaired():
    """Drift across several tiers all get reconciled to the Master set."""
    d = Path(tempfile.mkdtemp())
    _mk_index(
        d,
        summary={"C": 1, "H": 2, "M": 3, "L": 0, "I": 0},
        master={"C": 2, "H": 5, "M": 10, "L": 4, "I": 1},
    )
    raw = (d / "report_index.md").read_bytes()
    derivation = V.derive_report_index_summary_master_parity(raw)
    notes = V.validate_report_index_summary_master_parity(d)
    assert notes
    assert _summary_count_bytes(derivation.output_bytes, "Critical") == 2
    assert _summary_count_bytes(derivation.output_bytes, "High") == 5
    assert _summary_count_bytes(derivation.output_bytes, "Medium") == 10
    assert _summary_count_bytes(derivation.output_bytes, "Low") == 4
    assert _summary_count_bytes(derivation.output_bytes, "Informational") == 1
    assert _summary_count_bytes(derivation.output_bytes, "Total") == 22
    assert (d / "report_index.md").read_bytes() == raw


# --------------------------------------------------------------------------- #
# A2: consistent index -> NO false flag, NO rewrite.
# --------------------------------------------------------------------------- #
def test_a2_consistent_index_no_false_flag():
    """Summary == distinct Master report-ID set per tier -> no flag, no edit."""
    d = Path(tempfile.mkdtemp())
    _mk_index(
        d,
        summary={"C": 1, "H": 2, "M": 5, "L": 3, "I": 1},
        master={"C": 1, "H": 2, "M": 5, "L": 3, "I": 1},
    )
    before = (d / "report_index.md").read_text(encoding="utf-8")

    notes = V.validate_report_index_summary_master_parity(d)

    assert notes == [], "consistent index must NOT be flagged"
    # File left byte-identical (no spurious rewrite).
    assert (d / "report_index.md").read_text(encoding="utf-8") == before


def test_a2_master_total_equals_summary_total_after_repair():
    """Post-repair, the distinct Master report-ID count equals the Summary
    total — the invariant tier writers rely on."""
    d = Path(tempfile.mkdtemp())
    _mk_index(d, summary={"M": 3}, master={"C": 1, "H": 1, "M": 12, "L": 2})
    raw = (d / "report_index.md").read_bytes()
    derivation = V.derive_report_index_summary_master_parity(raw)
    V.validate_report_index_summary_master_parity(d)
    distinct_master = len(V._distinct_master_report_ids(d))
    assert (
        _summary_count_bytes(derivation.output_bytes, "Total")
        == distinct_master
        == 16
    )
    assert (d / "report_index.md").read_bytes() == raw


# --------------------------------------------------------------------------- #
# A2: defensive — missing/empty index is a NO-OP, never a crash.
# --------------------------------------------------------------------------- #
def test_a2_missing_index_is_noop():
    d = Path(tempfile.mkdtemp())  # no report_index.md at all
    assert V.validate_report_index_summary_master_parity(d) == []


def test_a2_no_master_rows_is_noop():
    """report_index.md exists with a Summary but NO Master rows -> nothing to
    reconcile against; do not touch the Summary (no false flag)."""
    d = Path(tempfile.mkdtemp())
    (d / "report_index.md").write_text(
        "\n".join([
            "# Report Index", "",
            "## Summary Counts", "",
            "| Severity | Count |", "|----------|-------|",
            "| Medium | 7 |", "| Total | 7 |", "",
            "## Master Finding Index", "",
            "(no rows yet)", "",
        ]),
        encoding="utf-8",
    )
    before = (d / "report_index.md").read_text(encoding="utf-8")
    assert V.validate_report_index_summary_master_parity(d) == []
    assert (d / "report_index.md").read_text(encoding="utf-8") == before
