"""report_index scoping (R1/R2): the index is a MAPPING task over BOUNDED
ledgers; it must NOT bulk-read the 100K+ findings_inventory.md.

R1: the report_index prompt scope forbids reading findings_inventory.md /
    hypotheses.md in full (the context-collapse trigger).
R2: the driver writes report_index_coverage_seed.md -- a SUPERSET ID list from
    bounded ledgers (verification queue + severity binding + finding_mapping +
    dedup absorbed map) -- so completeness is guaranteed mechanically without
    re-reading finding prose.
"""
import re
import shutil
from pathlib import Path

import plamen_driver as D
from plamen_mechanical import apply_llm_dedup_decisions


def _write_queue(tmp_path, finding_ids):
    header = (
        "# Verification Queue Manifest\n"
        "| Queue # | Finding ID | Expected Output File | Severity | Title | "
        "Bug Class | Preferred Tag | Location | Primary Artifact | PoC Class |\n"
        "|---|---|---|---|---|---|---|---|---|---|\n"
    )
    body = ""
    for i, (fid, sev) in enumerate(finding_ids, start=1):
        body += (
            f"| {i} | {fid} | verify_{fid}.md | {sev} | T{i} | logic | "
            f"CODE-TRACE | Foo.sol:L{i} | depth | structural |\n"
        )
    (tmp_path / "verification_queue.md").write_text(header + body, encoding="utf-8")


def _install_receipted_alias(tmp_path: Path, absorbed: str, survivor: str) -> None:
    inventory = (
        f"### Finding [{survivor}]: survivor\n"
        "**Severity**: High\n**Location**: Foo.sol:1-20\n"
        "**Source IDs**: A-1, B-1\n**Root Cause**: same root\n"
        "**Description**: full path\n**Impact**: material\n"
        "**Recommendation**: fix once\n\n"
        f"### Finding [{absorbed}]: member\n"
        "**Severity**: Medium\n**Location**: Foo.sol:2-4\n"
        "**Source IDs**: B-1\n**Root Cause**: same root\n"
        "**Description**: boundary path\n**Impact**: material\n"
        "**Recommendation**: fix once\n"
    )
    (tmp_path / "findings_inventory.md").write_text(inventory, encoding="utf-8")
    (tmp_path / "dedup_decisions.md").write_text(
        f"MERGE: {survivor}, {absorbed}\n", encoding="utf-8"
    )
    assert apply_llm_dedup_decisions(tmp_path, "sc_semantic_dedup") == 1
    shutil.copy2(
        tmp_path / "findings_inventory_deduped.md",
        tmp_path / "findings_inventory.md",
    )


# ── R2: coverage seed is a superset of every bounded ID ───────────────────────

def test_coverage_seed_enumerates_every_queue_id(tmp_path):
    _write_queue(tmp_path, [("INV-001", "High"), ("INV-002", "Medium"),
                            ("INV-003", "Low")])
    n = D._write_report_index_coverage_seed(tmp_path)
    seed = (tmp_path / "report_index_coverage_seed.md").read_text(encoding="utf-8")
    assert n == 3
    for fid in ("INV-001", "INV-002", "INV-003"):
        assert fid in seed, f"{fid} must appear in the coverage seed"
    assert "DRIVER_ENUMERATED" in seed


def test_coverage_seed_includes_dedup_absorbed_and_survivor(tmp_path):
    _write_queue(tmp_path, [("INV-010", "High"), ("INV-011", "Medium")])
    _install_receipted_alias(tmp_path, "INV-011", "INV-010")
    D._write_report_index_coverage_seed(tmp_path)
    seed = (tmp_path / "report_index_coverage_seed.md").read_text(encoding="utf-8")
    assert "INV-010" in seed and "INV-011" in seed
    # The absorbed side records the relation; the survivor records its inverse.
    assert "ABSORBED into INV-010" in seed
    assert "SURVIVOR of INV-011" in seed


def test_coverage_seed_includes_finding_mapping_hypotheses(tmp_path):
    _write_queue(tmp_path, [("INV-020", "High")])
    (tmp_path / "finding_mapping.md").write_text(
        "# Finding Mapping\n\n"
        "| Finding ID | Hypothesis ID | Mapping Status | Notes |\n"
        "|------------|---------------|----------------|-------|\n"
        "| INV-020 | H-5 | confirmed | note |\n"
        "| VS-1 | H-7 | confirmed | note |\n",
        encoding="utf-8",
    )
    D._write_report_index_coverage_seed(tmp_path)
    seed = (tmp_path / "report_index_coverage_seed.md").read_text(encoding="utf-8")
    # Mapped hypothesis carried through, and an ID present ONLY in
    # finding_mapping (VS-1) is still enumerated (superset behavior).
    assert "H-5" in seed
    assert "VS-1" in seed, "an ID present only in finding_mapping must still be seeded"


def test_coverage_seed_does_not_promote_raw_dedup_proposal_to_coverage(tmp_path):
    # Union across all bounded sources -> the seed row count >= the number of
    # distinct IDs in any single source.
    _write_queue(tmp_path, [("INV-100", "High"), ("INV-101", "Medium")])
    (tmp_path / "finding_mapping.md").write_text(
        "# Finding Mapping\n\n"
        "| Finding ID | Hypothesis ID | Mapping Status | Notes |\n"
        "|------------|---------------|----------------|-------|\n"
        "| INV-102 | H-1 | confirmed | n |\n", encoding="utf-8",
    )
    (tmp_path / "dedup_decisions.md").write_text(
        "# Dedup Decisions\n\n| INV-103 | MERGED into INV-100 | c | n |\n",
        encoding="utf-8",
    )
    n = D._write_report_index_coverage_seed(tmp_path)
    seed = (tmp_path / "report_index_coverage_seed.md").read_text(encoding="utf-8")
    for fid in ("INV-100", "INV-101", "INV-102"):
        assert fid in seed
    assert "INV-103" not in seed
    assert n >= 3


def test_coverage_seed_empty_inputs_safe(tmp_path):
    # No bounded artifacts at all -> writes a placeholder, never raises.
    n = D._write_report_index_coverage_seed(tmp_path)
    assert n == 0
    assert (tmp_path / "report_index_coverage_seed.md").exists()


# ── R1: the report_index prompt scope forbids the bulk inventory read ─────────

def test_report_index_scope_forbids_bulk_inventory_read():
    import plamen_prompt as P
    src = Path(P.__file__).read_text(encoding="utf-8")
    # The override block must explicitly forbid bulk-reading the inventory.
    m = re.search(r'phase\.name == "report_index".*?report_critical_high',
                  src, re.DOTALL)
    assert m, "report_index override block not found"
    block = m.group(0)
    assert "Do NOT read `findings_inventory.md`" in block, (
        "report_index scope must forbid bulk-reading findings_inventory.md"
    )
    assert "report_index_coverage_seed.md" in block, (
        "report_index scope must name the bounded coverage seed"
    )


def test_report_prompt_rules_demote_inventory_to_fallback():
    rules = Path(__file__).resolve().parents[1] / "rules" / "phase6-report-prompts.md"
    text = rules.read_text(encoding="utf-8")
    # The Step 6a inputs must mark the inventory fallback-only and name the seed.
    assert "report_index_coverage_seed.md" in text
    assert "fallback-only" in text
    assert "Do NOT bulk-read" in text


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-q"]))


def test_coverage_seed_captures_l1_severity_encoded_ids(tmp_path):
    r"""Regression (feedback_id_regex_catalog): the finding_mapping row regex must
    capture L1 severity-encoded hypothesis IDs (H-C01 / H-M27 / L1-H-12), not just
    SC H-22 / INV-041. A `[A-Za-z]+-\d+` pattern silently dropped these (digits not
    immediately after the dash), under-covering an L1 report. Catalog ALL formats."""
    _write_queue(tmp_path, [("H-C01", "Critical"), ("H-M27", "Medium")])
    # finding_mapping rows: | source-id | hypothesis-id | across mixed formats.
    (tmp_path / "finding_mapping.md").write_text(
        "# Finding Mapping\n"
        "| Source ID | Hypothesis |\n|---|---|\n"
        "| INV-041 | H-C01 |\n"
        "| L1-H-12 | H-M27 |\n"
        "| HL-05 | H-C01 |\n",
        encoding="utf-8",
    )
    D._write_report_index_coverage_seed(tmp_path)
    seed = (tmp_path / "report_index_coverage_seed.md").read_text(encoding="utf-8")
    for fid in ("H-C01", "H-M27", "INV-041", "L1-H-12", "HL-05"):
        assert fid in seed, f"{fid} (L1/mixed format) must appear in the coverage seed"
