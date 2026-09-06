"""Tests for the ZERO-DATA-LOSS mechanical dedup gates in plamen_mechanical.py.

Covers:
- survivor-superset gate (flip / keep-separate)
- aggregate-source-ID guard (>4 source IDs suppresses subset/PERT merge)
- content coupling on accepted merges (SC block + L1 row)

Run: python scripts/test_dedup_mechanical_superset.py
"""
from __future__ import annotations
import os
import sys
import tempfile
import traceback
from pathlib import Path

sys.path.insert(0, os.path.dirname(__file__))

from plamen_mechanical import (
    _apply_mechanical_dedup_from_pairs,
    _dedup_parse_finding_info,
    _dedup_survivor_superset_ok,
    _resolve_dedup_survivor,
    _DEDUP_AGGREGATE_SOURCE_ID_THRESHOLD,
)


# ─── helpers ──────────────────────────────────────────────────────

def _sc_inventory(blocks: list[str]) -> str:
    return "# Findings Inventory\n\n" + "\n\n".join(blocks) + "\n"


def _sc_block(inv_id, title, location, severity, source_ids, extra=""):
    src = ", ".join(source_ids)
    return (
        f"### Finding [{inv_id}]: {title}\n"
        f"**Severity**: {severity}\n"
        f"**Location**: {location}\n"
        f"**Source IDs**: {src}\n"
        f"{extra}"
    ).rstrip()


def _pairs_file(rows: list[str], header="Finding A | Finding B | Score | Signal | Same Sev?") -> str:
    sep = "|".join(["---"] * (header.count("|") + 1))
    body = [f"| {header} |", f"| {sep} |"]
    body.extend(rows)
    return "\n".join(body) + "\n"


# ─── _dedup_parse_finding_info ────────────────────────────────────

def test_parse_sc_block_info():
    inv = _sc_inventory([
        _sc_block("INV-013", "config hash mismatch inbound",
                  "peer_network_service.rs:990-1000", "Medium",
                  ["CI-1", "NS-2"], "**Impact**: rejects valid peers.\n[CODE-TRACE]\n"),
    ])
    info = _dedup_parse_finding_info(inv)
    assert "INV-013" in info
    rec = info["INV-013"]
    assert rec["kind"] == "sc"
    assert rec["source_ids"] == {"CI-1", "NS-2"}
    assert rec["line_range"] == (990, 1000)
    assert rec["severity"] == "Medium"
    assert "CODE-TRACE" in rec["evidence"]


def test_parse_l1_queue_rows():
    queue = (
        "| Finding ID | Severity | Location | Preferred Tag |\n"
        "|------------|----------|----------|---------------|\n"
        "| INV-031 | High | rate_limiting.rs:170-180 | [POC-PASS] |\n"
        "| INV-044 | High | rate_limiting.rs:175 | [CODE-TRACE] |\n"
    )
    info = _dedup_parse_finding_info(queue)
    assert info["INV-031"]["kind"] == "l1"
    assert info["INV-031"]["severity"] == "High"
    assert info["INV-031"]["line_range"] == (170, 180)
    assert "POC-PASS" in info["INV-031"]["evidence"]


# ─── superset gate primitives ─────────────────────────────────────

def test_superset_ok_strict():
    keep = {"source_ids": {"CI-1", "NS-2", "NS-7"}, "line_range": (990, 1048)}
    absorb = {"source_ids": {"CI-1", "NS-2"}, "line_range": (990, 1000)}
    assert _dedup_survivor_superset_ok(absorb, keep) is True
    # reversed direction must NOT be a valid superset
    assert _dedup_survivor_superset_ok(keep, absorb) is False


def test_superset_keep_separate_when_neither_subsumes():
    a = {"source_ids": {"NS-1", "NS-2"}, "line_range": (10, 20)}
    b = {"source_ids": {"NS-2", "NS-3"}, "line_range": (15, 40)}
    assert _dedup_survivor_superset_ok(a, b) is False
    assert _dedup_survivor_superset_ok(b, a) is False


def test_resolve_flips_survivor():
    # proposed_keep is the SUBSET; proposed_absorb is the SUPERSET → flip.
    finfo = {
        "INV-013": {"source_ids": {"CI-1", "NS-2"}, "line_range": (990, 1000)},
        "INV-014": {"source_ids": {"CI-1", "NS-2", "NS-7"}, "line_range": (990, 1048)},
    }
    # Propose absorbing INV-014 into INV-013 (wrong direction) → must flip.
    resolved = _resolve_dedup_survivor("INV-013", "INV-014", "INV-014", "INV-013", finfo)
    assert resolved == ("INV-013", "INV-014"), resolved


def test_resolve_keep_separate():
    finfo = {
        "INV-1": {"source_ids": {"NS-1"}, "line_range": (10, 20)},
        "INV-2": {"source_ids": {"NS-2"}, "line_range": (200, 210)},
    }
    assert _resolve_dedup_survivor("INV-1", "INV-2", "INV-2", "INV-1", finfo) is None


# ─── fallback path: superset gate + coupling ──────────────────────

def test_fallback_superset_flips_and_couples():
    """Higher-INV is the superset → merge keeps superset (flip), couples content."""
    with tempfile.TemporaryDirectory() as td:
        sp = Path(td)
        # INV-014 is the superset (more source IDs, wider range, POC-PASS, High)
        inv = _sc_inventory([
            _sc_block("INV-013", "config hash mismatch",
                      "peer_network_service.rs:990-1000", "Medium",
                      ["CI-1", "NS-2"], "**Impact**: inbound rejection.\n[CODE-TRACE]\n"),
            _sc_block("INV-014", "config hash mismatch + outbound",
                      "peer_network_service.rs:990-1048", "High",
                      ["CI-1", "NS-2", "NS-7"],
                      "**Impact**: also outbound path.\n[POC-PASS]\n"),
        ])
        (sp / "findings_inventory.md").write_text(inv, encoding="utf-8")
        # Subset signal proposes absorbing A(INV-013) into B(INV-014) — but ⊂
        # direction with id_a=INV-013 (subset) into id_b=INV-014 is correct;
        # use a row that proposes the WRONG direction to exercise the flip.
        pairs = _pairs_file([
            "| INV-014: config | INV-013: config | 0.9 | source-ID subset NS-2 ⊂ ... | yes |",
        ])
        (sp / "dedup_candidate_pairs.md").write_text(pairs, encoding="utf-8")

        n = _apply_mechanical_dedup_from_pairs(sp, "sc_semantic_dedup", supplemental=False)
        assert n == 1, f"expected 1 merge, got {n}"
        out = (sp / "findings_inventory_deduped.md").read_text(encoding="utf-8")
        # survivor INV-014 retained, absorbed INV-013 block removed
        assert "Finding [INV-014]" in out
        assert "Finding [INV-013]" not in out
        # coupling: absorbed location carried into survivor
        assert "990-1000" in out, "absorbed location must be coupled into survivor"
        assert "Coupled from INV-013" in out
        # union source IDs on survivor
        assert "NS-7" in out and "CI-1" in out
        # POC-PASS preserved
        assert "POC-PASS" in out
        # decision rows
        dec = (sp / "dedup_decisions.md").read_text(encoding="utf-8")
        assert "MERGED into INV-014" in dec
        assert "Coupled-content" in dec


def test_fallback_aggregate_guard_blocks_subset():
    """A >4-source-ID finding must NOT be merged on subset/PERT signal."""
    with tempfile.TemporaryDirectory() as td:
        sp = Path(td)
        big_src = [f"NS-{i}" for i in range(1, 16)]  # 15 source IDs
        inv = _sc_inventory([
            _sc_block("INV-118", "distinct dos route",
                      "server.rs:1178", "Medium", ["NS-3"]),
            _sc_block("INV-127", "perturbation aggregate",
                      "peer_network_service.rs:1042", "Medium", big_src),
        ])
        (sp / "findings_inventory.md").write_text(inv, encoding="utf-8")
        # subset signal fires because NS-3 ∈ INV-127's aggregate
        pairs = _pairs_file([
            "| INV-118: dos | INV-127: aggregate | 0.9 | source-ID subset NS-3 ⊂ ... | yes |",
        ])
        (sp / "dedup_candidate_pairs.md").write_text(pairs, encoding="utf-8")

        n = _apply_mechanical_dedup_from_pairs(sp, "sc_semantic_dedup", supplemental=False)
        assert n == 0, f"aggregate guard must block this merge, got {n} merges"


def test_aggregate_threshold_boundary():
    """Exactly 4 source IDs is NOT aggregate; 5 IS."""
    src4 = ["NS-1", "NS-2", "NS-3", "NS-4"]
    src5 = ["NS-1", "NS-2", "NS-3", "NS-4", "NS-5"]
    assert len(src4) == _DEDUP_AGGREGATE_SOURCE_ID_THRESHOLD
    with tempfile.TemporaryDirectory() as td:
        sp = Path(td)
        # 4-source survivor (superset) absorbs a 1-source subset → ALLOWED
        inv = _sc_inventory([
            _sc_block("INV-1", "stub", "f.rs:10", "Medium", ["NS-1"]),
            _sc_block("INV-2", "full", "f.rs:10-30", "Medium", src4),
        ])
        (sp / "findings_inventory.md").write_text(inv, encoding="utf-8")
        pairs = _pairs_file([
            "| INV-1: stub | INV-2: full | 0.9 | source-ID subset NS-1 ⊂ ... | yes |",
        ])
        (sp / "dedup_candidate_pairs.md").write_text(pairs, encoding="utf-8")
        n = _apply_mechanical_dedup_from_pairs(sp, "sc_semantic_dedup", supplemental=False)
        assert n == 1, f"4-source survivor must allow subset merge, got {n}"

    with tempfile.TemporaryDirectory() as td:
        sp = Path(td)
        inv = _sc_inventory([
            _sc_block("INV-1", "stub", "f.rs:10", "Medium", ["NS-1"]),
            _sc_block("INV-2", "full", "f.rs:10-30", "Medium", src5),
        ])
        (sp / "findings_inventory.md").write_text(inv, encoding="utf-8")
        pairs = _pairs_file([
            "| INV-1: stub | INV-2: full | 0.9 | source-ID subset NS-1 ⊂ ... | yes |",
        ])
        (sp / "dedup_candidate_pairs.md").write_text(pairs, encoding="utf-8")
        n = _apply_mechanical_dedup_from_pairs(sp, "sc_semantic_dedup", supplemental=False)
        assert n == 0, f"5-source aggregate must suppress subset merge, got {n}"


def test_fallback_keep_separate_when_no_superset():
    """Subset signal misfires but neither side subsumes the other → KEEP SEPARATE."""
    with tempfile.TemporaryDirectory() as td:
        sp = Path(td)
        inv = _sc_inventory([
            _sc_block("INV-1", "rwlock poison", "cache.rs:40-50", "Medium", ["NS-1", "NS-9"]),
            _sc_block("INV-2", "non-atomic race", "cache.rs:79-90", "Medium", ["NS-9", "NS-2"]),
        ])
        (sp / "findings_inventory.md").write_text(inv, encoding="utf-8")
        pairs = _pairs_file([
            "| INV-1: poison | INV-2: race | 0.9 | source-ID subset NS-9 ⊂ ... | yes |",
        ])
        (sp / "dedup_candidate_pairs.md").write_text(pairs, encoding="utf-8")
        n = _apply_mechanical_dedup_from_pairs(sp, "sc_semantic_dedup", supplemental=False)
        assert n == 0, f"non-subsuming pair must KEEP SEPARATE, got {n}"
        # 0 merges → no deduped artifact written; both findings stay in inventory
        assert not (sp / "findings_inventory_deduped.md").exists()
        out = (sp / "findings_inventory.md").read_text(encoding="utf-8")
        assert "Finding [INV-1]" in out and "Finding [INV-2]" in out


# ─── L1 supplemental row coupling ─────────────────────────────────

def test_supplemental_l1_row_merge_is_field_complete_receipted():
    """The absorbed row is retained exactly in an out-of-table member card."""
    with tempfile.TemporaryDirectory() as td:
        sp = Path(td)
        inventory = (
            "# Findings Inventory\n\n"
            "| Finding ID | Severity | Location | Preferred Tag |\n"
            "|------------|----------|----------|---------------|\n"
            "| INV-3 | Medium | block_pool.rs:151 | [CODE-TRACE] |\n"
            "| INV-7 | Medium | block_pool.rs:151 | [POC-PASS] |\n"
        )
        (sp / "findings_inventory.md").write_text(inventory, encoding="utf-8")
        # live file (already-evaluated set) — empty so this pair is eligible
        (sp / "dedup_candidate_pairs.md").write_text(
            "| Finding A | Finding B | Score | Signal | Same Sev? |\n|---|---|---|---|---|\n",
            encoding="utf-8",
        )
        # full candidate set with location-overlap exact-line + title 1.0
        full = _pairs_file([
            "| INV-3: requested blocks leak | INV-7: requested blocks leak "
            "| 1.0 | location overlap (L151-151 vs L151-151) | yes |",
        ])
        (sp / "dedup_candidate_pairs_full.md").write_text(full, encoding="utf-8")

        n = _apply_mechanical_dedup_from_pairs(sp, "semantic_dedup", supplemental=True)
        assert n == 1
        out = (sp / "findings_inventory.md").read_text(encoding="utf-8")
        assert "POC-PASS" in out
        data_rows = [l for l in out.splitlines() if l.strip().startswith("|")
                     and "INV-" in l]
        assert len(data_rows) == 1
        assert "PLAMEN_DEDUP_PRESERVED_MEMBER_BEGIN id=INV-7" in out


if __name__ == "__main__":
    tests = [f for f in dir() if f.startswith("test_")]
    passed = failed = 0
    for name in sorted(tests):
        print(f"\n--- {name} ---")
        try:
            globals()[name]()
            print("  PASS")
            passed += 1
        except AssertionError as e:
            print(f"  FAIL: {e}")
            traceback.print_exc()
            failed += 1
        except Exception as e:
            print(f"  ERROR: {type(e).__name__}: {e}")
            traceback.print_exc()
            failed += 1
    print(f"\n{'=' * 40}\n{passed} passed, {failed} failed")
    sys.exit(1 if failed else 0)
