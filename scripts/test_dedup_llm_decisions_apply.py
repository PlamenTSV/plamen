"""Tests for the decisions-as-delta dedup path (D1/D2).

The dedup agent now emits ONLY ``dedup_decisions.md`` (decisions-as-delta); the
driver mechanically rebuilds ``findings_inventory_deduped.md`` via
``apply_llm_dedup_decisions`` reusing the shared coupling+removal engine. This
removes the context-bomb (the agent no longer reads/rewrites the whole
inventory) while keeping the ZERO-DATA-LOSS coupling enforced mechanically on
the LLM's own MERGE choices.

Covers:
- A large inventory: the agent needs only the bounded focus packet + decisions;
  the driver builds the deduped artifact from decisions alone (no full read).
- MERGE: absorbed block removed, survivor coupled (union source IDs, higher
  severity, evidence retained).
- GROUP: both blocks kept, ``**Dedup Group**:`` note stamped on the member.
- KEEP SEPARATE / passthrough: no-op, both blocks remain.
- Heading-only and status-row-only decision forms both parse.
- Small audit (one pair) is unaffected.

Run: python scripts/test_dedup_llm_decisions_apply.py
"""
from __future__ import annotations

import os
import sys
import traceback
from pathlib import Path

sys.path.insert(0, os.path.dirname(__file__))

from plamen_mechanical import (
    apply_llm_dedup_decisions,
    _stamp_dedup_group_note,
)
import semantic_dedup_authority as dedup_authority


# ─── helpers ──────────────────────────────────────────────────────

def _sc_block(inv_id, title, location, severity, source_ids, extra=""):
    src = ", ".join(source_ids)
    return (
        f"### Finding [{inv_id}]: {title}\n"
        f"**Severity**: {severity}\n"
        f"**Location**: {location}\n"
        f"**Source IDs**: {src}\n"
        f"{extra}"
    ).rstrip()


def _inventory(blocks: list[str]) -> str:
    return "# Findings Inventory\n\n" + "\n\n".join(blocks) + "\n"


def _write_inv(sp: Path, blocks: list[str]) -> None:
    (sp / "findings_inventory.md").write_text(_inventory(blocks), encoding="utf-8")


def _decisions(body: str) -> str:
    return "# Semantic Dedup Decisions\n\n## Decisions\n\n" + body + "\n"


def _count_blocks(text: str) -> int:
    return text.count("### Finding [")


# ─── MERGE via status row ─────────────────────────────────────────

def test_merge_status_row_removes_absorbed_and_couples(tmp_path=None):
    sp = Path(tmp_path or _mktmp())
    _write_inv(sp, [
        _sc_block("INV-013", "config hash mismatch inbound",
                  "peer.rs:990-1000", "Medium", ["CI-1", "NS-2"],
                  "**Impact**: inbound rejected.\n[CODE-TRACE]\n"),
        _sc_block("INV-014", "config hash mismatch outbound",
                  "peer.rs:990-1048", "High", ["CI-1", "NS-2", "NS-9"],
                  "**Impact**: outbound mismatch.\n[POC-PASS]\n"),
    ])
    # Survivor INV-014 is the superset (⊇ source IDs, subsuming location).
    (sp / "dedup_decisions.md").write_text(
        _decisions(
            "### MERGE: INV-014 absorbs INV-013\n"
            "- Survivor superset: confirmed\n\n"
            "## Dedup Status Table\n"
            "| Finding ID | Status | Coupled-content | Notes |\n"
            "|---|---|---|---|\n"
            "| INV-013 | MERGED into INV-014 | inbound coupled | survivor superset |\n"
        ),
        encoding="utf-8",
    )
    n = apply_llm_dedup_decisions(sp, "sc_semantic_dedup")
    assert n == 1, f"expected 1 merge, got {n}"
    out = (sp / "findings_inventory_deduped.md").read_text(encoding="utf-8")
    assert _count_blocks(out) == 1, "absorbed block must be removed"
    # survivor retained, absorbed block gone
    assert "[INV-014]" in out
    assert "### Finding [INV-013]" not in out
    # zero-data-loss: absorbed source ID + its evidence coupled into survivor
    # (the survivor already had the superset, but coupling must not drop POC-PASS)
    assert "POC-PASS" in out


# ─── MERGE via heading only (no status row) ───────────────────────

def test_merge_heading_only_parses(tmp_path=None):
    sp = Path(tmp_path or _mktmp())
    _write_inv(sp, [
        _sc_block("INV-1", "a", "x.sol:10-20", "Low", ["A-1"]),
        _sc_block("INV-2", "b", "x.sol:10-25", "Low", ["A-1", "A-2"]),
    ])
    (sp / "dedup_decisions.md").write_text(
        _decisions("### MERGE: INV-2 absorbs INV-1\n- Survivor superset: confirmed\n"),
        encoding="utf-8",
    )
    n = apply_llm_dedup_decisions(sp, "sc_semantic_dedup")
    assert n == 1
    out = (sp / "findings_inventory_deduped.md").read_text(encoding="utf-8")
    assert "### Finding [INV-1]" not in out
    assert "[INV-2]" in out


# ─── GROUP keeps both, stamps note ────────────────────────────────

def test_group_keeps_both_and_stamps_note(tmp_path=None):
    sp = Path(tmp_path or _mktmp())
    _write_inv(sp, [
        _sc_block("INV-5", "rep", "a.sol:1-5", "Medium", ["G-1"]),
        _sc_block("INV-6", "member", "b.sol:1-5", "Medium", ["G-2"]),
    ])
    (sp / "dedup_decisions.md").write_text(
        _decisions("### GROUP: INV-5 represents INV-5, INV-6\n- Pattern: same fix\n"),
        encoding="utf-8",
    )
    n = apply_llm_dedup_decisions(sp, "sc_semantic_dedup")
    assert n == 0, "GROUP applies no merges"
    out = (sp / "findings_inventory_deduped.md").read_text(encoding="utf-8")
    assert _count_blocks(out) == 2, "GROUP keeps both blocks"
    assert "**Dedup Group**: inherits verification from INV-5" in out
    # representative is NOT stamped
    rep_block = out.split("### Finding [INV-5]")[1].split("### Finding")[0]
    assert "Dedup Group" not in rep_block
    # GROUP annotations are part of the primary postimage.  They must be
    # complete before the immutable receipt hashes that output.
    assert dedup_authority.load_applied_aliases(
        sp,
        canonical_text=(
            sp / "findings_inventory_deduped.md"
        ).read_bytes().decode("utf-8", errors="strict"),
    ) == {}


def test_group_note_idempotent(tmp_path=None):
    sp = Path(tmp_path or _mktmp())
    inv = sp / "findings_inventory_deduped.md"
    inv.write_text(_inventory([
        _sc_block("INV-5", "rep", "a.sol:1-5", "Medium", ["G-1"]),
        _sc_block("INV-6", "member", "b.sol:1-5", "Medium", ["G-2"],
                  "**Dedup Group**: inherits verification from INV-5\n"),
    ]), encoding="utf-8")
    stamped = _stamp_dedup_group_note(inv, "INV-5", ["INV-6"])
    assert stamped == 0, "already-noted member must not be re-stamped"


# ─── KEEP SEPARATE / passthrough is a no-op ───────────────────────

def test_keep_separate_noop_leaves_passthrough(tmp_path=None):
    sp = Path(tmp_path or _mktmp())
    _write_inv(sp, [
        _sc_block("INV-1", "a", "x.sol:1-5", "Low", ["A-1"]),
        _sc_block("INV-2", "b", "y.sol:1-5", "Low", ["B-1"]),
    ])
    (sp / "dedup_decisions.md").write_text(
        _decisions("### KEEP SEPARATE: INV-1 vs INV-2\n- Reason: different root cause\n"),
        encoding="utf-8",
    )
    n = apply_llm_dedup_decisions(sp, "sc_semantic_dedup")
    assert n == 0
    # P0-S writes an exact passthrough so the immutable no-delta receipt can
    # bind the output identity set; it must never create a partial rewrite.
    deduped = sp / "findings_inventory_deduped.md"
    assert deduped.read_text(encoding="utf-8") == (
        sp / "findings_inventory.md"
    ).read_text(encoding="utf-8")


def test_passthrough_status_noop(tmp_path=None):
    sp = Path(tmp_path or _mktmp())
    _write_inv(sp, [_sc_block("INV-1", "a", "x.sol:1-5", "Low", ["A-1"])])
    (sp / "dedup_decisions.md").write_text(
        "# Semantic Dedup Decisions\n\n**Status**: PASSTHROUGH\n", encoding="utf-8",
    )
    n = apply_llm_dedup_decisions(sp, "sc_semantic_dedup")
    assert n == 0
    assert (sp / "findings_inventory_deduped.md").read_text(encoding="utf-8") == (
        sp / "findings_inventory.md"
    ).read_text(encoding="utf-8")


# ─── Large inventory: no full read required ───────────────────────

def test_large_inventory_apply_from_decisions_only(tmp_path=None):
    """A 120-block inventory: the driver builds the deduped artifact from
    decisions alone. The point is that the AGENT never had to read the full
    inventory — here we verify the driver's apply works at scale and removes
    exactly the absorbed blocks."""
    sp = Path(tmp_path or _mktmp())
    blocks = [
        _sc_block(f"INV-{i}", f"finding {i}", f"f{i}.sol:{i}-{i+5}", "Medium",
                  [f"S-{i}"])
        for i in range(1, 121)
    ]
    # Make INV-2 a superset of INV-1 (same file, subsuming range + ⊇ source).
    blocks[0] = _sc_block("INV-1", "finding 1", "f1.sol:1-6", "Medium", ["S-1"])
    blocks[1] = _sc_block("INV-2", "finding 2 super", "f1.sol:1-6", "High",
                          ["S-1", "S-2"])
    _write_inv(sp, blocks)
    (sp / "dedup_decisions.md").write_text(
        _decisions(
            "### MERGE: INV-2 absorbs INV-1\n- Survivor superset: confirmed\n\n"
            "| INV-1 | MERGED into INV-2 |\n"
        ),
        encoding="utf-8",
    )
    n = apply_llm_dedup_decisions(sp, "sc_semantic_dedup")
    assert n == 1
    out = (sp / "findings_inventory_deduped.md").read_text(encoding="utf-8")
    assert _count_blocks(out) == 119, f"expected 119 surviving blocks, got {_count_blocks(out)}"
    assert "### Finding [INV-1]" not in out
    assert "[INV-2]" in out
    # higher severity inherited / retained
    assert "High" in out.split("### Finding [INV-2]")[1].split("### Finding")[0]


# ─── survivor flip recorded by LLM is honored ─────────────────────

def test_llm_flip_direction_honored(tmp_path=None):
    """If the LLM (per the superset gate) chose to absorb the LARGER-INV into
    the SMALLER-INV because the smaller is the superset, the driver honors that
    direction verbatim — it does not re-derive direction from INV numbers."""
    sp = Path(tmp_path or _mktmp())
    _write_inv(sp, [
        _sc_block("INV-1", "superset", "x.sol:1-50", "High", ["A-1", "A-2"]),
        _sc_block("INV-9", "subset", "x.sol:1-50", "Medium", ["A-1"]),
    ])
    (sp / "dedup_decisions.md").write_text(
        _decisions(
            "### MERGE: INV-1 absorbs INV-9\n- Survivor superset: confirmed\n\n"
            "| INV-9 | MERGED into INV-1 |\n"
        ),
        encoding="utf-8",
    )
    n = apply_llm_dedup_decisions(sp, "sc_semantic_dedup")
    assert n == 1
    out = (sp / "findings_inventory_deduped.md").read_text(encoding="utf-8")
    assert "### Finding [INV-9]" not in out
    assert "[INV-1]" in out


# ─── chained merge collapses transitively (union-find redesign) ────

def test_survivor_of_one_merge_not_absorbed_by_another(tmp_path=None):
    sp = Path(tmp_path or _mktmp())
    _write_inv(sp, [
        _sc_block("INV-1", "a", "x.sol:1-5", "Low", ["A-1"]),
        _sc_block("INV-2", "b", "x.sol:1-5", "Low", ["A-1", "A-2"]),
        _sc_block("INV-3", "c", "x.sol:1-5", "Low", ["A-1", "A-2", "A-3"]),
    ])
    # INV-1 -> INV-2 and INV-2 -> INV-3 are two MERGE rows over the SAME
    # signal cluster. Under the dedup REDESIGN (union-find transitive closure),
    # {INV-1, INV-2, INV-3} is ONE component: INV-3 is the source-ID superset
    # survivor, so BOTH INV-1 and INV-2 are absorbed into INV-3 (2 merges).
    # The invariant the old pairwise contract protected — INV-2's distinct
    # content must NOT be lost — is STILL enforced: INV-2's body is coupled
    # into the INV-3 survivor via the zero-loss `Coupled from` engine, and the
    # survivor INV-3 remains. The old code dropped the chained merge as a
    # workaround; the redesign instead recovers transitivity and couples
    # losslessly, which is strictly more correct (no duplicate INV-2 left).
    (sp / "dedup_decisions.md").write_text(
        _decisions(
            "| INV-1 | MERGED into INV-2 |\n"
            "| INV-2 | MERGED into INV-3 |\n"
        ),
        encoding="utf-8",
    )
    n = apply_llm_dedup_decisions(sp, "sc_semantic_dedup")
    # Transitive component {INV-1,INV-2,INV-3} -> survivor INV-3 absorbs both.
    assert n == 2, f"expected 2 transitive merges, got {n}"
    out = (sp / "findings_inventory_deduped.md").read_text(encoding="utf-8")
    # Both absorbed standalone blocks removed, survivor kept.
    assert "### Finding [INV-1]" not in out
    assert "### Finding [INV-2]" not in out
    assert "### Finding [INV-3]" in out
    # ZERO-LOSS: INV-1's and INV-2's distinct content coupled into the survivor.
    assert "Coupled from INV-1" in out
    assert "Coupled from INV-2" in out


# ─── small audit unaffected ───────────────────────────────────────

def test_small_audit_single_pair_unaffected(tmp_path=None):
    sp = Path(tmp_path or _mktmp())
    _write_inv(sp, [
        _sc_block("INV-1", "a", "x.sol:1-5", "Low", ["A-1"]),
        _sc_block("INV-2", "b", "x.sol:1-9", "Low", ["A-1", "A-2"]),
    ])
    (sp / "dedup_decisions.md").write_text(
        _decisions("| INV-1 | MERGED into INV-2 |\n"), encoding="utf-8",
    )
    n = apply_llm_dedup_decisions(sp, "sc_semantic_dedup")
    assert n == 1
    out = (sp / "findings_inventory_deduped.md").read_text(encoding="utf-8")
    assert _count_blocks(out) == 1


# ─── runner / tmp ─────────────────────────────────────────────────

def _mktmp() -> str:
    import tempfile
    return tempfile.mkdtemp()


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
