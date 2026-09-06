"""Tests for finding dedup scoring and candidate computation."""
from __future__ import annotations
import re
import sys
import os
import traceback
from pathlib import Path

sys.path.insert(0, os.path.dirname(__file__))

from plamen_parsers import (
    _titles_overlap_score, _title_tokens, _stem_token,
    _shared_anchor_tokens, _compute_dedup_candidate_pairs, _norm_loc,
    _parse_line_range, _line_ranges_overlap,
)


# ─── Fix 2: Scoring function tests ───────────────────────────────

def test_stem_token():
    assert _stem_token("poisoning") == "poison"
    assert _stem_token("cascading") == "cascad"
    assert _stem_token("rwlock") == "rwlock"
    assert _stem_token("to") == "to"  # short, untouched
    assert _stem_token("truncation") == "trunca"  # strips -tion
    assert _stem_token("initialization") == "initializa"


def test_title_tokens_stop_words():
    tokens = _title_tokens("RwLock poisoning cascades via unwrap")
    assert "rwlock" in tokens
    assert "poison" in tokens  # stemmed
    assert "via" not in tokens  # stop word
    assert "unwrap" in tokens


def test_scoring_near_identical_titles():
    """Near-identical titles (same tokens, minor rewording) should score ≥0.80."""
    score = _titles_overlap_score(
        "RwLock poisoning cascades through all guard types",
        "RwLock Poison Cascade Through Guard Types",
    )
    print(f"  Near-identical: {score:.3f}")
    assert score >= 0.80, f"Near-identical titles should score ≥0.80, got {score:.3f}"


def test_scoring_shared_anchor_boosts():
    """Shared function names should boost the score."""
    score = _titles_overlap_score(
        "write_info_file non atomic persistence",
        "write_info_file torn write risk",
    )
    print(f"  Shared anchor: {score:.3f}")
    # Anchor boost should fire on write_info_file
    anchors = _shared_anchor_tokens(
        "write_info_file non atomic persistence",
        "write_info_file torn write risk",
    )
    print(f"  Shared anchors: {anchors}")
    assert "write_info_file" in anchors


def test_scoring_different_anchors_no_boost():
    """Different function names should NOT get anchor boost."""
    score = _titles_overlap_score(
        "write_info_file non atomic persistence",
        "write_data_chunk non atomic persistence",
    )
    print(f"  Different anchors: {score:.3f}")
    anchors = _shared_anchor_tokens(
        "write_info_file non atomic persistence",
        "write_data_chunk non atomic persistence",
    )
    assert len(anchors) == 0
    # Score is still high because non-anchor tokens overlap heavily —
    # that's correct behavior. The test validates no ANCHOR boost fires.
    assert score >= 0.50, "Shared non-anchor tokens still produce high overlap"


def test_scoring_completely_different():
    """Completely different bugs should score near 0."""
    score = _titles_overlap_score(
        "Xorshift RNG with Zero Seed Produces Degenerate Partition Assignments",
        "RwLock poisoning cascades through all guard types",
    )
    print(f"  Completely different: {score:.3f}")
    assert score < 0.20, f"Different bugs should score low, got {score:.3f}"


def test_scoring_same_pattern_different_targets():
    """Same bug pattern at different targets scores high (correct — they ARE similar titles).
    The protection against false merge comes from same-file check, not from the score."""
    score = _titles_overlap_score(
        "Panic via unwrap in block_tree initialization",
        "Panic via unwrap in storage_module initialization",
    )
    print(f"  Same pattern different targets: {score:.3f}")
    # This SHOULD score high — the titles ARE similar. The same-file check
    # in the promotion gate prevents false merges across files.
    assert score >= 0.50, f"Similar titles should score high, got {score:.3f}"


# ─── Fix 1: Promotion gate integration test ──────────────────────

def test_promotion_tags_same_file_near_identical(tmp_path):
    """Depth finding with near-identical title in same file should be promoted but tagged."""
    sp = tmp_path / "scratchpad"
    sp.mkdir()

    inv = sp / "findings_inventory.md"
    inv.write_text(
        "# Findings Inventory\n\n"
        "### Finding [INV-001]: RwLock Poison Cascade Through Guard Types\n"
        "**Source IDs**: [CS-7]\n"
        "**Severity**: Medium\n"
        "**Location**: crates/domain/src/block_tree.rs:L89\n"
        "**Preferred Tag**: CODE-TRACE\n"
        "**Description**: RwLock poison.\n\n"
    )

    depth = sp / "depth_consensus_invariant_findings.md"
    depth.write_text(
        "## DCI-5: RwLock poisoning cascades through all guard types via .unwrap()\n"
        "**Severity**: Medium\n"
        "**Location**: crates/domain/src/block_tree.rs:L45\n"
        "**Preferred Tag**: CODE-TRACE\n"
        "**Verdict**: CONFIRMED\n"
        "**Description**: Same RwLock poison issue, different line.\n\n"
    )

    from plamen_validators import _promote_depth_findings_to_inventory
    promoted = _promote_depth_findings_to_inventory(sp)
    print(f"  Promoted: {promoted}")
    assert "DCI-5" in promoted, (
        f"DCI-5 should be promoted (tag-and-promote, never block): {promoted}"
    )

    # Check inventory has the LIKELY-DUP tag so the LLM can decide
    inv_text = inv.read_text()
    print(f"  Has LIKELY-DUP tag: {'LIKELY-DUP' in inv_text}")
    assert "LIKELY-DUP" in inv_text, "Promoted finding should carry [LIKELY-DUP] tag"

    # Check receipt logs the likely duplicate
    receipt = (sp / "depth_promotion_receipt.md").read_text()
    print(f"  Receipt has 'Likely Duplicates': {'Likely Duplicates' in receipt}")
    assert "DCI-5" in receipt


def test_promotion_allows_different_bug_same_file(tmp_path):
    """Genuinely different bug in same file should still be promoted."""
    sp = tmp_path / "scratchpad"
    sp.mkdir()

    inv = sp / "findings_inventory.md"
    inv.write_text(
        "# Findings Inventory\n\n"
        "### Finding [INV-001]: RwLock Poison Cascade Through Guard Types\n"
        "**Source IDs**: [CS-7]\n"
        "**Severity**: Medium\n"
        "**Location**: crates/domain/src/block_tree.rs:L89\n"
        "**Preferred Tag**: CODE-TRACE\n"
        "**Description**: RwLock poison.\n\n"
    )

    depth = sp / "depth_consensus_invariant_findings.md"
    depth.write_text(
        "## DCI-1: Non-deterministic fork choice via HashMap iteration in find_max_difficulty\n"
        "**Severity**: Medium\n"
        "**Location**: crates/domain/src/block_tree.rs:L250\n"
        "**Preferred Tag**: CODE-TRACE\n"
        "**Verdict**: CONFIRMED\n"
        "**Description**: HashMap provides no ordering guarantees.\n\n"
    )

    from plamen_validators import _promote_depth_findings_to_inventory
    promoted = _promote_depth_findings_to_inventory(sp)
    print(f"  Promoted: {promoted}")
    assert "DCI-1" in promoted, (
        f"DCI-1 should be promoted (different bug in same file), got: {promoted}"
    )


def test_promotion_allows_same_pattern_different_file(tmp_path):
    """Same bug pattern in different file should be promoted."""
    sp = tmp_path / "scratchpad"
    sp.mkdir()

    inv = sp / "findings_inventory.md"
    inv.write_text(
        "# Findings Inventory\n\n"
        "### Finding [INV-001]: Panic via unwrap in block_tree initialization\n"
        "**Source IDs**: [CS-1]\n"
        "**Severity**: Medium\n"
        "**Location**: crates/domain/src/block_tree.rs:L50\n"
        "**Preferred Tag**: CODE-TRACE\n"
        "**Description**: Unwrap panic.\n\n"
    )

    depth = sp / "depth_state_trace_findings.md"
    depth.write_text(
        "## DST-3: Panic via unwrap in storage_module initialization\n"
        "**Severity**: Medium\n"
        "**Location**: crates/domain/src/storage_module.rs:L80\n"
        "**Preferred Tag**: CODE-TRACE\n"
        "**Verdict**: CONFIRMED\n"
        "**Description**: Same unwrap pattern but different module.\n\n"
    )

    from plamen_validators import _promote_depth_findings_to_inventory
    promoted = _promote_depth_findings_to_inventory(sp)
    print(f"  Promoted: {promoted}")
    assert "DST-3" in promoted, (
        f"DST-3 should be promoted (different file), got: {promoted}"
    )


# ─── Fix 3 (replaced): Candidate pair computation tests ──────────

def test_candidate_pairs_same_file_high_overlap(tmp_path):
    """Two findings in same file with overlapping titles should be flagged as candidates."""
    sp = tmp_path / "scratchpad"
    sp.mkdir()

    (sp / "findings_inventory.md").write_text(
        "# Findings Inventory\n\n"
        "### Finding [INV-001]: RwLock Poison Cascade Through Guard Types\n"
        "**Severity**: Medium\n"
        "**Location**: crates/domain/src/block_tree.rs:L89\n\n"
        "### Finding [INV-002]: RwLock poisoning cascades through all guard types via .unwrap()\n"
        "**Severity**: Medium\n"
        "**Location**: crates/domain/src/block_tree.rs:L45\n\n"
        "### Finding [INV-003]: Non-deterministic fork choice via HashMap\n"
        "**Severity**: Medium\n"
        "**Location**: crates/domain/src/block_tree.rs:L250\n\n"
    )

    count = _compute_dedup_candidate_pairs(sp)
    print(f"  Candidate pairs: {count}")
    assert count >= 1, f"Should find at least 1 candidate pair, got {count}"

    content = (sp / "dedup_candidate_pairs.md").read_text()
    print(f"  Content preview: {content[:300]}")
    assert "INV-001" in content and "INV-002" in content


def test_candidate_pairs_different_files_no_match(tmp_path):
    """Two findings in different files should NOT be paired, even with similar titles."""
    sp = tmp_path / "scratchpad"
    sp.mkdir()

    (sp / "findings_inventory.md").write_text(
        "# Findings Inventory\n\n"
        "### Finding [INV-001]: Panic via unwrap in initialization\n"
        "**Severity**: Medium\n"
        "**Location**: crates/domain/src/block_tree.rs:L50\n\n"
        "### Finding [INV-002]: Panic via unwrap in initialization\n"
        "**Severity**: Medium\n"
        "**Location**: crates/domain/src/storage_module.rs:L80\n\n"
    )

    count = _compute_dedup_candidate_pairs(sp)
    print(f"  Candidate pairs: {count}")
    assert count == 0, f"Different files should not be paired, got {count}"


def test_candidate_pairs_anchor_match(tmp_path):
    """Two findings sharing a function name anchor should be flagged even with low token overlap."""
    sp = tmp_path / "scratchpad"
    sp.mkdir()

    (sp / "findings_inventory.md").write_text(
        "# Findings Inventory\n\n"
        "### Finding [INV-001]: Non-atomic write_info_file leaves storage in torn state\n"
        "**Severity**: Medium\n"
        "**Location**: crates/domain/src/storage_module.rs:L340\n\n"
        "### Finding [INV-002]: write_info_file truncate then write pattern loses data\n"
        "**Severity**: Medium\n"
        "**Location**: crates/domain/src/storage_module.rs:L345\n\n"
    )

    count = _compute_dedup_candidate_pairs(sp)
    print(f"  Candidate pairs: {count}")
    assert count >= 1, f"Shared anchor should create candidate pair, got {count}"


# ─── Fix 4: Advisory validator tests ─────────────────────────────

def test_inflation_gate_flags_high_ratio(tmp_path):
    """Post-promotion validator should flag >40% inflation with <3 new files."""
    sp = tmp_path / "scratchpad"
    sp.mkdir()

    pre = "# Findings Inventory\n\n"
    for i in range(1, 11):
        pre += (
            f"### Finding [INV-{i:03d}]: Bug {i}\n"
            f"**Location**: crates/domain/src/file_{i % 3}.rs:L{i * 10}\n\n"
        )
    pre += "\n## Depth Promotion Supplement\n\n"
    for i in range(11, 19):
        pre += (
            f"### Finding [INV-{i:03d}]: Depth Bug {i}\n"
            f"**Location**: crates/domain/src/file_{i % 2}.rs:L{i * 10}\n\n"
        )

    (sp / "findings_inventory.md").write_text(pre)
    (sp / "depth_promotion_receipt.md").write_text(
        "# Depth Promotion Receipt\n\nPromoted 8 findings.\n"
    )

    from plamen_validators import _validate_depth_promotion_dedup
    issues = _validate_depth_promotion_dedup(sp)
    print(f"  Issues: {issues}")
    assert len(issues) > 0, "Should flag high inflation with few new files"
    assert "inflation" in issues[0].lower()


# ─── Location overlap signal tests ─────────────────────────────────

def test_parse_line_range_single():
    assert _parse_line_range("proxy.rs:L40") == (40, 40)
    assert _parse_line_range("proxy.rs:40") == (40, 40)

def test_parse_line_range_range():
    assert _parse_line_range("proxy.rs:L40-L65") == (40, 65)
    assert _parse_line_range("proxy.rs:40-65") == (40, 65)
    assert _parse_line_range("proxy.rs:L65-L40") == (40, 65)  # swapped

def test_parse_line_range_no_lines():
    assert _parse_line_range("proxy.rs") is None
    assert _parse_line_range("unknown") is None
    assert _parse_line_range("") is None

def test_line_ranges_overlap_exact():
    assert _line_ranges_overlap((40, 65), (50, 70)) is True

def test_line_ranges_overlap_proximity():
    assert _line_ranges_overlap((40, 40), (50, 50)) is True  # 10 lines apart, within 15
    assert _line_ranges_overlap((40, 40), (55, 55)) is True  # exactly 15
    assert _line_ranges_overlap((40, 40), (56, 56)) is False  # 16 apart

def test_line_ranges_overlap_no_overlap():
    assert _line_ranges_overlap((10, 20), (100, 200)) is False


def test_candidate_pairs_location_overlap_different_titles(tmp_path):
    """Two findings at same file+lines but completely different titles should pair."""
    sp = tmp_path / "scratchpad"
    sp.mkdir()

    (sp / "findings_inventory.md").write_text(
        "# Findings Inventory\n\n"
        "### Finding [INV-001]: Unfiltered debug_ Namespace in RPC Proxy Enables Unrestricted EVM Access\n"
        "**Severity**: High\n"
        "**Location**: crates/rpc/src/proxy.rs:L40\n\n"
        "### Finding [INV-002]: EVM RPC Proxy Passes All Methods Without Filtering\n"
        "**Severity**: Medium\n"
        "**Location**: crates/rpc/src/proxy.rs:L42\n\n"
    )

    count = _compute_dedup_candidate_pairs(sp)
    print(f"  Candidate pairs: {count}")
    assert count >= 1, f"Location-overlap pair should be found, got {count}"

    content = (sp / "dedup_candidate_pairs.md").read_text()
    print(f"  Content preview: {content[:400]}")
    assert "location overlap" in content, "Signal should mention location overlap"
    assert "INV-001" in content and "INV-002" in content


def test_candidate_pairs_location_overlap_zero_title_score(tmp_path):
    """Even with 0.00 title score, location overlap should pair findings."""
    sp = tmp_path / "scratchpad"
    sp.mkdir()

    (sp / "findings_inventory.md").write_text(
        "# Findings Inventory\n\n"
        "### Finding [INV-001]: Reth Debug Namespace Enabled\n"
        "**Severity**: Low\n"
        "**Location**: crates/rpc/src/proxy.rs:L40\n\n"
        "### Finding [INV-002]: EVM RPC Proxy Passes All Methods Without Filtering\n"
        "**Severity**: Medium\n"
        "**Location**: crates/rpc/src/proxy.rs:L45\n\n"
    )

    # Verify title score is actually very low
    score = _titles_overlap_score(
        "Reth Debug Namespace Enabled",
        "EVM RPC Proxy Passes All Methods Without Filtering",
    )
    print(f"  Title score: {score:.3f} (should be very low)")
    assert score < 0.30, f"Titles should have very low overlap, got {score}"

    count = _compute_dedup_candidate_pairs(sp)
    print(f"  Candidate pairs: {count}")
    assert count >= 1, f"Location overlap should catch this despite low title score, got {count}"

    content = (sp / "dedup_candidate_pairs.md").read_text()
    assert "location overlap" in content


def test_candidate_pairs_no_location_overlap_far_lines(tmp_path):
    """Same file but lines far apart + different titles should NOT pair."""
    sp = tmp_path / "scratchpad"
    sp.mkdir()

    (sp / "findings_inventory.md").write_text(
        "# Findings Inventory\n\n"
        "### Finding [INV-001]: Missing authorization check on admin endpoint\n"
        "**Severity**: Medium\n"
        "**Location**: crates/rpc/src/proxy.rs:L10\n\n"
        "### Finding [INV-002]: Response streaming lacks size cap\n"
        "**Severity**: Medium\n"
        "**Location**: crates/rpc/src/proxy.rs:L500\n\n"
    )

    count = _compute_dedup_candidate_pairs(sp)
    print(f"  Candidate pairs: {count}")
    assert count == 0, f"Far-apart lines + different titles should not pair, got {count}"


def test_promotion_tags_location_overlap(tmp_path):
    """Depth finding at overlapping location should get LIKELY-DUP tag
    even with completely different title."""
    sp = tmp_path / "scratchpad"
    sp.mkdir()

    inv = sp / "findings_inventory.md"
    inv.write_text(
        "# Findings Inventory\n\n"
        "### Finding [INV-001]: Unfiltered debug_ Namespace in RPC Proxy\n"
        "**Source IDs**: [CS-1]\n"
        "**Severity**: High\n"
        "**Location**: crates/rpc/src/proxy.rs:L40\n"
        "**Preferred Tag**: CODE-TRACE\n"
        "**Description**: Debug namespace exposed.\n\n"
    )

    depth = sp / "depth_network_surface_findings.md"
    depth.write_text(
        "## DN-3: EVM RPC Proxy Passes All Methods Without Filtering\n"
        "**Severity**: Medium\n"
        "**Location**: crates/rpc/src/proxy.rs:L42\n"
        "**Preferred Tag**: CODE-TRACE\n"
        "**Verdict**: CONFIRMED\n"
        "**Description**: Proxy forwards every RPC method.\n\n"
    )

    from plamen_validators import _promote_depth_findings_to_inventory
    promoted = _promote_depth_findings_to_inventory(sp)
    print(f"  Promoted: {promoted}")
    assert "DN-3" in promoted

    inv_text = inv.read_text()
    print(f"  Has LIKELY-DUP tag: {'LIKELY-DUP' in inv_text}")
    assert "LIKELY-DUP" in inv_text, "Location-overlap should produce LIKELY-DUP tag"
    assert "location overlap" in inv_text, "Tag should mention location overlap"


# ─── End-to-end scoring matrix ───────────────────────────────────

def test_scoring_matrix():
    """Print full scoring matrix for all cluster pairs — no assertions, observational."""
    clusters = {
        "RwLock": [
            "RwLock poisoning cascades through all guard types via .unwrap()",
            "BlockTreeReadGuard::read() Uses unwrap() on RwLock — Poison Panic Propagation",
            "RwLock Poison Cascade Through Guard Types",
            "RwLock Unwrap Pattern Creates Cascade Failure on Poison Across Domain Services",
            "StorageModulesReadGuard::read() Poison Cascade Extends to ALL Write Callers",
        ],
        "write_info_file": [
            "Non-atomic write_info_file leaves storage module in torn state after crash",
            "write_info_file Uses truncate(false) — read_info_file Reads Stale Tail",
            "write_info_file Truncate-Then-Write Pattern Loses Data on Short Write",
        ],
        "fork_choice": [
            "Non-deterministic fork choice via HashMap iteration in find_max_difficulty",
            "Fork Choice Non-Determinism on Max-Difficulty Block Removal",
            "Block ADDITION Uses > But REMOVAL Recomputes With last()-Wins Semantics",
        ],
    }
    for name, titles in clusters.items():
        print(f"\n  === {name} cluster ===")
        for i in range(len(titles)):
            for j in range(i + 1, len(titles)):
                score = _titles_overlap_score(titles[i], titles[j])
                anchors = _shared_anchor_tokens(titles[i], titles[j])
                anchor_str = f" anchors={anchors}" if anchors else ""
                flag = ""
                if score >= 0.80:
                    flag = " -> PROMOTION GATE"
                elif score >= 0.50 or anchors:
                    flag = " -> CANDIDATE PAIR"
                else:
                    flag = " -> LLM ONLY"
                print(f"  [{i}]<->[{j}]: {score:.3f}{anchor_str}{flag}")


# ─── Source-ID subset signal tests ────────────────────────────────

def test_candidate_pairs_source_id_subset(tmp_path):
    """Finding A with source IDs ⊂ Finding B's source IDs should pair."""
    sp = tmp_path / "scratchpad"
    sp.mkdir()

    (sp / "findings_inventory.md").write_text(
        "# Findings Inventory\n\n"
        "### Finding [INV-001]: Partial RwLock issue\n"
        "**Source IDs**: [D-58, D-59]\n"
        "**Severity**: Medium\n"
        "**Location**: crates/domain/src/block_tree.rs:L89\n\n"
        "### Finding [INV-002]: Complete RwLock cascade analysis\n"
        "**Source IDs**: [D-57, D-58, D-59, D-60]\n"
        "**Severity**: Medium\n"
        "**Location**: crates/domain/src/block_tree.rs:L45\n\n"
    )

    count = _compute_dedup_candidate_pairs(sp)
    print(f"  Candidate pairs: {count}")
    assert count >= 1, f"Source-ID subset should create pair, got {count}"

    content = (sp / "dedup_candidate_pairs.md").read_text()
    print(f"  Content preview: {content[:500]}")
    assert "source-ID subset" in content, "Should mention source-ID subset signal"
    assert "INV-001" in content and "INV-002" in content


def test_candidate_pairs_source_id_subset_cross_file(tmp_path):
    """Source-ID subset should fire even across different files.

    Superset kept at <=4 source IDs so the subset signal is NOT suppressed by
    the aggregate rule (>4 source IDs suppresses subset/PERT hints). The
    aggregate boundary itself is covered by
    test_dedup_aggregate_threshold_boundary.
    """
    sp = tmp_path / "scratchpad"
    sp.mkdir()

    (sp / "findings_inventory.md").write_text(
        "# Findings Inventory\n\n"
        "### Finding [INV-001]: RwLock unwrap in block_tree\n"
        "**Source IDs**: [D-58, D-59]\n"
        "**Severity**: Medium\n"
        "**Location**: crates/domain/src/block_tree.rs:L89\n\n"
        "### Finding [INV-002]: RwLock cascade in storage_module\n"
        "**Source IDs**: [D-57, D-58, D-59, D-60]\n"
        "**Severity**: Medium\n"
        "**Location**: crates/domain/src/storage_module.rs:L120\n\n"
    )

    count = _compute_dedup_candidate_pairs(sp)
    print(f"  Candidate pairs: {count}")
    assert count >= 1, f"Source-ID subset should fire across files, got {count}"

    content = (sp / "dedup_candidate_pairs.md").read_text()
    assert "source-ID subset" in content


def test_candidate_pairs_source_id_no_subset(tmp_path):
    """Disjoint source IDs should NOT trigger source-ID subset signal."""
    sp = tmp_path / "scratchpad"
    sp.mkdir()

    (sp / "findings_inventory.md").write_text(
        "# Findings Inventory\n\n"
        "### Finding [INV-001]: Bug alpha\n"
        "**Source IDs**: [D-1, D-2]\n"
        "**Severity**: Medium\n"
        "**Location**: crates/domain/src/alpha.rs:L10\n\n"
        "### Finding [INV-002]: Bug beta\n"
        "**Source IDs**: [D-3, D-4]\n"
        "**Severity**: Medium\n"
        "**Location**: crates/domain/src/beta.rs:L20\n\n"
    )

    count = _compute_dedup_candidate_pairs(sp)
    print(f"  Candidate pairs: {count}")
    assert count == 0, f"Disjoint source IDs should not pair, got {count}"


def test_candidate_pairs_source_id_overlap_not_subset(tmp_path):
    """Overlapping but non-subset source IDs should trigger overlap signal."""
    sp = tmp_path / "scratchpad"
    sp.mkdir()

    (sp / "findings_inventory.md").write_text(
        "# Findings Inventory\n\n"
        "### Finding [INV-001]: Bug alpha\n"
        "**Source IDs**: [D-1, D-2, D-3]\n"
        "**Severity**: Medium\n"
        "**Location**: crates/domain/src/alpha.rs:L10\n\n"
        "### Finding [INV-002]: Bug beta\n"
        "**Source IDs**: [D-2, D-3, D-4]\n"
        "**Severity**: Medium\n"
        "**Location**: crates/domain/src/beta.rs:L20\n\n"
    )

    count = _compute_dedup_candidate_pairs(sp)
    print(f"  Candidate pairs: {count}")
    assert count >= 1, f"Source-ID overlap should create pair, got {count}"

    content = (sp / "dedup_candidate_pairs.md").read_text()
    assert "source-ID overlap" in content


# ─── PERT lineage signal tests ───────────────────────────────────

def test_candidate_pairs_pert_lineage_shared_sources(tmp_path):
    """PERT finding sharing depth source IDs with parent should pair."""
    sp = tmp_path / "scratchpad"
    sp.mkdir()

    (sp / "findings_inventory.md").write_text(
        "# Findings Inventory\n\n"
        "### Finding [INV-001]: Original RwLock bug\n"
        "**Source IDs**: [DST-3]\n"
        "**Severity**: Medium\n"
        "**Location**: crates/domain/src/block_tree.rs:L89\n\n"
        "### Finding [INV-002]: Perturbation: RwLock write path variant\n"
        "**Source IDs**: [PERT-1, DST-3]\n"
        "**Severity**: Medium\n"
        "**Location**: crates/domain/src/block_tree.rs:L92\n\n"
    )

    count = _compute_dedup_candidate_pairs(sp)
    print(f"  Candidate pairs: {count}")
    assert count >= 1, f"PERT lineage should create pair, got {count}"

    content = (sp / "dedup_candidate_pairs.md").read_text()
    print(f"  Content preview: {content[:500]}")
    assert "PERT lineage" in content or "source-ID" in content, \
        "Should mention PERT lineage or source-ID signal"


def test_candidate_pairs_pert_same_file_no_shared_source(tmp_path):
    """PERT finding in same file as non-PERT should pair via PERT lineage."""
    sp = tmp_path / "scratchpad"
    sp.mkdir()

    (sp / "findings_inventory.md").write_text(
        "# Findings Inventory\n\n"
        "### Finding [INV-001]: Original HashMap non-determinism\n"
        "**Source IDs**: [DCI-1]\n"
        "**Severity**: High\n"
        "**Location**: crates/domain/src/block_tree.rs:L250\n\n"
        "### Finding [INV-002]: Perturbation: BTreeMap still has tie-break issue\n"
        "**Source IDs**: [PERT-2]\n"
        "**Severity**: Medium\n"
        "**Location**: crates/domain/src/block_tree.rs:L255\n\n"
    )

    count = _compute_dedup_candidate_pairs(sp)
    print(f"  Candidate pairs: {count}")
    assert count >= 1, f"PERT in same file should create pair, got {count}"


def test_candidate_pairs_source_ids_bold_colon_format(tmp_path):
    """Dedup source-ID parsing accepts `**Source IDs:**` drift."""
    sp = tmp_path / "scratchpad"
    sp.mkdir()

    (sp / "findings_inventory.md").write_text(
        "# Findings Inventory\n\n"
        "### Finding [INV-001]: Partial RwLock issue\n"
        "**Source IDs:** D-58, D-59\n"
        "**Severity**: Medium\n"
        "**Location**: crates/domain/src/block_tree.rs:L89\n\n"
        "### Finding [INV-002]: Complete RwLock cascade analysis\n"
        "**Source IDs:** D-57, D-58, D-59, D-60\n"
        "**Severity**: Medium\n"
        "**Location**: crates/domain/src/block_tree.rs:L45\n\n",
        encoding="utf-8",
    )

    count = _compute_dedup_candidate_pairs(sp)
    assert count >= 1
    content = (sp / "dedup_candidate_pairs.md").read_text(encoding="utf-8")
    assert "source-ID subset" in content


# ─── v2.8.5: All-blocked-no-receipt regression ─────────────────

def test_promotion_all_similar_findings_are_promoted_and_receipted(tmp_path):
    """Pre-verification similarity is tag-only and fully receipted."""
    sp = tmp_path / "scratchpad"
    sp.mkdir()

    inv = sp / "findings_inventory.md"
    inv.write_text(
        "# Findings Inventory\n\n"
        "### Finding [INV-001]: Oracle settlement TWAP backfills stale interval\n"
        "**Source IDs**: [OS-1]\n"
        "**Severity**: High\n"
        "**Location**: core/MarketManager.sol:L578\n"
        "**Preferred Tag**: oracle\n"
        "**Description**: TWAP backfill with terminal reserves.\n\n"
        "### Finding [INV-002]: Post-deadline sweeps bypass LBP migration\n"
        "**Source IDs**: [ML-1]\n"
        "**Severity**: High\n"
        "**Location**: launchpad/LBP.sol:L195\n"
        "**Preferred Tag**: liveness\n"
        "**Description**: Permissionless sweep drains reserves before migrate.\n\n"
    )

    depth = sp / "depth_external_findings.md"
    depth.write_text(
        "### Finding [DX-1]: Oracle settlement TWAP can backfill stale interval with terminal reserves\n"
        "**Severity**: High\n"
        "**Location**: core/MarketManager.sol:L578\n"
        "**Preferred Tag**: oracle\n"
        "**Verdict**: CONFIRMED\n"
        "**Description**: Same TWAP oracle backfill issue.\n\n"
        "### Finding [DX-2]: Permissionless post-deadline sweeps bypass LBP migration permanently\n"
        "**Severity**: High\n"
        "**Location**: launchpad/LBP.sol:L195\n"
        "**Preferred Tag**: liveness\n"
        "**Verdict**: CONFIRMED\n"
        "**Description**: Same sweep-before-migrate issue.\n\n"
    )

    from plamen_validators import _promote_depth_findings_to_inventory
    promoted = _promote_depth_findings_to_inventory(sp)
    print(f"  Promoted: {promoted}")
    assert promoted == ["DX-1", "DX-2"]

    receipt_path = sp / "depth_promotion_receipt.md"
    assert receipt_path.exists(), "Receipt MUST record every promoted finding"

    receipt = receipt_path.read_text()
    print(f"  Receipt content:\n{receipt[:500]}")
    assert "Promoted 2" in receipt
    assert "## Likely Duplicates" in receipt, "Must have Likely Duplicates section"
    assert "DX-1" in receipt
    assert "DX-2" in receipt
    inventory = inv.read_text(encoding="utf-8")
    assert "**Source IDs**: [DX-1]" in inventory
    assert "**Source IDs**: [DX-2]" in inventory


def test_promotion_all_similar_validator_passes(tmp_path):
    """Receipt validation passes when similar findings are promoted and tagged."""
    sp = tmp_path / "scratchpad"
    sp.mkdir()

    inv = sp / "findings_inventory.md"
    inv.write_text(
        "# Findings Inventory\n\n"
        "### Finding [INV-001]: Oracle TWAP stale backfill\n"
        "**Source IDs**: [OS-1]\n"
        "**Severity**: High\n"
        "**Location**: core/MarketManager.sol:L578\n"
        "**Preferred Tag**: oracle\n"
        "**Description**: TWAP issue.\n\n"
    )

    depth = sp / "depth_external_findings.md"
    depth.write_text(
        "### Finding [DX-1]: Oracle TWAP stale backfill with terminal reserves\n"
        "**Severity**: High\n"
        "**Location**: core/MarketManager.sol:L578\n"
        "**Preferred Tag**: oracle\n"
        "**Verdict**: CONFIRMED\n"
        "**Description**: Same issue.\n\n"
    )

    # Step 1: Run promotion; similarity tags DX-1 but cannot block it.
    from plamen_validators import (
        _promote_depth_findings_to_inventory,
        _validate_depth_promotion_receipt,
    )
    promoted = _promote_depth_findings_to_inventory(sp)
    assert promoted == ["DX-1"]

    # Step 2: Run the validator — it should find DX-1 in the receipt's
    # Likely Duplicates section and NOT flag it as missing
    issues = _validate_depth_promotion_receipt(sp)
    print(f"  Validator issues: {issues}")
    assert issues == [], (
        f"Validator should pass (DX-1 was promoted and receipted), got: {issues}"
    )


def test_promotion_mixed_similar_and_novel_both_promote(tmp_path):
    """Similar and novel findings both promote; similarity remains a hint."""
    sp = tmp_path / "scratchpad"
    sp.mkdir()

    inv = sp / "findings_inventory.md"
    inv.write_text(
        "# Findings Inventory\n\n"
        "### Finding [INV-001]: Oracle TWAP stale backfill\n"
        "**Source IDs**: [OS-1]\n"
        "**Severity**: High\n"
        "**Location**: core/MarketManager.sol:L578\n"
        "**Preferred Tag**: oracle\n"
        "**Description**: TWAP issue.\n\n"
    )

    depth = sp / "depth_external_findings.md"
    depth.write_text(
        "### Finding [DX-1]: Oracle TWAP stale backfill with terminal reserves\n"
        "**Severity**: High\n"
        "**Location**: core/MarketManager.sol:L578\n"
        "**Preferred Tag**: oracle\n"
        "**Verdict**: CONFIRMED\n"
        "**Description**: Same issue (should be blocked).\n\n"
        "### Finding [DX-2]: Completely novel governance executor rotation bug\n"
        "**Severity**: High\n"
        "**Location**: core/GovernanceExecutor.sol:L44\n"
        "**Preferred Tag**: governance\n"
        "**Verdict**: CONFIRMED\n"
        "**Description**: Different file, different bug.\n\n"
    )

    from plamen_validators import _promote_depth_findings_to_inventory
    promoted = _promote_depth_findings_to_inventory(sp)
    print(f"  Promoted: {promoted}")
    assert "DX-2" in promoted, "DX-2 is a novel finding, must be promoted"
    assert "DX-1" in promoted, "DX-1 must reach semantic verification"

    receipt = (sp / "depth_promotion_receipt.md").read_text()
    assert "## Promoted" in receipt, "Receipt must have Promoted section"
    assert "DX-2" in receipt, "Promoted DX-2 must appear in receipt"
    assert "## Likely Duplicates" in receipt, "Receipt must have Likely Duplicates"
    assert "DX-1" in receipt, "Blocked DX-1 must appear in receipt"

    inv_text = inv.read_text()
    assert "DX-2" in inv_text, "DX-2 must be appended to inventory"
    assert "DX-1" in inv_text and "LIKELY-DUP" in inv_text


if __name__ == "__main__":
    tests = [f for f in dir() if f.startswith("test_")]
    passed = 0
    failed = 0
    for name in sorted(tests):
        print(f"\n--- {name} ---")
        try:
            import inspect
            sig = inspect.signature(globals()[name])
            if sig.parameters:
                import tempfile
                with tempfile.TemporaryDirectory() as td:
                    globals()[name](Path(td))
            else:
                globals()[name]()
            print(f"  PASS")
            passed += 1
        except AssertionError as e:
            print(f"  FAIL: {e}")
            failed += 1
        except Exception as e:
            print(f"  ERROR: {type(e).__name__}: {e}")
            traceback.print_exc()
            failed += 1
    print(f"\n{'=' * 40}\n{passed} passed, {failed} failed")
