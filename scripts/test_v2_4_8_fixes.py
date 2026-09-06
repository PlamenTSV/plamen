"""Tests for v2.4.8 fixes:
  Fix 1: _repair_report_index_dropouts ID normalization
  Fix 2: Hypothesis-aware verify queue dedup
  Fix 3: [LIKELY-DUP] blocking for high-confidence duplicates
"""
import re
from pathlib import Path

import pytest


# ---------------------------------------------------------------------------
# Fix 1: _repair_report_index_dropouts normalization
# ---------------------------------------------------------------------------

def _make_repair_scenario(sp, master_ids, excluded_ids, verify_ids):
    """Create the artifacts that _repair_report_index_dropouts reads."""
    # report_index.md with a Master Finding Index table
    lines = [
        "# Report Index\n",
        "## Master Finding Index\n",
        "| Report ID | Title | Severity | Location | Verification | Trust Adj. | Internal Hypothesis |\n",
        "|-----------|-------|----------|----------|--------------|-----------|--------------------|",
    ]
    for mid in master_ids:
        lines.append(f"| M-01 | title | Medium | file.sol:L1 | VERIFIED | - | {mid} |")
    lines.append("")
    lines.append("## Excluded Findings\n")
    lines.append("| Internal ID | Severity | Title | Exclusion Reason |\n")
    lines.append("|-------------|----------|-------|-----------------|")
    for eid in excluded_ids:
        lines.append(f"| {eid} | Low | title | FALSE_POSITIVE |")
    (sp / "report_index.md").write_text("\n".join(lines), encoding="utf-8")

    # verification_queue.md with verify_ids
    q_lines = [
        "# Verification Queue Manifest\n",
        "| Queue # | Finding ID | Severity | Title | Bug Class | Preferred Tag | Location | Primary Artifact | PoC Class |\n",
        "|---------|-----------|----------|-------|-----------|--------------|----------|------------------|-----------|\n",
    ]
    for i, vid in enumerate(verify_ids, 1):
        q_lines.append(f"| {i} | {vid} | Medium | title | Bug | CODE-TRACE | file.sol:L1 | inv | structural |")
    q_lines.append(f"\nTotal: {len(verify_ids)} findings | Expected verify_F-*.md files: {len(verify_ids)}\n")
    (sp / "verification_queue.md").write_text("\n".join(q_lines), encoding="utf-8")


def test_repair_normalization_prevents_duplicate_injection(tmp_path):
    """H-01 in master and H-1 in verify should NOT be treated as dropout."""
    sp = tmp_path / "scratchpad"
    sp.mkdir()
    _make_repair_scenario(
        sp,
        master_ids=["H-01", "H-02", "H-03"],
        excluded_ids=["H-04"],
        verify_ids=["H-1", "H-2", "H-3", "H-4"],
    )
    from plamen_validators import _repair_report_index_dropouts
    repaired = _repair_report_index_dropouts(sp)
    assert len(repaired) == 0, f"Expected 0 repairs (all covered via normalization), got {repaired}"


def test_repair_normalization_detects_real_dropout(tmp_path):
    """H-5 not in master or excluded should be detected as real dropout."""
    sp = tmp_path / "scratchpad"
    sp.mkdir()
    _make_repair_scenario(
        sp,
        master_ids=["H-01", "H-02"],
        excluded_ids=["H-03"],
        verify_ids=["H-1", "H-2", "H-3", "H-5"],
    )
    # Need a verify_H-5.md file for the repair to find
    (sp / "verify_H-5.md").write_text(
        "# Hypothesis H-5\n**Verdict**: CONFIRMED\n**Severity**: Medium\n",
        encoding="utf-8",
    )
    from plamen_validators import _repair_report_index_dropouts
    repaired = _repair_report_index_dropouts(sp)
    assert len(repaired) >= 1, f"H-5 should be detected as a real dropout, got {repaired}"


def test_repair_normalization_symmetric(tmp_path):
    """Both directions: H-1 master vs H-01 verify, and H-01 master vs H-1 verify."""
    sp = tmp_path / "scratchpad"
    sp.mkdir()
    # Master has bare "H-1", verify has zero-padded "H-01"
    _make_repair_scenario(
        sp,
        master_ids=["H-1"],
        excluded_ids=[],
        verify_ids=["H-01"],
    )
    from plamen_validators import _repair_report_index_dropouts
    repaired = _repair_report_index_dropouts(sp)
    assert len(repaired) == 0, "H-1 == H-01 via normalization"


# ---------------------------------------------------------------------------
# Fix 2: Hypothesis-aware verify queue dedup
# ---------------------------------------------------------------------------

def _make_hypothesis_scenario(sp, hypotheses_content, queue_rows):
    """Create hypotheses.md and verification_queue.md for dedup testing."""
    (sp / "hypotheses.md").write_text(hypotheses_content, encoding="utf-8")

    header = (
        "# Verification Queue Manifest\n"
        "| Queue # | Finding ID | Severity | Title | Bug Class | Preferred Tag | Location | Primary Artifact | PoC Class |\n"
        "|---------|-----------|----------|-------|-----------|--------------|----------|------------------|-----------|\n"
    )
    body = []
    for i, row in enumerate(queue_rows, 1):
        body.append(
            f"| {i} | {row['id']} | {row['sev']} | {row['title']} | "
            f"Bug | CODE-TRACE | {row.get('loc', 'file.sol:L1')} | inv | structural |"
        )
    footer = f"\nTotal: {len(queue_rows)} findings | Expected verify_F-*.md files: {len(queue_rows)}\n"
    (sp / "verification_queue.md").write_text(header + "\n".join(body) + footer, encoding="utf-8")


def test_dedup_does_not_collapse_unproven_multi_member_hypothesis(tmp_path):
    """Raw Markdown grouping cannot destructively collapse queue members."""
    sp = tmp_path / "scratchpad"
    sp.mkdir()

    hypotheses = (
        "## Hypothesis H-1: Missing Access Control\n"
        "**Constituent Findings**: INV-001, INV-002, INV-003\n"
        "**Severity**: High\n\n"
        "## Hypothesis H-2: Unchecked Return Value\n"
        "**Constituent Findings**: INV-004\n"
        "**Severity**: Medium\n"
    )
    queue = [
        {"id": "INV-001", "sev": "High", "title": "Access control A"},
        {"id": "INV-002", "sev": "Medium", "title": "Access control B"},
        {"id": "INV-003", "sev": "Low", "title": "Access control C"},
        {"id": "INV-004", "sev": "Medium", "title": "Unchecked return"},
    ]
    _make_hypothesis_scenario(sp, hypotheses, queue)

    from plamen_parsers import _dedup_queue_by_hypothesis, parse_verification_queue_rows
    removed = _dedup_queue_by_hypothesis(sp)
    assert removed == 0

    rows = parse_verification_queue_rows(sp)
    finding_ids = [r.get("finding id", "").upper() for r in rows]
    assert {"INV-001", "INV-002", "INV-003"} <= set(finding_ids)
    assert "H-2" in finding_ids, "Single-constituent hypothesis should also use hypo ID"
    assert len(rows) == 4


def test_dedup_preserves_each_severity_for_unproven_group(tmp_path):
    """Proposal-only grouping preserves each constituent and its severity."""
    sp = tmp_path / "scratchpad"
    sp.mkdir()

    hypotheses = (
        "## Hypothesis H-1: Price Manipulation\n"
        "INV-010 is Critical, INV-011 is Medium.\n"
        "Both share the same root cause.\n"
    )
    queue = [
        {"id": "INV-010", "sev": "Critical", "title": "Flash loan price manip"},
        {"id": "INV-011", "sev": "Medium", "title": "Oracle staleness enables manip"},
    ]
    _make_hypothesis_scenario(sp, hypotheses, queue)

    from plamen_parsers import _dedup_queue_by_hypothesis, parse_verification_queue_rows
    removed = _dedup_queue_by_hypothesis(sp)
    assert removed == 0

    rows = parse_verification_queue_rows(sp)
    assert len(rows) == 2
    assert {row.get("severity", "").lower() for row in rows} == {
        "critical", "medium"
    }


def test_dedup_unmapped_rows_preserved(tmp_path):
    """Rows not in any hypothesis stay in the queue unchanged."""
    sp = tmp_path / "scratchpad"
    sp.mkdir()

    hypotheses = (
        "## Hypothesis H-1: Bug A\n"
        "Constituent: INV-001\n"
    )
    queue = [
        {"id": "INV-001", "sev": "High", "title": "Bug A"},
        {"id": "INV-099", "sev": "Medium", "title": "Orphan finding"},
    ]
    _make_hypothesis_scenario(sp, hypotheses, queue)

    from plamen_parsers import _dedup_queue_by_hypothesis, parse_verification_queue_rows
    removed = _dedup_queue_by_hypothesis(sp)
    assert removed == 0  # 1→1 for H-1, 1 orphan stays = 2 total, same as input

    rows = parse_verification_queue_rows(sp)
    assert len(rows) == 2
    finding_ids = {r.get("finding id", "").upper() for r in rows}
    assert "H-1" in finding_ids
    assert "INV-099" in finding_ids


def test_dedup_no_hypotheses_noop(tmp_path):
    """If hypotheses.md doesn't exist, dedup is a no-op."""
    sp = tmp_path / "scratchpad"
    sp.mkdir()

    header = (
        "# Verification Queue Manifest\n"
        "| Queue # | Finding ID | Severity | Title | Bug Class | Preferred Tag | Location | Primary Artifact | PoC Class |\n"
        "|---------|-----------|----------|-------|-----------|--------------|----------|------------------|-----------|\n"
    )
    body = "| 1 | INV-001 | High | Bug | Bug | CODE-TRACE | f.sol:L1 | inv | structural |"
    footer = "\nTotal: 1 findings | Expected verify_F-*.md files: 1\n"
    (sp / "verification_queue.md").write_text(header + body + footer, encoding="utf-8")

    from plamen_parsers import _dedup_queue_by_hypothesis
    removed = _dedup_queue_by_hypothesis(sp)
    assert removed == 0


def test_dedup_finding_mapping_preferred(tmp_path):
    """finding_mapping.md (if present) is used instead of hypotheses.md body scan."""
    sp = tmp_path / "scratchpad"
    sp.mkdir()

    # finding_mapping.md with explicit table
    mapping = (
        "# Finding Mapping\n\n"
        "| Finding ID | Hypothesis |\n"
        "|-----------|------------|\n"
        "| INV-001 | H-1 |\n"
        "| INV-002 | H-1 |\n"
        "| INV-003 | H-2 |\n"
    )
    (sp / "finding_mapping.md").write_text(mapping, encoding="utf-8")

    # hypotheses.md exists but we should prefer finding_mapping.md
    (sp / "hypotheses.md").write_text(
        "## Hypothesis H-1\nSome text\n## Hypothesis H-2\nSome text\n",
        encoding="utf-8",
    )

    queue = [
        {"id": "INV-001", "sev": "High", "title": "Bug A"},
        {"id": "INV-002", "sev": "Medium", "title": "Bug B"},
        {"id": "INV-003", "sev": "Low", "title": "Bug C"},
    ]
    _make_hypothesis_scenario(sp, "", queue)
    # Overwrite hypotheses.md with minimal content (finding_mapping.md has the real data)
    (sp / "finding_mapping.md").write_text(mapping, encoding="utf-8")

    from plamen_parsers import _dedup_queue_by_hypothesis, parse_verification_queue_rows
    removed = _dedup_queue_by_hypothesis(sp)
    assert removed == 0

    rows = parse_verification_queue_rows(sp)
    assert len(rows) == 3
    finding_ids = {r.get("finding id", "").upper() for r in rows}
    assert {"INV-001", "INV-002"} <= finding_ids
    assert "H-2" in finding_ids


def test_dedup_chain_hypotheses(tmp_path):
    """CH-* hypothesis IDs are handled correctly."""
    sp = tmp_path / "scratchpad"
    sp.mkdir()

    hypotheses = (
        "## Hypothesis H-1: Base Bug\n"
        "Constituent: INV-001\n\n"
        "## Chain Hypothesis CH-1\n"
        "Chain combines INV-002 and INV-003 into a compound attack.\n"
    )
    queue = [
        {"id": "INV-001", "sev": "High", "title": "Base bug"},
        {"id": "INV-002", "sev": "Medium", "title": "Enabler"},
        {"id": "INV-003", "sev": "Medium", "title": "Blocked finding"},
    ]
    _make_hypothesis_scenario(sp, hypotheses, queue)

    from plamen_parsers import _dedup_queue_by_hypothesis, parse_verification_queue_rows
    removed = _dedup_queue_by_hypothesis(sp)
    assert removed == 0

    rows = parse_verification_queue_rows(sp)
    finding_ids = {r.get("finding id", "").upper() for r in rows}
    assert "H-1" in finding_ids
    assert {"INV-002", "INV-003"} <= finding_ids
    assert "CH-1" not in finding_ids
    assert len(rows) == 3


# ---------------------------------------------------------------------------
# Fix 3: [LIKELY-DUP] blocking for high-confidence duplicates
# ---------------------------------------------------------------------------

def test_high_title_overlap_is_tag_only(tmp_path):
    """Title overlap >= 0.90 is a hint, not a pre-verification drop."""
    sp = tmp_path / "scratchpad"
    sp.mkdir()

    inv = sp / "findings_inventory.md"
    inv.write_text(
        "# Findings Inventory\n\n"
        "### Finding [INV-001]: Missing Access Control on Admin Setter\n"
        "**Source IDs**: [CS-1]\n"
        "**Severity**: High\n"
        "**Location**: src/Vault.sol:L40\n"
        "**Preferred Tag**: CODE-TRACE\n"
        "**Description**: Admin setter lacks access control.\n\n"
    )

    depth = sp / "depth_state_trace_findings.md"
    # Nearly identical title (>0.90 overlap)
    depth.write_text(
        "## DST-1: Missing Access Control on Admin Setter Function\n"
        "**Severity**: High\n"
        "**Location**: src/Vault.sol:L40\n"
        "**Preferred Tag**: CODE-TRACE\n"
        "**Verdict**: CONFIRMED\n"
        "**Description**: The admin setter lacks access control.\n\n"
    )

    from plamen_validators import _promote_depth_findings_to_inventory
    promoted = _promote_depth_findings_to_inventory(sp)
    assert "DST-1" in promoted
    assert "LIKELY-DUP" in (sp / "findings_inventory.md").read_text(encoding="utf-8")


def test_location_plus_moderate_title_is_tag_only(tmp_path):
    """Location plus moderate title similarity still reaches verification."""
    sp = tmp_path / "scratchpad"
    sp.mkdir()

    inv = sp / "findings_inventory.md"
    inv.write_text(
        "# Findings Inventory\n\n"
        "### Finding [INV-001]: Reentrancy in Withdraw Function\n"
        "**Source IDs**: [CS-1]\n"
        "**Severity**: High\n"
        "**Location**: src/Vault.sol:L100\n"
        "**Preferred Tag**: CODE-TRACE\n"
        "**Description**: Reentrancy.\n\n"
    )

    depth = sp / "depth_state_trace_findings.md"
    # Moderate title overlap (~0.6) + same location
    depth.write_text(
        "## DST-1: Reentrancy Vulnerability in Withdraw\n"
        "**Severity**: High\n"
        "**Location**: src/Vault.sol:L100\n"
        "**Preferred Tag**: CODE-TRACE\n"
        "**Verdict**: CONFIRMED\n"
        "**Description**: Reentrancy in withdraw.\n\n"
    )

    from plamen_parsers import _titles_overlap_score
    overlap = _titles_overlap_score(
        "Reentrancy in Withdraw Function",
        "Reentrancy Vulnerability in Withdraw",
    )
    assert overlap >= 0.50, f"Sanity check: expected overlap >= 0.50, got {overlap:.2f}"

    from plamen_validators import _promote_depth_findings_to_inventory
    promoted = _promote_depth_findings_to_inventory(sp)
    assert "DST-1" in promoted
    assert "LIKELY-DUP" in (sp / "findings_inventory.md").read_text(encoding="utf-8")


def test_tagging_low_title_overlap_with_location(tmp_path):
    """Location overlap + title overlap < 0.50 should TAG but promote."""
    sp = tmp_path / "scratchpad"
    sp.mkdir()

    inv = sp / "findings_inventory.md"
    inv.write_text(
        "# Findings Inventory\n\n"
        "### Finding [INV-001]: Unfiltered Debug Namespace in RPC\n"
        "**Source IDs**: [CS-1]\n"
        "**Severity**: High\n"
        "**Location**: src/proxy.rs:L40\n"
        "**Preferred Tag**: CODE-TRACE\n"
        "**Description**: Debug exposed.\n\n"
    )

    depth = sp / "depth_network_surface_findings.md"
    # Different bug at overlapping location
    depth.write_text(
        "## DN-1: Proxy Forwards All Methods Without Access List\n"
        "**Severity**: Medium\n"
        "**Location**: src/proxy.rs:L42\n"
        "**Preferred Tag**: CODE-TRACE\n"
        "**Verdict**: CONFIRMED\n"
        "**Description**: No method whitelist.\n\n"
    )

    from plamen_parsers import _titles_overlap_score
    overlap = _titles_overlap_score(
        "Unfiltered Debug Namespace in RPC",
        "Proxy Forwards All Methods Without Access List",
    )
    assert overlap < 0.50, f"Sanity: expected < 0.50, got {overlap:.2f}"

    from plamen_validators import _promote_depth_findings_to_inventory
    promoted = _promote_depth_findings_to_inventory(sp)
    assert "DN-1" in promoted, "Low title overlap + location should still promote"
    # Verify it's tagged
    inv_text = inv.read_text()
    assert "LIKELY-DUP" in inv_text
    assert "location overlap" in inv_text


def test_tagging_moderate_title_without_location(tmp_path):
    """Title overlap 0.80-0.89 without location overlap should TAG but promote."""
    sp = tmp_path / "scratchpad"
    sp.mkdir()

    inv = sp / "findings_inventory.md"
    inv.write_text(
        "# Findings Inventory\n\n"
        "### Finding [INV-001]: Incorrect Fee Calculation in Deposit Path\n"
        "**Source IDs**: [CS-1]\n"
        "**Severity**: Low\n"
        "**Location**: src/Fees.sol:L40\n"
        "**Preferred Tag**: CODE-TRACE\n"
        "**Description**: Fee calc wrong.\n\n"
    )

    depth = sp / "depth_state_trace_findings.md"
    # 0.80 title overlap at different location
    depth.write_text(
        "## DST-1: Incorrect Fee Calculation in Withdraw Path\n"
        "**Severity**: Low\n"
        "**Location**: src/Fees.sol:L200\n"
        "**Preferred Tag**: CODE-TRACE\n"
        "**Verdict**: CONFIRMED\n"
        "**Description**: Fee calc wrong in withdraw.\n\n"
    )

    from plamen_parsers import _titles_overlap_score
    overlap = _titles_overlap_score(
        "Incorrect Fee Calculation in Deposit Path",
        "Incorrect Fee Calculation in Withdraw Path",
    )
    assert 0.80 <= overlap < 0.90, f"Sanity: expected 0.80-0.89, got {overlap:.2f}"

    from plamen_validators import _promote_depth_findings_to_inventory
    promoted = _promote_depth_findings_to_inventory(sp)
    assert "DST-1" in promoted, "0.80 title without location overlap → promote with tag"
    inv_text = inv.read_text()
    assert "LIKELY-DUP" in inv_text


# ---------------------------------------------------------------------------
# Parse hypothesis constituents unit tests
# ---------------------------------------------------------------------------

def test_parse_hypothesis_constituents_from_hypotheses(tmp_path):
    """Parse constituents from hypotheses.md section bodies."""
    sp = tmp_path / "scratchpad"
    sp.mkdir()

    (sp / "hypotheses.md").write_text(
        "# Hypotheses\n\n"
        "## Hypothesis H-1: Access Control\n"
        "Root cause: INV-001, INV-002 both miss the onlyOwner check.\n"
        "INV-003 is related but lower severity.\n\n"
        "## Hypothesis H-2: Oracle Manipulation\n"
        "Root cause: INV-004 manipulates TWAP.\n"
        "## Chain Hypothesis CH-1\n"
        "INV-005 enables INV-006.\n",
        encoding="utf-8",
    )

    from plamen_parsers import _parse_hypothesis_constituents
    mapping = _parse_hypothesis_constituents(
        sp, apply_chain_grouping_authority=False
    )
    assert "H-1" in mapping
    assert set(mapping["H-1"]) == {"INV-001", "INV-002", "INV-003"}
    assert "H-2" in mapping
    assert "INV-004" in mapping["H-2"]
    assert "CH-1" in mapping
    assert set(mapping["CH-1"]) == {"INV-005", "INV-006"}


def test_parse_hypothesis_constituents_from_mapping(tmp_path):
    """finding_mapping.md table is preferred over hypotheses.md body scan."""
    sp = tmp_path / "scratchpad"
    sp.mkdir()

    (sp / "finding_mapping.md").write_text(
        "# Finding → Hypothesis Mapping\n\n"
        "| Finding | Hypothesis | Notes |\n"
        "|---------|-----------|-------|\n"
        "| INV-010 | H-5 | primary |\n"
        "| INV-011 | H-5 | secondary |\n"
        "| INV-012 | H-6 | standalone |\n",
        encoding="utf-8",
    )
    (sp / "hypotheses.md").write_text("## Hypothesis H-5\nblah\n", encoding="utf-8")

    from plamen_parsers import _parse_hypothesis_constituents
    mapping = _parse_hypothesis_constituents(
        sp, apply_chain_grouping_authority=False
    )
    assert set(mapping.get("H-5", [])) == {"INV-010", "INV-011"}
    assert set(mapping.get("H-6", [])) == {"INV-012"}
