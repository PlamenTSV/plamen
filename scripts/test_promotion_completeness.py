"""Gate P — content-shaped Promotion Completeness (Class C pipeline-loss).

Replaces the v2.8.9 ID-pattern feeder harvest (86% net-noise: promoted on
bare ID-token presence with no harm signal) with a CONTENT-SHAPED harvest:
`compute_promotion_orphans` only harvests a candidate when it carries a real
`file:Lnnn` location + a generic defect-mechanism cue + enough descriptive
text — bare ID-pattern noise never becomes a candidate. `route_promotion_orphans`
then routes each orphan through the EXISTING material-harm classifier
(`classify_body_or_appendix`, the same primitive `write_disposition_md` /
`enforce_material_harm_floor` already use) — never straight to body-at-severity.

Covers every "hiding spot" named in the design (checklist cell / summary-table
row / referent-less EXCLUDED stub / unpromoted `depth_*` finding block) crossed
with the 3 dispositions (harm -> BODY, quality -> Appendix C, refuted ->
Appendix A), plus: already-tracked dedup, resume-idempotency, the v2.8.9
noise-flood regression, the graph/ledger-absent no-op, and per-run bounding.

No protocol/token/contract name appears in any fixture (Part-0 no-overfit) —
every fixture uses a generic placeholder path (`core/Vault.sol`, `Escrow.sol`,
`Encoder.sol`, `Oracle.sol`) purely as an illustrative file-shape example.

Run: `python -m pytest -q test_promotion_completeness.py`
"""
from __future__ import annotations

import importlib
import os
import sys
from pathlib import Path


def _mech():
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    return importlib.import_module("plamen_mechanical")


_SEED_HEADER = (
    "# Report Index Coverage Seed\n\n"
    "**Status**: DRIVER_ENUMERATED\n\n"
    "| Finding/Hyp ID | Expected Severity | Verdict | Mapped Hypothesis | Dedup Relation |\n"
    "|----------------|-------------------|---------|-------------------|----------------|\n"
)


def _setup(tmp_path: Path, *, seed_rows: str = "| (none) | | | | no bounded IDs found |\n") -> Path:
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    (sp / "findings_inventory.md").write_text(
        "# Finding Inventory\n\n### Finding [INV-001]: placeholder\n"
        "**Severity**: Low\n**Location**: `core/Vault.sol:L1`\n"
        "**Description**: x\n**Impact**: y\n",
        encoding="utf-8",
    )
    (sp / "report_index_coverage_seed.md").write_text(
        _SEED_HEADER + seed_rows, encoding="utf-8"
    )
    return sp


# --------------------------------------------------------------------------
# Hiding spot 1: checklist / table cell with concrete harm -> BODY
# --------------------------------------------------------------------------

def test_checklist_cell_harm_routes_to_body(tmp_path: Path):
    m = _mech()
    sp = _setup(tmp_path)
    (sp / "skill_execution_gaps.md").write_text(
        "# Skill Execution Checklist\n\n"
        "| ID | Function | Location | Note | Status |\n"
        "|----|----------|----------|------|--------|\n"
        "| DA-2 | withdraw | core/Vault.sol:L120 | withdraw() fails to validate "
        "the recipient address, allowing an attacker to drain unclaimed rewards "
        "to an arbitrary account | CONFIRMED |\n",
        encoding="utf-8",
    )
    orphans = m.compute_promotion_orphans(sp)
    assert orphans, "checklist cell with location+mechanism+harm must be harvested"
    cand = next(c for c in orphans if c["shape"] == "table_row")
    assert cand["disposition"] == "BODY"
    assert "core/Vault.sol:L120" in cand["location"]

    result = m.route_promotion_orphans(sp, orphans)
    assert result["emitted_to_inventory"] >= 1
    inv = (sp / "findings_inventory.md").read_text(encoding="utf-8")
    assert "PROMOGAP" in inv
    assert "drain" in inv.lower()


# --------------------------------------------------------------------------
# Hiding spot 2: summary-table row, pure quality -> Appendix C
# --------------------------------------------------------------------------

def test_summary_table_row_quality_proposal_routes_to_verification(tmp_path: Path):
    m = _mech()
    sp = _setup(tmp_path)
    (sp / "validation_sweep_findings.md").write_text(
        "# Validation Sweep Summary\n\n"
        "| Location | Note |\n"
        "|----------|------|\n"
        "| core/Reward.sol:L88 | setFee() does not emit an event when the fee "
        "value is changed by governance |\n",
        encoding="utf-8",
    )
    orphans = m.compute_promotion_orphans(sp)
    assert orphans, "summary-table row with location+mechanism must be harvested"
    cand = next(c for c in orphans if c["shape"] == "table_row")
    assert cand["disposition"] == "BODY"
    assert cand["zero_harm_proposal"] is True

    result = m.route_promotion_orphans(sp, orphans)
    assert result["emitted_to_inventory"] >= 1
    inv = (sp / "findings_inventory.md").read_text(encoding="utf-8")
    assert "PROMOGAP" in inv
    assert "Zero-Harm Proposal" in inv


# --------------------------------------------------------------------------
# Hiding spot 3: referent-less EXCLUDED stub, content-bearing -> BODY
# --------------------------------------------------------------------------

def test_referent_less_excluded_stub_content_bearing_routes_to_body(tmp_path: Path):
    m = _mech()
    sp = _setup(tmp_path)
    (sp / "analysis_percontract_2.md").write_text(
        "# Per-Contract Agent 2\n\n"
        "EXCLUDED [PC2-5] encoder byte-width mismatch at Encoder.sol:L412 "
        "— truncates the high byte so a crafted account passes validation, "
        "draining escrowed funds to an attacker-controlled address\n",
        encoding="utf-8",
    )
    orphans = m.compute_promotion_orphans(sp)
    assert orphans, "content-bearing referent-less EXCLUDED stub must be harvested"
    cand = next(c for c in orphans if c["shape"] == "excluded_stub")
    assert cand["content_bearing"] is True
    assert cand["disposition"] == "BODY"

    result = m.route_promotion_orphans(sp, orphans)
    assert result["emitted_to_inventory"] >= 1
    inv = (sp / "findings_inventory.md").read_text(encoding="utf-8")
    assert "Encoder.sol:L412" in inv


def test_referent_less_excluded_stub_content_less_routes_to_visible_debt(tmp_path: Path):
    m = _mech()
    sp = _setup(tmp_path)
    (sp / "analysis_percontract_3.md").write_text(
        "# Per-Contract Agent 3\n\n"
        "EXCLUDED [PC3-9] already known\n",
        encoding="utf-8",
    )
    orphans = m.compute_promotion_orphans(sp)
    assert orphans, "even a content-less referent-less stub must be harvested (never dropped)"
    cand = next(c for c in orphans if c["shape"] == "excluded_stub")
    assert cand["content_bearing"] is False
    assert cand["disposition"] == "BODY"
    assert cand["shape_debt"] is True

    result = m.route_promotion_orphans(sp, orphans)
    assert result["emitted_to_inventory"] >= 1
    inv = (sp / "findings_inventory.md").read_text(encoding="utf-8")
    assert "PROMOGAP" in inv
    assert "Promotion Shape Debt" in inv


def test_excluded_stub_with_textual_referent_is_alias_proposal(tmp_path: Path):
    """Textual duplication nominates equivalence but cannot apply it."""
    m = _mech()
    sp = _setup(tmp_path)
    (sp / "analysis_percontract_4.md").write_text(
        "# Per-Contract Agent 4\n\n"
        "EXCLUDED [PC4-1] dup of [B1-2] same encoder mismatch at Encoder.sol:L412\n",
        encoding="utf-8",
    )
    orphans = m.compute_promotion_orphans(sp)
    candidate = next(c for c in orphans if c["shape"] == "excluded_stub")
    assert candidate["alias_proposal"] is True
    assert candidate["alias_target"] == "B1-2"
    assert candidate["disposition"] == "BODY"


# --------------------------------------------------------------------------
# Hiding spot 4: unpromoted depth_* finding block, verifier-refuted -> Appendix A
# --------------------------------------------------------------------------

def test_unpromoted_depth_block_refuted_reopens_for_verification(tmp_path: Path):
    m = _mech()
    sp = _setup(tmp_path)
    (sp / "depth_state_trace_findings.md").write_text(
        "# Depth State-Trace Findings\n\n"
        "## Finding [DE-11]: reentrancy drains the escrow during withdraw\n"
        "**Verdict**: REFUTED\n"
        "**Location**: `core/Escrow.sol:L215`\n"
        "**Severity**: High\n"
        "**Description**: Reentrancy would drain the escrow balance during "
        "withdraw, but the nonReentrant guard at L210 blocks the re-entrant "
        "call before any state is read.\n"
        "**Impact**: N/A — refuted; the guard blocks the attack path.\n\n",
        encoding="utf-8",
    )
    orphans = m.compute_promotion_orphans(sp)
    assert orphans, "unpromoted depth_* finding block must be harvested"
    cand = next(c for c in orphans if c["shape"] == "finding_block")
    assert cand["orig_id"] == "DE-11"
    assert cand["disposition"] == "BODY"
    assert cand["negative_proposal"] is True
    assert "authority" in cand["reason"].lower()

    result = m.route_promotion_orphans(sp, orphans)
    assert result["emitted_to_inventory"] >= 1
    inv = (sp / "findings_inventory.md").read_text(encoding="utf-8")
    assert "PROMOGAP" in inv
    assert "Negative Proposal" in inv


# --------------------------------------------------------------------------
# A producer-local ID is never sufficient suppression authority
# --------------------------------------------------------------------------

def test_already_tracked_id_does_not_suppress_distinct_subject(tmp_path: Path):
    m = _mech()
    sp = _setup(
        tmp_path,
        seed_rows="| DE-3 | High | PARTIAL | H-7 | |\n",
    )
    (sp / "depth_token_flow_findings.md").write_text(
        "# Depth Token-Flow Findings\n\n"
        "## Finding [DE-3]: stale price used in liquidation\n"
        "**Verdict**: PARTIAL\n"
        "**Location**: `core/Oracle.sol:L88`\n"
        "**Severity**: High\n"
        "**Description**: liquidate() fails to validate that the oracle price "
        "is fresh, allowing a liquidation to use a stale price and drain "
        "excess collateral from the borrower.\n"
        "**Impact**: the borrower loses excess collateral to the liquidator.\n\n",
        encoding="utf-8",
    )
    orphans = m.compute_promotion_orphans(sp)
    assert any(c.get("orig_id") == "DE-3" for c in orphans), (
        "a producer-local ID cannot prove byte-level identity or equivalence"
    )
    ledger = (sp / "promotion_orphans.md").read_text(encoding="utf-8")
    assert "Exact delivered/repeated subjects excluded: 0" in ledger


# --------------------------------------------------------------------------
# Resume-idempotency
# --------------------------------------------------------------------------

def test_resume_idempotency_second_call_identical(tmp_path: Path):
    m = _mech()
    sp = _setup(tmp_path)
    (sp / "skill_execution_gaps.md").write_text(
        "# Skill Execution Checklist\n\n"
        "| ID | Function | Location | Note | Status |\n"
        "|----|----------|----------|------|--------|\n"
        "| DA-2 | withdraw | core/Vault.sol:L120 | withdraw() fails to "
        "validate the recipient address, allowing an attacker to drain "
        "unclaimed rewards to an arbitrary account | CONFIRMED |\n",
        encoding="utf-8",
    )
    r1 = m.route_promotion_orphans(sp)
    inv_after_first = (sp / "findings_inventory.md").read_text(encoding="utf-8")
    assert r1["emitted_to_inventory"] >= 1

    r2 = m.route_promotion_orphans(sp)
    inv_after_second = (sp / "findings_inventory.md").read_text(encoding="utf-8")

    assert inv_after_first == inv_after_second, "second call must not duplicate inventory content"
    assert r2["emitted_to_inventory"] == 0, "already-emitted candidate must be skipped on resume"
    # PROMOGAP heading/tag appears exactly once, not duplicated.
    assert inv_after_second.count("Promotion-Completeness Candidates (PROMOGAP)") == 1
    assert inv_after_second.count("core/Vault.sol:L120") == 1


# --------------------------------------------------------------------------
# Regression: v2.8.9-style flood of low-harm ID-pattern candidates does NOT
# inflate the body count.
# --------------------------------------------------------------------------

def test_v289_style_id_pattern_flood_does_not_inflate_body(tmp_path: Path):
    m = _mech()
    sp = _setup(tmp_path)
    rows = "\n".join(
        f"| XX-{i} | reviewed, looks fine, no concrete issue identified here |"
        for i in range(1, 51)
    )
    (sp / "analysis_flood.md").write_text(
        "# Flood Analysis\n\n| ID | Note |\n|----|------|\n" + rows + "\n",
        encoding="utf-8",
    )
    orphans = m.compute_promotion_orphans(sp)
    assert orphans == [], (
        "bare ID-token rows with no location/mechanism must never become candidates "
        "(the exact v2.8.9 net-noise class)"
    )
    result = m.route_promotion_orphans(sp, orphans)
    assert result["emitted_to_inventory"] == 0
    inv = (sp / "findings_inventory.md").read_text(encoding="utf-8")
    assert "PROMOGAP" not in inv
    assert inv.count("### Finding [INV-") == 1, "only the pre-existing placeholder finding remains"


def test_flood_of_id_mentions_without_location_or_mechanism_in_prose(tmp_path: Path):
    """Prose (not table rows) that merely name-drops IDs must also be rejected."""
    m = _mech()
    sp = _setup(tmp_path)
    prose = " ".join(f"See DE-{i}, DE-{i+1} for details." for i in range(1, 30, 2))
    (sp / "analysis_prose_flood.md").write_text(
        "# Prose Flood\n\n" + prose + "\n", encoding="utf-8"
    )
    orphans = m.compute_promotion_orphans(sp)
    assert orphans == []


# --------------------------------------------------------------------------
# Recall-safe no-op: coverage seed absent -> mirrors enumeration_gate's
# graph-absent no-op contract.
# --------------------------------------------------------------------------

def test_no_seed_file_is_noop(tmp_path: Path):
    m = _mech()
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    (sp / "findings_inventory.md").write_text("# Finding Inventory\n", encoding="utf-8")
    (sp / "depth_state_trace_findings.md").write_text(
        "## Finding [DE-1]: x\n**Verdict**: CONFIRMED\n"
        "**Location**: `core/Vault.sol:L1`\n"
        "**Description**: does not validate the recipient, allowing drain of funds.\n"
        "**Impact**: funds drained.\n",
        encoding="utf-8",
    )
    assert m.compute_promotion_orphans(sp) == []
    result = m.route_promotion_orphans(sp)
    assert result == {
        "harvested": 0, "body_candidates": 0, "appendix_c": 0,
        "appendix_a": 0, "emitted_to_inventory": 0,
    }
    # No side-effect ledgers written when the gate never ran (no seed to harvest against).
    assert not (sp / "promotion_orphans.md").exists()


def test_missing_scratchpad_never_raises(tmp_path: Path):
    m = _mech()
    sp = tmp_path / "does_not_exist"
    assert m.compute_promotion_orphans(sp) == []
    result = m.route_promotion_orphans(sp)
    assert result["harvested"] == 0


# --------------------------------------------------------------------------
# Bounded: per-file and per-run caps hold even with many valid candidates.
# --------------------------------------------------------------------------

def test_per_file_cap_bounds_harvest(tmp_path: Path):
    m = _mech()
    sp = _setup(tmp_path)
    rows = "\n".join(
        f"| Vault.sol:L{100+i} | withdraw() does not validate parameter {i}, "
        f"allowing an attacker to drain funds via path {i} |"
        for i in range(1, 21)  # 20 valid rows, well above _PROMO_MAX_PER_FILE
    )
    (sp / "analysis_many.md").write_text(
        "# Many Findings\n\n| Location | Note |\n|----------|------|\n" + rows + "\n",
        encoding="utf-8",
    )
    orphans = m.compute_promotion_orphans(sp)
    per_file = [c for c in orphans if c["source_file"] == "analysis_many.md"]
    assert 0 < len(per_file) <= m._PROMO_MAX_PER_FILE


# --------------------------------------------------------------------------
# Precision regressions (from the Spectra isolation replay, 2026-07-12).
# The coverage seed tracks hypothesis/report IDs with NO locations and never the
# raw depth-agent IDs (DE-N) the feeders carry, so ID-only reconciliation
# re-flagged every already-consolidated finding as a false orphan (24/30 on the
# real run — the v2.8.9 net-noise class). And the content-shape test accepted
# methodology/meta section headers and "No Additional Findings" rationale blocks
# as findings. Both are now closed; these tests lock them.
# --------------------------------------------------------------------------

def test_location_covered_by_inventory_is_only_duplicate_nomination(tmp_path: Path):
    m = _mech()
    sp = _setup(tmp_path)  # inventory has a promoted finding at core/Vault.sol:L1
    # Same location, a raw depth-agent ID the coverage seed never carries.
    (sp / "depth_edge_case_findings.md").write_text(
        "# Depth Edge-Case Findings\n\n"
        "## Finding [DE-9]: withdraw lacks a zero-amount guard\n"
        "**Verdict**: CONFIRMED\n"
        "**Location**: `core/Vault.sol:L12`\n"
        "**Severity**: Medium\n"
        "**Description**: withdraw() is missing a check and allows a zero-amount "
        "call to corrupt the share accounting.\n"
        "**Impact**: depositors lose value.\n\n",
        encoding="utf-8",
    )
    orphans = m.compute_promotion_orphans(sp)
    assert any(c.get("orig_id") == "DE-9" for c in orphans), (
        "location proximity must not apply semantic dedup without equivalence authority"
    )


def test_location_NOT_covered_still_harvested(tmp_path: Path):
    # Control for the test above: a genuinely-lost finding at an UNcovered location
    # must still be harvested (the location guard must not over-suppress).
    m = _mech()
    sp = _setup(tmp_path)  # inventory only covers core/Vault.sol:L1
    (sp / "depth_edge_case_findings.md").write_text(
        "# Depth Edge-Case Findings\n\n"
        "## Finding [DE-40]: setFee lacks an upper-bound check\n"
        "**Verdict**: CONFIRMED\n"
        "**Location**: `svc/Fees.sol:L900`\n"
        "**Severity**: Medium\n"
        "**Description**: setFee() is missing an upper-bound guard and allows the "
        "fee to be set above 100%, bricking every withdrawal.\n"
        "**Impact**: users cannot withdraw.\n\n",
        encoding="utf-8",
    )
    orphans = m.compute_promotion_orphans(sp)
    assert any(c.get("orig_id") == "DE-40" for c in orphans), (
        "a genuine pipeline-loss at an uncovered location must still be harvested"
    )


def test_meta_heading_block_is_not_harvested(tmp_path: Path):
    m = _mech()
    sp = _setup(tmp_path)
    (sp / "blind_spot_c_findings.md").write_text(
        "# Blind Spot C\n\n"
        "## Step Execution Checklist\n"
        "**Location**: `svc/Router.sol:L500`\n"
        "Enumerated every setter; the missing-validation check was performed and "
        "the guard is present. Methodology bookkeeping, not a finding.\n\n",
        encoding="utf-8",
    )
    assert not m.compute_promotion_orphans(sp), (
        "a methodology/meta section heading must never be harvested as a finding"
    )


def test_negative_disposition_block_is_harvested_as_proposal(tmp_path: Path):
    m = _mech()
    sp = _setup(tmp_path)
    (sp / "blind_spot_a_findings.md").write_text(
        "# Blind Spot A\n\n"
        "## No Additional Findings - CHECK 1 approve/allowance (rationale)\n"
        "**Location**: `svc/Router.sol:L620`\n"
        "Checked whether the allowance path is missing a guard; it is not — the "
        "approve flow is correct usage and permits no drain.\n\n",
        encoding="utf-8",
    )
    rows = m.compute_promotion_orphans(sp)
    assert len(rows) == 1
    assert rows[0]["disposition"] == "BODY"
    assert rows[0]["negative_proposal"] is True


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-q"]))
