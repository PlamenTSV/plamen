"""Driver wiring tests for the three recall gates (Gate V, Gate P, Hook-4).

Gate V (`compute_variant_gaps`, enumeration_gate.py) and Gate P
(`compute_promotion_orphans` / `route_promotion_orphans`, plamen_mechanical.py)
are DONE modules with their own full test suites (`test_variant_gate_axes.py`,
`test_promotion_completeness.py`). This file does NOT re-test their internal
axis/harvest logic — it proves the DRIVER actually calls them at the correct
pipeline hook and that the wiring itself is haltless.

To make the wiring independently testable (the driver's phase-processing
logic otherwise lives inline inside two giant functions —
`_run_phase_validators` for Gate V, `main()` for Gate P/Hook-4), the driver
owner extracted three thin, directly-callable wrapper functions that the
inline call sites now invoke:

  - `plamen_driver._run_gate_v_for_phase(phase_name, scratchpad)`
  - `plamen_driver._run_gate_p_for_report_index(scratchpad)`
  - `plamen_driver._check_external_research_citation_gaps(scratchpad)` +
    `plamen_driver._append_external_research_appendix_note(scratchpad, root)`

Every positive-harvest test asserts a NON-EMPTY landing (a synthetic
candidate actually reaches `findings_inventory.md` / a gap ledger row is
written), not merely "does not crash" — per the ID-regex-catalog lesson that
an over-loose gate with an empty harvest is worse than none.

Run: `python -m pytest -q test_recall_gate_wiring.py`
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS_DIR))

import plamen_driver as D  # noqa: E402


# ─────────────────────────────────────────────────────────────────────────
# Gate V wiring: driver hook fires `compute_variant_gaps` and a synthetic
# VARGAP reaches findings_inventory.md.
# ─────────────────────────────────────────────────────────────────────────

def _sol(root: Path, rel: str, body: str) -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(
        "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.20;\n" + body,
        encoding="utf-8",
    )


def _finding_block(fid: str, loc: str, verdict: str, body: str, severity: str = "Medium") -> str:
    return (
        f"### Finding [{fid}]: a finding\n"
        f"**Severity**: {severity}\n"
        f"**Location**: `{loc}`\n"
        f"**Verdict**: {verdict}\n"
        "**Source IDs**: B1-1\n"
        f"{body}\n"
    )


def _write_inv(sp: Path, *blocks: str) -> None:
    (sp / "findings_inventory.md").write_text(
        "# Finding Inventory\n\n" + "\n\n".join(blocks) + "\n", encoding="utf-8"
    )


def test_gate_v_hook_fires_and_vargap_reaches_inventory(tmp_path: Path):
    root = tmp_path / "proj"
    sp = root / ".scratchpad"
    sp.mkdir(parents=True)
    _sol(
        root, "Vault.sol",
        "contract Vault {\n"
        "  function withdraw(uint256 amount) external {\n"
        "    // body\n"
        "  }\n}\n",
    )
    (sp / "_mechanical_graph.json").write_text(
        json.dumps({
            "source": "test", "var_refs": {},
            "functions": {
                "Vault.withdraw": {
                    "bare": "withdraw", "loc": "Vault.sol:L5", "callers": [],
                }
            },
        }),
        encoding="utf-8",
    )
    # Names 5 of 6 boundary members; omits MAX -> exactly one axis-2 VARGAP.
    _write_inv(sp, _finding_block(
        "INV-001", "Vault.sol:L5", "CONFIRMED",
        "Verified at zero amount; verified at one wei; enforces a minimum "
        "threshold; verified with an empty balance; verified for self "
        "transfers; safe otherwise.",
    ))

    result = D._run_gate_v_for_phase("depth", sp)
    assert result.get("emitted", 0) >= 1, result

    inv = (sp / "findings_inventory.md").read_text(encoding="utf-8")
    assert "VARGAP" in inv, "Gate V wiring must land a VARGAP in findings_inventory.md"


def test_gate_v_hook_no_op_when_graph_absent(tmp_path: Path):
    root = tmp_path / "proj"
    sp = root / ".scratchpad"
    sp.mkdir(parents=True)
    _sol(root, "Vault.sol", "contract Vault {\n  function withdraw(uint256 amount) external {}\n}\n")
    _write_inv(sp, _finding_block("INV-001", "Vault.sol:L2", "CONFIRMED", "no guard here"))
    # No _mechanical_graph.json at all.
    result = D._run_gate_v_for_phase("depth", sp)
    assert result.get("emitted", 0) == 0
    inv = (sp / "findings_inventory.md").read_text(encoding="utf-8")
    assert "VARGAP" not in inv


def test_gate_v_hook_never_raises_on_missing_scratchpad(tmp_path: Path):
    sp = tmp_path / "does_not_exist"
    result = D._run_gate_v_for_phase("depth", sp)
    assert result.get("emitted", 0) == 0


def test_gate_v_hook_never_raises_on_garbage_inputs(tmp_path: Path):
    root = tmp_path / "proj"
    sp = root / ".scratchpad"
    sp.mkdir(parents=True)
    (sp / "_mechanical_graph.json").write_text("not json {{{", encoding="utf-8")
    (sp / "chain_candidate_pairs.md").write_text("not a table at all", encoding="utf-8")
    (sp / "findings_inventory.md").write_text("### garbage\nno fields\n", encoding="utf-8")
    result = D._run_gate_v_for_phase("depth", sp)
    assert result.get("emitted", 0) == 0


# ─────────────────────────────────────────────────────────────────────────
# Gate P wiring: driver hook fires `compute_promotion_orphans` +
# `route_promotion_orphans` and a synthetic orphan is routed.
# ─────────────────────────────────────────────────────────────────────────

_SEED_HEADER = (
    "# Report Index Coverage Seed\n\n"
    "**Status**: DRIVER_ENUMERATED\n\n"
    "| Finding/Hyp ID | Expected Severity | Verdict | Mapped Hypothesis | Dedup Relation |\n"
    "|----------------|-------------------|---------|-------------------|----------------|\n"
    "| (none) | | | | no bounded IDs found |\n"
)


def _setup_promo(tmp_path: Path) -> Path:
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    (sp / "findings_inventory.md").write_text(
        "# Finding Inventory\n\n### Finding [INV-001]: placeholder\n"
        "**Severity**: Low\n**Location**: `core/Vault.sol:L1`\n"
        "**Description**: x\n**Impact**: y\n",
        encoding="utf-8",
    )
    (sp / "report_index_coverage_seed.md").write_text(_SEED_HEADER, encoding="utf-8")
    return sp


def test_gate_p_hook_routes_synthetic_orphan_to_body(tmp_path: Path):
    sp = _setup_promo(tmp_path)
    (sp / "skill_execution_gaps.md").write_text(
        "# Skill Execution Checklist\n\n"
        "| ID | Function | Location | Note | Status |\n"
        "|----|----------|----------|------|--------|\n"
        "| DA-2 | withdraw | core/Vault.sol:L120 | withdraw() fails to "
        "validate the recipient address, allowing an attacker to drain "
        "unclaimed rewards to an arbitrary account | CONFIRMED |\n",
        encoding="utf-8",
    )

    result = D._run_gate_p_for_report_index(sp)
    assert result["emitted_to_inventory"] >= 1, result

    inv = (sp / "findings_inventory.md").read_text(encoding="utf-8")
    assert "PROMOGAP" in inv
    assert "drain" in inv.lower()
    assert "NEEDS_VERIFICATION" in inv


def test_gate_p_hook_backfills_coverage_seed_for_promoted_body_candidate(tmp_path: Path):
    """The driver-owned recall-safety extension: a BODY-routed PROMOGAP ID
    must additively reappear in report_index_coverage_seed.md so the Index
    Agent's bounded completeness check (which is told NOT to bulk-read
    findings_inventory.md) still accounts for it."""
    sp = _setup_promo(tmp_path)
    (sp / "skill_execution_gaps.md").write_text(
        "# Skill Execution Checklist\n\n"
        "| ID | Function | Location | Note | Status |\n"
        "|----|----------|----------|------|--------|\n"
        "| DA-2 | withdraw | core/Vault.sol:L120 | withdraw() fails to "
        "validate the recipient address, allowing an attacker to drain "
        "unclaimed rewards to an arbitrary account | CONFIRMED |\n",
        encoding="utf-8",
    )

    D._run_gate_p_for_report_index(sp)

    inv = (sp / "findings_inventory.md").read_text(encoding="utf-8")
    import re
    new_ids = set(re.findall(r"\bINV-\d+\b", inv)) - {"INV-001"}
    assert new_ids, "expected at least one new PROMOGAP INV id in inventory"

    seed = (sp / "report_index_coverage_seed.md").read_text(encoding="utf-8")
    for fid in new_ids:
        assert fid in seed, f"{fid} promoted to BODY but missing from coverage seed"
    assert "no bounded IDs found" not in seed


def test_gate_p_hook_no_op_when_coverage_seed_absent(tmp_path: Path):
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
    # No report_index_coverage_seed.md at all.
    result = D._run_gate_p_for_report_index(sp)
    assert result == {
        "harvested": 0, "body_candidates": 0, "appendix_c": 0,
        "appendix_a": 0, "emitted_to_inventory": 0,
    }


def test_gate_p_hook_never_raises_on_missing_scratchpad(tmp_path: Path):
    sp = tmp_path / "does_not_exist"
    result = D._run_gate_p_for_report_index(sp)
    assert result["harvested"] == 0


# ─────────────────────────────────────────────────────────────────────────
# Hook-4 wiring: uncited external-assumption findings land a non-empty
# external_research_gaps.md row and never halt.
# ─────────────────────────────────────────────────────────────────────────

def test_hook4_uncited_external_assumption_tag_writes_gap_row(tmp_path: Path):
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    (sp / "findings_inventory.md").write_text(
        "# Finding Inventory\n\n"
        "### Finding [H-07]: bridge messenger send assumed always-succeed\n"
        "**Severity**: High\n"
        "**Location**: `Gateway.sol:L140`\n"
        "**Evidence**: [EXTERNAL-ASSUMPTION: zero-gas send always succeeds]\n"
        "**Description**: The bridge messenger's send() return value is "
        "assumed to always succeed at zero gas cost; worst-case per R10.\n"
        "**Impact**: funds may be lost if the messenger silently fails.\n",
        encoding="utf-8",
    )

    n = D._check_external_research_citation_gaps(sp)
    assert n >= 1

    ledger = (sp / "external_research_gaps.md").read_text(encoding="utf-8")
    assert "H-07" in ledger
    assert "Gateway.sol:L140" in ledger


def test_hook4_cited_external_assumption_is_not_flagged(tmp_path: Path):
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    (sp / "findings_inventory.md").write_text(
        "# Finding Inventory\n\n"
        "### Finding [H-08]: bridge messenger send assumed always-succeed\n"
        "**Severity**: High\n"
        "**Location**: `Gateway.sol:L140`\n"
        "**Evidence**: [EXTERNAL-ASSUMPTION: zero-gas send always succeeds] "
        "[EXT-CITED: IBridgeMessenger, source=https://example.test, fetched=2026-07-12]\n"
        "**Description**: cited.\n",
        encoding="utf-8",
    )
    n = D._check_external_research_citation_gaps(sp)
    assert n == 0
    assert not (sp / "external_research_gaps.md").exists()


def test_hook4_uncited_finding_at_researched_surface_location_is_flagged(tmp_path: Path):
    """Axis (b): a finding with NO [EXTERNAL-ASSUMPTION] tag of its own but
    whose Location sits inside a researched external-dependency integration
    surface (Hook 1's recon-baked ledger) is still flagged when uncited."""
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    (sp / "external_dependency_research.md").write_text(
        "# External Dependency Research\n\n"
        "| Dependency | Integration Surface | Assumed Behavior | Real Behavior | Source | Conformance | Fetch Status |\n"
        "|---|---|---|---|---|---|---|\n"
        "| IBridgeMessenger | Gateway.sol:L140 | returns success bool | "
        "unknown | - | CHECK | FETCH_FAILED:no deployed address |\n",
        encoding="utf-8",
    )
    (sp / "findings_inventory.md").write_text(
        "# Finding Inventory\n\n"
        "### Finding [H-09]: messenger return value not checked\n"
        "**Severity**: High\n"
        "**Location**: `Gateway.sol:L140`\n"
        "**Description**: return value of the external messenger call is "
        "not validated.\n",
        encoding="utf-8",
    )
    n = D._check_external_research_citation_gaps(sp)
    assert n >= 1
    ledger = (sp / "external_research_gaps.md").read_text(encoding="utf-8")
    assert "H-09" in ledger
    assert "IBridgeMessenger" in ledger


def test_hook4_never_raises_when_inputs_absent(tmp_path: Path):
    sp = tmp_path / "does_not_exist"
    n = D._check_external_research_citation_gaps(sp)
    assert n == 0

    sp2 = tmp_path / ".scratchpad"
    sp2.mkdir()
    # No findings_inventory.md, no verify_*.md, no research ledger.
    n2 = D._check_external_research_citation_gaps(sp2)
    assert n2 == 0
    assert not (sp2 / "external_research_gaps.md").exists()


def test_hook4_zero_denominator_removes_stale_projection(tmp_path: Path):
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    stale = sp / "external_research_gaps.md"
    stale.write_text("stale prior gap\n", encoding="utf-8")

    assert D._check_external_research_citation_gaps(sp) == 0
    assert not stale.exists()


def test_hook4_never_raises_on_garbage_inputs(tmp_path: Path):
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    (sp / "findings_inventory.md").write_text("not a finding block at all\n", encoding="utf-8")
    (sp / "external_dependency_research.md").write_text("not a table\n", encoding="utf-8")
    n = D._check_external_research_citation_gaps(sp)
    assert n == 0


def test_hook4_appendix_note_surfaces_gap_ledger_on_report(tmp_path: Path):
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    root = tmp_path / "proj"
    root.mkdir()
    (sp / "external_research_gaps.md").write_text(
        "# External-Dependency Research Gaps\n\n"
        "| Finding ID | Dependency | Integration Surface | Reason |\n"
        "|------------|------------|----------------------|--------|\n"
        "| H-07 | IBridgeMessenger | `Gateway.sol:L140` | uncited [EXTERNAL-ASSUMPTION] tag |\n",
        encoding="utf-8",
    )
    (root / "AUDIT_REPORT.md").write_text(
        "# Security Audit Report\n\n## Summary\n\nSome content.\n", encoding="utf-8",
    )

    n = D._append_external_research_appendix_note(sp, root)
    assert n >= 1
    report = (root / "AUDIT_REPORT.md").read_text(encoding="utf-8")
    assert "Appendix D: External-Dependency Research Gaps" in report
    assert "H-07" in report

    # Idempotent: a second call does not duplicate the section.
    n2 = D._append_external_research_appendix_note(sp, root)
    assert n2 == 0
    report2 = (root / "AUDIT_REPORT.md").read_text(encoding="utf-8")
    assert report2.count("Appendix D: External-Dependency Research Gaps") == 1


def test_hook4_appendix_note_no_op_when_ledger_empty_or_absent(tmp_path: Path):
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    root = tmp_path / "proj"
    root.mkdir()
    (root / "AUDIT_REPORT.md").write_text("# Report\n", encoding="utf-8")

    # No ledger at all.
    assert D._append_external_research_appendix_note(sp, root) == 0
    assert "Appendix D" not in (root / "AUDIT_REPORT.md").read_text(encoding="utf-8")

    # Empty ledger (no gap rows).
    (sp / "external_research_gaps.md").write_text(
        "# External-Dependency Research Gaps\n\n"
        "| Finding ID | Dependency | Integration Surface | Reason |\n"
        "|------------|------------|----------------------|--------|\n"
        "| (none) | | | no uncited external-assumption findings |\n",
        encoding="utf-8",
    )
    assert D._append_external_research_appendix_note(sp, root) == 0
    assert "Appendix D" not in (root / "AUDIT_REPORT.md").read_text(encoding="utf-8")


def test_hook4_appendix_note_never_raises_on_missing_report(tmp_path: Path):
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    (sp / "external_research_gaps.md").write_text(
        "| Finding ID | Dependency | Integration Surface | Reason |\n"
        "|------------|------------|----------------------|--------|\n"
        "| H-01 | X | `a.sol:L1` | uncited |\n",
        encoding="utf-8",
    )
    root = tmp_path / "does_not_exist_proj"
    assert D._append_external_research_appendix_note(sp, root) == 0


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-q"]))
