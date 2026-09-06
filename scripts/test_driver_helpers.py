"""Unit-level smoke tests for v1.1.9 driver validator helpers.

Targets:
  - _validate_inventory_parity       (H1)
  - _validate_recon_coverage / _module_key  (A1)
  - _match_label_status / _validate_depth_exit  (H2)
  - graph sweep trigger / stale degraded sentinel cleanup

These complement test_driver_smoke.py, which is an end-to-end runtime
policy test. This file is fixture-based and fast; import the helpers
directly and assert on their returns.

Run: `python test_driver_helpers.py`
"""

from __future__ import annotations

import sys
import tempfile
import os
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS_DIR))

from plamen_types import plamen_home  # noqa: E402

import plamen_driver as D  # noqa: E402
import inventory_reemit_authority as R  # noqa: E402


PASS, FAIL = 0, 0


def check(label: str, ok: bool, detail: str = "") -> None:
    global PASS, FAIL
    if ok:
        PASS += 1
        print(f"  PASS  {label}")
    else:
        FAIL += 1
        print(f"  FAIL  {label} :: {detail}")


# --------------------------------------------------------------------------
# H1: _validate_inventory_parity
# --------------------------------------------------------------------------

def _mkscratch(files: dict[str, str]) -> Path:
    sp = Path(tempfile.mkdtemp(prefix="plamen_t_"))
    for name, body in files.items():
        (sp / name).write_text(body, encoding="utf-8")
    return sp


def _h1_finding(fid: str, title: str, location: str) -> str:
    """Render one deterministic, materially complete reconciliation block."""
    return (
        f"### Finding [{fid}]: {title}\n"
        "**Severity**: Medium\n"
        f"**Location**: {location}\n"
        f"**Root Cause**: exact mechanism for {title}\n"
        f"**Description**: exact description for {title}\n"
        f"**Impact**: exact impact for {title}\n"
        "**Verdict**: NEEDS_VERIFICATION\n\n"
    )


def _apply_h1_test_repair(
    sp: Path,
    expected_source_ids: set[str],
) -> dict[str, object]:
    """Exercise the private compatibility repair and its exact replay."""
    receipt = R._apply_inventory_reemit_repair_for_tests(sp)
    rows = receipt["rows"]
    assert receipt["status"] == "APPLIED"
    assert {row["source_finding_id"] for row in rows} == expected_source_ids
    assert len(rows) == len(expected_source_ids)
    assert all(row["effect"] == "ADDITIVE_REEMIT" for row in rows)
    assert all(
        row["delivery_state"] == "INDEPENDENT_VERIFICATION_REQUIRED"
        for row in rows
    )
    materialized = {
        name: (sp / name).read_bytes()
        for name in R.MATERIALIZATION_FILES
    }
    assert D._validate_inventory_parity(sp) == []
    assert R._apply_inventory_reemit_repair_for_tests(sp) == receipt
    assert materialized == {
        name: (sp / name).read_bytes()
        for name in R.MATERIALIZATION_FILES
    }
    return receipt


def test_H1_truncated_inventory_detected():
    """Inventory truncation is repaired by exact additive re-emission."""
    upstream = "".join(
        _h1_finding(f"CS-{i}", f"example {i}", f"src/a.sol:L{i}")
        for i in range(1, 11)
    )
    inv = "# Findings Inventory\n\n" + "".join(
        _h1_finding(f"CS-{i}", f"example {i}", f"src/a.sol:L{i}")
        for i in range(1, 3)
    )
    sp = _mkscratch({
        "analysis_breadth1.md": upstream,
        "findings_inventory.md": inv,
    })
    before = {path.name: path.read_bytes() for path in sp.iterdir()}
    issues = D._validate_inventory_parity(sp)
    expected = {f"CS-{i}" for i in range(3, 11)}
    assert any("8/10 raw discovery identity(s)" in issue for issue in issues)
    assert before == {path.name: path.read_bytes() for path in sp.iterdir()}
    assert not (sp / R.INTENT_FILE).exists()
    assert not (sp / "inventory_reemit_receipt.json").exists()
    receipt = _apply_h1_test_repair(sp, expected)
    reemitted = {row["source_finding_id"] for row in receipt["rows"]}
    check("H1 truncated inventory repaired without source loss",
          reemitted == expected
          and all(
              f"analysis_breadth1.md:CS-{i}" in
              (sp / "findings_inventory.md").read_text(encoding="utf-8")
              for i in range(3, 11)
          ),
          f"issues={issues!r} reemitted={sorted(reemitted)!r}")


def test_H1_full_coverage_passes():
    upstream = "".join(
        _h1_finding(f"CS-{i}", f"title {i}", f"src/x.sol:L{i}")
        for i in range(1, 11)
    )
    inv = "# Inventory\n\n" + upstream
    sp = _mkscratch({
        "analysis_breadth1.md": upstream,
        "findings_inventory.md": inv,
    })
    before = {path.name: path.read_bytes() for path in sp.iterdir()}
    issues = D._validate_inventory_parity(sp)
    check("H1 full-coverage inventory passes",
          issues == []
          and before == {path.name: path.read_bytes() for path in sp.iterdir()}
          and not (sp / R.INTENT_FILE).exists()
          and not (sp / "inventory_reemit_receipt.json").exists(),
          repr(issues))


def test_H1_zero_upstream_signal_fails_loudly():
    """Upstream artifacts present but completely empty of findings.
    Inventory has body. Codex-flagged failure mode — must NOT pass."""
    upstream = "# Analysis\n\nNo findings.\n"
    inv = (
        "# Findings Inventory\n"
        "## Finding [CS-1]: placeholder\n"
        "**Location**: src/a.sol:L1\n"
    )
    sp = _mkscratch({
        "analysis_breadth1.md": upstream,
        "findings_inventory.md": inv,
    })
    issues = D._validate_inventory_parity(sp)
    check("H1 zero-upstream-signal fails loudly",
          any("zero finding signals" in s for s in issues),
          repr(issues))


def test_H1_no_upstream_no_inventory_body_passes():
    """Light mode: no artifacts, empty-ish inventory. Vacuous OK."""
    sp = _mkscratch({
        "findings_inventory.md": "# Findings Inventory\n\nNo findings.\n",
    })
    issues = D._validate_inventory_parity(sp)
    check("H1 vacuous-light-mode passes",
          issues == [],
          repr(issues))


def test_H1_missing_inventory_fails():
    sp = _mkscratch({})
    issues = D._validate_inventory_parity(sp)
    check("H1 missing inventory fails",
          any("missing" in s for s in issues),
          repr(issues))


# --------------------------------------------------------------------------
# AP-HF-1: inventory degrade-and-continue helper
# --------------------------------------------------------------------------

def _inventory_block(idx: int, *, fields: bool = True) -> str:
    lines = [f"### Finding [INV-{idx:03d}]: usable issue {idx}"]
    if fields:
        lines += [
            "**Severity**: Medium",
            f"**Location**: src/F{idx}.sol:L{idx}",
            f"**Source IDs**: AC-{idx}",
            "**Preferred Tag**: CODE-TRACE",
        ]
    lines.append(f"Description of issue {idx} with enough body to be substantive.")
    lines.append("")
    return "\n".join(lines)


def test_AP_HF_1_usable_findings_true_for_3plus_blocks():
    sp = _mkscratch({
        "findings_inventory.md": "# Finding Inventory\n\n## Findings\n\n"
        + "\n".join(_inventory_block(i) for i in range(1, 4)),
    })
    assert D._inventory_has_usable_findings(sp) is True


def test_AP_HF_1_usable_findings_false_for_zero_blocks():
    sp = _mkscratch({
        "findings_inventory.md": "# Finding Inventory\n\nNo parseable findings here.\n",
    })
    assert D._inventory_has_usable_findings(sp) is False


def test_AP_HF_1_usable_findings_false_for_near_empty():
    sp = _mkscratch({"findings_inventory.md": "# Finding Inventory\n"})
    assert D._inventory_has_usable_findings(sp) is False


def test_AP_HF_1_usable_findings_false_for_missing_file():
    sp = _mkscratch({})
    assert D._inventory_has_usable_findings(sp) is False


def test_AP_HF_1_structure_failure_with_usable_blocks_would_degrade():
    """Integration precondition: a genuine STRUCTURE field-completeness HARD
    failure on an inventory that STILL has >= 3 usable blocks. The new driver
    branch degrades-and-continues (does NOT funnel to wait_critical_halt_choice)
    precisely because both conditions hold."""
    # 5 titled blocks, 4 of which (>40%) are missing required fields.
    blocks = [_inventory_block(1)]  # complete
    blocks += [_inventory_block(i, fields=False) for i in range(2, 6)]  # 4 incomplete
    inv = "# Finding Inventory\n\n## Findings\n\n" + "\n".join(blocks)
    sp = _mkscratch({"findings_inventory.md": inv})
    structure_issues = D._validate_inventory_structure(sp)
    # The STRUCTURE gate (the one FC4 enforces for inventory) genuinely fails...
    assert any("missing one or more required fields" in s for s in structure_issues), structure_issues
    # ...yet usable blocks are present, so the degrade branch fires.
    assert D._inventory_has_usable_findings(sp) is True


def test_AP_HF_1_zero_blocks_still_halts():
    """Regression: an inventory with 0 usable blocks (missing-file class) does
    NOT satisfy the degrade precondition, so the critical-halt path is preserved."""
    sp = _mkscratch({})
    # FC4's content gate (structure) fails AND no usable blocks → halt preserved.
    assert D._validate_inventory_structure(sp), "structure gate must fail for missing inventory"
    assert D._inventory_has_usable_findings(sp) is False


def test_H1_block_count_retention_gate():
    """Collapsed headings cannot absorb distinct source blocks."""
    upstream = "".join(
        _h1_finding(f"CS-{i}", f"finding {i}", f"a.sol:L{i}")
        for i in range(1, 11)
    )
    # Only CS-1 and CS-10 are retained blocks. Body mentions grant no authority.
    inv = (
        "# Inventory\n\n"
        + _h1_finding("CS-1", "finding 1", "a.sol:L1")
        + "Consolidated prose mentions: "
        + " ".join(f"[CS-{i}]" for i in range(2, 10))
        + "\n\n"
        + _h1_finding("CS-10", "finding 10", "a.sol:L10")
    )
    sp = _mkscratch({
        "analysis_breadth1.md": upstream,
        "findings_inventory.md": inv,
    })
    before = {path.name: path.read_bytes() for path in sp.iterdir()}
    issues = D._validate_inventory_parity(sp)
    expected = {f"CS-{i}" for i in range(2, 10)}
    assert any("8/10 raw discovery identity(s)" in issue for issue in issues)
    assert before == {path.name: path.read_bytes() for path in sp.iterdir()}
    assert not (sp / "inventory_reemit_receipt.json").exists()
    receipt = _apply_h1_test_repair(sp, expected)
    reemitted = {row["source_finding_id"] for row in receipt["rows"]}
    check("H1 block-retention drop repaired additively",
          reemitted == expected,
          f"issues={issues!r} reemitted={sorted(reemitted)!r}")


def test_H1_unmanifested_shard_merge_cannot_dispose_raw_candidates_by_threshold():
    """Raw candidates need exact shard/merge lineage, even when called duplicates."""
    raw = "".join(
        _h1_finding(
            f"A{i:02d}-1",
            f"duplicate raw candidate {i}",
            f"src/raw{i}.rs:L1",
        )
        for i in range(1, 31)
    )
    chunk_a = "\n".join(
        f"### Finding [CA-{i}]: shard candidate\n"
        f"**Location**: src/a{i}.rs:L1\n"
        f"**Source IDs**: A{i:02d}-1"
        for i in range(1, 5)
    )
    chunk_b = "\n".join(
        f"### Finding [CB-{i}]: shard candidate\n"
        f"**Location**: src/b{i}.rs:L1\n"
        f"**Source IDs**: A{i+4:02d}-1"
        for i in range(1, 5)
    )
    inv = "\n".join(
        f"### Finding [INV-{i:02d}]: canonical merged root cause\n"
        f"**Location**: src/merged{i}.rs:L1\n"
        f"**Source IDs**: CA-{i}, CB-{i}"
        for i in range(1, 5)
    )
    sp = _mkscratch({
        "analysis_01.md": raw,
        "findings_inventory_chunk_a.md": chunk_a,
        "findings_inventory_chunk_b.md": chunk_b,
        "findings_inventory.md": inv,
    })
    before = {path.name: path.read_bytes() for path in sp.iterdir()}
    issues = D._validate_inventory_parity(sp)
    expected = {f"A{i:02d}-1" for i in range(1, 31)}
    assert any("30/30 raw discovery identity(s)" in issue for issue in issues)
    assert before == {path.name: path.read_bytes() for path in sp.iterdir()}
    assert not (sp / "inventory_reemit_receipt.json").exists()
    receipt = _apply_h1_test_repair(sp, expected)
    reemitted = {row["source_finding_id"] for row in receipt["rows"]}
    repaired_inventory = (sp / "findings_inventory.md").read_text(encoding="utf-8")
    check("H1 unmanifested shard merge re-emits every raw candidate",
          reemitted == expected
          and all(row["effect"] == "ADDITIVE_REEMIT" for row in receipt["rows"]),
          f"issues={issues!r} count={len(reemitted)}")
    assert all(
        f"analysis_01.md:A{i:02d}-1" in repaired_inventory
        and f"exact impact for duplicate raw candidate {i}" in repaired_inventory
        for i in range(1, 31)
    )


# --------------------------------------------------------------------------
# A1: _validate_recon_coverage + _module_key
# --------------------------------------------------------------------------

def test_A1_module_key_grouping():
    cases = [
        ("crates/types/src/lib.rs",      "crates/types"),
        ("crates/api-client/src/lib.rs", "crates/api-client"),
        ("eth/downloader/handler.go",    "eth/downloader"),
        ("x/staking/keeper/msg.go",      "x/staking"),
        ("cmd/geth/main.go",             "cmd/geth"),
        ("core/state.go",                "core"),
        ("consensus/engine.go",          "consensus"),
        ("Makefile",                     "_root"),
    ]
    for rel, expected in cases:
        got = D._module_key(rel)
        check(f"A1 _module_key {rel!r} -> {expected!r}",
              got == expected,
              f"got {got!r}")


def test_A1b_ai_model_summary_lists_unique_codex_models():
    phases = [
        D.Phase("recon", [], [], 60, model="sonnet"),
        D.Phase("depth", [], [], 60, model="opus"),
        D.Phase("report", [], [], 60, model="haiku"),
        D.Phase("dedup", [], [], 60, model="sonnet"),
    ]
    summary = D._format_ai_model_summary({"cli_backend": "codex"}, phases, "thorough")
    check("A1b AI model summary lists unique Codex models",
          summary == "Codex CLI / gpt-5.6-terra, gpt-5.6-sol, gpt-5.6-luna",
          repr(summary))


def test_A1c_ai_model_summary_light_mode_collapses_to_sonnet():
    phases = [
        D.Phase("depth", [], [], 60, model="opus"),
        D.Phase("report", [], [], 60, model="haiku"),
    ]
    summary = D._format_ai_model_summary({"cli_backend": "claude"}, phases, "light")
    check("A1c AI model summary light mode uses only pinned Sonnet 5",
          summary == "Claude Code / claude-sonnet-5",
          repr(summary))


def _mkrepo(files: list[str]) -> Path:
    root = Path(tempfile.mkdtemp(prefix="plamen_repo_"))
    for rel in files:
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("// stub\n", encoding="utf-8")
    return root


def test_A1_monorepo_granularity():
    """Rust mono-repo style. crates/types and crates/api-client are
    distinct coverage buckets; citing crates/p2p/src/lib.rs must NOT
    satisfy crates/types."""
    files = []
    for crate in ("types", "api-client", "p2p", "consensus"):
        for i in range(12):
            files.append(f"crates/{crate}/src/mod{i}.rs")
    root = _mkrepo(files)
    sp = _mkscratch({
        "attack_surface.md":
        "Layer: consensus\n"
        "- Concern: X\n"
        "  - Code path: `crates/p2p/src/mod0.rs:42`\n",
    })
    issues = D._validate_recon_coverage(sp, str(root), "l1")
    # types, api-client, consensus all uncited; p2p covered.
    uncovered_line = next((s for s in issues if "missed" in s), "")
    check("A1 monorepo: uncited crates flagged",
          "crates/types" in uncovered_line
          and "crates/api-client" in uncovered_line
          and "crates/consensus" in uncovered_line
          and "crates/p2p" not in uncovered_line,
          repr(issues))


def test_A1_basename_collision_does_not_false_cover():
    """Two crates both have src/lib.rs. Citing one must NOT cover the
    other under the new full-path rule."""
    files = []
    for crate in ("types", "api-client"):
        for i in range(12):
            files.append(f"crates/{crate}/src/mod{i}.rs")
        files.append(f"crates/{crate}/src/lib.rs")
    root = _mkrepo(files)
    sp = _mkscratch({
        "attack_surface.md":
        "- Code path: `crates/types/src/lib.rs:1`\n",
    })
    issues = D._validate_recon_coverage(sp, str(root), "l1")
    uncovered_line = next((s for s in issues if "missed" in s), "")
    check("A1 basename collision does not false-cover",
          "crates/api-client" in uncovered_line
          and "crates/types" not in uncovered_line,
          repr(issues))


def test_A1_acknowledged_exempts_module():
    files = [f"crates/legacy/src/m{i}.rs" for i in range(12)] + \
            [f"crates/core/src/m{i}.rs" for i in range(12)]
    root = _mkrepo(files)
    leftover = (
        "| File | LOC | Reason | Acknowledged |\n"
        "|------|-----|--------|--------------|\n"
        "| crates/legacy/src/m0.rs | 10 | deprecated | "
        "ACKNOWLEDGED: SUPERSEDED |\n"
    )
    surface = "- `crates/core/src/m0.rs:1`\n"
    sp = _mkscratch({
        "attack_surface.md": surface,
        "scope_leftover.md": leftover,
    })
    issues = D._validate_recon_coverage(sp, str(root), "l1")
    uncovered_line = next((s for s in issues if "missed" in s), "")
    # legacy should NOT appear in uncovered because one of its files
    # is ACKNOWLEDGED; core IS cited.
    check("A1 ACKNOWLEDGED exempts whole module",
          "crates/legacy" not in uncovered_line
          and "crates/core" not in uncovered_line,
          repr(issues))


def test_A1_small_module_exempt():
    # Tiny module (<10 files) is uncited; a separate large module IS cited
    # so the orthogonal zero-citation guard stays silent. Intent: confirm
    # the <10-file exemption, not the overall-zero-citation safety net.
    files = [f"crates/tiny/src/m{i}.rs" for i in range(3)]
    files += [f"crates/big/src/m{i}.rs" for i in range(12)]
    root = _mkrepo(files)
    sp = _mkscratch({
        "attack_surface.md": "- `crates/big/src/m0.rs:1`\n",
    })
    issues = D._validate_recon_coverage(sp, str(root), "l1")
    check("A1 small module (<10 files) exempt",
          issues == [],
          repr(issues))


def test_A1_zero_citations_overall_fails():
    files = [f"crates/types/src/m{i}.rs" for i in range(12)]
    root = _mkrepo(files)
    sp = _mkscratch({"attack_surface.md": "no file refs here at all\n"})
    issues = D._validate_recon_coverage(sp, str(root), "l1")
    check("A1 zero citations emits its own issue",
          any("zero file-path citations" in s for s in issues),
          repr(issues))


def test_A2_scope_leftover_test_support_whitelist():
    body = (
        "| File | LOC | Reason | Acknowledged |\n"
        "|------|-----|--------|--------------|\n"
        "| crates/testing-utils/src/lib.rs | 1200 | test support crate | |\n"
        "| crates/test-helpers/src/lib.rs | 900 | test support crate | |\n"
    )
    sp = _mkscratch({"scope_leftover.md": body})
    issues = D._validate_scope_leftover(sp)
    check("A2 scope_leftover test-support crates auto-ack",
          issues == [],
          repr(issues))


# --------------------------------------------------------------------------
# H2: _match_label_status + _validate_depth_exit
# --------------------------------------------------------------------------

def test_H2_match_label_bullet_and_table():
    bullet = "- design-stress: SKIPPED NO_APPLICABLE_FLAG (no BLS surface)"
    r = D._match_label_status(bullet, "design-stress")
    check("H2 bullet SKIPPED matched",
          r is not None and r[0] == "SKIPPED"
          and "NO_APPLICABLE_FLAG" in r[1],
          repr(r))

    table = "| design-stress | SPAWNED | agent-id=depth-7 |"
    r = D._match_label_status(table, "design-stress")
    check("H2 table SPAWNED matched",
          r is not None and r[0] == "SPAWNED",
          repr(r))

    empty = "no label here"
    r = D._match_label_status(empty, "design-stress")
    check("H2 missing label returns None",
          r is None,
          repr(r))


def test_H2_depth_exit_bullet_form():
    body = (
        "# Depth Exit\n"
        "criterion: 2\n"
        "rationale: confidence stable above threshold\n"
        "explored_paths:\n"
        "  - cache-lifecycle: COVERED\n"
        "  - sig-id-binding: COVERED\n"
        "  - fp-determinism: COVERED\n"
    )
    sp = _mkscratch({"depth_exit.md": body})
    issues = D._validate_depth_exit(sp)
    check("H2 depth_exit bullet form passes",
          issues == [],
          repr(issues))


def test_H2_depth_exit_table_form():
    body = (
        "# Depth Exit\n\n"
        "| field | value |\n"
        "|-------|-------|\n"
        "| criterion | 2 |\n"
        "| rationale | confidence stable above threshold |\n\n"
        "## explored_paths\n"
        "| path | status |\n"
        "|------|--------|\n"
        "| cache-lifecycle | COVERED |\n"
        "| sig-id-binding | COVERED |\n"
        "| fp-determinism | COVERED |\n"
    )
    sp = _mkscratch({"depth_exit.md": body})
    issues = D._validate_depth_exit(sp)
    check("H2 depth_exit table form passes",
          issues == [],
          repr(issues))


def test_H3_ceremonial_step_trace_becomes_unknown_not_posthoc_proof():
    sp = _mkscratch({
        "depth_consensus_invariant_findings.md": (
            "### Finding [DCI-7]: example\n"
            "**Location**: crates/chain/src/validation.rs:L42\n"
            "[BOUNDARY:header] checked at crates/chain/src/validation.rs:L42\n"
        ),
        "step_execution_trace_consensus_invariant.md": (
            "| Skill | Step | Executed | Evidence | Result |\n"
            "|---|---|---|---|---|\n"
            "| consensus | boundary check | yes | DCI-7 | finding ref only |\n"
        ),
    })
    issues = D._check_step_execution_traces(sp, "thorough")
    honesty_trace = (
        sp / "step_execution_trace_consensus_invariant.md"
    ).read_text(encoding="utf-8", errors="replace")
    check("H3 ceremonial trace routes an UNKNOWN gap without self-certifying",
          issues == []
          and "| unknown |" in honesty_trace.lower()
          and "| yes |" not in honesty_trace.lower()
          and "crates/chain/src/validation.rs:L42" not in honesty_trace,
          f"issues={issues!r}; trace={honesty_trace!r}")


def test_H4_notread_basename_collision_does_not_false_cover():
    sp = _mkscratch({
        "scope_leftover.md": (
            "| File | LOC | Reason | Acknowledged |\n"
            "|------|-----|--------|--------------|\n"
            "| crates/database/src/metadata.rs | 300 | deferred | |\n"
            "| crates/chain/src/metadata.rs | 300 | deferred | |\n"
        ),
        "depth_state_trace_findings.md": (
            "### Finding [DST-1]: example\n"
            "**Location**: crates/database/src/metadata.rs:L10\n"
        ),
    })
    issues = D._check_notread_priority_coverage(sp, "thorough")
    gaps = (sp / "notread_priority_gaps.md").read_text(
        encoding="utf-8", errors="replace"
    )
    check("H4 NOTREAD basename collision does not false-cover sibling file",
          issues and "crates/chain/src/metadata.rs" in gaps
          and "crates/database/src/metadata.rs" not in gaps,
          f"issues={issues!r}; gaps={gaps!r}")


def test_R1_new_l1_ids_are_harvested_for_promotion():
    text = " ".join([
        "INV-03", "DCOV1-01", "DST-DSIGN-3", "PERT-7",
        "PAIR-9", "PANIC-EXPLOIT-2", "DCI-14",
    ])
    found = set(D._INTERNAL_FINDING_ID_RE.findall(text))
    expected = {
        "INV-03", "DCOV1-01", "DST-DSIGN-3", "PERT-7",
        "PAIR-9", "PANIC-EXPLOIT-2", "DCI-14",
    }
    check("R1 new L1 IDs harvested by canonical regex",
          expected <= found,
          repr(found))


def test_R1b_sc_feeder_ids_are_harvested_for_promotion():
    text = " ".join([
        "SLITHER-1", "FUZZ-2", "MEDUSA-3", "RSW-4",
        "CS-5", "TF-6", "OR-7", "FL-8", "PDA-9", "ZS-10",
    ])
    found = set(D._INTERNAL_FINDING_ID_RE.findall(text))
    expected = {
        "SLITHER-1", "FUZZ-2", "MEDUSA-3", "RSW-4",
        "CS-5", "TF-6", "OR-7", "FL-8", "PDA-9", "ZS-10",
    }
    check("R1b SC feeder IDs harvested by canonical regex",
          expected <= found,
          repr(found))


def test_R2_unresolved_fallback_mapping_flags_missing_body_tag():
    sp = _mkscratch({
        "verification_queue.md": (
            "| Queue # | Finding ID | Severity | Title | Bug Class | Preferred Tag | Location | Primary Artifact |\n"
            "|---------|------------|----------|-------|-----------|---------------|----------|------------------|\n"
            "| 1 | INV-03 | High | replay | replay | CODE-TRACE | src/lib.rs:L1 | verify_INV-03.md |\n"
        ),
        "skeptic_judge_decisions.md": (
            "## INV-03\n"
            "**Verdict**: UNRESOLVED\n"
            "Verifier and skeptic disagree.\n"
        ),
        "report_index.md": "# Report Index\n\nNarrative only; no parseable table.\n",
        "AUDIT_REPORT.md": "## High Findings\n\n### [H-01] replay\n\nbody\n",
    })
    issues = D._check_unresolved_authenticity(sp, str(sp))
    check("R2 UNRESOLVED fallback mapping requires body flag",
          any("unresolved untagged" in s for s in issues),
          repr(issues))


def test_R3_confirmed_verify_requires_body_or_explicit_non_body():
    sp = _mkscratch({
        "verification_queue.md": (
            "| Queue # | Finding ID | Severity | Title | Bug Class | Preferred Tag | Location | Primary Artifact |\n"
            "|---------|------------|----------|-------|-----------|---------------|----------|------------------|\n"
            "| 1 | INV-03 | High | replay | replay | CODE-TRACE | src/lib.rs:L1 | verify_INV-03.md |\n"
        ),
        "verify_INV-03.md": (
            "# Verification INV-03\n"
            "**Verdict**: CONFIRMED\n"
            "Finding ID: INV-03\n"
        ),
        "report_index.md": (
            "## Master Finding Index\n\n"
            "| Report ID | Title | Severity | Internal ID |\n"
            "|-----------|-------|----------|-------------|\n"
            "| H-01 | replay | High | INV-03 |\n"
        ),
        "AUDIT_REPORT.md": "## High Findings\n\n_No body section was written._\n",
    })
    issues = D._check_promotion_symmetry(sp, str(sp))
    check("R3 confirmed verify requires body section or explicit non-body disposition",
          any("promotion dropout" in s for s in issues),
          repr(issues))


def test_R4_report_repair_restores_missing_assigned_section_and_unresolved():
    sp = _mkscratch({
        "verification_queue.md": (
            "| Queue # | Finding ID | Severity | Title | Bug Class | Preferred Tag | Location | Primary Artifact |\n"
            "|---------|------------|----------|-------|-----------|---------------|----------|------------------|\n"
            "| 1 | INV-03 | High | replay remains disputed | replay | CODE-TRACE | src/lib.rs:L1 | verify_INV-03.md |\n"
            "| 2 | DCOV1-01 | Medium | dropped coverage finding | bounds | TRACE | src/other.rs:L2 | verify_DCOV1-01.md |\n"
        ),
        "verify_INV-03.md": (
            "# Verification INV-03\n"
            "**Verdict**: CONFIRMED\n"
            "**Preferred Tag**: CODE-TRACE\n"
            "**Evidence Tag**: CODE-TRACE\n"
            "**Location**: src/lib.rs:L1\n"
            "## Impact\n"
            "Replay can invalidate accounting.\n"
            "## Execution Output\n"
            "Code trace confirms the replay path.\n"
            "## Suggested Fix\n"
            "Bind the transaction to a nonce.\n"
        ),
        "verify_DCOV1-01.md": (
            "# Verification DCOV1-01\n"
            "**Verdict**: CONFIRMED\n"
            "**Preferred Tag**: TRACE\n"
            "**Evidence Tag**: TRACE\n"
            "**Location**: src/other.rs:L2\n"
            "## Analysis\n"
            "The bounds check is missing before the array access.\n"
            "## Impact\n"
            "Malformed input can panic the validator.\n"
            "## Execution Output\n"
            "Code trace reaches the unchecked access.\n"
            "## Suggested Fix\n"
            "Reject inputs shorter than the required length.\n"
        ),
        "skeptic_judge_decisions.md": (
            "## INV-03\n"
            "**Verdict**: UNRESOLVED\n"
        ),
        "report_index.md": (
            "## Master Finding Index\n\n"
            "| Report ID | Title | Severity | Internal ID |\n"
            "|-----------|-------|----------|-------------|\n"
            "| H-01 | replay remains disputed | High | INV-03 |\n"
            "| M-01 | dropped coverage finding | Medium | DCOV1-01 |\n"
        ),
    })
    body = "## High Findings\n\n### [H-01] replay remains disputed\n\nbody\n\n## Priority Remediation Order\n"
    repaired = D._repair_report_body_from_assignments(body, sp)
    check("R4 existing unresolved assigned section is tagged",
          "### [H-01] replay remains disputed [UNRESOLVED - needs human review]" in repaired,
          repaired)
    check("R4 missing assigned section restored from verifier metadata",
          "### [M-01] dropped coverage finding" in repaired
          and "src/other.rs:L2" in repaired,
          repaired)


def test_R5_python_assembler_refuses_missing_assigned_sections():
    sp = _mkscratch({
        "verification_queue.md": (
            "| Queue # | Finding ID | Severity | Title | Bug Class | Preferred Tag | Location | Primary Artifact |\n"
            "|---------|------------|----------|-------|-----------|---------------|----------|------------------|\n"
            "| 1 | INV-03 | High | replay remains disputed | replay | CODE-TRACE | src/lib.rs:L1 | verify_INV-03.md |\n"
            "| 2 | DCOV1-01 | Medium | dropped coverage finding | bounds | TRACE | src/other.rs:L2 | verify_DCOV1-01.md |\n"
        ),
        "verify_INV-03.md": (
            "# Verification INV-03\n"
            "**Verdict**: CONFIRMED\n"
            "**Preferred Tag**: CODE-TRACE\n"
            "**Evidence Tag**: CODE-TRACE\n"
            "**Location**: src/lib.rs:L1\n"
        ),
        "verify_DCOV1-01.md": (
            "# Verification DCOV1-01\n"
            "**Verdict**: CONFIRMED\n"
            "**Preferred Tag**: TRACE\n"
            "**Evidence Tag**: TRACE\n"
            "**Location**: src/other.rs:L2\n"
        ),
        "skeptic_judge_decisions.md": (
            "## INV-03\n"
            "**Verdict**: UNRESOLVED\n"
        ),
        "report_index.md": (
            "## Summary\n\n"
            "| Severity | Count |\n"
            "|----------|-------|\n"
            "| High | 1 |\n"
            "| Medium | 0 |\n\n"
            "## Master Finding Index\n\n"
            "| Report ID | Title | Severity | Internal ID |\n"
            "|-----------|-------|----------|-------------|\n"
            "| H-01 | replay remains disputed | High | INV-03 |\n"
            "| M-01 | dropped coverage finding | Medium | DCOV1-01 |\n"
        ),
        "report_critical_high.md": (
            "## High Findings\n\n"
            "### [H-01] replay remains disputed\n\n"
            "**Severity**: High\n\nBody.\n"
            "**Impact**:\nReplay can invalidate accounting.\n\n"
            "**PoC Result**:\nCode trace confirms the replay path.\n"
        ),
        "report_medium.md": "",
        "file_coverage_ledger.md": (
            "| File | Status |\n"
            "|------|--------|\n"
            "| crates/a/src/lib.rs | COVERED |\n"
        ),
    })
    project = Path(tempfile.mkdtemp(prefix="plamen_proj_"))
    ok = D._assemble_report_python(sp, str(project))
    issues = D._run_report_quality_gate(sp, str(project)) if ok else ["assemble failed"]
    report = (project / "AUDIT_REPORT.md").read_text(encoding="utf-8")
    check("R5 python assembler rejects missing assigned sections",
          ok
          and any("missing" in issue.lower() and "M-01" in issue for issue in issues)
          and "### [M-01] dropped coverage finding" not in report
          and "### Components Audited" in report,
          f"ok={ok}; issues={issues!r}; report={report!r}")


def test_R6_complete_report_index_does_not_merge_stale_queue_rows():
    sp = _mkscratch({
        "report_index.md": (
            "# Report Index\n\n"
            "## Summary Counts\n\n"
            "| Severity | Count |\n"
            "|----------|-------|\n"
            "| Critical | 1 |\n"
            "| High | 2 |\n"
            "| Medium | 1 |\n"
            "| Low | 0 |\n"
            "| Informational | 0 |\n\n"
            "## Tier Assignments\n\n"
            "### Critical+High Tier\n\n"
            "| Report ID | Internal Ref | Verify File |\n"
            "|-----------|--------------|-------------|\n"
            "| C-01 | INV-01 | verify_INV-01.md |\n"
            "| H-01 | INV-02 | verify_INV-02.md |\n"
            "| H-02 | INV-03 + INV-04 | verify_INV-03.md |\n\n"
            "### Medium Tier\n\n"
            "| Report ID | Internal Ref | Verify File |\n"
            "|-----------|--------------|-------------|\n"
            "| M-01 | INV-05 | verify_INV-05.md |\n"
        ),
        "verification_queue.md": (
            "| Queue # | Finding ID | Severity | Title |\n"
            "|---------|------------|----------|-------|\n"
            "| 1 | INV-01 | Critical | kept |\n"
            "| 2 | INV-02 | High | kept |\n"
            "| 3 | INV-03 | High | kept |\n"
            "| 4 | INV-99 | High | refuted stale queue item |\n"
            "| 5 | INV-05 | Medium | kept |\n"
        ),
        "report_critical_high.md": (
            "### [C-01] kept\n\nbody\n\n"
            "### [H-01] kept\n\nbody\n\n"
            "### [H-02] kept\n\nbody\n"
        ),
    })
    rows, source = D.get_tier_assignments(sp)
    counts = D.parse_report_index_counts(sp)
    issues = D._validate_report_tier_completeness(sp, "report_critical_high")
    check("R6 complete index is authoritative over stale verify queue",
          source == "index"
          and len(rows) == 4
          and counts == {"critical_high": 3, "medium": 1, "low_info": 0}
          and issues == [],
          f"source={source}; rows={rows!r}; counts={counts!r}; issues={issues!r}")


def test_R7_verify_schema_alias_is_accepted_without_mutating_owned_bytes():
    sp = _mkscratch({
        "verification_queue.md": (
            "| Queue # | Finding ID | Severity | Title |\n"
            "|---------|------------|----------|-------|\n"
            "| 1 | INV-49 | Medium | schema drift |\n"
        ),
        "verify_INV-49.md": (
            "# Verification INV-49\n\n"
            "**Verdict**: CONFIRMED\n"
            "**Evidence Tag**: CODE-TRACE\n"
            "**Location**: crates/a/src/lib.rs:L10\n"
        ),
    })
    before = (sp / "verify_INV-49.md").read_bytes()
    issues = D._validate_verify_completion(sp, "verify_medium_a")
    after = (sp / "verify_INV-49.md").read_bytes()
    text = (sp / "verify_INV-49.md").read_text(encoding="utf-8")
    check("R7 Evidence Tag alias is accepted and verifier bytes stay immutable",
          issues == [] and before == after and "**Evidence Tag**: CODE-TRACE" in text,
          f"issues={issues!r}; text={text!r}")


def test_R8_report_index_excludes_refuted_rows_from_assignments():
    sp = _mkscratch({
        "report_index.md": (
            "## Summary Counts\n\n"
            "| Severity | Count |\n"
            "|----------|-------|\n"
            "| High | 1 |\n\n"
            "## Master Finding Index\n\n"
            "| Report ID | Internal Ref | Verify File |\n"
            "|-----------|--------------|-------------|\n"
            "| H-01 | INV-01 | verify_INV-01.md |\n\n"
            "## Excluded Findings\n\n"
            "| Report ID | Internal Ref | Reason |\n"
            "|-----------|--------------|--------|\n"
            "| H-02 | INV-02 | FALSE_POSITIVE |\n"
        ),
        "verification_queue.md": (
            "| Queue # | Finding ID | Severity | Title |\n"
            "|---------|------------|----------|-------|\n"
            "| 1 | INV-01 | High | active |\n"
            "| 2 | INV-02 | High | excluded |\n"
        ),
    })
    rows, source = D.get_tier_assignments(sp)
    check("R8 excluded report_index rows are not active assignments",
          source == "index"
          and [r["finding_id"] for r in rows] == ["INV-01"]
          and D.parse_report_index_counts(sp)["critical_high"] == 1,
          f"source={source}; rows={rows!r}; counts={D.parse_report_index_counts(sp)!r}")


def test_R9_crossbatch_fail_signals_block_phase():
    sp = _mkscratch({
        "cross_batch_consistency.md": (
            "# Crossbatch\n\n"
            "Overall: FAIL\n\n"
            "schema violations: 49 missing severity field\n"
        )
    })
    issues = D._validate_crossbatch_quality(sp)
    check("R9 crossbatch schema failure is promoted to gate issue",
          any("crossbatch" in s for s in issues),
          repr(issues))


def test_R10_depth_findings_promote_into_inventory_before_verify_queue():
    sp = _mkscratch({
        "findings_inventory.md": (
            "# Inventory\n\n"
            "### Finding [INV-01]: existing\n"
            "**Source IDs**: [CC-1]\n"
            "**Severity**: High\n"
            "**Location**: crates/a/src/lib.rs:L1\n"
            "**Preferred Tag**: CODE-TRACE\n"
        ),
        "depth_consensus_invariant_findings.md": (
            "### Finding [DCI-3]: VDF seed is deterministic\n\n"
            "**Severity**: Critical\n"
            "**Location**: crates/consensus/src/vdf.rs:L42\n"
            "**Evidence Tag**: CODE-TRACE\n"
            "**Description**: Deterministic seed permits precomputation.\n"
        ),
        "confidence_scores.md": "DCI-3 composite confidence 0.85\n",
    })
    promoted = D._promote_depth_findings_to_inventory(sp)
    text = (sp / "findings_inventory.md").read_text(encoding="utf-8")
    issues = D._validate_depth_promotion_receipt(sp)
    check("R10 high-confidence depth finding is appended to inventory",
          promoted == ["DCI-3"]
          and "### Finding [INV-002]: VDF seed is deterministic" in text
          and "**Source IDs**: [DCI-3]" in text
          and issues == [],
          f"promoted={promoted!r}; issues={issues!r}; text={text!r}")


def test_R10b_confirmed_depth_tail_ids_promote_without_confidence_allowlist():
    sp = _mkscratch({
        "findings_inventory.md": "# Finding Inventory\n\n## Findings\n\n",
        "depth_network_surface_findings.md": (
            "### [DNS-10] Peer Scoring Asymmetry\n"
            "**Verdict**: CONFIRMED\n"
            "**Severity**: Medium\n"
            "**Location**: crates/p2p/src/block_pool_service.rs:10\n"
            "**Description**: Invalid peer responses are not penalized.\n\n"
            "### [DA3-NEW-DNS-1] Unbounded peer handshakes\n"
            "**Verdict**: CONFIRMED\n"
            "**Severity**: High\n"
            "**Location**: crates/p2p/src/peer_list.rs:20\n"
            "**Description**: Peer lists can spawn unbounded handshake tasks.\n"
        ),
    })
    promoted = D._promote_depth_findings_to_inventory(sp)
    text = (sp / "findings_inventory.md").read_text(encoding="utf-8")
    issues = D._validate_depth_promotion_receipt(sp)
    check("R10b confirmed DNS/DA3 depth tail findings promote",
          promoted == ["DNS-10", "DA3-NEW-DNS-1"]
          and "DNS-10" in text
          and "DA3-NEW-DNS-1" in text
          and issues == [],
          f"promoted={promoted!r}; issues={issues!r}; text={text!r}")


def test_R11_sc_feeder_findings_promote_into_inventory_before_verify_queue():
    sp = _mkscratch({
        "findings_inventory.md": (
            "# Inventory\n\n"
            "### Finding [INV-01]: existing\n"
            "**Source IDs**: [H-1]\n"
            "**Severity**: High\n"
            "**Location**: contracts/Vault.sol:L1\n"
            "**Preferred Tag**: CODE-TRACE\n"
        ),
        "niche_callback_findings.md": (
            "### Finding [CS-1]: Callback can reenter accounting\n\n"
            "**Severity**: High\n"
            "**Location**: contracts/Vault.sol:L42\n"
            "**Evidence Tag**: CODE-TRACE\n"
            "**Description**: Callback observes inconsistent accounting.\n"
        ),
        "analysis_rescan_01.md": (
            "### Finding [RSW-1]: Rescan found stale share price\n\n"
            "**Severity**: Medium\n"
            "**Location**: contracts/Strategy.sol:L88\n"
            "**Evidence Tag**: CODE-TRACE\n"
            "**Description**: Iteration-2 rescan found a stale price path.\n"
        ),
        "medusa_fuzz_findings.md": (
            "### Finding [MEDUSA-1]: Fuzzer violates solvency invariant\n\n"
            "**Severity**: Critical\n"
            "**Location**: test/fuzz/Solvency.t.sol:L12\n"
            "**Evidence Tag**: FUZZ-PASS\n"
            "**Description**: Medusa generated a solvency counterexample.\n"
        ),
        "scanner_validation_findings.md": (
            "### Finding [SLITHER-1]: Unprotected setter reaches live config\n\n"
            "**Severity**: Medium\n"
            "**Location**: contracts/Admin.sol:L27\n"
            "**Evidence Tag**: CODE-TRACE\n"
            "**Description**: Static scanner identified a live unprotected setter.\n"
        ),
    })
    promoted = set(D._promote_depth_findings_to_inventory(sp))
    text = (sp / "findings_inventory.md").read_text(encoding="utf-8")
    issues = D._validate_depth_promotion_receipt(sp)
    expected = {"CS-1", "RSW-1", "MEDUSA-1", "SLITHER-1"}
    check("R11 SC feeder findings are appended to inventory",
          expected <= promoted
          and all(f"**Source IDs**: [{fid}]" in text for fid in expected)
          and issues == [],
          f"promoted={promoted!r}; issues={issues!r}; text={text!r}")


def test_R12_sc_fuzzer_refuted_proposal_stays_visible_pending_closure():
    sp = _mkscratch({
        "verification_queue.md": (
            "| Queue # | Finding ID | Severity | Title | Bug Class | Preferred Tag | Location | Primary Artifact |\n"
            "|---------|------------|----------|-------|-----------|---------------|----------|------------------|\n"
            "| 1 | FUZZ-1 | High | invariant violation | fuzz | FUZZ-PASS | contracts/Vault.sol:L10 | verify_FUZZ-1.md |\n"
        ),
        "verify_FUZZ-1.md": (
            "# Verification FUZZ-1\n"
            "**Severity**: High\n"
            "**Preferred Tag**: FUZZ-PASS\n"
            "**Evidence Tag**: FUZZ-PASS\n"
            "**Verdict**: REFUTED\n"
            "**Location**: contracts/Vault.sol:L10\n"
            "The fuzzer harness was invalid.\n"
        ),
    })
    count = D._write_mechanical_report_index(sp)
    records = json.loads((sp / "report_records.json").read_text(encoding="utf-8"))
    D._write_mechanical_report_tier(sp, "report_critical_high")
    body_path = sp / "report_critical_high.md"
    body = body_path.read_text(encoding="utf-8") if body_path.exists() else ""
    check("R12 SC FUZZ refutation is non-authoritative and remains visible",
          count == 1
          and len(records["active"]) == 1
          and len(records["excluded"]) == 0
          and len(records["negative_disposition_proposals"]) == 1
          and "invariant violation" in body
          and "UNRESOLVED - needs human review" in body,
          f"count={count}; records={records!r}; body={body!r}")


def test_R13_sc_slither_confirmed_promotes_through_report_index():
    sp = _mkscratch({
        "verification_queue.md": (
            "| Queue # | Finding ID | Severity | Title | Bug Class | Preferred Tag | Location | Primary Artifact |\n"
            "|---------|------------|----------|-------|-----------|---------------|----------|------------------|\n"
            "| 1 | SLITHER-1 | Medium | unprotected setter | access-control | CODE-TRACE | contracts/Admin.sol:L27 | verify_SLITHER-1.md |\n"
        ),
        "verify_SLITHER-1.md": (
            "# Verification SLITHER-1\n"
            "**Severity**: Medium\n"
            "**Preferred Tag**: CODE-TRACE\n"
            "**Evidence Tag**: CODE-TRACE\n"
            "**Verdict**: CONFIRMED\n"
            "**Location**: contracts/Admin.sol:L27\n"
            "**Impact**: live config can be changed by anyone.\n"
        ),
    })
    count = D._write_mechanical_report_index(sp)
    records = json.loads((sp / "report_records.json").read_text(encoding="utf-8"))
    check("R13 SC SLITHER confirmed finding reaches active report records",
          count == 1
          and records["active"][0]["finding_id"] == "SLITHER-1"
          and records["active"][0]["severity"] == "Medium",
          f"count={count}; records={records!r}")


def test_R14_consolidation_map_acknowledges_confirmed_source_ids():
    sp = _mkscratch({
        "report_records.json": json.dumps({
            "active": [{
                "report_id": "H-01",
                "finding_id": "INV-100",
                "severity": "High",
                "title": "Consolidated issue",
                "location": "src/lib.rs:L1",
                "evidence": "CODE-TRACE",
                "verdict": "CONFIRMED",
                "unresolved": "no",
            }],
            "excluded": [],
        }),
        "verify_INV-100.md": (
            "# Verification INV-100\n"
            "**Verdict**: CONFIRMED\n"
            "**Severity**: High\n"
            "This verifier consolidates DCI-2 and DA-DEC-9 under INV-100.\n"
        ),
    })
    project = sp / "project"
    project.mkdir()
    report = project / "AUDIT_REPORT.md"
    report.write_text(
        "# Audit Report\n\n### [H-01] Consolidated issue\n\nBody.\n",
        encoding="utf-8",
    )
    mapped = D._ensure_report_consolidation_map(sp, str(project))
    text = report.read_text(encoding="utf-8")
    internal = (sp / "report_consolidation_internal.md").read_text(encoding="utf-8")
    issues = D._check_promotion_symmetry(sp, str(project))
    check("R14 consolidation map acknowledges confirmed source IDs",
          mapped == 2
          and "DCI-2" not in text
          and "DA-DEC-9" not in text
          and "DCI-2" in internal
          and "DA-DEC-9" in internal
          and issues == [],
          f"mapped={mapped}; issues={issues!r}; text={text!r}; internal={internal!r}")


def test_R15_client_title_sanitizer_removes_internal_ids():
    title = "Consensus Split on Epoch Boundary (Depth Validation of INV-002)"
    clean = D._sanitize_client_title(title)
    check("R15 client title sanitizer removes internal IDs",
          "INV-002" not in clean and "Depth Validation" not in clean,
          clean)


def test_R16_report_renderer_uses_verifier_content():
    sp = _mkscratch({
        "verification_queue.md": (
            "| Finding ID | Severity | Title | Location | Preferred Tag |\n"
            "|------------|----------|-------|----------|---------------|\n"
            "| INV-001 | High | Rich bug | src/lib.rs:1 | CODE-TRACE |\n"
        ),
        "verify_INV-001.md": (
            "# Verify INV-001\n"
            "**Verdict**: CONFIRMED\n"
            "**Severity**: High\n"
            "**Evidence Tag**: CODE-TRACE\n"
            "## Analysis\n"
            "The function accepts attacker-controlled input and writes it before validation.\n"
            "## Impact\n"
            "Attackers can corrupt consensus state.\n"
            "## Execution Output\n"
            "Code trace reaches the unsafe write.\n"
            "## Suggested Fix\n"
            "Validate before writing state.\n"
        ),
    })
    section = D._synth_report_section_from_verify(
        sp, "H-01", "INV-001",
        {"title": "Rich bug", "severity": "High", "location": "src/lib.rs:1"},
        False,
    )
    check("R16 report renderer uses verifier content",
          "Attackers can corrupt consensus state" in section
          and "**PoC Result**" in section
          and "Code trace reaches the unsafe write" in section
          and "tier writer omitted" not in section,
          section)


def test_R17_report_quality_rejects_stub_body():
    sp = _mkscratch({
        "report_records.json": json.dumps({"active": [], "excluded": []}),
    })
    project = sp / "project"
    project.mkdir()
    (project / "AUDIT_REPORT.md").write_text(
        "# Report\n\n## Summary\n\n| Severity | Count |\n|--|--|\n| High | 1 |\n| **Total** | **1** |\n\n"
        "### Components Audited\n\n| Component | Files |\n|--|--|\n| src | 1 |\n\n"
        "## High Findings\n\n"
        "### [H-01] Stub\n\n"
        "**Severity**: High\n\n"
        "**Description**: This finding was present in the verification queue and had a verifier artifact, but was missing from the tier-written report body. The Python assembler restored the assigned section from deterministic verification metadata.\n\n"
        "**Recommendation**: Review the cited location and apply the mitigation described in the verifier and upstream finding artifact.\n",
        encoding="utf-8",
    )
    issues = D._run_report_quality_gate(sp, str(project))
    check("R17 report quality rejects stub body",
          any("boilerplate" in s or "rich finding" in s for s in issues),
          issues)


def test_R18_crossbatch_requires_full_verify_scope():
    sp = _mkscratch({
        "verify_INV-001.md": "**Verdict**: CONFIRMED\n",
        "verify_INV-002.md": "**Verdict**: CONFIRMED\n",
        "cross_batch_consistency.md": "Verifiers Checked: 1\nINV-001\nOverall: PASS\n",
    })
    issues = D._validate_crossbatch_full_coverage(sp)
    check("R18 crossbatch requires full verify scope",
          any("1/2" in s for s in issues),
          issues)


def test_R19_skeptic_requires_all_critical_high():
    sp = _mkscratch({
        "verification_queue.md": (
            "| Finding ID | Severity | Title | Location | Preferred Tag |\n"
            "|------------|----------|-------|----------|---------------|\n"
            "| INV-001 | Critical | A | src/a.rs:1 | CODE-TRACE |\n"
            "| INV-002 | High | B | src/b.rs:1 | CODE-TRACE |\n"
            "| INV-003 | Medium | C | src/c.rs:1 | CODE-TRACE |\n"
        ),
        "verify_INV-001.md": "**Verdict**: CONFIRMED\n",
        "verify_INV-002.md": "**Verdict**: CONFIRMED\n",
        "verify_INV-003.md": "**Verdict**: CONFIRMED\n",
        "skeptic_judge_decisions.md": "## INV-001\nVerdict: ORIGINAL VERDICT\n",
    })
    expected_rows = D._skeptic_expected_findings(sp)
    expected = {row["finding_id"]: row for row in expected_rows}
    check(
        "R19 skeptic trigger manifest includes every independently selected tier",
        set(expected) == {"INV-001", "INV-002", "INV-003"}
        and "HIGH_RISK_ADVERSARIAL_REVIEW"
        in expected["INV-001"]["challenge_triggers"]
        and "HIGH_RISK_ADVERSARIAL_REVIEW"
        in expected["INV-002"]["challenge_triggers"]
        and "HIGH_RISK_ADVERSARIAL_REVIEW"
        not in expected["INV-003"]["challenge_triggers"]
        and bool(expected["INV-003"]["challenge_triggers"]),
        expected_rows,
    )
    issues = D._validate_skeptic_scope(sp)
    check(
        "R19 skeptic requires every manifest-triggered challenge",
        issues == [
            "skeptic scope: reviewed 1/3 manifest-triggered skeptic challenge "
            "finding(s); missing INV-002, INV-003"
        ],
        issues,
    )


# --------------------------------------------------------------------------
# Graph sweeps + degraded sentinel cleanup
# --------------------------------------------------------------------------

def test_G1_inventory_sources_include_graph_sweeps():
    sp = _mkscratch({
        "analysis_agent_1.md": "# Analysis\nfinding\n",
        "coverage_fill_1.md": "# Coverage Fill\nfinding\n",
        "panic_audit_1.md": "# Panic Audit\nfinding\n",
        "panic_audit_summary.md": "# Panic Summary\nEXPLOITABLE\n",
        "symmetric_pair_findings.md": "# Symmetric Pair\nfinding\n",
        "field_validation_matrix.md": "# Field Matrix\nfinding\n",
        "primitive_correctness_findings.md": "# Primitive Sweep\nfinding\n",
        "network_amplification_findings.md": "# Network Sweep\nfinding\n",
        "lifecycle_replay_findings.md": "# Lifecycle Sweep\nfinding\n",
    })
    names = [p.name for p in D._inventory_source_files(sp)]
    check("G1 graph sweep outputs feed inventory",
          "coverage_fill_1.md" in names
          and "panic_audit_1.md" in names
          and "panic_audit_summary.md" in names
          and "symmetric_pair_findings.md" in names
          and "field_validation_matrix.md" in names
          and "primitive_correctness_findings.md" in names
          and "network_amplification_findings.md" in names
          and "lifecycle_replay_findings.md" in names,
          repr(names))


def test_G2_graph_sweeps_validate_low_coverage_outputs():
    sp = _mkscratch({
        "subsystem_coverage_gap.md": (
            "# Subsystem Coverage Gap\n\n"
            "**Indexed prod files**: 100 | **Cited**: 40 | "
            "**Uncited**: 60 | **Coverage**: 40.0%\n"
        ),
        "graph_sweep_summary.md": "# Summary\n" + ("padding " * 30),
    })
    scip = sp / "scip"
    scip.mkdir()
    (scip / "repo_map.md").write_text("## crates/a/src/lib.rs\n", encoding="utf-8")
    hard, soft = D._validate_graph_sweeps(sp, "thorough")
    issues = hard + soft
    check("G2 low coverage requires coverage_fill",
          any("coverage_fill" in s for s in issues),
          repr(issues))
    (sp / "coverage_fill_1.md").write_text("# Fill\n" + ("padding " * 30),
                                            encoding="utf-8")
    hard2, soft2 = D._validate_graph_sweeps(sp, "thorough")
    check("G2 coverage_fill satisfies low-coverage gate",
          hard2 == [] and soft2 == [],
          repr((hard2, soft2)))


def test_G3_completed_phase_deletes_stale_degraded_sentinel():
    sp = _mkscratch({"depth.degraded": "old failure\n"})
    ckpt = D.Checkpoint(completed=["depth"], degraded=[])
    added = D._sync_degraded_sentinels_to_checkpoint(sp, ckpt)
    check("G3 stale degraded sentinel ignored for completed phase",
          added == [] and ckpt.degraded == [] and not (sp / "depth.degraded").exists(),
          f"added={added}, degraded={ckpt.degraded}, exists={(sp / 'depth.degraded').exists()}")


def test_G4_repo_map_table_format_is_indexed():
    sp = _mkscratch({})
    scip = sp / "scip"
    scip.mkdir()
    (scip / "repo_map.md").write_text(
        "| File | Symbols |\n"
        "|------|---------|\n"
        "| crates/types/src/merkle.rs | validate_path |\n"
        "| crates/p2p/src/peer_list.rs | from_compact |\n",
        encoding="utf-8",
    )
    paths = D._collect_scip_indexed_paths(sp)
    check("G4 table-form repo_map paths are indexed",
          {"crates/types/src/merkle.rs", "crates/p2p/src/peer_list.rs"} <= paths,
          repr(paths))


def test_G5_subsystem_coverage_basename_collision_not_false_covered():
    sp = _mkscratch({
        "analysis_1.md": "Finding cites crates/a/src/config.rs:L10 only.\n",
    })
    scip = sp / "scip"
    scip.mkdir()
    (scip / "repo_map.md").write_text(
        "## crates/a/src/config.rs\n"
        "## crates/b/src/config.rs\n",
        encoding="utf-8",
    )
    issues = D._compute_subsystem_coverage_gap(sp, "thorough")
    gap = (sp / "subsystem_coverage_gap.md").read_text(encoding="utf-8")
    check("G5 basename collision leaves uncited sibling in coverage gap",
          issues and "crates/b/src/config.rs" in gap and "crates/a/src/config.rs" not in gap,
          f"issues={issues!r}; gap={gap!r}")


def test_G5b_sc_subsystem_coverage_flags_uncited_contract_bucket():
    sp = _mkscratch({
        "contract_inventory.md": (
            "| Contract | Path |\n"
            "|----------|------|\n"
            "| LendA | contracts/lending/LendA.sol |\n"
            "| LendB | contracts/lending/LendB.sol |\n"
            "| LendC | contracts/lending/LendC.sol |\n"
            "| LendD | contracts/lending/LendD.sol |\n"
            "| DexA | contracts/dex/DexA.sol |\n"
            "| DexB | contracts/dex/DexB.sol |\n"
            "| DexC | contracts/dex/DexC.sol |\n"
            "| DexD | contracts/dex/DexD.sol |\n"
        ),
        "analysis_1.md": "Finding cites contracts/dex/DexA.sol:L10 only.\n",
    })
    issues = D._validate_sc_subsystem_coverage(sp, "thorough")
    gap = (sp / "sc_subsystem_coverage.md").read_text(encoding="utf-8")
    check("G5b SC coverage flags uncited substantial contract bucket",
          issues and "contracts/lending" in issues[0]
          and "contracts/lending (4 files)" in gap
          and "contracts/dex" not in gap,
          f"issues={issues!r}; gap={gap!r}")


def test_G5c_sc_subsystem_coverage_ack_exempts_bucket():
    sp = _mkscratch({
        "contract_inventory.md": (
            "| Contract | Path |\n"
            "|----------|------|\n"
            "| LendA | contracts/lending/LendA.sol |\n"
            "| LendB | contracts/lending/LendB.sol |\n"
            "| LendC | contracts/lending/LendC.sol |\n"
            "| LendD | contracts/lending/LendD.sol |\n"
        ),
        "analysis_1.md": "Finding cites contracts/lending/LendA.sol:L10.\n",
    })
    issues = D._validate_sc_subsystem_coverage(sp, "thorough")
    check("G5c SC coverage passes when bucket has citation",
          issues == [],
          repr(issues))


def test_G5b2_sc_coverage_excludes_interfaces_directory():
    """interfaces/ dir should never trigger a coverage gap (non-auditable)."""
    sp = _mkscratch({
        "contract_inventory.md": (
            "| Contract | Path |\n"
            "|----------|------|\n"
            "| ISwapRouter | interfaces/ISwapRouter.sol |\n"
            "| IUniswapV2Factory | interfaces/IUniswapV2Factory.sol |\n"
            "| IUniswapV2Router01 | interfaces/IUniswapV2Router01.sol |\n"
            "| IWETH9 | interfaces/IWETH9.sol |\n"
            "| CoreA | contracts/core/CoreA.sol |\n"
            "| CoreB | contracts/core/CoreB.sol |\n"
        ),
        "analysis_1.md": "Finding cites contracts/core/CoreA.sol:L10.\n",
    })
    issues = D._validate_sc_subsystem_coverage(sp, "thorough")
    check("G5b2 interfaces/ excluded from subsystem coverage",
          issues == [],
          repr(issues))


def test_G5b3_sc_coverage_excludes_mocks_directory():
    """mocks/ dir should never trigger a coverage gap (test infrastructure)."""
    sp = _mkscratch({
        "contract_inventory.md": (
            "| Contract | Path |\n"
            "|----------|------|\n"
            "| ERC20Mock | mocks/ERC20Mock.sol |\n"
            "| GatewayMock | mocks/BridgeRouterMock.sol |\n"
            "| WrappedTokenMock | mocks/WrappedTokenMock.sol |\n"
            "| SwapRouterMock | mocks/SwapRouterMock.sol |\n"
            "| CoreA | contracts/core/CoreA.sol |\n"
            "| CoreB | contracts/core/CoreB.sol |\n"
        ),
        "analysis_1.md": "Finding cites contracts/core/CoreA.sol:L10.\n",
    })
    issues = D._validate_sc_subsystem_coverage(sp, "thorough")
    check("G5b3 mocks/ excluded from subsystem coverage",
          issues == [],
          repr(issues))


def test_G5b4_sc_coverage_excludes_nested_interfaces_and_mocks():
    """src/interfaces/ and src/mocks/ with slash-embedded markers excluded."""
    sp = _mkscratch({
        "contract_inventory.md": (
            "| Contract | Path |\n"
            "|----------|------|\n"
            "| IFoo | src/interfaces/IFoo.sol |\n"
            "| IBar | src/interfaces/IBar.sol |\n"
            "| IBaz | src/interfaces/IBaz.sol |\n"
            "| IQux | src/interfaces/IQux.sol |\n"
            "| MockA | src/mocks/MockA.sol |\n"
            "| MockB | src/mocks/MockB.sol |\n"
            "| MockC | src/mocks/MockC.sol |\n"
            "| MockD | src/mocks/MockD.sol |\n"
            "| Vault | src/core/Vault.sol |\n"
        ),
        "analysis_1.md": "Finding cites src/core/Vault.sol:L10.\n",
    })
    issues = D._validate_sc_subsystem_coverage(sp, "thorough")
    check("G5b4 nested interfaces/ and mocks/ excluded from subsystem coverage",
          issues == [],
          repr(issues))


def test_G5b5_sc_coverage_still_flags_real_uncited_prod_buckets():
    """Interfaces/mocks exclusion must not accidentally exclude real prod code."""
    sp = _mkscratch({
        "contract_inventory.md": (
            "| Contract | Path |\n"
            "|----------|------|\n"
            "| ISwapRouter | interfaces/ISwapRouter.sol |\n"
            "| IUniswapV2Factory | interfaces/IUniswapV2Factory.sol |\n"
            "| IUniswapV2Router01 | interfaces/IUniswapV2Router01.sol |\n"
            "| IWETH9 | interfaces/IWETH9.sol |\n"
            "| LendA | contracts/lending/LendA.sol |\n"
            "| LendB | contracts/lending/LendB.sol |\n"
            "| LendC | contracts/lending/LendC.sol |\n"
            "| LendD | contracts/lending/LendD.sol |\n"
            "| DexA | contracts/dex/DexA.sol |\n"
        ),
        "analysis_1.md": "Finding cites contracts/dex/DexA.sol:L10.\n",
    })
    issues = D._validate_sc_subsystem_coverage(sp, "thorough")
    check("G5b5 interfaces excluded but real uncited lending bucket still flagged",
          issues and "contracts/lending" in issues[0]
          and "interfaces" not in issues[0],
          repr(issues))


def test_G5d_sc_slither_flat_files_materialize_from_recon_artifacts():
    sp = _mkscratch({
        "call_graph.md": "# Call Graph\nVault.deposit -> Strategy.invest\n",
        "function_summary.md": "# Functions\nVault.deposit external nonReentrant\n",
        "state_write_map.md": "# Writes\nVault.deposit writes totalAssets\n",
        "contract_inventory.md": "# Contracts\ncontracts/Vault.sol\n",
        "modifiers.md": "# Modifiers\nonlyOwner protects setFee\n",
        "static_analysis.md": "# Static\nNo detector findings.\n",
    })
    generated = D._materialize_sc_slither_flat_files(sp)
    status = (sp / "slither" / "primitive_status.md").read_text(encoding="utf-8")
    call_graph = (sp / "slither" / "call_graph.md").read_text(encoding="utf-8")
    check("G5d SC Slither flat files materialize from recon artifacts",
          {"call_graph.md", "function_summary.md", "state_write_map.md",
           "inheritance_tree.md", "access_control_map.md", "detector_findings.md"} <= set(generated)
          and "SLITHER_PREBAKE_COMPLETE: true" in status
          and "Vault.deposit -> Strategy.invest" in call_graph,
          f"generated={generated!r}; status={status!r}; call_graph={call_graph!r}")


def test_G6_graph_sweeps_require_miss_class_work_queues():
    sp = _mkscratch({
        "graph_sweep_summary.md": "# Summary\n" + ("padding " * 30),
    })
    scip = sp / "scip"
    scip.mkdir()
    (scip / "repo_map.md").write_text(
        "## crates/types/src/merkle.rs\n"
        "## crates/chain/src/block_header.rs\n"
        "## crates/p2p/src/peer_gossip.rs\n"
        "## crates/cache/src/seen_cache.rs\n",
        encoding="utf-8",
    )
    hard, soft = D._validate_graph_sweeps(sp, "thorough")
    issues = hard + soft
    check("G6 miss-class surfaces require dedicated graph work queues",
          any("field_validation_matrix" in s for s in issues)
          and any("primitive_correctness" in s for s in issues)
          and any("network_amplification" in s for s in issues)
          and any("lifecycle_replay" in s for s in issues),
          repr(issues))
    (sp / "field_validation_matrix.md").write_text(
        "# Work Queue\n" + ("evidence " * 30), encoding="utf-8")
    (sp / "primitive_correctness_findings.md").write_text(
        "# Work Queue\n" + ("evidence " * 30), encoding="utf-8")
    (sp / "network_amplification_findings.md").write_text(
        "# Work Queue\n"
        "| Ingress | Dedup / seen-cache point | Validation point | Egress / loop | Verdict | Evidence |\n"
        "|---------|--------------------------|------------------|---------------|---------|----------|\n"
        "| gossip | seen cache | validate | broadcast loop | SAFE | crates/p2p/src/peer_gossip.rs:L1 |\n",
        encoding="utf-8")
    (sp / "lifecycle_replay_findings.md").write_text(
        "# Work Queue\n"
        "| Object | Insert | Consume | Evict on success | Evict on error | Replay guard | Verdict | Evidence |\n"
        "|--------|--------|---------|------------------|----------------|--------------|---------|----------|\n"
        "| cache | insert | consume | remove | delete | nonce | SAFE | crates/cache/src/seen_cache.rs:L1 |\n",
        encoding="utf-8")
    hard2, soft2 = D._validate_graph_sweeps(sp, "thorough")
    check("G6 dedicated graph work queues satisfy miss-class gate",
          hard2 == [] and soft2 == [],
          repr((hard2, soft2)))


def test_G7_final_coverage_summary_uses_late_verify_citations():
    sp = _mkscratch({
        "verify_INV-01.md": (
            "# Verification\n\n"
            "**Location**: crates/a/src/lib.rs:L10\n"
        ),
    })
    scip = sp / "scip"
    scip.mkdir()
    (scip / "repo_map.md").write_text(
        "## crates/a/src/lib.rs\n"
        "## crates/b/src/lib.rs\n",
        encoding="utf-8",
    )
    D._write_final_subsystem_coverage_summary(sp)
    text = (sp / "subsystem_coverage_final.md").read_text(encoding="utf-8")
    check("G7 final coverage summary includes verify-time citations",
          "Covered by source citation**: 1" in text
          and "crates/b/src/lib.rs" in text
          and "crates/a/src/lib.rs" not in text.split("## Uncovered Production Files", 1)[-1],
          text)


def test_G8_verify_shard_gate_respects_min_bytes_param():
    """Verify-shard gate and verify-file-present helpers use the min_bytes
    parameter instead of hardcoded 100. Ensures Codex byte relaxation flows
    through to verify-file presence checks."""
    sp = _mkscratch({
        "verification_queue.md": (
            "| Finding ID | Severity | Preferred Verification |\n"
            "|------------|----------|------------------------|\n"
            "| INV-01     | High     | [CODE-TRACE]           |\n"
        ),
    })
    # Write a verify file that's 60 bytes — below 100 but above 50
    small_content = "# Verify INV-01\n**Verdict**: CONFIRMED\n**Preferred Tag**: [CODE-TRACE]\n"
    assert 50 < len(small_content.encode()) < 100
    (sp / "verify_INV-01.md").write_text(small_content, encoding="utf-8")

    # Default min_bytes=100: file is "not present"
    present_100 = D._verify_file_present_for_id(sp, "INV-01", min_bytes=100)
    check("G8a verify file < 100 bytes rejected at min_bytes=100",
          present_100 is False,
          repr(present_100))

    # Codex-relaxed min_bytes=50: file is present
    present_50 = D._verify_file_present_for_id(sp, "INV-01", min_bytes=50)
    check("G8b verify file >= 50 bytes accepted at min_bytes=50",
          present_50 is True,
          repr(present_50))

    # _validate_verify_files_for_queue also respects min_bytes
    issues_100 = D._validate_verify_files_for_queue(sp, min_bytes=100)
    issues_50 = D._validate_verify_files_for_queue(sp, min_bytes=50)
    check("G8c verify-queue parity fails at min_bytes=100",
          len(issues_100) > 0,
          repr(issues_100))
    check("G8d verify-queue parity passes at min_bytes=50",
          issues_50 == [],
          repr(issues_50))


def test_G9_codex_model_not_available_detection():
    """Model-not-available detector catches plan-access errors and
    auth detector correctly excludes them (no false permanent halt)."""
    import tempfile, pathlib
    with tempfile.TemporaryDirectory() as td:
        log = pathlib.Path(td) / "stdio.log"

        # Pattern 1: model does not exist
        log.write_text('Error: The model `gpt-5.5` does not exist', encoding="utf-8")
        check("G9a model does not exist detected",
              D._detect_codex_model_not_available(log) is True, "")
        check("G9b auth detector excludes model-not-available",
              D._detect_codex_auth_error(log) is False, "")

        # Pattern 2: model not found
        log.write_text('{"error": {"message": "model not found", "code": 404}}',
                       encoding="utf-8")
        check("G9c model not found detected",
              D._detect_codex_model_not_available(log) is True, "")

        # Pattern 3: access denied to model
        log.write_text('access denied for model gpt-5.5 on your plan',
                       encoding="utf-8")
        check("G9d access denied to model detected",
              D._detect_codex_model_not_available(log) is True, "")

        # Pattern 4: real auth error (no model mention) — NOT model-not-available
        log.write_text('HTTP 401 Unauthorized: invalid_api_key', encoding="utf-8")
        check("G9e real auth error not misclassified as model issue",
              D._detect_codex_model_not_available(log) is False, "")
        check("G9f real auth error still detected by auth detector",
              D._detect_codex_auth_error(log) is True, "")

        # Pattern 5: missing file
        missing = pathlib.Path(td) / "nonexistent.log"
        check("G9g missing log returns False for model detector",
              D._detect_codex_model_not_available(missing) is False, "")

        # Model/command output is untrusted audited data, not provider-routing
        # evidence.  A phrase inside a successful JSONL command event must not
        # manufacture a model-unavailable halt.
        log.write_text(json.dumps({
            "type": "item.completed",
            "item": {
                "type": "command_execution",
                "aggregated_output": "The dependency model is not available here",
                "exit_code": 0,
            },
        }), encoding="utf-8")
        check("G9h command output cannot spoof model unavailability",
              D._detect_codex_model_not_available(log) is False, "")


def test_G10_codex_model_unavailable_downgrade():
    """_codex_model_unavailable downgrades only matching phases."""
    from plamen_types import Phase, phase_model
    depth = Phase("depth", ["Depth"], ["depth_findings.md"],
                  base_timeout_s=3600, model="opus")
    breadth = Phase("breadth", ["Breadth"], ["analysis_*.md"],
                    base_timeout_s=3600, model="sonnet")
    # Without unavailable: opus → gpt-5.5, sonnet → gpt-5.4
    cfg = {"cli_backend": "codex", "mode": "core"}
    check("G10a opus maps to gpt-5.6-sol",
          phase_model(depth, "core", cfg) == "gpt-5.6-sol", "")
    check("G10b sonnet maps to gpt-5.6-terra",
          phase_model(breadth, "core", cfg) == "gpt-5.6-terra", "")
    # Mark gpt-5.5 unavailable: opus phases downgrade, sonnet stays
    cfg["_codex_model_unavailable"] = "gpt-5.6-sol"
    cfg["_codex_model_fallback"] = "gpt-5.6-terra"
    check("G10c opus downgraded to gpt-5.6-terra",
          phase_model(depth, "core", cfg) == "gpt-5.6-terra", "")
    check("G10d sonnet unaffected (still gpt-5.6-terra)",
          phase_model(breadth, "core", cfg) == "gpt-5.6-terra", "")


def test_Q1_no_sleep_override_clears_hibernation_marker():
    sp = _mkscratch({
        ".hibernating": (
            '{"wake_at_utc":"'
            + (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
            + '","last_phase":"verify_medium_a","attempt_count":1}'
        )
    })
    old = os.environ.get("PLAMEN_NO_HIBERNATE")
    old_enable = os.environ.get("PLAMEN_HIBERNATE")
    os.environ["PLAMEN_NO_HIBERNATE"] = "1"
    os.environ.pop("PLAMEN_HIBERNATE", None)
    try:
        rc = D.maybe_resume_hibernation(sp)
    finally:
        if old is None:
            os.environ.pop("PLAMEN_NO_HIBERNATE", None)
        else:
            os.environ["PLAMEN_NO_HIBERNATE"] = old
        if old_enable is None:
            os.environ.pop("PLAMEN_HIBERNATE", None)
        else:
            os.environ["PLAMEN_HIBERNATE"] = old_enable
    check("Q1 no-sleep override clears existing hibernation marker",
          rc is None and not (sp / ".hibernating").exists(),
          f"rc={rc}, marker_exists={(sp / '.hibernating').exists()}")


def test_Q2_no_sleep_override_skips_new_hibernation_on_rate_limit():
    sp = _mkscratch({
        "_stdio_verify_medium_a.log": (
            '{"type":"result","is_error":true,'
            '"api_error_status":429,"error":{"type":"rate_limit_error"},'
            '"message":"retry-after: 20 minutes"}'
        )
    })
    old = os.environ.get("PLAMEN_NO_HIBERNATE")
    old_enable = os.environ.get("PLAMEN_HIBERNATE")
    os.environ["PLAMEN_NO_HIBERNATE"] = "1"
    os.environ.pop("PLAMEN_HIBERNATE", None)
    try:
        rc = D.maybe_hibernate_on_rate_limit(sp, "verify_medium_a", 1)
    finally:
        if old is None:
            os.environ.pop("PLAMEN_NO_HIBERNATE", None)
        else:
            os.environ["PLAMEN_NO_HIBERNATE"] = old
        if old_enable is None:
            os.environ.pop("PLAMEN_HIBERNATE", None)
        else:
            os.environ["PLAMEN_HIBERNATE"] = old_enable
    check("Q2 no-sleep override prevents new hibernation marker",
          rc is None and not (sp / ".hibernating").exists(),
          f"rc={rc}, marker_exists={(sp / '.hibernating').exists()}")


def test_Q3_hibernation_disabled_by_default():
    sp = _mkscratch({
        "_stdio_verify_medium_a.log": (
            '{"type":"result","is_error":true,'
            '"api_error_status":429,"error":{"type":"rate_limit_error"},'
            '"message":"retry-after: 20 minutes"}'
        )
    })
    old = os.environ.get("PLAMEN_NO_HIBERNATE")
    old_enable = os.environ.get("PLAMEN_HIBERNATE")
    os.environ.pop("PLAMEN_NO_HIBERNATE", None)
    os.environ.pop("PLAMEN_HIBERNATE", None)
    try:
        rc = D.maybe_hibernate_on_rate_limit(sp, "verify_medium_a", 1)
    finally:
        if old is None:
            os.environ.pop("PLAMEN_NO_HIBERNATE", None)
        else:
            os.environ["PLAMEN_NO_HIBERNATE"] = old
        if old_enable is None:
            os.environ.pop("PLAMEN_HIBERNATE", None)
        else:
            os.environ["PLAMEN_HIBERNATE"] = old_enable
    check("Q3 hibernation disabled by default",
          rc is None and not (sp / ".hibernating").exists(),
          f"rc={rc}, marker_exists={(sp / '.hibernating').exists()}")


def test_Q4_hibernation_can_be_opted_in():
    sp = _mkscratch({
        "_stdio_verify_medium_a.log": (
            '{"type":"result","is_error":true,'
            '"api_error_status":429,"error":{"type":"rate_limit_error"},'
            '"message":"retry-after: 20 minutes"}'
        )
    })
    old = os.environ.get("PLAMEN_NO_HIBERNATE")
    old_enable = os.environ.get("PLAMEN_HIBERNATE")
    os.environ.pop("PLAMEN_NO_HIBERNATE", None)
    os.environ["PLAMEN_HIBERNATE"] = "1"
    try:
        rc = D.maybe_hibernate_on_rate_limit(sp, "verify_medium_a", 1)
    finally:
        if old is None:
            os.environ.pop("PLAMEN_NO_HIBERNATE", None)
        else:
            os.environ["PLAMEN_NO_HIBERNATE"] = old
        if old_enable is None:
            os.environ.pop("PLAMEN_HIBERNATE", None)
        else:
            os.environ["PLAMEN_HIBERNATE"] = old_enable
    check("Q4 hibernation opt-in still works",
          rc == D.EXIT_HIBERNATING and (sp / ".hibernating").exists(),
          f"rc={rc}, marker_exists={(sp / '.hibernating').exists()}")


# --------------------------------------------------------------------------
# A3: Attention repair is bounded and evidence-driven
# --------------------------------------------------------------------------

def test_A3_attention_repair_queue_from_notread_and_uncited_security_files():
    sp = _mkscratch({
        "notread_priority_gaps.md": (
            "# NOTREAD priority coverage gaps\n\n"
            "| # | File |\n|---|------|\n"
            "| 1 | `crates/consensus/src/block_validation.rs` |\n"
        ),
        "analysis_01.md": "## Finding [A-1]\ncrates/p2p/src/gossip.rs:L1\n",
    })
    (sp / "scip").mkdir()
    (sp / "scip" / "repo_map.md").write_text(
        "## crates/consensus/src/block_validation.rs\n"
        "## crates/p2p/src/gossip.rs\n"
        "## crates/api-server/src/routes/block.rs\n",
        encoding="utf-8",
    )
    needed, reason = D._prepare_attention_repair(sp, "thorough")
    queue = (sp / "attention_repair_queue.md").read_text(encoding="utf-8")
    check("A3 attention repair queues concrete gaps",
          needed
          and "block_validation.rs" in queue
          and "api-server/src/routes/block.rs" in queue
          and "bounded repair item" in reason,
          queue)


def test_A3_attention_repair_validation_requires_verdicts_and_paths():
    sp = _mkscratch({
        "attention_repair_queue.md": (
            "# Attention Repair Queue\n\n"
            "| # | Kind | Target | Reason | Source | Evidence hint |\n"
            "|---|------|--------|--------|--------|---------------|\n"
            "| 1 | notread-file | `crates/a/src/lib.rs` | gap | `scope_leftover.md` | `crates/a/src/lib.rs` |\n"
        ),
        "attention_repair_summary.md": (
            "# Attention Repair\n\n"
            "| Queue # | Kind | Target | Verdict | Evidence | Notes |\n"
            "|---------|------|--------|---------|----------|-------|\n"
            "| 1 | notread-file | `crates/a/src/lib.rs` | SAFE | crates/a/src/lib.rs:L10 | reviewed |\n"
        ),
    })
    hard, soft = D._validate_attention_repair(sp, "thorough")
    check("A3 attention repair accepts SAFE verdict with queued path evidence",
          hard == [],
          repr((hard, soft)))


def test_A3_attention_repair_accepts_covered_verdict_for_receipts():
    sp = _mkscratch({
        "attention_repair_queue.md": (
            "# Attention Repair Queue\n\n"
            "| # | Kind | Target | Reason | Source | Evidence hint |\n"
            "|---|------|--------|--------|--------|---------------|\n"
            "| 1 | security-obligation | `SO-001` | gap | `security_obligations.md` | `SO-001` |\n"
            "| 2 | security-obligation | `SO-002` | gap | `security_obligations.md` | `SO-002` |\n"
            "| 3 | security-obligation | `SO-003` | gap | `security_obligations.md` | `SO-003` |\n"
        ),
        "attention_repair_summary.md": (
            "# Attention Repair\n\n"
            "| Queue # | Kind | Target | Verdict | Evidence | Notes |\n"
            "|---------|------|--------|---------|----------|-------|\n"
            "| Row 1 | security-obligation | `SO-001` | COVERED | Existing depth/scanner artifacts cover SO-001 | no new finding |\n"
            "| #2 | security-obligation | `SO-002` | REVIEWED | Existing depth/scanner artifacts cover SO-002 | no new finding |\n"
            "- Queue 3: CLOSED after reviewing SO-003; no new finding.\n"
        ),
    })
    hard, soft = D._validate_attention_repair(sp, "thorough")
    check("A3 attention repair accepts common verdict and row-number variants",
          hard == [],
          repr((hard, soft)))


def test_A3_attention_repair_requires_full_queued_path_receipt():
    sp = _mkscratch({
        "attention_repair_queue.md": (
            "# Attention Repair Queue\n\n"
            "| # | Kind | Target | Reason | Source | Evidence hint |\n"
            "|---|------|--------|--------|--------|---------------|\n"
            "| 1 | uncited-security-file | `base/DecodersAndSanitizers/Protocols/MorphoRewardsMerkleClaimerDecoderAndSanitizer.sol` | gap | `repo_map.md` | `base/DecodersAndSanitizers/Protocols/MorphoRewardsMerkleClaimerDecoderAndSanitizer.sol` |\n"
        ),
        "attention_repair_summary.md": (
            "# Attention Repair\n\n"
            "| Queue # | Kind | Target | Verdict | Evidence | Notes |\n"
            "|---------|------|--------|---------|----------|-------|\n"
            "| 1 | uncited-security-file | `MorphoRewardsMerkleClaimerDecoderAndSanitizer.sol` | SAFE | MorphoRewardsMerkleClaimerDecoderAndSanitizer.sol:L10 | reviewed |\n"
        ),
    })
    hard, soft = D._validate_attention_repair(sp, "thorough")
    check("A3 attention repair rejects basename-only queued path receipts",
          any("did not cite queued path" in issue for issue in hard),
          repr((hard, soft)))


def test_A3_attention_repair_validation_accepts_row_shard_suffix_paths():
    sp = _mkscratch({
        "attention_repair_queue.md": (
            "| # | Kind | Target | Reason | Source | Evidence hint |\n"
            "|---|------|--------|--------|--------|---------------|\n"
            "| 1 | uncited-security-file | `src/crates/p2p/src/gossip_service.rs` | gap | `repo_map.md` | `src/crates/p2p/src/gossip_service.rs` |\n"
        ),
        "attention_repair_summary.md": (
            "# Attention Repair Summary\n\n"
            "| Row | Status | Verdict |\n"
            "|-----|--------|---------|\n"
            "| 1 | SAFE | duplicate already captured | `gossip_service.rs` |\n"
        ),
        "attention_repair_rows_1_8.md": (
            "Row 1 | SAFE | gossip_service.rs | all issues duplicate\n"
        ),
    })
    hard, soft = D._validate_attention_repair(sp, "thorough")
    check("A3 attention repair accepts row-shard basename/suffix citations",
          hard == [],
          repr((hard, soft)))


def test_A3_attention_repair_graph_rows_do_not_require_exact_source_path():
    sp = _mkscratch({
        "attention_repair_queue.md": (
            "| # | Kind | Target | Reason | Source | Evidence hint |\n"
            "|---|------|--------|--------|--------|---------------|\n"
            "| 1 | graph-row | `| TransactionHeader | ledger_id | transaction.rs:61 |` | graph row | `field_validation_matrix.md` | `transaction.rs, block.rs` |\n"
        ),
        "attention_repair_summary.md": (
            "# Attention Repair Summary\n\n"
            "| Row | Kind | Status | Finding | Verdict |\n"
            "|-----|------|--------|---------|---------|\n"
            "| 1 | graph-row | CONFIRMED | ATT-1 | ledger-id issue merged at `tx.rs:158` |\n"
        ),
    })
    hard, soft = D._validate_attention_repair(sp, "thorough")
    check("A3 graph-row repair requires verdicts, not exact source path citation",
          hard == [],
          repr((hard, soft)))


def test_A3_attention_repair_findings_promote_into_inventory():
    sp = _mkscratch({
        "findings_inventory.md": "# Inventory\n\n### Finding [INV-01]: existing\n",
        "attention_repair_findings.md": (
            "### Finding [ATT-1]: repaired issue\n"
            "**Severity**: High\n"
            "**Location**: crates/a/src/lib.rs:L10\n"
            "**Preferred Tag**: CODE-TRACE\n"
            "**Description**: repaired from attention queue\n"
        ),
    })
    promoted = D._promote_depth_findings_to_inventory(sp)
    inv = (sp / "findings_inventory.md").read_text(encoding="utf-8")
    check("A3 attention repair findings are mechanically promoted",
          promoted == ["ATT-1"] and "Source IDs**: [ATT-1]" in inv,
          f"promoted={promoted}, inv={inv}")


def test_A3_graph_schema_catches_weak_network_rows():
    sp = _mkscratch({
        "graph_sweep_summary.md": "# Summary\n\ncompleted graph sweeps\n",
        "network_amplification_findings.md": (
            "# Network\n\n"
            "| Entry | Verdict | Evidence |\n"
            "|-------|---------|----------|\n"
            "| p2p | SAFE | crates/p2p/src/lib.rs:L1 |\n"
        ),
    })
    (sp / "scip").mkdir()
    (sp / "scip" / "repo_map.md").write_text(
        "## crates/p2p/src/lib.rs\n",
        encoding="utf-8",
    )
    hard, soft = D._validate_graph_sweeps(sp, "thorough")
    check("A3 graph schema rejects network sweep without dedup/validation/egress",
          any("network_amplification_findings.md lacks required" in s for s in soft),
          repr(soft))


def test_A3_sc_contract_inventory_drives_attention_repair_without_scip():
    sp = _mkscratch({
        "contract_inventory.md": (
            "# Contracts\n\n"
            "- contracts/Vault.sol\n"
            "- contracts/Strategy.sol\n"
            "- contracts/oracle/PriceOracle.sol\n"
        ),
        "analysis_01.md": (
            "## Finding [A-1]\n"
            "**Location**: contracts/Vault.sol:L10\n"
        ),
    })
    needed, _ = D._prepare_attention_repair(sp, "thorough")
    queue = (sp / "attention_repair_queue.md").read_text(encoding="utf-8")
    check("A3 SC contract_inventory fallback queues uncited security files",
          needed
          and "contracts/Strategy.sol" in queue
          and "contracts/oracle/PriceOracle.sol" in queue
          and "contracts/Vault.sol" not in queue.split("uncited-security-file", 1)[-1],
          queue)


def test_A3_attention_repair_excludes_support_files_but_writes_spec_expectations():
    sp = _mkscratch({
        "analysis_01.md": (
            "## Finding [A-1]\n"
            "**Location**: contracts/Vault.sol:L10\n"
        ),
    })
    (sp / "scip").mkdir()
    (sp / "scip" / "repo_map.md").write_text(
        "## contracts/Vault.sol\n"
        "## contracts/Strategy.sol\n"
        "## mocks/MockToken.sol\n"
        "## MedusaHarness.sol\n"
        "## test/Vault.t.sol\n",
        encoding="utf-8",
    )
    needed, _ = D._prepare_attention_repair(sp, "thorough")
    queue = (sp / "attention_repair_queue.md").read_text(encoding="utf-8")
    spec = (sp / "spec_expectations.md").read_text(encoding="utf-8")
    check("A3 attention repair queues only production gaps",
          needed
          and "contracts/Strategy.sol" in queue
          and "MockToken.sol" not in queue
          and "MedusaHarness.sol" not in queue
          and "Vault.t.sol" not in queue,
          queue)
    check("A3 spec support files become expectation evidence",
          "mocks/MockToken.sol" in spec
          and "MedusaHarness.sol" in spec
          and "test/Vault.t.sol" in spec
          and "specification evidence only" in spec,
          spec)


def test_A3_semantic_dedup_candidate_packet_is_bounded(tmp_path):
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    blocks = ["# Inventory", ""]
    for i in range(1, 32):
        blocks.extend([
            f"### Finding [INV-{i:03d}]: Shared source duplicate {i}",
            "**Severity**: Medium",
            f"**Location**: contracts/Vault.sol:L{i}",
            "**Source IDs**: CC-1, CC-2, CC-3",
            "**Description**: candidate duplicate for bounded packet testing.",
            "",
        ])
    (sp / "findings_inventory.md").write_text("\n".join(blocks), encoding="utf-8")
    total = D._compute_dedup_candidate_pairs(sp)
    live = (sp / "dedup_candidate_pairs.md").read_text(encoding="utf-8")
    focus = (sp / "dedup_focus_inventory.md").read_text(encoding="utf-8")
    live_rows = [
        line for line in live.splitlines()
        if line.startswith("| INV-")
    ]
    focus_ids = set(re.findall(r"Finding \\[(INV-\\d+)\\]", focus))
    check("A3 semantic dedup has many total pairs",
          total > 24,
          f"total={total}")
    # v2.8.17 dedup-throughput upgrade: the old hard 24-cap is gone. The live
    # packet (round 1 when multi-round) is bounded by the per-round chunk size,
    # NOT 24 — every admitted pair is still per-pair LLM-judged and the full set
    # is preserved (deferred pairs in dedup_candidate_pairs_full.md). Recall is
    # never reduced: more genuine candidates now reach the LLM, never fewer.
    import plamen_parsers as _pp
    chunk = _pp._DEDUP_ROUND_CHUNK
    cap = D._dedup_live_pair_cap()
    check("A3 semantic dedup live packet bounded by chunk size (not 24)",
          0 < len(live_rows) <= max(chunk, 1) and len(live_rows) <= cap,
          f"rows={len(live_rows)} chunk={chunk} cap={cap}\n{live[:500]}")
    check("A3 semantic dedup focus inventory only contains live IDs",
          len(focus_ids) <= 2 * max(chunk, 1),
          f"focus_ids={len(focus_ids)} chunk={chunk}")


def test_A3_semantic_dedup_prompt_is_fail_open_and_bounded():
    prompt = (
        plamen_home() / "prompts" / "shared" / "v2" /
        "phase4e-semantic-dedup.md"
    ).read_text(encoding="utf-8")
    # D1: SC and L1 emit only the decisions stub. The driver owns both the
    # crash-safety passthrough and the post-dedup inventory; L1 semantic dedup
    # is prequeue and must neither read nor copy a verification queue.
    check(
        "A3 semantic dedup prompt writes decisions stub before driver materialization",
        "Mandatory First Action" in prompt
        and "IN_PROGRESS_PASSTHROUGH_WRITTEN" in prompt
        and "do NOT read `{SCRATCHPAD}/findings_inventory.md`" in prompt
        and "L1: do NOT read `{SCRATCHPAD}/verification_queue.md`; it does not exist yet"
        in prompt
        and "do NOT copy or edit a verification queue" in prompt
        and "driver owns and (re)builds that artifact mechanically" in prompt
        and "copy `{SCRATCHPAD}/verification_queue.md`" not in prompt
        and "`verification_queue_deduped.md`" not in prompt,
        prompt[:1800],
    )
    check("A3 semantic dedup prompt forbids global expansion",
          "Do NOT read or expand" in prompt
          and "Evaluate ONLY the candidate rows" in prompt
          and "do not scan the full inventory" in prompt.lower(),
          prompt[:1500])
    check("A3 semantic dedup prompt keeps disposition out of severity",
          "Never write disposition text in the severity field" in prompt
          and "N/a (absorbed into DE-2)" in prompt,
          prompt)


def test_A3_sc_phase_order_has_attention_repair_before_rag_and_chain():
    names = [p.name for p in D.SC_PHASES]
    check("A3 SC attention_repair phase is before rag_sweep and chain",
          "attention_repair" in names
          and names.index("depth") < names.index("attention_repair")
          < names.index("rag_sweep") < names.index("chain"),
          repr(names))


def test_M1_opus_alias_pins_to_5():
    phase = D.Phase("depth", [], [], base_timeout_s=1, model="opus")
    check("M1 bare opus resolves to claude-opus-5",
          D.phase_model(phase, "thorough") == "claude-opus-5",
          D.phase_model(phase, "thorough"))


def test_M2_light_mode_still_forces_sonnet():
    phase = D.Phase("depth", [], [], base_timeout_s=1, model="opus")
    check("M2 light mode forces pinned Sonnet 5 despite opus phase",
          D.phase_model(phase, "light") == "claude-sonnet-5",
          D.phase_model(phase, "light"))


def test_M3_l1_verify_shards_are_cost_capped():
    phases = {p.name: p for p in D.L1_PHASES}
    for name in D.L1_VERIFY_PHASE_NAMES:
        check(f"M3 L1 {name} uses pinned Sonnet 5",
              D.phase_model(phases[name], "thorough") == "claude-sonnet-5",
              D.phase_model(phases[name], "thorough"))
    check("M3 L1 verify_queue is promoted to pinned Sonnet 5",
          D.phase_model(phases["verify_queue"], "thorough") == "claude-sonnet-5",
          D.phase_model(phases["verify_queue"], "thorough"))
    check("M3 L1 verify_aggregate is promoted to pinned Sonnet 5",
          D.phase_model(phases["verify_aggregate"], "thorough") == "claude-sonnet-5",
          D.phase_model(phases["verify_aggregate"], "thorough"))


def test_M4_l1_verify_shards_are_severity_weighted():
    rows = [
        "| Queue # | Finding ID | Severity | Title | Bug Class | Preferred Tag | Location | Primary Artifact |",
        "|---------|------------|----------|-------|-----------|---------------|----------|------------------|",
    ]
    q = 1
    for i in range(1, 86):
        sev = "Critical" if i <= 12 else "High"
        rows.append(f"| {q} | INV-{i:03d} | {sev} | H{i} | consensus | [CODE-TRACE] | crates/a.rs:L1 | depth.md |")
        q += 1
    for i in range(1, 44):
        rows.append(f"| {q} | MED-{i:03d} | Medium | M{i} | p2p | [CODE-TRACE] | crates/b.rs:L1 | depth.md |")
        q += 1
    for i in range(1, 18):
        rows.append(f"| {q} | LOW-{i:03d} | Low | L{i} | rpc | [CODE-TRACE] | crates/c.rs:L1 | depth.md |")
        q += 1
    sp = _mkscratch({"verification_queue.md": "\n".join(rows)})
    shards = D.compute_verify_shards(sp)
    non_empty = {k: len(v) for k, v in shards.items() if v}
    ch_sizes = [
        len(shards[name]) for name in D.L1_VERIFY_CRITHIGH_PHASE_NAMES
        if shards.get(name)
    ]
    med_sizes = [
        len(shards[name]) for name in (
            "verify_medium_a", "verify_medium_b", "verify_medium_c",
            "verify_medium_d", "verify_medium_e", "verify_medium_f",
        )
        if shards.get(name)
    ]
    low_sizes = [
        len(shards[name]) for name in (
            "verify_low_a", "verify_low_b", "verify_low_c", "verify_low_d",
        )
        if shards.get(name)
    ]
    # Uniform per-shard target (VERIFY_TARGET_PER_SHARD=4): C/H spreads across
    # the full 10-slot pool (84 findings -> ~9/shard, slot-pool capped).
    check("M4 L1 C/H verify shards are <=9 on a large queue",
          max(ch_sizes) <= 9,
          repr(non_empty))
    # Medium now uses ALL 6 slots (43 findings / 4 ~= 11 desired, capped at 6
    # slots -> ~8/shard) instead of the old ~11/shard heavy lane.
    check("M4 L1 Medium verify shards stay in the fast lane (<=8)",
          max(med_sizes) <= 8,
          repr(non_empty))
    # Low spreads to ~5/shard (17 findings / 4 = 5 shards over 4 slots)
    # instead of the old ~17/shard near-timeout lane.
    check("M4 L1 Low verify shards stay in the fast lane (<=5)",
          max(low_sizes) <= 5,
          repr(non_empty))
    # Heavy tiers produce MORE shards (negative control: spread, not cram).
    check("M4 L1 verify shard count is bounded and balanced",
          len(non_empty) == 20 and min(non_empty.values()) >= 4,
          repr(non_empty))
    check("M4 L1 verify shard total preserves queue",
          sum(non_empty.values()) == 145,
          repr(non_empty))


def test_M4b_sc_high_verify_shards_are_small_enough_for_thorough():
    rows = [
        "| Queue # | Finding ID | Severity | Title | Bug Class | Preferred Tag | Location | Primary Artifact |",
        "|---------|------------|----------|-------|-----------|---------------|----------|------------------|",
    ]
    for i in range(1, 14):
        sev = "Critical" if i == 1 else "High"
        rows.append(
            f"| {i} | INV-{i:03d} | {sev} | H{i} | access | [CODE-TRACE] | src/A.sol:L{i} | depth.md |"
        )
    sp = _mkscratch({"verification_queue.md": "\n".join(rows)})
    shards = D.compute_sc_verify_shards(sp)
    non_empty = {k: len(v) for k, v in shards.items() if v}
    ch_sizes = [
        len(shards[name]) for name in D.SC_VERIFY_CRITHIGH_PHASE_NAMES
        if shards.get(name)
    ]
    # Uniform per-shard target (VERIFY_TARGET_PER_SHARD=4): 13 C/H findings
    # spread across 4 shards (4,3,3,3) -> max 4, still the fast lane.
    check("M4b SC C/H verify shards cap live 13-item queue at <= target",
          max(ch_sizes) <= D.VERIFY_TARGET_PER_SHARD,
          repr(non_empty))
    check("M4b SC C/H verify shards preserve all rows",
          sum(ch_sizes) == 13,
          repr(non_empty))


def _build_skewed_queue(counts: dict[str, int]) -> str:
    """Build a verification_queue.md with the given per-severity finding counts."""
    header = [
        "| Queue # | Finding ID | Severity | Title | Bug Class | Preferred Tag | Location | Primary Artifact |",
        "|---------|------------|----------|-------|-----------|---------------|----------|------------------|",
    ]
    rows = []
    q = 1
    prefix = {"Critical": "C", "High": "H", "Medium": "M", "Low": "L", "Informational": "I"}
    for sev, n in counts.items():
        for i in range(1, n + 1):
            fid = f"{prefix[sev]}-{i:03d}"
            rows.append(
                f"| {q} | {fid} | {sev} | T{q} | logic | [CODE-TRACE] | src/A.sol:L{q} | depth.md |"
            )
            q += 1
    return "\n".join(header + rows)


def test_M4h_sc_verify_shard_partition_complete_and_disjoint():
    """ROOT FIX: every finding lands in EXACTLY ONE shard (complete + disjoint)
    on a live-like skewed distribution (1C / 18H / 30M / 37L / 13I)."""
    counts = {"Critical": 1, "High": 18, "Medium": 30, "Low": 37, "Informational": 13}
    sp = _mkscratch({"verification_queue.md": _build_skewed_queue(counts)})
    queue_rows = D.parse_verification_queue_rows(sp)
    queue_ids = [r.get("finding id") for r in queue_rows]
    shards = D.compute_sc_verify_shards(sp)

    sharded_ids = [
        r.get("finding id")
        for rows_in in shards.values()
        for r in rows_in
    ]
    # Completeness: every queued finding is assigned to some shard.
    check("M4h every finding is assigned (complete)",
          set(sharded_ids) == set(queue_ids),
          f"queue={len(set(queue_ids))} sharded={len(set(sharded_ids))}")
    # Disjoint: no finding appears in two shards, and the total count matches.
    check("M4h no finding is duplicated (disjoint)",
          len(sharded_ids) == len(set(sharded_ids)) == len(queue_ids),
          f"sharded={len(sharded_ids)} unique={len(set(sharded_ids))} queue={len(queue_ids)}")
    # Every returned shard name exists in all four registries (slot contract).
    for name in shards:
        check(f"M4h {name} is a registered shard name",
              name in D.SC_VERIFY_SHARD_MANIFESTS,
              name)
    # Fast-lane assertion: no non-empty shard exceeds TARGET_PER_SHARD+1.
    target = D.VERIFY_TARGET_PER_SHARD
    for name, rows_in in shards.items():
        if rows_in:
            check(f"M4h {name} stays in the fast lane (<= target+1)",
                  len(rows_in) <= target + 1,
                  f"{name}={len(rows_in)} target={target}")


def test_M4i_sc_verify_shards_spread_heavy_tiers_not_overshard_light():
    """Negative control: a heavy tier produces MORE shards (spread, not cram);
    a light tier does NOT over-shard."""
    # Heavy: 36 Low findings -> ceil(36/4)=9 Low shards (spread).
    heavy = _mkscratch({"verification_queue.md": _build_skewed_queue({"Low": 36})})
    heavy_shards = D.compute_sc_verify_shards(heavy)
    low_used = [n for n, v in heavy_shards.items()
                if n.startswith("sc_verify_low") and v]
    check("M4i heavy Low tier spreads across many shards (>=8)",
          len(low_used) >= 8,
          f"low_used={len(low_used)}")
    check("M4i heavy Low shards stay small (<=5 each)",
          max(len(heavy_shards[n]) for n in low_used) <= 5,
          {n: len(heavy_shards[n]) for n in low_used})

    # Light: 2 Medium findings -> only 1 Medium shard used (no over-shard).
    light = _mkscratch({"verification_queue.md": _build_skewed_queue({"Medium": 2})})
    light_shards = D.compute_sc_verify_shards(light)
    med_used = [n for n, v in light_shards.items()
                if n.startswith("sc_verify_medium") and v]
    check("M4i light Medium tier does NOT over-shard (1 shard)",
          len(med_used) == 1,
          f"med_used={med_used}")
    check("M4i light Medium shard holds all findings",
          len(light_shards[med_used[0]]) == 2,
          light_shards[med_used[0]])


def test_M4c_stale_verify_retry_hint_cleared_after_reshard():
    sp = _mkscratch({
        "sc_verify_high_b_retry_hint.md": (
            "Previous shard was missing INV-109 and INV-110.\n"
        )
    })
    assigned = [
        {"finding id": "INV-091"},
        {"finding id": "INV-098"},
        {"finding id": "INV-099"},
    ]
    cleared = D._clear_stale_verify_retry_hint_after_reshard(
        sp, "sc_verify_high_b", assigned,
    )
    check("M4c stale verify retry hint is cleared when IDs moved shards",
          cleared and not (sp / "sc_verify_high_b_retry_hint.md").exists(),
          (sp / "sc_verify_high_b_retry_hint.md").read_text(encoding="utf-8")
          if (sp / "sc_verify_high_b_retry_hint.md").exists() else "")


def test_M4d_semantic_dedup_passthrough_with_pairs_is_not_complete():
    sp = _mkscratch({
        "dedup_candidate_pairs.md": (
            "| Finding A | Finding B | Title Score | Signal(s) | Same Sev? |\n"
            "|-----------|-----------|-------------|-----------|-----------|\n"
            "| INV-001 | INV-002 | 0.90 | location overlap | Yes |\n"
        ),
        "dedup_decisions.md": (
            "# Semantic Dedup Decisions\n\n"
            "**Status**: PASSTHROUGH\n\n"
            "pre-run passthrough safety net\n"
        ),
    })
    issue = D._semantic_dedup_passthrough_issue(sp)
    check("M4d semantic dedup passthrough with live pairs is incomplete",
          bool(issue) and "PASSTHROUGH unchanged" in issue,
          repr(issue))


def test_M4e_semantic_dedup_prompt_overrides_passthrough_resumption(tmp_path: Path):
    project = tmp_path / "proj"
    scratch = project / ".scratchpad"
    scratch.mkdir(parents=True)
    phase = next(p for p in D.L1_PHASES if p.name == "semantic_dedup")
    v1 = tmp_path / "fake_l1.md"
    v1.write_text("# fake\n", encoding="utf-8")
    prompt = D.build_phase_prompt(v1, phase, {
        "mode": "thorough",
        "project_root": str(project),
        "scratchpad": str(scratch),
        "pipeline": "l1",
        "language": "go",
        "docs_path": "",
        "scope_file": "",
        "scope_notes": "",
        "subsystem_scope": "",
        "proven_only": False,
    })
    check("M4e semantic dedup prompt says passthrough is not complete",
          "PASSTHROUGH" in prompt and "crash-safety net, not a completed phase result" in prompt,
          prompt[:500])


def test_M4f_verify_queue_parity_accepts_semantic_dedup_absorbed_ids():
    sp = _mkscratch({
        "findings_inventory.md": (
            "# Findings Inventory\n\n"
            "## Finding [INV-010]: duplicate hash bug\n"
            "**Severity**: High\n"
            "**Location**: crates/vdf/src/lib.rs:L10\n\n"
            "## Finding [INV-011]: survivor hash bug\n"
            "**Severity**: High\n"
            "**Location**: crates/vdf/src/lib.rs:L20\n"
        ),
        "verification_queue.md": (
            "| Queue # | Finding ID | Severity | Title | Bug Class | Preferred Tag | Location | Primary Artifact |\n"
            "|---------|------------|----------|-------|-----------|---------------|----------|------------------|\n"
            "| 1 | INV-011 | High | survivor | vdf | CODE-TRACE | crates/vdf/src/lib.rs:L20 | dedup.md |\n"
        ),
        "dedup_decisions.md": (
            "# Semantic Dedup Decisions\n\n"
            "### MERGE: INV-011 absorbs INV-010\n\n"
            "## Dedup Status Table\n"
            "| Finding ID | Status | Notes |\n"
            "|------------|--------|-------|\n"
            "| INV-010 | MERGED into INV-011 | same root cause |\n"
        ),
    })
    issues = D._validate_verification_queue_inventory_parity(sp)
    check("M4f semantic-dedup absorbed IDs satisfy queue parity",
          issues == [],
          repr(issues))


def test_M4g_verify_queue_parity_still_flags_missing_pass_ids():
    sp = _mkscratch({
        "findings_inventory.md": (
            "# Findings Inventory\n\n"
            "## Finding [INV-010]: missing pass bug\n"
            "**Severity**: High\n"
            "**Location**: crates/vdf/src/lib.rs:L10\n\n"
            "## Finding [INV-011]: survivor hash bug\n"
            "**Severity**: High\n"
            "**Location**: crates/vdf/src/lib.rs:L20\n"
        ),
        "verification_queue.md": (
            "| Queue # | Finding ID | Severity | Title | Bug Class | Preferred Tag | Location | Primary Artifact |\n"
            "|---------|------------|----------|-------|-----------|---------------|----------|------------------|\n"
            "| 1 | INV-011 | High | survivor | vdf | CODE-TRACE | crates/vdf/src/lib.rs:L20 | dedup.md |\n"
        ),
        "dedup_decisions.md": (
            "# Semantic Dedup Decisions\n\n"
            "## Dedup Status Table\n"
            "| Finding ID | Status | Notes |\n"
            "|------------|--------|-------|\n"
            "| INV-010 | PASS | unchanged |\n"
        ),
    })
    issues = D._validate_verification_queue_inventory_parity(sp)
    check("M4g semantic-dedup PASS IDs must remain queued",
          any("INV-010" in issue for issue in issues),
          repr(issues))


def test_M4h_report_index_prompt_examples_use_non_copyable_placeholder_ids():
    prompt = (SCRIPTS_DIR.parent / "rules" / "phase6-report-prompts.md").read_text(encoding="utf-8")
    bad_examples = [
        "| C-01 | [title] | Critical | [location] | VERIFIED | - | H-1 |",
        "| H-01 | [title] | High | [location] | VERIFIED | - | H-2 |",
        "| M-01 | [title] | Medium | [location] | UNVERIFIED | TRUSTED-ACTOR(High) | H-18 |",
    ]
    check("M4h report-index examples avoid real hypothesis IDs",
          all(row not in prompt for row in bad_examples)
          and "<critical-internal-id>" in prompt
          and "Example rows use placeholders only" in prompt,
          prompt[prompt.find("## Master Finding Index"):prompt.find("## Tier Assignments")])


def test_M5_report_index_recovery_promotes_missing_confirmed():
    sp = _mkscratch({
        "report_index.md": (
            "# Report Index\n\n"
            "## Master Finding Index\n"
            "| Report ID | Title | Severity | Internal Hypothesis ID |\n"
            "|-----------|-------|----------|------------------------|\n"
            "| H-01 | Existing | High | INV-002 |\n\n"
            "## Excluded Findings\n"
            "| Internal ID | Verdict | Reason |\n"
            "|-------------|---------|--------|\n"
        ),
        "verification_queue.md": (
            "| Queue # | Finding ID | Severity | Title | Bug Class | Preferred Tag | Location | Primary Artifact |\n"
            "|---------|------------|----------|-------|-----------|---------------|----------|------------------|\n"
            "| 1 | INV-001 | High | Missing index finding | consensus | [CODE-TRACE] | crates/a.rs:L10 | depth.md |\n"
            "| 2 | INV-002 | High | Existing | consensus | [CODE-TRACE] | crates/b.rs:L20 | depth.md |\n"
        ),
        "verify_INV-001.md": (
            "## Finding [INV-001]: Missing index finding\n"
            "**Severity**: High\n"
            "**Location**: crates/a.rs:L10\n"
            "**Verdict**: CONFIRMED\n"
            "**Evidence Tag**: CODE-TRACE\n"
        ),
        "verify_INV-002.md": (
            "## Finding [INV-002]: Existing\n"
            "**Severity**: High\n"
            "**Verdict**: CONFIRMED\n"
        ),
    })
    before = D._check_index_completeness(sp)
    repaired = D._repair_report_index_dropouts(sp)
    after = D._check_index_completeness(sp)
    text = (sp / "report_index.md").read_text(encoding="utf-8")
    assignments = D.parse_report_index_assignments(sp)
    check("M5 report_index recovery detects missing confirmed first",
          any("index dropout" in s for s in before),
          repr(before))
    check("M5 report_index recovery adds active assignment",
          repaired == ["INV-001"]
          and not after
          and any(a.get("finding_id") == "INV-001" for a in assignments),
          f"repaired={repaired}, after={after}, assignments={assignments}, text={text}")
    check("M5 report_index recovery does not blanket false-positive",
          "INV-001 | FALSE_POSITIVE" not in text,
          text)


def test_M6_inventory_evidence_validation_and_queue_filter():
    root = Path(tempfile.mkdtemp(prefix="plamen_proj_"))
    src = root / "crates" / "real" / "src"
    src.mkdir(parents=True)
    (src / "lib.rs").write_text("fn a() {}\nfn b() {}\n", encoding="utf-8")
    sp = _mkscratch({
        "analysis_01.md": "### Finding [A-1]: real\n**Location**: crates/real/src/lib.rs:L2\n",
        "findings_inventory.md": (
            "### Finding [INV-001]: recoverable basename\n"
            "**Source IDs**: [A-1]\n"
            "**Severity**: High\n"
            "**Location**: lib.rs:L2\n"
            "**Preferred Tag**: CODE-TRACE\n\n"
            "### Finding [INV-002]: phantom\n"
            "**Source IDs**: [missing.md:nope]\n"
            "**Severity**: High\n"
            "**Location**: ghost.rs:L1\n"
            "**Preferred Tag**: CODE-TRACE\n"
        ),
        "verification_queue.md": (
            "| Queue # | Finding ID | Severity | Title | Bug Class | Preferred Tag | Location | Primary Artifact |\n"
            "|---------|------------|----------|-------|-----------|---------------|----------|------------------|\n"
            "| 1 | INV-001 | High | recoverable | consensus | [CODE-TRACE] | lib.rs:L2 | analysis_01.md |\n"
            "| 2 | INV-002 | High | phantom | consensus | [CODE-TRACE] | ghost.rs:L1 | missing.md |\n"
        ),
    })
    records = D._validate_inventory_evidence(sp, str(root))
    inv = (sp / "findings_inventory.md").read_text(encoding="utf-8")
    removed = D._filter_verification_queue_by_evidence(sp)
    queue = (sp / "verification_queue.md").read_text(encoding="utf-8")
    check("M6 inventory evidence validation recovers unique basename",
          records["INV-001"]["location_status"] == "RECOVERED_BASENAME"
          and "crates/real/src/lib.rs:L2" in inv,
          f"records={records}, inv={inv}")
    debt = (sp / "verification_queue_evidence_debt.md").read_text(encoding="utf-8")
    check("M6 queue filter retains invalid evidence as explicit repair debt",
          removed == []
          and "INV-001" in queue
          and "INV-002" in queue
          and "LOCATION_INVALID" in queue
          and "INV-002" in debt,
          f"removed={removed}, queue={queue}")


def test_M7_mechanical_report_index_keeps_unproven_negative_visible():
    sp = _mkscratch({
        "verification_queue.md": (
            "| Queue # | Finding ID | Severity | Title | Bug Class | Preferred Tag | Location | Primary Artifact |\n"
            "|---------|------------|----------|-------|-----------|---------------|----------|------------------|\n"
            "| 1 | INV-001 | High | real bug | consensus | [CODE-TRACE] | crates/a.rs:L1 | depth.md |\n"
            "| 2 | INV-002 | High | fake bug | consensus | [CODE-TRACE] | crates/b.rs:L1 | depth.md |\n"
        ),
        "verify_INV-001.md": (
            "## Finding [INV-001]: real bug\n"
            "**Severity**: High\n"
            "**Impact**: High\n**Likelihood**: Medium\n"
            "**Verdict**: CONFIRMED\n"
            "**Evidence Tag**: CODE-TRACE\n"
        ),
        "verify_INV-002.md": (
            "## Finding [INV-002]: fake bug\n"
            "**Severity**: High\n"
            "**Impact**: High\n**Likelihood**: Medium\n"
            "**Verdict**: FALSE_POSITIVE\n"
            "**Evidence Tag**: CODE-TRACE\n"
        ),
    })
    active = D._write_mechanical_report_index(sp)
    assignments = D.parse_report_index_assignments(sp)
    idx = (sp / "report_index.md").read_text(encoding="utf-8")
    count = D._write_mechanical_report_tier(sp, "report_critical_high")
    tier = (sp / "report_critical_high.md").read_text(encoding="utf-8")
    check("M7 verifier negative is a proposal, not report-removal authority",
          active == 2
          and any(a.get("finding_id") == "INV-001" for a in assignments)
          and any(a.get("finding_id") == "INV-002" for a in assignments)
          and "UNPROVEN_NEGATIVE(FALSE_POSITIVE)" in idx
          and "Proposed Negative Dispositions (Non-authoritative)" in idx,
          f"active={active}, assignments={assignments}, idx={idx}")
    check("M7 mechanical tier writer visibly retains disputed candidate",
          count == 2 and "real bug" in tier and "fake bug" in tier
          and "FALSE_POSITIVE" in tier
          and "UNRESOLVED - needs human review" in tier,
          tier)


def test_M8_messy_formats_are_tolerated_without_dropping_leads():
    root = Path(tempfile.mkdtemp(prefix="plamen_proj_fmt_"))
    src = root / "crates" / "p2p" / "src"
    src.mkdir(parents=True)
    (src / "gossip.rs").write_text("fn handler() {}\n", encoding="utf-8")
    sp = _mkscratch({
        "weird_source.md": "# Merkle Validation Finding\nThis discusses merkle validation logic.\n",
        "findings_inventory.md": (
            "### [INV-001] messy valid lead\n"
            "**Source IDs** - weird_source.md#merkle-validation\n"
            "**Severity** - High\n"
            "**Location** - file: crates/p2p/src/gossip.rs line 1\n"
            "**Preferred Tag** - CODE-TRACE\n\n"
            "## Finding ID: [INV-002] - freeform provenance with location\n"
            "**Source IDs**: graph sweep note\n"
            "**Severity**: Medium\n"
            "**Location**: crates/p2p/src/gossip.rs#L1\n"
            "**Preferred Tag**: CODE-TRACE\n"
        ),
        "verification_queue.md": (
            "| Queue # | Finding ID | Severity | Title | Bug Class | Preferred Tag | Location | Primary Artifact |\n"
            "|---------|------------|----------|-------|-----------|---------------|----------|------------------|\n"
            "| 1 | [INV-001](verify_INV-001.md) | High | messy | p2p | [CODE-TRACE] | crates/p2p/src/gossip.rs line 1 | weird_source.md |\n"
            "| 2 | `INV-002` | Medium | freeform | p2p | [CODE-TRACE] | crates/p2p/src/gossip.rs#L1 | weird_source.md |\n"
        ),
        "verify_INV-001.md": (
            "## Finding [INV-001]\n"
            "**Status** - true positive with caveats\n"
            "**Severity** - High\n"
            "**Evidence** - CODE-TRACE\n"
        ),
        "verify_INV-002.md": (
            "## Finding [INV-002]\n"
            "**Final Verdict** = false positive\n"
            "**Severity** = Medium\n"
            "**Evidence Tags** = CODE-TRACE\n"
        ),
    })
    records = D._validate_inventory_evidence(sp, str(root))
    removed = D._filter_verification_queue_by_evidence(sp)
    active = D._write_mechanical_report_index(sp)
    idx = (sp / "report_index.md").read_text(encoding="utf-8")
    check("M8 messy location/source formats remain verifiable",
          not removed
          and records["INV-001"]["location_status"] == "OK"
          and records["INV-002"]["source_status"] == "SOURCE_UNVERIFIED",
          f"removed={removed}, records={records}")
    check("M8 status/final-verdict aliases preserve negative proposals",
          active == 2
          and "INV-001" in idx
          and "INV-002" in idx
          and "UNPROVEN_NEGATIVE(FALSE_POSITIVE)" in idx,
          idx)


def test_M9_mechanical_inventory_merge_preserves_chunk_source_ids():
    sp = _mkscratch({
        "findings_inventory_chunk_a.md": (
            "### Finding [CA-01]: first bug\n"
            "**Severity**: High\n"
            "**Location**: crates/a.rs:L1\n"
            "**Source IDs**: CF1-1, PA1-2\n"
            "**Preferred Tag**: CODE-TRACE\n"
            "**Description**: concrete issue\n"
        ),
        "findings_inventory_chunk_b.md": (
            "### Finding [CB-02]: second bug\n"
            "**Severity**: Medium\n"
            "**Location**: crates/b.rs:L2\n"
            "**Source IDs**: CF2-7\n"
            "**Preferred Tag**: CODE-TRACE\n"
            "**Description**: another concrete issue\n"
        ),
    })
    parsed, merged = D._write_mechanical_inventory_from_chunks(sp)
    issues = D._validate_inventory_parity(sp)
    inv = (sp / "findings_inventory.md").read_text(encoding="utf-8")
    review = D._reconcile_exact_inventory(sp, persist=False)
    debt = {
        row["source_finding_id"]
        for row in review["candidates"]
        if row["disposition"] == "HUMAN_REVIEW_DEBT"
    }
    check("M9 mechanical inventory merge retains exact review debt",
          parsed == 2
          and merged == 2
          and debt == {"CA-01", "CB-02"}
          and any("2/2 raw discovery identity(s)" in issue for issue in issues),
          f"parsed={parsed}, merged={merged}, issues={issues}, inv={inv}")
    check("M9 mechanical inventory preserves source IDs",
          all(
              tok in inv
              for tok in ("CF1-1", "PA1-2", "CA-01", "CF2-7", "CB-02")
          ),
          inv)


def test_M9b_inventory_merge_does_not_overcut_same_location_sibling_bugs():
    sp = _mkscratch({
        "findings_inventory_chunk_a.md": (
            "### Finding [A-1]: Early loop termination accepts missing sys-tx\n"
            "**Severity**: Critical\n"
            "**Location**: crates/actors/src/block_validation.rs:L598\n"
            "**Source IDs**: A-1\n"
            "**Preferred Tag**: CODE-TRACE\n"
            "**Root Cause**: loop exits before checking all expected transactions\n\n"
            "### Finding [A-2]: Extra sys-tx accepted by >= length check\n"
            "**Severity**: Critical\n"
            "**Location**: crates/actors/src/block_validation.rs:L598\n"
            "**Source IDs**: A-2\n"
            "**Preferred Tag**: CODE-TRACE\n"
            "**Root Cause**: loop exits before checking all expected transactions\n"
        ),
    })
    parsed, merged = D._write_mechanical_inventory_from_chunks(sp)
    inv = (sp / "findings_inventory.md").read_text(encoding="utf-8")
    check("M9b inventory merge keeps same-location sibling bugs separate",
          parsed == 2 and merged == 2 and "A-1" in inv and "A-2" in inv,
          f"parsed={parsed}; merged={merged}; inv={inv!r}")


def test_M10_mechanical_verify_queue_routes_every_inventory_id():
    sp = _mkscratch({
        "findings_inventory.md": (
            "# Inventory\n\n"
            "### Finding [INV-001]: critical bug\n"
            "**Source IDs**: [ATT-1]\n"
            "**Severity**: Critical\n"
            "**Location**: crates/a/src/lib.rs:L10\n"
            "**Preferred Tag**: POC-PASS\n"
            "**Root Cause**: missing validation\n\n"
            "### Finding [INV-002]: high bug\n"
            "**Source IDs**: [DCI-3]\n"
            "**Severity**: High\n"
            "**Location**: crates/b/src/lib.rs:L20\n\n"
            "### Finding [INV-003]: low bug\n"
            "**Source IDs**: [CF1-7]\n"
            "**Severity**: Low\n"
            "**Location**: crates/c/src/lib.rs:L30\n"
        ),
    })
    routed = D._write_mechanical_verification_queue_from_inventory(sp)
    shards = D.ensure_verify_shard_manifests(sp)
    rows = D.parse_verification_queue_rows(sp)
    issues = D._validate_verification_queue_inventory_parity(sp)
    ids = {r["finding id"] for r in rows}
    shard_ids = {
        r["finding id"]
        for shard_rows in shards.values()
        for r in shard_rows
    }
    check("M10 mechanical verify queue preserves all inventory IDs",
          routed == 3
          and ids == {"INV-001", "INV-002", "INV-003"}
          and shard_ids == ids
          and issues == [],
          f"routed={routed}, ids={ids}, shard_ids={shard_ids}, issues={issues}")


def test_M11_verify_queue_parity_flags_dropped_inventory_ids():
    sp = _mkscratch({
        "findings_inventory.md": (
            "# Inventory\n\n"
            "### Finding [INV-001]: first\n"
            "**Severity**: High\n"
            "**Location**: crates/a/src/lib.rs:L1\n\n"
            "### Finding [INV-002]: second\n"
            "**Severity**: Medium\n"
            "**Location**: crates/b/src/lib.rs:L2\n"
        ),
        "verification_queue.md": (
            "| Queue # | Finding ID | Severity | Title | Bug Class | Preferred Tag | Location | Primary Artifact |\n"
            "|---------|------------|----------|-------|-----------|---------------|----------|------------------|\n"
            "| 1 | INV-001 | High | first | class | CODE-TRACE | crates/a/src/lib.rs:L1 | findings_inventory.md |\n"
        ),
    })
    issues = D._validate_verification_queue_inventory_parity(sp)
    check("M11 verification queue parity rejects dropped inventory IDs",
          any("INV-002" in issue and "dropout" in issue for issue in issues),
          repr(issues))


def test_M12_verify_queue_parity_hypothesis_aware_expansion():
    """M12: proposal-only grouping cannot replace independent queue work.

    P0-W deliberately removed Markdown grouping as coverage authority.  A
    multi-member H-N proposal must not acknowledge its INV-NNN constituents;
    only independently routed member rows close queue parity.
    """
    sp = _mkscratch({
        "findings_inventory.md": (
            "# Inventory\n\n"
            "### Finding [INV-001]: reentrancy in withdraw\n"
            "**Severity**: High\n"
            "**Location**: src/vault.sol:L45\n\n"
            "### Finding [INV-002]: missing access control on setFee\n"
            "**Severity**: Medium\n"
            "**Location**: src/vault.sol:L80\n\n"
            "### Finding [INV-003]: unchecked return in transfer\n"
            "**Severity**: High\n"
            "**Location**: src/router.sol:L20\n"
        ),
        # finding_mapping.md maps INV-001 and INV-002 to H-1, INV-003 to H-2
        "finding_mapping.md": (
            "# Finding Mapping\n\n"
            "| Finding ID | Hypothesis | Title |\n"
            "|------------|-----------|-------|\n"
            "| INV-001 | H-1 | reentrancy in withdraw |\n"
            "| INV-002 | H-1 | missing access control on setFee |\n"
            "| INV-003 | H-2 | unchecked return in transfer |\n"
        ),
        # Post-dedup queue: H-1 and H-2 (not INV-NNN)
        "verification_queue.md": (
            "| Queue # | Finding ID | Severity | Title | Bug Class | Preferred Tag | Location | Primary Artifact |\n"
            "|---------|------------|----------|-------|-----------|---------------|----------|------------------|\n"
            "| 1 | H-1 | High | reentrancy in withdraw | reentrancy | CODE-TRACE | src/vault.sol:L45 | findings_inventory.md |\n"
            "| 2 | H-2 | High | unchecked return in transfer | unchecked-return | CODE-TRACE | src/router.sol:L20 | findings_inventory.md |\n"
        ),
    })
    issues = D._validate_verification_queue_inventory_parity(sp)
    check("M12a proposal-only H-N grouping cannot acknowledge constituents",
          any("INV-001" in issue and "dropout" in issue for issue in issues)
          and any("H-1" in issue and "not present in inventory" in issue for issue in issues),
          repr(issues))

    # P0-W active identity is every exact member.  Once the independent rows
    # are routed, parity is exact and does not depend on the proposal aliases.
    (sp / "verification_queue.md").write_text(
        "| Queue # | Finding ID | Severity | Title | Bug Class | Preferred Tag | Location | Primary Artifact |\n"
        "|---------|------------|----------|-------|-----------|---------------|----------|------------------|\n"
        "| 1 | INV-001 | High | reentrancy in withdraw | reentrancy | CODE-TRACE | src/vault.sol:L45 | findings_inventory.md |\n"
        "| 2 | INV-002 | Medium | missing access control | access | CODE-TRACE | src/vault.sol:L80 | findings_inventory.md |\n"
        "| 3 | INV-003 | High | unchecked return | unchecked-return | CODE-TRACE | src/router.sol:L20 | findings_inventory.md |\n",
        encoding="utf-8",
    )
    issues_independent = D._validate_verification_queue_inventory_parity(sp)
    check("M12b independent member routing closes exact parity",
          issues_independent == [], repr(issues_independent))

    # Now test the partial-coverage case: remove one independent member.
    (sp / "verification_queue.md").write_text(
        "| Queue # | Finding ID | Severity | Title | Bug Class | Preferred Tag | Location | Primary Artifact |\n"
        "|---------|------------|----------|-------|-----------|---------------|----------|------------------|\n"
        "| 1 | INV-001 | High | reentrancy in withdraw | reentrancy | CODE-TRACE | src/vault.sol:L45 | findings_inventory.md |\n"
        "| 2 | INV-002 | Medium | missing access control | access | CODE-TRACE | src/vault.sol:L80 | findings_inventory.md |\n",
        encoding="utf-8",
    )
    issues2 = D._validate_verification_queue_inventory_parity(sp)
    check("M12c parity flags an independently missing INV-003",
          any("INV-003" in i and "dropout" in i for i in issues2),
          repr(issues2))


# --------------------------------------------------------------------------
# v2.4.9 Regression Tests: Format Consistency Audit Fixes
# --------------------------------------------------------------------------

def test_V249_P51_index_completeness_retry_hint_uses_norm_indexed():
    """P5-1 HIGH: _check_index_completeness retry hint references len(norm_indexed) not len(indexed)."""
    import plamen_validators as V
    sp = _mkscratch({
        # Two verify files on disk
        "verify_H-1.md": "## Hypothesis H-1\nVerdict: CONFIRMED\n",
        "verify_H-2.md": "## Hypothesis H-2\nVerdict: CONFIRMED\n",
        # report_index.md only includes H-1, missing H-2
        "report_index.md": (
            "## Master Finding Index\n"
            "| Report ID | Title | Severity | Location | Verification | Trust Adj. | Internal Hypothesis |\n"
            "|-----------|-------|----------|----------|--------------|------------|--------------------|\n"
            "| H-01 | Bug A | High | a.sol:L1 | VERIFIED | - | H-1 |\n\n"
            "## Excluded Findings\n"
            "| Internal ID | Severity | Title | Exclusion Reason |\n"
            "|-------------|----------|-------|------------------|\n"
        ),
    })
    issues = V._check_index_completeness(sp, str(sp))
    # Should have flagged H-2 as dropped
    check("V249-P51a completeness detects dropped H-2",
          any("H-2" in i for i in issues), repr(issues))
    hint = sp / "report_index_retry_hint.md"
    check("V249-P51b observational validation writes no retry hint",
          not hint.exists(), "observational validator wrote a retry hint")

    published_issues = V._check_index_completeness(
        sp,
        str(sp),
        write_retry_hint=True,
    )
    check("V249-P51c explicit retry publication preserves the dropout",
          published_issues == issues and any("H-2" in i for i in published_issues),
          repr(published_issues))
    check("V249-P51d explicit retry publication writes the hint",
          hint.exists(), "hint file missing")
    if hint.exists():
        body = hint.read_text(encoding="utf-8")
        check("V249-P51e hint references norm_indexed count (1)",
              "indexed 1 hypothesis" in body, body[:200])


def test_V249_P43_depth_evidence_tag_regex_covers_all_tags():
    """P4-3 MED: _DEPTH_EVIDENCE_TAG_RE matches PERTURBATION, CROSS-DOMAIN-DEP, MEDUSA-PASS."""
    from plamen_parsers import _DEPTH_EVIDENCE_TAG_RE
    must_match = [
        "[BOUNDARY:X=0]",
        "[VARIATION:decimals 18->6]",
        "[TRACE:path->outcome]",
        "[REGRESS:symptom->cause]",
        "[PERTURBATION:DIRECTION_FLIP]",
        "[NON-DET: map iteration]",
        "[PRE-AUTH-PANIC: unmarshal]",
        "[ASYMMETRIC: cost ratio]",
        "[SCORE-DRAIN: peer]",
        "[REORG-DIVERGE: block 100]",
        "[DECODE-UNBOUNDED: varint]",
        "[CROSS-DOMAIN-DEP: external]",
        "[MEDUSA-PASS: invariant violated]",
    ]
    for tag in must_match:
        m = _DEPTH_EVIDENCE_TAG_RE.search(tag)
        check(f"V249-P43 tag regex matches '{tag[:25]}'",
              m is not None, f"no match for {tag}")


def test_V249_P45_fid_allowed_prefixes_covers_niche_agents():
    """P4-5 MED: _FID_ALLOWED_PREFIXES includes niche agent prefixes (GOV, NFT, BLS, etc.)."""
    from plamen_parsers import _FID_ALLOWED_PREFIXES, _extract_finding_ids_from_text
    # Niche prefixes from _ID_NICHE_ALTS that should now be recognized
    niche_samples = ["GOV", "NFT", "BLS", "DEX", "LEND", "P2P", "RPC", "SIG", "EVT"]
    for pfx in niche_samples:
        check(f"V249-P45a prefix '{pfx}' in allowed set",
              pfx in _FID_ALLOWED_PREFIXES, f"missing: {pfx}")
    # End-to-end: extract niche IDs from text
    text = "Found [GOV-1] governance attack, [NFT-2] reentrancy, and [BLS-3] aggregation bug."
    ids = _extract_finding_ids_from_text(text)
    check("V249-P45b GOV-1 extracted", "GOV-1" in ids, repr(ids))
    check("V249-P45c NFT-2 extracted", "NFT-2" in ids, repr(ids))
    check("V249-P45d BLS-3 extracted", "BLS-3" in ids, repr(ids))
    # Negative: non-finding prefixes like OZ-4626 should NOT be extracted
    text2 = "Implements OZ-4626 and WETH-9 standards"
    ids2 = _extract_finding_ids_from_text(text2)
    check("V249-P45e non-finding prefix OZ-4626 NOT extracted", "OZ-4626" not in ids2, repr(ids2))


def test_V249_P42_hypo_heading_re_matches_l1_ids():
    """P4-2 MED: _HYPO_HEADING_RE matches L1 hypothesis headings (H-C01, L1-C-01)."""
    from plamen_parsers import _HYPO_HEADING_RE
    # Standard SC hypothesis headings (must still work)
    sc_cases = [
        ("## Hypothesis H-1", "H-1"),
        ("### H-5", "H-5"),
        ("## Chain Hypothesis CH-3", "CH-3"),
    ]
    for text, expected in sc_cases:
        m = _HYPO_HEADING_RE.search(text)
        check(f"V249-P42a SC '{expected}' matches",
              m is not None and m.group(1).upper() == expected.upper(),
              f"got {m.group(1) if m else 'None'}")
    # L1 compound hypothesis headings
    l1_cases = [
        ("## Hypothesis H-C01", "H-C01"),
        ("### H-M27", "H-M27"),
        ("## H-L07", "H-L07"),
        ("## Hypothesis L1-C-01", "L1-C-01"),
        ("### L1-H-05", "L1-H-05"),
    ]
    for text, expected in l1_cases:
        m = _HYPO_HEADING_RE.search(text)
        check(f"V249-P42b L1 '{expected}' matches",
              m is not None and m.group(1).upper() == expected.upper(),
              f"got {m.group(1) if m else 'None'}")


def test_V249_P44_quality_gate_leak_check_catches_niche_ids():
    """P4-4 LOW-MED: quality gate internal ID leak check catches niche agent IDs."""
    from plamen_parsers import _ID_ALL_NONHYPO
    import re
    # Simulate the leak check logic from _report_quality_gate
    pattern = rf"\b(?:{_ID_ALL_NONHYPO})\b"
    test_body = (
        "## High Findings\n\n"
        "### [H-01] Some bug\nDescription: Found via GOV-1 analysis and BLS-3 check.\n"
        "Also referenced SLITHER-5 and DEPTH-TF-2 internally.\n"
    )
    hits = re.findall(pattern, test_body)
    check("V249-P44a catches GOV-1", any("GOV-1" in h for h in hits), repr(hits))
    check("V249-P44b catches BLS-3", any("BLS-3" in h for h in hits), repr(hits))
    check("V249-P44c catches SLITHER-5", any("SLITHER-5" in h for h in hits), repr(hits))
    check("V249-P44d catches DEPTH-TF-2", any("DEPTH-TF-2" in h for h in hits), repr(hits))
    # Report IDs should NOT be caught (H-01, M-03)
    clean_body = "### [H-01] Some bug\n### [M-03] Another bug\n"
    clean_hits = re.findall(pattern, clean_body)
    check("V249-P44e H-01 not caught as leak", len(clean_hits) == 0, repr(clean_hits))


def test_V249_P01_chain_agent2_phase_in_sc_phases():
    """P0-1: chain_agent2 phase exists in SC_PHASES and maps to correct prompt file."""
    from plamen_types import SC_PHASES
    from plamen_prompt import _STANDALONE_PROMPT_MAP
    phase_names = [p.name for p in SC_PHASES]
    check("V249-P01a chain_agent2 in SC_PHASES",
          "chain_agent2" in phase_names, repr(phase_names))
    # chain_agent2 must come AFTER chain
    if "chain" in phase_names and "chain_agent2" in phase_names:
        check("V249-P01b chain_agent2 after chain",
              phase_names.index("chain_agent2") > phase_names.index("chain"),
              f"chain={phase_names.index('chain')}, chain_agent2={phase_names.index('chain_agent2')}")
    # Prompt map
    check("V249-P01c chain_agent2 in prompt map",
          "chain_agent2" in _STANDALONE_PROMPT_MAP,
          repr(list(_STANDALONE_PROMPT_MAP.keys())[:20]))
    check("V249-P01d maps to correct file",
          _STANDALONE_PROMPT_MAP.get("chain_agent2") == "phase4c-chain-agent2.md",
          _STANDALONE_PROMPT_MAP.get("chain_agent2", "MISSING"))
    # Expected artifacts
    ca2 = next((p for p in SC_PHASES if p.name == "chain_agent2"), None)
    check("V249-P01e chain_agent2 expects chain_hypotheses.md",
          ca2 is not None and "chain_hypotheses.md" in ca2.expected_artifacts,
          repr(ca2.expected_artifacts if ca2 else "NONE"))
    check("V249-P01f chain_agent2 expects composition_coverage.md",
          ca2 is not None and "composition_coverage.md" in ca2.expected_artifacts,
          repr(ca2.expected_artifacts if ca2 else "NONE"))


def test_V249_P15_sc_depth_owned_patterns_aligned_with_l1():
    """P1-5: SC depth _owned_artifact_patterns includes all L1-equivalent patterns."""
    import plamen_validators as V
    sc_owned = V._owned_artifact_patterns("sc")
    l1_owned = V._owned_artifact_patterns("l1")
    sc_depth = set(sc_owned.get("depth", []))
    l1_depth = set(l1_owned.get("depth", []))
    # All L1 depth patterns must also appear in SC depth
    missing = l1_depth - sc_depth
    check("V249-P15a SC depth has all L1 patterns",
          len(missing) == 0, f"SC missing: {missing}")
    # Specific critical patterns that were added
    must_have = [
        "depth_iter2_*_findings.md",
        "da_*_findings.md",
        "confidence_scores.md",
        "design_stress_findings.md",
        "perturbation_findings.md",
        "skill_execution_gaps.md",
        "never_cut_checkpoint.md",
        "depth_exit.md",
    ]
    for pat in must_have:
        check(f"V249-P15b SC depth has '{pat}'",
              pat in sc_depth, f"missing from SC depth patterns")


def test_V249_P14_chain_owned_patterns_split_correctly():
    """P1-4: chain and chain_agent2 owned patterns are distinct and correct."""
    import plamen_validators as V
    sc_owned = V._owned_artifact_patterns("sc")
    chain1 = sc_owned.get("chain", [])
    chain2 = sc_owned.get("chain_agent2", [])
    check("V249-P14a chain has hypotheses.md",
          "hypotheses.md" in chain1, repr(chain1))
    check("V249-P14b chain has finding_mapping.md",
          "finding_mapping.md" in chain1, repr(chain1))
    check("V249-P14c chain has enabler_results.md",
          "enabler_results.md" in chain1, repr(chain1))
    check("V249-P14d chain_agent2 has chain_hypotheses.md",
          "chain_hypotheses.md" in chain2, repr(chain2))
    check("V249-P14e chain_agent2 has composition_coverage.md",
          "composition_coverage.md" in chain2, repr(chain2))
    check("V249-P14f chain_agent2 has synthesis_full.md",
          "synthesis_full.md" in chain2, repr(chain2))
    # No overlap
    overlap = set(chain1) & set(chain2)
    check("V249-P14g no overlap between chain and chain_agent2",
          len(overlap) == 0, repr(overlap))


def test_V249_P12_report_index_expects_report_coverage():
    """P1-2: report_index phase expected_artifacts includes report_coverage.md."""
    from plamen_types import SC_PHASES, L1_PHASES
    for phases, label in [(SC_PHASES, "SC"), (L1_PHASES, "L1")]:
        ri_phase = next((p for p in phases if p.name == "report_index"), None)
        check(f"V249-P12a {label} report_index phase exists",
              ri_phase is not None, "phase not found")
        if ri_phase:
            check(f"V249-P12b {label} report_index expects report_coverage.md",
                  "report_coverage.md" in ri_phase.expected_artifacts,
                  repr(ri_phase.expected_artifacts))


def test_V249_P13_chain_summaries_compact_extraction():
    """P1-3: _extract_chain_summaries_compact produces compact file from depth artifacts."""
    from plamen_parsers import _extract_chain_summaries_compact
    sp = _mkscratch({
        "depth_token_flow_findings.md": (
            "## Finding [DEPTH-TF-1]: Reentrancy\n"
            "Some analysis here.\n\n"
            "## Chain Summary\n"
            "| Finding | Postcondition | Precondition Match |\n"
            "| DEPTH-TF-1 | Unlocked state | Needed by DEPTH-ST-2 |\n\n"
            "## Another Section\n"
            "Not chain summary.\n"
        ),
        "depth_state_trace_findings.md": (
            "## Finding [DEPTH-ST-2]: State corruption\n"
            "Analysis.\n\n"
            "## Chain Summary\n"
            "| Finding | Postcondition | Precondition Match |\n"
            "| DEPTH-ST-2 | Corrupted balance | Enables DEPTH-TF-1 |\n"
        ),
        "blind_spot_a_findings.md": (
            "## Finding [BLIND-1]: No chain summary here\n"
            "Nothing.\n"
        ),
    })
    contributors = _extract_chain_summaries_compact(sp)
    check("V249-P13a extracted from 2 source files",
          contributors == 2, f"got {contributors}")
    out = sp / "chain_summaries_compact.md"
    check("V249-P13b output file exists", out.exists(), "missing")
    if out.exists():
        text = out.read_text(encoding="utf-8")
        check("V249-P13c contains depth_token_flow source",
              "depth_token_flow_findings.md" in text, text[:200])
        check("V249-P13d contains depth_state_trace source",
              "depth_state_trace_findings.md" in text, "")
        check("V249-P13e does NOT contain 'Another Section'",
              "Another Section" not in text, "leaked non-chain section")
        check("V249-P13f contains chain table content",
              "DEPTH-TF-1" in text and "DEPTH-ST-2" in text, "")


# --------------------------------------------------------------------------

def main():
    tests = [
        test_H1_truncated_inventory_detected,
        test_H1_full_coverage_passes,
        test_H1_zero_upstream_signal_fails_loudly,
        test_H1_no_upstream_no_inventory_body_passes,
        test_H1_missing_inventory_fails,
        test_AP_HF_1_usable_findings_true_for_3plus_blocks,
        test_AP_HF_1_usable_findings_false_for_zero_blocks,
        test_AP_HF_1_usable_findings_false_for_near_empty,
        test_AP_HF_1_usable_findings_false_for_missing_file,
        test_AP_HF_1_structure_failure_with_usable_blocks_would_degrade,
        test_AP_HF_1_zero_blocks_still_halts,
        test_H1_block_count_retention_gate,
        test_H1_inventory_shard_merge_allows_dedup_against_chunks,
        test_A1_module_key_grouping,
        test_A1b_ai_model_summary_lists_unique_codex_models,
        test_A1c_ai_model_summary_light_mode_collapses_to_sonnet,
        test_A1_monorepo_granularity,
        test_A1_basename_collision_does_not_false_cover,
        test_A1_acknowledged_exempts_module,
        test_A1_small_module_exempt,
        test_A1_zero_citations_overall_fails,
        test_A2_scope_leftover_test_support_whitelist,
        test_H2_match_label_bullet_and_table,
        test_H2_depth_exit_bullet_form,
        test_H2_depth_exit_table_form,
        test_H3_ceremonial_step_trace_becomes_unknown_not_posthoc_proof,
        test_H4_notread_basename_collision_does_not_false_cover,
        test_R1_new_l1_ids_are_harvested_for_promotion,
        test_R1b_sc_feeder_ids_are_harvested_for_promotion,
        test_R2_unresolved_fallback_mapping_flags_missing_body_tag,
        test_R3_confirmed_verify_requires_body_or_explicit_non_body,
        test_R4_report_repair_restores_missing_assigned_section_and_unresolved,
        test_R5_python_assembler_refuses_missing_assigned_sections,
        test_R6_complete_report_index_does_not_merge_stale_queue_rows,
        test_R7_verify_schema_drift_is_normalized_to_preferred_tag,
        test_R8_report_index_excludes_refuted_rows_from_assignments,
        test_R9_crossbatch_fail_signals_block_phase,
        test_R10_depth_findings_promote_into_inventory_before_verify_queue,
        test_R10b_confirmed_depth_tail_ids_promote_without_confidence_allowlist,
        test_R11_sc_feeder_findings_promote_into_inventory_before_verify_queue,
        test_R12_sc_fuzzer_refuted_proposal_stays_visible_pending_closure,
        test_R13_sc_slither_confirmed_promotes_through_report_index,
        test_R14_consolidation_map_acknowledges_confirmed_source_ids,
        test_R15_client_title_sanitizer_removes_internal_ids,
        test_R16_report_renderer_uses_verifier_content,
        test_R17_report_quality_rejects_stub_body,
        test_R18_crossbatch_requires_full_verify_scope,
        test_R19_skeptic_requires_all_critical_high,
        test_G1_inventory_sources_include_graph_sweeps,
        test_G2_graph_sweeps_validate_low_coverage_outputs,
        test_G3_completed_phase_deletes_stale_degraded_sentinel,
        test_G4_repo_map_table_format_is_indexed,
        test_G5_subsystem_coverage_basename_collision_not_false_covered,
        test_G5b_sc_subsystem_coverage_flags_uncited_contract_bucket,
        test_G5c_sc_subsystem_coverage_ack_exempts_bucket,
        test_G5d_sc_slither_flat_files_materialize_from_recon_artifacts,
        test_G6_graph_sweeps_require_miss_class_work_queues,
        test_G7_final_coverage_summary_uses_late_verify_citations,
        test_Q1_no_sleep_override_clears_hibernation_marker,
        test_Q2_no_sleep_override_skips_new_hibernation_on_rate_limit,
        test_Q3_hibernation_disabled_by_default,
        test_Q4_hibernation_can_be_opted_in,
        test_A3_attention_repair_queue_from_notread_and_uncited_security_files,
        test_A3_attention_repair_validation_requires_verdicts_and_paths,
        test_A3_attention_repair_accepts_covered_verdict_for_receipts,
        test_A3_attention_repair_requires_full_queued_path_receipt,
        test_A3_attention_repair_validation_accepts_row_shard_suffix_paths,
        test_A3_attention_repair_graph_rows_do_not_require_exact_source_path,
        test_A3_attention_repair_findings_promote_into_inventory,
        test_A3_graph_schema_catches_weak_network_rows,
        test_A3_sc_contract_inventory_drives_attention_repair_without_scip,
        test_A3_attention_repair_excludes_support_files_but_writes_spec_expectations,
        test_A3_semantic_dedup_candidate_packet_is_bounded,
        test_A3_semantic_dedup_prompt_is_fail_open_and_bounded,
        test_A3_sc_phase_order_has_attention_repair_before_rag_and_chain,
        test_M1_opus_alias_pins_to_48,
        test_M2_light_mode_still_forces_sonnet,
        test_M3_l1_verify_shards_are_cost_capped,
        test_M4_l1_verify_shards_are_severity_weighted,
        test_M4b_sc_high_verify_shards_are_small_enough_for_thorough,
        test_M4h_sc_verify_shard_partition_complete_and_disjoint,
        test_M4i_sc_verify_shards_spread_heavy_tiers_not_overshard_light,
        test_M4c_stale_verify_retry_hint_cleared_after_reshard,
        test_M4d_semantic_dedup_passthrough_with_pairs_is_not_complete,
        test_M4e_semantic_dedup_prompt_overrides_passthrough_resumption,
        test_M4f_verify_queue_parity_accepts_semantic_dedup_absorbed_ids,
        test_M4g_verify_queue_parity_still_flags_missing_pass_ids,
        test_M4h_report_index_prompt_examples_use_non_copyable_placeholder_ids,
        test_M5_report_index_recovery_promotes_missing_confirmed,
        test_M6_inventory_evidence_validation_and_queue_filter,
        test_M7_mechanical_report_index_keeps_unproven_negative_visible,
        test_M8_messy_formats_are_tolerated_without_dropping_leads,
        test_M9_mechanical_inventory_merge_preserves_chunk_source_ids,
        test_M9b_inventory_merge_does_not_overcut_same_location_sibling_bugs,
        test_M10_mechanical_verify_queue_routes_every_inventory_id,
        test_M11_verify_queue_parity_flags_dropped_inventory_ids,
        test_M12_verify_queue_parity_hypothesis_aware_expansion,
        # v2.4.9 regression tests
        test_V249_P51_index_completeness_retry_hint_uses_norm_indexed,
        test_V249_P43_depth_evidence_tag_regex_covers_all_tags,
        test_V249_P45_fid_allowed_prefixes_covers_niche_agents,
        test_V249_P42_hypo_heading_re_matches_l1_ids,
        test_V249_P44_quality_gate_leak_check_catches_niche_ids,
        test_V249_P01_chain_agent2_phase_in_sc_phases,
        test_V249_P15_sc_depth_owned_patterns_aligned_with_l1,
        test_V249_P14_chain_owned_patterns_split_correctly,
        test_V249_P12_report_index_expects_report_coverage,
        test_V249_P13_chain_summaries_compact_extraction,
    ]
    print(f"Running {len(tests)} helper smoke tests...")
    for t in tests:
        print(f"\n[{t.__name__}]")
        t()
    print(f"\n{'=' * 48}")
    print(f"  PASS: {PASS}   FAIL: {FAIL}")
    print('=' * 48)
    sys.exit(0 if FAIL == 0 else 1)


if __name__ == "__main__":
    main()
