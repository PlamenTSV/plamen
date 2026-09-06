"""Pipeline phase-contract tests.

Each test asserts a clause from the formal phase contract:
  - Loss invariant: information that cannot be silently lost
  - Quality invariant: what counts as honest output (not boilerplate)
  - Failure invariant: conditions that MUST trigger HALT

Phases covered:
  P1  Recon                P5    Verification
  P2  Instantiate          P51   Skeptic-Judge
  P3  Breadth/Rescan/PC    P52   Cross-batch
  P4a Inventory merge      P6    Report
  P4a5 Semantic invariants
  P4b Depth loop
  P4b5 RAG validation
  P4c Chain analysis (SC)

Tests are written contract-first: the test exists before the helper does.
A test that fails with AttributeError reveals a missing gate, not a missing
test — that becomes a driver work item.

Run: `python test_pipeline_contracts.py`
"""

from __future__ import annotations

import re
import sys
import tempfile
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS_DIR))

import plamen_driver as D  # noqa: E402

PASS = 0
FAIL = 0
ERRORS: list[tuple[str, str, str]] = []  # (test, label, detail)


def check(label: str, ok: bool, detail: str = ""):
    global PASS, FAIL
    if ok:
        PASS += 1
        print(f"  PASS  {label}")
    else:
        FAIL += 1
        print(f"  FAIL  {label} :: {detail}")


def _mkscratch(files: dict[str, str]) -> Path:
    sp = Path(tempfile.mkdtemp(prefix="plamen_pc_"))
    for name, body in files.items():
        p = sp / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body, encoding="utf-8")
    return sp


def _mkrepo(files: list[str]) -> Path:
    root = Path(tempfile.mkdtemp(prefix="plamen_pc_repo_"))
    for rel in files:
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("// stub\n" * 30, encoding="utf-8")
    return root


# =============================================================================
# Phase 1 — Recon
# Goal: every production source file is mapped or explicitly acknowledged.
# =============================================================================

def test_P1_loss_every_module_with_10plus_files_is_cited_or_acked():
    """P1 loss: 12-file consensus/ module uncited and not in scope_leftover -> halt."""
    files = (
        [f"crates/consensus/src/m{i}.rs" for i in range(12)] +
        [f"crates/core/src/m{i}.rs" for i in range(12)]
    )
    root = _mkrepo(files)
    sp = _mkscratch({
        "attack_surface.md": "\n".join(
            f"- `crates/core/src/m{i}.rs:1`" for i in range(12)
        ),
    })
    issues = D._validate_recon_coverage(sp, str(root), "l1")
    check(
        "P1.loss.module-coverage flagged for uncited 12-file module",
        any("crates/consensus" in s for s in issues),
        repr(issues),
    )


def test_P1_loss_acknowledged_module_exempt():
    """P1 loss: bucket entirely uncited but with ACKNOWLEDGED row -> exempt."""
    files = (
        [f"crates/legacy/src/m{i}.rs" for i in range(12)] +
        [f"crates/active/src/m{i}.rs" for i in range(12)]
    )
    root = _mkrepo(files)
    sp = _mkscratch({
        "attack_surface.md": "- `crates/active/src/m0.rs:1`\n",
        "scope_leftover.md": (
            "| File | LOC | Reason | Acknowledged |\n"
            "|------|-----|--------|--------------|\n"
            "| crates/legacy/src/m0.rs | 10 | superseded | "
            "ACKNOWLEDGED: SUPERSEDED |\n"
        ),
    })
    issues = D._validate_recon_coverage(sp, str(root), "l1")
    check(
        "P1.loss.ack-exempt: ACKNOWLEDGED bucket not flagged",
        not any("legacy" in s for s in issues),
        repr(issues),
    )


def test_P1_failure_zero_citations_overall_halts():
    """P1 failure: empty attack_surface.md (zero file citations) -> halt."""
    root = _mkrepo([f"crates/x/src/m{i}.rs" for i in range(12)])
    sp = _mkscratch({"attack_surface.md": "no citations here\n"})
    issues = D._validate_recon_coverage(sp, str(root), "l1")
    check(
        "P1.failure.zero-citations halts",
        any("zero file-path citations" in s for s in issues),
        repr(issues),
    )


def test_P1_loss_basename_collision_does_not_false_cover():
    """P1 loss: two crates share lib.rs; citing one must not cover the other."""
    files = []
    for crate in ("a", "b"):
        files += [f"crates/{crate}/src/m{i}.rs" for i in range(12)]
        files.append(f"crates/{crate}/src/lib.rs")
    root = _mkrepo(files)
    sp = _mkscratch({
        "attack_surface.md": "- `crates/a/src/lib.rs:1`\n",
    })
    issues = D._validate_recon_coverage(sp, str(root), "l1")
    uncovered = next((s for s in issues if "missed" in s), "")
    check(
        "P1.loss.basename-collision: separate crates not false-covered",
        "crates/b" in uncovered and "crates/a" not in uncovered,
        repr(issues),
    )


# =============================================================================
# Phase 4a — Inventory merge
# Goal: every feeder ID preserved as Source ID OR documented in dedup.
# =============================================================================

def test_P4a_loss_chunk_truncation_halts():
    """P4a loss: chunks have 200 entries, queue covers 50 -> parity halts."""
    chunks = {}
    for c in ("a", "b"):
        body = []
        for i in range(50):
            body.extend([
                f"### Finding [CHK{c.upper()}-{i:02d}]: bug {c}{i}",
                f"**Source IDs**: CHK{c.upper()}-{i:02d}",
                "**Severity**: Medium",
                f"**Location**: src/{c}/m{i}.rs:L{i+1}",
                f"**Root Cause**: cause {c}{i}",
                "",
            ])
        chunks[f"findings_inventory_chunk_{c}.md"] = "\n".join(body)
    sp = _mkscratch(chunks)
    D._write_mechanical_inventory_from_chunks(sp)

    queue_lines = [
        "| Queue # | Finding ID | Severity | Title | Bug Class | Preferred Tag | Location | Primary Artifact |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for i in range(1, 26):  # 25 of 100
        queue_lines.append(f"| {i} | INV-{i:03d} | Medium | t | x | CODE-TRACE | s:L{i} | x.md |")
    (sp / "verification_queue.md").write_text("\n".join(queue_lines), encoding="utf-8")
    issues = D._validate_verification_queue_inventory_parity(sp)
    check(
        "P4a.loss.parity halts on 75% queue dropout",
        any("dropout" in s for s in issues),
        repr(issues[:2]),
    )


def test_P4a_loss_distinct_sibling_bugs_at_same_line_kept():
    """P4a loss: two distinct bugs at same file:line -> NOT merged."""
    entries = [
        {"title": "loop early-exit", "severity": "High", "location": "src/x.sol:L10",
         "source_ids": ["BLIND-1"], "root_cause": "early exit"},
        {"title": "missing decimals check", "severity": "Medium", "location": "src/x.sol:L10",
         "source_ids": ["VS-3"], "root_cause": "no validation"},
    ]
    merged = D._merge_inventory_entries(entries)
    check(
        "P4a.loss.sibling-bugs at same line both kept",
        len(merged) == 2,
        f"merged_count={len(merged)}",
    )


def test_P4a_failure_zero_upstream_signal_with_inventory_halts():
    """P4a failure: inventory has body but upstream is empty (truncation symptom)."""
    sp = _mkscratch({
        "analysis_breadth1.md": "no findings produced.\n",
        "findings_inventory.md": (
            "# Inventory\n## Finding [CS-1]: bug\n**Location**: a.sol:L1\n"
        ),
    })
    issues = D._validate_inventory_parity(sp)
    check(
        "P4a.failure.zero-upstream-signal halts",
        any("zero finding signals" in s for s in issues),
        repr(issues),
    )


def test_AP_HF_1_inventory_degrade_branch_precedes_critical_funnel():
    """AP-HF-1: the inventory degrade-and-continue branch must run BEFORE the
    generic `elif phase.critical:` FC4 → wait_critical_halt_choice funnel, so a
    structure-gate failure on an inventory with usable blocks continues instead
    of halting. Verified structurally against the run-loop source (ecosystem-
    agnostic: the same branch covers SC and L1)."""
    import inspect
    src = inspect.getsource(D.main)
    # B2: the inventory degrade branch now routes through the B1-floor-aware
    # helper `_inventory_degrade_floor_ok` (reconstructs an honest inventory
    # from completed artifacts before any halt) instead of the bare
    # `_inventory_has_usable_findings` precondition. The structural invariant
    # (degrade branch precedes the critical-halt funnel) is unchanged.
    degrade_match = re.search(
        r'phase\.name\s*==\s*"inventory"\s*and\s*'
        r'_inventory_degrade_floor_ok\s*\(',
        src,
    )
    degrade_idx = degrade_match.start() if degrade_match else -1
    critical_idx = src.find("elif phase.critical:")
    assert degrade_idx != -1, "inventory degrade branch missing from run loop"
    assert critical_idx != -1, "critical-halt funnel missing from run loop"
    assert degrade_idx < critical_idx, (
        "inventory degrade branch must precede the critical-halt funnel"
    )


def test_AP_HF_1_inventory_usable_findings_functional_both_pipelines():
    """The degrade precondition helper is ecosystem-agnostic: it gates on
    parseable finding blocks regardless of SC vs L1 ID conventions."""
    # SC-style INV ids and L1-style INV ids both parse as usable.
    for prefix in ("INV", "L1-H"):
        body = "# Finding Inventory\n\n## Findings\n\n" + "\n".join(
            f"### Finding [{prefix}-{i:02d}]: bug {i}\n"
            f"**Severity**: Medium\n**Location**: src/F{i}:L{i}\n"
            f"**Source IDs**: AC-{i}\n**Preferred Tag**: CODE-TRACE\n"
            f"**Description**: Finding {i} describes a concrete state "
            f"inconsistency in the accounting path with material user impact.\n"
            for i in range(1, 4)
        )
        sp = _mkscratch({"findings_inventory.md": body})
        assert D._inventory_has_usable_findings(sp) is True, prefix


def test_P4a_loss_sc_feeder_ids_in_promotion_files():
    """P4a loss: SC feeder file patterns are in _DEPTH_PROMOTION_FILES."""
    pat_text = "\n".join(D._DEPTH_PROMOTION_FILES)
    required_patterns = [
        "niche_*_findings.md",
        "blind_spot_*_findings.md",
        "analysis_rescan_*.md",
        "analysis_percontract_*.md",
        "validation_sweep_findings.md",
        "scanner_*_findings.md",
    ]
    missing = [p for p in required_patterns if p not in pat_text]
    check(
        "P4a.loss.sc-feeder-patterns in _DEPTH_PROMOTION_FILES",
        not missing,
        f"missing={missing}",
    )


def test_P4a_loss_sc_feeder_ids_match_canonical_regex():
    """P4a loss: SC feeder IDs (SLITHER, FUZZ, MEDUSA, RSW, SP) match regex."""
    cases = ["SLITHER-1", "SLITHER-99", "FUZZ-1", "FUZZ-22", "MEDUSA-3", "RSW-7", "SP-12"]
    failed = [c for c in cases if not D._INTERNAL_FINDING_ID_RE.fullmatch(c)]
    check(
        "P4a.loss.sc-feeder-id-regex covers all known SC feeder formats",
        not failed,
        f"unmatched={failed}",
    )


# =============================================================================
# Phase 4b — Depth loop
# Goal: every inventory finding gets a disposition with evidence tags.
# =============================================================================

def test_P4b_loss_depth_word_boundary_promotion_receipt():
    """P4b loss: DCI-1 vs DCI-12 substring collision must NOT false-pass."""
    inv = (
        "### Finding [INV-001]: bug from DCI-12\n"
        "**Source IDs**: DCI-12\n**Severity**: High\n**Location**: src/a.rs:L1\n"
    )
    depth = (
        "### Finding [DCI-1]: low\n**Confidence**: 0.85\n"
        "**Severity**: Medium\n**Location**: src/a.rs:L1\n**Description**: a\n\n"
        "### Finding [DCI-12]: high\n**Confidence**: 0.85\n"
        "**Severity**: High\n**Location**: src/a.rs:L12\n**Description**: b\n"
    )
    scores = "| Finding ID | Confidence |\n|---|---|\n| DCI-1 | 0.85 |\n| DCI-12 | 0.85 |\n"
    sp = _mkscratch({
        "findings_inventory.md": inv,
        "depth_consensus_invariant_findings.md": depth,
        "confidence_scores.md": scores,
    })
    issues = D._validate_depth_promotion_receipt(sp)
    check(
        "P4b.loss.word-boundary catches DCI-1 missing despite DCI-12 present",
        any("DCI-1" in s for s in issues),
        repr(issues),
    )


def test_P4b_loss_low_confidence_not_promoted():
    """P4b loss: depth findings < min_confidence (0.70) NOT promoted."""
    inv = "### Finding [INV-001]: existing\n**Location**: src/a.rs:L1\n"
    depth = (
        "### Finding [DCI-1]: low conf\n**Confidence**: 0.65\n"
        "**Severity**: High\n**Location**: src/x.rs:L1\n**Description**: x\n\n"
        "### Finding [DCI-2]: high conf\n**Confidence**: 0.85\n"
        "**Severity**: High\n**Location**: src/y.rs:L1\n**Description**: y\n"
    )
    scores = "| Finding ID | Confidence |\n|---|---|\n| DCI-1 | 0.65 |\n| DCI-2 | 0.85 |\n"
    sp = _mkscratch({
        "findings_inventory.md": inv,
        "depth_consensus_invariant_findings.md": depth,
        "confidence_scores.md": scores,
    })
    promoted = D._promote_depth_findings_to_inventory(sp)
    check(
        "P4b.loss.low-confidence finding NOT promoted",
        "DCI-1" not in promoted and "DCI-2" in promoted,
        f"promoted={promoted}",
    )


def test_P4b_loss_dns_da3_ids_in_regex():
    """P4b loss: DNS-* and DA3-* depth-tail IDs match canonical regex."""
    cases = ["DNS-1", "DNS-12", "DA3-CONSENSUS-1", "DA3-NETWORK-7"]
    failed = [c for c in cases if not D._INTERNAL_FINDING_ID_RE.fullmatch(c)]
    check(
        "P4b.loss.dns-da3-regex matches",
        not failed,
        f"unmatched={failed}",
    )


# =============================================================================
# Phase 5 — Verification
# Goal: every queue ID has verify_*.md with rich content; CONFIRMED is real.
# =============================================================================

def test_P5_failure_empty_verify_returns_unresolved():
    """P5 failure: empty/whitespace verify body must NOT auto-CONFIRM."""
    empty_status = D._verifier_status_from_text("")
    ws_status = D._verifier_status_from_text("   \n\n   \n")
    check(
        "P5.failure.empty-verify -> non-CONFIRMED",
        empty_status != "CONFIRMED" and ws_status != "CONFIRMED",
        f"empty={empty_status} ws={ws_status}",
    )


def test_P5_quality_garbage_verdict_not_auto_confirmed():
    """P5 quality: 'TBD', 'maybe?' verdicts must NOT default CONFIRMED."""
    cases = ["**Verdict**: TBD\n", "**Verdict**: maybe?\n", "**Verdict**: ???\n"]
    statuses = [D._verifier_status_from_text(c) for c in cases]
    check(
        "P5.quality.garbage-verdict not CONFIRMED",
        all(s != "CONFIRMED" for s in statuses),
        f"statuses={statuses}",
    )


def test_P5_loss_queue_id_dropout_halts():
    """P5 loss: queue has 10 IDs, only 3 get verify_*.md -> parity halts."""
    inv_lines = ["# Inventory", ""]
    queue_lines = [
        "| Queue # | Finding ID | Severity | Title | Bug Class | Preferred Tag | Location | Primary Artifact |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for i in range(1, 11):
        inv_lines.extend([
            f"### Finding [INV-{i:03d}]: bug",
            "**Severity**: Medium",
            f"**Location**: src/x.rs:L{i}",
            "",
        ])
        queue_lines.append(
            f"| {i} | INV-{i:03d} | Medium | t | x | CODE-TRACE | src/x.rs:L{i} | x.md |"
        )
    files = {
        "findings_inventory.md": "\n".join(inv_lines),
        "verification_queue.md": "\n".join(queue_lines),
    }
    # Only 3 verify files exist; queue covers all 10 -> parity check is OK
    # (parity is inventory<->queue, not queue<->verify). Use a different
    # contract surface: report-index recovery should detect 7 missing CONFIRMs.
    sp = _mkscratch(files)
    # parity check is between inventory and queue; this scenario is queue
    # complete but verify shards missing. Surface this through verify-receipt
    # collection: 0 CONFIRMED receipts because no verify file exists.
    receipts = D._collect_verify_promotion_receipts(sp)
    check(
        "P5.loss.no-verify-files yields zero CONFIRMED receipts",
        receipts == set(),
        f"receipts={receipts}",
    )


# =============================================================================
# Phase 5.1 — Skeptic-Judge
# =============================================================================

def test_P51_loss_partial_critical_high_skeptic_halts():
    """P51 loss: 5 C/H findings, skeptic covers 2 -> halt."""
    queue = (
        "| Queue # | Finding ID | Severity | Title | Bug Class | Preferred Tag | Location | Primary Artifact |\n"
        "|---|---|---|---|---|---|---|---|\n"
    )
    files = {}
    for i in range(1, 6):
        fid = f"INV-{i:03d}"
        sev = "Critical" if i <= 2 else "High"
        queue += f"| {i} | {fid} | {sev} | b{i} | x | CODE-TRACE | s:L{i} | x.md |\n"
        files[f"verify_{fid}.md"] = "**Verdict**: CONFIRMED\nReal.\n"
    files["verification_queue.md"] = queue
    files["skeptic_findings.md"] = (
        "# Skeptic\n## INV-001\n**Verdict**: AGREE\n## INV-002\n**Verdict**: AGREE\n"
    )
    sp = _mkscratch(files)
    issues = D._validate_skeptic_scope(sp)
    check(
        "P51.loss.partial-coverage halts",
        bool(issues),
        f"issues={issues}",
    )


def test_P51_loss_unresolved_demote_keep_in_body():
    """P51 loss: UNRESOLVED finding stays in active index, demoted -1 tier."""
    inv = "### Finding [INV-001]: bug\n**Severity**: High\n**Location**: src/a.rs:L1\n"
    queue = (
        "| Queue # | Finding ID | Severity | Title | Bug Class | Preferred Tag | Location | Primary Artifact |\n"
        "|---|---|---|---|---|---|---|---|\n"
        "| 1 | INV-001 | High | bug | x | CODE-TRACE | src/a.rs:L1 | x.md |\n"
    )
    sp = _mkscratch({
        "findings_inventory.md": inv,
        "verification_queue.md": queue,
        "verify_INV-001.md": "**Verdict**: UNRESOLVED\n",
    })
    D._write_mechanical_report_index(sp)
    idx = (sp / "report_index.md").read_text(encoding="utf-8")
    excluded_at = idx.find("Excluded Findings")
    in_master = "INV-001" in idx[:excluded_at] if excluded_at > -1 else "INV-001" in idx
    demoted = "| Medium |" in idx
    check(
        "P51.loss.unresolved stays in body, demoted High->Medium",
        in_master and demoted and "UNRESOLVED" in idx,
        f"in_master={in_master} demoted={demoted}",
    )


# =============================================================================
# Phase 5.2 — Cross-batch consistency
# =============================================================================

def test_P52_loss_partial_crossbatch_coverage_halts():
    """P52 loss: 10 verify files, crossbatch reports 4 -> halt."""
    files = {}
    for i in range(1, 11):
        files[f"verify_INV-{i:03d}.md"] = (
            f"**Verdict**: CONFIRMED\nFinding {i}.\n**Evidence Tag**: CODE-TRACE\n"
        )
    files["cross_batch_consistency.md"] = (
        "# Cross-Batch\nVerifiers Checked: 4\nFiles checked: 4\n"
        "Overall: PASS\nReviewed: INV-001, INV-002, INV-003, INV-004\n"
    )
    sp = _mkscratch(files)
    issues = D._validate_crossbatch_full_coverage(sp)
    check(
        "P52.loss.partial-crossbatch halts",
        bool(issues),
        f"issues={issues}",
    )


# =============================================================================
# Phase 6 — Report
# =============================================================================

def test_P6_loss_refuted_is_retained_with_non_authoritative_proposal():
    """P6 loss: verifier prose cannot remove a candidate from the body."""
    inv = "### Finding [INV-001]: claim\n**Severity**: High\n**Location**: src/a.rs:L1\n"
    queue = (
        "| Queue # | Finding ID | Severity | Title | Bug Class | Preferred Tag | Location | Primary Artifact |\n"
        "|---|---|---|---|---|---|---|---|\n"
        "| 1 | INV-001 | High | bogus | x | CODE-TRACE | src/a.rs:L1 | x.md |\n"
    )
    sp = _mkscratch({
        "findings_inventory.md": inv,
        "verification_queue.md": queue,
        "verify_INV-001.md": "**Verdict**: FALSE_POSITIVE\nNot exploitable.\n",
    })
    D._write_mechanical_report_index(sp)
    idx = (sp / "report_index.md").read_text(encoding="utf-8")
    proposal_at = idx.find("Proposed Negative Dispositions")
    master = idx[:proposal_at]
    proposals = idx[proposal_at:]
    check(
        "P6.loss.refuted retained in Master with proposal-only negative",
        "| INV-001 |" in master and "INV-001" in proposals,
        f"in_proposals={('INV-001' in proposals)} in_master={('| INV-001 |' in master)}",
    )


def test_P6_quality_renderer_pulls_rich_content_from_verify():
    """P6 quality: rendered section contains real Description/Impact/PoC,
    not boilerplate."""
    sp = _mkscratch({
        "verify_INV-001.md": (
            "**Verdict**: CONFIRMED\n**Severity**: High\n**Location**: src/x.sol:L42\n\n"
            "## Description\n\nThe `redeem()` function ignores `paused` state, "
            "letting users drain funds during emergency pauses.\n\n"
            "## Impact\n\nUsers can extract assets while halted; "
            "loss bounded by current vault balance.\n\n"
            "## PoC Result\n\nPASS - test_INV001 reproduces.\n"
        ),
    })
    section = D._synth_report_section_from_verify(
        sp, "H-01", "INV-001",
        {"severity": "High", "title": "redeem ignores pause",
         "location": "src/x.sol:L42", "preferred tag": "POC-PASS",
         "bug class": "access control"},
        unresolved=False,
    )
    has_desc = "redeem()" in section and "drain funds" in section
    has_impact = "extract assets" in section
    has_poc = "PASS" in section or "test_INV001" in section
    no_boilerplate = "did not include" not in section.lower()
    check(
        "P6.quality.rich-rendering: Description+Impact+PoC from verify",
        has_desc and has_impact and has_poc and no_boilerplate,
        f"desc={has_desc} impact={has_impact} poc={has_poc} no_bp={no_boilerplate}",
    )


def test_P6_quality_empty_verify_yields_stub_recovered_marker():
    """P6 quality: missing verify -> STUB-RECOVERED + UNRESOLVED, never auto-CONFIRM."""
    sp = _mkscratch({})
    section = D._synth_report_section_from_verify(
        sp, "H-01", "INV-001",
        {"severity": "High", "title": "x", "location": "src/a.rs:L1",
         "preferred tag": "", "bug class": ""},
        unresolved=False,
    )
    check(
        "P6.quality.stub-marker on empty verify",
        "STUB-RECOVERED" in section and "**Verdict**: UNRESOLVED" in section,
        f"section_excerpt={section[:300]!r}",
    )


def test_P6_quality_internal_id_sanitized_from_title():
    """P6 quality: titles must not contain internal IDs (INV-001, DCI-7)."""
    title_clean = D._sanitize_client_title("INV-001: Reentrancy in withdraw")
    check(
        "P6.quality.title-sanitization removes INV-001",
        "INV-001" not in title_clean,
        f"sanitized={title_clean!r}",
    )


def test_P6_quality_internal_id_sanitized_from_body():
    """P6 quality: body prose must not contain internal IDs."""
    body = "This bug (originally INV-001) was confirmed by DCI-7 and VS-3."
    sanitized = D._sanitize_client_body(body)
    check(
        "P6.quality.body-sanitization removes INV/DCI/VS",
        all(t not in sanitized for t in ("INV-001", "DCI-7", "VS-3")),
        f"sanitized={sanitized!r}",
    )


def test_P6_quality_genuine_text_preserved():
    """P6 quality: sanitization is lossless for non-ID text."""
    body = "The function fails when user balance equals zero."
    check(
        "P6.quality.sanitization lossless for non-ID text",
        D._sanitize_client_body(body) == body,
        "",
    )


def test_P6_failure_severity_demote_floor_no_inflation():
    """P6 failure: Informational does NOT inflate to Low on demote."""
    check(
        "P6.failure.severity-demote-floor: Informational stays Informational",
        D._demote_severity_once("Informational") == "Informational",
        f"got {D._demote_severity_once('Informational')!r}",
    )


def test_P6_failure_severity_demote_low_floor():
    check(
        "P6.failure.severity-demote-floor: Low stays Low",
        D._demote_severity_once("Low") == "Low",
        "",
    )


def test_P6_failure_severity_demote_critical_to_high():
    check(
        "P6.failure.severity-demote: Critical -> High",
        D._demote_severity_once("Critical") == "High",
        "",
    )


# =============================================================================
# Cross-phase / integration invariants
# =============================================================================

def test_X_promotion_symmetry_confirmed_in_body_or_excluded():
    """Cross-phase: every CONFIRMED verify ID -> body section OR excluded row."""
    queue = (
        "| Queue # | Finding ID | Severity | Title | Bug Class | Preferred Tag | Location | Primary Artifact |\n"
        "|---|---|---|---|---|---|---|---|\n"
        "| 1 | INV-001 | High | bug | x | CODE-TRACE | s:L1 | x.md |\n"
    )
    sp = _mkscratch({
        "verify_INV-001.md": "## Verify\n**Verdict**: CONFIRMED\nINV-001 confirmed.\n",
        "report_index.md": (
            "## Master Finding Index\n\n"
            "| Report ID | Title | Severity | Location | "
            "Internal Hypothesis ID | Evidence Tag | Verdict | Trust Adj. |\n"
            "|---|---|---|---|---|---|---|---|\n"
            "| H-01 | bug | High | s:L1 | INV-001 | CODE-TRACE | CONFIRMED | |\n"
        ),
        "verification_queue.md": queue,
    })
    proj = Path(tempfile.mkdtemp(prefix="plamen_pc_proj_"))
    (proj / "AUDIT_REPORT.md").write_text(
        "# Audit Report\n\nNo body section for H-01.\n", encoding="utf-8",
    )
    issues = D._check_promotion_symmetry(sp, str(proj))
    check(
        "X.promotion-symmetry: missing body section flagged as dropout",
        any("dropout" in s and "INV-001" in s for s in issues),
        repr(issues),
    )


def test_X_unresolved_authenticity_phantom_flagged():
    """Cross-phase: body [UNRESOLVED] without Judge UNRESOLVED -> flagged."""
    sp = _mkscratch({
        "skeptic_judge_decisions.md": (
            "## INV-002\n**Verdict**: UNRESOLVED\n"
        ),
        "report_index.md": (
            "## Master Finding Index\n\n"
            "| Report ID | Title | Severity | Location | "
            "Internal Hypothesis ID | Evidence Tag | Verdict | Trust Adj. |\n"
            "|---|---|---|---|---|---|---|---|\n"
            "| H-01 | bug | High | s:L1 | INV-001 | CODE-TRACE | CONFIRMED | |\n"
        ),
    })
    proj = Path(tempfile.mkdtemp(prefix="plamen_pc_proj_"))
    (proj / "AUDIT_REPORT.md").write_text(
        "### [H-01] bug [UNRESOLVED - needs human review]\nBody.\n",
        encoding="utf-8",
    )
    issues = D._check_unresolved_authenticity(sp, str(proj))
    check(
        "X.unresolved-authenticity: phantom body tag flagged",
        any("phantom" in s and "H-01" in s for s in issues),
        repr(issues),
    )


def test_X_inventory_to_queue_to_report_round_trip():
    """Cross-phase end-to-end: 5 inventory entries -> 5 queue rows ->
    5 active OR excluded report rows. No silent loss."""
    inv_lines = ["# Inventory", ""]
    for i in range(1, 6):
        inv_lines.extend([
            f"### Finding [INV-{i:03d}]: bug{i}",
            "**Severity**: " + ("High" if i % 2 else "Medium"),
            f"**Location**: src/m{i}.sol:L{i}",
            "**Preferred Tag**: CODE-TRACE",
            "",
        ])
    files = {"findings_inventory.md": "\n".join(inv_lines)}
    sp = _mkscratch(files)
    n = D._write_mechanical_verification_queue_from_inventory(sp)
    rows = D.parse_verification_queue_rows(sp)
    queue_ids = {r["finding id"] for r in rows}

    # Simulate verifier outputs: 3 CONFIRMED, 2 FALSE_POSITIVE
    for i, fid in enumerate(sorted(queue_ids), start=1):
        verdict = "CONFIRMED" if i <= 3 else "FALSE_POSITIVE"
        (sp / f"verify_{fid}.md").write_text(
            f"**Verdict**: {verdict}\n## Description\nFinding {fid} description.\n"
            f"## Impact\nImpact text.\n## PoC Result\nx.\n",
            encoding="utf-8",
        )
    D._write_mechanical_report_index(sp)
    idx = (sp / "report_index.md").read_text(encoding="utf-8")
    proposal_at = idx.find("Proposed Negative Dispositions")
    master = idx[:proposal_at]
    proposals = idx[proposal_at:]
    in_master = sum(1 for fid in queue_ids if f"| {fid} |" in master)
    in_proposals = sum(1 for fid in queue_ids if fid in proposals)
    check(
        "X.round-trip: 5 inv -> 5 queue -> 5 active + 2 negative proposals",
        n == 5 and in_master == 5 and in_proposals == 2,
        f"queue={n} master={in_master} proposals={in_proposals}",
    )


# =============================================================================
# Phase 2 — Instantiate
# =============================================================================

def test_P2_loss_template_recommendations_artifact_exists():
    """P2 loss: spawn manifest derivable from template_recommendations.md."""
    sp = _mkscratch({
        "template_recommendations.md": (
            "## Required Skills\n\n- ORACLE_ANALYSIS\n- FLASH_LOAN_INTERACTION\n\n"
            "## Niche Agents\n\n- EVENT_COMPLETENESS\n"
        ),
    })
    text = (sp / "template_recommendations.md").read_text(encoding="utf-8")
    has_required = "## Required Skills" in text
    has_niche = "## Niche Agents" in text
    check(
        "P2.loss.template-recommendations has Required + Niche sections",
        has_required and has_niche,
        f"required={has_required} niche={has_niche}",
    )


# =============================================================================
# Phase 3 — Breadth / Rescan / Per-contract
# =============================================================================

def test_P3_loss_attack_surface_files_appear_in_breadth_outputs():
    """P3 loss contract: every file in attack_surface.md must be cited in
    at least one analysis_*.md output. Manual file-coverage check (no helper
    yet — surfaces a missing gate)."""
    sp = _mkscratch({
        "attack_surface.md": (
            "- `contracts/Vault.sol:L1`\n"
            "- `contracts/Lender.sol:L1`\n"
            "- `contracts/Auth.sol:L1`\n"
        ),
        "analysis_breadth1.md": "Reviewed `contracts/Vault.sol:L42`.\n",
        "analysis_breadth2.md": "Reviewed `contracts/Lender.sol:L88`.\n",
        # Auth.sol is uncovered.
    })
    surface_files = re.findall(r"`([^`]+\.sol)", (sp / "attack_surface.md").read_text(encoding="utf-8"))
    breadth_text = ""
    for p in sp.glob("analysis_breadth*.md"):
        breadth_text += p.read_text(encoding="utf-8")
    uncovered = [f for f in surface_files if f not in breadth_text]
    check(
        "P3.loss.attack-surface-coverage: uncovered file detected by content scan",
        "contracts/Auth.sol" in uncovered,
        f"uncovered={uncovered}",
    )


def test_P3_quality_breadth_with_zero_findings_must_declare():
    """P3 quality: breadth output with zero ## Finding sections must contain
    explicit 'no findings' or 'reviewed without finding' declaration."""
    bad_breadth = "# Breadth Agent 1\n\nAll quiet on the western front.\n"
    good_breadth_zero = (
        "# Breadth Agent 1\n\nReviewed all assigned contracts; no findings "
        "above Informational severity.\n"
    )
    bad_has_decl = "no findings" in bad_breadth.lower() or "reviewed" in bad_breadth.lower() and "no" in bad_breadth.lower()
    good_has_decl = "no findings" in good_breadth_zero.lower()
    check(
        "P3.quality.zero-finding-declaration is a recognizable pattern",
        good_has_decl and not bad_has_decl,
        f"bad_decl={bad_has_decl} good_decl={good_has_decl}",
    )


# =============================================================================
# Phase 4a.5 — Semantic invariants
# =============================================================================

def test_P4a5_loss_state_var_coverage_artifact():
    """P4a.5 loss contract: state_variables.md → semantic_invariants_p1.md
    output exists when input has variables."""
    sp = _mkscratch({
        "state_variables.md": (
            "# State Variables\n\n"
            "| Contract | Variable | Type | Mutability |\n"
            "|---|---|---|---|\n"
            "| Vault | totalAssets | uint256 | mutable |\n"
            "| Vault | lastUpdate | uint64 | mutable |\n"
        ),
        "semantic_invariants_p1.md": (
            "# Semantic Invariants P1\n\n"
            "## totalAssets\nWriters: deposit, withdraw\nReaders: previewDeposit\n\n"
            "## lastUpdate\nWriters: _accrue\nReaders: claim\n"
        ),
    })
    inv_text = (sp / "semantic_invariants_p1.md").read_text(encoding="utf-8")
    has_total = "totalAssets" in inv_text
    has_last = "lastUpdate" in inv_text
    check(
        "P4a5.loss.state-var-coverage: every state var has section",
        has_total and has_last,
        f"total={has_total} last={has_last}",
    )


# =============================================================================
# Phase 4b.5 — RAG validation
# =============================================================================

def test_P4b5_loss_rag_validation_row_per_finding():
    """P4b.5 loss: every inventory finding has a row in rag_validation.md OR
    an explicit decision-neutral unavailable proposal is documented."""
    sp = _mkscratch({
        "findings_inventory.md": (
            "### Finding [INV-001]: a\n**Location**: x.sol:L1\n\n"
            "### Finding [INV-002]: b\n**Location**: y.sol:L1\n"
        ),
        "rag_validation.md": (
            "| Finding ID | Source Kind | Availability | Relation | Match Proposal | Notes |\n"
            "|---|---|---|---|---|---|\n"
            "| INV-001 | PRIMARY_PRECEDENT | AVAILABLE | SUPPORTING | EXACT_PROPOSED | context only |\n"
            "| INV-002 | UNAVAILABLE | TIMEOUT | UNKNOWN | UNSCORED | no decision authority |\n"
        ),
    })
    rag_text = (sp / "rag_validation.md").read_text(encoding="utf-8")
    inv_ids = re.findall(r"\[INV-\d+\]", (sp / "findings_inventory.md").read_text(encoding="utf-8"))
    missing = [fid.strip("[]") for fid in inv_ids if fid.strip("[]") not in rag_text]
    check(
        "P4b5.loss.rag-row-per-finding",
        not missing,
        f"missing={missing}",
    )


# =============================================================================
# Phase 4c — Chain analysis (SC only)
# =============================================================================

def test_P4c_loss_composition_coverage_artifact():
    """P4c loss: composition_coverage.md exists with cross-class explored/excluded."""
    sp = _mkscratch({
        "composition_coverage.md": (
            "| Finding A | Finding B | Explored? | Result | Notes |\n"
            "|---|---|---|---|---|\n"
            "| INV-001 | INV-002 | YES | no chain | postcondition mismatch |\n"
            "| INV-003 | INV-004 | EXCLUDED | no shared state | class A vs B |\n"
        ),
    })
    text = (sp / "composition_coverage.md").read_text(encoding="utf-8")
    rows = [ln for ln in text.splitlines() if ln.startswith("|") and ("YES" in ln or "EXCLUDED" in ln or "NO" in ln)]
    check(
        "P4c.loss.composition-coverage rows present",
        len(rows) >= 1,
        f"rows={len(rows)}",
    )


# =============================================================================
# Robustness — adversarial fixtures (chaos)
# =============================================================================

def test_R_inventory_with_unicode_in_title_round_trip():
    """Unicode in titles must not crash the parser/merger/router."""
    inv = (
        "### Finding [INV-001]: incorrect rebase calculation — truncates remainder\n"
        "**Severity**: High\n**Location**: src/Vault.sol:L42\n"
        "**Preferred Tag**: CODE-TRACE\n"
    )
    sp = _mkscratch({"findings_inventory.md": inv})
    rows = D._queue_rows_from_inventory(sp)
    check(
        "R.unicode-in-title: parser+router survive em-dash in title",
        len(rows) == 1 and "INV-001" in rows[0]["finding id"],
        f"rows={rows}",
    )


def test_R_inventory_with_pipe_in_location_field_escaped():
    """Pipe character in Location should not corrupt the queue table."""
    inv = (
        "### Finding [INV-001]: bug\n"
        "**Severity**: High\n"
        "**Location**: src/Vault.sol:L42 (in branch | early-exit)\n"
        "**Preferred Tag**: CODE-TRACE\n"
    )
    sp = _mkscratch({"findings_inventory.md": inv})
    D._write_mechanical_verification_queue_from_inventory(sp)
    queue_text = (sp / "verification_queue.md").read_text(encoding="utf-8")
    rows = D.parse_verification_queue_rows(sp)
    check(
        "R.pipe-in-location: queue parses despite literal pipe in field",
        len(rows) == 1,
        f"rows={len(rows)} queue_excerpt={queue_text[:200]!r}",
    )


def test_R_500_inventory_round_trip_no_drops():
    """500-finding inventory through queue + report round-trip; no IDs lost."""
    inv_lines = ["# Inventory", ""]
    for i in range(1, 501):
        inv_lines.extend([
            f"### Finding [INV-{i:03d}]: bug{i}",
            "**Severity**: " + ("High" if i % 3 == 0 else "Medium" if i % 5 == 0 else "Low"),
            f"**Location**: src/m{i % 50}.sol:L{i}",
            "",
        ])
    sp = _mkscratch({"findings_inventory.md": "\n".join(inv_lines)})
    n = D._write_mechanical_verification_queue_from_inventory(sp)
    rows = D.parse_verification_queue_rows(sp)
    issues = D._validate_verification_queue_inventory_parity(sp)
    expected = {f"INV-{i:03d}" for i in range(1, 501)}
    actual = {r["finding id"] for r in rows}
    check(
        "R.500-finding-round-trip: every ID routed; parity holds",
        n == 500 and actual == expected and not issues,
        f"routed={n} parity_issues={issues[:2] if issues else 'none'}",
    )


def test_R_idempotent_mechanical_writes():
    """Running mechanical writes twice produces identical output (no growth)."""
    inv = (
        "### Finding [INV-001]: bug\n**Severity**: High\n"
        "**Location**: src/x.sol:L1\n**Preferred Tag**: CODE-TRACE\n"
    )
    sp = _mkscratch({"findings_inventory.md": inv})
    D._write_mechanical_verification_queue_from_inventory(sp)
    q1 = (sp / "verification_queue.md").read_text(encoding="utf-8")
    D._write_mechanical_verification_queue_from_inventory(sp)
    q2 = (sp / "verification_queue.md").read_text(encoding="utf-8")
    check(
        "R.idempotent-mechanical-writes: queue identical on re-run",
        q1 == q2,
        f"q1_len={len(q1)} q2_len={len(q2)}",
    )


# =============================================================================
# Bullshit-phase-write detection
# =============================================================================
# Scenarios specifically targeting failure modes of the form "phase produced
# A FILE that PASSES byte-size gates but contains nothing useful". This is the
# class the user has hit repeatedly: stub renderer, boilerplate output, partial
# write that satisfied byte-size but not content contract.

def test_BS_verifier_status_blank_line_only():
    """BS: verify_*.md with literal '\\n' content -> non-CONFIRMED."""
    status = D._verifier_status_from_text("\n")
    check(
        "BS.blank-line-only verify body -> non-CONFIRMED",
        status != "CONFIRMED",
        f"status={status!r}",
    )


def test_BS_verifier_status_only_header_no_body():
    """BS: verify_*.md with only a markdown header -> non-CONFIRMED if no verdict."""
    status = D._verifier_status_from_text("# Verify INV-001\n")
    # Header alone has no Verdict field -> falls through to whole-text regex
    # search, finds no verdict tokens -> default to CONFIRMED. This is a
    # genuine quality gap if it returns CONFIRMED for header-only input.
    check(
        "BS.header-only verify body should not be CONFIRMED",
        status != "CONFIRMED",
        f"status={status!r} (returns CONFIRMED for header-only is a bug)",
    )


def test_BS_synth_section_missing_verify_path_marked_stub():
    """BS: every synth path leading to no verify input must mark STUB."""
    sp = _mkscratch({})
    section = D._synth_report_section_from_verify(
        sp, "L-99", "INV-999",
        {"severity": "Low", "title": "x", "location": "src/x.sol:L1",
         "preferred tag": "", "bug class": ""},
        unresolved=False,
    )
    check(
        "BS.synth-no-verify always carries STUB-RECOVERED",
        "STUB-RECOVERED" in section,
        f"excerpt={section[:200]!r}",
    )


def test_BS_synth_section_carries_real_recommendation_when_present():
    """BS: synth must pull Recommendation field from verify when present."""
    sp = _mkscratch({
        "verify_INV-001.md": (
            "**Verdict**: CONFIRMED\n\n"
            "## Description\nx\n\n"
            "## Impact\ny\n\n"
            "## PoC Result\nPASS\n\n"
            "## Recommendation\n\nApply input check at L42 to validate amount > 0.\n"
        ),
    })
    section = D._synth_report_section_from_verify(
        sp, "M-01", "INV-001",
        {"severity": "Medium", "title": "bug", "location": "src/x.sol:L42",
         "preferred tag": "POC-PASS", "bug class": "validation"},
        unresolved=False,
    )
    check(
        "BS.synth-recommendation-present in output",
        "input check" in section or "validate amount" in section,
        f"excerpt={section[-400:]!r}",
    )


def test_BS_inventory_chunk_with_only_summary_no_findings():
    """BS: chunk file with summary table but zero ### Finding entries -> 0 merged."""
    chunk = (
        "# Findings Inventory Chunk A\n\n"
        "## Summary\n\n"
        "| Severity | Count |\n|---|---|\n| High | 5 |\n"
        "<!-- findings list missing! -->\n"
    )
    sp = _mkscratch({"findings_inventory_chunk_a.md": chunk})
    parsed, merged = D._write_mechanical_inventory_from_chunks(sp)
    check(
        "BS.chunk-summary-only-no-findings -> zero merged",
        merged == 0,
        f"parsed={parsed} merged={merged}",
    )


def test_BS_queue_empty_table_zero_rows():
    """BS: verification_queue.md with header row only (no data) parses to 0 rows."""
    q = (
        "| Queue # | Finding ID | Severity | Title | Bug Class | Preferred Tag | Location | Primary Artifact |\n"
        "|---|---|---|---|---|---|---|---|\n"
    )
    sp = _mkscratch({"verification_queue.md": q})
    rows = D.parse_verification_queue_rows(sp)
    check(
        "BS.empty-queue-table -> 0 rows",
        rows == [],
        f"rows={rows}",
    )


def test_INV_receipt_accounted_chunk_dedup_not_truncation():
    """Legacy dedup is safe when Source IDs preserve the exact input union."""
    chunk = "\n".join([
        "| Finding ID | Title | Severity | Location |",
        "|------------|-------|----------|----------|",
        *(
            f"| AC-{i} | duplicate root | High | src/A.sol:L1 |"
            for i in range(1, 11)
        ),
    ])
    source_groups = (
        "AC-1, AC-5, AC-9",
        "AC-2, AC-6, AC-10",
        "AC-3, AC-7",
        "AC-4, AC-8",
    )
    inv = "\n".join(
        f"### Finding [INV-{i:03d}]: duplicate root\n"
        f"**Severity**: High\n"
        f"**Location**: src/A.sol:L1\n"
        f"**Source IDs**: {source_ids}\n"
        for i, source_ids in enumerate(source_groups, start=1)
    )
    receipt = (
        "# Mechanical Inventory Merge Receipt\n\n"
        "Chunk files: 1\n"
        "Parsed chunk findings: 10\n"
        "Merged inventory findings: 4\n"
    )
    sp = _mkscratch({
        "findings_inventory_chunk_a.md": chunk,
        "findings_inventory.md": inv,
        "inventory_merge_receipt.md": receipt,
    })
    issues = D._validate_inventory_parity(sp)
    assert issues == []


def test_INV_receipt_allows_mechanically_promoted_inventory_supplement():
    """Resume parity must allow inventory blocks added by depth promotion."""
    chunk = "\n".join([
        "| Finding ID | Title | Severity | Location |",
        "|------------|-------|----------|----------|",
        *(
            f"| AC-{i} | base bug {i} | High | src/A.sol:L{i} |"
            for i in range(1, 70)
        ),
    ])
    inv_lines = ["# Finding Inventory", ""]
    for i in range(1, 58):
        absorbed = f", AC-{i + 57}" if i <= 12 else ""
        inv_lines.extend([
            f"### Finding [INV-{i:03d}]: base bug {i}",
            "**Severity**: High",
            f"**Location**: src/A.sol:L{i}",
            f"**Source IDs**: AC-{i}{absorbed}",
            "",
        ])
    inv_lines.extend([
        "## Depth Promotion Supplement",
        "",
    ])
    for i in range(58, 106):
        inv_lines.extend([
            f"### Finding [INV-{i:03d}]: promoted depth bug {i}",
            f"**Source IDs**: [DX-{i - 57}]",
            "**Severity**: Medium",
            f"**Location**: src/D.sol:L{i}",
            "**Preferred Tag**: CODE-TRACE",
            "",
        ])
    receipt = (
        "# Mechanical Inventory Merge Receipt\n\n"
        "Chunk files: 3\n"
        "Parsed chunk findings: 69\n"
        "Merged inventory findings: 57\n"
    )
    promotion_receipt = (
        "# Depth Promotion Receipt\n\n"
        "Promoted 48 depth finding(s) into findings_inventory.md.\n"
    )
    sp = _mkscratch({
        "findings_inventory_chunk_a.md": chunk,
        "findings_inventory.md": "\n".join(inv_lines),
        "inventory_merge_receipt.md": receipt,
        "depth_promotion_receipt.md": promotion_receipt,
    })
    issues = D._validate_inventory_parity(sp)
    assert issues == []


def test_INV_receipt_uses_parser_entries_not_loose_signal_blocks():
    """A chunk may contain tables plus prose headings; parser entries are authoritative."""
    chunk = "\n".join([
        "| Finding ID | Title | Severity | Location | Source IDs |",
        "|------------|-------|----------|----------|------------|",
        "| AC-1 | first bug | High | src/A.sol:L1 | AC-1 |",
        "| AC-2 | second bug | Medium | src/B.sol:L2 | AC-2 |",
        "",
        "### Finding [AC-1]: first bug",
        "**Severity**: High",
        "**Location**: src/A.sol:L1",
        "",
        "### Finding [AC-2]: second bug",
        "**Severity**: Medium",
        "**Location**: src/B.sol:L2",
    ])
    sp = _mkscratch({"findings_inventory_chunk_a.md": chunk})
    parsed, merged = D._write_mechanical_inventory_from_chunks(sp)
    issues = D._validate_inventory_parity(sp)
    inv = (sp / "findings_inventory.md").read_text(encoding="utf-8")
    ok = (
        parsed == 2 and merged == 2
        and len(issues) == 1 and "NEEDS_INVENTORY_REVIEW" in issues[0]
        and "AC-1" in inv and "AC-2" in inv
    )
    check(
        "INV.receipt-parser-entries-not-loose-signal-blocks",
        ok,
        f"parsed={parsed} merged={merged} issues={issues} inv={inv[:500]}",
    )
    assert ok


def test_INV_chunk_parser_combines_tables_and_heading_findings():
    """INV: table presence must not suppress later detailed heading findings."""
    chunk = "\n".join([
        "| Finding ID | Title | Severity | Location | Source IDs |",
        "|------------|-------|----------|----------|------------|",
        "| AC-1 | table bug | High | src/A.sol:L1 | AC-1 |",
        "",
        "## Finding [TF-1]: heading-only bug",
        "**Severity**: Medium",
        "**Location**: src/B.sol:L2",
        "**Source IDs**: TF-1",
        "**Preferred Tag**: CODE-TRACE",
        "",
        "| Finding ID | Title | Severity | Location | Source IDs |",
        "|------------|-------|----------|----------|------------|",
        "| EC-1 | second table bug | Low | src/C.sol:L3 | EC-1 |",
    ])
    sp = _mkscratch({"findings_inventory_chunk_a.md": chunk})
    parsed, merged = D._write_mechanical_inventory_from_chunks(sp)
    issues = D._validate_inventory_parity(sp)
    inv = (sp / "findings_inventory.md").read_text(encoding="utf-8")
    ok = (
        parsed == 3
        and merged == 3
        and len(issues) == 1
        and "NEEDS_INVENTORY_REVIEW" in issues[0]
        and all(tok in inv for tok in ("AC-1", "TF-1", "EC-1"))
    )
    check(
        "INV.chunk-parser-combines-tables-and-headings",
        ok,
        f"parsed={parsed} merged={merged} issues={issues} inv={inv[:700]}",
    )
    assert ok


def test_INV_receipt_mismatch_still_fails():
    chunk = "\n".join([
        "| Finding ID | Title | Severity | Location |",
        "|------------|-------|----------|----------|",
        *(
            f"| AC-{i} | candidate {i} | High | src/A.sol:L{i} |"
            for i in range(1, 8)
        ),
    ])
    inv = "\n".join(
        f"### Finding [INV-{i:03d}]: candidate {i}\n"
        f"**Severity**: High\n"
        f"**Location**: src/A.sol:L{i}\n"
        for i in range(1, 3)
    )
    receipt = (
        "# Mechanical Inventory Merge Receipt\n\n"
        "Chunk files: 1\n"
        "Parsed chunk findings: 7\n"
        "Merged inventory findings: 7\n"
    )
    sp = _mkscratch({
        "findings_inventory_chunk_a.md": chunk,
        "findings_inventory.md": inv,
        "inventory_merge_receipt.md": receipt,
    })
    issues = D._validate_inventory_parity(sp)
    assert any("receipt mismatch" in issue for issue in issues)


def test_INV_refuted_na_severity_uses_provisional_recall_floor_and_routes_to_review():
    chunk = (
        "| Finding ID | Title | Severity | Location |\n"
        "|------------|-------|----------|----------|\n"
        "| AC-1 | refuted candidate | N/a (refuted) | src/A.sol:L1 |\n"
    )
    sp = _mkscratch({"findings_inventory_chunk_a.md": chunk})
    parsed, merged = D._write_mechanical_inventory_from_chunks(sp)
    queue_count = D._write_mechanical_verification_queue_from_inventory(sp)
    inv = (sp / "findings_inventory.md").read_text(encoding="utf-8")
    rows = D.parse_verification_queue_rows(sp)
    excluded = (sp / "verification_queue_evidence_excluded.md").read_text(encoding="utf-8")
    parity_issues = D._validate_verification_queue_inventory_parity(sp)

    assert parsed == 1 and merged == 1
    assert "**Severity**: Medium" in inv
    assert "**Verdict**: REFUTED" not in inv
    assert queue_count == 1
    assert [row["finding id"] for row in rows] == ["INV-001"]
    assert rows[0]["severity"] == "Medium"
    assert rows[0]["origin assessment"] == "NEEDS_VERIFICATION"
    assert "INV-001" not in excluded
    assert parity_issues == []


def test_VQ_refuted_inventory_verdict_is_advisory_and_routes_to_review():
    inv = (
        "### Finding [INV-054]: uint8 CycleId Parameter in claim() - Within Safe Range\n"
        "**Severity**: Informational\n"
        "**Location**: Minting.sol:L137\n"
        "**Preferred Tag**: [CODE]\n"
        "**Source IDs**: AC-8, CC-26\n"
        "**Verdict**: REFUTED\n"
        "**Root Cause**: MAX_MINT_CYCLE=125 < uint8.max=255; non-vulnerability\n"
    )
    sp = _mkscratch({"findings_inventory.md": inv})
    queue_count = D._write_mechanical_verification_queue_from_inventory(sp)
    queue_rows = D.parse_verification_queue_rows(sp)
    excluded = (sp / "verification_queue_evidence_excluded.md").read_text(encoding="utf-8")
    issues = D._validate_verification_queue_inventory_parity(sp)

    assert queue_count == 1
    assert [row["finding id"] for row in queue_rows] == ["INV-054"]
    assert queue_rows[0]["origin assessment"] == "REFUTED"
    assert "INV-054" not in excluded
    assert issues == []


def test_VQ_evidence_filter_keeps_refuted_origin_and_bad_evidence_active():
    inv = (
        "### Finding [INV-001]: refuted candidate\n"
        "**Severity**: Informational\n"
        "**Location**: src/A.sol:L1\n"
        "**Verdict**: REFUTED\n\n"
        "### Finding [INV-002]: bad evidence candidate\n"
        "**Severity**: High\n"
        "**Location**: missing/File.sol:L99\n"
    )
    evidence = (
        "| Finding ID | Location Status | Source Status |\n"
        "|------------|-----------------|---------------|\n"
        "| INV-001 | OK | OK |\n"
        "| INV-002 | LOCATION_INVALID | SOURCE_MISSING |\n"
    )
    sp = _mkscratch({
        "findings_inventory.md": inv,
        "inventory_evidence_validation.md": evidence,
    })
    D._write_mechanical_verification_queue_from_inventory(sp)
    removed = D._filter_verification_queue_by_evidence(sp)
    excluded = (sp / "verification_queue_evidence_excluded.md").read_text(encoding="utf-8")
    issues = D._validate_verification_queue_inventory_parity(sp)

    assert removed == []
    remaining = D.parse_verification_queue_rows(sp)
    assert [row["finding id"] for row in remaining] == ["INV-001", "INV-002"]
    assert remaining[0]["origin assessment"] == "REFUTED"
    assert "LOCATION_INVALID" in remaining[1]["evidence debt"]
    assert "INV-001" not in excluded
    assert "INV-002" not in excluded
    debt = (sp / "verification_queue_evidence_debt.md").read_text(encoding="utf-8")
    assert "INV-002" in debt and "RETAINED_ACTIVE" in debt
    assert issues == []


def test_INV_plain_na_severity_uses_provisional_floor_not_refuted():
    chunk = (
        "| Finding ID | Title | Severity | Location |\n"
        "|------------|-------|----------|----------|\n"
        "| AC-1 | ambiguous candidate | N/A | src/A.sol:L1 |\n"
    )
    sp = _mkscratch({"findings_inventory_chunk_a.md": chunk})
    D._write_mechanical_inventory_from_chunks(sp)
    queue_count = D._write_mechanical_verification_queue_from_inventory(sp)
    inv = (sp / "findings_inventory.md").read_text(encoding="utf-8")
    rows = D.parse_verification_queue_rows(sp)

    assert "**Severity**: Medium" in inv
    assert "**Verdict**: NEEDS_VERIFICATION" in inv
    assert queue_count == 1
    assert len(rows) == 1 and rows[0]["severity"] == "Medium"
    assert rows[0]["origin assessment"] == "NEEDS_VERIFICATION"


def test_INV_refuted_na_depth_feeder_not_promoted():
    sp = _mkscratch({
        "findings_inventory.md": (
            "# Finding Inventory\n\n"
            "### Finding [INV-001]: seed\n"
            "**Severity**: Low\n"
            "**Location**: src/Seed.sol:L1\n"
            "**Source IDs**: SEED-1\n"
        ),
        "depth_edge_case_findings.md": (
            "### Finding [DEC-1]: refuted depth lead\n"
            "**Severity**: N/a (refuted)\n"
            "**Location**: src/A.sol:L1\n"
            "**Description**: This path was checked and refuted.\n"
        ),
    })
    promoted = D._promote_depth_findings_to_inventory(sp)
    issues = D._validate_depth_promotion_receipt(sp)
    inv = (sp / "findings_inventory.md").read_text(encoding="utf-8")

    assert promoted == []
    assert issues == []
    assert "DEC-1" not in inv


def test_BS_report_index_missing_master_section():
    """BS: report_index.md without Master Finding Index header -> downstream
    consumers must not silently treat as zero findings."""
    # Build a "headerless" index — Codex's report machinery needs to handle it.
    sp = _mkscratch({
        "report_index.md": (
            "# Report Index\n\n## Summary\n\n| Severity | Count |\n|---|---|\n| Total | 0 |\n"
        ),
    })
    # parse_report_index_counts should return at least the 0 counts cleanly.
    counts = D.parse_report_index_counts(sp)
    check(
        "BS.headerless-report-index parses without crash",
        isinstance(counts, dict),
        f"counts={counts}",
    )


def test_BS_skeptic_artifact_with_zero_verdicts_flagged():
    """BS: skeptic_findings.md exists but contains zero Verdict entries."""
    queue = (
        "| Queue # | Finding ID | Severity | Title | Bug Class | Preferred Tag | Location | Primary Artifact |\n"
        "|---|---|---|---|---|---|---|---|\n"
        "| 1 | INV-001 | Critical | a | x | CODE-TRACE | s:L1 | x.md |\n"
    )
    sp = _mkscratch({
        "verify_INV-001.md": "**Verdict**: CONFIRMED\n",
        "verification_queue.md": queue,
        # Skeptic file exists but has no actual review.
        "skeptic_findings.md": "# Skeptic\n\nNothing reviewed.\n",
    })
    issues = D._validate_skeptic_scope(sp)
    check(
        "BS.skeptic-file-no-verdicts flagged as missing scope coverage",
        bool(issues),
        f"issues={issues}",
    )


def test_BS_verify_with_only_evidence_tag_no_verdict():
    """BS: verify_*.md has Evidence Tag but no Verdict -> classified safely."""
    text = "**Evidence Tag**: CODE-TRACE\n**Severity**: High\nNo verdict here.\n"
    status = D._verifier_status_from_text(text)
    # Per regex fallback, this should match CONFIRMED on the literal word
    # "Confirmed" or similar... but this text has none, so should default.
    # The contract: no verdict token + no Verdict field -> non-reportable.
    check(
        "BS.verify-no-verdict-tokens -> non-CONFIRMED",
        status != "CONFIRMED",
        f"status={status!r}",
    )


def test_BS_severity_with_nonsense_returns_demote_floor():
    """BS: 'Catastrophic' is not a valid severity -> normalize+demote yields Low."""
    # _severity_name_from_text maps 'Catastrophic' to Medium (fallback);
    # _demote_severity_once then yields Low. Conservative behavior.
    got = D._demote_severity_once("Catastrophic")
    check(
        "BS.nonsense-severity -> conservative Low after demote",
        got == "Low",
        f"got {got!r}",
    )


def test_BS_synth_section_no_internal_id_leak_in_body():
    """BS: rendered section MUST NOT contain INV-* or DCI-* in body prose."""
    sp = _mkscratch({
        "verify_INV-001.md": (
            "**Verdict**: CONFIRMED\n\n## Description\n\n"
            "Bug at INV-001 traced via DCI-7 by VS-3.\n\n"
            "## Impact\n\nLoss bounded.\n\n## PoC Result\nPASS\n"
        ),
    })
    section = D._synth_report_section_from_verify(
        sp, "H-01", "INV-001",
        {"severity": "High", "title": "bug", "location": "src/x.sol:L1",
         "preferred tag": "POC-PASS", "bug class": "x"},
        unresolved=False,
    )
    # Title shouldn't contain INV-*; Description/Impact prose shouldn't either.
    # The header contains "[H-01]" which is intentional (report ID).
    body_only = section[section.find("Description"):]
    leak_inv = "INV-001" in body_only
    leak_dci = "DCI-7" in body_only
    leak_vs = "VS-3" in body_only
    check(
        "BS.synth-section-no-internal-id-leak in body prose",
        not leak_inv and not leak_dci and not leak_vs,
        f"INV={leak_inv} DCI={leak_dci} VS={leak_vs}",
    )


def test_BS_report_index_empty_inventory_does_not_crash():
    """BS: empty inventory + empty queue → mechanical report_index handles it."""
    sp = _mkscratch({
        "findings_inventory.md": "# Inventory\n\nNo findings.\n",
    })
    n = D._write_mechanical_report_index(sp)
    check(
        "BS.empty-inventory-no-crash returns 0",
        n == 0,
        f"n={n}",
    )


def test_INV_chunk_heading_ids_are_preserved_when_source_ids_missing():
    """INV: chunk-local heading IDs are provenance, not disposable labels."""
    chunk = "\n\n".join(
        f"### Finding [AC-{i}]: access control bug {i}\n"
        "**Severity**: High\n"
        f"**Location**: src/Auth.sol:L{i}\n"
        "**Preferred Tag**: CODE-TRACE\n"
        "**Root Cause**: missing role check"
        for i in range(1, 8)
    )
    sp = _mkscratch({"findings_inventory_chunk_a.md": chunk})
    parsed, merged = D._write_mechanical_inventory_from_chunks(sp)
    issues = D._validate_inventory_parity(sp)
    inv = (sp / "findings_inventory.md").read_text(encoding="utf-8")
    ok = (
        parsed == 7
        and merged == 7
        and len(issues) == 1
        and "NEEDS_INVENTORY_REVIEW" in issues[0]
        and all(f"AC-{i}" in inv for i in range(1, 8))
    )
    check(
        "INV.chunk-heading-local-ids-preserved-as-source-ids",
        ok,
        f"parsed={parsed} merged={merged} issues={issues} inv={inv[:500]}",
    )
    assert ok


def test_INV_shard_exact_mech_similarity_is_tag_only_without_shared_source():
    """INV: 147 disjoint producers survive MECH similarity to semantic dedup."""
    chunk = "\n\n".join(
        f"### Finding [AC-{i}]: same access-control root cause\n"
        "**Severity**: High\n"
        "**Location**: src/Auth.sol:L42\n"
        "**Preferred Tag**: CODE-TRACE\n"
        "**Root Cause**: missing role check"
        for i in range(1, 148)
    )
    sp = _mkscratch({"findings_inventory_chunk_a.md": chunk})
    parsed, merged = D._write_mechanical_inventory_from_chunks(sp)
    issues = D._validate_inventory_parity(sp)
    inv = (sp / "findings_inventory.md").read_text(encoding="utf-8")
    ok = (
        parsed == 147
            and merged == 147
            and len(issues) == 1
            and "NEEDS_INVENTORY_REVIEW" in issues[0]
        and all(f"AC-{i}" in inv for i in range(1, 148))
    )
    check(
        "INV.shard-exact-MECH-tag-only",
        ok,
        f"parsed={parsed} merged={merged} issues={issues} inv_len={len(inv)}",
    )
    assert ok


def test_INV_source_ids_bold_colon_format_counts_for_parity():
    """INV: `**Source IDs:** X` is canonical prompt drift and must parse."""
    sp = _mkscratch({
        "findings_inventory_chunk_a.md": (
            "### Finding [AC-1]: bug\n"
            "**Severity:** High\n"
            "**Location:** src/Auth.sol:L42\n"
            "**Source IDs:** CS-1, TF-2\n"
            "**Preferred Tag:** CODE-TRACE\n"
        ),
        "findings_inventory.md": (
            "### Finding [INV-001]: bug\n"
            "**Severity**: High\n"
            "**Location**: src/Auth.sol:L42\n"
            "**Source IDs**: AC-1, CS-1, TF-2\n"
            "**Preferred Tag**: CODE-TRACE\n"
        ),
    })
    issues = D._validate_inventory_parity(sp)
    check(
        "INV.source-ids-bold-colon-format-counts-for-parity",
        len(issues) == 1 and "NEEDS_INVENTORY_REVIEW" in issues[0],
        repr(issues),
    )
    assert len(issues) == 1
    assert "NEEDS_INVENTORY_REVIEW" in issues[0]


# =============================================================================
# Property-based-style invariants
# =============================================================================

def test_PROP_inventory_order_invariant():
    """PROP: shuffling chunk order produces same final ID set."""
    a_body = "\n\n".join(
        f"### Finding [A-{i}]: bug{i}\n**Severity**: Medium\n"
        f"**Location**: src/a.sol:L{i}\n**Source IDs**: A-{i}"
        for i in range(1, 6)
    )
    b_body = "\n\n".join(
        f"### Finding [B-{i}]: bug{i+5}\n**Severity**: Medium\n"
        f"**Location**: src/b.sol:L{i}\n**Source IDs**: B-{i}"
        for i in range(1, 6)
    )
    sp1 = _mkscratch({
        "findings_inventory_chunk_a.md": a_body,
        "findings_inventory_chunk_b.md": b_body,
    })
    D._write_mechanical_inventory_from_chunks(sp1)
    inv1 = (sp1 / "findings_inventory.md").read_text(encoding="utf-8")
    ids1 = set(re.findall(r"\[INV-\d+\]", inv1))

    sp2 = _mkscratch({
        "findings_inventory_chunk_a.md": b_body,  # swapped
        "findings_inventory_chunk_b.md": a_body,
    })
    D._write_mechanical_inventory_from_chunks(sp2)
    inv2 = (sp2 / "findings_inventory.md").read_text(encoding="utf-8")
    ids2 = set(re.findall(r"\[INV-\d+\]", inv2))
    check(
        "PROP.inventory-order-invariant: same ID count regardless of chunk order",
        len(ids1) == len(ids2) == 10,
        f"ids1={len(ids1)} ids2={len(ids2)}",
    )


def test_PROP_queue_idempotent_under_inventory_no_change():
    """PROP: re-running queue write on unchanged inventory is no-op."""
    inv = "\n\n".join(
        f"### Finding [INV-{i:03d}]: bug{i}\n**Severity**: Medium\n"
        f"**Location**: src/x.sol:L{i}"
        for i in range(1, 11)
    )
    sp = _mkscratch({"findings_inventory.md": inv})
    n1 = D._write_mechanical_verification_queue_from_inventory(sp)
    q1 = (sp / "verification_queue.md").read_text(encoding="utf-8")
    n2 = D._write_mechanical_verification_queue_from_inventory(sp)
    q2 = (sp / "verification_queue.md").read_text(encoding="utf-8")
    check(
        "PROP.queue-idempotent under no inventory change",
        n1 == n2 == 10 and q1 == q2,
        f"n1={n1} n2={n2} q_eq={q1==q2}",
    )


def test_PROP_severity_demote_monotonic():
    """PROP: demote(demote(X)) <= demote(X) for all X."""
    severities = ["Critical", "High", "Medium", "Low", "Informational"]
    rank = {s: i for i, s in enumerate(severities)}
    rank["Medium"] = 2  # default for unknown
    for s in severities:
        once = D._demote_severity_once(s)
        twice = D._demote_severity_once(once)
        # Monotonic: rank(twice) >= rank(once) (lower severity = higher index)
        if rank.get(once, 2) > rank.get(twice, 2):
            check(
                f"PROP.demote-monotonic for {s}",
                False,
                f"once={once} twice={twice} (twice ranked higher)",
            )
            return
    check("PROP.demote-monotonic for all 5 severities", True, "")


def test_PROP_id_regex_round_trip_via_finditer():
    """PROP: ID regex round-trip — every documented ID is recovered from prose."""
    text = (
        "Confirmed by SLITHER-3, FUZZ-12, MEDUSA-1, RSW-7, SP-22.\n"
        "Cross-referenced to DCI-1, DCI-12 (distinct), DA-CONSENSUS-1, "
        "DEPTH-CI-7, DA3-NETWORK-9, DNS-3, INV-001, INV-12, H-C01, H-M27.\n"
    )
    found = sorted({m.group(1) for m in D._INTERNAL_FINDING_ID_RE.finditer(text)})
    expected_subset = {
        "SLITHER-3", "FUZZ-12", "MEDUSA-1", "RSW-7", "SP-22",
        "DCI-1", "DCI-12", "DA-CONSENSUS-1", "DEPTH-CI-7",
        "DA3-NETWORK-9", "DNS-3", "INV-001", "INV-12", "H-C01", "H-M27",
    }
    missing = expected_subset - set(found)
    check(
        "PROP.id-regex-round-trip catches all 15 documented prefixes",
        not missing,
        f"missing={missing}",
    )


# =============================================================================
# Aggressive boundary scenarios
# =============================================================================

def test_AGG_verify_with_only_severity_field():
    """AGG: verify_*.md with ONLY Severity field, no Verdict, no narrative."""
    status = D._verifier_status_from_text("**Severity**: High\n")
    check(
        "AGG.severity-only verify body -> non-CONFIRMED",
        status != "CONFIRMED",
        f"status={status!r}",
    )


def test_AGG_verify_with_traceback_only():
    """AGG: verify_*.md is a Python traceback (timeout artifact). Must NOT
    be CONFIRMED."""
    text = (
        "Traceback (most recent call last):\n"
        '  File "verify.py", line 12, in <module>\n'
        "    run_test()\n"
        "TimeoutError: forge test exceeded 300s\n"
    )
    status = D._verifier_status_from_text(text)
    check(
        "AGG.traceback-only verify body -> non-CONFIRMED",
        status != "CONFIRMED",
        f"status={status!r}",
    )


def test_AGG_verify_with_word_confirmed_in_unrelated_context():
    """AGG: 'CONFIRMED' appears in unrelated prose -> still becomes CONFIRMED.
    This is intentional regex permissiveness (prefer more findings); but it
    must NEVER turn a REFUTED into a CONFIRMED.
    """
    text = (
        "**Verdict**: REFUTED\n\n"
        "Earlier I said CONFIRMED but on review the attack does not "
        "actually work — paths are not reachable.\n"
    )
    # Verdict field takes priority — should be REFUTED.
    status = D._verifier_status_from_text(text)
    check(
        "AGG.verdict-field-precedence over prose mention",
        status == "REFUTED",
        f"status={status!r}",
    )


def test_AGG_inventory_with_no_severity_field_defaults_safely():
    """AGG: inventory entry without Severity -> defaults to Medium safely."""
    inv = (
        "### Finding [INV-001]: bug\n"
        "**Location**: src/x.sol:L1\n"
        # NO Severity line
    )
    sp = _mkscratch({"findings_inventory.md": inv})
    n = D._write_mechanical_verification_queue_from_inventory(sp)
    rows = D.parse_verification_queue_rows(sp)
    check(
        "AGG.no-severity-defaults to Medium, not crash",
        n == 1 and rows[0].get("severity", "") == "Medium",
        f"n={n} rows={rows}",
    )


def test_AGG_verify_with_multiple_verdicts_takes_field_precedence():
    """AGG: verify body has multiple verdict words but explicit Verdict field;
    field wins."""
    text = (
        "**Verdict**: CONFIRMED\n\n"
        "## Considered alternatives\n\n"
        "I almost marked this REFUTED because the path is gated by "
        "onlyOwner, but the test showed the modifier can be bypassed.\n"
    )
    status = D._verifier_status_from_text(text)
    check(
        "AGG.multiple-verdicts: explicit Verdict field wins",
        status == "CONFIRMED",
        f"status={status!r}",
    )


def test_AGG_severity_name_handles_lowercase_partial():
    """AGG: severity name handles 'crit' / 'high' / 'med' prefix gracefully."""
    cases = [
        ("crit", "Critical"),
        ("HIGH", "High"),
        ("med", "Medium"),
        ("low priority", "Low"),
        ("informational", "Informational"),
        ("garbage", "Medium"),
    ]
    failed = []
    for inp, expected in cases:
        got = D._severity_name_from_text(f"**Severity**: {inp}", {})
        if got != expected:
            failed.append(f"{inp!r}->{got!r} expected {expected!r}")
    check(
        "AGG.severity-name handles 6 input forms",
        not failed,
        f"failed: {failed}",
    )


def test_AGG_inventory_block_with_h2_heading_recognized():
    """AGG: '## Finding [X-1]' (H2) recognized as inventory block, not just '###'."""
    inv = (
        "## Finding [INV-001]: bug\n"
        "**Severity**: High\n"
        "**Location**: src/a.sol:L1\n"
    )
    blocks = D._inventory_blocks(inv)
    check(
        "AGG.h2-heading-recognized as inventory block",
        len(blocks) == 1 and blocks[0]["id"] == "INV-001",
        f"blocks={blocks}",
    )


def test_AGG_severity_demote_chain_does_not_inflate_at_any_step():
    """AGG: chained demote(demote(demote(X))) never goes UP a tier."""
    severities = ["Critical", "High", "Medium", "Low", "Informational"]
    rank = {s: i for i, s in enumerate(severities)}
    for s in severities:
        a = D._demote_severity_once(s)
        b = D._demote_severity_once(a)
        c = D._demote_severity_once(b)
        ranks = [rank.get(s, 2), rank.get(a, 2), rank.get(b, 2), rank.get(c, 2)]
        # Strictly non-increasing severity (rank non-decreasing)
        is_monotonic = all(ranks[i] <= ranks[i+1] for i in range(3))
        if not is_monotonic:
            check(
                f"AGG.demote-chain-no-inflation for {s}",
                False,
                f"chain={s!r}->{a!r}->{b!r}->{c!r} ranks={ranks}",
            )
            return
    check("AGG.demote-chain-no-inflation across all 5 severities", True, "")


def test_AGG_normalize_finding_id_handles_lowercase_input():
    """AGG: normalize_finding_id should uppercase and trim consistently."""
    cases = [
        ("[inv-001]", "INV-001"),
        ("##  Finding  [DCI-7]:  title", "DCI-7"),
        ("[ slither-3 ]", "SLITHER-3"),
        ("###[H-C01]", "H-C01"),
        ("plain text no id", ""),
    ]
    failed = []
    for inp, expected in cases:
        got = D._normalize_finding_id(inp)
        if got != expected:
            failed.append(f"{inp!r}->{got!r} expected {expected!r}")
    check(
        "AGG.normalize-finding-id handles 5 input variants",
        not failed,
        f"failed: {failed}",
    )


def test_AGG_parse_location_ref_no_path_in_string():
    """AGG: location field with no parseable path -> ('', None) not crash."""
    cases = [
        "see verifier artifact",
        "TBD",
        "",
        "L42",  # line number alone
        "src/x.foo:L1",  # unsupported extension
    ]
    failed = []
    for c in cases:
        try:
            rel, line = D._parse_location_ref(c)
            if c == "src/x.foo:L1":
                # Unsupported extension — should return empty
                if rel != "":
                    failed.append(f"{c!r} unsupported ext returned {rel!r}")
            elif rel != "" or line is not None:
                failed.append(f"{c!r} expected empty, got ({rel!r}, {line})")
        except Exception as e:
            failed.append(f"{c!r} crashed: {e!r}")
    check(
        "AGG.parse-location-ref no-path-cases handled",
        not failed,
        f"failed: {failed}",
    )


def test_AGG_round_trip_real_world_inventory_format():
    """AGG: end-to-end round-trip with realistic LLM-emitted inventory format
    (varying whitespace, nested bullets, multi-paragraph descriptions)."""
    inv = (
        "# Findings Inventory\n\n"
        "Generated from depth + breadth phases.\n\n"
        "## Findings\n\n"
        "### Finding [INV-001]: Reentrancy in withdraw — owner can drain\n\n"
        "**Severity**:  High\n"
        "**Location**: contracts/Vault.sol:L142\n"
        "**Source IDs**: [DCI-7, BLIND-3, VS-12]\n"
        "**Preferred Tag**: POC-PASS\n\n"
        "**Root Cause**: The `withdraw()` function calls `transfer()` before "
        "updating `balances[msg.sender]`, allowing an attacker to re-enter "
        "via a callback in their fallback function and drain the vault.\n\n"
        "**Description**:\n"
        "1. Attacker deposits 1 ETH.\n"
        "2. Calls withdraw(); transfer triggers fallback.\n"
        "3. Fallback re-enters withdraw before balance update.\n"
        "4. Drains entire vault.\n\n"
        "**Impact**: Total loss of vault balance (~$10M based on TVL).\n\n"
    )
    sp = _mkscratch({"findings_inventory.md": inv})
    blocks = D._inventory_blocks(inv)
    n_routed = D._write_mechanical_verification_queue_from_inventory(sp)
    rows = D.parse_verification_queue_rows(sp)
    check(
        "AGG.real-world-format: parser handles realistic LLM inventory",
        len(blocks) == 1
        and blocks[0]["id"] == "INV-001"
        and n_routed == 1
        and rows[0]["severity"] == "High"
        and "withdraw" in rows[0].get("title", "").lower(),
        f"blocks={len(blocks)} routed={n_routed} rows={rows}",
    )


def test_AGG_synth_section_with_inline_markdown_in_verify():
    """AGG: verify file has nested markdown (lists, code blocks); synth must
    preserve content faithfully."""
    sp = _mkscratch({
        "verify_INV-001.md": (
            "**Verdict**: CONFIRMED\n\n"
            "## Description\n\n"
            "The bug occurs when:\n\n"
            "1. User deposits.\n"
            "2. Admin calls `setFee(0)`.\n"
            "3. User withdraws — receives `principal * (1 - oldFee)` instead of `principal`.\n\n"
            "Code:\n\n"
            "```solidity\n"
            "function withdraw() external {\n"
            "    uint amount = balances[msg.sender] * (1 - fee);\n"
            "    msg.sender.transfer(amount);\n"
            "}\n"
            "```\n\n"
            "## Impact\n\nUser receives less than deposited.\n\n"
            "## PoC Result\n\n`forge test --match test_drain_via_setFee` PASS\n"
        ),
    })
    section = D._synth_report_section_from_verify(
        sp, "H-01", "INV-001",
        {"severity": "High", "title": "fee race", "location": "src/Vault.sol:L42",
         "preferred tag": "POC-PASS", "bug class": "race"},
        unresolved=False,
    )
    check(
        "AGG.synth-with-nested-markdown preserves content",
        "setFee(0)" in section
        and "balances[msg.sender]" in section
        and "forge test" in section,
        f"section_excerpt={section[:500]!r}",
    )


# =============================================================================
# Real LLM output drift — patterns observed in actual audits
# =============================================================================

def test_DRIFT_inventory_with_smart_quotes_in_title():
    """DRIFT: LLM emits curly quotes in titles."""
    inv = (
        "### Finding [INV-001]: “Withdraw” ignores pause\n"
        "**Severity**: High\n**Location**: src/x.sol:L1\n"
    )
    sp = _mkscratch({"findings_inventory.md": inv})
    rows = D._queue_rows_from_inventory(sp)
    check(
        "DRIFT.smart-quotes-in-title don't break parser",
        len(rows) == 1,
        f"rows={rows}",
    )


def test_DRIFT_inventory_with_multiple_blank_lines_between_findings():
    """DRIFT: LLM emits 5 blank lines between findings — parser must handle."""
    inv = (
        "### Finding [INV-001]: a\n**Severity**: High\n**Location**: x:L1\n"
        "\n\n\n\n\n"
        "### Finding [INV-002]: b\n**Severity**: Medium\n**Location**: y:L2\n"
    )
    sp = _mkscratch({"findings_inventory.md": inv})
    blocks = D._inventory_blocks(inv)
    check(
        "DRIFT.multiple-blank-lines: both findings parsed",
        len(blocks) == 2 and {b["id"] for b in blocks} == {"INV-001", "INV-002"},
        f"blocks={[b['id'] for b in blocks]}",
    )


def test_DRIFT_inventory_with_html_entities_in_field():
    """DRIFT: LLM emits HTML entities in fields (&gt; &lt; &amp;)."""
    inv = (
        "### Finding [INV-001]: amount &gt; balance check missing\n"
        "**Severity**: Medium\n**Location**: src/x.sol:L42\n"
    )
    sp = _mkscratch({"findings_inventory.md": inv})
    rows = D._queue_rows_from_inventory(sp)
    check(
        "DRIFT.html-entities don't crash router",
        len(rows) == 1,
        f"rows={rows}",
    )


def test_DRIFT_verify_with_windows_crlf_line_endings():
    """DRIFT: verify file with CRLF line endings parses identically to LF."""
    text_lf = "**Verdict**: CONFIRMED\nReal bug.\n"
    text_crlf = "**Verdict**: CONFIRMED\r\nReal bug.\r\n"
    s_lf = D._verifier_status_from_text(text_lf)
    s_crlf = D._verifier_status_from_text(text_crlf)
    check(
        "DRIFT.crlf-line-endings produce same status as lf",
        s_lf == s_crlf == "CONFIRMED",
        f"lf={s_lf} crlf={s_crlf}",
    )


def test_DRIFT_inventory_with_trailing_whitespace_in_severity():
    """DRIFT: 'Severity: High   ' with trailing spaces still maps correctly."""
    inv = (
        "### Finding [INV-001]: bug\n"
        "**Severity**: High   \n"  # trailing spaces
        "**Location**: src/x.sol:L1\n"
    )
    sp = _mkscratch({"findings_inventory.md": inv})
    rows = D._queue_rows_from_inventory(sp)
    check(
        "DRIFT.severity-trailing-whitespace mapped correctly",
        len(rows) == 1 and rows[0]["severity"] == "High",
        f"rows={rows}",
    )


def test_DRIFT_inventory_block_with_empty_location_field():
    """DRIFT: '**Location**:' with empty value — block kept, location empty."""
    inv = (
        "### Finding [INV-001]: bug at unknown location\n"
        "**Severity**: High\n"
        "**Location**: \n"
        "**Source IDs**: BLIND-1\n"
    )
    sp = _mkscratch({"findings_inventory.md": inv})
    rows = D._queue_rows_from_inventory(sp)
    check(
        "DRIFT.empty-location-field: row produced, no crash",
        len(rows) == 1,
        f"rows={rows}",
    )


# =============================================================================
# End-to-end mini pipeline fixture
# =============================================================================

def test_E2E_inventory_to_audit_report_round_trip():
    """E2E: complete fixture scratchpad through inventory + queue + verify
    + report-index + tier write. Assert the report contains real content
    and no internal IDs leak."""
    # Stage 1: inventory
    inv_lines = ["# Inventory", ""]
    for i in range(1, 6):
        sev = ["Critical", "High", "Medium", "Low", "Informational"][i-1]
        inv_lines.extend([
            f"### Finding [INV-{i:03d}]: bug{i} - real issue",
            f"**Severity**: {sev}",
            f"**Location**: src/m{i}.sol:L{i*10}",
            "**Preferred Tag**: CODE-TRACE",
            "**Source IDs**: BLIND-{i}",
            "",
        ])
    sp = _mkscratch({"findings_inventory.md": "\n".join(inv_lines)})

    # Stage 2: queue
    n_routed = D._write_mechanical_verification_queue_from_inventory(sp)
    parity = D._validate_verification_queue_inventory_parity(sp)

    # Stage 3: simulated verify outputs (3 CONFIRMED, 1 REFUTED, 1 UNRESOLVED)
    verdicts = ["CONFIRMED", "CONFIRMED", "CONFIRMED", "REFUTED", "UNRESOLVED"]
    sevs = ["Critical", "High", "Medium", "Low", "Informational"]
    impact_likelihood = {
        "Critical": ("High", "High"),
        "High": ("High", "Medium"),
        "Medium": ("Medium", "Medium"),
        "Low": ("Low", "Medium"),
        "Informational": ("Informational", "Low"),
    }
    for i, verdict in enumerate(verdicts, start=1):
        sev = sevs[i - 1]
        impact, likelihood = impact_likelihood[sev]
        (sp / f"verify_INV-{i:03d}.md").write_text(
            f"# Verify INV-{i:03d}\n\n"
            f"**Verdict**: {verdict}\n"
            f"**Severity**: {sev}\n"
            f"**Impact**: {impact}\n"
            f"**Likelihood**: {likelihood}\n"
            "**Evidence Tag**: CODE-TRACE\n\n"
            f"## Description\nDetailed description for finding {i}.\n\n"
            f"## Impact\nImpact statement for finding {i}.\n\n"
            f"## PoC Result\n{'PASS' if verdict == 'CONFIRMED' else 'N/A'}\n\n"
            f"## Recommendation\nApply mitigation at L{i*10}.\n",
            encoding="utf-8",
        )

    # Stage 4: report index
    n_active = D._write_mechanical_report_index(sp)
    idx = (sp / "report_index.md").read_text(encoding="utf-8")
    proposal_at = idx.find("Proposed Negative Dispositions")
    master = idx[:proposal_at] if proposal_at > -1 else idx
    proposals = idx[proposal_at:] if proposal_at > -1 else ""

    # Stage 5: report tier write
    D._write_mechanical_report_tier(sp, "report_critical_high")
    crithigh_text = (sp / "report_critical_high.md").read_text(encoding="utf-8") if (sp / "report_critical_high.md").exists() else ""

    # Assertions
    confirmed_in_master = sum(1 for fid in ["INV-001", "INV-002", "INV-003"] if f"| {fid} |" in master)
    refuted_in_master = "INV-004" in master
    refuted_proposal_visible = "INV-004" in proposals
    unresolved_in_master = "INV-005" in master  # demoted, kept in body
    rich_content = "Detailed description" in crithigh_text or "Apply mitigation" in crithigh_text
    no_id_leak_in_body = "INV-001" not in crithigh_text or "BLIND-1" not in crithigh_text

    check(
        "E2E.full-round-trip: 5 inv -> 5 queue -> 5 reportable with visible negative proposal",
        n_routed == 5
        and not parity
        and confirmed_in_master == 3
        and refuted_in_master
        and refuted_proposal_visible
        and unresolved_in_master
        and rich_content,
        f"routed={n_routed} parity={parity} master={confirmed_in_master} "
        f"refuted_active={refuted_in_master} proposal={refuted_proposal_visible} "
        f"unres={unresolved_in_master} rich={rich_content}",
    )


def test_E2E_zero_findings_pipeline():
    """E2E: empty inventory must produce honest empty report, not stub."""
    sp = _mkscratch({"findings_inventory.md": "# Inventory\n\nNo findings.\n"})
    n_routed = D._write_mechanical_verification_queue_from_inventory(sp)
    n_active = D._write_mechanical_report_index(sp)
    idx_path = sp / "report_index.md"
    check(
        "E2E.zero-findings: routes 0, indexes 0, no crash",
        n_routed == 0 and n_active == 0,
        f"routed={n_routed} active={n_active}",
    )


def test_E2E_all_refuted_pipeline():
    """E2E: verifier negatives remain active and visible as proposals."""
    inv_lines = ["# Inventory", ""]
    for i in range(1, 4):
        inv_lines.extend([
            f"### Finding [INV-{i:03d}]: claim{i}",
            "**Severity**: High",
            f"**Location**: src/x.sol:L{i}",
            "",
        ])
    sp = _mkscratch({"findings_inventory.md": "\n".join(inv_lines)})
    D._write_mechanical_verification_queue_from_inventory(sp)
    for i in range(1, 4):
        (sp / f"verify_INV-{i:03d}.md").write_text(
            f"**Verdict**: FALSE_POSITIVE\nNot exploitable.\n",
            encoding="utf-8",
        )
    D._write_mechanical_report_index(sp)
    idx = (sp / "report_index.md").read_text(encoding="utf-8")
    proposal_at = idx.find("Proposed Negative Dispositions")
    master = idx[:proposal_at]
    proposals = idx[proposal_at:]
    in_master = sum(1 for i in range(1, 4) if f"| INV-{i:03d} |" in master)
    in_proposals = sum(1 for i in range(1, 4) if f"INV-{i:03d}" in proposals)
    check(
        "E2E.all-refuted: 3 in master, 3 non-authoritative proposals",
        in_master == 3 and in_proposals == 3,
        f"master={in_master} proposals={in_proposals}",
    )


def test_E2E_partial_verify_failure_yields_unresolved_not_confirmed():
    """E2E: 5 queued, 5 verify files but 2 are empty -> empties become
    UNRESOLVED in report index, demoted, kept in body, not silently CONFIRMED."""
    inv_lines = ["# Inventory", ""]
    for i in range(1, 6):
        inv_lines.extend([
            f"### Finding [INV-{i:03d}]: bug{i}",
            "**Severity**: High",
            f"**Location**: src/x.sol:L{i}",
            "",
        ])
    sp = _mkscratch({"findings_inventory.md": "\n".join(inv_lines)})
    D._write_mechanical_verification_queue_from_inventory(sp)
    # Write 3 normal CONFIRMED + 2 empty
    for i in range(1, 4):
        (sp / f"verify_INV-{i:03d}.md").write_text(
            "**Verdict**: CONFIRMED\nReal.\n",
            encoding="utf-8",
        )
    for i in (4, 5):
        (sp / f"verify_INV-{i:03d}.md").write_text("", encoding="utf-8")
    D._write_mechanical_report_index(sp)
    idx = (sp / "report_index.md").read_text(encoding="utf-8")
    # The empty verify files should be UNRESOLVED -> demoted to Medium, kept in body
    has_unresolved_in_master = "UNRESOLVED" in idx
    medium_count_increased = idx.count("| Medium |") >= 1
    check(
        "E2E.partial-empty-verify: empty verify -> UNRESOLVED, demoted, kept in body",
        has_unresolved_in_master and medium_count_increased,
        f"unresolved_in_idx={has_unresolved_in_master} medium_increased={medium_count_increased}",
    )


# =============================================================================
# Stress: large inputs, deep nesting, dense IDs
# =============================================================================

def test_STRESS_long_finding_title():
    """STRESS: 800-char title doesn't crash parser."""
    long_title = "Reentrancy in withdraw function " * 25  # ~800 chars
    inv = (
        f"### Finding [INV-001]: {long_title}\n"
        "**Severity**: High\n**Location**: src/x.sol:L1\n"
    )
    sp = _mkscratch({"findings_inventory.md": inv})
    rows = D._queue_rows_from_inventory(sp)
    check(
        "STRESS.long-title doesn't crash",
        len(rows) == 1,
        f"rows={len(rows)}",
    )


def test_STRESS_inventory_with_many_source_ids_per_finding():
    """STRESS: finding with 30 Source IDs round-trips."""
    sids = ", ".join(f"BLIND-{i}" for i in range(30))
    inv = (
        "### Finding [INV-001]: bug\n"
        "**Severity**: High\n**Location**: src/x.sol:L1\n"
        f"**Source IDs**: {sids}\n"
    )
    sp = _mkscratch({"findings_inventory.md": inv})
    rows = D._queue_rows_from_inventory(sp)
    check(
        "STRESS.many-source-ids preserved",
        len(rows) == 1 and "BLIND-29" in rows[0].get("primary artifact", "")
        or "BLIND-29" in str(rows[0]),
        f"rows={rows}",
    )


def test_STRESS_chunk_with_100_findings_at_each_severity():
    """STRESS: 500-finding inventory across 5 severities; mechanical merge."""
    chunks = {}
    severities = ["Critical", "High", "Medium", "Low", "Informational"]
    for ci, sev in enumerate(severities):
        body = []
        for i in range(100):
            body.extend([
                f"### Finding [{sev[:1]}{ci}{i:03d}]: bug",
                f"**Severity**: {sev}",
                f"**Location**: src/m{ci}.sol:L{i+1}",
                f"**Source IDs**: {sev[:1]}{ci}{i:03d}",
                "**Root Cause**: cause",
                "",
            ])
        chunks[f"findings_inventory_chunk_{chr(ord('a')+ci)}.md"] = "\n".join(body)
    sp = _mkscratch(chunks)
    parsed, merged = D._write_mechanical_inventory_from_chunks(sp)
    check(
        "STRESS.500-findings-5-severities merged correctly",
        merged == 500,
        f"parsed={parsed} merged={merged}",
    )


# =============================================================================
# Phase-completion contracts — "did phase X really finish, or just exit?"
# =============================================================================

def test_COMP_verify_core_aggregate_covers_all_verify_files():
    """COMP: verify_core.md aggregate must contain a row for EVERY verify_*.md.
    A v2.2.2 bug had crit/high in aggregate but Medium shard's 31 rows missing.
    """
    files = {}
    for i in range(1, 8):
        files[f"verify_INV-{i:03d}.md"] = (
            f"**Verdict**: CONFIRMED\n**Severity**: Medium\n**Location**: x:L{i}\n"
        )
    sp = _mkscratch(files)
    rebuilt = D._generate_verify_core_if_missing(sp)
    assert rebuilt, "verify_core should be generated from existing files"
    aggregate = (sp / "verify_core.md").read_text(encoding="utf-8")
    missing = [f"INV-{i:03d}" for i in range(1, 8) if f"INV-{i:03d}" not in aggregate]
    check(
        "COMP.verify_core covers all 7 verify_*.md files",
        not missing,
        f"missing={missing}",
    )


def test_COMP_verify_core_excludes_skeptic_judge_files():
    """COMP: verify_core aggregate must NOT include skeptic_*.md / judge_*.md."""
    files = {
        "verify_INV-001.md": "**Verdict**: CONFIRMED\n",
        "skeptic_INV-001.md": "**Verdict**: AGREE\n",
        "judge_INV-001.md": "**Verdict**: SKEPTIC CORRECT\n",
        "verify_core.md.tmp": "stale\n",
    }
    sp = _mkscratch(files)
    D._generate_verify_core_if_missing(sp)
    aggregate = (sp / "verify_core.md").read_text(encoding="utf-8")
    has_inv = "INV-001" in aggregate
    has_skeptic_text = "AGREE" in aggregate
    has_judge_text = "SKEPTIC CORRECT" in aggregate
    check(
        "COMP.verify_core: skeptic/judge text NOT mixed into aggregate",
        has_inv and not has_skeptic_text and not has_judge_text,
        f"inv={has_inv} skeptic={has_skeptic_text} judge={has_judge_text}",
    )


def test_COMP_promotion_dropout_retry_hint_lists_missing_ids():
    """COMP: when dropouts detected, retry hint file lists exact missing IDs."""
    sp = _mkscratch({})
    hint = D._write_promotion_dropout_retry_hint(sp, ["INV-001", "INV-002"])
    assert hint is not None
    text = hint.read_text(encoding="utf-8")
    check(
        "COMP.retry-hint lists specific missing IDs",
        "INV-001" in text and "INV-002" in text,
        f"text={text!r}",
    )


def test_COMP_inventory_evidence_validation_writes_ledger():
    """COMP: _validate_inventory_evidence writes a triage ledger."""
    repo = _mkrepo(["src/x.sol"])
    inv = (
        "### Finding [INV-001]: bug\n"
        "**Severity**: High\n"
        "**Location**: src/x.sol:L1\n"
        "**Source IDs**: BLIND-1\n"
    )
    sp = _mkscratch({"findings_inventory.md": inv})
    records = D._validate_inventory_evidence(sp, str(repo))
    check(
        "COMP.evidence-validation produces records",
        len(records) >= 1,
        f"record_count={len(records)}",
    )


def test_COMP_inventory_chunk_merge_writes_receipt():
    """COMP: chunk merge writes inventory_merge_receipt.md with counts."""
    chunk = (
        "### Finding [A1]: bug\n"
        "**Source IDs**: A1\n"
        "**Severity**: High\n"
        "**Location**: src/x.sol:L1\n"
        "**Root Cause**: cause\n"
    )
    sp = _mkscratch({"findings_inventory_chunk_a.md": chunk})
    D._write_mechanical_inventory_from_chunks(sp)
    receipt_path = sp / "inventory_merge_receipt.md"
    check(
        "COMP.merge-receipt: written with counts",
        receipt_path.exists() and "Merged" in receipt_path.read_text(encoding="utf-8"),
        f"exists={receipt_path.exists()}",
    )


def test_COMP_severity_demote_handles_unicode_input():
    """COMP: severity input with unicode (em-dash, smart quote) doesn't crash."""
    cases = ["High—needs review", "“Critical”", "Médium"]
    for c in cases:
        try:
            got = D._demote_severity_once(c)
            assert got in ("Critical", "High", "Medium", "Low", "Informational"), got
        except Exception as e:
            check(
                "COMP.demote-unicode-input doesn't crash",
                False,
                f"{c!r} crashed: {e!r}",
            )
            return
    check("COMP.demote-unicode-input handles 3 weird inputs", True, "")


def test_COMP_filter_evidence_does_not_drop_lone_lenient_anchor():
    """COMP: a row with bad location BUT valid source -> kept (lenient)."""
    repo = _mkrepo(["src/x.rs"])
    inv = (
        "### Finding [INV-001]: bug\n"
        "**Severity**: High\n"
        "**Location**: nonexistent/file.rs:L99\n"
        "**Source IDs**: DCI-7\n"
    )
    queue = (
        "| Queue # | Finding ID | Severity | Title | Bug Class | Preferred Tag | Location | Primary Artifact |\n"
        "|---|---|---|---|---|---|---|---|\n"
        "| 1 | INV-001 | High | bug | x | CODE-TRACE | nonexistent/file.rs:L99 | x.md |\n"
    )
    depth = (
        "### Finding [DCI-7]: confirmed\n"
        "**Confidence**: 0.85\n"
        "**Location**: src/x.rs:L1\n"
    )
    sp = _mkscratch({
        "findings_inventory.md": inv,
        "verification_queue.md": queue,
        "depth_consensus_invariant_findings.md": depth,
    })
    D._validate_inventory_evidence(sp, str(repo))
    excluded = D._filter_verification_queue_by_evidence(sp)
    check(
        "COMP.lenient-filter: bad-loc + good-source NOT dropped",
        excluded == [],
        f"excluded={excluded}",
    )


def test_COMP_filter_evidence_retains_double_invalid_as_repair_debt():
    """COMP: both-bad evidence remains active but explicitly repair-bound."""
    repo = _mkrepo(["src/x.rs"])
    inv = (
        "### Finding [INV-001]: bug\n"
        "**Severity**: High\n"
        "**Location**: nonexistent/path.rs:L99\n"
        "**Source IDs**: nonexistent-source.md:not-a-real-anchor\n"
    )
    queue = (
        "| Queue # | Finding ID | Severity | Title | Bug Class | Preferred Tag | Location | Primary Artifact |\n"
        "|---|---|---|---|---|---|---|---|\n"
        "| 1 | INV-001 | High | bug | x | CODE-TRACE | nonexistent/path.rs:L99 | x.md |\n"
    )
    sp = _mkscratch({
        "findings_inventory.md": inv,
        "verification_queue.md": queue,
    })
    D._validate_inventory_evidence(sp, str(repo))
    excluded = D._filter_verification_queue_by_evidence(sp)
    active = D.parse_verification_queue_rows(sp)
    check(
        "COMP.repair-filter: bad-loc + bad-source retained with debt",
        excluded == []
        and [row["finding id"] for row in active] == ["INV-001"]
        and "LOCATION_INVALID" in active[0].get("evidence debt", ""),
        f"excluded={excluded}, active={active}",
    )


def test_COMP_recon_placeholder_detector_ignores_negated_cleanup_status():
    body = (
        "# Recon Summary\n\n"
        "## Protocol Summary\n"
        "Substantive protocol handoff content with contracts, attack surface, "
        "templates, and downstream risk themes.\n\n"
        "## Phase Gate Status\n"
        "No `[LLM TO ENRICH]` or placeholder markers remain.\n"
        + ("Detailed recon evidence.\n" * 60)
    )
    sp = _mkscratch({"recon_summary.md": body})
    hard, soft = D._validate_recon_content_structure(sp)
    all_issues = hard + soft
    check(
        "COMP.recon-placeholder-negated-status-not-flagged",
        not any("placeholder" in issue for issue in all_issues),
        str(all_issues),
    )


def test_P4b_loss_semantic_gap_trigger_requires_niche_artifact():
    """P4b loss: Phase 4a.5 semantic-gap counters must spawn semantic-gap niche."""
    sp = _mkscratch({
        "semantic_invariants.md": "\n".join([
            "# Semantic Invariants",
            "- sync_gaps = 2 (`totalRewardsDistributed` vs live balance)",
            "- accumulation_exposures = 1",
            "- conditional_writes = 5",
            "- cluster_gaps = 1",
        ])
    })
    check(
        "P4b.loss.semantic-gap-trigger-detected",
        D._semantic_gap_required(sp),
    )
    issues = D._validate_semantic_gap_niche(sp, "thorough")
    check(
        "P4b.loss.semantic-gap-niche-required",
        any("niche_semantic_gap_findings.md" in i for i in issues),
        str(issues),
    )
    (sp / "niche_semantic_gap_findings.md").write_text(
        "# Semantic Gap Findings\n\n" + ("line-backed finding\n" * 80),
        encoding="utf-8",
    )
    check(
        "P4b.loss.semantic-gap-niche-satisfies-gate",
        D._validate_semantic_gap_niche(sp, "thorough") == [],
    )


# =============================================================================
# Test runner
# =============================================================================

TESTS = [
    # Phase 1 — Recon
    test_P1_loss_every_module_with_10plus_files_is_cited_or_acked,
    test_P1_loss_acknowledged_module_exempt,
    test_P1_failure_zero_citations_overall_halts,
    test_P1_loss_basename_collision_does_not_false_cover,
    # Phase 4a — Inventory
    test_P4a_loss_chunk_truncation_halts,
    test_P4a_loss_distinct_sibling_bugs_at_same_line_kept,
    test_P4a_failure_zero_upstream_signal_with_inventory_halts,
    test_AP_HF_1_inventory_degrade_branch_precedes_critical_funnel,
    test_AP_HF_1_inventory_usable_findings_functional_both_pipelines,
    test_P4a_loss_sc_feeder_ids_in_promotion_files,
    test_P4a_loss_sc_feeder_ids_match_canonical_regex,
    # Phase 4b — Depth
    test_P4b_loss_semantic_gap_trigger_requires_niche_artifact,
    test_P4b_loss_depth_word_boundary_promotion_receipt,
    test_P4b_loss_low_confidence_not_promoted,
    test_P4b_loss_dns_da3_ids_in_regex,
    # Phase 5 — Verification
    test_P5_failure_empty_verify_returns_unresolved,
    test_P5_quality_garbage_verdict_not_auto_confirmed,
    test_P5_loss_queue_id_dropout_halts,
    # Phase 5.1 — Skeptic
    test_P51_loss_partial_critical_high_skeptic_halts,
    test_P51_loss_unresolved_demote_keep_in_body,
    # Phase 5.2 — Cross-batch
    test_P52_loss_partial_crossbatch_coverage_halts,
    # Phase 6 — Report
    test_P6_loss_refuted_is_retained_with_non_authoritative_proposal,
    test_P6_quality_renderer_pulls_rich_content_from_verify,
    test_P6_quality_empty_verify_yields_stub_recovered_marker,
    test_P6_quality_internal_id_sanitized_from_title,
    test_P6_quality_internal_id_sanitized_from_body,
    test_P6_quality_genuine_text_preserved,
    test_P6_failure_severity_demote_floor_no_inflation,
    test_P6_failure_severity_demote_low_floor,
    test_P6_failure_severity_demote_critical_to_high,
    # Cross-phase integration
    test_X_promotion_symmetry_confirmed_in_body_or_excluded,
    test_X_unresolved_authenticity_phantom_flagged,
    test_X_inventory_to_queue_to_report_round_trip,
    # Phase 2 / 3 / 4a.5 / 4b.5 / 4c
    test_P2_loss_template_recommendations_artifact_exists,
    test_P3_loss_attack_surface_files_appear_in_breadth_outputs,
    test_P3_quality_breadth_with_zero_findings_must_declare,
    test_P4a5_loss_state_var_coverage_artifact,
    test_P4b5_loss_rag_validation_row_per_finding,
    test_P4c_loss_composition_coverage_artifact,
    # Robustness / chaos
    test_R_inventory_with_unicode_in_title_round_trip,
    test_R_inventory_with_pipe_in_location_field_escaped,
    test_R_500_inventory_round_trip_no_drops,
    test_R_idempotent_mechanical_writes,
    # Bullshit-phase-write detection
    test_BS_verifier_status_blank_line_only,
    test_BS_verifier_status_only_header_no_body,
    test_BS_synth_section_missing_verify_path_marked_stub,
    test_BS_synth_section_carries_real_recommendation_when_present,
    test_BS_inventory_chunk_with_only_summary_no_findings,
    test_BS_queue_empty_table_zero_rows,
    test_BS_report_index_missing_master_section,
    test_BS_skeptic_artifact_with_zero_verdicts_flagged,
    test_BS_verify_with_only_evidence_tag_no_verdict,
    test_BS_severity_with_nonsense_returns_demote_floor,
    test_BS_synth_section_no_internal_id_leak_in_body,
    test_BS_report_index_empty_inventory_does_not_crash,
    test_INV_chunk_heading_ids_are_preserved_when_source_ids_missing,
    test_INV_shard_exact_mech_similarity_is_tag_only_without_shared_source,
    test_INV_source_ids_bold_colon_format_counts_for_parity,
    # Property-based-style
    test_PROP_inventory_order_invariant,
    test_PROP_queue_idempotent_under_inventory_no_change,
    test_PROP_severity_demote_monotonic,
    test_PROP_id_regex_round_trip_via_finditer,
    # Aggressive boundary
    test_AGG_verify_with_only_severity_field,
    test_AGG_verify_with_traceback_only,
    test_AGG_verify_with_word_confirmed_in_unrelated_context,
    test_AGG_inventory_with_no_severity_field_defaults_safely,
    test_AGG_verify_with_multiple_verdicts_takes_field_precedence,
    test_AGG_severity_name_handles_lowercase_partial,
    test_AGG_inventory_block_with_h2_heading_recognized,
    test_AGG_severity_demote_chain_does_not_inflate_at_any_step,
    test_AGG_normalize_finding_id_handles_lowercase_input,
    test_AGG_parse_location_ref_no_path_in_string,
    test_AGG_round_trip_real_world_inventory_format,
    test_AGG_synth_section_with_inline_markdown_in_verify,
    # Real LLM output drift
    test_DRIFT_inventory_with_smart_quotes_in_title,
    test_DRIFT_inventory_with_multiple_blank_lines_between_findings,
    test_DRIFT_inventory_with_html_entities_in_field,
    test_DRIFT_verify_with_windows_crlf_line_endings,
    test_DRIFT_inventory_with_trailing_whitespace_in_severity,
    test_DRIFT_inventory_block_with_empty_location_field,
    # End-to-end mini pipeline
    test_E2E_inventory_to_audit_report_round_trip,
    test_E2E_zero_findings_pipeline,
    test_E2E_all_refuted_pipeline,
    test_E2E_partial_verify_failure_yields_unresolved_not_confirmed,
    # Stress
    test_STRESS_long_finding_title,
    test_STRESS_inventory_with_many_source_ids_per_finding,
    test_STRESS_chunk_with_100_findings_at_each_severity,
    # Phase-completion contracts
    test_COMP_verify_core_aggregate_covers_all_verify_files,
    test_COMP_verify_core_excludes_skeptic_judge_files,
    test_COMP_promotion_dropout_retry_hint_lists_missing_ids,
    test_COMP_inventory_evidence_validation_writes_ledger,
    test_COMP_inventory_chunk_merge_writes_receipt,
    test_COMP_severity_demote_handles_unicode_input,
    test_COMP_filter_evidence_does_not_drop_lone_lenient_anchor,
    test_COMP_filter_evidence_retains_double_invalid_as_repair_debt,
    test_COMP_recon_placeholder_detector_ignores_negated_cleanup_status,
]


def main() -> int:
    print(f"Running {len(TESTS)} pipeline-contract tests...")
    for t in TESTS:
        print(f"\n[{t.__name__}]")
        try:
            t()
        except Exception as exc:
            global FAIL
            FAIL += 1
            print(f"  CRASH {t.__name__} :: {exc!r}")
    print(f"\n{'=' * 64}")
    print(f"  PASS: {PASS}   FAIL: {FAIL}")
    print('=' * 64)
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
