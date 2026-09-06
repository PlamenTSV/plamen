"""End-to-end integration scenarios — the 10 gaps Codex flagged.

Strict assertions, written first-principles. NO bias toward passing — each
test asserts what the contract REQUIRES, not what the driver currently does.

Run: `python test_e2e_integration.py`
"""

from __future__ import annotations

import json
import re
import sys
import tempfile
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS_DIR))

import plamen_driver as D  # noqa: E402
import plamen_validators as V  # noqa: E402

PASS = 0
FAIL = 0


def check(label: str, ok: bool, detail: str = ""):
    global PASS, FAIL
    if ok:
        PASS += 1
        print(f"  PASS  {label}")
    else:
        FAIL += 1
        print(f"  FAIL  {label} :: {detail}")


def _mkscratch(files: dict[str, str]) -> Path:
    sp = Path(tempfile.mkdtemp(prefix="plamen_e2e_"))
    for name, body in files.items():
        p = sp / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body, encoding="utf-8")
    return sp


# =============================================================================
# 1. End-to-end mini L1 fixture
# =============================================================================

def test_E2E_L1_full_fixture_through_all_gates():
    """L1 fixture: chunks -> inventory -> queue -> verify -> partial crossbatch
    -> semantic-trigger skeptic. Each gate must HALT/FLAG at the correct point
    until each layer is complete, then produce a rich report."""
    chunks = {}
    for ci, prefix in enumerate("ab"):
        body = []
        for i in range(3):
            body.extend([
                f"### Finding [{prefix.upper()}-{i+1}]: bug{ci}{i}",
                f"**Severity**: {'Critical' if i == 0 else 'High' if i == 1 else 'Medium'}",
                f"**Location**: src/{prefix}/m{i}.rs:L{i+1}",
                f"**Source IDs**: {prefix.upper()}-{i+1}",
                f"**Root Cause**: cause {ci}{i}",
                "",
            ])
        chunks[f"findings_inventory_chunk_{prefix}.md"] = "\n".join(body)
    sp = _mkscratch(chunks)

    # Stage 1: inventory chunk merge
    parsed, merged = D._write_mechanical_inventory_from_chunks(sp)
    assert merged == 6, f"expected 6 merged, got {merged}"

    # Stage 2: depth promotion (DNS-* / DA3-* findings)
    (sp / "depth_network_surface_findings.md").write_text(
        "### Finding [DNS-1]: high-confidence depth\n"
        "**Confidence**: 0.85\n**Severity**: High\n"
        "**Location**: src/p2p/handler.rs:L42\n"
        "**Description**: depth-channel finding\n",
        encoding="utf-8",
    )
    (sp / "confidence_scores.md").write_text(
        "| Finding ID | Confidence |\n|---|---|\n| DNS-1 | 0.85 |\n",
        encoding="utf-8",
    )
    promoted = D._promote_depth_findings_to_inventory(sp)
    assert "DNS-1" in promoted, f"DNS-1 not promoted: {promoted}"

    # Stage 3: mechanical queue write + parity
    n = D._write_mechanical_verification_queue_from_inventory(sp)
    parity = D._validate_verification_queue_inventory_parity(sp)
    assert n == 7, f"expected 7 queue rows (6 inv + 1 promoted), got {n}"
    assert not parity, f"parity issues: {parity}"

    # Stage 4: simulate verify shards (3 confirmed, 1 refuted, 3 unresolved-ish)
    queue_rows = D.parse_verification_queue_rows(sp)
    for i, row in enumerate(queue_rows):
        fid = row["finding id"]
        verdict = ["CONFIRMED", "CONFIRMED", "CONFIRMED",
                   "FALSE_POSITIVE", "CONFIRMED", "CONFIRMED", "CONFIRMED"][i]
        (sp / f"verify_{fid}.md").write_text(
            f"# Verify {fid}\n\n**Verdict**: {verdict}\n"
            f"**Severity**: {row['severity']}\n"
            "**Impact**: High\n**Likelihood**: Medium\n"
            "**Evidence Tag**: CODE-TRACE\n\n"
            f"## Description\nFinding {fid} description with substance.\n\n"
            f"## Impact\nImpact statement quantifying loss.\n\n"
            f"## PoC Result\n{'PASS' if verdict == 'CONFIRMED' else 'N/A'}\n\n"
            f"## Recommendation\nApply fix at line {(i+1)*10}.\n",
            encoding="utf-8",
        )

    # P0-V/R35A: skeptic scope is semantic, not a severity-only C/H subset.
    # Pin the fixture's complete denominator and trigger authority so deriving
    # the positive body below cannot conceal a future regression.
    expected_rows = D._skeptic_expected_findings(sp)
    expected_ids = [row["finding_id"] for row in expected_rows]
    expected_triggers = {
        "INV-001": {"HIGH_RISK_ADVERSARIAL_REVIEW", "UNRESOLVED_EXTERNAL_PREMISE", "EVIDENCE_INTEGRITY_REVIEW"},
        "INV-002": {"HIGH_RISK_ADVERSARIAL_REVIEW", "UNRESOLVED_EXTERNAL_PREMISE", "EVIDENCE_INTEGRITY_REVIEW"},
        "INV-003": {"HIGH_RISK_ADVERSARIAL_REVIEW", "UNRESOLVED_EXTERNAL_PREMISE", "EVIDENCE_INTEGRITY_REVIEW"},
        "INV-004": {
            "HIGH_RISK_ADVERSARIAL_REVIEW",
            "PROPOSED_NONBODY_DISPOSITION",
            "DEPTH_VERIFIER_DISAGREEMENT",
            "UNRESOLVED_EXTERNAL_PREMISE",
            "EVIDENCE_INTEGRITY_REVIEW",
        },
        "INV-005": {"UNRESOLVED_EXTERNAL_PREMISE", "EVIDENCE_INTEGRITY_REVIEW"},
        "INV-006": {"UNRESOLVED_EXTERNAL_PREMISE", "EVIDENCE_INTEGRITY_REVIEW"},
        "INV-007": {"HIGH_RISK_ADVERSARIAL_REVIEW", "UNRESOLVED_EXTERNAL_PREMISE", "EVIDENCE_INTEGRITY_REVIEW"},
    }
    assert expected_ids == [f"INV-{i:03d}" for i in range(1, 8)]
    assert len(expected_ids) == len(set(expected_ids)) == 7
    assert {
        row["finding_id"]: set(row["challenge_triggers"])
        for row in expected_rows
    } == expected_triggers
    for row in expected_rows:
        if row["finding_id"] in {"INV-005", "INV-006"}:
            assert "COMPUTE_RECEIPT_MISSING" in row["mechanical_authority_issue"]

    # Scope derivation and manifest projection are observational and replay
    # stable across queue, inventory, and verifier authority inputs.
    authority_paths = sorted(
        {
            sp / "findings_inventory.md",
            sp / "verification_queue.md",
            *sp.glob("verify_*.md"),
            *sp.glob("external_assumption_*"),
        },
        key=lambda path: path.as_posix(),
    )
    authority_before = {path: path.read_bytes() for path in authority_paths}
    assert D._skeptic_expected_findings(sp) == expected_rows
    assert V._skeptic_manifest_ids(sp) == expected_ids
    assert V._skeptic_manifest_ids(sp) == expected_ids
    assert {path: path.read_bytes() for path in authority_paths} == authority_before

    # Stage 5: PARTIAL crossbatch (only 2 of 7 verify files reviewed)
    (sp / "cross_batch_consistency.md").write_text(
        "# Cross-Batch\nFiles checked: 2\nVerifiers Checked: 2\n"
        "Overall: PASS\nReviewed: " + queue_rows[0]["finding id"] + ", " + queue_rows[1]["finding id"] + "\n",
        encoding="utf-8",
    )
    cb_issues = D._validate_crossbatch_full_coverage(sp)
    check(
        "E2E.L1: partial crossbatch (2/7) is flagged",
        bool(cb_issues),
        f"cb_issues={cb_issues}",
    )

    # Stage 6: PARTIAL skeptic (only first semantic-trigger row reviewed)
    crit_high_ids = [r["finding id"] for r in queue_rows
                     if r["severity"].lower() in ("critical", "high")]
    assert crit_high_ids == ["INV-001", "INV-002", "INV-003", "INV-004", "INV-007"]
    assert set(expected_ids) - set(crit_high_ids) == {"INV-005", "INV-006"}
    (sp / "skeptic_findings.md").write_text(
        f"# Skeptic\n\n## {expected_ids[0]}\n**Verdict**: AGREE\n",
        encoding="utf-8",
    )
    sk_issues = D._validate_skeptic_scope(sp)
    check(
        f"E2E.L1: partial skeptic (1/{len(expected_ids)} semantic) is flagged",
        bool(sk_issues) and "reviewed 1/7" in sk_issues[0],
        f"sk_issues={sk_issues}",
    )

    # A five-ID Critical/High body is explicitly incomplete: provisional
    # severity cannot erase the two Medium rows carrying R10 authority debt.
    sk_body = "# Skeptic\n\n" + "\n\n".join(
        f"## {fid}\n**Verdict**: AGREE" for fid in crit_high_ids
    ) + "\n"
    (sp / "skeptic_findings.md").write_text(sk_body, encoding="utf-8")
    ch_only_issues = D._validate_skeptic_scope(sp)
    check(
        "E2E.L1: C/H-only skeptic cannot shrink semantic scope",
        bool(ch_only_issues)
        and "reviewed 5/7" in ch_only_issues[0]
        and "INV-005" in ch_only_issues[0]
        and "INV-006" in ch_only_issues[0],
        f"ch_only_issues={ch_only_issues}",
    )

    # A stale, well-formed five-row prompt manifest never overrides current
    # verifier semantics; the current seven-row denominator remains primary.
    (sp / "skeptic_manifest.json").write_text(
        json.dumps({
            "phase": "skeptic",
            "required_count": len(crit_high_ids),
            "findings": [{"finding_id": fid} for fid in crit_high_ids],
        }, sort_keys=True),
        encoding="utf-8",
    )
    assert V._skeptic_manifest_ids(sp) == expected_ids
    assert D._validate_skeptic_scope(sp) == ch_only_issues

    # Stage 7: complete semantic-trigger skeptic — gate clears.
    complete_body = "# Skeptic\n\n" + "\n\n".join(
        f"## {fid}\n**Verdict**: AGREE" for fid in expected_ids
    ) + "\n"
    (sp / "skeptic_findings.md").write_text(complete_body, encoding="utf-8")
    sk_issues_after = D._validate_skeptic_scope(sp)
    check(
        "E2E.L1: full semantic-trigger skeptic clears scope gate",
        not sk_issues_after,
        f"sk_issues_after={sk_issues_after}",
    )

    # Coverage tamper is exact and replayable for both semantic-only IDs.
    for fid in ("INV-005", "INV-006"):
        tampered = complete_body.replace(f"## {fid}\n", f"## X-{fid[-3:]}\n", 1)
        (sp / "skeptic_findings.md").write_text(tampered, encoding="utf-8")
        tamper_issues = D._validate_skeptic_scope(sp)
        assert tamper_issues and "reviewed 6/7" in tamper_issues[0]
        assert f"missing {fid}" in tamper_issues[0]
        (sp / "skeptic_findings.md").write_text(complete_body, encoding="utf-8")
        assert D._validate_skeptic_scope(sp) == []

    # Invalid/tampered denominator authority is fail-closed: changing a
    # verifier's provisional verdict/severity or adding malformed R10 compute
    # evidence may retain/expand independent review, but cannot shrink it.
    inv006 = sp / "verify_INV-006.md"
    inv006_before = inv006.read_bytes()
    inv006.write_bytes(
        inv006_before.replace(b"CONFIRMED", b"FALSE_POSITIVE", 1).replace(
            b"**Severity**: Medium", b"**Severity**: Low", 1
        )
    )
    verifier_tampered_ids = [
        row["finding_id"] for row in D._skeptic_expected_findings(sp)
    ]
    assert set(verifier_tampered_ids) >= set(expected_ids)
    assert V._skeptic_manifest_ids(sp) == verifier_tampered_ids
    inv006.write_bytes(inv006_before)
    assert D._skeptic_expected_findings(sp) == expected_rows

    invalid_r10 = sp / "external_assumption_undemotion_compute.json"
    invalid_r10.write_bytes(b'{"schema_version":"tampered"}')
    invalid_r10_ids = [row["finding_id"] for row in D._skeptic_expected_findings(sp)]
    assert set(invalid_r10_ids) >= set(expected_ids)
    invalid_r10.unlink()
    assert D._skeptic_expected_findings(sp) == expected_rows

    # Legitimate report-ID aliases cover the same semantic identities.
    assignments, _assignment_source = V.get_tier_assignments(sp)
    aliases = {
        row["finding_id"]: row["report_id"]
        for row in assignments
        if row.get("finding_id") in set(expected_ids)
    }
    assert set(aliases) == set(expected_ids)
    alias_body = "# Skeptic\n\n" + "\n\n".join(
        f"## {aliases[fid]}\n**Verdict**: AGREE" for fid in expected_ids
    ) + "\n"
    (sp / "skeptic_findings.md").write_text(alias_body, encoding="utf-8")
    assert D._validate_skeptic_scope(sp) == []
    assert D._validate_skeptic_scope(sp) == []

    # Skeptic coverage is proposal-only. It does not rewrite verifier,
    # inventory, queue, R10 debt, or report-disposition authority.
    assert {path: path.read_bytes() for path in authority_paths} == authority_before
    assert not invalid_r10.exists()

    # Stage 8: build report index + tier files; assert rich content
    n_active = D._write_mechanical_report_index(sp)
    D._write_mechanical_report_tier(sp, "report_critical_high")
    crit_high_text = (sp / "report_critical_high.md").read_text(encoding="utf-8") if (sp / "report_critical_high.md").exists() else ""
    has_real_descr = "Finding" in crit_high_text and "description with substance" in crit_high_text
    has_real_recommendation = "Apply fix at line" in crit_high_text
    no_internal_id_leak = "INV-007" not in crit_high_text and "DNS-1" not in crit_high_text
    check(
        "E2E.L1: tier file has rich content + no internal ID leak",
        has_real_descr and has_real_recommendation and no_internal_id_leak,
        f"descr={has_real_descr} rec={has_real_recommendation} no_leak={no_internal_id_leak}",
    )


# =============================================================================
# 2. Crossbatch alternate count formats
# =============================================================================

def test_CB_format_checked_X_of_Y():
    """CB: 'Checked 41 of 203' phrasing must trigger gate when partial."""
    files = {f"verify_INV-{i:03d}.md": "**Verdict**: CONFIRMED\n" for i in range(1, 11)}
    files["cross_batch_consistency.md"] = (
        "# Cross-Batch\n\nChecked 4 of 10 verify files.\nOverall: PASS\n"
    )
    sp = _mkscratch(files)
    issues = D._validate_crossbatch_full_coverage(sp)
    check(
        "CB.alt-format-checked-X-of-Y partial flagged",
        bool(issues),
        f"issues={issues}",
    )


def test_CB_format_table_only():
    """CB: table-only crossbatch listing N/M IDs without explicit count."""
    files = {f"verify_INV-{i:03d}.md": "**Verdict**: CONFIRMED\n" for i in range(1, 11)}
    rows = "\n".join(
        f"| INV-{i:03d} | CONFIRMED | OK |"
        for i in range(1, 4)  # only 3 of 10
    )
    files["cross_batch_consistency.md"] = (
        "# Cross-Batch\n\n| Finding | Status | Result |\n|---|---|---|\n" + rows + "\n"
    )
    sp = _mkscratch(files)
    issues = D._validate_crossbatch_full_coverage(sp)
    check(
        "CB.table-only-format with 3/10 IDs is flagged",
        bool(issues),
        f"issues={issues}",
    )


def test_CB_format_id_list_no_count():
    """CB: IDs listed but no count phrase. Gate must derive coverage from
    IDs in the file vs verify_*.md count."""
    files = {f"verify_INV-{i:03d}.md": "**Verdict**: CONFIRMED\n" for i in range(1, 11)}
    files["cross_batch_consistency.md"] = (
        "# Cross-Batch\n\nReviewed: INV-001, INV-002, INV-003.\n"
        "Overall: PASS\n"  # no Verifiers Checked, no Files checked
    )
    sp = _mkscratch(files)
    issues = D._validate_crossbatch_full_coverage(sp)
    check(
        "CB.id-list-no-count: 3 listed of 10 verify files -> flagged",
        bool(issues),
        f"issues={issues}",
    )


# =============================================================================
# 3. Skeptic alternate ID formats (report ID, table, bullet, header)
# =============================================================================

def test_SK_accepts_report_id_with_mapping():
    """SK: skeptic file uses report IDs (C-01) with valid index mapping —
    gate should resolve via mapping, not require raw INV-*."""
    queue = (
        "| Queue # | Finding ID | Severity | Title | Bug Class | Preferred Tag | Location | Primary Artifact |\n"
        "|---|---|---|---|---|---|---|---|\n"
        "| 1 | INV-001 | Critical | a | x | CODE-TRACE | s:L1 | x.md |\n"
    )
    sp = _mkscratch({
        "verify_INV-001.md": "**Verdict**: CONFIRMED\n",
        "verification_queue.md": queue,
        "report_index.md": (
            "## Master Finding Index\n\n"
            "| Report ID | Title | Severity | Location | "
            "Internal Hypothesis ID | Evidence Tag | Verdict | Trust Adj. |\n"
            "|---|---|---|---|---|---|---|---|\n"
            "| C-01 | a | Critical | s:L1 | INV-001 | CODE-TRACE | CONFIRMED | |\n"
        ),
        "skeptic_findings.md": (
            "# Skeptic\n\n## C-01\n**Verdict**: AGREE\n"  # report ID, not INV
        ),
    })
    issues = D._validate_skeptic_scope(sp)
    # Strict: gate should resolve C-01 -> INV-001 via report_index.md mapping.
    # If it doesn't, this is a real gap (false flag on legitimate review).
    check(
        "SK.accepts-report-id with mapping (no false flag)",
        not issues,
        f"issues={issues}",
    )


def test_SK_skeptic_in_table_form():
    """SK: skeptic file is a markdown table with finding IDs in column 1."""
    queue = (
        "| Queue # | Finding ID | Severity | Title | Bug Class | Preferred Tag | Location | Primary Artifact |\n"
        "|---|---|---|---|---|---|---|---|\n"
        "| 1 | INV-001 | Critical | a | x | CODE-TRACE | s:L1 | x.md |\n"
        "| 2 | INV-002 | High | b | x | CODE-TRACE | s:L2 | x.md |\n"
    )
    sp = _mkscratch({
        "verify_INV-001.md": "**Verdict**: CONFIRMED\n",
        "verify_INV-002.md": "**Verdict**: CONFIRMED\n",
        "verification_queue.md": queue,
        "skeptic_findings.md": (
            "# Skeptic\n\n"
            "| Finding | Verdict | Note |\n|---|---|---|\n"
            "| INV-001 | AGREE | reviewed |\n"
            "| INV-002 | AGREE | reviewed |\n"
        ),
    })
    issues = D._validate_skeptic_scope(sp)
    check(
        "SK.table-form skeptic resolves both IDs",
        not issues,
        f"issues={issues}",
    )


# =============================================================================
# 4. Report content quality with mixed sections
# =============================================================================

def test_REPORT_mixed_quality_at_threshold():
    """REPORT: 95% rich + 5% fallback — what does quality gate say?
    Strict: any STUB-RECOVERED in body should be tracked, not silently ignored."""
    inv_lines = ["# Inventory", ""]
    for i in range(1, 21):  # 20 findings
        inv_lines.extend([
            f"### Finding [INV-{i:03d}]: bug{i}",
            "**Severity**: High",
            f"**Location**: src/x.sol:L{i}",
            "",
        ])
    sp = _mkscratch({"findings_inventory.md": "\n".join(inv_lines)})
    D._write_mechanical_verification_queue_from_inventory(sp)
    # 19 rich, 1 stub (verify file empty)
    for i in range(1, 20):
        (sp / f"verify_INV-{i:03d}.md").write_text(
            "**Verdict**: CONFIRMED\n\n## Description\nReal.\n\n"
            "## Impact\nReal.\n\n## PoC Result\nPASS\n",
            encoding="utf-8",
        )
    (sp / "verify_INV-020.md").write_text("", encoding="utf-8")  # empty
    D._write_mechanical_report_index(sp)
    # Empty verify -> UNRESOLVED -> demoted High to Medium tier; need to
    # write all tier files to find the stub section.
    for phase_name in ("report_critical_high", "report_medium_a",
                       "report_medium_b", "report_low_info"):
        try:
            D._write_mechanical_report_tier(sp, phase_name)
        except Exception:
            pass
    all_text = ""
    for fname in ("report_critical_high.md", "report_medium.md",
                  "report_medium_a.md", "report_medium_b.md",
                  "report_low_info.md"):
        p = sp / fname
        if p.exists():
            all_text += p.read_text(encoding="utf-8")
    has_stub_marker = "STUB-RECOVERED" in all_text
    rich_count = all_text.count("Real.")
    check(
        "REPORT.mixed-quality: stub section tagged, rich kept rich",
        has_stub_marker and rich_count >= 5,
        f"stub_marker={has_stub_marker} rich_count={rich_count}",
    )


# =============================================================================
# 5. Verifier-thin-content path
# =============================================================================

def test_THIN_too_many_thin_verify_files_flagged():
    """THIN: 80% of verify files have no Analysis/Impact/Recommendation.
    Strict: there should be a quality signal that fires here. If no helper
    exists, this test FAILS — that surfaces a missing gate."""
    inv_lines = ["# Inventory", ""]
    for i in range(1, 11):
        inv_lines.extend([
            f"### Finding [INV-{i:03d}]: bug{i}",
            "**Severity**: High",
            f"**Location**: src/x.sol:L{i}",
            "",
        ])
    sp = _mkscratch({"findings_inventory.md": "\n".join(inv_lines)})
    D._write_mechanical_verification_queue_from_inventory(sp)
    # 8 thin (verdict only), 2 rich
    for i in range(1, 9):
        (sp / f"verify_INV-{i:03d}.md").write_text(
            "**Verdict**: CONFIRMED\n",  # no Description, Impact, etc.
            encoding="utf-8",
        )
    for i in (9, 10):
        (sp / f"verify_INV-{i:03d}.md").write_text(
            "**Verdict**: CONFIRMED\n\n## Description\nReal.\n\n"
            "## Impact\nReal.\n\n## PoC Result\nPASS\n",
            encoding="utf-8",
        )
    # Check if a helper exists; if not, the test surfaces the gap.
    issues = D._validate_verify_content_quality(sp)
    check(
        "THIN.80%-thin-verify-files flagged",
        bool(issues),
        f"issues={issues}",
    )


# =============================================================================
# 6. Depth promotion verdict filtering (DUPLICATE/REFUTED/CONSOLIDATED)
# =============================================================================

def test_DPROM_duplicate_verdict_not_promoted():
    """DPROM: depth finding marked DUPLICATE -> NOT promoted to inventory."""
    inv = "### Finding [INV-001]: existing\n**Location**: src/a.rs:L1\n"
    depth = (
        "### Finding [DNS-1]: depth dup\n"
        "**Confidence**: 0.85\n**Severity**: High\n"
        "**Location**: src/x.rs:L1\n**Verdict**: DUPLICATE\n"
        "**Description**: dup of INV-001\n\n"
        "### Finding [DNS-2]: depth real\n"
        "**Confidence**: 0.85\n**Severity**: High\n"
        "**Location**: src/y.rs:L1\n**Verdict**: CONFIRMED\n"
        "**Description**: real bug\n"
    )
    scores = "| Finding ID | Confidence |\n|---|---|\n| DNS-1 | 0.85 |\n| DNS-2 | 0.85 |\n"
    sp = _mkscratch({
        "findings_inventory.md": inv,
        "depth_network_surface_findings.md": depth,
        "confidence_scores.md": scores,
    })
    promoted = D._promote_depth_findings_to_inventory(sp)
    check(
        "DPROM.duplicate-verdict NOT promoted; CONFIRMED IS promoted",
        "DNS-1" not in promoted and "DNS-2" in promoted,
        f"promoted={promoted}",
    )


def test_DPROM_refuted_verdict_not_promoted():
    inv = "### Finding [INV-001]: existing\n**Location**: src/a.rs:L1\n"
    depth = (
        "### Finding [DA3-CONSENSUS-1]: refuted\n"
        "**Confidence**: 0.85\n**Severity**: High\n"
        "**Location**: src/x.rs:L1\n**Verdict**: REFUTED\n"
        "**Description**: not exploitable\n"
    )
    scores = "| Finding ID | Confidence |\n|---|---|\n| DA3-CONSENSUS-1 | 0.85 |\n"
    sp = _mkscratch({
        "findings_inventory.md": inv,
        "depth_consensus_invariant_findings.md": depth,
        "confidence_scores.md": scores,
    })
    promoted = D._promote_depth_findings_to_inventory(sp)
    check(
        "DPROM.refuted-verdict NOT promoted",
        "DA3-CONSENSUS-1" not in promoted,
        f"promoted={promoted}",
    )


def test_DPROM_consolidated_and_false_positive_not_promoted():
    inv = "### Finding [INV-001]: existing\n**Location**: src/a.rs:L1\n"
    depth = (
        "### Finding [DNS-1]: consolidated\n"
        "**Confidence**: 0.85\n**Severity**: High\n"
        "**Location**: src/x.rs:L1\n**Verdict**: CONSOLIDATED\n"
        "**Description**: merged into INV-001\n\n"
        "### Finding [DNS-2]: false positive\n"
        "**Confidence**: 0.85\n**Severity**: Medium\n"
        "**Location**: src/y.rs:L1\n**Verdict**: FALSE_POSITIVE\n"
        "**Description**: not real\n"
    )
    scores = "| Finding ID | Confidence |\n|---|---|\n| DNS-1 | 0.85 |\n| DNS-2 | 0.85 |\n"
    sp = _mkscratch({
        "findings_inventory.md": inv,
        "depth_network_surface_findings.md": depth,
        "confidence_scores.md": scores,
    })
    promoted = D._promote_depth_findings_to_inventory(sp)
    check(
        "DPROM.consolidated + false-positive NOT promoted",
        "DNS-1" not in promoted and "DNS-2" not in promoted,
        f"promoted={promoted}",
    )


# =============================================================================
# 7. Inventory merge near-duplicates
# =============================================================================

def test_MERGE_exact_mechanism_disjoint_provenance_stays_distinct():
    """MECH similarity alone is tag-only before independent verification."""
    entries = [
        {"title": "missing zero check", "severity": "High", "location": "src/x.sol:L10",
         "source_ids": ["A1"], "root_cause": "no validation"},
        {"title": "missing zero check", "severity": "High", "location": "src/x.sol:L10",
         "source_ids": ["A2"], "root_cause": "no validation"},
    ]
    merged = D._merge_inventory_entries(entries)
    check(
        "MERGE.exact-mechanism: disjoint sources remain distinct",
        len(merged) == 2,
        f"merged={merged}",
    )


def test_MERGE_same_location_different_title_kept():
    entries = [
        {"title": "loop early-exit", "severity": "High", "location": "src/x.sol:L10",
         "source_ids": ["A1"], "root_cause": "early exit"},
        {"title": "missing decimals check", "severity": "High", "location": "src/x.sol:L10",
         "source_ids": ["A2"], "root_cause": "no decimals"},
    ]
    merged = D._merge_inventory_entries(entries)
    check(
        "MERGE.same-loc-diff-title: 2 inputs -> 2 distinct entries",
        len(merged) == 2,
        f"merged_count={len(merged)}",
    )


def test_MERGE_same_title_different_location_kept():
    entries = [
        {"title": "missing zero check", "severity": "High", "location": "src/a.sol:L1",
         "source_ids": ["A1"], "root_cause": "no validation"},
        {"title": "missing zero check", "severity": "High", "location": "src/b.sol:L1",
         "source_ids": ["A2"], "root_cause": "no validation"},
    ]
    merged = D._merge_inventory_entries(entries)
    check(
        "MERGE.same-title-diff-loc: 2 inputs -> 2 distinct entries (different files)",
        len(merged) == 2,
        f"merged_count={len(merged)}",
    )


# =============================================================================
# 8. SC regression mini fixture (post-L1 alignment)
# =============================================================================

def test_SC_regression_slither_fuzz_niche_through_pipeline():
    """SC: SLITHER-*, FUZZ-*, niche IDs preserved through inv -> queue -> report.
    A bare REFUTED claim remains visible until exact negative authority exists.
    No L1 assumptions leak in."""
    inv = (
        "### Finding [INV-001]: real Slither finding\n"
        "**Severity**: High\n**Location**: contracts/Vault.sol:L42\n"
        "**Source IDs**: SLITHER-3, BLIND-2\n\n"
        "### Finding [INV-002]: fuzz finding\n"
        "**Severity**: Medium\n**Location**: contracts/Lender.sol:L88\n"
        "**Source IDs**: FUZZ-7\n\n"
        "### Finding [INV-003]: niche callback finding\n"
        "**Severity**: High\n**Location**: contracts/Hook.sol:L12\n"
        "**Source IDs**: CBS-1\n"
    )
    sp = _mkscratch({"findings_inventory.md": inv})
    n = D._write_mechanical_verification_queue_from_inventory(sp)
    rows = D.parse_verification_queue_rows(sp)
    assert n == 3
    # SLITHER-3 + BLIND-2 + FUZZ-7 + CBS-1 should all be preserved as Source IDs
    all_artifacts = " ".join(r.get("primary artifact", "") for r in rows)
    sids_preserved = all(
        sid in all_artifacts for sid in ("SLITHER-3", "BLIND-2", "FUZZ-7", "CBS-1")
    )
    # Verify shards: 1 confirmed, 1 refuted, 1 confirmed
    (sp / "verify_INV-001.md").write_text(
        "**Verdict**: CONFIRMED\n## Description\nSlither-confirmed bug.\n"
        "## Impact\nLoss.\n## PoC Result\nPASS\n",
        encoding="utf-8",
    )
    (sp / "verify_INV-002.md").write_text(
        "**Verdict**: REFUTED\nFuzz did not reproduce.\n",
        encoding="utf-8",
    )
    (sp / "verify_INV-003.md").write_text(
        "**Verdict**: CONFIRMED\n## Description\nCallback issue.\n"
        "## Impact\nState corruption.\n## PoC Result\nPASS\n",
        encoding="utf-8",
    )
    D._write_mechanical_report_index(sp)
    idx = (sp / "report_index.md").read_text(encoding="utf-8")
    negative_at = idx.find("Proposed Negative Dispositions")
    master = idx[:negative_at] if negative_at > -1 else idx
    proposed_negative = idx[negative_at:] if negative_at > -1 else ""
    check(
        "SC.regression: SLITHER + BLIND + FUZZ + CBS all in queue; "
        "unproven REFUTED FUZZ remains visible with a proposal-only disposition",
        sids_preserved
        and "INV-001" in master and "INV-003" in master
        and "INV-002" in master and "INV-002" in proposed_negative
        and "terminal authority not established" in proposed_negative,
        f"sids={sids_preserved}",
    )


# =============================================================================
# 9. Resume with stale partial artifacts
# =============================================================================

def test_RESUME_stale_crossbatch_forces_rerun():
    """RESUME: checkpoint says crossbatch completed, but the on-disk
    cross_batch_consistency.md only covers 4/10 verify files. The scope
    validator must FAIL on resume so the phase reruns."""
    files = {f"verify_INV-{i:03d}.md": "**Verdict**: CONFIRMED\n" for i in range(1, 11)}
    files["cross_batch_consistency.md"] = (
        "# Cross-Batch\nFiles checked: 4\nVerifiers Checked: 4\nOverall: PASS\n"
        "Reviewed: INV-001, INV-002, INV-003, INV-004\n"
    )
    sp = _mkscratch(files)
    # Stale checkpoint says crossbatch is complete
    cp = D.Checkpoint(completed=["crossbatch"], degraded=[])
    cp.save(sp)
    # Validator must still flag the partial coverage so a rerun is forced
    issues = D._validate_crossbatch_full_coverage(sp)
    check(
        "RESUME.stale-partial-crossbatch flagged for rerun",
        bool(issues),
        f"issues={issues}",
    )


def test_RESUME_stale_partial_skeptic_forces_rerun():
    queue = (
        "| Queue # | Finding ID | Severity | Title | Bug Class | Preferred Tag | Location | Primary Artifact |\n"
        "|---|---|---|---|---|---|---|---|\n"
    )
    files = {}
    for i in range(1, 6):
        fid = f"INV-{i:03d}"
        sev = "Critical" if i <= 2 else "High"
        queue += f"| {i} | {fid} | {sev} | b{i} | x | CODE-TRACE | s:L{i} | x.md |\n"
        files[f"verify_{fid}.md"] = "**Verdict**: CONFIRMED\n"
    files["verification_queue.md"] = queue
    files["skeptic_findings.md"] = (
        "# Skeptic\n\n## INV-001\n**Verdict**: AGREE\n## INV-002\n**Verdict**: AGREE\n"
    )
    sp = _mkscratch(files)
    cp = D.Checkpoint(completed=["skeptic"], degraded=[])
    cp.save(sp)
    issues = D._validate_skeptic_scope(sp)
    check(
        "RESUME.stale-partial-skeptic flagged despite checkpoint",
        bool(issues),
        f"issues={issues}",
    )


# =============================================================================
# 10. Sanitization scope: Executive Summary + Priority Remediation
# =============================================================================

def test_SANIT_executive_summary_no_internal_id_leak():
    """SANIT: titles in finding rows can contain internal IDs because the LLM
    wrote them. Executive Summary must use sanitized titles."""
    inv_lines = ["# Inventory", ""]
    for i in range(1, 4):
        inv_lines.extend([
            # Title contains INV-* - simulates LLM leakage into title
            f"### Finding [INV-{i:03d}]: INV-{i:03d} bug at line {i}",
            "**Severity**: Critical",
            f"**Location**: src/x.sol:L{i}",
            "",
        ])
    sp = _mkscratch({"findings_inventory.md": "\n".join(inv_lines)})
    D._write_mechanical_verification_queue_from_inventory(sp)
    for i in range(1, 4):
        (sp / f"verify_INV-{i:03d}.md").write_text(
            "**Verdict**: CONFIRMED\n## Description\nReal.\n## Impact\nx.\n",
            encoding="utf-8",
        )
    D._write_mechanical_report_index(sp)
    for phase_name in ("report_critical_high", "report_medium_a",
                       "report_medium_b", "report_low_info"):
        try:
            D._write_mechanical_report_tier(sp, phase_name)
        except Exception:
            pass
    # Concatenate medium shards into report_medium.md (assembler reads that).
    med_text = ""
    for fname in ("report_medium_a.md", "report_medium_b.md"):
        p = sp / fname
        if p.exists():
            med_text += p.read_text(encoding="utf-8") + "\n"
    if med_text:
        (sp / "report_medium.md").write_text(med_text, encoding="utf-8")
    # Run the Python assembler to produce final report
    proj = Path(tempfile.mkdtemp(prefix="plamen_e2e_proj_"))
    try:
        D._assemble_report_python(sp, str(proj))
    except Exception as e:
        check("SANIT.exec-summary assembler runs", False, f"crashed: {e!r}")
        return
    report_path = proj / "AUDIT_REPORT.md"
    if not report_path.exists():
        check("SANIT.exec-summary assembler wrote report", False, "no AUDIT_REPORT.md")
        return
    text = report_path.read_text(encoding="utf-8")
    # Find Executive Summary section
    summary_section_re = re.compile(
        r"(?ims)^##\s+Executive Summary.*?(?=^##\s|\Z)",
        re.MULTILINE,
    )
    m = summary_section_re.search(text)
    if not m:
        check("SANIT.exec-summary section exists", False, "section not found")
        return
    exec_section = m.group(0)
    leak = re.search(r"\bINV-\d+\b", exec_section)
    check(
        "SANIT.executive-summary no INV-* leak",
        not leak,
        f"first leak: {leak.group(0) if leak else None}; section_excerpt={exec_section[:300]!r}",
    )


def test_SANIT_priority_remediation_no_internal_id_leak():
    """SANIT: same as above but for Priority Remediation Order section."""
    inv_lines = ["# Inventory", ""]
    for i in range(1, 4):
        inv_lines.extend([
            f"### Finding [INV-{i:03d}]: INV-{i:03d} appears in title",
            "**Severity**: High",
            f"**Location**: src/x.sol:L{i}",
            "",
        ])
    sp = _mkscratch({"findings_inventory.md": "\n".join(inv_lines)})
    D._write_mechanical_verification_queue_from_inventory(sp)
    for i in range(1, 4):
        (sp / f"verify_INV-{i:03d}.md").write_text(
            "**Verdict**: CONFIRMED\n## Description\nx.\n## Impact\nx.\n",
            encoding="utf-8",
        )
    D._write_mechanical_report_index(sp)
    for phase_name in ("report_critical_high", "report_medium_a",
                       "report_medium_b", "report_low_info"):
        try:
            D._write_mechanical_report_tier(sp, phase_name)
        except Exception:
            pass
    med_text = ""
    for fname in ("report_medium_a.md", "report_medium_b.md"):
        p = sp / fname
        if p.exists():
            med_text += p.read_text(encoding="utf-8") + "\n"
    if med_text:
        (sp / "report_medium.md").write_text(med_text, encoding="utf-8")
    proj = Path(tempfile.mkdtemp(prefix="plamen_e2e_proj_"))
    try:
        D._assemble_report_python(sp, str(proj))
    except Exception as e:
        check("SANIT.priority-remediation assembler runs", False, f"crashed: {e!r}")
        return
    report_path = proj / "AUDIT_REPORT.md"
    if not report_path.exists():
        check("SANIT.priority-remediation report exists", False, "no AUDIT_REPORT.md")
        return
    report = report_path.read_text(encoding="utf-8")
    pr_section_re = re.compile(
        r"(?ims)^##\s+Priority Remediation Order.*?(?=^##\s|\Z)",
        re.MULTILINE,
    )
    m = pr_section_re.search(report)
    if not m:
        check("SANIT.priority-remediation section exists", False, "section not found")
        return
    pr_section = m.group(0)
    leak = re.search(r"\bINV-\d+\b", pr_section)
    check(
        "SANIT.priority-remediation no INV-* leak",
        not leak,
        f"first leak: {leak.group(0) if leak else None}",
    )


# =============================================================================
# Test runner
# =============================================================================

TESTS = [
    test_E2E_L1_full_fixture_through_all_gates,
    test_CB_format_checked_X_of_Y,
    test_CB_format_table_only,
    test_CB_format_id_list_no_count,
    test_SK_accepts_report_id_with_mapping,
    test_SK_skeptic_in_table_form,
    test_REPORT_mixed_quality_at_threshold,
    test_THIN_too_many_thin_verify_files_flagged,
    test_DPROM_duplicate_verdict_not_promoted,
    test_DPROM_refuted_verdict_not_promoted,
    test_DPROM_consolidated_and_false_positive_not_promoted,
    test_MERGE_exact_mechanism_disjoint_provenance_stays_distinct,
    test_MERGE_same_location_different_title_kept,
    test_MERGE_same_title_different_location_kept,
    test_SC_regression_slither_fuzz_niche_through_pipeline,
    test_RESUME_stale_crossbatch_forces_rerun,
    test_RESUME_stale_partial_skeptic_forces_rerun,
    test_SANIT_executive_summary_no_internal_id_leak,
    test_SANIT_priority_remediation_no_internal_id_leak,
]


def main() -> int:
    print(f"Running {len(TESTS)} integration scenarios (10 gap classes)...")
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
