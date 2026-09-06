"""Phase C: duplicate / root-cause consolidation gate tests.

Per ~/.claude/rules/report-template.md and ~/.claude/rules/phase6-report-prompts.md
STEP 1.5 (Index Agent), findings that share the same root cause MUST be merged
into one report finding when ALL of:

  1. Same fix pattern (same TYPE of code change)
  2. Same severity tier (after Phase B matrix enforcement)
  3. Same vulnerability class
  4. Describable together (single description + location table)

The driver must mechanically detect candidate duplicates by signature so the
LLM never silently produces N entries for the same root cause. The driver
records consolidations into report_records.json and emits a Consolidation Map
in report_index.md.

Run: `python test_phase_c_dedup_gate.py`
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS_DIR))

import plamen_driver as D  # noqa: E402

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


# =============================================================================
# Signature derivation: the dedup key is (severity, fix_pattern, vuln_class).
# =============================================================================

def test_SIG_extracts_fix_pattern_keyword():
    """Fix pattern derived from Recommendation / Suggested Fix."""
    text = """
**Severity**: Low
**Recommendation**: Add zero-value validation in setProtocolFee().
"""
    sig = D._dedup_signature_for_finding(text, severity="Low")
    check(
        "SIG.fix_pattern_zero_validation",
        "zero" in sig.fix_pattern.lower() or "validation" in sig.fix_pattern.lower(),
        f"sig.fix_pattern={sig.fix_pattern}",
    )


def test_SIG_extracts_section_headed_fix_and_body():
    """Dedup signatures must read section-headed verifier narratives."""
    text = """
# Missing event emission on admin setter

## Description

Admin parameter changes occur without an emitted event, leaving monitoring
systems unable to track governance-controlled state changes.

## Suggested Fix

Emit an event from each admin setter after the new value is stored.
"""
    sig = D._dedup_signature_for_finding(text, severity="Low")
    ok = (
        ("event" in sig.vuln_class.lower() or "monitoring" in sig.vuln_class.lower())
        and ("event" in sig.fix_pattern.lower() or "setter" in sig.fix_pattern.lower())
    )
    check(
        "SIG.section_headed_fix_and_body",
        ok,
        f"sig={sig}",
    )


def test_SIG_extracts_vuln_class_from_title_or_body():
    text = """
# Missing event emission on admin setter
**Severity**: Low
**Recommendation**: Emit an event in setAdmin().
"""
    sig = D._dedup_signature_for_finding(text, severity="Low")
    check(
        "SIG.vuln_class_missing_event",
        "event" in sig.vuln_class.lower() or "missing" in sig.vuln_class.lower(),
        f"sig.vuln_class={sig.vuln_class}",
    )


def test_SIG_severity_kept_separate():
    """Same fix pattern, different severities -> different signatures."""
    body = "**Recommendation**: Add zero-value validation."
    sig_high = D._dedup_signature_for_finding(body, severity="High")
    sig_low = D._dedup_signature_for_finding(body, severity="Low")
    check(
        "SIG.severity_separates",
        sig_high.key() != sig_low.key(),
        f"high={sig_high.key()} low={sig_low.key()}",
    )


# =============================================================================
# Cluster detection: 3+ findings sharing the same key form a cluster.
# =============================================================================

def test_CLUSTER_finds_3_plus_same_signature(tmp_path: Path):
    """Three findings with the same fix pattern + same severity -> one cluster."""
    sp = tmp_path
    (sp / "verification_queue.md").write_text("""# Verification Queue

| Finding ID | Severity | Title | Location | Preferred Tag |
|------------|----------|-------|----------|---------------|
| INV-001 | Low | Missing event in setFee | src/A.sol:L10 | CODE-TRACE |
| INV-002 | Low | Missing event in setAdmin | src/B.sol:L20 | CODE-TRACE |
| INV-003 | Low | Missing event in setOwner | src/C.sol:L30 | CODE-TRACE |
""", encoding="utf-8")

    for fid, fn, ln in [("INV-001", "setFee", 10), ("INV-002", "setAdmin", 20), ("INV-003", "setOwner", 30)]:
        (sp / f"verify_{fid}.md").write_text(f"""# {fid}
**Verdict**: CONFIRMED
**Severity**: Low
**Description**: Missing event emission on admin state change.
**Recommendation**: Emit an event in {fn}().
""", encoding="utf-8")

    clusters = D._detect_dedup_clusters(sp)
    check(
        "CLUSTER.3_findings_one_cluster",
        len(clusters) == 1 and len(clusters[0]["finding_ids"]) == 3,
        f"clusters={clusters}",
    )


def test_CLUSTER_different_severity_no_cluster(tmp_path: Path):
    """Different severities even with same fix pattern -> not a cluster."""
    sp = tmp_path
    (sp / "verification_queue.md").write_text("""# Verification Queue

| Finding ID | Severity | Title | Location | Preferred Tag |
|------------|----------|-------|----------|---------------|
| INV-001 | High | Missing event A | src/A.sol:L10 | CODE-TRACE |
| INV-002 | Low | Missing event B | src/B.sol:L20 | CODE-TRACE |
""", encoding="utf-8")

    for fid, sev in [("INV-001", "High"), ("INV-002", "Low")]:
        (sp / f"verify_{fid}.md").write_text(f"""# {fid}
**Verdict**: CONFIRMED
**Severity**: {sev}
**Recommendation**: Emit an event.
""", encoding="utf-8")

    clusters = D._detect_dedup_clusters(sp)
    check(
        "CLUSTER.different_severity_no_merge",
        len(clusters) == 0,
        f"clusters={clusters}",
    )


def test_CLUSTER_two_findings_below_threshold(tmp_path: Path):
    """Threshold is 3+ identical signatures (template guidance). 2 is not a halt."""
    sp = tmp_path
    (sp / "verification_queue.md").write_text("""# Verification Queue

| Finding ID | Severity | Title | Location | Preferred Tag |
|------------|----------|-------|----------|---------------|
| INV-001 | Low | Missing event A | src/A.sol:L10 | CODE-TRACE |
| INV-002 | Low | Missing event B | src/B.sol:L20 | CODE-TRACE |
""", encoding="utf-8")

    for fid in ["INV-001", "INV-002"]:
        (sp / f"verify_{fid}.md").write_text(f"""# {fid}
**Verdict**: CONFIRMED
**Severity**: Low
**Recommendation**: Emit an event.
""", encoding="utf-8")

    clusters = D._detect_dedup_clusters(sp)
    check(
        "CLUSTER.below_threshold_returns_empty",
        len(clusters) == 0,
        f"clusters={clusters}",
    )


# =============================================================================
# Application: clusters become non-authoritative consolidation proposals.
# =============================================================================

def test_APPLY_3_findings_remain_independent_with_one_proposal(tmp_path: Path):
    sp = tmp_path
    (sp / "verification_queue.md").write_text("""# Verification Queue

| Finding ID | Severity | Title | Location | Preferred Tag |
|------------|----------|-------|----------|---------------|
| INV-001 | Low | Missing event in setFee | src/A.sol:L10 | CODE-TRACE |
| INV-002 | Low | Missing event in setAdmin | src/B.sol:L20 | CODE-TRACE |
| INV-003 | Low | Missing event in setOwner | src/C.sol:L30 | CODE-TRACE |
""", encoding="utf-8")

    for fid, fn in [("INV-001", "setFee"), ("INV-002", "setAdmin"), ("INV-003", "setOwner")]:
        (sp / f"verify_{fid}.md").write_text(f"""# {fid}
**Verdict**: CONFIRMED
**Severity**: Low
**Description**: Missing event emission on admin state change.
**Recommendation**: Emit an event in {fn}().
""", encoding="utf-8")

    n_active = D._write_mechanical_report_index(sp)
    records = json.loads((sp / "report_records.json").read_text(encoding="utf-8"))
    check(
        "APPLY.active_count_preserves_all_cluster_members",
        n_active == 3 and len(records["active"]) == 3,
        f"n_active={n_active} active={records.get('active')}",
    )

    consolidation_map = records.get("consolidation_map", [])
    check(
        "APPLY.consolidation_map_records_3_absorbed",
        len(consolidation_map) == 1
        and len(consolidation_map[0].get("absorbed_finding_ids", [])) == 3,
        f"map={consolidation_map}",
    )


def test_APPLY_index_includes_consolidation_section(tmp_path: Path):
    sp = tmp_path
    (sp / "verification_queue.md").write_text("""# Verification Queue

| Finding ID | Severity | Title | Location | Preferred Tag |
|------------|----------|-------|----------|---------------|
| INV-001 | Low | Missing event A | src/A.sol:L10 | CODE-TRACE |
| INV-002 | Low | Missing event B | src/B.sol:L20 | CODE-TRACE |
| INV-003 | Low | Missing event C | src/C.sol:L30 | CODE-TRACE |
""", encoding="utf-8")

    for fid in ["INV-001", "INV-002", "INV-003"]:
        (sp / f"verify_{fid}.md").write_text(f"""# {fid}
**Verdict**: CONFIRMED
**Severity**: Low
**Recommendation**: Emit an event.
""", encoding="utf-8")

    D._write_mechanical_report_index(sp)
    idx = (sp / "report_index.md").read_text(encoding="utf-8")
    check(
        "APPLY.index_has_consolidation_map_section",
        "## Proposed Consolidation Map (Non-authoritative)" in idx,
        idx[:1000],
    )
    check(
        "APPLY.consolidation_lists_absorbed_ids",
        all(f in idx for f in ["INV-001", "INV-002", "INV-003"]),
        idx,
    )


def test_APPLY_unrelated_findings_kept_separate(tmp_path: Path):
    """Different vulnerability classes -> no merging even at same severity."""
    sp = tmp_path
    (sp / "verification_queue.md").write_text("""# Verification Queue

| Finding ID | Severity | Title | Location | Preferred Tag |
|------------|----------|-------|----------|---------------|
| INV-001 | Low | Missing event | src/A.sol:L10 | CODE-TRACE |
| INV-002 | Low | Reentrancy | src/B.sol:L20 | CODE-TRACE |
| INV-003 | Low | Integer overflow | src/C.sol:L30 | CODE-TRACE |
""", encoding="utf-8")

    (sp / "verify_INV-001.md").write_text("""# INV-001
**Verdict**: CONFIRMED
**Severity**: Low
**Description**: Missing event emission.
**Recommendation**: Emit an event.
""", encoding="utf-8")
    (sp / "verify_INV-002.md").write_text("""# INV-002
**Verdict**: CONFIRMED
**Severity**: Low
**Description**: Reentrancy guard missing.
**Recommendation**: Add ReentrancyGuard modifier.
""", encoding="utf-8")
    (sp / "verify_INV-003.md").write_text("""# INV-003
**Verdict**: CONFIRMED
**Severity**: Low
**Description**: Integer overflow possible.
**Recommendation**: Use SafeMath or checked arithmetic.
""", encoding="utf-8")

    n_active = D._write_mechanical_report_index(sp)
    check(
        "APPLY.unrelated_kept_separate",
        n_active == 3,
        f"n_active={n_active}",
    )


def test_APPLY_consolidation_proposal_gets_class_level_title(tmp_path: Path):
    """Proposal may summarize a class without replacing source identities."""
    sp = tmp_path
    (sp / "verification_queue.md").write_text("""# Verification Queue

| Finding ID | Severity | Title | Location | Preferred Tag |
|------------|----------|-------|----------|---------------|
| INV-001 | Low | setFee no event | src/A.sol:L10 | CODE-TRACE |
| INV-002 | Low | setAdmin no event | src/B.sol:L20 | CODE-TRACE |
| INV-003 | Low | setOwner no event | src/C.sol:L30 | CODE-TRACE |
""", encoding="utf-8")

    for fid in ["INV-001", "INV-002", "INV-003"]:
        (sp / f"verify_{fid}.md").write_text(f"""# {fid}
**Verdict**: CONFIRMED
**Severity**: Low
**Description**: Missing event emission on admin state change.
**Recommendation**: Emit an event.
""", encoding="utf-8")

    D._write_mechanical_report_index(sp)
    records = json.loads((sp / "report_records.json").read_text(encoding="utf-8"))
    assert len(records["active"]) == 3
    assert all(not row["absorbed_finding_ids"] for row in records["active"])
    title = records["consolidation_map"][0]["title"]
    # The proposal title may be class-level; active rows retain their own IDs.
    check(
        "APPLY.title_is_class_level",
        "missing event" in title.lower() or "event emission" in title.lower(),
        f"title={title}",
    )


# =============================================================================
# Test runner
# =============================================================================

TESTS_BASIC = [
    test_SIG_extracts_fix_pattern_keyword,
    test_SIG_extracts_section_headed_fix_and_body,
    test_SIG_extracts_vuln_class_from_title_or_body,
    test_SIG_severity_kept_separate,
]

TESTS_INTEG = [
    test_CLUSTER_finds_3_plus_same_signature,
    test_CLUSTER_different_severity_no_cluster,
    test_CLUSTER_two_findings_below_threshold,
    test_APPLY_3_findings_remain_independent_with_one_proposal,
    test_APPLY_index_includes_consolidation_section,
    test_APPLY_unrelated_findings_kept_separate,
    test_APPLY_consolidation_proposal_gets_class_level_title,
]


def main() -> int:
    n = len(TESTS_BASIC) + len(TESTS_INTEG)
    print(f"Running {n} dedup-gate tests...")
    for t in TESTS_BASIC:
        print(f"\n[{t.__name__}]")
        try:
            t()
        except Exception as exc:
            global FAIL
            FAIL += 1
            print(f"  CRASH {t.__name__} :: {exc!r}")
    for t in TESTS_INTEG:
        print(f"\n[{t.__name__}]")
        try:
            with tempfile.TemporaryDirectory() as td:
                t(Path(td))
        except Exception as exc:
            FAIL += 1
            print(f"  CRASH {t.__name__} :: {exc!r}")
    print(f"\n{'=' * 64}")
    print(f"  PASS: {PASS}   FAIL: {FAIL}")
    print('=' * 64)
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
