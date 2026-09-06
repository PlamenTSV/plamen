"""Pre-soak hardening tests for Phase E11 follow-ups.

Items addressed:
1. Empty-shard body-writer skip: when a tier has 0 findings, the body
   writer must not call an LLM and must not depend on LLM output.
2. Crossbatch / skeptic ID parsing: handle bracketed IDs, markdown links,
   comma lists, range syntax like `INV-001..INV-150`.
3. Body-writer retry hints: when the validator fails, the retry-hint file
   names missing IDs, extra IDs, integrity errors, and blocked-tag misses.
4. Trivial regression: severity matrix + UNRESOLVED composition.

Run: `python test_phase_e_pre_soak.py`
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS_DIR))

import plamen_driver as D  # noqa: E402
from typed_test_authority import bind_verifier_outputs  # noqa: E402

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
# Item 1: Empty-shard body-writer skip.
# =============================================================================

def test_EMPTY_skip_writes_empty_tier_note(tmp_path: Path):
    sp = tmp_path
    # Seed a queue with only Low findings — Critical/High and Medium shards
    # produce no manifest entries.
    (sp / "verification_queue.md").write_text("""# Verification Queue

| Finding ID | Severity | Title | Location | Preferred Tag |
|------------|----------|-------|----------|---------------|
| INV-001 | Low | only-low | src/F.sol:L1 | CODE-TRACE |
""", encoding="utf-8")
    (sp / "verify_INV-001.md").write_text("""# INV-001
**Verdict**: CONFIRMED
**Severity**: Low
**Impact**: Low
**Likelihood**: Medium
**Location**: src/F.sol:L1
**Description**: bug
**Recommendation**: fix
**Evidence Tag**: CODE-TRACE
""", encoding="utf-8")
    bind_verifier_outputs(sp)
    D._write_mechanical_report_index(sp)
    # The empty-tier handler should produce a substantive note for shards
    # with no findings.
    skipped = D._maybe_skip_empty_body_writer(sp, "report_body_writer_critical_high")
    check("EMPTY.skip_returns_true_for_empty_shard", skipped is True, f"got={skipped}")
    out = sp / "report_critical_high.md"
    check(
        "EMPTY.tier_file_substantive",
        out.exists() and out.stat().st_size > 100,
        f"size={out.stat().st_size if out.exists() else 'absent'}",
    )
    txt = out.read_text(encoding="utf-8")
    check(
        "EMPTY.tier_file_marks_no_findings_for_tier",
        "no findings" in txt.lower() or "no findings of this severity" in txt.lower(),
        txt[:200],
    )
    check(
        "EMPTY.tier_file_has_driver_auth_token",
        "Empty-Tier-Auth: PLAMEN-DRIVER-AUTHENTIC-EMPTY-TIER" in txt,
        txt[-250:],
    )
    issues = D._validate_tier_body_against_manifest(sp, "report_critical_high")
    check("EMPTY.authenticated_empty_tier_passes_validator", issues == [], repr(issues))


def test_EMPTY_missing_manifest_with_no_auth_fails(tmp_path: Path):
    sp = tmp_path
    (sp / "report_critical_high.md").write_text(
        "# Critical and High Findings\n\n_No findings here._\n",
        encoding="utf-8",
    )
    issues = D._validate_tier_body_against_manifest(sp, "report_critical_high")
    check(
        "EMPTY.unauthenticated_no_id_body_fails",
        bool(issues) and "body_manifests missing" in issues[0],
        repr(issues),
    )


def test_EMPTY_skip_returns_false_when_manifest_exists(tmp_path: Path):
    sp = tmp_path
    (sp / "verification_queue.md").write_text("""# Verification Queue

| Finding ID | Severity | Title | Location | Preferred Tag |
|------------|----------|-------|----------|---------------|
| INV-001 | High | bug | src/F.sol:L1 | CODE-TRACE |
""", encoding="utf-8")
    (sp / "verify_INV-001.md").write_text("""# INV-001
**Verdict**: CONFIRMED
**Severity**: High
**Impact**: High
**Likelihood**: Medium
**Description**: x
**Recommendation**: y
**Evidence Tag**: CODE-TRACE
""", encoding="utf-8")
    bind_verifier_outputs(sp)
    D._write_mechanical_report_index(sp)
    # Body-writer manifest for critical_high is non-empty; skip must be False.
    skipped = D._maybe_skip_empty_body_writer(sp, "report_body_writer_critical_high")
    check("EMPTY.skip_false_when_findings", skipped is False, f"got={skipped}")


# =============================================================================
# Item 2: Crossbatch / skeptic ID parsing hardening.
# =============================================================================

def test_IDPARSE_bracketed_link_comma_range():
    # Bracketed
    s = "Findings reviewed: [INV-001], [INV-002]"
    got = D._extract_finding_ids_from_text(s)
    check(
        "IDPARSE.bracketed",
        {"INV-001", "INV-002"}.issubset(got),
        repr(got),
    )

    # Markdown links
    s = "See [INV-003](verify_INV-003.md) and [INV-004](verify_INV-004.md)."
    got = D._extract_finding_ids_from_text(s)
    check(
        "IDPARSE.markdown_link",
        {"INV-003", "INV-004"}.issubset(got),
        repr(got),
    )

    # Comma list
    s = "INV-005, INV-006, INV-007 — all consistent"
    got = D._extract_finding_ids_from_text(s)
    check(
        "IDPARSE.comma_list",
        {"INV-005", "INV-006", "INV-007"}.issubset(got),
        repr(got),
    )

    # Range
    s = "Reviewed INV-010..INV-015 inclusive"
    got = D._extract_finding_ids_from_text(s)
    check(
        "IDPARSE.range_expansion",
        {"INV-010", "INV-011", "INV-012", "INV-013", "INV-014", "INV-015"}
            .issubset(got),
        repr(got),
    )

    # Range with leading-zero preservation
    s = "Reviewed INV-001..INV-003"
    got = D._extract_finding_ids_from_text(s)
    check(
        "IDPARSE.range_preserves_padding",
        {"INV-001", "INV-002", "INV-003"}.issubset(got),
        repr(got),
    )


def test_IDPARSE_doesnt_overmatch():
    """Plain prose without IDs returns empty."""
    s = "All verified findings were reviewed and found consistent with prior analysis."
    got = D._extract_finding_ids_from_text(s)
    check("IDPARSE.no_overmatch", got == set(), repr(got))


def test_IDPARSE_range_cap():
    """Pathological ranges (very large) are bounded to prevent DoS."""
    s = "INV-000001..INV-100000"
    got = D._extract_finding_ids_from_text(s)
    check(
        "IDPARSE.large_range_capped",
        len(got) <= 10000,  # reasonable cap
        f"size={len(got)}",
    )


def test_IDPARSE_crossbatch_validator_uses_robust_parsing(tmp_path: Path):
    sp = tmp_path
    # 5 verify files, crossbatch references them via a range.
    for i in range(1, 6):
        (sp / f"verify_INV-{i:03d}.md").write_text(
            f"# INV-{i:03d}\n**Verdict**: CONFIRMED\n", encoding="utf-8")
    (sp / "cross_batch_consistency.md").write_text(
        "# CB\nReviewed INV-001..INV-005 — consistent.\n", encoding="utf-8")
    issues = D._validate_crossbatch_full_coverage(sp)
    check(
        "IDPARSE.crossbatch_range_clears_gate",
        not issues,
        repr(issues),
    )


def test_IDPARSE_skeptic_validator_uses_robust_parsing(tmp_path: Path):
    sp = tmp_path
    # 3 C/H verify files; skeptic uses comma list.
    (sp / "verification_queue.md").write_text("""# Q

| Finding ID | Severity | Title | Location | Preferred Tag |
|------------|----------|-------|----------|---------------|
| INV-001 | Critical | x | src/F:L1 | CODE-TRACE |
| INV-002 | High | y | src/F:L2 | CODE-TRACE |
| INV-003 | High | z | src/F:L3 | CODE-TRACE |
""", encoding="utf-8")
    for fid, sev in [("INV-001", "Critical"), ("INV-002", "High"), ("INV-003", "High")]:
        (sp / f"verify_{fid}.md").write_text(
            f"""# {fid}
**Verdict**: CONFIRMED
**Severity**: {sev}
**Impact**: High
**Likelihood**: Medium
**Location**: src/F:L1
**Description**: x
**Recommendation**: y
""", encoding="utf-8")
    (sp / "skeptic_findings.md").write_text(
        "# S\nReviewed: INV-001, INV-002, INV-003.\n", encoding="utf-8")
    (sp / "skeptic_judge_decisions.md").write_text(
        "| Finding ID | Original Severity | Final Severity | Decision | Rationale |\n"
        "|------------|-------------------|----------------|----------|-----------|\n"
        "| INV-001 | Critical | Critical | KEEP | ok |\n"
        "| INV-002 | High | High | KEEP | ok |\n"
        "| INV-003 | High | High | KEEP | ok |\n",
        encoding="utf-8",
    )
    issues = D._validate_skeptic_full_ch_coverage(sp)
    check(
        "IDPARSE.skeptic_comma_list_clears_gate",
        not issues,
        repr(issues),
    )


# =============================================================================
# Item 3: Body-writer retry hints.
# =============================================================================

def test_RETRY_hint_lists_specific_violations(tmp_path: Path):
    sp = tmp_path
    (sp / "verification_queue.md").write_text("""# Q

| Finding ID | Severity | Title | Location | Preferred Tag |
|------------|----------|-------|----------|---------------|
| INV-001 | High | a | src/F.sol:L1 | CODE-TRACE |
| INV-002 | High | b | src/F.sol:L2 | CODE-TRACE |
""", encoding="utf-8")
    for fid in ["INV-001", "INV-002"]:
        (sp / f"verify_{fid}.md").write_text(f"""# {fid}
**Verdict**: CONFIRMED
**Severity**: High
**Impact**: High
**Likelihood**: Medium
**Location**: src/F.sol:L1
**Description**: a
**Recommendation**: b
**Evidence Tag**: CODE-TRACE
""", encoding="utf-8")
    bind_verifier_outputs(sp)
    D._write_mechanical_report_index(sp)
    # Bad body: missing H-02, hallucinates H-99, wrong location for H-01.
    (sp / "report_critical_high.md").write_text("""# Critical and High

## High Findings

### [H-01] real bug
**Severity**: High
**Location**: src/HALLUCINATED.sol:L99
**Description**: ...

### [H-99] hallucinated
**Severity**: High
**Location**: src/X.sol:L1
""", encoding="utf-8")
    hint = D._generate_body_writer_retry_hint(sp, "report_body_writer_critical_high")
    check(
        "RETRY.hint_names_missing_id",
        "H-02" in hint,
        hint[:400],
    )
    check(
        "RETRY.hint_names_extra_id",
        "H-99" in hint,
        hint[:400],
    )
    check(
        "RETRY.hint_mentions_location_drift",
        "location" in hint.lower() or "integrity" in hint.lower(),
        hint[:400],
    )


def test_RETRY_hint_empty_when_body_clean(tmp_path: Path):
    sp = tmp_path
    (sp / "verification_queue.md").write_text("""# Q

| Finding ID | Severity | Title | Location | Preferred Tag |
|------------|----------|-------|----------|---------------|
| INV-001 | High | a | src/F.sol:L1 | CODE-TRACE |
""", encoding="utf-8")
    (sp / "verify_INV-001.md").write_text("""# INV-001
**Verdict**: CONFIRMED
**Severity**: High
**Impact**: High
**Likelihood**: Medium
**Location**: src/F.sol:L1
**Description**: a
**Recommendation**: b
**Evidence Tag**: CODE-TRACE
""", encoding="utf-8")
    bind_verifier_outputs(sp)
    D._write_mechanical_report_index(sp)
    (sp / "report_critical_high.md").write_text("""# Critical and High

## High Findings

### [H-01] a
**Severity**: High
**Location**: src/F.sol:L1
**Description**: ok
**Impact**: An attacker can withdraw more than their share.
**PoC Result**: Test confirms the excess withdrawal; assertion passed.
**Recommendation**: ok
""", encoding="utf-8")
    hint = D._generate_body_writer_retry_hint(sp, "report_body_writer_critical_high")
    check("RETRY.hint_empty_for_clean_body", hint == "", repr(hint))


# =============================================================================
# Item 4: Severity-matrix + UNRESOLVED composition (regression).
# =============================================================================

def test_E7_then_UNRESOLVED_composition(tmp_path: Path):
    """UNRESOLVED records uncertainty without acquiring downgrade authority."""
    sp = tmp_path
    (sp / "verification_queue.md").write_text("""# Q

| Finding ID | Severity | Title | Location | Preferred Tag |
|------------|----------|-------|----------|---------------|
| INV-001 | Critical | bug | src/F.sol:L1 | CODE-TRACE |
""", encoding="utf-8")
    (sp / "verify_INV-001.md").write_text("""# INV-001
**Verdict**: UNRESOLVED
**Severity**: Critical
**Description**: x
**Recommendation**: y
**Evidence Tag**: CODE-TRACE
""", encoding="utf-8")
    bind_verifier_outputs(sp)
    D._write_mechanical_report_index(sp)
    rec = json.loads((sp / "report_records.json").read_text(encoding="utf-8"))
    sev = rec["active"][0]["severity"]
    unresolved = rec["active"][0]["unresolved"]
    adjustments = rec["active"][0]["severity_adjustments"]
    # P0-V: uncertainty is additive evidence state.  It cannot silently lower
    # the queue/verifier Critical tier without typed adjudication authority.
    check(
        "COMPOSE.E7_then_UNRESOLVED_retains_Critical",
        sev == "Critical"
        and unresolved is True
        and adjustments == ["UNRESOLVED(Critical)"],
        f"sev={sev} unresolved={unresolved} adjustments={adjustments}",
    )


def test_REPORT_INDEX_silent_severity_delta_flagged(tmp_path: Path):
    """Index Agent may change severity only with an explicit adjustment reason."""
    sp = tmp_path
    (sp / "verification_queue.md").write_text("""# Q

| Finding ID | Severity | Title | Location | Preferred Tag |
|------------|----------|-------|----------|---------------|
| H-1 | Medium | bug | src/F.sol:L1 | CODE-TRACE |
""", encoding="utf-8")
    (sp / "verify_H-1.md").write_text("""# H-1
**Verdict**: CONFIRMED
**Severity**: Medium
**Location**: src/F.sol:L1
**Description**: This verifier confirms a real medium-severity issue with enough narrative content to pass file-size parity.
**Recommendation**: Fix the issue and add a regression test covering the affected accounting path.
""", encoding="utf-8")
    (sp / "report_index.md").write_text("""# Report Index

## Master Finding Index
| Report ID | Title | Severity | Location | Verification | Trust Adj. | Internal Hypothesis |
|-----------|-------|----------|----------|--------------|------------|---------------------|
| L-01 | bug | Low | src/F.sol:L1 | CONFIRMED | - | H-1 |
""", encoding="utf-8")
    bind_verifier_outputs(sp)
    issues = D._validate_report_index_inputs(sp)
    check(
        "REPORT_INDEX.silent_severity_delta_flagged",
        bool(issues) and "severity provenance" in issues[0],
        f"issues={issues}",
    )


def test_REPORT_INDEX_reason_prose_is_not_severity_authority(tmp_path: Path):
    """A prose reason cannot lower a tier without typed cutover authority."""
    sp = tmp_path
    (sp / "verification_queue.md").write_text("""# Q

| Finding ID | Severity | Title | Location | Preferred Tag |
|------------|----------|-------|----------|---------------|
| H-1 | Medium | bug | src/F.sol:L1 | CODE-TRACE |
""", encoding="utf-8")
    (sp / "verify_H-1.md").write_text("""# H-1
**Verdict**: CONFIRMED
**Severity**: Medium
**Location**: src/F.sol:L1
**Description**: This verifier confirms a real medium-severity issue with enough narrative content to pass file-size parity.
**Recommendation**: Fix the issue and add a regression test covering the affected accounting path.
""", encoding="utf-8")
    (sp / "report_index.md").write_text("""# Report Index

## Master Finding Index
| Report ID | Title | Severity | Location | Verification | Trust Adj. | Internal Hypothesis |
|-----------|-------|----------|----------|--------------|------------|---------------------|
| L-01 | bug | Low | src/F.sol:L1 | CONFIRMED | TRUSTED-ACTOR downgrade from Medium | H-1 |
""", encoding="utf-8")
    bind_verifier_outputs(sp)
    issues = D._validate_report_index_inputs(sp)
    check(
        "REPORT_INDEX.reason_prose_is_not_severity_authority",
        bool(issues) and "severity provenance" in issues[0],
        f"issues={issues}",
    )


# =============================================================================
# Test runner
# =============================================================================

TESTS_BASIC = [
    test_IDPARSE_bracketed_link_comma_range,
    test_IDPARSE_doesnt_overmatch,
    test_IDPARSE_range_cap,
]

TESTS_INTEG = [
    test_EMPTY_skip_writes_empty_tier_note,
    test_EMPTY_skip_returns_false_when_manifest_exists,
    test_IDPARSE_crossbatch_validator_uses_robust_parsing,
    test_IDPARSE_skeptic_validator_uses_robust_parsing,
    test_RETRY_hint_lists_specific_violations,
    test_RETRY_hint_empty_when_body_clean,
    test_E7_then_UNRESOLVED_composition,
    test_REPORT_INDEX_silent_severity_delta_flagged,
    test_REPORT_INDEX_reason_prose_is_not_severity_authority,
]


def main() -> int:
    n = len(TESTS_BASIC) + len(TESTS_INTEG)
    print(f"Running {n} pre-soak hardening tests...")
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
