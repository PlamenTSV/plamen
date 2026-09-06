"""Phase E: live pipeline enforcement gates.

These tests cover the live failure modes from the latest audit assessment that
the helper-only Phase A-D work did not yet make structurally impossible:

E1. Verify-output parity: queue rows = N -> N verify files exist (covers Low).
E2. report_index rejects unverified queue rows (verified files = sole input).
E3. crossbatch must cover all verify files; skeptic must cover all C/H reportable.
E4. report_assemble degraded sentinel must halt instead of shipping.
E6. Preferred / Evidence tag missing is a schema failure (queue or verify).
E7. C/H without Impact + Likelihood -> conservative downgrade to Medium.
E8. Dedup runs before report_index ID lock (already exercised in Phase C; here
    we lock the ratio threshold + sibling preservation contract).

Run: `python test_phase_e_live_gates.py`
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


def _seed_queue(sp: Path, ids: list[tuple[str, str]]):
    """ids: list of (finding_id, severity)"""
    lines = ["# Verification Queue", "",
             "| Finding ID | Severity | Title | Location | Preferred Tag |",
             "|------------|----------|-------|----------|---------------|"]
    for fid, sev in ids:
        lines.append(f"| {fid} | {sev} | T {fid} | src/F.sol:L1 | CODE-TRACE |")
    (sp / "verification_queue.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def _write_verify(sp: Path, fid: str, sev: str, body: str = ""):
    (sp / f"verify_{fid}.md").write_text(
        f"""# {fid}
**Verdict**: CONFIRMED
**Severity**: {sev}
**Location**: src/F.sol:L1
**Description**: {body or f'Description for {fid}.'}
**Recommendation**: Do the right thing.
**Evidence Tag**: CODE-TRACE
**Preferred Tag**: CODE-TRACE
""",
        encoding="utf-8",
    )
    bind_verifier_outputs(sp)


# =============================================================================
# E1. Verify-output parity gate.
# =============================================================================

def test_E1_parity_clean(tmp_path: Path):
    sp = tmp_path
    _seed_queue(sp, [("INV-001", "High"), ("INV-002", "Medium"), ("INV-003", "Low")])
    for fid, sev in [("INV-001", "High"), ("INV-002", "Medium"), ("INV-003", "Low")]:
        _write_verify(sp, fid, sev)
    issues = D._validate_verify_files_for_queue(sp)
    check("E1.parity_clean_no_issues", not issues, repr(issues))


def test_E1_parity_missing_high(tmp_path: Path):
    sp = tmp_path
    _seed_queue(sp, [("INV-001", "High"), ("INV-002", "High")])
    _write_verify(sp, "INV-001", "High")
    # INV-002 missing.
    issues = D._validate_verify_files_for_queue(sp)
    check(
        "E1.parity_flags_missing_high",
        any("INV-002" in s for s in issues),
        repr(issues),
    )


def test_E1_parity_missing_low_too(tmp_path: Path):
    """Low shards must NOT be silently allowed to drop."""
    sp = tmp_path
    _seed_queue(sp, [("INV-001", "High"), ("INV-002", "Low")])
    _write_verify(sp, "INV-001", "High")
    # INV-002 (Low) missing.
    issues = D._validate_verify_files_for_queue(sp)
    check(
        "E1.parity_low_missing_blocks",
        any("INV-002" in s for s in issues),
        repr(issues),
    )


def test_E1_parity_206_vs_131_pattern(tmp_path: Path):
    """Replicates the live failure shape: many missing across all tiers."""
    sp = tmp_path
    ids = (
        [(f"INV-H{i:03d}", "High") for i in range(1, 51)]
        + [(f"INV-M{i:03d}", "Medium") for i in range(1, 81)]
        + [(f"INV-L{i:03d}", "Low") for i in range(1, 76)]
    )
    _seed_queue(sp, ids)
    # Write verify files for only ~131 of the 206.
    for fid, sev in ids[:131]:
        _write_verify(sp, fid, sev)
    issues = D._validate_verify_files_for_queue(sp)
    # Must report a count gap and at least sample missing IDs.
    check(
        "E1.parity_count_gap_reported",
        any("206" in s or "131" in s or "75" in s for s in issues),
        repr(issues[:3]),
    )


def test_E1_empty_queue_no_issues(tmp_path: Path):
    sp = tmp_path
    (sp / "verification_queue.md").write_text("""# Verification Queue

| Finding ID | Severity | Title | Location | Preferred Tag |
|------------|----------|-------|----------|---------------|
""", encoding="utf-8")
    issues = D._validate_verify_files_for_queue(sp)
    check(
        "E1.empty_queue_requires_authenticated_marker",
        any("no parseable finding rows" in issue for issue in issues),
        repr(issues),
    )


# =============================================================================
# E2. Report index rejects unverified findings.
# =============================================================================

def test_E2_report_index_halts_when_unverified(tmp_path: Path):
    sp = tmp_path
    _seed_queue(sp, [("INV-001", "High"), ("INV-002", "Medium")])
    _write_verify(sp, "INV-001", "High")
    # INV-002 has no verify file.
    issues = D._validate_report_index_inputs(sp)
    check(
        "E2.unverified_blocks_index",
        any("INV-002" in s or "unverified" in s.lower() for s in issues),
        repr(issues),
    )


def test_E2_report_index_passes_when_all_verified(tmp_path: Path):
    sp = tmp_path
    _seed_queue(sp, [("INV-001", "High"), ("INV-002", "Medium")])
    _write_verify(sp, "INV-001", "High")
    _write_verify(sp, "INV-002", "Medium")
    D._write_mechanical_report_index(sp)
    issues = D._validate_report_index_inputs(sp)
    check("E2.all_verified_passes", not issues, repr(issues))


# =============================================================================
# E3. Crossbatch / skeptic partial coverage halt.
# =============================================================================

def test_E3_crossbatch_partial_blocks(tmp_path: Path):
    sp = tmp_path
    _seed_queue(sp, [(f"INV-{i:03d}", "High") for i in range(1, 6)])
    for i in range(1, 6):
        _write_verify(sp, f"INV-{i:03d}", "High")
    # Crossbatch only covers 2 of 5.
    (sp / "cross_batch_consistency.md").write_text("""# Cross-Batch Consistency

| Finding ID | Status |
|------------|--------|
| INV-001 | CONSISTENT |
| INV-002 | CONSISTENT |
""", encoding="utf-8")
    issues = D._validate_crossbatch_full_coverage(sp)
    check(
        "E3.crossbatch_partial_blocks",
        any("INV-003" in s or "coverage" in s.lower() for s in issues),
        repr(issues),
    )


def test_E3_skeptic_partial_ch_blocks(tmp_path: Path):
    sp = tmp_path
    # 4 C/H reportable verify files; skeptic only covers 1.
    _seed_queue(sp, [
        ("INV-001", "Critical"), ("INV-002", "High"),
        ("INV-003", "High"), ("INV-004", "Low"),
    ])
    _write_verify(sp, "INV-001", "Critical")
    _write_verify(sp, "INV-002", "High")
    _write_verify(sp, "INV-003", "High")
    _write_verify(sp, "INV-004", "Low")
    # Skeptic file only has INV-001.
    (sp / "skeptic_findings.md").write_text("""# Skeptic Findings

| Finding ID | Decision |
|------------|----------|
| INV-001 | AGREE |
""", encoding="utf-8")
    issues = D._validate_skeptic_full_ch_coverage(sp)
    check(
        "E3.skeptic_partial_ch_blocks",
        any("INV-002" in s or "INV-003" in s or "coverage" in s.lower()
            for s in issues),
        repr(issues),
    )


# =============================================================================
# E4. Report assembly degradation is blocking.
# =============================================================================

def test_E4_assemble_degraded_halts(tmp_path: Path):
    sp = tmp_path
    # Degraded sentinel from prior runs - if it's present, halt.
    (sp / "report_assemble.degraded").write_text(
        "missing-finding: M-99\nfp-leakage: H-04",
        encoding="utf-8",
    )
    issues = D._validate_assemble_not_degraded(sp)
    check(
        "E4.assemble_degraded_blocks",
        any("degraded" in s.lower() or "halt" in s.lower() for s in issues),
        repr(issues),
    )


def test_E4_assemble_clean_passes(tmp_path: Path):
    sp = tmp_path
    issues = D._validate_assemble_not_degraded(sp)
    check("E4.assemble_clean_passes", not issues, repr(issues))


# =============================================================================
# E6. Preferred / Evidence tag schema failure.
# =============================================================================

def test_E6_missing_preferred_tag_in_verify_blocks(tmp_path: Path):
    sp = tmp_path
    _seed_queue(sp, [("INV-001", "High")])
    # Verify body without Preferred Tag / Evidence Tag.
    (sp / "verify_INV-001.md").write_text("""# INV-001
**Verdict**: CONFIRMED
**Severity**: High
**Location**: src/F.sol:L1
**Description**: x
**Recommendation**: y
""", encoding="utf-8")
    issues = D._validate_verify_evidence_tags(sp)
    check(
        "E6.missing_evidence_tag_flagged",
        any("INV-001" in s for s in issues),
        repr(issues),
    )


def test_E6_evidence_tag_present_passes(tmp_path: Path):
    sp = tmp_path
    _seed_queue(sp, [("INV-001", "High")])
    _write_verify(sp, "INV-001", "High")
    issues = D._validate_verify_evidence_tags(sp)
    check("E6.evidence_tag_present_passes", not issues, repr(issues))


# =============================================================================
# E7. Severity matrix input completeness for C/H.
# =============================================================================

def test_E7_critical_verifier_stated_preserved(tmp_path: Path):
    """Verifier explicitly wrote Severity: Critical -> preserved even without
    Impact/Likelihood. E7 only fires for queue-row-inherited severity."""
    sp = tmp_path
    _seed_queue(sp, [("INV-001", "Critical")])
    (sp / "verify_INV-001.md").write_text("""# INV-001
**Verdict**: CONFIRMED
**Severity**: Critical
**Location**: src/F.sol:L1
**Description**: x
**Recommendation**: y
**Evidence Tag**: CODE-TRACE
""", encoding="utf-8")
    bind_verifier_outputs(sp)
    D._write_mechanical_report_index(sp)
    records = json.loads((sp / "report_records.json").read_text(encoding="utf-8"))
    sev = records["active"][0]["severity"]
    check(
        "E7.critical_verifier_stated_preserved",
        sev == "Critical",
        f"sev={sev}",
    )


def test_E7_critical_queue_only_downgrades_to_medium(tmp_path: Path):
    """No Severity field in verify text, queue says Critical -> E7 downgrades
    to Medium (conservative fallback for queue-inherited severity)."""
    sp = tmp_path
    _seed_queue(sp, [("INV-001", "Critical")])
    (sp / "verify_INV-001.md").write_text("""# INV-001
**Verdict**: CONFIRMED
**Location**: src/F.sol:L1
**Description**: x
**Recommendation**: y
**Evidence Tag**: CODE-TRACE
""", encoding="utf-8")
    bind_verifier_outputs(sp)
    D._write_mechanical_report_index(sp)
    records = json.loads((sp / "report_records.json").read_text(encoding="utf-8"))
    sev = records["active"][0]["severity"]
    check(
        "E7.critical_queue_only_downgraded",
        sev == "Medium",
        f"sev={sev}",
    )


def test_E7_high_with_impact_likelihood_keeps_severity(tmp_path: Path):
    sp = tmp_path
    _seed_queue(sp, [("INV-001", "High")])
    (sp / "verify_INV-001.md").write_text("""# INV-001
**Verdict**: CONFIRMED
**Severity**: High
**Location**: src/F.sol:L1
**Impact**: High
**Likelihood**: Medium
**Description**: x
**Recommendation**: y
**Evidence Tag**: CODE-TRACE
""", encoding="utf-8")
    bind_verifier_outputs(sp)
    D._write_mechanical_report_index(sp)
    records = json.loads((sp / "report_records.json").read_text(encoding="utf-8"))
    sev = records["active"][0]["severity"]
    check(
        "E7.high_with_inputs_kept",
        sev == "High",
        f"sev={sev}",
    )


def test_E7_low_without_inputs_NOT_downgraded(tmp_path: Path):
    """Conservative downgrade only triggers for C/H, not Low/Info."""
    sp = tmp_path
    _seed_queue(sp, [("INV-001", "Low")])
    _write_verify(sp, "INV-001", "Low")
    D._write_mechanical_report_index(sp)
    records = json.loads((sp / "report_records.json").read_text(encoding="utf-8"))
    sev = records["active"][0]["severity"]
    check(
        "E7.low_missing_inputs_kept",
        sev == "Low",
        f"sev={sev}",
    )


# =============================================================================
# E8. Dedup ratio threshold + sibling preservation.
# =============================================================================

def test_E8_sibling_bugs_at_same_location_kept_separate(tmp_path: Path):
    """Two bugs at the same file:line with DIFFERENT fix patterns -> not consolidated."""
    sp = tmp_path
    _seed_queue(sp, [("INV-001", "Medium"), ("INV-002", "Medium"), ("INV-003", "Medium")])
    # INV-001/002/003 share location but require different fixes.
    (sp / "verify_INV-001.md").write_text("""# INV-001
**Verdict**: CONFIRMED
**Severity**: Medium
**Location**: src/F.sol:L1
**Description**: Reentrancy.
**Recommendation**: Add ReentrancyGuard.
**Evidence Tag**: CODE-TRACE
""", encoding="utf-8")
    (sp / "verify_INV-002.md").write_text("""# INV-002
**Verdict**: CONFIRMED
**Severity**: Medium
**Location**: src/F.sol:L1
**Description**: Integer overflow.
**Recommendation**: Use SafeMath.
**Evidence Tag**: CODE-TRACE
""", encoding="utf-8")
    (sp / "verify_INV-003.md").write_text("""# INV-003
**Verdict**: CONFIRMED
**Severity**: Medium
**Location**: src/F.sol:L1
**Description**: Missing access control.
**Recommendation**: Add onlyOwner.
**Evidence Tag**: CODE-TRACE
""", encoding="utf-8")
    bind_verifier_outputs(sp)
    D._write_mechanical_report_index(sp)
    records = json.loads((sp / "report_records.json").read_text(encoding="utf-8"))
    n = len(records["active"])
    check(
        "E8.sibling_bugs_at_same_location_kept",
        n == 3,
        f"n={n} active={records['active']}",
    )


# =============================================================================
# E5. LLM body writer wiring: manifest emission + tier validator hook.
# =============================================================================

def test_E5_report_index_emits_body_manifests(tmp_path: Path):
    """report_index must emit body_manifests/<shard>.json for every shard."""
    sp = tmp_path
    _seed_queue(sp, [
        ("INV-001", "Critical"), ("INV-002", "High"),
        ("INV-003", "Medium"), ("INV-004", "Low"),
    ])
    for fid, sev in [("INV-001", "Critical"), ("INV-002", "High"),
                     ("INV-003", "Medium"), ("INV-004", "Low")]:
        # Add Impact/Likelihood so E7 doesn't downgrade.
        impact_likelihood = {
            "Critical": ("High", "High"),
            "High": ("High", "Medium"),
            "Medium": ("Medium", "Medium"),
            "Low": ("Low", "Medium"),
        }
        impact, likelihood = impact_likelihood[sev]
        (sp / f"verify_{fid}.md").write_text(
            f"""# {fid}
**Verdict**: CONFIRMED
**Severity**: {sev}
**Impact**: {impact}
**Likelihood**: {likelihood}
**Location**: src/F.sol:L1
**Description**: Test for {fid}
**Recommendation**: Fix it
**Evidence Tag**: CODE-TRACE
**Preferred Tag**: CODE-TRACE
""",
            encoding="utf-8",
        )
    bind_verifier_outputs(sp)
    D._write_mechanical_report_index(sp)
    manifests_dir = sp / "body_manifests"
    check(
        "E5.body_manifests_dir_exists",
        manifests_dir.exists() and manifests_dir.is_dir(),
        f"dir={manifests_dir}",
    )
    has_ch = (manifests_dir / "report_critical_high.json").exists()
    has_low = (manifests_dir / "report_low_info.json").exists()
    check(
        "E5.body_manifests_per_shard_emitted",
        has_ch and has_low,
        f"ch={has_ch} low={has_low}",
    )


def test_E5_tier_validator_catches_hallucinated_body(tmp_path: Path):
    sp = tmp_path
    _seed_queue(sp, [("INV-001", "High")])
    (sp / "verify_INV-001.md").write_text(
        """# INV-001
**Verdict**: CONFIRMED
**Severity**: High
**Impact**: High
**Likelihood**: Medium
**Location**: src/F.sol:L1
**Description**: real bug
**Recommendation**: fix it
**Evidence Tag**: CODE-TRACE
""", encoding="utf-8")
    bind_verifier_outputs(sp)
    D._write_mechanical_report_index(sp)
    # Write a body file that contains a hallucinated H-99 ID.
    (sp / "report_critical_high.md").write_text(
        """# Critical and High Findings

## High Findings

### [H-01] real bug
**Severity**: High
**Location**: src/F.sol:L1
real description.

### [H-99] hallucinated bug
**Severity**: High
**Location**: src/HALLUCINATED.sol:L42
fake description.
""", encoding="utf-8")
    issues = D._validate_tier_body_against_manifest(sp, "report_critical_high")
    check(
        "E5.tier_validator_catches_hallucination",
        any("H-99" in s or "hallucinated" in s.lower() for s in issues),
        repr(issues),
    )


def test_E5_tier_validator_clean_passes(tmp_path: Path):
    sp = tmp_path
    _seed_queue(sp, [("INV-001", "High")])
    (sp / "verify_INV-001.md").write_text(
        """# INV-001
**Verdict**: CONFIRMED
**Severity**: High
**Impact**: High
**Likelihood**: Medium
**Location**: src/F.sol:L1
**Description**: real bug
**Recommendation**: fix it
**Evidence Tag**: CODE-TRACE
""", encoding="utf-8")
    bind_verifier_outputs(sp)
    D._write_mechanical_report_index(sp)
    (sp / "report_critical_high.md").write_text(
        """# Critical and High Findings

## High Findings

### [H-01] real bug
**Severity**: High
**Location**: src/F.sol:L1
**Description**: A real description.
**Impact**: An attacker can withdraw more than their share.
**PoC Result**: Test confirms the excess withdrawal; assertion passed.
**Recommendation**: fix it
""", encoding="utf-8")
    issues = D._validate_tier_body_against_manifest(sp, "report_critical_high")
    check(
        "E5.tier_validator_clean_passes",
        not issues,
        repr(issues),
    )


# =============================================================================
# Test runner
# =============================================================================

TESTS = [
    test_E1_parity_clean,
    test_E1_parity_missing_high,
    test_E1_parity_missing_low_too,
    test_E1_parity_206_vs_131_pattern,
    test_E1_empty_queue_no_issues,
    test_E2_report_index_halts_when_unverified,
    test_E2_report_index_passes_when_all_verified,
    test_E3_crossbatch_partial_blocks,
    test_E3_skeptic_partial_ch_blocks,
    test_E4_assemble_degraded_halts,
    test_E4_assemble_clean_passes,
    test_E6_missing_preferred_tag_in_verify_blocks,
    test_E6_evidence_tag_present_passes,
    test_E7_critical_verifier_stated_preserved,
    test_E7_critical_queue_only_downgrades_to_medium,
    test_E7_high_with_impact_likelihood_keeps_severity,
    test_E7_low_without_inputs_NOT_downgraded,
    test_E8_sibling_bugs_at_same_location_kept_separate,
    test_E5_report_index_emits_body_manifests,
    test_E5_tier_validator_catches_hallucinated_body,
    test_E5_tier_validator_clean_passes,
]


def main() -> int:
    print(f"Running {len(TESTS)} live-gate tests...")
    for t in TESTS:
        print(f"\n[{t.__name__}]")
        try:
            with tempfile.TemporaryDirectory() as td:
                t(Path(td))
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
