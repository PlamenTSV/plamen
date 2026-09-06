"""Tests for the report_dedup phase + assembler ghost-reference fix.

Covers BUILD STEP 1:
  (a) report_dedup phase scaffold present, last, critical=False (SC + L1);
      Python-native cross-tier dedup with snapshot-both + mechanical
      data-loss gate; idempotent no-op; veto-keeps-original safety.
  (b) Priority Remediation Order ghost-reference repair: every remediation
      ID must resolve to a real `### [X-NN]` finding section.

Each test uses plain `assert` so pytest genuinely fails on regression.
Run: `python -m pytest scripts/test_report_dedup_phase.py -q`
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS_DIR))

import plamen_types as T  # noqa: E402
import plamen_mechanical as M  # noqa: E402
import plamen_driver as D  # noqa: E402


# =============================================================================
# (a.1) Phase-graph: report_dedup present, last, critical=False
# =============================================================================

def test_report_dedup_present_last_sc():
    names = [p.name for p in T.SC_PHASES]
    assert "report_dedup" in names, "report_dedup missing from SC_PHASES"
    # report_dedup must run AFTER report_assemble (operates on assembled report).
    assert names.index("report_dedup") > names.index("report_assemble")
    # The material-harm floor is the terminal report mutation, AFTER dedup so it
    # operates on the final deduped report; disposition precedes the floor.
    assert names[-1] == "report_floor", f"report_floor not last: {names[-3:]}"
    assert names.index("report_floor") > names.index("report_dedup")
    assert names.index("report_disposition") > names.index("report_dedup")
    assert names.index("report_floor") > names.index("report_disposition")


def test_report_dedup_present_last_l1():
    names = [p.name for p in T.L1_PHASES]
    assert "report_dedup" in names, "report_dedup missing from L1_PHASES"
    assert names.index("report_dedup") > names.index("report_assemble")
    assert names[-1] == "report_floor", f"report_floor not last: {names[-3:]}"
    assert names.index("report_floor") > names.index("report_dedup")
    assert names.index("report_disposition") > names.index("report_dedup")
    assert names.index("report_floor") > names.index("report_disposition")


def test_report_dedup_critical_false():
    for phases, label in [(T.SC_PHASES, "sc"), (T.L1_PHASES, "l1")]:
        dp = [p for p in phases if p.name == "report_dedup"][0]
        assert dp.critical is False, f"{label} report_dedup must be critical=False"
        # gate artifact is the mapping, NOT AUDIT_REPORT.md (must not gate on
        # the delivered report, which is unchanged on no-op/veto).
        assert dp.expected_artifacts == [
            "report_dedup_mapping.md",
            "report_dedup_applied_alias_receipt.json",
        ], dp.expected_artifacts
        assert "AUDIT_REPORT.md" not in dp.expected_artifacts
        # static graph validator requires non-empty markers + artifacts
        assert dp.section_markers, f"{label} report_dedup needs section_markers"
        assert dp.base_timeout_s > 0


def test_report_dedup_phase_graph_valid_all_modes():
    for phases, pipe in [(T.SC_PHASES, "sc"), (T.L1_PHASES, "l1")]:
        for mode in ("light", "core", "thorough"):
            issues = D.validate_phase_graph(phases, pipe, mode)
            rd = [i for i in issues if "report_dedup" in i]
            assert not rd, f"{pipe} {mode} report_dedup issues: {rd}"


# NEGATIVE CONTROL: a phase with empty artifacts AND empty any_of is flagged.
def test_negctrl_empty_artifacts_flagged():
    from dataclasses import replace
    bad = replace(
        [p for p in T.SC_PHASES if p.name == "report_dedup"][0],
        expected_artifacts=[], any_of=[],
    )
    issues = D.validate_phase_graph([bad], "sc", "thorough")
    assert any("expected_artifacts" in i for i in issues), issues


# NEGATIVE CONTROL: empty section_markers is flagged (we deliberately gave the
# Python-native phase a placeholder marker to satisfy the static validator).
def test_negctrl_empty_section_markers_flagged():
    from dataclasses import replace
    bad = replace(
        [p for p in T.SC_PHASES if p.name == "report_dedup"][0],
        section_markers=[],
    )
    issues = D.validate_phase_graph([bad], "sc", "thorough")
    assert any("section_markers" in i for i in issues), issues


# =============================================================================
# (a.2) Section parsing + candidate-pair detection
# =============================================================================

_REPORT_TWO_TIER = """# Security Audit Report — demo

## Critical Findings

### [C-01] Reentrancy in withdraw [VERIFIED]

**Severity**: Critical
**Location**: `src/Vault.sol:L42`
**Description**: The withdraw path is reentrant.
**Impact**:
- Attacker drains the vault.
**PoC Result**: testReentrancyDrain passed.
**Recommendation**: Add a reentrancy guard.

---

## High Findings

### [H-03] Reentrancy in withdraw (duplicate at lower sev) [VERIFIED]

**Severity**: High
**Location**: `src/Vault.sol:L42`
**Description**: Same reentrant withdraw, surfaced again.
**Impact**:
- Funds can be stolen by reentering.
**PoC Result**: testReentrancyDrain passed.
**Recommendation**: Add nonReentrant.

### [H-04] Unrelated overflow

**Severity**: High
**Location**: `src/Math.sol:L9`
**Description**: An unrelated overflow bug.
**Impact**:
- Wrong accounting.
**Recommendation**: Use checked math.
"""


def test_sections_parsed():
    recs = M._dedup_report_sections(_REPORT_TWO_TIER)
    ids = {r["id"] for r in recs}
    assert ids == {"C-01", "H-03", "H-04"}, ids
    c01 = [r for r in recs if r["id"] == "C-01"][0]
    assert "src/Vault.sol:L42" in c01["locations"]
    assert "testReentrancyDrain" in c01["pocs"]


def test_candidate_pairs_cross_tier_shared_location_and_poc():
    recs = M._dedup_report_sections(_REPORT_TWO_TIER)
    # no source IDs available → relies on location/poc/title signals only
    pairs = M._dedup_report_candidate_pairs(recs, {})
    cross = [p for p in pairs if {p["keep"], p["absorb"]} == {"C-01", "H-03"}]
    assert cross, f"expected C-01/H-03 candidate pair, got {pairs}"
    # survivor is the higher-severity finding (C-01)
    assert cross[0]["keep"] == "C-01"
    # H-04 is unrelated → must NOT pair with C-01
    assert not any({"C-01", "H-04"} == {p["keep"], p["absorb"]} for p in pairs)


# The prior version of this test asserted that NO same-tier pair is EVER a
# candidate. That was vacuously true only because `_REPORT_TWO_TIER`'s two
# same-tier findings (H-03, H-04) happen to be genuinely unrelated — the
# assertion held regardless of whether same-tier candidate generation was
# implemented at all. `_dedup_report_candidate_pairs`'s own docstring already
# states candidate generation "spans BOTH same-tier and cross-tier pairs
# (F2)" — the two tests below make that a REAL, non-vacuous assertion: a
# genuine same-tier duplicate DOES surface as a candidate (positive control),
# while two genuinely different same-tier bugs at the same site do NOT reach
# a merge decision (negative control, via the actual merge-authority gate).


def test_same_tier_duplicate_is_a_candidate_pair():
    """Same-tier candidate generation is REAL, not vacuous: two SAME-TIER
    findings describing the same bug at the same location DO surface as a
    candidate pair (report_dedup is the deterministic backstop for same-tier
    duplicates that report_index STEP-1.5 misses — see the function's own
    docstring, 'F2')."""
    report = """# Security Audit Report — demo

## Medium Findings

### [M-01] Reentrancy in withdraw [VERIFIED]

**Severity**: Medium
**Location**: `src/Vault.sol:L42`
**Description**: The withdraw path is reentrant.
**Impact**:
- Attacker drains the vault.
**Recommendation**: Add a reentrancy guard.

### [M-02] Reentrancy withdraw bug [VERIFIED]

**Severity**: Medium
**Location**: `src/Vault.sol:L42`
**Description**: Same reentrant withdraw, surfaced again.
**Impact**:
- Funds can be stolen by reentering.
**Recommendation**: Add nonReentrant.
"""
    recs = M._dedup_report_sections(report)
    pairs = M._dedup_report_candidate_pairs(recs, {})
    same_tier = [p for p in pairs if {p["keep"], p["absorb"]} == {"M-01", "M-02"}]
    assert same_tier, f"expected M-01/M-02 same-tier candidate pair, got {pairs}"


# Same-tier findings at the same code site describing two DIFFERENT bugs
# (missing access control vs. missing event emission) — a shared function name
# alone is deliberately NOT enough to merge (see `_dedup_same_root_cause_ok`'s
# docstring: "a single shared anchor ... is just a co-located function name,
# i.e. a different bug").
_REPORT_SAME_TIER_DIFFERENT_BUGS = """# Security Audit Report — demo

## Medium Findings

### [M-01] withdrawFunds lacks an onlyOwner access-control check [VERIFIED]

**Severity**: Medium
**Location**: `src/Vault.sol:L120-135`
**Description**: Any address can call withdrawFunds and drain the vault.
**Impact**:
- Attacker drains the vault.
**Recommendation**: Restrict withdrawFunds to the contract owner with an onlyOwner modifier.

### [M-02] withdrawFunds omits a WithdrawalProcessed event emission [VERIFIED]

**Severity**: Medium
**Location**: `src/Vault.sol:L120-135`
**Description**: withdrawFunds transfers funds but never emits WithdrawalProcessed, breaking off-chain accounting.
**Impact**:
- Off-chain indexers miss withdrawals.
**Recommendation**: Emit a WithdrawalProcessed event whenever a payout succeeds.
"""


def test_same_tier_different_bugs_not_merge_eligible():
    """NEGATIVE CONTROL (item C, mandate a): two SAME-TIER findings at the
    SAME code site that are DIFFERENT bugs must NOT be merge-eligible.
    Candidate generation may surface them (a shared site/site-adjacent title
    is only ever a HINT — see F2), but the merge AUTHORITY
    (`_dedup_same_fix_ok`, unchanged by this fix) must refuse them: KEEP
    SEPARATE, never MERGE."""
    recs = M._dedup_report_sections(_REPORT_SAME_TIER_DIFFERENT_BUGS)
    a = next(r for r in recs if r["id"] == "M-01")
    b = next(r for r in recs if r["id"] == "M-02")
    ok, reason = M._dedup_same_fix_ok(a, b)
    assert ok is False, (
        f"different same-tier bugs at the same site must NOT be merge-"
        f"eligible, got ok=True reason={reason!r}"
    )


def test_title_jaccard():
    assert M._dedup_title_jaccard("Reentrancy in withdraw", "Reentrancy withdraw bug") >= 0.5
    assert M._dedup_title_jaccard("Reentrancy in withdraw", "Integer overflow in mint") < 0.5


# =============================================================================
# (a.3) data-loss gate
# =============================================================================

def test_data_loss_gate_detects_dropped_location():
    orig = _REPORT_TWO_TIER
    # remove a location that existed in the original
    bad = orig.replace("`src/Math.sol:L9`", "")
    lost = M._dedup_data_loss_gate(orig, bad)
    assert any("src/Math.sol:L9" in x for x in lost), lost


def test_data_loss_gate_detects_dropped_poc():
    orig = _REPORT_TWO_TIER
    bad = orig.replace("testReentrancyDrain", "x", 99)
    lost = M._dedup_data_loss_gate(orig, bad)
    assert any("poc:testReentrancyDrain" in x for x in lost), lost


def test_data_loss_gate_passes_on_identity():
    assert M._dedup_data_loss_gate(_REPORT_TWO_TIER, _REPORT_TWO_TIER) == []


# =============================================================================
# (a.4) end-to-end: merge with source-ID subset + snapshot-both + promote
# =============================================================================

def _setup(tmp: Path, report: str, index: str = "", mapping: str = "") -> tuple[Path, Path]:
    scratch = tmp / "scratch"
    scratch.mkdir()
    proj = tmp / "proj"
    proj.mkdir()
    (proj / "AUDIT_REPORT.md").write_text(report, encoding="utf-8")
    if index:
        (scratch / "report_index.md").write_text(index, encoding="utf-8")
    if mapping:
        (scratch / "finding_mapping.md").write_text(mapping, encoding="utf-8")
    return scratch, proj


# A Master Finding Index that back-joins C-01 and H-03 to overlapping source IDs
# (subset relationship → authorizes a mechanical cross-tier merge).
_INDEX_SUBSET = """# Report Index

## Master Finding Index

| Report ID | Title | Severity | Location | Verification | Trust Adj. | Internal Hypothesis |
|-----------|-------|----------|----------|--------------|-----------|--------------------|
| C-01 | Reentrancy in withdraw | Critical | src/Vault.sol:L42 | VERIFIED | - | H-7 |
| H-03 | Reentrancy in withdraw | High | src/Vault.sol:L42 | VERIFIED | - | H-7 |
| H-04 | Unrelated overflow | High | src/Math.sol:L9 | VERIFIED | - | H-9 |
"""


def test_e2e_merge_promotes_and_snapshots():
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        scratch, proj = _setup(tmp, _REPORT_TWO_TIER, index=_INDEX_SUBSET)
        ok = M._dedup_report_python(scratch, str(proj))
        assert ok is True
        # snapshot-both: original preserved
        assert (scratch / "AUDIT_REPORT.pre-dedup.md").exists()
        assert (scratch / "AUDIT_REPORT.pre-dedup.md").read_text(encoding="utf-8") == _REPORT_TWO_TIER
        # deduped side artifact written
        assert (scratch / "AUDIT_REPORT.deduped.md").exists()
        # mapping written with a MERGE row
        mapping = (scratch / "report_dedup_mapping.md").read_text(encoding="utf-8")
        assert "MERGE" in mapping
        assert "DATA-LOSS GATE: PASS" in mapping
        # delivered report: absorbed content survives (zero loss), absorbed
        # standalone heading removed (survivor consolidated).
        delivered = (proj / "AUDIT_REPORT.md").read_text(encoding="utf-8")
        assert "src/Vault.sol:L42" in delivered
        assert "Consolidated from H-03" in delivered
        # data-loss gate must hold against the original
        assert M._dedup_data_loss_gate(_REPORT_TWO_TIER, delivered) == []


def test_e2e_idempotent_noop_when_no_pairs():
    # A report with two genuinely unrelated cross-tier findings → no merge.
    report = """# Report

## Critical Findings

### [C-01] Reentrancy

**Severity**: Critical
**Location**: `src/A.sol:L1`
**Impact**:
- Drain.
**Recommendation**: guard.

## Low Findings

### [L-01] Missing event on pause

**Severity**: Low
**Location**: `src/B.sol:L99`
**Impact**:
- None.
**Recommendation**: emit a Paused event.
"""
    # NOTE: the Low finding is deliberately a *security-relevant* observation
    # (missing event), NOT a cosmetic class, so the F1 Quality-Observations
    # retabulation does not fire — this test verifies the no-candidate-pair
    # idempotent no-op path specifically.
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        scratch, proj = _setup(tmp, report)
        ok = M._dedup_report_python(scratch, str(proj))
        assert ok is True
        # no-op: delivered report unchanged
        assert (proj / "AUDIT_REPORT.md").read_text(encoding="utf-8") == report
        mapping = (scratch / "report_dedup_mapping.md").read_text(encoding="utf-8")
        assert "report unchanged" in mapping.lower()


def test_e2e_missing_report_is_visible_transaction_debt():
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        scratch = tmp / "scratch"; scratch.mkdir()
        proj = tmp / "proj"; proj.mkdir()
        ok = M._dedup_report_python(scratch, str(proj))
        assert ok is False
        mapping = (scratch / "report_dedup_mapping.md").read_text(
            encoding="utf-8"
        )
        assert "transaction unavailable; retained as debt" in mapping
        assert (scratch / "report_dedup_mapping.md").exists()
        assert not (proj / "AUDIT_REPORT.md").exists()


# NEGATIVE CONTROL: even if a merge is proposed, a deduped output that would
# lose content is VETOED and the ORIGINAL is kept as the delivered report.
def test_negctrl_data_loss_veto_keeps_original(monkeypatch):
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        scratch, proj = _setup(tmp, _REPORT_TWO_TIER, index=_INDEX_SUBSET)

        # Force a lossy "merge" by monkeypatching the coupling to drop content:
        # we simulate by making the gate see a deduped body that lost a location.
        real_gate = M._dedup_data_loss_gate

        def lossy_gate(original, deduped):
            return ["location:src/Vault.sol:L42"]  # pretend content was lost

        monkeypatch.setattr(M, "_dedup_data_loss_gate", lossy_gate)
        ok = M._dedup_report_python(scratch, str(proj))
        monkeypatch.setattr(M, "_dedup_data_loss_gate", real_gate)

        assert ok is True  # critical=False: never halts
        # original report retained as delivered
        delivered = (proj / "AUDIT_REPORT.md").read_text(encoding="utf-8")
        assert delivered == _REPORT_TWO_TIER, "VETO must keep the original report"
        mapping = (scratch / "report_dedup_mapping.md").read_text(encoding="utf-8")
        assert "VETO" in mapping
        # deduped artifact still left as a side artifact for human review
        assert (scratch / "AUDIT_REPORT.deduped.md").exists()


# NEGATIVE CONTROL (mandate b): idempotency — a SECOND run of the phase on an
# already-deduped delivered report is a no-op (no further merge, report stable).
def test_negctrl_second_run_on_deduped_is_noop():
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        scratch, proj = _setup(tmp, _REPORT_TWO_TIER, index=_INDEX_SUBSET)
        # First run: performs the cross-tier merge and promotes.
        ok1 = M._dedup_report_python(scratch, str(proj))
        assert ok1 is True
        after_first = (proj / "AUDIT_REPORT.md").read_text(encoding="utf-8")
        # The merge must actually have happened (otherwise this is a vacuous test).
        assert "Consolidated from H-03" in after_first
        assert after_first != _REPORT_TWO_TIER

        # Second run on the already-deduped report: the absorbed standalone
        # H-03 section is gone, so no cross-tier pair remains → identity no-op.
        ok2 = M._dedup_report_python(scratch, str(proj))
        assert ok2 is True
        after_second = (proj / "AUDIT_REPORT.md").read_text(encoding="utf-8")
        assert after_second == after_first, "second run must be a no-op (idempotent)"
        mapping = (scratch / "report_dedup_mapping.md").read_text(encoding="utf-8")
        assert "report unchanged" in mapping.lower(), \
            "second run should record an identity no-op, got:\n" + mapping


# NEGATIVE CONTROL (mandate d): a pair where BOTH findings carry a large
# source-ID set is SUPPRESSED from the subset signal — no false merge. This is
# the dangerous class-D false-merge guard (large aggregates always carry many
# source IDs; merging them across tiers would destroy distinct findings).
def test_negctrl_large_source_id_set_suppressed():
    recs = M._dedup_report_sections(_REPORT_TWO_TIER)
    n = M._DEDUP_AGGREGATE_SUPPRESS_THRESHOLD
    big_a = {f"H-{k}" for k in range(1, n + 3)}          # > threshold
    big_b = big_a | {f"H-{k}" for k in range(n + 3, n + 6)}  # superset, also big
    # C-01 / H-03 share the SAME location + PoC (weak signals) but both have a
    # large source-ID set, so the strong subset signal must be suppressed.
    src_by_id = {"C-01": big_a, "H-03": big_b, "H-04": {"H-9"}}
    pairs = M._dedup_report_candidate_pairs(recs, src_by_id)
    cross = [p for p in pairs if {p["keep"], p["absorb"]} == {"C-01", "H-03"}]
    # The pair may still surface on weak (location/poc) signals, but the
    # source-id-subset signal MUST be absent (suppressed) — that is what would
    # otherwise authorize a mechanical merge in _dedup_report_python.
    for p in cross:
        assert "source-id-subset" not in p["signals"], \
            f"large-aggregate subset must be suppressed, got signals {p['signals']}"

    # End-to-end: with only weak signals, the phase must NOT merge (KEEP_SEPARATE).
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        scratch, proj = _setup(tmp, _REPORT_TWO_TIER)
        # Build an index that gives C-01/H-03 the large overlapping source sets.
        idx_rows = [
            "# Report Index", "", "## Master Finding Index", "",
            "| Report ID | Title | Severity | Location | Verification | Trust Adj. | Internal Hypothesis |",
            "|---|---|---|---|---|---|---|",
            "| C-01 | Reentrancy | Critical | src/Vault.sol:L42 | VERIFIED | - | " + " ".join(sorted(big_a)) + " |",
            "| H-03 | Reentrancy | High | src/Vault.sol:L42 | VERIFIED | - | " + " ".join(sorted(big_b)) + " |",
            "| H-04 | Overflow | High | src/Math.sol:L9 | VERIFIED | - | H-9 |",
        ]
        (scratch / "report_index.md").write_text("\n".join(idx_rows) + "\n", encoding="utf-8")
        ok = M._dedup_report_python(scratch, str(proj))
        assert ok is True
        # No false merge: the delivered report is unchanged (no consolidation).
        delivered = (proj / "AUDIT_REPORT.md").read_text(encoding="utf-8")
        assert "Consolidated from" not in delivered, \
            "large-aggregate pair must NOT be merged"
        mapping = (scratch / "report_dedup_mapping.md").read_text(encoding="utf-8")
        assert "MERGE" not in mapping.replace("Merges proposed: 0", ""), \
            "no MERGE decision should be recorded for large-aggregate pair"


# =============================================================================
# (b) Assembler ghost-reference fix
# =============================================================================

def test_defined_report_section_ids():
    ids = M._defined_report_section_ids(_REPORT_TWO_TIER)
    assert ids == {"C-01", "H-03", "H-04"}, ids
    # empty / None inputs are tolerated
    assert M._defined_report_section_ids("", None) == set()


# Master index lists M-18 but the medium tier file has NO M-18 section → ghost.
_INDEX_WITH_GHOST = """# Report Index

## Summary

| Severity | Count |
|----------|-------|
| Critical | 0 |
| High | 0 |
| Medium | 2 |
| Low | 0 |
| Informational | 0 |

## Master Finding Index

| Report ID | Title | Severity | Location | Verification | Trust Adj. | Internal Hypothesis |
|-----------|-------|----------|----------|--------------|-----------|--------------------|
| M-01 | Real medium finding | Medium | src/X.sol:L1 | VERIFIED | - | H-1 |
| M-18 | Ghost finding with no section | Medium | src/Y.sol:L2 | VERIFIED | - | H-99 |
"""

_MEDIUM_TIER = """# Medium Findings

## Medium Findings

### [M-01] Real medium finding [VERIFIED]

**Severity**: Medium
**Location**: `src/X.sol:L1`
**Description**: A real, fully-written medium finding with enough body text to
clear the substantive-body gate and appear in the assembled report body.
**Impact**:
- Some concrete medium impact happens here.
**Recommendation**: Apply the documented fix.
"""


def test_assembler_drops_ghost_remediation_id():
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        scratch = tmp / "scratch"; scratch.mkdir()
        proj = tmp / "proj"; proj.mkdir()
        (scratch / "report_index.md").write_text(_INDEX_WITH_GHOST, encoding="utf-8")
        (scratch / "report_medium.md").write_text(_MEDIUM_TIER, encoding="utf-8")
        # empty crit/low so assembly proceeds with medium only
        ok = M._assemble_report_python(scratch, str(proj))
        assert ok is True
        body = (proj / "AUDIT_REPORT.md").read_text(encoding="utf-8")

        # M-01 has a real ### section AND a remediation entry.
        assert "### [M-01]" in body
        # GHOST: M-18 is in the index but has NO finding section.
        assert "### [M-18]" not in body
        # The Priority Remediation Order must NOT cite the ghost M-18.
        rem = body.split("## Priority Remediation Order", 1)[1]
        assert "M-18" not in rem, "ghost remediation ID M-18 leaked into report"
        assert "M-01" in rem, "real finding M-01 missing from remediation order"


# NEGATIVE CONTROL: every Priority Remediation Order ID resolves to a real
# finding section in the assembled body (the general invariant, not just M-18).
def test_negctrl_every_remediation_id_resolves_to_section():
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        scratch = tmp / "scratch"; scratch.mkdir()
        proj = tmp / "proj"; proj.mkdir()
        (scratch / "report_index.md").write_text(_INDEX_WITH_GHOST, encoding="utf-8")
        (scratch / "report_medium.md").write_text(_MEDIUM_TIER, encoding="utf-8")
        ok = M._assemble_report_python(scratch, str(proj))
        assert ok is True
        body = (proj / "AUDIT_REPORT.md").read_text(encoding="utf-8")

        defined = M._defined_report_section_ids(body)
        rem = body.split("## Priority Remediation Order", 1)[1]
        import re
        cited = set(re.findall(r"\b([CHMLI]-\d+)\b", rem))
        dangling = cited - defined
        assert not dangling, f"dangling remediation IDs with no section: {dangling}"


# =============================================================================
# (c) Same-fix recall layer: catch TRUE cross-tier dupes without false merges
# =============================================================================

# (a) TRUE same-fix cross-tier dup: DIFFERENT source IDs (different agents found
# it → no subset signal), DIFFERENT tiers, SAME code site (shared anchor +
# location), SAME recommendation. Must become a candidate AND merge losslessly.
_REPORT_SAME_FIX = """# Security Audit Report — demo

## Medium Findings

### [M-02] Stale reward in claimReward accounting [VERIFIED]

**Severity**: Medium
**Location**: `src/Staking.sol:L120`
**Description**: claimReward reads a stale accumulator before settling.
**Impact**:
- Users receive an incorrect reward amount.
**Recommendation**: Update the reward accumulator inside claimReward by calling
the settle helper before reading the pending balance so the snapshot is current.

## Low Findings

### [L-08] claimReward uses outdated accumulator snapshot [VERIFIED]

**Severity**: Low
**Location**: `src/Staking.sol:L120`
**Description**: The accumulator snapshot in claimReward is outdated.
**Impact**:
- Reward reads can be slightly off.
**Recommendation**: Update the reward accumulator inside claimReward by calling
the settle helper before reading the pending balance so the snapshot is current.
"""

_INDEX_SAME_FIX = """# Report Index

## Master Finding Index

| Report ID | Title | Severity | Location | Verification | Trust Adj. | Internal Hypothesis |
|-----------|-------|----------|----------|--------------|-----------|--------------------|
| M-02 | Stale reward in claimReward accounting | Medium | src/Staking.sol:L120 | VERIFIED | - | H-31 |
| L-08 | claimReward uses outdated accumulator snapshot | Low | src/Staking.sol:L120 | VERIFIED | - | H-44 |
"""


def test_same_fix_pair_is_candidate():
    recs = M._dedup_report_sections(_REPORT_SAME_FIX)
    # DIFFERENT source IDs → no subset signal; same-fix layer must catch it.
    src = {"M-02": {"H-31"}, "L-08": {"H-44"}}
    pairs = M._dedup_report_candidate_pairs(recs, src)
    cross = [p for p in pairs if {p["keep"], p["absorb"]} == {"M-02", "L-08"}]
    assert cross, f"expected M-02/L-08 same-fix candidate, got {pairs}"
    assert any(s.startswith("same-fix-cross-tier") for s in cross[0]["signals"]), \
        f"same-fix-cross-tier signal missing: {cross[0]['signals']}"
    # survivor is the higher-severity finding (M-02 over L-08)
    assert cross[0]["keep"] == "M-02"
    # and NO source-id-subset signal (the whole point — different agents)
    assert "source-id-subset" not in cross[0]["signals"]


def test_same_fix_gate_accepts_true_dup():
    recs = {r["id"]: r for r in M._dedup_report_sections(_REPORT_SAME_FIX)}
    ok, reason = M._dedup_same_fix_ok(recs["M-02"], recs["L-08"])
    assert ok, f"true same-fix pair must pass gate, got {reason}"


def test_negctrl_a_same_fix_different_identity_remains_proposal_only():
    """Same-fix similarity cannot replace applied identity authority."""
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        scratch, proj = _setup(tmp, _REPORT_SAME_FIX, index=_INDEX_SAME_FIX)
        ok = M._dedup_report_python(scratch, str(proj))
        assert ok is True
        delivered = (proj / "AUDIT_REPORT.md").read_text(encoding="utf-8")
        assert "Consolidated from L-08" not in delivered
        assert "### [M-02]" in delivered
        assert "### [L-08]" in delivered
        mapping = (scratch / "report_dedup_mapping.md").read_text(encoding="utf-8")
        assert "KEEP_SEPARATE" in mapping
        assert "SOURCE_IDENTITY_NOT_EQUIVALENT" in mapping


# (b) RELATED-BUT-DISTINCT: SAME variable/topic (totalRewardDistributed), same
# function family, but OPPOSITE direction → DIFFERENT fix. Must NOT merge.
_REPORT_RELATED_DISTINCT = """# Security Audit Report — demo

## Medium Findings

### [M-09] totalRewardDistributed not updated on inflow deposit [VERIFIED]

**Severity**: Medium
**Location**: `src/Burn.sol:L235`
**Description**: distributeRewardForBurning deposits Reward but never increments
totalRewardDistributed on the inflow path.
**Impact**:
- Inflow accounting undercounts distributed Reward.
**Recommendation**: Increment totalRewardDistributed on the inflow deposit path
inside distributeRewardForBurning so the deposited amount is recorded.

## Low Findings

### [I-03] totalRewardDistributed not decremented on outflow burn [VERIFIED]

**Severity**: Informational
**Location**: `src/Burn.sol:L235`
**Description**: The outflow burn path of distributeRewardForBurning never
decrements totalRewardDistributed when Reward leaves.
**Impact**:
- Outflow accounting overcounts remaining Reward.
**Recommendation**: Decrement totalRewardDistributed on the outflow burn path
inside distributeRewardForBurning so the burned amount is removed.
"""

_INDEX_RELATED_DISTINCT = """# Report Index

## Master Finding Index

| Report ID | Title | Severity | Location | Verification | Trust Adj. | Internal Hypothesis |
|-----------|-------|----------|----------|--------------|-----------|--------------------|
| M-09 | totalRewardDistributed not updated on inflow deposit | Medium | src/Burn.sol:L235 | VERIFIED | - | H-50 |
| I-03 | totalRewardDistributed not decremented on outflow burn | Informational | src/Burn.sol:L235 | VERIFIED | - | H-51 |
"""


def test_same_fix_gate_rejects_related_distinct():
    recs = {r["id"]: r for r in M._dedup_report_sections(_REPORT_RELATED_DISTINCT)}
    ok, reason = M._dedup_same_fix_ok(recs["M-09"], recs["I-03"])
    assert not ok, "inflow-vs-outflow (opposite fix) must NOT pass same-fix gate"
    assert "antonym" in reason.lower(), f"expected antonym veto, got {reason}"


def test_negctrl_b_related_distinct_not_merged():
    """NEGATIVE CONTROL (b): a RELATED-BUT-DISTINCT pair (same variable/topic,
    DIFFERENT fix — inflow-vs-outflow) is NOT merged (stays separate)."""
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        scratch, proj = _setup(tmp, _REPORT_RELATED_DISTINCT, index=_INDEX_RELATED_DISTINCT)
        ok = M._dedup_report_python(scratch, str(proj))
        assert ok is True
        delivered = (proj / "AUDIT_REPORT.md").read_text(encoding="utf-8")
        # BOTH findings survive as standalone sections — no false merge.
        assert "### [M-09]" in delivered
        assert "### [I-03]" in delivered
        assert "Consolidated from" not in delivered, \
            "opposite-direction pair must NOT merge (would HIDE a real finding)"
        # delivered report is unchanged (identity)
        assert delivered == _REPORT_RELATED_DISTINCT


def test_negctrl_b_distinct_fix_text_not_merged():
    """Reinforces (b): same site, but the fixes touch different functions /
    have low fix-text overlap → KEEP_SEPARATE even without an antonym."""
    report = """# Report

## High Findings

### [H-01] Access control gap in pause()

**Severity**: High
**Location**: `src/Ctrl.sol:L10`
**Description**: pause() lacks an onlyOwner modifier.
**Impact**:
- Anyone can pause the protocol.
**Recommendation**: Restrict pause to the owner by adding the onlyOwner modifier
to the pause entry point.

## Low Findings

### [L-01] Event missing in pause()

**Severity**: Low
**Location**: `src/Ctrl.sol:L10`
**Description**: pause() emits no event.
**Impact**:
- Off-chain monitors miss pause transitions.
**Recommendation**: Emit a Paused event when the contract transitions so indexers
observe the state change reliably.
"""
    recs = {r["id"]: r for r in M._dedup_report_sections(report)}
    ok, reason = M._dedup_same_fix_ok(recs["H-01"], recs["L-01"])
    assert not ok, f"different fixes (modifier vs event) must not merge: {reason}"
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        scratch, proj = _setup(tmp, report)
        assert M._dedup_report_python(scratch, str(proj)) is True
        delivered = (proj / "AUDIT_REPORT.md").read_text(encoding="utf-8")
        assert "Consolidated from" not in delivered
        assert delivered == report


# (c) data-loss gate still vetoes a lossy same-fix merge → original kept.
def test_negctrl_c_same_fix_lossy_merge_vetoed(monkeypatch):
    """NEGATIVE CONTROL (c): the data-loss gate still vetoes a lossy merge
    (original kept) — even on the new same-fix path."""
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        exact_index = _INDEX_SAME_FIX.replace("| H-44 |", "| H-31 |")
        scratch, proj = _setup(tmp, _REPORT_SAME_FIX, index=exact_index)

        def lossy_gate(original, deduped):
            return ["location:src/Staking.sol:L120"]

        monkeypatch.setattr(M, "_dedup_data_loss_gate", lossy_gate)
        ok = M._dedup_report_python(scratch, str(proj))
        assert ok is True
        delivered = (proj / "AUDIT_REPORT.md").read_text(encoding="utf-8")
        assert delivered == _REPORT_SAME_FIX, "VETO must keep the original report"
        mapping = (scratch / "report_dedup_mapping.md").read_text(encoding="utf-8")
        assert "VETO" in mapping


# (d) idempotency: a second run on an already-same-fix-deduped report is a no-op.
def test_negctrl_d_same_fix_second_run_is_noop():
    """NEGATIVE CONTROL (d): idempotency on the same-fix merge path."""
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        exact_index = _INDEX_SAME_FIX.replace("| H-44 |", "| H-31 |")
        scratch, proj = _setup(tmp, _REPORT_SAME_FIX, index=exact_index)
        assert M._dedup_report_python(scratch, str(proj)) is True
        after_first = (proj / "AUDIT_REPORT.md").read_text(encoding="utf-8")
        assert "Consolidated from L-08" in after_first
        assert after_first != _REPORT_SAME_FIX

        assert M._dedup_report_python(scratch, str(proj)) is True
        after_second = (proj / "AUDIT_REPORT.md").read_text(encoding="utf-8")
        assert after_second == after_first, "second run must be a no-op (idempotent)"
        mapping = (scratch / "report_dedup_mapping.md").read_text(encoding="utf-8")
        assert "report unchanged" in mapping.lower()


def test_antonym_conflict_helper_direct():
    # Direct unit coverage of the antonym discriminator.
    assert M._dedup_fix_antonym_conflict(
        "increment the inflow counter", "decrement the outflow counter"
    )
    # A fix that mentions BOTH directions is not a conflict.
    assert not M._dedup_fix_antonym_conflict(
        "handle both deposit and withdraw paths", "handle deposit and withdraw"
    )
    # Unrelated fixes → no conflict.
    assert not M._dedup_fix_antonym_conflict(
        "add the onlyOwner modifier", "emit a Paused event"
    )


def test_same_fix_gate_rejects_thin_fix_text():
    # A near-empty Recommendation must not authorize a merge.
    thin = {"fix_text": "Fix it.", "anchors": set()}
    other = {"fix_text": "Update the reward accumulator inside claimReward by "
                         "calling settle before reading pending balance.",
             "anchors": set()}
    ok, reason = M._dedup_same_fix_ok(thin, other)
    assert not ok and "thin" in reason.lower(), reason


# =============================================================================
# (e) REAL-SHAPE same-root-cause merge: the bug this fix targets.
#
# Two agents find the SAME bug at the SAME site (OVERLAPPING-but-not-identical
# line ranges) and write SUBSTANTIVE but DIFFERENTLY-WORDED Recommendations with
# NO antonym. Recommendation-Jaccard is < floor here (the inert-on-real-data
# failure mode), so the merge MUST rest on the shared TITLE / root-cause
# identifiers instead. This mirrors the real duplicate halves split across the
# Low and Informational tiers. (The prior thin-rec test exercised the WRONG
# shape — substantive-but-different recs are the real shape.)
# =============================================================================
_REPORT_REAL_SHAPE = """# Security Audit Report — demo

## Low Findings

### [L-50] verifyAndLockStake strict equality bricks creation on floor change [VERIFIED]

**Severity**: Low
**Location**: `core/StakeManager.sol:90-104,44-61`
**Description**: verifyAndLockStake re-reads the live minimum and enforces strict
equality against the snapshot taken at deposit time, so any floor change reverts
market creation for that staker.
**Impact**:
- A valid staker is temporarily blocked from creating their market.
**Recommendation**: Replace the strict-equality guard with a `>=` floor check so
an over-stake still passes, or compare against the value snapshotted at deposit
time instead of the freshly-read live minimum.

## Informational Findings

### [I-40] verifyAndLockStake enforces exact equality against a mutable minimum [VERIFIED]

**Severity**: Informational
**Location**: `core/StakeManager.sol:91-100,45-60`
**Description**: depositMarketStake snapshots the live minimum; verifyAndLockStake
re-reads the live minimum and requires exact equality, so a minimum changed
between deposit and create reverts the staker's creation despite a valid deposit.
**Impact**:
- The staker must withdraw and re-deposit at the new minimum to proceed.
**Recommendation**: Treat the recorded amount as a lower bound rather than an
exact match, or freeze the minimum at deposit time to remove the staleness window
between deposit and verification.
"""

_INDEX_REAL_SHAPE = """# Report Index

## Master Finding Index

| Report ID | Title | Severity | Location | Verification | Trust Adj. | Internal Hypothesis |
|-----------|-------|----------|----------|--------------|-----------|--------------------|
| L-50 | verifyAndLockStake strict equality bricks creation on floor change | Low | core/StakeManager.sol:90-104 | VERIFIED | - | H-71 |
| I-40 | verifyAndLockStake enforces exact equality against a mutable minimum | Informational | core/StakeManager.sol:91-100 | VERIFIED | - | H-72 |
"""


def test_real_shape_same_root_cause_gate_passes():
    """Overlapping (not identical) location + similar title sharing >= 2 anchors
    + substantive-but-DIFFERENT recs + no antonym → gate MUST authorize MERGE on
    the TITLE/root-cause signal (Recommendation Jaccard is below floor here)."""
    recs = {r["id"]: r for r in M._dedup_report_sections(_REPORT_REAL_SHAPE)}
    a, b = recs["L-50"], recs["I-40"]
    # Pre-conditions that make this the REAL shape (not the thin-rec shape):
    # ranges OVERLAP but NO exact location token is shared, so the merge cannot
    # lean on exact-token equality — it must come from range-overlap + title.
    assert not (a["locations"] & b["locations"]), "no exact location token may be shared"
    assert M._dedup_locations_overlap(a["locations"], b["locations"]), \
        "line ranges must overlap (90-104/44-61 vs 91-100/45-60)"
    assert M._dedup_fix_jaccard(a["fix_text"], b["fix_text"]) < M._DEDUP_SAME_FIX_JACCARD, \
        "recs must be substantively DIFFERENT (below the same-fix Jaccard floor)"
    assert len(M._dedup_fix_terms(a["fix_text"])) >= M._DEDUP_SAME_FIX_MIN_TERMS
    assert len(M._dedup_fix_terms(b["fix_text"])) >= M._DEDUP_SAME_FIX_MIN_TERMS
    assert not M._dedup_fix_antonym_conflict(a["fix_text"], b["fix_text"])
    ok, reason = M._dedup_same_fix_ok(a, b)
    assert ok, f"real-shape duplicate halves must merge, got: {reason}"
    assert "same-root-cause" in reason, reason


def test_real_shape_merges_end_to_end_at_higher_tier():
    """End-to-end: the real-shape pair merges losslessly, survivor = higher tier."""
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        exact_index = _INDEX_REAL_SHAPE.replace("| H-72 |", "| H-71 |")
        scratch, proj = _setup(tmp, _REPORT_REAL_SHAPE, index=exact_index)
        assert M._dedup_report_python(scratch, str(proj)) is True
        delivered = (proj / "AUDIT_REPORT.md").read_text(encoding="utf-8")
        # survivor is the Low (higher tier than Info); Info heading is absorbed
        assert "### [L-50]" in delivered
        assert "### [I-40]" not in delivered
        assert "Consolidated from I-40" in delivered
        # lossless against the original
        assert M._dedup_data_loss_gate(_REPORT_REAL_SHAPE, delivered) == []
        mapping = (scratch / "report_dedup_mapping.md").read_text(encoding="utf-8")
        assert "MERGE" in mapping and "EXACT_CURRENT_SOURCE_IDENTITY" in mapping


def test_real_shape_negctrl_same_site_distinct_title_keeps_separate():
    """Same-site, but the titles share < 2 meaningful anchors and have low title
    overlap AND the recs differ → KEEP SEPARATE (guards against over-merge: two
    different bugs in the same function must NOT be conflated)."""
    report = """# Report

## High Findings

### [H-20] Access control gap in settle()

**Severity**: High
**Location**: `core/StakeManager.sol:90-104`
**Description**: settle() lacks an onlyOwner modifier so anyone may call it.
**Impact**:
- Anyone can force settlement.
**Recommendation**: Restrict settle to the owner by adding the onlyOwner modifier
to the entry point so only governance can trigger it.

## Low Findings

### [L-60] Missing event in settle()

**Severity**: Low
**Location**: `core/StakeManager.sol:95-100`
**Description**: settle() emits no event when it mutates accounting state.
**Impact**:
- Off-chain indexers miss settlement transitions.
**Recommendation**: Emit a Settled event when the contract transitions so indexers
and monitors can observe the state change reliably.
"""
    recs = {r["id"]: r for r in M._dedup_report_sections(report)}
    # same site (overlapping ranges) confirmed
    assert M._dedup_locations_overlap(recs["H-20"]["locations"], recs["L-60"]["locations"])
    ok, reason = M._dedup_same_fix_ok(recs["H-20"], recs["L-60"])
    assert not ok, f"different bugs in one function must NOT merge: {reason}"
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        scratch, proj = _setup(tmp, report)
        assert M._dedup_report_python(scratch, str(proj)) is True
        delivered = (proj / "AUDIT_REPORT.md").read_text(encoding="utf-8")
        assert "Consolidated from" not in delivered
        assert delivered == report


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-q"]))
