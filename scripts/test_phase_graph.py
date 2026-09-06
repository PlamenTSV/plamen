"""Phase graph + mode×pipeline coverage tests.

Goal: prove every (mode, pipeline) combination has a valid, executable phase
list, and prove the validator catches structural defects before any phase
runs. Closes the "user must fix mode/ordering bugs every audit" failure mode.

Run: `python test_phase_graph.py`
"""

from __future__ import annotations

import sys
import tempfile
from dataclasses import replace
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
# Live phase-list validation: every (mode, pipeline) combination must pass.
# =============================================================================

def test_LIVE_sc_light_valid():
    issues = D.validate_phase_graph(D.SC_PHASES, "light", "sc")
    check("LIVE.sc-light: phase graph valid", not issues, repr(issues[:3]))


def test_LIVE_sc_core_valid():
    issues = D.validate_phase_graph(D.SC_PHASES, "core", "sc")
    check("LIVE.sc-core: phase graph valid", not issues, repr(issues[:3]))


def test_LIVE_sc_thorough_valid():
    issues = D.validate_phase_graph(D.SC_PHASES, "thorough", "sc")
    check("LIVE.sc-thorough: phase graph valid", not issues, repr(issues[:3]))


def test_LIVE_l1_light_valid():
    issues = D.validate_phase_graph(D.L1_PHASES, "light", "l1")
    check("LIVE.l1-light: phase graph valid", not issues, repr(issues[:3]))


def test_LIVE_l1_core_valid():
    issues = D.validate_phase_graph(D.L1_PHASES, "core", "l1")
    check("LIVE.l1-core: phase graph valid", not issues, repr(issues[:3]))


def test_LIVE_l1_thorough_valid():
    issues = D.validate_phase_graph(D.L1_PHASES, "thorough", "l1")
    check("LIVE.l1-thorough: phase graph valid", not issues, repr(issues[:3]))


# =============================================================================
# Adversarial fixtures: validator MUST flag broken phase lists.
# =============================================================================

def test_ADV_duplicate_phase_name_flagged():
    p1 = D.Phase("recon", ["A"], ["x.md"], base_timeout_s=600)
    p2 = D.Phase("recon", ["B"], ["y.md"], base_timeout_s=600)  # duplicate
    issues = D.validate_phase_graph([p1, p2], "thorough", "sc")
    check(
        "ADV.duplicate-phase-name flagged",
        any("duplicate" in s for s in issues),
        repr(issues),
    )


def test_ADV_invalid_phase_name_flagged():
    p = D.Phase("Recon-with-dashes", ["A"], ["x.md"], base_timeout_s=600)
    issues = D.validate_phase_graph([p], "thorough", "sc")
    check(
        "ADV.invalid-phase-name (dashes/uppercase) flagged",
        any("[a-z][a-z0-9_]*" in s for s in issues),
        repr(issues),
    )


def test_ADV_negative_timeout_flagged():
    p = D.Phase("recon", ["A"], ["x.md"], base_timeout_s=-1)
    issues = D.validate_phase_graph([p], "thorough", "sc")
    check(
        "ADV.negative-timeout flagged",
        any("invalid timeout" in s for s in issues),
        repr(issues),
    )


def test_ADV_excessive_timeout_flagged():
    p = D.Phase("recon", ["A"], ["x.md"], base_timeout_s=99999)
    issues = D.validate_phase_graph([p], "thorough", "sc")
    check(
        "ADV.excessive-timeout (>4h) flagged",
        any("exceeds 4-hour ceiling" in s for s in issues),
        repr(issues),
    )


def test_ADV_empty_artifacts_and_any_of_flagged():
    """Non-verify-shard phase with no expected_artifacts AND no any_of -> flagged."""
    p = D.Phase("custom_phase", ["A"], [], base_timeout_s=600)
    issues = D.validate_phase_graph([p], "thorough", "sc")
    check(
        "ADV.empty-artifacts non-shard flagged",
        any("silent-pass risk" in s for s in issues),
        repr(issues),
    )


def test_ADV_verify_shard_empty_artifacts_exempt():
    """Verify shards have empty expected_artifacts by design (manifest-driven).
    Validator must NOT flag them.
    """
    p = D.Phase("verify_high_a", ["Step 5"], [], base_timeout_s=2100)
    p_full = D.Phase("recon", ["A"], ["x.md"], base_timeout_s=600)
    issues = D.validate_phase_graph([p_full, p], "thorough", "sc")
    check(
        "ADV.verify-shard-empty-artifacts exempt from silent-pass rule",
        not any("verify_high_a" in s and "silent-pass" in s for s in issues),
        repr(issues),
    )


def test_ADV_empty_phase_list_flagged():
    issues = D.validate_phase_graph([], "thorough", "sc")
    check(
        "ADV.empty-phase-list flagged",
        any("empty" in s for s in issues),
        repr(issues),
    )


def test_ADV_invalid_pipeline_name_flagged():
    p = D.Phase("recon", ["A"], ["x.md"], base_timeout_s=600)
    issues = D.validate_phase_graph([p], "thorough", "evm-typo")
    check(
        "ADV.invalid-pipeline-name flagged",
        any("pipeline" in s for s in issues),
        repr(issues),
    )


def test_ADV_invalid_mode_name_flagged():
    p = D.Phase("recon", ["A"], ["x.md"], base_timeout_s=600)
    issues = D.validate_phase_graph([p], "ultra", "sc")
    check(
        "ADV.invalid-mode-name flagged",
        any("mode" in s for s in issues),
        repr(issues),
    )


def test_ADV_no_phase_in_mode_flagged():
    """No phase has the active mode in its `modes` set -> halt."""
    p = D.Phase("recon", ["A"], ["x.md"], base_timeout_s=600,
                modes={"thorough"})  # only Thorough — Light has nothing to run
    issues = D.validate_phase_graph([p], "light", "sc")
    check(
        "ADV.no-phase-in-mode flagged",
        any("no phase" in s and "light" in s for s in issues),
        repr(issues),
    )


def test_ADV_empty_modes_set_flagged():
    p = D.Phase("recon", ["A"], ["x.md"], base_timeout_s=600, modes=set())
    issues = D.validate_phase_graph([p], "thorough", "sc")
    check(
        "ADV.empty-modes-set flagged",
        any("empty modes set" in s for s in issues),
        repr(issues),
    )


def test_ADV_no_section_markers_flagged():
    p = D.Phase("recon", [], ["x.md"], base_timeout_s=600)
    issues = D.validate_phase_graph([p], "thorough", "sc")
    check(
        "ADV.no-section-markers flagged",
        any("no section_markers" in s for s in issues),
        repr(issues),
    )


def test_ADV_malformed_any_of_flagged():
    p = D.Phase("recon", ["A"], [], base_timeout_s=600,
                any_of=[[]])  # empty OR-group
    issues = D.validate_phase_graph([p], "thorough", "sc")
    check(
        "ADV.empty-any-of-group flagged",
        any("any_of" in s and "non-empty" in s for s in issues),
        repr(issues),
    )


def test_ADV_whitespace_only_artifact_flagged():
    p = D.Phase("recon", ["A"], ["   "], base_timeout_s=600)
    issues = D.validate_phase_graph([p], "thorough", "sc")
    check(
        "ADV.whitespace-only-artifact flagged",
        any("invalid" in s for s in issues),
        repr(issues),
    )


# =============================================================================
# Phase-name regex coverage (used elsewhere in driver)
# =============================================================================

def test_PNR_every_live_phase_name_matches():
    """Every actual phase name in SC_PHASES + L1_PHASES matches the regex."""
    bad = []
    for phases, lbl in [(D.SC_PHASES, "sc"), (D.L1_PHASES, "l1")]:
        for p in phases:
            if not D._PHASE_NAME_RE.match(p.name):
                bad.append(f"{lbl}/{p.name}")
    check(
        "PNR.every-live-phase-name matches [a-z][a-z0-9_]*",
        not bad,
        f"bad={bad}",
    )


# =============================================================================
# Coverage matrix smoke: every mode has SOME phase in every pipeline.
# =============================================================================

def test_MX_sc_every_mode_has_phases():
    for mode in ("light", "core", "thorough"):
        active = [p for p in D.SC_PHASES if mode in p.modes]
        if not active:
            check(f"MX.sc-{mode} has phases", False, "0 phases active")
            return
    check("MX.sc-every-mode has at least one active phase", True, "")


def test_MX_l1_every_mode_has_phases():
    for mode in ("light", "core", "thorough"):
        active = [p for p in D.L1_PHASES if mode in p.modes]
        if not active:
            check(f"MX.l1-{mode} has phases", False, "0 phases active")
            return
    check("MX.l1-every-mode has at least one active phase", True, "")


def test_MX_l1_has_no_chain_phases():
    names = {p.name for p in D.L1_PHASES}
    forbidden = {"chain", "chain_agent2"} & names
    check(
        "MX.l1-no-chain-phases",
        not forbidden,
        f"forbidden={sorted(forbidden)}",
    )


def test_MX_l1_medium_report_uses_shard_sentinel_only():
    names = {p.name for p in D.L1_PHASES}
    forbidden = {
        "report_body_writer_medium_a",
        "report_body_writer_medium_b",
        "report_medium_a",
        "report_medium_b",
    } & names
    required = {"report_body_writer_medium", "report_medium"} <= names
    check(
        "MX.l1-medium-report-sentinel-only",
        required and not forbidden,
        f"required={required} forbidden={sorted(forbidden)}",
    )


def test_MX_expand_medium_report_shards_has_no_duplicates():
    with tempfile.TemporaryDirectory() as td:
        sp = Path(td)
        manifest_dir = sp / "body_manifests"
        manifest_dir.mkdir()
        (manifest_dir / "report_medium_a.json").write_text("{}", encoding="utf-8")
        (manifest_dir / "report_medium_b.json").write_text("{}", encoding="utf-8")
        expanded = D.expand_shard_phases(D.L1_PHASES, sp)
    names = [p.name for p in expanded]
    dupes = sorted({name for name in names if names.count(name) > 1})
    ok = (
        not dupes
        and "report_body_writer_medium_a" in names
        and "report_body_writer_medium_b" in names
        and "report_medium_a" in names
        and "report_medium_b" in names
    )
    check(
        "MX.expand-medium-report-shards-no-duplicates",
        ok,
        f"dupes={dupes} names={names}",
    )


def test_MX_report_shard_expansion_ignores_support_manifests():
    with tempfile.TemporaryDirectory() as td:
        sp = Path(td)
        manifest_dir = sp / "body_manifests"
        manifest_dir.mkdir()
        (manifest_dir / "report_medium_a.json").write_text("{}", encoding="utf-8")
        (manifest_dir / "report_medium_assignments.json").write_text("{}", encoding="utf-8")
        (manifest_dir / "report_low_info_receipt.json").write_text("{}", encoding="utf-8")
        expanded = D.expand_shard_phases(D.L1_PHASES, sp)
        owned = D._owned_artifact_patterns("l1", sp)
    names = {p.name for p in expanded}
    forbidden = {
        "report_body_writer_medium_assignments",
        "report_medium_assignments",
        "report_body_writer_low_info_receipt",
        "report_low_info_receipt",
    }
    owned_text = repr(owned)
    ok = (
        "report_body_writer_medium_a" in names
        and "report_medium_a" in names
        and not (forbidden & names)
        and "report_medium_assignments.md" not in owned_text
        and "report_low_info_receipt.md" not in owned_text
    )
    check(
        "MX.report-shard-expansion-ignores-support-manifests",
        ok,
        f"names={sorted(forbidden & names)} owned={owned_text}",
    )
    assert ok


def test_MX_thorough_strict_superset_of_core():
    """Thorough should run every Core phase + extras."""
    for phases, lbl in [(D.SC_PHASES, "sc"), (D.L1_PHASES, "l1")]:
        core = {p.name for p in phases if "core" in p.modes}
        thorough = {p.name for p in phases if "thorough" in p.modes}
        if not core.issubset(thorough):
            missing = core - thorough
            check(
                f"MX.{lbl}-thorough-superset",
                False,
                f"core phases not in thorough: {missing}",
            )
            return
    check("MX.thorough strict-superset of core (sc + l1)", True, "")


def test_MX_axis_coverage_registered_thorough_soft_ordered():
    """M2 (recall-build-plan §5.3): axis_coverage is registered Thorough-only,
    critical=False, ordered AFTER exploration_skeptic (4b.6) + enumgap_exploration
    (4b.7) and BEFORE sc_semantic_dedup (4e) / chain (4c), with the correct
    expected artifact."""
    names = [p.name for p in D.SC_PHASES]
    by_name = {p.name: p for p in D.SC_PHASES}
    if "axis_coverage" not in by_name:
        check("MX.axis_coverage registered in SC_PHASES", False, f"names={names}")
        return
    ax = by_name["axis_coverage"]
    # Thorough-only
    check(
        "MX.axis_coverage Thorough-only",
        ax.modes == {"thorough"},
        f"modes={ax.modes}",
    )
    # Soft (degrade-and-continue, never halts)
    check(
        "MX.axis_coverage critical=False",
        ax.critical is False,
        f"critical={ax.critical}",
    )
    # Correct expected artifact
    check(
        "MX.axis_coverage expected artifact",
        ax.expected_artifacts == [
            "axis_coverage_findings.md",
            "axis_coverage_dispositions.json",
        ],
        f"expected_artifacts={ax.expected_artifacts}",
    )
    # Ordering: after 4b.6 + 4b.7, before 4e + chain
    idx = names.index("axis_coverage")
    ordered_after = ["exploration_skeptic", "enumgap_exploration"]
    ordered_before = ["sc_semantic_dedup", "chain"]
    after_ok = all(n in names and names.index(n) < idx for n in ordered_after)
    before_ok = all(n in names and names.index(n) > idx for n in ordered_before)
    check(
        "MX.axis_coverage ordered after 4b.6/4b.7, before 4e/chain",
        after_ok and before_ok,
        f"idx={idx} after_ok={after_ok} before_ok={before_ok} names={names}",
    )


def test_MX_critical_phases_have_artifacts_or_any_of():
    """Every phase marked `critical=True` declares artifacts or any_of OR is
    a verify shard (manifest-driven)."""
    # Verify shards are manifest-driven (empty expected_artifacts by design):
    # exempt every name registered in the SC/L1 verify-shard manifests so the
    # check stays correct as the slot pools grow.
    shard_names = set(D.SC_VERIFY_PHASE_NAMES) | set(D.L1_VERIFY_PHASE_NAMES)
    bad = []
    for phases, lbl in [(D.SC_PHASES, "sc"), (D.L1_PHASES, "l1")]:
        for p in phases:
            if not p.critical:
                continue
            if p.name in shard_names:
                continue  # exempt
            if not p.expected_artifacts and not p.any_of:
                bad.append(f"{lbl}/{p.name}")
    check(
        "MX.critical-phases declare artifacts or any_of",
        not bad,
        f"bad={bad}",
    )


# =============================================================================
# Test runner
# =============================================================================

TESTS = [
    test_LIVE_sc_light_valid,
    test_LIVE_sc_core_valid,
    test_LIVE_sc_thorough_valid,
    test_LIVE_l1_light_valid,
    test_LIVE_l1_core_valid,
    test_LIVE_l1_thorough_valid,
    test_ADV_duplicate_phase_name_flagged,
    test_ADV_invalid_phase_name_flagged,
    test_ADV_negative_timeout_flagged,
    test_ADV_excessive_timeout_flagged,
    test_ADV_empty_artifacts_and_any_of_flagged,
    test_ADV_verify_shard_empty_artifacts_exempt,
    test_ADV_empty_phase_list_flagged,
    test_ADV_invalid_pipeline_name_flagged,
    test_ADV_invalid_mode_name_flagged,
    test_ADV_no_phase_in_mode_flagged,
    test_ADV_empty_modes_set_flagged,
    test_ADV_no_section_markers_flagged,
    test_ADV_malformed_any_of_flagged,
    test_ADV_whitespace_only_artifact_flagged,
    test_PNR_every_live_phase_name_matches,
    test_MX_sc_every_mode_has_phases,
    test_MX_l1_every_mode_has_phases,
    test_MX_l1_has_no_chain_phases,
    test_MX_l1_medium_report_uses_shard_sentinel_only,
    test_MX_expand_medium_report_shards_has_no_duplicates,
    test_MX_thorough_strict_superset_of_core,
    test_MX_axis_coverage_registered_thorough_soft_ordered,
    test_MX_critical_phases_have_artifacts_or_any_of,
]


def main() -> int:
    print(f"Running {len(TESTS)} phase-graph tests...")
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
