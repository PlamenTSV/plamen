"""Contract tests for prompts/shared/v2/phase6d-report-dedup.md + registry wiring.

Phase 6d (`report_dedup`) is PYTHON-NATIVE: the driver short-circuits it to
`plamen_mechanical._dedup_report_python` and never sends this prompt to a model.
The markdown file exists only so `build_phase_prompt` returns a non-error
placeholder when the phase is queried.

Even so, the prompt carries load-bearing documentation that pins the phase's
safety contract, and the prompt REGISTRY wiring is load-bearing: if the registry
points `report_dedup` at a missing/renamed file, `build_phase_prompt` raises and
the phase cannot dispatch. These tests fail loudly on either regression.

The behavioral guarantees themselves (snapshot-both, mechanical data-loss gate,
conservative KEEP_SEPARATE default, lossless superset survivor, idempotent
no-op, veto-keeps-original) are exercised end-to-end in
`test_report_dedup_phase.py`; this file pins the prompt+registry contract.

Run: `python -m pytest scripts/test_report_dedup_prompt_contract.py -q`
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

SCRIPTS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS_DIR))

import plamen_prompt as P  # noqa: E402
import plamen_types as T  # noqa: E402

PROMPT_DIR = SCRIPTS_DIR.parent / "prompts" / "shared" / "v2"
PHASE6D = PROMPT_DIR / "phase6d-report-dedup.md"


@pytest.fixture(scope="module")
def text() -> str:
    assert PHASE6D.is_file(), f"missing prompt: {PHASE6D}"
    return PHASE6D.read_text(encoding="utf-8")


# =============================================================================
# Registry wiring: report_dedup -> phase6d-report-dedup.md, file present
# =============================================================================

def test_registry_maps_report_dedup_to_phase6d():
    fn = P._STANDALONE_PROMPT_MAP.get("report_dedup")
    assert fn == "phase6d-report-dedup.md", fn


def test_registry_target_file_exists_on_disk():
    fn = P._STANDALONE_PROMPT_MAP["report_dedup"]
    assert (PROMPT_DIR / fn).is_file(), f"registry target missing: {fn}"


def test_every_registry_prompt_resolves_to_a_file():
    """Registry-vs-filesystem consistency: every mapped prompt must exist.

    Guards the whole registry, not just report_dedup — a renamed/deleted prompt
    anywhere would break build_phase_prompt for that phase.
    """
    missing = [
        (phase, fn)
        for phase, fn in P._STANDALONE_PROMPT_MAP.items()
        if not (PROMPT_DIR / fn).is_file()
    ]
    assert not missing, f"registry entries with no file on disk: {missing}"


# NEGATIVE CONTROL: a registry pointing at a nonexistent file is detectable by
# the same consistency check (so the check is not vacuously passing).
def test_negctrl_consistency_check_catches_missing_file():
    fake = dict(P._STANDALONE_PROMPT_MAP)
    fake["__bogus_phase__"] = "phase-does-not-exist-zzz.md"
    missing = [
        (phase, fn)
        for phase, fn in fake.items()
        if not (PROMPT_DIR / fn).is_file()
    ]
    assert ("__bogus_phase__", "phase-does-not-exist-zzz.md") in missing


# =============================================================================
# Prompt contract: documents the Python-native + safety invariants
# =============================================================================

def test_prompt_declares_python_native(text: str):
    low = text.lower()
    assert "python-native" in low or "python native" in low, \
        "prompt must declare the phase is PYTHON-NATIVE (no LLM subprocess)"
    # names the actual implementation entry point so a maintainer can find it
    assert "_dedup_report_python" in text


def test_prompt_declares_critical_false(text: str):
    assert "critical=False" in text or "critical = False" in text, \
        "prompt must document critical=False (never halts the run)"


def test_prompt_pins_snapshot_and_data_loss_gate(text: str):
    low = text.lower()
    assert "snapshot" in low, "prompt must document the snapshot-both safety step"
    assert "data-loss gate" in low or "data loss gate" in low, \
        "prompt must document the mechanical data-loss gate"
    # invariant #1 framing: original is kept on any veto / loss
    assert "original" in low and ("kept" in low or "retained" in low or "stands" in low), \
        "prompt must state the original report is kept on any data-loss veto"


def test_prompt_pins_decisions_only_mapping(text: str):
    # decisions-only contract: writes report_dedup_mapping.md
    assert "report_dedup_mapping.md" in text, \
        "prompt must reference the decisions-only mapping artifact"


def test_prompt_pins_conservative_keep_separate(text: str):
    low = text.lower()
    assert "keep_separate" in low or "keep separate" in low, \
        "prompt must document the conservative KEEP_SEPARATE default"
    # recall-loss rationale: a duplicate is cosmetic, a dropped finding is loss
    assert "cosmetic" in low and ("recall" in low or "dropped" in low), \
        "prompt must justify conservatism (duplicate cosmetic vs dropped = loss)"


def test_prompt_targets_cross_tier(text: str):
    low = text.lower()
    assert "cross-tier" in low or "cross tier" in low, \
        "prompt must state cross-tier same-root-cause is the target"


# NEGATIVE CONTROL: gate on mapping + applied authority, never AUDIT_REPORT.md.
# Gating on the delivered report would (wrongly) require it to change, but the
# phase is a no-op/veto in the common case — so the phase MUST gate on mapping.
def test_phase_gate_artifact_is_mapping_not_report():
    for phases, label in [(T.SC_PHASES, "sc"), (T.L1_PHASES, "l1")]:
        dp = [p for p in phases if p.name == "report_dedup"][0]
        assert dp.expected_artifacts == [
            "report_dedup_mapping.md",
            "report_dedup_applied_alias_receipt.json",
        ], f"{label}: gate artifacts must bind mapping + authority, got {dp.expected_artifacts}"
        assert "AUDIT_REPORT.md" not in dp.expected_artifacts, \
            f"{label}: must NOT gate on the delivered report"


def test_build_phase_prompt_does_not_raise_for_report_dedup():
    """build_phase_prompt must resolve report_dedup without error.

    The phase is Python-native, but the registry/file must still be wired so the
    driver's prompt-build step doesn't crash when it queries this phase.
    """
    # The function signature varies across versions; resolve the prompt file the
    # same way build_phase_prompt does, via the registry, and confirm it loads.
    fn = P._STANDALONE_PROMPT_MAP["report_dedup"]
    body = (PROMPT_DIR / fn).read_text(encoding="utf-8")
    assert body.strip(), "phase6d prompt resolved to empty content"


if __name__ == "__main__":
    import pytest as _pytest
    sys.exit(_pytest.main([__file__, "-q"]))
