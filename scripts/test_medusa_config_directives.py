"""Contract tests for the Medusa campaign prompt updates.

Background: the Medusa stateful-fuzz campaign was historically configured
with Medusa's default `stopOnFailedTest: true`, which halts the entire
campaign at the first invariant violation. A prior cross-chain DEX
Thorough audit demonstrated the impact: MEDUSA-1 fired in
<1 second, the remaining ~24 invariants never got the deep-state
exploration they needed, and the configured 15-minute budget was
effectively wasted.

The fix changes two things in both EVM Medusa prompt files
(`prompts/evm/v2/phase4b-medusa-fuzz.md` and `prompts/evm/phase4b-loop.md`):
  1. Add explicit `stopOnFailedTest: false` directive in the medusa.json
     config the agent generates.
  2. Cut the per-campaign timeout from 900s → 600s. The campaign now
     runs the full budget across all invariants (rather than halting
     at the first failure), so the total wall time is unchanged or
     slightly reduced while coverage improves.
  3. Add a STEP 3a dedup directive so the agent collapses multiple
     witnesses of the same root cause into a single MEDUSA-N finding
     instead of emitting one per counterexample.
  4. Compile the exact generated harness before campaign launch and permit
     three bounded, targeted harness-only compiler repairs. A one-shot
     compile policy wasted real campaigns on repairable Solidity type errors.

These tests lock in the prompt contract. Drift in either file
(forgetting `stopOnFailedTest: false`, regressing back to 900s, or
losing the dedup directive) gets caught immediately by CI.
"""
from __future__ import annotations

import sys
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS_DIR))

from plamen_types import plamen_home  # noqa: E402

ROOT = plamen_home()

MEDUSA_PROMPTS = [
    ROOT / "prompts" / "evm" / "v2" / "phase4b-medusa-fuzz.md",
    ROOT / "prompts" / "evm" / "phase4b-loop.md",
]


def _read(p: Path) -> str:
    return p.read_text(encoding="utf-8", errors="replace")


def test_medusa_prompt_files_exist():
    for p in MEDUSA_PROMPTS:
        assert p.exists(), f"Medusa prompt file missing: {p}"


def test_medusa_prompts_set_stop_on_failed_test_false():
    """Both Medusa prompts must instruct the agent to disable
    stopOnFailedTest. Without this the campaign halts at first failure
    and burns the timeout budget with single-test coverage."""
    for p in MEDUSA_PROMPTS:
        text = _read(p)
        assert "stopOnFailedTest" in text, (
            f"{p.name}: stopOnFailedTest directive missing — Medusa will "
            "halt at first failure by default"
        )
        # Accept either form: "stopOnFailedTest: false" or
        # "stopOnFailedTest`: false`" or json-style "false"
        text_lower = text.lower()
        assert "stoponfailedtest" in text_lower
        # Must explicitly set false somewhere near the directive.
        # We accept "stoponfailedtest" followed (within 100 chars) by
        # "false". Generous to allow for formatting variations.
        import re
        flag_to_false = re.search(
            r"stoponfailedtest[^\n]{0,100}false",
            text_lower,
        )
        assert flag_to_false, (
            f"{p.name}: stopOnFailedTest is mentioned but not set to "
            "false — regression risk"
        )


def test_medusa_prompts_use_600s_timeout():
    """Both prompts should use the new 600s timeout, not the old 900s."""
    for p in MEDUSA_PROMPTS:
        text = _read(p)
        assert "--timeout 600" in text, (
            f"{p.name}: medusa fuzz command should use --timeout 600 "
            "(reduced from 900 to balance the stopOnFailedTest=false change)"
        )
        # Must NOT contain the old 900 value in a medusa-fuzz context.
        # (Avoid false-positives on unrelated 900s elsewhere in the file.)
        assert "--timeout 900" not in text, (
            f"{p.name}: stale --timeout 900 still present — regression"
        )


def test_medusa_prompts_have_dedup_directive():
    """The dedup step prevents the report from blowing up with N
    counterexample witnesses for one root cause."""
    for p in MEDUSA_PROMPTS:
        text = _read(p)
        text_lower = text.lower()
        # Look for either the explicit "STEP 3a" header or the dedup
        # keyword + grouping language. We accept any of: "dedup",
        # "deduplicat", "group by", combined with "counterexample" or
        # "violation" to be safe.
        has_dedup_word = any(
            t in text_lower for t in ("dedup", "deduplicat", "group by")
        )
        has_violation_word = any(
            t in text_lower for t in ("counterexample", "violation", "witness")
        )
        assert has_dedup_word and has_violation_word, (
            f"{p.name}: dedup directive missing or weakly phrased — "
            "with stopOnFailedTest: false the agent will produce one "
            "MEDUSA-N per counterexample rather than per root cause, "
            "inflating the report"
        )


def test_medusa_prompts_preflight_exact_generated_harness_with_bounded_repairs():
    """A repairable generated-harness compiler error must not erase a campaign.

    The production root can compile while the newly generated test does not,
    so both prompt surfaces require the same build-info path used by Medusa's
    crytic-compile adapter and a small, explicit retry budget.
    """

    for p in MEDUSA_PROMPTS:
        text = _read(p)
        low = text.lower()
        assert "forge build --build-info .medusa-tests" in text, (
            f"{p.name}: exact generated-harness compile preflight missing"
        )
        assert "3 total generated-harness compile attempts" in low, (
            f"{p.name}: generated-harness repair budget is not explicit"
        )
        assert "do not delete" in low and "weaken" in low, (
            f"{p.name}: compile recovery could silently weaken an oracle"
        )
        assert "payable(address(instance))" in text, (
            f"{p.name}: Solidity payable target conversion guidance missing"
        )
        assert "do not retry past the first compilation failure" not in low, (
            f"{p.name}: stale one-shot compilation policy remains"
        )
