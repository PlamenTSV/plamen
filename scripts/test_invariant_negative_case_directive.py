"""Contract tests for the invariant negative-case reachability directive.

Background: a prior cross-chain DEX Thorough audit surfaced
two invariant-construction defects that no validator caught:
  1. `fuzz_refundClaimProtection` (Medusa) — the harness contract
     itself was a registered bot, so the authorization tautology meant
     the property mechanically could not return false. INV-003
     (Critical: anyone can steal non-EVM refunds) got a PASSED* sticker.
  2. `INV-9` (Foundry) — asserted "20-byte walletAddress claimPayout
     sends to stored wallet" while INV-8 simultaneously asserted "52-byte
     revertMessage triggers immediate transfer, never stored" — mutually
     exclusive properties. INV-9 "VIOLATED" because of its own setup,
     not the protocol.

Both share a root cause: the invariant-writing agent didn't prove that
its harness setup is capable of producing a failing test. The fix adds
a soft prompt directive (`STEP 1.5: Negative-Case Reachability`) to
both EVM invariant prompts requiring, for each invariant, a one-line
note describing the call sequence that WOULD falsify it.

This is intentionally PROMPT-ONLY — no post-phase validator gates the
output, because:
  - A hard validator that fails the depth phase on "missing negative
    case comment" would trigger a depth retry (we just fixed one of
    those in v2 commit 0299243). New retry paths are the exact thing
    the user asked not to introduce.
  - The directive's value is in the agent's THINKING during invariant
    construction; the comment is a forcing function, not the goal.

These tests lock in the prompt contract so the directive doesn't get
accidentally deleted in a future edit.
"""
from __future__ import annotations

import sys
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS_DIR))

from plamen_types import plamen_home  # noqa: E402

ROOT = plamen_home()

INVARIANT_PROMPTS = [
    ROOT / "prompts" / "evm" / "v2" / "phase4b-invariant-fuzz.md",
    ROOT / "prompts" / "evm" / "v2" / "phase4b-medusa-fuzz.md",
]


def _read(p: Path) -> str:
    return p.read_text(encoding="utf-8", errors="replace")


def test_invariant_prompts_exist():
    for p in INVARIANT_PROMPTS:
        assert p.exists(), f"Invariant prompt missing: {p}"


def test_invariant_prompts_have_negative_case_directive():
    """Both prompts must contain the STEP 1.5 directive heading and
    explain the two recurring failure modes (authorization tautology and
    branch tautology). Drift gets caught here, not in production."""
    required_phrases = [
        # The step heading
        "Negative-Case Reachability",
        # The core forcing question
        "would cause",
        # Both named failure modes
        "Authorization tautology",
        "Branch tautology",
        # The output requirement
        "UNREACHABLE",
    ]
    for p in INVARIANT_PROMPTS:
        text = _read(p)
        for phrase in required_phrases:
            assert phrase in text, (
                f"{p.name}: missing required phrase '{phrase}' in the "
                "negative-case reachability directive"
            )


def test_invariant_prompts_explicitly_call_out_evidence_tag_demotion():
    """If an invariant's negative case is UNREACHABLE, a PASS verdict
    is zero coverage. The directive must instruct the agent to demote
    the evidence tag (don't emit [POC-PASS] / [MEDUSA-PASS] for
    structurally-unfailable invariants). Without this, the formerly-
    broken `fuzz_refundClaimProtection` PASS would still
    propagate to the report as a Critical-finding confirmation."""
    foundry_prompt = _read(INVARIANT_PROMPTS[0])
    medusa_prompt = _read(INVARIANT_PROMPTS[1])
    assert "[CODE-TRACE]" in foundry_prompt, (
        "phase4b-invariant-fuzz.md: must instruct agent to emit "
        "[CODE-TRACE] instead of [POC-PASS] for unreachable-negative invariants"
    )
    assert "PASSED*" in medusa_prompt or "[CODE-TRACE]" in medusa_prompt, (
        "phase4b-medusa-fuzz.md: must instruct agent to flag MEDUSA "
        "passes whose negative case is unreachable"
    )


def test_invariant_prompts_dont_introduce_hard_gate():
    """Sanity: the directive must NOT instruct the agent to abort or
    emit a failure marker that the driver could pick up as a gate fail.
    This is a prompt-only soft check by design."""
    forbidden_phrases = [
        "REFUSE TO PROCEED",
        "ABORT THE PHASE",
        "EMIT HALT_REQUESTED",
        "[HALT]",
    ]
    for p in INVARIANT_PROMPTS:
        text = _read(p)
        for phrase in forbidden_phrases:
            assert phrase not in text, (
                f"{p.name}: contains '{phrase}' which would convert the "
                "soft directive into a hard gate — new retry path risk"
            )


def test_invariant_prompts_did_not_explode_in_size():
    """The directive adds ~25 lines per prompt. Sanity-check that we
    didn't accidentally bloat the prompt past a reasonable size, which
    could affect agent quality on its primary task."""
    # Soft caps based on current file sizes + reasonable headroom.
    # Foundry invariant prompt was ~200 lines pre-fix; new cap 300.
    # Medusa prompt was ~100 lines pre-fix; new cap 200.
    max_lines = {
        "phase4b-invariant-fuzz.md": 350,
        # The bounded generated-harness compile/recovery contract adds one
        # small preflight section; retain modest headroom without permitting
        # the methodology to grow without bound.
        "phase4b-medusa-fuzz.md": 330,
    }
    for p in INVARIANT_PROMPTS:
        lines = len(_read(p).splitlines())
        cap = max_lines.get(p.name, 400)
        assert lines <= cap, (
            f"{p.name}: {lines} lines exceeds budget of {cap} — the "
            "directive may have grown beyond a single forcing function"
        )
