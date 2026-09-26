"""Regression for forge-std/target declaration collisions in fuzz harnesses."""
from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PROMPT = ROOT / "prompts" / "evm" / "v2" / "phase4b-invariant-fuzz.md"


def test_invariant_fuzz_prompt_requires_target_type_aliases() -> None:
    text = PROMPT.read_text(encoding="utf-8")

    assert "Solidity declaration namespace safety (MANDATORY)" in text
    assert "Account as TargetAccount" in text
    assert "StdCheatsSafe.Account" in text
    assert "do not rely on import order" in text
    assert "must not remove an" in text
    assert "invariant, handler, assertion, negative case, or target call" in text


def test_invariant_fuzz_prompt_forbids_duplicate_forge_std_inheritance() -> None:
    text = PROMPT.read_text(encoding="utf-8")

    assert "`Test` base already inherits `StdInvariant`" in text
    assert "exactly `contract InvariantFuzz is Test`" in text
    assert "Do **not** import `StdInvariant` directly" in text
    assert "do **not** declare\n`is Test, StdInvariant`" in text
    example = text.split("### Solidity declaration namespace safety", 1)[0]
    assert "contract InvariantFuzz is Test {" in example
    assert "contract InvariantFuzz is Test, StdInvariant" not in example
