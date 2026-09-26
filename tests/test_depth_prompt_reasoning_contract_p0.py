"""Keep depth methodology evidence-led across all language projections."""

from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LANGUAGES = ("evm", "solana", "aptos", "sui", "soroban", "daml")


def test_depth_templates_do_not_promote_uncertainty_to_confirmation() -> None:
    for language in LANGUAGES:
        body = (ROOT / "prompts" / language / "phase4b-depth-templates.md").read_text(
            encoding="utf-8"
        )
        assert "If you cannot construct a trace showing the defense" not in body
        assert "an unproven defense alone does not prove the attack" in body
        assert "[EXTERNAL-ASSUMPTION: ...]" in body
        assert "NEEDS_DEPENDENCY_RESEARCH" in body
        assert "financial or non-financial harm" in body


def test_four_technique_lists_do_not_claim_there_are_three() -> None:
    for language in ("evm", "aptos", "sui", "soroban"):
        body = (ROOT / "prompts" / language / "phase4b-depth-templates.md").read_text(
            encoding="utf-8"
        )
        outer = body.split("## MANDATORY DEPTH DIRECTIVE", 1)[1].split(
            "## EXPLOITATION TRACE MANDATE", 1
        )[0]
        assert "these 3 techniques" not in outer
        assert all(f"{index}. **" in outer for index in range(1, 5))


def test_phase_wrapper_has_no_obsolete_backend_or_mcp_fallback() -> None:
    body = (ROOT / "scripts" / "plamen_prompt.py").read_text(encoding="utf-8")
    header = body.split('header = f"""You are running the', 1)[1].split(
        'header = _render_runtime_placeholders', 1
    )[0]
    assert "HARD SCOPE DIRECTIVE (OVERRIDES V1 PROMPT STEP 0)" not in header
    assert "phase-scoped claude -p subprocess" not in header
    assert "switch to fallback (code analysis, grep, WebSearch)" not in header
    assert "The driver has already resolved the configuration" in header
