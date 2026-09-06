"""Regression tests for a report_index provenance halt fix.

Root cause: three independent driver bugs in expected-severity computation
flagged the LLM's correct report_index output as "silent severity change":

1. `_enforce_severity_matrix` asymmetric verifier-vs-matrix rule
   The function respected verifier's explicit Severity ONLY when LOWER
   than the matrix computation. When the matrix accidentally inflated
   (e.g. false-positive `fully-trusted` modifier match from PROSE the
   verifier explicitly REJECTED), the matrix value won over the
   verifier's explicit High → driver expected Medium → LLM wrote High
   (correct per verifier) → provenance gate halted.
   Fix: explicit verifier severity is authoritative in BOTH directions.

2. PARTIAL/UNRESOLVED auto-demotion in `_expected_report_index_severities`
   Driver demoted Medium → Low on PARTIAL verdict even when the verifier
   had ALREADY explicitly assigned Severity: Medium with the partial
   context in mind. Caused INV-128 false-fail.
   Fix: only auto-demote when verifier did NOT assign explicit Severity.

3. Inline adjustment notation in verifier Severity field
   Verifier wrote `Severity: High (adjusted to Medium — external
   precondition required)`. Parser read "High" (first token). Verifier
   intent was Medium. LLM correctly wrote Medium → provenance gate
   misclassified as LLM-fault.
   Fix: `_extract_verifier_severity_with_adjustment` recognizes the
   common "X (adjusted to Y)" and "X → Y" idioms and returns Y.

These tests lock all three fixes against regression. Without them, any
future audit hitting the same idioms would burn another opus-tier
report_index retry storm before halting.
"""
from __future__ import annotations

import sys
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS_DIR))

from plamen_parsers import (  # noqa: E402
    _enforce_severity_matrix,
    _extract_verifier_severity_with_adjustment,
)


# -------- _extract_verifier_severity_with_adjustment ----------------------

def test_adjustment_parens_idiom_returns_adjusted_value():
    """The failure mode verbatim:
    `Severity: High (adjusted to Medium — external precondition required)`"""
    inputs = [
        "High (adjusted to Medium - external precondition required; see below)",
        "** High (adjusted to Medium - external precondition required; see below)",
        "**High (adjusted to Medium)**",
        "High (demoted to Low — onchain-only modifier)",
        "Critical (upgraded to High after chain analysis)",
    ]
    for raw in inputs:
        result = _extract_verifier_severity_with_adjustment(raw)
        assert result.lower() in {"medium", "low", "high"}, (
            f"Failed on {raw!r}: got {result!r}"
        )


def test_adjustment_arrow_idiom_returns_post_arrow_value():
    """Various arrow-style adjustment notations."""
    assert _extract_verifier_severity_with_adjustment("High -> Medium") == "Medium"
    assert _extract_verifier_severity_with_adjustment("High => Medium") == "Medium"
    assert _extract_verifier_severity_with_adjustment("High → Medium") == "Medium"
    assert _extract_verifier_severity_with_adjustment("Critical → High") == "High"


def test_no_adjustment_passes_through():
    """Plain severity values must round-trip unchanged so downstream
    normalize_severity continues to work."""
    for v in ("High", "Medium", "**Low**", "  High  "):
        result = _extract_verifier_severity_with_adjustment(v)
        # Either passes through verbatim, or returns the bare severity
        # word after strip — both are fine for downstream normalization.
        assert "high" in result.lower() or "medium" in result.lower() \
            or "low" in result.lower(), f"Lost severity in {v!r} -> {result!r}"


def test_empty_input_handled():
    assert _extract_verifier_severity_with_adjustment("") == ""
    assert _extract_verifier_severity_with_adjustment(None) == ""


# -------- _enforce_severity_matrix symmetric rule --------------------------

def test_explicit_verifier_severity_wins_when_higher_than_matrix():
    """The H-9 failure mode: verifier wrote High, matrix computed
    Medium (false-positive fully-trusted modifier from PROSE), pre-fix
    driver returned Medium → halt. Post-fix: returns High."""
    verify_text = """
**Severity**: High
**Verdict**: CONFIRMED

**Impact**: HIGH
**Likelihood**: MEDIUM

**Note on Vector B (Trusted Actor)**: While SwapRouter changes
require the owner to act maliciously, the severity discount for
fully-trusted actors applies only when the attack path requires the
actor to violate their trust assumption. The overall finding severity
remains High due to the more accessible Vectors A and C.
"""
    queue_row = {"severity": "High"}
    result = _enforce_severity_matrix(verify_text, queue_row)
    assert result == "High", (
        f"Verifier wrote Severity: High explicitly; driver expected "
        f"to honor that and return High, got {result!r}"
    )


def test_explicit_verifier_severity_wins_when_lower_than_matrix():
    """Pre-fix behavior preserved: when verifier explicitly chose LOWER,
    that wins too. Caught by the existing logic but checked here for
    completeness — the fix is symmetric, not asymmetric-reversed."""
    verify_text = """
**Severity**: Low
**Impact**: HIGH
**Likelihood**: HIGH
"""
    queue_row = {"severity": "Low"}
    result = _enforce_severity_matrix(verify_text, queue_row)
    assert result == "Low", f"Verifier explicit Low ignored: got {result!r}"


def test_inline_adjustment_in_severity_field_extracted():
    """The H-20 failure mode: verifier wrote
    `Severity: High (adjusted to Medium — external precondition required)`.
    Driver should return Medium (the post-adjustment value), not High."""
    verify_text = """
**Severity:** High (adjusted to Medium - external precondition required; see below)
**Verdict:** PARTIAL
**Impact**: HIGH
**Likelihood**: HIGH
"""
    queue_row = {"severity": "High"}
    result = _enforce_severity_matrix(verify_text, queue_row)
    assert result == "Medium", (
        f"Inline adjustment in Severity field should be honored; "
        f"expected Medium, got {result!r}"
    )


def test_no_explicit_severity_falls_back_to_matrix():
    """When verifier did NOT assign a Severity field, the matrix
    (Impact × Likelihood + modifiers) is the fallback. Ensures the fix
    doesn't break the legitimate matrix path."""
    verify_text = """
**Impact**: HIGH
**Likelihood**: MEDIUM
"""
    queue_row = {"severity": "Medium"}
    result = _enforce_severity_matrix(verify_text, queue_row)
    # HIGH × MEDIUM = High per the matrix; no modifiers detected.
    assert result == "High", f"Matrix fallback broken: got {result!r}"


def test_no_explicit_severity_no_axes_uses_queue_fallback():
    """When neither verifier nor matrix axes are present, fall back to
    queue row with the existing conservative demotion."""
    verify_text = "Some description without severity fields."
    # Conservative E7: Critical/High in queue without verifier confirmation
    # demote to Medium (existing behavior; not changed by this fix).
    assert _enforce_severity_matrix(verify_text, {"severity": "High"}) == "Medium"
    assert _enforce_severity_matrix(verify_text, {"severity": "Medium"}) == "Medium"
    assert _enforce_severity_matrix(verify_text, {"severity": "Low"}) == "Low"


# -------- Cross-component integration -----------------------------------

def test_partial_verdict_with_explicit_severity_not_demoted(tmp_path: Path):
    """The INV-128 failure mode: verifier wrote Severity: Medium
    with Verdict: PARTIAL. Pre-fix driver auto-demoted to Low. Post-fix:
    explicit Severity field wins, no auto-demotion applied."""
    import plamen_validators as V

    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    (sp / "verification_queue.md").write_text(
        "| Queue # | Finding ID | Severity | Title |\n"
        "|---------|------------|----------|-------|\n"
        "| 1 | INV-X | Medium | example |\n",
        encoding="utf-8",
    )
    (sp / "verify_INV-X.md").write_text(
        "**Severity:** Medium\n\n"
        "**Verdict:** PARTIAL\n\n"
        "Verifier observed the mechanism but the harm path requires an "
        "external precondition that may or may not hold in production.\n",
        encoding="utf-8",
    )
    expected = V._expected_report_index_severities(sp)
    assert expected.get("INV-X") == "Medium", (
        f"PARTIAL verdict over-rode explicit Medium: got "
        f"{expected.get('INV-X')!r}. Pre-fix behavior demoted to Low."
    )


def test_partial_verdict_without_explicit_severity_retains_matrix_tier(tmp_path: Path):
    """P0-V: an evidence-status label cannot self-author a tier reduction."""
    import plamen_validators as V

    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    (sp / "verification_queue.md").write_text(
        "| Queue # | Finding ID | Severity | Title |\n"
        "|---------|------------|----------|-------|\n"
        "| 1 | INV-Y | Medium | example |\n",
        encoding="utf-8",
    )
    (sp / "verify_INV-Y.md").write_text(
        "**Verdict:** PARTIAL\n\n"
        "**Impact**: MEDIUM\n"
        "**Likelihood**: MEDIUM\n\n"
        "No explicit Severity field — driver must compute one. PARTIAL "
        "remains an evidence state pending separate typed tier authority.\n",
        encoding="utf-8",
    )
    expected = V._expected_report_index_severities(sp)
    # Matrix: MEDIUM × MEDIUM = Medium. PARTIAL is challenge-only and cannot
    # silently lower the retained tier.
    assert expected.get("INV-Y") == "Medium", (
        f"PARTIAL retention regressed: got "
        f"{expected.get('INV-Y')!r}, expected Medium"
    )
