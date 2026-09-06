"""Phase B: severity-matrix enforcement tests.

Per `~/.claude/rules/report-template.md`, severity is Impact x Likelihood with
three downgrade modifiers (on-chain-only, view-function-only, fully-trusted).

The driver MUST mechanically apply this matrix at report-index time, overriding
any LLM-emitted severity that violates the matrix. Missing matrix data is
permitted (back-compat) but when Impact + Likelihood are present in the verify
file, the computed severity is authoritative.

Run: `python test_phase_b_severity_matrix.py`
"""

from __future__ import annotations

import sys
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
# Matrix cell coverage: 3 impacts x 3 likelihoods = 9 cells, plus Informational.
# =============================================================================

# Per report-template.md:
# | Impact / Likelihood | High        | Medium  | Low    |
# | High                | Critical    | High    | Medium |
# | Medium              | High        | Medium  | Medium |
# | Low                 | Medium      | Low     | Low    |
# | Informational       | Informational | Informational | Informational |

MATRIX_CASES = [
    ("High", "High", "Critical"),
    ("High", "Medium", "High"),
    ("High", "Low", "Medium"),
    ("Medium", "High", "High"),
    ("Medium", "Medium", "Medium"),
    ("Medium", "Low", "Medium"),
    ("Low", "High", "Medium"),
    ("Low", "Medium", "Low"),
    ("Low", "Low", "Low"),
    ("Informational", "High", "Informational"),
    ("Informational", "Medium", "Informational"),
    ("Informational", "Low", "Informational"),
]


def test_MATRIX_all_cells():
    for impact, likelihood, expected in MATRIX_CASES:
        got = D._compute_matrix_severity(impact, likelihood)
        check(
            f"MATRIX.{impact}x{likelihood} -> {expected}",
            got == expected,
            f"got={got}",
        )


# =============================================================================
# Case-insensitive / whitespace tolerance on inputs.
# =============================================================================

def test_MATRIX_case_insensitive():
    cases = [
        ("high", "high", "Critical"),
        ("HIGH", "MEDIUM", "High"),
        ("  Medium  ", " Low ", "Medium"),
    ]
    for impact, likelihood, expected in cases:
        got = D._compute_matrix_severity(impact, likelihood)
        check(
            f"CASE.{impact!r}x{likelihood!r} -> {expected}",
            got == expected,
            f"got={got}",
        )


# =============================================================================
# Unparseable inputs: matrix cannot compute, returns None (caller decides).
# =============================================================================

def test_MATRIX_unparseable_returns_none():
    cases = [
        ("", "High"),
        ("High", ""),
        ("Catastrophic", "High"),       # invalid impact label
        ("High", "Certain"),             # invalid likelihood label
        (None, "High"),
        ("High", None),
    ]
    for impact, likelihood in cases:
        got = D._compute_matrix_severity(impact, likelihood)
        check(
            f"UNPARSE.({impact!r},{likelihood!r}) -> None",
            got is None,
            f"got={got}",
        )


# =============================================================================
# Downgrade modifiers per report-template.md.
# =============================================================================

def test_MOD_onchain_only_demotes_one_tier():
    # On-chain-only: -1 tier (only when impact is on-chain confined)
    got = D._apply_severity_modifiers("Critical", {"onchain_only": True})
    check("MOD.onchain.Critical->High", got == "High", f"got={got}")

    got = D._apply_severity_modifiers("High", {"onchain_only": True})
    check("MOD.onchain.High->Medium", got == "Medium", f"got={got}")


def test_MOD_view_function_caps_at_medium():
    # View-function-only -> cap at Medium
    got = D._apply_severity_modifiers("Critical", {"view_function": True})
    check("MOD.view.Critical->Medium", got == "Medium", f"got={got}")

    got = D._apply_severity_modifiers("High", {"view_function": True})
    check("MOD.view.High->Medium", got == "Medium", f"got={got}")

    # Cap means: don't UPGRADE below-Medium severities.
    got = D._apply_severity_modifiers("Low", {"view_function": True})
    check("MOD.view.Low stays Low", got == "Low", f"got={got}")


def test_MOD_fully_trusted_demotes_with_floor_informational():
    got = D._apply_severity_modifiers("Critical", {"fully_trusted": True})
    check("MOD.trusted.Critical->High", got == "High", f"got={got}")

    got = D._apply_severity_modifiers("Low", {"fully_trusted": True})
    check("MOD.trusted.Low->Informational", got == "Informational", f"got={got}")

    got = D._apply_severity_modifiers("Informational", {"fully_trusted": True})
    check("MOD.trusted.Informational stays (floor)",
          got == "Informational", f"got={got}")


def test_MOD_no_modifiers_passthrough():
    got = D._apply_severity_modifiers("High", {})
    check("MOD.empty.High->High", got == "High", f"got={got}")


def test_MOD_combined_apply_in_order():
    """Per template: matrix lookup first, then modifiers stack:
    onchain_only(-1), view_function(cap@Medium), fully_trusted(-1).
    Critical -> onchain -> High -> view-cap -> Medium -> trusted -> Low.
    """
    got = D._apply_severity_modifiers("Critical", {
        "onchain_only": True,
        "view_function": True,
        "fully_trusted": True,
    })
    check("MOD.combined.Critical->Low", got == "Low", f"got={got}")


# =============================================================================
# Verify-file parsing: Impact / Likelihood / modifier flags.
# =============================================================================

def test_PARSE_impact_likelihood_from_verify_text():
    text = """
**Verdict**: CONFIRMED
**Severity**: Medium
**Impact**: High
**Likelihood**: Medium
**Location**: src/Foo.sol:L42
"""
    got = D._extract_severity_inputs(text)
    check(
        "PARSE.impact_likelihood",
        got.get("impact") == "High" and got.get("likelihood") == "Medium",
        repr(got),
    )


def test_PARSE_modifier_flags():
    text = """
**Verdict**: CONFIRMED
**Severity**: Critical
**Impact**: High
**Likelihood**: High
**Trust**: FULLY_TRUSTED — governance multisig only
**Note**: View-function-only impact, on-chain-only attack (no UI exposure).
"""
    got = D._extract_severity_inputs(text)
    mods = got.get("modifiers", {})
    check(
        "PARSE.fully_trusted_flag",
        mods.get("fully_trusted") is True,
        repr(mods),
    )
    check(
        "PARSE.view_function_flag",
        mods.get("view_function") is True,
        repr(mods),
    )
    check(
        "PARSE.onchain_only_flag",
        mods.get("onchain_only") is True,
        repr(mods),
    )


def test_PARSE_no_modifiers_when_absent():
    text = """
**Verdict**: CONFIRMED
**Severity**: High
**Impact**: High
**Likelihood**: Medium
"""
    got = D._extract_severity_inputs(text)
    mods = got.get("modifiers", {})
    check(
        "PARSE.no_phantom_modifiers",
        not any(mods.values()),
        repr(mods),
    )


# =============================================================================
# End-to-end enforcement: matrix overrides LLM severity.
# =============================================================================

def test_ENFORCE_matrix_overrides_llm_severity():
    """LLM said Critical, but Impact=Medium/Likelihood=Low -> matrix says Medium."""
    verify_text = """
**Verdict**: CONFIRMED
**Severity**: Critical
**Impact**: Medium
**Likelihood**: Low
"""
    queue_row = {"severity": "Critical"}
    got = D._enforce_severity_matrix(verify_text, queue_row)
    check(
        "ENFORCE.matrix_wins_over_llm",
        got == "Medium",
        f"got={got}",
    )


def test_ENFORCE_no_matrix_data_falls_back_to_llm():
    """No Impact/Likelihood, severity below E7 trigger -> preserve LLM severity.

    Phase E7 forces a conservative downgrade for C/H without inputs. Low and
    Informational pass through unchanged.
    """
    verify_text = """
**Verdict**: CONFIRMED
**Severity**: Low
**Location**: src/Foo.sol:L42
"""
    queue_row = {"severity": "Low"}
    got = D._enforce_severity_matrix(verify_text, queue_row)
    check(
        "ENFORCE.no_matrix_keeps_llm_low",
        got == "Low",
        f"got={got}",
    )


def test_ENFORCE_no_matrix_data_critical_preserved_when_verifier_states():
    """Verifier explicitly wrote Severity: Critical -> preserve even without
    Impact/Likelihood. E7 only kicks in for queue-row-inherited severity."""
    verify_text = """
**Verdict**: CONFIRMED
**Severity**: Critical
**Location**: src/Foo.sol:L42
"""
    queue_row = {"severity": "Critical"}
    got = D._enforce_severity_matrix(verify_text, queue_row)
    check(
        "ENFORCE.verifier_explicit_critical_preserved",
        got == "Critical",
        f"got={got}",
    )


def test_ENFORCE_E7_downgrades_queue_only_critical():
    """Phase E7: severity from queue row only (no Severity field in verify text),
    no Impact/Likelihood -> conservative downgrade to Medium."""
    verify_text = """
**Verdict**: CONFIRMED
**Location**: src/Foo.sol:L42
"""
    queue_row = {"severity": "Critical"}
    got = D._enforce_severity_matrix(verify_text, queue_row)
    check(
        "ENFORCE.E7_downgrades_queue_only_critical",
        got == "Medium",
        f"got={got}",
    )


def test_ENFORCE_no_matrix_data_high_preserved_when_verifier_states():
    """Verifier explicitly wrote Severity: High -> preserve. This is the exact
    an observed L1 failure mode: verify file says 'Severity: High' but has no
    Impact/Likelihood fields, so E7 was incorrectly flattening to Medium."""
    verify_text = """
Severity: High
Preferred Tag: [FUZZ-PASS]
Evidence Tag: [CODE-TRACE]
Verdict: CONFIRMED
"""
    queue_row = {"severity": "High"}
    got = D._enforce_severity_matrix(verify_text, queue_row)
    check(
        "ENFORCE.verifier_explicit_high_preserved",
        got == "High",
        f"got={got}",
    )


def test_ENFORCE_matrix_plus_modifiers():
    """A raw fully_trusted claim cannot demote the High matrix result."""
    verify_text = """
**Verdict**: CONFIRMED
**Severity**: Critical
**Impact**: High
**Likelihood**: Medium
**Trust**: FULLY_TRUSTED
"""
    queue_row = {"severity": "Critical"}
    got = D._enforce_severity_matrix(verify_text, queue_row)
    check(
        "ENFORCE.raw_trust_proposal_has_zero_authority",
        got == "High",
        f"got={got}",
    )


def test_ENFORCE_partial_matrix_data_falls_back():
    """Only Impact, no Likelihood -> matrix uncomputable.

    For Low severity, Phase E7 leaves the value alone. (For C/H, Phase E7
    would downgrade to Medium - covered by the dedicated E7 test above.)
    """
    verify_text = """
**Verdict**: CONFIRMED
**Severity**: Low
**Impact**: High
"""
    queue_row = {"severity": "Low"}
    got = D._enforce_severity_matrix(verify_text, queue_row)
    check(
        "ENFORCE.partial_data_low_kept",
        got == "Low",
        f"got={got}",
    )


def test_ENFORCE_verifier_lower_than_matrix_wins():
    """Verifier says High but Impact=High/Likelihood=High -> matrix=Critical.
    Directional override: verifier LOWER than matrix -> verifier wins."""
    verify_text = """
**Verdict**: CONFIRMED
**Severity**: High
**Impact**: High
**Likelihood**: High
"""
    queue_row = {"severity": "High"}
    got = D._enforce_severity_matrix(verify_text, queue_row)
    check(
        "ENFORCE.verifier_lower_than_matrix_wins",
        got == "High",
        f"got={got}",
    )


def test_ENFORCE_verifier_higher_than_matrix_loses():
    """Verifier says Critical but Impact=Medium/Likelihood=Medium -> matrix=Medium.
    Directional override: verifier HIGHER than matrix -> matrix constrains."""
    verify_text = """
**Verdict**: CONFIRMED
**Severity**: Critical
**Impact**: Medium
**Likelihood**: Medium
"""
    queue_row = {"severity": "Critical"}
    got = D._enforce_severity_matrix(verify_text, queue_row)
    check(
        "ENFORCE.verifier_higher_than_matrix_loses",
        got == "Medium",
        f"got={got}",
    )


def test_ENFORCE_verifier_lower_with_rationale():
    """An observed SC pattern: verifier says 'High (Impact High x Likelihood High
    = Critical; see note below)'. Verifier deliberately chose lower."""
    verify_text = """
**Verdict**: CONFIRMED
**Severity**: High (Impact: High × Likelihood: High = Critical/High; see note below)
**Impact**: High
**Likelihood**: High
"""
    queue_row = {"severity": "High"}
    got = D._enforce_severity_matrix(verify_text, queue_row)
    check(
        "ENFORCE.verifier_lower_with_rationale",
        got == "High",
        f"got={got}",
    )


def test_ENFORCE_verifier_equal_to_matrix():
    """When verifier and matrix agree, return the shared severity."""
    verify_text = """
**Verdict**: CONFIRMED
**Severity**: Medium
**Impact**: Medium
**Likelihood**: Medium
"""
    queue_row = {"severity": "Medium"}
    got = D._enforce_severity_matrix(verify_text, queue_row)
    check(
        "ENFORCE.verifier_equal_to_matrix",
        got == "Medium",
        f"got={got}",
    )


# =============================================================================
# Integration: _write_mechanical_report_index uses matrix when available.
# =============================================================================

def test_INTEG_report_index_applies_matrix(tmp_path: Path):
    """Verify file says Impact=Low/Likelihood=Low, queue says Critical -> Low."""
    sp = tmp_path
    (sp / "verification_queue.md").write_text("""# Verification Queue

| Finding ID | Severity | Title | Location | Preferred Tag |
|------------|----------|-------|----------|---------------|
| INV-001 | Critical | Test bug | src/Foo.sol:L1 | CODE-TRACE |
""", encoding="utf-8")

    (sp / "verify_INV-001.md").write_text("""# Finding INV-001
**Verdict**: CONFIRMED
**Severity**: Critical
**Impact**: Low
**Likelihood**: Low
**Location**: src/Foo.sol:L1
""", encoding="utf-8")

    bind_verifier_outputs(sp)
    n = D._write_mechanical_report_index(sp)
    check("INTEG.row_count_1", n == 1, f"n={n}")

    idx_text = (sp / "report_index.md").read_text(encoding="utf-8")
    # Critical x queue input but matrix Low x Low -> Low. Report ID should be L-01.
    check(
        "INTEG.matrix_demotes_to_L-01",
        "L-01" in idx_text and "C-01" not in idx_text,
        idx_text[:600],
    )


def test_INTEG_report_index_preserves_when_no_matrix_data(tmp_path: Path):
    """No Impact/Likelihood, severity Low -> preserved (E7 only fires on C/H)."""
    sp = tmp_path
    (sp / "verification_queue.md").write_text("""# Verification Queue

| Finding ID | Severity | Title | Location | Preferred Tag |
|------------|----------|-------|----------|---------------|
| INV-002 | Low | Test bug | src/Foo.sol:L1 | CODE-TRACE |
""", encoding="utf-8")

    (sp / "verify_INV-002.md").write_text("""# Finding INV-002
**Verdict**: CONFIRMED
**Severity**: Low
**Location**: src/Foo.sol:L1
""", encoding="utf-8")

    bind_verifier_outputs(sp)
    D._write_mechanical_report_index(sp)
    idx_text = (sp / "report_index.md").read_text(encoding="utf-8")
    check(
        "INTEG.no_matrix_keeps_L-01",
        "L-01" in idx_text,
        idx_text[:600],
    )


# =============================================================================
# Test runner
# =============================================================================

import tempfile  # noqa: E402

TESTS_BASIC = [
    test_MATRIX_all_cells,
    test_MATRIX_case_insensitive,
    test_MATRIX_unparseable_returns_none,
    test_MOD_onchain_only_demotes_one_tier,
    test_MOD_view_function_caps_at_medium,
    test_MOD_fully_trusted_demotes_with_floor_informational,
    test_MOD_no_modifiers_passthrough,
    test_MOD_combined_apply_in_order,
    test_PARSE_impact_likelihood_from_verify_text,
    test_PARSE_modifier_flags,
    test_PARSE_no_modifiers_when_absent,
    test_ENFORCE_matrix_overrides_llm_severity,
    test_ENFORCE_no_matrix_data_falls_back_to_llm,
    test_ENFORCE_no_matrix_data_critical_preserved_when_verifier_states,
    test_ENFORCE_E7_downgrades_queue_only_critical,
    test_ENFORCE_no_matrix_data_high_preserved_when_verifier_states,
    test_ENFORCE_matrix_plus_modifiers,
    test_ENFORCE_partial_matrix_data_falls_back,
]

TESTS_INTEG = [
    test_INTEG_report_index_applies_matrix,
    test_INTEG_report_index_preserves_when_no_matrix_data,
]


def main() -> int:
    n = len(TESTS_BASIC) + len(TESTS_INTEG)
    print(f"Running {n} severity-matrix tests...")
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
