"""Fixtures for Fix 1 (canonical verification-status token) + Fix 3 (narrow
always-on external-assumption severity brake).

Fix 1: ONE canonical `Verification` token per finding, from (verifier verdict,
EFFECTIVE best-evidence tag). VERIFIED = confirmed + proof-grade; CONFIRMED =
confirmed + [CODE-TRACE]; CONTESTED = disputed; UNVERIFIED = refuted/none. An
integrity-DOWNGRADED tag ("(was [POC-PASS], …)") is NOT proof-grade → CONFIRMED,
not VERIFIED (the label-honesty fix). The migration makes CONFIRMED a
non-speculative status everywhere a stale parser previously read it as
UNVERIFIED.

Fix 3: a High/Critical whose ONLY in-scope-proven fact is a missing balance-delta
check, whose harm rides on an assumed untrusted-external-return-value, with NO
PoC attempted, is capped to Medium (floor Medium, in-body, never Low) and stamped
EXTERNAL-ASSUMPTION-CAP(<orig>). A PoC Attempted:YES + PASS is NOT capped.

Per the feedback_id_regex_catalog rule these fixtures exercise the two NEW
tokens (`CONFIRMED`, `EXTERNAL-ASSUMPTION-CAP`) across the parser + provenance
allowlist + header-tag surfaces so no stale reader mis-reads them.

All fixtures are synthetic/generic (no protocol/token/contract/function names).

Run: pytest scripts/test_fix1_fix3_status_and_external_assumption.py -v
"""
from __future__ import annotations

import importlib
import json
import os
import sys
from pathlib import Path


def _v():
    sys.path.insert(0, os.path.join(os.path.dirname(__file__)))
    if "plamen_validators" in sys.modules:
        del sys.modules["plamen_validators"]
    return importlib.import_module("plamen_validators")


def _scratch(tmp_path: Path, *, proven_only: bool = False) -> Path:
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    (sp / "config.json").write_text(
        json.dumps({"proven_only": bool(proven_only)}), encoding="utf-8"
    )
    return sp


def _queue(sp: Path, rows: list[tuple[str, str, str]]) -> None:
    out = [
        "| Queue # | Finding ID | Severity | Title | PoC Class |",
        "|---------|------------|----------|-------|-----------|",
    ]
    for i, (fid, sev, pc) in enumerate(rows, start=1):
        out.append(f"| {i} | {fid} | {sev} | example finding | {pc} |")
    (sp / "verification_queue.md").write_text("\n".join(out) + "\n", encoding="utf-8")


# The "external-assumption-promoted" mechanism prose the guard 3 anchor detects:
# an external call's RETURN VALUE consumed verbatim with NO balance-delta check,
# harm promoted on assumed worst-case external behavior.
_EXT_RETURN_MECH = (
    "The external router's reported return value is consumed verbatim and paid "
    "out from the contract's own balance with no balanceOf delta check. Under "
    "the external dependency's worst realistic behavior the over-payment is "
    "direct. `[EXTERNAL-ASSUMPTION: reported return value diverges from actual "
    "received balance]`"
)


def _verify(sp: Path, fid: str, *, severity: str, verdict: str, tag: str,
            attempted: str, skip_reason: str = "N/A",
            result: str = "NOT_EXECUTED", body: str = "") -> None:
    (sp / f"verify_{fid}.md").write_text(
        f"**Severity**: {severity}\n\n"
        f"**Verdict**: {verdict}\n\n"
        f"**Evidence Tag**: {tag}\n\n"
        f"{body}\n\n"
        "### PoC Attempt\n"
        "- PoC Required: YES\n"
        f"- Attempted: {attempted}\n"
        f"- PoC Not Attempted Because: {skip_reason}\n\n"
        "### Execution Result\n"
        f"- Result: {result}\n",
        encoding="utf-8",
    )


def _verdict_manifest(sp: Path, rows: list[dict[str, str]]) -> None:
    (sp / "verdict_manifest.json").write_text(
        json.dumps({
            "schema_version": "plamen.verdict_manifest.v1",
            "mechanical_source": "mechanical_verify_manifest.md",
            "row_count": len(rows),
            "verdicts": rows,
        }),
        encoding="utf-8",
    )


# ===========================================================================
# Fix 1 — canonical_verification_status pure mapping
# ===========================================================================

def test_canonical_status_pure_mapping():
    import plamen_types as T
    C = T.canonical_verification_status
    assert C("CONFIRMED", True) == "VERIFIED"
    assert C("CONFIRMED", False) == "CONFIRMED"
    assert C("TRUE_POSITIVE", True) == "VERIFIED"
    assert C("VALID", False) == "CONFIRMED"
    assert C("CONTESTED", False) == "CONTESTED"
    assert C("UNRESOLVED", False) == "CONTESTED"
    assert C("PARTIAL", False) == "CONTESTED"
    assert C("REFUTED", False) == "UNVERIFIED"
    assert C("FALSE_POSITIVE", True) == "UNVERIFIED"  # proof-grade irrelevant
    assert C("", False) == "UNVERIFIED"
    # sort strength
    k = T.canonical_status_sort_key
    assert k("VERIFIED") < k("CONFIRMED") < k("CONTESTED") < k("UNVERIFIED")


def test_status_map_proof_grade_is_verified(tmp_path):
    V = _v()
    sp = _scratch(tmp_path)
    _queue(sp, [("INV-1", "High", "unit")])
    _verify(sp, "INV-1", severity="High", verdict="CONFIRMED",
            tag="[POC-PASS]", attempted="YES", result="PASS")
    assert V._expected_report_index_statuses(sp).get("INV-1") == "VERIFIED"


def test_status_map_manifest_mechanical_unavailable_is_confirmed(tmp_path):
    """Preserved proof prose is not execution proof when mechanics were absent."""
    V = _v()
    sp = _scratch(tmp_path)
    _queue(sp, [("INV-6", "High", "unit")])
    _verify(sp, "INV-6", severity="High", verdict="CONFIRMED",
            tag="[POC-PASS] [MECHANICAL-UNAVAILABLE]", attempted="YES",
            result="PASS")
    before = {
        "severity": V._expected_report_index_severities(sp),
        "verdict": V._verifier_status_from_text(
            (sp / "verify_INV-6.md").read_text(encoding="utf-8")
        ),
    }
    _verdict_manifest(sp, [{
        "finding_id": "INV-6",
        "verify_file": "verify_INV-6.md",
        "mechanical_status": "TOOLCHAIN_UNAVAILABLE",
        "verifier_prose_tag": "[POC-PASS]",
        "integrity_state": "MECHANICAL_UNAVAILABLE",
        "effective_tag": "[POC-PASS] [MECHANICAL-UNAVAILABLE]",
    }])

    assert V._expected_report_index_statuses(sp).get("INV-6") == "CONFIRMED"
    assert V._expected_report_index_severities(sp) == before["severity"]
    assert V._verifier_status_from_text(
        (sp / "verify_INV-6.md").read_text(encoding="utf-8")
    ) == before["verdict"]


def test_status_map_manifest_unverified_harness_is_confirmed(tmp_path):
    V = _v()
    sp = _scratch(tmp_path)
    _queue(sp, [("INV-7", "Medium", "unit")])
    _verify(sp, "INV-7", severity="Medium", verdict="CONFIRMED",
            tag="[POC-PASS] [POC-UNVERIFIED-HARNESS] [NEEDS-BUILD]",
            attempted="YES", result="PASS")
    _verdict_manifest(sp, [{
        "finding_id": "INV-7",
        "verify_file": "verify_INV-7.md",
        "mechanical_status": "NO_TEST_FILE",
        "verifier_prose_tag": "[POC-PASS]",
        "integrity_state": "POC_UNVERIFIED_HARNESS",
        "effective_tag": "[POC-PASS] [POC-UNVERIFIED-HARNESS] [NEEDS-BUILD]",
    }])
    assert V._expected_report_index_statuses(sp).get("INV-7") == "CONFIRMED"


def test_status_map_manifest_effective_tag_overrides_stale_prose(tmp_path):
    V = _v()
    sp = _scratch(tmp_path)
    _queue(sp, [("INV-11", "Medium", "unit")])
    _verify(sp, "INV-11", severity="Medium", verdict="CONFIRMED",
            tag="[POC-PASS]", attempted="YES", result="PASS")
    _verdict_manifest(sp, [{
        "finding_id": "INV-11",
        "verify_file": "verify_INV-11.md",
        "mechanical_status": "NO_TEST_MATCH",
        "verifier_prose_tag": "[POC-PASS]",
        "integrity_state": "INFLATED_PROSE",
        "effective_tag": "[CODE-TRACE] [INTEGRITY-DOWNGRADE]",
    }])
    assert V._expected_report_index_statuses(sp).get("INV-11") == "CONFIRMED"


def test_status_map_manifest_genuine_pass_remains_verified(tmp_path):
    V = _v()
    sp = _scratch(tmp_path)
    _queue(sp, [("INV-8", "High", "unit")])
    _verify(sp, "INV-8", severity="High", verdict="CONFIRMED",
            tag="[POC-PASS]", attempted="YES", result="PASS")
    _verdict_manifest(sp, [{
        "finding_id": "INV-8",
        "verify_file": "verify_INV-8.md",
        "mechanical_status": "PASS",
        "verifier_prose_tag": "[POC-PASS]",
        "integrity_state": "CONSISTENT",
        "effective_tag": "[POC-PASS]",
    }])
    assert V._expected_report_index_statuses(sp).get("INV-8") == "VERIFIED"


def test_status_map_manifest_production_evidence_remains_verified(tmp_path):
    V = _v()
    sp = _scratch(tmp_path)
    _queue(sp, [("INV-9", "High", "integration")])
    _verify(sp, "INV-9", severity="High", verdict="CONFIRMED",
            tag="[PROD-ONCHAIN] [MECHANICAL-UNAVAILABLE]", attempted="NO")
    _verdict_manifest(sp, [{
        "finding_id": "INV-9",
        "verify_file": "verify_INV-9.md",
        "mechanical_status": "TOOLCHAIN_UNAVAILABLE",
        "verifier_prose_tag": "[PROD-ONCHAIN]",
        "integrity_state": "MECHANICAL_UNAVAILABLE",
        "effective_tag": "[PROD-ONCHAIN] [MECHANICAL-UNAVAILABLE]",
    }])
    assert V._expected_report_index_statuses(sp).get("INV-9") == "VERIFIED"


def test_status_map_legacy_unavailable_flag_fallback_is_confirmed(tmp_path):
    """Pre-manifest resumes still interpret the explicit integrity flag honestly."""
    V = _v()
    sp = _scratch(tmp_path)
    _queue(sp, [("INV-10", "Medium", "unit")])
    _verify(sp, "INV-10", severity="Medium", verdict="CONFIRMED",
            tag="[POC-PASS]", attempted="YES", result="PASS",
            body="Mechanical integrity: [MECHANICAL-UNAVAILABLE]")
    assert not (sp / "verdict_manifest.json").exists()
    assert V._expected_report_index_statuses(sp).get("INV-10") == "CONFIRMED"


def test_status_map_legacy_harness_flag_fallback_is_confirmed(tmp_path):
    V = _v()
    sp = _scratch(tmp_path)
    _queue(sp, [("INV-12", "Medium", "unit")])
    _verify(sp, "INV-12", severity="Medium", verdict="CONFIRMED",
            tag="[POC-PASS]", attempted="YES", result="PASS",
            body="Harness state: [POC-UNVERIFIED-HARNESS] [NEEDS-BUILD]")
    assert not (sp / "verdict_manifest.json").exists()
    assert V._expected_report_index_statuses(sp).get("INV-12") == "CONFIRMED"


def test_status_map_code_trace_is_confirmed_not_unverified(tmp_path):
    V = _v()
    sp = _scratch(tmp_path)
    _queue(sp, [("INV-2", "Medium", "structural")])
    _verify(sp, "INV-2", severity="Medium", verdict="CONFIRMED",
            tag="[CODE-TRACE]", attempted="NO",
            skip_reason="STRUCTURAL_NO_EXECUTABLE_HARM_ASSERTION")
    assert V._expected_report_index_statuses(sp).get("INV-2") == "CONFIRMED"


def test_status_map_integrity_downgraded_pocpass_is_confirmed(tmp_path):
    """The label-honesty fix: a [POC-PASS] demoted to [CODE-TRACE] with a
    `(was [POC-PASS], integrity downgrade: …)` annotation must read CONFIRMED,
    NOT VERIFIED — the residual [POC-PASS] inside the annotation is not current
    evidence."""
    V = _v()
    sp = _scratch(tmp_path)
    _queue(sp, [("INV-3", "High", "unit")])
    _verify(
        sp, "INV-3", severity="High", verdict="CONFIRMED",
        tag="[CODE-TRACE] (was [POC-PASS], integrity downgrade: "
            "No assertion found in PoC code — downgrade to [CODE-TRACE])",
        attempted="YES", result="PASS",
    )
    assert V._expected_report_index_statuses(sp).get("INV-3") == "CONFIRMED"


def test_status_map_refuted_is_unverified(tmp_path):
    V = _v()
    sp = _scratch(tmp_path)
    _queue(sp, [("INV-4", "Medium", "unit")])
    _verify(sp, "INV-4", severity="Medium", verdict="REFUTED",
            tag="[POC-FAIL]", attempted="YES", result="FAIL")
    assert V._expected_report_index_statuses(sp).get("INV-4") == "UNVERIFIED"


def test_status_map_contested_is_contested(tmp_path):
    V = _v()
    sp = _scratch(tmp_path)
    _queue(sp, [("INV-5", "High", "structural")])
    _verify(sp, "INV-5", severity="High", verdict="CONTESTED",
            tag="[CODE-TRACE]", attempted="NO",
            skip_reason="STRUCTURAL_NO_EXECUTABLE_HARM_ASSERTION")
    assert V._expected_report_index_statuses(sp).get("INV-5") == "CONTESTED"


# ===========================================================================
# Fix 1 — migration: CONFIRMED accepted everywhere UNVERIFIED-vs-VERIFIED matters
# ===========================================================================

def _write_master_index(sp: Path, verif: str, *, internal: str = "CH-1") -> None:
    (sp / "report_index.md").write_text(
        "# Report Index\n\n## Master Finding Index\n\n"
        "| Report ID | Title | Severity | Location | Verification | Trust Adj. | Internal Hypothesis |\n"
        "|-----------|-------|----------|----------|--------------|-----------|--------------------|\n"
        f"| C-01 | example chain | Critical | file.x:1 | {verif} | - | {internal} |\n",
        encoding="utf-8",
    )


def test_speculative_critical_accepts_confirmed(tmp_path):
    """A Critical chain row whose Verification is CONFIRMED must NOT be flagged
    speculative (rule-8 migration)."""
    V = _v()
    sp = _scratch(tmp_path)
    _write_master_index(sp, "CONFIRMED")
    assert V._check_speculative_critical_chains(sp) == []


def test_speculative_critical_still_flags_unverified(tmp_path):
    """Regression guard: an UNVERIFIED Critical chain is STILL flagged."""
    V = _v()
    sp = _scratch(tmp_path)
    _write_master_index(sp, "UNVERIFIED")
    flagged = V._check_speculative_critical_chains(sp)
    assert flagged and "C-01" in flagged[0]


def test_provenance_allowlist_accepts_ext_assumption_cap(tmp_path):
    V = _v()
    # EXTERNAL-ASSUMPTION-CAP(<orig>) is a valid severity-change reason (matches
    # the existing `assumption`/`cap` alternatives).
    assert V._report_index_adjustment_reason_present("EXTERNAL-ASSUMPTION-CAP(High)") is True
    # A canonical Verification STATUS word must NOT excuse a silent severity
    # delta — it is a status, not a severity-change reason.
    assert V._report_index_adjustment_reason_present("CONFIRMED") is False
    assert V._report_index_adjustment_reason_present("VERIFIED") is False
    # no regression on empty/none
    assert V._report_index_adjustment_reason_present("") is False
    assert V._report_index_adjustment_reason_present("-") is False


def test_header_status_regex_preserves_confirmed():
    """The mechanical body-header finalizer must recognize/preserve a trailing
    [CONFIRMED] status tag (Fix 1) — parity with [VERIFIED]/[UNVERIFIED]."""
    import importlib as _il
    import plamen_mechanical as M
    _il.reload(M)
    section = "### [H-01] Example finding [CONFIRMED]\n\nbody\n"
    out = M._finalize_report_tier_section(section, {"H-01": "Example finding"})
    assert "[CONFIRMED]" in out


# ===========================================================================
# Fix 3 — external-assumption severity cap
# ===========================================================================

def test_ext_assumption_structural_blocker_caps_to_medium(tmp_path):
    """H-11 shape: CODE-TRACE + Attempted:NO + STRUCTURAL blocker + external-
    return-value promotion → capped to Medium."""
    V = _v()
    sp = _scratch(tmp_path)
    _queue(sp, [("INV-EA1", "High", "structural")])
    _verify(sp, "INV-EA1", severity="High", verdict="CONFIRMED",
            tag="[CODE-TRACE]", attempted="NO",
            skip_reason="STRUCTURAL_NO_EXECUTABLE_HARM_ASSERTION",
            body=_EXT_RETURN_MECH)
    assert V._expected_report_index_severities(sp).get("INV-EA1") == "Medium"


def test_ext_assumption_external_dep_blocker_caps_to_medium(tmp_path):
    """H-18 shape: CODE-TRACE + Attempted:NO + EXTERNAL_DEPENDENCY blocker +
    external-return-value promotion → capped to Medium."""
    V = _v()
    sp = _scratch(tmp_path)
    _queue(sp, [("INV-EA2", "High", "structural")])
    _verify(sp, "INV-EA2", severity="High", verdict="CONFIRMED",
            tag="[CODE-TRACE]", attempted="NO",
            skip_reason="EXTERNAL_DEPENDENCY_NO_FORK_OR_ADDRESS",
            body=_EXT_RETURN_MECH)
    assert V._expected_report_index_severities(sp).get("INV-EA2") == "Medium"


def test_ext_assumption_floor_is_medium_never_low_under_proven_only(tmp_path):
    """Even under proven_only (which would otherwise cap CODE-TRACE to Low), an
    external-assumption High floors at Medium, never Low."""
    V = _v()
    sp = _scratch(tmp_path, proven_only=True)
    _queue(sp, [("INV-EA3", "High", "structural")])
    _verify(sp, "INV-EA3", severity="High", verdict="CONFIRMED",
            tag="[CODE-TRACE]", attempted="NO",
            skip_reason="STRUCTURAL_NO_EXECUTABLE_HARM_ASSERTION",
            body=_EXT_RETURN_MECH)
    assert V._expected_report_index_severities(sp).get("INV-EA3") == "Medium"


def test_carveout_attempted_yes_pass_not_capped(tmp_path):
    """Load-bearing carve-out: a PoC Attempted:YES + PASS (even integrity-
    downgraded to CODE-TRACE) is NOT capped — protects the executed-High family."""
    V = _v()
    sp = _scratch(tmp_path)
    _queue(sp, [("INV-EA4", "High", "unit")])
    _verify(
        sp, "INV-EA4", severity="High", verdict="CONFIRMED",
        tag="[CODE-TRACE] (was [POC-PASS], integrity downgrade: no assertion)",
        attempted="YES", result="PASS", body=_EXT_RETURN_MECH,
    )
    assert V._expected_report_index_severities(sp).get("INV-EA4") == "High"


def test_proof_grade_not_capped(tmp_path):
    """Guard 1: a proof-grade [POC-PASS] finding is never capped."""
    V = _v()
    sp = _scratch(tmp_path)
    _queue(sp, [("INV-EA5", "High", "unit")])
    _verify(sp, "INV-EA5", severity="High", verdict="CONFIRMED",
            tag="[POC-PASS]", attempted="YES", result="PASS", body=_EXT_RETURN_MECH)
    assert V._expected_report_index_severities(sp).get("INV-EA5") == "High"


def test_internal_logic_bug_not_capped(tmp_path):
    """Guard 3: a CODE-TRACE + Attempted:NO + structural finding with NO
    external-return-value promotion (a plain internal-logic bug) is NOT capped —
    the cap is anchored to the external-return mechanism, not bare R10/structural."""
    V = _v()
    sp = _scratch(tmp_path)
    _queue(sp, [("INV-EA6", "High", "structural")])
    _verify(sp, "INV-EA6", severity="High", verdict="CONFIRMED",
            tag="[CODE-TRACE]", attempted="NO",
            skip_reason="STRUCTURAL_NO_EXECUTABLE_HARM_ASSERTION",
            body="An off-by-one in the internal accumulator lets the loop skip "
                 "the final index, so the stored total is understated. Purely "
                 "internal arithmetic; no external calls involved.")
    assert V._expected_report_index_severities(sp).get("INV-EA6") == "High"


def test_bare_r10_without_return_mech_not_capped(tmp_path):
    """Guard 3 'NOT bare R10': a finding that merely cites R10 worst-case
    language WITHOUT an untrusted-external-return-value mechanism is NOT capped."""
    V = _v()
    sp = _scratch(tmp_path)
    _queue(sp, [("INV-EA7", "High", "structural")])
    _verify(sp, "INV-EA7", severity="High", verdict="CONFIRMED",
            tag="[CODE-TRACE]", attempted="NO",
            skip_reason="STRUCTURAL_NO_EXECUTABLE_HARM_ASSERTION",
            body="Applying R10 worst-case severity to this admin-only setter "
                 "misconfiguration; no external return value is trusted.")
    assert V._expected_report_index_severities(sp).get("INV-EA7") == "High"


def test_ext_assumption_cap_trust_adj_token_accepted(tmp_path):
    """The stamped Trust Adj. token is accepted by the provenance allowlist so
    a capped row does not fail the severity-provenance gate."""
    V = _v()
    assert V._report_index_adjustment_reason_present(
        "EXTERNAL-ASSUMPTION-CAP(High)"
    ) is True


def test_ext_assumption_predicate_helpers(tmp_path):
    """Direct unit coverage of the three guards + carve-out predicate."""
    V = _v()
    good = (
        "**Evidence Tag**: [CODE-TRACE]\n"
        f"{_EXT_RETURN_MECH}\n"
        "- Attempted: NO\n"
        "- PoC Not Attempted Because: EXTERNAL_DEPENDENCY_NO_FORK_OR_ADDRESS\n"
        "- Result: NOT_EXECUTED\n"
    )
    assert V._poc_not_attempted(good) is True
    assert V._external_assumption_promoted(good) is True
    assert V._poc_attempted_and_passed(good) is False
    assert V._external_assumption_cap_applies(good) is True
    # flip to Attempted:YES + PASS → carve-out kicks in
    passed = good.replace("- Attempted: NO", "- Attempted: YES").replace(
        "- Result: NOT_EXECUTED", "- Result: PASS"
    )
    assert V._poc_attempted_and_passed(passed) is True
    assert V._external_assumption_cap_applies(passed) is False
