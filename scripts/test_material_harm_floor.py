"""Material-harm body floor — mechanically-enforced BODY vs APPENDIX routing.

The validated, recall-safe policy:
  - APPENDIX only when a finding has ZERO security consequence (pure quality /
    hardening / observability / style: missing events, missing zero-address /
    range checks with no shown loss, one-step ownership, defense-in-depth,
    EIP-712 binding hardening, naming, typos, magic numbers, gas, docs, etc.).
  - BODY for ANY real security consequence at ANY severity (fund loss / lock,
    privilege escalation, liveness brick, accounting corruption -> loss), even
    when trusted-actor-gated / self-inflicted / bounded.
  - Recall-safe default: when in doubt -> BODY.

The enforcement is driver-mechanical (prior soft LLM rules were ignored):
  1. write_disposition_md  -> disposition.md (report-ID keyed).
  2. enforce_material_harm_floor / apply_material_harm_floor -> relocate any
     APPENDIX body `### [X-NN]` section into Appendix C (never drop).
  3. _run_report_quality_gate is disposition-aware so relocation does not trip
     the body-count / exact-id / promotion-symmetry checks.

Run: `python -m pytest -q test_material_harm_floor.py`
"""
from __future__ import annotations

import importlib
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

P = importlib.import_module("plamen_parsers")
M = importlib.import_module("plamen_mechanical")
V = importlib.import_module("plamen_validators")


# --------------------------------------------------------------- classifier ---

def test_classify_appendix_pure_quality():
    appendix_cases = [
        ("Admin call emits no event", "Medium", "", ""),
        ("Missing zero-address check in setAdmin", "Low", "", ""),
        ("No two-step ownership transfer (Ownable2Step)", "Low", "", ""),
        ("Owner can renounceOwnership", "Low", "", ""),
        ("Add nonReentrant to deposit (defense in depth)", "Low",
         "no reentrancy path is demonstrated", ""),
        ("EIP-712 domain separator should bind chainId", "Low", "", ""),
        ("Typo in error message", "Informational", "", ""),
        ("Magic number 86400 should be a named constant", "Informational", "", ""),
        ("Gas optimization in the loop", "Informational", "", ""),
        ("supportsInterface omits ERC165 id", "Informational", "", ""),
        ("Missing input validation in setConfig", "Low", "", ""),
    ]
    for title, sev, harm, verdict in appendix_cases:
        disp, reason = P.classify_body_or_appendix(title, sev, harm, verdict)
        assert disp == "APPENDIX", f"{title!r} -> {disp} ({reason})"


def test_classify_body_real_consequence_at_any_severity():
    body_cases = [
        ("Reentrancy in withdraw drains the vault", "High", "attacker drains all funds", ""),
        ("Depositors lose pro-rata share on rounding", "Low", "depositors lose value", ""),
        ("Funds permanently locked after pause", "Medium", "users cannot withdraw", ""),
        ("Privilege escalation via unprotected setter", "High", "takeover", ""),
        ("First depositor share inflation", "Medium", "share inflation lets attacker steal", ""),
        # consequence wins even when a quality keyword is also present
        ("Missing event AND fund loss", "Medium", "funds are lost", ""),
        ("Missing nonReentrant lets attacker drain deposits", "High",
         "attacker drains deposits", ""),
    ]
    for title, sev, harm, verdict in body_cases:
        disp, reason = P.classify_body_or_appendix(title, sev, harm, verdict)
        assert disp == "BODY", f"{title!r} -> {disp} ({reason})"


def test_classify_default_is_body_recall_safe():
    disp, reason = P.classify_body_or_appendix("Some unusual behaviour", "Medium", "", "")
    assert disp == "BODY"
    assert "recall-safe" in reason.lower()


# ---------------------------------------------------------- disposition parse ---

def test_parse_disposition_missing_returns_empty(tmp_path: Path):
    assert P.parse_disposition_md(tmp_path) == {}
    assert P._appendix_disposition_report_ids(tmp_path) == set()


def test_parse_disposition_malformed_returns_empty(tmp_path: Path):
    (tmp_path / "disposition.md").write_text("not a table at all\n", encoding="utf-8")
    assert P.parse_disposition_md(tmp_path) == {}


def test_parse_disposition_valid(tmp_path: Path):
    (tmp_path / "disposition.md").write_text(
        "# Finding Disposition\n\n"
        "| Report ID | Disposition | Reason |\n"
        "|-----------|-------------|--------|\n"
        "| C-01 | BODY | real security consequence |\n"
        "| M-01 | APPENDIX | pure quality/hardening |\n"
        "| m-02 | appendix | observability |\n",
        encoding="utf-8",
    )
    disp = P.parse_disposition_md(tmp_path)
    assert disp["C-01"][0] == "BODY"
    assert disp["M-01"][0] == "APPENDIX"
    assert disp["M-02"][0] == "APPENDIX"  # case-normalised
    assert P._appendix_disposition_report_ids(tmp_path) == {"M-01", "M-02"}


# ------------------------------------------------------------------- floor -----

_REPORT = """# Security Audit Report — Demo

## Executive Summary

This audit identified findings.

- **C-01** — Critical drain
- **M-01** — Missing event on setFee

## Summary

| Severity | Count |
|----------|-------|
| Critical | 1 |
| Medium | 2 |

## Critical Findings

### [C-01] Critical drain [VERIFIED]

**Severity**: Critical
**Location**: `src/Vault.sol:L120`
**Description**: Attacker drains the vault.
**Impact**: All funds lost.

---

## Medium Findings

### [M-01] Missing event on setFee [UNVERIFIED]

**Severity**: Medium
**Location**: `src/Vault.sol:L40`
**Description**: setFee does not emit an event.
**Impact**: Off-chain indexers miss the change.

### [M-02] Reentrancy allows draining deposits [VERIFIED]

**Severity**: Medium
**Location**: `src/Vault.sol:L88`
**Description**: Reentrancy.
**Impact**: Funds lost.

---

## Priority Remediation Order

1. **C-01** — Critical drain *(Immediate)*
2. **M-01** — Missing event on setFee *(Before launch)*
3. **M-02** — Reentrancy allows draining deposits *(Before launch)*

---

## Appendix A: Excluded Findings

| Severity | Title | Exclusion Reason |
|----------|-------|------------------|
| Low | Foo | FALSE_POSITIVE |
"""


def test_floor_relocates_appendix_section():
    disp = {
        "C-01": ("BODY", "x"),
        "M-01": ("APPENDIX", "pure quality/hardening — observability"),
        "M-02": ("BODY", "x"),
    }
    new, moved = M.enforce_material_harm_floor(_REPORT, disp)
    assert [r[0] for r in moved] == ["M-01"]
    # (b)/(c): no body section, present as exactly one Appendix C row.
    assert "### [M-01]" not in new
    assert "Appendix C: Quality & Hardening Observations" in new
    assert new.count("| M-01 |") == 1
    # (a): the BODY findings remain as sections.
    assert "### [C-01]" in new
    assert "### [M-02]" in new
    # Dangling references removed + remediation renumbered.
    assert "- **M-01**" not in new
    assert "1. **C-01**" in new
    assert "2. **M-02**" in new
    assert "**M-01**" not in new.split("Appendix")[0]
    # Existing Appendix A is preserved and distinct.
    assert "Appendix A: Excluded Findings" in new


def test_floor_decrements_summary_counts():
    # Relocating M-01 (Medium) out of the body must drop the Summary Medium
    # count 2 -> 1 so the delivered summary matches the remaining body sections.
    disp = {"C-01": ("BODY", "x"), "M-01": ("APPENDIX", "observability"), "M-02": ("BODY", "x")}
    new, moved = M.enforce_material_harm_floor(_REPORT, disp)
    assert [r[0] for r in moved] == ["M-01"]
    summary = new.split("## Summary", 1)[1].split("\n## ", 1)[0]
    assert "| Medium | 1 |" in summary, summary
    assert "| Critical | 1 |" in summary  # untouched tier unchanged
    assert "| Medium | 2 |" not in summary
    # Idempotent: a second pass moves nothing and does not double-decrement.
    new2, moved2 = M.enforce_material_harm_floor(new, disp)
    assert moved2 == []
    assert new2 == new
    summary2 = new2.split("## Summary", 1)[1].split("\n## ", 1)[0]
    assert "| Medium | 1 |" in summary2


def test_floor_decrement_floors_at_zero():
    # Even a malformed summary (count lower than moved) floors at 0, never raises.
    txt = M._decrement_summary_counts(
        "## Summary\n\n| Severity | Count |\n|---|---|\n| Medium | 0 |\n",
        {"Medium": 3},
    )
    assert "| Medium | 0 |" in txt


def test_floor_recall_safe_noop_when_no_appendix():
    disp = {"C-01": ("BODY", "x"), "M-01": ("BODY", "x"), "M-02": ("BODY", "x")}
    new, moved = M.enforce_material_harm_floor(_REPORT, disp)
    assert moved == []
    assert new == _REPORT


def test_floor_noop_when_disposition_empty():
    new, moved = M.enforce_material_harm_floor(_REPORT, {})
    assert moved == []
    assert new == _REPORT


def test_floor_never_drops_a_finding():
    # Even if EVERY finding were dispositioned APPENDIX, each must survive as a
    # row — relocation, never deletion.
    disp = {
        "C-01": ("APPENDIX", "r1"),
        "M-01": ("APPENDIX", "r2"),
        "M-02": ("APPENDIX", "r3"),
    }
    new, moved = M.enforce_material_harm_floor(_REPORT, disp)
    assert {r[0] for r in moved} == {"C-01", "M-01", "M-02"}
    for rid in ("C-01", "M-01", "M-02"):
        assert f"| {rid} |" in new  # appears as an Appendix C row
        assert f"### [{rid}]" not in new  # removed from body


def test_floor_idempotent():
    disp = {"M-01": ("APPENDIX", "r")}
    new, moved = M.enforce_material_harm_floor(_REPORT, disp)
    assert moved
    new2, moved2 = M.enforce_material_harm_floor(new, disp)
    assert moved2 == []
    assert new2 == new


# --------------------------------------------------- write_disposition_md ------

def _seed_index_and_verify(sp: Path):
    (sp / "report_index.md").write_text(
        "# Report Index\n\n"
        "## Master Finding Index\n\n"
        "| Report ID | Title | Severity | Location | Verification | Trust Adj. | Internal Hypothesis |\n"
        "|-----------|-------|----------|----------|--------------|-----------|--------------------|\n"
        "| C-01 | Reentrancy drains vault | Critical | src/Vault.sol:L120 | VERIFIED | - | H-1 |\n"
        "| M-01 | Missing event on setFee | Medium | src/Vault.sol:L40 | UNVERIFIED | - | H-2 |\n",
        encoding="utf-8",
    )
    (sp / "verify_H-1.md").write_text(
        "# H-1 Reentrancy drains vault\n\n"
        "**Verdict**: CONFIRMED\n"
        "**Severity**: Critical\n"
        "**Material Harm**: An attacker drains all depositor funds.\n",
        encoding="utf-8",
    )
    (sp / "verify_H-2.md").write_text(
        "# H-2 Missing event on setFee\n\n"
        "**Verdict**: CONFIRMED\n"
        "**Severity**: Medium\n"
        "**Material Harm**: Off-chain indexers do not observe the fee change.\n",
        encoding="utf-8",
    )


def test_write_disposition_md_keyed_by_report_id(tmp_path: Path):
    _seed_index_and_verify(tmp_path)
    n = M.write_disposition_md(tmp_path)
    assert n == 2
    disp = P.parse_disposition_md(tmp_path)
    assert disp["C-01"][0] == "BODY"
    assert disp["M-01"][0] == "APPENDIX"


def test_write_disposition_noop_without_assignments(tmp_path: Path):
    assert M.write_disposition_md(tmp_path) == 0
    assert not (tmp_path / "disposition.md").exists()


# ------------------------------------------------ apply_material_harm_floor ----

def test_apply_floor_end_to_end(tmp_path: Path):
    _seed_index_and_verify(tmp_path)
    M.write_disposition_md(tmp_path)
    (tmp_path / "AUDIT_REPORT.md").write_text(_REPORT, encoding="utf-8")
    res = M.apply_material_harm_floor(tmp_path, str(tmp_path))
    assert res["moved"] == 1 and res["ids"] == ["M-01"]
    out = (tmp_path / "AUDIT_REPORT.md").read_text(encoding="utf-8")
    assert "### [M-01]" not in out
    assert "Appendix C" in out


def test_apply_floor_noop_without_disposition(tmp_path: Path):
    (tmp_path / "AUDIT_REPORT.md").write_text(_REPORT, encoding="utf-8")
    res = M.apply_material_harm_floor(tmp_path, str(tmp_path))
    assert res["moved"] == 0
    assert (tmp_path / "AUDIT_REPORT.md").read_text(encoding="utf-8") == _REPORT


# ----------------------------------------------- gate disposition-awareness ----

def _seed_floored_scratchpad(sp: Path):
    """A scratchpad where M-01 was relocated to Appendix C by the floor."""
    # Tier assignments source for the gate.
    (sp / "verification_queue.md").write_text(
        "# Verification Queue\n\n"
        "| Finding ID | Severity | Title | Location | Preferred Tag |\n"
        "|------------|----------|-------|----------|---------------|\n"
        "| H-1 | Critical | Reentrancy drains vault | src/Vault.sol:L120 | CODE-TRACE |\n"
        "| H-2 | Medium | Missing event on setFee | src/Vault.sol:L40 | CODE-TRACE |\n"
        "| H-3 | Medium | Reentrancy allows draining deposits | src/Vault.sol:L88 | CODE-TRACE |\n",
        encoding="utf-8",
    )
    (sp / "report_index.md").write_text(
        "# Report Index\n\n"
        "## Summary\n\n"
        "| Severity | Count |\n|----------|-------|\n"
        "| Critical | 1 |\n| Medium | 2 |\n\n"
        "## Master Finding Index\n\n"
        "| Report ID | Title | Severity | Location | Verification | Trust Adj. | Internal Hypothesis |\n"
        "|-----------|-------|----------|----------|--------------|-----------|--------------------|\n"
        "| C-01 | Reentrancy drains vault | Critical | src/Vault.sol:L120 | VERIFIED | - | H-1 |\n"
        "| M-01 | Missing event on setFee | Medium | src/Vault.sol:L40 | UNVERIFIED | - | H-2 |\n"
        "| M-02 | Reentrancy allows draining deposits | Medium | src/Vault.sol:L88 | VERIFIED | - | H-3 |\n",
        encoding="utf-8",
    )
    (sp / "disposition.md").write_text(
        "| Report ID | Disposition | Reason |\n"
        "|-----------|-------------|--------|\n"
        "| C-01 | BODY | x |\n"
        "| M-01 | APPENDIX | observability |\n"
        "| M-02 | BODY | x |\n",
        encoding="utf-8",
    )
    # The floored report: M-01 lives in Appendix C, not in the body.
    disp = {"C-01": ("BODY", "x"), "M-01": ("APPENDIX", "observability"), "M-02": ("BODY", "x")}
    floored, _ = M.enforce_material_harm_floor(_REPORT, disp)
    (sp / "AUDIT_REPORT.md").write_text(floored, encoding="utf-8")


def test_quality_gate_tolerates_relocation(tmp_path: Path):
    _seed_floored_scratchpad(tmp_path)
    issues = V._run_report_quality_gate(tmp_path, str(tmp_path))
    # The relocation must not produce a body-count / exact-id / promotion issue.
    blob = " ".join(issues).lower()
    assert "count mismatch" not in blob, issues
    assert "id set mismatch" not in blob, issues
    assert "promotion dropout" not in blob, issues


def test_quality_gate_promotion_symmetry_rejects_untyped_appendix_ack(tmp_path: Path):
    _seed_floored_scratchpad(tmp_path)
    # P0-R: a raw legacy Appendix row is identity accounting, not disposition
    # authority. Without the typed receipt/decision it must remain a dropout.
    (tmp_path / "verify_H-2.md").write_text(
        "**Verdict**: CONFIRMED\n**Preferred Tag**: CODE-TRACE\n", encoding="utf-8"
    )
    issues = V._check_promotion_symmetry(tmp_path, str(tmp_path))
    blob = " ".join(issues)
    assert "H-2" in blob, issues


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-q"]))
