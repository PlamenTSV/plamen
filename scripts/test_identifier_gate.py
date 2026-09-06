"""Phase 1 — mechanical disposition gate: identifier-existence hallucination
catch (Gate 3, IDENTIFIER_UNVERIFIED).

A finding may cite a CONCRETE function/method identifier (backtick-quoted
`foo()` / `Contract.method`, or a `function fooBar` / bare `fooBar()` prose
token) that does not exist ANYWHERE in the whole-project source index. This is
a stronger anti-hallucination signal than the path-based location gates, which
only validate the *file*, not the *symbol* inside it.

RECALL-SAFE by construction:
  - No concrete identifier cited (generic prose, ambiguous, multi-identifier,
    bare variable name) -> gate never fires, loc_status untouched.
  - Identifier present ANYWHERE in the project (even a different file, e.g.
    inheritance/base contract) -> gate never fires.
  - Only Low/Informational findings are appendix-routed (IDENTIFIER_UNVERIFIED).
  - Medium/High/Critical findings are FLAGGED ONLY (loc_reason annotated) and
    KEEP their original loc_status (stay in the body) — never appendix-routed,
    never dropped.
"""
from __future__ import annotations

import importlib
import os
import sys
from pathlib import Path


def _val():
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    return importlib.import_module("plamen_validators")


def _inv(*blocks: str) -> str:
    return "# Findings Inventory\n\n" + "\n\n".join(blocks) + "\n"


def _block(fid: str, title: str, loc: str, severity: str = "Low", src: str = "B1-1") -> str:
    return (
        f"## [{fid}] {title}\n\n"
        f"**Severity**: {severity}\n"
        f"**Location**: `{loc}`\n"
        f"**Source IDs**: {src}\n"
    )


def _mk_project(tmp_path: Path) -> Path:
    root = tmp_path / "proj"
    (root / "core").mkdir(parents=True)
    (root / "base").mkdir(parents=True)
    (root / "core" / "Real.sol").write_text(
        "\n".join(f"contract Real {{ function knownFunc() public {{}} }} // line{i}" for i in range(1, 11)),
        encoding="utf-8",
    )
    (root / "base" / "Base.sol").write_text(
        "\n".join(["contract Base {"] + [f"    // line{i}" for i in range(1, 8)] + ["    function fooBarBaz() public {}", "}"]),
        encoding="utf-8",
    )
    return root


# -------------------------------------------------------- unit: extraction --

def test_extract_concrete_identifier_backtick_call():
    v = _val()
    assert v._extract_concrete_identifier("Reentrancy in `fooBarBaz()`", "") == "fooBarBaz"


def test_extract_concrete_identifier_dotted_form():
    v = _val()
    assert v._extract_concrete_identifier("Bug in `Vault.withdraw`", "") == "withdraw"


def test_extract_concrete_identifier_function_prose():
    v = _val()
    assert v._extract_concrete_identifier("Missing check in function settleMarket", "") == "settleMarket"


def test_extract_concrete_identifier_bare_call_token():
    v = _val()
    assert v._extract_concrete_identifier("", "core/Real.sol calls fooBarBaz() unsafely") == "fooBarBaz"


def test_extract_concrete_identifier_skips_generic_prose():
    v = _val()
    assert v._extract_concrete_identifier("The setter allows arbitrary withdrawal", "") is None
    assert v._extract_concrete_identifier("Issue in the withdraw path", "") is None


def test_extract_concrete_identifier_skips_bare_variable_backtick():
    # a backtick-quoted bare name with no dot and no parens is NOT "clearly a
    # function" per spec -> must be skipped (recall-safe).
    v = _val()
    assert v._extract_concrete_identifier("Stale value in `totalSupply`", "") is None


def test_extract_concrete_identifier_skips_multi_identifier_titles():
    v = _val()
    assert v._extract_concrete_identifier("Mismatch between `fooBar()` and `bazQux()`", "") is None


# --------------------------------------------------- end-to-end: positive ---

def test_low_finding_absent_identifier_routes_to_appendix(tmp_path: Path):
    v = _val()
    root = _mk_project(tmp_path)
    scratch = tmp_path / ".scratchpad"
    scratch.mkdir()
    (scratch / "findings_inventory.md").write_text(_inv(
        _block("L-01", "Reentrancy in `fooBarBaz2()`", "core/Real.sol:L5", severity="Low"),
    ), encoding="utf-8")

    recs = v._validate_inventory_evidence(scratch, str(root), apply_safe_recovery=False)
    assert recs["L-01"]["location_status"] == "IDENTIFIER_UNVERIFIED"
    assert "fooBarBaz2" in recs["L-01"]["location_reason"]


def test_informational_finding_absent_identifier_routes_to_appendix(tmp_path: Path):
    v = _val()
    root = _mk_project(tmp_path)
    scratch = tmp_path / ".scratchpad"
    scratch.mkdir()
    (scratch / "findings_inventory.md").write_text(_inv(
        _block("I-01", "Dead code in `neverCalled()`", "core/Real.sol:L5", severity="Informational"),
    ), encoding="utf-8")

    recs = v._validate_inventory_evidence(scratch, str(root), apply_safe_recovery=False)
    assert recs["I-01"]["location_status"] == "IDENTIFIER_UNVERIFIED"


# ------------------------------------------------- negative controls -------

def test_neg1_identifier_present_in_different_file_stays_ok(tmp_path: Path):
    """Inheritance / cross-file case: identifier absent from the RESOLVED file
    but present ELSEWHERE in the project -> whole-scope check must not fire."""
    v = _val()
    root = _mk_project(tmp_path)
    scratch = tmp_path / ".scratchpad"
    scratch.mkdir()
    (scratch / "findings_inventory.md").write_text(_inv(
        _block("L-02", "Bug in `fooBarBaz()`", "core/Real.sol:L5", severity="Low"),
    ), encoding="utf-8")

    recs = v._validate_inventory_evidence(scratch, str(root), apply_safe_recovery=False)
    # fooBarBaz() lives in base/Base.sol, not core/Real.sol -> still OK.
    assert recs["L-02"]["location_status"] == "OK"


def test_neg2_critical_absent_identifier_not_appendix_routed(tmp_path: Path):
    v = _val()
    root = _mk_project(tmp_path)
    scratch = tmp_path / ".scratchpad"
    scratch.mkdir()
    (scratch / "findings_inventory.md").write_text(_inv(
        _block("C-01", "Fund loss via `ghostFunc()`", "core/Real.sol:L5", severity="Critical"),
    ), encoding="utf-8")

    recs = v._validate_inventory_evidence(scratch, str(root), apply_safe_recovery=False)
    assert recs["C-01"]["location_status"] == "OK", "Critical must stay in body, never appendix-routed"
    assert "IDENTIFIER-UNVERIFIED" in recs["C-01"]["location_reason"], "must still be flagged for human review"


def test_neg2b_high_absent_identifier_not_appendix_routed(tmp_path: Path):
    v = _val()
    root = _mk_project(tmp_path)
    scratch = tmp_path / ".scratchpad"
    scratch.mkdir()
    (scratch / "findings_inventory.md").write_text(_inv(
        _block("H-01", "Privilege escalation via `ghostFunc2()`", "core/Real.sol:L5", severity="High"),
    ), encoding="utf-8")

    recs = v._validate_inventory_evidence(scratch, str(root), apply_safe_recovery=False)
    assert recs["H-01"]["location_status"] == "OK", "High must stay in body, never appendix-routed"
    assert "IDENTIFIER-UNVERIFIED" in recs["H-01"]["location_reason"]


def test_neg3_medium_absent_identifier_flag_only(tmp_path: Path):
    v = _val()
    root = _mk_project(tmp_path)
    scratch = tmp_path / ".scratchpad"
    scratch.mkdir()
    (scratch / "findings_inventory.md").write_text(_inv(
        _block("M-01", "Accounting drift via `ghostFunc3()`", "core/Real.sol:L5", severity="Medium"),
    ), encoding="utf-8")

    recs = v._validate_inventory_evidence(scratch, str(root), apply_safe_recovery=False)
    assert recs["M-01"]["location_status"] == "OK", "Medium must stay in body, not appendix-routed"
    assert "IDENTIFIER-UNVERIFIED" in recs["M-01"]["location_reason"]


def test_neg4_no_concrete_identifier_untouched(tmp_path: Path):
    v = _val()
    root = _mk_project(tmp_path)
    scratch = tmp_path / ".scratchpad"
    scratch.mkdir()
    (scratch / "findings_inventory.md").write_text(_inv(
        _block("L-03", "The withdraw path allows arbitrary transfers", "core/Real.sol:L5", severity="Low"),
    ), encoding="utf-8")

    recs = v._validate_inventory_evidence(scratch, str(root), apply_safe_recovery=False)
    assert recs["L-03"]["location_status"] == "OK"
    assert recs["L-03"]["location_reason"] == "path exists"


# --------------------------------------------- downstream filter behavior ---

def test_filter_retains_identifier_unverified_as_repair_debt_for_all_severities(tmp_path: Path):
    v = _val()
    scratch = tmp_path / ".scratchpad"
    scratch.mkdir()
    ledger = """# Inventory Evidence Validation

| Finding ID | Location Status | Resolved Location | Location Reason | Source Status | Source Reason |
|---|---|---|---|---|---|
| L-01 | IDENTIFIER_UNVERIFIED | core/Real.sol:L5 | cited identifier `fooBarBaz2` not found anywhere in the project source index (likely hallucinated) | OK | ok |
| M-01 | OK | core/Real.sol:L5 | path exists [IDENTIFIER-UNVERIFIED - human review: `ghostFunc3` not found anywhere in the project source index] | OK | ok |
"""
    queue = """# Verification Queue

| Queue # | Finding ID | Severity | Title |
|---|---|---|---|
| 1 | L-01 | Low | hallucinated identifier |
| 2 | M-01 | Medium | flagged identifier, still verified |
"""
    (scratch / "inventory_evidence_validation.md").write_text(ledger, encoding="utf-8")
    (scratch / "verification_queue.md").write_text(queue, encoding="utf-8")

    removed = v._filter_verification_queue_by_evidence(scratch)
    assert removed == []
    active = v.parse_verification_queue_rows(scratch)
    assert {row["finding id"] for row in active} == {"L-01", "M-01"}
    low = next(row for row in active if row["finding id"] == "L-01")
    assert "IDENTIFIER_UNVERIFIED" in low["evidence debt"]
    debt = (scratch / "verification_queue_evidence_debt.md").read_text(encoding="utf-8")
    assert "L-01" in debt and "RETAINED_ACTIVE" in debt


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-q"]))
