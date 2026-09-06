"""Mechanical location and non-production evidence diagnostics.

Invalid, missing, or non-production locations are evidence-quality signals,
not finding-disposition authority. Every candidate stays in the active
verification denominator and the driver emits explicit evidence debt for
independent verification/report retention. A merely unparseable prose
location remains soft as well.
"""
from __future__ import annotations

import importlib
import os
import sys
from pathlib import Path


def _val():
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    return importlib.import_module("plamen_validators")


# --------------------------------------------------------- non-production ---

def test_is_nonproduction_location():
    v = _val()
    # CONSERVATIVE: only a non-production DIRECTORY or a test-file SUFFIX flags.
    nonprod = [
        "test/Foo.sol", "tests/Bar.sol", "src/fuzz/Harness.sol",
        "_fuzzproj/CPMM.sol", "contracts/mocks/MockToken.sol",
        "script/Deploy.s.sol", ".medusa-tests/out/CPMM.sol",
        "core/Real.t.sol", "src/Vault.s.sol",
    ]
    # production contracts whose NAME contains stub/mock/test but live in a real
    # dir with a real suffix must NOT be flagged (would drop real findings).
    prod = [
        "core/MarketManager.sol", "libraries/CPMM.sol",
        "periphery/Hook.sol", "tokens/QOrgToken.sol:L40",
        "core/Stub.sol", "src/MockableVault.sol", "x/MockOracle.sol",
        "a/FooTest.sol",
    ]
    for p in nonprod:
        assert v._is_nonproduction_location(p) is True, p
    for p in prod:
        assert v._is_nonproduction_location(p) is False, p


def test_is_harness_location_prose():
    v = _val()
    harness = [
        "Invariant fuzz test harness (CPMM)",
        "Test harness invariant quoteMatchesExecution",
        "fuzz harness, empty catch blocks",
        "the invariant harness setup",
        "Medusa harness configuration",
    ]
    notharness = [
        "core/MarketManager.sol:L40",        # real file -> path logic
        "the addLiquidity function",             # prose but not a harness
        "Missing test coverage for settleMarket",  # mentions test, not a harness loc
        "src/test/Foo.t.sol",                    # real-ish file token -> path logic
    ]
    for h in harness:
        assert v._is_harness_location_prose(h) is True, h
    for n in notharness:
        assert v._is_harness_location_prose(n) is False, n


# --------------------------------------- end-to-end: location status set ----

def _inv(*blocks: str) -> str:
    return "# Findings Inventory\n\n" + "\n\n".join(blocks) + "\n"


def _block(fid, loc, src="B1-1"):
    return f"## [{fid}] finding {fid}\n\n**Location**: `{loc}`\n**Source IDs**: {src}\n"


def test_validate_inventory_evidence_sets_location_status(tmp_path: Path):
    v = _val()
    root = tmp_path / "proj"
    (root / "core").mkdir(parents=True)
    (root / "test").mkdir(parents=True)
    (root / "core" / "Real.sol").write_text("\n".join(f"line{i}" for i in range(1, 11)), encoding="utf-8")
    (root / "test" / "Foo.t.sol").write_text("\n".join(["x"] * 20), encoding="utf-8")
    scratch = tmp_path / ".scratchpad"
    scratch.mkdir()
    (scratch / "findings_inventory.md").write_text(_inv(
        _block("M-01", "core/Real.sol:L5"),          # OK
        _block("M-02", "test/Foo.t.sol:L3"),         # non-production
        _block("M-03", "factories/StrategyFactory.sol:L10"),  # hallucinated
        _block("M-04", "core/Real.sol:L999"),        # line exceeds EOF
    ), encoding="utf-8")

    recs = v._validate_inventory_evidence(scratch, str(root), apply_safe_recovery=False)
    assert recs["M-01"]["location_status"] == "OK"
    assert recs["M-02"]["location_status"] == "LOCATION_NONPRODUCTION"
    assert recs["M-03"]["location_status"] == "LOCATION_INVALID"
    assert "not found" in recs["M-03"]["location_reason"].lower()
    assert recs["M-04"]["location_status"] == "LOCATION_INVALID"
    assert "exceed" in recs["M-04"]["location_reason"].lower()


# --------------------------------------------- filter drop policy ----------

_LEDGER = """# Inventory Evidence Validation

| Finding ID | Location Status | Resolved Location | Location Reason | Source Status | Source Reason |
|---|---|---|---|---|---|
| M-01 | OK | core/Real.sol:L5 | path exists | OK | ok |
| M-02 | LOCATION_NONPRODUCTION | test/Foo.t.sol:L3 | resolved to a non-production (test/fuzz/mock/harness) path | OK | ok |
| M-03 | LOCATION_INVALID |  | file not found | OK | ok |
| M-04 | LOCATION_INVALID |  | line 999 exceeds file length 10 | OK | ok |
| M-05 | LOCATION_INVALID |  | no parseable source path | OK | ok |
| M-06 | LOCATION_AMBIGUOUS |  | 2 basename matches | SOURCE_INVALID | bad |
| M-07 | LOCATION_INVALID |  | file not found | SOURCE_INVALID | bad |
"""

_QUEUE = """# Verification Queue

| Queue # | Finding ID | Severity | Title |
|---|---|---|---|
| 1 | M-01 | Medium | real production |
| 2 | M-02 | Medium | test harness |
| 3 | M-03 | Medium | hallucinated file |
| 4 | M-04 | Low | line exceeds |
| 5 | M-05 | Medium | prose location, good source |
| 6 | M-06 | Low | ambiguous, bad source |
| 7 | M-07 | Medium | hallucinated AND bad source |
"""


def test_filter_drops_hard_invalid_alone_keeps_soft(tmp_path: Path):
    v = _val()
    scratch = tmp_path / ".scratchpad"
    scratch.mkdir()
    (scratch / "inventory_evidence_validation.md").write_text(_LEDGER, encoding="utf-8")
    (scratch / "verification_queue.md").write_text(_QUEUE, encoding="utf-8")

    removed = v._filter_verification_queue_by_evidence(scratch)
    assert removed == []
    rows = v.parse_verification_queue_rows(scratch)
    assert {row["finding id"] for row in rows} == {
        "M-01", "M-02", "M-03", "M-04", "M-05", "M-06", "M-07"
    }

    # Location defects are repair evidence, not proof that a candidate is
    # safe. Non-production and jointly-invalid rows remain active and acquire
    # an explicit advisory debt record.
    debt_path = scratch / "verification_queue_evidence_debt.md"
    assert debt_path.exists()
    debt = debt_path.read_text(encoding="utf-8")
    assert all(fid in debt for fid in ("M-02", "M-06", "M-07"))
    assert "never exclusion authority" in debt


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-q"]))
