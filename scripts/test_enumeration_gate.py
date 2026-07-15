"""G1 + G2 — the mechanical enumeration-coverage gate. Reproduces the L-04 shape:
a finding analyzing `withdrawERC721` (which touches a shared symbol) that never
addresses `createMarket` (a co-referencer of that symbol) → an ENUMGAP candidate
is appended for the verifier. Recall-safe, idempotent, no-op without a graph."""
from __future__ import annotations

import importlib
import json
import os
import sys
from pathlib import Path


def _eg():
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    return importlib.import_module("enumeration_gate")


_GRAPH = {
    "source": "slither",
    "var_refs": {
        "Vault.lpId": {"bare": "lpId", "refs": [
            "withdrawERC721 (Vault.sol:L100)", "createMarket (Vault.sol:L200)"]},
    },
    "functions": {
        "Vault.withdrawERC721": {"bare": "withdrawERC721", "loc": "Vault.sol:L100", "callers": []},
        "Vault.createMarket": {"bare": "createMarket", "loc": "Vault.sol:L200", "callers": []},
    },
}


def _inv(*blocks: str) -> str:
    return "# Finding Inventory\n\n" + "\n\n".join(blocks) + "\n"


def _finding(fid, loc, body):
    return (f"### Finding [{fid}]: a finding\n**Severity**: Medium\n"
            f"**Location**: `{loc}`\n**Source IDs**: B1-1\n{body}\n")


def _setup(tmp_path: Path, finding_body: str) -> Path:
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    (sp / "_mechanical_graph.json").write_text(json.dumps(_GRAPH), encoding="utf-8")
    (sp / "findings_inventory.md").write_text(
        _inv(_finding("INV-001", "Vault.sol:L100", finding_body)), encoding="utf-8")
    return sp


def _coverage_setup(tmp_path: Path, required: list[str], body: str) -> Path:
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    (sp / "_enumeration_obligations.json").write_text(
        json.dumps({"obligations": [{
            "finding_id": "INV-001",
            "function": "entry",
            "symbol": "sharedState",
            "required_corefs": required,
        }]}),
        encoding="utf-8",
    )
    (sp / "findings_inventory.md").write_text(
        _inv(_finding("INV-001", "Module.ext:L10", body)),
        encoding="utf-8",
    )
    return sp


def test_emits_enumgap_for_unaddressed_coreferencer(tmp_path: Path):
    eg = _eg()
    # finding about withdrawERC721 mentions lpId but NOT createMarket -> gap
    sp = _setup(tmp_path, "withdrawERC721 removes the lpId NFT; recipient-gated, safe.")
    res = eg.run_enumeration_gate(sp)
    assert res["obligations"] >= 1
    assert res["emitted"] == 1
    inv = (sp / "findings_inventory.md").read_text(encoding="utf-8")
    assert "ENUMGAP" in inv
    assert "createMarket" in inv
    assert "Enumeration-Coverage Candidates" in inv


def test_no_gap_when_coreferencer_is_addressed(tmp_path: Path):
    eg = _eg()
    # finding DOES discuss createMarket -> no gap
    sp = _setup(tmp_path,
                "withdrawERC721 removes lpId; note createMarket also depends on lpId, "
                "but it reverts cleanly, so this is fine.")
    res = eg.run_enumeration_gate(sp)
    assert res["emitted"] == 0
    assert "ENUMGAP" not in (sp / "findings_inventory.md").read_text(encoding="utf-8")


def test_coreferencer_substring_settlement_does_not_cover_settle(tmp_path: Path):
    eg = _eg()
    sp = _coverage_setup(tmp_path, ["settle"], "The settlement path is bounded.")
    assert eg.compute_coverage_gaps(sp)[0]["missing"] == ["settle"]


def test_coreferencer_identifier_suffix_does_not_cover_base_name(tmp_path: Path):
    eg = _eg()
    sp = _coverage_setup(tmp_path, ["foo"], "The foo_v2 path is analyzed.")
    assert eg.compute_coverage_gaps(sp)[0]["missing"] == ["foo"]


def test_coreferencer_exact_and_backticked_names_are_covered(tmp_path: Path):
    eg = _eg()
    sp = _coverage_setup(
        tmp_path, ["settle", "foo"],
        "The SETTLE path and the `foo` helper are both analyzed.",
    )
    assert eg.compute_coverage_gaps(sp) == []


def test_coreferencer_qualified_terminal_names_are_covered(tmp_path: Path):
    eg = _eg()
    sp = _coverage_setup(
        tmp_path, ["settle", "foo"],
        "Review Module.settle() together with Namespace::foo().",
    )
    assert eg.compute_coverage_gaps(sp) == []


def test_idempotent(tmp_path: Path):
    eg = _eg()
    sp = _setup(tmp_path, "withdrawERC721 removes lpId; safe.")
    eg.run_enumeration_gate(sp)
    res2 = eg.run_enumeration_gate(sp)
    assert res2["emitted"] == 0
    assert (sp / "findings_inventory.md").read_text(encoding="utf-8").count("createMarket also references") <= 1


def test_no_graph_is_noop(tmp_path: Path):
    eg = _eg()
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    (sp / "findings_inventory.md").write_text(
        _inv(_finding("INV-001", "Vault.sol:L100", "x")), encoding="utf-8")
    res = eg.run_enumeration_gate(sp)
    assert res == {"obligations": 0, "gaps": 0, "emitted": 0}


def test_common_symbol_skipped(tmp_path: Path):
    eg = _eg()
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    # a symbol referenced by 30 functions is too common to gate on
    refs = [f"fn{i} (Vault.sol:L{i})" for i in range(30)]
    g = {"source": "slither",
         "var_refs": {"Vault.common": {"bare": "common", "refs": refs}},
         "functions": {"Vault.fn0": {"bare": "fn0", "loc": "Vault.sol:L0", "callers": []}}}
    (sp / "_mechanical_graph.json").write_text(json.dumps(g), encoding="utf-8")
    (sp / "findings_inventory.md").write_text(
        _inv(_finding("INV-001", "Vault.sol:L0", "fn0 does x")), encoding="utf-8")
    res = eg.run_enumeration_gate(sp)
    assert res["emitted"] == 0  # common symbol skipped, no flood


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-q"]))
