"""Compilation-free EVM source-parse graph provider (the always-on tier beneath
Slither). Proves the coverage gate runs on a Solidity project that does NOT
compile (missing deps) — without mocking the compiler — by deriving the in-scope
co-reference set from a source parse, same tier as the Move/DAML providers."""
from __future__ import annotations

import importlib
import json
import os
import sys
from pathlib import Path

import pytest


def _rp():
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    return importlib.import_module("recon_prepass")


@pytest.fixture(autouse=True)
def _force_visible_slither_authority_debt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rp = _rp()
    monkeypatch.setattr(
        rp,
        "_capture_python_provider_authority",
        lambda *_args, **_kwargs: {
            "authority_status": "UNAVAILABLE",
            "deterministic_provider_authority": False,
            "reason": "fixture exercises source fallback",
        },
    )


_SRC = (
    "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;\n"
    "import \"missing-dep/IFoo.sol\";\n"  # unresolvable -> would break Slither
    "contract Vault is IFoo {\n"
    "    uint256 public lpId;\n"
    "    function withdrawERC721() external {\n        lpId = 0;\n    }\n"
    "    function createMarket() external {\n        uint256 x = lpId;\n    }\n"
    "}\n"
)


def _proj(tmp_path: Path) -> Path:
    p = tmp_path / "proj"
    p.mkdir()
    (p / "Vault.sol").write_text(_SRC, encoding="utf-8")
    return p


def test_source_graph_built_without_compilation(tmp_path: Path):
    rp = _rp()
    sp = tmp_path / "scratch"
    sp.mkdir()
    r = rp._bake_evm_source_graph(sp, _proj(tmp_path))
    assert r == "WRITTEN"
    g = json.loads((sp / "_mechanical_graph.json").read_text(encoding="utf-8"))
    assert g["source"] == "evm-source"
    refs = {d.split("(", 1)[0].strip() for d in g["var_refs"]["lpId"]["refs"]}
    assert refs == {"withdrawERC721", "createMarket"}


def test_tiered_wrapper_falls_back_not_mocks(tmp_path: Path):
    rp = _rp()
    sp = tmp_path / "scratch"
    sp.mkdir()
    # Slither cannot compile this (no framework / missing dep) -> wrapper must
    # fall back to the source tier, never fabricate a compiled graph.
    r = rp._bake_evm_graph(sp, _proj(tmp_path))
    assert r.startswith("WRITTEN:evm-source")
    assert (sp / "_mechanical_graph.json").exists()


def test_no_sol_sources_skips(tmp_path: Path):
    rp = _rp()
    sp = tmp_path / "scratch"
    sp.mkdir()
    empty = tmp_path / "empty"
    empty.mkdir()
    assert rp._bake_evm_source_graph(sp, empty) == "SKIPPED:no .sol sources"


def test_gate_recovers_enumgap_on_uncompilable_project(tmp_path: Path):
    rp = _rp()
    eg = importlib.import_module("enumeration_gate")
    sp = tmp_path / "scratch"
    sp.mkdir()
    rp._bake_evm_graph(sp, _proj(tmp_path))
    (sp / "findings_inventory.md").write_text(
        "# Inv\n\n### Finding [INV-001]: withdrawERC721 clears lpId\n"
        "**Severity**: Medium\n**Location**: `Vault.sol:L6`\n**Source IDs**: B1\n"
        "withdrawERC721 zeroes lpId, recipient-gated, safe.\n", encoding="utf-8")
    res = eg.run_enumeration_gate(sp)
    assert res["emitted"] == 1
    assert "createMarket" in (sp / "findings_inventory.md").read_text(encoding="utf-8")


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-q"]))
