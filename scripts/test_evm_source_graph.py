"""Compilation-free EVM source-parse graph provider (the always-on tier beneath
Slither). Proves the coverage gate runs on a Solidity project that does NOT
compile (missing deps) — without mocking the compiler — by deriving the in-scope
co-reference set from a source parse, same tier as the Move/DAML providers."""
from __future__ import annotations

import importlib
import hashlib
import json
import os
import sys
from pathlib import Path

import pytest

import evm_analysis_workspace_authority as WORKSPACE


ROOT = Path(__file__).resolve().parents[1]


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


def _workspace_authority(project: Path, scratchpad: Path) -> dict:
    """Publish and replay the real workspace authority for wrapper tests."""

    preparation = {
        "schema_version": "plamen.evm_input_preparation.v1",
        "status": "DEGRADED",
        "reason": "source-fallback fixture has no dependency materialization",
    }
    preparation["preparation_sha256"] = hashlib.sha256(
        json.dumps(
            preparation, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
    ).hexdigest()
    config = {
        "pipeline": "sc",
        "mode": "core",
        "language": "evm",
        "cli_backend": "claude",
        "_resolved_build_root": str(project),
        "_resolved_build_root_authority": (
            WORKSPACE.capture_evm_build_root_resolver_authority(project, project)
        ),
        "_snapshot_input_preparation": preparation,
    }
    snapshot = {
        "snapshot_digest": "c" * 64,
        "components": {
            "source_scope": {
                "digest": "d" * 64,
                "path_set_digest": "e" * 64,
                "file_count": 1,
                "byte_count": len(_SRC.encode("utf-8")),
            },
            "toolchain": {"digest": "f" * 64, "runtime_entries": {}},
        },
    }
    run_id = "evm-source-graph-workspace-v1"
    outcome = WORKSPACE.ensure_evm_analysis_workspace_authority(
        config=config,
        scratchpad=scratchpad,
        project_root=project,
        run_id=run_id,
        audit_snapshot=snapshot,
        implementation_root=ROOT,
    )
    assert outcome is not None
    return WORKSPACE.load_evm_analysis_workspace_authority(
        scratchpad,
        expected_run_id=run_id,
        expected_snapshot_sha256=snapshot["snapshot_digest"],
    )


def test_source_graph_built_without_compilation(tmp_path: Path):
    rp = _rp()
    sp = tmp_path / "scratch"
    sp.mkdir()
    r = rp._bake_evm_source_graph(sp, _proj(tmp_path))
    assert r == "WRITTEN"
    g = json.loads((sp / "_mechanical_graph.json").read_text(encoding="utf-8"))
    assert g["source"] == "evm-source"
    refs = {
        d.split("(", 1)[0].strip()
        for d in g["var_refs"]["Vault.sol::Vault.lpId"]["refs"]
    }
    assert refs == {"withdrawERC721", "createMarket"}


def test_tiered_wrapper_falls_back_not_mocks(tmp_path: Path):
    rp = _rp()
    sp = tmp_path / "scratch"
    sp.mkdir()
    # Slither cannot compile this (no framework / missing dep) -> wrapper must
    # fall back to the source tier, never fabricate a compiled graph.
    project = _proj(tmp_path)
    workspace = _workspace_authority(project, sp)
    r = rp._bake_evm_graph(sp, project, workspace_authority=workspace)
    assert r.startswith("WRITTEN:evm-source")
    assert (sp / "_mechanical_graph.json").exists()


def test_axis_graph_accepts_only_receipt_bound_evm_workspace_extension(
    tmp_path: Path,
):
    rp = _rp()
    eg = importlib.import_module("enumeration_gate")
    sp = tmp_path / "scratch"
    sp.mkdir()
    project = _proj(tmp_path)
    workspace = _workspace_authority(project, sp)
    result = rp._bake_evm_graph(
        sp,
        project,
        workspace_authority=workspace,
    )
    assert result.startswith("WRITTEN:evm-source")

    graph, debt = eg._axis_graph_provider_debt(sp, project)

    assert graph is not None
    assert not any("workspace" in row.casefold() for row in debt)
    assert not any("shape mismatch" in row.casefold() for row in debt)

    graph_path = sp / "_mechanical_graph.json"
    tampered = json.loads(graph_path.read_text(encoding="utf-8"))
    tampered["evm_analysis_workspace"]["receipt_sha256"] = "0" * 64
    graph_path.write_text(json.dumps(tampered, indent=1), encoding="utf-8")

    _graph, tamper_debt = eg._axis_graph_provider_debt(sp, project)

    assert any(
        "does not match the committed typed workspace receipt" in row
        for row in tamper_debt
    )


def test_axis_graph_rejects_unknown_field_beside_workspace_extension(
    tmp_path: Path,
):
    rp = _rp()
    eg = importlib.import_module("enumeration_gate")
    sp = tmp_path / "scratch"
    sp.mkdir()
    project = _proj(tmp_path)
    workspace = _workspace_authority(project, sp)
    result = rp._bake_evm_graph(
        sp,
        project,
        workspace_authority=workspace,
    )
    assert result.startswith("WRITTEN:evm-source")
    graph_path = sp / "_mechanical_graph.json"
    malformed = json.loads(graph_path.read_text(encoding="utf-8"))
    malformed["unregistered_extension"] = {}
    graph_path.write_text(json.dumps(malformed, indent=1), encoding="utf-8")

    _graph, debt = eg._axis_graph_provider_debt(sp, project)

    assert debt == ["mechanical graph typed authority shape mismatch"]


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
    project = _proj(tmp_path)
    workspace = _workspace_authority(project, sp)
    rp._bake_evm_graph(sp, project, workspace_authority=workspace)
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
