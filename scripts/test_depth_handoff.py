from __future__ import annotations

import json

import depth_handoff
import plamen_driver as driver
import semantic_invariant_authority
from phase_io_contracts import resolve_phase_io_contract


def _inputs():
    graph = {
        "schema_version": "test",
        "functions": {
            "deposit": {
                "loc": "contracts/Vault.sol:L10",
                "callers": [],
                "callees": ["transferFrom"],
                "signature_fact": {
                    "visibility": "external",
                    "authority": "AST",
                },
            },
            "withdraw": {
                "loc": "contracts/Vault.sol:L20",
                "callers": [],
                "callees": ["transfer"],
                "signature_fact": {
                    "visibility": "external",
                    "authority": "AST",
                },
            },
        },
        "state_symbols": [{
            "symbol_id": "STATE-1",
            "qualified_name": "balances",
            "declaration_locus": "contracts/Vault.sol:L5",
            "read_sites": ["withdraw (contracts/Vault.sol:L21)"],
            "write_sites": ["deposit (contracts/Vault.sol:L12)"],
            "graph_confidence": "AST_EXACT",
        }],
    }
    inventory = """# Finding Inventory

### Finding [INV-001]: Incorrect balance update
**Severity**: High
**Location**: contracts/Vault.sol:12
**Verdict**: UNRESOLVED
**Root Cause**: State is updated after token transfer.

### Finding [INV-001]: Duplicate additive projection
**Severity**: High
**Location**: contracts/Vault.sol:12
**Verdict**: UNRESOLVED
**Root Cause**: Duplicate identity.
"""
    contract_inventory = """# Contract Inventory
| File | Path | Lines | Bytes |
|---|---|---:|---:|
| Vault.sol | `contracts/Vault.sol` | 30 | 1000 |
| Helper.sol | `contracts/Helper.sol` | 10 | 100 |
"""
    manifest = """| Kind | Template | Required | Agent ID | Output |
|---|---|---|---|---|
| AGENT | STATE | YES | B1 | analysis_state.md |
"""
    breadth = {"analysis_state.md": b"Vault.sol:12 examined\n"}
    return (
        json.dumps(graph).encode(),
        inventory.encode(),
        contract_inventory.encode(),
        manifest.encode(),
        breadth,
    )


def test_render_depth_handoff_is_exact_recall_preserving_and_honest():
    graph, inventory, contracts, manifest, breadth = _inputs()
    first = depth_handoff.render_depth_handoff(
        mechanical_graph_raw=graph,
        findings_inventory_raw=inventory,
        contract_inventory_raw=contracts,
        spawn_manifest_raw=manifest,
        breadth_raw_by_name=breadth,
    )
    second = depth_handoff.render_depth_handoff(
        mechanical_graph_raw=graph,
        findings_inventory_raw=inventory,
        contract_inventory_raw=contracts,
        spawn_manifest_raw=manifest,
        breadth_raw_by_name=breadth,
    )
    assert first == second
    assert set(first) == set(depth_handoff.OUTPUTS)
    assert first["depth_candidates.md"].count(b"| INV-001 |") == 1
    assert b"> **Status**: POPULATED" in first["caller_map.md"]
    assert b"deposit" in first["callee_map.md"]
    assert b"balances" in first["state_write_map.md"]
    assert b"UNKNOWN \xe2\x80\x94 requires Depth judgment" in first["state_dependency_map.md"]
    assert b"`contracts/Helper.sol` | NO" in first["file_coverage.md"]
    assert b"**Status**: OPEN" in first["phase4_gates.md"]
    receipt = json.loads(first["depth_handoff_receipt.json"])
    assert receipt["finding_count"] == 1
    assert receipt["uncovered_files"] == ["contracts/Helper.sol"]


def test_depth_handoff_phaseio_contract_is_driver_owned_and_exact():
    outputs = depth_handoff.OUTPUTS
    contract = resolve_phase_io_contract(
        pipeline="sc",
        mode="thorough",
        ecosystem="sol",
        backend="codex",
        phase="inventory",
        work_unit_id="depth_handoff",
        exact_inputs=(
            "_mechanical_graph.json",
            "findings_inventory.md",
            "contract_inventory.md",
            "attack_surface.md",
            "spawn_manifest.md",
            "analysis_state.md",
        ),
        exact_outputs=outputs,
        exact_writer="DRIVER",
    )
    assert contract.model_invoked is False
    assert contract.required_commit_actor == "DRIVER"
    assert tuple(spec.path for spec in contract.outputs) == outputs


def test_handoff_publishes_state_map_before_invariant_compatibility(tmp_path):
    graph, inventory, contracts, manifest, breadth = _inputs()
    files = {
        "_mechanical_graph.json": graph,
        "findings_inventory.md": inventory,
        "contract_inventory.md": contracts,
        "attack_surface.md": b"# Attack Surface\n\nBounded test surface.\n",
        "spawn_manifest.md": manifest,
        **breadth,
    }
    for name, raw in files.items():
        (tmp_path / name).write_bytes(raw)
    config = {
        "pipeline": "sc",
        "mode": "thorough",
        "language": "evm",
        "cli_backend": "codex",
        "project_root": str(tmp_path.parent),
        "_run_id": "run-depth-handoff-before-invariants",
    }

    assert driver._prepare_depth_handoff(tmp_path, config) == []
    state_before = (tmp_path / "state_write_map.md").read_bytes()
    assert b"balances" in state_before
    created = (
        semantic_invariant_authority
        .materialize_semantic_invariant_compatibility_inputs(tmp_path)
    )
    assert "state_write_map.md" not in created
    assert (tmp_path / "state_write_map.md").read_bytes() == state_before
    assert driver._prepare_depth_handoff(tmp_path, config) == []
