from __future__ import annotations

import hashlib
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
    graph_raw = json.dumps(graph).encode()
    graph_views = depth_handoff._graph_views(graph)
    graph_evidence = {
        **graph_views,
        "_mechanical_graph.json": graph_raw,
    }
    denominator = [*depth_handoff.GRAPH_INPUTS, "_mechanical_graph.json"]
    unsigned = {
        "schema_version": "plamen.mechanical_graph_generation.v1",
        "state": "COMMITTED",
        "artifact_denominator": denominator,
        "artifacts": [
            {
                "path": name,
                "sha256": hashlib.sha256(graph_evidence[name]).hexdigest(),
                "bytes": len(graph_evidence[name]),
            }
            for name in denominator
        ],
    }
    generation = {
        **unsigned,
        "generation_sha256": hashlib.sha256(
            (
                json.dumps(
                    unsigned,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n"
            ).encode()
        ).hexdigest(),
    }
    return (
        graph_raw,
        json.dumps(generation).encode(),
        graph_views,
        inventory.encode(),
        contract_inventory.encode(),
        manifest.encode(),
        breadth,
    )


def test_render_depth_handoff_is_exact_recall_preserving_and_honest():
    graph, generation, graph_views, inventory, contracts, manifest, breadth = _inputs()
    first = depth_handoff.render_depth_handoff(
        mechanical_graph_raw=graph,
        graph_generation_raw=generation,
        graph_projection_raw_by_name=graph_views,
        findings_inventory_raw=inventory,
        contract_inventory_raw=contracts,
        spawn_manifest_raw=manifest,
        breadth_raw_by_name=breadth,
    )
    second = depth_handoff.render_depth_handoff(
        mechanical_graph_raw=graph,
        graph_generation_raw=generation,
        graph_projection_raw_by_name=graph_views,
        findings_inventory_raw=inventory,
        contract_inventory_raw=contracts,
        spawn_manifest_raw=manifest,
        breadth_raw_by_name=breadth,
    )
    assert first == second
    assert set(first) == set(depth_handoff.OUTPUTS)
    assert first["depth_candidates.md"].count(b"| INV-001 |") == 1
    assert not set(depth_handoff.GRAPH_INPUTS).intersection(first)
    assert b"UNKNOWN \xe2\x80\x94 requires Depth judgment" in first["state_dependency_map.md"]
    assert b"`contracts/Helper.sol` | NO" in first["file_coverage.md"]
    assert b"**Status**: OPEN" in first["phase4_gates.md"]
    receipt = json.loads(first["depth_handoff_receipt.json"])
    assert receipt["finding_count"] == 1
    assert receipt["uncovered_files"] == ["contracts/Helper.sol"]
    assert receipt["source_sha256"]["caller_map.md"] == hashlib.sha256(
        graph_views["caller_map.md"]
    ).hexdigest()


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
            "_mechanical_graph_generation.json",
            *depth_handoff.GRAPH_INPUTS,
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


def test_mechanical_graph_projection_phaseio_contract_is_driver_owned_and_exact():
    contract = resolve_phase_io_contract(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="codex",
        phase="inventory",
        work_unit_id="mechanical_graph_projection",
        exact_inputs=("_mechanical_graph.json",),
        exact_outputs=depth_handoff.GRAPH_PROJECTION_OUTPUTS,
        exact_writer="DRIVER",
    )
    assert contract.model_invoked is False
    assert contract.required_commit_actor == "DRIVER"
    assert tuple(spec.path for spec in contract.outputs) == (
        depth_handoff.GRAPH_PROJECTION_OUTPUTS
    )


def test_handoff_materializes_missing_evm_graph_generation_once(tmp_path):
    graph, _generation, _graph_views, inventory, contracts, manifest, breadth = (
        _inputs()
    )
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
        "_run_id": "run-depth-handoff-source-graph",
    }

    assert driver._prepare_depth_handoff(tmp_path, config) == []
    first = {
        name: (tmp_path / name).read_bytes()
        for name in depth_handoff.GRAPH_PROJECTION_OUTPUTS
    }
    assert b"deposit" in first["function_summary.md"]
    assert json.loads(first[depth_handoff.GRAPH_GENERATION_FILE])["state"] == (
        "COMMITTED"
    )
    assert driver._prepare_depth_handoff(tmp_path, config) == []
    assert first == {
        name: (tmp_path / name).read_bytes()
        for name in depth_handoff.GRAPH_PROJECTION_OUTPUTS
    }


def test_handoff_publishes_state_map_before_invariant_compatibility(tmp_path):
    graph, generation, graph_views, inventory, contracts, manifest, breadth = _inputs()
    files = {
        "_mechanical_graph.json": graph,
        "_mechanical_graph_generation.json": generation,
        **graph_views,
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


def test_handoff_rejects_graph_projection_drift_without_overwriting(
    tmp_path,
):
    graph, generation, graph_views, inventory, contracts, manifest, breadth = _inputs()
    files = {
        "_mechanical_graph.json": graph,
        "_mechanical_graph_generation.json": generation,
        **graph_views,
        "findings_inventory.md": inventory,
        "contract_inventory.md": contracts,
        "attack_surface.md": b"# Attack Surface\n\nBounded test surface.\n",
        "spawn_manifest.md": manifest,
        **breadth,
    }
    for name, raw in files.items():
        (tmp_path / name).write_bytes(raw)
    stale = b"# Caller Map\n\nmutated after generation\n"
    (tmp_path / "caller_map.md").write_bytes(stale)
    config = {
        "pipeline": "sc",
        "mode": "thorough",
        "language": "evm",
        "cli_backend": "codex",
        "project_root": str(tmp_path.parent),
        "_run_id": "run-depth-handoff-graph-drift",
    }

    issues = driver._prepare_depth_handoff(tmp_path, config)
    assert any("mechanical graph generation artifact differs" in issue for issue in issues)
    assert (tmp_path / "caller_map.md").read_bytes() == stale
    assert not (tmp_path / "depth_handoff_receipt.json").exists()
