"""V2 fixture-first RED denominator for Cut-4 recon prepass authority.

This is the repaired successor to the frozen 2026-07-30 prepass fixture.  It
tests a *public* closed-publication boundary and the live public prepass entry
point.  It never intercepts ``Path.write_text`` and never requires a private
renderer or driver helper.  The intended implementation surface is the small
``recon_phaseio_application`` module described by the accepted Cut-4
inventory: a closed planner/publisher over the existing PhaseIO and
ArtifactLedger stores, plus thin live-route adapters.

The tests are deliberately RED on the frozen current production preimage.
GREEN tests in this module are controls for the current under-bound contract,
the typed tool-debt vocabulary, and pure deterministic dependency-free
rendering inputs.  They are not claims that recon publication is applied.
"""
from __future__ import annotations

import hashlib
import importlib
import json
from pathlib import Path
import sys
from typing import Any, Callable, Mapping

import pytest


SCRIPTS = Path(__file__).resolve().parent
ROOT = SCRIPTS.parent
sys.path.insert(0, str(SCRIPTS))
sys.path.insert(0, str(ROOT))

import artifact_ledger as AL  # noqa: E402
import recon_prepass as RP  # noqa: E402
import tool_coverage_ledger as TCL  # noqa: E402
from phase_io_contracts import (  # noqa: E402
    ArtifactSpec,
    LaunchSpec,
    PhaseIOContract,
    canonical_work_unit_key,
    resolve_phase_io_contract,
)


RUN_ID = "cut4-recon-v2"
CONFIG = {
    "pipeline": "sc",
    "mode": "thorough",
    "language": "evm",
    "cli_backend": "claude",
    "run_id": RUN_ID,
    "_run_id": RUN_ID,
    "prepass_external_scanners": False,
}

LOCAL_BASELINE_OUTPUTS = (
    "contract_inventory.md",
    "state_variables.md",
    "function_list.md",
    "niche_interface_parity_findings.md",
    "niche_permissionless_setters_findings.md",
    "design_context.md",
    "attack_surface.md",
    "detected_patterns.md",
    "setter_list.md",
    "emit_list.md",
    "template_recommendations.md",
    "recon_summary.md",
    "meta_buffer.md",
    "external_dependency_research.md",
)

PRECISE_GRAPH_OUTPUTS = (
    "caller_map.md",
    "callee_map.md",
    "state_write_map.md",
    "function_summary.md",
    "_mechanical_graph.json",
    "_mechanical_graph_generation.json",
    "tool_coverage_ledger.json",
    "tool_coverage_ledger.md",
)

APPROXIMATE_GRAPH_OUTPUTS = (
    "_mechanical_graph.json",
    "_mechanical_graph_generation.json",
    "tool_coverage_ledger.json",
    "tool_coverage_ledger.md",
)

CAPTURE_INPUTS = (
    "audit_snapshot.json",
    "recon_prepass_source_closure.json",
    "recon_prepass_build_root_closure.json",
    "recon_prepass_skill_index_authority.json",
    "recon_prepass_config_authority.json",
    "recon_prepass_tool_context_authority.json",
    "recon_prepass_namespace_manifest.json",
)

TERMINAL_STATES = frozenset({
    "APPLIED",
    "TYPED_ZERO",
    "MODEL_OUTPUT",
    "DRIVER_FALLBACK",
    "EXPLICIT_ABSENCE",
    "DEBT",
    "REJECTED",
    "QUARANTINED",
    "REUSED_COMMITTED_GENERATION",
})

PUBLIC_SURFACE = (
    "prepare_prepass_plan",
    "publish_recon_plan",
    "run_prepass",
    "recover_recon_publications",
    "recon_route_application",
)


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical(value: object) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")


def _application() -> Any:
    """Load the required public seam during execution, never collection."""

    try:
        module = importlib.import_module("recon_phaseio_application")
    except ModuleNotFoundError:
        pytest.fail(
            "Cut-4 public closed publisher is absent: expected the bounded "
            "recon_phaseio_application module",
            pytrace=False,
        )
    missing = [name for name in PUBLIC_SURFACE if not callable(getattr(module, name, None))]
    assert not missing, "Cut-4 public publisher surface is incomplete: " + ", ".join(missing)
    return module


def _resolve(work_unit_id: str, *, inputs: tuple[str, ...], outputs: tuple[str, ...]):
    return resolve_phase_io_contract(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        phase="recon",
        work_unit_id=work_unit_id,
        exact_inputs=inputs,
        exact_outputs=outputs,
        exact_writer="DRIVER",
    )


def _paths(contract: object) -> set[str]:
    return {output.identity.split(":", 1)[1] for output in contract.outputs}


def _workspace(tmp_path: Path, *, scanners: bool = False) -> tuple[Path, Path, dict[str, Any]]:
    project = tmp_path / "project"
    scratchpad = tmp_path / "scratchpad"
    project.mkdir(parents=True)
    scratchpad.mkdir(parents=True)
    (project / "Protocol.sol").write_text(
        "pragma solidity ^0.8.20;\n"
        "contract Fixture { uint256 public value; "
        "function set(uint256 x) external { value = x; } }\n",
        encoding="utf-8",
    )
    authorities = {
        "audit_snapshot.json": {"generation": "snapshot-g1"},
        "recon_prepass_source_closure.json": {
            "generation": "source-g1",
            "files": ["Protocol.sol"],
        },
        "recon_prepass_build_root_closure.json": {
            "generation": "build-root-g1",
            "root": str(project.resolve()),
            "profile": "fixture",
            "command": ["forge", "build"],
            "environment": {"FOUNDRY_PROFILE": "default"},
        },
        "recon_prepass_skill_index_authority.json": {"generation": "skills-g1"},
        "recon_prepass_config_authority.json": {
            "generation": "config-g1",
            "scanner_enabled": scanners,
        },
        "recon_prepass_tool_context_authority.json": {
            "generation": "tools-g1",
            "provider": "fixture",
        },
        "recon_prepass_namespace_manifest.json": {
            "generation": "namespace-g1",
            "selected_outputs": sorted(
                {
                    *LOCAL_BASELINE_OUTPUTS,
                    *APPROXIMATE_GRAPH_OUTPUTS,
                    "build_status.md",
                    "recon_prepass_selected_roster.json",
                    "recon_prepass_finalize.json",
                }
            ),
        },
    }
    for name, payload in authorities.items():
        (scratchpad / name).write_bytes(_canonical(payload))
    config = {
        **CONFIG,
        "project_root": str(project),
        "scratchpad": str(scratchpad),
        "prepass_external_scanners": scanners,
    }
    return project, scratchpad, config


def _provider_outcomes(state: str = "APPROXIMATE") -> dict[str, Any]:
    return {
        "graph": {
            "state": state,
            "provider": "fixture-graph",
            "tool": "fixture",
            "reason": f"fixture {state.casefold()}",
        },
        "build": {
            "state": "SKIPPED",
            "provider": "fixture-build",
            "reason": "fixture build is deterministic",
        },
        "scanner": {
            "state": "EXPLICIT_ABSENCE",
            "reason": "scanner switch is false",
        },
    }


def _semantic_snapshot(scratchpad: Path, names: tuple[str, ...]) -> dict[str, str | None]:
    return {
        name: (_sha((scratchpad / name).read_bytes()) if (scratchpad / name).is_file() else None)
        for name in names
    }


def _registered_control(
    scratchpad: Path,
    project: Path,
    *,
    work: str,
    outputs: tuple[str, ...],
) -> tuple[PhaseIOContract, LaunchSpec]:
    key = canonical_work_unit_key("sc", "thorough", "evm", "claude", "recon", work)
    contract = PhaseIOContract(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        phase="recon",
        work_unit_id=work,
        outputs=tuple(
            ArtifactSpec(
                root="scratchpad",
                path=relative,
                owner_key=key,
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                write_mode="CREATE",
                schema_version="fixture.registered-control.v1",
                minimum_gate="EXACT_TYPED_TERMINAL",
            )
            for relative in outputs
        ),
        immutable_inputs=(),
        model_invoked=False,
    )
    launch = LaunchSpec(
        work_unit_key=key,
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        model="deterministic",
        timeout_s=30,
        exec_mode="python",
    )
    AL.record_work_unit_inputs(scratchpad, project, contract, launch, run_id=RUN_ID)
    return contract, launch


def _assert_one_terminal(unit: Mapping[str, Any], expected: set[str] | None = None) -> str:
    terminal = unit.get("terminal_authority")
    assert isinstance(terminal, Mapping), "work unit lacks typed terminal authority"
    assert terminal.get("selected_count") == 1
    states = terminal.get("states")
    assert isinstance(states, list) and len(states) == 1
    state = str(states[0])
    assert state in TERMINAL_STATES
    if expected is not None:
        assert state in expected
    return state


def _assert_full_replay(
    scratchpad: Path,
    result: Mapping[str, Any],
    *,
    expected_inputs: set[str] | None = None,
    expected_outputs: set[str] | None = None,
    expected_terminal: set[str] | None = None,
) -> Mapping[str, Any]:
    key = str(result.get("work_unit_key") or "")
    assert key.startswith("sc/thorough/evm/claude/recon/")
    ledger = AL.read_artifact_ledger(scratchpad)
    unit = ledger.get("work_units", {}).get(key)
    assert isinstance(unit, Mapping), f"missing ArtifactLedger work unit {key}"
    assert unit.get("work_unit_key") == key
    assert unit.get("run_id") == RUN_ID
    assert unit.get("semantic_status") == "ACTIVE"
    assert unit.get("execution_state") == "OUTPUT_COMMITTED"
    assert unit.get("contract_digest") == result.get("contract_digest")
    assert unit.get("launch_digest") == result.get("launch_digest")
    assert isinstance(unit.get("contract_manifest"), Mapping)
    assert isinstance(unit.get("launch_manifest"), Mapping)
    assert isinstance(unit.get("input_set_digest"), str) and len(unit["input_set_digest"]) == 64
    assert isinstance(unit.get("output_prestate_digest"), str) and len(unit["output_prestate_digest"]) == 64
    assert unit.get("publication_generation") == result.get("generation_id")
    if expected_inputs is not None:
        assert set(unit.get("input_bindings", {})) == {
            f"scratchpad:{name}" for name in expected_inputs
        }
    if expected_outputs is not None:
        identities = {f"scratchpad:{name}" for name in expected_outputs}
        assert set(unit.get("output_prestates", {})) == identities
        assert set(unit.get("artifacts", {})) == identities
        commit = unit.get("commit_authority")
        assert isinstance(commit, Mapping)
        assert commit.get("state") == "ACTIVE"
        assert commit.get("work_unit_key") == key
        assert commit.get("run_id") == RUN_ID
        assert commit.get("contract_digest") == unit.get("contract_digest")
        assert commit.get("launch_digest") == unit.get("launch_digest")
        assert set(commit.get("expected_output_records", {})) == identities
        for identity in identities:
            binding = ledger.get("artifact_bindings", {}).get(identity)
            assert isinstance(binding, Mapping)
            assert binding.get("owner_key") == key
            assert binding.get("run_id") == RUN_ID
            assert binding.get("status") == "ACTIVE"
    _assert_one_terminal(unit, expected_terminal)
    return unit


def test_v1_fixtures_remain_byte_frozen_positive_control() -> None:
    expected = {
        "test_phaseio_cut4_recon_prepass_red_20260730.py": (
            "50be6f719bde3c0910b9766fdf682824d5a3d4d4ec26cec86cedc48c4a224f2a"
        ),
        "test_phaseio_cut4_recon_dependency_merge_red_20260730.py": (
            "7abf2efb49123bdcf93732a909ccd0f98f9371688c4bee7a69a5675b970e1bb1"
        ),
    }
    observed = {name: _sha((SCRIPTS / name).read_bytes()) for name in expected}
    assert observed == expected


def test_positive_control_current_prepass_is_still_the_underbound_pair() -> None:
    contract = resolve_phase_io_contract(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        phase="recon",
        work_unit_id="prepass",
    )
    assert _paths(contract) == {"meta_buffer.md", "external_dependency_research.md"}
    assert contract.model_invoked is False


def test_positive_control_typed_tool_debt_is_not_clean_success(tmp_path: Path) -> None:
    project = tmp_path / "project"
    scratchpad = tmp_path / "scratchpad"
    project.mkdir()
    scratchpad.mkdir()
    contract, launch = _registered_control(
        scratchpad,
        project,
        work="control.typed_tool_debt",
        outputs=("tool_coverage_ledger.json", "tool_coverage_ledger.md"),
    )
    outcome = TCL.ToolOutcome.debt(
        "slither.evm-reference-graph",
        "slither",
        TCL.ToolOutcomeState.UNAVAILABLE,
        "fixture provider unavailable",
    )
    TCL.record_tool_outcome(scratchpad, outcome)
    payload = TCL.load_tool_coverage_ledger(scratchpad)
    rows = payload["records"] if isinstance(payload, Mapping) and "records" in payload else payload
    assert rows
    row = next(iter(rows.values())) if isinstance(rows, Mapping) else rows[0]
    assert row.state is TCL.ToolOutcomeState.UNAVAILABLE
    assert row.finding_count is None
    unit = AL.record_work_unit_artifacts(
        scratchpad,
        project,
        contract,
        launch,
        run_id=RUN_ID,
    )
    assert unit["semantic_status"] == "ACTIVE"
    assert unit["execution_state"] == "OUTPUT_COMMITTED"


def test_positive_control_approximate_fallback_retains_precise_tool_debt(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    scratchpad = tmp_path / "scratchpad"
    project.mkdir()
    scratchpad.mkdir()
    contract, launch = _registered_control(
        scratchpad,
        project,
        work="control.typed_approximate_fallback",
        outputs=(
            "_mechanical_graph.json",
            "tool_coverage_ledger.json",
            "tool_coverage_ledger.md",
        ),
    )
    graph = scratchpad / "_mechanical_graph.json"
    graph.write_bytes(_canonical({"schema": "fixture.approximate-graph.v1", "nodes": []}))
    TCL.record_tool_outcome(
        scratchpad,
        TCL.ToolOutcome.debt(
            "slither.evm-reference-graph",
            "slither",
            TCL.ToolOutcomeState.FAILED,
            "precise provider failed before approximate fallback",
        ),
    )
    rows = TCL.load_tool_coverage_ledger(scratchpad)
    assert rows["slither.evm-reference-graph"].state is TCL.ToolOutcomeState.FAILED
    assert json.loads(graph.read_text(encoding="utf-8"))["schema"] == (
        "fixture.approximate-graph.v1"
    )
    assert set(rows) == {"slither.evm-reference-graph"}
    unit = AL.record_work_unit_artifacts(
        scratchpad,
        project,
        contract,
        launch,
        run_id=RUN_ID,
    )
    assert unit["semantic_status"] == "ACTIVE"
    assert unit["execution_state"] == "OUTPUT_COMMITTED"


def test_public_closed_publisher_surface_is_present() -> None:
    app = _application()
    failpoints = getattr(app, "RECON_PUBLICATION_FAILPOINTS", ())
    assert tuple(failpoints) == (
        "AFTER_SOURCE_CAPTURE",
        "AFTER_NAMESPACE_SEAL",
        "AFTER_ARM",
        "AFTER_STAGE",
        "BEFORE_PUBLISH",
        "AFTER_PUBLISH",
        "BEFORE_COMMIT",
        "AFTER_COMMIT",
    )


@pytest.mark.parametrize(
    ("work_unit", "inputs", "outputs"),
    (
        (
            "prepass.roster_capture",
            CAPTURE_INPUTS,
            ("recon_prepass_selected_roster.json",),
        ),
        (
            "prepass.baseline",
            ("recon_prepass_selected_roster.json", "recon_prepass_namespace_manifest.json"),
            LOCAL_BASELINE_OUTPUTS,
        ),
        (
            "prepass.graph_provider.evm.precise",
            ("recon_prepass_selected_roster.json", "recon_prepass_tool_context_authority.json"),
            PRECISE_GRAPH_OUTPUTS,
        ),
        (
            "prepass.graph_provider.evm.approximate",
            ("recon_prepass_selected_roster.json", "recon_prepass_tool_context_authority.json"),
            APPROXIMATE_GRAPH_OUTPUTS,
        ),
        (
            "prepass.graph_provider.evm.debt",
            ("recon_prepass_selected_roster.json", "recon_prepass_tool_context_authority.json"),
            ("tool_coverage_ledger.json", "tool_coverage_ledger.md"),
        ),
        (
            "prepass.build_probe.evm",
            (
                "recon_prepass_selected_roster.json",
                "recon_prepass_build_root_closure.json",
                "recon_prepass_source_closure.json",
                "recon_prepass_tool_context_authority.json",
                "_mechanical_graph_generation.json",
            ),
            ("build_status.md",),
        ),
        (
            "prepass.flag_transform.cross_chain",
            (
                "recon_prepass_selected_roster.json",
                "recon_prepass_flag_cross_chain_source_capture.json",
            ),
            ("template_recommendations.md", "detected_patterns.md", "recon_summary.md"),
        ),
        (
            "prepass.flag_transform.external_dependency",
            (
                "recon_prepass_selected_roster.json",
                "recon_prepass_flag_external_dependency_source_capture.json",
            ),
            ("template_recommendations.md", "detected_patterns.md", "recon_summary.md"),
        ),
        (
            "prepass.scanner.opengrep.success",
            (
                "recon_prepass_selected_roster.json",
                "recon_prepass_config_authority.json",
                "recon_prepass_tool_context_authority.json",
                "recon_prepass_opengrep_rules_authority.json",
            ),
            (
                "opengrep_results.sarif",
                "opengrep_findings.md",
                "tool_coverage_ledger.json",
                "tool_coverage_ledger.md",
            ),
        ),
        (
            "prepass.scanner.opengrep.debt",
            (
                "recon_prepass_selected_roster.json",
                "recon_prepass_config_authority.json",
                "recon_prepass_tool_context_authority.json",
                "recon_prepass_opengrep_rules_authority.json",
            ),
            ("tool_coverage_ledger.json", "tool_coverage_ledger.md"),
        ),
        (
            "prepass.tool_debt_projection",
            ("tool_coverage_ledger.json", "tool_coverage_ledger.md"),
            ("tool_coverage_ledger_repair_required.md",),
        ),
        (
            "prepass.finalize",
            (
                "recon_prepass_selected_roster.json",
                "recon_prepass_namespace_manifest.json",
                "recon_prepass_selected_children.json",
            ),
            ("recon_prepass_finalize.json",),
        ),
    ),
)
def test_prepass_vertical_slice_contracts_are_registered_and_closed(
    work_unit: str,
    inputs: tuple[str, ...],
    outputs: tuple[str, ...],
) -> None:
    contract = _resolve(work_unit, inputs=inputs, outputs=outputs)
    assert _paths(contract) == set(outputs)
    assert set(contract.immutable_inputs) == {f"scratchpad:{name}" for name in inputs}
    assert contract.model_invoked is False
    assert all(output.writer == "DRIVER" for output in contract.outputs)


def test_live_public_prepass_commits_full_selected_subgraph(tmp_path: Path) -> None:
    app = _application()
    _project, scratchpad, config = _workspace(tmp_path)
    result = app.run_prepass(config, provider_outcomes=_provider_outcomes())
    assert isinstance(result, Mapping)
    assert result.get("route") == "prepass"
    assert result.get("selected_roster") == sorted(set(result.get("selected_roster", ())))
    assert set(LOCAL_BASELINE_OUTPUTS).issubset(set(result["selected_roster"]))
    assert set(APPROXIMATE_GRAPH_OUTPUTS).issubset(set(result["selected_roster"]))
    assert set(result.get("children", {})) == set(result.get("selected_children", ()))
    assert result.get("parent_terminal") == "APPLIED"
    for child in result["children"].values():
        _assert_full_replay(scratchpad, child)


def test_existing_public_recon_prepass_entrypoint_executes_closed_publisher(
    tmp_path: Path,
) -> None:
    _project, scratchpad, config = _workspace(tmp_path)
    result = RP.run_recon_prepass(
        config,
        provider_outcomes=_provider_outcomes(),
        failpoint=None,
    )
    assert result["publisher"] == "recon_phaseio_application.publish_recon_plan"
    assert result["applied"] is True
    assert result["parent_terminal"] == "APPLIED"
    ledger = AL.read_artifact_ledger(scratchpad)
    for key in result["work_unit_keys"]:
        assert ledger["work_units"][key]["execution_state"] == "OUTPUT_COMMITTED"


def test_roster_is_armed_before_any_semantic_write(tmp_path: Path) -> None:
    app = _application()
    _project, scratchpad, config = _workspace(tmp_path)
    seen: list[str] = []

    def observe(label: str) -> None:
        seen.append(label)
        if label == "AFTER_ARM":
            assert not any((scratchpad / name).exists() for name in LOCAL_BASELINE_OUTPUTS)

    app.run_prepass(config, provider_outcomes=_provider_outcomes(), failpoint=observe)
    assert seen.index("AFTER_NAMESPACE_SEAL") < seen.index("AFTER_ARM")
    assert seen.index("AFTER_ARM") < seen.index("AFTER_STAGE")


def test_mutation_after_arm_is_rejected_or_published_as_successor(tmp_path: Path) -> None:
    app = _application()
    _project, scratchpad, config = _workspace(tmp_path)

    def mutate(label: str) -> None:
        if label == "AFTER_ARM":
            path = scratchpad / "recon_prepass_source_closure.json"
            path.write_bytes(_canonical({"generation": "source-g2", "files": []}))

    result = app.run_prepass(
        config,
        provider_outcomes=_provider_outcomes(),
        failpoint=mutate,
    )
    assert result["parent_terminal"] in {"REJECTED", "DEBT", "APPLIED"}
    if result["parent_terminal"] == "APPLIED":
        assert result.get("successor_of")
        assert result.get("generation_id") != result.get("armed_generation_id")
    else:
        assert result.get("semantic_writer_count", 0) == 0


def test_unexpected_output_after_namespace_seal_is_not_adopted(tmp_path: Path) -> None:
    app = _application()
    _project, scratchpad, config = _workspace(tmp_path)

    def add_unselected(label: str) -> None:
        if label == "AFTER_NAMESPACE_SEAL":
            (scratchpad / "recon_unselected_surprise.md").write_text(
                "# unselected\n", encoding="utf-8"
            )

    result = app.run_prepass(
        config,
        provider_outcomes=_provider_outcomes(),
        failpoint=add_unselected,
    )
    assert result["parent_terminal"] in {"REJECTED", "DEBT", "QUARANTINED"}
    ledger = AL.read_artifact_ledger(scratchpad)
    assert "scratchpad:recon_unselected_surprise.md" not in ledger.get("artifact_bindings", {})


@pytest.mark.parametrize(
    "provider_state",
    ("PRECISE", "APPROXIMATE", "UNAVAILABLE", "FAILED", "TIMEOUT", "PROVIDER_DRIFT"),
)
def test_graph_provider_matrix_has_one_typed_terminal(
    tmp_path: Path,
    provider_state: str,
) -> None:
    app = _application()
    _project, scratchpad, config = _workspace(tmp_path)
    result = app.run_prepass(
        config,
        provider_outcomes=_provider_outcomes(provider_state),
    )
    graph_children = [
        row for name, row in result["children"].items()
        if "graph_provider.evm" in name
    ]
    assert len(graph_children) == 1
    unit = _assert_full_replay(scratchpad, graph_children[0])
    terminal = _assert_one_terminal(unit)
    if provider_state == "PRECISE":
        assert terminal == "APPLIED"
    elif provider_state == "APPROXIMATE":
        assert terminal == "DRIVER_FALLBACK"
    else:
        assert terminal == "DEBT"


@pytest.mark.parametrize("defect", ("missing_member", "tampered_member", "missing_manifest", "tampered_manifest"))
def test_precise_graph_requires_every_member_and_generation_manifest(
    tmp_path: Path,
    defect: str,
) -> None:
    app = _application()
    _project, scratchpad, config = _workspace(tmp_path)
    outcomes = _provider_outcomes("PRECISE")
    outcomes["graph"]["defect"] = defect
    result = app.run_prepass(config, provider_outcomes=outcomes)
    graph = next(row for name, row in result["children"].items() if "graph_provider.evm" in name)
    unit = _assert_full_replay(scratchpad, graph, expected_terminal={"DEBT", "QUARANTINED"})
    assert unit["commit_authority"]["reason_codes"]


@pytest.mark.parametrize(
    "authority_field",
    ("root", "profile", "source", "tool", "command", "environment"),
)
def test_build_authority_drift_cannot_rebind_armed_generation(
    tmp_path: Path,
    authority_field: str,
) -> None:
    app = _application()
    _project, scratchpad, config = _workspace(tmp_path)
    result = app.run_prepass(
        config,
        provider_outcomes={**_provider_outcomes(), "mutate_after_arm": authority_field},
    )
    build = next(row for name, row in result["children"].items() if "build_probe" in name)
    unit = _assert_full_replay(scratchpad, build)
    state = _assert_one_terminal(unit)
    assert state in {"DEBT", "REJECTED", "QUARANTINED", "APPLIED"}
    if state == "APPLIED":
        assert build.get("successor_of")


@pytest.mark.parametrize("flag", ("cross_chain", "external_dependency"))
def test_flag_transform_rejects_stale_predecessor_bytes(tmp_path: Path, flag: str) -> None:
    app = _application()
    _project, scratchpad, config = _workspace(tmp_path)
    result = app.run_prepass(
        config,
        provider_outcomes={**_provider_outcomes(), "stale_flag_prestate": flag},
    )
    transform = next(row for name, row in result["children"].items() if name.endswith(flag))
    assert transform["terminal_state"] in {"DEBT", "REJECTED", "QUARANTINED"}
    assert not transform.get("rebound_generation", False)


@pytest.mark.parametrize(
    ("scanner_state", "expected"),
    (
        ("SUCCEEDED", "APPLIED"),
        ("UNAVAILABLE", "DEBT"),
        ("FAILED", "DEBT"),
        ("PROVIDER_DRIFT", "DEBT"),
    ),
)
def test_scanner_switch_rules_and_provider_are_typed(
    tmp_path: Path,
    scanner_state: str,
    expected: str,
) -> None:
    app = _application()
    _project, scratchpad, config = _workspace(tmp_path, scanners=True)
    outcomes = _provider_outcomes()
    outcomes["scanner"] = {
        "state": scanner_state,
        "provider": "opengrep-fixture",
        "rules_generation": "rules-g1",
        "reason": "fixture scanner terminal",
    }
    result = app.run_prepass(config, provider_outcomes=outcomes)
    scanner = next(row for name, row in result["children"].items() if "scanner.opengrep" in name)
    assert scanner["terminal_state"] == expected
    unit = _assert_full_replay(scratchpad, scanner, expected_terminal={expected})
    assert "scratchpad:recon_prepass_config_authority.json" in unit["input_bindings"]
    assert "scratchpad:recon_prepass_tool_context_authority.json" in unit["input_bindings"]


@pytest.mark.parametrize(
    "failpoint",
    (
        "AFTER_SOURCE_CAPTURE",
        "AFTER_NAMESPACE_SEAL",
        "AFTER_ARM",
        *(f"AFTER_STAGE:{name}" for name in LOCAL_BASELINE_OUTPUTS),
        "BEFORE_PUBLISH",
        *(f"AFTER_PUBLISH:{name}" for name in LOCAL_BASELINE_OUTPUTS),
        "BEFORE_COMMIT",
        "AFTER_COMMIT",
    ),
)
def test_named_publication_failpoints_recover_without_mixed_adoption(
    tmp_path: Path,
    failpoint: str,
) -> None:
    app = _application()
    _project, scratchpad, config = _workspace(tmp_path)
    fired = False

    class InjectedCrash(RuntimeError):
        pass

    def crash(label: str) -> None:
        nonlocal fired
        if not fired and label == failpoint:
            fired = True
            raise InjectedCrash(label)

    before = _semantic_snapshot(scratchpad, LOCAL_BASELINE_OUTPUTS)
    with pytest.raises(InjectedCrash, match=failpoint.split(":", 1)[0]):
        app.run_prepass(
            config,
            provider_outcomes=_provider_outcomes(),
            failpoint=crash,
        )
    assert fired, f"public publisher did not emit named failpoint {failpoint}"
    ledger = AL.read_artifact_ledger(scratchpad)
    pending = ledger.get("recon_publication_journal", {})
    assert pending, "crash lacks durable quarantine/roll-forward authority"
    assert pending.get("state") in {"STAGED", "ROLL_FORWARD", "QUARANTINED", "COMMITTED"}

    recovered = app.recover_recon_publications(config, route="prepass")
    assert recovered["terminal_state"] in {"APPLIED", "QUARANTINED", "DEBT"}
    after = _semantic_snapshot(scratchpad, LOCAL_BASELINE_OUTPUTS)
    changed = {name for name in before if before[name] != after[name]}
    assert changed in (set(), set(LOCAL_BASELINE_OUTPUTS))


def test_exact_retry_reuses_real_committed_generation_with_zero_semantic_writer(
    tmp_path: Path,
) -> None:
    app = _application()
    _project, scratchpad, config = _workspace(tmp_path)
    first = app.run_prepass(config, provider_outcomes=_provider_outcomes())
    assert first["parent_terminal"] == "APPLIED"
    generation = first["generation_id"]
    before = _semantic_snapshot(scratchpad, tuple(first["selected_roster"]))
    calls = 0

    def forbidden_provider(*_args: object, **_kwargs: object) -> Mapping[str, Any]:
        nonlocal calls
        calls += 1
        raise AssertionError("exact retry invoked a semantic provider")

    second = app.run_prepass(
        config,
        provider_outcomes=_provider_outcomes(),
        semantic_provider=forbidden_provider,
    )
    assert calls == 0
    assert second["terminal_state"] == "REUSED_COMMITTED_GENERATION"
    assert second["generation_id"] == generation
    assert second["semantic_writer_count"] == 0
    assert _semantic_snapshot(scratchpad, tuple(first["selected_roster"])) == before
    final_unit = _assert_full_replay(scratchpad, second)
    assert final_unit["commit_authority"]["state"] == "ACTIVE"


@pytest.mark.parametrize(
    "route",
    ("prepass", "pty", "headless", "startup_resume", "validation_fallback", "instantiate", "breadth"),
)
def test_every_recon_route_executes_the_registered_authority_boundary(
    tmp_path: Path,
    route: str,
) -> None:
    app = _application()
    _project, scratchpad, config = _workspace(tmp_path / route)
    result = app.recon_route_application(
        route,
        config=config,
        provider_outcomes=_provider_outcomes(),
    )
    assert result["route"] == route
    assert result["publisher"] == "recon_phaseio_application.publish_recon_plan"
    assert result["applied"] is True
    assert result["work_unit_keys"]
    ledger = AL.read_artifact_ledger(scratchpad)
    for key in result["work_unit_keys"]:
        assert key in ledger.get("work_units", {})


@pytest.mark.parametrize("ecosystem", ("solana", "aptos", "sui", "soroban", "daml"))
def test_deferred_ecosystems_are_closed_nonlocal_debt_not_local_success(ecosystem: str) -> None:
    contract = resolve_phase_io_contract(
        pipeline="sc",
        mode="thorough",
        ecosystem=ecosystem,
        backend="claude",
        phase="recon",
        work_unit_id="prepass.roster_capture.nonlocal_debt",
        exact_inputs=CAPTURE_INPUTS,
        exact_outputs=("recon_prepass_selected_roster.json",),
        exact_writer="DRIVER",
    )
    output = contract.outputs[0]
    assert output.writer == "DRIVER"
    assert output.schema_version == "plamen.recon_prepass_roster.v2"
    assert "DEBT" in output.minimum_gate.upper()
