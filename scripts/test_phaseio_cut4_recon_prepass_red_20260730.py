"""Fixture-first RED denominator for PhaseIO Cut-4 recon prepass.

The accepted Cut-4 specification requires a selected, closed prepass subgraph
instead of the current two-output ``recon/prepass`` receipt.  These fixtures
exercise the public resolver and live prepass entrypoint.  They deliberately
fail the 2026-08-09 production bytes because roster capture, branch-specific
children, crash debt, and finalize authority are not yet registered/applied.

This module does not prescribe model reasoning, finding semantics, or a second
ledger.  ArtifactLedger remains the only completion authority.
"""
from __future__ import annotations

import json
from pathlib import Path
import sys

import pytest


SCRIPTS = Path(__file__).resolve().parent
ROOT = SCRIPTS.parent
sys.path.insert(0, str(SCRIPTS))
sys.path.insert(0, str(ROOT))

import artifact_ledger as AL  # noqa: E402
import plamen_driver as D  # noqa: E402
import recon_prepass as RP  # noqa: E402
from phase_io_contracts import resolve_phase_io_contract  # noqa: E402


CONFIG = {
    "pipeline": "sc",
    "mode": "thorough",
    "language": "evm",
    "cli_backend": "claude",
    "run_id": "cut4-recon-red",
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

CAPTURE_INPUTS = (
    "audit_snapshot.json",
    "recon_prepass_source_closure.json",
    "recon_prepass_build_root_closure.json",
    "recon_prepass_skill_index_authority.json",
    "recon_prepass_config_authority.json",
    "recon_prepass_tool_context_authority.json",
)


def _resolve(work_unit_id: str, *, inputs=(), outputs=(), ecosystem="evm"):
    return resolve_phase_io_contract(
        pipeline="sc",
        mode="thorough",
        ecosystem=ecosystem,
        backend="claude",
        phase="recon",
        work_unit_id=work_unit_id,
        exact_inputs=tuple(inputs),
        exact_outputs=tuple(outputs),
        exact_writer="DRIVER",
    )


def _output_paths(contract: object) -> set[str]:
    return {
        output.identity.split(":", 1)[1]
        for output in contract.outputs
    }


def _semantic_files(root: Path) -> set[str]:
    return {
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file()
        and path.name != AL.LEDGER_NAME
        and not path.name.startswith(".phaseio-")
    }


def _fast_local_evm_prepass(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[Path, Path, dict[str, str]]:
    """Run the real coordinator without invoking external tools.

    Pure parsers and routing transforms remain live.  Only the provider/build
    leaves are replaced with deterministic fixture writers, which keeps this
    an application test rather than a source-text assertion.
    """

    project = tmp_path / "project"
    scratchpad = tmp_path / "scratchpad"
    project.mkdir()
    scratchpad.mkdir()
    (project / "Protocol.sol").write_text(
        "pragma solidity ^0.8.20;\n"
        "contract Fixture { uint256 public value; function set(uint256 x) "
        "external { value = x; } }\n",
        encoding="utf-8",
    )

    monkeypatch.setattr(
        RP,
        "build_tool_execution_context",
        lambda *_args, **_kwargs: None,
    )

    def graph_leaf(scratch: Path, _project: Path, *, context=None) -> str:
        del context
        graph = scratch / "_mechanical_graph.json"
        generation = scratch / "_mechanical_graph_generation.json"
        graph.write_text('{"schema":"fixture.graph.v1","nodes":[]}\n', encoding="utf-8")
        generation.write_text(
            '{"schema":"fixture.graph-generation.v1","provider":"fixture"}\n',
            encoding="utf-8",
        )
        return "APPROXIMATE:fixture"

    def build_leaf(
        scratch: Path,
        _project: Path,
        _language: str,
        _graph_status: object,
    ) -> str:
        RP._write_text(
            scratch / "build_status.md",
            "# Build Status\n\nStatus: SKIPPED_FIXTURE\n",
        )
        return "SKIPPED_FIXTURE"

    monkeypatch.setattr(RP, "_bake_evm_graph", graph_leaf)
    monkeypatch.setattr(RP, "_write_build_status", build_leaf)
    config = {
        **CONFIG,
        "project_root": str(project),
        "scratchpad": str(scratchpad),
        "prepass_external_scanners": False,
    }
    result = RP.run_recon_prepass(config)
    return project, scratchpad, result


def test_positive_control_current_prepass_contract_is_only_its_declared_pair() -> None:
    """The RED is underbinding, not a malformed assertion about current bytes."""

    contract = _resolve("prepass")
    assert contract.model_invoked is False
    assert _output_paths(contract) == {
        "meta_buffer.md",
        "external_dependency_research.md",
    }
    assert {output.writer for output in contract.outputs} == {"DRIVER"}


def test_live_local_evm_prepass_publishes_a_closed_selected_roster(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """All live writes must be named before the first semantic publication."""

    _project, scratchpad, result = _fast_local_evm_prepass(tmp_path, monkeypatch)
    observed = _semantic_files(scratchpad)
    # Positive controls: the fixture actually exercised the conditional fanout.
    assert set(LOCAL_BASELINE_OUTPUTS).issubset(observed)
    assert result["contract_inventory.md"] == "WRITTEN"
    assert "_mechanical_graph.json" in observed

    roster_path = scratchpad / "recon_prepass_selected_roster.json"
    assert roster_path.is_file(), (
        "missing roster_capture application: current live prepass writes many "
        "semantic files while recon/prepass declares only two"
    )
    roster = json.loads(roster_path.read_text(encoding="utf-8"))
    assert set(roster["selected_outputs"]) == observed - {roster_path.name}
    assert roster["pipeline"] == "sc"
    assert roster["ecosystem"] == "evm"
    assert roster["backend"] == "claude"


def test_prepass_roster_capture_binds_every_branch_authority() -> None:
    """Source/config/tool drift must change a captured generation, not leak in."""

    contract = _resolve(
        "prepass.roster_capture",
        inputs=CAPTURE_INPUTS,
        outputs=("recon_prepass_selected_roster.json",),
    )
    assert _output_paths(contract) == {"recon_prepass_selected_roster.json"}
    assert set(contract.immutable_inputs) == {
        f"scratchpad:{name}" for name in CAPTURE_INPUTS
    }
    assert contract.model_invoked is False


def test_prepass_baseline_is_a_closed_driver_child() -> None:
    """Baseline enumeration/context/routing cannot hide wildcard writes."""

    contract = _resolve(
        "prepass.baseline",
        inputs=("recon_prepass_selected_roster.json",),
        outputs=LOCAL_BASELINE_OUTPUTS,
    )
    assert _output_paths(contract) == set(LOCAL_BASELINE_OUTPUTS)
    assert all(output.writer == "DRIVER" for output in contract.outputs)
    assert contract.model_invoked is False


@pytest.mark.parametrize(
    ("branch", "outputs"),
    (
        (
            "prepass.graph_provider.evm.precise",
            (
                "caller_map.md",
                "callee_map.md",
                "state_write_map.md",
                "function_summary.md",
                "_mechanical_graph.json",
                "_mechanical_graph_generation.json",
                "tool_coverage_ledger.json",
                "tool_coverage_ledger.md",
            ),
        ),
        (
            "prepass.graph_provider.evm.approximate",
            (
                "_mechanical_graph.json",
                "_mechanical_graph_generation.json",
                "tool_coverage_ledger.json",
                "tool_coverage_ledger.md",
            ),
        ),
        (
            "prepass.graph_provider.evm.unavailable",
            (
                "tool_coverage_ledger.json",
                "tool_coverage_ledger.md",
            ),
        ),
    ),
)
def test_graph_provider_terminal_branches_are_distinct_and_closed(
    branch: str,
    outputs: tuple[str, ...],
) -> None:
    contract = _resolve(
        branch,
        inputs=(
            "recon_prepass_selected_roster.json",
            "recon_prepass_tool_context_authority.json",
        ),
        outputs=outputs,
    )
    assert _output_paths(contract) == set(outputs)
    assert contract.model_invoked is False


def test_build_probe_binds_root_profile_source_tool_and_graph_authority() -> None:
    required = (
        "recon_prepass_selected_roster.json",
        "recon_prepass_build_root_closure.json",
        "recon_prepass_source_closure.json",
        "recon_prepass_tool_context_authority.json",
        "_mechanical_graph_generation.json",
    )
    contract = _resolve(
        "prepass.build_probe.evm",
        inputs=required,
        outputs=("build_status.md",),
    )
    assert set(contract.immutable_inputs) == {
        f"scratchpad:{name}" for name in required
    }
    assert _output_paths(contract) == {"build_status.md"}


@pytest.mark.parametrize(
    "flag_name",
    ("cross_chain", "external_dependency"),
)
def test_flag_transform_has_captured_prestate_and_successor_generation(
    flag_name: str,
) -> None:
    source = f"recon_prepass_flag_{flag_name}_source_capture.json"
    contract = _resolve(
        f"prepass.flag_transform.{flag_name}",
        inputs=("recon_prepass_selected_roster.json", source),
        outputs=(
            "template_recommendations.md",
            "detected_patterns.md",
            "recon_summary.md",
        ),
    )
    assert f"scratchpad:{source}" in contract.immutable_inputs
    assert _output_paths(contract) == {
        "template_recommendations.md",
        "detected_patterns.md",
        "recon_summary.md",
    }
    assert contract.model_invoked is False


def test_scanner_branch_is_selected_by_captured_switch_and_provider() -> None:
    inputs = (
        "recon_prepass_selected_roster.json",
        "recon_prepass_config_authority.json",
        "recon_prepass_tool_context_authority.json",
        "recon_prepass_opengrep_rules_authority.json",
    )
    outputs = (
        "opengrep_results.sarif",
        "opengrep_findings.md",
        "tool_coverage_ledger.json",
        "tool_coverage_ledger.md",
    )
    contract = _resolve(
        "prepass.scanner.opengrep",
        inputs=inputs,
        outputs=outputs,
    )
    assert set(contract.immutable_inputs) == {
        f"scratchpad:{name}" for name in inputs
    }
    assert _output_paths(contract) == set(outputs)


def test_prepass_finalize_binds_complete_selected_child_roster() -> None:
    children = (
        "recon_prepass_selected_roster.json",
        *LOCAL_BASELINE_OUTPUTS,
        "_mechanical_graph.json",
        "_mechanical_graph_generation.json",
        "tool_coverage_ledger.json",
        "tool_coverage_ledger.md",
        "build_status.md",
    )
    contract = _resolve(
        "prepass.finalize",
        inputs=children,
        outputs=("recon_prepass_finalize.json",),
    )
    assert set(contract.immutable_inputs) == {
        f"scratchpad:{name}" for name in children
    }
    assert _output_paths(contract) == {"recon_prepass_finalize.json"}


@pytest.mark.parametrize(
    "ecosystem",
    ("solana", "aptos", "sui", "soroban", "daml"),
)
def test_deferred_sc_ecosystems_have_closed_roster_schema_not_local_success(
    ecosystem: str,
) -> None:
    """Schema parity is required; these branches remain explicit nonlocal debt."""

    contract = _resolve(
        "prepass.roster_capture",
        inputs=CAPTURE_INPUTS,
        outputs=("recon_prepass_selected_roster.json",),
        ecosystem=ecosystem,
    )
    spec = contract.outputs[0]
    assert spec.schema_version == "plamen.recon_prepass_roster.v1"
    assert spec.writer == "DRIVER"


def test_prepass_crash_cannot_leave_unowned_public_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A partial public write must quarantine or create durable typed debt."""

    original = Path.write_text
    writes = {"count": 0}

    def fail_after_partial(self: Path, data: str, *args, **kwargs):
        if self.parent.name == "scratchpad":
            writes["count"] += 1
            if writes["count"] == 4:
                original(self, "fixture-partial-public-byte\n", encoding="utf-8")
                raise OSError("cut4 fixture crash after public write")
        return original(self, data, *args, **kwargs)

    monkeypatch.setattr(Path, "write_text", fail_after_partial)
    _project, scratchpad, result = _fast_local_evm_prepass(tmp_path, monkeypatch)
    assert writes["count"] >= 4
    assert any("FAILED" in str(value) for value in result.values())

    ledger_path = scratchpad / AL.LEDGER_NAME
    assert ledger_path.is_file(), (
        "prepass crash left semantic bytes without durable ArtifactLedger debt"
    )
    ledger = AL.read_artifact_ledger(scratchpad)
    recon_units = [
        unit for key, unit in ledger.get("work_units", {}).items()
        if "/recon/prepass." in key
    ]
    assert recon_units
    assert any(
        unit.get("semantic_status") in {"QUARANTINED", "STALE_INPUT"}
        or unit.get("execution_state") == "OUTPUT_QUARANTINED"
        for unit in recon_units
    )


def test_exact_prepass_resume_reuses_committed_generation_without_rewrite(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An exact retry revalidates a committed child instead of re-running writers."""

    _project, scratchpad, first = _fast_local_evm_prepass(tmp_path, monkeypatch)
    assert first["contract_inventory.md"] == "WRITTEN"
    assert (scratchpad / "contract_inventory.md").is_file()

    called = {"count": 0}

    def forbidden_rewrite(*_args, **_kwargs) -> str:
        called["count"] += 1
        raise AssertionError("committed prepass generation was rewritten")

    monkeypatch.setattr(RP, "_write_contract_inventory_sc", forbidden_rewrite)
    config = {
        **CONFIG,
        "project_root": str(tmp_path / "project"),
        "scratchpad": str(scratchpad),
        "prepass_external_scanners": False,
    }
    second = RP.run_recon_prepass(config)
    assert called["count"] == 0
    assert second.get("_phaseio_resume") == "REUSED_COMMITTED_GENERATION"
    ledger = AL.read_artifact_ledger(scratchpad)
    committed = [
        unit for key, unit in ledger.get("work_units", {}).items()
        if "/recon/prepass.finalize" in key
        and unit.get("semantic_status") == "ACTIVE"
        and unit.get("execution_state") == "OUTPUT_COMMITTED"
    ]
    assert len(committed) == 1


def test_instantiate_binds_prepass_finalize_and_supplementary_disposition(
    tmp_path: Path,
) -> None:
    """Downstream file existence cannot replace exact producer generations."""

    required = (
        "skill_selection_catalog.json",
        "template_recommendations.md",
        "detected_patterns.md",
        "design_context.md",
        "attack_surface.md",
        "contract_inventory.md",
        "function_list.md",
        "state_variables.md",
        "recon_prepass_finalize.json",
        "recon_supplementary_disposition.json",
    )
    for name in required:
        (tmp_path / name).write_text("{}\n" if name.endswith(".json") else "# fixture\n", encoding="utf-8")
    selected = set(D._instantiate_exact_inputs(tmp_path))
    assert set(required).issubset(selected)
