"""Adversarial contracts for the Toolchain R5 authority cutover.

All fixtures are local and synthetic.  They do not install or execute a real
provider, contact a registry, launch a backend, or run an audit.
"""

from __future__ import annotations

import ast
import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

import assurance_limitations as ASSURANCE
import plamen as INSTALLER
import plamen_driver as DRIVER
import plamen_mechanical as MECHANICAL
import recon_prepass as RECON
import tool_coverage_ledger as LEDGER
import toolchain_control_authority as CONTROL
from enumeration_type_ir import build_function_signature_fact


_GRAPH_ARTIFACTS = (
    "caller_map.md",
    "callee_map.md",
    "state_write_map.md",
    "function_summary.md",
    "_mechanical_graph.json",
)


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(
        (
            json.dumps(
                value,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("utf-8")
    ).hexdigest()


def _authority(tool_id: str) -> dict[str, object]:
    unsigned = {
        "schema": "plamen.runtime-tool-identity.v2",
        "tool_id": tool_id,
        "identity_kind": (
            "python_distribution"
            if tool_id == "protobuf"
            else "command"
        ),
        "authority_status": "MATCH",
        "deterministic_provider_authority": True,
        "toolchain_version_lock_sha256": "1" * 64,
        "toolchain_governance_sha256": "2" * 64,
    }
    return {
        **unsigned,
        "authority_digest": hashlib.sha256(
            json.dumps(
                unsigned,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest(),
    }


def _context(ecosystem: str = "go") -> dict[str, str]:
    return {
        "run_id": "toolchain-r5-fixture",
        "phase": "recon-prebreadth",
        "snapshot_sha256": "3" * 64,
        "project_root_sha256": "4" * 64,
        "ecosystem": ecosystem,
        "pipeline": "l1",
        "mode": "thorough",
        "platform": "windows",
    }


def _graph_payload(ecosystem: str, identity: str = "shared") -> dict:
    source = f"scip-{ecosystem}"
    fact = build_function_signature_fact(
        ecosystem=ecosystem,
        provider=source,
        function_identity=identity,
        bare_name=identity,
        provider_symbol=f"{source} fixture {identity}()",
        raw_signature="",
        source_path=f"{ecosystem}/main.{ecosystem}",
        source_line=1,
        source_sha256="",
        kind="Function",
        authority="PROVIDER_IDENTITY_ONLY",
    )
    return {
        "schema_version": "plamen.mechanical_graph.v2",
        "function_signature_schema": "plamen.function_signature_fact.v1",
        "source": source,
        "state_symbols": [],
        "var_refs": {},
        "functions": {
            identity: {
                "bare": identity,
                "loc": f"{ecosystem}/main.{ecosystem}:L1",
                "callers": [],
                "callees": [],
                "signature_fact": fact,
            }
        },
        "function_signatures": {identity: fact},
    }


def _write_graph_set(root: Path, ecosystem: str) -> None:
    root.mkdir(parents=True, exist_ok=True)
    for name in _GRAPH_ARTIFACTS[:-1]:
        (root / name).write_text(
            f"# {name}\n\nprovider={ecosystem}\n",
            encoding="utf-8",
        )
    (root / "_mechanical_graph.json").write_text(
        json.dumps(_graph_payload(ecosystem), sort_keys=True),
        encoding="utf-8",
    )
    (root / RECON._GRAPH_GENERATION_MANIFEST).write_text(
        json.dumps(
            RECON._graph_generation_manifest(
                RECON._graph_artifact_evidence(root)
            ),
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


def test_real_capture_control_digest_keys_are_preserved() -> None:
    encoded = RECON._graph_provider_ref(_authority("scip-go"))
    decoded = json.loads(encoded)
    assert decoded["toolchain_version_lock_sha256"] == "1" * 64
    assert decoded["toolchain_governance_sha256"] == "2" * 64
    assert "lock_sha256" not in decoded
    assert "governance_sha256" not in decoded


def test_capability_id_and_provider_boolean_cannot_mint_graph_success(
    tmp_path: Path,
) -> None:
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    (scratch / "caller_map.md").write_text("# partial\n", encoding="utf-8")

    RECON._record_precise_graph_outcome(
        scratch,
        capability_id="scip-go.reference-graph",
        tool="scip-go",
        status="WRITTEN",
        authority=_authority("scip-go"),
    )

    outcome = LEDGER.load_tool_coverage_ledger(scratch)[
        "scip-go.reference-graph"
    ]
    assert outcome.state is not LEDGER.ToolOutcomeState.SUCCEEDED
    assert (
        "CONTEXT" in outcome.reason.upper()
        or "ARTIFACT" in outcome.reason.upper()
        or "CONTROL" in outcome.reason.upper()
    )


def test_context_bound_envelope_replays_artifacts_and_rejects_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scratch = tmp_path / "scratch"
    _write_graph_set(scratch, "go")
    controls = SimpleNamespace(
        lock_sha256="1" * 64,
        governance_sha256="2" * 64,
    )
    governance = LEDGER.load_toolchain_governance(
        Path(__file__).resolve().parents[1]
        / "verification_policy"
        / "toolchain_governance.v1.json"
    )
    monkeypatch.setattr(
        CONTROL,
        "load_toolchain_controls",
        lambda *_args, **_kwargs: controls,
    )
    monkeypatch.setattr(
        LEDGER,
        "load_toolchain_governance",
        lambda *_args, **_kwargs: governance,
    )

    envelope = LEDGER.build_context_bound_tool_outcome_envelope(
        scratch,
        capability_id="scip-go.reference-graph",
        tool="scip-go",
        authority=_authority("scip-go"),
        context=_context(),
        artifacts=_GRAPH_ARTIFACTS,
    )
    assert LEDGER.replay_context_bound_tool_outcome_envelope(
        scratch,
        envelope,
    ) == []

    (scratch / "caller_map.md").write_text("# drift\n", encoding="utf-8")
    issues = LEDGER.replay_context_bound_tool_outcome_envelope(
        scratch,
        envelope,
    )
    assert any("artifact" in issue.lower() and "drift" in issue.lower()
               for issue in issues)


def test_ledger_load_replays_graph_artifacts_not_only_envelope_prose(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scratch = tmp_path / "scratch"
    _write_graph_set(scratch, "go")
    controls = SimpleNamespace(
        lock_sha256="1" * 64,
        governance_sha256="2" * 64,
    )
    governance = LEDGER.load_toolchain_governance(
        Path(__file__).resolve().parents[1]
        / "verification_policy"
        / "toolchain_governance.v1.json"
    )
    monkeypatch.setattr(
        CONTROL,
        "load_toolchain_controls",
        lambda *_args, **_kwargs: controls,
    )
    monkeypatch.setattr(
        LEDGER,
        "load_toolchain_governance",
        lambda *_args, **_kwargs: governance,
    )
    envelope = LEDGER.build_context_bound_tool_outcome_envelope(
        scratch,
        capability_id="scip-go.reference-graph",
        tool="scip-go",
        authority=_authority("scip-go"),
        context=_context(),
        artifacts=_GRAPH_ARTIFACTS,
    )
    LEDGER.record_tool_outcome(
        scratch,
        LEDGER.ToolOutcome.succeeded(
            "scip-go.reference-graph",
            "scip-go",
            0,
            artifacts=_GRAPH_ARTIFACTS,
            provider_ref=json.dumps(
                envelope,
                sort_keys=True,
                separators=(",", ":"),
            ),
        ),
    )
    (scratch / "callee_map.md").write_text(
        "# post-receipt drift\n",
        encoding="utf-8",
    )
    with pytest.raises(
        LEDGER.ToolCoverageLedgerError,
        match="does not replay",
    ):
        LEDGER.load_tool_coverage_ledger(scratch)


def test_graph_set_publication_is_complete_or_rolls_back(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stage = tmp_path / "stage"
    destination = tmp_path / "scratch"
    _write_graph_set(stage, "go")
    _write_graph_set(destination, "rust")
    before = {
        name: (destination / name).read_bytes()
        for name in _GRAPH_ARTIFACTS
    }
    real_replace = RECON.os.replace

    def fail_graph(source, target):
        if Path(target).name == "_mechanical_graph.json":
            raise OSError("synthetic graph publication failure")
        return real_replace(source, target)

    monkeypatch.setattr(RECON.os, "replace", fail_graph)
    status, _artifacts = RECON._validate_and_publish_graph_artifact_set(
        stage,
        destination,
    )
    assert status.startswith("FAILED:ARTIFACT_PUBLICATION")
    assert {
        name: (destination / name).read_bytes()
        for name in _GRAPH_ARTIFACTS
    } == before


def test_slither_graph_json_write_failure_cannot_return_precise_written(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scratch = tmp_path / "scratch"
    project = tmp_path / "project"
    scratch.mkdir()
    project.mkdir()
    observed: list[str] = []

    def incomplete(stage: Path, _project: Path) -> str:
        for name in _GRAPH_ARTIFACTS[:-1]:
            (Path(stage) / name).write_text(
                "# staged partial\n",
                encoding="utf-8",
            )
        return "WRITTEN"

    monkeypatch.setattr(RECON, "_bake_evm_slither_graph", incomplete)
    monkeypatch.setattr(
        RECON,
        "_record_precise_graph_outcome",
        lambda _scratch, **kwargs: observed.append(str(kwargs["status"])),
    )
    result = RECON._bake_evm_graph(scratch, project)
    assert result.startswith("FAILED:")
    assert len(observed) == 1
    assert observed[0].startswith("FAILED:ARTIFACT_STAGE:")


def test_mixed_go_rust_graphs_are_namespaced_and_merged(
    tmp_path: Path,
) -> None:
    scratch = tmp_path / "scratch"
    _write_graph_set(scratch / "_graph_providers" / "go", "go")
    _write_graph_set(scratch / "_graph_providers" / "rust", "rust")

    status = RECON._merge_namespaced_graph_artifacts(
        scratch,
        ecosystems=("go", "rust"),
    )
    assert status == "WRITTEN:mixed"
    graph = json.loads(
        (scratch / "_mechanical_graph.json").read_text(encoding="utf-8")
    )
    assert set(graph["functions"]) == {"go::shared", "rust::shared"}
    assert set(graph["function_signatures"]) == {
        "go::shared",
        "rust::shared",
    }
    caller_map = (scratch / "caller_map.md").read_text(encoding="utf-8")
    assert "provider=go" in caller_map
    assert "provider=rust" in caller_map


def test_mixed_l1_execution_invokes_both_providers_before_merge(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    def graph(label: str):
        def invoke(scratch, _project, **_kwargs):
            calls.append(label)
            _write_graph_set(Path(scratch), label)
            return f"WRITTEN:{label}"

        return invoke

    monkeypatch.setattr(DRIVER, "_bake_go_reference_graph", graph("go"))
    monkeypatch.setattr(DRIVER, "_bake_rust_reference_graph", graph("rust"))
    monkeypatch.setattr(
        RECON,
        "_record_mixed_graph_outcomes",
        lambda *_args, **_kwargs: None,
    )
    result = DRIVER._run_l1_reference_graph_capabilities(
        tmp_path / "scratch",
        tmp_path / "project",
        language="mixed",
        context=_context("mixed"),
    )
    assert calls == ["go", "rust"]
    assert result["merge"] == "WRITTEN:mixed"


def test_driver_graph_context_binds_current_run_snapshot_and_project(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    context = DRIVER._toolchain_graph_execution_context(
        {
            "_run_id": "run-r5",
            "_audit_snapshot": {"snapshot_digest": "a" * 64},
            "project_root": str(project),
            "language": "go",
            "pipeline": "l1",
            "mode": "thorough",
        },
        phase="recon-prebreadth",
    )
    expected_project = os.path.normcase(
        str(project.resolve())
    ).replace("\\", "/")
    expected_platform = (
        "windows"
        if DRIVER.sys.platform == "win32"
        else "macos"
        if DRIVER.sys.platform == "darwin"
        else "linux"
        if DRIVER.sys.platform.startswith("linux")
        else DRIVER.sys.platform
    )
    assert context == {
        "run_id": "run-r5",
        "phase": "recon-prebreadth",
        "snapshot_sha256": "a" * 64,
        "project_root_sha256": hashlib.sha256(
            expected_project.encode("utf-8")
        ).hexdigest(),
        "ecosystem": "go",
        "pipeline": "l1",
        "mode": "thorough",
        "platform": expected_platform,
    }


def test_mixed_status_string_without_lane_receipt_cannot_mint_success(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scratch = tmp_path / "scratch"
    project = tmp_path / "project"
    _write_graph_set(scratch, "go")
    project.mkdir()
    monkeypatch.setattr(
        RECON,
        "_capture_command_provider_authority",
        lambda tool, *_args, **_kwargs: _authority(tool),
    )
    monkeypatch.setattr(
        RECON,
        "_capture_python_provider_authority",
        lambda tool, **_kwargs: _authority(tool),
    )
    RECON._record_mixed_graph_outcomes(
        scratch,
        project,
        statuses={
            "go": "WRITTEN:scip",
            "rust": "SKIPPED:fixture",
            "merge": "WRITTEN:mixed",
        },
        context=_context("mixed"),
    )
    outcome = LEDGER.load_tool_coverage_ledger(scratch)[
        "scip-go.reference-graph"
    ]
    assert outcome.state is not LEDGER.ToolOutcomeState.SUCCEEDED
    assert "FALLBACK" in outcome.reason


def test_mixed_projection_binds_and_replays_lane_ledger(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scratch = tmp_path / "scratch"
    project = tmp_path / "project"
    lane = scratch / "_graph_providers" / "go"
    _write_graph_set(lane, "go")
    _write_graph_set(scratch, "go")
    project.mkdir()
    controls = SimpleNamespace(
        lock_sha256="1" * 64,
        governance_sha256="2" * 64,
    )
    governance = LEDGER.load_toolchain_governance(
        Path(__file__).resolve().parents[1]
        / "verification_policy"
        / "toolchain_governance.v1.json"
    )
    monkeypatch.setattr(
        CONTROL,
        "load_toolchain_controls",
        lambda *_args, **_kwargs: controls,
    )
    monkeypatch.setattr(
        LEDGER,
        "load_toolchain_governance",
        lambda *_args, **_kwargs: governance,
    )
    monkeypatch.setattr(
        RECON,
        "_capture_command_provider_authority",
        lambda tool, *_args, **_kwargs: _authority(tool),
    )
    monkeypatch.setattr(
        RECON,
        "_capture_python_provider_authority",
        lambda tool, **_kwargs: _authority(tool),
    )
    for capability_id, tool in (
        ("protobuf.scip-graph-parser", "protobuf"),
        ("scip-go.reference-graph", "scip-go"),
    ):
        envelope = LEDGER.build_context_bound_tool_outcome_envelope(
            lane,
            capability_id=capability_id,
            tool=tool,
            authority=_authority(tool),
            context=_context("go"),
            artifacts=_GRAPH_ARTIFACTS,
        )
        LEDGER.record_tool_outcome(
            lane,
            LEDGER.ToolOutcome.succeeded(
                capability_id,
                tool,
                0,
                artifacts=_GRAPH_ARTIFACTS,
                provider_ref=json.dumps(
                    envelope,
                    sort_keys=True,
                    separators=(",", ":"),
                ),
            ),
        )

    RECON._record_mixed_graph_outcomes(
        scratch,
        project,
        statuses={
            "go": "WRITTEN:scip",
            "rust": "SKIPPED:fixture",
            "merge": "WRITTEN:mixed",
        },
        context=_context("mixed"),
    )
    root_outcomes = LEDGER.load_tool_coverage_ledger(
        scratch,
        expected_context=_context("mixed"),
    )
    assert (
        root_outcomes["scip-go.reference-graph"].state
        is LEDGER.ToolOutcomeState.SUCCEEDED
    )
    assert (
        root_outcomes["protobuf.scip-graph-parser"].state
        is LEDGER.ToolOutcomeState.SUCCEEDED
    )
    (lane / "caller_map.md").write_text(
        "# lane drift\n",
        encoding="utf-8",
    )
    with pytest.raises(
        LEDGER.ToolCoverageLedgerError,
        match="does not replay",
    ):
        LEDGER.load_tool_coverage_ledger(scratch)


def test_unresolved_tool_debt_reaches_phase_assurance_and_report_consumer(
    tmp_path: Path,
) -> None:
    scratch = tmp_path / "scratch"
    LEDGER.record_tool_outcome(
        scratch,
        LEDGER.ToolOutcome.debt(
            "scip-go.reference-graph",
            "scip-go",
            LEDGER.ToolOutcomeState.UNAVAILABLE,
            "fixture provider unavailable",
        ),
    )
    delivered = LEDGER.deliver_unresolved_tool_coverage_debt(
        scratch,
        phase_name="breadth",
    )
    assert delivered == ("scip-go.reference-graph",)
    assert (scratch / "toolchain_coverage_debt.json").is_file()
    appendix = scratch / "report_semantic_toolchain_coverage.md"
    assert appendix.is_file()
    assert "scip-go.reference-graph" in appendix.read_text(encoding="utf-8")

    rows = ASSURANCE._toolchain_coverage_assurance_rows(scratch)
    assert any(row["gate_id"] == "toolchain.scip-go.reference-graph"
               for row in rows)
    DRIVER._append_phase_io_debt(
        scratch,
        "breadth",
        "TOOLCHAIN_COVERAGE_DEBT",
        "scip-go.reference-graph",
    )
    assert "[TOOLCHAIN_COVERAGE_DEBT]" in (
        scratch / "breadth.degraded"
    ).read_text(encoding="utf-8")
    appendix_text = MECHANICAL._build_human_review_appendix(scratch)
    assert "Toolchain Coverage" in appendix_text
    assert "scip-go.reference-graph" in appendix_text


def test_breadth_driver_toolchain_report_is_not_misattributed_to_model(
    tmp_path: Path,
) -> None:
    scratch = tmp_path / "scratch"
    project = tmp_path / "project"
    scratch.mkdir()
    project.mkdir()
    config = {
        "_run_id": "driver-prelaunch-fixture",
        "project_root": str(project),
        "pipeline": "sc",
    }
    before = DRIVER._snapshot_file_state(scratch, str(project))
    LEDGER.record_tool_outcome(
        scratch,
        LEDGER.ToolOutcome.debt(
            "opengrep.static-analysis",
            "opengrep",
            LEDGER.ToolOutcomeState.UNAVAILABLE,
            "fixture provider unavailable",
        ),
    )
    assert LEDGER.deliver_unresolved_tool_coverage_debt(
        scratch,
        phase_name="breadth",
    ) == ("opengrep.static-analysis",)

    phases = [SimpleNamespace(name="breadth")]
    foreign = DRIVER._detect_foreign_phase_writes(
        scratch,
        str(project),
        phases,
        "breadth",
        "sc",
        before,
    )
    report_name = LEDGER.TOOLCHAIN_COVERAGE_REPORT_FILENAME
    assert report_name in foreign

    try:
        DRIVER._bind_driver_prelaunch_containment_artifact(
            config,
            "breadth",
            scratch,
            report_name,
        )
        assert DRIVER._filter_driver_prelaunch_containment_artifacts(
            config,
            "breadth",
            scratch,
            foreign,
        ) == []
        with pytest.raises(RuntimeError, match="unsupported"):
            DRIVER._bind_driver_prelaunch_containment_artifact(
                config,
                "breadth",
                scratch,
                "report_semantic_unrelated.md",
            )
    finally:
        DRIVER._clear_driver_prelaunch_containment_artifacts(config, "breadth")


def test_breadth_driver_toolchain_report_exemption_rejects_model_drift(
    tmp_path: Path,
) -> None:
    scratch = tmp_path / "scratch"
    config = {"_run_id": "driver-prelaunch-drift-fixture"}
    LEDGER.record_tool_outcome(
        scratch,
        LEDGER.ToolOutcome.debt(
            "opengrep.static-analysis",
            "opengrep",
            LEDGER.ToolOutcomeState.UNAVAILABLE,
            "fixture provider unavailable",
        ),
    )
    LEDGER.deliver_unresolved_tool_coverage_debt(
        scratch,
        phase_name="breadth",
    )
    report_name = LEDGER.TOOLCHAIN_COVERAGE_REPORT_FILENAME
    report = scratch / report_name

    try:
        DRIVER._bind_driver_prelaunch_containment_artifact(
            config,
            "breadth",
            scratch,
            report_name,
        )
        original = report.read_bytes()
        report.write_bytes(original + b"\nMODEL mutation\n")
        assert DRIVER._filter_driver_prelaunch_containment_artifacts(
            config,
            "breadth",
            scratch,
            [report_name],
        ) == [report_name]

        report.write_bytes(original)
        DRIVER._bind_driver_prelaunch_containment_artifact(
            config,
            "breadth",
            scratch,
            report_name,
        )
        replacement = scratch / ".toolchain-report-replacement"
        replacement.write_bytes(original)
        os.replace(replacement, report)
        assert report.read_bytes() == original
        assert DRIVER._filter_driver_prelaunch_containment_artifacts(
            config,
            "breadth",
            scratch,
            [report_name],
        ) == [report_name]
    finally:
        DRIVER._clear_driver_prelaunch_containment_artifacts(config, "breadth")


def test_clean_toolchain_ledger_removes_stale_debt_projection(
    tmp_path: Path,
) -> None:
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    for name in (
        LEDGER.TOOLCHAIN_COVERAGE_DEBT_FILENAME,
        LEDGER.TOOLCHAIN_COVERAGE_REPORT_FILENAME,
    ):
        (scratch / name).write_text("# stale\n", encoding="utf-8")
    assert LEDGER.deliver_unresolved_tool_coverage_debt(
        scratch,
        phase_name="breadth",
    ) == ()
    assert not (
        scratch / LEDGER.TOOLCHAIN_COVERAGE_DEBT_FILENAME
    ).exists()
    assert not (
        scratch / LEDGER.TOOLCHAIN_COVERAGE_REPORT_FILENAME
    ).exists()


def test_runtime_dependency_denominator_and_manifest_cachebuster(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    required = set(CONTROL.TOOLCHAIN_RUNTIME_REQUIRED_FILES)
    expected = {
        "plamen_l1/scip_pb2.py",
        "plamen_l1/scip_reader.py",
        "scripts/state_symbol_authority.py",
        "scripts/enumeration_type_ir.py",
        "scripts/linux_cgroup_exec.py",
        "scripts/owned_process_runner.py",
        "scripts/owned_process_scope.py",
    }
    assert expected <= required
    assert all((Path(__file__).resolve().parents[1] / value).is_file()
               for value in required)

    install_root = tmp_path / "plamen"
    install_root.mkdir()
    for relative in required:
        source = Path(__file__).resolve().parents[1] / relative
        target = install_root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(source.read_bytes())
    digest = INSTALLER._toolchain_runtime_bundle_sha256(install_root)
    assert len(digest) == 64

    claude_home = tmp_path / ".claude"
    codex_home = tmp_path / ".codex"
    claude_home.mkdir()
    codex_home.mkdir()
    monkeypatch.setattr(INSTALLER, "PLAMEN_HOME", str(install_root))
    monkeypatch.setattr(INSTALLER, "CLAUDE_HOME", str(claude_home))
    original_expanduser = INSTALLER.os.path.expanduser
    monkeypatch.setattr(
        INSTALLER.os.path,
        "expanduser",
        lambda value: str(codex_home)
        if value == "~/.codex"
        else original_expanduser(value),
    )
    monkeypatch.setattr(
        INSTALLER,
        "_manifest_paths",
        lambda: [str(claude_home / INSTALLER._PLAMEN_MANIFEST)],
    )
    INSTALLER._write_install_manifest()
    manifest = json.loads(
        (claude_home / INSTALLER._PLAMEN_MANIFEST).read_text(
            encoding="utf-8"
        )
    )
    assert manifest["runtime_bundle_sha256"] == digest


def test_runtime_denominator_tracks_the_real_graph_import_slice() -> None:
    root = Path(__file__).resolve().parents[1]
    required = set(CONTROL.TOOLCHAIN_RUNTIME_REQUIRED_FILES)
    expected_edges = {
        "scripts/recon_prepass.py": {
            "scripts/audit_snapshot.py",
            "scripts/enumeration_type_ir.py",
            "scripts/owned_process_runner.py",
            "scripts/plamen_types.py",
            "scripts/production_source_scope.py",
            "scripts/state_symbol_authority.py",
            "scripts/supply_chain_gate.py",
            "scripts/tool_coverage_ledger.py",
        },
        "scripts/tool_coverage_ledger.py": {
            "scripts/toolchain_control_authority.py",
        },
        "scripts/audit_snapshot.py": {
            "scripts/owned_process_runner.py",
            "scripts/plamen_types.py",
            "scripts/production_source_scope.py",
            "scripts/toolchain_control_authority.py",
        },
        "scripts/owned_process_runner.py": {
            "scripts/owned_process_scope.py",
        },
        "scripts/owned_process_scope.py": {
            "scripts/linux_cgroup_exec.py",
            "scripts/windows_low_integrity_lease.py",
        },
        "plamen_l1/scip_reader.py": {
            "plamen_l1/scip_pb2.py",
        },
    }

    def imported_local_files(relative: str) -> set[str]:
        path = root / relative
        tree = ast.parse(path.read_text(encoding="utf-8"))
        found: set[str] = set()
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "with_name"
                and len(node.args) == 1
                and isinstance(node.args[0], ast.Constant)
                and isinstance(node.args[0].value, str)
                and node.args[0].value.endswith(".py")
            ):
                dynamic = (
                    Path(relative).parent / node.args[0].value
                ).as_posix()
                if (root / dynamic).is_file():
                    found.add(dynamic)
                continue
            if isinstance(node, ast.Import):
                modules = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                if node.level == 1 and node.module is None:
                    modules = [
                        f"plamen_l1.{alias.name}"
                        for alias in node.names
                    ]
                elif node.module:
                    modules = [node.module]
                else:
                    modules = []
            else:
                continue
            for module in modules:
                leaf = module.split(".")[-1]
                candidates = (
                    f"scripts/{leaf}.py",
                    f"{module.replace('.', '/')}.py",
                )
                for candidate in candidates:
                    if (root / candidate).is_file():
                        found.add(candidate)
        return found

    for source, dependencies in expected_edges.items():
        assert dependencies <= imported_local_files(source)
        assert dependencies <= required
    assert not (root / "scripts/exhaustive_process_scope.py").exists()
