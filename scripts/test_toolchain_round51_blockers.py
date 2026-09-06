"""Frozen red contracts for the independently adjudicated Toolchain R5.1 block.

The fixtures are local and synthetic.  They launch no provider, install
nothing, contact no network, and run no audit.
"""

from __future__ import annotations

import hashlib
import inspect
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

import plamen as INSTALLER
import audit_snapshot as SNAPSHOT
import plamen_driver as DRIVER
import recon_prepass as RECON
import tool_coverage_ledger as LEDGER
import toolchain_control_authority as CONTROL
from enumeration_type_ir import build_function_signature_fact


GRAPH_ARTIFACTS = LEDGER.PRECISE_GRAPH_ARTIFACTS
GRAPH_GENERATION_FILES = (
    *GRAPH_ARTIFACTS,
    LEDGER.PRECISE_GRAPH_GENERATION_MANIFEST,
)


def _context(
    *,
    run_id: str = "toolchain-r51-current",
    ecosystem: str = "go",
    pipeline: str = "l1",
) -> dict[str, str]:
    return {
        "run_id": run_id,
        "phase": "recon-prebreadth",
        "snapshot_sha256": "3" * 64,
        "project_root_sha256": "4" * 64,
        "ecosystem": ecosystem,
        "pipeline": pipeline,
        "mode": "thorough",
        "platform": "windows",
    }


def _authority(tool_id: str) -> dict[str, object]:
    unsigned = {
        "schema": "plamen.runtime-tool-identity.v2",
        "tool_id": tool_id,
        "identity_kind": (
            "python_distribution"
            if tool_id in {"slither", "protobuf"}
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


def _graph_payload(ecosystem: str) -> dict:
    identity = f"{ecosystem}.entry"
    fact = build_function_signature_fact(
        ecosystem=ecosystem,
        provider=f"scip-{ecosystem}",
        function_identity=identity,
        bare_name="entry",
        provider_symbol=identity,
        raw_signature="",
        source_path=f"{ecosystem}/main.rs",
        source_line=1,
        source_sha256="",
        kind="Function",
        authority="PROVIDER_IDENTITY_ONLY",
    )
    return {
        "schema_version": "plamen.mechanical_graph.v2",
        "function_signature_schema": "plamen.function_signature_fact.v1",
        "source": f"scip-{ecosystem}",
        "state_symbols": [],
        "var_refs": {},
        "functions": {
            identity: {
                "bare": "entry",
                "loc": f"{ecosystem}/main.rs:L1",
                "callers": [],
                "callees": [],
                "signature_fact": fact,
            }
        },
        "function_signatures": {identity: fact},
    }


def _write_graph_set(root: Path, ecosystem: str) -> None:
    root.mkdir(parents=True, exist_ok=True)
    for name in GRAPH_ARTIFACTS[:-1]:
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


def _patch_controls(monkeypatch: pytest.MonkeyPatch) -> None:
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


def _bind_synthetic_audit_snapshot(config: dict) -> dict:
    """Bind a schema-valid snapshot without probing host tool providers."""

    project = Path(config["project_root"])
    language = str(config.get("language") or "").lower()
    if language == "evm":
        (project / "Protocol.sol").write_text(
            "contract Protocol {}\n", encoding="utf-8"
        )
        # The production driver performs this deterministic bootstrap before
        # binding its snapshot.  Seed it here so the in-process prepass cannot
        # introduce a new source-scope input after the synthetic bind.
        (project / "foundry.toml").write_text(
            '[profile.default]\nsrc = "."\n', encoding="utf-8"
        )
    elif language == "solana":
        source = project / "src" / "lib.rs"
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_text("pub fn fixture() {}\n", encoding="utf-8")
    else:  # pragma: no cover - helper is intentionally narrow
        raise AssertionError(f"unsupported synthetic snapshot language: {language}")

    empty_component = SNAPSHOT._digest_entries(())
    snapshot = {
        "schema": SNAPSHOT.SNAPSHOT_SCHEMA,
        "components": {
            "source_scope": SNAPSHOT._source_component(config),
            "audit_config": SNAPSHOT._config_component(config),
            "methodology": dict(empty_component),
            "toolchain": dict(empty_component),
        },
    }
    snapshot["snapshot_digest"] = hashlib.sha256(
        SNAPSHOT._canonical_json(snapshot)
    ).hexdigest()
    assert SNAPSHOT._valid_snapshot(snapshot)
    config["_audit_snapshot"] = snapshot
    return snapshot


def test_b1_old_precise_context_is_replaced_by_current_run_debt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_controls(monkeypatch)
    scratch = tmp_path / "scratch"
    _write_graph_set(scratch, "go")
    envelope = LEDGER.build_context_bound_tool_outcome_envelope(
        scratch,
        capability_id="scip-go.reference-graph",
        tool="scip-go",
        authority=_authority("scip-go"),
        context=_context(run_id="old-run"),
        artifacts=GRAPH_ARTIFACTS,
    )
    LEDGER.record_tool_outcome(
        scratch,
        LEDGER.ToolOutcome.succeeded(
            "scip-go.reference-graph",
            "scip-go",
            0,
            artifacts=GRAPH_ARTIFACTS,
            provider_ref=json.dumps(
                envelope, sort_keys=True, separators=(",", ":")
            ),
        ),
    )

    changed = LEDGER.reconcile_expected_tool_capabilities(
        scratch,
        pipeline="l1",
        ecosystem="go",
        platform_name="win32",
        mode="thorough",
        phase="recon-prebreadth",
        execution_context=_context(run_id="current-run"),
    )

    assert "scip-go.reference-graph" in changed
    outcome = LEDGER.load_tool_coverage_ledger(scratch)[
        "scip-go.reference-graph"
    ]
    assert outcome.state is LEDGER.ToolOutcomeState.FAILED
    assert "STALE_CONTEXT" in outcome.reason


def test_b1_mixed_root_rejects_stale_lane_context_projection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_controls(monkeypatch)
    scratch = tmp_path / "scratch"
    project = tmp_path / "project"
    lane = scratch / "_graph_providers" / "go"
    project.mkdir()
    _write_graph_set(lane, "go")
    _write_graph_set(scratch, "go")
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
        ("scip-go.reference-graph", "scip-go"),
        ("protobuf.scip-graph-parser", "protobuf"),
    ):
        envelope = LEDGER.build_context_bound_tool_outcome_envelope(
            lane,
            capability_id=capability_id,
            tool=tool,
            authority=_authority(tool),
            context=_context(run_id="old-lane"),
            artifacts=GRAPH_ARTIFACTS,
        )
        LEDGER.record_tool_outcome(
            lane,
            LEDGER.ToolOutcome.succeeded(
                capability_id,
                tool,
                0,
                artifacts=GRAPH_ARTIFACTS,
                provider_ref=json.dumps(
                    envelope, sort_keys=True, separators=(",", ":")
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
        context=_context(
            run_id="current-root", ecosystem="mixed"
        ),
    )
    root = LEDGER.load_tool_coverage_ledger(scratch)
    assert (
        root["scip-go.reference-graph"].state
        is LEDGER.ToolOutcomeState.FAILED
    )


@pytest.mark.parametrize(
    ("language", "expected"),
    (("evm", "_bake_evm_graph"), ("solana", "_bake_rust_graph")),
)
def test_b2_startup_graph_paths_receive_exact_execution_context(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    language: str,
    expected: str,
) -> None:
    scratch = tmp_path / "scratch"
    project = tmp_path / "project"
    project.mkdir()
    observed: list[dict | None] = []

    def capture(_scratch, _project, *, context=None):
        observed.append(context)
        return "SKIPPED:fixture"

    monkeypatch.setattr(RECON, expected, capture)
    config = {
        "scratchpad": str(scratch),
        "project_root": str(project),
        "language": language,
        "pipeline": "sc",
        "mode": "thorough",
        "_run_id": "startup-context",
        "prepass_external_scanners": language == "solana",
    }
    snapshot = _bind_synthetic_audit_snapshot(config)
    RECON.run_recon_prepass(config)

    assert len(observed) == 1
    assert observed[0] is not None
    assert observed[0]["run_id"] == "startup-context"
    assert observed[0]["snapshot_sha256"] == snapshot["snapshot_digest"]
    assert observed[0]["ecosystem"] == language
    assert observed[0]["phase"] == "recon-prebreadth"


@pytest.mark.parametrize(
    ("language", "capability_id", "provider_hook"),
    (
        ("evm", "slither.evm-reference-graph", "evm"),
        ("solana", "scip-rust.reference-graph", "rust"),
    ),
)
def test_b2_production_prepass_precise_success_replays_current_context(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    language: str,
    capability_id: str,
    provider_hook: str,
) -> None:
    _patch_controls(monkeypatch)
    scratch = tmp_path / "scratch"
    project = tmp_path / "project"
    project.mkdir()
    monkeypatch.setattr(
        RECON,
        "_capture_python_provider_authority",
        lambda tool, **_kwargs: _authority(tool),
    )
    monkeypatch.setattr(
        RECON,
        "_capture_command_provider_authority",
        lambda tool, *_args, **_kwargs: _authority(tool),
    )
    if provider_hook == "evm":
        monkeypatch.setattr(
            RECON,
            "_bake_evm_slither_graph",
            lambda stage, _project: (
                _write_graph_set(Path(stage), "evm") or "WRITTEN"
            ),
        )
    else:
        monkeypatch.setattr(
            RECON,
            "_bake_rust_scip",
            lambda root, _project, **_kwargs: (
                _write_graph_set(Path(root), "rust") or "WRITTEN"
            ),
        )
    config = {
        "scratchpad": str(scratch),
        "project_root": str(project),
        "language": language,
        "pipeline": "sc",
        "mode": "thorough",
        "_run_id": "production-prepass",
        "prepass_external_scanners": language == "solana",
    }
    _bind_synthetic_audit_snapshot(config)
    RECON.run_recon_prepass(config)
    context = LEDGER.build_tool_execution_context(
        config, phase="recon-prebreadth"
    )
    outcome = LEDGER.load_tool_coverage_ledger(
        scratch,
        expected_context=context,
    )[capability_id]
    assert outcome.state is LEDGER.ToolOutcomeState.SUCCEEDED
    envelope = json.loads(outcome.provider_ref)
    assert envelope["context"] == context


def test_b3_publish_and_rollback_double_fault_quarantines_complete_set(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stage = tmp_path / "stage"
    destination = tmp_path / "scratch"
    _write_graph_set(stage, "go")
    _write_graph_set(destination, "rust")
    prior = {
        name: (destination / name).read_bytes()
        for name in GRAPH_ARTIFACTS
    }
    real_replace = RECON.os.replace

    def double_fault(source, target):
        source_name = Path(source).name
        target_name = Path(target).name
        if (
            target_name == "_mechanical_graph.json"
            and source_name.endswith(".r5-publish")
        ):
            raise OSError("synthetic publication fault")
        if (
            target_name == "caller_map.md"
            and source_name.endswith(".r5-restore")
        ):
            raise OSError("synthetic rollback fault")
        return real_replace(source, target)

    monkeypatch.setattr(RECON.os, "replace", double_fault)
    status, evidence = RECON._validate_and_publish_graph_artifact_set(
        stage, destination
    )

    assert status.startswith("FAILED:ARTIFACT_PUBLICATION")
    assert evidence == {}
    visible = {
        name: (destination / name).read_bytes()
        for name in GRAPH_ARTIFACTS
        if (destination / name).is_file()
    }
    assert visible == prior or set(visible) != set(GRAPH_ARTIFACTS)


@pytest.mark.parametrize("publish_target", GRAPH_GENERATION_FILES)
def test_b3_each_publication_step_preserves_the_old_generation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    publish_target: str,
) -> None:
    stage = tmp_path / "stage"
    destination = tmp_path / "scratch"
    _write_graph_set(stage, "go")
    _write_graph_set(destination, "rust")
    before = {
        name: (destination / name).read_bytes()
        for name in GRAPH_GENERATION_FILES
    }
    real_replace = RECON.os.replace

    def fail_one_publish(source, target):
        if (
            Path(source).name.endswith(".r5-publish")
            and Path(target).name == publish_target
        ):
            raise OSError("publication matrix fixture")
        return real_replace(source, target)

    monkeypatch.setattr(RECON.os, "replace", fail_one_publish)
    status, _evidence = (
        RECON._validate_and_publish_graph_artifact_set(
            stage, destination
        )
    )
    assert status.startswith("FAILED:ARTIFACT_PUBLICATION")
    assert {
        name: (destination / name).read_bytes()
        for name in GRAPH_GENERATION_FILES
    } == before


@pytest.mark.parametrize("restore_target", GRAPH_GENERATION_FILES)
def test_b3_each_rollback_step_failure_invalidates_the_generation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    restore_target: str,
) -> None:
    stage = tmp_path / "stage"
    destination = tmp_path / "scratch"
    _write_graph_set(stage, "go")
    _write_graph_set(destination, "rust")
    real_replace = RECON.os.replace
    real_validate = RECON._validate_graph_generation_manifest

    def fail_publish_then_restore(source, target):
        source_name = Path(source).name
        target_name = Path(target).name
        if (
            restore_target
            != LEDGER.PRECISE_GRAPH_GENERATION_MANIFEST
            and
            source_name.endswith(".r5-publish")
            and target_name
            == LEDGER.PRECISE_GRAPH_GENERATION_MANIFEST
        ):
            raise OSError("publication matrix fixture")
        if (
            source_name.endswith(".r5-restore")
            and target_name == restore_target
        ):
            raise OSError("rollback matrix fixture")
        return real_replace(source, target)

    def fail_after_committed_manifest(root, evidence):
        real_validate(root, evidence)
        if (
            restore_target
            == LEDGER.PRECISE_GRAPH_GENERATION_MANIFEST
        ):
            raise OSError("post-commit validation matrix fixture")

    monkeypatch.setattr(
        RECON.os, "replace", fail_publish_then_restore
    )
    monkeypatch.setattr(
        RECON,
        "_validate_graph_generation_manifest",
        fail_after_committed_manifest,
    )
    status, evidence = (
        RECON._validate_and_publish_graph_artifact_set(
            stage, destination
        )
    )
    assert "ROLLBACK_QUARANTINED" in status
    assert evidence == {}
    assert not any(
        (destination / name).exists()
        for name in GRAPH_GENERATION_FILES
    )


def test_b4_linux_dynamic_helper_is_runtime_bound_and_mutation_sensitive(
    tmp_path: Path,
) -> None:
    relative = "scripts/linux_cgroup_exec.py"
    assert relative in CONTROL.TOOLCHAIN_RUNTIME_REQUIRED_FILES
    source_root = Path(__file__).resolve().parents[1]
    install_root = tmp_path / "runtime"
    for name in CONTROL.TOOLCHAIN_RUNTIME_REQUIRED_FILES:
        target = install_root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((source_root / name).read_bytes())
    before = INSTALLER._toolchain_runtime_bundle_sha256(install_root)
    assert len(before) == 64
    helper = install_root / relative
    helper.write_bytes(helper.read_bytes() + b"\n# mutation fixture\n")
    with pytest.raises(RuntimeError, match="scripts/linux_cgroup_exec.py"):
        INSTALLER._toolchain_runtime_bundle_sha256(install_root)


def test_b5_nonprecise_success_replays_context_and_artifact_hashes(
    tmp_path: Path,
) -> None:
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    for name in ("opengrep_results.sarif", "opengrep_findings.md"):
        (scratch / name).write_text(f"{name}\n", encoding="utf-8")
    context = _context(ecosystem="evm", pipeline="sc")
    bound = LEDGER.bind_succeeded_tool_outcome(
        scratch,
        LEDGER.ToolOutcome.succeeded(
            "opengrep.static-analysis",
            "opengrep",
            0,
            artifacts=(
                "opengrep_results.sarif",
                "opengrep_findings.md",
            ),
            provider_ref="rules@fixture",
        ),
        context=context,
    )
    LEDGER.record_tool_outcome(scratch, bound)
    assert (
        LEDGER.load_tool_coverage_ledger(
            scratch, expected_context=context
        )["opengrep.static-analysis"].state
        is LEDGER.ToolOutcomeState.SUCCEEDED
    )

    (scratch / "opengrep_results.sarif").unlink()
    changed = LEDGER.reconcile_expected_tool_capabilities(
        scratch,
        pipeline="sc",
        ecosystem="evm",
        platform_name="win32",
        mode="thorough",
        phase="recon-prebreadth",
        execution_context=context,
    )
    assert "opengrep.static-analysis" in changed
    outcome = LEDGER.load_tool_coverage_ledger(scratch)[
        "opengrep.static-analysis"
    ]
    assert outcome.state is LEDGER.ToolOutcomeState.FAILED
    assert "ARTIFACT_REPLAY" in outcome.reason


def test_b5_legacy_unbound_success_materializes_migration_debt(
    tmp_path: Path,
) -> None:
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    legacy = LEDGER.ToolOutcome.succeeded(
        "opengrep.static-analysis",
        "opengrep",
        0,
        artifacts=(
            "opengrep_results.sarif",
            "opengrep_findings.md",
        ),
        provider_ref="legacy-rules",
    )
    payload = LEDGER._empty_ledger()
    payload["capabilities"] = {
        legacy.capability_id: legacy.to_record()
    }
    payload["ledger_sha256"] = hashlib.sha256(
        LEDGER._canonical_json(payload)
    ).hexdigest()
    (scratch / LEDGER.LEDGER_FILENAME).write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    changed = LEDGER.reconcile_expected_tool_capabilities(
        scratch,
        pipeline="sc",
        ecosystem="evm",
        platform_name="win32",
        mode="thorough",
        phase="recon-prebreadth",
        execution_context=_context(
            ecosystem="evm", pipeline="sc"
        ),
    )

    assert "opengrep.static-analysis" in changed
    migrated = LEDGER.load_tool_coverage_ledger(scratch)[
        "opengrep.static-analysis"
    ]
    assert migrated.state is LEDGER.ToolOutcomeState.FAILED
    assert "SUCCESS_REPLAY" in migrated.reason
    assert migrated.provider_ref.startswith(
        "invalid-success-envelope-sha256:"
    )


def test_b5_legacy_sec3_success_is_typed_migration_debt(
    tmp_path: Path,
) -> None:
    """A pre-envelope Sec3 receipt is visible debt, never current coverage."""

    scratch = tmp_path / "scratch"
    scratch.mkdir()
    for name in ("sec3_results.sarif", "sec3_findings.md"):
        (scratch / name).write_text(name, encoding="utf-8")
    legacy = LEDGER.ToolOutcome.succeeded(
        "sec3-xray.solana-static-analysis",
        "sec3-xray",
        0,
        artifacts=("sec3_results.sarif", "sec3_findings.md"),
        provider_ref="sec3@sha256:" + "4" * 64,
    )
    payload = LEDGER._empty_ledger()
    payload["capabilities"] = {
        legacy.capability_id: legacy.to_record()
    }
    payload["ledger_sha256"] = hashlib.sha256(
        LEDGER._canonical_json(payload)
    ).hexdigest()
    (scratch / LEDGER.LEDGER_FILENAME).write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    changed = LEDGER.reconcile_expected_tool_capabilities(
        scratch,
        pipeline="sc",
        ecosystem="solana",
        platform_name="win32",
        mode="thorough",
        phase="recon-prebreadth",
        execution_context=_context(
            ecosystem="solana", pipeline="sc"
        ),
    )

    assert legacy.capability_id in changed
    migrated = LEDGER.load_tool_coverage_ledger(scratch)[
        legacy.capability_id
    ]
    assert migrated.state is LEDGER.ToolOutcomeState.FAILED
    assert "SUCCESS_REPLAY" in migrated.reason
    assert "LEGACY_UNBOUND_SUCCESS" in migrated.reason
    assert migrated.provider_ref.startswith(
        "invalid-success-envelope-sha256:"
    )
    assert all(
        (scratch / name).is_file() for name in legacy.artifacts
    )


def test_b5_legacy_dependency_shared_output_migrates_both_lanes(
    tmp_path: Path,
) -> None:
    """One shared legacy artifact cannot preserve either lane's authority."""

    scratch = tmp_path / "scratch"
    scratch.mkdir()
    artifact = scratch / "dependency_audit_findings.md"
    artifact.write_text("# legacy shared output\n", encoding="utf-8")

    def advisory(source_id: str, provider: str) -> str:
        return json.dumps(
            {
                "schema_version": "plamen.advisory_source.v1",
                "source_id": source_id,
                "provider": provider,
                "content_sha256": "6" * 64,
                "as_of": "2026-01-01T00:00:00Z",
                "expires_at": "2026-01-02T00:00:00Z",
            },
            sort_keys=True,
            separators=(",", ":"),
        )

    legacy_outcomes = (
        LEDGER.ToolOutcome.succeeded(
            "govulncheck.dependency-audit",
            "govulncheck",
            0,
            artifacts=(artifact.name,),
            provider_ref=advisory(
                "govulndb-local", "Go Vulnerability Database"
            ),
        ),
        LEDGER.ToolOutcome.succeeded(
            "cargo-audit.dependency-audit",
            "cargo-audit",
            0,
            artifacts=(artifact.name,),
            provider_ref=advisory(
                "rustsec-local", "RustSec Advisory Database"
            ),
        ),
    )
    payload = LEDGER._empty_ledger()
    payload["capabilities"] = {
        outcome.capability_id: outcome.to_record()
        for outcome in legacy_outcomes
    }
    payload["ledger_sha256"] = hashlib.sha256(
        LEDGER._canonical_json(payload)
    ).hexdigest()
    (scratch / LEDGER.LEDGER_FILENAME).write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    changed = LEDGER.reconcile_expected_tool_capabilities(
        scratch,
        pipeline="l1",
        ecosystem="mixed",
        platform_name="win32",
        mode="thorough",
        phase="recon-prebreadth",
        execution_context=_context(
            ecosystem="mixed", pipeline="l1"
        ),
    )

    capability_ids = {
        outcome.capability_id for outcome in legacy_outcomes
    }
    assert capability_ids <= set(changed)
    migrated = LEDGER.load_tool_coverage_ledger(scratch)
    for capability_id in capability_ids:
        assert (
            migrated[capability_id].state
            is LEDGER.ToolOutcomeState.FAILED
        )
        assert "SUCCESS_REPLAY" in migrated[capability_id].reason
        assert (
            "LEGACY_UNBOUND_SUCCESS"
            in migrated[capability_id].reason
        )
        assert migrated[capability_id].provider_ref.startswith(
            "invalid-success-envelope-sha256:"
        )
    assert artifact.is_file()


def test_b5_implicit_zero_artifact_success_is_rejected(
    tmp_path: Path,
) -> None:
    with pytest.raises(
        LEDGER.ToolCoverageLedgerError,
        match="context-bound envelope",
    ):
        LEDGER.record_tool_outcome(
            tmp_path,
            LEDGER.ToolOutcome.succeeded(
                "opengrep.static-analysis",
                "opengrep",
                0,
            ),
        )


def test_b5_sec3_success_loses_authority_when_sarif_drifts(
    tmp_path: Path,
) -> None:
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    for name in ("sec3_results.sarif", "sec3_findings.md"):
        (scratch / name).write_text(name, encoding="utf-8")
    context = _context(ecosystem="solana", pipeline="sc")
    success = LEDGER.bind_succeeded_tool_outcome(
        scratch,
        LEDGER.ToolOutcome.succeeded(
            "sec3-xray.solana-static-analysis",
            "sec3-xray",
            0,
            artifacts=("sec3_results.sarif", "sec3_findings.md"),
            provider_ref="sec3@sha256:" + "5" * 64,
        ),
        context=context,
    )
    LEDGER.record_tool_outcome(scratch, success)
    (scratch / "sec3_results.sarif").write_text(
        "drift", encoding="utf-8"
    )
    LEDGER.reconcile_expected_tool_capabilities(
        scratch,
        pipeline="sc",
        ecosystem="solana",
        platform_name="win32",
        mode="thorough",
        phase="recon-prebreadth",
        execution_context=context,
    )
    assert (
        LEDGER.load_tool_coverage_ledger(scratch)[
            "sec3-xray.solana-static-analysis"
        ].state
        is LEDGER.ToolOutcomeState.FAILED
    )


def test_b5_dependency_lanes_bind_the_same_shared_artifact(
    tmp_path: Path,
) -> None:
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    artifact = scratch / "dependency_audit_findings.md"
    artifact.write_text("# shared\n", encoding="utf-8")
    context = _context(ecosystem="mixed", pipeline="l1")

    def advisory(source_id: str, provider: str) -> str:
        return json.dumps(
            {
                "schema_version": "plamen.advisory_source.v1",
                "source_id": source_id,
                "provider": provider,
                "content_sha256": "6" * 64,
                "as_of": "2026-01-01T00:00:00Z",
                "expires_at": "2026-01-02T00:00:00Z",
            },
            sort_keys=True,
            separators=(",", ":"),
        )

    for capability_id, tool, source_id, provider in (
        (
            "govulncheck.dependency-audit",
            "govulncheck",
            "govulndb-local",
            "Go Vulnerability Database",
        ),
        (
            "cargo-audit.dependency-audit",
            "cargo-audit",
            "rustsec-local",
            "RustSec Advisory Database",
        ),
    ):
        bound = LEDGER.bind_succeeded_tool_outcome(
            scratch,
            LEDGER.ToolOutcome.succeeded(
                capability_id,
                tool,
                0,
                artifacts=("dependency_audit_findings.md",),
                provider_ref=advisory(source_id, provider),
            ),
            context=context,
        )
        LEDGER.record_tool_outcome(scratch, bound)
    artifact.write_text("# shared drift\n", encoding="utf-8")
    changed = LEDGER.reconcile_expected_tool_capabilities(
        scratch,
        pipeline="l1",
        ecosystem="mixed",
        platform_name="win32",
        mode="thorough",
        phase="recon-prebreadth",
        execution_context=context,
    )
    assert {
        "govulncheck.dependency-audit",
        "cargo-audit.dependency-audit",
    } <= set(changed)
    ledger = LEDGER.load_tool_coverage_ledger(scratch)
    assert all(
        ledger[capability].state is LEDGER.ToolOutcomeState.FAILED
        for capability in (
            "govulncheck.dependency-audit",
            "cargo-audit.dependency-audit",
        )
    )


def test_b3_missing_commit_manifest_quarantines_all_precise_projections(
    tmp_path: Path,
) -> None:
    scratch = tmp_path / "scratch"
    _write_graph_set(scratch, "go")
    (scratch / RECON._GRAPH_GENERATION_MANIFEST).unlink()
    # Recreate an invalid marker so this is distinguishable from an
    # approximate machine-graph-only provider.
    (scratch / RECON._GRAPH_GENERATION_MANIFEST).write_text(
        "{}\n", encoding="utf-8"
    )
    quarantined, issues = (
        LEDGER.quarantine_invalid_committed_graph_generation(
            scratch
        )
    )
    assert quarantined is True
    assert issues
    assert not any(
        (scratch / name).exists()
        for name in (
            LEDGER.PRECISE_GRAPH_GENERATION_MANIFEST,
            *GRAPH_ARTIFACTS,
        )
    )


def test_b3_approximate_fallback_cannot_mix_with_prior_precise_generation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scratch = tmp_path / "scratch"
    project = tmp_path / "project"
    project.mkdir()
    _write_graph_set(scratch, "rust")
    monkeypatch.setattr(
        RECON,
        "_bake_evm_slither_graph",
        lambda _stage, _project: "FAILED:fixture",
    )

    def fallback(root: Path, _project: Path) -> str:
        assert not (
            Path(root) / RECON._GRAPH_GENERATION_MANIFEST
        ).exists()
        assert not any(
            (Path(root) / name).exists()
            for name in GRAPH_ARTIFACTS
        )
        (Path(root) / "_mechanical_graph.json").write_text(
            '{"source":"evm-source"}\n',
            encoding="utf-8",
        )
        return "WRITTEN"

    monkeypatch.setattr(RECON, "_bake_evm_source_graph", fallback)
    result = RECON._bake_evm_graph(scratch, project)
    assert result.startswith("WRITTEN:evm-source")
    assert (scratch / "_mechanical_graph.json").is_file()
    assert not (scratch / RECON._GRAPH_GENERATION_MANIFEST).exists()


def test_b3_every_model_phase_replays_commit_before_prompt_consumption() -> None:
    wrapper = inspect.getsource(DRIVER.run_phase)
    assert "_run_phase_once(" in wrapper
    source = inspect.getsource(DRIVER._run_phase_once)
    replay = source.index(
        "quarantine_invalid_committed_graph_generation"
    )
    prompt = source.index("build_phase_prompt")
    assert replay < prompt


@pytest.mark.skipif(os.name != "nt", reason="Windows hardlink semantics")
def test_b6_same_directory_windows_launcher_hardlinks_are_canonical(
    tmp_path: Path,
) -> None:
    executable = Path(
        os.environ.get(
            "PLAMEN_TEST_GIT",
            r"C:\Program Files\Git\cmd\git.exe",
        )
    )
    if not executable.is_file() or executable.stat().st_nlink <= 1:
        pytest.skip("Git for Windows hardlinked launchers unavailable")
    SNAPSHOT._reject_unexpected_hardlinks(
        executable.resolve(strict=True),
        "runtime tool git",
        project_root=tmp_path,
    )


@pytest.mark.skipif(os.name != "nt", reason="Windows hardlink semantics")
def test_b6_cross_directory_windows_hardlink_alias_is_rejected(
    tmp_path: Path,
) -> None:
    first = tmp_path / "trusted" / "tool.exe"
    alias = tmp_path / "other" / "alias.exe"
    first.parent.mkdir()
    alias.parent.mkdir()
    first.write_bytes(b"synthetic tool")
    os.link(first, alias)
    with pytest.raises(
        SNAPSHOT.SnapshotInputError,
        match="hardlink alias",
    ):
        SNAPSHOT._reject_unexpected_hardlinks(
            first,
            "runtime tool fixture",
            project_root=tmp_path / "target",
        )
