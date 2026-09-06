"""Backend-neutral methodology dispatch and closed-role regression fixtures."""
from __future__ import annotations

import json
from pathlib import Path
import re
import threading

import plamen_driver as D
import plamen_validators as V
import pytest


_RUN_ID = "12345678-1234-4234-9234-123456789abc"
_SNAPSHOT_DIGEST = "a" * 64
_SOURCE_SCOPE_DIGEST = "b" * 64


def test_bounded_headless_provider_wave_actually_overlaps_and_joins() -> None:
    rows = [{"output": f"row-{index}"} for index in range(3)]
    barrier = threading.Barrier(3, timeout=5)
    lock = threading.Lock()
    active = 0
    maximum_active = 0

    def invoke(row: dict[str, str]) -> int:
        nonlocal active, maximum_active
        with lock:
            active += 1
            maximum_active = max(maximum_active, active)
        barrier.wait()
        with lock:
            active -= 1
        return 0

    results, terminal = D._run_bounded_headless_provider_wave(
        rows=rows,
        row_key=lambda row: str(row["output"]),
        invoke=invoke,
        concurrency=3,
        thread_name_prefix="test-headless-overlap",
    )

    assert terminal is None
    assert maximum_active == 3
    assert results == {"row-0": 0, "row-1": 0, "row-2": 0}


def test_headless_provider_concurrency_matches_process_boundary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(D.sys, "platform", "win32")
    assert D._effective_headless_provider_concurrency(4) == 1

    monkeypatch.setattr(D.sys, "platform", "linux")
    assert D._effective_headless_provider_concurrency(4) == 4
    assert D._effective_headless_provider_concurrency(99) == 6


def _write_manifest(sp: Path, depth_destination: str = "depth-external") -> None:
    sp.joinpath("spawn_manifest.md").write_text(
        "# Spawn Manifest\n\n## Breadth Agents\n\n"
        "| Row Type | Template | Required? | Agent ID | Focus Area | Expected Output | Status |\n"
        "|---|---|---|---|---|---|---|\n"
        "| AGENT | ORACLE_ANALYSIS | ✓ | B1 | oracle | analysis_oracle.md | QUEUED |\n"
        "| AGENT | GENERAL | YES | B2 | state | analysis_state.md | QUEUED |\n"
        "| AGENT | GENERAL | YES | B3 | access | analysis_access.md | QUEUED |\n\n"
        "## Skill Bindings\n\n"
        "| Skill | Required? | Inject Into | Delivery |\n"
        "|---|---|---|---|\n"
        f"| ORACLE_ANALYSIS | ✓ | {depth_destination} | full methodology |\n",
        encoding="utf-8",
    )


def _config(backend: str) -> dict:
    return {
        "pipeline": "sc", "language": "evm", "mode": "light",
        "cli_backend": backend,
    }


def _runtime_config(backend: str, root: Path) -> dict:
    return {
        **_config(backend),
        "project_root": root.as_posix(),
        "_run_id": _RUN_ID,
        "_audit_snapshot": {"snapshot_digest": _SNAPSHOT_DIGEST},
    }


def _write_exact_worker_inputs(
    root: Path,
    *,
    phase: D.Phase,
    config: dict,
    agent_id: str,
    output: str,
) -> None:
    """Materialize the exact contract denominator used by the real fanout."""
    contract, _launch = D._typed_model_worker_contract_and_launch(
        phase=phase,
        config=config,
        scratchpad=root,
        project_root=str(config["project_root"]),
        agent_id=agent_id,
        output=output,
        timeout_s=60,
    )
    obligation_sidecars = {
        "security_feature_facts.json",
        "security_obligation_authority.json",
        "security_obligations.md",
    }
    for identity in contract.immutable_inputs:
        scope, relative = identity.split(":", 1)
        assert scope == "scratchpad"
        if relative in obligation_sidecars:
            continue
        target = root.joinpath(relative)
        if target.exists():
            continue
        target.write_text(
            f"# Fixture input: {relative}\n", encoding="utf-8"
        )


def _write_depth_worker_inputs(
    root: Path,
    *,
    phase: D.Phase,
    config: dict,
    agent_id: str,
    output: str,
) -> None:
    """Create and producer-bind the PRE-depth semantic denominator."""
    root.joinpath("_v2_checkpoint.json").write_text(
        json.dumps(
            {
                "completed": ["recon", "instantiate", "breadth", "inventory"],
                "degraded": [],
                "rate_limited_at": None,
                "run_id": _RUN_ID,
                "config": {
                    "pipeline": "sc",
                    "language": "evm",
                    "mode": "light",
                },
                "audit_snapshot": {
                    "schema": "plamen.audit-input-snapshot.v1",
                    "snapshot_digest": _SNAPSHOT_DIGEST,
                    "components": {
                        "source_scope": {"digest": _SOURCE_SCOPE_DIGEST}
                    },
                },
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    root.joinpath("_mechanical_graph.json").write_text(
        json.dumps(
            {
                "schema_version": "plamen.mechanical-graph.v2",
                "source": "evm-source",
                "functions": {},
                "var_refs": {},
                "state_symbols": [],
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    _write_exact_worker_inputs(
        root,
        phase=phase,
        config=config,
        agent_id=agent_id,
        output=output,
    )
    assert D._record_security_obligation_phase_io(
        root, config, stage="pre_depth"
    ) == []


def test_single_agent_claude_phase_cannot_spawn_untracked_children():
    """P0-AM: prose-only foreground rules are not an execution control."""
    phase = D.Phase(
        "report_dedup_agent",
        ["report dedup"],
        ["report_dedup_agent_decisions.md"],
        base_timeout_s=60,
    )
    assert D._claude_disallowed_tool_names(phase) == (
        "mcp__*",
        "WebSearch",
        "WebFetch",
        "Task",
        "Agent",
    )


@pytest.mark.parametrize("name", sorted(D.CODEX_MULTI_AGENT_PHASES))
def test_explicit_coordinator_retains_child_tools(name: str):
    phase = D.Phase(name, [name], [f"{name}.md"], base_timeout_s=60)
    expected = ("mcp__*",) if name == "recon" else (
        "mcp__*", "WebSearch", "WebFetch",
    )
    assert D._claude_disallowed_tool_names(
        phase, allow_child_agents=True
    ) == expected


@pytest.mark.parametrize("name", sorted(D.CODEX_MULTI_AGENT_PHASES))
def test_driver_spawned_worker_is_leaf_even_under_pool_phase_name(name: str):
    phase = D.Phase(name, [name], [f"{name}.md"], base_timeout_s=60)
    expected = (
        ("mcp__*", "Task", "Agent")
        if name == "recon"
        else ("mcp__*", "WebSearch", "WebFetch", "Task", "Agent")
    )
    assert D._claude_disallowed_tool_names(phase) == expected


def test_mcp_phase_still_disallows_untracked_children_without_disabling_mcp():
    phase = D.Phase(
        "rag_sweep", ["rag"], ["rag_validation.md"],
        base_timeout_s=60, needs_mcp=True,
    )
    assert D._claude_disallowed_tool_names(phase) == ("Task", "Agent")


def test_backend_neutral_plan_contains_exact_skill_digest_and_steps(tmp_path: Path):
    _write_manifest(tmp_path)
    plans = [
        D._breadth_dispatch_plan(
            scratchpad=tmp_path, project_root=tmp_path.as_posix(),
            config=_config(backend), attempt=1,
        )
        for backend in ("claude", "claude-headless", "codex")
    ]
    oracle_entries = [
        next(e for e in plan if e["job"]["output"] == "analysis_oracle.md")
        for plan in plans
    ]
    assert len({entry["prompt_sha256"] for entry in oracle_entries}) == 1
    assert len(oracle_entries[0]["skill_dispatch"]) == 1
    descriptor = oracle_entries[0]["skill_dispatch"][0]
    assert descriptor["skill"] == "ORACLE_ANALYSIS"
    assert descriptor["path"].endswith("/evm/oracle-analysis/SKILL.md")
    assert len(descriptor["sha256"]) == 64
    assert {"1", "2", "3", "3d", "6"}.issubset(
        descriptor["top_level_checklist_step_ids"]
    )
    for entry in oracle_entries:
        # Restricted workers receive a complete inline projection and its
        # logical installed identity, never a host-absolute source path.
        assert "agents/skills/evm/oracle-analysis/SKILL.md" in entry["prompt"]
        assert descriptor["sha256"] in entry["prompt"]
        assert "Prompt delivery is not application proof" in entry["prompt"]
        assert "## Step Execution Trace" in entry["prompt"]
        assert "PLAMEN_STEP_TRACE_JSON_BEGIN" in entry["prompt"]
        assert '"schema_version":1,"rows"' in entry["prompt"]
        assert "`ORACLE_ANALYSIS` / `3d`" in entry["prompt"]
        assert entry["dispatch_contract_sha256"] in entry["prompt"]


def test_dispatch_contract_is_content_bound_and_backend_labeled(tmp_path: Path):
    _write_manifest(tmp_path)
    plan = D._breadth_dispatch_plan(
        scratchpad=tmp_path, project_root=tmp_path.as_posix(),
        config=_config("claude"), attempt=1,
    )
    D._write_breadth_dispatch_contract(tmp_path, _config("claude"), "claude-pty", plan)
    receipt = json.loads(
        tmp_path.joinpath("_breadth_worker_pool_contract.json").read_text(encoding="utf-8")
    )
    assert receipt["version"] == 2
    assert receipt["backend"] == "claude-pty"
    oracle = next(row for row in receipt["jobs"] if row["output"] == "analysis_oracle.md")
    assert oracle["prompt_sha256"] == next(
        entry["prompt_sha256"] for entry in plan
        if entry["job"]["output"] == "analysis_oracle.md"
    )
    assert "skill_dispatch" not in oracle
    dispatch = json.loads(tmp_path.joinpath("skill_dispatch.json").read_text(encoding="utf-8"))
    breadth = dispatch["phases"]["breadth"]
    assert receipt["skill_dispatch_sha256"] == breadth["dispatch_sha256"]
    oracle_dispatch = next(
        row for row in breadth["entries"] if row["output"] == "analysis_oracle.md"
    )
    assert oracle_dispatch["methodologies"][0]["top_level_checklist_step_ids"]


def test_all_backend_contracts_emit_identical_methodology_entries(tmp_path: Path):
    _write_manifest(tmp_path)
    plan = D._breadth_dispatch_plan(
        scratchpad=tmp_path, project_root=tmp_path.as_posix(),
        config=_config("claude"), attempt=1,
    )
    observed = []
    for backend in ("claude-pty", "claude-headless", "codex"):
        D._write_breadth_dispatch_contract(tmp_path, _config(backend), backend, plan)
        payload = json.loads(
            tmp_path.joinpath("skill_dispatch.json").read_text(encoding="utf-8")
        )["phases"]["breadth"]
        assert payload["backend"] == backend
        observed.append(payload["entries"])
    assert observed[0] == observed[1] == observed[2]


@pytest.mark.parametrize("backend", ["claude-pty", "claude-headless", "codex"])
def test_mixed_retry_preserves_last_executed_row_dispatch(
    tmp_path: Path, backend: str,
):
    _write_manifest(tmp_path)
    config = _config(backend)
    round1 = D._breadth_dispatch_plan(
        scratchpad=tmp_path, project_root=tmp_path.as_posix(),
        config=config, attempt=1,
    )
    D._write_breadth_dispatch_contract(
        tmp_path, config, backend, round1,
        dispatched_outputs={"analysis_oracle.md", "analysis_state.md", "analysis_access.md"},
    )
    first = json.loads(tmp_path.joinpath("skill_dispatch.json").read_text())[
        "phases"
    ]["breadth"]
    a_first = next(e for e in first["entries"] if e["output"] == "analysis_oracle.md")
    b_first = next(e for e in first["entries"] if e["output"] == "analysis_state.md")

    round2 = D._breadth_dispatch_plan(
        scratchpad=tmp_path, project_root=tmp_path.as_posix(),
        config=config, attempt=2,
        retry_reasons_by_output={"analysis_state.md": ["targeted retry"]},
    )
    D._write_breadth_dispatch_contract(
        tmp_path, config, backend, round2,
        dispatched_outputs={"analysis_state.md"},
    )
    second = json.loads(tmp_path.joinpath("skill_dispatch.json").read_text())[
        "phases"
    ]["breadth"]
    a_second = next(e for e in second["entries"] if e["output"] == "analysis_oracle.md")
    b_second = next(e for e in second["entries"] if e["output"] == "analysis_state.md")

    assert a_second == a_first
    assert b_second["prompt_sha256"] != b_first["prompt_sha256"]


def test_l1_breadth_resolves_layer_skill_files_not_just_labels(tmp_path: Path):
    job = {
        "agent_id": "L1B1", "focus_area": "network",
        "output": "analysis_layer_network.md", "layers": "network",
        "skills": "p2p-dos-and-eclipse, go-concurrency-safety",
        "difficulty": "HIGH",
    }
    config = {
        "pipeline": "l1", "language": "go", "mode": "light",
        "cli_backend": "claude",
    }
    descriptors = D._breadth_job_skill_descriptors(job, tmp_path, config)
    assert {item["skill"] for item in descriptors} == {
        "P2P_DOS_AND_ECLIPSE", "GO_CONCURRENCY_SAFETY",
    }
    prompt = D._build_breadth_worker_prompt(
        job=job, scratchpad=tmp_path, project_root=tmp_path.as_posix(),
        config=config, attempt=1,
    )
    for item in descriptors:
        logical = Path(item["path"]).resolve().relative_to(
            D.plamen_home().resolve()
        ).as_posix()
        assert logical in prompt
        assert Path(item["path"]).read_text(encoding="utf-8").strip() in prompt
        assert item["sha256"] in prompt
    assert "## Step Execution Trace" in prompt


def test_every_builtin_l1_layer_has_resolved_digest_bound_methodology(tmp_path: Path):
    for index, layer in enumerate(D._L1_BREADTH_LAYERS, start=1):
        job = {
            "agent_id": f"L1B{index}", "focus_area": str(layer["layer"]),
            "output": f"analysis_layer_{layer['layer']}.md",
            "layers": str(layer["layer"]), "skills": str(layer["skills"]),
            "difficulty": str(layer["difficulty"]),
        }
        descriptors = D._breadth_job_skill_descriptors(
            job, tmp_path,
            {"pipeline": "l1", "language": "go", "mode": "light"},
        )
        assert descriptors, layer
        assert all(len(item["sha256"]) == 64 for item in descriptors)
        assert all(item["top_level_checklist_step_ids"] for item in descriptors)


def test_closed_depth_registry_rejects_fake_scanner_niche_and_ghost(tmp_path: Path):
    for destination in (
        "depth-ghost", "depth-blind-spot-a", "depth-scanner",
        "depth-niche-semantic-gap",
    ):
        _write_manifest(tmp_path, destination)
        issues = V._validate_spawn_manifest_schema(tmp_path, mode="light")
        assert any("noncanonical depth skill destination" in issue for issue in issues), (
            destination, issues
        )
        _breadth, depth = D._parse_sc_skill_bindings(tmp_path, "evm")
        assert depth == {}


def test_skill_resolution_is_ecosystem_local_with_shared_catalog_only(
    tmp_path: Path, monkeypatch,
):
    home = tmp_path / "home"
    for tree, marker in (("evm", "evm"), ("solana", "solana")):
        path = home / "agents" / "skills" / tree / "collision" / "SKILL.md"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"# {marker}\n", encoding="utf-8")
    shared = home / "agents" / "skills" / "injectable" / "shared-only" / "SKILL.md"
    shared.parent.mkdir(parents=True, exist_ok=True)
    shared.write_text("# shared\n", encoding="utf-8")
    monkeypatch.setattr(D, "plamen_home", lambda: home)

    assert "/solana/collision/" in D._sc_skill_path_for_name(
        "COLLISION", "solana"
    ).as_posix()
    assert "/evm/collision/" in D._sc_skill_path_for_name(
        "COLLISION", "evm"
    ).as_posix()
    # Aptos must not fall across to EVM/Solana. The shared catalog remains valid.
    assert D._sc_skill_path_for_name("COLLISION", "aptos") is None
    assert "/injectable/shared-only/" in D._sc_skill_path_for_name(
        "SHARED_ONLY", "aptos"
    ).as_posix()
    assert D._sc_skill_path_for_name("COLLISION", "") is None


def test_wrong_ecosystem_manifest_binding_fails_and_is_not_dispatched(tmp_path: Path):
    _write_manifest(tmp_path)
    issues = V._validate_spawn_manifest_schema(
        tmp_path, mode="light", language="solana"
    )
    assert any(
        "outside active ecosystem solana" in issue and "ORACLE_ANALYSIS" in issue
        for issue in issues
    ), issues
    plan = D._breadth_dispatch_plan(
        scratchpad=tmp_path, project_root=tmp_path.as_posix(),
        config={
            "pipeline": "sc", "language": "solana", "mode": "light",
            "cli_backend": "claude",
        },
        attempt=1,
    )
    oracle = next(
        entry for entry in plan if entry["job"]["output"] == "analysis_oracle.md"
    )
    assert oracle["skill_dispatch"] == []
    assert "oracle-analysis/SKILL.md" not in oracle["prompt"]


def test_canonical_depth_binding_reaches_the_scheduled_worker_prompt(tmp_path: Path):
    _write_manifest(tmp_path, "depth-external")
    _breadth, depth = D._parse_sc_skill_bindings(tmp_path, "evm")
    assert depth == {"external": ["ORACLE_ANALYSIS"]}
    job = next(
        job for job in D._depth_worker_jobs(tmp_path, _config("claude"))
        if job["role"] == "external"
    )
    prompt = D._build_depth_worker_prompt(
        job=job, scratchpad=tmp_path, project_root=tmp_path.as_posix(),
        config=_config("claude"), attempt=1,
    )
    assert "oracle-analysis/SKILL.md" in prompt
    assert "ORACLE_ANALYSIS" in prompt


def test_depth_dispatch_binds_role_and_injected_skill_for_every_backend(
    tmp_path: Path,
):
    _write_manifest(tmp_path, "depth-external")
    observed = []
    for backend in ("claude", "claude-headless", "codex"):
        plan = D._depth_dispatch_plan(
            scratchpad=tmp_path,
            project_root=tmp_path.as_posix(),
            config=_config(backend),
            attempt=1,
        )
        external = next(
            entry for entry in plan if entry["job"]["role"] == "external"
        )
        methods = external["methodology_dispatch"]
        assert any(
            item["path"].endswith("/agents/depth-external.md")
            for item in methods
        )
        oracle = next(item for item in methods if item["skill"] == "ORACLE_ANALYSIS")
        assert oracle["path"].endswith("/evm/oracle-analysis/SKILL.md")
        assert oracle["top_level_checklist_step_ids"]
        assert external["dispatch_contract_sha256"] in external["prompt"]
        assert D.TRACE_JSON_BEGIN in external["prompt"]
        assert "`ORACLE_ANALYSIS` /" in external["prompt"]
        assert "~/.claude/" not in external["prompt"]
        observed.append((external["prompt_sha256"], methods))
    assert observed[0] == observed[1] == observed[2]


def test_triggered_signature_niche_attests_exact_skill_obligations(tmp_path: Path):
    job = {
        "agent_id": "niche-signature-verification-audit",
        "role": "signature_verification_audit",
        "output": "niche_signature_verification_audit_findings.md",
        "category": "niche",
        "focus": "signature verification",
    }
    descriptors = D._depth_job_methodology_descriptors(
        job, tmp_path, _config("claude")
    )
    assert len(descriptors) == 1
    descriptor = descriptors[0]
    assert descriptor["skill"] == "SIGNATURE_VERIFICATION_AUDIT"
    assert descriptor["path"].endswith(
        "/agents/skills/niche/signature-verification-audit/SKILL.md"
    )
    assert "h2:check-10-aggregate-signature-merkle-leaf-linkage" in descriptor[
        "top_level_checklist_step_ids"
    ]
    plan = D._depth_dispatch_plan(
        scratchpad=tmp_path,
        project_root=tmp_path.as_posix(),
        config=_config("claude"),
        attempt=1,
        jobs=[job],
    )[0]
    assert descriptor["sha256"] in plan["prompt"]
    assert "`SIGNATURE_VERIFICATION_AUDIT` /" in plan["prompt"]


@pytest.mark.parametrize("mode", ["light", "core", "thorough"])
def test_every_scheduled_depth_job_has_a_bound_methodology(
    tmp_path: Path, mode: str,
):
    config = {**_config("claude"), "mode": mode}
    plan = D._depth_dispatch_plan(
        scratchpad=tmp_path,
        project_root=tmp_path.as_posix(),
        config=config,
        attempt=1,
    )
    assert plan
    assert all(entry["methodology_dispatch"] for entry in plan), [
        entry["job"] for entry in plan if not entry["methodology_dispatch"]
    ]


@pytest.mark.parametrize("backend", ["claude-pty", "claude-headless", "codex"])
def test_depth_mixed_retry_preserves_last_executed_row_dispatch(
    tmp_path: Path, backend: str,
):
    config = _config(backend)
    jobs = D._depth_worker_jobs(tmp_path, config)
    outputs = {str(job["output"]) for job in jobs}
    first_plan = D._depth_dispatch_plan(
        scratchpad=tmp_path,
        project_root=tmp_path.as_posix(),
        config=config,
        attempt=1,
        jobs=jobs,
    )
    D._write_depth_dispatch_contract(
        tmp_path, config, backend, first_plan, dispatched_outputs=outputs
    )
    first = json.loads(tmp_path.joinpath("skill_dispatch.json").read_text())[
        "phases"
    ]["depth"]
    preserved_output, retry_output = sorted(outputs)[:2]
    preserved_first = next(
        entry for entry in first["entries"] if entry["output"] == preserved_output
    )
    retry_first = next(
        entry for entry in first["entries"] if entry["output"] == retry_output
    )

    retry_plan = D._depth_dispatch_plan(
        scratchpad=tmp_path,
        project_root=tmp_path.as_posix(),
        config=config,
        attempt=2,
        jobs=jobs,
        retry_reasons_by_output={retry_output: ["targeted retry"]},
    )
    D._write_depth_dispatch_contract(
        tmp_path, config, backend, retry_plan,
        dispatched_outputs={retry_output},
    )
    second = json.loads(tmp_path.joinpath("skill_dispatch.json").read_text())[
        "phases"
    ]["depth"]
    assert next(
        entry for entry in second["entries"] if entry["output"] == preserved_output
    ) == preserved_first
    assert next(
        entry for entry in second["entries"] if entry["output"] == retry_output
    )["prompt_sha256"] != retry_first["prompt_sha256"]


def test_depth_serial_claude_and_codex_launch_same_canonical_prompt(
    tmp_path: Path, monkeypatch,
):
    codex_root = tmp_path / "codex"
    claude_root = tmp_path / "claude"
    codex_root.mkdir()
    claude_root.mkdir()
    for root in (codex_root, claude_root):
        _write_manifest(root, "depth-external")
    job = next(
        item for item in D._depth_worker_jobs(codex_root, _config("claude"))
        if item["role"] == "external"
    )
    phase = D.Phase(
        name="depth", section_markers=["Phase 4b"],
        expected_artifacts=[job["output"]], base_timeout_s=60,
        min_artifact_bytes=1,
    )
    codex_config = _runtime_config("codex", codex_root)
    _write_depth_worker_inputs(
        codex_root,
        phase=phase,
        config=codex_config,
        agent_id=str(job["agent_id"]),
        output=str(job["output"]),
    )
    claude_config = {
        **_runtime_config("claude", claude_root),
        "claude_exec_mode": "headless",
    }
    _write_depth_worker_inputs(
        claude_root,
        phase=phase,
        config=claude_config,
        agent_id=str(job["agent_id"]),
        output=str(job["output"]),
    )
    launched: dict[str, str] = {}

    monkeypatch.setattr(D, "_depth_worker_jobs", lambda sp, cfg: [job])
    monkeypatch.setattr(
        D, "_depth_worker_output_complete",
        lambda sp, ph, row, **kw: sp.joinpath(row["output"]).exists(),
    )
    monkeypatch.setattr(D, "_synthesize_depth_lifecycle_artifacts", lambda *a, **k: None)
    monkeypatch.setattr(D, "_depth_da_job_if_required", lambda *a, **k: [])

    def finish(label: str, prompt: str, scratchpad: Path) -> int:
        launched[label] = prompt
        scratchpad.joinpath(job["output"]).write_text("done", encoding="utf-8")
        return 0

    monkeypatch.setattr(
        D, "_run_one_codex_exec",
        lambda **kw: finish("codex", kw["prompt"], kw["scratchpad"]),
    )
    monkeypatch.setattr(
        D, "_run_one_claude_headless_breadth_worker",
        lambda **kw: finish(
            "claude-headless", kw["prompt"], kw["scratchpad"]
        ),
    )

    assert D._run_depth_codex_fanout(
        phase=phase, config=codex_config, scratchpad=codex_root, attempt=1
    ) == 0
    assert D._run_depth_codex_fanout(
        phase=phase, config=claude_config, scratchpad=claude_root, attempt=1
    ) == 0
    def canonical_run_projection(prompt: str, root: Path) -> str:
        normalized = prompt.replace(root.as_posix(), "{SCRATCHPAD}")
        # Projection and dispatch digests correctly bind the run-specific
        # scratchpad/PhaseIO authority. Backend parity concerns the resulting
        # methodology and instructions, not equality of those run identities.
        return re.sub(
            r"(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])",
            "{RUN_BOUND_DIGEST}",
            normalized,
        )

    codex_prompt = canonical_run_projection(launched["codex"], codex_root)
    claude_prompt = canonical_run_projection(
        launched["claude-headless"], claude_root
    )
    assert codex_prompt == claude_prompt
    assert "oracle-analysis/SKILL.md" in launched["claude-headless"]
    assert D.TRACE_JSON_BEGIN in launched["claude-headless"]


@pytest.mark.parametrize("backend", ["codex", "claude-headless"])
def test_parallel_backend_fanout_launches_one_canonical_prompt_per_row(
    tmp_path: Path, monkeypatch, backend: str,
):
    _write_manifest(tmp_path)
    phase = D.Phase(
        name="breadth", section_markers=["Phase 3"],
        expected_artifacts=["analysis_*.md"], base_timeout_s=60,
        min_artifact_bytes=200,
    )
    config = _runtime_config(backend, tmp_path)
    for job in D._breadth_worker_jobs(tmp_path, config):
        _write_exact_worker_inputs(
            tmp_path,
            phase=phase,
            config=config,
            agent_id=str(job["agent_id"]),
            output=str(job["output"]),
        )
    calls: list[tuple[str, str]] = []

    def complete(output: str, prompt: str) -> None:
        agent = next(
            job["agent_id"] for job in D._breadth_worker_jobs(tmp_path, _config("codex"))
            if job["output"] == output
        )
        tmp_path.joinpath(output).write_text(
            f"<!-- PLAMEN_ARTIFACT: {output} -->\n"
            f"<!-- PLAMEN_OWNER: {agent} -->\n"
            "<!-- PLAMEN_STATUS: IN_PROGRESS -->\n"
            "<!-- PLAMEN_PHASE: breadth -->\n<!-- PLAMEN_VERSION: 1 -->\n"
            f"<!-- AGENT_ROW: {agent} -->\n<!-- EXPECTED_OUTPUT: {output} -->\n\n"
            "# Analysis\n\n## No Findings\n\n" + ("evidence " * 40) +
            "\n<!-- PLAMEN_STATUS: COMPLETE -->\n",
            encoding="utf-8",
        )

    def fake_codex(**kwargs):
        output = kwargs["expected_outputs"][0]
        prompt = kwargs["prompt"]
        calls.append((output, prompt))
        complete(output, prompt)
        return 0

    def fake_headless(**kwargs):
        output = kwargs["job"]["output"]
        prompt = kwargs["prompt"]
        calls.append((output, prompt))
        complete(output, prompt)
        return 0

    monkeypatch.setattr(D, "_run_one_codex_exec", fake_codex)
    monkeypatch.setattr(D, "_run_one_claude_headless_breadth_worker", fake_headless)
    monkeypatch.setattr(D, "_translate_prompt_for_codex", lambda prompt, **kw: prompt)
    rc = D._run_breadth_backend_fanout(
        backend=backend, phase=phase,
        config=config,
        scratchpad=tmp_path, attempt=1, timeout=60, effective_model="test",
    )
    assert rc == 0
    assert {output for output, _prompt in calls} == {
        "analysis_oracle.md", "analysis_state.md", "analysis_access.md",
    }
    oracle_prompt = next(prompt for output, prompt in calls if output == "analysis_oracle.md")
    assert "oracle-analysis/SKILL.md" in oracle_prompt
    assert "## Step Execution Trace" in oracle_prompt


def test_empty_structured_signal_suppresses_stale_positive_prose(tmp_path: Path):
    tmp_path.joinpath("template_recommendations.md").write_text(
        "# Recommendations\n\n## BINDING MANIFEST\n\n### EVM Skills\n\n"
        "| Skill | Trigger | Required | Rationale |\n|---|---|---|---|\n"
        "| ORACLE_ANALYSIS | oracle | NO | no current selection |\n\n"
        '<!-- PLAMEN_SIGNALS: {"required_skills":[]} -->\n\n'
        "## Template / Skill Recommendations\n\n"
        "- ORACLE_ANALYSIS -- recommended by stale prose.\n",
        encoding="utf-8",
    )
    assert V._reconcile_skill_manifest_sources(tmp_path) == 0
    text = tmp_path.joinpath("template_recommendations.md").read_text(encoding="utf-8")
    assert "ORACLE_ANALYSIS" not in V._required_skill_tokens_from_binding_manifest(text)


def test_selected_absent_canonical_row_fails_loudly(tmp_path: Path):
    tmp_path.joinpath("template_recommendations.md").write_text(
        "# Recommendations\n\n## BINDING MANIFEST\n\n### EVM Skills\n\n"
        "| Skill | Trigger | Required | Rationale |\n|---|---|---|---|\n"
        "| TOKEN_FLOW_TRACING | flow | NO | no |\n\n"
        '<!-- PLAMEN_SIGNALS: {"required_skills":["ORACLE_ANALYSIS"]} -->\n',
        encoding="utf-8",
    )
    assert V._reconcile_skill_manifest_sources(tmp_path) == 0
    issues = V._selected_skill_manifest_issues(tmp_path)
    assert issues and "ORACLE_ANALYSIS" in issues[0]


def test_checkmark_required_cell_is_recognized():
    for value in ("✓", "✔", "☑", "✅", "[x]", "YES"):
        assert V._required_cell_is_yes(value), value


def test_legacy_step_heading_fallback_excludes_nonmethod_sections(tmp_path: Path):
    skill = tmp_path / "SKILL.md"
    skill.write_text(
        "# Legacy Skill\n\n## Methodology\n\n"
        "### Step 1: Inventory\n### Step 2: Trace state\n"
        "## Output Schema\n## Finding Template\n## References\n",
        encoding="utf-8",
    )
    assert D._skill_checklist_step_ids(skill) == ["1", "2"]


def test_legacy_numbered_h2_fallback_and_whole_method_obligation(tmp_path: Path):
    numbered = tmp_path / "numbered.md"
    numbered.write_text(
        "# L1 Skill\n\n## 1. Fingerprint\n## 2. Invariant checks\n"
        "## 3. Output schema\n## 4. Known bug exemplars\n"
        "## 5. Fallback if primitives unavailable\n",
        encoding="utf-8",
    )
    assert D._skill_checklist_step_ids(numbered) == ["1", "2", "5"]
    opaque = tmp_path / "opaque.md"
    opaque.write_text("# Opaque Skill\n\nAnalyze every relevant path.\n", encoding="utf-8")
    assert D._skill_checklist_step_ids(opaque) == ["WHOLE_METHOD/UNENUMERATED"]
    descriptor = D._skill_dispatch_descriptor("OPAQUE", opaque)
    assert descriptor["enumeration_status"] == "UNENUMERATED_WHOLE_METHOD"


def test_substantive_h2_slug_fallback_is_stable_and_excludes_format_sections(
    tmp_path: Path,
):
    skill = tmp_path / "legacy_h2.md"
    skill.write_text(
        "# Skill\n\n## Processing Protocol (MANDATORY)\n"
        "## CHECK: State/Rate Binding\n## Output Format\n"
        "## References\n## Agent Prompt Template\n",
        encoding="utf-8",
    )
    first = D._skill_checklist_step_ids(skill)
    second = D._skill_checklist_step_ids(skill)
    assert first == second == [
        "h2:processing-protocol-mandatory",
        "h2:check-state-rate-binding",
    ]


def test_substantive_h2_slug_collisions_get_content_stable_suffixes(tmp_path: Path):
    skill = tmp_path / "collision.md"
    skill.write_text(
        "# Skill\n\n## Check A/B\n## Check A B\n",
        encoding="utf-8",
    )
    ids = D._skill_checklist_step_ids(skill)
    assert len(ids) == 2
    assert ids[0] != ids[1]
    assert all(item.startswith("h2:check-a-b-") for item in ids)
    skill.write_text(
        "# Skill\n\n## Check A B\n## Check A/B\n",
        encoding="utf-8",
    )
    assert set(D._skill_checklist_step_ids(skill)) == set(ids)
