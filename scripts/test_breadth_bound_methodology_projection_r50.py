"""Restricted breadth receives bound, policy-consistent methodology in-prompt."""
from __future__ import annotations

import hashlib
from pathlib import Path
from types import SimpleNamespace

import pytest

import artifact_ledger as ledger
import claude_worker_prompt_consistency as consistency
import plamen_driver as D
from phase_io_contracts import LaunchSpec, resolve_phase_io_contract
from test_claude_launch_authority_fixtures import OFFLINE_OAUTH_TOKEN
from test_headless_driver_cutover_p0_am import _install_offline_driver_provider
from test_support_startup_permit import FIXTURE_RUN_ID, durable_startup_permit


# Exact breadth roster and assigned methodology denominator observed in the r51
# DODO launch.  B6 alone has the additional cross-VM injectable.
_R51_COMMON_SKILLS = (
    "CENTRALIZATION_RISK",
    "CROSS_CHAIN_MESSAGE_INTEGRITY",
    "DEX_INTEGRATION_SECURITY",
    "ECONOMIC_DESIGN_AUDIT",
    "EXTERNAL_PRECONDITION_AUDIT",
    "SEMI_TRUSTED_ROLES",
    "TEMPORAL_PARAMETER_STALENESS",
    "TOKEN_FLOW_TRACING",
)
_R51_BREADTH_ROWS = (
    ("B1", "core_state_temporal", "analysis_core_state_temporal.md", _R51_COMMON_SKILLS),
    ("B2", "access_control_roles", "analysis_access_control_roles.md", _R51_COMMON_SKILLS),
    ("B3", "economic_centralization", "analysis_economic_centralization.md", _R51_COMMON_SKILLS),
    ("B4", "token_flow_timing", "analysis_token_flow_timing.md", _R51_COMMON_SKILLS),
    ("B5", "storage_layout_upgrade", "analysis_storage_layout_upgrade.md", _R51_COMMON_SKILLS),
    (
        "B6",
        "cross_chain_message_integrity",
        "analysis_cross_chain_message_integrity.md",
        (*_R51_COMMON_SKILLS, "CROSS_VM_SERIALIZATION_CONFORMANCE"),
    ),
    ("B7", "external_precondition_dex", "analysis_external_precondition_dex.md", _R51_COMMON_SKILLS),
)


def _breadth_fixture(tmp_path: Path) -> tuple[Path, Path, dict[str, str], dict[str, str]]:
    project = tmp_path / "project"
    scratchpad = project / ".scratchpad"
    source = project / "contracts"
    source.mkdir(parents=True)
    config = {
        "pipeline": "sc",
        "mode": "thorough",
        "language": "evm",
        "cli_backend": "claude",
        "project_root": str(project),
        "scratchpad": str(scratchpad),
    }
    job = {
        "agent_id": "B1",
        "focus_area": "token_flow",
        "output": "analysis_token_flow.md",
    }
    inputs = D._typed_worker_registered_input_paths(
        phase_name="breadth",
        scratchpad=scratchpad,
        config=config,
        agent_id="B1",
        output=job["output"],
        focus_area=job["focus_area"],
        attempt=1,
    )
    for relative in inputs:
        path = scratchpad / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"# Bound input: {relative}\n", encoding="utf-8")
    return project, scratchpad, config, job


def test_live_style_breadth_prompt_is_self_contained_and_consistent(
    tmp_path: Path,
) -> None:
    project, scratchpad, config, job = _breadth_fixture(tmp_path)
    skill_path = D._sc_skill_path_for_name("TOKEN_FLOW_TRACING", "evm")
    assert skill_path is not None
    descriptor = D._skill_dispatch_descriptor("TOKEN_FLOW_TRACING", skill_path)
    prompt = D._build_breadth_worker_prompt(
        job=job,
        scratchpad=scratchpad,
        project_root=str(project),
        config=config,
        attempt=1,
        skill_descriptors=[descriptor],
    )

    assert skill_path.read_text(encoding="utf-8").strip() in prompt
    assert descriptor["sha256"] in prompt
    assert D.plamen_home().as_posix() not in prompt
    assert "~/.claude/" not in prompt
    assert "read `C:/" not in prompt.casefold()
    assert D._claude_methodology_read_roots("breadth") == ()

    inputs = D._typed_worker_registered_input_paths(
        phase_name="breadth",
        scratchpad=scratchpad,
        config=config,
        agent_id="B1",
        output=job["output"],
        focus_area=job["focus_area"],
        attempt=1,
    )
    issues = consistency.validate_claude_worker_prompt_consistency(
        prompt,
        phase_io_inputs=[scratchpad / relative for relative in inputs],
        phase_io_outputs=[scratchpad / job["output"]],
        policy_tools=["Read", "Write", "Glob", "Grep"],
        safe_search_roots=[project / "contracts"],
        project_root=project,
        scratchpad_root=scratchpad,
    )
    assert issues == ()


def test_bound_skill_advertised_digest_drift_fails_closed() -> None:
    skill_path = D._sc_skill_path_for_name("TOKEN_FLOW_TRACING", "evm")
    assert skill_path is not None
    with pytest.raises(ValueError, match="digest drifted"):
        D._render_bound_methodology_projection(
            skill_path,
            title="skill TOKEN_FLOW_TRACING",
            expected_sha256="0" * 64,
        )


def test_bound_methodology_path_identity_drift_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    skill_path = D._sc_skill_path_for_name("TOKEN_FLOW_TRACING", "evm")
    assert skill_path is not None
    digest = hashlib.sha256(skill_path.read_bytes()).hexdigest()
    monkeypatch.setattr(D.os.path, "samestat", lambda _left, _right: False)
    with pytest.raises(ValueError, match="changed during projection"):
        D._render_bound_methodology_projection(
            skill_path,
            title="skill TOKEN_FLOW_TRACING",
            expected_sha256=digest,
        )


def test_transactional_breadth_leaf_uses_projection_without_global_read_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_offline_driver_provider(monkeypatch)
    project, scratchpad, config, job = _breadth_fixture(tmp_path)
    config.update({
        "_run_id": FIXTURE_RUN_ID,
        "_auxiliary_writable_root_startup_binding": durable_startup_permit(
            scratchpad
        ),
        "_audit_snapshot": {"snapshot_digest": "a" * 64},
        "claude_exec_mode": "headless",
        "claude_auth_route": "OAUTH_TOKEN",
        "claude_oauth_token": OFFLINE_OAUTH_TOKEN,
    })
    skill_path = D._sc_skill_path_for_name("TOKEN_FLOW_TRACING", "evm")
    assert skill_path is not None
    descriptor = D._skill_dispatch_descriptor("TOKEN_FLOW_TRACING", skill_path)
    prompt = D._build_breadth_worker_prompt(
        job=job,
        scratchpad=scratchpad,
        project_root=str(project),
        config=config,
        attempt=1,
        skill_descriptors=[descriptor],
    )
    inputs = tuple(D._typed_worker_registered_input_paths(
        phase_name="breadth",
        scratchpad=scratchpad,
        config=config,
        agent_id="B1",
        output=job["output"],
        focus_area=job["focus_area"],
        attempt=1,
    ))
    phase = D.Phase(
        name="breadth",
        section_markers=["## Breadth"],
        expected_artifacts=[job["output"]],
        base_timeout_s=30,
        model="opus",
        min_artifact_bytes=1,
    )
    contract = resolve_phase_io_contract(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        phase="breadth",
        work_unit_id="worker.b1",
        exact_outputs=(job["output"],),
        exact_inputs=inputs,
    )
    launch = LaunchSpec(
        work_unit_key=contract.key,
        pipeline=contract.pipeline,
        mode=contract.mode,
        ecosystem=contract.ecosystem,
        backend=contract.backend,
        model="claude-opus-5",
        timeout_s=30,
        exec_mode="headless",
        tool_policy=("filesystem",),
    )
    ledger.record_work_unit_inputs(
        scratchpad,
        project,
        contract,
        launch,
        run_id=FIXTURE_RUN_ID,
    )
    captured: dict[str, object] = {}

    def capture(**kwargs):
        captured.update(kwargs)
        return SimpleNamespace(stdout=b"", stderr=b"")

    monkeypatch.setattr(D, "execute_headless_worker", capture)
    monkeypatch.setattr(D, "_record_phase_cost", lambda *_a, **_k: None)
    monkeypatch.setattr(D, "detect_background_orphan", lambda *_a, **_k: None)
    assert D._run_transactional_headless_leaf(
        backend="claude",
        prompt=prompt,
        phase=phase,
        config=config,
        scratchpad=scratchpad,
        attempt=1,
        label="breadth-worker-B1",
        expected_outputs=[job["output"]],
        timeout=30,
        effective_model=launch.model,
        contract=contract,
        launch=launch,
        working_directory=str(project),
        analysis_directories=(str(project / "contracts"),),
    ) == 0
    effective_prompt = str(captured["prompt"])
    assert skill_path.read_text(encoding="utf-8").strip() in effective_prompt
    policy_path = Path(
        config["_claude_phase_tool_boundaries"]["breadth"]["policy_path"]
    )
    policy = D.claude_phase_tool_policy.load_policy(policy_path)
    assert policy["methodology_read_roots"] == []


def test_r51_seven_worker_skill_matrix_is_restricted_policy_consistent(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    scratchpad = project / ".scratchpad"
    (project / "contracts").mkdir(parents=True)
    scratchpad.mkdir()
    config = {
        "pipeline": "sc",
        "mode": "thorough",
        "language": "evm",
        "cli_backend": "claude",
        "project_root": str(project),
        "scratchpad": str(scratchpad),
    }

    rendered_workers: list[str] = []
    for agent_id, focus_area, output, skill_names in _R51_BREADTH_ROWS:
        job = {
            "agent_id": agent_id,
            "focus_area": focus_area,
            "output": output,
        }
        relative_inputs = D._typed_worker_registered_input_paths(
            phase_name="breadth",
            scratchpad=scratchpad,
            config=config,
            agent_id=agent_id,
            output=output,
            focus_area=focus_area,
            attempt=1,
        )
        input_paths = tuple(scratchpad / value for value in relative_inputs)
        for path in input_paths:
            path.parent.mkdir(parents=True, exist_ok=True)
            if not path.exists():
                path.write_text(f"# Bound input: {path.name}\n", encoding="utf-8")

        descriptors = []
        for skill_name in skill_names:
            skill_path = D._sc_skill_path_for_name(skill_name, "evm")
            assert skill_path is not None
            descriptors.append(D._skill_dispatch_descriptor(skill_name, skill_path))
        prompt = D._build_breadth_worker_prompt(
            job=job,
            scratchpad=scratchpad,
            project_root=str(project),
            config=config,
            attempt=1,
            skill_descriptors=descriptors,
        )
        snapshot = scratchpad / f"_prompt_breadth_worker_{agent_id}.attempt1.md"
        snapshot.write_text(prompt, encoding="utf-8")
        staged_output = scratchpad / "staged" / agent_id / output
        staged_output.parent.mkdir(parents=True, exist_ok=True)
        policy = D.claude_phase_tool_policy.build_policy_manifest(
            run_id=FIXTURE_RUN_ID,
            phase="breadth",
            attempt=1,
            expected_cwd=project,
            project_root=project,
            scratchpad_root=scratchpad,
            methodology_read_roots=(),
            exact_read_files=(*input_paths, snapshot),
            exact_write_files=(staged_output,),
            forbidden_read_files=(),
            receipt_directory=scratchpad / "receipts" / agent_id,
        )
        projection = D.claude_phase_tool_policy.build_model_visible_projection(
            policy,
            phase_io_input_paths=input_paths,
            private_exact_read_paths=(snapshot,),
        )
        effective_prompt = (
            prompt.rstrip()
            + "\n\n"
            + D.claude_phase_tool_policy.render_model_visible_supervisor_block(
                projection
            ).rstrip()
            + "\n"
        )

        consistency.require_claude_worker_prompt_consistency(
            effective_prompt,
            phase_io_inputs=input_paths,
            phase_io_outputs=(scratchpad / output,),
            policy_tools=D.claude_phase_tool_policy.provider_builtin_tools(policy),
            safe_search_roots=policy["safe_search_roots"],
            project_root=project,
            scratchpad_root=scratchpad,
        )
        for descriptor in descriptors:
            skill_bytes = Path(descriptor["path"]).read_text(encoding="utf-8").strip()
            assert skill_bytes in prompt
            assert descriptor["sha256"] in prompt
        centralization = next(
            Path(descriptor["path"]).read_text(encoding="utf-8")
            for descriptor in descriptors
            if descriptor["skill"] == "CENTRALIZATION_RISK"
        )
        assert "provided function and modifier\ninventories" in centralization
        assert "list_functions" not in centralization
        assert "analyze_modifiers" not in centralization
        assert "Use Slither" not in prompt
        assert "list_functions" not in prompt
        assert "analyze_modifiers" not in prompt
        rendered_workers.append(agent_id)

    assert rendered_workers == [f"B{index}" for index in range(1, 8)]
