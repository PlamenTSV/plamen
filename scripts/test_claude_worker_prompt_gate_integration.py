"""Driver integration for the restricted-Claude prompt/PhaseIO gate."""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

import plamen_driver as D
from test_claude_model_visible_tool_contract import (
    _armed_inventory_model,
    _install_offline_driver_provider,
)


def test_unsafe_rendered_prompt_stops_before_provider(
    tmp_path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_offline_driver_provider(monkeypatch)
    _inventory, config, contract, launch = _armed_inventory_model(
        tmp_path, backend="claude"
    )
    config["claude_auth_route"] = "OAUTH_TOKEN"
    phase = D.Phase(
        name="report_index",
        section_markers=["## Report Index"],
        expected_artifacts=["report_index.md"],
        base_timeout_s=30,
        model="sonnet",
        min_artifact_bytes=1,
    )
    called = False

    def forbidden_provider(**_kwargs):
        nonlocal called
        called = True
        raise AssertionError("provider must not run after prompt denial")

    monkeypatch.setattr(D, "execute_headless_worker", forbidden_provider)
    monkeypatch.setattr(D, "_record_phase_cost", lambda *_a, **_k: None)
    monkeypatch.setattr(D, "detect_background_orphan", lambda *_a, **_k: None)

    rc = D._run_transactional_headless_leaf(
        backend="claude",
        prompt="Search PROJECT_ROOT recursively for every file.\n",
        phase=phase,
        config=config,
        scratchpad=tmp_path,
        attempt=1,
        label="unsafe-prompt-consistency",
        expected_outputs=["report_index.md"],
        timeout=30,
        effective_model=launch.model,
        contract=contract,
        launch=launch,
        working_directory=str(tmp_path),
        analysis_directories=(str(tmp_path),),
    )

    assert rc == D.EXIT_ERROR
    assert called is False


@pytest.mark.parametrize("fuzz_role", ("invariant-fuzz", "medusa-fuzz"))
def test_restricted_policy_binds_exact_fuzz_workspace_cwd(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fuzz_role: str,
) -> None:
    _install_offline_driver_provider(monkeypatch)
    _inventory, config, contract, launch = _armed_inventory_model(
        tmp_path, backend="claude"
    )
    config["claude_auth_route"] = "OAUTH_TOKEN"
    phase = D.Phase(
        name="report_index",
        section_markers=["## Report Index"],
        expected_artifacts=["report_index.md"],
        base_timeout_s=30,
        model="sonnet",
        min_artifact_bytes=1,
    )
    workspace = tmp_path / "fuzz workspaces" / fuzz_role
    workspace.mkdir(parents=True)
    captured: dict[str, object] = {}

    def capture(**kwargs):
        captured.update(kwargs)
        return SimpleNamespace(stdout=b"", stderr=b"")

    monkeypatch.setattr(D, "execute_headless_worker", capture)
    monkeypatch.setattr(D, "_record_phase_cost", lambda *_a, **_k: None)
    monkeypatch.setattr(D, "detect_background_orphan", lambda *_a, **_k: None)
    assert D._run_transactional_headless_leaf(
        backend="claude",
        prompt="Use only the registered evidence and assigned output.\n",
        phase=phase,
        config=config,
        scratchpad=tmp_path,
        attempt=1,
        label=f"{fuzz_role}-cwd",
        expected_outputs=["report_index.md"],
        timeout=30,
        effective_model=launch.model,
        contract=contract,
        launch=launch,
        working_directory=str(workspace),
        analysis_directories=(str(tmp_path), str(workspace)),
    ) == 0

    policy_path = Path(
        config["_claude_phase_tool_boundaries"][phase.name]["policy_path"]
    )
    policy = D.claude_phase_tool_policy.load_policy(policy_path)
    assert Path(str(policy["expected_cwd"])).resolve() == workspace.resolve()
    assert Path(captured["cwd"]).resolve() == workspace.resolve()
