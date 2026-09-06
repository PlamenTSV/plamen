from __future__ import annotations

import inspect
from pathlib import Path
from types import SimpleNamespace

import pytest

import claude_provider_policy as policy


def _standard() -> policy.ClaudeHeadlessProviderPolicy:
    return policy.compile_standard_claude_headless_provider_policy(
        phase="provider",
        launch_model="fixture-model",
        ecosystem="evm",
        tool_policy=("filesystem", "network"),
        desired_auth_route=policy.DEFAULT_AUTH_ROUTE,
    )


def test_public_policy_is_driver_free_and_secret_free() -> None:
    source = inspect.getsource(policy)
    assert "plamen_driver" not in source
    assert "test_claude" not in source
    compiled = _standard()
    assert compiled.launch_model == "fixture-model"
    assert compiled.required_capabilities == ()
    assert compiled.forbidden_capabilities == ("remote-agents",)
    assert "Agent" in compiled.phase_tool_policy["forbidden_tools"]
    assert "WebSearch" in compiled.phase_tool_policy["builtin_tools"]
    assert policy.FUNCTIONAL_CONTROLS["DISABLE_UPDATES"] == "1"
    assert policy.FUNCTIONAL_CONTROLS["DISABLE_AUTOUPDATER"] == "1"
    assert (
        policy.FUNCTIONAL_CONTROLS[
            "CLAUDE_CODE_DISABLE_OFFICIAL_MARKETPLACE_AUTOINSTALL"
        ]
        == "1"
    )
    assert (
        policy.FUNCTIONAL_CONTROLS["ENABLE_CLAUDEAI_MCP_SERVERS"]
        == "false"
    )
    assert "CLAUDE_CODE_DISABLE_CLAUDEAI_MCP_SERVERS" not in (
        policy.FUNCTIONAL_CONTROLS
    )


def test_shared_authority_returns_only_attempt_independent_base_argv(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = tmp_path / "project"
    scratchpad = project / ".scratchpad"
    extra = tmp_path / "external-source"
    project.mkdir()
    scratchpad.mkdir()
    extra.mkdir()
    captured = {}
    profile_flags = ("--tools", "Read,Write")
    final = (
        str(Path(__file__).resolve()),
        "-p",
        "--model",
        "fixture-model",
        *profile_flags,
    )

    class FakePreparation:
        eligible = True
        record = {
            "debts": [],
            "headless_profile": {"cli_flags": list(profile_flags)},
        }

        def public_headless_arguments(self):
            return {
                "environment": {},
                "environment_allowlist": ["PATH"],
            }

        def command_for_bound_stdin(self):
            return final

    def prepare(**kwargs):
        captured.update(kwargs)
        return FakePreparation()

    monkeypatch.setattr(policy, "prepare_claude_provider", prepare)
    authority = policy.compile_claude_headless_provider_authority(
        policy=_standard(),
        run_id="run-fixture",
        cwd=project,
        session_id="00000000-0000-4000-8000-000000000001",
        configured_claude_bin="claude",
        ambient_environment={"PATH": "fixture"},
        settings_evidence={},
        stored_subscription_source_path=None,
        source_config_dir=None,
        project_root=project,
        trusted_cwds=(project, extra),
        startup_authority_binding={"fixture": "startup"},
        startup_scratchpad=scratchpad,
        source_snapshot_sha256="a" * 64,
    )
    assert authority.base_argv_template == final[:-len(profile_flags)]
    assert authority.base_argv_template[1:3] == ("-p", "--model")
    assert tuple(captured["trusted_cwds"]) == (
        project.resolve(),
        extra.resolve(),
    )
    assert authority.public_arguments["environment"] == {}
    assert authority.runtime_local_inputs["trusted_cwds"] == (
        project.resolve(),
        extra.resolve(),
    )


def test_shared_authority_rejects_nonseparable_command_template(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = tmp_path / "project"
    scratchpad = project / ".scratchpad"
    project.mkdir()
    scratchpad.mkdir()

    fake = SimpleNamespace(
        eligible=True,
        record={
            "debts": [],
            "headless_profile": {"cli_flags": ["--tools", "Read"]},
        },
        public_headless_arguments=lambda: {
            "environment": {},
            "environment_allowlist": ["PATH"],
        },
        command_for_bound_stdin=lambda: (
            "claude",
            "--tools",
            "Read",
            "-p",
        ),
    )
    monkeypatch.setattr(
        policy,
        "prepare_claude_provider",
        lambda **_kwargs: fake,
    )
    with pytest.raises(
        policy.ClaudeProviderPolicyError,
        match="not canonically separable",
    ):
        policy.compile_claude_headless_provider_authority(
            policy=_standard(),
            run_id="run-fixture",
            cwd=project,
            session_id="00000000-0000-4000-8000-000000000002",
            configured_claude_bin="claude",
            ambient_environment={"PATH": "fixture"},
            settings_evidence={},
            stored_subscription_source_path=None,
            source_config_dir=None,
            project_root=project,
            trusted_cwds=(project,),
            startup_authority_binding={"fixture": "startup"},
            startup_scratchpad=scratchpad,
            source_snapshot_sha256="a" * 64,
        )
