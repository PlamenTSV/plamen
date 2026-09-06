"""WER must carry exactly the Claude launch authority frozen by WorkPlan."""

from __future__ import annotations

import json
import os
from pathlib import Path
from types import SimpleNamespace
import sys

import pytest

import claude_executable_observation as E
import claude_launch_security as L
from claude_headless_profile import compile_claude_headless_profile
import test_worker_execution_receipts as fixtures
import worker_execution_receipts as W


POLICY_KEY = "claude_launch_security"


@pytest.fixture(autouse=True)
def _single_link_windows_test_runtime(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if os.name == "nt" and int(getattr(Path(sys.executable).stat(), "st_nlink", 1)) != 1:
        reviewed = Path(r"C:\p27rt\python.exe")
        if reviewed.is_file() and int(getattr(reviewed.stat(), "st_nlink", 1)) == 1:
            monkeypatch.setattr(sys, "executable", str(reviewed.resolve(strict=True)))


def _request(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[dict[str, object], dict[str, object]]:
    monkeypatch.setattr(
        E,
        "run_owned_process",
        lambda command, **kwargs: SimpleNamespace(
            args=tuple(command),
            returncode=0,
            stdout="2.1.220 (Claude Code)\n",
            stderr="",
            process_tree_terminated=True,
        ),
    )
    executable = E.observe_claude_executable(
        configured_claude_bin=str(Path(sys.executable).resolve(strict=True)),
        environment={},
    )
    profile = compile_claude_headless_profile(
        claude_code_version="2.1.220",
        cwd=str(tmp_path.resolve()),
        accepted_models=("claude-opus", "claude-opus-5"),
        permission_mode="bypassPermissions",
        builtin_tools=("Read", "Write"),
        required_tools=("Read", "Write"),
        forbidden_tools=("Bash", "Task", "WebFetch", "WebSearch"),
        mcp_server_names=(),
        customization_mode="SAFE_MODE",
        accepted_api_key_sources=("none",),
    )
    auth = L.compile_claude_auth_route_policy(
        claude_code_version="2.1.220",
        desired_route="STORED_SUBSCRIPTION_OAUTH",
    )
    policy = L.compile_claude_launch_security(
        headless_profile=profile,
        auth_route_policy=auth,
        executable_observation=executable,
        settings_authority=L.compile_claude_settings_authority(
            mode="SAFE_MODE",
            settings_sha256=None,
            external_policy_sha256=None,
        ),
        mcp_authority=L.compile_claude_mcp_authority(
            settings_mode="SAFE_MODE",
            server_names=(),
            source_manifest_sha256=None,
            selected_config_sha256=None,
        ),
        home_variable_policy="PRESERVE_TOOLCHAIN_HOME",
        phase_environment_policies=("base",),
        functional_controls={
            "CLAUDE_CODE_SUBPROCESS_ENV_SCRUB": "1",
            "DISABLE_AUTOUPDATER": "1",
        },
        expected_child_environment_key_set_sha256="8" * 64,
    )
    return (
        L.compile_claude_launch_security_request(
            policy=policy,
            executable_observation=executable,
        ),
        profile,
    )


def _configuration(
    tmp_path: Path,
    profile: dict[str, object],
) -> dict[str, object]:
    value = fixtures._claude_stream_configuration(tmp_path)
    value["expected_init_contract"] = profile["expected_init_contract"]
    return value


def _stream_bytes(tmp_path: Path) -> bytes:
    events = [
        {
            "type": "system",
            "subtype": "init",
            "uuid": "init-uuid",
            "session_id": fixtures.CLAUDE_STREAM_SESSION,
            "claude_code_version": "2.1.220",
            "cwd": str(tmp_path.resolve()),
            "model": "claude-opus-5",
            "permissionMode": "bypassPermissions",
            "apiKeySource": "none",
            "tools": ["Read", "Write"],
            "mcp_servers": [],
            "slash_commands": [],
            "output_style": "default",
            "skills": [],
            "plugins": [],
            "agents": [],
            "capabilities": [],
        },
        {
            "type": "assistant",
            "uuid": "assistant-root",
            "session_id": fixtures.CLAUDE_STREAM_SESSION,
            "parent_tool_use_id": None,
            "message": {
                "id": "msg-root",
                "type": "message",
                "role": "assistant",
                "content": [{"type": "text", "text": "complete"}],
                "model": "claude-opus-5",
                "stop_reason": "end_turn",
                "usage": {"input_tokens": 1, "output_tokens": 1},
            },
        },
        {
            "type": "result",
            "subtype": "success",
            "uuid": "result-uuid",
            "session_id": fixtures.CLAUDE_STREAM_SESSION,
            "duration_ms": 1,
            "duration_api_ms": 1,
            "is_error": False,
            "num_turns": 1,
            "result": "complete",
            "total_cost_usd": 0.0,
            "usage": {"input_tokens": 1, "output_tokens": 1},
            "modelUsage": {"claude-opus-5": {"inputTokens": 1}},
            "permission_denials": [],
            "stop_reason": "end_turn",
            "origin": {"kind": "human"},
        },
    ]
    return b"".join(
        json.dumps(item, separators=(",", ":")).encode() + b"\n"
        for item in events
    )


def _argv(provider: Path, profile: dict[str, object]) -> list[str]:
    return [
        *fixtures._claude_stream_argv(provider),
        *profile["cli_flags"],
    ]


def _write_plan(
    tmp_path: Path,
    *,
    stream_policy: dict[str, object],
    launch_policy: dict[str, object],
) -> None:
    path = tmp_path / "launch-inputs" / "plan.json"
    path.parent.mkdir(exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "schema": "plamen.worker_work_plan.v2",
                "completion_policy": {
                    "provider_stdout_evidence_configuration": stream_policy,
                    POLICY_KEY: launch_policy,
                },
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


def test_exact_workplan_request_arms_completes_and_replays(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = fixtures._runtime_case(
        tmp_path,
        label="security-exact",
        monkeypatch=monkeypatch,
    )
    fixtures._install_runtime_case(monkeypatch, case)
    kwargs = case.wer_kwargs()
    kwargs["parser_digest"] = fixtures.strict_json_digest
    completed = W.run_observed_worker(**kwargs)
    arm = json.loads(completed.arm_path.read_text(encoding="utf-8"))
    assert (
        arm["process_intent"]["claude_launch_security_request"]
        == case.launch_request
    )
    W.validate_staged_execution(
        scratchpad=tmp_path,
        receipt_path=completed.receipt_path,
        parser_digest=fixtures.strict_json_digest,
        expected_completion_sha256=completed.completion_sha256,
    )


@pytest.mark.parametrize("case", ("dropped", "substituted"))
def test_workplan_claude_security_cannot_be_dropped_or_substituted_before_popen(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    case: str,
) -> None:
    runtime_case = fixtures._runtime_case(
        tmp_path,
        label=f"security-{case}",
        monkeypatch=monkeypatch,
    )
    supplied = None
    if case == "substituted":
        supplied = json.loads(
            json.dumps(runtime_case.launch_request)
        )
        supplied["policy"]["expected_child_environment_key_set_sha256"] = "9" * 64
        policy_core = dict(supplied["policy"])
        policy_core.pop("policy_sha256")
        supplied["policy"]["policy_sha256"] = L._digest(policy_core)
        request_core = dict(supplied)
        request_core.pop("request_sha256")
        supplied["request_sha256"] = L._digest(request_core)
    monkeypatch.setattr(
        W.subprocess,
        "Popen",
        lambda *_args, **_kwargs: pytest.fail(
            "provider launched before Claude security reconciliation"
        ),
    )
    with pytest.raises(
        W.WorkerExecutionError,
        match="launch-security|launch security|WorkPlan Claude",
    ):
        kwargs = runtime_case.wer_kwargs()
        kwargs["claude_launch_security_request"] = supplied
        W.run_observed_worker(**kwargs)


def test_malformed_or_duplicate_workplan_never_becomes_unknown_security_authority() -> None:
    duplicate = (
        b'{"schema":"plamen.worker_work_plan.v2",'
        b'"completion_policy":{"claude_launch_security":null},'
        b'"completion_policy":{}}'
    )
    with pytest.raises(
        W.WorkerExecutionError,
        match="duplicate JSON keys",
    ):
        W._recognized_work_plan_claude_security_policy(duplicate)

    malformed = b'{"schema":"plamen.worker_work_plan.v2",'
    with pytest.raises(
        W.WorkerExecutionError,
        match="unambiguous UTF-8 JSON",
    ):
        W._recognized_work_plan_claude_security_policy(malformed)
