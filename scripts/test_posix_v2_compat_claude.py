from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess

import pytest

import claude_phase_tool_policy as POLICY
import posix_v2_compat_claude as CLAUDE
from phase_io_contracts import ArtifactSpec, LaunchSpec, PhaseIOContract, canonical_work_unit_key


SESSION = "11111111-2222-4333-8444-555555555555"


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _phase_io() -> tuple[PhaseIOContract, LaunchSpec]:
    key = canonical_work_unit_key("sc", "thorough", "evm", "claude", "recon", "worker.r1")
    contract = PhaseIOContract(
        pipeline="sc", mode="thorough", ecosystem="evm", backend="claude",
        phase="recon", work_unit_id="worker.r1",
        outputs=(ArtifactSpec(
            root="scratchpad", path="result.md", owner_key=key,
            artifact_class="REQUIRED", writer="MODEL", write_mode="CREATE",
        ),),
    )
    launch = LaunchSpec(
        work_unit_key=key, pipeline="sc", mode="thorough", ecosystem="evm",
        backend="claude", model="claude-sonnet-5", timeout_s=30,
        exec_mode="headless", tool_policy=("filesystem",),
    )
    return contract, launch


def _session(tmp_path: Path) -> dict[str, object]:
    core = {
        "schema": "plamen.posix_v2_compat_session.v1",
        "mode": CLAUDE.COMPATIBILITY_MODE,
        "run_id": "run-1", "backend": "claude",
        "project_root": str(tmp_path), "project_root_identity_sha256": "1" * 64,
        "scratchpad": str(tmp_path), "scratchpad_identity_sha256": "2" * 64,
        "creator_pid": os.getpid(), "interpreter_nonce_sha256": "3" * 64,
        "native_broker_authority": False, "wer_authority": False,
    }
    return {**core, "session_binding_sha256": _digest(core)}


def _observation(binary: Path, version: str = "2.1.270") -> dict[str, object]:
    flags = [
        # `--add-dir` is required: the worker cwd is the scratchpad, but the
        # audited source it must read lives outside it, and under
        # `--restricted --permission-mode dontAsk` the CLI denies those reads
        # without an explicit directory grant.
        "--add-dir",
        "--disable-slash-commands", "--input-format", "--mcp-config", "--model",
        "--no-chrome", "--no-session-persistence", "--output-format",
        "--permission-mode", "--permission-prompts", "--print", "--restricted",
        "--session-id", "--setting-sources", "--settings", "--strict-mcp-config",
        "--prompt-suggestions", "--tools", "--verbose",
    ]
    core = {
        "schema": "plamen.posix-v2-compat-claude-executable-observation.v1",
        "backend": "claude", "resolved_executable": str(binary), "version": version,
        "version_output_sha256": "4" * 64, "help_sha256": "5" * 64,
        "help_byte_count": 1, "supported_flags": flags,
        "executable_sha256": "6" * 64, "executable_byte_count": 1,
        "identity": {"device": 1, "inode": 2, "size": 1, "mode": 0o100755},
    }
    return {**core, "observation_sha256": _digest(core)}


def _boundary(tmp_path: Path, contract: PhaseIOContract, output: Path) -> dict[str, object]:
    policy_path = tmp_path / "policy.json"
    settings_path = tmp_path / "settings.json"
    mcp_path = tmp_path / "mcp.json"
    receipts = tmp_path / "receipts"
    policy, _ = POLICY.write_policy_bundle(
        policy_path=policy_path, settings_path=settings_path,
        hook_script=Path(POLICY.__file__), run_id="run-1", phase="recon", attempt=1,
        expected_cwd=tmp_path, project_root=tmp_path, scratchpad_root=tmp_path,
        methodology_read_roots=(), exact_read_files=(), exact_write_files=(output,),
        forbidden_read_files=(), receipt_directory=receipts,
    )
    mcp_path.write_bytes(POLICY.canonical_json_bytes({"mcpServers": {}}))
    return {
        "phase": "recon", "attempt": 1, "contract_key": contract.key,
        "contract_digest": contract.digest, "input_set_digest": "7" * 64,
        "manifest_digest": policy["manifest_digest"], "policy_path": str(policy_path),
        "settings_path": str(settings_path), "mcp_config_path": str(mcp_path),
        "receipt_directory": str(receipts), "write_namespace": str(output.parent),
    }


def _auth() -> CLAUDE.PosixV2CompatClaudeAuth:
    return CLAUDE.PosixV2CompatClaudeAuth(
        True, CLAUDE.AUTH_MODE, "firstParty", "NATIVE_DEFAULT_CONFIG_AND_KEYCHAIN", "8" * 64,
    )


def _plan(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> CLAUDE.PosixV2CompatClaudePlan:
    binary = tmp_path / "claude"
    binary.write_bytes(b"x")
    binary.chmod(0o700)
    output = tmp_path / "staged" / "result.md"
    output.parent.mkdir()
    contract, launch = _phase_io()
    monkeypatch.setattr(CLAUDE, "check_claude_native_auth", lambda **_kwargs: _auth())
    return CLAUDE.compile_posix_v2_compat_claude_plan(
        session_binding=_session(tmp_path), phase_io_contract=contract,
        phase_io_launch=launch, executable_observation=_observation(binary),
        provider_session_id=SESSION, prompt_bytes=b"audit\n", cwd=tmp_path,
        output_routes=[{"path": str(output)}],
        phase_tool_boundary=_boundary(tmp_path, contract, output),
        source_config_root=tmp_path,
        environment={
            "HOME": str(tmp_path), "PATH": "/bin",
            "CLAUDE_CODE_DISABLE_AUTO_MEMORY": "0",
        },
        max_stdout_bytes=1_000_000, max_stderr_bytes=10_000, max_line_bytes=10_000,
    )


def _usage_row(
    canonical_model: str, *, web_search_requests: int = 0,
) -> dict[str, object]:
    return {
        "inputTokens": 4,
        "outputTokens": 7,
        "cacheReadInputTokens": 11,
        "cacheCreationInputTokens": 3,
        "webSearchRequests": web_search_requests,
        "costUSD": 0.01,
        "provider": "firstParty",
        "canonicalModel": canonical_model,
    }


def _valid_events(tmp_path: Path) -> list[dict[str, object]]:
    return [
        {
            "type": "system", "subtype": "init", "uuid": "init",
            "session_id": SESSION, "claude_code_version": "2.1.270",
            "cwd": str(tmp_path), "model": "claude-sonnet-5",
            "permissionMode": "dontAsk", "apiKeySource": "none",
            "tools": ["Read", "Write", "Edit", "Glob", "Grep"],
            "mcp_servers": [], "plugins": [], "skills": [],
            "slash_commands": [], "plugin_errors": [],
            "agents": [
                "claude", "Explore", "general-purpose", "Plan",
                "statusline-setup",
            ],
            "capabilities": [
                "interrupt_receipt_v1", "interrupt_cancel_queued_v1",
                "msg_lifecycle_v1",
            ],
            "output_style": "default",
        },
        {
            "type": "assistant", "uuid": "assistant",
            "session_id": SESSION, "parent_tool_use_id": None,
            "message": {
                "id": "msg", "type": "message", "role": "assistant",
                "content": [{"type": "text", "text": "done"}],
                "model": "claude-sonnet-5", "stop_reason": None,
                "usage": {"input_tokens": 1, "output_tokens": 1},
            },
        },
        {
            "type": "result", "subtype": "success", "uuid": "result",
            "session_id": SESSION, "duration_ms": 1, "duration_api_ms": 1,
            "is_error": False, "num_turns": 1, "result": "done",
            "total_cost_usd": 0.0,
            "usage": {"input_tokens": 1, "output_tokens": 1},
            "modelUsage": {
                "claude-sonnet-5": _usage_row("claude-sonnet-5"),
                "claude-haiku-4-5-20251001": _usage_row(
                    "claude-haiku-4-5"
                ),
            },
            "permission_denials": [], "stop_reason": "end_turn",
            "terminal_reason": "completed", "origin": {"kind": "human"},
            "subagent_stats": {
                "spawned": 0, "completed": 0, "failed": 0,
                "by_type": {},
            },
        },
    ]


def _stream(events: list[dict[str, object]]) -> bytes:
    return b"".join(_canonical(event) + b"\n" for event in events)


def test_native_auth_uses_default_discovery_and_projects_no_secret(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    binary = tmp_path / "claude"
    binary.write_bytes(b"x")
    binary.chmod(0o700)
    seen: dict[str, object] = {}

    def fake_run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        seen.update(argv=argv, env=kwargs["env"])
        return subprocess.CompletedProcess(argv, 0, _canonical({
            "loggedIn": True, "authMethod": "claude.ai", "apiProvider": "firstParty",
            "email": "must-not-project@example.invalid",
        }), b"")

    monkeypatch.setattr(CLAUDE.subprocess, "run", fake_run)
    observed = CLAUDE.check_claude_native_auth(
        executable=binary,
        source_environment={
            "HOME": str(tmp_path), "PATH": "/bin", "CLAUDE_CONFIG_DIR": str(tmp_path),
            "ANTHROPIC_API_KEY": "must-not-cross",
        },
    )
    assert observed.auth_mode == CLAUDE.AUTH_MODE
    assert "CLAUDE_CONFIG_DIR" not in seen["env"]
    assert "ANTHROPIC_API_KEY" not in seen["env"]
    assert "must-not-project" not in repr(observed)


def test_native_auth_rejects_api_key_route(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    binary = tmp_path / "claude"
    binary.write_bytes(b"x")
    binary.chmod(0o700)
    monkeypatch.setattr(CLAUDE.subprocess, "run", lambda *a, **k: subprocess.CompletedProcess(
        a[0], 0, _canonical({"loggedIn": True, "authMethod": "api_key", "apiProvider": "firstParty"}), b""
    ))
    with pytest.raises(CLAUDE.PosixV2CompatClaudeError, match="AUTH_MODE_REJECTED"):
        CLAUDE.check_claude_native_auth(executable=binary, source_environment={"HOME": str(tmp_path)})


def test_plan_is_opaque_latest_capability_bound_and_has_no_unsafe_flags(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan = _plan(tmp_path, monkeypatch)
    projected = CLAUDE.project_posix_v2_compat_claude_plan(plan)
    assert projected["expected_version"] is None
    assert projected["executable_version"] == "2.1.270"
    assert projected["compatibility_mode"] == CLAUDE.COMPATIBILITY_MODE
    assert projected["auth_mode"] == CLAUDE.AUTH_MODE
    argv = projected["argv"]
    assert "--restricted" in argv and "--setting-sources=" in argv
    assert "--bare" not in argv and "--safe-mode" not in argv
    assert "--dangerously-skip-permissions" not in argv
    assert "CLAUDE_CONFIG_DIR" not in projected["environment"]
    assert projected["environment"]["CLAUDE_CODE_DISABLE_AUTO_MEMORY"] == "1"
    assert projected["terminal_grammar"] == CLAUDE.TERMINAL_GRAMMAR
    with pytest.raises(TypeError):
        CLAUDE.PosixV2CompatClaudePlan(object(), 1)


def test_explicit_version_binding_rejects_drift(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    binary = tmp_path / "claude"
    binary.write_bytes(b"x")
    binary.chmod(0o700)
    output = tmp_path / "staged" / "result.md"
    output.parent.mkdir()
    contract, launch = _phase_io()
    monkeypatch.setattr(CLAUDE, "check_claude_native_auth", lambda **_kwargs: _auth())
    with pytest.raises(CLAUDE.PosixV2CompatClaudeError, match="EXPLICIT_VERSION_MISMATCH"):
        CLAUDE.compile_posix_v2_compat_claude_plan(
            session_binding=_session(tmp_path), phase_io_contract=contract,
            phase_io_launch=launch, executable_observation=_observation(binary),
            provider_session_id=SESSION, prompt_bytes=b"audit\n", cwd=tmp_path,
            output_routes=[{"path": str(output)}],
            phase_tool_boundary=_boundary(tmp_path, contract, output),
            source_config_root=tmp_path, environment={"HOME": str(tmp_path)},
            max_stdout_bytes=1000, max_stderr_bytes=1000, max_line_bytes=1000,
            expected_version="2.1.252",
        )


def test_plan_rejects_stale_write_namespace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    binary = tmp_path / "claude"
    binary.write_bytes(b"x")
    binary.chmod(0o700)
    old_output = tmp_path / "old" / "result.md"
    old_output.parent.mkdir()
    new_output = tmp_path / "new" / "result.md"
    new_output.parent.mkdir()
    contract, launch = _phase_io()
    monkeypatch.setattr(CLAUDE, "check_claude_native_auth", lambda **_kwargs: _auth())
    with pytest.raises(CLAUDE.PosixV2CompatClaudeError, match="OUTPUT_MISMATCH"):
        CLAUDE.compile_posix_v2_compat_claude_plan(
            session_binding=_session(tmp_path), phase_io_contract=contract,
            phase_io_launch=launch, executable_observation=_observation(binary),
            provider_session_id=SESSION, prompt_bytes=b"audit\n", cwd=tmp_path,
            output_routes=[{"path": str(new_output)}],
            phase_tool_boundary=_boundary(tmp_path, contract, old_output),
            source_config_root=tmp_path, environment={"HOME": str(tmp_path)},
            max_stdout_bytes=1000, max_stderr_bytes=1000, max_line_bytes=1000,
        )


def test_completion_rejects_version_or_tool_drift_before_accepting_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan = _plan(tmp_path, monkeypatch)
    init = {
        "type": "system", "subtype": "init", "uuid": "init", "session_id": SESSION,
        "claude_code_version": "99.0.0", "cwd": str(tmp_path), "model": "claude-sonnet-5",
        "permissionMode": "dontAsk", "apiKeySource": None,
        "tools": ["Bash"], "mcp_servers": [], "plugins": [], "skills": [],
        "slash_commands": [], "plugin_errors": [],
    }
    with pytest.raises(CLAUDE.PosixV2CompatClaudeError, match="INIT_APPLICABILITY_MISMATCH"):
        CLAUDE.validate_posix_v2_compat_claude_completion(
            plan, stdout=_canonical(init) + b"\n", stderr=b"", returncode=0,
        )


def test_positive_completion_binds_exact_model_and_replays(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan = _plan(tmp_path, monkeypatch)
    stdout = _stream(_valid_events(tmp_path))
    completed = CLAUDE.validate_posix_v2_compat_claude_completion(
        plan, stdout=stdout, stderr=b"", returncode=0,
    )
    assert completed["status"] == "COMPLETED"
    assert completed["observed_model"] == "claude-sonnet-5"
    assert completed["additional_provider_usage_models"] == [
        "claude-haiku-4-5-20251001"
    ]
    assert completed["exclusive_model_execution_claimed"] is False
    assert completed["usage_model_provenance"][
        "claude-haiku-4-5-20251001"
    ]["webSearchRequests"] == 0
    replayed = CLAUDE.replay_posix_v2_compat_claude_completion(
        CLAUDE.project_posix_v2_compat_claude_plan(plan), completed,
    )
    assert replayed["completion_sha256"] == completed["completion_sha256"]


def test_completion_replay_rejects_recomputed_binding_substitution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan = _plan(tmp_path, monkeypatch)
    projected = dict(CLAUDE.project_posix_v2_compat_claude_plan(plan))
    completion = dict(CLAUDE.validate_posix_v2_compat_claude_completion(
        plan, stdout=_stream(_valid_events(tmp_path)), stderr=b"", returncode=0,
    ))
    assert CLAUDE.replay_posix_v2_compat_claude_completion(projected, completion)
    completion["provider_session_id"] = "22222222-2222-4222-8222-222222222222"
    completion["completion_sha256"] = _digest({k: v for k, v in completion.items() if k != "completion_sha256"})
    with pytest.raises(CLAUDE.PosixV2CompatClaudeError, match="binding changed"):
        CLAUDE.replay_posix_v2_compat_claude_completion(projected, completion)


def test_completion_replay_rejects_recomputed_usage_provenance_substitution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan = _plan(tmp_path, monkeypatch)
    projected = dict(CLAUDE.project_posix_v2_compat_claude_plan(plan))
    completed = CLAUDE.validate_posix_v2_compat_claude_completion(
        plan, stdout=_stream(_valid_events(tmp_path)), stderr=b"", returncode=0,
    )
    substituted = json.loads(json.dumps(dict(completed)))
    substituted["usage_model_provenance"][
        "claude-haiku-4-5-20251001"
    ]["provider"] = "substituted"
    unsigned = {
        key: value
        for key, value in substituted.items()
        if key != "completion_sha256"
    }
    substituted["completion_sha256"] = _digest(unsigned)
    with pytest.raises(
        CLAUDE.PosixV2CompatClaudeError,
        match="usage provenance",
    ):
        CLAUDE.replay_posix_v2_compat_claude_completion(
            projected, substituted,
        )


def test_ancillary_web_searches_are_admitted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The provider runs WebSearch ON the auxiliary model.

    Measured on DODO run41 recon R-EXT: the armed model did 0 web searches and
    the auxiliary did 16. Requiring zero here discarded a complete, correct
    25-obligation research artifact and published `researched=0` -- on every
    Claude-backend run from 35 onward. Authorship is what this gate owns, and
    it is enforced separately by the assistant-event model binding
    (`assistant_model` above still rejects).
    """
    plan = _plan(tmp_path, monkeypatch)
    events = _valid_events(tmp_path)
    events[-1]["modelUsage"]["claude-haiku-4-5-20251001"][  # type: ignore[index]
        "webSearchRequests"
    ] = 16
    completed = CLAUDE.validate_posix_v2_compat_claude_completion(
        plan, stdout=_stream(events), stderr=b"", returncode=0,
    )
    assert completed is not None
    # Resume must accept exactly what the live run accepted.
    projected = CLAUDE.project_posix_v2_compat_claude_plan(plan)
    CLAUDE.replay_posix_v2_compat_claude_completion(projected, completed)


@pytest.mark.parametrize(
    ("mutation", "code"),
    [
        ("spawned_subagent", "SUBAGENT_EXECUTION_REJECTED"),
        ("unexpected_usage_model", "MODEL_DENOMINATOR_MISMATCH"),
        ("ancillary_canonical_model", "MODEL_DENOMINATOR_MISMATCH"),
        ("assistant_model", "MODEL_DENOMINATOR_MISMATCH"),
    ],
)
def test_completion_rejects_unarmed_execution_or_usage(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
    code: str,
) -> None:
    plan = _plan(tmp_path, monkeypatch)
    events = _valid_events(tmp_path)
    result = events[-1]
    if mutation == "spawned_subagent":
        result["subagent_stats"]["spawned"] = 1  # type: ignore[index]
    elif mutation == "unexpected_usage_model":
        result["modelUsage"]["claude-unknown"] = _usage_row(  # type: ignore[index]
            "claude-unknown"
        )
    elif mutation == "ancillary_canonical_model":
        # Provenance on the auxiliary row is still binding. What is NO LONGER
        # binding is its web-search count -- see
        # test_ancillary_web_searches_are_admitted below.
        result["modelUsage"]["claude-haiku-4-5-20251001"][  # type: ignore[index]
            "canonicalModel"
        ] = "claude-opus-5"
    else:
        events[1]["message"]["model"] = "claude-opus-5"  # type: ignore[index]
    with pytest.raises(CLAUDE.PosixV2CompatClaudeError) as caught:
        CLAUDE.validate_posix_v2_compat_claude_completion(
            plan, stdout=_stream(events), stderr=b"", returncode=0,
        )
    assert caught.value.code == code
