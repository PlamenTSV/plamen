"""Adversarial Claude CLI grammar and parser-runtime fingerprint fixtures."""

from __future__ import annotations

import hashlib
import importlib
import json
from pathlib import Path
import sys
import sysconfig

import pytest

import claude_headless_profile as P
from test_support_startup_permit import durable_startup_permit
import test_worker_execution_receipts as fixtures
import worker_execution_receipts as W


def _binding(
    tmp_path: Path,
    argv: list[str],
) -> dict[str, object]:
    return W._claude_stream_stdout_binding(
        fixtures._claude_stream_configuration(tmp_path),
        argv=argv,
        stdout_limit_bytes=W.DEFAULT_STDOUT_LIMIT_BYTES,
        cwd=tmp_path.resolve(),
        effective_model="claude-opus",
    )


def _binding_with_configuration(
    tmp_path: Path,
    argv: list[str],
    configuration: dict[str, object],
) -> dict[str, object]:
    return W._claude_stream_stdout_binding(
        configuration,
        argv=argv,
        stdout_limit_bytes=W.DEFAULT_STDOUT_LIMIT_BYTES,
        cwd=tmp_path.resolve(),
        effective_model="claude-opus",
    )


def _v2_configuration(
    tmp_path: Path,
    *,
    permission_mode: str,
    mcp_server_names: tuple[str, ...] = (),
    customization_mode: str | None = None,
) -> tuple[dict[str, object], list[str]]:
    profile = P.compile_claude_headless_profile(
        claude_code_version="2.1.220",
        cwd=str(tmp_path.resolve()),
        accepted_models=("claude-opus-5",),
        permission_mode=permission_mode,
        builtin_tools=("Read", "Glob", "Grep", "Write", "Edit"),
        required_tools=("Read", "Write"),
        forbidden_tools=("Agent", "Task", "WebFetch", "WebSearch"),
        mcp_server_names=mcp_server_names,
        customization_mode=customization_mode or (
            "BOUND_SETTINGS" if mcp_server_names else "SAFE_MODE"
        ),
    )
    configuration = fixtures._claude_stream_configuration(tmp_path)
    configuration["expected_init_contract"] = profile[
        "expected_init_contract"
    ]
    return configuration, list(profile["cli_flags"])


def _write_empty_bound_settings(tmp_path: Path) -> Path:
    settings = tmp_path / "bound-settings.json"
    settings.write_bytes(
        (
            json.dumps(
            {
                "enabledPlugins": {},
                "hooks": {},
                "mcpServers": {},
                "permissions": {"deny": []},
            },
            sort_keys=True,
            separators=(",", ":"),
        )
            + "\n"
        ).encode("utf-8"),
    )
    return settings


@pytest.mark.parametrize(
    "mutation",
    [
        "option-terminator",
        "equals-output",
        "shadow-output",
        "duplicate-model",
        "noncanonical-order",
        "long-print-alias",
        "missing-no-persistence",
        "duplicate-no-persistence",
        "resume-short",
        "resume-short-attached",
        "resume-long",
        "resume-equals",
        "continue-short",
        "continue-long",
        "from-pr",
        "from-pr-equals",
        "fork-session",
        "print-short-attached",
    ],
)
def test_claude_stream_command_rejects_noncanonical_or_resumable_grammar(
    tmp_path: Path,
    mutation: str,
) -> None:
    script = tmp_path / "provider.py"
    script.write_text("pass\n", encoding="utf-8")
    argv = fixtures._claude_stream_argv(script)
    if mutation == "option-terminator":
        argv.insert(2, "--")
    elif mutation == "equals-output":
        index = argv.index("--output-format")
        argv[index : index + 2] = ["--output-format=stream-json"]
    elif mutation == "shadow-output":
        argv.append("--output-format=text")
    elif mutation == "duplicate-model":
        argv.extend(["--model", "claude-opus"])
    elif mutation == "noncanonical-order":
        model = argv.index("--model")
        output = argv.index("--output-format")
        argv[model : model + 2], argv[output : output + 2] = (
            argv[output : output + 2],
            argv[model : model + 2],
        )
    elif mutation == "long-print-alias":
        argv[argv.index("-p")] = "--print"
    elif mutation == "missing-no-persistence":
        argv.remove("--no-session-persistence")
    elif mutation == "duplicate-no-persistence":
        argv.append("--no-session-persistence")
    elif mutation == "resume-short":
        argv.extend(["-r", fixtures.CLAUDE_STREAM_SESSION])
    elif mutation == "resume-short-attached":
        argv.append(f"-r{fixtures.CLAUDE_STREAM_SESSION}")
    elif mutation == "resume-long":
        argv.extend(["--resume", fixtures.CLAUDE_STREAM_SESSION])
    elif mutation == "resume-equals":
        argv.append(f"--resume={fixtures.CLAUDE_STREAM_SESSION}")
    elif mutation == "continue-short":
        argv.append("-c")
    elif mutation == "continue-long":
        argv.append("--continue")
    elif mutation == "from-pr":
        argv.extend(["--from-pr", "21"])
    elif mutation == "from-pr-equals":
        argv.append("--from-pr=21")
    elif mutation == "fork-session":
        argv.append("--fork-session")
    elif mutation == "print-short-attached":
        argv.append("-pignored")
    else:  # pragma: no cover - parametrization is the denominator
        raise AssertionError(mutation)

    with pytest.raises(
        W.WorkerExecutionError,
        match="Claude stream command",
    ):
        _binding(tmp_path, argv)


def test_claude_stream_command_accepts_one_canonical_critical_sequence(
    tmp_path: Path,
) -> None:
    script = tmp_path / "provider.py"
    script.write_text("pass\n", encoding="utf-8")

    binding = _binding(tmp_path, fixtures._claude_stream_argv(script))

    assert binding["command_contract"] == {
        "print_mode": True,
        "output_format": "stream-json",
        "verbose": True,
        "include_partial_messages": False,
        "forward_subagent_text": False,
        "session_resume": False,
        "session_persistence": False,
        "critical_argv_order": [
            "-p",
            "--model",
            "--output-format",
            "--verbose",
            "--session-id",
            "--no-session-persistence",
        ],
    }


@pytest.mark.parametrize("safe_mode", (False, True))
def test_claude_stream_command_accepts_canonical_headless_profile_flags(
    tmp_path: Path,
    safe_mode: bool,
) -> None:
    script = tmp_path / "provider.py"
    script.write_text("pass\n", encoding="utf-8")
    argv = fixtures._claude_stream_argv(script)
    argv.extend(
        [
            "--tools",
            "Read,Glob,Grep,Write,Edit",
            "--disable-slash-commands",
            "--setting-sources=",
            "--no-chrome",
            "--prompt-suggestions",
            "false",
        ]
    )
    if safe_mode:
        argv.append("--safe-mode")

    binding = _binding(tmp_path, argv)

    assert binding["command_contract"]["headless_profile"] == {
        "tools": "Read,Glob,Grep,Write,Edit",
        "disable_slash_commands": True,
        "setting_sources": [],
        "no_chrome": True,
        "prompt_suggestions": False,
        "safe_mode": safe_mode,
    }


@pytest.mark.parametrize(
    "mutation",
    (
        ("--tools=Read",),
        ("--tools", "Read", "--tools", "Write"),
        ("--disable-slash-commands=true",),
        ("--disable-slash-commands", "--disable-slash-commands"),
        ("--setting-sources", ""),
        ("--setting-sources=user",),
        ("--setting-sources=", "--setting-sources="),
        ("--no-chrome=true",),
        ("--no-chrome", "--no-chrome"),
        ("--prompt-suggestions=false",),
        ("--prompt-suggestions", "true"),
        (
            "--prompt-suggestions",
            "false",
            "--prompt-suggestions",
            "false",
        ),
        ("--safe-mode=true",),
        ("--safe-mode", "--safe-mode"),
        ("--disallowedTools", "Bash"),
    ),
)
def test_claude_stream_command_rejects_headless_profile_aliases_and_duplicates(
    tmp_path: Path,
    mutation: tuple[str, ...],
) -> None:
    script = tmp_path / "provider.py"
    script.write_text("pass\n", encoding="utf-8")
    argv = fixtures._claude_stream_argv(script)
    argv.extend(mutation)

    with pytest.raises(W.WorkerExecutionError, match="Claude stream command"):
        _binding(tmp_path, argv)


@pytest.mark.parametrize(
    "unbound_flags",
    (
        ("--dangerously-skip-permissions",),
        ("--permission-mode", "dontAsk"),
        ("--strict-mcp-config", "--mcp-config", "unbound.json"),
    ),
)
def test_expected_init_v1_rejects_unbound_v2_authority_flags(
    tmp_path: Path,
    unbound_flags: tuple[str, ...],
) -> None:
    script = tmp_path / "provider.py"
    script.write_text("pass\n", encoding="utf-8")
    argv = fixtures._claude_stream_argv(script)
    argv.extend(
        [
            "--tools",
            "Read,Write",
            "--disable-slash-commands",
            "--setting-sources=",
            "--no-chrome",
            "--prompt-suggestions",
            "false",
            *unbound_flags,
        ]
    )

    with pytest.raises(W.WorkerExecutionError, match="Claude stream command"):
        _binding(tmp_path, argv)


@pytest.mark.parametrize(
    "permission_mode",
    ("bypassPermissions", "dontAsk"),
)
def test_expected_init_v2_requires_exact_cross_bound_secure_profile(
    tmp_path: Path,
    permission_mode: str,
) -> None:
    script = tmp_path / "provider.py"
    script.write_text("pass\n", encoding="utf-8")
    configuration, profile_flags = _v2_configuration(
        tmp_path,
        permission_mode=permission_mode,
    )
    argv = fixtures._claude_stream_argv(script)
    argv.extend(profile_flags)

    binding = _binding_with_configuration(tmp_path, argv, configuration)

    profile = binding["command_contract"]["headless_profile"]
    assert profile["tools"] == "Edit,Glob,Grep,Read,Write"
    assert profile["permission_mode"] == permission_mode


def test_expected_init_v2_rejects_missing_or_tool_divergent_profile(
    tmp_path: Path,
) -> None:
    script = tmp_path / "provider.py"
    script.write_text("pass\n", encoding="utf-8")
    configuration, profile_flags = _v2_configuration(
        tmp_path,
        permission_mode="bypassPermissions",
    )
    base = fixtures._claude_stream_argv(script)
    with pytest.raises(W.WorkerExecutionError, match="Claude stream command"):
        _binding_with_configuration(tmp_path, base, configuration)

    for tools in (
        "Read,Edit,Glob,Grep,Write",
        "Edit,Glob,Grep,Read",
        "Edit,Glob,Grep,Read,Write,Bash",
    ):
        argv = [*base, *profile_flags]
        argv[argv.index("--tools") + 1] = tools
        with pytest.raises(W.WorkerExecutionError, match="Claude stream command"):
            _binding_with_configuration(tmp_path, argv, configuration)


@pytest.mark.parametrize(
    ("permission_mode", "mutation"),
    (
        ("bypassPermissions", "missing"),
        ("bypassPermissions", "add-dontask"),
        ("bypassPermissions", "duplicate-dangerous"),
        ("dontAsk", "missing"),
        ("dontAsk", "add-dangerous"),
        ("dontAsk", "wrong-value"),
        ("dontAsk", "duplicate-mode"),
    ),
)
def test_expected_init_v2_rejects_permission_argv_divergence(
    tmp_path: Path,
    permission_mode: str,
    mutation: str,
) -> None:
    script = tmp_path / "provider.py"
    script.write_text("pass\n", encoding="utf-8")
    configuration, profile_flags = _v2_configuration(
        tmp_path,
        permission_mode=permission_mode,
    )
    argv = [*fixtures._claude_stream_argv(script), *profile_flags]
    if mutation == "missing":
        if permission_mode == "bypassPermissions":
            argv.remove("--dangerously-skip-permissions")
        else:
            index = argv.index("--permission-mode")
            del argv[index : index + 2]
    elif mutation == "add-dontask":
        argv.extend(["--permission-mode", "dontAsk"])
    elif mutation == "duplicate-dangerous":
        argv.append("--dangerously-skip-permissions")
    elif mutation == "add-dangerous":
        argv.append("--dangerously-skip-permissions")
    elif mutation == "wrong-value":
        argv[argv.index("--permission-mode") + 1] = "default"
    elif mutation == "duplicate-mode":
        argv.extend(["--permission-mode", "dontAsk"])
    else:  # pragma: no cover - parametrization is the denominator
        raise AssertionError(mutation)

    with pytest.raises(W.WorkerExecutionError, match="Claude stream command"):
        _binding_with_configuration(tmp_path, argv, configuration)


@pytest.mark.parametrize(
    "mutation",
    ("safe-mode", "missing-strict", "duplicate-strict", "missing-config"),
)
def test_expected_init_v2_mcp_profile_requires_strict_config_and_no_safe_mode(
    tmp_path: Path,
    mutation: str,
) -> None:
    script = tmp_path / "provider.py"
    script.write_text("pass\n", encoding="utf-8")
    mcp_config = tmp_path / "mcp.json"
    mcp_config.write_text(
        '{"mcpServers":{"solodit":{"command":"fixture"}}}\n',
        encoding="utf-8",
    )
    configuration, profile_flags = _v2_configuration(
        tmp_path,
        permission_mode="dontAsk",
        mcp_server_names=("solodit",),
    )
    settings = _write_empty_bound_settings(tmp_path)
    argv = [
        *fixtures._claude_stream_argv(script),
        *profile_flags,
        "--settings",
        str(settings),
        "--strict-mcp-config",
        "--mcp-config",
        str(mcp_config),
    ]
    if mutation == "safe-mode":
        argv.append("--safe-mode")
    elif mutation == "missing-strict":
        argv.remove("--strict-mcp-config")
    elif mutation == "duplicate-strict":
        argv.append("--strict-mcp-config")
    elif mutation == "missing-config":
        index = argv.index("--mcp-config")
        del argv[index : index + 2]

    with pytest.raises(W.WorkerExecutionError, match="Claude stream command"):
        _binding_with_configuration(tmp_path, argv, configuration)


def test_expected_init_v2_mcp_profile_binds_exact_config_bytes(
    tmp_path: Path,
) -> None:
    script = tmp_path / "provider.py"
    script.write_text("pass\n", encoding="utf-8")
    mcp_config = tmp_path / "mcp.json"
    raw = b'{"mcpServers":{"solodit":{"command":"fixture"}}}\n'
    mcp_config.write_bytes(raw)
    configuration, profile_flags = _v2_configuration(
        tmp_path,
        permission_mode="dontAsk",
        mcp_server_names=("solodit",),
    )
    settings = _write_empty_bound_settings(tmp_path)
    argv = [
        *fixtures._claude_stream_argv(script),
        *profile_flags,
        "--settings",
        str(settings),
        "--strict-mcp-config",
        "--mcp-config",
        str(mcp_config),
    ]

    binding = _binding_with_configuration(tmp_path, argv, configuration)

    assert binding["command_contract"]["headless_profile"]["mcp_config"] == {
        "path": str(mcp_config.resolve()),
        "size": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }


@pytest.mark.parametrize(
    "raw",
    (
        b'{"mcpServers":{"other":{"command":"fixture"}}}\n',
        b'{"mcpServers":{},"mcpServers":{"solodit":{}}}\n',
        b'{"mcpServers":{"solodit":{}},"extra":true}\n',
        b'{"mcpServers":["solodit"]}\n',
    ),
)
def test_expected_init_v2_rejects_ambiguous_mcp_server_denominator(
    tmp_path: Path,
    raw: bytes,
) -> None:
    script = tmp_path / "provider.py"
    script.write_text("pass\n", encoding="utf-8")
    mcp_config = tmp_path / "mcp.json"
    mcp_config.write_bytes(raw)
    configuration, profile_flags = _v2_configuration(
        tmp_path,
        permission_mode="dontAsk",
        mcp_server_names=("solodit",),
    )
    settings = _write_empty_bound_settings(tmp_path)
    argv = [
        *fixtures._claude_stream_argv(script),
        *profile_flags,
        "--settings",
        str(settings),
        "--strict-mcp-config",
        "--mcp-config",
        str(mcp_config),
    ]

    with pytest.raises(W.WorkerExecutionError, match="MCP configuration"):
        _binding_with_configuration(tmp_path, argv, configuration)


def test_expected_init_v2_without_mcp_rejects_stray_mcp_authority(
    tmp_path: Path,
) -> None:
    script = tmp_path / "provider.py"
    script.write_text("pass\n", encoding="utf-8")
    mcp_config = tmp_path / "mcp.json"
    mcp_config.write_text('{"mcpServers":{}}\n', encoding="utf-8")
    configuration, profile_flags = _v2_configuration(
        tmp_path,
        permission_mode="dontAsk",
    )
    argv = [
        *fixtures._claude_stream_argv(script),
        *profile_flags,
        "--strict-mcp-config",
        "--mcp-config",
        str(mcp_config),
    ]

    with pytest.raises(W.WorkerExecutionError, match="Claude stream command"):
        _binding_with_configuration(tmp_path, argv, configuration)


def test_expected_init_v2_bound_settings_uses_strict_empty_mcp_config(
    tmp_path: Path,
) -> None:
    script = tmp_path / "provider.py"
    script.write_text("pass\n", encoding="utf-8")
    hook = tmp_path / "hook.py"
    hook.write_text("pass\n", encoding="utf-8")
    policy = tmp_path / "policy.json"
    policy.write_text('{"policy":"fixture"}\n', encoding="utf-8")
    settings = tmp_path / "settings.json"
    settings.write_bytes(
        (
            json.dumps(
            {
                "enabledPlugins": {},
                "hooks": {
                    "PreToolUse": [
                        {
                            "hooks": [
                                {
                                    "args": [
                                        str(hook.resolve()),
                                        "--policy",
                                        str(policy.resolve()),
                                    ],
                                    "command": str(Path(sys.executable).resolve()),
                                    "timeout": 10,
                                    "type": "command",
                                }
                            ],
                            "matcher": ".*",
                        }
                    ]
                },
                "mcpServers": {},
                "permissions": {"deny": []},
            },
            sort_keys=True,
            separators=(",", ":"),
        )
            + "\n"
        ).encode("utf-8"),
    )
    mcp_config = tmp_path / "mcp.json"
    mcp_config.write_text('{"mcpServers":{}}\n', encoding="utf-8")
    configuration, profile_flags = _v2_configuration(
        tmp_path,
        permission_mode="dontAsk",
        customization_mode="BOUND_SETTINGS",
    )
    argv = [
        *fixtures._claude_stream_argv(script),
        *profile_flags,
        "--settings",
        str(settings),
        "--strict-mcp-config",
        "--mcp-config",
        str(mcp_config),
    ]

    binding = _binding_with_configuration(tmp_path, argv, configuration)

    assert binding["command_contract"]["headless_profile"]["mcp_config"][
        "sha256"
    ] == hashlib.sha256(mcp_config.read_bytes()).hexdigest()
    settings_binding = binding["command_contract"]["headless_profile"][
        "settings"
    ]
    assert settings_binding["path"] == str(settings.resolve())
    assert settings_binding["sha256"] == hashlib.sha256(
        settings.read_bytes()
    ).hexdigest()
    assert settings_binding["hook_executable"]["path"] == str(
        Path(sys.executable).resolve()
    )
    assert settings_binding["hook_script"]["path"] == str(hook.resolve())
    assert settings_binding["hook_policy"]["path"] == str(policy.resolve())


@pytest.mark.parametrize(
    "mutation",
    (
        "missing",
        "duplicate",
        "inline-json",
        "relative",
        "unknown-field",
        "duplicate-json-key",
    ),
)
def test_expected_init_v2_bound_settings_rejects_unbound_or_ambiguous_settings(
    tmp_path: Path,
    mutation: str,
) -> None:
    script = tmp_path / "provider.py"
    script.write_text("pass\n", encoding="utf-8")
    hook = tmp_path / "hook.py"
    hook.write_text("pass\n", encoding="utf-8")
    policy = tmp_path / "policy.json"
    policy.write_text('{"policy":"fixture"}\n', encoding="utf-8")
    settings = tmp_path / "settings.json"
    payload = {
        "enabledPlugins": {},
        "hooks": {
            "PreToolUse": [
                {
                    "hooks": [
                        {
                            "args": [
                                str(hook.resolve()),
                                "--policy",
                                str(policy.resolve()),
                            ],
                            "command": str(Path(sys.executable).resolve()),
                            "timeout": 10,
                            "type": "command",
                        }
                    ],
                    "matcher": ".*",
                }
            ]
        },
        "mcpServers": {},
        "permissions": {"deny": []},
    }
    if mutation == "unknown-field":
        payload["unknown"] = True
    settings.write_bytes(
        (
            json.dumps(payload, sort_keys=True, separators=(",", ":"))
            + "\n"
        ).encode("utf-8"),
    )
    if mutation == "duplicate-json-key":
        settings.write_text(
            '{"enabledPlugins":{},"enabledPlugins":{},"hooks":{},'
            '"mcpServers":{},"permissions":{"deny":[]}}\n',
            encoding="utf-8",
        )
    mcp_config = tmp_path / "mcp.json"
    mcp_config.write_text('{"mcpServers":{}}\n', encoding="utf-8")
    configuration, profile_flags = _v2_configuration(
        tmp_path,
        permission_mode="dontAsk",
        customization_mode="BOUND_SETTINGS",
    )
    argv = [
        *fixtures._claude_stream_argv(script),
        *profile_flags,
        "--settings",
        str(settings),
        "--strict-mcp-config",
        "--mcp-config",
        str(mcp_config),
    ]
    if mutation == "missing":
        index = argv.index("--settings")
        del argv[index : index + 2]
    elif mutation == "duplicate":
        argv.extend(["--settings", str(settings)])
    elif mutation == "inline-json":
        argv[argv.index("--settings") + 1] = "{}"
    elif mutation == "relative":
        argv[argv.index("--settings") + 1] = settings.name

    with pytest.raises(
        W.WorkerExecutionError,
        match="Claude stream .*settings",
    ):
        _binding_with_configuration(tmp_path, argv, configuration)


def test_expected_init_v2_safe_mode_rejects_settings_authority(
    tmp_path: Path,
) -> None:
    script = tmp_path / "provider.py"
    script.write_text("pass\n", encoding="utf-8")
    settings = tmp_path / "settings.json"
    settings.write_text("{}\n", encoding="utf-8")
    configuration, profile_flags = _v2_configuration(
        tmp_path,
        permission_mode="dontAsk",
        customization_mode="SAFE_MODE",
    )
    argv = [
        *fixtures._claude_stream_argv(script),
        *profile_flags,
        "--settings",
        str(settings),
    ]

    with pytest.raises(
        W.WorkerExecutionError,
        match="Claude stream .*settings",
    ):
        _binding_with_configuration(tmp_path, argv, configuration)


def test_expected_init_v2_profile_survives_arm_execution_and_receipt_replay(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = fixtures._runtime_case(
        tmp_path,
        label="init-v2-replay",
        monkeypatch=monkeypatch,
    )
    fixtures._install_runtime_case(monkeypatch, case)
    kwargs = case.wer_kwargs()
    kwargs["publish_canonical"] = True
    kwargs["parser_digest"] = fixtures.strict_json_digest
    completed = W.run_observed_worker(**kwargs)

    receipt = W.validate_completed_execution(
        scratchpad=tmp_path,
        receipt_path=completed.receipt_path,
        publish_receipt_path=completed.publish_receipt_path,
        parser_digest=fixtures.strict_json_digest,
        expected_completion_sha256=completed.completion_sha256,
        expected_publish_sha256=completed.publish_sha256,
    )
    assert receipt["provider_stdout_evidence"]["schema"] == (
        "plamen.claude-stream-json-evidence/v1"
    )


def test_bound_settings_changed_after_process_exit_blocks_unpublished_completion(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = fixtures._runtime_case(
        tmp_path,
        label="fingerprint-after-exit",
        monkeypatch=monkeypatch,
    )
    fixtures._install_runtime_case(monkeypatch, case)
    original_binding = W._claude_stream_stdout_binding
    calls = 0

    def drift_after_launch(*args: object, **kwargs: object) -> object:
        nonlocal calls
        calls += 1
        binding = original_binding(*args, **kwargs)
        if calls >= 3:
            binding = dict(binding)
            binding["max_line_bytes"] = int(
                binding["max_line_bytes"]
            ) - 1
        return binding

    monkeypatch.setattr(
        W,
        "_claude_stream_stdout_binding",
        drift_after_launch,
    )

    with pytest.raises(
        W.WorkerExecutionError,
        match="provider stdout evidence binding changed during execution",
    ):
        W.run_observed_worker(**case.wer_kwargs())


def test_bound_settings_changed_at_final_startup_replay_blocks_process_creation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = fixtures._runtime_case(
        tmp_path,
        label="fingerprint-before-create",
        monkeypatch=monkeypatch,
    )
    original_binding = W._claude_stream_stdout_binding
    calls = 0

    def drift_before_process(*args: object, **kwargs: object) -> object:
        nonlocal calls
        calls += 1
        binding = original_binding(*args, **kwargs)
        if calls >= 2:
            binding = dict(binding)
            binding["max_line_bytes"] = int(
                binding["max_line_bytes"]
            ) - 1
        return binding

    monkeypatch.setattr(
        W,
        "_claude_stream_stdout_binding",
        drift_before_process,
    )
    monkeypatch.setattr(
        W.subprocess,
        "Popen",
        lambda *_args, **_kwargs: pytest.fail(
            "fingerprint drift reached process creation"
        ),
    )

    with pytest.raises(
        W.WorkerExecutionError,
        match="provider stdout evidence binding changed before process creation",
    ):
        W.run_observed_worker(**case.wer_kwargs())
    assert not (
        tmp_path / case.output_scope / "result.json"
    ).exists()


def _all_runtime_file_rows(binding: dict[str, object]) -> list[dict[str, object]]:
    rows = list(binding["native_binaries"])
    for module in binding["modules"]:
        rows.extend(module["files"])
    return rows


def test_parser_runtime_fingerprint_binds_direct_module_code_and_native_owners() -> None:
    binding = W._claude_stream_parser_runtime_binding()
    assert binding["schema"] == "plamen.claude_stream_parser_runtime.v2"

    required_modules = {
        "_abc",
        "_codecs",
        "_collections_abc",
        "_json",
        "_sre",
        "abc",
        "builtins",
        "claude_stream_json_evidence",
        "codecs",
        "collections",
        "collections.abc",
        "dataclasses",
        "encodings",
        "encodings.utf_8",
        "hashlib",
        "json",
        "json.decoder",
        "json.encoder",
        "json.scanner",
        "math",
        "pathlib",
        "re",
        "sys",
        "typing",
        "unicodedata",
    }
    modules = {row["module"]: row for row in binding["modules"]}
    assert required_modules.issubset(modules)
    assert hashlib.sha256.__module__ in modules
    assert modules["claude_stream_json_evidence"]["code_sha256"]
    assert modules["json.encoder"]["code_sha256"]

    native = binding["native_binaries"]
    native_paths = {Path(row["path"]).resolve() for row in native}
    assert Path(sys.executable).resolve() in native_paths
    if sys.platform == "win32":
        shared_python = (
            Path(sys.base_prefix)
            / f"python{sys.version_info.major}{sys.version_info.minor}.dll"
        ).resolve(strict=True)
        assert shared_python in native_paths
    elif sys.platform == "darwin" or sysconfig.get_config_var(
        "Py_ENABLE_SHARED"
    ):
        assert any(
            "python_runtime_library" in row["roles"]
            for row in native
        )
    if hashlib.sha256.__module__ == "_hashlib":
        assert any(
            "crypto_provider_library" in row["roles"]
            for row in native
        )

    for row in _all_runtime_file_rows(binding):
        path = Path(row["path"])
        raw = path.read_bytes()
        assert row["size"] == len(raw)
        assert row["sha256"] == hashlib.sha256(raw).hexdigest()


def test_parser_runtime_module_origin_claim_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    encoder = importlib.import_module("json.encoder")
    spec = encoder.__spec__
    assert spec is not None
    monkeypatch.setattr(spec, "origin", str(tmp_path / "missing-encoder.py"))

    with pytest.raises(
        W.WorkerExecutionError,
        match="runtime module 'json.encoder'.*cannot be content-bound",
    ):
        W._claude_stream_parser_runtime_binding()


def test_parser_runtime_missing_python_owner_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(
        W,
        "_python_runtime_native_path",
        lambda: tmp_path / "missing-python-runtime",
    )

    with pytest.raises(
        W.WorkerExecutionError,
        match="native binary for python_runtime",
    ):
        W._claude_stream_parser_runtime_binding()


def test_parser_runtime_missing_crypto_owner_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if hashlib.sha256.__module__ != "_hashlib":
        pytest.skip("current runtime does not execute _hashlib")
    monkeypatch.setattr(W, "_loaded_native_image_paths", lambda: ())

    with pytest.raises(
        W.WorkerExecutionError,
        match="cryptographic provider library cannot be discovered",
    ):
        W._claude_stream_parser_runtime_binding()


def test_parser_runtime_fingerprint_is_canonical_and_reconstructible() -> None:
    first = W._claude_stream_parser_runtime_binding()
    second = W._claude_stream_parser_runtime_binding()

    assert first == second
    assert [row["module"] for row in first["modules"]] == sorted(
        row["module"] for row in first["modules"]
    )
    assert [row["path"] for row in first["native_binaries"]] == sorted(
        row["path"] for row in first["native_binaries"]
    )
    assert json.dumps(
        first,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )
