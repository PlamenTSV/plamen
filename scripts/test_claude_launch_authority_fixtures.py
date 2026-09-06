"""Pytest-only Claude launch authority fixtures for offline headless tests.

This module is collected only with the dedicated test suite and is excluded
from the runtime package.  Production code must never import it.  It
deliberately observes no Claude installation and performs no model call: the
exact Python executable running pytest stands in for a native image while
synthetic stream-json bytes exercise the same WorkPlan/WER contracts.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sys
from typing import Any, Callable, Mapping, Sequence
import uuid

import claude_launch_security as L
import claude_provider_preparation as P
from claude_child_environment import (
    planned_claude_child_environment_key_set_sha256,
    planned_claude_child_environment_names,
)
from claude_headless_profile import (
    compile_claude_headless_profile_from_authorities,
)
import worker_execution_receipts as W


VERSION = "2.1.252"
OFFLINE_OAUTH_TOKEN = "offline-headless-runtime-oauth-token"
TEST_ONLY_LAUNCH_SECURITY_REQUEST_SCHEMA = (
    "plamen.test_only_claude_launch_security_request.v1"
)
TEST_ONLY_NO_PROVIDER_AUTHORITY = "TEST_ONLY_NO_PROVIDER_AUTHORITY"
_TEST_PROVIDER_COMMAND_TEMPLATES: dict[str, tuple[str, ...]] = {}


def _canonical(value: Mapping[str, Any]) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _digest(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _replay_test_only_request(value: Mapping[str, Any]) -> dict[str, Any]:
    """Replay the deliberately non-production request used by offline tests."""

    if not isinstance(value, Mapping):
        raise L.ClaudeLaunchSecurityError(
            "test-only Claude launch request must be an object"
        )
    clone = dict(value)
    if set(clone) != {
        "schema",
        "authority_class",
        "policy",
        "executable_observation",
        "request_sha256",
    }:
        raise L.ClaudeLaunchSecurityError(
            "test-only Claude launch request fields drifted"
        )
    digest = clone.pop("request_sha256")
    if (
        clone.get("schema") != TEST_ONLY_LAUNCH_SECURITY_REQUEST_SCHEMA
        or clone.get("authority_class") != TEST_ONLY_NO_PROVIDER_AUTHORITY
        or not isinstance(digest, str)
        or len(digest) != 64
        or any(char not in "0123456789abcdef" for char in digest)
        or digest != _digest(clone)
    ):
        raise L.ClaudeLaunchSecurityError(
            "test-only Claude launch request authority drifted"
        )
    policy = L.replay_claude_launch_security(clone["policy"])
    executable = clone["executable_observation"]
    if (
        not isinstance(executable, Mapping)
        or executable.get("observation_sha256")
        != policy["executable_observation_sha256"]
        or executable.get("claude_code_version")
        != policy["claude_code_version"]
    ):
        raise L.ClaudeLaunchSecurityError(
            "test-only executable observation differs from policy"
        )
    return {
        **clone,
        "policy": policy,
        "executable_observation": dict(executable),
        "request_sha256": digest,
    }


def install_test_only_launch_authority_adapter(
    patch: Callable[[object, str, object], None],
) -> None:
    """Inject the non-provider request replayer into offline test consumers.

    The adapter is explicit and test-owned.  Production modules reject the
    test-only schema unless a fixture injects this replayer into each imported
    consumer alias.
    """

    patch(
        P,
        "observe_claude_executable",
        lambda **_kwargs: _executable_observation(),
    )
    unavailable_source = _stored_source_evidence()
    patch(
        P,
        "observe_stored_subscription_source_authority",
        lambda **_kwargs: unavailable_source,
    )
    patch(
        P,
        "replay_stored_subscription_source_observation",
        lambda value: dict(value),
    )
    patch(
        P,
        "_command_template",
        _test_provider_command_template,
    )


def _stored_source_evidence() -> dict[str, Any]:
    core = {
        "schema": "plamen.claude_stored_subscription_source.v1",
        "store_class": "FILE_BACKED",
        "source_identity": "fixture-profile",
        "source_size": 0,
        "available": False,
        "observation_authority_sha256": "b" * 64,
        "credential_values_recorded": False,
        "credential_content_hashes_recorded": False,
    }
    return {**core, "receipt_sha256": _digest(core)}


def _test_provider_command_template(
    *,
    executable: str,
    intent: Mapping[str, Any],
    profile: Mapping[str, Any],
) -> list[str]:
    """Return the exact registered offline command through production replay."""

    del profile
    template = _TEST_PROVIDER_COMMAND_TEMPLATES.get(
        str(intent["session_id"])
    )
    if template is None or template[0] != executable:
        raise P.ClaudeProviderPreparationError(
            "offline provider command template is not registered"
        )
    return list(template)


def _executable_observation() -> dict[str, Any]:
    executable = Path(sys.executable).resolve(strict=True)
    row = executable.stat()
    file_row = {
        "role": "CONFIGURED_EXECUTABLE",
        "path": str(executable),
        "sha256": hashlib.sha256(executable.read_bytes()).hexdigest(),
        "size": int(row.st_size),
        "device": int(row.st_dev),
        "inode": int(row.st_ino),
        "mode": int(row.st_mode),
        "link_count": int(row.st_nlink),
    }
    compatibility_core = {
        "compatibility_id": "claude-code-2.1.252",
        "claude_code_version": VERSION,
        "supported_capabilities": sorted(
            (
                "-p",
                "--dangerously-skip-permissions",
                "--disable-slash-commands",
                "--mcp-config",
                "--no-chrome",
                "--no-session-persistence",
                "--output-format=stream-json",
                "--permission-mode=default",
                "--permission-mode=dontAsk",
                "--prompt-suggestions=false",
                "--safe-mode",
                "--session-id",
                "--setting-sources=",
                "--strict-mcp-config",
                "--tools",
                "--verbose",
                "init-security-v2",
            )
        ),
    }
    stdout = f"{VERSION} (Claude Code)\n"
    native_core = {
        "schema": "plamen.claude_native_platform_authority.v1",
        "platform": "WINDOWS_AUTHENTICODE",
        "publisher_policy_id": "anthropic-claude-code-windows-v1",
        "publisher_name": "Anthropic PBC",
        "signer_subject": "CN=Anthropic PBC, O=Anthropic PBC",
        "product_name": "Claude Code",
        "file_version": f"{VERSION}.0",
        "claude_code_version": VERSION,
        "executable_path": str(executable),
        "executable_sha256": file_row["sha256"],
        "executable_size": file_row["size"],
        "signature_status": "Valid",
        "implementation_closure": (
            "SIGNED_NATIVE_PRODUCT_IMAGE_WITH_EXTERNAL_OS_AUTHORITY"
        ),
    }
    core = {
        "schema": "plamen.claude_executable_observation.v1",
        "configured_claude_bin": str(executable),
        "resolved_executable": str(executable),
        "claude_code_version": VERSION,
        "compatibility": {
            **compatibility_core,
            "compatibility_sha256": _digest(compatibility_core),
        },
        "implementation_kind": "NATIVE_EXECUTABLE_IMAGE",
        "implementation_status": "DIRECT_IMPLEMENTATION_BOUND",
        "implementation_debt": None,
        "implementation_files": [file_row],
        "implementation_closure_roots": [],
        "native_platform_authority": {
            **native_core,
            "authority_sha256": _digest(native_core),
        },
        "version_probe": {
            "argv": [str(executable), "--version"],
            "returncode": 0,
            "stdout_utf8": stdout,
            "stdout_bytes": len(stdout.encode("utf-8")),
            "stdout_sha256": hashlib.sha256(
                stdout.encode("utf-8")
            ).hexdigest(),
            "stderr_bytes": 0,
            "stderr_sha256": hashlib.sha256(b"").hexdigest(),
            "owned_process_scope_closed": True,
        },
        "launch_authority": "PROOF_GRADE",
    }
    return {**core, "observation_sha256": _digest(core)}


def _stream_bytes(
    *,
    expected_init: Mapping[str, Any],
    session_id: str,
    observed_model: str,
) -> bytes:
    events: list[dict[str, Any]] = [
        {
            "type": "system",
            "subtype": "init",
            "uuid": "fixture-init",
            "session_id": session_id,
            "claude_code_version": expected_init[
                "claude_code_version"
            ],
            "cwd": expected_init["cwd"],
            "model": observed_model,
            "permissionMode": expected_init["permission_mode"],
            "apiKeySource": expected_init["accepted_api_key_sources"][0],
            "tools": list(expected_init["allowed_tools"]),
            "mcp_servers": [],
            "slash_commands": [],
            "output_style": expected_init["accepted_output_styles"][0],
            "skills": [],
            "plugins": [],
        },
        {
            "type": "assistant",
            "uuid": "fixture-assistant",
            "session_id": session_id,
            "parent_tool_use_id": None,
            "message": {
                "id": "fixture-message",
                "type": "message",
                "role": "assistant",
                "content": [{"type": "text", "text": "complete"}],
                "model": observed_model,
                "stop_reason": "end_turn",
                "usage": {"input_tokens": 1, "output_tokens": 1},
            },
        },
        {
            "type": "result",
            "subtype": "success",
            "uuid": "fixture-result",
            "session_id": session_id,
            "duration_ms": 1,
            "duration_api_ms": 1,
            "is_error": False,
            "num_turns": 1,
            "result": "complete",
            "total_cost_usd": 0,
            "usage": {"input_tokens": 1, "output_tokens": 1},
            "modelUsage": {
                observed_model: {"inputTokens": 1, "outputTokens": 1}
            },
            "permission_denials": [],
            "stop_reason": "end_turn",
            "origin": {"kind": "human"},
        },
    ]
    return b"".join(
        json.dumps(
            event,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
        for event in events
    )


def compile_test_claude_runtime_local_inputs(
    *,
    cwd: Path,
) -> dict[str, Any]:
    """Build explicit provider-free host inputs for runtime integration tests."""

    root = Path(cwd).resolve(strict=True)
    ambient: dict[str, str] = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": os.environ.get("HOME", str(Path.home())),
        "USERPROFILE": os.environ.get("USERPROFILE", str(Path.home())),
        "CLAUDE_CODE_OAUTH_TOKEN": OFFLINE_OAUTH_TOKEN,
    }
    for name in (
        "APPDATA",
        "COMSPEC",
        "HOMEDRIVE",
        "HOMEPATH",
        "LOCALAPPDATA",
        "PATHEXT",
        "SYSTEMDRIVE",
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "TMPDIR",
        "WINDIR",
        "XDG_CACHE_HOME",
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
    ):
        value = os.environ.get(name)
        if value is not None:
            ambient[name] = value
    return {
        "ambient_environment": ambient,
        "source_config_dir": None,
        "trusted_cwds": (root,),
    }


def claude_test_postprocess_state_update_source() -> str:
    """Return the bounded state delta emitted by the offline Claude stand-in."""

    return (
        "import json, os\n"
        "state_path=Path(os.environ['CLAUDE_CONFIG_DIR'])/'.claude.json'\n"
        "state=json.loads(state_path.read_text(encoding='utf-8'))\n"
        "state['numStartups']=2\n"
        "state_path.write_text(json.dumps(state,sort_keys=True,"
        "separators=(',',':')),encoding='utf-8')\n"
    )


def compile_test_claude_launch_authority(
    *,
    cwd: Path,
    launch_model: str,
    stdout_limit_bytes: int,
    session_label: str,
    observed_model: str | None = None,
    accepted_models: Sequence[str] | None = None,
    builtin_tools: Sequence[str] = ("Read", "Write"),
    required_tools: Sequence[str] = ("Read",),
    session_id: str | None = None,
    settings_mode: str = "SAFE_MODE",
) -> dict[str, Any]:
    """Compile a self-consistent fake policy/request/stream/argv denominator."""

    root = Path(cwd).resolve(strict=True)
    observed = observed_model or launch_model
    models = tuple(
        accepted_models
        or tuple(sorted({launch_model, observed}))
    )
    runtime_local_inputs = compile_test_claude_runtime_local_inputs(
        cwd=root
    )
    ambient = runtime_local_inputs["ambient_environment"]
    auth = L.compile_claude_auth_route_policy(
        claude_code_version=VERSION,
        desired_route="OAUTH_TOKEN",
    )
    executable = _executable_observation()
    if settings_mode == "SAFE_MODE":
        bound_settings_bytes = None
        selected_mcp_config_bytes = None
        settings_sha256 = None
        external_policy_sha256 = None
        selected_config_sha256 = None
    elif settings_mode == "BOUND_SETTINGS":
        bound_settings_bytes = _canonical(
            {
                "enabledPlugins": {},
                "hooks": {},
                "mcpServers": {},
                "permissions": {"deny": []},
            }
        ) + b"\n"
        selected_mcp_config_bytes = (
            _canonical({"mcpServers": {}}) + b"\n"
        )
        settings_sha256 = hashlib.sha256(
            bound_settings_bytes
        ).hexdigest()
        external_policy_sha256 = hashlib.sha256(
            _canonical({"fixturePolicy": "exact-files"})
        ).hexdigest()
        selected_config_sha256 = hashlib.sha256(
            selected_mcp_config_bytes
        ).hexdigest()
    else:
        raise AssertionError("unsupported fixture settings mode")
    settings_authority = L.compile_claude_settings_authority(
        mode=settings_mode,
        settings_sha256=settings_sha256,
        external_policy_sha256=external_policy_sha256,
    )
    mcp_authority = L.compile_claude_mcp_authority(
        settings_mode=settings_mode,
        server_names=(),
        source_manifest_sha256=None,
        selected_config_sha256=selected_config_sha256,
    )
    profile = compile_claude_headless_profile_from_authorities(
        executable_observation=executable,
        auth_route_policy=auth,
        settings_authority=settings_authority,
        mcp_authority=mcp_authority,
        cwd=str(root),
        accepted_models=models,
        permission_mode="dontAsk",
        builtin_tools=builtin_tools,
        required_tools=required_tools,
        forbidden_tools=("Bash",),
    )
    controls = {
        "CLAUDE_CODE_DISABLE_OFFICIAL_MARKETPLACE_AUTOINSTALL": "1",
        "CLAUDE_CODE_SUBPROCESS_ENV_SCRUB": "1",
        "DISABLE_AUTOUPDATER": "1",
        "DISABLE_UPDATES": "1",
        "ENABLE_CLAUDEAI_MCP_SERVERS": "false",
    }
    environment_allowlist = planned_claude_child_environment_names(
        ambient=ambient,
        selected_route="OAUTH_TOKEN",
        endpoint_environment_names=(),
        phase_environment_policies=("base",),
        functional_control_names=tuple(controls),
        home_variable_policy="PRESERVE_TOOLCHAIN_HOME",
    )
    policy = L.compile_claude_launch_security(
        headless_profile=profile,
        auth_route_policy=auth,
        executable_observation=executable,
        settings_authority=settings_authority,
        mcp_authority=mcp_authority,
        home_variable_policy="PRESERVE_TOOLCHAIN_HOME",
        phase_environment_policies=("base",),
        functional_controls=controls,
        expected_child_environment_key_set_sha256=(
            planned_claude_child_environment_key_set_sha256(
                ambient=ambient,
                selected_route="OAUTH_TOKEN",
                endpoint_environment_names=(),
                phase_environment_policies=("base",),
                functional_control_names=tuple(controls),
                home_variable_policy="PRESERVE_TOOLCHAIN_HOME",
            )
        ),
    )
    production_shape = L.compile_claude_launch_security_request(
        policy=policy,
        executable_observation=executable,
    )
    request = production_shape
    bound_session_id = (
        session_id
        or str(
            uuid.uuid5(
                uuid.NAMESPACE_URL,
                f"plamen-test:{root}:{session_label}",
            )
        )
    )
    expected_init = profile["expected_init_contract"]
    stream_configuration = {
        "schema": W.CLAUDE_STREAM_STDOUT_CONFIGURATION_SCHEMA,
        "expected_session_id": bound_session_id,
        "expected_init_contract": expected_init,
        "max_line_bytes": min(
            2 * 1024 * 1024,
            int(stdout_limit_bytes) - 1,
        ),
        "max_stream_bytes": int(stdout_limit_bytes),
    }
    return {
        "policy": policy,
        "request": request,
        "stream_configuration": stream_configuration,
        "stream_bytes": _stream_bytes(
            expected_init=expected_init,
            session_id=bound_session_id,
            observed_model=observed,
        ),
        "command_suffix": (
            "-p",
            "--model",
            launch_model,
            "--output-format",
            "stream-json",
            "--verbose",
            "--session-id",
            bound_session_id,
            "--no-session-persistence",
        ),
        "environment_allowlist": environment_allowlist,
        "runtime_local_inputs": runtime_local_inputs,
        "bound_settings_bytes": bound_settings_bytes,
        "selected_mcp_config_bytes": selected_mcp_config_bytes,
    }


def compile_test_claude_provider_preparation(
    *,
    authority: Mapping[str, Any],
    base_argv: Sequence[str],
    cwd: Path,
    run_id: str,
    phase: str,
    startup_authority_binding: Mapping[str, Any],
    source_snapshot_sha256: str,
    project_root: Path | None = None,
    startup_scratchpad: Path | None = None,
) -> P.ClaudeProviderPreparation:
    """Mint a real reusable provider parent around an offline fake command.

    The executable/auth observations are fixture-injected, but the returned
    object is issued, replayed, attached, and claimed only by the production
    provider APIs.  No raw-host-input materialization fallback is involved.
    """

    root = Path(cwd).resolve(strict=True)
    bound_project_root = (
        root
        if project_root is None
        else Path(project_root).resolve(strict=True)
    )
    bound_startup_scratchpad = (
        root
        if startup_scratchpad is None
        else Path(startup_scratchpad).resolve(strict=True)
    )
    policy = L.replay_claude_launch_security(authority["policy"])
    request = L.replay_claude_launch_security_request(
        authority["request"]
    )
    stream = dict(authority["stream_configuration"])
    runtime_inputs = authority["runtime_local_inputs"]
    if (
        request["policy"] != policy
        or not isinstance(runtime_inputs, Mapping)
        or isinstance(base_argv, (str, bytes))
    ):
        raise AssertionError("offline provider authority is malformed")
    base = tuple(base_argv)
    if (
        not base
        or base[0] != str(Path(sys.executable).resolve(strict=True))
        or base.count("-p") != 1
        or any(
            "__PLAMEN_ATTEMPT_" in item
            for item in base
            if isinstance(item, str)
        )
    ):
        raise AssertionError(
            "offline provider base argv must be exact and attempt independent"
        )
    if (
        base.count("--model") != 1
        or base.index("--model") != base.index("-p") + 1
    ):
        raise AssertionError("offline provider is not canonical stdin-only")
    final_template = [
        *base,
        *tuple(policy["headless_profile"]["cli_flags"]),
    ]
    session_id = str(stream["expected_session_id"])
    _TEST_PROVIDER_COMMAND_TEMPLATES[session_id] = tuple(final_template)

    expected = policy["headless_profile"]["expected_init_contract"]
    semantic_intent = P.compile_claude_provider_semantic_intent(
        run_id=run_id,
        phase=phase,
        backend="claude",
        launch_model=str(base[base.index("--model") + 1]),
        accepted_models=tuple(expected["accepted_models"]),
        cwd=str(root),
        session_id=session_id,
        max_line_bytes=int(stream["max_line_bytes"]),
        max_stream_bytes=int(stream["max_stream_bytes"]),
        desired_auth_route=policy["auth_route_policy"]["desired_route"],
        home_variable_policy=policy["home_variable_policy"],
        phase_environment_policies=tuple(
            policy["phase_environment_policies"]
        ),
        functional_controls=policy["functional_controls"],
        required_capabilities=tuple(expected["required_capabilities"]),
        forbidden_capabilities=tuple(expected["forbidden_capabilities"]),
        accepted_output_styles=tuple(expected["accepted_output_styles"]),
    )
    phase_tool_policy = P.compile_claude_phase_tool_policy(
        phase=phase,
        permission_mode=expected["permission_mode"],
        builtin_tools=tuple(expected["allowed_tools"]),
        required_tools=tuple(expected["required_tools"]),
        forbidden_tools=tuple(expected["forbidden_tools"]),
    )
    settings = policy["settings_authority"]
    settings_policy = P.compile_claude_settings_policy(
        mode=settings["mode"],
        settings_sha256=settings["settings_sha256"],
        external_policy_sha256=settings["external_policy_sha256"],
    )
    mcp = policy["mcp_authority"]
    mcp_policy = P.compile_claude_mcp_policy(
        settings_mode=settings["mode"],
        server_names=tuple(mcp["server_names"]),
        source_manifest_sha256=mcp["source_manifest_sha256"],
        selected_config_sha256=mcp["selected_config_sha256"],
    )
    package = P.prepare_claude_provider(
        semantic_intent=semantic_intent,
        phase_tool_policy=phase_tool_policy,
        settings_policy=settings_policy,
        mcp_policy=mcp_policy,
        configured_claude_bin=str(Path(sys.executable).resolve(strict=True)),
        ambient_environment=runtime_inputs["ambient_environment"],
        settings_evidence={},
        stored_subscription_source_path=None,
        source_config_dir=runtime_inputs["source_config_dir"],
        project_root=bound_project_root,
        trusted_cwds=runtime_inputs["trusted_cwds"],
        startup_authority_binding=startup_authority_binding,
        startup_scratchpad=bound_startup_scratchpad,
        source_snapshot_sha256=source_snapshot_sha256,
    )
    if not package.eligible:
        raise AssertionError(
            f"offline provider preparation carried debt: {package.record['debts']}"
        )
    public = package.public_headless_arguments()
    if (
        public["claude_launch_security"] != policy
        or public["claude_launch_security_request"] != request
        or public["provider_stdout_evidence_configuration"] != stream
        or tuple(public["environment_allowlist"])
        != tuple(authority["environment_allowlist"])
    ):
        raise AssertionError(
            "offline provider preparation differs from fixture authority"
        )
    return package


__all__ = [
    "TEST_ONLY_LAUNCH_SECURITY_REQUEST_SCHEMA",
    "TEST_ONLY_NO_PROVIDER_AUTHORITY",
    "claude_test_postprocess_state_update_source",
    "compile_test_claude_launch_authority",
    "compile_test_claude_provider_preparation",
    "compile_test_claude_runtime_local_inputs",
    "install_test_only_launch_authority_adapter",
]
