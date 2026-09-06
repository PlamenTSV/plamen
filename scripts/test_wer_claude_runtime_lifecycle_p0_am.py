"""Executable RED fixtures for WER-owned Claude attempt runtimes.

These tests intentionally exercise the public transaction/runtime boundaries.
They do not inspect source ordering or ASTs, and they never contact a provider.
The "Claude" process is an offline Python fixture substituted at the final
Popen boundary after WER has compiled and armed the real argv/environment.

The suite is expected to remain red until WER owns the complete runtime
lifecycle.  A missing integration API must fail as an explicit contract
failure, not make the tests silently skip.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
import hashlib
import inspect
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
from typing import Any, Mapping
import uuid

import pytest

import auxiliary_writable_root_lease as A
from claude_child_environment import (
    planned_claude_child_environment_key_set_sha256,
)
from claude_headless_profile import (
    compile_claude_headless_profile_from_authorities,
)
import claude_launch_security as L
import claude_phase_tool_policy as Q
import claude_provider_preparation as P
import claude_runtime_materialization as M
import claude_stored_subscription_source as S
import owned_process_scope as O
from provider_command_authority import argv_authority_sha256
import test_claude_provider_preparation as provider_fixtures
from test_support_startup_permit import (
    FIXTURE_RUN_ID,
    durable_startup_permit,
    rotate_startup_permit,
)
import worker_execution_receipts as W
import worker_transaction as T


VERSION = "2.1.220"
MODEL = "claude-opus-5"
RUNTIME_PARAMETER = "claude_runtime_materialization_request"
OFFLINE_TOKEN = "offline-wer-oauth-token-7dA1cF0eB925"
_USE_CASE_REQUEST = object()
REVIEWED_OAUTH_CHILD_ENVIRONMENT_ALLOWLIST = tuple(
    sorted(
        {
            # Exact fixture ambient names admitted by the selected base policy.
            "PATH",
            "PATHEXT",
            "SYSTEMROOT",
            "WINDIR",
            "COMSPEC",
            "HOME",
            "USERPROFILE",
            "TMP",
            "TEMP",
            # Attempt-private profile overlay.
            "CLAUDE_CONFIG_DIR",
            "CLAUDE_CODE_TMPDIR",
            "TMPDIR",
            # Exact selected auth route and functional controls.
            "CLAUDE_CODE_OAUTH_TOKEN",
            "CLAUDE_CODE_SUBPROCESS_ENV_SCRUB",
            "DISABLE_AUTOUPDATER",
        }
    )
)


def _digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def _raw_sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _strict_json_digest(_path: Path, raw: bytes) -> str:
    value = json.loads(raw.decode("utf-8"))
    if (
        not isinstance(value, Mapping)
        or not isinstance(value.get("finding_id"), str)
    ):
        raise ValueError("fixture output must be a finding object")
    return _digest(dict(value))


def _fixture_runtime_namespace(project_root: Path) -> Path:
    """Return an attempt-runtime namespace disjoint from the project tree."""

    resolved = project_root.resolve()
    return resolved.parent / f".{resolved.name}-runtime-authority"


@pytest.fixture(autouse=True)
def _isolated_auxiliary_namespace(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        A,
        "_default_runtime_namespace",
        lambda: _fixture_runtime_namespace(tmp_path),
    )
    provider_fixtures._install_observers(
        monkeypatch,
        Path(sys.executable).resolve(strict=True),
    )


def _executable_observation(
    executable: Path,
    *,
    version: str = VERSION,
) -> dict[str, object]:
    executable = executable.resolve(strict=True)
    stat = executable.stat()
    raw = executable.read_bytes()
    row = {
        "role": "CONFIGURED_EXECUTABLE",
        "path": str(executable),
        "sha256": _raw_sha256(raw),
        "size": len(raw),
        "device": int(stat.st_dev),
        "inode": int(stat.st_ino),
        "mode": int(stat.st_mode),
        "link_count": int(stat.st_nlink),
    }
    supported_capabilities = {
                "-p",
                "--dangerously-skip-permissions",
                "--disable-slash-commands",
                "--mcp-config",
                "--no-chrome",
                "--no-session-persistence",
                "--output-format=stream-json",
                "--permission-mode=dontAsk",
                "--prompt-suggestions=false",
                "--safe-mode",
                "--session-id",
                "--setting-sources=",
                "--strict-mcp-config",
                "--tools",
                "--verbose",
                "init-security-v2",
    }
    if version == "2.1.252":
        supported_capabilities.add("--permission-mode=default")
    compatibility_core = {
        "compatibility_id": f"claude-code-{version}",
        "claude_code_version": version,
        "supported_capabilities": sorted(supported_capabilities),
    }
    stdout = f"{version} (Claude Code)\n"
    native_core = {
        "schema": "plamen.claude_native_platform_authority.v1",
        "platform": "WINDOWS_AUTHENTICODE",
        "publisher_policy_id": "anthropic-claude-code-windows-v1",
        "publisher_name": "Anthropic PBC",
        "signer_subject": "CN=Anthropic PBC, O=Anthropic PBC",
        "product_name": "Claude Code",
        "file_version": f"{version}.0",
        "claude_code_version": version,
        "executable_path": str(executable),
        "executable_sha256": row["sha256"],
        "executable_size": row["size"],
        "signature_status": "Valid",
        "implementation_closure": (
            "SIGNED_NATIVE_PRODUCT_IMAGE_WITH_EXTERNAL_OS_AUTHORITY"
        ),
    }
    core: dict[str, object] = {
        "schema": "plamen.claude_executable_observation.v1",
        "configured_claude_bin": str(executable),
        "resolved_executable": str(executable),
        "claude_code_version": version,
        "compatibility": {
            **compatibility_core,
            "compatibility_sha256": _digest(compatibility_core),
        },
        "implementation_kind": "NATIVE_EXECUTABLE_IMAGE",
        "implementation_status": "DIRECT_IMPLEMENTATION_BOUND",
        "implementation_debt": None,
        "implementation_files": [row],
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
            "stdout_sha256": _raw_sha256(stdout.encode("utf-8")),
            "stderr_bytes": 0,
            "stderr_sha256": _raw_sha256(b""),
            "owned_process_scope_closed": True,
        },
        "launch_authority": "PROOF_GRADE",
    }
    return {**core, "observation_sha256": _digest(core)}


def _ambient() -> dict[str, str]:
    values = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": os.environ.get("HOME", str(Path.home())),
        "USERPROFILE": os.environ.get("USERPROFILE", str(Path.home())),
        "CLAUDE_CODE_OAUTH_TOKEN": OFFLINE_TOKEN,
        "CLAUDE_SECURESTORAGE_CONFIG_DIR": (
            str(Path.cwd() / "attacker-controlled-secure-store")
        ),
        "ANTHROPIC_API_KEY": "must-be-removed-api-key",
        "GITHUB_TOKEN": "unrelated-ambient-secret",
    }
    for name in (
        "SYSTEMROOT",
        "WINDIR",
        "TEMP",
        "TMP",
        "COMSPEC",
        "PATHEXT",
    ):
        if name in os.environ:
            values[name] = os.environ[name]
    return values


def _stored_subscription_source(root: Path, label: str) -> Path:
    source = root / f"stored-source-{label}"
    source.mkdir(exist_ok=False)
    credential = source / ".credentials.json"
    credential.write_text(
        json.dumps(
            {
                "claudeAiOauth": {
                    "accessToken": "offline-stored-access-token",
                    "refreshToken": "offline-stored-refresh-token",
                    "expiresAt": 4102444800000,
                }
            }
        ),
        encoding="utf-8",
    )
    credential.chmod(0o600)
    if os.name == "nt":
        account = os.environ.get("USERNAME")
        domain = os.environ.get("USERDOMAIN")
        if not account:
            raise AssertionError("Windows credential fixture account absent")
        principal = f"{domain}\\{account}" if domain else account
        completed = subprocess.run(
            [
                "icacls",
                str(source),
                "/inheritance:r",
                "/grant:r",
                f"{principal}:(F)",
            ],
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=15,
        )
        if completed.returncode != 0:
            raise AssertionError("Windows credential fixture ACL failed")
        completed = subprocess.run(
            [
                "icacls",
                str(credential),
                "/inheritance:r",
                "/grant:r",
                f"{principal}:(F)",
            ],
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=15,
        )
        if completed.returncode != 0:
            raise AssertionError("Windows credential fixture ACL failed")
    return source


def _launch_authority(
    *,
    root: Path,
    session_id: str,
    ambient: Mapping[str, str],
) -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
    controls = {
        "CLAUDE_CODE_SUBPROCESS_ENV_SCRUB": "1",
        "DISABLE_AUTOUPDATER": "1",
    }
    expected_key_set = planned_claude_child_environment_key_set_sha256(
        ambient=ambient,
        selected_route="OAUTH_TOKEN",
        endpoint_environment_names=(),
        phase_environment_policies=("base", "git", "rust"),
        functional_control_names=tuple(controls),
        home_variable_policy="PRESERVE_TOOLCHAIN_HOME",
    )
    executable = _executable_observation(Path(sys.executable))
    auth = L.compile_claude_auth_route_policy(
        claude_code_version=VERSION,
        desired_route="OAUTH_TOKEN",
    )
    settings = L.compile_claude_settings_authority(
        mode="SAFE_MODE",
        settings_sha256=None,
        external_policy_sha256=None,
    )
    mcp = L.compile_claude_mcp_authority(
        settings_mode="SAFE_MODE",
        server_names=(),
        source_manifest_sha256=None,
        selected_config_sha256=None,
    )
    profile = compile_claude_headless_profile_from_authorities(
        executable_observation=executable,
        auth_route_policy=auth,
        settings_authority=settings,
        mcp_authority=mcp,
        cwd=str(root.resolve()),
        accepted_models=(MODEL,),
        permission_mode="dontAsk",
        builtin_tools=("Edit", "Glob", "Grep", "Read", "Write"),
        required_tools=("Read",),
        forbidden_tools=("Bash",),
    )
    policy = L.compile_claude_launch_security(
        headless_profile=profile,
        auth_route_policy=auth,
        executable_observation=executable,
        settings_authority=settings,
        mcp_authority=mcp,
        home_variable_policy="PRESERVE_TOOLCHAIN_HOME",
        phase_environment_policies=("base", "git", "rust"),
        functional_controls=controls,
        expected_child_environment_key_set_sha256=expected_key_set,
    )
    request = L.compile_claude_launch_security_request(
        policy=policy,
        executable_observation=executable,
    )
    stream = {
        "schema": W.CLAUDE_STREAM_STDOUT_CONFIGURATION_SCHEMA,
        "expected_session_id": session_id,
        "expected_init_contract": profile["expected_init_contract"],
        "max_line_bytes": 2 * 1024 * 1024,
        "max_stream_bytes": W.DEFAULT_STDOUT_LIMIT_BYTES,
    }
    return request, profile, stream


def _stream_bytes(
    *,
    root: Path,
    session_id: str,
    profile: Mapping[str, object],
) -> bytes:
    expected = profile["expected_init_contract"]
    assert isinstance(expected, Mapping)
    events = [
        {
            "type": "system",
            "subtype": "init",
            "uuid": f"init-{session_id}",
            "session_id": session_id,
            "claude_code_version": expected["claude_code_version"],
            "cwd": str(root.resolve()),
            "model": MODEL,
            "permissionMode": expected["permission_mode"],
            "apiKeySource": "none",
            "tools": list(expected["allowed_tools"]),
            "mcp_servers": list(expected["allowed_mcp_servers"]),
            "slash_commands": list(expected["expected_slash_commands"]),
            "output_style": expected["accepted_output_styles"][0],
            "skills": list(expected["expected_skills"]),
            "plugins": list(expected["expected_plugins"]),
            "agents": list(expected["expected_agents"]),
            "capabilities": list(
                expected.get(
                    "expected_native_capabilities",
                    expected["required_capabilities"],
                )
            ),
        },
        {
            "type": "assistant",
            "uuid": f"assistant-{session_id}",
            "session_id": session_id,
            "parent_tool_use_id": None,
            "message": {
                "id": f"message-{session_id}",
                "type": "message",
                "role": "assistant",
                "content": [{"type": "text", "text": "offline complete"}],
                "model": MODEL,
                "stop_reason": "end_turn",
                "usage": {"input_tokens": 1, "output_tokens": 1},
            },
        },
        {
            "type": "result",
            "subtype": "success",
            "uuid": f"result-{session_id}",
            "session_id": session_id,
            "duration_ms": 1,
            "duration_api_ms": 1,
            "is_error": False,
            "num_turns": 1,
            "result": "offline complete",
            "total_cost_usd": 0.0,
            "usage": {"input_tokens": 1, "output_tokens": 1},
            "modelUsage": {MODEL: {"inputTokens": 1}},
            "permission_denials": [],
            "stop_reason": "end_turn",
            "origin": {"kind": "human"},
        },
    ]
    return b"".join(
        json.dumps(
            row,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
        for row in events
    )


def _bindings(
    *,
    root: Path,
    prefix: str,
    backend: str,
    shard_id: str,
    plan_raw: bytes,
    startup_binding: Mapping[str, object],
    environment_allowlist: tuple[str, ...],
) -> W.ExecutionBindings:
    inputs = root / prefix
    inputs.mkdir(parents=True, exist_ok=False)
    intent = {
        "effective_backend": backend,
        "effective_model": MODEL,
        "environment_allowlist_sha256": (
            W.environment_allowlist_sha256(environment_allowlist)
        ),
        "auxiliary_writable_root_startup": dict(startup_binding),
    }
    rows = {
        "plan.json": plan_raw,
        "manifest.json": b"{}\n",
        "intent.json": (
            json.dumps(intent, sort_keys=True) + "\n"
        ).encode("utf-8"),
        "context.md": b"context\n",
        "prompt.md": b"prompt\n",
        "tool-policy.json": b'{"network":false}\n',
    }
    for name, raw in rows.items():
        (inputs / name).write_bytes(raw)
    return W.ExecutionBindings(
        run_id=FIXTURE_RUN_ID,
        shard_id=shard_id,
        plan=W.BoundInput(f"{prefix}/plan.json"),
        manifest=W.BoundInput(f"{prefix}/manifest.json"),
        intent=W.BoundInput(f"{prefix}/intent.json"),
        context=W.BoundInput(f"{prefix}/context.md"),
        prompt=W.BoundInput(f"{prefix}/prompt.md"),
        tool_policy=W.BoundInput(f"{prefix}/tool-policy.json"),
        worker=W.PrincipalInvocation(
            f"worker-{prefix}",
            f"worker-invocation-{prefix}",
        ),
        assessors=(),
        effective_backend=backend,
        effective_model=MODEL,
    )


@dataclass
class RuntimeCase:
    root: Path
    label: str
    session_id: str
    output_scope: str
    request: M.ClaudeRuntimeMaterializationRequest
    launch_request: dict[str, object]
    profile: dict[str, object]
    stream: dict[str, object]
    environment_allowlist: tuple[str, ...]
    startup_binding: dict[str, object]
    bindings: W.ExecutionBindings
    base_argv: tuple[str, ...]
    expected_final_argv: tuple[str, ...]
    fake_script: Path

    def wer_kwargs(
        self,
        *,
        request: object = _USE_CASE_REQUEST,
        bindings: W.ExecutionBindings | None = None,
    ) -> dict[str, object]:
        return {
            "scratchpad": self.root,
            "bindings": self.bindings if bindings is None else bindings,
            "argv": self.base_argv,
            "cwd": self.root,
            "output_scope_relative": self.output_scope,
            "expected_outputs": (
                W.ExpectedOutput(
                    f"finding-{self.label}",
                    "result.json",
                    f"canonical/{self.label}.json",
                ),
            ),
            "parser_digest": _strict_json_digest,
            "environment": {},
            "environment_allowlist": self.environment_allowlist,
            "timeout_seconds": 10,
            "publish_canonical": False,
            "process_scope_identity": f"scope-{self.label}",
            "provider_stdout_evidence_configuration": self.stream,
            "startup_authority_binding": self.startup_binding,
            "claude_launch_security_request": self.launch_request,
            RUNTIME_PARAMETER: (
                self.request
                if request is _USE_CASE_REQUEST
                else request
            ),
        }


def _case(
    root: Path,
    *,
    label: str,
    backend: str = "claude",
    route: str = "OAUTH_TOKEN",
    restricted: bool = False,
    startup_binding: dict[str, object] | None = None,
) -> RuntimeCase:
    root.mkdir(parents=True, exist_ok=True)
    startup = (
        durable_startup_permit(root)
        if startup_binding is None
        else dict(startup_binding)
    )
    session_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"wer:{label}"))
    ambient = _ambient()
    source_config = None
    if route == "STORED_SUBSCRIPTION_OAUTH":
        ambient.pop("CLAUDE_CODE_OAUTH_TOKEN", None)
        source_config = _stored_subscription_source(root, label)
    output_scope = f"worker-out-{label}"
    output_path = root / output_scope / "result.json"
    policy_path: Path | None = None
    bound_settings_bytes: bytes | None = None
    bound_mcp_bytes: bytes | None = None
    if restricted:
        policy_path = root / f"restricted-policy-{label}.json"
        settings_path = root / f"restricted-settings-{label}.json"
        Q.write_policy_bundle(
            policy_path=policy_path,
            settings_path=settings_path,
            hook_script=Path(Q.__file__),
            run_id=FIXTURE_RUN_ID,
            phase="depth",
            attempt=1,
            expected_cwd=root,
            project_root=root,
            scratchpad_root=root,
            methodology_read_roots=(),
            exact_read_files=(),
            exact_write_files=(output_path,),
            forbidden_read_files=(),
            receipt_directory=root / f"hook-receipts-{label}",
        )
        bound_settings_bytes = settings_path.read_bytes()
        bound_mcp_bytes = Q.canonical_json_bytes({"mcpServers": {}})
    intent = P.compile_claude_provider_semantic_intent(
        run_id=FIXTURE_RUN_ID,
        phase="depth",
        backend="claude",
        launch_model=MODEL,
        accepted_models=(MODEL,),
        cwd=str(root.resolve()),
        session_id=session_id,
        max_line_bytes=2 * 1024 * 1024,
        max_stream_bytes=W.DEFAULT_STDOUT_LIMIT_BYTES,
        desired_auth_route=route,
        home_variable_policy="PRESERVE_TOOLCHAIN_HOME",
        phase_environment_policies=("base", "git", "rust"),
        functional_controls={
            "CLAUDE_CODE_DISABLE_OFFICIAL_MARKETPLACE_AUTOINSTALL": "1",
            "CLAUDE_CODE_SUBPROCESS_ENV_SCRUB": "1",
            "DISABLE_AUTOUPDATER": "1",
            "DISABLE_UPDATES": "1",
            "ENABLE_CLAUDEAI_MCP_SERVERS": "false",
        },
        required_capabilities=(
            ("vendor-restricted-analysis",) if restricted else ()
        ),
        forbidden_capabilities=("remote-agents",),
    )
    package = P.prepare_claude_provider(
        semantic_intent=intent,
        phase_tool_policy=P.compile_claude_phase_tool_policy(
            phase="depth",
            permission_mode="default" if restricted else "dontAsk",
            builtin_tools=("Edit", "Glob", "Grep", "Read", "Write"),
            required_tools=("Read",),
            forbidden_tools=(
                (
                    "Agent",
                    "Bash",
                    "PowerShell",
                    "Task",
                    "WebFetch",
                    "WebSearch",
                )
                if restricted
                else ("Bash",)
            ),
        ),
        settings_policy=P.compile_claude_settings_policy(
            mode="BOUND_SETTINGS" if restricted else "SAFE_MODE",
            settings_sha256=(
                _raw_sha256(bound_settings_bytes)
                if bound_settings_bytes is not None
                else None
            ),
            external_policy_sha256=(
                _raw_sha256(policy_path.read_bytes())
                if policy_path is not None
                else None
            ),
        ),
        mcp_policy=P.compile_claude_mcp_policy(
            settings_mode=(
                "BOUND_SETTINGS" if restricted else "SAFE_MODE"
            ),
            server_names=(),
            source_manifest_sha256=None,
            selected_config_sha256=(
                _raw_sha256(bound_mcp_bytes)
                if bound_mcp_bytes is not None
                else None
            ),
        ),
        configured_claude_bin=str(
            Path(sys.executable).resolve(strict=True)
        ),
        ambient_environment=ambient,
        settings_evidence={},
        stored_subscription_source_path=(
            None
            if source_config is None
            else source_config / ".credentials.json"
        ),
        source_config_dir=source_config,
        project_root=root,
        trusted_cwds=(root,),
        startup_authority_binding=startup,
        startup_scratchpad=root,
        source_snapshot_sha256="a" * 64,
    )
    package_record = package.record
    launch = package_record["launch_security_request"]
    profile = package_record["headless_profile"]
    stream = package_record["stream_configuration"]
    provider_arguments = package.public_headless_arguments()
    environment_allowlist = tuple(
        provider_arguments["environment_allowlist"]
    )
    plan = {
        "schema": "plamen.worker_work_plan.v2",
        "provider": {"backend": backend},
        "completion_policy": {
            "provider_stdout_evidence_configuration": stream,
            "auxiliary_writable_root_startup_permit": startup,
            "claude_launch_security": launch["policy"],
        },
    }
    plan_raw = (
        json.dumps(plan, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    bindings = _bindings(
        root=root,
        prefix=f"launch-inputs-{label}",
        backend=backend,
        shard_id=f"shard-runtime-{label}",
        plan_raw=plan_raw,
        startup_binding=startup,
        environment_allowlist=environment_allowlist,
    )
    command = package.command_for_bound_stdin()
    base_argv = command[
        : command.index("--no-session-persistence") + 1
    ]
    bound_runtime = P.attach_claude_provider_runtime(
        package,
        ambient_environment=ambient,
        source_config_dir=source_config,
        project_root=root,
        trusted_cwds=(root,),
        bound_settings_bytes=bound_settings_bytes,
        selected_mcp_config_bytes=bound_mcp_bytes,
    )
    claimed_runtime = P.claim_bound_claude_provider_runtime(
        bound_runtime,
        provider_preparation=package,
        expected_preparation_sha256=package.preparation_sha256,
        expected_runtime_host_policy_sha256=package_record[
            "runtime_host_policy"
        ]["policy_sha256"],
        expected_attachment_sha256=bound_runtime.attachment_sha256,
    )
    request = M.compile_claude_runtime_materialization_request(
        launch_security_request=launch,
        provider_runtime=claimed_runtime,
        base_argv=base_argv,
        scratchpad=root,
        startup_permit_binding=startup,
        run_id=FIXTURE_RUN_ID,
        outer_attempt_arm_sha256=_digest({"outer-arm": label}),
        work_plan_sha256=_raw_sha256(plan_raw),
        attempt_id=f"attempt-{label}",
        process_scope_identity=f"scope-{label}",
    )
    raw_stream = _stream_bytes(
        root=root,
        session_id=session_id,
        profile=profile,
    )
    fake_script = root / f"offline-claude-{label}.py"
    fake_script.write_text(
        "from pathlib import Path\n"
        "import sys\n"
        f"p=Path({str(output_path)!r})\n"
        "p.parent.mkdir(parents=True,exist_ok=True)\n"
        "p.write_text('{\"finding_id\":\"H-01\"}',encoding='utf-8')\n"
        f"sys.stdout.buffer.write({raw_stream!r})\n",
        encoding="utf-8",
    )
    return RuntimeCase(
        root=root,
        label=label,
        session_id=session_id,
        output_scope=output_scope,
        request=request,
        launch_request=launch,
        profile=profile,
        stream=stream,
        environment_allowlist=environment_allowlist,
        startup_binding=startup,
        bindings=bindings,
        base_argv=base_argv,
        expected_final_argv=command,
        fake_script=fake_script,
    )


def _require_runtime_boundary() -> None:
    parameter = inspect.signature(W.run_observed_worker).parameters.get(
        RUNTIME_PARAMETER
    )
    assert parameter is not None, (
        "WER does not yet accept the opaque Claude runtime request"
    )
    assert parameter.kind is inspect.Parameter.KEYWORD_ONLY
    assert parameter.default is None


def _install_fake_cli(
    monkeypatch: pytest.MonkeyPatch,
    cases: tuple[RuntimeCase, ...],
    *,
    advance_provider_state: bool = True,
    replace_private_credential: bool = False,
) -> list[dict[str, object]]:
    real_popen = subprocess.Popen
    scripts = {case.session_id: case.fake_script for case in cases}
    captures: list[dict[str, object]] = []
    lock = threading.Lock()

    def advance_runtime_state(environment: Mapping[str, object]) -> None:
        config_dir = Path(str(environment["CLAUDE_CONFIG_DIR"]))
        state_path = config_dir / ".claude.json"
        state = json.loads(state_path.read_text(encoding="utf-8"))
        assert state["numStartups"] == 1
        state["numStartups"] = 2
        state_path.write_text(
            json.dumps(
                state,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ),
            encoding="utf-8",
        )

    def fake_popen(
        physical_argv: list[str] | tuple[str, ...],
        **kwargs: object,
    ) -> subprocess.Popen[bytes]:
        argv = tuple(str(item) for item in physical_argv)
        session = None
        if "--session-id" in argv:
            index = argv.index("--session-id")
            if index + 1 < len(argv):
                session = argv[index + 1]
        if session not in scripts:
            raise AssertionError(
                f"final provider argv lost its session authority: {argv!r}"
            )
        with lock:
            captures.append(
                {
                    "argv": argv,
                    "env": dict(kwargs.get("env") or {}),
                    "cwd": str(kwargs.get("cwd")),
                }
            )
            if advance_provider_state:
                advance_runtime_state(dict(kwargs.get("env") or {}))
            if replace_private_credential:
                config_dir = Path(
                    str(dict(kwargs.get("env") or {})["CLAUDE_CONFIG_DIR"])
                )
                credential = config_dir / ".credentials.json"
                replacement = config_dir / "replacement"
                replacement.write_text(
                    json.dumps(
                        {
                            "claudeAiOauth": {
                                "accessToken": "rotated-access-token",
                                "refreshToken": "rotated-refresh-token",
                                "expiresAt": 4102444802000,
                            }
                        }
                    ),
                    encoding="utf-8",
                )
                replacement.chmod(0o600)
                os.replace(replacement, credential)
        return real_popen(
            [sys.executable, str(scripts[str(session)])],
            **kwargs,
        )

    monkeypatch.setattr(subprocess, "Popen", fake_popen)
    return captures


def _json_artifacts(root: Path) -> list[tuple[Path, dict[str, object]]]:
    rows: list[tuple[Path, dict[str, object]]] = []
    for path in sorted(root.rglob("*.json")):
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, ValueError):
            continue
        if isinstance(value, dict):
            rows.append((path, value))
    return rows


def _all_json_text(root: Path) -> str:
    return "\n".join(
        json.dumps(value, sort_keys=True)
        for _path, value in _json_artifacts(root)
    )


def _public_evidence_bytes(root: Path) -> bytes:
    chunks: list[bytes] = []
    for directory_name in (
        ".worker_execution_receipts",
        ".worker_transactions",
    ):
        directory = root / directory_name
        if not directory.exists():
            continue
        for path in sorted(directory.rglob("*")):
            if path.is_file() and not path.is_symlink():
                chunks.append(path.read_bytes())
    return b"\n".join(chunks)


def _find_values(value: object, key: str) -> list[object]:
    found: list[object] = []
    if isinstance(value, Mapping):
        for name, child in value.items():
            if name == key:
                found.append(child)
            found.extend(_find_values(child, key))
    elif isinstance(value, list):
        for child in value:
            found.extend(_find_values(child, key))
    return found


def _completion_paths(root: Path) -> list[Path]:
    return sorted(
        (root / ".worker_execution_receipts").glob(
            "**/completion_*.json"
        )
    )


def test_wer_public_boundary_requires_one_opaque_runtime_request_parameter() -> None:
    _require_runtime_boundary()


@pytest.mark.parametrize("candidate", (None, {}, object()))
def test_valid_workplan_rejects_missing_or_forged_request_before_process_creation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    candidate: object,
) -> None:
    case = _case(tmp_path, label=f"reject-{type(candidate).__name__}")
    calls: list[object] = []

    def forbidden(*args: object, **kwargs: object) -> object:
        calls.append((args, kwargs))
        raise AssertionError("invalid runtime request reached Popen")

    monkeypatch.setattr(subprocess, "Popen", forbidden)
    with pytest.raises(
        W.WorkerExecutionError,
        match="Claude.*runtime|runtime.*Claude|opaque",
    ):
        W.run_observed_worker(
            **case.wer_kwargs(request=candidate)
        )
    assert calls == []


def test_non_claude_workplan_rejects_runtime_request_before_process_creation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = _case(tmp_path, label="foreign-backend", backend="codex")
    calls: list[object] = []
    monkeypatch.setattr(
        subprocess,
        "Popen",
        lambda *args, **kwargs: calls.append((args, kwargs)),
    )
    with pytest.raises(
        W.WorkerExecutionError,
        match="Claude.*backend|backend.*Claude|runtime.*Claude",
    ):
        W.run_observed_worker(**case.wer_kwargs())
    assert calls == []


def test_offline_cli_happy_path_uses_exact_final_runtime_and_lifecycle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = _case(tmp_path, label="happy")
    captures = _install_fake_cli(monkeypatch, (case,))
    real_scope = W._OwnedProcessTree
    scope_calls: list[dict[str, object]] = []

    def scope_factory(**kwargs: object) -> object:
        scope_calls.append(dict(kwargs))
        return real_scope(**kwargs)

    monkeypatch.setattr(W, "_OwnedProcessTree", scope_factory)
    completed = W.run_observed_worker(**case.wer_kwargs())

    assert len(captures) == 1
    assert tuple(captures[0]["argv"]) == case.expected_final_argv
    child_environment = captures[0]["env"]
    assert isinstance(child_environment, dict)
    assert child_environment["CLAUDE_CODE_OAUTH_TOKEN"] == OFFLINE_TOKEN
    assert "ANTHROPIC_API_KEY" not in child_environment
    assert "CLAUDE_SECURESTORAGE_CONFIG_DIR" not in child_environment
    assert (
        M.claude_runtime_environment_key_set_sha256(
            tuple(child_environment)
        )
        == case.launch_request["policy"][
            "expected_child_environment_key_set_sha256"
        ]
    )
    assert len(scope_calls) == 1
    roots = tuple(scope_calls[0]["writable_roots"])
    runtime_root = Path(
        str(child_environment["CLAUDE_CONFIG_DIR"])
    ).parents[1]
    if sys.platform == "win32":
        assert runtime_root not in roots
    else:
        assert runtime_root in roots

    arm = json.loads(completed.arm_path.read_text(encoding="utf-8"))
    completion = json.loads(
        completed.receipt_path.read_text(encoding="utf-8")
    )
    assert arm["process_intent"]["argv"] == list(case.expected_final_argv)
    assert (
        arm["process_intent"]["argv_sha256"]
        == argv_authority_sha256(case.expected_final_argv)
    )
    assert _find_values(completion, "completion_authority") == [True]
    assert _find_values(completion, "closure_mode") == [
        "NORMAL_COMPLETION"
    ]
    assert _find_values(completion, "profile_first_cleanup") == [True]
    W.validate_completed_execution(
        scratchpad=tmp_path,
        receipt_path=completed.receipt_path,
        publish_receipt_path=None,
        parser_digest=_strict_json_digest,
        expected_completion_sha256=completed.completion_sha256,
        expected_publish_sha256=None,
    )


def test_stored_subscription_rc0_completes_only_with_unchanged_private_copy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        P,
        "observe_stored_subscription_source_authority",
        S.observe_stored_subscription_source_authority,
    )
    case = _case(
        tmp_path,
        label="stored-unchanged",
        route="STORED_SUBSCRIPTION_OAUTH",
    )
    captures = _install_fake_cli(monkeypatch, (case,))

    completed = W.run_observed_worker(**case.wer_kwargs())

    assert len(captures) == 1
    child_environment = captures[0]["env"]
    assert isinstance(child_environment, dict)
    assert "CLAUDE_CODE_OAUTH_TOKEN" not in child_environment
    completion = json.loads(
        completed.receipt_path.read_text(encoding="utf-8")
    )
    assert _find_values(
        completion,
        "current_attempt_credential_copy_status",
    ) == ["ORIGINAL_PRIVATE_COPY_UNCHANGED"]
    assert _find_values(completion, "completion_authority") == [True]
    assert _find_values(completion, "closure_mode") == [
        "NORMAL_COMPLETION"
    ]


def test_stored_subscription_rc0_rejects_replaced_private_copy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        P,
        "observe_stored_subscription_source_authority",
        S.observe_stored_subscription_source_authority,
    )
    case = _case(
        tmp_path,
        label="stored-replaced",
        route="STORED_SUBSCRIPTION_OAUTH",
    )
    _install_fake_cli(
        monkeypatch,
        (case,),
        replace_private_credential=True,
    )

    with pytest.raises(
        W.WorkerExecutionError,
        match="normal closure.*completion authority",
    ):
        W.run_observed_worker(**case.wer_kwargs())

    assert _completion_paths(tmp_path) == []
    public = _public_evidence_bytes(tmp_path)
    assert b"rotated-access-token" not in public
    assert b"rotated-refresh-token" not in public


def test_r42_restricted_stored_subscription_rc0_reaches_completion_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        P,
        "observe_claude_executable",
        lambda **_kwargs: _executable_observation(
            Path(sys.executable).resolve(strict=True),
            version="2.1.252",
        ),
    )
    monkeypatch.setattr(
        P,
        "observe_stored_subscription_source_authority",
        S.observe_stored_subscription_source_authority,
    )
    case = _case(
        tmp_path,
        label="r42-restricted-stored",
        route="STORED_SUBSCRIPTION_OAUTH",
        restricted=True,
    )
    captures = _install_fake_cli(monkeypatch, (case,))

    completed = W.run_observed_worker(**case.wer_kwargs())

    assert len(captures) == 1
    assert captures[0]["env"]["CLAUDE_CODE_SUBPROCESS_ENV_SCRUB"] == "1"
    completion = json.loads(
        completed.receipt_path.read_text(encoding="utf-8")
    )
    assert _find_values(completion, "completion_authority") == [True]
    assert _find_values(completion, "closure_mode") == [
        "NORMAL_COMPLETION"
    ]
    assert _find_values(
        completion,
        "current_attempt_credential_copy_status",
    ) == ["ORIGINAL_PRIVATE_COPY_UNCHANGED"]


def test_nonzero_provider_is_primary_and_failure_cleanup_cannot_complete(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = _case(tmp_path, label="nonzero-primary")
    case.fake_script.write_text(
        case.fake_script.read_text(encoding="utf-8")
        + "\nraise SystemExit(7)\n",
        encoding="utf-8",
    )
    _install_fake_cli(
        monkeypatch,
        (case,),
        advance_provider_state=False,
    )

    with pytest.raises(W.WorkerExecutionIncomplete) as captured:
        W.run_observed_worker(**case.wer_kwargs())

    assert captured.value.debt_path is not None
    debt = json.loads(
        captured.value.debt_path.read_text(encoding="utf-8")
    )
    assert debt["reason_code"] == "NONZERO_EXIT"
    assert debt["process_observation"]["returncode"] == 7
    cleanup = debt["process_observation"][
        "claude_runtime_failure_cleanup"
    ]
    assert cleanup == {
        "status": "CLEANED",
        "primary_reason_code": "NONZERO_EXIT",
        "secondary_reason_code": None,
    }
    lifecycle = debt["process_observation"][
        "claude_runtime_lifecycle"
    ]
    assert lifecycle["closure_mode"] == (
        "NORMAL_SCOPE_FAILURE_CLEANUP"
    )
    assert lifecycle["reason_code"] == "NONZERO_EXIT"
    assert lifecycle["completion_authority"] is False
    assert _completion_paths(tmp_path) == []
    assert not any(
        value is True
        for value in _find_values(debt, "completion_authority")
    )


def test_nonzero_primary_preserves_runtime_cleanup_fault_as_secondary_debt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = _case(tmp_path, label="nonzero-cleanup-fault")
    case.fake_script.write_text(
        case.fake_script.read_text(encoding="utf-8")
        + "\nraise SystemExit(7)\n",
        encoding="utf-8",
    )
    _install_fake_cli(
        monkeypatch,
        (case,),
        advance_provider_state=False,
    )
    real_cleanup = (
        M.ClaudeRuntimeMaterialization
        .revoke_after_failed_scope_close
    )

    def cleanup_then_fail(
        runtime: M.ClaudeRuntimeMaterialization,
        scope: object,
        reason_code: str,
        *,
        primary_failure_evidence_sha256: str,
    ) -> dict[str, object]:
        real_cleanup(
            runtime,
            scope,
            reason_code,
            primary_failure_evidence_sha256=(
                primary_failure_evidence_sha256
            ),
        )
        raise M.ClaudeRuntimeMaterializationError(
            "INJECTED_FAILURE_CLEANUP_FAULT",
            "injected post-cleanup receipt fault",
        )

    monkeypatch.setattr(
        M.ClaudeRuntimeMaterialization,
        "revoke_after_failed_scope_close",
        cleanup_then_fail,
    )

    with pytest.raises(W.WorkerExecutionIncomplete) as captured:
        W.run_observed_worker(**case.wer_kwargs())

    assert captured.value.debt_path is not None
    debt = json.loads(
        captured.value.debt_path.read_text(encoding="utf-8")
    )
    assert debt["reason_code"] == "NONZERO_EXIT"
    assert debt["process_observation"]["returncode"] == 7
    cleanup = debt["process_observation"][
        "claude_runtime_failure_cleanup"
    ]
    assert cleanup["status"] == "FAILED"
    assert cleanup["primary_reason_code"] == "NONZERO_EXIT"
    assert cleanup["secondary_reason_code"] == (
        "CLAUDE_RUNTIME_CLEANUP_FAILED"
    )
    assert "INJECTED_FAILURE_CLEANUP_FAULT" in cleanup["detail"]
    assert "INJECTED_FAILURE_CLEANUP_FAULT" in debt["detail"]
    assert _completion_paths(tmp_path) == []
    assert not any(
        value is True
        for value in _find_values(debt, "completion_authority")
    )


@pytest.mark.parametrize(
    ("failure", "reason"),
    (
        ("scope-constructor", "CLAUDE_RUNTIME_SCOPE_CONSTRUCTION_FAILED"),
        ("popen-factory", "CLAUDE_RUNTIME_PROCESS_CREATION_FAILED"),
        ("attach", "CLAUDE_RUNTIME_PROCESS_ATTACH_FAILED"),
    ),
)
def test_scope_constructor_popen_and_attach_failures_are_distinct_debt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
    reason: str,
) -> None:
    case = _case(tmp_path, label=f"failure-{failure}")
    captures = _install_fake_cli(monkeypatch, (case,))

    if failure == "scope-constructor":
        monkeypatch.setattr(
            W,
            "_OwnedProcessTree",
            lambda **_kwargs: (_ for _ in ()).throw(
                O.OwnedProcessScopeError("offline constructor failure")
            ),
        )
    elif failure == "popen-factory":
        monkeypatch.setattr(
            subprocess,
            "Popen",
            lambda *_args, **_kwargs: (_ for _ in ()).throw(
                OSError("offline Popen failure")
            ),
        )
    else:
        real_attach = O.OwnedProcessScope.attach

        def fail_after_attach(
            scope: O.OwnedProcessScope,
            process: object,
        ) -> None:
            real_attach(scope, process)
            raise O.OwnedProcessScopeError("offline attach failure")

        monkeypatch.setattr(
            O.OwnedProcessScope,
            "attach",
            fail_after_attach,
        )

    with pytest.raises(W.WorkerExecutionIncomplete):
        W.run_observed_worker(**case.wer_kwargs())
    assert _completion_paths(tmp_path) == []
    debt_reasons = [
        value.get("reason_code")
        for _path, value in _json_artifacts(tmp_path)
        if value.get("schema_version") == W.DEBT_SCHEMA
    ]
    assert debt_reasons == [reason]
    if failure == "scope-constructor":
        assert captures == []


def test_post_zero_reconcile_and_profile_first_revoke_precede_completion(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert hasattr(W, "reconcile_claude_runtime_after_scope_close"), (
        "WER must use the explicit typed post-zero reconciliation API"
    )
    case = _case(tmp_path, label="post-zero-order")
    _install_fake_cli(monkeypatch, (case,))
    events: list[str] = []
    real_reconcile = W.reconcile_claude_runtime_after_scope_close
    real_revoke = M.ClaudeRuntimeMaterialization.revoke_after_normal_scope_close
    real_persist = W._persist_hashed_json

    def reconcile(runtime: object, scope: object) -> dict[str, object]:
        assert getattr(scope, "closed") is True
        assert getattr(scope, "population_zero_proven") is True
        assert getattr(scope, "attached") is True
        events.append("post-zero-reconcile")
        return real_reconcile(runtime, scope)

    def revoke(
        runtime: M.ClaudeRuntimeMaterialization,
        scope: object,
    ) -> dict[str, object]:
        assert events == ["post-zero-reconcile"]
        events.append("profile-first-revoke")
        return real_revoke(runtime, scope)

    def persist(
        directory: Path,
        prefix: str,
        payload: Mapping[str, object],
    ) -> tuple[Path, str]:
        if prefix == "completion":
            assert events == [
                "post-zero-reconcile",
                "profile-first-revoke",
            ]
            events.append("completion")
        return real_persist(directory, prefix, payload)

    monkeypatch.setattr(
        W,
        "reconcile_claude_runtime_after_scope_close",
        reconcile,
    )
    monkeypatch.setattr(
        M.ClaudeRuntimeMaterialization,
        "revoke_after_normal_scope_close",
        revoke,
    )
    monkeypatch.setattr(W, "_persist_hashed_json", persist)
    W.run_observed_worker(**case.wer_kwargs())
    assert events == [
        "post-zero-reconcile",
        "profile-first-revoke",
        "completion",
    ]


def test_late_profile_mutation_after_diagnostic_reconcile_blocks_completion(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = _case(tmp_path, label="late-profile-mutation")
    _install_fake_cli(monkeypatch, (case,))
    real_reconcile = W.reconcile_claude_runtime_after_scope_close
    mutation_observed: list[Path] = []

    def reconcile_then_mutate(
        runtime: M.ClaudeRuntimeMaterialization,
        scope: object,
    ) -> dict[str, object]:
        receipt = real_reconcile(runtime, scope)
        state_path = (
            runtime.process_writable_root
            / "claude-profile"
            / "claude-config"
            / ".claude.json"
        )
        state = json.loads(state_path.read_text(encoding="utf-8"))
        state["mcpServers"] = {
            "late-unreviewed-server": {
                "command": "forbidden-after-reconcile"
            }
        }
        state_path.write_text(
            json.dumps(
                state,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ),
            encoding="utf-8",
        )
        mutation_observed.append(state_path)
        return receipt

    monkeypatch.setattr(
        W,
        "reconcile_claude_runtime_after_scope_close",
        reconcile_then_mutate,
    )
    with pytest.raises(
        W.WorkerExecutionIncomplete,
        match="runtime|observation|cleanup",
    ):
        W.run_observed_worker(**case.wer_kwargs())
    assert len(mutation_observed) >= 1
    assert _completion_paths(tmp_path) == []
    debt_payloads = [
        payload
        for path, payload in _json_artifacts(tmp_path)
        if path.name.startswith("debt_")
    ]
    assert debt_payloads
    assert all(
        payload.get("completion_emitted") is False
        for payload in debt_payloads
    )
    assert "NORMAL_COMPLETION" not in [
        item
        for payload in debt_payloads
        for item in _find_values(payload, "closure_mode")
    ]


def test_runtime_request_is_one_shot_and_cannot_mint_two_completions(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = _case(tmp_path, label="one-shot")
    _install_fake_cli(monkeypatch, (case,))
    W.run_observed_worker(**case.wer_kwargs())
    assert len(_completion_paths(tmp_path)) == 1
    calls: list[object] = []
    monkeypatch.setattr(
        subprocess,
        "Popen",
        lambda *args, **kwargs: calls.append((args, kwargs)),
    )
    second = case.wer_kwargs()
    second["output_scope_relative"] = "worker-out-one-shot-second"
    second["expected_outputs"] = (
        W.ExpectedOutput(
            "finding-one-shot-second",
            "result.json",
            "canonical/one-shot-second.json",
        ),
    )
    with pytest.raises(
        W.WorkerExecutionError,
        match="claimed|one-shot|consumed|runtime request",
    ):
        W.run_observed_worker(**second)
    assert calls == []
    assert len(_completion_paths(tmp_path)) == 1


@pytest.mark.parametrize("artifact", ("arm", "completion"))
def test_durable_arm_and_completion_mutations_fail_replay(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    artifact: str,
) -> None:
    case = _case(tmp_path, label=f"mutation-{artifact}")
    _install_fake_cli(monkeypatch, (case,))
    completed = W.run_observed_worker(**case.wer_kwargs())
    target = (
        completed.arm_path
        if artifact == "arm"
        else completed.receipt_path
    )
    payload = json.loads(target.read_text(encoding="utf-8"))
    payload["offline_mutation"] = True
    try:
        target.chmod(0o600)
        target.write_text(json.dumps(payload), encoding="utf-8")
    except OSError:
        pytest.skip("platform forbids deliberate fixture mutation")
    with pytest.raises(W.WorkerExecutionError):
        W.validate_completed_execution(
            scratchpad=tmp_path,
            receipt_path=completed.receipt_path,
            publish_receipt_path=None,
            parser_digest=_strict_json_digest,
            expected_completion_sha256=completed.completion_sha256,
            expected_publish_sha256=None,
        )


def test_public_evidence_never_persists_token_hash_or_host_paths(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = _case(tmp_path, label="redaction")
    _install_fake_cli(monkeypatch, (case,))
    W.run_observed_worker(**case.wer_kwargs())
    public = _all_json_text(tmp_path)
    public_bytes = _public_evidence_bytes(tmp_path)
    assert OFFLINE_TOKEN not in public
    assert OFFLINE_TOKEN.encode("utf-8") not in public_bytes
    assert _raw_sha256(OFFLINE_TOKEN.encode("utf-8")) not in public
    assert (
        _raw_sha256(OFFLINE_TOKEN.encode("utf-8")).encode("ascii")
        not in public_bytes
    )
    assert "must-be-removed-api-key" not in public
    assert "attacker-controlled-secure-store" not in public
    for name in (
        "credential_values_recorded",
        "credential_content_hashes_recorded",
        "host_paths_recorded",
    ):
        values = [
            item
            for _path, payload in _json_artifacts(tmp_path)
            for item in _find_values(payload, name)
        ]
        assert values
        assert set(values) == {False}


@pytest.mark.parametrize(
    "fault",
    ("startup", "version", "inner-arm", "revocation"),
)
def test_startup_version_inner_arm_and_revocation_faults_never_complete(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fault: str,
) -> None:
    case = _case(tmp_path, label=f"fault-{fault}")
    captures = _install_fake_cli(monkeypatch, (case,))
    expected_exception: type[BaseException] = W.WorkerExecutionError

    if fault == "startup":
        rotate_startup_permit(tmp_path)
    elif fault == "version":
        real_recheck = W._recheck_claude_executable_before_launch

        def changed(*args: object, **kwargs: object) -> object:
            real_recheck(*args, **kwargs)
            raise RuntimeError("offline executable-version drift")

        monkeypatch.setattr(
            W,
            "_recheck_claude_executable_before_launch",
            changed,
        )
    elif fault == "inner-arm":
        real_persist = W._persist_hashed_json

        def mutate_arm(
            directory: Path,
            prefix: str,
            payload: Mapping[str, object],
        ) -> tuple[Path, str]:
            path, digest = real_persist(directory, prefix, payload)
            if prefix == "arm":
                value = json.loads(path.read_text(encoding="utf-8"))
                value["armed_at_unix_ns"] += 1
                path.chmod(0o600)
                path.write_text(json.dumps(value), encoding="utf-8")
            return path, digest

        monkeypatch.setattr(W, "_persist_hashed_json", mutate_arm)
    else:
        expected_exception = W.WorkerExecutionIncomplete

        def fail_revoke(
            self: M.ClaudeRuntimeMaterialization,
            scope: object,
        ) -> dict[str, object]:
            raise M.ClaudeRuntimeMaterializationError(
                "OFFLINE_REVOCATION_FAILURE",
                "offline revocation failure",
            )

        monkeypatch.setattr(
            M.ClaudeRuntimeMaterialization,
            "revoke_after_normal_scope_close",
            fail_revoke,
        )

    with pytest.raises(expected_exception):
        W.run_observed_worker(**case.wer_kwargs())
    assert _completion_paths(tmp_path) == []
    if fault in {"startup", "version", "inner-arm"}:
        assert captures == []


def _emergency_cleanup_child(
    root: Path,
    population_zero: bool,
) -> None:
    root.mkdir(parents=True, exist_ok=False)
    A._default_runtime_namespace = lambda: _fixture_runtime_namespace(root)
    monkeypatch = pytest.MonkeyPatch()
    provider_fixtures._install_observers(
        monkeypatch,
        Path(sys.executable).resolve(strict=True),
    )
    case = _case(
        root,
        label=f"emergency-{int(population_zero)}",
    )
    _install_fake_cli(monkeypatch, (case,))
    real_attach = O.OwnedProcessScope.attach
    real_emergency_close = O.OwnedProcessScope.emergency_close

    def fail_after_attach(
        scope: O.OwnedProcessScope,
        process: object,
    ) -> None:
        real_attach(scope, process)
        raise O.OwnedProcessScopeError("offline post-attach failure")

    def emergency_close(scope: O.OwnedProcessScope) -> None:
        if population_zero:
            scope.terminate()
            scope.close()
            scope._emergency_closed = True
            return
        real_emergency_close(scope)

    monkeypatch.setattr(
        O.OwnedProcessScope,
        "attach",
        fail_after_attach,
    )
    monkeypatch.setattr(
        O.OwnedProcessScope,
        "emergency_close",
        emergency_close,
    )
    if not population_zero and os.name == "nt":
        monkeypatch.setattr(
            O.OwnedProcessScope,
            "_wait_windows_population_zero",
            lambda _scope: (_ for _ in ()).throw(
                O.OwnedProcessScopeError(
                    "offline zero population cannot be proven"
                )
            ),
        )
    try:
        W.run_observed_worker(**case.wer_kwargs())
    except W.WorkerExecutionIncomplete:
        pass
    else:
        raise AssertionError("emergency cleanup minted completion")
    assert _completion_paths(root) == []
    expected_mode = (
        "EMERGENCY_ZERO_POPULATION_CLEANUP"
        if population_zero
        else "EMERGENCY_ZERO_UNPROVEN_DEBT"
    )
    modes = [
        item
        for _path, payload in _json_artifacts(root)
        for item in _find_values(payload, "closure_mode")
    ]
    assert expected_mode in modes
    assert True not in [
        item
        for _path, payload in _json_artifacts(root)
        for item in _find_values(payload, "completion_authority")
    ]
    monkeypatch.undo()


@pytest.mark.parametrize("population_zero", (True, False))
def test_emergency_zero_is_cleanup_only_and_unproven_zero_is_quarantined(
    tmp_path: Path,
    population_zero: bool,
) -> None:
    child_root = tmp_path / f"isolated-{int(population_zero)}"
    module_root = str(Path(__file__).resolve().parent)
    code = (
        "import sys;"
        f"sys.path.insert(0,{module_root!r});"
        "from pathlib import Path;"
        "import test_wer_claude_runtime_lifecycle_p0_am as F;"
        f"F._emergency_cleanup_child("
        f"Path({str(child_root)!r}),{population_zero!r})"
    )
    completed = subprocess.run(
        [sys.executable, "-I", "-c", code],
        check=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stderr.decode(
        "utf-8",
        errors="replace",
    )


def _hard_crash_child(root: Path, cutpoint: str) -> None:
    """Run one WER cutpoint in a disposable child interpreter."""

    A._default_runtime_namespace = lambda: _fixture_runtime_namespace(root)
    monkeypatch = pytest.MonkeyPatch()
    provider_fixtures._install_observers(
        monkeypatch,
        Path(sys.executable).resolve(strict=True),
    )
    case = _case(root, label=f"hard-{cutpoint}")
    real_popen = subprocess.Popen

    def fake_popen(
        _argv: object,
        **kwargs: object,
    ) -> subprocess.Popen[bytes]:
        environment = dict(kwargs.get("env") or {})
        state_path = (
            Path(str(environment["CLAUDE_CONFIG_DIR"]))
            / ".claude.json"
        )
        state = json.loads(state_path.read_text(encoding="utf-8"))
        state["numStartups"] = 2
        state_path.write_text(
            json.dumps(
                state,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ),
            encoding="utf-8",
        )
        return real_popen(
            [sys.executable, str(case.fake_script)],
            **kwargs,
        )

    subprocess.Popen = fake_popen  # type: ignore[assignment]
    if not hasattr(W, "materialize_claude_runtime"):
        raise AssertionError("WER runtime materialization seam is absent")

    if cutpoint == "after-materialization":
        real_materialize = W.materialize_claude_runtime

        def materialize_then_crash(request: object) -> object:
            runtime = real_materialize(request)
            del runtime
            os._exit(81)

        W.materialize_claude_runtime = materialize_then_crash
    elif cutpoint == "after-inner-arm":
        real_persist = W._persist_hashed_json

        def arm_then_crash(
            directory: Path,
            prefix: str,
            payload: Mapping[str, object],
        ) -> tuple[Path, str]:
            result = real_persist(directory, prefix, payload)
            if prefix == "arm":
                os._exit(82)
            return result

        W._persist_hashed_json = arm_then_crash
    elif cutpoint == "after-process-created":
        real_create = O.OwnedProcessScope.create_process

        def create_then_crash(
            scope: O.OwnedProcessScope,
            physical_argv: object,
            **kwargs: object,
        ) -> object:
            process = real_create(
                scope,
                physical_argv,
                **kwargs,
            )
            del process
            os._exit(83)

        O.OwnedProcessScope.create_process = (  # type: ignore[method-assign]
            create_then_crash
        )
    elif cutpoint == "after-revocation":
        real_revoke = (
            M.ClaudeRuntimeMaterialization.revoke_after_normal_scope_close
        )

        def revoke_then_crash(
            runtime: M.ClaudeRuntimeMaterialization,
            scope: object,
        ) -> dict[str, object]:
            receipt = real_revoke(runtime, scope)
            del receipt
            os._exit(84)

        M.ClaudeRuntimeMaterialization.revoke_after_normal_scope_close = (
            revoke_then_crash
        )
    else:
        raise AssertionError(f"unknown hard-crash cutpoint: {cutpoint}")
    W.run_observed_worker(**case.wer_kwargs())
    raise AssertionError("hard-crash cutpoint was not reached")


@pytest.mark.parametrize(
    ("cutpoint", "returncode"),
    (
        ("after-materialization", 81),
        ("after-inner-arm", 82),
        ("after-process-created", 83),
        ("after-revocation", 84),
    ),
)
def test_subprocess_hard_crash_cutpoints_cannot_mint_completion(
    tmp_path: Path,
    cutpoint: str,
    returncode: int,
) -> None:
    child_root = tmp_path / cutpoint
    module_root = str(Path(__file__).resolve().parent)
    code = (
        "import sys;"
        f"sys.path.insert(0,{module_root!r});"
        "from pathlib import Path;"
        "import test_wer_claude_runtime_lifecycle_p0_am as F;"
        f"F._hard_crash_child(Path({str(child_root)!r}),{cutpoint!r})"
    )
    completed = subprocess.run(
        [sys.executable, "-I", "-c", code],
        check=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
    )
    assert completed.returncode == returncode, completed.stderr.decode(
        "utf-8", errors="replace"
    )
    assert _completion_paths(child_root) == []
    public = _all_json_text(child_root)
    public_bytes = _public_evidence_bytes(child_root)
    assert OFFLINE_TOKEN not in public
    assert OFFLINE_TOKEN.encode("utf-8") not in public_bytes
    assert _raw_sha256(OFFLINE_TOKEN.encode()) not in public
    assert (
        _raw_sha256(OFFLINE_TOKEN.encode()).encode("ascii")
        not in public_bytes
    )


def test_outer_attempt_arm_directory_fsync_precedes_request_compile(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # This test imports a helper from another test module, so that module's
    # autouse fixture does not run here.  Install only the offline provider
    # observations and command-template lookup needed to prepare and attach
    # the real production authority package.
    from test_claude_launch_authority_fixtures import (
        install_test_only_launch_authority_adapter,
    )

    install_test_only_launch_authority_adapter(monkeypatch.setattr)
    assert hasattr(T, "compile_claude_runtime_materialization_request")
    adapter_fields = inspect.signature(T.HeadlessModelAdapter).parameters
    assert "claude_runtime_local_inputs" not in adapter_fields
    assert "claude_provider_preparation" in adapter_fields
    assert "claude_provider_runtime" in adapter_fields

    from test_worker_work_plan_v2_roster_binding_p0_am import (
        _arm_phaseio,
        _run_headless,
    )

    _arm_phaseio(tmp_path)
    (tmp_path / "allow-success").write_text("yes", encoding="utf-8")
    events: list[tuple[str, Path | None]] = []
    real_write = T._write_absent_json
    real_fsync = T._fsync_directory

    def write(path: Path, value: Mapping[str, object]) -> None:
        real_write(path, value)
        if path.name == "arm.json":
            events.append(("outer-arm-written", path))

    def fsync(path: Path) -> None:
        real_fsync(path)
        events.append(("directory-fsync", path))

    class StopAfterCompile(RuntimeError):
        pass

    def compile_request(**kwargs: object) -> object:
        assert "host_inputs" not in kwargs
        assert isinstance(
            kwargs["provider_runtime"],
            P.ClaimedClaudeProviderRuntime,
        )
        arm_paths = [
            path
            for name, path in events
            if name == "outer-arm-written" and path is not None
        ]
        assert len(arm_paths) == 1
        assert arm_paths[0].is_file()
        assert any(
            name == "directory-fsync" and path == arm_paths[0].parent
            for name, path in events
        )
        events.append(("request-compile", None))
        raise StopAfterCompile

    monkeypatch.setattr(T, "_write_absent_json", write)
    monkeypatch.setattr(T, "_fsync_directory", fsync)
    monkeypatch.setattr(
        T,
        "compile_claude_runtime_materialization_request",
        compile_request,
    )
    with pytest.raises(StopAfterCompile):
        _run_headless(
            tmp_path,
            attempt_id="attempt-" + "e" * 24,
        )
    names = [name for name, _path in events]
    assert names.index("outer-arm-written") < names.index(
        "request-compile"
    )


def test_runtime_root_scope_authority_is_platform_bounded_and_not_generic(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = _case(tmp_path, label="lease-separation")
    captures = _install_fake_cli(monkeypatch, (case,))
    real_generic = W._armed_auxiliary_lease_binding
    real_scope = W._OwnedProcessTree
    generic_inputs: list[tuple[object, ...]] = []
    scope_roots: list[tuple[Path, ...]] = []

    def generic(
        leases: object,
        **kwargs: object,
    ) -> object:
        generic_inputs.append(tuple(leases))
        return real_generic(leases, **kwargs)

    def scope(**kwargs: object) -> object:
        scope_roots.append(tuple(kwargs["writable_roots"]))
        return real_scope(**kwargs)

    monkeypatch.setattr(W, "_armed_auxiliary_lease_binding", generic)
    monkeypatch.setattr(W, "_OwnedProcessTree", scope)
    completed = W.run_observed_worker(**case.wer_kwargs())
    assert generic_inputs == [()]
    assert len(scope_roots) == 1
    runtime_root = Path(
        str(captures[0]["env"]["CLAUDE_CONFIG_DIR"])
    ).parents[1]
    if sys.platform == "win32":
        # Windows grants the confined child write authority only to the
        # pre-existing provider-owned .claude.json state file.  Passing the
        # lease parent to OwnedProcessScope would lower the whole directory
        # and allow sibling creation/deletion.
        assert runtime_root not in scope_roots[0]
        assert len(scope_roots[0]) == 1
    else:
        # POSIX Landlock needs the attempt-private runtime root in the owned
        # process scope because it has no per-file MIC label.
        assert runtime_root in scope_roots[0]
        assert len(scope_roots[0]) >= 2
    arm = json.loads(completed.arm_path.read_text(encoding="utf-8"))
    generic_bindings = arm["process_intent"]["completion_observer"][
        "auxiliary_root_leases"
    ]
    assert generic_bindings == []
    runtime_binding_sha = _find_values(
        arm,
        "auxiliary_lease_binding_sha256",
    )
    assert len(runtime_binding_sha) == 1


def test_prelaunch_rejection_discards_and_zeroizes_unclaimed_request(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = _case(tmp_path, label="discard")
    plan_path = (
        tmp_path / "launch-inputs-discard" / "plan.json"
    )
    plan_path.write_bytes(plan_path.read_bytes() + b" ")
    calls: list[object] = []
    monkeypatch.setattr(
        subprocess,
        "Popen",
        lambda *args, **kwargs: calls.append((args, kwargs)),
    )
    with pytest.raises(
        W.WorkerExecutionError,
        match="WorkPlan|runtime.*authority|digest",
    ):
        W.run_observed_worker(**case.wer_kwargs())
    assert calls == []
    assert OFFLINE_TOKEN not in repr(case.request)
    with pytest.raises(
        M.ClaudeRuntimeMaterializationError,
        match="discard|claimed|consumed|zero",
    ):
        M.materialize_claude_runtime(case.request)


def test_two_concurrent_attempts_have_disjoint_runtime_and_scope_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = _case(tmp_path, label="concurrent-a")
    second = _case(
        tmp_path,
        label="concurrent-b",
        startup_binding=first.startup_binding,
    )
    captures = _install_fake_cli(monkeypatch, (first, second))
    real_scope = W._OwnedProcessTree
    scope_rows: list[tuple[str, tuple[Path, ...]]] = []
    lock = threading.Lock()

    def scope(**kwargs: object) -> object:
        row = (
            str(kwargs["persistent_identity"]),
            tuple(kwargs["writable_roots"]),
        )
        with lock:
            scope_rows.append(row)
        return real_scope(**kwargs)

    monkeypatch.setattr(W, "_OwnedProcessTree", scope)
    with ThreadPoolExecutor(max_workers=2) as pool:
        completed = list(
            pool.map(
                lambda case: W.run_observed_worker(
                    **case.wer_kwargs()
                ),
                (first, second),
            )
        )
    assert len(completed) == 2
    assert len(captures) == 2
    assert {row[0] for row in scope_rows} == {
        "scope-concurrent-a",
        "scope-concurrent-b",
    }
    output_roots = {
        (tmp_path / first.output_scope).resolve(),
        (tmp_path / second.output_scope).resolve(),
    }
    runtime_roots = [
        {path.resolve() for path in roots} - output_roots
        for _identity, roots in scope_rows
    ]
    profile_roots = [
        Path(str(capture["env"]["CLAUDE_CONFIG_DIR"])).parents[1].resolve()
        for capture in captures
    ]
    assert profile_roots[0] != profile_roots[1]
    if sys.platform == "win32":
        assert runtime_roots == [set(), set()]
        scoped_paths = {
            path.resolve()
            for _identity, roots in scope_rows
            for path in roots
        }
        assert all(
            profile_root not in scoped_paths
            for profile_root in profile_roots
        )
    else:
        assert all(runtime_roots)
        assert runtime_roots[0].isdisjoint(runtime_roots[1])
    assert len(_completion_paths(tmp_path)) == 2
    assert OFFLINE_TOKEN not in _all_json_text(tmp_path)
    assert (
        OFFLINE_TOKEN.encode("utf-8")
        not in _public_evidence_bytes(tmp_path)
    )
