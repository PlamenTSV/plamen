"""Claude launch-security authority at the headless WorkPlan boundary."""

from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import shutil
import sys
from typing import Any, Callable, Mapping

import pytest

import artifact_ledger as ledger
import claude_launch_security as L
from claude_child_environment import (
    planned_claude_child_environment_key_set_sha256,
    planned_claude_child_environment_names,
)
from claude_headless_profile import (
    compile_claude_headless_profile_from_authorities,
)
from test_claude_launch_authority_fixtures import (
    compile_test_claude_provider_preparation,
    compile_test_claude_runtime_local_inputs,
    install_test_only_launch_authority_adapter,
)
import headless_worker_runtime as H
from phase_io_contracts import (
    ArtifactSpec,
    LaunchSpec,
    PhaseIOContract,
    canonical_work_unit_key,
)
from test_support_startup_permit import (
    FIXTURE_RUN_ID as RUN_ID,
    durable_startup_permit,
)
import worker_execution_receipts as W
import worker_transaction as T


VERSION = "2.1.252"
MODEL = "fixture-model"
SESSION_ID = "11111111-2222-4333-8444-555555555555"
STDOUT_LIMIT = 16 * 1024 * 1024
CURRENT_FUNCTIONAL_CONTROLS = {
    "CLAUDE_CODE_DISABLE_OFFICIAL_MARKETPLACE_AUTOINSTALL": "1",
    "CLAUDE_CODE_SUBPROCESS_ENV_SCRUB": "1",
    "DISABLE_AUTOUPDATER": "1",
    "DISABLE_UPDATES": "1",
    "ENABLE_CLAUDEAI_MCP_SERVERS": "false",
}


@pytest.fixture(autouse=True)
def _offline_provider_observers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_executable = Path(sys.executable).resolve(strict=True)
    fixture_executable = tmp_path / "claude-executable-fixture.exe"
    shutil.copyfile(source_executable, fixture_executable)
    assert fixture_executable.stat().st_nlink == 1
    monkeypatch.setattr(sys, "executable", str(fixture_executable))
    install_test_only_launch_authority_adapter(monkeypatch.setattr)


def _digest(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def _executable_observation() -> dict[str, Any]:
    executable = Path(sys.executable).resolve(strict=True)
    stat_row = executable.stat()
    assert stat_row.st_nlink == 1
    file_row = {
        "role": "CONFIGURED_EXECUTABLE",
        "path": str(executable),
        "sha256": hashlib.sha256(executable.read_bytes()).hexdigest(),
        "size": int(stat_row.st_size),
        "device": int(stat_row.st_dev),
        "inode": int(stat_row.st_ino),
        "mode": int(stat_row.st_mode),
        "link_count": int(stat_row.st_nlink),
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


def _security(
    root: Path,
    *,
    model: str = MODEL,
    cwd: Path | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    expected_cwd = (cwd or root).resolve()
    runtime_local_inputs = compile_test_claude_runtime_local_inputs(
        cwd=root
    )
    ambient = runtime_local_inputs["ambient_environment"]
    auth = L.compile_claude_auth_route_policy(
        claude_code_version=VERSION,
        desired_route="OAUTH_TOKEN",
    )
    executable = _executable_observation()
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
        cwd=str(expected_cwd),
        accepted_models=(model,),
        permission_mode="dontAsk",
        builtin_tools=("Edit", "Glob", "Grep", "Read", "Write"),
        required_tools=("Read",),
        forbidden_tools=("Bash",),
    )
    controls = dict(CURRENT_FUNCTIONAL_CONTROLS)
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
        settings_authority=settings,
        mcp_authority=mcp,
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
    request = L.compile_claude_launch_security_request(
        policy=policy,
        executable_observation=executable,
    )
    return policy, request


def _stream_policy(policy: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "schema": W.CLAUDE_STREAM_STDOUT_CONFIGURATION_SCHEMA,
        "expected_session_id": SESSION_ID,
        "expected_init_contract": deepcopy(
            policy["headless_profile"]["expected_init_contract"]
        ),
        "max_line_bytes": 2 * 1024 * 1024,
        "max_stream_bytes": STDOUT_LIMIT,
    }


def _authority(
    root: Path,
    *,
    backend: str,
) -> tuple[PhaseIOContract, LaunchSpec]:
    key = canonical_work_unit_key(
        "sc",
        "thorough",
        "evm",
        backend,
        "depth",
        f"worker.launch-security-{backend}",
    )
    contract = PhaseIOContract(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend=backend,
        phase="depth",
        work_unit_id=f"worker.launch-security-{backend}",
        outputs=(
            ArtifactSpec(
                root="scratchpad",
                path=f"launch_security_{backend}.md",
                owner_key=key,
                artifact_class="REQUIRED",
                writer="MODEL",
                write_mode="CREATE",
            ),
        ),
    )
    launch = LaunchSpec(
        work_unit_key=key,
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend=backend,
        model=MODEL,
        timeout_s=30,
        exec_mode="headless" if backend == "claude" else "exec",
        tool_policy=("filesystem",),
    )
    ledger.record_work_unit_inputs(
        root,
        root,
        contract,
        launch,
        run_id=RUN_ID,
    )
    return contract, launch


def _builder(
    calls: list[Path] | None = None,
) -> Callable[[Path], tuple[str, ...]]:
    def build(output_directory: Path) -> tuple[str, ...]:
        if calls is not None:
            calls.append(output_directory)
        return (
            sys.executable,
            "-I",
            "-c",
            "raise SystemExit(0)",
            "-p",
            "--model",
            MODEL,
            "--output-format",
            "stream-json",
            "--verbose",
            "--session-id",
            SESSION_ID,
            "--no-session-persistence",
        )

    return build


def _prepare(
    root: Path,
    *,
    backend: str = "claude",
    policy: Mapping[str, Any] | None,
    request: Mapping[str, Any] | None,
    stream_policy: Mapping[str, Any] | None,
    command_builder: Callable[[Path], tuple[str, ...]] | None = None,
    cwd: Path | None = None,
    force_codex_runtime_local_inputs: bool = False,
) -> H.PreparedHeadlessWorker:
    contract, launch = _authority(root, backend=backend)
    runtime_local_inputs = (
        compile_test_claude_runtime_local_inputs(cwd=root)
        if (
            (backend == "claude" and policy is not None)
            or force_codex_runtime_local_inputs
        )
        else None
    )
    environment_allowlist = ()
    if runtime_local_inputs is not None and policy is not None:
        ambient = runtime_local_inputs["ambient_environment"]
        environment_allowlist = (
            planned_claude_child_environment_names(
                ambient=ambient,
                selected_route=policy["auth_route_policy"][
                    "desired_route"
                ],
                endpoint_environment_names=tuple(
                    policy["auth_route_policy"]["endpoint_policy"][
                        "endpoint_environment"
                    ]
                ),
                phase_environment_policies=policy[
                    "phase_environment_policies"
                ],
                functional_control_names=tuple(
                    policy["functional_controls"]
                ),
                home_variable_policy=policy[
                    "home_variable_policy"
                ],
            )
        )
    builder = command_builder or _builder()
    startup = durable_startup_permit(root)
    provider_preparation = None
    profile_init = (
        policy.get("headless_profile", {}).get(
            "expected_init_contract", {}
        )
        if isinstance(policy, Mapping)
        else {}
    )
    provider_contract_is_self_consistent = (
        backend == "claude"
        and policy is not None
        and request is not None
        and request.get("policy") == policy
        and stream_policy is not None
        and stream_policy.get("expected_init_contract") == profile_init
        and MODEL in profile_init.get("accepted_models", ())
        and profile_init.get("cwd") == str(root.resolve())
    )
    if provider_contract_is_self_consistent:
        provider_preparation = compile_test_claude_provider_preparation(
            authority={
                "policy": policy,
                "request": request,
                "stream_configuration": stream_policy,
                "environment_allowlist": environment_allowlist,
                "runtime_local_inputs": runtime_local_inputs,
            },
            base_argv=builder(Path("unused")),
            cwd=root,
            run_id=RUN_ID,
            phase=contract.phase,
            startup_authority_binding=startup,
            source_snapshot_sha256="a" * 64,
        )
    return H.prepare_headless_worker(
        scratchpad=root,
        project_root=root,
        run_id=RUN_ID,
        phase_io_contract=contract,
        phase_io_launch=launch,
        prompt="Analyze the assigned role and write the artifact.",
        command_builder=builder,
        cwd=cwd or root,
        environment={},
        environment_allowlist=environment_allowlist,
        source_snapshot_digest="a" * 64,
        methodology_digests=("b" * 64,),
        startup_authority_binding=startup,
        stdout_limit_bytes=STDOUT_LIMIT,
        provider_stdout_evidence_configuration=stream_policy,
        claude_launch_security=policy,
        claude_launch_security_request=request,
        claude_provider_preparation=provider_preparation,
        claude_runtime_local_inputs=runtime_local_inputs,
    )


def _roster(
    prepared: H.PreparedHeadlessWorker,
) -> dict[str, Any]:
    plan = prepared.work_plan
    return T.compile_phase_work_roster(
        run_id=plan["run_id"],
        phase=plan["phase"],
        generation=plan["generation"],
        required_work_unit_ids=(plan["work_unit_id"],),
        work_plan_digests={
            plan["work_unit_id"]: plan["work_plan_digest"],
        },
    )


def test_claude_fixture_binds_exact_current_functional_control_roster(
    tmp_path: Path,
) -> None:
    policy, _request = _security(tmp_path)
    assert policy["functional_controls"] == CURRENT_FUNCTIONAL_CONTROLS


@pytest.mark.parametrize(
    "drop",
    ("policy", "request", "both", "stream"),
)
def test_claude_prepare_requires_policy_request_and_stream_before_builder(
    tmp_path: Path,
    drop: str,
) -> None:
    policy, request = _security(tmp_path)
    stream = _stream_policy(policy)
    if drop in {"policy", "both"}:
        policy = None
    if drop in {"request", "both"}:
        request = None
    if drop == "stream":
        stream = None
    calls: list[Path] = []

    with pytest.raises(
        H.HeadlessWorkerRuntimeError,
        match="launch-security|stream",
    ):
        _prepare(
            tmp_path,
            policy=policy,
            request=request,
            stream_policy=stream,
            command_builder=_builder(calls),
        )
    assert calls == []


def test_claude_policy_is_in_plan_and_request_is_frozen_then_adapted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy, request = _security(tmp_path)
    expected_policy = deepcopy(policy)
    expected_request = deepcopy(request)
    prepared = _prepare(
        tmp_path,
        policy=policy,
        request=request,
        stream_policy=_stream_policy(policy),
    )
    local_inputs = compile_test_claude_runtime_local_inputs(
        cwd=tmp_path
    )
    secret = local_inputs["ambient_environment"][
        "CLAUDE_CODE_OAUTH_TOKEN"
    ]

    policy["policy_sha256"] = "f" * 64
    request["request_sha256"] = "e" * 64
    assert secret not in repr(prepared)
    assert secret not in json.dumps(
        prepared.work_plan,
        sort_keys=True,
    )
    assert not hasattr(prepared, "claude_runtime_local_inputs")
    assert prepared.work_plan["completion_policy"][
        T.CLAUDE_LAUNCH_SECURITY_POLICY_KEY
    ] == expected_policy
    assert prepared.claude_launch_security_request == expected_request
    caller_copy = prepared.claude_launch_security_request
    assert caller_copy is not None
    caller_copy["request_sha256"] = "d" * 64
    assert prepared.claude_launch_security_request == expected_request

    captured: dict[str, Any] = {}

    def capture(
        _plan: Mapping[str, Any],
        adapter: T.NativeCommandAdapter | T.HeadlessModelAdapter,
        _cancel_token: Any,
    ) -> T.ExecutionRef:
        assert isinstance(adapter, T.HeadlessModelAdapter)
        assert secret not in repr(adapter)
        captured["request"] = adapter.claude_launch_security_request
        raise T.WorkerTransactionError("fixture stop before provider")

    monkeypatch.setattr(H, "execute_worker_transaction", capture)
    with pytest.raises(
        H.HeadlessWorkerRuntimeError,
        match="fixture stop",
    ):
        H.execute_prepared_headless_worker(
            prepared,
            _roster(prepared),
        )
    assert captured["request"] == expected_request


def test_claude_request_policy_substitution_rejects_before_builder(
    tmp_path: Path,
) -> None:
    policy, _request = _security(tmp_path)
    other_policy, other_request = _security(
        tmp_path,
        model="different-model",
    )
    del other_policy
    calls: list[Path] = []

    with pytest.raises(
        H.HeadlessWorkerRuntimeError,
        match="request.*policy|policy.*request",
    ):
        _prepare(
            tmp_path,
            policy=policy,
            request=other_request,
            stream_policy=_stream_policy(policy),
            command_builder=_builder(calls),
        )
    assert calls == []


@pytest.mark.parametrize("supplied", ("policy", "request", "both"))
def test_codex_rejects_any_claude_launch_security_authority(
    tmp_path: Path,
    supplied: str,
) -> None:
    policy, request = _security(tmp_path)
    with pytest.raises(
        H.HeadlessWorkerRuntimeError,
        match="Codex.*Claude|Claude.*Codex",
    ):
        _prepare(
            tmp_path,
            backend="codex",
            policy=policy if supplied in {"policy", "both"} else None,
            request=request if supplied in {"request", "both"} else None,
            stream_policy=None,
        )


def test_codex_rejects_claude_runtime_local_inputs_without_policy(
    tmp_path: Path,
) -> None:
    with pytest.raises(
        H.HeadlessWorkerRuntimeError,
        match="Codex.*runtime attachment inputs|runtime attachment inputs.*Codex",
    ):
        _prepare(
            tmp_path,
            backend="codex",
            policy=None,
            request=None,
            stream_policy=None,
            force_codex_runtime_local_inputs=True,
        )


@pytest.mark.parametrize("drift", ("model", "cwd", "stream"))
def test_claude_launch_model_cwd_and_stream_have_one_profile_authority(
    tmp_path: Path,
    drift: str,
) -> None:
    different_cwd = tmp_path / "different-cwd"
    different_cwd.mkdir()
    policy, request = _security(
        tmp_path,
        model="different-model" if drift == "model" else MODEL,
        cwd=different_cwd if drift == "cwd" else tmp_path,
    )
    stream = _stream_policy(policy)
    if drift == "stream":
        canonical_policy, _canonical_request = _security(tmp_path)
        stream = _stream_policy(canonical_policy)
        stream["expected_init_contract"]["permission_mode"] = (
            "bypassPermissions"
        )
    calls: list[Path] = []

    with pytest.raises(
        H.HeadlessWorkerRuntimeError,
        match="model|cwd|stream|init",
    ):
        _prepare(
            tmp_path,
            policy=policy,
            request=request,
            stream_policy=stream,
            command_builder=_builder(calls),
        )
    assert calls == []
