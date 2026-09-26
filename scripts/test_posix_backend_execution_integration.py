from __future__ import annotations

import hashlib
import json
import os
import copy
import pickle
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import gc
from pathlib import Path
import sys
import threading
import time
from typing import Any, Mapping

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

import posix_backend_execution as execution
import posix_backend_launch_policy as launch_policy
import worker_execution_receipts as wer
import claude_stream_json_evidence as stream_evidence
from test_posix_backend_launch_policy import Harness


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def test_driver_config_never_projects_native_authority_into_mapping_ops() -> None:
    import plamen_driver as driver

    class PoisonAuthority:
        def __repr__(self) -> str:
            raise AssertionError("authority repr was observed")

        def __eq__(self, _other: object) -> bool:
            raise AssertionError("authority equality was observed")

        def __reduce__(self):
            raise AssertionError("authority pickle was observed")

    authority = PoisonAuthority()
    config = driver._DriverConfig(
        {"pipeline": "sc", "nested": {"value": 1}},
        native_guest_runtime_authorities=authority,
    )

    assert repr(config) == "{'pipeline': 'sc', 'nested': {'value': 1}}"
    assert config == {"pipeline": "sc", "nested": {"value": 1}}
    assert list(config) == ["pipeline", "nested"]
    assert list(config.items()) == [
        ("pipeline", "sc"), ("nested", {"value": 1}),
    ]
    assert config.get("native_backend_execution_authority") is None
    assert json.loads(json.dumps(config, sort_keys=True)) == dict(config)

    for copied in (
        dict(config), config.copy(), copy.copy(config), copy.deepcopy(config),
    ):
        assert type(copied) is dict
        assert copied == dict(config)
    with pytest.raises(TypeError, match="cannot be serialized"):
        pickle.dumps(config)


def test_driver_config_copy_loss_and_authority_substitution_fail_closed() -> None:
    import plamen_driver as driver

    config = driver._DriverConfig(
        {"pipeline": "sc"},
        native_guest_runtime_authorities=object(),
    )
    with pytest.raises(execution.PosixBackendExecutionError):
        driver._native_backend_execution_authority_for_launch(config)

    for lost in (dict(config), config.copy(), copy.copy(config)):
        with pytest.raises(
            driver.HeadlessWorkerRuntimeError,
            match="lost its exact driver runtime authority binding",
        ):
            driver._native_backend_execution_authority_for_launch(lost)

    class Substitute(driver._DriverConfig):
        pass

    substituted = Substitute(
        {"pipeline": "sc"},
        native_guest_runtime_authorities=object(),
    )
    with pytest.raises(
        driver.HeadlessWorkerRuntimeError,
        match="lost its exact driver runtime authority binding",
    ):
        driver._native_backend_execution_authority_for_launch(substituted)


def test_driver_main_native_acquisition_precedes_config_and_state_effects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import plamen_driver as driver

    events: list[str] = []

    def reject_native_startup():
        events.append("native")
        raise execution.PosixBackendExecutionError(
            "TEST_NATIVE_ABSENT", "expected first-effect rejection",
        )

    def forbidden_state_mutation() -> None:
        events.append("state")
        raise AssertionError("driver state mutated before native admission")

    monkeypatch.setattr(
        driver, "acquire_native_guest_runtime_authorities",
        reject_native_startup,
    )
    monkeypatch.setattr(
        driver, "_clear_audit_input_drift_decision_authority",
        forbidden_state_mutation,
    )
    monkeypatch.setattr(
        sys, "argv", ["plamen_driver.py", "/must/not/be/inspected.json"],
    )

    with pytest.raises(SystemExit) as stopped:
        driver.main()
    assert stopped.value.code == driver.EXIT_DEGRADED
    assert events == ["native"]


class _Verifier:
    def verify_posix_backend_receipt(
        self,
        stage: str,
        receipt: bytes,
        expected: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        return {
            "schema": execution.EXTERNAL_VERIFICATION_SCHEMA,
            "stage": stage,
            "receipt_sha256": _sha(receipt),
            "expected_sha256": _sha(execution.canonical_json_bytes(expected)),
            "valid": True,
        }


class _Consumer:
    def __init__(
        self,
        harness: Harness,
        *,
        nonce: str = "nonce-001",
        issued_at_unix_ns: int | None = None,
        plan_model: str | None = None,
        outer_overrides: Mapping[str, Any] | None = None,
        fail_materialization: bool = False,
        materialized_environment_extra: bool = False,
        materialization_overrides: Mapping[str, Any] | None = None,
    ) -> None:
        self.harness = harness
        self.nonce = nonce
        self.issued_at_unix_ns = issued_at_unix_ns
        self.plan_model = plan_model
        self.outer_overrides = dict(outer_overrides or {})
        self.fail_materialization = fail_materialization
        self.materialized_environment_extra = materialized_environment_extra
        self.materialization_overrides = dict(
            materialization_overrides or {}
        )
        self.materializations = 0
        self.revocations = 0

    def consume_posix_backend_launch(
        self,
        request: Mapping[str, Any],
        *,
        prompt_fd: int,
    ):
        launch_request = self.harness.request()
        launch_request["prompt_fd"] = prompt_fd
        provider_contract = request["provider_stdout_contract"]
        if self.harness.backend == "claude":
            launch_request["session_id"] = provider_contract["session_id"]
            launch_request["claude_tools"] = provider_contract["claude_tools"]
        if self.plan_model is not None:
            launch_request["model"] = self.plan_model
        plan = self.harness.render(launch_request)
        plan_receipt = plan.public_receipt_bytes()
        issued = self.issued_at_unix_ns or time.time_ns()
        outer = {
            "schema": execution.OUTER_AUTHORITY_SCHEMA,
            **{
                key: request[key]
                for key in (
                    "attempt_id",
                    "backend",
                    "model",
                    "outer_attempt_arm_sha256",
                    "work_plan_sha256",
                    "process_scope_identity",
                    "base_argv_sha256",
                    "base_environment_sha256",
                    "cwd_identity_sha256",
                    "prompt_sha256",
                    "provider_stdout_contract_sha256",
                )
            },
            "plan_receipt_sha256": _sha(plan_receipt),
            "provider_context_sha256": "9" * 64,
            "descendant_credential_denial_sha256": launch_request[
                "credential_isolation_sha256"
            ],
            "context_nonce": self.nonce,
            "issued_at_unix_ns": issued,
            "expires_at_unix_ns": issued + 60_000_000_000,
        }
        outer.update(self.outer_overrides)
        return plan, execution.canonical_json_bytes(outer)

    def materialize_posix_backend_launch(
        self,
        invocation,
        binding: Mapping[str, Any],
    ):
        self.materializations += 1
        if self.fail_materialization:
            raise RuntimeError("fake materializer rejected")
        environment = dict(invocation.environment)
        if self.materialized_environment_extra:
            environment["AMBIENT_SUBSTITUTION"] = "forbidden"
        pass_fds = tuple(invocation.pass_fds)
        fd_rows = [
            execution._fd_binding(fd, f"retained-{index:03d}")
            for index, fd in enumerate(pass_fds)
        ]
        receipt = {
            "schema": execution.MATERIALIZATION_SCHEMA,
            **dict(binding),
            "environment_names": sorted(environment),
            "final_environment_sha256": execution._environment_sha(
                environment
            ),
            "cwd_fd_identity_sha256": execution._mapping_sha(
                execution._fd_binding(invocation.cwd_fd, "cwd")
            ),
            "stdin_fd_identity_sha256": execution._mapping_sha(
                execution._fd_binding(invocation.stdin_fd, "stdin")
            ),
            "pass_fds_identity_sha256": execution._mapping_sha(
                {"fds": fd_rows}
            ),
            "retained_fd_count": len(pass_fds),
            "materialized_private_state_sha256": "a" * 64,
            "status": "MATERIALIZED_AFTER_INNER_ARM",
        }
        receipt.update(self.materialization_overrides)
        return environment, execution.canonical_json_bytes(receipt)

    def revoke_posix_backend_launch(
        self,
        _materialization_receipt: bytes,
        binding: Mapping[str, Any],
    ) -> bytes:
        self.revocations += 1
        return execution.canonical_json_bytes(binding)


@pytest.fixture(autouse=True)
def _isolated_bridge():
    execution._reset_trusted_bridge_for_tests()
    yield
    execution._reset_trusted_bridge_for_tests()


def _prepare(
    harness: Harness,
    consumer: _Consumer,
    *,
    base_argv: list[str] | None = None,
    verifier: _Verifier | None = None,
):
    execution._register_test_only_outer_supervisor_bridge(
        consumer, verifier or _Verifier()
    )
    return execution._TEST_ONLY_prepare_posix_backend_execution(
        **_prepare_arguments(harness, base_argv=base_argv)
    )


def _prepare_arguments(
    harness: Harness,
    *, base_argv: list[str] | None = None,
) -> dict[str, Any]:
    prompt = harness.prompt_path.read_bytes()
    request = harness.request()
    provider_configuration = None
    if harness.backend == "claude":
        provider_configuration = {
            "schema": wer.CLAUDE_STREAM_STDOUT_CONFIGURATION_SCHEMA,
            "expected_session_id": request["session_id"],
            "expected_init_contract": {
                "claude_code_version": "2.1.252",
                "permission_mode": "dontAsk",
                "allowed_tools": list(request["claude_tools"]),
                "allowed_tool_prefixes": [],
                "allowed_mcp_servers": [],
                "required_mcp_servers": [],
                "required_capabilities": ["vendor-restricted-analysis"],
            },
            "max_line_bytes": 2 * 1024 * 1024,
            "max_stream_bytes": wer.DEFAULT_STDOUT_LIMIT_BYTES,
        }
    return {
        "backend": harness.backend,
        "model": str(request["model"]),
        "attempt_id": "attempt-01",
        "outer_attempt_arm_sha256": "b" * 64,
        "work_plan_sha256": "c" * 64,
        "process_scope_identity": "scope-001",
        "base_argv": base_argv
        or ["fake-builder", "--legacy-logical-flag"],
        "base_environment": {},
        "cwd": harness.project,
        "prompt_path": harness.prompt_path,
        "prompt_sha256": _sha(prompt),
        "provider_stdout_evidence_configuration": provider_configuration,
    }


def _restricted_claude_stream_configuration(
    *, cwd: Path, session_id: str, model: str,
) -> dict[str, Any]:
    return {
        "schema": wer.CLAUDE_STREAM_STDOUT_CONFIGURATION_SCHEMA,
        "expected_session_id": session_id,
        "expected_init_contract": {
            "schema": stream_evidence.EXPECTED_INIT_SECURITY_SCHEMA,
            "claude_code_version": "2.1.252",
            "cwd": str(cwd),
            "accepted_models": [model],
            "permission_mode": "dontAsk",
            "allowed_tools": ["Edit", "Glob", "Grep", "Read", "Write"],
            "allowed_tool_prefixes": [],
            "required_tools": ["Read", "Write"],
            "forbidden_tools": [
                "Agent", "Bash", "PowerShell", "Task", "WebFetch",
                "WebSearch",
            ],
            "allowed_mcp_servers": [],
            "required_mcp_servers": [],
            "expected_plugins": [],
            "expected_skills": [],
            "expected_agents": list(
                stream_evidence.REVIEWED_RESTRICTED_INIT_AGENTS
            ),
            "accepted_api_key_sources": ["none"],
            "required_capabilities": ["vendor-restricted-analysis"],
            "expected_native_capabilities": list(
                stream_evidence.REVIEWED_RESTRICTED_INIT_CAPABILITIES
            ),
            "forbidden_capabilities": ["remote-agents"],
            "expected_slash_commands": [],
            "accepted_output_styles": ["default"],
        },
        "max_line_bytes": 2 * 1024 * 1024,
        "max_stream_bytes": wer.DEFAULT_STDOUT_LIMIT_BYTES,
    }


def _posix_claude_argv(*, session_id: str, model: str) -> list[str]:
    return [
        "/proc/self/fd/11", "-p", "--model", model,
        "--input-format", "text", "--output-format", "stream-json",
        "--verbose", "--session-id", session_id,
        "--no-session-persistence", "--bare", "--restricted",
        "--permission-mode", "dontAsk", "--tools",
        "Edit,Glob,Grep,Read,Write", "--setting-sources=", "--settings",
        "/proc/self/fd/21", "--strict-mcp-config", "--mcp-config",
        "/proc/self/fd/22", "--add-dir", "/workspace/project",
        "--add-dir", "/workspace/scratch", "--no-chrome",
        "--disable-slash-commands", "--prompt-suggestions", "false",
    ]


def test_wer_binds_posix_claude_native_sandbox_without_legacy_validator(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        wer,
        "_claude_stream_parser_runtime_binding",
        lambda: {"fixture": "parser-runtime"},
    )
    session_id = "12345678-1234-4234-8234-123456789abc"
    model = "claude-opus-4-6"
    settings_sha256 = "1" * 64
    mcp_sha256 = "2" * 64
    isolation_sha256 = "3" * 64
    arm = {
        "plan_receipt_sha256": "4" * 64,
        "policy_sealed_content_sha256": {
            "Claude settings": settings_sha256,
            "Claude MCP config": mcp_sha256,
        },
        "policy_sealed_policy": {
            "codex_profile_sha256": None,
            "claude_settings_contract": (
                "POSIX_NATIVE_SANDBOX_DONTASK_V1"
            ),
            "claude_settings_sha256": settings_sha256,
            "claude_mcp_sha256": mcp_sha256,
            "codex_permission_profile_status": "NOT_APPLICABLE",
            "credential_isolation_mode": (
                "NATIVE_PROCESS_DOMAIN_SPLIT_NO_DESCENDANT_READ_V1"
            ),
            "credential_isolation_sha256": isolation_sha256,
        },
    }
    configuration = _restricted_claude_stream_configuration(
        cwd=tmp_path,
        session_id=session_id,
        model=model,
    )
    argv = _posix_claude_argv(session_id=session_id, model=model)

    binding = wer._claude_stream_stdout_binding(
        configuration,
        argv=argv,
        stdout_limit_bytes=wer.DEFAULT_STDOUT_LIMIT_BYTES,
        cwd=tmp_path,
        effective_model=model,
        posix_backend_profile=True,
        posix_backend_arm_authority=arm,
    )
    profile = binding["command_contract"]["headless_profile"]
    assert profile["permission_mode"] == "dontAsk"
    assert "permission_prompts" not in profile
    assert profile["settings"]["authority"] == (
        "AUTHENTICATED_POSIX_NATIVE_SANDBOX_POLICY"
    )
    assert profile["mcp_config"]["sha256"] == mcp_sha256

    with pytest.raises(wer.WorkerExecutionError, match="permission-prompts"):
        wer._claude_stream_stdout_binding(
            configuration,
            argv=[
                *argv[: argv.index("--tools")],
                "--permission-prompts", "none",
                *argv[argv.index("--tools") :],
            ],
            stdout_limit_bytes=wer.DEFAULT_STDOUT_LIMIT_BYTES,
            cwd=tmp_path,
            effective_model=model,
            posix_backend_profile=True,
            posix_backend_arm_authority=arm,
        )


@pytest.mark.parametrize(
    ("backend", "unsafe_builder_argv"),
    (
        (
            "codex",
            ["codex", "--dangerously-bypass-approvals-and-sandbox", "exec"],
        ),
        (
            "claude",
            ["claude", "--dangerously-skip-permissions", "--print"],
        ),
    ),
)
def test_fake_native_builder_is_replaced_only_by_one_shot_policy_invocation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    backend: str,
    unsafe_builder_argv: list[str],
) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "ambient-must-not-cross")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "ambient-must-not-cross")
    harness = Harness(tmp_path, backend)
    authority = None
    try:
        consumer = _Consumer(harness)
        authority = _prepare(
            harness,
            consumer,
            base_argv=unsafe_builder_argv,
        )
        preview = authority.preview_physical_binding()
        argv = tuple(preview["argv"])
        assert unsafe_builder_argv != list(argv)
        assert "--dangerously-bypass-approvals-and-sandbox" not in argv
        assert "--dangerously-skip-permissions" not in argv
        assert "--sandbox" not in argv
        assert all(not item.startswith("--sandbox=") for item in argv)
        assert argv[0].startswith("/proc/self/fd/")
        assert "OPENAI_API_KEY" not in preview["environment"]
        assert "ANTHROPIC_API_KEY" not in preview["environment"]
        arm_binding = dict(authority.arm_binding)
        if backend == "codex":
            assert "--ignore-user-config" not in argv
            assert argv[argv.index("--profile") + 1] == "plamen-audit"
            census_sha256 = arm_binding[
                "codex_config_census_contract_sha256"
            ]
            assert census_sha256 == arm_binding["policy_sealed_policy"][
                "codex_config_census_contract_sha256"
            ]
            assert arm_binding["credential_delivery"] == (
                "SUPERVISOR_MATERIALIZE_EXACT_PRIVATE_CODEX_HOME_CENSUS_"
                "THEN_CLOSE"
            )
        else:
            assert arm_binding[
                "codex_config_census_contract_sha256"
            ] is None
            assert arm_binding["credential_delivery"] == (
                launch_policy.CLAUDE_CREDENTIAL_DELIVERY
            )

        physical = authority.materialize_after_inner_arm(
            inner_arm_sha256="d" * 64
        )
        assert dict(authority.arm_binding) == arm_binding
        assert "ANTHROPIC_API_KEY" not in physical.environment
        authority.revalidate_immediately_before_process_creation()
        authority.mark_process_created()
        terminal = authority.revoke_after_scope_close(
            process_creation_state="ATTACHED",
            process_population_zero_proven=True,
            returncode=0,
            reason_code="PROCESS_SCOPE_CLOSED",
        )
        assert terminal["policy_completion_status"] == "EXECUTED_AND_REVOKED"
        assert terminal["policy_completion_evidence_sha256"] == terminal[
            "receipt_sha256"
        ]
        assert consumer.materializations == 1
        assert consumer.revocations == 1
        with pytest.raises(execution.PosixBackendExecutionError):
            authority.revoke_after_scope_close(
                process_creation_state="ATTACHED",
                process_population_zero_proven=True,
                returncode=0,
                reason_code="PROCESS_SCOPE_CLOSED",
            )
        authority.close()
        authority = None
    finally:
        if authority is not None:
            authority.close()
        harness.close()


def test_missing_outer_context_fails_before_plan_or_process(tmp_path: Path) -> None:
    harness = Harness(tmp_path, "codex")
    try:
        arguments = _prepare_arguments(
            harness, base_argv=["codex", "exec"]
        )
        with pytest.raises(
            execution.PosixBackendExecutionError,
            match="TEST_ONLY_OUTER_SUPERVISOR_REQUIRED",
        ):
            execution._TEST_ONLY_prepare_posix_backend_execution(
                **arguments
            )
        reservation = execution._TEST_ONLY_ISSUANCE_RESERVATIONS[
            ("attempt-01", "b" * 64, "scope-001")
        ]
        assert reservation.state == "QUARANTINED"
        with pytest.raises(
            execution.PosixBackendExecutionError,
            match="ISSUANCE_REPLAY",
        ):
            execution._TEST_ONLY_prepare_posix_backend_execution(
                **arguments
            )
    finally:
        harness.close()


@pytest.mark.parametrize("backend", ("codex", "claude"))
def test_wer_replays_exact_policy_arm_and_rejects_bound_field_drift(
    tmp_path: Path,
    backend: str,
) -> None:
    harness = Harness(tmp_path, backend)
    authority = None
    try:
        authority = _prepare(harness, _Consumer(harness))
        preview = authority.preview_physical_binding()
        arm = dict(authority.arm_binding)
        replay = wer._replay_posix_backend_arm_binding(
            arm,
            argv=list(preview["argv"]),
            environment=dict(preview["environment"]),
            cwd_fd=int(str(preview["cwd"]).removeprefix("/proc/self/fd/")),
            stdin_fd=preview["stdin_fd"],
            pass_fds=preview["pass_fds"],
            backend=backend,
            model=str(harness.request()["model"]),
            process_scope_identity="scope-001",
        )
        assert replay == arm

        changed = json.loads(json.dumps(arm))
        if backend == "codex":
            changed["codex_config_census_contract_sha256"] = "0" * 64
        else:
            changed["credential_delivery"] = "SUBSTITUTED"
        with pytest.raises(wer.WorkerExecutionError):
            wer._replay_posix_backend_arm_binding(
                changed,
                argv=list(preview["argv"]),
                environment=dict(preview["environment"]),
                cwd_fd=int(
                    str(preview["cwd"]).removeprefix("/proc/self/fd/")
                ),
                stdin_fd=preview["stdin_fd"],
                pass_fds=preview["pass_fds"],
                backend=backend,
                model=str(harness.request()["model"]),
                process_scope_identity="scope-001",
            )
        authority.abort_before_process_creation(reason_code="TEST_ABORT")
        authority.close()
        authority = None
    finally:
        if authority is not None:
            authority.close()
        harness.close()


@pytest.mark.parametrize(
    ("field", "substitute"),
    (
        ("final_environment_sha256", "0" * 64),
        ("cwd_fd_identity_sha256", "1" * 64),
        ("stdin_fd_identity_sha256", "2" * 64),
        ("pass_fds_identity_sha256", "3" * 64),
        ("retained_fd_count", 999),
    ),
)
def test_wer_rejects_exact_environment_and_fd_binding_substitution(
    tmp_path: Path,
    field: str,
    substitute: str | int,
) -> None:
    harness = Harness(tmp_path, "codex")
    authority = None
    try:
        authority = _prepare(harness, _Consumer(harness))
        preview = authority.preview_physical_binding()
        changed = json.loads(json.dumps(dict(authority.arm_binding)))
        changed[field] = substitute
        with pytest.raises(
            wer.WorkerExecutionError,
            match="environment or descriptor authority",
        ):
            wer._replay_posix_backend_arm_binding(
                changed,
                argv=list(preview["argv"]),
                environment=dict(preview["environment"]),
                cwd_fd=int(
                    str(preview["cwd"]).removeprefix("/proc/self/fd/")
                ),
                stdin_fd=preview["stdin_fd"],
                pass_fds=preview["pass_fds"],
                backend="codex",
                model=str(harness.request()["model"]),
                process_scope_identity="scope-001",
            )
        authority.abort_before_process_creation(reason_code="TEST_ABORT")
        authority.close()
        authority = None
    finally:
        if authority is not None:
            authority.close()
        harness.close()


def test_wer_rejects_preview_to_materialized_pass_fd_drift(
    tmp_path: Path,
) -> None:
    harness = Harness(tmp_path, "codex")
    authority = None
    extra_fd: int | None = None
    try:
        authority = _prepare(harness, _Consumer(harness))
        preview = authority.preview_physical_binding()
        authority.materialize_after_inner_arm(inner_arm_sha256="d" * 64)
        extra_fd = os.open(
            harness.project,
            os.O_RDONLY | int(getattr(os, "O_DIRECTORY", 0) or 0),
        )
        changed_pass_fds = tuple(
            sorted({*preview["pass_fds"], extra_fd})
        )
        with pytest.raises(
            wer.WorkerExecutionError,
            match="materialized pass-FD roster differs",
        ):
            wer._replay_posix_backend_arm_binding(
                dict(authority.arm_binding),
                argv=list(preview["argv"]),
                environment=dict(preview["environment"]),
                cwd_fd=int(
                    str(preview["cwd"]).removeprefix("/proc/self/fd/")
                ),
                stdin_fd=preview["stdin_fd"],
                pass_fds=preview["pass_fds"],
                materialized_pass_fds=changed_pass_fds,
                backend="codex",
                model=str(harness.request()["model"]),
                process_scope_identity="scope-001",
            )
        authority.abort_before_process_creation(reason_code="TEST_ABORT")
        authority.close()
        authority = None
    finally:
        if extra_fd is not None:
            os.close(extra_fd)
        if authority is not None:
            authority.close()
        harness.close()


def test_production_bridge_has_no_python_registration_or_plan_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = Harness(tmp_path, "codex")
    try:
        consumer = _Consumer(harness)
        with pytest.raises(
            execution.PosixBackendExecutionError,
            match="NATIVE_BRIDGE_UNAVAILABLE",
        ):
            execution.register_trusted_outer_supervisor_bridge(consumer)

        forged_native = object.__new__(
            execution.NativeOuterSupervisorBridgeCapability
        )
        with pytest.raises(
            execution.PosixBackendExecutionError,
            match="NATIVE_BRIDGE_UNAVAILABLE",
        ):
            execution.register_trusted_outer_supervisor_bridge(forged_native)

        execution._register_test_only_outer_supervisor_bridge(
            consumer, _Verifier()
        )
        test_bridge = execution._TEST_ONLY_BRIDGE
        assert test_bridge is not None
        transplanted = replace(test_bridge, verifier=_Verifier())
        with pytest.raises(
            execution.PosixBackendExecutionError,
            match="NATIVE_BRIDGE_UNAVAILABLE",
        ):
            execution.register_trusted_outer_supervisor_bridge(transplanted)

        # A dynamically transplanted registry cannot affect production: the
        # public preparer has no Python registry/consumer path.
        monkeypatch.setattr(execution, "_BRIDGE", transplanted, raising=False)
        assert execution.outer_supervisor_context_available() is False
        prompt = harness.prompt_path.read_bytes()
        with pytest.raises(
            execution.PosixBackendExecutionError,
            match="NATIVE_BRIDGE_UNAVAILABLE",
        ):
            execution.prepare_posix_backend_execution(
                backend="codex",
                model=str(harness.request()["model"]),
                attempt_id="attempt-01",
                outer_attempt_arm_sha256="b" * 64,
                work_plan_sha256="c" * 64,
                process_scope_identity="scope-001",
                base_argv=["codex", "exec"],
                base_environment={},
                cwd=harness.project,
                    prompt_path=harness.prompt_path,
                    prompt_sha256=_sha(prompt),
                    native_authority=consumer,
                    timeout_seconds=2400,
                    stdout_limit_bytes=1024,
                    stderr_limit_bytes=1024,
            )

        forged_execution = object.__new__(execution.PosixBackendExecution)
        assert type(forged_execution) is execution.PosixBackendExecution
        assert type(forged_execution) is not execution.TestOnlyPosixBackendExecution
        with pytest.raises(
            execution.PosixBackendExecutionError,
            match="NATIVE_BRIDGE_UNAVAILABLE",
        ):
            forged_execution.preview_physical_binding()
    finally:
        harness.close()


def test_stale_and_substituted_outer_contexts_are_terminal(tmp_path: Path) -> None:
    stale_harness = Harness(tmp_path / "stale", "codex")
    try:
        stale = _Consumer(
            stale_harness,
            issued_at_unix_ns=time.time_ns() - 120_000_000_000,
        )
        with pytest.raises(
            execution.PosixBackendExecutionError, match="OUTER_STALE"
        ):
            _prepare(stale_harness, stale)
    finally:
        stale_harness.close()
    execution._reset_trusted_bridge_for_tests()

    substitute_harness = Harness(tmp_path / "substitute", "codex")
    try:
        substitute = _Consumer(
            substitute_harness,
            plan_model="substituted-model",
        )
        with pytest.raises(
            execution.PosixBackendExecutionError, match="OUTER_CONSUME"
        ):
            _prepare(substitute_harness, substitute)
    finally:
        substitute_harness.close()


def test_outer_context_nonce_cannot_be_replayed(tmp_path: Path) -> None:
    first_harness = Harness(tmp_path / "first", "codex")
    first = None
    try:
        consumer = _Consumer(first_harness, nonce="same")
        first = _prepare(first_harness, consumer)
        first.preview_physical_binding()
        first.abort_before_process_creation(reason_code="TEST_ABORT")
        first.close()
        first = None
        with pytest.raises(
            execution.PosixBackendExecutionError, match="ISSUANCE_REPLAY"
        ):
            prompt = first_harness.prompt_path.read_bytes()
            execution._TEST_ONLY_prepare_posix_backend_execution(
                backend="codex",
                model=str(first_harness.request()["model"]),
                attempt_id="attempt-01",
                outer_attempt_arm_sha256="b" * 64,
                work_plan_sha256="c" * 64,
                process_scope_identity="scope-001",
                base_argv=["codex", "exec"],
                base_environment={},
                cwd=first_harness.project,
                prompt_path=first_harness.prompt_path,
                prompt_sha256=_sha(prompt),
            )
    finally:
        if first is not None:
            first.close()
        first_harness.close()


def test_descriptor_drift_and_materialization_failure_revoke_one_shot(
    tmp_path: Path,
) -> None:
    drift_harness = Harness(tmp_path / "drift", "codex")
    authority = None
    try:
        authority = _prepare(drift_harness, _Consumer(drift_harness))
        authority.preview_physical_binding()
        drift_harness.prompt_path.write_bytes(b"changed after invocation arm\n")
        with pytest.raises(execution.PosixBackendExecutionError):
            authority.preview_physical_binding()
        authority.abort_before_process_creation(reason_code="DRIFT_REJECTED")
        authority.close()
        authority = None
    finally:
        if authority is not None:
            authority.close()
        drift_harness.close()
    execution._reset_trusted_bridge_for_tests()

    failure_harness = Harness(tmp_path / "materialize", "codex")
    failed = None
    try:
        failure_consumer = _Consumer(
            failure_harness, fail_materialization=True
        )
        failed = _prepare(
            failure_harness,
            failure_consumer,
        )
        failed.preview_physical_binding()
        with pytest.raises(
            execution.PosixBackendExecutionError, match="MATERIALIZE"
        ):
            failed.materialize_after_inner_arm(inner_arm_sha256="d" * 64)
        with pytest.raises(execution.PosixBackendExecutionError):
            failed.preview_physical_binding()
        assert failure_consumer.revocations == 1
        failed.close()
        failed = None
    finally:
        if failed is not None:
            failed.close()
        failure_harness.close()


@pytest.mark.parametrize(
    ("failure", "receipt_override"),
    (
        ("environment", None),
        ("status", {"status": "SUBSTITUTED"}),
        (
            "final-environment-digest",
            {"final_environment_sha256": "0" * 64},
        ),
        ("cwd-digest", {"cwd_fd_identity_sha256": "1" * 64}),
        ("stdin-digest", {"stdin_fd_identity_sha256": "2" * 64}),
        ("pass-fds-digest", {"pass_fds_identity_sha256": "3" * 64}),
        ("pass-fds-count", {"retained_fd_count": 999}),
    ),
)
def test_invalid_post_arm_materialization_is_revoked_before_process(
    tmp_path: Path,
    failure: str,
    receipt_override: Mapping[str, Any] | None,
) -> None:
    harness = Harness(tmp_path, "codex")
    authority = None
    try:
        consumer = _Consumer(
            harness,
            materialized_environment_extra=(failure == "environment"),
            materialization_overrides=receipt_override,
        )
        authority = _prepare(harness, consumer)
        authority.preview_physical_binding()
        with pytest.raises(execution.PosixBackendExecutionError):
            authority.materialize_after_inner_arm(
                inner_arm_sha256="d" * 64
            )
        assert consumer.materializations == 1
        assert consumer.revocations == 1
        with pytest.raises(execution.PosixBackendExecutionError):
            authority.preview_physical_binding()
        authority.close()
        authority = None
    finally:
        if authority is not None:
            authority.close()
        harness.close()


def test_precreate_replay_rejects_materialized_environment_value_drift(
    tmp_path: Path,
) -> None:
    harness = Harness(tmp_path, "claude")
    authority = None
    try:
        authority = _prepare(harness, _Consumer(harness))
        authority.preview_physical_binding()
        authority.materialize_after_inner_arm(inner_arm_sha256="d" * 64)
        record = execution._TEST_ONLY_EXECUTIONS[id(authority)]
        record.materialized_environment = {
            **dict(record.materialized_environment or {}),
            "INJECTED_AFTER_MATERIALIZATION": "forbidden",
        }
        with pytest.raises(
            execution.PosixBackendExecutionError,
            match="MATERIALIZE_DRIFT",
        ):
            authority.revalidate_immediately_before_process_creation()
        authority.abort_before_process_creation(reason_code="DRIFT_REJECTED")
        authority.close()
        authority = None
    finally:
        if authority is not None:
            authority.close()
        harness.close()


def test_completion_replay_cross_binds_materialized_environment_and_fds(
    tmp_path: Path,
) -> None:
    harness = Harness(tmp_path, "codex")
    authority = None
    try:
        authority = _prepare(harness, _Consumer(harness))
        preview = authority.preview_physical_binding()
        arm = dict(authority.arm_binding)
        physical = authority.materialize_after_inner_arm(
            inner_arm_sha256="d" * 64
        )
        physical_binding = wer._posix_backend_live_physical_binding(
            environment=dict(physical.environment),
            cwd_fd=int(physical.cwd.removeprefix("/proc/self/fd/")),
            stdin_fd=physical.stdin_fd,
            pass_fds=physical.pass_fds,
        )
        authority.revalidate_immediately_before_process_creation()
        authority.mark_process_created()
        revocation = dict(
            authority.revoke_after_scope_close(
                process_creation_state="ATTACHED",
                process_population_zero_proven=True,
                returncode=0,
                reason_code="PROCESS_SCOPE_CLOSED",
            )
        )
        shard = tmp_path / "completion-replay"
        shard.mkdir()
        materialization_path, materialization_sha = wer._persist_hashed_json(
            shard,
            "posix_materialization",
            dict(physical.materialization_binding),
        )
        process_observation = {
            "posix_backend_materialization": {
                "relative_path": materialization_path.name,
                "sha256": materialization_sha,
                "binding": dict(physical.materialization_binding),
            },
            "posix_backend_physical_binding": physical_binding,
            "posix_backend_revocation": revocation,
            "process_creation": {"state": "ATTACHED"},
            "returncode": 0,
        }
        wer._replay_posix_backend_completion_lifecycle(
            shard_dir=shard,
            arm_sha256="d" * 64,
            arm_binding=arm,
            process_observation=process_observation,
            environment_names=tuple(preview["environment_names"]),
        )

        substituted = json.loads(json.dumps(process_observation))
        substituted["posix_backend_physical_binding"][
            "pass_fds_identity_sha256"
        ] = "3" * 64
        with pytest.raises(
            wer.WorkerExecutionError,
            match="materialized physical values differ",
        ):
            wer._replay_posix_backend_completion_lifecycle(
                shard_dir=shard,
                arm_sha256="d" * 64,
                arm_binding=arm,
                process_observation=substituted,
                environment_names=tuple(preview["environment_names"]),
            )
        authority.close()
        authority = None
    finally:
        if authority is not None:
            authority.close()
        harness.close()


def _minimal_wer_bindings(tmp_path: Path) -> wer.ExecutionBindings:
    inputs = tmp_path / "inputs"
    inputs.mkdir(parents=True)
    for name in (
        "plan.json",
        "manifest.json",
        "intent.json",
        "context.md",
        "prompt.md",
        "tool-policy.json",
    ):
        (inputs / name).write_text("{}\n", encoding="utf-8")
    return wer.ExecutionBindings(
        run_id="run-001",
        shard_id="shard-001",
        plan=wer.BoundInput("inputs/plan.json"),
        manifest=wer.BoundInput("inputs/manifest.json"),
        intent=wer.BoundInput("inputs/intent.json"),
        context=wer.BoundInput("inputs/context.md"),
        prompt=wer.BoundInput("inputs/prompt.md"),
        tool_policy=wer.BoundInput("inputs/tool-policy.json"),
        worker=wer.PrincipalInvocation("worker", "invocation"),
        assessors=(),
        effective_backend="codex",
        effective_model="gpt-5.6-sol",
    )


def test_wer_rejects_posix_model_leaf_without_bridge_before_popen(
    tmp_path: Path,
) -> None:
    bindings = _minimal_wer_bindings(tmp_path)
    with pytest.raises(
        wer.NativePosixProcessAuthorityUnavailable,
        match="NATIVE_POSIX_PROCESS_AUTHORITY_UNAVAILABLE",
    ):
        wer.run_observed_worker(
            scratchpad=tmp_path,
            bindings=bindings,
            argv=[sys.executable, "-c", "raise SystemExit(99)"],
            cwd=tmp_path,
            output_scope_relative="output",
            expected_outputs=(),
            parser_digest=lambda _path, _raw: "0" * 64,
            environment={},
            environment_allowlist=(),
        )
    assert not (tmp_path / "output").exists()
    assert not (tmp_path / ".worker_execution_receipts").exists()


@pytest.mark.parametrize("entrypoint", ("public", "direct"))
@pytest.mark.parametrize("attack", ("object-new-method", "rebound-symbol"))
def test_forged_python_execution_cannot_reach_behavior_or_mutate_disk(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    attack: str,
    entrypoint: str,
) -> None:
    bindings = _minimal_wer_bindings(tmp_path)
    callback_marker = tmp_path / "forged-callback-reached"

    def forged_preview(_self: object) -> Mapping[str, Any]:
        callback_marker.write_text("reached", encoding="utf-8")
        raise AssertionError("forged preview callback must never run")

    if attack == "object-new-method":
        supplied = object.__new__(execution.PosixBackendExecution)
        monkeypatch.setattr(
            execution.PosixBackendExecution,
            "preview_physical_binding",
            forged_preview,
        )
    else:
        class ReboundPosixBackendExecution:
            preview_physical_binding = forged_preview

        monkeypatch.setattr(
            wer,
            "PosixBackendExecution",
            ReboundPosixBackendExecution,
        )
        supplied = object.__new__(ReboundPosixBackendExecution)

    with pytest.raises(
        wer.NativePosixProcessAuthorityUnavailable,
        match="NATIVE_POSIX_PROCESS_AUTHORITY_UNAVAILABLE",
    ):
        runner = (
            wer.run_observed_worker
            if entrypoint == "public"
            else wer._run_observed_worker_direct
        )
        runner(
            scratchpad=tmp_path,
            bindings=bindings,
            argv=[sys.executable, "-c", "raise SystemExit(99)"],
            cwd=tmp_path,
            output_scope_relative="output",
            expected_outputs=(),
            parser_digest=lambda _path, _raw: "0" * 64,
            environment={},
            environment_allowlist=(),
            posix_backend_execution=supplied,
        )

    assert not callback_marker.exists()
    assert not (tmp_path / "output").exists()
    assert not (tmp_path / ".worker_execution_receipts").exists()


def test_test_only_execution_type_cannot_authorize_production_wer(
    tmp_path: Path,
) -> None:
    harness = Harness(tmp_path / "harness", "codex")
    authority = None
    try:
        authority = _prepare(harness, _Consumer(harness))
        assert type(authority) is execution.TestOnlyPosixBackendExecution
        assert type(authority) is not execution.PosixBackendExecution
        bindings = _minimal_wer_bindings(tmp_path / "wer")
        with pytest.raises(
            wer.NativePosixProcessAuthorityUnavailable,
            match="NATIVE_POSIX_PROCESS_AUTHORITY_UNAVAILABLE",
        ):
            wer.run_observed_worker(
                scratchpad=tmp_path / "wer",
                bindings=bindings,
                argv=[sys.executable, "-c", "raise SystemExit(99)"],
                cwd=tmp_path / "wer",
                output_scope_relative="output",
                expected_outputs=(),
                parser_digest=lambda _path, _raw: "0" * 64,
                environment={},
                environment_allowlist=(),
                posix_backend_execution=authority,
            )
        assert not (tmp_path / "wer" / "output").exists()
        assert not (
            tmp_path / "wer" / ".worker_execution_receipts"
        ).exists()
        authority.close()
        authority = None
    finally:
        if authority is not None:
            authority.close()
        harness.close()


def test_test_only_authority_is_invalidated_in_forked_child(
    tmp_path: Path,
) -> None:
    if not hasattr(os, "fork"):
        pytest.skip("requires POSIX fork to prove inherited-authority rejection")
    harness = Harness(tmp_path, "codex")
    authority = None
    read_fd, write_fd = os.pipe()
    try:
        authority = _prepare(harness, _Consumer(harness))
        child = os.fork()
        if child == 0:
            os.close(read_fd)
            results: list[str] = []
            for operation in (
                authority.preview_physical_binding,
                lambda: authority.abort_before_process_creation(
                    reason_code="CHILD_MUST_NOT_ABORT_PARENT"
                ),
            ):
                try:
                    operation()
                except execution.PosixBackendExecutionError as exc:
                    results.append(exc.code)
                except BaseException as exc:
                    results.append(type(exc).__name__)
                else:
                    results.append("UNEXPECTED_SUCCESS")
            os.write(write_fd, "\n".join(results).encode("ascii"))
            os.close(write_fd)
            os._exit(0)
        os.close(write_fd)
        write_fd = -1
        payload = os.read(read_fd, 4096).decode("ascii")
        _, status = os.waitpid(child, 0)
        assert os.waitstatus_to_exitcode(status) == 0
        assert payload.splitlines() == [
            "EXECUTION_FORK_REPLAY", "EXECUTION_FORK_REPLAY"
        ]

        # The parent owns the sole live registry and can still consume/revoke.
        authority.preview_physical_binding()
        authority.abort_before_process_creation(reason_code="PARENT_ABORT")
        authority.close()
        authority = None
    finally:
        if read_fd >= 0:
            os.close(read_fd)
        if write_fd >= 0:
            os.close(write_fd)
        if authority is not None:
            authority.close()
        harness.close()


@pytest.mark.parametrize("callback_stage", ("consumer", "verifier"))
def test_fork_during_issuance_cannot_mint_child_authority(
    tmp_path: Path,
    callback_stage: str,
) -> None:
    if not hasattr(os, "fork"):
        pytest.skip("requires POSIX fork during issuance")
    harness = Harness(tmp_path, "codex")
    read_fd, write_fd = os.pipe()
    authority = None

    class ForkingConsumer(_Consumer):
        child_pid = -1
        in_child = False
        forked = False

        def consume_posix_backend_launch(self, request, *, prompt_fd):
            if callback_stage == "consumer" and not self.forked:
                self.forked = True
                child = os.fork()
                if child == 0:
                    self.in_child = True
                else:
                    self.child_pid = child
            return super().consume_posix_backend_launch(
                request, prompt_fd=prompt_fd
            )

    class ForkingVerifier(_Verifier):
        child_pid = -1
        in_child = False
        forked = False

        def verify_posix_backend_receipt(self, stage, receipt, expected):
            if (
                callback_stage == "verifier"
                and stage == "CONSUME"
                and not self.forked
            ):
                self.forked = True
                child = os.fork()
                if child == 0:
                    self.in_child = True
                else:
                    self.child_pid = child
            return super().verify_posix_backend_receipt(
                stage, receipt, expected
            )

    consumer = ForkingConsumer(harness)
    verifier = ForkingVerifier()
    actor = consumer if callback_stage == "consumer" else verifier
    try:
        try:
            authority = _prepare(harness, consumer, verifier=verifier)
        except BaseException as exc:
            if actor.in_child:
                os.close(read_fd)
                code = (
                    exc.code
                    if isinstance(
                        exc, execution.PosixBackendExecutionError
                    )
                    else type(exc).__name__
                )
                payload = (
                    f"{code}|{len(execution._TEST_ONLY_EXECUTIONS)}|"
                    f"{len(execution._TEST_ONLY_ISSUANCE_RESERVATIONS)}|"
                    f"{len(launch_policy._TEST_ONLY_PLANS)}|"
                    f"{len(launch_policy._TEST_ONLY_INVOCATIONS)}"
                )
                os.write(write_fd, payload.encode("ascii"))
                os.close(write_fd)
                os._exit(0)
            raise
        if actor.in_child:
            os.close(read_fd)
            os.write(write_fd, b"UNEXPECTED_SUCCESS")
            os.close(write_fd)
            os._exit(0)

        os.close(write_fd)
        write_fd = -1
        payload = os.read(read_fd, 4096).decode("ascii")
        _, status = os.waitpid(actor.child_pid, 0)
        assert os.waitstatus_to_exitcode(status) == 0
        assert payload == "ISSUANCE_PROCESS_BOUNDARY|0|0|0|0"

        authority.preview_physical_binding()
        authority.abort_before_process_creation(reason_code="PARENT_ABORT")
        authority.close()
        authority = None
    finally:
        if read_fd >= 0:
            os.close(read_fd)
        if write_fd >= 0:
            os.close(write_fd)
        if authority is not None:
            authority.close()
        harness.close()


@pytest.mark.parametrize(
    "callback_stage", ("materialize", "precreate", "revoke")
)
def test_fork_during_post_issuance_callback_is_child_local_failure(
    tmp_path: Path,
    callback_stage: str,
) -> None:
    if not hasattr(os, "fork"):
        pytest.skip("requires POSIX fork inside a lifecycle callback")
    harness = Harness(tmp_path, "codex")
    read_fd, write_fd = os.pipe()
    authority = None

    class ForkingConsumer(_Consumer):
        child_pid = -1
        in_child = False
        forked = False

        def _fork_once(self, stage: str) -> None:
            if callback_stage != stage or self.forked:
                return
            self.forked = True
            child = os.fork()
            if child == 0:
                self.in_child = True
            else:
                self.child_pid = child

        def materialize_posix_backend_launch(self, invocation, binding):
            result = super().materialize_posix_backend_launch(
                invocation, binding
            )
            self._fork_once("materialize")
            return result

        def revoke_posix_backend_launch(
            self, materialization_receipt, binding,
        ):
            result = super().revoke_posix_backend_launch(
                materialization_receipt, binding
            )
            self._fork_once("revoke")
            return result

    class ForkingVerifier(_Verifier):
        child_pid = -1
        in_child = False
        forked = False

        def verify_posix_backend_receipt(self, stage, receipt, expected):
            result = super().verify_posix_backend_receipt(
                stage, receipt, expected
            )
            if (
                callback_stage == "precreate"
                and stage == "PRE_CREATE"
                and not self.forked
            ):
                self.forked = True
                child = os.fork()
                if child == 0:
                    self.in_child = True
                else:
                    self.child_pid = child
            return result

    consumer = ForkingConsumer(harness)
    verifier = ForkingVerifier()
    actor = verifier if callback_stage == "precreate" else consumer
    try:
        authority = _prepare(harness, consumer, verifier=verifier)
        authority.preview_physical_binding()
        record = execution._record(authority)
        expected_fds = tuple(record.pass_fds or ()) + tuple(
            record.private_fds or ()
        )
        try:
            authority.materialize_after_inner_arm(inner_arm_sha256="d" * 64)
            if callback_stage != "materialize":
                authority.revalidate_immediately_before_process_creation()
            if callback_stage == "revoke":
                authority.mark_process_created()
                authority.revoke_after_scope_close(
                    process_creation_state="PROCESS_EXITED",
                    process_population_zero_proven=True,
                    returncode=0,
                    reason_code="NORMAL_EXIT",
                )
        except BaseException as exc:
            if actor.in_child:
                os.close(read_fd)
                code = (
                    exc.code
                    if isinstance(
                        exc, execution.PosixBackendExecutionError
                    )
                    else type(exc).__name__
                )
                closed = 0
                for fd in expected_fds:
                    try:
                        os.fstat(fd)
                    except OSError:
                        closed += 1
                payload = (
                    f"{code}|{closed}|{len(expected_fds)}|"
                    f"{len(execution._TEST_ONLY_EXECUTIONS)}"
                )
                os.write(write_fd, payload.encode("ascii"))
                os.close(write_fd)
                os._exit(0)
            raise
        if actor.in_child:
            os.close(read_fd)
            os.write(write_fd, b"UNEXPECTED_SUCCESS")
            os.close(write_fd)
            os._exit(0)

        os.close(write_fd)
        write_fd = -1
        payload = os.read(read_fd, 4096).decode("ascii")
        _, status = os.waitpid(actor.child_pid, 0)
        assert os.waitstatus_to_exitcode(status) == 0
        assert payload == (
            f"EXECUTION_PROCESS_BOUNDARY|{len(expected_fds)}|"
            f"{len(expected_fds)}|0"
        )

        # Child-local close does not mutate the parent's registry or FDs.  A
        # successful parent revocation then closes its own descriptor copies.
        if callback_stage == "revoke":
            for fd in expected_fds:
                with pytest.raises(OSError):
                    os.fstat(fd)
        else:
            assert all(os.fstat(fd) for fd in expected_fds)
        if callback_stage in {"materialize", "precreate"}:
            authority.abort_before_process_creation(
                reason_code="PARENT_ABORT"
            )
        authority.close()
        authority = None
    finally:
        if read_fd >= 0:
            os.close(read_fd)
        if write_fd >= 0:
            os.close(write_fd)
        if authority is not None:
            authority.close()
        harness.close()


def test_reentrant_issuance_is_reserved_before_consumer_callback(
    tmp_path: Path,
) -> None:
    harness = Harness(tmp_path, "codex")

    class ReentrantConsumer(_Consumer):
        inner_authority = None
        inner_error = ""

        def consume_posix_backend_launch(self, request, *, prompt_fd):
            try:
                self.inner_authority = (
                    execution._TEST_ONLY_prepare_posix_backend_execution(
                        **_prepare_arguments(harness)
                    )
                )
            except execution.PosixBackendExecutionError as exc:
                self.inner_error = exc.code
            return super().consume_posix_backend_launch(
                request, prompt_fd=prompt_fd
            )

    consumer = ReentrantConsumer(harness)
    authority = None
    try:
        authority = _prepare(harness, consumer)
        assert consumer.inner_authority is None
        assert consumer.inner_error == "ISSUANCE_REPLAY"
        assert len(execution._TEST_ONLY_EXECUTIONS) == 1
        authority.preview_physical_binding()
        authority.abort_before_process_creation(reason_code="OUTER_ABORT")
        authority.close()
        authority = None
    finally:
        if consumer.inner_authority is not None:
            consumer.inner_authority.close()
        if authority is not None:
            authority.close()
        harness.close()


def test_concurrent_issuance_reserves_before_consumer_callback(
    tmp_path: Path,
) -> None:
    harness = Harness(tmp_path, "codex")
    entered = threading.Event()
    release = threading.Event()

    class BlockingConsumer(_Consumer):
        calls = 0

        def consume_posix_backend_launch(self, request, *, prompt_fd):
            self.calls += 1
            entered.set()
            if not release.wait(5):
                raise AssertionError("issuance release timed out")
            return super().consume_posix_backend_launch(
                request, prompt_fd=prompt_fd
            )

    consumer = BlockingConsumer(harness)
    authority = None
    execution._register_test_only_outer_supervisor_bridge(
        consumer, _Verifier()
    )
    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            first = pool.submit(
                execution._TEST_ONLY_prepare_posix_backend_execution,
                **_prepare_arguments(harness),
            )
            assert entered.wait(5)
            second = pool.submit(
                execution._TEST_ONLY_prepare_posix_backend_execution,
                **_prepare_arguments(harness),
            )
            with pytest.raises(
                execution.PosixBackendExecutionError,
                match="ISSUANCE_REPLAY",
            ):
                second.result(timeout=5)
            release.set()
            authority = first.result(timeout=5)
        assert consumer.calls == 1
        assert len(execution._TEST_ONLY_EXECUTIONS) == 1
        authority.preview_physical_binding()
        authority.abort_before_process_creation(reason_code="THREAD_ABORT")
        authority.close()
        authority = None
    finally:
        release.set()
        if authority is not None:
            authority.close()
        harness.close()


def test_abandoned_test_only_record_is_retired_without_outer_callbacks(
    tmp_path: Path,
) -> None:
    harness = Harness(tmp_path, "codex")
    consumer = _Consumer(harness)
    authority = None
    try:
        authority = _prepare(harness, consumer)
        identity = id(authority)
        record = execution._TEST_ONLY_EXECUTIONS[identity]
        plan_identity = id(record.plan)
        del record
        authority = None
        gc.collect()
        assert identity not in execution._TEST_ONLY_EXECUTIONS
        assert plan_identity not in launch_policy._TEST_ONLY_PLANS
        assert consumer.materializations == 0
        assert consumer.revocations == 0
    finally:
        if authority is not None:
            authority.close()
        harness.close()


def test_forced_id_reuse_cannot_transplant_abandoned_record(
    tmp_path: Path,
) -> None:
    harness = Harness(tmp_path, "codex")
    authority = None
    candidate = None
    try:
        authority = _prepare(harness, _Consumer(harness))
        stale_identity = id(authority)
        token = object.__getattribute__(
            authority, "_TestOnlyPosixBackendExecution__token"
        )
        creator_pid = object.__getattribute__(
            authority, "_TestOnlyPosixBackendExecution__creator_pid"
        )
        interpreter_nonce = object.__getattribute__(
            authority, "_TestOnlyPosixBackendExecution__interpreter_nonce"
        )
        stale_record = execution._TEST_ONLY_EXECUTIONS[stale_identity]
        authority = None
        gc.collect()
        assert stale_identity not in execution._TEST_ONLY_EXECUTIONS

        candidate = object.__new__(execution.TestOnlyPosixBackendExecution)
        object.__setattr__(
            candidate, "_TestOnlyPosixBackendExecution__token", token
        )
        object.__setattr__(
            candidate,
            "_TestOnlyPosixBackendExecution__creator_pid",
            creator_pid,
        )
        object.__setattr__(
            candidate,
            "_TestOnlyPosixBackendExecution__interpreter_nonce",
            interpreter_nonce,
        )
        # Deterministically recreate CPython's integer-id reuse outcome: the
        # stale record is present at the newly allocated exact-type object's
        # identity and every forgeable slot has been restored.  The dead weakref
        # identity, not allocator timing, must reject the transplant.
        execution._TEST_ONLY_EXECUTIONS[id(candidate)] = stale_record
        with pytest.raises(
            execution.PosixBackendExecutionError,
            match="object identity drifted",
        ):
            candidate.preview_physical_binding()
    finally:
        if candidate is not None:
            execution._TEST_ONLY_EXECUTIONS.pop(id(candidate), None)
        candidate = None
        if authority is not None:
            authority.close()
        harness.close()


def test_materialization_is_thread_safe_and_consumed_once(
    tmp_path: Path,
) -> None:
    harness = Harness(tmp_path, "codex")
    entered = threading.Event()
    release = threading.Event()

    class BlockingConsumer(_Consumer):
        def materialize_posix_backend_launch(self, invocation, binding):
            entered.set()
            if not release.wait(5):
                raise AssertionError("materialization test release timed out")
            return super().materialize_posix_backend_launch(invocation, binding)

    consumer = BlockingConsumer(harness)
    authority = None
    try:
        authority = _prepare(harness, consumer)
        authority.preview_physical_binding()
        with ThreadPoolExecutor(max_workers=2) as pool:
            first = pool.submit(
                authority.materialize_after_inner_arm,
                inner_arm_sha256="d" * 64,
            )
            assert entered.wait(5)
            second = pool.submit(
                authority.materialize_after_inner_arm,
                inner_arm_sha256="d" * 64,
            )
            release.set()
            assert isinstance(first.result(timeout=5), execution.PosixPhysicalLaunch)
            with pytest.raises(
                execution.PosixBackendExecutionError,
                match="EXECUTION_STATE",
            ):
                second.result(timeout=5)
        assert consumer.materializations == 1
        authority.abort_before_process_creation(reason_code="TEST_ABORT")
        authority.close()
        authority = None
    finally:
        release.set()
        if authority is not None:
            authority.close()
        harness.close()


def test_precreate_validation_and_process_creation_are_one_shot(
    tmp_path: Path,
) -> None:
    harness = Harness(tmp_path, "codex")
    authority = None
    try:
        authority = _prepare(harness, _Consumer(harness))
        authority.preview_physical_binding()
        authority.materialize_after_inner_arm(inner_arm_sha256="d" * 64)
        with pytest.raises(
            execution.PosixBackendExecutionError, match="EXECUTION_STATE"
        ):
            authority.mark_process_created()
        gate = threading.Barrier(3)

        def precreate_once():
            gate.wait(timeout=5)
            return authority.revalidate_immediately_before_process_creation()

        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(precreate_once) for _ in range(2)]
            gate.wait(timeout=5)
            outcomes: list[object] = []
            for future in futures:
                try:
                    outcomes.append(future.result(timeout=5))
                except BaseException as exc:
                    outcomes.append(exc)
        assert outcomes.count(None) == 1
        assert sum(
            isinstance(item, execution.PosixBackendExecutionError)
            for item in outcomes
        ) == 1
        authority.mark_process_created()
        with pytest.raises(
            execution.PosixBackendExecutionError, match="EXECUTION_STATE"
        ):
            authority.mark_process_created()
        authority.revoke_after_scope_close(
            process_creation_state="ATTACHED",
            process_population_zero_proven=True,
            returncode=0,
            reason_code="PROCESS_SCOPE_CLOSED",
        )
        authority.close()
        authority = None
    finally:
        if authority is not None:
            authority.close()
        harness.close()


def test_preview_abort_and_terminal_completion_are_thread_one_shot(
    tmp_path: Path,
) -> None:
    preview_harness = Harness(tmp_path / "preview", "codex")
    preview_authority = None
    try:
        preview_authority = _prepare(
            preview_harness, _Consumer(preview_harness)
        )
        gate = threading.Barrier(3)

        def preview_once():
            gate.wait(timeout=5)
            return preview_authority.preview_physical_binding()

        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(preview_once) for _ in range(2)]
            gate.wait(timeout=5)
            outcomes: list[object] = []
            for future in futures:
                try:
                    outcomes.append(future.result(timeout=5))
                except BaseException as exc:
                    outcomes.append(exc)
        assert sum(isinstance(item, Mapping) for item in outcomes) == 1
        assert sum(
            isinstance(item, execution.PosixBackendExecutionError)
            for item in outcomes
        ) == 1

        gate = threading.Barrier(3)

        def abort_once():
            gate.wait(timeout=5)
            return preview_authority.abort_before_process_creation(
                reason_code="THREAD_ABORT"
            )

        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(abort_once) for _ in range(2)]
            gate.wait(timeout=5)
            outcomes = []
            for future in futures:
                try:
                    outcomes.append(future.result(timeout=5))
                except BaseException as exc:
                    outcomes.append(exc)
        assert sum(isinstance(item, Mapping) for item in outcomes) == 1
        assert sum(
            isinstance(item, execution.PosixBackendExecutionError)
            for item in outcomes
        ) == 1
        preview_authority.close()
        preview_authority = None
    finally:
        if preview_authority is not None:
            preview_authority.close()
        preview_harness.close()

    execution._reset_trusted_bridge_for_tests()
    completion_harness = Harness(tmp_path / "completion", "codex")
    consumer = _Consumer(completion_harness)
    completion_authority = None
    try:
        completion_authority = _prepare(completion_harness, consumer)
        completion_authority.preview_physical_binding()
        completion_authority.materialize_after_inner_arm(
            inner_arm_sha256="d" * 64
        )
        completion_authority.revalidate_immediately_before_process_creation()
        completion_authority.mark_process_created()
        gate = threading.Barrier(3)

        def complete_once():
            gate.wait(timeout=5)
            return completion_authority.revoke_after_scope_close(
                process_creation_state="ATTACHED",
                process_population_zero_proven=True,
                returncode=0,
                reason_code="PROCESS_SCOPE_CLOSED",
            )

        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(complete_once) for _ in range(2)]
            gate.wait(timeout=5)
            outcomes = []
            for future in futures:
                try:
                    outcomes.append(future.result(timeout=5))
                except BaseException as exc:
                    outcomes.append(exc)
        assert consumer.revocations == 1
        assert sum(isinstance(item, Mapping) for item in outcomes) == 1
        assert sum(
            isinstance(item, execution.PosixBackendExecutionError)
            for item in outcomes
        ) == 1
        completion_authority.close()
        completion_authority = None
    finally:
        if completion_authority is not None:
            completion_authority.close()
        completion_harness.close()


@pytest.mark.parametrize("entrypoint", ("public", "direct"))
@pytest.mark.parametrize("attack", ("subclass-property", "exact-evil-value"))
def test_posix_hardstop_precedes_all_bindings_callbacks_and_mutation(
    tmp_path: Path,
    entrypoint: str,
    attack: str,
) -> None:
    marker = tmp_path / "bindings-callback-reached"

    class EvilValue:
        def __hash__(self) -> int:
            marker.write_text("hash", encoding="utf-8")
            return 0

        def __eq__(self, _other: object) -> bool:
            marker.write_text("equal", encoding="utf-8")
            return False

    if attack == "subclass-property":
        class EvilBindings(wer.ExecutionBindings):
            @property
            def effective_backend(self):
                marker.write_text("property", encoding="utf-8")
                return "codex"

        bindings = object.__new__(EvilBindings)
    else:
        bindings = _minimal_wer_bindings(tmp_path)
        object.__setattr__(bindings, "effective_backend", EvilValue())

    runner = (
        wer.run_observed_worker
        if entrypoint == "public"
        else wer._run_observed_worker_direct
    )
    with pytest.raises(
        wer.NativePosixProcessAuthorityUnavailable,
        match="NATIVE_POSIX_PROCESS_AUTHORITY_UNAVAILABLE",
    ):
        runner(
            scratchpad=tmp_path,
            bindings=bindings,
            argv=[sys.executable, "-c", "raise SystemExit(99)"],
            cwd=tmp_path,
            output_scope_relative="output",
            expected_outputs=(),
            parser_digest=lambda _path, _raw: "0" * 64,
            environment={},
            environment_allowlist=(),
        )
    assert not marker.exists()
    assert not (tmp_path / "output").exists()
    assert not (tmp_path / ".worker_execution_receipts").exists()


def test_production_hardstops_raise_before_temporary_destructors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    original_fail = execution._fail

    def observed_fail(code: str, message: str, exc=None):
        events.append(f"raise:{code}")
        original_fail(code, message, exc)

    class Evil:
        def __del__(self) -> None:
            events.append("destructor")

    monkeypatch.setattr(execution, "_fail", observed_fail)
    with pytest.raises(
        execution.PosixBackendExecutionError,
        match="NATIVE_BRIDGE_UNAVAILABLE",
    ):
        execution.prepare_posix_backend_execution(
            backend=Evil(), model="unused", attempt_id="unused",
            outer_attempt_arm_sha256="unused", work_plan_sha256="unused",
            process_scope_identity="unused", base_argv=(),
            base_environment={}, cwd=tmp_path, prompt_path=tmp_path,
            prompt_sha256="unused",
            native_authority=Evil(),
            timeout_seconds=2400,
            stdout_limit_bytes=1024,
            stderr_limit_bytes=1024,
        )
    gc.collect()
    assert events[0] == "raise:NATIVE_BRIDGE_UNAVAILABLE"

    events.clear()
    forged = object.__new__(execution.PosixBackendExecution)
    with pytest.raises(
        execution.PosixBackendExecutionError,
        match="NATIVE_BRIDGE_UNAVAILABLE",
    ):
        forged.materialize_after_inner_arm(inner_arm_sha256=Evil())
    gc.collect()
    assert events[0] == "raise:NATIVE_BRIDGE_UNAVAILABLE"
