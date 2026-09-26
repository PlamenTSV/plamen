from __future__ import annotations

import base64
import copy
import gc
import hashlib
import importlib.machinery
import importlib.util
import json
import pickle
from pathlib import Path
import re
import sys
import threading
import types
import weakref

import pytest


sys.path.insert(0, str(Path(__file__).resolve().parent))

import posix_backend_execution as execution
import posix_backend_launch_policy as launch_policy


_HEX = "a" * 64


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _raw(value: dict[str, object]) -> bytes:
    return execution.canonical_json_bytes(value)


def _install_generation(backend: str, version: str | None = None):
    resolved = version or ("0.154.0" if backend == "codex" else "2.1.270")
    return launch_policy.TEST_ONLY_issue_backend_install_generation(
        backend=backend,
        resolved_version=resolved,
        executable_sha256="1" * 64,
        executable_size=12345,
        runtime_closure_sha256="2" * 64,
        publisher="OpenAI" if backend == "codex" else "Anthropic PBC",
        publisher_identity_sha256="3" * 64,
        provenance="SIGNED_UPSTREAM_RELEASE",
        provenance_receipt_sha256="4" * 64,
        latest_resolution_receipt_sha256="5" * 64,
        cli_behavior_contract_sha256=(
            launch_policy.backend_cli_behavior_contract_sha256(backend)
        ),
        cli_conformance_sha256="7" * 64,
        install_generation_id=f"{backend}-generation-1",
        producer_receipt_sha256="8" * 64,
        acquisition_policy_sha256="9" * 64,
        acquisition_validator_sha256="a" * 64,
        registry_latest_observation_sha256="b" * 64,
        upstream_integrity_sha256="c" * 64,
        signature_provenance_sha256="d" * 64,
        installed_manifest_sha256="e" * 64,
        coordinator_receipt_sha256="f" * 64,
    )


def _envelope(backend: str) -> tuple[bytes, dict[str, object]]:
    raw = execution.native_backend_execution_envelope_v2(
        backend=backend,
        model="gpt-5.6-sol" if backend == "codex" else "claude-opus-4-1",
        attempt_id="attempt-001",
        outer_attempt_arm_sha256=_HEX,
        work_plan_sha256="b" * 64,
        process_scope_identity="scope-001",
        base_argv=[backend, "exec", "secret-argument-must-be-digested"],
        base_environment={
            "LANG": "C.UTF-8",
            "PLAMEN_TOKEN": "secret-value-must-be-digested",
        },
        cwd_identity_sha256="c" * 64,
        prompt_sha256="d" * 64,
        provider_stdout_contract_sha256="e" * 64,
        timeout_seconds=2400,
        stdout_limit_bytes=execution.BACKEND_STDOUT_LIMIT_BYTES,
        stderr_limit_bytes=execution.BACKEND_STDERR_LIMIT_BYTES,
        backend_install_generation_authority=_install_generation(backend),
    )
    return raw, json.loads(raw)


def _enum_value(header: str, name: str) -> int:
    match = re.search(rf"\b{name}\s*=\s*(0x[0-9a-fA-F]+|[0-9]+)", header)
    assert match is not None, name
    return int(match.group(1), 0)


def test_v2_envelopes_share_wire_abi_but_keep_backends_distinct() -> None:
    codex_raw, codex = _envelope("codex")
    claude_raw, claude = _envelope("claude")

    assert codex_raw == execution.canonical_json_bytes(codex)
    assert claude_raw == execution.canonical_json_bytes(claude)
    assert codex["schema"] == execution.NATIVE_CODEX_REQUEST_SCHEMA
    assert claude["schema"] == execution.NATIVE_CLAUDE_REQUEST_SCHEMA
    assert codex["schema"] != claude["schema"]
    for envelope in (codex, claude):
        assert envelope["native_broker_abi_schema"] == "plamen.native-broker.v2"
        assert envelope["native_broker_protocol_version"] == 2
        assert envelope["native_execution_abi_schema"] == (
            "plamen.posix_backend_execution.native.v2"
        )
        assert envelope["lifecycle_contract"] == {
            "ack_loss_replays_without_effect": True,
            "cli_prepare_forbidden_for_guest_backend_execution": True,
            "credential_and_egress_revocation_required": True,
            "durable_exited_before_ack": True,
            "durable_prepare_before_spawn": True,
            "durable_started_before_ack": True,
            "close_exchange": [112, 113],
            "initial_consume_exchange": [2, 3],
            "output_exchange": [96, 97],
            "output_reads_replay_without_effect": True,
            "prepare_exchange": [80, 81],
            "process_tree_extinction_required": True,
            "revoke_exchange": [64, 65],
            "role_selection": "NATIVE_REGISTRATION_ONLY",
            "start_exchange": [32, 33, 34],
            "wait_exchange": [48, 49, 50],
        }
        stream = envelope["stream_contract"]
        assert stream["full_stream_sha256_required"] is True
        assert stream["retained_stream_sha256_required"] is True
        assert stream["overflow_disposition"] == "REVOKE_WITHOUT_COMPLETION"
        assert stream["read_chunk_max_bytes"] == 256 * 1024
        assert stream["stdout_retained_limit_bytes"] == 16 * 1024 * 1024

    assert codex["backend_policy"]["schema"].endswith("codex_policy.v2")
    assert claude["backend_policy"]["schema"].endswith("claude_policy.v2")
    assert codex["backend_executable_contract"]["allowed_version"] == "0.154.0"
    assert claude["backend_executable_contract"]["allowed_version"] == "2.1.270"
    for envelope in (codex, claude):
        contract = envelope["backend_executable_contract"]
        assert contract["install_generation_sha256"]
        assert contract["latest_resolution_receipt_sha256"] == "5" * 64
        assert contract["cli_behavior_contract_sha256"] == (
            launch_policy.backend_cli_behavior_contract_sha256(
                envelope["backend"]
            )
        )
        assert contract["cli_conformance_sha256"] == "7" * 64
    assert codex["fd_roster_contract"]["ordered_purpose_ids"] != (
        claude["fd_roster_contract"]["ordered_purpose_ids"]
    )
    assert 0x0015 in codex["fd_roster_contract"]["ordered_purpose_ids"]
    assert 0x0016 in claude["fd_roster_contract"]["ordered_purpose_ids"]
    assert 0x0017 in claude["fd_roster_contract"]["ordered_purpose_ids"]
    assert b"secret-value-must-be-digested" not in codex_raw
    assert b"secret-argument-must-be-digested" not in codex_raw


def test_native_envelope_rejects_missing_or_cross_backend_install_generation() -> None:
    arguments = {
        "backend": "codex",
        "model": "gpt-5.6-sol",
        "attempt_id": "attempt-001",
        "outer_attempt_arm_sha256": _HEX,
        "work_plan_sha256": "b" * 64,
        "process_scope_identity": "scope-001",
        "base_argv": ["codex", "exec"],
        "base_environment": {"LANG": "C.UTF-8"},
        "cwd_identity_sha256": "c" * 64,
        "prompt_sha256": "d" * 64,
        "provider_stdout_contract_sha256": "e" * 64,
        "timeout_seconds": 2400,
        "stdout_limit_bytes": execution.BACKEND_STDOUT_LIMIT_BYTES,
        "stderr_limit_bytes": execution.BACKEND_STDERR_LIMIT_BYTES,
    }
    with pytest.raises(
        execution.PosixBackendExecutionError,
        match="INSTALL_GENERATION_AUTHORITY",
    ):
        execution.native_backend_execution_envelope_v2(**arguments)
    with pytest.raises(
        execution.PosixBackendExecutionError,
        match="INSTALL_GENERATION_BACKEND",
    ):
        execution.native_backend_execution_envelope_v2(
            **arguments,
            backend_install_generation_authority=_install_generation("claude"),
        )


def test_v2_wire_constants_match_current_native_header() -> None:
    header = (
        Path(__file__).resolve().parents[1]
        / "native"
        / "include"
        / "plamen_broker_v2.h"
    ).read_text(encoding="utf-8")
    expected = {
        "PLAMEN_BROKER_V2_AUTH_CONSUME": execution.NATIVE_BROKER_AUTH_CONSUME,
        "PLAMEN_BROKER_V2_AUTH_ACCEPTED": execution.NATIVE_BROKER_AUTH_ACCEPTED,
        "PLAMEN_BROKER_V2_START_PREPARE": execution.NATIVE_BROKER_START_PREPARE,
        "PLAMEN_BROKER_V2_STARTED": execution.NATIVE_BROKER_STARTED,
        "PLAMEN_BROKER_V2_START_RECOVER": execution.NATIVE_BROKER_START_RECOVER,
        "PLAMEN_BROKER_V2_WAIT_PREPARE": execution.NATIVE_BROKER_WAIT_PREPARE,
        "PLAMEN_BROKER_V2_EXITED": execution.NATIVE_BROKER_EXITED,
        "PLAMEN_BROKER_V2_WAIT_RECOVER": execution.NATIVE_BROKER_WAIT_RECOVER,
        "PLAMEN_BROKER_V2_REVOKE_PREPARE": execution.NATIVE_BROKER_REVOKE_PREPARE,
        "PLAMEN_BROKER_V2_REVOKED": execution.NATIVE_BROKER_REVOKED,
        "PLAMEN_BROKER_V2_BACKEND_PREPARE": (
            execution.NATIVE_BROKER_BACKEND_PREPARE
        ),
        "PLAMEN_BROKER_V2_BACKEND_PREPARED": (
            execution.NATIVE_BROKER_BACKEND_PREPARED
        ),
        "PLAMEN_BROKER_V2_OUTPUT_READ": execution.NATIVE_BROKER_OUTPUT_READ,
        "PLAMEN_BROKER_V2_OUTPUT_CHUNK": execution.NATIVE_BROKER_OUTPUT_CHUNK,
        "PLAMEN_BROKER_V2_OPERATION_CLOSE": (
            execution.NATIVE_BROKER_OPERATION_CLOSE
        ),
        "PLAMEN_BROKER_V2_OPERATION_FINISHED": (
            execution.NATIVE_BROKER_OPERATION_FINISHED
        ),
        "PLAMEN_BROKER_V2_INITIAL_GUEST_DRIVER": (
            execution.NATIVE_INITIAL_ROLE_GUEST_DRIVER
        ),
        "PLAMEN_BROKER_V2_PROCESS_BACKEND_EXECUTION": (
            execution.NATIVE_PROCESS_ROLE_BACKEND_EXECUTION
        ),
    }
    assert {
        name: _enum_value(header, name) for name in expected
    } == expected
    assert execution.NATIVE_PROCESS_ROLE_BACKEND_EXECUTION == 3
    assert execution.NATIVE_SPAWNED_ROLE_BACKEND_EXECUTION == 3
    assert "#define PLAMEN_BROKER_V2_OUTPUT_CHUNK_MAX 262144U" in header
    assert "#define PLAMEN_BROKER_V2_OUTPUT_STREAM_MAX 16777216U" in header


def test_python_module_forgery_is_not_an_admitted_native_extension(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = types.ModuleType("_plamen_native_supervisor")
    loader = importlib.machinery.ExtensionFileLoader(
        "_plamen_native_supervisor", "/tmp/_plamen_native_supervisor.so"
    )
    fake.__spec__ = importlib.util.spec_from_loader(
        "_plamen_native_supervisor", loader
    )
    fake.__file__ = "/tmp/_plamen_native_supervisor.so"
    fake.TEST_ONLY_BUILD = False
    fake.BROKER_V2_ABI_SCHEMA = "plamen.native-broker.v2"
    fake.BROKER_V2_PROTOCOL_VERSION = 2
    fake.BROKER_V2_FRAME_HEADER_SIZE = 196
    fake.BROKER_V2_AUTH_OFFSET = 164
    fake.BROKER_V2_MAX_FRAME_PAYLOAD_BYTES = 2 * 1024 * 1024
    fake.BROKER_V2_MAX_SCM_RIGHTS_FDS = 16
    fake.BROKER_V2_INITIAL_AUTHORITY_AVAILABLE = True
    fake.BROKER_V2_PRODUCTION_ACQUISITION = (
        "AVAILABLE_AUTHENTICATED_NATIVE_SESSION"
    )

    class Forged:
        def consume_once(self, *_args: object) -> object:
            raise AssertionError("forged Python callback must not be consumed")

    fake.NativeAuthorityConsumer = Forged
    fake.BrokerV2AuthorityConsumer = Forged
    fake.INITIAL_AUTHORITY = object.__new__(Forged)
    for name in (
        "SupervisorAuthorities",
        "RuntimeImageAuthority",
        "WorkspaceAuthority",
        "BackendContextAuthority",
        "ProviderAuthority",
        "GuestAdmissionAuthority",
        "ExtinctionAuthority",
        "ArtifactAuthority",
        "ExportAuthority",
        "JournalAuthority",
        "RecoveryAuthority",
        "SupervisorAuthority",
        "ProcessReceiptProjection",
        "ExitReceiptProjection",
        "NetworkReceiptProjection",
    ):
        setattr(fake, name, Forged)

    monkeypatch.setattr(
        execution.importlib, "import_module", lambda _name: fake
    )
    assert execution._admitted_native_supervisor_module() is None


def test_guest_runtime_acquisition_retains_distinct_tool_custody_before_consume(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[object] = []

    class Initial:
        def request_projection(self) -> bytes:
            events.append("projection")
            return b"authenticated-projection"

        def consume_once(self, fingerprint: str, attempt: str) -> object:
            events.append(("consume", fingerprint, attempt))
            return Bundle()

    class Backend:
        pass

    class BackendInstallGeneration:
        pass

    class Custody:
        pass

    class Lease:
        pass

    class Terminal:
        pass

    class ManagedInitial:
        pass

    class ManagedLease:
        pass

    class ManagedTerminal:
        pass

    class JSInitial:
        pass

    class JSSession:
        pass

    class JSExecution:
        pass

    class JSReplay:
        pass

    class Projection:
        pass

    class Bundle:
        def consume_once(self) -> tuple[Backend]:
            events.append("bundle")
            return (Backend(),)

    request = types.SimpleNamespace(
        fingerprint_sha256="1" * 64,
        attempt_id="attempt-1",
        run_id="run-1",
        backend="codex",
    )
    identity = execution.canonical_json_bytes({
        "schema": "plamen.darwin-tool-runtime-identity.v1",
        "platform": "MACOS",
        "extension_path": "/opt/plamen/_plamen_native_supervisor.so",
        "extension_sha256": "2" * 64,
        "extension_byte_count": 4096,
        "native_deployment_receipt_sha256": "3" * 64,
        "runtime_closure_sha256": "4" * 64,
        "broker_peer_identity_sha256": "5" * 64,
    })
    managed_identity = execution.canonical_json_bytes({
        "schema": "plamen.managed-evm-toolchain-runtime-identity.v1",
        "platform": "MACOS",
        "extension_path": "/opt/plamen/_plamen_native_supervisor.so",
        "extension_sha256": "2" * 64,
        "extension_byte_count": 4096,
        "native_deployment_receipt_sha256": "3" * 64,
        "runtime_closure_sha256": "4" * 64,
        "broker_peer_identity_sha256": "5" * 64,
        "managed_toolchain_custody_sha256": "6" * 64,
        "managed_python_sha256": "7" * 64,
        "managed_python_size": 123456,
        "native_interpreter_probe": {
            "base_prefix": "/usr/local/lib/plamen/python",
            "executable": "/usr/local/lib/plamen/python/bin/python3.12",
            "implementation": "CPython",
            "machine": "x86_64",
            "platlib": "/usr/local/lib/plamen/python/lib/python3.12/site-packages",
            "prefix": "/usr/local/lib/plamen/python",
            "purelib": "/usr/local/lib/plamen/python/lib/python3.12/site-packages",
            "sys_platform": "linux",
            "version": "3.12.12",
            "version_info": [3, 12, 12],
        },
        "guest_execution_authority": {
            "schema": "plamen.apple-container-tool-custody.v1",
            "platform": "linux",
            "architecture": "amd64",
            "runtime_image_reference": "example.invalid/plamen@sha256:" + "8" * 64,
            "image_closure_sha256": "9" * 64,
            "provider_admission_sha256": "a" * 64,
            "rosetta_required": True,
            "rosetta_authority_sha256": "b" * 64,
            "rootfs_readonly": True,
            "network_policy": "DENY_ALL",
            "network_isolation_authority_sha256": "c" * 64,
            "custody_receipt_sha256": "d" * 64,
            "immutable_launch_authority": "PRIVATE_IMMUTABLE_PROJECTED_CLOSURE",
            "population_zero_authority": True,
        },
    })
    js_identity = execution.canonical_json_bytes({
        "anchor_relative_path": "verification_policy/js_toolchain_bootstrap.v1.json",
        "anchor_sha256": "a" * 64,
        "custody_receipt_sha256": "b" * 64,
        "install_provenance_sha256": "c" * 64,
        "native_deployment_receipt_sha256": "d" * 64,
        "native_extension_sha256": "e" * 64,
        "offline_network_denial_sha256": "f" * 64,
        "online_network_admission_sha256": "1" * 64,
        "schema": "plamen.js-dependency-materializer-runtime-identity.v1",
        "source_census_sha256": "2" * 64,
        "trust_boundary": "AUTHENTICATED_INSTALLER_LAUNCHER_BOUNDARY_V1",
    })
    initial = Initial()
    managed_initial = ManagedInitial()
    js_initial = JSInitial()
    custody = Custody()
    lease = Lease()
    terminal = Terminal()
    managed_lease = ManagedLease()
    managed_terminal = ManagedTerminal()
    js_session = JSSession()
    js_execution = JSExecution()
    js_replay = JSReplay()
    projection = Projection()
    backend_install_generation = BackendInstallGeneration()
    module = types.SimpleNamespace(
        INITIAL_AUTHORITY=initial,
        JS_DEPENDENCY_MATERIALIZER_INITIAL_AUTHORITY=js_initial,
        MANAGED_EVM_TOOLCHAIN_INITIAL_AUTHORITY=managed_initial,
        NativeAuthorityConsumer=Initial,
        GuestDriverAuthorities=Bundle,
        BackendExecutionAuthority=Backend,
        BackendInstallGenerationAuthority=BackendInstallGeneration,
        DarwinToolCustodyAuthority=Custody,
        DarwinToolExecutionLease=Lease,
        DarwinToolExecutionTerminal=Terminal,
        JSDependencyMaterializerAuthority=JSInitial,
        JSDependencyMaterializerSessionLease=JSSession,
        JSDependencyMaterializerExecutionLease=JSExecution,
        JSDependencyMaterializerTerminalReplayLease=JSReplay,
        ManagedEVMToolchainInitialAuthority=ManagedInitial,
        ManagedEVMToolchainProvisionLease=ManagedLease,
        ManagedEVMToolchainProvisionTerminal=ManagedTerminal,
        EVMAnalysisProjectionAuthority=Projection,
    )

    def runtime_identity(observed: object) -> bytes:
        assert observed is initial
        events.append("runtime-identity")
        return identity

    def acquire(observed: object) -> object:
        assert observed is initial
        events.append("custody")
        return custody

    def managed_runtime(observed: object) -> bytes:
        assert observed is managed_initial
        events.append("managed-runtime-identity")
        return managed_identity

    def js_runtime(observed: object) -> bytes:
        assert observed is js_initial
        events.append("js-runtime-identity")
        return js_identity

    def prepare(
        observed: object, raw: bytes, source_fd: int, scratch_fd: int,
        state_fd: int, project_fd: int,
    ) -> object:
        assert observed is custody
        events.append(("prepare", raw, source_fd, scratch_fd, state_fd, project_fd))
        return lease

    def execute(observed: object, observed_lease: object) -> object:
        assert observed is custody and observed_lease is lease
        events.append("execute")
        return terminal

    def project(observed: object) -> bytes:
        assert observed is terminal
        events.append("project")
        return b'{"schema":"terminal"}'

    module.darwin_tool_runtime_identity = runtime_identity
    module.js_dependency_materializer_runtime_identity = js_runtime
    module.managed_evm_toolchain_runtime_identity = managed_runtime
    module.acquire_darwin_tool_custody = acquire

    def acquire_install_generation(observed: object, backend: str) -> object:
        assert observed is initial and backend == "codex"
        events.append("backend-install-generation")
        return backend_install_generation

    module.acquire_backend_install_generation = acquire_install_generation
    module.prepare_darwin_tool_execution = prepare
    module.execute_darwin_tool = execute
    module.project_darwin_tool_execution_terminal = project

    def prepare_managed(
        observed: object, raw: bytes, policy_fd: int, project_fd: int,
        cache_fd: int, generations_fd: int, acquisition_fd: int,
    ) -> object:
        assert observed is managed_initial
        events.append((
            "managed-prepare", raw, policy_fd, project_fd, cache_fd,
            generations_fd, acquisition_fd,
        ))
        return managed_lease

    def execute_managed(observed: object) -> object:
        assert observed is managed_lease
        events.append("managed-execute")
        return managed_terminal

    def project_managed(observed: object) -> bytes:
        assert observed is managed_terminal
        events.append("managed-project")
        return b'{"schema":"managed-terminal"}'

    module.prepare_managed_evm_toolchain_provision = prepare_managed
    module.execute_managed_evm_toolchain_provision = execute_managed
    module.project_managed_evm_toolchain_terminal = project_managed

    def authenticate_js(observed: object, raw: bytes) -> object:
        assert observed is js_initial
        events.append(("js-authenticate", raw))
        return js_session

    def prepare_js(
        observed: object, observed_session: object, raw: bytes,
        source_fd: int, scratch_fd: int, state_fd: int, archive_fd: int,
    ) -> object:
        assert observed is js_initial and observed_session is js_session
        events.append((
            "js-prepare", raw, source_fd, scratch_fd, state_fd, archive_fd,
        ))
        return js_execution

    def execute_js(
        observed: object, observed_session: object, observed_lease: object,
    ) -> bytes:
        assert (
            observed is js_initial and observed_session is js_session
            and observed_lease is js_execution
        )
        events.append("js-execute")
        return b'{"schema":"js-terminal"}\n'

    def replay_js(
        observed: object, observed_session: object, request_raw: bytes,
        terminal_raw: bytes, source_fd: int, scratch_fd: int,
        state_fd: int, archive_fd: int,
    ) -> object:
        assert observed is js_initial and observed_session is js_session
        events.append((
            "js-replay", request_raw, terminal_raw, source_fd, scratch_fd,
            state_fd, archive_fd,
        ))
        return js_replay

    module.authenticate_js_dependency_materializer_capability = authenticate_js
    module.prepare_js_dependency_materializer_execution = prepare_js
    module.execute_js_dependency_materializer = execute_js
    module.replay_js_dependency_materializer_terminal = replay_js

    def commit_projection(
        raw: bytes, project_fd: int, scratch_fd: int, state_fd: int,
        modules_fd: int,
    ) -> object:
        request_value = json.loads(raw)
        assert request_value["run_id"] == "run-1"
        events.append((
            "projection-commit", raw, project_fd, scratch_fd, state_fd,
            modules_fd,
        ))
        return projection

    def project_projection_receipt(observed: object) -> bytes:
        assert observed is projection
        return execution.canonical_json_bytes({
            "schema": "plamen.private-analysis-projection-custody.v1",
        })

    def project_projection_lineage(observed: object) -> bytes:
        assert observed is projection
        return execution.canonical_json_bytes({
            "schema": "plamen.evm-tool-materialization-lineage.v2",
        })

    def project_projection_workspace(observed: object) -> bytes:
        assert observed is projection
        return execution.canonical_json_bytes({
            "descriptor_identity_sha256": "a" * 64,
            "projection_receipt_sha256": "b" * 64,
            "schema": "plamen.evm-analysis-projection-workspace-binding.v1",
            "workspace_path": "/private/projection/analysis-workspace",
        })

    module.commit_evm_analysis_projection = commit_projection
    module.project_evm_analysis_projection_receipt = project_projection_receipt
    module.project_evm_analysis_projection_lineage = project_projection_lineage
    module.project_evm_analysis_projection_workspace_binding = (
        project_projection_workspace
    )
    monkeypatch.setattr(
        execution, "_admitted_native_supervisor_module", lambda: module,
    )
    import posix_audit_entrypoint as entrypoint
    import posix_audit_supervisor as supervisor
    monkeypatch.setattr(supervisor, "AuditRequest", type(request))
    monkeypatch.setattr(
        entrypoint, "_decode_request_projection", lambda *_args: request,
    )

    authority = execution.acquire_native_guest_runtime_authorities()
    assert type(authority) is execution.NativeGuestRuntimeAuthorities
    assert events[:8] == [
        "projection", "runtime-identity", "backend-install-generation",
        "js-runtime-identity",
        "managed-runtime-identity", "custody",
        ("consume", "1" * 64, "attempt-1"), "bundle",
    ]
    admitted_install_generation = object()

    def issue_install_generation(observed: object, *, expected_backend: str):
        assert observed is backend_install_generation
        assert expected_backend == "codex"
        events.append("project-backend-install-generation")
        return admitted_install_generation

    monkeypatch.setattr(
        execution._launch_policy,
        "_issue_native_backend_install_generation",
        issue_install_generation,
    )
    assert execution.native_guest_backend_install_generation_authority(
        authority
    ) is admitted_install_generation
    assert execution.native_guest_backend_install_generation_authority(
        authority
    ) is admitted_install_generation
    assert events.count("project-backend-install-generation") == 1
    assert execution.authenticated_native_guest_request(authority) is request
    assert type(
        execution.native_guest_backend_execution_authority(authority)
    ) is Backend
    assert execution.native_guest_snapshot_tool_runtime_identity(authority) == identity
    assert execution.native_guest_js_materializer_runtime_identity(
        authority
    ) == js_identity
    assert execution.native_guest_managed_evm_runtime_identity(
        authority
    ) == managed_identity
    bootstrap = json.loads(
        execution.native_guest_managed_evm_bootstrap_inputs(authority)
    )
    managed_value = json.loads(managed_identity)
    assert bootstrap == {
        "schema": "plamen.native-guest-managed-evm-bootstrap-inputs.v1",
        "guest_execution_authority": managed_value["guest_execution_authority"],
        "managed_python_sha256": "7" * 64,
        "managed_python_size": 123456,
        "managed_runtime_identity_sha256": _sha(managed_identity),
        "native_interpreter_probe": managed_value["native_interpreter_probe"],
    }
    assert repr(authority) == "<NativeGuestRuntimeAuthorities opaque>"
    with pytest.raises(TypeError, match="cannot be copied"):
        copy.copy(authority)
    with pytest.raises(TypeError, match="cannot be serialized"):
        pickle.dumps(authority)
    forged = object.__new__(execution.NativeGuestRuntimeAuthorities)
    with pytest.raises(
        execution.PosixBackendExecutionError,
        match="forged, expired, or changed",
    ):
        execution.authenticated_native_guest_request(forged)

    js_admission = b'{"schema":"js-admission"}\n'
    observed_js_session = execution.authenticate_native_guest_js_materializer(
        authority, js_admission,
    )
    assert observed_js_session is js_session
    with pytest.raises(
        execution.PosixBackendExecutionError, match="one-shot",
    ):
        execution.authenticate_native_guest_js_materializer(
            authority, js_admission,
        )
    js_request = b'{"schema":"js-request"}\n'
    observed_js_execution = (
        execution.prepare_native_guest_js_materializer_execution(
            authority, observed_js_session, js_request, 30, 31, 32, 33,
        )
    )
    assert observed_js_execution is js_execution
    js_terminal = execution.execute_native_guest_js_materializer(
        authority, observed_js_session, observed_js_execution,
    )
    assert js_terminal == b'{"schema":"js-terminal"}\n'
    with pytest.raises(
        execution.PosixBackendExecutionError, match="foreign or consumed",
    ):
        execution.execute_native_guest_js_materializer(
            authority, observed_js_session, observed_js_execution,
        )
    assert execution.replay_native_guest_js_materializer_terminal(
        authority, observed_js_session, js_request, js_terminal,
        30, 31, 32, 33,
    ) is js_replay
    with pytest.raises(
        execution.PosixBackendExecutionError, match="trailing LF",
    ):
        execution.prepare_native_guest_js_materializer_execution(
            authority, observed_js_session, js_request[:-1], 30, 31, 32, 33,
        )

    managed_request = b'{"schema":"managed-request"}'
    observed_managed_lease = execution.prepare_native_guest_managed_evm_provision(
        authority, managed_request, 20, 21, 22, 23, 24,
    )
    assert observed_managed_lease is managed_lease
    observed_managed_terminal = execution.execute_native_guest_managed_evm_provision(
        authority, observed_managed_lease,
    )
    assert observed_managed_terminal is managed_terminal
    assert execution.project_native_guest_managed_evm_terminal(
        authority, observed_managed_terminal,
    ) == b'{"schema":"managed-terminal"}'
    with pytest.raises(
        execution.PosixBackendExecutionError, match="already projected",
    ):
        execution.project_native_guest_managed_evm_terminal(
            authority, observed_managed_terminal,
        )

    dependency_body = {
        "lock_selection_sha256": "1" * 64,
        "modules_tree": {
            "algorithm": "PLAMEN_CANONICAL_TREE_SHA256_V1",
            "entry_count": 3,
            "expanded_bytes": 42,
            "sha256": "2" * 64,
        },
        "schema": "plamen.js-dependency-materialization-receipt.v2",
    }
    dependency_receipt = dependency_body | {
        "receipt_sha256": _sha(execution.canonical_json_bytes(dependency_body)),
    }
    observed_projection = (
        execution.commit_native_guest_evm_analysis_projection(
            authority,
            dependency_materialization_receipt=dependency_receipt,
            original_source_scope_sha256="3" * 64,
            project_fd=40,
            scratch_fd=41,
            state_fd=42,
            modules_fd=43,
        )
    )
    assert observed_projection is projection
    assert json.loads(
        execution.project_native_guest_evm_analysis_projection_receipt(
            authority, projection,
        )
    )["schema"] == "plamen.private-analysis-projection-custody.v1"
    assert json.loads(
        execution.project_native_guest_evm_analysis_projection_lineage(
            authority, projection,
        )
    )["schema"] == "plamen.evm-tool-materialization-lineage.v2"
    workspace = json.loads(
        execution.project_native_guest_evm_analysis_projection_workspace_binding(
            authority, projection,
        )
    )
    assert workspace["descriptor_identity_sha256"] == "a" * 64
    tampered = dependency_receipt | {"lock_selection_sha256": "4" * 64}
    with pytest.raises(
        execution.PosixBackendExecutionError, match="malformed or unauthenticated",
    ):
        execution.commit_native_guest_evm_analysis_projection(
            authority,
            dependency_materialization_receipt=tampered,
            original_source_scope_sha256="3" * 64,
            project_fd=40,
            scratch_fd=41,
            state_fd=42,
            modules_fd=43,
        )

    snapshot_request = execution.canonical_json_bytes({
        "schema": "plamen.snapshot-bound-tool-execution-request.v3",
        "run_id": "run-1",
        "audit_snapshot_sha256": "6" * 64,
        "tool_id": "forge",
        "source_descriptor": {
            "descriptor_sha256": "7" * 64, "kind": "directory",
        },
        "mounts": [
            {"mount_id": "analysis-input", "source_sha256": "7" * 64},
            {"mount_id": "project"},
            {"mount_id": "scratch"},
            {"mount_id": "state"},
        ],
    })
    observed_lease = execution.prepare_native_guest_snapshot_tool_execution(
        authority, snapshot_request, 10, 11, 12, 13,
    )
    assert observed_lease is lease
    observed_terminal = execution.execute_native_guest_snapshot_tool_execution(
        authority, observed_lease,
    )
    assert observed_terminal is terminal
    assert execution.project_native_guest_snapshot_tool_terminal(
        authority, observed_terminal,
    ) == b'{"schema":"terminal"}'

    opengrep_request = execution.canonical_json_bytes({
        "schema": "plamen.snapshot-bound-tool-execution-request.v3",
        "run_id": "run-1",
        "audit_snapshot_sha256": "6" * 64,
        "tool_id": "opengrep",
        "source_descriptor": {
            "descriptor_sha256": "7" * 64, "kind": "directory",
        },
        "mounts": [
            {"mount_id": "analysis-input", "source_sha256": "7" * 64},
            {"mount_id": "project"},
            {"mount_id": "scratch"},
            {"mount_id": "state"},
        ],
    })
    assert execution.prepare_native_guest_snapshot_tool_execution(
        authority, opengrep_request, 10, 11, 12, 13,
    ) is lease

    opengrep_without_analysis_input = execution.canonical_json_bytes({
        "schema": "plamen.snapshot-bound-tool-execution-request.v3",
        "run_id": "run-1",
        "audit_snapshot_sha256": "6" * 64,
        "tool_id": "opengrep",
        "source_descriptor": {
            "descriptor_sha256": "7" * 64, "kind": "directory",
        },
        "mounts": [
            {"mount_id": "project"},
            {"mount_id": "scratch"},
            {"mount_id": "state"},
        ],
    })
    with pytest.raises(
        execution.PosixBackendExecutionError,
        match="belongs to another run",
    ):
        execution.prepare_native_guest_snapshot_tool_execution(
            authority, opengrep_without_analysis_input, 10, 11, 12, 13,
        )

    forge_file_source = execution.canonical_json_bytes({
        "schema": "plamen.snapshot-bound-tool-execution-request.v3",
        "run_id": "run-1",
        "audit_snapshot_sha256": "6" * 64,
        "tool_id": "forge",
        "source_descriptor": {
            "descriptor_sha256": "7" * 64, "kind": "file",
        },
        "mounts": [
            {"mount_id": "analysis-input", "source_sha256": "7" * 64},
            {"mount_id": "project"},
            {"mount_id": "scratch"},
            {"mount_id": "state"},
        ],
    })
    with pytest.raises(
        execution.PosixBackendExecutionError,
        match="belongs to another run",
    ):
        execution.prepare_native_guest_snapshot_tool_execution(
            authority, forge_file_source, 10, 11, 12, 13,
        )

    wrong_run = execution.canonical_json_bytes({
        "schema": "plamen.snapshot-bound-tool-execution-request.v3",
        "run_id": "run-2",
        "audit_snapshot_sha256": "6" * 64,
        "tool_id": "forge",
        "source_descriptor": {
            "descriptor_sha256": "7" * 64, "kind": "directory",
        },
        "mounts": [
            {"mount_id": "analysis-input", "source_sha256": "7" * 64},
            {"mount_id": "project"},
            {"mount_id": "scratch"},
            {"mount_id": "state"},
        ],
    })
    with pytest.raises(
        execution.PosixBackendExecutionError,
        match="belongs to another run",
    ):
        execution.prepare_native_guest_snapshot_tool_execution(
            authority, wrong_run, 10, 11, 12, 13,
        )


def test_managed_bootstrap_identity_rejects_probe_and_guest_substitution() -> None:
    guest = {
        "schema": "plamen.apple-container-tool-custody.v1",
        "platform": "linux", "architecture": "amd64",
        "runtime_image_reference": "example.invalid/p@sha256:" + "1" * 64,
        "image_closure_sha256": "2" * 64,
        "provider_admission_sha256": "3" * 64,
        "rosetta_required": True,
        "rosetta_authority_sha256": "4" * 64,
        "rootfs_readonly": True, "network_policy": "DENY_ALL",
        "network_isolation_authority_sha256": "5" * 64,
        "custody_receipt_sha256": "6" * 64,
        "immutable_launch_authority": "PRIVATE_IMMUTABLE_PROJECTED_CLOSURE",
        "population_zero_authority": True,
    }
    probe = {
        "base_prefix": "/usr/local/lib/plamen/python",
        "executable": "/usr/local/lib/plamen/python/bin/python3.12",
        "implementation": "CPython", "machine": "x86_64",
        "platlib": "/usr/local/lib/plamen/python/lib/python3.12/site-packages",
        "prefix": "/usr/local/lib/plamen/python",
        "purelib": "/usr/local/lib/plamen/python/lib/python3.12/site-packages",
        "sys_platform": "linux", "version": "3.12.12",
        "version_info": [3, 12, 12],
    }
    identity = {
        "schema": "plamen.managed-evm-toolchain-runtime-identity.v1",
        "platform": "MACOS",
        "extension_path": "/opt/plamen/_plamen_native_supervisor.so",
        "extension_sha256": "7" * 64, "extension_byte_count": 4096,
        "native_deployment_receipt_sha256": "8" * 64,
        "runtime_closure_sha256": "9" * 64,
        "broker_peer_identity_sha256": "a" * 64,
        "managed_toolchain_custody_sha256": "b" * 64,
        "managed_python_sha256": "c" * 64, "managed_python_size": 4096,
        "native_interpreter_probe": probe,
        "guest_execution_authority": guest,
    }
    raw = execution.canonical_json_bytes(identity)
    assert execution._validate_native_managed_runtime_identity(raw) == raw

    substituted_probe = json.loads(raw)
    substituted_probe["native_interpreter_probe"]["machine"] = "arm64"
    with pytest.raises(
        execution.PosixBackendExecutionError, match="interpreter probe differs",
    ):
        execution._validate_native_managed_runtime_identity(
            execution.canonical_json_bytes(substituted_probe)
        )

    substituted_guest = json.loads(raw)
    substituted_guest["guest_execution_authority"]["rosetta_required"] = False
    with pytest.raises(
        execution.PosixBackendExecutionError, match="authority differs",
    ):
        execution._validate_native_managed_runtime_identity(
            execution.canonical_json_bytes(substituted_guest)
        )


def test_missing_native_backend_api_precedes_request_inspection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []

    class Evil:
        def __eq__(self, _other: object) -> bool:
            events.append("eq")
            return False

        def __iter__(self):
            events.append("iter")
            return iter(())

        def __fspath__(self) -> str:
            events.append("fspath")
            return str(tmp_path)

        def __str__(self) -> str:
            events.append("str")
            return "evil"

    monkeypatch.setattr(
        execution, "_admitted_native_supervisor_module", lambda: None
    )
    evil = Evil()
    with pytest.raises(
        execution.PosixBackendExecutionError,
        match="NATIVE_BRIDGE_UNAVAILABLE",
    ):
        execution.prepare_posix_backend_execution(
            backend=evil,
            model=evil,
            attempt_id=evil,
            outer_attempt_arm_sha256=evil,
            work_plan_sha256=evil,
            process_scope_identity=evil,
            base_argv=evil,
            base_environment=evil,
            cwd=evil,
            prompt_path=evil,
            prompt_sha256=evil,
            provider_stdout_evidence_configuration=evil,
            native_authority=evil,
            timeout_seconds=2400,
            stdout_limit_bytes=1024,
            stderr_limit_bytes=1024,
        )
    assert events == []
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("backend", ["other", "CODEX", ""])
def test_native_envelope_rejects_unknown_backend(backend: str) -> None:
    with pytest.raises(execution.PosixBackendExecutionError, match="BACKEND"):
        execution.native_backend_execution_envelope_v2(
            backend=backend,
            model="model",
            attempt_id="attempt-001",
            outer_attempt_arm_sha256=_HEX,
            work_plan_sha256=_HEX,
            process_scope_identity="scope-001",
            base_argv=["backend"],
            base_environment={},
            cwd_identity_sha256=_HEX,
            prompt_sha256=_HEX,
            provider_stdout_contract_sha256=_HEX,
            timeout_seconds=2400,
            stdout_limit_bytes=1024,
            stderr_limit_bytes=1024,
        )


@pytest.mark.parametrize(
    ("field", "value", "error"),
    [
        ("timeout_seconds", False, "TIMEOUT"),
        ("timeout_seconds", 0, "TIMEOUT"),
        (
            "timeout_seconds",
            execution.NATIVE_BACKEND_TIMEOUT_MAX_SECONDS + 1,
            "TIMEOUT",
        ),
        ("stdout_limit_bytes", False, "STREAM_LIMIT"),
        ("stdout_limit_bytes", 0, "STREAM_LIMIT"),
        (
            "stdout_limit_bytes",
            execution.BACKEND_STDOUT_LIMIT_BYTES - 1,
            "STREAM_LIMIT",
        ),
        (
            "stdout_limit_bytes",
            execution.NATIVE_STREAM_OBSERVED_LIMIT_BYTES + 1,
            "STREAM_LIMIT",
        ),
        ("stderr_limit_bytes", False, "STREAM_LIMIT"),
        ("stderr_limit_bytes", 0, "STREAM_LIMIT"),
        (
            "stderr_limit_bytes",
            execution.BACKEND_STDERR_LIMIT_BYTES - 1,
            "STREAM_LIMIT",
        ),
        (
            "stderr_limit_bytes",
            execution.NATIVE_STREAM_OBSERVED_LIMIT_BYTES + 1,
            "STREAM_LIMIT",
        ),
    ],
)
def test_native_envelope_rejects_untrusted_timeout_and_stream_limits(
    field: str, value: object, error: str,
) -> None:
    arguments = {
        "backend": "codex",
        "model": "gpt-5.6-sol",
        "attempt_id": "attempt-001",
        "outer_attempt_arm_sha256": _HEX,
        "work_plan_sha256": "b" * 64,
        "process_scope_identity": "scope-001",
        "base_argv": ["codex", "exec"],
        "base_environment": {"LANG": "C.UTF-8"},
        "cwd_identity_sha256": "c" * 64,
        "prompt_sha256": "d" * 64,
        "provider_stdout_contract_sha256": "e" * 64,
        "timeout_seconds": 2400,
        "stdout_limit_bytes": execution.BACKEND_STDOUT_LIMIT_BYTES,
        "stderr_limit_bytes": execution.BACKEND_STDERR_LIMIT_BYTES,
        "backend_install_generation_authority": _install_generation("codex"),
    }
    arguments[field] = value
    with pytest.raises(execution.PosixBackendExecutionError, match=error):
        execution.native_backend_execution_envelope_v2(**arguments)


def _semantic_transcript() -> dict[str, object]:
    envelope, _ = _envelope("codex")
    prepare_request, operation_key = execution._prepare_request(envelope)
    prepared_raw = _raw({
        "schema": execution.NATIVE_PREPARED_RECEIPT_SCHEMA,
        "status": "PREPARED",
        "operation_key_sha256": operation_key,
        "prepare_request_sha256": _sha(prepare_request),
        "execution_envelope_sha256": _sha(envelope),
        "retained_fd_roster_sha256": "1" * 64,
        "preparation_generation_sha256": "2" * 64,
        "timeout_seconds": 2400,
        "stdout_requested_limit_bytes": execution.BACKEND_STDOUT_LIMIT_BYTES,
        "stderr_requested_limit_bytes": execution.BACKEND_STDERR_LIMIT_BYTES,
        "stdout_effective_limit_bytes": execution.BACKEND_STDOUT_LIMIT_BYTES,
        "stderr_effective_limit_bytes": execution.BACKEND_STDERR_LIMIT_BYTES,
    })
    prepared = execution.parse_native_prepared_receipt(
        prepared_raw,
        operation_key_sha256=operation_key,
        prepare_request_sha256=_sha(prepare_request),
        execution_envelope_sha256=_sha(envelope),
        timeout_seconds=2400,
        stdout_limit_bytes=execution.BACKEND_STDOUT_LIMIT_BYTES,
        stderr_limit_bytes=execution.BACKEND_STDERR_LIMIT_BYTES,
    )
    start_request = execution._start_request(prepared)
    process_identity = {
        "operation_key_sha256": operation_key,
        "start_request_sha256": _sha(start_request),
        "executable_identity_sha256": "3" * 64,
        "peer": {
            "pid": 4242,
            "uid": 501,
            "gid": 20,
            "birth_kind": 1,
            "birth_primary": 1_700_000_000,
            "birth_secondary": 123,
            "boot_id_sha256": "0" * 64,
        },
        "native_process_handle_sha256": "4" * 64,
    }
    process_identity_sha = execution._mapping_sha(process_identity)
    started_raw = _raw({
        "schema": execution.NATIVE_STARTED_RECEIPT_SCHEMA,
        "status": "STARTED",
        "disposition": "STARTED_NEW",
        "operation_key_sha256": operation_key,
        "start_request_sha256": _sha(start_request),
        "prepared_receipt_sha256": prepared.sha256,
        "process_identity": process_identity,
        "process_identity_sha256": process_identity_sha,
    })
    started = execution.parse_native_started_receipt(
        started_raw, prepared=prepared, start_request_sha256=_sha(start_request),
    )
    wait_request = execution._wait_request(started)
    stdout = b"audit-result\n"
    stderr = b""
    exited_raw = _raw({
        "schema": execution.NATIVE_EXITED_RECEIPT_SCHEMA,
        "status": "EXITED",
        "disposition": "OBSERVED_NEW",
        "operation_key_sha256": operation_key,
        "wait_request_sha256": _sha(wait_request),
        "started_receipt_sha256": started.sha256,
        "process_identity_sha256": process_identity_sha,
        "exit_kind": "EXIT_CODE",
        "returncode": 0,
        "signal": None,
        "stdout_size_bytes": len(stdout),
        "stdout_sha256": _sha(stdout),
        "stderr_size_bytes": len(stderr),
        "stderr_sha256": _sha(stderr),
        "overflowed_stream": None,
        "process_population_zero_proven": True,
        "credentials_revoked": True,
        "egress_revoked": True,
        "timed_out": False,
        "timeout_seconds": 2400,
        "stdout_requested_limit_bytes": execution.BACKEND_STDOUT_LIMIT_BYTES,
        "stderr_requested_limit_bytes": execution.BACKEND_STDERR_LIMIT_BYTES,
        "stdout_effective_limit_bytes": execution.BACKEND_STDOUT_LIMIT_BYTES,
        "stderr_effective_limit_bytes": execution.BACKEND_STDERR_LIMIT_BYTES,
    })
    exited = execution.parse_native_exited_receipt(
        exited_raw, started=started, wait_request_sha256=_sha(wait_request),
    )
    output_request = execution._output_request(
        exited, stream="stdout", offset=0,
        max_bytes=execution.NATIVE_OUTPUT_CHUNK_MAX_BYTES,
    )
    output_raw = _raw({
        "schema": execution.NATIVE_OUTPUT_RECEIPT_SCHEMA,
        "status": "OUTPUT_CHUNK",
        "operation_key_sha256": operation_key,
        "output_request_sha256": _sha(output_request),
        "exited_receipt_sha256": exited.sha256,
        "stream": "stdout",
        "offset": 0,
        "length": len(stdout),
        "eof": True,
        "chunk_base64": base64.b64encode(stdout).decode("ascii"),
        "chunk_sha256": _sha(stdout),
        "full_stream_sha256": _sha(stdout),
    })
    output = execution.parse_native_output_receipt(
        output_raw, exited=exited, output_request=output_request,
    )
    extinguish_request = execution._extinguish_request(
        prepared,
        latest_lifecycle_receipt_sha256=exited.sha256,
        reason_code="NORMAL_SCOPE_CLOSE",
    )
    revoked_raw = _raw({
        "schema": execution.NATIVE_REVOKED_RECEIPT_SCHEMA,
        "status": "REVOKED",
        "disposition": "REVOKED_NEW",
        "operation_key_sha256": operation_key,
        "extinguish_request_sha256": _sha(extinguish_request),
        "prepared_receipt_sha256": prepared.sha256,
        "latest_lifecycle_receipt_sha256": exited.sha256,
        "process_identity_sha256": process_identity_sha,
        "reason_code": "NORMAL_SCOPE_CLOSE",
        "process_population_zero_proven": True,
        "credentials_revoked": True,
        "egress_revoked": True,
        "output_retention_disposition": "DISCARDED",
    })
    revoked = execution.parse_native_revoked_receipt(
        revoked_raw,
        prepared=prepared,
        extinguish_request=extinguish_request,
        expected_process_identity_sha256=process_identity_sha,
    )
    close_request = execution._close_request(
        prepared, terminal_receipt_sha256=revoked.sha256,
    )
    finished_raw = _raw({
        "schema": execution.NATIVE_FINISHED_RECEIPT_SCHEMA,
        "status": "FINISHED",
        "disposition": "FINISHED_NEW",
        "operation_key_sha256": operation_key,
        "close_request_sha256": _sha(close_request),
        "terminal_receipt_sha256": revoked.sha256,
        "retained_descriptors_closed": True,
        "retained_output_closed": True,
    })
    finished = execution.parse_native_finished_receipt(
        finished_raw, prepared=prepared, close_request=close_request,
    )
    return locals()


def test_native_semantic_transcript_is_canonical_operation_bound_and_secret_free() -> None:
    item = _semantic_transcript()
    for name in (
        "prepare_request", "start_request", "wait_request",
        "output_request", "extinguish_request", "close_request",
    ):
        request = item[name]
        assert type(request) is bytes
        assert request.endswith(b"\n")
        assert not request.endswith(b"\n\n")
        assert execution.canonical_json_bytes(json.loads(request)) + b"\n" == request
    prepare = json.loads(item["prepare_request"])
    assert prepare["operation_key_sha256"] == execution._operation_key(item["envelope"])
    assert item["prepared"].operation_key_sha256 == prepare["operation_key_sha256"]
    assert item["started"].process_identity.pid == 4242
    assert item["exited"].returncode == 0
    assert item["output"].chunk == b"audit-result\n"
    assert item["revoked"].reason_code == "NORMAL_SCOPE_CLOSE"
    assert item["finished"].terminal_receipt_sha256 == item["revoked"].sha256
    assert b"secret-value-must-be-digested" not in item["prepare_request"]
    assert b"secret-argument-must-be-digested" not in item["prepare_request"]
    wait = json.loads(item["wait_request"])
    assert set(wait) == execution._WAIT_REQUEST_FIELDS
    assert "stdout" not in json.loads(item["exited_raw"])
    assert "stderr" not in json.loads(item["exited_raw"])


def test_native_operation_request_parser_rejects_missing_or_extra_lf() -> None:
    canonical = execution._canonical_operation_request_bytes({"value": 1})
    assert execution._strict_operation_request(
        canonical, label="test request"
    ) == {"value": 1}
    for malformed in (canonical[:-1], canonical + b"\n", canonical + b" "):
        with pytest.raises(
            execution.PosixBackendExecutionError,
            match="NATIVE_REQUEST_CANONICAL|RECEIPT_CANONICAL",
        ):
            execution._strict_operation_request(
                malformed, label="test request"
            )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("timeout_seconds", 2399),
        ("stdout_requested_limit_bytes", 4096),
        ("stderr_requested_limit_bytes", 4096),
        ("stdout_effective_limit_bytes", 4096),
        ("stderr_effective_limit_bytes", 4096),
    ],
)
def test_prepared_receipt_rejects_timeout_and_stream_limit_drift(
    field: str, value: int,
) -> None:
    transcript = _semantic_transcript()
    changed = json.loads(transcript["prepared_raw"])
    changed[field] = value
    with pytest.raises(execution.PosixBackendExecutionError, match="PREPARED_LIMIT"):
        execution.parse_native_prepared_receipt(
            _raw(changed),
            operation_key_sha256=transcript["operation_key"],
            prepare_request_sha256=_sha(transcript["prepare_request"]),
            execution_envelope_sha256=_sha(transcript["envelope"]),
            timeout_seconds=2400,
            stdout_limit_bytes=execution.BACKEND_STDOUT_LIMIT_BYTES,
            stderr_limit_bytes=execution.BACKEND_STDERR_LIMIT_BYTES,
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("timeout_seconds", True),
        ("stdout_limit_bytes", True),
        ("stderr_limit_bytes", False),
    ],
)
def test_prepared_parser_rejects_boolean_expected_limits(
    field: str, value: bool,
) -> None:
    transcript = _semantic_transcript()
    expected = {
        "timeout_seconds": 2400,
        "stdout_limit_bytes": execution.BACKEND_STDOUT_LIMIT_BYTES,
        "stderr_limit_bytes": execution.BACKEND_STDERR_LIMIT_BYTES,
    }
    expected[field] = value
    with pytest.raises(execution.PosixBackendExecutionError):
        execution.parse_native_prepared_receipt(
            transcript["prepared_raw"],
            operation_key_sha256=transcript["operation_key"],
            prepare_request_sha256=_sha(transcript["prepare_request"]),
            execution_envelope_sha256=_sha(transcript["envelope"]),
            **expected,
        )


@pytest.mark.parametrize(
    "field",
    [
        "timeout_seconds",
        "stdout_requested_limit_bytes",
        "stderr_requested_limit_bytes",
        "stdout_effective_limit_bytes",
        "stderr_effective_limit_bytes",
    ],
)
def test_exited_receipt_rejects_authenticated_limit_drift(field: str) -> None:
    transcript = _semantic_transcript()
    changed = json.loads(transcript["exited_raw"])
    changed[field] -= 1
    with pytest.raises(execution.PosixBackendExecutionError, match="EXITED_LIMIT"):
        execution.parse_native_exited_receipt(
            _raw(changed),
            started=transcript["started"],
            wait_request_sha256=_sha(transcript["wait_request"]),
        )


def test_timed_out_exit_is_terminal_native_deadline_evidence() -> None:
    transcript = _semantic_transcript()
    changed = json.loads(transcript["exited_raw"])
    changed.update({
        "status": "TIMED_OUT_REVOKED",
        "exit_kind": "TIMEOUT",
        "returncode": None,
        "signal": None,
        "overflowed_stream": None,
        "timed_out": True,
    })
    timed_out = execution.parse_native_exited_receipt(
        _raw(changed),
        started=transcript["started"],
        wait_request_sha256=_sha(transcript["wait_request"]),
    )
    assert timed_out.status == "TIMED_OUT_REVOKED"
    assert timed_out.exit_kind == "TIMEOUT"
    assert timed_out.timed_out is True
    assert timed_out.timeout_seconds == 2400
    assert timed_out.stdout_requested_limit_bytes == (
        execution.BACKEND_STDOUT_LIMIT_BYTES
    )
    assert timed_out.stderr_effective_limit_bytes == (
        execution.BACKEND_STDERR_LIMIT_BYTES
    )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("status", "EXITED"),
        ("exit_kind", "EXIT_CODE"),
        ("returncode", 0),
        ("signal", 9),
        ("overflowed_stream", "stdout"),
        ("timed_out", False),
    ],
)
def test_timed_out_exit_rejects_conflicting_metadata(
    field: str, value: object,
) -> None:
    transcript = _semantic_transcript()
    changed = json.loads(transcript["exited_raw"])
    changed.update({
        "status": "TIMED_OUT_REVOKED",
        "exit_kind": "TIMEOUT",
        "returncode": None,
        "signal": None,
        "overflowed_stream": None,
        "timed_out": True,
        field: value,
    })
    with pytest.raises(execution.PosixBackendExecutionError):
        execution.parse_native_exited_receipt(
            _raw(changed),
            started=transcript["started"],
            wait_request_sha256=_sha(transcript["wait_request"]),
        )


@pytest.mark.parametrize(
    ("receipt_name", "parser_name", "kwargs", "field"),
    [
        (
            "prepared_raw", "parse_native_prepared_receipt",
            lambda t: {
                "operation_key_sha256": t["operation_key"],
                "prepare_request_sha256": _sha(t["prepare_request"]),
                "execution_envelope_sha256": _sha(t["envelope"]),
                "timeout_seconds": 2400,
                "stdout_limit_bytes": execution.BACKEND_STDOUT_LIMIT_BYTES,
                "stderr_limit_bytes": execution.BACKEND_STDERR_LIMIT_BYTES,
            }, "operation_key_sha256",
        ),
        (
            "started_raw", "parse_native_started_receipt",
            lambda t: {
                "prepared": t["prepared"],
                "start_request_sha256": _sha(t["start_request"]),
            }, "prepared_receipt_sha256",
        ),
        (
            "exited_raw", "parse_native_exited_receipt",
            lambda t: {
                "started": t["started"],
                "wait_request_sha256": _sha(t["wait_request"]),
            }, "process_identity_sha256",
        ),
        (
            "output_raw", "parse_native_output_receipt",
            lambda t: {
                "exited": t["exited"], "output_request": t["output_request"],
            }, "output_request_sha256",
        ),
        (
            "revoked_raw", "parse_native_revoked_receipt",
            lambda t: {
                "prepared": t["prepared"],
                "extinguish_request": t["extinguish_request"],
                "expected_process_identity_sha256": t["process_identity_sha"],
            }, "latest_lifecycle_receipt_sha256",
        ),
        (
            "finished_raw", "parse_native_finished_receipt",
            lambda t: {
                "prepared": t["prepared"], "close_request": t["close_request"],
            }, "terminal_receipt_sha256",
        ),
    ],
)
def test_every_lifecycle_receipt_rejects_digest_substitution(
    receipt_name: str, parser_name: str, kwargs, field: str,
) -> None:
    transcript = _semantic_transcript()
    changed = json.loads(transcript[receipt_name])
    changed[field] = "f" * 64
    parser = getattr(execution, parser_name)
    with pytest.raises(execution.PosixBackendExecutionError, match="BINDING|IDENTITY"):
        parser(_raw(changed), **kwargs(transcript))


def test_output_chunk_rejects_range_digest_encoding_and_eof_mutations() -> None:
    transcript = _semantic_transcript()
    original = json.loads(transcript["output_raw"])
    mutations = (
        {**original, "length": original["length"] + 1},
        {**original, "chunk_sha256": "f" * 64},
        {**original, "chunk_base64": "***"},
        {**original, "eof": False},
        {**original, "full_stream_sha256": "f" * 64},
    )
    for changed in mutations:
        with pytest.raises(execution.PosixBackendExecutionError):
            execution.parse_native_output_receipt(
                _raw(changed),
                exited=transcript["exited"],
                output_request=transcript["output_request"],
            )
    with pytest.raises(execution.PosixBackendExecutionError, match="CHUNK"):
        execution._output_request(
            transcript["exited"], stream="stdout", offset=0,
            max_bytes=execution.NATIVE_OUTPUT_CHUNK_MAX_BYTES + 1,
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("operation_key_sha256", "f" * 64),
        ("exited_receipt_sha256", "f" * 64),
        ("stream", "other"),
        ("offset", 1_000_000),
        ("max_bytes", 0),
        ("max_bytes", execution.NATIVE_OUTPUT_CHUNK_MAX_BYTES + 1),
    ],
)
def test_output_parser_rejects_mutated_request_denominator(
    field: str, value: object,
) -> None:
    transcript = _semantic_transcript()
    changed = json.loads(transcript["output_request"])
    changed[field] = value
    with pytest.raises(execution.PosixBackendExecutionError):
        execution.parse_native_output_receipt(
            transcript["output_raw"],
            exited=transcript["exited"],
            output_request=_raw(changed),
        )


def test_overflow_is_exact_cap_plus_one_terminal_and_unreadable() -> None:
    transcript = _semantic_transcript()
    changed = json.loads(transcript["exited_raw"])
    changed.update({
        "status": "OUTPUT_OVERFLOW_REVOKED",
        "exit_kind": "OUTPUT_OVERFLOW",
        "returncode": None,
        "timed_out": False,
        "overflowed_stream": "stdout",
        "stdout_size_bytes": execution.BACKEND_STDOUT_LIMIT_BYTES + 1,
    })
    overflow = execution.parse_native_exited_receipt(
        _raw(changed),
        started=transcript["started"],
        wait_request_sha256=_sha(transcript["wait_request"]),
    )
    wrapper = execution._new_native_backend_execution(object(), transcript["prepared"])
    object.__setattr__(wrapper, "_PosixBackendExecution__started", transcript["started"])
    object.__setattr__(wrapper, "_PosixBackendExecution__exited", overflow)
    with pytest.raises(execution.PosixBackendExecutionError, match="OVERFLOW"):
        wrapper.read_output_or_recover(stream="stdout", offset=0)


def test_overflow_rejects_a_second_stream_over_its_effective_limit() -> None:
    transcript = _semantic_transcript()
    changed = json.loads(transcript["exited_raw"])
    changed.update({
        "status": "OUTPUT_OVERFLOW_REVOKED",
        "exit_kind": "OUTPUT_OVERFLOW",
        "returncode": None,
        "timed_out": False,
        "overflowed_stream": "stdout",
        "stdout_size_bytes": execution.BACKEND_STDOUT_LIMIT_BYTES + 1,
        "stderr_size_bytes": execution.BACKEND_STDERR_LIMIT_BYTES + 1,
    })
    with pytest.raises(execution.PosixBackendExecutionError, match="OVERFLOW"):
        execution.parse_native_exited_receipt(
            _raw(changed),
            started=transcript["started"],
            wait_request_sha256=_sha(transcript["wait_request"]),
        )


def test_operation_wrapper_retains_shared_native_authority_without_exposing_it() -> None:
    class Native:
        pass

    native = Native()
    reference = weakref.ref(native)
    transcript = _semantic_transcript()
    wrapper = execution._new_native_backend_execution(native, transcript["prepared"])
    del native
    gc.collect()
    assert reference() is not None
    assert "Native" not in repr(wrapper)
    assert not hasattr(wrapper, "native_authority")


def test_wrapper_replays_exact_native_bytes_and_closes_per_operation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transcript = _semantic_transcript()
    responses = {
        "start_or_recover": transcript["started_raw"],
        "wait_or_recover": transcript["exited_raw"],
        "read_output_or_recover": transcript["output_raw"],
        "extinguish_or_recover": transcript["revoked_raw"],
        "close_operation": transcript["finished_raw"],
    }
    calls: list[tuple[str, bytes]] = []

    def call(_self, method: str, request: bytes) -> bytes:
        calls.append((method, request))
        return responses[method]

    monkeypatch.setattr(execution.PosixBackendExecution, "_native_call", call)
    wrapper = execution._new_native_backend_execution(object(), transcript["prepared"])
    assert wrapper.state == "PREPARED"
    assert wrapper.start_or_recover() is wrapper.start_or_recover()
    assert wrapper.wait_or_recover() is wrapper.wait_or_recover()
    assert wrapper.read_output_or_recover(stream="stdout", offset=0).chunk == b"audit-result\n"
    assert wrapper.read_output_or_recover(stream="stdout", offset=0).chunk == b"audit-result\n"
    assert wrapper.extinguish_or_recover(reason_code="NORMAL_SCOPE_CLOSE") is (
        wrapper.extinguish_or_recover(reason_code="NORMAL_SCOPE_CLOSE")
    )
    assert wrapper.close_operation() is wrapper.close_operation()
    assert wrapper.state == "FINISHED"
    for method in responses:
        matching = [request for name, request in calls if name == method]
        assert len(matching) == 2
        assert matching[0] == matching[1]
    with pytest.raises(execution.PosixBackendExecutionError, match="terminal operation"):
        wrapper.start_or_recover()


def test_blocking_wait_does_not_prevent_concurrent_native_extinction(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transcript = _semantic_transcript()
    wait_entered = threading.Event()
    release_wait = threading.Event()

    def call(_self, method: str, request: bytes) -> bytes:
        if method == "wait_or_recover":
            wait_entered.set()
            assert release_wait.wait(timeout=2)
            return transcript["exited_raw"]
        if method == "extinguish_or_recover":
            release_wait.set()
            requested = json.loads(request)
            return _raw({
                "schema": execution.NATIVE_REVOKED_RECEIPT_SCHEMA,
                "status": "REVOKED",
                "disposition": "REVOKED_NEW",
                "operation_key_sha256": (
                    transcript["prepared"].operation_key_sha256
                ),
                "extinguish_request_sha256": _sha(request),
                "prepared_receipt_sha256": transcript["prepared"].sha256,
                "latest_lifecycle_receipt_sha256": requested[
                    "latest_lifecycle_receipt_sha256"
                ],
                "process_identity_sha256": (
                    transcript["started"].process_identity.sha256
                ),
                "reason_code": "NORMAL_SCOPE_CLOSE",
                "process_population_zero_proven": True,
                "credentials_revoked": True,
                "egress_revoked": True,
                "output_retention_disposition": "DISCARDED",
            })
        raise AssertionError(method)

    monkeypatch.setattr(execution.PosixBackendExecution, "_native_call", call)
    wrapper = execution._new_native_backend_execution(
        object(), transcript["prepared"],
    )
    object.__setattr__(
        wrapper,
        "_PosixBackendExecution__started",
        transcript["started"],
    )
    wait_errors: list[BaseException] = []

    def wait() -> None:
        try:
            wrapper.wait_or_recover()
        except BaseException as exc:
            wait_errors.append(exc)

    thread = threading.Thread(target=wait)
    thread.start()
    assert wait_entered.wait(timeout=2)
    revoked = wrapper.extinguish_or_recover(reason_code="NORMAL_SCOPE_CLOSE")
    thread.join(timeout=2)
    assert not thread.is_alive()
    assert revoked.reason_code == "NORMAL_SCOPE_CLOSE"
    assert len(wait_errors) == 1
    assert isinstance(wait_errors[0], execution.PosixBackendExecutionError)
    assert "while native wait was in flight" in str(wait_errors[0])


def test_strict_native_parser_rejects_duplicate_keys_and_noncanonical_json() -> None:
    for raw in (
        b'{"a":1,"a":1}',
        b'{"a": 1}',
        b'{"value":NaN}',
        b'\xff',
    ):
        with pytest.raises(execution.PosixBackendExecutionError):
            execution._strict_json(raw, label="mutation")
