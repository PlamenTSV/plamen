"""Fake-only Apple Container fuzz consumer tests; never mutates a provider."""
from __future__ import annotations

from dataclasses import replace
import hashlib
import json
from pathlib import Path

import pytest

import apple_container_provider as A
import apple_supervisor_adapter as M
import fuzz_workspace_authority as F


def _d(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


def _preflight(*, version: str = "1.4.0") -> A.PreflightReceipt:
    return A.PreflightReceipt(
        executable_path=str(A.DEFAULT_EXECUTABLE),
        executable_sha256=_d("compatible-latest-cli"),
        cli_version=version, cli_build="release", cli_commit="c" * 40,
        cli_signing_identifier=A.SUPPORTED_CLI_SIGNING_IDENTIFIER,
        cli_signing_team_id=A.SUPPORTED_RUNTIME_SIGNING_TEAM_ID,
        server_executable_path=str(A.DEFAULT_SERVER_EXECUTABLE),
        server_executable_sha256=_d("compatible-latest-server"),
        server_version=version, server_build="release", server_commit="c" * 40,
        server_signing_identifier=A.SUPPORTED_SERVER_SIGNING_IDENTIFIER,
        server_signing_team_id=A.SUPPORTED_RUNTIME_SIGNING_TEAM_ID,
        containerization_version="0.43.0", containerization_build="release",
        containerization_commit="e" * 40,
        containerization_binary_sha256=_d("containerization"),
        init_image_reference=A.SUPPORTED_INIT_IMAGE_REFERENCE,
        init_image_index_digest=A.SUPPORTED_INIT_IMAGE_INDEX_DIGEST,
        init_image_manifest_digest=A.SUPPORTED_INIT_IMAGE_MANIFEST_DIGEST,
        init_image_postcondition_sha256=_d("init-postcondition"),
        plugin_root=str(A.DEFAULT_PLUGIN_ROOT),
        core_images_plugin_sha256=A.SUPPORTED_CORE_IMAGES_PLUGIN_SHA256,
        network_vmnet_plugin_sha256=A.SUPPORTED_NETWORK_VMNET_PLUGIN_SHA256,
        runtime_linux_plugin_sha256=A.SUPPORTED_RUNTIME_LINUX_PLUGIN_SHA256,
        machine_apiserver_plugin_sha256=
            A.SUPPORTED_MACHINE_APISERVER_PLUGIN_SHA256,
        plugin_signing_team_id=A.SUPPORTED_RUNTIME_SIGNING_TEAM_ID,
        plugin_closure_sha256=A.SUPPORTED_PLUGIN_CLOSURE_SHA256,
        package_identifier=A.SUPPORTED_PACKAGE_IDENTIFIER,
        package_version=version,
        package_install_location=A.SUPPORTED_PACKAGE_INSTALL_LOCATION,
        package_authorization=A.SUPPORTED_PACKAGE_AUTHORIZATION,
        package_signing_team_id=A.SUPPORTED_INSTALLER_TEAM_ID,
        package_receipt_sha256=_d("package-receipt"),
        package_installer_leaf_sha256=A.SUPPORTED_INSTALLER_LEAF_SHA256,
        package_signed=True, package_notarized=True, package_timestamped=True,
        kernel_archive_url=A.SUPPORTED_KERNEL_ARCHIVE_URL,
        kernel_archive_sha256=A.SUPPORTED_KERNEL_ARCHIVE_SHA256,
        kernel_archive_size=A.SUPPORTED_KERNEL_ARCHIVE_SIZE,
        kernel_binary_member=A.SUPPORTED_KERNEL_BINARY_MEMBER,
        kernel_binary_sha256=A.SUPPORTED_KERNEL_BINARY_SHA256,
        implicit_kernel_install_disabled=True,
        host_architecture="arm64", host_os_major=26,
    )


def _project(tmp_path: Path) -> Path:
    root = tmp_path / "project"
    root.mkdir()
    (root / "foundry.toml").write_text("[profile.default]\n", encoding="utf-8")
    (root / "Contract.sol").write_text(
        "pragma solidity ^0.8.20; contract Contract {}\n", encoding="utf-8"
    )
    return root


def _secure(
    authority: dict[str, object], preflight: A.PreflightReceipt,
    *, tool: str,
) -> dict[str, object]:
    preflight_sha = A.apple_container_preflight_sha256(preflight)
    attempt_id = "dodo-fuzz-001"
    phase_io = _d("phase-io")
    guest_sha = _d(f"guest-{tool}")
    operation_key = A.apple_fuzz_operation_key(
        str(authority["payload_digest"]), phase_io, attempt_id, guest_sha
    )
    receipt: dict[str, object] = {
        "schema_version": F.SECURE_LAUNCHER_SCHEMA,
        "status": "ENFORCED",
        "authority_digest": authority["payload_digest"],
        "workspace_root": authority["workspace_root"],
        "filesystem_policy": "READONLY_INPUTS_EXPLICIT_WRITE_LANES",
        "process_tree_policy": F.APPLE_CONTAINER_PROCESS_POLICY,
        "network_policy": "DENY",
        "phase_io_binding_digest": phase_io,
        "apple_container_preflight_sha256": preflight_sha,
        "apple_container_provider_provenance_sha256": preflight_sha,
        "apple_container_cli_executable_sha256": preflight.executable_sha256,
        "apple_container_id": A.derive_apple_fuzz_container_id(
            str(authority["payload_digest"]), operation_key
        ),
        "apple_container_attempt_id": attempt_id,
        "apple_container_spec_sha256": _d("container-spec"),
        "apple_container_launch_policy_sha256": _d("launch-policy"),
        "guest_executable": f"/opt/plamen/bin/{tool}",
        "guest_executable_sha256": guest_sha,
        "guest_cwd": "/workspace/scratch/fuzz/active",
        "guest_environment": ("PATH=/opt/plamen/bin:/usr/bin",),
        "rosetta_required": False,
    }
    receipt["guest_environment"] = list(receipt["guest_environment"])
    receipt["payload_digest"] = F.payload_digest(receipt)
    return receipt


def _forge(value: object, **changes: object) -> object:
    forged = object.__new__(type(value))
    for field in value.__dataclass_fields__:  # type: ignore[attr-defined]
        object.__setattr__(forged, field, changes.get(field, getattr(value, field)))
    return forged


def _enable_test_only_atomic_service(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Keep fake terminal-validation tests below a production-RED gate."""

    monkeypatch.setattr(M, "apple_fuzz_service_admission_status", lambda: {
        "schema": M.APPLE_FUZZ_SERVICE_ABI_SCHEMA,
        "status": "READY",
        "issues": [],
    })
    monkeypatch.setattr(
        M,
        "require_apple_fuzz_service_admission",
        lambda value, receipt: value,
    )


def _bundle(
    request: A.AppleFuzzExecutionRequest, *,
    wait_changes: dict[str, object] | None = None,
    delete_changes: dict[str, object] | None = None,
) -> A.AppleNativeFuzzExecutionBundle:
    launch_request_sha256 = _d("native-launch-request")
    start_receipt_sha256 = _d("native-start-receipt")
    native_spec_sha256 = _d("native-spec")
    native_mount_roster_sha256 = _d("native-mount-roster")
    launch = A.AppleNativeFuzzLaunchReceipt(
        request_sha256=request.request_sha256,
        container_id=request.container_id, attempt_id=request.attempt_id,
        spec_sha256=native_spec_sha256,
        launch_policy_sha256=request.launch_policy_sha256,
        launch_request_sha256=launch_request_sha256,
        created_receipt_sha256=_d("native-created-receipt"),
        start_receipt_sha256=start_receipt_sha256,
        driver_argv_sha256=_d("native-argv"),
        driver_environment_sha256=_d("native-environment"),
        driver_cwd_sha256=_d("native-cwd"),
        driver_stdin_sha256=_d("native-stdin"),
        pass_fd_roster_sha256=_d("native-pass-fds"),
        mount_roster_sha256=native_mount_roster_sha256,
        start_operation_nonce=_d("native-start-nonce"),
        native_process_id=101,
        native_process_handle_sha256=_d("native-process-handle"),
        start_monotonic_ms=1_000,
        provider_preflight_sha256=request.provider_preflight_sha256,
        provider_provenance_sha256=request.provider_provenance_sha256,
        cli_executable_sha256=request.cli_executable_sha256,
        guest_executable_sha256=request.guest_executable_sha256,
        rosetta_required=request.rosetta_required,
    )
    stdout = b"campaign completed\n"
    stderr = b""
    terminal = A.AppleNativeFuzzTerminalReceipt(
        request_sha256=request.request_sha256,
        container_id=request.container_id, attempt_id=request.attempt_id,
        spec_sha256=native_spec_sha256,
        launch_request_sha256=launch_request_sha256,
        start_receipt_sha256=start_receipt_sha256,
        terminal_receipt_sha256=_d("native-terminal-receipt"),
        start_operation_nonce=launch.start_operation_nonce,
        wait_operation_nonce=_d("native-wait-nonce"),
        revoke_operation_nonce=_d("native-revoke-nonce"),
        native_process_id=launch.native_process_id,
        native_process_handle_sha256=launch.native_process_handle_sha256,
        exit_code=0, stdout_sha256=hashlib.sha256(stdout).hexdigest(),
        stderr_sha256=hashlib.sha256(stderr).hexdigest(),
        stdout_retained_sha256=hashlib.sha256(stdout).hexdigest(),
        stderr_retained_sha256=hashlib.sha256(stderr).hexdigest(),
        stdout_observed_bytes=len(stdout), stderr_observed_bytes=0,
        stdout_retained_bytes=len(stdout), stderr_retained_bytes=0,
        stdout_truncated=False, stderr_truncated=False,
        start_monotonic_ms=launch.start_monotonic_ms,
        end_monotonic_ms=2_000,
        native_process_extinction_sha256=_d("native-extinction"),
        cleanup_sha256=_d("cleanup"), stop_argv_sha256=_d("stop-argv"),
        stop_stdout_sha256=_d("stop-stdout"),
        stop_stderr_sha256=_d("stop-stderr"),
        stopped_observation_sha256=_d("stopped-observation"),
        guest_population_extinction_sha256=_d("guest-population-extinction"),
        descendants_extinct=True, guest_process_extinct=True,
        backend_egress_revoked=True, stop_control_process_reaped=True,
        stop_control_process_group_extinct=True, guest_population_zero=True,
        container_vm_stopped=True,
        provider_preflight_sha256=request.provider_preflight_sha256,
        provider_provenance_sha256=request.provider_provenance_sha256,
        cli_executable_sha256=request.cli_executable_sha256,
        guest_executable_sha256=request.guest_executable_sha256,
        rosetta_required=request.rosetta_required,
    )
    if wait_changes:
        terminal = _forge(terminal, **wait_changes)  # type: ignore[assignment]
    deleted = A.AppleNativeFuzzDeleteReceipt(
        request_sha256=request.request_sha256,
        container_id=request.container_id, spec_sha256=native_spec_sha256,
        terminal_receipt_sha256=terminal.terminal_receipt_sha256,
        delete_receipt_sha256=_d("native-delete-receipt"),
        cleanup_sha256=_d("native-delete-cleanup"),
        absence_sha256=_d("native-absence"),
        descendants_extinct=True, guest_process_extinct=True,
        backend_egress_revoked=True, absent=True,
        provider_preflight_sha256=request.provider_preflight_sha256,
        guest_executable_sha256=request.guest_executable_sha256,
    )
    if delete_changes:
        deleted = _forge(deleted, **delete_changes)  # type: ignore[assignment]
    return A.AppleNativeFuzzExecutionBundle(
        request_sha256=request.request_sha256, launch=launch,
        terminal=terminal, deleted=deleted,
        lifecycle_sha256=_d("native-lifecycle"),
        native_mount_roster_sha256=native_mount_roster_sha256,
        native_provider_admission_sha256=_d("native-provider-admission"),
        native_provider_provenance_sha256=
            _d("native-provider-provenance"),
        native_spec_sha256=native_spec_sha256,
        stdout=stdout, stderr=stderr,
    )


def _prepared(
    tmp_path: Path, *, role: str, command: list[str], harness: str,
) -> tuple[dict[str, object], dict[str, object], A.PreflightReceipt]:
    root = _project(tmp_path)
    scratchpad = root / ".scratchpad"
    scratchpad.mkdir()
    authority = F.materialize_fuzz_workspace(
        scratchpad=scratchpad, build_root=root, project_root=root,
        job_id=role.replace("_", "-"), language="evm", role=role,
        run_id="RUN-APPLE-FUZZ", source_snapshot_digest=_d("snapshot"),
        allowed_tools=(command[0],),
    )
    generated = Path(str(authority["active_root"])) / harness
    generated.parent.mkdir(parents=True, exist_ok=True)
    generated.write_text("contract GeneratedInvariant {}\n", encoding="utf-8")
    preflight = _preflight()
    contract = F.prepare_fuzz_campaign_contract(
        Path(str(authority["authority_path"])), argv=command,
        timeout_seconds=600, cwd_relative=".", selected_harnesses=[harness],
        assertion_ids=["INV-001"], expected_case_count=256,
        secure_launcher_receipt=_secure(authority, preflight, tool=command[0]),
    )
    assert contract["status"] == "READY"
    return authority, contract, preflight


@pytest.mark.parametrize(("role", "command", "harness"), [
    (
        "invariant_fuzz",
        ["forge", "test", "--match-contract", "GeneratedInvariant",
         "--invariant-runs", "256"],
        ".plamen-generated/GeneratedInvariant.t.sol",
    ),
    (
        "medusa_fuzz", ["medusa", "fuzz", "--test-limit", "256"],
        ".plamen-generated/MedusaHarness.sol",
    ),
])
def test_forge_and_medusa_publish_measured_apple_vm_authority(
    tmp_path: Path, role: str, command: list[str], harness: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _enable_test_only_atomic_service(monkeypatch)
    authority, contract, preflight = _prepared(
        tmp_path, role=role, command=command, harness=harness
    )
    seen: list[A.AppleFuzzExecutionRequest] = []

    def execute(
        request: A.AppleFuzzExecutionRequest,
    ) -> A.AppleNativeFuzzExecutionBundle:
        seen.append(request)
        return _bundle(request)

    assert F.run_prepared_apple_container_campaign(
        Path(str(authority["authority_path"])),
        Path(str(contract["contract_path"])), apple_preflight=preflight,
        execute_lifecycle=execute,
    ) == 0
    assert len(seen) == 1
    assert seen[0].guest_argv[0] == f"/opt/plamen/bin/{command[0]}"
    assert A._HEX64.fullmatch(seen[0].operation_key_sha256) is not None
    assert seen[0].container_id == A.derive_apple_fuzz_container_id(
        seen[0].authority_digest, seen[0].operation_key_sha256
    )
    assert len(seen[0].container_id) == 39
    with pytest.raises(A.AppleContainerConfigurationError):
        replace(seen[0], container_id="plamen-dodo-fuzz-001")
    result = F.finalize_fuzz_workspace(Path(str(authority["authority_path"])))
    assert result["status"] == "MEASURED"
    assert result["campaign_execution_status"] == "EXECUTED_SUCCESS"
    assert result["proof_authority"] == "APPLE_CONTAINER_V2_TERMINAL_DELETE"
    assert F.validate_fuzz_workspace_result(
        Path(str(authority["authority_path"]))
    ) == []
    scratchpad = Path(str(authority["scratchpad_root"]))
    output = f"{role}.md"
    (scratchpad / output).write_text("# authenticated fuzz result\n")
    workspace_index = F.write_fuzz_workspace_index(
        scratchpad,
        [{
            "agent_id": authority["job_id"], "role": role, "output": output,
            "fuzz_authority_path": authority["authority_path"],
            "fuzz_workspace_status": "READY",
        }],
        run_id="RUN-APPLE-FUZZ", pipeline="sc", mode="thorough",
        ecosystem="evm", backend="codex",
    )
    assert workspace_index["rows"][0]["status"] == "READY"
    result_index = F.write_fuzz_workspace_result_index(
        scratchpad / F.WORKSPACE_INDEX_FILE
    )
    assert result_index["rows"][0]["status"] == "MEASURED"
    assert result_index["rows"][0]["proof_authority"] == (
        "APPLE_CONTAINER_V2_TERMINAL_DELETE"
    )
    assert F.validate_fuzz_workspace_result_index(
        scratchpad / F.RESULT_INDEX_FILE
    ) == []


@pytest.mark.parametrize(("field", "value"), [
    ("stop_argv_sha256", "x"),
    ("stop_stdout_sha256", "x"),
    ("stop_stderr_sha256", "x"),
    ("stopped_observation_sha256", "x"),
    ("guest_population_extinction_sha256", "x"),
    ("stop_control_process_reaped", False),
    ("stop_control_process_group_extinct", False),
    ("guest_population_zero", False),
    ("container_vm_stopped", False),
])
def test_each_missing_or_mismatched_stop_vm_proof_fails_closed(
    tmp_path: Path, field: str, value: object,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _enable_test_only_atomic_service(monkeypatch)
    authority, contract, preflight = _prepared(
        tmp_path, role="invariant_fuzz",
        command=["forge", "test", "--match-contract", "GeneratedInvariant"],
        harness=".plamen-generated/GeneratedInvariant.t.sol",
    )
    assert F.run_prepared_apple_container_campaign(
        Path(str(authority["authority_path"])),
        Path(str(contract["contract_path"])), apple_preflight=preflight,
        execute_lifecycle=lambda request: _bundle(
            request, wait_changes={field: value}
        ),
    ) == 125
    result = F.finalize_fuzz_workspace(Path(str(authority["authority_path"])))
    assert result["status"] == "UNSCORED"
    assert result["proof_authority"] == "NONE"
    assert "APPLE_CONTAINER_PROOF_INVALID" in {
        row["code"] for row in result["issues"]
    }


def test_delete_absence_and_compatible_admission_are_mandatory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _enable_test_only_atomic_service(monkeypatch)
    authority, contract, preflight = _prepared(
        tmp_path, role="medusa_fuzz",
        command=["medusa", "fuzz", "--test-limit", "256"],
        harness=".plamen-generated/MedusaHarness.sol",
    )
    assert preflight.cli_version == "1.4.0"
    assert F.run_prepared_apple_container_campaign(
        Path(str(authority["authority_path"])),
        Path(str(contract["contract_path"])), apple_preflight=preflight,
        execute_lifecycle=lambda request: _bundle(
            request, delete_changes={"absent": False}
        ),
    ) == 125
    command_dir = Path(str(authority["runtime_root"])) / "commands"
    assert list(command_dir.glob("*-command.json")) == []
    debt = json.loads(Path(str(authority["debt_path"])).read_text())
    assert {row["code"] for row in debt["issues"]} == {
        "APPLE_CONTAINER_PROOF_INVALID"
    }


def test_admission_drift_rejects_before_lifecycle_callback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _enable_test_only_atomic_service(monkeypatch)
    authority, contract, preflight = _prepared(
        tmp_path, role="invariant_fuzz",
        command=["forge", "test", "--match-contract", "GeneratedInvariant"],
        harness=".plamen-generated/GeneratedInvariant.t.sol",
    )
    called = False

    def forbidden(_request: object) -> object:
        nonlocal called
        called = True
        raise AssertionError("drifted admission reached provider mutation")

    drifted = replace(preflight, server_version="1.4.1")
    assert F.run_prepared_apple_container_campaign(
        Path(str(authority["authority_path"])),
        Path(str(contract["contract_path"])), apple_preflight=drifted,
        execute_lifecycle=forbidden,
    ) == 125
    assert called is False


def test_macos_capability_stays_red_without_atomic_native_admission(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    authority, contract, preflight = _prepared(
        tmp_path, role="invariant_fuzz",
        command=["forge", "test", "--match-contract", "GeneratedInvariant"],
        harness=".plamen-generated/GeneratedInvariant.t.sol",
    )
    monkeypatch.setattr(F, "process_tree_termination_capability", lambda: {
        "platform": "MACOS", "strategy": "PROCESS_GROUP_DIAGNOSTIC_ONLY",
        "write_confinement": "UNAVAILABLE",
        "exhaustive_descendant_termination_authority": False,
        "exhaustive_write_confinement_authority": False,
        "limitation": "NO_HOST_PROCESS_TREE_AUTHORITY",
    })
    secure = contract["secure_launcher_receipt"]
    assert isinstance(secure, dict)
    capability = F.fuzz_execution_capability(
        apple_preflight=preflight, secure_launcher_receipt=secure
    )
    assert capability["status"] == "UNSCORED"
    assert capability["process_tree_policy"] == (
        "PROCESS_GROUP_DIAGNOSTIC_ONLY"
    )
    producer_codes = {
        "APPLE_FUZZ_SERVICE_SESSION_PRODUCER_ABSENT",
        "APPLE_FUZZ_SECURE_RECEIPT_MINTER_ABSENT",
        "APPLE_FUZZ_CONTINUATION_LEASE_PRODUCER_ABSENT",
        "APPLE_FUZZ_LIFECYCLE_TERMINAL_PRODUCER_ABSENT",
    }
    assert producer_codes.issubset({
        row["code"] for row in capability["issues"]
    })
    _enable_test_only_atomic_service(monkeypatch)
    malformed = dict(secure)
    malformed.pop("guest_executable_sha256")
    malformed["payload_digest"] = F.payload_digest(malformed)
    rejected = F.fuzz_execution_capability(
        apple_preflight=preflight, secure_launcher_receipt=malformed
    )
    assert rejected["status"] == "UNSCORED"
    assert "APPLE_CONTAINER_ADMISSION_UNAVAILABLE" in {
        row["code"] for row in rejected["issues"]
    }


def test_macos_driver_probe_names_missing_atomic_producers_without_preflight(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The driver's no-argument probe must retain the actionable native debt."""

    monkeypatch.setattr(F, "process_tree_termination_capability", lambda: {
        "platform": "MACOS", "strategy": "PROCESS_GROUP_DIAGNOSTIC_ONLY",
        "write_confinement": "UNAVAILABLE",
        "exhaustive_descendant_termination_authority": False,
        "exhaustive_write_confinement_authority": False,
        "limitation": "NO_HOST_PROCESS_TREE_AUTHORITY",
    })
    capability = F.fuzz_execution_capability()
    codes = {row["code"] for row in capability["issues"]}
    assert capability["status"] == "UNSCORED"
    assert {
        "APPLE_FUZZ_SERVICE_SESSION_PRODUCER_ABSENT",
        "APPLE_FUZZ_SECURE_RECEIPT_MINTER_ABSENT",
        "APPLE_FUZZ_CONTINUATION_LEASE_PRODUCER_ABSENT",
        "APPLE_FUZZ_LIFECYCLE_TERMINAL_PRODUCER_ABSENT",
        "PROCESS_CONTAINMENT_UNAVAILABLE",
        "FILESYSTEM_CONTAINMENT_UNAVAILABLE",
    }.issubset(codes)
