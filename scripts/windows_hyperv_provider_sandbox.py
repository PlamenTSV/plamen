"""Fail-closed Windows Hyper-V/HCS provider boundary contracts.

The legacy Windows MIC lease is useful defence in depth, but it is not the
production sandbox described by the Program Facts A8/A9 contract.  That
contract requires a Hyper-V isolated compute system with immutable input and
bounded output disks, no network adapter, and terminal HCS plus guest-Job
evidence.

This module validates evidence emitted by that native provider.  Validation is
not observation: none of these functions synthesize configured/observed/
enforced states, and the host readiness probe never reports production-ready
until the installed native provider artifacts are present.
"""

from __future__ import annotations

import ctypes
import hashlib
import json
import os
from pathlib import Path
import platform
import secrets
import subprocess
import threading
from typing import Any, Mapping

from bounded_artifact_io import read_bounded_regular_bytes


BOUNDARY_PROFILE = "WINDOWS_HYPERV_HCS_PROVIDER_BOUNDARY_V1"
WINDOWS_CAPABILITIES = (
    "PINNED_HELPER_RUNTIME_TOOL_EXECUTION_IDENTITY",
    "IMMUTABLE_READONLY_VHDX_READ_ROOT",
    "BOUNDED_WRITABLE_VHDX_ROOT",
    "SECRET_FREE_CLOSED_CHILD_ENVIRONMENT",
    "EXPLICIT_INHERITED_HANDLE_ALLOWLIST",
    "NO_NETWORK_ADAPTER",
    "NON_BREAKAWAY_GUEST_JOB_PROCESS_TREE_OWNERSHIP",
    "HCS_COMPUTE_SYSTEM_PROCESS_TREE_OWNERSHIP",
    "JOB_HCS_RESOURCE_ENFORCEMENT_AND_READBACK",
    "FIXED_VHDX_BYTE_AND_FILE_RECORD_BOUND",
    "TERMINAL_DESCENDANT_ZERO_EVIDENCE",
    "FLUSH_DETACH_CLEANUP_EVIDENCE",
)
_EVIDENCE_STATE = {"configured": True, "observed": True, "enforced": True}
_HANDLE_ALLOWLIST = ("STDIN", "STDOUT", "STDERR")
_REQUIRED_HCS_EXPORTS = (
    "HcsCreateOperation",
    "HcsCloseOperation",
    "HcsCreateComputeSystem",
    "HcsStartComputeSystem",
    "HcsTerminateComputeSystem",
    "HcsGetComputeSystemProperties",
    "HcsWaitForOperationResult",
    "HcsCloseComputeSystem",
)
_NATIVE_PROVIDER_RELATIVE = Path("native/windows/plamen_windows_hcs_provider.exe")
_NATIVE_RECEIPT_RELATIVE = Path(
    "native/windows/plamen_windows_hcs_provider.install-receipt.json"
)
EMPTY_VM_CONFIGURATION_SHA256 = (
    "676b20877bdf01359203cdc355b19b58d4a291724c527bbf7e836f9ee1f1dc7b"
)
MAX_NATIVE_PROVIDER_BYTES = 64 * 1024 * 1024
MAX_NATIVE_INSTALL_RECEIPT_BYTES = 64 * 1024
MAX_NATIVE_DOCTOR_OUTPUT_BYTES = 64 * 1024
_HEX_SHA256 = frozenset("0123456789abcdef")


class WindowsHyperVProviderError(RuntimeError):
    """The native Windows boundary or its evidence failed closed."""


def _reject(reason_code: str, detail: str) -> None:
    raise WindowsHyperVProviderError(f"{reason_code}: {detail}")


def _mapping(value: Any, *, reason_code: str, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        _reject(reason_code, f"{label} must be a mapping")
    return value


def _exact_keys(
    value: Mapping[str, Any],
    expected: tuple[str, ...],
    *,
    reason_code: str,
    label: str,
) -> None:
    if set(value) != set(expected):
        _reject(reason_code, f"{label} keys diverged")


def _exact_capability_states(
    raw: Any,
    *,
    reason_code: str,
) -> None:
    states = _mapping(raw, reason_code=reason_code, label="capability states")
    if tuple(states) != WINDOWS_CAPABILITIES:
        _reject(reason_code, "capability roster or order diverged")
    for capability in WINDOWS_CAPABILITIES:
        state = _mapping(
            states[capability],
            reason_code=reason_code,
            label=f"{capability} state",
        )
        if dict(state) != _EVIDENCE_STATE:
            _reject(
                reason_code,
                f"{capability} lacks configured/observed/enforced evidence",
            )


def validate_windows_provider_boundary_v1(
    evidence: Mapping[str, Any],
) -> dict[str, Any]:
    """Validate an A8 native boundary observation without minting one."""

    reason = "PF_A8_WINDOWS_BOUNDARY_CLAIM_INVALID"
    document = _mapping(evidence, reason_code=reason, label="boundary evidence")
    _exact_keys(
        document,
        (
            "provider_environment",
            "capability_states",
            "host_filesystem_shares",
            "network_adapters",
            "guest_job_breakaway_allowed",
            "inherited_handles",
            "inherited_handle_allowlist",
            "borrowed_capabilities",
            "permit_upgraded_capabilities",
            "linux_shaped_evidence",
            "generic_windows_tag_only",
        ),
        reason_code=reason,
        label="boundary evidence",
    )
    environment = _mapping(
        document["provider_environment"],
        reason_code=reason,
        label="provider environment",
    )
    boundary = _mapping(
        environment.get("windows_boundary"),
        reason_code=reason,
        label="Windows boundary",
    )
    if (
        environment.get("platform") != "WINDOWS"
        or environment.get("linux_boundary") is not None
        or boundary.get("boundary_profile") != BOUNDARY_PROFILE
        or tuple(boundary.get("provided_capabilities", ()))
        != WINDOWS_CAPABILITIES
    ):
        _reject(reason, "provider environment is not the exact native profile")
    _exact_capability_states(document["capability_states"], reason_code=reason)
    if (
        document["linux_shaped_evidence"] is not False
        or document["generic_windows_tag_only"] is not False
        or document["borrowed_capabilities"] != []
        or document["permit_upgraded_capabilities"] != []
    ):
        _reject(reason, "native evidence was substituted or upgraded")

    containment_reason = "PF_A8_WINDOWS_CONTAINMENT_EVIDENCE_MISSING"
    if (
        document["host_filesystem_shares"] != []
        or document["network_adapters"] != []
        or document["guest_job_breakaway_allowed"] is not False
        or tuple(document["inherited_handles"]) != _HANDLE_ALLOWLIST
        or tuple(document["inherited_handle_allowlist"]) != _HANDLE_ALLOWLIST
    ):
        _reject(
            containment_reason,
            "host share, network, breakaway, or handle closure diverged",
        )
    return {
        "accepted": True,
        "boundary_profile": BOUNDARY_PROFILE,
        "capabilities": WINDOWS_CAPABILITIES,
    }


def validate_windows_resource_authority_v1(
    evidence: Mapping[str, Any],
) -> dict[str, Any]:
    """Validate A9 readback and terminal evidence emitted by native HCS."""

    readback_reason = "PF_A9_WINDOWS_RESOURCE_READBACK_UNPROVEN"
    document = _mapping(evidence, reason_code=readback_reason, label="resource evidence")
    _exact_keys(
        document,
        (
            "boundary_profile",
            "capability_states",
            "readback",
            "quota_evidence",
            "terminal_evidence",
            "cleanup_evidence",
        ),
        reason_code=readback_reason,
        label="resource evidence",
    )
    if document["boundary_profile"] != BOUNDARY_PROFILE:
        _reject(readback_reason, "boundary profile diverged")
    _exact_capability_states(
        document["capability_states"],
        reason_code=readback_reason,
    )
    readback = _mapping(
        document["readback"], reason_code=readback_reason, label="readback"
    )
    if set(readback) != {
        "job_memory_and_process_limits",
        "hcs_compute_system_limits",
        "vhdx_capacity_and_file_record_bound",
    } or not all(value is True for value in readback.values()):
        _reject(readback_reason, "Job/HCS/VHDX readback is incomplete")

    terminal_reason = "PF_A9_WINDOWS_TERMINAL_EVIDENCE_INCOMPLETE"
    expected_groups = {
        "quota_evidence": {
            "fixed_vhdx_capacity",
            "fixed_ntfs_file_record_bound",
            "sparse_logical_and_allocated_bounds",
        },
        "terminal_evidence": {
            "active_process_zero",
            "descendant_count_zero",
        },
        "cleanup_evidence": {
            "output_flushed",
            "vhdx_flushed",
            "vhdx_detached",
            "hcs_terminated",
        },
    }
    for label, keys in expected_groups.items():
        group = _mapping(
            document[label], reason_code=terminal_reason, label=label
        )
        if set(group) != keys or not all(
            value is True for value in group.values()
        ):
            _reject(terminal_reason, f"{label} is incomplete")
    return {
        "accepted": True,
        "boundary_profile": BOUNDARY_PROFILE,
        "terminal": "FLUSHED_DETACHED_HCS_AND_DESCENDANTS_ZERO",
    }


def _canonical_json_bytes(value: Mapping[str, Any]) -> bytes:
    return (
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
        + "\n"
    ).encode("ascii")


def _sha256_text(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and not set(value) - _HEX_SHA256
    )


def validate_windows_hcs_doctor_receipt_v1(
    receipt: Mapping[str, Any],
    *,
    expected_challenge: bytes,
    expected_provider_identity: Mapping[str, Any],
) -> dict[str, Any]:
    """Bind one live doctor response to its launch and installed provider.

    Authenticity comes from capturing this receipt from the stdout handle of
    the exact, hash-locked native process.  This function therefore requires
    the caller's independently observed provider identity and a fresh challenge;
    a receipt file discovered by path is never sufficient.
    """

    reason = "WINDOWS_HCS_DOCTOR_RECEIPT_INVALID"
    if (
        not isinstance(expected_challenge, bytes)
        or not 16 <= len(expected_challenge) <= 256
    ):
        _reject(reason, "doctor challenge must contain 16..256 bytes")
    expected_identity = _mapping(
        expected_provider_identity,
        reason_code=reason,
        label="expected provider identity",
    )
    _exact_keys(
        expected_identity,
        ("path", "size", "sha256"),
        reason_code=reason,
        label="expected provider identity",
    )
    if (
        not isinstance(expected_identity["path"], str)
        or not expected_identity["path"]
        or isinstance(expected_identity["size"], bool)
        or not isinstance(expected_identity["size"], int)
        or expected_identity["size"] <= 0
        or not _sha256_text(expected_identity["sha256"])
    ):
        _reject(reason, "expected provider identity is malformed")

    document = _mapping(receipt, reason_code=reason, label="doctor receipt")
    _exact_keys(
        document,
        (
            "schema",
            "challenge_sha256",
            "provider_identity",
            "compute_system_properties_sha256",
            "boundary_evidence",
            "resource_evidence",
            "observed_at_windows_filetime",
        ),
        reason_code=reason,
        label="doctor receipt",
    )
    if document["schema"] != "plamen.windows_hcs_doctor_receipt.v1":
        _reject(reason, "doctor receipt schema diverged")
    if document["challenge_sha256"] != hashlib.sha256(
        expected_challenge
    ).hexdigest():
        _reject(reason, "doctor challenge was replayed or substituted")
    observed_identity = _mapping(
        document["provider_identity"],
        reason_code=reason,
        label="observed provider identity",
    )
    if dict(observed_identity) != dict(expected_identity):
        _reject(reason, "doctor provider identity diverged")
    if not _sha256_text(document["compute_system_properties_sha256"]):
        _reject(reason, "compute-system property digest is malformed")
    observed_at = document["observed_at_windows_filetime"]
    if (
        isinstance(observed_at, bool)
        or not isinstance(observed_at, int)
        or observed_at <= 0
    ):
        _reject(reason, "doctor observation time is malformed")
    boundary = validate_windows_provider_boundary_v1(
        _mapping(
            document["boundary_evidence"],
            reason_code=reason,
            label="boundary evidence",
        )
    )
    resources = validate_windows_resource_authority_v1(
        _mapping(
            document["resource_evidence"],
            reason_code=reason,
            label="resource evidence",
        )
    )
    raw = _canonical_json_bytes(document)
    return {
        "accepted": True,
        "boundary_profile": boundary["boundary_profile"],
        "terminal": resources["terminal"],
        "doctor_receipt_sha256": hashlib.sha256(raw).hexdigest(),
    }


def validate_windows_hcs_native_diagnostic_v1(
    diagnostic: Mapping[str, Any],
    *,
    expected_challenge: bytes,
    expected_provider_identity: Mapping[str, Any],
) -> dict[str, Any]:
    """Validate the native pre-production service probe without promoting it."""

    reason = "WINDOWS_HCS_NATIVE_DIAGNOSTIC_INVALID"
    if (
        not isinstance(expected_challenge, bytes)
        or not 16 <= len(expected_challenge) <= 256
    ):
        _reject(reason, "native doctor challenge must contain 16..256 bytes")
    expected = _mapping(
        expected_provider_identity,
        reason_code=reason,
        label="expected provider identity",
    )
    _exact_keys(
        expected,
        ("path", "size", "sha256"),
        reason_code=reason,
        label="expected provider identity",
    )
    document = _mapping(diagnostic, reason_code=reason, label="native diagnostic")
    _exact_keys(
        document,
        (
            "schema",
            "challenge_sha256",
            "provider_identity",
            "provider_file_identity",
            "hcs_api_surface_available",
            "hcs_service_probe",
            "hcs_enumeration_sha256",
            "disposable_empty_vm_probe",
            "observed_at_windows_filetime",
            "production_ready",
            "limitation",
        ),
        reason_code=reason,
        label="native diagnostic",
    )
    if document["schema"] != "plamen.windows_hcs_native_doctor.diagnostic.v1":
        _reject(reason, "native diagnostic schema diverged")
    if document["challenge_sha256"] != hashlib.sha256(
        expected_challenge
    ).hexdigest():
        _reject(reason, "native diagnostic challenge was replayed")
    observed = _mapping(
        document["provider_identity"],
        reason_code=reason,
        label="observed provider identity",
    )
    _exact_keys(
        observed,
        ("path", "size", "sha256"),
        reason_code=reason,
        label="observed provider identity",
    )
    if (
        observed.get("size") != expected.get("size")
        or observed.get("sha256") != expected.get("sha256")
        or not isinstance(observed.get("path"), str)
        or os.path.normcase(os.path.abspath(observed["path"]))
        != os.path.normcase(os.path.abspath(str(expected.get("path", ""))))
    ):
        _reject(reason, "native diagnostic provider identity diverged")
    physical = _mapping(
        document["provider_file_identity"],
        reason_code=reason,
        label="provider file identity",
    )
    _exact_keys(
        physical,
        (
            "volume_serial",
            "file_index_high",
            "file_index_low",
            "number_of_links",
            "last_write_filetime",
        ),
        reason_code=reason,
        label="provider file identity",
    )
    if any(
        isinstance(value, bool) or not isinstance(value, int) or value < 0
        for value in physical.values()
    ) or physical["number_of_links"] != 1 or physical["last_write_filetime"] <= 0:
        _reject(reason, "native provider physical identity is malformed")
    lifecycle = _mapping(
        document["disposable_empty_vm_probe"],
        reason_code=reason,
        label="disposable empty VM probe",
    )
    _exact_keys(
        lifecycle,
        (
            "configuration_sha256",
            "properties_sha256",
            "created",
            "started",
            "terminated",
        ),
        reason_code=reason,
        label="disposable empty VM probe",
    )
    if (
        document["hcs_api_surface_available"] is not True
        or document["hcs_service_probe"] != "ENUMERATE_COMPUTE_SYSTEMS_OK"
        or not _sha256_text(document["hcs_enumeration_sha256"])
        or lifecycle["configuration_sha256"] != EMPTY_VM_CONFIGURATION_SHA256
        or not _sha256_text(lifecycle["properties_sha256"])
        or lifecycle["created"] is not True
        or lifecycle["started"] is not False
        or lifecycle["terminated"] is not True
        or isinstance(document["observed_at_windows_filetime"], bool)
        or not isinstance(document["observed_at_windows_filetime"], int)
        or document["observed_at_windows_filetime"] <= 0
        or document["production_ready"] is not False
        or document["limitation"]
        != "LIVE_GUEST_STORAGE_JOB_NETWORK_PROBE_NOT_IMPLEMENTED"
    ):
        _reject(reason, "native HCS service observation is incomplete")
    return {
        "accepted_diagnostic": True,
        "production_ready": False,
        "challenge_sha256": document["challenge_sha256"],
        "provider_sha256": observed["sha256"],
        "hcs_enumeration_sha256": document["hcs_enumeration_sha256"],
        "empty_vm_properties_sha256": lifecycle["properties_sha256"],
        "observed_at_windows_filetime": document["observed_at_windows_filetime"],
        "limitation": document["limitation"],
    }


def _regular_file_capture(
    path: Path,
    *,
    maximum_bytes: int,
) -> tuple[dict[str, Any], bytes] | None:
    try:
        raw = read_bounded_regular_bytes(
            path,
            maximum_bytes,
            require_single_link=True,
        )
    except (OSError, ValueError):
        return None
    return (
        {
            "path": str(path.absolute()),
            "size": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest(),
        },
        raw,
    )


def _run_native_doctor_bounded(
    command: list[str],
    *,
    environment: Mapping[str, str],
    timeout_seconds: float,
) -> tuple[int, bytes, bytes]:
    """Capture an exact helper without allowing pipe-backed memory growth."""

    process = subprocess.Popen(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        close_fds=True,
        env=dict(environment),
    )
    if process.stdout is None or process.stderr is None:
        process.kill()
        process.wait()
        raise OSError("native doctor pipes were not created")
    captured: dict[str, bytes] = {}
    failures: list[BaseException] = []

    def read_one(label: str, stream: Any) -> None:
        try:
            value = stream.read(MAX_NATIVE_DOCTOR_OUTPUT_BYTES + 1)
            captured[label] = value
            if len(value) > MAX_NATIVE_DOCTOR_OUTPUT_BYTES:
                try:
                    process.kill()
                except OSError:
                    pass
        except BaseException as error:  # pragma: no cover - OS pipe failure
            failures.append(error)
            try:
                process.kill()
            except OSError:
                pass
        finally:
            stream.close()

    readers = [
        threading.Thread(
            target=read_one,
            args=("stdout", process.stdout),
            daemon=True,
        ),
        threading.Thread(
            target=read_one,
            args=("stderr", process.stderr),
            daemon=True,
        ),
    ]
    for reader in readers:
        reader.start()
    try:
        return_code = process.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
        for reader in readers:
            reader.join()
        raise
    for reader in readers:
        reader.join()
    if failures:
        raise OSError("native doctor pipe capture failed") from failures[0]
    return return_code, captured.get("stdout", b""), captured.get("stderr", b"")


def windows_hyperv_hcs_runtime_capability(
    *,
    install_root: Path | None = None,
) -> dict[str, Any]:
    """Probe prerequisites while refusing to treat API presence as authority."""

    root = (
        Path(__file__).resolve().parents[1]
        if install_root is None
        else Path(install_root).resolve(strict=True)
    )
    helper_capture = _regular_file_capture(
        root / _NATIVE_PROVIDER_RELATIVE,
        maximum_bytes=MAX_NATIVE_PROVIDER_BYTES,
    )
    receipt_capture = _regular_file_capture(
        root / _NATIVE_RECEIPT_RELATIVE,
        maximum_bytes=MAX_NATIVE_INSTALL_RECEIPT_BYTES,
    )
    helper = None if helper_capture is None else helper_capture[0]
    receipt = None if receipt_capture is None else receipt_capture[0]
    result: dict[str, Any] = {
        "boundary_profile": BOUNDARY_PROFILE,
        "host_platform": platform.system().upper(),
        "host_machine": platform.machine().upper(),
        "hcs_api_surface_available": False,
        "native_provider_identity": helper,
        "native_install_receipt_identity": receipt,
        "production_ready": False,
    }
    if os.name != "nt":
        result["limitation"] = "WINDOWS_HYPERV_HCS_HOST_REQUIRED"
        return result
    if platform.machine().upper() not in {"AMD64", "X86_64"}:
        result["limitation"] = "WINDOWS_NATIVE_AMD64_REQUIRED"
        return result
    try:
        compute_core = ctypes.WinDLL("ComputeCore.dll", use_last_error=True)
    except (AttributeError, OSError):
        result["limitation"] = "COMPUTECORE_DLL_UNAVAILABLE"
        return result
    missing = [name for name in _REQUIRED_HCS_EXPORTS if not hasattr(compute_core, name)]
    if missing:
        result["limitation"] = "HCS_API_EXPORTS_UNAVAILABLE:" + ",".join(missing)
        return result
    result["hcs_api_surface_available"] = True
    if helper is None or receipt is None:
        result["limitation"] = "AUTHENTICATED_NATIVE_HCS_PROVIDER_NOT_INSTALLED"
        return result
    try:
        payload = json.loads(receipt_capture[1].decode("utf-8", errors="strict"))
    except (UnicodeError, json.JSONDecodeError):
        result["limitation"] = "NATIVE_HCS_INSTALL_RECEIPT_MALFORMED"
        return result
    if (
        not isinstance(payload, dict)
        or set(payload) != {
            "schema",
            "boundary_profile",
            "provider_sha256",
            "provider_size",
        }
        or payload.get("schema") != "plamen.windows_hcs_install_receipt.v1"
        or payload.get("boundary_profile") != BOUNDARY_PROFILE
        or payload.get("provider_sha256") != helper["sha256"]
        or payload.get("provider_size") != helper["size"]
    ):
        result["limitation"] = "NATIVE_HCS_INSTALL_RECEIPT_DIVERGED"
        return result
    challenge = secrets.token_bytes(32)
    system_root = os.environ.get("SystemRoot", r"C:\Windows")
    try:
        return_code, stdout, stderr = _run_native_doctor_bounded(
            [
                str(root / _NATIVE_PROVIDER_RELATIVE),
                "doctor",
                "--challenge-hex",
                challenge.hex(),
            ],
            timeout_seconds=45,
            environment={
                "SystemRoot": system_root,
                "WINDIR": system_root,
                "PATH": str(Path(system_root) / "System32"),
            },
        )
    except (OSError, subprocess.SubprocessError):
        result["limitation"] = "NATIVE_HCS_DOCTOR_EXECUTION_FAILED"
        return result
    if return_code == 4 and stdout == b"":
        result["limitation"] = "HCS_SERVICE_OPERATION_UNAVAILABLE"
        return result
    if (
        return_code != 3
        or stderr != b""
        or len(stdout) > MAX_NATIVE_DOCTOR_OUTPUT_BYTES
    ):
        result["limitation"] = "NATIVE_HCS_DOCTOR_PROTOCOL_DIVERGED"
        return result
    try:
        diagnostic_payload = json.loads(stdout.decode("utf-8", errors="strict"))
        diagnostic = validate_windows_hcs_native_diagnostic_v1(
            diagnostic_payload,
            expected_challenge=challenge,
            expected_provider_identity=helper,
        )
    except (UnicodeError, json.JSONDecodeError, WindowsHyperVProviderError):
        result["limitation"] = "NATIVE_HCS_DOCTOR_DIAGNOSTIC_INVALID"
        return result
    result["native_doctor_diagnostic"] = diagnostic
    # The native probe now proves exact helper execution and a fresh HCS
    # service operation.  It deliberately does not promote those facts into
    # guest isolation/resource authority: that requires the disposable VM's
    # complete A8/A9 receipt.
    result["limitation"] = "LIVE_ISOLATED_GUEST_DOCTOR_RECEIPT_REQUIRED"
    return result


def require_windows_hyperv_hcs_runtime(
    *,
    install_root: Path | None = None,
) -> dict[str, Any]:
    """Fail closed until a live native doctor receipt is implemented."""

    capability = windows_hyperv_hcs_runtime_capability(install_root=install_root)
    if capability.get("production_ready") is not True:
        _reject(
            "WINDOWS_HYPERV_HCS_RUNTIME_UNAVAILABLE",
            str(capability.get("limitation", "UNKNOWN")),
        )
    return capability


__all__ = [
    "BOUNDARY_PROFILE",
    "EMPTY_VM_CONFIGURATION_SHA256",
    "MAX_NATIVE_INSTALL_RECEIPT_BYTES",
    "MAX_NATIVE_DOCTOR_OUTPUT_BYTES",
    "MAX_NATIVE_PROVIDER_BYTES",
    "WINDOWS_CAPABILITIES",
    "WindowsHyperVProviderError",
    "require_windows_hyperv_hcs_runtime",
    "validate_windows_hcs_doctor_receipt_v1",
    "validate_windows_hcs_native_diagnostic_v1",
    "validate_windows_provider_boundary_v1",
    "validate_windows_resource_authority_v1",
    "windows_hyperv_hcs_runtime_capability",
]
