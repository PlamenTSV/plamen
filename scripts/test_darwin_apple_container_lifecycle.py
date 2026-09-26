from __future__ import annotations

import ctypes
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess

import pytest

import build_posix_native_supervisor as production_builder


ROOT = Path(__file__).resolve().parent.parent

pytestmark = pytest.mark.skipif(
    platform.system() != "Darwin", reason="Darwin native lifecycle only"
)


class _AdmissionReceipt(ctypes.Structure):
    _fields_ = [
        ("version", ctypes.c_uint32), ("status", ctypes.c_uint32),
        *[(name, ctypes.c_uint8 * 32) for name in (
            "cli_sha256", "request_fingerprint_sha256",
            "provider_provenance_sha256", "image_closure_sha256",
            "closure_sha256", "version_stdout_sha256", "status_stdout_sha256",
            "init_image_stdout_sha256", "runtime_image_stdout_sha256",
            "init_image_postcondition_sha256", "runtime_image_postcondition_sha256",
        )],
        ("command_count", ctypes.c_uint8), ("commands_read_only", ctypes.c_uint8),
        ("lifecycle_authority_granted", ctypes.c_uint8),
        ("mutable_identifier_accepted", ctypes.c_uint8),
        ("control_processes_reaped", ctypes.c_uint8),
        ("control_process_groups_extinct", ctypes.c_uint8),
        ("runtime_image_reference", ctypes.c_char * 512),
        ("admission_sha256", ctypes.c_uint8 * 32),
    ]


class _Mount(ctypes.Structure):
    _fields_ = [
        ("source_fd", ctypes.c_int), ("source_path", ctypes.c_char_p),
        ("target_path", ctypes.c_char_p),
        ("expected_identity_sha256", ctypes.c_uint8 * 32),
        ("readonly", ctypes.c_uint8),
    ]


class _LifecycleSpec(ctypes.Structure):
    _fields_ = [
        ("version", ctypes.c_uint32), ("cli_fd", ctypes.c_int),
        ("cli_path", ctypes.c_char_p), ("cwd_fd", ctypes.c_int),
        ("stdin_fd", ctypes.c_int), ("state_directory_fd", ctypes.c_int),
        ("admission", ctypes.POINTER(_AdmissionReceipt)),
        ("container_id", ctypes.c_char_p),
        ("runtime_image_reference", ctypes.c_char_p),
        ("working_directory", ctypes.c_char_p), ("entrypoint", ctypes.c_char_p),
        ("arguments", ctypes.POINTER(ctypes.c_char_p)),
        ("argument_count", ctypes.c_size_t), ("cpus", ctypes.c_uint32),
        ("memory_bytes", ctypes.c_uint64), ("uid", ctypes.c_uint32),
        ("gid", ctypes.c_uint32), ("create_timeout_seconds", ctypes.c_uint32),
        ("driver_timeout_seconds", ctypes.c_uint32),
        ("stop_grace_seconds", ctypes.c_uint32),
        ("rosetta_required", ctypes.c_uint8),
        *[(name, ctypes.c_uint8 * 32) for name in (
            "spec_sha256", "launch_request_sha256", "launch_policy_sha256",
            "driver_argv_sha256", "driver_environment_sha256",
            "driver_cwd_sha256", "driver_stdin_sha256", "pass_fd_roster_sha256",
            "create_operation_key", "start_operation_nonce", "wait_operation_nonce",
            "revoke_operation_nonce",
        )],
        ("mounts", _Mount * 12),
        ("mount_count", ctypes.c_size_t),
        ("dynamic_mounts", ctypes.c_uint8),
    ]


class _Commitments(ctypes.Structure):
    _fields_ = [(name, ctypes.c_uint8 * 32) for name in (
        "spec_sha256", "launch_request_sha256", "driver_argv_sha256",
        "driver_environment_sha256", "driver_cwd_sha256", "driver_stdin_sha256",
        "pass_fd_roster_sha256", "mount_roster_sha256", "create_argv_sha256",
    )]


class _CreateReceipt(ctypes.Structure):
    _fields_ = [
        ("version", ctypes.c_uint32), ("status", ctypes.c_uint32),
        ("container_id", ctypes.c_char * 40),
        *[(name, ctypes.c_uint8 * 32) for name in (
            "request_fingerprint_sha256", "provider_provenance_sha256",
            "image_closure_sha256", "spec_sha256", "mount_roster_sha256",
            "create_argv_sha256", "create_stdout_sha256",
            "create_stderr_sha256", "stopped_observation_sha256",
        )],
        ("rootfs_readonly", ctypes.c_uint8), ("use_init", ctypes.c_uint8),
        ("network_attachment_count", ctypes.c_uint8),
        ("dns_disabled", ctypes.c_uint8),
        ("control_process_reaped", ctypes.c_uint8),
        ("control_process_group_extinct", ctypes.c_uint8),
        ("receipt_sha256", ctypes.c_uint8 * 32),
    ]


class _StartReceipt(ctypes.Structure):
    _fields_ = [
        ("version", ctypes.c_uint32), ("status", ctypes.c_uint32),
        ("container_id", ctypes.c_char * 40),
        *[(name, ctypes.c_uint8 * 32) for name in (
            "request_fingerprint_sha256", "spec_sha256",
            "launch_request_sha256", "start_operation_nonce",
            "start_argv_sha256", "native_process_handle_sha256",
        )],
        ("native_process_id", ctypes.c_int32),
        ("start_monotonic_ms", ctypes.c_uint64),
        *[(name, ctypes.c_uint8 * 32) for name in (
            "prepared_record_sha256", "custody_process_spec_sha256",
            "custody_prepared_checkpoint_sha256",
            "custody_started_checkpoint_sha256", "receipt_sha256",
        )],
        ("post_spawn_dynamic_identity_kind", ctypes.c_uint32),
        ("post_spawn_dynamic_identity_size", ctypes.c_uint32),
        ("post_spawn_dynamic_identity_sha256", ctypes.c_uint8 * 32),
    ]


class _TerminalReceipt(ctypes.Structure):
    _fields_ = [
        ("version", ctypes.c_uint32), ("status", ctypes.c_uint32),
        ("container_id", ctypes.c_char * 40),
        *[(name, ctypes.c_uint8 * 32) for name in (
            "request_fingerprint_sha256", "spec_sha256",
            "launch_request_sha256", "start_operation_nonce",
            "wait_operation_nonce", "revoke_operation_nonce",
            "native_process_handle_sha256",
        )],
        ("native_process_id", ctypes.c_int32), ("exit_code", ctypes.c_int32),
        ("start_monotonic_ms", ctypes.c_uint64),
        ("end_monotonic_ms", ctypes.c_uint64),
        ("stdout_observed_bytes", ctypes.c_uint64),
        ("stderr_observed_bytes", ctypes.c_uint64),
        ("stdout_retained_bytes", ctypes.c_uint32),
        ("stderr_retained_bytes", ctypes.c_uint32),
        *[(name, ctypes.c_uint8 * 32) for name in (
            "stdout_sha256", "stderr_sha256", "stdout_retained_sha256",
            "stderr_retained_sha256", "native_process_extinction_sha256",
            "cleanup_sha256",
        )],
        *[(name, ctypes.c_uint8) for name in (
            "descendants_extinct", "guest_process_extinct",
            "backend_egress_revoked", "stdout_truncated", "stderr_truncated",
            "terminal_durable", "deleted",
        )],
        *[(name, ctypes.c_uint8 * 32) for name in (
            "stop_argv_sha256", "stop_stdout_sha256", "stop_stderr_sha256",
            "stopped_observation_sha256", "guest_population_extinction_sha256",
        )],
        *[(name, ctypes.c_uint8) for name in (
            "stop_control_process_reaped",
            "stop_control_process_group_extinct", "guest_population_zero",
            "container_vm_stopped",
        )],
        ("receipt_sha256", ctypes.c_uint8 * 32),
        ("stdout_retained", ctypes.c_void_p),
        ("stderr_retained", ctypes.c_void_p),
    ]


@pytest.fixture(scope="module")
def lifecycle_library(tmp_path_factory: pytest.TempPathFactory) -> ctypes.CDLL:
    output = tmp_path_factory.mktemp("apple-lifecycle") / "lifecycle.dylib"
    subprocess.run(
        [
            "/usr/bin/clang", "-std=c11", "-Wall", "-Wextra", "-Werror",
            "-fblocks", "-dynamiclib",
            "-DPLAMEN_BROKER_V2_APPLE_CONTAINER_TEST_ONLY=1",
            "-I", str(ROOT / "native" / "include"),
            "-I", str(ROOT / "native" / "darwin"),
            str(ROOT / "native" / "darwin" / "plamen_broker_v2_process.c"),
            str(ROOT / "native" / "darwin" / "plamen_broker_v2_process_custodian.c"),
            str(ROOT / "native" / "darwin" / "plamen_broker_v2_process_custody_client.c"),
            str(ROOT / "native" / "darwin" / "plamen_broker_v2_apple_container.c"),
            str(ROOT / "native" / "darwin" / "plamen_broker_v2_apple_container_lifecycle.c"),
            str(ROOT / "native" / "posix" / "plamen_broker_v2_protocol.c"),
            "-framework", "Security", "-framework", "CoreFoundation",
            "-o", str(output),
        ],
        cwd=ROOT, check=True, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30,
    )
    library = ctypes.CDLL(str(output))
    library.plamen_broker_v2_fd_identity.argtypes = [
        ctypes.c_int, ctypes.POINTER(ctypes.c_uint8),
    ]
    library.plamen_broker_v2_fd_identity.restype = ctypes.c_int
    library.plamen_broker_v2_apple_container_derive_id.argtypes = [
        ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(ctypes.c_uint8), ctypes.c_char_p,
    ]
    library.plamen_broker_v2_apple_container_derive_id.restype = ctypes.c_int
    library.plamen_broker_v2_apple_container_receipt_validate.argtypes = [
        ctypes.POINTER(_AdmissionReceipt),
    ]
    library.plamen_broker_v2_apple_container_receipt_validate.restype = ctypes.c_int
    library.plamen_broker_v2_apple_lifecycle_derive_commitments.argtypes = [
        ctypes.POINTER(_LifecycleSpec), ctypes.POINTER(_Commitments),
    ]
    library.plamen_broker_v2_apple_lifecycle_derive_commitments.restype = ctypes.c_int
    library.plamen_broker_v2_apple_lifecycle_test_validate_spec.argtypes = [
        ctypes.POINTER(_LifecycleSpec),
    ]
    library.plamen_broker_v2_apple_lifecycle_test_validate_spec.restype = ctypes.c_int
    library.plamen_broker_v2_apple_lifecycle_test_validate_inspect.argtypes = [
        ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(_LifecycleSpec),
        ctypes.c_char_p, ctypes.POINTER(ctypes.c_uint8),
    ]
    library.plamen_broker_v2_apple_lifecycle_test_validate_inspect.restype = ctypes.c_int
    library.plamen_broker_v2_apple_lifecycle_test_exact_id_output.argtypes = [
        ctypes.c_void_p, ctypes.c_size_t, ctypes.c_char_p,
    ]
    library.plamen_broker_v2_apple_lifecycle_test_exact_id_output.restype = ctypes.c_int
    library.plamen_broker_v2_apple_lifecycle_test_list_proves_absent.argtypes = [
        ctypes.c_void_p, ctypes.c_size_t, ctypes.c_char_p,
    ]
    library.plamen_broker_v2_apple_lifecycle_test_list_proves_absent.restype = ctypes.c_int
    record_pointer = ctypes.POINTER(ctypes.c_uint8)
    library.plamen_broker_v2_apple_lifecycle_test_encode_create_receipt.argtypes = [
        ctypes.POINTER(_CreateReceipt), record_pointer,
    ]
    library.plamen_broker_v2_apple_lifecycle_test_encode_create_receipt.restype = ctypes.c_int
    library.plamen_broker_v2_apple_lifecycle_test_decode_create_receipt.argtypes = [
        record_pointer, ctypes.POINTER(_CreateReceipt),
    ]
    library.plamen_broker_v2_apple_lifecycle_test_decode_create_receipt.restype = ctypes.c_int
    library.plamen_broker_v2_apple_lifecycle_test_encode_start_receipt.argtypes = [
        ctypes.POINTER(_StartReceipt), record_pointer,
    ]
    library.plamen_broker_v2_apple_lifecycle_test_encode_start_receipt.restype = ctypes.c_int
    library.plamen_broker_v2_apple_lifecycle_test_decode_start_receipt.argtypes = [
        record_pointer, ctypes.POINTER(_StartReceipt),
    ]
    library.plamen_broker_v2_apple_lifecycle_test_decode_start_receipt.restype = ctypes.c_int
    library.plamen_broker_v2_apple_lifecycle_test_encode_terminal_receipt.argtypes = [
        ctypes.POINTER(_TerminalReceipt), record_pointer,
    ]
    library.plamen_broker_v2_apple_lifecycle_test_encode_terminal_receipt.restype = ctypes.c_int
    library.plamen_broker_v2_apple_lifecycle_test_decode_terminal_receipt.argtypes = [
        record_pointer, ctypes.POINTER(_TerminalReceipt),
    ]
    library.plamen_broker_v2_apple_lifecycle_test_decode_terminal_receipt.restype = ctypes.c_int
    return library


def _set_digest(target: ctypes.Array[ctypes.c_uint8], value: bytes) -> None:
    assert len(value) == 32
    target[:] = value


def _seal_struct_receipt(receipt: ctypes.Structure, field: str) -> None:
    offset = getattr(type(receipt), field).offset
    digest = hashlib.sha256(
        ctypes.string_at(ctypes.addressof(receipt), offset)
    ).digest()
    getattr(receipt, field)[:] = digest


def test_durable_create_and_start_receipts_are_canonical_and_tamper_evident(
    lifecycle_library: ctypes.CDLL,
) -> None:
    container_id = b"plamen-" + b"a" * 32
    create = _CreateReceipt(version=1, status=0, container_id=container_id)
    for index, name in enumerate((
        "request_fingerprint_sha256", "provider_provenance_sha256",
        "image_closure_sha256", "spec_sha256", "mount_roster_sha256",
        "create_argv_sha256", "create_stdout_sha256",
        "create_stderr_sha256", "stopped_observation_sha256",
    ), start=1):
        _set_digest(getattr(create, name), bytes([index]) * 32)
    create.rootfs_readonly = 1
    create.use_init = 1
    create.dns_disabled = 1
    create.control_process_reaped = 1
    create.control_process_group_extinct = 1
    _seal_struct_receipt(create, "receipt_sha256")
    encoded = (ctypes.c_uint8 * 512)()
    decoded = _CreateReceipt()
    assert lifecycle_library.plamen_broker_v2_apple_lifecycle_test_encode_create_receipt(
        ctypes.byref(create), encoded
    ) == 0
    assert lifecycle_library.plamen_broker_v2_apple_lifecycle_test_decode_create_receipt(
        encoded, ctypes.byref(decoded)
    ) == 0
    assert bytes(decoded) == bytes(create)
    encoded[123] ^= 1
    assert lifecycle_library.plamen_broker_v2_apple_lifecycle_test_decode_create_receipt(
        encoded, ctypes.byref(decoded)
    ) != 0

    start = _StartReceipt(
        version=1, status=0, container_id=container_id,
        native_process_id=4242, start_monotonic_ms=123456,
    )
    for index, name in enumerate((
        "request_fingerprint_sha256", "spec_sha256",
        "launch_request_sha256", "start_operation_nonce",
        "start_argv_sha256", "native_process_handle_sha256",
        "prepared_record_sha256", "custody_process_spec_sha256",
        "custody_prepared_checkpoint_sha256",
        "custody_started_checkpoint_sha256",
    ), start=1):
        _set_digest(getattr(start, name), bytes([index + 20]) * 32)
    _seal_struct_receipt(start, "receipt_sha256")
    encoded = (ctypes.c_uint8 * 512)()
    decoded_start = _StartReceipt()
    assert lifecycle_library.plamen_broker_v2_apple_lifecycle_test_encode_start_receipt(
        ctypes.byref(start), encoded
    ) == 0
    assert lifecycle_library.plamen_broker_v2_apple_lifecycle_test_decode_start_receipt(
        encoded, ctypes.byref(decoded_start)
    ) == 0
    assert bytes(decoded_start) == bytes(start)
    encoded[390] ^= 1
    assert lifecycle_library.plamen_broker_v2_apple_lifecycle_test_decode_start_receipt(
        encoded, ctypes.byref(decoded_start)
    ) != 0


def test_terminal_receipt_requires_vm_stop_and_guest_extinction_proof(
    lifecycle_library: ctypes.CDLL,
) -> None:
    terminal = _TerminalReceipt(
        version=2, status=0, container_id=b"plamen-" + b"b" * 32,
        native_process_id=4242, exit_code=0, start_monotonic_ms=100,
        end_monotonic_ms=200,
    )
    digests = (
        "request_fingerprint_sha256", "spec_sha256",
        "launch_request_sha256", "start_operation_nonce",
        "wait_operation_nonce", "revoke_operation_nonce",
        "native_process_handle_sha256", "stdout_sha256", "stderr_sha256",
        "stdout_retained_sha256", "stderr_retained_sha256",
        "native_process_extinction_sha256", "cleanup_sha256",
        "stop_argv_sha256", "stop_stdout_sha256", "stop_stderr_sha256",
        "stopped_observation_sha256", "guest_population_extinction_sha256",
    )
    for index, name in enumerate(digests, start=1):
        _set_digest(getattr(terminal, name), bytes([index]) * 32)
    terminal.descendants_extinct = 1
    terminal.guest_process_extinct = 1
    terminal.backend_egress_revoked = 1
    terminal.terminal_durable = 1
    terminal.stop_control_process_reaped = 1
    terminal.stop_control_process_group_extinct = 1
    terminal.guest_population_zero = 1
    terminal.container_vm_stopped = 1
    encoded = (ctypes.c_uint8 * 768)()
    decoded = _TerminalReceipt()
    assert lifecycle_library.plamen_broker_v2_apple_lifecycle_test_encode_terminal_receipt(
        ctypes.byref(terminal), encoded
    ) == 0
    assert lifecycle_library.plamen_broker_v2_apple_lifecycle_test_decode_terminal_receipt(
        encoded, ctypes.byref(decoded)
    ) == 0
    assert bytes(decoded) == bytes(terminal)
    for offset in (544, 576, 608, 640, 672, 704, 705, 706, 707):
        mutated = (ctypes.c_uint8 * 768).from_buffer_copy(encoded)
        mutated[offset] ^= 1
        assert lifecycle_library.plamen_broker_v2_apple_lifecycle_test_decode_terminal_receipt(
            mutated, ctypes.byref(decoded)
        ) != 0


def _receipt(reference: bytes) -> _AdmissionReceipt:
    receipt = _AdmissionReceipt(version=2, status=0)
    for index, name in enumerate((
        "request_fingerprint_sha256", "provider_provenance_sha256",
        "image_closure_sha256",
    ), start=1):
        _set_digest(getattr(receipt, name), bytes([index]) * 32)
    receipt.command_count = 4
    receipt.commands_read_only = 1
    receipt.control_processes_reaped = 1
    receipt.control_process_groups_extinct = 1
    receipt.runtime_image_reference = reference
    offset = _AdmissionReceipt.admission_sha256.offset
    encoded = ctypes.string_at(ctypes.addressof(receipt), offset)
    _set_digest(receipt.admission_sha256, hashlib.sha256(
        b"plamen.apple-container.admission.v1\0" + encoded
    ).digest())
    return receipt


def _spec(library: ctypes.CDLL, tmp_path: Path) -> tuple[
    _LifecycleSpec, _AdmissionReceipt, ctypes.Array[ctypes.c_char_p], list[int], list[bytes]
]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    reference = b"example.invalid/plamen/runtime@sha256:" + b"a" * 64
    receipt = _receipt(reference)
    assert library.plamen_broker_v2_apple_container_receipt_validate(
        ctypes.byref(receipt)
    ) == 0
    stdin_path = tmp_path / "stdin-empty"
    stdin_path.write_bytes(b"")
    descriptors = [
        os.open(tmp_path, os.O_RDONLY), os.open(tmp_path, os.O_RDONLY),
        os.open(stdin_path, os.O_RDONLY), os.open(tmp_path, os.O_RDONLY),
    ]
    sources: list[bytes] = []
    targets = [
        b"/workspace/project", b"/workspace/scratch", b"/workspace/state",
        b"/workspace/control", b"/run/plamen/seccomp",
        b"/run/plamen/credentials", b"/run/plamen/backend", b"/opt/plamen",
        b"/workspace/docs", b"/workspace/scope",
    ]
    spec = _LifecycleSpec(
        version=1, cli_fd=descriptors[0], cli_path=b"/usr/local/bin/container",
        cwd_fd=descriptors[1], stdin_fd=descriptors[2],
        state_directory_fd=descriptors[3], admission=ctypes.pointer(receipt),
        runtime_image_reference=reference, working_directory=b"/workspace/project",
        entrypoint=b"/opt/plamen/entrypoint", argument_count=2, cpus=4,
        memory_bytes=4 * 1024**3, uid=1000, gid=1000,
        create_timeout_seconds=30, driver_timeout_seconds=120,
        stop_grace_seconds=5, rosetta_required=0,
    )
    arguments = (ctypes.c_char_p * 2)(b"audit", b"--offline")
    spec.arguments = arguments
    for index, target in enumerate(targets):
        source = tmp_path / f"mount-{index}"
        source.mkdir()
        encoded = os.fsencode(source)
        sources.append(encoded)
        descriptor = os.open(source, os.O_RDONLY)
        descriptors.append(descriptor)
        spec.mounts[index].source_fd = descriptor
        spec.mounts[index].source_path = encoded
        spec.mounts[index].target_path = target
        spec.mounts[index].readonly = int(index == 0 or index >= 3)
        identity = (ctypes.c_uint8 * 32)()
        assert library.plamen_broker_v2_fd_identity(descriptor, identity) == 0
        spec.mounts[index].expected_identity_sha256[:] = bytes(identity)
    _set_digest(spec.launch_policy_sha256, b"L" * 32)
    _set_digest(spec.create_operation_key, b"C" * 32)
    _set_digest(spec.start_operation_nonce, b"S" * 32)
    _set_digest(spec.wait_operation_nonce, b"W" * 32)
    _set_digest(spec.revoke_operation_nonce, b"R" * 32)
    container_id = ctypes.create_string_buffer(40)
    assert library.plamen_broker_v2_apple_container_derive_id(
        receipt.request_fingerprint_sha256, spec.create_operation_key, container_id
    ) == 0
    spec.container_id = container_id.value
    # Keep backing Python objects alive through the native calls.
    spec._container_id = container_id  # type: ignore[attr-defined]
    spec._sources = sources  # type: ignore[attr-defined]
    commitments = _Commitments()
    assert library.plamen_broker_v2_apple_lifecycle_derive_commitments(
        ctypes.byref(spec), ctypes.byref(commitments)
    ) == 0
    for name in (
        "spec_sha256", "launch_request_sha256", "driver_argv_sha256",
        "driver_environment_sha256", "driver_cwd_sha256", "driver_stdin_sha256",
        "pass_fd_roster_sha256",
    ):
        getattr(spec, name)[:] = bytes(getattr(commitments, name))
    return spec, receipt, arguments, descriptors, sources


def test_incomplete_lifecycle_remains_an_explicit_release_blocker() -> None:
    roster = dict(production_builder.PRODUCTION_DARWIN_SOURCE_ROSTER)
    frozen = production_builder.PRODUCTION_FROZEN_SOURCE_SHA256
    assert roster["darwin_apple_lifecycle_header"].endswith(
        "plamen_broker_v2_apple_container_lifecycle.h"
    )
    assert roster["darwin_apple_lifecycle"].endswith(
        "plamen_broker_v2_apple_container_lifecycle.c"
    )
    assert "darwin_apple_lifecycle_header" not in frozen
    assert "darwin_apple_lifecycle" not in frozen


def test_lifecycle_source_compiles_with_production_warnings_as_errors(tmp_path: Path) -> None:
    output = tmp_path / "plamen-lifecycle.o"
    subprocess.run(
        [
            "/usr/bin/clang",
            "-std=c11",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-fblocks",
            "-c",
            "-I",
            str(ROOT / "native" / "include"),
            "-I",
            str(ROOT / "native" / "darwin"),
            "-I",
            str(ROOT / "native" / "posix"),
            str(ROOT / "native" / "darwin" / "plamen_broker_v2_apple_container_lifecycle.c"),
            "-o",
            str(output),
        ],
        cwd=ROOT,
        check=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
    )


def test_lifecycle_command_surface_is_fixed_and_network_closed() -> None:
    source = (
        ROOT / "native" / "darwin" / "plamen_broker_v2_apple_container_lifecycle.c"
    ).read_text(encoding="utf-8")
    assert 'argv[1] = "start"; argv[2] = "--attach"' in source
    assert 'argv[1] = "stop"' in source
    assert 'argv[2] = "--time"' in source
    assert 'argv[2] = "--signal"' in source
    assert 'argv[3] = "KILL"' in source
    assert 'remove[0] = context->cli_path; remove[1] = "delete"' in source
    assert 'ADD("--read-only"); ADD("--init")' in source
    assert 'ADD("--cap-drop"); ADD("ALL"); ADD("--network"); ADD("none")' in source
    assert 'ADD("--no-dns")' in source
    assert (
        '"ghcr.io/apple/containerization/vminit@sha256:"' in source
        and '"cde8a93f9861c664bf2b74b4e2893cf877680806f12e7e989eb9c51b2f2e93bf"'
        in source
    )
    assert '"pull"' not in source
    assert '"build"' not in source
    assert '"tag"' not in source
    assert '"exec"' not in source


def test_every_slice3_mount_is_exact_order_and_narrowly_writable() -> None:
    source = (
        ROOT / "native" / "darwin" / "plamen_broker_v2_apple_container_lifecycle.c"
    ).read_text(encoding="utf-8")
    expected = (
        "/workspace/project",
        "/workspace/scratch",
        "/workspace/state",
        "/workspace/control",
        "/run/plamen/seccomp",
        "/run/plamen/credentials",
        "/run/plamen/backend",
        "/opt/plamen",
        "/workspace/docs",
        "/workspace/scope",
    )
    positions = [source.index(f'"{target}"') for target in expected]
    assert positions == sorted(positions)
    assert "1, 0, 0, 1, 1, 1, 1, 1, 1, 1" in source
    assert '",readonly"' in source
    assert "|| !S_ISDIR(descriptor.st_mode)" in source


def test_durable_order_is_prepare_start_wait_terminal_cleanup_delete() -> None:
    source = (
        ROOT / "native" / "darwin" / "plamen_broker_v2_apple_container_lifecycle.c"
    ).read_text(encoding="utf-8")
    start = source[source.index("plamen_broker_v2_apple_lifecycle_start(") :]
    assert start.index("START_PREPARED_RECORD") < start.index(
        "plamen_broker_v2_process_custody_client_start"
    ) < start.index("START_RECORD")
    wait = source[source.index("plamen_broker_v2_apple_lifecycle_wait(") :]
    assert wait.index("WAIT_PREPARED_RECORD") < wait.index(
        "plamen_broker_v2_process_custody_client_wait"
    ) < wait.index("stop_and_prove_guest_extinction") < wait.index(
        "collect_terminal"
    )
    revoke = source[source.index("plamen_broker_v2_apple_lifecycle_revoke_delete(") :]
    assert revoke.index("REVOKE_PREPARED_RECORD") < revoke.index(
        "stop_and_prove_guest_extinction"
    )
    assert "context, 0, &guest_extinction" in revoke
    assert "context, 1, &guest_extinction" in revoke
    assert "PLAMEN_BROKER_V2_APPLE_LIFECYCLE_REVOKED" in revoke
    assert revoke.index("collect_terminal") < revoke.index(
        "plamen_broker_v2_apple_lifecycle_delete(context"
    )
    deletion = source[
        source.index("plamen_broker_v2_apple_lifecycle_delete(") :
    ]
    assert deletion.index('remove[1] = "delete"') < deletion.index(
        "container_absent"
    )
    assert deletion.index("container_absent") < deletion.index("DELETE_RECORD")


def test_id_is_derived_from_request_and_create_operation_key() -> None:
    source = (
        ROOT / "native" / "darwin" / "plamen_broker_v2_apple_container_lifecycle.c"
    ).read_text(encoding="utf-8")
    validation = source[source.index("static int validate_spec") :]
    assert "plamen_broker_v2_apple_container_derive_id" in validation
    assert "spec->create_operation_key" in validation
    assert "strcmp(derived_id, spec->container_id)" in validation


def test_mount_descriptors_are_retained_and_revalidated_before_start() -> None:
    source = (
        ROOT / "native" / "darwin" / "plamen_broker_v2_apple_container_lifecycle.c"
    ).read_text(encoding="utf-8")
    copy = source[source.index("static int copy_context") :]
    assert "context->mount_fds[index] = duplicate_fd" in copy
    start = source[source.index("plamen_broker_v2_apple_lifecycle_start(") :]
    assert "context_mount_recensus(context, prepared_sha)" in start
    assert "context->mount_roster_sha256" in start


def test_retained_and_observed_output_bounds_are_distinct() -> None:
    process = (
        ROOT / "native" / "darwin" / "plamen_broker_v2_process.c"
    ).read_text(encoding="utf-8")
    assert (
        "capture_init(&process->stdout_capture, process->stdout_spool_limit,\n"
        "            PLAMEN_BROKER_V2_OBSERVED_MAX)"
    ) in process
    assert "*full_size = process->terminal.stdout_size" in process
    assert "*full_size = process->terminal.stderr_size" in process


def test_terminal_digest_binds_extinction_cleanup_and_flags() -> None:
    source = (
        ROOT / "native" / "darwin" / "plamen_broker_v2_apple_container_lifecycle.c"
    ).read_text(encoding="utf-8")
    terminal = source[source.index("static int encode_terminal") :]
    assert "bytes + 464, receipt->native_process_extinction_sha256" in terminal
    assert "bytes + 496, receipt->cleanup_sha256" in terminal
    assert "bytes[528] = receipt->descendants_extinct" in terminal
    assert "TERMINAL_DIGEST_OFFSET" in terminal
    assert "persist_terminal_record(context->state_fd, receipt)" in terminal


def test_actual_inputs_derive_and_gate_every_execution_commitment(
    lifecycle_library: ctypes.CDLL, tmp_path: Path,
) -> None:
    spec, _receipt_value, arguments, descriptors, _sources = _spec(
        lifecycle_library, tmp_path
    )
    try:
        assert lifecycle_library.plamen_broker_v2_apple_lifecycle_test_validate_spec(
            ctypes.byref(spec)
        ) == 0
        supplied = (
            "spec_sha256", "launch_request_sha256", "driver_argv_sha256",
            "driver_environment_sha256", "driver_cwd_sha256",
            "driver_stdin_sha256", "pass_fd_roster_sha256",
        )
        for name in supplied:
            original = bytes(getattr(spec, name))
            getattr(spec, name)[0] ^= 1
            assert lifecycle_library.plamen_broker_v2_apple_lifecycle_test_validate_spec(
                ctypes.byref(spec)
            ) != 0, name
            getattr(spec, name)[:] = original

        baseline = _Commitments()
        assert lifecycle_library.plamen_broker_v2_apple_lifecycle_derive_commitments(
            ctypes.byref(spec), ctypes.byref(baseline)
        ) == 0
        assert all(any(bytes(getattr(baseline, name))) for name, _ in baseline._fields_)

        cases: list[tuple[str, tuple[str, ...]]] = [
            ("entrypoint", ("driver_argv_sha256", "create_argv_sha256",
                            "spec_sha256", "launch_request_sha256")),
            ("arguments", ("driver_argv_sha256", "create_argv_sha256",
                           "spec_sha256", "launch_request_sha256")),
            ("cwd", ("driver_cwd_sha256", "create_argv_sha256",
                     "spec_sha256", "launch_request_sha256")),
            ("cpu", ("create_argv_sha256", "spec_sha256",
                     "launch_request_sha256")),
            ("rosetta", ("create_argv_sha256", "spec_sha256",
                         "launch_request_sha256")),
        ]
        for label, changed in cases:
            fresh, _r, fresh_arguments, fresh_descriptors, _s = _spec(
                lifecycle_library, tmp_path / label
            )
            try:
                before = _Commitments()
                assert lifecycle_library.plamen_broker_v2_apple_lifecycle_derive_commitments(
                    ctypes.byref(fresh), ctypes.byref(before)
                ) == 0
                if label == "arguments":
                    fresh_arguments[1] = b"--changed"
                elif label == "entrypoint":
                    fresh.entrypoint = b"/opt/plamen/changed"
                elif label == "cwd":
                    fresh.working_directory = b"/workspace/scratch"
                elif label == "cpu":
                    fresh.cpus = 5
                elif label == "rosetta":
                    fresh.rosetta_required = 1
                candidate = _Commitments()
                assert lifecycle_library.plamen_broker_v2_apple_lifecycle_derive_commitments(
                    ctypes.byref(fresh), ctypes.byref(candidate),
                ) == 0
                for name in changed:
                    assert bytes(getattr(candidate, name)) != bytes(
                        getattr(before, name)
                    ), (label, name)
            finally:
                for descriptor in fresh_descriptors:
                    os.close(descriptor)

        stdin_file = tmp_path / "stdin"
        stdin_file.write_bytes(b"bounded input")
        alternate_stdin = os.open(stdin_file, os.O_RDONLY)
        try:
            spec, _r, _a, extra_descriptors, _s = _spec(
                lifecycle_library, tmp_path / "stdin-case"
            )
            before = _Commitments()
            assert lifecycle_library.plamen_broker_v2_apple_lifecycle_derive_commitments(
                ctypes.byref(spec), ctypes.byref(before)
            ) == 0
            spec.stdin_fd = alternate_stdin
            candidate = _Commitments()
            assert lifecycle_library.plamen_broker_v2_apple_lifecycle_derive_commitments(
                ctypes.byref(spec), ctypes.byref(candidate)
            ) == 0
            assert bytes(candidate.driver_stdin_sha256) != bytes(
                before.driver_stdin_sha256
            )
            assert bytes(candidate.launch_request_sha256) != bytes(
                before.launch_request_sha256
            )
        finally:
            os.close(alternate_stdin)
            for descriptor in extra_descriptors:
                os.close(descriptor)

        mount_spec, _r, _a, mount_descriptors, _s = _spec(
            lifecycle_library, tmp_path / "mount-case"
        )
        replacement = tmp_path / "replacement-mount"
        replacement.mkdir()
        replacement_fd = os.open(replacement, os.O_RDONLY)
        try:
            before = _Commitments()
            assert lifecycle_library.plamen_broker_v2_apple_lifecycle_derive_commitments(
                ctypes.byref(mount_spec), ctypes.byref(before)
            ) == 0
            identity = (ctypes.c_uint8 * 32)()
            assert lifecycle_library.plamen_broker_v2_fd_identity(
                replacement_fd, identity
            ) == 0
            mount_spec.mounts[0].source_fd = replacement_fd
            mount_spec.mounts[0].source_path = os.fsencode(replacement)
            mount_spec.mounts[0].expected_identity_sha256[:] = bytes(identity)
            candidate = _Commitments()
            assert lifecycle_library.plamen_broker_v2_apple_lifecycle_derive_commitments(
                ctypes.byref(mount_spec), ctypes.byref(candidate)
            ) == 0
            for name in ("mount_roster_sha256", "create_argv_sha256",
                         "spec_sha256", "launch_request_sha256"):
                assert bytes(getattr(candidate, name)) != bytes(getattr(before, name))
        finally:
            os.close(replacement_fd)
            for descriptor in mount_descriptors:
                os.close(descriptor)
    finally:
        for descriptor in descriptors:
            os.close(descriptor)


def test_dynamic_worker_mounts_are_exact_unique_and_non_overlapping(
    lifecycle_library: ctypes.CDLL, tmp_path: Path,
) -> None:
    spec, _receipt_value, arguments, descriptors, sources = _spec(
        lifecycle_library, tmp_path
    )
    try:
        spec.version = 2
        spec.mount_count = 10
        spec.dynamic_mounts = 1
        spec.mounts[9].target_path = b"/workspace/worker-scope"
        commitments = _Commitments()
        assert lifecycle_library.plamen_broker_v2_apple_lifecycle_derive_commitments(
            ctypes.byref(spec), ctypes.byref(commitments)
        ) == 0
        for name in (
            "spec_sha256", "launch_request_sha256", "driver_argv_sha256",
            "driver_environment_sha256", "driver_cwd_sha256",
            "driver_stdin_sha256", "pass_fd_roster_sha256",
        ):
            getattr(spec, name)[:] = bytes(getattr(commitments, name))
        assert lifecycle_library.plamen_broker_v2_apple_lifecycle_test_validate_spec(
            ctypes.byref(spec)
        ) == 0

        spec.mounts[9].target_path = b"/workspace/project/nested"
        assert lifecycle_library.plamen_broker_v2_apple_lifecycle_derive_commitments(
            ctypes.byref(spec), ctypes.byref(commitments)
        ) != 0
        spec.mounts[9].target_path = b"/workspace/worker-scope"
        spec.mount_count = 13
        assert lifecycle_library.plamen_broker_v2_apple_lifecycle_derive_commitments(
            ctypes.byref(spec), ctypes.byref(commitments)
        ) != 0
    finally:
        _ = arguments, sources
        for descriptor in descriptors:
            os.close(descriptor)


def _inspect_document(spec: _LifecycleSpec) -> list[dict[str, object]]:
    mounts = []
    count = spec.mount_count if spec.version == 2 else 10
    for item in spec.mounts[:count]:
        mounts.append({
            "type": {"virtiofs": {}},
            "source": os.fsdecode(item.source_path),
            "destination": os.fsdecode(item.target_path),
            "options": ["ro"] if item.readonly else [],
        })
    return [{
        "id": os.fsdecode(spec.container_id),
        "configuration": {
            "id": os.fsdecode(spec.container_id),
            "image": {
                "reference": os.fsdecode(spec.runtime_image_reference),
                "descriptor": {
                    "digest": os.fsdecode(spec.runtime_image_reference).split("@", 1)[1],
                    "mediaType": "application/vnd.oci.image.index.v1+json",
                    "size": 321,
                },
            },
            "mounts": mounts,
            "publishedPorts": [], "publishedSockets": [], "labels": {},
            "sysctls": {}, "networks": [], "dns": None,
            "rosetta": bool(spec.rosetta_required),
            "initProcess": {
                "executable": os.fsdecode(spec.entrypoint),
                "arguments": [os.fsdecode(spec.arguments[index])
                              for index in range(spec.argument_count)],
                "environment": [],
                "workingDirectory": os.fsdecode(spec.working_directory),
                "terminal": False,
                "user": {"id": {"uid": spec.uid, "gid": spec.gid}},
                "supplementalGroups": [], "rlimits": [],
            },
            "platform": {
                "os": "linux",
                "architecture": "amd64" if spec.rosetta_required else "arm64",
            },
            "resources": {"cpus": spec.cpus, "memoryInBytes": spec.memory_bytes,
                          "storage": None, "cpuOverhead": 1},
            "runtimeHandler": "container-runtime-linux",
            "virtualization": False, "ssh": False, "readOnly": True,
            "useInit": True, "capAdd": [], "capDrop": ["ALL"],
            "shmSize": None, "stopSignal": None, "maskedPaths": None,
            "readonlyPaths": None, "creationDate": "2026-09-08T00:00:00Z",
        },
        "status": {"state": "stopped", "networks": []},
    }]


def _validate_inspect(
    library: ctypes.CDLL, spec: _LifecycleSpec, document: object,
) -> int:
    encoded = json.dumps(document, separators=(",", ":")).encode()
    buffer = ctypes.create_string_buffer(encoded)
    observation = (ctypes.c_uint8 * 32)()
    return library.plamen_broker_v2_apple_lifecycle_test_validate_inspect(
        buffer, len(encoded), ctypes.byref(spec), b"stopped", observation
    )


def test_post_create_inspect_attests_the_complete_fixed_configuration(
    lifecycle_library: ctypes.CDLL, tmp_path: Path,
) -> None:
    spec, _receipt_value, _arguments, descriptors, _sources = _spec(
        lifecycle_library, tmp_path
    )
    try:
        baseline = _inspect_document(spec)
        assert _validate_inspect(lifecycle_library, spec, baseline) == 0
        config = baseline[0]["configuration"]
        assert isinstance(config, dict)
        process = config["initProcess"]
        assert isinstance(process, dict)
        mutations = [
            lambda d: d[0].update(id="plamen-" + "f" * 32),
            lambda d: d[0]["configuration"]["image"]["descriptor"].update(
                digest="sha256:" + "b" * 64
            ),
            lambda d: d[0]["configuration"].update(readOnly=False),
            lambda d: d[0]["configuration"].update(useInit=False),
            lambda d: d[0]["configuration"].update(networks=[{"default": {}}]),
            lambda d: d[0]["configuration"].update(dns=["1.1.1.1"]),
            lambda d: d[0]["configuration"]["mounts"][0].update(options=[]),
            lambda d: d[0]["configuration"]["mounts"].pop(),
            lambda d: d[0]["configuration"]["initProcess"].update(
                executable="/bin/sh"
            ),
            lambda d: d[0]["configuration"]["initProcess"].update(
                arguments=["audit"]
            ),
            lambda d: d[0]["configuration"]["initProcess"].update(
                workingDirectory="/"
            ),
            lambda d: d[0]["configuration"]["initProcess"]["user"]["id"].update(
                uid=0
            ),
            lambda d: d[0]["configuration"]["resources"].update(cpus=5),
            lambda d: d[0]["configuration"]["platform"].update(
                architecture="amd64"
            ),
            lambda d: d[0]["configuration"].update(capDrop=[]),
            lambda d: d[0]["configuration"].update(runtimeHandler="runc"),
            lambda d: d[0]["configuration"].update(futureSecurityField=True),
            lambda d: d[0]["status"].update(networks=[{"default": {}}]),
        ]
        for index, mutate in enumerate(mutations):
            candidate = json.loads(json.dumps(baseline))
            mutate(candidate)
            assert _validate_inspect(lifecycle_library, spec, candidate) != 0, index
    finally:
        for descriptor in descriptors:
            os.close(descriptor)


def test_exact_create_and_list_output_parsers_reject_ambiguous_forms(
    lifecycle_library: ctypes.CDLL,
) -> None:
    container_id = b"plamen-" + b"a" * 32

    def exact(value: bytes) -> int:
        buffer = ctypes.create_string_buffer(value)
        return lifecycle_library.plamen_broker_v2_apple_lifecycle_test_exact_id_output(
            buffer, len(value), container_id
        )

    assert exact(container_id + b"\n") == 0
    for value in (container_id, container_id + b"\r\n", container_id + b"\n\n",
                  b"prefix" + container_id, container_id + b" "):
        assert exact(value) != 0

    def absent(value: bytes) -> int:
        buffer = ctypes.create_string_buffer(value)
        return lifecycle_library.plamen_broker_v2_apple_lifecycle_test_list_proves_absent(
            buffer, len(value), container_id
        )

    def listing(*ids: str) -> bytes:
        return json.dumps([
            {"status": "stopped", "networks": [],
             "configuration": {"id": value}}
            for value in ids
        ], separators=(",", ":"), sort_keys=True).encode("ascii")

    assert absent(b"[]") == 0
    assert absent(listing("ordinary-container", "second.container")) == 0
    for value in (
        listing(container_id.decode("ascii")), b"", b"not-json",
        listing("duplicate", "duplicate"), listing("../escape"),
        b'[{"status":"stopped","networks":[],"configuration":{}}]',
        b'[{"status":"stopped","networks":[],"configuration":{"id":"ok"},"future":true}]',
    ):
        assert absent(value) != 0
