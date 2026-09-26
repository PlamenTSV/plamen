from __future__ import annotations

import ctypes
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess

import pytest

ROOT = Path(__file__).resolve().parent.parent
pytestmark = pytest.mark.skipif(platform.system() != "Darwin", reason="Darwin only")


class Capability(ctypes.Structure):
    _fields_ = [
        ("version", ctypes.c_uint32),
        ("runtime_image_reference", ctypes.c_char_p),
        ("image_closure_sha256", ctypes.c_uint8 * 32),
        ("provider_admission_sha256", ctypes.c_uint8 * 32),
        ("rosetta_authority_sha256", ctypes.c_uint8 * 32),
        ("network_isolation_authority_sha256", ctypes.c_uint8 * 32),
        ("custody_receipt_sha256", ctypes.c_uint8 * 32),
        ("rosetta_required", ctypes.c_uint8),
    ]


class Projection(ctypes.Structure):
    _fields_ = [
        ("version", ctypes.c_uint32),
        ("original_source_scope_sha256", ctypes.c_uint8 * 32),
        ("source_copy_closure_sha256", ctypes.c_uint8 * 32),
        ("source_copy_file_count", ctypes.c_uint64),
        ("source_copy_directory_count", ctypes.c_uint64),
        ("source_copy_bytes", ctypes.c_uint64),
        ("js_lock_selection_sha256", ctypes.c_uint8 * 32),
        ("dependency_materialization_receipt_sha256", ctypes.c_uint8 * 32),
        ("materialized_node_modules_closure_sha256", ctypes.c_uint8 * 32),
        ("materialized_node_modules_file_count", ctypes.c_uint64),
        ("materialized_node_modules_directory_count", ctypes.c_uint64),
        ("materialized_node_modules_bytes", ctypes.c_uint64),
        ("materialization_lineage_sha256", ctypes.c_uint8 * 32),
        ("materialization_lineage_byte_count", ctypes.c_uint64),
        ("native_materialization_request_sha256", ctypes.c_uint8 * 32),
        ("analysis_workspace_closure_sha256", ctypes.c_uint8 * 32),
        ("analysis_workspace_file_count", ctypes.c_uint64),
        ("analysis_workspace_directory_count", ctypes.c_uint64),
        ("analysis_workspace_bytes", ctypes.c_uint64),
        ("native_projection_custody_sha256", ctypes.c_uint8 * 32),
        ("host_descriptor_identity_sha256", ctypes.c_uint8 * 32),
        ("guest_mount_identity_sha256", ctypes.c_uint8 * 32),
        ("invocation_sha256", ctypes.c_uint8 * 32),
    ]


class Binding(ctypes.Structure):
    _fields_ = [
        ("version", ctypes.c_uint32), ("tool_id", ctypes.c_char_p),
        ("run_id", ctypes.c_char_p),
        *[(name, ctypes.c_uint8 * 32) for name in (
            "request_sha256", "custody_receipt_sha256",
            "materialization_receipt_sha256",
            "materialization_lineage_schema_sha256", "snapshot_sha256",
            "analysis_projection_sha256",
        )],
        ("analysis_projection_bytes", ctypes.c_uint64),
        ("launch_object_sha256", ctypes.c_uint8 * 32),
        ("launch_object_bytes", ctypes.c_uint64),
        *[(name, ctypes.c_uint8 * 32) for name in (
            "governance_sha256", "version_lock_sha256",
            "source_descriptor_identity_sha256", "source_scope_sha256",
            "argv_sha256", "environment_sha256", "cwd_sha256",
            "mounts_sha256", "native_runtime_identity_sha256",
            "network_authority_sha256",
            "allowed_path_manifest_sha256",
        )],
        ("timeout_ms", ctypes.c_uint64), ("memory_bytes", ctypes.c_uint64),
        ("stdout_bound_bytes", ctypes.c_uint64),
        ("stderr_bound_bytes", ctypes.c_uint64),
        ("output_file_bound_bytes", ctypes.c_uint64),
    ]


class GuestTerminal(ctypes.Structure):
    _fields_ = [
        ("version", ctypes.c_uint32), ("tool_id", ctypes.c_char * 33),
        *[(name, ctypes.c_uint8 * 32) for name in (
            "custody_receipt_sha256", "materialization_receipt_sha256",
            "snapshot_sha256", "launch_object_sha256",
        )],
        ("launch_object_bytes", ctypes.c_uint64),
        *[(name, ctypes.c_uint8 * 32) for name in (
            "post_spawn_dynamic_identity_sha256", "argv_sha256",
            "environment_sha256", "cwd_sha256", "mounts_sha256",
        )],
        ("returncode", ctypes.c_int32),
        ("stdout_observed_bytes", ctypes.c_uint64),
        ("stdout_retained_bytes", ctypes.c_uint64),
        ("stdout_sha256", ctypes.c_uint8 * 32),
        ("stderr_observed_bytes", ctypes.c_uint64),
        ("stderr_retained_bytes", ctypes.c_uint64),
        ("stderr_sha256", ctypes.c_uint8 * 32),
        ("artifact_manifest_sha256", ctypes.c_uint8 * 32),
        ("artifact_count", ctypes.c_uint64),
        ("artifact_bytes", ctypes.c_uint64),
        ("network_denied", ctypes.c_uint8),
        ("population_zero", ctypes.c_uint8),
        ("cleanup_complete", ctypes.c_uint8),
        ("duration_ms", ctypes.c_uint64),
        ("peak_memory_bytes", ctypes.c_uint64),
        ("output_limit_exceeded", ctypes.c_uint8),
        ("record_hmac_sha256", ctypes.c_uint8 * 32),
    ]


def _fill(target: ctypes.Array[ctypes.c_uint8], value: int) -> None:
    target[:] = bytes([value]) * 32


@pytest.fixture(scope="module")
def native(tmp_path_factory: pytest.TempPathFactory) -> ctypes.CDLL:
    output = tmp_path_factory.mktemp("tool-custody") / "tool-custody.dylib"
    subprocess.run([
        "/usr/bin/clang", "-std=c11", "-Wall", "-Wextra", "-Werror",
        "-fblocks", "-dynamiclib", "-DPLAMEN_BROKER_V2_TOOL_CUSTODY_TEST_ONLY",
        "-I", str(ROOT / "native/include"),
        "-I", str(ROOT / "native/darwin"),
        str(ROOT / "native/darwin/plamen_broker_v2_process.c"),
        str(ROOT / "native/darwin/plamen_broker_v2_process_custodian.c"),
        str(ROOT / "native/darwin/plamen_broker_v2_process_custody_client.c"),
        str(ROOT / "native/darwin/plamen_broker_v2_apple_container.c"),
        str(ROOT / "native/darwin/plamen_broker_v2_apple_container_lifecycle.c"),
        str(ROOT / "native/darwin/plamen_broker_v2_tool_custody.c"),
        str(ROOT / "native/posix/plamen_broker_v2_protocol.c"),
        "-framework", "Security", "-framework", "CoreFoundation",
        "-framework", "Foundation",
        "-o", str(output),
    ], cwd=ROOT, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
       stdin=subprocess.DEVNULL, timeout=30)
    library = ctypes.CDLL(str(output))
    for name, input_type in (
        ("plamen_broker_v2_tool_custody_render_apple_authority", Capability),
        ("plamen_broker_v2_tool_custody_render_snapshot_authority", Capability),
        ("plamen_broker_v2_tool_custody_render_analysis_projection", Projection),
    ):
        function = getattr(library, name)
        function.argtypes = [ctypes.POINTER(input_type), ctypes.c_void_p,
                             ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t),
                             ctypes.POINTER(ctypes.c_uint8)]
        function.restype = ctypes.c_int
    library.plamen_broker_v2_tool_guest_terminal_encode.argtypes = [
        ctypes.POINTER(Binding), ctypes.POINTER(GuestTerminal),
        ctypes.POINTER(ctypes.c_uint8), ctypes.c_void_p,
    ]
    library.plamen_broker_v2_tool_guest_terminal_encode.restype = ctypes.c_int
    library.plamen_broker_v2_tool_guest_terminal_decode.argtypes = [
        ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_uint8),
        ctypes.POINTER(Binding), ctypes.POINTER(GuestTerminal),
    ]
    library.plamen_broker_v2_tool_guest_terminal_decode.restype = ctypes.c_int
    library.plamen_broker_v2_tool_custody_test_render_terminal_v3.argtypes = [
        ctypes.POINTER(Binding), ctypes.POINTER(GuestTerminal),
        ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t),
        ctypes.POINTER(ctypes.c_uint8),
    ]
    library.plamen_broker_v2_tool_custody_test_render_terminal_v3.restype = ctypes.c_int
    return library


def _render(native: ctypes.CDLL, name: str, value: ctypes.Structure) -> tuple[bytes, bytes]:
    output = ctypes.create_string_buffer(8192)
    size = ctypes.c_size_t()
    digest = (ctypes.c_uint8 * 32)()
    assert getattr(native, name)(ctypes.byref(value), output, len(output),
                                 ctypes.byref(size), digest) == 0
    return output.raw[:size.value], bytes(digest)


def _capability() -> Capability:
    value = Capability(version=1, runtime_image_reference=(
        b"registry.example/plamen/runtime@sha256:" + b"a" * 64
    ), rosetta_required=1)
    for index, name in enumerate((
        "image_closure_sha256", "provider_admission_sha256",
        "rosetta_authority_sha256", "network_isolation_authority_sha256",
        "custody_receipt_sha256",
    ), start=1):
        _fill(getattr(value, name), index)
    return value


def test_native_capabilities_are_canonical_and_python_consumer_compatible(
    native: ctypes.CDLL,
) -> None:
    capability = _capability()
    apple_raw, apple_sha = _render(
        native, "plamen_broker_v2_tool_custody_render_apple_authority", capability
    )
    apple = json.loads(apple_raw)
    assert apple_raw == json.dumps(
        apple, sort_keys=True, separators=(",", ":")
    ).encode("ascii")
    assert hashlib.sha256(apple_raw).digest() == apple_sha
    assert apple["architecture"] == "amd64"
    assert apple["rosetta_required"] is True
    assert apple["rootfs_readonly"] is True
    assert apple["network_policy"] == "DENY_ALL"

    raw, digest = _render(
        native, "plamen_broker_v2_tool_custody_render_snapshot_authority", capability
    )
    receipt = json.loads(raw)
    assert raw == json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode()
    assert receipt["receipt_sha256"] == digest.hex()
    assert receipt["schema"] == "plamen.snapshot-bound-tool-custody.v1"
    assert receipt["immutable_launch_authority"] == (
        "PRIVATE_IMMUTABLE_PROJECTED_CLOSURE"
    )


def test_analysis_projection_receipt_binds_complete_two_stage_lineage(
    native: ctypes.CDLL,
) -> None:
    value = Projection(
        version=1,
        source_copy_file_count=120,
        source_copy_directory_count=15,
        source_copy_bytes=45678,
        materialized_node_modules_file_count=500,
        materialized_node_modules_directory_count=80,
        materialized_node_modules_bytes=234567,
        materialization_lineage_byte_count=4096,
        analysis_workspace_file_count=620,
        analysis_workspace_directory_count=95,
        analysis_workspace_bytes=280245,
    )
    digest_fields = [name for name, field_type in value._fields_
                     if field_type == ctypes.c_uint8 * 32]
    for index, name in enumerate(digest_fields, start=1):
        _fill(getattr(value, name), index)
    raw, digest = _render(
        native, "plamen_broker_v2_tool_custody_render_analysis_projection", value
    )
    receipt = json.loads(raw)
    assert raw == json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode()
    unsigned = dict(receipt)
    assert unsigned.pop("receipt_sha256") == digest.hex()
    assert hashlib.sha256(json.dumps(
        unsigned, sort_keys=True, separators=(",", ":")
    ).encode()).digest() == digest
    assert receipt["receipt_byte_count"] == len(raw)
    assert receipt["component_kind"] == "evm_analysis_projection.v1"
    assert receipt["original_source_scope_sha256"] == "01" * 32
    assert receipt["source_copy_file_count"] == 120
    assert receipt["materialized_node_modules_file_count"] == 500
    assert receipt["analysis_workspace_file_count"] == 620
    assert receipt["materialization_lineage_byte_count"] == 4096
    assert receipt["guest_mount_path"] == "/workspace/project"
    assert receipt["project_read_only"] is True
    assert receipt["writable_mounts"] == ["/workspace/scratch", "/workspace/state"]


def _binding_and_terminal() -> tuple[Binding, GuestTerminal]:
    binding = Binding(version=1, tool_id=b"slither", run_id=b"run-15",
                      analysis_projection_bytes=777, launch_object_bytes=555,
                      timeout_ms=30_000, memory_bytes=2**30,
                      stdout_bound_bytes=4096, stderr_bound_bytes=4096,
                      output_file_bound_bytes=2**20)
    fields = [name for name, kind in binding._fields_ if kind == ctypes.c_uint8 * 32]
    for index, name in enumerate(fields, start=1):
        _fill(getattr(binding, name), index)
    terminal = GuestTerminal(
        version=1, tool_id=b"slither", returncode=0,
        launch_object_bytes=binding.launch_object_bytes,
        stdout_observed_bytes=3, stdout_retained_bytes=3,
        stderr_observed_bytes=0, stderr_retained_bytes=0,
        artifact_count=1, artifact_bytes=3, duration_ms=17,
        peak_memory_bytes=4096, output_limit_exceeded=0,
        network_denied=1, population_zero=1, cleanup_complete=1,
    )
    for name in (
        "custody_receipt_sha256", "materialization_receipt_sha256",
        "snapshot_sha256", "launch_object_sha256", "argv_sha256",
        "environment_sha256", "cwd_sha256", "mounts_sha256",
    ):
        getattr(terminal, name)[:] = bytes(getattr(binding, name))
    _fill(terminal.post_spawn_dynamic_identity_sha256, 29)
    _fill(terminal.artifact_manifest_sha256, 30)
    terminal.stdout_sha256[:] = hashlib.sha256(b"abc").digest()
    terminal.stderr_sha256[:] = hashlib.sha256(b"").digest()
    return binding, terminal


def test_guest_terminal_hmac_binds_every_execution_control_and_rejects_tamper(
    native: ctypes.CDLL,
) -> None:
    binding, terminal = _binding_and_terminal()
    key = (ctypes.c_uint8 * 32).from_buffer_copy(b"K" * 32)
    record = ctypes.create_string_buffer(1024)
    assert native.plamen_broker_v2_tool_guest_terminal_encode(
        ctypes.byref(binding), ctypes.byref(terminal), key, record
    ) == 0
    decoded = GuestTerminal()
    assert native.plamen_broker_v2_tool_guest_terminal_decode(
        record, len(record), key, ctypes.byref(binding), ctypes.byref(decoded)
    ) == 0
    assert decoded.population_zero == 1 and decoded.network_denied == 1

    for name, kind in binding._fields_:
        if kind != ctypes.c_uint8 * 32:
            continue
        candidate = Binding.from_buffer_copy(binding)
        getattr(candidate, name)[0] ^= 1
        assert native.plamen_broker_v2_tool_guest_terminal_decode(
            record, len(record), key, ctypes.byref(candidate), ctypes.byref(decoded)
        ) != 0, name
    tampered = ctypes.create_string_buffer(record.raw)
    tampered[700] = bytes([tampered[700][0] ^ 1])
    assert native.plamen_broker_v2_tool_guest_terminal_decode(
        tampered, len(tampered), key, ctypes.byref(binding), ctypes.byref(decoded)
    ) != 0
    wrong_key = (ctypes.c_uint8 * 32).from_buffer_copy(b"J" * 32)
    assert native.plamen_broker_v2_tool_guest_terminal_decode(
        record, len(record), wrong_key, ctypes.byref(binding), ctypes.byref(decoded)
    ) != 0


def test_guest_terminal_false_security_claims_are_never_encodable(
    native: ctypes.CDLL,
) -> None:
    binding, terminal = _binding_and_terminal()
    key = (ctypes.c_uint8 * 32).from_buffer_copy(b"K" * 32)
    record = ctypes.create_string_buffer(1024)
    for field in ("network_denied", "population_zero", "cleanup_complete"):
        setattr(terminal, field, 0)
        assert native.plamen_broker_v2_tool_guest_terminal_encode(
            ctypes.byref(binding), ctypes.byref(terminal), key, record
        ) != 0, field
        setattr(terminal, field, 1)


def test_source_contains_no_stopped_state_extinction_inference() -> None:
    source = (ROOT / "native/darwin/plamen_broker_v2_tool_custody.c").read_text()
    join = source[source.index("lifecycle_chain_valid") :]
    assert "guest_process_extinct" not in join
    assert "backend_egress_revoked" not in join
    assert "terminal->network_denied == 1" in source
    assert "terminal->population_zero == 1" in source


def test_native_terminal_v3_exact_bytes_match_python_schema_contract(
    native: ctypes.CDLL,
) -> None:
    binding, terminal = _binding_and_terminal()
    output = ctypes.create_string_buffer(8192)
    size = ctypes.c_size_t()
    digest = (ctypes.c_uint8 * 32)()
    assert native.plamen_broker_v2_tool_custody_test_render_terminal_v3(
        ctypes.byref(binding), ctypes.byref(terminal), output, len(output),
        ctypes.byref(size), digest,
    ) == 0
    raw = output.raw[:size.value]
    value = json.loads(raw)
    assert raw == json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    assert hashlib.sha256(raw).digest() == bytes(digest)
    assert set(value) == {
        "schema", "request_sha256", "run_id", "audit_snapshot_sha256",
        "tool_id", "source_descriptor_sha256",
        "materialization_lineage_sha256", "toolchain_governance_sha256",
        "toolchain_version_lock_sha256", "native_runtime_identity_sha256",
        "argv_sha256", "environment_sha256", "cwd_sha256", "mounts_sha256",
        "source_scope_sha256", "post_spawn_dynamic_identity_sha256",
        "egress_policy", "egress_denied", "exit_state", "returncode",
        "duration_ms", "peak_memory_bytes", "stdout_sha256",
        "stdout_observed_bytes", "stdout_retained_bytes", "stderr_sha256",
        "stderr_observed_bytes", "stderr_retained_bytes", "output_tree_sha256",
        "output_file_count", "output_bytes", "output_limit_exceeded",
        "population_zero", "cleanup_complete", "truncation_debt",
    }
    assert value["schema"] == "plamen.snapshot-bound-tool-execution-terminal.v3"
    assert value["request_sha256"] == bytes(binding.request_sha256).hex()
    assert value["run_id"] == "run-15"
    assert value["audit_snapshot_sha256"] == bytes(binding.snapshot_sha256).hex()
    assert value["materialization_lineage_sha256"] == bytes(
        binding.materialization_lineage_schema_sha256
    ).hex()
    assert value["native_runtime_identity_sha256"] == bytes(
        binding.native_runtime_identity_sha256
    ).hex()
    assert value["source_descriptor_sha256"] == bytes(
        binding.source_descriptor_identity_sha256
    ).hex()
    assert value["output_tree_sha256"] == bytes(
        terminal.artifact_manifest_sha256
    ).hex()
    assert value["exit_state"] == "COMPLETED"
    assert value["truncation_debt"] is None
    assert value["egress_policy"] == "DENY_ALL"
    assert value["output_limit_exceeded"] is False
    assert "terminal_sha256" not in value
