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

MAX_FDS = 16
PAYLOAD_MAX = 1024 * 1024

JS_LANE = 1
JS_AUTHENTICATE = 0x2101
JS_PREPARE = 0x2102
JS_EXECUTE = 0x2103
JS_REPLAY = 0x2104
JS_RUNTIME_IDENTITY = 0x2105
MANAGED_LANE = 2
MANAGED_PREPARE = 0x2202
MANAGED_EXECUTE = 0x2203
SNAPSHOT_LANE = 4
SNAPSHOT_PREPARE = 0x2403
SNAPSHOT_EXECUTE = 0x2404


class FDMetadata(ctypes.Structure):
    _fields_ = [
        ("purpose", ctypes.c_uint16),
        ("target", ctypes.c_uint16),
        ("access_mode", ctypes.c_uint8),
        ("identity", ctypes.c_uint8 * 32),
    ]


class SpecializedRequest(ctypes.Structure):
    _fields_ = [
        ("lane", ctypes.c_uint16),
        ("method", ctypes.c_uint16),
        ("flags", ctypes.c_uint16),
        ("capability_id", ctypes.c_uint8 * 32),
        ("operation_nonce", ctypes.c_uint8 * 32),
        ("authority_binding_sha256", ctypes.c_uint8 * 32),
        ("fd_count", ctypes.c_uint16),
        ("descriptors", FDMetadata * MAX_FDS),
        ("payload_size", ctypes.c_uint32),
        ("payload", ctypes.POINTER(ctypes.c_uint8)),
    ]


class PlanInput(ctypes.Structure):
    _fields_ = [
        ("version", ctypes.c_uint32),
        ("request", ctypes.POINTER(SpecializedRequest)),
        ("request_wire", ctypes.POINTER(ctypes.c_uint8)),
        ("request_wire_size", ctypes.c_size_t),
        ("request_sha256", ctypes.c_uint8 * 32),
        ("effects_context_sha256", ctypes.c_uint8 * 32),
        ("fds", ctypes.POINTER(ctypes.c_int)),
        ("fd_count", ctypes.c_size_t),
    ]


class PlanView(ctypes.Structure):
    _fields_ = [
        ("version", ctypes.c_uint32),
        ("lane", ctypes.c_uint16),
        ("method", ctypes.c_uint16),
        ("flags", ctypes.c_uint16),
        ("authority_binding_sha256", ctypes.c_uint8 * 32),
        ("operation_nonce", ctypes.c_uint8 * 32),
        ("request_sha256", ctypes.c_uint8 * 32),
        ("effects_context_sha256", ctypes.c_uint8 * 32),
        ("archive_root_identity_sha256", ctypes.c_uint8 * 32),
        ("archive_manifest_sha256", ctypes.c_uint8 * 32),
        ("archive_census_sha256", ctypes.c_uint8 * 32),
        ("payload", ctypes.POINTER(ctypes.c_uint8)),
        ("payload_size", ctypes.c_size_t),
        ("descriptors", ctypes.POINTER(FDMetadata)),
        ("fds", ctypes.POINTER(ctypes.c_int)),
        ("fd_count", ctypes.c_size_t),
    ]


class Evidence(ctypes.Structure):
    _fields_ = [
        ("version", ctypes.c_uint32),
        ("lane", ctypes.c_uint16),
        ("method", ctypes.c_uint16),
        ("authority_binding_sha256", ctypes.c_uint8 * 32),
        ("operation_nonce", ctypes.c_uint8 * 32),
        ("request_sha256", ctypes.c_uint8 * 32),
        ("effects_context_sha256", ctypes.c_uint8 * 32),
        ("effect_receipt_sha256", ctypes.c_uint8 * 32),
        ("lifecycle_receipt_sha256", ctypes.c_uint8 * 32),
        ("durable_operation_sha256", ctypes.c_uint8 * 32),
        ("network_policy_sha256", ctypes.c_uint8 * 32),
        ("observed_egress_sha256", ctypes.c_uint8 * 32),
        ("effect_authenticated", ctypes.c_uint8),
        ("effect_completed", ctypes.c_uint8),
        ("durable_operation", ctypes.c_uint8),
        ("provider_authenticated", ctypes.c_uint8),
        ("network_policy_enforced", ctypes.c_uint8),
        ("population_zero", ctypes.c_uint8),
        ("cleanup_complete", ctypes.c_uint8),
        ("terminal", ctypes.POINTER(ctypes.c_uint8)),
        ("terminal_size", ctypes.c_size_t),
    ]


class WorkerLimits(ctypes.Structure):
    _fields_ = [
        ("duration_ms", ctypes.c_uint64),
        ("memory_bytes", ctypes.c_uint64),
        ("open_fds", ctypes.c_uint64),
        ("output_bytes", ctypes.c_uint64),
        ("output_files", ctypes.c_uint64),
        ("stderr_bytes", ctypes.c_uint64),
        ("stdout_bytes", ctypes.c_uint64),
    ]


class WorkerBinding(ctypes.Structure):
    _fields_ = [
        ("version", ctypes.c_uint32),
        ("provider_mode", ctypes.c_uint16),
        ("lane", ctypes.c_uint16),
        ("method", ctypes.c_uint16),
        ("operation", ctypes.c_char * 32),
        ("request_id", ctypes.c_char * 129),
        ("method_payload_sha256", ctypes.c_uint8 * 32),
        ("effects_binding_sha256", ctypes.c_uint8 * 32),
        ("worker_runtime_sha256", ctypes.c_uint8 * 32),
        ("worker_runtime_size", ctypes.c_uint64),
        ("runtime_closure_sha256", ctypes.c_uint8 * 32),
        ("apple_mount_payload_sha256", ctypes.c_uint8 * 32),
        ("tool_image_member_sha256", ctypes.c_uint8 * 32),
        ("tool_image_member_size", ctypes.c_uint64),
        ("managed_provisioner_sha256", ctypes.c_uint8 * 32),
        ("managed_provisioner_size", ctypes.c_uint64),
        ("js_offline_materializer_sha256", ctypes.c_uint8 * 32),
        ("js_offline_materializer_size", ctypes.c_uint64),
        ("tool_anchor_id", ctypes.c_char * 32),
        ("worker_request_sha256", ctypes.c_uint8 * 32),
        ("descriptor_identity_sha256", (ctypes.c_uint8 * 32) * 8),
        ("role_present", ctypes.c_uint8 * 8),
        ("limits", WorkerLimits),
    ]


class WorkerTerminalObservation(ctypes.Structure):
    _fields_ = [
        ("version", ctypes.c_uint32),
        ("status", ctypes.c_char * 40),
        ("returncode", ctypes.c_int32),
        ("duration_ms", ctypes.c_uint64),
        ("peak_memory_bytes", ctypes.c_uint64),
        ("stdout_observed_bytes", ctypes.c_uint64),
        ("stdout_retained_bytes", ctypes.c_uint64),
        ("stdout_sha256", ctypes.c_uint8 * 32),
        ("stderr_observed_bytes", ctypes.c_uint64),
        ("stderr_retained_bytes", ctypes.c_uint64),
        ("stderr_sha256", ctypes.c_uint8 * 32),
        ("output_file_count", ctypes.c_uint64),
        ("output_bytes", ctypes.c_uint64),
        ("output_manifest_sha256", ctypes.c_uint8 * 32),
        ("projection_observation_sha256", ctypes.c_uint8 * 32),
        ("observed_egress_sha256", ctypes.c_uint8 * 32),
        ("descriptor_post_sha256", (ctypes.c_uint8 * 32) * 8),
        ("terminal_sha256", ctypes.c_uint8 * 32),
        ("terminal_hmac_sha256", ctypes.c_uint8 * 32),
    ]


class OutputTree(ctypes.Structure):
    _fields_ = [
        ("version", ctypes.c_uint32),
        ("role", ctypes.c_uint16),
        ("name", ctypes.c_char * 32),
        ("relative_path", ctypes.c_char * 128),
        ("tree_sha256", ctypes.c_uint8 * 32),
        ("entry_count", ctypes.c_uint64),
        ("expanded_bytes", ctypes.c_uint64),
    ]


class SnapshotHostAuthority(ctypes.Structure):
    _fields_ = [
        ("version", ctypes.c_uint32),
        ("lane", ctypes.c_uint16),
        ("method", ctypes.c_uint16),
        ("operation", ctypes.c_char * 32),
        ("request_sha256", ctypes.c_uint8 * 32),
        ("effects_binding_sha256", ctypes.c_uint8 * 32),
        ("worker_request_sha256", ctypes.c_uint8 * 32),
        ("lifecycle_receipt_sha256", ctypes.c_uint8 * 32),
        ("post_spawn_dynamic_identity_kind", ctypes.c_uint32),
        ("post_spawn_dynamic_identity_size", ctypes.c_uint32),
        ("post_spawn_dynamic_identity_sha256", ctypes.c_uint8 * 32),
        ("network_policy_sha256", ctypes.c_uint8 * 32),
        ("observed_egress_sha256", ctypes.c_uint8 * 32),
        ("provider_authenticated", ctypes.c_uint8),
        ("network_policy_enforced", ctypes.c_uint8),
        ("population_zero", ctypes.c_uint8),
        ("cleanup_complete", ctypes.c_uint8),
        ("tree_count", ctypes.c_uint16),
        ("trees", OutputTree * 2),
        ("tree_roster_sha256", ctypes.c_uint8 * 32),
        ("receipt_hmac_sha256", ctypes.c_uint8 * 32),
    ]


ExecuteCallback = ctypes.CFUNCTYPE(
    ctypes.c_int, ctypes.c_void_p, ctypes.POINTER(PlanView), ctypes.POINTER(Evidence)
)
DisposeCallback = ctypes.CFUNCTYPE(
    None, ctypes.c_void_p, ctypes.POINTER(Evidence)
)


class Executor(ctypes.Structure):
    _fields_ = [
        ("version", ctypes.c_uint32),
        ("context", ctypes.c_void_p),
        ("execute", ExecuteCallback),
        ("dispose", DisposeCallback),
    ]


PLAN_NAMES = (
    "js_authenticate", "js_runtime_identity", "js_prepare", "js_execute",
    "js_replay", "managed_evm_runtime_identity", "managed_evm_prepare",
    "managed_evm_execute", "managed_evm_project", "evm_projection_commit",
    "evm_projection_recover", "evm_projection_project",
    "snapshot_runtime_identity", "snapshot_acquire", "snapshot_prepare",
    "snapshot_execute", "fuzz_campaign_execute", "fuzz_service_admit",
    "fuzz_service_execute",
)


class ExactExecutor(ctypes.Structure):
    _fields_ = [
        ("version", ctypes.c_uint32),
        ("context", ctypes.c_void_p),
        *[(name, ExecuteCallback) for name in PLAN_NAMES],
        ("dispose", DisposeCallback),
    ]


@pytest.fixture(scope="module")
def native(tmp_path_factory: pytest.TempPathFactory) -> ctypes.CDLL:
    output = tmp_path_factory.mktemp("specialized-tool-effects") / "effects.dylib"
    subprocess.run([
        "/usr/bin/clang", "-std=c11", "-Wall", "-Wextra", "-Werror",
        "-Wno-unused-function",
        "-fblocks", "-dynamiclib", "-I", str(ROOT / "native/include"),
        "-I", str(ROOT / "native/darwin"),
        *[str(ROOT / path) for path in (
            "native/darwin/plamen_broker_v2_process.c",
            "native/darwin/plamen_broker_v2_process_custodian.c",
            "native/darwin/plamen_broker_v2_process_custody_client.c",
            "native/darwin/plamen_broker_v2_apple_container.c",
            "native/darwin/plamen_broker_v2_apple_container_lifecycle.c",
            "native/darwin/plamen_broker_v2_tool_custody.c",
            "native/tests/plamen_broker_v2_specialized_request_integration_wrapper.c",
            "native/darwin/plamen_broker_v2_specialized_output_census.c",
            "native/darwin/plamen_broker_v2_specialized_output_receipt.c",
            "native/posix/plamen_broker_v2_protocol.c",
        )],
        "-framework", "Security", "-framework", "CoreFoundation",
        "-framework", "Foundation", "-o", str(output),
    ], cwd=ROOT, check=True, stdin=subprocess.DEVNULL,
       stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
    library = ctypes.CDLL(str(output))
    library.plamen_broker_v2_specialized_request_encode.argtypes = [
        ctypes.POINTER(SpecializedRequest), ctypes.c_void_p, ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_size_t),
    ]
    library.plamen_broker_v2_specialized_request_encode.restype = ctypes.c_int
    library.plamen_broker_v2_specialized_worker_tool_anchor_path.argtypes = [
        ctypes.c_uint16, ctypes.c_uint16, ctypes.c_char_p,
        ctypes.POINTER(ctypes.c_char_p),
    ]
    library.plamen_broker_v2_specialized_worker_tool_anchor_path.restype = ctypes.c_int
    library.plamen_broker_v2_specialized_worker_tool_anchor_id.argtypes = [
        ctypes.POINTER(PlanView), ctypes.c_void_p,
    ]
    library.plamen_broker_v2_specialized_worker_tool_anchor_id.restype = ctypes.c_int
    library.plamen_broker_v2_specialized_snapshot_method_terminal_render.argtypes = [
        ctypes.POINTER(PlanView), ctypes.POINTER(WorkerBinding),
        ctypes.POINTER(WorkerTerminalObservation),
        ctypes.POINTER(SnapshotHostAuthority),
        ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(ctypes.c_uint8),
        ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_size_t),
    ]
    library.plamen_broker_v2_specialized_snapshot_method_terminal_render.restype = ctypes.c_int
    library.plamen_broker_v2_specialized_snapshot_host_authority_seal.argtypes = [
        ctypes.POINTER(SnapshotHostAuthority), ctypes.POINTER(ctypes.c_uint8),
    ]
    library.plamen_broker_v2_specialized_snapshot_host_authority_seal.restype = ctypes.c_int
    for suffix in PLAN_NAMES:
        function = getattr(library, f"plamen_broker_v2_tool_effect_plan_{suffix}")
        function.argtypes = [ctypes.POINTER(PlanInput), ctypes.POINTER(ctypes.c_void_p)]
        function.restype = ctypes.c_int
    library.plamen_broker_v2_tool_effect_plan_view.argtypes = [
        ctypes.c_void_p, ctypes.POINTER(PlanView),
    ]
    library.plamen_broker_v2_tool_effect_plan_view.restype = ctypes.c_int
    library.plamen_broker_v2_tool_effect_plan_finalize.argtypes = [
        ctypes.c_void_p, ctypes.POINTER(Evidence),
        ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_size_t),
        ctypes.POINTER(ctypes.c_uint8),
    ]
    library.plamen_broker_v2_tool_effect_plan_finalize.restype = ctypes.c_int
    library.plamen_broker_v2_tool_effect_plan_issue_lease.argtypes = [
        ctypes.c_void_p, ctypes.POINTER(Evidence),
        ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_size_t),
        ctypes.POINTER(ctypes.c_uint8),
    ]
    library.plamen_broker_v2_tool_effect_plan_issue_lease.restype = ctypes.c_int
    for suffix in ("js", "managed_evm", "snapshot"):
        function = getattr(
            library,
            f"plamen_broker_v2_tool_effect_plan_{suffix}_execute_from_lease",
        )
        function.argtypes = [
            ctypes.c_void_p, ctypes.POINTER(PlanInput),
            ctypes.POINTER(ctypes.c_void_p),
        ]
        function.restype = ctypes.c_int
    library.plamen_broker_v2_tool_effect_plan_execute.argtypes = [
        ctypes.c_void_p, ctypes.POINTER(Executor),
        ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_size_t),
        ctypes.POINTER(ctypes.c_uint8),
    ]
    library.plamen_broker_v2_tool_effect_plan_execute.restype = ctypes.c_int
    library.plamen_broker_v2_tool_effect_plan_execute_exact.argtypes = [
        ctypes.c_void_p, ctypes.POINTER(ExactExecutor),
        ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_size_t),
        ctypes.POINTER(ctypes.c_uint8),
    ]
    library.plamen_broker_v2_tool_effect_plan_execute_exact.restype = ctypes.c_int
    library.plamen_broker_v2_tool_effect_plan_destroy.argtypes = [ctypes.c_void_p]
    library.plamen_broker_v2_tool_effect_plan_destroy.restype = None
    library.plamen_broker_v2_fd_identity.argtypes = [
        ctypes.c_int, ctypes.POINTER(ctypes.c_uint8),
    ]
    library.plamen_broker_v2_fd_identity.restype = ctypes.c_int
    return library


@pytest.mark.parametrize(
    ("tool_id", "guest_path"),
    [
        (b"forge", b"/usr/local/lib/plamen/toolchains/foundry/bin/forge"),
        (b"opengrep", b"/usr/local/lib/plamen/toolchains/opengrep/bin/opengrep"),
        (b"slither", b"/usr/local/lib/plamen/toolchains/managed-evm/bin/slither"),
        (b"solc", b"/usr/local/lib/plamen/toolchains/solc-amd64/solc"),
    ],
)
def test_snapshot_image_member_anchors_are_compiled_and_method_exact(
    native: ctypes.CDLL, tool_id: bytes, guest_path: bytes,
) -> None:
    resolved = ctypes.c_char_p()
    assert native.plamen_broker_v2_specialized_worker_tool_anchor_path(
        SNAPSHOT_LANE, SNAPSHOT_EXECUTE, tool_id, ctypes.byref(resolved)
    ) == 0
    assert resolved.value == guest_path
    assert native.plamen_broker_v2_specialized_worker_tool_anchor_path(
        SNAPSHOT_LANE, SNAPSHOT_PREPARE, tool_id, ctypes.byref(resolved)
    ) != 0


def test_snapshot_image_member_anchor_rejects_unrostered_alias(
    native: ctypes.CDLL,
) -> None:
    resolved = ctypes.c_char_p()
    assert native.plamen_broker_v2_specialized_worker_tool_anchor_path(
        SNAPSHOT_LANE, SNAPSHOT_EXECUTE, b"semgrep", ctypes.byref(resolved)
    ) != 0
    assert resolved.value is None


@pytest.mark.parametrize("tool_id", ["forge", "opengrep", "slither", "solc"])
def test_snapshot_tool_source_kind_is_directory_and_cross_kind_fails_closed(
    native: ctypes.CDLL, tool_id: str,
) -> None:
    def payload(kind: str) -> bytes:
        return _canonical({
            "egress_policy": "DENY_ALL",
            "mounts": [
                {
                    "guest_path": "/workspace/source", "mode": "READ_ONLY",
                    "mount_id": "analysis-input", "source_sha256": "11" * 32,
                },
                {
                    "guest_path": "/workspace/project", "mode": "READ_ONLY",
                    "mount_id": "project", "source_sha256": "22" * 32,
                },
                {
                    "guest_path": "/workspace/scratch",
                    "mode": "READ_WRITE_EXCLUSIVE", "mount_id": "scratch",
                    "source_sha256": "33" * 32,
                },
                {
                    "guest_path": "/workspace/state",
                    "mode": "READ_WRITE_EXCLUSIVE", "mount_id": "state",
                    "source_sha256": "44" * 32,
                },
            ],
            "schema": "plamen.snapshot-bound-tool-execution-request.v3",
            "source_descriptor": {
                "descriptor_sha256": "11" * 32, "kind": kind,
            },
            "tool_id": tool_id,
        })

    raw = payload("directory")
    buffer = (ctypes.c_uint8 * len(raw)).from_buffer_copy(raw)
    view = PlanView(
        version=1, lane=SNAPSHOT_LANE, method=SNAPSHOT_EXECUTE,
        payload=buffer, payload_size=len(raw),
    )
    anchor = ctypes.create_string_buffer(32)
    assert native.plamen_broker_v2_specialized_worker_tool_anchor_id(
        ctypes.byref(view), anchor,
    ) == 0
    assert anchor.value.decode("ascii") == tool_id

    cross_kind = payload("file")
    cross_kind_buffer = (ctypes.c_uint8 * len(cross_kind)).from_buffer_copy(
        cross_kind
    )
    view.payload = cross_kind_buffer
    view.payload_size = len(cross_kind)
    assert native.plamen_broker_v2_specialized_worker_tool_anchor_id(
        ctypes.byref(view), anchor,
    ) != 0
    assert anchor.value == b""


def test_snapshot_terminal_is_exact_request_bound_canonical_v3(
    native: ctypes.CDLL,
) -> None:
    request = {
        "argv": ["opengrep", "--config", "/workspace/source/rules"],
        "audit_snapshot_sha256": "11" * 32,
        "authentic_content_authority": False,
        "authority_tier": "SNAPSHOT_BOUND_LOCAL",
        "build_system": "foundry",
        "can_certify_clean": False,
        "cwd": "/workspace/project",
        "egress_policy": "DENY_ALL",
        "environment": {"HOME": "/workspace/state"},
        "evidence_ceiling": "POSITIVE_FINDINGS_AND_HEURISTIC_COVERAGE_ONLY",
        "execution_authority": True,
        "limits": {
            "duration_ms": 60000,
            "memory_bytes": 536870912,
            "output_bytes": 1048576,
            "output_files": 16,
            "stderr_bytes": 2097152,
            "stdout_bytes": 8388608,
        },
        "materialization_lineage_sha256": "22" * 32,
        "mounts": [
            {
                "guest_path": "/workspace/source", "mode": "READ_ONLY",
                "mount_id": "analysis-input", "source_sha256": "55" * 32,
            },
            {
                "guest_path": "/workspace/project", "mode": "READ_ONLY",
                "mount_id": "project", "source_sha256": "99" * 32,
            },
            {
                "guest_path": "/workspace/scratch",
                "mode": "READ_WRITE_EXCLUSIVE", "mount_id": "scratch",
                "source_sha256": "aa" * 32,
            },
            {
                "guest_path": "/workspace/state",
                "mode": "READ_WRITE_EXCLUSIVE", "mount_id": "state",
                "source_sha256": "bb" * 32,
            },
        ],
        "native_runtime_identity": {
            "runtime_sha256": "33" * 32,
            "schema": "plamen.native-runtime-identity.v1",
        },
        "platform": "MACOS",
        "run_id": "run-native-snapshot-1",
        "schema": "plamen.snapshot-bound-tool-execution-request.v3",
        "snapshot_projection_bytes": 1234,
        "snapshot_projection_sha256": "44" * 32,
        "source_descriptor": {
            "descriptor_sha256": "55" * 32,
            "kind": "directory",
        },
        "source_scope_sha256": "66" * 32,
        "tool_id": "opengrep",
        "toolchain_governance_sha256": "77" * 32,
        "toolchain_version_lock_sha256": "88" * 32,
        "trust_assumption": "OPERATOR_LOCAL_TOOL_INSTALL",
    }
    payload = _canonical(request)
    payload_buffer = (ctypes.c_uint8 * len(payload)).from_buffer_copy(payload)
    view = PlanView(
        version=1, lane=SNAPSHOT_LANE, method=SNAPSHOT_EXECUTE,
        payload=payload_buffer, payload_size=len(payload),
    )
    _fill(view.request_sha256, hashlib.sha256(payload).digest())
    binding = WorkerBinding(
        version=1, lane=SNAPSHOT_LANE, method=SNAPSHOT_EXECUTE,
        operation=b"SNAPSHOT_TOOL_EXECUTE",
    )
    observed = WorkerTerminalObservation(
        version=1, status=b"COMPLETE", returncode=0, duration_ms=321,
        peak_memory_bytes=654321, stdout_observed_bytes=7,
        stdout_retained_bytes=7, stderr_observed_bytes=0,
        stderr_retained_bytes=0, output_file_count=2, output_bytes=909,
    )
    _fill(observed.stdout_sha256, b"S" * 32)
    _fill(observed.stderr_sha256, b"T" * 32)
    _fill(observed.output_manifest_sha256, b"O" * 32)
    _fill(observed.observed_egress_sha256, b"G" * 32)
    _fill(binding.effects_binding_sha256, b"E" * 32)
    _fill(binding.worker_request_sha256, b"W" * 32)
    host = SnapshotHostAuthority(
        version=1, lane=SNAPSHOT_LANE, method=SNAPSHOT_EXECUTE,
        operation=b"SNAPSHOT_TOOL_EXECUTE",
        post_spawn_dynamic_identity_kind=1,
        post_spawn_dynamic_identity_size=20,
        provider_authenticated=1, network_policy_enforced=1,
        population_zero=1, cleanup_complete=1,
    )
    _fill(host.request_sha256, bytes(view.request_sha256))
    _fill(host.effects_binding_sha256, bytes(binding.effects_binding_sha256))
    _fill(host.worker_request_sha256, bytes(binding.worker_request_sha256))
    _fill(host.lifecycle_receipt_sha256, b"L" * 32)
    _fill(host.post_spawn_dynamic_identity_sha256, b"D" * 32)
    _fill(host.network_policy_sha256, b"P" * 32)
    _fill(host.observed_egress_sha256, bytes(observed.observed_egress_sha256))
    session_key = (ctypes.c_uint8 * 32).from_buffer_copy(b"K" * 32)
    lifecycle = (ctypes.c_uint8 * 32).from_buffer_copy(b"L" * 32)
    assert native.plamen_broker_v2_specialized_snapshot_host_authority_seal(
        ctypes.byref(host), session_key,
    ) == 0
    terminal = ctypes.c_void_p()
    terminal_size = ctypes.c_size_t()
    assert native.plamen_broker_v2_specialized_snapshot_method_terminal_render(
        ctypes.byref(view), ctypes.byref(binding), ctypes.byref(observed),
        ctypes.byref(host), session_key, lifecycle, ctypes.byref(terminal),
        ctypes.byref(terminal_size),
    ) == 0
    actual = ctypes.string_at(terminal, terminal_size.value)
    ctypes.CDLL(None).free(terminal)

    node_hash = lambda value: hashlib.sha256(_canonical(value)).hexdigest()
    expected = {
        "argv_sha256": node_hash(request["argv"]),
        "audit_snapshot_sha256": request["audit_snapshot_sha256"],
        "cleanup_complete": True,
        "cwd_sha256": node_hash(request["cwd"]),
        "duration_ms": 321,
        "egress_denied": True,
        "egress_policy": "DENY_ALL",
        "environment_sha256": node_hash(request["environment"]),
        "exit_state": "COMPLETED",
        "materialization_lineage_sha256": request["materialization_lineage_sha256"],
        "mounts_sha256": node_hash(request["mounts"]),
        "native_runtime_identity_sha256": node_hash(request["native_runtime_identity"]),
        "output_bytes": 909,
        "output_file_count": 2,
        "output_limit_exceeded": False,
        "output_tree_sha256": (b"O" * 32).hex(),
        "peak_memory_bytes": 654321,
        "population_zero": True,
        "post_spawn_dynamic_identity_sha256": (b"D" * 32).hex(),
        "request_sha256": hashlib.sha256(payload).hexdigest(),
        "returncode": 0,
        "run_id": request["run_id"],
        "schema": "plamen.snapshot-bound-tool-execution-terminal.v3",
        "source_descriptor_sha256": request["source_descriptor"]["descriptor_sha256"],
        "source_scope_sha256": request["source_scope_sha256"],
        "stderr_observed_bytes": 0,
        "stderr_retained_bytes": 0,
        "stderr_sha256": (b"T" * 32).hex(),
        "stdout_observed_bytes": 7,
        "stdout_retained_bytes": 7,
        "stdout_sha256": (b"S" * 32).hex(),
        "tool_id": "opengrep",
        "toolchain_governance_sha256": request["toolchain_governance_sha256"],
        "toolchain_version_lock_sha256": request["toolchain_version_lock_sha256"],
        "truncation_debt": None,
    }
    assert actual == _canonical(expected)
    assert not actual.endswith(b"\n")

    # The renderer must not turn a guest claim into host population authority.
    host.population_zero = 0
    terminal = ctypes.c_void_p(1)
    terminal_size = ctypes.c_size_t(99)
    assert native.plamen_broker_v2_specialized_snapshot_method_terminal_render(
        ctypes.byref(view), ctypes.byref(binding), ctypes.byref(observed),
        ctypes.byref(host), session_key, lifecycle, ctypes.byref(terminal),
        ctypes.byref(terminal_size),
    ) != 0
    assert terminal.value is None and terminal_size.value == 0


def _fill(target: ctypes.Array[ctypes.c_uint8], value: bytes) -> None:
    assert len(value) == 32
    target[:] = value


def _request(native: ctypes.CDLL, method: int, payload: bytes, *,
             lane: int = JS_LANE,
             capability: bool = False, flags: int = 0,
             descriptors: list[tuple[int, int, int, bytes]] | None = None,
             fds: list[int] | None = None) -> tuple[SpecializedRequest, PlanInput, object]:
    descriptors = descriptors or []
    fds = fds or []
    raw = (ctypes.c_uint8 * len(payload)).from_buffer_copy(payload)
    request = SpecializedRequest(
        lane=lane, method=method, flags=flags, fd_count=len(descriptors),
        payload_size=len(payload), payload=raw,
    )
    if capability:
        _fill(request.capability_id, b"C" * 32)
    _fill(request.operation_nonce, b"N" * 32)
    _fill(request.authority_binding_sha256, b"A" * 32)
    for index, (purpose, target, access, identity) in enumerate(descriptors):
        request.descriptors[index].purpose = purpose
        request.descriptors[index].target = target
        request.descriptors[index].access_mode = access
        _fill(request.descriptors[index].identity, identity)
    wire = (ctypes.c_uint8 * (PAYLOAD_MAX + 1024))()
    size = ctypes.c_size_t()
    assert native.plamen_broker_v2_specialized_request_encode(
        ctypes.byref(request), wire, len(wire), ctypes.byref(size)
    ) == 0
    wire_exact = (ctypes.c_uint8 * size.value).from_buffer_copy(
        bytes(wire[:size.value])
    )
    fd_array = (ctypes.c_int * len(fds))(*fds) if fds else None
    plan_input = PlanInput(
        version=1, request=ctypes.pointer(request), request_wire=wire_exact,
        request_wire_size=size.value, fds=fd_array, fd_count=len(fds),
    )
    _fill(plan_input.request_sha256, hashlib.sha256(bytes(wire_exact)).digest())
    _fill(plan_input.effects_context_sha256, b"E" * 32)
    return request, plan_input, (raw, wire_exact, fd_array)


def _request_encode_status(
    native: ctypes.CDLL, lane: int, method: int,
    descriptors: list[tuple[int, int, int]], *, capability: bool,
) -> int:
    payload = b"{}"
    raw = (ctypes.c_uint8 * len(payload)).from_buffer_copy(payload)
    request = SpecializedRequest(
        lane=lane, method=method, fd_count=len(descriptors),
        payload_size=len(payload), payload=raw,
    )
    if capability:
        _fill(request.capability_id, b"C" * 32)
    _fill(request.operation_nonce, b"N" * 32)
    _fill(request.authority_binding_sha256, b"A" * 32)
    for index, (purpose, target, access) in enumerate(descriptors):
        request.descriptors[index].purpose = purpose
        request.descriptors[index].target = target
        request.descriptors[index].access_mode = access
        _fill(request.descriptors[index].identity, bytes([index + 1]) * 32)
    wire = (ctypes.c_uint8 * 4096)()
    size = ctypes.c_size_t()
    return native.plamen_broker_v2_specialized_request_encode(
        ctypes.byref(request), wire, len(wire), ctypes.byref(size)
    )


def _open_plan(native: ctypes.CDLL, suffix: str, plan_input: PlanInput) -> ctypes.c_void_p:
    plan = ctypes.c_void_p()
    assert getattr(native, f"plamen_broker_v2_tool_effect_plan_{suffix}")(
        ctypes.byref(plan_input), ctypes.byref(plan)
    ) == 0
    assert plan.value
    return plan


def _evidence(plan_input: PlanInput, method: int, terminal: bytes, *,
              execute: bool = False) -> tuple[Evidence, object]:
    raw = (ctypes.c_uint8 * len(terminal)).from_buffer_copy(terminal)
    evidence = Evidence(
        version=1, lane=plan_input.request.contents.lane, method=method,
        effect_authenticated=1, effect_completed=1,
        durable_operation=0 if method == JS_RUNTIME_IDENTITY else 1,
        provider_authenticated=1 if execute else 0,
        network_policy_enforced=1 if execute else 0,
        population_zero=1 if execute else 0,
        cleanup_complete=1 if execute else 0,
        terminal=raw, terminal_size=len(terminal),
    )
    for name in ("authority_binding_sha256", "operation_nonce"):
        _fill(getattr(evidence, name), bytes(getattr(plan_input.request.contents, name)))
    _fill(evidence.request_sha256, bytes(plan_input.request_sha256))
    _fill(evidence.effects_context_sha256, bytes(plan_input.effects_context_sha256))
    _fill(evidence.effect_receipt_sha256, b"R" * 32)
    _fill(evidence.durable_operation_sha256, b"D" * 32)
    if execute:
        _fill(evidence.lifecycle_receipt_sha256, b"L" * 32)
        _fill(evidence.network_policy_sha256, b"P" * 32)
        _fill(evidence.observed_egress_sha256, b"O" * 32)
    return evidence, raw


def _finalize(native: ctypes.CDLL, plan: ctypes.c_void_p,
              evidence: Evidence) -> tuple[int, bytes]:
    terminal = ctypes.c_void_p()
    terminal_size = ctypes.c_size_t()
    digest = (ctypes.c_uint8 * 32)()
    status = native.plamen_broker_v2_tool_effect_plan_finalize(
        plan, ctypes.byref(evidence), ctypes.byref(terminal),
        ctypes.byref(terminal_size), digest,
    )
    if status != 0:
        return status, b""
    result = ctypes.string_at(terminal, terminal_size.value)
    assert hashlib.sha256(result).digest() == bytes(digest)
    ctypes.CDLL(None).free(terminal)
    return status, result


def _issue_lease(native: ctypes.CDLL, plan: ctypes.c_void_p,
                 evidence: Evidence) -> tuple[int, bytes]:
    terminal = ctypes.c_void_p()
    terminal_size = ctypes.c_size_t()
    digest = (ctypes.c_uint8 * 32)()
    status = native.plamen_broker_v2_tool_effect_plan_issue_lease(
        plan, ctypes.byref(evidence), ctypes.byref(terminal),
        ctypes.byref(terminal_size), digest,
    )
    if status != 0:
        return status, b""
    result = ctypes.string_at(terminal, terminal_size.value)
    assert hashlib.sha256(result).digest() == bytes(digest)
    ctypes.CDLL(None).free(terminal)
    return status, result


def _fd_identity(native: ctypes.CDLL, fd: int) -> bytes:
    identity = (ctypes.c_uint8 * 32)()
    assert native.plamen_broker_v2_fd_identity(fd, identity) == 0
    return bytes(identity)


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode("ascii")


def _archive_fixture(
    root: Path, *, missing: bool = False, extra: bool = False,
    symlink: bool = False,
) -> tuple[dict[str, object], bytes, bytes]:
    root.mkdir(mode=0o700)
    root.chmod(0o700)
    artifacts = {
        "node-linux-x86_64": b"\xfd7zXZ\x00node-fixture",
        "yarn-classic-noarch": b"\x1f\x8b\x08yarn-fixture",
    }
    rows = []
    for artifact_id, content in sorted(artifacts.items()):
        digest = hashlib.sha256(content).hexdigest()
        filename = f"{digest}.archive"
        rows.append({
            "artifact_id": artifact_id,
            "filename": filename,
            "sha256": digest,
            "size": len(content),
        })
        if missing and artifact_id == "yarn-classic-noarch":
            continue
        if symlink and artifact_id == "yarn-classic-noarch":
            source = root.parent / "symlink-archive-source"
            source.write_bytes(content)
            os.symlink(source, root / filename)
        else:
            (root / filename).write_bytes(content)
    census = hashlib.sha256(_canonical(rows)).hexdigest()
    manifest = {
        "archive_census_sha256": census,
        "archive_count": len(rows),
        "archives": rows,
        "schema": "plamen.js-archive-root-manifest.v1",
    }
    manifest_bytes = _canonical(manifest)
    (root / "archive-manifest.json").write_bytes(manifest_bytes)
    if extra:
        (root / "unexpected").write_bytes(b"extra")
    binding_body = {
        "archive_census_sha256": census,
        "archive_count": len(rows),
        "archive_manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "archive_root": str(root),
        "archives": rows,
    }
    binding = dict(binding_body)
    binding["binding_sha256"] = hashlib.sha256(_canonical(binding_body)).hexdigest()
    return binding, hashlib.sha256(manifest_bytes).digest(), bytes.fromhex(census)


def _js_payload(binding: dict[str, object]) -> bytes:
    return _canonical({
        "archives": binding,
        "network_policy": {"allowed_origins": [
            {"host": "registry.npmjs.org", "port": 443, "scheme": "https"},
            {"host": "registry.yarnpkg.com", "port": 443, "scheme": "https"},
        ]},
        "schema": "plamen.js-dependency-materialization-request.v2",
    })


def test_runtime_identity_requires_exact_wire_context_and_one_shot_evidence(
    native: ctypes.CDLL,
) -> None:
    _, plan_input, keepalive = _request(native, JS_RUNTIME_IDENTITY, b"{}")
    plan = _open_plan(native, "js_runtime_identity", plan_input)
    view = PlanView()
    assert native.plamen_broker_v2_tool_effect_plan_view(plan, ctypes.byref(view)) == 0
    assert view.method == JS_RUNTIME_IDENTITY
    assert bytes(view.effects_context_sha256) == b"E" * 32

    terminal = json.dumps({
        "anchor_relative_path": "verification_policy/js_toolchain_bootstrap.v1.json",
        "anchor_sha256": "01" * 32,
        "custody_receipt_sha256": "02" * 32,
        "install_provenance_sha256": "03" * 32,
        "native_deployment_receipt_sha256": "04" * 32,
        "native_extension_sha256": "05" * 32,
        "offline_network_denial_sha256": "06" * 32,
        "online_network_admission_sha256": "07" * 32,
        "schema": "plamen.js-dependency-materializer-runtime-identity.v1",
        "source_census_sha256": "08" * 32,
        "trust_boundary": "AUTHENTICATED_INSTALLER_LAUNCHER_BOUNDARY_V1",
    }, sort_keys=True, separators=(",", ":")).encode()
    evidence, evidence_keepalive = _evidence(
        plan_input, JS_RUNTIME_IDENTITY, terminal
    )
    status, observed = _finalize(native, plan, evidence)
    assert status == 0 and observed == terminal
    assert native.plamen_broker_v2_tool_effect_plan_view(plan, ctypes.byref(view)) != 0
    assert _finalize(native, plan, evidence)[0] != 0
    native.plamen_broker_v2_tool_effect_plan_destroy(plan)
    assert keepalive and evidence_keepalive


def test_method_wire_digest_and_context_forgery_fail_closed(native: ctypes.CDLL) -> None:
    _, plan_input, keepalive = _request(native, JS_RUNTIME_IDENTITY, b"{}")
    plan = ctypes.c_void_p()
    assert native.plamen_broker_v2_tool_effect_plan_js_execute(
        ctypes.byref(plan_input), ctypes.byref(plan)
    ) != 0
    plan_input.request_sha256[0] ^= 1
    assert native.plamen_broker_v2_tool_effect_plan_js_runtime_identity(
        ctypes.byref(plan_input), ctypes.byref(plan)
    ) != 0
    plan_input.request_sha256[0] ^= 1
    plan = _open_plan(native, "js_runtime_identity", plan_input)
    terminal = b'{"schema":"plamen.js-dependency-materializer-runtime-identity.v1"}'
    evidence, evidence_keepalive = _evidence(
        plan_input, JS_RUNTIME_IDENTITY, terminal
    )
    evidence.effects_context_sha256[0] ^= 1
    assert _finalize(native, plan, evidence)[0] != 0
    native.plamen_broker_v2_tool_effect_plan_destroy(plan)

    plan = _open_plan(native, "js_runtime_identity", plan_input)
    evidence, incomplete_keepalive = _evidence(
        plan_input, JS_RUNTIME_IDENTITY, terminal
    )
    assert _finalize(native, plan, evidence)[0] != 0
    native.plamen_broker_v2_tool_effect_plan_destroy(plan)
    assert keepalive and evidence_keepalive and incomplete_keepalive


def test_js_execute_enforces_authenticated_lifecycle_and_exact_origin_subset(
    native: ctypes.CDLL,
) -> None:
    origins = [
        {"host": "registry.npmjs.org", "port": 443, "scheme": "https"},
        {"host": "registry.yarnpkg.com", "port": 443, "scheme": "https"},
    ]
    request_payload = json.dumps({
        "network_policy": {"allowed_origins": origins},
        "schema": "plamen.js-dependency-materialization-request.v2",
    }, sort_keys=True, separators=(",", ":")).encode()
    _, plan_input, keepalive = _request(
        native, JS_EXECUTE, request_payload, capability=True
    )

    def terminal(observed: list[dict[str, object]]) -> bytes:
        return json.dumps({
            "network_policy_sha256": (b"P" * 32).hex(),
            "observed_egress_origins": observed,
            "observed_egress_sha256": (b"O" * 32).hex(),
            "schema": "plamen.js-dependency-native-terminal.v2",
        }, sort_keys=True, separators=(",", ":")).encode() + b"\n"

    plan = _open_plan(native, "js_execute", plan_input)
    evidence, evidence_keepalive = _evidence(
        plan_input, JS_EXECUTE, terminal(origins[:1]), execute=True
    )
    assert _finalize(native, plan, evidence)[0] == 0
    native.plamen_broker_v2_tool_effect_plan_destroy(plan)

    plan = _open_plan(native, "js_execute", plan_input)
    evidence, rogue_keepalive = _evidence(plan_input, JS_EXECUTE, terminal([
        {"host": "evil.example", "port": 443, "scheme": "https"},
    ]), execute=True)
    assert _finalize(native, plan, evidence)[0] != 0
    native.plamen_broker_v2_tool_effect_plan_destroy(plan)

    plan = _open_plan(native, "js_execute", plan_input)
    evidence, weak_keepalive = _evidence(
        plan_input, JS_EXECUTE, terminal([]), execute=True
    )
    evidence.population_zero = 0
    assert _finalize(native, plan, evidence)[0] != 0
    native.plamen_broker_v2_tool_effect_plan_destroy(plan)
    assert keepalive and evidence_keepalive and rogue_keepalive and weak_keepalive


def test_all_specialized_methods_have_distinct_native_plan_entrypoints(
    native: ctypes.CDLL,
) -> None:
    addresses = {
        ctypes.cast(
            getattr(native, f"plamen_broker_v2_tool_effect_plan_{suffix}"),
            ctypes.c_void_p,
        ).value
        for suffix in PLAN_NAMES
    }
    assert len(addresses) == len(PLAN_NAMES)


def test_typed_executor_failure_burns_plan_and_disposes_evidence(
    native: ctypes.CDLL,
) -> None:
    _, plan_input, keepalive = _request(native, JS_RUNTIME_IDENTITY, b"{}")
    plan = _open_plan(native, "js_runtime_identity", plan_input)
    counters = (ctypes.c_int * 2)(0, 0)

    @ExecuteCallback
    def execute(context: int, view: ctypes.POINTER(PlanView),
                evidence: ctypes.POINTER(Evidence)) -> int:
        observed = ctypes.cast(context, ctypes.POINTER(ctypes.c_int * 2)).contents
        observed[0] += 1
        assert view.contents.method == JS_RUNTIME_IDENTITY
        assert evidence.contents.method == JS_RUNTIME_IDENTITY
        return -17

    @DisposeCallback
    def dispose(context: int, evidence: ctypes.POINTER(Evidence)) -> None:
        observed = ctypes.cast(context, ctypes.POINTER(ctypes.c_int * 2)).contents
        observed[1] += 1
        assert evidence.contents.method == JS_RUNTIME_IDENTITY

    executor = Executor(
        version=1, context=ctypes.cast(counters, ctypes.c_void_p),
        execute=execute, dispose=dispose,
    )
    terminal = ctypes.c_void_p()
    terminal_size = ctypes.c_size_t()
    digest = (ctypes.c_uint8 * 32)()
    assert native.plamen_broker_v2_tool_effect_plan_execute(
        plan, ctypes.byref(executor), ctypes.byref(terminal),
        ctypes.byref(terminal_size), digest,
    ) == -17
    assert counters[:] == [1, 1]
    assert not terminal.value and terminal_size.value == 0 and bytes(digest) == bytes(32)
    view = PlanView()
    assert native.plamen_broker_v2_tool_effect_plan_view(plan, ctypes.byref(view)) != 0
    native.plamen_broker_v2_tool_effect_plan_destroy(plan)
    assert keepalive and execute and dispose


def test_js_prepare_lease_retains_exact_descriptors_for_zero_fd_execute(
    native: ctypes.CDLL, tmp_path: Path,
) -> None:
    roots = [tmp_path / name for name in ("source", "scratch", "state")]
    for root in roots:
        root.mkdir()
    binding, manifest_sha256, census_sha256 = _archive_fixture(
        tmp_path / "archive-root"
    )
    roots.append(tmp_path / "archive-root")
    fds = [os.open(root, os.O_RDONLY) for root in roots]
    try:
        payload = _js_payload(binding)
        descriptors = [
            (0x4001, 1, 1, _fd_identity(native, fds[0])),
            (0x4002, 2, 3, _fd_identity(native, fds[1])),
            (0x4003, 3, 3, _fd_identity(native, fds[2])),
            (0x4004, 4, 1, _fd_identity(native, fds[3])),
        ]
        _, prepare_input, prepare_keepalive = _request(
            native, JS_PREPARE, payload, capability=True,
            descriptors=descriptors, fds=fds,
        )
        lease = _open_plan(native, "js_prepare", prepare_input)
        prepare_terminal = b'{"schema":"plamen.js-materializer-prepare.v1"}'
        prepare_evidence, prepare_evidence_keepalive = _evidence(
            prepare_input, JS_PREPARE, prepare_terminal,
        )
        assert _issue_lease(native, lease, prepare_evidence) == (
            0, prepare_terminal,
        )
        lease_view = PlanView()
        assert native.plamen_broker_v2_tool_effect_plan_view(
            lease, ctypes.byref(lease_view)
        ) == 0
        assert lease_view.fd_count == 4
        assert bytes(lease_view.archive_root_identity_sha256) == descriptors[3][3]
        assert bytes(lease_view.archive_manifest_sha256) == manifest_sha256
        assert bytes(lease_view.archive_census_sha256) == census_sha256

        _, execute_input, execute_keepalive = _request(
            native, JS_EXECUTE, payload, capability=True,
        )
        execute_plan = ctypes.c_void_p()
        assert native.plamen_broker_v2_tool_effect_plan_js_execute_from_lease(
            lease, ctypes.byref(execute_input), ctypes.byref(execute_plan)
        ) == 0
        assert execute_plan.value
        assert native.plamen_broker_v2_tool_effect_plan_view(
            lease, ctypes.byref(lease_view)
        ) != 0
        execute_view = PlanView()
        assert native.plamen_broker_v2_tool_effect_plan_view(
            execute_plan, ctypes.byref(execute_view)
        ) == 0
        assert execute_view.method == JS_EXECUTE
        assert execute_view.fd_count == 4
        assert [execute_view.descriptors[index].purpose for index in range(4)] == [
            0x4001, 0x4002, 0x4003, 0x4004,
        ]
        assert bytes(execute_view.archive_root_identity_sha256) == descriptors[3][3]
        assert bytes(execute_view.archive_manifest_sha256) == manifest_sha256
        assert bytes(execute_view.archive_census_sha256) == census_sha256
        for index, fd in enumerate(fds):
            assert execute_view.fds[index] != fd
            assert _fd_identity(native, execute_view.fds[index]) == descriptors[index][3]
        native.plamen_broker_v2_tool_effect_plan_destroy(execute_plan)
        native.plamen_broker_v2_tool_effect_plan_destroy(lease)

        forged_lease = _open_plan(native, "js_prepare", prepare_input)
        assert _issue_lease(native, forged_lease, prepare_evidence)[0] == 0
        forged_payload = payload.replace(
            b'"schema"', b'"request_id":"forged","schema"', 1,
        )
        _, forged_input, forged_keepalive = _request(
            native, JS_EXECUTE, forged_payload, capability=True,
        )
        forged_execute = ctypes.c_void_p()
        assert native.plamen_broker_v2_tool_effect_plan_js_execute_from_lease(
            forged_lease, ctypes.byref(forged_input), ctypes.byref(forged_execute)
        ) != 0
        assert not forged_execute.value
        assert native.plamen_broker_v2_tool_effect_plan_view(
            forged_lease, ctypes.byref(lease_view)
        ) != 0
        native.plamen_broker_v2_tool_effect_plan_destroy(forged_lease)
        assert (
            prepare_keepalive and prepare_evidence_keepalive
            and execute_keepalive and forged_keepalive
        )
    finally:
        for fd in fds:
            os.close(fd)


@pytest.mark.parametrize("mutation", ["missing", "extra", "symlink"])
def test_js_archive_root_rejects_incomplete_or_aliased_census(
    native: ctypes.CDLL, tmp_path: Path, mutation: str,
) -> None:
    source, scratch, state = (
        tmp_path / "source", tmp_path / "scratch", tmp_path / "state"
    )
    for root in (source, scratch, state):
        root.mkdir()
    archive_root = tmp_path / "archive-root"
    binding, _, _ = _archive_fixture(
        archive_root,
        missing=mutation == "missing",
        extra=mutation == "extra",
        symlink=mutation == "symlink",
    )
    fds = [os.open(path, os.O_RDONLY) for path in (
        source, scratch, state, archive_root,
    )]
    try:
        descriptors = [
            (purpose, index + 1, access, _fd_identity(native, fds[index]))
            for index, (purpose, access) in enumerate((
                (0x4001, 1), (0x4002, 3), (0x4003, 3), (0x4004, 1),
            ))
        ]
        _, plan_input, keepalive = _request(
            native, JS_PREPARE, _js_payload(binding), capability=True,
            descriptors=descriptors, fds=fds,
        )
        plan = ctypes.c_void_p()
        assert native.plamen_broker_v2_tool_effect_plan_js_prepare(
            ctypes.byref(plan_input), ctypes.byref(plan)
        ) != 0
        assert not plan.value and keepalive
    finally:
        for fd in fds:
            os.close(fd)


def test_js_archive_manifest_drift_burns_issued_lease(
    native: ctypes.CDLL, tmp_path: Path,
) -> None:
    roots = [tmp_path / name for name in ("source", "scratch", "state")]
    for root in roots:
        root.mkdir()
    archive_root = tmp_path / "archive-root"
    binding, _, _ = _archive_fixture(archive_root)
    roots.append(archive_root)
    fds = [os.open(root, os.O_RDONLY) for root in roots]
    try:
        descriptors = [
            (purpose, index + 1, access, _fd_identity(native, fds[index]))
            for index, (purpose, access) in enumerate((
                (0x4001, 1), (0x4002, 3), (0x4003, 3), (0x4004, 1),
            ))
        ]
        payload = _js_payload(binding)
        _, prepare_input, keepalive = _request(
            native, JS_PREPARE, payload, capability=True,
            descriptors=descriptors, fds=fds,
        )
        lease = _open_plan(native, "js_prepare", prepare_input)
        evidence, evidence_keepalive = _evidence(
            prepare_input, JS_PREPARE,
            b'{"schema":"plamen.js-materializer-prepare.v1"}',
        )
        assert _issue_lease(native, lease, evidence)[0] == 0
        (archive_root / "archive-manifest.json").write_bytes(b"{}")
        _, execute_input, execute_keepalive = _request(
            native, JS_EXECUTE, payload, capability=True,
        )
        execute = ctypes.c_void_p()
        assert native.plamen_broker_v2_tool_effect_plan_js_execute_from_lease(
            lease, ctypes.byref(execute_input), ctypes.byref(execute)
        ) != 0
        assert not execute.value
        view = PlanView()
        assert native.plamen_broker_v2_tool_effect_plan_view(
            lease, ctypes.byref(view)
        ) != 0
        native.plamen_broker_v2_tool_effect_plan_destroy(lease)
        assert keepalive and evidence_keepalive and execute_keepalive
    finally:
        for fd in fds:
            os.close(fd)


def test_exact_executor_routes_only_matching_method_and_burns_missing_slot(
    native: ctypes.CDLL,
) -> None:
    _, plan_input, keepalive = _request(native, JS_RUNTIME_IDENTITY, b"{}")
    terminal_payload = json.dumps({
        "anchor_relative_path": "verification_policy/js_toolchain_bootstrap.v1.json",
        "anchor_sha256": "01" * 32,
        "custody_receipt_sha256": "02" * 32,
        "install_provenance_sha256": "03" * 32,
        "native_deployment_receipt_sha256": "04" * 32,
        "native_extension_sha256": "05" * 32,
        "offline_network_denial_sha256": "06" * 32,
        "online_network_admission_sha256": "07" * 32,
        "schema": "plamen.js-dependency-materializer-runtime-identity.v1",
        "source_census_sha256": "08" * 32,
        "trust_boundary": "AUTHENTICATED_INSTALLER_LAUNCHER_BOUNDARY_V1",
    }, sort_keys=True, separators=(",", ":")).encode()
    terminal_raw = (ctypes.c_uint8 * len(terminal_payload)).from_buffer_copy(
        terminal_payload
    )
    counters = (ctypes.c_int * 2)(0, 0)

    @ExecuteCallback
    def runtime_identity(context: int, view: ctypes.POINTER(PlanView),
                         evidence: ctypes.POINTER(Evidence)) -> int:
        observed = ctypes.cast(context, ctypes.POINTER(ctypes.c_int * 2)).contents
        observed[0] += 1
        assert view.contents.method == JS_RUNTIME_IDENTITY
        _fill(evidence.contents.effect_receipt_sha256, b"R" * 32)
        evidence.contents.effect_authenticated = 1
        evidence.contents.effect_completed = 1
        evidence.contents.terminal = terminal_raw
        evidence.contents.terminal_size = len(terminal_payload)
        return 0

    @DisposeCallback
    def dispose(context: int, evidence: ctypes.POINTER(Evidence)) -> None:
        observed = ctypes.cast(context, ctypes.POINTER(ctypes.c_int * 2)).contents
        observed[1] += 1
        assert evidence.contents.method == JS_RUNTIME_IDENTITY

    executor = ExactExecutor()
    executor.version = 1
    executor.context = ctypes.cast(counters, ctypes.c_void_p)
    executor.js_runtime_identity = runtime_identity
    executor.dispose = dispose
    plan = _open_plan(native, "js_runtime_identity", plan_input)
    terminal = ctypes.c_void_p()
    terminal_size = ctypes.c_size_t()
    digest = (ctypes.c_uint8 * 32)()
    assert native.plamen_broker_v2_tool_effect_plan_execute_exact(
        plan, ctypes.byref(executor), ctypes.byref(terminal),
        ctypes.byref(terminal_size), digest,
    ) == 0
    assert ctypes.string_at(terminal, terminal_size.value) == terminal_payload
    ctypes.CDLL(None).free(terminal)
    assert counters[:] == [1, 1]
    native.plamen_broker_v2_tool_effect_plan_destroy(plan)

    missing = ExactExecutor()
    missing.version = 1
    missing.context = ctypes.cast(counters, ctypes.c_void_p)
    missing.dispose = dispose
    plan = _open_plan(native, "js_runtime_identity", plan_input)
    terminal = ctypes.c_void_p()
    terminal_size = ctypes.c_size_t()
    assert native.plamen_broker_v2_tool_effect_plan_execute_exact(
        plan, ctypes.byref(missing), ctypes.byref(terminal),
        ctypes.byref(terminal_size), digest,
    ) != 0
    view = PlanView()
    assert native.plamen_broker_v2_tool_effect_plan_view(
        plan, ctypes.byref(view)
    ) != 0
    assert counters[:] == [1, 2]
    native.plamen_broker_v2_tool_effect_plan_destroy(plan)
    assert keepalive and runtime_identity and dispose and terminal_raw


def test_managed_prepare_requires_five_typed_fds_and_leases_all(
    native: ctypes.CDLL, tmp_path: Path,
) -> None:
    policy = tmp_path / "policy.json"
    acquisition = tmp_path / "acquisition.json"
    policy.write_bytes(b"{}")
    acquisition.write_bytes(b"{}")
    project = tmp_path / "project"
    cache = tmp_path / "cache"
    generations = tmp_path / "generations"
    for root in (project, cache, generations):
        root.mkdir()
    paths = (policy, project, cache, generations, acquisition)
    fds = [os.open(path, os.O_RDONLY) for path in paths]
    try:
        descriptors = [
            (purpose, index + 1, access, _fd_identity(native, fds[index]))
            for index, (purpose, access) in enumerate((
                (0x4030, 1), (0x4031, 1), (0x4032, 3),
                (0x4033, 3), (0x4034, 1),
            ))
        ]
        payload = b'{"schema":"plamen.managed-evm-provision-plan.v1"}'
        _, prepare_input, prepare_keepalive = _request(
            native, MANAGED_PREPARE, payload, lane=MANAGED_LANE,
            descriptors=descriptors, fds=fds,
        )
        lease = _open_plan(native, "managed_evm_prepare", prepare_input)
        receipt = b'{"schema":"plamen.managed-evm-prepare.v1"}'
        evidence, evidence_keepalive = _evidence(
            prepare_input, MANAGED_PREPARE, receipt,
        )
        assert _issue_lease(native, lease, evidence) == (0, receipt)
        _, execute_input, execute_keepalive = _request(
            native, MANAGED_EXECUTE, payload, lane=MANAGED_LANE,
            capability=True,
        )
        execute = ctypes.c_void_p()
        assert native.plamen_broker_v2_tool_effect_plan_managed_evm_execute_from_lease(
            lease, ctypes.byref(execute_input), ctypes.byref(execute)
        ) == 0
        view = PlanView()
        assert native.plamen_broker_v2_tool_effect_plan_view(
            execute, ctypes.byref(view)
        ) == 0
        assert view.fd_count == 5
        assert [view.descriptors[index].purpose for index in range(5)] == list(
            range(0x4030, 0x4035)
        )
        native.plamen_broker_v2_tool_effect_plan_destroy(execute)
        native.plamen_broker_v2_tool_effect_plan_destroy(lease)

        aliased_fds = [
            os.dup(fds[0]), os.dup(fds[1]), os.dup(fds[1]),
            os.dup(fds[3]), os.dup(fds[4]),
        ]
        aliased_descriptors = list(descriptors)
        aliased_descriptors[2] = (
            0x4032, 3, 3, _fd_identity(native, fds[1]),
        )
        _, aliased_input, alias_keepalive = _request(
            native, MANAGED_PREPARE, payload, lane=MANAGED_LANE,
            descriptors=aliased_descriptors, fds=aliased_fds,
        )
        rejected = ctypes.c_void_p()
        assert native.plamen_broker_v2_tool_effect_plan_managed_evm_prepare(
            ctypes.byref(aliased_input), ctypes.byref(rejected)
        ) != 0
        assert not rejected.value
        assert (
            prepare_keepalive and evidence_keepalive and execute_keepalive
            and alias_keepalive
        )
    finally:
        for fd in fds:
            os.close(fd)


def test_snapshot_prepare_adds_read_only_audited_project_to_lease(
    native: ctypes.CDLL, tmp_path: Path,
) -> None:
    source = tmp_path / "tool"
    source.write_bytes(b"tool")
    roots = [tmp_path / name for name in ("scratch", "state", "project")]
    for root in roots:
        root.mkdir()
    paths = (source, *roots)
    fds = [os.open(path, os.O_RDONLY) for path in paths]
    try:
        descriptors = [
            (purpose, index + 1, access, _fd_identity(native, fds[index]))
            for index, (purpose, access) in enumerate((
                (0x4020, 1), (0x4021, 3), (0x4022, 3), (0x4023, 1),
            ))
        ]
        payload = b'{"schema":"plamen.snapshot-bound-tool-execution-request.v3"}'
        _, prepare_input, prepare_keepalive = _request(
            native, SNAPSHOT_PREPARE, payload, lane=SNAPSHOT_LANE,
            capability=True, descriptors=descriptors, fds=fds,
        )
        lease = _open_plan(native, "snapshot_prepare", prepare_input)
        receipt = b'{"schema":"plamen.snapshot-tool-prepare.v1"}'
        evidence, evidence_keepalive = _evidence(
            prepare_input, SNAPSHOT_PREPARE, receipt,
        )
        assert _issue_lease(native, lease, evidence) == (0, receipt)
        _, execute_input, execute_keepalive = _request(
            native, SNAPSHOT_EXECUTE, payload, lane=SNAPSHOT_LANE,
            capability=True,
        )
        execute = ctypes.c_void_p()
        assert native.plamen_broker_v2_tool_effect_plan_snapshot_execute_from_lease(
            lease, ctypes.byref(execute_input), ctypes.byref(execute)
        ) == 0
        view = PlanView()
        assert native.plamen_broker_v2_tool_effect_plan_view(
            execute, ctypes.byref(view)
        ) == 0
        assert view.fd_count == 4
        assert [view.descriptors[index].purpose for index in range(4)] == list(
            range(0x4020, 0x4024)
        )
        assert view.descriptors[3].access_mode == 1
        native.plamen_broker_v2_tool_effect_plan_destroy(execute)
        native.plamen_broker_v2_tool_effect_plan_destroy(lease)
        assert prepare_keepalive and evidence_keepalive and execute_keepalive
    finally:
        for fd in fds:
            os.close(fd)


def test_prepare_rosters_reject_missing_extra_and_access_forgery(
    native: ctypes.CDLL,
) -> None:
    js = [
        (0x4001, 1, 1), (0x4002, 2, 3),
        (0x4003, 3, 3), (0x4004, 4, 1),
    ]
    managed = [
        (0x4030, 1, 1), (0x4031, 2, 1), (0x4032, 3, 3),
        (0x4033, 4, 3), (0x4034, 5, 1),
    ]
    snapshot = [
        (0x4020, 1, 1), (0x4021, 2, 3),
        (0x4022, 3, 3), (0x4023, 4, 1),
    ]
    assert _request_encode_status(
        native, JS_LANE, JS_PREPARE, js[:-1], capability=True
    ) != 0
    assert _request_encode_status(
        native, JS_LANE, JS_PREPARE,
        js + [(0x4004, 5, 1)], capability=True,
    ) != 0
    legacy_archive_files = list(js)
    legacy_archive_files[3] = (0x4004, 4, 1)
    legacy_archive_files.append((0x4004, 5, 1))
    assert _request_encode_status(
        native, JS_LANE, JS_REPLAY, legacy_archive_files, capability=True
    ) != 0
    assert _request_encode_status(
        native, MANAGED_LANE, MANAGED_PREPARE, managed[:-1], capability=False
    ) != 0
    wrong_access = list(managed)
    wrong_access[2] = (0x4032, 3, 1)
    assert _request_encode_status(
        native, MANAGED_LANE, MANAGED_PREPARE, wrong_access, capability=False
    ) != 0
    assert _request_encode_status(
        native, SNAPSHOT_LANE, SNAPSHOT_PREPARE,
        snapshot + [(0x4023, 5, 1)], capability=True,
    ) != 0
    wrong_target = list(snapshot)
    wrong_target[3] = (0x4023, 3, 1)
    assert _request_encode_status(
        native, SNAPSHOT_LANE, SNAPSHOT_PREPARE, wrong_target, capability=True
    ) != 0
