from __future__ import annotations

import ctypes
import hashlib
import hmac
import json
import os
from pathlib import Path
import platform
import subprocess

import pytest

import posix_specialized_tool_worker as worker


ROOT = Path(__file__).resolve().parent.parent
pytestmark = pytest.mark.skipif(platform.system() != "Darwin", reason="Darwin native codec")
MAX_FDS = 16


class FDMetadata(ctypes.Structure):
    _fields_ = [("purpose", ctypes.c_uint16), ("target", ctypes.c_uint16),
                ("access_mode", ctypes.c_uint8), ("identity", ctypes.c_uint8 * 32)]


class PlanView(ctypes.Structure):
    _fields_ = [
        ("version", ctypes.c_uint32), ("lane", ctypes.c_uint16),
        ("method", ctypes.c_uint16), ("flags", ctypes.c_uint16),
        ("authority_binding_sha256", ctypes.c_uint8 * 32),
        ("operation_nonce", ctypes.c_uint8 * 32),
        ("request_sha256", ctypes.c_uint8 * 32),
        ("effects_context_sha256", ctypes.c_uint8 * 32),
        ("archive_root_identity_sha256", ctypes.c_uint8 * 32),
        ("archive_manifest_sha256", ctypes.c_uint8 * 32),
        ("archive_census_sha256", ctypes.c_uint8 * 32),
        ("payload", ctypes.POINTER(ctypes.c_uint8)), ("payload_size", ctypes.c_size_t),
        ("descriptors", ctypes.POINTER(FDMetadata)),
        ("fds", ctypes.POINTER(ctypes.c_int)), ("fd_count", ctypes.c_size_t),
    ]


class WorkerFD(ctypes.Structure):
    _fields_ = [
        ("version", ctypes.c_uint32), ("role", ctypes.c_uint16),
        ("purpose", ctypes.c_uint16), ("target", ctypes.c_uint16),
        ("access_mode", ctypes.c_uint8), ("kind", ctypes.c_uint8),
        ("provenance", ctypes.c_uint8), ("native_identity", ctypes.c_uint8 * 32),
        ("host_fd", ctypes.c_int), ("guest_fd", ctypes.c_uint32),
        ("payload_sha256", ctypes.c_uint8 * 32),
        ("payload_bytes", ctypes.c_uint64), ("payload_entries", ctypes.c_uint64),
    ]


class Env(ctypes.Structure):
    _fields_ = [("name", ctypes.c_char_p), ("value", ctypes.c_char_p)]


class Limits(ctypes.Structure):
    _fields_ = [(name, ctypes.c_uint64) for name in (
        "duration_ms", "memory_bytes", "open_fds", "output_bytes",
        "output_files", "stderr_bytes", "stdout_bytes",
    )]


class Launch(ctypes.Structure):
    _fields_ = [
        ("version", ctypes.c_uint32), ("provider_mode", ctypes.c_uint16),
        ("request_id", ctypes.c_char_p),
        ("worker_runtime_sha256", ctypes.c_uint8 * 32),
        ("worker_runtime_size", ctypes.c_uint64),
        ("tool_anchor_id", ctypes.c_char_p),
        ("oci_image_sha256", ctypes.c_uint8 * 32),
        ("runtime_manifest_sha256", ctypes.c_uint8 * 32),
        ("tool_image_member_sha256", ctypes.c_uint8 * 32),
        ("tool_image_member_size", ctypes.c_uint64),
        ("managed_provisioner_sha256", ctypes.c_uint8 * 32),
        ("managed_provisioner_size", ctypes.c_uint64),
        ("js_offline_materializer_sha256", ctypes.c_uint8 * 32),
        ("js_offline_materializer_size", ctypes.c_uint64),
        ("argv", ctypes.POINTER(ctypes.c_char_p)), ("argc", ctypes.c_size_t),
        ("environment", ctypes.POINTER(Env)), ("environment_count", ctypes.c_size_t),
        ("cwd_role", ctypes.c_uint16), ("cwd_relative", ctypes.c_char_p),
        ("limits", Limits),
        ("slither_forge_sha256", ctypes.c_uint8 * 32),
        ("slither_forge_size", ctypes.c_uint64),
        ("slither_solc_sha256", ctypes.c_uint8 * 32),
        ("slither_solc_size", ctypes.c_uint64),
        ("slither_python_sha256", ctypes.c_uint8 * 32),
        ("slither_python_size", ctypes.c_uint64),
        ("slither_internal_environment_sha256", ctypes.c_uint8 * 32),
    ]


class Binding(ctypes.Structure):
    _fields_ = [
        ("version", ctypes.c_uint32), ("provider_mode", ctypes.c_uint16),
        ("lane", ctypes.c_uint16),
        ("method", ctypes.c_uint16), ("operation", ctypes.c_char * 32),
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
        ("role_present", ctypes.c_uint8 * 8), ("limits", Limits),
        ("slither_forge_sha256", ctypes.c_uint8 * 32),
        ("slither_forge_size", ctypes.c_uint64),
        ("slither_solc_sha256", ctypes.c_uint8 * 32),
        ("slither_solc_size", ctypes.c_uint64),
        ("slither_python_sha256", ctypes.c_uint8 * 32),
        ("slither_python_size", ctypes.c_uint64),
        ("slither_internal_environment_sha256", ctypes.c_uint8 * 32),
    ]


class TerminalAuth(ctypes.Structure):
    _fields_ = [("version", ctypes.c_uint32),
                ("terminal_hmac_key", ctypes.c_uint8 * 32),
                ("terminal_hmac_sha256", ctypes.c_uint8 * 32)]


class Observation(ctypes.Structure):
    _fields_ = [
        ("version", ctypes.c_uint32), ("status", ctypes.c_char * 40),
        ("returncode", ctypes.c_int32), ("duration_ms", ctypes.c_uint64),
        ("peak_memory_bytes", ctypes.c_uint64),
        ("stdout_observed_bytes", ctypes.c_uint64),
        ("stdout_retained_bytes", ctypes.c_uint64), ("stdout_sha256", ctypes.c_uint8 * 32),
        ("stderr_observed_bytes", ctypes.c_uint64),
        ("stderr_retained_bytes", ctypes.c_uint64), ("stderr_sha256", ctypes.c_uint8 * 32),
        ("output_file_count", ctypes.c_uint64), ("output_bytes", ctypes.c_uint64),
        ("output_manifest_sha256", ctypes.c_uint8 * 32),
        ("projection_observation_sha256", ctypes.c_uint8 * 32),
        ("observed_egress_sha256", ctypes.c_uint8 * 32),
        ("descriptor_post_sha256", (ctypes.c_uint8 * 32) * 8),
        ("terminal_sha256", ctypes.c_uint8 * 32),
        ("terminal_hmac_sha256", ctypes.c_uint8 * 32),
    ]


@pytest.fixture(scope="module")
def native(tmp_path_factory: pytest.TempPathFactory) -> ctypes.CDLL:
    output = tmp_path_factory.mktemp("specialized-request-codec") / "codec.dylib"
    subprocess.run([
        "/usr/bin/clang", "-std=c11", "-Wall", "-Wextra", "-Werror",
        "-dynamiclib", "-I", str(ROOT / "native/include"),
        "-I", str(ROOT / "native/darwin"),
        str(ROOT / "native/darwin/plamen_broker_v2_specialized_request.c"),
        str(ROOT / "native/darwin/plamen_broker_v2_specialized_output_census.c"),
        str(ROOT / "native/darwin/plamen_broker_v2_specialized_output_receipt.c"),
        str(ROOT / "native/posix/plamen_broker_v2_protocol.c"),
        "-framework", "Security", "-framework", "CoreFoundation",
        "-o", str(output),
    ], cwd=ROOT, check=True, stdin=subprocess.DEVNULL,
       stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
    library = ctypes.CDLL(str(output))
    library.plamen_broker_v2_fd_identity.argtypes = [ctypes.c_int, ctypes.POINTER(ctypes.c_uint8)]
    library.plamen_broker_v2_fd_identity.restype = ctypes.c_int
    library.plamen_broker_v2_specialized_worker_request_build.argtypes = [
        ctypes.POINTER(PlanView), ctypes.POINTER(WorkerFD), ctypes.c_size_t,
        ctypes.POINTER(Launch), ctypes.c_void_p, ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_size_t), ctypes.POINTER(Binding),
    ]
    library.plamen_broker_v2_specialized_worker_request_build.restype = ctypes.c_int
    library.plamen_broker_v2_specialized_worker_terminal_parse.argtypes = [
        ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(Binding),
        ctypes.POINTER(TerminalAuth), ctypes.POINTER(Observation),
    ]
    library.plamen_broker_v2_specialized_worker_terminal_parse.restype = ctypes.c_int
    library.plamen_broker_v2_specialized_worker_tool_anchor_path.argtypes = [
        ctypes.c_uint16, ctypes.c_uint16, ctypes.c_char_p,
        ctypes.POINTER(ctypes.c_char_p),
    ]
    library.plamen_broker_v2_specialized_worker_tool_anchor_path.restype = ctypes.c_int
    library.plamen_broker_v2_specialized_slither_internal_environment_sha256.argtypes = [
        ctypes.POINTER(ctypes.c_uint8)
    ]
    library.plamen_broker_v2_specialized_slither_internal_environment_sha256.restype = ctypes.c_int
    return library


def _fill(target: object, value: bytes) -> None:
    target[:] = value


def _seal(value: dict[str, object]) -> bytes:
    unsigned = dict(value)
    unsigned.pop("request_sha256", None)
    value["request_sha256"] = hashlib.sha256(
        worker.canonical_bytes(unsigned)
    ).hexdigest()
    return worker.canonical_bytes(value)


def _identity(native: ctypes.CDLL, fd: int) -> bytes:
    result = (ctypes.c_uint8 * 32)()
    assert native.plamen_broker_v2_fd_identity(fd, result) == 0
    return bytes(result)


def _snapshot_payload(tool_id: str) -> dict[str, object]:
    return {
        "egress_policy": "DENY_ALL",
        "mounts": [
            {"guest_path": "/workspace/source", "mode": "READ_ONLY",
             "mount_id": "analysis-input", "source_sha256": "1" * 64},
            {"guest_path": "/workspace/project", "mode": "READ_ONLY",
             "mount_id": "project", "source_sha256": "2" * 64},
            {"guest_path": "/workspace/scratch", "mode": "READ_WRITE_EXCLUSIVE",
             "mount_id": "scratch", "source_sha256": "3" * 64},
            {"guest_path": "/workspace/state", "mode": "READ_WRITE_EXCLUSIVE",
             "mount_id": "state", "source_sha256": "4" * 64},
        ],
        "schema": "plamen.snapshot-bound-tool-execution-request.v3",
        "source_descriptor": {"descriptor_sha256": "1" * 64,
                              "kind": "directory"},
        "tool_id": tool_id,
    }


def _case(native: ctypes.CDLL, tmp_path: Path, lane: int, method: int) -> tuple[bytes, Binding, list[int], object]:
    directories = {}
    for role in ("acquisition", "cache", "generation", "project", "scratch", "state"):
        path = tmp_path / f"{lane}-{role}"
        path.mkdir()
        directories[role] = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    source = tmp_path / f"{lane}-source"
    if lane in {1, 3, 4}:
        source.mkdir()
        directories["source"] = os.open(
            source, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        )
    else:
        source.write_bytes(b"source\n")
        directories["source"] = os.open(source, os.O_RDONLY)
    directories["tool"] = os.open("/bin/echo", os.O_RDONLY)
    role_ids = {name: index + 1 for index, name in enumerate(worker._ROLES)}
    if lane == 1:
        payload_obj = {"network_mode": "NO_NETWORK", "operation": "OFFLINE_REPLAY",
                       "schema": "plamen.js-dependency-native-request.v2"}
        plan_roles = ("source", "scratch", "state")
        purposes = (0x4001, 0x4002, 0x4003)
    elif lane == 2:
        receipt = tmp_path / "managed-acquisition"
        receipt.write_bytes(b"receipt")
        os.close(directories["acquisition"])
        directories["acquisition"] = os.open(receipt, os.O_RDONLY)
        payload_obj = {"schema": "plamen.managed-evm-python-native-plan.v1"}
        plan_roles = ("source", "project", "cache", "generation", "acquisition")
        purposes = tuple(range(0x4030, 0x4035))
    elif lane == 3:
        receipt_body = {
            "lock_selection_sha256": "5" * 64,
            "modules_tree": {
                "algorithm": "PLAMEN_CANONICAL_TREE_SHA256_V1",
                "entry_count": 0,
                "expanded_bytes": 0,
                "sha256": "6" * 64,
            },
            "schema": "plamen.js-dependency-materialization-receipt.v2",
        }
        receipt = receipt_body | {
            "receipt_sha256": hashlib.sha256(
                worker.canonical_bytes(receipt_body)
            ).hexdigest(),
        }
        payload_obj = {
            "dependency_materialization_receipt": receipt,
            "original_source_scope_sha256": "7" * 64,
            "run_id": "run-projection-1",
            "schema": "plamen.evm-analysis-projection-native-request.v1",
        }
        plan_roles = ("project", "scratch", "state", "source")
        purposes = (0x4010, 0x4011, 0x4012, 0x4016)
    else:
        payload_obj = _snapshot_payload("forge")
        plan_roles = ("source", "scratch", "state", "project")
        purposes = tuple(range(0x4020, 0x4024))
    payload = worker.canonical_bytes(payload_obj) + (b"\n" if lane == 1 else b"")
    payload_raw = (ctypes.c_uint8 * len(payload)).from_buffer_copy(payload)
    metadata = (FDMetadata * len(plan_roles))()
    plan_fds = (ctypes.c_int * len(plan_roles))()
    for index, (role, purpose) in enumerate(zip(plan_roles, purposes)):
        fd = directories[role]
        plan_fds[index] = fd
        metadata[index].purpose = purpose
        metadata[index].target = index + 1
        metadata[index].access_mode = 3 if role in {"cache", "generation", "scratch", "state"} else 1
        _fill(metadata[index].identity, _identity(native, fd))
    view = PlanView(version=1, lane=lane, method=method, payload=payload_raw,
                    payload_size=len(payload), descriptors=metadata,
                    fds=plan_fds, fd_count=len(plan_roles))
    _fill(view.request_sha256, b"R" * 32)
    _fill(view.effects_context_sha256, b"E" * 32)
    included = set(
        worker._ROLES
        if lane not in {3, 4}
        else ("project", "scratch", "source", "state", "tool")
    )
    roster = (WorkerFD * len(included))()
    for index, role in enumerate(name for name in worker._ROLES if name in included):
        fd = directories[role]
        roster[index].version = 1
        roster[index].role = role_ids[role]
        roster[index].host_fd = -1 if lane == 3 and role == "tool" else fd
        roster[index].guest_fd = 0 if lane == 3 else fd
        roster[index].kind = (
            3 if role == "tool" and lane == 3 else
            1 if role == "tool" or (role == "source" and lane == 2)
            or (lane == 2 and role == "acquisition") else 2
        )
        roster[index].access_mode = 3 if role in {"cache", "generation", "scratch", "state"} else 1
        if role in plan_roles:
            plan_index = plan_roles.index(role)
            roster[index].purpose = purposes[plan_index]
            roster[index].target = plan_index + 1
            roster[index].provenance = 1
        else:
            roster[index].purpose = 0x5000 + role_ids[role]
            roster[index].target = 0x100 + role_ids[role]
            roster[index].provenance = 2
        if lane == 3:
            if role == "tool":
                _fill(roster[index].payload_sha256, b"T" * 32)
                roster[index].payload_bytes = 8192
                roster[index].payload_entries = 1
            else:
                observed = worker._apple_payload_observation(
                    fd, "DIRECTORY",
                    {
                        "output_files": worker.MAX_OUTPUT_FILES,
                        "output_bytes": worker.MAX_OUTPUT_BYTES,
                    },
                )
                _fill(
                    roster[index].payload_sha256,
                    bytes.fromhex(str(observed["payload_sha256"])),
                )
                roster[index].payload_bytes = int(observed["payload_bytes"])
                roster[index].payload_entries = int(observed["payload_entries"])
                _fill(roster[index].native_identity, _identity(native, fd))
        else:
            _fill(roster[index].native_identity, _identity(native, fd))
    argv = (ctypes.c_char_p * 2)(b"@fd:tool", b"@fd:source")
    launch = Launch(version=1, provider_mode=2 if lane == 3 else 1,
                    request_id=f"lane-{lane}".encode(), argv=argv,
                    argc=1 if lane == 3 else 2,
                    cwd_role=role_ids["scratch"], cwd_relative=b".",
                    limits=Limits(5000, 512 * 1024 * 1024, 32, 1024 * 1024,
                                  128, 4096, 4096))
    _fill(launch.worker_runtime_sha256, b"W" * 32)
    if lane == 3:
        launch.tool_anchor_id = b"js-python"
        launch.worker_runtime_size = 4096
        _fill(launch.oci_image_sha256, b"I" * 32)
        _fill(launch.runtime_manifest_sha256, b"M" * 32)
        _fill(launch.tool_image_member_sha256, b"T" * 32)
        launch.tool_image_member_size = 8192
        _fill(launch.slither_solc_sha256, b"C" * 32)
        launch.slither_solc_size = 12345
    output = (ctypes.c_uint8 * (1024 * 1024))()
    size = ctypes.c_size_t()
    binding = Binding()
    keepalive = (payload_raw, metadata, plan_fds, roster, argv, launch, view)
    assert native.plamen_broker_v2_specialized_worker_request_build(
        ctypes.byref(view), roster, len(roster), ctypes.byref(launch), output,
        len(output), ctypes.byref(size), ctypes.byref(binding),
    ) == 0
    return bytes(output[:size.value]), binding, list(directories.values()), keepalive


@pytest.mark.parametrize(("lane", "method", "operation"), [
    (1, 0x2103, "OFFLINE_REPLAY"),
    (2, 0x2203, "MANAGED_EVM_EXECUTE"),
    (3, 0x2301, "EVM_PROJECTION_COMMIT"),
    (4, 0x2404, "SNAPSHOT_TOOL_EXECUTE"),
])
def test_native_translation_is_accepted_by_exact_guest_parser(
    native: ctypes.CDLL, tmp_path: Path, lane: int, method: int, operation: str,
) -> None:
    raw, binding, opened, keepalive = _case(native, tmp_path, lane, method)
    try:
        if lane == 3:
            parsed = worker._parse_apple_attached_request(raw)
            observations = {
                role: row for role, row in parsed["descriptors"].items()
                if row is not None
            }
        else:
            parsed, observations = worker.parse_request(raw)
        assert parsed["operation"] == operation
        assert parsed["network_mode"] == "DENY_ALL"
        assert parsed["argv"] == (
            ["@fd:tool"] if lane == 3 else ["@fd:tool", "@fd:source"]
        )
        assert set(observations) == (
            set(worker._ROLES) if lane not in {3, 4}
            else {"project", "scratch", "source", "state", "tool"}
        )
        if lane == 3:
            assert parsed["projection_solc_sha256"] == (b"C" * 32).hex()
            assert parsed["projection_solc_size"] == 12345
            assert bytes(binding.slither_solc_sha256) == b"C" * 32
            assert binding.slither_solc_size == 12345
        assert hashlib.sha256(worker.canonical_bytes({
            key: value for key, value in parsed.items() if key != "request_sha256"
        })).digest() == bytes(binding.worker_request_sha256)
        assert keepalive
    finally:
        for fd in opened:
            os.close(fd)


def test_terminal_requires_exact_schema_replay_bounds_and_native_hmac(
    native: ctypes.CDLL, tmp_path: Path,
) -> None:
    request_raw, binding, opened, keepalive = _case(native, tmp_path, 1, 0x2103)
    request = json.loads(request_raw)
    terminal = {
        "descriptor_post": {key: value["identity_sha256"] for key, value in request["descriptors"].items() if value},
        "descriptor_pre": {key: value["identity_sha256"] for key, value in request["descriptors"].items() if value},
        "duration_ms": 1,
        "effects_binding_sha256": request["effects_binding_sha256"],
        "host_authority_required": ["HMAC_AUTHENTICATION", "MOUNT_RECENSUS", "NETWORK_DENIAL", "POPULATION_ZERO"],
        "network": {"guest_observation": "NATIVE_PROVIDER_EVIDENCE_REQUIRED", "mode": "DENY_ALL",
                    "observed_egress_sha256": worker.EMPTY_LIST_SHA256},
        "operation": request["operation"],
        "output_manifest": {"byte_count": 0, "file_count": 0,
                            "sha256": hashlib.sha256(b"[]").hexdigest()},
        "peak_memory_bytes": 1, "process_group_kill_issued": True,
        "request_id": request["request_id"], "request_sha256": request["request_sha256"],
        "returncode": 0, "schema": worker.TERMINAL_SCHEMA, "status": "COMPLETE",
        "stderr": {"observed_bytes": 0, "retained_bytes": 0, "sha256": hashlib.sha256(b"").hexdigest()},
        "stdout": {"observed_bytes": 0, "retained_bytes": 0, "sha256": hashlib.sha256(b"").hexdigest()},
        "worker_runtime_sha256": request["worker_runtime_sha256"],
    }
    raw = worker.canonical_bytes(terminal)
    key = b"K" * 32
    tag = hmac.new(key, b"PLAMEN-SPECIALIZED-WORKER-TERMINAL-V1\0\0" + raw, hashlib.sha256).digest()
    auth = TerminalAuth(version=1)
    _fill(auth.terminal_hmac_key, key)
    _fill(auth.terminal_hmac_sha256, tag)
    observed = Observation()
    try:
        assert native.plamen_broker_v2_specialized_worker_terminal_parse(
            raw, len(raw), ctypes.byref(binding), ctypes.byref(auth), ctypes.byref(observed),
        ) == 0
        assert observed.version == 1 and observed.status == b"COMPLETE"
        assert bytes(observed.terminal_sha256) == hashlib.sha256(raw).digest()

        terminal["unknown"] = True
        forged = worker.canonical_bytes(terminal)
        forged_tag = hmac.new(key, b"PLAMEN-SPECIALIZED-WORKER-TERMINAL-V1\0\0" + forged, hashlib.sha256).digest()
        _fill(auth.terminal_hmac_sha256, forged_tag)
        assert native.plamen_broker_v2_specialized_worker_terminal_parse(
            forged, len(forged), ctypes.byref(binding), ctypes.byref(auth), ctypes.byref(observed),
        ) != 0

        terminal.pop("unknown")
        terminal["descriptor_post"]["source"] = "0" * 64
        forged = worker.canonical_bytes(terminal)
        _fill(auth.terminal_hmac_sha256, hmac.new(
            key, b"PLAMEN-SPECIALIZED-WORKER-TERMINAL-V1\0\0" + forged,
            hashlib.sha256,
        ).digest())
        assert native.plamen_broker_v2_specialized_worker_terminal_parse(
            forged, len(forged), ctypes.byref(binding), ctypes.byref(auth), ctypes.byref(observed),
        ) != 0

        _fill(auth.terminal_hmac_sha256, b"X" * 32)
        assert native.plamen_broker_v2_specialized_worker_terminal_parse(
            raw, len(raw), ctypes.byref(binding), ctypes.byref(auth), ctypes.byref(observed),
        ) != 0
    finally:
        assert keepalive
        for fd in opened:
            os.close(fd)


def test_projection_translation_rejects_path_and_descriptor_kind_substitution(
    native: ctypes.CDLL, tmp_path: Path,
) -> None:
    raw, _binding, opened, keepalive = _case(native, tmp_path, 3, 0x2301)
    try:
        request = json.loads(raw)
        assert set(request) == worker._APPLE_PROJECTION_REQUEST_KEYS
        request["environment"] = [["PATH", "/tmp/caller-controlled"]]
        with pytest.raises(worker.SpecializedToolWorkerError) as raised:
            worker._parse_apple_attached_request(_seal(request))
        assert raised.value.code == "AMBIENT_OR_LOADER_ENVIRONMENT_DENIED"

        request = json.loads(raw)
        request["descriptors"]["source"]["kind"] = "REGULAR_FILE"
        with pytest.raises(worker.SpecializedToolWorkerError) as raised:
            worker._parse_apple_attached_request(_seal(request))
        assert raised.value.code == "DESCRIPTOR_KIND_MISMATCH"
        assert keepalive
    finally:
        for fd in opened:
            os.close(fd)


def test_online_duplicate_and_non_utf8_payloads_fail_before_request_emission(
    native: ctypes.CDLL, tmp_path: Path,
) -> None:
    raw, binding, opened, keepalive = _case(native, tmp_path, 1, 0x2103)
    del raw, binding
    view = keepalive[-1]
    roster = keepalive[3]
    launch = keepalive[5]
    output = (ctypes.c_uint8 * 8192)()
    size = ctypes.c_size_t(99)
    rejected = Binding()
    try:
        for payload in (
            b'{"network_mode":"NO_NETWORK","operation":"ONLINE_INSTALL","schema":"plamen.js-dependency-native-request.v2"}',
            b'{"network_mode":"NO_NETWORK","operation":"OFFLINE_REPLAY","schema":"a","schema":"plamen.js-dependency-native-request.v2"}',
            b'{"network_mode":"NO_NETWORK","operation":"OFFLINE_REPLAY","schema":"plamen.js-dependency-native-request.v2","x":"\xff"}',
        ):
            payload_raw = (ctypes.c_uint8 * len(payload)).from_buffer_copy(payload)
            view.payload = payload_raw
            view.payload_size = len(payload)
            assert native.plamen_broker_v2_specialized_worker_request_build(
                ctypes.byref(view), roster, len(roster), ctypes.byref(launch), output,
                len(output), ctypes.byref(size), ctypes.byref(rejected),
            ) != 0
            assert size.value == 0 and rejected.version == 0

        view.payload = keepalive[0]
        view.payload_size = len(bytes(keepalive[0]))
        launch.argv[1] = b"/tmp/ambient"
        assert native.plamen_broker_v2_specialized_worker_request_build(
            ctypes.byref(view), roster, len(roster), ctypes.byref(launch), output,
            len(output), ctypes.byref(size), ctypes.byref(rejected),
        ) == -4
        launch.argv[1] = b"@fd:source"

        assert native.plamen_broker_v2_specialized_worker_request_build(
            ctypes.byref(view), roster, len(roster) - 1, ctypes.byref(launch), output,
            len(output), ctypes.byref(size), ctypes.byref(rejected),
        ) == -3
        original_guest_fd = roster[1].guest_fd
        roster[1].guest_fd = roster[0].guest_fd
        assert native.plamen_broker_v2_specialized_worker_request_build(
            ctypes.byref(view), roster, len(roster), ctypes.byref(launch), output,
            len(output), ctypes.byref(size), ctypes.byref(rejected),
        ) == -3
        roster[1].guest_fd = original_guest_fd
    finally:
        for fd in opened:
            os.close(fd)


@pytest.mark.parametrize(("lane", "method", "anchor", "path"), [
    (1, 0x2103, "js-python", "/usr/local/lib/plamen/python/bin/python3.12"),
    (2, 0x2203, "managed-python", "/usr/local/lib/plamen/python/bin/python3.12"),
    (4, 0x2404, "forge", "/usr/local/lib/plamen/toolchains/foundry/bin/forge"),
    (4, 0x2404, "opengrep", "/usr/local/lib/plamen/toolchains/opengrep/bin/opengrep"),
    (4, 0x2404, "slither", "/usr/local/lib/plamen/toolchains/managed-evm/bin/slither"),
    (4, 0x2404, "solc", "/usr/local/lib/plamen/toolchains/solc-amd64/solc"),
])
def test_apple_image_member_request_matches_guest_contract_and_fixed_anchor(
    native: ctypes.CDLL, tmp_path: Path, lane: int, method: int,
    anchor: str, path: str,
) -> None:
    _raw, _binding, opened, keepalive = _case(native, tmp_path, lane, method)
    view, roster, launch = keepalive[-1], keepalive[3], keepalive[5]
    payload_keepalive = None
    if lane == 4:
        payload = worker.canonical_bytes(_snapshot_payload(anchor))
        payload_keepalive = (ctypes.c_uint8 * len(payload)).from_buffer_copy(payload)
        view.payload = payload_keepalive
        view.payload_size = len(payload)
    tool_sha = hashlib.sha256(f"image:{anchor}".encode()).digest()
    empty_tree = hashlib.sha256(b"[]").digest()
    for item in roster:
        item.guest_fd = 0
        if item.role == 8:
            item.kind = 3
            item.host_fd = -1
            item.native_identity[:] = bytes(32)
            item.payload_sha256[:] = tool_sha
            item.payload_bytes = 4096
            item.payload_entries = 1
        elif item.kind == 1:
            info = os.fstat(item.host_fd)
            item.payload_sha256[:] = hashlib.sha256(
                os.pread(item.host_fd, info.st_size, 0)
            ).digest()
            item.payload_bytes = info.st_size
            item.payload_entries = 1
        else:
            item.payload_sha256[:] = empty_tree
            item.payload_bytes = 0
            item.payload_entries = 0
    request_roster = roster
    if lane == 1:
        request_roster = (WorkerFD * 5)(
            *(item for item in roster if item.role in {1, 5, 6, 7, 8})
        )
    launch.provider_mode = 2
    launch.worker_runtime_size = 8192
    launch.tool_anchor_id = anchor.encode()
    launch.oci_image_sha256[:] = b"I" * 32
    launch.runtime_manifest_sha256[:] = b"M" * 32
    launch.tool_image_member_sha256[:] = tool_sha
    launch.tool_image_member_size = 4096
    apple_argv_keepalive = None
    if lane == 1:
        apple_argv_keepalive = (ctypes.c_char_p * 14)(
            b"@fd:tool", b"-I", b"-S", b"-B",
            b"@image:js-offline-materializer", b"offline-replay",
            b"--acquisition-root", b"@fd:acquisition",
            b"--source-root", b"@fd:source",
            b"--scratch-root", b"@fd:scratch",
            b"--state-root", b"@fd:state",
        )
        launch.argv = apple_argv_keepalive
        launch.argc = len(apple_argv_keepalive)
        launch.js_offline_materializer_sha256[:] = b"J" * 32
        launch.js_offline_materializer_size = 12288
    elif lane == 2:
        apple_argv_keepalive = (ctypes.c_char_p * 16)(
            b"@fd:tool", b"-I", b"-S", b"-B",
            b"@image:managed-provisioner", b"--policy", b"@fd:source",
            b"--generation", b"@fd:generation", b"--cache", b"@fd:cache",
            b"--project-root", b"@fd:project", b"--acquisition-receipt",
            b"@fd:acquisition", b"--offline",
        )
        launch.argv = apple_argv_keepalive
        launch.argc = len(apple_argv_keepalive)
        launch.cwd_role = 4
        launch.managed_provisioner_sha256[:] = b"P" * 32
        launch.managed_provisioner_size = 16384
    elif anchor == "slither":
        launch.slither_forge_sha256[:] = b"F" * 32
        launch.slither_forge_size = 4096
        launch.slither_solc_sha256[:] = b"S" * 32
        launch.slither_solc_size = 8192
        launch.slither_python_sha256[:] = b"P" * 32
        launch.slither_python_size = 12288
        assert native.plamen_broker_v2_specialized_slither_internal_environment_sha256(
            launch.slither_internal_environment_sha256
        ) == 0
    output = (ctypes.c_uint8 * (1024 * 1024))()
    size = ctypes.c_size_t()
    binding = Binding()
    guest_path = ctypes.c_char_p()
    try:
        assert native.plamen_broker_v2_specialized_worker_request_build(
            ctypes.byref(view), request_roster, len(request_roster), ctypes.byref(launch), output,
            len(output), ctypes.byref(size), ctypes.byref(binding),
        ) == 0
        raw = bytes(output[:size.value])
        parsed = worker._parse_apple_attached_request(raw)
        assert parsed["schema"] == worker.APPLE_REQUEST_SCHEMA
        assert parsed["tool_anchor_id"] == anchor
        assert parsed["runtime_closure_sha256"] == bytes(
            binding.runtime_closure_sha256
        ).hex()
        assert parsed["descriptors"]["tool"] == {
            "access": "READ_ONLY", "kind": "IMAGE_MEMBER",
            "payload_bytes": 4096, "payload_entries": 1,
            "payload_sha256": tool_sha.hex(),
        }
        if anchor == "slither":
            assert parsed["slither_forge_sha256"] == (b"F" * 32).hex()
            assert parsed["slither_solc_sha256"] == (b"S" * 32).hex()
            assert parsed["slither_python_sha256"] == (b"P" * 32).hex()
            assert parsed["slither_internal_environment_sha256"] == (
                worker.SLITHER_INTERNAL_ENVIRONMENT_SHA256
            )
            descriptor_replay = {
                role: (b"D" * 32).hex()
                for role, row in parsed["descriptors"].items()
                if row is not None
            }
            terminal = {
                "apple_mount_payload_sha256": bytes(
                    binding.apple_mount_payload_sha256
                ).hex(),
                "descriptor_post": descriptor_replay,
                "descriptor_pre": descriptor_replay,
                "duration_ms": 1,
                "effects_binding_sha256": parsed["effects_binding_sha256"],
                "host_authority_required": [
                    "HMAC_AUTHENTICATION", "MOUNT_RECENSUS",
                    "NETWORK_DENIAL", "POPULATION_ZERO",
                ],
                "network": {
                    "guest_observation": "NATIVE_PROVIDER_EVIDENCE_REQUIRED",
                    "mode": "DENY_ALL",
                    "observed_egress_sha256": worker.EMPTY_LIST_SHA256,
                },
                "operation": "SNAPSHOT_TOOL_EXECUTE",
                "output_manifest": {
                    "byte_count": 0, "file_count": 0,
                    "sha256": hashlib.sha256(b"[]").hexdigest(),
                },
                "peak_memory_bytes": 1,
                "process_group_kill_issued": True,
                "request_id": parsed["request_id"],
                "request_sha256": parsed["request_sha256"],
                "returncode": 0,
                "runtime_closure_sha256": parsed["runtime_closure_sha256"],
                "schema": worker.APPLE_TERMINAL_SCHEMA,
                "slither_forge_sha256": parsed["slither_forge_sha256"],
                "slither_forge_size": parsed["slither_forge_size"],
                "slither_internal_environment_sha256": parsed[
                    "slither_internal_environment_sha256"
                ],
                "slither_python_sha256": parsed["slither_python_sha256"],
                "slither_python_size": parsed["slither_python_size"],
                "slither_solc_sha256": parsed["slither_solc_sha256"],
                "slither_solc_size": parsed["slither_solc_size"],
                "status": "COMPLETE",
                "stderr": {
                    "observed_bytes": 0, "retained_bytes": 0,
                    "sha256": hashlib.sha256(b"").hexdigest(),
                },
                "stdout": {
                    "observed_bytes": 0, "retained_bytes": 0,
                    "sha256": hashlib.sha256(b"").hexdigest(),
                },
                "tool_anchor_id": "slither",
                "tool_image_member_sha256": tool_sha.hex(),
                "worker_runtime_sha256": parsed["worker_runtime_sha256"],
            }
            key = b"K" * 32
            auth = TerminalAuth(version=1)
            auth.terminal_hmac_key[:] = key
            observation = Observation()

            def parse_terminal(value: dict[str, object]) -> int:
                terminal_raw = worker.canonical_bytes(value)
                auth.terminal_hmac_sha256[:] = hmac.new(
                    key,
                    b"PLAMEN-SPECIALIZED-WORKER-TERMINAL-V1\0\0"
                    + terminal_raw,
                    hashlib.sha256,
                ).digest()
                return native.plamen_broker_v2_specialized_worker_terminal_parse(
                    terminal_raw, len(terminal_raw), ctypes.byref(binding),
                    ctypes.byref(auth), ctypes.byref(observation),
                )

            assert parse_terminal(terminal) == 0
            terminal["slither_forge_sha256"] = "0" * 64
            assert parse_terminal(terminal) != 0
            terminal["slither_forge_sha256"] = parsed["slither_forge_sha256"]
            terminal["slither_internal_environment_sha256"] = "0" * 64
            assert parse_terminal(terminal) != 0

            denied_environment = (Env * 1)(Env(b"PATH", b"/tmp/injected"))
            launch.environment = denied_environment
            launch.environment_count = 1
            assert native.plamen_broker_v2_specialized_worker_request_build(
                ctypes.byref(view), request_roster, len(request_roster),
                ctypes.byref(launch), output, len(output), ctypes.byref(size),
                ctypes.byref(binding),
            ) != 0
            launch.environment = None
            launch.environment_count = 0

            writable = _snapshot_payload("slither")
            writable["mounts"][1]["mode"] = "READ_WRITE_EXCLUSIVE"
            writable_raw = worker.canonical_bytes(writable)
            writable_keepalive = (
                ctypes.c_uint8 * len(writable_raw)
            ).from_buffer_copy(writable_raw)
            view.payload = writable_keepalive
            view.payload_size = len(writable_raw)
            assert native.plamen_broker_v2_specialized_worker_request_build(
                ctypes.byref(view), request_roster, len(request_roster),
                ctypes.byref(launch), output, len(output), ctypes.byref(size),
                ctypes.byref(binding),
            ) != 0
            view.payload = payload_keepalive
            view.payload_size = len(payload)
        assert native.plamen_broker_v2_specialized_worker_tool_anchor_path(
            lane, method, anchor.encode(), ctypes.byref(guest_path),
        ) == 0
        assert guest_path.value.decode() == path

        launch.tool_anchor_id = b"forge" if anchor == "managed-python" else b"managed-python"
        assert native.plamen_broker_v2_specialized_worker_request_build(
            ctypes.byref(view), request_roster, len(request_roster), ctypes.byref(launch), output,
            len(output), ctypes.byref(size), ctypes.byref(binding),
        ) == -2
        assert payload_keepalive is not None or lane in {1, 2}
    finally:
        for fd in opened:
            os.close(fd)
