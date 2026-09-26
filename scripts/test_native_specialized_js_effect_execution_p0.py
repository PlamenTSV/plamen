from __future__ import annotations

import ctypes
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess

import pytest

import scripts.test_darwin_specialized_tool_effects as base


ROOT = Path(__file__).resolve().parents[1]
NATIVE_TESTS = ROOT / "native/tests"
pytestmark = pytest.mark.skipif(
    platform.system() != "Darwin", reason="Darwin native service integration",
)


def _compile(output: Path) -> ctypes.CDLL:
    completed = subprocess.run([
        "/usr/bin/clang", "-std=c11", "-Wall", "-Wextra", "-Werror",
        "-fblocks", "-dynamiclib", "-DPLAMEN_TEST_REAL_METHOD_CODEC=1",
        "-I", str(ROOT / "native/darwin"), "-I", str(ROOT / "native/posix"),
        "-I", str(ROOT / "native/include"),
        str(NATIVE_TESTS / "plamen_broker_v2_specialized_apple_effect_execution_test.c"),
        str(NATIVE_TESTS / "plamen_broker_v2_specialized_request_integration_wrapper.c"),
        str(ROOT / "native/darwin/plamen_broker_v2_tool_custody.c"),
        str(ROOT / "native/darwin/plamen_broker_v2_specialized_apple_effect_execution.c"),
        str(ROOT / "native/darwin/plamen_broker_v2_specialized_effect_store.c"),
        str(ROOT / "native/darwin/plamen_broker_v2_specialized_output_census.c"),
        str(ROOT / "native/darwin/plamen_broker_v2_specialized_output_receipt.c"),
        str(ROOT / "native/posix/plamen_broker_v2_protocol.c"),
        "-framework", "Security", "-framework", "CoreFoundation",
        "-o", str(output),
    ], cwd=ROOT, check=False, stdin=subprocess.DEVNULL,
       stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
    assert completed.returncode == 0, completed.stderr.decode("utf-8", "replace")
    lib = ctypes.CDLL(str(output))
    lib.plamen_broker_v2_specialized_request_encode.argtypes = [
        ctypes.POINTER(base.SpecializedRequest), ctypes.c_void_p,
        ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t),
    ]
    lib.plamen_broker_v2_specialized_request_encode.restype = ctypes.c_int
    for name in base.PLAN_NAMES:
        fn = getattr(lib, f"plamen_broker_v2_tool_effect_plan_{name}")
        fn.argtypes = [ctypes.POINTER(base.PlanInput), ctypes.POINTER(ctypes.c_void_p)]
        fn.restype = ctypes.c_int
    lib.plamen_broker_v2_tool_effect_plan_issue_lease.argtypes = [
        ctypes.c_void_p, ctypes.POINTER(base.Evidence),
        ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_size_t),
        ctypes.POINTER(ctypes.c_uint8),
    ]
    lib.plamen_broker_v2_tool_effect_plan_issue_lease.restype = ctypes.c_int
    lib.plamen_broker_v2_tool_effect_plan_js_execute_from_lease.argtypes = [
        ctypes.c_void_p, ctypes.POINTER(base.PlanInput), ctypes.POINTER(ctypes.c_void_p),
    ]
    lib.plamen_broker_v2_tool_effect_plan_js_execute_from_lease.restype = ctypes.c_int
    lib.plamen_broker_v2_tool_effect_plan_execute_exact.argtypes = [
        ctypes.c_void_p, ctypes.POINTER(base.ExactExecutor),
        ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_size_t),
        ctypes.POINTER(ctypes.c_uint8),
    ]
    lib.plamen_broker_v2_tool_effect_plan_execute_exact.restype = ctypes.c_int
    lib.plamen_broker_v2_tool_effect_plan_destroy.argtypes = [ctypes.c_void_p]
    lib.plamen_broker_v2_tool_effect_plan_destroy.restype = None
    lib.plamen_broker_v2_tool_effect_plan_view.argtypes = [
        ctypes.c_void_p, ctypes.POINTER(base.PlanView)]
    lib.plamen_broker_v2_tool_effect_plan_view.restype = ctypes.c_int
    lib.plamen_broker_v2_specialized_js_replay_terminal_binding.argtypes = [
        ctypes.POINTER(base.PlanView), ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_size_t), ctypes.POINTER(ctypes.c_uint8)]
    lib.plamen_broker_v2_specialized_js_replay_terminal_binding.restype = ctypes.c_int
    lib.plamen_broker_v2_fd_identity.argtypes = [ctypes.c_int, ctypes.POINTER(ctypes.c_uint8)]
    lib.plamen_broker_v2_fd_identity.restype = ctypes.c_int
    lib.plamen_test_effect_adapter_open.argtypes = [
        ctypes.c_int, ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(ctypes.c_uint8),
        ctypes.POINTER(ctypes.c_void_p),
    ]
    lib.plamen_test_effect_adapter_open.restype = ctypes.c_int
    lib.plamen_test_effect_adapter_close.argtypes = [ctypes.c_void_p]
    lib.plamen_test_effect_adapter_execute_calls.argtypes = [ctypes.c_void_p]
    lib.plamen_test_effect_adapter_execute_calls.restype = ctypes.c_uint
    lib.plamen_test_effect_adapter_replay_calls.argtypes = [ctypes.c_void_p]
    lib.plamen_test_effect_adapter_replay_calls.restype = ctypes.c_uint
    lib.plamen_test_effect_adapter_worker_calls.restype = ctypes.c_int
    lib.plamen_test_effect_adapter_last_status.argtypes = [ctypes.c_void_p]
    lib.plamen_test_effect_adapter_last_status.restype = ctypes.c_int
    lib.plamen_test_effect_adapter_seed_projection.argtypes = [
        ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint8),
    ]
    lib.plamen_test_effect_adapter_seed_projection.restype = ctypes.c_int
    lib.plamen_test_effect_adapter_recover_projection.argtypes = [
        ctypes.c_void_p, ctypes.POINTER(base.PlanView), ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_size_t),
    ]
    lib.plamen_test_effect_adapter_recover_projection.restype = (
        ctypes.c_int
    )
    return lib


class _Completion(ctypes.Structure):
    _fields_ = [
        ("version", ctypes.c_uint32), ("lane", ctypes.c_uint16),
        ("method", ctypes.c_uint16), ("flags", ctypes.c_uint32),
        *[(name, ctypes.c_uint8 * 32) for name in (
            "operation_key", "request_sha256", "runtime_authority_sha256",
            "worker_request_sha256", "lifecycle_receipt_sha256",
            "terminal_sha256", "terminal_hmac_sha256",
            "network_policy_sha256", "observed_egress_sha256",
        )],
        ("provider_authenticated", ctypes.c_uint8),
        ("network_policy_enforced", ctypes.c_uint8),
        ("population_zero", ctypes.c_uint8),
        ("cleanup_complete", ctypes.c_uint8),
    ]


def _request(lib: ctypes.CDLL, method: int, payload: bytes, nonce: int, *,
             descriptors: list[tuple[int, int, int, bytes]] | None = None,
             fds: list[int] | None = None, flags: int = 0,
             capability: bool = True) -> tuple[base.PlanInput, object]:
    descriptors = descriptors or []
    fds = fds or []
    raw = (ctypes.c_uint8 * len(payload)).from_buffer_copy(payload)
    request = base.SpecializedRequest(
        lane=base.JS_LANE, method=method, flags=flags,
        fd_count=len(descriptors),
        payload_size=len(payload), payload=raw,
    )
    if capability:
        base._fill(request.capability_id, b"C" * 32)
    base._fill(request.operation_nonce, bytes([nonce]) * 32)
    base._fill(request.authority_binding_sha256, b"A" * 32)
    for index, (purpose, target, access, identity) in enumerate(descriptors):
        request.descriptors[index].purpose = purpose
        request.descriptors[index].target = target
        request.descriptors[index].access_mode = access
        base._fill(request.descriptors[index].identity, identity)
    wire = (ctypes.c_uint8 * (base.PAYLOAD_MAX + 1024))()
    size = ctypes.c_size_t()
    assert lib.plamen_broker_v2_specialized_request_encode(
        ctypes.byref(request), wire, len(wire), ctypes.byref(size)) == 0
    exact = (ctypes.c_uint8 * size.value).from_buffer_copy(bytes(wire[:size.value]))
    fd_array = (ctypes.c_int * len(fds))(*fds) if fds else None
    plan_input = base.PlanInput(
        version=1, request=ctypes.pointer(request), request_wire=exact,
        request_wire_size=size.value, fds=fd_array, fd_count=len(fds),
    )
    base._fill(plan_input.request_sha256, hashlib.sha256(bytes(exact)).digest())
    base._fill(plan_input.effects_context_sha256, b"E" * 32)
    return plan_input, (request, raw, exact, fd_array)


def _native_payload(archives: dict[str, object]) -> tuple[dict[str, object], bytes]:
    fixed = "11" * 32
    request: dict[str, object] = {
        "archives": archives,
        "argv": [],
        "bounds": {"modules": {"max_bytes": 4096, "max_entries": 32}},
        "contract_sha256": fixed,
        "cwd": ".",
        "dependency_expectation_sha256": fixed,
        "environment": [],
        "expected_inputs": {},
        "generation_id": "generation-1",
        "guest_argv": [],
        "guest_cwd": "/workspace/scratch",
        "guest_environment": [],
        "guest_execution_binding_sha256": fixed,
        "guest_expected_inputs": {},
        "guest_outputs": {"modules": "/workspace/scratch/offline-replay/modules"},
        "guest_platform": {"architecture": "arm64", "system": "Linux"},
        "launch_object_kind": "PRIVATE_IMMUTABLE_PROJECTED_CLOSURE",
        "mounts": {},
        "native_custody_receipt_sha256": fixed,
        "native_deployment_receipt_sha256": fixed,
        "native_module_sha256": fixed,
        "network_authority_sha256": fixed,
        "network_mode": "NO_NETWORK",
        "network_policy": {"allowed_origins": [], "policy_sha256": fixed},
        "operation": "OFFLINE_REPLAY",
        "outputs": {"modules": "/controller/modules"},
        "projected_closure_manifest_sha256": fixed,
        "request_sha256": fixed,
        "required_dynamic_identity_kind": "APPLE_CODEDIRECTORY_CDHASH",
        "schema": "plamen.js-dependency-native-request.v2",
        "session_admission_sha256": fixed,
        "source_access": "READ_ONLY",
        "source_guard_sha256": fixed,
        "source_snapshot_sha256": fixed,
        "timeout_seconds": 30,
        "toolchain_binding_sha256": fixed,
        "write_access": ["scratch", "state"],
    }
    return request, base._canonical(request) + b"\n"


def _open(lib: ctypes.CDLL, name: str, plan_input: base.PlanInput) -> ctypes.c_void_p:
    plan = ctypes.c_void_p()
    assert getattr(lib, f"plamen_broker_v2_tool_effect_plan_{name}")(
        ctypes.byref(plan_input), ctypes.byref(plan)) == 0
    return plan


def _run_exact(lib: ctypes.CDLL, plan: ctypes.c_void_p,
               executor: base.ExactExecutor) -> tuple[int, bytes, bytes]:
    terminal = ctypes.c_void_p()
    size = ctypes.c_size_t()
    digest = (ctypes.c_uint8 * 32)()
    status = lib.plamen_broker_v2_tool_effect_plan_execute_exact(
        plan, ctypes.byref(executor), ctypes.byref(terminal), ctypes.byref(size), digest)
    data = ctypes.string_at(terminal, size.value) if terminal.value else b""
    if terminal.value:
        ctypes.CDLL(None).free(terminal)
    return status, data, bytes(digest)


def test_projection_recovery_replays_only_authenticated_commit_terminal(
    tmp_path: Path,
) -> None:
    lib = _compile(tmp_path / "projection-recover.dylib")
    store = tmp_path / "projection-store"
    store.mkdir(mode=0o700)
    store_fd = os.open(store, os.O_RDONLY | os.O_CLOEXEC)
    adapter = ctypes.c_void_p()
    session = (ctypes.c_uint8 * 32).from_buffer_copy(b"K" * 32)
    runtime = (ctypes.c_uint8 * 32).from_buffer_copy(b"3" * 32)
    assert lib.plamen_test_effect_adapter_open(
        store_fd, session, runtime, ctypes.byref(adapter),
    ) == 0
    terminal_digest = (ctypes.c_uint8 * 32)()
    try:
        assert lib.plamen_test_effect_adapter_seed_projection(
            adapter, terminal_digest,
        ) == 0
        payload = (
            b'{"receipt_sha256":"' + bytes(terminal_digest).hex().encode("ascii")
            + b'"}'
        )
        raw = (ctypes.c_uint8 * len(payload)).from_buffer_copy(payload)
        view = base.PlanView(
            version=1, lane=3, method=0x2302, flags=1,
            payload=raw, payload_size=len(payload), fd_count=0,
        )
        completion = _Completion()
        terminal = ctypes.c_void_p()
        terminal_size = ctypes.c_size_t()
        assert lib.plamen_test_effect_adapter_recover_projection(
            adapter, ctypes.byref(view), ctypes.byref(completion),
            ctypes.byref(terminal), ctypes.byref(terminal_size),
        ) == 0
        recovered = ctypes.string_at(terminal, terminal_size.value)
        ctypes.CDLL(None).free(terminal)
        assert hashlib.sha256(recovered).digest() == bytes(terminal_digest)
        assert completion.lane == 3
        assert completion.method == 0x2301

        # A different, still-canonical lowercase digest must not recover the
        # neighboring authenticated record.  This is the resume mismatch
        # boundary consumed by evm_analysis_workspace_authority.
        raw[22] = ord("0") if raw[22] != ord("0") else ord("1")
        terminal = ctypes.c_void_p()
        terminal_size = ctypes.c_size_t()
        assert lib.plamen_test_effect_adapter_recover_projection(
            adapter, ctypes.byref(view), ctypes.byref(_Completion()),
            ctypes.byref(terminal), ctypes.byref(terminal_size),
        ) == -1
        assert not terminal.value

        raw[22] = ord("A")  # uppercase is not canonical lowercase hex
        terminal = ctypes.c_void_p()
        terminal_size = ctypes.c_size_t()
        assert lib.plamen_test_effect_adapter_recover_projection(
            adapter, ctypes.byref(view), ctypes.byref(_Completion()),
            ctypes.byref(terminal), ctypes.byref(terminal_size),
        ) == -1
        assert not terminal.value
    finally:
        lib.plamen_test_effect_adapter_close(adapter)
        os.close(store_fd)


def test_actual_execute_and_replay_cross_exact_custody(tmp_path: Path) -> None:
    lib = _compile(tmp_path / "plan-exact.dylib")
    roots = [tmp_path / name for name in ("source", "scratch", "state")]
    for root in roots:
        root.mkdir()
    binding, _, _ = base._archive_fixture(tmp_path / "archive-root")
    roots.append(tmp_path / "archive-root")
    output = roots[1] / "offline-replay" / "modules"
    output.mkdir(parents=True)
    (output / "module.js").write_bytes(b"module.exports=1;\n")
    fds = [os.open(root, os.O_RDONLY) for root in roots]
    store_root = tmp_path / "store"
    store_root.mkdir()
    store_root.chmod(0o700)
    store_fd = os.open(store_root, os.O_RDONLY | os.O_CLOEXEC)
    adapter = ctypes.c_void_p()
    session = (ctypes.c_uint8 * 32).from_buffer_copy(b"K" * 32)
    runtime = (ctypes.c_uint8 * 32).from_buffer_copy(b"3" * 32)
    assert lib.plamen_test_effect_adapter_open(
        store_fd, session, runtime, ctypes.byref(adapter)) == 0
    keepalive: list[object] = []
    try:
        request, payload = _native_payload(binding)
        descriptors = [
            (0x4001, 1, 1, base._fd_identity(lib, fds[0])),
            (0x4002, 2, 3, base._fd_identity(lib, fds[1])),
            (0x4003, 3, 3, base._fd_identity(lib, fds[2])),
            (0x4004, 4, 1, base._fd_identity(lib, fds[3])),
        ]
        prepare_input, held = _request(
            lib, base.JS_PREPARE, payload, 0x41, descriptors=descriptors, fds=fds)
        keepalive.append(held)
        lease = _open(lib, "js_prepare", prepare_input)
        prepare_terminal = b'{"schema":"plamen.js-materializer-prepare.v1"}'
        prepare_evidence, held_evidence = base._evidence(
            prepare_input, base.JS_PREPARE, prepare_terminal)
        keepalive.append(held_evidence)
        issued = ctypes.c_void_p(); issued_size = ctypes.c_size_t()
        issued_sha = (ctypes.c_uint8 * 32)()
        assert lib.plamen_broker_v2_tool_effect_plan_issue_lease(
            lease, ctypes.byref(prepare_evidence), ctypes.byref(issued),
            ctypes.byref(issued_size), issued_sha) == 0
        ctypes.CDLL(None).free(issued)
        execute_input, held = _request(lib, base.JS_EXECUTE, payload, 0x42)
        keepalive.append(held)
        execute_plan = ctypes.c_void_p()
        assert lib.plamen_broker_v2_tool_effect_plan_js_execute_from_lease(
            lease, ctypes.byref(execute_input), ctypes.byref(execute_plan)) == 0
        execute_fn = base.ExecuteCallback(("plamen_test_effect_adapter_execute", lib))
        replay_fn = base.ExecuteCallback(("plamen_test_effect_adapter_replay", lib))
        dispose_fn = base.DisposeCallback(("plamen_test_effect_adapter_dispose", lib))
        executor = base.ExactExecutor(version=1, context=adapter,
                                      js_execute=execute_fn, js_replay=replay_fn,
                                      dispose=dispose_fn)
        status, terminal, digest = _run_exact(lib, execute_plan, executor)
        assert status == 0, (
            lib.plamen_test_effect_adapter_execute_calls(adapter),
            lib.plamen_test_effect_adapter_worker_calls(),
            lib.plamen_test_effect_adapter_last_status(adapter),
        )
        assert terminal.endswith(b"\n") and not terminal.endswith(b"\n\n")
        assert hashlib.sha256(terminal).digest() == digest
        assert lib.plamen_test_effect_adapter_execute_calls(adapter) == 1

        replay_payload = base._canonical({
            "request": request,
            "terminal": json.loads(terminal),
        })
        replay_input, held = _request(
            lib, base.JS_REPLAY, replay_payload, 0x43,
            descriptors=descriptors, fds=fds, flags=1)
        keepalive.append(held)
        replay_plan = _open(lib, "js_replay", replay_input)
        replay_view = base.PlanView()
        assert lib.plamen_broker_v2_tool_effect_plan_view(
            replay_plan, ctypes.byref(replay_view)) == 0
        embedded = ctypes.c_void_p(); embedded_size = ctypes.c_size_t()
        embedded_sha = (ctypes.c_uint8 * 32)()
        assert lib.plamen_broker_v2_specialized_js_replay_terminal_binding(
            ctypes.byref(replay_view), ctypes.byref(embedded),
            ctypes.byref(embedded_size), embedded_sha) == 0
        assert ctypes.string_at(embedded, embedded_size.value) == terminal[:-1]
        assert bytes(embedded_sha) == digest
        status, replayed, replay_digest = _run_exact(lib, replay_plan, executor)
        assert status == 0 and replayed == terminal and replay_digest == digest, (
            status, lib.plamen_test_effect_adapter_replay_calls(adapter),
            lib.plamen_test_effect_adapter_last_status(adapter),
        )
        assert lib.plamen_test_effect_adapter_execute_calls(adapter) == 1
        assert lib.plamen_test_effect_adapter_replay_calls(adapter) == 1

        terminal_base = (
            b'{"network_policy_sha256":"' + (b"50" * 32)
            + b'","observed_egress_origins":[],"observed_egress_sha256":"'
            + (b"4f" * 32)
            + b'","schema":"plamen.js-dependency-native-terminal.v2"}'
        )

        def rejected(method: int, plan_name: str, body: bytes, nonce: int,
                     field: str, *, capability: bool = True) -> None:
            plan_input, held_local = _request(
                lib, method, payload if method != base.JS_REPLAY else replay_payload,
                nonce, descriptors=descriptors if method == base.JS_REPLAY else None,
                fds=fds if method == base.JS_REPLAY else None,
                flags=1 if method == base.JS_REPLAY else 0,
                capability=capability,
            )
            keepalive.append(held_local)
            plan = _open(lib, plan_name, plan_input)
            raw = (ctypes.c_uint8 * len(body)).from_buffer_copy(body)
            keepalive.append(raw)

            @base.ExecuteCallback
            def emit(_context: int, _view: ctypes.POINTER(base.PlanView),
                     evidence: ctypes.POINTER(base.Evidence)) -> int:
                item = evidence.contents
                base._fill(item.effect_receipt_sha256, b"R" * 32)
                item.effect_authenticated = 1
                item.effect_completed = 1
                item.terminal = raw
                item.terminal_size = len(body)
                if method != base.JS_RUNTIME_IDENTITY:
                    base._fill(item.durable_operation_sha256, b"D" * 32)
                    item.durable_operation = 1
                if method == base.JS_EXECUTE:
                    base._fill(item.lifecycle_receipt_sha256, b"L" * 32)
                    base._fill(item.network_policy_sha256, b"P" * 32)
                    base._fill(item.observed_egress_sha256, b"O" * 32)
                    item.provider_authenticated = 1
                    item.network_policy_enforced = 1
                    item.population_zero = 1
                    item.cleanup_complete = 1
                return 0

            @base.DisposeCallback
            def noop(_context: int, _evidence: ctypes.POINTER(base.Evidence)) -> None:
                return None

            bad = base.ExactExecutor(version=1, context=adapter, dispose=noop)
            setattr(bad, field, emit)
            assert _run_exact(lib, plan, bad)[0] != 0
            lib.plamen_broker_v2_tool_effect_plan_destroy(plan)
            keepalive.extend((emit, noop))

        rejected(base.JS_EXECUTE, "js_execute", terminal_base, 0x51,
                 "js_execute")
        rejected(base.JS_EXECUTE, "js_execute", terminal_base + b"\n\n", 0x52,
                 "js_execute")
        rejected(base.JS_REPLAY, "js_replay", b'{"schema":"wrong.v1"}\n', 0x53,
                 "js_replay")
        rejected(base.JS_RUNTIME_IDENTITY, "js_runtime_identity",
                 b'{"schema":"plamen.js-dependency-materializer-runtime-identity.v1"}\n',
                 0x54, "js_runtime_identity", capability=False)
        lib.plamen_broker_v2_tool_effect_plan_destroy(replay_plan)
        lib.plamen_broker_v2_tool_effect_plan_destroy(execute_plan)
        lib.plamen_broker_v2_tool_effect_plan_destroy(lease)
    finally:
        lib.plamen_test_effect_adapter_close(adapter)
        os.close(store_fd)
        for fd in fds:
            os.close(fd)
        assert keepalive
