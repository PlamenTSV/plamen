"""Bounded-allocation and pre-live durability regressions for Windows install."""

import ast
import ctypes
import hashlib
import hmac
import importlib.util
import json
from pathlib import Path
import sys
import threading
import tracemalloc

import pytest


ROOT = Path(__file__).resolve().parents[1]


def _load_front():
    spec = importlib.util.spec_from_file_location(
        "plamen_windows_install_performance_front", ROOT / "plamen.py"
    )
    module = importlib.util.module_from_spec(spec)
    saved = sys.argv
    sys.argv = ["plamen.py"]
    try:
        spec.loader.exec_module(module)
    finally:
        sys.argv = saved
    return module


class _StreamKernel32:
    def __init__(self, *, grow=False, malformed=False):
        self.grow = grow
        self.malformed = malformed
        self.sizes = []

    def GetFileInformationByHandleEx(self, _handle, info_class, buffer, size):
        assert info_class == 7
        self.sizes.append(size)
        if self.grow and size < 8192:
            ctypes.set_last_error(234)  # ERROR_MORE_DATA
            return False
        name = "::$DATA".encode("utf-16-le")
        next_offset = 1 if self.malformed else 0
        raw = b"".join((
            next_offset.to_bytes(4, "little"),
            len(name).to_bytes(4, "little"),
            (7).to_bytes(8, "little", signed=True),
            (4096).to_bytes(8, "little", signed=True),
            name,
        ))
        ctypes.memmove(ctypes.addressof(buffer), raw, len(raw))
        return True


class _DirectoryKernel32:
    def __init__(self, *, grow=False):
        self.grow = grow
        self.calls = []
        self.returned = False

    def GetFileInformationByHandleEx(self, _handle, info_class, buffer, size):
        self.calls.append((info_class, size))
        if self.grow and len(self.calls) == 1:
            ctypes.set_last_error(234)  # ERROR_MORE_DATA
            return False
        if self.returned:
            ctypes.set_last_error(18)  # ERROR_NO_MORE_FILES
            return False
        self.returned = True
        name = "entry.txt".encode("utf-16-le")
        raw = bytearray(104 + len(name))
        raw[60:64] = len(name).to_bytes(4, "little")
        raw[104:] = name
        ctypes.memmove(ctypes.addressof(buffer), bytes(raw), len(raw))
        return True


@pytest.mark.skipif(sys.platform != "win32", reason="Windows native installer")
@pytest.mark.parametrize("grow,expected_sizes", ((False, [4096]), (True, [4096, 8192])))
def test_stream_roster_starts_small_and_keeps_bounded_growth(monkeypatch, grow, expected_sizes):
    front = _load_front()
    kernel32 = _StreamKernel32(grow=grow)
    monkeypatch.setattr(
        front,
        "_codex_native_api",
        lambda: {"ctypes": ctypes, "kernel32": kernel32},
    )
    assert front._codex_native_stream_roster(123) == ({
        "name": "::$DATA", "size": 7, "allocation_size": 4096,
    },)
    assert kernel32.sizes == expected_sizes


@pytest.mark.skipif(sys.platform != "win32", reason="Windows native installer")
def test_stream_roster_still_rejects_malformed_offsets(monkeypatch):
    front = _load_front()
    kernel32 = _StreamKernel32(malformed=True)
    monkeypatch.setattr(
        front,
        "_codex_native_api",
        lambda: {"ctypes": ctypes, "kernel32": kernel32},
    )
    with pytest.raises(RuntimeError, match="stream offset is malformed"):
        front._codex_native_stream_roster(123)


@pytest.mark.skipif(sys.platform != "win32", reason="Windows native installer")
@pytest.mark.parametrize(
    "grow,expected_calls",
    (
        (False, [(11, 4096), (10, 4096)]),
        (True, [(11, 4096), (11, 8192), (10, 4096)]),
    ),
)
def test_directory_roster_uses_continuation_and_bounded_growth(
    monkeypatch, grow, expected_calls,
):
    front = _load_front()
    kernel32 = _DirectoryKernel32(grow=grow)
    monkeypatch.setattr(
        front,
        "_codex_native_api",
        lambda: {"ctypes": ctypes, "kernel32": kernel32},
    )
    assert front._codex_native_directory_names(123) == ("entry.txt",)
    assert kernel32.calls == expected_calls


@pytest.mark.skipif(sys.platform != "win32", reason="Windows native installer")
def test_crt_heap_trim_has_strict_success_and_fail_open_reports(monkeypatch):
    front = _load_front()
    succeeded = front._codex_install_trim_crt_heap()
    assert succeeded == {
        "attempted": True,
        "succeeded": True,
        "return_code": 0,
        "errno": 0,
        "error": None,
    }

    def denied(*_args, **_kwargs):
        raise OSError("unavailable")

    monkeypatch.setattr(ctypes, "CDLL", denied)
    declined = front._codex_install_trim_crt_heap()
    assert declined == {
        "attempted": False,
        "succeeded": False,
        "return_code": None,
        "errno": None,
        "error": "OSError",
    }


@pytest.mark.skipif(sys.platform != "win32", reason="Windows native installer")
def test_full_trim_reports_gc_then_crt_then_working_set(monkeypatch):
    front = _load_front()
    events = []
    monkeypatch.setattr(front.gc, "collect", lambda: events.append("gc") or 7)
    monkeypatch.setattr(
        front,
        "_codex_install_trim_crt_heap",
        lambda: events.append("crt") or {
            "attempted": True, "succeeded": True, "return_code": 0,
            "errno": 0, "error": None,
        },
    )
    result = front._codex_install_trim_working_set(collect=True, report=True)
    assert events == ["gc", "crt"]
    assert result["gc_collected"] == 7
    assert result["crt_heap"]["succeeded"] is True
    assert result["working_set_attempted"] is True
    assert isinstance(result["working_set_released"], bool)


def test_census_result_rejects_exit_truncation_malformed_and_oversize(monkeypatch):
    front = _load_front()
    secret = b"s" * 32
    kwargs = {
        "secret": secret, "nonce": "a" * 32, "state_sha256": "b" * 64,
    }
    with pytest.raises(RuntimeError, match="exited unsuccessfully"):
        front._codex_install_validate_census_result(
            b"", returncode=9, stderr=b"child failed", **kwargs,
        )
    with pytest.raises(RuntimeError, match="output is truncated"):
        front._codex_install_validate_census_result(
            b"", returncode=0, stderr=b"", **kwargs,
        )
    with pytest.raises(RuntimeError):
        front._codex_install_validate_census_result(
            b"{", returncode=0, stderr=b"", **kwargs,
        )
    monkeypatch.setattr(front, "_CODEX_INSTALL_CENSUS_MAX_OUTPUT", 16)
    with pytest.raises(RuntimeError, match="output exceeds bound"):
        front._codex_install_validate_census_result(
            b"x" * 17, returncode=0, stderr=b"", **kwargs,
        )


def test_census_ready_accepts_only_exact_launcher_actual_topology(monkeypatch):
    front = _load_front()
    launcher_pid = 22001
    launcher_started = 134000000000000001
    actual_pid = 22002
    actual_started = 134000000000000002
    ready = {
        "schema": front._CODEX_INSTALL_CENSUS_READY_SCHEMA,
        "pid": actual_pid, "started_100ns": actual_started,
        "parent_pid": launcher_pid,
        "parent_started_100ns": launcher_started,
    }
    monkeypatch.setattr(
        front, "_borrowed_reader_parent_started_100ns",
        lambda pid: actual_started if pid == actual_pid else 0,
    )
    observed = front._codex_install_validate_census_ready(
        front._borrowed_reader_canonical_bytes(ready),
        launcher_pid=launcher_pid,
        launcher_started_100ns=launcher_started,
    )
    assert observed["topology"] == "LAUNCHER_ACTUAL"

    grandchild = dict(ready); grandchild["parent_pid"] = 22003
    with pytest.raises(RuntimeError, match="topology differs"):
        front._codex_install_validate_census_ready(
            front._borrowed_reader_canonical_bytes(grandchild),
            launcher_pid=launcher_pid,
            launcher_started_100ns=launcher_started,
        )

    monkeypatch.setattr(
        front, "_borrowed_reader_parent_started_100ns", lambda _pid: actual_started + 1,
    )
    with pytest.raises(RuntimeError, match="readiness authority differs"):
        front._codex_install_validate_census_ready(
            front._borrowed_reader_canonical_bytes(ready),
            launcher_pid=launcher_pid,
            launcher_started_100ns=launcher_started,
        )


def test_streamed_census_wire_matches_canonical_protocol_exactly():
    front = _load_front()

    class Dispatcher:
        _operation_policy = {("codex", ("skills",)): {"MKDIR", "UNLINK"}}
        _stable_b_keys = {("source", ("VERSION",))}
        _foreign_b_baseline = {
            ("codex", ("foreign.txt",)): {"kind": "file", "inode": 7},
        }
        events = [{
            "ordinal": 0, "root": "codex", "components": ["skills"],
            "operation": "MKDIR", "state": "COMPLETED",
            "old": None, "new": {"kind": "directory", "inode": 8},
        }]

    dispatcher = Dispatcher()
    marker = front._CODEX_INSTALL_CENSUS_STREAMED
    state = {
        "schema": front._CODEX_INSTALL_CENSUS_SCHEMA,
        "events": marker, "operation_policy": marker,
        "stable_b_keys": marker, "foreign_b_baseline": marker,
        "label": "PRE_SOURCE_CAPTURE",
    }
    expected_state = {
        "schema": front._CODEX_INSTALL_CENSUS_SCHEMA,
        "events": dispatcher.events,
        "operation_policy": [{
            "root": "codex", "components": ["skills"],
            "value": ["MKDIR", "UNLINK"],
        }],
        "stable_b_keys": [{
            "root": "source", "components": ["VERSION"],
        }],
        "foreign_b_baseline": [{
            "root": "codex", "components": ["foreign.txt"],
            "value": {"kind": "file", "inode": 7},
        }],
        "label": "PRE_SOURCE_CAPTURE",
    }
    state_raw = b"".join(
        front._codex_install_census_state_document_chunks(state, dispatcher)
    )
    assert state_raw == front._borrowed_reader_canonical_bytes(expected_state)
    secret = b"w" * 32
    state_sha256, signature, _size = front._codex_install_census_wire_authority(
        state, dispatcher, secret,
    )
    unsigned = {
        "schema": front._CODEX_INSTALL_CENSUS_SCHEMA,
        "state": expected_state, "state_sha256": state_sha256,
    }
    assert signature == hmac.new(
        secret, front._borrowed_reader_canonical_bytes(unsigned), hashlib.sha256,
    ).hexdigest()
    envelope = dict(unsigned); envelope["signature"] = signature
    assert b"".join(front._codex_install_census_envelope_chunks(
        state, dispatcher, state_sha256=state_sha256, signature=signature,
    )) == front._borrowed_reader_canonical_bytes(envelope)
    dispatcher.events[0]["_native"] = {"handle": 123}
    with pytest.raises(RuntimeError, match="live native authority"):
        front._codex_install_census_wire_authority(state, dispatcher, secret)


def test_high_volume_census_streaming_keeps_parent_allocation_bounded(monkeypatch):
    front = _load_front()

    class Events:
        def __iter__(self):
            for ordinal in range(30000):
                yield {
                    "ordinal": ordinal, "root": "codex",
                    "components": ["events", f"row-{ordinal:08d}"],
                    "operation": "ATOMIC_BYTES", "state": "COMPLETED",
                    "old": None,
                    "new": {"kind": "file", "inode": ordinal + 1},
                }

    class Dispatcher:
        _operation_policy = {}
        _stable_b_keys = set()
        _foreign_b_baseline = {}
        events = Events()

    marker = front._CODEX_INSTALL_CENSUS_STREAMED
    state = {
        "schema": front._CODEX_INSTALL_CENSUS_SCHEMA,
        "events": marker, "operation_policy": marker,
        "stable_b_keys": marker, "foreign_b_baseline": marker,
    }
    monkeypatch.setattr(
        front, "_borrowed_reader_canonical_bytes",
        lambda _value: (_ for _ in ()).throw(
            AssertionError("full canonical materialization is forbidden")
        ),
    )
    tracemalloc.start()
    try:
        state_sha256, signature, state_size = (
            front._codex_install_census_wire_authority(
                state, Dispatcher(), b"z" * 32,
            )
        )
        maximum_chunk = 0; wire_size = 0
        for chunk in front._codex_install_census_envelope_chunks(
            state, Dispatcher(), state_sha256=state_sha256,
            signature=signature,
        ):
            maximum_chunk = max(maximum_chunk, len(chunk)); wire_size += len(chunk)
        _current, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert state_size > 4 * 1024 * 1024
    assert wire_size > state_size
    assert maximum_chunk < 4096
    assert peak < 8 * 1024 * 1024


def test_doctor_checks_heavy_rag_packages_without_importing_them():
    tree = ast.parse((ROOT / "plamen.py").read_text(encoding="utf-8"))
    doctor = next(
        node for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "run_doctor"
    )
    rag_loop = next(
        node for node in ast.walk(doctor)
        if isinstance(node, ast.For)
        and any(
            isinstance(item, ast.Constant)
            and item.value == "sentence_transformers"
            for item in ast.walk(node.iter)
        )
    )
    assert not any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "__import__"
        for node in ast.walk(rag_loop)
    )
    assert any(
        isinstance(node, ast.Name) and node.id == "find_spec"
        for node in ast.walk(rag_loop)
    )


@pytest.mark.skipif(sys.platform != "win32", reason="Windows native installer")
def test_isolated_census_matches_in_process_capture(tmp_path, monkeypatch):
    front = _load_front()
    monkeypatch.setattr(front, "_CODEX_INSTALL_SOURCE_COUNT", 3)
    monkeypatch.setattr(front, "_CODEX_INSTALL_RUNTIME_COUNT", 2)
    monkeypatch.setattr(front, "_CODEX_INSTALL_ADAPTER_COUNT", 1)
    source = tmp_path / "source"; plamen_root = tmp_path / "plamen"
    codex_home = tmp_path / "codex"
    source.mkdir(); plamen_root.mkdir(); codex_home.mkdir()
    poison = tmp_path / "poison"; poison.mkdir()
    poison_marker = tmp_path / "sitecustomize-ran"
    (poison / "sitecustomize.py").write_text(
        f"from pathlib import Path\nPath({str(poison_marker)!r}).write_text('ran')\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("PYTHONPATH", str(poison))
    monkeypatch.setenv("PYTHONSTARTUP", str(poison / "sitecustomize.py"))
    specs = (
        ("a.txt", "plamen", "a.txt"),
        ("b.txt", "plamen", "sub/b.txt"),
        ("c.txt", "codex", "skills/plamen/c.txt"),
    )
    rows = []
    for name in ("VERSION", "plamen.py"):
        (source / name).write_bytes((name + "-payload").encode())
    for source_path, destination_root, destination_path in specs:
        raw = (source_path + "-payload").encode()
        (source / source_path).write_bytes(raw)
        rows.append({
            "source_path": source_path,
            "install_kind": (
                "runtime" if destination_root == "plamen" else "codex-adapter"
            ),
            "destination_root": destination_root,
            "destination_path": destination_path,
            "destination_key": f"{destination_root}/{destination_path}".casefold(),
            "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
        })
    _anchor, writer, writer_close = front._open_install_admission_anchor(
        codex_home, writer=True, create=True,
    )
    dispatcher = None
    try:
        dispatcher = front._CodexInstallMutationDispatcher(
            front._CODEX_INSTALL_CONTEXT_AUTHORITY,
            transaction_id="d" * 32, writer_generation="parity-generation",
            writer_handle=writer, source_root=source,
            plamen_root=plamen_root, codex_home=codex_home,
            source_rows=rows,
        )
        dispatcher._contract_failpoint = None
        topologies = []
        validate_ready = front._codex_install_validate_census_ready

        def recording_validate_ready(*args, **kwargs):
            value = validate_ready(*args, **kwargs)
            topologies.append(value["topology"])
            return value

        monkeypatch.setattr(
            front, "_codex_install_validate_census_ready",
            recording_validate_ready,
        )
        inline = front._capture_codex_install_sentinel_in_process(
            dispatcher=dispatcher, source_rows=rows,
            transaction_components=(".plamen-install-transactions", "d" * 32),
            label="PRE_SOURCE_CAPTURE", include_rows=True,
        )
        isolated = front._capture_codex_install_sentinel_isolated(
            dispatcher=dispatcher, source_rows=rows,
            transaction_components=(".plamen-install-transactions", "d" * 32),
            label="PRE_SOURCE_CAPTURE", include_rows=True,
        )
        assert isolated == inline
        assert topologies == ["DIRECT"]
        assert not poison_marker.exists()

        managed_launcher = (
            Path.home() / ".local" / "share" / "plamen" / "runtime"
            / "py312" / "Scripts" / "python.exe"
        )
        if managed_launcher.is_file():
            monkeypatch.setattr(front.sys, "executable", str(managed_launcher))
            redirected_inline = front._capture_codex_install_sentinel_in_process(
                dispatcher=dispatcher, source_rows=rows,
                transaction_components=(
                    ".plamen-install-transactions", "d" * 32,
                ),
                label="PRE_SOURCE_CAPTURE", include_rows=True,
            )
            redirected_isolated = front._capture_codex_install_sentinel_isolated(
                dispatcher=dispatcher, source_rows=rows,
                transaction_components=(
                    ".plamen-install-transactions", "d" * 32,
                ),
                label="PRE_SOURCE_CAPTURE", include_rows=True,
            )
            assert redirected_isolated == redirected_inline
            assert topologies == ["DIRECT", "LAUNCHER_ACTUAL"]
    finally:
        if dispatcher is not None and not dispatcher.closed:
            dispatcher.close()
        writer_close()


def test_native_roster_parsers_do_not_materialize_full_buffer_raw():
    tree = ast.parse((ROOT / "plamen.py").read_text(encoding="utf-8"))
    selected = {
        node.name: node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name in {
            "_codex_native_streams",
            "_codex_native_stream_roster",
            "_codex_native_directory_names",
        }
    }
    assert set(selected) == {
        "_codex_native_streams",
        "_codex_native_stream_roster",
        "_codex_native_directory_names",
    }
    for name, function in selected.items():
        assert not any(
            isinstance(node, ast.Attribute) and node.attr == "raw"
            for node in ast.walk(function)
        ), name


@pytest.mark.skipif(sys.platform != "win32", reason="Windows native installer")
def test_hot_native_metadata_types_and_buffers_are_reused():
    front = _load_front()
    first = front._borrowed_reader_identity_api()
    second = front._borrowed_reader_identity_api()
    assert first is second
    assert first[2] is second[2]
    assert first[3] is second[3]

    byte_one, byte_capacity = front._codex_native_reusable_byte_buffer(
        ctypes, "performance-test-byte", 4096,
    )
    byte_two, byte_capacity_two = front._codex_native_reusable_byte_buffer(
        ctypes, "performance-test-byte", 1024,
    )
    assert byte_two is byte_one
    assert byte_capacity_two == byte_capacity == 4096
    unicode_one, unicode_capacity = front._codex_native_reusable_unicode_buffer(
        ctypes, "performance-test-unicode", 64,
    )
    unicode_two, unicode_capacity_two = front._codex_native_reusable_unicode_buffer(
        ctypes, "performance-test-unicode", 32,
    )
    assert unicode_two is unicode_one
    assert unicode_capacity_two == unicode_capacity

    tree = ast.parse((ROOT / "plamen.py").read_text(encoding="utf-8"))
    hot = {
        node.name: node for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name in {
            "_borrowed_reader_handle_identity",
            "_codex_native_content_cache_authority",
            "_codex_native_set_readonly",
            "_codex_native_rename",
        }
    }
    assert len(hot) == 4
    for name, function in hot.items():
        assert not any(isinstance(node, ast.ClassDef) for node in ast.walk(function)), name


@pytest.mark.skipif(sys.platform != "win32", reason="Windows native installer")
def test_native_api_cold_start_publishes_one_cache_to_all_threads():
    front = _load_front()
    for api in (
        front._borrowed_reader_identity_api,
        front._codex_native_api,
        front._codex_install_process_memory_api,
    ):
        if hasattr(api, "_cached"):
            delattr(api, "_cached")
        barrier = threading.Barrier(24)
        results = [None] * 24
        failures = []

        def cold_start(index):
            try:
                barrier.wait(timeout=10)
                results[index] = api()
            except BaseException as exc:
                failures.append(exc)

        threads = [
            threading.Thread(target=cold_start, args=(index,))
            for index in range(len(results))
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=20)
        assert not any(thread.is_alive() for thread in threads)
        assert failures == []
        assert all(value is results[0] for value in results)
        assert getattr(api, "_cached") is results[0]


def test_write_and_rename_verify_by_bounded_streaming_digest():
    tree = ast.parse((ROOT / "plamen.py").read_text(encoding="utf-8"))
    functions = {
        node.name: node for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name in {
            "_codex_native_write", "_codex_native_sha256",
        }
    }
    methods = {
        node.name: node for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == "_native_rename_path"
    }
    assert set(functions) == {"_codex_native_write", "_codex_native_sha256"}
    assert set(methods) == {"_native_rename_path"}
    for function in (functions["_codex_native_write"], methods["_native_rename_path"]):
        calls = {
            node.func.id for node in ast.walk(function)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        }
        assert "_codex_native_read" not in calls
        assert "_codex_native_sha256" in calls


def test_opt_in_parent_memory_trace_is_bounded_and_non_authoritative(monkeypatch):
    front = _load_front()
    reports = []

    class _Dispatcher:
        events = [{"state": "COMPLETED", "new": {"sha256": "a" * 64}}]
        _native_descriptor_cache = {("file", 1): "b" * 64}
        _memory_trace_callback = reports.append

    monkeypatch.setattr(
        front, "_codex_install_process_memory",
        lambda: {"private_bytes": 1234, "working_set_bytes": 5678},
    )
    front._CODEX_INSTALL_MEMORY_COUNTERS["native_hash_calls"] = 9
    observed = front._codex_install_memory_trace(
        _Dispatcher(), label="PRE_STAGE", point="BEFORE_CAPTURE",
    )
    assert observed == reports[0]
    assert observed["private_bytes"] == 1234
    assert observed["working_set_bytes"] == 5678
    assert observed["event_count"] == 1
    assert observed["native_event_count"] == 0
    assert observed["descriptor_cache_count"] == 1
    assert observed["event_deep_bytes"] > 0
    assert observed["native_counters"]["native_hash_calls"] == 9

    _Dispatcher._memory_trace_callback = lambda _report: (_ for _ in ()).throw(
        RuntimeError("diagnostic failure")
    )
    assert front._codex_install_memory_trace(
        _Dispatcher(), label="PRE_STAGE", point="AFTER_CAPTURE",
    ) is None


def test_install_row_loops_do_not_rewrite_growing_json_documents():
    tree = ast.parse((ROOT / "plamen.py").read_text(encoding="utf-8"))
    install = next(
        node for node in tree.body
        if isinstance(node, ast.FunctionDef)
        and node.name == "_install_codex_package_transaction"
    )
    found = set()
    for loop in (node for node in ast.walk(install) if isinstance(node, ast.For)):
        seams = {
            arg.value
            for call in (node for node in ast.walk(loop) if isinstance(node, ast.Call))
            for arg in call.args
            if isinstance(arg, ast.Constant)
            and arg.value in {
                "after_staged_row", "after_backup_row", "after_live_row",
            }
        }
        if not seams:
            continue
        found.update(seams)
        assert not any(
            isinstance(call, ast.Call)
            and isinstance(call.func, ast.Attribute)
            and call.func.attr == "atomic_json"
            for call in ast.walk(loop)
        ), seams
    assert found == {
        "after_staged_row", "after_backup_row", "after_live_row",
    }


def test_bounded_publication_model_removes_quadratic_live_churn():
    count = 759
    rows = [{"index": index, "authority": "a" * 768} for index in range(count)]
    old_live_bytes = sum(
        len(json.dumps({"rows": rows[:end]}, sort_keys=True).encode()) * 2
        for end in range(1, count + 1)
    )
    bounded_bytes = (
        len(json.dumps({"rows": rows}, sort_keys=True).encode()) * 2
    )
    assert old_live_bytes > bounded_bytes * 300


def test_live_state_classifier_rejects_every_unsigned_authority():
    front = _load_front()
    prior_identity = {"inode": 1, "sha256": "1" * 64}
    successor = {"inode": 2, "sha256": "2" * 64}
    restored = {"inode": 3, "sha256": "1" * 64}
    prior = {"state": "PRESENT", "identity": prior_identity}
    assert front._codex_install_live_state(
        prior_identity, prior, successor, restored,
    ) == "PREIMAGE"
    assert front._codex_install_live_state(
        successor, prior, successor, restored,
    ) == "SUCCESSOR"
    assert front._codex_install_live_state(
        restored, prior, successor, restored,
    ) == "RESTORED"
    with pytest.raises(RuntimeError, match="foreign destination authority"):
        front._codex_install_live_state(
            {"inode": 4, "sha256": "2" * 64}, prior, successor, restored,
        )


class _RecoveryDispatcher:
    def __init__(self, values):
        self.values = dict(values)

    def _current(self, address):
        value = self.values.get(address)
        return None if value is None else dict(value)

    def replace(self, source, destination):
        value = self.values.pop(source)
        value = dict(value)
        value["name"] = destination[1][-1]
        self.values[destination] = value

    def unlink(self, address):
        self.values.pop(address)


def _authority(name, inode, digest):
    return {
        "kind": "file", "device": 7, "inode": inode, "mode": 0,
        "links": 1, "size": 7, "attributes": 0, "reparse_tag": 0,
        "name": name, "sha256": digest,
        "streams": [{"name": "::$DATA", "size": 7, "allocation_size": 4096}],
    }


def test_restart_equivalent_recovery_covers_every_atomic_rename_seam(tmp_path):
    front = _load_front()
    transaction_id = "a" * 32
    transaction_components = (".plamen-install-transactions", transaction_id)
    destination = tmp_path / "file.txt"
    row = {
        "destination": str(destination), "destination_root": "plamen",
        "destination_path": "file.txt", "size": 7, "sha256": "2" * 64,
    }
    preimage = _authority("file.txt", 1, "1" * 64)
    successor = _authority("file.txt", 2, "2" * 64)
    restored = _authority("file.txt", 3, "1" * 64)
    prior_absent = {
        "destination": str(destination), "state": "ABSENT",
        "successor": {
            "schema": front._CODEX_INSTALL_SUCCESSOR_AUTHORITY_V1,
            "authority": successor,
        },
    }
    prior_present = {
        "destination": str(destination), "state": "PRESENT", "size": 7,
        "sha256": "1" * 64, "identity": preimage,
        "backup": str(tmp_path / "backup" / "file.txt"),
        "restored_identity": restored,
        "successor": {
            "schema": front._CODEX_INSTALL_SUCCESSOR_AUTHORITY_V1,
            "authority": successor,
        },
    }
    evidence_path = tmp_path / "persisted-prepared-evidence.json"
    evidence_path.write_text(json.dumps({
        "state": "COMMITTING", "journal": [], "row": row,
        "absent": prior_absent, "present": prior_present,
    }), encoding="utf-8")
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))

    def address(root, components):
        return root, tuple(components)

    destination_address = address("plamen", ("file.txt",))
    new_name = f"file.txt.{transaction_id}.new"
    new_address = address("plamen", (new_name,))
    rollback_name = f"file.txt.{transaction_id}.rollback"
    rollback_address = address("plamen", (rollback_name,))

    # Crash after stage -> .new: destination is still the exact preimage and
    # disk journal is empty. Recovery removes only the signed successor temp.
    staged_temp = dict(successor); staged_temp["name"] = new_name
    dispatcher = _RecoveryDispatcher({new_address: staged_temp})
    result = front._codex_install_compensate_signed_row(
        dispatcher=dispatcher, address=address, row=evidence["row"],
        prior=evidence["absent"], transaction_id=transaction_id,
        transaction_components=transaction_components,
    )
    assert result == {"initial_state": "PREIMAGE", "changed": False}
    assert dispatcher.values == {}

    # Crash after .new -> destination but before any journal publication.
    dispatcher = _RecoveryDispatcher({destination_address: successor})
    result = front._codex_install_compensate_signed_row(
        dispatcher=dispatcher, address=address, row=evidence["row"],
        prior=evidence["absent"], transaction_id=transaction_id,
        transaction_components=transaction_components,
    )
    assert result == {"initial_state": "SUCCESSOR", "changed": True}
    assert dispatcher.values == {}

    # A recovery crash after signed backup -> rollback temp is resumed, and a
    # second recovery accepts the exact restored identity idempotently.
    rollback_temp = dict(restored); rollback_temp["name"] = rollback_name
    dispatcher = _RecoveryDispatcher({
        destination_address: successor, rollback_address: rollback_temp,
    })
    first = front._codex_install_compensate_signed_row(
        dispatcher=dispatcher, address=address, row=evidence["row"],
        prior=evidence["present"], transaction_id=transaction_id,
        transaction_components=transaction_components,
    )
    second = front._codex_install_compensate_signed_row(
        dispatcher=dispatcher, address=address, row=evidence["row"],
        prior=evidence["present"], transaction_id=transaction_id,
        transaction_components=transaction_components,
    )
    assert first == {"initial_state": "SUCCESSOR", "changed": True}
    assert second == {"initial_state": "RESTORED", "changed": False}
    assert dispatcher.values[destination_address] == restored

    # Same digest is insufficient: a third inode/authority is foreign.
    foreign = dict(successor); foreign["inode"] = 999
    dispatcher = _RecoveryDispatcher({destination_address: foreign})
    with pytest.raises(RuntimeError, match="foreign destination authority"):
        front._codex_install_compensate_signed_row(
            dispatcher=dispatcher, address=address, row=evidence["row"],
            prior=evidence["absent"], transaction_id=transaction_id,
            transaction_components=transaction_components,
        )


@pytest.mark.skipif(sys.platform != "win32", reason="Windows native installer")
def test_pre_live_failpoints_restore_absent_prestate(tmp_path, monkeypatch):
    front = _load_front()
    specs = (
        ("a.txt", "plamen", "a.txt"),
        ("b.txt", "plamen", "sub/b.txt"),
        ("c.txt", "codex", "skills/plamen/c.txt"),
    )
    monkeypatch.setattr(front, "_CODEX_INSTALL_SOURCE_COUNT", 3)
    monkeypatch.setattr(front, "_CODEX_INSTALL_RUNTIME_COUNT", 2)
    monkeypatch.setattr(front, "_CODEX_INSTALL_ADAPTER_COUNT", 1)
    monkeypatch.setattr(
        front, "_toolchain_runtime_required_integrity_issues",
        lambda *_a, **_k: {"missing": [], "mismatched": []},
    )

    for seam in ("after_staged_row", "after_backup_row", "after_live_row"):
        for wanted_index in (0, 1, 2):
            case = tmp_path / f"{seam}-{wanted_index}"
            source = case / "source"
            plamen_root = case / "plamen"
            codex_home = case / "codex"
            source.mkdir(parents=True)
            plamen_root.mkdir()
            codex_home.mkdir()
            (source / "VERSION").write_text("probe", encoding="utf-8")
            (source / "plamen.py").write_text("probe", encoding="utf-8")
            rows = []
            for source_path, destination_root, destination_path in specs:
                raw = (source_path + "-payload").encode()
                (source / source_path).write_bytes(raw)
                rows.append({
                    "source_path": source_path,
                    "install_kind": (
                        "runtime" if destination_root == "plamen" else "codex-adapter"
                    ),
                    "destination_root": destination_root,
                    "destination_path": destination_path,
                    "destination_key": (
                        f"{destination_root}/{destination_path}".casefold()
                    ),
                    "size": len(raw),
                    "sha256": hashlib.sha256(raw).hexdigest(),
                })
            monkeypatch.setattr(
                front,
                "_codex_install_source_rows",
                lambda *_args, _rows=rows, **_kwargs: [dict(row) for row in _rows],
            )
            fired = False

            def failpoint(name, row):
                nonlocal fired
                if not fired and name == seam and row == wanted_index:
                    fired = True
                    raise RuntimeError("PERFORMANCE_FAILPOINT")

            with pytest.raises(RuntimeError, match="PERFORMANCE_FAILPOINT"):
                    front._install_codex_package_transaction(
                        source_root=source,
                        plamen_root=plamen_root,
                        codex_home=codex_home,
                        failpoint=failpoint,
                        enable_claude_projection=False,
                    )
            assert fired
            assert not (codex_home / front._CODEX_INSTALL_RECEIPT).exists()
            assert not (plamen_root / "a.txt").exists()
            assert not (plamen_root / "sub" / "b.txt").exists()
            assert not (codex_home / "skills" / "plamen" / "c.txt").exists()
            transactions = list(
                (codex_home / ".plamen-install-transactions").iterdir()
            )
            assert len(transactions) == 1
            inverse = json.loads((transactions[0] / "inverse.json").read_text())
            rollback = json.loads(
                (transactions[0] / "rollback-result.json").read_text()
            )
            if seam == "after_live_row":
                assert len(inverse["rows"]) == 3
                assert rollback["restored_rows"] == wanted_index + 1
            else:
                assert inverse["rows"] == []
                assert rollback["restored_rows"] == 0
