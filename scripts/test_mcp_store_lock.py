"""Cross-platform concurrency regressions for the immutable MCP store lock."""

from __future__ import annotations

import importlib.util
import ctypes
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import uuid

import pytest


RUNTIME_PATH = Path(__file__).with_name("plamen_mcp_runtime.py")


def _load_runtime():
    name = "plamen_mcp_store_lock_test_" + uuid.uuid4().hex
    spec = importlib.util.spec_from_file_location(name, RUNTIME_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def runtime():
    return _load_runtime()


def _initialize_store(runtime, root: Path) -> None:
    with runtime._store_lock(
        root, mode=runtime._STORE_LOCK_EXCLUSIVE, create=True,
        timeout_seconds=1.0,
    ):
        pass


def _holder_process(root: Path, mode: str, *, spawn_child: bool = False):
    code = r"""
import importlib.util, pathlib, subprocess, sys, time
runtime_path, root, mode, spawn_child = sys.argv[1:]
spec = importlib.util.spec_from_file_location("plamen_mcp_store_lock_child", runtime_path)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
with module._store_lock(
    pathlib.Path(root), mode=mode, create=False, timeout_seconds=2.0,
):
    if spawn_child == "1":
        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(20)"])
        print("READY", child.pid, flush=True)
    else:
        print("READY", flush=True)
    time.sleep(20)
"""
    process = subprocess.Popen(
        [sys.executable, "-c", code, str(RUNTIME_PATH), str(root), mode,
         "1" if spawn_child else "0"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    assert process.stdout is not None
    ready = process.stdout.readline().strip()
    if not ready.startswith("READY"):
        stderr = process.stderr.read() if process.stderr is not None else ""
        process.kill()
        process.wait(timeout=5)
        pytest.fail(f"lock holder failed before readiness: {ready!r} {stderr!r}")
    child_pid = int(ready.split()[1]) if spawn_child else None
    return process, child_pid


def _stop_process(process: subprocess.Popen[str]) -> None:
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def _windows_process_is_active(process_id: int) -> bool:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    open_process = kernel32.OpenProcess
    open_process.argtypes = [ctypes.c_ulong, ctypes.c_int, ctypes.c_ulong]
    open_process.restype = ctypes.c_void_p
    get_exit_code = kernel32.GetExitCodeProcess
    get_exit_code.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong)]
    get_exit_code.restype = ctypes.c_int
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = [ctypes.c_void_p]
    close_handle.restype = ctypes.c_int
    handle = open_process(0x1000, False, process_id)
    if not handle:
        return False
    try:
        exit_code = ctypes.c_ulong()
        if not get_exit_code(handle, ctypes.byref(exit_code)):
            return False
        return exit_code.value == 259  # STILL_ACTIVE
    finally:
        close_handle(handle)


def test_read_only_lock_does_not_create_missing_store_or_lock(
    runtime, tmp_path: Path,
) -> None:
    root = tmp_path / "absent-store"
    with pytest.raises(runtime.MCPRuntimeSecurityError, match="store root is missing"):
        with runtime._store_lock(
            root, mode=runtime._STORE_LOCK_SHARED, create=False,
            timeout_seconds=0.0,
        ):
            pass
    assert not root.exists()

    existing = tmp_path / "existing-store"
    runtime._ensure_store(existing)
    assert not (existing / ".lock").exists()
    with pytest.raises(runtime.MCPRuntimeSecurityError, match="store lock is missing"):
        with runtime._store_lock(
            existing, mode=runtime._STORE_LOCK_SHARED, create=False,
            timeout_seconds=0.0,
        ):
            pass
    assert not (existing / ".lock").exists()


def test_acquisition_failure_never_unlocks_and_preserves_exact_exception(
    runtime, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "store"
    marker = OSError(36, "resource deadlock avoided")
    releases: list[object] = []

    def fail_acquire(*_args, **_kwargs):
        raise marker

    monkeypatch.setattr(runtime, "_acquire_store_lock", fail_acquire)
    monkeypatch.setattr(
        runtime, "_release_store_lock",
        lambda *_args, **_kwargs: releases.append(object()),
    )
    with pytest.raises(OSError) as caught:
        with runtime._store_lock(
            root, mode=runtime._STORE_LOCK_EXCLUSIVE, create=True,
            timeout_seconds=0.0,
        ):
            pass
    assert caught.value is marker
    assert releases == []


def test_release_failure_does_not_mask_body_exception(
    runtime, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "store"
    _initialize_store(runtime, root)
    marker = LookupError("primary body failure")

    def fail_release(*_args, **_kwargs):
        raise PermissionError(13, "unlock denied")

    monkeypatch.setattr(runtime, "_release_store_lock", fail_release)
    with pytest.raises(LookupError) as caught:
        with runtime._store_lock(
            root, mode=runtime._STORE_LOCK_SHARED, create=False,
            timeout_seconds=1.0,
        ):
            raise marker
    assert caught.value is marker
    assert any("lock release failed" in note for note in caught.value.__notes__)


def test_same_thread_same_root_reentry_rejects_immediately(
    runtime, tmp_path: Path,
) -> None:
    root = tmp_path / "store"
    with runtime._store_lock(
        root, mode=runtime._STORE_LOCK_EXCLUSIVE, create=True,
        timeout_seconds=1.0,
    ):
        started = time.monotonic()
        with pytest.raises(
            runtime.MCPRuntimeSecurityError, match="same-thread reentry"
        ):
            with runtime._store_lock(
                root, mode=runtime._STORE_LOCK_SHARED, create=False,
                timeout_seconds=10.0,
            ):
                pass
        assert time.monotonic() - started < 0.25


def test_lock_descriptor_is_non_inheritable(
    runtime, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "store"
    original = runtime._acquire_store_lock
    observed: list[bool] = []

    def inspect(descriptor, mode, *, timeout_seconds):
        observed.append(os.get_inheritable(descriptor))
        return original(descriptor, mode, timeout_seconds=timeout_seconds)

    monkeypatch.setattr(runtime, "_acquire_store_lock", inspect)
    _initialize_store(runtime, root)
    assert observed == [False]


@pytest.mark.parametrize("raw", (b"x", b"\0x"))
def test_existing_nonzero_lock_content_or_size_drift_fails_closed(
    runtime, tmp_path: Path, raw: bytes,
) -> None:
    root = tmp_path / "store"
    _initialize_store(runtime, root)
    (root / ".lock").write_bytes(raw)
    with pytest.raises(runtime.MCPRuntimeStoreCorruptError, match="lock (content|size)"):
        with runtime._store_lock(
            root, mode=runtime._STORE_LOCK_SHARED, create=False,
            timeout_seconds=0.0,
        ):
            pass
    assert (root / ".lock").read_bytes() == raw


def test_reader_never_repairs_zero_byte_lock_but_writer_recovers_it(
    runtime, tmp_path: Path,
) -> None:
    root = tmp_path / "store"
    runtime._ensure_store(root)
    (root / ".lock").write_bytes(b"")

    with pytest.raises(
        runtime.MCPRuntimeStoreUnavailableError,
        match="lock initialization is incomplete",
    ):
        with runtime._store_lock(
            root, mode=runtime._STORE_LOCK_SHARED, create=False,
            timeout_seconds=0.2,
        ):
            pass
    assert (root / ".lock").read_bytes() == b""

    with runtime._store_lock(
        root, mode=runtime._STORE_LOCK_EXCLUSIVE, create=True,
        timeout_seconds=1.0,
    ):
        pass
    assert (root / ".lock").read_bytes() == b"\0"


def test_interrupted_zero_byte_initialization_remains_retryable(
    runtime, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "store"
    original_write = runtime.os.write

    def interrupted_write(descriptor: int, raw: bytes) -> int:
        if raw == b"\0":
            return 0
        return original_write(descriptor, raw)

    monkeypatch.setattr(runtime.os, "write", interrupted_write)
    with pytest.raises(
        runtime.MCPRuntimeStoreUnavailableError, match="initialization was interrupted",
    ):
        with runtime._store_lock(
            root, mode=runtime._STORE_LOCK_EXCLUSIVE, create=True,
            timeout_seconds=1.0,
        ):
            pass
    assert (root / ".lock").read_bytes() == b""

    monkeypatch.setattr(runtime.os, "write", original_write)
    _initialize_store(runtime, root)
    assert (root / ".lock").read_bytes() == b"\0"


def test_hard_kill_before_initialization_leaves_writer_recoverable_state(
    runtime, tmp_path: Path,
) -> None:
    root = tmp_path / "store"
    code = r"""
import importlib.util, os, pathlib, sys
runtime_path, root = sys.argv[1:]
spec = importlib.util.spec_from_file_location("plamen_mcp_store_lock_crash", runtime_path)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
original = module._acquire_store_lock
def crash_after_lease(descriptor, mode, *, timeout_seconds):
    original(descriptor, mode, timeout_seconds=timeout_seconds)
    os._exit(91)
module._acquire_store_lock = crash_after_lease
with module._store_lock(
    pathlib.Path(root), mode=module._STORE_LOCK_EXCLUSIVE, create=True,
    timeout_seconds=1.0,
):
    raise AssertionError("body must not be reached")
"""
    crashed = subprocess.run(
        [sys.executable, "-c", code, str(RUNTIME_PATH), str(root)],
        capture_output=True, text=True, timeout=10,
    )
    assert crashed.returncode == 91, (crashed.stdout, crashed.stderr)
    assert (root / ".lock").read_bytes() == b""

    with pytest.raises(runtime.MCPRuntimeStoreUnavailableError):
        with runtime._store_lock(
            root, mode=runtime._STORE_LOCK_SHARED, create=False,
            timeout_seconds=0.2,
        ):
            pass
    assert (root / ".lock").read_bytes() == b""
    _initialize_store(runtime, root)
    assert (root / ".lock").read_bytes() == b"\0"


def test_real_readers_share_and_writer_gets_typed_bounded_contention(
    runtime, tmp_path: Path,
) -> None:
    root = tmp_path / "store"
    _initialize_store(runtime, root)
    holder, _ = _holder_process(root, runtime._STORE_LOCK_SHARED)
    try:
        with runtime._store_lock(
            root, mode=runtime._STORE_LOCK_SHARED, create=False,
            timeout_seconds=0.25,
        ):
            pass
        started = time.monotonic()
        with pytest.raises(runtime.MCPRuntimeStoreBusyError) as caught:
            with runtime._store_lock(
                root, mode=runtime._STORE_LOCK_EXCLUSIVE, create=False,
                timeout_seconds=0.2,
            ):
                pass
        elapsed = time.monotonic() - started
        assert caught.value.reason == "MCP_RUNTIME_STORE_BUSY"
        assert caught.value.mode == runtime._STORE_LOCK_EXCLUSIVE
        assert 0.15 <= elapsed < 1.5
    finally:
        _stop_process(holder)


@pytest.mark.skipif(os.name != "nt", reason="real handle inheritance is Windows-only")
def test_windows_killed_holder_releases_lock_while_child_remains_alive(
    runtime, tmp_path: Path,
) -> None:
    root = tmp_path / "store"
    _initialize_store(runtime, root)
    holder, child_pid = _holder_process(
        root, runtime._STORE_LOCK_EXCLUSIVE, spawn_child=True,
    )
    assert child_pid is not None
    try:
        holder.terminate()
        holder.wait(timeout=5)
        with runtime._store_lock(
            root, mode=runtime._STORE_LOCK_EXCLUSIVE, create=False,
            timeout_seconds=1.0,
        ):
            pass
        # The unrelated descendant is still alive, proving it did not retain
        # the non-inheritable lock handle after its parent died.
        assert _windows_process_is_active(child_pid)
    finally:
        _stop_process(holder)
        try:
            os.kill(child_pid, signal.SIGTERM)
        except OSError:
            pass


@pytest.mark.skipif(os.name == "nt", reason="POSIX rename semantics only")
def test_posix_named_lock_replacement_is_detected_before_body(
    runtime, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "store"
    _initialize_store(runtime, root)
    original = runtime._acquire_store_lock

    def replace_after_acquire(descriptor, mode, *, timeout_seconds):
        token = original(descriptor, mode, timeout_seconds=timeout_seconds)
        replacement = root / ".replacement"
        replacement.write_bytes(b"\0")
        os.replace(replacement, root / ".lock")
        return token

    monkeypatch.setattr(runtime, "_acquire_store_lock", replace_after_acquire)
    entered = False
    with pytest.raises(runtime.MCPRuntimeSecurityError, match="identity changed"):
        with runtime._store_lock(
            root, mode=runtime._STORE_LOCK_SHARED, create=False,
            timeout_seconds=1.0,
        ):
            entered = True
    assert entered is False
