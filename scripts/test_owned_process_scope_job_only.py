"""Windows Job-only descendant-containment regressions."""

from __future__ import annotations

import ctypes
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import time
import types

import pytest

import owned_process_scope as S


pytestmark = pytest.mark.skipif(
    os.name != "nt", reason="Windows Job-only containment is Windows-only",
)


def _process_is_running(process_id: int) -> bool:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
    kernel32.OpenProcess.restype = ctypes.c_void_p
    kernel32.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
    kernel32.WaitForSingleObject.restype = ctypes.c_uint32
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel32.CloseHandle.restype = ctypes.c_int
    handle = kernel32.OpenProcess(0x00100000 | 0x1000, False, process_id)
    if not handle:
        return False
    try:
        return int(kernel32.WaitForSingleObject(handle, 0)) == 0x00000102
    finally:
        kernel32.CloseHandle(handle)


def _start_sleeping_scope() -> tuple[S.OwnedProcessScope, subprocess.Popen[bytes]]:
    scope = S.OwnedProcessScope(windows_job_only=True)
    physical = scope.wrap_argv(
        (sys.executable, "-I", "-S", "-c", "import time; time.sleep(60)")
    )
    process = scope.create_process(
        physical,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        shell=False,
        **scope.popen_kwargs(),
    )
    scope.attach(process)
    return scope, process


def _terminate_close_reap(
    scope: S.OwnedProcessScope, process: subprocess.Popen[bytes],
) -> None:
    if scope.attached and not scope.terminated:
        scope.terminate()
    if not scope.closed:
        scope.close()
    process.wait(timeout=5)


def test_windows_job_only_capability_is_exactly_non_write_confined() -> None:
    scope = S.OwnedProcessScope(windows_job_only=True)
    try:
        capability = scope.scope_capability
        assert capability["mode"] == "WINDOWS_JOB_ONLY_DESCENDANT_CONTAINMENT"
        assert capability["provider_owns_tree"] is True
        assert capability["exhaustive_descendant_termination_authority"] is True
        assert capability["population_zero_proof"] == "JOB_ACTIVE_PROCESSES"
        assert capability["write_confinement"] == "NOT_PROVIDED"
        assert capability["exhaustive_write_confinement_authority"] is False
        assert capability["serialized_low_integrity_stage_authority"] is False
        assert scope._windows_write_lease is None
        assert scope.write_confinement_proven is False
        assert scope.serialized_stage_write_confinement_proven is False
        assert scope.write_confinement_binding is None
        assert scope.containment_evidence["write_confinement_proven"] is False
    finally:
        scope.close()
    assert scope.population_zero_proven is True
    assert scope.containment_evidence["closed"] is True


def test_job_only_zero_root_scope_loads_from_installed_file_without_sibling_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Doctor loads this file by spec; zero-root probes need no sibling import."""
    script_dir = Path(S.__file__).resolve().parent
    monkeypatch.setattr(
        sys,
        "path",
        [item for item in sys.path if Path(item or ".").resolve() != script_dir],
    )
    monkeypatch.delitem(sys.modules, "rooted_path_io", raising=False)
    spec = importlib.util.spec_from_file_location(
        "_isolated_owned_process_scope_fixture", Path(S.__file__).resolve()
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(
        module.OwnedProcessScope,
        "_create_windows_job",
        staticmethod(lambda: 123),
    )
    scope = module.OwnedProcessScope(windows_job_only=True)
    assert scope._writable_roots == ()
    assert "rooted_path_io" not in sys.modules
    # The fixture does not own a real native handle.
    scope._job_handle = None
    scope._closed = True


def test_windows_job_only_rejects_write_lease_inputs_before_job_creation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0

    def create_job() -> int:
        nonlocal calls
        calls += 1
        return 123

    monkeypatch.setattr(S.OwnedProcessScope, "_create_windows_job", staticmethod(create_job))
    with pytest.raises(S.OwnedProcessScopeError, match="does not accept writable roots"):
        S.OwnedProcessScope(windows_job_only=True, writable_roots=(tmp_path,))
    with pytest.raises(S.OwnedProcessScopeError, match="lease controls"):
        S.OwnedProcessScope(
            windows_job_only=True, lease_acquisition_deadline_monotonic=1.0,
        )
    assert calls == 0


def test_default_windows_mode_still_acquires_the_low_integrity_lease(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    acquisitions: list[dict[str, object]] = []

    class _Lease:
        active = True
        binding = {"fixture": "default-mode"}

        def __init__(self, **kwargs: object) -> None:
            acquisitions.append(dict(kwargs))

        def release_after_proven_closure(self) -> None:
            return None

    fake_module = types.SimpleNamespace(WindowsLowIntegrityExecutionLease=_Lease)
    monkeypatch.setitem(sys.modules, "windows_low_integrity_lease", fake_module)
    monkeypatch.setattr(S, "process_tree_termination_capability", lambda: {"platform": "WINDOWS"})
    monkeypatch.setattr(S.OwnedProcessScope, "_create_windows_job", staticmethod(lambda: 123))
    scope = S.OwnedProcessScope()
    try:
        assert len(acquisitions) == 1
        assert scope._windows_write_lease is not None
        assert scope._windows_job_only is False
    finally:
        # This fixture never created a real native handle.
        scope._job_handle = None
        scope._closed = True


def test_two_windows_job_only_scopes_execute_concurrently_without_global_lease() -> None:
    scopes: list[tuple[S.OwnedProcessScope, subprocess.Popen[bytes]]] = []
    try:
        scopes.append(_start_sleeping_scope())
        scopes.append(_start_sleeping_scope())
        assert all(process.poll() is None for _scope, process in scopes)
        assert scopes[0][0]._job_handle != scopes[1][0]._job_handle
        assert all(scope._windows_write_lease is None for scope, _process in scopes)
        assert all(scope._windows_integrity_sid is None for scope, _process in scopes)
    finally:
        for scope, process in scopes:
            _terminate_close_reap(scope, process)
    assert all(scope.population_zero_proven for scope, _process in scopes)


def test_windows_job_only_terminates_detached_grandchild_and_proves_zero(
    tmp_path: Path,
) -> None:
    grandchild_pid_path = tmp_path / "grandchild.pid"
    detached_process = getattr(subprocess, "DETACHED_PROCESS", 0x00000008)
    child_code = "\n".join(
        (
            "from pathlib import Path",
            "import subprocess, sys, time",
            "grandchild = subprocess.Popen(",
            "    [sys.executable, '-I', '-S', '-c', 'import time; time.sleep(60)'],",
            "    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,",
            "    stderr=subprocess.DEVNULL, close_fds=True,",
            f"    creationflags={detached_process} | subprocess.CREATE_NEW_PROCESS_GROUP,",
            ")",
            f"pid_path = Path({str(grandchild_pid_path)!r})",
            "pid_staging = pid_path.with_suffix('.staging')",
            "pid_staging.write_text(str(grandchild.pid), encoding='ascii')",
            "pid_staging.replace(pid_path)",
            "time.sleep(60)",
        )
    )
    scope = S.OwnedProcessScope(windows_job_only=True)
    process: subprocess.Popen[bytes] | None = None
    grandchild_pid: int | None = None
    try:
        process = scope.create_process(
            scope.wrap_argv((sys.executable, "-I", "-S", "-c", child_code)),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            shell=False,
            **scope.popen_kwargs(),
        )
        scope.attach(process)
        deadline = time.monotonic() + 5
        while not grandchild_pid_path.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        assert grandchild_pid_path.exists(), "detached grandchild did not start"
        grandchild_pid = int(grandchild_pid_path.read_text(encoding="ascii"))
        assert _process_is_running(grandchild_pid)

        scope.terminate()
        scope.close()
        process.wait(timeout=5)
        deadline = time.monotonic() + 5
        while _process_is_running(grandchild_pid) and time.monotonic() < deadline:
            time.sleep(0.01)
        assert _process_is_running(grandchild_pid) is False
        assert scope.population_zero_proven is True
        assert scope.containment_evidence == {
            "mode": "WINDOWS_JOB_ONLY_DESCENDANT_CONTAINMENT",
            "platform": "WINDOWS",
            "provider_owns_tree": True,
            "exhaustive_descendant_termination_authority": True,
            "write_confinement_proven": False,
            "serialized_stage_write_confinement_proven": False,
            "population_zero_proven": True,
            "closed": True,
        }
    finally:
        if process is not None and process.poll() is None:
            if scope.attached and not scope.terminated:
                scope.terminate()
            process.wait(timeout=5)
        if not scope.closed:
            scope.close()
        if grandchild_pid is not None and _process_is_running(grandchild_pid):
            pytest.fail("Job-only cleanup left the detached grandchild live")
