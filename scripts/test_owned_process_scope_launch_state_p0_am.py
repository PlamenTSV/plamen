"""Fixture-first process-creation authority tests for OwnedProcessScope."""

from __future__ import annotations

import ctypes
from dataclasses import dataclass
import os
from pathlib import Path
import subprocess
import sys
import time
from typing import Any
from types import SimpleNamespace

import pytest

import owned_process_scope as S


_LIVE_WINDOWS_PY312 = os.name == "nt" and sys.version_info[:2] == (3, 12)
_CPYTHON_312 = (
    getattr(sys.implementation, "name", None) == "cpython"
    and sys.version_info[:2] == (3, 12)
)
_CPYTHON_312_TRANSPORT = pytest.mark.skipif(
    not _CPYTHON_312,
    reason="the copied Windows Popen transport is pinned to CPython 3.12",
)


class _OSProxy:
    """Override only ``os.name`` without mutating Python's global os module."""

    def __init__(self, name: str) -> None:
        self.name = name

    def __getattr__(self, attribute: str) -> Any:
        return getattr(os, attribute)


def _simulate_platform(
    monkeypatch: pytest.MonkeyPatch,
    name: str,
) -> None:
    monkeypatch.setattr(S, "os", _OSProxy(name))


@dataclass
class _FakeProcess:
    pid: int
    primary_thread_handle: int | None = None

    def _take_primary_thread_handle(self) -> int | None:
        handle = self.primary_thread_handle
        self.primary_thread_handle = None
        return handle


@dataclass
class _CleanupProcess:
    pid: int
    poll_result: int | None = None
    kill_error: BaseException | None = None
    wait_error: BaseException | None = None
    kill_calls: int = 0
    wait_calls: int = 0

    def poll(self) -> int | None:
        return self.poll_result

    def kill(self) -> None:
        self.kill_calls += 1
        if self.kill_error is not None:
            raise self.kill_error
        self.poll_result = -9

    def wait(self, *, timeout: float) -> int:
        del timeout
        self.wait_calls += 1
        if self.wait_error is not None:
            raise self.wait_error
        if self.poll_result is None:
            self.poll_result = 0
        return self.poll_result


class _FakeWinFunction:
    def __init__(self, callback: Any) -> None:
        self._callback = callback
        self.argtypes: list[Any] = []
        self.restype: Any = None

    def __call__(self, *args: Any) -> Any:
        return self._callback(*args)


class _FakeAtomicKernel:
    """Stateful Win32 model for the portable atomic-create boundary tests."""

    def __init__(self, *, fail_at: str | None = None) -> None:
        self.fail_at = fail_at
        self.last_error = 0
        self.events: list[str] = []
        self.attributes: list[int] = []
        self.live_processes: set[int] = set()
        self.closed_handles: list[int] = []
        self.terminated_processes: list[int] = []
        self.InitializeProcThreadAttributeList = _FakeWinFunction(
            self._initialize
        )
        self.UpdateProcThreadAttribute = _FakeWinFunction(self._update)
        self.DeleteProcThreadAttributeList = _FakeWinFunction(self._delete)
        self.CreateProcessW = _FakeWinFunction(self._create)
        self.TerminateProcess = _FakeWinFunction(self._terminate)
        self.WaitForSingleObject = _FakeWinFunction(self._wait)
        self.CloseHandle = _FakeWinFunction(self._close)
        self.ResumeThread = _FakeWinFunction(self._resume)

    def _initialize(
        self,
        storage: Any,
        _count: int,
        _flags: int,
        size_pointer: Any,
    ) -> int:
        size = ctypes.cast(
            size_pointer, ctypes.POINTER(ctypes.c_size_t)
        )
        if storage is None:
            self.events.append("SIZE")
            if self.fail_at == "SIZE":
                self.last_error = 50
                return 0
            size[0] = 256
            self.last_error = 122
            return 0
        self.events.append("INITIALIZE")
        if self.fail_at == "INITIALIZE":
            self.last_error = 50
            return 0
        return 1

    def _update(
        self,
        _storage: Any,
        _flags: int,
        attribute: int,
        _value: Any,
        _value_size: int,
        _previous: Any,
        _return_size: Any,
    ) -> int:
        value = int(attribute)
        self.attributes.append(value)
        label = (
            "JOB_UPDATE"
            if value == S._PROC_THREAD_ATTRIBUTE_JOB_LIST
            else "HANDLE_UPDATE"
        )
        self.events.append(label)
        if self.fail_at == label:
            self.last_error = 50
            return 0
        return 1

    def _delete(self, _storage: Any) -> None:
        self.events.append("DELETE")

    def _create(self, *args: Any) -> int:
        self.events.append("CREATE")
        if self.fail_at == "CREATE":
            # ERROR_ACCESS_DENIED is a documented outcome when requested Job
            # assignment conflicts with the caller's nesting constraints.
            self.last_error = 5
            return 0
        flags = int(args[5])
        assert flags & S._CREATE_SUSPENDED
        assert flags & S._EXTENDED_STARTUPINFO_PRESENT
        information = ctypes.cast(
            args[9], ctypes.POINTER(S._WindowsProcessInformation)
        ).contents
        information.hProcess = 7001
        information.hThread = 7002
        information.dwProcessId = 7003
        information.dwThreadId = 7004
        self.live_processes.add(7001)
        return 1

    def _terminate(self, handle: Any, _exit_code: int) -> int:
        value = int(getattr(handle, "value", handle))
        self.events.append("TERMINATE")
        self.terminated_processes.append(value)
        self.live_processes.discard(value)
        return 1

    def _wait(self, _handle: Any, _milliseconds: int) -> int:
        self.events.append("WAIT")
        return 0

    def _close(self, handle: Any) -> int:
        self.events.append("CLOSE")
        self.closed_handles.append(int(getattr(handle, "value", handle)))
        return 1

    def _resume(self, handle: Any) -> int:
        self.events.append("RESUME")
        assert int(getattr(handle, "value", handle)) == 791
        return 1


class _InjectedProviderCrash(BaseException):
    pass


def _windows_process_is_running(process_id: int) -> bool:
    if os.name != "nt":
        return False
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.argtypes = [
        ctypes.c_uint32,
        ctypes.c_int,
        ctypes.c_uint32,
    ]
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


def _terminate_exact_windows_fixture_process(process_id: int) -> None:
    if os.name != "nt":
        return
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.argtypes = [
        ctypes.c_uint32,
        ctypes.c_int,
        ctypes.c_uint32,
    ]
    kernel32.OpenProcess.restype = ctypes.c_void_p
    kernel32.TerminateProcess.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
    kernel32.TerminateProcess.restype = ctypes.c_int
    kernel32.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
    kernel32.WaitForSingleObject.restype = ctypes.c_uint32
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel32.CloseHandle.restype = ctypes.c_int
    handle = kernel32.OpenProcess(
        0x0001 | 0x00100000 | 0x1000,
        False,
        process_id,
    )
    if not handle:
        return
    try:
        kernel32.TerminateProcess(handle, 97)
        kernel32.WaitForSingleObject(handle, 5000)
    finally:
        kernel32.CloseHandle(handle)


def _bare_scope() -> S.OwnedProcessScope:
    """Build a platform-neutral scope for the launch-state unit boundary."""

    scope = object.__new__(S.OwnedProcessScope)
    scope._attached = False
    scope._closed = False
    scope._process_creation_attempted = False
    scope._process_creation_state = "NOT_ATTEMPTED"
    scope._created_process = None
    scope._created_process_termination_proven = False
    scope._job_handle = None
    scope._windows_job_owned_suspended = False
    scope._windows_primary_thread_handle = None
    scope._linux_cgroup = None
    scope._linux_created_process_cgroup_membership_proven = False
    scope._process_group_id = None
    return scope


def test_cancellation_before_create_remains_not_attempted() -> None:
    scope = _bare_scope()

    assert scope.process_creation_state == "NOT_ATTEMPTED"
    assert scope.process_creation_evidence == {
        "state": "NOT_ATTEMPTED",
        "creation_attempted": False,
        "process_object_returned": False,
        "attached": False,
        "created_process_termination_proven": False,
    }


def test_factory_raise_is_creation_failed_without_process_object() -> None:
    scope = _bare_scope()
    calls: list[tuple[tuple[str, ...], dict[str, Any]]] = []

    def fail(argv: list[str], **kwargs: Any) -> _FakeProcess:
        calls.append((tuple(argv), dict(kwargs)))
        assert scope.process_creation_state == "NOT_ATTEMPTED"
        assert scope.process_creation_evidence["creation_attempted"] is True
        raise OSError("injected create failure")

    with pytest.raises(OSError, match="injected create failure"):
        scope.create_process(
            ("C:/trusted/claude.exe", "-p"),
            popen_factory=fail,
            cwd="C:/project",
            env={"SAFE": "1"},
            stdin=None,
            stdout="stdout-sentinel",
            stderr="stderr-sentinel",
            shell=False,
            creationflags=4,
        )

    assert calls == [
        (
            ("C:/trusted/claude.exe", "-p"),
            {
                "cwd": "C:/project",
                "env": {"SAFE": "1"},
                "stdin": None,
                "stdout": "stdout-sentinel",
                "stderr": "stderr-sentinel",
                "shell": False,
                "creationflags": 4,
            },
        )
    ]
    assert scope.process_creation_state == (
        "CREATION_FAILED_WITHOUT_PROCESS_OBJECT"
    )
    assert scope.process_creation_evidence == {
        "state": "CREATION_FAILED_WITHOUT_PROCESS_OBJECT",
        "creation_attempted": True,
        "process_object_returned": False,
        "attached": False,
        "created_process_termination_proven": False,
    }
    with pytest.raises(
        S.OwnedProcessScopeError,
        match="process creation was already attempted",
    ):
        scope.create_process(
            ("C:/trusted/claude.exe", "-p"),
            popen_factory=lambda *_a, **_k: _FakeProcess(pid=999),
        )
    assert scope.process_creation_state == (
        "CREATION_FAILED_WITHOUT_PROCESS_OBJECT"
    )
    scope.close()
    assert scope.closed is True
    assert scope.process_creation_state == (
        "CREATION_FAILED_WITHOUT_PROCESS_OBJECT"
    )


def test_returned_process_is_created_before_factory_returns_to_caller() -> None:
    scope = _bare_scope()
    process = _FakeProcess(pid=101)

    def create(_argv: list[str], **_kwargs: Any) -> _FakeProcess:
        return process

    returned = scope.create_process(
        ("C:/trusted/claude.exe", "-p"),
        popen_factory=create,
    )

    assert returned is process
    assert scope.process_creation_state == "PROCESS_CREATED"
    assert scope.process_creation_evidence == {
        "state": "PROCESS_CREATED",
        "creation_attempted": True,
        "process_object_returned": True,
        "attached": False,
        "created_process_termination_proven": False,
    }


def test_windows_job_ownership_is_established_inside_create_before_return(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scope = _bare_scope()
    scope._job_handle = 123
    process = _FakeProcess(pid=111, primary_thread_handle=789)
    process._handle = 456  # type: ignore[attr-defined]
    events: list[tuple[int, tuple[str, ...]]] = []

    _simulate_platform(monkeypatch, "nt")

    def atomic_create(
        job_handle: int,
        argv: list[str],
        **_kwargs: Any,
    ) -> _FakeProcess:
        events.append((job_handle, tuple(argv)))
        return process

    returned = scope.create_process(
        ("C:/trusted/claude.exe", "-p"),
        _windows_atomic_factory=atomic_create,
        creationflags=S._CREATE_SUSPENDED,
    )

    assert returned is process
    assert events == [(123, ("C:/trusted/claude.exe", "-p"))]
    assert scope._windows_job_owned_suspended is True
    assert scope._windows_primary_thread_handle == 789
    assert process.primary_thread_handle is None
    assert scope.process_creation_state == "PROCESS_CREATED"


def test_windows_create_rejects_non_suspended_launch_before_factory(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scope = _bare_scope()
    scope._job_handle = 123
    factory_calls = 0

    def create(*_args: Any, **_kwargs: Any) -> _FakeProcess:
        nonlocal factory_calls
        factory_calls += 1
        return _FakeProcess(pid=112)

    _simulate_platform(monkeypatch, "nt")
    with pytest.raises(
        S.OwnedProcessScopeError,
        match="CREATE_SUSPENDED",
    ):
        scope.create_process(
            ("C:/trusted/claude.exe", "-p"),
            _windows_atomic_factory=lambda _job, *args, **kwargs: create(
                *args, **kwargs
            ),
            creationflags=0,
        )

    assert factory_calls == 0
    assert scope.process_creation_state == "NOT_ATTEMPTED"
    assert scope.process_creation_evidence["creation_attempted"] is False


def test_windows_atomic_create_failure_returns_no_process_object(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scope = _bare_scope()
    scope._job_handle = 123

    _simulate_platform(monkeypatch, "nt")

    def fail_create(
        _job_handle: int,
        _argv: list[str],
        **_kwargs: Any,
    ) -> _CleanupProcess:
        raise S.OwnedProcessScopeError("injected atomic create failure")

    with pytest.raises(
        S.OwnedProcessScopeError,
        match="injected atomic create failure",
    ):
        scope.create_process(
            ("C:/trusted/claude.exe", "-p"),
            _windows_atomic_factory=fail_create,
            creationflags=S._CREATE_SUSPENDED,
        )

    assert scope._created_process is None
    assert scope.process_creation_state == "CREATION_FAILED_WITHOUT_PROCESS_OBJECT"
    assert scope.created_process_termination_proven is False
    assert scope._windows_job_owned_suspended is False


def test_windows_rejects_ordinary_factory_without_consuming_authority(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scope = _bare_scope()
    scope._job_handle = 123
    calls = 0

    def ordinary_factory(*_args: Any, **_kwargs: Any) -> _FakeProcess:
        nonlocal calls
        calls += 1
        return _FakeProcess(pid=999)

    _simulate_platform(monkeypatch, "nt")
    with pytest.raises(
        S.OwnedProcessScopeError,
        match="rejects non-atomic Popen factories",
    ):
        scope.create_process(
            ("C:/trusted/claude.exe",),
            popen_factory=ordinary_factory,
            creationflags=S._CREATE_SUSPENDED,
        )

    assert calls == 0
    assert scope.process_creation_state == "NOT_ATTEMPTED"


def test_windows_default_provider_is_atomic_popen_transport(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scope = _bare_scope()
    scope._job_handle = 123
    process = _FakeProcess(pid=1001, primary_thread_handle=790)
    calls: list[tuple[int, tuple[str, ...], int]] = []

    def atomic_transport(
        job_handle: int,
        argv: list[str],
        **kwargs: Any,
    ) -> _FakeProcess:
        calls.append((job_handle, tuple(argv), kwargs["creationflags"]))
        return process

    _simulate_platform(monkeypatch, "nt")
    monkeypatch.setattr(S, "_WindowsAtomicJobPopen", atomic_transport)

    assert scope.create_process(
        ("C:/trusted/claude.exe",),
        creationflags=S._CREATE_SUSPENDED,
    ) is process
    assert calls == [(123, ("C:/trusted/claude.exe",), S._CREATE_SUSPENDED)]
    assert scope._windows_job_owned_suspended is True
    assert scope._windows_primary_thread_handle == 790


def _atomic_startup(*, with_handles: bool = True) -> Any:
    class _Startup:
        dwFlags = 0x100
        wShowWindow = 0
        hStdInput = 11
        hStdOutput = 12
        hStdError = 13
        lpAttributeList = {"handle_list": [11, 12, 13]} if with_handles else {}

        def copy(self) -> Any:
            return self

    return _Startup()


def _call_fake_atomic_create(
    kernel: _FakeAtomicKernel,
    *,
    with_handles: bool = True,
    boundary_hook: Any | None = None,
) -> tuple[int, int, int, int]:
    return S._windows_create_process_in_job(
        job_handle=123,
        application_name="C:/trusted/claude.exe",
        command_line='C:/trusted/claude.exe -p',
        inherit_handles=with_handles,
        creationflags=S._CREATE_SUSPENDED,
        environment={"SAFE": "1"},
        current_directory="C:/project",
        startupinfo=_atomic_startup(with_handles=with_handles),
        kernel32=kernel,
        _boundary_hook=boundary_hook,
    )


def test_windows_atomic_create_uses_job_and_handle_attributes_and_cleans_list() -> None:
    kernel = _FakeAtomicKernel()

    result = _call_fake_atomic_create(kernel)

    assert result == (7001, 7002, 7003, 7004)
    assert kernel.attributes == [
        S._PROC_THREAD_ATTRIBUTE_JOB_LIST,
        S._PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
    ]
    assert kernel.events == [
        "SIZE",
        "INITIALIZE",
        "JOB_UPDATE",
        "HANDLE_UPDATE",
        "CREATE",
        "DELETE",
    ]
    # Ownership of successful result handles transfers to Popen.  Attribute
    # storage is already gone; neither process handle is prematurely closed.
    assert kernel.closed_handles == []
    assert kernel.live_processes == {7001}


@pytest.mark.parametrize(
    "native_failure,expected_events",
    (
        ("SIZE", ["SIZE"]),
        ("INITIALIZE", ["SIZE", "INITIALIZE"]),
        ("JOB_UPDATE", ["SIZE", "INITIALIZE", "JOB_UPDATE", "DELETE"]),
        (
            "HANDLE_UPDATE",
            [
                "SIZE",
                "INITIALIZE",
                "JOB_UPDATE",
                "HANDLE_UPDATE",
                "DELETE",
            ],
        ),
        (
            "CREATE",
            [
                "SIZE",
                "INITIALIZE",
                "JOB_UPDATE",
                "HANDLE_UPDATE",
                "CREATE",
                "DELETE",
            ],
        ),
    ),
)
def test_windows_atomic_setup_and_nested_job_failures_leave_no_child(
    native_failure: str,
    expected_events: list[str],
) -> None:
    kernel = _FakeAtomicKernel(fail_at=native_failure)

    with pytest.raises(S.OwnedProcessScopeError):
        _call_fake_atomic_create(kernel)

    assert kernel.events == expected_events
    assert kernel.live_processes == set()
    assert kernel.closed_handles == []


@pytest.mark.parametrize(
    "boundary",
    (
        "ATTRIBUTE_LIST_INITIALIZED",
        "JOB_ATTRIBUTE_SET",
        "HANDLE_ATTRIBUTE_SET",
        "CREATE_RETURNED",
    ),
)
def test_windows_provider_crash_boundary_has_exact_no_orphan_postcondition(
    boundary: str,
) -> None:
    kernel = _FakeAtomicKernel()

    def crash(observed: str, _process_info: Any) -> None:
        if observed == boundary:
            raise _InjectedProviderCrash(observed)

    expected = (
        S._WindowsAtomicPopenConstructionError
        if boundary == "CREATE_RETURNED"
        else _InjectedProviderCrash
    )
    with pytest.raises(expected):
        _call_fake_atomic_create(kernel, boundary_hook=crash)

    assert kernel.live_processes == set()
    assert kernel.events.count("DELETE") == 1
    if boundary == "CREATE_RETURNED":
        assert kernel.terminated_processes == [7001]
        assert kernel.closed_handles == [7002, 7001]
    else:
        assert kernel.terminated_processes == []
        assert kernel.closed_handles == []


def test_windows_atomic_create_rejects_unknown_attributes_before_native_setup() -> None:
    kernel = _FakeAtomicKernel()
    startup = _atomic_startup()
    startup.lpAttributeList["parent_process"] = [99]

    with pytest.raises(
        S.OwnedProcessScopeError,
        match="unsupported Windows process attribute",
    ):
        S._windows_create_process_in_job(
            job_handle=123,
            application_name=None,
            command_line="C:/trusted/claude.exe",
            inherit_handles=True,
            creationflags=S._CREATE_SUSPENDED,
            environment=None,
            current_directory=None,
            startupinfo=startup,
            kernel32=kernel,
        )

    assert kernel.events == []
    assert kernel.live_processes == set()


def test_windows_missing_atomic_api_fails_before_any_process_exists() -> None:
    class _UnsupportedKernel:
        pass

    with pytest.raises(
        S.OwnedProcessScopeError,
        match="atomic Job creation API is unavailable",
    ):
        S._windows_create_process_in_job(
            job_handle=123,
            application_name=None,
            command_line="C:/trusted/claude.exe",
            inherit_handles=False,
            creationflags=S._CREATE_SUSPENDED,
            environment=None,
            current_directory=None,
            startupinfo=_atomic_startup(with_handles=False),
            kernel32=_UnsupportedKernel(),
        )


def test_windows_job_handle_cannot_be_inherited_by_child() -> None:
    kernel = _FakeAtomicKernel()
    startup = _atomic_startup()
    startup.lpAttributeList["handle_list"].append(123)

    with pytest.raises(
        S.OwnedProcessScopeError,
        match="Job handle must not be inherited",
    ):
        S._windows_create_process_in_job(
            job_handle=123,
            application_name=None,
            command_line="C:/trusted/claude.exe",
            inherit_handles=True,
            creationflags=S._CREATE_SUSPENDED,
            environment=None,
            current_directory=None,
            startupinfo=startup,
            kernel32=kernel,
        )

    assert kernel.events == []
    assert kernel.live_processes == set()


@pytest.mark.parametrize(
    "field,value",
    (
        ("application_name", "C:/safe.exe\x00C:/evil.exe"),
        ("command_line", "C:/safe.exe --ok\x00 --evil"),
        ("current_directory", "C:/safe\x00C:/evil"),
    ),
)
def test_windows_create_rejects_nul_truncation_before_native_setup(
    field: str,
    value: str,
) -> None:
    kernel = _FakeAtomicKernel()
    kwargs: dict[str, Any] = {
        "job_handle": 123,
        "application_name": "C:/safe.exe",
        "command_line": "C:/safe.exe --ok",
        "inherit_handles": False,
        "creationflags": S._CREATE_SUSPENDED,
        "environment": None,
        "current_directory": "C:/safe",
        "startupinfo": _atomic_startup(with_handles=False),
        "kernel32": kernel,
    }
    kwargs[field] = value

    with pytest.raises(S.OwnedProcessScopeError, match="embedded NUL"):
        S._windows_create_process_in_job(**kwargs)

    assert kernel.events == []
    assert kernel.live_processes == set()


@pytest.mark.parametrize(
    "environment,match",
    (
        ({"SAFE": "ok\x00evil"}, "illegal Windows environment entry"),
        ({"Path": "one", "PATH": "two"}, "case-insensitive duplicate"),
        ({"S\N{LATIN SMALL LETTER E WITH ACUTE}CURITY": "1"}, "non-ASCII"),
    ),
)
def test_windows_environment_ambiguity_fails_before_native_setup(
    environment: dict[str, str],
    match: str,
) -> None:
    kernel = _FakeAtomicKernel()
    with pytest.raises((ValueError, S.OwnedProcessScopeError), match=match):
        S._windows_create_process_in_job(
            job_handle=123,
            application_name="C:/safe.exe",
            command_line="C:/safe.exe",
            inherit_handles=False,
            creationflags=S._CREATE_SUSPENDED,
            environment=environment,
            current_directory="C:/safe",
            startupinfo=_atomic_startup(with_handles=False),
            kernel32=kernel,
        )
    assert kernel.events == []
    assert kernel.live_processes == set()


def test_windows_structure_layout_matches_x86_and_x64_abi() -> None:
    expected = {
        4: (68, 72, 16, 68),
        8: (104, 112, 24, 104),
    }
    assert expected[ctypes.sizeof(ctypes.c_void_p)] == (
        ctypes.sizeof(S._WindowsStartupInfo),
        ctypes.sizeof(S._WindowsStartupInfoEx),
        ctypes.sizeof(S._WindowsProcessInformation),
        S._WindowsStartupInfoEx.lpAttributeList.offset,
    )
    assert S._windows_structure_layout_supported() is True

    class _StartupInfo32(ctypes.Structure):
        _fields_ = [
            (
                name,
                ctypes.c_uint32
                if name in {
                    "lpReserved",
                    "lpDesktop",
                    "lpTitle",
                    "lpReserved2",
                    "hStdInput",
                    "hStdOutput",
                    "hStdError",
                }
                else field,
            )
            for name, field in S._WindowsStartupInfo._fields_
        ]

    class _StartupInfoEx32(ctypes.Structure):
        _fields_ = [
            ("StartupInfo", _StartupInfo32),
            ("lpAttributeList", ctypes.c_uint32),
        ]

    class _ProcessInformation32(ctypes.Structure):
        _fields_ = [
            ("hProcess", ctypes.c_uint32),
            ("hThread", ctypes.c_uint32),
            ("dwProcessId", ctypes.c_uint32),
            ("dwThreadId", ctypes.c_uint32),
        ]

    assert ctypes.sizeof(_StartupInfo32) == 68
    assert ctypes.sizeof(_StartupInfoEx32) == 72
    assert ctypes.sizeof(_ProcessInformation32) == 16
    assert _StartupInfoEx32.lpAttributeList.offset == 68


def test_windows_exact_primary_thread_handle_is_one_shot() -> None:
    process = object.__new__(S._WindowsAtomicJobPopen)
    process._plamen_primary_thread_handle = 791

    assert process._take_primary_thread_handle() == 791
    with pytest.raises(
        S.OwnedProcessScopeError,
        match="primary-thread handle is unavailable",
    ):
        process._take_primary_thread_handle()


def test_windows_resume_uses_exact_handle_then_closes_it() -> None:
    scope = _bare_scope()
    scope._windows_primary_thread_handle = 791
    kernel = _FakeAtomicKernel()

    scope._resume_exact_windows_primary_thread(kernel32=kernel)

    assert kernel.events == ["RESUME", "CLOSE"]
    assert kernel.closed_handles == [791]
    assert scope._windows_primary_thread_handle is None


def test_windows_unreturned_process_abort_closes_both_exact_handles() -> None:
    kernel = _FakeAtomicKernel()
    kernel.live_processes.add(7001)

    assert S._abort_windows_unreturned_process(
        7001, 7002, kernel32=kernel
    ) is True
    assert kernel.live_processes == set()
    assert kernel.terminated_processes == [7001]
    assert kernel.closed_handles == [7002, 7001]


def _invoke_atomic_popen_execute(process: Any, startup: Any) -> None:
    process._execute_child(
        ["C:/safe.exe"],
        None,
        None,
        True,
        (),
        None,
        None,
        startup,
        S._CREATE_SUSPENDED,
        False,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        False,
        None,
        None,
        None,
        -1,
        False,
        -1,
    )


@_CPYTHON_312_TRANSPORT
def test_windows_popen_commits_only_after_pipe_cleanup_and_retains_thread(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = object.__new__(S._WindowsAtomicJobPopen)
    process._plamen_job_handle = 123
    process._plamen_primary_thread_handle = None
    process._child_created = False
    process.returncode = 0
    events: list[str] = []
    monkeypatch.setitem(
        sys.modules,
        "_winapi",
        SimpleNamespace(STARTF_USESTDHANDLES=0x100, STARTF_USESHOWWINDOW=1),
    )
    monkeypatch.setattr(
        S,
        "_windows_create_process_in_job",
        lambda **_kwargs: (7001, 7002, 7003, 7004),
    )
    monkeypatch.setattr(S.subprocess, "Handle", lambda value: value, raising=False)
    process._close_pipe_fds = lambda *_args: events.append("pipes-closed")

    _invoke_atomic_popen_execute(process, _atomic_startup(with_handles=False))

    assert events == ["pipes-closed"]
    assert process._child_created is True
    assert process._handle == 7001
    assert process.pid == 7003
    assert process._take_primary_thread_handle() == 7002


@_CPYTHON_312_TRANSPORT
def test_windows_popen_construction_failure_aborts_before_commit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = object.__new__(S._WindowsAtomicJobPopen)
    process._plamen_job_handle = 123
    process._plamen_primary_thread_handle = None
    process._child_created = False
    process.returncode = 0
    aborts: list[tuple[int, int]] = []
    monkeypatch.setitem(
        sys.modules,
        "_winapi",
        SimpleNamespace(STARTF_USESTDHANDLES=0x100, STARTF_USESHOWWINDOW=1),
    )
    monkeypatch.setattr(
        S,
        "_windows_create_process_in_job",
        lambda **_kwargs: (7001, 7002, 7003, 7004),
    )
    monkeypatch.setattr(
        S,
        "_abort_windows_unreturned_process",
        lambda process_handle, thread_handle: (
            aborts.append((process_handle, thread_handle)) or True
        ),
    )
    process._close_pipe_fds = lambda *_args: (_ for _ in ()).throw(
        OSError("injected pipe cleanup failure")
    )

    with pytest.raises(
        S._WindowsAtomicPopenConstructionError,
        match="abort was proven",
    ) as caught:
        _invoke_atomic_popen_execute(
            process, _atomic_startup(with_handles=False)
        )

    assert caught.value.termination_proven is True
    assert aborts == [(7001, 7002)]
    assert process._child_created is False
    assert process._plamen_primary_thread_handle is None


def test_windows_popen_init_failure_after_execute_aborts_owned_handles(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _FakeHandle:
        def __init__(self, value: int) -> None:
            self.value = value
            self.detached = False

        def __int__(self) -> int:
            return self.value

        def Detach(self) -> int:
            self.detached = True
            return self.value

    handle = _FakeHandle(7001)
    aborts: list[tuple[int, int]] = []

    def fail_after_execute(instance: Any, *_args: Any, **_kwargs: Any) -> None:
        instance._handle = handle
        instance._plamen_primary_thread_handle = 7002
        instance._child_created = True
        raise RuntimeError("injected Popen.__init__ return failure")

    monkeypatch.setattr(S.subprocess.Popen, "__init__", fail_after_execute)
    monkeypatch.setattr(
        S,
        "_abort_windows_unreturned_process",
        lambda process_handle, thread_handle: (
            aborts.append((process_handle, thread_handle)) or True
        ),
    )

    with pytest.raises(
        S._WindowsAtomicPopenConstructionError,
        match="Popen.__init__ did not return",
    ) as caught:
        S._WindowsAtomicJobPopen(123, ["C:/safe.exe"])

    assert caught.value.termination_proven is True
    assert handle.detached is True
    assert aborts == [(7001, 7002)]


@_CPYTHON_312_TRANSPORT
def test_windows_popen_emits_subprocess_audit_event_before_native_create(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = object.__new__(S._WindowsAtomicJobPopen)
    process._plamen_job_handle = 123
    process._plamen_primary_thread_handle = None
    process._child_created = False
    process.returncode = 0
    audit_events: list[tuple[Any, ...]] = []
    monkeypatch.setitem(
        sys.modules,
        "_winapi",
        SimpleNamespace(STARTF_USESTDHANDLES=0x100, STARTF_USESHOWWINDOW=1),
    )
    monkeypatch.setattr(
        S,
        "_windows_create_process_in_job",
        lambda **_kwargs: (_ for _ in ()).throw(
            S.OwnedProcessScopeError("injected pre-create failure")
        ),
    )
    monkeypatch.setattr(
        S.sys,
        "audit",
        lambda *event: audit_events.append(event),
    )
    process._close_pipe_fds = lambda *_args: None

    with pytest.raises(S.OwnedProcessScopeError):
        _invoke_atomic_popen_execute(
            process, _atomic_startup(with_handles=False)
        )

    assert audit_events == [
        (
            "subprocess.Popen",
            None,
            "C:/safe.exe",
            None,
            None,
        )
    ]


@pytest.mark.parametrize("proven", (False, True))
def test_windows_created_but_unreturned_has_distinct_monotonic_state(
    monkeypatch: pytest.MonkeyPatch,
    proven: bool,
) -> None:
    scope = _bare_scope()
    scope._job_handle = 123
    _simulate_platform(monkeypatch, "nt")

    def fail_after_create(*_args: Any, **_kwargs: Any) -> None:
        raise S._WindowsAtomicPopenConstructionError(
            "injected post-create construction failure",
            termination_proven=proven,
        )

    with pytest.raises(S._WindowsAtomicPopenConstructionError):
        scope.create_process(
            ("C:/safe.exe",),
            creationflags=S._CREATE_SUSPENDED,
            _windows_atomic_factory=fail_after_create,
        )

    assert scope.process_creation_state == (
        "PROCESS_CREATED_BUT_NOT_RETURNED_TERMINATED"
        if proven
        else "PROCESS_CREATED_BUT_NOT_RETURNED_CONTAINED"
    )
    assert scope.process_creation_evidence["process_object_returned"] is False
    assert scope.created_process_termination_proven is proven


def test_windows_unsupported_runtime_capability_and_constructor_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _simulate_platform(monkeypatch, "nt")
    monkeypatch.setattr(S.sys, "version_info", (3, 11, 9))

    capability = S.windows_job_only_process_tree_capability()
    assert capability["provider_owns_tree"] is False
    assert capability["pre_execution_assignment"] is False
    assert capability["exhaustive_descendant_termination_authority"] is False
    assert capability["process_scope_limitation"] == (
        "WINDOWS_ATOMIC_JOB_REQUIRES_CPYTHON_3_12"
    )
    with pytest.raises(
        S.OwnedProcessScopeError,
        match="REQUIRES_CPYTHON_3_12",
    ):
        S.OwnedProcessScope(windows_job_only=True)


def test_windows_attach_proves_existing_job_ownership_without_reassignment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scope = _bare_scope()
    scope._job_handle = 123
    scope._windows_job_owned_suspended = True
    scope._windows_primary_thread_handle = 791
    process = _FakeProcess(pid=114)
    process._handle = 456  # type: ignore[attr-defined]
    scope._created_process = process
    scope._process_creation_attempted = True
    scope._process_creation_state = "PROCESS_CREATED"

    class _Assignment:
        argtypes: list[Any] = []
        restype: Any = None
        calls = 0

        def __call__(self, *_args: Any) -> int:
            self.calls += 1
            return 1

    class _Kernel:
        AssignProcessToJobObject = _Assignment()

    kernel = _Kernel()
    _simulate_platform(monkeypatch, "nt")
    monkeypatch.setattr(
        S.ctypes,
        "WinDLL",
        lambda *_a, **_k: kernel,
        raising=False,
    )
    monkeypatch.setattr(
        scope,
        "_prove_windows_created_process_job_membership",
        lambda exact: exact is process,
        raising=False,
    )
    monkeypatch.setattr(
        S,
        "_lower_windows_process_integrity",
        lambda _handle: S._WINDOWS_LOW_INTEGRITY_SID,
    )
    monkeypatch.setattr(
        scope, "_resume_exact_windows_primary_thread", lambda: None
    )

    scope.attach(process)

    assert kernel.AssignProcessToJobObject.calls == 0
    assert scope.process_creation_state == "ATTACHED"
    assert scope.attached is True


def test_windows_attach_failure_exact_cleanup_then_ordinary_close(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scope = _bare_scope()
    scope._job_handle = 123
    scope._windows_job_owned_suspended = True
    scope._population_zero = False
    scope._terminated = False
    scope._emergency_closed = False
    process = _CleanupProcess(pid=115)
    process._handle = 456  # type: ignore[attr-defined]
    scope._created_process = process
    scope._process_creation_attempted = True
    scope._process_creation_state = "PROCESS_CREATED"
    lease_releases = 0

    class _Lease:
        def release_after_proven_closure(self) -> None:
            nonlocal lease_releases
            lease_releases += 1

    class _Close:
        argtypes: list[Any] = []
        restype: Any = None

        def __call__(self, *_args: Any) -> int:
            return 1

    class _Kernel:
        CloseHandle = _Close()

    scope._windows_write_lease = _Lease()
    _simulate_platform(monkeypatch, "nt")
    monkeypatch.setattr(
        scope,
        "_prove_windows_created_process_job_membership",
        lambda exact: exact is process,
    )
    monkeypatch.setattr(
        S,
        "_lower_windows_process_integrity",
        lambda _handle: (_ for _ in ()).throw(
            S.OwnedProcessScopeError("injected integrity failure")
        ),
    )
    monkeypatch.setattr(
        S.ctypes,
        "WinDLL",
        lambda *_a, **_k: _Kernel(),
        raising=False,
    )

    with pytest.raises(
        S.OwnedProcessScopeError,
        match="injected integrity failure",
    ):
        scope.attach(process)

    # MIC failed while the exact thread was still suspended, so the scope
    # remains a created-but-never-attached process eligible for exact cleanup.
    assert scope.attached is False
    assert scope.process_creation_state == "PROCESS_CREATED"
    scope.terminate_created_process(timeout_seconds=1)
    assert scope.created_process_termination_proven is True

    def prove_population_zero() -> None:
        scope._population_zero = True

    monkeypatch.setattr(scope, "_wait_windows_population_zero", prove_population_zero)
    scope.close()

    assert scope.closed is True
    assert scope.population_zero_proven is True
    assert lease_releases == 1


def test_windows_emergency_recovery_releases_only_after_exact_job_zero(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scope = _bare_scope()
    scope._job_handle = 123
    scope._population_zero = False
    scope._terminated = False
    scope._emergency_closed = False
    release_calls = 0
    quarantine_calls = 0

    class _Lease:
        def release_after_proven_closure(self) -> None:
            nonlocal release_calls
            release_calls += 1

        def quarantine_after_emergency_close(self) -> None:
            nonlocal quarantine_calls
            quarantine_calls += 1

    class _Call:
        argtypes: list[Any] = []
        restype: Any = None

        def __init__(self, result: int) -> None:
            self.result = result
            self.calls = 0

        def __call__(self, *_args: Any) -> int:
            self.calls += 1
            return self.result

    class _Kernel:
        TerminateJobObject = _Call(1)
        CloseHandle = _Call(1)

    kernel = _Kernel()
    scope._windows_write_lease = _Lease()
    _simulate_platform(monkeypatch, "nt")
    monkeypatch.setattr(
        S.ctypes,
        "WinDLL",
        lambda *_a, **_k: kernel,
        raising=False,
    )

    def prove_population_zero() -> None:
        assert kernel.TerminateJobObject.calls == 1
        assert kernel.CloseHandle.calls == 0
        scope._population_zero = True

    monkeypatch.setattr(scope, "_wait_windows_population_zero", prove_population_zero)

    scope.emergency_close()

    assert kernel.TerminateJobObject.calls == 1
    assert kernel.CloseHandle.calls == 1
    assert scope.terminated is True
    assert scope.population_zero_proven is True
    assert scope.emergency_closed is True
    assert scope.closed is True
    assert release_calls == 1
    assert quarantine_calls == 0


@pytest.mark.parametrize("failure_mode", ("terminate", "observation"))
def test_windows_emergency_ambiguity_closes_job_but_retains_quarantined_lease(
    failure_mode: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scope = _bare_scope()
    scope._job_handle = 123
    scope._population_zero = False
    scope._terminated = False
    scope._emergency_closed = False
    release_calls = 0
    quarantine_calls = 0

    class _Lease:
        def release_after_proven_closure(self) -> None:
            nonlocal release_calls
            release_calls += 1

        def quarantine_after_emergency_close(self) -> None:
            nonlocal quarantine_calls
            quarantine_calls += 1

    class _Call:
        argtypes: list[Any] = []
        restype: Any = None

        def __init__(self, result: int) -> None:
            self.result = result
            self.calls = 0

        def __call__(self, *_args: Any) -> int:
            self.calls += 1
            return self.result

    class _Kernel:
        TerminateJobObject = _Call(0 if failure_mode == "terminate" else 1)
        CloseHandle = _Call(1)

    kernel = _Kernel()
    scope._windows_write_lease = _Lease()
    _simulate_platform(monkeypatch, "nt")
    monkeypatch.setattr(
        S.ctypes,
        "WinDLL",
        lambda *_a, **_k: kernel,
        raising=False,
    )

    def observe_population_zero() -> None:
        if failure_mode == "observation":
            raise S.OwnedProcessScopeError(
                "injected Job population observation failure"
            )
        pytest.fail("population observation followed failed termination")

    monkeypatch.setattr(
        scope,
        "_wait_windows_population_zero",
        observe_population_zero,
    )

    scope.emergency_close()

    assert kernel.TerminateJobObject.calls == 1
    assert kernel.CloseHandle.calls == 1
    assert scope.population_zero_proven is False
    assert scope.emergency_closed is True
    assert scope.closed is True
    assert release_calls == 0
    assert quarantine_calls == 1


@pytest.mark.skipif(
    not _LIVE_WINDOWS_PY312,
    reason="requires live Windows with the supported CPython 3.12 transport",
)
@pytest.mark.parametrize(
    "boundary",
    (
        "ATTRIBUTE_LIST_INITIALIZED",
        "JOB_ATTRIBUTE_SET",
        "HANDLE_ATTRIBUTE_SET",
        "CREATE_RETURNED",
    ),
)
def test_windows_real_hard_crash_at_native_boundary_has_no_orphan_or_child_code(
    tmp_path: Path,
    boundary: str,
) -> None:
    pid_path = tmp_path / f"{boundary}.pid"
    marker_path = tmp_path / f"{boundary}.child-ran"
    module_root = Path(S.__file__).resolve().parent
    parent_code = "\n".join(
        (
            "import os",
            "from pathlib import Path",
            "import subprocess",
            "import sys",
            f"sys.path.insert(0, {str(module_root)!r})",
            "import owned_process_scope as S",
            "native_create = S._windows_create_process_in_job",
            "def injected_create(**kwargs):",
            "    def crash(name, process_info):",
            f"        if name != {boundary!r}:",
            "            return",
            (
                "        value = ('NONE' if process_info is None else "
                "str(int(process_info.dwProcessId)))"
            ),
            f"        target = Path({str(pid_path)!r})",
            "        with target.open('w', encoding='ascii') as stream:",
            "            stream.write(value)",
            "            stream.flush()",
            "            os.fsync(stream.fileno())",
            "        os._exit(92)",
            "    kwargs['_boundary_hook'] = crash",
            "    return native_create(**kwargs)",
            "S._windows_create_process_in_job = injected_create",
            "scope = S.OwnedProcessScope(windows_job_only=True)",
            "physical = scope.wrap_argv((",
            "    sys.executable, '-I', '-S', '-c',",
            (
                "    "
                + repr(
                    "from pathlib import Path; "
                    f"Path({str(marker_path)!r}).write_text('ran'); "
                    "import time; time.sleep(60)"
                )
                + ","
            ),
            "))",
            "scope.create_process(",
            "    physical,",
            "    stdin=subprocess.DEVNULL,",
            "    stdout=subprocess.DEVNULL,",
            "    stderr=subprocess.DEVNULL,",
            "    shell=False,",
            "    **scope.popen_kwargs(),",
            ")",
            "raise AssertionError('crash boundary was not reached')",
        )
    )

    result = subprocess.run(
        [sys.executable, "-I", "-S", "-c", parent_code],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        timeout=20,
        check=False,
    )
    assert result.returncode == 92, result.stderr.decode(
        "utf-8", errors="replace"
    )
    observed = pid_path.read_text(encoding="ascii")
    child_pid = None if observed == "NONE" else int(observed)
    try:
        if child_pid is not None:
            deadline = time.monotonic() + 5
            while (
                _windows_process_is_running(child_pid)
                and time.monotonic() < deadline
            ):
                time.sleep(0.01)
            assert _windows_process_is_running(child_pid) is False
        assert marker_path.exists() is False
    finally:
        if child_pid is not None and _windows_process_is_running(child_pid):
            _terminate_exact_windows_fixture_process(child_pid)


@pytest.mark.skipif(
    not _LIVE_WINDOWS_PY312,
    reason="requires live Windows with the supported CPython 3.12 transport",
)
def test_windows_hard_crash_after_create_return_leaves_no_orphan_and_runs_no_child(
    tmp_path: Path,
) -> None:
    pid_path = tmp_path / "created.pid"
    marker_path = tmp_path / "child-ran.txt"
    module_root = Path(S.__file__).resolve().parent
    parent_code = "\n".join(
        (
            "import os",
            "from pathlib import Path",
            "import subprocess",
            "import sys",
            f"sys.path.insert(0, {str(module_root)!r})",
            "from owned_process_scope import OwnedProcessScope",
            "scope = OwnedProcessScope()",
            "physical = scope.wrap_argv((",
            "    sys.executable, '-I', '-S', '-c',",
            (
                "    "
                + repr(
                    "from pathlib import Path; "
                    f"Path({str(marker_path)!r}).write_text('ran'); "
                    "import time; time.sleep(60)"
                )
                + ","
            ),
            "))",
            "created = scope.create_process(",
            "    physical,",
            "    stdin=subprocess.DEVNULL,",
            "    stdout=subprocess.DEVNULL,",
            "    stderr=subprocess.DEVNULL,",
            "    shell=False,",
            "    **scope.popen_kwargs(),",
            ")",
            f"pid_file = Path({str(pid_path)!r})",
            "with pid_file.open('w', encoding='ascii') as stream:",
            "    stream.write(str(created.pid))",
            "    stream.flush()",
            "    os.fsync(stream.fileno())",
            "os._exit(91)",
        )
    )

    result = subprocess.run(
        [sys.executable, "-I", "-S", "-c", parent_code],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        timeout=20,
        check=False,
    )
    assert result.returncode == 91, result.stderr.decode(
        "utf-8",
        errors="replace",
    )
    child_pid = int(pid_path.read_text(encoding="ascii"))
    try:
        deadline = time.monotonic() + 5
        while (
            _windows_process_is_running(child_pid)
            and time.monotonic() < deadline
        ):
            time.sleep(0.01)
        assert _windows_process_is_running(child_pid) is False
        assert marker_path.exists() is False
    finally:
        if _windows_process_is_running(child_pid):
            _terminate_exact_windows_fixture_process(child_pid)


def test_attach_failure_after_return_stays_created_not_prelaunch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scope = _bare_scope()
    process = _FakeProcess(pid=102)
    scope.create_process(("C:/trusted/claude.exe",), popen_factory=lambda *_a, **_k: process)
    _simulate_platform(monkeypatch, "posix")

    def fail_getpgid(_pid: int) -> int:
        raise OSError("injected attach observation failure")

    monkeypatch.setattr(S.os, "getpgid", fail_getpgid, raising=False)
    with pytest.raises(
        S.OwnedProcessScopeError,
        match="cannot observe provider process group",
    ):
        scope.attach(process)

    assert scope.process_creation_state == "PROCESS_CREATED"
    assert scope.process_creation_evidence["process_object_returned"] is True


def test_successful_attach_is_monotonic_and_foreign_attach_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scope = _bare_scope()
    process = _FakeProcess(pid=103)
    foreign = _FakeProcess(pid=103)
    scope.create_process(("C:/trusted/claude.exe",), popen_factory=lambda *_a, **_k: process)
    _simulate_platform(monkeypatch, "posix")
    monkeypatch.setattr(S.os, "getpgid", lambda pid: pid, raising=False)

    with pytest.raises(
        S.OwnedProcessScopeError,
        match="not created by this process scope",
    ):
        scope.attach(foreign)

    scope.attach(process)
    assert scope.process_creation_state == "ATTACHED"
    assert scope.process_creation_evidence == {
        "state": "ATTACHED",
        "creation_attempted": True,
        "process_object_returned": True,
        "attached": True,
        "created_process_termination_proven": False,
    }

    with pytest.raises(
        S.OwnedProcessScopeError,
        match="process scope cannot be attached",
    ):
        scope.attach(process)
    assert scope.process_creation_state == "ATTACHED"


def test_attach_before_creation_is_rejected_without_changing_state() -> None:
    scope = _bare_scope()

    with pytest.raises(
        S.OwnedProcessScopeError,
        match="not created by this process scope",
    ):
        scope.attach(_FakeProcess(pid=105))

    assert scope.process_creation_state == "NOT_ATTEMPTED"
    assert scope.process_creation_evidence["creation_attempted"] is False


def test_second_creation_and_creation_after_close_are_rejected() -> None:
    scope = _bare_scope()
    process = _FakeProcess(pid=104)
    calls = 0

    def create(*_args: Any, **_kwargs: Any) -> _FakeProcess:
        nonlocal calls
        calls += 1
        return process

    scope.create_process(("C:/trusted/claude.exe",), popen_factory=create)
    with pytest.raises(
        S.OwnedProcessScopeError,
        match="process creation was already attempted",
    ):
        scope.create_process(("C:/trusted/claude.exe",), popen_factory=create)
    assert calls == 1
    assert scope.process_creation_state == "PROCESS_CREATED"

    fresh = _bare_scope()
    fresh._closed = True
    with pytest.raises(
        S.OwnedProcessScopeError,
        match="closed process scope",
    ):
        fresh.create_process(("C:/trusted/claude.exe",), popen_factory=create)
    assert calls == 1
    assert fresh.process_creation_state == "NOT_ATTEMPTED"


def test_close_before_creation_preserves_not_attempted_evidence() -> None:
    scope = _bare_scope()

    scope.close()

    assert scope.closed is True
    assert scope.process_creation_state == "NOT_ATTEMPTED"
    assert scope.process_creation_evidence["creation_attempted"] is False


def test_public_state_and_evidence_cannot_reset_or_forge_authority() -> None:
    scope = _bare_scope()
    evidence = scope.process_creation_evidence
    evidence["state"] = "ATTACHED"
    evidence["created_process_termination_proven"] = True

    assert scope.process_creation_state == "NOT_ATTEMPTED"
    with pytest.raises(AttributeError):
        scope.process_creation_state = "ATTACHED"  # type: ignore[misc]
    with pytest.raises(AttributeError):
        scope.created_process_termination_proven = True  # type: ignore[misc]
    assert scope.process_creation_state == "NOT_ATTEMPTED"
    assert scope.created_process_termination_proven is False


def test_omitted_factory_calls_scope_module_popen(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scope = _bare_scope()
    process = _FakeProcess(pid=106)
    calls: list[tuple[str, ...]] = []

    def create(argv: list[str], **_kwargs: Any) -> _FakeProcess:
        calls.append(tuple(argv))
        return process

    monkeypatch.setattr(S.subprocess, "Popen", create)
    returned = scope.create_process(("C:/trusted/claude.exe", "-p"))

    assert returned is process
    assert calls == [("C:/trusted/claude.exe", "-p")]
    assert scope.process_creation_state == "PROCESS_CREATED"


def test_invalid_request_does_not_consume_creation_authority() -> None:
    scope = _bare_scope()

    with pytest.raises(
        S.OwnedProcessScopeError,
        match="non-empty physical argv",
    ):
        scope.create_process((), popen_factory=lambda *_a, **_k: None)

    assert scope.process_creation_state == "NOT_ATTEMPTED"
    assert scope.process_creation_evidence["creation_attempted"] is False


def test_created_process_cleanup_kills_waits_and_certifies_exact_process() -> None:
    scope = _bare_scope()
    process = _CleanupProcess(pid=107)
    scope.create_process(
        ("C:/trusted/claude.exe",),
        popen_factory=lambda *_a, **_k: process,
    )

    scope.terminate_created_process(timeout_seconds=1.5)

    assert process.kill_calls == 1
    assert process.wait_calls == 1
    assert scope.process_creation_state == "PROCESS_CREATED"
    assert scope.created_process_termination_proven is True
    assert scope.process_creation_evidence == {
        "state": "PROCESS_CREATED",
        "creation_attempted": True,
        "process_object_returned": True,
        "attached": False,
        "created_process_termination_proven": True,
    }
    mutated = scope.process_creation_evidence
    mutated["created_process_termination_proven"] = False
    assert scope.created_process_termination_proven is True

    # Monotonic and idempotent: the trusted exact-process operations are not
    # repeated once proof has been established.
    scope.terminate_created_process(timeout_seconds=1.5)
    assert process.kill_calls == 1
    assert process.wait_calls == 1


def test_created_process_cleanup_reaps_already_exited_exact_process() -> None:
    scope = _bare_scope()
    process = _CleanupProcess(pid=108, poll_result=0)
    scope.create_process(
        ("C:/trusted/claude.exe",),
        popen_factory=lambda *_a, **_k: process,
    )

    scope.terminate_created_process()

    assert process.kill_calls == 0
    assert process.wait_calls == 1
    assert scope.created_process_termination_proven is True


def test_real_created_process_cleanup_is_cross_platform_and_close_safe() -> None:
    scope = S.OwnedProcessScope()
    process: subprocess.Popen[bytes] | None = None
    try:
        physical = scope.wrap_argv(
            (
                sys.executable,
                "-I",
                "-S",
                "-c",
                "import time; time.sleep(60)",
            )
        )
        process = scope.create_process(
            physical,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            shell=False,
            **scope.popen_kwargs(),
        )

        scope.terminate_created_process(timeout_seconds=5)
        assert process.poll() is not None
        assert scope.created_process_termination_proven is True
        assert scope.process_creation_state == "PROCESS_CREATED"
        scope.close()
        assert scope.closed is True
    finally:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait(timeout=5)
        if not scope.closed:
            scope.emergency_close()


@pytest.mark.parametrize(
    "process,match",
    (
        (
            _CleanupProcess(
                pid=109,
                wait_error=subprocess.TimeoutExpired("claude", 0.01),
            ),
            "did not exit",
        ),
        (
            _CleanupProcess(
                pid=110,
                kill_error=OSError("injected kill error"),
            ),
            "could not be killed",
        ),
    ),
)
def test_created_process_cleanup_timeout_or_error_never_mints_proof(
    process: _CleanupProcess,
    match: str,
) -> None:
    scope = _bare_scope()
    scope.create_process(
        ("C:/trusted/claude.exe",),
        popen_factory=lambda *_a, **_k: process,
    )

    with pytest.raises(S.OwnedProcessScopeError, match=match):
        scope.terminate_created_process(timeout_seconds=0.01)

    assert scope.created_process_termination_proven is False
    assert (
        scope.process_creation_evidence[
            "created_process_termination_proven"
        ]
        is False
    )


def test_created_process_cleanup_without_exact_process_is_rejected() -> None:
    scope = _bare_scope()

    with pytest.raises(
        S.OwnedProcessScopeError,
        match="no exact created process",
    ):
        scope.terminate_created_process()

    assert scope.process_creation_state == "NOT_ATTEMPTED"
    assert scope.created_process_termination_proven is False
