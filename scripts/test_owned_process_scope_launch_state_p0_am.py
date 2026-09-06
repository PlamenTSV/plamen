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

import pytest

import owned_process_scope as S


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
    process = _FakeProcess(pid=111)
    process._handle = 456  # type: ignore[attr-defined]
    events: list[str] = []

    _simulate_platform(monkeypatch, "nt")
    monkeypatch.setattr(
        scope,
        "_assign_windows_created_process_to_job",
        lambda exact: events.append(
            "job-owned" if exact is process else "foreign-process"
        ),
        raising=False,
    )

    returned = scope.create_process(
        ("C:/trusted/claude.exe", "-p"),
        popen_factory=lambda *_a, **_k: process,
        creationflags=S._CREATE_SUSPENDED,
    )

    assert returned is process
    assert events == ["job-owned"]
    assert scope._windows_job_owned_suspended is True
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
            popen_factory=create,
            creationflags=0,
        )

    assert factory_calls == 0
    assert scope.process_creation_state == "NOT_ATTEMPTED"
    assert scope.process_creation_evidence["creation_attempted"] is False


def test_windows_assignment_failure_kills_and_reaps_exact_created_process(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scope = _bare_scope()
    scope._job_handle = 123
    process = _CleanupProcess(pid=113)
    process._handle = 456  # type: ignore[attr-defined]

    _simulate_platform(monkeypatch, "nt")

    def fail_assignment(_exact: _CleanupProcess) -> None:
        raise S.OwnedProcessScopeError("injected Job assignment failure")

    monkeypatch.setattr(
        scope,
        "_assign_windows_created_process_to_job",
        fail_assignment,
        raising=False,
    )

    with pytest.raises(
        S.OwnedProcessScopeError,
        match="could not be assigned to its Windows Job",
    ):
        scope.create_process(
            ("C:/trusted/claude.exe", "-p"),
            popen_factory=lambda *_a, **_k: process,
            creationflags=S._CREATE_SUSPENDED,
        )

    assert process.kill_calls == 1
    assert process.wait_calls == 1
    assert scope.process_creation_state == "PROCESS_CREATED"
    assert scope.created_process_termination_proven is True
    assert scope._windows_job_owned_suspended is False


def test_windows_attach_proves_existing_job_ownership_without_reassignment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scope = _bare_scope()
    scope._job_handle = 123
    scope._windows_job_owned_suspended = True
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
    monkeypatch.setattr(scope, "_resume_only_thread", lambda _pid: None)

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

    assert scope.attached is True
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
    os.name != "nt",
    reason="Windows Job kill-on-close hard-crash semantics are Windows-only",
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
