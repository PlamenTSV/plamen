"""Windows sibling-stage isolation fixtures for the temporary MIC lease.

These are real cross-process tests.  They intentionally exercise the fact that
two low-integrity tokens can otherwise write one another's low-labeled output
directories even though each process tree is correctly contained by its own
Job Object.
"""
from __future__ import annotations

import ctypes
import os
import json
from pathlib import Path
import subprocess
import sys
import threading
import time

import pytest

import windows_low_integrity_lease as W
from owned_process_scope import (
    OwnedProcessScope,
    OwnedProcessScopeError,
    process_tree_termination_capability,
)
from windows_low_integrity_lease import (
    LEASE_DIRECTORY_ENV,
    LEASE_TEST_OVERRIDE_ENV,
    WindowsLowIntegrityLeaseError,
    restore_windows_medium_integrity_tree,
    set_windows_low_integrity_root,
)


pytestmark = pytest.mark.skipif(
    sys.platform != "win32",
    reason="Windows mandatory-integrity control fixture",
)


_CREATE_SUSPENDED = 0x00000004
_JOB_OBJECT_BASIC_ACCOUNTING_INFORMATION = 1


class _JobBasicAccountingInformation(ctypes.Structure):
    _fields_ = [
        ("TotalUserTime", ctypes.c_int64),
        ("TotalKernelTime", ctypes.c_int64),
        ("ThisPeriodTotalUserTime", ctypes.c_int64),
        ("ThisPeriodTotalKernelTime", ctypes.c_int64),
        ("TotalPageFaultCount", ctypes.c_uint32),
        ("TotalProcesses", ctypes.c_uint32),
        ("ActiveProcesses", ctypes.c_uint32),
        ("TotalTerminatedProcesses", ctypes.c_uint32),
    ]


class _ProcessCleanupError(AssertionError):
    """Deterministic aggregate that keeps the earliest cleanup cause."""

    def __init__(
        self,
        context: str,
        failures: tuple[BaseException, ...] | list[BaseException],
    ) -> None:
        ordered = tuple(failures)
        if not ordered:
            raise ValueError("cleanup error requires at least one failure")
        self.context = context
        self.failures = ordered
        details = "; ".join(
            f"{type(exc).__name__}: {exc}" for exc in ordered
        )
        super().__init__(
            f"{context} failed with {len(ordered)} ordered error(s): {details}"
        )


class _WindowsOuterJob:
    """Medium-integrity test-only outer-process tree authority."""

    def __init__(self) -> None:
        if os.name != "nt":
            raise AssertionError("Windows outer Job is unavailable")
        self._handle = OwnedProcessScope._create_windows_job()
        self._closed = False
        self._assigned = False
        self._population_zero = False

    @staticmethod
    def _kernel32() -> ctypes.WinDLL:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.AssignProcessToJobObject.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
        ]
        kernel32.AssignProcessToJobObject.restype = ctypes.c_int
        kernel32.TerminateJobObject.argtypes = [
            ctypes.c_void_p,
            ctypes.c_uint32,
        ]
        kernel32.TerminateJobObject.restype = ctypes.c_int
        kernel32.QueryInformationJobObject.argtypes = [
            ctypes.c_void_p,
            ctypes.c_int,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_void_p,
        ]
        kernel32.QueryInformationJobObject.restype = ctypes.c_int
        kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
        kernel32.CloseHandle.restype = ctypes.c_int
        return kernel32

    def assign_and_resume(self, process: subprocess.Popen[bytes]) -> None:
        if self._closed:
            raise AssertionError("outer Job is already closed")
        process_handle = getattr(process, "_handle", None)
        if process_handle is None:
            raise AssertionError("outer process handle is unavailable")
        kernel32 = self._kernel32()
        if not kernel32.AssignProcessToJobObject(
            ctypes.c_void_p(self._handle),
            ctypes.c_void_p(int(process_handle)),
        ):
            raise OSError(
                ctypes.get_last_error(),
                "AssignProcessToJobObject failed",
            )
        self._assigned = True
        OwnedProcessScope._resume_only_thread(process.pid)

    def _active_processes(self) -> int:
        if self._closed:
            raise AssertionError("outer Job population cannot be re-observed")
        accounting = _JobBasicAccountingInformation()
        kernel32 = self._kernel32()
        if not kernel32.QueryInformationJobObject(
            ctypes.c_void_p(self._handle),
            _JOB_OBJECT_BASIC_ACCOUNTING_INFORMATION,
            ctypes.byref(accounting),
            ctypes.sizeof(accounting),
            None,
        ):
            raise OSError(
                ctypes.get_last_error(),
                "QueryInformationJobObject failed",
            )
        return int(accounting.ActiveProcesses)

    def terminate_and_reap(
        self,
        process: subprocess.Popen[bytes],
        *,
        timeout: float = 5.0,
    ) -> None:
        if self._closed:
            if process.poll() is None:
                raise AssertionError(
                    "closed outer Job retained a live parent process"
                )
            process.wait(timeout=timeout)
            return
        kernel32 = self._kernel32()
        if not kernel32.TerminateJobObject(
            ctypes.c_void_p(self._handle),
            1,
        ):
            raise OSError(
                ctypes.get_last_error(),
                "TerminateJobObject failed",
            )
        deadline = time.monotonic() + timeout
        while self._active_processes() != 0:
            if time.monotonic() >= deadline:
                raise subprocess.TimeoutExpired(
                    "Windows outer Job population",
                    timeout,
                )
            time.sleep(0.01)
        self._population_zero = True
        process.wait(timeout=timeout)
        if process.poll() is None:
            raise AssertionError("outer process did not exit after Job kill")
        if not kernel32.CloseHandle(ctypes.c_void_p(self._handle)):
            raise OSError(ctypes.get_last_error(), "CloseHandle(Job) failed")
        self._closed = True
        self._handle = 0

    def close_empty(self) -> None:
        if self._closed:
            return
        if self._active_processes() != 0:
            raise AssertionError("cannot close a populated outer Job as empty")
        kernel32 = self._kernel32()
        if not kernel32.CloseHandle(ctypes.c_void_p(self._handle)):
            raise OSError(ctypes.get_last_error(), "CloseHandle(Job) failed")
        self._closed = True
        self._handle = 0
        self._population_zero = True

    @property
    def population_zero_proven(self) -> bool:
        return self._population_zero

    @property
    def assigned(self) -> bool:
        return self._assigned

    @property
    def closed(self) -> bool:
        return self._closed


class _TestProcessGuard:
    """Reap every exact helper even when a fixture assertion is interrupted."""

    def __init__(self) -> None:
        self._scopes: list[
            tuple[OwnedProcessScope, subprocess.Popen[bytes]]
        ] = []
        self._outer: list[
            tuple[_WindowsOuterJob, subprocess.Popen[bytes]]
        ] = []

    def track_scope(
        self,
        scope: OwnedProcessScope,
        process: subprocess.Popen[bytes],
    ) -> None:
        self._scopes.append((scope, process))

    def release_scope(
        self,
        scope: OwnedProcessScope,
        process: subprocess.Popen[bytes],
    ) -> None:
        try:
            self._scopes.remove((scope, process))
        except ValueError:
            pass

    def track_outer(
        self,
        job: _WindowsOuterJob,
        process: subprocess.Popen[bytes],
    ) -> subprocess.Popen[bytes]:
        self._outer.append((job, process))
        return process

    def release_outer(
        self,
        job: _WindowsOuterJob,
        process: subprocess.Popen[bytes],
    ) -> None:
        try:
            self._outer.remove((job, process))
        except ValueError:
            pass

    @staticmethod
    def _kill_and_reap(
        process: subprocess.Popen[bytes],
        *,
        timeout: float = 5.0,
    ) -> None:
        errors: list[BaseException] = []
        try:
            running = process.poll() is None
        except BaseException as exc:
            errors.append(exc)
            running = True
        if running:
            try:
                process.terminate()
            except BaseException as exc:
                errors.append(exc)
            try:
                process.wait(timeout=timeout)
            except BaseException as exc:
                errors.append(exc)
                try:
                    process.kill()
                except BaseException as kill_exc:
                    errors.append(kill_exc)
                try:
                    process.wait(timeout=timeout)
                except BaseException as wait_exc:
                    errors.append(wait_exc)
        else:
            try:
                process.wait(timeout=timeout)
            except BaseException as exc:
                errors.append(exc)
        try:
            exited = process.poll() is not None
        except BaseException as exc:
            errors.append(exc)
            exited = False
        if not exited:
            errors.append(
                AssertionError(
                    f"exact helper {getattr(process, 'pid', '?')} remains live"
                )
            )
        if errors:
            aggregate = _ProcessCleanupError("exact-process reap", errors)
            raise aggregate from errors[0]

    def cleanup_scope(
        self,
        scope: OwnedProcessScope,
        process: subprocess.Popen[bytes],
    ) -> None:
        errors: list[BaseException] = []
        state = ""
        try:
            state = scope.process_creation_state
            if state == "PROCESS_CREATED":
                scope.terminate_created_process(timeout_seconds=5.0)
                scope.close()
            elif state == "ATTACHED":
                if not scope.terminated:
                    scope.terminate()
                process.wait(timeout=5)
                scope.close()
            else:
                self._kill_and_reap(process)
                scope.emergency_close()
        except BaseException as exc:
            errors.append(exc)
            try:
                scope.emergency_close()
            except BaseException as emergency_exc:
                errors.append(emergency_exc)
            try:
                self._kill_and_reap(process)
            except _ProcessCleanupError as reap_exc:
                errors.extend(reap_exc.failures)
            except BaseException as reap_exc:
                errors.append(reap_exc)
        try:
            process_exited = process.poll() is not None
        except BaseException as exc:
            errors.append(exc)
            process_exited = False
        if state == "ATTACHED":
            try:
                tree_quiescent = bool(scope.population_zero_proven)
            except BaseException as exc:
                errors.append(exc)
                tree_quiescent = False
        else:
            tree_quiescent = process_exited
        exact_quiescence = process_exited and tree_quiescent
        if exact_quiescence:
            self.release_scope(scope, process)
        else:
            errors.append(
                AssertionError(
                f"owned helper {process.pid} survived fixture cleanup"
                )
            )
        if errors:
            aggregate = _ProcessCleanupError("owned helper cleanup", errors)
            raise aggregate from errors[0]

    def cleanup(self) -> None:
        errors: list[BaseException] = []
        for scope, process in reversed(tuple(self._scopes)):
            try:
                self.cleanup_scope(scope, process)
            except BaseException as exc:
                errors.append(exc)
        for job, process in reversed(tuple(self._outer)):
            try:
                self.cleanup_outer(job, process)
            except BaseException as exc:
                errors.append(exc)
        if errors:
            aggregate = _ProcessCleanupError(
                "test helper cleanup",
                errors,
            )
            raise aggregate from errors[0]

    def cleanup_outer(
        self,
        job: _WindowsOuterJob,
        process: subprocess.Popen[bytes],
    ) -> None:
        """Quiesce one outer helper from either side of Job assignment."""

        errors: list[BaseException] = []
        if job.assigned:
            try:
                job.terminate_and_reap(process)
            except BaseException as exc:
                errors.append(exc)
        else:
            try:
                self._kill_and_reap(process)
            except _ProcessCleanupError as exc:
                errors.extend(exc.failures)
            except BaseException as exc:
                errors.append(exc)
            try:
                job.close_empty()
            except BaseException as exc:
                errors.append(exc)

        try:
            process_exited = process.poll() is not None
        except BaseException as exc:
            errors.append(exc)
            process_exited = False
        try:
            job_quiescent = job.closed and job.population_zero_proven
        except BaseException as exc:
            errors.append(exc)
            job_quiescent = False

        if process_exited and job_quiescent:
            self.release_outer(job, process)
        else:
            errors.append(
                AssertionError(
                    f"outer helper tree {process.pid} survived cleanup"
                )
            )
        if errors:
            aggregate = _ProcessCleanupError(
                "outer helper cleanup",
                errors,
            )
            raise aggregate from errors[0]


_ACTIVE_PROCESS_GUARD: _TestProcessGuard | None = None


@pytest.fixture(autouse=True)
def _reap_exact_test_helpers() -> None:
    global _ACTIVE_PROCESS_GUARD
    assert _ACTIVE_PROCESS_GUARD is None
    guard = _TestProcessGuard()
    _ACTIVE_PROCESS_GUARD = guard
    try:
        yield
    finally:
        try:
            guard.cleanup()
        finally:
            _ACTIVE_PROCESS_GUARD = None


def _process_guard() -> _TestProcessGuard:
    if _ACTIVE_PROCESS_GUARD is None:
        raise AssertionError("test process guard is unavailable")
    return _ACTIVE_PROCESS_GUARD


def _start_owned(scope: OwnedProcessScope, code: str) -> subprocess.Popen[bytes]:
    process = scope.create_process(
        scope.wrap_argv((sys.executable, "-I", "-S", "-c", code)),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        shell=False,
        **scope.popen_kwargs(),
    )
    guard = _process_guard()
    guard.track_scope(scope, process)
    try:
        scope.attach(process)
    except BaseException:
        guard.cleanup_scope(scope, process)
        raise
    return process


def _close_owned(
    scope: OwnedProcessScope,
    process: subprocess.Popen[bytes],
) -> None:
    scope.terminate()
    process.wait(timeout=5)
    scope.close()
    _process_guard().release_scope(scope, process)


def _start_outer(
    argv: list[str],
    **kwargs: object,
) -> subprocess.Popen[bytes]:
    job = _WindowsOuterJob()
    guard = _process_guard()
    process: subprocess.Popen[bytes] | None = None
    try:
        creationflags = kwargs.pop("creationflags", 0)
        if (
            isinstance(creationflags, bool)
            or not isinstance(creationflags, int)
        ):
            raise AssertionError("outer creationflags must be an integer")
        kwargs["creationflags"] = (
            creationflags
            | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
            | _CREATE_SUSPENDED
        )
        process = subprocess.Popen(argv, **kwargs)
        guard.track_outer(job, process)
        job.assign_and_resume(process)
    except BaseException as exc:
        cleanup_errors: list[BaseException] = [exc]
        if process is None:
            try:
                job.close_empty()
            except BaseException as cleanup_exc:
                cleanup_errors.append(cleanup_exc)
        else:
            try:
                guard.cleanup_outer(job, process)
            except _ProcessCleanupError as cleanup_exc:
                cleanup_errors.extend(cleanup_exc.failures)
            except BaseException as cleanup_exc:
                cleanup_errors.append(cleanup_exc)
        if len(cleanup_errors) > 1:
            aggregate = _ProcessCleanupError(
                "outer helper startup",
                cleanup_errors,
            )
            raise aggregate from exc
        raise
    assert process is not None
    return process


def _windows_process_is_alive(process_id: int) -> bool:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.argtypes = [
        ctypes.c_uint32,
        ctypes.c_int,
        ctypes.c_uint32,
    ]
    kernel32.OpenProcess.restype = ctypes.c_void_p
    kernel32.GetExitCodeProcess.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_uint32),
    ]
    kernel32.GetExitCodeProcess.restype = ctypes.c_int
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel32.CloseHandle.restype = ctypes.c_int
    handle = kernel32.OpenProcess(0x1000, False, process_id)
    if not handle:
        return False
    try:
        code = ctypes.c_uint32()
        if not kernel32.GetExitCodeProcess(handle, ctypes.byref(code)):
            return False
        return code.value == 259
    finally:
        kernel32.CloseHandle(handle)


def test_attach_failure_kills_and_reaps_exact_created_process(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An exception between create and attach cannot strand a suspended child."""

    _isolated_lease(tmp_path, monkeypatch)
    root = tmp_path / "attach-failure"
    root.mkdir()
    scope = OwnedProcessScope(writable_roots=(root,))
    created: list[subprocess.Popen[bytes]] = []
    original_create = scope.create_process

    def capture_create(
        physical_argv: list[str] | tuple[str, ...],
        **popen_kwargs: object,
    ) -> subprocess.Popen[bytes]:
        process = original_create(physical_argv, **popen_kwargs)
        created.append(process)
        return process

    def reject_attach(_process: subprocess.Popen[bytes]) -> None:
        raise OwnedProcessScopeError("injected attach failure")

    monkeypatch.setattr(scope, "create_process", capture_create)
    monkeypatch.setattr(scope, "attach", reject_attach)

    with pytest.raises(OwnedProcessScopeError, match="injected attach failure"):
        _start_owned(scope, "import time; time.sleep(30)")

    assert len(created) == 1
    assert created[0].poll() is not None
    assert scope.created_process_termination_proven is True
    assert scope.closed is True


def test_injected_assertion_failure_reaps_owned_descendant_tree(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Fixture assertion failure cleanup owns the helper's complete Job tree."""

    _isolated_lease(tmp_path, monkeypatch)
    root = tmp_path / "assertion-failure"
    root.mkdir()
    descendant_pid_path = root / "descendant.pid"
    scope = OwnedProcessScope(writable_roots=(root,))
    process = _start_owned(
        scope,
        (
            "from pathlib import Path\n"
            "import subprocess,sys,time\n"
            "child = subprocess.Popen([sys.executable, '-I', '-S', '-c', "
            "'import time; time.sleep(30)'], stdin=subprocess.DEVNULL, "
            "stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)\n"
            f"Path({str(descendant_pid_path)!r}).write_text(str(child.pid))\n"
            "time.sleep(30)\n"
        ),
    )
    deadline = time.monotonic() + 5
    while (
        not descendant_pid_path.exists()
        and time.monotonic() < deadline
    ):
        time.sleep(0.01)
    descendant_pid = int(descendant_pid_path.read_text(encoding="utf-8"))

    caught: AssertionError | None = None
    try:
        raise AssertionError("injected fixture assertion failure")
    except AssertionError as exc:
        caught = exc
    finally:
        _process_guard().cleanup_scope(scope, process)

    assert caught is not None
    assert process.poll() is not None
    assert _windows_process_is_alive(descendant_pid) is False


def test_injected_outer_timeout_is_killed_and_reaped() -> None:
    """A timed-out non-owned provider helper remains fixture-owned."""

    process = _start_outer(
        [sys.executable, "-I", "-S", "-c", "import time; time.sleep(30)"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    with pytest.raises(subprocess.TimeoutExpired):
        process.wait(timeout=0.01)
    _process_guard().cleanup()
    assert process.poll() is not None


def test_missing_emergency_stop_signal_cannot_orphan_outer_provider(
    tmp_path: Path,
) -> None:
    """Failure to send a cooperative stop still triggers forced fixture cleanup."""

    ready = tmp_path / "provider.ready"
    stop = tmp_path / "provider.stop"
    process = _start_outer(
        [
            sys.executable,
            "-I",
            "-S",
            "-c",
            (
                "from pathlib import Path\n"
                "import time\n"
                f"ready = Path({str(ready)!r})\n"
                f"stop = Path({str(stop)!r})\n"
                "ready.write_text('ready')\n"
                "while not stop.exists():\n"
                " time.sleep(0.01)\n"
            ),
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    deadline = time.monotonic() + 5
    while not ready.exists() and time.monotonic() < deadline:
        time.sleep(0.01)
    assert ready.read_text(encoding="utf-8") == "ready"
    assert not stop.exists()

    _process_guard().cleanup()
    assert process.poll() is not None


def test_outer_cleanup_reaps_descendant_tree_immediately(
    tmp_path: Path,
) -> None:
    """The test-only outer Job, not a child timer, proves tree quiescence."""

    descendant_pid_path = tmp_path / "outer-descendant.pid"
    process = _start_outer(
        [
            sys.executable,
            "-I",
            "-S",
            "-c",
            (
                "from pathlib import Path\n"
                "import subprocess,sys,time\n"
                "child = subprocess.Popen([sys.executable, '-I', '-S', '-c', "
                "'import time; time.sleep(30)'], stdin=subprocess.DEVNULL, "
                "stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)\n"
                f"Path({str(descendant_pid_path)!r}).write_text(str(child.pid))\n"
                "time.sleep(30)\n"
            ),
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    deadline = time.monotonic() + 5
    while (
        not descendant_pid_path.exists()
        and time.monotonic() < deadline
    ):
        time.sleep(0.01)
    descendant_pid = int(descendant_pid_path.read_text(encoding="utf-8"))
    assert _windows_process_is_alive(descendant_pid) is True

    _process_guard().cleanup()

    assert process.poll() is not None
    assert _windows_process_is_alive(descendant_pid) is False
    assert _process_guard()._outer == []


def test_uncaught_nested_pytest_assertion_reaps_tracked_descendant_tree(
    tmp_path: Path,
) -> None:
    """Exercise the real pytest body-failure -> autouse-teardown sequence."""

    scripts_dir = Path(__file__).resolve().parent
    nested_test = tmp_path / "test_nested_uncaught_cleanup.py"
    nested_basetemp = tmp_path / "nested-pytest-temp"
    descendant_pid_path = tmp_path / "nested-descendant.pid"
    nested_test.write_text(
        (
            "from pathlib import Path\n"
            "import subprocess,sys,time\n"
            "import pytest\n"
            f"sys.path.insert(0, {str(scripts_dir)!r})\n"
            "import test_windows_low_integrity_lease_p0_am as H\n"
            "\n"
            "@pytest.fixture(autouse=True)\n"
            "def exact_guard():\n"
            " generator = H._reap_exact_test_helpers.__wrapped__()\n"
            " next(generator)\n"
            " try:\n"
            "  yield\n"
            " finally:\n"
            "  try:\n"
            "   next(generator)\n"
            "  except StopIteration:\n"
            "   pass\n"
            "\n"
            "def test_uncaught():\n"
            " process = H._start_outer(\n"
            "  [sys.executable, '-I', '-S', '-c',\n"
            "   \"from pathlib import Path\\n\"\n"
            "   \"import subprocess,sys,time\\n\"\n"
            "   \"child = subprocess.Popen([sys.executable, '-I', '-S', "
            "'-c', 'import time; time.sleep(30)'], "
            "stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, "
            "stderr=subprocess.DEVNULL)\\n\"\n"
            f"   \"Path({descendant_pid_path.as_posix()!r}).write_text(str(child.pid))\\n\"\n"
            "   \"time.sleep(30)\\n\"],\n"
            "  stdin=subprocess.DEVNULL,\n"
            "  stdout=subprocess.DEVNULL,\n"
            "  stderr=subprocess.DEVNULL,\n"
            " )\n"
            " deadline = time.monotonic() + 5\n"
            f" marker = Path({str(descendant_pid_path)!r})\n"
            " while not marker.exists() and time.monotonic() < deadline:\n"
            "  time.sleep(0.01)\n"
            " assert process.poll() is None\n"
            " raise AssertionError('ORIGINAL-NESTED-BODY-FAILURE')\n"
        ),
        encoding="utf-8",
        newline="\n",
    )
    nested_environment = dict(os.environ)
    nested_environment["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
    stdout_path = tmp_path / "nested.stdout"
    stderr_path = tmp_path / "nested.stderr"
    with stdout_path.open("wb") as stdout_file, stderr_path.open(
        "wb"
    ) as stderr_file:
        nested = subprocess.Popen(
            [
                sys.executable,
                "-c",
                (
                    "import pytest\n"
                    "raise SystemExit(pytest.main(["
                        "'-s','-q','-p','no:cacheprovider',"
                        f"'--rootdir={tmp_path.as_posix()}',"
                        f"'--basetemp={nested_basetemp.as_posix()}',"
                    f"{nested_test.as_posix()!r}]))\n"
                ),
            ],
            stdin=subprocess.DEVNULL,
            stdout=stdout_file,
            stderr=stderr_file,
            cwd=str(tmp_path),
            env=nested_environment,
        )
        try:
            nested.wait(timeout=20)
        except subprocess.TimeoutExpired as exc:
            nested.kill()
            nested.wait(timeout=5)
            stdout_file.flush()
            stderr_file.flush()
            raise AssertionError(
                "nested pytest teardown timed out:\n"
                + stdout_path.read_text(
                    encoding="utf-8",
                    errors="replace",
                )
                + stderr_path.read_text(
                    encoding="utf-8",
                    errors="replace",
                )
            ) from exc
    stdout = stdout_path.read_bytes()
    stderr = stderr_path.read_bytes()
    assert nested.returncode == 1, (
        stdout.decode(errors="replace"),
        stderr.decode(errors="replace"),
    )
    output = (stdout + stderr).decode(errors="replace")
    assert "ORIGINAL-NESTED-BODY-FAILURE" in output
    descendant_pid = int(
        descendant_pid_path.read_text(encoding="utf-8")
    )
    assert _windows_process_is_alive(descendant_pid) is False


def test_outer_job_kill_on_owner_death_reaps_live_helper(
    tmp_path: Path,
) -> None:
    """Abrupt owner death closes the non-inheritable kill-on-close Job."""

    scripts_dir = Path(__file__).resolve().parent
    helper_pid_path = tmp_path / "hard-exit-helper.pid"
    launcher = _start_outer(
        [
            sys.executable,
            "-c",
            (
                "import os,sys,time\n"
                "from pathlib import Path\n"
                f"sys.path.insert(0, {str(scripts_dir)!r})\n"
                "import test_windows_low_integrity_lease_p0_am as H\n"
                "H._ACTIVE_PROCESS_GUARD = H._TestProcessGuard()\n"
                "inner = H._start_outer(\n"
                " [sys.executable, '-I', '-S', '-c', "
                f"\"import os,time; from pathlib import Path; "
                f"Path({helper_pid_path.as_posix()!r}).write_text(str(os.getpid())); "
                "time.sleep(30)\"],\n"
                " stdin=H.subprocess.DEVNULL,\n"
                " stdout=H.subprocess.DEVNULL,\n"
                " stderr=H.subprocess.DEVNULL,\n"
                ")\n"
                "deadline = time.monotonic() + 5\n"
                f"marker = Path({str(helper_pid_path)!r})\n"
                "while not marker.exists() and time.monotonic() < deadline:\n"
                " time.sleep(0.01)\n"
                "if not marker.exists():\n"
                " raise RuntimeError("
                "'inner helper did not start; poll=' + repr(inner.poll()))\n"
                "os._exit(91)\n"
            ),
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    stdout, stderr = launcher.communicate(timeout=15)
    assert launcher.returncode == 91, (
        stdout.decode(errors="replace"),
        stderr.decode(errors="replace"),
    )
    helper_pid = int(helper_pid_path.read_text(encoding="utf-8"))
    deadline = time.monotonic() + 5
    while _windows_process_is_alive(helper_pid) and time.monotonic() < deadline:
        time.sleep(0.01)
    assert _windows_process_is_alive(helper_pid) is False


def test_cleanup_faults_preserve_order_and_retry_tracking() -> None:
    """Every failed cleanup operation remains ordered and retryable."""

    class _FailingProcess:
        pid = 424242

        def poll(self) -> None:
            return None

        def terminate(self) -> None:
            raise OSError("process-terminate-failed")

        def kill(self) -> None:
            raise OSError("process-kill-failed")

        def wait(self, *, timeout: float) -> None:
            raise subprocess.TimeoutExpired("process-wait", timeout)

    class _FailingScope:
        process_creation_state = "ATTACHED"
        terminated = False
        population_zero_proven = False

        def terminate(self) -> None:
            raise subprocess.TimeoutExpired("scope-terminate", 1)

        def emergency_close(self) -> None:
            raise OSError("scope-emergency-close-failed")

    guard = _TestProcessGuard()
    scope = _FailingScope()
    process = _FailingProcess()
    guard.track_scope(scope, process)  # type: ignore[arg-type]

    with pytest.raises(_ProcessCleanupError) as caught:
        guard.cleanup_scope(  # type: ignore[arg-type]
            scope,
            process,
        )

    failures = caught.value.failures
    assert isinstance(failures[0], subprocess.TimeoutExpired)
    assert "scope-terminate" in str(failures[0])
    assert "scope-emergency-close-failed" in str(failures[1])
    assert "process-terminate-failed" in str(failures[2])
    assert "process-wait" in str(failures[3])
    assert "process-kill-failed" in str(failures[4])
    assert caught.value.__cause__ is failures[0]
    assert guard._scopes == [(scope, process)]


def test_outer_cleanup_failure_retains_retry_authority() -> None:
    class _LiveProcess:
        pid = 525252

        def poll(self) -> None:
            return None

    class _FailingJob:
        assigned = True
        closed = False
        population_zero_proven = False

        def terminate_and_reap(
            self,
            process: object,
            *,
            timeout: float = 5.0,
        ) -> None:
            del process, timeout
            raise OSError("outer-job-terminate-failed")

    guard = _TestProcessGuard()
    job = _FailingJob()
    process = _LiveProcess()
    guard._outer.append((job, process))  # type: ignore[arg-type]

    with pytest.raises(_ProcessCleanupError) as caught:
        guard.cleanup()

    assert "outer-job-terminate-failed" in str(caught.value.failures[0])
    assert guard._outer == [(job, process)]


def test_outer_assignment_failure_retains_and_reaps_exact_suspended_process(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Create-to-Job-attach failure keeps exact retry authority."""

    captured: list[subprocess.Popen[bytes]] = []
    original_popen = subprocess.Popen
    original_reap = _TestProcessGuard._kill_and_reap

    def capture_popen(
        argv: list[str],
        **kwargs: object,
    ) -> subprocess.Popen[bytes]:
        process = original_popen(argv, **kwargs)
        captured.append(process)
        return process

    def reject_assignment(
        self: _WindowsOuterJob,
        process: subprocess.Popen[bytes],
    ) -> None:
        del self, process
        raise OSError("fixture-assign-failed")

    first_cleanup = True

    def fail_first_exact_reap(
        process: subprocess.Popen[bytes],
        *,
        timeout: float = 5.0,
    ) -> None:
        nonlocal first_cleanup
        del process, timeout
        if first_cleanup:
            first_cleanup = False
            raise OSError("fixture-first-reap-failed")
        raise AssertionError("unexpected patched reap retry")

    monkeypatch.setattr(subprocess, "Popen", capture_popen)
    monkeypatch.setattr(
        _WindowsOuterJob,
        "assign_and_resume",
        reject_assignment,
    )
    monkeypatch.setattr(
        _TestProcessGuard,
        "_kill_and_reap",
        staticmethod(fail_first_exact_reap),
    )

    with pytest.raises(_ProcessCleanupError) as caught:
        _start_outer(
            [
                sys.executable,
                "-I",
                "-S",
                "-c",
                "import time; time.sleep(30)",
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    assert "fixture-assign-failed" in str(caught.value.failures[0])
    assert "fixture-first-reap-failed" in str(caught.value.failures[1])
    assert len(captured) == 1
    process = captured[0]
    guard = _process_guard()
    assert _windows_process_is_alive(process.pid) is True
    assert len(guard._outer) == 1
    job, tracked_process = guard._outer[0]
    assert tracked_process is process
    assert job.assigned is False
    assert job.closed is True

    monkeypatch.setattr(
        _TestProcessGuard,
        "_kill_and_reap",
        staticmethod(original_reap),
    )
    guard.cleanup()

    assert _windows_process_is_alive(process.pid) is False
    assert guard._outer == []
    assert job.closed is True
    assert job.population_zero_proven is True


def _isolated_lease(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> Path:
    directory = tmp_path / "lease-authority"
    monkeypatch.setenv(LEASE_TEST_OVERRIDE_ENV, "1")
    monkeypatch.setenv(LEASE_DIRECTORY_ENV, str(directory))
    return directory


def test_concurrent_scope_cannot_write_active_sibling_stage(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """RED before the lease: the second low-IL worker writes ``stage_a``."""

    stage_a = tmp_path / "stage-a"
    stage_b = tmp_path / "stage-b"
    stage_a.mkdir()
    stage_b.mkdir()
    _isolated_lease(tmp_path, monkeypatch)
    sibling_marker = stage_a / "written-by-sibling.txt"

    scope_a = OwnedProcessScope(
        writable_roots=(stage_a,),
        persistent_identity=f"lease-a-{os.getpid()}",
    )
    process_a = _start_owned(
        scope_a,
        (
            "from pathlib import Path; import time; "
            f"Path({str(sibling_marker)!r}).write_text('owner'); "
            "time.sleep(30)"
        ),
    )
    deadline = time.monotonic() + 5
    while not sibling_marker.exists() and time.monotonic() < deadline:
        time.sleep(0.01)
    assert sibling_marker.read_text(encoding="utf-8") == "owner"

    scripts_dir = Path(__file__).resolve().parent
    contender = (
        "from pathlib import Path\n"
        "import subprocess,sys\n"
        f"sys.path.insert(0, {str(scripts_dir)!r})\n"
        "from owned_process_scope import OwnedProcessScope\n"
        f"stage = Path({str(stage_b)!r})\n"
        f"marker = Path({str(sibling_marker)!r})\n"
        "scope = OwnedProcessScope(writable_roots=(stage,), "
        f"persistent_identity='lease-b-{os.getpid()}')\n"
        "code = \"from pathlib import Path; \" + "
        "\"Path(\" + repr(str(marker)) + \").write_text('escaped')\"\n"
        "child = scope.create_process(scope.wrap_argv((sys.executable, '-I', "
        "'-S', '-c', code)), stdin=subprocess.DEVNULL, "
        "stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, "
        "shell=False, **scope.popen_kwargs())\n"
        "scope.attach(child)\n"
        "child.wait(timeout=5)\n"
        "scope.terminate()\n"
        "child.wait(timeout=5)\n"
        "scope.close()\n"
    )
    contender_process = _start_outer(
        [sys.executable, "-I", "-S", "-c", contender],
        cwd=scripts_dir,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
    )
    try:
        time.sleep(0.8)
        assert sibling_marker.read_text(encoding="utf-8") == "owner"
    finally:
        _close_owned(scope_a, process_a)

    stdout, stderr = contender_process.communicate(timeout=10)
    assert contender_process.returncode == 0, (
        stdout.decode(errors="replace"),
        stderr.decode(errors="replace"),
    )
    # The recursively restored file itself (not only its parent directory)
    # rejects the next low-integrity worker's overwrite.
    assert sibling_marker.read_text(encoding="utf-8") == "owner"


def test_same_provider_worker_threads_are_serialized(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _isolated_lease(tmp_path, monkeypatch)
    stage_a = tmp_path / "thread-a"
    stage_b = tmp_path / "thread-b"
    stage_a.mkdir()
    stage_b.mkdir()
    first = OwnedProcessScope(writable_roots=(stage_a,))
    first_process = _start_owned(first, "import time; time.sleep(30)")
    acquired = threading.Event()
    finished = threading.Event()
    errors: list[BaseException] = []

    def contender() -> None:
        try:
            second = OwnedProcessScope(writable_roots=(stage_b,))
            acquired.set()
            second.close()
        except BaseException as exc:
            errors.append(exc)
        finally:
            finished.set()

    thread = threading.Thread(target=contender, daemon=True)
    thread.start()
    time.sleep(0.4)
    assert not acquired.is_set()
    _close_owned(first, first_process)
    assert finished.wait(5)
    thread.join(timeout=1)
    assert not errors
    assert acquired.is_set()


def test_lease_wait_obeys_caller_deadline_and_then_allows_next_scope(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _isolated_lease(tmp_path, monkeypatch)
    stage_a = tmp_path / "deadline-a"
    stage_b = tmp_path / "deadline-b"
    stage_a.mkdir()
    stage_b.mkdir()
    first = OwnedProcessScope(writable_roots=(stage_a,))
    first_process = _start_owned(first, "import time; time.sleep(30)")
    started = time.monotonic()
    try:
        with pytest.raises(
            OwnedProcessScopeError,
            match="serialized Windows low-integrity scope",
        ) as caught:
            OwnedProcessScope(
                writable_roots=(stage_b,),
                lease_acquisition_deadline_monotonic=time.monotonic() + 0.20,
            )
        assert time.monotonic() - started < 1.5
        assert isinstance(caught.value.__cause__, WindowsLowIntegrityLeaseError)
        assert "deadline" in str(caught.value.__cause__)
    finally:
        _close_owned(first, first_process)

    next_scope = OwnedProcessScope(
        writable_roots=(stage_b,),
        lease_acquisition_deadline_monotonic=time.monotonic() + 2,
    )
    next_scope.close()


def test_lease_wait_obeys_caller_cancellation_without_damaging_holder(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _isolated_lease(tmp_path, monkeypatch)
    stage_a = tmp_path / "cancel-a"
    stage_b = tmp_path / "cancel-b"
    stage_a.mkdir()
    stage_b.mkdir()
    first = OwnedProcessScope(writable_roots=(stage_a,))
    first_process = _start_owned(first, "import time; time.sleep(30)")
    cancelled = threading.Event()
    finished = threading.Event()
    errors: list[BaseException] = []

    def contender() -> None:
        try:
            OwnedProcessScope(
                writable_roots=(stage_b,),
                lease_acquisition_deadline_monotonic=time.monotonic() + 5,
                lease_cancel_token=cancelled,
            )
        except BaseException as exc:
            errors.append(exc)
        finally:
            finished.set()

    thread = threading.Thread(target=contender, daemon=True)
    started = time.monotonic()
    thread.start()
    time.sleep(0.10)
    cancelled.set()
    assert finished.wait(1.5)
    assert time.monotonic() - started < 1.8
    assert len(errors) == 1
    assert isinstance(errors[0], OwnedProcessScopeError)
    assert isinstance(errors[0].__cause__, WindowsLowIntegrityLeaseError)
    assert "cancelled" in str(errors[0].__cause__)
    _close_owned(first, first_process)

    next_scope = OwnedProcessScope(writable_roots=(stage_b,))
    next_scope.close()


def test_default_namespace_ignores_mutable_localappdata_environment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Production authority comes from Known Folders, never LOCALAPPDATA."""

    known_local = tmp_path / "known-local"
    attacker_redirect = tmp_path / "attacker-local"
    known_local.mkdir()
    attacker_redirect.mkdir()
    monkeypatch.delenv(LEASE_DIRECTORY_ENV, raising=False)
    monkeypatch.delenv(LEASE_TEST_OVERRIDE_ENV, raising=False)
    monkeypatch.setenv("LOCALAPPDATA", str(attacker_redirect))
    monkeypatch.setattr(
        W,
        "_windows_known_folder_local_app_data",
        lambda: known_local,
        raising=False,
    )

    binding = W.lease_capability_binding()

    assert Path(binding["lock_path"]).is_relative_to(known_local)
    assert not Path(binding["lock_path"]).is_relative_to(attacker_redirect)
    assert binding["namespace_authority"] == (
        "WINDOWS_KNOWN_FOLDER_LOCAL_APP_DATA"
    )
    assert binding["namespace_limitation"] == (
        "SAME_USER_MEDIUM_INTEGRITY_MUTATION_OUT_OF_SCOPE"
    )


def test_test_override_cannot_claim_production_global_namespace(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _isolated_lease(tmp_path, monkeypatch)

    binding = W.lease_capability_binding()

    assert binding["namespace_authority"] == (
        "TEST_ONLY_EXPLICIT_DIRECTORY_OVERRIDE"
    )
    assert binding["namespace_limitation"] == (
        "TEST_OVERRIDE_NOT_PRODUCTION_AUTHORITY"
    )
    assert binding["scope"] == "TEST_PROCESS_EXPLICIT_NAMESPACE_ONLY"


def test_medium_source_canonical_and_inactive_sibling_are_protected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lease_directory = _isolated_lease(tmp_path, monkeypatch)
    owned = tmp_path / "owned"
    source = tmp_path / "source"
    canonical = tmp_path / "canonical"
    sibling = tmp_path / "inactive-sibling"
    for path in (owned, source, canonical, sibling):
        path.mkdir()
    result = owned / "result.json"
    targets = {
        "source": source / "forbidden.txt",
        "canonical": canonical / "forbidden.txt",
        "sibling": sibling / "forbidden.txt",
        "lease_state": lease_directory / "state.json",
        "owned": owned / "allowed.txt",
    }
    script = (
        "import json\n"
        "from pathlib import Path\n"
        f"targets = { {key: str(value) for key, value in targets.items()}!r}\n"
        "observed = {}\n"
        "for name, raw in targets.items():\n"
        "  try:\n"
        "    Path(raw).write_text(name, encoding='utf-8')\n"
        "    observed[name] = 'WRITTEN'\n"
        "  except OSError:\n"
        "    observed[name] = 'DENIED'\n"
        f"Path({str(result)!r}).write_text(json.dumps(observed), encoding='utf-8')\n"
    )

    scope = OwnedProcessScope(writable_roots=(owned,))
    process = _start_owned(scope, script)
    process.wait(timeout=5)
    _close_owned(scope, process)

    assert json.loads(result.read_text(encoding="utf-8")) == {
        "source": "DENIED",
        "canonical": "DENIED",
        "sibling": "DENIED",
        "lease_state": "DENIED",
        "owned": "WRITTEN",
    }
    assert targets["owned"].is_file()
    assert not targets["source"].exists()
    assert not targets["canonical"].exists()
    assert not targets["sibling"].exists()
    assert json.loads(targets["lease_state"].read_text(encoding="utf-8"))[
        "status"
    ] == "IDLE"


def test_provider_crash_recovers_stale_root_before_next_scope(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lease_directory = _isolated_lease(tmp_path, monkeypatch)
    stale = tmp_path / "stale"
    current = tmp_path / "current"
    stale.mkdir()
    current.mkdir()
    scripts_dir = Path(__file__).resolve().parent
    crash_code = (
        "import os,sys\n"
        f"sys.path.insert(0, {str(scripts_dir)!r})\n"
        "from pathlib import Path\n"
        "from owned_process_scope import OwnedProcessScope\n"
        f"OwnedProcessScope(writable_roots=(Path({str(stale)!r}),), "
        "persistent_identity='crashed-provider')\n"
        "os._exit(91)\n"
    )
    crashed = subprocess.run(
        [sys.executable, "-I", "-S", "-c", crash_code],
        cwd=scripts_dir,
        env=os.environ.copy(),
        capture_output=True,
        timeout=10,
        check=False,
    )
    assert crashed.returncode == 91
    stale_state = json.loads(
        (lease_directory / "state.json").read_text(encoding="utf-8")
    )
    assert stale_state["status"] == "ACTIVE"
    assert stale_state["writable_roots"] == [str(stale)]

    marker = stale / "must-remain-medium.txt"
    scope = OwnedProcessScope(
        writable_roots=(current,),
        persistent_identity="recovery-provider",
    )
    binding = scope.write_confinement_binding
    assert binding is not None
    assert binding["recovered_state_sha256"] is not None
    process = _start_owned(
        scope,
        (
            "from pathlib import Path\n"
            "try:\n"
            f" Path({str(marker)!r}).write_text('escaped')\n"
            "except OSError:\n"
            " pass\n"
        ),
    )
    process.wait(timeout=5)
    _close_owned(scope, process)
    assert not marker.exists()
    idle_state = json.loads(
        (lease_directory / "state.json").read_text(encoding="utf-8")
    )
    assert idle_state["status"] == "IDLE"


def test_emergency_close_releases_after_exact_zero_while_provider_alive(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lease_directory = _isolated_lease(tmp_path, monkeypatch)
    stale = tmp_path / "emergency-stale"
    current = tmp_path / "emergency-current"
    stale.mkdir()
    current.mkdir()
    owned_file = stale / "owned-before-emergency.txt"
    ready = tmp_path / "emergency-ready"
    stop = tmp_path / "emergency-stop"
    scripts_dir = Path(__file__).resolve().parent
    provider_code = (
        "from pathlib import Path\n"
        "import os,subprocess,sys,time\n"
        f"sys.path.insert(0, {str(scripts_dir)!r})\n"
        "from owned_process_scope import OwnedProcessScope\n"
        f"root = Path({str(stale)!r})\n"
        "scope = OwnedProcessScope(writable_roots=(root,), "
        "persistent_identity='emergency-provider')\n"
        f"code = \"from pathlib import Path; import time; Path({str(owned_file)!r})"
        ".write_text('owner'); time.sleep(30)\"\n"
        "child = scope.create_process(scope.wrap_argv((sys.executable, '-I', "
        "'-S', '-c', code)), stdin=subprocess.DEVNULL, "
        "stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, "
        "shell=False, **scope.popen_kwargs())\n"
        "scope.attach(child)\n"
        f"owned = Path({str(owned_file)!r})\n"
        "deadline = time.monotonic() + 5\n"
        "while not owned.exists() and time.monotonic() < deadline:\n"
        " time.sleep(0.01)\n"
        "scope.emergency_close()\n"
        "child.wait(timeout=5)\n"
        f"Path({str(ready)!r}).write_text('ready')\n"
        f"stop = Path({str(stop)!r})\n"
        "while not stop.exists():\n"
        " time.sleep(0.01)\n"
        "os._exit(92)\n"
    )
    provider = _start_outer(
        [sys.executable, "-I", "-S", "-c", provider_code],
        cwd=scripts_dir,
        env=os.environ.copy(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    deadline = time.monotonic() + 10
    while not ready.exists() and provider.poll() is None and time.monotonic() < deadline:
        time.sleep(0.01)
    assert ready.exists(), provider.communicate(timeout=1)
    released = json.loads(
        (lease_directory / "state.json").read_text(encoding="utf-8")
    )
    assert released["status"] == "IDLE"

    contender_code = (
        "from pathlib import Path\n"
        "import sys\n"
        f"sys.path.insert(0, {str(scripts_dir)!r})\n"
        "from owned_process_scope import OwnedProcessScope\n"
        f"scope = OwnedProcessScope(writable_roots=(Path({str(current)!r}),))\n"
        "scope.close()\n"
    )
    next_scope = subprocess.run(
        [sys.executable, "-I", "-S", "-c", contender_code],
        cwd=scripts_dir,
        env=os.environ.copy(),
        capture_output=True,
        timeout=5,
        check=False,
    )
    assert next_scope.returncode == 0, (
        next_scope.stdout.decode(errors="replace"),
        next_scope.stderr.decode(errors="replace"),
    )
    assert json.loads(
        (lease_directory / "state.json").read_text(encoding="utf-8")
    )["status"] == "IDLE"

    stop.write_text("exit", encoding="utf-8")
    stdout, stderr = provider.communicate(timeout=5)
    assert provider.returncode == 92, (
        stdout.decode(errors="replace"),
        stderr.decode(errors="replace"),
    )

    marker = stale / "must-not-overwrite-after-recovery.txt"
    scope = OwnedProcessScope(writable_roots=(current,))
    process = _start_owned(
        scope,
        (
            "from pathlib import Path\n"
            "try:\n"
            f" Path({str(marker)!r}).write_text('escaped')\n"
            "except OSError:\n"
            " pass\n"
        ),
    )
    process.wait(timeout=5)
    _close_owned(scope, process)
    assert not marker.exists()


def test_scope_membership_proof_accepts_owned_pid_and_rejects_outsider(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _isolated_lease(tmp_path, monkeypatch)
    owned = tmp_path / "owned"
    owned.mkdir()
    outsider = _start_outer(
        [sys.executable, "-I", "-S", "-c", "import time; time.sleep(30)"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    scope = OwnedProcessScope(writable_roots=(owned,))
    descendant_pid_path = owned / "descendant.pid"
    process = _start_owned(
        scope,
        (
            "from pathlib import Path\n"
            "import subprocess,sys,time\n"
            "child = subprocess.Popen([sys.executable, '-I', '-S', '-c', "
            "'import time; time.sleep(30)'], stdin=subprocess.DEVNULL, "
            "stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)\n"
            f"Path({str(descendant_pid_path)!r}).write_text(str(child.pid))\n"
            "time.sleep(30)\n"
        ),
    )
    try:
        assert scope.write_confinement_proven is False
        assert scope.serialized_stage_write_confinement_proven is True
        deadline = time.monotonic() + 5
        while (
            not descendant_pid_path.exists()
            and time.monotonic() < deadline
        ):
            time.sleep(0.01)
        descendant_pid = int(
            descendant_pid_path.read_text(encoding="utf-8")
        )
        assert scope.contains_process_id(process.pid) is True
        assert scope.contains_process_id(descendant_pid) is True
        assert scope.contains_process_id(outsider.pid) is False
        for invalid in (True, 0, -1, "1"):
            with pytest.raises(OwnedProcessScopeError):
                scope.contains_process_id(invalid)  # type: ignore[arg-type]
    finally:
        _close_owned(scope, process)
        outsider.terminate()
        outsider.wait(timeout=5)
    with pytest.raises(OwnedProcessScopeError):
        scope.contains_process_id(process.pid)


def test_symlink_root_and_symlink_member_are_never_followed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _isolated_lease(tmp_path, monkeypatch)
    real = tmp_path / "real"
    alias = tmp_path / "alias"
    outside = tmp_path / "outside"
    real.mkdir()
    outside.mkdir()
    try:
        alias.symlink_to(real, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"directory symlink unavailable: {exc}")

    with pytest.raises(
        OwnedProcessScopeError,
        match="serialized Windows low-integrity scope",
    ):
        OwnedProcessScope(writable_roots=(alias,))

    root = tmp_path / "restore-root"
    root.mkdir()
    set_windows_low_integrity_root(root)
    nested_alias = root / "outside-alias"
    nested_alias.symlink_to(outside, target_is_directory=True)
    try:
        with pytest.raises(
            WindowsLowIntegrityLeaseError,
            match="reparse",
        ):
            restore_windows_medium_integrity_tree(root)
        assert not (outside / "touched").exists()
    finally:
        nested_alias.unlink()
        restore_windows_medium_integrity_tree(root)


def test_unrelated_low_integrity_object_is_explicitly_out_of_scope(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _isolated_lease(tmp_path, monkeypatch)
    owned = tmp_path / "owned"
    unrelated = tmp_path / "unrelated-low"
    owned.mkdir()
    unrelated.mkdir()
    marker = unrelated / "writable-by-design-residual.txt"
    set_windows_low_integrity_root(unrelated)
    try:
        capability = process_tree_termination_capability()
        assert capability["exhaustive_write_confinement_authority"] is False
        assert capability["serialized_low_integrity_stage_authority"] is True
        assert capability["write_confinement_limitation"] == (
            "UNRELATED_PREEXISTING_LOW_INTEGRITY_OBJECTS_OUT_OF_SCOPE"
        )

        scope = OwnedProcessScope(writable_roots=(owned,))
        process = _start_owned(
            scope,
            (
                "from pathlib import Path; "
                f"Path({str(marker)!r}).write_text('residual', encoding='utf-8')"
            ),
        )
        process.wait(timeout=5)
        _close_owned(scope, process)
        assert marker.read_text(encoding="utf-8") == "residual"
    finally:
        restore_windows_medium_integrity_tree(unrelated)
