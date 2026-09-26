"""Single provider-owned process-scope authority.

Windows workers are created suspended and atomically associated with a
non-breakaway kill-on-close Job Object, then resumed.  Linux uses a gated
cgroup-v2 helper plus Landlock.  macOS capability admission separately probes
inherited Seatbelt write confinement and the kernel ``NOTE_TRACK`` descendant
primitive; hosts without both fail closed instead of inflating process groups
into proof.
"""

from __future__ import annotations

import ctypes
import hashlib
import os
from pathlib import Path
import re
import select
import signal
import stat
import subprocess
import sys
import threading
import time
from typing import Any, Mapping
import uuid


_JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
_JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 0x00000008
_JOB_OBJECT_LIMIT_JOB_MEMORY = 0x00000200
_JOB_OBJECT_EXTENDED_LIMIT_INFORMATION = 9
_JOB_OBJECT_BASIC_ACCOUNTING_INFORMATION = 1
_WINDOWS_JOB_ACTIVE_PROCESS_LIMIT = 64
_WINDOWS_JOB_MEMORY_LIMIT_BYTES = 4 * 1024 * 1024 * 1024
_CREATE_SUSPENDED = 0x00000004
_CREATE_UNICODE_ENVIRONMENT = 0x00000400
_EXTENDED_STARTUPINFO_PRESENT = 0x00080000
# ProcThreadAttributeValue(13, FALSE, TRUE, FALSE).  Python 3.12's
# ``_winapi.CreateProcess`` only translates PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
# so the Job list must be supplied at the native CreateProcessW boundary.
_PROC_THREAD_ATTRIBUTE_JOB_LIST = 0x0002000D
_PROC_THREAD_ATTRIBUTE_HANDLE_LIST = 0x00020002
_TH32CS_SNAPTHREAD = 0x00000004
_THREAD_SUSPEND_RESUME = 0x0002
_INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
PROCESS_CREATED_BUT_NOT_RETURNED_TERMINATED = (
    "PROCESS_CREATED_BUT_NOT_RETURNED_TERMINATED"
)
PROCESS_CREATED_BUT_NOT_RETURNED_CONTAINED = (
    "PROCESS_CREATED_BUT_NOT_RETURNED_CONTAINED"
)
_LINUX_CGROUP_ROOT_ENV = "PLAMEN_CGROUP_V2_ROOT"
_WINDOWS_LOW_INTEGRITY_SID = "S-1-16-4096"
_PERSISTENT_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}")
_WINDOWS_JOB_ONLY_MODE = "WINDOWS_JOB_ONLY_DESCENDANT_CONTAINMENT"
_MCP_LINUX_SCOPE_RE = re.compile(
    r"plamen-mcp-p([1-9][0-9]*)-s([1-9][0-9]*)-"
    r"t([1-9][0-9]*)-u([1-9][0-9]*)-([0-9a-f]{24})\Z"
)


class OwnedProcessScopeError(RuntimeError):
    """Process-scope creation, containment, termination, or cleanup failed."""


class _WindowsAtomicPopenConstructionError(OwnedProcessScopeError):
    """Native process existed but Popen construction did not return it."""

    def __init__(self, message: str, *, termination_proven: bool) -> None:
        super().__init__(message)
        self.termination_proven = termination_proven


class _WindowsStartupInfo(ctypes.Structure):
    _fields_ = [
        ("cb", ctypes.c_uint32),
        ("lpReserved", ctypes.c_wchar_p),
        ("lpDesktop", ctypes.c_wchar_p),
        ("lpTitle", ctypes.c_wchar_p),
        ("dwX", ctypes.c_uint32),
        ("dwY", ctypes.c_uint32),
        ("dwXSize", ctypes.c_uint32),
        ("dwYSize", ctypes.c_uint32),
        ("dwXCountChars", ctypes.c_uint32),
        ("dwYCountChars", ctypes.c_uint32),
        ("dwFillAttribute", ctypes.c_uint32),
        ("dwFlags", ctypes.c_uint32),
        ("wShowWindow", ctypes.c_uint16),
        ("cbReserved2", ctypes.c_uint16),
        ("lpReserved2", ctypes.POINTER(ctypes.c_ubyte)),
        ("hStdInput", ctypes.c_void_p),
        ("hStdOutput", ctypes.c_void_p),
        ("hStdError", ctypes.c_void_p),
    ]


class _WindowsStartupInfoEx(ctypes.Structure):
    _fields_ = [
        ("StartupInfo", _WindowsStartupInfo),
        ("lpAttributeList", ctypes.c_void_p),
    ]


class _WindowsProcessInformation(ctypes.Structure):
    _fields_ = [
        ("hProcess", ctypes.c_void_p),
        ("hThread", ctypes.c_void_p),
        ("dwProcessId", ctypes.c_uint32),
        ("dwThreadId", ctypes.c_uint32),
    ]


def _windows_structure_layout_supported() -> bool:
    pointer_size = ctypes.sizeof(ctypes.c_void_p)
    expected = {
        4: (68, 72, 16, 68),
        8: (104, 112, 24, 104),
    }.get(pointer_size)
    return expected == (
        ctypes.sizeof(_WindowsStartupInfo),
        ctypes.sizeof(_WindowsStartupInfoEx),
        ctypes.sizeof(_WindowsProcessInformation),
        _WindowsStartupInfoEx.lpAttributeList.offset,
    )


def _windows_atomic_job_runtime_support() -> tuple[bool, str | None]:
    if os.name != "nt":
        return False, "WINDOWS_ATOMIC_JOB_HOST_UNAVAILABLE"
    if (
        getattr(sys.implementation, "name", None) != "cpython"
        or sys.version_info[:2] != (3, 12)
    ):
        return False, "WINDOWS_ATOMIC_JOB_REQUIRES_CPYTHON_3_12"
    try:
        windows_major = sys.getwindowsversion().major
    except AttributeError:
        return False, "WINDOWS_VERSION_API_UNAVAILABLE"
    if windows_major < 10:
        return False, "PROC_THREAD_ATTRIBUTE_JOB_LIST_OS_UNAVAILABLE"
    if not _windows_structure_layout_supported():
        return False, "WINDOWS_STARTUPINFOEX_ABI_LAYOUT_UNSUPPORTED"
    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        _configure_windows_atomic_create_api(kernel32)
    except (
        AttributeError,
        OSError,
        TypeError,
        ValueError,
        OwnedProcessScopeError,
    ):
        return False, "WINDOWS_ATOMIC_JOB_API_UNAVAILABLE"
    return True, None


def _windows_environment_block(
    environment: Any | None,
) -> ctypes.Array[ctypes.c_wchar] | None:
    """Build the mutable Unicode environment block required by CreateProcessW."""

    if environment is None:
        return None
    if not hasattr(environment, "items"):
        raise TypeError("environment must be a mapping or None")
    normalized: dict[str, str] = {}
    canonical_keys: dict[str, str] = {}
    for key, value in environment.items():
        if not isinstance(key, str) or not isinstance(value, str):
            raise TypeError("environment can only contain strings")
        if not key or "\x00" in key or "\x00" in value or "=" in key[1:]:
            raise ValueError("illegal Windows environment entry")
        if not key.isascii():
            raise ValueError(
                "non-ASCII Windows environment keys are unsupported"
            )
        folded = key.upper()
        if folded in canonical_keys:
            raise ValueError(
                "case-insensitive duplicate Windows environment key"
            )
        canonical_keys[folded] = key
        normalized[key] = value
    rows = [
        f"{key}={normalized[key]}"
        for key in sorted(normalized, key=lambda item: item.upper())
    ]
    # Even an empty environment requires two terminating NUL characters.
    block = "\x00".join(rows) + "\x00\x00"
    return ctypes.create_unicode_buffer(block, len(block))


def _configure_windows_atomic_create_api(kernel32: Any) -> None:
    """Bind every API needed for atomic Job association, or fail closed."""

    required = (
        "InitializeProcThreadAttributeList",
        "UpdateProcThreadAttribute",
        "DeleteProcThreadAttributeList",
        "CreateProcessW",
        "TerminateProcess",
        "WaitForSingleObject",
        "CloseHandle",
    )
    missing = [name for name in required if not hasattr(kernel32, name)]
    if missing:
        raise OwnedProcessScopeError(
            "Windows atomic Job creation API is unavailable: "
            + ", ".join(missing)
        )
    kernel32.InitializeProcThreadAttributeList.argtypes = [
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_size_t),
    ]
    kernel32.InitializeProcThreadAttributeList.restype = ctypes.c_int
    kernel32.UpdateProcThreadAttribute.argtypes = [
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_size_t,
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.c_void_p,
        ctypes.c_void_p,
    ]
    kernel32.UpdateProcThreadAttribute.restype = ctypes.c_int
    kernel32.DeleteProcThreadAttributeList.argtypes = [ctypes.c_void_p]
    kernel32.DeleteProcThreadAttributeList.restype = None
    kernel32.CreateProcessW.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_wchar_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_int,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_wchar_p,
        ctypes.POINTER(_WindowsStartupInfoEx),
        ctypes.POINTER(_WindowsProcessInformation),
    ]
    kernel32.CreateProcessW.restype = ctypes.c_int
    kernel32.TerminateProcess.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
    kernel32.TerminateProcess.restype = ctypes.c_int
    kernel32.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
    kernel32.WaitForSingleObject.restype = ctypes.c_uint32
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel32.CloseHandle.restype = ctypes.c_int


def _windows_last_error(kernel32: Any) -> int:
    getter = getattr(ctypes, "get_last_error", None)
    if getter is not None:
        return int(getter())
    return int(getattr(kernel32, "last_error", 0))


def _clear_windows_last_error(kernel32: Any) -> None:
    setter = getattr(ctypes, "set_last_error", None)
    if setter is not None:
        setter(0)
    elif hasattr(kernel32, "last_error"):
        kernel32.last_error = 0


def _windows_create_process_in_job(
    *,
    job_handle: int,
    application_name: str | None,
    command_line: str,
    inherit_handles: bool,
    creationflags: int,
    environment: Any | None,
    current_directory: str | None,
    startupinfo: Any,
    kernel32: Any | None = None,
    _boundary_hook: Any | None = None,
) -> tuple[int, int, int, int]:
    """Call CreateProcessW with atomic Job membership and suspended startup.

    A successful native return means the process was assigned to ``job_handle``
    as part of creation.  Every setup failure occurs before a process exists.
    If Python fails while translating a successful native return, the exact
    still-suspended process is terminated and both returned handles are closed.
    """

    if os.name != "nt" and kernel32 is None:
        raise OwnedProcessScopeError(
            "Windows atomic Job creation is unavailable on this host"
        )
    if kernel32 is None and (
        getattr(sys.implementation, "name", None) != "cpython"
        or sys.version_info[:2] != (3, 12)
    ):
        raise OwnedProcessScopeError(
            "Windows atomic Job creation requires Python 3.12"
        )
    if kernel32 is None and sys.getwindowsversion().major < 10:
        raise OwnedProcessScopeError(
            "PROC_THREAD_ATTRIBUTE_JOB_LIST requires Windows 10 or newer"
        )
    if not _windows_structure_layout_supported():
        raise OwnedProcessScopeError(
            "Windows STARTUPINFOEX structure layout is unsupported"
        )
    if (
        isinstance(job_handle, bool)
        or not isinstance(job_handle, int)
        or job_handle <= 0
    ):
        raise OwnedProcessScopeError("Windows Job handle is invalid")
    if creationflags & _CREATE_SUSPENDED != _CREATE_SUSPENDED:
        raise OwnedProcessScopeError(
            "Windows atomic Job creation requires CREATE_SUSPENDED"
        )
    for label, value in (
        ("application name", application_name),
        ("command line", command_line),
        ("current directory", current_directory),
    ):
        if value is not None and "\x00" in value:
            raise OwnedProcessScopeError(
                f"Windows {label} contains an embedded NUL"
            )
    attribute_mapping = getattr(startupinfo, "lpAttributeList", None) or {}
    unknown_attributes = set(attribute_mapping) - {"handle_list"}
    if unknown_attributes:
        raise OwnedProcessScopeError(
            "unsupported Windows process attribute(s): "
            + ", ".join(sorted(map(str, unknown_attributes)))
        )
    handle_values = tuple(int(item) for item in attribute_mapping.get(
        "handle_list", ()
    ))
    if job_handle in handle_values:
        raise OwnedProcessScopeError(
            "kill-on-close Job handle must not be inherited by the child"
        )
    environment_buffer = _windows_environment_block(environment)
    api = (
        ctypes.WinDLL("kernel32", use_last_error=True)
        if kernel32 is None
        else kernel32
    )
    _configure_windows_atomic_create_api(api)

    size = ctypes.c_size_t()
    attribute_count = 1 + bool(handle_values)
    # The sizing call must fail with ERROR_INSUFFICIENT_BUFFER (122).  Accepting
    # any other result would turn an unsupported/partially hooked API into a
    # launch path.
    _clear_windows_last_error(api)
    sizing_result = api.InitializeProcThreadAttributeList(
        None, attribute_count, 0, ctypes.byref(size)
    )
    sizing_error = _windows_last_error(api)
    if sizing_result or sizing_error != 122 or size.value <= 0:
        raise OwnedProcessScopeError(
            "InitializeProcThreadAttributeList sizing failed closed: "
            f"{sizing_error}"
        )

    attribute_storage = ctypes.create_string_buffer(size.value)
    attribute_pointer = ctypes.cast(attribute_storage, ctypes.c_void_p)
    initialized = False
    process_info = _WindowsProcessInformation()
    created = False
    returned_handles_closed = False
    try:
        if not api.InitializeProcThreadAttributeList(
            attribute_pointer, attribute_count, 0, ctypes.byref(size)
        ):
            raise OwnedProcessScopeError(
                "InitializeProcThreadAttributeList failed: "
                f"{_windows_last_error(api)}"
            )
        initialized = True
        if _boundary_hook is not None:
            _boundary_hook("ATTRIBUTE_LIST_INITIALIZED", None)

        job_values = (ctypes.c_void_p * 1)(job_handle)
        if not api.UpdateProcThreadAttribute(
            attribute_pointer,
            0,
            _PROC_THREAD_ATTRIBUTE_JOB_LIST,
            ctypes.cast(job_values, ctypes.c_void_p),
            ctypes.sizeof(job_values),
            None,
            None,
        ):
            raise OwnedProcessScopeError(
                "PROC_THREAD_ATTRIBUTE_JOB_LIST setup failed: "
                f"{_windows_last_error(api)}"
            )
        if _boundary_hook is not None:
            _boundary_hook("JOB_ATTRIBUTE_SET", None)

        inherited_values: Any | None = None
        if handle_values:
            inherited_values = (ctypes.c_void_p * len(handle_values))(
                *handle_values
            )
            if not api.UpdateProcThreadAttribute(
                attribute_pointer,
                0,
                _PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                ctypes.cast(inherited_values, ctypes.c_void_p),
                ctypes.sizeof(inherited_values),
                None,
                None,
            ):
                raise OwnedProcessScopeError(
                    "PROC_THREAD_ATTRIBUTE_HANDLE_LIST setup failed: "
                    f"{_windows_last_error(api)}"
                )
            if _boundary_hook is not None:
                _boundary_hook("HANDLE_ATTRIBUTE_SET", None)

        native_startup = _WindowsStartupInfoEx()
        native_startup.StartupInfo.cb = ctypes.sizeof(native_startup)
        native_startup.StartupInfo.dwFlags = int(startupinfo.dwFlags)
        native_startup.StartupInfo.wShowWindow = int(startupinfo.wShowWindow)
        native_startup.StartupInfo.hStdInput = startupinfo.hStdInput
        native_startup.StartupInfo.hStdOutput = startupinfo.hStdOutput
        native_startup.StartupInfo.hStdError = startupinfo.hStdError
        native_startup.lpAttributeList = attribute_pointer
        command_buffer = ctypes.create_unicode_buffer(command_line)
        flags = (
            int(creationflags)
            | _EXTENDED_STARTUPINFO_PRESENT
            | (_CREATE_UNICODE_ENVIRONMENT if environment is not None else 0)
        )
        _clear_windows_last_error(api)
        if not api.CreateProcessW(
            application_name,
            ctypes.cast(command_buffer, ctypes.c_wchar_p),
            None,
            None,
            int(inherit_handles),
            flags,
            (
                ctypes.cast(environment_buffer, ctypes.c_void_p)
                if environment_buffer is not None
                else None
            ),
            current_directory,
            ctypes.byref(native_startup),
            ctypes.byref(process_info),
        ):
            error = _windows_last_error(api)
            raise OwnedProcessScopeError(
                "atomic CreateProcessW Job association failed "
                f"(including nested-Job rejection): {error}"
            )
        created = True
        if _boundary_hook is not None:
            _boundary_hook("CREATE_RETURNED", process_info)
        return (
            int(process_info.hProcess),
            int(process_info.hThread),
            int(process_info.dwProcessId),
            int(process_info.dwThreadId),
        )
    except BaseException as exc:
        termination_proven = False
        if created and process_info.hProcess:
            try:
                termination_proven = _abort_windows_unreturned_process(
                    int(process_info.hProcess),
                    int(process_info.hThread),
                    kernel32=api,
                )
            except BaseException:
                termination_proven = False
        returned_handles_closed = created
        if created:
            raise _WindowsAtomicPopenConstructionError(
                "native Windows process existed but could not be returned",
                termination_proven=termination_proven,
            ) from exc
        raise
    finally:
        if initialized:
            try:
                api.DeleteProcThreadAttributeList(attribute_pointer)
            except BaseException as delete_exc:
                if created and not returned_handles_closed:
                    try:
                        proven = _abort_windows_unreturned_process(
                            int(process_info.hProcess),
                            int(process_info.hThread),
                            kernel32=api,
                        )
                    except BaseException:
                        proven = False
                    raise _WindowsAtomicPopenConstructionError(
                        "attribute-list cleanup failed after native process "
                        "creation",
                        termination_proven=proven,
                    ) from delete_exc
                if not created:
                    raise OwnedProcessScopeError(
                        "Windows process attribute list cleanup failed"
                    ) from delete_exc


def _abort_windows_unreturned_process(
    process_handle: int,
    thread_handle: int,
    *,
    kernel32: Any | None = None,
) -> bool:
    """Terminate/wait a native child that could not become a Popen object."""

    api = (
        ctypes.WinDLL("kernel32", use_last_error=True)
        if kernel32 is None
        else kernel32
    )
    _configure_windows_atomic_create_api(api)
    terminated = waited = False
    try:
        terminated = bool(
            api.TerminateProcess(
                ctypes.c_void_p(process_handle), 0xE0000002
            )
        )
        waited = (
            int(
                api.WaitForSingleObject(
                    ctypes.c_void_p(process_handle), 5000
                )
            )
            == 0
        )
    except BaseException:
        pass
    try:
        thread_closed = bool(
            api.CloseHandle(ctypes.c_void_p(thread_handle))
        )
    except BaseException:
        thread_closed = False
    try:
        process_closed = bool(
            api.CloseHandle(ctypes.c_void_p(process_handle))
        )
    except BaseException:
        process_closed = False
    return terminated and waited and thread_closed and process_closed


class _WindowsAtomicJobPopen(subprocess.Popen[bytes]):
    """Python 3.12 Popen transport with atomic Job-list process creation."""

    def __init__(self, job_handle: int, *args: Any, **kwargs: Any) -> None:
        self._plamen_job_handle = job_handle
        self._plamen_primary_thread_handle: int | None = None
        try:
            super().__init__(*args, **kwargs)
        except BaseException as exc:
            process_handle = getattr(self, "_handle", None)
            thread_handle = self._plamen_primary_thread_handle
            if (
                getattr(self, "_child_created", False)
                and process_handle is not None
                and thread_handle is not None
            ):
                raw_process_handle = int(process_handle)
                ownership_detached = False
                try:
                    process_handle.Detach()
                    ownership_detached = True
                except BaseException:
                    # The exact raw capability is still usable for a best-effort
                    # terminate/wait.  Failure to prove every close remains the
                    # CONTAINED state and forces the Job emergency path.
                    pass
                try:
                    proven = _abort_windows_unreturned_process(
                        raw_process_handle,
                        thread_handle,
                    ) and ownership_detached
                except BaseException:
                    proven = False
                self._plamen_primary_thread_handle = None
                self._handle = None
                self._child_created = False
                raise _WindowsAtomicPopenConstructionError(
                    "native Windows process was created but Popen.__init__ "
                    "did not return; exact-process abort "
                    + ("was proven" if proven else "was not proven"),
                    termination_proven=proven,
                ) from exc
            raise

    def _take_primary_thread_handle(self) -> int:
        handle = self._plamen_primary_thread_handle
        if handle is None:
            raise OwnedProcessScopeError(
                "exact Windows primary-thread handle is unavailable"
            )
        self._plamen_primary_thread_handle = None
        return handle

    def _execute_child(
        self,
        args: Any,
        executable: Any,
        preexec_fn: Any,
        close_fds: bool,
        pass_fds: Any,
        cwd: Any,
        env: Any,
        startupinfo: Any,
        creationflags: int,
        shell: bool,
        p2cread: Any,
        p2cwrite: Any,
        c2pread: Any,
        c2pwrite: Any,
        errread: Any,
        errwrite: Any,
        unused_restore_signals: Any,
        unused_gid: Any,
        unused_gids: Any,
        unused_uid: Any,
        unused_umask: Any,
        unused_start_new_session: Any,
        unused_process_group: Any,
    ) -> None:
        """Mirror CPython 3.12's Windows transport, replacing only creation."""

        del (
            preexec_fn,
            unused_restore_signals,
            unused_gid,
            unused_gids,
            unused_uid,
            unused_umask,
            unused_start_new_session,
            unused_process_group,
        )
        if (
            getattr(sys.implementation, "name", None) != "cpython"
            or sys.version_info[:2] != (3, 12)
        ):
            raise OwnedProcessScopeError(
                "Windows atomic Job transport requires Python 3.12"
            )
        if pass_fds:
            raise OwnedProcessScopeError("pass_fds is unsupported on Windows")
        import _winapi

        if isinstance(args, str):
            command_line = args
        elif isinstance(args, bytes):
            if shell:
                raise TypeError("bytes args is not allowed on Windows")
            command_line = subprocess.list2cmdline([args])
        elif isinstance(args, os.PathLike):
            if shell:
                raise TypeError(
                    "path-like args is not allowed when shell is true"
                )
            command_line = subprocess.list2cmdline([args])
        else:
            command_line = subprocess.list2cmdline(args)
        if executable is not None:
            executable = os.fsdecode(executable)
        if startupinfo is None:
            startupinfo = subprocess.STARTUPINFO()
        else:
            startupinfo = startupinfo.copy()

        use_std_handles = -1 not in (p2cread, c2pwrite, errwrite)
        if use_std_handles:
            startupinfo.dwFlags |= _winapi.STARTF_USESTDHANDLES
            startupinfo.hStdInput = p2cread
            startupinfo.hStdOutput = c2pwrite
            startupinfo.hStdError = errwrite
        attribute_list = startupinfo.lpAttributeList
        have_handle_list = bool(
            attribute_list
            and "handle_list" in attribute_list
            and attribute_list["handle_list"]
        )
        if have_handle_list or (use_std_handles and close_fds):
            if attribute_list is None:
                attribute_list = startupinfo.lpAttributeList = {}
            handle_list = attribute_list["handle_list"] = list(
                attribute_list.get("handle_list", [])
            )
            if use_std_handles:
                handle_list += [int(p2cread), int(c2pwrite), int(errwrite)]
            handle_list[:] = self._filter_handle_list(handle_list)
            if handle_list:
                close_fds = False

        if shell:
            startupinfo.dwFlags |= _winapi.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = _winapi.SW_HIDE
            if not executable:
                comspec = os.environ.get("ComSpec")
                if not comspec:
                    system_root = os.environ.get("SystemRoot", "")
                    comspec = os.path.join(
                        system_root, "System32", "cmd.exe"
                    )
                    if not os.path.isabs(comspec):
                        raise FileNotFoundError("Windows command shell not found")
                if os.path.isabs(comspec):
                    executable = comspec
            else:
                comspec = executable
            command_line = f'{comspec} /c "{command_line}"'
        if cwd is not None:
            cwd = os.fsdecode(cwd)

        sys.audit("subprocess.Popen", executable, command_line, cwd, env)
        hp = ht = None
        native_created = False
        pipe_cleanup_attempted = False
        wrapped_process_handle: Any | None = None
        try:
            hp, ht, pid, _tid = _windows_create_process_in_job(
                job_handle=self._plamen_job_handle,
                application_name=executable,
                command_line=command_line,
                inherit_handles=not close_fds,
                creationflags=creationflags,
                environment=env,
                current_directory=cwd,
                startupinfo=startupinfo,
            )
            native_created = True
            pipe_cleanup_attempted = True
            self._close_pipe_fds(
                p2cread,
                p2cwrite,
                c2pread,
                c2pwrite,
                errread,
                errwrite,
            )
            wrapped_process_handle = subprocess.Handle(hp)
            self._handle = wrapped_process_handle
            self._plamen_primary_thread_handle = ht
            self.pid = pid
            self._child_created = True
            hp = ht = None
        except BaseException as exc:
            if not pipe_cleanup_attempted:
                self._close_pipe_fds(
                    p2cread,
                    p2cwrite,
                    c2pread,
                    c2pwrite,
                    errread,
                    errwrite,
                )
            if native_created and hp is not None and ht is not None:
                ownership_detached = wrapped_process_handle is None
                if wrapped_process_handle is not None:
                    try:
                        wrapped_process_handle.Detach()
                        ownership_detached = True
                    except BaseException:
                        pass
                try:
                    proven = _abort_windows_unreturned_process(
                        hp, ht
                    ) and ownership_detached
                except BaseException:
                    proven = False
                hp = ht = None
                self._plamen_primary_thread_handle = None
                raise _WindowsAtomicPopenConstructionError(
                    "native Windows process was created but Popen "
                    "construction failed; exact-process abort "
                    + ("was proven" if proven else "was not proven"),
                    termination_proven=proven,
                ) from exc
            raise


def _linux_task_start_ticks(process_id: int, thread_id: int | None = None) -> str | None:
    path = (
        Path(f"/proc/{process_id}/stat")
        if thread_id is None
        else Path(f"/proc/{process_id}/task/{thread_id}/stat")
    )
    try:
        raw = path.read_text(encoding="ascii")
        tail = raw[raw.rfind(")") + 2 :].split()
        value = tail[19]
    except (OSError, IndexError):
        return None
    return value if value.isdigit() and int(value) > 0 else None


def mcp_linux_persistent_identity(route_digest: str) -> str:
    """Derive the recoverable one-thread identity for one MCP launch route."""

    if _host_platform() != "LINUX":
        raise OwnedProcessScopeError(
            "Linux MCP process-scope identity is unavailable on this host"
        )
    if not isinstance(route_digest, str) or not re.fullmatch(
        r"[0-9a-f]{64}", route_digest
    ):
        raise OwnedProcessScopeError("MCP route digest is malformed")
    process_id = os.getpid()
    thread_id = threading.get_native_id()
    start_ticks = _linux_task_start_ticks(process_id)
    thread_start_ticks = _linux_task_start_ticks(process_id, thread_id)
    if start_ticks is None or thread_start_ticks is None:
        raise OwnedProcessScopeError("current Linux process identity is unavailable")
    return (
        f"plamen-mcp-p{process_id}-s{start_ticks}-"
        f"t{thread_id}-u{thread_start_ticks}-{route_digest[:24]}"
    )


def _recover_linux_cgroup_by_descriptor(
    root: Path, cgroup: Path, persistent_identity: str,
    *, timeout_seconds: float,
) -> dict[str, Any]:
    """Recover one real Linux cgroup through retained no-follow descriptors.

    The directory descriptor binds control I/O to the originally authenticated
    cgroup even if its public name is raced. After the pathname rmdir, the
    retained descriptor's zero link count proves that exact object—not a
    replacement at the same name—was removed.
    """

    absent = {
        "platform": "LINUX",
        "identity": persistent_identity,
        "cleanup": "SCOPE_REMOVED_BY_CONCURRENT_RECOVERY",
        "population_zero": True,
    }
    already_absent = dict(absent, cleanup="SCOPE_ALREADY_ABSENT")
    directory_flags = (
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        | getattr(os, "O_CLOEXEC", 0)
    )
    try:
        directory_fd = os.open(cgroup, directory_flags)
    except FileNotFoundError:
        return already_absent
    kill_fd = None
    events_fd = None
    try:
        opened = os.fstat(directory_fd)
        opened_identity = (
            int(opened.st_dev), int(opened.st_ino),
            stat.S_IFMT(opened.st_mode), int(opened.st_nlink),
        )

        def descriptor_proves_concurrent_removal() -> bool:
            return (
                not os.path.lexists(cgroup)
                and os.fstat(directory_fd).st_nlink == 0
            )

        try:
            named = os.lstat(cgroup)
        except FileNotFoundError:
            if descriptor_proves_concurrent_removal():
                return absent
            raise OwnedProcessScopeError(
                "persisted Linux process scope moved during recovery"
            )
        named_identity = (
            int(named.st_dev), int(named.st_ino),
            stat.S_IFMT(named.st_mode), int(named.st_nlink),
        )
        if (
            named_identity != opened_identity
            or stat.S_ISLNK(named.st_mode)
            or not stat.S_ISDIR(named.st_mode)
            or cgroup.resolve(strict=True).parent != root
        ):
            raise OwnedProcessScopeError(
                "persisted Linux process scope identity changed during recovery"
            )
        control_common = os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
        try:
            kill_fd = os.open(
                "cgroup.kill", os.O_WRONLY | control_common,
                dir_fd=directory_fd,
            )
            events_fd = os.open(
                "cgroup.events", os.O_RDONLY | control_common,
                dir_fd=directory_fd,
            )
        except OSError as exc:
            if descriptor_proves_concurrent_removal():
                return absent
            raise OwnedProcessScopeError(
                "persisted Linux process scope lacks cgroup-v2 controls"
            ) from exc
        if not all(
            stat.S_ISREG(os.fstat(descriptor).st_mode)
            for descriptor in (kill_fd, events_fd)
        ):
            raise OwnedProcessScopeError(
                "persisted Linux process scope lacks ordinary cgroup-v2 controls"
            )
        try:
            if os.write(kill_fd, b"1\n") != 2:
                raise OSError("short cgroup.kill write")
        except OSError as exc:
            raise OwnedProcessScopeError(
                "persisted Linux cgroup.kill failed"
            ) from exc
        deadline = time.monotonic() + float(timeout_seconds)
        while True:
            try:
                os.lseek(events_fd, 0, os.SEEK_SET)
                raw = os.read(events_fd, 4097)
                if len(raw) > 4096:
                    raise ValueError("cgroup.events exceeds bound")
                values = dict(
                    line.split(maxsplit=1)
                    for line in raw.decode("ascii", "strict").splitlines()
                )
            except (OSError, UnicodeDecodeError, ValueError) as exc:
                raise OwnedProcessScopeError(
                    "persisted Linux cgroup.events is unreadable"
                ) from exc
            if values.get("populated") == "0":
                break
            if time.monotonic() >= deadline:
                raise OwnedProcessScopeError(
                    "persisted Linux cgroup remained populated"
                )
            time.sleep(0.01)
        try:
            named_before_remove = os.lstat(cgroup)
        except FileNotFoundError:
            if descriptor_proves_concurrent_removal():
                return absent
            raise OwnedProcessScopeError(
                "persisted Linux process scope moved before removal"
            )
        before_remove_identity = (
            int(named_before_remove.st_dev), int(named_before_remove.st_ino),
            stat.S_IFMT(named_before_remove.st_mode),
            int(named_before_remove.st_nlink),
        )
        if before_remove_identity != opened_identity:
            raise OwnedProcessScopeError(
                "persisted Linux process scope identity changed before removal"
            )
        try:
            cgroup.rmdir()
        except FileNotFoundError:
            if descriptor_proves_concurrent_removal():
                return absent
            raise OwnedProcessScopeError(
                "persisted Linux process scope moved during removal"
            )
        except OSError as exc:
            raise OwnedProcessScopeError(
                "persisted Linux cgroup removal failed"
            ) from exc
        if os.path.lexists(cgroup) or os.fstat(directory_fd).st_nlink != 0:
            raise OwnedProcessScopeError(
                "persisted Linux process scope exact-object removal was not proven"
            )
        return {
            "platform": "LINUX",
            "identity": persistent_identity,
            "cleanup": "CGROUP_KILL_POPULATED_ZERO_REMOVE",
            "population_zero": True,
        }
    finally:
        for descriptor in (events_fd, kill_fd, directory_fd):
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass


def recover_stale_mcp_process_scopes(
    *, timeout_seconds: float = 5.0,
) -> tuple[dict[str, Any], ...]:
    """Recover MCP cgroups whose exact provider process no longer exists.

    Live providers are never disturbed.  PID reuse is distinguished by the
    procfs start-tick identity embedded in every deterministic cgroup name.
    """

    if _host_platform() != "LINUX":
        raise OwnedProcessScopeError(
            "Linux MCP process-scope recovery is unavailable on this host"
        )
    root, limitation = _linux_delegated_cgroup_root()
    if root is None:
        raise OwnedProcessScopeError(
            limitation or "delegated cgroup root is unavailable"
        )
    try:
        names = sorted(entry.name for entry in os.scandir(root))
    except OSError as exc:
        raise OwnedProcessScopeError(
            "delegated cgroup root cannot be enumerated"
        ) from exc
    recovered = []
    for name in names:
        match = _MCP_LINUX_SCOPE_RE.fullmatch(name)
        if match is None:
            continue
        process_id = int(match.group(1))
        start_ticks = match.group(2)
        thread_id = int(match.group(3))
        thread_start_ticks = match.group(4)
        if (
            _linux_task_start_ticks(process_id) == start_ticks
            and _linux_task_start_ticks(process_id, thread_id)
            == thread_start_ticks
        ):
            continue
        recovered.append(
            recover_persisted_process_scope(
                name, timeout_seconds=timeout_seconds,
            )
        )
    return tuple(recovered)


def recover_persisted_process_scope(
    persistent_identity: str,
    *,
    timeout_seconds: float = 5.0,
) -> dict[str, Any]:
    """Close a scope left by a dead provider before an attempt is retried."""

    if (
        not isinstance(persistent_identity, str)
        or not _PERSISTENT_ID_RE.fullmatch(persistent_identity)
    ):
        raise OwnedProcessScopeError(
            "recovery process-scope identity is invalid"
        )
    platform = _host_platform()
    if platform == "WINDOWS":
        # Job handles are deliberately non-inheritable.  Process death closes
        # the last provider handle and KILL_ON_JOB_CLOSE terminates members.
        return {
            "platform": "WINDOWS",
            "identity": persistent_identity,
            "cleanup": "KILL_ON_LAST_NONINHERITABLE_HANDLE_CLOSE",
            "population_zero": True,
        }
    if platform != "LINUX":
        raise OwnedProcessScopeError(
            "persistent process-scope recovery is unavailable on this host"
        )
    root, limitation = _linux_delegated_cgroup_root()
    if root is None:
        raise OwnedProcessScopeError(
            limitation or "delegated cgroup root is unavailable"
        )
    cgroup = root / persistent_identity
    if sys.platform.startswith("linux"):
        return _recover_linux_cgroup_by_descriptor(
            root, cgroup, persistent_identity,
            timeout_seconds=timeout_seconds,
        )

    def concurrently_removed() -> dict[str, Any] | None:
        """Authenticate the only benign recovery race: exact-name absence.

        Public routes may independently discover the same dead-provider
        cgroup. Once either route removes that exact directory, every
        filesystem operation in the other route may observe ENOENT. Absence
        is the desired postcondition; a replacement, symlink, or alias at the
        same name is not and therefore remains a hard failure.
        """

        if os.path.lexists(cgroup):
            return None
        return {
            "platform": "LINUX",
            "identity": persistent_identity,
            "cleanup": "SCOPE_REMOVED_BY_CONCURRENT_RECOVERY",
            "population_zero": True,
        }

    if not os.path.lexists(cgroup):
        return {
            "platform": "LINUX",
            "identity": persistent_identity,
            "cleanup": "SCOPE_ALREADY_ABSENT",
            "population_zero": True,
        }
    try:
        initial_info = os.lstat(cgroup)
        aliased = (
            stat.S_ISLNK(initial_info.st_mode)
            or not stat.S_ISDIR(initial_info.st_mode)
            or cgroup.resolve(strict=True).parent != root
        )
    except FileNotFoundError:
        removed = concurrently_removed()
        if removed is not None:
            return removed
        raise OwnedProcessScopeError(
            "persisted Linux process scope identity changed during recovery"
        )
    if aliased:
        raise OwnedProcessScopeError(
            "persisted Linux process scope is aliased or escaped"
        )
    initial_identity = (
        int(initial_info.st_dev), int(initial_info.st_ino),
        stat.S_IFMT(initial_info.st_mode), int(initial_info.st_nlink),
    )

    def replay_scope_identity() -> bool:
        """Return false only for concurrent removal; reject replacement."""

        try:
            current = os.lstat(cgroup)
        except FileNotFoundError:
            return False
        current_identity = (
            int(current.st_dev), int(current.st_ino),
            stat.S_IFMT(current.st_mode), int(current.st_nlink),
        )
        if (
            current_identity != initial_identity
            or stat.S_ISLNK(current.st_mode)
            or not stat.S_ISDIR(current.st_mode)
        ):
            raise OwnedProcessScopeError(
                "persisted Linux process scope identity changed during recovery"
            )
        return True

    events = cgroup / "cgroup.events"
    kill = cgroup / "cgroup.kill"
    if not replay_scope_identity():
        removed = concurrently_removed()
        if removed is not None:
            return removed
        raise OwnedProcessScopeError(
            "persisted Linux process scope identity changed during recovery"
        )
    controls_valid = (
        events.is_file()
        and not events.is_symlink()
        and kill.is_file()
        and not kill.is_symlink()
    )
    if not controls_valid:
        removed = concurrently_removed()
        if removed is not None:
            return removed
        raise OwnedProcessScopeError(
            "persisted Linux process scope lacks cgroup-v2 controls"
        )
    if not replay_scope_identity():
        removed = concurrently_removed()
        if removed is not None:
            return removed
        raise OwnedProcessScopeError(
            "persisted Linux process scope identity changed during recovery"
        )
    try:
        kill.write_text("1\n", encoding="ascii")
    except OSError as exc:
        removed = concurrently_removed()
        if removed is not None:
            return removed
        raise OwnedProcessScopeError(
            "persisted Linux cgroup.kill failed"
        ) from exc
    deadline = time.monotonic() + float(timeout_seconds)
    while True:
        if not replay_scope_identity():
            removed = concurrently_removed()
            if removed is not None:
                return removed
            raise OwnedProcessScopeError(
                "persisted Linux process scope identity changed during recovery"
            )
        try:
            values = dict(
                line.split(maxsplit=1)
                for line in events.read_text(encoding="ascii").splitlines()
            )
        except (OSError, ValueError) as exc:
            removed = concurrently_removed()
            if removed is not None:
                return removed
            raise OwnedProcessScopeError(
                "persisted Linux cgroup.events is unreadable"
            ) from exc
        if values.get("populated") == "0":
            break
        if time.monotonic() >= deadline:
            raise OwnedProcessScopeError(
                "persisted Linux cgroup remained populated"
            )
        time.sleep(0.01)
    if not replay_scope_identity():
        removed = concurrently_removed()
        if removed is not None:
            return removed
        raise OwnedProcessScopeError(
            "persisted Linux process scope identity changed during recovery"
        )
    try:
        cgroup.rmdir()
    except OSError as exc:
        removed = concurrently_removed()
        if removed is not None:
            return removed
        raise OwnedProcessScopeError(
            "persisted Linux cgroup removal failed"
        ) from exc
    if os.path.lexists(cgroup):
        raise OwnedProcessScopeError(
            "persisted Linux process scope was recreated during recovery"
        )
    return {
        "platform": "LINUX",
        "identity": persistent_identity,
        "cleanup": "CGROUP_KILL_POPULATED_ZERO_REMOVE",
        "population_zero": True,
    }


def _lower_windows_process_integrity(process_handle: int) -> str:
    """Lower a suspended child token and mechanically read the result back."""

    from ctypes import wintypes

    class _SidAndAttributes(ctypes.Structure):
        _fields_ = [
            ("Sid", ctypes.c_void_p),
            ("Attributes", wintypes.DWORD),
        ]

    class _TokenMandatoryLabel(ctypes.Structure):
        _fields_ = [("Label", _SidAndAttributes)]

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi32.OpenProcessToken.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
    ]
    advapi32.OpenProcessToken.restype = wintypes.BOOL
    advapi32.ConvertStringSidToSidW.argtypes = [
        wintypes.LPCWSTR,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    advapi32.ConvertStringSidToSidW.restype = wintypes.BOOL
    advapi32.SetTokenInformation.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
    ]
    advapi32.SetTokenInformation.restype = wintypes.BOOL
    advapi32.GetTokenInformation.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi32.GetTokenInformation.restype = wintypes.BOOL
    advapi32.ConvertSidToStringSidW.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.LPWSTR),
    ]
    advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL
    advapi32.GetLengthSid.argtypes = [ctypes.c_void_p]
    advapi32.GetLengthSid.restype = wintypes.DWORD
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p

    token = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(
        wintypes.HANDLE(process_handle),
        0x0008 | 0x0080,  # TOKEN_QUERY | TOKEN_ADJUST_DEFAULT
        ctypes.byref(token),
    ):
        raise OwnedProcessScopeError(
            f"OpenProcessToken failed: {ctypes.get_last_error()}"
        )
    sid = ctypes.c_void_p()
    try:
        if not advapi32.ConvertStringSidToSidW(
            _WINDOWS_LOW_INTEGRITY_SID,
            ctypes.byref(sid),
        ):
            raise OwnedProcessScopeError(
                f"ConvertStringSidToSidW failed: {ctypes.get_last_error()}"
            )
        label = _TokenMandatoryLabel(
            _SidAndAttributes(sid, 0x00000020)  # SE_GROUP_INTEGRITY
        )
        size = ctypes.sizeof(label) + int(advapi32.GetLengthSid(sid))
        if not advapi32.SetTokenInformation(
            token,
            25,  # TokenIntegrityLevel
            ctypes.byref(label),
            size,
        ):
            raise OwnedProcessScopeError(
                f"SetTokenInformation(low integrity) failed: {ctypes.get_last_error()}"
            )

        required = wintypes.DWORD()
        advapi32.GetTokenInformation(token, 25, None, 0, ctypes.byref(required))
        if required.value == 0:
            raise OwnedProcessScopeError(
                "cannot size the child integrity-token observation"
            )
        buffer = ctypes.create_string_buffer(required.value)
        if not advapi32.GetTokenInformation(
            token,
            25,
            buffer,
            required,
            ctypes.byref(required),
        ):
            raise OwnedProcessScopeError(
                f"GetTokenInformation failed: {ctypes.get_last_error()}"
            )
        observed = ctypes.cast(
            buffer,
            ctypes.POINTER(_TokenMandatoryLabel),
        ).contents
        rendered = wintypes.LPWSTR()
        if not advapi32.ConvertSidToStringSidW(
            observed.Label.Sid,
            ctypes.byref(rendered),
        ):
            raise OwnedProcessScopeError(
                f"ConvertSidToStringSidW failed: {ctypes.get_last_error()}"
            )
        try:
            value = str(rendered.value)
        finally:
            kernel32.LocalFree(rendered)
        if value != _WINDOWS_LOW_INTEGRITY_SID:
            raise OwnedProcessScopeError(
                f"child integrity token is {value}, expected low integrity"
            )
        return value
    finally:
        if sid.value:
            kernel32.LocalFree(sid)
        kernel32.CloseHandle(token)


def _linux_cgroup2_mounts() -> tuple[Path, ...]:
    try:
        raw = Path("/proc/self/mountinfo").read_text(
            encoding="utf-8", errors="strict"
        )
    except OSError:
        return ()
    mounts: list[Path] = []
    for line in raw.splitlines():
        before, separator, after = line.partition(" - ")
        fields = before.split()
        filesystem = after.split()
        if not separator or len(fields) < 5 or not filesystem:
            continue
        if filesystem[0] != "cgroup2":
            continue
        # mountinfo escapes space, tab, newline, and backslash as octal.
        mount_text = (
            fields[4]
            .replace("\\040", " ")
            .replace("\\011", "\t")
            .replace("\\012", "\n")
            .replace("\\134", "\\")
        )
        try:
            mounts.append(Path(mount_text).resolve(strict=True))
        except OSError:
            continue
    return tuple(sorted(set(mounts), key=lambda item: len(item.parts), reverse=True))


def _linux_delegated_cgroup_root() -> tuple[Path | None, str | None]:
    configured = os.environ.get(_LINUX_CGROUP_ROOT_ENV, "")
    if not configured:
        return None, "DELEGATED_CGROUP_V2_ROOT_NOT_CONFIGURED"
    if configured != configured.strip() or "\x00" in configured:
        return None, "DELEGATED_CGROUP_V2_ROOT_INVALID"
    raw = Path(configured)
    if not raw.is_absolute():
        return None, "DELEGATED_CGROUP_V2_ROOT_NOT_ABSOLUTE"
    try:
        resolved = raw.resolve(strict=True)
        if not resolved.is_dir():
            return None, "DELEGATED_CGROUP_V2_ROOT_NOT_DIRECTORY"
        current = resolved
        while True:
            if stat.S_ISLNK(current.lstat().st_mode):
                return None, "DELEGATED_CGROUP_V2_ROOT_ALIASED"
            if current.parent == current:
                break
            current = current.parent
    except OSError:
        return None, "DELEGATED_CGROUP_V2_ROOT_UNREADABLE"
    mounts = _linux_cgroup2_mounts()
    if not any(
        resolved == mount or mount in resolved.parents
        for mount in mounts
    ):
        return None, "DELEGATED_ROOT_NOT_ON_CGROUP_V2"
    for name in ("cgroup.controllers", "cgroup.events", "cgroup.procs"):
        path = resolved / name
        try:
            if not path.is_file() or path.is_symlink():
                return None, f"DELEGATED_ROOT_MISSING_{name.upper().replace('.', '_')}"
        except OSError:
            return None, "DELEGATED_CGROUP_V2_ROOT_UNREADABLE"
    if not os.access(resolved, os.W_OK | os.X_OK):
        return None, "DELEGATED_CGROUP_V2_ROOT_NOT_WRITABLE"
    return resolved, None


def _linux_helper_binding() -> dict[str, str]:
    helper = Path(__file__).with_name("linux_cgroup_exec.py").resolve(strict=True)
    interpreter = Path(sys.executable).resolve(strict=True)
    return {
        "helper_path": str(helper),
        "helper_sha256": hashlib.sha256(helper.read_bytes()).hexdigest(),
        "interpreter_path": str(interpreter),
        "interpreter_sha256": hashlib.sha256(interpreter.read_bytes()).hexdigest(),
    }


def _linux_landlock_abi() -> int:
    try:
        machine = os.uname().machine.casefold()
    except AttributeError:
        return 0
    if machine not in {
        "x86_64",
        "amd64",
        "aarch64",
        "arm64",
        "riscv64",
        "ppc64",
        "ppc64le",
        "s390x",
    }:
        return 0
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    result = int(
        libc.syscall(
            444,
            ctypes.c_void_p(),
            ctypes.c_size_t(0),
            ctypes.c_uint(1),  # LANDLOCK_CREATE_RULESET_VERSION
        )
    )
    return result if result >= 1 else 0


def _darwin_helper_binding() -> dict[str, str]:
    helper = Path(__file__).with_name("darwin_sandbox_exec.py").resolve(
        strict=True
    )
    interpreter = Path(sys.executable).resolve(strict=True)
    sandbox_exec = Path("/usr/bin/sandbox-exec").resolve(strict=True)
    return {
        "helper_path": str(helper),
        "helper_sha256": hashlib.sha256(helper.read_bytes()).hexdigest(),
        "interpreter_path": str(interpreter),
        "interpreter_sha256": hashlib.sha256(interpreter.read_bytes()).hexdigest(),
        "sandbox_exec_path": str(sandbox_exec),
        "sandbox_exec_sha256": hashlib.sha256(sandbox_exec.read_bytes()).hexdigest(),
    }


def _darwin_seatbelt_available() -> tuple[bool, str | None]:
    try:
        sandbox_exec = Path("/usr/bin/sandbox-exec")
        row = sandbox_exec.stat(follow_symlinks=False)
        if not stat.S_ISREG(row.st_mode) or not os.access(sandbox_exec, os.X_OK):
            raise OSError("sandbox-exec is not an executable ordinary file")
    except OSError:
        return False, "DARWIN_SEATBELT_PROVIDER_UNAVAILABLE"
    return True, None


def _darwin_seatbelt_profile(write_roots: tuple[Path, ...]) -> str:
    def scheme_string(value: str) -> str:
        if (
            not value
            or "\x00" in value
            or any(ord(character) < 32 for character in value)
        ):
            raise OwnedProcessScopeError(
                "macOS writable-root path contains unsupported control bytes"
            )
        return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'

    rules = [
        "(version 1)",
        "(allow default)",
        # Audit tools consume only snapshot-bound local inputs.  Denying all
        # sockets closes both remote egress and local-service side effects;
        # descendants inherit the same Seatbelt profile across fork/exec and
        # cannot shed it with setsid(2).
        "(deny network*)",
        "(deny file-write*)",
    ]
    rules.extend(
        f"(allow file-write* (subpath {scheme_string(os.fspath(root))}))"
        for root in write_roots
    )
    profile = "\n".join(rules) + "\n"
    if len(profile.encode("utf-8", "strict")) > 65_536:
        raise OwnedProcessScopeError("macOS Seatbelt profile exceeds size bound")
    return profile


def _darwin_stdio_descriptor(value: Any) -> int | None:
    if value is None or any(
        value == sentinel
        for sentinel in (
            subprocess.PIPE,
            subprocess.DEVNULL,
            subprocess.STDOUT,
        )
    ):
        return None
    if isinstance(value, bool):
        raise OwnedProcessScopeError("macOS stdio descriptor is boolean")
    if isinstance(value, int):
        return value
    fileno = getattr(value, "fileno", None)
    if not callable(fileno):
        raise OwnedProcessScopeError("macOS stdio object lacks a descriptor")
    descriptor = fileno()
    if isinstance(descriptor, bool) or not isinstance(descriptor, int):
        raise OwnedProcessScopeError("macOS stdio descriptor is invalid")
    return descriptor


def _darwin_validate_inherited_descriptors(
    popen_options: Mapping[str, Any],
    *,
    expected_pass_fds: tuple[int, ...],
    writable_roots: tuple[Path, ...],
) -> None:
    """Reject pre-opened writable files that Seatbelt cannot revoke.

    ``sandbox-exec`` prevents future path-based write acquisition, but an open
    writable file description remains usable.  Popen closes ambient FDs; this
    gate covers the only explicit inheritance surfaces before process creation.
    """

    if popen_options.get("start_new_session") is not True:
        raise OwnedProcessScopeError(
            "macOS Seatbelt helper requires an isolated process group"
        )
    observed_pass = popen_options.get("pass_fds", ())
    if (
        not isinstance(observed_pass, tuple)
        or observed_pass != expected_pass_fds
    ):
        raise OwnedProcessScopeError(
            "macOS inherited descriptor roster differs from the scope authority"
        )
    if popen_options.get("close_fds", True) is not True:
        raise OwnedProcessScopeError(
            "macOS Seatbelt helper requires close_fds"
        )

    try:
        import fcntl
    except ImportError as exc:  # pragma: no cover - Darwin always provides it.
        raise OwnedProcessScopeError("macOS descriptor inspection unavailable") from exc
    for field in ("stdin", "stdout", "stderr"):
        descriptor = _darwin_stdio_descriptor(popen_options.get(field))
        if descriptor is None:
            continue
        try:
            flags = fcntl.fcntl(descriptor, fcntl.F_GETFL)
            information = os.fstat(descriptor)
        except OSError as exc:
            raise OwnedProcessScopeError(
                f"macOS {field} descriptor cannot be authenticated"
            ) from exc
        if (flags & os.O_ACCMODE) not in {os.O_WRONLY, os.O_RDWR}:
            continue
        if not stat.S_ISREG(information.st_mode):
            continue
        try:
            raw = fcntl.fcntl(descriptor, 50, b"\0" * 1024)  # F_GETPATH
            decoded = bytes(raw).split(b"\0", 1)[0].decode("utf-8", "strict")
            path = Path(decoded).resolve(strict=True)
        except (OSError, UnicodeError, ValueError) as exc:
            raise OwnedProcessScopeError(
                f"macOS writable {field} path cannot be authenticated"
            ) from exc
        if not any(
            path == root or root in path.parents for root in writable_roots
        ):
            raise OwnedProcessScopeError(
                f"macOS writable {field} descriptor escapes admitted roots"
            )


def _darwin_note_track_available() -> tuple[bool, str | None]:
    """Return Darwin's fixed recursive-process-tracking limitation.

    XNU has rejected ``NOTE_TRACK``, ``NOTE_TRACKERR``, and ``NOTE_CHILD``
    with ``ENOTSUP`` since macOS 10.5.  Their constants remain in the public
    ABI, so probing them made an impossible containment strategy look like a
    host-version-dependent capability.  Keep this helper for callers and
    diagnostics, but never let retained constants mint descendant authority.
    """

    return False, "DARWIN_KQUEUE_NOTE_TRACK_UNSUPPORTED_SINCE_10_5"


def _host_platform() -> str:
    if os.name == "nt":
        return "WINDOWS"
    if sys.platform.startswith("linux"):
        return "LINUX"
    if sys.platform == "darwin":
        return "MACOS"
    return "POSIX_UNSUPPORTED"


def process_tree_termination_capability() -> dict[str, Any]:
    """Return the exact host capability; never inflate process groups to proof."""

    platform = _host_platform()
    if platform == "WINDOWS":
        atomic_supported, atomic_limitation = (
            _windows_atomic_job_runtime_support()
        )
        try:
            from windows_low_integrity_lease import lease_capability_binding

            lease_binding: dict[str, Any] | None = lease_capability_binding()
            lease_limitation: str | None = None
        except Exception as exc:
            lease_binding = None
            lease_limitation = (
                "WINDOWS_LOW_INTEGRITY_GLOBAL_LEASE_UNAVAILABLE:"
                f"{type(exc).__name__}"
            )
        return {
            "platform": "WINDOWS",
            "strategy": (
                "STARTUPINFOEX_ATOMIC_JOB_LIST_SUSPENDED_CREATE_"
                "MIC_RESUME_TERMINATE_POPULATION_ZERO_CLOSE"
                if atomic_supported
                else "WINDOWS_ATOMIC_JOB_CREATION_UNAVAILABLE"
            ),
            "provider_owns_tree": atomic_supported,
            "descendant_termination_required": True,
            "pre_execution_assignment": atomic_supported,
            "termination_scope": (
                "JOB_TREE" if atomic_supported else "UNAVAILABLE"
            ),
            "population_zero_proof": (
                "JOB_ACTIVE_PROCESSES" if atomic_supported else "UNAVAILABLE"
            ),
            "aggregate_memory_limit_bytes": (
                _WINDOWS_JOB_MEMORY_LIMIT_BYTES if atomic_supported else None
            ),
            "active_process_limit": (
                _WINDOWS_JOB_ACTIVE_PROCESS_LIMIT if atomic_supported else None
            ),
            "resource_limit_readback": atomic_supported,
            "write_confinement": (
                "LOW_INTEGRITY_TOKEN_PLUS_SERIALIZED_PLAMEN_STAGE_LEASE"
            ),
            "exhaustive_descendant_termination_authority": atomic_supported,
            "atomic_job_creation_runtime_supported": atomic_supported,
            "process_scope_limitation": atomic_limitation,
            # MIC protects medium source/canonical state and the lease prevents
            # overlap among Plamen-owned low roots.  It cannot distinguish an
            # unrelated pre-existing low-integrity object, so calling this
            # exhaustive filesystem confinement would be an overclaim.
            "exhaustive_write_confinement_authority": False,
            "serialized_low_integrity_stage_authority": (
                lease_binding is not None
            ),
            "medium_integrity_source_and_canonical_protection": True,
            "write_confinement_limitation": (
                lease_limitation
                or "UNRELATED_PREEXISTING_LOW_INTEGRITY_OBJECTS_OUT_OF_SCOPE"
            ),
            **(
                {"low_integrity_lease": lease_binding}
                if lease_binding is not None
                else {}
            ),
        }
    if platform == "LINUX":
        root, limitation = _linux_delegated_cgroup_root()
        if root is not None:
            try:
                helper = _linux_helper_binding()
            except OSError:
                root = None
                limitation = "TRUSTED_CGROUP_EXEC_HELPER_UNREADABLE"
            else:
                landlock_abi = _linux_landlock_abi()
                return {
                    "platform": "LINUX",
                    "strategy": (
                        "TRUSTED_PREEXEC_CGROUP_V2_ASSIGN_ACK_"
                        "CGROUP_KILL_POPULATED_ZERO"
                    ),
                    "provider_owns_tree": True,
                    "descendant_termination_required": True,
                    "pre_execution_assignment": True,
                    "termination_scope": "CGROUP_V2_SUBTREE",
                    "population_zero_proof": "CGROUP_EVENTS_POPULATED_ZERO",
                    "exhaustive_descendant_termination_authority": True,
                    "exhaustive_write_confinement_authority": (
                        landlock_abi >= 1
                    ),
                    "write_confinement": (
                        f"LANDLOCK_ABI_{landlock_abi}_PATH_BENEATH"
                        if landlock_abi >= 1
                        else "UNAVAILABLE"
                    ),
                    **(
                        {}
                        if landlock_abi >= 1
                        else {
                            "write_confinement_limitation": (
                                "LANDLOCK_PROVIDER_UNAVAILABLE"
                            )
                        }
                    ),
                    "delegated_root": str(root),
                    **helper,
                }
        return {
            "platform": "LINUX",
            "strategy": "PROCESS_GROUP_DIAGNOSTIC_ONLY",
            "provider_owns_tree": False,
            "descendant_termination_required": True,
            "pre_execution_assignment": True,
            "termination_scope": "PROCESS_GROUP_ONLY",
            "population_zero_proof": "UNAVAILABLE",
            "exhaustive_descendant_termination_authority": False,
            "exhaustive_write_confinement_authority": False,
            "limitation": limitation
            or "DELEGATED_CGROUP_V2_PROVIDER_NOT_CONFIGURED",
        }
    if platform == "MACOS":
        try:
            helper = _darwin_helper_binding()
        except OSError:
            helper = {}
            helper_limitation = "TRUSTED_DARWIN_EXEC_HELPER_UNREADABLE"
        else:
            helper_limitation = None
        seatbelt, seatbelt_limitation = _darwin_seatbelt_available()
        note_track, note_track_limitation = _darwin_note_track_available()
        if helper and seatbelt and note_track:
            return {
                "platform": "MACOS",
                "strategy": (
                    "TRUSTED_PREEXEC_SEATBELT_ACK_KQUEUE_"
                    "NOTE_TRACK_TERMINATE_POPULATION_ZERO"
                ),
                "provider_owns_tree": True,
                "descendant_termination_required": True,
                "pre_execution_assignment": True,
                "termination_scope": "KQUEUE_NOTE_TRACK_PROCESS_TREE",
                "population_zero_proof": "KQUEUE_TRACKED_NOTE_EXIT_ZERO",
                "write_confinement": "DARWIN_SEATBELT_PATH_SUBPATH_V1",
                "network_confinement": "DARWIN_SEATBELT_NETWORK_DENY_V1",
                "exhaustive_descendant_termination_authority": True,
                "exhaustive_write_confinement_authority": True,
                "exhaustive_network_confinement_authority": True,
                # The live owner has the only kqueue observation authority.
                # No post-crash recovery claim is made for this strategy.
                "persistent_recovery_authority": False,
                **helper,
            }
        return {
            "platform": "MACOS",
            "strategy": (
                "SEATBELT_WRITE_CONFINEMENT_WITH_"
                "PROCESS_GROUP_DIAGNOSTIC_ONLY"
            ),
            "provider_owns_tree": False,
            "descendant_termination_required": True,
            "pre_execution_assignment": True,
            "termination_scope": "PROCESS_GROUP_ONLY",
            "population_zero_proof": "UNAVAILABLE",
            "exhaustive_descendant_termination_authority": False,
            # Seatbelt confinement is inherited by fork/exec descendants and
            # remains exhaustive for filesystem/network effects even when the
            # host cannot prove population-zero cleanup.  This does *not*
            # authorize execution: callers still require the independent
            # descendant-termination authority above.
            "exhaustive_write_confinement_authority": bool(helper and seatbelt),
            "write_confinement": (
                "DARWIN_SEATBELT_PATH_SUBPATH_V1"
                if helper and seatbelt else "UNAVAILABLE"
            ),
            "exhaustive_network_confinement_authority": bool(
                helper and seatbelt
            ),
            "network_confinement": (
                "DARWIN_SEATBELT_NETWORK_DENY_V1"
                if helper and seatbelt else "UNAVAILABLE"
            ),
            "seatbelt_write_confinement_provider_available": bool(
                helper and seatbelt
            ),
            "persistent_recovery_authority": False,
            "limitation": (
                helper_limitation
                or seatbelt_limitation
                or note_track_limitation
                or "DARWIN_EXHAUSTIVE_PROCESS_AUTHORITY_UNAVAILABLE"
            ),
            **helper,
        }
    return {
        "platform": "POSIX_UNSUPPORTED",
        "strategy": "PROCESS_GROUP_DIAGNOSTIC_ONLY",
        "provider_owns_tree": False,
        "descendant_termination_required": True,
        "pre_execution_assignment": True,
        "termination_scope": "PROCESS_GROUP_ONLY",
        "population_zero_proof": "UNAVAILABLE",
        "exhaustive_descendant_termination_authority": False,
        "exhaustive_write_confinement_authority": False,
        "limitation": "PROCESS_SCOPE_AUTHORITY_UNAVAILABLE",
    }


def _windows_job_only_capability() -> dict[str, Any]:
    """Describe exact Job containment without claiming filesystem authority."""

    atomic_supported, atomic_limitation = _windows_atomic_job_runtime_support()
    return {
        "platform": "WINDOWS",
        "mode": _WINDOWS_JOB_ONLY_MODE,
        "strategy": (
            "STARTUPINFOEX_ATOMIC_JOB_LIST_SUSPENDED_CREATE_"
            "RESUME_TERMINATE_POPULATION_ZERO_CLOSE"
            if atomic_supported
            else "WINDOWS_ATOMIC_JOB_CREATION_UNAVAILABLE"
        ),
        "provider_owns_tree": atomic_supported,
        "descendant_termination_required": True,
        "pre_execution_assignment": atomic_supported,
        "termination_scope": (
            "NON_BREAKAWAY_KILL_ON_CLOSE_JOB_TREE"
            if atomic_supported
            else "UNAVAILABLE"
        ),
        "population_zero_proof": (
            "JOB_ACTIVE_PROCESSES" if atomic_supported else "UNAVAILABLE"
        ),
        "aggregate_memory_limit_bytes": (
            _WINDOWS_JOB_MEMORY_LIMIT_BYTES if atomic_supported else None
        ),
        "active_process_limit": (
            _WINDOWS_JOB_ACTIVE_PROCESS_LIMIT if atomic_supported else None
        ),
        "resource_limit_readback": atomic_supported,
        "exhaustive_descendant_termination_authority": atomic_supported,
        "atomic_job_creation_runtime_supported": atomic_supported,
        "process_scope_limitation": atomic_limitation,
        "write_confinement": "NOT_PROVIDED",
        "exhaustive_write_confinement_authority": False,
        "serialized_low_integrity_stage_authority": False,
        "medium_integrity_source_and_canonical_protection": False,
        "write_confinement_limitation": "WINDOWS_JOB_ONLY_MODE_HAS_NO_WRITE_BOUNDARY",
    }


def windows_job_only_process_tree_capability() -> dict[str, Any]:
    """Return the honest Windows Job-only boundary for restricted providers."""

    if os.name != "nt":
        raise OwnedProcessScopeError(
            "Windows Job-only capability is unavailable on this host"
        )
    return _windows_job_only_capability()


class OwnedProcessScope:
    """Own one native process tree from pre-execution assignment through zero."""

    def __init__(
        self,
        *,
        population_zero_timeout_seconds: float = 5.0,
        writable_roots: tuple[Path, ...] = (),
        windows_private_root_authorities: tuple[object, ...] = (),
        persistent_identity: str | None = None,
        lease_acquisition_deadline_monotonic: float | None = None,
        lease_cancel_token: Any = None,
        windows_job_only: bool = False,
    ) -> None:
        if (
            isinstance(population_zero_timeout_seconds, bool)
            or not isinstance(population_zero_timeout_seconds, (int, float))
            or population_zero_timeout_seconds <= 0
        ):
            raise OwnedProcessScopeError(
                "population-zero timeout must be positive"
            )
        self._population_zero_timeout_seconds = float(
            population_zero_timeout_seconds
        )
        identity = (
            persistent_identity
            if persistent_identity is not None
            else f"plamen-{os.getpid()}-{uuid.uuid4().hex}"
        )
        if (
            not isinstance(identity, str)
            or not _PERSISTENT_ID_RE.fullmatch(identity)
        ):
            raise OwnedProcessScopeError(
                "process-scope persistent identity is invalid"
            )
        self._persistent_identity = identity
        if type(windows_job_only) is not bool:
            raise OwnedProcessScopeError("Windows Job-only mode must be boolean")
        if windows_job_only and os.name != "nt":
            raise OwnedProcessScopeError(
                "Windows Job-only mode is unavailable on this host"
            )
        if windows_job_only and writable_roots:
            raise OwnedProcessScopeError(
                "Windows Job-only mode does not accept writable roots"
            )
        if windows_job_only and windows_private_root_authorities:
            raise OwnedProcessScopeError(
                "Windows Job-only mode does not accept private root authorities"
            )
        if os.name != "nt" and windows_private_root_authorities:
            raise OwnedProcessScopeError(
                "Windows private root authorities are unavailable on this host"
            )
        if windows_job_only and (
            lease_acquisition_deadline_monotonic is not None
            or lease_cancel_token is not None
        ):
            raise OwnedProcessScopeError(
                "Windows Job-only mode does not accept low-integrity lease controls"
            )
        if os.name == "nt":
            atomic_supported, atomic_limitation = (
                _windows_atomic_job_runtime_support()
            )
            if not atomic_supported:
                raise OwnedProcessScopeError(
                    "Windows process scope is unavailable: "
                    f"{atomic_limitation}"
                )
        self._windows_job_only = windows_job_only
        self._job_handle: int | None = None
        self._process_group_id: int | None = None
        self._linux_cgroup: Path | None = None
        self._linux_gate_read: int | None = None
        self._linux_gate_write: int | None = None
        self._linux_status_read: int | None = None
        self._linux_status_write: int | None = None
        self._linux_landlock_abi: int = 0
        self._darwin_gate_read: int | None = None
        self._darwin_gate_write: int | None = None
        self._darwin_status_read: int | None = None
        self._darwin_status_write: int | None = None
        self._darwin_root_descriptors: tuple[int, ...] = ()
        self._darwin_kqueue: Any | None = None
        self._darwin_tracked_processes: set[int] = set()
        self._darwin_tracking_error: str | None = None
        self._darwin_seatbelt_active = False
        self._darwin_seatbelt_provider = False
        self._pre_release_process_identity: dict[str, str] | None = None
        self._windows_integrity_sid: str | None = None
        self._windows_write_lease: Any | None = None
        self._capability = (
            _windows_job_only_capability()
            if windows_job_only
            else process_tree_termination_capability()
        )
        raw_writable_roots = tuple(Path(item) for item in writable_roots)
        if os.name == "nt" and raw_writable_roots:
            # Retry/output roots can exceed the legacy Win32 path boundary.
            # Their opaque private-root authorities are replayed below; keep
            # this public denominator lexical while validating it through the
            # shared extended-length, no-reparse rooted I/O layer.
            from rooted_path_io import RootedPathIOError, checked_directory

            try:
                self._writable_roots = tuple(
                    checked_directory(
                        item,
                        label="owned process writable root",
                    )
                    for item in raw_writable_roots
                )
            except RootedPathIOError as exc:
                raise OwnedProcessScopeError(
                    "cannot establish the serialized Windows low-integrity "
                    f"scope: {type(exc).__name__}: {exc}"
                ) from exc
        elif os.name == "nt":
            # Job-only backend probes deliberately have no writable-root
            # grant.  Keep that zero-state dependency-free: this module is
            # loaded from the authenticated installed closure by file path,
            # where its sibling scripts directory is intentionally not added
            # to ambient ``sys.path``.  Import rooted_path_io only when there
            # is an actual root to authenticate.
            self._writable_roots = ()
        elif sys.platform == "darwin":
            resolved_roots: list[Path] = []
            if len(raw_writable_roots) > 64:
                raise OwnedProcessScopeError(
                    "macOS Seatbelt scope accepts at most 64 writable roots"
                )
            for item in raw_writable_roots:
                try:
                    row = item.lstat()
                    if stat.S_ISLNK(row.st_mode) or not stat.S_ISDIR(row.st_mode):
                        raise OSError("writable root is aliased or not a directory")
                    resolved_roots.append(item.resolve(strict=True))
                except OSError as exc:
                    raise OwnedProcessScopeError(
                        "cannot authenticate macOS writable root"
                    ) from exc
            if len(set(resolved_roots)) != len(resolved_roots):
                raise OwnedProcessScopeError(
                    "macOS Seatbelt writable roots contain duplicates"
                )
            self._writable_roots = tuple(resolved_roots)
        else:
            self._writable_roots = tuple(
                item.resolve(strict=True) for item in raw_writable_roots
            )
        self._attached = False
        # Popen authority is deliberately owned by this scope.  Callers may
        # supply the physical argv and Popen options, but cannot create a
        # process elsewhere and later claim that this scope owns it.
        self._process_creation_attempted = False
        self._process_creation_state = "NOT_ATTEMPTED"
        self._created_process: Any | None = None
        self._created_process_termination_proven = False
        # Windows creation returns only after the exact suspended process is
        # owned by this kill-on-close Job.  Linux creation returns only after
        # the trusted, still-gated helper is observed in the persistent cgroup.
        # These private facts refine PROCESS_CREATED without changing the
        # downstream five-field launch-evidence contract.
        self._windows_job_owned_suspended = False
        self._windows_primary_thread_handle: int | None = None
        self._linux_created_process_cgroup_membership_proven = False
        self._terminated = False
        self._population_zero = False
        self._emergency_closed = False
        self._closed = False
        if os.name == "nt":
            try:
                if not self._windows_job_only:
                    from windows_low_integrity_lease import (
                        WindowsLowIntegrityExecutionLease,
                    )

                    self._windows_write_lease = (
                        WindowsLowIntegrityExecutionLease(
                            writable_roots=raw_writable_roots,
                            writable_root_authorities=tuple(
                                windows_private_root_authorities
                            ),
                            owner_identity=self._persistent_identity,
                            acquisition_deadline_monotonic=(
                                lease_acquisition_deadline_monotonic
                            ),
                            cancel_token=lease_cancel_token,
                        )
                    )
                self._job_handle = self._create_windows_job()
            except Exception as exc:
                if self._windows_write_lease is not None:
                    try:
                        self._windows_write_lease.release_after_proven_closure()
                    except Exception:
                        pass
                boundary = (
                    "Windows Job-only descendant scope"
                    if self._windows_job_only
                    else "serialized Windows low-integrity scope"
                )
                raise OwnedProcessScopeError(
                    f"cannot establish the {boundary}: "
                    f"{type(exc).__name__}: {exc}"
                ) from exc
        elif (
            sys.platform.startswith("linux")
            and self._capability.get(
                "exhaustive_descendant_termination_authority"
            )
            is True
        ):
            root = Path(str(self._capability["delegated_root"]))
            cgroup = root / self._persistent_identity
            try:
                cgroup.mkdir(mode=0o700)
                for name in ("cgroup.events", "cgroup.kill", "cgroup.procs"):
                    member = cgroup / name
                    if not member.is_file() or member.is_symlink():
                        raise OwnedProcessScopeError(
                            f"cgroup-v2 scope lacks {name}"
                        )
                read_fd, write_fd = os.pipe()
                os.set_inheritable(read_fd, True)
                os.set_inheritable(write_fd, False)
                status_read, status_write = os.pipe()
                os.set_inheritable(status_read, False)
                os.set_inheritable(status_write, True)
            except BaseException:
                try:
                    cgroup.rmdir()
                except OSError:
                    pass
                raise
            self._linux_cgroup = cgroup
            self._linux_gate_read = read_fd
            self._linux_gate_write = write_fd
            self._linux_status_read = status_read
            self._linux_status_write = status_write
        elif (
            sys.platform == "darwin"
            and self._capability.get(
                "exhaustive_write_confinement_authority"
            )
            is True
        ):
            descriptors: list[int] = []
            pipe_descriptors: list[int] = []
            queue = None
            try:
                directory_flags = (
                    os.O_RDONLY
                    | os.O_DIRECTORY
                    | os.O_NOFOLLOW
                    | getattr(os, "O_CLOEXEC", 0)
                )
                for root in self._writable_roots:
                    descriptor = os.open(root, directory_flags)
                    if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
                        raise OwnedProcessScopeError(
                            "macOS writable-root descriptor is not a directory"
                        )
                    os.set_inheritable(descriptor, True)
                    descriptors.append(descriptor)
                gate_read, gate_write = os.pipe()
                status_read, status_write = os.pipe()
                pipe_descriptors.extend(
                    (gate_read, gate_write, status_read, status_write)
                )
                os.set_inheritable(gate_read, True)
                os.set_inheritable(gate_write, False)
                os.set_inheritable(status_read, False)
                os.set_inheritable(status_write, True)
                if self._capability.get(
                    "exhaustive_descendant_termination_authority"
                ) is True:
                    queue = select.kqueue()
            except BaseException:
                for descriptor in (*descriptors, *pipe_descriptors):
                    try:
                        os.close(descriptor)
                    except OSError:
                        pass
                if queue is not None:
                    queue.close()
                raise
            self._darwin_root_descriptors = tuple(descriptors)
            self._darwin_gate_read = gate_read
            self._darwin_gate_write = gate_write
            self._darwin_status_read = status_read
            self._darwin_status_write = status_write
            self._darwin_kqueue = queue
            self._darwin_seatbelt_provider = True

    @staticmethod
    def _create_windows_job() -> int:
        class _IoCounters(ctypes.Structure):
            _fields_ = [
                ("ReadOperationCount", ctypes.c_uint64),
                ("WriteOperationCount", ctypes.c_uint64),
                ("OtherOperationCount", ctypes.c_uint64),
                ("ReadTransferCount", ctypes.c_uint64),
                ("WriteTransferCount", ctypes.c_uint64),
                ("OtherTransferCount", ctypes.c_uint64),
            ]

        class _BasicLimit(ctypes.Structure):
            _fields_ = [
                ("PerProcessUserTimeLimit", ctypes.c_int64),
                ("PerJobUserTimeLimit", ctypes.c_int64),
                ("LimitFlags", ctypes.c_uint32),
                ("MinimumWorkingSetSize", ctypes.c_size_t),
                ("MaximumWorkingSetSize", ctypes.c_size_t),
                ("ActiveProcessLimit", ctypes.c_uint32),
                ("Affinity", ctypes.c_size_t),
                ("PriorityClass", ctypes.c_uint32),
                ("SchedulingClass", ctypes.c_uint32),
            ]

        class _ExtendedLimit(ctypes.Structure):
            _fields_ = [
                ("BasicLimitInformation", _BasicLimit),
                ("IoInfo", _IoCounters),
                ("ProcessMemoryLimit", ctypes.c_size_t),
                ("JobMemoryLimit", ctypes.c_size_t),
                ("PeakProcessMemoryUsed", ctypes.c_size_t),
                ("PeakJobMemoryUsed", ctypes.c_size_t),
            ]

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateJobObjectW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p]
        kernel32.CreateJobObjectW.restype = ctypes.c_void_p
        kernel32.SetInformationJobObject.argtypes = [
            ctypes.c_void_p,
            ctypes.c_int,
            ctypes.c_void_p,
            ctypes.c_uint32,
        ]
        kernel32.SetInformationJobObject.restype = ctypes.c_int
        kernel32.QueryInformationJobObject.argtypes = [
            ctypes.c_void_p,
            ctypes.c_int,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_uint32),
        ]
        kernel32.QueryInformationJobObject.restype = ctypes.c_int
        kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
        kernel32.CloseHandle.restype = ctypes.c_int
        handle = kernel32.CreateJobObjectW(None, None)
        if not handle:
            raise OwnedProcessScopeError(
                f"CreateJobObjectW failed: {ctypes.get_last_error()}"
            )
        limits = _ExtendedLimit()
        # Breakaway flags remain unset. Children therefore inherit the Job and
        # cannot request a permitted breakaway from this scope.
        limits.BasicLimitInformation.LimitFlags = (
            _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            | _JOB_OBJECT_LIMIT_ACTIVE_PROCESS
            | _JOB_OBJECT_LIMIT_JOB_MEMORY
        )
        limits.BasicLimitInformation.ActiveProcessLimit = (
            _WINDOWS_JOB_ACTIVE_PROCESS_LIMIT
        )
        limits.JobMemoryLimit = _WINDOWS_JOB_MEMORY_LIMIT_BYTES
        if not kernel32.SetInformationJobObject(
            handle,
            _JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
            ctypes.byref(limits),
            ctypes.sizeof(limits),
        ):
            error = ctypes.get_last_error()
            kernel32.CloseHandle(handle)
            raise OwnedProcessScopeError(
                f"SetInformationJobObject failed: {error}"
            )
        observed = _ExtendedLimit()
        returned = ctypes.c_uint32()
        if not kernel32.QueryInformationJobObject(
            handle,
            _JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
            ctypes.byref(observed),
            ctypes.sizeof(observed),
            ctypes.byref(returned),
        ):
            error = ctypes.get_last_error()
            kernel32.CloseHandle(handle)
            raise OwnedProcessScopeError(
                f"QueryInformationJobObject limit readback failed: {error}"
            )
        required_flags = (
            _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            | _JOB_OBJECT_LIMIT_ACTIVE_PROCESS
            | _JOB_OBJECT_LIMIT_JOB_MEMORY
        )
        if (
            returned.value != ctypes.sizeof(observed)
            or observed.BasicLimitInformation.LimitFlags & required_flags
            != required_flags
            or observed.BasicLimitInformation.ActiveProcessLimit
            != _WINDOWS_JOB_ACTIVE_PROCESS_LIMIT
            or observed.JobMemoryLimit != _WINDOWS_JOB_MEMORY_LIMIT_BYTES
        ):
            kernel32.CloseHandle(handle)
            raise OwnedProcessScopeError(
                "Windows Job resource-limit readback diverged"
            )
        return int(handle)

    def popen_kwargs(self) -> dict[str, Any]:
        if os.name == "nt":
            return {
                "creationflags": (
                    getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
                    | _CREATE_SUSPENDED
                )
            }
        if self._linux_cgroup is not None:
            if self._linux_gate_read is None:
                raise OwnedProcessScopeError("Linux cgroup gate is unavailable")
            if self._linux_status_write is None:
                raise OwnedProcessScopeError("Linux Landlock status pipe is unavailable")
            return {
                "start_new_session": True,
                "pass_fds": (
                    self._linux_gate_read,
                    self._linux_status_write,
                ),
            }
        if getattr(self, "_darwin_seatbelt_provider", False):
            if self._darwin_gate_read is None:
                raise OwnedProcessScopeError("macOS execution gate is unavailable")
            if self._darwin_status_write is None:
                raise OwnedProcessScopeError(
                    "macOS Seatbelt status pipe is unavailable"
                )
            return {
                "start_new_session": True,
                "pass_fds": (
                    self._darwin_gate_read,
                    self._darwin_status_write,
                    *self._darwin_root_descriptors,
                ),
            }
        return {"start_new_session": True}

    def create_process(
        self,
        physical_argv: list[str] | tuple[str, ...],
        *,
        popen_factory: Any | None = None,
        _windows_atomic_factory: Any | None = None,
        **popen_kwargs: Any,
    ) -> subprocess.Popen[bytes]:
        """Exercise this scope's one-shot process-creation authority.

        ``physical_argv`` is the already-wrapped command returned by
        :meth:`wrap_argv`; ``popen_kwargs`` accepts the existing cwd, env,
        stdio, shell, and platform-specific values.  The injected factory is a
        fixture seam only.  Production callers omit it and therefore execute
        :class:`subprocess.Popen` here, inside the owning scope.

        The private attempted bit is set immediately before invoking the
        creation provider.  A provider exception is the only transition to
        ``CREATION_FAILED_WITHOUT_PROCESS_OBJECT``.  Any returned object is
        recorded by identity and transitions immediately to
        ``PROCESS_CREATED``.  A Windows process is created suspended with this
        scope's kill-on-close Job in ``PROC_THREAD_ATTRIBUTE_JOB_LIST``; there
        is no post-create assignment interval.  A
        Linux trusted helper is observed in this scope's persistent cgroup.
        Only a successful :meth:`attach` may then advance the public state to
        ``ATTACHED``.
        """

        if self._closed:
            raise OwnedProcessScopeError(
                "process cannot be created in a closed process scope"
            )
        if self._process_creation_attempted:
            raise OwnedProcessScopeError(
                "process creation was already attempted for this scope"
            )
        if (
            not isinstance(physical_argv, (list, tuple))
            or not physical_argv
            or any(
                not isinstance(item, str) or not item
                for item in physical_argv
            )
        ):
            raise OwnedProcessScopeError(
                "process creation requires a non-empty physical argv"
            )
        windows_job_creation = os.name == "nt" and self._job_handle is not None
        if windows_job_creation:
            if popen_factory is not None:
                raise OwnedProcessScopeError(
                    "Windows Job creation rejects non-atomic Popen factories"
                )
            creationflags = popen_kwargs.get("creationflags")
            if (
                isinstance(creationflags, bool)
                or not isinstance(creationflags, int)
                or creationflags & _CREATE_SUSPENDED != _CREATE_SUSPENDED
            ):
                raise OwnedProcessScopeError(
                    "Windows Job-owned process creation requires "
                    "CREATE_SUSPENDED before the factory is invoked"
                )
            if _windows_atomic_factory is None:
                def factory(argv: list[str], **kwargs: Any) -> Any:
                    return _WindowsAtomicJobPopen(
                        int(self._job_handle), argv, **kwargs
                    )
            else:
                if not callable(_windows_atomic_factory):
                    raise OwnedProcessScopeError(
                        "Windows atomic process factory must be callable"
                    )
                atomic_factory = _windows_atomic_factory

                def factory(argv: list[str], **kwargs: Any) -> Any:
                    return atomic_factory(
                        int(self._job_handle), argv, **kwargs
                    )
        else:
            if _windows_atomic_factory is not None:
                raise OwnedProcessScopeError(
                    "Windows atomic process factory is unavailable on this host"
                )
            factory = subprocess.Popen if popen_factory is None else popen_factory
            if not callable(factory):
                raise OwnedProcessScopeError("Popen factory must be callable")

        if getattr(self, "_darwin_seatbelt_provider", False):
            if self._darwin_gate_read is None or self._darwin_status_write is None:
                raise OwnedProcessScopeError(
                    "macOS Seatbelt descriptor authority is unavailable"
                )
            _darwin_validate_inherited_descriptors(
                popen_kwargs,
                expected_pass_fds=(
                    self._darwin_gate_read,
                    self._darwin_status_write,
                    *self._darwin_root_descriptors,
                ),
                writable_roots=self._writable_roots,
            )
            if popen_kwargs.get("shell", False) is not False:
                raise OwnedProcessScopeError(
                    "macOS Seatbelt process creation rejects shell transport"
                )

        self._process_creation_attempted = True
        try:
            process = factory(list(physical_argv), **popen_kwargs)
        except _WindowsAtomicPopenConstructionError as exc:
            self._process_creation_state = (
                PROCESS_CREATED_BUT_NOT_RETURNED_TERMINATED
                if exc.termination_proven
                else PROCESS_CREATED_BUT_NOT_RETURNED_CONTAINED
            )
            self._created_process_termination_proven = exc.termination_proven
            raise
        except BaseException:
            self._process_creation_state = (
                "CREATION_FAILED_WITHOUT_PROCESS_OBJECT"
            )
            raise
        self._created_process = process
        self._process_creation_state = "PROCESS_CREATED"
        try:
            if windows_job_creation:
                take_thread = getattr(
                    process, "_take_primary_thread_handle", None
                )
                if not callable(take_thread):
                    raise OwnedProcessScopeError(
                        "atomic Windows provider did not return the exact "
                        "primary-thread capability"
                    )
                thread_handle = take_thread()
                if (
                    isinstance(thread_handle, bool)
                    or not isinstance(thread_handle, int)
                    or thread_handle <= 0
                ):
                    raise OwnedProcessScopeError(
                        "atomic Windows primary-thread handle is invalid"
                    )
                self._windows_primary_thread_handle = thread_handle
                # The native CreateProcessW call cannot succeed unless Windows
                # has already assigned the process to the complete Job list.
                self._windows_job_owned_suspended = True
            elif self._linux_cgroup is not None:
                self._wait_linux_created_process_cgroup_membership(process)
                self._linux_created_process_cgroup_membership_proven = True
            elif getattr(self, "_darwin_seatbelt_provider", False):
                if getattr(self, "_darwin_kqueue", None) is not None:
                    self._register_darwin_created_process(process)
                else:
                    if process.poll() is not None:
                        raise OwnedProcessScopeError(
                            "trusted macOS Seatbelt helper exited before attach"
                        )
                    if os.getpgid(int(process.pid)) != int(process.pid):
                        raise OwnedProcessScopeError(
                            "trusted macOS Seatbelt helper lacks isolated process group"
                        )
        except BaseException as exc:
            boundary = (
                "Windows Job"
                if windows_job_creation
                else (
                    "Linux persistent cgroup"
                    if self._linux_cgroup is not None
                    else (
                        "macOS kqueue process tracker"
                        if getattr(self, "_darwin_kqueue", None) is not None
                        else "macOS Seatbelt pre-exec gate"
                    )
                )
            )
            try:
                self.terminate_created_process()
            except BaseException as cleanup_exc:
                raise OwnedProcessScopeError(
                    f"created process could not enter its {boundary}, and "
                    "exact-process cleanup also failed"
                ) from cleanup_exc
            raise OwnedProcessScopeError(
                f"created process could not be assigned to its {boundary}; "
                "the exact suspended/gated process was killed and reaped"
            ) from exc
        return process

    def _prove_windows_created_process_job_membership(
        self,
        process: subprocess.Popen[bytes],
    ) -> bool:
        """Observe Job membership through the exact private process handle."""

        handle = getattr(process, "_handle", None)
        if handle is None or self._job_handle is None:
            raise OwnedProcessScopeError(
                "Windows process/job handle is unavailable"
            )
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.IsProcessInJob.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_int),
        ]
        kernel32.IsProcessInJob.restype = ctypes.c_int
        in_job = ctypes.c_int()
        if not kernel32.IsProcessInJob(
            ctypes.c_void_p(int(handle)),
            ctypes.c_void_p(self._job_handle),
            ctypes.byref(in_job),
        ):
            raise OwnedProcessScopeError(
                "IsProcessInJob failed for the exact created process: "
                f"{ctypes.get_last_error()}"
            )
        return bool(in_job.value)

    def _wait_linux_created_process_cgroup_membership(
        self,
        process: subprocess.Popen[bytes],
    ) -> None:
        """Prove the gated helper entered the persistent cgroup before return."""

        if self._linux_cgroup is None:
            raise OwnedProcessScopeError("Linux cgroup gate is unavailable")
        deadline = time.monotonic() + self._population_zero_timeout_seconds
        procs = self._linux_cgroup / "cgroup.procs"
        while True:
            try:
                members = {
                    int(item)
                    for item in procs.read_text(encoding="ascii").split()
                }
            except (OSError, ValueError) as exc:
                raise OwnedProcessScopeError(
                    "cannot observe Linux cgroup membership"
                ) from exc
            if process.pid in members:
                return
            try:
                exited = process.poll() is not None
            except BaseException as exc:
                raise OwnedProcessScopeError(
                    "cannot observe the trusted Linux helper"
                ) from exc
            if exited:
                raise OwnedProcessScopeError(
                    "trusted Linux helper exited before entering the cgroup"
                )
            if time.monotonic() >= deadline:
                raise OwnedProcessScopeError(
                    "trusted Linux helper did not enter the cgroup"
                )
            time.sleep(0.005)

    def _register_darwin_created_process(
        self,
        process: subprocess.Popen[bytes],
    ) -> None:
        """Register the still-gated helper for recursive kernel tracking."""

        if getattr(self, "_darwin_kqueue", None) is None:
            raise OwnedProcessScopeError("macOS kqueue tracker is unavailable")
        change = select.kevent(
            process.pid,
            filter=select.KQ_FILTER_PROC,
            flags=(
                select.KQ_EV_ADD
                | select.KQ_EV_ENABLE
                | select.KQ_EV_CLEAR
            ),
            fflags=(
                select.KQ_NOTE_EXIT
                | select.KQ_NOTE_FORK
                | select.KQ_NOTE_TRACK
            ),
        )
        try:
            self._darwin_kqueue.control([change], 0, 0)
        except OSError as exc:
            raise OwnedProcessScopeError(
                "kernel rejected recursive macOS process tracking"
            ) from exc
        self._darwin_tracked_processes.add(int(process.pid))
        self._drain_darwin_process_events(timeout_seconds=0.0)
        if process.poll() is not None:
            raise OwnedProcessScopeError(
                "trusted macOS helper exited before tracker admission"
            )

    def _drain_darwin_process_events(self, *, timeout_seconds: float) -> None:
        if getattr(self, "_darwin_kqueue", None) is None:
            raise OwnedProcessScopeError("macOS kqueue tracker is unavailable")
        if self._darwin_tracking_error is not None:
            raise OwnedProcessScopeError(self._darwin_tracking_error)
        timeout = max(0.0, float(timeout_seconds))
        observed = 0
        while True:
            try:
                events = self._darwin_kqueue.control(None, 256, timeout)
            except OSError as exc:
                self._darwin_tracking_error = (
                    "macOS kqueue process observation failed"
                )
                raise OwnedProcessScopeError(
                    self._darwin_tracking_error
                ) from exc
            observed += len(events)
            if observed > 65_536:
                self._darwin_tracking_error = (
                    "macOS kqueue event drain exceeded its safety bound"
                )
                raise OwnedProcessScopeError(self._darwin_tracking_error)
            for event in events:
                if int(event.flags) & select.KQ_EV_ERROR:
                    self._darwin_tracking_error = (
                        "macOS kernel returned an error process event; "
                        "descendant scope is no longer exhaustive"
                    )
                    raise OwnedProcessScopeError(self._darwin_tracking_error)
                flags = int(event.fflags)
                if flags & select.KQ_NOTE_TRACKERR:
                    self._darwin_tracking_error = (
                        "macOS kernel reported NOTE_TRACKERR; descendant scope "
                        "is no longer exhaustive"
                    )
                    raise OwnedProcessScopeError(self._darwin_tracking_error)
                process_id = int(event.ident)
                if flags & select.KQ_NOTE_CHILD:
                    # NOTE_CHILD is emitted only after the kernel has installed
                    # the inherited tracking knote for this exact child.
                    self._darwin_tracked_processes.add(process_id)
                if flags & select.KQ_NOTE_EXIT:
                    self._darwin_tracked_processes.discard(process_id)
            if len(events) < 256:
                return
            timeout = 0.0

    def _wait_darwin_population_zero(self) -> None:
        deadline = time.monotonic() + self._population_zero_timeout_seconds
        while self._darwin_tracked_processes:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise OwnedProcessScopeError(
                    "macOS tracked process tree remained populated"
                )
            self._drain_darwin_process_events(
                timeout_seconds=min(remaining, 0.05)
            )
        self._population_zero = True

    def _close_darwin_descriptors(self) -> None:
        for field in (
            "_darwin_gate_read",
            "_darwin_gate_write",
            "_darwin_status_read",
            "_darwin_status_write",
        ):
            descriptor = getattr(self, field, None)
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
                setattr(self, field, None)
        for descriptor in getattr(self, "_darwin_root_descriptors", ()):
            try:
                os.close(descriptor)
            except OSError:
                pass
        self._darwin_root_descriptors = ()

    def terminate_created_process(
        self,
        *,
        timeout_seconds: float = 10.0,
    ) -> None:
        """Kill and reap the exact returned process after attachment failure.

        This is deliberately distinct from :meth:`terminate`, which operates
        on an attached Job/cgroup/process-group scope.  The method accepts no
        caller-supplied process identity: it can act only on the exact private
        object returned by :meth:`create_process`.  Proof becomes true only
        after that object is observed exited and successfully reaped.
        """

        if self._created_process_termination_proven:
            return
        if (
            self._process_creation_state != "PROCESS_CREATED"
            or self._created_process is None
        ):
            raise OwnedProcessScopeError(
                "no exact created process is available for termination"
            )
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or timeout_seconds <= 0
        ):
            raise OwnedProcessScopeError(
                "created-process termination timeout must be positive"
            )
        process = self._created_process
        try:
            running = process.poll() is None
        except BaseException as exc:
            if os.name == "nt":
                self._close_exact_windows_primary_thread()
            raise OwnedProcessScopeError(
                "exact created process could not be observed"
            ) from exc
        if running:
            try:
                process.kill()
            except BaseException as exc:
                if os.name == "nt":
                    self._close_exact_windows_primary_thread()
                raise OwnedProcessScopeError(
                    "exact created process could not be killed"
                ) from exc
        try:
            process.wait(timeout=float(timeout_seconds))
        except subprocess.TimeoutExpired as exc:
            if os.name == "nt":
                self._close_exact_windows_primary_thread()
            raise OwnedProcessScopeError(
                "exact created process did not exit before timeout"
            ) from exc
        except BaseException as exc:
            if os.name == "nt":
                self._close_exact_windows_primary_thread()
            raise OwnedProcessScopeError(
                "exact created process could not be reaped"
            ) from exc
        try:
            if process.poll() is None:
                raise OwnedProcessScopeError(
                    "exact created process did not exit after wait"
                )
        except OwnedProcessScopeError:
            if os.name == "nt":
                self._close_exact_windows_primary_thread()
            raise
        except BaseException as exc:
            if os.name == "nt":
                self._close_exact_windows_primary_thread()
            raise OwnedProcessScopeError(
                "exact created process exit could not be observed"
            ) from exc
        if os.name == "nt":
            self._close_exact_windows_primary_thread()
        self._created_process_termination_proven = True

    def wrap_argv(self, argv: list[str] | tuple[str, ...]) -> list[str]:
        """Return the exact physical argv needed for pre-exec containment."""

        command = [str(item) for item in argv]
        if not command or not Path(command[0]).is_absolute():
            raise OwnedProcessScopeError(
                "owned process argv requires an absolute executable"
            )
        if (
            self._linux_cgroup is None
            and not getattr(self, "_darwin_seatbelt_provider", False)
        ):
            return command
        if getattr(self, "_darwin_seatbelt_provider", False):
            if self._darwin_gate_read is None:
                raise OwnedProcessScopeError("macOS execution gate is unavailable")
            if self._darwin_status_write is None:
                raise OwnedProcessScopeError(
                    "macOS Seatbelt status pipe is unavailable"
                )
            helper = str(self._capability["helper_path"])
            interpreter = str(self._capability["interpreter_path"])
            sandbox_exec = str(self._capability["sandbox_exec_path"])
            return [
                sandbox_exec,
                "-p",
                _darwin_seatbelt_profile(self._writable_roots),
                interpreter,
                "-I",
                "-S",
                helper,
                str(self._darwin_gate_read),
                str(self._darwin_status_write),
                str(len(self._darwin_root_descriptors)),
                *(
                    value
                    for descriptor, root in zip(
                        self._darwin_root_descriptors,
                        self._writable_roots,
                    )
                    for value in (str(descriptor), os.fspath(root))
                ),
                "--",
                *command,
            ]
        if self._linux_gate_read is None:
            raise OwnedProcessScopeError("Linux cgroup gate is unavailable")
        if self._linux_status_write is None:
            raise OwnedProcessScopeError("Linux Landlock status pipe is unavailable")
        helper = str(self._capability["helper_path"])
        interpreter = str(self._capability["interpreter_path"])
        return [
            interpreter,
            "-I",
            "-S",
            helper,
            str(self._linux_cgroup / "cgroup.procs"),
            str(self._linux_gate_read),
            str(self._linux_status_write),
            *(str(root) for root in self._writable_roots),
            "--",
            *command,
        ]

    @staticmethod
    def _resume_only_thread(process_id: int) -> None:
        class _ThreadEntry(ctypes.Structure):
            _fields_ = [
                ("dwSize", ctypes.c_uint32),
                ("cntUsage", ctypes.c_uint32),
                ("th32ThreadID", ctypes.c_uint32),
                ("th32OwnerProcessID", ctypes.c_uint32),
                ("tpBasePri", ctypes.c_long),
                ("tpDeltaPri", ctypes.c_long),
                ("dwFlags", ctypes.c_uint32),
            ]

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateToolhelp32Snapshot.argtypes = [
            ctypes.c_uint32,
            ctypes.c_uint32,
        ]
        kernel32.CreateToolhelp32Snapshot.restype = ctypes.c_void_p
        kernel32.Thread32First.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(_ThreadEntry),
        ]
        kernel32.Thread32First.restype = ctypes.c_int
        kernel32.Thread32Next.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(_ThreadEntry),
        ]
        kernel32.Thread32Next.restype = ctypes.c_int
        kernel32.OpenThread.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
        kernel32.OpenThread.restype = ctypes.c_void_p
        kernel32.ResumeThread.argtypes = [ctypes.c_void_p]
        kernel32.ResumeThread.restype = ctypes.c_uint32
        kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
        kernel32.CloseHandle.restype = ctypes.c_int

        snapshot = kernel32.CreateToolhelp32Snapshot(_TH32CS_SNAPTHREAD, 0)
        if not snapshot or int(snapshot) == _INVALID_HANDLE_VALUE:
            raise OwnedProcessScopeError(
                f"CreateToolhelp32Snapshot failed: {ctypes.get_last_error()}"
            )
        thread_ids: list[int] = []
        try:
            entry = _ThreadEntry()
            entry.dwSize = ctypes.sizeof(entry)
            present = kernel32.Thread32First(snapshot, ctypes.byref(entry))
            while present:
                if int(entry.th32OwnerProcessID) == process_id:
                    thread_ids.append(int(entry.th32ThreadID))
                entry.dwSize = ctypes.sizeof(entry)
                present = kernel32.Thread32Next(snapshot, ctypes.byref(entry))
        finally:
            kernel32.CloseHandle(snapshot)
        if len(thread_ids) != 1:
            raise OwnedProcessScopeError(
                "suspended worker does not have exactly one primary thread"
            )
        thread = kernel32.OpenThread(
            _THREAD_SUSPEND_RESUME, False, thread_ids[0]
        )
        if not thread:
            raise OwnedProcessScopeError(
                f"OpenThread failed: {ctypes.get_last_error()}"
            )
        try:
            prior = kernel32.ResumeThread(thread)
            if prior == 0xFFFFFFFF or prior != 1:
                raise OwnedProcessScopeError(
                    f"worker resume returned unexpected suspend count {prior}"
                )
        finally:
            kernel32.CloseHandle(thread)

    def _resume_exact_windows_primary_thread(
        self,
        *,
        kernel32: Any | None = None,
    ) -> None:
        """Resume and close only the primary-thread capability from creation."""

        handle = getattr(self, "_windows_primary_thread_handle", None)
        if handle is None:
            raise OwnedProcessScopeError(
                "exact Windows primary-thread handle is unavailable"
            )
        api = (
            ctypes.WinDLL("kernel32", use_last_error=True)
            if kernel32 is None
            else kernel32
        )
        api.ResumeThread.argtypes = [ctypes.c_void_p]
        api.ResumeThread.restype = ctypes.c_uint32
        api.CloseHandle.argtypes = [ctypes.c_void_p]
        api.CloseHandle.restype = ctypes.c_int
        try:
            prior = int(api.ResumeThread(ctypes.c_void_p(handle)))
            if prior == 0xFFFFFFFF or prior != 1:
                raise OwnedProcessScopeError(
                    "exact worker primary-thread resume returned unexpected "
                    f"suspend count {prior}"
                )
        finally:
            if not api.CloseHandle(ctypes.c_void_p(handle)):
                raise OwnedProcessScopeError(
                    "exact Windows primary-thread handle could not be closed"
                )
            self._windows_primary_thread_handle = None

    def _close_exact_windows_primary_thread(
        self,
        *,
        kernel32: Any | None = None,
    ) -> None:
        handle = getattr(self, "_windows_primary_thread_handle", None)
        if handle is None:
            return
        api = (
            ctypes.WinDLL("kernel32", use_last_error=True)
            if kernel32 is None
            else kernel32
        )
        api.CloseHandle.argtypes = [ctypes.c_void_p]
        api.CloseHandle.restype = ctypes.c_int
        if not api.CloseHandle(ctypes.c_void_p(handle)):
            raise OwnedProcessScopeError(
                "exact Windows primary-thread handle could not be closed"
            )
        self._windows_primary_thread_handle = None

    def attach(self, process: subprocess.Popen[bytes]) -> None:
        if self._attached or self._closed:
            raise OwnedProcessScopeError("process scope cannot be attached")
        if self._created_process_termination_proven:
            raise OwnedProcessScopeError(
                "terminated created process cannot be attached"
            )
        if (
            self._process_creation_state != "PROCESS_CREATED"
            or process is not self._created_process
        ):
            raise OwnedProcessScopeError(
                "process was not created by this process scope"
            )
        if os.name == "nt":
            handle = getattr(process, "_handle", None)
            if handle is None or self._job_handle is None:
                raise OwnedProcessScopeError("Windows process/job handle is unavailable")
            if not self._windows_job_owned_suspended:
                raise OwnedProcessScopeError(
                    "Windows process was not Job-owned before create returned"
                )
            if not self._prove_windows_created_process_job_membership(process):
                raise OwnedProcessScopeError(
                    "exact created process is not a member of its Windows Job"
                )
            if not getattr(self, "_windows_job_only", False):
                self._windows_integrity_sid = _lower_windows_process_integrity(
                    int(handle)
                )
            self._attached = True
            self._resume_exact_windows_primary_thread()
            self._process_creation_state = "ATTACHED"
            return
        if self._linux_cgroup is not None:
            if not self._linux_created_process_cgroup_membership_proven:
                raise OwnedProcessScopeError(
                    "Linux helper cgroup membership was not proven before "
                    "create returned"
                )
            for field in ("_linux_gate_read", "_linux_status_write"):
                descriptor = getattr(self, field)
                if descriptor is not None:
                    try:
                        os.close(descriptor)
                    except OSError:
                        pass
                    setattr(self, field, None)
            # Re-observe rather than treating the create-time fact as durable:
            # a helper that exited between create and attach must not receive a
            # gate acknowledgement or ATTACHED authority.
            self._wait_linux_created_process_cgroup_membership(process)
            deadline = time.monotonic() + self._population_zero_timeout_seconds
            if self._linux_status_read is None:
                raise OwnedProcessScopeError(
                    "Linux Landlock status reader is unavailable"
                )
            remaining = max(0.0, deadline - time.monotonic())
            readable, _, _ = select.select(
                [self._linux_status_read],
                [],
                [],
                remaining,
            )
            if not readable:
                raise OwnedProcessScopeError(
                    "trusted Linux helper did not prove Landlock confinement"
                )
            status = os.read(self._linux_status_read, 64)
            try:
                text = status.decode("ascii", errors="strict")
                prefix, abi_text = text.strip().split(":", 1)
                abi = int(abi_text, 10)
            except (UnicodeError, ValueError) as exc:
                raise OwnedProcessScopeError(
                    "trusted Linux helper emitted malformed confinement status"
                ) from exc
            if prefix != "LANDLOCK_READY" or abi < 1:
                raise OwnedProcessScopeError(
                    "trusted Linux helper did not activate Landlock"
                )
            self._linux_landlock_abi = abi
            os.close(self._linux_status_read)
            self._linux_status_read = None
            try:
                raw = Path(f"/proc/{process.pid}/stat").read_text(
                    encoding="ascii"
                )
                tail = raw[raw.rfind(")") + 2 :].split()
                start_ticks = tail[19]
                if not start_ticks.isdigit():
                    raise ValueError("non-numeric procfs start ticks")
            except (OSError, IndexError, ValueError) as exc:
                raise OwnedProcessScopeError(
                    "cannot bind Linux helper process start identity"
                ) from exc
            self._pre_release_process_identity = {
                "kind": "POSIX_PROCFS_START_TICKS",
                "value": start_ticks,
            }
            self._attached = True
            try:
                if self._linux_gate_write is None:
                    raise OwnedProcessScopeError("Linux cgroup gate is unavailable")
                if os.write(self._linux_gate_write, b"1") != 1:
                    raise OwnedProcessScopeError(
                        "Linux cgroup helper acknowledgement was truncated"
                    )
            finally:
                for field in (
                    "_linux_gate_read",
                    "_linux_gate_write",
                    "_linux_status_read",
                    "_linux_status_write",
                ):
                    descriptor = getattr(self, field)
                    if descriptor is not None:
                        try:
                            os.close(descriptor)
                        except OSError:
                            pass
                        setattr(self, field, None)
            self._process_creation_state = "ATTACHED"
            return
        if getattr(self, "_darwin_seatbelt_provider", False):
            if getattr(self, "_darwin_kqueue", None) is not None:
                self._drain_darwin_process_events(timeout_seconds=0.0)
                if int(process.pid) not in self._darwin_tracked_processes:
                    raise OwnedProcessScopeError(
                        "trusted macOS helper left its tracked scope before attach"
                    )
            else:
                try:
                    group_id = os.getpgid(int(process.pid))
                except OSError as exc:
                    raise OwnedProcessScopeError(
                        "cannot re-observe macOS helper process group"
                    ) from exc
                if group_id != int(process.pid):
                    raise OwnedProcessScopeError(
                        "macOS helper process group identity drifted before attach"
                    )
            for field in ("_darwin_gate_read", "_darwin_status_write"):
                descriptor = getattr(self, field)
                if descriptor is not None:
                    try:
                        os.close(descriptor)
                    except OSError:
                        pass
                    setattr(self, field, None)
            deadline = time.monotonic() + self._population_zero_timeout_seconds
            if self._darwin_status_read is None:
                raise OwnedProcessScopeError(
                    "macOS Seatbelt status reader is unavailable"
                )
            readable, _, _ = select.select(
                [self._darwin_status_read],
                [],
                [],
                max(0.0, deadline - time.monotonic()),
            )
            if not readable:
                raise OwnedProcessScopeError(
                    "trusted macOS helper did not prove Seatbelt confinement"
                )
            status = os.read(self._darwin_status_read, 64)
            if status != b"SEATBELT_READY:1\n":
                raise OwnedProcessScopeError(
                    "trusted macOS helper emitted malformed confinement status"
                )
            os.close(self._darwin_status_read)
            self._darwin_status_read = None
            self._darwin_seatbelt_active = True
            self._attached = True
            self._process_group_id = int(process.pid)
            try:
                if self._darwin_gate_write is None:
                    raise OwnedProcessScopeError(
                        "macOS execution gate is unavailable"
                    )
                if os.write(self._darwin_gate_write, b"1") != 1:
                    raise OwnedProcessScopeError(
                        "macOS helper acknowledgement was truncated"
                    )
            finally:
                for field in (
                    "_darwin_gate_read",
                    "_darwin_gate_write",
                    "_darwin_status_read",
                    "_darwin_status_write",
                ):
                    descriptor = getattr(self, field)
                    if descriptor is not None:
                        try:
                            os.close(descriptor)
                        except OSError:
                            pass
                        setattr(self, field, None)
                for descriptor in self._darwin_root_descriptors:
                    try:
                        os.close(descriptor)
                    except OSError:
                        pass
                self._darwin_root_descriptors = ()
            self._process_creation_state = "ATTACHED"
            return
        try:
            group_id = os.getpgid(process.pid)
        except OSError as exc:
            raise OwnedProcessScopeError(
                "cannot observe provider process group"
            ) from exc
        if group_id != process.pid:
            raise OwnedProcessScopeError(
                "worker is not its own process-group leader"
            )
        self._process_group_id = group_id
        self._attached = True
        self._process_creation_state = "ATTACHED"

    def contains_process_id(self, process_id: int) -> bool:
        """Prove whether a live PID belongs to this exact owned scope.

        This is used by interactive transports whose trusted host reports a
        separately spawned model PID.  A PID claim alone is not authority: the
        provider mechanically checks Job/cgroup membership before accepting it.
        """

        if (
            isinstance(process_id, bool)
            or not isinstance(process_id, int)
            or process_id <= 0
        ):
            raise OwnedProcessScopeError("process id must be a positive integer")
        if not self._attached or self._closed:
            raise OwnedProcessScopeError(
                "process-scope membership is unavailable before attach or after close"
            )
        if os.name == "nt":
            if self._job_handle is None:
                raise OwnedProcessScopeError("Windows Job handle is unavailable")
            from ctypes import wintypes

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel32.OpenProcess.argtypes = [
                wintypes.DWORD,
                wintypes.BOOL,
                wintypes.DWORD,
            ]
            kernel32.OpenProcess.restype = wintypes.HANDLE
            kernel32.IsProcessInJob.argtypes = [
                wintypes.HANDLE,
                wintypes.HANDLE,
                ctypes.POINTER(wintypes.BOOL),
            ]
            kernel32.IsProcessInJob.restype = wintypes.BOOL
            kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
            kernel32.CloseHandle.restype = wintypes.BOOL
            process_handle = kernel32.OpenProcess(
                0x1000,  # PROCESS_QUERY_LIMITED_INFORMATION
                False,
                process_id,
            )
            if not process_handle:
                raise OwnedProcessScopeError(
                    "cannot open the reported Windows process for membership proof: "
                    f"{ctypes.get_last_error()}"
                )
            try:
                in_job = wintypes.BOOL()
                if not kernel32.IsProcessInJob(
                    process_handle,
                    wintypes.HANDLE(self._job_handle),
                    ctypes.byref(in_job),
                ):
                    raise OwnedProcessScopeError(
                        "IsProcessInJob failed for the reported process: "
                        f"{ctypes.get_last_error()}"
                    )
                return bool(in_job.value)
            finally:
                kernel32.CloseHandle(process_handle)
        if self._linux_cgroup is not None:
            try:
                members = {
                    int(item)
                    for item in (
                        self._linux_cgroup / "cgroup.procs"
                    ).read_text(encoding="ascii").split()
                }
            except (OSError, ValueError) as exc:
                raise OwnedProcessScopeError(
                    "cannot observe Linux cgroup membership"
                ) from exc
            return process_id in members
        if getattr(self, "_darwin_kqueue", None) is not None:
            self._drain_darwin_process_events(timeout_seconds=0.0)
            return process_id in self._darwin_tracked_processes
        raise OwnedProcessScopeError(
            "diagnostic process groups cannot prove exact scope membership"
        )

    def terminate(self) -> None:
        if self._terminated:
            return
        if not self._attached:
            raise OwnedProcessScopeError("process scope was not attached")
        if os.name == "nt":
            if self._job_handle is None:
                raise OwnedProcessScopeError("Windows Job handle is unavailable")
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel32.TerminateJobObject.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
            kernel32.TerminateJobObject.restype = ctypes.c_int
            if not kernel32.TerminateJobObject(
                ctypes.c_void_p(self._job_handle), 1
            ):
                raise OwnedProcessScopeError(
                    f"TerminateJobObject failed: {ctypes.get_last_error()}"
                )
        elif self._linux_cgroup is not None:
            try:
                (self._linux_cgroup / "cgroup.kill").write_text(
                    "1\n", encoding="ascii"
                )
            except OSError as exc:
                raise OwnedProcessScopeError(
                    "Linux cgroup.kill failed"
                ) from exc
        elif getattr(self, "_darwin_kqueue", None) is not None:
            deadline = time.monotonic() + self._population_zero_timeout_seconds
            while self._darwin_tracked_processes:
                self._drain_darwin_process_events(timeout_seconds=0.0)
                for process_id in tuple(self._darwin_tracked_processes):
                    try:
                        os.kill(process_id, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    except OSError as exc:
                        raise OwnedProcessScopeError(
                            "macOS tracked-process termination failed"
                        ) from exc
                if time.monotonic() >= deadline:
                    raise OwnedProcessScopeError(
                        "macOS tracked process tree could not be terminated"
                    )
                self._drain_darwin_process_events(timeout_seconds=0.01)
        else:
            if self._process_group_id is None:
                raise OwnedProcessScopeError("process group is unavailable")
            try:
                os.killpg(self._process_group_id, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except OSError as exc:
                raise OwnedProcessScopeError(
                    "process group termination failed"
                ) from exc
        self._terminated = True

    def _wait_windows_population_zero(self) -> None:
        class _BasicAccounting(ctypes.Structure):
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

        if self._job_handle is None:
            raise OwnedProcessScopeError("Windows Job handle is unavailable")
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.QueryInformationJobObject.argtypes = [
            ctypes.c_void_p,
            ctypes.c_int,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_uint32),
        ]
        kernel32.QueryInformationJobObject.restype = ctypes.c_int
        deadline = time.monotonic() + self._population_zero_timeout_seconds
        while True:
            accounting = _BasicAccounting()
            returned = ctypes.c_uint32()
            if not kernel32.QueryInformationJobObject(
                ctypes.c_void_p(self._job_handle),
                _JOB_OBJECT_BASIC_ACCOUNTING_INFORMATION,
                ctypes.byref(accounting),
                ctypes.sizeof(accounting),
                ctypes.byref(returned),
            ):
                raise OwnedProcessScopeError(
                    "QueryInformationJobObject failed while proving zero "
                    f"population: {ctypes.get_last_error()}"
                )
            if int(accounting.ActiveProcesses) == 0:
                self._population_zero = True
                return
            if time.monotonic() >= deadline:
                raise OwnedProcessScopeError(
                    "Windows Job remained populated after termination"
                )
            time.sleep(0.01)

    def close(self) -> None:
        if self._closed:
            return
        if os.name == "nt" and self._job_handle is not None:
            if (
                self._attached
                and not self._terminated
                and not self._created_process_termination_proven
            ):
                raise OwnedProcessScopeError(
                    "cannot close an attached scope before explicit termination"
                )
            self._wait_windows_population_zero()
            self._close_exact_windows_primary_thread()
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
            kernel32.CloseHandle.restype = ctypes.c_int
            if not kernel32.CloseHandle(ctypes.c_void_p(self._job_handle)):
                raise OwnedProcessScopeError(
                    f"CloseHandle(Job Object) failed: {ctypes.get_last_error()}"
                )
            self._job_handle = None
            if not getattr(self, "_windows_job_only", False):
                if self._windows_write_lease is None:
                    raise OwnedProcessScopeError(
                        "Windows low-integrity execution lease is unavailable"
                    )
                try:
                    self._windows_write_lease.release_after_proven_closure()
                except Exception as exc:
                    raise OwnedProcessScopeError(
                        "Windows low-integrity roots or lease could not be restored: "
                        f"{type(exc).__name__}: {exc}"
                    ) from exc
        elif self._linux_cgroup is not None:
            if (
                self._attached
                and not self._terminated
                and not self._created_process_termination_proven
            ):
                raise OwnedProcessScopeError(
                    "cannot close an attached cgroup before termination"
                )
            for field in (
                "_linux_gate_read",
                "_linux_gate_write",
                "_linux_status_read",
                "_linux_status_write",
            ):
                descriptor = getattr(self, field)
                if descriptor is not None:
                    try:
                        os.close(descriptor)
                    except OSError:
                        pass
                    setattr(self, field, None)
            events = self._linux_cgroup / "cgroup.events"
            deadline = time.monotonic() + self._population_zero_timeout_seconds
            while True:
                try:
                    values = dict(
                        line.split(maxsplit=1)
                        for line in events.read_text(encoding="ascii").splitlines()
                    )
                except (OSError, ValueError) as exc:
                    raise OwnedProcessScopeError(
                        "cannot read Linux cgroup.events"
                    ) from exc
                if values.get("populated") == "0":
                    self._population_zero = True
                    break
                if time.monotonic() >= deadline:
                    raise OwnedProcessScopeError(
                        "Linux cgroup remained populated after termination"
                    )
                time.sleep(0.01)
            try:
                self._linux_cgroup.rmdir()
            except OSError as exc:
                raise OwnedProcessScopeError(
                    "Linux cgroup cleanup failed"
                ) from exc
            self._linux_cgroup = None
        elif getattr(self, "_darwin_kqueue", None) is not None:
            if (
                self._attached
                and not self._terminated
                and not self._created_process_termination_proven
            ):
                raise OwnedProcessScopeError(
                    "cannot close an attached macOS scope before termination"
                )
            self._close_darwin_descriptors()
            if self._darwin_tracked_processes:
                self._wait_darwin_population_zero()
            else:
                self._population_zero = True
            self._darwin_kqueue.close()
            self._darwin_kqueue = None
        elif getattr(self, "_darwin_seatbelt_provider", False):
            if (
                self._attached
                and not self._terminated
                and not self._created_process_termination_proven
            ):
                raise OwnedProcessScopeError(
                    "cannot close an attached reduced macOS scope before termination"
                )
            self._close_darwin_descriptors()
            # Process-group cleanup is useful hygiene but cannot observe an
            # escaped setsid descendant.  Preserve that distinction forever.
            self._population_zero = False
        elif self._attached:
            # Process groups are diagnostic-only, so this state is not proof.
            self._population_zero = False
        self._closed = True

    def emergency_close(self) -> None:
        """Fail closed when the normal terminate/observe/close sequence fails.

        This is deliberately *not* a clean-completion primitive.  On Windows it
        first retries native Job termination while retaining the observation
        handle.  Only an exact ``ActiveProcesses == 0`` observation may release
        the serialized low-integrity lease for same-process continuation.  The
        scope remains ``emergency_closed`` and callers must still emit debt;
        zero population does not turn the emergency path into completion.

        If termination or observation is ambiguous, closing the provider's last
        non-inheritable Job handle invokes ``KILL_ON_JOB_CLOSE`` for every
        remaining member, but consumes the handle before zero can be observed.
        That path retains the quarantined lease until executor-process death.

        Linux retries cgroup.kill, observes populated=0, and removes the named
        scope.  If any one of those proof steps fails, the deterministic MCP
        identity remains on disk and the next public-route admission recovers
        it before reuse.  Diagnostic process groups receive a best-effort kill
        only; they never become proof-grade.
        """

        if self._closed:
            return
        if os.name == "nt":
            exact_population_zero = False
            if self._job_handle is not None:
                kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
                kernel32.TerminateJobObject.argtypes = [
                    ctypes.c_void_p,
                    ctypes.c_uint32,
                ]
                kernel32.TerminateJobObject.restype = ctypes.c_int
                kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
                kernel32.CloseHandle.restype = ctypes.c_int
                try:
                    if kernel32.TerminateJobObject(
                        ctypes.c_void_p(self._job_handle),
                        1,
                    ):
                        self._terminated = True
                        self._wait_windows_population_zero()
                        exact_population_zero = (
                            self._population_zero is True
                        )
                except BaseException:
                    # Emergency recovery is deliberately best-effort.  Any
                    # native termination or observation ambiguity falls
                    # through to kill-on-close plus retained quarantine.
                    exact_population_zero = False
                if not kernel32.CloseHandle(ctypes.c_void_p(self._job_handle)):
                    raise OwnedProcessScopeError(
                        "CloseHandle(Job Object emergency close) failed: "
                        f"{ctypes.get_last_error()}"
                    )
                self._job_handle = None
            self._close_exact_windows_primary_thread()
            if self._windows_write_lease is not None:
                try:
                    if exact_population_zero:
                        self._windows_write_lease.release_after_proven_closure()
                    else:
                        self._windows_write_lease.quarantine_after_emergency_close()
                except Exception as exc:
                    raise OwnedProcessScopeError(
                        "Windows emergency root restoration failed"
                    ) from exc
            self._emergency_closed = True
            self._closed = True
            return
        if self._linux_cgroup is not None:
            cgroup = self._linux_cgroup
            cleanup_error: BaseException | None = None
            try:
                (cgroup / "cgroup.kill").write_text("1\n", encoding="ascii")
                self._terminated = True
            except BaseException as exc:
                cleanup_error = exc
            for field in (
                "_linux_gate_read",
                "_linux_gate_write",
                "_linux_status_read",
                "_linux_status_write",
            ):
                descriptor = getattr(self, field)
                if descriptor is not None:
                    try:
                        os.close(descriptor)
                    except OSError:
                        pass
                    setattr(self, field, None)
            if cleanup_error is None:
                events = cgroup / "cgroup.events"
                deadline = time.monotonic() + self._population_zero_timeout_seconds
                while True:
                    try:
                        values = dict(
                            line.split(maxsplit=1)
                            for line in events.read_text(
                                encoding="ascii"
                            ).splitlines()
                        )
                    except BaseException as exc:
                        cleanup_error = exc
                        break
                    if values.get("populated") == "0":
                        self._population_zero = True
                        break
                    if time.monotonic() >= deadline:
                        cleanup_error = OwnedProcessScopeError(
                            "Linux emergency cgroup remained populated"
                        )
                        break
                    time.sleep(0.01)
            if cleanup_error is None:
                try:
                    cgroup.rmdir()
                    self._linux_cgroup = None
                except BaseException as exc:
                    cleanup_error = exc
            self._emergency_closed = True
            self._closed = True
            if cleanup_error is not None:
                raise OwnedProcessScopeError(
                    "Linux emergency scope cleanup failed; retained "
                    f"persistent identity {self._persistent_identity}"
                ) from cleanup_error
            return
        if getattr(self, "_darwin_kqueue", None) is not None:
            cleanup_error: BaseException | None = None
            try:
                if self._attached:
                    self.terminate()
                elif (
                    self._process_creation_state == "PROCESS_CREATED"
                    and not self._created_process_termination_proven
                ):
                    self.terminate_created_process()
                if self._darwin_tracked_processes:
                    self._wait_darwin_population_zero()
                else:
                    self._population_zero = True
            except BaseException as exc:
                cleanup_error = exc
            self._close_darwin_descriptors()
            self._darwin_kqueue.close()
            self._darwin_kqueue = None
            self._emergency_closed = True
            self._closed = True
            if cleanup_error is not None:
                raise OwnedProcessScopeError(
                    "macOS emergency cleanup lost live-owner kqueue authority; "
                    "persistent recovery is unavailable"
                ) from cleanup_error
            return
        if getattr(self, "_darwin_seatbelt_provider", False):
            cleanup_error: BaseException | None = None
            try:
                if self._attached:
                    self.terminate()
                    if self._created_process is not None:
                        self._created_process.wait(
                            timeout=self._population_zero_timeout_seconds
                        )
                elif (
                    self._process_creation_state == "PROCESS_CREATED"
                    and not self._created_process_termination_proven
                ):
                    self.terminate_created_process()
            except BaseException as exc:
                cleanup_error = exc
            self._close_darwin_descriptors()
            self._population_zero = False
            self._emergency_closed = True
            self._closed = True
            if cleanup_error is not None:
                raise OwnedProcessScopeError(
                    "reduced macOS Seatbelt scope cleanup failed; descendant "
                    "population remains unprovable"
                ) from cleanup_error
            return
        if self._attached and self._process_group_id is not None:
            try:
                os.killpg(self._process_group_id, signal.SIGKILL)
            except (ProcessLookupError, OSError):
                pass
        self._emergency_closed = True
        self._closed = True

    @property
    def terminated(self) -> bool:
        return self._terminated

    @property
    def process_creation_state(self) -> str:
        """Return the exact monotonic lifecycle classification."""

        return self._process_creation_state

    @property
    def process_creation_evidence(self) -> dict[str, Any]:
        """Return redacted closure/recovery evidence without process handles."""

        return {
            "state": self._process_creation_state,
            "creation_attempted": self._process_creation_attempted,
            "process_object_returned": self._created_process is not None,
            "attached": self._process_creation_state == "ATTACHED",
            "created_process_termination_proven": (
                self._created_process_termination_proven
            ),
        }

    @property
    def scope_capability(self) -> dict[str, Any]:
        """Return a detached copy of this scope's exact host authority."""

        return dict(self._capability)

    @property
    def containment_evidence(self) -> dict[str, Any]:
        """Report tree authority without inflating absent write confinement."""

        return {
            "mode": (
                _WINDOWS_JOB_ONLY_MODE
                if getattr(self, "_windows_job_only", False)
                else "DEFAULT_WRITE_CONFINED_SCOPE"
            ),
            "platform": self._capability.get("platform"),
            "provider_owns_tree": (
                self._capability.get("provider_owns_tree") is True
            ),
            "exhaustive_descendant_termination_authority": (
                self._capability.get(
                    "exhaustive_descendant_termination_authority"
                )
                is True
            ),
            "write_confinement_proven": self.write_confinement_proven,
            "network_confinement_proven": (
                getattr(self, "_darwin_seatbelt_provider", False)
                and self._darwin_seatbelt_active is True
                and self._capability.get(
                    "exhaustive_network_confinement_authority"
                )
                is True
            ),
            "serialized_stage_write_confinement_proven": (
                self.serialized_stage_write_confinement_proven
            ),
            "population_zero_proven": self._population_zero,
            "closed": self._closed,
        }

    @property
    def created_process_termination_proven(self) -> bool:
        """Whether the exact returned, unattached process was killed/reaped."""

        return self._created_process_termination_proven

    @property
    def attached(self) -> bool:
        return self._attached

    @property
    def population_zero_proven(self) -> bool:
        return self._population_zero

    @property
    def closed(self) -> bool:
        return self._closed

    @property
    def emergency_closed(self) -> bool:
        return self._emergency_closed

    @property
    def pre_release_process_identity(self) -> dict[str, str] | None:
        if self._pre_release_process_identity is None:
            return None
        return dict(self._pre_release_process_identity)

    @property
    def write_confinement_proven(self) -> bool:
        if os.name == "nt":
            # The temporary MIC+lease boundary is intentionally narrower than
            # exhaustive filesystem confinement; unrelated pre-existing low-IL
            # objects remain writable.
            return False
        if self._linux_cgroup is not None:
            return self._linux_landlock_abi >= 1
        if getattr(self, "_darwin_seatbelt_provider", False):
            return self._darwin_seatbelt_active is True
        return False

    @property
    def serialized_stage_write_confinement_proven(self) -> bool:
        if os.name == "nt":
            return (
                self._windows_integrity_sid == _WINDOWS_LOW_INTEGRITY_SID
                and self._windows_write_lease is not None
                and self._windows_write_lease.active
            )
        return self.write_confinement_proven

    @property
    def write_confinement_binding(self) -> dict[str, Any] | None:
        if os.name == "nt" and self._windows_write_lease is not None:
            return dict(self._windows_write_lease.binding)
        if self._linux_cgroup is not None:
            return {
                "protocol": "LINUX_CGROUP_V2_PLUS_LANDLOCK",
                "cgroup": str(self._linux_cgroup),
                "landlock_abi": self._linux_landlock_abi,
            }
        if getattr(self, "_darwin_seatbelt_provider", False):
            roots = "\0".join(
                os.fspath(root) for root in self._writable_roots
            ).encode("utf-8", "surrogateescape")
            return {
                "protocol": (
                    "DARWIN_SANDBOX_EXEC_SEATBELT_PLUS_KQUEUE_NOTE_TRACK_V1"
                    if getattr(self, "_darwin_kqueue", None) is not None
                    else "DARWIN_SANDBOX_EXEC_SEATBELT_REDUCED_V1"
                ),
                "writable_roots_sha256": hashlib.sha256(roots).hexdigest(),
                "helper_sha256": self._capability["helper_sha256"],
                "sandbox_exec_sha256": self._capability[
                    "sandbox_exec_sha256"
                ],
                "network_confinement": self._capability.get(
                    "network_confinement"
                ),
                "descendant_termination_authority": (
                    self._capability.get(
                        "exhaustive_descendant_termination_authority"
                    )
                    is True
                ),
                "persistent_recovery_authority": False,
            }
        return None

    @property
    def persistent_identity(self) -> str:
        return self._persistent_identity


__all__ = [
    "OwnedProcessScope",
    "OwnedProcessScopeError",
    "PROCESS_CREATED_BUT_NOT_RETURNED_CONTAINED",
    "PROCESS_CREATED_BUT_NOT_RETURNED_TERMINATED",
    "process_tree_termination_capability",
    "recover_persisted_process_scope",
    "windows_job_only_process_tree_capability",
]
