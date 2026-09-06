"""Single provider-owned process-scope authority.

Windows workers are created suspended, assigned to a non-breakaway
kill-on-close Job Object, then resumed.  Completion requires explicit job
termination, an observed ActiveProcesses==0 state, and successful handle
cleanup.  POSIX process groups remain available only as a diagnostic
capability; they are deliberately marked non-exhaustive and cannot authorize a
clean WorkerTransaction completion.
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
from typing import Any
import uuid


_JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
_JOB_OBJECT_EXTENDED_LIMIT_INFORMATION = 9
_JOB_OBJECT_BASIC_ACCOUNTING_INFORMATION = 1
_CREATE_SUSPENDED = 0x00000004
_TH32CS_SNAPTHREAD = 0x00000004
_THREAD_SUSPEND_RESUME = 0x0002
_INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
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
                "SUSPENDED_CREATE_JOB_ASSIGN_RESUME_TERMINATE_"
                "POPULATION_ZERO_CLOSE"
            ),
            "provider_owns_tree": True,
            "descendant_termination_required": True,
            "pre_execution_assignment": True,
            "termination_scope": "JOB_TREE",
            "population_zero_proof": "JOB_ACTIVE_PROCESSES",
            "write_confinement": (
                "LOW_INTEGRITY_TOKEN_PLUS_SERIALIZED_PLAMEN_STAGE_LEASE"
            ),
            "exhaustive_descendant_termination_authority": True,
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
        return {
            "platform": "MACOS",
            "strategy": "PROCESS_GROUP_DIAGNOSTIC_ONLY",
            "provider_owns_tree": False,
            "descendant_termination_required": True,
            "pre_execution_assignment": True,
            "termination_scope": "PROCESS_GROUP_ONLY",
            "population_zero_proof": "UNAVAILABLE",
            "exhaustive_descendant_termination_authority": False,
            "exhaustive_write_confinement_authority": False,
            "limitation": "NATIVE_SANDBOX_PROCESS_AUTHORITY_NOT_CONFIGURED",
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

    return {
        "platform": "WINDOWS",
        "mode": _WINDOWS_JOB_ONLY_MODE,
        "strategy": (
            "SUSPENDED_CREATE_JOB_ASSIGN_RESUME_TERMINATE_"
            "POPULATION_ZERO_CLOSE"
        ),
        "provider_owns_tree": True,
        "descendant_termination_required": True,
        "pre_execution_assignment": True,
        "termination_scope": "NON_BREAKAWAY_KILL_ON_CLOSE_JOB_TREE",
        "population_zero_proof": "JOB_ACTIVE_PROCESSES",
        "exhaustive_descendant_termination_authority": True,
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
        self._windows_job_only = windows_job_only
        self._job_handle: int | None = None
        self._process_group_id: int | None = None
        self._linux_cgroup: Path | None = None
        self._linux_gate_read: int | None = None
        self._linux_gate_write: int | None = None
        self._linux_status_read: int | None = None
        self._linux_status_write: int | None = None
        self._linux_landlock_abi: int = 0
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
        )
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
        return {"start_new_session": True}

    def create_process(
        self,
        physical_argv: list[str] | tuple[str, ...],
        *,
        popen_factory: Any | None = None,
        **popen_kwargs: Any,
    ) -> subprocess.Popen[bytes]:
        """Exercise this scope's one-shot process-creation authority.

        ``physical_argv`` is the already-wrapped command returned by
        :meth:`wrap_argv`; ``popen_kwargs`` accepts the existing cwd, env,
        stdio, shell, and platform-specific values.  The injected factory is a
        fixture seam only.  Production callers omit it and therefore execute
        :class:`subprocess.Popen` here, inside the owning scope.

        The private attempted bit is set immediately before invoking the
        factory.  A factory exception is the only transition to
        ``CREATION_FAILED_WITHOUT_PROCESS_OBJECT``.  Any returned object is
        recorded by identity and transitions immediately to
        ``PROCESS_CREATED``.  Before this method returns, a Windows process is
        assigned while suspended to this scope's kill-on-close Job, and a
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
        factory = subprocess.Popen if popen_factory is None else popen_factory
        if not callable(factory):
            raise OwnedProcessScopeError("Popen factory must be callable")
        windows_job_creation = os.name == "nt" and self._job_handle is not None
        if windows_job_creation:
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

        self._process_creation_attempted = True
        try:
            process = factory(list(physical_argv), **popen_kwargs)
        except BaseException:
            self._process_creation_state = (
                "CREATION_FAILED_WITHOUT_PROCESS_OBJECT"
            )
            raise
        self._created_process = process
        self._process_creation_state = "PROCESS_CREATED"
        try:
            if windows_job_creation:
                self._assign_windows_created_process_to_job(process)
                self._windows_job_owned_suspended = True
            elif self._linux_cgroup is not None:
                self._wait_linux_created_process_cgroup_membership(process)
                self._linux_created_process_cgroup_membership_proven = True
        except BaseException as exc:
            boundary = (
                "Windows Job"
                if windows_job_creation
                else "Linux persistent cgroup"
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

    def _assign_windows_created_process_to_job(
        self,
        process: subprocess.Popen[bytes],
    ) -> None:
        """Assign the exact suspended process before create_process returns."""

        handle = getattr(process, "_handle", None)
        if handle is None or self._job_handle is None:
            raise OwnedProcessScopeError(
                "Windows process/job handle is unavailable"
            )
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.AssignProcessToJobObject.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
        ]
        kernel32.AssignProcessToJobObject.restype = ctypes.c_int
        if not kernel32.AssignProcessToJobObject(
            ctypes.c_void_p(self._job_handle),
            ctypes.c_void_p(int(handle)),
        ):
            raise OwnedProcessScopeError(
                f"AssignProcessToJobObject failed: {ctypes.get_last_error()}"
            )

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
            raise OwnedProcessScopeError(
                "exact created process could not be observed"
            ) from exc
        if running:
            try:
                process.kill()
            except BaseException as exc:
                raise OwnedProcessScopeError(
                    "exact created process could not be killed"
                ) from exc
        try:
            process.wait(timeout=float(timeout_seconds))
        except subprocess.TimeoutExpired as exc:
            raise OwnedProcessScopeError(
                "exact created process did not exit before timeout"
            ) from exc
        except BaseException as exc:
            raise OwnedProcessScopeError(
                "exact created process could not be reaped"
            ) from exc
        try:
            if process.poll() is None:
                raise OwnedProcessScopeError(
                    "exact created process did not exit after wait"
                )
        except OwnedProcessScopeError:
            raise
        except BaseException as exc:
            raise OwnedProcessScopeError(
                "exact created process exit could not be observed"
            ) from exc
        self._created_process_termination_proven = True

    def wrap_argv(self, argv: list[str] | tuple[str, ...]) -> list[str]:
        """Return the exact physical argv needed for pre-exec containment."""

        command = [str(item) for item in argv]
        if not command or not Path(command[0]).is_absolute():
            raise OwnedProcessScopeError(
                "owned process argv requires an absolute executable"
            )
        if self._linux_cgroup is None:
            return command
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
            self._attached = True
            if not getattr(self, "_windows_job_only", False):
                self._windows_integrity_sid = _lower_windows_process_integrity(
                    int(handle)
                )
            self._resume_only_thread(process.pid)
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
        return None

    @property
    def persistent_identity(self) -> str:
        return self._persistent_identity


__all__ = [
    "OwnedProcessScope",
    "OwnedProcessScopeError",
    "process_tree_termination_capability",
    "recover_persisted_process_scope",
    "windows_job_only_process_tree_capability",
]
