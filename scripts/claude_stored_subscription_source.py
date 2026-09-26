"""Host observation authority for Claude stored-subscription credentials.

The durable product of this module is deliberately small and redacted.  It
states whether one reviewed host store is present, but contains neither
credential values nor hashes derived from credential content.  File-backed
bytes are read through an exact no-follow descriptor.  On macOS, bytes are
acquired only from the exact Claude generic-password service and kernel UID
account through the absolute system ``security`` tool.  Material is validated
in memory and never added to a durable receipt.

This provider does not copy credentials and does not launch Claude.  The
attempt-profile transaction remains responsible for materialization, while
``claude_auth_route`` consumes the exact evidence schema emitted here.
"""

from __future__ import annotations

import ctypes
import hashlib
import hmac
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import selectors
import signal
import stat
import subprocess
import sys
import threading
import time
from typing import Any, Callable, Mapping
import weakref

import claude_auth_route as _auth


HOST_WINDOWS_NATIVE = "WINDOWS_NATIVE"
HOST_LINUX_NATIVE = "LINUX_NATIVE"
HOST_WSL_NATIVE = "WSL_NATIVE"
HOST_MACOS = "MACOS"
HOST_UNSUPPORTED = "UNSUPPORTED"

MAX_CREDENTIAL_FILE_BYTES = 1024 * 1024
MAX_IMPLEMENTATION_FILE_BYTES = 4 * 1024 * 1024
MAX_MOUNTINFO_BYTES = 4 * 1024 * 1024
MAX_KEYCHAIN_OBSERVATION_STDOUT_BYTES = 64 * 1024
MAX_KEYCHAIN_STDERR_BYTES = 64 * 1024
MACOS_KEYCHAIN_TIMEOUT_SECONDS = 3.0
MACOS_SECURITY_TOOL = "/usr/bin/security"
MACOS_CLAUDE_KEYCHAIN_SERVICE = "Claude Code-credentials"
STORED_SUBSCRIPTION_MATERIALIZATION_SCHEMA = (
    "plamen.claude_stored_subscription_materialization.v1"
)
PRIVATE_CREDENTIAL_TARGET_AUTHORITY_SCHEMA = (
    "plamen.claude_private_credential_target_authority.v2"
)

_FILE_ATTRIBUTE_REPARSE_POINT = 0x400
_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_OPAQUE_ID_RE = re.compile(r"[0-9a-f]{32}")
_WINDOWS_SE_FILE_OBJECT = 1
_WINDOWS_OWNER_SECURITY_INFORMATION = 0x00000001
_WINDOWS_DACL_SECURITY_INFORMATION = 0x00000004
_WINDOWS_TOKEN_QUERY = 0x0008
_WINDOWS_TOKEN_USER = 1
_WINDOWS_ERROR_INSUFFICIENT_BUFFER = 122
_WINDOWS_ACCESS_ALLOWED_ACE_TYPE = 0x00
_WINDOWS_ACCESS_DENIED_ACE_TYPE = 0x01
_WINDOWS_FILE_READ_DATA = 0x00000001
_WINDOWS_FILE_WRITE_DATA = 0x00000002
_WINDOWS_FILE_APPEND_DATA = 0x00000004
_WINDOWS_FILE_WRITE_EA = 0x00000010
_WINDOWS_FILE_DELETE_CHILD = 0x00000040
_WINDOWS_FILE_WRITE_ATTRIBUTES = 0x00000100
_WINDOWS_DELETE = 0x00010000
_WINDOWS_WRITE_DAC = 0x00040000
_WINDOWS_WRITE_OWNER = 0x00080000
_WINDOWS_GENERIC_ALL = 0x10000000
_WINDOWS_GENERIC_WRITE = 0x40000000
_WINDOWS_GENERIC_READ = 0x80000000
_WINDOWS_SENSITIVE_FILE_ACCESS = (
    _WINDOWS_FILE_READ_DATA
    | _WINDOWS_FILE_WRITE_DATA
    | _WINDOWS_FILE_APPEND_DATA
    | _WINDOWS_FILE_WRITE_EA
    | _WINDOWS_FILE_DELETE_CHILD
    | _WINDOWS_FILE_WRITE_ATTRIBUTES
    | _WINDOWS_DELETE
    | _WINDOWS_WRITE_DAC
    | _WINDOWS_WRITE_OWNER
    | _WINDOWS_GENERIC_ALL
    | _WINDOWS_GENERIC_WRITE
    | _WINDOWS_GENERIC_READ
)
_WINDOWS_TRUSTED_PRIVILEGED_SIDS = frozenset(
    {
        "S-1-5-18",  # LocalSystem
        "S-1-5-32-544",  # Builtin Administrators
    }
)
_NATIVE_WSL_FILESYSTEMS = frozenset(
    {
        "btrfs",
        "ext2",
        "ext3",
        "ext4",
        "f2fs",
        "tmpfs",
        "xfs",
    }
)
_HOST_TAG = {
    HOST_WINDOWS_NATIVE: "windows",
    HOST_LINUX_NATIVE: "linux",
    HOST_WSL_NATIVE: "wsl",
}
_PRIVATE_TARGET_TOKEN = object()
_CAPABILITY_STATE_LOCK = threading.RLock()
_PRIVATE_TARGET_PENDING: dict[str, dict[str, Any]] = {}
_PRIVATE_TARGET_ISSUED: dict[
    int, tuple[weakref.ReferenceType[Any], dict[str, Any]]
] = {}
_MATERIALIZATION_PENDING: dict[str, dict[str, Any]] = {}
_MATERIALIZATION_ISSUED: dict[
    int, tuple[weakref.ReferenceType[Any], dict[str, Any]]
] = {}


class ClaudeStoredSubscriptionSourceError(RuntimeError):
    """The requested host credential-store observation is not trustworthy."""

    def __init__(self, message: str, *, reason_code: str | None = None) -> None:
        super().__init__(message)
        self.reason_code = reason_code


class _SecurityCommandResult:
    """Mutable, explicitly erasable output from one ``security`` command."""

    __slots__ = (
        "overflowed",
        "returncode",
        "stderr",
        "stdout",
        "timed_out",
    )

    def __init__(
        self,
        *,
        returncode: int,
        stdout: bytearray,
        stderr: bytearray,
        timed_out: bool = False,
        overflowed: bool = False,
    ) -> None:
        if not isinstance(stdout, bytearray) or not isinstance(
            stderr, bytearray
        ):
            raise TypeError("security command output must be mutable")
        self.returncode = int(returncode)
        self.stdout = stdout
        self.stderr = stderr
        self.timed_out = bool(timed_out)
        self.overflowed = bool(overflowed)

    def take_stdout(self) -> bytearray:
        value = self.stdout
        self.stdout = bytearray()
        return value

    def discard(self) -> None:
        for value in (self.stdout, self.stderr):
            for index in range(len(value)):
                value[index] = 0
        self.stdout = bytearray()
        self.stderr = bytearray()


class _DuplicateJsonKey(ValueError):
    pass


def _terminate_security_process(
    process: subprocess.Popen[bytes],
    *,
    include_process_group: bool,
) -> bool:
    """Best-effort kill of the isolated no-shell ``security`` process group."""

    reconciled = True
    if include_process_group:
        try:
            pid = int(process.pid)
            if pid <= 1:
                return False
            # Popen(start_new_session=True) makes this exact child PID the
            # process-group ID.  Kill that group even when the leader has
            # already exited: descendants may still own our capture pipes.
            os.killpg(pid, signal.SIGKILL)
        except ProcessLookupError:
            # No such group is already the desired reconciled state.
            pass
        except Exception:
            reconciled = False
    try:
        running = process.poll() is None
    except Exception:
        return False
    if running:
        try:
            process.kill()
        except ProcessLookupError:
            pass
        except Exception:
            reconciled = False
    return reconciled


def _close_security_stream(stream: Any) -> bool:
    """Close one owned subprocess pipe and report whether close succeeded."""

    try:
        stream.close()
        return bool(getattr(stream, "closed", True))
    except Exception:
        return False


def _bounded_reap_security_process(
    process: subprocess.Popen[bytes],
    *,
    force_process_group: bool,
) -> bool:
    """Bound termination/reaping while never treating an unreaped child as OK."""

    reconciled = True
    for _attempt in range(3):
        if force_process_group:
            reconciled = (
                _terminate_security_process(
                    process,
                    include_process_group=True,
                )
                and reconciled
            )
        try:
            process.wait(timeout=0.5)
            return reconciled
        except subprocess.TimeoutExpired:
            # A wait timeout promotes cleanup to exact group termination even
            # if the original command appeared to have completed normally.
            force_process_group = True
        except OSError:
            try:
                if process.poll() is not None:
                    return reconciled
            except (AttributeError, OSError, ProcessLookupError):
                pass
            return False
        except Exception:
            _terminate_security_process(
                process,
                include_process_group=True,
            )
            return False
    return False


def _run_bounded_security_command(
    argv: tuple[str, ...],
    *,
    timeout_s: float,
    stdout_ceiling: int,
    stderr_ceiling: int,
) -> _SecurityCommandResult:
    """Run one absolute ``security`` argv with bounded mutable captures.

    This is intentionally not a general command runner.  Callers validate the
    exact closed argv before reaching it.  No shell, inherited environment,
    terminal input, or unbounded ``communicate`` buffer is involved.
    """

    try:
        exact_account = _macos_current_account()
    except ClaudeStoredSubscriptionSourceError:
        raise
    allowed_base = (
        MACOS_SECURITY_TOOL,
        "find-generic-password",
        "-s",
        MACOS_CLAUDE_KEYCHAIN_SERVICE,
        "-a",
        exact_account,
    )
    if (
        not isinstance(argv, tuple)
        or argv not in {allowed_base, (*allowed_base, "-w")}
        or any(
            not isinstance(item, str) or not item or "\x00" in item
            for item in argv
        )
        or isinstance(timeout_s, bool)
        or not isinstance(timeout_s, (int, float))
        or timeout_s <= 0
        or isinstance(stdout_ceiling, bool)
        or not isinstance(stdout_ceiling, int)
        or stdout_ceiling <= 0
        or isinstance(stderr_ceiling, bool)
        or not isinstance(stderr_ceiling, int)
        or stderr_ceiling <= 0
    ):
        raise ClaudeStoredSubscriptionSourceError(
            "macOS Keychain command policy is malformed",
            reason_code="KEYCHAIN_COMMAND_POLICY_INVALID",
        )
    try:
        process = subprocess.Popen(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd="/",
            env={},
            shell=False,
            close_fds=True,
            start_new_session=True,
            text=False,
            bufsize=0,
        )
    except (OSError, ValueError):
        raise ClaudeStoredSubscriptionSourceError(
            "macOS Keychain command could not be started",
            reason_code="KEYCHAIN_COMMAND_UNAVAILABLE",
        ) from None
    if process.stdout is None or process.stderr is None:
        cleanup_ok = True
        for stream in (process.stdout, process.stderr):
            if stream is not None:
                cleanup_ok = _close_security_stream(stream) and cleanup_ok
        cleanup_ok = (
            _bounded_reap_security_process(
                process,
                force_process_group=True,
            )
            and cleanup_ok
        )
        raise ClaudeStoredSubscriptionSourceError(
            (
                "macOS Keychain command capture is unavailable"
                if cleanup_ok
                else "macOS Keychain command capture failed"
            ),
            reason_code=(
                "KEYCHAIN_CAPTURE_UNAVAILABLE"
                if cleanup_ok
                else "KEYCHAIN_CAPTURE_FAILED"
            ),
        )

    stdout: bytearray | None = None
    stderr: bytearray | None = None
    stdout_scratch: bytearray | None = None
    stderr_scratch: bytearray | None = None
    selector: selectors.BaseSelector | None = None
    timed_out = False
    overflowed = False
    capture_failed = False
    cleanup_failed = False
    try:
        stdout = bytearray()
        stderr = bytearray()
        stdout_scratch = bytearray(64 * 1024)
        stderr_scratch = bytearray(64 * 1024)
        selector = selectors.DefaultSelector()
        for stream, destination, ceiling, scratch in (
            (process.stdout, stdout, stdout_ceiling, stdout_scratch),
            (process.stderr, stderr, stderr_ceiling, stderr_scratch),
        ):
            os.set_blocking(stream.fileno(), False)
            selector.register(
                stream,
                selectors.EVENT_READ,
                (destination, ceiling, scratch),
            )
        deadline = time.monotonic() + float(timeout_s)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                _terminate_security_process(
                    process,
                    include_process_group=True,
                )
                break
            try:
                events = selector.select(remaining)
            except InterruptedError:
                continue
            except OSError:
                capture_failed = True
                _terminate_security_process(
                    process,
                    include_process_group=True,
                )
                break
            if not events:
                timed_out = True
                _terminate_security_process(
                    process,
                    include_process_group=True,
                )
                break
            for key, _mask in events:
                destination, ceiling, scratch = key.data
                try:
                    count = os.readv(key.fd, (scratch,))
                except BlockingIOError:
                    continue
                except InterruptedError:
                    continue
                except OSError:
                    capture_failed = True
                    _terminate_security_process(
                        process,
                        include_process_group=True,
                    )
                    break
                if count == 0:
                    try:
                        selector.unregister(key.fileobj)
                    except (KeyError, OSError, ValueError):
                        capture_failed = True
                    continue
                accepted = min(max(0, ceiling - len(destination)), count)
                if accepted:
                    destination.extend(memoryview(scratch)[:accepted])
                for index in range(count):
                    scratch[index] = 0
                if accepted != count:
                    overflowed = True
                    _terminate_security_process(
                        process,
                        include_process_group=True,
                    )
                    break
            if capture_failed or overflowed:
                break
    except Exception:
        capture_failed = True
        cleanup_failed = not _terminate_security_process(
            process,
            include_process_group=True,
        )
    finally:
        if selector is not None:
            selector_closed = False
            for _attempt in range(2):
                try:
                    selector.close()
                    selector_closed = True
                    break
                except Exception:
                    cleanup_failed = True
            if not selector_closed:
                cleanup_failed = True
        for stream in (process.stdout, process.stderr):
            if not _close_security_stream(stream):
                cleanup_failed = True
        if not _bounded_reap_security_process(
            process,
            force_process_group=(
                timed_out
                or overflowed
                or capture_failed
                or cleanup_failed
            ),
        ):
            cleanup_failed = True
        for scratch in (stdout_scratch, stderr_scratch):
            if scratch is None:
                continue
            for index in range(len(scratch)):
                scratch[index] = 0

    if capture_failed or cleanup_failed:
        for value in (stdout, stderr):
            if value is None:
                continue
            for index in range(len(value)):
                value[index] = 0
        raise ClaudeStoredSubscriptionSourceError(
            "macOS Keychain command capture failed",
            reason_code="KEYCHAIN_CAPTURE_FAILED",
        )
    return _SecurityCommandResult(
        returncode=(
            int(process.returncode)
            if process.returncode is not None
            else -int(signal.SIGKILL)
        ),
        stdout=stdout if stdout is not None else bytearray(),
        stderr=stderr if stderr is not None else bytearray(),
        timed_out=timed_out,
        overflowed=overflowed,
    )


def _canonical_json(value: Mapping[str, Any] | list[Any]) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ClaudeStoredSubscriptionSourceError(
            "stored-subscription evidence is not canonical JSON"
        ) from exc


def _digest(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def _is_reparse_stat(info: os.stat_result) -> bool:
    return bool(
        int(getattr(info, "st_file_attributes", 0))
        & _FILE_ATTRIBUTE_REPARSE_POINT
    )


def _sid_to_string(
    sid_pointer: ctypes.c_void_p,
    *,
    advapi32: Any,
    kernel32: Any,
) -> str:
    from ctypes import wintypes

    text = wintypes.LPWSTR()
    if not sid_pointer or not sid_pointer.value:
        raise ClaudeStoredSubscriptionSourceError(
            "Windows DACL contains an absent principal"
        )
    if not advapi32.ConvertSidToStringSidW(
        sid_pointer,
        ctypes.byref(text),
    ):
        raise ClaudeStoredSubscriptionSourceError(
            "Windows DACL principal cannot be canonicalized"
        )
    try:
        result = text.value
        if not result:
            raise ClaudeStoredSubscriptionSourceError(
                "Windows DACL principal is empty"
            )
        return result
    finally:
        kernel32.LocalFree(
            ctypes.c_void_p(ctypes.cast(text, ctypes.c_void_p).value)
        )


def _current_windows_user_sid_string() -> str:
    if os.name != "nt":
        raise ClaudeStoredSubscriptionSourceError(
            "Windows token-user observation requested on a non-Windows host"
        )
    from ctypes import wintypes

    class _SidAndAttributes(ctypes.Structure):
        _fields_ = [
            ("Sid", ctypes.c_void_p),
            ("Attributes", wintypes.DWORD),
        ]

    class _TokenUser(ctypes.Structure):
        _fields_ = [("User", _SidAndAttributes)]

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetCurrentProcess.argtypes = []
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p
    advapi32.OpenProcessToken.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
    ]
    advapi32.OpenProcessToken.restype = wintypes.BOOL
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

    token = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(
        kernel32.GetCurrentProcess(),
        _WINDOWS_TOKEN_QUERY,
        ctypes.byref(token),
    ):
        raise ClaudeStoredSubscriptionSourceError(
            "current Windows token cannot be opened for DACL authority"
        )
    try:
        needed = wintypes.DWORD()
        if advapi32.GetTokenInformation(
            token,
            _WINDOWS_TOKEN_USER,
            None,
            0,
            ctypes.byref(needed),
        ):
            raise ClaudeStoredSubscriptionSourceError(
                "Windows token-user sizing unexpectedly succeeded"
            )
        if (
            ctypes.get_last_error()
            != _WINDOWS_ERROR_INSUFFICIENT_BUFFER
            or needed.value <= 0
        ):
            raise ClaudeStoredSubscriptionSourceError(
                "current Windows token-user record cannot be sized"
            )
        buffer = ctypes.create_string_buffer(needed.value)
        if not advapi32.GetTokenInformation(
            token,
            _WINDOWS_TOKEN_USER,
            buffer,
            needed,
            ctypes.byref(needed),
        ):
            raise ClaudeStoredSubscriptionSourceError(
                "current Windows token-user record cannot be read"
            )
        token_user = ctypes.cast(
            buffer,
            ctypes.POINTER(_TokenUser),
        ).contents
        return _sid_to_string(
            ctypes.c_void_p(token_user.User.Sid),
            advapi32=advapi32,
            kernel32=kernel32,
        )
    finally:
        kernel32.CloseHandle(token)


def _windows_private_acl_snapshot(
    path: Path,
    *,
    label: str,
) -> tuple[str, tuple[tuple[int, int, int, str], ...]]:
    """Return transient ACL authority after enforcing a private owner."""

    if os.name != "nt":
        raise ClaudeStoredSubscriptionSourceError(
            "Windows DACL observation requested on a non-Windows host"
        )
    try:
        info = os.lstat(path)
    except OSError as exc:
        raise ClaudeStoredSubscriptionSourceError(
            f"{label} DACL source is unavailable"
        ) from exc
    if stat.S_ISLNK(info.st_mode) or _is_reparse_stat(info):
        raise ClaudeStoredSubscriptionSourceError(
            f"{label} DACL source became a symlink/reparse point"
        )

    from ctypes import wintypes

    class _Acl(ctypes.Structure):
        _fields_ = [
            ("AclRevision", ctypes.c_ubyte),
            ("Sbz1", ctypes.c_ubyte),
            ("AclSize", wintypes.WORD),
            ("AceCount", wintypes.WORD),
            ("Sbz2", wintypes.WORD),
        ]

    class _AceHeader(ctypes.Structure):
        _fields_ = [
            ("AceType", ctypes.c_ubyte),
            ("AceFlags", ctypes.c_ubyte),
            ("AceSize", wintypes.WORD),
        ]

    class _AccessAce(ctypes.Structure):
        _fields_ = [
            ("Header", _AceHeader),
            ("Mask", wintypes.DWORD),
            ("SidStart", wintypes.DWORD),
        ]

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi32.GetNamedSecurityInfoW.argtypes = [
        wintypes.LPWSTR,
        ctypes.c_int,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
    ]
    advapi32.GetNamedSecurityInfoW.restype = wintypes.DWORD
    advapi32.GetAce.argtypes = [
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    advapi32.GetAce.restype = wintypes.BOOL
    advapi32.IsValidAcl.argtypes = [ctypes.c_void_p]
    advapi32.IsValidAcl.restype = wintypes.BOOL
    advapi32.IsValidSecurityDescriptor.argtypes = [ctypes.c_void_p]
    advapi32.IsValidSecurityDescriptor.restype = wintypes.BOOL
    advapi32.ConvertSidToStringSidW.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.LPWSTR),
    ]
    advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p

    owner = ctypes.c_void_p()
    dacl = ctypes.c_void_p()
    descriptor = ctypes.c_void_p()
    result = int(
        advapi32.GetNamedSecurityInfoW(
            str(path),
            _WINDOWS_SE_FILE_OBJECT,
            (
                _WINDOWS_OWNER_SECURITY_INFORMATION
                | _WINDOWS_DACL_SECURITY_INFORMATION
            ),
            ctypes.byref(owner),
            None,
            ctypes.byref(dacl),
            None,
            ctypes.byref(descriptor),
        )
    )
    if (
        result != 0
        or not descriptor.value
        or not owner.value
        or not dacl.value
    ):
        if descriptor.value:
            kernel32.LocalFree(descriptor)
        raise ClaudeStoredSubscriptionSourceError(
            f"{label} DACL authority is unavailable"
        )
    try:
        if (
            not advapi32.IsValidSecurityDescriptor(descriptor)
            or not advapi32.IsValidAcl(dacl)
        ):
            raise ClaudeStoredSubscriptionSourceError(
                f"{label} DACL authority is malformed"
            )
        owner_sid = _sid_to_string(
            owner,
            advapi32=advapi32,
            kernel32=kernel32,
        )
        current_sid = _current_windows_user_sid_string()
        if owner_sid != current_sid:
            raise ClaudeStoredSubscriptionSourceError(
                f"{label} owner is not the current Windows token user"
            )

        acl = ctypes.cast(dacl, ctypes.POINTER(_Acl)).contents
        rows: list[tuple[int, int, int, str]] = []
        current_user_has_sensitive_access = False
        trusted = {
            current_sid,
            *_WINDOWS_TRUSTED_PRIVILEGED_SIDS,
        }
        for index in range(int(acl.AceCount)):
            ace_pointer = ctypes.c_void_p()
            if not advapi32.GetAce(
                dacl,
                index,
                ctypes.byref(ace_pointer),
            ):
                raise ClaudeStoredSubscriptionSourceError(
                    f"{label} DACL ACE cannot be read"
                )
            ace = ctypes.cast(
                ace_pointer,
                ctypes.POINTER(_AccessAce),
            ).contents
            ace_type = int(ace.Header.AceType)
            if ace_type not in {
                _WINDOWS_ACCESS_ALLOWED_ACE_TYPE,
                _WINDOWS_ACCESS_DENIED_ACE_TYPE,
            }:
                raise ClaudeStoredSubscriptionSourceError(
                    f"{label} DACL contains an unsupported ACE type"
                )
            sid_pointer = ctypes.c_void_p(
                int(ace_pointer.value) + int(_AccessAce.SidStart.offset)
            )
            principal = _sid_to_string(
                sid_pointer,
                advapi32=advapi32,
                kernel32=kernel32,
            )
            mask = int(ace.Mask)
            rows.append(
                (
                    ace_type,
                    int(ace.Header.AceFlags),
                    mask,
                    principal,
                )
            )
            if (
                ace_type == _WINDOWS_ACCESS_ALLOWED_ACE_TYPE
                and mask & _WINDOWS_SENSITIVE_FILE_ACCESS
            ):
                if principal not in trusted:
                    raise ClaudeStoredSubscriptionSourceError(
                        f"{label} DACL grants sensitive access to "
                        "an untrusted principal"
                    )
                if principal == current_sid:
                    current_user_has_sensitive_access = True
        if not current_user_has_sensitive_access:
            raise ClaudeStoredSubscriptionSourceError(
                f"{label} DACL does not grant the current user access"
            )
        return owner_sid, tuple(rows)
    finally:
        kernel32.LocalFree(descriptor)


def _verify_windows_source_security(path: Path) -> None:
    """Replay file and immediate-ancestor DACLs twice without persisting SIDs."""

    for target, label in (
        (path, "Windows credential file"),
        (path.parent, "Windows credential ancestor"),
    ):
        first = _windows_private_acl_snapshot(target, label=label)
        second = _windows_private_acl_snapshot(target, label=label)
        if first != second:
            raise ClaudeStoredSubscriptionSourceError(
                f"{label} DACL changed during observation"
            )


def _same_path_spelling(left: str, right: str) -> bool:
    if os.name == "nt":
        return os.path.normcase(left) == os.path.normcase(right)
    return left == right


def _path_text(value: str | os.PathLike[str]) -> str:
    try:
        text = os.fspath(value)
    except TypeError as exc:
        raise ClaudeStoredSubscriptionSourceError(
            "credential source path is malformed"
        ) from exc
    if (
        not isinstance(text, str)
        or not text
        or text != text.strip()
        or "\x00" in text
    ):
        raise ClaudeStoredSubscriptionSourceError(
            "credential source path is malformed"
        )
    return text


def _canonical_candidate_path(
    value: str | os.PathLike[str],
    *,
    label: str,
) -> tuple[Path, bool]:
    text = _path_text(value)
    path = Path(text)
    if not path.is_absolute():
        raise ClaudeStoredSubscriptionSourceError(
            f"{label} must be an absolute exact path"
        )
    normalized = os.path.normpath(text)
    if not _same_path_spelling(text, normalized):
        raise ClaudeStoredSubscriptionSourceError(
            f"{label} is not a canonical path spelling"
        )

    missing = False
    cursor = Path(path.anchor)
    for part in path.parts[1:]:
        cursor = cursor / part
        if missing:
            continue
        try:
            info = os.lstat(cursor)
        except FileNotFoundError:
            missing = True
            continue
        except OSError as exc:
            raise ClaudeStoredSubscriptionSourceError(
                f"{label} cannot be inspected"
            ) from exc
        if stat.S_ISLNK(info.st_mode) or _is_reparse_stat(info):
            raise ClaudeStoredSubscriptionSourceError(
                f"{label} traverses a symlink/reparse alias"
            )

    try:
        resolved = path.resolve(strict=not missing)
    except OSError as exc:
        raise ClaudeStoredSubscriptionSourceError(
            f"{label} cannot be resolved"
        ) from exc
    if not _same_path_spelling(str(path), str(resolved)):
        raise ClaudeStoredSubscriptionSourceError(
            f"{label} resolves through an alias"
        )
    return resolved, missing


def _read_descriptor_bounded(
    descriptor: int,
    *,
    ceiling: int,
    label: str,
) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = os.read(descriptor, 64 * 1024)
        if not chunk:
            break
        total += len(chunk)
        if total > ceiling:
            raise ClaudeStoredSubscriptionSourceError(
                f"{label} exceeds its observation ceiling"
            )
        chunks.append(chunk)
    return b"".join(chunks)


def _stable_regular_file_bytes(
    path: Path,
    *,
    ceiling: int,
    label: str,
) -> tuple[Path, os.stat_result, bytes]:
    canonical, missing = _canonical_candidate_path(path, label=label)
    if missing:
        raise ClaudeStoredSubscriptionSourceError(f"{label} does not exist")
    try:
        before = os.lstat(canonical)
    except OSError as exc:
        raise ClaudeStoredSubscriptionSourceError(
            f"{label} cannot be inspected"
        ) from exc
    if (
        not stat.S_ISREG(before.st_mode)
        or stat.S_ISLNK(before.st_mode)
        or _is_reparse_stat(before)
    ):
        raise ClaudeStoredSubscriptionSourceError(
            f"{label} must be a regular non-symlink/reparse file"
        )
    if int(getattr(before, "st_nlink", 1)) != 1:
        raise ClaudeStoredSubscriptionSourceError(
            f"{label} is a hardlink alias"
        )
    if int(before.st_size) > ceiling:
        raise ClaudeStoredSubscriptionSourceError(
            f"{label} exceeds its observation ceiling"
        )

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(canonical, flags)
    except OSError as exc:
        raise ClaudeStoredSubscriptionSourceError(
            f"{label} cannot be opened without following aliases"
        ) from exc
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or (int(opened.st_dev), int(opened.st_ino))
            != (int(before.st_dev), int(before.st_ino))
            or int(getattr(opened, "st_nlink", 1)) != 1
        ):
            raise ClaudeStoredSubscriptionSourceError(
                f"{label} changed or resolved through an alias while opening"
            )
        first = _read_descriptor_bounded(
            descriptor,
            ceiling=ceiling,
            label=label,
        )
        os.lseek(descriptor, 0, os.SEEK_SET)
        second = _read_descriptor_bounded(
            descriptor,
            ceiling=ceiling,
            label=label,
        )
        after_fd = os.fstat(descriptor)
    finally:
        os.close(descriptor)

    try:
        after_path = os.lstat(canonical)
    except OSError as exc:
        raise ClaudeStoredSubscriptionSourceError(
            f"{label} disappeared during observation"
        ) from exc
    # Windows' CRT reports a descriptor ``st_ctime_ns`` that can differ from
    # the path-backed value even when the file is unchanged.  Bind ctime
    # before/after by path, while descriptor identity uses the kernel-stable
    # fields shared with lstat.
    descriptor_stable_fields = (
        "st_dev",
        "st_ino",
        "st_size",
        "st_mtime_ns",
        "st_nlink",
    )
    if (
        first != second
        or any(
            int(getattr(before, field, 0))
            != int(getattr(after_fd, field, 0))
            or int(getattr(before, field, 0))
            != int(getattr(after_path, field, 0))
            for field in descriptor_stable_fields
        )
        or int(getattr(before, "st_ctime_ns", 0))
        != int(getattr(after_path, "st_ctime_ns", 0))
        or int(before.st_mode) != int(after_path.st_mode)
        or stat.S_ISLNK(after_path.st_mode)
        or _is_reparse_stat(after_path)
    ):
        raise ClaudeStoredSubscriptionSourceError(
            f"{label} changed or drifted during observation"
        )
    if len(first) != int(before.st_size):
        raise ClaudeStoredSubscriptionSourceError(
            f"{label} byte count drifted during observation"
        )
    return canonical, before, first


def _acquire_stable_credential_descriptor(
    path: Path,
    *,
    label: str,
) -> tuple[Path, os.stat_result, bytearray, int]:
    """Read twice through one no-follow descriptor and retain that descriptor."""

    canonical, missing = _canonical_candidate_path(path, label=label)
    if missing:
        raise ClaudeStoredSubscriptionSourceError(f"{label} does not exist")
    try:
        before = os.lstat(canonical)
    except OSError:
        raise ClaudeStoredSubscriptionSourceError(
            f"{label} cannot be inspected"
        ) from None
    if (
        not stat.S_ISREG(before.st_mode)
        or stat.S_ISLNK(before.st_mode)
        or _is_reparse_stat(before)
    ):
        raise ClaudeStoredSubscriptionSourceError(
            f"{label} must be a regular non-symlink/reparse file"
        )
    if int(getattr(before, "st_nlink", 1)) != 1:
        raise ClaudeStoredSubscriptionSourceError(
            f"{label} is a hardlink alias"
        )
    if int(before.st_size) > MAX_CREDENTIAL_FILE_BYTES:
        raise ClaudeStoredSubscriptionSourceError(
            f"{label} exceeds its observation ceiling"
        )

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(canonical, flags)
    except OSError:
        raise ClaudeStoredSubscriptionSourceError(
            f"{label} cannot be opened without following aliases"
        ) from None
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or (int(opened.st_dev), int(opened.st_ino))
            != (int(before.st_dev), int(before.st_ino))
            or int(getattr(opened, "st_nlink", 1)) != 1
        ):
            raise ClaudeStoredSubscriptionSourceError(
                f"{label} changed or resolved through an alias while opening"
            )
        first = _read_descriptor_bounded(
            descriptor,
            ceiling=MAX_CREDENTIAL_FILE_BYTES,
            label=label,
        )
        os.lseek(descriptor, 0, os.SEEK_SET)
        second = _read_descriptor_bounded(
            descriptor,
            ceiling=MAX_CREDENTIAL_FILE_BYTES,
            label=label,
        )
        after_fd = os.fstat(descriptor)
        try:
            after_path = os.lstat(canonical)
        except OSError:
            raise ClaudeStoredSubscriptionSourceError(
                f"{label} disappeared during observation"
            ) from None
        descriptor_fields = (
            "st_dev",
            "st_ino",
            "st_size",
            "st_mtime_ns",
            "st_nlink",
        )
        if (
            first != second
            or any(
                int(getattr(before, field, 0))
                != int(getattr(after_fd, field, 0))
                or int(getattr(before, field, 0))
                != int(getattr(after_path, field, 0))
                for field in descriptor_fields
            )
            or int(getattr(before, "st_ctime_ns", 0))
            != int(getattr(after_path, "st_ctime_ns", 0))
            or int(before.st_mode) != int(after_path.st_mode)
            or stat.S_ISLNK(after_path.st_mode)
            or _is_reparse_stat(after_path)
            or len(first) != int(before.st_size)
        ):
            raise ClaudeStoredSubscriptionSourceError(
                f"{label} changed or drifted during observation"
            )
        material = bytearray(first)
        return canonical, before, material, descriptor
    except OSError:
        os.close(descriptor)
        raise ClaudeStoredSubscriptionSourceError(
            f"{label} could not be observed through its exact descriptor"
        ) from None
    except BaseException:
        os.close(descriptor)
        raise


def _implementation_authority_sha256() -> str:
    rows: list[dict[str, Any]] = []
    for role, module_path in (
        ("stored-subscription-observer", Path(__file__)),
        ("stored-source-schema-replayer", Path(_auth.__file__)),
    ):
        _, _, raw = _stable_regular_file_bytes(
            module_path,
            ceiling=MAX_IMPLEMENTATION_FILE_BYTES,
            label=f"{role} implementation",
        )
        rows.append(
            {
                "role": role,
                "size": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest(),
            }
        )
    return hashlib.sha256(_canonical_json(rows)).hexdigest()


def _macos_current_account() -> str:
    """Return the kernel UID's account, never an ambient environment alias."""

    if _detect_host_platform() != HOST_MACOS:
        raise ClaudeStoredSubscriptionSourceError(
            "macOS Keychain account observation requested on another host",
            reason_code="KEYCHAIN_HOST_INVALID",
        )
    try:
        import pwd

        account = pwd.getpwuid(os.getuid()).pw_name
    except (ImportError, KeyError, OSError):
        raise ClaudeStoredSubscriptionSourceError(
            "macOS Keychain current account is unavailable",
            reason_code="KEYCHAIN_ACCOUNT_UNAVAILABLE",
        ) from None
    if (
        not isinstance(account, str)
        or not account
        or account != account.strip()
        or "\x00" in account
        or len(account.encode("utf-8")) > 1024
    ):
        raise ClaudeStoredSubscriptionSourceError(
            "macOS Keychain current account is malformed",
            reason_code="KEYCHAIN_ACCOUNT_INVALID",
        )
    return account


def _macos_security_tool_identity() -> dict[str, Any]:
    """Bind the exact SIP-owned executable used by Claude's Keychain query."""

    canonical, info, raw = _stable_regular_file_bytes(
        Path(MACOS_SECURITY_TOOL),
        ceiling=MAX_IMPLEMENTATION_FILE_BYTES,
        label="macOS security tool",
    )
    if (
        str(canonical) != MACOS_SECURITY_TOOL
        or int(getattr(info, "st_uid", -1)) != 0
        or int(info.st_mode) & 0o022
    ):
        raise ClaudeStoredSubscriptionSourceError(
            "macOS security tool authority is invalid",
            reason_code="KEYCHAIN_TOOL_AUTHORITY_INVALID",
        )
    return {
        "path": MACOS_SECURITY_TOOL,
        "device": int(info.st_dev),
        "inode": int(info.st_ino),
        "mode": int(info.st_mode),
        "owner_uid": int(getattr(info, "st_uid", -1)),
        "size": len(raw),
        "mtime_ns": int(info.st_mtime_ns),
        "ctime_ns": int(info.st_ctime_ns),
        "link_count": int(getattr(info, "st_nlink", 1)),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }


def _macos_keychain_binding(
    *,
    account: str | None = None,
    tool_identity: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    exact_account = account if account is not None else _macos_current_account()
    if (
        not isinstance(exact_account, str)
        or not exact_account
        or exact_account != exact_account.strip()
        or "\x00" in exact_account
    ):
        raise ClaudeStoredSubscriptionSourceError(
            "macOS Keychain current account is malformed",
            reason_code="KEYCHAIN_ACCOUNT_INVALID",
        )
    exact_tool = dict(
        tool_identity
        if tool_identity is not None
        else _macos_security_tool_identity()
    )
    binding = {
        "schema": "plamen.macos_claude_keychain_binding.v1",
        "service": MACOS_CLAUDE_KEYCHAIN_SERVICE,
        "account": exact_account,
        "tool_identity": exact_tool,
        "observation_argv": [
            MACOS_SECURITY_TOOL,
            "find-generic-password",
            "-s",
            MACOS_CLAUDE_KEYCHAIN_SERVICE,
            "-a",
            exact_account,
        ],
        "acquisition_argv": [
            MACOS_SECURITY_TOOL,
            "find-generic-password",
            "-s",
            MACOS_CLAUDE_KEYCHAIN_SERVICE,
            "-a",
            exact_account,
            "-w",
        ],
        "password_output_normalization": "REMOVE_ONE_TRAILING_LF",
    }
    try:
        return json.loads(_canonical_json(binding).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ClaudeStoredSubscriptionSourceError(
            "macOS Keychain binding is malformed",
            reason_code="KEYCHAIN_BINDING_INVALID",
        ) from None


def _macos_keychain_source_identity(
    binding: Mapping[str, Any],
    *,
    status: str,
) -> str:
    prefixes = {
        "AVAILABLE": "keychain-macos-",
        "UNAVAILABLE": "keychain-macos-unavailable-",
        "INTERACTION_REQUIRED": "keychain-macos-interaction-",
    }
    try:
        prefix = prefixes[status]
    except KeyError:
        raise ClaudeStoredSubscriptionSourceError(
            "macOS Keychain status is invalid",
            reason_code="KEYCHAIN_STATUS_INVALID",
        ) from None
    return f"{prefix}{hashlib.sha256(_canonical_json(binding)).hexdigest()}"


def _validate_macos_source_marker(
    source_path: str | os.PathLike[str] | None,
) -> None:
    """Accept the runtime's absent-file marker, never a file-backed secret."""

    if source_path is None:
        return
    text = _path_text(source_path)
    if Path(text).name != ".credentials.json":
        raise ClaudeStoredSubscriptionSourceError(
            "macOS Keychain route requires the .credentials.json marker",
            reason_code="KEYCHAIN_SOURCE_MARKER_INVALID",
        )
    if os.path.lexists(text):
        raise ClaudeStoredSubscriptionSourceError(
            "macOS Keychain file-backed credential emulation is unimplemented",
            reason_code="KEYCHAIN_FILE_SOURCE_REJECTED",
        )


_KeychainRunner = Callable[..., _SecurityCommandResult]
_ToolIdentityObserver = Callable[[], Mapping[str, Any]]


def _invoke_macos_keychain(
    *,
    binding: Mapping[str, Any],
    acquisition: bool,
    runner: _KeychainRunner,
) -> _SecurityCommandResult:
    field = "acquisition_argv" if acquisition else "observation_argv"
    argv = binding.get(field)
    account = binding.get("account")
    tool_identity = binding.get("tool_identity")
    if not isinstance(account, str) or not isinstance(
        tool_identity, Mapping
    ):
        raise ClaudeStoredSubscriptionSourceError(
            "macOS Keychain binding drifted",
            reason_code="KEYCHAIN_BINDING_DRIFT",
        )
    try:
        expected = _macos_keychain_binding(
            account=account,
            tool_identity=tool_identity,
        )
    except (ClaudeStoredSubscriptionSourceError, TypeError, ValueError):
        raise ClaudeStoredSubscriptionSourceError(
            "macOS Keychain binding drifted",
            reason_code="KEYCHAIN_BINDING_DRIFT",
        ) from None
    if (
        dict(binding) != expected
        or not isinstance(argv, list)
        or any(not isinstance(item, str) for item in argv)
    ):
        raise ClaudeStoredSubscriptionSourceError(
            "macOS Keychain binding drifted",
            reason_code="KEYCHAIN_BINDING_DRIFT",
        )
    result = runner(
        tuple(argv),
        timeout_s=MACOS_KEYCHAIN_TIMEOUT_SECONDS,
        stdout_ceiling=(
            MAX_CREDENTIAL_FILE_BYTES + 2
            if acquisition
            else MAX_KEYCHAIN_OBSERVATION_STDOUT_BYTES
        ),
        stderr_ceiling=MAX_KEYCHAIN_STDERR_BYTES,
    )
    if type(result) is not _SecurityCommandResult:
        raise ClaudeStoredSubscriptionSourceError(
            "macOS Keychain command result is invalid",
            reason_code="KEYCHAIN_COMMAND_RESULT_INVALID",
        )
    return result


def _observe_macos_keychain(
    *,
    runner: _KeychainRunner = _run_bounded_security_command,
    account: str | None = None,
    tool_identity_observer: _ToolIdentityObserver | None = None,
) -> dict[str, Any]:
    observer = (
        tool_identity_observer
        if tool_identity_observer is not None
        else _macos_security_tool_identity
    )
    binding = _macos_keychain_binding(
        account=account,
        tool_identity=observer(),
    )
    result = _invoke_macos_keychain(
        binding=binding,
        acquisition=False,
        runner=runner,
    )
    try:
        after_binding = _macos_keychain_binding(
            account=account,
            tool_identity=observer(),
        )
        if after_binding != binding:
            raise ClaudeStoredSubscriptionSourceError(
                "macOS Keychain command authority changed",
                reason_code="KEYCHAIN_TOOL_CHANGED",
            )
        if result.overflowed:
            raise ClaudeStoredSubscriptionSourceError(
                "macOS Keychain observation exceeded its output ceiling",
                reason_code="KEYCHAIN_OUTPUT_LIMIT",
            )
        if result.timed_out or result.returncode in {36, 128}:
            return _emit_evidence(
                store_class="OS_KEYCHAIN",
                source_identity=_macos_keychain_source_identity(
                    binding,
                    status="INTERACTION_REQUIRED",
                ),
                source_size=0,
                available=False,
            )
        if result.returncode == 44:
            return _emit_evidence(
                store_class="OS_KEYCHAIN",
                source_identity=_macos_keychain_source_identity(
                    binding,
                    status="UNAVAILABLE",
                ),
                source_size=0,
                available=False,
            )
        if result.returncode != 0:
            raise ClaudeStoredSubscriptionSourceError(
                "macOS Keychain observation failed",
                reason_code="KEYCHAIN_OBSERVATION_FAILED",
            )
        return _emit_evidence(
            store_class="OS_KEYCHAIN",
            source_identity=_macos_keychain_source_identity(
                binding,
                status="AVAILABLE",
            ),
            source_size=0,
            available=True,
        )
    finally:
        result.discard()


def _emit_evidence(
    *,
    store_class: str,
    source_identity: str,
    source_size: int,
    available: bool,
) -> dict[str, Any]:
    core = {
        "schema": _auth.STORED_SUBSCRIPTION_SOURCE_SCHEMA,
        "store_class": store_class,
        "source_identity": source_identity,
        "source_size": source_size,
        "available": available,
        "observation_authority_sha256": (
            _implementation_authority_sha256()
        ),
        "credential_values_recorded": False,
        "credential_content_hashes_recorded": False,
    }
    evidence = {**core, "receipt_sha256": _digest(core)}
    try:
        return _auth.replay_stored_subscription_source_evidence(evidence)
    except _auth.ClaudeAuthRouteError as exc:
        raise ClaudeStoredSubscriptionSourceError(
            "stored-subscription evidence schema rejected provider output"
        ) from exc


def replay_stored_subscription_materialization_receipt(
    value: Mapping[str, Any],
) -> dict[str, Any]:
    """Replay a one-shot exact-copy receipt without credential material."""

    if not isinstance(value, Mapping):
        raise ClaudeStoredSubscriptionSourceError(
            "stored-subscription materialization receipt must be an object"
        )
    clone = dict(value)
    expected_fields = {
        "schema",
        "source_evidence",
        "private_target_authority_sha256",
        "source_size",
        "exact_copy_verified",
        "source_descriptor_replayed",
        "source_path_reopened",
        "source_bytes_reread",
        "materialization_id",
        "credential_values_recorded",
        "credential_content_hashes_recorded",
        "receipt_sha256",
    }
    if set(clone) != expected_fields:
        raise ClaudeStoredSubscriptionSourceError(
            "stored-subscription materialization fields drifted"
        )
    digest = clone.pop("receipt_sha256")
    try:
        source = _auth.replay_stored_subscription_source_evidence(
            clone.get("source_evidence")
        )
    except _auth.ClaudeAuthRouteError:
        raise ClaudeStoredSubscriptionSourceError(
            "stored-subscription materialization source does not replay"
        ) from None
    if (
        clone.get("schema")
        != STORED_SUBSCRIPTION_MATERIALIZATION_SCHEMA
        or source["store_class"] not in {"FILE_BACKED", "OS_KEYCHAIN"}
        or source["available"] is not True
        or clone.get("source_size") != source["source_size"]
        or clone.get("exact_copy_verified") is not True
        or (
            source["store_class"] == "FILE_BACKED"
            and clone.get("source_descriptor_replayed") is not True
        )
        or (
            source["store_class"] == "OS_KEYCHAIN"
            and clone.get("source_descriptor_replayed") is not False
        )
        or clone.get("source_path_reopened") is not False
        or clone.get("source_bytes_reread") is not False
        or not isinstance(
            clone.get("private_target_authority_sha256"),
            str,
        )
        or _SHA256_RE.fullmatch(
            clone["private_target_authority_sha256"]
        )
        is None
        or not isinstance(clone.get("materialization_id"), str)
        or _OPAQUE_ID_RE.fullmatch(clone["materialization_id"]) is None
        or clone.get("credential_values_recorded") is not False
        or clone.get("credential_content_hashes_recorded") is not False
        or not isinstance(digest, str)
        or _SHA256_RE.fullmatch(digest) is None
    ):
        raise ClaudeStoredSubscriptionSourceError(
            "stored-subscription materialization receipt does not replay"
        )
    clone["source_evidence"] = source
    if digest != _digest(clone):
        raise ClaudeStoredSubscriptionSourceError(
            "stored-subscription materialization digest drifted"
        )
    return {**clone, "receipt_sha256": digest}


def _path_stat_signature(info: os.stat_result) -> tuple[int, ...]:
    return (
        int(info.st_dev),
        int(info.st_ino),
        int(info.st_size),
        int(info.st_mtime_ns),
        int(info.st_ctime_ns),
        int(info.st_mode),
        int(getattr(info, "st_nlink", 1)),
    )


def _descriptor_stat_signature(info: os.stat_result) -> tuple[int, ...]:
    return (
        int(info.st_dev),
        int(info.st_ino),
        int(info.st_size),
        int(info.st_mtime_ns),
        int(getattr(info, "st_nlink", 1)),
    )


def _private_target_authority(
    value: Mapping[str, Any],
) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ClaudeStoredSubscriptionSourceError(
            "private credential target authority must be an object"
        )
    clone = dict(value)
    expected = {
        "schema",
        "run_id",
        "startup_permit_sha256",
        "outer_attempt_arm_sha256",
        "execution_generation_sha256",
        "work_plan_sha256",
        "attempt_id",
        "process_scope_identity",
        "auxiliary_lease_binding_sha256",
        "launch_security_policy_sha256",
        "executable_observation_sha256",
        "auth_environment_receipt_sha256",
        "settings_authority_sha256",
        "mcp_authority_sha256",
        "target_role",
        "credential_parent_identity",
    }
    digests = expected - {
        "schema",
        "run_id",
        "attempt_id",
        "process_scope_identity",
        "target_role",
        "credential_parent_identity",
    }
    parent = clone.get("credential_parent_identity")
    if (
        set(clone) != expected
        or clone.get("schema")
        != PRIVATE_CREDENTIAL_TARGET_AUTHORITY_SCHEMA
        or not isinstance(clone.get("run_id"), str)
        or not clone["run_id"]
        or len(clone["run_id"]) > 128
        or not isinstance(clone.get("attempt_id"), str)
        or not clone["attempt_id"]
        or len(clone["attempt_id"]) > 128
        or not isinstance(clone.get("process_scope_identity"), str)
        or not clone["process_scope_identity"]
        or len(clone["process_scope_identity"]) > 128
        or clone.get("target_role")
        != "CLAUDE_STORED_SUBSCRIPTION_CREDENTIAL"
        or any(
            not isinstance(clone.get(name), str)
            or _SHA256_RE.fullmatch(clone[name]) is None
            for name in digests
        )
        or clone.get("execution_generation_sha256")
        != clone.get("work_plan_sha256")
        or not isinstance(parent, Mapping)
        or not parent
        or any(
            not isinstance(name, str)
            or not name
            or isinstance(item, bool)
            or not isinstance(item, int)
            or item < 0
            for name, item in parent.items()
        )
    ):
        raise ClaudeStoredSubscriptionSourceError(
            "private credential target authority is malformed"
        )
    return json.loads(_canonical_json(clone).decode("utf-8"))


def _target_identity(
    descriptor: int,
    path: Path,
) -> tuple[tuple[int, ...], tuple[int, ...]]:
    try:
        descriptor_info = os.fstat(descriptor)
        path_info = os.lstat(path)
    except OSError:
        raise ClaudeStoredSubscriptionSourceError(
            "private credential target identity is unavailable"
        ) from None
    if (
        not stat.S_ISREG(descriptor_info.st_mode)
        or not stat.S_ISREG(path_info.st_mode)
        or stat.S_ISLNK(path_info.st_mode)
        or _is_reparse_stat(path_info)
        or int(getattr(descriptor_info, "st_nlink", 1)) != 1
        or int(getattr(path_info, "st_nlink", 1)) != 1
        or int(descriptor_info.st_size) != 0
        or int(path_info.st_size) != 0
        or (int(descriptor_info.st_dev), int(descriptor_info.st_ino))
        != (int(path_info.st_dev), int(path_info.st_ino))
    ):
        raise ClaudeStoredSubscriptionSourceError(
            "destination must be an empty private regular file"
        )
    return (
        _descriptor_stat_signature(descriptor_info),
        _path_stat_signature(path_info),
    )


def _validate_private_target_security(
    path: Path,
    *,
    host: str,
) -> None:
    try:
        info = os.lstat(path)
    except OSError:
        raise ClaudeStoredSubscriptionSourceError(
            "private credential target security is unavailable"
        ) from None
    if host == HOST_WINDOWS_NATIVE:
        _verify_windows_source_security(path)
    elif host in {HOST_LINUX_NATIVE, HOST_WSL_NATIVE, HOST_MACOS}:
        if host == HOST_WSL_NATIVE:
            _require_wsl_native_root(str(path))
        _validate_posix_source_security(path, info)
    else:
        raise ClaudeStoredSubscriptionSourceError(
            "private credential target host is unsupported"
        )


class PrivateCredentialTargetCapability:
    """One-shot exact descriptor plus pre-write security authority."""

    __slots__ = (
        "__active",
        "__authority",
        "__authority_sha256",
        "__descriptor",
        "__descriptor_signature",
        "__host",
        "__integrity_key",
        "__integrity_tag",
        "__lock",
        "__path",
        "__path_signature",
        "__weakref__",
    )

    def __init__(
        self,
        *,
        descriptor: int,
        path: Path,
        host: str,
        authority: Mapping[str, Any],
        descriptor_signature: tuple[int, ...],
        path_signature: tuple[int, ...],
        _token: object,
        _issuance_id: str | None = None,
    ) -> None:
        if (
            type(self) is not PrivateCredentialTargetCapability
            or _token is not _PRIVATE_TARGET_TOKEN
            or not isinstance(_issuance_id, str)
        ):
            raise TypeError(
                "private credential target capability is provider-owned"
            )
        normalized = _private_target_authority(authority)
        with _CAPABILITY_STATE_LOCK:
            pending = _PRIVATE_TARGET_PENDING.pop(
                _issuance_id,
                None,
            )
        if (
            pending is None
            or pending["descriptor"] != descriptor
            or pending["path"] != path
            or pending["host"] != host
            or pending["authority"] != normalized
            or pending["descriptor_signature"]
            != descriptor_signature
            or pending["path_signature"] != path_signature
        ):
            raise TypeError(
                "private credential target requires validator issuance"
            )
        authority_sha256 = _digest(normalized)
        material = _canonical_json(
            {
                "authority_sha256": authority_sha256,
                "descriptor_signature": list(descriptor_signature),
                "path_signature": list(path_signature),
                "host": host,
            }
        )
        self.__authority = normalized
        self.__authority_sha256 = authority_sha256
        self.__descriptor = descriptor
        self.__descriptor_signature = descriptor_signature
        self.__path = path
        self.__path_signature = path_signature
        self.__host = host
        self.__integrity_key = bytearray(secrets.token_bytes(32))
        self.__integrity_tag = bytearray(
            hmac.digest(self.__integrity_key, material, "sha256")
        )
        self.__active = True
        self.__lock = threading.Lock()
        state = {
            "authority_sha256": authority_sha256,
            "descriptor": descriptor,
            "path": path,
            "descriptor_signature": descriptor_signature,
            "path_signature": path_signature,
            "consumed": False,
            "issuer_pid": os.getpid(),
        }
        key = id(self)

        def retire(reference: weakref.ReferenceType[Any]) -> None:
            with _CAPABILITY_STATE_LOCK:
                current = _PRIVATE_TARGET_ISSUED.get(key)
                if current is not None and current[0] is reference:
                    _PRIVATE_TARGET_ISSUED.pop(key, None)

        reference = weakref.ref(self, retire)
        with _CAPABILITY_STATE_LOCK:
            _PRIVATE_TARGET_ISSUED[key] = (reference, state)

    def __repr__(self) -> str:
        return "<PrivateCredentialTargetCapability opaque>"

    def __copy__(self) -> None:
        raise TypeError("private credential target cannot be copied")

    def __deepcopy__(self, _memo: object) -> None:
        raise TypeError("private credential target cannot be copied")

    def __reduce__(self) -> None:
        raise TypeError("private credential target cannot be serialized")

    def _consume(self) -> tuple[int, str]:
        with _CAPABILITY_STATE_LOCK:
            issued = _PRIVATE_TARGET_ISSUED.get(id(self))
            if (
                issued is None
                or issued[0]() is not self
                or issued[1]["consumed"]
                or issued[1]["issuer_pid"] != os.getpid()
            ):
                raise ClaudeStoredSubscriptionSourceError(
                    "private credential target capability is stale or consumed"
                )
            issued[1]["consumed"] = True
            material = _canonical_json(
                {
                    "authority_sha256": self.__authority_sha256,
                    "descriptor_signature": list(
                        self.__descriptor_signature
                    ),
                    "path_signature": list(self.__path_signature),
                    "host": self.__host,
                }
            )
            if not hmac.compare_digest(
                hmac.digest(
                    self.__integrity_key,
                    material,
                    "sha256",
                ),
                self.__integrity_tag,
            ) or (
                issued[1]["authority_sha256"]
                != self.__authority_sha256
                or issued[1]["descriptor"] != self.__descriptor
                or issued[1]["path"] != self.__path
                or issued[1]["descriptor_signature"]
                != self.__descriptor_signature
                or issued[1]["path_signature"]
                != self.__path_signature
            ):
                raise ClaudeStoredSubscriptionSourceError(
                    "private credential target capability was rebound"
                )
            descriptor_signature, path_signature = _target_identity(
                self.__descriptor,
                self.__path,
            )
            if (
                descriptor_signature != self.__descriptor_signature
                or path_signature != self.__path_signature
            ):
                raise ClaudeStoredSubscriptionSourceError(
                    "private credential target identity changed"
                )
            _validate_private_target_security(
                self.__path,
                host=self.__host,
            )
            # Recheck identity after ACL/mode observation.
            if _target_identity(self.__descriptor, self.__path) != (
                self.__descriptor_signature,
                self.__path_signature,
            ):
                raise ClaudeStoredSubscriptionSourceError(
                    "private credential target changed during security replay"
                )
            self.__active = False
            for private in (self.__integrity_key, self.__integrity_tag):
                for index in range(len(private)):
                    private[index] = 0
            return self.__descriptor, self.__authority_sha256


def authorize_private_credential_target(
    destination_descriptor: int,
    *,
    destination_path: str | os.PathLike[str],
    target_authority: Mapping[str, Any],
    host_platform: str | None = None,
) -> PrivateCredentialTargetCapability:
    """Bind one empty private file to one exact execution target authority."""

    if (
        isinstance(destination_descriptor, bool)
        or not isinstance(destination_descriptor, int)
        or destination_descriptor < 0
    ):
        raise ClaudeStoredSubscriptionSourceError(
            "private credential target descriptor is malformed"
        )
    path, missing = _canonical_candidate_path(
        destination_path,
        label="private credential target",
    )
    if missing:
        raise ClaudeStoredSubscriptionSourceError(
            "private credential target disappeared before authorization"
        )
    host = host_platform or _detect_host_platform()
    descriptor_signature, path_signature = _target_identity(
        destination_descriptor,
        path,
    )
    _validate_private_target_security(path, host=host)
    if _target_identity(destination_descriptor, path) != (
        descriptor_signature,
        path_signature,
    ):
        raise ClaudeStoredSubscriptionSourceError(
            "private credential target changed during authorization"
        )
    normalized_authority = _private_target_authority(target_authority)
    issuance_id = secrets.token_hex(32)
    pending = {
        "descriptor": destination_descriptor,
        "path": path,
        "host": host,
        "authority": normalized_authority,
        "descriptor_signature": descriptor_signature,
        "path_signature": path_signature,
    }
    with _CAPABILITY_STATE_LOCK:
        _PRIVATE_TARGET_PENDING[issuance_id] = pending
    try:
        return PrivateCredentialTargetCapability(
            descriptor=destination_descriptor,
            path=path,
            host=host,
            authority=normalized_authority,
            descriptor_signature=descriptor_signature,
            path_signature=path_signature,
            _token=_PRIVATE_TARGET_TOKEN,
            _issuance_id=issuance_id,
        )
    finally:
        with _CAPABILITY_STATE_LOCK:
            _PRIVATE_TARGET_PENDING.pop(issuance_id, None)


class StoredSubscriptionMaterializationCapability:
    """Opaque, one-shot ownership of exact observed credential bytes."""

    __slots__ = (
        "__buffer",
        "__host",
        "__integrity_key",
        "__integrity_tag",
        "__lock",
        "__source_evidence_authority",
        "__source_descriptor",
        "__source_descriptor_signature",
        "__source_kind",
        "__keychain_binding",
        "__source_path",
        "__source_path_signature",
        "__state",
        "__weakref__",
    )

    def __init__(
        self,
        *,
        material: bytearray,
        source_descriptor: int,
        source_path: Path | None,
        source_info: os.stat_result | None,
        source_kind: str,
        keychain_binding: Mapping[str, Any] | None,
        host: str,
        source_evidence: Mapping[str, Any],
        _issuance_id: str | None = None,
    ) -> None:
        if not isinstance(material, bytearray):
            raise TypeError("credential material must be privately mutable")
        replayed = _auth.replay_stored_subscription_source_evidence(
            source_evidence
        )
        if not isinstance(_issuance_id, str):
            raise TypeError(
                "stored-subscription capability requires acquisition"
            )
        with _CAPABILITY_STATE_LOCK:
            pending = _MATERIALIZATION_PENDING.pop(
                _issuance_id,
                None,
            )
        source_signature = (
            None
            if source_info is None
            else _path_stat_signature(source_info)
        )
        normalized_keychain_binding = (
            None
            if keychain_binding is None
            else json.loads(
                _canonical_json(dict(keychain_binding)).decode("utf-8")
            )
        )
        if (
            pending is None
            or pending["material"] is not material
            or pending["source_descriptor"] != source_descriptor
            or pending["source_path"] != source_path
            or pending["source_signature"] != source_signature
            or pending["source_kind"] != source_kind
            or pending["keychain_binding"] != normalized_keychain_binding
            or pending["host"] != host
            or pending["source_evidence"] != replayed
            or (
                source_kind == "FILE_BACKED"
                and (
                    source_info is None
                    or source_path is None
                    or source_descriptor < 0
                    or keychain_binding is not None
                    or replayed["store_class"] != "FILE_BACKED"
                )
            )
            or (
                source_kind == "OS_KEYCHAIN"
                and (
                    host != HOST_MACOS
                    or source_info is not None
                    or source_path is not None
                    or source_descriptor != -1
                    or normalized_keychain_binding is None
                    or replayed["store_class"] != "OS_KEYCHAIN"
                )
            )
            or source_kind not in {"FILE_BACKED", "OS_KEYCHAIN"}
        ):
            raise TypeError(
                "stored-subscription capability requires validator issuance"
            )
        self.__buffer = material
        self.__source_descriptor = source_descriptor
        self.__source_path = source_path
        self.__source_path_signature = source_signature
        self.__source_descriptor_signature = (
            None
            if source_info is None
            else _descriptor_stat_signature(source_info)
        )
        self.__source_kind = source_kind
        self.__keychain_binding = normalized_keychain_binding
        self.__host = host
        self.__source_evidence_authority = (
            _auth._promote_stored_subscription_source_evidence(
                replayed,
                provider_authority_sha256=(
                    replayed["observation_authority_sha256"]
                ),
            )
        )
        self.__integrity_key = bytearray(secrets.token_bytes(32))
        self.__integrity_tag = bytearray(
            hmac.digest(
                self.__integrity_key,
                self.__buffer,
                "sha256",
            )
        )
        self.__state = "READY"
        self.__lock = threading.Lock()
        state = {
            "source_descriptor": source_descriptor,
            "source_path": source_path,
            "source_path_signature": self.__source_path_signature,
            "source_descriptor_signature": (
                self.__source_descriptor_signature
            ),
            "source_kind": source_kind,
            "keychain_binding_sha256": (
                None
                if normalized_keychain_binding is None
                else hashlib.sha256(
                    _canonical_json(normalized_keychain_binding)
                ).hexdigest()
            ),
            "source_evidence_receipt_sha256": replayed["receipt_sha256"],
            "state": "READY",
            "issuer_pid": os.getpid(),
        }
        key = id(self)

        def retire(reference: weakref.ReferenceType[Any]) -> None:
            with _CAPABILITY_STATE_LOCK:
                current = _MATERIALIZATION_ISSUED.get(key)
                if current is not None and current[0] is reference:
                    _MATERIALIZATION_ISSUED.pop(key, None)

        reference = weakref.ref(self, retire)
        with _CAPABILITY_STATE_LOCK:
            _MATERIALIZATION_ISSUED[key] = (reference, state)

    def __repr__(self) -> str:
        return "<StoredSubscriptionMaterializationCapability opaque>"

    def __copy__(self) -> None:
        raise TypeError("stored-subscription capability cannot be copied")

    def __deepcopy__(self, _memo: object) -> None:
        raise TypeError("stored-subscription capability cannot be copied")

    def __reduce__(self) -> None:
        raise TypeError("stored-subscription capability cannot be serialized")

    def __reduce_ex__(self, _protocol: int) -> None:
        raise TypeError("stored-subscription capability cannot be serialized")

    def __getstate__(self) -> None:
        raise TypeError("stored-subscription capability cannot be serialized")

    @property
    def source_evidence(self) -> dict[str, Any]:
        with _CAPABILITY_STATE_LOCK:
            issued = _MATERIALIZATION_ISSUED.get(id(self))
            if (
                issued is None
                or issued[0]() is not self
                or issued[1]["issuer_pid"] != os.getpid()
            ):
                raise ClaudeStoredSubscriptionSourceError(
                    "stored-subscription capability was not acquired"
                )
            replayed = _auth.replay_stored_subscription_source_evidence(
                self.__source_evidence_authority
            )
            if (
                replayed["receipt_sha256"]
                != issued[1]["source_evidence_receipt_sha256"]
            ):
                raise ClaudeStoredSubscriptionSourceError(
                    "stored-subscription capability evidence drifted"
                )
            return self.__source_evidence_authority

    def __destroy_material(self) -> None:
        authority = getattr(
            self,
            "_StoredSubscriptionMaterializationCapability"
            "__source_evidence_authority",
            None,
        )
        if authority is not None:
            authority._invalidate()
        for private in (
            self.__buffer,
            self.__integrity_key,
            self.__integrity_tag,
        ):
            for index in range(len(private)):
                private[index] = 0
        self.__buffer = bytearray()
        self.__integrity_key = bytearray()
        self.__integrity_tag = bytearray()
        if self.__source_descriptor >= 0:
            try:
                os.close(self.__source_descriptor)
            except OSError:
                pass
            self.__source_descriptor = -1

    def __del__(self) -> None:
        try:
            self.__destroy_material()
        except BaseException:
            pass

    def discard(self) -> None:
        with _CAPABILITY_STATE_LOCK:
            issued = _MATERIALIZATION_ISSUED.get(id(self))
            if (
                issued is None
                or issued[0]() is not self
                or issued[1]["issuer_pid"] != os.getpid()
                or issued[1]["state"] != "READY"
                or self.__state != "READY"
            ):
                raise ClaudeStoredSubscriptionSourceError(
                    "stored-subscription capability is no longer available"
                )
            issued[1]["state"] = "DISCARDED"
            self.__state = "DISCARDED"
            self.__destroy_material()

    def __validate_integrity_and_source(self) -> None:
        if not hmac.compare_digest(
            hmac.digest(
                self.__integrity_key,
                self.__buffer,
                "sha256",
            ),
            self.__integrity_tag,
        ):
            raise ClaudeStoredSubscriptionSourceError(
                "stored-subscription capability was tampered"
            )
        if self.__source_kind == "OS_KEYCHAIN":
            if (
                self.__host != HOST_MACOS
                or self.__source_descriptor != -1
                or self.__source_path is not None
                or self.__source_path_signature is not None
                or self.__source_descriptor_signature is not None
                or self.__keychain_binding is None
                or _macos_keychain_binding() != self.__keychain_binding
                or self.__source_evidence_authority["store_class"]
                != "OS_KEYCHAIN"
                or self.__source_evidence_authority["source_identity"]
                != _macos_keychain_source_identity(
                    self.__keychain_binding,
                    status="AVAILABLE",
                )
                or self.__source_evidence_authority["source_size"]
                != len(self.__buffer)
            ):
                raise ClaudeStoredSubscriptionSourceError(
                    "stored-subscription Keychain authority changed",
                    reason_code="KEYCHAIN_AUTHORITY_CHANGED",
                )
            return
        if self.__source_kind != "FILE_BACKED":
            raise ClaudeStoredSubscriptionSourceError(
                "stored-subscription capability host became unsupported"
            )
        assert self.__source_path is not None
        try:
            descriptor_info = os.fstat(self.__source_descriptor)
            path_info = os.lstat(self.__source_path)
        except OSError:
            raise ClaudeStoredSubscriptionSourceError(
                "stored-subscription source changed"
            ) from None
        if (
            _descriptor_stat_signature(descriptor_info)
            != self.__source_descriptor_signature
            or _path_stat_signature(path_info)
            != self.__source_path_signature
            or (int(descriptor_info.st_dev), int(descriptor_info.st_ino))
            != (int(path_info.st_dev), int(path_info.st_ino))
            or not stat.S_ISREG(path_info.st_mode)
            or stat.S_ISLNK(path_info.st_mode)
            or _is_reparse_stat(path_info)
            or int(getattr(path_info, "st_nlink", 1)) != 1
            or len(self.__buffer) != int(path_info.st_size)
        ):
            raise ClaudeStoredSubscriptionSourceError(
                "stored-subscription source changed"
            )
        if self.__host == HOST_WINDOWS_NATIVE:
            _verify_windows_source_security(self.__source_path)
        elif self.__host in {HOST_LINUX_NATIVE, HOST_WSL_NATIVE}:
            if self.__host == HOST_WSL_NATIVE:
                _require_wsl_native_root(str(self.__source_path))
            _validate_posix_source_security(
                self.__source_path,
                path_info,
            )
        else:
            raise ClaudeStoredSubscriptionSourceError(
                "stored-subscription capability host became unsupported"
            )
        try:
            final_descriptor = os.fstat(self.__source_descriptor)
            final_path = os.lstat(self.__source_path)
        except OSError:
            raise ClaudeStoredSubscriptionSourceError(
                "stored-subscription source changed"
            ) from None
        if (
            _descriptor_stat_signature(final_descriptor)
            != self.__source_descriptor_signature
            or _path_stat_signature(final_path)
            != self.__source_path_signature
        ):
            raise ClaudeStoredSubscriptionSourceError(
                "stored-subscription source changed"
            )

    def consume_into_private_descriptor(
        self,
        private_target: PrivateCredentialTargetCapability,
        *,
        expected_source_evidence: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Write exact held bytes once into an already-open private target."""

        with _CAPABILITY_STATE_LOCK:
            issued = _MATERIALIZATION_ISSUED.get(id(self))
            if (
                issued is None
                or issued[0]() is not self
                or issued[1]["issuer_pid"] != os.getpid()
                or issued[1]["state"] != "READY"
                or self.__state != "READY"
            ):
                raise ClaudeStoredSubscriptionSourceError(
                    "stored-subscription capability is no longer available"
                )
            issued[1]["state"] = "CONSUMING"
            self.__state = "CONSUMING"
            target_accepted = False
            try:
                try:
                    expected = (
                        _auth.replay_stored_subscription_source_evidence(
                            expected_source_evidence
                        )
                    )
                except _auth.ClaudeAuthRouteError:
                    raise ClaudeStoredSubscriptionSourceError(
                        "stored-subscription expected evidence drifted"
                    ) from None
                internal = self.source_evidence
                if expected != internal:
                    raise ClaudeStoredSubscriptionSourceError(
                        "stored-subscription expected evidence drifted"
                    )
                if type(private_target) is not PrivateCredentialTargetCapability:
                    raise ClaudeStoredSubscriptionSourceError(
                        "typed private credential target capability is required"
                    )
                self.__validate_integrity_and_source()
                (
                    destination_descriptor,
                    private_target_authority_sha256,
                ) = private_target._consume()
                try:
                    target = os.fstat(destination_descriptor)
                    source = (
                        os.fstat(self.__source_descriptor)
                        if self.__source_descriptor >= 0
                        else None
                    )
                except OSError:
                    raise ClaudeStoredSubscriptionSourceError(
                        "destination must be an empty private regular file"
                    ) from None
                if (
                    not stat.S_ISREG(target.st_mode)
                    or int(getattr(target, "st_nlink", 1)) != 1
                    or int(target.st_size) != 0
                    or (
                        source is not None
                        and (int(target.st_dev), int(target.st_ino))
                        == (int(source.st_dev), int(source.st_ino))
                    )
                ):
                    raise ClaudeStoredSubscriptionSourceError(
                        "destination must be an empty private regular file"
                    )
                target_accepted = True
                try:
                    os.lseek(destination_descriptor, 0, os.SEEK_SET)
                    view = memoryview(self.__buffer)
                    offset = 0
                    while offset < len(view):
                        written = os.write(
                            destination_descriptor,
                            view[offset:],
                        )
                        if written <= 0:
                            raise OSError("short credential write")
                        offset += written
                    os.fsync(destination_descriptor)
                    after_write = os.fstat(destination_descriptor)
                    if int(after_write.st_size) != len(view):
                        raise OSError("credential byte count drifted")
                    os.lseek(destination_descriptor, 0, os.SEEK_SET)
                    verified = 0
                    while verified < len(view):
                        chunk = os.read(
                            destination_descriptor,
                            min(64 * 1024, len(view) - verified),
                        )
                        if (
                            not chunk
                            or chunk
                            != view[
                                verified : verified + len(chunk)
                            ].tobytes()
                        ):
                            raise OSError("credential copy mismatch")
                        verified += len(chunk)
                    if verified != len(view):
                        raise OSError("credential copy incomplete")
                    os.lseek(destination_descriptor, 0, os.SEEK_END)
                except OSError:
                    try:
                        os.ftruncate(destination_descriptor, 0)
                    except OSError:
                        pass
                    raise ClaudeStoredSubscriptionSourceError(
                        "private credential materialization failed"
                    ) from None

                core = {
                    "schema": (
                        STORED_SUBSCRIPTION_MATERIALIZATION_SCHEMA
                    ),
                    "source_evidence": internal,
                    "private_target_authority_sha256": (
                        private_target_authority_sha256
                    ),
                    "source_size": len(self.__buffer),
                    "exact_copy_verified": True,
                    "source_descriptor_replayed": (
                        self.__source_kind == "FILE_BACKED"
                    ),
                    "source_path_reopened": False,
                    "source_bytes_reread": False,
                    "materialization_id": secrets.token_hex(16),
                    "credential_values_recorded": False,
                    "credential_content_hashes_recorded": False,
                }
                receipt = {**core, "receipt_sha256": _digest(core)}
                replayed = (
                    replay_stored_subscription_materialization_receipt(
                        receipt
                    )
                )
                issued[1]["state"] = "CONSUMED"
                self.__state = "CONSUMED"
                self.__destroy_material()
                return replayed
            except ClaudeStoredSubscriptionSourceError:
                if target_accepted:
                    try:
                        os.ftruncate(destination_descriptor, 0)
                    except OSError:
                        pass
                issued[1]["state"] = "FAILED"
                self.__state = "FAILED"
                self.__destroy_material()
                raise
            except BaseException:
                if target_accepted:
                    try:
                        os.ftruncate(destination_descriptor, 0)
                    except OSError:
                        pass
                issued[1]["state"] = "FAILED"
                self.__state = "FAILED"
                self.__destroy_material()
                raise ClaudeStoredSubscriptionSourceError(
                    "private credential materialization failed"
                ) from None


def _detect_host_platform() -> str:
    if sys.platform == "win32":
        return HOST_WINDOWS_NATIVE
    if sys.platform == "darwin":
        return HOST_MACOS
    if sys.platform.startswith("linux"):
        try:
            release = Path("/proc/sys/kernel/osrelease").read_text(
                encoding="utf-8",
                errors="strict",
            )
        except OSError:
            release = ""
        if "microsoft" in release.casefold():
            return HOST_WSL_NATIVE
        return HOST_LINUX_NATIVE
    return HOST_UNSUPPORTED


def _mountinfo_unescape(value: str) -> str:
    result = value
    for encoded, decoded in (
        ("\\040", " "),
        ("\\011", "\t"),
        ("\\012", "\n"),
        ("\\134", "\\"),
    ):
        result = result.replace(encoded, decoded)
    return result


def wsl_path_has_native_linux_semantics(
    path: str,
    *,
    mountinfo_text: str,
) -> bool:
    """Return whether a WSL path is on a reviewed native Linux filesystem."""

    if (
        not isinstance(path, str)
        or not isinstance(mountinfo_text, str)
        or "\x00" in path
        or "\\" in path
    ):
        return False
    candidate = PurePosixPath(path)
    if not candidate.is_absolute():
        return False
    candidate_text = str(candidate)
    if candidate_text != path:
        return False

    mounts: list[tuple[str, str]] = []
    for raw_line in mountinfo_text.splitlines():
        try:
            left, right = raw_line.split(" - ", 1)
        except ValueError:
            return False
        left_fields = left.split()
        right_fields = right.split()
        if len(left_fields) < 5 or not right_fields:
            return False
        mount_point = _mountinfo_unescape(left_fields[4])
        filesystem_type = right_fields[0]
        if not mount_point.startswith("/"):
            return False
        mounts.append((mount_point.rstrip("/") or "/", filesystem_type))

    matching = [
        row
        for row in mounts
        if candidate_text == row[0]
        or (
            row[0] == "/"
            and candidate_text.startswith("/")
        )
        or candidate_text.startswith(row[0] + "/")
    ]
    if not matching:
        return False
    mount_point, filesystem_type = max(
        matching,
        key=lambda row: len(row[0]),
    )
    del mount_point
    return filesystem_type.casefold() in _NATIVE_WSL_FILESYSTEMS


def _read_linux_mountinfo() -> str:
    path = Path("/proc/self/mountinfo")
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise ClaudeStoredSubscriptionSourceError(
            "WSL mount authority is unavailable"
        ) from exc
    if len(raw) > MAX_MOUNTINFO_BYTES:
        raise ClaudeStoredSubscriptionSourceError(
            "WSL mount authority exceeds its observation ceiling"
        )
    try:
        return raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ClaudeStoredSubscriptionSourceError(
            "WSL mount authority is malformed"
        ) from exc


def _require_wsl_native_root(path: str) -> None:
    if not wsl_path_has_native_linux_semantics(
        path,
        mountinfo_text=_read_linux_mountinfo(),
    ):
        raise ClaudeStoredSubscriptionSourceError(
            "WSL credential source must be on a native Linux root"
        )


def _posix_mode_is_private(mode: int) -> bool:
    return isinstance(mode, int) and (stat.S_IMODE(mode) & 0o077) == 0


def _validate_posix_source_security(
    path: Path,
    info: os.stat_result,
) -> None:
    if not _posix_mode_is_private(int(info.st_mode)):
        raise ClaudeStoredSubscriptionSourceError(
            "credential source permissions are not owner-private"
        )
    if hasattr(os, "geteuid") and int(info.st_uid) != int(os.geteuid()):
        raise ClaudeStoredSubscriptionSourceError(
            "credential source owner does not match the current user"
        )
    try:
        parent = os.lstat(path.parent)
    except OSError as exc:
        raise ClaudeStoredSubscriptionSourceError(
            "credential source parent cannot be inspected"
        ) from exc
    if (
        not stat.S_ISDIR(parent.st_mode)
        or stat.S_ISLNK(parent.st_mode)
        or _is_reparse_stat(parent)
        or stat.S_IMODE(parent.st_mode) & 0o022
    ):
        raise ClaudeStoredSubscriptionSourceError(
            "credential source parent is writable by another principal"
        )
    if hasattr(os, "geteuid") and int(parent.st_uid) != int(os.geteuid()):
        raise ClaudeStoredSubscriptionSourceError(
            "credential source parent owner does not match the current user"
        )


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJsonKey(key)
        result[key] = value
    return result


def _reject_json_constant(_value: str) -> None:
    raise ValueError("non-finite JSON constant")


def _valid_secret_slot(value: object) -> bool:
    return (
        isinstance(value, str)
        and bool(value)
        and len(value) <= 256 * 1024
        and "\x00" not in value
    )


def _validate_file_store_shape(raw: bytes | bytearray) -> None:
    parse_failed = False
    try:
        decoded = raw.decode("utf-8", errors="strict")
        document = json.loads(
            decoded,
            object_pairs_hook=_strict_object,
            parse_constant=_reject_json_constant,
        )
        oauth = document["claudeAiOauth"]
        access_token = oauth["accessToken"]
        refresh_token = oauth["refreshToken"]
        expires_at = oauth["expiresAt"]
        scopes = oauth.get("scopes", [])
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        _DuplicateJsonKey,
        KeyError,
        TypeError,
        ValueError,
    ):
        parse_failed = True
        decoded = None
        document = None
        oauth = None
        access_token = None
        refresh_token = None
        expires_at = None
        scopes = None
    if parse_failed:
        # Raise outside the parser's exception context.  JSONDecodeError.doc
        # and UnicodeDecodeError.object can otherwise retain credential bytes
        # even when traceback display is suppressed with ``from None``.
        raw = None
        raise ClaudeStoredSubscriptionSourceError(
            "unsupported credential-store format"
        ) from None
    invalid_shape = (
        not isinstance(document, dict)
        or not isinstance(oauth, dict)
        or not _valid_secret_slot(access_token)
        or not _valid_secret_slot(refresh_token)
        or isinstance(expires_at, bool)
        or not isinstance(expires_at, int)
        or expires_at <= 0
        or not isinstance(scopes, list)
        or any(
            not isinstance(scope, str)
            or not scope
            or len(scope) > 256
            or "\x00" in scope
            for scope in scopes
        )
    )
    # A traceback retains this frame's locals.  Clear decoded and parsed
    # credential values before either a semantic-shape exception or return.
    raw = None
    decoded = None
    document = None
    oauth = None
    access_token = None
    refresh_token = None
    expires_at = None
    scopes = None
    if invalid_shape:
        raise ClaudeStoredSubscriptionSourceError(
            "unsupported credential-store format"
        ) from None


def _metadata_source_identity(
    *,
    host: str,
    path: Path,
    info: os.stat_result,
) -> str:
    normalized_path = (
        os.path.normcase(str(path))
        if host == HOST_WINDOWS_NATIVE
        else str(path)
    )
    metadata = {
        "host": host,
        "path": normalized_path,
        "device": int(info.st_dev),
        "inode": int(info.st_ino),
        "mode": int(info.st_mode),
        "size": int(info.st_size),
        "mtime_ns": int(info.st_mtime_ns),
        "ctime_ns": int(info.st_ctime_ns),
        "link_count": int(getattr(info, "st_nlink", 1)),
    }
    metadata_digest = hashlib.sha256(
        _canonical_json(metadata)
    ).hexdigest()
    return f"file-{_HOST_TAG[host]}-{metadata_digest}"


def _missing_source_identity(host: str, path: Path) -> str:
    normalized_path = (
        os.path.normcase(str(path))
        if host == HOST_WINDOWS_NATIVE
        else str(path)
    )
    path_digest = hashlib.sha256(
        normalized_path.encode("utf-8")
    ).hexdigest()
    return f"file-{_HOST_TAG[host]}-missing-{path_digest}"


def _acquire_macos_keychain_materialization(
    *,
    runner: _KeychainRunner = _run_bounded_security_command,
    account: str | None = None,
    tool_identity_observer: _ToolIdentityObserver | None = None,
) -> StoredSubscriptionMaterializationCapability:
    observer = (
        tool_identity_observer
        if tool_identity_observer is not None
        else _macos_security_tool_identity
    )
    binding = _macos_keychain_binding(
        account=account,
        tool_identity=observer(),
    )
    result = _invoke_macos_keychain(
        binding=binding,
        acquisition=True,
        runner=runner,
    )
    material: bytearray | None = None
    try:
        after_binding = _macos_keychain_binding(
            account=account,
            tool_identity=observer(),
        )
        if after_binding != binding:
            raise ClaudeStoredSubscriptionSourceError(
                "macOS Keychain command authority changed",
                reason_code="KEYCHAIN_TOOL_CHANGED",
            )
        if result.overflowed:
            raise ClaudeStoredSubscriptionSourceError(
                "macOS Keychain credential exceeded its output ceiling",
                reason_code="KEYCHAIN_OUTPUT_LIMIT",
            )
        if result.timed_out or result.returncode in {36, 128}:
            raise ClaudeStoredSubscriptionSourceError(
                "macOS Keychain credential requires user interaction",
                reason_code="KEYCHAIN_INTERACTION_REQUIRED",
            )
        if result.returncode == 44:
            raise ClaudeStoredSubscriptionSourceError(
                "macOS Keychain credential is unavailable",
                reason_code="KEYCHAIN_CREDENTIAL_UNAVAILABLE",
            )
        if result.returncode != 0:
            raise ClaudeStoredSubscriptionSourceError(
                "macOS Keychain credential acquisition failed",
                reason_code="KEYCHAIN_ACQUISITION_FAILED",
            )
        material = result.take_stdout()
        if material.endswith(b"\n"):
            del material[-1:]
        if not material or len(material) > MAX_CREDENTIAL_FILE_BYTES:
            raise ClaudeStoredSubscriptionSourceError(
                "macOS Keychain credential has an invalid size",
                reason_code="KEYCHAIN_CREDENTIAL_SIZE_INVALID",
            )
        _validate_file_store_shape(material)
        evidence = _emit_evidence(
            store_class="OS_KEYCHAIN",
            source_identity=_macos_keychain_source_identity(
                binding,
                status="AVAILABLE",
            ),
            source_size=len(material),
            available=True,
        )
        issuance_id = secrets.token_hex(32)
        pending = {
            "material": material,
            "source_descriptor": -1,
            "source_path": None,
            "source_signature": None,
            "source_kind": "OS_KEYCHAIN",
            "keychain_binding": binding,
            "host": HOST_MACOS,
            "source_evidence": evidence,
        }
        with _CAPABILITY_STATE_LOCK:
            _MATERIALIZATION_PENDING[issuance_id] = pending
        try:
            capability = StoredSubscriptionMaterializationCapability(
                material=material,
                source_descriptor=-1,
                source_path=None,
                source_info=None,
                source_kind="OS_KEYCHAIN",
                keychain_binding=binding,
                host=HOST_MACOS,
                source_evidence=evidence,
                _issuance_id=issuance_id,
            )
        finally:
            with _CAPABILITY_STATE_LOCK:
                _MATERIALIZATION_PENDING.pop(issuance_id, None)
        material = None
        return capability
    finally:
        result.discard()
        if material is not None:
            for index in range(len(material)):
                material[index] = 0


def acquire_stored_subscription_materialization(
    *,
    source_path: str | os.PathLike[str] | None,
) -> StoredSubscriptionMaterializationCapability:
    """Acquire exact source bytes into one opaque, one-shot capability."""

    host = _detect_host_platform()
    if host == HOST_MACOS:
        if source_path is None:
            raise ClaudeStoredSubscriptionSourceError(
                "macOS Keychain acquisition requires the stored-route marker",
                reason_code="KEYCHAIN_SOURCE_MARKER_REQUIRED",
            )
        _validate_macos_source_marker(source_path)
        return _acquire_macos_keychain_materialization(
            runner=_run_bounded_security_command,
        )
    if host == HOST_UNSUPPORTED or host not in _HOST_TAG:
        raise ClaudeStoredSubscriptionSourceError(
            "stored subscription materialization is unsupported host"
        )
    if source_path is None:
        raise ClaudeStoredSubscriptionSourceError(
            "file-backed source path is required"
        )
    text = _path_text(source_path)
    if Path(text).name != ".credentials.json":
        raise ClaudeStoredSubscriptionSourceError(
            "file-backed source must name .credentials.json"
        )
    if host == HOST_WSL_NATIVE:
        _require_wsl_native_root(text)
    canonical, missing = _canonical_candidate_path(
        text,
        label="stored subscription credential source",
    )
    if missing:
        raise ClaudeStoredSubscriptionSourceError(
            "stored subscription credential source is unavailable"
        )
    try:
        pre_info = os.lstat(canonical)
    except OSError:
        raise ClaudeStoredSubscriptionSourceError(
            "stored subscription credential source is unavailable"
        ) from None
    if host == HOST_WINDOWS_NATIVE:
        _verify_windows_source_security(canonical)
    else:
        _validate_posix_source_security(canonical, pre_info)

    material: bytearray | None = None
    descriptor = -1
    try:
        canonical, info, material, descriptor = (
            _acquire_stable_credential_descriptor(
                canonical,
                label="stored subscription credential source",
            )
        )
        if host == HOST_WINDOWS_NATIVE:
            _verify_windows_source_security(canonical)
        else:
            _validate_posix_source_security(canonical, info)
        try:
            current_path = os.lstat(canonical)
            current_descriptor = os.fstat(descriptor)
        except OSError:
            raise ClaudeStoredSubscriptionSourceError(
                "stored subscription credential source changed"
            ) from None
        if (
            _path_stat_signature(current_path)
            != _path_stat_signature(info)
            or _descriptor_stat_signature(current_descriptor)
            != _descriptor_stat_signature(info)
        ):
            raise ClaudeStoredSubscriptionSourceError(
                "stored subscription credential source changed"
            )
        _validate_file_store_shape(material)
        evidence = _emit_evidence(
            store_class="FILE_BACKED",
            source_identity=_metadata_source_identity(
                host=host,
                path=canonical,
                info=info,
            ),
            source_size=len(material),
            available=True,
        )
        issuance_id = secrets.token_hex(32)
        pending = {
            "material": material,
            "source_descriptor": descriptor,
            "source_path": canonical,
            "source_signature": _path_stat_signature(info),
            "source_kind": "FILE_BACKED",
            "keychain_binding": None,
            "host": host,
            "source_evidence": evidence,
        }
        with _CAPABILITY_STATE_LOCK:
            _MATERIALIZATION_PENDING[issuance_id] = pending
        try:
            capability = StoredSubscriptionMaterializationCapability(
                material=material,
                source_descriptor=descriptor,
                source_path=canonical,
                source_info=info,
                source_kind="FILE_BACKED",
                keychain_binding=None,
                host=host,
                source_evidence=evidence,
                _issuance_id=issuance_id,
            )
        finally:
            with _CAPABILITY_STATE_LOCK:
                _MATERIALIZATION_PENDING.pop(issuance_id, None)
        material = None
        descriptor = -1
        return capability
    except BaseException:
        if material is not None:
            for index in range(len(material)):
                material[index] = 0
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass
        raise


def observe_stored_subscription_source(
    *,
    source_path: str | os.PathLike[str] | None,
) -> dict[str, Any]:
    """Observe one reviewed host store and emit exact redacted evidence.

    Windows native and Linux/WSL use private files.  macOS queries only the
    exact Claude generic-password service and current kernel UID account.
    """

    host = _detect_host_platform()
    if host == HOST_MACOS:
        # ``None`` is the existing explicit OAuth-token lane's request for
        # stored-source absence evidence.  Never let that request touch the
        # Keychain or change authentication precedence.
        if source_path is None:
            return _emit_evidence(
                store_class="OS_KEYCHAIN",
                source_identity="keychain-macos-route-not-selected",
                source_size=0,
                available=False,
            )
        _validate_macos_source_marker(source_path)
        return _observe_macos_keychain(
            runner=_run_bounded_security_command,
        )
    if host == HOST_UNSUPPORTED:
        raise ClaudeStoredSubscriptionSourceError(
            "stored subscription observation is unsupported host"
        )
    if host not in _HOST_TAG:
        raise ClaudeStoredSubscriptionSourceError(
            "stored subscription host classification is invalid"
        )
    if source_path is None:
        return _emit_evidence(
            store_class="FILE_BACKED",
            source_identity=f"file-{_HOST_TAG[host]}-path-unconfigured",
            source_size=0,
            available=False,
        )

    text = _path_text(source_path)
    if Path(text).name != ".credentials.json":
        raise ClaudeStoredSubscriptionSourceError(
            "file-backed source must name .credentials.json"
        )
    if host == HOST_WSL_NATIVE:
        _require_wsl_native_root(text)
    canonical, missing = _canonical_candidate_path(
        text,
        label="stored subscription credential source",
    )
    if missing:
        return _emit_evidence(
            store_class="FILE_BACKED",
            source_identity=_missing_source_identity(host, canonical),
            source_size=0,
            available=False,
        )

    # Establish Windows confidentiality and replacement authority before
    # credential bytes are inspected at all.  Replay it after the read as
    # well, then re-read the same file to bracket both content and DACL state.
    if host == HOST_WINDOWS_NATIVE:
        _verify_windows_source_security(canonical)
    canonical, info, raw = _stable_regular_file_bytes(
        canonical,
        ceiling=MAX_CREDENTIAL_FILE_BYTES,
        label="stored subscription credential source",
    )
    if host == HOST_WINDOWS_NATIVE:
        _verify_windows_source_security(canonical)
        after_path, after_info, after_raw = _stable_regular_file_bytes(
            canonical,
            ceiling=MAX_CREDENTIAL_FILE_BYTES,
            label="stored subscription credential source",
        )
        if (
            after_path != canonical
            or after_raw != raw
            or _metadata_source_identity(
                host=host,
                path=after_path,
                info=after_info,
            )
            != _metadata_source_identity(
                host=host,
                path=canonical,
                info=info,
            )
        ):
            raise ClaudeStoredSubscriptionSourceError(
                "stored subscription credential source drifted "
                "around Windows DACL observation"
            )
        info = after_info
        raw = after_raw
    elif host in {HOST_LINUX_NATIVE, HOST_WSL_NATIVE}:
        _validate_posix_source_security(canonical, info)
    _validate_file_store_shape(raw)
    source_identity = _metadata_source_identity(
        host=host,
        path=canonical,
        info=info,
    )
    # Do not compute or retain a credential-content digest.  ``raw`` falls out
    # of scope after structural validation.
    return _emit_evidence(
        store_class="FILE_BACKED",
        source_identity=source_identity,
        source_size=len(raw),
        available=True,
    )


def observe_stored_subscription_source_authority(
    *,
    source_path: str | os.PathLike[str] | None,
) -> Mapping[str, Any]:
    """Observe a store and retain live provenance for immediate auth use.

    The durable observation returned by
    :func:`observe_stored_subscription_source` is intentionally replayable
    but cannot prove that the current process performed the observation.
    Provider preparation needs that stronger, authentic channel when it
    classifies an *available* stored-subscription route.  Mint the one-shot
    promotion only on this direct observer path; unavailable evidence remains
    an ordinary replayable receipt because it cannot authorize credential
    use.
    """

    evidence = observe_stored_subscription_source(source_path=source_path)
    if not evidence["available"]:
        return evidence
    return _auth._promote_stored_subscription_source_evidence(
        evidence,
        provider_authority_sha256=(
            evidence["observation_authority_sha256"]
        ),
    )


def replay_stored_subscription_source_observation(
    value: Mapping[str, Any],
) -> dict[str, Any]:
    """Replay schema and require the exact current observer implementation."""

    try:
        replayed = _auth.replay_stored_subscription_source_evidence(value)
    except _auth.ClaudeAuthRouteError as exc:
        raise ClaudeStoredSubscriptionSourceError(
            "stored-subscription source evidence does not replay"
        ) from exc
    if (
        replayed["observation_authority_sha256"]
        != _implementation_authority_sha256()
    ):
        raise ClaudeStoredSubscriptionSourceError(
            "stored-subscription implementation authority drifted"
        )
    return replayed


def reconcile_stored_subscription_source_observation(
    value: Mapping[str, Any],
    *,
    source_path: str | os.PathLike[str] | None,
) -> dict[str, Any]:
    """Reobserve the exact host source and reject metadata/availability drift."""

    replayed = replay_stored_subscription_source_observation(value)
    fresh = observe_stored_subscription_source(source_path=source_path)
    if fresh != replayed:
        raise ClaudeStoredSubscriptionSourceError(
            "stored-subscription source observation drifted"
        )
    return replayed


__all__ = [
    "HOST_LINUX_NATIVE",
    "HOST_MACOS",
    "HOST_UNSUPPORTED",
    "HOST_WINDOWS_NATIVE",
    "HOST_WSL_NATIVE",
    "PRIVATE_CREDENTIAL_TARGET_AUTHORITY_SCHEMA",
    "STORED_SUBSCRIPTION_MATERIALIZATION_SCHEMA",
    "ClaudeStoredSubscriptionSourceError",
    "PrivateCredentialTargetCapability",
    "StoredSubscriptionMaterializationCapability",
    "acquire_stored_subscription_materialization",
    "authorize_private_credential_target",
    "observe_stored_subscription_source",
    "observe_stored_subscription_source_authority",
    "reconcile_stored_subscription_source_observation",
    "replay_stored_subscription_materialization_receipt",
    "replay_stored_subscription_source_observation",
    "wsl_path_has_native_linux_semantics",
]
