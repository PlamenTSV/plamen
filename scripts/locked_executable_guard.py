"""Process-lifetime guards for reviewed provider executables.

Claude Code's Windows updater can rename a shared ``claude.exe`` before it
has durably installed the replacement. A concurrent worker wave then leaves
the reviewed runtime without its executable. Environment switches are useful
policy inputs, but they are not an operating-system security boundary.

On Windows this module retains a native read handle with only
``FILE_SHARE_READ``. The kernel therefore denies writes, deletes, renames, and
replacements through every hardlink name until the driver exits. Other
platforms retain a non-inheritable identity handle; the audit snapshot remains
the fail-closed mutation boundary there.
"""

from __future__ import annotations

import atexit
import hashlib
import os
from pathlib import Path
import sys
import threading
from typing import Any


class LockedExecutableGuardError(RuntimeError):
    """The reviewed provider executable could not be guarded exactly."""


_LOCK = threading.RLock()
_RETAINED: dict[tuple[int, int], int] = {}
_BINDING_KEYS = {
    "schema",
    "enforcement",
    "identity",
    "size",
    "mtime_ns",
    "ctime_ns",
    "sha256",
    "inheritable",
    "host_path_recorded",
}


def _identity(row: os.stat_result) -> tuple[int, int]:
    return int(row.st_dev), int(row.st_ino)


def _open_windows_denial_handle(path: Path) -> int:
    import ctypes
    import msvcrt
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create_file = kernel32.CreateFileW
    create_file.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    create_file.restype = wintypes.HANDLE
    handle = create_file(
        str(path),
        0x80000000,  # GENERIC_READ
        0x00000001,  # FILE_SHARE_READ: deny write and delete/rename
        None,
        3,  # OPEN_EXISTING
        0x00000080,  # FILE_ATTRIBUTE_NORMAL
        None,
    )
    invalid = ctypes.c_void_p(-1).value
    if handle == invalid:
        raise OSError(
            ctypes.get_last_error(),
            "locked executable write/delete denial is unavailable",
        )
    try:
        descriptor = msvcrt.open_osfhandle(
            int(handle), os.O_RDONLY | getattr(os, "O_BINARY", 0)
        )
    except BaseException:
        kernel32.CloseHandle(handle)
        raise
    os.set_inheritable(descriptor, False)
    return descriptor


def _open_identity_handle(path: Path) -> int:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    os.set_inheritable(descriptor, False)
    return descriptor


def _descriptor_sha256(descriptor: int) -> str:
    digest = hashlib.sha256()
    offset = os.lseek(descriptor, 0, os.SEEK_CUR)
    try:
        os.lseek(descriptor, 0, os.SEEK_SET)
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    finally:
        os.lseek(descriptor, offset, os.SEEK_SET)
    return digest.hexdigest()


def _stable_binding(receipt: dict[str, Any]) -> dict[str, Any]:
    return {key: receipt[key] for key in _BINDING_KEYS}


def _stat_matches_binding(row: Any, binding: dict[str, Any]) -> bool:
    return (
        list(_identity(row)) == binding.get("identity")
        and int(row.st_size) == binding.get("size")
        and int(row.st_mtime_ns) == binding.get("mtime_ns")
        and int(row.st_ctime_ns) == binding.get("ctime_ns")
    )


def _pread_sha256(os_api: Any, descriptor: int, size: int) -> str:
    digest = hashlib.sha256()
    offset = 0
    while offset < size:
        chunk = os_api.pread(descriptor, min(1024 * 1024, size - offset), offset)
        if not chunk:
            raise LockedExecutableGuardError(
                "locked executable snapshot was truncated"
            )
        digest.update(chunk)
        offset += len(chunk)
    return digest.hexdigest()


def _create_linux_sealed_snapshot(
    descriptor: int,
    binding: dict[str, Any],
    *,
    os_api: Any = os,
    fcntl_api: Any = None,
    proc_fd_exists: Any = None,
) -> tuple[str, int]:
    """Copy one stable retained executable into an immutable Linux memfd."""

    if fcntl_api is None:
        try:
            import fcntl as fcntl_api
        except ImportError as exc:
            raise LockedExecutableGuardError(
                "Linux executable sealing is unavailable"
            ) from exc
    required_os = (
        "memfd_create",
        "MFD_ALLOW_SEALING",
        "MFD_CLOEXEC",
        "pread",
        "fchmod",
    )
    required_fcntl = (
        "F_ADD_SEALS",
        "F_GET_SEALS",
        "F_SEAL_WRITE",
        "F_SEAL_GROW",
        "F_SEAL_SHRINK",
        "F_SEAL_SEAL",
    )
    if any(not hasattr(os_api, name) for name in required_os) or any(
        not hasattr(fcntl_api, name) for name in required_fcntl
    ):
        raise LockedExecutableGuardError(
            "Linux executable sealing is unavailable"
        )

    source_before = os_api.fstat(descriptor)
    if not _stat_matches_binding(source_before, binding):
        raise LockedExecutableGuardError(
            "locked executable changed before sealed acquisition"
        )
    mode = int(source_before.st_mode) & 0o777
    if mode & 0o111 == 0:
        raise LockedExecutableGuardError(
            "locked executable has no execute permission"
        )
    snapshot = os_api.memfd_create(
        "plamen-owned-executable",
        int(os_api.MFD_ALLOW_SEALING) | int(os_api.MFD_CLOEXEC),
    )
    try:
        os_api.set_inheritable(snapshot, False)
        digest = hashlib.sha256()
        offset = 0
        size = int(binding["size"])
        while offset < size:
            chunk = os_api.pread(
                descriptor,
                min(1024 * 1024, size - offset),
                offset,
            )
            if not chunk:
                raise LockedExecutableGuardError(
                    "locked executable changed during sealed acquisition"
                )
            digest.update(chunk)
            cursor = 0
            while cursor < len(chunk):
                written = os_api.write(snapshot, chunk[cursor:])
                if not isinstance(written, int) or written <= 0:
                    raise LockedExecutableGuardError(
                        "locked executable sealed snapshot write failed"
                    )
                cursor += written
            offset += len(chunk)

        source_after = os_api.fstat(descriptor)
        if (
            not _stat_matches_binding(source_after, binding)
            or digest.hexdigest() != binding["sha256"]
        ):
            raise LockedExecutableGuardError(
                "locked executable changed during sealed acquisition"
            )
        os_api.fchmod(snapshot, mode)
        required_seals = (
            int(fcntl_api.F_SEAL_WRITE)
            | int(fcntl_api.F_SEAL_GROW)
            | int(fcntl_api.F_SEAL_SHRINK)
            | int(fcntl_api.F_SEAL_SEAL)
        )
        fcntl_api.fcntl(snapshot, fcntl_api.F_ADD_SEALS, required_seals)
        observed_seals = int(
            fcntl_api.fcntl(snapshot, fcntl_api.F_GET_SEALS)
        )
        snapshot_stat = os_api.fstat(snapshot)
        if (
            observed_seals != required_seals
            or int(snapshot_stat.st_size) != size
            or _pread_sha256(os_api, snapshot, size) != binding["sha256"]
        ):
            raise LockedExecutableGuardError(
                "locked executable sealed snapshot verification failed"
            )
        launch_path = f"/proc/self/fd/{snapshot}"
        exists = (
            Path(launch_path).exists()
            if proc_fd_exists is None
            else bool(proc_fd_exists(launch_path))
        )
        if not exists:
            raise LockedExecutableGuardError(
                "locked executable sealed launch path is unavailable"
            )
        return launch_path, snapshot
    except BaseException:
        os_api.close(snapshot)
        raise


def retain_locked_executable(path: str | Path) -> dict[str, Any]:
    """Retain one process-lifetime guard for an exact regular executable.

    The returned receipt intentionally contains no host path. Repeated calls
    for hardlink aliases join the same retained kernel identity.
    """

    candidate = Path(path)
    try:
        if candidate.is_symlink():
            raise LockedExecutableGuardError(
                "locked provider executable must not be a symlink"
            )
        before = candidate.stat(follow_symlinks=False)
    except OSError as exc:
        raise LockedExecutableGuardError(
            "locked provider executable is unavailable"
        ) from exc
    if not candidate.is_file():
        raise LockedExecutableGuardError(
            "locked provider executable is not a regular file"
        )
    expected = _identity(before)

    with _LOCK:
        retained = _RETAINED.get(expected)
        acquired = False
        if retained is None:
            try:
                retained = (
                    _open_windows_denial_handle(candidate)
                    if os.name == "nt"
                    else _open_identity_handle(candidate)
                )
            except OSError as exc:
                raise LockedExecutableGuardError(
                    "locked provider executable cannot be protected"
                ) from exc
            acquired = True
            held = os.fstat(retained)
            after = candidate.stat(follow_symlinks=False)
            if _identity(held) != expected or _identity(after) != expected:
                os.close(retained)
                raise LockedExecutableGuardError(
                    "locked provider executable changed during guard acquisition"
                )
        else:
            held = os.fstat(retained)
            after = candidate.stat(follow_symlinks=False)
            if _identity(held) != expected or _identity(after) != expected:
                raise LockedExecutableGuardError(
                    "retained provider executable identity drifted"
                )

        try:
            content_before = os.fstat(retained)
            content_sha256 = _descriptor_sha256(retained)
            content_after = os.fstat(retained)
            stable_metadata = (
                int(content_before.st_size),
                int(content_before.st_mtime_ns),
                int(content_before.st_ctime_ns),
            ) == (
                int(content_after.st_size),
                int(content_after.st_mtime_ns),
                int(content_after.st_ctime_ns),
            )
            if (
                _identity(content_before) != expected
                or _identity(content_after) != expected
                or not stable_metadata
            ):
                raise LockedExecutableGuardError(
                    "locked provider executable changed during content binding"
                )
            if acquired:
                _RETAINED[expected] = retained
        except BaseException:
            if acquired:
                os.close(retained)
            raise

    return {
        "schema": "plamen.locked_executable_guard.v2",
        "enforcement": (
            "WINDOWS_SHARE_DENY_WRITE_DELETE"
            if os.name == "nt"
            else (
                "LINUX_RETAINED_IDENTITY_SEALED_MEMFD_AT_LAUNCH"
                if sys.platform.startswith("linux")
                else "POSIX_RETAINED_IDENTITY_FAIL_CLOSED_SNAPSHOT"
            )
        ),
        "identity": [expected[0], expected[1]],
        "size": int(content_after.st_size),
        "mtime_ns": int(content_after.st_mtime_ns),
        "ctime_ns": int(content_after.st_ctime_ns),
        "sha256": content_sha256,
        "acquired": acquired,
        "inheritable": False,
        "host_path_recorded": False,
    }


def bind_locked_executable(path: str | Path) -> dict[str, Any]:
    """Return the stable identity/content binding while retaining its guard."""

    return _stable_binding(retain_locked_executable(path))


def validate_locked_executable_binding(
    path: str | Path,
    binding: Any,
) -> dict[str, Any]:
    """Retain and validate an exact executable against a prior binding."""

    if not isinstance(binding, dict) or set(binding) != _BINDING_KEYS:
        raise LockedExecutableGuardError(
            "locked executable binding schema is invalid"
        )
    observed = bind_locked_executable(path)
    if observed != binding:
        raise LockedExecutableGuardError(
            "locked executable identity or content binding drifted"
        )
    return observed


def acquire_locked_executable_launch(
    path: str | Path,
    binding: Any,
) -> tuple[str, int | None]:
    """Return a launch name and optional inherited duplicate identity handle.

    Windows relies on the retained share-deny-write/delete handle. Linux uses
    an exact-byte sealed memfd through ``/proc/self/fd`` so the kernel executes
    immutable bytes even if the source inode or directory entry is mutated.
    Other POSIX platforms retain the identity handle and require pre/post path
    validation, but do not claim same-name replacement prevention.
    """

    candidate = Path(path)
    observed = validate_locked_executable_binding(candidate, binding)
    identity = tuple(int(value) for value in observed["identity"])
    if os.name == "nt":
        return str(candidate), None
    with _LOCK:
        retained = _RETAINED.get(identity)
        if retained is None:
            raise LockedExecutableGuardError(
                "locked executable retained identity is unavailable"
            )
        if sys.platform.startswith("linux"):
            return _create_linux_sealed_snapshot(retained, observed)
    return str(candidate), None


def release_locked_executables() -> None:
    """Release all retained guards. Production uses this only at exit."""

    with _LOCK:
        descriptors = tuple(_RETAINED.values())
        _RETAINED.clear()
    for descriptor in descriptors:
        try:
            os.close(descriptor)
        except OSError:
            pass


atexit.register(release_locked_executables)


__all__ = [
    "LockedExecutableGuardError",
    "acquire_locked_executable_launch",
    "bind_locked_executable",
    "release_locked_executables",
    "retain_locked_executable",
    "validate_locked_executable_binding",
]
