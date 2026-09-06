"""Portable rooted filesystem operations for persisted pipeline authority.

Serialized artifacts retain ordinary absolute or relative path spellings.  This
module alone translates an already validated lexical path to Windows'
extended-length syscall spelling.  It also centralizes exact-case component
walking and no-follow file-handle identity checks so WER, WTx, and later
authority consumers do not each grow subtly different path semantics.
"""

from __future__ import annotations

import ctypes
import errno
import hashlib
import os
from pathlib import Path
import stat
import sys
from typing import Iterator
import uuid

if os.name == "nt":
    from ctypes import wintypes

    class _FILETIME(ctypes.Structure):
        _fields_ = (
            ("dwLowDateTime", wintypes.DWORD),
            ("dwHighDateTime", wintypes.DWORD),
        )

    class _WIN32_FIND_DATAW(ctypes.Structure):
        _fields_ = (
            ("dwFileAttributes", wintypes.DWORD),
            ("ftCreationTime", _FILETIME),
            ("ftLastAccessTime", _FILETIME),
            ("ftLastWriteTime", _FILETIME),
            ("nFileSizeHigh", wintypes.DWORD),
            ("nFileSizeLow", wintypes.DWORD),
            ("dwReserved0", wintypes.DWORD),
            ("dwReserved1", wintypes.DWORD),
            ("cFileName", wintypes.WCHAR * 260),
            ("cAlternateFileName", wintypes.WCHAR * 14),
        )

    _FindFirstFileW = ctypes.WinDLL(
        "kernel32",
        use_last_error=True,
    ).FindFirstFileW
    _FindFirstFileW.argtypes = (
        wintypes.LPCWSTR,
        ctypes.POINTER(_WIN32_FIND_DATAW),
    )
    _FindFirstFileW.restype = wintypes.HANDLE
    _FindClose = ctypes.WinDLL(
        "kernel32",
        use_last_error=True,
    ).FindClose
    _FindClose.argtypes = (wintypes.HANDLE,)
    _FindClose.restype = wintypes.BOOL
    _INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
    _MoveFileExW = ctypes.WinDLL(
        "kernel32",
        use_last_error=True,
    ).MoveFileExW
    _MoveFileExW.argtypes = (
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        wintypes.DWORD,
    )
    _MoveFileExW.restype = wintypes.BOOL
    _CreateHardLinkW = ctypes.WinDLL(
        "kernel32",
        use_last_error=True,
    ).CreateHardLinkW
    _CreateHardLinkW.argtypes = (
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        ctypes.c_void_p,
    )
    _CreateHardLinkW.restype = wintypes.BOOL
    _CreateFileW = ctypes.WinDLL(
        "kernel32",
        use_last_error=True,
    ).CreateFileW
    _CreateFileW.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    )
    _CreateFileW.restype = wintypes.HANDLE
    _CloseHandle = ctypes.WinDLL(
        "kernel32",
        use_last_error=True,
    ).CloseHandle
    _CloseHandle.argtypes = (wintypes.HANDLE,)
    _CloseHandle.restype = wintypes.BOOL
    _FlushFileBuffers = ctypes.WinDLL(
        "kernel32",
        use_last_error=True,
    ).FlushFileBuffers
    _FlushFileBuffers.argtypes = (wintypes.HANDLE,)
    _FlushFileBuffers.restype = wintypes.BOOL
    _SetFilePointerEx = ctypes.WinDLL(
        "kernel32",
        use_last_error=True,
    ).SetFilePointerEx
    _SetFilePointerEx.argtypes = (
        wintypes.HANDLE,
        ctypes.c_longlong,
        ctypes.POINTER(ctypes.c_longlong),
        wintypes.DWORD,
    )
    _SetFilePointerEx.restype = wintypes.BOOL
    _ReadFile = ctypes.WinDLL(
        "kernel32",
        use_last_error=True,
    ).ReadFile
    _ReadFile.argtypes = (
        wintypes.HANDLE,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        ctypes.c_void_p,
    )
    _ReadFile.restype = wintypes.BOOL
    _WriteFile = ctypes.WinDLL(
        "kernel32",
        use_last_error=True,
    ).WriteFile
    _WriteFile.argtypes = (
        wintypes.HANDLE,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        ctypes.c_void_p,
    )
    _WriteFile.restype = wintypes.BOOL

    class _BY_HANDLE_FILE_INFORMATION(ctypes.Structure):
        _fields_ = (
            ("dwFileAttributes", wintypes.DWORD),
            ("ftCreationTime", _FILETIME),
            ("ftLastAccessTime", _FILETIME),
            ("ftLastWriteTime", _FILETIME),
            ("dwVolumeSerialNumber", wintypes.DWORD),
            ("nFileSizeHigh", wintypes.DWORD),
            ("nFileSizeLow", wintypes.DWORD),
            ("nNumberOfLinks", wintypes.DWORD),
            ("nFileIndexHigh", wintypes.DWORD),
            ("nFileIndexLow", wintypes.DWORD),
        )

    _GetFileInformationByHandle = ctypes.WinDLL(
        "kernel32",
        use_last_error=True,
    ).GetFileInformationByHandle
    _GetFileInformationByHandle.argtypes = (
        wintypes.HANDLE,
        ctypes.POINTER(_BY_HANDLE_FILE_INFORMATION),
    )
    _GetFileInformationByHandle.restype = wintypes.BOOL
    _SetFileInformationByHandle = ctypes.WinDLL(
        "kernel32",
        use_last_error=True,
    ).SetFileInformationByHandle
    _SetFileInformationByHandle.argtypes = (
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
    )
    _SetFileInformationByHandle.restype = wintypes.BOOL

    class _FILE_RENAME_INFO(ctypes.Structure):
        _fields_ = (
            ("ReplaceIfExists", wintypes.BOOLEAN),
            ("RootDirectory", wintypes.HANDLE),
            ("FileNameLength", wintypes.DWORD),
            ("FileName", wintypes.WCHAR * 1),
        )

    class _FILE_DISPOSITION_INFO(ctypes.Structure):
        _fields_ = (("DeleteFile", wintypes.BOOLEAN),)


_FILE_ATTRIBUTE_REPARSE_POINT = 0x400
_WINDOWS_EXTENDED_PREFIX = "\\\\?\\"
_WINDOWS_EXTENDED_UNC_PREFIX = "\\\\?\\UNC\\"
_MOVEFILE_REPLACE_EXISTING = 0x1
_MOVEFILE_WRITE_THROUGH = 0x8
_ERROR_FILE_EXISTS = 80
_ERROR_ALREADY_EXISTS = 183
_GENERIC_READ = 0x80000000
_GENERIC_WRITE = 0x40000000
_DELETE_ACCESS = 0x00010000
_FILE_SHARE_READ = 0x1
_FILE_SHARE_WRITE = 0x2
_FILE_SHARE_DELETE = 0x4
_CREATE_NEW = 1
_OPEN_EXISTING = 3
_FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
_FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
_FILE_FLAG_WRITE_THROUGH = 0x80000000
_FILE_BEGIN = 0
_FILE_ATTRIBUTE_DIRECTORY = 0x10
_FILE_RENAME_INFO_CLASS = 3
_FILE_DISPOSITION_INFO_CLASS = 4


class RootedPathIOError(RuntimeError):
    """A lexical or filesystem object violated rooted authority."""


class DurableWriteOnceDebtError(RootedPathIOError):
    """Structured, blocking debt from a write-once durability boundary."""

    def __init__(
        self,
        *,
        stage: Path,
        destination: Path,
        expected: bytes,
        observed: bytes | None,
        cleanup_state: str,
        detail: str,
    ) -> None:
        self.stage = stage
        self.destination = destination
        self.expected_sha256 = hashlib.sha256(expected).hexdigest()
        self.observed_sha256 = (
            hashlib.sha256(observed).hexdigest()
            if observed is not None
            else None
        )
        self.expected_size = len(expected)
        self.observed_size = len(observed) if observed is not None else None
        self.cleanup_state = cleanup_state
        self.durability_debt = {
            "stage": os.fspath(stage),
            "destination": os.fspath(destination),
            "expected_sha256": self.expected_sha256,
            "observed_sha256": self.observed_sha256,
            "expected_size": self.expected_size,
            "observed_size": self.observed_size,
            "cleanup_state": cleanup_state,
        }
        super().__init__(
            f"{detail}: stage={stage}; destination={destination}; "
            f"expected_sha256={self.expected_sha256}; "
            f"observed_sha256={self.observed_sha256}; "
            f"expected_size={self.expected_size}; "
            f"observed_size={self.observed_size}; "
            f"cleanup_state={cleanup_state}"
        )


class DurableWriteOnceStageError(DurableWriteOnceDebtError):
    """A deterministic publication stage does not match its bound postimage."""

    def __init__(
        self,
        *,
        stage: Path,
        destination: Path | None = None,
        expected: bytes,
        observed: bytes,
    ) -> None:
        super().__init__(
            stage=stage,
            destination=destination or stage,
            expected=expected,
            observed=observed,
            cleanup_state="STAGE_MISMATCH_PRESERVED",
            detail="durable write-once staging bytes mismatch",
        )


def _raw_path(path: str | os.PathLike[str]) -> str:
    raw = os.fspath(path)
    if not isinstance(raw, str) or not raw or "\x00" in raw:
        raise RootedPathIOError("rooted I/O path is malformed")
    if os.name == "nt" and raw.startswith(_WINDOWS_EXTENDED_PREFIX):
        raise RootedPathIOError(
            "caller-supplied Windows extended path is not accepted"
        )
    return raw


def absolute_path(path: str | os.PathLike[str]) -> Path:
    """Return a normalized lexical absolute path without resolving links."""

    return Path(os.path.abspath(_raw_path(path)))


def native_path(path: str | os.PathLike[str]) -> str:
    """Return the internal syscall spelling for one lexical absolute path."""

    absolute = os.fspath(absolute_path(path))
    if os.name != "nt":
        return absolute
    if absolute.startswith("\\\\"):
        return _WINDOWS_EXTENDED_UNC_PREFIX + absolute[2:]
    drive, tail = os.path.splitdrive(absolute)
    if not drive or not tail.startswith(("\\", "/")):
        raise RootedPathIOError(
            "Windows rooted I/O path is not absolute"
        )
    return _WINDOWS_EXTENDED_PREFIX + absolute


def _same_parent(
    source: str | os.PathLike[str],
    destination: str | os.PathLike[str],
) -> tuple[Path, Path]:
    source_path = absolute_path(source)
    destination_path = absolute_path(destination)
    if os.path.normcase(os.fspath(source_path.parent)) != os.path.normcase(
        os.fspath(destination_path.parent)
    ):
        raise RootedPathIOError(
            "durable publication requires a same-directory temporary"
        )
    return source_path, destination_path


def _fsync_directory(path: str | os.PathLike[str]) -> None:
    if os.name == "nt":
        _windows_directory_write_through_barrier(absolute_path(path))
        return
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    descriptor = os.open(native_path(path), flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _windows_move(
    source: Path,
    destination: Path,
    *,
    replace_existing: bool,
) -> None:
    flags = _MOVEFILE_WRITE_THROUGH
    if replace_existing:
        flags |= _MOVEFILE_REPLACE_EXISTING
    if _MoveFileExW(
        native_path(source),
        native_path(destination),
        flags,
    ):
        return
    error = ctypes.get_last_error()
    if not replace_existing and error in {
        _ERROR_FILE_EXISTS,
        _ERROR_ALREADY_EXISTS,
    }:
        raise FileExistsError(
            error,
            "durable write-once publication already exists",
            os.fspath(destination),
        )
    raise OSError(
        error,
        "durable Windows publication failed",
        os.fspath(destination),
    )


def _windows_directory_write_through_barrier(directory: Path) -> None:
    """Flush a Windows directory handle or use a same-directory WT rename.

    Some filesystems reject ``FlushFileBuffers`` for directory handles.  The
    fallback performs a write-through namespace transition in the exact
    directory after flushing the marker's data.  It is an ordering barrier,
    not an emulation of POSIX directory-fsync semantics.
    """

    handle = _CreateFileW(
        native_path(directory),
        _GENERIC_READ,
        _FILE_SHARE_READ | _FILE_SHARE_WRITE | _FILE_SHARE_DELETE,
        None,
        _OPEN_EXISTING,
        _FILE_FLAG_BACKUP_SEMANTICS | _FILE_FLAG_WRITE_THROUGH,
        None,
    )
    if handle != _INVALID_HANDLE_VALUE:
        try:
            if _FlushFileBuffers(handle):
                return
        finally:
            _CloseHandle(handle)

    token = uuid.uuid4().hex
    source = directory / f".plamen-dir-sync-{token}.stage"
    destination = directory / f".plamen-dir-sync-{token}.done"
    marker = b"\x00"
    handle = _CreateFileW(
        native_path(source),
        _GENERIC_READ | _GENERIC_WRITE | _DELETE_ACCESS,
        # This handle is the marker's lifetime boundary.  Permit readers only;
        # a writer or delete/rename capability must not coexist with the
        # validation, namespace transition, or disposition operation.
        _FILE_SHARE_READ,
        None,
        _CREATE_NEW,
        _FILE_FLAG_OPEN_REPARSE_POINT | _FILE_FLAG_WRITE_THROUGH,
        None,
    )
    if handle == _INVALID_HANDLE_VALUE:
        error = ctypes.get_last_error()
        raise DurableWriteOnceDebtError(
            stage=source,
            destination=destination,
            expected=marker,
            observed=_best_effort_observed_bytes(source),
            cleanup_state="DIRECTORY_BARRIER_MARKER_CREATE_FAILED_PRESERVED",
            detail=(
                "Windows directory barrier marker could not be created "
                f"exclusively (WinError {error})"
            ),
        )

    renamed = False
    retirement_marked = False
    cleanup_state = "DIRECTORY_BARRIER_PREPARE_FAILED_MARKER_PRESERVED"
    failure: BaseException | None = None
    held_observed: bytes | None = None
    try:
        consumed = wintypes.DWORD()
        buffer = ctypes.create_string_buffer(marker)
        if not _WriteFile(
            handle,
            buffer,
            len(marker),
            ctypes.byref(consumed),
            None,
        ) or int(consumed.value) != len(marker):
            error = ctypes.get_last_error()
            raise OSError(error or errno.EIO, "directory marker write failed")
        if not _FlushFileBuffers(handle):
            error = ctypes.get_last_error()
            raise OSError(error, "directory marker data flush failed")
        _windows_validate_named_handle(
            handle,
            source,
            label="Windows directory barrier marker",
        )
        held_observed = _windows_handle_bytes(handle)
        if held_observed != marker:
            raise RootedPathIOError(
                "Windows directory barrier marker bytes are not exact"
            )

        cleanup_state = (
            "DIRECTORY_BARRIER_RENAME_FAILED_MARKER_PRESERVED"
        )
        _windows_rename_open_handle_new(handle, destination)
        renamed = True

        cleanup_state = (
            "DIRECTORY_BARRIER_PUBLICATION_UNPROVEN_NAMES_PRESERVED"
        )
        _windows_validate_named_handle(
            handle,
            destination,
            label="Windows directory barrier renamed marker",
        )
        information = _windows_handle_information(handle)
        held_observed = _windows_handle_bytes(handle)
        if (
            int(information.nNumberOfLinks) != 1
            or held_observed != marker
        ):
            raise RootedPathIOError(
                "Windows directory barrier renamed marker is not exact and "
                "single-link"
            )
        # Flush the same write-through handle after its no-replace namespace
        # transition.  This is the fallback ordering barrier on filesystems
        # that reject FlushFileBuffers for directory handles.
        if not _FlushFileBuffers(handle):
            error = ctypes.get_last_error()
            raise OSError(error, "directory marker publication flush failed")
        _windows_validate_named_handle(
            handle,
            destination,
            label="Windows directory barrier durable marker",
        )
        held_observed = _windows_handle_bytes(handle)
        if held_observed != marker:
            raise RootedPathIOError(
                "Windows directory barrier marker changed before retirement"
            )

        cleanup_state = (
            "DIRECTORY_BARRIER_RETIREMENT_FAILED_MARKER_PRESERVED"
        )
        _windows_mark_open_link_for_deletion(handle)
        retirement_marked = True
        information = _windows_handle_information(handle)
        # Classic FileDispositionInformation removes the exact opened link
        # from the namespace immediately.  Zero proves there was no second
        # hardlink at that retirement linearization point; a positive count
        # means an alias remains and retirement must be cancelled.
        if int(information.nNumberOfLinks) != 0:
            raise RootedPathIOError(
                "Windows directory barrier marker acquired a hardlink while "
                "retirement was armed"
            )
    except BaseException as exc:
        failure = exc
        if retirement_marked:
            try:
                _windows_cancel_open_link_deletion(handle)
                retirement_marked = False
            except BaseException as cancel_exc:
                failure = cancel_exc
                cleanup_state = (
                    "DIRECTORY_BARRIER_RETIREMENT_CANCELLATION_UNPROVEN"
                )
        try:
            held_observed = _windows_handle_bytes(handle)
        except BaseException:
            held_observed = None

    close_succeeded = bool(_CloseHandle(handle))
    if not close_succeeded and failure is None:
        error = ctypes.get_last_error()
        failure = OSError(error, "directory marker handle release failed")
        cleanup_state = "DIRECTORY_BARRIER_HANDLE_RELEASE_UNPROVEN"

    if failure is not None:
        raise DurableWriteOnceDebtError(
            stage=source,
            destination=destination,
            expected=marker,
            observed=held_observed,
            cleanup_state=cleanup_state,
            detail=(
                "Windows directory write-through marker transaction failed; "
                f"no pathname cleanup was attempted: {failure}"
            ),
        ) from failure
    if not renamed or not retirement_marked:
        raise DurableWriteOnceDebtError(
            stage=source,
            destination=destination,
            expected=marker,
            observed=held_observed,
            cleanup_state="DIRECTORY_BARRIER_RETIREMENT_UNPROVEN",
            detail=(
                "Windows directory write-through marker transaction did not "
                "prove rename and object-bound retirement"
            ),
        )

    # FileDispositionInformation retires only the exact link opened above.
    # A name that appears after handle release is foreign and must be retained.
    remaining = [path for path in (source, destination) if lexists(path)]
    if remaining:
        observed_path = remaining[0]
        raise DurableWriteOnceDebtError(
            stage=source,
            destination=destination,
            expected=marker,
            observed=_best_effort_observed_bytes(observed_path),
            cleanup_state="DIRECTORY_BARRIER_FOREIGN_NAME_PRESERVED",
            detail=(
                "Windows directory barrier marker retired, but a current "
                "marker name contains unowned bytes and was preserved"
            ),
        )


def _windows_publication_host() -> bool:
    """Return whether durable publication must use the Win32 move path.

    Kept as a seam so cross-platform tests can verify the no-replace dispatch
    contract without pretending to emulate Win32 filesystem semantics.
    """

    return os.name == "nt"


def _same_inode(left: os.stat_result, right: os.stat_result) -> bool:
    return (
        int(getattr(left, "st_dev", 0)),
        int(getattr(left, "st_ino", 0)),
    ) == (
        int(getattr(right, "st_dev", 0)),
        int(getattr(right, "st_ino", 0)),
    )


def _posix_exclusive_rename(source: Path, destination: Path) -> bool:
    """Use the host's atomic no-replace rename, or report unsupported."""

    source_raw = os.fsencode(native_path(source))
    destination_raw = os.fsencode(native_path(destination))
    unsupported = {
        errno.ENOSYS,
        errno.EINVAL,
        getattr(errno, "ENOTSUP", errno.EINVAL),
        getattr(errno, "EOPNOTSUPP", errno.EINVAL),
    }
    if sys.platform.startswith("linux"):
        library = ctypes.CDLL(None, use_errno=True)
        renameat2 = getattr(library, "renameat2", None)
        if renameat2 is None:
            return False
        renameat2.argtypes = (
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        )
        renameat2.restype = ctypes.c_int
        # AT_FDCWD, RENAME_NOREPLACE
        result = renameat2(
            -100,
            source_raw,
            -100,
            destination_raw,
            1,
        )
    elif sys.platform == "darwin":
        library = ctypes.CDLL(None, use_errno=True)
        renamex = getattr(library, "renamex_np", None)
        if renamex is None:
            return False
        renamex.argtypes = (
            ctypes.c_char_p,
            ctypes.c_char_p,
            ctypes.c_uint,
        )
        renamex.restype = ctypes.c_int
        # Darwin's RENAME_EXCL.
        result = renamex(source_raw, destination_raw, 0x4)
    else:
        return False
    if result == 0:
        return True
    error = ctypes.get_errno()
    if error == errno.EEXIST:
        raise FileExistsError(
            error,
            "durable write-once publication already exists",
            os.fspath(destination),
        )
    if error in unsupported:
        return False
    raise OSError(
        error,
        "atomic no-replace publication failed",
        os.fspath(destination),
    )


def _retire_publication_source(source: Path) -> None:
    os.unlink(native_path(source))


def _durable_publish_new_link_fallback(
    source: Path,
    destination: Path,
) -> None:
    """Recoverable no-clobber fallback for hosts without exclusive rename."""

    if lexists(destination):
        if not lexists(source):
            raise FileExistsError(
                errno.EEXIST,
                "durable write-once publication already exists",
                os.fspath(destination),
            )
        source_row = lstat(source)
        destination_row = lstat(destination)
        if (
            not _same_inode(source_row, destination_row)
            or int(getattr(destination_row, "st_nlink", 1) or 1) != 2
        ):
            raise FileExistsError(
                errno.EEXIST,
                "durable write-once publication already exists",
                os.fspath(destination),
            )
        _retire_publication_source(source)
        _fsync_directory(destination.parent)
        if (
            not lexists(destination)
            or int(getattr(lstat(destination), "st_nlink", 1) or 1) != 1
        ):
            raise RootedPathIOError(
                "recovered write-once publication is not single-link"
            )
        return
    os.link(native_path(source), native_path(destination))
    try:
        _retire_publication_source(source)
    except BaseException:
        # Persist the two-name prefix when possible.  A retry with the exact
        # deterministic staging name can then retire it without clobbering
        # the already-published destination.
        _fsync_directory(destination.parent)
        raise
    _fsync_directory(destination.parent)


def durable_replace(
    source: str | os.PathLike[str],
    destination: str | os.PathLike[str],
) -> None:
    """Atomically replace and durably publish a same-directory successor."""

    source_path, destination_path = _same_parent(source, destination)
    if _windows_publication_host():
        _windows_move(
            source_path,
            destination_path,
            replace_existing=True,
        )
        return
    os.replace(
        native_path(source_path),
        native_path(destination_path),
    )
    _fsync_directory(destination_path.parent)


def durable_publish_new(
    source: str | os.PathLike[str],
    destination: str | os.PathLike[str],
) -> None:
    """Durably publish a same-directory file without replacing a peer."""

    source_path, destination_path = _same_parent(source, destination)
    if lexists(destination_path):
        if lexists(source_path):
            source_row = lstat(source_path)
            destination_row = lstat(destination_path)
            if (
                _same_inode(source_row, destination_row)
                and int(
                    getattr(destination_row, "st_nlink", 1) or 1
                )
                == 2
            ):
                _retire_publication_source(source_path)
                _fsync_directory(destination_path.parent)
                return
        raise FileExistsError(
            errno.EEXIST,
            "durable write-once publication already exists",
            os.fspath(destination_path),
        )
    if _windows_publication_host():
        _windows_move(
            source_path,
            destination_path,
            replace_existing=False,
        )
        return
    if _posix_exclusive_rename(source_path, destination_path):
        _fsync_directory(destination_path.parent)
        return
    _durable_publish_new_link_fallback(
        source_path,
        destination_path,
    )


def durable_unlink(path: str | os.PathLike[str]) -> None:
    """Durably retire one exact name; a crash may leave only a tombstone."""

    target = absolute_path(path)
    if not lexists(target):
        return
    if os.name != "nt":
        os.unlink(native_path(target))
        _fsync_directory(target.parent)
        return
    tombstone = target.parent / (
        f".plamen-deleted-{uuid.uuid4().hex}.tombstone"
    )
    durable_publish_new(target, tombstone)
    try:
        os.unlink(native_path(tombstone))
    except OSError:
        # The authoritative name is already durably absent.  Surface cleanup
        # debt so a caller can flag it without resurrecting that name.
        raise


def lstat(path: str | os.PathLike[str]) -> os.stat_result:
    return os.stat(native_path(path), follow_symlinks=False)


def lexists(path: str | os.PathLike[str]) -> bool:
    try:
        lstat(path)
    except (FileNotFoundError, NotADirectoryError):
        return False
    return True


def _is_reparse_row(row: os.stat_result) -> bool:
    return bool(
        getattr(row, "st_file_attributes", 0)
        & _FILE_ATTRIBUTE_REPARSE_POINT
    )


def is_reparse(path: str | os.PathLike[str]) -> bool:
    try:
        return _is_reparse_row(lstat(path))
    except (FileNotFoundError, NotADirectoryError):
        return False


def is_symlink(path: str | os.PathLike[str]) -> bool:
    try:
        return stat.S_ISLNK(lstat(path).st_mode)
    except (FileNotFoundError, NotADirectoryError):
        return False


def is_file(path: str | os.PathLike[str]) -> bool:
    try:
        return stat.S_ISREG(lstat(path).st_mode)
    except (FileNotFoundError, NotADirectoryError):
        return False


def is_dir(path: str | os.PathLike[str]) -> bool:
    try:
        return stat.S_ISDIR(lstat(path).st_mode)
    except (FileNotFoundError, NotADirectoryError):
        return False


def scandir(path: str | os.PathLike[str]) -> Iterator[os.DirEntry[str]]:
    return os.scandir(native_path(path))


def exact_existing_name(path: str | os.PathLike[str]) -> None:
    """Reject a case-distinct spelling of an existing final component."""

    candidate = absolute_path(path)
    parent = candidate.parent
    if candidate == parent:
        return
    if os.name == "nt":
        data = _WIN32_FIND_DATAW()
        handle = _FindFirstFileW(
            native_path(candidate),
            ctypes.byref(data),
        )
        if handle == _INVALID_HANDLE_VALUE:
            error = ctypes.get_last_error()
            raise RootedPathIOError(
                f"cannot inspect exact rooted name {candidate}: "
                f"WinError {error}"
            )
        try:
            observed = str(data.cFileName)
        finally:
            _FindClose(handle)
        if observed != candidate.name:
            if observed.casefold() == candidate.name.casefold():
                raise RootedPathIOError(
                    f"path casing mismatch for {candidate}"
                )
            raise RootedPathIOError(
                f"path name changed while inspecting {candidate}"
            )
        return
    if not is_dir(parent):
        return
    try:
        with scandir(parent) as entries:
            names = [entry.name for entry in entries]
    except OSError as exc:
        raise RootedPathIOError(
            f"cannot enumerate rooted directory {parent}: {exc}"
        ) from exc
    if candidate.name in names:
        return
    if any(name.casefold() == candidate.name.casefold() for name in names):
        raise RootedPathIOError(
            f"path casing mismatch for {candidate}"
        )


def _validate_directory_row(
    path: Path,
    row: os.stat_result,
    *,
    label: str,
) -> None:
    if (
        stat.S_ISLNK(row.st_mode)
        or _is_reparse_row(row)
        or not stat.S_ISDIR(row.st_mode)
    ):
        raise RootedPathIOError(
            f"{label} is not a safe regular directory: {path}"
        )


def _validate_file_row(
    path: Path,
    row: os.stat_result,
    *,
    label: str,
    require_single_link: bool,
) -> None:
    if (
        stat.S_ISLNK(row.st_mode)
        or _is_reparse_row(row)
        or not stat.S_ISREG(row.st_mode)
        or (
            require_single_link
            and int(getattr(row, "st_nlink", 1)) != 1
        )
    ):
        raise RootedPathIOError(
            f"{label} is not a safe regular file: {path}"
        )


def checked_directory(
    path: str | os.PathLike[str],
    *,
    label: str = "rooted directory",
    verify_ancestors: bool = True,
    verify_exact_name: bool = True,
) -> Path:
    """Validate every existing component without resolving through aliases."""

    absolute = absolute_path(path)
    if not verify_ancestors:
        if verify_exact_name:
            exact_existing_name(absolute)
        try:
            row = lstat(absolute)
        except OSError as exc:
            raise RootedPathIOError(
                f"{label} is unavailable: {absolute}"
            ) from exc
        _validate_directory_row(absolute, row, label=label)
        return absolute
    anchor = Path(absolute.anchor)
    if not absolute.anchor:
        raise RootedPathIOError(f"{label} is not absolute")
    try:
        anchor_row = lstat(anchor)
    except OSError as exc:
        raise RootedPathIOError(f"{label} anchor is unavailable") from exc
    _validate_directory_row(anchor, anchor_row, label=label)

    current = anchor
    anchor_parts = len(anchor.parts)
    for part in absolute.parts[anchor_parts:]:
        candidate = current / part
        try:
            row = lstat(candidate)
        except OSError as exc:
            raise RootedPathIOError(
                f"{label} component is unavailable: {candidate}"
            ) from exc
        exact_existing_name(candidate)
        _validate_directory_row(candidate, row, label=label)
        current = candidate
    return absolute


def ensure_directory(
    path: str | os.PathLike[str],
    *,
    mode: int = 0o777,
    parents: bool = True,
    label: str = "rooted directory",
) -> Path:
    """Create and validate a directory without legacy-path or link traversal.

    Each component is addressed through :func:`native_path`, then re-read
    without following links.  A concurrent creator is accepted only when the
    resulting exact-name object is the safe directory that was requested.
    """

    absolute = absolute_path(path)
    if not absolute.anchor:
        raise RootedPathIOError(f"{label} is not absolute")
    anchor = Path(absolute.anchor)
    try:
        anchor_row = lstat(anchor)
    except OSError as exc:
        raise RootedPathIOError(f"{label} anchor is unavailable") from exc
    _validate_directory_row(anchor, anchor_row, label=label)

    current = anchor
    anchor_parts = len(anchor.parts)
    parts = absolute.parts[anchor_parts:]
    for ordinal, part in enumerate(parts):
        candidate = current / part
        if lexists(candidate):
            exact_existing_name(candidate)
            row = lstat(candidate)
            _validate_directory_row(candidate, row, label=label)
            current = candidate
            continue
        if not parents and ordinal != len(parts) - 1:
            raise RootedPathIOError(
                f"{label} parent is unavailable: {candidate.parent}"
            )
        try:
            os.mkdir(native_path(candidate), mode)
        except FileExistsError:
            # A concurrent creator is safe only after the same no-follow
            # exact-name validation as a pre-existing component.
            pass
        try:
            exact_existing_name(candidate)
            row = lstat(candidate)
        except OSError as exc:
            raise RootedPathIOError(
                f"{label} component could not be created: {candidate}"
            ) from exc
        _validate_directory_row(candidate, row, label=label)
        current = candidate
    return absolute


def _safe_temporary_affix(value: str, *, label: str) -> str:
    if (
        not isinstance(value, str)
        or "\x00" in value
        or any(char in value for char in ("/", "\\", ":"))
    ):
        raise RootedPathIOError(f"{label} is malformed")
    return value


def exclusive_temp_file(
    directory: str | os.PathLike[str],
    *,
    prefix: str = ".p.",
    suffix: str = ".tmp",
    mode: int = 0o600,
) -> tuple[int, Path]:
    """Create an exclusive same-directory temporary via rooted native I/O."""

    parent = checked_directory(
        directory,
        label="rooted temporary directory",
    )
    prefix = _safe_temporary_affix(prefix, label="temporary prefix")
    suffix = _safe_temporary_affix(suffix, label="temporary suffix")
    flags = os.O_RDWR | os.O_CREAT | os.O_EXCL
    flags |= int(getattr(os, "O_BINARY", 0) or 0)
    flags |= int(getattr(os, "O_NOFOLLOW", 0) or 0)
    for _attempt in range(128):
        candidate = parent / f"{prefix}{uuid.uuid4().hex}{suffix}"
        descriptor = -1
        try:
            descriptor = os.open(native_path(candidate), flags, mode)
        except FileExistsError:
            continue
        opened: os.stat_result | None = None
        try:
            opened = os.fstat(descriptor)
            exact_existing_name(candidate)
            named = lstat(candidate)
            if (
                not stat.S_ISREG(opened.st_mode)
                or _is_reparse_row(opened)
                or int(getattr(opened, "st_nlink", 1) or 1) != 1
                or not _same_inode(opened, named)
                or _is_reparse_row(named)
                or not stat.S_ISREG(named.st_mode)
                or int(getattr(named, "st_nlink", 1) or 1) != 1
            ):
                raise RootedPathIOError(
                    "exclusive rooted temporary is not a stable "
                    "single-link regular file"
                )
            return descriptor, candidate
        except BaseException:
            os.close(descriptor)
            # Remove only the name that still denotes the object we opened.
            try:
                named = lstat(candidate)
            except OSError:
                pass
            else:
                if opened is not None and _same_inode(opened, named):
                    os.unlink(native_path(candidate))
            raise
    raise FileExistsError(
        errno.EEXIST,
        "could not allocate an exclusive rooted temporary",
        os.fspath(parent),
    )


def checked_file(
    path: str | os.PathLike[str],
    *,
    label: str = "rooted file",
    require_single_link: bool = True,
    verify_ancestors: bool = True,
    verify_exact_name: bool = True,
) -> Path:
    """Validate an exact-case, alias-free existing regular file."""

    absolute = absolute_path(path)
    if verify_ancestors:
        checked_directory(absolute.parent, label=f"{label} parent")
    if verify_exact_name:
        exact_existing_name(absolute)
    try:
        row = lstat(absolute)
    except OSError as exc:
        raise RootedPathIOError(f"{label} is unavailable: {absolute}") from exc
    _validate_file_row(
        absolute,
        row,
        label=label,
        require_single_link=require_single_link,
    )
    return absolute


def _identity(row: os.stat_result) -> tuple[int, int]:
    return (
        int(getattr(row, "st_dev", 0)),
        int(getattr(row, "st_ino", 0)),
    )


def _bounded_read_pre_read_hook(path: Path) -> None:
    """Fault-injection seam after descriptor validation, before bounded read."""


def read_bytes(
    path: str | os.PathLike[str],
    *,
    label: str = "rooted file",
    require_single_link: bool = False,
    verify_ancestors: bool = True,
    verify_exact_name: bool = True,
    max_bytes: int | None = None,
) -> bytes:
    """Read through a checked handle whose identity matches the lstat row."""

    if max_bytes is not None and (
        isinstance(max_bytes, bool)
        or not isinstance(max_bytes, int)
        or max_bytes < 0
    ):
        raise ValueError("max_bytes must be a non-negative integer or None")

    checked = checked_file(
        path,
        label=label,
        require_single_link=require_single_link,
        verify_ancestors=verify_ancestors,
        verify_exact_name=verify_exact_name,
    )
    before = lstat(checked)
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    try:
        descriptor = os.open(native_path(checked), flags)
        after = os.fstat(descriptor)
        _validate_file_row(
            checked,
            after,
            label=label,
            require_single_link=require_single_link,
        )
        if _identity(before) != _identity(after):
            raise RootedPathIOError(
                f"{label} identity changed while opening: {checked}"
            )
        with os.fdopen(descriptor, "rb", closefd=True) as handle:
            descriptor = None
            if max_bytes is None:
                return handle.read()
            if int(after.st_size) > max_bytes:
                raise RootedPathIOError(
                    f"{label} exceeds the {max_bytes}-byte read bound: {checked}"
                )
            _bounded_read_pre_read_hook(checked)
            raw = handle.read(max_bytes + 1)
            if len(raw) > max_bytes:
                raise RootedPathIOError(
                    f"{label} exceeded the {max_bytes}-byte read bound while "
                    f"reading: {checked}"
                )
            final_opened = os.fstat(handle.fileno())
            final_named = lstat(checked)
            _validate_file_row(
                checked,
                final_opened,
                label=label,
                require_single_link=require_single_link,
            )
            _validate_file_row(
                checked,
                final_named,
                label=label,
                require_single_link=require_single_link,
            )
            identity_fields = (
                "st_dev", "st_ino", "st_nlink",
                "st_file_attributes", "st_reparse_tag",
            )
            content_fields = ("st_size", "st_mtime_ns", "st_ctime_ns")

            def fields(
                row: os.stat_result, names: tuple[str, ...],
            ) -> tuple[int, ...]:
                return tuple(int(getattr(row, field, 0)) for field in names)

            identities = {
                fields(row, identity_fields)
                for row in (before, after, final_opened, final_named)
            }
            # Windows can expose a different cached ctime through the pathname
            # and already-open descriptor immediately after a prior write.
            # Compare stability within each observation channel, while binding
            # the file identity and exact size across both channels.
            stable_named = (
                fields(before, content_fields)
                == fields(final_named, content_fields)
            )
            stable_opened = (
                fields(after, content_fields)
                == fields(final_opened, content_fields)
            )
            same_size = (
                int(before.st_size)
                == int(after.st_size)
                == int(final_opened.st_size)
                == int(final_named.st_size)
                == len(raw)
            )
            if (
                len(identities) != 1
                or not stable_named
                or not stable_opened
                or not same_size
            ):
                raise RootedPathIOError(
                    f"{label} identity or content size changed during bounded "
                    f"read: {checked}"
                )
            return raw
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _write_once_stage_path(destination: Path, raw: bytes) -> Path:
    token = hashlib.sha256(
        os.fsencode(destination.name) + b"\x00" + raw
    ).hexdigest()
    return destination.parent / f".plamen-write-once-{token}.stage"


def _write_once_pre_publish_hook(stage: Path, destination: Path) -> None:
    """Fault-injection seam after durable validation, before publication."""


def _write_once_pre_rename_hook(stage: Path, destination: Path) -> None:
    """Fault-injection seam at the Windows no-replace linearization edge."""


def _write_once_post_publish_hook(stage: Path, destination: Path) -> None:
    """Fault-injection seam after Windows rename, before commit checks."""


def _write_once_pre_retire_hook(stage: Path, destination: Path) -> None:
    """Fault-injection seam while the exact retirement handle remains held."""


def _validate_single_link_row(
    path: Path,
    row: os.stat_result,
    *,
    label: str,
) -> None:
    _validate_file_row(
        path,
        row,
        label=label,
        require_single_link=False,
    )
    if int(getattr(row, "st_nlink", 1) or 1) != 1:
        raise RootedPathIOError(
            f"{label} is not a stable single-link regular file: {path}"
        )


def _descriptor_bytes(descriptor: int) -> bytes:
    os.lseek(descriptor, 0, os.SEEK_SET)
    chunks: list[bytes] = []
    while True:
        chunk = os.read(descriptor, 1024 * 1024)
        if not chunk:
            break
        chunks.append(chunk)
    return b"".join(chunks)


def _validate_named_descriptor(
    descriptor: int,
    path: Path,
    *,
    label: str,
) -> os.stat_result:
    opened = os.fstat(descriptor)
    named = lstat(path)
    _validate_single_link_row(path, opened, label=label)
    _validate_single_link_row(path, named, label=label)
    if not _same_inode(opened, named):
        raise RootedPathIOError(
            f"{label} identity changed before publication: {path}"
        )
    return opened


def _mismatch_error(
    path: Path,
    expected: bytes,
    observed: bytes,
    *,
    destination: Path | None,
    stage: bool,
    label: str,
) -> BaseException:
    if stage:
        return DurableWriteOnceStageError(
            stage=path,
            destination=destination,
            expected=expected,
            observed=observed,
        )
    return FileExistsError(
        errno.EEXIST,
        f"{label} contains foreign bytes",
        os.fspath(path),
    )


def _open_exact_single_descriptor(
    path: Path,
    raw: bytes,
    *,
    label: str,
    stage: bool,
    durable: bool,
    destination: Path | None = None,
) -> int:
    flags = os.O_RDWR | getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(native_path(path), flags)
    try:
        _validate_named_descriptor(descriptor, path, label=label)
        observed = _descriptor_bytes(descriptor)
        if observed != raw:
            raise _mismatch_error(
                path,
                raw,
                observed,
                destination=destination,
                stage=stage,
                label=label,
            )
        if durable:
            os.fsync(descriptor)
        _validate_named_descriptor(descriptor, path, label=label)
        if _descriptor_bytes(descriptor) != raw:
            raise RootedPathIOError(
                f"{label} changed while durability was established: {path}"
            )
        if durable:
            _fsync_directory(path.parent)
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _write_once_existing_is_exact(
    path: Path,
    raw: bytes,
    *,
    label: str,
    stage: bool = False,
    durable: bool = False,
    destination: Path | None = None,
) -> bool:
    if not lexists(path):
        return False
    if os.name == "nt":
        _windows_locked_existing_is_exact(
            path,
            raw,
            label=label,
            stage=stage,
            durable=durable,
            destination=destination or path,
        )
        return True
    descriptor = _open_exact_single_descriptor(
        path,
        raw,
        label=label,
        stage=stage,
        durable=durable,
        destination=destination,
    )
    os.close(descriptor)
    return True


def _retire_exact_write_once_stage(
    stage: Path,
    destination: Path,
    raw: bytes,
) -> None:
    """Retire an exact stage left beside an already-exact destination."""

    if not lexists(stage):
        return
    if os.name == "nt":
        _windows_retire_exact_stage(stage, destination, raw)
        return
    exact_stage = _write_once_existing_is_exact(
        stage,
        raw,
        label="durable write-once staging bytes",
        stage=True,
        durable=True,
        destination=destination,
    )
    if not exact_stage:
        return
    # POSIX has no portable unlink-by-open-file-description primitive.  A
    # pathname unlink after validation can remove a replacement, so preserve
    # the exact residue and require explicit recovery instead.
    raise DurableWriteOnceDebtError(
        stage=stage,
        destination=destination,
        expected=raw,
        observed=raw,
        cleanup_state="EXACT_STAGE_RETIREMENT_REQUIRES_RECOVERY",
        detail=(
            "durable write-once exact stage cannot be retired object-bound "
            "on this platform and was preserved"
        ),
    )


def _posix_link_open_descriptor(
    descriptor: int,
    destination: Path,
) -> str:
    directory_descriptor = os.open(
        native_path(destination.parent),
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
    )
    try:
        library = ctypes.CDLL(None, use_errno=True)
        if sys.platform.startswith("linux"):
            linkat = getattr(library, "linkat", None)
            if linkat is None:
                raise RootedPathIOError(
                    "descriptor-bound linkat publication is unavailable"
                )
            linkat.argtypes = (
                ctypes.c_int,
                ctypes.c_char_p,
                ctypes.c_int,
                ctypes.c_char_p,
                ctypes.c_int,
            )
            linkat.restype = ctypes.c_int
            result = linkat(
                descriptor,
                b"",
                directory_descriptor,
                os.fsencode(destination.name),
                0x1000,  # AT_EMPTY_PATH
            )
            if result != 0 and ctypes.get_errno() in {
                errno.EPERM,
                errno.EINVAL,
                getattr(errno, "ENOTSUP", errno.EINVAL),
            }:
                result = linkat(
                    -100,
                    os.fsencode(f"/proc/self/fd/{descriptor}"),
                    directory_descriptor,
                    os.fsencode(destination.name),
                    0x400,  # AT_SYMLINK_FOLLOW
                )
            if result == 0:
                # Linux callers pass an unnamed O_TMPFILE descriptor.  The
                # resulting final therefore has one link; it is not an alias
                # of the deterministic recovery stage.
                return "ANONYMOUS"
        elif sys.platform == "darwin":
            clone = getattr(library, "fclonefileat", None)
            if clone is None:
                raise RootedPathIOError(
                    "descriptor-bound clone publication is unavailable"
                )
            clone.argtypes = (
                ctypes.c_int,
                ctypes.c_int,
                ctypes.c_char_p,
                ctypes.c_int,
            )
            clone.restype = ctypes.c_int
            if clone(
                descriptor,
                directory_descriptor,
                os.fsencode(destination.name),
                0,
            ) == 0:
                return "CLONE"
        else:
            raise RootedPathIOError(
                "descriptor-bound no-replace publication is unsupported "
                f"on {sys.platform}"
            )
        error = ctypes.get_errno()
        if error == errno.EEXIST:
            raise FileExistsError(
                error,
                "durable write-once destination already exists",
                os.fspath(destination),
            )
        raise OSError(
            error,
            "descriptor-bound no-replace publication failed",
            os.fspath(destination),
        )
    finally:
        os.close(directory_descriptor)


def _windows_handle_information(handle: int) -> Any:
    information = _BY_HANDLE_FILE_INFORMATION()
    if not _GetFileInformationByHandle(handle, ctypes.byref(information)):
        error = ctypes.get_last_error()
        raise OSError(error, "GetFileInformationByHandle failed")
    return information


def _windows_handle_bytes(handle: int) -> bytes:
    """Read a locked Windows file through its handle, never through its name."""

    position = ctypes.c_longlong()
    if not _SetFilePointerEx(handle, 0, ctypes.byref(position), _FILE_BEGIN):
        error = ctypes.get_last_error()
        raise OSError(error, "SetFilePointerEx failed")
    information = _windows_handle_information(handle)
    size = (int(information.nFileSizeHigh) << 32) | int(
        information.nFileSizeLow
    )
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        amount = min(remaining, 1024 * 1024)
        buffer = ctypes.create_string_buffer(amount)
        consumed = wintypes.DWORD()
        if not _ReadFile(
            handle,
            buffer,
            amount,
            ctypes.byref(consumed),
            None,
        ):
            error = ctypes.get_last_error()
            raise OSError(error, "ReadFile failed")
        if not consumed.value:
            raise RootedPathIOError(
                "locked Windows file ended before its advertised size"
            )
        chunks.append(buffer.raw[: consumed.value])
        remaining -= consumed.value
    return b"".join(chunks)


def _windows_handle_identity(information: Any) -> tuple[int, int, int]:
    return (
        int(information.dwVolumeSerialNumber),
        int(information.nFileIndexHigh),
        int(information.nFileIndexLow),
    )


def _windows_validate_named_handle(
    handle: int,
    path: Path,
    *,
    label: str,
) -> Any:
    """Bind a locked file handle to its exact non-reparse single-link name."""

    opened = _windows_handle_information(handle)
    if int(opened.dwFileAttributes) & (
        _FILE_ATTRIBUTE_REPARSE_POINT | _FILE_ATTRIBUTE_DIRECTORY
    ):
        raise RootedPathIOError(
            f"{label} is not a regular, non-reparse file: {path}"
        )
    if int(opened.nNumberOfLinks) != 1:
        raise RootedPathIOError(
            f"{label} is not a stable single-link regular file: {path}"
        )
    named_handle = _CreateFileW(
        native_path(path),
        _GENERIC_READ,
        _FILE_SHARE_READ | _FILE_SHARE_WRITE | _FILE_SHARE_DELETE,
        None,
        _OPEN_EXISTING,
        _FILE_FLAG_OPEN_REPARSE_POINT,
        None,
    )
    if named_handle == _INVALID_HANDLE_VALUE:
        error = ctypes.get_last_error()
        raise OSError(error, f"{label} name handle open failed", os.fspath(path))
    try:
        named = _windows_handle_information(named_handle)
        if int(named.dwFileAttributes) & (
            _FILE_ATTRIBUTE_REPARSE_POINT | _FILE_ATTRIBUTE_DIRECTORY
        ):
            raise RootedPathIOError(
                f"{label} name is not a regular, non-reparse file: {path}"
            )
        if _windows_handle_identity(opened) != _windows_handle_identity(named):
            raise RootedPathIOError(
                f"{label} name identity differs from its locked handle: {path}"
            )
    finally:
        _CloseHandle(named_handle)
    return opened


def _best_effort_observed_bytes(path: Path) -> bytes | None:
    try:
        return read_bytes(
            path,
            label="durable write-once debt observation",
            require_single_link=False,
        )
    except BaseException:
        return None


def _windows_locked_existing_is_exact(
    path: Path,
    raw: bytes,
    *,
    label: str,
    stage: bool,
    durable: bool,
    destination: Path,
) -> None:
    """Validate an existing name at a write/delete-excluding linearization.

    The final handle check after the file and directory barriers is the
    linearization point.  The handle excludes concurrent write and delete
    capabilities until it closes; mutation acquired after release is a later
    filesystem event and is not represented as part of this completed CAS.
    """

    handle = _CreateFileW(
        native_path(path),
        _GENERIC_READ | _GENERIC_WRITE,
        _FILE_SHARE_READ,
        None,
        _OPEN_EXISTING,
        _FILE_FLAG_OPEN_REPARSE_POINT | _FILE_FLAG_WRITE_THROUGH,
        None,
    )
    if handle == _INVALID_HANDLE_VALUE:
        error = ctypes.get_last_error()
        raise DurableWriteOnceDebtError(
            stage=path if stage else _write_once_stage_path(destination, raw),
            destination=destination,
            expected=raw,
            observed=_best_effort_observed_bytes(path),
            cleanup_state=(
                "EXACT_STAGE_NOT_EXCLUSIVELY_LOCKED"
                if stage
                else "EXACT_FINAL_NOT_EXCLUSIVELY_LOCKED"
            ),
            detail=(
                "durable write-once exact object could not acquire a "
                f"write-excluding handle (WinError {error})"
            ),
        )
    try:
        _windows_validate_named_handle(handle, path, label=label)
        observed = _windows_handle_bytes(handle)
        if observed != raw:
            raise _mismatch_error(
                path,
                raw,
                observed,
                destination=destination,
                stage=stage,
                label=label,
            )
        if durable:
            if not _FlushFileBuffers(handle):
                error = ctypes.get_last_error()
                raise OSError(error, f"{label} FlushFileBuffers failed")
            _fsync_directory(path.parent)
        _windows_validate_named_handle(handle, path, label=label)
        observed = _windows_handle_bytes(handle)
        if observed != raw:
            raise _mismatch_error(
                path,
                raw,
                observed,
                destination=destination,
                stage=stage,
                label=label,
            )
    except DurableWriteOnceDebtError:
        raise
    except FileExistsError:
        raise
    except RootedPathIOError as exc:
        raise DurableWriteOnceDebtError(
            stage=path if stage else _write_once_stage_path(destination, raw),
            destination=destination,
            expected=raw,
            observed=_best_effort_observed_bytes(path),
            cleanup_state=(
                "EXACT_STAGE_VALIDATION_FAILED"
                if stage
                else "EXACT_FINAL_VALIDATION_FAILED"
            ),
            detail=f"durable write-once locked object validation failed: {exc}",
        ) from exc
    except OSError as exc:
        raise DurableWriteOnceDebtError(
            stage=path if stage else _write_once_stage_path(destination, raw),
            destination=destination,
            expected=raw,
            observed=_best_effort_observed_bytes(path),
            cleanup_state=(
                "EXACT_STAGE_DURABILITY_FAILED"
                if stage
                else "EXACT_FINAL_DURABILITY_FAILED"
            ),
            detail=f"durable write-once exact object durability failed: {exc}",
        ) from exc
    finally:
        _CloseHandle(handle)


def _windows_set_open_link_deletion(handle: int, *, delete: bool) -> None:
    information = _FILE_DISPOSITION_INFO()
    information.DeleteFile = 1 if delete else 0
    if not _SetFileInformationByHandle(
        handle,
        _FILE_DISPOSITION_INFO_CLASS,
        ctypes.byref(information),
        ctypes.sizeof(information),
    ):
        error = ctypes.get_last_error()
        action = "retirement" if delete else "retirement cancellation"
        raise OSError(error, f"FileDispositionInformation {action} failed")


def _windows_mark_open_link_for_deletion(handle: int) -> None:
    _windows_set_open_link_deletion(handle, delete=True)


def _windows_cancel_open_link_deletion(handle: int) -> None:
    _windows_set_open_link_deletion(handle, delete=False)


def _windows_retire_exact_stage(
    stage: Path,
    destination: Path,
    raw: bytes,
) -> None:
    """Retire only the exact object denoted by a held Windows handle."""

    handle = _CreateFileW(
        native_path(stage),
        _GENERIC_READ | _GENERIC_WRITE | _DELETE_ACCESS,
        _FILE_SHARE_READ | _FILE_SHARE_DELETE,
        None,
        _OPEN_EXISTING,
        _FILE_FLAG_OPEN_REPARSE_POINT | _FILE_FLAG_WRITE_THROUGH,
        None,
    )
    if handle == _INVALID_HANDLE_VALUE:
        error = ctypes.get_last_error()
        raise DurableWriteOnceDebtError(
            stage=stage,
            destination=destination,
            expected=raw,
            observed=_best_effort_observed_bytes(stage),
            cleanup_state="EXACT_STAGE_RETIREMENT_UNPROVEN",
            detail=(
                "durable write-once exact stage could not acquire its "
                f"object-bound retirement handle (WinError {error})"
            ),
        )
    marked = False
    hook_failure: BaseException | None = None
    try:
        _windows_validate_named_handle(
            handle,
            stage,
            label="durable write-once staging bytes",
        )
        observed = _windows_handle_bytes(handle)
        if observed != raw:
            raise DurableWriteOnceStageError(
                stage=stage,
                destination=destination,
                expected=raw,
                observed=observed,
            )
        if not _FlushFileBuffers(handle):
            error = ctypes.get_last_error()
            raise OSError(error, "durable stage retirement flush failed")
        _fsync_directory(stage.parent)
        try:
            _write_once_pre_retire_hook(stage, destination)
        except BaseException as exc:
            hook_failure = exc
        # The name may have moved, but all destructive action remains bound to
        # the validated object.  Never reopen or unlink the deterministic name.
        information = _windows_handle_information(handle)
        observed = _windows_handle_bytes(handle)
        if observed != raw:
            raise DurableWriteOnceStageError(
                stage=stage,
                destination=destination,
                expected=raw,
                observed=observed,
            )
        if int(information.nNumberOfLinks) < 1:
            raise RootedPathIOError(
                "durable write-once retirement handle lost all links"
            )
        _windows_mark_open_link_for_deletion(handle)
        marked = True
    except DurableWriteOnceDebtError:
        raise
    except (RootedPathIOError, OSError) as exc:
        raise DurableWriteOnceDebtError(
            stage=stage,
            destination=destination,
            expected=raw,
            observed=_best_effort_observed_bytes(stage),
            cleanup_state="EXACT_STAGE_RETIREMENT_UNPROVEN",
            detail=f"durable write-once exact stage retirement failed: {exc}",
        ) from exc
    finally:
        _CloseHandle(handle)

    if not marked:
        raise DurableWriteOnceDebtError(
            stage=stage,
            destination=destination,
            expected=raw,
            observed=_best_effort_observed_bytes(stage),
            cleanup_state="EXACT_STAGE_RETIREMENT_UNPROVEN",
            detail="durable write-once exact stage retirement was not proven",
        )
    _fsync_directory(stage.parent)
    if lexists(stage):
        raise DurableWriteOnceDebtError(
            stage=stage,
            destination=destination,
            expected=raw,
            observed=_best_effort_observed_bytes(stage),
            cleanup_state="FOREIGN_STAGE_NAME_PRESERVED",
            detail=(
                "durable write-once deterministic stage name was replaced; "
                "the replacement was preserved"
            ),
        )
    if hook_failure is not None:
        raise DurableWriteOnceDebtError(
            stage=stage,
            destination=destination,
            expected=raw,
            observed=None,
            cleanup_state="EXACT_STAGE_RETIRED_WITH_HOOK_FAILURE",
            detail=f"durable write-once retirement hook failed: {hook_failure}",
        )


def _windows_rename_open_handle_new(handle: int, destination: Path) -> None:
    """Atomically rename an open handle without replacing a destination."""

    encoded = native_path(destination).encode("utf-16-le")
    name_offset = int(_FILE_RENAME_INFO.FileName.offset)
    # Windows documents the allocation as sizeof(FILE_RENAME_INFO) plus the
    # variable filename bytes.  Keep the structure's trailing alignment bytes;
    # omitting them can make FileRenameInfo consume stale source-name suffixes.
    buffer = ctypes.create_string_buffer(
        ctypes.sizeof(_FILE_RENAME_INFO) + len(encoded)
    )
    information = _FILE_RENAME_INFO.from_buffer(buffer)
    information.ReplaceIfExists = 0
    information.RootDirectory = None
    information.FileNameLength = len(encoded)
    ctypes.memmove(
        ctypes.addressof(buffer) + name_offset,
        encoded,
        len(encoded),
    )
    if _SetFileInformationByHandle(
        handle,
        _FILE_RENAME_INFO_CLASS,
        buffer,
        len(buffer),
    ):
        return
    error = ctypes.get_last_error()
    if error in {_ERROR_FILE_EXISTS, _ERROR_ALREADY_EXISTS}:
        raise FileExistsError(
            error,
            "durable write-once destination already exists",
            os.fspath(destination),
        )
    raise OSError(
        error,
        "SetFileInformationByHandle durable publication failed",
        os.fspath(destination),
    )


def _windows_publish_locked_stage(
    stage: Path,
    destination: Path,
    raw: bytes,
) -> None:
    handle = _CreateFileW(
        native_path(stage),
        _GENERIC_READ | _GENERIC_WRITE | _DELETE_ACCESS,
        _FILE_SHARE_READ | _FILE_SHARE_DELETE,
        None,
        _OPEN_EXISTING,
        _FILE_FLAG_OPEN_REPARSE_POINT | _FILE_FLAG_WRITE_THROUGH,
        None,
    )
    if handle == _INVALID_HANDLE_VALUE:
        error = ctypes.get_last_error()
        raise DurableWriteOnceDebtError(
            stage=stage,
            destination=destination,
            expected=raw,
            observed=_best_effort_observed_bytes(stage),
            cleanup_state="STAGE_PUBLICATION_NOT_EXCLUSIVELY_LOCKED",
            detail=(
                "durable stage could not acquire a write-excluding "
                f"publication handle (WinError {error})"
            ),
        )
    published = False
    failure: BaseException | None = None
    rollback_marked = False
    rollback_failure: BaseException | None = None
    held_observed: bytes | None = None
    try:
        _windows_validate_named_handle(
            handle,
            stage,
            label="durable write-once staging bytes",
        )
        observed = _windows_handle_bytes(handle)
        if observed != raw:
            raise DurableWriteOnceStageError(
                stage=stage,
                destination=destination,
                expected=raw,
                observed=observed,
            )
        if not _FlushFileBuffers(handle):
            error = ctypes.get_last_error()
            raise OSError(error, "durable stage FlushFileBuffers failed")
        _fsync_directory(stage.parent)
        try:
            _write_once_pre_publish_hook(stage, destination)
        except OSError as exc:
            named_observed = _best_effort_observed_bytes(stage)
            if named_observed is not None and named_observed != raw:
                raise DurableWriteOnceStageError(
                    stage=stage,
                    destination=destination,
                    expected=raw,
                    observed=named_observed,
                ) from exc
            raise DurableWriteOnceDebtError(
                stage=stage,
                destination=destination,
                expected=raw,
                observed=named_observed,
                cleanup_state="PREPUBLICATION_MUTATION_DENIED",
                detail=(
                    "durable write-once stage identity mutation was denied "
                    "before publication"
                ),
            ) from exc
        information = _windows_handle_information(handle)
        if int(information.nNumberOfLinks) != 1:
            raise RootedPathIOError(
                "durable write-once staging bytes acquired a hardlink alias"
            )
        if _windows_handle_bytes(handle) != raw:
            raise RootedPathIOError(
                "durable write-once staging bytes changed before publication"
            )
        _write_once_pre_rename_hook(stage, destination)
        _windows_rename_open_handle_new(handle, destination)
        published = True
        _write_once_post_publish_hook(stage, destination)
        information = _windows_handle_information(handle)
        if int(information.nNumberOfLinks) != 1:
            raise RootedPathIOError(
                "durable destination acquired an unexpected hardlink alias"
            )
        if _windows_handle_bytes(handle) != raw:
            raise RootedPathIOError(
                "durable destination differs from the validated postimage"
            )
        _windows_validate_named_handle(
            handle,
            destination,
            label="durable write-once destination",
        )
        if not _FlushFileBuffers(handle):
            error = ctypes.get_last_error()
            raise OSError(error, "published file FlushFileBuffers failed")
        _fsync_directory(destination.parent)
        # Linearization point: exact name/identity, bytes and single-link state
        # are observed after both durability barriers while the publication
        # handle still excludes writers.  Mutation after handle release is a
        # later filesystem event, not part of this completed CAS.
        _windows_validate_named_handle(
            handle,
            destination,
            label="durable write-once destination",
        )
        held_observed = _windows_handle_bytes(handle)
        if held_observed != raw:
            raise RootedPathIOError(
                "durable destination changed before publication commit"
            )
    except BaseException as exc:
        failure = exc
        if published:
            try:
                held_observed = _windows_handle_bytes(handle)
            except BaseException:
                held_observed = None
            try:
                _windows_mark_open_link_for_deletion(handle)
                rollback_marked = True
            except BaseException as rollback_exc:
                rollback_failure = rollback_exc
    finally:
        _CloseHandle(handle)

    if failure is not None:
        if not published:
            if isinstance(failure, (DurableWriteOnceDebtError, FileExistsError)):
                raise failure
            raise DurableWriteOnceDebtError(
                stage=stage,
                destination=destination,
                expected=raw,
                observed=_best_effort_observed_bytes(stage),
                cleanup_state="STAGE_PUBLICATION_ABORTED_PRESERVED",
                detail=(
                    "durable write-once publication stopped before the "
                    f"no-replace boundary: {failure}"
                ),
            ) from failure
        if rollback_marked:
            try:
                _fsync_directory(destination.parent)
            except BaseException as exc:
                rollback_failure = exc
        if rollback_marked and not lexists(destination):
            raise DurableWriteOnceDebtError(
                stage=stage,
                destination=destination,
                expected=raw,
                observed=held_observed,
                cleanup_state="PUBLISHED_LINK_ROLLED_BACK",
                detail=(
                    "durable publication commit failed and its exact public "
                    "link was rolled back through the held handle"
                ),
            ) from failure
        cleanup_state = (
            "PUBLISHED_OBJECT_ROLLBACK_UNPROVEN"
            if rollback_failure is not None
            else "FOREIGN_DESTINATION_NAME_PRESERVED"
        )
        raise DurableWriteOnceDebtError(
            stage=stage,
            destination=destination,
            expected=raw,
            observed=_best_effort_observed_bytes(destination),
            cleanup_state=cleanup_state,
            detail=(
                "durable publication commit failed; only the held exact "
                "object was eligible for rollback and the current public "
                "name was preserved"
            ),
        ) from (rollback_failure or failure)

    if not published:
        raise RootedPathIOError("durable Windows publication did not run")
    # A name-swap racer may have installed an unrelated object at the
    # deterministic stage path while the validated handle was renamed.  Never
    # delete it; surface structured debt so callers cannot silently accept it.
    if lexists(stage):
        _retire_exact_write_once_stage(stage, destination, raw)


def _linux_publish_anonymous_bytes(
    logical_stage: Path,
    destination: Path,
    raw: bytes,
) -> None:
    """Publish raw bytes from an unnamed, single-link Linux snapshot."""

    temporary_flag = int(getattr(os, "O_TMPFILE", 0) or 0)
    if not temporary_flag:
        raise DurableWriteOnceDebtError(
            stage=logical_stage,
            destination=destination,
            expected=raw,
            observed=None,
            cleanup_state="LINUX_ANONYMOUS_SNAPSHOT_UNAVAILABLE",
            detail="Linux immutable anonymous publication is unavailable",
        )
    descriptor = -1
    linked = False
    try:
        descriptor = os.open(
            native_path(destination.parent),
            os.O_RDWR | temporary_flag,
            0o600,
        )
        view = memoryview(raw)
        offset = 0
        while offset < len(view):
            written = os.write(descriptor, view[offset:])
            if written <= 0 or written > len(view) - offset:
                raise OSError(errno.EIO, "anonymous durable write-once short write")
            offset += written
        os.fsync(descriptor)
        row = os.fstat(descriptor)
        if (
            not stat.S_ISREG(row.st_mode)
            or int(getattr(row, "st_nlink", 0) or 0) != 0
            or _descriptor_bytes(descriptor) != raw
        ):
            raise RootedPathIOError(
                "Linux anonymous publication snapshot is not exact and unlinked"
            )
        _write_once_pre_publish_hook(logical_stage, destination)
        if _posix_link_open_descriptor(descriptor, destination) != "ANONYMOUS":
            raise RootedPathIOError(
                "Linux anonymous publication used an unexpected primitive"
            )
        linked = True
        destination_row = lstat(destination)
        _validate_single_link_row(
            destination,
            destination_row,
            label="durable write-once destination",
        )
        if (
            not _same_inode(os.fstat(descriptor), destination_row)
            or _descriptor_bytes(descriptor) != raw
        ):
            raise RootedPathIOError(
                "Linux descriptor-published destination is not the exact snapshot"
            )
        os.fsync(descriptor)
        _fsync_directory(destination.parent)
        destination_row = lstat(destination)
        _validate_single_link_row(
            destination,
            destination_row,
            label="durable write-once destination",
        )
        if (
            not _same_inode(os.fstat(descriptor), destination_row)
            or _descriptor_bytes(descriptor) != raw
        ):
            raise RootedPathIOError(
                "Linux destination changed before its durability linearization"
            )
    except FileExistsError:
        raise
    except BaseException as exc:
        raise DurableWriteOnceDebtError(
            stage=logical_stage,
            destination=destination,
            expected=raw,
            observed=(
                _best_effort_observed_bytes(destination) if linked else None
            ),
            cleanup_state=(
                "ANONYMOUS_PUBLICATION_RESIDUE_PRESERVED"
                if linked
                else "ANONYMOUS_PUBLICATION_FAILED_ABSENT"
            ),
            detail=f"Linux anonymous durable publication failed: {exc}",
        ) from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _posix_publish_open_stage(
    stage: Path,
    destination: Path,
    raw: bytes,
) -> None:
    if sys.platform == "darwin":
        # fclonefileat is descriptor-bound but its source can still be mutated
        # through a pre-existing descriptor.  Until Darwin has an immutable
        # anonymous snapshot source, cloning the deterministic stage directly
        # could materialize foreign bytes under the authoritative final name.
        raise DurableWriteOnceDebtError(
            stage=stage,
            destination=destination,
            expected=raw,
            observed=_best_effort_observed_bytes(stage),
            cleanup_state="DARWIN_IMMUTABLE_SNAPSHOT_UNAVAILABLE",
            detail=(
                "Darwin durable publication requires an immutable anonymous "
                "snapshot and therefore fails closed"
            ),
        )
    source_descriptor = _open_exact_single_descriptor(
        stage,
        raw,
        label="durable write-once staging bytes",
        stage=True,
        durable=True,
        destination=destination,
    )
    publication_descriptor = source_descriptor
    source_row: os.stat_result | None = None
    try:
        source_row = _validate_named_descriptor(
            source_descriptor,
            stage,
            label="durable write-once staging bytes",
        )
        if sys.platform.startswith("linux"):
            temporary_flag = int(getattr(os, "O_TMPFILE", 0) or 0)
            if not temporary_flag:
                raise RootedPathIOError(
                    "single-link anonymous publication is unavailable"
                )
            try:
                publication_descriptor = os.open(
                    native_path(destination.parent),
                    os.O_RDWR | temporary_flag,
                    0o600,
                )
            except OSError as exc:
                raise RootedPathIOError(
                    "single-link anonymous publication is unavailable"
                ) from exc
            view = memoryview(raw)
            offset = 0
            while offset < len(view):
                written = os.write(publication_descriptor, view[offset:])
                if written <= 0 or written > len(view) - offset:
                    raise OSError(
                        errno.EIO,
                        "anonymous durable write-once short write",
                    )
                offset += written
            os.fsync(publication_descriptor)
            anonymous_row = os.fstat(publication_descriptor)
            if (
                not stat.S_ISREG(anonymous_row.st_mode)
                or int(getattr(anonymous_row, "st_nlink", 0) or 0) != 0
                or _descriptor_bytes(publication_descriptor) != raw
            ):
                raise RootedPathIOError(
                    "anonymous publication copy is not an exact unlinked file"
                )
        _write_once_pre_publish_hook(stage, destination)
        # Re-read the held source after the seam.  Publication itself uses a
        # separate exact anonymous copy on Linux, so a later name swap cannot
        # redirect foreign bytes into the authoritative final.
        if _descriptor_bytes(source_descriptor) != raw:
            raise DurableWriteOnceStageError(
                stage=stage,
                destination=destination,
                expected=raw,
                observed=_descriptor_bytes(source_descriptor),
            )
        publication_kind = _posix_link_open_descriptor(
            publication_descriptor,
            destination,
        )
        destination_row = lstat(destination)
        _validate_single_link_row(
            destination,
            destination_row,
            label="durable write-once destination",
        )
        publication_row = os.fstat(publication_descriptor)
        if publication_kind == "ANONYMOUS":
            if not _same_inode(publication_row, destination_row):
                raise RootedPathIOError(
                    "descriptor-published destination identity is incorrect"
                )
            if _descriptor_bytes(publication_descriptor) != raw:
                raise RootedPathIOError(
                    "descriptor-published destination differs from its "
                    "postimage"
                )
        else:
            destination_descriptor = _open_exact_single_descriptor(
                destination,
                raw,
                label="durable write-once destination",
                stage=False,
                durable=True,
            )
            os.close(destination_descriptor)
        os.fsync(publication_descriptor)
        _fsync_directory(destination.parent)
        if publication_kind not in {"ANONYMOUS", "CLONE"}:
            raise RootedPathIOError("unexpected POSIX publication primitive")

        # POSIX has no portable unlink-by-open-file-description primitive.
        # Even after an inode comparison, pathname unlink could remove a swap
        # that lands between the comparison and syscall.  Preserve the stage
        # as explicit recovery debt instead of deleting by name.
        if lexists(stage):
            stage_row = lstat(stage)
            if source_row is None or not _same_inode(source_row, stage_row):
                observed = read_bytes(
                    stage,
                    label="durable write-once swapped staging bytes",
                    require_single_link=True,
                )
                raise DurableWriteOnceStageError(
                    stage=stage,
                    destination=destination,
                    expected=raw,
                    observed=observed,
                )
            raise DurableWriteOnceDebtError(
                stage=stage,
                destination=destination,
                expected=raw,
                observed=raw,
                cleanup_state="EXACT_STAGE_RETIREMENT_REQUIRES_RECOVERY",
                detail=(
                    "descriptor-published destination is exact, but POSIX "
                    "cannot retire its deterministic stage object-bound"
                ),
            )
    except BaseException:
        # As on Windows, a successfully published descriptor is byte-exact.
        # Leave it for deterministic exact-file resume on a later retry.
        raise
    finally:
        if publication_descriptor != source_descriptor:
            os.close(publication_descriptor)
        os.close(source_descriptor)


def _publish_validated_write_once_stage(
    stage: Path,
    destination: Path,
    raw: bytes,
) -> None:
    try:
        if os.name == "nt":
            _windows_publish_locked_stage(stage, destination, raw)
        else:
            _posix_publish_open_stage(stage, destination, raw)
    except FileExistsError:
        # A concurrent publisher may win the no-replace boundary.  Its final
        # file is acceptable only after single-link, byte-exact durability is
        # re-established; the deterministic local stage is then retired.
        if not _write_once_existing_is_exact(
            destination,
            raw,
            label="durable write-once destination",
            durable=True,
        ):
            raise
        _retire_exact_write_once_stage(stage, destination, raw)
        return

    if not _write_once_existing_is_exact(
        destination,
        raw,
        label="durable write-once destination",
        durable=True,
    ):
        raise RootedPathIOError(
            "durable write-once publication produced no destination"
        )


def durable_write_once_bytes(
    destination: str | os.PathLike[str],
    raw: bytes,
) -> None:
    """Durably publish one byte-exact absent/exact-postimage CAS artifact.

    The authoritative destination is never written in place.  Windows exact
    resume obtains write access only so ``FlushFileBuffers`` can establish the
    data barrier while its share mode excludes mutators.  New bytes first
    enter an exclusively-created, content-addressed same-directory stage,
    whose file and directory entry are made durable before atomic no-replace
    publication.  An exact final postimage is an idempotent resume.  An exact
    stage resumes publication; a mismatched stage is explicit recovery debt
    and is never overwritten.
    """

    if not isinstance(raw, bytes):
        raise TypeError("durable write-once payload must be bytes")
    destination_path = absolute_path(destination)
    checked_directory(
        destination_path.parent,
        label="durable write-once parent",
    )
    stage = _write_once_stage_path(destination_path, raw)

    if _write_once_existing_is_exact(
        destination_path,
        raw,
        label="durable write-once destination",
        durable=True,
    ):
        _retire_exact_write_once_stage(stage, destination_path, raw)
        return

    if lexists(stage):
        exact_stage = _write_once_existing_is_exact(
            stage,
            raw,
            label="durable write-once staging bytes",
            stage=True,
            durable=True,
            destination=destination_path,
        )
        if not exact_stage:
            raise RootedPathIOError(
                "durable write-once staging bytes are unavailable"
            )
        _publish_validated_write_once_stage(stage, destination_path, raw)
        return

    if os.name != "nt" and sys.platform.startswith("linux"):
        try:
            _linux_publish_anonymous_bytes(stage, destination_path, raw)
        except FileExistsError:
            if not _write_once_existing_is_exact(
                destination_path,
                raw,
                label="durable write-once destination",
                durable=True,
            ):
                raise
        return
    if os.name != "nt" and sys.platform == "darwin":
        raise DurableWriteOnceDebtError(
            stage=stage,
            destination=destination_path,
            expected=raw,
            observed=None,
            cleanup_state="DARWIN_IMMUTABLE_SNAPSHOT_UNAVAILABLE",
            detail=(
                "Darwin durable publication requires an immutable anonymous "
                "snapshot and therefore fails closed"
            ),
        )

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= int(getattr(os, "O_BINARY", 0) or 0)
    flags |= int(getattr(os, "O_NOFOLLOW", 0) or 0)
    try:
        descriptor = os.open(native_path(stage), flags, 0o600)
    except FileExistsError as exc:
        # A concurrent stage creator may still be streaming bytes.  Do not
        # inspect or retire its name mid-write; a later serialized retry will
        # validate the deterministic stage as exact or explicit debt.
        raise RootedPathIOError(
            "durable write-once staging name appeared concurrently"
        ) from exc
    opened: os.stat_result | None = None
    try:
        opened = os.fstat(descriptor)
        exact_existing_name(stage)
        named = lstat(stage)
        if (
            not stat.S_ISREG(opened.st_mode)
            or _is_reparse_row(opened)
            or int(getattr(opened, "st_nlink", 1) or 1) != 1
            or not _same_inode(opened, named)
            or not stat.S_ISREG(named.st_mode)
            or _is_reparse_row(named)
            or int(getattr(named, "st_nlink", 1) or 1) != 1
        ):
            raise RootedPathIOError(
                "durable write-once stage is not a stable single-link file"
            )
        view = memoryview(raw)
        offset = 0
        while offset < len(view):
            written = os.write(descriptor, view[offset:])
            if written <= 0 or written > len(view) - offset:
                raise OSError(errno.EIO, "durable write-once short write")
            offset += written
        os.fsync(descriptor)
    except BaseException as exc:
        try:
            os.close(descriptor)
        except OSError:
            pass
        # A pathname unlink after closing the creating descriptor can race a
        # replacement and delete foreign data.  Preserve the deterministic
        # name as explicit recovery debt; a later resume can validate it, but
        # this failure path never removes whatever currently occupies it.
        raise DurableWriteOnceDebtError(
            stage=stage,
            destination=destination_path,
            expected=raw,
            observed=_best_effort_observed_bytes(stage),
            cleanup_state="PARTIAL_STAGE_PRESERVED",
            detail=f"durable write-once stage creation failed: {exc}",
        ) from exc
    else:
        os.close(descriptor)

    # Persist the recoverable completed stage before publication.  A crash
    # after this point leaves exact bytes under the deterministic stage name.
    _fsync_directory(stage.parent)
    if not _write_once_existing_is_exact(
        stage,
        raw,
        label="durable write-once staging bytes",
        stage=True,
        durable=True,
        destination=destination_path,
    ):
        raise RootedPathIOError(
            "durable write-once completed stage disappeared"
        )
    _publish_validated_write_once_stage(stage, destination_path, raw)


def safe_descendant(
    root: str | os.PathLike[str],
    relative: str,
    *,
    allow_missing: bool,
    label: str = "rooted descendant",
    verify_root_ancestors: bool = True,
    verify_root_exact_name: bool = True,
) -> Path:
    """Walk one canonical relative path beneath a checked lexical root."""

    if (
        not isinstance(relative, str)
        or not relative
        or relative != relative.strip()
        or "\x00" in relative
    ):
        raise RootedPathIOError(f"{label} path is malformed")
    text = relative.replace("\\", "/")
    parts = text.split("/")
    candidate_relative = Path(text)
    if (
        candidate_relative.is_absolute()
        or text.startswith("/")
        or any(part in {"", ".", ".."} for part in parts)
        or any(":" in part for part in parts)
    ):
        raise RootedPathIOError(f"{label} path is not a safe relative path")

    checked_root = checked_directory(
        root,
        label=f"{label} root",
        verify_ancestors=verify_root_ancestors,
        verify_exact_name=verify_root_exact_name,
    )
    current = checked_root
    missing = False
    for part in parts:
        candidate = current / part
        if not missing and lexists(candidate):
            exact_existing_name(candidate)
            row = lstat(candidate)
            if stat.S_ISLNK(row.st_mode) or _is_reparse_row(row):
                raise RootedPathIOError(
                    f"{label} contains a symlink/reparse component: "
                    f"{candidate}"
                )
        else:
            if not allow_missing:
                raise RootedPathIOError(
                    f"{label} is missing: {candidate}"
                )
            missing = True
        current = candidate

    root_text = os.path.normcase(os.fspath(checked_root))
    current_text = os.path.normcase(
        os.fspath(absolute_path(current))
    )
    try:
        common = os.path.normcase(
            os.path.commonpath((root_text, current_text))
        )
    except ValueError as exc:
        raise RootedPathIOError(
            f"{label} escapes its root"
        ) from exc
    if common != root_text:
        raise RootedPathIOError(f"{label} escapes its root")
    return current


def unlink(path: str | os.PathLike[str]) -> None:
    os.unlink(native_path(path))


def mkdir(path: str | os.PathLike[str], mode: int = 0o777) -> None:
    os.mkdir(native_path(path), mode)


def rmdir(path: str | os.PathLike[str]) -> None:
    os.rmdir(native_path(path))


def replace(
    source: str | os.PathLike[str],
    destination: str | os.PathLike[str],
) -> None:
    os.replace(native_path(source), native_path(destination))


__all__ = [
    "DurableWriteOnceDebtError",
    "DurableWriteOnceStageError",
    "RootedPathIOError",
    "absolute_path",
    "checked_directory",
    "checked_file",
    "durable_publish_new",
    "durable_replace",
    "durable_unlink",
    "durable_write_once_bytes",
    "ensure_directory",
    "exact_existing_name",
    "exclusive_temp_file",
    "is_dir",
    "is_file",
    "is_reparse",
    "is_symlink",
    "lexists",
    "lstat",
    "mkdir",
    "native_path",
    "read_bytes",
    "replace",
    "rmdir",
    "safe_descendant",
    "scandir",
    "unlink",
]
