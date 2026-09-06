"""Retained-handle authority for one attempt-owned directory.

The guard is acquired before untrusted work begins and keeps the exact parent
and root objects open, non-inheritable, and non-delete-shared for the complete
attempt.  Cleanup first durably records intent outside the owned tree, then
quarantines and removes only objects reached through retained handles.

The receipt is cleanup evidence only.  It can never mint model completion.
"""

from __future__ import annotations

import ctypes
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import threading
from types import MappingProxyType
from typing import Any, Mapping

from rooted_path_io import native_path as _native_path


GUARD_BINDING_SCHEMA = "plamen.owned_directory_guard.binding.v1"
GUARD_LEDGER_SCHEMA = "plamen.owned_directory_guard.ledger.v1"
GUARD_REVOCATION_SCHEMA = "plamen.owned_directory_guard.revocation.v1"
GUARD_RECONCILIATION_SCHEMA = (
    "plamen.owned_directory_guard.reconciliation.v1"
)

_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_SAFE_COMPONENT_RE = re.compile(r"[A-Za-z0-9._-]{1,128}")
_LEDGER_NAME_RE = re.compile(r"guard-([0-9a-f]{32})\.jsonl")
_STAGES = (
    "INTENT_DURABLE",
    "QUARANTINE_CONFIRMED",
    "TREE_EMPTY",
    "ROOT_DISPOSITION_SET",
    "VERIFIED_ABSENT",
)
_MAX_LEDGER_BYTES = 1024 * 1024
_MAX_LEDGER_RECORDS = 32
_MAX_RECONCILIATION_LEDGERS = 10_000
_MAX_RECONCILIATION_BYTES = 512 * 1024 * 1024
_MAX_TREE_DEPTH = 128
_MAX_TREE_ENTRIES = 100_000
_REPARSE_ATTRIBUTE = 0x400
_DIRECTORY_ATTRIBUTE = 0x10


class OwnedDirectoryGuardError(RuntimeError):
    """Retained directory authority could not prove safe cleanup."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(message)


class OwnedDirectoryGuardInjectedCrash(RuntimeError):
    """Fixture-only process-loss cut point after a durable stage."""


def _canonical_json(value: Mapping[str, Any]) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _digest(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def _strict_object(raw: bytes, *, label: str) -> dict[str, Any]:
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate key")
            result[key] = value
        return result

    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=unique,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                ValueError("non-finite number")
            ),
        )
    except (UnicodeDecodeError, ValueError, TypeError) as exc:
        raise OwnedDirectoryGuardError(
            "LEDGER_RECORD_INVALID",
            f"{label} is not strict JSON",
        ) from exc
    if not isinstance(value, dict):
        raise OwnedDirectoryGuardError(
            "LEDGER_RECORD_INVALID",
            f"{label} is not an object",
        )
    return value


def _validate_digest(value: object, *, label: str) -> str:
    if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
        raise OwnedDirectoryGuardError(
            "DIGEST_INVALID",
            f"{label} must be a SHA-256 digest",
        )
    return value


def _validate_component(value: object, *, label: str) -> str:
    if (
        not isinstance(value, str)
        or not _SAFE_COMPONENT_RE.fullmatch(value)
        or value in {".", ".."}
        or "/" in value
        or "\\" in value
        or "\x00" in value
    ):
        raise OwnedDirectoryGuardError(
            "COMPONENT_INVALID",
            f"{label} is not one safe path component",
        )
    return value


def _validate_owned_child_component(
    value: object,
    *,
    label: str,
) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 255
        or value in {".", ".."}
        or "/" in value
        or "\\" in value
        or "\x00" in value
    ):
        raise OwnedDirectoryGuardError(
            "CHILD_COMPONENT_INVALID",
            f"{label} is not one bounded path component",
        )
    return value


def _private_directory(path: Path) -> None:
    try:
        os.makedirs(_native_path(path), mode=0o700, exist_ok=True)
        row = os.lstat(_native_path(path))
    except OSError as exc:
        raise OwnedDirectoryGuardError(
            "LEDGER_DIRECTORY_UNAVAILABLE",
            "guard ledger directory is unavailable",
        ) from exc
    if (
        not stat.S_ISDIR(row.st_mode)
        or stat.S_ISLNK(row.st_mode)
        or bool(getattr(row, "st_file_attributes", 0) & 0x400)
    ):
        raise OwnedDirectoryGuardError(
            "LEDGER_DIRECTORY_ALIASED",
            "guard ledger directory is aliased",
        )
    if os.name != "nt":
        try:
            path.chmod(0o700)
        except OSError as exc:
            raise OwnedDirectoryGuardError(
                "LEDGER_DIRECTORY_SECURITY",
                "guard ledger directory is not private",
            ) from exc


def _flush_file(handle: int) -> None:
    try:
        os.fsync(handle)
    except OSError as exc:
        raise OwnedDirectoryGuardError(
            "LEDGER_FSYNC_FAILED",
            "guard ledger did not fsync",
        ) from exc


def _flush_directory(path: Path) -> None:
    if os.name == "nt":
        return
    descriptor = -1
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
        )
        os.fsync(descriptor)
    except OSError as exc:
        raise OwnedDirectoryGuardError(
            "LEDGER_DIRECTORY_FSYNC_FAILED",
            "guard ledger directory did not fsync",
        ) from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _ledger_records(path: Path) -> list[dict[str, Any]]:
    try:
        row = os.lstat(_native_path(path))
        if (
            not stat.S_ISREG(row.st_mode)
            or stat.S_ISLNK(row.st_mode)
            or int(getattr(row, "st_nlink", 1)) != 1
            or int(row.st_size) <= 0
            or int(row.st_size) > _MAX_LEDGER_BYTES
        ):
            raise OwnedDirectoryGuardError(
                "LEDGER_FILE_INVALID",
                "guard ledger is not one bounded regular file",
            )
        with open(_native_path(path), "rb") as ledger:
            raw = ledger.read(_MAX_LEDGER_BYTES + 1)
        if len(raw) > _MAX_LEDGER_BYTES:
            raise OwnedDirectoryGuardError(
                "LEDGER_FILE_INVALID", "guard ledger exceeded its byte bound",
            )
    except OwnedDirectoryGuardError:
        raise
    except OSError as exc:
        raise OwnedDirectoryGuardError(
            "LEDGER_UNAVAILABLE",
            "guard ledger is unavailable",
        ) from exc
    lines = raw.splitlines()
    if (
        not lines
        or len(lines) > _MAX_LEDGER_RECORDS
        or raw[-1:] != b"\n"
    ):
        raise OwnedDirectoryGuardError(
            "LEDGER_BOUNDS_INVALID",
            "guard ledger record framing is invalid",
        )
    records: list[dict[str, Any]] = []
    previous = "0" * 64
    for sequence, line in enumerate(lines):
        record = _strict_object(
            line,
            label=f"guard ledger record {sequence}",
        )
        expected_keys = {
            "schema",
            "guard_id",
            "sequence",
            "previous_record_sha256",
            "stage",
            "subject_binding_sha256",
            "platform",
            "parent_relative_path",
            "original_component",
            "quarantine_component",
            "parent_identity",
            "root_identity",
            "zero_population_evidence_sha256",
            "cleanup_mode",
            "completion_authority",
            "bound_root_link_absent",
            "recovered",
            "record_sha256",
        }
        if set(record) != expected_keys:
            raise OwnedDirectoryGuardError(
                "LEDGER_RECORD_FIELDS",
                "guard ledger record fields drifted",
            )
        digest = record.get("record_sha256")
        core = dict(record)
        core.pop("record_sha256", None)
        if (
            record.get("schema") != GUARD_LEDGER_SCHEMA
            or not isinstance(record.get("guard_id"), str)
            or re.fullmatch(r"[0-9a-f]{32}", record["guard_id"]) is None
            or record.get("sequence") != sequence
            or record.get("previous_record_sha256") != previous
            or not isinstance(digest, str)
            or digest != _digest(core)
        ):
            raise OwnedDirectoryGuardError(
                "LEDGER_RECORD_DIGEST",
                "guard ledger chain or digest is invalid",
            )
        if sequence >= len(_STAGES) or record.get("stage") != _STAGES[sequence]:
            raise OwnedDirectoryGuardError(
                "LEDGER_STAGE_INVALID",
                "guard ledger stage ordering is invalid",
            )
        _validate_digest(
            record.get("subject_binding_sha256"),
            label="subject binding",
        )
        _validate_digest(
            record.get("zero_population_evidence_sha256"),
            label="zero-population evidence",
        )
        _validate_component(
            record.get("original_component"),
            label="original component",
        )
        _validate_component(
            record.get("quarantine_component"),
            label="quarantine component",
        )
        if (
            record.get("platform")
            not in {"windows_ntfs_handle_v1", "posix_dirfd_v1"}
            or not isinstance(record.get("parent_relative_path"), str)
            or not record["parent_relative_path"]
            or "\x00" in record["parent_relative_path"]
            or not isinstance(record.get("parent_identity"), dict)
            or not isinstance(record.get("root_identity"), dict)
            or not isinstance(record.get("cleanup_mode"), str)
            or _SAFE_COMPONENT_RE.fullmatch(record["cleanup_mode"]) is None
            or record.get("recovered") not in {False, True}
        ):
            raise OwnedDirectoryGuardError(
                "LEDGER_RECORD_VALUES",
                "guard ledger record values are invalid",
            )
        if record.get("completion_authority") is not False:
            raise OwnedDirectoryGuardError(
                "LEDGER_COMPLETION_FORBIDDEN",
                "directory cleanup ledger cannot mint completion",
            )
        if record.get("bound_root_link_absent") is not (
            record.get("stage") == "VERIFIED_ABSENT"
        ):
            raise OwnedDirectoryGuardError(
                "LEDGER_ABSENCE_INVALID",
                "guard ledger absence claim drifted",
            )
        previous = digest
        records.append(record)
    return records


def replay_owned_directory_cleanup_ledger(
    ledger_path: str | Path,
    *,
    expected_subject_binding_sha256: str | None = None,
) -> dict[str, Any]:
    path = Path(ledger_path)
    records = _ledger_records(path)
    first = records[0]
    stable = {
        "guard_id",
        "subject_binding_sha256",
        "platform",
        "parent_relative_path",
        "original_component",
        "quarantine_component",
        "parent_identity",
        "root_identity",
        "zero_population_evidence_sha256",
        "cleanup_mode",
        "completion_authority",
    }
    for record in records[1:]:
        if any(record[key] != first[key] for key in stable):
            raise OwnedDirectoryGuardError(
                "LEDGER_STABLE_FIELDS_DRIFTED",
                "guard ledger stable fields drifted",
            )
    if (
        expected_subject_binding_sha256 is not None
        and first["subject_binding_sha256"]
        != _validate_digest(
            expected_subject_binding_sha256,
            label="expected subject binding",
        )
    ):
        raise OwnedDirectoryGuardError(
            "LEDGER_SUBJECT_MISMATCH",
            "guard ledger belongs to another subject",
        )
    return {
        "valid": True,
        "records": records,
        "terminal": records[-1]["stage"] == "VERIFIED_ABSENT",
        "head_sha256": records[-1]["record_sha256"],
    }


def _append_ledger_stage(
    path: Path,
    *,
    stable: Mapping[str, Any],
    stage: str,
    recovered: bool,
) -> dict[str, Any]:
    if stage not in _STAGES:
        raise OwnedDirectoryGuardError(
            "LEDGER_STAGE_INVALID",
            "guard ledger stage is invalid",
        )
    existed = os.path.lexists(_native_path(path))
    if existed:
        records = _ledger_records(path)
        sequence = len(records)
        previous = records[-1]["record_sha256"]
        if sequence >= len(_STAGES) or _STAGES[sequence] != stage:
            raise OwnedDirectoryGuardError(
                "LEDGER_STAGE_INVALID",
                "guard ledger transition is invalid",
            )
    else:
        if stage != "INTENT_DURABLE":
            raise OwnedDirectoryGuardError(
                "LEDGER_STAGE_INVALID",
                "guard ledger must start with durable intent",
            )
        sequence = 0
        previous = "0" * 64
    core = {
        "schema": GUARD_LEDGER_SCHEMA,
        "guard_id": stable["guard_id"],
        "sequence": sequence,
        "previous_record_sha256": previous,
        "stage": stage,
        "subject_binding_sha256": stable["subject_binding_sha256"],
        "platform": stable["platform"],
        "parent_relative_path": stable["parent_relative_path"],
        "original_component": stable["original_component"],
        "quarantine_component": stable["quarantine_component"],
        "parent_identity": stable["parent_identity"],
        "root_identity": stable["root_identity"],
        "zero_population_evidence_sha256": stable[
            "zero_population_evidence_sha256"
        ],
        "cleanup_mode": stable["cleanup_mode"],
        "completion_authority": False,
        "bound_root_link_absent": stage == "VERIFIED_ABSENT",
        "recovered": recovered,
    }
    record = {**core, "record_sha256": _digest(core)}
    flags = os.O_WRONLY | os.O_APPEND
    if not existed:
        flags |= os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = -1
    try:
        descriptor = os.open(_native_path(path), flags, 0o600)
        os.set_inheritable(descriptor, False)
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or int(getattr(opened, "st_nlink", 1)) != 1
        ):
            raise OwnedDirectoryGuardError(
                "LEDGER_FILE_INVALID",
                "guard ledger append target is not one regular file",
            )
        raw = _canonical_json(record) + b"\n"
        written = 0
        while written < len(raw):
            count = os.write(descriptor, raw[written:])
            if count <= 0:
                raise OSError("short ledger write")
            written += count
        _flush_file(descriptor)
    except OwnedDirectoryGuardError:
        raise
    except OSError as exc:
        raise OwnedDirectoryGuardError(
            "LEDGER_WRITE_FAILED",
            "guard ledger transition was not durable",
        ) from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    _flush_directory(path.parent)
    replay_owned_directory_cleanup_ledger(
        path,
        expected_subject_binding_sha256=str(
            stable["subject_binding_sha256"]
        ),
    )
    return record


def _identity_digest(identity: Mapping[str, Any]) -> str:
    return _digest(identity)


def _same_identity(
    left: Mapping[str, Any],
    right: Mapping[str, Any],
) -> bool:
    if left.get("kind") != right.get("kind"):
        return False
    if left.get("kind") == "WINDOWS_FILE_ID_128":
        return (
            left.get("volume_serial_number")
            == right.get("volume_serial_number")
            and left.get("file_id_128") == right.get("file_id_128")
        )
    if left.get("kind") == "POSIX_DEVICE_INODE":
        return (
            left.get("st_dev") == right.get("st_dev")
            and left.get("st_ino") == right.get("st_ino")
        )
    return False


def _relative_parent_path(parent: Path, ledger_directory: Path) -> str:
    try:
        raw = os.path.relpath(parent, ledger_directory)
    except ValueError as exc:
        raise OwnedDirectoryGuardError(
            "LEDGER_PARENT_UNREPRESENTABLE",
            "guard parent is on another volume than the cleanup ledger",
        ) from exc
    normalized = raw.replace("\\", "/")
    if not normalized or "\x00" in normalized:
        raise OwnedDirectoryGuardError(
            "LEDGER_PARENT_UNREPRESENTABLE",
            "guard parent relation is invalid",
        )
    return normalized


def _parent_from_ledger(
    ledger_path: Path,
    parent_relative_path: str,
) -> Path:
    if (
        not isinstance(parent_relative_path, str)
        or not parent_relative_path
        or "\x00" in parent_relative_path
    ):
        raise OwnedDirectoryGuardError(
            "LEDGER_PARENT_INVALID",
            "guard parent relation is invalid",
        )
    parts = parent_relative_path.split("/")
    if any(part == "" for part in parts):
        raise OwnedDirectoryGuardError(
            "LEDGER_PARENT_INVALID",
            "guard parent relation has an empty component",
        )
    return Path(os.path.abspath(ledger_path.parent.joinpath(*parts)))


if os.name == "nt":
    from ctypes import wintypes as _wintypes

    class _FILE_ID_128(ctypes.Structure):
        _fields_ = [("Identifier", ctypes.c_ubyte * 16)]


    class _FILE_ID_INFO(ctypes.Structure):
        _fields_ = [
            ("VolumeSerialNumber", ctypes.c_ulonglong),
            ("FileId", _FILE_ID_128),
        ]


    class _FILE_ATTRIBUTE_TAG_INFO(ctypes.Structure):
        _fields_ = [
            ("FileAttributes", ctypes.c_ulong),
            ("ReparseTag", ctypes.c_ulong),
        ]


    class _FILE_ID_EXTD_DIR_INFO(ctypes.Structure):
        _fields_ = [
            ("NextEntryOffset", ctypes.c_ulong),
            ("FileIndex", ctypes.c_ulong),
            ("CreationTime", ctypes.c_longlong),
            ("LastAccessTime", ctypes.c_longlong),
            ("LastWriteTime", ctypes.c_longlong),
            ("ChangeTime", ctypes.c_longlong),
            ("EndOfFile", ctypes.c_longlong),
            ("AllocationSize", ctypes.c_longlong),
            ("FileAttributes", ctypes.c_ulong),
            ("FileNameLength", ctypes.c_ulong),
            ("EaSize", ctypes.c_ulong),
            ("ReparsePointTag", ctypes.c_ulong),
            ("FileId", _FILE_ID_128),
            ("FileName", ctypes.c_wchar * 1),
        ]


    class _FILE_RENAME_UNION(ctypes.Union):
        _fields_ = [
            ("ReplaceIfExists", ctypes.c_ubyte),
            ("Flags", ctypes.c_ulong),
        ]


    class _FILE_RENAME_INFO(ctypes.Structure):
        _anonymous_ = ("Choice",)
        _fields_ = [
            ("Choice", _FILE_RENAME_UNION),
            ("RootDirectory", ctypes.c_void_p),
            ("FileNameLength", ctypes.c_ulong),
            ("FileName", ctypes.c_wchar * 1),
        ]


    class _FILE_DISPOSITION_INFO_EX(ctypes.Structure):
        _fields_ = [("Flags", ctypes.c_ulong)]


    class _UNICODE_STRING(ctypes.Structure):
        _fields_ = [
            ("Length", ctypes.c_ushort),
            ("MaximumLength", ctypes.c_ushort),
            ("Buffer", ctypes.c_void_p),
        ]


    class _OBJECT_ATTRIBUTES(ctypes.Structure):
        _fields_ = [
            ("Length", ctypes.c_ulong),
            ("RootDirectory", ctypes.c_void_p),
            ("ObjectName", ctypes.POINTER(_UNICODE_STRING)),
            ("Attributes", ctypes.c_ulong),
            ("SecurityDescriptor", ctypes.c_void_p),
            ("SecurityQualityOfService", ctypes.c_void_p),
        ]


    class _IO_STATUS_UNION(ctypes.Union):
        _fields_ = [
            ("Status", ctypes.c_long),
            ("Pointer", ctypes.c_void_p),
        ]


    class _IO_STATUS_BLOCK(ctypes.Structure):
        _anonymous_ = ("Result",)
        _fields_ = [
            ("Result", _IO_STATUS_UNION),
            ("Information", ctypes.c_size_t),
        ]


def windows_abi_layout() -> dict[str, int]:
    """Return the exact native structure layout used by the Windows backend."""

    if os.name != "nt":
        raise OwnedDirectoryGuardError(
            "WINDOWS_ABI_UNAVAILABLE",
            "Windows directory ABI is unavailable on this platform",
        )
    return {
        "FILE_ID_INFO.size": ctypes.sizeof(_FILE_ID_INFO),
        "FILE_ID_EXTD_DIR_INFO.size": ctypes.sizeof(
            _FILE_ID_EXTD_DIR_INFO
        ),
        "FILE_ID_EXTD_DIR_INFO.FileName.offset": (
            _FILE_ID_EXTD_DIR_INFO.FileName.offset
        ),
        "FILE_RENAME_INFO.size": ctypes.sizeof(_FILE_RENAME_INFO),
        "FILE_RENAME_INFO.RootDirectory.offset": (
            _FILE_RENAME_INFO.RootDirectory.offset
        ),
        "FILE_RENAME_INFO.FileNameLength.offset": (
            _FILE_RENAME_INFO.FileNameLength.offset
        ),
        "FILE_RENAME_INFO.FileName.offset": (
            _FILE_RENAME_INFO.FileName.offset
        ),
        "UNICODE_STRING.size": ctypes.sizeof(_UNICODE_STRING),
        "OBJECT_ATTRIBUTES.size": ctypes.sizeof(_OBJECT_ATTRIBUTES),
    }


if os.name == "nt":
    _KERNEL32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _NTDLL = ctypes.WinDLL("ntdll")
    _CreateFileW = _KERNEL32.CreateFileW
    _CreateFileW.argtypes = [
        _wintypes.LPCWSTR,
        _wintypes.DWORD,
        _wintypes.DWORD,
        ctypes.c_void_p,
        _wintypes.DWORD,
        _wintypes.DWORD,
        _wintypes.HANDLE,
    ]
    _CreateFileW.restype = _wintypes.HANDLE
    _CloseHandle = _KERNEL32.CloseHandle
    _CloseHandle.argtypes = [_wintypes.HANDLE]
    _CloseHandle.restype = _wintypes.BOOL
    _SetHandleInformation = _KERNEL32.SetHandleInformation
    _SetHandleInformation.argtypes = [
        _wintypes.HANDLE,
        _wintypes.DWORD,
        _wintypes.DWORD,
    ]
    _SetHandleInformation.restype = _wintypes.BOOL
    _GetFileInformationByHandleEx = (
        _KERNEL32.GetFileInformationByHandleEx
    )
    _GetFileInformationByHandleEx.argtypes = [
        _wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        _wintypes.DWORD,
    ]
    _GetFileInformationByHandleEx.restype = _wintypes.BOOL
    _SetFileInformationByHandle = (
        _KERNEL32.SetFileInformationByHandle
    )
    _SetFileInformationByHandle.argtypes = [
        _wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        _wintypes.DWORD,
    ]
    _SetFileInformationByHandle.restype = _wintypes.BOOL
    _GetVolumePathNameW = _KERNEL32.GetVolumePathNameW
    _GetVolumePathNameW.argtypes = [
        _wintypes.LPCWSTR,
        _wintypes.LPWSTR,
        _wintypes.DWORD,
    ]
    _GetVolumePathNameW.restype = _wintypes.BOOL
    _GetVolumeInformationW = _KERNEL32.GetVolumeInformationW
    _GetVolumeInformationW.argtypes = [
        _wintypes.LPCWSTR,
        _wintypes.LPWSTR,
        _wintypes.DWORD,
        ctypes.POINTER(_wintypes.DWORD),
        ctypes.POINTER(_wintypes.DWORD),
        ctypes.POINTER(_wintypes.DWORD),
        _wintypes.LPWSTR,
        _wintypes.DWORD,
    ]
    _GetVolumeInformationW.restype = _wintypes.BOOL
    _GetDriveTypeW = _KERNEL32.GetDriveTypeW
    _GetDriveTypeW.argtypes = [_wintypes.LPCWSTR]
    _GetDriveTypeW.restype = _wintypes.UINT
    _NtOpenFile = _NTDLL.NtOpenFile
    _NtOpenFile.argtypes = [
        ctypes.POINTER(_wintypes.HANDLE),
        _wintypes.DWORD,
        ctypes.POINTER(_OBJECT_ATTRIBUTES),
        ctypes.POINTER(_IO_STATUS_BLOCK),
        _wintypes.DWORD,
        _wintypes.DWORD,
    ]
    _NtOpenFile.restype = ctypes.c_long
    _NtSetInformationFile = _NTDLL.NtSetInformationFile
    _NtSetInformationFile.argtypes = [
        _wintypes.HANDLE,
        ctypes.POINTER(_IO_STATUS_BLOCK),
        ctypes.c_void_p,
        _wintypes.DWORD,
        ctypes.c_int,
    ]
    _NtSetInformationFile.restype = ctypes.c_long

    _INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
    _DELETE = 0x00010000
    _FILE_LIST_DIRECTORY = 0x00000001
    _FILE_ADD_SUBDIRECTORY = 0x00000004
    _FILE_TRAVERSE = 0x00000020
    _FILE_READ_ATTRIBUTES = 0x00000080
    _FILE_WRITE_ATTRIBUTES = 0x00000100
    _SYNCHRONIZE = 0x00100000
    _FILE_SHARE_READ = 0x00000001
    _FILE_SHARE_WRITE = 0x00000002
    _OPEN_EXISTING = 3
    _FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
    _FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
    _HANDLE_FLAG_INHERIT = 0x00000001
    _FILE_ID_INFO_CLASS = 18
    _FILE_ATTRIBUTE_TAG_INFO_CLASS = 9
    _FILE_ID_EXTD_DIRECTORY_INFO_CLASS = 19
    _FILE_ID_EXTD_DIRECTORY_RESTART_INFO_CLASS = 20
    _FILE_DISPOSITION_INFO_EX_CLASS = 21
    _FILE_RENAME_INFO_EX_CLASS = 22
    _NATIVE_FILE_RENAME_INFORMATION_EX_CLASS = 65
    _FILE_DIRECTORY_FILE = 0x00000001
    _FILE_NON_DIRECTORY_FILE = 0x00000040
    _FILE_SYNCHRONOUS_IO_NONALERT = 0x00000020
    _FILE_OPEN_REPARSE_POINT = 0x00200000
    _FILE_OPEN_FOR_BACKUP_INTENT = 0x00004000
    _OBJ_CASE_INSENSITIVE = 0x00000040
    _FILE_DISPOSITION_DELETE = 0x00000001
    _FILE_DISPOSITION_POSIX_SEMANTICS = 0x00000002
    _FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE = 0x00000010
    _ERROR_NO_MORE_FILES = 18
    _STATUS_NOT_FOUND = {
        0xC000000F,
        0xC0000034,
        0xC000003A,
    }


def _windows_error(code: str, message: str) -> OwnedDirectoryGuardError:
    error = ctypes.get_last_error()
    return OwnedDirectoryGuardError(
        code,
        f"{message} (winerror={error})",
    )


def _windows_close(handle: int | None) -> None:
    if os.name != "nt" or handle in {None, 0, _INVALID_HANDLE_VALUE}:
        return
    _CloseHandle(_wintypes.HANDLE(handle))


def _windows_require_supported_volume(path: Path) -> str:
    volume = ctypes.create_unicode_buffer(32768)
    if not _GetVolumePathNameW(_native_path(path), volume, len(volume)):
        raise _windows_error(
            "WINDOWS_VOLUME_UNAVAILABLE",
            "owned directory volume could not be identified",
        )
    filesystem = ctypes.create_unicode_buffer(256)
    serial = _wintypes.DWORD()
    maximum_component = _wintypes.DWORD()
    flags = _wintypes.DWORD()
    if not _GetVolumeInformationW(
        volume.value,
        None,
        0,
        ctypes.byref(serial),
        ctypes.byref(maximum_component),
        ctypes.byref(flags),
        filesystem,
        len(filesystem),
    ):
        raise _windows_error(
            "WINDOWS_VOLUME_UNAVAILABLE",
            "owned directory filesystem could not be identified",
        )
    if filesystem.value.casefold() not in {"ntfs", "refs"}:
        raise OwnedDirectoryGuardError(
            "WINDOWS_VOLUME_UNSUPPORTED",
            "retained cleanup requires a local NTFS or ReFS volume",
        )
    if int(_GetDriveTypeW(volume.value)) != 3:
        raise OwnedDirectoryGuardError(
            "WINDOWS_VOLUME_UNSUPPORTED",
            "retained cleanup requires a fixed local volume",
        )
    return filesystem.value.upper()


def _windows_open_absolute_directory(path: Path) -> int:
    access = (
        _DELETE
        | _FILE_LIST_DIRECTORY
        | _FILE_ADD_SUBDIRECTORY
        | _FILE_TRAVERSE
        | _FILE_READ_ATTRIBUTES
        | _FILE_WRITE_ATTRIBUTES
        | _SYNCHRONIZE
    )
    handle = _CreateFileW(
        _native_path(path),
        access,
        _FILE_SHARE_READ | _FILE_SHARE_WRITE,
        None,
        _OPEN_EXISTING,
        _FILE_FLAG_BACKUP_SEMANTICS
        | _FILE_FLAG_OPEN_REPARSE_POINT,
        None,
    )
    value = ctypes.cast(handle, ctypes.c_void_p).value
    if value in {None, _INVALID_HANDLE_VALUE}:
        raise _windows_error(
            "WINDOWS_HANDLE_OPEN_FAILED",
            "owned directory handle could not be retained",
        )
    if not _SetHandleInformation(
        handle,
        _HANDLE_FLAG_INHERIT,
        0,
    ):
        _windows_close(value)
        raise _windows_error(
            "WINDOWS_HANDLE_INHERITANCE",
            "owned directory handle could not be made non-inheritable",
        )
    return int(value)


def _windows_handle_identity(handle: int) -> dict[str, Any]:
    file_id = _FILE_ID_INFO()
    tag = _FILE_ATTRIBUTE_TAG_INFO()
    if not _GetFileInformationByHandleEx(
        _wintypes.HANDLE(handle),
        _FILE_ID_INFO_CLASS,
        ctypes.byref(file_id),
        ctypes.sizeof(file_id),
    ):
        raise _windows_error(
            "WINDOWS_IDENTITY_UNAVAILABLE",
            "owned directory file identity is unavailable",
        )
    if not _GetFileInformationByHandleEx(
        _wintypes.HANDLE(handle),
        _FILE_ATTRIBUTE_TAG_INFO_CLASS,
        ctypes.byref(tag),
        ctypes.sizeof(tag),
    ):
        raise _windows_error(
            "WINDOWS_ATTRIBUTES_UNAVAILABLE",
            "owned directory attributes are unavailable",
        )
    return {
        "kind": "WINDOWS_FILE_ID_128",
        "volume_serial_number": int(file_id.VolumeSerialNumber),
        "file_id_128": bytes(file_id.FileId.Identifier).hex(),
        "file_attributes": int(tag.FileAttributes),
        "reparse_tag": int(tag.ReparseTag),
    }


def _windows_open_relative(
    parent_handle: int,
    component: str,
    *,
    is_directory: bool,
    deletion_access: bool,
) -> int | None:
    _validate_owned_child_component(
        component,
        label="relative object component",
    )
    raw_name = ctypes.create_unicode_buffer(component)
    byte_length = len(component.encode("utf-16-le"))
    name = _UNICODE_STRING(
        byte_length,
        byte_length,
        ctypes.cast(raw_name, ctypes.c_void_p),
    )
    attributes = _OBJECT_ATTRIBUTES(
        ctypes.sizeof(_OBJECT_ATTRIBUTES),
        ctypes.c_void_p(parent_handle),
        ctypes.pointer(name),
        _OBJ_CASE_INSENSITIVE,
        None,
        None,
    )
    result = _wintypes.HANDLE()
    io_status = _IO_STATUS_BLOCK()
    access = _FILE_READ_ATTRIBUTES | _SYNCHRONIZE
    if deletion_access:
        access |= _DELETE
    if is_directory:
        access |= _FILE_LIST_DIRECTORY
    options = (
        _FILE_SYNCHRONOUS_IO_NONALERT
        | _FILE_OPEN_REPARSE_POINT
        | _FILE_OPEN_FOR_BACKUP_INTENT
        | (
            _FILE_DIRECTORY_FILE
            if is_directory
            else _FILE_NON_DIRECTORY_FILE
        )
    )
    status = int(
        _NtOpenFile(
            ctypes.byref(result),
            access,
            ctypes.byref(attributes),
            ctypes.byref(io_status),
            _FILE_SHARE_READ | _FILE_SHARE_WRITE,
            options,
        )
    )
    status_unsigned = status & 0xFFFFFFFF
    if status < 0:
        if status_unsigned in _STATUS_NOT_FOUND:
            return None
        raise OwnedDirectoryGuardError(
            "WINDOWS_RELATIVE_OPEN_FAILED",
            (
                "owned child could not be opened relative to its retained "
                f"parent (ntstatus=0x{status_unsigned:08x})"
            ),
        )
    value = ctypes.cast(result, ctypes.c_void_p).value
    if value in {None, _INVALID_HANDLE_VALUE}:
        raise OwnedDirectoryGuardError(
            "WINDOWS_RELATIVE_OPEN_FAILED",
            "owned child returned an invalid native handle",
        )
    if not _SetHandleInformation(
        result,
        _HANDLE_FLAG_INHERIT,
        0,
    ):
        _windows_close(int(value))
        raise _windows_error(
            "WINDOWS_HANDLE_INHERITANCE",
            "owned child handle could not be made non-inheritable",
        )
    return int(value)


def _windows_relative_identity(
    parent_handle: int,
    component: str,
    *,
    is_directory: bool,
) -> dict[str, Any] | None:
    del is_directory
    _validate_owned_child_component(
        component,
        label="relative object component",
    )
    folded = component.casefold()
    matches = [
        entry
        for entry in _windows_directory_entries(parent_handle)
        if str(entry["name"]).casefold() == folded
    ]
    if not matches:
        return None
    if len(matches) != 1 or matches[0]["name"] != component:
        raise OwnedDirectoryGuardError(
            "WINDOWS_NAME_AMBIGUOUS",
            "owned child has ambiguous case ownership",
        )
    parent_identity = _windows_handle_identity(parent_handle)
    entry = matches[0]
    return {
        "kind": "WINDOWS_FILE_ID_128",
        "volume_serial_number": parent_identity[
            "volume_serial_number"
        ],
        "file_id_128": entry["file_id_128"],
        "file_attributes": entry["file_attributes"],
        "reparse_tag": entry["reparse_tag"],
    }


def _windows_rename_handle(
    handle: int,
    parent_handle: int,
    component: str,
) -> None:
    _validate_component(component, label="quarantine component")
    name_raw = component.encode("utf-16-le")
    # Windows validates the variable-length structure against its aligned
    # native sizeof, not merely the byte offset of FileName.
    size = ctypes.sizeof(_FILE_RENAME_INFO) + len(name_raw)
    buffer = ctypes.create_string_buffer(size)
    rename = _FILE_RENAME_INFO.from_buffer(buffer)
    rename.Flags = 0
    rename.RootDirectory = ctypes.c_void_p(parent_handle)
    rename.FileNameLength = len(name_raw)
    ctypes.memmove(
        ctypes.addressof(buffer) + _FILE_RENAME_INFO.FileName.offset,
        name_raw,
        len(name_raw),
    )
    io_status = _IO_STATUS_BLOCK()
    status = int(
        _NtSetInformationFile(
            _wintypes.HANDLE(handle),
            ctypes.byref(io_status),
            buffer,
            size,
            _NATIVE_FILE_RENAME_INFORMATION_EX_CLASS,
        )
    )
    if status < 0:
        raise OwnedDirectoryGuardError(
            "QUARANTINE_RENAME_FAILED",
            (
                "owned directory could not be quarantined atomically "
                f"(ntstatus=0x{status & 0xFFFFFFFF:08x})"
            ),
        )


def _windows_set_disposition(handle: int) -> None:
    disposition = _FILE_DISPOSITION_INFO_EX(
        _FILE_DISPOSITION_DELETE
        | _FILE_DISPOSITION_POSIX_SEMANTICS
        | _FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE
    )
    if not _SetFileInformationByHandle(
        _wintypes.HANDLE(handle),
        _FILE_DISPOSITION_INFO_EX_CLASS,
        ctypes.byref(disposition),
        ctypes.sizeof(disposition),
    ):
        raise _windows_error(
            "HANDLE_DISPOSITION_FAILED",
            "owned object could not be deleted by retained handle",
        )


def _windows_parse_directory_buffer(
    buffer: ctypes.Array[Any],
    capacity: int,
) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    offset = 0
    while True:
        if offset + _FILE_ID_EXTD_DIR_INFO.FileName.offset > capacity:
            raise OwnedDirectoryGuardError(
                "WINDOWS_ENUMERATION_INVALID",
                "owned directory enumeration record is truncated",
            )
        entry = _FILE_ID_EXTD_DIR_INFO.from_buffer(buffer, offset)
        name_length = int(entry.FileNameLength)
        name_start = offset + _FILE_ID_EXTD_DIR_INFO.FileName.offset
        name_end = name_start + name_length
        if (
            name_length <= 0
            or name_length % 2 != 0
            or name_end > capacity
        ):
            raise OwnedDirectoryGuardError(
                "WINDOWS_ENUMERATION_INVALID",
                "owned directory entry name is malformed",
            )
        try:
            name = bytes(buffer[name_start:name_end]).decode(
                "utf-16-le",
                errors="strict",
            )
        except UnicodeDecodeError as exc:
            raise OwnedDirectoryGuardError(
                "WINDOWS_ENUMERATION_INVALID",
                "owned directory entry name is not valid UTF-16",
            ) from exc
        next_offset = int(entry.NextEntryOffset)
        if name not in {".", ".."}:
            _validate_owned_child_component(
                name,
                label="enumerated child component",
            )
            entries.append({
                "name": name,
                "file_attributes": int(entry.FileAttributes),
                "reparse_tag": int(entry.ReparsePointTag),
                "file_id_128": bytes(entry.FileId.Identifier).hex(),
            })
        if next_offset == 0:
            return entries
        if (
            next_offset < _FILE_ID_EXTD_DIR_INFO.FileName.offset
            or offset + next_offset <= offset
            or offset + next_offset >= capacity
        ):
            raise OwnedDirectoryGuardError(
                "WINDOWS_ENUMERATION_INVALID",
                "owned directory enumeration offsets are malformed",
            )
        offset += next_offset


def _windows_directory_entries(
    directory_handle: int,
) -> list[dict[str, Any]]:
    capacity = 64 * 1024
    entries: list[dict[str, Any]] = []
    info_class = _FILE_ID_EXTD_DIRECTORY_RESTART_INFO_CLASS
    while True:
        buffer = ctypes.create_string_buffer(capacity)
        if not _GetFileInformationByHandleEx(
            _wintypes.HANDLE(directory_handle),
            info_class,
            buffer,
            capacity,
        ):
            error = ctypes.get_last_error()
            if error == _ERROR_NO_MORE_FILES:
                return entries
            raise _windows_error(
                "WINDOWS_ENUMERATION_FAILED",
                "owned directory enumeration failed",
            )
        entries.extend(
            _windows_parse_directory_buffer(buffer, capacity)
        )
        if len(entries) > _MAX_TREE_ENTRIES:
            raise OwnedDirectoryGuardError(
                "TREE_ENTRY_BOUND_EXCEEDED",
                "owned directory exceeded the enumeration bound",
            )
        info_class = _FILE_ID_EXTD_DIRECTORY_INFO_CLASS


def _windows_first_directory_entry(
    directory_handle: int,
) -> dict[str, Any] | None:
    capacity = 64 * 1024
    buffer = ctypes.create_string_buffer(capacity)
    if not _GetFileInformationByHandleEx(
        _wintypes.HANDLE(directory_handle),
        _FILE_ID_EXTD_DIRECTORY_RESTART_INFO_CLASS,
        buffer,
        capacity,
    ):
        error = ctypes.get_last_error()
        if error == _ERROR_NO_MORE_FILES:
            return None
        raise _windows_error(
            "WINDOWS_ENUMERATION_FAILED",
            "owned directory enumeration failed",
        )
    entries = _windows_parse_directory_buffer(buffer, capacity)
    return entries[0] if entries else None


def _windows_empty_directory(
    directory_handle: int,
    *,
    root_volume_serial: int,
    depth: int,
    budget: list[int],
) -> None:
    if depth > _MAX_TREE_DEPTH:
        raise OwnedDirectoryGuardError(
            "TREE_DEPTH_EXCEEDED",
            "owned directory tree exceeded the cleanup depth bound",
        )
    while True:
        entry = _windows_first_directory_entry(directory_handle)
        if entry is None:
            return
        budget[0] += 1
        if budget[0] > _MAX_TREE_ENTRIES:
            raise OwnedDirectoryGuardError(
                "TREE_ENTRY_BOUND_EXCEEDED",
                "owned directory tree exceeded the cleanup entry bound",
            )
        attributes = int(entry["file_attributes"])
        is_directory = bool(attributes & _DIRECTORY_ATTRIBUTE)
        is_reparse = bool(attributes & _REPARSE_ATTRIBUTE)
        child = _windows_open_relative(
            directory_handle,
            str(entry["name"]),
            is_directory=is_directory,
            deletion_access=True,
        )
        if child is None:
            raise OwnedDirectoryGuardError(
                "CHILD_IDENTITY_AMBIGUOUS",
                "enumerated owned child disappeared before handle binding",
            )
        try:
            identity = _windows_handle_identity(child)
            if (
                identity["volume_serial_number"]
                != root_volume_serial
                or identity["file_id_128"] != entry["file_id_128"]
                or bool(
                    int(identity["file_attributes"])
                    & _DIRECTORY_ATTRIBUTE
                )
                != is_directory
                or bool(
                    int(identity["file_attributes"])
                    & _REPARSE_ATTRIBUTE
                )
                != is_reparse
            ):
                raise OwnedDirectoryGuardError(
                    "CHILD_IDENTITY_DRIFTED",
                    "owned child identity drifted during cleanup",
                )
            if is_directory and not is_reparse:
                _windows_empty_directory(
                    child,
                    root_volume_serial=root_volume_serial,
                    depth=depth + 1,
                    budget=budget,
                )
            _windows_set_disposition(child)
        finally:
            _windows_close(child)


def _posix_identity_from_stat(row: os.stat_result) -> dict[str, Any]:
    return {
        "kind": "POSIX_DEVICE_INODE",
        "st_dev": int(row.st_dev),
        "st_ino": int(row.st_ino),
        "file_type": int(stat.S_IFMT(row.st_mode)),
    }


def _require_posix_dirfd_contract() -> None:
    required_dirfd = {
        os.open,
        os.stat,
        os.unlink,
        os.rmdir,
        os.rename,
    }
    if (
        not hasattr(os, "O_DIRECTORY")
        or not hasattr(os, "O_NOFOLLOW")
        or not required_dirfd.issubset(os.supports_dir_fd)
        or os.stat not in os.supports_follow_symlinks
        or os.listdir not in os.supports_fd
    ):
        raise OwnedDirectoryGuardError(
            "POSIX_DIRFD_UNSUPPORTED",
            "platform lacks the required no-follow dirfd cleanup contract",
        )


def _posix_open_directory(
    component_or_path: str | Path,
    *,
    parent_fd: int | None = None,
) -> int:
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    try:
        if parent_fd is None:
            descriptor = os.open(component_or_path, flags)
        else:
            descriptor = os.open(
                component_or_path,
                flags,
                dir_fd=parent_fd,
            )
        os.set_inheritable(descriptor, False)
        return descriptor
    except OSError as exc:
        raise OwnedDirectoryGuardError(
            "POSIX_DIRECTORY_OPEN_FAILED",
            "owned directory could not be retained without following links",
        ) from exc


def _posix_relative_lstat(
    parent_fd: int,
    component: str,
) -> os.stat_result | None:
    _validate_owned_child_component(
        component,
        label="relative object component",
    )
    try:
        return os.stat(
            component,
            dir_fd=parent_fd,
            follow_symlinks=False,
        )
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise OwnedDirectoryGuardError(
            "POSIX_RELATIVE_STAT_FAILED",
            "owned relative object could not be inspected",
        ) from exc


def _posix_empty_directory(
    directory_fd: int,
    *,
    root_device: int,
    depth: int,
    budget: list[int],
) -> None:
    if depth > _MAX_TREE_DEPTH:
        raise OwnedDirectoryGuardError(
            "TREE_DEPTH_EXCEEDED",
            "owned directory tree exceeded the cleanup depth bound",
        )
    try:
        names = os.listdir(directory_fd)
    except OSError as exc:
        raise OwnedDirectoryGuardError(
            "POSIX_ENUMERATION_FAILED",
            "owned directory enumeration failed",
        ) from exc
    for name in names:
        _validate_owned_child_component(
            name,
            label="enumerated child component",
        )
        budget[0] += 1
        if budget[0] > _MAX_TREE_ENTRIES:
            raise OwnedDirectoryGuardError(
                "TREE_ENTRY_BOUND_EXCEEDED",
                "owned directory tree exceeded the cleanup entry bound",
            )
        observed = _posix_relative_lstat(directory_fd, name)
        if observed is None:
            raise OwnedDirectoryGuardError(
                "CHILD_IDENTITY_AMBIGUOUS",
                "enumerated owned child disappeared before cleanup",
            )
        if stat.S_ISDIR(observed.st_mode) and not stat.S_ISLNK(
            observed.st_mode
        ):
            child = _posix_open_directory(name, parent_fd=directory_fd)
            try:
                opened = os.fstat(child)
                if (
                    int(opened.st_dev) != root_device
                    or int(opened.st_dev) != int(observed.st_dev)
                    or int(opened.st_ino) != int(observed.st_ino)
                ):
                    raise OwnedDirectoryGuardError(
                        "CHILD_IDENTITY_DRIFTED",
                        "owned child identity or device drifted",
                    )
                _posix_empty_directory(
                    child,
                    root_device=root_device,
                    depth=depth + 1,
                    budget=budget,
                )
                current = _posix_relative_lstat(directory_fd, name)
                if current is None or not _same_identity(
                    _posix_identity_from_stat(opened),
                    _posix_identity_from_stat(current),
                ):
                    raise OwnedDirectoryGuardError(
                        "CHILD_IDENTITY_DRIFTED",
                        "owned child name changed before disposition",
                    )
                os.rmdir(name, dir_fd=directory_fd)
            except OwnedDirectoryGuardError:
                raise
            except OSError as exc:
                raise OwnedDirectoryGuardError(
                    "POSIX_CHILD_DISPOSITION_FAILED",
                    "owned child directory could not be removed",
                ) from exc
            finally:
                os.close(child)
        else:
            try:
                current = _posix_relative_lstat(directory_fd, name)
                if current is None or not _same_identity(
                    _posix_identity_from_stat(observed),
                    _posix_identity_from_stat(current),
                ):
                    raise OwnedDirectoryGuardError(
                        "CHILD_IDENTITY_DRIFTED",
                        "owned child name changed before unlink",
                    )
                os.unlink(name, dir_fd=directory_fd)
            except OwnedDirectoryGuardError:
                raise
            except OSError as exc:
                raise OwnedDirectoryGuardError(
                    "POSIX_CHILD_DISPOSITION_FAILED",
                    "owned child could not be unlinked",
                ) from exc


_GUARD_CONSTRUCTOR_CAPABILITY = object()


class OwnedDirectoryGuard:
    """Opaque retained authority for one exact owned directory."""

    __slots__ = (
        "_binding",
        "_subject_binding_sha256",
        "_guard_id",
        "_platform",
        "_filesystem",
        "_parent_path",
        "_original_component",
        "_quarantine_component",
        "_parent_identity",
        "_root_identity",
        "_parent_authority",
        "_root_authority",
        "_ledger_path",
        "_parent_relative_path",
        "_lock",
        "_closed",
        "_receipt",
    )

    def __new__(
        cls,
        *,
        _capability: object,
        **_kwargs: Any,
    ) -> OwnedDirectoryGuard:
        if _capability is not _GUARD_CONSTRUCTOR_CAPABILITY:
            raise TypeError("OwnedDirectoryGuard is opaque")
        return super().__new__(cls)

    def __init__(
        self,
        *,
        _capability: object,
        binding: Mapping[str, Any],
        subject_binding_sha256: str,
        guard_id: str,
        platform: str,
        filesystem: str,
        parent_path: Path,
        original_component: str,
        quarantine_component: str,
        parent_identity: Mapping[str, Any],
        root_identity: Mapping[str, Any],
        parent_authority: int,
        root_authority: int | None,
        ledger_path: Path,
        parent_relative_path: str,
    ) -> None:
        if _capability is not _GUARD_CONSTRUCTOR_CAPABILITY:
            raise TypeError("OwnedDirectoryGuard is opaque")
        self._binding = MappingProxyType(dict(binding))
        self._subject_binding_sha256 = subject_binding_sha256
        self._guard_id = guard_id
        self._platform = platform
        self._filesystem = filesystem
        self._parent_path = parent_path
        self._original_component = original_component
        self._quarantine_component = quarantine_component
        self._parent_identity = dict(parent_identity)
        self._root_identity = dict(root_identity)
        self._parent_authority = parent_authority
        self._root_authority = root_authority
        self._ledger_path = ledger_path
        self._parent_relative_path = parent_relative_path
        self._lock = threading.RLock()
        self._closed = False
        self._receipt: Mapping[str, Any] | None = None

    def __repr__(self) -> str:
        return "<OwnedDirectoryGuard opaque>"

    def __reduce__(self) -> object:
        raise TypeError("OwnedDirectoryGuard cannot be serialized")

    @property
    def binding(self) -> dict[str, Any]:
        return json.loads(json.dumps(dict(self._binding)))

    @property
    def ledger_path(self) -> Path:
        return self._ledger_path

    @property
    def quarantine_component_for_test(self) -> str:
        return self._quarantine_component

    def _close_authorities(self) -> None:
        if self._platform == "windows_ntfs_handle_v1":
            _windows_close(self._root_authority)
            _windows_close(self._parent_authority)
        else:
            for descriptor in (
                self._root_authority,
                self._parent_authority,
            ):
                if descriptor is not None and descriptor >= 0:
                    try:
                        os.close(descriptor)
                    except OSError:
                        pass
        self._root_authority = None
        self._parent_authority = -1
        self._closed = True

    def close_without_cleanup_for_test(self) -> None:
        """Fixture-only release; never valid production cleanup evidence."""

        with self._lock:
            self._close_authorities()

    def _stable(
        self,
        *,
        zero_population_evidence_sha256: str,
        cleanup_mode: str,
    ) -> dict[str, Any]:
        return {
            "guard_id": self._guard_id,
            "subject_binding_sha256": self._subject_binding_sha256,
            "platform": self._platform,
            "parent_relative_path": self._parent_relative_path,
            "original_component": self._original_component,
            "quarantine_component": self._quarantine_component,
            "parent_identity": self._parent_identity,
            "root_identity": self._root_identity,
            "zero_population_evidence_sha256": (
                zero_population_evidence_sha256
            ),
            "cleanup_mode": cleanup_mode,
        }

    def _append(
        self,
        stable: Mapping[str, Any],
        stage: str,
        *,
        recovered: bool,
        fault_after_stage: str | None,
    ) -> None:
        _append_ledger_stage(
            self._ledger_path,
            stable=stable,
            stage=stage,
            recovered=recovered,
        )
        if fault_after_stage == stage:
            self._close_authorities()
            raise OwnedDirectoryGuardInjectedCrash(stage)

    def _validate_live_parent(self) -> None:
        if self._platform == "windows_ntfs_handle_v1":
            observed = _windows_handle_identity(
                self._parent_authority
            )
        else:
            observed = _posix_identity_from_stat(
                os.fstat(self._parent_authority)
            )
        if not _same_identity(self._parent_identity, observed):
            raise OwnedDirectoryGuardError(
                "PARENT_IDENTITY_DRIFTED",
                "retained owned-directory parent identity drifted",
            )

    def _relative_identities(
        self,
    ) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
        if self._platform == "windows_ntfs_handle_v1":
            original = _windows_relative_identity(
                self._parent_authority,
                self._original_component,
                is_directory=True,
            )
            quarantine = _windows_relative_identity(
                self._parent_authority,
                self._quarantine_component,
                is_directory=True,
            )
            return original, quarantine
        original_row = _posix_relative_lstat(
            self._parent_authority,
            self._original_component,
        )
        quarantine_row = _posix_relative_lstat(
            self._parent_authority,
            self._quarantine_component,
        )
        return (
            (
                _posix_identity_from_stat(original_row)
                if original_row is not None
                else None
            ),
            (
                _posix_identity_from_stat(quarantine_row)
                if quarantine_row is not None
                else None
            ),
        )

    def _require_namespace_state(self, stage_count: int) -> None:
        self._validate_live_parent()
        original, quarantine = self._relative_identities()
        if stage_count <= 1:
            if (
                original is None
                or not _same_identity(original, self._root_identity)
                or quarantine is not None
            ):
                raise OwnedDirectoryGuardError(
                    "ORIGINAL_IDENTITY_AMBIGUOUS",
                    "owned root was substituted or quarantine collided",
                )
        elif stage_count in {2, 3}:
            if (
                original is not None
                or quarantine is None
                or not _same_identity(
                    quarantine,
                    self._root_identity,
                )
            ):
                raise OwnedDirectoryGuardError(
                    "QUARANTINE_IDENTITY_AMBIGUOUS",
                    "owned quarantine identity is missing or ambiguous",
                )
        else:
            if original is not None or quarantine is not None:
                raise OwnedDirectoryGuardError(
                    "ROOT_DISPOSITION_AMBIGUOUS",
                    "owned root or quarantine name remains after disposition",
                )

    def _quarantine(self) -> None:
        self._require_namespace_state(1)
        if self._root_authority is None:
            raise OwnedDirectoryGuardError(
                "ROOT_AUTHORITY_UNAVAILABLE",
                "owned root authority is unavailable before quarantine",
            )
        if self._platform == "windows_ntfs_handle_v1":
            retained = _windows_handle_identity(self._root_authority)
            if not _same_identity(retained, self._root_identity):
                raise OwnedDirectoryGuardError(
                    "ROOT_IDENTITY_DRIFTED",
                    "retained owned root identity drifted",
                )
            _windows_rename_handle(
                self._root_authority,
                self._parent_authority,
                self._quarantine_component,
            )
        else:
            retained = _posix_identity_from_stat(
                os.fstat(self._root_authority)
            )
            if not _same_identity(retained, self._root_identity):
                raise OwnedDirectoryGuardError(
                    "ROOT_IDENTITY_DRIFTED",
                    "retained owned root identity drifted",
                )
            try:
                os.rename(
                    self._original_component,
                    self._quarantine_component,
                    src_dir_fd=self._parent_authority,
                    dst_dir_fd=self._parent_authority,
                )
                os.fsync(self._parent_authority)
            except OSError as exc:
                raise OwnedDirectoryGuardError(
                    "QUARANTINE_RENAME_FAILED",
                    "owned directory could not be quarantined",
                ) from exc
        self._require_namespace_state(2)

    def _empty_tree(self) -> None:
        if self._root_authority is None:
            raise OwnedDirectoryGuardError(
                "ROOT_AUTHORITY_UNAVAILABLE",
                "owned root authority is unavailable during cleanup",
            )
        if self._platform == "windows_ntfs_handle_v1":
            _windows_empty_directory(
                self._root_authority,
                root_volume_serial=int(
                    self._root_identity["volume_serial_number"]
                ),
                depth=0,
                budget=[0],
            )
        else:
            _posix_empty_directory(
                self._root_authority,
                root_device=int(self._root_identity["st_dev"]),
                depth=0,
                budget=[0],
            )

    def _dispose_root(self) -> None:
        self._require_namespace_state(3)
        if self._root_authority is None:
            raise OwnedDirectoryGuardError(
                "ROOT_AUTHORITY_UNAVAILABLE",
                "owned root authority is unavailable before disposition",
            )
        if self._platform == "windows_ntfs_handle_v1":
            _windows_set_disposition(self._root_authority)
            _windows_close(self._root_authority)
        else:
            try:
                current = _posix_relative_lstat(
                    self._parent_authority,
                    self._quarantine_component,
                )
                retained = _posix_identity_from_stat(
                    os.fstat(self._root_authority)
                )
                if current is None or not _same_identity(
                    retained,
                    _posix_identity_from_stat(current),
                ):
                    raise OwnedDirectoryGuardError(
                        "QUARANTINE_IDENTITY_AMBIGUOUS",
                        "owned quarantine changed before root disposition",
                    )
                os.rmdir(
                    self._quarantine_component,
                    dir_fd=self._parent_authority,
                )
                os.fsync(self._parent_authority)
            except OwnedDirectoryGuardError:
                raise
            except OSError as exc:
                raise OwnedDirectoryGuardError(
                    "ROOT_DISPOSITION_FAILED",
                    "owned quarantine root could not be removed",
                ) from exc
            os.close(self._root_authority)
        self._root_authority = None

    def _terminal_receipt(
        self,
        *,
        recovered: bool,
    ) -> dict[str, Any]:
        replay = replay_owned_directory_cleanup_ledger(
            self._ledger_path,
            expected_subject_binding_sha256=(
                self._subject_binding_sha256
            ),
        )
        if replay["terminal"] is not True:
            raise OwnedDirectoryGuardError(
                "CLEANUP_NOT_TERMINAL",
                "owned directory cleanup ledger is not terminal",
            )
        first = replay["records"][0]
        core = {
            "schema": GUARD_REVOCATION_SCHEMA,
            "guard_binding_sha256": self._binding["binding_sha256"],
            "subject_binding_sha256": self._subject_binding_sha256,
            "zero_population_evidence_sha256": first[
                "zero_population_evidence_sha256"
            ],
            "cleanup_mode": first["cleanup_mode"],
            "terminal_stage": "VERIFIED_ABSENT",
            "terminal_ledger_head_sha256": replay["head_sha256"],
            "bound_root_link_absent": True,
            "completion_authority": False,
            "recovered": recovered,
        }
        return {**core, "receipt_sha256": _digest(core)}

    def _run_cleanup(
        self,
        *,
        stable: Mapping[str, Any],
        recovered: bool,
        initial_stage_count: int,
        fault_after_stage: str | None,
    ) -> dict[str, Any]:
        stage_count = initial_stage_count
        if stage_count == 0:
            self._require_namespace_state(0)
            self._append(
                stable,
                "INTENT_DURABLE",
                recovered=recovered,
                fault_after_stage=fault_after_stage,
            )
            stage_count = 1
        if stage_count == 1:
            self._quarantine()
            self._append(
                stable,
                "QUARANTINE_CONFIRMED",
                recovered=recovered,
                fault_after_stage=fault_after_stage,
            )
            stage_count = 2
        if stage_count == 2:
            self._require_namespace_state(stage_count)
            self._empty_tree()
            self._append(
                stable,
                "TREE_EMPTY",
                recovered=recovered,
                fault_after_stage=fault_after_stage,
            )
            stage_count = 3
        if stage_count == 3:
            self._dispose_root()
            self._append(
                stable,
                "ROOT_DISPOSITION_SET",
                recovered=recovered,
                fault_after_stage=fault_after_stage,
            )
            stage_count = 4
        if stage_count == 4:
            self._require_namespace_state(stage_count)
            self._append(
                stable,
                "VERIFIED_ABSENT",
                recovered=recovered,
                fault_after_stage=fault_after_stage,
            )
        self._require_namespace_state(5)
        receipt = self._terminal_receipt(recovered=recovered)
        self._receipt = MappingProxyType(receipt)
        self._close_authorities()
        return dict(receipt)

    def revoke_after_zero(
        self,
        *,
        zero_population_evidence_sha256: str,
        cleanup_mode: str,
        _fault_after_stage: str | None = None,
    ) -> dict[str, Any]:
        """Revoke only after exact zero-population evidence is bound."""

        zero = _validate_digest(
            zero_population_evidence_sha256,
            label="zero-population evidence",
        )
        mode = _validate_component(cleanup_mode, label="cleanup mode")
        if (
            _fault_after_stage is not None
            and _fault_after_stage not in _STAGES
        ):
            raise OwnedDirectoryGuardError(
                "FAULT_STAGE_INVALID",
                "fixture fault stage is invalid",
            )
        with self._lock:
            if self._receipt is not None:
                return dict(self._receipt)
            if self._closed:
                raise OwnedDirectoryGuardError(
                    "GUARD_AUTHORITY_CLOSED",
                    "retained directory guard authority is closed",
                )
            stable = self._stable(
                zero_population_evidence_sha256=zero,
                cleanup_mode=mode,
            )
            return self._run_cleanup(
                stable=stable,
                recovered=False,
                initial_stage_count=0,
                fault_after_stage=_fault_after_stage,
            )


def _guard_binding(
    *,
    guard_id: str,
    subject_binding_sha256: str,
    platform: str,
    filesystem: str,
    parent_identity: Mapping[str, Any],
    root_identity: Mapping[str, Any],
) -> dict[str, Any]:
    core = {
        "schema": GUARD_BINDING_SCHEMA,
        "guard_id": guard_id,
        "subject_binding_sha256": subject_binding_sha256,
        "platform": platform,
        "filesystem": filesystem,
        "parent_identity_sha256": _identity_digest(parent_identity),
        "root_identity_sha256": _identity_digest(root_identity),
        "retained_parent_authority": True,
        "retained_root_authority": True,
        "handles_noninheritable": True,
        "completion_authority": False,
        "crash_recovery_assurance": (
            "FAIL_CLOSED_IDENTITY_REPLAY_NOT_HOSTILE_SAME_USER_PROOF"
        ),
        "host_paths_recorded": False,
    }
    return {**core, "binding_sha256": _digest(core)}


def bind_owned_directory(
    root: str | Path,
    *,
    subject_binding_sha256: str,
    ledger_directory: str | Path,
) -> OwnedDirectoryGuard:
    """Retain exact root and parent authority before untrusted work starts."""

    subject = _validate_digest(
        subject_binding_sha256,
        label="subject binding",
    )
    root_path = Path(os.path.abspath(root))
    original_component = _validate_component(
        root_path.name,
        label="owned root component",
    )
    parent_path = root_path.parent
    ledger_path_parent = Path(os.path.abspath(ledger_directory))
    try:
        shared = os.path.commonpath(
            [
                os.path.normcase(str(root_path)),
                os.path.normcase(str(ledger_path_parent)),
            ]
        )
    except ValueError:
        shared = ""
    if os.path.normcase(shared) == os.path.normcase(str(root_path)):
        raise OwnedDirectoryGuardError(
            "LEDGER_INSIDE_OWNED_ROOT",
            "cleanup ledger must remain outside the owned directory",
        )
    _private_directory(ledger_path_parent)
    parent_relative_path = _relative_parent_path(
        parent_path,
        ledger_path_parent,
    )
    guard_id = secrets.token_hex(16)
    quarantine_component = f".plamen-q-{guard_id}"
    ledger_path = ledger_path_parent / f"guard-{guard_id}.jsonl"
    if os.path.lexists(_native_path(ledger_path)):
        raise OwnedDirectoryGuardError(
            "LEDGER_COLLISION",
            "new cleanup ledger identity collided",
        )

    parent_authority: int | None = None
    root_authority: int | None = None
    try:
        if os.name == "nt":
            filesystem = _windows_require_supported_volume(root_path)
            ledger_filesystem = _windows_require_supported_volume(
                ledger_path_parent
            )
            if ledger_filesystem != filesystem:
                raise OwnedDirectoryGuardError(
                    "LEDGER_VOLUME_MISMATCH",
                    "guard ledger and owned root require one local filesystem",
                )
            parent_authority = _windows_open_absolute_directory(
                parent_path
            )
            root_authority = _windows_open_absolute_directory(root_path)
            parent_identity = _windows_handle_identity(parent_authority)
            root_identity = _windows_handle_identity(root_authority)
            if (
                not bool(
                    int(parent_identity["file_attributes"])
                    & _DIRECTORY_ATTRIBUTE
                )
                or bool(
                    int(parent_identity["file_attributes"])
                    & _REPARSE_ATTRIBUTE
                )
                or not bool(
                    int(root_identity["file_attributes"])
                    & _DIRECTORY_ATTRIBUTE
                )
                or bool(
                    int(root_identity["file_attributes"])
                    & _REPARSE_ATTRIBUTE
                )
                or parent_identity["volume_serial_number"]
                != root_identity["volume_serial_number"]
            ):
                raise OwnedDirectoryGuardError(
                    "WINDOWS_ROOT_UNSUPPORTED",
                    "owned root and parent must be non-reparse directories",
                )
            relative_identity = _windows_relative_identity(
                parent_authority,
                original_component,
                is_directory=True,
            )
            if (
                relative_identity is None
                or not _same_identity(
                    relative_identity,
                    root_identity,
                )
            ):
                raise OwnedDirectoryGuardError(
                    "ROOT_IDENTITY_AMBIGUOUS",
                    "owned root is not the exact retained parent child",
                )
            platform = "windows_ntfs_handle_v1"
        else:
            _require_posix_dirfd_contract()
            filesystem = "POSIX_LOCAL_DIRFD"
            parent_authority = _posix_open_directory(parent_path)
            root_authority = _posix_open_directory(root_path)
            parent_identity = _posix_identity_from_stat(
                os.fstat(parent_authority)
            )
            root_identity = _posix_identity_from_stat(
                os.fstat(root_authority)
            )
            relative = _posix_relative_lstat(
                parent_authority,
                original_component,
            )
            if (
                relative is None
                or not stat.S_ISDIR(relative.st_mode)
                or stat.S_ISLNK(relative.st_mode)
                or not _same_identity(
                    _posix_identity_from_stat(relative),
                    root_identity,
                )
            ):
                raise OwnedDirectoryGuardError(
                    "ROOT_IDENTITY_AMBIGUOUS",
                    "owned root is not the exact retained parent child",
                )
            platform = "posix_dirfd_v1"
        binding = _guard_binding(
            guard_id=guard_id,
            subject_binding_sha256=subject,
            platform=platform,
            filesystem=filesystem,
            parent_identity=parent_identity,
            root_identity=root_identity,
        )
        return OwnedDirectoryGuard(
            _capability=_GUARD_CONSTRUCTOR_CAPABILITY,
            binding=binding,
            subject_binding_sha256=subject,
            guard_id=guard_id,
            platform=platform,
            filesystem=filesystem,
            parent_path=parent_path,
            original_component=original_component,
            quarantine_component=quarantine_component,
            parent_identity=parent_identity,
            root_identity=root_identity,
            parent_authority=parent_authority,
            root_authority=root_authority,
            ledger_path=ledger_path,
            parent_relative_path=parent_relative_path,
        )
    except Exception:
        if os.name == "nt":
            _windows_close(root_authority)
            _windows_close(parent_authority)
        else:
            for descriptor in (root_authority, parent_authority):
                if descriptor is not None:
                    try:
                        os.close(descriptor)
                    except OSError:
                        pass
        raise


def _recover_guard_from_records(
    ledger_path: Path,
    records: list[dict[str, Any]],
) -> OwnedDirectoryGuard:
    first = records[0]
    parent_path = _parent_from_ledger(
        ledger_path,
        str(first["parent_relative_path"]),
    )
    parent_authority: int | None = None
    root_authority: int | None = None
    try:
        if first["platform"] == "windows_ntfs_handle_v1":
            if os.name != "nt":
                raise OwnedDirectoryGuardError(
                    "RECOVERY_PLATFORM_MISMATCH",
                    "Windows cleanup ledger cannot recover on this platform",
                )
            filesystem = _windows_require_supported_volume(parent_path)
            parent_authority = _windows_open_absolute_directory(
                parent_path
            )
            parent_identity = _windows_handle_identity(parent_authority)
            if not _same_identity(
                parent_identity,
                first["parent_identity"],
            ):
                raise OwnedDirectoryGuardError(
                    "RECOVERY_PARENT_MISMATCH",
                    "cleanup recovery parent identity mismatched",
                )
            stage_count = len(records)
            component = (
                first["original_component"]
                if stage_count == 1
                else first["quarantine_component"]
            )
            if stage_count <= 3:
                root_authority = _windows_open_relative(
                    parent_authority,
                    component,
                    is_directory=True,
                    deletion_access=True,
                )
                if root_authority is None:
                    raise OwnedDirectoryGuardError(
                        "RECOVERY_ROOT_MISSING",
                        "cleanup recovery root identity is missing",
                    )
                root_identity = _windows_handle_identity(root_authority)
                if not _same_identity(
                    root_identity,
                    first["root_identity"],
                ):
                    raise OwnedDirectoryGuardError(
                        "RECOVERY_ROOT_MISMATCH",
                        "cleanup recovery root identity mismatched",
                    )
            platform = "windows_ntfs_handle_v1"
        elif first["platform"] == "posix_dirfd_v1":
            if os.name == "nt":
                raise OwnedDirectoryGuardError(
                    "RECOVERY_PLATFORM_MISMATCH",
                    "POSIX cleanup ledger cannot recover on Windows",
                )
            _require_posix_dirfd_contract()
            filesystem = "POSIX_LOCAL_DIRFD"
            parent_authority = _posix_open_directory(parent_path)
            parent_identity = _posix_identity_from_stat(
                os.fstat(parent_authority)
            )
            if not _same_identity(
                parent_identity,
                first["parent_identity"],
            ):
                raise OwnedDirectoryGuardError(
                    "RECOVERY_PARENT_MISMATCH",
                    "cleanup recovery parent identity mismatched",
                )
            stage_count = len(records)
            component = (
                first["original_component"]
                if stage_count == 1
                else first["quarantine_component"]
            )
            if stage_count <= 3:
                root_authority = _posix_open_directory(
                    component,
                    parent_fd=parent_authority,
                )
                root_identity = _posix_identity_from_stat(
                    os.fstat(root_authority)
                )
                if not _same_identity(
                    root_identity,
                    first["root_identity"],
                ):
                    raise OwnedDirectoryGuardError(
                        "RECOVERY_ROOT_MISMATCH",
                        "cleanup recovery root identity mismatched",
                    )
            platform = "posix_dirfd_v1"
        else:
            raise OwnedDirectoryGuardError(
                "RECOVERY_PLATFORM_INVALID",
                "cleanup ledger platform is invalid",
            )
        binding = _guard_binding(
            guard_id=str(first["guard_id"]),
            subject_binding_sha256=str(
                first["subject_binding_sha256"]
            ),
            platform=platform,
            filesystem=filesystem,
            parent_identity=first["parent_identity"],
            root_identity=first["root_identity"],
        )
        guard = OwnedDirectoryGuard(
            _capability=_GUARD_CONSTRUCTOR_CAPABILITY,
            binding=binding,
            subject_binding_sha256=str(
                first["subject_binding_sha256"]
            ),
            guard_id=str(first["guard_id"]),
            platform=platform,
            filesystem=filesystem,
            parent_path=parent_path,
            original_component=str(first["original_component"]),
            quarantine_component=str(
                first["quarantine_component"]
            ),
            parent_identity=first["parent_identity"],
            root_identity=first["root_identity"],
            parent_authority=parent_authority,
            root_authority=root_authority,
            ledger_path=ledger_path,
            parent_relative_path=str(first["parent_relative_path"]),
        )
        guard._require_namespace_state(len(records))
        return guard
    except Exception:
        if os.name == "nt":
            _windows_close(root_authority)
            _windows_close(parent_authority)
        else:
            for descriptor in (root_authority, parent_authority):
                if descriptor is not None:
                    try:
                        os.close(descriptor)
                    except OSError:
                        pass
        raise


def recover_owned_directory_cleanup(
    ledger_path: str | Path,
    *,
    expected_subject_binding_sha256: str,
) -> dict[str, Any]:
    """Fail-closed replay and completion of one interrupted cleanup."""

    path = Path(ledger_path)
    replay = replay_owned_directory_cleanup_ledger(
        path,
        expected_subject_binding_sha256=(
            expected_subject_binding_sha256
        ),
    )
    records = replay["records"]
    guard = _recover_guard_from_records(path, records)
    stable = {
        key: records[0][key]
        for key in (
            "guard_id",
            "subject_binding_sha256",
            "platform",
            "parent_relative_path",
            "original_component",
            "quarantine_component",
            "parent_identity",
            "root_identity",
            "zero_population_evidence_sha256",
            "cleanup_mode",
        )
    }
    try:
        if replay["terminal"] is True:
            receipt = guard._terminal_receipt(recovered=True)
            guard._close_authorities()
            return receipt
        return guard._run_cleanup(
            stable=stable,
            recovered=True,
            initial_stage_count=len(records),
            fault_after_stage=None,
        )
    except Exception:
        guard._close_authorities()
        raise


def reconcile_owned_directory_cleanup_ledgers(
    ledger_directory: str | Path,
) -> dict[str, Any]:
    """Boundedly finish every interrupted cleanup before outer-root recovery."""

    directory = Path(ledger_directory)
    try:
        row = os.lstat(_native_path(directory))
    except FileNotFoundError:
        row = None
    except OSError as exc:
        raise OwnedDirectoryGuardError(
            "RECONCILIATION_DIRECTORY_UNAVAILABLE",
            "profile lifecycle directory cannot be inventoried",
        ) from exc
    if row is None:
        core = {
            "schema": GUARD_RECONCILIATION_SCHEMA,
            "directory_present": False,
            "complete": True,
            "reason": "NO_PROFILE_LIFECYCLE_DIRECTORY",
            "scanned": 0,
            "recovered": 0,
            "terminal": 0,
            "nominal_bytes": 0,
            "ledger_set_sha256": _digest({"ledgers": []}),
            "completion_authority": False,
        }
        return {**core, "receipt_sha256": _digest(core)}
    try:
        if (
            not stat.S_ISDIR(row.st_mode)
            or stat.S_ISLNK(row.st_mode)
            or bool(
                getattr(row, "st_file_attributes", 0)
                & _REPARSE_ATTRIBUTE
            )
        ):
            raise OwnedDirectoryGuardError(
                "RECONCILIATION_DIRECTORY_INVALID",
                "profile lifecycle directory is aliased or not a directory",
            )
        with os.scandir(_native_path(directory)) as entries:
            paths = []
            for entry in entries:
                if len(paths) >= _MAX_RECONCILIATION_LEDGERS:
                    raise OwnedDirectoryGuardError(
                        "RECONCILIATION_ENTRY_BOUND",
                        "profile lifecycle ledger count exceeded its bound",
                    )
                paths.append(directory / Path(entry.path).name)
    except OwnedDirectoryGuardError:
        raise
    except OSError as exc:
        raise OwnedDirectoryGuardError(
            "RECONCILIATION_DIRECTORY_UNAVAILABLE",
            "profile lifecycle directory cannot be inventoried",
        ) from exc
    folded: set[str] = set()
    nominal_bytes = 0
    for path in paths:
        key = path.name.casefold()
        if key in folded:
            raise OwnedDirectoryGuardError(
                "RECONCILIATION_NAME_AMBIGUOUS",
                "profile lifecycle ledger names collide by case",
            )
        folded.add(key)
        if _LEDGER_NAME_RE.fullmatch(path.name) is None:
            raise OwnedDirectoryGuardError(
                "RECONCILIATION_ENTRY_INVALID",
                "profile lifecycle directory has an unexpected entry",
            )
        try:
            entry = os.lstat(_native_path(path))
        except OSError as exc:
            raise OwnedDirectoryGuardError(
                "RECONCILIATION_ENTRY_UNAVAILABLE",
                "profile lifecycle ledger cannot be inspected",
            ) from exc
        if (
            not stat.S_ISREG(entry.st_mode)
            or stat.S_ISLNK(entry.st_mode)
            or int(getattr(entry, "st_nlink", 1)) != 1
            or int(entry.st_size) <= 0
            or int(entry.st_size) > _MAX_LEDGER_BYTES
        ):
            raise OwnedDirectoryGuardError(
                "RECONCILIATION_ENTRY_INVALID",
                "profile lifecycle ledger is not one bounded regular file",
            )
        nominal_bytes += int(entry.st_size)
        if nominal_bytes > _MAX_RECONCILIATION_BYTES:
            raise OwnedDirectoryGuardError(
                "RECONCILIATION_BYTE_BOUND",
                "profile lifecycle ledger bytes exceeded their bound",
            )

    recovered = 0
    terminal = 0
    ledger_heads: list[dict[str, str]] = []
    for path in sorted(paths, key=lambda item: item.name.casefold()):
        replay = replay_owned_directory_cleanup_ledger(path)
        subject = str(
            replay["records"][0]["subject_binding_sha256"]
        )
        if replay["terminal"] is not True:
            receipt = recover_owned_directory_cleanup(
                path,
                expected_subject_binding_sha256=subject,
            )
            if (
                receipt.get("terminal_stage") != "VERIFIED_ABSENT"
                or receipt.get("completion_authority") is not False
                or receipt.get("recovered") is not True
            ):
                raise OwnedDirectoryGuardError(
                    "RECONCILIATION_RECOVERY_INVALID",
                    "profile lifecycle cleanup recovery did not replay",
                )
            recovered += 1
            replay = replay_owned_directory_cleanup_ledger(
                path,
                expected_subject_binding_sha256=subject,
            )
        if replay["terminal"] is not True:
            raise OwnedDirectoryGuardError(
                "RECONCILIATION_NONTERMINAL",
                "profile lifecycle cleanup remained nonterminal",
            )
        terminal += 1
        ledger_heads.append({
            "guard_id": str(replay["records"][0]["guard_id"]),
            "head_sha256": str(replay["head_sha256"]),
        })
    core = {
        "schema": GUARD_RECONCILIATION_SCHEMA,
        "directory_present": True,
        "complete": True,
        "reason": "PROFILE_LIFECYCLE_RECONCILED",
        "scanned": len(paths),
        "recovered": recovered,
        "terminal": terminal,
        "nominal_bytes": nominal_bytes,
        "ledger_set_sha256": _digest({"ledgers": ledger_heads}),
        "completion_authority": False,
    }
    return {**core, "receipt_sha256": _digest(core)}


__all__ = [
    "GUARD_BINDING_SCHEMA",
    "GUARD_LEDGER_SCHEMA",
    "GUARD_RECONCILIATION_SCHEMA",
    "GUARD_REVOCATION_SCHEMA",
    "OwnedDirectoryGuard",
    "OwnedDirectoryGuardError",
    "OwnedDirectoryGuardInjectedCrash",
    "bind_owned_directory",
    "recover_owned_directory_cleanup",
    "reconcile_owned_directory_cleanup_ledgers",
    "replay_owned_directory_cleanup_ledger",
    "windows_abi_layout",
]
