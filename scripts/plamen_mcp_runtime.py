"""Immutable, authenticated generations for npm-backed MCP runtimes.

This module deliberately has no dependency on :mod:`plamen`.  An installer can
adapt its existing projection/install key by passing small ``signer`` and
``verifier`` callbacks.  A generation is published with one atomic,
no-replacement directory rename only after its complete payload census and
signed receipt have been written into private staging.

Threat model
------------
The authenticated materializer, pinned npm/Node executables, and pinned package
bytes are trusted inputs. Package code admitted by that authority is trusted to
execute. This primitive detects storage drift and non-ordinary filesystem
objects, but it does **not** claim to defeat a hostile same-account actor racing
filesystem mutation after authenticated materialization. The validation lock is
held through process creation and final authorities are replayed immediately
before ``Popen`` to close cooperating installer/recovery races.

Store layout::

    STORE/
      .lock
      .pending/TXN.json
      .staging/TXN/{payload,.plamen-mcp-generation.json}
      .abandoned/TXN/...       # retained; never traversed/deleted automatically
      generations/GENERATION/{payload,.plamen-mcp-generation.json}

The pending marker is intentionally outside the published directory.  Launches
fail closed while *any* pending/staged state exists. Recovery atomically
quarantines a private staging root without traversing it. Once the no-replace
rename commits a generation, recovery validates it and merely retires its
pending marker; it never modifies or removes the committed directory.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import ctypes
import errno
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import re
import secrets
import stat
import subprocess
import sys
import tarfile
import threading
import time
from typing import Any, Callable, Iterator, Mapping, Sequence
import unicodedata
import urllib.request
import zipfile


RECEIPT_NAME = ".plamen-mcp-generation.json"
RECEIPT_SCHEMA = "plamen.mcp_immutable_generation_receipt.v2"
CENSUS_SCHEMA = "plamen.mcp_recursive_census.v2"
PENDING_SCHEMA = "plamen.mcp_generation_pending.v1"
GENERATION_REQUEST_SCHEMA = "plamen.mcp_generation_request.v2"
MEMBER_AUTHORITY_SCHEMA = "plamen.mcp_native_resource_closure.v2"
PAYLOAD_NAME = "payload"
MANAGED_NODE_RECEIPT_NAME = ".plamen-managed-node.json"
MANAGED_NODE_RECEIPT_SCHEMA = "plamen.managed_node_runtime.v2"
MANAGED_NODE_VERSION = "24.20.0"
MANAGED_NPM_VERSION = "11.19.0"

# Reviewed from Node.js v24.20.0's official signed SHASUMS256 release file.
# Archive SHA-256 is the reviewed-content root for every extracted byte and
# directory in the Node/npm implementation closure.
MANAGED_NODE_ARCHIVES = {
    "windows-x64": {
        "filename": "node-v24.20.0-win-x64.zip",
        "sha256": "6cac9ffbca8f6a47091e4b5c772e0606049c3871cb67d900c0cedde630e545ba",
        "format": "zip", "archive_root": "node-v24.20.0-win-x64",
        "node": "node.exe", "npm_cli": "node_modules/npm/bin/npm-cli.js",
    },
    "windows-arm64": {
        "filename": "node-v24.20.0-win-arm64.zip",
        "sha256": "31c6799744de8a54601643098040c68c3697e56c94e407d61d0e5fa5f34191d7",
        "format": "zip", "archive_root": "node-v24.20.0-win-arm64",
        "node": "node.exe", "npm_cli": "node_modules/npm/bin/npm-cli.js",
    },
    "linux-x64": {
        "filename": "node-v24.20.0-linux-x64.tar.xz",
        "sha256": "2f2c0da162318f0de47665410c7c8c2ed3d36c8f3105de4bbc61176c70a7cbf2",
        "format": "tar.xz", "archive_root": "node-v24.20.0-linux-x64",
        "node": "bin/node", "npm_cli": "lib/node_modules/npm/bin/npm-cli.js",
    },
    "linux-arm64": {
        "filename": "node-v24.20.0-linux-arm64.tar.xz",
        "sha256": "5f4ddab610c1ab2016b3c227cebdbf6d9495161487e4739c7b90090595f465f7",
        "format": "tar.xz", "archive_root": "node-v24.20.0-linux-arm64",
        "node": "bin/node", "npm_cli": "lib/node_modules/npm/bin/npm-cli.js",
    },
    "darwin-x64": {
        "filename": "node-v24.20.0-darwin-x64.tar.gz",
        "sha256": "9e5b2644cf107befb6aefca676b96d3296bc10138096f022ed378d6233ed81f4",
        "format": "tar.gz", "archive_root": "node-v24.20.0-darwin-x64",
        "node": "bin/node", "npm_cli": "lib/node_modules/npm/bin/npm-cli.js",
    },
    "darwin-arm64": {
        "filename": "node-v24.20.0-darwin-arm64.tar.gz",
        "sha256": "40e5607e5ecb3db9192723776da2d75d966260fc74a7a9e731c1bd67dda96bc8",
        "format": "tar.gz", "archive_root": "node-v24.20.0-darwin-arm64",
        "node": "bin/node", "npm_cli": "lib/node_modules/npm/bin/npm-cli.js",
    },
}

_GENERATION_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_TXN_RE = re.compile(r"txn-[0-9a-f]{64}\Z")
_HEX64_RE = re.compile(r"[0-9a-f]{64}\Z")
_AUTH_TOKEN_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/+-]{0,255}\Z")
_MAX_RECEIPT_BYTES = 64 * 1024 * 1024
_FILE_ATTRIBUTE_REPARSE_POINT = 0x400
_WINDOWS_RESERVED_NAMES = {
    "CON", "PRN", "AUX", "NUL", "CLOCK$",
    *(f"COM{index}" for index in range(1, 10)),
    *(f"LPT{index}" for index in range(1, 10)),
}

# Bind the alternate-stream enumeration ABI exactly once.  Creating the
# structure class inside ``_windows_stream_names`` also creates a distinct
# ``ctypes.POINTER`` type on every filesystem row.  ctypes retains those
# pointer types in its process-global cache, so a complete npm census could
# consume gigabytes across repeated validation passes on Windows.
if os.name == "nt":
    from ctypes import wintypes as _WINDOWS_STREAM_WINTYPES

    class _WIN32_FIND_STREAM_DATA(ctypes.Structure):
        _fields_ = [
            ("StreamSize", ctypes.c_longlong),
            ("cStreamName", _WINDOWS_STREAM_WINTYPES.WCHAR * 296),
        ]

    _LP_WIN32_FIND_STREAM_DATA = ctypes.POINTER(_WIN32_FIND_STREAM_DATA)
    _WINDOWS_STREAM_KERNEL32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _WINDOWS_FIND_FIRST_STREAM = _WINDOWS_STREAM_KERNEL32.FindFirstStreamW
    _WINDOWS_FIND_FIRST_STREAM.argtypes = [
        _WINDOWS_STREAM_WINTYPES.LPCWSTR,
        _WINDOWS_STREAM_WINTYPES.INT,
        _LP_WIN32_FIND_STREAM_DATA,
        _WINDOWS_STREAM_WINTYPES.DWORD,
    ]
    _WINDOWS_FIND_FIRST_STREAM.restype = _WINDOWS_STREAM_WINTYPES.HANDLE
    _WINDOWS_FIND_NEXT_STREAM = _WINDOWS_STREAM_KERNEL32.FindNextStreamW
    _WINDOWS_FIND_NEXT_STREAM.argtypes = [
        _WINDOWS_STREAM_WINTYPES.HANDLE,
        _LP_WIN32_FIND_STREAM_DATA,
    ]
    _WINDOWS_FIND_NEXT_STREAM.restype = _WINDOWS_STREAM_WINTYPES.BOOL
    _WINDOWS_FIND_CLOSE = _WINDOWS_STREAM_KERNEL32.FindClose
    _WINDOWS_FIND_CLOSE.argtypes = [_WINDOWS_STREAM_WINTYPES.HANDLE]
    _WINDOWS_FIND_CLOSE.restype = _WINDOWS_STREAM_WINTYPES.BOOL
    _WINDOWS_INVALID_HANDLE_VALUE = _WINDOWS_STREAM_WINTYPES.HANDLE(-1).value

    class _STORE_LOCK_OVERLAPPED(ctypes.Structure):
        _fields_ = [
            ("Internal", ctypes.c_size_t),
            ("InternalHigh", ctypes.c_size_t),
            ("Offset", _WINDOWS_STREAM_WINTYPES.DWORD),
            ("OffsetHigh", _WINDOWS_STREAM_WINTYPES.DWORD),
            ("hEvent", _WINDOWS_STREAM_WINTYPES.HANDLE),
        ]

    _STORE_LOCK_FILE_EX = _WINDOWS_STREAM_KERNEL32.LockFileEx
    _STORE_LOCK_FILE_EX.argtypes = [
        _WINDOWS_STREAM_WINTYPES.HANDLE,
        _WINDOWS_STREAM_WINTYPES.DWORD,
        _WINDOWS_STREAM_WINTYPES.DWORD,
        _WINDOWS_STREAM_WINTYPES.DWORD,
        _WINDOWS_STREAM_WINTYPES.DWORD,
        ctypes.POINTER(_STORE_LOCK_OVERLAPPED),
    ]
    _STORE_LOCK_FILE_EX.restype = _WINDOWS_STREAM_WINTYPES.BOOL
    _STORE_UNLOCK_FILE_EX = _WINDOWS_STREAM_KERNEL32.UnlockFileEx
    _STORE_UNLOCK_FILE_EX.argtypes = [
        _WINDOWS_STREAM_WINTYPES.HANDLE,
        _WINDOWS_STREAM_WINTYPES.DWORD,
        _WINDOWS_STREAM_WINTYPES.DWORD,
        _WINDOWS_STREAM_WINTYPES.DWORD,
        ctypes.POINTER(_STORE_LOCK_OVERLAPPED),
    ]
    _STORE_UNLOCK_FILE_EX.restype = _WINDOWS_STREAM_WINTYPES.BOOL
else:
    _WIN32_FIND_STREAM_DATA = None
    _LP_WIN32_FIND_STREAM_DATA = None
    _WINDOWS_FIND_FIRST_STREAM = None
    _WINDOWS_FIND_NEXT_STREAM = None
    _WINDOWS_FIND_CLOSE = None
    _WINDOWS_INVALID_HANDLE_VALUE = None
    _STORE_LOCK_OVERLAPPED = None
    _STORE_LOCK_FILE_EX = None
    _STORE_UNLOCK_FILE_EX = None

REQUIRED_NPM_INSTALL_FLAGS = (
    "ci",
    "--ignore-scripts",
    "--no-audit",
    "--no-fund",
    "--no-bin-links",
)
_PINNED_VERSION_RE = re.compile(
    r"v?[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?\Z"
)
_LAUNCH_ENVIRONMENT_POLICY = {
    "schema": "plamen.mcp_node_launch_environment.v1",
    "remove_exact_casefold": ["NODE_OPTIONS", "NODE_PATH"],
    "remove_prefix_casefold": ["LD_", "DYLD_"],
}

Signer = Callable[[bytes], Mapping[str, str]]
Verifier = Callable[[bytes, Mapping[str, str]], bool]
Materializer = Callable[[Path], Any]
FaultHook = Callable[[str], Any]


class MCPRuntimeSecurityError(RuntimeError):
    """The runtime generation cannot be proven safe and exact."""


class MCPRuntimeStoreBusyError(MCPRuntimeSecurityError):
    """The bounded generation-store lock acquisition window expired."""

    reason = "MCP_RUNTIME_STORE_BUSY"
    reason_code = reason

    def __init__(self, mode: str) -> None:
        self.mode = mode
        super().__init__(f"{self.reason}: generation store {mode.lower()} lock is busy")


class MCPRuntimeStoreUnavailableError(MCPRuntimeSecurityError):
    """The store has no complete, reader-admissible lock authority."""

    reason = "MCP_RUNTIME_STORE_UNAVAILABLE"
    reason_code = reason

    def __init__(self, detail: str) -> None:
        super().__init__(f"{self.reason}: {detail}")


class MCPRuntimeStoreCorruptError(MCPRuntimeSecurityError):
    """The named store lock has non-recoverable foreign bytes or shape."""

    reason = "MCP_RUNTIME_STORE_CORRUPT"
    reason_code = reason

    def __init__(self, detail: str) -> None:
        super().__init__(f"{self.reason}: {detail}")


@dataclass(frozen=True)
class PublishedGeneration:
    generation_id: str
    generation_path: Path
    payload_path: Path
    receipt_sha256: str
    census_sha256: str
    request_sha256: str


@dataclass(frozen=True)
class ValidatedGeneration(PublishedGeneration):
    entries: tuple[Mapping[str, Any], ...]


@dataclass(frozen=True)
class ValidatedGenerationAuthority(PublishedGeneration):
    """Signed generation authority without a recursive payload census.

    ``entries`` are receipt claims.  Callers may use them to select an exact
    execution closure, but must use :func:`launch_generation_member` for the
    locked, immediate member revalidation or :func:`validate_generation` when
    the complete payload denominator is required.
    """

    generation_policy_sha256: str
    entries: tuple[Mapping[str, Any], ...]


@dataclass(frozen=True)
class GenerationRequest:
    """Canonical, content-derived authority for one generation identity."""

    generation_id: str
    request_sha256: str
    authority_json: bytes


@dataclass(frozen=True)
class ManagedNodeRuntime:
    store_root: Path
    generation_id: str
    generation_path: Path
    payload_path: Path
    node_path: Path
    npm_cli_path: Path
    receipt_sha256: str
    census_sha256: str
    archive_sha256: str
    platform_key: str
    npm_version: str


GENERATION_POLICY_SCHEMA = "plamen.mcp_generation_policy.v1"


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _parse_canonical_json_document(
    raw: bytes, label: str, *, maximum_bytes: int
) -> Any:
    if not isinstance(raw, bytes) or not raw or len(raw) > maximum_bytes:
        raise MCPRuntimeSecurityError(f"{label} bytes are malformed")
    def exact_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise MCPRuntimeSecurityError(f"{label} has duplicate JSON key {key!r}")
            result[key] = value
        return result

    def reject_constant(value: str) -> None:
        raise MCPRuntimeSecurityError(f"{label} has non-finite JSON value {value}")

    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=exact_object,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise MCPRuntimeSecurityError(f"{label} is not strict JSON") from exc
    if raw != _canonical_json(value) + b"\n":
        raise MCPRuntimeSecurityError(f"{label} bytes are not canonical")
    return value


def _canonical_manifest_bytes(raw: bytes, label: str) -> bytes:
    value = _parse_canonical_json_document(
        raw, f"expected {label}", maximum_bytes=64 * 1024 * 1024
    )
    if not isinstance(value, dict):
        raise MCPRuntimeSecurityError(f"expected {label} root is not an object")
    return raw


def _platform_authority() -> dict[str, str]:
    return {
        "os_name": os.name,
        "sys_platform": sys.platform,
        "system": platform.system().lower(),
        "machine": platform.machine().lower(),
    }


def _fs_path(path: os.PathLike[str] | str) -> str:
    """Return an absolute path accepted by long-path Windows APIs."""
    value = os.path.abspath(os.fspath(path))
    if os.name != "nt" or value.startswith("\\\\?\\"):
        return value
    if value.startswith("\\\\"):
        return "\\\\?\\UNC\\" + value[2:]
    return "\\\\?\\" + value


def _display_path(path: os.PathLike[str] | str) -> Path:
    value = os.fspath(path)
    if os.name == "nt" and value.startswith("\\\\?\\UNC\\"):
        value = "\\\\" + value[8:]
    elif os.name == "nt" and value.startswith("\\\\?\\"):
        value = value[4:]
    return Path(value)


def _lstat(path: os.PathLike[str] | str) -> os.stat_result:
    return os.stat(_fs_path(path), follow_symlinks=False)


def _is_reparse(info: os.stat_result) -> bool:
    return bool(
        getattr(info, "st_file_attributes", 0)
        & _FILE_ATTRIBUTE_REPARSE_POINT
    )


def _reject_windows_ambiguous_component(name: str, label: str) -> None:
    if os.name != "nt":
        return
    if (
        not name
        or name != name.rstrip(" .")
        or ":" in name
        or any(ord(character) < 32 for character in name)
        or name.split(".", 1)[0].upper() in _WINDOWS_RESERVED_NAMES
    ):
        raise MCPRuntimeSecurityError(f"{label} is Windows-ambiguous: {name!r}")


def _windows_stream_names(path: Path) -> tuple[str, ...]:
    if _WIN32_FIND_STREAM_DATA is None:
        raise MCPRuntimeSecurityError(
            "Windows alternate stream enumeration is unavailable on this host"
        )
    data = _WIN32_FIND_STREAM_DATA()
    handle = _WINDOWS_FIND_FIRST_STREAM(
        _fs_path(path), 0, ctypes.byref(data), 0
    )
    if handle == _WINDOWS_INVALID_HANDLE_VALUE:
        code = ctypes.get_last_error()
        if code in {2, 18, 38}:  # no streams exposed for an existing directory
            return ()
        raise MCPRuntimeSecurityError(
            f"Windows alternate stream enumeration failed for {path}: {code}"
        )
    names: list[str] = []
    try:
        names.append(str(data.cStreamName))
        while _WINDOWS_FIND_NEXT_STREAM(handle, ctypes.byref(data)):
            names.append(str(data.cStreamName))
        code = ctypes.get_last_error()
        if code not in {0, 18, 38}:
            raise MCPRuntimeSecurityError(
                f"Windows alternate stream enumeration tore for {path}: {code}"
            )
    finally:
        _WINDOWS_FIND_CLOSE(handle)
    return tuple(names)


def _reject_extended_metadata(path: Path, label: str) -> None:
    if os.name == "nt":
        streams = _windows_stream_names(path)
        extras = [name for name in streams if name != "::$DATA"]
        if extras:
            raise MCPRuntimeSecurityError(
                f"{label} has alternate data streams: {extras!r}"
            )
        return
    listxattr = getattr(os, "listxattr", None)
    if listxattr is None:
        raise MCPRuntimeSecurityError(
            f"extended-attribute enumeration is unavailable for {label}"
        )
    try:
        attributes = listxattr(_fs_path(path), follow_symlinks=False)
    except OSError as exc:
        raise MCPRuntimeSecurityError(
            f"extended-attribute enumeration failed for {label}"
        ) from exc
    if attributes:
        raise MCPRuntimeSecurityError(
            f"{label} has extended attributes: {sorted(attributes)!r}"
        )


def _safe_component(value: str, label: str) -> str:
    # Windows canonicalizes reserved device names and trailing dot/space
    # components before ordinary path resolution.  Reject those spellings
    # before applying the portable grammar so every caller gets the same
    # fail-closed check before it can create the store.
    if isinstance(value, str):
        _reject_windows_ambiguous_component(value, label)
    if not isinstance(value, str) or not _GENERATION_RE.fullmatch(value):
        raise MCPRuntimeSecurityError(f"{label} is malformed")
    if value in {".", ".."}:
        raise MCPRuntimeSecurityError(f"{label} is unsafe")
    return value


def _case_key(value: str) -> str:
    return unicodedata.normalize("NFC", value).casefold()


def _reject_case_alias_names(names: Sequence[str], label: str) -> None:
    seen: dict[str, str] = {}
    for name in names:
        key = _case_key(name)
        prior = seen.get(key)
        if prior is not None and prior != name:
            raise MCPRuntimeSecurityError(
                f"{label} contains a cross-platform case alias: {prior!r}, {name!r}"
            )
        if prior is not None:
            raise MCPRuntimeSecurityError(f"{label} contains duplicate name {name!r}")
        seen[key] = name


def _require_plain_directory(path: os.PathLike[str] | str, label: str) -> os.stat_result:
    try:
        info = _lstat(path)
    except FileNotFoundError as exc:
        raise MCPRuntimeSecurityError(f"{label} is missing") from exc
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or _is_reparse(info):
        raise MCPRuntimeSecurityError(f"{label} is not a plain directory")
    _reject_extended_metadata(_display_path(path), label)
    return info


def _require_plain_file(
    path: os.PathLike[str] | str, label: str, *, single_link: bool = True
) -> os.stat_result:
    try:
        info = _lstat(path)
    except FileNotFoundError as exc:
        raise MCPRuntimeSecurityError(f"{label} is missing") from exc
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or _is_reparse(info):
        raise MCPRuntimeSecurityError(f"{label} is not a plain file")
    if single_link and info.st_nlink != 1:
        raise MCPRuntimeSecurityError(f"{label} is hardlinked")
    _reject_extended_metadata(_display_path(path), label)
    return info


def _require_no_link_ancestors(path: Path, label: str) -> None:
    """Reject symlink/reparse indirection in every existing ancestor."""
    absolute = _display_path(os.path.abspath(path))
    anchor = Path(absolute.anchor)
    current = anchor
    parts = absolute.parts[1:] if absolute.anchor else absolute.parts
    for part in parts:
        current = current / part
        if not os.path.lexists(_fs_path(current)):
            break
        info = _lstat(current)
        if stat.S_ISLNK(info.st_mode) or _is_reparse(info):
            raise MCPRuntimeSecurityError(f"{label} has a link/reparse ancestor")


def _mkdir_plain(path: Path, mode: int = 0o700) -> bool:
    created = False
    try:
        os.mkdir(_fs_path(path), mode)
        created = True
    except FileExistsError:
        _require_plain_directory(path, str(path))
    if os.name != "nt":
        os.chmod(_fs_path(path), mode, follow_symlinks=False)
    return created


def _fsync_directory(path: Path) -> None:
    if os.name == "nt":
        # Win32 exposes no portable directory-fsync operation: both
        # FlushFileBuffers and NtFlushBuffersFile reject directory handles.
        # Retain/replay the ordinary directory identity here; publication and
        # quarantine use same-volume MoveFileExW(MOVEFILE_WRITE_THROUGH), while
        # every created regular file is flushed separately.
        _require_plain_directory(path, f"durability directory {path}")
        _durability_event("directory-identity", path)
        return
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    descriptor = os.open(_fs_path(path), flags)
    try:
        os.fsync(descriptor)
        _durability_event("directory-fsync", path)
    finally:
        os.close(descriptor)


def _durability_event(_event: str, _path: Path) -> None:
    """Test instrumentation point; production intentionally does nothing."""


def _fsync_regular_file(path: Path) -> None:
    info = _require_plain_file(path, f"durability file {path}")
    flags = (
        (os.O_RDWR if os.name == "nt" else os.O_RDONLY)
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open(_fs_path(path), flags)
    try:
        opened = os.fstat(descriptor)
        if (
            opened.st_dev != info.st_dev
            or opened.st_ino != info.st_ino
            or opened.st_size != info.st_size
            or opened.st_nlink != 1
        ):
            raise MCPRuntimeSecurityError(f"durability file identity changed: {path}")
        os.fsync(descriptor)
        _durability_event("file-fsync", path)
    finally:
        os.close(descriptor)


def _fsync_tree_bottom_up(root: Path) -> None:
    info = _lstat(root)
    if stat.S_ISLNK(info.st_mode) or _is_reparse(info):
        raise MCPRuntimeSecurityError(f"durability tree root is a link/reparse: {root}")
    if stat.S_ISREG(info.st_mode):
        _fsync_regular_file(root)
        return
    _require_plain_directory(root, f"durability tree directory {root}")
    entries = list(os.scandir(_fs_path(root)))
    _reject_case_alias_names([entry.name for entry in entries], "durability tree")
    for entry in sorted(entries, key=lambda item: item.name.encode("utf-8")):
        _reject_windows_ambiguous_component(entry.name, "durability tree member")
        _fsync_tree_bottom_up(root / entry.name)
    _fsync_directory(root)


def _fsync_control_roots(store_root: Path) -> None:
    _fsync_directory(store_root)
    for name in (".pending", ".staging", ".abandoned", "generations"):
        _fsync_directory(store_root / name)


def _write_exclusive(path: Path, raw: bytes, *, mode: int = 0o600) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    descriptor = os.open(_fs_path(path), flags, mode)
    try:
        view = memoryview(raw)
        while view:
            count = os.write(descriptor, view)
            if count <= 0:
                raise OSError("short exclusive write")
            view = view[count:]
        os.fsync(descriptor)
        _durability_event("file-fsync", path)
    finally:
        os.close(descriptor)
    if os.name != "nt":
        os.chmod(_fs_path(path), mode, follow_symlinks=False)
    _fsync_directory(path.parent)


def _durable_unlink(path: Path) -> None:
    os.unlink(_fs_path(path))
    _durability_event("pending-retired", path)
    _fsync_directory(path.parent)


def _ensure_store(store_root: Path) -> None:
    store_root = _display_path(os.path.abspath(store_root))
    parent = store_root.parent
    if not os.path.lexists(_fs_path(parent)):
        raise MCPRuntimeSecurityError("generation store parent is missing")
    _require_no_link_ancestors(parent, "generation store")
    _require_plain_directory(parent, "generation store parent")
    store_created = _mkdir_plain(store_root)
    _require_no_link_ancestors(store_root, "generation store")
    for name in (".pending", ".staging", ".abandoned", "generations"):
        _mkdir_plain(store_root / name)
    _reject_case_alias_names(
        [entry.name for entry in os.scandir(_fs_path(store_root))],
        "generation store root",
    )
    _fsync_control_roots(store_root)
    if store_created:
        _fsync_directory(parent)


_STORE_LOCK_SHARED = "SHARED"
_STORE_LOCK_EXCLUSIVE = "EXCLUSIVE"
_STORE_LOCK_TIMEOUT_SECONDS = 30.0
_STORE_LOCK_POLL_SECONDS = 0.05
_STORE_LOCK_THREAD_STATE = threading.local()


def _require_existing_store(store_root: Path) -> os.stat_result:
    """Validate the store denominator without creating any filesystem object."""
    store_root = _display_path(os.path.abspath(store_root))
    parent = store_root.parent
    _require_no_link_ancestors(parent, "generation store")
    _require_plain_directory(parent, "generation store parent")
    _require_no_link_ancestors(store_root, "generation store")
    root_info = _require_plain_directory(store_root, "generation store root")
    for name in (".pending", ".staging", ".abandoned", "generations"):
        _require_plain_directory(
            store_root / name, f"generation store control directory {name}"
        )
    _reject_case_alias_names(
        [entry.name for entry in os.scandir(_fs_path(store_root))],
        "generation store root",
    )
    return root_info


def _store_lock_file_snapshot(
    descriptor: int, lock_path: Path, *, allow_empty: bool = False,
) -> tuple[int, int, int, int, int]:
    """Replay the named lock through the retained descriptor."""
    opened_before = os.fstat(descriptor)
    named = _require_plain_file(lock_path, "generation store lock")
    identity = (
        opened_before.st_dev,
        opened_before.st_ino,
        stat.S_IFMT(opened_before.st_mode),
        opened_before.st_nlink,
        opened_before.st_size,
    )
    named_identity = (
        named.st_dev, named.st_ino, stat.S_IFMT(named.st_mode),
        named.st_nlink, named.st_size,
    )
    if identity != named_identity or not stat.S_ISREG(opened_before.st_mode):
        raise MCPRuntimeSecurityError("generation store lock identity changed")
    if opened_before.st_nlink != 1:
        raise MCPRuntimeSecurityError("generation store lock is hardlinked")
    if opened_before.st_size == 0 and not allow_empty:
        raise MCPRuntimeStoreUnavailableError(
            "generation store lock initialization is incomplete"
        )
    if opened_before.st_size not in ({0, 1} if allow_empty else {1}):
        raise MCPRuntimeStoreCorruptError("generation store lock size differs")
    os.lseek(descriptor, 0, os.SEEK_SET)
    raw = os.read(descriptor, 2)
    opened_after = os.fstat(descriptor)
    after_identity = (
        opened_after.st_dev,
        opened_after.st_ino,
        stat.S_IFMT(opened_after.st_mode),
        opened_after.st_nlink,
        opened_after.st_size,
    )
    if after_identity != identity:
        raise MCPRuntimeSecurityError("generation store lock changed while reading")
    if raw != (b"" if allow_empty and opened_before.st_size == 0 else b"\0"):
        raise MCPRuntimeStoreCorruptError("generation store lock content differs")
    return identity


def _store_root_identity(path: Path) -> tuple[int, int, int, int]:
    info = _require_plain_directory(path, "generation store root")
    return (info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode), info.st_nlink)


def _acquire_store_lock(
    descriptor: int, mode: str, *, timeout_seconds: float,
) -> Any:
    deadline = time.monotonic() + timeout_seconds
    if os.name == "nt":
        import msvcrt

        handle_value = msvcrt.get_osfhandle(descriptor)
        if handle_value == -1:
            raise MCPRuntimeSecurityError("generation store lock handle is invalid")
        overlapped = _STORE_LOCK_OVERLAPPED()
        flags = 0x00000001  # LOCKFILE_FAIL_IMMEDIATELY
        if mode == _STORE_LOCK_EXCLUSIVE:
            flags |= 0x00000002  # LOCKFILE_EXCLUSIVE_LOCK
        while True:
            ctypes.set_last_error(0)
            if _STORE_LOCK_FILE_EX(
                handle_value, flags, 0, 1, 0, ctypes.byref(overlapped)
            ):
                return overlapped
            code = ctypes.get_last_error()
            if code != 33:  # ERROR_LOCK_VIOLATION
                raise MCPRuntimeSecurityError(
                    f"generation store LockFileEx failed: {code}"
                )
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise MCPRuntimeStoreBusyError(mode)
            time.sleep(min(_STORE_LOCK_POLL_SECONDS, remaining))
    else:
        import fcntl

        operation = (
            fcntl.LOCK_SH if mode == _STORE_LOCK_SHARED else fcntl.LOCK_EX
        ) | fcntl.LOCK_NB
        while True:
            try:
                fcntl.flock(descriptor, operation)
                return None
            except OSError as exc:
                if exc.errno == errno.EINTR:
                    pass
                elif exc.errno not in {errno.EACCES, errno.EAGAIN}:
                    raise
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise MCPRuntimeStoreBusyError(mode) from exc
                time.sleep(min(_STORE_LOCK_POLL_SECONDS, remaining))


def _release_store_lock(descriptor: int, token: Any) -> None:
    if os.name == "nt":
        import msvcrt

        handle_value = msvcrt.get_osfhandle(descriptor)
        if handle_value == -1:
            raise MCPRuntimeSecurityError("generation store lock handle is invalid")
        if not isinstance(token, _STORE_LOCK_OVERLAPPED):
            raise MCPRuntimeSecurityError("generation store lock token is malformed")
        ctypes.set_last_error(0)
        if not _STORE_UNLOCK_FILE_EX(
            handle_value, 0, 1, 0, ctypes.byref(token)
        ):
            code = ctypes.get_last_error()
            raise MCPRuntimeSecurityError(
                f"generation store UnlockFileEx failed: {code}"
            )
    else:
        import fcntl

        fcntl.flock(descriptor, fcntl.LOCK_UN)


@contextmanager
def _store_lock(
    store_root: Path, *, mode: str, create: bool,
    timeout_seconds: float = _STORE_LOCK_TIMEOUT_SECONDS,
) -> Iterator[None]:
    if mode not in {_STORE_LOCK_SHARED, _STORE_LOCK_EXCLUSIVE}:
        raise MCPRuntimeSecurityError("generation store lock mode differs")
    if type(create) is not bool or (create and mode != _STORE_LOCK_EXCLUSIVE):
        raise MCPRuntimeSecurityError("generation store lock creation policy differs")
    if (
        not isinstance(timeout_seconds, (int, float))
        or isinstance(timeout_seconds, bool)
        or not (0 <= float(timeout_seconds) < float("inf"))
    ):
        raise MCPRuntimeSecurityError("generation store lock timeout differs")
    timeout_seconds = float(timeout_seconds)
    store_root = _display_path(os.path.abspath(store_root))
    root_key = os.path.normcase(os.path.normpath(os.fspath(store_root)))
    held_roots = getattr(_STORE_LOCK_THREAD_STATE, "roots", None)
    if held_roots is None:
        held_roots = set()
        _STORE_LOCK_THREAD_STATE.roots = held_roots
    if root_key in held_roots:
        raise MCPRuntimeSecurityError("generation store same-thread reentry is forbidden")
    held_roots.add(root_key)
    descriptor = -1
    acquired = False
    token: Any = None
    primary: BaseException | None = None
    cleanup_error: BaseException | None = None
    created_lock = False
    root_identity: tuple[int, int, int, int] | None = None
    lock_path = store_root / ".lock"
    try:
        if create:
            _ensure_store(store_root)
        else:
            if not os.path.lexists(_fs_path(store_root)):
                raise MCPRuntimeStoreUnavailableError(
                    "generation store root is missing"
                )
            _require_existing_store(store_root)
        root_identity = _store_root_identity(store_root)
        base_flags = (
            (os.O_RDONLY if mode == _STORE_LOCK_SHARED else os.O_RDWR)
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        if create:
            try:
                descriptor = os.open(
                    _fs_path(lock_path), base_flags | os.O_CREAT | os.O_EXCL, 0o600
                )
                created_lock = True
            except FileExistsError:
                descriptor = os.open(_fs_path(lock_path), base_flags)
        else:
            try:
                descriptor = os.open(_fs_path(lock_path), base_flags)
            except FileNotFoundError as exc:
                raise MCPRuntimeStoreUnavailableError(
                    "generation store lock is missing"
                ) from exc
        os.set_inheritable(descriptor, False)
        if os.get_inheritable(descriptor):
            raise MCPRuntimeSecurityError("generation store lock is inheritable")
        if created_lock:
            # Publish the exact zero-byte recovery state durably before lock
            # acquisition.  A hard kill at any later seam is recoverable only
            # by a create=True writer holding the exclusive byte-range lease.
            _fsync_directory(store_root)
        before_lock = _store_lock_file_snapshot(
            descriptor, lock_path, allow_empty=True,
        )
        token = _acquire_store_lock(
            descriptor, mode, timeout_seconds=timeout_seconds,
        )
        acquired = True
        if _store_root_identity(store_root) != root_identity:
            raise MCPRuntimeSecurityError("generation store root identity changed")
        after_lock = _store_lock_file_snapshot(
            descriptor, lock_path, allow_empty=True,
        )
        if after_lock[:4] != before_lock[:4]:
            raise MCPRuntimeSecurityError("generation store lock identity changed")
        if after_lock[4] == 0:
            if mode != _STORE_LOCK_EXCLUSIVE or not create:
                raise MCPRuntimeStoreUnavailableError(
                    "generation store lock initialization is incomplete"
                )
            os.lseek(descriptor, 0, os.SEEK_SET)
            count = os.write(descriptor, b"\0")
            if count != 1:
                raise MCPRuntimeStoreUnavailableError(
                    "generation store lock initialization was interrupted"
                )
            os.fsync(descriptor)
            _durability_event("file-fsync", lock_path)
            _fsync_directory(store_root)
        _store_lock_file_snapshot(descriptor, lock_path)
        yield
    except BaseException as exc:
        primary = exc
        raise
    finally:
        if acquired:
            try:
                if _store_root_identity(store_root) != root_identity:
                    raise MCPRuntimeSecurityError("generation store root identity changed")
                _store_lock_file_snapshot(descriptor, lock_path)
            except BaseException as exc:
                if primary is not None:
                    primary.add_note(f"generation store post-lock replay failed: {exc}")
                else:
                    cleanup_error = exc
            try:
                _release_store_lock(descriptor, token)
            except BaseException as exc:
                if primary is not None:
                    primary.add_note(f"generation store lock release failed: {exc}")
                elif cleanup_error is not None:
                    cleanup_error.add_note(f"generation store lock release failed: {exc}")
                else:
                    cleanup_error = exc
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except BaseException as exc:
                if primary is not None:
                    primary.add_note(f"generation store lock close failed: {exc}")
                elif cleanup_error is not None:
                    cleanup_error.add_note(f"generation store lock close failed: {exc}")
                else:
                    cleanup_error = exc
        held_roots.discard(root_key)
        if primary is None and cleanup_error is not None:
            raise MCPRuntimeSecurityError(
                "generation store lock cleanup failed"
            ) from cleanup_error


def _read_file_exact(path: Path, expected: os.stat_result) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(_fs_path(path), flags)
    try:
        opened_before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened_before.st_mode)
            or opened_before.st_nlink != 1
            or opened_before.st_dev != expected.st_dev
            or opened_before.st_ino != expected.st_ino
            or opened_before.st_size != expected.st_size
            or stat.S_IMODE(opened_before.st_mode) != stat.S_IMODE(expected.st_mode)
        ):
            raise MCPRuntimeSecurityError(f"file identity changed while opening {path}")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        opened_after = os.fstat(descriptor)
        named_after = _require_plain_file(path, str(path), single_link=False)
        descriptor_signature = lambda row: (
            row.st_dev,
            row.st_ino,
            row.st_size,
            row.st_nlink,
        ) + (() if os.name == "nt" else (stat.S_IMODE(row.st_mode),))
        named_signature = lambda row: (
            row.st_dev,
            row.st_ino,
            row.st_size,
            row.st_nlink,
            stat.S_IMODE(row.st_mode),
        )
        if (
            descriptor_signature(opened_before) != descriptor_signature(opened_after)
            or named_signature(named_after) != named_signature(expected)
            or descriptor_signature(opened_after)[:4] != named_signature(named_after)[:4]
        ):
            raise MCPRuntimeSecurityError(f"file changed during census: {path}")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _digest_file_exact(
    path: Path,
    expected: os.stat_result,
    *,
    required_link_count: int | None = 1,
) -> tuple[int, str]:
    """Stream a file digest while retaining no attacker-sized byte buffer."""
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(_fs_path(path), flags)
    try:
        opened_before = os.fstat(descriptor)
        descriptor_signature = lambda row: (
            row.st_dev,
            row.st_ino,
            row.st_size,
            row.st_nlink,
        ) + (() if os.name == "nt" else (stat.S_IMODE(row.st_mode),))
        named_signature = lambda row: (
            row.st_dev,
            row.st_ino,
            row.st_size,
            row.st_nlink,
            stat.S_IMODE(row.st_mode),
        )
        if (
            not stat.S_ISREG(opened_before.st_mode)
            or (
                required_link_count is not None
                and opened_before.st_nlink != required_link_count
            )
            or descriptor_signature(opened_before)[:4]
            != named_signature(expected)[:4]
        ):
            raise MCPRuntimeSecurityError(f"file identity changed while opening {path}")
        digest = hashlib.sha256()
        size = 0
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            size += len(chunk)
            digest.update(chunk)
        opened_after = os.fstat(descriptor)
        named_after = _require_plain_file(path, str(path), single_link=False)
        if (
            descriptor_signature(opened_before) != descriptor_signature(opened_after)
            or descriptor_signature(opened_after)[:4] != named_signature(named_after)[:4]
            or named_signature(named_after) != named_signature(expected)
            or size != opened_after.st_size
        ):
            raise MCPRuntimeSecurityError(f"file changed during census: {path}")
        return size, digest.hexdigest()
    finally:
        os.close(descriptor)


def _directory_census_identity(info: os.stat_result) -> tuple[int, ...]:
    """Stable identity for one directory during a recursive census.

    NTFS directory ``st_size`` is a lazily refreshed allocation detail, not a
    namespace or object identity.  Windows namespace integrity is instead
    proven by retained object identity plus exact before/after child snapshots.
    POSIX retains size and namespace timestamps in addition to that replay.
    """
    identity = (
        info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode),
        stat.S_IMODE(info.st_mode), info.st_nlink, int(_is_reparse(info)),
    )
    if os.name == "nt":
        return identity
    return identity + (
        info.st_size,
        getattr(info, "st_mtime_ns", int(info.st_mtime * 1_000_000_000)),
        getattr(info, "st_ctime_ns", int(info.st_ctime * 1_000_000_000)),
    )


def _namespace_entry_identity(info: os.stat_result) -> tuple[int, ...]:
    object_type = stat.S_IFMT(info.st_mode)
    identity = (
        info.st_dev, info.st_ino, object_type, stat.S_IMODE(info.st_mode),
        info.st_nlink, int(_is_reparse(info)),
    )
    if stat.S_ISDIR(info.st_mode):
        return _directory_census_identity(info)
    return identity + (
        info.st_size,
        getattr(info, "st_mtime_ns", int(info.st_mtime * 1_000_000_000)),
        getattr(info, "st_ctime_ns", int(info.st_ctime * 1_000_000_000)),
    )


def _census_directory_entries(
    path: Path, relative: str, *, maximum_names: int | None,
) -> tuple[list[tuple[str, os.stat_result]], dict[str, tuple[int, ...]]]:
    entries: list[tuple[str, os.stat_result]] = []
    try:
        with os.scandir(_fs_path(path)) as iterator:
            for entry in iterator:
                if maximum_names is not None and len(entries) >= maximum_names:
                    raise MCPRuntimeSecurityError(
                        "payload census exceeds its row bound"
                    )
                name = entry.name
                _reject_windows_ambiguous_component(name, "payload member")
                if name in {".", ".."} or "/" in name or "\\" in name or "\0" in name:
                    raise MCPRuntimeSecurityError(f"unsafe payload member name: {name!r}")
                entries.append((name, _lstat(path / name)))
    except OSError as exc:
        raise MCPRuntimeSecurityError(
            f"payload directory cannot be enumerated: {relative}"
        ) from exc
    names = [name for name, _info in entries]
    _reject_case_alias_names(names, relative)
    identities = {
        name: _namespace_entry_identity(info) for name, info in entries
    }
    return entries, identities


def _census_tree_once(
    root: Path, *, maximum_rows: int | None = None,
    maximum_file_bytes: int | None = None,
) -> tuple[list[dict[str, Any]], str]:
    root = _display_path(os.path.abspath(root))
    _require_plain_directory(root, "MCP generation payload")
    rows: list[dict[str, Any]] = []
    visited_rows = 0
    visited_file_bytes = 0

    def walk(path: Path, relative: str) -> dict[str, Any]:
        nonlocal visited_rows, visited_file_bytes
        visited_rows += 1
        if maximum_rows is not None and visited_rows > maximum_rows:
            raise MCPRuntimeSecurityError("payload census exceeds its row bound")
        before = _require_plain_directory(path, f"payload directory {relative}")
        remaining = None if maximum_rows is None else maximum_rows - visited_rows
        entries, before_children = _census_directory_entries(
            path, relative, maximum_names=remaining,
        )
        children: list[dict[str, Any]] = []
        for name, info in sorted(
            entries,
            key=lambda item: unicodedata.normalize("NFC", item[0]).encode("utf-8"),
        ):
            child_path = path / name
            child_relative = name if relative == "." else f"{relative}/{name}"
            if stat.S_ISLNK(info.st_mode) or _is_reparse(info):
                raise MCPRuntimeSecurityError(
                    f"payload member is a link or reparse point: {child_relative}"
                )
            if stat.S_ISDIR(info.st_mode):
                child = walk(child_path, child_relative)
            elif stat.S_ISREG(info.st_mode):
                if info.st_nlink != 1:
                    raise MCPRuntimeSecurityError(
                        f"payload member is hardlinked: {child_relative}"
                    )
                visited_rows += 1
                visited_file_bytes += info.st_size
                if maximum_rows is not None and visited_rows > maximum_rows:
                    raise MCPRuntimeSecurityError("payload census exceeds its row bound")
                if (
                    maximum_file_bytes is not None
                    and visited_file_bytes > maximum_file_bytes
                ):
                    raise MCPRuntimeSecurityError("payload census exceeds its byte bound")
                size, digest = _digest_file_exact(child_path, info)
                child = {
                    "path": child_relative,
                    "kind": "file",
                    "size": size,
                    "sha256": digest,
                    "mode": stat.S_IMODE(info.st_mode),
                    "link_count": info.st_nlink,
                    "reparse": False,
                }
                rows.append(child)
            else:
                raise MCPRuntimeSecurityError(
                    f"payload member has unsupported type: {child_relative}"
                )
            children.append(child)
        after = _require_plain_directory(path, f"payload directory {relative}")
        _after_entries, after_children = _census_directory_entries(
            path, relative, maximum_names=len(entries),
        )
        if (
            _directory_census_identity(before) != _directory_census_identity(after)
            or after_children != before_children
        ):
            raise MCPRuntimeSecurityError(
                f"payload directory changed during census: {relative}"
            )
        child_projection = [
            {
                "name": child["path"].rsplit("/", 1)[-1],
                "kind": child["kind"],
                "size": child["size"],
                "sha256": child["sha256"],
                "mode": child["mode"],
                "link_count": child["link_count"],
                "reparse": child["reparse"],
            }
            for child in children
        ]
        row = {
            "path": relative,
            "kind": "directory",
            "size": 0 if os.name == "nt" else after.st_size,
            "sha256": _sha256(_canonical_json(child_projection)),
            "mode": stat.S_IMODE(after.st_mode),
            "link_count": after.st_nlink,
            "reparse": False,
        }
        rows.append(row)
        return row

    walk(root, ".")
    rows.sort(key=lambda row: row["path"].encode("utf-8"))
    return rows, _sha256(_canonical_json(rows))


def _census_tree(
    root: Path, *, maximum_rows: int | None = None,
    maximum_file_bytes: int | None = None,
) -> tuple[list[dict[str, Any]], str]:
    """Return one exact tree authority only after a full recursive replay.

    Per-directory namespace replays close local enumeration races.  This
    second complete pass additionally catches a nested child changing after
    its own replay but before a later ancestor completes on Windows, where
    directory size/timestamps are intentionally not treated as identity.
    Both passes independently enforce the same row and byte bounds.
    """
    first_rows, first_digest = _census_tree_once(
        root, maximum_rows=maximum_rows,
        maximum_file_bytes=maximum_file_bytes,
    )
    replay_rows, replay_digest = _census_tree_once(
        root, maximum_rows=maximum_rows,
        maximum_file_bytes=maximum_file_bytes,
    )
    if replay_rows != first_rows or replay_digest != first_digest:
        raise MCPRuntimeSecurityError("payload changed during full census replay")
    return first_rows, first_digest


def _strict_auth(value: Any) -> dict[str, str]:
    if not isinstance(value, Mapping) or set(value) != {
        "scheme",
        "key_id",
        "signature",
    }:
        raise MCPRuntimeSecurityError("generation receipt authentication is malformed")
    result = {key: value[key] for key in ("scheme", "key_id", "signature")}
    if not all(isinstance(item, str) for item in result.values()):
        raise MCPRuntimeSecurityError("generation receipt authentication types differ")
    if not _AUTH_TOKEN_RE.fullmatch(result["scheme"]):
        raise MCPRuntimeSecurityError("generation receipt authentication scheme differs")
    if not result["key_id"] or len(result["key_id"].encode("utf-8")) > 1024:
        raise MCPRuntimeSecurityError("generation receipt key identity differs")
    try:
        signature_raw = result["signature"].encode("ascii", "strict")
    except UnicodeEncodeError as exc:
        raise MCPRuntimeSecurityError("generation receipt signature differs") from exc
    if not signature_raw or len(signature_raw) > 16384:
        raise MCPRuntimeSecurityError("generation receipt signature differs")
    return result


def _invoke_signer(signer: Signer, authority_raw: bytes) -> dict[str, str]:
    if not callable(signer):
        raise MCPRuntimeSecurityError("an authenticated receipt signer is required")
    try:
        authentication = signer(authority_raw)
    except Exception as exc:
        raise MCPRuntimeSecurityError("generation receipt signing failed") from exc
    return _strict_auth(authentication)


def _invoke_verifier(
    verifier: Verifier, authority_raw: bytes, authentication: Mapping[str, str]
) -> None:
    if not callable(verifier):
        raise MCPRuntimeSecurityError("an authenticated receipt verifier is required")
    try:
        accepted = verifier(authority_raw, authentication)
    except Exception as exc:
        raise MCPRuntimeSecurityError("generation receipt verification failed") from exc
    if accepted is not True:
        raise MCPRuntimeSecurityError("generation receipt signature is not authenticated")


def _receipt_bytes(authority: Mapping[str, Any], signer: Signer) -> tuple[bytes, str]:
    authority_raw = _canonical_json(authority)
    authentication = _invoke_signer(signer, authority_raw)
    unsigned_receipt = {
        "schema": RECEIPT_SCHEMA,
        "authority": authority,
        "authentication": authentication,
    }
    receipt_sha256 = _sha256(_canonical_json(unsigned_receipt))
    receipt = {**unsigned_receipt, "receipt_sha256": receipt_sha256}
    return _canonical_json(receipt) + b"\n", receipt_sha256


_ENTRY_KEYS = {
    "path",
    "kind",
    "size",
    "sha256",
    "mode",
    "link_count",
    "reparse",
}
_AUTHORITY_KEYS = {
    "schema",
    "generation_id",
    "payload_name",
    "census_schema",
    "census_sha256",
    "entries",
    "package_json_sha256",
    "package_lock_sha256",
    "node_executable_authority",
    "npm_executable_authority",
    "npm_version",
    "npm_install_policy",
    "platform_authority",
    "launch_environment_policy",
    "request_sha256",
    "generation_request",
}
_EXECUTABLE_AUTHORITY_KEYS = {
    "canonical_path",
    "size",
    "sha256",
    "mode",
    "link_count",
    "reparse",
}
_GENERATION_REQUEST_KEYS = {
    "schema",
    "census_schema",
    "package_json_sha256",
    "package_lock_sha256",
    "sanitizer_relative_path",
    "sanitizer_sha256",
    "node_executable_authority",
    "npm_executable_authority",
    "npm_version",
    "npm_install_policy",
    "platform_authority",
    "launch_environment_policy",
    "materialization_environment_policy",
    "finalizer_policy",
}
_NPM_INSTALL_POLICY_KEYS = {
    "schema", "command", "flags", "lifecycle_scripts", "audit", "fund",
}
_FINALIZER_POLICY_KEYS = {
    "schema", "output_entrypoint", "require_ordinary_file",
    "require_single_link", "post_npm_actions",
}
_MATERIALIZATION_ENVIRONMENT_POLICY = {
    "schema": "plamen.mcp_materialization_environment.v1",
    "path": "exact-node-and-npm-parent-directories",
    "home": "private-generation-staging",
    "temporary": "private-generation-staging",
    "ambient_npm_config": False,
    "node_loader_injection": False,
    "dynamic_loader_injection": False,
}


def _executable_authority(
    executable: os.PathLike[str] | str,
    label: str,
) -> dict[str, Any]:
    supplied = os.fspath(executable)
    if not supplied or not os.path.isabs(supplied):
        raise MCPRuntimeSecurityError(f"{label} must be an absolute path")
    canonical = _display_path(os.path.realpath(os.path.abspath(supplied)))
    _require_no_link_ancestors(canonical, label)
    info = _require_plain_file(canonical, label, single_link=False)
    size, digest = _digest_file_exact(
        canonical, info, required_link_count=None
    )
    return {
        "canonical_path": os.path.normcase(os.path.abspath(str(canonical))),
        "size": size,
        "sha256": digest,
        "mode": stat.S_IMODE(info.st_mode),
        "link_count": info.st_nlink,
        "reparse": False,
    }


def _node_executable_authority(
    node_executable: os.PathLike[str] | str,
) -> dict[str, Any]:
    return _executable_authority(node_executable, "Node executable")


def _npm_install_policy(flags: Sequence[str]) -> dict[str, Any]:
    exact = tuple(flags)
    if exact != REQUIRED_NPM_INSTALL_FLAGS:
        raise MCPRuntimeSecurityError("npm install flags differ from locked policy")
    return {
        "schema": "plamen.mcp_npm_install_policy.v1",
        "command": "npm",
        "flags": list(exact),
        "lifecycle_scripts": False,
        "audit": False,
        "fund": False,
    }


def _validate_npm_install_policy(value: Any) -> dict[str, Any]:
    expected = _npm_install_policy(REQUIRED_NPM_INSTALL_FLAGS)
    if (
        not isinstance(value, dict)
        or set(value) != _NPM_INSTALL_POLICY_KEYS
        or value.get("schema") != expected["schema"]
        or value.get("command") != "npm"
        or not isinstance(value.get("flags"), list)
        or any(not isinstance(item, str) for item in value["flags"])
        or value["flags"] != expected["flags"]
        or value.get("lifecycle_scripts") is not False
        or value.get("audit") is not False
        or value.get("fund") is not False
    ):
        raise MCPRuntimeSecurityError("npm install policy differs from locked policy")
    if _canonical_json(value) != _canonical_json(expected):
        raise MCPRuntimeSecurityError("npm install policy bytes differ from locked policy")
    return value


def _validate_finalizer_policy(value: Any) -> dict[str, Any]:
    if (
        not isinstance(value, dict)
        or set(value) != _FINALIZER_POLICY_KEYS
        or value.get("schema") != "plamen.mcp_finalizer_policy.v1"
        or not isinstance(value.get("output_entrypoint"), str)
        or value.get("require_ordinary_file") is not True
        or value.get("require_single_link") is not True
        or not isinstance(value.get("post_npm_actions"), list)
    ):
        raise MCPRuntimeSecurityError("generation finalizer policy fields differ")
    output = _safe_relative_entrypoint(value["output_entrypoint"])
    if output != value["output_entrypoint"]:
        raise MCPRuntimeSecurityError("generation finalizer output path differs")
    actions = value["post_npm_actions"]
    if len(actions) > 1:
        raise MCPRuntimeSecurityError("generation post-npm finalizer count differs")
    if actions:
        expected_action = {
            "schema": "plamen.claude_native_finalizer.v1",
            "package": "@anthropic-ai/claude-code",
            "version": "2.1.252",
            "script": "node_modules/@anthropic-ai/claude-code/install.cjs",
            "output": "node_modules/@anthropic-ai/claude-code/bin/claude.exe",
            "probe_args": ["--version"],
        }
        if actions[0] != expected_action:
            raise MCPRuntimeSecurityError("generation post-npm finalizer differs")
    expected = {
        "schema": "plamen.mcp_finalizer_policy.v1",
        "output_entrypoint": output,
        "require_ordinary_file": True,
        "require_single_link": True,
        "post_npm_actions": actions,
    }
    if value != expected or _canonical_json(value) != _canonical_json(expected):
        raise MCPRuntimeSecurityError("generation finalizer policy is not canonical")
    return value


def _normalize_policy_value(value: Any, label: str, *, depth: int = 0) -> Any:
    """Return an immutable-by-copy, strict JSON policy value."""
    if depth > 32:
        raise MCPRuntimeSecurityError(f"{label} nesting is excessive")
    if value is None or type(value) is bool or type(value) is int:
        return value
    if isinstance(value, str):
        if "\0" in value:
            raise MCPRuntimeSecurityError(f"{label} contains NUL")
        return value
    if isinstance(value, (list, tuple)):
        if len(value) > 4096:
            raise MCPRuntimeSecurityError(f"{label} is excessive")
        return [
            _normalize_policy_value(item, label, depth=depth + 1)
            for item in value
        ]
    if isinstance(value, Mapping):
        if len(value) > 4096 or not all(isinstance(key, str) for key in value):
            raise MCPRuntimeSecurityError(f"{label} object is malformed")
        result: dict[str, Any] = {}
        for key in sorted(value):
            if not key or "\0" in key:
                raise MCPRuntimeSecurityError(f"{label} key is malformed")
            result[key] = _normalize_policy_value(
                value[key], label, depth=depth + 1
            )
        return result
    raise MCPRuntimeSecurityError(f"{label} contains a non-JSON policy value")


def _validate_generation_request_authority(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != _GENERATION_REQUEST_KEYS:
        raise MCPRuntimeSecurityError("generation request authority fields are not exact")
    if value["schema"] != GENERATION_REQUEST_SCHEMA:
        raise MCPRuntimeSecurityError("generation request schema differs")
    if value["census_schema"] != CENSUS_SCHEMA:
        raise MCPRuntimeSecurityError("generation request census schema differs")
    for field in (
        "package_json_sha256",
        "package_lock_sha256",
        "sanitizer_sha256",
    ):
        if not isinstance(value[field], str) or not _HEX64_RE.fullmatch(value[field]):
            raise MCPRuntimeSecurityError(f"generation request {field} differs")
    if not isinstance(value["sanitizer_relative_path"], str):
        raise MCPRuntimeSecurityError("generation request sanitizer path differs")
    sanitizer_path = _safe_relative_entrypoint(value["sanitizer_relative_path"])
    if sanitizer_path != value["sanitizer_relative_path"]:
        raise MCPRuntimeSecurityError("generation request sanitizer path differs")
    _validate_executable_receipt(value["node_executable_authority"], "request Node")
    _validate_executable_receipt(value["npm_executable_authority"], "request npm")
    if (
        not isinstance(value["npm_version"], str)
        or not _PINNED_VERSION_RE.fullmatch(value["npm_version"])
        or value["platform_authority"] != _platform_authority()
        or value["launch_environment_policy"] != _LAUNCH_ENVIRONMENT_POLICY
        or value["materialization_environment_policy"] != _MATERIALIZATION_ENVIRONMENT_POLICY
    ):
        raise MCPRuntimeSecurityError("generation request install/launch policy differs")
    _validate_npm_install_policy(value["npm_install_policy"])
    finalizer = _validate_finalizer_policy(value["finalizer_policy"])
    if len(_canonical_json(value)) > 1024 * 1024:
        raise MCPRuntimeSecurityError("generation request authority is excessive")
    return value


def _request_from_authority(authority: Mapping[str, Any]) -> GenerationRequest:
    normalized = _validate_generation_request_authority(dict(authority))
    authority_json = _canonical_json(normalized)
    request_sha256 = _sha256(authority_json)
    return GenerationRequest(
        generation_id="npm-" + request_sha256,
        request_sha256=request_sha256,
        authority_json=authority_json,
    )


def derive_generation_request(
    *,
    expected_package_json_bytes: bytes,
    expected_package_lock_bytes: bytes,
    sanitizer_bytes: bytes,
    sanitizer_relative_path: str,
    node_executable: os.PathLike[str] | str,
    npm_executable: os.PathLike[str] | str,
    npm_version: str,
    npm_install_flags: Sequence[str],
    finalizer_policy: Mapping[str, Any],
) -> GenerationRequest:
    """Derive the sole permitted generation identity from exact authorities.

    Callers must pass this object back to :func:`stage_npm_generation`; the
    stage operation recomputes and cross-binds every field, so an integration
    cannot substitute a friendly/version label for the content authority.
    """
    package_bytes = _canonical_manifest_bytes(
        expected_package_json_bytes, "package.json"
    )
    lock_bytes = _canonical_manifest_bytes(
        expected_package_lock_bytes, "package-lock.json"
    )
    if not isinstance(sanitizer_bytes, bytes) or not sanitizer_bytes:
        raise MCPRuntimeSecurityError("sanitizer bytes are empty or malformed")
    if len(sanitizer_bytes) > 64 * 1024 * 1024:
        raise MCPRuntimeSecurityError("sanitizer bytes are excessive")
    sanitizer_path = _safe_relative_entrypoint(sanitizer_relative_path)
    if not isinstance(npm_version, str) or not _PINNED_VERSION_RE.fullmatch(npm_version):
        raise MCPRuntimeSecurityError("npm version is not exactly pinned")
    finalizer = _validate_finalizer_policy(
        _normalize_policy_value(finalizer_policy, "generation finalizer policy")
    )
    authority = {
        "schema": GENERATION_REQUEST_SCHEMA,
        "census_schema": CENSUS_SCHEMA,
        "package_json_sha256": _sha256(package_bytes),
        "package_lock_sha256": _sha256(lock_bytes),
        "sanitizer_relative_path": sanitizer_path,
        "sanitizer_sha256": _sha256(sanitizer_bytes),
        "node_executable_authority": _node_executable_authority(node_executable),
        "npm_executable_authority": _executable_authority(
            npm_executable, "npm executable"
        ),
        "npm_version": npm_version,
        "npm_install_policy": _npm_install_policy(npm_install_flags),
        "platform_authority": _platform_authority(),
        "launch_environment_policy": _LAUNCH_ENVIRONMENT_POLICY,
        "materialization_environment_policy": _MATERIALIZATION_ENVIRONMENT_POLICY,
        "finalizer_policy": finalizer,
    }
    return _request_from_authority(authority)


def _replay_generation_request(value: GenerationRequest) -> dict[str, Any]:
    if not isinstance(value, GenerationRequest):
        raise MCPRuntimeSecurityError("an exact generation request is required")
    if not isinstance(value.authority_json, bytes):
        raise MCPRuntimeSecurityError("generation request bytes are malformed")
    try:
        authority = json.loads(value.authority_json.decode("utf-8"))
    except (AttributeError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise MCPRuntimeSecurityError("generation request bytes are malformed") from exc
    if _canonical_json(authority) != value.authority_json:
        raise MCPRuntimeSecurityError("generation request bytes are not canonical")
    replayed = _request_from_authority(authority)
    if replayed != value:
        raise MCPRuntimeSecurityError("generation request identity differs")
    return authority


def generation_policy_sha256(value: GenerationRequest) -> str:
    """Digest the execution/install policy subset of a generation request."""
    authority = _replay_generation_request(value)
    policy = {
        "schema": GENERATION_POLICY_SCHEMA,
        "census_schema": authority["census_schema"],
        "sanitizer_relative_path": authority["sanitizer_relative_path"],
        "sanitizer_sha256": authority["sanitizer_sha256"],
        "node_executable_authority": authority["node_executable_authority"],
        "npm_executable_authority": authority["npm_executable_authority"],
        "npm_version": authority["npm_version"],
        "npm_install_policy": authority["npm_install_policy"],
        "platform_authority": authority["platform_authority"],
        "launch_environment_policy": authority["launch_environment_policy"],
        "materialization_environment_policy": authority["materialization_environment_policy"],
        "finalizer_policy": authority["finalizer_policy"],
    }
    return _sha256(_canonical_json(policy))


def materialization_environment(
    node_executable: os.PathLike[str] | str,
    npm_executable: os.PathLike[str] | str,
    private_root: os.PathLike[str] | str,
    *,
    source_env: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Construct the sole admitted npm/finalizer environment."""
    node = _node_executable_authority(node_executable)
    npm = _executable_authority(npm_executable, "npm executable")
    root = Path(os.path.abspath(os.fspath(private_root)))
    _require_no_link_ancestors(root, "materialization private root")
    root.mkdir(parents=True, exist_ok=True)
    private_home = root / ".plamen-home"
    private_temp = root / ".plamen-temp"
    private_home.mkdir(exist_ok=True); private_temp.mkdir(exist_ok=True)
    supplied = os.environ if source_env is None else source_env
    if not isinstance(supplied, Mapping):
        raise MCPRuntimeSecurityError("materialization source environment is malformed")
    retained = {}
    for name in ("SYSTEMROOT", "COMSPEC", "PATHEXT"):
        value = supplied.get(name)
        if isinstance(value, str) and value and "\0" not in value:
            retained[name] = value
    path_rows = []
    for authority in (node, npm):
        parent = str(Path(authority["canonical_path"]).parent)
        if os.path.normcase(parent) not in {os.path.normcase(item) for item in path_rows}:
            path_rows.append(parent)
    retained.update({
        "PATH": os.pathsep.join(path_rows),
        "HOME": str(private_home), "USERPROFILE": str(private_home),
        "TEMP": str(private_temp), "TMP": str(private_temp), "TMPDIR": str(private_temp),
    })
    return retained


def finalize_claude_native(
    payload_root: os.PathLike[str] | str,
    *,
    version: str,
    node_executable: os.PathLike[str] | str,
    environment: Mapping[str, str],
    runner: Callable[..., Any] = subprocess.run,
    managed_node: ManagedNodeRuntime | None = None,
    verifier: Verifier | None = None,
) -> dict[str, Any]:
    """Execute and verify the sole request-bound post-npm lifecycle action."""
    if version != "2.1.252":
        raise MCPRuntimeSecurityError("Claude native finalizer version differs")
    if any(
        key.upper() in {"NODE_OPTIONS", "NODE_PATH"}
        or key.upper().startswith(("NPM_CONFIG_", "LD_", "DYLD_"))
        for key in environment
    ):
        raise MCPRuntimeSecurityError("Claude native finalizer environment differs")
    node = _node_executable_authority(node_executable)
    payload = Path(os.path.abspath(os.fspath(payload_root)))
    package = payload / "node_modules" / "@anthropic-ai" / "claude-code"
    script = package / "install.cjs"
    output = package / "bin" / "claude.exe"
    _require_plain_file(script, "Claude native finalizer script")
    if managed_node is not None:
        if verifier is None or Path(node["canonical_path"]) != managed_node.node_path:
            raise MCPRuntimeSecurityError("Claude finalizer managed Node authority differs")
        result = run_managed_node(
            managed_node, [str(_display_path(script))], verifier=verifier,
            cwd=package, environment=environment, runner=runner, timeout=120,
            capture_output=True, text=True,
        )
    else:
        result = runner(
            [node["canonical_path"], str(_display_path(script))], cwd=package,
            capture_output=True, text=True, timeout=120, env=dict(environment),
        )
    if result.returncode != 0:
        raise MCPRuntimeSecurityError("Claude native finalizer script failed")
    info = _require_plain_file(output, "Claude native finalizer output", single_link=False)
    if info.st_nlink != 1:
        temporary = output.with_name(".claude.detached-" + secrets.token_hex(16))
        try:
            descriptor = os.open(_fs_path(temporary), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "wb") as destination, open(_fs_path(output), "rb") as source:
                while True:
                    block = source.read(1024 * 1024)
                    if not block:
                        break
                    destination.write(block)
                destination.flush(); os.fsync(destination.fileno())
            os.chmod(_fs_path(temporary), stat.S_IMODE(info.st_mode))
            os.replace(_fs_path(temporary), _fs_path(output))
            _fsync_directory(output.parent)
        finally:
            try:
                os.unlink(_fs_path(temporary))
            except FileNotFoundError:
                pass
    info = _require_plain_file(output, "Claude native finalizer output")
    size, digest = _digest_file_exact(output, info)
    probe = runner(
        [str(_display_path(output)), "--version"], capture_output=True, text=True,
        timeout=60, env=dict(environment),
    )
    if probe.returncode != 0 or version not in ((probe.stdout or "") + (probe.stderr or "")):
        raise MCPRuntimeSecurityError("Claude native finalized version differs")
    return {"relative_path": "node_modules/@anthropic-ai/claude-code/bin/claude.exe",
            "version": version, "size": size, "sha256": digest, "link_count": info.st_nlink}


def _validate_executable_receipt(value: Any, label: str) -> None:
    if (
        not isinstance(value, dict)
        or set(value) != _EXECUTABLE_AUTHORITY_KEYS
        or not isinstance(value["canonical_path"], str)
        or not os.path.isabs(value["canonical_path"])
        or type(value["size"]) is not int
        or value["size"] < 0
        or not isinstance(value["sha256"], str)
        or not _HEX64_RE.fullmatch(value["sha256"])
        or type(value["mode"]) is not int
        or not 0 <= value["mode"] <= 0o7777
        or type(value["link_count"]) is not int
        or value["link_count"] < 1
        or value["reparse"] is not False
    ):
        raise MCPRuntimeSecurityError(f"generation receipt {label} authority differs")


def _parse_receipt(raw: bytes, generation_id: str, verifier: Verifier) -> dict[str, Any]:
    value = _parse_canonical_json_document(
        raw, "generation receipt", maximum_bytes=_MAX_RECEIPT_BYTES
    )
    if not isinstance(value, dict) or set(value) != {
        "schema",
        "authority",
        "authentication",
        "receipt_sha256",
    }:
        raise MCPRuntimeSecurityError("generation receipt fields are not exact")
    if value["schema"] != RECEIPT_SCHEMA or not _HEX64_RE.fullmatch(
        value.get("receipt_sha256", "") if isinstance(value.get("receipt_sha256"), str) else ""
    ):
        raise MCPRuntimeSecurityError("generation receipt header differs")
    authority = value["authority"]
    if not isinstance(authority, dict) or set(authority) != _AUTHORITY_KEYS:
        raise MCPRuntimeSecurityError("generation receipt authority fields are not exact")
    if (
        authority["schema"] != RECEIPT_SCHEMA
        or authority["generation_id"] != generation_id
        or authority["payload_name"] != PAYLOAD_NAME
        or authority["census_schema"] != CENSUS_SCHEMA
    ):
        raise MCPRuntimeSecurityError("generation receipt authority identity differs")
    for field in (
        "census_sha256",
        "package_json_sha256",
        "package_lock_sha256",
        "request_sha256",
    ):
        if not isinstance(authority[field], str) or not _HEX64_RE.fullmatch(authority[field]):
            raise MCPRuntimeSecurityError(f"generation receipt {field} differs")
    _validate_executable_receipt(authority["node_executable_authority"], "Node")
    _validate_executable_receipt(authority["npm_executable_authority"], "npm")
    if (
        not isinstance(authority["npm_version"], str)
        or not _PINNED_VERSION_RE.fullmatch(authority["npm_version"])
        or authority["platform_authority"] != _platform_authority()
        or authority["launch_environment_policy"] != _LAUNCH_ENVIRONMENT_POLICY
    ):
        raise MCPRuntimeSecurityError("generation receipt install/launch policy differs")
    _validate_npm_install_policy(authority["npm_install_policy"])
    request_authority = _validate_generation_request_authority(
        authority["generation_request"]
    )
    request = _request_from_authority(request_authority)
    if (
        request.generation_id != generation_id
        or request.request_sha256 != authority["request_sha256"]
        or authority["census_schema"] != request_authority["census_schema"]
        or authority["package_json_sha256"]
        != request_authority["package_json_sha256"]
        or authority["package_lock_sha256"]
        != request_authority["package_lock_sha256"]
        or authority["node_executable_authority"]
        != request_authority["node_executable_authority"]
        or authority["npm_executable_authority"]
        != request_authority["npm_executable_authority"]
        or authority["npm_version"] != request_authority["npm_version"]
        or authority["npm_install_policy"]
        != request_authority["npm_install_policy"]
        or authority["platform_authority"]
        != request_authority["platform_authority"]
        or authority["launch_environment_policy"]
        != request_authority["launch_environment_policy"]
    ):
        raise MCPRuntimeSecurityError("generation receipt request authority differs")
    entries = authority["entries"]
    if not isinstance(entries, list) or not entries:
        raise MCPRuntimeSecurityError("generation receipt census is empty")
    paths: list[str] = []
    for row in entries:
        if not isinstance(row, dict) or set(row) != _ENTRY_KEYS:
            raise MCPRuntimeSecurityError("generation receipt census row is malformed")
        if (
            not isinstance(row["path"], str)
            or not isinstance(row["kind"], str)
            or row["kind"] not in {"file", "directory"}
            or type(row["size"]) is not int
            or row["size"] < 0
            or not isinstance(row["sha256"], str)
            or not _HEX64_RE.fullmatch(row["sha256"])
            or type(row["mode"]) is not int
            or row["mode"] < 0
            or row["mode"] > 0o7777
            or type(row["link_count"]) is not int
            or row["link_count"] < 1
            or row["reparse"] is not False
        ):
            raise MCPRuntimeSecurityError("generation receipt census row types differ")
        parts = row["path"].split("/")
        if row["path"] != "." and (
            row["path"].startswith("/")
            or "\\" in row["path"]
            or any(part in {"", ".", ".."} for part in parts)
        ):
            raise MCPRuntimeSecurityError("generation receipt census path is unsafe")
        if row["path"] != ".":
            for part in parts:
                _reject_windows_ambiguous_component(part, "receipt census component")
        if row["kind"] == "file" and row["link_count"] != 1:
            raise MCPRuntimeSecurityError("generation receipt admits a hardlinked file")
        paths.append(row["path"])
    if paths != sorted(paths, key=lambda item: item.encode("utf-8")) or len(paths) != len(set(paths)):
        raise MCPRuntimeSecurityError("generation receipt census order differs")
    _reject_case_alias_names(paths, "generation receipt census")
    root_rows = [row for row in entries if row["path"] == "."]
    if len(root_rows) != 1 or root_rows[0]["kind"] != "directory":
        raise MCPRuntimeSecurityError("generation receipt census root differs")
    if _sha256(_canonical_json(entries)) != authority["census_sha256"]:
        raise MCPRuntimeSecurityError("generation receipt census digest differs")
    authentication = _strict_auth(value["authentication"])
    unsigned_receipt = {
        "schema": value["schema"],
        "authority": authority,
        "authentication": authentication,
    }
    if _sha256(_canonical_json(unsigned_receipt)) != value["receipt_sha256"]:
        raise MCPRuntimeSecurityError("generation receipt self-digest differs")
    _invoke_verifier(verifier, _canonical_json(authority), authentication)
    return value


def _atomic_rename_noreplace(source: Path, destination: Path) -> None:
    source_info = _lstat(source)
    source_parent_info = _require_plain_directory(
        source.parent, "atomic rename source parent"
    )
    destination_parent_info = _require_plain_directory(
        destination.parent, "atomic rename destination parent"
    )
    if source_info.st_dev != destination_parent_info.st_dev:
        raise MCPRuntimeSecurityError("atomic rename would cross filesystems")
    parent_identity = lambda info: (
        info.st_dev,
        info.st_ino,
        stat.S_IFMT(info.st_mode),
        int(_is_reparse(info)),
        int(getattr(info, "st_file_attributes", 0)),
    )
    source_parent_identity = parent_identity(source_parent_info)
    destination_parent_identity = parent_identity(destination_parent_info)
    source_raw = _fs_path(source)
    destination_raw = _fs_path(destination)
    if os.name == "nt":
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.MoveFileExW.argtypes = [
            wintypes.LPCWSTR,
            wintypes.LPCWSTR,
            wintypes.DWORD,
        ]
        kernel32.MoveFileExW.restype = wintypes.BOOL
        if not kernel32.MoveFileExW(source_raw, destination_raw, 0x00000008):
            code = ctypes.get_last_error()
            if os.path.lexists(destination_raw):
                raise FileExistsError(code, "generation already exists", str(destination))
            raise OSError(code, "atomic generation publication failed", str(destination))
        _durability_event("rename-noreplace-write-through", destination)
    else:
        libc = ctypes.CDLL(None, use_errno=True)
        source_bytes = os.fsencode(source_raw)
        destination_bytes = os.fsencode(destination_raw)
        if sys.platform.startswith("linux"):
            function = getattr(libc, "renameat2", None)
            if function is None:
                raise MCPRuntimeSecurityError("atomic no-replace rename is unavailable")
            function.argtypes = [
                ctypes.c_int,
                ctypes.c_char_p,
                ctypes.c_int,
                ctypes.c_char_p,
                ctypes.c_uint,
            ]
            function.restype = ctypes.c_int
            result = function(-100, source_bytes, -100, destination_bytes, 1)
        elif sys.platform == "darwin":
            function = getattr(libc, "renamex_np", None)
            if function is None:
                raise MCPRuntimeSecurityError("atomic no-replace rename is unavailable")
            function.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint]
            function.restype = ctypes.c_int
            result = function(source_bytes, destination_bytes, 0x00000004)
        else:
            raise MCPRuntimeSecurityError(
                "atomic no-replace directory rename is unsupported on this POSIX platform"
            )
        if result != 0:
            code = ctypes.get_errno()
            if code in {errno.EEXIST, errno.ENOTEMPTY}:
                raise FileExistsError(code, "generation already exists", str(destination))
            raise OSError(code, "atomic generation publication failed", str(destination))
        _fsync_directory(destination.parent)
        _durability_event("rename-noreplace", destination)
    if os.path.lexists(source_raw) or not os.path.lexists(destination_raw):
        raise MCPRuntimeSecurityError("atomic rename postcondition differs")
    destination_info = _lstat(destination)
    if _root_object_identity(destination_info) != _root_object_identity(source_info):
        raise MCPRuntimeSecurityError("atomic rename object identity changed")
    if (
        parent_identity(_require_plain_directory(source.parent, "atomic rename source parent"))
        != source_parent_identity
        or parent_identity(
            _require_plain_directory(destination.parent, "atomic rename destination parent")
        )
        != destination_parent_identity
    ):
        raise MCPRuntimeSecurityError("atomic rename parent identity changed")
    _fsync_directory(source.parent)
    if os.path.normcase(str(source.parent)) != os.path.normcase(str(destination.parent)):
        _fsync_directory(destination.parent)


def _pending_payload(txn_id: str, generation_id: str) -> dict[str, Any]:
    unsigned = {
        "schema": PENDING_SCHEMA,
        "transaction_id": txn_id,
        "generation_id": generation_id,
        "staging_name": txn_id,
    }
    return {**unsigned, "pending_sha256": _sha256(_canonical_json(unsigned))}


def _parse_pending(path: Path) -> dict[str, Any]:
    info = _require_plain_file(path, "MCP pending transaction")
    if info.st_size > 16 * 1024:
        raise MCPRuntimeSecurityError("MCP pending transaction exceeds its bound")
    raw = _read_file_exact(path, info)
    value = _parse_canonical_json_document(
        raw, "MCP pending transaction", maximum_bytes=16 * 1024
    )
    if not isinstance(value, dict) or set(value) != {
        "schema",
        "transaction_id",
        "generation_id",
        "staging_name",
        "pending_sha256",
    }:
        raise MCPRuntimeSecurityError("MCP pending transaction fields are not exact")
    if (
        value["schema"] != PENDING_SCHEMA
        or not isinstance(value["transaction_id"], str)
        or not _TXN_RE.fullmatch(value["transaction_id"])
        or value["staging_name"] != value["transaction_id"]
        or not isinstance(value["generation_id"], str)
        or not _GENERATION_RE.fullmatch(value["generation_id"])
        or not isinstance(value["pending_sha256"], str)
        or not _HEX64_RE.fullmatch(value["pending_sha256"])
    ):
        raise MCPRuntimeSecurityError("MCP pending transaction identity differs")
    _safe_component(value["generation_id"], "pending generation identity")
    unsigned = {key: value[key] for key in value if key != "pending_sha256"}
    if _sha256(_canonical_json(unsigned)) != value["pending_sha256"]:
        raise MCPRuntimeSecurityError("MCP pending transaction digest differs")
    if path.name != value["transaction_id"] + ".json":
        raise MCPRuntimeSecurityError("MCP pending transaction filename differs")
    return value


def _list_plain_names(path: Path, label: str) -> list[str]:
    _require_plain_directory(path, label)
    names = [entry.name for entry in os.scandir(_fs_path(path))]
    _reject_case_alias_names(names, label)
    return names


def _assert_no_pending(store_root: Path) -> None:
    pending = _list_plain_names(store_root / ".pending", "MCP pending directory")
    staged = _list_plain_names(store_root / ".staging", "MCP staging directory")
    if pending or staged:
        raise MCPRuntimeSecurityError(
            "incomplete MCP generation transaction; recover before launching Node"
        )


def _generation_path(store_root: Path, generation_id: str) -> Path:
    return store_root / "generations" / _safe_component(
        generation_id, "generation identity"
    )


def _managed_node_platform_key() -> str:
    system = platform.system().lower()
    machine = platform.machine().lower()
    os_key = {"windows": "windows", "linux": "linux", "darwin": "darwin"}.get(system)
    arch_key = {
        "amd64": "x64", "x86_64": "x64", "x64": "x64",
        "arm64": "arm64", "aarch64": "arm64",
    }.get(machine)
    key = f"{os_key}-{arch_key}" if os_key and arch_key else ""
    if key not in MANAGED_NODE_ARCHIVES:
        raise MCPRuntimeSecurityError(
            f"Node {MANAGED_NODE_VERSION} has no reviewed archive for {system}/{machine}"
        )
    return key


def _managed_node_generation_id(platform_key: str) -> str:
    row = MANAGED_NODE_ARCHIVES[platform_key]
    return (
        f"node-{MANAGED_NODE_VERSION}-{platform_key}-census2-"
        f"{row['sha256'][:24]}"
    )


def _managed_node_download(url: str, maximum_bytes: int) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "Plamen-managed-node/1"})
    with urllib.request.urlopen(request, timeout=120) as response:
        if response.geturl() != url:
            raise MCPRuntimeSecurityError("managed Node archive redirected")
        length = response.headers.get("Content-Length")
        if length is not None and (not length.isdigit() or int(length) > maximum_bytes):
            raise MCPRuntimeSecurityError("managed Node archive length is excessive")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = response.read(min(1024 * 1024, maximum_bytes + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            if total > maximum_bytes:
                raise MCPRuntimeSecurityError("managed Node archive is excessive")
            chunks.append(chunk)
    return b"".join(chunks)


def _managed_archive_relative(name: str, archive_root: str) -> str | None:
    if not isinstance(name, str) or not name or "\\" in name or "\0" in name:
        raise MCPRuntimeSecurityError("managed Node archive path is malformed")
    normalized = name[:-1] if name.endswith("/") else name
    parts = normalized.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise MCPRuntimeSecurityError("managed Node archive path is unsafe")
    for part in parts:
        _reject_windows_ambiguous_component(part, "managed Node archive component")
    if parts[0] != archive_root:
        raise MCPRuntimeSecurityError("managed Node archive root differs")
    return "/".join(parts[1:]) or None


def _managed_node_selected(relative: str | None, archive: Mapping[str, str]) -> bool:
    if relative is None:
        return False
    npm_root = archive["npm_cli"].rsplit("/bin/npm-cli.js", 1)[0]
    return relative == archive["node"] or relative == npm_root or relative.startswith(npm_root + "/")


def _extract_managed_node_archive(
    raw: bytes, destination: Path, archive: Mapping[str, str],
) -> None:
    """Extract only Node plus npm's complete bundled implementation closure."""
    if _sha256(raw) != archive["sha256"]:
        raise MCPRuntimeSecurityError("managed Node archive digest differs")
    maximum_members = 20000
    maximum_expanded = 768 * 1024 * 1024
    files: list[tuple[str, int, int, Callable[[], bytes]]] = []
    explicit_directories: dict[str, int] = {}
    seen_all: list[str] = []
    if archive["format"] == "zip":
        holder = zipfile.ZipFile(io.BytesIO(raw), "r")
        members = holder.infolist()
        if len(members) > maximum_members:
            holder.close(); raise MCPRuntimeSecurityError("managed Node archive has excessive members")
        for item in members:
            relative = _managed_archive_relative(item.filename, archive["archive_root"])
            if relative is not None:
                seen_all.append(relative)
            unix_mode = (item.external_attr >> 16) & 0xFFFF
            if stat.S_ISLNK(unix_mode):
                if _managed_node_selected(relative, archive):
                    holder.close(); raise MCPRuntimeSecurityError("managed npm closure contains a link")
                continue
            if item.flag_bits & 0x1:
                holder.close(); raise MCPRuntimeSecurityError("managed Node archive is encrypted")
            if not _managed_node_selected(relative, archive):
                continue
            mode = stat.S_IMODE(unix_mode) if unix_mode else 0o755
            if item.is_dir():
                explicit_directories[relative] = mode or 0o755
            else:
                if item.file_size < 0:
                    holder.close(); raise MCPRuntimeSecurityError("managed Node member size differs")
                files.append((relative, item.file_size, mode or 0o644,
                              lambda item=item: holder.read(item)))
    else:
        holder = tarfile.open(fileobj=io.BytesIO(raw), mode="r:*")
        members = holder.getmembers()
        if len(members) > maximum_members:
            holder.close(); raise MCPRuntimeSecurityError("managed Node archive has excessive members")
        for item in members:
            relative = _managed_archive_relative(item.name, archive["archive_root"])
            if relative is not None:
                seen_all.append(relative)
            if not _managed_node_selected(relative, archive):
                continue
            if item.issym() or item.islnk():
                holder.close(); raise MCPRuntimeSecurityError("managed npm closure contains a link")
            if item.isdir():
                explicit_directories[relative] = stat.S_IMODE(item.mode) or 0o755
            elif item.isfile():
                def read_tar(item=item):
                    stream = holder.extractfile(item)
                    if stream is None:
                        raise MCPRuntimeSecurityError("managed Node archive member is unreadable")
                    return stream.read()
                files.append((relative, item.size, stat.S_IMODE(item.mode) or 0o644, read_tar))
            else:
                holder.close(); raise MCPRuntimeSecurityError("managed npm closure contains a special member")
    _reject_case_alias_names(seen_all, "managed Node archive")
    selected_names = [name for name, _size, _mode, _reader in files]
    _reject_case_alias_names(selected_names, "managed Node selected closure")
    if len(selected_names) != len(set(selected_names)):
        holder.close(); raise MCPRuntimeSecurityError("managed Node archive has duplicate members")
    if sum(size for _name, size, _mode, _reader in files) > maximum_expanded:
        holder.close(); raise MCPRuntimeSecurityError("managed Node archive expansion is excessive")
    required = {archive["node"], archive["npm_cli"]}
    if not required.issubset(selected_names):
        holder.close(); raise MCPRuntimeSecurityError("managed Node archive omits Node/npm entrypoints")
    directories = {"."}
    for name in selected_names:
        parts = name.split("/")[:-1]
        directories.update("/".join(parts[:index]) for index in range(1, len(parts) + 1))
    for relative in sorted(directories - {"."}, key=lambda item: (item.count("/"), item)):
        path = destination.joinpath(*relative.split("/"))
        _mkdir_plain(path, explicit_directories.get(relative, 0o755))
    try:
        for relative, expected_size, mode, reader in sorted(files, key=lambda row: row[0]):
            payload = reader()
            if len(payload) != expected_size:
                raise MCPRuntimeSecurityError("managed Node archive member length differs")
            output = destination.joinpath(*relative.split("/"))
            _write_exclusive(output, payload, mode=mode)
    finally:
        holder.close()


_MANAGED_NODE_AUTHORITY_KEYS = frozenset({
    "schema", "generation_id", "node_version", "npm_version", "platform_key",
    "archive", "extraction_policy", "node_relative_path", "npm_cli_relative_path",
    "census_sha256", "entries",
})


def _managed_node_receipt_bytes(authority: Mapping[str, Any], signer: Signer) -> tuple[bytes, str]:
    authentication = _invoke_signer(signer, _canonical_json(authority))
    unsigned = {
        "schema": MANAGED_NODE_RECEIPT_SCHEMA,
        "authority": authority,
        "authentication": authentication,
    }
    digest = _sha256(_canonical_json(unsigned))
    return _canonical_json({**unsigned, "receipt_sha256": digest}) + b"\n", digest


def _parse_managed_node_receipt(
    raw: bytes, generation_id: str, verifier: Verifier,
) -> dict[str, Any]:
    value = _parse_canonical_json_document(
        raw, "managed Node receipt", maximum_bytes=_MAX_RECEIPT_BYTES,
    )
    if not isinstance(value, dict) or set(value) != {
        "schema", "authority", "authentication", "receipt_sha256",
    }:
        raise MCPRuntimeSecurityError("managed Node receipt fields differ")
    authority = value["authority"]
    if (
        value["schema"] != MANAGED_NODE_RECEIPT_SCHEMA
        or not isinstance(authority, dict) or set(authority) != _MANAGED_NODE_AUTHORITY_KEYS
        or authority["schema"] != MANAGED_NODE_RECEIPT_SCHEMA
        or authority["generation_id"] != generation_id
        or authority["node_version"] != MANAGED_NODE_VERSION
        or authority["npm_version"] != MANAGED_NPM_VERSION
        or authority["extraction_policy"] != "official-archive-node+npm-complete-v1"
        or not isinstance(authority["entries"], list) or not authority["entries"]
        or not isinstance(authority["census_sha256"], str)
        or not _HEX64_RE.fullmatch(authority["census_sha256"])
    ):
        raise MCPRuntimeSecurityError("managed Node receipt authority differs")
    platform_key = _managed_node_platform_key()
    reviewed = MANAGED_NODE_ARCHIVES[platform_key]
    expected_archive = {
        "url": f"https://nodejs.org/dist/v{MANAGED_NODE_VERSION}/{reviewed['filename']}",
        **dict(reviewed),
    }
    if (
        authority["platform_key"] != platform_key
        or authority["archive"] != expected_archive
        or authority["node_relative_path"] != reviewed["node"]
        or authority["npm_cli_relative_path"] != reviewed["npm_cli"]
        or _sha256(_canonical_json(authority["entries"])) != authority["census_sha256"]
    ):
        raise MCPRuntimeSecurityError("managed Node reviewed-content authority differs")
    authentication = _strict_auth(value["authentication"])
    unsigned = {"schema": value["schema"], "authority": authority,
                "authentication": authentication}
    if (
        not isinstance(value["receipt_sha256"], str)
        or _sha256(_canonical_json(unsigned)) != value["receipt_sha256"]
    ):
        raise MCPRuntimeSecurityError("managed Node receipt digest differs")
    _invoke_verifier(verifier, _canonical_json(authority), authentication)
    return value


def _validate_managed_node_locked(
    root: Path, generation_id: str, verifier: Verifier,
) -> ManagedNodeRuntime:
    generation = _generation_path(root, generation_id)
    aliases = [
        name for name in _list_plain_names(root / "generations", "managed Node generations")
        if _case_key(name) == _case_key(generation_id)
    ]
    if aliases != [generation_id]:
        raise MCPRuntimeSecurityError("managed Node generation is missing or case-aliased")
    _require_plain_directory(generation, "managed Node generation")
    names = _list_plain_names(generation, "managed Node generation root")
    if set(names) != {PAYLOAD_NAME, MANAGED_NODE_RECEIPT_NAME} or len(names) != 2:
        raise MCPRuntimeSecurityError("managed Node generation root differs")
    receipt_path = generation / MANAGED_NODE_RECEIPT_NAME
    receipt_info = _require_plain_file(receipt_path, "managed Node receipt")
    receipt = _parse_managed_node_receipt(
        _read_file_exact(receipt_path, receipt_info), generation_id, verifier,
    )
    authority = receipt["authority"]
    payload = generation / PAYLOAD_NAME
    entries, census = _census_tree(payload)
    if entries != authority["entries"] or census != authority["census_sha256"]:
        raise MCPRuntimeSecurityError("managed Node/npm implementation closure changed")
    node = payload.joinpath(*authority["node_relative_path"].split("/"))
    npm_cli = payload.joinpath(*authority["npm_cli_relative_path"].split("/"))
    _require_plain_file(node, "managed Node executable")
    _require_plain_file(npm_cli, "managed npm CLI")
    package_path = npm_cli.parent.parent / "package.json"
    package_info = _require_plain_file(package_path, "managed npm package manifest")
    try:
        package = json.loads(_read_file_exact(package_path, package_info).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise MCPRuntimeSecurityError("managed npm package manifest is malformed") from exc
    if not isinstance(package, dict) or package.get("version") != MANAGED_NPM_VERSION:
        raise MCPRuntimeSecurityError("managed npm version differs")
    return ManagedNodeRuntime(
        store_root=root, generation_id=generation_id, generation_path=generation,
        payload_path=payload, node_path=node, npm_cli_path=npm_cli,
        receipt_sha256=receipt["receipt_sha256"], census_sha256=census,
        archive_sha256=authority["archive"]["sha256"],
        platform_key=authority["platform_key"], npm_version=authority["npm_version"],
    )


def _recover_managed_node_pending_locked(
    root: Path, generation_id: str, verifier: Verifier,
) -> ManagedNodeRuntime | None:
    pending_names = _list_plain_names(root / ".pending", "managed Node pending directory")
    staging_names = _list_plain_names(root / ".staging", "managed Node staging directory")
    if not pending_names and not staging_names:
        return None
    if len(pending_names) != 1:
        raise MCPRuntimeSecurityError("managed Node recovery denominator differs")
    pending_path = root / ".pending" / pending_names[0]
    pending = _parse_pending(pending_path)
    if pending["generation_id"] != generation_id:
        raise MCPRuntimeSecurityError("managed Node pending authority differs")
    staging_name = pending["staging_name"]
    if staging_names:
        if staging_names != [staging_name]:
            raise MCPRuntimeSecurityError("managed Node staging authority differs")
        if os.path.lexists(_fs_path(_generation_path(root, generation_id))):
            raise MCPRuntimeSecurityError("managed Node has simultaneous staged/committed state")
        _quarantine_private_staging(root, staging_name)
        _durable_unlink(pending_path)
        return None
    if not os.path.lexists(_fs_path(_generation_path(root, generation_id))):
        raise MCPRuntimeSecurityError("managed Node pending publication is missing")
    managed = _validate_managed_node_locked(root, generation_id, verifier)
    _durable_unlink(pending_path)
    return managed


def ensure_managed_node_runtime(
    store_root: os.PathLike[str] | str, *, signer: Signer, verifier: Verifier,
    allow_download: bool = True,
    downloader: Callable[[str, int], bytes] = _managed_node_download,
) -> ManagedNodeRuntime:
    """Idempotently acquire and seal the reviewed official Node/npm closure."""
    if type(allow_download) is not bool or not callable(downloader):
        raise MCPRuntimeSecurityError("managed Node acquisition policy differs")
    root = _display_path(os.path.abspath(os.fspath(store_root)))
    platform_key = _managed_node_platform_key()
    reviewed = MANAGED_NODE_ARCHIVES[platform_key]
    generation_id = _managed_node_generation_id(platform_key)
    with _store_lock(root, mode=_STORE_LOCK_EXCLUSIVE, create=True):
        recovered = _recover_managed_node_pending_locked(root, generation_id, verifier)
        if recovered is not None:
            return recovered
        generation = _generation_path(root, generation_id)
        if os.path.lexists(_fs_path(generation)):
            _assert_no_pending(root)
            return _validate_managed_node_locked(root, generation_id, verifier)
        _assert_no_pending(root)
        if not allow_download:
            raise MCPRuntimeSecurityError("reviewed managed Node generation is unavailable offline")
        txn_id = "txn-" + secrets.token_hex(32)
        pending = root / ".pending" / f"{txn_id}.json"
        staging = root / ".staging" / txn_id
        payload = staging / PAYLOAD_NAME
        _write_exclusive(pending, _canonical_json(_pending_payload(txn_id, generation_id)) + b"\n")
        _mkdir_plain(staging); _mkdir_plain(payload)
        try:
            url = f"https://nodejs.org/dist/v{MANAGED_NODE_VERSION}/{reviewed['filename']}"
            raw = downloader(url, 128 * 1024 * 1024)
            if not isinstance(raw, bytes) or _sha256(raw) != reviewed["sha256"]:
                raise MCPRuntimeSecurityError("downloaded managed Node archive differs")
            _extract_managed_node_archive(raw, payload, reviewed)
            entries, census = _census_tree(payload)
            authority = {
                "schema": MANAGED_NODE_RECEIPT_SCHEMA,
                "generation_id": generation_id,
                "node_version": MANAGED_NODE_VERSION,
                "npm_version": MANAGED_NPM_VERSION,
                "platform_key": platform_key,
                "archive": {"url": url, **dict(reviewed)},
                "extraction_policy": "official-archive-node+npm-complete-v1",
                "node_relative_path": reviewed["node"],
                "npm_cli_relative_path": reviewed["npm_cli"],
                "census_sha256": census, "entries": entries,
            }
            receipt_raw, _receipt_sha = _managed_node_receipt_bytes(authority, signer)
            _write_exclusive(staging / MANAGED_NODE_RECEIPT_NAME, receipt_raw)
            _parse_managed_node_receipt(receipt_raw, generation_id, verifier)
            _fsync_tree_bottom_up(staging)
            _atomic_rename_noreplace(staging, generation)
            managed = _validate_managed_node_locked(root, generation_id, verifier)
            _durable_unlink(pending)
            return managed
        except BaseException:
            if not os.path.lexists(_fs_path(generation)):
                if os.path.lexists(_fs_path(staging)):
                    _quarantine_private_staging(root, txn_id)
                if os.path.lexists(_fs_path(pending)):
                    _durable_unlink(pending)
            raise


def _same_managed_runtime(left: ManagedNodeRuntime, right: ManagedNodeRuntime) -> bool:
    return left == right


def run_managed_node(
    managed: ManagedNodeRuntime, arguments: Sequence[str], *, verifier: Verifier,
    cwd: os.PathLike[str] | str, environment: Mapping[str, str],
    runner: Callable[..., Any] = subprocess.run, timeout: int = 600,
    **runner_kwargs: Any,
) -> Any:
    """Run exact managed Node while holding and replaying its full closure."""
    if not isinstance(managed, ManagedNodeRuntime):
        raise MCPRuntimeSecurityError("managed Node launch authority differs")
    if isinstance(arguments, (str, bytes)) or not all(isinstance(item, str) for item in arguments):
        raise MCPRuntimeSecurityError("managed Node arguments differ")
    if not callable(runner) or type(timeout) is not int or timeout <= 0:
        raise MCPRuntimeSecurityError("managed Node runner policy differs")
    forbidden = {"shell", "executable", "preexec_fn", "env", "cwd"}.intersection(runner_kwargs)
    if forbidden:
        raise MCPRuntimeSecurityError("unsafe managed Node runner override")
    if not isinstance(environment, Mapping) or any(
        not isinstance(key, str) or not isinstance(value, str)
        for key, value in environment.items()
    ):
        raise MCPRuntimeSecurityError("managed Node environment differs")
    if any(
        key.upper() in {"NODE_OPTIONS", "NODE_PATH"}
        or key.upper().startswith(("LD_", "DYLD_", "NPM_CONFIG_"))
        for key in environment
    ):
        raise MCPRuntimeSecurityError("managed Node environment contains injection controls")
    root = _display_path(os.path.abspath(os.fspath(managed.store_root)))
    with _store_lock(root, mode=_STORE_LOCK_SHARED, create=False):
        _assert_no_pending(root)
        current = _validate_managed_node_locked(root, managed.generation_id, verifier)
        if not _same_managed_runtime(current, managed):
            raise MCPRuntimeSecurityError("managed Node launch authority changed")
        _require_plain_directory(cwd, "managed Node working directory")
        command = [str(_display_path(current.node_path)), *arguments]
        try:
            result = runner(
                command, cwd=_display_path(cwd), env=dict(environment),
                timeout=timeout, **runner_kwargs,
            )
        finally:
            after = _validate_managed_node_locked(root, managed.generation_id, verifier)
            if not _same_managed_runtime(after, managed):
                raise MCPRuntimeSecurityError("managed Node closure changed during execution")
        return result


def run_managed_npm_ci(
    managed: ManagedNodeRuntime, payload: os.PathLike[str] | str, *, verifier: Verifier,
    environment: Mapping[str, str], runner: Callable[..., Any] = subprocess.run,
    timeout: int = 600,
) -> Any:
    """Invoke npm-cli.js directly through exact managed Node; never a wrapper."""
    if tuple(REQUIRED_NPM_INSTALL_FLAGS) != (
        "ci", "--ignore-scripts", "--no-audit", "--no-fund", "--no-bin-links",
    ):
        raise MCPRuntimeSecurityError("managed npm install policy differs")
    return run_managed_node(
        managed, [str(_display_path(managed.npm_cli_path)), *REQUIRED_NPM_INSTALL_FLAGS],
        verifier=verifier, cwd=payload, environment=environment, runner=runner,
        timeout=timeout, capture_output=True, text=True,
    )


def _validate_generation_locked(
    store_root: Path, generation_id: str, verifier: Verifier
) -> ValidatedGeneration:
    generation_path = _generation_path(store_root, generation_id)
    generations = store_root / "generations"
    names = _list_plain_names(generations, "MCP generations directory")
    aliases = [name for name in names if _case_key(name) == _case_key(generation_id)]
    if aliases != [generation_id]:
        raise MCPRuntimeSecurityError("generation identity is missing or case-aliased")
    _require_plain_directory(generation_path, "MCP committed generation")
    root_names = _list_plain_names(generation_path, "MCP generation root")
    if set(root_names) != {PAYLOAD_NAME, RECEIPT_NAME} or len(root_names) != 2:
        raise MCPRuntimeSecurityError("MCP generation root contains extra or missing members")
    payload_path = generation_path / PAYLOAD_NAME
    receipt_path = generation_path / RECEIPT_NAME
    _require_plain_directory(payload_path, "MCP generation payload")
    receipt_info = _require_plain_file(receipt_path, "MCP generation receipt")
    if receipt_info.st_size > _MAX_RECEIPT_BYTES:
        raise MCPRuntimeSecurityError("MCP generation receipt exceeds its bound")
    receipt_raw = _read_file_exact(receipt_path, receipt_info)
    receipt = _parse_receipt(receipt_raw, generation_id, verifier)
    authority = receipt["authority"]
    current_entries, current_census = _census_tree(payload_path)
    if current_entries != authority["entries"] or current_census != authority["census_sha256"]:
        raise MCPRuntimeSecurityError("MCP generation payload differs from its receipt")
    by_path = {row["path"]: row for row in current_entries}
    for name, field in (
        ("package.json", "package_json_sha256"),
        ("package-lock.json", "package_lock_sha256"),
    ):
        row = by_path.get(name)
        if row is None or row["kind"] != "file" or row["sha256"] != authority[field]:
            raise MCPRuntimeSecurityError(f"MCP generation {name} authority differs")
    request_authority = authority["generation_request"]
    sanitizer = by_path.get(request_authority["sanitizer_relative_path"])
    if (
        sanitizer is None
        or sanitizer["kind"] != "file"
        or sanitizer["sha256"] != request_authority["sanitizer_sha256"]
    ):
        raise MCPRuntimeSecurityError("MCP generation sanitizer authority differs")
    finalizer_output = by_path.get(
        request_authority["finalizer_policy"]["output_entrypoint"]
    )
    if (
        finalizer_output is None
        or finalizer_output["kind"] != "file"
        or finalizer_output["link_count"] != 1
    ):
        raise MCPRuntimeSecurityError("MCP generation finalizer output differs")
    return ValidatedGeneration(
        generation_id=generation_id,
        generation_path=generation_path,
        payload_path=payload_path,
        receipt_sha256=receipt["receipt_sha256"],
        census_sha256=current_census,
        request_sha256=authority["request_sha256"],
        entries=tuple(current_entries),
    )


def validate_generation(
    store_root: os.PathLike[str] | str,
    generation_id: str,
    *,
    verifier: Verifier,
    require_no_pending: bool = True,
) -> ValidatedGeneration:
    """Authenticate and exactly recensus a committed generation."""
    root = _display_path(os.path.abspath(os.fspath(store_root)))
    with _store_lock(root, mode=_STORE_LOCK_SHARED, create=False):
        if require_no_pending:
            _assert_no_pending(root)
        return _validate_generation_locked(root, generation_id, verifier)


def _validate_generation_receipt_locked(
    root: Path, generation_id: str, verifier: Verifier, *,
    expected_receipt_sha256: str, expected_census_sha256: str,
    expected_request_sha256: str, expected_generation_policy_sha256: str,
) -> tuple[Path, dict[str, Any]]:
    """Validate the signed immutable-root seal without walking the payload."""
    expected = (
        expected_receipt_sha256, expected_census_sha256,
        expected_request_sha256, expected_generation_policy_sha256,
    )
    if any(not isinstance(item, str) or not _HEX64_RE.fullmatch(item) for item in expected):
        raise MCPRuntimeSecurityError("expected generation authority digest is malformed")
    generation = _generation_path(root, generation_id)
    names = _list_plain_names(root / "generations", "MCP generations directory")
    if [name for name in names if _case_key(name) == _case_key(generation_id)] != [generation_id]:
        raise MCPRuntimeSecurityError("generation identity is missing or case-aliased")
    _require_plain_directory(generation, "MCP committed generation")
    root_names = _list_plain_names(generation, "MCP generation root")
    if set(root_names) != {PAYLOAD_NAME, RECEIPT_NAME} or len(root_names) != 2:
        raise MCPRuntimeSecurityError("MCP generation root contains extra or missing members")
    payload = generation / PAYLOAD_NAME
    _require_plain_directory(payload, "MCP generation payload")
    receipt_path = generation / RECEIPT_NAME
    receipt_info = _require_plain_file(receipt_path, "MCP generation receipt")
    if receipt_info.st_size > _MAX_RECEIPT_BYTES:
        raise MCPRuntimeSecurityError("MCP generation receipt exceeds its bound")
    receipt = _parse_receipt(
        _read_file_exact(receipt_path, receipt_info), generation_id, verifier,
    )
    authority = receipt["authority"]
    request = _request_from_authority(authority["generation_request"])
    if (
        receipt["receipt_sha256"] != expected_receipt_sha256
        or authority["census_sha256"] != expected_census_sha256
        or authority["request_sha256"] != expected_request_sha256
        or generation_policy_sha256(request) != expected_generation_policy_sha256
    ):
        raise MCPRuntimeSecurityError("generation receipt authority differs")
    return payload, receipt


def validate_generation_authority_fast(
    store_root: os.PathLike[str] | str,
    generation_id: str,
    *, verifier: Verifier,
    expected_receipt_sha256: str,
    expected_census_sha256: str,
    expected_request_sha256: str,
    expected_generation_policy_sha256: str,
) -> ValidatedGenerationAuthority:
    """Authenticate the signed generation/root seal without a payload walk.

    This is the bounded public-selection admission primitive.  It never treats
    receipt rows as current filesystem bytes. Selected native backend readiness
    follows through ``launch_generation_member(full_census=False)``, which
    replays the signed exact member/resource closure under the store lock.
    Whole-generation and deep-integrity Doctor checks use the full recursive
    validator.
    """
    root = _display_path(os.path.abspath(os.fspath(store_root)))
    with _store_lock(root, mode=_STORE_LOCK_SHARED, create=False):
        _assert_no_pending(root)
        payload, receipt = _validate_generation_receipt_locked(
            root, generation_id, verifier,
            expected_receipt_sha256=expected_receipt_sha256,
            expected_census_sha256=expected_census_sha256,
            expected_request_sha256=expected_request_sha256,
            expected_generation_policy_sha256=expected_generation_policy_sha256,
        )
        authority = receipt["authority"]
        return ValidatedGenerationAuthority(
            generation_id=generation_id,
            generation_path=_generation_path(root, generation_id),
            payload_path=payload,
            receipt_sha256=receipt["receipt_sha256"],
            census_sha256=authority["census_sha256"],
            request_sha256=authority["request_sha256"],
            generation_policy_sha256=expected_generation_policy_sha256,
            entries=tuple(authority["entries"]),
        )


_MEMBER_AUTHORITY_KEYS = frozenset({
    "schema", "generation_id", "receipt_sha256", "census_sha256",
    "request_sha256", "generation_policy_sha256", "execution_kind",
    "receipt_file_sha256", "relative_path", "size", "sha256", "mode",
    "link_count", "closure_root", "closure_count", "closure_sha256",
    "closure", "ancestors",
})
_MEMBER_ANCESTOR_KEYS = frozenset({"path", "mode", "link_count", "reparse"})
_MEMBER_CLOSURE_ROW_KEYS = frozenset({
    "path", "kind", "size", "sha256", "mode",
    "link_count", "reparse",
})
_MAX_NATIVE_RESOURCE_CLOSURE_ROWS = 16
_MAX_NATIVE_RESOURCE_CLOSURE_BYTES = 2 * 1024 * 1024 * 1024


_CODEX_NATIVE_TARGETS = {
    ("darwin", "arm64"): "aarch64-apple-darwin",
    ("darwin", "x64"): "x86_64-apple-darwin",
    ("linux", "arm64"): "aarch64-unknown-linux-musl",
    ("linux", "x64"): "x86_64-unknown-linux-musl",
    ("win32", "arm64"): "aarch64-pc-windows-msvc",
    ("win32", "x64"): "x86_64-pc-windows-msvc",
}
_CODEX_NATIVE_PATH_RE = re.compile(
    r"node_modules/@openai/codex-(darwin|linux|win32)-(arm64|x64)/"
    r"vendor/([^/]+)/bin/(codex(?:\.exe)?)\Z"
)
_CLAUDE_NATIVE_PATH = "node_modules/@anthropic-ai/claude-code/bin/claude.exe"


def _native_resource_closure_spec(
    relative: str,
) -> tuple[str, frozenset[str] | None]:
    """Return the fixed package root/roster for a known native backend.

    Unknown native members retain the legacy exact-directory behavior used by
    embedders.  Plamen only publishes the two known backend paths below.
    """
    match = _CODEX_NATIVE_PATH_RE.fullmatch(relative)
    if match is not None:
        platform_name, architecture, target, primary_name = match.groups()
        expected_target = _CODEX_NATIVE_TARGETS.get((platform_name, architecture))
        expected_primary = "codex.exe" if platform_name == "win32" else "codex"
        if target != expected_target or primary_name != expected_primary:
            raise MCPRuntimeSecurityError("Codex native target topology differs")
        closure_root = relative.rsplit("/bin/", 1)[0]
        executable_suffix = ".exe" if platform_name == "win32" else ""
        paths = {
            ".", "bin", "codex-path", "codex-resources", "codex-package.json",
            f"bin/codex{executable_suffix}",
            f"bin/codex-code-mode-host{executable_suffix}",
            f"codex-path/rg{executable_suffix}",
        }
        if platform_name == "win32":
            paths.update({
                "codex-resources/codex-command-runner.exe",
                "codex-resources/codex-windows-sandbox-setup.exe",
            })
        else:
            paths.update({
                "codex-resources/zsh",
                "codex-resources/zsh/bin",
                "codex-resources/zsh/bin/zsh",
            })
            if platform_name == "linux":
                paths.add("codex-resources/bwrap")
        return closure_root, frozenset(
            closure_root if path == "." else f"{closure_root}/{path}"
            for path in paths
        )
    if relative == _CLAUDE_NATIVE_PATH:
        closure_root = relative.rsplit("/", 1)[0]
        return closure_root, frozenset({closure_root, relative})
    return relative.rsplit("/", 1)[0] if "/" in relative else ".", None


def native_resource_roster(relative_path: os.PathLike[str] | str) -> tuple[str, ...]:
    """Expose the fixed known-backend roster for installer contract checks."""
    relative = _safe_relative_entrypoint(relative_path)
    _root, expected = _native_resource_closure_spec(relative)
    if expected is None:
        raise MCPRuntimeSecurityError("native backend has no fixed resource roster")
    return tuple(sorted(expected, key=lambda path: (_case_key(path), path)))


def sign_generation_member_authority(
    validated: ValidatedGeneration,
    relative_path: os.PathLike[str] | str,
    *, execution_kind: str,
    generation_policy_sha256_value: str,
    signer: Signer,
) -> dict[str, Any]:
    """Seal one exact transitive native resource closure after a full census."""
    if not isinstance(validated, ValidatedGeneration):
        raise MCPRuntimeSecurityError("member authority requires a full validated generation")
    relative = _safe_relative_entrypoint(relative_path)
    if execution_kind != "native":
        raise MCPRuntimeSecurityError("native resource closure requires native code")
    if (
        not isinstance(generation_policy_sha256_value, str)
        or not _HEX64_RE.fullmatch(generation_policy_sha256_value)
    ):
        raise MCPRuntimeSecurityError("member generation policy differs")
    if not callable(signer):
        raise MCPRuntimeSecurityError("member authority signer is required")
    by_path = {row["path"]: row for row in validated.entries}
    member = by_path.get(relative)
    if member is None or member.get("kind") != "file" or member.get("link_count") != 1:
        raise MCPRuntimeSecurityError("member is outside the full generation census")
    closure_root, expected_roster = _native_resource_closure_spec(relative)
    closure_prefix = "" if closure_root == "." else closure_root + "/"
    closure = []
    for path, row in by_path.items():
        if path != closure_root and not path.startswith(closure_prefix):
            continue
        if (
            row.get("kind") not in {"file", "directory"}
            or row.get("reparse") is not False
            or type(row.get("link_count")) is not int
            or row["link_count"] < 1
            or (row["kind"] == "file" and row["link_count"] != 1)
        ):
            raise MCPRuntimeSecurityError(
                "native resource closure is not an exact ordinary tree"
            )
        closure.append({key: row[key] for key in _MEMBER_CLOSURE_ROW_KEYS})
    closure.sort(key=lambda row: (_case_key(row["path"]), row["path"]))
    paths = [row["path"] for row in closure]
    _reject_case_alias_names(paths, "native resource closure census")
    if (
        not closure
        or len(closure) > _MAX_NATIVE_RESOURCE_CLOSURE_ROWS
        or sum(row["size"] for row in closure if row["kind"] == "file")
        > _MAX_NATIVE_RESOURCE_CLOSURE_BYTES
    ):
        raise MCPRuntimeSecurityError("native resource closure exceeds its bound")
    if expected_roster is not None and set(paths) != set(expected_roster):
        raise MCPRuntimeSecurityError("native resource closure roster differs")
    if relative not in paths:
        raise MCPRuntimeSecurityError("native primary is absent from its resource closure")
    closure_projection = _canonical_json(closure)
    closure_parts = [] if closure_root == "." else closure_root.split("/")
    parent_parts = closure_parts[:-1]
    ancestor_paths = ["."] + [
        "/".join(parent_parts[:index])
        for index in range(1, len(parent_parts) + 1)
    ]
    ancestors = []
    for path in ancestor_paths:
        row = by_path.get(path)
        if row is None or row.get("kind") != "directory" or row.get("reparse") is not False:
            raise MCPRuntimeSecurityError("member ancestor is outside the full census")
        ancestors.append({key: row[key] for key in ("path", "mode", "link_count", "reparse")})
    receipt_path = validated.generation_path / RECEIPT_NAME
    receipt_info = _require_plain_file(receipt_path, "MCP generation receipt")
    _receipt_size, receipt_file_sha256 = _digest_file_exact(receipt_path, receipt_info)
    authority = {
        "schema": MEMBER_AUTHORITY_SCHEMA,
        "generation_id": validated.generation_id,
        "receipt_sha256": validated.receipt_sha256,
        "census_sha256": validated.census_sha256,
        "request_sha256": validated.request_sha256,
        "generation_policy_sha256": generation_policy_sha256_value,
        "receipt_file_sha256": receipt_file_sha256,
        "execution_kind": execution_kind,
        "relative_path": relative,
        "size": member["size"], "sha256": member["sha256"],
        "mode": member["mode"], "link_count": member["link_count"],
        "closure_root": closure_root, "closure_count": len(closure),
        "closure_sha256": _sha256(closure_projection), "closure": closure,
        "ancestors": ancestors,
    }
    authentication = _strict_auth(signer(_canonical_json(authority)))
    return {"authority": authority, "authentication": authentication}


def _validate_signed_member_authority(
    value: Any, verifier: Verifier,
) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {"authority", "authentication"}:
        raise MCPRuntimeSecurityError("signed member authority fields differ")
    authority = value["authority"]
    if not isinstance(authority, dict) or set(authority) != _MEMBER_AUTHORITY_KEYS:
        raise MCPRuntimeSecurityError("member authority fields differ")
    if (
        authority["schema"] != MEMBER_AUTHORITY_SCHEMA
        or not isinstance(authority["generation_id"], str)
        or not _GENERATION_RE.fullmatch(authority["generation_id"])
        or authority["execution_kind"] != "native"
        or type(authority["size"]) is not int or authority["size"] < 0
        or type(authority["mode"]) is not int or not 0 <= authority["mode"] <= 0o7777
        or type(authority["link_count"]) is not int or authority["link_count"] != 1
        or any(
            not isinstance(authority[field], str) or not _HEX64_RE.fullmatch(authority[field])
            for field in (
                "receipt_sha256", "census_sha256", "request_sha256",
                "generation_policy_sha256", "receipt_file_sha256", "sha256",
            )
        )
    ):
        raise MCPRuntimeSecurityError("member authority types differ")
    relative = _safe_relative_entrypoint(authority["relative_path"])
    if relative != authority["relative_path"]:
        raise MCPRuntimeSecurityError("member authority path differs")
    expected_root, expected_roster = _native_resource_closure_spec(relative)
    if authority["closure_root"] != expected_root:
        raise MCPRuntimeSecurityError("member resource-closure root differs")
    closure = authority["closure"]
    if (
        not isinstance(closure, list) or not closure
        or len(closure) > _MAX_NATIVE_RESOURCE_CLOSURE_ROWS
        or type(authority["closure_count"]) is not int
        or authority["closure_count"] != len(closure)
        or not isinstance(authority["closure_sha256"], str)
        or not _HEX64_RE.fullmatch(authority["closure_sha256"])
        or authority["closure_sha256"] != _sha256(_canonical_json(closure))
    ):
        raise MCPRuntimeSecurityError("member resource-closure census differs")
    def closure_sort_key(row: Any) -> tuple[str, str]:
        path = row.get("path") if isinstance(row, dict) else None
        return (_case_key(path), path) if isinstance(path, str) else ("", "")

    expected_closure = sorted(closure, key=closure_sort_key)
    if closure != expected_closure:
        raise MCPRuntimeSecurityError("member resource-closure order differs")
    paths = []
    primary = None
    total_size = 0
    root_prefix = "" if expected_root == "." else expected_root + "/"
    for row in closure:
        if (
            not isinstance(row, dict) or set(row) != _MEMBER_CLOSURE_ROW_KEYS
            or row["kind"] not in {"file", "directory"}
            or row["reparse"] is not False
            or type(row["size"]) is not int or row["size"] < 0
            or type(row["mode"]) is not int or not 0 <= row["mode"] <= 0o7777
            or type(row["link_count"]) is not int or row["link_count"] < 1
            or (row["kind"] == "file" and row["link_count"] != 1)
            or not isinstance(row["sha256"], str)
            or not _HEX64_RE.fullmatch(row["sha256"])
        ):
            raise MCPRuntimeSecurityError("member resource-closure row differs")
        path = "." if row["path"] == "." else _safe_relative_entrypoint(row["path"])
        if path != row["path"] or (
            path != expected_root and not path.startswith(root_prefix)
        ):
            raise MCPRuntimeSecurityError("member resource-closure topology differs")
        paths.append(path)
        if row["kind"] == "file":
            total_size += row["size"]
        if path == relative:
            primary = row
    _reject_case_alias_names(paths, "member resource-closure authority")
    if set(paths) != set(expected_roster or paths):
        raise MCPRuntimeSecurityError("member resource-closure roster differs")
    if total_size > _MAX_NATIVE_RESOURCE_CLOSURE_BYTES:
        raise MCPRuntimeSecurityError("member resource-closure size exceeds its bound")
    if (
        primary is None or primary["kind"] != "file"
        or primary["size"] != authority["size"]
        or primary["sha256"] != authority["sha256"]
        or primary["mode"] != authority["mode"]
        or primary["link_count"] != authority["link_count"]
    ):
        raise MCPRuntimeSecurityError("primary member differs from resource closure")
    closure_parts = [] if expected_root == "." else expected_root.split("/")
    parent_parts = closure_parts[:-1]
    expected_paths = ["."] + [
        "/".join(parent_parts[:index])
        for index in range(1, len(parent_parts) + 1)
    ]
    ancestors = authority["ancestors"]
    if not isinstance(ancestors, list) or len(ancestors) != len(expected_paths):
        raise MCPRuntimeSecurityError("member ancestor authority differs")
    for row, expected_path in zip(ancestors, expected_paths):
        if (
            not isinstance(row, dict) or set(row) != _MEMBER_ANCESTOR_KEYS
            or row["path"] != expected_path
            or type(row["mode"]) is not int or not 0 <= row["mode"] <= 0o7777
            or type(row["link_count"]) is not int or row["link_count"] < 1
            or row["reparse"] is not False
        ):
            raise MCPRuntimeSecurityError("member ancestor authority differs")
    authentication = _strict_auth(value["authentication"])
    if not callable(verifier) or verifier(_canonical_json(authority), authentication) is not True:
        raise MCPRuntimeSecurityError("member authority authentication failed")
    return authority


def _validate_generation_member_seal_locked(
    root: Path, authority: Mapping[str, Any], relative: str,
) -> tuple[Path, dict[str, Any]]:
    """Replay a signed exact transitive resource tree without a full payload walk."""
    generation_id = authority["generation_id"]
    generation = _generation_path(root, generation_id)
    names = _list_plain_names(root / "generations", "MCP generations directory")
    if [name for name in names if _case_key(name) == _case_key(generation_id)] != [generation_id]:
        raise MCPRuntimeSecurityError("generation identity is missing or case-aliased")
    _require_plain_directory(generation, "MCP committed generation")
    root_names = _list_plain_names(generation, "MCP generation root")
    if set(root_names) != {PAYLOAD_NAME, RECEIPT_NAME} or len(root_names) != 2:
        raise MCPRuntimeSecurityError("MCP generation root contains extra or missing members")
    receipt_path = generation / RECEIPT_NAME
    receipt_info = _require_plain_file(receipt_path, "MCP generation receipt")
    if receipt_info.st_size > _MAX_RECEIPT_BYTES:
        raise MCPRuntimeSecurityError("MCP generation receipt exceeds its bound")
    _receipt_size, receipt_digest = _digest_file_exact(receipt_path, receipt_info)
    if receipt_digest != authority["receipt_file_sha256"]:
        raise MCPRuntimeSecurityError("MCP generation receipt seal differs")
    payload = generation / PAYLOAD_NAME
    root_info = _require_plain_directory(payload, "MCP generation payload")
    ancestor_rows = authority["ancestors"]
    if (
        stat.S_IMODE(root_info.st_mode) != ancestor_rows[0]["mode"]
        or root_info.st_nlink != ancestor_rows[0]["link_count"]
    ):
        raise MCPRuntimeSecurityError("backend payload-root authority differs")
    current = payload
    closure_root = authority["closure_root"]
    closure_parts = [] if closure_root == "." else closure_root.split("/")
    parent_parts = closure_parts[:-1]
    for component, signed in zip(parent_parts, ancestor_rows[1:]):
        aliases = [
            name for name in _list_plain_names(current, "backend member ancestor")
            if _case_key(name) == _case_key(component)
        ]
        if aliases != [component]:
            raise MCPRuntimeSecurityError("backend member component is missing or case-aliased")
        current = current / component
        info = _require_plain_directory(current, "backend member ancestor")
        if (
            stat.S_IMODE(info.st_mode) != signed["mode"]
            or info.st_nlink != signed["link_count"]
        ):
            raise MCPRuntimeSecurityError("backend member ancestor authority differs")
    if closure_parts:
        component = closure_parts[-1]
        aliases = [
            name for name in _list_plain_names(current, "backend closure parent")
            if _case_key(name) == _case_key(component)
        ]
        if aliases != [component]:
            raise MCPRuntimeSecurityError(
                "backend resource closure is missing or case-aliased"
            )
        current = current / component
    current_rows, _current_tree_sha256 = _census_tree(
        current,
        maximum_rows=_MAX_NATIVE_RESOURCE_CLOSURE_ROWS,
        maximum_file_bytes=_MAX_NATIVE_RESOURCE_CLOSURE_BYTES,
    )
    mapped_rows = []
    for row in current_rows:
        mapped = dict(row)
        local = mapped["path"]
        mapped["path"] = (
            closure_root if local == "."
            else local if closure_root == "."
            else f"{closure_root}/{local}"
        )
        mapped_rows.append(mapped)
    mapped_rows.sort(key=lambda row: (_case_key(row["path"]), row["path"]))
    if (
        len(mapped_rows) > _MAX_NATIVE_RESOURCE_CLOSURE_ROWS
        or sum(row["size"] for row in mapped_rows if row["kind"] == "file")
        > _MAX_NATIVE_RESOURCE_CLOSURE_BYTES
        or mapped_rows != authority["closure"]
        or _sha256(_canonical_json(mapped_rows)) != authority["closure_sha256"]
    ):
        raise MCPRuntimeSecurityError("backend native resource closure changed before launch")
    current_rows_by_path = {row["path"]: row for row in mapped_rows}
    primary = current_rows_by_path.get(relative)
    if primary is None:
        raise MCPRuntimeSecurityError("backend primary is absent from resource closure")
    return payload, dict(primary)


def _validate_generation_member_locked(
    root: Path, generation_id: str, relative: str, verifier: Verifier,
    *, expected_receipt_sha256: str, expected_census_sha256: str,
    expected_request_sha256: str, expected_generation_policy_sha256: str,
) -> tuple[Path, dict[str, Any], dict[str, Any]]:
    """Authenticate the immutable root/receipt and one exact execution closure."""
    payload, receipt = _validate_generation_receipt_locked(
        root, generation_id, verifier,
        expected_receipt_sha256=expected_receipt_sha256,
        expected_census_sha256=expected_census_sha256,
        expected_request_sha256=expected_request_sha256,
        expected_generation_policy_sha256=expected_generation_policy_sha256,
    )
    authority = receipt["authority"]
    by_path = {row["path"]: row for row in authority["entries"]}
    row = by_path.get(relative)
    if row is None or row["kind"] != "file":
        raise MCPRuntimeSecurityError("backend member is outside the signed receipt")
    # Bind every directory component of this one execution closure. Unrelated
    # payload members remain the install/Doctor full-census denominator.
    current = payload
    for index, component in enumerate(relative.split("/")[:-1]):
        aliases = [
            name for name in _list_plain_names(current, "backend member ancestor")
            if _case_key(name) == _case_key(component)
        ]
        if aliases != [component]:
            raise MCPRuntimeSecurityError("backend member component is missing or case-aliased")
        current = current / component
        directory = _require_plain_directory(current, "backend member ancestor")
        signed = by_path.get("/".join(relative.split("/")[:index + 1]))
        if (
            signed is None or signed["kind"] != "directory"
            or signed["mode"] != stat.S_IMODE(directory.st_mode)
            or signed["link_count"] != directory.st_nlink
        ):
            raise MCPRuntimeSecurityError("backend member ancestor authority differs")
    return payload, receipt, row


def _call_fault(hook: FaultHook | None, event: str) -> None:
    if hook is not None:
        hook(event)


def stage_npm_generation(
    store_root: os.PathLike[str] | str,
    generation_id: str,
    materialize: Materializer,
    *,
    expected_package_json_bytes: bytes,
    expected_package_lock_bytes: bytes,
    node_executable: os.PathLike[str] | str,
    npm_executable: os.PathLike[str] | str,
    npm_version: str,
    npm_install_flags: Sequence[str],
    generation_request: GenerationRequest,
    signer: Signer,
    verifier: Verifier,
    fault_hook: FaultHook | None = None,
) -> PublishedGeneration:
    """Materialize, seal, and atomically publish one immutable generation.

    ``materialize`` receives the private payload directory and may run ``npm
    ci`` there.  This primitive itself never invokes npm.  It must leave exact
    ``package.json`` and ``package-lock.json`` files in the payload root.

    ``generation_id`` must equal the deterministic identity in
    ``generation_request``. Reusing that exact content authority is idempotent;
    in that case ``materialize`` is not called again.
    """
    root = _display_path(os.path.abspath(os.fspath(store_root)))
    generation_id = _safe_component(generation_id, "generation identity")
    if not callable(materialize):
        raise TypeError("materialize must be callable")
    if not callable(signer):
        raise MCPRuntimeSecurityError("an authenticated receipt signer is required")
    if not callable(verifier):
        raise MCPRuntimeSecurityError("an authenticated receipt verifier is required")
    package_bytes = _canonical_manifest_bytes(
        expected_package_json_bytes, "package.json"
    )
    lock_bytes = _canonical_manifest_bytes(
        expected_package_lock_bytes, "package-lock.json"
    )
    request_authority = _replay_generation_request(generation_request)
    if generation_id != generation_request.generation_id:
        raise MCPRuntimeSecurityError(
            "generation identity differs from deterministic request authority"
        )
    if not isinstance(npm_version, str) or not _PINNED_VERSION_RE.fullmatch(npm_version):
        raise MCPRuntimeSecurityError("npm version is not exactly pinned")
    install_policy = _npm_install_policy(npm_install_flags)
    with _store_lock(root, mode=_STORE_LOCK_EXCLUSIVE, create=True):
        _assert_no_pending(root)
        node_authority = _node_executable_authority(node_executable)
        npm_authority = _executable_authority(npm_executable, "npm executable")
        expected_authority = {
            "package_json_sha256": _sha256(package_bytes),
            "package_lock_sha256": _sha256(lock_bytes),
            "node_executable_authority": node_authority,
            "npm_executable_authority": npm_authority,
            "npm_version": npm_version,
            "npm_install_policy": install_policy,
            "platform_authority": _platform_authority(),
            "launch_environment_policy": _LAUNCH_ENVIRONMENT_POLICY,
            "request_sha256": generation_request.request_sha256,
            "generation_request": request_authority,
        }
        request_cross_bindings = {
            "census_schema": CENSUS_SCHEMA,
            "package_json_sha256": expected_authority["package_json_sha256"],
            "package_lock_sha256": expected_authority["package_lock_sha256"],
            "node_executable_authority": node_authority,
            "npm_executable_authority": npm_authority,
            "npm_version": npm_version,
            "npm_install_policy": install_policy,
            "platform_authority": expected_authority["platform_authority"],
            "launch_environment_policy": expected_authority[
                "launch_environment_policy"
            ],
        }
        if any(
            request_authority[key] != expected
            for key, expected in request_cross_bindings.items()
        ):
            raise MCPRuntimeSecurityError(
                "stage inputs differ from deterministic generation request"
            )
        generations = root / "generations"
        existing = _list_plain_names(generations, "MCP generations directory")
        aliases = [name for name in existing if _case_key(name) == _case_key(generation_id)]
        if aliases:
            if aliases != [generation_id]:
                raise FileExistsError(f"case-aliased generation already exists: {generation_id}")
            committed = _validate_generation_locked(root, generation_id, verifier)
            receipt_path = committed.generation_path / RECEIPT_NAME
            receipt_info = _require_plain_file(receipt_path, "MCP generation receipt")
            receipt = _parse_receipt(
                _read_file_exact(receipt_path, receipt_info), generation_id, verifier
            )
            if any(
                receipt["authority"][key] != expected
                for key, expected in expected_authority.items()
            ):
                raise MCPRuntimeSecurityError(
                    "existing generation differs from exact requested install authority"
                )
            return committed
        txn_id = "txn-" + secrets.token_hex(32)
        pending_path = root / ".pending" / f"{txn_id}.json"
        staging_path = root / ".staging" / txn_id
        payload_path = staging_path / PAYLOAD_NAME
        pending_raw = _canonical_json(_pending_payload(txn_id, generation_id)) + b"\n"
        # Establish the fresh store and every control-directory durability
        # barrier before the first transaction marker becomes observable.
        _fsync_control_roots(root)
        _write_exclusive(pending_path, pending_raw)
        _call_fault(fault_hook, "after_pending")
        _mkdir_plain(staging_path)
        _mkdir_plain(payload_path)
        _call_fault(fault_hook, "after_staging")
        try:
            materialize(payload_path)
            _call_fault(fault_hook, "after_materialize")
            entries, census_sha256 = _census_tree(payload_path)
            by_path = {row["path"]: row for row in entries}
            package = by_path.get("package.json")
            lock = by_path.get("package-lock.json")
            if package is None or package["kind"] != "file":
                raise MCPRuntimeSecurityError("materialization lacks package.json")
            if lock is None or lock["kind"] != "file":
                raise MCPRuntimeSecurityError("materialization lacks package-lock.json")
            if (
                package["sha256"] != expected_authority["package_json_sha256"]
                or lock["sha256"] != expected_authority["package_lock_sha256"]
            ):
                raise MCPRuntimeSecurityError(
                    "materialized package/lock bytes differ from expected canonical bytes"
                )
            sanitizer = by_path.get(request_authority["sanitizer_relative_path"])
            if (
                sanitizer is None
                or sanitizer["kind"] != "file"
                or sanitizer["sha256"] != request_authority["sanitizer_sha256"]
            ):
                raise MCPRuntimeSecurityError(
                    "materialized sanitizer differs from generation request"
                )
            finalizer_output = by_path.get(
                request_authority["finalizer_policy"]["output_entrypoint"]
            )
            if (
                finalizer_output is None
                or finalizer_output["kind"] != "file"
                or finalizer_output["link_count"] != 1
            ):
                raise MCPRuntimeSecurityError(
                    "materialized finalizer output is missing or non-ordinary"
                )
            authority = {
                "schema": RECEIPT_SCHEMA,
                "generation_id": generation_id,
                "payload_name": PAYLOAD_NAME,
                "census_schema": CENSUS_SCHEMA,
                "census_sha256": census_sha256,
                "entries": entries,
                **expected_authority,
            }
            receipt_raw, receipt_sha256 = _receipt_bytes(authority, signer)
            _write_exclusive(staging_path / RECEIPT_NAME, receipt_raw)
            # Replay the staged postimage with the independent verifier before
            # giving the directory a committed name.
            _parse_receipt(receipt_raw, generation_id, verifier)
            replay_entries, replay_census = _census_tree(payload_path)
            if replay_entries != entries or replay_census != census_sha256:
                raise MCPRuntimeSecurityError("materialization changed after sealing")
            _fsync_tree_bottom_up(staging_path)
            _fsync_control_roots(root)
            _call_fault(fault_hook, "before_publish")
            destination = generations / generation_id
            _atomic_rename_noreplace(staging_path, destination)
            _fsync_control_roots(root)
            _call_fault(fault_hook, "after_publish")
            committed = _validate_generation_locked(root, generation_id, verifier)
            if (
                committed.receipt_sha256 != receipt_sha256
                or committed.census_sha256 != census_sha256
            ):
                raise MCPRuntimeSecurityError("published MCP generation authority differs")
            _call_fault(fault_hook, "before_pending_retire")
            _fsync_control_roots(root)
            _durable_unlink(pending_path)
            _fsync_control_roots(root)
            _call_fault(fault_hook, "after_commit")
            return committed
        except BaseException:
            # Once destination exists, never modify it: leave the durable
            # pending marker for authenticated recovery. Pre-publication state
            # is retained by an atomic root quarantine, never traversed.
            destination = generations / generation_id
            if not os.path.lexists(_fs_path(destination)):
                if os.path.lexists(_fs_path(staging_path)):
                    _quarantine_private_staging(root, txn_id)
                if os.path.lexists(_fs_path(pending_path)):
                    _fsync_control_roots(root)
                    _durable_unlink(pending_path)
                    _fsync_control_roots(root)
            raise


def _root_object_identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        stat.S_IFMT(info.st_mode),
        info.st_nlink,
        int(_is_reparse(info)),
        int(getattr(info, "st_file_attributes", 0)),
    )


def _quarantine_private_staging(store_root: Path, txn_id: str) -> Path:
    """Rename one staging root as an opaque retained object; never traverse it."""
    if not _TXN_RE.fullmatch(txn_id):
        raise MCPRuntimeSecurityError("private staging transaction identity differs")
    source = store_root / ".staging" / txn_id
    destination = store_root / ".abandoned" / txn_id
    if not os.path.lexists(_fs_path(source)):
        raise MCPRuntimeSecurityError("private staging root is missing")
    if os.path.lexists(_fs_path(destination)):
        raise MCPRuntimeSecurityError("private staging quarantine already exists")
    before = _lstat(source)
    identity = _root_object_identity(before)
    _fsync_control_roots(store_root)
    _atomic_rename_noreplace(source, destination)
    if os.path.lexists(_fs_path(source)) or not os.path.lexists(_fs_path(destination)):
        raise MCPRuntimeSecurityError("private staging quarantine postcondition differs")
    after = _lstat(destination)
    if _root_object_identity(after) != identity:
        raise MCPRuntimeSecurityError("private staging quarantine identity changed")
    _durability_event("staging-quarantined", destination)
    _fsync_control_roots(store_root)
    return destination


def recover_private_staging(
    store_root: os.PathLike[str] | str, *, verifier: Verifier
) -> tuple[str, ...]:
    """Recover pending private transactions without touching committed bytes."""
    root = _display_path(os.path.abspath(os.fspath(store_root)))
    recovered: list[str] = []
    with _store_lock(root, mode=_STORE_LOCK_EXCLUSIVE, create=True):
        pending_dir = root / ".pending"
        staging_dir = root / ".staging"
        pending_names = _list_plain_names(pending_dir, "MCP pending directory")
        staging_names = _list_plain_names(staging_dir, "MCP staging directory")
        for name in pending_names:
            if not name.endswith(".json"):
                raise MCPRuntimeSecurityError("unexpected MCP pending transaction member")
            pending_path = pending_dir / name
            pending = _parse_pending(pending_path)
            txn_id = pending["transaction_id"]
            generation_id = pending["generation_id"]
            staging_path = staging_dir / txn_id
            generation_path = _generation_path(root, generation_id)
            staged_exists = os.path.lexists(_fs_path(staging_path))
            committed_exists = os.path.lexists(_fs_path(generation_path))
            if staged_exists and committed_exists:
                raise MCPRuntimeSecurityError(
                    "MCP transaction has both staged and committed generations"
                )
            if committed_exists:
                _validate_generation_locked(root, generation_id, verifier)
                _fsync_control_roots(root)
                _durable_unlink(pending_path)
                _fsync_control_roots(root)
                recovered.append(generation_id)
                continue
            if staged_exists:
                _quarantine_private_staging(root, txn_id)
            _fsync_control_roots(root)
            _durable_unlink(pending_path)
            _fsync_control_roots(root)
            recovered.append(generation_id)
        remaining_staging = _list_plain_names(staging_dir, "MCP staging directory")
        expected_staging = {
            _parse_pending(pending_dir / name)["transaction_id"]
            for name in _list_plain_names(pending_dir, "MCP pending directory")
        }
        extras = set(remaining_staging) - expected_staging
        if extras:
            raise MCPRuntimeSecurityError(
                "orphan MCP private staging exists without a pending transaction"
            )
        return tuple(recovered)


def _safe_relative_entrypoint(value: os.PathLike[str] | str) -> str:
    raw = os.fspath(value).replace("\\", "/")
    if (
        not raw
        or raw.startswith("/")
        or re.match(r"^[A-Za-z]:", raw)
        or any(part in {"", ".", ".."} for part in raw.split("/"))
    ):
        raise MCPRuntimeSecurityError("MCP Node entrypoint is not an exact relative path")
    for part in raw.split("/"):
        _reject_windows_ambiguous_component(part, "MCP Node entrypoint component")
    return raw


def launch_node_generation(
    store_root: os.PathLike[str] | str,
    generation_id: str,
    entrypoint: os.PathLike[str] | str,
    *,
    node_executable: os.PathLike[str] | str,
    verifier: Verifier,
    expected_receipt_sha256: str,
    expected_census_sha256: str,
    expected_request_sha256: str,
    node_args: Sequence[str] = (),
    base_env: Mapping[str, str] | None = None,
    popen_factory: Callable[..., Any] = subprocess.Popen,
    **popen_kwargs: Any,
) -> Any:
    """Authenticate immediately before spawning Node from one generation.

    The cross-process store lock is held through ``popen_factory`` invocation,
    preventing a cooperating install/recovery transaction from beginning in the
    validation-to-spawn interval.
    """
    root = _display_path(os.path.abspath(os.fspath(store_root)))
    relative = _safe_relative_entrypoint(entrypoint)
    expected_digests = {
        "receipt": expected_receipt_sha256,
        "census": expected_census_sha256,
        "request": expected_request_sha256,
    }
    if any(
        not isinstance(value, str) or not _HEX64_RE.fullmatch(value)
        for value in expected_digests.values()
    ):
        raise MCPRuntimeSecurityError("expected generation authority digest is malformed")
    if isinstance(node_args, (str, bytes)) or not all(
        isinstance(item, str) for item in node_args
    ):
        raise TypeError("node_args must be a sequence of strings")
    forbidden_overrides = {"shell", "executable", "preexec_fn", "env"}
    present_overrides = forbidden_overrides.intersection(popen_kwargs)
    if present_overrides:
        raise MCPRuntimeSecurityError(
            "unsafe Node process overrides are forbidden: "
            + ", ".join(sorted(present_overrides))
        )
    source_env = os.environ if base_env is None else base_env
    if not isinstance(source_env, Mapping) or not all(
        isinstance(key, str)
        and isinstance(value, str)
        and "\0" not in key
        and "\0" not in value
        for key, value in source_env.items()
    ):
        raise MCPRuntimeSecurityError("Node launch environment is malformed")
    sanitized_env = {
        key: value
        for key, value in source_env.items()
        if key.upper() not in {"NODE_OPTIONS", "NODE_PATH"}
        and not key.upper().startswith(("LD_", "DYLD_"))
    }
    with _store_lock(root, mode=_STORE_LOCK_SHARED, create=False):
        _assert_no_pending(root)
        validated = _validate_generation_locked(root, generation_id, verifier)
        if (
            validated.receipt_sha256 != expected_receipt_sha256
            or validated.census_sha256 != expected_census_sha256
            or validated.request_sha256 != expected_request_sha256
        ):
            raise MCPRuntimeSecurityError(
                "MCP generation differs from expected launch authority"
            )
        by_path = {row["path"]: row for row in validated.entries}
        row = by_path.get(relative)
        if row is None or row["kind"] != "file":
            raise MCPRuntimeSecurityError("MCP Node entrypoint is outside the receipt")
        entry_path = validated.payload_path.joinpath(*relative.split("/"))
        receipt_path = validated.generation_path / RECEIPT_NAME
        receipt_info = _require_plain_file(receipt_path, "MCP generation receipt")
        receipt = _parse_receipt(
            _read_file_exact(receipt_path, receipt_info), generation_id, verifier
        )
        if (
            relative
            != receipt["authority"]["generation_request"]["finalizer_policy"][
                "output_entrypoint"
            ]
        ):
            raise MCPRuntimeSecurityError(
                "requested Node entrypoint differs from receipt-bound finalizer output"
            )
        if (
            receipt["receipt_sha256"] != expected_receipt_sha256
            or receipt["authority"]["census_sha256"] != expected_census_sha256
            or receipt["authority"]["request_sha256"] != expected_request_sha256
            or receipt["authority"]["launch_environment_policy"]
            != _LAUNCH_ENVIRONMENT_POLICY
        ):
            raise MCPRuntimeSecurityError("Node launch environment policy differs")
        # Final authority replay under the held lock. No caller-controlled
        # process override or filesystem operation follows these checks.
        _assert_no_pending(root)
        entry_info = _require_plain_file(entry_path, "MCP Node entrypoint")
        entry_size, entry_digest = _digest_file_exact(entry_path, entry_info)
        if (
            entry_size != row["size"]
            or entry_digest != row["sha256"]
            or stat.S_IMODE(entry_info.st_mode) != row["mode"]
        ):
            raise MCPRuntimeSecurityError("MCP Node entrypoint changed before launch")
        current_node_authority = _node_executable_authority(node_executable)
        if current_node_authority != receipt["authority"]["node_executable_authority"]:
            raise MCPRuntimeSecurityError(
                "Node executable differs from signed generation authority"
        )
        node_path = Path(current_node_authority["canonical_path"])
        command = [str(_display_path(node_path)), str(_display_path(entry_path)), *node_args]
        return popen_factory(command, env=sanitized_env, **popen_kwargs)


def launch_generation_member(
    store_root: os.PathLike[str] | str,
    generation_id: str,
    relative_path: os.PathLike[str] | str,
    *,
    execution_kind: str,
    expected_size: int,
    expected_sha256: str,
    node_executable: os.PathLike[str] | str | None,
    verifier: Verifier,
    expected_receipt_sha256: str,
    expected_census_sha256: str,
    expected_request_sha256: str,
    expected_generation_policy_sha256: str,
    member_args: Sequence[str] = (),
    base_env: Mapping[str, str] | None = None,
    popen_factory: Callable[..., Any] = subprocess.Popen,
    full_census: bool = True,
    authenticated_member_authority: Mapping[str, Any] | None = None,
    **popen_kwargs: Any,
) -> Any:
    """Launch one selection-bound backend CLI member under the store lock.

    The signed current-selection is validated by the installed public front;
    this primitive independently replays either the full generation census or
    the signed exact transitive native resource closure immediately before
    spawning the selected backend executable.
    """
    root = _display_path(os.path.abspath(os.fspath(store_root)))
    relative = _safe_relative_entrypoint(relative_path)
    if execution_kind not in {"native", "node"}:
        raise MCPRuntimeSecurityError("backend execution kind differs")
    if type(full_census) is not bool:
        raise MCPRuntimeSecurityError("backend census policy differs")
    if (
        not isinstance(expected_size, int) or isinstance(expected_size, bool)
        or expected_size < 0
        or not isinstance(expected_sha256, str) or not _HEX64_RE.fullmatch(expected_sha256)
    ):
        raise MCPRuntimeSecurityError("backend member authority is malformed")
    if isinstance(member_args, (str, bytes)) or not all(
        isinstance(item, str) for item in member_args
    ):
        raise TypeError("member_args must be a sequence of strings")
    digests = (
        expected_receipt_sha256, expected_census_sha256,
        expected_request_sha256, expected_generation_policy_sha256,
    )
    if any(not isinstance(item, str) or not _HEX64_RE.fullmatch(item) for item in digests):
        raise MCPRuntimeSecurityError("expected generation authority digest is malformed")
    forbidden = {"shell", "executable", "preexec_fn", "env"}.intersection(popen_kwargs)
    if forbidden:
        raise MCPRuntimeSecurityError(
            "unsafe backend process overrides are forbidden: " + ", ".join(sorted(forbidden))
        )
    source_env = os.environ if base_env is None else base_env
    if not isinstance(source_env, Mapping) or not all(
        isinstance(key, str) and isinstance(value, str)
        and "\0" not in key and "\0" not in value
        for key, value in source_env.items()
    ):
        raise MCPRuntimeSecurityError("backend launch environment is malformed")
    sanitized_env = {
        key: value for key, value in source_env.items()
        if key.upper() not in {"NODE_OPTIONS", "NODE_PATH"}
        and not key.upper().startswith(("LD_", "DYLD_"))
    }
    with _store_lock(root, mode=_STORE_LOCK_SHARED, create=False):
        _assert_no_pending(root)
        if full_census:
            validated = _validate_generation_locked(root, generation_id, verifier)
            if (
                validated.receipt_sha256 != expected_receipt_sha256
                or validated.census_sha256 != expected_census_sha256
                or validated.request_sha256 != expected_request_sha256
            ):
                raise MCPRuntimeSecurityError("backend generation authority differs")
            payload_path = validated.payload_path
            receipt_path = validated.generation_path / RECEIPT_NAME
            row = {item["path"]: item for item in validated.entries}.get(relative)
            receipt_info = _require_plain_file(receipt_path, "MCP generation receipt")
            receipt = _parse_receipt(
                _read_file_exact(receipt_path, receipt_info), generation_id, verifier,
            )
            request = _request_from_authority(
                receipt["authority"]["generation_request"]
            )
            if generation_policy_sha256(request) != expected_generation_policy_sha256:
                raise MCPRuntimeSecurityError("backend generation policy differs")
        else:
            if execution_kind != "native":
                raise MCPRuntimeSecurityError(
                    "fast backend admission requires a signed native resource closure"
                )
            authority = _validate_signed_member_authority(
                authenticated_member_authority, verifier,
            )
            expected_projection = {
                "generation_id": generation_id,
                "receipt_sha256": expected_receipt_sha256,
                "census_sha256": expected_census_sha256,
                "request_sha256": expected_request_sha256,
                "generation_policy_sha256": expected_generation_policy_sha256,
                "execution_kind": execution_kind, "relative_path": relative,
                "size": expected_size, "sha256": expected_sha256,
            }
            if any(authority[key] != value for key, value in expected_projection.items()):
                raise MCPRuntimeSecurityError(
                    "signed member authority differs from selected backend"
                )
            payload_path, row = _validate_generation_member_seal_locked(
                root, authority, relative,
            )
        if (
            row is None or row.get("kind") != "file"
            or row.get("size") != expected_size or row.get("sha256") != expected_sha256
        ):
            raise MCPRuntimeSecurityError("backend member differs from signed selection")
        member = payload_path.joinpath(*relative.split("/"))
        info = _require_plain_file(member, "backend generation member")
        size, digest = _digest_file_exact(member, info)
        if (
            size != expected_size or digest != expected_sha256
            or stat.S_IMODE(info.st_mode) != row.get("mode")
            or info.st_nlink != row.get("link_count")
        ):
            raise MCPRuntimeSecurityError("backend member changed before launch")
        if execution_kind == "native":
            command = [str(_display_path(member)), *member_args]
        else:
            current_node = _node_executable_authority(node_executable)
            if current_node != receipt["authority"]["node_executable_authority"]:
                raise MCPRuntimeSecurityError("backend Node authority differs")
            command = [
                str(_display_path(Path(current_node["canonical_path"]))),
                str(_display_path(member)), *member_args,
            ]
        _assert_no_pending(root)
        return popen_factory(command, env=sanitized_env, **popen_kwargs)


__all__ = [
    "CENSUS_SCHEMA",
    "GENERATION_REQUEST_SCHEMA",
    "GENERATION_POLICY_SCHEMA",
    "MEMBER_AUTHORITY_SCHEMA",
    "GenerationRequest",
    "MCPRuntimeSecurityError",
    "MCPRuntimeStoreBusyError",
    "MCPRuntimeStoreCorruptError",
    "MCPRuntimeStoreUnavailableError",
    "PublishedGeneration",
    "RECEIPT_NAME",
    "RECEIPT_SCHEMA",
    "ValidatedGeneration",
    "ValidatedGenerationAuthority",
    "derive_generation_request",
    "generation_policy_sha256",
    "launch_generation_member",
    "materialization_environment",
    "native_resource_roster",
    "sign_generation_member_authority",
    "finalize_claude_native",
    "launch_node_generation",
    "recover_private_staging",
    "stage_npm_generation",
    "validate_generation_authority_fast",
    "validate_generation",
]
