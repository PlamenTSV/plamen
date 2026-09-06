"""Typed, byte-frozen inputs for deterministic report assembly.

This module is deliberately independent of the driver, ArtifactLedger, report
renderers, and quality gates.  A source capture answers which exact scratchpad
bytes and namespace members a report-assembly preparation step observed, but
carries no authority over report outputs.  A distinct final-capture successor
binds the committed source-capture producer and closes the fixed seven-output
universe: both mandatory outputs are present, while each conditional is
represented exactly once as present bytes or a canonical explicit absence.

Production callers must enter through ``report_capture_phaseio_authority``.
The codec/build/replay helpers in this module are private because a caller-
supplied mapping is data, never producer authority.  The adapter independently
resolves the active ArtifactLedger+PhaseIO receipt and replays exact bytes
immediately before construction, validation, extraction, or publication.

The mutable ArtifactLedger is intentionally not a source row.  Producer
authority belongs in PhaseIO input requirements; treating the ledger file as
ordinary data would create a self-reference because arming this work unit
changes that ledger.
"""
from __future__ import annotations

import base64
from contextlib import contextmanager
import ctypes
from dataclasses import dataclass, field
from datetime import date
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import unicodedata
from typing import Any, Iterator, Mapping
from uuid import UUID

if os.name == "nt":
    from ctypes import wintypes

    class _FILETIME(ctypes.Structure):
        _fields_ = (
            ("dwLowDateTime", wintypes.DWORD),
            ("dwHighDateTime", wintypes.DWORD),
        )

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

    _KERNEL32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _CREATE_FILE_W = _KERNEL32.CreateFileW
    _CREATE_FILE_W.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    )
    _CREATE_FILE_W.restype = wintypes.HANDLE
    _GET_FILE_INFORMATION_BY_HANDLE = _KERNEL32.GetFileInformationByHandle
    _GET_FILE_INFORMATION_BY_HANDLE.argtypes = (
        wintypes.HANDLE,
        ctypes.POINTER(_BY_HANDLE_FILE_INFORMATION),
    )
    _GET_FILE_INFORMATION_BY_HANDLE.restype = wintypes.BOOL
    _GET_FINAL_PATH_NAME_BY_HANDLE_W = _KERNEL32.GetFinalPathNameByHandleW
    _GET_FINAL_PATH_NAME_BY_HANDLE_W.argtypes = (
        wintypes.HANDLE,
        wintypes.LPWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
    )
    _GET_FINAL_PATH_NAME_BY_HANDLE_W.restype = wintypes.DWORD
    _READ_FILE = _KERNEL32.ReadFile
    _READ_FILE.argtypes = (
        wintypes.HANDLE,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        ctypes.c_void_p,
    )
    _READ_FILE.restype = wintypes.BOOL
    _SET_FILE_POINTER_EX = _KERNEL32.SetFilePointerEx
    _SET_FILE_POINTER_EX.argtypes = (
        wintypes.HANDLE,
        ctypes.c_longlong,
        ctypes.POINTER(ctypes.c_longlong),
        wintypes.DWORD,
    )
    _SET_FILE_POINTER_EX.restype = wintypes.BOOL
    _CLOSE_HANDLE = _KERNEL32.CloseHandle
    _CLOSE_HANDLE.argtypes = (wintypes.HANDLE,)
    _CLOSE_HANDLE.restype = wintypes.BOOL


SOURCE_SCHEMA_VERSION = "plamen.report_assembly_source_capture.v3"
FINAL_SCHEMA_VERSION = "plamen.report_assembly_final_capture.v1"
SCHEMA_VERSION = SOURCE_SCHEMA_VERSION
SOURCE_CAPTURE_IDENTITY = "scratchpad:report_assembly_source_capture.json"
FINAL_CAPTURE_IDENTITY = "scratchpad:report_assembly_final_capture.json"
PRESENT = "PRESENT"
ABSENT = "ABSENT"

_CAPTURE_KEYS = frozenset(
    {
        "schema_version",
        "metadata",
        "fixed_sources",
        "namespace_specs",
        "sources",
        "namespaces",
        "input_paths",
        "explicit_absences",
        "source_set_digest",
        "capture_digest",
    }
)
_FINAL_CAPTURE_KEYS = frozenset(
    {
        "schema_version",
        "metadata",
        "predecessor_binding",
        "derived_outputs",
        "location_decisions",
        "capture_digest",
    }
)
_PREDECESSOR_KEYS = frozenset(
    {
        "artifact_identity",
        "content_sha256",
        "run_id",
        "producer_work_unit_key",
        "contract_digest",
        "launch_digest",
        "commit_receipt_digest",
    }
)
_METADATA_KEYS = frozenset(
    {
        "backend",
        "ecosystem",
        "mode",
        "pipeline",
        "project_name",
        "report_date",
        "run_id",
        "scope",
        "source_roster_authority_sha256",
        "source_snapshot_sha256",
    }
)
_SOURCE_KEYS = frozenset(
    {
        "path",
        "roles",
        "presence",
        "size",
        "sha256",
        "content_base64",
    }
)
_NAMESPACE_KEYS = frozenset(
    {
        "pattern",
        "role",
        "members",
        "member_count",
        "membership_digest",
    }
)
_SPEC_KEYS = frozenset({"path", "role"})
_NAMESPACE_SPEC_KEYS = frozenset({"pattern", "role"})
_OUTPUT_KEYS = frozenset(
    {
        "root",
        "path",
        "role",
        "presence",
        "size",
        "sha256",
        "content_base64",
    }
)
_LOCATION_KEYS = frozenset(
    {
        "decision",
        "original_location",
        "report_id",
        "resolved_location",
        "source_paths",
        "source_snapshot_sha256",
    }
)
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
_DIMENSION_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]*$", re.ASCII)
_ROLE_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,95}$", re.ASCII)
_PATTERN_RE = re.compile(r"^[A-Za-z0-9_.*/-]+$", re.ASCII)
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_REPORT_ID_RE = re.compile(r"^[CHMLI]-[0-9]{1,4}$", re.ASCII)
_LOCATION_PATH_RE = re.compile(
    r"^(?P<path>.+?)(?P<suffix>:(?:[Ll])?[0-9]+"
    r"(?:(?:-|:)(?:[Ll])?[0-9]+)?)$",
    re.ASCII,
)
_LOCATION_DECISIONS = frozenset(
    {"NOT_APPLICABLE", "RECOVERED_FROM_INDEX", "UNCHANGED", "UNRESOLVED"}
)

_MAX_SOURCE_COUNT = 8_192
_MAX_FILE_BYTES = 16 * 1024 * 1024
_MAX_TOTAL_BYTES = 128 * 1024 * 1024
_MAX_OUTPUT_COUNT = 64
_MAX_NAMESPACE_COUNT = 64
_MAX_LOCATION_COUNT = 8_192
_MAX_LOCATION_SOURCE_PATHS = 64
_MAX_SOURCE_ROLES = _MAX_NAMESPACE_COUNT + 1
_MAX_PATH_CHARS = 1_024
_MAX_PATH_COMPONENT_CHARS = 255
_MAX_PATTERN_CHARS = 1_024
_MAX_CANONICAL_BYTES = 192 * 1024 * 1024
_READ_CHUNK_BYTES = 1024 * 1024

_WIN_INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
_WIN_GENERIC_READ = 0x80000000
_WIN_SHARE_READ = 0x00000001
_WIN_SHARE_WRITE = 0x00000002
_WIN_SHARE_DELETE = 0x00000004
_WIN_OPEN_EXISTING = 3
_WIN_FILE_ATTRIBUTE_DIRECTORY = 0x00000010
_WIN_FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
_WIN_FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
_WIN_FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
_WIN_FILE_BEGIN = 0
_WIN_FINAL_PATH_BUFFER_CHARS = 32_768

_WIN_RESERVED_DEVICE_STEMS = frozenset(
    {
        "con",
        "prn",
        "aux",
        "nul",
        "clock$",
        "conin$",
        "conout$",
        *(f"com{ordinal}" for ordinal in range(1, 10)),
        *(f"lpt{ordinal}" for ordinal in range(1, 10)),
        "com¹",
        "com²",
        "com³",
        "lpt¹",
        "lpt²",
        "lpt³",
    }
)


DEFAULT_FIXED_SOURCE_ROLES: dict[str, str] = {
    "_coverage_shortfalls.json": "COVERAGE_SHORTFALL_AUTHORITY",
    "chain_composition_coverage_gaps.md": "CHAIN_COVERAGE_DEBT",
    "contract_inventory.md": "COMPONENT_FALLBACK_CONTRACTS",
    "depth_finalization_report_authority.json": "DEPTH_FINALIZATION_REPORT_AUTHORITY",
    "disposition.md": "REPORT_DISPOSITION",
    "exact_scope_coverage_authority.json": "EXACT_SCOPE_COVERAGE_AUTHORITY",
    "file_coverage_ledger.md": "COMPONENT_FILE_COVERAGE",
    "finding_delivery_receipt.json": "FINDING_DELIVERY_LEGACY_RECEIPT",
    "finding_delivery_successor.json": "FINDING_DELIVERY_SUCCESSOR",
    "findings_inventory.md": "COMPONENT_FINDING_CONTEXT",
    "mandatory_reverification_assignment.json": "MANDATORY_ASSIGNMENT",
    "mandatory_reverification_completion.json": "MANDATORY_COMPLETION",
    "mandatory_reverification_denominator.json": "MANDATORY_DENOMINATOR",
    "mandatory_reverification_routing.json": "MANDATORY_ROUTING",
    "negative_closure_broker_authority.json": "NEGATIVE_CLOSURE_AUTHORITY",
    "preverify_inventory_successor.json": "PREVERIFY_INVENTORY_SUCCESSOR",
    "judge_decisions.json": "JUDGE_TYPED_DECISIONS",
    "report_critical_high.md": "TIER_CRITICAL_HIGH",
    "report_evidence_projection.md": "REPORT_EVIDENCE_PROJECTION",
    "report_evidence_records.json": "REPORT_EVIDENCE_AUTHORITY",
    "report_human_review_authority.json": "REPORT_HUMAN_REVIEW_AUTHORITY",
    "report_index.md": "REPORT_INDEX",
    "report_index_status_projection.json": "REPORT_INDEX_STATUS",
    "report_low_info.md": "TIER_LOW_INFO",
    "report_low_info_a.md": "TIER_LOW_INFO_SHARD",
    "report_low_info_b.md": "TIER_LOW_INFO_SHARD",
    "report_medium.md": "TIER_MEDIUM",
    "report_medium_a.md": "TIER_MEDIUM_SHARD",
    "report_medium_b.md": "TIER_MEDIUM_SHARD",
    "report_records.json": "REPORT_RECORDS",
    "report_source_path_authority.json": "PRODUCTION_SOURCE_PATH_AUTHORITY",
    "report_semantic_retention_risks.md": "RETENTION_REVIEW_DEBT",
    "report_semantic_severity_repairs.md": "SEVERITY_REVIEW_DEBT",
    "security_obligation_authority.json": "SECURITY_OBLIGATION_AUTHORITY",
    "security_obligation_lifecycle.json": "SECURITY_OBLIGATION_LIFECYCLE",
    "security_obligation_report_retention.md": "LIFECYCLE_RETENTION_CACHE",
    "severity_binding.md": "SEVERITY_BINDING",
    "skeptic_judge_decisions.md": "JUDGE_PRIMARY",
    "status_binding.md": "STATUS_BINDING",
    "subsystem_map.md": "COMPONENT_SUBSYSTEM_MAP",
    "verification_queue.work_items.json": "VERIFICATION_QUEUE_ITEMS",
    "verification_queue.work_plan.json": "VERIFICATION_QUEUE_PLAN",
    "verification_runtime_roster.json": "VERIFIER_RUNTIME_ROSTER",
}

DEFAULT_NAMESPACE_ROLES: dict[str, str] = {
    "body_manifests/report_*.json": "BODY_MANIFEST_NAMESPACE",
    "judge_*.md": "JUDGE_FALLBACK_NAMESPACE",
    "negative_closure_provider_bundles/**/*": "NEGATIVE_CLOSURE_BUNDLE_NAMESPACE",
    "report_evidence_manifests/*.json": "REPORT_EVIDENCE_MANIFEST_NAMESPACE",
    "report_semantic_*.md": "REPORT_SEMANTIC_NAMESPACE",
}

ALLOWED_DERIVED_OUTPUT_ROLES: dict[str, str] = {
    "project:AUDIT_REPORT.md": "CLIENT_REPORT",
    "scratchpad:report_assemble_retry_hint.md": "REPORT_RETRY_HINT",
    "scratchpad:report_consolidation_internal.md": "INTERNAL_CONSOLIDATION",
    "scratchpad:report_evidence_quality_receipt.json": (
        "REPORT_EVIDENCE_QUALITY"
    ),
    "scratchpad:report_quality.md": "REPORT_QUALITY",
    "scratchpad:report_quality_debt.json": "REPORT_QUALITY_DEBT",
    "scratchpad:report_traceability_internal.md": "INTERNAL_TRACEABILITY",
}
MANDATORY_DERIVED_OUTPUTS = frozenset(
    {
        "project:AUDIT_REPORT.md",
        "scratchpad:report_quality.md",
    }
)


class ReportAssemblyCaptureError(ValueError):
    """The report source capture is malformed, unsafe, or no longer current."""


def _fail(code: str, detail: str = "") -> None:
    suffix = f": {detail}" if detail else ""
    raise ReportAssemblyCaptureError(f"{code}{suffix}")


def _digest(value: object) -> str:
    raw = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _canonical_json_bytes(value: object) -> bytes:
    raw = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    if len(raw) + 1 > _MAX_CANONICAL_BYTES:
        _fail("CAPTURE_CANONICAL_SIZE_LIMIT", str(len(raw) + 1))
    return raw


def _canonical_report_assembly_source_capture_bytes(
    payload: Mapping[str, Any],
) -> bytes:
    """Return canonical source-capture JSON after full validation."""

    value = _validate_report_assembly_source_capture(payload)
    return _canonical_json_bytes(value) + b"\n"


def _canonical_report_assembly_final_capture_bytes(
    payload: Mapping[str, Any],
    *,
    expected_final_artifact_identity: str,
    expected_predecessor_binding: Mapping[str, str],
) -> bytes:
    """Return canonical final-capture JSON under external authority."""

    value = _validate_report_assembly_final_capture(
        payload,
        expected_final_artifact_identity=expected_final_artifact_identity,
        expected_predecessor_binding=expected_predecessor_binding,
    )
    return _canonical_json_bytes(value) + b"\n"


def _canonical_path(value: object) -> str:
    if not isinstance(value, str) or not value:
        _fail("PATH_INVALID", repr(value))
    if len(value) > _MAX_PATH_CHARS:
        _fail("PATH_SIZE_LIMIT", value[:80])
    if value != value.strip():
        _fail("PATH_INVALID", repr(value))
    if "\\" in value or re.match(r"^[A-Za-z]:", value) or value.startswith("/"):
        _fail("PATH_INVALID", value)
    if unicodedata.normalize("NFC", value) != value:
        _fail("PATH_NON_NFC", value)
    candidate = PurePosixPath(value)
    if (
        candidate.is_absolute()
        or candidate.as_posix() != value
        or any(part in {"", ".", ".."} or ":" in part for part in candidate.parts)
    ):
        _fail("PATH_INVALID", value)
    if any(char in value for char in '*?[]<>|"'):
        _fail("PATH_GLOB_NOT_ALLOWED", value)
    if any(
        len(part) > _MAX_PATH_COMPONENT_CHARS
        or part.rstrip(" .") != part
        for part in candidate.parts
    ):
        _fail("PATH_WINDOWS_ALIAS", value)
    if any(
        part.split(".", 1)[0].rstrip(" ").casefold()
        in _WIN_RESERVED_DEVICE_STEMS
        for part in candidate.parts
    ):
        _fail("PATH_WINDOWS_DEVICE", value)
    return value


def _canonical_pattern(value: object) -> str:
    if not isinstance(value, str) or not value:
        _fail("NAMESPACE_PATTERN_INVALID", repr(value))
    if len(value) > _MAX_PATTERN_CHARS:
        _fail("NAMESPACE_PATTERN_SIZE_LIMIT", value[:80])
    if value != value.strip():
        _fail("NAMESPACE_PATTERN_INVALID", repr(value))
    if (
        "\\" in value
        or re.match(r"^[A-Za-z]:", value)
        or value.startswith("/")
        or "//" in value
        or not _PATTERN_RE.fullmatch(value)
    ):
        _fail("NAMESPACE_PATTERN_INVALID", value)
    if unicodedata.normalize("NFC", value) != value:
        _fail("NAMESPACE_PATTERN_NON_NFC", value)
    parts = value.split("/")
    if any(part in {"", ".", ".."} or ":" in part for part in parts):
        _fail("NAMESPACE_PATTERN_INVALID", value)
    if any(
        len(part) > _MAX_PATH_COMPONENT_CHARS
        or part.rstrip(" .") != part
        for part in parts
    ):
        _fail("NAMESPACE_PATTERN_WINDOWS_ALIAS", value)
    if any(
        not any(marker in part for marker in "*?")
        and part.split(".", 1)[0].rstrip(" ").casefold()
        in _WIN_RESERVED_DEVICE_STEMS
        for part in parts
    ):
        _fail("NAMESPACE_PATTERN_WINDOWS_DEVICE", value)
    if not any("*" in part for part in parts):
        _fail("NAMESPACE_PATTERN_HAS_NO_WILDCARD", value)
    if any("***" in part for part in parts):
        _fail("NAMESPACE_PATTERN_INVALID", value)
    return value


def _filesystem_key(value: str) -> str:
    """Return a conservative cross-platform identity for a canonical path."""

    return "/".join(part.casefold() for part in value.split("/"))


def _canonical_role(value: object) -> str:
    if (
        not isinstance(value, str)
        or len(value) > 96
        or not _ROLE_RE.fullmatch(value)
    ):
        _fail("ROLE_INVALID", repr(value))
    return value


def _normalized_metadata(value: object) -> dict[str, str]:
    if not isinstance(value, Mapping) or set(value) != _METADATA_KEYS:
        _fail("METADATA_SCHEMA", "exact deterministic metadata fields required")
    out: dict[str, str] = {}
    for key in sorted(_METADATA_KEYS):
        raw = value.get(key)
        if not isinstance(raw, str) or raw != raw.strip() or not raw:
            _fail("METADATA_VALUE", key)
        if len(raw) > 4_096 or _CONTROL_RE.search(raw):
            _fail("METADATA_VALUE", key)
        if unicodedata.normalize("NFC", raw) != raw:
            _fail("METADATA_NON_NFC", key)
        out[key] = raw
    for key in ("pipeline", "mode", "ecosystem", "backend"):
        if not _DIMENSION_RE.fullmatch(out[key]):
            _fail("METADATA_DIMENSION", key)
    try:
        parsed_run_id = UUID(out["run_id"])
    except (ValueError, AttributeError):
        _fail("METADATA_RUN_ID", out["run_id"])
    if parsed_run_id.version != 4 or str(parsed_run_id) != out["run_id"]:
        _fail("METADATA_RUN_ID", out["run_id"])
    if not _HEX64_RE.fullmatch(out["source_snapshot_sha256"]):
        _fail("METADATA_SOURCE_SNAPSHOT", out["source_snapshot_sha256"])
    if not _HEX64_RE.fullmatch(out["source_roster_authority_sha256"]):
        _fail(
            "METADATA_SOURCE_ROSTER_AUTHORITY",
            out["source_roster_authority_sha256"],
        )
    try:
        parsed_date = date.fromisoformat(out["report_date"])
    except ValueError:
        _fail("METADATA_REPORT_DATE", out["report_date"])
    if parsed_date.isoformat() != out["report_date"]:
        _fail("METADATA_REPORT_DATE", out["report_date"])
    return out


def _normalized_fixed_specs(value: Mapping[str, str]) -> list[dict[str, str]]:
    if not isinstance(value, Mapping) or len(value) > _MAX_SOURCE_COUNT:
        _fail("FIXED_SOURCE_SCHEMA")
    rows = [
        {"path": _canonical_path(path), "role": _canonical_role(role)}
        for path, role in value.items()
    ]
    rows.sort(key=lambda row: row["path"])
    paths = [row["path"] for row in rows]
    if len(paths) != len(set(paths)) or len(paths) != len(
        {_filesystem_key(path) for path in paths}
    ):
        _fail("FIXED_SOURCE_ALIAS")
    return rows


def _normalized_namespace_specs(value: Mapping[str, str]) -> list[dict[str, str]]:
    if not isinstance(value, Mapping) or len(value) > _MAX_NAMESPACE_COUNT:
        _fail("NAMESPACE_SPEC_SCHEMA")
    rows = [
        {"pattern": _canonical_pattern(pattern), "role": _canonical_role(role)}
        for pattern, role in value.items()
    ]
    rows.sort(key=lambda row: row["pattern"])
    patterns = [row["pattern"] for row in rows]
    if len(patterns) != len(set(patterns)) or len(patterns) != len(
        {_filesystem_key(pattern) for pattern in patterns}
    ):
        _fail("NAMESPACE_SPEC_ALIAS")
    return rows


def _is_reparse(path: Path) -> bool:
    try:
        attrs = int(getattr(path.lstat(), "st_file_attributes", 0))
    except OSError:
        return False
    return bool(attrs & int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)))


@dataclass(frozen=True)
class _PinnedRoot:
    path: Path
    descriptor: int | None = None
    handle: object | None = None
    identity: tuple[int, ...] = ()
    windows_directories: dict[str, "_PinnedWindowsDirectory"] = field(
        default_factory=dict,
        compare=False,
    )
    absent_paths: set[str] = field(default_factory=set, compare=False)
    retained_files: dict[str, "_RetainedFile"] = field(
        default_factory=dict,
        compare=False,
    )
    retained_posix_directories: dict[str, "_RetainedPosixDirectory"] = field(
        default_factory=dict,
        compare=False,
    )
    retained_namespace_members: dict[str, tuple[str, ...]] = field(
        default_factory=dict,
        compare=False,
    )
    retained_windows_root_identity: tuple[int, ...] = ()
    retained_windows_root_stat_identity: tuple[int, ...] = ()


@dataclass(frozen=True)
class _PinnedWindowsDirectory:
    relative: str
    path: Path
    handle: object
    identity: tuple[int, ...]
    final_path: str


@dataclass(frozen=True)
class _RetainedFile:
    relative: str
    path: Path
    expected_bytes: bytes
    expected_sha256: str
    expected_size: int
    physical_identity: tuple[int, ...]
    maximum_bytes: int
    descriptor: int | None = None
    handle: object | None = None


@dataclass(frozen=True)
class _RetainedPosixDirectory:
    relative: str
    descriptor: int
    physical_identity: tuple[int, ...]


def _posix_root_identity(row: os.stat_result) -> tuple[int, ...]:
    return (
        int(row.st_mode),
        int(getattr(row, "st_dev", 0)),
        int(getattr(row, "st_ino", 0)),
    )


def _directory_metadata_identity(row: os.stat_result) -> tuple[int, ...]:
    if not stat.S_ISDIR(row.st_mode) or stat.S_ISLNK(row.st_mode):
        _fail("TERMINAL_NAMESPACE_DIRECTORY_TYPE")
    return (
        int(row.st_mode),
        int(getattr(row, "st_mtime_ns", 0)),
        int(getattr(row, "st_ctime_ns", 0)),
        int(getattr(row, "st_dev", 0)),
        int(getattr(row, "st_ino", 0)),
        int(getattr(row, "st_nlink", 1)),
        int(getattr(row, "st_file_attributes", 0)),
    )


def _windows_file_index(info: object) -> int:
    return (int(info.nFileIndexHigh) << 32) | int(info.nFileIndexLow)


def _windows_stat_matches_information(
    row: os.stat_result,
    info: object,
    *,
    require_directory: bool,
) -> bool:
    attributes = int(info.dwFileAttributes)
    return (
        bool(attributes & _WIN_FILE_ATTRIBUTE_DIRECTORY) == require_directory
        and not bool(attributes & _WIN_FILE_ATTRIBUTE_REPARSE_POINT)
        and stat.S_ISDIR(row.st_mode) == require_directory
        and not stat.S_ISLNK(row.st_mode)
        and not bool(
            int(getattr(row, "st_file_attributes", 0))
            & _WIN_FILE_ATTRIBUTE_REPARSE_POINT
        )
        and int(getattr(row, "st_ino", 0)) == _windows_file_index(info)
        and int(getattr(row, "st_nlink", 1)) == int(info.nNumberOfLinks)
        and (
            require_directory
            or int(row.st_size) == _windows_information_size(info)
        )
    )


def _open_posix_child_directory(
    parent_descriptor: int,
    component: str,
    flags: int,
    *,
    error_code: str,
    detail: str,
    allow_missing: bool = False,
) -> int | None:
    """Open one directory child and transfer ownership only after fstat.

    Keeping the provisional descriptor local is important: an injected or
    kernel-level fstat failure must not leak the just-opened child while the
    caller still owns the parent descriptor.
    """

    child = -1
    try:
        child = os.open(component, flags, dir_fd=parent_descriptor)
        child_row = os.fstat(child)
        if not stat.S_ISDIR(child_row.st_mode):
            _fail(error_code, detail)
        result = child
        child = -1
        return result
    except FileNotFoundError:
        if allow_missing:
            return None
        _fail(error_code, detail)
    except ReportAssemblyCaptureError:
        raise
    except OSError as exc:
        _fail(error_code, f"{detail}: {type(exc).__name__}")
    finally:
        if child >= 0:
            try:
                os.close(child)
            except OSError:
                pass


def _open_posix_pinned_root(candidate: Path) -> _PinnedRoot:
    nofollow = int(getattr(os, "O_NOFOLLOW", 0) or 0)
    directory_flag = int(getattr(os, "O_DIRECTORY", 0) or 0)
    supports_dir_fd = os.open in getattr(os, "supports_dir_fd", set())
    if not nofollow or not directory_flag or not supports_dir_fd:
        _fail("CAPTURE_ROOT_NOFOLLOW_UNAVAILABLE", str(candidate))
    if not candidate.anchor:
        _fail("CAPTURE_ROOT_UNSAFE", str(candidate))
    flags = (
        os.O_RDONLY
        | nofollow
        | directory_flag
        | int(getattr(os, "O_CLOEXEC", 0) or 0)
    )
    descriptor = -1
    try:
        descriptor = os.open(candidate.anchor, flags)
        for component in candidate.parts[1:]:
            child = _open_posix_child_directory(
                descriptor,
                component,
                flags,
                error_code="CAPTURE_ROOT_NOFOLLOW_OPEN",
                detail=str(candidate),
            )
            if child is None:  # pragma: no cover - allow_missing is false
                _fail("CAPTURE_ROOT_NOFOLLOW_OPEN", str(candidate))
            os.close(descriptor)
            descriptor = child
        row = os.fstat(descriptor)
        if not stat.S_ISDIR(row.st_mode):
            _fail("CAPTURE_ROOT_UNSAFE", str(candidate))
        return _PinnedRoot(
            path=candidate,
            descriptor=descriptor,
            identity=_posix_root_identity(row),
        )
    except ReportAssemblyCaptureError:
        if descriptor >= 0:
            os.close(descriptor)
        raise
    except OSError as exc:
        if descriptor >= 0:
            os.close(descriptor)
        _fail("CAPTURE_ROOT_NOFOLLOW_OPEN", f"{candidate}: {type(exc).__name__}")


def _open_windows_pinned_root(candidate: Path) -> _PinnedRoot:
    handle = _CREATE_FILE_W(
        _windows_native_path(candidate),
        _WIN_GENERIC_READ,
        # The lexical capture root must not be renamed out from under the
        # retained handle.  Readers and ordinary writers may coexist, but a
        # delete/rename opener is deliberately denied for the capture window.
        _WIN_SHARE_READ | _WIN_SHARE_WRITE,
        None,
        _WIN_OPEN_EXISTING,
        _WIN_FILE_FLAG_OPEN_REPARSE_POINT | _WIN_FILE_FLAG_BACKUP_SEMANTICS,
        None,
    )
    if handle == _WIN_INVALID_HANDLE_VALUE:
        _fail("CAPTURE_ROOT_NOFOLLOW_OPEN", str(candidate))
    try:
        info = _windows_file_information(handle, relative="<capture-root>")
        attributes = int(info.dwFileAttributes)
        if (
            not attributes & _WIN_FILE_ATTRIBUTE_DIRECTORY
            or attributes & _WIN_FILE_ATTRIBUTE_REPARSE_POINT
        ):
            _fail("CAPTURE_ROOT_LINK_UNSAFE", str(candidate))
        expected = os.path.normcase(os.path.normpath(os.fspath(candidate)))
        observed = os.path.normcase(
            _windows_final_path(handle, relative="<capture-root>")
        )
        if observed != expected:
            _fail("CAPTURE_ROOT_FINAL_PATH_ESCAPE", str(candidate))
        return _PinnedRoot(
            path=candidate,
            handle=handle,
            identity=_windows_information_identity(info),
        )
    except Exception:
        _CLOSE_HANDLE(handle)
        raise


def _verify_pinned_root(root: _PinnedRoot) -> None:
    try:
        path_row = os.lstat(root.path)
    except OSError as exc:
        _fail("CAPTURE_ROOT_IDENTITY_DRIFT", type(exc).__name__)
    if os.name == "nt":
        if root.handle is None:
            _fail("CAPTURE_ROOT_HANDLE_MISSING")
        info = _windows_file_information(root.handle, relative="<capture-root>")
        if (
            _windows_information_identity(info) != root.identity
            or not _windows_stat_matches_information(
                path_row,
                info,
                require_directory=True,
            )
        ):
            _fail("CAPTURE_ROOT_IDENTITY_DRIFT", str(root.path))
        expected = os.path.normcase(os.path.normpath(os.fspath(root.path)))
        observed = os.path.normcase(
            _windows_final_path(root.handle, relative="<capture-root>")
        )
        if observed != expected:
            _fail("CAPTURE_ROOT_FINAL_PATH_ESCAPE", str(root.path))
        return
    if root.descriptor is None:
        _fail("CAPTURE_ROOT_DESCRIPTOR_MISSING")
    handle_row = os.fstat(root.descriptor)
    if (
        not stat.S_ISDIR(path_row.st_mode)
        or stat.S_ISLNK(path_row.st_mode)
        or _is_reparse(root.path)
        or _posix_root_identity(handle_row) != root.identity
        or _posix_root_identity(path_row) != root.identity
    ):
        _fail("CAPTURE_ROOT_IDENTITY_DRIFT", str(root.path))


@contextmanager
def _pinned_root(root: Path) -> Iterator[_PinnedRoot]:
    candidate = Path(os.path.abspath(os.fspath(root)))
    pinned = (
        _open_windows_pinned_root(candidate)
        if os.name == "nt"
        else _open_posix_pinned_root(candidate)
    )
    try:
        # This path projection is not authoritative.  Keeping the check makes a
        # concurrent lexical swap observable before the first enumeration.
        try:
            candidate_is_dir = candidate.is_dir()
        except OSError as exc:
            _fail("CAPTURE_ROOT_IDENTITY_DRIFT", type(exc).__name__)
        if not candidate_is_dir:
            _fail("CAPTURE_ROOT_UNSAFE", str(candidate))
        _verify_pinned_root(pinned)
        yield pinned
        _verify_pinned_capture(pinned)
    finally:
        for retained in tuple(pinned.retained_files.values()):
            if retained.descriptor is not None:
                try:
                    os.close(retained.descriptor)
                except OSError:
                    pass
            if retained.handle is not None:
                _CLOSE_HANDLE(retained.handle)
        pinned.retained_files.clear()
        for directory in tuple(pinned.retained_posix_directories.values()):
            try:
                os.close(directory.descriptor)
            except OSError:
                pass
        pinned.retained_posix_directories.clear()
        for directory in reversed(
            tuple(pinned.windows_directories.values())
        ):
            _CLOSE_HANDLE(directory.handle)
        pinned.windows_directories.clear()
        if pinned.descriptor is not None:
            os.close(pinned.descriptor)
        if pinned.handle is not None:
            _CLOSE_HANDLE(pinned.handle)


def _assert_safe_ancestors(root: Path, relative: str) -> Path:
    path = root
    for part in PurePosixPath(relative).parts:
        path = path / part
        if path.is_symlink() or _is_reparse(path):
            _fail("SOURCE_LINK_UNSAFE", relative)
    return path


def _source_metadata_identity(row: os.stat_result) -> tuple[int, ...]:
    return (
        int(row.st_mode),
        int(row.st_size),
        int(getattr(row, "st_mtime_ns", 0)),
        int(getattr(row, "st_ctime_ns", 0)),
        int(getattr(row, "st_dev", 0)),
        int(getattr(row, "st_ino", 0)),
        int(getattr(row, "st_nlink", 1)),
        int(getattr(row, "st_file_attributes", 0)),
    )


def _validate_source_metadata(
    row: os.stat_result,
    *,
    relative: str,
    maximum_bytes: int | None = None,
) -> None:
    limit = _MAX_FILE_BYTES if maximum_bytes is None else maximum_bytes
    if (
        not stat.S_ISREG(row.st_mode)
        or stat.S_ISLNK(row.st_mode)
        or bool(
            int(getattr(row, "st_file_attributes", 0))
            & _WIN_FILE_ATTRIBUTE_REPARSE_POINT
        )
    ):
        _fail("SOURCE_NOT_NOFOLLOW_REGULAR", relative)
    if row.st_size < 0 or row.st_size > limit:
        _fail("SOURCE_SIZE_LIMIT", relative)
    if int(getattr(row, "st_nlink", 1)) != 1:
        _fail("SOURCE_MULTILINK_UNSAFE", relative)


def _read_descriptor_bounded(
    descriptor: int,
    *,
    relative: str,
    maximum_bytes: int | None = None,
) -> bytes:
    limit = _MAX_FILE_BYTES if maximum_bytes is None else maximum_bytes
    chunks: list[bytes] = []
    remaining = limit + 1
    while remaining:
        try:
            chunk = os.read(
                descriptor,
                min(_READ_CHUNK_BYTES, remaining),
            )
        except OSError as exc:
            _fail("SOURCE_READ", f"{relative}: {type(exc).__name__}")
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    raw = b"".join(chunks)
    if len(raw) > limit:
        _fail("SOURCE_SIZE_LIMIT", relative)
    return raw


def _open_posix_rooted_source(
    root: _PinnedRoot,
    relative: str,
) -> int:
    nofollow = int(getattr(os, "O_NOFOLLOW", 0) or 0)
    directory_flag = int(getattr(os, "O_DIRECTORY", 0) or 0)
    supports_dir_fd = os.open in getattr(os, "supports_dir_fd", set())
    if not nofollow or not directory_flag or not supports_dir_fd:
        _fail("SOURCE_NOFOLLOW_UNAVAILABLE", relative)
    if root.descriptor is None:
        _fail("SOURCE_ROOT_DESCRIPTOR_MISSING", relative)
    directory_flags = (
        os.O_RDONLY
        | nofollow
        | directory_flag
        | int(getattr(os, "O_CLOEXEC", 0) or 0)
    )
    file_flags = (
        os.O_RDONLY
        | nofollow
        | int(getattr(os, "O_CLOEXEC", 0) or 0)
        | int(getattr(os, "O_BINARY", 0) or 0)
    )
    descriptor = -1
    try:
        descriptor = os.dup(root.descriptor)
        relative_parts = PurePosixPath(relative).parts
        for component in relative_parts[:-1]:
            child = _open_posix_child_directory(
                descriptor,
                component,
                directory_flags,
                error_code="SOURCE_PARENT_NOFOLLOW_OPEN",
                detail=relative,
            )
            if child is None:  # pragma: no cover - allow_missing is false
                _fail("SOURCE_PARENT_NOFOLLOW_OPEN", relative)
            os.close(descriptor)
            descriptor = child
        source = os.open(
            relative_parts[-1],
            file_flags,
            dir_fd=descriptor,
        )
    except ReportAssemblyCaptureError:
        raise
    except OSError as exc:
        _fail("SOURCE_NOFOLLOW_OPEN", f"{relative}: {type(exc).__name__}")
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass
    return source


def _read_posix_rooted_source(
    root: _PinnedRoot,
    relative: str,
    path: Path,
    before: os.stat_result,
    *,
    maximum_bytes: int | None = None,
) -> bytes:
    descriptor = _open_posix_rooted_source(root, relative)
    try:
        opened = os.fstat(descriptor)
        _validate_source_metadata(
            opened, relative=relative, maximum_bytes=maximum_bytes
        )
        if _source_metadata_identity(opened) != _source_metadata_identity(before):
            _fail("SOURCE_OPEN_IDENTITY_DRIFT", relative)
        first = _read_descriptor_bounded(
            descriptor, relative=relative, maximum_bytes=maximum_bytes
        )
        try:
            os.lseek(descriptor, 0, os.SEEK_SET)
        except OSError as exc:
            _fail("SOURCE_SEEK", f"{relative}: {type(exc).__name__}")
        second = _read_descriptor_bounded(
            descriptor, relative=relative, maximum_bytes=maximum_bytes
        )
        after_handle = os.fstat(descriptor)
        _verify_pinned_root(root)
        _assert_safe_ancestors(root.path, relative)
        try:
            after_path = os.lstat(path)
        except OSError as exc:
            _fail("SOURCE_POST_STAT", f"{relative}: {type(exc).__name__}")
        _validate_source_metadata(
            after_path, relative=relative, maximum_bytes=maximum_bytes
        )
        identity = _source_metadata_identity(opened)
        if (
            first != second
            or identity != _source_metadata_identity(after_handle)
            or identity != _source_metadata_identity(after_path)
            or len(first) != int(opened.st_size)
        ):
            _fail("SOURCE_READ_IDENTITY_DRIFT", relative)
        return first
    finally:
        os.close(descriptor)


def _windows_native_path(path: Path) -> str:
    absolute = os.path.abspath(os.fspath(path))
    if absolute.startswith("\\\\"):
        return "\\\\?\\UNC\\" + absolute[2:]
    return "\\\\?\\" + absolute


def _windows_file_information(
    handle: object,
    *,
    relative: str,
) -> object:
    info = _BY_HANDLE_FILE_INFORMATION()
    if not _GET_FILE_INFORMATION_BY_HANDLE(handle, ctypes.byref(info)):
        _fail("SOURCE_HANDLE_INFO", f"{relative}: {ctypes.get_last_error()}")
    return info


def _windows_information_identity(info: object) -> tuple[int, ...]:
    return (
        int(info.dwFileAttributes),
        int(info.dwVolumeSerialNumber),
        int(info.nFileIndexHigh),
        int(info.nFileIndexLow),
        int(info.nFileSizeHigh),
        int(info.nFileSizeLow),
        int(info.nNumberOfLinks),
        int(info.ftLastWriteTime.dwHighDateTime),
        int(info.ftLastWriteTime.dwLowDateTime),
    )


def _windows_information_size(info: object) -> int:
    return (int(info.nFileSizeHigh) << 32) | int(info.nFileSizeLow)


def _windows_final_path(handle: object, *, relative: str) -> str:
    buffer = ctypes.create_unicode_buffer(_WIN_FINAL_PATH_BUFFER_CHARS)
    count = _GET_FINAL_PATH_NAME_BY_HANDLE_W(
        handle,
        buffer,
        len(buffer),
        0,
    )
    if not count or count >= len(buffer):
        _fail("SOURCE_FINAL_PATH", f"{relative}: {ctypes.get_last_error()}")
    value = buffer.value
    if value.startswith("\\\\?\\UNC\\"):
        value = "\\\\" + value[len("\\\\?\\UNC\\"):]
    elif value.startswith("\\\\?\\"):
        value = value[len("\\\\?\\"):]
    else:
        _fail("SOURCE_FINAL_PATH_NAMESPACE", relative)
    return os.path.normpath(value)


def _verify_windows_pinned_directory(
    directory: _PinnedWindowsDirectory,
) -> None:
    try:
        path_row = os.lstat(directory.path)
    except OSError as exc:
        _fail("SOURCE_PARENT_IDENTITY_DRIFT", type(exc).__name__)
    info = _windows_file_information(
        directory.handle,
        relative=directory.relative or "<capture-root>",
    )
    observed = os.path.normcase(
        _windows_final_path(
            directory.handle,
            relative=directory.relative or "<capture-root>",
        )
    )
    if (
        _windows_information_identity(info) != directory.identity
        or observed != directory.final_path
        or not _windows_stat_matches_information(
            path_row,
            info,
            require_directory=True,
        )
    ):
        _fail("SOURCE_PARENT_IDENTITY_DRIFT", directory.relative)


def _verify_windows_parent_authority(
    root: _PinnedRoot,
    relative: str,
) -> None:
    parent = "/".join(PurePosixPath(relative).parts[:-1])
    if parent:
        pinned = root.windows_directories.get(parent)
        if pinned is None:
            _fail("SOURCE_PARENT_HANDLE_MISSING", relative)
        _verify_windows_pinned_directory(pinned)
    _verify_pinned_root(root)


def _verify_all_windows_directories(root: _PinnedRoot) -> None:
    for directory in tuple(root.windows_directories.values()):
        _verify_windows_pinned_directory(directory)


def _pin_windows_directory(
    root: _PinnedRoot,
    relative: str,
    *,
    allow_missing: bool,
) -> bool:
    """Retain every lexical directory from the pinned root to ``relative``.

    Windows has no public ``openat`` equivalent for ordinary Python callers.
    Holding each directory without ``FILE_SHARE_DELETE`` prevents a checked
    ancestor from being renamed while later descendants are opened by their
    final lexical path.  File IDs and final paths are revalidated for the full
    capture lifetime.
    """

    if os.name != "nt":
        _fail("SOURCE_PARENT_HANDLE_PLATFORM", relative)
    if not relative:
        _verify_pinned_root(root)
        return True
    relative_n = _canonical_path(relative)
    current_parts: list[str] = []
    for component in PurePosixPath(relative_n).parts:
        current_parts.append(component)
        current = "/".join(current_parts)
        cached = root.windows_directories.get(current)
        if cached is not None:
            _verify_windows_pinned_directory(cached)
            continue
        if len(root.windows_directories) >= _MAX_SOURCE_COUNT:
            _fail("NAMESPACE_DIRECTORY_COUNT_LIMIT", relative_n)
        parent_relative = "/".join(current_parts[:-1])
        if parent_relative:
            parent = root.windows_directories.get(parent_relative)
            if parent is None:
                _fail("SOURCE_PARENT_HANDLE_MISSING", current)
            _verify_windows_pinned_directory(parent)
        _verify_pinned_root(root)
        candidate = root.path.joinpath(*current_parts)
        handle = _CREATE_FILE_W(
            _windows_native_path(candidate),
            _WIN_GENERIC_READ,
            _WIN_SHARE_READ | _WIN_SHARE_WRITE,
            None,
            _WIN_OPEN_EXISTING,
            _WIN_FILE_FLAG_OPEN_REPARSE_POINT
            | _WIN_FILE_FLAG_BACKUP_SEMANTICS,
            None,
        )
        if handle == _WIN_INVALID_HANDLE_VALUE:
            if allow_missing:
                try:
                    os.lstat(candidate)
                except FileNotFoundError:
                    _verify_pinned_root(root)
                    return False
                except OSError as exc:
                    _fail(
                        "SOURCE_PARENT_NOFOLLOW_OPEN",
                        f"{current}: {type(exc).__name__}",
                    )
            _fail(
                "SOURCE_PARENT_NOFOLLOW_OPEN",
                f"{current}: {ctypes.get_last_error()}",
            )
        try:
            info = _windows_file_information(handle, relative=current)
            attributes = int(info.dwFileAttributes)
            if (
                not attributes & _WIN_FILE_ATTRIBUTE_DIRECTORY
                or attributes & _WIN_FILE_ATTRIBUTE_REPARSE_POINT
            ):
                _fail("SOURCE_LINK_UNSAFE", current)
            expected = os.path.normcase(
                os.path.normpath(os.path.abspath(os.fspath(candidate)))
            )
            observed = os.path.normcase(
                _windows_final_path(handle, relative=current)
            )
            if observed != expected:
                _fail("SOURCE_PARENT_FINAL_PATH_ESCAPE", current)
            try:
                path_row = os.lstat(candidate)
            except OSError as exc:
                _fail(
                    "SOURCE_PARENT_IDENTITY_DRIFT",
                    f"{current}: {type(exc).__name__}",
                )
            if not _windows_stat_matches_information(
                path_row,
                info,
                require_directory=True,
            ):
                _fail("SOURCE_PARENT_IDENTITY_DRIFT", current)
            pinned = _PinnedWindowsDirectory(
                relative=current,
                path=candidate,
                handle=handle,
                identity=_windows_information_identity(info),
                final_path=expected,
            )
            # Revalidate the retained direct parent after opening the child.
            # A rename between the pre-open check and CreateFileW is therefore
            # observable through that parent's directory identity.
            if parent_relative:
                _verify_windows_pinned_directory(parent)
            _verify_pinned_root(root)
            root.windows_directories[current] = pinned
            handle = None
        finally:
            if handle not in {None, _WIN_INVALID_HANDLE_VALUE}:
                _CLOSE_HANDLE(handle)
    return True


def _open_posix_rooted_parent(
    root: _PinnedRoot,
    relative: str,
) -> int | None:
    if root.descriptor is None:
        _fail("SOURCE_ROOT_DESCRIPTOR_MISSING", relative)
    nofollow = int(getattr(os, "O_NOFOLLOW", 0) or 0)
    directory_flag = int(getattr(os, "O_DIRECTORY", 0) or 0)
    supports_dir_fd = os.open in getattr(os, "supports_dir_fd", set())
    if not nofollow or not directory_flag or not supports_dir_fd:
        _fail("SOURCE_NOFOLLOW_UNAVAILABLE", relative)
    flags = (
        os.O_RDONLY
        | nofollow
        | directory_flag
        | int(getattr(os, "O_CLOEXEC", 0) or 0)
    )
    descriptor = os.dup(root.descriptor)
    try:
        for component in PurePosixPath(relative).parts[:-1]:
            child = _open_posix_child_directory(
                descriptor,
                component,
                flags,
                error_code="SOURCE_LINK_UNSAFE",
                detail=relative,
                allow_missing=True,
            )
            if child is None:
                os.close(descriptor)
                descriptor = -1
                return None
            os.close(descriptor)
            descriptor = child
        result = descriptor
        descriptor = -1
        return result
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _rooted_source_present(root: _PinnedRoot, relative: str) -> bool:
    """Probe one leaf against retained/descriptor-relative parent authority."""

    parts = PurePosixPath(relative).parts
    parent_relative = "/".join(parts[:-1])
    if os.name == "nt":
        if parent_relative and not _pin_windows_directory(
            root,
            parent_relative,
            allow_missing=True,
        ):
            return False
        _verify_windows_parent_authority(root, relative)
        path = root.path.joinpath(*parts)
        try:
            row = os.lstat(path)
        except FileNotFoundError:
            _verify_windows_parent_authority(root, relative)
            return False
        except OSError as exc:
            _fail("SOURCE_STAT", f"{relative}: {type(exc).__name__}")
        _validate_source_metadata(row, relative=relative)
        _verify_windows_parent_authority(root, relative)
        return True

    parent = _open_posix_rooted_parent(root, relative)
    if parent is None:
        return False
    try:
        try:
            row = os.stat(
                parts[-1],
                dir_fd=parent,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            return False
        except OSError as exc:
            _fail("SOURCE_STAT", f"{relative}: {type(exc).__name__}")
        _validate_source_metadata(row, relative=relative)
        return True
    finally:
        os.close(parent)


def _register_rooted_absence(root: _PinnedRoot, relative: str) -> None:
    if _rooted_source_present(root, relative):
        _fail("SOURCE_OPTIONAL_PATH_UNSAFE", relative)
    root.absent_paths.add(relative)


def _verify_registered_absences(root: _PinnedRoot) -> None:
    for relative in sorted(root.absent_paths):
        if _rooted_source_present(root, relative):
            _fail("SOURCE_ABSENCE_DRIFT", relative)


def _verify_pinned_capture(root: _PinnedRoot) -> None:
    _verify_pinned_root(root)
    if os.name == "nt":
        _verify_all_windows_directories(root)
    _verify_registered_absences(root)
    if root.retained_namespace_members:
        _verify_retained_terminal_namespaces(root)
    if root.retained_files:
        _verify_retained_terminal_files(root)
    # A retained-file verification callback cannot make a previously bound
    # absence or namespace gain invisible at the terminal linearization point.
    _verify_registered_absences(root)
    if root.retained_namespace_members:
        _verify_retained_terminal_namespaces(root)
    if os.name == "nt":
        _verify_all_windows_directories(root)
    _verify_pinned_root(root)
    # For the terminal-pair context this return is the linearization point.
    # The context manager performs cleanup-only handle closes afterward.


def _windows_read_once(
    handle: object,
    *,
    relative: str,
    maximum_bytes: int | None = None,
) -> bytes:
    limit = _MAX_FILE_BYTES if maximum_bytes is None else maximum_bytes
    chunks: list[bytes] = []
    remaining = limit + 1
    while remaining:
        requested = min(_READ_CHUNK_BYTES, remaining)
        buffer = ctypes.create_string_buffer(requested)
        observed = wintypes.DWORD(0)
        if not _READ_FILE(
            handle,
            buffer,
            requested,
            ctypes.byref(observed),
            None,
        ):
            _fail("SOURCE_READ", f"{relative}: {ctypes.get_last_error()}")
        count = int(observed.value)
        if not count:
            break
        chunks.append(buffer.raw[:count])
        remaining -= count
    raw = b"".join(chunks)
    if len(raw) > limit:
        _fail("SOURCE_SIZE_LIMIT", relative)
    return raw


def _read_windows_rooted_source(
    root: _PinnedRoot,
    relative: str,
    path: Path,
    before: os.stat_result,
    *,
    maximum_bytes: int | None = None,
) -> bytes:
    limit = _MAX_FILE_BYTES if maximum_bytes is None else maximum_bytes
    _verify_windows_parent_authority(root, relative)
    handle = _CREATE_FILE_W(
        _windows_native_path(path),
        _WIN_GENERIC_READ,
        _WIN_SHARE_READ,
        None,
        _WIN_OPEN_EXISTING,
        _WIN_FILE_FLAG_OPEN_REPARSE_POINT,
        None,
    )
    if handle == _WIN_INVALID_HANDLE_VALUE:
        _fail("SOURCE_NOFOLLOW_OPEN", f"{relative}: {ctypes.get_last_error()}")
    try:
        before_handle = _windows_file_information(
            handle,
            relative=relative,
        )
        attributes = int(before_handle.dwFileAttributes)
        if attributes & (
            _WIN_FILE_ATTRIBUTE_DIRECTORY
            | _WIN_FILE_ATTRIBUTE_REPARSE_POINT
        ):
            _fail("SOURCE_NOT_NOFOLLOW_REGULAR", relative)
        if int(before_handle.nNumberOfLinks) != 1:
            _fail("SOURCE_MULTILINK_UNSAFE", relative)
        size = _windows_information_size(before_handle)
        if size > limit:
            _fail("SOURCE_SIZE_LIMIT", relative)
        expected_path = os.path.normcase(
            os.path.normpath(os.path.abspath(os.fspath(path)))
        )
        observed_path = os.path.normcase(
            _windows_final_path(handle, relative=relative)
        )
        if observed_path != expected_path:
            _fail("SOURCE_FINAL_PATH_ESCAPE", relative)
        if not _windows_stat_matches_information(
            before,
            before_handle,
            require_directory=False,
        ):
            _fail("SOURCE_OPEN_IDENTITY_DRIFT", relative)
        first = _windows_read_once(
            handle, relative=relative, maximum_bytes=maximum_bytes
        )
        if not _SET_FILE_POINTER_EX(
            handle,
            0,
            None,
            _WIN_FILE_BEGIN,
        ):
            _fail("SOURCE_SEEK", f"{relative}: {ctypes.get_last_error()}")
        second = _windows_read_once(
            handle, relative=relative, maximum_bytes=maximum_bytes
        )
        after_handle = _windows_file_information(
            handle,
            relative=relative,
        )
        _verify_windows_parent_authority(root, relative)
        _assert_safe_ancestors(root.path, relative)
        try:
            after_path = os.lstat(path)
        except OSError as exc:
            _fail("SOURCE_POST_STAT", f"{relative}: {type(exc).__name__}")
        _validate_source_metadata(
            after_path, relative=relative, maximum_bytes=maximum_bytes
        )
        if (
            first != second
            or _windows_information_identity(before_handle)
            != _windows_information_identity(after_handle)
            or not _windows_stat_matches_information(
                after_path,
                after_handle,
                require_directory=False,
            )
            or _source_metadata_identity(before)
            != _source_metadata_identity(after_path)
            or len(first) != size
        ):
            _fail("SOURCE_READ_IDENTITY_DRIFT", relative)
        return first
    finally:
        _CLOSE_HANDLE(handle)


def _read_rooted_source_bytes(
    root: _PinnedRoot,
    relative: str,
    path: Path,
    *,
    maximum_bytes: int | None = None,
) -> bytes:
    try:
        before = os.lstat(path)
    except OSError as exc:
        _fail("SOURCE_STAT", f"{relative}: {type(exc).__name__}")
    _validate_source_metadata(
        before, relative=relative, maximum_bytes=maximum_bytes
    )
    if os.name == "nt":
        return _read_windows_rooted_source(
            root,
            relative,
            path,
            before,
            maximum_bytes=maximum_bytes,
        )
    return _read_posix_rooted_source(
        root,
        relative,
        path,
        before,
        maximum_bytes=maximum_bytes,
    )


def _glob_pattern_regex(pattern: str) -> re.Pattern[str]:
    fragments = ["^"]
    index = 0
    while index < len(pattern):
        if pattern.startswith("**/", index):
            fragments.append("(?:[^/]+/)*")
            index += 3
        elif pattern.startswith("**", index):
            fragments.append(".*")
            index += 2
        elif pattern[index] == "*":
            fragments.append("[^/]*")
            index += 1
        else:
            fragments.append(re.escape(pattern[index]))
            index += 1
    fragments.append("$")
    return re.compile("".join(fragments), re.ASCII)


def _retain_posix_namespace_directory(
    root: _PinnedRoot,
    relative: str,
    descriptor: int,
) -> None:
    if not root.retained_namespace_members:
        return
    physical = _directory_metadata_identity(os.fstat(descriptor))
    path = (
        root.path
        if not relative
        else root.path.joinpath(*PurePosixPath(relative).parts)
    )
    try:
        live = _directory_metadata_identity(os.lstat(path))
    except OSError as exc:
        _fail(
            "TERMINAL_NAMESPACE_DIRECTORY_STAT",
            f"{relative or '<root>'}: {type(exc).__name__}",
        )
    if live != physical:
        _fail("TERMINAL_NAMESPACE_DIRECTORY_DRIFT", relative or "<root>")
    prior = root.retained_posix_directories.get(relative)
    if prior is not None:
        if prior.physical_identity != physical:
            _fail("TERMINAL_NAMESPACE_DIRECTORY_DRIFT", relative or "<root>")
        return
    root.retained_posix_directories[relative] = _RetainedPosixDirectory(
        relative=relative,
        descriptor=os.dup(descriptor),
        physical_identity=physical,
    )


def _open_posix_namespace_directory(
    root: _PinnedRoot,
    relative: str,
) -> int:
    if root.descriptor is None:
        _fail("TERMINAL_NAMESPACE_ROOT_DESCRIPTOR")
    descriptor = os.dup(root.descriptor)
    if not relative:
        return descriptor
    flags = (
        os.O_RDONLY
        | int(getattr(os, "O_NOFOLLOW", 0) or 0)
        | int(getattr(os, "O_DIRECTORY", 0) or 0)
        | int(getattr(os, "O_CLOEXEC", 0) or 0)
    )
    try:
        for component in PurePosixPath(relative).parts:
            child = _open_posix_child_directory(
                descriptor,
                component,
                flags,
                error_code="TERMINAL_NAMESPACE_DIRECTORY_OPEN",
                detail=relative,
            )
            if child is None:  # pragma: no cover - allow_missing is false
                _fail("TERMINAL_NAMESPACE_DIRECTORY_OPEN", relative)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except Exception:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise


def _verify_retained_posix_namespace_directories(root: _PinnedRoot) -> None:
    for relative in sorted(root.retained_posix_directories):
        retained = root.retained_posix_directories[relative]
        physical = _directory_metadata_identity(os.fstat(retained.descriptor))
        path = (
            root.path
            if not relative
            else root.path.joinpath(*PurePosixPath(relative).parts)
        )
        try:
            live = _directory_metadata_identity(os.lstat(path))
        except OSError as exc:
            _fail(
                "TERMINAL_NAMESPACE_DIRECTORY_STAT",
                f"{relative or '<root>'}: {type(exc).__name__}",
            )
        current = _open_posix_namespace_directory(root, relative)
        try:
            current_identity = _directory_metadata_identity(os.fstat(current))
        finally:
            os.close(current)
        if not (
            physical
            == live
            == current_identity
            == retained.physical_identity
        ):
            _fail("TERMINAL_NAMESPACE_DIRECTORY_DRIFT", relative or "<root>")


def _posix_namespace_members(
    root: _PinnedRoot,
    pattern: str,
) -> tuple[str, ...]:
    if root.descriptor is None:
        _fail("NAMESPACE_ROOT_DESCRIPTOR_MISSING", pattern)
    nofollow = int(getattr(os, "O_NOFOLLOW", 0) or 0)
    directory_flag = int(getattr(os, "O_DIRECTORY", 0) or 0)
    directory_flags = (
        os.O_RDONLY
        | nofollow
        | directory_flag
        | int(getattr(os, "O_CLOEXEC", 0) or 0)
    )
    parts = pattern.split("/")
    fixed_prefix: list[str] = []
    for part in parts:
        if "*" in part:
            break
        fixed_prefix.append(part)
    remaining = parts[len(fixed_prefix):]
    unlimited_depth = any("**" in part for part in remaining)
    maximum_directory_depth = (
        _MAX_PATH_CHARS if unlimited_depth else max(0, len(remaining) - 1)
    )
    matcher = _glob_pattern_regex(pattern)
    members: list[str] = []
    descriptor = os.dup(root.descriptor)
    try:
        _retain_posix_namespace_directory(root, "", descriptor)
        retained_prefix: list[str] = []
        for component in fixed_prefix:
            child = _open_posix_child_directory(
                descriptor,
                component,
                directory_flags,
                error_code="NAMESPACE_ENUMERATION",
                detail=pattern,
                allow_missing=True,
            )
            if child is None:
                return ()
            os.close(descriptor)
            descriptor = child
            retained_prefix.append(component)
            _retain_posix_namespace_directory(
                root, "/".join(retained_prefix), descriptor
            )

        prefix = "/".join(fixed_prefix)

        def walk(directory: int, relative_directory: str, depth: int) -> None:
            try:
                entries = sorted(os.scandir(directory), key=lambda row: row.name)
            except OSError as exc:
                _fail("NAMESPACE_ENUMERATION", f"{pattern}: {type(exc).__name__}")
            for entry in entries:
                relative = (
                    f"{relative_directory}/{entry.name}"
                    if relative_directory
                    else entry.name
                )
                relative = _canonical_path(relative)
                try:
                    row = entry.stat(follow_symlinks=False)
                except OSError as exc:
                    _fail(
                        "NAMESPACE_ENUMERATION",
                        f"{pattern}: {type(exc).__name__}",
                    )
                if stat.S_ISLNK(row.st_mode) or bool(
                    int(getattr(row, "st_file_attributes", 0))
                    & _WIN_FILE_ATTRIBUTE_REPARSE_POINT
                ):
                    if matcher.fullmatch(relative):
                        _fail("SOURCE_LINK_UNSAFE", relative)
                    continue
                if stat.S_ISREG(row.st_mode):
                    if matcher.fullmatch(relative):
                        _validate_source_metadata(row, relative=relative)
                        members.append(relative)
                        if len(members) > _MAX_SOURCE_COUNT:
                            _fail("NAMESPACE_MEMBER_COUNT_LIMIT", pattern)
                    continue
                if stat.S_ISDIR(row.st_mode) and depth < maximum_directory_depth:
                    child = -1
                    try:
                        opened = _open_posix_child_directory(
                            directory,
                            entry.name,
                            directory_flags,
                            error_code="NAMESPACE_ENUMERATION",
                            detail=relative,
                        )
                        if opened is None:  # pragma: no cover
                            _fail("NAMESPACE_ENUMERATION", relative)
                        child = opened
                        _retain_posix_namespace_directory(
                            root, relative, child
                        )
                        walk(child, relative, depth + 1)
                    except ReportAssemblyCaptureError:
                        raise
                    except OSError as exc:
                        _fail(
                            "NAMESPACE_ENUMERATION",
                            f"{pattern}: {type(exc).__name__}",
                        )
                    finally:
                        if child >= 0:
                            os.close(child)

        walk(descriptor, prefix, 0)
    except FileNotFoundError:
        return ()
    except ReportAssemblyCaptureError:
        raise
    except OSError as exc:
        _fail("NAMESPACE_ENUMERATION", f"{pattern}: {type(exc).__name__}")
    finally:
        os.close(descriptor)
    return tuple(members)


def _windows_namespace_members(
    root: _PinnedRoot,
    pattern: str,
) -> tuple[str, ...]:
    """Enumerate below retained no-delete directory handles on Windows."""

    parts = pattern.split("/")
    fixed_prefix: list[str] = []
    for part in parts:
        if "*" in part:
            break
        fixed_prefix.append(part)
    remaining = parts[len(fixed_prefix):]
    unlimited_depth = any("**" in part for part in remaining)
    maximum_directory_depth = (
        _MAX_PATH_CHARS if unlimited_depth else max(0, len(remaining) - 1)
    )
    matcher = _glob_pattern_regex(pattern)
    prefix = "/".join(fixed_prefix)
    if prefix and not _pin_windows_directory(
        root,
        prefix,
        allow_missing=True,
    ):
        return ()

    members: list[str] = []

    def directory_handle(relative: str) -> object:
        if not relative:
            if root.handle is None:
                _fail("NAMESPACE_ROOT_HANDLE_MISSING", pattern)
            return root.handle
        pinned = root.windows_directories.get(relative)
        if pinned is None:
            _fail("NAMESPACE_PARENT_HANDLE_MISSING", relative)
        _verify_windows_pinned_directory(pinned)
        return pinned.handle

    def walk(relative_directory: str, depth: int) -> None:
        handle = directory_handle(relative_directory)
        final_directory = _windows_final_path(
            handle,
            relative=relative_directory or "<capture-root>",
        )
        try:
            with os.scandir(_windows_native_path(Path(final_directory))) as scan:
                entries = sorted(list(scan), key=lambda row: row.name)
        except OSError as exc:
            _fail("NAMESPACE_ENUMERATION", f"{pattern}: {type(exc).__name__}")
        for entry in entries:
            relative = (
                f"{relative_directory}/{entry.name}"
                if relative_directory
                else entry.name
            )
            relative = _canonical_path(relative)
            try:
                # ``DirEntry.stat`` obtained from an extended-path scandir can
                # report zeroed inode/link fields on Windows.  The retained
                # no-delete parent handle makes this lexical lstat stable
                # against ancestor replacement, and subsequent child/file
                # handle validation binds the object identity itself.
                row = os.lstat(root.path.joinpath(*PurePosixPath(relative).parts))
            except OSError as exc:
                _fail(
                    "NAMESPACE_ENUMERATION",
                    f"{pattern}: {type(exc).__name__}",
                )
            if stat.S_ISLNK(row.st_mode) or bool(
                int(getattr(row, "st_file_attributes", 0))
                & _WIN_FILE_ATTRIBUTE_REPARSE_POINT
            ):
                if matcher.fullmatch(relative):
                    _fail("SOURCE_LINK_UNSAFE", relative)
                continue
            if stat.S_ISREG(row.st_mode):
                if matcher.fullmatch(relative):
                    _validate_source_metadata(row, relative=relative)
                    members.append(relative)
                    if len(members) > _MAX_SOURCE_COUNT:
                        _fail("NAMESPACE_MEMBER_COUNT_LIMIT", pattern)
                continue
            if stat.S_ISDIR(row.st_mode) and depth < maximum_directory_depth:
                _pin_windows_directory(
                    root,
                    relative,
                    allow_missing=False,
                )
                walk(relative, depth + 1)
        if relative_directory:
            pinned = root.windows_directories.get(relative_directory)
            if pinned is None:  # pragma: no cover - internal invariant
                _fail("NAMESPACE_PARENT_HANDLE_MISSING", relative_directory)
            _verify_windows_pinned_directory(pinned)
        _verify_pinned_root(root)

    walk(prefix, 0)
    return tuple(members)


def _namespace_members(root: _PinnedRoot, pattern: str) -> tuple[str, ...]:
    _verify_pinned_root(root)
    if os.name != "nt":
        members = list(_posix_namespace_members(root, pattern))
    else:
        members = list(_windows_namespace_members(root, pattern))
    _verify_pinned_root(root)
    members.sort()
    if len(members) > _MAX_SOURCE_COUNT:
        _fail("NAMESPACE_MEMBER_COUNT_LIMIT", pattern)
    if len(members) != len(set(members)) or len(members) != len(
        {_filesystem_key(member) for member in members}
    ):
        _fail("NAMESPACE_MEMBER_ALIAS", pattern)
    return tuple(members)


def _source_row(
    root: _PinnedRoot,
    relative: str,
    roles: set[str],
    *,
    present: bool,
) -> dict[str, Any]:
    canonical_roles = sorted({_canonical_role(role) for role in roles})
    if not canonical_roles:
        _fail("SOURCE_ROLE_EMPTY", relative)
    if not present:
        return {
            "path": relative,
            "roles": canonical_roles,
            "presence": ABSENT,
            "size": 0,
            "sha256": "",
            "content_base64": "",
        }
    _verify_pinned_root(root)
    path = root.path.joinpath(*PurePosixPath(relative).parts)
    raw = _read_rooted_source_bytes(root, relative, path)
    return {
        "path": relative,
        "roles": canonical_roles,
        "presence": PRESENT,
        "size": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "content_base64": base64.b64encode(raw).decode("ascii"),
    }


def _membership_digest(
    pattern: str,
    role: str,
    members: list[str],
    source_by_path: Mapping[str, Mapping[str, Any]],
) -> str:
    return _digest(
        {
            "pattern": pattern,
            "role": role,
            "members": [
                {
                    "path": path,
                    "sha256": source_by_path[path]["sha256"],
                    "size": source_by_path[path]["size"],
                }
                for path in members
            ],
        }
    )


def _source_set_digest(rows: list[Mapping[str, Any]]) -> str:
    return _digest(
        [
            {
                "path": row["path"],
                "roles": row["roles"],
                "presence": row["presence"],
                "size": row["size"],
                "sha256": row["sha256"],
            }
            for row in rows
        ]
    )


def _canonical_identity(value: object) -> tuple[str, str]:
    if not isinstance(value, str) or ":" not in value:
        _fail("OUTPUT_IDENTITY", repr(value))
    root, path = value.split(":", 1)
    if root not in {"project", "scratchpad"}:
        _fail("OUTPUT_ROOT", root)
    return root, _canonical_path(path)


def _canonical_artifact_identity(value: object, *, field: str) -> str:
    root, path = _canonical_identity(value)
    return f"{root}:{path}"


def _normalized_predecessor_binding(
    value: object,
) -> dict[str, str]:
    if not isinstance(value, Mapping) or set(value) != _PREDECESSOR_KEYS:
        _fail("PREDECESSOR_BINDING_SCHEMA")
    identity = _canonical_artifact_identity(
        value.get("artifact_identity"), field="artifact_identity"
    )
    if identity != SOURCE_CAPTURE_IDENTITY:
        _fail("PREDECESSOR_BINDING_IDENTITY", identity)
    run_id = value.get("run_id")
    try:
        parsed_run_id = UUID(str(run_id))
    except (ValueError, AttributeError):
        _fail("PREDECESSOR_BINDING_RUN", repr(run_id))
    if parsed_run_id.version != 4 or str(parsed_run_id) != run_id:
        _fail("PREDECESSOR_BINDING_RUN", repr(run_id))
    work_unit = value.get("producer_work_unit_key")
    if not isinstance(work_unit, str) or work_unit != work_unit.strip():
        _fail("PREDECESSOR_BINDING_PRODUCER", repr(work_unit))
    dimensions = work_unit.split("/")
    if len(dimensions) != 6 or any(
        not _DIMENSION_RE.fullmatch(part) for part in dimensions
    ):
        _fail("PREDECESSOR_BINDING_PRODUCER", work_unit)
    digests: dict[str, str] = {}
    for field in (
        "content_sha256",
        "contract_digest",
        "launch_digest",
        "commit_receipt_digest",
    ):
        digest = value.get(field)
        if not isinstance(digest, str) or not _HEX64_RE.fullmatch(digest):
            _fail("PREDECESSOR_BINDING_DIGEST", field)
        digests[field] = digest
    return {
        "artifact_identity": identity,
        "content_sha256": digests["content_sha256"],
        "run_id": run_id,
        "producer_work_unit_key": work_unit,
        "contract_digest": digests["contract_digest"],
        "launch_digest": digests["launch_digest"],
        "commit_receipt_digest": digests["commit_receipt_digest"],
    }


def _expected_final_identity(value: object) -> str:
    identity = _canonical_artifact_identity(value, field="final capture")
    if identity != FINAL_CAPTURE_IDENTITY:
        _fail("FINAL_CAPTURE_IDENTITY", identity)
    return identity


def _output_row(
    identity: str,
    role_and_bytes: tuple[str, bytes] | None,
) -> dict[str, Any]:
    root, path = _canonical_identity(identity)
    canonical_identity = f"{root}:{path}"
    expected_role = ALLOWED_DERIVED_OUTPUT_ROLES.get(canonical_identity)
    if expected_role is None:
        _fail("OUTPUT_AUTHORITY", canonical_identity)
    if role_and_bytes is None:
        return {
            "root": root,
            "path": path,
            "role": expected_role,
            "presence": ABSENT,
            "size": 0,
            "sha256": "",
            "content_base64": "",
        }
    if (
        not isinstance(role_and_bytes, tuple)
        or len(role_and_bytes) != 2
        or not isinstance(role_and_bytes[1], bytes)
    ):
        _fail("OUTPUT_VALUE", identity)
    role = _canonical_role(role_and_bytes[0])
    if expected_role != role:
        _fail("OUTPUT_AUTHORITY", canonical_identity)
    raw = role_and_bytes[1]
    if len(raw) > _MAX_FILE_BYTES:
        _fail("OUTPUT_SIZE_LIMIT", identity)
    return {
        "root": root,
        "path": path,
        "role": role,
        "presence": PRESENT,
        "size": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "content_base64": base64.b64encode(raw).decode("ascii"),
    }


def _bounded_location_text(value: object, field: str) -> str:
    if not isinstance(value, str) or value != value.strip():
        _fail("LOCATION_VALUE", field)
    if len(value) > 4_096 or _CONTROL_RE.search(value):
        _fail("LOCATION_VALUE", field)
    if unicodedata.normalize("NFC", value) != value:
        _fail("LOCATION_NON_NFC", field)
    return value


def _location_row(
    value: object,
    *,
    expected_source_snapshot_sha256: str,
) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != _LOCATION_KEYS:
        _fail("LOCATION_SCHEMA")
    report_id = value.get("report_id")
    if not isinstance(report_id, str) or not _REPORT_ID_RE.fullmatch(report_id):
        _fail("LOCATION_REPORT_ID", repr(report_id))
    decision = value.get("decision")
    if decision not in _LOCATION_DECISIONS:
        _fail("LOCATION_DECISION", str(decision))
    original = _bounded_location_text(value.get("original_location"), "original_location")
    resolved = _bounded_location_text(value.get("resolved_location"), "resolved_location")
    snapshot = value.get("source_snapshot_sha256")
    if snapshot != expected_source_snapshot_sha256:
        _fail("LOCATION_SOURCE_SNAPSHOT", report_id)
    raw_paths = value.get("source_paths")
    if (
        not isinstance(raw_paths, list)
        or len(raw_paths) > _MAX_LOCATION_SOURCE_PATHS
    ):
        _fail("LOCATION_SOURCE_PATHS", report_id)
    source_paths = [_canonical_path(path) for path in raw_paths]
    if (
        source_paths != sorted(set(source_paths))
        or len(source_paths)
        != len({_filesystem_key(path) for path in source_paths})
    ):
        _fail("LOCATION_SOURCE_PATHS", report_id)
    if decision == "RECOVERED_FROM_INDEX" and (not resolved or not source_paths):
        _fail("LOCATION_RECOVERY_INCOMPLETE", report_id)
    if decision == "UNCHANGED" and original != resolved:
        _fail("LOCATION_UNCHANGED_MISMATCH", report_id)
    if decision in {"UNRESOLVED", "NOT_APPLICABLE"} and source_paths:
        _fail("LOCATION_UNRESOLVED_HAS_SOURCES", report_id)
    return {
        "decision": decision,
        "original_location": original,
        "report_id": report_id,
        "resolved_location": resolved,
        "source_paths": source_paths,
        "source_snapshot_sha256": snapshot,
    }


def _location_original_key(value: str) -> str:
    match = _LOCATION_PATH_RE.fullmatch(value)
    if match is not None:
        path = _canonical_path(match.group("path"))
        return (
            f"path:{_filesystem_key(path)}"
            f"{match.group('suffix').casefold()}"
        )
    if "/" in value or "\\" in value:
        return f"path:{_filesystem_key(_canonical_path(value))}"
    return f"text:{value.casefold()}"


def _assert_unique_location_keys(
    rows: list[Mapping[str, Any]],
) -> None:
    keys = [
        (
            str(row["report_id"]),
            _location_original_key(str(row["original_location"])),
        )
        for row in rows
    ]
    if len(keys) != len(set(keys)):
        _fail("LOCATION_DUPLICATE_ALIAS")


def _register_clean_scratch_output_namespace(root: _PinnedRoot) -> None:
    """Pin absence of every report output that will later be pure-published."""

    for identity in sorted(ALLOWED_DERIVED_OUTPUT_ROLES):
        output_root, output_path = _canonical_identity(identity)
        if output_root != "scratchpad":
            continue
        if _rooted_source_present(root, output_path):
            _fail("OUTPUT_PREEXISTING", identity)
        _register_rooted_absence(root, output_path)


def _capture_report_assembly_source(
    scratchpad: str | Path,
    *,
    metadata: Mapping[str, str],
    fixed_source_roles: Mapping[str, str] | None = None,
    namespace_roles: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Capture exact source bytes and namespace membership only."""

    with _pinned_root(Path(scratchpad)) as root:
        return _build_report_assembly_source_capture(
            root,
            metadata=metadata,
            fixed_source_roles=fixed_source_roles,
            namespace_roles=namespace_roles,
        )


def _build_report_assembly_source_capture(
    root: _PinnedRoot,
    *,
    metadata: Mapping[str, str],
    fixed_source_roles: Mapping[str, str] | None,
    namespace_roles: Mapping[str, str] | None,
) -> dict[str, Any]:
    """Build while retaining one pinned lexical-root authority."""

    _verify_pinned_root(root)
    metadata_n = _normalized_metadata(metadata)
    fixed_specs = _normalized_fixed_specs(
        DEFAULT_FIXED_SOURCE_ROLES
        if fixed_source_roles is None
        else fixed_source_roles
    )
    namespace_specs = _normalized_namespace_specs(
        DEFAULT_NAMESPACE_ROLES if namespace_roles is None else namespace_roles
    )

    roles_by_path: dict[str, set[str]] = {
        row["path"]: {row["role"]} for row in fixed_specs
    }
    members_by_pattern: dict[str, list[str]] = {}
    for spec in namespace_specs:
        members = list(_namespace_members(root, spec["pattern"]))
        members_by_pattern[spec["pattern"]] = members
        for relative in members:
            roles_by_path.setdefault(relative, set()).add(spec["role"])
    if len(roles_by_path) > _MAX_SOURCE_COUNT:
        _fail("SOURCE_COUNT_LIMIT", str(len(roles_by_path)))
    source_keys: dict[str, str] = {}
    for relative in roles_by_path:
        key = _filesystem_key(relative)
        prior = source_keys.setdefault(key, relative)
        if prior != relative:
            _fail("SOURCE_PATH_ALIAS", f"{prior}; {relative}")

    fixed_paths = {row["path"] for row in fixed_specs}
    namespace_paths = {
        path for members in members_by_pattern.values() for path in members
    }
    sources: list[dict[str, Any]] = []
    total_bytes = 0
    for relative in sorted(roles_by_path):
        _verify_pinned_root(root)
        present = _rooted_source_present(
            root,
            relative,
        )
        if relative in namespace_paths and not present:
            _fail("SOURCE_NAMESPACE_MEMBER_MISSING", relative)
        if present:
            row = _source_row(root, relative, roles_by_path[relative], present=True)
        elif relative in fixed_paths:
            _register_rooted_absence(root, relative)
            row = _source_row(root, relative, roles_by_path[relative], present=False)
        else:  # pragma: no cover - namespace enumerator yields present files only
            _fail("SOURCE_NAMESPACE_MEMBER_MISSING", relative)
        total_bytes += int(row["size"])
        if total_bytes > _MAX_TOTAL_BYTES:
            _fail("SOURCE_TOTAL_SIZE_LIMIT", str(total_bytes))
        sources.append(row)
    source_by_path = {row["path"]: row for row in sources}
    for spec in fixed_specs:
        source = source_by_path.get(spec["path"])
        if source is None or spec["role"] not in source["roles"]:
            _fail("FIXED_SOURCE_LINK", spec["path"])

    namespaces: list[dict[str, Any]] = []
    for spec in namespace_specs:
        members = members_by_pattern[spec["pattern"]]
        namespaces.append(
            {
                "pattern": spec["pattern"],
                "role": spec["role"],
                "members": members,
                "member_count": len(members),
                "membership_digest": _membership_digest(
                    spec["pattern"], spec["role"], members, source_by_path
                ),
            }
        )

    input_paths = sorted(
        row["path"] for row in sources if row["presence"] == PRESENT
    )
    explicit_absences = sorted(
        row["path"]
        for row in sources
        if row["presence"] == ABSENT and row["path"] in fixed_paths
    )
    payload: dict[str, Any] = {
        "schema_version": SOURCE_SCHEMA_VERSION,
        "metadata": metadata_n,
        "fixed_sources": fixed_specs,
        "namespace_specs": namespace_specs,
        "sources": sources,
        "namespaces": namespaces,
        "input_paths": input_paths,
        "explicit_absences": explicit_absences,
        "source_set_digest": _source_set_digest(sources),
        "capture_digest": "",
    }
    payload["capture_digest"] = _digest(payload)
    _canonical_json_bytes(payload)
    normalized = _validate_report_assembly_source_capture(payload)
    _verify_pinned_root(root)
    for spec in namespace_specs:
        if list(_namespace_members(root, spec["pattern"])) != members_by_pattern[
            spec["pattern"]
        ]:
            _fail("NAMESPACE_DRIFT", spec["pattern"])
    _verify_pinned_capture(root)
    return normalized


def _build_report_assembly_final_capture(
    scratchpad: str | Path,
    *,
    source_capture: object,
    expected_final_artifact_identity: str,
    predecessor_binding: Mapping[str, str],
    derived_outputs: Mapping[str, tuple[str, bytes]],
    location_decisions: tuple[Mapping[str, Any], ...] = (),
) -> dict[str, Any]:
    """Build the externally-bound successor over one committed source capture."""

    _expected_final_identity(expected_final_artifact_identity)
    source = _validate_report_assembly_source_capture(source_capture)
    predecessor = _normalized_predecessor_binding(predecessor_binding)
    if predecessor["run_id"] != source["metadata"]["run_id"]:
        _fail("PREDECESSOR_BINDING_RUN")
    expected_producer = "/".join(
        (
            source["metadata"]["pipeline"],
            source["metadata"]["mode"],
            source["metadata"]["ecosystem"],
            source["metadata"]["backend"],
            "report_assemble",
            "source_capture",
        )
    )
    if predecessor["producer_work_unit_key"] != expected_producer:
        _fail("PREDECESSOR_BINDING_PRODUCER")
    source_content_digest = hashlib.sha256(
        _canonical_report_assembly_source_capture_bytes(source)
    ).hexdigest()
    if predecessor["content_sha256"] != source_content_digest:
        _fail("PREDECESSOR_CONTENT")
    if not isinstance(derived_outputs, Mapping):
        _fail("OUTPUT_SCHEMA")
    canonical_mapping: dict[str, tuple[str, bytes]] = {}
    for identity, role_and_bytes in derived_outputs.items():
        root_name, output_path = _canonical_identity(identity)
        canonical_identity = f"{root_name}:{output_path}"
        if canonical_identity in canonical_mapping:
            _fail("OUTPUT_DUPLICATE", canonical_identity)
        canonical_mapping[canonical_identity] = role_and_bytes
    unknown = set(canonical_mapping) - set(ALLOWED_DERIVED_OUTPUT_ROLES)
    if unknown:
        _fail("OUTPUT_AUTHORITY", sorted(unknown)[0])
    missing_mandatory = MANDATORY_DERIVED_OUTPUTS - set(canonical_mapping)
    if missing_mandatory:
        _fail("OUTPUT_MANDATORY_ABSENT", sorted(missing_mandatory)[0])
    output_rows = sorted(
        (
            _output_row(identity, canonical_mapping.get(identity))
            for identity in ALLOWED_DERIVED_OUTPUT_ROLES
        ),
        key=lambda row: (row["root"], row["path"]),
    )
    source_keys = {
        _filesystem_key(row["path"]): row["path"]
        for row in source["sources"]
    }
    overlaps = {
        _filesystem_key(row["path"])
        for row in output_rows
        if row["root"] == "scratchpad"
    } & set(source_keys)
    if overlaps:
        _fail(
            "OUTPUT_SOURCE_OVERLAP",
            ", ".join(sorted(source_keys[key] for key in overlaps)),
        )
    if sum(row["size"] for row in output_rows) > _MAX_TOTAL_BYTES:
        _fail("CAPTURE_TOTAL_SIZE_LIMIT")
    if (
        not isinstance(location_decisions, (tuple, list))
        or len(location_decisions) > _MAX_LOCATION_COUNT
    ):
        _fail("LOCATION_SCHEMA")
    location_rows = sorted(
        (
            _location_row(
                row,
                expected_source_snapshot_sha256=source["metadata"][
                    "source_snapshot_sha256"
                ],
            )
            for row in location_decisions
        ),
        key=lambda row: (row["report_id"], row["original_location"]),
    )
    _assert_unique_location_keys(location_rows)
    with _pinned_root(Path(scratchpad)) as root:
        _register_clean_scratch_output_namespace(root)
        _verify_pinned_capture(root)
    payload: dict[str, Any] = {
        "schema_version": FINAL_SCHEMA_VERSION,
        "metadata": source["metadata"],
        "predecessor_binding": predecessor,
        "derived_outputs": output_rows,
        "location_decisions": location_rows,
        "capture_digest": "",
    }
    payload["capture_digest"] = _digest(payload)
    return _validate_report_assembly_final_capture(
        payload,
        expected_final_artifact_identity=expected_final_artifact_identity,
        expected_predecessor_binding=predecessor_binding,
    )


def _preflight_source_encodings(rows: list[object]) -> tuple[int, int]:
    declared_total = 0
    encoded_total = 0
    for value in rows:
        if not isinstance(value, Mapping) or set(value) != _SOURCE_KEYS:
            _fail("SOURCE_SCHEMA")
        presence = value.get("presence")
        size = value.get("size")
        content = value.get("content_base64")
        if (
            presence not in {PRESENT, ABSENT}
            or type(size) is not int
            or size < 0
            or not isinstance(content, str)
        ):
            _fail("SOURCE_STATE")
        if presence == ABSENT:
            if size != 0 or content:
                _fail("SOURCE_ABSENCE")
        else:
            if size > _MAX_FILE_BYTES:
                _fail("SOURCE_STATE")
            if len(content) != 4 * ((size + 2) // 3):
                _fail("SOURCE_CONTENT_SIZE_LIMIT")
        declared_total += size
        encoded_total += len(content)
        if declared_total > _MAX_TOTAL_BYTES:
            _fail("SOURCE_TOTAL_SIZE_LIMIT", str(declared_total))
        if encoded_total > _MAX_CANONICAL_BYTES:
            _fail("SOURCE_TOTAL_ENCODED_SIZE_LIMIT", str(encoded_total))
    return declared_total, encoded_total


def _preflight_output_encodings(
    rows: list[object],
    *,
    source_declared_total: int,
    source_encoded_total: int,
) -> None:
    declared_total = source_declared_total
    encoded_total = source_encoded_total
    for value in rows:
        if not isinstance(value, Mapping) or set(value) != _OUTPUT_KEYS:
            _fail("OUTPUT_SCHEMA")
        size = value.get("size")
        content = value.get("content_base64")
        presence = value.get("presence")
        if (
            presence not in {PRESENT, ABSENT}
            or
            type(size) is not int
            or size < 0
            or size > _MAX_FILE_BYTES
            or not isinstance(content, str)
        ):
            _fail("OUTPUT_STATE")
        if presence == ABSENT:
            if size != 0 or content:
                _fail("OUTPUT_ABSENCE")
        elif len(content) != 4 * ((size + 2) // 3):
            _fail("OUTPUT_CONTENT_SIZE_LIMIT")
        declared_total += size
        encoded_total += len(content)
        if declared_total > _MAX_TOTAL_BYTES:
            _fail("CAPTURE_TOTAL_SIZE_LIMIT", str(declared_total))
        if encoded_total > _MAX_CANONICAL_BYTES:
            _fail("CAPTURE_TOTAL_ENCODED_SIZE_LIMIT", str(encoded_total))


def _validated_source_row(value: object) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != _SOURCE_KEYS:
        _fail("SOURCE_SCHEMA")
    path = _canonical_path(value.get("path"))
    raw_roles = value.get("roles")
    if (
        not isinstance(raw_roles, list)
        or not raw_roles
        or len(raw_roles) > _MAX_SOURCE_ROLES
    ):
        _fail("SOURCE_ROLES", path)
    roles = [_canonical_role(role) for role in raw_roles]
    if roles != sorted(set(roles)):
        _fail("SOURCE_ROLES", path)
    presence = value.get("presence")
    size = value.get("size")
    sha256 = value.get("sha256")
    content = value.get("content_base64")
    if presence not in {PRESENT, ABSENT} or type(size) is not int or size < 0:
        _fail("SOURCE_STATE", path)
    if not isinstance(sha256, str) or not isinstance(content, str):
        _fail("SOURCE_STATE", path)
    if presence == ABSENT:
        if size != 0 or sha256 or content:
            _fail("SOURCE_ABSENCE", path)
    else:
        if size > _MAX_FILE_BYTES or not _HEX64_RE.fullmatch(sha256):
            _fail("SOURCE_STATE", path)
        encoded_limit = 4 * ((_MAX_FILE_BYTES + 2) // 3)
        if len(content) > encoded_limit or not content.isascii():
            _fail("SOURCE_CONTENT_SIZE_LIMIT", path)
        try:
            raw = base64.b64decode(content.encode("ascii"), validate=True)
        except (ValueError, UnicodeEncodeError) as exc:
            _fail("SOURCE_CONTENT", f"{path}: {type(exc).__name__}")
        if len(raw) != size or hashlib.sha256(raw).hexdigest() != sha256:
            _fail("SOURCE_CONTENT", path)
        if base64.b64encode(raw).decode("ascii") != content:
            _fail("SOURCE_CONTENT_NON_CANONICAL", path)
    return {
        "path": path,
        "roles": roles,
        "presence": presence,
        "size": size,
        "sha256": sha256,
        "content_base64": content,
    }


def _validate_report_assembly_source_capture(value: object) -> dict[str, Any]:
    """Validate and normalize one untrusted source-capture payload."""

    if not isinstance(value, Mapping) or set(value) != _CAPTURE_KEYS:
        _fail("CAPTURE_SCHEMA")
    if value.get("schema_version") != SOURCE_SCHEMA_VERSION:
        _fail("CAPTURE_SCHEMA_VERSION", str(value.get("schema_version")))
    metadata = _normalized_metadata(value.get("metadata"))

    fixed_raw = value.get("fixed_sources")
    if (
        not isinstance(fixed_raw, list)
        or len(fixed_raw) > _MAX_SOURCE_COUNT
        or any(
        not isinstance(row, Mapping) or set(row) != _SPEC_KEYS for row in fixed_raw
        )
    ):
        _fail("FIXED_SOURCE_SCHEMA")
    fixed_sources = [
        {
            "path": _canonical_path(row["path"]),
            "role": _canonical_role(row["role"]),
        }
        for row in fixed_raw
    ]
    if fixed_sources != sorted(fixed_sources, key=lambda row: row["path"]):
        _fail("FIXED_SOURCE_ORDER")
    fixed_paths = [row["path"] for row in fixed_sources]
    if len(fixed_paths) != len(set(fixed_paths)) or len(fixed_paths) != len(
        {_filesystem_key(path) for path in fixed_paths}
    ):
        _fail("FIXED_SOURCE_ALIAS")

    namespace_raw = value.get("namespace_specs")
    if (
        not isinstance(namespace_raw, list)
        or len(namespace_raw) > _MAX_NAMESPACE_COUNT
        or any(
            not isinstance(row, Mapping) or set(row) != _NAMESPACE_SPEC_KEYS
            for row in namespace_raw
        )
    ):
        _fail("NAMESPACE_SPEC_SCHEMA")
    namespace_specs = [
        {
            "pattern": _canonical_pattern(row["pattern"]),
            "role": _canonical_role(row["role"]),
        }
        for row in namespace_raw
    ]
    if namespace_specs != sorted(namespace_specs, key=lambda row: row["pattern"]):
        _fail("NAMESPACE_SPEC_ORDER")
    patterns = [row["pattern"] for row in namespace_specs]
    if len(patterns) != len(set(patterns)) or len(patterns) != len(
        {_filesystem_key(pattern) for pattern in patterns}
    ):
        _fail("NAMESPACE_SPEC_ALIAS")

    raw_sources = value.get("sources")
    if not isinstance(raw_sources, list) or len(raw_sources) > _MAX_SOURCE_COUNT:
        _fail("SOURCE_SCHEMA")
    source_declared_total, source_encoded_total = _preflight_source_encodings(
        raw_sources
    )
    sources = [_validated_source_row(row) for row in raw_sources]
    if sources != sorted(sources, key=lambda row: row["path"]):
        _fail("SOURCE_ORDER")
    paths = [row["path"] for row in sources]
    if len(paths) != len(set(paths)) or len(paths) != len(
        {_filesystem_key(path) for path in paths}
    ):
        _fail("SOURCE_PATH_ALIAS")
    total_bytes = source_declared_total
    source_by_path = {row["path"]: row for row in sources}
    for spec in fixed_sources:
        source = source_by_path.get(spec["path"])
        if source is None or spec["role"] not in source["roles"]:
            _fail("FIXED_SOURCE_LINK", spec["path"])

    raw_namespaces = value.get("namespaces")
    if (
        not isinstance(raw_namespaces, list)
        or len(raw_namespaces) > _MAX_NAMESPACE_COUNT
    ):
        _fail("NAMESPACE_SCHEMA")
    namespaces: list[dict[str, Any]] = []
    for raw in raw_namespaces:
        if not isinstance(raw, Mapping) or set(raw) != _NAMESPACE_KEYS:
            _fail("NAMESPACE_SCHEMA")
        pattern = _canonical_pattern(raw.get("pattern"))
        role = _canonical_role(raw.get("role"))
        members_raw = raw.get("members")
        if (
            not isinstance(members_raw, list)
            or len(members_raw) > _MAX_SOURCE_COUNT
        ):
            _fail("NAMESPACE_MEMBERS", pattern)
        members = [_canonical_path(member) for member in members_raw]
        if (
            members != sorted(set(members))
            or len(members)
            != len({_filesystem_key(member) for member in members})
        ):
            _fail("NAMESPACE_MEMBERS", pattern)
        if type(raw.get("member_count")) is not int or raw["member_count"] != len(members):
            _fail("NAMESPACE_COUNT", pattern)
        for member in members:
            source = source_by_path.get(member)
            if source is None or source["presence"] != PRESENT or role not in source["roles"]:
                _fail("NAMESPACE_SOURCE_LINK", f"{pattern}: {member}")
        expected_digest = _membership_digest(pattern, role, members, source_by_path)
        roster_digest = raw.get("membership_digest")
        if (
            not isinstance(roster_digest, str)
            or not _HEX64_RE.fullmatch(roster_digest)
            or roster_digest != expected_digest
        ):
            _fail("NAMESPACE_DIGEST", pattern)
        namespaces.append(
            {
                "pattern": pattern,
                "role": role,
                "members": members,
                "member_count": len(members),
                "membership_digest": expected_digest,
            }
        )
    if namespaces != sorted(namespaces, key=lambda row: row["pattern"]):
        _fail("NAMESPACE_ORDER")
    if [row["pattern"] for row in namespaces] != patterns:
        _fail("NAMESPACE_SPEC_ROSTER_MISMATCH")
    for spec, roster in zip(namespace_specs, namespaces, strict=True):
        if spec["role"] != roster["role"]:
            _fail("NAMESPACE_SPEC_ROSTER_MISMATCH", spec["pattern"])
    justified_paths = set(fixed_paths) | {
        member for roster in namespaces for member in roster["members"]
    }
    if set(source_by_path) != justified_paths:
        _fail("SOURCE_ROSTER_CLOSURE")

    input_paths = value.get("input_paths")
    explicit_absences = value.get("explicit_absences")
    if (
        not isinstance(input_paths, list)
        or not isinstance(explicit_absences, list)
        or len(input_paths) > _MAX_SOURCE_COUNT
        or len(explicit_absences) > _MAX_SOURCE_COUNT
    ):
        _fail("CAPTURE_DENOMINATOR_SCHEMA")
    input_paths_n = [_canonical_path(path) for path in input_paths]
    explicit_absences_n = [_canonical_path(path) for path in explicit_absences]
    expected_inputs = sorted(
        row["path"] for row in sources if row["presence"] == PRESENT
    )
    fixed_set = set(fixed_paths)
    expected_absences = sorted(
        row["path"]
        for row in sources
        if row["presence"] == ABSENT and row["path"] in fixed_set
    )
    if input_paths_n != expected_inputs:
        _fail("CAPTURE_INPUT_DENOMINATOR")
    if explicit_absences_n != expected_absences:
        _fail("CAPTURE_ABSENCE_DENOMINATOR")
    if value.get("source_set_digest") != _source_set_digest(sources):
        _fail("SOURCE_SET_DIGEST")

    normalized = {
        "schema_version": SOURCE_SCHEMA_VERSION,
        "metadata": metadata,
        "fixed_sources": fixed_sources,
        "namespace_specs": namespace_specs,
        "sources": sources,
        "namespaces": namespaces,
        "input_paths": input_paths_n,
        "explicit_absences": explicit_absences_n,
        "source_set_digest": value.get("source_set_digest"),
        "capture_digest": value.get("capture_digest"),
    }
    capture_digest = normalized["capture_digest"]
    if not isinstance(capture_digest, str) or not _HEX64_RE.fullmatch(capture_digest):
        _fail("CAPTURE_DIGEST")
    unsigned = dict(normalized)
    unsigned["capture_digest"] = ""
    _canonical_json_bytes(normalized)
    if _digest(unsigned) != capture_digest:
        _fail("CAPTURE_DIGEST")
    return normalized


def _validate_report_assembly_final_capture(
    value: object,
    *,
    expected_final_artifact_identity: str,
    expected_predecessor_binding: Mapping[str, str],
) -> dict[str, Any]:
    """Validate a final capture against caller-owned identity and provenance."""

    _expected_final_identity(expected_final_artifact_identity)
    expected_predecessor = _normalized_predecessor_binding(
        expected_predecessor_binding
    )
    if not isinstance(value, Mapping) or set(value) != _FINAL_CAPTURE_KEYS:
        _fail("CAPTURE_SCHEMA")
    if value.get("schema_version") != FINAL_SCHEMA_VERSION:
        _fail("CAPTURE_SCHEMA_VERSION", str(value.get("schema_version")))
    metadata = _normalized_metadata(value.get("metadata"))
    predecessor = _normalized_predecessor_binding(
        value.get("predecessor_binding")
    )
    if predecessor != expected_predecessor:
        _fail("PREDECESSOR_BINDING_MISMATCH")
    if predecessor["run_id"] != metadata["run_id"]:
        _fail("PREDECESSOR_BINDING_RUN")
    expected_producer = "/".join(
        (
            metadata["pipeline"],
            metadata["mode"],
            metadata["ecosystem"],
            metadata["backend"],
            "report_assemble",
            "source_capture",
        )
    )
    if predecessor["producer_work_unit_key"] != expected_producer:
        _fail("PREDECESSOR_BINDING_PRODUCER")

    raw_outputs = value.get("derived_outputs")
    if not isinstance(raw_outputs, list) or len(raw_outputs) > _MAX_OUTPUT_COUNT:
        _fail("OUTPUT_SCHEMA")
    _preflight_output_encodings(
        raw_outputs,
        source_declared_total=0,
        source_encoded_total=0,
    )
    outputs: list[dict[str, Any]] = []
    for raw in raw_outputs:
        if not isinstance(raw, Mapping) or set(raw) != _OUTPUT_KEYS:
            _fail("OUTPUT_SCHEMA")
        root = raw.get("root")
        path = _canonical_path(raw.get("path"))
        if root not in {"project", "scratchpad"}:
            _fail("OUTPUT_ROOT", str(root))
        role = _canonical_role(raw.get("role"))
        identity = f"{root}:{path}"
        if ALLOWED_DERIVED_OUTPUT_ROLES.get(identity) != role:
            _fail("OUTPUT_AUTHORITY", identity)
        presence = raw.get("presence")
        size = raw.get("size")
        sha256 = raw.get("sha256")
        content = raw.get("content_base64")
        if (
            presence not in {PRESENT, ABSENT}
            or type(size) is not int
            or size < 0
            or size > _MAX_FILE_BYTES
            or not isinstance(sha256, str)
            or not isinstance(content, str)
        ):
            _fail("OUTPUT_STATE", identity)
        if presence == ABSENT:
            if size != 0 or sha256 or content:
                _fail("OUTPUT_ABSENCE", identity)
            outputs.append(
                {
                    "root": root,
                    "path": path,
                    "role": role,
                    "presence": ABSENT,
                    "size": 0,
                    "sha256": "",
                    "content_base64": "",
                }
            )
            continue
        if not _HEX64_RE.fullmatch(sha256):
            _fail("OUTPUT_STATE", identity)
        encoded_limit = 4 * ((_MAX_FILE_BYTES + 2) // 3)
        if len(content) > encoded_limit or not content.isascii():
            _fail("OUTPUT_CONTENT_SIZE_LIMIT", identity)
        try:
            raw_bytes = base64.b64decode(content.encode("ascii"), validate=True)
        except (ValueError, UnicodeEncodeError) as exc:
            _fail("OUTPUT_CONTENT", f"{identity}: {type(exc).__name__}")
        if (
            len(raw_bytes) != size
            or hashlib.sha256(raw_bytes).hexdigest() != sha256
            or base64.b64encode(raw_bytes).decode("ascii") != content
        ):
            _fail("OUTPUT_CONTENT", identity)
        outputs.append(
            {
                "root": root,
                "path": path,
                "role": role,
                "presence": PRESENT,
                "size": size,
                "sha256": sha256,
                "content_base64": content,
            }
        )
    if outputs != sorted(outputs, key=lambda row: (row["root"], row["path"])):
        _fail("OUTPUT_ORDER")
    output_ids = [f"{row['root']}:{row['path']}" for row in outputs]
    filesystem_ids = [
        f"{row['root']}:{_filesystem_key(row['path'])}" for row in outputs
    ]
    if len(output_ids) != len(set(output_ids)) or len(filesystem_ids) != len(
        set(filesystem_ids)
    ):
        _fail("OUTPUT_DUPLICATE")
    if sorted(output_ids) != sorted(ALLOWED_DERIVED_OUTPUT_ROLES):
        _fail("OUTPUT_DENOMINATOR")
    output_by_id = dict(zip(output_ids, outputs, strict=True))
    for identity in MANDATORY_DERIVED_OUTPUTS:
        if output_by_id[identity]["presence"] != PRESENT:
            _fail("OUTPUT_MANDATORY_ABSENT", identity)
    if sum(row["size"] for row in outputs) > _MAX_TOTAL_BYTES:
        _fail("CAPTURE_TOTAL_SIZE_LIMIT")

    raw_locations = value.get("location_decisions")
    if (
        not isinstance(raw_locations, list)
        or len(raw_locations) > _MAX_LOCATION_COUNT
    ):
        _fail("LOCATION_SCHEMA")
    location_decisions = [
        _location_row(
            row,
            expected_source_snapshot_sha256=metadata[
                "source_snapshot_sha256"
            ],
        )
        for row in raw_locations
    ]
    if location_decisions != sorted(
        location_decisions,
        key=lambda row: (row["report_id"], row["original_location"]),
    ):
        _fail("LOCATION_ORDER")
    _assert_unique_location_keys(location_decisions)
    normalized = {
        "schema_version": FINAL_SCHEMA_VERSION,
        "metadata": metadata,
        "predecessor_binding": predecessor,
        "derived_outputs": outputs,
        "location_decisions": location_decisions,
        "capture_digest": value.get("capture_digest"),
    }
    capture_digest = normalized["capture_digest"]
    if not isinstance(capture_digest, str) or not _HEX64_RE.fullmatch(
        capture_digest
    ):
        _fail("CAPTURE_DIGEST")
    unsigned = dict(normalized)
    unsigned["capture_digest"] = ""
    _canonical_json_bytes(normalized)
    if _digest(unsigned) != capture_digest:
        _fail("CAPTURE_DIGEST")
    return normalized


def _report_assembly_capture_exact_inputs(value: object) -> tuple[str, ...]:
    """Return the exact present-file PhaseIO denominator."""

    payload = _validate_report_assembly_source_capture(value)
    return tuple(payload["input_paths"])


def _report_assembly_capture_explicit_absences(value: object) -> tuple[str, ...]:
    """Return fixed paths whose absence must be bound by the integration."""

    payload = _validate_report_assembly_source_capture(value)
    return tuple(payload["explicit_absences"])


def _report_assembly_capture_source_bytes(
    value: object,
) -> dict[str, tuple[tuple[str, ...], bytes]]:
    """Return immutable-source roles and exact bytes from a valid capture.

    This is deliberately a narrow private codec seam.  Production callers add
    committed ArtifactLedger authority before exposing frozen typed rows.
    """

    payload = _validate_report_assembly_source_capture(value)
    return {
        row["path"]: (
            tuple(row["roles"]),
            base64.b64decode(
                row["content_base64"].encode("ascii"), validate=True
            ),
        )
        for row in payload["sources"]
        if row["presence"] == PRESENT
    }


def _report_assembly_capture_source_namespaces(
    value: object,
) -> tuple[tuple[str, str, tuple[str, ...], str], ...]:
    """Return canonical namespace rosters without leaking mutable mappings."""

    payload = _validate_report_assembly_source_capture(value)
    return tuple(
        (
            row["pattern"],
            row["role"],
            tuple(row["members"]),
            row["membership_digest"],
        )
        for row in payload["namespaces"]
    )


def _report_assembly_capture_output_bytes(
    value: object,
    *,
    expected_final_artifact_identity: str,
    expected_predecessor_binding: Mapping[str, str],
) -> dict[str, bytes]:
    """Return the exact derived output bytes carried by a valid capture."""

    payload = _validate_report_assembly_final_capture(
        value,
        expected_final_artifact_identity=expected_final_artifact_identity,
        expected_predecessor_binding=expected_predecessor_binding,
    )
    return {
        f"{row['root']}:{row['path']}": base64.b64decode(
            row["content_base64"].encode("ascii"), validate=True
        )
        for row in payload["derived_outputs"]
        if row["presence"] == PRESENT
    }


def _report_assembly_capture_output_absences(
    value: object,
    *,
    expected_final_artifact_identity: str,
    expected_predecessor_binding: Mapping[str, str],
) -> tuple[str, ...]:
    """Return the exact final-output identities declared canonically absent."""

    payload = _validate_report_assembly_final_capture(
        value,
        expected_final_artifact_identity=expected_final_artifact_identity,
        expected_predecessor_binding=expected_predecessor_binding,
    )
    return tuple(
        sorted(
            f"{row['root']}:{row['path']}"
            for row in payload["derived_outputs"]
            if row["presence"] == ABSENT
        )
    )


def _replay_report_assembly_source_capture(
    scratchpad: str | Path,
    value: object,
) -> dict[str, Any]:
    """Reject source drift and late live outputs from a capture payload."""

    expected = _validate_report_assembly_source_capture(value)
    fixed = {row["path"]: row["role"] for row in expected["fixed_sources"]}
    namespace = {
        row["pattern"]: row["role"] for row in expected["namespace_specs"]
    }
    with _pinned_root(Path(scratchpad)) as root:
        current = _build_report_assembly_source_capture(
            root,
            metadata=expected["metadata"],
            fixed_source_roles=fixed,
            namespace_roles=namespace,
        )
    expected_namespaces = {
        row["pattern"]: row for row in expected["namespaces"]
    }
    current_namespaces = {
        row["pattern"]: row for row in current["namespaces"]
    }
    if expected_namespaces != current_namespaces:
        _fail("NAMESPACE_DRIFT")
    expected_sources = {row["path"]: row for row in expected["sources"]}
    current_sources = {row["path"]: row for row in current["sources"]}
    if expected_sources != current_sources:
        _fail("SOURCE_DRIFT")
    if (
        expected["input_paths"] != current["input_paths"]
        or expected["explicit_absences"] != current["explicit_absences"]
        or expected["source_set_digest"] != current["source_set_digest"]
    ):
        _fail("SOURCE_DRIFT")
    return expected


def _replay_report_assembly_final_capture(
    scratchpad: str | Path,
    value: object,
    *,
    expected_final_artifact_identity: str,
    expected_predecessor_binding: Mapping[str, str],
) -> dict[str, Any]:
    """Revalidate provenance and the closed scratch-output namespace."""

    expected = _validate_report_assembly_final_capture(
        value,
        expected_final_artifact_identity=expected_final_artifact_identity,
        expected_predecessor_binding=expected_predecessor_binding,
    )
    with _pinned_root(Path(scratchpad)) as root:
        _register_clean_scratch_output_namespace(root)
        _verify_pinned_capture(root)
    return expected


def _observe_terminal_exact_file(
    root: _PinnedRoot,
    relative: str,
    *,
    maximum_bytes: int,
) -> tuple[bytes, tuple[int, ...]]:
    """Observe through a retained handle that survives terminal verification."""

    retained = root.retained_files.get(relative)
    if retained is None:
        retained = _retain_terminal_exact_file(
            root, relative, maximum_bytes=maximum_bytes
        )
        root.retained_files[relative] = retained
        return retained.expected_bytes, retained.physical_identity
    if retained.maximum_bytes != maximum_bytes:
        _fail("TERMINAL_PAIR_FILE_BOUND_DRIFT", relative)
    raw, physical = _verify_retained_terminal_file(root, retained)
    return raw, physical


def _retain_terminal_exact_file(
    root: _PinnedRoot,
    relative: str,
    *,
    maximum_bytes: int,
) -> _RetainedFile:
    path = root.path.joinpath(*PurePosixPath(relative).parts)
    try:
        path_row = os.lstat(path)
    except OSError as exc:
        _fail("TERMINAL_PAIR_FILE_STAT", f"{relative}: {type(exc).__name__}")
    _validate_source_metadata(
        path_row, relative=relative, maximum_bytes=maximum_bytes
    )
    path_identity = _source_metadata_identity(path_row)

    if os.name != "nt":
        descriptor = _open_posix_rooted_source(root, relative)
        try:
            opened = os.fstat(descriptor)
            _validate_source_metadata(
                opened, relative=relative, maximum_bytes=maximum_bytes
            )
            physical = _source_metadata_identity(opened)
            if physical != path_identity:
                _fail("TERMINAL_PAIR_PHYSICAL_DRIFT", relative)
            os.lseek(descriptor, 0, os.SEEK_SET)
            first = _read_descriptor_bounded(
                descriptor,
                relative=relative,
                maximum_bytes=maximum_bytes,
            )
            os.lseek(descriptor, 0, os.SEEK_SET)
            second = _read_descriptor_bounded(
                descriptor,
                relative=relative,
                maximum_bytes=maximum_bytes,
            )
            if first != second or len(first) != int(opened.st_size):
                _fail("TERMINAL_PAIR_CONTENT_DRIFT", relative)
            return _RetainedFile(
                relative=relative,
                path=path,
                expected_bytes=first,
                expected_sha256=hashlib.sha256(first).hexdigest(),
                expected_size=len(first),
                physical_identity=physical,
                maximum_bytes=maximum_bytes,
                descriptor=descriptor,
            )
        except Exception:
            os.close(descriptor)
            raise

    handle = _CREATE_FILE_W(
        _windows_native_path(path),
        _WIN_GENERIC_READ,
        # Retain a read-only, read-share-only handle: another opener cannot
        # write, delete, or replace the file before terminal verification.
        _WIN_SHARE_READ,
        None,
        _WIN_OPEN_EXISTING,
        _WIN_FILE_FLAG_OPEN_REPARSE_POINT,
        None,
    )
    if handle == _WIN_INVALID_HANDLE_VALUE:
        _fail("TERMINAL_PAIR_FILE_OPEN", relative)
    try:
        info = _windows_file_information(handle, relative=relative)
        attributes = int(info.dwFileAttributes)
        size = _windows_information_size(info)
        if (
            attributes
            & (_WIN_FILE_ATTRIBUTE_DIRECTORY | _WIN_FILE_ATTRIBUTE_REPARSE_POINT)
            or int(info.nNumberOfLinks) != 1
            or size > maximum_bytes
            or not _windows_stat_matches_information(
                path_row, info, require_directory=False
            )
        ):
            _fail("TERMINAL_PAIR_FILE_IDENTITY", relative)
        expected_path = os.path.normcase(
            os.path.normpath(os.path.abspath(os.fspath(path)))
        )
        if os.path.normcase(_windows_final_path(handle, relative=relative)) != expected_path:
            _fail("TERMINAL_PAIR_FILE_PATH", relative)
        first = _windows_read_once(
            handle, relative=relative, maximum_bytes=maximum_bytes
        )
        if not _SET_FILE_POINTER_EX(handle, 0, None, _WIN_FILE_BEGIN):
            _fail("TERMINAL_PAIR_FILE_SEEK", relative)
        second = _windows_read_once(
            handle, relative=relative, maximum_bytes=maximum_bytes
        )
        if first != second or len(first) != size:
            _fail("TERMINAL_PAIR_CONTENT_DRIFT", relative)
        physical = (
            *_windows_information_identity(info),
            *path_identity,
        )
        return _RetainedFile(
            relative=relative,
            path=path,
            expected_bytes=first,
            expected_sha256=hashlib.sha256(first).hexdigest(),
            expected_size=len(first),
            physical_identity=physical,
            maximum_bytes=maximum_bytes,
            handle=handle,
        )
    except Exception:
        _CLOSE_HANDLE(handle)
        raise


def _verify_retained_terminal_file(
    root: _PinnedRoot,
    retained: _RetainedFile,
) -> tuple[bytes, tuple[int, ...]]:
    relative = retained.relative
    try:
        live_row = os.lstat(retained.path)
    except OSError as exc:
        _fail("TERMINAL_PAIR_FILE_STAT", f"{relative}: {type(exc).__name__}")
    _validate_source_metadata(
        live_row,
        relative=relative,
        maximum_bytes=retained.maximum_bytes,
    )

    if os.name != "nt":
        if retained.descriptor is None:
            _fail("TERMINAL_PAIR_RETAINED_DESCRIPTOR", relative)
        handle_row = os.fstat(retained.descriptor)
        _validate_source_metadata(
            handle_row,
            relative=relative,
            maximum_bytes=retained.maximum_bytes,
        )
        physical = _source_metadata_identity(handle_row)
        if (
            physical != retained.physical_identity
            or _source_metadata_identity(live_row) != physical
        ):
            _fail("TERMINAL_PAIR_PHYSICAL_DRIFT", relative)
        live_descriptor = _open_posix_rooted_source(root, relative)
        try:
            if _source_metadata_identity(os.fstat(live_descriptor)) != physical:
                _fail("TERMINAL_PAIR_LIVE_PATH_DRIFT", relative)
        finally:
            os.close(live_descriptor)
        os.lseek(retained.descriptor, 0, os.SEEK_SET)
        first = _read_descriptor_bounded(
            retained.descriptor,
            relative=relative,
            maximum_bytes=retained.maximum_bytes,
        )
        os.lseek(retained.descriptor, 0, os.SEEK_SET)
        second = _read_descriptor_bounded(
            retained.descriptor,
            relative=relative,
            maximum_bytes=retained.maximum_bytes,
        )
    else:
        if retained.handle is None:
            _fail("TERMINAL_PAIR_RETAINED_HANDLE", relative)
        info = _windows_file_information(retained.handle, relative=relative)
        physical = (
            *_windows_information_identity(info),
            *_source_metadata_identity(live_row),
        )
        if (
            physical != retained.physical_identity
            or not _windows_stat_matches_information(
                live_row, info, require_directory=False
            )
            or os.path.normcase(
                _windows_final_path(retained.handle, relative=relative)
            )
            != os.path.normcase(
                os.path.normpath(os.path.abspath(os.fspath(retained.path)))
            )
        ):
            _fail("TERMINAL_PAIR_PHYSICAL_DRIFT", relative)
        if not _SET_FILE_POINTER_EX(
            retained.handle, 0, None, _WIN_FILE_BEGIN
        ):
            _fail("TERMINAL_PAIR_FILE_SEEK", relative)
        first = _windows_read_once(
            retained.handle,
            relative=relative,
            maximum_bytes=retained.maximum_bytes,
        )
        if not _SET_FILE_POINTER_EX(
            retained.handle, 0, None, _WIN_FILE_BEGIN
        ):
            _fail("TERMINAL_PAIR_FILE_SEEK", relative)
        second = _windows_read_once(
            retained.handle,
            relative=relative,
            maximum_bytes=retained.maximum_bytes,
        )
    if (
        first != second
        or first != retained.expected_bytes
        or len(first) != retained.expected_size
        or hashlib.sha256(first).hexdigest() != retained.expected_sha256
    ):
        _fail("TERMINAL_PAIR_CONTENT_DRIFT", relative)
    return first, retained.physical_identity


def _verify_retained_terminal_files(root: _PinnedRoot) -> None:
    for retained in tuple(
        root.retained_files[path] for path in sorted(root.retained_files)
    ):
        _verify_retained_terminal_file(root, retained)


def _register_terminal_namespace_authority(
    root: _PinnedRoot,
    expected_source: Mapping[str, Any],
) -> None:
    root.retained_namespace_members.update(
        {
            row["pattern"]: tuple(row["members"])
            for row in expected_source["namespaces"]
        }
    )
    if os.name == "nt":
        if root.handle is None:
            _fail("TERMINAL_NAMESPACE_ROOT_HANDLE")
        info = _windows_file_information(
            root.handle, relative="<capture-root>"
        )
        try:
            path_row = os.lstat(root.path)
        except OSError as exc:
            _fail("TERMINAL_NAMESPACE_ROOT_STAT", type(exc).__name__)
        object.__setattr__(
            root,
            "retained_windows_root_identity",
            _windows_information_identity(info),
        )
        object.__setattr__(
            root,
            "retained_windows_root_stat_identity",
            _directory_metadata_identity(path_row),
        )


def _verify_retained_terminal_namespaces(root: _PinnedRoot) -> None:
    for pattern in sorted(root.retained_namespace_members):
        if _namespace_members(root, pattern) != root.retained_namespace_members[
            pattern
        ]:
            _fail("TERMINAL_NAMESPACE_MEMBERSHIP_DRIFT", pattern)
    if os.name == "nt":
        if root.handle is None:
            _fail("TERMINAL_NAMESPACE_ROOT_HANDLE")
        info = _windows_file_information(
            root.handle, relative="<capture-root>"
        )
        try:
            path_row = os.lstat(root.path)
        except OSError as exc:
            _fail("TERMINAL_NAMESPACE_ROOT_STAT", type(exc).__name__)
        if (
            _windows_information_identity(info)
            != root.retained_windows_root_identity
            or _directory_metadata_identity(path_row)
            != root.retained_windows_root_stat_identity
        ):
            _fail("TERMINAL_NAMESPACE_ROOT_DRIFT")
        _verify_all_windows_directories(root)
    else:
        _verify_retained_posix_namespace_directories(root)


def _terminal_source_rebuild(
    root: _PinnedRoot,
    expected: Mapping[str, Any],
) -> None:
    fixed = {row["path"]: row["role"] for row in expected["fixed_sources"]}
    namespace = {
        row["pattern"]: row["role"] for row in expected["namespace_specs"]
    }
    current = _build_report_assembly_source_capture(
        root,
        metadata=expected["metadata"],
        fixed_source_roles=fixed,
        namespace_roles=namespace,
    )
    if current != expected:
        _fail("TERMINAL_PAIR_SOURCE_DRIFT")


def _replay_report_assembly_terminal_pair(
    scratchpad: str | Path,
    *,
    source_capture: object,
    source_capture_bytes: bytes,
    final_capture: object,
    final_capture_bytes: bytes,
    expected_final_artifact_identity: str,
    expected_predecessor_binding: Mapping[str, str],
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Replay source and final filesystem authority in one pinned epoch.

    The epoch binds both capture artifacts, every live source member's bytes
    and physical identity, fixed/namespace membership, and the complete clean
    scratch-output namespace.  The linearization point is the context's final
    retained-handle/directory/absence verification: retained handles are then
    closed as cleanup, and no authority read or callback occurs before the
    exact in-memory pair is returned.  A mutation after handle verification is
    future filesystem state and cannot change that returned pair.  Callers
    must perform no filesystem authority operation after this primitive.
    """

    expected_source = _validate_report_assembly_source_capture(source_capture)
    expected_final = _validate_report_assembly_final_capture(
        final_capture,
        expected_final_artifact_identity=expected_final_artifact_identity,
        expected_predecessor_binding=expected_predecessor_binding,
    )
    if type(source_capture_bytes) is not bytes or type(final_capture_bytes) is not bytes:
        _fail("TERMINAL_PAIR_CAPTURE_BYTES")
    if (
        len(source_capture_bytes) > _MAX_CANONICAL_BYTES
        or len(final_capture_bytes) > _MAX_CANONICAL_BYTES
        or _canonical_report_assembly_source_capture_bytes(expected_source)
        != source_capture_bytes
        or _canonical_report_assembly_final_capture_bytes(
            expected_final,
            expected_final_artifact_identity=expected_final_artifact_identity,
            expected_predecessor_binding=expected_predecessor_binding,
        )
        != final_capture_bytes
    ):
        _fail("TERMINAL_PAIR_CAPTURE_BYTES")

    expected_files: dict[str, tuple[bytes, int]] = {
        SOURCE_CAPTURE_IDENTITY.split(":", 1)[1]: (
            source_capture_bytes,
            _MAX_CANONICAL_BYTES,
        ),
        FINAL_CAPTURE_IDENTITY.split(":", 1)[1]: (
            final_capture_bytes,
            _MAX_CANONICAL_BYTES,
        ),
    }
    for row in expected_source["sources"]:
        if row["presence"] != PRESENT:
            continue
        raw = base64.b64decode(row["content_base64"].encode("ascii"), validate=True)
        prior = expected_files.setdefault(row["path"], (raw, _MAX_FILE_BYTES))
        if prior[0] != raw:
            _fail("TERMINAL_PAIR_SOURCE_ALIAS", row["path"])

    with _pinned_root(Path(scratchpad)) as root:
        _register_terminal_namespace_authority(root, expected_source)
        _terminal_source_rebuild(root, expected_source)
        observations: dict[str, tuple[tuple[int, ...], str, int]] = {}
        for relative, (expected_raw, maximum_bytes) in sorted(
            expected_files.items()
        ):
            raw, physical = _observe_terminal_exact_file(
                root, relative, maximum_bytes=maximum_bytes
            )
            if raw != expected_raw:
                _fail("TERMINAL_PAIR_CONTENT_DRIFT", relative)
            observations[relative] = (
                physical,
                hashlib.sha256(raw).hexdigest(),
                len(raw),
            )

        _register_clean_scratch_output_namespace(root)

        # Rebuild after the output half so membership/content mutations after
        # either half are reconciled inside this same retained-root epoch.
        _terminal_source_rebuild(root, expected_source)
        for relative, (expected_raw, maximum_bytes) in sorted(
            expected_files.items()
        ):
            raw, physical = _observe_terminal_exact_file(
                root, relative, maximum_bytes=maximum_bytes
            )
            observed = (
                physical,
                hashlib.sha256(raw).hexdigest(),
                len(raw),
            )
            if raw != expected_raw or observed != observations[relative]:
                _fail("TERMINAL_PAIR_PHYSICAL_OR_CONTENT_DRIFT", relative)
        _verify_pinned_capture(root)
    return expected_source, expected_final


__all__ = [
    "ABSENT",
    "ALLOWED_DERIVED_OUTPUT_ROLES",
    "DEFAULT_FIXED_SOURCE_ROLES",
    "DEFAULT_NAMESPACE_ROLES",
    "FINAL_CAPTURE_IDENTITY",
    "FINAL_SCHEMA_VERSION",
    "MANDATORY_DERIVED_OUTPUTS",
    "PRESENT",
    "ReportAssemblyCaptureError",
    "SCHEMA_VERSION",
    "SOURCE_CAPTURE_IDENTITY",
    "SOURCE_SCHEMA_VERSION",
]
