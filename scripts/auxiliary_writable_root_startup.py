"""Crash-safe startup authority for auxiliary writable-root allocation.

The provider owns lease recovery.  This module owns the driver-facing startup
ordering boundary:

1. acquire one cooperative, per-scratchpad OS advisory lock;
2. durably replace the current pointer with a unique ``RECONCILING`` epoch;
3. run and replay provider reconciliation;
4. publish an immutable, epoch-and-digest-addressed receipt; and
5. compare-and-swap the exact current pointer to ``COMPLETE``.

Only a current, COMPLETE, exact-epoch ALLOW receipt can produce a permit
binding.  A prior ALLOW is therefore structurally stale before reconciliation
starts, including when later receipt publication fails.

Filesystem claims are deliberately bounded.  POSIX uses no-follow opens,
descriptor identity replay, file fsync, atomic link/replace, and directory
fsync.  Windows uses lstat/fstat identity checks and
MoveFileExW(MOVEFILE_WRITE_THROUGH), because CPython does not expose a
portable directory fsync or a fully reparse-safe open.  Cooperative locking
does not protect against a hostile same-user process, and network filesystems
may not honor local atomicity/durability contracts; unsupported directory
fsync fails closed rather than being described as durable.

The nested provider reconciliation includes absolute provider-runtime paths.
This receipt is internal execution evidence and must not be exported in a
client-facing run bundle without a separate redaction/provenance projection.
"""

from __future__ import annotations

from contextlib import contextmanager
import ctypes
import hashlib
import json
import math
import os
from pathlib import Path
import re
import secrets
import stat
import time
from typing import Any, Iterator, Mapping
import uuid

from auxiliary_writable_root_lease import (
    reconcile_auxiliary_writable_root_leases,
    replay_auxiliary_writable_root_reconciliation,
)


STARTUP_RECEIPT_SCHEMA = (
    "plamen.auxiliary_writable_root_startup_receipt.v2"
)
STARTUP_CURRENT_SCHEMA = (
    "plamen.auxiliary_writable_root_startup_current.v1"
)
STARTUP_BINDING_SCHEMA = (
    "plamen.auxiliary_writable_root_startup_permit_binding.v2"
)
STARTUP_CURRENT_NAME = "_auxiliary_writable_root_startup_current.json"
# Retained as a source-compatibility alias.  It now names the authority pointer,
# not a replaceable receipt.  Callers must use the relative receipt path in the
# replayed binding.
STARTUP_RECEIPT_NAME = STARTUP_CURRENT_NAME
STARTUP_RECEIPT_DIRECTORY_NAME = (
    "_auxiliary_writable_root_startup_receipts"
)
STARTUP_QUARANTINE_DIRECTORY_NAME = (
    "_auxiliary_writable_root_startup_abandoned"
)
STARTUP_LOCK_NAME = "_auxiliary_writable_root_startup.lock"

MAX_STARTUP_RECEIPT_BYTES = 4 * 1024 * 1024
MAX_STARTUP_POINTER_BYTES = 64 * 1024
MAX_JSON_DEPTH = 64
MAX_JSON_STRING_CHARS = 32 * 1024
MAX_JSON_NODES = 100_000
MAX_JSON_INTEGER_DIGITS = 19
MAX_ABANDONED_TEMPORARIES = 1024
MAX_IMMUTABLE_RECEIPTS = 10_000
STARTUP_LOCK_TIMEOUT_SECONDS = 30.0

_RUN_ID_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12}"
)
_EPOCH_RE = re.compile(r"[0-9a-f]{32}")
_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_EXCEPTION_TYPE_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}")
_RECEIPT_NAME_RE = re.compile(
    r"startup-([0-9a-f]{32})-([0-9a-f]{64})\.json"
)
_DISPOSITIONS = {
    "ALLOW_NEW_LEASES",
    "ALLOW_NEW_LEASES_WITH_RUNTIME_DEBT",
    "DENY_NEW_LEASES",
}
_PERMIT_DISPOSITIONS = {
    "ALLOW_NEW_LEASES",
    "ALLOW_NEW_LEASES_WITH_RUNTIME_DEBT",
}


class AuxiliaryWritableRootStartupError(RuntimeError):
    """Raised when exact startup allocation authority cannot be established."""


def _windows_extended_path(path: Path) -> str:
    value = str(Path(path).absolute())
    if value.startswith("\\\\?\\"):
        return value
    if value.startswith("\\\\"):
        return "\\\\?\\UNC\\" + value[2:]
    return "\\\\?\\" + value


def _native_path(path: Path) -> str | Path:
    return _windows_extended_path(path) if os.name == "nt" else path


def _lstat(path: Path) -> os.stat_result:
    return os.lstat(_native_path(path))


def _lexists(path: Path) -> bool:
    try:
        _lstat(path)
        return True
    except (FileNotFoundError, NotADirectoryError):
        return False


def _unlink_if_present(path: Path) -> None:
    try:
        os.unlink(_native_path(path))
    except FileNotFoundError:
        pass


def _strict_object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise AuxiliaryWritableRootStartupError(
                "startup JSON contains duplicate keys"
            )
        result[key] = value
    return result


def _reject_json_constant(value: str) -> Any:
    raise AuxiliaryWritableRootStartupError(
        f"startup JSON contains invalid constant {value}"
    )


def _bounded_json_integer(value: str) -> int:
    digits = value[1:] if value.startswith("-") else value
    if len(digits) > MAX_JSON_INTEGER_DIGITS:
        raise AuxiliaryWritableRootStartupError(
            "startup JSON integer exceeds its digit bound"
        )
    try:
        result = int(value, 10)
    except ValueError as exc:
        raise AuxiliaryWritableRootStartupError(
            "startup JSON integer is invalid"
        ) from exc
    if abs(result) > 9_223_372_036_854_775_807:
        raise AuxiliaryWritableRootStartupError(
            "startup JSON integer exceeds its value bound"
        )
    return result


def _bounded_json_float(value: str) -> float:
    if len(value) > 64:
        raise AuxiliaryWritableRootStartupError(
            "startup JSON float exceeds its token bound"
        )
    try:
        result = float(value)
    except ValueError as exc:
        raise AuxiliaryWritableRootStartupError(
            "startup JSON float is invalid"
        ) from exc
    if not math.isfinite(result):
        raise AuxiliaryWritableRootStartupError(
            "startup JSON float is not finite"
        )
    return result


def _preflight_json_depth(text: str) -> None:
    """Bound structural nesting before CPython's decoder can recurse."""

    depth = 0
    in_string = False
    escaped = False
    for char in text:
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char in "[{":
            depth += 1
            if depth > MAX_JSON_DEPTH:
                raise AuxiliaryWritableRootStartupError(
                    "startup JSON exceeds its depth bound"
                )
        elif char in "]}":
            depth -= 1
            if depth < 0:
                # Let the strict decoder provide the generic syntax failure.
                return


def _validate_json_limits(value: Any) -> None:
    stack: list[tuple[Any, int]] = [(value, 0)]
    nodes = 0
    while stack:
        current, depth = stack.pop()
        nodes += 1
        if nodes > MAX_JSON_NODES:
            raise AuxiliaryWritableRootStartupError(
                "startup JSON exceeds its node bound"
            )
        if depth > MAX_JSON_DEPTH:
            raise AuxiliaryWritableRootStartupError(
                "startup JSON exceeds its depth bound"
            )
        if isinstance(current, str):
            if len(current) > MAX_JSON_STRING_CHARS or "\x00" in current:
                raise AuxiliaryWritableRootStartupError(
                    "startup JSON string exceeds its bound or contains NUL"
                )
        elif current is None or isinstance(current, bool):
            continue
        elif isinstance(current, int):
            if abs(current) > 9_223_372_036_854_775_807:
                raise AuxiliaryWritableRootStartupError(
                    "startup JSON integer exceeds its value bound"
                )
        elif isinstance(current, float):
            if not math.isfinite(current):
                raise AuxiliaryWritableRootStartupError(
                    "startup JSON float is not finite"
                )
        elif isinstance(current, Mapping):
            if len(current) > MAX_JSON_NODES:
                raise AuxiliaryWritableRootStartupError(
                    "startup JSON object exceeds its item bound"
                )
            for key, item in current.items():
                if not isinstance(key, str):
                    raise AuxiliaryWritableRootStartupError(
                        "startup JSON object key is not a string"
                    )
                stack.append((key, depth + 1))
                stack.append((item, depth + 1))
        elif isinstance(current, (list, tuple)):
            if len(current) > MAX_JSON_NODES:
                raise AuxiliaryWritableRootStartupError(
                    "startup JSON array exceeds its item bound"
                )
            stack.extend((item, depth + 1) for item in current)
        else:
            raise AuxiliaryWritableRootStartupError(
                "startup value is not strict JSON"
            )


def _canonical_json(value: Mapping[str, Any]) -> bytes:
    _validate_json_limits(value)
    try:
        raw = json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise AuxiliaryWritableRootStartupError(
            "startup value is not canonicalizable"
        ) from exc
    return raw


def _parse_json(raw: bytes, *, label: str) -> Any:
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise AuxiliaryWritableRootStartupError(
            f"{label} is not strict UTF-8 JSON"
        ) from exc
    _preflight_json_depth(text)
    try:
        value = json.loads(
            text,
            object_pairs_hook=_strict_object_pairs,
            parse_constant=_reject_json_constant,
            parse_int=_bounded_json_integer,
            parse_float=_bounded_json_float,
        )
    except AuxiliaryWritableRootStartupError:
        raise
    except (json.JSONDecodeError, RecursionError, ValueError, OverflowError) as exc:
        raise AuxiliaryWritableRootStartupError(
            f"{label} is not strict JSON"
        ) from exc
    _validate_json_limits(value)
    return value


def canonical_startup_bytes(value: Mapping[str, Any]) -> bytes:
    """Return the canonical persisted encoding for a startup record."""

    return _canonical_json(value)


def digest_startup_payload(value: Mapping[str, Any]) -> str:
    """Digest a record core using the public canonical encoding."""

    return hashlib.sha256(_canonical_json(value)).hexdigest()


def _canonical_run_id(value: Any) -> str:
    if not isinstance(value, str) or _RUN_ID_RE.fullmatch(value) is None:
        raise AuxiliaryWritableRootStartupError(
            "startup run_id must be a canonical UUIDv4"
        )
    return value


def _canonical_epoch(value: Any) -> str:
    if not isinstance(value, str) or _EPOCH_RE.fullmatch(value) is None:
        raise AuxiliaryWritableRootStartupError(
            "startup epoch must be 32 lowercase hexadecimal characters"
        )
    return value


def _canonical_sha256(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise AuxiliaryWritableRootStartupError(
            f"{label} must be a lowercase SHA-256 digest"
        )
    return value


def _clone_json(value: Any) -> Any:
    raw = _canonical_json({"value": value})
    parsed = _parse_json(raw, label="startup value")
    try:
        return parsed["value"]
    except (KeyError, TypeError) as exc:
        raise AuxiliaryWritableRootStartupError(
            "startup value is not strict JSON"
        ) from exc


def _runtime_debt(value: Any) -> dict[str, Any]:
    if (
        not isinstance(value, Mapping)
        or set(value) != {"required", "category", "reason"}
        or not isinstance(value.get("required"), bool)
    ):
        raise AuxiliaryWritableRootStartupError(
            "startup receipt runtime debt is malformed"
        )
    required = bool(value["required"])
    category = value.get("category")
    reason = value.get("reason")
    if required:
        if (
            not isinstance(category, str)
            or not category
            or category != category.strip()
            or "\x00" in category
            or not isinstance(reason, str)
            or not reason
            or reason != reason.strip()
            or "\x00" in reason
        ):
            raise AuxiliaryWritableRootStartupError(
                "startup receipt required debt lacks canonical detail"
            )
    elif category is not None or reason is not None:
        raise AuxiliaryWritableRootStartupError(
            "startup receipt clean debt has non-null detail"
        )
    return {
        "required": required,
        "category": category,
        "reason": reason,
    }


def _sanitized_exception_type(exc: BaseException) -> str:
    candidate = type(exc).__name__
    if _EXCEPTION_TYPE_RE.fullmatch(candidate) is None:
        return "Exception"
    return candidate


def compile_startup_receipt(
    *,
    run_id: str,
    startup_epoch: str,
    reconciliation: Mapping[str, Any] | None = None,
    failure_type: str | None = None,
) -> dict[str, Any]:
    """Compile one deterministic receipt from a report or sanitized failure."""

    run = _canonical_run_id(run_id)
    epoch = _canonical_epoch(startup_epoch)
    if (reconciliation is None) == (failure_type is None):
        raise AuxiliaryWritableRootStartupError(
            "startup receipt requires exactly one reconciliation outcome"
        )
    if reconciliation is not None:
        report = _clone_json(reconciliation)
        replay = replay_auxiliary_writable_root_reconciliation(report)
        if replay.get("valid") is not True:
            raise AuxiliaryWritableRootStartupError(
                "auxiliary-root reconciliation did not replay"
            )
        disposition = replay.get("allocation_disposition")
        debt = _runtime_debt(replay.get("runtime_debt"))
        failure: dict[str, str] | None = None
    else:
        if (
            not isinstance(failure_type, str)
            or _EXCEPTION_TYPE_RE.fullmatch(failure_type) is None
        ):
            raise AuxiliaryWritableRootStartupError(
                "startup reconciliation exception type is invalid"
            )
        report = None
        disposition = "DENY_NEW_LEASES"
        debt = {
            "required": True,
            "category": "AUXILIARY_ROOT_RECONCILIATION_UNPROVEN",
            "reason": "RECONCILIATION_EXCEPTION",
        }
        failure = {
            "category": "AUXILIARY_ROOT_RECONCILIATION_UNPROVEN",
            "exception_type": failure_type,
            "reason": "RECONCILIATION_EXCEPTION",
        }
    if disposition not in _DISPOSITIONS:
        raise AuxiliaryWritableRootStartupError(
            "startup receipt allocation disposition is invalid"
        )
    if debt["required"] is not (disposition != "ALLOW_NEW_LEASES"):
        raise AuxiliaryWritableRootStartupError(
            "startup receipt disposition/debt linkage is invalid"
        )
    core = {
        "schema": STARTUP_RECEIPT_SCHEMA,
        "run_id": run,
        "startup_epoch": epoch,
        "reconciliation": report,
        "failure": failure,
        "allocation_disposition": disposition,
        "runtime_debt": debt,
    }
    receipt = {
        **core,
        "receipt_sha256": digest_startup_payload(core),
    }
    if len(canonical_startup_bytes(receipt)) > MAX_STARTUP_RECEIPT_BYTES:
        raise AuxiliaryWritableRootStartupError(
            "startup receipt exceeds its byte bound"
        )
    return receipt


def replay_startup_receipt(value: Mapping[str, Any]) -> dict[str, Any]:
    """Replay digest, epoch, nested reconciliation, and decision semantics."""

    try:
        receipt = _clone_json(value)
        expected_fields = {
            "schema",
            "run_id",
            "startup_epoch",
            "reconciliation",
            "failure",
            "allocation_disposition",
            "runtime_debt",
            "receipt_sha256",
        }
        if not isinstance(receipt, dict) or set(receipt) != expected_fields:
            raise AuxiliaryWritableRootStartupError(
                "startup receipt fields are invalid"
            )
        digest = receipt.pop("receipt_sha256")
        if (
            _canonical_sha256(digest, label="startup receipt digest")
            != digest_startup_payload(receipt)
        ):
            raise AuxiliaryWritableRootStartupError(
                "startup receipt digest mismatched"
            )
        if receipt.get("schema") != STARTUP_RECEIPT_SCHEMA:
            raise AuxiliaryWritableRootStartupError(
                "startup receipt schema is unsupported"
            )
        run_id = _canonical_run_id(receipt.get("run_id"))
        epoch = _canonical_epoch(receipt.get("startup_epoch"))
        disposition = receipt.get("allocation_disposition")
        if disposition not in _DISPOSITIONS:
            raise AuxiliaryWritableRootStartupError(
                "startup receipt disposition is invalid"
            )
        debt = _runtime_debt(receipt.get("runtime_debt"))
        report = receipt.get("reconciliation")
        failure = receipt.get("failure")
        if report is not None:
            if failure is not None:
                raise AuxiliaryWritableRootStartupError(
                    "startup receipt has two outcomes"
                )
            report_replay = replay_auxiliary_writable_root_reconciliation(
                report
            )
            if (
                report_replay.get("valid") is not True
                or report_replay.get("allocation_disposition") != disposition
                or report_replay.get("runtime_debt") != debt
            ):
                raise AuxiliaryWritableRootStartupError(
                    "startup receipt reconciliation semantics drifted"
                )
        else:
            if (
                not isinstance(failure, dict)
                or set(failure)
                != {"category", "exception_type", "reason"}
                or failure.get("category")
                != "AUXILIARY_ROOT_RECONCILIATION_UNPROVEN"
                or failure.get("reason") != "RECONCILIATION_EXCEPTION"
                or not isinstance(failure.get("exception_type"), str)
                or _EXCEPTION_TYPE_RE.fullmatch(
                    failure["exception_type"]
                )
                is None
                or disposition != "DENY_NEW_LEASES"
                or debt
                != {
                    "required": True,
                    "category": (
                        "AUXILIARY_ROOT_RECONCILIATION_UNPROVEN"
                    ),
                    "reason": "RECONCILIATION_EXCEPTION",
                }
            ):
                raise AuxiliaryWritableRootStartupError(
                    "startup receipt failure semantics are invalid"
                )
        if debt["required"] is not (disposition != "ALLOW_NEW_LEASES"):
            raise AuxiliaryWritableRootStartupError(
                "startup receipt disposition/debt semantics drifted"
            )
        return {
            "valid": True,
            "reason": "STARTUP_RECEIPT_REPLAYED",
            "receipt_sha256": digest,
            "run_id": run_id,
            "startup_epoch": epoch,
            "allocation_disposition": disposition,
            "allocation_permitted": disposition in _PERMIT_DISPOSITIONS,
            "runtime_debt": debt,
        }
    except (
        AuxiliaryWritableRootStartupError,
        KeyError,
        TypeError,
        ValueError,
        OverflowError,
        RecursionError,
    ):
        return {
            "valid": False,
            "reason": "STARTUP_RECEIPT_REPLAY_FAILED",
        }


def _is_alias(row: os.stat_result) -> bool:
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return stat.S_ISLNK(row.st_mode) or bool(
        reparse and int(getattr(row, "st_file_attributes", 0)) & reparse
    )


def _identity(row: os.stat_result) -> tuple[int, int, int]:
    return (
        int(getattr(row, "st_dev", 0)),
        int(getattr(row, "st_ino", 0)),
        int(stat.S_IFMT(row.st_mode)),
    )


def _safe_scratchpad(path: Path) -> Path:
    requested = Path(path)
    try:
        row = _lstat(requested)
    except OSError as exc:
        raise AuxiliaryWritableRootStartupError(
            "startup scratchpad is unavailable"
        ) from exc
    if _is_alias(row) or not stat.S_ISDIR(row.st_mode):
        raise AuxiliaryWritableRootStartupError(
            "startup scratchpad is an alias or not a directory"
        )
    try:
        resolved = requested.resolve(strict=True)
    except OSError as exc:
        raise AuxiliaryWritableRootStartupError(
            "startup scratchpad resolution failed"
        ) from exc
    if os.path.normcase(str(resolved)) != os.path.normcase(
        str(requested.absolute())
    ):
        raise AuxiliaryWritableRootStartupError(
            "startup scratchpad has an alias ancestor"
        )
    return resolved


def _safe_child_directory(
    root: Path,
    name: str,
    *,
    create: bool,
) -> Path:
    path = root / name
    if path.parent != root:
        raise AuxiliaryWritableRootStartupError(
            "startup child directory escaped the scratchpad"
        )
    if create:
        try:
            os.mkdir(_native_path(path), 0o700)
        except FileExistsError:
            pass
        except OSError as exc:
            raise AuxiliaryWritableRootStartupError(
                "startup child directory creation failed"
            ) from exc
    try:
        row = _lstat(path)
    except OSError as exc:
        raise AuxiliaryWritableRootStartupError(
            "startup child directory is unavailable"
        ) from exc
    if _is_alias(row) or not stat.S_ISDIR(row.st_mode):
        raise AuxiliaryWritableRootStartupError(
            "startup child directory is an alias or not a directory"
        )
    if os.name == "nt":
        # The row itself is not a reparse point and ``root`` was already
        # resolved/checked. ``Path.resolve`` re-enters the legacy MAX_PATH
        # API for a long direct child on supported Python/Windows builds.
        return path.absolute()
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise AuxiliaryWritableRootStartupError(
            "startup child directory resolution failed"
        ) from exc
    if resolved.parent != root or resolved.name != name:
        raise AuxiliaryWritableRootStartupError(
            "startup child directory identity drifted"
        )
    return resolved


def _read_regular_file_bounded(
    path: Path,
    *,
    label: str,
    maximum_bytes: int,
) -> bytes:
    try:
        path_row = _lstat(path)
    except OSError as exc:
        raise AuxiliaryWritableRootStartupError(
            f"{label} is unavailable"
        ) from exc
    if (
        _is_alias(path_row)
        or not stat.S_ISREG(path_row.st_mode)
        or int(getattr(path_row, "st_nlink", 1)) != 1
    ):
        raise AuxiliaryWritableRootStartupError(
            f"{label} is an alias or not a single-link regular file"
        )
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    try:
        descriptor = os.open(_native_path(path), flags)
        before = os.fstat(descriptor)
        if (
            _is_alias(before)
            or not stat.S_ISREG(before.st_mode)
            or int(getattr(before, "st_nlink", 1)) != 1
            or _identity(before) != _identity(path_row)
        ):
            raise AuxiliaryWritableRootStartupError(
                f"{label} identity changed before no-follow open"
            )
        expected_size = int(before.st_size)
        if expected_size <= 0 or expected_size > maximum_bytes:
            raise AuxiliaryWritableRootStartupError(
                f"{label} size is invalid"
            )
        chunks: list[bytes] = []
        observed = 0
        while True:
            chunk = os.read(descriptor, min(64 * 1024, maximum_bytes + 1))
            if not chunk:
                break
            chunks.append(chunk)
            observed += len(chunk)
            if observed > maximum_bytes:
                raise AuxiliaryWritableRootStartupError(
                    f"{label} exceeded its byte bound"
                )
        after = os.fstat(descriptor)
        if (
            _identity(before) != _identity(after)
            or int(getattr(after, "st_nlink", 1)) != 1
            or int(after.st_size) != expected_size
            or observed != expected_size
        ):
            raise AuxiliaryWritableRootStartupError(
                f"{label} changed during no-follow read"
            )
        try:
            final_path_row = _lstat(path)
        except OSError as exc:
            raise AuxiliaryWritableRootStartupError(
                f"{label} path disappeared during read"
            ) from exc
        if (
            _is_alias(final_path_row)
            or int(getattr(final_path_row, "st_nlink", 1)) != 1
            or _identity(final_path_row) != _identity(after)
        ):
            raise AuxiliaryWritableRootStartupError(
                f"{label} path identity changed during read"
            )
        return b"".join(chunks)
    except AuxiliaryWritableRootStartupError:
        raise
    except OSError as exc:
        raise AuxiliaryWritableRootStartupError(
            f"{label} read failed"
        ) from exc
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _write_all(descriptor: int, raw: bytes) -> None:
    offset = 0
    while offset < len(raw):
        try:
            written = os.write(descriptor, raw[offset:])
        except OSError as exc:
            raise AuxiliaryWritableRootStartupError(
                "startup record write failed"
            ) from exc
        if written <= 0:
            raise AuxiliaryWritableRootStartupError(
                "startup record write was truncated"
            )
        offset += written


def _publish_windows(
    source: Path,
    destination: Path,
    *,
    replace: bool,
) -> None:
    from ctypes import wintypes

    move = ctypes.WinDLL("kernel32", use_last_error=True).MoveFileExW
    move.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD]
    move.restype = wintypes.BOOL
    flags = 0x00000008  # MOVEFILE_WRITE_THROUGH
    if replace:
        flags |= 0x00000001  # MOVEFILE_REPLACE_EXISTING
    if not move(
        _windows_extended_path(source),
        _windows_extended_path(destination),
        flags,
    ):
        code = ctypes.get_last_error()
        if not replace and code in {80, 183}:  # ERROR_FILE_EXISTS/ALREADY_EXISTS
            raise FileExistsError(str(destination))
        raise AuxiliaryWritableRootStartupError(
            f"startup Windows write-through publication failed: {code}"
        )


def _sync_directory(directory: Path) -> None:
    if os.name == "nt":
        # Publication uses MoveFileExW(MOVEFILE_WRITE_THROUGH).  CPython does
        # not provide a portable directory handle with FlushFileBuffers.
        return
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    try:
        descriptor = os.open(_native_path(directory), flags)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except OSError as exc:
        raise AuxiliaryWritableRootStartupError(
            "startup directory fsync is unsupported or failed; durability "
            "cannot be claimed on this filesystem"
        ) from exc


def _temporary_path(directory: Path, label: str) -> Path:
    return directory / (
        f".aux-root-startup-{label}-{secrets.token_hex(16)}.tmp"
    )


def _write_temporary(directory: Path, label: str, raw: bytes) -> Path:
    temporary = _temporary_path(directory, label)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    try:
        descriptor = os.open(_native_path(temporary), flags, 0o600)
        _write_all(descriptor, raw)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        if (
            _read_regular_file_bounded(
                temporary,
                label="startup temporary record",
                maximum_bytes=max(
                    MAX_STARTUP_RECEIPT_BYTES,
                    MAX_STARTUP_POINTER_BYTES,
                ),
            )
            != raw
        ):
            raise AuxiliaryWritableRootStartupError(
                "startup temporary record readback mismatched"
            )
        return temporary
    except BaseException:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        try:
            _unlink_if_present(temporary)
        except OSError:
            pass
        raise


def _replace_record(path: Path, raw: bytes) -> None:
    temporary = _write_temporary(path.parent, "current", raw)
    try:
        if os.name == "nt":
            _publish_windows(temporary, path, replace=True)
        else:
            os.replace(temporary, path)
            _sync_directory(path.parent)
    except OSError as exc:
        raise AuxiliaryWritableRootStartupError(
            "startup current-pointer atomic replacement failed"
        ) from exc
    finally:
        try:
            _unlink_if_present(temporary)
        except OSError:
            pass


def _publish_absent_record(path: Path, raw: bytes) -> None:
    temporary = _write_temporary(path.parent, "receipt", raw)
    try:
        if os.name == "nt":
            _publish_windows(temporary, path, replace=False)
        else:
            os.link(temporary, path, follow_symlinks=False)
            os.unlink(temporary)
            _sync_directory(path.parent)
    except FileExistsError as exc:
        raise AuxiliaryWritableRootStartupError(
            "startup immutable receipt already exists"
        ) from exc
    except OSError as exc:
        raise AuxiliaryWritableRootStartupError(
            "startup immutable receipt publication failed"
        ) from exc
    finally:
        try:
            _unlink_if_present(temporary)
        except OSError:
            pass


def _open_startup_lock(root: Path) -> tuple[int, Path, tuple[int, int, int]]:
    path = root / STARTUP_LOCK_NAME
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    try:
        descriptor = os.open(_native_path(path), flags, 0o600)
        row = os.fstat(descriptor)
        if (
            _is_alias(row)
            or not stat.S_ISREG(row.st_mode)
            or int(getattr(row, "st_nlink", 1)) != 1
        ):
            raise AuxiliaryWritableRootStartupError(
                "startup lock is an alias or not a single-link file"
            )
        if int(row.st_size) == 0:
            _write_all(descriptor, b"0")
            os.fsync(descriptor)
        os.lseek(descriptor, 0, os.SEEK_SET)
        path_row = _lstat(path)
        if (
            _is_alias(path_row)
            or int(getattr(path_row, "st_nlink", 1)) != 1
            or _identity(path_row) != _identity(os.fstat(descriptor))
        ):
            raise AuxiliaryWritableRootStartupError(
                "startup lock identity drifted"
            )
        return descriptor, path, _identity(path_row)
    except BaseException:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        raise


def _try_lock_descriptor(descriptor: int) -> bool:
    try:
        if os.name == "nt":
            import msvcrt

            os.lseek(descriptor, 0, os.SEEK_SET)
            msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
        else:
            import fcntl

            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return True
    except (OSError, BlockingIOError):
        return False


def _unlock_descriptor(descriptor: int) -> None:
    if os.name == "nt":
        import msvcrt

        os.lseek(descriptor, 0, os.SEEK_SET)
        msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
    else:
        import fcntl

        fcntl.flock(descriptor, fcntl.LOCK_UN)


@contextmanager
def _startup_guard(root: Path) -> Iterator[None]:
    descriptor, path, identity = _open_startup_lock(root)
    acquired = False
    deadline = time.monotonic() + STARTUP_LOCK_TIMEOUT_SECONDS
    try:
        while not acquired:
            acquired = _try_lock_descriptor(descriptor)
            if acquired:
                break
            if time.monotonic() >= deadline:
                raise AuxiliaryWritableRootStartupError(
                    "startup advisory lock timed out"
                )
            time.sleep(0.025)
        row = _lstat(path)
        if (
            _is_alias(row)
            or int(getattr(row, "st_nlink", 1)) != 1
            or _identity(row) != identity
        ):
            raise AuxiliaryWritableRootStartupError(
                "startup advisory lock changed after acquisition"
            )
        yield
    finally:
        if acquired:
            try:
                _unlock_descriptor(descriptor)
            except OSError:
                pass
        os.close(descriptor)


def _pointer_record(
    *,
    run_id: str,
    startup_epoch: str,
    state: str,
    reconciling_pointer_sha256: str | None,
    receipt_relative_path: str | None,
    receipt_sha256: str | None,
    allocation_disposition: str | None,
) -> dict[str, Any]:
    core = {
        "schema": STARTUP_CURRENT_SCHEMA,
        "run_id": _canonical_run_id(run_id),
        "startup_epoch": _canonical_epoch(startup_epoch),
        "state": state,
        "reconciling_pointer_sha256": reconciling_pointer_sha256,
        "receipt_relative_path": receipt_relative_path,
        "receipt_sha256": receipt_sha256,
        "allocation_disposition": allocation_disposition,
    }
    return {**core, "pointer_sha256": digest_startup_payload(core)}


def _replay_pointer(value: Mapping[str, Any]) -> dict[str, Any]:
    row = _clone_json(value)
    expected = {
        "schema",
        "run_id",
        "startup_epoch",
        "state",
        "reconciling_pointer_sha256",
        "receipt_relative_path",
        "receipt_sha256",
        "allocation_disposition",
        "pointer_sha256",
    }
    if not isinstance(row, dict) or set(row) != expected:
        raise AuxiliaryWritableRootStartupError(
            "startup current pointer fields are invalid"
        )
    digest = row.pop("pointer_sha256")
    if (
        _canonical_sha256(digest, label="startup current pointer digest")
        != digest_startup_payload(row)
    ):
        raise AuxiliaryWritableRootStartupError(
            "startup current pointer digest mismatched"
        )
    if row.get("schema") != STARTUP_CURRENT_SCHEMA:
        raise AuxiliaryWritableRootStartupError(
            "startup current pointer schema is unsupported"
        )
    run_id = _canonical_run_id(row.get("run_id"))
    epoch = _canonical_epoch(row.get("startup_epoch"))
    state = row.get("state")
    if state == "RECONCILING":
        if any(
            row.get(field) is not None
            for field in (
                "reconciling_pointer_sha256",
                "receipt_relative_path",
                "receipt_sha256",
                "allocation_disposition",
            )
        ):
            raise AuxiliaryWritableRootStartupError(
                "startup RECONCILING pointer carries authority"
            )
    elif state == "COMPLETE":
        reconciling = _canonical_sha256(
            row.get("reconciling_pointer_sha256"),
            label="startup reconciling pointer digest",
        )
        receipt_digest = _canonical_sha256(
            row.get("receipt_sha256"),
            label="startup pointer receipt digest",
        )
        disposition = row.get("allocation_disposition")
        relative = row.get("receipt_relative_path")
        expected_relative = _receipt_relative_path(epoch, receipt_digest)
        if (
            not isinstance(relative, str)
            or relative != expected_relative
            or disposition not in _DISPOSITIONS
        ):
            raise AuxiliaryWritableRootStartupError(
                "startup COMPLETE pointer authority is malformed"
            )
        row["reconciling_pointer_sha256"] = reconciling
        row["receipt_sha256"] = receipt_digest
    else:
        raise AuxiliaryWritableRootStartupError(
            "startup current pointer state is invalid"
        )
    return {
        **row,
        "run_id": run_id,
        "startup_epoch": epoch,
        "pointer_sha256": digest,
    }


def _receipt_relative_path(epoch: str, digest: str) -> str:
    _canonical_epoch(epoch)
    _canonical_sha256(digest, label="startup receipt digest")
    return (
        f"{STARTUP_RECEIPT_DIRECTORY_NAME}/"
        f"startup-{epoch}-{digest}.json"
    )


def _read_pointer_locked(root: Path) -> tuple[dict[str, Any], bytes]:
    path = root / STARTUP_CURRENT_NAME
    raw = _read_regular_file_bounded(
        path,
        label="startup current pointer",
        maximum_bytes=MAX_STARTUP_POINTER_BYTES,
    )
    value = _parse_json(raw, label="startup current pointer")
    if not isinstance(value, dict) or canonical_startup_bytes(value) != raw:
        raise AuxiliaryWritableRootStartupError(
            "startup current pointer encoding is not canonical"
        )
    return _replay_pointer(value), raw


def _publish_reconciling_pointer(
    root: Path,
    *,
    run_id: str,
    startup_epoch: str,
) -> dict[str, Any]:
    pointer = _pointer_record(
        run_id=run_id,
        startup_epoch=startup_epoch,
        state="RECONCILING",
        reconciling_pointer_sha256=None,
        receipt_relative_path=None,
        receipt_sha256=None,
        allocation_disposition=None,
    )
    raw = canonical_startup_bytes(pointer)
    if len(raw) > MAX_STARTUP_POINTER_BYTES:
        raise AuxiliaryWritableRootStartupError(
            "startup current pointer exceeds its byte bound"
        )
    _replace_record(root / STARTUP_CURRENT_NAME, raw)
    replayed, observed = _read_pointer_locked(root)
    if observed != raw or replayed != pointer:
        raise AuxiliaryWritableRootStartupError(
            "startup RECONCILING pointer did not replay exactly"
        )
    return pointer


def _receipt_path(root: Path, receipt: Mapping[str, Any]) -> Path:
    replay = replay_startup_receipt(receipt)
    if replay.get("valid") is not True:
        raise AuxiliaryWritableRootStartupError(
            "startup receipt does not replay"
        )
    directory = _safe_child_directory(
        root,
        STARTUP_RECEIPT_DIRECTORY_NAME,
        create=True,
    )
    name = (
        f"startup-{replay['startup_epoch']}-"
        f"{replay['receipt_sha256']}.json"
    )
    if _RECEIPT_NAME_RE.fullmatch(name) is None:
        raise AuxiliaryWritableRootStartupError(
            "startup immutable receipt filename is invalid"
        )
    path = directory / name
    if path.parent != directory:
        raise AuxiliaryWritableRootStartupError(
            "startup immutable receipt escaped its directory"
        )
    return path


def _publish_immutable_receipt(
    root: Path,
    receipt: Mapping[str, Any],
) -> Path:
    path = _receipt_path(root, receipt)
    replay = replay_startup_receipt(receipt)
    assert replay.get("valid") is True
    try:
        with os.scandir(_native_path(path.parent)) as stream:
            entries = [Path(entry.path) for entry in stream]
    except OSError as exc:
        raise AuxiliaryWritableRootStartupError(
            "startup immutable receipt inventory failed"
        ) from exc
    if len(entries) > MAX_IMMUTABLE_RECEIPTS:
        raise AuxiliaryWritableRootStartupError(
            "startup immutable receipt inventory bound exceeded"
        )
    for entry in entries:
        matched = _RECEIPT_NAME_RE.fullmatch(entry.name)
        if (
            matched is not None
            and matched.group(1) == replay["startup_epoch"]
            and entry.name != path.name
        ):
            raise AuxiliaryWritableRootStartupError(
                "startup epoch already has a different immutable receipt"
            )
    raw = canonical_startup_bytes(receipt)
    if len(raw) > MAX_STARTUP_RECEIPT_BYTES:
        raise AuxiliaryWritableRootStartupError(
            "startup receipt exceeds its byte bound"
        )
    if _lexists(path):
        observed = _read_regular_file_bounded(
            path,
            label="startup immutable receipt",
            maximum_bytes=MAX_STARTUP_RECEIPT_BYTES,
        )
        if observed != raw:
            raise AuxiliaryWritableRootStartupError(
                "startup immutable receipt already exists with different bytes"
            )
        return path
    _publish_absent_record(path, raw)
    observed = _read_regular_file_bounded(
        path,
        label="startup immutable receipt",
        maximum_bytes=MAX_STARTUP_RECEIPT_BYTES,
    )
    if observed != raw:
        raise AuxiliaryWritableRootStartupError(
            "startup immutable receipt readback mismatched"
        )
    return path


def _invalidate_complete_after_failure(
    root: Path,
    reconciling_pointer: Mapping[str, Any],
    complete_raw: bytes,
) -> None:
    """Best-effort rollback for the ambiguous post-replace fsync window."""

    try:
        _, current_raw = _read_pointer_locked(root)
        if current_raw != complete_raw:
            return
        _replace_record(
            root / STARTUP_CURRENT_NAME,
            canonical_startup_bytes(reconciling_pointer),
        )
    except BaseException:
        # The original operation already fails closed for the cooperative
        # caller.  Filesystems that violate/lose both atomic replacements are
        # outside the durability contract documented at module scope.
        pass


def _cas_complete_pointer(
    root: Path,
    *,
    reconciling_pointer: Mapping[str, Any],
    receipt: Mapping[str, Any],
    receipt_path: Path,
) -> dict[str, Any]:
    observed, observed_raw = _read_pointer_locked(root)
    expected_raw = canonical_startup_bytes(reconciling_pointer)
    if (
        observed_raw != expected_raw
        or observed.get("state") != "RECONCILING"
    ):
        raise AuxiliaryWritableRootStartupError(
            "startup COMPLETE pointer CAS predecessor mismatched"
        )
    replay = replay_startup_receipt(receipt)
    if replay.get("valid") is not True:
        raise AuxiliaryWritableRootStartupError(
            "startup COMPLETE pointer receipt did not replay"
        )
    receipt_raw = _read_regular_file_bounded(
        receipt_path,
        label="startup immutable receipt",
        maximum_bytes=MAX_STARTUP_RECEIPT_BYTES,
    )
    parsed_receipt = _parse_json(
        receipt_raw,
        label="startup immutable receipt",
    )
    if (
        not isinstance(parsed_receipt, dict)
        or canonical_startup_bytes(parsed_receipt) != receipt_raw
        or parsed_receipt != receipt
        or replay_startup_receipt(parsed_receipt).get("valid") is not True
    ):
        raise AuxiliaryWritableRootStartupError(
            "startup COMPLETE pointer receipt bytes did not replay exactly"
        )
    relative = receipt_path.relative_to(root).as_posix()
    complete = _pointer_record(
        run_id=replay["run_id"],
        startup_epoch=replay["startup_epoch"],
        state="COMPLETE",
        reconciling_pointer_sha256=observed["pointer_sha256"],
        receipt_relative_path=relative,
        receipt_sha256=replay["receipt_sha256"],
        allocation_disposition=replay["allocation_disposition"],
    )
    complete_raw = canonical_startup_bytes(complete)
    try:
        # Re-read immediately before replacement: this is the byte-exact CAS
        # check. The advisory lock serializes cooperative writers.
        _, final_predecessor = _read_pointer_locked(root)
        if final_predecessor != expected_raw:
            raise AuxiliaryWritableRootStartupError(
                "startup COMPLETE pointer CAS lost its predecessor"
            )
        _replace_record(root / STARTUP_CURRENT_NAME, complete_raw)
        replayed, final_raw = _read_pointer_locked(root)
        if final_raw != complete_raw or replayed != complete:
            raise AuxiliaryWritableRootStartupError(
                "startup COMPLETE pointer did not replay exactly"
            )
    except BaseException:
        _invalidate_complete_after_failure(
            root,
            reconciling_pointer,
            complete_raw,
        )
        raise
    return complete


def _abandoned_candidates(directory: Path) -> list[Path]:
    try:
        with os.scandir(_native_path(directory)) as stream:
            entries = [Path(entry.path) for entry in stream]
    except OSError as exc:
        raise AuxiliaryWritableRootStartupError(
            "startup abandoned-temporary inventory failed"
        ) from exc
    candidates = [
        entry
        for entry in entries
        if entry.name.startswith(".aux-root-startup-")
        and entry.name.endswith(".tmp")
    ]
    if len(candidates) > MAX_ABANDONED_TEMPORARIES:
        raise AuxiliaryWritableRootStartupError(
            "startup abandoned-temporary bound exceeded"
        )
    return sorted(candidates, key=lambda item: item.name.casefold())


def _cleanup_abandoned_temporaries(root: Path) -> None:
    directories = [root]
    receipt_directory = root / STARTUP_RECEIPT_DIRECTORY_NAME
    if _lexists(receipt_directory):
        directories.append(
            _safe_child_directory(
                root,
                STARTUP_RECEIPT_DIRECTORY_NAME,
                create=False,
            )
        )
    quarantine: Path | None = None
    touched_directories: set[Path] = set()
    total = 0
    for directory in directories:
        for candidate in _abandoned_candidates(directory):
            total += 1
            if total > MAX_ABANDONED_TEMPORARIES:
                raise AuxiliaryWritableRootStartupError(
                    "startup abandoned-temporary total bound exceeded"
                )
            try:
                row = _lstat(candidate)
            except OSError:
                continue
            if (
                not _is_alias(row)
                and stat.S_ISREG(row.st_mode)
                and int(getattr(row, "st_nlink", 1)) == 1
            ):
                try:
                    os.unlink(_native_path(candidate))
                except OSError as exc:
                    raise AuxiliaryWritableRootStartupError(
                        "startup abandoned temporary cleanup failed"
                    ) from exc
                touched_directories.add(directory)
                continue
            if quarantine is None:
                quarantine = _safe_child_directory(
                    root,
                    STARTUP_QUARANTINE_DIRECTORY_NAME,
                    create=True,
                )
            destination = quarantine / (
                f"abandoned-{secrets.token_hex(16)}-{candidate.name[1:]}"
            )
            try:
                os.replace(
                    _native_path(candidate),
                    _native_path(destination),
                )
            except OSError as exc:
                raise AuxiliaryWritableRootStartupError(
                    "startup unsafe temporary quarantine failed"
                ) from exc
            touched_directories.add(directory)
            touched_directories.add(quarantine)
    if total:
        touched_directories.add(root)
        for directory in sorted(
            touched_directories,
            key=lambda item: os.path.normcase(str(item)),
        ):
            _sync_directory(directory)


def _complete_receipt_locked(
    root: Path,
    *,
    reconciling_pointer: Mapping[str, Any],
    receipt: Mapping[str, Any],
) -> Path:
    receipt_path = _publish_immutable_receipt(root, receipt)
    _cas_complete_pointer(
        root,
        reconciling_pointer=reconciling_pointer,
        receipt=receipt,
        receipt_path=receipt_path,
    )
    return receipt_path


def _load_current_locked(
    root: Path,
    *,
    expected_run_id: str,
    expected_startup_epoch: str,
) -> dict[str, Any]:
    run_id = _canonical_run_id(expected_run_id)
    epoch = _canonical_epoch(expected_startup_epoch)
    pointer, _ = _read_pointer_locked(root)
    if pointer.get("state") != "COMPLETE":
        raise AuxiliaryWritableRootStartupError(
            "startup current pointer is not COMPLETE"
        )
    if pointer.get("run_id") != run_id:
        raise AuxiliaryWritableRootStartupError(
            "startup current pointer run authority mismatched"
        )
    if pointer.get("startup_epoch") != epoch:
        raise AuxiliaryWritableRootStartupError(
            "startup current pointer epoch authority mismatched"
        )
    receipt_directory = _safe_child_directory(
        root,
        STARTUP_RECEIPT_DIRECTORY_NAME,
        create=False,
    )
    relative = pointer["receipt_relative_path"]
    receipt_path = root / Path(relative)
    if (
        receipt_path.parent != receipt_directory
        or receipt_path.name
        != (
            f"startup-{epoch}-{pointer['receipt_sha256']}.json"
        )
    ):
        raise AuxiliaryWritableRootStartupError(
            "startup receipt path authority mismatched"
        )
    raw = _read_regular_file_bounded(
        receipt_path,
        label="startup immutable receipt",
        maximum_bytes=MAX_STARTUP_RECEIPT_BYTES,
    )
    receipt = _parse_json(raw, label="startup immutable receipt")
    if (
        not isinstance(receipt, dict)
        or canonical_startup_bytes(receipt) != raw
    ):
        raise AuxiliaryWritableRootStartupError(
            "startup receipt encoding is not canonical"
        )
    replay = replay_startup_receipt(receipt)
    if (
        replay.get("valid") is not True
        or replay.get("run_id") != run_id
        or replay.get("startup_epoch") != epoch
        or replay.get("receipt_sha256") != pointer["receipt_sha256"]
        or replay.get("allocation_disposition")
        != pointer["allocation_disposition"]
    ):
        raise AuxiliaryWritableRootStartupError(
            "startup receipt/current-pointer semantics mismatched"
        )
    binding: dict[str, Any] | None = None
    if replay["allocation_permitted"] is True:
        binding = {
            "schema": STARTUP_BINDING_SCHEMA,
            "run_id": run_id,
            "startup_epoch": epoch,
            "current_pointer_sha256": pointer["pointer_sha256"],
            "receipt_relative_path": relative,
            "receipt_sha256": replay["receipt_sha256"],
            "allocation_disposition": replay["allocation_disposition"],
        }
    return {
        **replay,
        "receipt": receipt,
        "receipt_relative_path": relative,
        "current_pointer": pointer,
        "current_pointer_sha256": pointer["pointer_sha256"],
        "binding": binding,
    }


def persist_startup_receipt(
    *,
    scratchpad: Path,
    receipt: Mapping[str, Any],
) -> Path:
    """Publish one receipt through RECONCILING -> immutable -> COMPLETE."""

    replay = replay_startup_receipt(receipt)
    if replay.get("valid") is not True:
        raise AuxiliaryWritableRootStartupError(
            "refusing to persist an invalid startup receipt"
        )
    root = _safe_scratchpad(Path(scratchpad))
    with _startup_guard(root):
        # Exact retries after a returned success are idempotent. They neither
        # replace the immutable receipt nor manufacture a new epoch.
        try:
            current = _load_current_locked(
                root,
                expected_run_id=replay["run_id"],
                expected_startup_epoch=replay["startup_epoch"],
            )
        except AuxiliaryWritableRootStartupError:
            current = None
        if (
            current is not None
            and current["receipt"] == receipt
            and current["receipt_sha256"] == replay["receipt_sha256"]
        ):
            return root / current["receipt_relative_path"]
        reconciling = _publish_reconciling_pointer(
            root,
            run_id=replay["run_id"],
            startup_epoch=replay["startup_epoch"],
        )
        _cleanup_abandoned_temporaries(root)
        return _complete_receipt_locked(
            root,
            reconciling_pointer=reconciling,
            receipt=receipt,
        )


def reconcile_and_persist_startup_receipt(
    *,
    scratchpad: Path,
    run_id: str,
) -> dict[str, Any]:
    """Invalidate old authority, reconcile, and durably publish one outcome."""

    run = _canonical_run_id(run_id)
    epoch = _canonical_epoch(uuid.uuid4().hex)
    root = _safe_scratchpad(Path(scratchpad))
    with _startup_guard(root):
        reconciling = _publish_reconciling_pointer(
            root,
            run_id=run,
            startup_epoch=epoch,
        )
        _cleanup_abandoned_temporaries(root)
        try:
            report = reconcile_auxiliary_writable_root_leases()
            receipt = compile_startup_receipt(
                run_id=run,
                startup_epoch=epoch,
                reconciliation=report,
            )
        except Exception as exc:
            # Persist no host path/message.  A malformed provider result and a
            # provider exception share the same conservative DENY semantics.
            receipt = compile_startup_receipt(
                run_id=run,
                startup_epoch=epoch,
                failure_type=_sanitized_exception_type(exc),
            )
        _complete_receipt_locked(
            root,
            reconciling_pointer=reconciling,
            receipt=receipt,
        )
        return receipt


def load_and_replay_startup_receipt(
    *,
    scratchpad: Path,
    expected_run_id: str,
    expected_startup_epoch: str,
) -> dict[str, Any]:
    """Load only the exact current COMPLETE epoch and its immutable receipt."""

    root = _safe_scratchpad(Path(scratchpad))
    with _startup_guard(root):
        return _load_current_locked(
            root,
            expected_run_id=expected_run_id,
            expected_startup_epoch=expected_startup_epoch,
        )


def replay_startup_permit_binding(
    *,
    scratchpad: Path,
    expected_run_id: str,
    binding: Mapping[str, Any],
) -> dict[str, Any]:
    """Strictly replay an AttemptArm-ready ALLOW binding from durable state."""

    try:
        candidate = _clone_json(binding)
    except AuxiliaryWritableRootStartupError as exc:
        raise AuxiliaryWritableRootStartupError(
            "startup permit binding is malformed"
        ) from exc
    expected_fields = {
        "schema",
        "run_id",
        "startup_epoch",
        "current_pointer_sha256",
        "receipt_relative_path",
        "receipt_sha256",
        "allocation_disposition",
    }
    if not isinstance(candidate, dict) or set(candidate) != expected_fields:
        raise AuxiliaryWritableRootStartupError(
            "startup permit binding fields are invalid"
        )
    run_id = _canonical_run_id(candidate.get("run_id"))
    if run_id != _canonical_run_id(expected_run_id):
        raise AuxiliaryWritableRootStartupError(
            "startup permit binding run authority mismatched"
        )
    epoch = _canonical_epoch(candidate.get("startup_epoch"))
    pointer_digest = _canonical_sha256(
        candidate.get("current_pointer_sha256"),
        label="startup permit current-pointer digest",
    )
    receipt_digest = _canonical_sha256(
        candidate.get("receipt_sha256"),
        label="startup permit receipt digest",
    )
    if (
        candidate.get("schema") != STARTUP_BINDING_SCHEMA
        or candidate.get("allocation_disposition")
        not in _PERMIT_DISPOSITIONS
        or candidate.get("receipt_relative_path")
        != _receipt_relative_path(epoch, receipt_digest)
    ):
        raise AuxiliaryWritableRootStartupError(
            "startup permit binding is not a permit"
        )
    replay = load_and_replay_startup_receipt(
        scratchpad=scratchpad,
        expected_run_id=run_id,
        expected_startup_epoch=epoch,
    )
    if (
        replay.get("binding") is None
        or replay["current_pointer_sha256"] != pointer_digest
        or replay["binding"] != candidate
    ):
        raise AuxiliaryWritableRootStartupError(
            "startup permit binding mismatched durable authority"
        )
    return replay


def replay_startup_permit_evidence(
    *,
    scratchpad: Path,
    expected_run_id: str,
    evidence: Mapping[str, Any],
) -> dict[str, Any]:
    """Replay immutable proof that a permit was current when an arm was minted.

    This is deliberately distinct from :func:`replay_startup_permit_binding`.
    The latter is launch authority and therefore requires the epoch to remain
    current.  A completed execution instead retains the exact COMPLETE pointer
    that the provider replayed before launch; this function verifies that
    digest-bound pointer and its immutable receipt without granting authority
    to launch again after a later startup epoch.
    """

    try:
        candidate = _clone_json(evidence)
    except AuxiliaryWritableRootStartupError as exc:
        raise AuxiliaryWritableRootStartupError(
            "startup permit evidence is malformed"
        ) from exc
    if (
        not isinstance(candidate, dict)
        or set(candidate) != {"binding", "current_pointer"}
        or not isinstance(candidate.get("binding"), dict)
        or not isinstance(candidate.get("current_pointer"), dict)
    ):
        raise AuxiliaryWritableRootStartupError(
            "startup permit evidence fields are invalid"
        )
    binding = candidate["binding"]
    expected_binding_fields = {
        "schema",
        "run_id",
        "startup_epoch",
        "current_pointer_sha256",
        "receipt_relative_path",
        "receipt_sha256",
        "allocation_disposition",
    }
    if set(binding) != expected_binding_fields:
        raise AuxiliaryWritableRootStartupError(
            "startup permit evidence binding fields are invalid"
        )
    pointer = _replay_pointer(candidate["current_pointer"])
    run_id = _canonical_run_id(expected_run_id)
    epoch = _canonical_epoch(binding.get("startup_epoch"))
    receipt_digest = _canonical_sha256(
        binding.get("receipt_sha256"),
        label="startup permit evidence receipt digest",
    )
    pointer_digest = _canonical_sha256(
        binding.get("current_pointer_sha256"),
        label="startup permit evidence pointer digest",
    )
    relative = _receipt_relative_path(epoch, receipt_digest)
    disposition = binding.get("allocation_disposition")
    if (
        binding.get("schema") != STARTUP_BINDING_SCHEMA
        or binding.get("run_id") != run_id
        or binding.get("receipt_relative_path") != relative
        or disposition not in _PERMIT_DISPOSITIONS
        or pointer.get("state") != "COMPLETE"
        or pointer.get("run_id") != run_id
        or pointer.get("startup_epoch") != epoch
        or pointer.get("pointer_sha256") != pointer_digest
        or pointer.get("receipt_relative_path") != relative
        or pointer.get("receipt_sha256") != receipt_digest
        or pointer.get("allocation_disposition") != disposition
    ):
        raise AuxiliaryWritableRootStartupError(
            "startup permit evidence pointer/binding semantics mismatched"
        )

    root = _safe_scratchpad(Path(scratchpad))
    receipt_directory = _safe_child_directory(
        root,
        STARTUP_RECEIPT_DIRECTORY_NAME,
        create=False,
    )
    receipt_path = root / Path(relative)
    if (
        receipt_path.parent != receipt_directory
        or receipt_path.name
        != f"startup-{epoch}-{receipt_digest}.json"
    ):
        raise AuxiliaryWritableRootStartupError(
            "startup permit evidence receipt path mismatched"
        )
    raw = _read_regular_file_bounded(
        receipt_path,
        label="startup permit evidence immutable receipt",
        maximum_bytes=MAX_STARTUP_RECEIPT_BYTES,
    )
    receipt = _parse_json(
        raw,
        label="startup permit evidence immutable receipt",
    )
    if (
        not isinstance(receipt, dict)
        or canonical_startup_bytes(receipt) != raw
    ):
        raise AuxiliaryWritableRootStartupError(
            "startup permit evidence receipt encoding is not canonical"
        )
    replay = replay_startup_receipt(receipt)
    if (
        replay.get("valid") is not True
        or replay.get("run_id") != run_id
        or replay.get("startup_epoch") != epoch
        or replay.get("receipt_sha256") != receipt_digest
        or replay.get("allocation_disposition") != disposition
        or replay.get("allocation_permitted") is not True
    ):
        raise AuxiliaryWritableRootStartupError(
            "startup permit evidence receipt semantics mismatched"
        )
    return {
        **replay,
        "binding": binding,
        "current_pointer": pointer,
        "receipt": receipt,
        "receipt_relative_path": relative,
    }


__all__ = [
    "AuxiliaryWritableRootStartupError",
    "MAX_STARTUP_RECEIPT_BYTES",
    "STARTUP_BINDING_SCHEMA",
    "STARTUP_CURRENT_NAME",
    "STARTUP_CURRENT_SCHEMA",
    "STARTUP_QUARANTINE_DIRECTORY_NAME",
    "STARTUP_RECEIPT_DIRECTORY_NAME",
    "STARTUP_RECEIPT_NAME",
    "STARTUP_RECEIPT_SCHEMA",
    "canonical_startup_bytes",
    "compile_startup_receipt",
    "digest_startup_payload",
    "load_and_replay_startup_receipt",
    "persist_startup_receipt",
    "reconcile_and_persist_startup_receipt",
    "replay_startup_permit_binding",
    "replay_startup_permit_evidence",
    "replay_startup_receipt",
]
