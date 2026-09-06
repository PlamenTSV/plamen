"""Crash-safe publication of the L1 semantic-dedup canonical pair.

This module deliberately owns no artifact-ledger or semantic-ledger policy.
The driver supplies four idempotent authority callbacks:

* arm the direct PhaseIO read-modify-write successor before any output write
  and commit it only after both canonical outputs are exact; and
* arm and finalize the semantic mutation of the two canonical artifacts.

The transaction keeps exact source snapshots, canonical preimages, canonical
postimages, and derived sidecars in a short private tree.  A signed pending
pointer is durable before either canonical file changes.  Recovery accepts
only the exact preimage or exact postimage for each member; a third state is
never overwritten or certified.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import tempfile
from typing import Any, Callable, Mapping, Sequence
import uuid

from bounded_artifact_io import read_bounded_regular_bytes


SCHEMA = "plamen.semantic_dedup_transaction.v1"
PENDING_SCHEMA = "plamen.semantic_dedup_transaction_pending.v1"
RECEIPT_SCHEMA = "plamen.semantic_dedup_transaction_receipt.v1"
ATTESTATION_SCHEMA = "plamen.semantic_dedup_external_attestation.v1"
REPAIR_PENDING_SCHEMA = (
    "plamen.semantic_dedup_committed_successor_repair_pending.v1"
)
REPAIR_RECEIPT_SCHEMA = (
    "plamen.semantic_dedup_committed_successor_repair_receipt.v1"
)

ROOT = "_sdt"
PENDING = f"{ROOT}/p.json"
REPAIR_PENDING = f"{ROOT}/repair_pending.json"
INVENTORY = "findings_inventory.md"
RECORDS = "finding_records.json"
PAIR = (INVENTORY, RECORDS)
APPLIED_RECEIPT = "semantic_dedup_applied_receipt.json"
ABSORBED_MAP = "dedup_absorbed_map.md"
DEDUPED_INVENTORY = "findings_inventory_deduped.md"
SIDECARS = (APPLIED_RECEIPT, ABSORBED_MAP, DEDUPED_INVENTORY)
OUTPUTS = (*PAIR, *SIDECARS)

MAX_ARTIFACT_BYTES = 64 * 1024 * 1024
MAX_CONTROL_BYTES = 2 * 1024 * 1024
_HEX64 = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
_WINDOWS_REPARSE_POINT = 0x400

FAILPOINTS = (
    "AFTER_INPUTS_VALIDATED",
    "AFTER_PHASEIO_ARM",
    "AFTER_GENERATION_DURABLE",
    "AFTER_PENDING_STAGED_DURABLE",
    "AFTER_MUTATION_ARM",
    "AFTER_PENDING_ARMED_DURABLE",
    "AFTER_INVENTORY_REPLACED",
    "AFTER_RECORDS_REPLACED",
    "AFTER_APPLIED_RECEIPT_REPLACED",
    "AFTER_ABSORBED_MAP_REPLACED",
    "AFTER_DEDUPED_INVENTORY_REPLACED",
    "AFTER_PAIR_VERIFIED",
    "AFTER_PHASEIO_COMMIT",
    "AFTER_MUTATION_FINALIZE",
    "AFTER_RECEIPT_DURABLE",
    "AFTER_PENDING_CLEARED",
)

REPAIR_FAILPOINTS = (
    "AFTER_REPAIR_PENDING_DURABLE",
    "AFTER_REPAIR_AUTHORITY_ARMED",
    "AFTER_REPAIR_INVENTORY_REPLACED",
    "AFTER_REPAIR_RECORDS_REPLACED",
    "AFTER_REPAIR_APPLIED_RECEIPT_REPLACED",
    "AFTER_REPAIR_ABSORBED_MAP_REPLACED",
    "AFTER_REPAIR_DEDUPED_INVENTORY_REPLACED",
    "AFTER_REPAIR_OUTPUTS_VERIFIED",
    "AFTER_REPAIR_AUTHORITY_RECONFIRMED",
    "AFTER_REPAIR_RECEIPT_DURABLE",
    "AFTER_REPAIR_PENDING_CLEARED",
)


class SemanticDedupTransactionError(RuntimeError):
    """The transaction cannot proceed or recover without ambiguity."""


@dataclass(frozen=True)
class SemanticDedupAuthorityRequest:
    """Immutable transaction identity passed to an external authority adapter."""

    run_id: str
    phase: str
    generation_digest: str
    intent_sha256: str
    generation_root: str
    authority_binding: Mapping[str, Any]
    exact_inputs: tuple[Mapping[str, Any], ...]
    proposal_inputs: tuple[str, ...]
    before: Mapping[str, Mapping[str, Any]]
    after: Mapping[str, Mapping[str, Any]]
    staged_sidecars: tuple[Mapping[str, Any], ...]
    outputs: Mapping[str, Mapping[str, Any]]


AuthorityCallback = Callable[
    [SemanticDedupAuthorityRequest],
    Mapping[str, Any],
]
RepairAuthorityCallback = Callable[
    [SemanticDedupAuthorityRequest, Mapping[str, Any]],
    Mapping[str, Any],
]


@dataclass(frozen=True)
class SemanticDedupAuthorityCallbacks:
    """Driver adapters for the two external authority systems.

    Callbacks must be idempotent.  They return a normalized attestation bound
    to the request's run, phase, and generation.  The core stores those exact
    attestations in its pending pointer and final receipt.
    """

    phaseio_arm: AuthorityCallback
    phaseio_commit: AuthorityCallback
    mutation_arm: AuthorityCallback
    mutation_finalize: AuthorityCallback


@dataclass(frozen=True)
class SemanticDedupTransactionResult:
    run_id: str
    phase: str
    generation_digest: str
    recovered: bool
    changed: bool
    state: str
    safe_to_consume: bool
    receipt_sha256: str


@dataclass(frozen=True)
class SemanticDedupRepairResult:
    """Outcome of exact repair of an already committed five-output successor."""

    run_id: str
    phase: str
    generation_digest: str
    repaired: bool
    recovered: bool
    state: str
    safe_to_consume: bool
    transaction_receipt_sha256: str
    repair_receipt_path: str
    repair_receipt_sha256: str


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise SemanticDedupTransactionError(
            f"transaction metadata is not canonical JSON: {exc}"
        ) from exc


def _signed(
    unsigned: Mapping[str, Any],
    digest_key: str,
) -> dict[str, Any]:
    row = dict(unsigned)
    row[digest_key] = _sha(_canonical(unsigned))
    return row


def _validate_signed(
    value: Mapping[str, Any],
    *,
    schema: str,
    digest_key: str,
    label: str,
) -> None:
    unsigned = dict(value)
    digest = str(unsigned.pop(digest_key, "") or "")
    if (
        value.get("schema_version") != schema
        or not _HEX64.fullmatch(digest)
        or digest != _sha(_canonical(unsigned))
    ):
        raise SemanticDedupTransactionError(
            f"{label} is stale, malformed, or tampered"
        )


def _binding(raw: bytes) -> dict[str, Any]:
    return {"sha256": _sha(raw), "size_bytes": len(raw)}


def _is_linklike(path: Path) -> bool:
    info = path.lstat()
    attributes = int(getattr(info, "st_file_attributes", 0) or 0)
    return stat.S_ISLNK(info.st_mode) or bool(
        attributes & _WINDOWS_REPARSE_POINT
    )


def _validate_root(root: Path) -> Path:
    target = Path(root)
    if not target.exists() or not target.is_dir() or _is_linklike(target):
        raise SemanticDedupTransactionError(
            "semantic-dedup scratchpad is missing, non-directory, or link-like"
        )
    try:
        return target.resolve(strict=True)
    except OSError as exc:
        raise SemanticDedupTransactionError(
            f"semantic-dedup scratchpad cannot be resolved: {exc}"
        ) from exc


def _safe_relative(value: str) -> str:
    raw = str(value or "").replace("\\", "/").strip()
    parsed = PurePosixPath(raw)
    if (
        not raw
        or raw != parsed.as_posix()
        or parsed.is_absolute()
        or raw.startswith("/")
        or any(part in {"", ".", ".."} for part in parsed.parts)
        or ":" in parsed.parts[0]
    ):
        raise SemanticDedupTransactionError(
            f"unsafe semantic-dedup relative path: {value!r}"
        )
    return parsed.as_posix()


def _unique_relatives(values: Sequence[str], *, label: str) -> tuple[str, ...]:
    normalized = tuple(_safe_relative(value) for value in values)
    if not normalized:
        raise SemanticDedupTransactionError(f"{label} must not be empty")
    folded: dict[str, str] = {}
    for relative in normalized:
        prior = folded.setdefault(relative.casefold(), relative)
        if prior != relative or normalized.count(relative) > 1:
            raise SemanticDedupTransactionError(
                f"{label} contains a cross-platform path collision: "
                f"{prior!r}, {relative!r}"
            )
    return tuple(sorted(normalized, key=lambda item: (item.casefold(), item)))


def _regular_path(
    root: Path,
    relative: str,
    *,
    allow_missing: bool,
) -> Path:
    normalized = _safe_relative(relative)
    cursor = root
    for part in PurePosixPath(normalized).parts:
        if cursor.exists():
            if not cursor.is_dir() or _is_linklike(cursor):
                raise SemanticDedupTransactionError(
                    f"semantic-dedup path has an unsafe parent: {relative}"
                )
        cursor = cursor / part
    path = cursor
    try:
        resolved = path.resolve(strict=False)
    except OSError as exc:
        raise SemanticDedupTransactionError(
            f"semantic-dedup path cannot be resolved: {relative}: {exc}"
        ) from exc
    if not resolved.is_relative_to(root):
        raise SemanticDedupTransactionError(
            f"semantic-dedup path escapes the scratchpad: {relative}"
        )
    if path.exists():
        if _is_linklike(path) or not path.is_file():
            raise SemanticDedupTransactionError(
                f"semantic-dedup artifact is not a regular file: {relative}"
            )
    elif not allow_missing:
        raise SemanticDedupTransactionError(
            f"semantic-dedup artifact is missing: {relative}"
        )
    return path


def _read(root: Path, relative: str, *, limit: int = MAX_ARTIFACT_BYTES) -> bytes:
    path = _regular_path(root, relative, allow_missing=False)
    try:
        return read_bounded_regular_bytes(path, limit)
    except (OSError, ValueError) as exc:
        raise SemanticDedupTransactionError(
            f"semantic-dedup artifact is unreadable or unstable: "
            f"{relative}: {exc}"
        ) from exc


def _fsync_parent(path: Path) -> None:
    if os.name == "nt":
        return
    descriptor = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _atomic_bytes(path: Path, raw: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if _is_linklike(path.parent):
        raise SemanticDedupTransactionError(
            f"semantic-dedup output parent is link-like: {path.parent.name}"
        )
    fd, name = tempfile.mkstemp(
        prefix=f".{path.name[:12]}.",
        suffix=".tmp",
        dir=str(path.parent),
    )
    temporary = Path(name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        _fsync_parent(path)
    finally:
        temporary.unlink(missing_ok=True)


def _exclusive_bytes(
    path: Path,
    raw: bytes,
    *,
    label: str,
    limit: int = MAX_CONTROL_BYTES,
) -> None:
    """Publish immutable bytes without exposing a partially written target."""

    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if _is_linklike(path) or not path.is_file():
            raise SemanticDedupTransactionError(f"{label} path is unsafe")
        if read_bounded_regular_bytes(path, limit) != raw:
            raise SemanticDedupTransactionError(
                f"{label} already exists with foreign bytes"
            )
        return
    fd, name = tempfile.mkstemp(
        prefix=f".{path.name[:12]}.",
        suffix=".immutable.tmp",
        dir=str(path.parent),
    )
    temporary = Path(name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(temporary, path)
        except FileExistsError:
            if (
                _is_linklike(path)
                or not path.is_file()
                or read_bounded_regular_bytes(path, limit) != raw
            ):
                raise SemanticDedupTransactionError(
                    f"{label} raced with foreign bytes"
                )
        _fsync_parent(path)
    finally:
        temporary.unlink(missing_ok=True)


@contextmanager
def _transaction_lock(root: Path):
    """Acquire one non-blocking, process-scoped cross-OS publication lock."""

    private = root / ROOT
    private.mkdir(parents=True, exist_ok=True)
    lock_path = private / "lck"
    if lock_path.exists() and (_is_linklike(lock_path) or not lock_path.is_file()):
        raise SemanticDedupTransactionError(
            "semantic-dedup transaction lock path is unsafe"
        )
    handle = lock_path.open("a+b")
    locked = False
    try:
        if os.name == "nt":
            import msvcrt

            handle.seek(0, os.SEEK_END)
            if handle.tell() == 0:
                handle.write(b"\0")
                handle.flush()
            handle.seek(0)
            try:
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            except OSError as exc:
                raise SemanticDedupTransactionError(
                    "semantic-dedup transaction lock is held"
                ) from exc
        else:
            import fcntl

            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as exc:
                raise SemanticDedupTransactionError(
                    "semantic-dedup transaction lock is held"
                ) from exc
        locked = True
        yield
    finally:
        if locked:
            if os.name == "nt":
                import msvcrt

                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        handle.close()


def _load_json(
    root: Path,
    relative: str,
    *,
    limit: int = MAX_CONTROL_BYTES,
) -> dict[str, Any]:
    raw = _read(root, relative, limit=limit)
    try:
        value = json.loads(raw.decode("utf-8", errors="strict"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise SemanticDedupTransactionError(
            "semantic-dedup control manifest/pointer is malformed or "
            f"tampered: {relative}"
        ) from exc
    if not isinstance(value, dict):
        raise SemanticDedupTransactionError(
            f"semantic-dedup control artifact is not an object: {relative}"
        )
    return value


def _require_canonical_control(
    root: Path,
    relative: str,
    value: Mapping[str, Any],
) -> None:
    if _read(root, relative, limit=MAX_CONTROL_BYTES) != _canonical(value):
        raise SemanticDedupTransactionError(
            f"semantic-dedup control artifact is not canonical: {relative}"
        )


def _boundary(
    fault_hook: Callable[[str], None] | None,
    name: str,
) -> None:
    if name not in FAILPOINTS:
        raise AssertionError(f"unknown semantic-dedup transaction boundary: {name}")
    if fault_hook is not None:
        fault_hook(name)


def _repair_boundary(
    fault_hook: Callable[[str], None] | None,
    name: str,
) -> None:
    if name not in REPAIR_FAILPOINTS:
        raise AssertionError(
            f"unknown semantic-dedup repair boundary: {name}"
        )
    if fault_hook is not None:
        fault_hook(name)


def _normalized_context(
    run_id: str,
    phase: str,
    authority_binding: Mapping[str, Any],
) -> tuple[str, str, dict[str, Any]]:
    run = str(run_id or "").strip()
    phase_name = str(phase or "").strip()
    if (
        not run
        or not phase_name
        or len(run) > 256
        or len(phase_name) > 128
    ):
        raise SemanticDedupTransactionError(
            "semantic-dedup transaction requires bounded run and phase identities"
        )
    if not isinstance(authority_binding, Mapping):
        raise SemanticDedupTransactionError(
            "semantic-dedup authority binding must be an object"
        )
    try:
        binding = json.loads(_canonical(dict(authority_binding)).decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise SemanticDedupTransactionError(
            "semantic-dedup authority binding cannot be normalized"
        ) from exc
    if (
        not isinstance(binding, dict)
        or binding.get("run_id") != run
        or binding.get("phase") != phase_name
    ):
        raise SemanticDedupTransactionError(
            "semantic-dedup authority binding is not exact for this run/phase"
        )
    if len(_canonical(binding)) > MAX_CONTROL_BYTES // 4:
        raise SemanticDedupTransactionError(
            "semantic-dedup authority binding is unbounded"
        )
    return run, phase_name, binding


def capture_semantic_dedup_inputs(
    scratchpad: Path,
    relatives: Sequence[str],
) -> tuple[dict[str, Any], ...]:
    """Capture an exact, required, stable source denominator.

    The caller captures this before deriving postimages and passes it back to
    :func:`apply_semantic_dedup_transaction`.  Missing/optional inputs must be
    resolved by the caller before the transaction; ambiguity is not encoded as
    a silently absent row.
    """

    root = _validate_root(Path(scratchpad))
    paths = _unique_relatives(relatives, label="exact_inputs")
    rows: list[dict[str, Any]] = []
    for relative in paths:
        raw = _read(root, relative)
        rows.append(
            {
                "path": relative,
                "sha256": _sha(raw),
                "size_bytes": len(raw),
            }
        )
    return tuple(rows)


def capture_semantic_dedup_output_prestate(
    scratchpad: Path,
    outputs: Sequence[str] = OUTPUTS,
) -> tuple[dict[str, Any], ...]:
    """Capture the exact present/missing RMW denominator for all outputs."""

    root = _validate_root(Path(scratchpad))
    paths = _unique_relatives(outputs, label="semantic-dedup outputs")
    if set(paths) != set(OUTPUTS):
        raise SemanticDedupTransactionError(
            "semantic-dedup output prestate must cover the exact five outputs"
        )
    rows: list[dict[str, Any]] = []
    for relative in paths:
        path = _regular_path(root, relative, allow_missing=True)
        if not path.is_file():
            rows.append({"path": relative, "status": "MISSING"})
            continue
        raw = _read(root, relative)
        rows.append(
            {
                "path": relative,
                "status": "PRESENT",
                "sha256": _sha(raw),
                "size_bytes": len(raw),
            }
        )
    return tuple(rows)


def _normalize_expected_inputs(
    exact_inputs: Sequence[str],
    expected_inputs: Sequence[Mapping[str, Any]],
) -> tuple[dict[str, Any], ...]:
    paths = _unique_relatives(exact_inputs, label="exact_inputs")
    if not isinstance(expected_inputs, Sequence):
        raise SemanticDedupTransactionError(
            "expected semantic-dedup inputs are malformed"
        )
    rows: list[dict[str, Any]] = []
    folded: set[str] = set()
    for value in expected_inputs:
        if not isinstance(value, Mapping):
            raise SemanticDedupTransactionError(
                "expected semantic-dedup input row is malformed"
            )
        relative = _safe_relative(str(value.get("path") or ""))
        digest = str(value.get("sha256") or "")
        size = value.get("size_bytes")
        if (
            relative.casefold() in folded
            or not _HEX64.fullmatch(digest)
            or isinstance(size, bool)
            or not isinstance(size, int)
            or size < 0
            or size > MAX_ARTIFACT_BYTES
            or set(value) != {"path", "sha256", "size_bytes"}
        ):
            raise SemanticDedupTransactionError(
                f"expected semantic-dedup input row is invalid: {relative}"
            )
        folded.add(relative.casefold())
        rows.append(
            {"path": relative, "sha256": digest, "size_bytes": size}
        )
    rows.sort(key=lambda row: (str(row["path"]).casefold(), str(row["path"])))
    if tuple(str(row["path"]) for row in rows) != paths:
        raise SemanticDedupTransactionError(
            "expected semantic-dedup input set differs from exact_inputs"
        )
    if set(PAIR) & set(paths):
        raise SemanticDedupTransactionError(
            "canonical RMW targets must be output prestates, not exact inputs"
        )
    return tuple(rows)


def _normalize_output_prestate(
    expected_output_prestate: Sequence[Mapping[str, Any]],
    expected_inputs: Sequence[Mapping[str, Any]],
) -> tuple[dict[str, Any], ...]:
    if not isinstance(expected_output_prestate, Sequence):
        raise SemanticDedupTransactionError(
            "semantic-dedup output prestate is malformed"
        )
    rows: list[dict[str, Any]] = []
    folded: set[str] = set()
    for value in expected_output_prestate:
        if not isinstance(value, Mapping):
            raise SemanticDedupTransactionError(
                "semantic-dedup output prestate row is malformed"
            )
        relative = _safe_relative(str(value.get("path") or ""))
        status = str(value.get("status") or "")
        if relative.casefold() in folded or status not in {"MISSING", "PRESENT"}:
            raise SemanticDedupTransactionError(
                f"semantic-dedup output prestate row is invalid: {relative}"
            )
        folded.add(relative.casefold())
        if status == "MISSING":
            if set(value) != {"path", "status"}:
                raise SemanticDedupTransactionError(
                    f"missing output prestate has unexpected fields: {relative}"
                )
            rows.append({"path": relative, "status": status})
            continue
        digest = str(value.get("sha256") or "")
        size = value.get("size_bytes")
        if (
            set(value) != {"path", "status", "sha256", "size_bytes"}
            or not _HEX64.fullmatch(digest)
            or isinstance(size, bool)
            or not isinstance(size, int)
            or size < 0
            or size > MAX_ARTIFACT_BYTES
        ):
            raise SemanticDedupTransactionError(
                f"present output prestate is invalid: {relative}"
            )
        rows.append(
            {
                "path": relative,
                "status": status,
                "sha256": digest,
                "size_bytes": size,
            }
        )
    rows.sort(key=lambda row: (str(row["path"]).casefold(), str(row["path"])))
    if {str(row["path"]) for row in rows} != set(OUTPUTS):
        raise SemanticDedupTransactionError(
            "semantic-dedup output prestate must cover the exact five outputs"
        )
    for relative in PAIR:
        output = next(row for row in rows if row["path"] == relative)
        if output.get("status") != "PRESENT":
            raise SemanticDedupTransactionError(
                f"canonical output prestate must be present: {relative}"
            )
    return tuple(rows)


def _validate_live_inputs(
    root: Path,
    rows: Sequence[Mapping[str, Any]],
) -> dict[str, bytes]:
    raw_by_path: dict[str, bytes] = {}
    for row in rows:
        relative = str(row["path"])
        raw = _read(root, relative)
        if (
            _sha(raw) != row.get("sha256")
            or len(raw) != row.get("size_bytes")
        ):
            raise SemanticDedupTransactionError(
                f"semantic-dedup input changed after snapshot: {relative}"
            )
        raw_by_path[relative] = raw
    return raw_by_path


def _validate_live_output_prestate(
    root: Path,
    rows: Sequence[Mapping[str, Any]],
) -> dict[str, bytes]:
    raw_by_path: dict[str, bytes] = {}
    for row in rows:
        relative = str(row["path"])
        path = _regular_path(root, relative, allow_missing=True)
        if row["status"] == "MISSING":
            if path.exists():
                raise SemanticDedupTransactionError(
                    f"semantic-dedup output appeared after prestate capture: "
                    f"{relative}"
                )
            continue
        raw = _read(root, relative)
        if (
            _sha(raw) != row.get("sha256")
            or len(raw) != row.get("size_bytes")
        ):
            raise SemanticDedupTransactionError(
                f"semantic-dedup output changed after prestate capture: {relative}"
            )
        raw_by_path[relative] = raw
    return raw_by_path


def _normalize_sidecars(
    staged_sidecars: Mapping[str, bytes],
    post_inventory: bytes,
) -> tuple[tuple[str, bytes], ...]:
    if not isinstance(staged_sidecars, Mapping):
        raise SemanticDedupTransactionError(
            "semantic-dedup staged sidecars must be a mapping"
        )
    normalized: dict[str, bytes] = {}
    source_name: dict[str, str] = {}
    folded: dict[str, str] = {}
    for name, value in staged_sidecars.items():
        relative = _safe_relative(str(name))
        prior = folded.setdefault(relative.casefold(), relative)
        if prior != relative:
            raise SemanticDedupTransactionError(
                "semantic-dedup sidecars contain a cross-platform collision"
            )
        if relative in PAIR:
            raise SemanticDedupTransactionError(
                f"canonical pair member cannot be a staged sidecar: {relative}"
            )
        raw = bytes(value)
        if len(raw) > MAX_ARTIFACT_BYTES:
            raise SemanticDedupTransactionError(
                f"semantic-dedup staged sidecar is unbounded: {relative}"
            )
        if relative in normalized:
            raise SemanticDedupTransactionError(
                "semantic-dedup sidecar identity collision after normalization: "
                f"{source_name[relative]!r}, {name!r}"
            )
        normalized[relative] = raw
        source_name[relative] = str(name)
    proposed = normalized.get("findings_inventory_deduped.md")
    if set(normalized) != set(SIDECARS):
        raise SemanticDedupTransactionError(
            "semantic-dedup transaction requires the exact three root sidecars"
        )
    if proposed is not None and proposed != post_inventory:
        raise SemanticDedupTransactionError(
            "staged dedup inventory differs from canonical inventory postimage"
        )
    return tuple(
        sorted(normalized.items(), key=lambda item: (item[0].casefold(), item[0]))
    )


def _validate_post_pair(inventory: bytes, records: bytes) -> None:
    if len(inventory) > MAX_ARTIFACT_BYTES or len(records) > MAX_ARTIFACT_BYTES:
        raise SemanticDedupTransactionError(
            "semantic-dedup canonical postimage exceeds the bounded limit"
        )
    try:
        inventory.decode("utf-8", errors="strict")
        records_value = json.loads(records.decode("utf-8", errors="strict"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise SemanticDedupTransactionError(
            "semantic-dedup postimages must be strict UTF-8/JSON"
        ) from exc
    if (
        not isinstance(records_value, dict)
        or records_value.get("source") != INVENTORY
        or records_value.get("source_sha256") != _sha(inventory)
        or not isinstance(records_value.get("records"), list)
    ):
        raise SemanticDedupTransactionError(
            "finding-record postimage does not bind the inventory postimage"
        )


def _intent_for(
    *,
    run_id: str,
    phase: str,
    authority_binding: Mapping[str, Any],
    expected_inputs: Sequence[Mapping[str, Any]],
    expected_output_prestate: Sequence[Mapping[str, Any]],
    proposal_inputs: Sequence[str],
    post_inventory: bytes,
    post_records: bytes,
    staged_sidecars: Sequence[tuple[str, bytes]],
) -> dict[str, Any]:
    prestate_by_path = {
        str(row["path"]): dict(row) for row in expected_output_prestate
    }
    before_rows: dict[str, dict[str, Any]] = {}
    after_rows: dict[str, dict[str, Any]] = {}
    for index, relative in enumerate(PAIR):
        source = prestate_by_path[relative]
        before_rows[relative] = {
            "status": "PRESENT",
            "payload": f"b{index}.bin",
            "sha256": source["sha256"],
            "size_bytes": source["size_bytes"],
        }
    for index, (relative, raw) in enumerate(
        ((INVENTORY, post_inventory), (RECORDS, post_records))
    ):
        after_rows[relative] = {
            "status": "PRESENT",
            "payload": f"a{index}.bin",
            **_binding(raw),
        }

    proposal_set = set(proposal_inputs)
    source_rows: list[dict[str, Any]] = []
    for index, row in enumerate(expected_inputs):
        relative = str(row["path"])
        roles = ["EXACT_INPUT"]
        if relative in proposal_set:
            roles.append("PROPOSAL")
        source_rows.append(
            {
                **dict(row),
                "payload": f"s/{index:03d}.bin",
                "roles": roles,
            }
        )
    sidecar_rows: list[dict[str, Any]] = []
    output_rows: dict[str, dict[str, Any]] = {
        relative: {
            "kind": "CANONICAL_PAIR",
            "before": dict(before_rows[relative]),
            "after": dict(after_rows[relative]),
        }
        for relative in PAIR
    }
    for index, (relative, raw) in enumerate(staged_sidecars):
        prestate = prestate_by_path[relative]
        before: dict[str, Any] = {"status": prestate["status"]}
        if prestate["status"] == "PRESENT":
            before.update(
                {
                    "payload": f"x/{index:03d}.bin",
                    "sha256": prestate["sha256"],
                    "size_bytes": prestate["size_bytes"],
                }
            )
        after = {
            "status": "PRESENT",
            "payload": f"s/{len(source_rows) + index:03d}.bin",
            **_binding(raw),
        }
        sidecar_rows.append(
            {
                "path": relative,
                "payload": after["payload"],
                "sha256": after["sha256"],
                "size_bytes": after["size_bytes"],
            }
        )
        output_rows[relative] = {
            "kind": "DERIVED_SIDECAR",
            "before": before,
            "after": after,
        }
    core = {
        "schema_version": SCHEMA,
        "run_id": run_id,
        "phase": phase,
        "transaction_kind": "L1_SEMANTIC_DEDUP_CANONICAL_PAIR",
        "canonical_pair": list(PAIR),
        "before": before_rows,
        "after": after_rows,
        "exact_inputs": source_rows,
        "proposal_inputs": list(proposal_inputs),
        "staged_sidecars": sidecar_rows,
        "outputs": output_rows,
        "authority_binding": dict(authority_binding),
        "authority_binding_sha256": _sha(_canonical(authority_binding)),
        "publication_order": list(OUTPUTS),
        "recovery_policy": "EACH_OUTPUT_EXACT_PRE_OR_POST_ONLY",
    }
    generation = _sha(_canonical(core))
    unsigned = {**core, "generation_digest": generation}
    return _signed(unsigned, "intent_sha256")


def _request(intent: Mapping[str, Any]) -> SemanticDedupAuthorityRequest:
    return SemanticDedupAuthorityRequest(
        run_id=str(intent["run_id"]),
        phase=str(intent["phase"]),
        generation_digest=str(intent["generation_digest"]),
        intent_sha256=str(intent["intent_sha256"]),
        generation_root=f"{ROOT}/g_{intent['generation_digest']}",
        authority_binding=dict(intent["authority_binding"]),
        exact_inputs=tuple(dict(row) for row in intent["exact_inputs"]),
        proposal_inputs=tuple(str(value) for value in intent["proposal_inputs"]),
        before={
            relative: dict(intent["before"][relative]) for relative in PAIR
        },
        after={
            relative: dict(intent["after"][relative]) for relative in PAIR
        },
        staged_sidecars=tuple(
            dict(row) for row in intent["staged_sidecars"]
        ),
        outputs={
            relative: {
                "kind": intent["outputs"][relative]["kind"],
                "before": dict(intent["outputs"][relative]["before"]),
                "after": dict(intent["outputs"][relative]["after"]),
            }
            for relative in OUTPUTS
        },
    )


_ATTESTATION_EXPECTATIONS = {
    "PHASEIO_ARM": ("PHASE_IO", "ARMED"),
    "PHASEIO_COMMIT": ("PHASE_IO", "COMMITTED"),
    "MUTATION_ARM": ("SEMANTIC_MUTATION", "ARMED"),
    "MUTATION_FINALIZE": ("SEMANTIC_MUTATION", "FINALIZED"),
}


def _authority_callback(
    callback: AuthorityCallback,
    request: SemanticDedupAuthorityRequest,
    *,
    action: str,
) -> dict[str, Any]:
    if not callable(callback):
        raise SemanticDedupTransactionError(
            f"semantic-dedup authority callback is unavailable: {action}"
        )
    try:
        value = callback(request)
    except Exception as exc:
        raise SemanticDedupTransactionError(
            f"semantic-dedup external authority rejected {action}: "
            f"{type(exc).__name__}: {exc}"
        ) from exc
    if not isinstance(value, Mapping):
        raise SemanticDedupTransactionError(
            f"semantic-dedup authority attestation is malformed: {action}"
        )
    try:
        row = json.loads(_canonical(dict(value)).decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise SemanticDedupTransactionError(
            f"semantic-dedup authority attestation cannot be normalized: {action}"
        ) from exc
    expected_kind, expected_status = _ATTESTATION_EXPECTATIONS[action]
    if (
        row.get("schema_version") != ATTESTATION_SCHEMA
        or row.get("run_id") != request.run_id
        or row.get("phase") != request.phase
        or row.get("generation_digest") != request.generation_digest
        or row.get("action") != action
        or row.get("authority_kind") != expected_kind
        or row.get("status") != expected_status
        or not str(row.get("authority_id") or "").strip()
        or not _HEX64.fullmatch(str(row.get("authority_digest") or ""))
        or len(_canonical(row)) > MAX_CONTROL_BYTES // 2
    ):
        raise SemanticDedupTransactionError(
            f"semantic-dedup authority attestation is not exact: {action}"
        )
    return row


def _generation_relative(generation: str, leaf: str = "") -> str:
    base = f"{ROOT}/g_{generation}"
    return f"{base}/{leaf}" if leaf else base


def _existing_context_generation(
    root: Path,
    *,
    run_id: str,
    phase: str,
) -> str | None:
    private = root / ROOT
    if not private.exists():
        return None
    if not private.is_dir() or _is_linklike(private):
        raise SemanticDedupTransactionError(
            "semantic-dedup private root is unsafe"
        )
    matches: list[str] = []
    generations = [
        path for path in private.iterdir() if path.name.startswith("g_")
    ]
    if len(generations) > 128:
        raise SemanticDedupTransactionError(
            "semantic-dedup private generation denominator is unbounded"
        )
    for path in generations:
        generation = path.name[2:]
        if not _HEX64.fullmatch(generation):
            raise SemanticDedupTransactionError(
                "semantic-dedup private root contains a malformed generation"
            )
        intent, _ = _validate_generation(root, generation)
        if intent.get("run_id") == run_id and intent.get("phase") == phase:
            matches.append(generation)
    if len(matches) > 1:
        raise SemanticDedupTransactionError(
            "semantic-dedup run/phase has ambiguous generations"
        )
    return matches[0] if matches else None


def _publish_generation(
    root: Path,
    intent: Mapping[str, Any],
    input_raw: Mapping[str, bytes],
    output_pre_raw: Mapping[str, bytes],
    post_inventory: bytes,
    post_records: bytes,
    staged_sidecars: Sequence[tuple[str, bytes]],
) -> None:
    generation = str(intent["generation_digest"])
    private = root / ROOT
    if private.exists() and (
        not private.is_dir() or _is_linklike(private)
    ):
        raise SemanticDedupTransactionError(
            "semantic-dedup private root is unsafe"
        )
    private.mkdir(parents=True, exist_ok=True)
    final = private / f"g_{generation}"

    payloads: dict[str, bytes] = {
        "i.json": _canonical(intent),
        "b0.bin": output_pre_raw[INVENTORY],
        "b1.bin": output_pre_raw[RECORDS],
        "a0.bin": post_inventory,
        "a1.bin": post_records,
    }
    for row in intent["exact_inputs"]:
        payloads[str(row["payload"])] = input_raw[str(row["path"])]
    sidecars_by_name = dict(staged_sidecars)
    for row in intent["staged_sidecars"]:
        payloads[str(row["payload"])] = sidecars_by_name[str(row["path"])]
        before = intent["outputs"][str(row["path"])]["before"]
        if before["status"] == "PRESENT":
            payloads[str(before["payload"])] = output_pre_raw[str(row["path"])]

    if final.exists():
        _validate_generation(root, generation)
        for leaf, raw in payloads.items():
            if _read(root, _generation_relative(generation, leaf)) != raw:
                raise SemanticDedupTransactionError(
                    "existing semantic-dedup generation has foreign bytes"
                )
        return

    staging = private / f".s_{generation[:10]}_{uuid.uuid4().hex[:8]}"
    staging.mkdir()
    try:
        for leaf, raw in payloads.items():
            target = staging.joinpath(*PurePosixPath(leaf).parts)
            _atomic_bytes(target, raw)
        _fsync_parent(staging / "i.json")
        try:
            os.replace(staging, final)
        except OSError:
            if not final.is_dir():
                raise
        _fsync_parent(final / "i.json")
    finally:
        if staging.exists():
            resolved_staging = staging.resolve(strict=True)
            resolved_private = private.resolve(strict=True)
            if (
                not resolved_staging.is_relative_to(resolved_private)
                or _is_linklike(staging)
            ):
                raise SemanticDedupTransactionError(
                    "semantic-dedup staging cleanup target is unsafe"
                )
            shutil.rmtree(staging)
    _validate_generation(root, generation)


def _expected_generation_leaves(intent: Mapping[str, Any]) -> set[str]:
    leaves = {"i.json", "b0.bin", "b1.bin", "a0.bin", "a1.bin"}
    leaves.update(str(row["payload"]) for row in intent["exact_inputs"])
    leaves.update(str(row["payload"]) for row in intent["staged_sidecars"])
    leaves.update(
        str(intent["outputs"][str(row["path"])]["before"]["payload"])
        for row in intent["staged_sidecars"]
        if intent["outputs"][str(row["path"])]["before"]["status"]
        == "PRESENT"
    )
    return leaves


def _validate_generation(
    root: Path,
    generation: str,
) -> tuple[dict[str, Any], dict[str, bytes]]:
    if not _HEX64.fullmatch(generation):
        raise SemanticDedupTransactionError(
            "semantic-dedup generation identity is malformed"
        )
    generation_relative = _generation_relative(generation)
    directory = root.joinpath(*PurePosixPath(generation_relative).parts)
    if (
        not directory.is_dir()
        or _is_linklike(directory)
        or _is_linklike(directory.parent)
    ):
        raise SemanticDedupTransactionError(
            "semantic-dedup generation directory is missing or unsafe"
        )
    intent = _load_json(root, f"{generation_relative}/i.json")
    _require_canonical_control(
        root, f"{generation_relative}/i.json", intent
    )
    _validate_signed(
        intent,
        schema=SCHEMA,
        digest_key="intent_sha256",
        label="semantic-dedup intent",
    )
    unsigned = dict(intent)
    unsigned.pop("intent_sha256", None)
    recorded_generation = str(unsigned.pop("generation_digest", "") or "")
    if (
        recorded_generation != generation
        or generation != _sha(_canonical(unsigned))
    ):
        raise SemanticDedupTransactionError(
            "semantic-dedup generation does not bind its intent"
        )
    if (
        intent.get("canonical_pair") != list(PAIR)
        or intent.get("publication_order") != list(OUTPUTS)
        or intent.get("recovery_policy")
        != "EACH_OUTPUT_EXACT_PRE_OR_POST_ONLY"
        or set(intent.get("outputs") or {}) != set(OUTPUTS)
    ):
        raise SemanticDedupTransactionError(
            "semantic-dedup intent changed its pair/recovery policy"
        )
    if (
        intent.get("authority_binding_sha256")
        != _sha(_canonical(intent.get("authority_binding")))
        or intent.get("transaction_kind")
        != "L1_SEMANTIC_DEDUP_CANONICAL_PAIR"
        or not str(intent.get("run_id") or "").strip()
        or not str(intent.get("phase") or "").strip()
    ):
        raise SemanticDedupTransactionError(
            "semantic-dedup intent identity/authority binding is invalid"
        )
    sidecar_by_path = {
        str(row.get("path") or ""): row
        for row in intent.get("staged_sidecars") or []
        if isinstance(row, Mapping)
    }
    if set(sidecar_by_path) != set(SIDECARS):
        raise SemanticDedupTransactionError(
            "semantic-dedup intent sidecar set is invalid"
        )
    for relative in OUTPUTS:
        output = intent["outputs"].get(relative)
        if not isinstance(output, Mapping):
            raise SemanticDedupTransactionError(
                f"semantic-dedup output row is malformed: {relative}"
            )
        expected_kind = (
            "CANONICAL_PAIR" if relative in PAIR else "DERIVED_SIDECAR"
        )
        if output.get("kind") != expected_kind:
            raise SemanticDedupTransactionError(
                f"semantic-dedup output kind is invalid: {relative}"
            )
        before = output.get("before")
        after = output.get("after")
        if (
            not isinstance(before, Mapping)
            or not isinstance(after, Mapping)
            or before.get("status") not in {"MISSING", "PRESENT"}
            or after.get("status") != "PRESENT"
        ):
            raise SemanticDedupTransactionError(
                f"semantic-dedup output lattice is invalid: {relative}"
            )
        if relative in PAIR:
            if (
                dict(before) != dict(intent["before"][relative])
                or dict(after) != dict(intent["after"][relative])
            ):
                raise SemanticDedupTransactionError(
                    f"semantic-dedup canonical output lattice drifted: {relative}"
                )
        else:
            sidecar = sidecar_by_path[relative]
            sidecar_after = {
                "status": "PRESENT",
                "payload": sidecar.get("payload"),
                "sha256": sidecar.get("sha256"),
                "size_bytes": sidecar.get("size_bytes"),
            }
            if (
                dict(before)
                != dict(intent["outputs"][relative].get("before") or {})
                or dict(after) != sidecar_after
            ):
                raise SemanticDedupTransactionError(
                    f"semantic-dedup sidecar output lattice drifted: {relative}"
                )

    expected_leaves = _expected_generation_leaves(intent)
    actual_leaves: set[str] = set()
    for parent, directories, files in os.walk(directory, followlinks=False):
        parent_path = Path(parent)
        if _is_linklike(parent_path):
            raise SemanticDedupTransactionError(
                "semantic-dedup generation contains a link-like directory"
            )
        for name in directories:
            child = parent_path / name
            if _is_linklike(child):
                raise SemanticDedupTransactionError(
                    "semantic-dedup generation contains a link-like directory"
                )
        for name in files:
            child = parent_path / name
            if _is_linklike(child) or not child.is_file():
                raise SemanticDedupTransactionError(
                    "semantic-dedup generation contains an unsafe payload"
                )
            actual_leaves.add(child.relative_to(directory).as_posix())
    if actual_leaves != expected_leaves:
        raise SemanticDedupTransactionError(
            "semantic-dedup generation file set is incomplete or expanded"
        )

    payloads: dict[str, bytes] = {}
    binding_rows: list[Mapping[str, Any]] = []
    binding_rows.extend(intent["before"].values())
    binding_rows.extend(intent["after"].values())
    binding_rows.extend(intent["exact_inputs"])
    binding_rows.extend(intent["staged_sidecars"])
    binding_rows.extend(
        intent["outputs"][str(row["path"])]["before"]
        for row in intent["staged_sidecars"]
        if intent["outputs"][str(row["path"])]["before"]["status"]
        == "PRESENT"
    )
    for row in binding_rows:
        leaf = _safe_relative(str(row.get("payload") or ""))
        if leaf not in expected_leaves:
            raise SemanticDedupTransactionError(
                "semantic-dedup intent references an undeclared payload"
            )
        raw = payloads.setdefault(
            leaf,
            _read(root, f"{generation_relative}/{leaf}"),
        )
        if _binding(raw) != {
            "sha256": row.get("sha256"),
            "size_bytes": row.get("size_bytes"),
        }:
            raise SemanticDedupTransactionError(
                f"semantic-dedup generation payload is tampered: {leaf}"
            )
    _validate_post_pair(payloads["a0.bin"], payloads["a1.bin"])
    proposed = next(
        (
            row for row in intent["staged_sidecars"]
            if row.get("path") == "findings_inventory_deduped.md"
        ),
        None,
    )
    if proposed is not None and payloads[str(proposed["payload"])] != payloads[
        "a0.bin"
    ]:
        raise SemanticDedupTransactionError(
            "staged dedup inventory no longer matches the canonical postimage"
        )
    return intent, payloads


def _pending_path(root: Path) -> Path:
    return _regular_path(root, PENDING, allow_missing=True)


def _pending_for(
    intent: Mapping[str, Any],
    *,
    state: str,
    phaseio_arm: Mapping[str, Any],
    phaseio_commit: Mapping[str, Any] | None,
    mutation_arm: Mapping[str, Any] | None,
) -> dict[str, Any]:
    unsigned = {
        "schema_version": PENDING_SCHEMA,
        "state": state,
        "run_id": intent["run_id"],
        "phase": intent["phase"],
        "generation_digest": intent["generation_digest"],
        "intent_sha256": intent["intent_sha256"],
        "authority_binding_sha256": intent["authority_binding_sha256"],
        "phaseio_arm": dict(phaseio_arm),
        "phaseio_commit": (
            dict(phaseio_commit) if phaseio_commit is not None else None
        ),
        "mutation_arm": (
            dict(mutation_arm) if mutation_arm is not None else None
        ),
    }
    return _signed(unsigned, "pending_sha256")


def _write_pending(root: Path, pending: Mapping[str, Any]) -> None:
    path = root / PENDING
    if path.exists() and (_is_linklike(path) or not path.is_file()):
        raise SemanticDedupTransactionError(
            "semantic-dedup pending pointer path is unsafe"
        )
    _atomic_bytes(path, _canonical(pending))


def _load_pending(root: Path) -> dict[str, Any] | None:
    path = _pending_path(root)
    if not path.is_file():
        return None
    value = _load_json(root, PENDING)
    _require_canonical_control(root, PENDING, value)
    _validate_signed(
        value,
        schema=PENDING_SCHEMA,
        digest_key="pending_sha256",
        label="semantic-dedup pending pointer",
    )
    if value.get("state") not in {"STAGED", "ARMED", "OUTPUT_COMMITTED"}:
        raise SemanticDedupTransactionError(
            "semantic-dedup pending state is not recoverable"
        )
    return value


def _validate_pending_intent(
    pending: Mapping[str, Any],
    intent: Mapping[str, Any],
    *,
    run_id: str,
    phase: str,
    authority_binding: Mapping[str, Any],
) -> None:
    if (
        pending.get("run_id") != run_id
        or pending.get("phase") != phase
        or pending.get("generation_digest") != intent.get("generation_digest")
        or pending.get("intent_sha256") != intent.get("intent_sha256")
        or pending.get("authority_binding_sha256")
        != _sha(_canonical(authority_binding))
        or intent.get("run_id") != run_id
        or intent.get("phase") != phase
        or intent.get("authority_binding") != dict(authority_binding)
    ):
        raise SemanticDedupTransactionError(
            "semantic-dedup pending transaction belongs to another run, "
            "phase, generation, or authority binding"
        )


def _compare_attestation(
    recorded: Any,
    live: Mapping[str, Any],
    *,
    action: str,
) -> None:
    if recorded != dict(live):
        raise SemanticDedupTransactionError(
            f"semantic-dedup {action} authority changed during recovery"
        )


def _output_state(
    root: Path,
    intent: Mapping[str, Any],
    payloads: Mapping[str, bytes],
) -> tuple[dict[str, str], bool]:
    states: dict[str, str] = {}
    mutation_started = False
    for relative in OUTPUTS:
        row = intent["outputs"][relative]
        before_row = row["before"]
        after = payloads[str(row["after"]["payload"])]
        path = _regular_path(root, relative, allow_missing=True)
        if not path.is_file():
            if before_row["status"] != "MISSING":
                raise SemanticDedupTransactionError(
                    f"{relative}: arbitrary missing state during recovery"
                )
            states[relative] = "PRE_MISSING"
            continue
        current = _read(root, relative)
        before = (
            payloads[str(before_row["payload"])]
            if before_row["status"] == "PRESENT"
            else None
        )
        if current != after and (before is None or current != before):
            raise SemanticDedupTransactionError(
                f"{relative}: arbitrary third state during paired recovery"
            )
        if before is not None and before == after:
            states[relative] = "UNCHANGED"
        elif current == after:
            states[relative] = "POST"
            mutation_started = True
        else:
            states[relative] = "PRE"
    return states, mutation_started


def _all_outputs_are_post(
    root: Path,
    intent: Mapping[str, Any],
    payloads: Mapping[str, bytes],
) -> bool:
    for relative in OUTPUTS:
        row = intent["outputs"][relative]
        path = _regular_path(root, relative, allow_missing=True)
        if not path.is_file() or _read(root, relative) != payloads[
            str(row["after"]["payload"])
        ]:
            return False
    return True


def _validate_generation_sources_live(
    root: Path,
    intent: Mapping[str, Any],
    payloads: Mapping[str, bytes],
) -> None:
    for row in intent["exact_inputs"]:
        relative = str(row["path"])
        current = _read(root, relative)
        expected = payloads[str(row["payload"])]
        if current != expected:
            raise SemanticDedupTransactionError(
                f"semantic-dedup input changed before canonical publication: "
                f"{relative}"
            )


def _receipt_for(
    intent: Mapping[str, Any],
    *,
    phaseio_arm: Mapping[str, Any],
    phaseio_commit: Mapping[str, Any],
    mutation_arm: Mapping[str, Any],
    mutation_finalize: Mapping[str, Any],
) -> dict[str, Any]:
    changed = any(
        (
            intent["outputs"][relative]["before"].get("status"),
            intent["outputs"][relative]["before"].get("sha256"),
            intent["outputs"][relative]["before"].get("size_bytes"),
        )
        != (
            "PRESENT",
            intent["outputs"][relative]["after"]["sha256"],
            intent["outputs"][relative]["after"]["size_bytes"],
        )
        for relative in OUTPUTS
    )
    unsigned = {
        "schema_version": RECEIPT_SCHEMA,
        "state": "COMMITTED",
        "run_id": intent["run_id"],
        "phase": intent["phase"],
        "generation_digest": intent["generation_digest"],
        "intent_sha256": intent["intent_sha256"],
        "authority_binding_sha256": intent["authority_binding_sha256"],
        "before": intent["before"],
        "after": intent["after"],
        "outputs": intent["outputs"],
        "staged_sidecars": intent["staged_sidecars"],
        "phaseio_arm": dict(phaseio_arm),
        "phaseio_commit": dict(phaseio_commit),
        "mutation_arm": dict(mutation_arm),
        "mutation_finalize": dict(mutation_finalize),
        "changed": changed,
        "safe_to_consume": True,
    }
    return _signed(unsigned, "receipt_sha256")


def _receipt_relative(generation: str) -> str:
    return f"{ROOT}/c_{generation}.json"


def _load_receipt(
    root: Path,
    generation: str,
) -> dict[str, Any] | None:
    relative = _receipt_relative(generation)
    path = _regular_path(root, relative, allow_missing=True)
    if not path.is_file():
        return None
    value = _load_json(root, relative)
    _require_canonical_control(root, relative, value)
    _validate_signed(
        value,
        schema=RECEIPT_SCHEMA,
        digest_key="receipt_sha256",
        label="semantic-dedup transaction receipt",
    )
    if (
        value.get("state") != "COMMITTED"
        or value.get("generation_digest") != generation
        or value.get("safe_to_consume") is not True
    ):
        raise SemanticDedupTransactionError(
            "semantic-dedup transaction receipt is not a committed generation"
        )
    return value


def _repair_receipt_relative(generation: str) -> str:
    return f"{ROOT}/r_{generation}.json"


def _output_observations(root: Path) -> dict[str, dict[str, Any]]:
    observations: dict[str, dict[str, Any]] = {}
    for relative in OUTPUTS:
        path = _regular_path(root, relative, allow_missing=True)
        if not path.is_file():
            observations[relative] = {
                "path": relative,
                "status": "MISSING",
            }
            continue
        raw = _read(root, relative)
        observations[relative] = {
            "path": relative,
            "status": "PRESENT",
            "sha256": _sha(raw),
            "size_bytes": len(raw),
        }
    return observations


def _target_records(
    intent: Mapping[str, Any],
    payloads: Mapping[str, bytes],
) -> dict[str, dict[str, Any]]:
    targets: dict[str, dict[str, Any]] = {}
    for relative in OUTPUTS:
        after = intent["outputs"][relative]["after"]
        raw = payloads[str(after["payload"])]
        binding = _binding(raw)
        if binding != {
            "sha256": after.get("sha256"),
            "size_bytes": after.get("size_bytes"),
        }:
            raise SemanticDedupTransactionError(
                f"semantic-dedup repair target changed: {relative}"
            )
        targets[relative] = {
            "path": relative,
            "payload": str(after["payload"]),
            **binding,
        }
    return targets


def _validate_committed_receipt_for_repair(
    intent: Mapping[str, Any],
    receipt: Mapping[str, Any],
) -> None:
    generation = str(intent["generation_digest"])
    request = _request(intent)
    if (
        receipt.get("run_id") != request.run_id
        or receipt.get("phase") != request.phase
        or receipt.get("generation_digest") != generation
        or receipt.get("intent_sha256") != request.intent_sha256
        or receipt.get("authority_binding_sha256")
        != intent.get("authority_binding_sha256")
        or receipt.get("safe_to_consume") is not True
    ):
        raise SemanticDedupTransactionError(
            "semantic-dedup committed repair authority differs from its intent"
        )
    recorded: dict[str, dict[str, Any]] = {}
    for action, key in (
        ("PHASEIO_ARM", "phaseio_arm"),
        ("PHASEIO_COMMIT", "phaseio_commit"),
        ("MUTATION_ARM", "mutation_arm"),
        ("MUTATION_FINALIZE", "mutation_finalize"),
    ):
        row = receipt.get(key)
        if not isinstance(row, Mapping):
            raise SemanticDedupTransactionError(
                f"semantic-dedup committed repair authority is missing {key}"
            )
        expected_kind, expected_status = _ATTESTATION_EXPECTATIONS[action]
        if (
            row.get("schema_version") != ATTESTATION_SCHEMA
            or row.get("run_id") != request.run_id
            or row.get("phase") != request.phase
            or row.get("generation_digest") != generation
            or row.get("action") != action
            or row.get("authority_kind") != expected_kind
            or row.get("status") != expected_status
            or not str(row.get("authority_id") or "").strip()
            or not _HEX64.fullmatch(
                str(row.get("authority_digest") or "")
            )
        ):
            raise SemanticDedupTransactionError(
                f"semantic-dedup committed repair authority is invalid: {key}"
            )
        recorded[key] = dict(row)
    if receipt != _receipt_for(intent, **recorded):
        raise SemanticDedupTransactionError(
            "semantic-dedup committed receipt is not exact for repair"
        )


def _repair_pending_for(
    intent: Mapping[str, Any],
    receipt: Mapping[str, Any],
    observations: Mapping[str, Mapping[str, Any]],
    targets: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    unsigned = {
        "schema_version": REPAIR_PENDING_SCHEMA,
        "state": "ARMED",
        "run_id": intent["run_id"],
        "phase": intent["phase"],
        "generation_digest": intent["generation_digest"],
        "intent_sha256": intent["intent_sha256"],
        "authority_binding_sha256": intent["authority_binding_sha256"],
        "transaction_receipt_sha256": receipt["receipt_sha256"],
        "observed_outputs": {
            relative: dict(observations[relative])
            for relative in OUTPUTS
        },
        "target_outputs": {
            relative: dict(targets[relative])
            for relative in OUTPUTS
        },
    }
    return _signed(unsigned, "repair_pending_sha256")


def _write_repair_pending(
    root: Path,
    pending: Mapping[str, Any],
) -> None:
    path = root / REPAIR_PENDING
    if path.exists() and (_is_linklike(path) or not path.is_file()):
        raise SemanticDedupTransactionError(
            "semantic-dedup repair pending path is unsafe"
        )
    _atomic_bytes(path, _canonical(pending))


def _load_repair_pending(root: Path) -> dict[str, Any] | None:
    path = _regular_path(root, REPAIR_PENDING, allow_missing=True)
    if not path.is_file():
        return None
    value = _load_json(root, REPAIR_PENDING)
    _require_canonical_control(root, REPAIR_PENDING, value)
    _validate_signed(
        value,
        schema=REPAIR_PENDING_SCHEMA,
        digest_key="repair_pending_sha256",
        label="semantic-dedup repair pending pointer",
    )
    return value


def _validate_repair_pending(
    pending: Mapping[str, Any],
    *,
    intent: Mapping[str, Any],
    receipt: Mapping[str, Any],
    targets: Mapping[str, Mapping[str, Any]],
) -> None:
    observations = pending.get("observed_outputs")
    pending_targets = pending.get("target_outputs")
    if (
        pending.get("state") != "ARMED"
        or pending.get("run_id") != intent.get("run_id")
        or pending.get("phase") != intent.get("phase")
        or pending.get("generation_digest")
        != intent.get("generation_digest")
        or pending.get("intent_sha256") != intent.get("intent_sha256")
        or pending.get("authority_binding_sha256")
        != intent.get("authority_binding_sha256")
        or pending.get("transaction_receipt_sha256")
        != receipt.get("receipt_sha256")
        or not isinstance(observations, Mapping)
        or set(observations) != set(OUTPUTS)
        or not isinstance(pending_targets, Mapping)
        or {
            relative: dict(pending_targets[relative])
            for relative in OUTPUTS
        }
        != {
            relative: dict(targets[relative])
            for relative in OUTPUTS
        }
    ):
        raise SemanticDedupTransactionError(
            "semantic-dedup repair pending authority changed"
        )
    for relative in OUTPUTS:
        row = observations.get(relative)
        if not isinstance(row, Mapping):
            raise SemanticDedupTransactionError(
                f"semantic-dedup repair observation is malformed: {relative}"
            )
        status = row.get("status")
        if (
            row.get("path") != relative
            or status not in {"MISSING", "PRESENT"}
            or (
                status == "MISSING"
                and set(row) != {"path", "status"}
            )
            or (
                status == "PRESENT"
                and (
                    set(row)
                    != {"path", "status", "sha256", "size_bytes"}
                    or not _HEX64.fullmatch(str(row.get("sha256") or ""))
                    or isinstance(row.get("size_bytes"), bool)
                    or not isinstance(row.get("size_bytes"), int)
                    or int(row.get("size_bytes")) < 0
                    or int(row.get("size_bytes")) > MAX_ARTIFACT_BYTES
                )
            )
        ):
            raise SemanticDedupTransactionError(
                f"semantic-dedup repair observation is invalid: {relative}"
            )


def _repair_authority_callback(
    callback: RepairAuthorityCallback,
    request: SemanticDedupAuthorityRequest,
    pending: Mapping[str, Any],
    transaction_receipt: Mapping[str, Any],
    *,
    schema: str,
    state: str,
    label: str,
) -> dict[str, Any]:
    if not callable(callback):
        raise SemanticDedupTransactionError(
            "semantic-dedup committed successor repair "
            f"{label} authority is unavailable"
        )
    try:
        value = callback(request, pending)
    except Exception as exc:
        raise SemanticDedupTransactionError(
            "semantic-dedup committed successor repair "
            f"{label} authority rejected: "
            f"{type(exc).__name__}: {exc}"
        ) from exc
    if not isinstance(value, Mapping):
        raise SemanticDedupTransactionError(
            "semantic-dedup committed successor repair "
            f"{label} authority is malformed"
        )
    try:
        row = json.loads(_canonical(dict(value)).decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise SemanticDedupTransactionError(
            "semantic-dedup committed successor repair "
            f"{label} authority cannot "
            "be normalized"
        ) from exc
    unsigned = dict(row)
    digest = str(unsigned.pop("authority_digest", "") or "")
    if (
        row.get("schema_version") != schema
        or row.get("state") != state
        or row.get("run_id") != request.run_id
        or row.get("phase") != request.phase
        or row.get("generation_digest") != request.generation_digest
        or row.get("transaction_receipt_sha256")
        != transaction_receipt.get("receipt_sha256")
        or row.get("repair_pending_sha256")
        != pending.get("repair_pending_sha256")
        or not str(row.get("work_unit_key") or "").strip()
        or not _HEX64.fullmatch(str(row.get("contract_digest") or ""))
        or not _HEX64.fullmatch(str(row.get("launch_digest") or ""))
        or not _HEX64.fullmatch(digest)
        or digest != _sha(_canonical(unsigned))
        or len(_canonical(row)) > MAX_CONTROL_BYTES
    ):
        raise SemanticDedupTransactionError(
            "semantic-dedup committed successor repair "
            f"{label} authority is not exact"
        )
    if state == "ARMED":
        if (
            row.get("intent_sha256") != request.intent_sha256
            or row.get("authority_binding_sha256")
            != _sha(_canonical(request.authority_binding))
            or set(row.get("observed_outputs") or {}) != set(OUTPUTS)
            or set(row.get("target_outputs") or {}) != set(OUTPUTS)
            or set(row.get("output_identities") or ())
            != {f"scratchpad:{relative}" for relative in OUTPUTS}
        ):
            raise SemanticDedupTransactionError(
                "semantic-dedup committed successor repair PRE arm "
                "denominator is not exact"
            )
    elif (
        not _HEX64.fullmatch(
            str(row.get("repair_arm_authority_digest") or "")
        )
        or set(row.get("restored_outputs") or {})
        != {f"scratchpad:{relative}" for relative in OUTPUTS}
    ):
        raise SemanticDedupTransactionError(
            "semantic-dedup committed successor repair POST finalize "
            "denominator is not exact"
        )
    return row


def _repair_receipt_for(
    intent: Mapping[str, Any],
    transaction_receipt: Mapping[str, Any],
    pending: Mapping[str, Any],
    repair_arm_authority: Mapping[str, Any],
    repair_finalize_authority: Mapping[str, Any],
) -> dict[str, Any]:
    unsigned = {
        "schema_version": REPAIR_RECEIPT_SCHEMA,
        "status": "RECOVERED",
        "state": "REPAIRED_ACTIVE",
        "safe_to_consume": True,
        "run_id": intent["run_id"],
        "phase": intent["phase"],
        "generation_digest": intent["generation_digest"],
        "intent_sha256": intent["intent_sha256"],
        "authority_binding_sha256": intent["authority_binding_sha256"],
        "transaction_receipt_sha256": transaction_receipt[
            "receipt_sha256"
        ],
        "repair_pending_sha256": pending["repair_pending_sha256"],
        "repair_arm_authority": dict(repair_arm_authority),
        "repair_finalize_authority": dict(repair_finalize_authority),
        "observed_outputs": {
            relative: dict(pending["observed_outputs"][relative])
            for relative in OUTPUTS
        },
        "restored_outputs": {
            relative: dict(pending["target_outputs"][relative])
            for relative in OUTPUTS
        },
    }
    return _signed(unsigned, "repair_receipt_sha256")


def _load_repair_receipt(
    root: Path,
    generation: str,
) -> dict[str, Any] | None:
    relative = _repair_receipt_relative(generation)
    path = _regular_path(root, relative, allow_missing=True)
    if not path.is_file():
        return None
    value = _load_json(root, relative)
    _require_canonical_control(root, relative, value)
    _validate_signed(
        value,
        schema=REPAIR_RECEIPT_SCHEMA,
        digest_key="repair_receipt_sha256",
        label="semantic-dedup committed successor repair receipt",
    )
    return value


def _validate_repair_receipt(
    repair_receipt: Mapping[str, Any],
    *,
    intent: Mapping[str, Any],
    transaction_receipt: Mapping[str, Any],
    targets: Mapping[str, Mapping[str, Any]],
    pending: Mapping[str, Any] | None,
    repair_arm_authority: Mapping[str, Any],
    repair_finalize_authority: Mapping[str, Any],
) -> None:
    observations = repair_receipt.get("observed_outputs")
    restored = repair_receipt.get("restored_outputs")
    if (
        repair_receipt.get("status") != "RECOVERED"
        or repair_receipt.get("state") != "REPAIRED_ACTIVE"
        or repair_receipt.get("safe_to_consume") is not True
        or repair_receipt.get("run_id") != intent.get("run_id")
        or repair_receipt.get("phase") != intent.get("phase")
        or repair_receipt.get("generation_digest")
        != intent.get("generation_digest")
        or repair_receipt.get("intent_sha256")
        != intent.get("intent_sha256")
        or repair_receipt.get("authority_binding_sha256")
        != intent.get("authority_binding_sha256")
        or repair_receipt.get("transaction_receipt_sha256")
        != transaction_receipt.get("receipt_sha256")
        or repair_receipt.get("repair_arm_authority")
        != dict(repair_arm_authority)
        or repair_receipt.get("repair_finalize_authority")
        != dict(repair_finalize_authority)
        or not _HEX64.fullmatch(
            str(repair_receipt.get("repair_pending_sha256") or "")
        )
        or not isinstance(observations, Mapping)
        or set(observations) != set(OUTPUTS)
        or not isinstance(restored, Mapping)
        or {
            relative: dict(restored[relative])
            for relative in OUTPUTS
        }
        != {
            relative: dict(targets[relative])
            for relative in OUTPUTS
        }
    ):
        raise SemanticDedupTransactionError(
            "semantic-dedup committed successor repair receipt changed"
        )
    receipt_pending = {
        "repair_pending_sha256": repair_receipt[
            "repair_pending_sha256"
        ],
        "observed_outputs": {
            relative: dict(observations[relative])
            for relative in OUTPUTS
        },
        "target_outputs": {
            relative: dict(restored[relative])
            for relative in OUTPUTS
        },
    }
    if (
        pending is not None
        and (
            pending.get("repair_pending_sha256")
            != receipt_pending["repair_pending_sha256"]
            or {
                relative: dict(pending["observed_outputs"][relative])
                for relative in OUTPUTS
            }
            != receipt_pending["observed_outputs"]
            or {
                relative: dict(pending["target_outputs"][relative])
                for relative in OUTPUTS
            }
            != receipt_pending["target_outputs"]
        )
    ):
        raise SemanticDedupTransactionError(
            "semantic-dedup repair receipt differs from pending authority"
        )
    if repair_receipt != _repair_receipt_for(
        intent,
        transaction_receipt,
        receipt_pending,
        repair_arm_authority,
        repair_finalize_authority,
    ):
        raise SemanticDedupTransactionError(
            "semantic-dedup repair receipt digest is not exact"
        )


def _repair_result(
    intent: Mapping[str, Any],
    transaction_receipt: Mapping[str, Any],
    repair_receipt: Mapping[str, Any] | None,
    *,
    repaired: bool,
    recovered: bool,
) -> SemanticDedupRepairResult:
    generation = str(intent["generation_digest"])
    return SemanticDedupRepairResult(
        run_id=str(intent["run_id"]),
        phase=str(intent["phase"]),
        generation_digest=generation,
        repaired=repaired,
        recovered=recovered,
        state=(
            "RECOVERED"
            if repaired
            else "ALREADY_RECOVERED"
            if repair_receipt is not None
            else "ALREADY_CURRENT"
        ),
        safe_to_consume=True,
        transaction_receipt_sha256=str(
            transaction_receipt["receipt_sha256"]
        ),
        repair_receipt_path=(
            _repair_receipt_relative(generation)
            if repair_receipt is not None
            else ""
        ),
        repair_receipt_sha256=(
            str(repair_receipt["repair_receipt_sha256"])
            if repair_receipt is not None
            else ""
        ),
    )


def _result(
    intent: Mapping[str, Any],
    receipt: Mapping[str, Any],
    *,
    recovered: bool,
) -> SemanticDedupTransactionResult:
    return SemanticDedupTransactionResult(
        run_id=str(intent["run_id"]),
        phase=str(intent["phase"]),
        generation_digest=str(intent["generation_digest"]),
        recovered=recovered,
        changed=bool(receipt["changed"]),
        state="COMMITTED",
        safe_to_consume=True,
        receipt_sha256=str(receipt["receipt_sha256"]),
    )


def _reconfirm_committed(
    *,
    root: Path,
    intent: Mapping[str, Any],
    payloads: Mapping[str, bytes],
    receipt: Mapping[str, Any],
    authority: SemanticDedupAuthorityCallbacks,
    recovered: bool,
) -> SemanticDedupTransactionResult:
    with _transaction_lock(root):
        _, _ = _output_state(root, intent, payloads)
        if not _all_outputs_are_post(root, intent, payloads):
            raise SemanticDedupTransactionError(
                "committed semantic-dedup outputs no longer have their postimages"
            )
        request = _request(intent)
        live = {
            "phaseio_arm": _authority_callback(
                authority.phaseio_arm, request, action="PHASEIO_ARM"
            ),
            "phaseio_commit": _authority_callback(
                authority.phaseio_commit, request, action="PHASEIO_COMMIT"
            ),
            "mutation_arm": _authority_callback(
                authority.mutation_arm, request, action="MUTATION_ARM"
            ),
            "mutation_finalize": _authority_callback(
                authority.mutation_finalize,
                request,
                action="MUTATION_FINALIZE",
            ),
        }
        for key, value in live.items():
            _compare_attestation(receipt.get(key), value, action=key)
        expected = _receipt_for(intent, **live)
        if receipt != expected:
            raise SemanticDedupTransactionError(
                "semantic-dedup committed receipt differs from its generation"
            )
        return _result(intent, receipt, recovered=recovered)


def _commit_pending(
    *,
    root: Path,
    pending: Mapping[str, Any],
    intent: Mapping[str, Any],
    payloads: Mapping[str, bytes],
    authority: SemanticDedupAuthorityCallbacks,
    recovered: bool,
    fault_hook: Callable[[str], None] | None,
) -> SemanticDedupTransactionResult:
    request = _request(intent)
    phaseio_arm = _authority_callback(
        authority.phaseio_arm, request, action="PHASEIO_ARM"
    )
    _compare_attestation(
        pending.get("phaseio_arm"), phaseio_arm, action="PHASEIO_ARM"
    )

    _, mutation_started = _output_state(root, intent, payloads)
    if not mutation_started:
        _validate_generation_sources_live(root, intent, payloads)

    mutation_arm = _authority_callback(
        authority.mutation_arm, request, action="MUTATION_ARM"
    )
    if pending.get("state") in {"ARMED", "OUTPUT_COMMITTED"}:
        _compare_attestation(
            pending.get("mutation_arm"),
            mutation_arm,
            action="MUTATION_ARM",
        )
    _boundary(fault_hook, "AFTER_MUTATION_ARM")

    if pending.get("state") == "STAGED":
        armed = _pending_for(
            intent,
            state="ARMED",
            phaseio_arm=phaseio_arm,
            phaseio_commit=None,
            mutation_arm=mutation_arm,
        )
        _write_pending(root, armed)
    else:
        armed = dict(pending)
    _boundary(fault_hook, "AFTER_PENDING_ARMED_DURABLE")

    replace_boundaries = {
        INVENTORY: "AFTER_INVENTORY_REPLACED",
        RECORDS: "AFTER_RECORDS_REPLACED",
        APPLIED_RECEIPT: "AFTER_APPLIED_RECEIPT_REPLACED",
        ABSORBED_MAP: "AFTER_ABSORBED_MAP_REPLACED",
        DEDUPED_INVENTORY: "AFTER_DEDUPED_INVENTORY_REPLACED",
    }
    with _transaction_lock(root):
        _, mutation_started = _output_state(root, intent, payloads)
        if not mutation_started:
            # This validation occurs after the arm callback and its fault
            # boundary, under the publication lock, immediately before the
            # first root output changes.
            _validate_generation_sources_live(root, intent, payloads)

        for relative in OUTPUTS:
            output = intent["outputs"][relative]
            before_row = output["before"]
            after = payloads[str(output["after"]["payload"])]
            path = _regular_path(root, relative, allow_missing=True)
            if path.is_file() and _read(root, relative) == after:
                pass
            elif before_row["status"] == "MISSING" and not path.exists():
                _exclusive_bytes(
                    path,
                    after,
                    label=f"semantic-dedup output {relative}",
                    limit=MAX_ARTIFACT_BYTES,
                )
            elif before_row["status"] == "PRESENT" and path.is_file():
                before = payloads[str(before_row["payload"])]
                if _read(root, relative) != before:
                    raise SemanticDedupTransactionError(
                        f"{relative}: arbitrary third state during publication"
                    )
                if before != after:
                    _atomic_bytes(path, after)
            else:
                raise SemanticDedupTransactionError(
                    f"{relative}: arbitrary present/missing state during "
                    "publication"
                )
            if not path.is_file() or _read(root, relative) != after:
                raise SemanticDedupTransactionError(
                    f"{relative}: output postimage was not durable"
                )
            _boundary(fault_hook, replace_boundaries[relative])

        _output_state(root, intent, payloads)
        if not _all_outputs_are_post(root, intent, payloads):
            raise SemanticDedupTransactionError(
                "semantic-dedup five-output successor is not fully published"
            )
        _boundary(fault_hook, "AFTER_PAIR_VERIFIED")

        # A hook/concurrent writer after verification must not be granted
        # PhaseIO OUTPUT_COMMITTED authority.
        if not _all_outputs_are_post(root, intent, payloads):
            raise SemanticDedupTransactionError(
                "semantic-dedup outputs changed before PhaseIO commit"
            )
        phaseio_commit = _authority_callback(
            authority.phaseio_commit, request, action="PHASEIO_COMMIT"
        )
        if pending.get("state") == "OUTPUT_COMMITTED":
            _compare_attestation(
                pending.get("phaseio_commit"),
                phaseio_commit,
                action="PHASEIO_COMMIT",
            )
        output_committed = _pending_for(
            intent,
            state="OUTPUT_COMMITTED",
            phaseio_arm=phaseio_arm,
            phaseio_commit=phaseio_commit,
            mutation_arm=mutation_arm,
        )
        _write_pending(root, output_committed)
        _boundary(fault_hook, "AFTER_PHASEIO_COMMIT")

        # PhaseIO now owns the exact five-output successor.  Semantic
        # finalization closes the already-armed predecessor transition; it
        # does not substitute for terminal PhaseIO output authority.
        if not _all_outputs_are_post(root, intent, payloads):
            raise SemanticDedupTransactionError(
                "semantic-dedup outputs changed after PhaseIO commit"
            )
        mutation_finalize = _authority_callback(
            authority.mutation_finalize,
            request,
            action="MUTATION_FINALIZE",
        )
        _boundary(fault_hook, "AFTER_MUTATION_FINALIZE")

        if not _all_outputs_are_post(root, intent, payloads):
            raise SemanticDedupTransactionError(
                "semantic-dedup outputs changed before receipt publication"
            )
        receipt = _receipt_for(
            intent,
            phaseio_arm=phaseio_arm,
            phaseio_commit=phaseio_commit,
            mutation_arm=mutation_arm,
            mutation_finalize=mutation_finalize,
        )
        receipt_path = root / _receipt_relative(
            str(intent["generation_digest"])
        )
        _exclusive_bytes(
            receipt_path,
            _canonical(receipt),
            label="semantic-dedup committed receipt",
        )
        _boundary(fault_hook, "AFTER_RECEIPT_DURABLE")

        # Do not erase the recovery pointer if any root output or the receipt
        # was changed at the final fault boundary.
        if not _all_outputs_are_post(root, intent, payloads):
            raise SemanticDedupTransactionError(
                "semantic-dedup outputs changed after receipt publication"
            )
        if _load_receipt(root, str(intent["generation_digest"])) != receipt:
            raise SemanticDedupTransactionError(
                "semantic-dedup receipt changed before pending clear"
            )
        pending_path = _pending_path(root)
        if not pending_path.is_file():
            raise SemanticDedupTransactionError(
                "semantic-dedup pending pointer vanished before commit"
            )
        pending_path.unlink()
        _fsync_parent(root / PENDING)
        _boundary(fault_hook, "AFTER_PENDING_CLEARED")

        if not _all_outputs_are_post(root, intent, payloads):
            raise SemanticDedupTransactionError(
                "semantic-dedup outputs changed after transaction commit"
            )
    return _result(intent, receipt, recovered=recovered)


def _recover_loaded(
    *,
    root: Path,
    run_id: str,
    phase: str,
    authority_binding: Mapping[str, Any],
    authority: SemanticDedupAuthorityCallbacks,
    pending: Mapping[str, Any],
    expected_generation: str | None,
    fault_hook: Callable[[str], None] | None,
) -> SemanticDedupTransactionResult:
    generation = str(pending.get("generation_digest") or "")
    if expected_generation is not None and generation != expected_generation:
        raise SemanticDedupTransactionError(
            "pending semantic-dedup generation differs from requested postimages"
        )
    intent, payloads = _validate_generation(root, generation)
    _validate_pending_intent(
        pending,
        intent,
        run_id=run_id,
        phase=phase,
        authority_binding=authority_binding,
    )
    receipt = _load_receipt(root, generation)
    if receipt is not None:
        result = _reconfirm_committed(
            root=root,
            intent=intent,
            payloads=payloads,
            receipt=receipt,
            authority=authority,
            recovered=True,
        )
        with _transaction_lock(root):
            if not _all_outputs_are_post(root, intent, payloads):
                raise SemanticDedupTransactionError(
                    "semantic-dedup outputs changed before recovered pending clear"
                )
            pending_path = _pending_path(root)
            if pending_path.is_file():
                pending_path.unlink()
                _fsync_parent(root / PENDING)
        return result
    return _commit_pending(
        root=root,
        pending=pending,
        intent=intent,
        payloads=payloads,
        authority=authority,
        recovered=True,
        fault_hook=fault_hook,
    )


def repair_committed_semantic_dedup_transaction(
    *,
    scratchpad: Path,
    run_id: str,
    phase: str,
    authority_binding: Mapping[str, Any],
    authority: SemanticDedupAuthorityCallbacks,
    repair_arm_authority: RepairAuthorityCallback,
    repair_finalize_authority: RepairAuthorityCallback,
    fault_hook: Callable[[str], None] | None = None,
) -> SemanticDedupRepairResult:
    """Restore one committed successor from its authenticated postimages.

    This is deliberately narrower than ordinary crash recovery.  It operates
    only after a committed transaction receipt exists, selects exactly one
    generation by the requested run/phase, and republishes only the five
    postimages already authorized by that receipt.  An immutable repair
    receipt records the observed corrupt/missing states.  If the private
    generation, receipt, authority binding, or live authority callbacks do not
    validate exactly, no repair bytes are published.
    """

    root = _validate_root(Path(scratchpad))
    run, phase_name, binding = _normalized_context(
        run_id, phase, authority_binding
    )
    generation = _existing_context_generation(
        root, run_id=run, phase=phase_name
    )
    if generation is None:
        raise SemanticDedupTransactionError(
            "semantic-dedup committed successor repair generation is absent"
        )
    intent, payloads = _validate_generation(root, generation)
    if (
        intent.get("run_id") != run
        or intent.get("phase") != phase_name
        or intent.get("authority_binding") != binding
    ):
        raise SemanticDedupTransactionError(
            "semantic-dedup committed successor repair context changed"
        )
    transaction_receipt = _load_receipt(root, generation)
    if transaction_receipt is None:
        raise SemanticDedupTransactionError(
            "semantic-dedup committed successor repair receipt is absent"
        )
    _validate_committed_receipt_for_repair(intent, transaction_receipt)
    targets = _target_records(intent, payloads)
    repair_relative = _repair_receipt_relative(generation)

    repair_receipt = _load_repair_receipt(root, generation)
    pending = _load_repair_pending(root)
    if pending is not None:
        _validate_repair_pending(
            pending,
            intent=intent,
            receipt=transaction_receipt,
            targets=targets,
        )
    if repair_receipt is not None:
        authority_pending = (
            pending
            if pending is not None
            else {
                "repair_pending_sha256": repair_receipt.get(
                    "repair_pending_sha256"
                ),
                "transaction_receipt_sha256": transaction_receipt.get(
                    "receipt_sha256"
                ),
                "observed_outputs": repair_receipt.get(
                    "observed_outputs"
                ),
                "target_outputs": repair_receipt.get(
                    "restored_outputs"
                ),
            }
        )
        live_repair_arm = _repair_authority_callback(
            repair_arm_authority,
            _request(intent),
            authority_pending,
            transaction_receipt,
            schema=(
                "plamen.exact_committed_output_repair_arm_authority.v1"
            ),
            state="ARMED",
            label="PRE arm",
        )
        live_repair_finalize = _repair_authority_callback(
            repair_finalize_authority,
            _request(intent),
            authority_pending,
            transaction_receipt,
            schema=(
                "plamen.exact_committed_output_repair_finalize_authority.v1"
            ),
            state="REPAIRED_ACTIVE",
            label="POST finalize",
        )
        _validate_repair_receipt(
            repair_receipt,
            intent=intent,
            transaction_receipt=transaction_receipt,
            targets=targets,
            pending=pending,
            repair_arm_authority=live_repair_arm,
            repair_finalize_authority=live_repair_finalize,
        )
        result = _reconfirm_committed(
            root=root,
            intent=intent,
            payloads=payloads,
            receipt=transaction_receipt,
            authority=authority,
            recovered=True,
        )
        if not result.safe_to_consume:
            raise SemanticDedupTransactionError(
                "semantic-dedup repaired successor is not consumable"
            )
        if pending is not None:
            with _transaction_lock(root):
                current_pending = _load_repair_pending(root)
                if current_pending != pending:
                    raise SemanticDedupTransactionError(
                        "semantic-dedup repair pending changed before clear"
                    )
                pending_path = _regular_path(
                    root, REPAIR_PENDING, allow_missing=False
                )
                pending_path.unlink()
                _fsync_parent(pending_path)
        return _repair_result(
            intent,
            transaction_receipt,
            repair_receipt,
            repaired=False,
            recovered=True,
        )

    if pending is None:
        already_current = False
        with _transaction_lock(root):
            observations = _output_observations(root)
            if _all_outputs_are_post(root, intent, payloads):
                already_current = True
            else:
                pending = _repair_pending_for(
                    intent,
                    transaction_receipt,
                    observations,
                    targets,
                )
                _write_repair_pending(root, pending)
        if already_current:
            current = _reconfirm_committed(
                root=root,
                intent=intent,
                payloads=payloads,
                receipt=transaction_receipt,
                authority=authority,
                recovered=True,
            )
            if not current.safe_to_consume:
                raise SemanticDedupTransactionError(
                    "semantic-dedup current successor is not consumable"
                )
            return _repair_result(
                intent,
                transaction_receipt,
                None,
                repaired=False,
                recovered=True,
            )
        _repair_boundary(fault_hook, "AFTER_REPAIR_PENDING_DURABLE")

    _validate_repair_pending(
        pending,
        intent=intent,
        receipt=transaction_receipt,
        targets=targets,
    )
    live_repair_arm = _repair_authority_callback(
        repair_arm_authority,
        _request(intent),
        pending,
        transaction_receipt,
        schema="plamen.exact_committed_output_repair_arm_authority.v1",
        state="ARMED",
        label="PRE arm",
    )
    _repair_boundary(fault_hook, "AFTER_REPAIR_AUTHORITY_ARMED")
    replacement_boundaries = {
        INVENTORY: "AFTER_REPAIR_INVENTORY_REPLACED",
        RECORDS: "AFTER_REPAIR_RECORDS_REPLACED",
        APPLIED_RECEIPT: "AFTER_REPAIR_APPLIED_RECEIPT_REPLACED",
        ABSORBED_MAP: "AFTER_REPAIR_ABSORBED_MAP_REPLACED",
        DEDUPED_INVENTORY: "AFTER_REPAIR_DEDUPED_INVENTORY_REPLACED",
    }
    with _transaction_lock(root):
        current_pending = _load_repair_pending(root)
        if current_pending != pending:
            raise SemanticDedupTransactionError(
                "semantic-dedup repair pending changed before publication"
            )
        for relative in OUTPUTS:
            path = _regular_path(root, relative, allow_missing=True)
            target = payloads[
                str(intent["outputs"][relative]["after"]["payload"])
            ]
            observed = pending["observed_outputs"][relative]
            if path.is_file():
                current = _read(root, relative)
                current_is_observed = bool(
                    observed.get("status") == "PRESENT"
                    and _binding(current)
                    == {
                        "sha256": observed.get("sha256"),
                        "size_bytes": observed.get("size_bytes"),
                    }
                )
                if current == target:
                    current_is_observed = True
            else:
                current_is_observed = observed.get("status") == "MISSING"
            if not current_is_observed:
                raise SemanticDedupTransactionError(
                    f"{relative}: arbitrary third state during committed "
                    "successor repair"
                )
            if not path.is_file() or _read(root, relative) != target:
                _atomic_bytes(path, target)
            if not path.is_file() or _read(root, relative) != target:
                raise SemanticDedupTransactionError(
                    f"{relative}: repaired postimage was not durable"
                )
            _repair_boundary(fault_hook, replacement_boundaries[relative])
        if not _all_outputs_are_post(root, intent, payloads):
            raise SemanticDedupTransactionError(
                "semantic-dedup repaired five-output successor is incomplete"
            )
    _repair_boundary(fault_hook, "AFTER_REPAIR_OUTPUTS_VERIFIED")

    live_repair_finalize = _repair_authority_callback(
        repair_finalize_authority,
        _request(intent),
        pending,
        transaction_receipt,
        schema=(
            "plamen.exact_committed_output_repair_finalize_authority.v1"
        ),
        state="REPAIRED_ACTIVE",
        label="POST finalize",
    )
    reconfirmed = _reconfirm_committed(
        root=root,
        intent=intent,
        payloads=payloads,
        receipt=transaction_receipt,
        authority=authority,
        recovered=True,
    )
    if not reconfirmed.safe_to_consume:
        raise SemanticDedupTransactionError(
            "semantic-dedup repaired successor failed authority reconfirmation"
        )
    _repair_boundary(fault_hook, "AFTER_REPAIR_AUTHORITY_RECONFIRMED")

    repair_receipt = _repair_receipt_for(
        intent,
        transaction_receipt,
        pending,
        live_repair_arm,
        live_repair_finalize,
    )
    with _transaction_lock(root):
        if not _all_outputs_are_post(root, intent, payloads):
            raise SemanticDedupTransactionError(
                "semantic-dedup repaired outputs changed before receipt"
            )
        current_pending = _load_repair_pending(root)
        if current_pending != pending:
            raise SemanticDedupTransactionError(
                "semantic-dedup repair pending changed before receipt"
            )
        _exclusive_bytes(
            root / repair_relative,
            _canonical(repair_receipt),
            label="semantic-dedup committed successor repair receipt",
        )
        _repair_boundary(fault_hook, "AFTER_REPAIR_RECEIPT_DURABLE")
        if _load_repair_receipt(root, generation) != repair_receipt:
            raise SemanticDedupTransactionError(
                "semantic-dedup repair receipt changed before pending clear"
            )
        pending_path = _regular_path(
            root, REPAIR_PENDING, allow_missing=False
        )
        pending_path.unlink()
        _fsync_parent(pending_path)
    _repair_boundary(fault_hook, "AFTER_REPAIR_PENDING_CLEARED")
    return _repair_result(
        intent,
        transaction_receipt,
        repair_receipt,
        repaired=True,
        recovered=False,
    )


def apply_semantic_dedup_transaction(
    *,
    scratchpad: Path,
    run_id: str,
    phase: str,
    post_inventory: bytes,
    post_records: bytes,
    exact_inputs: Sequence[str],
    proposal_inputs: Sequence[str],
    expected_inputs: Sequence[Mapping[str, Any]],
    expected_output_prestate: Sequence[Mapping[str, Any]],
    staged_sidecars: Mapping[str, bytes],
    authority_binding: Mapping[str, Any],
    authority: SemanticDedupAuthorityCallbacks,
    fault_hook: Callable[[str], None] | None = None,
) -> SemanticDedupTransactionResult:
    """Apply or resume one exact L1 semantic-dedup canonical successor."""

    root = _validate_root(Path(scratchpad))
    run, phase_name, binding = _normalized_context(
        run_id, phase, authority_binding
    )
    inputs = _normalize_expected_inputs(exact_inputs, expected_inputs)
    output_prestate = _normalize_output_prestate(
        expected_output_prestate, inputs
    )
    proposals = _unique_relatives(
        proposal_inputs, label="proposal_inputs"
    )
    exact_paths = {str(row["path"]) for row in inputs}
    if not set(proposals).issubset(exact_paths):
        raise SemanticDedupTransactionError(
            "semantic-dedup proposal inputs are not a subset of exact inputs"
        )
    post_i = bytes(post_inventory)
    post_r = bytes(post_records)
    _validate_post_pair(post_i, post_r)
    sidecars = _normalize_sidecars(staged_sidecars, post_i)
    intent = _intent_for(
        run_id=run,
        phase=phase_name,
        authority_binding=binding,
        expected_inputs=inputs,
        expected_output_prestate=output_prestate,
        proposal_inputs=proposals,
        post_inventory=post_i,
        post_records=post_r,
        staged_sidecars=sidecars,
    )
    generation = str(intent["generation_digest"])
    existing_generation = _existing_context_generation(
        root, run_id=run, phase=phase_name
    )
    if existing_generation is not None and existing_generation != generation:
        raise SemanticDedupTransactionError(
            "semantic-dedup run/phase is already bound to another generation"
        )

    pending = _load_pending(root)
    if pending is not None:
        return _recover_loaded(
            root=root,
            run_id=run,
            phase=phase_name,
            authority_binding=binding,
            authority=authority,
            pending=pending,
            expected_generation=generation,
            fault_hook=fault_hook,
        )

    receipt = _load_receipt(root, generation)
    generation_path = root / _generation_relative(generation)
    if receipt is not None:
        loaded_intent, payloads = _validate_generation(root, generation)
        if loaded_intent != intent:
            raise SemanticDedupTransactionError(
                "committed semantic-dedup intent differs from requested inputs"
            )
        return _reconfirm_committed(
            root=root,
            intent=loaded_intent,
            payloads=payloads,
            receipt=receipt,
            authority=authority,
            recovered=True,
        )
    if generation_path.exists():
        loaded_intent, _ = _validate_generation(root, generation)
        if loaded_intent != intent:
            raise SemanticDedupTransactionError(
                "staged semantic-dedup generation differs from requested inputs"
            )

    input_raw = _validate_live_inputs(root, inputs)
    output_pre_raw = _validate_live_output_prestate(root, output_prestate)
    _boundary(fault_hook, "AFTER_INPUTS_VALIDATED")
    request = _request(intent)
    phaseio_arm = _authority_callback(
        authority.phaseio_arm, request, action="PHASEIO_ARM"
    )
    _boundary(fault_hook, "AFTER_PHASEIO_ARM")
    _publish_generation(
        root,
        intent,
        input_raw,
        output_pre_raw,
        post_i,
        post_r,
        sidecars,
    )
    _boundary(fault_hook, "AFTER_GENERATION_DURABLE")

    # Close source drift after generation computation/authority work.  No
    # public canonical byte has changed yet.
    _validate_live_inputs(root, inputs)
    _validate_live_output_prestate(root, output_prestate)
    staged = _pending_for(
        intent,
        state="STAGED",
        phaseio_arm=phaseio_arm,
        phaseio_commit=None,
        mutation_arm=None,
    )
    _write_pending(root, staged)
    _boundary(fault_hook, "AFTER_PENDING_STAGED_DURABLE")
    return _commit_pending(
        root=root,
        pending=staged,
        intent=intent,
        payloads=_validate_generation(root, generation)[1],
        authority=authority,
        recovered=False,
        fault_hook=fault_hook,
    )


def recover_semantic_dedup_transaction(
    *,
    scratchpad: Path,
    run_id: str,
    phase: str,
    authority_binding: Mapping[str, Any],
    authority: SemanticDedupAuthorityCallbacks,
    fault_hook: Callable[[str], None] | None = None,
) -> SemanticDedupTransactionResult | None:
    """Recover the signed pending generation without recomputing postimages."""

    root = _validate_root(Path(scratchpad))
    run, phase_name, binding = _normalized_context(
        run_id, phase, authority_binding
    )
    pending = _load_pending(root)
    if pending is None:
        return None
    return _recover_loaded(
        root=root,
        run_id=run,
        phase=phase_name,
        authority_binding=binding,
        authority=authority,
        pending=pending,
        expected_generation=None,
        fault_hook=fault_hook,
    )


__all__ = [
    "ABSORBED_MAP",
    "APPLIED_RECEIPT",
    "ATTESTATION_SCHEMA",
    "DEDUPED_INVENTORY",
    "FAILPOINTS",
    "INVENTORY",
    "OUTPUTS",
    "PAIR",
    "PENDING",
    "PENDING_SCHEMA",
    "REPAIR_FAILPOINTS",
    "REPAIR_PENDING",
    "REPAIR_PENDING_SCHEMA",
    "REPAIR_RECEIPT_SCHEMA",
    "RECEIPT_SCHEMA",
    "RECORDS",
    "ROOT",
    "SCHEMA",
    "SIDECARS",
    "SemanticDedupAuthorityCallbacks",
    "SemanticDedupAuthorityRequest",
    "SemanticDedupRepairResult",
    "SemanticDedupTransactionError",
    "SemanticDedupTransactionResult",
    "apply_semantic_dedup_transaction",
    "capture_semantic_dedup_inputs",
    "capture_semantic_dedup_output_prestate",
    "repair_committed_semantic_dedup_transaction",
    "recover_semantic_dedup_transaction",
]
