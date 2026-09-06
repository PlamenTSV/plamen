"""Immutable, PhaseIO-backed lifecycle authority for niche agent actions.

``niche_identity_debt.json`` and ``niche_promotion_receipt.md`` are useful
human-readable projections, but both are mutable.  This module owns the
append-only authority beneath them.  Every generation binds one audit/run,
the complete retained source namespace, the exact action denominator, the
post-promotion inventory snapshot, the prior committed generation, and an
ordered transition for every live or historically unresolved action.

The producer of a niche action cannot resolve its own prior history.  A
source-authored ``supersedes`` field is retained as evidence but never grants
drop/clean authority.  Missing, malformed, stale, or cross-run authority is a
blocking error; callers may project that error as haltless human-review debt,
but must never interpret it as clean.
"""
from __future__ import annotations

import hashlib
import inspect
import json
import os
from pathlib import Path
import re
import stat
import tempfile
import threading
from typing import Any, Iterable, Mapping, Sequence

from artifact_ledger import (
    ArtifactLedgerError,
    read_artifact_ledger,
    record_work_unit_artifacts,
    record_work_unit_inputs,
    validate_work_unit_artifacts,
)
from bounded_artifact_io import read_bounded_regular_bytes
from phase_io_contracts import ArtifactSpec, LaunchSpec, PhaseIOContract


NICHE_LIFECYCLE_SCHEMA = "plamen.niche.lifecycle.v1"
NICHE_LIFECYCLE_CAS_DIR = "_niche_lifecycle_cas"
NICHE_LIFECYCLE_HEAD = "_niche_lifecycle_head.json"
NICHE_LIFECYCLE_TRANSACTION = "_niche_lifecycle_transaction.json"
_HEAD_SCHEMA = "plamen.niche.lifecycle.head.v1"
_TRANSACTION_SCHEMA = "plamen.niche.lifecycle.transaction.v1"
_MAX_GENERATION_BYTES = 32 * 1024 * 1024
_MAX_GENERATIONS = 4096
_MAX_ACTIONS = 16384
_MAX_HISTORY = 131072
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
_ACTION_ID_RE = re.compile(r"^NACT-[0-9A-F]{24}$", re.ASCII)
_DIMENSION_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]*$", re.ASCII)
_CAS_NAME_RE = re.compile(r"^[0-9a-f]{64}\.json$", re.ASCII)
_WINDOWS_REPARSE_POINT = 0x400

_GENERATION_FIELDS = frozenset({
    "schema_version",
    "audit_instance_id",
    "run_id",
    "pipeline",
    "mode",
    "ecosystem",
    "backend",
    "phase",
    "producer",
    "context_sha256",
    "attempt_ordinal",
    "previous_generation_sha256",
    "source_capture",
    "inventory_capture",
    "action_denominator_sha256",
    "actions",
    "action_history",
    "delivery_records",
    "transitions",
    "history",
    "independent_dispositions",
    "summary",
    "generation_sha256",
})
_CONTEXT_FIELDS = (
    "audit_instance_id", "run_id", "pipeline", "mode", "ecosystem",
    "backend", "phase", "producer",
)
_ACTION_FIELDS = frozenset({
    "source_action_identity",
    "source_file",
    "source_sha256",
    "source_byte_start",
    "source_byte_end",
    "source_block_sha256",
    "normalized_local_id",
    "action_record_sha256",
    "action_status",
    "identity_debt",
    "supersedes_source_action_identities",
    "action_payload",
})
_ACTION_PAYLOAD_FIELDS = frozenset({
    "source_file",
    "source_sha256",
    "source_size_bytes",
    "normalized_local_id",
    "raw_id",
    "source_byte_start",
    "source_byte_end",
    "source_block_sha256",
    "source_block_size_bytes",
    "exact_block_capture",
    "exact_block_bytes_b64",
    "source_action_identity",
    "identity_status",
    "identity_debt",
    "missing_required_fields",
    "supersedes_source_action_identities",
    "action_status",
    "quarantine",
    "action_record_sha256",
})
_TRANSITION_FIELDS = frozenset({
    "attempt_ordinal",
    "sequence",
    "source_action_identity",
    "source_file",
    "source_action_record_sha256",
    "state",
    "blocking",
    "debt_codes",
    "inventory_referents",
    "independent_disposition_digest",
    "transition_sha256",
})
_SOURCE_CAPTURE_FIELDS = frozenset({
    "namespace",
    "namespace_sha256",
    "source_snapshots",
    "source_snapshot_set_sha256",
})
_SOURCE_SNAPSHOT_FIELDS = frozenset({
    "source_file", "source_sha256", "source_size_bytes",
    "source_physical_identity",
})
_DELIVERY_RECORD_FIELDS = frozenset({
    "source_action_identity",
    "source_file",
    "normalized_local_id",
    "source_sha256",
    "source_byte_start",
    "source_byte_end",
    "source_block_sha256",
    "inventory_id",
    "inventory_block_sha256",
    "delivery_record_sha256",
})
_INVENTORY_CAPTURE_FIELDS = frozenset({
    "present", "sha256", "size_bytes", "physical_identity",
    "referent_set_sha256",
})
_SUMMARY_FIELDS = frozenset({
    "action_count",
    "action_history_count",
    "transition_count",
    "history_count",
    "blocking_count",
    "clean_delivered_count",
    "removed_count",
    "source_authored_supersession_count",
    "delivery_record_count",
})

_STATES = frozenset({
    "CURRENT_ACTION_DEBT",
    "DELIVERED_CLEAN_ACTION",
    "UNDELIVERED_CLEAN_ACTION",
    "SOURCE_ACTION_REMOVED",
    "DELIVERED_ACTION_REMOVED",
})


class NicheLifecycleAuthorityError(RuntimeError):
    """The lifecycle chain cannot provide current clean authority."""


class _InventoryPublicationCapability:
    """Opaque, process-local, one-use authority for one inventory publication."""

    __slots__ = ()


_INVENTORY_PUBLICATION_CAPABILITIES: dict[
    int, tuple[_InventoryPublicationCapability, dict[str, Any]]
] = {}
_INVENTORY_PUBLICATION_CAPABILITY_LOCK = threading.RLock()


def _canonical_bytes(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise NicheLifecycleAuthorityError(
            f"lifecycle value is not canonical JSON: {exc}"
        ) from exc


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _context_from_row(row: Mapping[str, Any]) -> dict[str, str]:
    return {field: str(row[field]) for field in _CONTEXT_FIELDS}


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise NicheLifecycleAuthorityError(
                f"duplicate lifecycle JSON key: {key}"
            )
        value[key] = item
    return value


def _reject_constant(value: str) -> None:
    raise NicheLifecycleAuthorityError(
        f"non-finite lifecycle JSON value: {value}"
    )


def _strict_json(raw: bytes, *, limit: int = _MAX_GENERATION_BYTES) -> dict[str, Any]:
    if len(raw) > limit:
        raise NicheLifecycleAuthorityError(
            f"lifecycle artifact exceeds {limit} bytes"
        )
    try:
        value = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_strict_object,
            parse_constant=_reject_constant,
        )
    except NicheLifecycleAuthorityError:
        raise
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise NicheLifecycleAuthorityError(
            "lifecycle artifact is not strict UTF-8 JSON"
        ) from exc
    if not isinstance(value, dict):
        raise NicheLifecycleAuthorityError("lifecycle artifact is not an object")
    return value


def _text(value: object, *, field: str, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or value != value.strip():
        raise NicheLifecycleAuthorityError(f"{field} is not canonical text")
    if not allow_empty and not value:
        raise NicheLifecycleAuthorityError(f"{field} is empty")
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise NicheLifecycleAuthorityError(f"{field} contains control characters")
    return value


def _sha(value: object, *, field: str, allow_empty: bool = False) -> str:
    text = _text(value, field=field, allow_empty=allow_empty)
    if text or not allow_empty:
        if not _HEX64_RE.fullmatch(text):
            raise NicheLifecycleAuthorityError(f"{field} is not a SHA-256")
    return text


def _ordered_unique_text(
    value: object, *, field: str, key=None, allow_empty: bool = True
) -> list[str]:
    if not isinstance(value, list):
        raise NicheLifecycleAuthorityError(f"{field} is not an array")
    rows = [_text(item, field=f"{field} item") for item in value]
    if not allow_empty and not rows:
        raise NicheLifecycleAuthorityError(f"{field} is empty")
    if len(rows) != len(set(rows)):
        raise NicheLifecycleAuthorityError(f"{field} contains duplicate values")
    expected = sorted(rows, key=key)
    if rows != expected:
        raise NicheLifecycleAuthorityError(f"{field} is not in canonical order")
    return rows


def _action_sort_key(row: Mapping[str, Any]) -> tuple[object, ...]:
    return (
        str(row.get("source_file") or "").casefold(),
        str(row.get("source_file") or ""),
        int(row.get("source_byte_start") or 0),
        int(row.get("source_byte_end") or 0),
        str(row.get("normalized_local_id") or ""),
        str(row.get("source_action_identity") or ""),
    )


def _transition_sort_key(row: Mapping[str, Any]) -> tuple[object, ...]:
    return (
        str(row.get("source_file") or "").casefold(),
        str(row.get("source_file") or ""),
        str(row.get("source_action_identity") or ""),
        str(row.get("state") or ""),
        str(row.get("transition_sha256") or ""),
    )


def _history_sort_key(row: Mapping[str, Any]) -> tuple[object, ...]:
    return (
        int(row.get("attempt_ordinal") or 0),
        int(row.get("sequence") or 0),
        str(row.get("transition_sha256") or ""),
    )


def _normalize_source_capture(value: object) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != _SOURCE_CAPTURE_FIELDS:
        raise NicheLifecycleAuthorityError("source capture fields are not exact")
    namespace = _ordered_unique_text(
        value["namespace"],
        field="source namespace",
        key=lambda item: (item.casefold(), item),
    )
    if len(namespace) > _MAX_ACTIONS or len(namespace) != len(
        {item.casefold() for item in namespace}
    ):
        raise NicheLifecycleAuthorityError("source namespace is ambiguous or over limit")
    for name in namespace:
        if (
            Path(name).name != name
            or not name.isascii()
            or not re.fullmatch(r"niche_[A-Za-z0-9_.-]+_findings\.md", name)
        ):
            raise NicheLifecycleAuthorityError(
                f"source namespace member is invalid: {name!r}"
            )
    snapshots = value["source_snapshots"]
    if not isinstance(snapshots, list) or len(snapshots) != len(namespace):
        raise NicheLifecycleAuthorityError(
            "source snapshot denominator does not match namespace"
        )
    normalized: list[dict[str, Any]] = []
    for item in snapshots:
        if not isinstance(item, Mapping) or set(item) != _SOURCE_SNAPSHOT_FIELDS:
            raise NicheLifecycleAuthorityError("source snapshot fields are not exact")
        name = _text(item["source_file"], field="source snapshot file")
        sha = _sha(item["source_sha256"], field="source snapshot SHA-256")
        size = item["source_size_bytes"]
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            raise NicheLifecycleAuthorityError("source snapshot size is invalid")
        physical = item["source_physical_identity"]
        if (
            not isinstance(physical, list)
            or not physical
            or any(
                not isinstance(value, int) or isinstance(value, bool) or value < 0
                for value in physical
            )
        ):
            raise NicheLifecycleAuthorityError(
                "source snapshot physical identity is invalid"
            )
        normalized.append({
            "source_file": name,
            "source_sha256": sha,
            "source_size_bytes": size,
            "source_physical_identity": list(physical),
        })
    if [row["source_file"] for row in normalized] != namespace:
        raise NicheLifecycleAuthorityError("source snapshots are not in namespace order")
    expected_namespace_sha = _digest({"namespace": namespace})
    if value["namespace_sha256"] != expected_namespace_sha:
        raise NicheLifecycleAuthorityError("source namespace digest mismatch")
    expected_set_sha = _digest({"source_snapshots": normalized})
    if value["source_snapshot_set_sha256"] != expected_set_sha:
        raise NicheLifecycleAuthorityError("source snapshot set digest mismatch")
    return {
        "namespace": namespace,
        "namespace_sha256": expected_namespace_sha,
        "source_snapshots": normalized,
        "source_snapshot_set_sha256": expected_set_sha,
    }


def _normalize_delivery_record(value: object) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != _DELIVERY_RECORD_FIELDS:
        raise NicheLifecycleAuthorityError("delivery record fields are not exact")
    row = dict(value)
    identity = _text(
        row["source_action_identity"], field="delivery action identity"
    )
    if not _ACTION_ID_RE.fullmatch(identity):
        raise NicheLifecycleAuthorityError("delivery action identity is invalid")
    source_file = _text(row["source_file"], field="delivery source file")
    if Path(source_file).name != source_file:
        raise NicheLifecycleAuthorityError("delivery source file is invalid")
    local_id = _text(row["normalized_local_id"], field="delivery local ID")
    source_sha = _sha(row["source_sha256"], field="delivery source SHA-256")
    block_sha = _sha(
        row["source_block_sha256"], field="delivery source block SHA-256"
    )
    inventory_id = _text(row["inventory_id"], field="delivery inventory ID")
    if re.fullmatch(r"INV-[0-9]+", inventory_id, re.ASCII) is None:
        raise NicheLifecycleAuthorityError("delivery inventory ID is invalid")
    inventory_block_sha = _sha(
        row["inventory_block_sha256"],
        field="delivery inventory block SHA-256",
    )
    start = row["source_byte_start"]
    end = row["source_byte_end"]
    if (
        not isinstance(start, int) or isinstance(start, bool)
        or not isinstance(end, int) or isinstance(end, bool)
        or start < 0 or end <= start
    ):
        raise NicheLifecycleAuthorityError("delivery source range is invalid")
    normalized = {
        "source_action_identity": identity,
        "source_file": source_file,
        "normalized_local_id": local_id,
        "source_sha256": source_sha,
        "source_byte_start": start,
        "source_byte_end": end,
        "source_block_sha256": block_sha,
        "inventory_id": inventory_id,
        "inventory_block_sha256": inventory_block_sha,
    }
    if row["delivery_record_sha256"] != _digest(normalized):
        raise NicheLifecycleAuthorityError("delivery record digest mismatch")
    normalized["delivery_record_sha256"] = row["delivery_record_sha256"]
    return normalized


def _delivery_sort_key(row: Mapping[str, Any]) -> tuple[str, str]:
    return (
        str(row.get("source_action_identity") or ""),
        str(row.get("inventory_id") or ""),
    )


def _normalize_inventory_capture(value: object) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != _INVENTORY_CAPTURE_FIELDS:
        raise NicheLifecycleAuthorityError("inventory capture fields are not exact")
    present = value["present"]
    size = value["size_bytes"]
    if not isinstance(present, bool):
        raise NicheLifecycleAuthorityError("inventory presence is not boolean")
    if not isinstance(size, int) or isinstance(size, bool) or size < 0:
        raise NicheLifecycleAuthorityError("inventory size is invalid")
    sha = _sha(value["sha256"], field="inventory SHA-256", allow_empty=True)
    referent_sha = _sha(
        value["referent_set_sha256"], field="inventory referent set SHA-256"
    )
    physical = value["physical_identity"]
    if (
        not isinstance(physical, list)
        or (physical and len(physical) != 7)
        or any(
            not isinstance(item, int) or isinstance(item, bool) or item < 0
            for item in physical
        )
        or (present and not physical)
        or (not present and physical)
    ):
        raise NicheLifecycleAuthorityError(
            "inventory physical identity is invalid"
        )
    if present != bool(sha) or (not present and size != 0):
        raise NicheLifecycleAuthorityError("inventory absence binding is inconsistent")
    return {
        "present": present,
        "sha256": sha,
        "size_bytes": size,
        "physical_identity": list(physical),
        "referent_set_sha256": referent_sha,
    }


def _physical_object_identity(value: Sequence[int]) -> tuple[int, ...]:
    """Project stable stat identity onto the pathname's physical object.

    Size and mtime are content/version fields, not replacement identity.  The
    retained capture still checks the full tuple within a transaction; this
    projection is only for detecting cross-generation pathname replacement.
    """

    if len(value) != 7:
        raise NicheLifecycleAuthorityError("physical identity shape is invalid")
    return tuple(value[index] for index in (0, 3, 4, 5, 6))


def _stable_file_identity(value: os.stat_result) -> tuple[int, ...]:
    return (
        int(value.st_mode),
        int(value.st_size),
        int(getattr(value, "st_mtime_ns", 0)),
        int(getattr(value, "st_dev", 0)),
        int(getattr(value, "st_ino", 0)),
        int(getattr(value, "st_nlink", 1)),
        int(getattr(value, "st_file_attributes", 0) or 0),
    )


def _capture_exact_inventory(path: Path, limit: int) -> dict[str, Any]:
    target = Path(path)
    before = target.lstat()
    attributes = int(getattr(before, "st_file_attributes", 0) or 0)
    if (
        not stat.S_ISREG(before.st_mode)
        or stat.S_ISLNK(before.st_mode)
        or attributes & _WINDOWS_REPARSE_POINT
        or int(getattr(before, "st_nlink", 0) or 0) != 1
        or before.st_size < 0
        or before.st_size > limit
    ):
        raise NicheLifecycleAuthorityError(
            "inventory publication target is not a bounded single-link regular file"
        )
    with target.open("rb") as handle:
        opened_before = os.fstat(handle.fileno())
        raw = handle.read(limit + 1)
        opened_after = os.fstat(handle.fileno())
    after = target.lstat()
    identities = tuple(
        _stable_file_identity(item)
        for item in (before, opened_before, opened_after, after)
    )
    if (
        len(raw) > limit
        or len(raw) != after.st_size
        or len(set(identities)) != 1
    ):
        raise NicheLifecycleAuthorityError(
            "inventory publication target changed during exact capture"
        )
    return {
        "raw": raw,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "size_bytes": len(raw),
        "physical_identity": list(identities[0]),
    }


def _publish_niche_inventory_with_capability(
    scratchpad: Path,
    *,
    project_root: Path,
    run_id: str,
    dimensions: Mapping[str, str],
    expected_pre_bytes: bytes,
    expected_post_bytes: bytes,
    max_bytes: int,
) -> object:
    """Atomically publish inventory and return an opaque one-use capability.

    The capability never touches disk.  Its private registry entry binds the
    exact pre/post bytes and physical objects, target pathname, and lifecycle
    context, process, and issuing thread.  The lifecycle commit consumes it
    exactly once against the retained post-publication current-input capture.

    This is transaction locality, not a same-process sandbox: the private
    capability prevents accidental cross-thread/cross-transaction authority
    transfer inside the trusted driver; it is not an isolation boundary for
    arbitrary Python code executing in the orchestrator process.
    """

    frame = inspect.currentframe()
    caller = frame.f_back if frame is not None else None
    try:
        if (
            caller is None
            or Path(caller.f_code.co_filename).name != "plamen_mechanical.py"
            or caller.f_code.co_name != "promote_niche_to_inventory"
        ):
            raise NicheLifecycleAuthorityError(
                "INVENTORY_PUBLICATION_ISSUER_CALLSITE_INVALID"
            )
    finally:
        del caller
        del frame

    if (
        not isinstance(expected_pre_bytes, bytes)
        or not isinstance(expected_post_bytes, bytes)
        or not isinstance(max_bytes, int)
        or isinstance(max_bytes, bool)
        or max_bytes < 0
        or len(expected_pre_bytes) > max_bytes
        or len(expected_post_bytes) > max_bytes
    ):
        raise NicheLifecycleAuthorityError(
            "inventory publication byte contract is invalid"
        )
    project = Path(project_root)
    context = niche_lifecycle_context(
        project_root=project,
        run_id=run_id,
        dimensions=dimensions,
    )
    target = Path(scratchpad) / "findings_inventory.md"
    pre = _capture_exact_inventory(target, max_bytes)
    if pre["raw"] != expected_pre_bytes:
        raise NicheLifecycleAuthorityError(
            "inventory changed before trusted publication"
        )
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=target.parent,
            prefix=f".{target.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary = Path(handle.name)
            handle.write(expected_post_bytes)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, target)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    post = _capture_exact_inventory(target, max_bytes)
    if post["raw"] != expected_post_bytes:
        raise NicheLifecycleAuthorityError(
            "inventory differs after trusted publication"
        )
    if _physical_object_identity(pre["physical_identity"]) == (
        _physical_object_identity(post["physical_identity"])
    ):
        raise NicheLifecycleAuthorityError(
            "trusted inventory publication did not replace the physical object"
        )
    token = _InventoryPublicationCapability()
    payload = {
        "target": os.path.normcase(os.path.abspath(os.fspath(target))),
        "context_sha256": context["context_sha256"],
        "pre_sha256": pre["sha256"],
        "pre_size_bytes": pre["size_bytes"],
        "pre_physical_identity": pre["physical_identity"],
        "post_sha256": post["sha256"],
        "post_size_bytes": post["size_bytes"],
        "post_physical_identity": post["physical_identity"],
        "issuer_pid": os.getpid(),
        "issuer_thread_ident": threading.get_ident(),
        "issuer_thread_native_id": threading.get_native_id(),
    }
    with _INVENTORY_PUBLICATION_CAPABILITY_LOCK:
        _INVENTORY_PUBLICATION_CAPABILITIES[id(token)] = (token, payload)
    return token


def _discard_niche_inventory_publication_capability(token: object) -> None:
    """Burn an unconsumed transaction capability after a local exception."""

    with _INVENTORY_PUBLICATION_CAPABILITY_LOCK:
        registered = _INVENTORY_PUBLICATION_CAPABILITIES.get(id(token))
        if registered is not None and registered[0] is token:
            _INVENTORY_PUBLICATION_CAPABILITIES.pop(id(token), None)


def _consume_inventory_publication_capability(
    token: object,
    *,
    scratchpad: Path,
    expected_context: Mapping[str, str],
    inventory_file: object,
) -> dict[str, Any]:
    with _INVENTORY_PUBLICATION_CAPABILITY_LOCK:
        registered = _INVENTORY_PUBLICATION_CAPABILITIES.pop(id(token), None)
    if registered is None or registered[0] is not token:
        raise NicheLifecycleAuthorityError(
            "INVENTORY_PUBLICATION_CAPABILITY_INVALID_OR_REUSED"
        )
    payload = registered[1]
    expected_target = os.path.normcase(os.path.abspath(os.fspath(
        Path(scratchpad) / "findings_inventory.md"
    )))
    if (
        payload["target"] != expected_target
        or payload["context_sha256"] != expected_context["context_sha256"]
        or payload["issuer_pid"] != os.getpid()
        or payload["issuer_thread_ident"] != threading.get_ident()
        or payload["issuer_thread_native_id"] != threading.get_native_id()
        or getattr(inventory_file, "sha256", None) != payload["post_sha256"]
        or getattr(inventory_file, "size", None) != payload["post_size_bytes"]
        or list(getattr(inventory_file, "physical_identity", ()))
        != payload["post_physical_identity"]
    ):
        raise NicheLifecycleAuthorityError(
            "INVENTORY_PUBLICATION_CAPABILITY_STALE_OR_DRIFTED"
        )
    return payload


def _normalize_action(value: object) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != _ACTION_FIELDS:
        raise NicheLifecycleAuthorityError("lifecycle action fields are not exact")
    identity = _text(value["source_action_identity"], field="source action identity")
    if not _ACTION_ID_RE.fullmatch(identity):
        raise NicheLifecycleAuthorityError("source action identity is invalid")
    source_file = _text(value["source_file"], field="source file")
    source_sha = _sha(value["source_sha256"], field="source SHA-256")
    block_sha = _sha(value["source_block_sha256"], field="source block SHA-256")
    start = value["source_byte_start"]
    end = value["source_byte_end"]
    if (
        not isinstance(start, int)
        or isinstance(start, bool)
        or not isinstance(end, int)
        or isinstance(end, bool)
        or start < 0
        or end <= start
    ):
        raise NicheLifecycleAuthorityError("source action byte range is invalid")
    local_id = _text(value["normalized_local_id"], field="normalized local ID")
    action_record_sha = _sha(
        value["action_record_sha256"], field="action record SHA-256"
    )
    status = _text(value["action_status"], field="action status")
    debt = _text(value["identity_debt"], field="identity debt", allow_empty=True)
    if status not in {"CLEAN", "DEBT"} or (status == "DEBT") != bool(debt):
        raise NicheLifecycleAuthorityError("action debt/status binding is invalid")
    supersedes = _ordered_unique_text(
        value["supersedes_source_action_identities"],
        field="source-authored supersession identities",
    )
    if any(not _ACTION_ID_RE.fullmatch(item) for item in supersedes):
        raise NicheLifecycleAuthorityError("source-authored supersession ID is invalid")
    payload = value["action_payload"]
    if not isinstance(payload, Mapping) or set(payload) != _ACTION_PAYLOAD_FIELDS:
        raise NicheLifecycleAuthorityError("full action payload fields are not exact")
    payload = dict(payload)
    supplied_payload_sha = payload.get("action_record_sha256")
    if supplied_payload_sha != _digest({
        key: item for key, item in payload.items()
        if key != "action_record_sha256"
    }):
        raise NicheLifecycleAuthorityError("full action payload digest mismatch")
    exact_bindings = {
        "source_action_identity": identity,
        "source_file": source_file,
        "source_sha256": source_sha,
        "source_byte_start": start,
        "source_byte_end": end,
        "source_block_sha256": block_sha,
        "normalized_local_id": local_id,
        "action_record_sha256": action_record_sha,
        "action_status": status,
        "identity_debt": debt,
        "supersedes_source_action_identities": supersedes,
    }
    if any(payload.get(field) != expected for field, expected in exact_bindings.items()):
        raise NicheLifecycleAuthorityError("full action payload binding mismatch")
    return {
        "source_action_identity": identity,
        "source_file": source_file,
        "source_sha256": source_sha,
        "source_byte_start": start,
        "source_byte_end": end,
        "source_block_sha256": block_sha,
        "normalized_local_id": local_id,
        "action_record_sha256": action_record_sha,
        "action_status": status,
        "identity_debt": debt,
        "supersedes_source_action_identities": supersedes,
        "action_payload": payload,
    }


def _normalize_transition(value: object) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != _TRANSITION_FIELDS:
        raise NicheLifecycleAuthorityError("lifecycle transition fields are not exact")
    row = dict(value)
    for field in ("attempt_ordinal", "sequence"):
        if (
            not isinstance(row[field], int)
            or isinstance(row[field], bool)
            or row[field] < 1
        ):
            raise NicheLifecycleAuthorityError(f"transition {field} is invalid")
    identity = _text(row["source_action_identity"], field="transition action ID")
    if not _ACTION_ID_RE.fullmatch(identity):
        raise NicheLifecycleAuthorityError("transition action ID is invalid")
    _text(row["source_file"], field="transition source file")
    _sha(row["source_action_record_sha256"], field="transition action record SHA-256")
    state = _text(row["state"], field="transition state")
    if state not in _STATES:
        raise NicheLifecycleAuthorityError("transition state is invalid")
    if not isinstance(row["blocking"], bool):
        raise NicheLifecycleAuthorityError("transition blocking flag is invalid")
    debts = _ordered_unique_text(row["debt_codes"], field="transition debt codes")
    referents = _ordered_unique_text(
        row["inventory_referents"], field="transition inventory referents"
    )
    disposition = _sha(
        row["independent_disposition_digest"],
        field="independent disposition digest",
        allow_empty=True,
    )
    if disposition:
        raise NicheLifecycleAuthorityError(
            "independent lifecycle dispositions are not yet a registered producer"
        )
    expected_blocking = state in {
        "CURRENT_ACTION_DEBT",
        "UNDELIVERED_CLEAN_ACTION",
        "SOURCE_ACTION_REMOVED",
    }
    if row["blocking"] is not expected_blocking:
        raise NicheLifecycleAuthorityError("transition state/blocking mismatch")
    if state in {"DELIVERED_CLEAN_ACTION", "DELIVERED_ACTION_REMOVED"}:
        if not referents:
            raise NicheLifecycleAuthorityError(
                "delivered transition has no exact inventory referent"
            )
    elif referents:
        raise NicheLifecycleAuthorityError(
            "non-delivered transition carries an inventory referent"
        )
    unsigned = {key: item for key, item in row.items() if key != "transition_sha256"}
    if row["transition_sha256"] != _digest(unsigned):
        raise NicheLifecycleAuthorityError("transition digest mismatch")
    row["debt_codes"] = debts
    row["inventory_referents"] = referents
    return row


def validate_niche_lifecycle_generation(value: object) -> dict[str, Any]:
    """Validate one complete generation without consulting mutable projections."""

    if not isinstance(value, Mapping) or set(value) != _GENERATION_FIELDS:
        raise NicheLifecycleAuthorityError("lifecycle generation fields are not exact")
    row = dict(value)
    if row["schema_version"] != NICHE_LIFECYCLE_SCHEMA:
        raise NicheLifecycleAuthorityError("lifecycle schema mismatch")
    _sha(row["audit_instance_id"], field="audit instance ID")
    _text(row["run_id"], field="run ID")
    for field in ("pipeline", "mode", "ecosystem", "backend", "phase", "producer"):
        item = _text(row[field], field=field)
        if not _DIMENSION_RE.fullmatch(item):
            raise NicheLifecycleAuthorityError(f"{field} is not canonical")
    expected_context_sha = _digest(_context_from_row(row))
    if row["context_sha256"] != expected_context_sha:
        raise NicheLifecycleAuthorityError("lifecycle context digest mismatch")
    attempt = row["attempt_ordinal"]
    if not isinstance(attempt, int) or isinstance(attempt, bool) or attempt < 1:
        raise NicheLifecycleAuthorityError("lifecycle attempt ordinal is invalid")
    previous = _sha(
        row["previous_generation_sha256"],
        field="previous generation SHA-256",
        allow_empty=True,
    )
    if (attempt == 1) != (previous == ""):
        raise NicheLifecycleAuthorityError("lifecycle predecessor binding is invalid")
    row["source_capture"] = _normalize_source_capture(row["source_capture"])
    row["inventory_capture"] = _normalize_inventory_capture(row["inventory_capture"])
    actions = row["actions"]
    if not isinstance(actions, list) or len(actions) > _MAX_ACTIONS:
        raise NicheLifecycleAuthorityError("action denominator is invalid or over limit")
    normalized_actions = [_normalize_action(item) for item in actions]
    if normalized_actions != sorted(normalized_actions, key=_action_sort_key):
        raise NicheLifecycleAuthorityError("actions are not in canonical order")
    action_ids = [item["source_action_identity"] for item in normalized_actions]
    if len(action_ids) != len(set(action_ids)):
        raise NicheLifecycleAuthorityError("action denominator contains duplicate keys")
    if row["action_denominator_sha256"] != _digest({"actions": normalized_actions}):
        raise NicheLifecycleAuthorityError("action denominator digest mismatch")
    action_history = row["action_history"]
    if not isinstance(action_history, list) or len(action_history) > _MAX_HISTORY:
        raise NicheLifecycleAuthorityError("action history is invalid or over limit")
    normalized_action_history = [
        _normalize_action(item) for item in action_history
    ]
    if normalized_action_history != sorted(
        normalized_action_history,
        key=lambda item: item["source_action_identity"],
    ):
        raise NicheLifecycleAuthorityError("action history is not in canonical order")
    historical_action_ids = [
        item["source_action_identity"] for item in normalized_action_history
    ]
    if len(historical_action_ids) != len(set(historical_action_ids)):
        raise NicheLifecycleAuthorityError("action history contains duplicate keys")
    if not set(action_ids).issubset(set(historical_action_ids)):
        raise NicheLifecycleAuthorityError("current actions are absent from action history")
    delivery_records = row["delivery_records"]
    if not isinstance(delivery_records, list) or len(delivery_records) > _MAX_ACTIONS:
        raise NicheLifecycleAuthorityError(
            "delivery record denominator is invalid or over limit"
        )
    normalized_deliveries = [
        _normalize_delivery_record(item) for item in delivery_records
    ]
    if normalized_deliveries != sorted(
        normalized_deliveries, key=_delivery_sort_key
    ):
        raise NicheLifecycleAuthorityError(
            "delivery records are not in canonical order"
        )
    delivery_action_ids = [
        item["source_action_identity"] for item in normalized_deliveries
    ]
    delivery_inventory_ids = [item["inventory_id"] for item in normalized_deliveries]
    if (
        len(delivery_action_ids) != len(set(delivery_action_ids))
        or len(delivery_inventory_ids) != len(set(delivery_inventory_ids))
    ):
        raise NicheLifecycleAuthorityError(
            "delivery record action/inventory mapping is not one-to-one"
        )
    historical_actions = {
        item["source_action_identity"]: item for item in normalized_action_history
    }
    for delivery in normalized_deliveries:
        action = historical_actions.get(delivery["source_action_identity"])
        if action is None or any(
            delivery[field] != action[field]
            for field in (
                "source_file", "normalized_local_id", "source_sha256",
                "source_byte_start", "source_byte_end", "source_block_sha256",
            )
        ):
            raise NicheLifecycleAuthorityError(
                "delivery record does not bind its exact source action"
            )
    transitions = row["transitions"]
    if not isinstance(transitions, list) or len(transitions) > _MAX_ACTIONS * 2:
        raise NicheLifecycleAuthorityError("transition denominator is invalid or over limit")
    normalized_transitions = [_normalize_transition(item) for item in transitions]
    if normalized_transitions != sorted(normalized_transitions, key=_transition_sort_key):
        raise NicheLifecycleAuthorityError("transitions are not in canonical order")
    transition_ids = [item["source_action_identity"] for item in normalized_transitions]
    if len(transition_ids) != len(set(transition_ids)):
        raise NicheLifecycleAuthorityError(
            "transition denominator contains duplicate action keys"
        )
    if [item["sequence"] for item in normalized_transitions] != list(
        range(1, len(normalized_transitions) + 1)
    ):
        raise NicheLifecycleAuthorityError("transition sequence does not match order")
    if any(item["attempt_ordinal"] != attempt for item in normalized_transitions):
        raise NicheLifecycleAuthorityError("transition attempt binding mismatch")
    delivery_by_action = {
        item["source_action_identity"]: item["inventory_id"]
        for item in normalized_deliveries
    }
    for transition in normalized_transitions:
        expected_referents = (
            [delivery_by_action[transition["source_action_identity"]]]
            if transition["source_action_identity"] in delivery_by_action
            else []
        )
        if transition["inventory_referents"] != expected_referents:
            raise NicheLifecycleAuthorityError(
                "transition delivery referents differ from typed records"
            )
    current_by_id = {item["source_action_identity"]: item for item in normalized_actions}
    for transition in normalized_transitions:
        current = current_by_id.get(transition["source_action_identity"])
        if transition["state"] in {
            "CURRENT_ACTION_DEBT", "DELIVERED_CLEAN_ACTION", "UNDELIVERED_CLEAN_ACTION",
        }:
            if current is None or transition["source_action_record_sha256"] != current[
                "action_record_sha256"
            ]:
                raise NicheLifecycleAuthorityError(
                    "current transition/action denominator mismatch"
                )
    if set(current_by_id) != {
        item["source_action_identity"]
        for item in normalized_transitions
        if item["state"] in {
            "CURRENT_ACTION_DEBT", "DELIVERED_CLEAN_ACTION", "UNDELIVERED_CLEAN_ACTION",
        }
    }:
        raise NicheLifecycleAuthorityError(
            "every current action must have exactly one transition"
        )
    history = row["history"]
    if not isinstance(history, list) or len(history) > _MAX_HISTORY:
        raise NicheLifecycleAuthorityError("lifecycle history is invalid or over limit")
    normalized_history = [_normalize_transition(item) for item in history]
    if normalized_history != sorted(normalized_history, key=_history_sort_key):
        raise NicheLifecycleAuthorityError("lifecycle history is not in canonical order")
    history_digests = [item["transition_sha256"] for item in normalized_history]
    if len(history_digests) != len(set(history_digests)):
        raise NicheLifecycleAuthorityError("lifecycle history has duplicate transitions")
    if not {
        item["transition_sha256"] for item in normalized_transitions
    }.issubset(set(history_digests)):
        raise NicheLifecycleAuthorityError("current transitions are absent from history")
    dispositions = row["independent_dispositions"]
    if dispositions != []:
        raise NicheLifecycleAuthorityError(
            "independent lifecycle disposition producer is not registered"
        )
    summary = row["summary"]
    if not isinstance(summary, Mapping) or set(summary) != _SUMMARY_FIELDS:
        raise NicheLifecycleAuthorityError("lifecycle summary fields are not exact")
    expected_summary = {
        "action_count": len(normalized_actions),
        "action_history_count": len(normalized_action_history),
        "transition_count": len(normalized_transitions),
        "history_count": len(normalized_history),
        "blocking_count": sum(item["blocking"] for item in normalized_transitions),
        "clean_delivered_count": sum(
            item["state"] == "DELIVERED_CLEAN_ACTION"
            for item in normalized_transitions
        ),
        "removed_count": sum(
            item["state"] in {"SOURCE_ACTION_REMOVED", "DELIVERED_ACTION_REMOVED"}
            for item in normalized_transitions
        ),
        "source_authored_supersession_count": sum(
            bool(item["supersedes_source_action_identities"])
            for item in normalized_actions
        ),
        "delivery_record_count": len(normalized_deliveries),
    }
    if dict(summary) != expected_summary:
        raise NicheLifecycleAuthorityError("lifecycle summary mismatch")
    unsigned = {key: item for key, item in row.items() if key != "generation_sha256"}
    if row["generation_sha256"] != _digest(unsigned):
        raise NicheLifecycleAuthorityError("lifecycle generation digest mismatch")
    row.update({
        "actions": normalized_actions,
        "action_history": normalized_action_history,
        "delivery_records": normalized_deliveries,
        "transitions": normalized_transitions,
        "history": normalized_history,
        "summary": expected_summary,
    })
    return row


def source_capture_record(capture: object) -> dict[str, Any]:
    """Project a retained bounded namespace into the lifecycle schema."""

    namespace = [
        name for name in getattr(capture, "namespace", ())
        if re.fullmatch(r"niche_[A-Za-z0-9_.-]+_findings\.md", name)
    ]
    files = getattr(capture, "files", {})
    snapshots = [
        {
            "source_file": name,
            "source_sha256": files[name].sha256,
            "source_size_bytes": files[name].size,
            "source_physical_identity": list(files[name].physical_identity),
        }
        for name in namespace
    ]
    return _normalize_source_capture({
        "namespace": namespace,
        "namespace_sha256": _digest({"namespace": namespace}),
        "source_snapshots": snapshots,
        "source_snapshot_set_sha256": _digest({"source_snapshots": snapshots}),
    })


def action_denominator_records(actions: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Project parser actions into the exact lifecycle action denominator."""

    rows: list[dict[str, Any]] = []
    for action in actions:
        payload = dict(action)
        rows.append(_normalize_action({
            "source_action_identity": str(action.get("source_action_identity") or ""),
            "source_file": str(action.get("source_file") or ""),
            "source_sha256": str(action.get("source_sha256") or ""),
            "source_byte_start": int(action.get("source_byte_start", -1)),
            "source_byte_end": int(action.get("source_byte_end", -1)),
            "source_block_sha256": str(action.get("source_block_sha256") or ""),
            "normalized_local_id": str(
                action.get("normalized_local_id") or action.get("source_id") or ""
            ),
            "action_record_sha256": str(action.get("action_record_sha256") or ""),
            "action_status": str(action.get("action_status") or ""),
            "identity_debt": str(action.get("identity_debt") or ""),
            "supersedes_source_action_identities": sorted({
                str(item)
                for item in action.get("supersedes_source_action_identities", [])
                if str(item)
            }),
            "action_payload": payload,
        }))
    rows.sort(key=_action_sort_key)
    identities = [row["source_action_identity"] for row in rows]
    if len(identities) != len(set(identities)):
        raise NicheLifecycleAuthorityError(
            "action denominator contains duplicate source-action identities"
        )
    return rows


def _audit_instance_id(project_root: Path) -> str:
    try:
        value = os.path.normcase(os.path.normpath(os.fspath(Path(project_root).resolve())))
    except OSError as exc:
        raise NicheLifecycleAuthorityError("audit instance root is unavailable") from exc
    return hashlib.sha256(value.encode("utf-8", errors="strict")).hexdigest()


def niche_lifecycle_context(
    *,
    project_root: Path,
    run_id: str,
    dimensions: Mapping[str, str],
) -> dict[str, str]:
    """Build the canonical execution context shared by CAS and driver reuse."""

    value = {
        "audit_instance_id": _audit_instance_id(Path(project_root)),
        "run_id": _text(run_id, field="run ID"),
    }
    for field in ("pipeline", "mode", "ecosystem", "backend", "phase", "producer"):
        item = _text(dimensions.get(field), field=field)
        if not _DIMENSION_RE.fullmatch(item):
            raise NicheLifecycleAuthorityError(
                f"lifecycle dimension is invalid: {field}"
            )
        value[field] = item
    value["context_sha256"] = _digest(value)
    return value


def _contract_for_generation(row: Mapping[str, Any]) -> tuple[PhaseIOContract, LaunchSpec]:
    digest = str(row["generation_sha256"])
    attempt = int(row["attempt_ordinal"])
    work_id = f"niche.lifecycle.{attempt:06d}.{digest[:12]}"
    key = "/".join((
        str(row["pipeline"]), str(row["mode"]), str(row["ecosystem"]),
        str(row["backend"]), str(row["phase"]), work_id,
    ))
    output_path = f"{NICHE_LIFECYCLE_CAS_DIR}/{digest}.json"
    inputs = [
        f"scratchpad:{name}"
        for name in row["source_capture"]["namespace"]
    ]
    if row["inventory_capture"]["present"]:
        inputs.append("scratchpad:findings_inventory.md")
    previous = str(row["previous_generation_sha256"] or "")
    if previous:
        inputs.append(f"scratchpad:{NICHE_LIFECYCLE_CAS_DIR}/{previous}.json")
    contract = PhaseIOContract(
        pipeline=str(row["pipeline"]),
        mode=str(row["mode"]),
        ecosystem=str(row["ecosystem"]),
        backend=str(row["backend"]),
        phase=str(row["phase"]),
        work_unit_id=work_id,
        outputs=(ArtifactSpec(
            root="scratchpad",
            path=output_path,
            owner_key=key,
            artifact_class="DRIVER_GENERATED",
            writer="DRIVER",
            write_mode="CREATE",
            schema_version=NICHE_LIFECYCLE_SCHEMA,
            minimum_gate="EXACT_NICHE_LIFECYCLE_GENERATION_REPLAY",
            consumers=("depth/niche_promotion", "depth/postprocessor"),
        ),),
        immutable_inputs=tuple(inputs),
        model_invoked=False,
        launch_profile="DRIVER_PYTHON_NO_TOOLS",
        required_commit_actor="DRIVER",
    )
    launch = LaunchSpec(
        work_unit_key=contract.key,
        pipeline=contract.pipeline,
        mode=contract.mode,
        ecosystem=contract.ecosystem,
        backend=contract.backend,
        model="driver",
        timeout_s=300,
        exec_mode="python",
    )
    return contract, launch


def _safe_cas_paths(root: Path) -> list[Path]:
    directory = root / NICHE_LIFECYCLE_CAS_DIR
    if not directory.exists():
        return []
    row = directory.lstat()
    attributes = int(getattr(row, "st_file_attributes", 0) or 0)
    if (
        not stat.S_ISDIR(row.st_mode)
        or stat.S_ISLNK(row.st_mode)
        or attributes & _WINDOWS_REPARSE_POINT
    ):
        raise NicheLifecycleAuthorityError("niche lifecycle CAS directory is unsafe")
    paths: list[Path] = []
    folded: set[str] = set()
    for entry in os.scandir(directory):
        if not _CAS_NAME_RE.fullmatch(entry.name):
            raise NicheLifecycleAuthorityError(
                f"unexpected niche lifecycle CAS member: {entry.name}"
            )
        key = entry.name.casefold()
        if key in folded:
            raise NicheLifecycleAuthorityError("niche lifecycle CAS name alias")
        folded.add(key)
        paths.append(directory / entry.name)
    if len(paths) > _MAX_GENERATIONS:
        raise NicheLifecycleAuthorityError("niche lifecycle CAS exceeds generation bound")
    return sorted(paths, key=lambda path: path.name)


def _head_payload(row: Mapping[str, Any]) -> dict[str, Any]:
    value = {
        "schema_version": _HEAD_SCHEMA,
        **_context_from_row(row),
        "context_sha256": row["context_sha256"],
        "attempt_ordinal": row["attempt_ordinal"],
        "generation_sha256": row["generation_sha256"],
    }
    value["head_sha256"] = _digest(value)
    return value


def _write_head_projection(root: Path, row: Mapping[str, Any]) -> None:
    path = root / NICHE_LIFECYCLE_HEAD
    payload = _canonical_bytes(_head_payload(row)) + b"\n"
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "wb", dir=str(root), delete=False,
            prefix=f".{NICHE_LIFECYCLE_HEAD}.", suffix=".tmp",
        ) as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
            temporary = Path(stream.name)
        os.replace(temporary, path)
        temporary = None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def _validate_head(root: Path, current: Mapping[str, Any]) -> None:
    path = root / NICHE_LIFECYCLE_HEAD
    try:
        value = _strict_json(
            read_bounded_regular_bytes(path, 64 * 1024, require_single_link=True),
            limit=64 * 1024,
        )
    except (OSError, ValueError) as exc:
        raise NicheLifecycleAuthorityError(
            "niche lifecycle head projection is missing or unsafe"
        ) from exc
    if set(value) != {
        "schema_version", *_CONTEXT_FIELDS, "context_sha256",
        "attempt_ordinal", "generation_sha256", "head_sha256",
    }:
        raise NicheLifecycleAuthorityError("niche lifecycle head fields are not exact")
    unsigned = {key: item for key, item in value.items() if key != "head_sha256"}
    if value["head_sha256"] != _digest(unsigned):
        raise NicheLifecycleAuthorityError("niche lifecycle head digest mismatch")
    expected = _head_payload(current)
    if value != expected:
        raise NicheLifecycleAuthorityError("niche lifecycle head is not the latest commit")


def _transaction_payload(row: Mapping[str, Any]) -> dict[str, Any]:
    if "source_capture" in row:
        contract, launch = _contract_for_generation(row)
        contract_key = contract.key
        contract_digest = contract.digest
        launch_digest = launch.digest
    else:
        contract_key = str(row["contract_key"])
        contract_digest = str(row["contract_digest"])
        launch_digest = str(row["launch_digest"])
    value = {
        "schema_version": _TRANSACTION_SCHEMA,
        **_context_from_row(row),
        "context_sha256": row["context_sha256"],
        "attempt_ordinal": row["attempt_ordinal"],
        "previous_generation_sha256": row["previous_generation_sha256"],
        "generation_sha256": row["generation_sha256"],
        "contract_key": contract_key,
        "contract_digest": contract_digest,
        "launch_digest": launch_digest,
    }
    value["transaction_sha256"] = _digest(value)
    return value


def _validate_transaction(value: object) -> dict[str, Any]:
    expected_fields = {
        "schema_version", *_CONTEXT_FIELDS, "context_sha256",
        "attempt_ordinal", "previous_generation_sha256",
        "generation_sha256", "contract_key", "contract_digest",
        "launch_digest", "transaction_sha256",
    }
    if not isinstance(value, Mapping) or set(value) != expected_fields:
        raise NicheLifecycleAuthorityError(
            "niche lifecycle transaction fields are not exact"
        )
    row = dict(value)
    if row["schema_version"] != _TRANSACTION_SCHEMA:
        raise NicheLifecycleAuthorityError("niche lifecycle transaction schema mismatch")
    _sha(row["audit_instance_id"], field="transaction audit instance ID")
    _text(row["run_id"], field="transaction run ID")
    for field in ("pipeline", "mode", "ecosystem", "backend", "phase", "producer"):
        item = _text(row[field], field=f"transaction {field}")
        if not _DIMENSION_RE.fullmatch(item):
            raise NicheLifecycleAuthorityError(
                f"transaction {field} is not canonical"
            )
    if row["context_sha256"] != _digest(_context_from_row(row)):
        raise NicheLifecycleAuthorityError("transaction context digest mismatch")
    _sha(row["generation_sha256"], field="transaction generation SHA-256")
    _text(row["contract_key"], field="transaction contract key")
    _sha(row["contract_digest"], field="transaction contract digest")
    _sha(row["launch_digest"], field="transaction launch digest")
    _sha(
        row["previous_generation_sha256"],
        field="transaction predecessor SHA-256",
        allow_empty=True,
    )
    attempt = row["attempt_ordinal"]
    if not isinstance(attempt, int) or isinstance(attempt, bool) or attempt < 1:
        raise NicheLifecycleAuthorityError("transaction attempt is invalid")
    if (attempt == 1) != (row["previous_generation_sha256"] == ""):
        raise NicheLifecycleAuthorityError("transaction predecessor is invalid")
    unsigned = {key: item for key, item in row.items() if key != "transaction_sha256"}
    if row["transaction_sha256"] != _digest(unsigned):
        raise NicheLifecycleAuthorityError("transaction digest mismatch")
    return row


def _read_transaction_journal(root: Path) -> dict[str, Any] | None:
    path = root / NICHE_LIFECYCLE_TRANSACTION
    if not path.exists():
        return None
    try:
        raw = read_bounded_regular_bytes(path, 64 * 1024, require_single_link=True)
    except (OSError, ValueError) as exc:
        raise NicheLifecycleAuthorityError(
            "niche lifecycle transaction is unsafe"
        ) from exc
    return _validate_transaction(_strict_json(raw, limit=64 * 1024))


def _write_transaction_journal(root: Path, row: Mapping[str, Any]) -> None:
    path = root / NICHE_LIFECYCLE_TRANSACTION
    payload = _canonical_bytes(_transaction_payload(row)) + b"\n"
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "wb", dir=str(root), delete=False,
            prefix=f".{NICHE_LIFECYCLE_TRANSACTION}.", suffix=".tmp",
        ) as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
            temporary = Path(stream.name)
        os.replace(temporary, path)
        temporary = None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def _clear_transaction_journal(root: Path) -> None:
    path = root / NICHE_LIFECYCLE_TRANSACTION
    if not path.exists():
        return
    _read_transaction_journal(root)
    path.unlink()


def _preexecution_unit_matches(
    root: Path,
    row: Mapping[str, Any],
    contract: PhaseIOContract,
    launch: LaunchSpec,
) -> bool:
    try:
        ledger = read_artifact_ledger(root)
    except ArtifactLedgerError:
        return False
    unit = ledger.get("work_units", {}).get(contract.key)
    return bool(
        isinstance(unit, Mapping)
        and unit.get("run_id") == row["run_id"]
        and unit.get("contract_digest") == contract.digest
        and unit.get("launch_digest") == launch.digest
        and unit.get("execution_state") == "INPUTS_BOUND_PREEXECUTION"
        and not unit.get("output_records")
        and not (
            isinstance(unit.get("commit_authority"), Mapping)
            and unit["commit_authority"].get("receipt_digest")
        )
    )


def _preexecution_journal_matches(root: Path, journal: Mapping[str, Any]) -> bool:
    try:
        ledger = read_artifact_ledger(root)
    except ArtifactLedgerError:
        return False
    unit = ledger.get("work_units", {}).get(journal.get("contract_key"))
    return bool(
        isinstance(unit, Mapping)
        and unit.get("run_id") == journal.get("run_id")
        and unit.get("contract_digest") == journal.get("contract_digest")
        and unit.get("launch_digest") == journal.get("launch_digest")
        and unit.get("execution_state") == "INPUTS_BOUND_PREEXECUTION"
        and not unit.get("output_records")
        and not (
            isinstance(unit.get("commit_authority"), Mapping)
            and unit["commit_authority"].get("receipt_digest")
        )
    )


def _head_is_missing(root: Path) -> bool:
    path = root / NICHE_LIFECYCLE_HEAD
    return not path.exists()


def _repair_or_validate_head(
    root: Path,
    rows: Sequence[Mapping[str, Any]],
) -> None:
    current = rows[-1]
    path = root / NICHE_LIFECYCLE_HEAD
    if _head_is_missing(root):
        _write_head_projection(root, current)
        return
    try:
        value = _strict_json(
            read_bounded_regular_bytes(path, 64 * 1024, require_single_link=True),
            limit=64 * 1024,
        )
    except (OSError, ValueError) as exc:
        raise NicheLifecycleAuthorityError(
            "niche lifecycle head projection is unsafe or tampered"
        ) from exc
    unsigned = {key: item for key, item in value.items() if key != "head_sha256"}
    if value.get("head_sha256") != _digest(unsigned):
        raise NicheLifecycleAuthorityError("niche lifecycle head digest mismatch")
    by_generation = {
        row["generation_sha256"]: _head_payload(row) for row in rows
    }
    generation = value.get("generation_sha256")
    if generation not in by_generation or value != by_generation[generation]:
        raise NicheLifecycleAuthorityError(
            "niche lifecycle head does not name a committed generation"
        )
    if generation != current["generation_sha256"]:
        _write_head_projection(root, current)


def load_current_niche_lifecycle(
    scratchpad: Path,
    *,
    project_root: Path | None = None,
    expected_run_id: str = "",
    expected_context: Mapping[str, str] | None = None,
) -> dict[str, Any] | None:
    """Replay the complete committed CAS chain and return its unique head."""

    root = Path(scratchpad)
    project = Path(project_root) if project_root is not None else root.parent
    journal = _read_transaction_journal(root)
    rows: list[dict[str, Any]] = []
    uncommitted: list[tuple[Path, dict[str, Any]]] = []
    for path in _safe_cas_paths(root):
        try:
            raw = read_bounded_regular_bytes(
                path, _MAX_GENERATION_BYTES, require_single_link=True
            )
            row = validate_niche_lifecycle_generation(_strict_json(raw))
        except (OSError, ValueError, NicheLifecycleAuthorityError) as exc:
            if (
                journal is not None
                and path.name == f"{journal['generation_sha256']}.json"
            ):
                if _preexecution_journal_matches(root, journal):
                    uncommitted.append((path, dict(journal)))
                    continue
            raise NicheLifecycleAuthorityError(
                f"niche lifecycle CAS member is unsafe: {path.name}"
            ) from exc
        if path.name != f"{row['generation_sha256']}.json":
            raise NicheLifecycleAuthorityError("niche lifecycle CAS filename mismatch")
        contract, launch = _contract_for_generation(row)
        issues = validate_work_unit_artifacts(
            root,
            project,
            contract,
            launch,
            run_id=str(row["run_id"]),
            actor="DRIVER",
            require_live_input_authority=False,
        )
        if issues:
            if _preexecution_unit_matches(root, row, contract, launch):
                uncommitted.append((path, row))
                continue
            raise NicheLifecycleAuthorityError(
                "niche lifecycle ArtifactLedger authority is invalid: "
                + "; ".join(issues[:8])
            )
        rows.append(row)
    if uncommitted:
        if len(uncommitted) != 1 or journal is None:
            raise NicheLifecycleAuthorityError(
                "ambiguous or unjournaled niche lifecycle CAS orphan"
            )
        orphan_path, orphan = uncommitted[0]
        if journal != _transaction_payload(orphan):
            raise NicheLifecycleAuthorityError(
                "niche lifecycle CAS orphan differs from transaction journal"
            )
        orphan_path.unlink()
        _clear_transaction_journal(root)
        journal = None
    if not rows:
        if journal is not None:
            if expected_context is not None and any(
                journal.get(field) != expected_context.get(field)
                for field in (*_CONTEXT_FIELDS, "context_sha256")
            ):
                raise NicheLifecycleAuthorityError("CROSS_CONTEXT_REPLAY")
            cas_path = root / NICHE_LIFECYCLE_CAS_DIR / (
                journal["generation_sha256"] + ".json"
            )
            if cas_path.exists():
                raise NicheLifecycleAuthorityError(
                    "journal names an unclassified lifecycle CAS member"
                )
            _clear_transaction_journal(root)
        return None
    audit_ids = {row["audit_instance_id"] for row in rows}
    run_ids = {row["run_id"] for row in rows}
    contexts = {row["context_sha256"] for row in rows}
    if len(audit_ids) != 1:
        raise NicheLifecycleAuthorityError("CROSS_AUDIT_INSTANCE_REPLAY")
    if len(run_ids) != 1 or (expected_run_id and run_ids != {expected_run_id}):
        raise NicheLifecycleAuthorityError("CROSS_RUN_REPLAY")
    if len(contexts) != 1:
        raise NicheLifecycleAuthorityError("CROSS_CONTEXT_GENERATION_REPLAY")
    if expected_context is not None:
        expected = dict(expected_context)
        if set(expected) != {*_CONTEXT_FIELDS, "context_sha256"}:
            raise NicheLifecycleAuthorityError("expected lifecycle context is malformed")
        if any(rows[0].get(field) != expected[field] for field in expected):
            raise NicheLifecycleAuthorityError("CROSS_CONTEXT_REPLAY")
    rows.sort(key=lambda row: row["attempt_ordinal"])
    if [row["attempt_ordinal"] for row in rows] != list(range(1, len(rows) + 1)):
        raise NicheLifecycleAuthorityError("niche lifecycle generation chain has gaps")
    previous = ""
    prior_history: list[dict[str, Any]] = []
    prior_action_history: dict[str, dict[str, Any]] = {}
    for row in rows:
        if row["previous_generation_sha256"] != previous:
            raise NicheLifecycleAuthorityError("niche lifecycle predecessor chain mismatch")
        if row["history"][:len(prior_history)] != prior_history:
            raise NicheLifecycleAuthorityError("niche lifecycle committed union was rewritten")
        current_action_history = {
            item["source_action_identity"]: item
            for item in row["action_history"]
        }
        if any(
            current_action_history.get(identity) != item
            for identity, item in prior_action_history.items()
        ):
            raise NicheLifecycleAuthorityError(
                "niche lifecycle committed action union was rewritten"
            )
        prior_history = row["history"]
        prior_action_history = current_action_history
        previous = row["generation_sha256"]
    _repair_or_validate_head(root, rows)
    if journal is not None:
        current = rows[-1]
        if journal != _transaction_payload(current):
            raise NicheLifecycleAuthorityError(
                "transaction journal does not match committed lifecycle head"
            )
        _clear_transaction_journal(root)
    return rows[-1]


def _transition(
    *,
    attempt: int,
    identity: str,
    source_file: str,
    action_record_sha256: str,
    state: str,
    debt_codes: Iterable[str],
    inventory_referents: Iterable[str],
) -> dict[str, Any]:
    row: dict[str, Any] = {
        "attempt_ordinal": attempt,
        "sequence": 0,
        "source_action_identity": identity,
        "source_file": source_file,
        "source_action_record_sha256": action_record_sha256,
        "state": state,
        "blocking": state in {
            "CURRENT_ACTION_DEBT", "UNDELIVERED_CLEAN_ACTION", "SOURCE_ACTION_REMOVED",
        },
        "debt_codes": sorted(set(str(item) for item in debt_codes if str(item))),
        "inventory_referents": sorted(set(
            str(item).upper() for item in inventory_referents if str(item)
        )),
        "independent_disposition_digest": "",
    }
    return row


def _derive_generation(
    *,
    project_root: Path,
    run_id: str,
    dimensions: Mapping[str, str],
    source_capture: Mapping[str, Any],
    inventory_capture: Mapping[str, Any],
    actions: Sequence[Mapping[str, Any]],
    delivery_records: Sequence[Mapping[str, Any]],
    prior: Mapping[str, Any] | None,
) -> dict[str, Any]:
    action_rows = action_denominator_records(actions)
    normalized_deliveries = sorted(
        (_normalize_delivery_record(item) for item in delivery_records),
        key=_delivery_sort_key,
    )
    inventory_referents = {
        item["source_action_identity"]: {item["inventory_id"]}
        for item in normalized_deliveries
    }
    attempt = int(prior["attempt_ordinal"]) + 1 if prior else 1
    current_ids = {row["source_action_identity"] for row in action_rows}
    transitions: list[dict[str, Any]] = []
    for action in action_rows:
        identity = action["source_action_identity"]
        referents = inventory_referents.get(identity, set())
        debts: list[str] = []
        if action["supersedes_source_action_identities"]:
            debts.append("SOURCE_AUTHORED_SUPERSESSION_NOT_AUTHORITY")
        if action["action_status"] == "DEBT":
            state = "CURRENT_ACTION_DEBT"
            debts.append(action["identity_debt"])
            referents = set()
        elif referents:
            state = "DELIVERED_CLEAN_ACTION"
        else:
            state = "UNDELIVERED_CLEAN_ACTION"
            debts.append("UNDELIVERED_CLEAN_ACTION")
        transitions.append(_transition(
            attempt=attempt,
            identity=identity,
            source_file=action["source_file"],
            action_record_sha256=action["action_record_sha256"],
            state=state,
            debt_codes=debts,
            inventory_referents=referents,
        ))
    if prior:
        prior_latest: dict[str, Mapping[str, Any]] = {
            row["source_action_identity"]: row for row in prior["transitions"]
        }
        prior_actions = {
            row["source_action_identity"]: row
            for row in prior["action_history"]
        }
        for identity, prior_transition in prior_latest.items():
            if identity in current_ids:
                continue
            action = prior_actions.get(identity)
            source_file = str(
                (action or prior_transition).get("source_file") or ""
            )
            action_sha = str(
                (action or prior_transition).get("action_record_sha256")
                or prior_transition.get("source_action_record_sha256")
                or ""
            )
            referents = inventory_referents.get(identity, set())
            state = "DELIVERED_ACTION_REMOVED" if referents else "SOURCE_ACTION_REMOVED"
            transitions.append(_transition(
                attempt=attempt,
                identity=identity,
                source_file=source_file,
                action_record_sha256=action_sha,
                state=state,
                debt_codes=[] if referents else ["SOURCE_ACTION_REMOVED"],
                inventory_referents=referents,
            ))
    transitions.sort(key=_transition_sort_key)
    for sequence, transition in enumerate(transitions, start=1):
        transition["sequence"] = sequence
        transition["transition_sha256"] = _digest(transition)
    history_by_digest = {
        row["transition_sha256"]: dict(row)
        for row in (prior or {}).get("history", [])
    }
    for transition in transitions:
        history_by_digest[transition["transition_sha256"]] = dict(transition)
    history = sorted(history_by_digest.values(), key=_history_sort_key)
    action_history_by_id = {
        row["source_action_identity"]: dict(row)
        for row in (prior or {}).get("action_history", [])
    }
    for action in action_rows:
        action_history_by_id[action["source_action_identity"]] = dict(action)
    action_history = [
        action_history_by_id[identity]
        for identity in sorted(action_history_by_id)
    ]
    context = niche_lifecycle_context(
        project_root=project_root,
        run_id=run_id,
        dimensions=dimensions,
    )
    row: dict[str, Any] = {
        "schema_version": NICHE_LIFECYCLE_SCHEMA,
        **context,
        "attempt_ordinal": attempt,
        "previous_generation_sha256": (
            str(prior["generation_sha256"]) if prior else ""
        ),
        "source_capture": dict(source_capture),
        "inventory_capture": dict(inventory_capture),
        "action_denominator_sha256": _digest({"actions": action_rows}),
        "actions": action_rows,
        "action_history": action_history,
        "delivery_records": normalized_deliveries,
        "transitions": transitions,
        "history": history,
        "independent_dispositions": [],
        "summary": {
            "action_count": len(action_rows),
            "action_history_count": len(action_history),
            "transition_count": len(transitions),
            "history_count": len(history),
            "blocking_count": sum(item["blocking"] for item in transitions),
            "clean_delivered_count": sum(
                item["state"] == "DELIVERED_CLEAN_ACTION" for item in transitions
            ),
            "removed_count": sum(
                item["state"] in {"SOURCE_ACTION_REMOVED", "DELIVERED_ACTION_REMOVED"}
                for item in transitions
            ),
            "source_authored_supersession_count": sum(
                bool(item["supersedes_source_action_identities"])
                for item in action_rows
            ),
            "delivery_record_count": len(normalized_deliveries),
        },
    }
    row["generation_sha256"] = _digest(row)
    return validate_niche_lifecycle_generation(row)


def _same_semantic_generation(left: Mapping[str, Any], right: Mapping[str, Any]) -> bool:
    fields = (
        "source_capture", "inventory_capture", "action_denominator_sha256",
        "actions", "delivery_records", "transitions",
    )
    # Transition attempt/sequence/digest necessarily differ. Compare their
    # semantic state projection while preserving the exact action denominator.
    if any(left[field] != right[field] for field in fields[:-1]):
        return False
    def semantic(rows: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
        return [
            {
                key: value for key, value in row.items()
                if key not in {"attempt_ordinal", "sequence", "transition_sha256"}
            }
            for row in rows
        ]
    return semantic(left["transitions"]) == semantic(right["transitions"])


def commit_niche_lifecycle_generation(
    scratchpad: Path,
    *,
    project_root: Path,
    run_id: str,
    dimensions: Mapping[str, str],
    retained_capture: object,
    actions: Sequence[Mapping[str, Any]],
    inventory_bytes: bytes | None,
    delivery_records: Sequence[Mapping[str, Any]],
    inventory_publication_capability: object | None = None,
) -> dict[str, Any]:
    """Derive, PhaseIO-commit, replay, and return one lifecycle generation."""

    root = Path(scratchpad)
    project = Path(project_root)
    for field in ("pipeline", "mode", "ecosystem", "backend", "phase", "producer"):
        if field not in dimensions or not _DIMENSION_RE.fullmatch(str(dimensions[field])):
            raise NicheLifecycleAuthorityError(f"lifecycle dimension is invalid: {field}")
    expected_context = niche_lifecycle_context(
        project_root=project,
        run_id=run_id,
        dimensions=dimensions,
    )
    retained_capture.revalidate()
    try:
        prior = load_current_niche_lifecycle(
            root,
            project_root=project,
            expected_run_id=run_id,
            expected_context=expected_context,
        )
    except NicheLifecycleAuthorityError:
        raise
    source_record = source_capture_record(retained_capture)
    inventory_raw = inventory_bytes if inventory_bytes is not None else b""
    retained_files = getattr(retained_capture, "files", {})
    inventory_file = retained_files.get("findings_inventory.md")
    if inventory_bytes is None:
        if inventory_file is not None:
            raise NicheLifecycleAuthorityError(
                "retained inventory presence differs from supplied capture"
            )
        inventory_physical_identity: list[int] = []
    else:
        if (
            inventory_file is None
            or inventory_file.raw != inventory_raw
            or inventory_file.size != len(inventory_raw)
            or inventory_file.sha256 != hashlib.sha256(inventory_raw).hexdigest()
        ):
            raise NicheLifecycleAuthorityError(
                "retained inventory bytes differ from supplied capture"
            )
        inventory_physical_identity = list(inventory_file.physical_identity)
    publication_payload = None
    if inventory_publication_capability is not None:
        if inventory_file is None:
            raise NicheLifecycleAuthorityError(
                "inventory publication capability has no retained inventory"
            )
        publication_payload = _consume_inventory_publication_capability(
            inventory_publication_capability,
            scratchpad=root,
            expected_context=expected_context,
            inventory_file=inventory_file,
        )
    normalized_deliveries = sorted(
        (_normalize_delivery_record(item) for item in delivery_records),
        key=_delivery_sort_key,
    )
    referent_rows = [
        {
            "source_action_identity": item["source_action_identity"],
            "inventory_referents": [item["inventory_id"]],
        }
        for item in normalized_deliveries
    ]
    inventory_record = _normalize_inventory_capture({
        "present": inventory_bytes is not None,
        "sha256": hashlib.sha256(inventory_raw).hexdigest() if inventory_bytes is not None else "",
        "size_bytes": len(inventory_raw),
        "physical_identity": inventory_physical_identity,
        "referent_set_sha256": _digest({"referents": referent_rows}),
    })
    candidate = _derive_generation(
        project_root=project,
        run_id=run_id,
        dimensions=dimensions,
        source_capture=source_record,
        inventory_capture=inventory_record,
        actions=actions,
        delivery_records=normalized_deliveries,
        prior=prior,
    )
    if prior is not None:
        prior_snapshots = {
            row["source_file"]: row
            for row in prior["source_capture"]["source_snapshots"]
        }
        for snapshot in candidate["source_capture"]["source_snapshots"]:
            previous_snapshot = prior_snapshots.get(snapshot["source_file"])
            if (
                previous_snapshot is not None
                and previous_snapshot["source_sha256"] == snapshot["source_sha256"]
                and previous_snapshot["source_size_bytes"] == snapshot["source_size_bytes"]
                and previous_snapshot["source_physical_identity"]
                != snapshot["source_physical_identity"]
            ):
                raise NicheLifecycleAuthorityError(
                    "PHYSICAL_SOURCE_REPLACEMENT_REPLAY"
                )
        previous_inventory = prior["inventory_capture"]
        current_inventory = candidate["inventory_capture"]
        if (
            previous_inventory["present"]
            and current_inventory["present"]
            and previous_inventory["sha256"] == current_inventory["sha256"]
            and previous_inventory["size_bytes"] == current_inventory["size_bytes"]
            and _physical_object_identity(
                previous_inventory["physical_identity"]
            ) != _physical_object_identity(current_inventory["physical_identity"])
            and publication_payload is None
        ):
            raise NicheLifecycleAuthorityError(
                "PHYSICAL_INVENTORY_REPLACEMENT_REPLAY"
            )
    if prior is not None and _same_semantic_generation(prior, candidate):
        retained_capture.revalidate()
        return dict(prior)
    contract, launch = _contract_for_generation(candidate)
    output_path = root / NICHE_LIFECYCLE_CAS_DIR / (
        candidate["generation_sha256"] + ".json"
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    retained_capture.revalidate()
    try:
        armed = record_work_unit_inputs(
            root, project, contract, launch, run_id=run_id
        )
    except (ArtifactLedgerError, OSError, ValueError) as exc:
        raise NicheLifecycleAuthorityError(
            f"niche lifecycle PhaseIO input arm failed: {exc}"
        ) from exc
    input_bindings = armed.get("input_bindings")
    if not isinstance(input_bindings, Mapping):
        raise NicheLifecycleAuthorityError(
            "niche lifecycle PhaseIO input bindings are absent"
        )
    expected_live_inputs: dict[str, tuple[int, str]] = {
        f"scratchpad:{snapshot['source_file']}": (
            int(snapshot["source_size_bytes"]),
            str(snapshot["source_sha256"]),
        )
        for snapshot in source_record["source_snapshots"]
    }
    if inventory_bytes is not None:
        expected_live_inputs["scratchpad:findings_inventory.md"] = (
            len(inventory_raw),
            hashlib.sha256(inventory_raw).hexdigest(),
        )
    for identity, (expected_size, expected_sha256) in expected_live_inputs.items():
        binding = input_bindings.get(identity)
        if (
            not isinstance(binding, Mapping)
            or binding.get("status") != "ACTIVE"
            or binding.get("size") != expected_size
            or binding.get("sha256") != expected_sha256
        ):
            raise NicheLifecycleAuthorityError(
                "niche lifecycle retained capture differs from PhaseIO input "
                f"authority: {identity}"
            )
    retained_capture.revalidate()
    _write_transaction_journal(root, candidate)
    retained_capture.revalidate()
    encoded = _canonical_bytes(candidate) + b"\n"
    if len(encoded) > _MAX_GENERATION_BYTES:
        raise NicheLifecycleAuthorityError("niche lifecycle generation exceeds byte bound")
    descriptor = -1
    try:
        descriptor = os.open(
            output_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | int(getattr(os, "O_BINARY", 0)),
            0o600,
        )
        offset = 0
        while offset < len(encoded):
            written = os.write(descriptor, encoded[offset:])
            if written <= 0:
                raise OSError("short lifecycle CAS write")
            offset += written
        os.fsync(descriptor)
    except FileExistsError as exc:
        raise NicheLifecycleAuthorityError(
            "niche lifecycle CAS generation already exists without idempotent head"
        ) from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    retained_capture.revalidate()
    try:
        unit = record_work_unit_artifacts(
            root,
            project,
            contract,
            launch,
            run_id=run_id,
            actor="DRIVER",
        )
    except (ArtifactLedgerError, OSError, ValueError) as exc:
        raise NicheLifecycleAuthorityError(
            f"niche lifecycle PhaseIO output commit failed: {exc}"
        ) from exc
    if unit.get("semantic_status") != "ACTIVE":
        reasons = unit.get("commit_authority", {}).get("reason_codes", [])
        raise NicheLifecycleAuthorityError(
            "niche lifecycle PhaseIO commit quarantined: "
            + ",".join(str(item) for item in reasons)
        )
    retained_capture.revalidate()
    _write_head_projection(root, candidate)
    retained_capture.revalidate()
    _clear_transaction_journal(root)
    replayed = load_current_niche_lifecycle(
        root,
        project_root=project,
        expected_run_id=run_id,
        expected_context=expected_context,
    )
    if replayed is None or replayed["generation_sha256"] != candidate[
        "generation_sha256"
    ]:
        raise NicheLifecycleAuthorityError("niche lifecycle post-commit replay failed")
    retained_capture.revalidate()
    return replayed


def projection_binding(row: Mapping[str, Any]) -> dict[str, Any]:
    """Return exact legacy-projection binding fields for one validated head."""

    current = validate_niche_lifecycle_generation(row)
    return {
        "lifecycle_authority_schema": NICHE_LIFECYCLE_SCHEMA,
        "lifecycle_authority_status": (
            "BLOCKED" if current["summary"]["blocking_count"] else "CURRENT"
        ),
        "lifecycle_audit_instance_id": current["audit_instance_id"],
        "lifecycle_run_id": current["run_id"],
        "lifecycle_pipeline": current["pipeline"],
        "lifecycle_mode": current["mode"],
        "lifecycle_ecosystem": current["ecosystem"],
        "lifecycle_backend": current["backend"],
        "lifecycle_phase": current["phase"],
        "lifecycle_producer": current["producer"],
        "lifecycle_context_sha256": current["context_sha256"],
        "lifecycle_attempt_ordinal": current["attempt_ordinal"],
        "lifecycle_head_sha256": current["generation_sha256"],
        "lifecycle_action_denominator_sha256": current[
            "action_denominator_sha256"
        ],
        "lifecycle_transition_set_sha256": _digest({
            "transitions": current["transitions"]
        }),
        "lifecycle_history_set_sha256": _digest({"history": current["history"]}),
        "lifecycle_blocking_count": current["summary"]["blocking_count"],
        "lifecycle_delivery_record_count": len(current["delivery_records"]),
        "lifecycle_delivery_record_set_sha256": _digest({
            "delivery_records": current["delivery_records"]
        }),
    }


def validate_projection_binding(
    scratchpad: Path,
    payload: Mapping[str, Any],
    *,
    project_root: Path | None = None,
    expected_context: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Require a mutable sidecar to equal the unique committed lifecycle head."""

    current = load_current_niche_lifecycle(
        Path(scratchpad),
        project_root=project_root,
        expected_context=expected_context,
    )
    if current is None:
        raise NicheLifecycleAuthorityError("lifecycle authority is absent")
    expected = projection_binding(current)
    if any(payload.get(key) != value for key, value in expected.items()):
        raise NicheLifecycleAuthorityError(
            "niche lifecycle projection does not match committed authority"
        )
    action_records = payload.get("actions")
    candidates = payload.get("candidates")
    source_errors = payload.get("source_errors")
    lifecycle_records = payload.get("lifecycle_records")
    if not all(
        isinstance(value, list)
        for value in (
            action_records,
            candidates,
            source_errors,
            lifecycle_records,
        )
    ):
        raise NicheLifecycleAuthorityError("niche lifecycle projection lists are invalid")
    projected_actions = action_denominator_records(action_records)
    if projected_actions != current["actions"]:
        raise NicheLifecycleAuthorityError(
            "niche lifecycle projection live action denominator/raw block "
            "binding differs from authority"
        )
    debt_actions = {
        row["source_action_identity"] for row in current["actions"]
        if row["action_status"] == "DEBT"
    }
    candidate_actions = {
        str(row.get("source_action_identity") or "")
        for row in candidates if isinstance(row, Mapping)
    }
    if debt_actions != candidate_actions or len(candidate_actions) != len(candidates):
        raise NicheLifecycleAuthorityError(
            "niche lifecycle DEBT/candidate bijection is not exact"
        )
    blocking_removed = {
        row["source_action_identity"] for row in current["transitions"]
        if row["state"] == "SOURCE_ACTION_REMOVED"
    }
    projected_removed_rows = [
        row
        for row in source_errors
        if isinstance(row, Mapping) and row.get("status") == "SOURCE_ACTION_REMOVED"
    ]
    projected_removed = {
        str(row.get("source_action_identity") or "")
        for row in projected_removed_rows
    }
    if (
        blocking_removed != projected_removed
        or len(projected_removed) != len(projected_removed_rows)
    ):
        raise NicheLifecycleAuthorityError(
            "niche lifecycle live lifecycle delivery / removed-action "
            "projection differs from authority"
        )
    blocking_undelivered = {
        row["source_action_identity"] for row in current["transitions"]
        if row["state"] == "UNDELIVERED_CLEAN_ACTION"
    }
    projected_undelivered_rows = [
        row for row in source_errors
        if isinstance(row, Mapping)
        and row.get("status") == "UNDELIVERED_CLEAN_ACTION"
    ]
    projected_undelivered = {
        str(row.get("source_action_identity") or "")
        for row in projected_undelivered_rows
    }
    if (
        blocking_undelivered != projected_undelivered
        or len(projected_undelivered) != len(projected_undelivered_rows)
    ):
        raise NicheLifecycleAuthorityError(
            "niche lifecycle UNDELIVERED_CLEAN_ACTION projection is not exact"
        )
    delivered_removed = {
        row["source_action_identity"]: row["inventory_referents"]
        for row in current["transitions"]
        if row["state"] == "DELIVERED_ACTION_REMOVED"
    }
    projected_delivered_rows = [
        row for row in lifecycle_records
        if isinstance(row, Mapping)
        and row.get("status") == "DELIVERED_ACTION_REMOVED"
    ]
    projected_delivered = {
        str(row.get("source_action_identity") or ""): list(
            row.get("inventory_referents") or []
        )
        for row in projected_delivered_rows
    }
    if (
        delivered_removed != projected_delivered
        or len(projected_delivered) != len(projected_delivered_rows)
    ):
        raise NicheLifecycleAuthorityError(
            "niche lifecycle delivered-removal projection is not exact"
        )
    return current


__all__ = [
    "NICHE_LIFECYCLE_CAS_DIR",
    "NICHE_LIFECYCLE_HEAD",
    "NICHE_LIFECYCLE_SCHEMA",
    "NICHE_LIFECYCLE_TRANSACTION",
    "NicheLifecycleAuthorityError",
    "action_denominator_records",
    "commit_niche_lifecycle_generation",
    "load_current_niche_lifecycle",
    "niche_lifecycle_context",
    "projection_binding",
    "source_capture_record",
    "validate_niche_lifecycle_generation",
    "validate_projection_binding",
]
