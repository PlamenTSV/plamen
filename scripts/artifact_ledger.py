"""Exact, digest-bound artifact ownership for typed Plamen work units.

This module is the P0-AE migration authority.  The legacy filename/glob view is
retained as a compatibility projection in the same JSON document, while new
work units are recorded and validated exclusively through ``PhaseIOContract``.
Ledger corruption is an explicit error; it never degrades to an empty ledger.
"""
from __future__ import annotations

import copy
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tempfile
import threading
import time
from typing import Any, Callable, Iterable, Mapping, Sequence
import unicodedata

from bounded_artifact_io import read_bounded_regular_bytes
import rooted_path_io as rooted_io
from external_preimage_authority import (
    ExternalPreimageValidationError,
    derive_external_preimage_receipt,
    validate_external_preimage_receipt_integrity,
)
from phase_io_contracts import (
    canonical_artifact_identity,
    ConditionalOutputReceipt,
    DriverMergeEvent,
    DriverOutputTransition,
    DriverSuccessorPlan,
    InputAuthorityRequirement,
    LaunchSpec,
    PhaseIOContract,
    driver_successor_plan_from_dict,
    registered_projection_handoff,
    replay_driver_successor_plan_authority,
    replay_phase_io_authority_pair,
)


LEDGER_NAME = "_artifact_state.json"
LEDGER_VERSION = 2
SEMANTIC_MUTATION_LEDGER_NAME = "_semantic_mutations.json"
_LEDGER_LOCK = threading.RLock()
_PROCESS_LOCK_STATE = threading.local()
_LEDGER_LOCK_FILE = "_artifact_state.lock"
_COMMIT_AUTHORITY_SCHEMA = "plamen.artifact-output-commit.v1"
_OUTPUT_AUTHORITY_LEDGER_NAME = "_artifact_output_authorities.json"
_OUTPUT_AUTHORITY_LEDGER_SCHEMA = "plamen.artifact-output-authorities.v1"
_OUTPUT_AUTHORITY_SCHEMA = "plamen.artifact-output-authority.v1"
_OUTPUT_AUTHORITY_CAS_DIRECTORY = "_artifact_output_authority_cas"
_OUTPUT_AUTHORITY_FIELDS = frozenset({
    "schema",
    "authority_key",
    "state",
    "source",
    "run_id",
    "work_unit_key",
    "contract_digest",
    "launch_digest",
    "input_set_digest",
    "attempt_ordinal",
    "quarantine_recovery_history_count",
    "quarantine_recovery_history_head_digest",
    "actor",
    "physical_policy",
    "expected_output_records",
    "observed_outputs",
    "reason_codes",
    "authority_digest",
})
_OUTPUT_AUTHORITY_SOURCES = frozenset({
    "LEGACY_DESCRIPTOR_CAPTURE",
    "VALIDATED_EXPECTED_OUTPUT_RECORDS",
    "WORKER_TRANSACTION_CAS",
})
_OUTPUT_AUTHORITY_ACTORS = frozenset({"", "MODEL", "DRIVER"})
_DRIVER_SUCCESSOR_AUTHORITY_LEDGER_NAME = (
    "_driver_successor_authorities.json"
)
_DRIVER_SUCCESSOR_AUTHORITY_LEDGER_SCHEMA = (
    "plamen.driver-successor-authorities.v1"
)
_DRIVER_SUCCESSOR_AUTHORITY_SCHEMA = (
    "plamen.driver-successor-authority.v1"
)
_DRIVER_SUCCESSOR_AUTHORITY_CAS_DIRECTORY = (
    "_driver_successor_authority_cas"
)
_DRIVER_SUCCESSOR_PHYSICAL_REBIND_SCHEMA = (
    "plamen.driver-successor-physical-rebind.v1"
)
_QUARANTINE_RECOVERY_AUTHORITY_SCHEMA = (
    "plamen.quarantine-recovery-authority.v1"
)
_DRIVER_SUCCESSOR_PHYSICAL_REBIND_CAS_DIRECTORY = (
    "_driver_successor_physical_rebind_cas"
)
_DRIVER_SUCCESSOR_PROGRESS_NAME = "_driver_successor_progress.json"
_DRIVER_SUCCESSOR_PROGRESS_SCHEMA = "plamen.driver-successor-progress.v1"
_DRIVER_SUCCESSOR_PROGRESS_EVENT_SCHEMA = (
    "plamen.driver-successor-progress-event.v1"
)
_DRIVER_SUCCESSOR_PROGRESS_EVENT_CAS_DIRECTORY = (
    "_driver_successor_progress_event_cas"
)
_DRIVER_SUCCESSOR_PROGRESS_AUTHORITY_SCHEMA = (
    "plamen.driver-successor-progress-authority.v1"
)
_NO_FOLLOW_PHYSICAL_POLICY = "LEXICAL_NO_FOLLOW_V1"
_COMMIT_TERMINAL_STATES = frozenset({
    "OUTPUT_COMMITTED", "OUTPUT_QUARANTINED", "OUTPUT_SUPERSEDED",
})
_INPUT_REBIND_HISTORY_SCHEMA = "plamen.artifact-input-rebind.v1"
_INPUT_REBIND_REASON_CODES = frozenset({
    "DYNAMIC_INPUT_DENOMINATOR_DRIFT_BEFORE_OUTPUT_COMMIT",
})
_INPUT_REBIND_EVENT_FIELDS = frozenset({
    "schema",
    "reason_code",
    "run_id",
    "work_unit_key",
    "ordinal",
    "prior_contract_digest",
    "replacement_contract_digest",
    "prior_input_set_digest",
    "replacement_input_set_digest",
    "added_identities",
    "removed_identities",
    "event_digest",
})
# Only these exact input-bound producer metadata fields may survive the
# generic output commit normalization boundary.  Their producer-specific
# semantics are validated by the owning phase; the artifact ledger owns the
# closed field roster, strict SHA-256 domain, and commit-receipt binding.
_REGISTERED_INPUT_BOUND_COMMIT_METADATA_SCHEMA = {
    "auxiliary_publication_intent_digest": "SHA256",
    "auxiliary_publication_authority_digest": "SHA256",
}
_SEMANTIC_INVALIDATION_AUTH_SCHEMA = (
    "plamen.semantic-invalidation-authorization.v2"
)
_SEMANTIC_INVALIDATION_AUTH_FIELDS = frozenset({
    "schema",
    "plan_digest",
    "run_id",
    "work_unit_key",
    "changed_input_identities",
    "invalidated_artifact_identities",
    "trigger_identities",
    "stale_artifact_identities",
    "authorization_digest",
})
_EXACT_REPAIR_ARM_SCHEMA = (
    "plamen.exact_committed_output_repair_arm_authority.v1"
)
_EXACT_REPAIR_FINALIZE_SCHEMA = (
    "plamen.exact_committed_output_repair_finalize_authority.v1"
)
_EXACT_REPAIR_HISTORY_SCHEMA = (
    "plamen.exact_committed_output_repair_history.v1"
)
_EXACT_REPAIR_PENDING_SCHEMA = (
    "plamen.semantic_dedup_committed_successor_repair_pending.v1"
)
_EXACT_REPAIR_INTENT_SCHEMA = "plamen.semantic_dedup_transaction.v1"
_EXACT_REPAIR_RECEIPT_SCHEMA = (
    "plamen.semantic_dedup_transaction_receipt.v1"
)
_EXACT_REPAIR_SOURCE_ANCHOR_SCHEMA = (
    "plamen.exact_committed_output_repair_source_anchor.v1"
)
_EXACT_REPAIR_SOURCE_ANCHOR_CAS_DIRECTORY = (
    "_exact_committed_output_repair_source_anchor_cas"
)
_EXACT_L1_SEMANTIC_REPAIR_OUTPUTS = (
    "findings_inventory.md",
    "finding_records.json",
    "semantic_dedup_applied_receipt.json",
    "dedup_absorbed_map.md",
    "findings_inventory_deduped.md",
)
_EXACT_REPAIR_CONTROL_LIMIT = 2 * 1024 * 1024
_EXACT_REPAIR_ARTIFACT_LIMIT = 64 * 1024 * 1024
_EXACT_REPAIR_SOURCE_ANCHOR_LIMIT = 128


class _RootBoundWorkUnit(dict[str, Any]):
    """In-memory work-unit view bound to its safely opened ledger root.

    The root is deliberately not serialized into the authority document.  It
    is ambient evidence supplied only by ``read_artifact_ledger`` after that
    function has performed its stable no-follow read.  Exact-repair replay
    needs this context to authenticate private transaction objects; a detached
    repaired dictionary cannot grant producer authority by hashes alone.
    """

    def __init__(
        self,
        value: Mapping[str, Any],
        *,
        artifact_ledger_root: Path,
    ) -> None:
        super().__init__(value)
        self._artifact_ledger_root = artifact_ledger_root
_PROGRAM_FACTS_SELECTION_HISTORY_FIELD = (
    "program_facts_v2_generation_selections"
)
_PROGRAM_FACTS_ACTIVE_SELECTION_FIELD = (
    "program_facts_v2_active_selection"
)
_PROGRAM_FACTS_SELECTION_FIELDS = frozenset({
    _PROGRAM_FACTS_SELECTION_HISTORY_FIELD,
    _PROGRAM_FACTS_ACTIVE_SELECTION_FIELD,
})
_PROGRAM_FACTS_SELECTION_PREFIX = "program_facts_v2_"
_PROGRAM_FACTS_GENERATION_ID_RE = re.compile(
    r"^pfg-[0-9a-f]{32}$",
    re.ASCII,
)
_PROGRAM_FACTS_SHA256_RE = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
_PROGRAM_FACTS_SELECTION_CONTROL_LIMIT = 8 * 1024 * 1024
_PROGRAM_FACTS_SELECTION_OUTPUT_LIMIT = 64 * 1024 * 1024


if os.name == "nt":
    import ctypes as _windows_ctypes
    from ctypes import wintypes as _windows_wintypes

    class _WindowsFindData(_windows_ctypes.Structure):
        """Stable process-wide FindFirstFileW result layout."""

        _fields_ = [
            ("dwFileAttributes", _windows_wintypes.DWORD),
            ("ftCreationTime", _windows_wintypes.FILETIME),
            ("ftLastAccessTime", _windows_wintypes.FILETIME),
            ("ftLastWriteTime", _windows_wintypes.FILETIME),
            ("nFileSizeHigh", _windows_wintypes.DWORD),
            ("nFileSizeLow", _windows_wintypes.DWORD),
            ("dwReserved0", _windows_wintypes.DWORD),
            ("dwReserved1", _windows_wintypes.DWORD),
            ("cFileName", _windows_wintypes.WCHAR * 260),
            ("cAlternateFileName", _windows_wintypes.WCHAR * 14),
        ]

    _WINDOWS_FIND_FIRST_FILE_W = (
        _windows_ctypes.windll.kernel32.FindFirstFileW
    )
    _WINDOWS_FIND_FIRST_FILE_W.argtypes = [
        _windows_wintypes.LPCWSTR,
        _windows_ctypes.POINTER(_WindowsFindData),
    ]
    _WINDOWS_FIND_FIRST_FILE_W.restype = _windows_wintypes.HANDLE
    _WINDOWS_FIND_CLOSE = _windows_ctypes.windll.kernel32.FindClose
    _WINDOWS_FIND_CLOSE.argtypes = [_windows_wintypes.HANDLE]
    _WINDOWS_FIND_CLOSE.restype = _windows_wintypes.BOOL
    _WINDOWS_BYREF = _windows_ctypes.byref
    _WINDOWS_INVALID_HANDLE_VALUE = (
        _windows_ctypes.c_void_p(-1).value
    )
else:
    # Keep non-Windows import and monkeypatch surfaces deterministic without
    # importing ctypes.wintypes or resolving any Windows library.
    _WindowsFindData = None
    _WINDOWS_FIND_FIRST_FILE_W = None
    _WINDOWS_FIND_CLOSE = None
    _WINDOWS_BYREF = None
    _WINDOWS_INVALID_HANDLE_VALUE = None


class ArtifactLedgerError(RuntimeError):
    pass


class ArtifactLedgerCASMismatch(ArtifactLedgerError):
    """The persisted ledger no longer matches a caller's exact preimage."""


def _is_nonnegative_exact_int(value: object) -> bool:
    """Accept a nonnegative JSON integer, never a Python boolean."""

    return type(value) is int and value >= 0


def _is_positive_exact_int(value: object) -> bool:
    """Accept a positive JSON integer, never a Python boolean."""

    return type(value) is int and value >= 1


def _nested_output_records_have_exact_sizes(
    records: object,
    *,
    expected_identities: set[str] | frozenset[str] | None = None,
) -> bool:
    """Validate persisted output byte counts before equality or replay.

    Python considers booleans equal to integers.  Every authority projection
    therefore has to establish the JSON scalar type before raw dictionaries
    or individual sizes may be compared.  This predicate deliberately owns
    only the common nested-output invariant; callers retain their existing
    closed schemas, statuses, and digest rules.
    """

    if not isinstance(records, Mapping):
        return False
    identities = list(records)
    if any(
        not isinstance(identity, str) or not identity
        for identity in identities
    ):
        return False
    if (
        expected_identities is not None
        and set(identities) != set(expected_identities)
    ):
        return False
    return all(
        isinstance(record, Mapping)
        and _is_nonnegative_exact_int(record.get("size"))
        for record in records.values()
    )


def _observed_output_records_are_exact(
    records: object,
    *,
    expected_identities: set[str] | frozenset[str],
) -> bool:
    """Validate the complete physical observation schema and state pairing."""

    if not _nested_output_records_have_exact_sizes(
        records,
        expected_identities=expected_identities,
    ):
        return False
    assert isinstance(records, Mapping)
    required = {
        "status",
        "size",
        "sha256",
        "physical_identity",
        "physical_policy",
    }
    for raw in records.values():
        if not isinstance(raw, Mapping) or set(raw) != required:
            return False
        status = raw.get("status")
        physical = raw.get("physical_identity")
        if (
            raw.get("physical_policy") != _NO_FOLLOW_PHYSICAL_POLICY
            or not isinstance(physical, str)
        ):
            return False
        if status == "PRESENT":
            if not _is_digest(raw.get("sha256")) or not physical:
                return False
        elif status == "ABSENT":
            if (
                raw.get("sha256") != ""
                or raw.get("size") != 0
                or not physical
            ):
                return False
        elif status == "UNSAFE":
            if raw.get("sha256") != "" or raw.get("size") != 0:
                return False
        else:
            return False
    return True


def _replay_authority_pair(
    contract: PhaseIOContract,
    launch: LaunchSpec,
) -> tuple[PhaseIOContract, LaunchSpec]:
    try:
        return replay_phase_io_authority_pair(contract, launch)
    except (TypeError, ValueError) as exc:
        raise ArtifactLedgerError(
            f"PhaseIO contract/launch authority replay failed: {exc}"
        ) from exc


@contextmanager
def _ledger_transaction_lock(
    scratchpad: Path, *, timeout_s: float = 30.0,
):
    """Serialize ledger read-modify-write transactions across processes."""

    try:
        root = rooted_io.ensure_directory(
            scratchpad,
            parents=True,
            label="artifact ledger root",
        )
    except rooted_io.RootedPathIOError as exc:
        raise ArtifactLedgerError(
            "artifact ledger root is not a safe directory"
        ) from exc
    lock_path = rooted_io.absolute_path(root / _LEDGER_LOCK_FILE)
    # Persisted paths use ordinary spelling, but process lock identity must be
    # alias-stable and must never depend on Path.resolve() crossing MAX_PATH.
    key = os.path.normcase(os.path.normpath(os.fspath(lock_path)))
    held = getattr(_PROCESS_LOCK_STATE, "held", {})
    with _LEDGER_LOCK:
        if held.get(key, 0):
            held[key] += 1
            _PROCESS_LOCK_STATE.held = held
            try:
                yield
            finally:
                held[key] -= 1
            return
        flags = os.O_RDWR | os.O_CREAT
        flags |= int(getattr(os, "O_BINARY", 0) or 0)
        flags |= int(getattr(os, "O_NOFOLLOW", 0) or 0)
        descriptor = -1
        try:
            descriptor = os.open(
                rooted_io.native_path(lock_path),
                flags,
                0o600,
            )
            opened = os.fstat(descriptor)
            rooted_io.exact_existing_name(lock_path)
            named = rooted_io.lstat(lock_path)
            if (
                _metadata_is_reparse(opened)
                or not stat.S_ISREG(opened.st_mode)
                or int(getattr(opened, "st_nlink", 1) or 1) != 1
                or _metadata_is_reparse(named)
                or not stat.S_ISREG(named.st_mode)
                or int(getattr(named, "st_nlink", 1) or 1) != 1
                or _metadata_object_identity(opened)
                != _metadata_object_identity(named)
            ):
                raise ArtifactLedgerError(
                    "artifact ledger lock is not a stable single-link "
                    "no-follow regular file"
                )
            stream = os.fdopen(descriptor, "r+b", closefd=True)
            descriptor = -1
            if os.fstat(stream.fileno()).st_size == 0:
                stream.write(b"\0")
                stream.flush()
                os.fsync(stream.fileno())
            deadline = time.monotonic() + max(0.1, float(timeout_s))
            while True:
                try:
                    stream.seek(0)
                    if os.name == "nt":
                        import msvcrt

                        msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
                    else:
                        import fcntl

                        fcntl.flock(
                            stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB
                        )
                    break
                except (BlockingIOError, OSError):
                    if time.monotonic() >= deadline:
                        raise ArtifactLedgerError(
                            "artifact ledger interprocess lock contention timed out"
                        )
                    time.sleep(0.05)
            held[key] = 1
            _PROCESS_LOCK_STATE.held = held
            try:
                yield
            finally:
                held.pop(key, None)
                try:
                    stream.seek(0)
                    if os.name == "nt":
                        import msvcrt

                        msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
                    else:
                        import fcntl

                        fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
                except OSError:
                    pass
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            if "stream" in locals():
                stream.close()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(rooted_io.native_path(path), "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _empty() -> dict[str, Any]:
    return {
        "version": LEDGER_VERSION,
        "artifacts": {},
        "artifact_bindings": {},
        "work_units": {},
        _PROGRAM_FACTS_SELECTION_HISTORY_FIELD: {},
        _PROGRAM_FACTS_ACTIVE_SELECTION_FIELD: {"state": "ABSENT"},
    }


def _windows_native_path(path: Path) -> str:
    try:
        return rooted_io.native_path(path)
    except rooted_io.RootedPathIOError as exc:
        raise ArtifactLedgerError(
            f"artifact path cannot be translated safely: {path}"
        ) from exc


def _fsync_directory(path: Path) -> None:
    """Persist directory metadata where the host exposes that primitive."""

    directory = Path(path)
    if os.name == "nt":
        # Critical replacements use MOVEFILE_WRITE_THROUGH below.  Windows
        # does not provide POSIX directory fsync semantics to ordinary Python
        # handles, so the write-through rename is the metadata commit point.
        return
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    descriptor = os.open(os.fspath(directory), flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _durable_replace(source: Path, destination: Path) -> None:
    """Atomically replace and durably publish one critical control file."""

    rooted_io.durable_replace(Path(source), Path(destination))


def _write_rooted_control_bytes(path: Path, payload: bytes) -> None:
    """Durably replace one critical control file via a short rooted temp."""

    target = rooted_io.absolute_path(path)
    try:
        rooted_io.checked_directory(
            target.parent,
            label="artifact control parent",
        )
        descriptor, temporary = rooted_io.exclusive_temp_file(
            target.parent,
            prefix="_.p.",
            suffix=".tmp",
        )
    except rooted_io.RootedPathIOError as exc:
        raise ArtifactLedgerError(
            f"artifact control temporary cannot be created: {target}"
        ) from exc
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            descriptor = -1
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        _lexical_no_follow_chain(temporary)
        _durable_replace(temporary, target)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if rooted_io.lexists(temporary):
            rooted_io.unlink(temporary)


def read_artifact_ledger(scratchpad: Path) -> dict[str, Any]:
    root = Path(os.path.abspath(os.fspath(scratchpad)))
    path = root / LEDGER_NAME
    if not rooted_io.lexists(path):
        return _empty()
    try:
        _lexical_no_follow_chain(path)
        metadata = rooted_io.lstat(path)
        if (
            _metadata_is_reparse(metadata)
            or not stat.S_ISREG(metadata.st_mode)
            or int(getattr(metadata, "st_nlink", 1) or 1) != 1
        ):
            raise ArtifactLedgerError(
                "artifact ledger path is not a single-link no-follow "
                "regular file"
            )

        def _pairs(rows: list[tuple[str, Any]]) -> dict[str, Any]:
            result: dict[str, Any] = {}
            for key, value in rows:
                if key in result:
                    raise ArtifactLedgerError(
                        f"artifact ledger contains duplicate key {key!r}"
                    )
                result[key] = value
            return result

        data = json.loads(
            _read_stable_regular_bytes(
                path, limit=256 * 1024 * 1024
            ).decode("utf-8", errors="strict"),
            object_pairs_hook=_pairs,
            parse_constant=lambda token: (_ for _ in ()).throw(
                ArtifactLedgerError(
                    f"artifact ledger contains non-finite value {token}"
                )
            ),
        )
    except ArtifactLedgerError:
        raise
    except Exception as exc:
        raise ArtifactLedgerError(
            f"artifact ledger is unreadable: {type(exc).__name__}: {exc}"
        ) from exc
    if not isinstance(data, dict):
        raise ArtifactLedgerError("artifact ledger root must be an object")
    version = data.get("version", 1)
    if type(version) is not int or version not in {1, LEDGER_VERSION}:
        raise ArtifactLedgerError(f"unsupported artifact ledger version: {version!r}")
    for key in ("artifacts", "artifact_bindings", "work_units"):
        value = data.get(key, {})
        if not isinstance(value, dict):
            raise ArtifactLedgerError(f"artifact ledger {key} must be an object")
        data[key] = value
    _validate_program_facts_selection_ledger_state(data)
    data["work_units"] = {
        key: (
            _RootBoundWorkUnit(
                value,
                artifact_ledger_root=root,
            )
            if isinstance(value, Mapping)
            else value
        )
        for key, value in data["work_units"].items()
    }
    data["version"] = LEDGER_VERSION
    return data


def write_artifact_ledger(scratchpad: Path, ledger: dict[str, Any]) -> None:
    root = Path(os.path.abspath(os.fspath(scratchpad)))
    try:
        rooted_io.ensure_directory(
            root,
            parents=True,
            label="artifact ledger root",
        )
    except rooted_io.RootedPathIOError as exc:
        raise ArtifactLedgerError(
            "artifact ledger root is not a safe directory"
        ) from exc
    _lexical_no_follow_chain(root)
    path = root / LEDGER_NAME
    if rooted_io.lexists(path):
        _lexical_no_follow_chain(path)
        metadata = rooted_io.lstat(path)
        if (
            _metadata_is_reparse(metadata)
            or not stat.S_ISREG(metadata.st_mode)
            or int(getattr(metadata, "st_nlink", 1) or 1) != 1
        ):
            raise ArtifactLedgerError(
                "artifact ledger destination is not a single-link "
                "no-follow regular file"
            )
    payload = json.dumps(ledger, indent=2, sort_keys=True) + "\n"
    _write_rooted_control_bytes(path, payload.encode("utf-8"))
    _lexical_no_follow_chain(path)
    metadata = rooted_io.lstat(path)
    if (
        _metadata_is_reparse(metadata)
        or not stat.S_ISREG(metadata.st_mode)
        or int(getattr(metadata, "st_nlink", 1) or 1) != 1
    ):
        raise ArtifactLedgerError(
            "artifact ledger publication is unsafe"
        )


def _mutation_event_digest(event: dict[str, Any]) -> str:
    unsigned = {key: value for key, value in event.items() if key != "event_digest"}
    encoded = json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )
    return hashlib.sha256(encoded).hexdigest()


def semantic_mutation_authority_digest(event: dict[str, Any]) -> str:
    """Digest immutable mutation outcome facts, excluding self-ack fields."""

    unsigned = {
        key: value for key, value in event.items()
        if key not in {
            "event_digest", "checkpoint_reconciled", "reconciled_by_run_id",
        }
    }
    return hashlib.sha256(
        json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
    ).hexdigest()


def _semantic_virtual_producer_core(
    *,
    identity: str,
    run_id: str,
    producer: Mapping[str, Any],
    mutation_event_ids: Sequence[str],
    mutation_authority_digests: Sequence[str],
    live_state: Mapping[str, Any],
) -> dict[str, Any]:
    """Canonical facts shared by live minting and frozen replay.

    This is intentionally one constructor: a frozen verifier must recompute
    the byte-for-byte producer digest minted by the live lineage resolver.
    Parallel hand-written field sets previously allowed the two paths to
    diverge while each remained internally plausible.
    """

    return {
        "identity": str(identity),
        "run_id": str(run_id),
        "historical_owner_key": str(producer["owner_key"]),
        "historical_contract_digest": str(producer["contract_digest"]),
        "historical_launch_digest": str(
            producer.get("launch_digest") or ""
        ),
        "historical_size": int(producer["size"]),
        "historical_sha256": str(producer["sha256"]),
        "mutation_event_ids": [str(value) for value in mutation_event_ids],
        "mutation_authority_digests": [
            str(value) for value in mutation_authority_digests
        ],
        "live_size": int(live_state["size"]),
        "live_sha256": str(live_state["sha256"]),
    }


def _semantic_virtual_producer_digest(
    authority_core: Mapping[str, Any],
) -> str:
    return hashlib.sha256(
        json.dumps(
            dict(authority_core),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()


def _semantic_mutation_event_id(event: dict[str, Any], ordinal: int) -> str:
    before = event.get("before") if isinstance(event.get("before"), dict) else {}
    return "SMUT-" + hashlib.sha256(
        "\0".join((
            str(event.get("run_id") or ""),
            str(event.get("mutation_kind") or ""),
            str(event.get("artifact_identity") or ""),
            str(before.get("status") or ""),
            str(before.get("sha256") or ""),
            str(ordinal),
        )).encode("utf-8")
    ).hexdigest()[:24].upper()


def _valid_semantic_artifact_snapshot(value: object) -> bool:
    if not isinstance(value, dict) or set(value) != {"status", "size", "sha256"}:
        return False
    status = value.get("status")
    size = value.get("size")
    digest = value.get("sha256")
    if (
        status not in {"ACTIVE", "MISSING"}
        or not _is_nonnegative_exact_int(size)
    ):
        return False
    if not isinstance(digest, str):
        return False
    if status == "MISSING":
        return size == 0 and digest == ""
    return len(digest) == 64 and all(ch in "0123456789abcdef" for ch in digest)


def _validate_semantic_mutation_event(event: dict[str, Any], ordinal: int) -> None:
    legacy_keys = {
        "schema", "event_id", "run_id", "mutation_kind", "artifact_identity",
        "status", "before", "after", "affected_record_ids",
        "invalidated_work_unit_keys", "plan_digest", "checkpoint_reconciled",
        "reconciled_by_run_id", "event_digest",
    }
    current_keys = legacy_keys | {"transition_authority"}
    if (
        frozenset(event) not in {
            frozenset(legacy_keys),
            frozenset(current_keys),
        }
        or event.get("schema") != "plamen.semantic_mutation.v1"
    ):
        raise ArtifactLedgerError("semantic mutation event schema/key mismatch")
    if (
        not str(event.get("run_id") or "").strip()
        or not str(event.get("mutation_kind") or "").strip()
        or str(event.get("mutation_kind")) != str(event.get("mutation_kind")).upper()
        or event.get("event_id") != _semantic_mutation_event_id(event, ordinal)
    ):
        raise ArtifactLedgerError("semantic mutation event identity failure")
    identity = str(event.get("artifact_identity") or "")
    if identity.count(":") != 1 or identity.split(":", 1)[0] not in {
        "scratchpad", "project",
    } or not identity.split(":", 1)[1]:
        raise ArtifactLedgerError("semantic mutation artifact identity failure")
    if not _valid_semantic_artifact_snapshot(event.get("before")):
        raise ArtifactLedgerError("semantic mutation before-state failure")
    for key in ("affected_record_ids", "invalidated_work_unit_keys"):
        values = event.get(key)
        if (
            not isinstance(values, list)
            or any(not isinstance(value, str) or not value for value in values)
            or values != sorted(set(values))
        ):
            raise ArtifactLedgerError(f"semantic mutation {key} denominator failure")
    reconciled = event.get("checkpoint_reconciled")
    reconciled_by = event.get("reconciled_by_run_id")
    if not isinstance(reconciled, bool) or not isinstance(reconciled_by, str):
        raise ArtifactLedgerError("semantic mutation reconciliation state failure")
    if reconciled != bool(reconciled_by):
        raise ArtifactLedgerError("semantic mutation reconciliation binding failure")

    status = event.get("status")
    after = event.get("after")
    invalidated = event.get("invalidated_work_unit_keys")
    plan_digest = event.get("plan_digest")
    transition = event.get("transition_authority", {})
    if not isinstance(transition, dict):
        raise ArtifactLedgerError(
            "semantic mutation transition authority is malformed"
        )
    if transition:
        expected_transition_keys = {
            "transition_kind",
            "preimage_sha256",
            "preimage_size",
            "successor_sha256",
            "successor_size",
            "appended_sha256",
            "appended_size",
        }
        if (
            set(transition) != expected_transition_keys
            or transition.get("transition_kind")
            not in {"NO_CHANGE", "STRICT_APPEND", "REPLACEMENT"}
            or not isinstance(transition.get("preimage_size"), int)
            or isinstance(transition.get("preimage_size"), bool)
            or int(transition.get("preimage_size") or 0) < 0
            or not isinstance(transition.get("successor_size"), int)
            or isinstance(transition.get("successor_size"), bool)
            or int(transition.get("successor_size") or 0) < 0
            or not isinstance(transition.get("appended_size"), int)
            or isinstance(transition.get("appended_size"), bool)
            or int(transition.get("appended_size") or 0) < 0
            or any(
                not isinstance(transition.get(key), str)
                or len(str(transition.get(key) or "")) != 64
                or any(
                    char not in "0123456789abcdef"
                    for char in str(transition.get(key) or "")
                )
                for key in (
                    "preimage_sha256",
                    "successor_sha256",
                    "appended_sha256",
                )
            )
        ):
            raise ArtifactLedgerError(
                "semantic mutation transition authority is invalid"
            )
        before = event.get("before")
        if (
            not isinstance(before, dict)
            or not isinstance(after, dict)
            or transition.get("preimage_sha256")
            != str(before.get("sha256") or "")
            or transition.get("preimage_size") != before.get("size")
            or transition.get("successor_sha256")
            != str(after.get("sha256") or "")
            or transition.get("successor_size") != after.get("size")
        ):
            raise ArtifactLedgerError(
                "semantic mutation transition snapshot binding failed"
            )
        empty_digest = hashlib.sha256(b"").hexdigest()
        if transition.get("transition_kind") == "NO_CHANGE" and (
            before != after
            or transition.get("appended_size") != 0
            or transition.get("appended_sha256") != empty_digest
        ):
            raise ArtifactLedgerError(
                "semantic mutation NO_CHANGE transition is invalid"
            )
        if transition.get("transition_kind") == "STRICT_APPEND" and (
            before.get("status") != "ACTIVE"
            or after.get("status") != "ACTIVE"
            or int(transition["successor_size"])
            <= int(transition["preimage_size"])
            or int(transition["appended_size"])
            != (
                int(transition["successor_size"])
                - int(transition["preimage_size"])
            )
        ):
            raise ArtifactLedgerError(
                "semantic mutation STRICT_APPEND transition is invalid"
            )
    if status == "ARMED":
        if (
            after != {}
            or event.get("affected_record_ids") != []
            or invalidated != []
            or plan_digest != ""
            or reconciled
            or transition
        ):
            raise ArtifactLedgerError("semantic mutation ARMED state failure")
    elif status == "NO_CHANGE":
        if (
            not _valid_semantic_artifact_snapshot(after)
            or after != event.get("before")
            or invalidated != []
            or plan_digest != ""
            or not reconciled
            or (
                transition
                and transition.get("transition_kind") != "NO_CHANGE"
            )
        ):
            raise ArtifactLedgerError("semantic mutation NO_CHANGE state failure")
    elif status == "INVALIDATION_APPLIED":
        if (
            not _valid_semantic_artifact_snapshot(after)
            or after == event.get("before")
            or not isinstance(plan_digest, str)
            or len(plan_digest) != 64
            or any(ch not in "0123456789abcdef" for ch in plan_digest)
            or (
                transition
                and transition.get("transition_kind") == "NO_CHANGE"
            )
        ):
            raise ArtifactLedgerError(
                "semantic mutation INVALIDATION_APPLIED state failure"
            )
    else:
        raise ArtifactLedgerError("semantic mutation status failure")


def _read_semantic_mutations(scratchpad: Path) -> dict[str, Any]:
    path = Path(scratchpad) / SEMANTIC_MUTATION_LEDGER_NAME
    if not path.is_file():
        return {"schema": "plamen.semantic_mutations.v1", "events": []}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise ArtifactLedgerError(
            f"semantic mutation ledger is unreadable: {type(exc).__name__}: {exc}"
        ) from exc
    if (
        not isinstance(payload, dict)
        or payload.get("schema") != "plamen.semantic_mutations.v1"
        or not isinstance(payload.get("events"), list)
    ):
        raise ArtifactLedgerError("semantic mutation ledger schema is malformed")
    seen: set[str] = set()
    for ordinal, event in enumerate(payload["events"], 1):
        if (
            not isinstance(event, dict)
            or not isinstance(event.get("event_id"), str)
            or not event.get("event_id")
            or event["event_id"] in seen
            or event.get("event_digest") != _mutation_event_digest(event)
        ):
            raise ArtifactLedgerError("semantic mutation event integrity failure")
        _validate_semantic_mutation_event(event, ordinal)
        seen.add(event["event_id"])
    return payload


def _write_semantic_mutations(scratchpad: Path, payload: dict[str, Any]) -> None:
    path = Path(scratchpad) / SEMANTIC_MUTATION_LEDGER_NAME
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", newline="\n", dir=str(path.parent),
        delete=False, prefix=f".{path.name}.", suffix=".tmp",
    ) as stream:
        stream.write(encoded)
        temporary = Path(stream.name)
    os.replace(temporary, path)


def _metadata_is_reparse(metadata: os.stat_result) -> bool:
    return bool(
        stat.S_ISLNK(metadata.st_mode)
        or int(getattr(metadata, "st_file_attributes", 0) or 0) & 0x400
    )


def _metadata_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        int(metadata.st_mode),
        int(metadata.st_size),
        int(metadata.st_mtime_ns),
        int(getattr(metadata, "st_dev", 0) or 0),
        int(getattr(metadata, "st_ino", 0) or 0),
        int(getattr(metadata, "st_nlink", 1) or 1),
        int(getattr(metadata, "st_file_attributes", 0) or 0),
    )


def _metadata_object_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        int(metadata.st_mode),
        int(getattr(metadata, "st_dev", 0) or 0),
        int(getattr(metadata, "st_ino", 0) or 0),
        int(getattr(metadata, "st_file_attributes", 0) or 0),
    )


def _lexical_no_follow_chain(path: Path) -> tuple[tuple[str, tuple[int, ...]], ...]:
    """Capture every existing path component without resolving a link.

    Exact spelling and NFC are part of the physical policy.  This rejects
    Windows case aliases, alternate-data-stream syntax, symlinks, junctions,
    mount-point reparses, and a parent swap that occurs during a stable read.
    """

    try:
        absolute = rooted_io.absolute_path(path)
    except rooted_io.RootedPathIOError as exc:
        raise ArtifactLedgerError(
            f"artifact physical path is malformed: {path}"
        ) from exc
    drive, _tail = os.path.splitdrive(str(absolute))
    rows: list[tuple[str, tuple[int, ...]]] = []
    current = Path(absolute.anchor or drive + os.sep)
    parts = absolute.parts[1:] if absolute.anchor else absolute.parts
    missing = False
    for component in parts:
        if (
            not component
            or component in {".", ".."}
            or ":" in component
            or unicodedata.normalize("NFC", component) != component
        ):
            raise ArtifactLedgerError(
                f"artifact physical path has unsafe lexical component: {path}"
            )
        if missing:
            current = current / component
            continue
        candidate = current / component
        try:
            metadata = rooted_io.lstat(candidate)
        except FileNotFoundError:
            missing = True
            current = candidate
            continue
        except OSError as exc:
            raise ArtifactLedgerError(
                f"artifact physical ancestor is unreadable: {path}"
            ) from exc
        try:
            rooted_io.exact_existing_name(candidate)
        except rooted_io.RootedPathIOError as exc:
            raise ArtifactLedgerError(
                f"artifact physical path uses a case/NFC alias: {path}"
            ) from exc
        current = candidate
        try:
            confirmed = rooted_io.lstat(current)
        except OSError as exc:
            raise ArtifactLedgerError(
                f"artifact physical component changed during inspection: {path}"
            ) from exc
        if (
            _metadata_object_identity(metadata)
            != _metadata_object_identity(confirmed)
        ):
            raise ArtifactLedgerError(
                f"artifact physical component changed during inspection: {path}"
            )
        if _metadata_is_reparse(confirmed):
            raise ArtifactLedgerError(
                f"artifact physical path contains a symlink/reparse component: {path}"
            )
        rows.append((str(current), _metadata_object_identity(confirmed)))
    return tuple(rows)


def _lexical_no_follow_chains(
    paths: Iterable[Path],
) -> dict[str, tuple[tuple[str, tuple[int, ...]], ...]]:
    """Capture a path denominator while inspecting each ancestor once.

    This is an invocation-local path trie, not a persistent cache.  Exact
    spelling remains part of every key, while common existing ancestors share
    one no-follow/name/identity inspection in this terminal capture.
    """

    results: dict[str, tuple[tuple[str, tuple[int, ...]], ...]] = {}
    components: dict[str, tuple[str, tuple[int, ...]] | None] = {}
    for original in paths:
        try:
            absolute = rooted_io.absolute_path(original)
        except rooted_io.RootedPathIOError as exc:
            raise ArtifactLedgerError(
                f"artifact physical path is malformed: {original}"
            ) from exc
        result_key = os.path.normcase(os.path.abspath(os.fspath(absolute)))
        rows: list[tuple[str, tuple[int, ...]]] = []
        drive, _tail = os.path.splitdrive(str(absolute))
        current = Path(absolute.anchor or drive + os.sep)
        parts = absolute.parts[1:] if absolute.anchor else absolute.parts
        missing = False
        for component in parts:
            if (
                not component
                or component in {".", ".."}
                or ":" in component
                or unicodedata.normalize("NFC", component) != component
            ):
                raise ArtifactLedgerError(
                    "artifact physical path has unsafe lexical component: "
                    f"{original}"
                )
            candidate = current / component
            current = candidate
            if missing:
                continue
            # Preserve exact spelling in the trie key.  A case-aliased sibling
            # must execute its own exact-name check and reject.
            component_key = os.path.abspath(os.fspath(candidate))
            cached = components.get(component_key, ...)
            if cached is None:
                missing = True
                continue
            if cached is not ...:
                rows.append(cached)
                continue
            try:
                metadata = rooted_io.lstat(candidate)
            except FileNotFoundError:
                components[component_key] = None
                missing = True
                continue
            except OSError as exc:
                raise ArtifactLedgerError(
                    f"artifact physical ancestor is unreadable: {original}"
                ) from exc
            try:
                rooted_io.exact_existing_name(candidate)
            except rooted_io.RootedPathIOError as exc:
                raise ArtifactLedgerError(
                    f"artifact physical path uses a case/NFC alias: {original}"
                ) from exc
            try:
                confirmed = rooted_io.lstat(candidate)
            except OSError as exc:
                raise ArtifactLedgerError(
                    "artifact physical component changed during inspection: "
                    f"{original}"
                ) from exc
            identity = _metadata_object_identity(confirmed)
            if _metadata_object_identity(metadata) != identity:
                raise ArtifactLedgerError(
                    "artifact physical component changed during inspection: "
                    f"{original}"
                )
            if _metadata_is_reparse(confirmed):
                raise ArtifactLedgerError(
                    "artifact physical path contains a symlink/reparse "
                    f"component: {original}"
                )
            row = (str(candidate), identity)
            components[component_key] = row
            rows.append(row)
        results[result_key] = tuple(rows)
    return results


def _path_for_identity(
    scratchpad: Path, project_root: Path, identity: str,
) -> Path:
    candidate, _base_chain, _candidate_chain = (
        _path_for_identity_with_chains(scratchpad, project_root, identity)
    )
    return candidate


def _path_for_identity_with_chains(
    scratchpad: Path,
    project_root: Path,
    identity: str,
    *,
    _known_base_chain: tuple[tuple[str, tuple[int, ...]], ...] | None = None,
) -> tuple[
    Path,
    tuple[tuple[str, tuple[int, ...]], ...],
    tuple[tuple[str, tuple[int, ...]], ...],
]:
    root, relative = identity.split(":", 1)
    base = Path(scratchpad) if root == "scratchpad" else Path(project_root)
    base_absolute = Path(os.path.abspath(os.fspath(base)))
    candidate = base_absolute.joinpath(*PurePosixPath(relative).parts)
    try:
        common = os.path.commonpath((str(base_absolute), str(candidate)))
    except (OSError, ValueError) as exc:
        raise ArtifactLedgerError(
            f"artifact physical path cannot be checked safely: {identity}"
        ) from exc
    if os.path.normcase(common) != os.path.normcase(str(base_absolute)):
        raise ArtifactLedgerError(
            f"artifact physical path escapes its declared root: {identity}"
        )
    base_chain = (
        _lexical_no_follow_chain(base_absolute)
        if _known_base_chain is None
        else _known_base_chain
    )
    candidate_chain = _lexical_no_follow_chain(candidate)
    return candidate, base_chain, candidate_chain


def _physical_file_identity(path: Path) -> str:
    """Return an OS-aware identity without following filesystem aliases."""

    try:
        _lexical_no_follow_chain(path)
        try:
            metadata = rooted_io.lstat(path)
        except FileNotFoundError:
            return (
                f"path:{os.path.normcase(os.path.abspath(os.fspath(path)))}"
            )
        if _metadata_is_reparse(metadata):
            raise ArtifactLedgerError(
                f"artifact physical identity rejects symlink/reparse: {path}"
            )
        inode = int(getattr(metadata, "st_ino", 0) or 0)
        device = int(getattr(metadata, "st_dev", 0) or 0)
        if inode:
            return f"file:{device}:{inode}"
        return f"path:{os.path.normcase(os.path.abspath(os.fspath(path)))}"
    except OSError as exc:
        raise ArtifactLedgerError(
            f"artifact physical identity unavailable: {path}"
        ) from exc


def _legacy_name(identity: str) -> str:
    root, relative = identity.split(":", 1)
    return relative if root == "scratchpad" else f"../{relative}"


def _stable_artifact_snapshot(
    path: Path,
    *,
    confirmation_reads: bool = True,
    _known_chain: tuple[tuple[str, tuple[int, ...]], ...] | None = None,
    _captured_chain: list[tuple[tuple[str, tuple[int, ...]], ...]] | None = None,
) -> tuple[dict[str, Any] | None, str]:
    """Hash one file only when its metadata is stable across the read.

    This is deterministic single-process containment, not an interprocess file
    lease.  A concurrent writer cannot be allowed to turn an indeterminate
    snapshot into ACTIVE authority merely because one of two metadata reads
    happened to line up.
    """

    descriptor = -1
    try:
        before_chain = (
            _lexical_no_follow_chain(path)
            if _known_chain is None
            else _known_chain
        )
        if _captured_chain is not None:
            _captured_chain.append(before_chain)
        before = rooted_io.lstat(path)
        if _metadata_is_reparse(before) or not stat.S_ISREG(before.st_mode):
            return None, "NOT_A_NOFOLLOW_REGULAR_FILE"
        flags = os.O_RDONLY | int(getattr(os, "O_BINARY", 0) or 0)
        flags |= int(getattr(os, "O_NOFOLLOW", 0) or 0)
        descriptor = os.open(rooted_io.native_path(path), flags)
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or _metadata_identity(opened) != _metadata_identity(before)
        ):
            return None, "OPENED_FILE_IDENTITY_CHANGED"
        digest_object = hashlib.sha256()
        size = 0
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest_object.update(chunk)
            size += len(chunk)
        after_fd = os.fstat(descriptor)
        after = rooted_io.lstat(path)
        after_chain = (
            _lexical_no_follow_chain(path)
            if _known_chain is None
            else _known_chain
        )
    except (ArtifactLedgerError, OSError) as exc:
        return None, f"SNAPSHOT_IO_{type(exc).__name__.upper()}"
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass
    if (
        before_chain != after_chain
        or _metadata_identity(before) != _metadata_identity(opened)
        or _metadata_identity(opened) != _metadata_identity(after_fd)
        or _metadata_identity(after_fd) != _metadata_identity(after)
        or size != int(after.st_size)
    ):
        return None, "UNSTABLE_FILE_SNAPSHOT"
    digest = digest_object.hexdigest()
    if not confirmation_reads:
        return {
            "size": after.st_size,
            "mtime_ns": after.st_mtime_ns,
            "sha256": digest,
        }, ""
    try:
        confirm_digest = _sha256(path)
        middle_metadata = rooted_io.lstat(path)
        replay_digest = _sha256(path)
        confirm_metadata = rooted_io.lstat(path)
        confirm_chain = _lexical_no_follow_chain(path)
    except (ArtifactLedgerError, OSError) as exc:
        return None, f"SNAPSHOT_CONFIRM_{type(exc).__name__.upper()}"
    if (
        confirm_digest != digest
        or replay_digest != digest
        or confirm_chain != after_chain
        or _metadata_identity(middle_metadata)
        != _metadata_identity(after)
        or _metadata_identity(confirm_metadata)
        != _metadata_identity(after)
    ):
        return None, "UNSTABLE_FILE_CONTENT"
    return {
        "size": after.st_size,
        "mtime_ns": after.st_mtime_ns,
        "sha256": digest,
    }, ""


def _stable_prefix_sha256(path: Path, length: int) -> tuple[str, str]:
    if not isinstance(length, int) or length < 0:
        return "", "INVALID_PREFIX_LENGTH"
    descriptor = -1
    try:
        before_chain = _lexical_no_follow_chain(path)
        before = rooted_io.lstat(path)
        if _metadata_is_reparse(before) or not stat.S_ISREG(before.st_mode):
            return "", "NOT_A_NOFOLLOW_REGULAR_FILE"
        flags = os.O_RDONLY | int(getattr(os, "O_BINARY", 0) or 0)
        flags |= int(getattr(os, "O_NOFOLLOW", 0) or 0)
        descriptor = os.open(rooted_io.native_path(path), flags)
        opened = os.fstat(descriptor)
        first = bytearray()
        while len(first) < length:
            chunk = os.read(descriptor, min(1024 * 1024, length - len(first)))
            if not chunk:
                break
            first.extend(chunk)
        after_fd = os.fstat(descriptor)
        after = rooted_io.lstat(path)
        after_chain = _lexical_no_follow_chain(path)
    except (ArtifactLedgerError, OSError) as exc:
        return "", f"PREFIX_IO_{type(exc).__name__.upper()}"
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass
    if (
        len(first) != length
        or before_chain != after_chain
        or _metadata_identity(before) != _metadata_identity(opened)
        or _metadata_identity(opened) != _metadata_identity(after_fd)
        or _metadata_identity(after_fd) != _metadata_identity(after)
    ):
        return "", "UNSTABLE_PREFIX_SNAPSHOT"
    return hashlib.sha256(bytes(first)).hexdigest(), ""


def _commit_receipt_digest(receipt: Mapping[str, Any]) -> str:
    unsigned = {
        key: value for key, value in receipt.items() if key != "receipt_digest"
    }
    return hashlib.sha256(
        json.dumps(
            unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")
    ).hexdigest()


def _canonical_json_bytes(value: Mapping[str, Any]) -> bytes:
    return json.dumps(
        dict(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def _canonical_json_digest(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(_canonical_json_bytes(value)).hexdigest()


def _assert_strict_json_domain(
    value: Any,
    *,
    _active: set[int] | None = None,
) -> None:
    """Reject Python-only values before a JSON freeze can normalize them."""

    if value is None or type(value) in {str, int, bool}:
        return
    active = set() if _active is None else _active
    if type(value) is list:
        identity = id(value)
        if identity in active:
            raise ArtifactLedgerError("artifact ledger JSON domain is cyclic")
        active.add(identity)
        try:
            for item in value:
                _assert_strict_json_domain(item, _active=active)
        finally:
            active.remove(identity)
        return
    if type(value) is dict:
        identity = id(value)
        if identity in active:
            raise ArtifactLedgerError("artifact ledger JSON domain is cyclic")
        active.add(identity)
        try:
            for key, item in value.items():
                if type(key) is not str:
                    raise ArtifactLedgerError(
                        "artifact ledger JSON object key is not an exact string"
                    )
                _assert_strict_json_domain(item, _active=active)
        finally:
            active.remove(identity)
        return
    raise ArtifactLedgerError(
        "artifact ledger contains a non-JSON-domain value"
    )


def _freeze_artifact_ledger_revision(
    ledger: Mapping[str, Any],
) -> tuple[dict[str, Any], str]:
    """Freeze one persisted ledger value and derive its canonical revision.

    ``read_artifact_ledger`` decorates work-unit rows with a private root
    capability.  That ambient capability is deliberately projected away;
    the revision covers exactly the JSON authority that can be published.
    Every other Python-only value or container subclass is rejected before
    publication so a CAS precondition cannot be changed by JSON coercion.
    """

    if type(ledger) is not dict:
        raise ArtifactLedgerError(
            "artifact ledger CAS value must be an exact dictionary"
        )
    projected = dict(ledger)
    work_units = projected.get("work_units")
    if type(work_units) is dict:
        plain_work_units: dict[str, Any] = {}
        for key, value in work_units.items():
            plain_work_units[key] = (
                dict(value)
                if type(value) is _RootBoundWorkUnit
                else value
            )
        projected["work_units"] = plain_work_units
    _assert_strict_json_domain(projected)
    frozen = _canonical_json_bytes(projected)
    normalized = json.loads(frozen.decode("utf-8", errors="strict"))
    if type(normalized) is not dict:
        raise ArtifactLedgerError(
            "artifact ledger CAS value did not freeze to an object"
        )
    return normalized, hashlib.sha256(frozen).hexdigest()


def artifact_ledger_digest(ledger: Mapping[str, Any]) -> str:
    """Return the canonical persisted-JSON revision for a ledger snapshot."""

    _normalized, digest = _freeze_artifact_ledger_revision(ledger)
    return digest


def _validated_artifact_ledger_cas_candidate(
    candidate: Mapping[str, Any],
) -> tuple[dict[str, Any], str]:
    """Apply the read-side ledger schema checks before CAS publication."""

    normalized, _digest = _freeze_artifact_ledger_revision(candidate)
    version = normalized.get("version", 1)
    if type(version) is not int or version not in {1, LEDGER_VERSION}:
        raise ArtifactLedgerError(
            f"unsupported artifact ledger version: {version!r}"
        )
    for key in ("artifacts", "artifact_bindings", "work_units"):
        value = normalized.get(key, {})
        if type(value) is not dict:
            raise ArtifactLedgerError(
                f"artifact ledger {key} must be an object"
            )
        normalized[key] = value
    _validate_program_facts_selection_ledger_state(normalized)
    normalized["version"] = LEDGER_VERSION
    return _freeze_artifact_ledger_revision(normalized)


def compare_and_swap_artifact_ledger(
    scratchpad: Path,
    *,
    expected_digest: str,
    mutator: Callable[
        [dict[str, Any]], dict[str, Any] | None
    ],
    timeout_s: float = 30.0,
) -> tuple[dict[str, Any], str]:
    """Atomically mutate the ledger iff its exact revision is still current.

    The advisory interprocess lock remains held across the stable read,
    revision check, callback, durable atomic replacement, and verification
    read.  ``mutator`` receives a detached strict-JSON preimage.  It may
    mutate that object in place and return ``None``, or return a replacement
    exact dictionary.  Exceptions and stale revisions publish nothing.

    The returned pair is the committed ledger and its canonical revision.
    A crash after durable publication is safely observable by a subsequent
    stale-digest rejection rather than a second blind mutation.
    """

    if (
        type(expected_digest) is not str
        or re.fullmatch(r"[0-9a-f]{64}", expected_digest, re.ASCII) is None
    ):
        raise ArtifactLedgerError(
            "artifact ledger CAS expected digest is malformed"
        )
    if not callable(mutator):
        raise ArtifactLedgerError("artifact ledger CAS mutator is not callable")

    with _ledger_transaction_lock(Path(scratchpad), timeout_s=timeout_s):
        current = read_artifact_ledger(Path(scratchpad))
        working, current_digest = _freeze_artifact_ledger_revision(current)
        if current_digest != expected_digest:
            raise ArtifactLedgerCASMismatch(
                "artifact ledger CAS preimage is stale: "
                f"expected {expected_digest}, observed {current_digest}"
            )

        result = mutator(working)
        # The underlying advisory lock is intentionally reentrant for legacy
        # ledger transactions.  A mutator can therefore invoke a nested CAS
        # (or another same-thread writer) without deadlocking.  Recheck the
        # persisted preimage after callback return so an inner durable commit
        # makes this outer transaction stale instead of being overwritten by
        # the outer detached working copy.
        post_callback = read_artifact_ledger(Path(scratchpad))
        _post_callback_normalized, post_callback_digest = (
            _freeze_artifact_ledger_revision(post_callback)
        )
        if post_callback_digest != expected_digest:
            raise ArtifactLedgerCASMismatch(
                "artifact ledger CAS preimage changed during mutation: "
                f"expected {expected_digest}, observed "
                f"{post_callback_digest}"
            )
        candidate = working if result is None else result
        normalized, candidate_digest = _validated_artifact_ledger_cas_candidate(
            candidate
        )
        write_artifact_ledger(Path(scratchpad), normalized)
        committed = read_artifact_ledger(Path(scratchpad))
        _committed_normalized, committed_digest = (
            _freeze_artifact_ledger_revision(committed)
        )
        if committed_digest != candidate_digest:
            raise ArtifactLedgerError(
                "artifact ledger CAS durable publication verification failed"
            )
        return committed, committed_digest


class _ArtifactValidationContext:
    """One invocation-local, mutation-detecting validation epoch.

    Every unique artifact path is read once during validation and once at the
    terminal boundary.  Producer replay results are keyed by the exact work
    unit and commit receipt, so sibling outputs are not rehashed for every
    consumer edge.  The context is private and is never persisted or shared
    across transaction API calls or durability barriers.
    """

    def __init__(
        self,
        scratchpad: Path,
        project_root: Path,
        *,
        ledger: Mapping[str, Any] | None = None,
    ) -> None:
        self.scratchpad = Path(scratchpad)
        self.project_root = Path(project_root)
        source_ledger = (
            read_artifact_ledger(self.scratchpad)
            if ledger is None
            else dict(ledger)
        )
        # ``read_artifact_ledger`` deliberately decorates persisted work-unit
        # objects with a private, non-serialized root capability used by exact
        # repair replay.  That ambient capability is not JSON authority and
        # must not be fed to the canonical encoder.  Admit only that exact
        # internal wrapper, only in the work-unit denominator, and only when
        # its bound root is this context's canonical ledger root.  Every other
        # dict subclass/custom object remains outside the strict JSON domain.
        bound_work_units: set[str] = set()
        work_units = source_ledger.get("work_units")
        if type(work_units) is dict:
            projected_work_units: dict[str, Any] = {}
            canonical_scratchpad = Path(
                os.path.abspath(os.fspath(self.scratchpad))
            )
            for key, value in work_units.items():
                if type(value) is _RootBoundWorkUnit:
                    if (
                        type(key) is not str
                        or getattr(value, "_artifact_ledger_root", None)
                        != canonical_scratchpad
                    ):
                        raise ArtifactLedgerError(
                            "artifact ledger work-unit root binding is invalid"
                        )
                    projected_work_units[key] = dict(value)
                    bound_work_units.add(key)
                else:
                    projected_work_units[key] = value
            source_ledger["work_units"] = projected_work_units
        # Ledger state is a strict persisted-JSON authority.  One canonical
        # serialization both freezes caller-owned containers and supplies the
        # exact immutable revision key; recursive ``deepcopy`` followed by a
        # second canonical traversal became quadratic as history grew.
        _assert_strict_json_domain(source_ledger)
        frozen_ledger = _canonical_json_bytes(source_ledger)
        self.ledger = json.loads(frozen_ledger.decode("utf-8", errors="strict"))
        if bound_work_units:
            decoded_work_units = self.ledger.get("work_units")
            if type(decoded_work_units) is not dict:
                raise ArtifactLedgerError(
                    "artifact ledger work-unit denominator is invalid"
                )
            for key in bound_work_units:
                value = decoded_work_units.get(key)
                if type(value) is not dict:
                    raise ArtifactLedgerError(
                        "artifact ledger bound work-unit is invalid"
                    )
                decoded_work_units[key] = _RootBoundWorkUnit(
                    value,
                    artifact_ledger_root=canonical_scratchpad,
                )
        self._ledger_digest = hashlib.sha256(frozen_ledger).hexdigest()
        self._snapshots: dict[
            str,
            tuple[
                Path,
                dict[str, Any] | None,
                str,
                str,
                tuple[tuple[str, tuple[int, ...]], ...],
            ],
        ] = {}
        self.producer_replay_issues: dict[
            tuple[
                str,
                str,
                str,
                str,
                bool,
                tuple[str, ...],
                tuple[tuple[str, str], ...],
                bool,
            ],
            tuple[str, ...],
        ] = {}
        self.input_binding_records: dict[
            tuple[str, str, str], dict[str, Any]
        ] = {}
        # A producer receipt covers its complete output bundle.  Many exact
        # consumer inputs can therefore replay the same historical bundle in
        # one validation epoch.  Resolving semantic-mutation exemptions walks
        # and hashes that bundle, so cache the base result by the exact frozen
        # producer authority and union the caller's already-verified identity
        # below.  Every consulted path is also captured by ``snapshot`` and is
        # rechecked by ``finish``; this is an epoch-local memo, never durable
        # authority.
        self.semantic_mutation_bundle_exemptions: dict[
            tuple[str, str, str, str, str], tuple[str, ...]
        ] = {}
        self._output_authority_journal: dict[str, Any] | None = None
        self._output_authority_cas: dict[str, dict[str, Any]] = {}
        self._immutable_control_paths: dict[
            str,
            tuple[Path, str, int, tuple[int, ...], str],
        ] = {}
        self._identity_paths: dict[
            str,
            tuple[
                Path,
                tuple[tuple[str, tuple[int, ...]], ...],
                tuple[tuple[str, tuple[int, ...]], ...],
            ],
        ] = {}
        self._identity_root_chains: dict[
            str,
            tuple[tuple[str, tuple[int, ...]], ...],
        ] = {}
        self._physical_owner_identities: dict[
            str, tuple[Path, str, tuple[int, ...] | None]
        ] = {}
        self._closed = False

    @staticmethod
    def _path_key(path: Path) -> str:
        return os.path.normcase(os.path.abspath(os.fspath(path)))

    def snapshot(
        self, path: Path
    ) -> tuple[dict[str, Any] | None, str]:
        if self._closed:
            raise ArtifactLedgerError("artifact validation epoch is closed")
        candidate = Path(path)
        key = self._path_key(candidate)
        cached = self._snapshots.get(key)
        if cached is None:
            captured_chain: list[
                tuple[tuple[str, tuple[int, ...]], ...]
            ] = []
            snapshot, error = _stable_artifact_snapshot(
                candidate,
                confirmation_reads=False,
                _captured_chain=captured_chain,
            )
            physical = ""
            if snapshot is not None:
                try:
                    physical = _physical_file_identity(candidate)
                except (ArtifactLedgerError, OSError):
                    error = "SNAPSHOT_PHYSICAL_IDENTITY_UNAVAILABLE"
                    snapshot = None
            elif not rooted_io.lexists(candidate):
                # Missing conditional outputs still have a stable namespace
                # identity.  Issuance and commit must bind the same canonical
                # absent path instead of diverging between ``path:...`` and an
                # empty physical identifier.
                physical = (
                    f"path:{os.path.normcase(os.path.abspath(os.fspath(candidate)))}"
                )
            if not captured_chain:
                raise ArtifactLedgerError(
                    f"artifact path denominator was not captured: {candidate}"
                )
            cached = (
                candidate,
                snapshot,
                error,
                physical,
                captured_chain[0],
            )
            self._snapshots[key] = cached
        snapshot = cached[1]
        return (dict(snapshot) if snapshot is not None else None, cached[2])

    def physical_identity(self, path: Path) -> str:
        self.snapshot(path)
        return self._snapshots[self._path_key(Path(path))][3]

    def path_for_identity(self, identity: str) -> Path:
        if self._closed:
            raise ArtifactLedgerError("artifact validation epoch is closed")
        key = str(identity)
        cached = self._identity_paths.get(key)
        if cached is None:
            root_name, _relative = key.split(":", 1)
            cached = _path_for_identity_with_chains(
                self.scratchpad,
                self.project_root,
                key,
                _known_base_chain=self._identity_root_chains.get(root_name),
            )
            self._identity_paths[key] = cached
            self._identity_root_chains.setdefault(root_name, cached[1])
        return cached[0]

    def physical_owner_identity(self, identity: str) -> str:
        """Join one owner identity without hashing unrelated artifact bytes."""

        if self._closed:
            raise ArtifactLedgerError("artifact validation epoch is closed")
        key = str(identity)
        cached = self._physical_owner_identities.get(key)
        if cached is None:
            path = self.path_for_identity(key)
            try:
                metadata = rooted_io.lstat(path)
            except FileNotFoundError:
                physical = (
                    f"path:{os.path.normcase(os.path.abspath(os.fspath(path)))}"
                )
                metadata_identity = None
            except OSError as exc:
                raise ArtifactLedgerError(
                    f"artifact physical identity unavailable: {path}"
                ) from exc
            else:
                if _metadata_is_reparse(metadata):
                    raise ArtifactLedgerError(
                        "artifact physical identity rejects symlink/reparse: "
                        f"{path}"
                    )
                inode = int(getattr(metadata, "st_ino", 0) or 0)
                device = int(getattr(metadata, "st_dev", 0) or 0)
                physical = (
                    f"file:{device}:{inode}"
                    if inode
                    else f"path:{os.path.normcase(os.path.abspath(os.fspath(path)))}"
                )
                metadata_identity = _metadata_identity(metadata)
            cached = (path, physical, metadata_identity)
            self._physical_owner_identities[key] = cached
        return cached[1]

    def physical_owner_link_count(self, identity: str) -> int:
        """Return the terminally witnessed native link count for one owner.

        ``physical_owner_identity`` stores the complete metadata identity and
        ``finish`` rechecks it, including ``st_nlink``.  A missing path returns
        zero; callers treat any other non-single-link value conservatively.
        """

        key = str(identity)
        self.physical_owner_identity(key)
        metadata_identity = self._physical_owner_identities[key][2]
        if metadata_identity is None:
            return 0
        return int(metadata_identity[5])

    def output_authority_journal(self) -> dict[str, Any]:
        """Parse the immutable journal once, bound to this terminal epoch."""

        if self._closed:
            raise ArtifactLedgerError("artifact validation epoch is closed")
        if self._output_authority_journal is None:
            journal, encoded = _read_output_authority_ledger_with_raw(
                self.scratchpad
            )
            path = self.scratchpad / _OUTPUT_AUTHORITY_LEDGER_NAME
            if encoded is not None:
                metadata = rooted_io.lstat(path)
                digest = hashlib.sha256(encoded).hexdigest()
                if (
                    _metadata_is_reparse(metadata)
                    or not stat.S_ISREG(metadata.st_mode)
                    or int(metadata.st_size) != len(encoded)
                ):
                    raise ArtifactLedgerError(
                        "output authority journal changed during validation read"
                    )
                self._immutable_control_paths[self._path_key(path)] = (
                    path,
                    digest,
                    len(encoded),
                    _metadata_identity(metadata),
                    "journal",
                )
            self._output_authority_journal = copy.deepcopy(journal)
        return copy.deepcopy(self._output_authority_journal)

    def output_authority_cas(self, authority_digest: str) -> dict[str, Any]:
        """Parse one exact CAS object once, bound to this terminal epoch."""

        if self._closed:
            raise ArtifactLedgerError("artifact validation epoch is closed")
        cached = self._output_authority_cas.get(authority_digest)
        if cached is None:
            value = _read_output_authority_cas_cached(
                self.scratchpad,
                authority_digest,
            )
            path = (
                self.scratchpad
                / _OUTPUT_AUTHORITY_CAS_DIRECTORY
                / f"{authority_digest}.json"
            )
            encoded = _canonical_json_bytes(value)
            metadata = rooted_io.lstat(path)
            if (
                _metadata_is_reparse(metadata)
                or not stat.S_ISREG(metadata.st_mode)
                or int(metadata.st_size) != len(encoded)
                or hashlib.sha256(encoded).hexdigest() != authority_digest
            ):
                raise ArtifactLedgerError(
                    "output authority CAS changed during validation read"
                )
            self._immutable_control_paths[self._path_key(path)] = (
                path,
                authority_digest,
                len(encoded),
                _metadata_identity(metadata),
                "cas",
            )
            cached = copy.deepcopy(value)
            self._output_authority_cas[authority_digest] = cached
        return copy.deepcopy(cached)

    def finish(self) -> list[str]:
        """Revalidate all observed paths and ledger immediately at return."""

        if self._closed:
            return ["artifact validation epoch was finalized more than once"]
        self._closed = True
        issues: list[str] = []
        terminal_paths = [
            row[0] for row in self._identity_paths.values()
        ] + [row[0] for row in self._snapshots.values()] + [
            self.scratchpad,
            self.project_root,
        ]
        try:
            terminal_before = _lexical_no_follow_chains(terminal_paths)
        except ArtifactLedgerError as exc:
            return [
                "artifact path denominator changed during validation epoch: "
                + str(exc)
            ]
        for identity in sorted(self._identity_paths):
            path, initial_base_chain, initial_candidate_chain = (
                self._identity_paths[identity]
            )
            root_name, _relative = identity.split(":", 1)
            base = (
                self.scratchpad
                if root_name == "scratchpad"
                else self.project_root
            )
            try:
                final_base_chain = terminal_before[self._path_key(base)]
                final_candidate_chain = terminal_before[self._path_key(path)]
            except KeyError:
                issues.append(
                    f"{identity}: artifact path denominator is incomplete"
                )
                continue
            if (
                final_base_chain != initial_base_chain
                or final_candidate_chain != initial_candidate_chain
            ):
                issues.append(
                    f"{identity}: artifact path changed during validation epoch"
                )
        for key in sorted(self._snapshots):
            (
                path,
                initial,
                initial_error,
                initial_physical,
                initial_chain,
            ) = self._snapshots[key]
            terminal_chain = terminal_before.get(key)
            if terminal_chain is None:
                issues.append(
                    f"{key}: artifact path denominator is incomplete"
                )
                continue
            final, final_error = _stable_artifact_snapshot(
                path,
                confirmation_reads=False,
                _known_chain=terminal_chain,
            )
            final_physical = ""
            if final is not None:
                try:
                    final_physical = _physical_file_identity(path)
                except (ArtifactLedgerError, OSError):
                    final_error = "SNAPSHOT_PHYSICAL_IDENTITY_UNAVAILABLE"
                    final = None
            elif not rooted_io.lexists(path):
                final_physical = (
                    f"path:{os.path.normcase(os.path.abspath(os.fspath(path)))}"
                )
            if (
                terminal_chain != initial_chain
                or final != initial
                or final_error != initial_error
                or final_physical != initial_physical
            ):
                issues.append(
                    f"{key}: artifact changed during validation epoch"
                )
        try:
            terminal_after = _lexical_no_follow_chains(terminal_paths)
        except ArtifactLedgerError as exc:
            issues.append(
                "artifact path denominator changed during validation epoch: "
                + str(exc)
            )
        else:
            for key, before_chain in terminal_before.items():
                if terminal_after.get(key) != before_chain:
                    issues.append(
                        f"{key}: artifact path changed during terminal rejoin"
                    )
        for identity in sorted(self._physical_owner_identities):
            path, _physical, initial_metadata = (
                self._physical_owner_identities[identity]
            )
            try:
                final_metadata = rooted_io.lstat(path)
            except FileNotFoundError:
                final_identity = None
            except OSError as exc:
                issues.append(
                    f"{identity}: artifact physical identity became unreadable: "
                    f"{exc}"
                )
                continue
            else:
                if _metadata_is_reparse(final_metadata):
                    issues.append(
                        f"{identity}: artifact physical identity became reparse"
                    )
                    continue
                final_identity = _metadata_identity(final_metadata)
            if final_identity != initial_metadata:
                issues.append(
                    f"{identity}: artifact physical identity changed during "
                    "validation epoch"
                )
        for key in sorted(self._immutable_control_paths):
            path, expected_digest, expected_size, initial_metadata, kind = (
                self._immutable_control_paths[key]
            )
            try:
                if kind == "journal":
                    # The initial projection was fully parsed and schema-
                    # validated.  At the terminal boundary exact stable bytes,
                    # digest, size, and physical metadata prove that same
                    # authority without rebuilding a second giant JSON string.
                    raw = _read_stable_regular_bytes(
                        path, limit=32 * 1024 * 1024
                    )
                else:
                    value = _read_output_authority_cas(
                        self.scratchpad, expected_digest
                    )
                    raw = _canonical_json_bytes(value)
                final_metadata = rooted_io.lstat(path)
            except (ArtifactLedgerError, OSError) as exc:
                issues.append(
                    f"{key}: immutable authority control changed during "
                    f"validation epoch: {exc}"
                )
                continue
            if (
                len(raw) != expected_size
                or hashlib.sha256(raw).hexdigest() != expected_digest
                or _metadata_identity(final_metadata) != initial_metadata
            ):
                issues.append(
                    f"{key}: immutable authority control changed during "
                    "validation epoch"
                )
        try:
            final_ledger = read_artifact_ledger(self.scratchpad)
        except ArtifactLedgerError as exc:
            issues.append(
                "artifact ledger changed during validation epoch: " + str(exc)
            )
        else:
            if (
                _canonical_json_digest(final_ledger) != self._ledger_digest
                or final_ledger != self.ledger
            ):
                issues.append("artifact ledger changed during validation epoch")
        return issues


def _read_stable_regular_bytes(
    path: Path,
    *,
    limit: int,
    allowed_link_counts: tuple[int, ...] = (1,),
) -> bytes:
    allowed_links = frozenset(int(value) for value in allowed_link_counts)
    if not allowed_links or any(value < 1 for value in allowed_links):
        raise ArtifactLedgerError(
            "authority file allowed-link denominator is invalid"
        )
    descriptor = -1
    try:
        before_chain = _lexical_no_follow_chain(path)
        before = rooted_io.lstat(path)
        if (
            _metadata_is_reparse(before)
            or not stat.S_ISREG(before.st_mode)
            or int(getattr(before, "st_nlink", 1) or 1)
            not in allowed_links
            or int(before.st_size) > limit
        ):
            raise ArtifactLedgerError(
                f"authority file is not a bounded no-follow regular file: {path}"
            )
        flags = os.O_RDONLY | int(getattr(os, "O_BINARY", 0) or 0)
        flags |= int(getattr(os, "O_NOFOLLOW", 0) or 0)
        descriptor = os.open(rooted_io.native_path(path), flags)
        opened = os.fstat(descriptor)
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, limit + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > limit:
                raise ArtifactLedgerError(f"authority file exceeds limit: {path}")
        after_fd = os.fstat(descriptor)
        after = rooted_io.lstat(path)
        after_chain = _lexical_no_follow_chain(path)
    except ArtifactLedgerError:
        raise
    except OSError as exc:
        raise ArtifactLedgerError(
            f"authority file cannot be read safely: {path}"
        ) from exc
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass
    if (
        before_chain != after_chain
        or _metadata_identity(before) != _metadata_identity(opened)
        or _metadata_identity(opened) != _metadata_identity(after_fd)
        or _metadata_identity(after_fd) != _metadata_identity(after)
        or any(
            int(getattr(row, "st_nlink", 1) or 1)
            not in allowed_links
            for row in (before, opened, after_fd, after)
        )
        or total != int(after.st_size)
    ):
        raise ArtifactLedgerError(
            f"authority file changed during descriptor read: {path}"
        )
    return b"".join(chunks)


def _windows_stream_primitives() -> tuple[Any, Any, Any, Any, Any] | None:
    if os.name != "nt":
        return None
    import ctypes
    from ctypes import wintypes

    class STREAM_DATA(ctypes.Structure):
        _fields_ = [
            ("size", ctypes.c_longlong),
            ("name", wintypes.WCHAR * 296),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    first = kernel32.FindFirstStreamW
    first.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.POINTER(STREAM_DATA),
        wintypes.DWORD,
    ]
    first.restype = wintypes.HANDLE
    following = kernel32.FindNextStreamW
    following.argtypes = [wintypes.HANDLE, ctypes.POINTER(STREAM_DATA)]
    following.restype = wintypes.BOOL
    close = kernel32.FindClose
    close.argtypes = [wintypes.HANDLE]
    close.restype = wintypes.BOOL
    return ctypes, STREAM_DATA, first, following, close


def _assert_default_stream_only(
    path: Path,
    primitives: tuple[Any, Any, Any, Any, Any] | None,
) -> None:
    if primitives is None:
        return
    ctypes, stream_type, first, following, close = primitives
    data = stream_type()
    # FindFirstStreamW is a Win32 path API and therefore needs the same
    # extended-length native spelling used by the descriptor/lstat helpers.
    # Passing pathlib's ordinary absolute spelling silently reintroduces the
    # MAX_PATH boundary for otherwise valid ledger roots.
    handle = first(rooted_io.native_path(path), 0, ctypes.byref(data), 0)
    if handle == ctypes.c_void_p(-1).value:
        raise ArtifactLedgerError(
            f"authority CAS stream namespace is unreadable: {path}"
        )
    names: list[str] = []
    try:
        names.append(str(data.name))
        while True:
            ctypes.set_last_error(0)
            if following(handle, ctypes.byref(data)):
                names.append(str(data.name))
                continue
            error = ctypes.get_last_error()
            if error == 38:
                break
            raise ArtifactLedgerError(
                f"authority CAS stream namespace is unreadable: {path}"
            )
    finally:
        close(handle)
    if names != ["::$DATA"]:
        raise ArtifactLedgerError(
            f"authority CAS child has an alternate data stream: {path}"
        )


def _read_stable_regular_bytes_in_bound_directory(
    path: Path,
    *,
    directory: Path,
    directory_identity: tuple[int, ...],
    expected_identity: tuple[int, ...],
    limit: int,
    allowed_link_counts: tuple[int, ...] = (1,),
    stream_primitives: tuple[Any, Any, Any, Any, Any] | None = None,
) -> bytes:
    """Stable-read a child beneath one already-bound exact directory."""

    candidate = Path(path)
    parent = Path(directory)
    if candidate.parent != parent:
        raise ArtifactLedgerError("authority CAS child escaped bound directory")
    allowed_links = frozenset(int(value) for value in allowed_link_counts)
    if not allowed_links or any(value < 1 for value in allowed_links):
        raise ArtifactLedgerError(
            "authority file allowed-link denominator is invalid"
        )
    descriptor = -1
    try:
        parent_before = rooted_io.lstat(parent)
        before = rooted_io.lstat(candidate)
        _assert_default_stream_only(candidate, stream_primitives)
        if (
            _metadata_object_identity(parent_before) != directory_identity
            or _metadata_is_reparse(parent_before)
            or not stat.S_ISDIR(parent_before.st_mode)
            or _metadata_identity(before) != expected_identity
            or _metadata_is_reparse(before)
            or not stat.S_ISREG(before.st_mode)
            or int(getattr(before, "st_nlink", 1) or 1) not in allowed_links
            or int(before.st_size) > limit
        ):
            raise ArtifactLedgerError(
                f"authority CAS child is not a bounded no-follow file: {candidate}"
            )
        flags = os.O_RDONLY | int(getattr(os, "O_BINARY", 0) or 0)
        flags |= int(getattr(os, "O_NOFOLLOW", 0) or 0)
        descriptor = os.open(rooted_io.native_path(candidate), flags)
        opened = os.fstat(descriptor)
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, limit + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > limit:
                raise ArtifactLedgerError(
                    f"authority CAS child exceeds limit: {candidate}"
                )
        after_fd = os.fstat(descriptor)
        after = rooted_io.lstat(candidate)
        _assert_default_stream_only(candidate, stream_primitives)
        parent_after = rooted_io.lstat(parent)
    except ArtifactLedgerError:
        raise
    except OSError as exc:
        raise ArtifactLedgerError(
            f"authority CAS child cannot be read safely: {candidate}"
        ) from exc
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass
    if (
        _metadata_object_identity(parent_after) != directory_identity
        or _metadata_identity(before) != _metadata_identity(opened)
        or _metadata_identity(opened) != _metadata_identity(after_fd)
        or _metadata_identity(after_fd) != _metadata_identity(after)
        or any(
            int(getattr(row, "st_nlink", 1) or 1) not in allowed_links
            for row in (before, opened, after_fd, after)
        )
        or total != int(after.st_size)
    ):
        raise ArtifactLedgerError(
            f"authority CAS child changed during stable read: {candidate}"
        )
    return b"".join(chunks)


def _program_facts_selection_digest(
    selection_record: Mapping[str, Any],
) -> str:
    return hashlib.sha256(_canonical_json_bytes(selection_record)).hexdigest()


def _validate_program_facts_selection_ledger_state(
    ledger: dict[str, Any],
) -> None:
    """Validate the closed Program Facts selection projection in-place."""

    unexpected = {
        key for key in ledger
        if (
            isinstance(key, str)
            and key.startswith(_PROGRAM_FACTS_SELECTION_PREFIX)
            and key not in _PROGRAM_FACTS_SELECTION_FIELDS
        )
    }
    if unexpected:
        raise ArtifactLedgerError(
            "artifact ledger contains an unknown Program Facts v2 field"
        )
    history_present = _PROGRAM_FACTS_SELECTION_HISTORY_FIELD in ledger
    active_present = _PROGRAM_FACTS_ACTIVE_SELECTION_FIELD in ledger
    if not history_present and not active_present:
        ledger[_PROGRAM_FACTS_SELECTION_HISTORY_FIELD] = {}
        ledger[_PROGRAM_FACTS_ACTIVE_SELECTION_FIELD] = {"state": "ABSENT"}
        return
    if history_present != active_present:
        raise ArtifactLedgerError(
            "artifact ledger Program Facts selection state is one-sided"
        )
    history = ledger[_PROGRAM_FACTS_SELECTION_HISTORY_FIELD]
    active = ledger[_PROGRAM_FACTS_ACTIVE_SELECTION_FIELD]
    if not isinstance(history, dict) or not isinstance(active, dict):
        raise ArtifactLedgerError(
            "artifact ledger Program Facts selection state must be objects"
        )

    try:
        from program_facts_publication import (
            parse_immutable_generation_selection_v1,
        )
        from program_facts_types import ProgramFactsTypeError

        for generation_id, row in history.items():
            if (
                not isinstance(generation_id, str)
                or _PROGRAM_FACTS_GENERATION_ID_RE.fullmatch(generation_id)
                is None
                or not isinstance(row, dict)
                or frozenset(row)
                != frozenset({"selection_digest", "selection_record"})
            ):
                raise ArtifactLedgerError(
                    "artifact ledger Program Facts selection history is malformed"
                )
            digest = row["selection_digest"]
            record = row["selection_record"]
            if (
                not isinstance(digest, str)
                or _PROGRAM_FACTS_SHA256_RE.fullmatch(digest) is None
                or not isinstance(record, dict)
            ):
                raise ArtifactLedgerError(
                    "artifact ledger Program Facts selection row is malformed"
                )
            parsed = parse_immutable_generation_selection_v1(record)
            if (
                parsed.generation_id != generation_id
                or _program_facts_selection_digest(record) != digest
            ):
                raise ArtifactLedgerError(
                    "artifact ledger Program Facts selection row diverges"
                )

        state = active.get("state")
        if state == "ABSENT":
            if frozenset(active) != frozenset({"state"}) or history:
                raise ArtifactLedgerError(
                    "artifact ledger ABSENT Program Facts selection diverges"
                )
            return
        if (
            state != "PRESENT"
            or frozenset(active)
            != frozenset({"state", "generation_id", "selection_digest"})
        ):
            raise ArtifactLedgerError(
                "artifact ledger ACTIVE Program Facts selection is malformed"
            )
        generation_id = active["generation_id"]
        digest = active["selection_digest"]
        if (
            not isinstance(generation_id, str)
            or _PROGRAM_FACTS_GENERATION_ID_RE.fullmatch(generation_id) is None
            or not isinstance(digest, str)
            or _PROGRAM_FACTS_SHA256_RE.fullmatch(digest) is None
            or generation_id not in history
            or history[generation_id]["selection_digest"] != digest
        ):
            raise ArtifactLedgerError(
                "artifact ledger ACTIVE Program Facts selection diverges"
            )
    except ArtifactLedgerError:
        raise
    except (ProgramFactsTypeError, TypeError, ValueError) as exc:
        raise ArtifactLedgerError(
            "artifact ledger Program Facts selection replay failed"
        ) from exc


def _program_facts_bound_root(
    supplied_path: Path,
    *,
    physical_relative_path: str,
    label: str,
) -> tuple[Path, Path]:
    if (
        not isinstance(supplied_path, Path)
        or not isinstance(physical_relative_path, str)
        or not physical_relative_path
    ):
        raise ArtifactLedgerError(f"{label} path binding is malformed")
    relative = PurePosixPath(physical_relative_path)
    parts = relative.parts
    if (
        relative.is_absolute()
        or not parts
        or relative.as_posix() != physical_relative_path
        or any(
            not component
            or component in {".", ".."}
            or "\\" in component
            or ":" in component
            or unicodedata.normalize("NFC", component) != component
            for component in parts
        )
    ):
        raise ArtifactLedgerError(f"{label} relative path is not canonical")
    path = Path(supplied_path)
    supplied_text = os.fspath(path)
    if (
        not path.is_absolute()
        or os.path.abspath(supplied_text) != supplied_text
    ):
        raise ArtifactLedgerError(f"{label} supplied path is not absolute")
    cursor = path
    for component in reversed(parts):
        if cursor.name != component:
            raise ArtifactLedgerError(
                f"{label} path does not equal its selection binding"
            )
        cursor = cursor.parent
    expected = cursor.joinpath(*parts)
    if os.fspath(expected) != supplied_text:
        raise ArtifactLedgerError(
            f"{label} path spelling diverges from its selection binding"
        )
    return cursor, path


def _program_facts_stable_evidence_read(
    path: Path,
    *,
    limit: int,
    expected_size: int,
    label: str,
) -> tuple[bytes, tuple[tuple[str, tuple[int, ...]], ...], tuple[int, ...]]:
    if (
        not isinstance(expected_size, int)
        or isinstance(expected_size, bool)
        or expected_size < 0
        or expected_size > limit
    ):
        raise ArtifactLedgerError(f"{label} selection size is out of bounds")
    try:
        before_chain = _lexical_no_follow_chain(path)
        before = rooted_io.lstat(path)
        if (
            _metadata_is_reparse(before)
            or not stat.S_ISREG(before.st_mode)
            or int(getattr(before, "st_nlink", 1) or 1) != 1
        ):
            raise ArtifactLedgerError(
                f"{label} is not a single-link no-follow regular file"
            )
        content = _read_stable_regular_bytes(path, limit=limit)
        after = rooted_io.lstat(path)
        after_chain = _lexical_no_follow_chain(path)
    except ArtifactLedgerError:
        raise
    except OSError as exc:
        raise ArtifactLedgerError(f"{label} cannot be reopened safely") from exc
    if (
        before_chain != after_chain
        or _metadata_identity(before) != _metadata_identity(after)
        or len(content) != expected_size
    ):
        raise ArtifactLedgerError(f"{label} changed during stable reopen")
    return content, after_chain, _metadata_identity(after)


def _program_facts_recheck_evidence_identity(
    path: Path,
    *,
    expected_chain: tuple[tuple[str, tuple[int, ...]], ...],
    expected_metadata: tuple[int, ...],
    label: str,
) -> None:
    try:
        observed = rooted_io.lstat(path)
        observed_chain = _lexical_no_follow_chain(path)
    except (ArtifactLedgerError, OSError) as exc:
        raise ArtifactLedgerError(
            f"{label} cannot be rechecked safely"
        ) from exc
    if (
        observed_chain != expected_chain
        or _metadata_identity(observed) != expected_metadata
        or _metadata_is_reparse(observed)
        or not stat.S_ISREG(observed.st_mode)
        or int(getattr(observed, "st_nlink", 1) or 1) != 1
    ):
        raise ArtifactLedgerError(
            f"{label} changed after evidence validation"
        )


def commit_immutable_generation_selection(
    *,
    selection_record: Mapping[str, Any],
    arm_path: Path,
    generation_manifest_path: Path,
    logical_output_paths: Mapping[str, Path],
) -> dict[str, Any]:
    """Commit one fully replayed immutable Program Facts generation selection."""

    try:
        from program_facts_publication import (
            PUBLIC_IDENTITIES,
            parse_immutable_generation_selection_v1,
            validate_generation_selection_evidence_v1,
        )
        from program_facts_types import (
            ProgramFactsTypeError,
            canonical_json_bytes,
            strict_json_loads,
        )

        if not isinstance(selection_record, Mapping):
            raise ArtifactLedgerError(
                "Program Facts generation selection must be an object"
            )
        selection_bytes = canonical_json_bytes(selection_record)
        selection = strict_json_loads(
            selection_bytes,
            require_canonical=True,
            max_bytes=_PROGRAM_FACTS_SELECTION_CONTROL_LIMIT,
        )
        if not isinstance(selection, dict):
            raise ArtifactLedgerError(
                "Program Facts generation selection must be an object"
            )
        parsed = parse_immutable_generation_selection_v1(selection)

        if not isinstance(logical_output_paths, Mapping):
            raise ArtifactLedgerError(
                "Program Facts logical output paths must be a mapping"
            )
        if tuple(logical_output_paths) != PUBLIC_IDENTITIES:
            raise ArtifactLedgerError(
                "Program Facts logical output path denominator diverges"
            )
        output_paths = {
            identity: logical_output_paths[identity]
            for identity in PUBLIC_IDENTITIES
        }

        roots_and_paths = [
            _program_facts_bound_root(
                arm_path,
                physical_relative_path=(
                    parsed.publication_transaction.arm_physical_path
                ),
                label="Program Facts publication arm",
            ),
            _program_facts_bound_root(
                generation_manifest_path,
                physical_relative_path=parsed.generation_manifest.physical_path,
                label="Program Facts generation manifest",
            ),
        ]
        for index, identity in enumerate(PUBLIC_IDENTITIES):
            roots_and_paths.append(
                _program_facts_bound_root(
                    output_paths[identity],
                    physical_relative_path=(
                        parsed.logical_outputs[index].physical_path
                    ),
                    label=f"Program Facts logical output {identity!r}",
                )
            )
        root_texts = tuple(os.fspath(row[0]) for row in roots_and_paths)
        if len(set(root_texts)) != 1:
            raise ArtifactLedgerError(
                "Program Facts evidence paths do not share one bound root"
            )
        scratchpad = roots_and_paths[0][0]
        paths = tuple(row[1] for row in roots_and_paths)
        if len({os.fspath(path) for path in paths}) != len(paths):
            raise ArtifactLedgerError(
                "Program Facts evidence paths are not distinct"
            )

        snapshots = [
            _program_facts_stable_evidence_read(
                paths[0],
                limit=_PROGRAM_FACTS_SELECTION_CONTROL_LIMIT,
                expected_size=(
                    parsed.publication_transaction.arm_file_size
                ),
                label="Program Facts publication arm",
            ),
            _program_facts_stable_evidence_read(
                paths[1],
                limit=_PROGRAM_FACTS_SELECTION_CONTROL_LIMIT,
                expected_size=parsed.generation_manifest.size,
                label="Program Facts generation manifest",
            ),
        ]
        for index, identity in enumerate(PUBLIC_IDENTITIES):
            snapshots.append(
                _program_facts_stable_evidence_read(
                    paths[index + 2],
                    limit=_PROGRAM_FACTS_SELECTION_OUTPUT_LIMIT,
                    expected_size=parsed.logical_outputs[index].size,
                    label=f"Program Facts logical output {identity!r}",
                )
            )
        object_identities = []
        for path, snapshot in zip(paths, snapshots):
            metadata = snapshot[2]
            inode = metadata[4]
            device = metadata[3]
            object_identities.append(
                ("file", device, inode)
                if inode
                else ("path", os.fspath(path))
            )
        if len(set(object_identities)) != len(object_identities):
            raise ArtifactLedgerError(
                "Program Facts evidence paths alias one physical object"
            )

        arm = strict_json_loads(
            snapshots[0][0],
            require_final_lf=True,
            require_canonical=True,
            max_bytes=_PROGRAM_FACTS_SELECTION_CONTROL_LIMIT,
        )
        manifest = strict_json_loads(
            snapshots[1][0],
            require_final_lf=True,
            require_canonical=True,
            max_bytes=_PROGRAM_FACTS_SELECTION_CONTROL_LIMIT,
        )
        if not isinstance(arm, dict) or not isinstance(manifest, dict):
            raise ArtifactLedgerError(
                "Program Facts control evidence must be objects"
            )
        output_bytes = {
            identity: snapshots[index + 2][0]
            for index, identity in enumerate(PUBLIC_IDENTITIES)
        }
        validated = validate_generation_selection_evidence_v1(
            arm=arm,
            generation_manifest=manifest,
            logical_outputs=output_bytes,
            selection_record=selection,
        )
        if validated != parsed:
            raise ArtifactLedgerError(
                "Program Facts selection evidence replay diverges"
            )

        labels = (
            "Program Facts publication arm",
            "Program Facts generation manifest",
            *tuple(
                f"Program Facts logical output {identity!r}"
                for identity in PUBLIC_IDENTITIES
            ),
        )
        for path, snapshot, label in zip(paths, snapshots, labels):
            _program_facts_recheck_evidence_identity(
                path,
                expected_chain=snapshot[1],
                expected_metadata=snapshot[2],
                label=label,
            )

        selection_digest = hashlib.sha256(selection_bytes).hexdigest()
        generation_id = parsed.generation_id
        stored_record = copy.deepcopy(selection)
        expected_prior = copy.deepcopy(dict(parsed.prior_active))
        if (
            expected_prior.get("state") == "PRESENT"
            and not rooted_io.lexists(scratchpad / LEDGER_NAME)
        ):
            preflight = read_artifact_ledger(scratchpad)
            if (
                preflight[_PROGRAM_FACTS_SELECTION_HISTORY_FIELD].get(
                    generation_id
                )
                is None
                and preflight[_PROGRAM_FACTS_ACTIVE_SELECTION_FIELD]
                != expected_prior
            ):
                raise ArtifactLedgerError(
                    "Program Facts prior ACTIVE selection CAS failed"
                )
        with _ledger_transaction_lock(scratchpad):
            ledger = read_artifact_ledger(scratchpad)
            history = ledger[_PROGRAM_FACTS_SELECTION_HISTORY_FIELD]
            active = ledger[_PROGRAM_FACTS_ACTIVE_SELECTION_FIELD]
            existing = history.get(generation_id)
            if existing is not None:
                if (
                    existing
                    != {
                        "selection_digest": selection_digest,
                        "selection_record": stored_record,
                    }
                    or active
                    != {
                        "state": "PRESENT",
                        "generation_id": generation_id,
                        "selection_digest": selection_digest,
                    }
                ):
                    raise ArtifactLedgerError(
                        "Program Facts same-generation selection diverges"
                    )
                result = {
                    "state": "ACTIVE",
                    "generation_id": generation_id,
                    "selection_digest": selection_digest,
                    "selection_record": copy.deepcopy(stored_record),
                    "idempotent_replay": True,
                }
                return copy.deepcopy(result)

            if active != expected_prior:
                raise ArtifactLedgerError(
                    "Program Facts prior ACTIVE selection CAS failed"
                )
            postimage = copy.deepcopy(ledger)
            post_history = postimage[
                _PROGRAM_FACTS_SELECTION_HISTORY_FIELD
            ]
            post_history[generation_id] = {
                "selection_digest": selection_digest,
                "selection_record": copy.deepcopy(stored_record),
            }
            postimage[_PROGRAM_FACTS_ACTIVE_SELECTION_FIELD] = {
                "state": "PRESENT",
                "generation_id": generation_id,
                "selection_digest": selection_digest,
            }
            write_artifact_ledger(scratchpad, postimage)
        result = {
            "state": "ACTIVE",
            "generation_id": generation_id,
            "selection_digest": selection_digest,
            "selection_record": copy.deepcopy(stored_record),
            "idempotent_replay": False,
        }
        return copy.deepcopy(result)
    except ArtifactLedgerError:
        raise
    except (ProgramFactsTypeError, OSError, TypeError, ValueError) as exc:
        raise ArtifactLedgerError(
            "Program Facts generation selection commit failed closed"
        ) from exc


def _output_authority_key(
    *, run_id: str, work_unit_key: str, attempt_ordinal: int,
) -> str:
    return hashlib.sha256(
        f"{run_id}\0{work_unit_key}\0{attempt_ordinal}".encode("utf-8")
    ).hexdigest()


def _validated_output_authority_envelope(
    raw: Mapping[str, Any],
    *,
    authority_key: str,
) -> tuple[tuple[str, str, int], dict[str, Any], dict[str, Any]]:
    """Validate one journal/CAS envelope without trusting either projection."""

    if not isinstance(raw, Mapping) or set(raw) != _OUTPUT_AUTHORITY_FIELDS:
        raise ArtifactLedgerError(
            "output authority attempt history row is malformed"
        )
    authority = dict(raw)
    attempt = authority.get("attempt_ordinal")
    run_id = str(authority.get("run_id") or "")
    work_unit_key = str(authority.get("work_unit_key") or "")
    unsigned = {
        name: value
        for name, value in authority.items()
        if name != "authority_digest"
    }
    digest = str(authority.get("authority_digest") or "")
    expected_outputs = authority.get("expected_output_records")
    expected_identities = (
        set(expected_outputs)
        if isinstance(expected_outputs, Mapping)
        else set()
    )
    nested_outputs_valid = bool(
        _nested_output_records_have_exact_sizes(expected_outputs)
        and _observed_output_records_are_exact(
            authority.get("observed_outputs"),
            expected_identities=expected_identities,
        )
    )
    reason_codes = authority.get("reason_codes")
    state = authority.get("state")
    provenance_valid = bool(
        authority.get("source") in _OUTPUT_AUTHORITY_SOURCES
        and authority.get("actor") in _OUTPUT_AUTHORITY_ACTORS
    )
    state_reason_pair_valid = bool(
        isinstance(reason_codes, list)
        and all(
            isinstance(code, str) and bool(code)
            for code in reason_codes
        )
        and len(reason_codes) == len(set(reason_codes))
        and reason_codes == sorted(reason_codes)
        and (
            (state == "ACTIVE" and not reason_codes)
            or (state == "INVALID" and bool(reason_codes))
        )
    )
    expected_key = (
        _output_authority_key(
            run_id=run_id,
            work_unit_key=work_unit_key,
            attempt_ordinal=attempt,
        )
        if isinstance(attempt, int)
        and not isinstance(attempt, bool)
        and attempt >= 1
        and run_id
        and work_unit_key
        else ""
    )
    if (
        authority.get("schema") != _OUTPUT_AUTHORITY_SCHEMA
        or not provenance_valid
        or not state_reason_pair_valid
        or not expected_key
        or authority_key != expected_key
        or authority.get("authority_key") != expected_key
        or authority.get("physical_policy") != _NO_FOLLOW_PHYSICAL_POLICY
        or not _is_nonnegative_exact_int(
            authority.get("quarantine_recovery_history_count")
        )
        or (
            bool(authority.get("quarantine_recovery_history_count"))
            != _is_digest(
                authority.get(
                    "quarantine_recovery_history_head_digest"
                )
            )
        )
        or not nested_outputs_valid
        or not _is_digest(digest)
        or digest != _canonical_json_digest(unsigned)
    ):
        raise ArtifactLedgerError(
            "output authority logical attempt history row is invalid"
        )
    return (run_id, work_unit_key, int(attempt)), authority, unsigned


def _read_authority_ledger(
    scratchpad: Path,
    *,
    file_name: str,
    schema: str,
    label: str,
) -> dict[str, Any]:
    path = Path(scratchpad) / file_name
    if not rooted_io.lexists(path):
        return {
            "schema": schema,
            "authorities": {},
        }
    raw = _read_stable_regular_bytes(path, limit=32 * 1024 * 1024)
    return _parse_authority_ledger_bytes(
        raw,
        schema=schema,
        label=label,
    )


def _parse_authority_ledger_bytes(
    raw: bytes,
    *,
    schema: str,
    label: str,
) -> dict[str, Any]:
    """Validate one already-stable authority-ledger byte projection."""

    try:
        def _pairs(rows: list[tuple[str, Any]]) -> dict[str, Any]:
            result: dict[str, Any] = {}
            for key, value in rows:
                if key in result:
                    raise ArtifactLedgerError(
                        f"{label} ledger contains duplicate key {key!r}"
                    )
                result[key] = value
            return result

        payload = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_pairs,
            parse_constant=lambda token: (_ for _ in ()).throw(
                ArtifactLedgerError(
                    f"{label} ledger contains non-finite value {token}"
                )
            ),
        )
    except (
        ArtifactLedgerError,
        UnicodeError,
        ValueError,
        json.JSONDecodeError,
    ) as exc:
        raise ArtifactLedgerError(
            f"{label} ledger is unreadable: {type(exc).__name__}: {exc}"
        ) from exc
    if (
        not isinstance(payload, dict)
        or set(payload) != {"schema", "authorities"}
        or payload.get("schema") != schema
        or not isinstance(payload.get("authorities"), dict)
    ):
        raise ArtifactLedgerError(f"{label} ledger schema is malformed")
    return payload


def _write_authority_ledger(
    scratchpad: Path,
    payload: Mapping[str, Any],
    *,
    file_name: str,
    schema: str,
    label: str,
) -> None:
    root = Path(os.path.abspath(os.fspath(scratchpad)))
    _lexical_no_follow_chain(root)
    if (
        not isinstance(payload, Mapping)
        or set(payload) != {"schema", "authorities"}
        or payload.get("schema") != schema
        or not isinstance(payload.get("authorities"), Mapping)
    ):
        raise ArtifactLedgerError(f"{label} ledger payload is malformed")
    path = root / file_name
    if rooted_io.lexists(path):
        _lexical_no_follow_chain(path)
        metadata = rooted_io.lstat(path)
        if (
            _metadata_is_reparse(metadata)
            or not stat.S_ISREG(metadata.st_mode)
            or int(getattr(metadata, "st_nlink", 1) or 1) != 1
        ):
            raise ArtifactLedgerError(
                f"{label} ledger path is not a no-follow regular file"
            )
    encoded = json.dumps(
        dict(payload), indent=2, sort_keys=True, ensure_ascii=True
    ) + "\n"
    _write_rooted_control_bytes(path, encoded.encode("utf-8"))
    _lexical_no_follow_chain(path)
    metadata = rooted_io.lstat(path)
    if (
        _metadata_is_reparse(metadata)
        or not stat.S_ISREG(metadata.st_mode)
        or int(getattr(metadata, "st_nlink", 1) or 1) != 1
    ):
        raise ArtifactLedgerError(
            f"{label} ledger publication is unsafe"
        )


def _read_output_authority_ledger(scratchpad: Path) -> dict[str, Any]:
    return _read_authority_ledger(
        scratchpad,
        file_name=_OUTPUT_AUTHORITY_LEDGER_NAME,
        schema=_OUTPUT_AUTHORITY_LEDGER_SCHEMA,
        label="output authority",
    )


def _read_output_authority_ledger_with_raw(
    scratchpad: Path,
) -> tuple[dict[str, Any], bytes | None]:
    """Read the journal once and retain its exact authenticated byte image."""

    path = Path(scratchpad) / _OUTPUT_AUTHORITY_LEDGER_NAME
    if not rooted_io.lexists(path):
        return (
            {
                "schema": _OUTPUT_AUTHORITY_LEDGER_SCHEMA,
                "authorities": {},
            },
            None,
        )
    raw = _read_stable_regular_bytes(path, limit=32 * 1024 * 1024)
    return (
        _parse_authority_ledger_bytes(
            raw,
            schema=_OUTPUT_AUTHORITY_LEDGER_SCHEMA,
            label="output authority",
        ),
        raw,
    )


def _write_output_authority_ledger(
    scratchpad: Path, payload: Mapping[str, Any],
) -> None:
    _write_authority_ledger(
        scratchpad,
        payload,
        file_name=_OUTPUT_AUTHORITY_LEDGER_NAME,
        schema=_OUTPUT_AUTHORITY_LEDGER_SCHEMA,
        label="output authority",
    )


def _read_driver_successor_authority_ledger(
    scratchpad: Path,
) -> dict[str, Any]:
    return _read_authority_ledger(
        scratchpad,
        file_name=_DRIVER_SUCCESSOR_AUTHORITY_LEDGER_NAME,
        schema=_DRIVER_SUCCESSOR_AUTHORITY_LEDGER_SCHEMA,
        label="driver successor authority",
    )


def _write_driver_successor_authority_ledger(
    scratchpad: Path, payload: Mapping[str, Any],
) -> None:
    _write_authority_ledger(
        scratchpad,
        payload,
        file_name=_DRIVER_SUCCESSOR_AUTHORITY_LEDGER_NAME,
        schema=_DRIVER_SUCCESSOR_AUTHORITY_LEDGER_SCHEMA,
        label="driver successor authority",
    )


def _write_once_authority_cas(
    scratchpad: Path,
    *,
    directory_name: str,
    authority_digest: str,
    unsigned_authority: Mapping[str, Any],
    label: str,
) -> None:
    if not _is_digest(authority_digest):
        raise ArtifactLedgerError(f"{label} CAS digest is malformed")
    root = Path(os.path.abspath(os.fspath(scratchpad)))
    directory = root / directory_name
    try:
        rooted_io.ensure_directory(
            directory,
            parents=False,
            label=f"{label} CAS directory",
        )
    except rooted_io.RootedPathIOError as exc:
        raise ArtifactLedgerError(
            f"{label} CAS directory is not a safe directory"
        ) from exc
    _lexical_no_follow_chain(directory)
    directory_metadata = rooted_io.lstat(directory)
    if (
        _metadata_is_reparse(directory_metadata)
        or not stat.S_ISDIR(directory_metadata.st_mode)
    ):
        raise ArtifactLedgerError(
            f"{label} CAS directory is not a no-follow directory"
        )
    raw = _canonical_json_bytes(unsigned_authority)
    if hashlib.sha256(raw).hexdigest() != authority_digest:
        raise ArtifactLedgerError(f"{label} CAS content digest changed")
    path = directory / f"{authority_digest}.json"
    temporary = directory / f".{authority_digest}.publishing.tmp"
    if rooted_io.lexists(path):
        metadata = rooted_io.lstat(path)
        link_count = int(getattr(metadata, "st_nlink", 1) or 1)
        existing = _read_stable_regular_bytes(
            path,
            limit=16 * 1024 * 1024,
            allowed_link_counts=(link_count,),
        )
        if (
            link_count == 2
            and rooted_io.lexists(temporary)
        ):
            staging = rooted_io.lstat(temporary)
            if (
                _metadata_is_reparse(staging)
                or not stat.S_ISREG(staging.st_mode)
                or _metadata_object_identity(metadata)
                != _metadata_object_identity(staging)
                or _read_stable_regular_bytes(
                    temporary,
                    limit=16 * 1024 * 1024,
                    allowed_link_counts=(2,),
                )
                != raw
            ):
                raise ArtifactLedgerError(
                    f"{label} CAS interrupted publication peer differs"
                )
            rooted_io.durable_publish_new(temporary, path)
            metadata = rooted_io.lstat(path)
            link_count = int(
                getattr(metadata, "st_nlink", 1) or 1
            )
        if (
            link_count != 1
            or hashlib.sha256(existing).hexdigest() != authority_digest
            or existing != raw
        ):
            raise ArtifactLedgerError(
                f"{label} CAS replay differs or is multiply linked"
            )
        return
    if rooted_io.lexists(temporary):
        staging = rooted_io.lstat(temporary)
        if (
            _metadata_is_reparse(staging)
            or not stat.S_ISREG(staging.st_mode)
            or int(getattr(staging, "st_nlink", 1) or 1) != 1
        ):
            raise ArtifactLedgerError(
                f"{label} CAS staging object is unsafe"
            )
        try:
            staging_raw = _read_stable_regular_bytes(
                temporary, limit=16 * 1024 * 1024
            )
        except ArtifactLedgerError:
            staging_raw = b""
        if staging_raw != raw:
            rooted_io.unlink(temporary)
    if not rooted_io.lexists(temporary):
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        flags |= int(getattr(os, "O_BINARY", 0) or 0)
        flags |= int(getattr(os, "O_NOFOLLOW", 0) or 0)
        descriptor = os.open(
            rooted_io.native_path(temporary),
            flags,
            0o600,
        )
        try:
            with os.fdopen(descriptor, "wb") as stream:
                descriptor = -1
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
        finally:
            if descriptor >= 0:
                os.close(descriptor)
    try:
        _lexical_no_follow_chain(temporary)
        try:
            rooted_io.durable_publish_new(temporary, path)
        except FileExistsError:
            existing = _read_stable_regular_bytes(
                path, limit=16 * 1024 * 1024
            )
            if existing != raw:
                raise ArtifactLedgerError(
                    f"{label} CAS concurrent replay changed"
                )
    finally:
        if rooted_io.lexists(temporary):
            rooted_io.unlink(temporary)
    descriptor = -1
    try:
        # Windows FlushFileBuffers (exposed by os.fsync) rejects a read-only
        # CRT descriptor.  Open the already-published CAS leaf read/write
        # without modifying it, then flush its data/metadata before the
        # directory commit point.
        flags = os.O_RDWR | int(getattr(os, "O_BINARY", 0) or 0)
        flags |= int(getattr(os, "O_NOFOLLOW", 0) or 0)
        descriptor = os.open(rooted_io.native_path(path), flags)
        opened = os.fstat(descriptor)
        if (
            _metadata_is_reparse(opened)
            or not stat.S_ISREG(opened.st_mode)
            or int(getattr(opened, "st_nlink", 1) or 1) != 1
        ):
            raise ArtifactLedgerError(
                f"{label} CAS publication handle is unsafe"
            )
        os.fsync(descriptor)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    _fsync_directory(directory)
    _lexical_no_follow_chain(path)
    metadata = rooted_io.lstat(path)
    if (
        _metadata_is_reparse(metadata)
        or not stat.S_ISREG(metadata.st_mode)
        or int(getattr(metadata, "st_nlink", 1) or 1) != 1
        or _read_stable_regular_bytes(
            path, limit=16 * 1024 * 1024
        )
        != raw
    ):
        raise ArtifactLedgerError(
            f"{label} CAS publication is not exact and single-link"
        )


def _read_authority_cas(
    scratchpad: Path,
    authority_digest: str,
    *,
    directory_name: str,
    label: str,
) -> dict[str, Any]:
    if not _is_digest(authority_digest):
        raise ArtifactLedgerError(f"{label} CAS digest is malformed")
    path = (
        Path(os.path.abspath(os.fspath(scratchpad)))
        / directory_name
        / f"{authority_digest}.json"
    )
    try:
        metadata = rooted_io.lstat(path)
    except OSError as exc:
        raise ArtifactLedgerError(
            f"{label} CAS object is absent"
        ) from exc
    if (
        _metadata_is_reparse(metadata)
        or not stat.S_ISREG(metadata.st_mode)
        or int(getattr(metadata, "st_nlink", 1) or 1) != 1
    ):
        raise ArtifactLedgerError(
            f"{label} CAS object is unsafe or multiply linked"
        )
    raw = _read_stable_regular_bytes(path, limit=16 * 1024 * 1024)
    if hashlib.sha256(raw).hexdigest() != authority_digest:
        raise ArtifactLedgerError(
            f"{label} CAS filename/content digest mismatch"
        )
    try:
        value = json.loads(raw.decode("utf-8", errors="strict"))
    except (UnicodeError, ValueError, json.JSONDecodeError) as exc:
        raise ArtifactLedgerError(
            f"{label} CAS object is unreadable"
        ) from exc
    if (
        not isinstance(value, dict)
        or _canonical_json_bytes(value) != raw
    ):
        raise ArtifactLedgerError(
            f"{label} CAS object is not canonical"
        )
    return value


def _write_once_output_authority_cas(
    scratchpad: Path,
    *,
    authority_digest: str,
    unsigned_authority: Mapping[str, Any],
) -> None:
    _write_once_authority_cas(
        scratchpad,
        directory_name=_OUTPUT_AUTHORITY_CAS_DIRECTORY,
        authority_digest=authority_digest,
        unsigned_authority=unsigned_authority,
        label="output authority",
    )


def _read_output_authority_cas(
    scratchpad: Path, authority_digest: str,
) -> dict[str, Any]:
    return _read_authority_cas(
        scratchpad,
        authority_digest,
        directory_name=_OUTPUT_AUTHORITY_CAS_DIRECTORY,
        label="output authority",
    )


def _read_output_authority_cas_cached(
    scratchpad: Path, authority_digest: str,
) -> dict[str, Any]:
    """Read one CAS object without borrowing a prior content projection.

    File metadata is not a content authority: an in-place, same-size rewrite
    can preserve the inode and restore the timestamp.  The validation context
    already deduplicates reads inside one terminally-rejoined epoch; calls that
    begin a new epoch must authenticate the current bytes again.
    """

    return _read_output_authority_cas(
        Path(os.path.abspath(os.fspath(scratchpad))),
        str(authority_digest or ""),
    )


def _validated_output_authority_cas_bytes(
    raw: bytes,
    *,
    authority_digest: str,
) -> tuple[tuple[str, str, int], dict[str, Any], dict[str, Any]]:
    """Decode one exact CAS payload without relying on its current name."""

    if (
        not _is_digest(authority_digest)
        or hashlib.sha256(raw).hexdigest() != authority_digest
    ):
        raise ArtifactLedgerError(
            "output authority CAS filename/content digest mismatch"
        )

    def _pairs(rows: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in rows:
            if key in result:
                raise ArtifactLedgerError(
                    "output authority CAS contains duplicate JSON key"
                )
            result[key] = value
        return result

    try:
        value = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_pairs,
            parse_constant=lambda token: (_ for _ in ()).throw(
                ArtifactLedgerError(
                    "output authority CAS contains non-finite value "
                    f"{token}"
                )
            ),
        )
        canonical = (
            _canonical_json_bytes(value)
            if isinstance(value, Mapping)
            else b""
        )
    except (
        ArtifactLedgerError,
        UnicodeError,
        TypeError,
        ValueError,
        json.JSONDecodeError,
    ) as exc:
        raise ArtifactLedgerError(
            "output authority CAS object is unreadable"
        ) from exc
    if not isinstance(value, dict) or canonical != raw:
        raise ArtifactLedgerError(
            "output authority CAS object is not canonical"
        )
    authority_key = str(value.get("authority_key") or "")
    return _validated_output_authority_envelope(
        {**value, "authority_digest": authority_digest},
        authority_key=authority_key,
    )


def _inspect_output_authority_cas_projection(
    root: Path,
) -> tuple[
    dict[tuple[str, str, int], tuple[dict[str, Any], dict[str, Any]]],
    dict[tuple[str, str, int], tuple[dict[str, Any], dict[str, Any]]],
    set[tuple[str, str, int]],
]:
    """Read final CAS objects and exact interrupted staging prefixes."""

    cas_by_logical: dict[
        tuple[str, str, int], tuple[dict[str, Any], dict[str, Any]]
    ] = {}
    staged_by_logical: dict[
        tuple[str, str, int], tuple[dict[str, Any], dict[str, Any]]
    ] = {}
    linked_staging: set[tuple[str, str, int]] = set()
    cas_directory = root / _OUTPUT_AUTHORITY_CAS_DIRECTORY
    if not rooted_io.lexists(cas_directory):
        return cas_by_logical, staged_by_logical, linked_staging
    initial_directory_chain = _lexical_no_follow_chain(cas_directory)
    metadata = rooted_io.lstat(cas_directory)
    if (
        _metadata_is_reparse(metadata)
        or not stat.S_ISDIR(metadata.st_mode)
    ):
        raise ArtifactLedgerError(
            "output authority CAS directory is unsafe"
        )
    with rooted_io.scandir(cas_directory) as entries:
        roster = {
            entry.name: _metadata_identity(
                rooted_io.lstat(cas_directory / entry.name)
            )
            for entry in entries
        }
    names = sorted(roster)
    directory_identity = _metadata_object_identity(metadata)
    stream_primitives = _windows_stream_primitives()
    final_digests: set[str] = set()
    staging_digests: set[str] = set()
    for name in names:
        final_match = re.fullmatch(r"([0-9a-f]{64})\.json", name)
        staging_match = re.fullmatch(
            r"\.([0-9a-f]{64})\.publishing\.tmp", name
        )
        if final_match is not None:
            final_digests.add(final_match.group(1))
        elif staging_match is not None:
            staging_digests.add(staging_match.group(1))
        else:
            raise ArtifactLedgerError(
                "output authority CAS directory has unexpected entry"
            )

    for digest in sorted(final_digests):
        path = cas_directory / f"{digest}.json"
        temporary = cas_directory / f".{digest}.publishing.tmp"
        if digest in staging_digests:
            final_metadata = rooted_io.lstat(path)
            staging_metadata = rooted_io.lstat(temporary)
            if (
                _metadata_is_reparse(final_metadata)
                or not stat.S_ISREG(final_metadata.st_mode)
                or int(getattr(final_metadata, "st_nlink", 1) or 1) != 2
                or _metadata_is_reparse(staging_metadata)
                or not stat.S_ISREG(staging_metadata.st_mode)
                or int(getattr(staging_metadata, "st_nlink", 1) or 1) != 2
                or _metadata_object_identity(final_metadata)
                != _metadata_object_identity(staging_metadata)
            ):
                raise ArtifactLedgerError(
                    "output authority CAS interrupted publication differs"
                )
            raw = _read_stable_regular_bytes_in_bound_directory(
                path,
                directory=cas_directory,
                directory_identity=directory_identity,
                expected_identity=roster[path.name],
                limit=16 * 1024 * 1024,
                allowed_link_counts=(2,),
                stream_primitives=stream_primitives,
            )
            if raw != _read_stable_regular_bytes_in_bound_directory(
                temporary,
                directory=cas_directory,
                directory_identity=directory_identity,
                expected_identity=roster[temporary.name],
                limit=16 * 1024 * 1024,
                allowed_link_counts=(2,),
                stream_primitives=stream_primitives,
            ):
                raise ArtifactLedgerError(
                    "output authority CAS interrupted publication differs"
                )
        else:
            raw = _read_stable_regular_bytes_in_bound_directory(
                path,
                directory=cas_directory,
                directory_identity=directory_identity,
                expected_identity=roster[path.name],
                limit=16 * 1024 * 1024,
                stream_primitives=stream_primitives,
            )
        logical, authority, unsigned = (
            _validated_output_authority_cas_bytes(
                raw, authority_digest=digest
            )
        )
        if logical in cas_by_logical:
            raise ArtifactLedgerError(
                "output authority CAS has duplicate logical attempt"
            )
        cas_by_logical[logical] = (authority, unsigned)
        if digest in staging_digests:
            linked_staging.add(logical)

    for digest in sorted(staging_digests - final_digests):
        temporary = cas_directory / f".{digest}.publishing.tmp"
        raw = _read_stable_regular_bytes_in_bound_directory(
            temporary,
            directory=cas_directory,
            directory_identity=directory_identity,
            expected_identity=roster[temporary.name],
            limit=16 * 1024 * 1024,
            stream_primitives=stream_primitives,
        )
        logical, authority, unsigned = (
            _validated_output_authority_cas_bytes(
                raw, authority_digest=digest
            )
        )
        if logical in staged_by_logical:
            raise ArtifactLedgerError(
                "output authority CAS staging has duplicate logical attempt"
            )
        staged_by_logical[logical] = (authority, unsigned)
    terminal_directory_chain = _lexical_no_follow_chain(cas_directory)
    terminal_metadata = rooted_io.lstat(cas_directory)
    with rooted_io.scandir(cas_directory) as entries:
        terminal_roster = {
            entry.name: _metadata_identity(
                rooted_io.lstat(cas_directory / entry.name)
            )
            for entry in entries
        }
    if (
        terminal_directory_chain != initial_directory_chain
        or _metadata_object_identity(terminal_metadata) != directory_identity
        or terminal_roster != roster
    ):
        raise ArtifactLedgerError(
            "output authority CAS directory changed during projection"
        )
    return cas_by_logical, staged_by_logical, linked_staging


def _plan_output_authority_reconciliation(
    root: Path,
) -> tuple[
    dict[str, Any],
    list[tuple[dict[str, Any], dict[str, Any]]],
    list[dict[str, Any]],
    list[tuple[dict[str, Any], dict[str, Any]]],
    list[tuple[dict[str, Any], dict[str, Any]]],
]:
    """Phase A: validate the complete union and return a mutation-free plan."""

    journal = _read_output_authority_ledger(root)
    journal_by_logical: dict[
        tuple[str, str, int], tuple[dict[str, Any], dict[str, Any]]
    ] = {}
    for key, raw in journal["authorities"].items():
        if not isinstance(raw, Mapping):
            raise ArtifactLedgerError(
                "output authority journal row is malformed"
            )
        logical, authority, unsigned = (
            _validated_output_authority_envelope(
                raw, authority_key=str(key)
            )
        )
        if logical in journal_by_logical:
            raise ArtifactLedgerError(
                "output authority journal has duplicate logical attempt"
            )
        journal_by_logical[logical] = (authority, unsigned)

    cas_by_logical, staged_by_logical, linked_staging = (
        _inspect_output_authority_cas_projection(root)
    )
    for logical, staged_row in staged_by_logical.items():
        cas_row = cas_by_logical.get(logical)
        journal_row = journal_by_logical.get(logical)
        if cas_row is not None and cas_row[0] != staged_row[0]:
            raise ArtifactLedgerError(
                "output authority CAS staging conflicts with committed CAS"
            )
        if journal_row is not None and journal_row[0] != staged_row[0]:
            raise ArtifactLedgerError(
                "output authority CAS staging conflicts with journal"
            )
        if cas_row is not None:
            raise ArtifactLedgerError(
                "output authority CAS staging aliases another final object"
            )

    union_by_logical = dict(cas_by_logical)
    for logical, journal_row in journal_by_logical.items():
        cas_row = cas_by_logical.get(logical)
        if cas_row is not None and cas_row[0] != journal_row[0]:
            raise ArtifactLedgerError(
                "output authority CAS/journal logical attempt disagrees"
            )
        union_by_logical[logical] = journal_row

    logical_by_key: dict[str, tuple[str, str, int]] = {}
    logical_by_digest: dict[str, tuple[str, str, int]] = {}
    ordinals_by_scope: dict[tuple[str, str], set[int]] = {}
    for logical, (authority, _unsigned) in union_by_logical.items():
        key = str(authority["authority_key"])
        digest = str(authority["authority_digest"])
        if key in logical_by_key and logical_by_key[key] != logical:
            raise ArtifactLedgerError(
                "output authority history aliases one key across attempts"
            )
        if (
            digest in logical_by_digest
            and logical_by_digest[digest] != logical
        ):
            raise ArtifactLedgerError(
                "output authority history aliases one digest across attempts"
            )
        logical_by_key[key] = logical
        logical_by_digest[digest] = logical
        ordinals_by_scope.setdefault(logical[:2], set()).add(logical[2])
    if any(
        ordinals != set(range(1, max(ordinals) + 1))
        for ordinals in ordinals_by_scope.values()
    ):
        raise ArtifactLedgerError(
            "output authority attempt history is noncontiguous"
        )

    cas_repairs = [
        journal_by_logical[logical]
        for logical in sorted(set(journal_by_logical) - set(cas_by_logical))
    ]
    journal_repairs = [
        cas_by_logical[logical][0]
        for logical in sorted(set(cas_by_logical) - set(journal_by_logical))
    ]
    linked_repairs = [
        cas_by_logical[logical]
        for logical in sorted(linked_staging)
    ]
    orphan_staging = [
        staged_by_logical[logical]
        for logical in sorted(
            set(staged_by_logical) - set(journal_by_logical)
        )
    ]
    return (
        journal,
        cas_repairs,
        journal_repairs,
        linked_repairs,
        orphan_staging,
    )


def _discard_output_authority_cas_staging(
    root: Path,
    *,
    authority: Mapping[str, Any],
    unsigned: Mapping[str, Any],
) -> None:
    """Retire one validated but unpublished CAS staging object exactly."""

    digest = str(authority.get("authority_digest") or "")
    temporary = (
        root
        / _OUTPUT_AUTHORITY_CAS_DIRECTORY
        / f".{digest}.publishing.tmp"
    )
    raw = _read_stable_regular_bytes(
        temporary, limit=16 * 1024 * 1024
    )
    if raw != _canonical_json_bytes(unsigned):
        raise ArtifactLedgerError(
            "output authority CAS staging changed before retirement"
        )
    rooted_io.unlink(temporary)
    _fsync_directory(temporary.parent)
    if rooted_io.lexists(temporary):
        raise ArtifactLedgerError(
            "output authority CAS staging retirement failed"
        )


def _reconcile_output_authority_history(
    scratchpad: Path,
) -> dict[str, Any]:
    """Validate both projections before repairing any exact missing peer."""

    root = Path(os.path.abspath(os.fspath(scratchpad)))
    with _ledger_transaction_lock(root):
        (
            journal,
            cas_repairs,
            journal_repairs,
            linked_repairs,
            orphan_staging,
        ) = _plan_output_authority_reconciliation(root)

        # Phase B preserves the validated logical union.  Each CAS operation
        # either publishes the exact missing peer or retires an exact linked
        # prefix; interruption before or after the operation is idempotent.
        for authority, unsigned in cas_repairs + linked_repairs:
            digest = str(authority["authority_digest"])
            _write_once_output_authority_cas(
                root,
                authority_digest=digest,
                unsigned_authority=unsigned,
            )
            if _read_output_authority_cas(root, digest) != unsigned:
                raise ArtifactLedgerError(
                    "output authority CAS repair did not replay exactly"
                )
        for authority, unsigned in orphan_staging:
            _discard_output_authority_cas_staging(
                root,
                authority=authority,
                unsigned=unsigned,
            )

        # Publish journal peers one at a time.  Atomic replacement means a
        # crash exposes either the prior valid union or the next valid union.
        for authority in journal_repairs:
            key = str(authority["authority_key"])
            prior = journal["authorities"].get(key)
            if prior is not None and prior != authority:
                raise ArtifactLedgerError(
                    "output authority CAS/journal key disagrees"
                )
            next_journal = {
                "schema": journal["schema"],
                "authorities": dict(journal["authorities"]),
            }
            next_journal["authorities"][key] = authority
            _write_output_authority_ledger(root, next_journal)
            observed = _read_output_authority_ledger(root)
            if observed != next_journal:
                raise ArtifactLedgerError(
                    "output authority journal repair did not replay exactly"
                )
            journal = observed

        final = _plan_output_authority_reconciliation(root)
        if any(final[index] for index in range(1, 5)):
            raise ArtifactLedgerError(
                "output authority reconciliation did not converge"
            )
        return final[0]


def _read_driver_successor_progress(
    scratchpad: Path,
) -> dict[str, Any]:
    path = Path(scratchpad) / _DRIVER_SUCCESSOR_PROGRESS_NAME
    if not rooted_io.lexists(path):
        return {
            "schema": _DRIVER_SUCCESSOR_PROGRESS_SCHEMA,
            "transactions": {},
        }
    try:
        def _pairs(rows: list[tuple[str, Any]]) -> dict[str, Any]:
            result: dict[str, Any] = {}
            for key, value in rows:
                if key in result:
                    raise ArtifactLedgerError(
                        "driver successor progress contains duplicate "
                        f"key {key!r}"
                    )
                result[key] = value
            return result

        payload = json.loads(
            _read_stable_regular_bytes(
                path, limit=32 * 1024 * 1024
            ).decode("utf-8", errors="strict")
            ,
            object_pairs_hook=_pairs,
            parse_constant=lambda token: (_ for _ in ()).throw(
                ArtifactLedgerError(
                    "driver successor progress contains non-finite "
                    f"value {token}"
                )
            ),
        )
    except (
        ArtifactLedgerError,
        UnicodeError,
        ValueError,
        json.JSONDecodeError,
    ) as exc:
        raise ArtifactLedgerError(
            "driver successor progress is unreadable: "
            f"{type(exc).__name__}: {exc}"
        ) from exc
    if (
        not isinstance(payload, dict)
        or set(payload) != {"schema", "transactions"}
        or payload.get("schema") != _DRIVER_SUCCESSOR_PROGRESS_SCHEMA
        or not isinstance(payload.get("transactions"), dict)
    ):
        raise ArtifactLedgerError(
            "driver successor progress schema is malformed"
        )
    return payload


def _write_driver_successor_progress(
    scratchpad: Path, payload: Mapping[str, Any],
) -> None:
    if (
        not isinstance(payload, Mapping)
        or set(payload) != {"schema", "transactions"}
        or payload.get("schema") != _DRIVER_SUCCESSOR_PROGRESS_SCHEMA
        or not isinstance(payload.get("transactions"), Mapping)
    ):
        raise ArtifactLedgerError(
            "driver successor progress payload is malformed"
        )
    root = Path(os.path.abspath(os.fspath(scratchpad)))
    _lexical_no_follow_chain(root)
    path = root / _DRIVER_SUCCESSOR_PROGRESS_NAME
    if rooted_io.lexists(path):
        _lexical_no_follow_chain(path)
        metadata = rooted_io.lstat(path)
        if (
            _metadata_is_reparse(metadata)
            or not stat.S_ISREG(metadata.st_mode)
            or int(getattr(metadata, "st_nlink", 1) or 1) != 1
        ):
            raise ArtifactLedgerError(
                "driver successor progress path is not a no-follow "
                "regular file"
            )
    encoded = (
        json.dumps(
            dict(payload),
            indent=2,
            sort_keys=True,
            ensure_ascii=True,
        )
        + "\n"
    )
    _write_rooted_control_bytes(path, encoded.encode("utf-8"))
    _lexical_no_follow_chain(path)
    metadata = rooted_io.lstat(path)
    if (
        _metadata_is_reparse(metadata)
        or not stat.S_ISREG(metadata.st_mode)
        or int(getattr(metadata, "st_nlink", 1) or 1) != 1
    ):
        raise ArtifactLedgerError(
            "driver successor progress publication is unsafe"
        )


def _driver_successor_progress_event_digest(
    event: Mapping[str, Any],
) -> str:
    return _canonical_json_digest({
        key: value
        for key, value in event.items()
        if key != "event_digest"
    })


def _validated_driver_successor_progress_events(
    progress: Mapping[str, Any],
    authority: Mapping[str, Any],
) -> list[dict[str, Any]]:
    authority_digest = str(authority.get("authority_digest") or "")
    plan_digest = str(authority.get("plan_digest") or "")
    plan = authority.get("plan")
    transactions = progress.get("transactions")
    transaction = (
        transactions.get(authority_digest)
        if isinstance(transactions, Mapping)
        else None
    )
    if not isinstance(plan, Mapping):
        raise ArtifactLedgerError(
            "driver successor authority plan is malformed"
        )
    transitions = plan.get("transitions")
    if (
        not isinstance(transitions, list)
        or not transitions
        or any(not isinstance(row, Mapping) for row in transitions)
    ):
        raise ArtifactLedgerError(
            "driver successor plan transition denominator is malformed"
        )
    if transaction is None:
        return []
    expected_transaction_fields = {
        "authority_digest",
        "plan_digest",
        "run_id",
        "work_unit_key",
        "events",
    }
    events = (
        transaction.get("events")
        if isinstance(transaction, Mapping)
        else None
    )
    if (
        not isinstance(transaction, Mapping)
        or set(transaction) != expected_transaction_fields
        or transaction.get("authority_digest") != authority_digest
        or transaction.get("plan_digest") != plan_digest
        or transaction.get("run_id") != authority.get("run_id")
        or transaction.get("work_unit_key")
        != authority.get("work_unit_key")
        or not isinstance(events, list)
        or len(events) > len(transitions) * 2
    ):
        raise ArtifactLedgerError(
            "driver successor progress transaction is malformed"
        )
    normalized: list[dict[str, Any]] = []
    prior_digest = ""
    expected_ordinal = 1
    expect_state = "STEP_ARMED"
    event_fields = {
        "schema",
        "authority_digest",
        "plan_digest",
        "run_id",
        "work_unit_key",
        "ordinal",
        "state",
        "prior_event_digest",
        "transition_digest",
        "event_digest",
    }
    for raw in events:
        if not isinstance(raw, Mapping) or set(raw) != event_fields:
            raise ArtifactLedgerError(
                "driver successor progress event fields are malformed"
            )
        ordinal = raw.get("ordinal")
        state = str(raw.get("state") or "")
        if (
            raw.get("schema")
            != _DRIVER_SUCCESSOR_PROGRESS_EVENT_SCHEMA
            or raw.get("authority_digest") != authority_digest
            or raw.get("plan_digest") != plan_digest
            or raw.get("run_id") != authority.get("run_id")
            or raw.get("work_unit_key")
            != authority.get("work_unit_key")
            or not isinstance(ordinal, int)
            or isinstance(ordinal, bool)
            or ordinal != expected_ordinal
            or state != expect_state
            or raw.get("prior_event_digest") != prior_digest
            or raw.get("event_digest")
            != _driver_successor_progress_event_digest(raw)
            or ordinal > len(transitions)
            or raw.get("transition_digest")
            != _canonical_json_digest(dict(transitions[ordinal - 1]))
        ):
            raise ArtifactLedgerError(
                "driver successor progress chain is invalid"
            )
        row = dict(raw)
        normalized.append(row)
        prior_digest = str(row["event_digest"])
        if state == "STEP_ARMED":
            expect_state = "STEP_APPLIED"
        else:
            expected_ordinal += 1
            expect_state = "STEP_ARMED"
    return normalized


def _driver_successor_progress_authority_digest(
    payload: Mapping[str, Any],
) -> str:
    return _canonical_json_digest({
        key: value
        for key, value in payload.items()
        if key != "receipt_digest"
    })


def _new_driver_successor_progress_authority(
    authority: Mapping[str, Any],
) -> dict[str, Any]:
    unsigned = {
        "schema": _DRIVER_SUCCESSOR_PROGRESS_AUTHORITY_SCHEMA,
        "authority_digest": str(
            authority.get("authority_digest") or ""
        ),
        "plan_digest": str(authority.get("plan_digest") or ""),
        "run_id": str(authority.get("run_id") or ""),
        "work_unit_key": str(
            authority.get("work_unit_key") or ""
        ),
        "events": [],
        "head_event_digest": "",
    }
    return {
        **unsigned,
        "receipt_digest": _canonical_json_digest(unsigned),
    }


def _validated_unit_driver_successor_progress_events(
    scratchpad: Path,
    unit: Mapping[str, Any],
    authority: Mapping[str, Any],
) -> list[dict[str, Any]]:
    progress_authority = unit.get(
        "successor_progress_authority"
    )
    fields = {
        "schema",
        "authority_digest",
        "plan_digest",
        "run_id",
        "work_unit_key",
        "events",
        "head_event_digest",
        "receipt_digest",
    }
    if (
        not isinstance(progress_authority, Mapping)
        or set(progress_authority) != fields
        or progress_authority.get("schema")
        != _DRIVER_SUCCESSOR_PROGRESS_AUTHORITY_SCHEMA
        or progress_authority.get("authority_digest")
        != authority.get("authority_digest")
        or progress_authority.get("plan_digest")
        != authority.get("plan_digest")
        or progress_authority.get("run_id")
        != authority.get("run_id")
        or progress_authority.get("work_unit_key")
        != authority.get("work_unit_key")
        or progress_authority.get("receipt_digest")
        != _driver_successor_progress_authority_digest(
            progress_authority
        )
    ):
        raise ArtifactLedgerError(
            "driver successor ledger-bound progress authority is malformed"
        )
    transaction = {
        "authority_digest": progress_authority[
            "authority_digest"
        ],
        "plan_digest": progress_authority["plan_digest"],
        "run_id": progress_authority["run_id"],
        "work_unit_key": progress_authority["work_unit_key"],
        "events": progress_authority["events"],
    }
    events = _validated_driver_successor_progress_events(
        {
            "schema": _DRIVER_SUCCESSOR_PROGRESS_SCHEMA,
            "transactions": {
                str(authority["authority_digest"]): transaction
            },
        },
        authority,
    )
    expected_head = (
        str(events[-1]["event_digest"]) if events else ""
    )
    if progress_authority.get("head_event_digest") != expected_head:
        raise ArtifactLedgerError(
            "driver successor ledger-bound progress head differs"
        )
    for event in events:
        unsigned = {
            key: value
            for key, value in event.items()
            if key != "event_digest"
        }
        if (
            _read_authority_cas(
                Path(scratchpad),
                str(event["event_digest"]),
                directory_name=(
                    _DRIVER_SUCCESSOR_PROGRESS_EVENT_CAS_DIRECTORY
                ),
                label="driver successor progress event",
            )
            != unsigned
        ):
            raise ArtifactLedgerError(
                "driver successor progress event CAS does not replay"
            )
    return events


def _driver_successor_progress_projection_from_ledger(
    scratchpad: Path,
    ledger: Mapping[str, Any],
) -> dict[str, Any]:
    transactions: dict[str, dict[str, Any]] = {}
    units = ledger.get("work_units")
    if not isinstance(units, Mapping):
        raise ArtifactLedgerError(
            "artifact ledger work-unit table is malformed"
        )
    for unit in units.values():
        if not isinstance(unit, Mapping):
            continue
        authority = unit.get("successor_consumption_authority")
        progress_authority = unit.get(
            "successor_progress_authority"
        )
        if authority is None and progress_authority is None:
            continue
        if not isinstance(authority, Mapping):
            raise ArtifactLedgerError(
                "driver successor projection authority is malformed"
            )
        events = _validated_unit_driver_successor_progress_events(
            Path(scratchpad), unit, authority
        )
        if not events:
            continue
        authority_digest = str(authority["authority_digest"])
        transaction = {
            "authority_digest": authority_digest,
            "plan_digest": str(authority["plan_digest"]),
            "run_id": str(authority["run_id"]),
            "work_unit_key": str(authority["work_unit_key"]),
            "events": [dict(event) for event in events],
        }
        prior = transactions.get(authority_digest)
        if prior is not None and prior != transaction:
            raise ArtifactLedgerError(
                "driver successor progress projection digest collision"
            )
        transactions[authority_digest] = transaction
    return {
        "schema": _DRIVER_SUCCESSOR_PROGRESS_SCHEMA,
        "transactions": transactions,
    }


def _synchronize_driver_successor_progress_projection(
    scratchpad: Path,
    ledger: Mapping[str, Any],
) -> None:
    expected = _driver_successor_progress_projection_from_ledger(
        Path(scratchpad), ledger
    )
    try:
        observed = _read_driver_successor_progress(Path(scratchpad))
    except ArtifactLedgerError:
        observed = None
    if observed != expected:
        _write_driver_successor_progress(
            Path(scratchpad), expected
        )


def _append_driver_successor_progress_event(
    scratchpad: Path,
    ledger: dict[str, Any],
    unit: Mapping[str, Any],
    authority: Mapping[str, Any],
    *,
    ordinal: int,
    state: str,
) -> dict[str, Any]:
    authority_digest = str(authority.get("authority_digest") or "")
    plan_digest = str(authority.get("plan_digest") or "")
    events = _validated_unit_driver_successor_progress_events(
        Path(scratchpad), unit, authority
    )
    plan = authority["plan"]
    transitions = plan["transitions"]
    unsigned = {
        "schema": _DRIVER_SUCCESSOR_PROGRESS_EVENT_SCHEMA,
        "authority_digest": authority_digest,
        "plan_digest": plan_digest,
        "run_id": authority["run_id"],
        "work_unit_key": authority["work_unit_key"],
        "ordinal": ordinal,
        "state": state,
        "prior_event_digest": (
            str(events[-1]["event_digest"]) if events else ""
        ),
        "transition_digest": _canonical_json_digest(
            dict(transitions[ordinal - 1])
        ),
    }
    event = {
        **unsigned,
        "event_digest": _canonical_json_digest(unsigned),
    }
    _write_once_authority_cas(
        Path(scratchpad),
        directory_name=(
            _DRIVER_SUCCESSOR_PROGRESS_EVENT_CAS_DIRECTORY
        ),
        authority_digest=str(event["event_digest"]),
        unsigned_authority=unsigned,
        label="driver successor progress event",
    )
    progress_authority = dict(
        unit["successor_progress_authority"]
    )
    progress_authority["events"] = [
        *[dict(row) for row in events],
        event,
    ]
    progress_authority["head_event_digest"] = event[
        "event_digest"
    ]
    progress_authority["receipt_digest"] = (
        _driver_successor_progress_authority_digest(
            progress_authority
        )
    )
    updated_unit = dict(unit)
    updated_unit["successor_progress_authority"] = (
        progress_authority
    )
    ledger["work_units"][
        str(authority["work_unit_key"])
    ] = updated_unit
    # The ledger-bound head is the authority.  Publish it durably before the
    # compatibility projection; a crash in between is repaired from the
    # ledger on the next trusted driver entry.
    write_artifact_ledger(Path(scratchpad), ledger)
    _synchronize_driver_successor_progress_projection(
        Path(scratchpad), ledger
    )
    return event


def _program_facts_output_authority_required(
    contract: PhaseIOContract,
) -> bool:
    return bool(
        contract.phase == "recon"
        and contract.work_unit_id in {
            "program_facts_methodology_capture",
            "program_facts_bake",
        }
    )


def _normalize_expected_output_records(
    records: Mapping[str, Mapping[str, Any]],
    *,
    allow_absent: bool = False,
) -> dict[str, dict[str, Any]]:
    if not _nested_output_records_have_exact_sizes(records):
        raise ArtifactLedgerError(
            "expected output records contain a malformed byte count"
        )
    normalized: dict[str, dict[str, Any]] = {}
    for raw_identity, raw_record in records.items():
        identity = str(raw_identity)
        if (
            not isinstance(raw_record, Mapping)
            or set(raw_record) != {"sha256", "size"}
            or (
                re.fullmatch(
                    r"[0-9a-f]{64}", str(raw_record.get("sha256") or "")
                )
                is None
                and not (
                    allow_absent
                    and raw_record.get("sha256") == ""
                    and raw_record.get("size") == 0
                )
            )
        ):
            raise ArtifactLedgerError(
                f"{identity}: expected output record is malformed"
            )
        normalized[identity] = {
            "sha256": str(raw_record["sha256"]),
            "size": int(raw_record["size"]),
        }
    return normalized


def _worker_execution_expected_records(
    scratchpad: Path,
    authority: Mapping[str, Any],
    contract: PhaseIOContract,
    launch: LaunchSpec,
    *,
    run_id: str,
) -> dict[str, dict[str, Any]]:
    from worker_transaction import validate_worker_execution_authority

    normalized = validate_worker_execution_authority(
        scratchpad=Path(scratchpad),
        authority=authority,
        contract=contract,
        launch=launch,
        run_id=run_id,
    )
    relative = str(normalized["incorporation_relative_path"])
    incorporation_path = _path_for_identity(
        Path(scratchpad),
        Path(scratchpad),
        f"scratchpad:{relative}",
    )
    incorporation = json.loads(
        _read_stable_regular_bytes(
            incorporation_path, limit=16 * 1024 * 1024
        ).decode("utf-8", errors="strict")
    )
    projected = (
        incorporation.get("projected_members")
        if isinstance(incorporation, Mapping)
        else None
    )
    if not isinstance(projected, list):
        raise ArtifactLedgerError(
            "worker incorporation has no exact projected output denominator"
        )
    return _normalize_expected_output_records({
        str(row["canonical_identity"]): {
            "sha256": row["sha256"],
            "size": row["size"],
        }
        for row in projected
        if isinstance(row, Mapping)
    })


def _attempt_ordinal_from_ledger(
    scratchpad: Path,
    ledger: Mapping[str, Any],
    contract: PhaseIOContract,
    *,
    run_id: str,
) -> int:
    """Allocate after every immutable issuance for this run/work unit.

    The mutable current-unit commit receipt is not the attempt namespace: it
    can be absent after a crash, deliberately removed during stale rebind, or
    corrupt.  The append-only journal plus its write-once CAS is authoritative.
    """

    unit = ledger.get("work_units", {}).get(contract.key)
    run = str(run_id or "").strip()
    if not run:
        raise ArtifactLedgerError("output authority attempt run_id is absent")
    journal = _reconcile_output_authority_history(Path(scratchpad))
    attempts: set[int] = set()
    for key, raw in journal["authorities"].items():
        logical, _authority, _unsigned = (
            _validated_output_authority_envelope(
                raw, authority_key=str(key)
            )
        )
        if (
            logical[0] == run
            and logical[1] == contract.key
        ):
            attempts.add(logical[2])

    historical_unit = bool(
        isinstance(unit, Mapping)
        and unit.get("run_id") == run
        and (
            "commit_authority" in unit
            or unit.get("execution_state") in _COMMIT_TERMINAL_STATES
            or bool(unit.get("artifacts"))
            or bool(unit.get("semantic_reexecution_history"))
            or bool(unit.get("quarantine_recovery_history"))
        )
    )
    if attempts:
        if attempts != set(range(1, max(attempts) + 1)):
            raise ArtifactLedgerError(
                "output authority attempt history is noncontiguous"
            )
        return max(attempts) + 1
    if historical_unit:
        raise ArtifactLedgerError(
            "historical output commit has no replayable issuance history"
        )
    return 1


def _issue_output_commit_authority(
    scratchpad: Path,
    project_root: Path,
    ledger: Mapping[str, Any],
    contract: PhaseIOContract,
    launch: LaunchSpec,
    *,
    run_id: str,
    actor: str | None,
    expected_output_records: Mapping[str, Mapping[str, Any]] | None,
    execution_authority: Mapping[str, Any] | None,
    _validation_context: _ArtifactValidationContext | None = None,
) -> dict[str, Any]:
    actor_n = str(actor or "").strip().upper()
    selection_actor = contract.required_commit_actor or actor_n
    specs = [
        spec
        for spec in contract.outputs
        if not selection_actor or spec.writer == selection_actor
    ]
    if not actor_n:
        inferred_actors = {spec.writer for spec in specs}
        if len(inferred_actors) == 1:
            # A caller that omits the optional actor still publishes outputs
            # under one exact contract writer.  Persist that derivable actor
            # instead of an unauthenticated empty provenance hint.
            actor_n = next(iter(inferred_actors))
    identities = {spec.identity for spec in specs}
    source = "LEGACY_DESCRIPTOR_CAPTURE"
    independent_records: dict[str, dict[str, Any]] | None = None
    if expected_output_records is not None:
        source = "VALIDATED_EXPECTED_OUTPUT_RECORDS"
        independent_records = _normalize_expected_output_records(
            expected_output_records
        )
    elif execution_authority is not None:
        source = "WORKER_TRANSACTION_CAS"
        independent_records = _worker_execution_expected_records(
            scratchpad,
            execution_authority,
            contract,
            launch,
            run_id=run_id,
        )

    issue_codes: set[str] = set()
    if independent_records is not None and set(independent_records) != identities:
        issue_codes.add("EXPECTED_OUTPUT_DENOMINATOR_MISMATCH")
    if (
        independent_records is None
        and _program_facts_output_authority_required(contract)
    ):
        issue_codes.add("OUTPUT_COMMIT_AUTHORITY_REQUIRED")

    observations: dict[str, dict[str, Any]] = {}
    for spec in specs:
        identity = spec.identity
        try:
            path = (
                _path_for_identity(
                    Path(scratchpad), Path(project_root), identity
                )
                if _validation_context is None
                else _validation_context.path_for_identity(identity)
            )
        except ArtifactLedgerError:
            observations[identity] = {
                "status": "UNSAFE",
                "size": 0,
                "sha256": "",
                "physical_identity": "",
                "physical_policy": _NO_FOLLOW_PHYSICAL_POLICY,
            }
            issue_codes.add("OUTPUT_PHYSICAL_PATH_UNSAFE")
            continue
        snapshot, snapshot_error = (
            _stable_artifact_snapshot(path)
            if _validation_context is None
            else _validation_context.snapshot(path)
        )
        if snapshot is None:
            observations[identity] = {
                "status": "ABSENT",
                "size": 0,
                "sha256": "",
                "physical_identity": (
                    (
                        _physical_file_identity(path)
                        if _validation_context is None
                        else _validation_context.physical_identity(path)
                    )
                    if rooted_io.lexists(path)
                    else f"path:{os.path.normcase(os.path.abspath(os.fspath(path)))}"
                ),
                "physical_policy": _NO_FOLLOW_PHYSICAL_POLICY,
            }
            if snapshot_error and rooted_io.lexists(path):
                issue_codes.add("OUTPUT_AUTHORITY_SNAPSHOT_UNSAFE")
        else:
            observations[identity] = {
                "status": "PRESENT",
                "size": int(snapshot["size"]),
                "sha256": str(snapshot["sha256"]),
                "physical_identity": (
                    _physical_file_identity(path)
                    if _validation_context is None
                    else _validation_context.physical_identity(path)
                ),
                "physical_policy": _NO_FOLLOW_PHYSICAL_POLICY,
            }
        expected = (
            independent_records.get(identity)
            if independent_records is not None
            else None
        )
        if expected is not None and (
            observations[identity]["status"] != "PRESENT"
            or observations[identity]["sha256"] != expected["sha256"]
            or observations[identity]["size"] != expected["size"]
        ):
            issue_codes.add("EXPECTED_OUTPUT_RECORD_MISMATCH")

    expected = (
        independent_records
        if independent_records is not None
        else {
            identity: {
                "sha256": row["sha256"],
                "size": row["size"],
            }
            for identity, row in observations.items()
        }
    )
    attempt = _attempt_ordinal_from_ledger(
        Path(scratchpad), ledger, contract, run_id=run_id
    )
    prior_unit = ledger.get("work_units", {}).get(contract.key)
    input_set_digest = (
        str(prior_unit.get("input_set_digest") or "")
        if isinstance(prior_unit, Mapping)
        else _input_set_digest({})
    )
    if (
        isinstance(prior_unit, Mapping)
        and prior_unit.get("input_bindings") == {}
        and input_set_digest == ""
    ):
        input_set_digest = _input_set_digest({})
    recovery_history: list[dict[str, Any]] = []
    if isinstance(prior_unit, Mapping):
        try:
            recovery_history = _validated_quarantine_recovery_history(
                prior_unit,
                work_unit_key=contract.key,
                run_id=run_id,
            )
        except ArtifactLedgerError:
            if (
                "commit_authority" in prior_unit
                or prior_unit.get("execution_state") in _COMMIT_TERMINAL_STATES
                or bool(prior_unit.get("artifacts"))
            ):
                # A terminal receipt belongs to its original run.  A caller
                # presenting the same logical key under another run must not
                # mint even an INVALID successor authority beside it.
                raise
            # Issuance is evidence capture, including for a deliberately
            # corrupted/stale predecessor.  Preserve the invalidity as a
            # reason code so the commit is quarantined; do not abort before
            # the normal metadata-CAS gate can record its more specific debt.
            issue_codes.add("QUARANTINE_RECOVERY_HISTORY_INVALID")
    recovery_count, recovery_head = _quarantine_recovery_history_binding(
        recovery_history
    )
    key = _output_authority_key(
        run_id=run_id,
        work_unit_key=contract.key,
        attempt_ordinal=attempt,
    )
    unsigned: dict[str, Any] = {
        "schema": _OUTPUT_AUTHORITY_SCHEMA,
        "authority_key": key,
        "state": "ACTIVE" if not issue_codes else "INVALID",
        "source": source,
        "run_id": run_id,
        "work_unit_key": contract.key,
        "contract_digest": contract.digest,
        "launch_digest": launch.digest,
        "input_set_digest": input_set_digest,
        "attempt_ordinal": attempt,
        "quarantine_recovery_history_count": recovery_count,
        "quarantine_recovery_history_head_digest": recovery_head,
        "actor": actor_n,
        "physical_policy": _NO_FOLLOW_PHYSICAL_POLICY,
        "expected_output_records": dict(sorted(expected.items())),
        "observed_outputs": dict(sorted(observations.items())),
        "reason_codes": sorted(issue_codes),
    }
    authority = {
        **unsigned,
        "authority_digest": _canonical_json_digest(unsigned),
    }
    _write_once_output_authority_cas(
        Path(scratchpad),
        authority_digest=authority["authority_digest"],
        unsigned_authority=unsigned,
    )
    journal = _read_output_authority_ledger(Path(scratchpad))
    prior = journal["authorities"].get(key)
    if prior is not None and prior != authority:
        raise ArtifactLedgerError(
            "output commit authority replay changed before ledger commit"
        )
    journal["authorities"][key] = authority
    _write_output_authority_ledger(Path(scratchpad), journal)
    return authority


def _replay_output_commit_authority_uncached(
    scratchpad: Path,
    project_root: Path,
    unit: Mapping[str, Any],
    *,
    require_live_bytes: bool,
    live_byte_exempt_identities: Sequence[str] = (),
    live_physical_override_by_identity: Mapping[str, str] | None = None,
    allow_quarantined_expected_mismatch: bool = False,
    _validation_context: _ArtifactValidationContext | None = None,
) -> list[str]:
    commit = unit.get("commit_authority")
    if not isinstance(commit, Mapping):
        return ["output commit authority receipt missing"]
    key = str(commit.get("output_authority_key") or "")
    digest = str(commit.get("output_authority_digest") or "")
    if not key or not digest:
        return ["output commit authority binding missing"]
    try:
        if _validation_context is None:
            cas_unsigned = _read_output_authority_cas(
                Path(scratchpad), digest
            )
            journal = _read_output_authority_ledger(Path(scratchpad))
        else:
            cas_unsigned = _validation_context.output_authority_cas(digest)
            journal = _validation_context.output_authority_journal()
    except ArtifactLedgerError as exc:
        return [str(exc)]
    sidecar_authority = journal["authorities"].get(key)
    authority = {
        **cas_unsigned,
        "authority_digest": digest,
    }
    try:
        _validated_output_authority_envelope(
            authority,
            authority_key=key,
        )
        if not isinstance(sidecar_authority, Mapping):
            raise ArtifactLedgerError(
                "output authority journal binding is absent"
            )
        _validated_output_authority_envelope(
            sidecar_authority,
            authority_key=key,
        )
    except ArtifactLedgerError as exc:
        return [str(exc)]
    records = unit.get("artifacts")
    try:
        recovery_history = _validated_quarantine_recovery_history(
            unit,
            work_unit_key=str(unit.get("work_unit_key") or ""),
            run_id=str(unit.get("run_id") or ""),
        )
    except ArtifactLedgerError as exc:
        return [str(exc)]
    recovery_count, recovery_head = _quarantine_recovery_history_binding(
        recovery_history
    )
    authority_expected = authority.get("expected_output_records")
    sidecar_expected = (
        sidecar_authority.get("expected_output_records")
        if isinstance(sidecar_authority, Mapping)
        else None
    )
    expected_identities = (
        set(authority_expected)
        if isinstance(authority_expected, Mapping)
        else set()
    )
    if not (
        isinstance(sidecar_authority, Mapping)
        and _nested_output_records_have_exact_sizes(
            authority_expected
        )
        and _nested_output_records_have_exact_sizes(
            authority.get("observed_outputs"),
            expected_identities=expected_identities,
        )
        and _nested_output_records_have_exact_sizes(
            sidecar_expected,
            expected_identities=expected_identities,
        )
        and _nested_output_records_have_exact_sizes(
            sidecar_authority.get("observed_outputs"),
            expected_identities=expected_identities,
        )
        and _nested_output_records_have_exact_sizes(
            commit.get("expected_output_records"),
            expected_identities=expected_identities,
        )
        and _nested_output_records_have_exact_sizes(
            records,
            expected_identities=expected_identities,
        )
    ):
        return ["output commit authority nested byte count is invalid"]
    if (
        dict(sidecar_authority) != authority
    ):
        return ["output commit authority issuance is absent"]
    unsigned = {
        name: value
        for name, value in authority.items()
        if name != "authority_digest"
    }
    state_replays = authority.get("state") == "ACTIVE"
    if (
        allow_quarantined_expected_mismatch
        and unit.get("semantic_status") == "QUARANTINED"
        and unit.get("execution_state") == "OUTPUT_QUARANTINED"
        and authority.get("state") == "INVALID"
        and set(authority.get("reason_codes") or ())
        == {"EXPECTED_OUTPUT_RECORD_MISMATCH"}
    ):
        state_replays = True
    if (
        authority.get("schema") != _OUTPUT_AUTHORITY_SCHEMA
        or authority.get("authority_key") != key
        or authority.get("authority_digest") != digest
        or _canonical_json_digest(unsigned) != digest
        or not state_replays
        or authority.get("run_id") != unit.get("run_id")
        or authority.get("work_unit_key") != unit.get("work_unit_key")
        or authority.get("contract_digest") != unit.get("contract_digest")
        or authority.get("launch_digest") != unit.get("launch_digest")
        or authority.get("input_set_digest") != unit.get("input_set_digest")
        or authority.get("attempt_ordinal") != commit.get("attempt_ordinal")
        or authority.get("quarantine_recovery_history_count")
        != recovery_count
        or authority.get("quarantine_recovery_history_head_digest")
        != recovery_head
        or commit.get("quarantine_recovery_history_count")
        != recovery_count
        or commit.get("quarantine_recovery_history_head_digest")
        != recovery_head
        or authority.get("physical_policy") != _NO_FOLLOW_PHYSICAL_POLICY
        or authority.get("expected_output_records")
        != commit.get("expected_output_records")
    ):
        return ["output commit authority issuance does not replay"]
    observations = authority.get("observed_outputs")
    if not isinstance(observations, Mapping) or not isinstance(records, Mapping):
        return ["output commit authority denominator is malformed"]
    repair_projection_valid, repair_observations = (
        _pure_exact_repair_output_projection(
            unit,
            commit,
            records,
            authority_expected,
        )
    )
    if not repair_projection_valid:
        return ["output commit exact-repair projection is invalid"]
    if (
        repair_observations is not None
        and repair_observations != dict(observations)
    ):
        return ["output commit exact-repair predecessor changed"]
    physical_rebound = repair_observations is not None
    live_exempt = {
        str(identity) for identity in live_byte_exempt_identities
    }
    raw_physical_overrides = live_physical_override_by_identity or {}
    if not isinstance(raw_physical_overrides, Mapping) or any(
        not isinstance(identity, str)
        or not identity
        or not isinstance(physical, str)
        or not physical
        for identity, physical in raw_physical_overrides.items()
    ) or len({
        identity.casefold() for identity in raw_physical_overrides
    }) != len(raw_physical_overrides) or len(
        set(raw_physical_overrides.values())
    ) != len(raw_physical_overrides):
        return ["output commit live-physical override is malformed"]
    physical_overrides = dict(raw_physical_overrides)
    if live_exempt - set(observations):
        return ["output commit live-byte exemption denominator differs"]
    if set(physical_overrides) - set(observations):
        return ["output commit live-physical override denominator differs"]
    if live_exempt & set(physical_overrides):
        return ["output commit live authority exemptions overlap"]
    issues: list[str] = []
    for identity, observation in observations.items():
        record = records.get(identity)
        if not isinstance(observation, Mapping) or not isinstance(record, Mapping):
            issues.append(f"{identity}: output authority record is absent")
            continue
        compared_fields = (
            ("size", "sha256")
            if physical_rebound
            else ("size", "sha256", "physical_identity")
        )
        for field in compared_fields:
            if observation.get(field) != record.get(field):
                issues.append(
                    f"{identity}: output authority {field} differs from ledger"
                )
        if observation.get("physical_policy") != _NO_FOLLOW_PHYSICAL_POLICY:
            issues.append(f"{identity}: output physical policy changed")
        if (
            not require_live_bytes
            or identity in live_exempt
            or observation.get("status") != "PRESENT"
        ):
            continue
        try:
            path = _path_for_identity(
                Path(scratchpad), Path(project_root), str(identity)
            )
            if _validation_context is None:
                snapshot, error = _stable_artifact_snapshot(path)
                physical = _physical_file_identity(path)
            else:
                snapshot, error = _validation_context.snapshot(path)
                physical = _validation_context.physical_identity(path)
        except ArtifactLedgerError as exc:
            issues.append(f"{identity}: output authority path unsafe: {exc}")
            continue
        if (
            snapshot is None
            or error
            or snapshot.get("sha256") != observation.get("sha256")
            or snapshot.get("size") != observation.get("size")
            or physical
            != (
                physical_overrides.get(
                    identity,
                    record.get("physical_identity")
                    if physical_rebound
                    else observation.get("physical_identity"),
                )
            )
        ):
            issues.append(
                f"{identity}: live bytes differ from issued output authority"
            )
    return issues


def _replay_output_commit_authority(
    scratchpad: Path,
    project_root: Path,
    unit: Mapping[str, Any],
    *,
    require_live_bytes: bool,
    live_byte_exempt_identities: Sequence[str] = (),
    live_physical_override_by_identity: Mapping[str, str] | None = None,
    allow_quarantined_expected_mismatch: bool = False,
    _validation_context: _ArtifactValidationContext | None = None,
) -> list[str]:
    """Replay one producer once per invocation and exact commit receipt."""

    if _validation_context is None:
        return _replay_output_commit_authority_uncached(
            scratchpad,
            project_root,
            unit,
            require_live_bytes=require_live_bytes,
            live_byte_exempt_identities=live_byte_exempt_identities,
            live_physical_override_by_identity=(
                live_physical_override_by_identity
            ),
            allow_quarantined_expected_mismatch=(
                allow_quarantined_expected_mismatch
            ),
        )
    commit = unit.get("commit_authority")
    producer_key = str(unit.get("work_unit_key") or "")
    receipt_digest = (
        str(commit.get("receipt_digest") or "")
        if isinstance(commit, Mapping)
        else ""
    )
    authority_digest = (
        str(commit.get("output_authority_digest") or "")
        if isinstance(commit, Mapping)
        else ""
    )
    cache_key = (
        _validation_context._ledger_digest,
        producer_key,
        receipt_digest,
        authority_digest,
        bool(require_live_bytes),
        tuple(sorted(str(value) for value in live_byte_exempt_identities)),
        tuple(sorted(
            (str(identity), str(physical))
            for identity, physical in (
                live_physical_override_by_identity or {}
            ).items()
        )),
        bool(allow_quarantined_expected_mismatch),
    )
    cached = _validation_context.producer_replay_issues.get(cache_key)
    if cached is not None:
        return list(cached)
    issues = _replay_output_commit_authority_uncached(
        scratchpad,
        project_root,
        unit,
        require_live_bytes=require_live_bytes,
        live_byte_exempt_identities=live_byte_exempt_identities,
        live_physical_override_by_identity=(
            live_physical_override_by_identity
        ),
        allow_quarantined_expected_mismatch=(
            allow_quarantined_expected_mismatch
        ),
        _validation_context=_validation_context,
    )
    _validation_context.producer_replay_issues[cache_key] = tuple(issues)
    return list(issues)


def _launch_manifest_is_valid(
    manifest: object,
    *,
    expected_digest: object,
) -> bool:
    if not isinstance(manifest, dict):
        return False
    expected_fields = {
        "launch_version",
        "work_unit_key",
        "pipeline",
        "mode",
        "ecosystem",
        "backend",
        "model",
        "timeout_s",
        "exec_mode",
        "tool_policy",
    }
    if set(manifest) != expected_fields:
        return False
    try:
        replay = LaunchSpec(
            work_unit_key=manifest["work_unit_key"],
            pipeline=manifest["pipeline"],
            mode=manifest["mode"],
            ecosystem=manifest["ecosystem"],
            backend=manifest["backend"],
            model=manifest["model"],
            timeout_s=manifest["timeout_s"],
            exec_mode=manifest["exec_mode"],
            tool_policy=tuple(manifest["tool_policy"]),
            launch_version=manifest["launch_version"],
        )
    except (KeyError, TypeError, ValueError):
        return False
    return bool(
        LaunchSpec.to_dict(replay) == manifest
        and replay.digest == expected_digest
    )


def _stored_launch_matches(
    unit: Mapping[str, Any],
    launch: LaunchSpec,
) -> bool:
    return bool(
        unit.get("launch_digest") == launch.digest
        and unit.get("launch_manifest") == launch.to_dict()
        and _launch_manifest_is_valid(
            unit.get("launch_manifest"),
            expected_digest=unit.get("launch_digest"),
        )
    )


def _registered_input_bound_commit_metadata(
    unit: Mapping[str, Any],
) -> dict[str, str]:
    """Replay the closed metadata extension admitted across generic commit."""

    fields = frozenset(_REGISTERED_INPUT_BOUND_COMMIT_METADATA_SCHEMA)
    present = fields & frozenset(unit)
    if not present:
        return {}
    if present != fields:
        raise ArtifactLedgerError(
            "registered input-bound commit metadata is one-sided"
        )
    result: dict[str, str] = {}
    for field, scalar_type in (
        _REGISTERED_INPUT_BOUND_COMMIT_METADATA_SCHEMA.items()
    ):
        value = unit.get(field)
        if scalar_type != "SHA256" or not _is_digest(value):
            raise ArtifactLedgerError(
                "registered input-bound commit metadata is malformed"
            )
        result[field] = str(value)
    return result


def _registered_commit_metadata_binding_is_valid(
    unit: Mapping[str, Any],
    commit: Mapping[str, Any],
) -> bool:
    """Require the committed row and receipt to carry one exact extension."""

    try:
        return _registered_input_bound_commit_metadata(
            unit
        ) == _registered_input_bound_commit_metadata(commit)
    except ArtifactLedgerError:
        return False


def _active_commit_receipt_is_valid(
    unit: Mapping[str, Any],
    *,
    work_unit_key: str,
    run_id: str,
) -> bool:
    manifest = unit.get("contract_manifest")
    launch_manifest = unit.get("launch_manifest")
    commit = unit.get("commit_authority")
    artifacts = unit.get("artifacts")
    if (
        unit.get("schema") != "plamen.artifact-work-unit.v2"
        or unit.get("work_unit_key") != work_unit_key
        or unit.get("run_id") != run_id
        or unit.get("semantic_status") != "ACTIVE"
        or unit.get("execution_state") != "OUTPUT_COMMITTED"
        or not isinstance(manifest, dict)
        or manifest.get("key") != work_unit_key
        or _contract_manifest_digest(manifest) != unit.get("contract_digest")
        or not isinstance(launch_manifest, dict)
        or launch_manifest.get("work_unit_key") != work_unit_key
        or not _launch_manifest_is_valid(
            launch_manifest,
            expected_digest=unit.get("launch_digest"),
        )
        or not isinstance(commit, dict)
        or not isinstance(artifacts, dict)
    ):
        return False
    expected_outputs = commit.get("expected_output_records")
    input_bindings = unit.get("input_bindings")
    if (
        not isinstance(expected_outputs, Mapping)
        or set(expected_outputs) != set(artifacts)
        or not _nested_output_records_have_exact_sizes(
            expected_outputs,
            expected_identities=set(artifacts),
        )
        or not _nested_output_records_have_exact_sizes(
            artifacts,
            expected_identities=set(expected_outputs),
        )
        or not _is_digest(commit.get("output_authority_key"))
        or not _is_digest(commit.get("output_authority_digest"))
        or not _is_positive_exact_int(commit.get("attempt_ordinal"))
        or not _is_nonnegative_exact_int(
            commit.get("precommit_issue_count")
        )
        or not isinstance(input_bindings, Mapping)
        or _input_set_digest({
            str(identity): dict(record)
            for identity, record in input_bindings.items()
            if isinstance(record, Mapping)
        }) != unit.get("input_set_digest")
        or len(input_bindings) != sum(
            isinstance(record, Mapping)
            for record in input_bindings.values()
        )
        or not _pure_attempt_lineage_is_valid(
            unit,
            attempt_ordinal=commit.get("attempt_ordinal"),
            work_unit_key=work_unit_key,
            run_id=run_id,
        )
        or not _pure_active_output_authority_binding_is_valid(
            unit,
            commit,
            artifacts,
        )
        or not _registered_commit_metadata_binding_is_valid(unit, commit)
    ):
        return False
    for identity, expected in expected_outputs.items():
        artifact = artifacts.get(identity)
        if (
            not isinstance(expected, Mapping)
            or set(expected) != {"sha256", "size"}
            or not isinstance(artifact, Mapping)
            or expected.get("sha256") != artifact.get("sha256")
            or expected.get("size") != artifact.get("size")
        ):
            return False
    return bool(
        commit.get("schema") == _COMMIT_AUTHORITY_SCHEMA
        and commit.get("state") == "ACTIVE"
        and commit.get("run_id") == run_id
        and commit.get("work_unit_key") == work_unit_key
        and commit.get("contract_digest") == unit.get("contract_digest")
        and commit.get("launch_digest") == unit.get("launch_digest")
        and commit.get("input_set_digest") == unit.get("input_set_digest")
        and commit.get("quarantine_recovery_history_count")
        == unit.get("quarantine_recovery_history_count", 0)
        and commit.get("quarantine_recovery_history_head_digest")
        == unit.get("quarantine_recovery_history_head_digest", "")
        and commit.get("reason_codes") == []
        and commit.get("precommit_issue_count", 0) == 0
        and (
            not str(manifest.get("required_commit_actor") or "")
            or commit.get("actor")
            == manifest.get("required_commit_actor")
        )
        and commit.get("receipt_digest") == _commit_receipt_digest(commit)
    )


def _pure_attempt_lineage_is_valid(
    unit: Mapping[str, Any],
    *,
    attempt_ordinal: object,
    work_unit_key: str,
    run_id: str,
) -> bool:
    """Bind the active attempt to every persisted retry transition."""

    if not _is_positive_exact_int(attempt_ordinal):
        return False
    semantic = unit.get("semantic_reexecution_history", [])
    try:
        repair_history = _exact_repair_history(unit)
        recovery = _validated_quarantine_recovery_history(
            unit,
            work_unit_key=work_unit_key,
            run_id=run_id,
        )
    except ArtifactLedgerError:
        return False
    if (
        not isinstance(semantic, list)
        or not isinstance(recovery, list)
        or len(semantic) > 32
        or len(recovery) > 32
        or int(attempt_ordinal)
        != 1 + len(semantic) + len(recovery)
    ):
        return False
    for row in semantic:
        if (
            not isinstance(row, dict)
            or set(row) != _SEMANTIC_INVALIDATION_AUTH_FIELDS
            or row.get("schema") != _SEMANTIC_INVALIDATION_AUTH_SCHEMA
            or row.get("run_id") != run_id
            or row.get("work_unit_key") != work_unit_key
            or row.get("authorization_digest")
            != _semantic_invalidation_authorization_digest(row)
        ):
            return False
    return all(
        int(row["prior_commit_authority"]["attempt_ordinal"])
        < int(attempt_ordinal)
        for row in recovery
    )


def _validated_quarantine_recovery_history(
    unit: Mapping[str, Any],
    *,
    work_unit_key: str,
    run_id: str,
) -> list[dict[str, Any]]:
    """Replay the exact causal history for quarantined retry attempts."""

    raw_history = unit.get("quarantine_recovery_history", [])
    if (
        not isinstance(raw_history, list)
        or len(raw_history) > 32
        or unit.get("work_unit_key") != work_unit_key
        or unit.get("run_id") != run_id
    ):
        raise ArtifactLedgerError(
            "quarantine recovery history is malformed"
        )
    contract_digest = unit.get("contract_digest")
    launch_digest = unit.get("launch_digest")
    if not _is_digest(contract_digest) or not _is_digest(launch_digest):
        raise ArtifactLedgerError(
            "quarantine recovery owner authority is malformed"
        )
    normalized: list[dict[str, Any]] = []
    previous_attempt = 0
    previous_recovered_at: datetime | None = None
    expected_fields = {
        "schema",
        "ordinal",
        "prior_recovery_authority_digest",
        "recovered_at",
        "prior_commit_authority",
        "prior_artifacts_sha256",
        "authority_digest",
    }
    previous_digest = ""
    for ordinal, raw in enumerate(raw_history, start=1):
        if not isinstance(raw, Mapping) or set(raw) != expected_fields:
            raise ArtifactLedgerError(
                "quarantine recovery history row is malformed"
            )
        recovered_at = raw.get("recovered_at")
        try:
            recovered_timestamp = datetime.fromisoformat(
                str(recovered_at or "")
            )
        except ValueError as exc:
            raise ArtifactLedgerError(
                "quarantine recovery timestamp is malformed"
            ) from exc
        prior = raw.get("prior_commit_authority")
        prior_attempt = (
            prior.get("attempt_ordinal")
            if isinstance(prior, Mapping)
            else None
        )
        if (
            raw.get("schema") != _QUARANTINE_RECOVERY_AUTHORITY_SCHEMA
            or raw.get("ordinal") != ordinal
            or raw.get("prior_recovery_authority_digest")
            != previous_digest
            or not isinstance(recovered_at, str)
            or recovered_timestamp.tzinfo is None
            or (
                previous_recovered_at is not None
                and recovered_timestamp <= previous_recovered_at
            )
            or not _is_digest(raw.get("prior_artifacts_sha256"))
            or not isinstance(prior, Mapping)
            or prior.get("schema") != _COMMIT_AUTHORITY_SCHEMA
            or prior.get("state") != "QUARANTINED"
            or prior.get("run_id") != run_id
            or prior.get("work_unit_key") != work_unit_key
            or prior.get("contract_digest") != contract_digest
            or prior.get("launch_digest") != launch_digest
            or not _is_positive_exact_int(prior_attempt)
            or int(prior_attempt) <= previous_attempt
            or prior.get("receipt_digest") != _commit_receipt_digest(prior)
            or raw.get("authority_digest")
            != _canonical_json_digest({
                key: value
                for key, value in raw.items()
                if key != "authority_digest"
            })
        ):
            raise ArtifactLedgerError(
                "quarantine recovery history does not replay"
            )
        previous_attempt = int(prior_attempt)
        previous_recovered_at = recovered_timestamp
        previous_digest = str(raw["authority_digest"])
        normalized.append(copy.deepcopy(dict(raw)))
    expected_count = len(normalized)
    expected_head = previous_digest
    if (
        unit.get("quarantine_recovery_history_count", 0)
        != expected_count
        or unit.get("quarantine_recovery_history_head_digest", "")
        != expected_head
    ):
        raise ArtifactLedgerError(
            "quarantine recovery history head/count does not replay"
        )
    return normalized


def _quarantine_recovery_history_binding(
    history: Sequence[Mapping[str, Any]],
) -> tuple[int, str]:
    return (
        len(history),
        str(history[-1].get("authority_digest") or "") if history else "",
    )


def _pure_active_output_authority_binding_is_valid(
    unit: Mapping[str, Any],
    commit: Mapping[str, Any],
    artifacts: Mapping[str, Any],
) -> bool:
    """Bind a pure producer snapshot to its canonical issued authority.

    Frozen producer/import validation cannot reread the mutable journal or CAS
    files.  It can, however, reconstruct every byte-bearing authority field
    from the receipt-bound work unit.  Requiring the committed digest to name
    one of those canonical envelopes prevents a coherently resealed external
    sidecar from granting authority when its nested scalar types or output
    observations differ from the sealed ledger projection.

    Older receipts did not persist the authority's source or optional actor.
    Both fields have a small closed issuance domain, so the pure replay checks
    all legitimate combinations while keeping every security-relevant output
    field exact.  This is compatibility enumeration, not trust in sidecar
    bytes.
    """

    expected = commit.get("expected_output_records")
    identities = set(artifacts)
    if (
        not _nested_output_records_have_exact_sizes(
            expected,
            expected_identities=identities,
        )
        or not _nested_output_records_have_exact_sizes(
            artifacts,
            expected_identities=identities,
        )
    ):
        return False
    attempt = commit.get("attempt_ordinal")
    run_id = str(unit.get("run_id") or "")
    work_unit_key = str(unit.get("work_unit_key") or "")
    if (
        not _is_positive_exact_int(attempt)
        or not run_id
        or not work_unit_key
    ):
        return False
    authority_key = _output_authority_key(
        run_id=run_id,
        work_unit_key=work_unit_key,
        attempt_ordinal=attempt,
    )
    if commit.get("output_authority_key") != authority_key:
        return False

    expected_projection: dict[str, dict[str, Any]] = {}
    for identity in sorted(identities):
        record = artifacts.get(identity)
        expected_record = expected.get(identity)
        if (
            not isinstance(identity, str)
            or not identity
            or not isinstance(record, Mapping)
            or not isinstance(expected_record, Mapping)
            or set(expected_record) != {"sha256", "size"}
        ):
            return False
        expected_projection[identity] = {
            "sha256": str(expected_record.get("sha256") or ""),
            "size": expected_record.get("size"),
        }
    repair_valid, repair_observations = (
        _pure_exact_repair_output_projection(
            unit,
            commit,
            artifacts,
            expected_projection,
        )
    )
    if not repair_valid:
        return False
    observations: dict[str, dict[str, Any]] = {}
    if repair_observations is not None:
        observations = repair_observations
    else:
        for identity in sorted(identities):
            record = artifacts[identity]
            status = str(record.get("status") or "")
            if status == "ACTIVE":
                observed_status = "PRESENT"
                if not _is_digest(record.get("sha256")):
                    return False
            elif status == "MISSING":
                observed_status = "ABSENT"
                if record.get("sha256") != "" or record.get("size") != 0:
                    return False
            else:
                return False
            physical_identity = str(
                record.get("physical_identity") or ""
            )
            if not physical_identity:
                return False
            observations[identity] = {
                "status": observed_status,
                "size": record.get("size"),
                "sha256": str(record.get("sha256") or ""),
                "physical_identity": physical_identity,
                "physical_policy": _NO_FOLLOW_PHYSICAL_POLICY,
            }
    if any(
        expected_projection[identity]["sha256"]
        != observations[identity]["sha256"]
        or expected_projection[identity]["size"]
        != observations[identity]["size"]
        for identity in identities
    ):
        return False

    common = {
        "schema": _OUTPUT_AUTHORITY_SCHEMA,
        "authority_key": authority_key,
        "state": "ACTIVE",
        "run_id": run_id,
        "work_unit_key": work_unit_key,
        "contract_digest": unit.get("contract_digest"),
        "launch_digest": unit.get("launch_digest"),
        "input_set_digest": unit.get("input_set_digest"),
        "attempt_ordinal": attempt,
        "quarantine_recovery_history_count": unit.get(
            "quarantine_recovery_history_count", 0
        ),
        "quarantine_recovery_history_head_digest": unit.get(
            "quarantine_recovery_history_head_digest", ""
        ),
        "physical_policy": _NO_FOLLOW_PHYSICAL_POLICY,
        "expected_output_records": dict(sorted(expected_projection.items())),
        "observed_outputs": dict(sorted(observations.items())),
        "reason_codes": [],
    }
    committed_digest = str(
        commit.get("output_authority_digest") or ""
    )
    if not _is_digest(committed_digest):
        return False
    manifest = unit.get("contract_manifest")
    output_rows = (
        manifest.get("outputs")
        if isinstance(manifest, Mapping)
        else None
    )
    if not isinstance(output_rows, list):
        return False
    writer_by_identity = {
        str(row.get("identity") or ""): str(row.get("writer") or "")
        for row in output_rows
        if isinstance(row, Mapping)
    }
    if identities:
        selected_writers = {
            writer_by_identity.get(identity, "")
            for identity in identities
        }
        if (
            len(selected_writers) != 1
            or not selected_writers <= {"MODEL", "DRIVER"}
        ):
            return False
        expected_actor = next(iter(selected_writers))
    else:
        if (
            output_rows != []
            or manifest.get("model_invoked") is not False
            or expected_projection != {}
            or observations != {}
            or dict(expected) != {}
            or dict(artifacts) != {}
            or commit.get("recorded_output_identities") != []
        ):
            return False
        expected_actor = "DRIVER"
    expected_records_witness = commit.get(
        "output_authority_expected_records_digest"
    )
    if isinstance(commit.get("execution_authority"), Mapping):
        expected_source = "WORKER_TRANSACTION_CAS"
        if expected_records_witness is not None:
            return False
    elif expected_records_witness is not None:
        if expected_records_witness != _canonical_json_digest(
            dict(sorted(expected_projection.items()))
        ):
            return False
        expected_source = "VALIDATED_EXPECTED_OUTPUT_RECORDS"
    else:
        expected_source = "LEGACY_DESCRIPTOR_CAPTURE"
    stored_source = commit.get("output_authority_source")
    stored_actor = commit.get("output_authority_actor")
    if stored_source is None and stored_actor is None:
        # Legacy receipts omitted both hints.  Compatibility is deliberately
        # one exact derivable tuple, never a Cartesian provenance search.
        source = expected_source
        actor = expected_actor
    elif stored_source is None or stored_actor is None:
        return False
    else:
        source = str(stored_source)
        actor = str(stored_actor)
        if source != expected_source or actor != expected_actor:
            return False
    return bool(
        _canonical_json_digest({
            **common,
            "source": source,
            "actor": actor,
        }) == committed_digest
    )


def _exact_repair_canonical(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ArtifactLedgerError(
            f"committed output repair metadata is not canonical JSON: {exc}"
        ) from exc


def _exact_repair_signed(
    unsigned: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        **dict(unsigned),
        "authority_digest": hashlib.sha256(
            _exact_repair_canonical(unsigned)
        ).hexdigest(),
    }


def _read_exact_repair_control(
    path: Path,
    *,
    schema: str,
    digest_key: str,
) -> dict[str, Any]:
    try:
        raw = _read_stable_regular_bytes(
            path,
            limit=_EXACT_REPAIR_CONTROL_LIMIT,
        )
        value = json.loads(raw.decode("utf-8", errors="strict"))
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
        raise ArtifactLedgerError(
            f"committed output repair control is unreadable: "
            f"{path.name}: {type(exc).__name__}: {exc}"
        ) from exc
    if not isinstance(value, dict):
        raise ArtifactLedgerError(
            f"committed output repair control is not an object: {path.name}"
        )
    if raw != _exact_repair_canonical(value):
        raise ArtifactLedgerError(
            f"committed output repair control is not canonical: {path.name}"
        )
    unsigned = dict(value)
    recorded = str(unsigned.pop(digest_key, "") or "")
    expected = hashlib.sha256(
        _exact_repair_canonical(unsigned)
    ).hexdigest()
    if (
        value.get("schema_version") != schema
        or recorded != expected
    ):
        raise ArtifactLedgerError(
            f"committed output repair control signature is invalid: "
            f"{path.name}"
        )
    return value


def _exact_repair_directory_is_safe(path: Path) -> bool:
    try:
        metadata = rooted_io.lstat(path)
    except OSError:
        return False
    attributes = int(
        getattr(metadata, "st_file_attributes", 0) or 0
    )
    return bool(
        stat.S_ISDIR(metadata.st_mode)
        and not stat.S_ISLNK(metadata.st_mode)
        and not attributes & 0x400
    )


def _exact_repair_snapshot(path: Path) -> dict[str, Any]:
    if not path.exists():
        if path.is_symlink():
            raise ArtifactLedgerError(
                f"committed output repair path is a dangling link: {path.name}"
            )
        return {"status": "MISSING", "path": path.name}
    try:
        raw = read_bounded_regular_bytes(
            path, _EXACT_REPAIR_ARTIFACT_LIMIT
        )
    except (OSError, ValueError) as exc:
        raise ArtifactLedgerError(
            f"committed output repair output is unsafe: "
            f"{path.name}: {type(exc).__name__}: {exc}"
        ) from exc
    return {
        "status": "PRESENT",
        "path": path.name,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "size_bytes": len(raw),
    }


def _validate_exact_repair_contract(
    contract: PhaseIOContract,
    launch: LaunchSpec,
) -> set[str]:
    if not isinstance(contract, PhaseIOContract):
        raise ArtifactLedgerError(
            "committed output repair contract must be PhaseIOContract"
        )
    if (
        not isinstance(launch, LaunchSpec)
        or launch.work_unit_key != contract.key
        or not launch.digest
        or contract.pipeline != "l1"
        or contract.phase != "semantic_dedup"
        or contract.work_unit_id != "prequeue_apply"
        or contract.model_invoked is not False
        or launch.model != "driver"
        or launch.exec_mode != "python"
    ):
        raise ArtifactLedgerError(
            "committed output repair is not the exact L1 prequeue contract"
        )
    expected = {
        f"scratchpad:{relative}"
        for relative in _EXACT_L1_SEMANTIC_REPAIR_OUTPUTS
    }
    identities = {spec.identity for spec in contract.outputs}
    if (
        identities != expected
        or any(
            spec.root != "scratchpad"
            or spec.writer != "DRIVER"
            or spec.owner_key != contract.key
            for spec in contract.outputs
        )
    ):
        raise ArtifactLedgerError(
            "committed output repair output denominator changed"
        )
    return expected


def _exact_repair_history(
    unit: Mapping[str, Any],
) -> list[dict[str, Any]]:
    history = unit.get("committed_output_repair_history", [])
    if (
        not isinstance(history, list)
        or len(history) > 8
        or any(not isinstance(row, Mapping) for row in history)
    ):
        raise ArtifactLedgerError(
            "committed output repair history is malformed or unbounded"
        )
    normalized: list[dict[str, Any]] = []
    pending_seen: set[str] = set()
    history_fields = {
        "schema_version",
        "state",
        "repair_pending_sha256",
        "arm_authority",
        "finalize_authority",
        "history_digest",
    }
    arm_fields = {
        "schema_version",
        "state",
        "run_id",
        "phase",
        "work_unit_key",
        "contract_digest",
        "launch_digest",
        "generation_digest",
        "intent_sha256",
        "authority_binding_sha256",
        "transaction_receipt_sha256",
        "repair_pending_sha256",
        "observed_outputs",
        "target_outputs",
        "output_identities",
        "predecessor_output_authority",
        "authority_digest",
    }
    finalize_fields = {
        "schema_version",
        "state",
        "run_id",
        "phase",
        "work_unit_key",
        "contract_digest",
        "launch_digest",
        "generation_digest",
        "transaction_receipt_sha256",
        "repair_pending_sha256",
        "repair_arm_authority_digest",
        "restored_outputs",
        "authority_digest",
    }
    for value in history:
        row = dict(value)
        unsigned = dict(row)
        digest = str(unsigned.pop("history_digest", "") or "")
        pending_digest = str(
            row.get("repair_pending_sha256") or ""
        )
        arm = row.get("arm_authority")
        finalize = row.get("finalize_authority")
        arm_unsigned = dict(arm) if isinstance(arm, Mapping) else {}
        arm_digest = str(
            arm_unsigned.pop("authority_digest", "") or ""
        )
        finalize_unsigned = (
            dict(finalize) if isinstance(finalize, Mapping) else {}
        )
        finalize_digest = str(
            finalize_unsigned.pop("authority_digest", "") or ""
        )
        predecessor = (
            arm.get("predecessor_output_authority")
            if isinstance(arm, Mapping)
            else None
        )
        predecessor_valid = False
        if isinstance(predecessor, Mapping):
            predecessor_key = str(
                predecessor.get("authority_key") or ""
            )
            try:
                _logical, validated_predecessor, _predecessor_unsigned = (
                    _validated_output_authority_envelope(
                        predecessor,
                        authority_key=predecessor_key,
                    )
                )
                predecessor_valid = bool(
                    validated_predecessor == dict(predecessor)
                )
            except ArtifactLedgerError:
                predecessor_valid = False
        if (
            set(row) != history_fields
            or row.get("schema_version") != _EXACT_REPAIR_HISTORY_SCHEMA
            or row.get("state") not in {"ARMED", "REPAIRED_ACTIVE"}
            or not re.fullmatch(r"[0-9a-f]{64}", pending_digest)
            or pending_digest in pending_seen
            or not isinstance(arm, Mapping)
            or set(arm) != arm_fields
            or arm.get("schema_version") != _EXACT_REPAIR_ARM_SCHEMA
            or arm.get("state") != "ARMED"
            or arm.get("repair_pending_sha256") != pending_digest
            or arm_digest != hashlib.sha256(
                _exact_repair_canonical(arm_unsigned)
            ).hexdigest()
            or not predecessor_valid
            or (
                row.get("state") == "ARMED"
                and finalize != {}
            )
            or (
                row.get("state") == "REPAIRED_ACTIVE"
                and not isinstance(finalize, Mapping)
            )
            or (
                row.get("state") == "REPAIRED_ACTIVE"
                and (
                    set(finalize) != finalize_fields
                    or finalize.get("schema_version")
                    != _EXACT_REPAIR_FINALIZE_SCHEMA
                    or finalize.get("state") != "REPAIRED_ACTIVE"
                    or finalize.get("repair_pending_sha256")
                    != pending_digest
                    or finalize.get("repair_arm_authority_digest")
                    != arm_digest
                    or finalize_digest != hashlib.sha256(
                        _exact_repair_canonical(finalize_unsigned)
                    ).hexdigest()
                )
            )
            or digest != hashlib.sha256(
                _exact_repair_canonical(unsigned)
            ).hexdigest()
        ):
            raise ArtifactLedgerError(
                "committed output repair history integrity failed"
            )
        pending_seen.add(pending_digest)
        normalized.append(row)
    return normalized


def _exact_repair_bound_root(unit: Mapping[str, Any]) -> Path:
    root_value = getattr(unit, "_artifact_ledger_root", None)
    if not isinstance(root_value, Path):
        raise ArtifactLedgerError(
            "committed output repair replay has no canonical ledger root"
        )
    root = Path(os.path.abspath(os.fspath(root_value)))
    if root != root_value or not _exact_repair_directory_is_safe(root):
        raise ArtifactLedgerError(
            "committed output repair ledger root is not canonical"
        )
    return root


def _exact_repair_directory_anchor(
    path: Path,
) -> tuple[
    tuple[tuple[str, tuple[int, ...]], ...],
    tuple[int, ...],
]:
    try:
        chain = _lexical_no_follow_chain(path)
        metadata = rooted_io.lstat(path)
    except (ArtifactLedgerError, OSError) as exc:
        raise ArtifactLedgerError(
            f"committed output repair directory is unreadable: {path.name}"
        ) from exc
    if not _exact_repair_directory_is_safe(path):
        raise ArtifactLedgerError(
            f"committed output repair directory is unsafe: {path.name}"
        )
    return chain, _metadata_object_identity(metadata)


def _exact_repair_file_identity(path: Path) -> tuple[int, ...]:
    try:
        metadata = rooted_io.lstat(path)
    except OSError as exc:
        raise ArtifactLedgerError(
            f"committed output repair private object disappeared: {path.name}"
        ) from exc
    if (
        _metadata_is_reparse(metadata)
        or not stat.S_ISREG(metadata.st_mode)
        or int(getattr(metadata, "st_nlink", 1) or 1) != 1
    ):
        raise ArtifactLedgerError(
            f"committed output repair private object is aliased: {path.name}"
        )
    return _metadata_object_identity(metadata)


def _exact_repair_source_anchor_key(
    unit: Mapping[str, Any],
) -> str:
    """Derive the one immutable repair-source slot from semantic authority."""

    commit = unit.get("commit_authority")
    if not isinstance(commit, Mapping):
        raise ArtifactLedgerError(
            "committed output repair source anchor has no commit receipt"
        )
    fields = {
        "schema": _EXACT_REPAIR_SOURCE_ANCHOR_SCHEMA,
        "run_id": unit.get("run_id"),
        "work_unit_key": unit.get("work_unit_key"),
        "contract_digest": unit.get("contract_digest"),
        "launch_digest": unit.get("launch_digest"),
        "commit_receipt_digest": commit.get("receipt_digest"),
        "commit_attempt_ordinal": commit.get("attempt_ordinal"),
        "output_authority_key": commit.get("output_authority_key"),
        "output_authority_digest": commit.get("output_authority_digest"),
    }
    if (
        not isinstance(fields["run_id"], str)
        or not fields["run_id"]
        or not isinstance(fields["work_unit_key"], str)
        or not fields["work_unit_key"]
        or any(
            not _is_digest(fields[name])
            for name in (
                "contract_digest",
                "launch_digest",
                "commit_receipt_digest",
                "output_authority_key",
                "output_authority_digest",
            )
        )
        or not _is_positive_exact_int(fields["commit_attempt_ordinal"])
    ):
        raise ArtifactLedgerError(
            "committed output repair source anchor key is invalid"
        )
    return _canonical_json_digest(fields)


def _exact_repair_payload_names(intent: Mapping[str, Any]) -> list[str]:
    """Collect every generation payload named by the committed intent."""

    names = {"a0.bin", "a1.bin", "b0.bin", "b1.bin"}

    def collect(value: object) -> None:
        if isinstance(value, Mapping):
            payload = value.get("payload")
            if payload is not None:
                names.add(str(payload))
            for nested in value.values():
                collect(nested)
        elif isinstance(value, list):
            for nested in value:
                collect(nested)

    collect(intent)
    if len(names) > _EXACT_REPAIR_SOURCE_ANCHOR_LIMIT:
        raise ArtifactLedgerError(
            "committed output repair source payload denominator is unbounded"
        )
    normalized: list[str] = []
    for name in sorted(names):
        relative = PurePosixPath(name)
        if (
            not name
            or name == "i.json"
            or relative.is_absolute()
            or relative.as_posix() != name
            or any(part in {"", ".", ".."} for part in relative.parts)
        ):
            raise ArtifactLedgerError(
                "committed output repair source payload path is unsafe"
            )
        normalized.append(name)
    return normalized


def _exact_repair_source_file_snapshot(
    path: Path,
    *,
    relative: str,
) -> dict[str, Any]:
    raw = _read_stable_regular_bytes(
        path,
        limit=_EXACT_REPAIR_ARTIFACT_LIMIT,
    )
    return {
        "path": relative,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "size": len(raw),
        "physical_identity": list(_exact_repair_file_identity(path)),
    }


def _exact_repair_source_physical_snapshot(
    root: Path,
    *,
    generation_digest: str,
    intent: Mapping[str, Any],
) -> dict[str, Any]:
    """Capture content and inode/file-ID evidence before public repair."""

    private = root / "_sdt"
    generation_root = private / f"g_{generation_digest}"
    private_anchor = _exact_repair_directory_anchor(private)
    generation_anchor = _exact_repair_directory_anchor(generation_root)
    intent_path = generation_root / "i.json"
    receipt_path = private / f"c_{generation_digest}.json"
    controls = {
        "intent": _exact_repair_source_file_snapshot(
            intent_path,
            relative="i.json",
        ),
        "transaction_receipt": _exact_repair_source_file_snapshot(
            receipt_path,
            relative=f"c_{generation_digest}.json",
        ),
    }
    payloads = {
        name: _exact_repair_source_file_snapshot(
            generation_root.joinpath(*PurePosixPath(name).parts),
            relative=name,
        )
        for name in _exact_repair_payload_names(intent)
    }
    identities = {
        tuple(row["physical_identity"])
        for row in [*controls.values(), *payloads.values()]
    }
    if len(identities) != len(controls) + len(payloads):
        raise ArtifactLedgerError(
            "committed output repair source files are physically aliased"
        )
    return {
        "private_directory_physical_identity": list(private_anchor[1]),
        "generation_directory_physical_identity": list(
            generation_anchor[1]
        ),
        "controls": controls,
        "payloads": payloads,
    }


def _exact_repair_source_anchor_unsigned(
    unit: Mapping[str, Any],
    arm: Mapping[str, Any],
) -> dict[str, Any]:
    root = _exact_repair_bound_root(unit)
    commit = unit.get("commit_authority")
    predecessor = arm.get("predecessor_output_authority")
    if not isinstance(commit, Mapping) or not isinstance(
        predecessor, Mapping
    ):
        raise ArtifactLedgerError(
            "committed output repair source authority is absent"
        )
    generation = str(arm.get("generation_digest") or "")
    if not _is_digest(generation):
        raise ArtifactLedgerError(
            "committed output repair source generation is invalid"
        )
    private = root / "_sdt"
    intent = _read_exact_repair_control(
        private / f"g_{generation}" / "i.json",
        schema=_EXACT_REPAIR_INTENT_SCHEMA,
        digest_key="intent_sha256",
    )
    receipt = _read_exact_repair_control(
        private / f"c_{generation}.json",
        schema=_EXACT_REPAIR_RECEIPT_SCHEMA,
        digest_key="receipt_sha256",
    )
    transaction_rows: dict[str, dict[str, Any]] = {}
    for name in (
        "phaseio_arm",
        "phaseio_commit",
        "mutation_arm",
        "mutation_finalize",
    ):
        row = receipt.get(name)
        if not isinstance(row, Mapping):
            raise ArtifactLedgerError(
                "committed output repair transaction authority is incomplete"
            )
        transaction_rows[name] = dict(row)
    source_key = _exact_repair_source_anchor_key(unit)
    return {
        "schema": _EXACT_REPAIR_SOURCE_ANCHOR_SCHEMA,
        "source_anchor_key": source_key,
        "state": "CAPTURED_BEFORE_PUBLIC_REPAIR",
        "run_id": unit.get("run_id"),
        "work_unit_key": unit.get("work_unit_key"),
        "contract_digest": unit.get("contract_digest"),
        "launch_digest": unit.get("launch_digest"),
        "commit_receipt_digest": commit.get("receipt_digest"),
        "commit_attempt_ordinal": commit.get("attempt_ordinal"),
        "output_authority_key": commit.get("output_authority_key"),
        "output_authority_digest": commit.get("output_authority_digest"),
        "predecessor_output_authority_digest": predecessor.get(
            "authority_digest"
        ),
        "repair_arm_authority_digest": arm.get("authority_digest"),
        "repair_pending_sha256": arm.get("repair_pending_sha256"),
        "generation_digest": generation,
        "intent_sha256": intent.get("intent_sha256"),
        "authority_binding_sha256": intent.get(
            "authority_binding_sha256"
        ),
        "transaction_receipt_sha256": receipt.get("receipt_sha256"),
        "transaction_authority": transaction_rows,
        "source_physical_snapshot": (
            _exact_repair_source_physical_snapshot(
                root,
                generation_digest=generation,
                intent=intent,
            )
        ),
        "physical_policy": _NO_FOLLOW_PHYSICAL_POLICY,
    }


def _exact_repair_source_anchor_records(
    root: Path,
) -> list[dict[str, Any]]:
    directory = root / _EXACT_REPAIR_SOURCE_ANCHOR_CAS_DIRECTORY
    if not rooted_io.lexists(directory):
        return []
    try:
        rooted_io.checked_directory(
            directory,
            label="committed output repair source-anchor CAS directory",
        )
        entries = sorted(directory.iterdir(), key=lambda path: path.name)
    except (OSError, rooted_io.RootedPathIOError) as exc:
        raise ArtifactLedgerError(
            "committed output repair source-anchor CAS is unreadable"
        ) from exc
    if len(entries) > _EXACT_REPAIR_SOURCE_ANCHOR_LIMIT:
        raise ArtifactLedgerError(
            "committed output repair source-anchor CAS is unbounded"
        )
    fields = {
        "schema",
        "source_anchor_key",
        "state",
        "run_id",
        "work_unit_key",
        "contract_digest",
        "launch_digest",
        "commit_receipt_digest",
        "commit_attempt_ordinal",
        "output_authority_key",
        "output_authority_digest",
        "predecessor_output_authority_digest",
        "repair_arm_authority_digest",
        "repair_pending_sha256",
        "generation_digest",
        "intent_sha256",
        "authority_binding_sha256",
        "transaction_receipt_sha256",
        "transaction_authority",
        "source_physical_snapshot",
        "physical_policy",
    }
    records: list[dict[str, Any]] = []
    seen_keys: set[str] = set()
    for entry in entries:
        match = re.fullmatch(r"([0-9a-f]{64})\.json", entry.name)
        if match is None:
            raise ArtifactLedgerError(
                "committed output repair source-anchor CAS has an "
                "unexpected entry"
            )
        digest = match.group(1)
        unsigned = _read_authority_cas(
            root,
            digest,
            directory_name=_EXACT_REPAIR_SOURCE_ANCHOR_CAS_DIRECTORY,
            label="committed output repair source anchor",
        )
        source_key = str(unsigned.get("source_anchor_key") or "")
        if (
            set(unsigned) != fields
            or unsigned.get("schema")
            != _EXACT_REPAIR_SOURCE_ANCHOR_SCHEMA
            or unsigned.get("state")
            != "CAPTURED_BEFORE_PUBLIC_REPAIR"
            or unsigned.get("physical_policy")
            != _NO_FOLLOW_PHYSICAL_POLICY
            or not _is_digest(source_key)
            or source_key in seen_keys
        ):
            raise ArtifactLedgerError(
                "committed output repair source-anchor CAS is malformed "
                "or ambiguous"
            )
        seen_keys.add(source_key)
        records.append({**unsigned, "authority_digest": digest})
    return records


def _issue_exact_repair_source_anchor(
    unit: Mapping[str, Any],
    arm: Mapping[str, Any],
) -> dict[str, Any]:
    """Capture the one pre-repair source in an append-only CAS slot."""

    root = _exact_repair_bound_root(unit)
    unsigned = _exact_repair_source_anchor_unsigned(unit, arm)
    source_key = str(unsigned["source_anchor_key"])
    existing = [
        row
        for row in _exact_repair_source_anchor_records(root)
        if row.get("source_anchor_key") == source_key
    ]
    if existing:
        if len(existing) != 1 or {
            key: value
            for key, value in existing[0].items()
            if key != "authority_digest"
        } != unsigned:
            raise ArtifactLedgerError(
                "committed output repair source anchor was already claimed"
            )
        return existing[0]
    digest = _canonical_json_digest(unsigned)
    _write_once_authority_cas(
        root,
        directory_name=_EXACT_REPAIR_SOURCE_ANCHOR_CAS_DIRECTORY,
        authority_digest=digest,
        unsigned_authority=unsigned,
        label="committed output repair source anchor",
    )
    replay = [
        row
        for row in _exact_repair_source_anchor_records(root)
        if row.get("source_anchor_key") == source_key
    ]
    if len(replay) != 1 or replay[0].get("authority_digest") != digest:
        raise ArtifactLedgerError(
            "committed output repair source anchor did not publish exactly"
        )
    return replay[0]


def _exact_repair_source_anchor_is_valid(
    unit: Mapping[str, Any],
    arm: Mapping[str, Any],
) -> bool:
    """Replay current private bytes only through the pre-repair CAS anchor."""

    try:
        root = _exact_repair_bound_root(unit)
        source_key = _exact_repair_source_anchor_key(unit)
        matching = [
            row
            for row in _exact_repair_source_anchor_records(root)
            if row.get("source_anchor_key") == source_key
        ]
        if len(matching) != 1:
            return False
        unsigned = _exact_repair_source_anchor_unsigned(unit, arm)
        recorded = {
            key: value
            for key, value in matching[0].items()
            if key != "authority_digest"
        }
        return recorded == unsigned
    except (ArtifactLedgerError, OSError, TypeError, ValueError):
        return False


def _exact_repair_private_lineage_is_valid(
    unit: Mapping[str, Any],
    arm: Mapping[str, Any],
    expected: Mapping[str, Mapping[str, Any]],
) -> bool:
    """Authenticate one repair arm against its immutable private generation.

    PRE/POST/history hashes prove internal consistency only.  Ordinary replay
    must also reopen the exact generation and committed receipt selected by
    those hashes, using the canonical root supplied by the ledger read.  All
    paths and files are bounded, stable, single-link, and no-follow; directory
    identities are rechecked after the composite read so an ancestor swap
    cannot splice evidence from different generations.
    """

    try:
        root = _exact_repair_bound_root(unit)
        if not _exact_repair_source_anchor_is_valid(unit, arm):
            return False
        generation_digest = str(arm.get("generation_digest") or "")
        if not _is_digest(generation_digest):
            return False
        private = root / "_sdt"
        generation_root = private / f"g_{generation_digest}"
        anchors = {
            path: _exact_repair_directory_anchor(path)
            for path in (root, private, generation_root)
        }

        intent_path = generation_root / "i.json"
        receipt_path = private / f"c_{generation_digest}.json"
        intent = _read_exact_repair_control(
            intent_path,
            schema=_EXACT_REPAIR_INTENT_SCHEMA,
            digest_key="intent_sha256",
        )
        receipt = _read_exact_repair_control(
            receipt_path,
            schema=_EXACT_REPAIR_RECEIPT_SCHEMA,
            digest_key="receipt_sha256",
        )
        physical_objects = {
            _exact_repair_file_identity(intent_path),
            _exact_repair_file_identity(receipt_path),
        }
        if len(physical_objects) != 2:
            return False

        intent_unsigned = dict(intent)
        intent_unsigned.pop("intent_sha256", None)
        recorded_generation = str(
            intent_unsigned.pop("generation_digest", "") or ""
        )
        authority_binding = intent.get("authority_binding")
        outputs = intent.get("outputs")
        target_outputs = arm.get("target_outputs")
        if (
            recorded_generation != generation_digest
            or generation_digest
            != hashlib.sha256(
                _exact_repair_canonical(intent_unsigned)
            ).hexdigest()
            or arm.get("intent_sha256") != intent.get("intent_sha256")
            or arm.get("authority_binding_sha256")
            != intent.get("authority_binding_sha256")
            or not isinstance(authority_binding, Mapping)
            or intent.get("authority_binding_sha256")
            != hashlib.sha256(
                _exact_repair_canonical(authority_binding)
            ).hexdigest()
            or intent.get("run_id") != unit.get("run_id")
            or intent.get("phase") != "semantic_dedup"
            or intent.get("transaction_kind")
            != "L1_SEMANTIC_DEDUP_CANONICAL_PAIR"
            or intent.get("publication_order")
            != list(_EXACT_L1_SEMANTIC_REPAIR_OUTPUTS)
            or not isinstance(outputs, Mapping)
            or set(outputs) != set(_EXACT_L1_SEMANTIC_REPAIR_OUTPUTS)
            or not isinstance(target_outputs, Mapping)
            or set(target_outputs)
            != set(_EXACT_L1_SEMANTIC_REPAIR_OUTPUTS)
        ):
            return False

        input_bindings = unit.get("input_bindings")
        binding_inputs = authority_binding.get("input_authority")
        if (
            authority_binding.get("schema_version")
            != "plamen.semantic_dedup_phaseio_binding.v1"
            or authority_binding.get("run_id") != unit.get("run_id")
            or authority_binding.get("phase") != "semantic_dedup"
            or authority_binding.get("work_unit_key")
            != unit.get("work_unit_key")
            or authority_binding.get("contract_digest")
            != unit.get("contract_digest")
            or authority_binding.get("launch_digest")
            != unit.get("launch_digest")
            or authority_binding.get("input_set_digest")
            != unit.get("input_set_digest")
            or authority_binding.get("output_prestate_digest")
            != unit.get("output_prestate_digest")
            or not isinstance(input_bindings, Mapping)
            or not isinstance(binding_inputs, Mapping)
            or set(binding_inputs) != set(input_bindings)
        ):
            return False
        for identity, bound in binding_inputs.items():
            source = input_bindings.get(identity)
            if (
                not isinstance(bound, Mapping)
                or not isinstance(source, Mapping)
                or any(source.get(key) != value for key, value in bound.items())
            ):
                return False

        commit = unit.get("commit_authority")
        receipt_outputs = receipt.get("outputs")
        phaseio_arm = receipt.get("phaseio_arm")
        phaseio_commit = receipt.get("phaseio_commit")
        phaseio_arm_evidence = (
            phaseio_arm.get("evidence")
            if isinstance(phaseio_arm, Mapping)
            else None
        )
        phaseio_commit_evidence = (
            phaseio_commit.get("evidence")
            if isinstance(phaseio_commit, Mapping)
            else None
        )
        if (
            not isinstance(commit, Mapping)
            or receipt.get("receipt_sha256")
            != arm.get("transaction_receipt_sha256")
            or receipt.get("state") != "COMMITTED"
            or receipt.get("safe_to_consume") is not True
            or receipt.get("run_id") != unit.get("run_id")
            or receipt.get("phase") != "semantic_dedup"
            or receipt.get("generation_digest") != generation_digest
            or receipt.get("intent_sha256") != intent.get("intent_sha256")
            or receipt.get("authority_binding_sha256")
            != intent.get("authority_binding_sha256")
            or receipt.get("before") != intent.get("before")
            or receipt.get("after") != intent.get("after")
            or receipt_outputs != outputs
            or receipt.get("staged_sidecars")
            != intent.get("staged_sidecars")
            or not isinstance(phaseio_arm, Mapping)
            or phaseio_arm.get("status") != "ARMED"
            or phaseio_arm.get("generation_digest") != generation_digest
            or phaseio_arm.get("run_id") != unit.get("run_id")
            or phaseio_arm.get("phase") != "semantic_dedup"
            or phaseio_arm.get("authority_id")
            != unit.get("work_unit_key")
            or not isinstance(phaseio_arm_evidence, Mapping)
            or phaseio_arm_evidence.get("contract_digest")
            != unit.get("contract_digest")
            or phaseio_arm_evidence.get("input_set_digest")
            != unit.get("input_set_digest")
            or phaseio_arm_evidence.get("launch_digest")
            != unit.get("launch_digest")
            or phaseio_arm_evidence.get("output_prestate_digest")
            != unit.get("output_prestate_digest")
            or not isinstance(phaseio_commit, Mapping)
            or phaseio_commit.get("status") != "COMMITTED"
            or phaseio_commit.get("generation_digest") != generation_digest
            or phaseio_commit.get("run_id") != unit.get("run_id")
            or phaseio_commit.get("phase") != "semantic_dedup"
            or phaseio_commit.get("authority_id")
            != unit.get("work_unit_key")
            or not isinstance(phaseio_commit_evidence, Mapping)
            or phaseio_commit_evidence.get("commit_receipt_digest")
            != commit.get("receipt_digest")
            or phaseio_commit_evidence.get("contract_digest")
            != unit.get("contract_digest")
            or phaseio_commit_evidence.get("expected_output_records")
            != dict(sorted(expected.items()))
        ):
            return False

        for relative in _EXACT_L1_SEMANTIC_REPAIR_OUTPUTS:
            identity = f"scratchpad:{relative}"
            expected_row = expected.get(identity)
            output = outputs.get(relative)
            after = (
                output.get("after")
                if isinstance(output, Mapping)
                else None
            )
            target = target_outputs.get(relative)
            if (
                not isinstance(expected_row, Mapping)
                or not isinstance(after, Mapping)
                or after.get("status") != "PRESENT"
                or not isinstance(target, Mapping)
                or target
                != {
                    "path": relative,
                    "payload": after.get("payload"),
                    "sha256": after.get("sha256"),
                    "size_bytes": after.get("size_bytes"),
                }
                or after.get("sha256") != expected_row.get("sha256")
                or after.get("size_bytes") != expected_row.get("size")
                or not _is_nonnegative_exact_int(after.get("size_bytes"))
                or int(after.get("size_bytes"))
                > _EXACT_REPAIR_ARTIFACT_LIMIT
            ):
                return False
            payload_name = str(after.get("payload") or "")
            payload_relative = PurePosixPath(payload_name)
            if (
                not payload_name
                or payload_relative.is_absolute()
                or payload_relative.as_posix() != payload_name
                or any(
                    part in {"", ".", ".."}
                    for part in payload_relative.parts
                )
            ):
                return False
            payload_path = generation_root.joinpath(*payload_relative.parts)
            raw = _read_stable_regular_bytes(
                payload_path,
                limit=_EXACT_REPAIR_ARTIFACT_LIMIT,
            )
            physical_identity = _exact_repair_file_identity(payload_path)
            if (
                physical_identity in physical_objects
                or hashlib.sha256(raw).hexdigest() != after.get("sha256")
                or len(raw) != after.get("size_bytes")
            ):
                return False
            physical_objects.add(physical_identity)

        for path, before_anchor in anchors.items():
            if _exact_repair_directory_anchor(path) != before_anchor:
                return False
        return True
    except (ArtifactLedgerError, OSError, TypeError, ValueError):
        return False


def _pure_exact_repair_output_projection(
    unit: Mapping[str, Any],
    commit: Mapping[str, Any],
    artifacts: Mapping[str, Any],
    expected: Mapping[str, Mapping[str, Any]],
) -> tuple[bool, dict[str, dict[str, Any]] | None]:
    """Replay a finalized physical rebind without changing semantic commit ID."""

    try:
        history = _exact_repair_history(unit)
    except ArtifactLedgerError:
        return False, None
    finalized = [
        row for row in history
        if row.get("state") == "REPAIRED_ACTIVE"
    ]
    if not finalized:
        return True, None

    identities = set(artifacts)
    relatives: dict[str, str] = {}
    for identity in identities:
        if not isinstance(identity, str) or not identity.startswith(
            "scratchpad:"
        ):
            return False, None
        relative = identity.split(":", 1)[1]
        if not relative:
            return False, None
        relatives[identity] = relative
    relative_set = set(relatives.values())
    predecessor: dict[str, Any] | None = None
    latest_finalize: Mapping[str, Any] | None = None
    for row in finalized:
        arm = row["arm_authority"]
        finalize = row["finalize_authority"]
        candidate = arm["predecessor_output_authority"]
        candidate_key = str(candidate.get("authority_key") or "")
        try:
            _logical, validated_candidate, _unsigned = (
                _validated_output_authority_envelope(
                    candidate,
                    authority_key=candidate_key,
                )
            )
        except ArtifactLedgerError:
            return False, None
        if (
            validated_candidate != dict(candidate)
            or candidate.get("authority_key")
            != commit.get("output_authority_key")
            or candidate.get("authority_digest")
            != commit.get("output_authority_digest")
            or candidate.get("expected_output_records")
            != dict(sorted(expected.items()))
            or arm.get("run_id") != unit.get("run_id")
            or arm.get("phase") != "semantic_dedup"
            or arm.get("work_unit_key") != unit.get("work_unit_key")
            or arm.get("contract_digest") != unit.get("contract_digest")
            or arm.get("launch_digest") != unit.get("launch_digest")
            or arm.get("output_identities") != sorted(identities)
            or not _is_digest(arm.get("generation_digest"))
            or not _is_digest(arm.get("intent_sha256"))
            or not _is_digest(arm.get("authority_binding_sha256"))
            or not _is_digest(arm.get("transaction_receipt_sha256"))
            or not _is_digest(arm.get("repair_pending_sha256"))
            or finalize.get("run_id") != arm.get("run_id")
            or finalize.get("phase") != arm.get("phase")
            or finalize.get("work_unit_key")
            != arm.get("work_unit_key")
            or finalize.get("contract_digest")
            != arm.get("contract_digest")
            or finalize.get("launch_digest")
            != arm.get("launch_digest")
            or finalize.get("generation_digest")
            != arm.get("generation_digest")
            or finalize.get("transaction_receipt_sha256")
            != arm.get("transaction_receipt_sha256")
            or finalize.get("repair_pending_sha256")
            != arm.get("repair_pending_sha256")
            or not _exact_repair_private_lineage_is_valid(
                unit,
                arm,
                expected,
            )
        ):
            return False, None
        if predecessor is None:
            predecessor = dict(candidate)
        elif predecessor != dict(candidate):
            return False, None

        observed = arm.get("observed_outputs")
        targets = arm.get("target_outputs")
        restored = finalize.get("restored_outputs")
        if (
            not isinstance(observed, Mapping)
            or set(observed) != relative_set
            or not isinstance(targets, Mapping)
            or set(targets) != relative_set
            or not isinstance(restored, Mapping)
            or set(restored) != identities
        ):
            return False, None
        for identity, relative in relatives.items():
            expected_row = expected.get(identity)
            observed_row = observed.get(relative)
            target_row = targets.get(relative)
            restored_row = restored.get(identity)
            if (
                not isinstance(expected_row, Mapping)
                or not isinstance(observed_row, Mapping)
                or observed_row.get("path") != relative
                or observed_row.get("status") not in {"MISSING", "PRESENT"}
                or (
                    observed_row.get("status") == "MISSING"
                    and set(observed_row) != {"path", "status"}
                )
                or (
                    observed_row.get("status") == "PRESENT"
                    and (
                        set(observed_row)
                        != {"path", "status", "sha256", "size_bytes"}
                        or not _is_digest(observed_row.get("sha256"))
                        or not _is_nonnegative_exact_int(
                            observed_row.get("size_bytes")
                        )
                    )
                )
                or not isinstance(target_row, Mapping)
                or set(target_row)
                != {"path", "payload", "sha256", "size_bytes"}
                or target_row.get("path") != relative
                or not isinstance(target_row.get("payload"), str)
                or not target_row.get("payload")
                or target_row.get("sha256")
                != expected_row.get("sha256")
                or target_row.get("size_bytes")
                != expected_row.get("size")
                or not isinstance(restored_row, Mapping)
                or set(restored_row)
                != {"sha256", "size", "physical_identity"}
                or restored_row.get("sha256")
                != expected_row.get("sha256")
                or restored_row.get("size") != expected_row.get("size")
                or not isinstance(
                    restored_row.get("physical_identity"), str
                )
                or not restored_row.get("physical_identity")
            ):
                return False, None
        latest_finalize = finalize

    if predecessor is None or latest_finalize is None:
        return False, None
    latest_digest = str(latest_finalize.get("authority_digest") or "")
    latest_restored = latest_finalize["restored_outputs"]
    for identity in identities:
        record = artifacts.get(identity)
        restored_row = latest_restored[identity]
        if (
            not isinstance(record, Mapping)
            or record.get("status") != "ACTIVE"
            or record.get("sha256") != restored_row.get("sha256")
            or record.get("size") != restored_row.get("size")
            or record.get("physical_identity")
            != restored_row.get("physical_identity")
            or record.get("repair_authority_digest") != latest_digest
        ):
            return False, None
    predecessor_observations = predecessor.get("observed_outputs")
    if not _observed_output_records_are_exact(
        predecessor_observations,
        expected_identities=identities,
    ):
        return False, None
    return True, {
        str(identity): dict(record)
        for identity, record in predecessor_observations.items()
    }


def _exact_repair_bundle(
    *,
    root: Path,
    project: Path,
    contract: PhaseIOContract,
    unit: Mapping[str, Any],
    ledger: Mapping[str, Any],
    run_id: str,
    generation_digest: str,
    transaction_receipt_sha256: str,
    repair_pending_sha256: str,
    prior: Mapping[str, Any] | None,
) -> dict[str, Any]:
    """Read and cross-bind every durable authority used by a repair."""

    private = root / "_sdt"
    generation_root = private / f"g_{generation_digest}"
    if (
        not _exact_repair_directory_is_safe(private)
        or not _exact_repair_directory_is_safe(generation_root)
    ):
        raise ArtifactLedgerError(
            "committed output repair private generation is unsafe"
        )
    intent = _read_exact_repair_control(
        generation_root / "i.json",
        schema=_EXACT_REPAIR_INTENT_SCHEMA,
        digest_key="intent_sha256",
    )
    intent_unsigned = dict(intent)
    intent_unsigned.pop("intent_sha256", None)
    recorded_generation = str(
        intent_unsigned.pop("generation_digest", "") or ""
    )
    if (
        recorded_generation != generation_digest
        or generation_digest != hashlib.sha256(
            _exact_repair_canonical(intent_unsigned)
        ).hexdigest()
        or intent.get("run_id") != run_id
        or intent.get("phase") != "semantic_dedup"
        or intent.get("transaction_kind")
        != "L1_SEMANTIC_DEDUP_CANONICAL_PAIR"
        or intent.get("authority_binding_sha256")
        != hashlib.sha256(
            _exact_repair_canonical(intent.get("authority_binding"))
        ).hexdigest()
        or intent.get("publication_order")
        != list(_EXACT_L1_SEMANTIC_REPAIR_OUTPUTS)
        or set(intent.get("outputs") or {})
        != set(_EXACT_L1_SEMANTIC_REPAIR_OUTPUTS)
    ):
        raise ArtifactLedgerError(
            "committed output repair generation intent changed"
        )
    receipt = _read_exact_repair_control(
        private / f"c_{generation_digest}.json",
        schema=_EXACT_REPAIR_RECEIPT_SCHEMA,
        digest_key="receipt_sha256",
    )
    if (
        receipt.get("receipt_sha256")
        != transaction_receipt_sha256
        or receipt.get("state") != "COMMITTED"
        or receipt.get("safe_to_consume") is not True
        or receipt.get("run_id") != run_id
        or receipt.get("phase") != "semantic_dedup"
        or receipt.get("generation_digest") != generation_digest
        or receipt.get("intent_sha256")
        != intent.get("intent_sha256")
        or receipt.get("authority_binding_sha256")
        != intent.get("authority_binding_sha256")
        or receipt.get("before") != intent.get("before")
        or receipt.get("after") != intent.get("after")
        or receipt.get("outputs") != intent.get("outputs")
        or receipt.get("staged_sidecars")
        != intent.get("staged_sidecars")
    ):
        raise ArtifactLedgerError(
            "committed output repair transaction receipt changed"
        )

    pending_path = private / "repair_pending.json"
    if pending_path.exists() or pending_path.is_symlink():
        pending = _read_exact_repair_control(
            pending_path,
            schema=_EXACT_REPAIR_PENDING_SCHEMA,
            digest_key="repair_pending_sha256",
        )
    elif prior is not None:
        arm = prior.get("arm_authority")
        if not isinstance(arm, Mapping):
            raise ArtifactLedgerError(
                "committed output repair replay arm is absent"
            )
        pending = {
            "schema_version": _EXACT_REPAIR_PENDING_SCHEMA,
            "state": "ARMED",
            "run_id": arm.get("run_id"),
            "phase": arm.get("phase"),
            "generation_digest": arm.get("generation_digest"),
            "intent_sha256": arm.get("intent_sha256"),
            "authority_binding_sha256": arm.get(
                "authority_binding_sha256"
            ),
            "transaction_receipt_sha256": arm.get(
                "transaction_receipt_sha256"
            ),
            "observed_outputs": arm.get("observed_outputs"),
            "target_outputs": arm.get("target_outputs"),
            "repair_pending_sha256": arm.get(
                "repair_pending_sha256"
            ),
        }
    else:
        raise ArtifactLedgerError(
            "committed output repair pending authority is absent"
        )
    observed = pending.get("observed_outputs")
    targets = pending.get("target_outputs")
    if (
        pending.get("repair_pending_sha256")
        != repair_pending_sha256
        or pending.get("state") != "ARMED"
        or pending.get("run_id") != run_id
        or pending.get("phase") != "semantic_dedup"
        or pending.get("generation_digest") != generation_digest
        or pending.get("intent_sha256") != intent.get("intent_sha256")
        or pending.get("authority_binding_sha256")
        != intent.get("authority_binding_sha256")
        or pending.get("transaction_receipt_sha256")
        != transaction_receipt_sha256
        or not isinstance(observed, Mapping)
        or set(observed) != set(_EXACT_L1_SEMANTIC_REPAIR_OUTPUTS)
        or not isinstance(targets, Mapping)
        or set(targets) != set(_EXACT_L1_SEMANTIC_REPAIR_OUTPUTS)
    ):
        raise ArtifactLedgerError(
            "committed output repair pending binding changed"
        )

    records = unit.get("artifacts")
    commit = unit.get("commit_authority")
    expected_records = (
        commit.get("expected_output_records")
        if isinstance(commit, Mapping)
        else None
    )
    expected_identities = {
        f"scratchpad:{relative}"
        for relative in _EXACT_L1_SEMANTIC_REPAIR_OUTPUTS
    }
    artifact_bindings = ledger.get("artifact_bindings")
    legacy_records = ledger.get("artifacts")
    selected_bindings = {
        identity: artifact_bindings.get(identity)
        for identity in expected_identities
    } if isinstance(artifact_bindings, Mapping) else None
    selected_legacy = {
        _legacy_name(identity): legacy_records.get(_legacy_name(identity))
        for identity in expected_identities
    } if isinstance(legacy_records, Mapping) else None
    if (
        not _nested_output_records_have_exact_sizes(
            records,
            expected_identities=expected_identities,
        )
        or not _nested_output_records_have_exact_sizes(
            expected_records,
            expected_identities=expected_identities,
        )
        or not _nested_output_records_have_exact_sizes(
            selected_bindings,
            expected_identities=expected_identities,
        )
        or not _nested_output_records_have_exact_sizes(
            selected_legacy,
            expected_identities={
                _legacy_name(identity)
                for identity in expected_identities
            },
        )
    ):
        raise ArtifactLedgerError(
            "committed output repair target denominator is invalid"
        )

    live: dict[str, dict[str, Any]] = {}
    normalized_observed: dict[str, dict[str, Any]] = {}
    normalized_targets: dict[str, dict[str, Any]] = {}
    for relative in _EXACT_L1_SEMANTIC_REPAIR_OUTPUTS:
        identity = f"scratchpad:{relative}"
        observation = observed.get(relative)
        target = targets.get(relative)
        intent_after = (
            intent.get("outputs", {})
            .get(relative, {})
            .get("after", {})
        )
        record = records.get(identity)
        expected = expected_records.get(identity)
        binding = selected_bindings.get(identity)
        legacy = selected_legacy.get(_legacy_name(identity))
        if (
            not isinstance(observation, Mapping)
            or observation.get("path") != relative
            or observation.get("status") not in {"MISSING", "PRESENT"}
            or not isinstance(target, Mapping)
            or target.get("path") != relative
            or intent_after.get("status") != "PRESENT"
            or target.get("payload") != intent_after.get("payload")
            or target.get("sha256") != intent_after.get("sha256")
            or target.get("size_bytes")
            != intent_after.get("size_bytes")
            or not isinstance(record, Mapping)
            or not isinstance(expected, Mapping)
            or record.get("owner_key") != contract.key
            or record.get("run_id") != run_id
            or record.get("status") != "ACTIVE"
            or record.get("sha256") != target.get("sha256")
            or record.get("size") != target.get("size_bytes")
            or record.get("sha256") != expected.get("sha256")
            or record.get("size") != expected.get("size")
            or not isinstance(binding, Mapping)
            or binding.get("owner_key") != contract.key
            or binding.get("sha256") != record.get("sha256")
            or binding.get("size") != record.get("size")
            or not isinstance(legacy, Mapping)
            or legacy.get("owner_key") != contract.key
            or legacy.get("sha256") != record.get("sha256")
            or legacy.get("size") != record.get("size")
        ):
            raise ArtifactLedgerError(
                f"{identity}: committed output repair lineage is invalid"
            )
        if observation.get("status") == "MISSING":
            if set(observation) != {"path", "status"}:
                raise ArtifactLedgerError(
                    f"{identity}: missing observation is malformed"
                )
        elif (
            set(observation)
            != {"path", "status", "sha256", "size_bytes"}
            or not re.fullmatch(
                r"[0-9a-f]{64}",
                str(observation.get("sha256") or ""),
            )
            or isinstance(observation.get("size_bytes"), bool)
            or not isinstance(observation.get("size_bytes"), int)
            or int(observation.get("size_bytes")) < 0
            or int(observation.get("size_bytes"))
            > _EXACT_REPAIR_ARTIFACT_LIMIT
        ):
            raise ArtifactLedgerError(
                f"{identity}: present observation is malformed"
            )
        payload_name = str(target.get("payload") or "")
        payload_relative = PurePosixPath(payload_name)
        if (
            not payload_name
            or payload_relative.is_absolute()
            or any(
                part in {"", ".", ".."}
                for part in payload_relative.parts
            )
            or payload_relative.as_posix() != payload_name
        ):
            raise ArtifactLedgerError(
                f"{identity}: private repair target path is invalid"
            )
        payload = generation_root.joinpath(*payload_relative.parts)
        parent = payload.parent
        while parent != generation_root:
            if not _exact_repair_directory_is_safe(parent):
                raise ArtifactLedgerError(
                    f"{identity}: private repair target parent is unsafe"
                )
            parent = parent.parent
        try:
            payload_raw = read_bounded_regular_bytes(
                payload, _EXACT_REPAIR_ARTIFACT_LIMIT
            )
        except (OSError, ValueError) as exc:
            raise ArtifactLedgerError(
                f"{identity}: private repair target is unsafe: {exc}"
            ) from exc
        if (
            hashlib.sha256(payload_raw).hexdigest()
            != target.get("sha256")
            or len(payload_raw) != target.get("size_bytes")
        ):
            raise ArtifactLedgerError(
                f"{identity}: private repair target digest changed"
            )
        current = _exact_repair_snapshot(
            _path_for_identity(root, project, identity)
        )
        normalized_observed[relative] = dict(observation)
        normalized_targets[relative] = dict(target)
        live[relative] = current

    return {
        "intent": intent,
        "receipt": receipt,
        "observed_outputs": normalized_observed,
        "target_outputs": normalized_targets,
        "live_outputs": live,
    }


def _exact_repair_state_matches(
    current: Mapping[str, Any],
    expected: Mapping[str, Any],
) -> bool:
    return dict(current) == dict(expected)


def _exact_repair_target_state(
    target: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "path": str(target["path"]),
        "status": "PRESENT",
        "sha256": str(target["sha256"]),
        "size_bytes": int(target["size_bytes"]),
    }


def _exact_repair_history_row(
    *,
    state: str,
    pending_digest: str,
    arm: Mapping[str, Any],
    finalize: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    unsigned = {
        "schema_version": _EXACT_REPAIR_HISTORY_SCHEMA,
        "state": state,
        "repair_pending_sha256": pending_digest,
        "arm_authority": dict(arm),
        "finalize_authority": (
            dict(finalize) if finalize is not None else {}
        ),
    }
    return {
        **unsigned,
        "history_digest": hashlib.sha256(
            _exact_repair_canonical(unsigned)
        ).hexdigest(),
    }


def _exact_repair_predecessor_output_authority(
    root: Path,
    unit: Mapping[str, Any],
) -> dict[str, Any]:
    """Freeze the exact issued authority whose physical objects are repaired."""

    commit = unit.get("commit_authority")
    if not isinstance(commit, Mapping):
        raise ArtifactLedgerError(
            "committed output repair predecessor receipt is absent"
        )
    key = str(commit.get("output_authority_key") or "")
    digest = str(commit.get("output_authority_digest") or "")
    if not _is_digest(key) or not _is_digest(digest):
        raise ArtifactLedgerError(
            "committed output repair predecessor binding is invalid"
        )
    journal = _reconcile_output_authority_history(root)
    raw = journal["authorities"].get(key)
    cas_unsigned = _read_output_authority_cas(root, digest)
    if not isinstance(raw, Mapping):
        raise ArtifactLedgerError(
            "committed output repair predecessor journal row is absent"
        )
    _logical, authority, unsigned = _validated_output_authority_envelope(
        raw,
        authority_key=key,
    )
    if (
        authority.get("authority_digest") != digest
        or unsigned != cas_unsigned
        or authority
        != {**cas_unsigned, "authority_digest": digest}
    ):
        raise ArtifactLedgerError(
            "committed output repair predecessor authority changed"
        )
    return authority


def arm_exact_committed_output_repair(
    scratchpad: Path,
    project_root: Path,
    contract: PhaseIOContract,
    launch: LaunchSpec,
    *,
    run_id: str,
    generation_digest: str,
    transaction_receipt_sha256: str,
    repair_pending_sha256: str,
) -> dict[str, Any]:
    """Durably arm exact restoration before the first public-root write."""

    contract, launch = _replay_authority_pair(contract, launch)
    expected_identities = _validate_exact_repair_contract(contract, launch)
    run = str(run_id or "").strip()
    generation = str(generation_digest or "").strip()
    transaction_receipt = str(transaction_receipt_sha256 or "").strip()
    pending_digest = str(repair_pending_sha256 or "").strip()
    if (
        not run
        or not re.fullmatch(r"[0-9a-f]{64}", generation)
        or not re.fullmatch(r"[0-9a-f]{64}", transaction_receipt)
        or not re.fullmatch(r"[0-9a-f]{64}", pending_digest)
    ):
        raise ArtifactLedgerError(
            "committed output repair arm binding is invalid"
        )

    with _ledger_transaction_lock(scratchpad):
        root = Path(scratchpad)
        project = Path(project_root)
        ledger = read_artifact_ledger(root)
        unit = ledger.get("work_units", {}).get(contract.key)
        if (
            not isinstance(unit, dict)
            or unit.get("contract_digest") != contract.digest
            or not _stored_launch_matches(unit, launch)
            or not _active_commit_receipt_is_valid(
                unit, work_unit_key=contract.key, run_id=run
            )
        ):
            raise ArtifactLedgerError(
                "committed output repair predecessor authority is invalid"
            )
        history = _exact_repair_history(unit)
        matches = [
            (index, row)
            for index, row in enumerate(history)
            if row.get("repair_pending_sha256") == pending_digest
        ]
        if len(matches) > 1:
            raise ArtifactLedgerError(
                "committed output repair arm is ambiguous"
            )
        prior = matches[0][1] if matches else None
        bundle = _exact_repair_bundle(
            root=root,
            project=project,
            contract=contract,
            unit=unit,
            ledger=ledger,
            run_id=run,
            generation_digest=generation,
            transaction_receipt_sha256=transaction_receipt,
            repair_pending_sha256=pending_digest,
            prior=prior,
        )
        observed = bundle["observed_outputs"]
        targets = bundle["target_outputs"]
        live = bundle["live_outputs"]
        predecessor_output_authority = (
            _exact_repair_predecessor_output_authority(root, unit)
        )
        for relative in _EXACT_L1_SEMANTIC_REPAIR_OUTPUTS:
            current = live[relative]
            original = observed[relative]
            target_state = _exact_repair_target_state(targets[relative])
            if prior is None:
                valid = _exact_repair_state_matches(current, original)
            else:
                valid = (
                    _exact_repair_state_matches(current, original)
                    or _exact_repair_state_matches(
                        current, target_state
                    )
                )
            if not valid:
                raise ArtifactLedgerError(
                    f"scratchpad:{relative}: repair arm observed an "
                    "unauthorized third state"
                )
        unsigned = {
            "schema_version": _EXACT_REPAIR_ARM_SCHEMA,
            "state": "ARMED",
            "run_id": run,
            "phase": contract.phase,
            "work_unit_key": contract.key,
            "contract_digest": contract.digest,
            "launch_digest": launch.digest,
            "generation_digest": generation,
            "intent_sha256": bundle["intent"]["intent_sha256"],
            "authority_binding_sha256": bundle["intent"][
                "authority_binding_sha256"
            ],
            "transaction_receipt_sha256": transaction_receipt,
            "repair_pending_sha256": pending_digest,
            "observed_outputs": {
                relative: dict(observed[relative])
                for relative in _EXACT_L1_SEMANTIC_REPAIR_OUTPUTS
            },
            "target_outputs": {
                relative: dict(targets[relative])
                for relative in _EXACT_L1_SEMANTIC_REPAIR_OUTPUTS
            },
            "output_identities": sorted(expected_identities),
            "predecessor_output_authority": (
                predecessor_output_authority
            ),
        }
        authority = _exact_repair_signed(unsigned)
        _issue_exact_repair_source_anchor(unit, authority)
        if prior is not None:
            if prior.get("arm_authority") != authority:
                raise ArtifactLedgerError(
                    "committed output repair arm replay changed"
                )
            return authority
        if len(history) >= 8:
            raise ArtifactLedgerError(
                "committed output repair history is exhausted"
            )
        history.append(
            _exact_repair_history_row(
                state="ARMED",
                pending_digest=pending_digest,
                arm=authority,
            )
        )
        unit["committed_output_repair_history"] = history
        ledger["work_units"][contract.key] = unit
        write_artifact_ledger(root, ledger)
        return authority


def authorize_exact_committed_output_repair(
    scratchpad: Path,
    project_root: Path,
    contract: PhaseIOContract,
    launch: LaunchSpec,
    *,
    run_id: str,
    generation_digest: str,
    transaction_receipt_sha256: str,
    repair_pending_sha256: str,
) -> dict[str, Any]:
    """Finalize an already-armed exact restoration and refresh lineage."""

    contract, launch = _replay_authority_pair(contract, launch)
    _validate_exact_repair_contract(contract, launch)
    run = str(run_id or "").strip()
    generation = str(generation_digest or "").strip()
    transaction_receipt = str(transaction_receipt_sha256 or "").strip()
    pending_digest = str(repair_pending_sha256 or "").strip()
    if (
        not run
        or not re.fullmatch(r"[0-9a-f]{64}", generation)
        or not re.fullmatch(r"[0-9a-f]{64}", transaction_receipt)
        or not re.fullmatch(r"[0-9a-f]{64}", pending_digest)
    ):
        raise ArtifactLedgerError(
            "committed output repair finalize binding is invalid"
        )
    with _ledger_transaction_lock(scratchpad):
        root = Path(scratchpad)
        project = Path(project_root)
        ledger = read_artifact_ledger(root)
        unit = ledger.get("work_units", {}).get(contract.key)
        if (
            not isinstance(unit, dict)
            or unit.get("contract_digest") != contract.digest
            or not _stored_launch_matches(unit, launch)
            or not _active_commit_receipt_is_valid(
                unit, work_unit_key=contract.key, run_id=run
            )
        ):
            raise ArtifactLedgerError(
                "committed output repair finalize predecessor is invalid"
            )
        history = _exact_repair_history(unit)
        matches = [
            (index, row)
            for index, row in enumerate(history)
            if row.get("repair_pending_sha256") == pending_digest
        ]
        if len(matches) != 1:
            raise ArtifactLedgerError(
                "committed output repair finalize has no unique PRE arm"
            )
        index, prior = matches[0]
        bundle = _exact_repair_bundle(
            root=root,
            project=project,
            contract=contract,
            unit=unit,
            ledger=ledger,
            run_id=run,
            generation_digest=generation,
            transaction_receipt_sha256=transaction_receipt,
            repair_pending_sha256=pending_digest,
            prior=prior,
        )
        arm = prior.get("arm_authority")
        if not isinstance(arm, Mapping):
            raise ArtifactLedgerError(
                "committed output repair finalize arm is malformed"
            )
        restored: dict[str, dict[str, Any]] = {}
        for relative in _EXACT_L1_SEMANTIC_REPAIR_OUTPUTS:
            identity = f"scratchpad:{relative}"
            target_state = _exact_repair_target_state(
                bundle["target_outputs"][relative]
            )
            current = bundle["live_outputs"][relative]
            if not _exact_repair_state_matches(current, target_state):
                raise ArtifactLedgerError(
                    f"{identity}: finalize bytes differ from committed target"
                )
            restored[identity] = {
                "sha256": str(current["sha256"]),
                "size": int(current["size_bytes"]),
                "physical_identity": _physical_file_identity(
                    _path_for_identity(root, project, identity)
                ),
            }
        unsigned = {
            "schema_version": _EXACT_REPAIR_FINALIZE_SCHEMA,
            "state": "REPAIRED_ACTIVE",
            "run_id": run,
            "phase": contract.phase,
            "work_unit_key": contract.key,
            "contract_digest": contract.digest,
            "launch_digest": launch.digest,
            "generation_digest": generation,
            "transaction_receipt_sha256": transaction_receipt,
            "repair_pending_sha256": pending_digest,
            "repair_arm_authority_digest": arm.get(
                "authority_digest"
            ),
            "restored_outputs": {
                identity: restored[identity]
                for identity in sorted(restored)
            },
        }
        authority = _exact_repair_signed(unsigned)
        if prior.get("state") == "REPAIRED_ACTIVE":
            if prior.get("finalize_authority") != authority:
                raise ArtifactLedgerError(
                    "committed output repair finalize replay changed"
                )
            return authority
        if prior.get("state") != "ARMED":
            raise ArtifactLedgerError(
                "committed output repair finalize state is invalid"
            )

        records = unit["artifacts"]
        for identity, target in restored.items():
            records[identity]["physical_identity"] = target[
                "physical_identity"
            ]
            records[identity]["repair_authority_digest"] = authority[
                "authority_digest"
            ]
            binding = ledger["artifact_bindings"][identity]
            binding["physical_identity"] = target["physical_identity"]
            binding["repair_authority_digest"] = authority[
                "authority_digest"
            ]
            legacy = ledger["artifacts"][_legacy_name(identity)]
            legacy["physical_identity"] = target["physical_identity"]
            legacy["repair_authority_digest"] = authority[
                "authority_digest"
            ]
        history[index] = _exact_repair_history_row(
            state="REPAIRED_ACTIVE",
            pending_digest=pending_digest,
            arm=arm,
            finalize=authority,
        )
        unit["committed_output_repair_history"] = history
        if not _active_commit_receipt_is_valid(
            unit,
            work_unit_key=contract.key,
            run_id=run,
        ):
            raise ArtifactLedgerError(
                "committed output repair refreshed receipt is invalid"
            )
        ledger["work_units"][contract.key] = unit
        write_artifact_ledger(root, ledger)
        return authority


def _producer_authority_is_active(
    ledger: Mapping[str, Any],
    binding: Mapping[str, Any],
    *,
    identity: str,
    run_id: str,
) -> bool:
    producer_key = str(binding.get("owner_key") or "")
    if not producer_key or producer_key.startswith("semantic-mutation:"):
        return bool(producer_key)
    producer = ledger.get("work_units", {}).get(producer_key)
    if not isinstance(producer, dict) or not _active_commit_receipt_is_valid(
        producer, work_unit_key=producer_key, run_id=run_id
    ):
        return False
    artifact = producer.get("artifacts", {}).get(identity)
    legacy = (
        ledger.get("artifacts", {}).get(_legacy_name(identity))
        if isinstance(ledger.get("artifacts"), Mapping)
        else None
    )
    if not (
        _nested_output_records_have_exact_sizes({identity: binding})
        and _nested_output_records_have_exact_sizes({identity: artifact})
        and _nested_output_records_have_exact_sizes({identity: legacy})
    ):
        return False
    return bool(
        isinstance(artifact, dict)
        and isinstance(legacy, Mapping)
        and artifact.get("status") == "ACTIVE"
        and artifact.get("owner_key") == producer_key
        and artifact.get("run_id") == run_id
        and artifact.get("contract_digest") == producer.get("contract_digest")
        and artifact.get("launch_digest") == producer.get("launch_digest")
        and artifact.get("writer") in {"DRIVER", "MODEL"}
        and binding.get("run_id") == run_id
        and binding.get("contract_digest") == producer.get("contract_digest")
        and binding.get("launch_digest") == producer.get("launch_digest")
        and binding.get("writer") == artifact.get("writer")
        and binding.get("status") == "ACTIVE"
        and binding.get("sha256") == artifact.get("sha256")
        and binding.get("size") == artifact.get("size")
        and legacy.get("owner_key") == producer_key
        and legacy.get("run_id") == run_id
        and legacy.get("contract_digest") == producer.get("contract_digest")
        and legacy.get("launch_digest") == producer.get("launch_digest")
        and legacy.get("status") == "ACTIVE"
        and legacy.get("sha256") == artifact.get("sha256")
        and legacy.get("size") == artifact.get("size")
    )


def _input_authority_requirement_issues(
    ledger: Mapping[str, Any],
    record: Mapping[str, Any],
    requirement: InputAuthorityRequirement,
    *,
    run_id: str,
) -> set[str]:
    """Validate one raw-or-exact-producer input authority declaration."""

    issues: set[str] = set()
    identity = str(record.get("identity") or "")
    if identity != requirement.identity:
        return {"INPUT_AUTHORITY_REQUIREMENT_IDENTITY_MISMATCH"}
    producer_key = str(
        record.get("producer_work_unit_key") or ""
    )
    if not producer_key:
        if not requirement.allow_raw:
            issues.add("INPUT_RAW_AUTHORITY_FORBIDDEN")
        return issues

    if requirement.expected_producer_work_unit_key and (
        producer_key != requirement.expected_producer_work_unit_key
    ):
        issues.add("INPUT_EXPECTED_PRODUCER_MISMATCH")
    producer_writer = str(record.get("producer_writer") or "")
    if requirement.expected_writer and (
        producer_writer != requirement.expected_writer
    ):
        issues.add("INPUT_EXPECTED_WRITER_MISMATCH")
    producer_run = str(record.get("producer_run_id") or "")
    if requirement.require_same_run and producer_run != run_id:
        issues.add("INPUT_PRODUCER_RUN_MISMATCH")

    work_units = ledger.get("work_units")
    bindings = ledger.get("artifact_bindings")
    producer = (
        work_units.get(producer_key)
        if isinstance(work_units, Mapping)
        else None
    )
    binding = (
        bindings.get(identity)
        if isinstance(bindings, Mapping)
        else None
    )
    artifact = (
        producer.get("artifacts", {}).get(identity)
        if isinstance(producer, Mapping)
        and isinstance(producer.get("artifacts"), Mapping)
        else None
    )
    legacy = (
        ledger.get("artifacts", {}).get(_legacy_name(identity))
        if isinstance(ledger.get("artifacts"), Mapping)
        else None
    )
    if (
        not isinstance(producer, Mapping)
        or not isinstance(binding, Mapping)
        or not isinstance(artifact, Mapping)
        or not isinstance(legacy, Mapping)
        or not _nested_output_records_have_exact_sizes({identity: binding})
        or not _nested_output_records_have_exact_sizes({identity: artifact})
        or not _nested_output_records_have_exact_sizes({identity: legacy})
        or not _active_commit_receipt_is_valid(
            producer,
            work_unit_key=producer_key,
            run_id=(
                run_id if requirement.require_same_run else producer_run
            ),
        )
    ):
        issues.add("INPUT_PRODUCER_UNIT_NOT_ACTIVE")
        return issues

    if requirement.expected_writer and any(
        value != requirement.expected_writer
        for value in (
            producer_writer,
            str(binding.get("writer") or ""),
            str(artifact.get("writer") or ""),
        )
    ):
        issues.add("INPUT_EXPECTED_WRITER_MISMATCH")

    producer_contract = str(producer.get("contract_digest") or "")
    recorded_contract = str(
        record.get("producer_contract_digest") or ""
    )
    if requirement.expected_contract_digest and any(
        value != requirement.expected_contract_digest
        for value in (
            producer_contract,
            recorded_contract,
            str(binding.get("contract_digest") or ""),
            str(artifact.get("contract_digest") or ""),
        )
    ):
        issues.add("INPUT_EXPECTED_CONTRACT_MISMATCH")
    if requirement.require_exact_contract:
        manifest = producer.get("contract_manifest")
        if (
            not _is_digest(producer_contract)
            or recorded_contract != producer_contract
            or not isinstance(manifest, Mapping)
            or _contract_manifest_digest(manifest) != producer_contract
            or binding.get("contract_digest") != producer_contract
            or artifact.get("contract_digest") != producer_contract
        ):
            issues.add("INPUT_PRODUCER_CONTRACT_MISMATCH")

    producer_launch = str(producer.get("launch_digest") or "")
    recorded_launch = str(
        record.get("producer_launch_digest") or ""
    )
    if requirement.expected_launch_digest and any(
        value != requirement.expected_launch_digest
        for value in (
            producer_launch,
            recorded_launch,
            str(binding.get("launch_digest") or ""),
            str(artifact.get("launch_digest") or ""),
        )
    ):
        issues.add("INPUT_EXPECTED_LAUNCH_MISMATCH")
    if requirement.require_exact_launch and (
        not _is_digest(producer_launch)
        or recorded_launch != producer_launch
        or binding.get("launch_digest") != producer_launch
        or artifact.get("launch_digest") != producer_launch
        or not _launch_manifest_is_valid(
            producer.get("launch_manifest"),
            expected_digest=producer_launch,
        )
    ):
        issues.add("INPUT_PRODUCER_LAUNCH_MISMATCH")

    commit = producer.get("commit_authority")
    manifest = producer.get("contract_manifest")
    required_actor = (
        str(manifest.get("required_commit_actor") or "")
        if isinstance(manifest, Mapping)
        else ""
    )
    if required_actor and (
        not isinstance(commit, Mapping)
        or commit.get("actor") != required_actor
    ):
        issues.add("INPUT_PRODUCER_COMMIT_ACTOR_MISMATCH")
    return issues


def _closed_launch_profile_issues(
    contract: PhaseIOContract,
    launch: LaunchSpec,
) -> set[str]:
    if not contract.launch_profile:
        return set()
    if contract.launch_profile == "DRIVER_PYTHON_NO_TOOLS":
        if (
            launch.model != "driver"
            or launch.exec_mode != "python"
            or launch.tool_policy
        ):
            return {"CLOSED_MODEL_FREE_LAUNCH_PROFILE_MISMATCH"}
        return set()
    return {"UNKNOWN_CLOSED_LAUNCH_PROFILE"}


def semantic_input_producer_authority_issues(
    ledger: Mapping[str, Any],
    input_record: Mapping[str, Any],
    *,
    run_id: str,
) -> list[str]:
    """Require one exact input to descend from current producer authority.

    Generic PhaseIO permits producer-less raw inputs because source snapshots
    and import boundaries may intentionally introduce external preimages.
    Semantic successor/canonicalization transactions need a stricter policy:
    a content hash alone cannot become provenance.  This helper exposes the
    ledger's existing active-producer validation without letting callers
    duplicate or weaken the commit-receipt rules.
    """

    identity = str(input_record.get("identity") or "")
    producer_key = str(
        input_record.get("producer_work_unit_key") or ""
    )
    producer_digest = str(
        input_record.get("producer_contract_digest") or ""
    )
    issues: list[str] = []
    if input_record.get("status") != "ACTIVE":
        issues.append(f"{identity}: semantic input is not ACTIVE")
        return issues
    if not producer_key:
        issues.append(
            f"{identity}: semantic input has no producer/external-preimage "
            "authority"
        )
        return issues
    if producer_key.startswith("semantic-mutation:"):
        if not _is_digest(producer_digest):
            issues.append(
                f"{identity}: semantic-mutation authority digest is invalid"
            )
        return issues
    binding = ledger.get("artifact_bindings", {}).get(identity)
    if not isinstance(binding, Mapping):
        issues.append(f"{identity}: active artifact binding is absent")
        return issues
    producer = (
        ledger.get("work_units", {}).get(producer_key)
        if isinstance(ledger.get("work_units"), Mapping)
        else None
    )
    commit = (
        producer.get("commit_authority")
        if isinstance(producer, Mapping)
        else None
    )
    if "producer_work_unit_key" in input_record:
        # This is a consumer-captured immutable input receipt, not the mutable
        # global ownership row.  Its producer receipt digest is the external
        # anchor that prevents a producer from rewriting its own authority and
        # then presenting the replacement as historical provenance.
        if (
            not isinstance(producer, Mapping)
            or not isinstance(commit, Mapping)
            or input_record.get("producer_run_id") != run_id
            or input_record.get("producer_launch_digest")
            != producer.get("launch_digest")
            or input_record.get("producer_writer")
            != binding.get("writer")
            or not _is_digest(
                input_record.get("producer_commit_receipt_digest")
            )
            or input_record.get("producer_commit_receipt_digest")
            != commit.get("receipt_digest")
        ):
            issues.append(
                f"{identity}: immutable producer receipt changed after "
                "consumer capture"
            )
    if not (
        _nested_output_records_have_exact_sizes(
            {identity: input_record}
        )
        and _nested_output_records_have_exact_sizes({identity: binding})
    ):
        issues.append(
            f"{identity}: semantic input producer byte count is invalid"
        )
    if (
        binding.get("owner_key") != producer_key
        or binding.get("contract_digest") != producer_digest
        or binding.get("sha256") != input_record.get("sha256")
        or binding.get("size") != input_record.get("size")
    ):
        issues.append(
            f"{identity}: semantic input producer binding differs from "
            "the armed byte receipt"
        )
    if not _producer_authority_is_active(
        ledger,
        binding,
        identity=identity,
        run_id=run_id,
    ):
        issues.append(
            f"{identity}: semantic input producer work unit is not an "
            "active current-run commit"
        )
    return list(dict.fromkeys(issues))


def semantic_input_prebind_producer_authority_issues(
    scratchpad: Path,
    project_root: Path,
    identities: Sequence[str],
    *,
    run_id: str,
) -> list[str]:
    """Validate strict current-run producer ancestry before consumer arm.

    Generic PhaseIO intentionally permits raw/external immutable inputs.  A
    successor that declares a strict producer-binding policy must close that
    broader import boundary *before* :func:`record_work_unit_inputs` writes a
    consumer receipt.  This helper snapshots each exact identity through the
    same ledger-aware path used by normal PhaseIO and then requires an active,
    current-run committed producer for the exact bytes.

    Semantic-mutation virtual producers are deliberately insufficient here:
    they authenticate a byte transition, but do not expose the complete
    owner/writer/run/contract/launch tuple required by this stricter policy.
    """

    run = str(run_id or "").strip()
    if not run:
        return ["strict producer prebind run_id is absent"]
    try:
        ledger = read_artifact_ledger(Path(scratchpad))
    except ArtifactLedgerError as exc:
        return [f"strict producer prebind ledger is invalid: {exc}"]
    normalized = tuple(sorted({str(value or "").strip() for value in identities}))
    if not normalized or any(not value for value in normalized):
        return ["strict producer prebind identity denominator is empty or malformed"]
    validation_context = _ArtifactValidationContext(
        Path(scratchpad),
        Path(project_root),
        ledger=ledger,
    )
    validation_ledger = validation_context.ledger
    issues: list[str] = []
    for identity in normalized:
        record = _input_binding_record(
            Path(scratchpad),
            Path(project_root),
            identity,
            "IMMUTABLE",
            validation_ledger,
            _validation_context=validation_context,
        )
        producer_key = str(record.get("producer_work_unit_key") or "")
        if producer_key.startswith("semantic-mutation:"):
            issues.append(
                f"{identity}: semantic-mutation authority lacks the exact "
                "owner/writer/run/contract/launch producer tuple"
            )
            continue
        issues.extend(
            semantic_input_producer_authority_issues(
                validation_ledger,
                record,
                run_id=run,
            )
        )
        binding = validation_ledger.get("artifact_bindings", {}).get(identity)
        producer = (
            validation_ledger.get("work_units", {}).get(producer_key)
            if producer_key
            else None
        )
        artifact = (
            producer.get("artifacts", {}).get(identity)
            if isinstance(producer, Mapping)
            and isinstance(producer.get("artifacts"), Mapping)
            else None
        )
        if not isinstance(binding, Mapping) or not isinstance(
            artifact, Mapping
        ):
            continue
        exact_fields = (
            "owner_key",
            "writer",
            "run_id",
            "contract_digest",
            "launch_digest",
            "sha256",
            "size",
        )
        if any(binding.get(field) != artifact.get(field) for field in exact_fields):
            issues.append(
                f"{identity}: producer owner/writer/run/contract/launch/hash/"
                "size tuple is not exact"
            )
        if binding.get("writer") not in {"DRIVER", "MODEL"}:
            issues.append(f"{identity}: producer writer is invalid")
    issues.extend(validation_context.finish())
    return list(dict.fromkeys(issues))


def active_committed_work_unit_authority_issues(
    ledger: Mapping[str, Any],
    *,
    work_unit_key: str,
    run_id: str,
    expected_artifact_identities: Sequence[str] | None = None,
) -> list[str]:
    """Replay one complete current-run PhaseIO commit from stored facts.

    This is the generic resolver boundary for downstream systems that already
    possess an artifact ledger.  It validates more than unit state labels:
    commit authority, contract digest, exact input denominator/digest, output
    manifest cardinality, and every producer-artifact/global-binding tuple.
    Callers remain responsible for comparing the manifest with their expected
    domain-specific contract; this function proves that the manifest actually
    committed the exact ledger state it declares.
    """

    key = str(work_unit_key or "").strip()
    run = str(run_id or "").strip()
    if not key or not run:
        return ["active work-unit authority key/run_id is absent"]
    work_units = ledger.get("work_units")
    bindings = ledger.get("artifact_bindings")
    legacy_bindings = ledger.get("artifacts")
    unit = (
        work_units.get(key)
        if isinstance(work_units, Mapping)
        else None
    )
    if not isinstance(unit, Mapping):
        return [f"{key}: active work-unit record is absent"]
    issues: list[str] = []
    if not _active_commit_receipt_is_valid(
        unit, work_unit_key=key, run_id=run
    ):
        issues.append(f"{key}: active commit authority is invalid")

    manifest = unit.get("contract_manifest")
    manifest_inputs: list[str] = []
    manifest_outputs: list[Mapping[str, Any]] = []
    if not isinstance(manifest, Mapping):
        issues.append(f"{key}: contract manifest is absent")
    else:
        immutable = manifest.get("immutable_inputs")
        bounded = manifest.get("bounded_lookup_inputs")
        outputs = manifest.get("outputs")
        if (
            not isinstance(immutable, list)
            or not isinstance(bounded, list)
            or any(not isinstance(value, str) for value in immutable + bounded)
            or len(immutable) != len(set(immutable))
            or len(bounded) != len(set(bounded))
        ):
            issues.append(f"{key}: contract input denominator is malformed")
        else:
            manifest_inputs = list(dict.fromkeys((*immutable, *bounded)))
        if (
            not isinstance(outputs, list)
            or any(not isinstance(row, Mapping) for row in outputs)
        ):
            issues.append(f"{key}: contract output denominator is malformed")
        else:
            manifest_outputs = list(outputs)

    input_bindings = unit.get("input_bindings")
    if not isinstance(input_bindings, Mapping):
        issues.append(f"{key}: input binding map is absent")
        input_bindings = {}
    input_keys = [str(value) for value in input_bindings]
    if (
        len(input_keys) != len(set(input_keys))
        or set(input_keys) != set(manifest_inputs)
    ):
        issues.append(f"{key}: manifest/input-binding denominator differs")
    normalized_inputs: dict[str, dict[str, Any]] = {}
    for identity, raw_record in input_bindings.items():
        if not isinstance(raw_record, Mapping):
            issues.append(f"{key}: {identity} input binding is malformed")
            continue
        record = dict(raw_record)
        normalized_inputs[str(identity)] = record
        if (
            record.get("identity") != identity
            or record.get("status") != "ACTIVE"
        ):
            issues.append(
                f"{key}: {identity} input binding is not exact and ACTIVE"
            )
    if (
        _input_set_digest(normalized_inputs)
        != unit.get("input_set_digest")
    ):
        issues.append(f"{key}: input_set_digest does not replay")

    artifacts = unit.get("artifacts")
    if not isinstance(artifacts, Mapping):
        issues.append(f"{key}: artifact record map is absent")
        artifacts = {}
    manifest_output_ids = [
        str(row.get("identity") or "")
        for row in manifest_outputs
    ]
    if (
        any(not identity for identity in manifest_output_ids)
        or len(manifest_output_ids) != len(set(manifest_output_ids))
        or set(manifest_output_ids) != set(artifacts)
    ):
        issues.append(f"{key}: manifest/artifact output denominator differs")
    if expected_artifact_identities is not None:
        expected_values = tuple(
            str(value) for value in expected_artifact_identities
        )
        expected = set(expected_values)
        if (
            len(expected) != len(expected_values)
            or set(artifacts) != expected
        ):
            issues.append(f"{key}: output denominator differs from consumer expectation")

    output_by_identity = {
        str(row.get("identity") or ""): row
        for row in manifest_outputs
        if str(row.get("identity") or "")
    }
    commit_authority = unit.get("commit_authority")
    committed_expected = (
        commit_authority.get("expected_output_records")
        if isinstance(commit_authority, Mapping)
        else None
    )
    if committed_expected is not None:
        if (
            not isinstance(committed_expected, Mapping)
            or set(committed_expected) != set(artifacts)
            or not _nested_output_records_have_exact_sizes(
                committed_expected,
                expected_identities=set(artifacts),
            )
            or not _nested_output_records_have_exact_sizes(
                artifacts,
                expected_identities=set(committed_expected),
            )
        ):
            issues.append(
                f"{key}: commit expected-output denominator differs"
            )
        else:
            for identity, expected_record in committed_expected.items():
                artifact = artifacts.get(identity)
                if (
                    not isinstance(expected_record, Mapping)
                    or set(expected_record) != {"sha256", "size"}
                    or not isinstance(artifact, Mapping)
                    or artifact.get("sha256")
                    != expected_record.get("sha256")
                    or artifact.get("size") != expected_record.get("size")
                ):
                    issues.append(
                        f"{key}: {identity} commit expected-output record "
                        "differs"
                    )
    exact_fields = (
        "identity",
        "owner_key",
        "writer",
        "run_id",
        "contract_digest",
        "launch_digest",
        "artifact_class",
        "write_mode",
        "schema_version",
        "minimum_gate",
        "consumers",
        "condition_id",
        "sha256",
        "size",
        "status",
    )
    if not isinstance(bindings, Mapping):
        issues.append(f"{key}: global artifact binding map is absent")
        bindings = {}
    if not isinstance(legacy_bindings, Mapping):
        issues.append(f"{key}: legacy artifact projection map is absent")
        legacy_bindings = {}
    for identity in sorted(set(artifacts)):
        artifact = artifacts.get(identity)
        binding = bindings.get(identity)
        legacy = legacy_bindings.get(_legacy_name(identity))
        output_spec = output_by_identity.get(identity)
        if (
            not isinstance(artifact, Mapping)
            or not isinstance(binding, Mapping)
            or not isinstance(legacy, Mapping)
            or not isinstance(output_spec, Mapping)
            or not _nested_output_records_have_exact_sizes(
                {identity: artifact}
            )
            or not _nested_output_records_have_exact_sizes(
                {identity: binding}
            )
            or not _nested_output_records_have_exact_sizes(
                {identity: legacy}
            )
        ):
            issues.append(
                f"{key}: {identity} output authority tuple is incomplete"
            )
            continue
        if (
            artifact.get("status") != "ACTIVE"
            or binding.get("status") != "ACTIVE"
            or artifact.get("owner_key") != key
            or binding.get("owner_key") != key
            or artifact.get("run_id") != run
            or binding.get("run_id") != run
            or artifact.get("contract_digest")
            != unit.get("contract_digest")
            or binding.get("contract_digest")
            != unit.get("contract_digest")
            or artifact.get("launch_digest") != unit.get("launch_digest")
            or binding.get("launch_digest") != unit.get("launch_digest")
            or any(
                artifact.get(field) != binding.get(field)
                for field in exact_fields
            )
            or any(
                artifact.get(field) != output_spec.get(field)
                for field in (
                    "identity",
                    "owner_key",
                    "writer",
                    "artifact_class",
                    "write_mode",
                    "schema_version",
                    "minimum_gate",
                    "consumers",
                    "condition_id",
                )
            )
            or any(
                legacy.get(field) != artifact.get(field)
                for field in (
                    "owner_key",
                    "status",
                    "size",
                    "sha256",
                    "contract_digest",
                    "launch_digest",
                    "run_id",
                    "authority_level",
                )
            )
        ):
            issues.append(
                f"{key}: {identity} output artifact/global/manifest tuple "
                "is not exact and ACTIVE"
            )
    return list(dict.fromkeys(issues))


def stored_committed_work_unit_authority_issues(
    ledger: Mapping[str, Any],
    *,
    work_unit_key: str,
    run_id: str,
    expected_artifact_identities: Sequence[str] | None = None,
) -> list[str]:
    """Validate a committed predecessor without claiming current ownership.

    Append/merge consumers transfer the live binding to a successor.  The
    predecessor commit nevertheless remains usable as historical lineage only
    when its signed commit, contract, inputs, prestates, and stored artifacts
    still replay exactly.  Callers must separately prove a contiguous
    successor chain to the current binding and live bytes.
    """

    key = str(work_unit_key or "").strip()
    run = str(run_id or "").strip()
    unit = (
        ledger.get("work_units", {}).get(key)
        if isinstance(ledger.get("work_units"), Mapping)
        else None
    )
    if not key or not run or not isinstance(unit, Mapping):
        return [f"{key or '<missing>'}: stored work-unit authority is absent"]
    issues: list[str] = []
    if not _active_commit_receipt_is_valid(
        unit, work_unit_key=key, run_id=run
    ):
        issues.append(f"{key}: stored commit authority is invalid")

    manifest = unit.get("contract_manifest")
    manifest_inputs: list[str] = []
    manifest_outputs: list[str] = []
    manifest_output_rows: dict[str, Mapping[str, Any]] = {}
    if not isinstance(manifest, Mapping):
        issues.append(f"{key}: stored contract manifest is absent")
    else:
        try:
            if (
                manifest.get("key") != key
                or _contract_manifest_digest(dict(manifest))
                != unit.get("contract_digest")
            ):
                issues.append(
                    f"{key}: stored contract manifest integrity failure"
                )
        except (TypeError, ValueError):
            issues.append(f"{key}: stored contract manifest is malformed")
        immutable = manifest.get("immutable_inputs")
        bounded = manifest.get("bounded_lookup_inputs")
        outputs = manifest.get("outputs")
        if (
            not isinstance(immutable, list)
            or not isinstance(bounded, list)
            or any(
                not isinstance(value, str)
                for value in (*immutable, *bounded)
            )
        ):
            issues.append(f"{key}: stored input denominator is malformed")
        else:
            manifest_inputs = list(dict.fromkeys((*immutable, *bounded)))
            if len(manifest_inputs) != len(immutable) + len(bounded):
                issues.append(
                    f"{key}: stored input denominator is not unique"
                )
        if (
            not isinstance(outputs, list)
            or any(not isinstance(row, Mapping) for row in outputs)
        ):
            issues.append(f"{key}: stored output denominator is malformed")
        else:
            manifest_outputs = [
                str(row.get("identity") or "") for row in outputs
            ]
            if (
                any(not identity for identity in manifest_outputs)
                or len(manifest_outputs) != len(set(manifest_outputs))
            ):
                issues.append(
                    f"{key}: stored output identities are malformed"
                )
            else:
                manifest_output_rows = {
                    str(row["identity"]): row for row in outputs
                }

    bindings = unit.get("input_bindings")
    normalized_inputs: dict[str, dict[str, Any]] = {}
    if not isinstance(bindings, Mapping):
        issues.append(f"{key}: stored input bindings are absent")
    else:
        if set(bindings) != set(manifest_inputs):
            issues.append(
                f"{key}: stored manifest/input denominator differs"
            )
        for identity, raw in bindings.items():
            if (
                not isinstance(raw, Mapping)
                or raw.get("identity") != identity
                or raw.get("status") != "ACTIVE"
            ):
                issues.append(
                    f"{key}: {identity} stored input binding is invalid"
                )
                continue
            normalized_inputs[str(identity)] = dict(raw)
        if (
            _input_set_digest(normalized_inputs)
            != unit.get("input_set_digest")
        ):
            issues.append(f"{key}: stored input_set_digest does not replay")

    artifacts = unit.get("artifacts")
    if not isinstance(artifacts, Mapping):
        issues.append(f"{key}: stored artifact records are absent")
        artifacts = {}
    expected = (
        {str(value) for value in expected_artifact_identities}
        if expected_artifact_identities is not None
        else set(manifest_outputs)
    )
    if set(manifest_outputs) != expected or set(artifacts) != expected:
        issues.append(f"{key}: stored output denominator differs")
    if not _nested_output_records_have_exact_sizes(
        artifacts,
        expected_identities=expected,
    ):
        issues.append(f"{key}: stored artifact byte counts are invalid")
    for identity, raw in artifacts.items():
        output_spec = manifest_output_rows.get(str(identity))
        if (
            not isinstance(raw, Mapping)
            or not isinstance(output_spec, Mapping)
            or raw.get("identity") != identity
            or raw.get("owner_key") != key
            or raw.get("run_id") != run
            or raw.get("contract_digest") != unit.get("contract_digest")
            or raw.get("launch_digest") != unit.get("launch_digest")
            or raw.get("status") != "ACTIVE"
            or raw.get("writer") not in {"DRIVER", "MODEL"}
            or not _is_digest(raw.get("sha256"))
            or not _nested_output_records_have_exact_sizes(
                {str(identity): raw}
            )
            or any(
                raw.get(field) != output_spec.get(field)
                for field in (
                    "identity",
                    "owner_key",
                    "writer",
                    "artifact_class",
                    "write_mode",
                    "schema_version",
                    "minimum_gate",
                    "consumers",
                    "condition_id",
                )
            )
        ):
            issues.append(
                f"{key}: {identity} stored artifact/manifest authority "
                "tuple is invalid"
            )

    prestates = unit.get("output_prestates")
    if not isinstance(prestates, Mapping):
        issues.append(f"{key}: stored output prestates are absent")
    else:
        if set(prestates) != expected:
            issues.append(
                f"{key}: stored output-prestate denominator differs"
            )
        try:
            if (
                _output_prestate_digest(prestates)
                != unit.get("output_prestate_digest")
            ):
                issues.append(
                    f"{key}: stored output-prestate digest mismatch"
                )
        except (AttributeError, TypeError, ValueError):
            issues.append(
                f"{key}: stored output-prestate receipt is malformed"
            )
        for identity, raw in prestates.items():
            if not isinstance(raw, Mapping) or not _output_prestate_is_clean(raw):
                issues.append(
                    f"{key}: {identity} stored output prestate is invalid"
                )
    commit = unit.get("commit_authority")
    if (
        not isinstance(commit, Mapping)
        or set(commit.get("recorded_output_identities") or ()) != expected
    ):
        issues.append(f"{key}: stored commit output denominator differs")
    return list(dict.fromkeys(issues))


def _driver_successor_authority_key(
    *, run_id: str, work_unit_key: str,
) -> str:
    return hashlib.sha256(
        f"{run_id}\0{work_unit_key}".encode("utf-8")
    ).hexdigest()


def _successor_base_input_records(
    records: Mapping[str, Any],
) -> dict[str, dict[str, Any]]:
    normalized: dict[str, dict[str, Any]] = {}
    for identity, raw in records.items():
        if not isinstance(raw, Mapping):
            raise ArtifactLedgerError(
                "driver successor input binding is malformed"
            )
        row = dict(raw)
        row.pop("driver_successor_plan_digest", None)
        row.pop("driver_successor_authority_digest", None)
        normalized[str(identity)] = row
    return normalized


def plan_driver_successor_transaction(
    scratchpad: Path,
    project_root: Path,
    contract: PhaseIOContract,
    launch: LaunchSpec,
    *,
    run_id: str,
    planned_output_bytes: Mapping[str, bytes],
    merge_events: Mapping[str, DriverMergeEvent] | None = None,
) -> DriverSuccessorPlan:
    """Seal the exact preimage/postimage denominator before driver writes.

    This operation is read-only.  The later input arm re-snapshots every
    preimage under the ledger lock and refuses the plan if anything changed
    between planning and arming.
    """

    contract, launch = _replay_authority_pair(contract, launch)
    run = str(run_id or "").strip()
    if not run:
        raise ArtifactLedgerError(
            "driver successor plan run_id must be non-empty"
        )
    if contract.model_invoked or any(
        spec.writer != "DRIVER" for spec in contract.outputs
    ):
        raise ArtifactLedgerError(
            "driver successor planning requires a driver-only work unit"
        )
    if not isinstance(planned_output_bytes, Mapping):
        raise ArtifactLedgerError(
            "planned output bytes must be an exact mapping"
        )
    expected_identities = tuple(
        spec.identity for spec in contract.outputs
    )
    if set(planned_output_bytes) != set(expected_identities):
        raise ArtifactLedgerError(
            "planned output-byte denominator differs from the contract"
        )
    normalized_bytes: dict[str, bytes] = {}
    for identity in expected_identities:
        raw = planned_output_bytes.get(identity)
        if type(raw) is not bytes:
            raise ArtifactLedgerError(
                f"{identity}: planned output must be exact immutable bytes"
            )
        normalized_bytes[identity] = raw

    supplied_events = dict(merge_events or {})
    merge_identities = {
        spec.identity
        for spec in contract.outputs
        if spec.write_mode == "MERGE"
    }
    if set(supplied_events) != merge_identities:
        raise ArtifactLedgerError(
            "planned merge-event denominator differs from MERGE outputs"
        )
    normalized_events: dict[str, DriverMergeEvent] = {}
    for identity, event in supplied_events.items():
        if type(event) is not DriverMergeEvent:
            raise ArtifactLedgerError(
                f"{identity}: planned merge event has the wrong type"
            )
        try:
            event.validate_against(contract)
        except ValueError as exc:
            raise ArtifactLedgerError(
                f"{identity}: planned merge event is invalid: {exc}"
            ) from exc
        if event.artifact_identity != identity:
            raise ArtifactLedgerError(
                f"{identity}: planned merge event key differs"
            )
        normalized_events[identity] = event

    with _ledger_transaction_lock(Path(scratchpad)):
        ledger = read_artifact_ledger(Path(scratchpad))
        prestates = _output_prestate_records(
            Path(scratchpad),
            Path(project_root),
            contract,
            ledger,
            run_id=run,
        )
        invalid = sorted(
            identity
            for identity, row in prestates.items()
            if not _output_prestate_is_clean(row)
        )
        if invalid:
            raise ArtifactLedgerError(
                "driver successor output prestate is not clean: "
                + ", ".join(invalid)
            )
        transitions: list[DriverOutputTransition] = []
        for ordinal, spec in enumerate(contract.outputs, start=1):
            identity = spec.identity
            prestate = prestates[identity]
            existed = bool(prestate.get("existed"))
            before_sha256 = (
                str(prestate.get("sha256") or "") if existed else ""
            )
            before_size = (
                int(prestate.get("size") or 0) if existed else 0
            )
            raw = normalized_bytes[identity]
            after_sha256 = hashlib.sha256(raw).hexdigest()
            event = normalized_events.get(identity)
            if event is not None and (
                not existed
                or event.before_sha256 != before_sha256
                or event.after_sha256 != after_sha256
            ):
                raise ArtifactLedgerError(
                    f"{identity}: planned merge event differs from "
                    "the observed preimage or planned postimage"
                )
            transitions.append(
                DriverOutputTransition(
                    work_unit_key=contract.key,
                    contract_digest=contract.digest,
                    ordinal=ordinal,
                    artifact_identity=identity,
                    before_status=(
                        "ACTIVE" if existed else "MISSING"
                    ),
                    before_sha256=before_sha256,
                    before_size=before_size,
                    after_sha256=after_sha256,
                    after_size=len(raw),
                    merge_event=event,
                )
            )
        plan = DriverSuccessorPlan(
            run_id=run,
            work_unit_key=contract.key,
            contract_digest=contract.digest,
            launch_digest=launch.digest,
            output_prestate_digest=_output_prestate_digest(prestates),
            transitions=tuple(transitions),
        )
        try:
            return replay_driver_successor_plan_authority(
                plan,
                contract=contract,
                launch=launch,
            )
        except (TypeError, ValueError) as exc:
            raise ArtifactLedgerError(
                f"driver successor plan replay failed: {exc}"
            ) from exc


def _driver_successor_transition_rows(
    plan_payload: Mapping[str, Any],
) -> list[dict[str, Any]]:
    rows = plan_payload.get("transitions")
    if (
        not isinstance(rows, list)
        or not rows
        or any(not isinstance(row, Mapping) for row in rows)
    ):
        raise ArtifactLedgerError(
            "driver successor transition denominator is malformed"
        )
    normalized = [dict(row) for row in rows]
    if [row.get("ordinal") for row in normalized] != list(
        range(1, len(normalized) + 1)
    ):
        raise ArtifactLedgerError(
            "driver successor transition ordinals are not contiguous"
        )
    identities = [
        str(row.get("artifact_identity") or "") for row in normalized
    ]
    if (
        any(not identity for identity in identities)
        or len(identities) != len(set(identities))
    ):
        raise ArtifactLedgerError(
            "driver successor transition identities are malformed"
        )
    return normalized


def _driver_successor_prestate_matches_transition(
    prestate: Mapping[str, Any],
    transition: Mapping[str, Any],
) -> bool:
    status = str(transition.get("before_status") or "")
    if status == "MISSING":
        return bool(
            prestate.get("existed") is False
            and prestate.get("size") == 0
            and prestate.get("sha256") == ""
            and prestate.get("status") == "ABSENT"
        )
    if status != "ACTIVE":
        return False
    return bool(
        prestate.get("existed") is True
        and prestate.get("size") == transition.get("before_size")
        and prestate.get("sha256") == transition.get("before_sha256")
        and _output_prestate_is_clean(prestate)
    )


def _derive_driver_successor_authority_unsigned(
    scratchpad: Path,
    project_root: Path,
    ledger: Mapping[str, Any],
    contract: PhaseIOContract,
    launch: LaunchSpec,
    *,
    run_id: str,
    plan: Any,
    input_records: Mapping[str, Any],
    output_prestates: Mapping[str, Any],
    authenticated_progress_identities: Sequence[str] = (),
    authenticated_physical_rebinds: Mapping[str, str] | None = None,
) -> tuple[dict[str, Any], tuple[str, ...]]:
    try:
        replayed_plan = replay_driver_successor_plan_authority(
            plan,
            contract=contract,
            launch=launch,
        )
    except (TypeError, ValueError) as exc:
        raise ArtifactLedgerError(
            f"driver successor plan authority replay failed: {exc}"
        ) from exc
    plan_payload = replayed_plan.to_dict()
    plan_digest = replayed_plan.digest
    if (
        plan_payload.get("run_id") != run_id
        or plan_payload.get("work_unit_key") != contract.key
        or plan_payload.get("contract_digest") != contract.digest
        or plan_payload.get("launch_digest") != launch.digest
        or plan_payload.get("output_prestate_digest")
        != _output_prestate_digest(dict(output_prestates))
    ):
        raise ArtifactLedgerError(
            "driver successor plan does not bind the armed transaction"
        )
    transitions = _driver_successor_transition_rows(plan_payload)
    transition_by_identity = {
        str(row["artifact_identity"]): row for row in transitions
    }
    if set(transition_by_identity) != {
        spec.identity for spec in contract.outputs
    }:
        raise ArtifactLedgerError(
            "driver successor plan output denominator differs"
        )
    progressed = {
        str(identity) for identity in authenticated_progress_identities
    }
    if progressed - set(transition_by_identity):
        raise ArtifactLedgerError(
            "driver successor progress exemption denominator differs"
        )
    rebound = dict(authenticated_physical_rebinds or {})
    if (
        any(
            not isinstance(identity, str)
            or not identity
            or not isinstance(physical, str)
            or not physical
            for identity, physical in rebound.items()
        )
        or set(rebound) - set(transition_by_identity)
        or set(rebound) & progressed
    ):
        raise ArtifactLedgerError(
            "driver successor physical-rebind override denominator differs"
        )
    for identity, transition in transition_by_identity.items():
        prestate = output_prestates.get(identity)
        if (
            not isinstance(prestate, Mapping)
            or not _driver_successor_prestate_matches_transition(
                prestate, transition
            )
        ):
            raise ArtifactLedgerError(
                f"{identity}: driver successor plan prestate differs "
                "from the arm receipt"
            )

    base_records = _successor_base_input_records(input_records)
    relative_consumer = f"{contract.phase}/{contract.work_unit_id}"
    consumer_outputs = set(transition_by_identity)
    by_producer: dict[str, list[str]] = {}
    for identity, record in base_records.items():
        producer_key = str(record.get("producer_work_unit_key") or "")
        if producer_key and not producer_key.startswith(
            "semantic-mutation:"
        ):
            by_producer.setdefault(producer_key, []).append(identity)
    # A registered successor may replace a producer's complete output bundle,
    # leaving no unchanged sibling that can also appear in immutable_inputs.
    # Preserve that valid class by deriving the historical producer directly
    # from the sealed output prestates. The intersection and handoff checks
    # below still require exact same-run producer replay and an explicit
    # predecessor->successor registration for every replaced artifact.
    for identity, prestate in output_prestates.items():
        if (
            identity in consumer_outputs
            and isinstance(prestate, Mapping)
            and prestate.get("existed") is True
            and _output_prestate_is_clean(prestate)
        ):
            producer_key = str(
                prestate.get("predecessor_owner_key") or ""
            )
            if producer_key and not producer_key.startswith(
                "semantic-mutation:"
            ):
                by_producer.setdefault(producer_key, [])

    bundles: list[dict[str, Any]] = []
    affected_inputs: set[str] = set()
    consumed_rebounds: set[str] = set()
    for producer_key, consumed in sorted(by_producer.items()):
        producer = (
            ledger.get("work_units", {}).get(producer_key)
            if isinstance(ledger.get("work_units"), Mapping)
            else None
        )
        artifacts = (
            producer.get("artifacts")
            if isinstance(producer, Mapping)
            else None
        )
        if not isinstance(producer, Mapping) or not isinstance(
            artifacts, Mapping
        ):
            continue
        intersection = sorted(set(artifacts) & consumer_outputs)
        if not intersection:
            continue
        producer_run = str(producer.get("run_id") or "")
        if producer_run != run_id:
            raise ArtifactLedgerError(
                "driver successor producer is cross-run"
            )
        stored_issues = stored_committed_work_unit_authority_issues(
            ledger,
            work_unit_key=producer_key,
            run_id=run_id,
            expected_artifact_identities=tuple(sorted(artifacts)),
        )
        producer_rebounds = set(rebound) & set(artifacts)
        if producer_rebounds & consumed_rebounds:
            raise ArtifactLedgerError(
                "driver successor physical-rebind override is ambiguous"
            )
        consumed_rebounds.update(producer_rebounds)
        stored_issues.extend(
            _replay_output_commit_authority(
                Path(scratchpad),
                Path(project_root),
                producer,
                require_live_bytes=True,
                # On initial issuance this set is empty, so every historical
                # producer byte must still be live.  During replay, only the
                # exact contiguous successor prefix whose events replay from
                # ledger-bound CAS may differ; unrelated producer siblings
                # remain live-byte checked.
                live_byte_exempt_identities=tuple(
                    sorted(progressed & set(artifacts))
                ),
                live_physical_override_by_identity={
                    identity: rebound[identity]
                    for identity in sorted(producer_rebounds)
                },
            )
        )
        if stored_issues:
            raise ArtifactLedgerError(
                "driver successor historical producer does not replay: "
                + "; ".join(stored_issues)
            )
        commit = producer.get("commit_authority")
        if not isinstance(commit, Mapping):
            raise ArtifactLedgerError(
                "driver successor producer commit authority is absent"
            )
        for identity in sorted(consumed):
            record = base_records[identity]
            artifact = artifacts.get(identity)
            binding = (
                ledger.get("artifact_bindings", {}).get(identity)
                if isinstance(
                    ledger.get("artifact_bindings"), Mapping
                )
                else None
            )
            try:
                registered_consumer = registered_projection_handoff(
                    producer_key,
                    contract.key,
                    identity,
                )
            except ValueError:
                registered_consumer = False
            if (
                not isinstance(artifact, Mapping)
                or not isinstance(binding, Mapping)
                or record.get("status") != "ACTIVE"
                or artifact.get("consumers") is None
                or (
                    relative_consumer
                    not in set(artifact.get("consumers") or ())
                    and not registered_consumer
                )
                or any(
                    record.get(field) != value
                    for field, value in (
                        ("producer_work_unit_key", producer_key),
                        (
                            "producer_contract_digest",
                            producer.get("contract_digest"),
                        ),
                        (
                            "producer_launch_digest",
                            producer.get("launch_digest"),
                        ),
                        (
                            "producer_commit_receipt_digest",
                            commit.get("receipt_digest"),
                        ),
                    )
                )
                or binding.get("owner_key") != producer_key
                or binding.get("run_id") != run_id
                or binding.get("sha256") != record.get("sha256")
                or binding.get("size") != record.get("size")
            ):
                raise ArtifactLedgerError(
                    f"{identity}: driver successor consumed-input "
                    "authority is invalid"
                )
        for identity in intersection:
            artifact = artifacts.get(identity)
            transition = transition_by_identity[identity]
            prestate = output_prestates.get(identity)
            try:
                handoff = registered_projection_handoff(
                    producer_key, contract.key, identity
                )
            except ValueError:
                handoff = False
            if (
                not isinstance(artifact, Mapping)
                or not isinstance(prestate, Mapping)
                or (
                    relative_consumer
                    not in set(artifact.get("consumers") or ())
                    and not handoff
                )
                or artifact.get("sha256")
                != transition.get("before_sha256")
                or artifact.get("size") != transition.get("before_size")
                or prestate.get("predecessor_owner_key") != producer_key
                or prestate.get("predecessor_contract_digest")
                != producer.get("contract_digest")
                or prestate.get("predecessor_launch_digest")
                != producer.get("launch_digest")
            ):
                raise ArtifactLedgerError(
                    f"{identity}: driver successor sibling handoff is "
                    "not exact and registered"
                )
        bundle = {
            "producer_work_unit_key": producer_key,
            "producer_run_id": producer_run,
            "producer_contract_digest": str(
                producer.get("contract_digest") or ""
            ),
            "producer_launch_digest": str(
                producer.get("launch_digest") or ""
            ),
            "producer_commit_receipt_digest": str(
                commit.get("receipt_digest") or ""
            ),
            "producer_output_authority_key": str(
                commit.get("output_authority_key") or ""
            ),
            "producer_output_authority_digest": str(
                commit.get("output_authority_digest") or ""
            ),
            "producer_output_records_digest": _canonical_json_digest(
                dict(artifacts)
            ),
            "producer_output_identities": sorted(artifacts),
            "consumed_input_identities": sorted(consumed),
            "successor_output_identities": intersection,
        }
        bundles.append(bundle)
        affected_inputs.update(consumed)
    if consumed_rebounds != set(rebound):
        raise ArtifactLedgerError(
            "driver successor physical-rebind override has no exact "
            "historical producer"
        )
    if not bundles:
        raise ArtifactLedgerError(
            "driver successor plan has no historical producer bundle "
            "intersection"
        )

    authority_key = _driver_successor_authority_key(
        run_id=run_id, work_unit_key=contract.key
    )
    unsigned = {
        "schema": _DRIVER_SUCCESSOR_AUTHORITY_SCHEMA,
        "authority_key": authority_key,
        "state": "ACTIVE",
        "run_id": run_id,
        "work_unit_key": contract.key,
        "contract_digest": contract.digest,
        "launch_digest": launch.digest,
        "plan_digest": plan_digest,
        "plan": plan_payload,
        "output_prestate_digest": _output_prestate_digest(
            dict(output_prestates)
        ),
        "input_binding_base_digest": _input_set_digest(base_records),
        "affected_input_identities": sorted(affected_inputs),
        "producer_bundles": bundles,
        "physical_policy": _NO_FOLLOW_PHYSICAL_POLICY,
    }
    return unsigned, tuple(sorted(affected_inputs))


def _issue_driver_successor_authority(
    scratchpad: Path,
    project_root: Path,
    ledger: Mapping[str, Any],
    contract: PhaseIOContract,
    launch: LaunchSpec,
    *,
    run_id: str,
    plan: Any,
    input_records: Mapping[str, Any],
    output_prestates: Mapping[str, Any],
) -> tuple[dict[str, Any], tuple[str, ...]]:
    unsigned, affected = _derive_driver_successor_authority_unsigned(
        Path(scratchpad),
        Path(project_root),
        ledger,
        contract,
        launch,
        run_id=run_id,
        plan=plan,
        input_records=input_records,
        output_prestates=output_prestates,
    )
    authority = {
        **unsigned,
        "authority_digest": _canonical_json_digest(unsigned),
    }
    digest = str(authority["authority_digest"])
    _write_once_authority_cas(
        Path(scratchpad),
        directory_name=_DRIVER_SUCCESSOR_AUTHORITY_CAS_DIRECTORY,
        authority_digest=digest,
        unsigned_authority=unsigned,
        label="driver successor authority",
    )
    journal = _read_driver_successor_authority_ledger(
        Path(scratchpad)
    )
    key = str(authority["authority_key"])
    prior = journal["authorities"].get(key)
    if prior is not None and prior != authority:
        raise ArtifactLedgerError(
            "driver successor authority key was already claimed by a "
            "different plan"
        )
    authority_fields = {
        "schema",
        "authority_key",
        "state",
        "run_id",
        "work_unit_key",
        "contract_digest",
        "launch_digest",
        "plan_digest",
        "plan",
        "output_prestate_digest",
        "input_binding_base_digest",
        "affected_input_identities",
        "producer_bundles",
        "physical_policy",
        "authority_digest",
    }
    for journal_key, other in journal["authorities"].items():
        # There is intentionally no terminal/release protocol in v1.  Every
        # extant peer row must therefore replay as the exact ACTIVE claim that
        # was originally issued.  A journal-only state edit, malformed row, or
        # orphaned CAS/unit projection fails closed instead of releasing its
        # predecessor siblings for a second successor.
        if (
            not isinstance(other, Mapping)
            or set(other) != authority_fields
            or other.get("schema")
            != _DRIVER_SUCCESSOR_AUTHORITY_SCHEMA
            or other.get("state") != "ACTIVE"
            or other.get("authority_key") != journal_key
            or other.get("physical_policy")
            != _NO_FOLLOW_PHYSICAL_POLICY
            or other.get("authority_digest")
            != _canonical_json_digest({
                field: value
                for field, value in other.items()
                if field != "authority_digest"
            })
        ):
            raise ArtifactLedgerError(
                "driver successor peer journal authority is malformed"
            )
        other_digest = str(other["authority_digest"])
        if _read_authority_cas(
            Path(scratchpad),
            other_digest,
            directory_name=_DRIVER_SUCCESSOR_AUTHORITY_CAS_DIRECTORY,
            label="driver successor authority",
        ) != {
            field: value
            for field, value in other.items()
            if field != "authority_digest"
        }:
            raise ArtifactLedgerError(
                "driver successor peer journal/CAS authority differs"
            )
        peer_unit = ledger.get("work_units", {}).get(
            str(other.get("work_unit_key") or "")
        )
        same_incomplete_arm = (
            other_digest == digest
            and journal_key == key
            and peer_unit is None
        )
        if (
            not same_incomplete_arm
            and (
                not isinstance(peer_unit, Mapping)
                or peer_unit.get("run_id") != other.get("run_id")
                or peer_unit.get("contract_digest")
                != other.get("contract_digest")
                or peer_unit.get("launch_digest")
                != other.get("launch_digest")
                or peer_unit.get("successor_consumption_authority")
                != dict(other)
            )
        ):
            raise ArtifactLedgerError(
                "driver successor peer armed-unit authority differs"
            )
        if same_incomplete_arm:
            # CAS + journal are the durable prefix of this exact arm.  A crash
            # before the main ledger publication leaves no output authority
            # and no progress head, so the same caller may finish publishing
            # the already-sealed arm.  No other/malformed peer is adopted.
            continue
        if (
            other_digest == digest
            or other.get("run_id") != run_id
        ):
            continue
        bundles = other.get("producer_bundles")
        if (
            not isinstance(bundles, list)
            or not bundles
            or any(not isinstance(bundle, Mapping) for bundle in bundles)
        ):
            raise ArtifactLedgerError(
                "driver successor peer producer denominator is malformed"
            )
        claimed = {
            (
                str(bundle.get("producer_work_unit_key") or ""),
                str(identity),
            )
            for bundle in bundles
            for identity in bundle.get(
                "successor_output_identities", ()
            )
        }
        if (
            not claimed
            or any(not producer or not identity for producer, identity in claimed)
        ):
            raise ArtifactLedgerError(
                "driver successor peer claim denominator is malformed"
            )
        requested = {
            (
                str(bundle.get("producer_work_unit_key") or ""),
                str(identity),
            )
            for bundle in authority["producer_bundles"]
            for identity in bundle["successor_output_identities"]
        }
        if claimed & requested:
            raise ArtifactLedgerError(
                "driver successor predecessor sibling already has an "
                "active successor claim"
            )
    journal["authorities"][key] = authority
    _write_driver_successor_authority_ledger(
        Path(scratchpad), journal
    )
    return authority, affected


def _replay_driver_successor_authority(
    scratchpad: Path,
    project_root: Path,
    ledger: Mapping[str, Any],
    unit: Mapping[str, Any],
    contract: PhaseIOContract,
    launch: LaunchSpec,
    *,
    run_id: str,
) -> tuple[dict[str, Any], Any]:
    authority = unit.get("successor_consumption_authority")
    authority_fields = {
        "schema",
        "authority_key",
        "state",
        "run_id",
        "work_unit_key",
        "contract_digest",
        "launch_digest",
        "plan_digest",
        "plan",
        "output_prestate_digest",
        "input_binding_base_digest",
        "affected_input_identities",
        "producer_bundles",
        "physical_policy",
        "authority_digest",
    }
    if (
        not isinstance(authority, Mapping)
        or set(authority) != authority_fields
        or authority.get("schema")
        != _DRIVER_SUCCESSOR_AUTHORITY_SCHEMA
        or authority.get("state") != "ACTIVE"
        or authority.get("run_id") != run_id
        or authority.get("work_unit_key") != contract.key
        or authority.get("contract_digest") != contract.digest
        or authority.get("launch_digest") != launch.digest
        or authority.get("physical_policy")
        != _NO_FOLLOW_PHYSICAL_POLICY
        or authority.get("authority_key")
        != _driver_successor_authority_key(
            run_id=run_id, work_unit_key=contract.key
        )
        or authority.get("authority_digest")
        != _canonical_json_digest({
            key: value
            for key, value in authority.items()
            if key != "authority_digest"
        })
    ):
        raise ArtifactLedgerError(
            "driver successor authority receipt is malformed"
        )
    digest = str(authority["authority_digest"])
    cas_unsigned = _read_authority_cas(
        Path(scratchpad),
        digest,
        directory_name=_DRIVER_SUCCESSOR_AUTHORITY_CAS_DIRECTORY,
        label="driver successor authority",
    )
    unsigned = {
        key: value
        for key, value in authority.items()
        if key != "authority_digest"
    }
    journal = _read_driver_successor_authority_ledger(
        Path(scratchpad)
    )
    if (
        cas_unsigned != unsigned
        or journal["authorities"].get(authority["authority_key"])
        != dict(authority)
    ):
        raise ArtifactLedgerError(
            "driver successor authority CAS/journal does not replay"
        )
    try:
        plan = driver_successor_plan_from_dict(
            authority["plan"],
            contract=contract,
            launch=launch,
        )
    except (TypeError, ValueError) as exc:
        raise ArtifactLedgerError(
            f"driver successor plan cannot be decoded: {exc}"
        ) from exc
    if (
        plan.digest != authority.get("plan_digest")
        or plan.to_dict() != authority.get("plan")
    ):
        raise ArtifactLedgerError(
            "driver successor plan digest/manifest differs"
        )
    progress_events = _validated_unit_driver_successor_progress_events(
        Path(scratchpad), unit, authority
    )
    transition_rows = _driver_successor_transition_rows(
        authority["plan"]
    )
    progressed_ordinals = {
        int(event["ordinal"]) for event in progress_events
    }
    progressed_identities = tuple(
        str(row["artifact_identity"])
        for row in transition_rows
        if int(row["ordinal"]) in progressed_ordinals
    )
    records = unit.get("input_bindings")
    prestates = unit.get("output_prestates")
    if not isinstance(records, Mapping) or not isinstance(
        prestates, Mapping
    ):
        raise ArtifactLedgerError(
            "driver successor armed input/prestate denominator is absent"
        )
    affected = authority.get("affected_input_identities")
    if (
        not isinstance(affected, list)
        or affected != sorted(set(affected))
        or any(identity not in records for identity in affected)
    ):
        raise ArtifactLedgerError(
            "driver successor affected-input denominator is malformed"
        )
    for identity, raw in records.items():
        if not isinstance(raw, Mapping):
            raise ArtifactLedgerError(
                "driver successor input binding is malformed"
            )
        plan_marker = raw.get("driver_successor_plan_digest")
        authority_marker = raw.get(
            "driver_successor_authority_digest"
        )
        if identity in affected:
            if (
                plan_marker != authority["plan_digest"]
                or authority_marker != digest
            ):
                raise ArtifactLedgerError(
                    f"{identity}: driver successor input marker differs"
                )
        elif plan_marker is not None or authority_marker is not None:
            raise ArtifactLedgerError(
                f"{identity}: unexpected driver successor input marker"
            )
    if (
        _input_set_digest(dict(records))
        != unit.get("input_set_digest")
        or _input_set_digest(_successor_base_input_records(records))
        != authority.get("input_binding_base_digest")
        or _output_prestate_digest(dict(prestates))
        != authority.get("output_prestate_digest")
    ):
        raise ArtifactLedgerError(
            "driver successor armed denominator digest differs"
        )
    rebind_history, accepted_physical = (
        _validated_driver_successor_physical_rebind_history(
            Path(scratchpad),
            unit,
            authority,
            require_live_prestate=False,
        )
    )
    rebound_identities = {
        str(identity)
        for row in rebind_history
        for identity in row["rebindings"]
    }
    physical_overrides = {
        identity: accepted_physical[identity]
        for identity in sorted(rebound_identities - set(progressed_identities))
    }
    expected_unsigned, expected_affected = (
        _derive_driver_successor_authority_unsigned(
            Path(scratchpad),
            Path(project_root),
            ledger,
            contract,
            launch,
            run_id=run_id,
            plan=plan,
            input_records=records,
            output_prestates=prestates,
            authenticated_progress_identities=progressed_identities,
            authenticated_physical_rebinds=physical_overrides,
        )
    )
    if (
        expected_unsigned != unsigned
        or tuple(affected) != expected_affected
    ):
        raise ArtifactLedgerError(
            "driver successor authority derivation does not replay"
        )
    return dict(authority), plan


def _validated_driver_successor_physical_rebind_history(
    scratchpad: Path,
    unit: Mapping[str, Any],
    authority: Mapping[str, Any],
    *,
    require_live_prestate: bool,
    project_root: Path | None = None,
) -> tuple[list[dict[str, Any]], dict[str, str]]:
    """Replay recovery-only physical identity substitutions.

    Exact predecessor bytes can be restored after a rejected atomic successor
    write, but the replaced directory entry cannot be resurrected.  A recovery
    must therefore bind the replacement identity without changing the original
    output-prestate receipt or silently weakening physical-identity checks.
    """

    raw_history = unit.get("successor_physical_rebind_history", [])
    if (
        not isinstance(raw_history, list)
        or len(raw_history) > 32
        or any(not isinstance(row, Mapping) for row in raw_history)
    ):
        raise ArtifactLedgerError(
            "driver successor physical-rebind history is malformed"
        )
    prestates = unit.get("output_prestates")
    if not isinstance(prestates, Mapping):
        raise ArtifactLedgerError(
            "driver successor physical-rebind prestates are absent"
        )
    recovery_history = _validated_quarantine_recovery_history(
        unit,
        work_unit_key=str(authority.get("work_unit_key") or ""),
        run_id=str(authority.get("run_id") or ""),
    )
    recovery_by_receipt = {
        str(row["prior_commit_authority"]["receipt_digest"]): (
            index,
            row["prior_commit_authority"],
            row,
        )
        for index, row in enumerate(recovery_history, start=1)
    }
    transition_identities = {
        str(row["artifact_identity"])
        for row in _driver_successor_transition_rows(authority.get("plan"))
    }
    active_prestates = {
        str(identity): row
        for identity, row in prestates.items()
        if isinstance(row, Mapping)
        and row.get("status")
        in {"ACTIVE_PREIMAGE", "ACTIVE_REGISTERED_PREDECESSOR"}
    }
    accepted = {
        identity: str(row.get("physical_identity") or "")
        for identity, row in active_prestates.items()
    }
    input_physical = {
        str(row.get("physical_identity") or "")
        for row in (
            unit.get("input_bindings", {}).values()
            if isinstance(unit.get("input_bindings"), Mapping)
            else ()
        )
        if isinstance(row, Mapping) and row.get("physical_identity")
    }
    if (
        len({identity.casefold() for identity in active_prestates})
        != len(active_prestates)
        or set(active_prestates) - transition_identities
        or len(set(accepted.values())) != len(accepted)
    ):
        raise ArtifactLedgerError(
            "driver successor physical-rebind identity denominator differs"
        )
    previous_digest = ""
    previous_recovery_index = 0
    normalized: list[dict[str, Any]] = []
    fields = {
        "schema",
        "run_id",
        "work_unit_key",
        "contract_digest",
        "launch_digest",
        "successor_authority_digest",
        "successor_plan_digest",
        "output_prestate_digest",
        "quarantined_commit_receipt_digest",
        "quarantined_commit_attempt_ordinal",
        "quarantine_recovery_authority_digest",
        "quarantine_recovery_history_count",
        "quarantine_recovery_history_head_digest",
        "ordinal",
        "prior_rebind_authority_digest",
        "rebindings",
        "physical_policy",
        "authority_digest",
    }
    for ordinal, raw in enumerate(raw_history, start=1):
        row = dict(raw)
        rebindings = row.get("rebindings")
        recovery_match = recovery_by_receipt.get(str(
            row.get("quarantined_commit_receipt_digest") or ""
        ))
        recovery_index, prior_commit, recovery_row = (
            recovery_match if recovery_match is not None else (0, {}, {})
        )
        unsigned = {
            key: value
            for key, value in row.items()
            if key != "authority_digest"
        }
        digest = str(row.get("authority_digest") or "")
        if (
            set(row) != fields
            or row.get("schema")
            != _DRIVER_SUCCESSOR_PHYSICAL_REBIND_SCHEMA
            or row.get("run_id") != authority.get("run_id")
            or row.get("work_unit_key") != authority.get("work_unit_key")
            or row.get("contract_digest")
            != authority.get("contract_digest")
            or row.get("launch_digest") != authority.get("launch_digest")
            or row.get("successor_authority_digest")
            != authority.get("authority_digest")
            or row.get("successor_plan_digest")
            != authority.get("plan_digest")
            or row.get("output_prestate_digest")
            != authority.get("output_prestate_digest")
            or row.get("ordinal") != ordinal
            or row.get("prior_rebind_authority_digest")
            != previous_digest
            or row.get("physical_policy") != _NO_FOLLOW_PHYSICAL_POLICY
            or row.get("quarantined_commit_receipt_digest")
            != prior_commit.get("receipt_digest")
            or row.get("quarantined_commit_attempt_ordinal")
            != prior_commit.get("attempt_ordinal")
            or row.get("quarantine_recovery_authority_digest")
            != recovery_row.get("authority_digest")
            or row.get("quarantine_recovery_history_count")
            != recovery_index
            or row.get("quarantine_recovery_history_head_digest")
            != recovery_row.get("authority_digest")
            or recovery_index <= previous_recovery_index
            or not isinstance(rebindings, Mapping)
            or not rebindings
            or len({
                str(identity).casefold() for identity in rebindings
            }) != len(rebindings)
            or digest != _canonical_json_digest(unsigned)
            or _read_authority_cas(
                Path(scratchpad),
                digest,
                directory_name=(
                    _DRIVER_SUCCESSOR_PHYSICAL_REBIND_CAS_DIRECTORY
                ),
                label="driver successor physical rebind",
            )
            != unsigned
        ):
            raise ArtifactLedgerError(
                "driver successor physical-rebind authority does not replay"
            )
        for identity, raw_binding in sorted(rebindings.items()):
            if (
                identity not in active_prestates
                or identity not in transition_identities
                or not isinstance(raw_binding, Mapping)
                or set(raw_binding)
                != {
                    "prior_physical_identity",
                    "replacement_physical_identity",
                    "sha256",
                    "size",
                }
                or raw_binding.get("prior_physical_identity")
                != accepted.get(identity)
                or not isinstance(
                    raw_binding.get("replacement_physical_identity"), str
                )
                or not raw_binding.get("replacement_physical_identity")
                or raw_binding.get("replacement_physical_identity")
                == raw_binding.get("prior_physical_identity")
                or raw_binding.get("replacement_physical_identity")
                in input_physical
                or raw_binding.get("sha256")
                != active_prestates[identity].get("sha256")
                or raw_binding.get("size")
                != active_prestates[identity].get("size")
            ):
                raise ArtifactLedgerError(
                    f"{identity}: driver successor physical rebind differs"
                )
            accepted[identity] = str(
                raw_binding["replacement_physical_identity"]
            )
        if len(set(accepted.values())) != len(accepted):
            raise ArtifactLedgerError(
                "driver successor physical-rebind aliases another output"
            )
        previous_digest = digest
        previous_recovery_index = recovery_index
        normalized.append(row)
    if require_live_prestate:
        if project_root is None:
            raise ArtifactLedgerError(
                "driver successor physical-rebind live root is absent"
            )
        for identity, expected_physical in accepted.items():
            path = _path_for_identity(
                Path(scratchpad), Path(project_root), identity
            )
            prestate = active_prestates[identity]
            if (
                not path.is_file()
                or path.is_symlink()
                or _physical_file_identity(path) != expected_physical
                or path.stat().st_size != prestate.get("size")
                or _sha256(path) != prestate.get("sha256")
            ):
                raise ArtifactLedgerError(
                    f"{identity}: driver successor rebound prestate differs"
                )
    return normalized, accepted


def _issue_driver_successor_physical_rebind(
    scratchpad: Path,
    project_root: Path,
    unit: Mapping[str, Any],
    authority: Mapping[str, Any],
    recovery_history: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    """Append one content-addressed recovery rebind."""

    history, accepted = (
        _validated_driver_successor_physical_rebind_history(
            Path(scratchpad),
            unit,
            authority,
            require_live_prestate=False,
        )
    )
    commit = unit.get("commit_authority")
    prestates = unit.get("output_prestates")
    if (
        unit.get("semantic_status") != "QUARANTINED"
        or unit.get("execution_state") != "OUTPUT_QUARANTINED"
        or not isinstance(commit, Mapping)
        or not _is_digest(commit.get("receipt_digest"))
        or not isinstance(prestates, Mapping)
    ):
        raise ArtifactLedgerError(
            "driver successor physical rebind requires a quarantined commit"
        )
    if (
        not isinstance(recovery_history, Sequence)
        or isinstance(recovery_history, (str, bytes))
        or len(recovery_history) != len(history) + 1
        or not isinstance(recovery_history[-1], Mapping)
        or recovery_history[-1].get("prior_commit_authority") != commit
    ):
        raise ArtifactLedgerError(
            "driver successor physical rebind recovery cause differs"
        )
    rebindings: dict[str, dict[str, Any]] = {}
    for identity, prestate in sorted(prestates.items()):
        if (
            not isinstance(prestate, Mapping)
            or prestate.get("status")
            not in {"ACTIVE_PREIMAGE", "ACTIVE_REGISTERED_PREDECESSOR"}
        ):
            continue
        path = _path_for_identity(
            Path(scratchpad), Path(project_root), str(identity)
        )
        replacement = _physical_file_identity(path)
        prior = accepted.get(str(identity))
        if (
            not prior
            or not path.is_file()
            or path.is_symlink()
            or path.stat().st_size != prestate.get("size")
            or _sha256(path) != prestate.get("sha256")
        ):
            raise ArtifactLedgerError(
                f"{identity}: restored successor prestate cannot be rebound"
            )
        if replacement == prior:
            continue
        rebindings[str(identity)] = {
            "prior_physical_identity": prior,
            "replacement_physical_identity": replacement,
            "sha256": prestate.get("sha256"),
            "size": prestate.get("size"),
        }
    if not rebindings:
        probe = dict(unit)
        probe["quarantine_recovery_history"] = copy.deepcopy(
            list(recovery_history)
        )
        recovery_count, recovery_head = (
            _quarantine_recovery_history_binding(recovery_history)
        )
        probe["quarantine_recovery_history_count"] = recovery_count
        probe["quarantine_recovery_history_head_digest"] = recovery_head
        probe["successor_physical_rebind_history"] = history
        _validated_driver_successor_physical_rebind_history(
            Path(scratchpad),
            probe,
            authority,
            require_live_prestate=True,
            project_root=Path(project_root),
        )
        return history
    unsigned = {
        "schema": _DRIVER_SUCCESSOR_PHYSICAL_REBIND_SCHEMA,
        "run_id": authority.get("run_id"),
        "work_unit_key": authority.get("work_unit_key"),
        "contract_digest": authority.get("contract_digest"),
        "launch_digest": authority.get("launch_digest"),
        "successor_authority_digest": authority.get("authority_digest"),
        "successor_plan_digest": authority.get("plan_digest"),
        "output_prestate_digest": authority.get("output_prestate_digest"),
        "quarantined_commit_receipt_digest": commit.get("receipt_digest"),
        "quarantined_commit_attempt_ordinal": commit.get(
            "attempt_ordinal"
        ),
        "quarantine_recovery_authority_digest": recovery_history[-1][
            "authority_digest"
        ],
        "quarantine_recovery_history_count": len(recovery_history),
        "quarantine_recovery_history_head_digest": recovery_history[-1][
            "authority_digest"
        ],
        "ordinal": len(history) + 1,
        "prior_rebind_authority_digest": (
            history[-1]["authority_digest"] if history else ""
        ),
        "rebindings": rebindings,
        "physical_policy": _NO_FOLLOW_PHYSICAL_POLICY,
    }
    receipt = {
        **unsigned,
        "authority_digest": _canonical_json_digest(unsigned),
    }
    _write_once_authority_cas(
        Path(scratchpad),
        directory_name=(
            _DRIVER_SUCCESSOR_PHYSICAL_REBIND_CAS_DIRECTORY
        ),
        authority_digest=str(receipt["authority_digest"]),
        unsigned_authority=unsigned,
        label="driver successor physical rebind",
    )
    candidate = [*history, receipt]
    probe = dict(unit)
    probe["quarantine_recovery_history"] = copy.deepcopy(
        list(recovery_history)
    )
    probe["successor_physical_rebind_history"] = candidate
    probe["quarantine_recovery_history_count"] = len(recovery_history)
    probe["quarantine_recovery_history_head_digest"] = recovery_history[-1][
        "authority_digest"
    ]
    _validated_driver_successor_physical_rebind_history(
        Path(scratchpad),
        probe,
        authority,
        require_live_prestate=True,
        project_root=Path(project_root),
    )
    return candidate


def _driver_successor_live_state(
    scratchpad: Path,
    project_root: Path,
    identity: str,
) -> dict[str, Any]:
    path = _path_for_identity(
        Path(scratchpad), Path(project_root), identity
    )
    try:
        rooted_io.lstat(path)
    except FileNotFoundError:
        return {
            "status": "MISSING",
            "size": 0,
            "sha256": "",
            "physical_identity": _physical_file_identity(path),
        }
    snapshot, error = _stable_artifact_snapshot(path)
    if snapshot is None or error:
        raise ArtifactLedgerError(
            f"{identity}: driver successor live snapshot is unsafe"
        )
    return {
        "status": "ACTIVE",
        "size": int(snapshot["size"]),
        "sha256": str(snapshot["sha256"]),
        "physical_identity": _physical_file_identity(path),
    }


def _driver_successor_transition_state(
    transition: Mapping[str, Any],
    *,
    after: bool,
) -> dict[str, Any]:
    if after:
        return {
            "status": "ACTIVE",
            "size": int(transition.get("after_size") or 0),
            "sha256": str(transition.get("after_sha256") or ""),
        }
    status = str(transition.get("before_status") or "")
    return {
        "status": status,
        "size": (
            int(transition.get("before_size") or 0)
            if status == "ACTIVE"
            else 0
        ),
        "sha256": (
            str(transition.get("before_sha256") or "")
            if status == "ACTIVE"
            else ""
        ),
    }


def _driver_successor_state_matches(
    live: Mapping[str, Any],
    expected: Mapping[str, Any],
) -> bool:
    return all(
        live.get(field) == expected.get(field)
        for field in ("status", "size", "sha256")
    )


def _validate_driver_successor_live_progress(
    scratchpad: Path,
    project_root: Path,
    ledger: Mapping[str, Any],
    unit: Mapping[str, Any],
    authority: Mapping[str, Any],
    *,
    require_complete: bool,
) -> list[dict[str, Any]]:
    events = _validated_unit_driver_successor_progress_events(
        Path(scratchpad), unit, authority
    )
    progress = _read_driver_successor_progress(Path(scratchpad))
    expected_projection = (
        _driver_successor_progress_projection_from_ledger(
            Path(scratchpad), ledger
        )
    )
    if progress != expected_projection:
        raise ArtifactLedgerError(
            "driver successor progress projection differs from its "
            "ledger-bound head"
        )
    transitions = _driver_successor_transition_rows(
        authority["plan"]
    )
    applied = sum(
        1 for event in events if event["state"] == "STEP_APPLIED"
    )
    armed_ordinal = (
        int(events[-1]["ordinal"])
        if events and events[-1]["state"] == "STEP_ARMED"
        else 0
    )
    if require_complete and (
        applied != len(transitions) or armed_ordinal
    ):
        raise ArtifactLedgerError(
            "driver successor progress is not complete"
        )
    prestates = unit.get("output_prestates")
    if not isinstance(prestates, Mapping):
        raise ArtifactLedgerError(
            "driver successor output prestates are absent"
        )
    _rebind_history, accepted_physical = (
        _validated_driver_successor_physical_rebind_history(
            Path(scratchpad),
            unit,
            authority,
            require_live_prestate=False,
        )
    )
    live_by_identity: dict[str, dict[str, Any]] = {}
    for transition in transitions:
        ordinal = int(transition["ordinal"])
        identity = str(transition["artifact_identity"])
        live = _driver_successor_live_state(
            Path(scratchpad), Path(project_root), identity
        )
        before = _driver_successor_transition_state(
            transition, after=False
        )
        after = _driver_successor_transition_state(
            transition, after=True
        )
        allowed = [after] if ordinal <= applied else [before]
        if ordinal == armed_ordinal:
            allowed = [before, after]
        if not any(
            _driver_successor_state_matches(live, expected)
            for expected in allowed
        ):
            raise ArtifactLedgerError(
                f"{identity}: driver successor live state is outside "
                "the ordered progress prefix"
            )
        prestate = prestates.get(identity)
        if (
            _driver_successor_state_matches(live, before)
            and before["status"] == "ACTIVE"
            and (
                not isinstance(prestate, Mapping)
                or live.get("physical_identity")
                != accepted_physical.get(
                    identity,
                    str(prestate.get("physical_identity") or "")
                    if isinstance(prestate, Mapping)
                    else "",
                )
            )
        ):
            raise ArtifactLedgerError(
                f"{identity}: driver successor preimage physical "
                "identity changed"
            )
        live_by_identity[identity] = live

    bindings = ledger.get("artifact_bindings")
    if not isinstance(bindings, Mapping):
        raise ArtifactLedgerError(
            "driver successor global artifact bindings are absent"
        )
    successor_committed = bool(
        unit.get("semantic_status") == "ACTIVE"
        and unit.get("execution_state") == "OUTPUT_COMMITTED"
    )
    transition_by_identity = {
        str(row["artifact_identity"]): row for row in transitions
    }
    for bundle in authority.get("producer_bundles", ()):
        if not isinstance(bundle, Mapping):
            raise ArtifactLedgerError(
                "driver successor producer bundle is malformed"
            )
        producer_key = str(
            bundle.get("producer_work_unit_key") or ""
        )
        producer = (
            ledger.get("work_units", {}).get(producer_key)
            if isinstance(ledger.get("work_units"), Mapping)
            else None
        )
        artifacts = (
            producer.get("artifacts")
            if isinstance(producer, Mapping)
            else None
        )
        if (
            not isinstance(artifacts, Mapping)
            or _canonical_json_digest(dict(artifacts))
            != bundle.get("producer_output_records_digest")
            or sorted(artifacts)
            != bundle.get("producer_output_identities")
        ):
            raise ArtifactLedgerError(
                "driver successor historical producer output "
                "denominator changed"
            )
        successor_outputs = set(
            bundle.get("successor_output_identities") or ()
        )
        for identity, artifact in artifacts.items():
            if not isinstance(artifact, Mapping):
                raise ArtifactLedgerError(
                    "driver successor producer artifact is malformed"
                )
            binding = bindings.get(identity)
            if not isinstance(binding, Mapping):
                raise ArtifactLedgerError(
                    f"{identity}: driver successor binding is absent"
                )
            if identity not in successor_outputs:
                live = _driver_successor_live_state(
                    Path(scratchpad), Path(project_root), identity
                )
                if (
                    live.get("status") != "ACTIVE"
                    or live.get("sha256") != artifact.get("sha256")
                    or live.get("size") != artifact.get("size")
                    or live.get("physical_identity")
                    != artifact.get("physical_identity")
                    or binding.get("owner_key") != producer_key
                    or binding.get("run_id")
                    != bundle.get("producer_run_id")
                    or binding.get("sha256") != artifact.get("sha256")
                    or binding.get("size") != artifact.get("size")
                ):
                    raise ArtifactLedgerError(
                        f"{identity}: unrelated producer sibling drifted"
                    )
                continue
            transition = transition_by_identity.get(identity)
            live = live_by_identity.get(identity)
            if not isinstance(transition, Mapping) or not isinstance(
                live, Mapping
            ):
                raise ArtifactLedgerError(
                    f"{identity}: driver successor transition is absent"
                )
            after = _driver_successor_transition_state(
                transition, after=True
            )
            if successor_committed:
                if (
                    not _driver_successor_state_matches(live, after)
                    or binding.get("owner_key")
                    != authority.get("work_unit_key")
                    or binding.get("run_id") != authority.get("run_id")
                    or binding.get("contract_digest")
                    != authority.get("contract_digest")
                    or binding.get("launch_digest")
                    != authority.get("launch_digest")
                    or binding.get("sha256") != live.get("sha256")
                    or binding.get("size") != live.get("size")
                ):
                    raise ArtifactLedgerError(
                        f"{identity}: committed successor binding differs"
                    )
            elif (
                binding.get("owner_key") != producer_key
                or binding.get("run_id")
                != bundle.get("producer_run_id")
                or binding.get("sha256") != artifact.get("sha256")
                or binding.get("size") != artifact.get("size")
            ):
                raise ArtifactLedgerError(
                    f"{identity}: precommit producer binding differs"
                )
    return events


def validate_driver_successor_transaction(
    scratchpad: Path,
    project_root: Path,
    contract: PhaseIOContract,
    launch: LaunchSpec,
    *,
    run_id: str,
    require_complete: bool = False,
) -> list[str]:
    try:
        contract, launch = _replay_authority_pair(contract, launch)
        ledger = read_artifact_ledger(Path(scratchpad))
        unit = ledger.get("work_units", {}).get(contract.key)
        if not isinstance(unit, Mapping):
            raise ArtifactLedgerError(
                "driver successor armed work unit is absent"
            )
        authority, _plan = _replay_driver_successor_authority(
            Path(scratchpad),
            Path(project_root),
            ledger,
            unit,
            contract,
            launch,
            run_id=run_id,
        )
        _validate_driver_successor_live_progress(
            Path(scratchpad),
            Path(project_root),
            ledger,
            unit,
            authority,
            require_complete=require_complete,
        )
    except (
        ArtifactLedgerError,
        KeyError,
        OSError,
        TypeError,
        ValueError,
    ) as exc:
        return [
            f"{contract.key}: driver successor transaction invalid: "
            f"{type(exc).__name__}: {exc}"
        ]
    return []


def load_driver_successor_plan(
    scratchpad: Path,
    project_root: Path,
    contract: PhaseIOContract,
    launch: LaunchSpec,
    *,
    run_id: str,
) -> DriverSuccessorPlan:
    """Replay and return an already-armed successor plan for exact resume."""

    contract, launch = _replay_authority_pair(contract, launch)
    run = str(run_id or "").strip()
    if not run:
        raise ArtifactLedgerError(
            "driver successor resume run_id must be non-empty"
        )
    with _ledger_transaction_lock(Path(scratchpad)):
        ledger = read_artifact_ledger(Path(scratchpad))
        unit = ledger.get("work_units", {}).get(contract.key)
        if not isinstance(unit, Mapping):
            raise ArtifactLedgerError(
                "driver successor armed work unit is absent"
            )
        authority, plan = _replay_driver_successor_authority(
            Path(scratchpad),
            Path(project_root),
            ledger,
            unit,
            contract,
            launch,
            run_id=run,
        )
        _synchronize_driver_successor_progress_projection(
            Path(scratchpad), ledger
        )
        _validate_driver_successor_live_progress(
            Path(scratchpad),
            Path(project_root),
            ledger,
            unit,
            authority,
            require_complete=False,
        )
        return plan


def begin_driver_successor_step(
    scratchpad: Path,
    project_root: Path,
    contract: PhaseIOContract,
    launch: LaunchSpec,
    *,
    run_id: str,
    ordinal: int,
) -> dict[str, Any]:
    contract, launch = _replay_authority_pair(contract, launch)
    with _ledger_transaction_lock(Path(scratchpad)):
        ledger = read_artifact_ledger(Path(scratchpad))
        unit = ledger.get("work_units", {}).get(contract.key)
        if not isinstance(unit, Mapping):
            raise ArtifactLedgerError(
                "driver successor arm is absent"
            )
        authority, _plan = _replay_driver_successor_authority(
            Path(scratchpad),
            Path(project_root),
            ledger,
            unit,
            contract,
            launch,
            run_id=run_id,
        )
        _synchronize_driver_successor_progress_projection(
            Path(scratchpad), ledger
        )
        events = _validate_driver_successor_live_progress(
            Path(scratchpad),
            Path(project_root),
            ledger,
            unit,
            authority,
            require_complete=False,
        )
        transitions = _driver_successor_transition_rows(
            authority["plan"]
        )
        if (
            not isinstance(ordinal, int)
            or isinstance(ordinal, bool)
            or ordinal < 1
            or ordinal > len(transitions)
        ):
            raise ArtifactLedgerError(
                "driver successor step ordinal is invalid"
            )
        applied_by_ordinal = {
            int(event["ordinal"]): event
            for event in events
            if event["state"] == "STEP_APPLIED"
        }
        if ordinal in applied_by_ordinal:
            return dict(applied_by_ordinal[ordinal])
        if events and events[-1]["state"] == "STEP_ARMED":
            if int(events[-1]["ordinal"]) != ordinal:
                raise ArtifactLedgerError(
                    "another driver successor step is already armed"
                )
            return dict(events[-1])
        expected = len(applied_by_ordinal) + 1
        if ordinal != expected:
            raise ArtifactLedgerError(
                "driver successor step would branch or reorder progress"
            )
        return _append_driver_successor_progress_event(
            Path(scratchpad),
            ledger,
            unit,
            authority,
            ordinal=ordinal,
            state="STEP_ARMED",
        )


def complete_driver_successor_step(
    scratchpad: Path,
    project_root: Path,
    contract: PhaseIOContract,
    launch: LaunchSpec,
    *,
    run_id: str,
    ordinal: int,
) -> dict[str, Any]:
    contract, launch = _replay_authority_pair(contract, launch)
    with _ledger_transaction_lock(Path(scratchpad)):
        ledger = read_artifact_ledger(Path(scratchpad))
        unit = ledger.get("work_units", {}).get(contract.key)
        if not isinstance(unit, Mapping):
            raise ArtifactLedgerError(
                "driver successor arm is absent"
            )
        authority, _plan = _replay_driver_successor_authority(
            Path(scratchpad),
            Path(project_root),
            ledger,
            unit,
            contract,
            launch,
            run_id=run_id,
        )
        _synchronize_driver_successor_progress_projection(
            Path(scratchpad), ledger
        )
        events = _validate_driver_successor_live_progress(
            Path(scratchpad),
            Path(project_root),
            ledger,
            unit,
            authority,
            require_complete=False,
        )
        transitions = _driver_successor_transition_rows(
            authority["plan"]
        )
        if (
            not isinstance(ordinal, int)
            or isinstance(ordinal, bool)
            or ordinal < 1
            or ordinal > len(transitions)
        ):
            raise ArtifactLedgerError(
                "driver successor step ordinal is invalid"
            )
        for event in events:
            if (
                event["state"] == "STEP_APPLIED"
                and event["ordinal"] == ordinal
            ):
                return dict(event)
        if (
            not events
            or events[-1]["state"] != "STEP_ARMED"
            or events[-1]["ordinal"] != ordinal
        ):
            raise ArtifactLedgerError(
                "driver successor step was not armed"
            )
        transition = transitions[ordinal - 1]
        live = _driver_successor_live_state(
            Path(scratchpad),
            Path(project_root),
            str(transition["artifact_identity"]),
        )
        if not _driver_successor_state_matches(
            live,
            _driver_successor_transition_state(
                transition, after=True
            ),
        ):
            raise ArtifactLedgerError(
                "driver successor step postimage differs from plan"
            )
        return _append_driver_successor_progress_event(
            Path(scratchpad),
            ledger,
            unit,
            authority,
            ordinal=ordinal,
            state="STEP_APPLIED",
        )


def semantic_import_authority(
    scratchpad: Path,
    project_root: Path,
    identity: str,
    *,
    run_id: str,
) -> dict[str, Any]:
    """Return exact current-run authority for one deterministic import.

    Unlike :func:`semantic_input_prebind_producer_authority_issues`, this
    boundary deliberately accepts a semantic-mutation successor, but only
    after replaying the same-run contiguous arm-before-write chain from the
    historical committed producer to the current bytes.  The returned record
    is suitable for inclusion in a content-addressed projection receipt; it
    does not grant the mutable root new PhaseIO ownership.
    """

    root = Path(scratchpad)
    project = Path(project_root)
    run = str(run_id or "").strip()
    normalized = str(identity or "").strip()
    if not run or not normalized:
        raise ArtifactLedgerError(
            "semantic import identity/run_id is absent"
        )
    ledger = read_artifact_ledger(root)
    record = _input_binding_record(
        root,
        project,
        normalized,
        "IMMUTABLE",
        ledger,
    )
    producer_key = str(record.get("producer_work_unit_key") or "")
    producer_digest = str(record.get("producer_contract_digest") or "")
    if not producer_key.startswith("semantic-mutation:"):
        issues = semantic_input_producer_authority_issues(
            ledger,
            record,
            run_id=run,
        )
        if issues:
            raise ArtifactLedgerError("; ".join(issues))
        return {
            "schema_version": "plamen.semantic_import_authority.v1",
            "identity": normalized,
            "run_id": run,
            "authority_kind": "EXACT_PHASE_IO_PRODUCER",
            "producer_work_unit_key": producer_key,
            "producer_contract_digest": producer_digest,
            "source_sha256": str(record.get("sha256") or ""),
            "source_size": int(record.get("size") or 0),
            "mutation_event_ids": [],
            "mutation_authority_digests": [],
        }

    binding = ledger.get("artifact_bindings", {}).get(normalized)
    if not isinstance(binding, dict):
        raise ArtifactLedgerError(
            f"{normalized}: historical producer binding is absent"
        )
    live_state = _semantic_artifact_state(root, project, normalized)
    authority = _semantic_mutation_producer_authority(
        root,
        project_root=project,
        identity=normalized,
        producer=binding,
        live_state=live_state,
    )
    if (
        authority is None
        or authority.get("producer_work_unit_key") != producer_key
        or authority.get("producer_contract_digest") != producer_digest
    ):
        raise ArtifactLedgerError(
            f"{normalized}: semantic mutation chain is not same-run, "
            "contiguous, and terminal"
        )
    rows = [
        row
        for row in semantic_mutation_events(root)
        if (
            row.get("artifact_identity") == normalized
            and row.get("run_id") == run
        )
    ]
    event_id = producer_key[len("semantic-mutation:"):]
    terminal_indexes = [
        index
        for index, row in enumerate(rows)
        if row.get("event_id") == event_id
    ]
    if len(terminal_indexes) != 1:
        raise ArtifactLedgerError(
            f"{normalized}: semantic mutation terminal event is ambiguous"
        )
    terminal = terminal_indexes[0]
    relevant = rows[: terminal + 1]
    started = False
    current = {
        "status": "ACTIVE",
        "size": binding.get("size"),
        "sha256": str(binding.get("sha256") or ""),
    }
    accepted: list[dict[str, Any]] = []
    for row in relevant:
        if not started:
            if row.get("before") != current:
                continue
            started = True
        elif row.get("before") != current:
            raise ArtifactLedgerError(
                f"{normalized}: semantic mutation chain is non-contiguous"
            )
        if row.get("status") not in {
            "NO_CHANGE",
            "INVALIDATION_APPLIED",
        }:
            raise ArtifactLedgerError(
                f"{normalized}: semantic mutation chain is not terminal"
            )
        after = row.get("after")
        if not isinstance(after, dict):
            raise ArtifactLedgerError(
                f"{normalized}: semantic mutation postimage is malformed"
            )
        current = dict(after)
        accepted.append(row)
    if (
        not accepted
        or accepted[-1].get("event_id") != event_id
        or current != live_state
    ):
        raise ArtifactLedgerError(
            f"{normalized}: semantic mutation chain does not end at live bytes"
        )
    return {
        "schema_version": "plamen.semantic_import_authority.v1",
        "identity": normalized,
        "run_id": run,
        "authority_kind": "CONTIGUOUS_SEMANTIC_MUTATION_CHAIN",
        "producer_work_unit_key": producer_key,
        "producer_contract_digest": producer_digest,
        "source_sha256": str(record.get("sha256") or ""),
        "source_size": int(record.get("size") or 0),
        "mutation_event_ids": [
            str(row.get("event_id") or "") for row in accepted
        ],
        "mutation_authority_digests": [
            semantic_mutation_authority_digest(row) for row in accepted
        ],
    }


def semantic_import_authority_from_snapshot(
    ledger: Mapping[str, Any],
    mutation_payload: Mapping[str, Any] | None,
    identity: str,
    source_binding: Mapping[str, Any],
    *,
    run_id: str,
) -> dict[str, Any]:
    """Replay one semantic import from immutable input/control snapshots.

    Frozen projections must remain verifiable after their mutable source file
    or acknowledgement-only mutation-ledger fields advance.  This pure
    variant therefore consumes the exact provider input binding plus the
    mutation-ledger preimage captured by that provider, instead of rereading
    current source bytes.
    """

    normalized = str(identity or "").strip()
    run = str(run_id or "").strip()
    binding = dict(source_binding)
    producer_key = str(binding.get("producer_work_unit_key") or "")
    producer_digest = str(
        binding.get("producer_contract_digest") or ""
    )
    if (
        not normalized
        or not run
        or binding.get("identity") != normalized
        or binding.get("status") != "ACTIVE"
        or not _is_digest(binding.get("sha256"))
        or not _is_nonnegative_exact_int(binding.get("size"))
        or not producer_key
        or not _is_digest(producer_digest)
    ):
        raise ArtifactLedgerError(
            f"{normalized}: frozen semantic import binding is malformed"
        )
    if not producer_key.startswith("semantic-mutation:"):
        issues = semantic_input_producer_authority_issues(
            ledger,
            binding,
            run_id=run,
        )
        if issues:
            raise ArtifactLedgerError("; ".join(issues))
        return {
            "schema_version": "plamen.semantic_import_authority.v1",
            "identity": normalized,
            "run_id": run,
            "authority_kind": "EXACT_PHASE_IO_PRODUCER",
            "producer_work_unit_key": producer_key,
            "producer_contract_digest": producer_digest,
            "source_sha256": str(binding["sha256"]),
            "source_size": int(binding["size"]),
            "mutation_event_ids": [],
            "mutation_authority_digests": [],
        }

    if (
        not isinstance(mutation_payload, Mapping)
        or mutation_payload.get("schema")
        != "plamen.semantic_mutations.v1"
        or not isinstance(mutation_payload.get("events"), list)
    ):
        raise ArtifactLedgerError(
            f"{normalized}: frozen semantic mutation snapshot is malformed"
        )
    historical = (
        ledger.get("artifact_bindings", {}).get(normalized)
        if isinstance(ledger.get("artifact_bindings"), Mapping)
        else None
    )
    if (
        not isinstance(historical, Mapping)
        or historical.get("status") != "ACTIVE"
        or historical.get("run_id") != run
        or not str(historical.get("owner_key") or "")
        or not _is_digest(historical.get("contract_digest"))
        or not _is_digest(historical.get("sha256"))
        or not _is_nonnegative_exact_int(historical.get("size"))
    ):
        raise ArtifactLedgerError(
            f"{normalized}: historical producer snapshot is unavailable"
        )
    terminal_id = producer_key.removeprefix("semantic-mutation:")
    current = {
        "status": "ACTIVE",
        "size": historical.get("size"),
        "sha256": str(historical.get("sha256") or ""),
    }
    accepted: list[Mapping[str, Any]] = []
    started = False
    terminal_seen = False
    relevant = [
        event
        for event in mutation_payload["events"]
        if (
            isinstance(event, Mapping)
            and event.get("artifact_identity") == normalized
            and event.get("run_id") == run
        )
    ]
    for event in relevant:
        raw_event = dict(event)
        if (
            raw_event.get("schema") != "plamen.semantic_mutation.v1"
            or raw_event.get("event_digest")
            != _mutation_event_digest(raw_event)
        ):
            raise ArtifactLedgerError(
                f"{normalized}: frozen semantic mutation event is invalid"
            )
        before = raw_event.get("before")
        if (
            not isinstance(before, Mapping)
            or not _valid_semantic_artifact_snapshot(dict(before))
        ):
            raise ArtifactLedgerError(
                f"{normalized}: frozen semantic mutation preimage is "
                "malformed"
            )
        if not started:
            if before != current:
                continue
            started = True
        elif before != current:
            raise ArtifactLedgerError(
                f"{normalized}: frozen semantic mutation chain is "
                "non-contiguous"
            )
        if raw_event.get("status") not in {
            "NO_CHANGE",
            "INVALIDATION_APPLIED",
        }:
            raise ArtifactLedgerError(
                f"{normalized}: frozen semantic mutation is not terminal"
            )
        after = raw_event.get("after")
        if (
            not isinstance(after, Mapping)
            or not _valid_semantic_artifact_snapshot(dict(after))
            or after.get("status") != "ACTIVE"
        ):
            raise ArtifactLedgerError(
                f"{normalized}: frozen semantic mutation postimage is "
                "malformed"
            )
        current = dict(after)
        accepted.append(raw_event)
        if raw_event.get("event_id") == terminal_id:
            terminal_seen = True
            break
    expected_live = {
        "status": "ACTIVE",
        "size": binding["size"],
        "sha256": str(binding["sha256"]),
    }
    if (
        not started
        or not terminal_seen
        or not accepted
        or current != expected_live
    ):
        raise ArtifactLedgerError(
            f"{normalized}: frozen semantic mutation snapshot does not end "
            "at the provider source bytes"
        )
    authority_digests = [
        semantic_mutation_authority_digest(dict(event))
        for event in accepted
    ]
    authority_core = _semantic_virtual_producer_core(
        identity=normalized,
        run_id=run,
        producer=historical,
        mutation_event_ids=[
            str(event.get("event_id") or "")
            for event in accepted
        ],
        mutation_authority_digests=authority_digests,
        live_state={
            "size": int(binding["size"]),
            "sha256": str(binding["sha256"]),
        },
    )
    expected_virtual_digest = _semantic_virtual_producer_digest(
        authority_core
    )
    if producer_digest != expected_virtual_digest:
        raise ArtifactLedgerError(
            f"{normalized}: frozen semantic mutation virtual producer "
            "digest differs"
        )
    return {
        "schema_version": "plamen.semantic_import_authority.v1",
        "identity": normalized,
        "run_id": run,
        "authority_kind": "CONTIGUOUS_SEMANTIC_MUTATION_CHAIN",
        "producer_work_unit_key": producer_key,
        "producer_contract_digest": producer_digest,
        "source_sha256": str(binding["sha256"]),
        "source_size": int(binding["size"]),
        "mutation_event_ids": [
            str(event.get("event_id") or "")
            for event in accepted
        ],
        "mutation_authority_digests": authority_digests,
    }


def _explicit_absence_receipt_digest(value: Mapping[str, Any]) -> str:
    unsigned = {
        key: item for key, item in value.items()
        if key != "receipt_digest"
    }
    return hashlib.sha256(
        json.dumps(
            unsigned,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def _absence_identity(value: Any) -> str:
    text = str(value or "").strip().replace("\\", "/")
    if text.startswith("scratchpad:"):
        return canonical_artifact_identity(
            "scratchpad", text[len("scratchpad:"):]
        )
    if text.startswith("project:"):
        return canonical_artifact_identity("project", text[len("project:"):])
    return canonical_artifact_identity("scratchpad", text)


def record_work_unit_explicit_absence_bindings(
    scratchpad: Path,
    project_root: Path,
    contract: PhaseIOContract,
    launch: LaunchSpec,
    *,
    run_id: str,
    presence_roster: Sequence[str],
) -> dict[str, Any]:
    """Bind an exact optional-input roster, including durable absences."""

    contract, launch = _replay_authority_pair(contract, launch)
    run = str(run_id or "").strip()
    if not run:
        raise ArtifactLedgerError("absence run_id is absent")
    if not isinstance(presence_roster, Sequence) or isinstance(
        presence_roster, (str, bytes)
    ):
        raise ArtifactLedgerError("explicit absence roster is malformed")
    roster = tuple(sorted({_absence_identity(value) for value in presence_roster}))
    if len(roster) != len(presence_roster):
        raise ArtifactLedgerError("explicit absence roster contains duplicates")
    contract_inputs = set(contract.immutable_inputs) | set(
        contract.bounded_lookup_inputs
    )
    present = tuple(sorted(set(roster) & contract_inputs))
    absent = tuple(sorted(set(roster) - set(present)))
    if not set(present).issubset(contract_inputs):
        raise ArtifactLedgerError(
            "explicit presence roster escapes the contract denominator"
        )
    for identity in absent:
        path = _path_for_identity(
            Path(scratchpad), Path(project_root), identity
        )
        try:
            rooted_io.lstat(path)
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise ArtifactLedgerError(
                f"{identity}: explicit absence prestate is unreadable: {exc}"
            ) from exc
        raise ArtifactLedgerError(
            f"{identity}: explicit absence prestate acquired bytes"
        )
    unsigned: dict[str, Any] = {
        "schema": "plamen.explicit-input-absence.v1",
        "work_unit_key": contract.key,
        "run_id": run,
        "contract_digest": contract.digest,
        "launch_digest": launch.digest,
        "roster_identities": list(roster),
        "roster_identity_digest": hashlib.sha256(
            json.dumps(
                list(roster),
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest(),
        "present_identities": list(present),
        "absent_identities": list(absent),
    }
    receipt = {
        **unsigned,
        "receipt_digest": _explicit_absence_receipt_digest(unsigned),
    }
    with _ledger_transaction_lock(scratchpad):
        ledger = read_artifact_ledger(scratchpad)
        unit = ledger.get("work_units", {}).get(contract.key)
        if (
            not isinstance(unit, dict)
            or unit.get("run_id") != run
            or unit.get("contract_digest") != contract.digest
            or not _stored_launch_matches(unit, launch)
            or unit.get("semantic_status") not in {"INPUTS_BOUND", "ACTIVE"}
        ):
            raise ArtifactLedgerError(
                f"{contract.key}: cannot attach absence authority before "
                "exact input binding"
            )
        prior = unit.get("explicit_absence_authority")
        if prior is not None and prior != receipt:
            raise ArtifactLedgerError(
                f"{contract.key}: explicit absence authority drifted"
            )
        unit = dict(unit)
        unit["explicit_absence_authority"] = receipt
        ledger["work_units"][contract.key] = unit
        write_artifact_ledger(scratchpad, ledger)
    return receipt


def validate_work_unit_explicit_absence_bindings(
    scratchpad: Path,
    project_root: Path,
    contract: PhaseIOContract,
    launch: LaunchSpec,
    *,
    run_id: str,
    require: bool = False,
    _validation_context: _ArtifactValidationContext | None = None,
) -> list[str]:
    """Reject late appearance or corruption of a bound absence roster."""

    try:
        contract, launch = _replay_authority_pair(contract, launch)
        ledger = (
            read_artifact_ledger(scratchpad)
            if _validation_context is None
            else _validation_context.ledger
        )
    except ArtifactLedgerError as exc:
        return [f"explicit absence ledger/authority is invalid: {exc}"]
    unit = ledger.get("work_units", {}).get(contract.key)
    if not isinstance(unit, Mapping) or not _stored_launch_matches(
        unit, launch
    ):
        return [f"{contract.key}: explicit absence launch authority invalid"]
    receipt = (
        unit.get("explicit_absence_authority")
        if isinstance(unit, Mapping)
        else None
    )
    if receipt is None:
        return (
            [f"{contract.key}: explicit absence authority is missing"]
            if require
            else []
        )
    issues: list[str] = []
    if not isinstance(receipt, Mapping):
        return [f"{contract.key}: explicit absence authority is malformed"]
    roster = receipt.get("roster_identities")
    present = receipt.get("present_identities")
    absent = receipt.get("absent_identities")
    if (
        receipt.get("schema") != "plamen.explicit-input-absence.v1"
        or receipt.get("work_unit_key") != contract.key
        or receipt.get("run_id") != run_id
        or receipt.get("contract_digest") != contract.digest
        or receipt.get("launch_digest") != launch.digest
        or receipt.get("receipt_digest")
        != _explicit_absence_receipt_digest(receipt)
        or not isinstance(roster, list)
        or roster != sorted(set(roster))
        or not isinstance(present, list)
        or present != sorted(set(present))
        or not isinstance(absent, list)
        or absent != sorted(set(absent))
        or set(roster) != set(present) | set(absent)
        or set(present) & set(absent)
    ):
        return [f"{contract.key}: explicit absence authority digest/roster invalid"]
    expected_roster_digest = hashlib.sha256(
        json.dumps(
            roster,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    if receipt.get("roster_identity_digest") != expected_roster_digest:
        issues.append(
            f"{contract.key}: explicit absence roster digest mismatch"
        )
    contract_inputs = set(contract.immutable_inputs) | set(
        contract.bounded_lookup_inputs
    )
    if not set(present).issubset(contract_inputs):
        issues.append(
            f"{contract.key}: explicit present roster escapes input denominator"
        )
    for identity in absent:
        try:
            path = (
                _path_for_identity(
                    Path(scratchpad), Path(project_root), str(identity)
                )
                if _validation_context is None
                else _validation_context.path_for_identity(str(identity))
            )
            rooted_io.lstat(path)
        except FileNotFoundError:
            continue
        except (ArtifactLedgerError, OSError) as exc:
            issues.append(
                f"{identity}: explicit absence revalidation failed: {exc}"
            )
        else:
            issues.append(
                f"{identity}: explicit absence presence drift; file appeared"
            )
    return list(dict.fromkeys(issues))


def _precommit_issue_receipt(values: Sequence[str]) -> dict[str, Any]:
    """Bound diagnostic prose without dropping its exact canonical denominator."""

    normalized = sorted({
        str(value).strip() for value in values if str(value).strip()
    })
    digest = hashlib.sha256(
        json.dumps(
            normalized, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")
    ).hexdigest()
    sample_limit = 64
    value_limit = 2000
    sample = [
        value
        if len(value) <= value_limit
        else value[: value_limit - 32] + "...[TRUNCATED:" + hashlib.sha256(
            value.encode("utf-8")
        ).hexdigest()[:16] + "]"
        for value in normalized[:sample_limit]
    ]
    return {
        "sample": sample,
        "count": len(normalized),
        "digest": digest,
        "overflow": max(0, len(normalized) - len(sample)),
    }


def _producer_binding_commit_issues(
    ledger: dict[str, Any],
    recorded: Mapping[str, Any],
    current: Mapping[str, Any],
    *,
    run_id: str,
) -> set[str]:
    """Defense-in-depth check of an input's exact producer authority."""

    issues: set[str] = set()
    producer_key = str(recorded.get("producer_work_unit_key") or "")
    producer_digest = str(recorded.get("producer_contract_digest") or "")
    if not producer_key:
        if producer_digest:
            issues.add("INPUT_PRODUCER_IDENTITY_MALFORMED")
        return issues
    if producer_key.startswith("semantic-mutation:"):
        # _input_binding_record validated the durable arm-before-write chain
        # and returned its digest-bound synthetic authority.
        if (
            current.get("producer_work_unit_key") != producer_key
            or current.get("producer_contract_digest") != producer_digest
        ):
            issues.add("INPUT_PRODUCER_AUTHORITY_CHANGED")
        return issues
    binding = ledger.get("artifact_bindings", {}).get(recorded.get("identity"))
    if (
        not isinstance(binding, dict)
        or not _producer_authority_is_active(
            ledger,
            binding,
            identity=str(recorded.get("identity") or ""),
            run_id=run_id,
        )
        or binding.get("contract_digest") != producer_digest
    ):
        issues.add("INPUT_PRODUCER_UNIT_NOT_ACTIVE")
    if (
        not isinstance(binding, dict)
        or binding.get("owner_key") != producer_key
        or binding.get("contract_digest") != producer_digest
        or binding.get("run_id") != run_id
        or binding.get("status") != "ACTIVE"
        or binding.get("sha256") != recorded.get("sha256")
        or binding.get("size") != recorded.get("size")
    ):
        issues.add("INPUT_PRODUCER_BINDING_MISMATCH")
    return issues


def _semantic_output_prestate_commit_issues(
    scratchpad: Path,
    project_root: Path,
    ledger: Mapping[str, Any],
    spec: Any,
    prestate: Mapping[str, Any],
    *,
    run_id: str,
    merge_event: DriverMergeEvent | None = None,
) -> set[str]:
    """Revalidate a mutation-current REPLACE prestate at commit time.

    The canonical file is already allowed to hold the successor when this
    check runs, so validation cannot reread the old bytes. Instead it replays
    the exact digest-bound semantic lineage captured at arm time from the
    still-active historical producer to the recorded prestate. Any missing,
    reordered, cross-run, branching, or changed event removes authority.
    """

    if prestate.get("status") != "ACTIVE_REGISTERED_SEMANTIC_PREDECESSOR":
        return set()
    codes: set[str] = set()
    identity = str(prestate.get("identity") or "")
    authority = prestate.get("semantic_predecessor_authority")
    required = {
        "identity",
        "run_id",
        "historical_owner_key",
        "historical_contract_digest",
        "historical_launch_digest",
        "historical_size",
        "historical_sha256",
        "mutation_event_ids",
        "mutation_authority_digests",
        "live_size",
        "live_sha256",
        "authority_digest",
        "terminal_event_id",
    }
    if not isinstance(authority, Mapping) or set(authority) != required:
        return {"SEMANTIC_OUTPUT_PRESTATE_AUTHORITY_MALFORMED"}
    core = {
        key: authority[key]
        for key in required - {"authority_digest", "terminal_event_id"}
    }
    try:
        digest = hashlib.sha256(
            json.dumps(
                core,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            ).encode("utf-8")
        ).hexdigest()
    except (TypeError, ValueError):
        return {"SEMANTIC_OUTPUT_PRESTATE_AUTHORITY_MALFORMED"}
    event_ids = authority.get("mutation_event_ids")
    event_digests = authority.get("mutation_authority_digests")
    if (
        digest != authority.get("authority_digest")
        or authority.get("identity") != identity
        or authority.get("run_id") != run_id
        or authority.get("live_sha256") != prestate.get("sha256")
        or authority.get("live_size") != prestate.get("size")
        or not isinstance(event_ids, list)
        or not event_ids
        or not isinstance(event_digests, list)
        or len(event_ids) != len(event_digests)
        or authority.get("terminal_event_id") != event_ids[-1]
        or any(not str(value or "") for value in event_ids)
        or any(not _is_digest(value) for value in event_digests)
    ):
        codes.add("SEMANTIC_OUTPUT_PRESTATE_AUTHORITY_MALFORMED")
        return codes
    binding = (
        ledger.get("artifact_bindings", {}).get(identity)
        if isinstance(ledger.get("artifact_bindings"), Mapping)
        else None
    )
    if not (
        isinstance(binding, Mapping)
        and binding.get("owner_key")
        == authority.get("historical_owner_key")
        and binding.get("contract_digest")
        == authority.get("historical_contract_digest")
        and binding.get("launch_digest")
        == authority.get("historical_launch_digest")
        and binding.get("sha256") == authority.get("historical_sha256")
        and binding.get("size") == authority.get("historical_size")
        and binding.get("run_id") == run_id
        and _producer_authority_is_active(
            ledger, binding, identity=identity, run_id=run_id
        )
        and _registered_projection_handoff(binding, spec)
    ):
        codes.add("SEMANTIC_OUTPUT_PRESTATE_HISTORICAL_PRODUCER_CHANGED")
        return codes
    try:
        mutation_payload = _read_semantic_mutations(Path(scratchpad))
    except ArtifactLedgerError:
        return {"SEMANTIC_OUTPUT_PRESTATE_LEDGER_UNREADABLE"}
    rows = [
        row
        for row in mutation_payload.get("events", [])
        if isinstance(row, Mapping)
        and row.get("artifact_identity") == identity
        and row.get("run_id") == run_id
    ]
    by_id = {
        str(row.get("event_id") or ""): row
        for row in rows
        if str(row.get("event_id") or "")
    }
    selected: list[Mapping[str, Any]] = []
    for event_id, event_digest in zip(event_ids, event_digests):
        row = by_id.get(str(event_id))
        if (
            row is None
            or semantic_mutation_authority_digest(dict(row)) != event_digest
        ):
            codes.add("SEMANTIC_OUTPUT_PRESTATE_EVENT_CHANGED")
            return codes
        selected.append(row)
    positions = [rows.index(row) for row in selected]
    if positions != sorted(positions) or len(set(positions)) != len(positions):
        codes.add("SEMANTIC_OUTPUT_PRESTATE_EVENT_ORDER_CHANGED")
        return codes
    current = {
        "status": "ACTIVE",
        "size": authority["historical_size"],
        "sha256": authority["historical_sha256"],
    }
    for row in selected:
        if (
            row.get("before") != current
            or row.get("status") not in {"NO_CHANGE", "INVALIDATION_APPLIED"}
            or not isinstance(row.get("after"), Mapping)
        ):
            codes.add("SEMANTIC_OUTPUT_PRESTATE_CHAIN_INVALID")
            return codes
        current = dict(row["after"])
    expected_terminal = {
        "status": "ACTIVE",
        "size": prestate.get("size"),
        "sha256": prestate.get("sha256"),
    }
    if current != expected_terminal:
        codes.add("SEMANTIC_OUTPUT_PRESTATE_TERMINAL_MISMATCH")
        return codes
    advancements = [
        later
        for later in rows[positions[-1] + 1:]
        if later.get("before") == expected_terminal
        and later.get("status") in {"NO_CHANGE", "INVALIDATION_APPLIED"}
    ]
    if advancements:
        # A report MERGE transaction journals its own arm-before-write
        # successor after this output prestate was sealed.  That one exact
        # authenticated transition is the expected commit, not foreign drift.
        # Bind it to the caller's DriverMergeEvent and independently replay the
        # durable report-transaction receipt.  Any second transition, changed
        # event, non-report mutation, or mismatched postimage remains debt.
        own_successor = len(advancements) == 1 and isinstance(
            merge_event, DriverMergeEvent
        )
        later = advancements[0]
        after = later.get("after")
        own_successor = bool(
            own_successor
            and merge_event.artifact_identity == identity
            and merge_event.before_sha256 == prestate.get("sha256")
            and isinstance(after, Mapping)
            and after.get("status") == "ACTIVE"
            and merge_event.after_sha256 == after.get("sha256")
            and _is_nonnegative_exact_int(after.get("size"))
        )
        if own_successor and identity == "project:AUDIT_REPORT.md":
            try:
                from report_mutation_transaction import (
                    validate_report_transaction_semantic_successor,
                )

                own_successor = (
                    validate_report_transaction_semantic_successor(
                        scratchpad=Path(scratchpad),
                        project_root=Path(project_root),
                        event=later,
                    )
                )
            except (ImportError, RuntimeError, TypeError, ValueError):
                own_successor = False
        if not own_successor:
            codes.add("SEMANTIC_OUTPUT_PRESTATE_ADVANCED_AFTER_ARM")
    return codes


def _output_commit_authority_issues(
    scratchpad: Path,
    project_root: Path,
    ledger: dict[str, Any],
    prior_unit: dict[str, Any] | None,
    contract: PhaseIOContract,
    launch: LaunchSpec,
    *,
    run_id: str,
    precommit_issues: Sequence[str],
    merge_events: Mapping[str, DriverMergeEvent] | None = None,
    _validation_context: _ArtifactValidationContext | None = None,
) -> tuple[set[str], list[str], dict[str, dict[str, Any]], str]:
    """Validate the stored receipt and live denominator from one ledger view."""

    codes: set[str] = set()
    issue_receipt = _precommit_issue_receipt(precommit_issues)
    details = list(issue_receipt["sample"])
    expected = set(contract.immutable_inputs) | set(contract.bounded_lookup_inputs)
    zero_kind = ""
    records: dict[str, dict[str, Any]] = {}
    if issue_receipt["count"]:
        codes.add("CALLER_PRECOMMIT_ISSUES")
    if prior_unit is None:
        codes.add("MISSING_PREEXECUTION_INPUT_RECEIPT")
        return codes, details, records, zero_kind

    if prior_unit.get("schema") != "plamen.artifact-work-unit.v2":
        codes.add("WORK_UNIT_SCHEMA_MISMATCH")
    if prior_unit.get("work_unit_key") != contract.key:
        codes.add("WORK_UNIT_KEY_MISMATCH")
    if prior_unit.get("run_id") != run_id:
        codes.add("RUN_ID_MISMATCH")
    if prior_unit.get("contract_digest") != contract.digest:
        codes.add("CONTRACT_DIGEST_MISMATCH")
    manifest = prior_unit.get("contract_manifest")
    if not isinstance(manifest, dict):
        codes.add("CONTRACT_MANIFEST_MALFORMED")
    else:
        if manifest != contract.to_dict():
            codes.add("CONTRACT_MANIFEST_MISMATCH")
        try:
            if _contract_manifest_digest(manifest) != prior_unit.get("contract_digest"):
                codes.add("CONTRACT_MANIFEST_DIGEST_MISMATCH")
        except (TypeError, ValueError):
            codes.add("CONTRACT_MANIFEST_MALFORMED")
    if prior_unit.get("launch_digest") != launch.digest:
        codes.add("LAUNCH_DIGEST_MISMATCH")
    if (
        prior_unit.get("launch_manifest") != launch.to_dict()
        or not _launch_manifest_is_valid(
            prior_unit.get("launch_manifest"),
            expected_digest=prior_unit.get("launch_digest"),
        )
    ):
        codes.add("LAUNCH_MANIFEST_MISMATCH")
    if prior_unit.get("model_invoked") is not contract.model_invoked:
        codes.add("MODEL_AUTHORITY_MISMATCH")
    codes.update(_closed_launch_profile_issues(contract, launch))
    execution_state = str(prior_unit.get("execution_state") or "")
    prior_semantic = str(prior_unit.get("semantic_status") or "")
    if execution_state not in {
        "INPUTS_BOUND_PREEXECUTION", "OUTPUT_COMMITTED",
        "OUTPUT_QUARANTINED", "OUTPUT_SUPERSEDED",
    }:
        codes.add("PREEXECUTION_STATE_INVALID")
    if execution_state == "OUTPUT_QUARANTINED" or prior_semantic == "QUARANTINED":
        codes.add("PRIOR_QUARANTINE_TERMINAL")
    if execution_state == "OUTPUT_SUPERSEDED" or prior_semantic == "SUPERSEDED":
        codes.add("PRIOR_SUPERSEDED_TERMINAL")
    if execution_state == "OUTPUT_COMMITTED" and not _active_commit_receipt_is_valid(
        prior_unit, work_unit_key=contract.key, run_id=run_id
    ):
        codes.add("PRIOR_COMMIT_AUTHORITY_INVALID")
    output_prestates = prior_unit.get("output_prestates")
    expected_outputs = {spec.identity for spec in contract.outputs}
    if not isinstance(output_prestates, dict):
        codes.add("OUTPUT_PRESTATE_RECEIPT_MISSING")
    elif set(output_prestates) != expected_outputs:
        codes.add("OUTPUT_PRESTATE_DENOMINATOR_MISMATCH")
    else:
        try:
            if (
                _output_prestate_digest(output_prestates)
                != prior_unit.get("output_prestate_digest")
            ):
                codes.add("OUTPUT_PRESTATE_DIGEST_MISMATCH")
        except (AttributeError, TypeError, ValueError):
            codes.add("OUTPUT_PRESTATE_RECEIPT_MALFORMED")
        for spec in contract.outputs:
            prestate = output_prestates.get(spec.identity)
            if not isinstance(prestate, Mapping) or not _output_prestate_is_clean(
                prestate
            ):
                codes.add("OUTPUT_PRESTATE_INVALID")
                if spec.write_mode in {"APPEND", "MERGE"}:
                    codes.add("READ_MODIFY_WRITE_PREIMAGE_INVALID")
            elif (
                prestate.get("status")
                == "ACTIVE_REGISTERED_SEMANTIC_PREDECESSOR"
            ):
                codes.update(
                    _semantic_output_prestate_commit_issues(
                        scratchpad,
                        project_root,
                        ledger,
                        spec,
                        prestate,
                        run_id=run_id,
                        merge_event=(merge_events or {}).get(spec.identity),
                    )
                )
    bindings = prior_unit.get("input_bindings")
    if not isinstance(bindings, dict):
        codes.add("INPUT_BINDINGS_MALFORMED")
        return codes, details, records, zero_kind
    records = {str(key): value for key, value in bindings.items()}
    if set(records) != expected:
        codes.add("INPUT_DENOMINATOR_MISMATCH")
    try:
        calculated_input_digest = _input_set_digest(records)
        stored_input_digest = prior_unit.get("input_set_digest")
        if not expected and records == {} and stored_input_digest == "":
            # Exact v2 output-only zero-denominator compatibility row.  The
            # commit migrates it to the canonical empty-set receipt digest.
            stored_input_digest = calculated_input_digest
        if stored_input_digest != calculated_input_digest:
            codes.add("INPUT_RECEIPT_DIGEST_MISMATCH")
    except (AttributeError, TypeError, ValueError):
        codes.add("INPUT_RECEIPT_MALFORMED")
    if prior_semantic not in {"INPUTS_BOUND", "ACTIVE"}:
        codes.add("INPUT_RECEIPT_NOT_CLEAN")
    try:
        _validated_input_rebind_history(
            prior_unit, work_unit_key=contract.key, run_id=run_id
        )
    except ArtifactLedgerError:
        codes.add("INPUT_REBIND_HISTORY_INVALID")

    successor_affected: set[str] = set()
    successor_valid = False
    if "successor_consumption_authority" in prior_unit:
        try:
            authority, _stored_plan = (
                _replay_driver_successor_authority(
                    Path(scratchpad),
                    Path(project_root),
                    ledger,
                    prior_unit,
                    contract,
                    launch,
                    run_id=run_id,
                )
            )
            _validate_driver_successor_live_progress(
                Path(scratchpad),
                Path(project_root),
                ledger,
                prior_unit,
                authority,
                require_complete=True,
            )
            successor_affected = set(
                authority["affected_input_identities"]
            )
            successor_valid = True
        except (
            ArtifactLedgerError,
            KeyError,
            OSError,
            TypeError,
            ValueError,
        ):
            codes.add("SUCCESSOR_CONSUMPTION_AUTHORITY_INVALID")

    allowed_classes = {
        "IMMUTABLE", "BOUNDED_LOOKUP", "IMMUTABLE_AND_BOUNDED_LOOKUP",
    }
    live_input_physical_identities: dict[str, list[str]] = {}
    for identity in sorted(expected):
        recorded = records.get(identity)
        if (
            not isinstance(recorded, dict)
            or recorded.get("identity") != identity
            or recorded.get("input_class") not in allowed_classes
        ):
            codes.add("INPUT_BINDING_MALFORMED")
            continue
        if recorded.get("status") != "ACTIVE":
            codes.add("INPUT_RECORDED_STATUS_NOT_ACTIVE")
        if recorded.get("status") == "PHYSICAL_INPUT_ALIAS_CONFLICT":
            codes.add("INPUT_PHYSICAL_ALIAS_CONFLICT")
        if successor_valid and identity in successor_affected:
            if contract.input_authority_requirements:
                try:
                    requirement = contract.input_authority(identity)
                except KeyError:
                    codes.add(
                        "INPUT_AUTHORITY_REQUIREMENT_DENOMINATOR_MISMATCH"
                    )
                else:
                    codes.update(
                        _input_authority_requirement_issues(
                            ledger,
                            recorded,
                            requirement,
                            run_id=run_id,
                        )
                    )
            try:
                live_path = _path_for_identity(
                    scratchpad,
                    project_root,
                    identity,
                )
                if live_path.exists():
                    physical = _physical_file_identity(live_path)
                    live_input_physical_identities.setdefault(
                        physical, []
                    ).append(identity)
            except ArtifactLedgerError:
                codes.add("INPUT_PHYSICAL_PATH_UNSAFE")
            continue
        current = _input_binding_record(
            scratchpad,
            project_root,
            identity,
            str(recorded.get("input_class") or "IMMUTABLE"),
            ledger,
            _validation_context=_validation_context,
        )
        if current.get("status") != "ACTIVE":
            codes.add("INPUT_LIVE_AUTHORITY_MISMATCH")
        if recorded.get("sha256") != current.get("sha256"):
            codes.add("INPUT_CONTENT_HASH_CHANGED")
        if recorded.get("size") != current.get("size"):
            codes.add("INPUT_SIZE_CHANGED")
        if (
            recorded.get("producer_work_unit_key", "")
            != current.get("producer_work_unit_key", "")
            or recorded.get("producer_contract_digest", "")
            != current.get("producer_contract_digest", "")
            or recorded.get("producer_launch_digest", "")
            != current.get("producer_launch_digest", "")
            or recorded.get("producer_commit_receipt_digest", "")
            != current.get("producer_commit_receipt_digest", "")
        ):
            codes.add("INPUT_PRODUCER_AUTHORITY_CHANGED")
        codes.update(
            _producer_binding_commit_issues(
                ledger, recorded, current, run_id=run_id
            )
        )
        if contract.input_authority_requirements:
            try:
                requirement = contract.input_authority(identity)
            except KeyError:
                codes.add(
                    "INPUT_AUTHORITY_REQUIREMENT_DENOMINATOR_MISMATCH"
                )
            else:
                codes.update(
                    _input_authority_requirement_issues(
                        ledger,
                        current,
                        requirement,
                        run_id=run_id,
                    )
                )
        try:
            live_path = _path_for_identity(
                scratchpad,
                project_root,
                identity,
            )
            if live_path.exists():
                physical = _physical_file_identity(
                    live_path
                )
                live_input_physical_identities.setdefault(
                    physical, []
                ).append(identity)
        except ArtifactLedgerError:
            codes.add("INPUT_PHYSICAL_PATH_UNSAFE")
    if any(
        len(identities) > 1
        for identities in live_input_physical_identities.values()
    ):
        codes.add("INPUT_PHYSICAL_ALIAS_CONFLICT")
    if not expected:
        zero_kind = str(prior_unit.get("input_receipt_kind") or "EXPLICIT_ZERO_INPUT")
    return codes, details, records, zero_kind


def _registered_projection_handoff(
    prior: Mapping[str, Any], spec: Any,
) -> bool:
    """Recognize only an exact resolver-declared deterministic successor."""

    predecessor = str(prior.get("owner_key") or "")
    try:
        return registered_projection_handoff(
            predecessor, spec.owner_key, spec.identity
        )
    except ValueError:
        return False


def _record_work_unit_artifacts_unlocked(
    scratchpad: Path,
    project_root: Path,
    contract: PhaseIOContract,
    launch: LaunchSpec,
    *,
    run_id: str,
    status: str = "ACTIVE",
    conditional_receipts: dict[str, ConditionalOutputReceipt] | None = None,
    actor: str | None = None,
    precommit_issues: Sequence[str] = (),
    merge_events: Mapping[str, DriverMergeEvent] | None = None,
    expected_output_records: Mapping[str, Mapping[str, Any]] | None = None,
    execution_authority: Mapping[str, Any] | None = None,
    output_commit_authority: Mapping[str, Any] | None = None,
    successor_reason_codes: Sequence[str] = (),
    _validation_context: _ArtifactValidationContext | None = None,
) -> dict[str, Any]:
    """Atomically check input authority and commit or quarantine all outputs.

    Output presence is never allowed to repair a missing, malformed, stale, or
    caller-rejected pre-execution receipt.  Failure is haltless: bytes remain in
    place and are recorded proposal-only at the work-unit, typed binding, and
    legacy projection levels.
    """
    if not isinstance(contract, PhaseIOContract):
        raise ArtifactLedgerError("contract must be a PhaseIOContract")
    if not isinstance(launch, LaunchSpec):
        raise ArtifactLedgerError("launch must be a LaunchSpec")
    if launch.work_unit_key != contract.key:
        raise ArtifactLedgerError("launch and contract work-unit keys differ")
    run_id = str(run_id or "").strip()
    if not run_id:
        raise ArtifactLedgerError("run_id must be non-empty")
    status = str(status or "").strip().upper()
    if status not in {"ACTIVE", "QUARANTINED", "SUPERSEDED"}:
        raise ArtifactLedgerError(f"unsupported artifact status: {status!r}")
    actor_n = str(actor or "").strip().upper()
    if actor_n and actor_n not in {"MODEL", "DRIVER"}:
        raise ArtifactLedgerError("actor must be MODEL or DRIVER")
    actor_reason_codes: set[str] = set()
    selection_actor = actor_n
    if contract.required_commit_actor:
        if not actor_n:
            actor_reason_codes.add("COMMIT_ACTOR_REQUIRED")
        elif actor_n != contract.required_commit_actor:
            actor_reason_codes.add("COMMIT_ACTOR_MISMATCH")
        selection_actor = contract.required_commit_actor
    normalized_execution_authority: dict[str, Any] | None = None
    if execution_authority is not None:
        try:
            from worker_transaction import validate_worker_execution_authority

            normalized_execution_authority = validate_worker_execution_authority(
                scratchpad=Path(scratchpad),
                authority=execution_authority,
                contract=contract,
                launch=launch,
                run_id=run_id,
            )
        except Exception as exc:
            raise ArtifactLedgerError(
                f"worker execution authority is invalid: {exc}"
            ) from exc
    if not isinstance(output_commit_authority, Mapping):
        raise ArtifactLedgerError(
            "output commit authority must be issued before ledger mutation"
        )

    root = Path(scratchpad)
    project = Path(project_root)
    validation_context = (
        _ArtifactValidationContext(
            root,
            project,
            ledger=read_artifact_ledger(root),
        )
        if _validation_context is None
        else _validation_context
    )
    validation_ledger = validation_context.ledger
    # Validation state is immutable for the epoch.  Build the future committed
    # projection separately, then publish it only after ``finish`` proves the
    # live ledger still equals the epoch's initial bytes.
    ledger = copy.deepcopy(validation_ledger)
    now = datetime.now(timezone.utc).isoformat()
    records: dict[str, dict[str, Any]] = {}
    prior_raw = validation_ledger["work_units"].get(contract.key)
    prior_unit = prior_raw if isinstance(prior_raw, dict) else None

    reason_codes, caller_issues, input_records, zero_input_kind = (
        _output_commit_authority_issues(
            root,
            project,
            validation_ledger,
            prior_unit,
            contract,
            launch,
            run_id=run_id,
            precommit_issues=precommit_issues,
            merge_events=merge_events,
            _validation_context=validation_context,
        )
    )
    reason_codes.update(actor_reason_codes)
    reason_codes.update(
        str(code)
        for code in successor_reason_codes
        if isinstance(code, str) and code
    )
    registered_commit_metadata: dict[str, str] = {}
    if isinstance(prior_unit, dict):
        try:
            registered_commit_metadata = (
                _registered_input_bound_commit_metadata(prior_unit)
            )
        except ArtifactLedgerError:
            reason_codes.add(
                "REGISTERED_INPUT_BOUND_COMMIT_METADATA_INVALID"
            )
    validated_recovery_history: list[dict[str, Any]] | None = None
    if (
        isinstance(prior_unit, dict)
        and "quarantine_recovery_history" in prior_unit
    ):
        try:
            validated_recovery_history = (
                _validated_quarantine_recovery_history(
                    prior_unit,
                    work_unit_key=contract.key,
                    run_id=run_id,
                )
            )
        except ArtifactLedgerError:
            reason_codes.add("QUARANTINE_RECOVERY_HISTORY_INVALID")
    if (
        status == "SUPERSEDED"
        and isinstance(prior_unit, dict)
        and prior_unit.get("semantic_status") == "SUPERSEDED"
        and prior_unit.get("execution_state") == "OUTPUT_SUPERSEDED"
    ):
        # Retirement is an idempotent terminal transition, not a new attempt
        # to reactivate authority.
        reason_codes.discard("PRIOR_SUPERSEDED_TERMINAL")
        reason_codes.discard("INPUT_RECEIPT_NOT_CLEAN")
    recovery_count, recovery_head = _quarantine_recovery_history_binding(
        validated_recovery_history or []
    )
    if prior_raw is not None and prior_unit is None:
        reason_codes.add("PRIOR_WORK_UNIT_MALFORMED")

    prior_commit = (
        prior_unit.get("commit_authority")
        if isinstance(prior_unit, dict)
        else None
    )
    if isinstance(prior_commit, dict):
        prior_ordinal = prior_commit.get("attempt_ordinal")
        if (
            prior_commit.get("schema") != _COMMIT_AUTHORITY_SCHEMA
            or not _is_positive_exact_int(prior_ordinal)
            or prior_commit.get("receipt_digest")
            != _commit_receipt_digest(prior_commit)
        ):
            reason_codes.add("PRIOR_COMMIT_RECEIPT_MALFORMED")
    elif (
        isinstance(prior_unit, dict)
        and prior_unit.get("execution_state") in _COMMIT_TERMINAL_STATES
    ):
        reason_codes.add("PRIOR_COMMIT_RECEIPT_MISSING")
    # The caller issued this authority under the same ledger transaction lock
    # immediately before entering the commit.  Re-deriving an ordinal here is
    # wrong for semantic re-execution: the issuance is already present in the
    # append-only journal, while the pre-execution unit deliberately no longer
    # carries the stale commit receipt.  Validate and consume the exact issued
    # ordinal instead of allocating a second one.
    issued_attempt = output_commit_authority.get("attempt_ordinal")
    attempt_ordinal = (
        int(issued_attempt)
        if isinstance(issued_attempt, int)
        and not isinstance(issued_attempt, bool)
        and issued_attempt >= 1
        else 0
    )
    prior_reexecution_history = (
        prior_unit.get("semantic_reexecution_history")
        if isinstance(prior_unit, dict)
        and "semantic_reexecution_history" in prior_unit
        else None
    )
    if prior_reexecution_history is not None and (
        not isinstance(prior_reexecution_history, list)
        or len(prior_reexecution_history) > 32
        or any(not isinstance(row, dict) for row in prior_reexecution_history)
    ):
        reason_codes.add("SEMANTIC_REEXECUTION_HISTORY_INVALID")

    receipts = dict(conditional_receipts or {})
    for identity, receipt in receipts.items():
        if not isinstance(receipt, ConditionalOutputReceipt):
            raise ArtifactLedgerError(
                f"conditional receipt for {identity} has the wrong type"
            )
        if receipt.artifact_identity != identity:
            raise ArtifactLedgerError(
                f"conditional receipt key/identity mismatch for {identity}"
            )
        try:
            receipt.validate_against(contract)
        except ValueError as exc:
            raise ArtifactLedgerError(str(exc)) from exc

    prior_records: dict[str, Any] = (
        prior_unit.get("artifacts", {}) if isinstance(prior_unit, dict) else {}
    )
    if not isinstance(prior_records, dict):
        prior_records = {}
        reason_codes.add("PRIOR_OUTPUT_DENOMINATOR_MALFORMED")
    elif not _nested_output_records_have_exact_sizes(prior_records):
        reason_codes.add("PRIOR_OUTPUT_SIZE_INVALID")

    # Snapshot the complete selected output denominator before mutating any
    # ledger table.  This avoids partially ACTIVE commits when a later output
    # is missing, unstable, or collides with an unrelated exact owner.
    snapshots: dict[str, dict[str, Any] | None] = {}
    snapshot_errors: dict[str, str] = {}
    physical_identities: dict[str, str] = {}
    rmw_transitions: dict[str, dict[str, Any]] = {}
    selected_specs = [
        spec
        for spec in contract.outputs
        if not selection_actor or spec.writer == selection_actor
    ]
    expected_identities = {spec.identity for spec in selected_specs}
    raw_expected_outputs = output_commit_authority.get(
        "expected_output_records", {}
    )
    try:
        normalized_expected_outputs = _normalize_expected_output_records(
            raw_expected_outputs,
            allow_absent=True,
        )
    except ArtifactLedgerError:
        reason_codes.add("EXPECTED_OUTPUT_SIZE_INVALID")
        normalized_expected_outputs = {
            str(identity): dict(record)
            for identity, record in raw_expected_outputs.items()
            if isinstance(identity, str) and isinstance(record, Mapping)
        } if isinstance(raw_expected_outputs, Mapping) else {}
    if set(normalized_expected_outputs) != expected_identities:
        reason_codes.add("EXPECTED_OUTPUT_DENOMINATOR_MISMATCH")
    if (
        output_commit_authority.get("schema") != _OUTPUT_AUTHORITY_SCHEMA
        or output_commit_authority.get("state") != "ACTIVE"
        or output_commit_authority.get("run_id") != run_id
        or output_commit_authority.get("work_unit_key") != contract.key
        or output_commit_authority.get("contract_digest") != contract.digest
        or output_commit_authority.get("launch_digest") != launch.digest
        or output_commit_authority.get("input_set_digest")
        != (
            _input_set_digest({})
            if not (
                set(contract.immutable_inputs)
                | set(contract.bounded_lookup_inputs)
            )
            else str(prior_unit.get("input_set_digest") or "")
            if isinstance(prior_unit, dict)
            else _input_set_digest({})
        )
        or output_commit_authority.get("attempt_ordinal") != attempt_ordinal
        or output_commit_authority.get(
            "quarantine_recovery_history_count"
        ) != recovery_count
        or output_commit_authority.get(
            "quarantine_recovery_history_head_digest"
        ) != recovery_head
        or output_commit_authority.get("physical_policy")
        != _NO_FOLLOW_PHYSICAL_POLICY
        or output_commit_authority.get("authority_digest")
        != _canonical_json_digest({
            name: value
            for name, value in output_commit_authority.items()
            if name != "authority_digest"
        })
    ):
        reason_codes.add("OUTPUT_COMMIT_AUTHORITY_INVALID")
    reason_codes.update(
        str(code)
        for code in output_commit_authority.get("reason_codes", ())
        if isinstance(code, str) and code
    )
    issued_observations = output_commit_authority.get("observed_outputs")
    if (
        not _nested_output_records_have_exact_sizes(
            issued_observations,
            expected_identities=expected_identities,
        )
    ):
        reason_codes.add("OUTPUT_COMMIT_AUTHORITY_DENOMINATOR_MISMATCH")
    # Snapshot the selected outputs first.  A terminally witnessed regular
    # file with st_nlink == 1 has exactly one filesystem name and therefore
    # cannot alias a second active artifact identity.  Only a genuinely
    # multi-link (or unknown) output needs the expensive global owner rejoin.
    # This keeps the ordinary commit O(selected outputs) while preserving the
    # full fail-closed hard-link scan for the only state where a collision is
    # possible.  The validation context terminally rechecks link counts.
    active_physical_owner_map: dict[str, set[str]] = {}
    output_link_counts: dict[str, int] = {}
    for spec in selected_specs:
        identity = spec.identity
        try:
            path = validation_context.path_for_identity(identity)
            physical_identities[identity] = (
                validation_context.physical_identity(path)
            )
            metadata = rooted_io.lstat(path)
            if _metadata_is_reparse(metadata) or not stat.S_ISREG(
                metadata.st_mode
            ):
                raise ArtifactLedgerError(
                    "output is not a no-follow regular file"
                )
            output_link_counts[identity] = int(
                getattr(metadata, "st_nlink", 1) or 1
            )
        except FileNotFoundError:
            physical_identities[identity] = (
                f"path:{os.path.normcase(os.path.abspath(os.fspath(path)))}"
            )
            output_link_counts[identity] = 0
        except ArtifactLedgerError as exc:
            snapshots[identity] = None
            snapshot_errors[identity] = str(exc)
            output_link_counts[identity] = -1
            reason_codes.add("OUTPUT_PHYSICAL_PATH_UNSAFE")
            continue
        snapshot: dict[str, Any] | None = None
        snapshot_error = ""
        snapshot, snapshot_error = validation_context.snapshot(path)
        if rooted_io.lexists(path) and snapshot is None:
            reason_codes.add("OUTPUT_SNAPSHOT_UNSTABLE")
            snapshot_errors[identity] = snapshot_error
        snapshots[identity] = snapshot

    if any(count not in {0, 1} for count in output_link_counts.values()):
        for active_identity, raw_active_binding in validation_ledger[
            "artifact_bindings"
        ].items():
            if (
                not isinstance(raw_active_binding, Mapping)
                or raw_active_binding.get("status") != "ACTIVE"
            ):
                continue
            try:
                active_physical = validation_context.physical_owner_identity(
                    str(active_identity)
                )
            except ArtifactLedgerError:
                continue
            if active_physical:
                active_physical_owner_map.setdefault(
                    active_physical, set()
                ).add(str(active_identity))

    for spec in selected_specs:
        identity = spec.identity
        snapshot = snapshots.get(identity)
        snapshot_error = snapshot_errors.get(identity, "")
        expected_record = normalized_expected_outputs.get(identity)
        expected_absence = bool(
            isinstance(expected_record, Mapping)
            and expected_record.get("sha256") == ""
            and expected_record.get("size") == 0
            and snapshot is None
            and spec.artifact_class == "CONDITIONAL"
        )
        if not expected_absence and (
            not isinstance(expected_record, Mapping)
            or snapshot is None
            or snapshot.get("sha256") != expected_record.get("sha256")
            or snapshot.get("size") != expected_record.get("size")
        ):
            reason_codes.add("EXPECTED_OUTPUT_RECORD_MISMATCH")
        issued = (
            issued_observations.get(identity)
            if isinstance(issued_observations, Mapping)
            else None
        )
        if (
            not isinstance(issued, Mapping)
            or issued.get("status") != (
                "PRESENT" if snapshot is not None else "ABSENT"
            )
            or issued.get("size")
            != (int(snapshot.get("size") or 0) if snapshot else 0)
            or issued.get("sha256")
            != (str(snapshot.get("sha256") or "") if snapshot else "")
            or issued.get("physical_identity")
            != physical_identities.get(identity, "")
            or issued.get("physical_policy") != _NO_FOLLOW_PHYSICAL_POLICY
        ):
            reason_codes.add("OUTPUT_COMMIT_AUTHORITY_REPLAY_MISMATCH")
        if snapshot is None and not snapshot_error and spec.artifact_class in {
            "REQUIRED", "DRIVER_GENERATED",
        }:
            reason_codes.add("REQUIRED_OUTPUT_MISSING")
        prior_binding = validation_ledger["artifact_bindings"].get(identity)
        current_physical = physical_identities.get(identity, "")
        if current_physical and any(
            other_identity != identity
            for other_identity in active_physical_owner_map.get(
                current_physical, set()
            )
        ):
            reason_codes.add("OUTPUT_PHYSICAL_OWNER_CONFLICT")
        if (
            isinstance(prior_binding, dict)
            and prior_binding.get("owner_key") not in {None, "", contract.key}
            and prior_binding.get("status") != "SUPERSEDED"
            and spec.write_mode not in {"APPEND", "MERGE"}
            and not _registered_projection_handoff(prior_binding, spec)
        ):
            reason_codes.add("OUTPUT_OWNER_CONFLICT")
        old_record = prior_records.get(identity)
        if (
            isinstance(prior_unit, dict)
            and prior_unit.get("semantic_status") == "ACTIVE"
            and prior_unit.get("execution_state") == "OUTPUT_COMMITTED"
            and isinstance(old_record, dict)
        ):
            legacy = ledger["artifacts"].get(_legacy_name(identity))
            expected_projection = {
                "owner_key": contract.key,
                "run_id": run_id,
                "contract_digest": contract.digest,
                "launch_digest": launch.digest,
                "status": "ACTIVE",
                "size": old_record.get("size"),
                "sha256": old_record.get("sha256"),
            }
            if (
                old_record.get("status") != "ACTIVE"
                or not _is_nonnegative_exact_int(old_record.get("size"))
                or not isinstance(prior_binding, dict)
                or not _is_nonnegative_exact_int(
                    prior_binding.get("size")
                )
                or any(
                    prior_binding.get(field) != value
                    for field, value in expected_projection.items()
                )
                or not isinstance(legacy, dict)
                or not _is_nonnegative_exact_int(legacy.get("size"))
                or any(
                    legacy.get(field) != value
                    for field, value in expected_projection.items()
                )
            ):
                reason_codes.add("PRIOR_LEDGER_STATE_MISMATCH")
        if (
            status == "ACTIVE"
            and isinstance(prior_unit, dict)
            and prior_unit.get("semantic_status") == "ACTIVE"
            and isinstance(old_record, dict)
            and old_record.get("status") == "ACTIVE"
            and snapshot is not None
            and (
                old_record.get("sha256") != snapshot.get("sha256")
                or old_record.get("size") != snapshot.get("size")
            )
        ):
            reason_codes.add("COMMITTED_OUTPUT_CHANGED_WITHOUT_INVALIDATION")
        prestates = (
            prior_unit.get("output_prestates", {})
            if isinstance(prior_unit, dict)
            else {}
        )
        prestate = (
            prestates.get(identity) if isinstance(prestates, dict) else None
        )
        if spec.write_mode == "APPEND" and isinstance(prestate, Mapping):
            prefix_digest, prefix_error = _stable_prefix_sha256(
                path, int(prestate.get("size") or 0)
            )
            prefix_preserved = bool(
                snapshot is not None
                and not prefix_error
                and snapshot.get("size", 0) > int(prestate.get("size") or 0)
                and prefix_digest == prestate.get("sha256")
            )
            if not prefix_preserved:
                reason_codes.add("APPEND_SUCCESSOR_INVALID")
            rmw_transitions[identity] = {
                "write_mode": "APPEND",
                "preimage_sha256": str(prestate.get("sha256") or ""),
                "preimage_size": int(prestate.get("size") or 0),
                "successor_sha256": (
                    str(snapshot.get("sha256") or "") if snapshot else ""
                ),
                "successor_size": (
                    int(snapshot.get("size") or 0) if snapshot else 0
                ),
                "prefix_preserved": prefix_preserved,
            }

    physical_output_groups: dict[str, list[str]] = {}
    for spec in selected_specs:
        if snapshots.get(spec.identity) is None:
            continue
        physical = physical_identities.get(spec.identity)
        if physical:
            physical_output_groups.setdefault(physical, []).append(
                spec.identity
            )
    if any(
        len(identities) > 1
        for identities in physical_output_groups.values()
    ):
        reason_codes.add("OUTPUT_PHYSICAL_ALIAS_CONFLICT")

    live_input_physical: dict[str, list[str]] = {}
    for identity in sorted(
        set(contract.immutable_inputs)
        | set(contract.bounded_lookup_inputs)
    ):
        try:
            input_path = validation_context.path_for_identity(identity)
            if input_path.exists() and input_path.is_file():
                physical = validation_context.physical_identity(input_path)
                live_input_physical.setdefault(physical, []).append(
                    identity
                )
        except ArtifactLedgerError:
            continue
    if any(
        physical in live_input_physical
        for physical in physical_output_groups
    ):
        reason_codes.add("INPUT_OUTPUT_PHYSICAL_ALIAS_CONFLICT")

    armed_prestates = (
        prior_unit.get("output_prestates", {})
        if isinstance(prior_unit, dict)
        else {}
    )
    if isinstance(armed_prestates, Mapping):
        for spec in selected_specs:
            live_physical = physical_identities.get(spec.identity, "")
            prestate = armed_prestates.get(spec.identity)
            if not live_physical or not isinstance(prestate, Mapping):
                continue
            prestate_physical = str(
                prestate.get("physical_identity") or ""
            )
            if any(
                other_identity != spec.identity
                and isinstance(other_prestate, Mapping)
                and str(
                    other_prestate.get("physical_identity") or ""
                )
                == live_physical
                for other_identity, other_prestate
                in armed_prestates.items()
            ):
                reason_codes.add("OUTPUT_PRESTATE_PHYSICAL_ALIAS_CONFLICT")

    for identity, receipt in receipts.items():
        present = snapshots.get(identity) is not None
        if receipt.state == "FAILED":
            reason_codes.add("CONDITIONAL_RECEIPT_FAILED")
        if (
            receipt.state == "PRODUCED"
            and (
                not present
                or identity not in set(receipt.produced_identities)
            )
        ) or (
            receipt.state in {"NOT_TRIGGERED", "TRIGGERED_EMPTY"}
            and present
        ):
            reason_codes.add("CONDITIONAL_RECEIPT_OUTPUT_MISMATCH")

    merge_receipts = dict(merge_events or {})
    for spec in selected_specs:
        if spec.write_mode != "MERGE":
            continue
        identity = spec.identity
        event = merge_receipts.get(identity)
        prestates = (
            prior_unit.get("output_prestates", {})
            if isinstance(prior_unit, dict)
            else {}
        )
        prestate = (
            prestates.get(identity) if isinstance(prestates, dict) else None
        )
        snapshot = snapshots.get(identity)
        valid = isinstance(event, DriverMergeEvent)
        if valid:
            try:
                event.validate_against(contract)
            except ValueError:
                valid = False
        valid = bool(
            valid
            and isinstance(prestate, Mapping)
            and snapshot is not None
            and event.before_sha256 == prestate.get("sha256")
            and event.after_sha256 == snapshot.get("sha256")
            and not event.removed_identities
        )
        external_receipt = (
            prestate.get("external_preimage_receipt")
            if isinstance(prestate, Mapping)
            else None
        )
        if external_receipt is not None:
            try:
                validate_external_preimage_receipt_integrity(
                    external_receipt
                )
            except ExternalPreimageValidationError:
                valid = False
            else:
                valid = bool(
                    valid
                    and external_receipt.get("work_unit_key")
                    == contract.key
                    and external_receipt.get("contract_digest")
                    == contract.digest
                    and external_receipt.get("artifact_identity") == identity
                    and external_receipt.get("validator_id")
                    == spec.external_preimage_validator
                    and external_receipt.get("raw_sha256")
                    == event.before_sha256
                    and external_receipt.get("size")
                    == prestate.get("size")
                    and tuple(external_receipt.get("parsed_identities") or ())
                    == event.identities_before
                )
        if not valid:
            reason_codes.add("DRIVER_MERGE_EVENT_INVALID")
        else:
            rmw_transitions[identity] = {
                "write_mode": "MERGE",
                "preimage_sha256": event.before_sha256,
                "successor_sha256": event.after_sha256,
                "merge_event_digest": event.digest,
                "identities_before": list(event.identities_before),
                "identities_after": list(event.identities_after),
                "source_identities": list(event.source_identities),
            }

    requested_status = status
    if requested_status == "QUARANTINED":
        reason_codes.add("EXPLICIT_QUARANTINE_REQUESTED")
    if requested_status == "SUPERSEDED" and not isinstance(prior_unit, dict):
        reason_codes.add("SUPERSEDE_WITHOUT_PRIOR_COMMIT")
    if requested_status == "SUPERSEDED" and reason_codes:
        effective_status = "QUARANTINED"
    elif requested_status == "SUPERSEDED":
        effective_status = "SUPERSEDED"
    elif reason_codes:
        effective_status = "QUARANTINED"
    else:
        effective_status = "ACTIVE"

    for spec in contract.outputs:
        identity = spec.identity
        if selection_actor and spec.writer != selection_actor:
            prior_record = (
                prior_records.get(identity)
                if isinstance(prior_records, dict) else None
            )
            if isinstance(prior_record, dict):
                records[identity] = dict(prior_record)
            else:
                records[identity] = {
                    "identity": identity,
                    "path": spec.path,
                    "root": spec.root,
                    "owner_key": contract.key,
                    "run_id": run_id,
                    "contract_digest": contract.digest,
                    "launch_digest": launch.digest,
                    "artifact_class": spec.artifact_class,
                    "writer": spec.writer,
                    "write_mode": spec.write_mode,
                    "schema_version": spec.schema_version,
                    "minimum_gate": spec.minimum_gate,
                    "consumers": list(spec.consumers),
                    "condition_id": spec.condition_id,
                    "status": "UNRECORDED",
                    "updated_at": now,
                    "size": 0,
                    "sha256": "",
                }
            continue
        snapshot = snapshots.get(identity)
        present = snapshot is not None
        record: dict[str, Any] = {
            "identity": identity,
            "path": spec.path,
            "root": spec.root,
            "owner_key": contract.key,
            "run_id": run_id,
            "contract_digest": contract.digest,
            "launch_digest": launch.digest,
            "artifact_class": spec.artifact_class,
            "writer": spec.writer,
            "write_mode": spec.write_mode,
            "schema_version": spec.schema_version,
            "minimum_gate": spec.minimum_gate,
            "consumers": list(spec.consumers),
            "condition_id": spec.condition_id,
            "physical_identity": physical_identities.get(identity, ""),
            "status": effective_status if present else "MISSING",
            "authority_level": (
                "ACTIVE_AUTHORITY"
                if effective_status == "ACTIVE" and present
                else "RETIRED"
                if effective_status == "SUPERSEDED" and present
                else "PROPOSAL_ONLY"
                if effective_status == "QUARANTINED"
                else "NONE"
            ),
            "updated_at": now,
            "size": 0,
            "sha256": "",
        }
        if present:
            record.update(snapshot)
        if identity in snapshot_errors:
            record["snapshot_error"] = snapshot_errors[identity]
        if spec.artifact_class == "CONDITIONAL":
            receipt = receipts.get(identity)
            if receipt is None:
                raise ArtifactLedgerError(
                    f"conditional output {identity} requires an explicit receipt"
                )
            record["conditional_receipt"] = receipt.to_dict()
        records[identity] = record

        prior = ledger["artifact_bindings"].get(identity)
        history: list[dict[str, Any]] = []
        if isinstance(prior, dict):
            history = list(prior.get("history") or [])
            prior_snapshot = {key: value for key, value in prior.items() if key != "history"}
            if prior_snapshot and prior_snapshot.get("owner_key") != contract.key:
                if _registered_projection_handoff(prior_snapshot, spec):
                    # Preserve the predecessor work unit verbatim while making
                    # the single-current-owner transition explicit in binding
                    # history.  This is a new historical projection, never an
                    # in-place rewrite of the MODEL/DRIVER generation record.
                    prior_snapshot["status"] = "SUPERSEDED"
                    prior_snapshot["authority_level"] = "RETIRED"
                    prior_snapshot["superseded_by_owner_key"] = contract.key
                history.append(prior_snapshot)
        ledger["artifact_bindings"][identity] = {**record, "history": history}

        legacy_name = _legacy_name(identity)
        phase_name = contract.key.split("/")[4]
        ledger["artifacts"][legacy_name] = {
            "path": legacy_name,
            "owner_phase": phase_name,
            "owner_key": contract.key,
            "status": record["status"],
            "mtime_ns": record.get("mtime_ns", 0),
            "size": record["size"],
            "sha256": record["sha256"],
            "updated_at": now,
            "contract_digest": contract.digest,
            "launch_digest": launch.digest,
            "run_id": run_id,
            "authority_level": record["authority_level"],
        }

    if effective_status == "QUARANTINED":
        # Mixed-writer units cannot leave a previously recorded sibling output
        # globally ACTIVE while the unit-level input authority is invalid.
        for identity, record in records.items():
            if not isinstance(record, dict) or record.get("status") in {
                "MISSING", "UNRECORDED",
            }:
                continue
            record["status"] = "QUARANTINED"
            record["authority_level"] = "PROPOSAL_ONLY"
            binding = ledger["artifact_bindings"].get(identity)
            if isinstance(binding, dict) and binding.get("owner_key") == contract.key:
                binding["status"] = "QUARANTINED"
                binding["authority_level"] = "PROPOSAL_ONLY"
            legacy = ledger["artifacts"].get(_legacy_name(identity))
            if isinstance(legacy, dict) and legacy.get("owner_key") == contract.key:
                legacy["status"] = "QUARANTINED"
                legacy["authority_level"] = "PROPOSAL_ONLY"

    committed_input_digest = (
        _input_set_digest({})
        if not (set(contract.immutable_inputs) | set(contract.bounded_lookup_inputs))
        else str(prior_unit.get("input_set_digest") or "")
        if isinstance(prior_unit, dict)
        else _input_set_digest({})
    )
    precommit_receipt = _precommit_issue_receipt(precommit_issues)
    commit_receipt: dict[str, Any] = {
        "schema": _COMMIT_AUTHORITY_SCHEMA,
        "state": effective_status,
        "run_id": run_id,
        "work_unit_key": contract.key,
        "contract_digest": contract.digest,
        "launch_digest": launch.digest,
        "input_set_digest": committed_input_digest,
        "attempt_ordinal": attempt_ordinal,
        "quarantine_recovery_history_count": recovery_count,
        "quarantine_recovery_history_head_digest": recovery_head,
        "reason_codes": sorted(reason_codes),
        "precommit_issues": caller_issues,
        "precommit_issue_count": precommit_receipt["count"],
        "precommit_issue_digest": precommit_receipt["digest"],
        "precommit_issue_overflow": precommit_receipt["overflow"],
        "read_modify_write_transitions": rmw_transitions,
        "recorded_output_identities": sorted(
            spec.identity for spec in selected_specs
        ),
        "output_authority_key": str(
            output_commit_authority.get("authority_key") or ""
        ),
        "output_authority_digest": str(
            output_commit_authority.get("authority_digest") or ""
        ),
        "output_authority_source": str(
            output_commit_authority.get("source") or ""
        ),
        "output_authority_actor": str(
            output_commit_authority.get("actor") or ""
        ),
        "expected_output_records": dict(
            sorted(normalized_expected_outputs.items())
        ),
    }
    if (
        isinstance(prior_unit, dict)
        and isinstance(
            prior_unit.get("successor_consumption_authority"),
            Mapping,
        )
    ):
        if "SUCCESSOR_CONSUMPTION_AUTHORITY_INVALID" in reason_codes:
            # The wrapper already failed strict replay.  Do not parse the raw,
            # attacker-controlled nested plan a second time while attempting
            # the haltless quarantine commit.
            commit_receipt[
                "successor_consumption_authority_state"
            ] = "INVALID_UNAVAILABLE"
        else:
            successor_authority = prior_unit[
                "successor_consumption_authority"
            ]
            transitions = _driver_successor_transition_rows(
                successor_authority.get("plan", {})
            )
            commit_receipt[
                "successor_consumption_authority_digest"
            ] = str(successor_authority.get("authority_digest") or "")
            commit_receipt["planned_merge_event_digests"] = {
                str(row["artifact_identity"]): _canonical_json_digest(
                    dict(row["merge_event"])
                )
                for row in transitions
                if isinstance(row.get("merge_event"), Mapping)
            }
    if contract.required_commit_actor:
        commit_receipt["actor"] = actor_n
    if normalized_execution_authority is not None:
        commit_receipt["execution_authority"] = dict(
            normalized_execution_authority
        )
    commit_receipt.update(registered_commit_metadata)
    if (
        output_commit_authority.get("source")
        == "VALIDATED_EXPECTED_OUTPUT_RECORDS"
    ):
        # Preserve the caller-selected, independently validated expected
        # denominator as a source-specific witness.  A later sidecar rewrite
        # cannot turn a legacy observation into an asserted expected-record
        # authority merely by replacing the source string.
        commit_receipt[
            "output_authority_expected_records_digest"
        ] = _canonical_json_digest(
            dict(sorted(normalized_expected_outputs.items()))
        )
    commit_receipt["receipt_digest"] = _commit_receipt_digest(commit_receipt)

    work_unit = {
        "schema": "plamen.artifact-work-unit.v2",
        "work_unit_key": contract.key,
        "run_id": run_id,
        "contract_digest": contract.digest,
        "contract_manifest": contract.to_dict(),
        "launch_digest": launch.digest,
        "launch_manifest": launch.to_dict(),
        "model_invoked": contract.model_invoked,
        "recorded_at": (
            prior_unit.get("recorded_at", now)
            if isinstance(prior_unit, dict)
            else now
        ),
        "output_recorded_at": now,
        "execution_state": (
            "OUTPUT_COMMITTED"
            if effective_status == "ACTIVE"
            else "OUTPUT_SUPERSEDED"
            if effective_status == "SUPERSEDED"
            else "OUTPUT_QUARANTINED"
        ),
        "semantic_status": effective_status,
        "input_bindings": dict(input_records),
        "input_set_digest": committed_input_digest,
        "output_prestates": (
            dict(prior_unit.get("output_prestates", {}))
            if isinstance(prior_unit, dict)
            and isinstance(prior_unit.get("output_prestates"), dict)
            else {}
        ),
        "output_prestate_digest": (
            str(prior_unit.get("output_prestate_digest") or "")
            if isinstance(prior_unit, dict)
            else ""
        ),
        "input_receipt_kind": (
            str(prior_unit.get("input_receipt_kind") or "BOUND_INPUTS")
            if isinstance(prior_unit, dict) and input_records
            else zero_input_kind
            if zero_input_kind
            else "MISSING_PREEXECUTION_RECEIPT"
        ),
        "commit_authority": commit_receipt,
        "artifacts": records,
    }
    if isinstance(prior_unit, dict) and (
        "preexecution_authority" in prior_unit
        or "preexecution_authority_digest" in prior_unit
    ):
        replayed_extension, replayed_extension_digest = (
            _canonical_preexecution_authority_extension(
                prior_unit.get("preexecution_authority")
            )
        )
        if (
            prior_unit.get("preexecution_authority_digest")
            != replayed_extension_digest
        ):
            raise ArtifactLedgerError(
                f"work unit {contract.key} preexecution authority digest "
                "is invalid at commit"
            )
        work_unit["preexecution_authority"] = copy.deepcopy(
            replayed_extension
        )
        work_unit["preexecution_authority_digest"] = (
            replayed_extension_digest
        )
    if normalized_execution_authority is not None:
        work_unit["execution_authority"] = dict(
            normalized_execution_authority
        )
    work_unit.update(registered_commit_metadata)
    if (
        isinstance(prior_unit, dict)
        and isinstance(
            prior_unit.get("successor_consumption_authority"),
            Mapping,
        )
    ):
        work_unit["successor_consumption_authority"] = dict(
            prior_unit["successor_consumption_authority"]
        )
        if isinstance(
            prior_unit.get("successor_progress_authority"),
            Mapping,
        ):
            work_unit["successor_progress_authority"] = copy.deepcopy(
                prior_unit["successor_progress_authority"]
            )
        if isinstance(
            prior_unit.get("successor_physical_rebind_history"),
            list,
        ):
            work_unit["successor_physical_rebind_history"] = (
                copy.deepcopy(
                    prior_unit["successor_physical_rebind_history"]
                )
            )
    if (
        isinstance(prior_unit, dict)
        and "explicit_absence_authority" in prior_unit
    ):
        work_unit["explicit_absence_authority"] = dict(
            prior_unit["explicit_absence_authority"]
        )
    if isinstance(prior_unit, dict) and "input_rebind_history" in prior_unit:
        try:
            work_unit["input_rebind_history"] = _validated_input_rebind_history(
                prior_unit, work_unit_key=contract.key, run_id=run_id
            )
        except ArtifactLedgerError:
            # The commit receipt already carries INPUT_REBIND_HISTORY_INVALID.
            # Do not propagate corrupt history as future CAS authority.
            work_unit["input_rebind_history"] = []
    if isinstance(prior_unit, dict) and "semantic_reexecution_history" in prior_unit:
        history = prior_unit.get("semantic_reexecution_history")
        if (
            not isinstance(history, list)
            or len(history) > 32
            or any(not isinstance(row, dict) for row in history)
        ):
            work_unit["semantic_reexecution_history"] = []
        else:
            work_unit["semantic_reexecution_history"] = [
                dict(row) for row in history
            ]
    if validated_recovery_history is not None:
        work_unit["quarantine_recovery_history"] = copy.deepcopy(
            validated_recovery_history
        )
        recovery_count, recovery_head = (
            _quarantine_recovery_history_binding(
                validated_recovery_history
            )
        )
        work_unit["quarantine_recovery_history_count"] = recovery_count
        work_unit[
            "quarantine_recovery_history_head_digest"
        ] = recovery_head
    validation_issues = validation_context.finish()
    if validation_issues:
        raise ArtifactLedgerError("; ".join(validation_issues))
    ledger["work_units"][contract.key] = work_unit
    write_artifact_ledger(root, ledger)
    return work_unit


def record_work_unit_artifacts(
    scratchpad: Path,
    project_root: Path,
    contract: PhaseIOContract,
    launch: LaunchSpec,
    *,
    run_id: str,
    status: str = "ACTIVE",
    conditional_receipts: dict[str, ConditionalOutputReceipt] | None = None,
    actor: str | None = None,
    precommit_issues: Sequence[str] = (),
    merge_events: Mapping[str, DriverMergeEvent] | None = None,
    expected_output_records: Mapping[str, Mapping[str, Any]] | None = None,
    execution_authority: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Atomic in-process authority check plus exact output ledger update."""
    contract, launch = _replay_authority_pair(contract, launch)
    with _ledger_transaction_lock(scratchpad):
        ledger = read_artifact_ledger(Path(scratchpad))
        validation_context = _ArtifactValidationContext(
            Path(scratchpad),
            Path(project_root),
            ledger=ledger,
        )
        successor_reason_codes: set[str] = set()
        effective_expected_output_records = expected_output_records
        prior = ledger.get("work_units", {}).get(contract.key)
        if (
            isinstance(prior, Mapping)
            and "successor_consumption_authority" in prior
        ):
            try:
                successor_authority, successor_plan = (
                    _replay_driver_successor_authority(
                        Path(scratchpad),
                        Path(project_root),
                        ledger,
                        prior,
                        contract,
                        launch,
                        run_id=str(run_id or "").strip(),
                    )
                )
                _synchronize_driver_successor_progress_projection(
                    Path(scratchpad), ledger
                )
                _validate_driver_successor_live_progress(
                    Path(scratchpad),
                    Path(project_root),
                    ledger,
                    prior,
                    successor_authority,
                    require_complete=True,
                )
            except (
                ArtifactLedgerError,
                KeyError,
                OSError,
                TypeError,
                ValueError,
            ):
                successor_reason_codes.add(
                    "SUCCESSOR_CONSUMPTION_AUTHORITY_INVALID"
                )
            else:
                planned_records = successor_plan.expected_output_records
                if expected_output_records is not None:
                    try:
                        supplied_records = (
                            _normalize_expected_output_records(
                                expected_output_records,
                                allow_absent=True,
                            )
                        )
                    except ArtifactLedgerError:
                        supplied_records = {}
                    if supplied_records != planned_records:
                        successor_reason_codes.add(
                            "PLANNED_OUTPUT_RECORD_MISMATCH"
                        )
                effective_expected_output_records = planned_records

                planned_merge_events = {
                    transition.artifact_identity: (
                        None
                        if transition.merge_event is None
                        else transition.merge_event.to_dict()
                    )
                    for transition in successor_plan.transitions
                    if transition.merge_event is not None
                }
                supplied_merge_events: dict[str, Any] = {}
                for identity, event in dict(
                    merge_events or {}
                ).items():
                    supplied_merge_events[str(identity)] = (
                        event.to_dict()
                        if type(event) is DriverMergeEvent
                        else None
                    )
                if supplied_merge_events != planned_merge_events:
                    successor_reason_codes.add(
                        "PLANNED_MERGE_EVENT_MISMATCH"
                    )
        output_commit_authority = _issue_output_commit_authority(
            Path(scratchpad),
            Path(project_root),
            ledger,
            contract,
            launch,
            run_id=str(run_id or "").strip(),
            actor=actor,
            expected_output_records=effective_expected_output_records,
            execution_authority=execution_authority,
            _validation_context=validation_context,
        )
        return _record_work_unit_artifacts_unlocked(
            scratchpad,
            project_root,
            contract,
            launch,
            run_id=run_id,
            status=status,
            conditional_receipts=conditional_receipts,
            actor=actor,
            precommit_issues=precommit_issues,
            merge_events=merge_events,
            expected_output_records=effective_expected_output_records,
            execution_authority=execution_authority,
            output_commit_authority=output_commit_authority,
            successor_reason_codes=tuple(
                sorted(successor_reason_codes)
            ),
            _validation_context=validation_context,
        )


def _input_binding_record_uncached(
    scratchpad: Path,
    project_root: Path,
    identity: str,
    input_class: str,
    ledger: dict[str, Any],
    *,
    _validation_context: _ArtifactValidationContext | None = None,
) -> dict[str, Any]:
    producer = ledger.get("artifact_bindings", {}).get(identity)
    record: dict[str, Any] = {
        "identity": identity,
        "input_class": input_class,
        "status": "MISSING",
        "size": 0,
        "sha256": "",
        "producer_work_unit_key": (
            str(producer.get("owner_key", ""))
            if isinstance(producer, dict)
            else ""
        ),
        "producer_contract_digest": (
            str(producer.get("contract_digest", ""))
            if isinstance(producer, dict)
            else ""
        ),
        "producer_launch_digest": (
            str(producer.get("launch_digest", ""))
            if isinstance(producer, dict)
            else ""
        ),
        "producer_writer": (
            str(producer.get("writer", ""))
            if isinstance(producer, dict)
            else ""
        ),
        "producer_run_id": (
            str(producer.get("run_id", ""))
            if isinstance(producer, dict)
            else ""
        ),
        "producer_commit_receipt_digest": "",
    }
    if isinstance(producer, dict):
        producer_key = str(producer.get("owner_key") or "")
        producer_unit = (
            ledger.get("work_units", {}).get(producer_key)
            if producer_key
            and isinstance(ledger.get("work_units"), Mapping)
            else None
        )
        commit = (
            producer_unit.get("commit_authority")
            if isinstance(producer_unit, Mapping)
            else None
        )
        if isinstance(commit, Mapping):
            record["producer_commit_receipt_digest"] = str(
                commit.get("receipt_digest") or ""
            )
    try:
        path = (
            _path_for_identity(scratchpad, project_root, identity)
            if _validation_context is None
            else _validation_context.path_for_identity(identity)
        )
    except ArtifactLedgerError as exc:
        record["status"] = "UNSAFE_PHYSICAL_PATH"
        record["snapshot_error"] = str(exc)
        return record
    validation_snapshot: dict[str, Any] | None = None
    validation_snapshot_error = ""
    if _validation_context is None:
        present = rooted_io.is_file(path)
    else:
        validation_snapshot, validation_snapshot_error = (
            _validation_context.snapshot(path)
        )
        present = (
            validation_snapshot is not None
            or rooted_io.lexists(path)
        )
    record["status"] = "ACTIVE" if present else "MISSING"
    if present:
        snapshot, snapshot_error = (
            _stable_artifact_snapshot(path)
            if _validation_context is None
            else (validation_snapshot, validation_snapshot_error)
        )
        if snapshot is None:
            record["status"] = "UNSTABLE_INPUT_SNAPSHOT"
            record["snapshot_error"] = snapshot_error
            return record
        live_sha256 = str(snapshot["sha256"])
        record.update(
            {
                "size": snapshot["size"],
                "mtime_ns": snapshot["mtime_ns"],
                "sha256": live_sha256,
            }
        )
        semantic_predecessor_verified = False
        if (
            isinstance(producer, dict)
            and (
                not _nested_output_records_have_exact_sizes(
                    {identity: producer}
                )
                or str(producer.get("status", "")) != "ACTIVE"
                or producer.get("size") != snapshot["size"]
                or str(producer.get("sha256", "")) != live_sha256
            )
        ):
            mutation_authority = _semantic_mutation_producer_authority(
                Path(scratchpad),
                project_root=Path(project_root),
                identity=identity,
                producer=producer,
                live_state={
                    "status": "ACTIVE",
                    "size": snapshot["size"],
                    "sha256": live_sha256,
                },
            )
            if mutation_authority is None:
                record["status"] = "PRODUCER_AUTHORITY_MISMATCH"
            else:
                # Do not rewrite or rebless the historical producer record.
                # The durable arm-before-write mutation chain is the exact
                # producer of these current bytes and gets its own identity.
                authority = mutation_authority.get(
                    "semantic_predecessor_authority"
                )
                authority_core = (
                    {
                        key: value
                        for key, value in authority.items()
                        if key not in {"authority_digest", "terminal_event_id"}
                    }
                    if isinstance(authority, Mapping)
                    else {}
                )
                event_ids = (
                    authority.get("mutation_event_ids")
                    if isinstance(authority, Mapping)
                    else None
                )
                event_digests = (
                    authority.get("mutation_authority_digests")
                    if isinstance(authority, Mapping)
                    else None
                )
                semantic_predecessor_verified = bool(
                    isinstance(authority, Mapping)
                    and set(authority)
                    == {
                        "identity",
                        "run_id",
                        "historical_owner_key",
                        "historical_contract_digest",
                        "historical_launch_digest",
                        "historical_size",
                        "historical_sha256",
                        "mutation_event_ids",
                        "mutation_authority_digests",
                        "live_size",
                        "live_sha256",
                        "authority_digest",
                        "terminal_event_id",
                    }
                    and authority.get("identity") == identity
                    and authority.get("run_id") == producer.get("run_id")
                    and authority.get("historical_owner_key")
                    == producer.get("owner_key")
                    and authority.get("historical_contract_digest")
                    == producer.get("contract_digest")
                    and authority.get("historical_launch_digest")
                    == str(producer.get("launch_digest") or "")
                    and authority.get("historical_size")
                    == producer.get("size")
                    and authority.get("historical_sha256")
                    == producer.get("sha256")
                    and authority.get("live_size") == snapshot["size"]
                    and authority.get("live_sha256") == live_sha256
                    and isinstance(event_ids, list)
                    and bool(event_ids)
                    and isinstance(event_digests, list)
                    and len(event_ids) == len(event_digests)
                    and all(str(value or "") for value in event_ids)
                    and all(_is_digest(value) for value in event_digests)
                    and authority.get("terminal_event_id") == event_ids[-1]
                    and mutation_authority.get("producer_work_unit_key")
                    == f"semantic-mutation:{event_ids[-1]}"
                    and mutation_authority.get("producer_contract_digest")
                    == authority.get("authority_digest")
                    and _semantic_virtual_producer_digest(authority_core)
                    == authority.get("authority_digest")
                )
                if semantic_predecessor_verified:
                    record.update(mutation_authority)
                else:
                    record["status"] = "PRODUCER_AUTHORITY_MISMATCH"
        if isinstance(producer, dict) and record.get("status") == "ACTIVE":
            producer_key = str(producer.get("owner_key") or "")
            if producer_key and not producer_key.startswith("semantic-mutation:"):
                producer_unit = ledger.get("work_units", {}).get(producer_key)
                live_byte_exemptions = (
                    _semantic_mutation_bundle_live_byte_exemptions(
                        Path(scratchpad),
                        Path(project_root),
                        ledger,
                        producer,
                        producer_unit,
                        verified_identity=(
                            identity if semantic_predecessor_verified else ""
                        ),
                        _validation_context=_validation_context,
                    )
                    if isinstance(producer_unit, Mapping)
                    else ()
                )
                if (
                    not _producer_authority_is_active(
                        ledger,
                        producer,
                        identity=identity,
                        run_id=str(producer.get("run_id") or ""),
                    )
                    or not isinstance(producer_unit, Mapping)
                    or _replay_output_commit_authority(
                        Path(scratchpad),
                        Path(project_root),
                        producer_unit,
                        # The historical receipt must still replay.  Every
                        # exempt bundle member has its own verified, same-run,
                        # contiguous mutation chain to the current bytes.
                        # Unjournaled siblings remain subject to ordinary
                        # live-byte validation and fail the replay closed.
                        require_live_bytes=True,
                        live_byte_exempt_identities=live_byte_exemptions,
                        _validation_context=_validation_context,
                    )
                ):
                    record["status"] = "PRODUCER_AUTHORITY_MISMATCH"
    return record


def _input_binding_record(
    scratchpad: Path,
    project_root: Path,
    identity: str,
    input_class: str,
    ledger: dict[str, Any],
    *,
    _validation_context: _ArtifactValidationContext | None = None,
) -> dict[str, Any]:
    """Replay one exact binding once inside an immutable ledger epoch."""

    cache_key: tuple[str, str, str] | None = None
    if (
        _validation_context is not None
        and ledger is _validation_context.ledger
    ):
        cache_key = (
            _validation_context._ledger_digest,
            str(identity),
            str(input_class),
        )
        cached = _validation_context.input_binding_records.get(cache_key)
        if cached is not None:
            return copy.deepcopy(cached)
    record = _input_binding_record_uncached(
        Path(scratchpad),
        Path(project_root),
        identity,
        input_class,
        ledger,
        _validation_context=_validation_context,
    )
    if cache_key is not None:
        _validation_context.input_binding_records[cache_key] = copy.deepcopy(
            record
        )
    return record


def _semantic_mutation_producer_authority(
    scratchpad: Path,
    *,
    project_root: Path,
    identity: str,
    producer: dict[str, Any],
    live_state: dict[str, Any],
) -> dict[str, Any] | None:
    """Resolve current bytes through a validated arm-before-write lineage.

    A semantic mutation deliberately changes a canonical artifact after its
    original producer committed it.  Treating the original producer as owner
    of the new hash would be self-reblessing; treating the bytes as unowned
    makes every legitimate downstream consumer permanent INPUT_DEBT.  The
    mutation ledger already contains the exact before/after transition and is
    written before the filesystem mutation.  This helper exposes a *virtual*
    producer identity only when a same-run, contiguous, terminal chain starts
    at the historical producer snapshot and ends at the live bytes.

    Corrupt, armed, branching, cross-run, or incomplete chains return no
    authority.  Callers then retain PRODUCER_AUTHORITY_MISMATCH.
    """

    if (
        not isinstance(producer, dict)
        or str(producer.get("status") or "") != "ACTIVE"
        or not _is_digest(producer.get("sha256"))
        or not str(producer.get("owner_key") or "")
        or not _is_digest(producer.get("contract_digest"))
        or not str(producer.get("run_id") or "")
    ):
        return None
    base_state = {
        "status": "ACTIVE",
        "size": producer.get("size"),
        "sha256": str(producer.get("sha256") or ""),
    }
    if (
        not _is_nonnegative_exact_int(base_state["size"])
        or set(live_state) != {"status", "size", "sha256"}
        or live_state.get("status") != "ACTIVE"
        or not _is_nonnegative_exact_int(live_state.get("size"))
        or not _is_digest(live_state.get("sha256"))
    ):
        return None
    try:
        payload = _read_semantic_mutations(Path(scratchpad))
    except ArtifactLedgerError:
        return None

    current = dict(base_state)
    chain: list[str] = []
    chain_event_ids: list[str] = []
    last_event_id = ""
    started = False
    run_id = str(producer["run_id"])
    relevant = [
        event
        for event in payload.get("events", [])
        if isinstance(event, dict)
        and event.get("artifact_identity") == identity
        and event.get("run_id") == run_id
    ]
    for event in relevant:
        if identity == "project:AUDIT_REPORT.md":
            # A semantic event is a lineage index, not independent authority to
            # bless canonical report bytes.  Require the full report
            # transaction receipt/input/sidecar denominator for every hop.
            try:
                from report_mutation_transaction import (
                    validate_report_transaction_semantic_successor,
                )

                report_successor_valid = (
                    validate_report_transaction_semantic_successor(
                        scratchpad=Path(scratchpad),
                        project_root=Path(project_root),
                        event=event,
                    )
                )
            except (ImportError, RuntimeError, TypeError, ValueError):
                report_successor_valid = False
            if not report_successor_valid:
                return None
        before = event.get("before")
        if not started:
            # Events older than the currently registered producer may exist
            # after a later canonical rewrite.  Only a transition beginning at
            # this exact producer snapshot can start the current lineage.
            if before != current:
                continue
            started = True
        elif before != current:
            # Two transitions from the same historical state, or a gap in the
            # chain, is ambiguous and therefore has no producer authority.
            return None
        status = str(event.get("status") or "")
        if status not in {"NO_CHANGE", "INVALIDATION_APPLIED"}:
            return None
        after = event.get("after")
        if not isinstance(after, dict) or set(after) != {
            "status", "size", "sha256",
        }:
            return None
        current = dict(after)
        chain.append(semantic_mutation_authority_digest(event))
        chain_event_ids.append(str(event.get("event_id") or ""))
        last_event_id = str(event.get("event_id") or "")

    if not started or not chain or current != live_state or not last_event_id:
        return None
    authority_core = _semantic_virtual_producer_core(
        identity=identity,
        run_id=run_id,
        producer=producer,
        mutation_event_ids=chain_event_ids,
        mutation_authority_digests=chain,
        live_state=live_state,
    )
    authority_digest = _semantic_virtual_producer_digest(authority_core)
    return {
        "producer_work_unit_key": f"semantic-mutation:{last_event_id}",
        "producer_contract_digest": authority_digest,
        "semantic_predecessor_authority": {
            **authority_core,
            "authority_digest": authority_digest,
            "terminal_event_id": last_event_id,
        },
    }


def _semantic_mutation_bundle_live_byte_exemptions(
    scratchpad: Path,
    project_root: Path,
    ledger: Mapping[str, Any],
    producer: Mapping[str, Any],
    producer_unit: Mapping[str, Any],
    *,
    verified_identity: str,
    _validation_context: _ArtifactValidationContext | None = None,
) -> tuple[str, ...]:
    """Resolve every mutated sibling through its own exact lineage.

    Output-authority replay covers a historical producer's complete bundle.
    Coupled canonical roots can legitimately advance together through separate
    arm-before-write events, so replaying an inventory input while exempting
    only that one root incorrectly rejects its equally authenticated record
    and ID-ledger siblings.

    A sibling is exempted only when its active binding is the exact same
    historical producer snapshot and a same-run, contiguous, terminal semantic
    mutation chain reaches its current bytes.  Any unjournaled, cross-run,
    branching, or partially published sibling remains unexempted, causing the
    ordinary bundle replay to fail closed.
    """

    verified = str(verified_identity or "")
    cache_key: tuple[str, str, str, str, str] | None = None
    if (
        _validation_context is not None
        and ledger is _validation_context.ledger
    ):
        cache_key = (
            _validation_context._ledger_digest,
            str(producer.get("owner_key") or ""),
            str(producer.get("contract_digest") or ""),
            str(producer.get("launch_digest") or ""),
            str(producer.get("run_id") or ""),
        )
        cached = _validation_context.semantic_mutation_bundle_exemptions.get(
            cache_key
        )
        if cached is not None:
            return tuple(sorted({*cached, *([verified] if verified else [])}))

    # Compute the bundle-wide base independently of the one identity whose
    # semantic predecessor was already verified by the caller.  This makes the
    # result reusable for every sibling consumer edge in this exact epoch.
    exemptions: set[str] = set()
    commit = producer_unit.get("commit_authority")
    expected = (
        commit.get("expected_output_records")
        if isinstance(commit, Mapping)
        else None
    )
    bindings = ledger.get("artifact_bindings")
    if not isinstance(expected, Mapping) or not isinstance(bindings, Mapping):
        return tuple(sorted(exemptions))

    historical_fields = (
        "owner_key", "contract_digest", "launch_digest", "run_id",
    )
    for raw_identity, raw_expected in expected.items():
        identity = str(raw_identity or "")
        if identity in exemptions or not isinstance(raw_expected, Mapping):
            continue
        sibling = bindings.get(identity)
        if not isinstance(sibling, dict):
            continue
        if any(
            sibling.get(field) != producer.get(field)
            for field in historical_fields
        ):
            if _registered_successor_bundle_member_authority(
                Path(scratchpad),
                Path(project_root),
                ledger,
                producer,
                identity=identity,
                expected_record=raw_expected,
            ):
                exemptions.add(identity)
            continue
        if (
            sibling.get("status") != "ACTIVE"
            or sibling.get("size") != raw_expected.get("size")
            or sibling.get("sha256") != raw_expected.get("sha256")
        ):
            continue
        try:
            live_state = _semantic_artifact_state(
                Path(scratchpad), Path(project_root), identity,
            )
        except ArtifactLedgerError:
            continue
        if _validation_context is not None:
            try:
                witnessed_path = _validation_context.path_for_identity(identity)
                witnessed, witness_error = _validation_context.snapshot(
                    witnessed_path
                )
            except ArtifactLedgerError:
                continue
            witnessed_state = (
                {
                    "status": "ACTIVE",
                    "size": witnessed.get("size"),
                    "sha256": witnessed.get("sha256"),
                }
                if witnessed is not None and not witness_error
                else {
                    "status": "MISSING",
                    "size": 0,
                    "sha256": "",
                }
            )
            if witnessed_state != live_state:
                continue
        if (
            live_state.get("status") == "ACTIVE"
            and live_state.get("size") == sibling.get("size")
            and live_state.get("sha256") == sibling.get("sha256")
        ):
            continue
        if _semantic_mutation_producer_authority(
            Path(scratchpad),
            project_root=Path(project_root),
            identity=identity,
            producer=sibling,
            live_state=live_state,
        ) is not None:
            exemptions.add(identity)
    base = tuple(sorted(exemptions))
    if cache_key is not None:
        _validation_context.semantic_mutation_bundle_exemptions[cache_key] = base
    return tuple(sorted({*base, *([verified] if verified else [])}))


def _registered_successor_bundle_member_authority(
    scratchpad: Path,
    project_root: Path,
    ledger: Mapping[str, Any],
    historical_producer: Mapping[str, Any],
    *,
    identity: str,
    expected_record: Mapping[str, Any],
) -> bool:
    """Prove one historical bundle sibling moved to a registered successor.

    A multi-output producer can retain immutable receipts after some canonical
    roots move through a resolver-declared successor (for example inventory
    aggregate -> additive re-emission).  The retained receipt must not become
    unreadable merely because those siblings advanced, but an arbitrary new
    owner must never excuse historical output drift.
    """

    bindings = ledger.get("artifact_bindings")
    units = ledger.get("work_units")
    if not isinstance(bindings, Mapping) or not isinstance(units, Mapping):
        return False
    current = bindings.get(identity)
    if not (
        isinstance(current, dict)
        and current.get("status") == "ACTIVE"
        and current.get("run_id") == historical_producer.get("run_id")
        and str(current.get("owner_key") or "")
        and current.get("owner_key") != historical_producer.get("owner_key")
        and registered_projection_handoff(
            str(historical_producer.get("owner_key") or ""),
            str(current.get("owner_key") or ""),
            identity,
        )
    ):
        return False
    history = current.get("history")
    matches = [
        row
        for row in history if isinstance(row, Mapping)
        and row.get("owner_key") == historical_producer.get("owner_key")
        and row.get("contract_digest")
        == historical_producer.get("contract_digest")
        and row.get("launch_digest")
        == historical_producer.get("launch_digest")
        and row.get("run_id") == historical_producer.get("run_id")
        and row.get("sha256") == expected_record.get("sha256")
        and row.get("size") == expected_record.get("size")
        and row.get("status") == "SUPERSEDED"
        and row.get("superseded_by_owner_key") == current.get("owner_key")
    ] if isinstance(history, list) else []
    if len(matches) != 1:
        return False
    current_unit = units.get(str(current["owner_key"]))
    if not (
        isinstance(current_unit, Mapping)
        and _producer_authority_is_active(
            ledger,
            current,
            identity=identity,
            run_id=str(current.get("run_id") or ""),
        )
    ):
        return False
    try:
        live = _semantic_artifact_state(
            Path(scratchpad), Path(project_root), identity,
        )
    except ArtifactLedgerError:
        return False
    mutated_identity = not (
        live.get("status") == "ACTIVE"
        and live.get("size") == current.get("size")
        and live.get("sha256") == current.get("sha256")
    )
    if mutated_identity and _semantic_mutation_producer_authority(
        Path(scratchpad),
        project_root=Path(project_root),
        identity=identity,
        producer=current,
        live_state=live,
    ) is None:
        return False

    # Validate only same-owner siblings here.  This keeps the proof bounded to
    # one registered handoff and prevents recursive successor cycles.
    exemptions = {identity} if mutated_identity else set()
    commit = current_unit.get("commit_authority")
    current_expected = (
        commit.get("expected_output_records")
        if isinstance(commit, Mapping)
        else None
    )
    if not isinstance(current_expected, Mapping):
        return False
    for sibling_identity in current_expected:
        sibling = bindings.get(sibling_identity)
        if not (
            isinstance(sibling, dict)
            and sibling.get("owner_key") == current.get("owner_key")
            and sibling.get("contract_digest") == current.get("contract_digest")
            and sibling.get("launch_digest") == current.get("launch_digest")
            and sibling.get("run_id") == current.get("run_id")
        ):
            continue
        try:
            sibling_live = _semantic_artifact_state(
                Path(scratchpad), Path(project_root), str(sibling_identity),
            )
        except ArtifactLedgerError:
            continue
        if (
            sibling_live.get("status") == "ACTIVE"
            and (
                sibling_live.get("size") != sibling.get("size")
                or sibling_live.get("sha256") != sibling.get("sha256")
            )
            and _semantic_mutation_producer_authority(
                Path(scratchpad),
                project_root=Path(project_root),
                identity=str(sibling_identity),
                producer=sibling,
                live_state=sibling_live,
            ) is not None
        ):
            exemptions.add(str(sibling_identity))
    try:
        return not _replay_output_commit_authority(
            Path(scratchpad),
            Path(project_root),
            current_unit,
            require_live_bytes=True,
            live_byte_exempt_identities=tuple(sorted(exemptions)),
        )
    except (ArtifactLedgerError, OSError, RuntimeError, TypeError, ValueError):
        return False


def _input_set_digest(records: dict[str, dict[str, Any]]) -> str:
    semantic = [
        {
            "identity": identity,
            "input_class": row.get("input_class", ""),
            "status": row.get("status", ""),
            "size": row.get("size", 0),
            "sha256": row.get("sha256", ""),
            "producer_work_unit_key": row.get("producer_work_unit_key", ""),
            "producer_contract_digest": row.get("producer_contract_digest", ""),
        }
        for identity, row in sorted(records.items())
    ]
    encoded = json.dumps(
        semantic, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _output_prestate_digest(records: Mapping[str, Mapping[str, Any]]) -> str:
    semantic = [
        {
            "identity": identity,
            "write_mode": row.get("write_mode", ""),
            "status": row.get("status", ""),
            "existed": bool(row.get("existed", False)),
            "size": row.get("size", 0),
            "sha256": row.get("sha256", ""),
            "physical_identity": row.get("physical_identity", ""),
            "predecessor_owner_key": row.get("predecessor_owner_key", ""),
            "predecessor_contract_digest": row.get(
                "predecessor_contract_digest", ""
            ),
            "predecessor_launch_digest": row.get(
                "predecessor_launch_digest", ""
            ),
            "external_preimage_validator": row.get(
                "external_preimage_validator", ""
            ),
            "external_preimage_receipt": row.get(
                "external_preimage_receipt"
            ),
            "external_preimage_validation_error": row.get(
                "external_preimage_validation_error", ""
            ),
            "semantic_predecessor_authority": row.get(
                "semantic_predecessor_authority"
            ),
        }
        for identity, row in sorted(records.items())
    ]
    return hashlib.sha256(
        json.dumps(
            semantic, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")
    ).hexdigest()


def _output_manifest_shapes(
    rows: object,
) -> list[dict[str, Any]] | None:
    """Compare output contracts without conflating generation owner keys."""

    if not isinstance(rows, list):
        return None
    shapes: list[dict[str, Any]] = []
    for raw in rows:
        if not isinstance(raw, dict):
            return None
        row = dict(raw)
        row.pop("owner_key", None)
        shapes.append(row)
    return sorted(shapes, key=lambda row: str(row.get("identity") or ""))


def _report_index_retry_parts(
    contract: PhaseIOContract,
) -> tuple[int, str, str] | None:
    unit = str(contract.work_unit_id or "")
    matched = re.fullmatch(r"model\.attempt-(\d{4})", unit)
    if (
        contract.phase != "report_index"
        or contract.model_invoked is not True
        or matched is None
    ):
        return None
    ordinal = int(matched.group(1))
    if ordinal < 2:
        return None
    prefix = contract.key.rsplit("/", 1)[0]
    prior_model = (
        f"{prefix}/model"
        if ordinal == 2
        else f"{prefix}/model.attempt-{ordinal - 1:04d}"
    )
    prior_driver = (
        f"{prefix}/summary_parity"
        if ordinal == 2
        else f"{prefix}/summary_parity.attempt-{ordinal - 1:04d}"
    )
    return ordinal, prior_model, prior_driver


def _authorized_report_index_generation_predecessor(
    scratchpad: Path,
    project_root: Path,
    contract: PhaseIOContract,
    ledger: Mapping[str, Any],
    *,
    identity: str,
    predecessor: Mapping[str, Any],
    run_id: str,
) -> bool:
    """Authorize retry N only from the exact prior report-index generation.

    Retry N accepts one complete current report head owned by the immediately
    preceding Summary or canonical successor.  Split MODEL/Summary generations
    are deliberately rejected; historical work-unit records are never
    rewritten or upgraded in place.
    """

    parts = _report_index_retry_parts(contract)
    if parts is None:
        return False
    ordinal, prior_model_key, prior_driver_key = parts
    key_prefix = contract.key.rsplit("/", 1)[0]
    prior_canonical_key = (
        f"{key_prefix}/canonicalize"
        if ordinal == 2
        else f"{key_prefix}/canonicalize.attempt-{ordinal - 1:04d}"
    )
    head_identities = {
        "scratchpad:report_index.md",
        "scratchpad:report_coverage.md",
    }
    if contract.pipeline == "l1":
        head_identities.add("scratchpad:report_records.json")
    if (
        {spec.identity for spec in contract.outputs} != head_identities
        or identity not in head_identities
    ):
        return False
    owner_key = str(predecessor.get("owner_key") or "")
    if owner_key not in {prior_driver_key, prior_canonical_key}:
        return False
    if not _producer_authority_is_active(
        ledger, predecessor, identity=identity, run_id=run_id
    ):
        return False

    work_units = ledger.get("work_units")
    prior_model = (
        work_units.get(prior_model_key)
        if isinstance(work_units, Mapping)
        else None
    )
    if (
        not isinstance(prior_model, dict)
        or not _active_commit_receipt_is_valid(
            prior_model,
            work_unit_key=prior_model_key,
            run_id=run_id,
        )
        or prior_model.get("model_invoked") is not True
    ):
        return False
    prior_manifest = prior_model.get("contract_manifest")
    current_manifest = contract.to_dict()
    if (
        not isinstance(prior_manifest, dict)
        or _contract_manifest_digest(prior_manifest)
        != prior_model.get("contract_digest")
        or prior_manifest.get("model_invoked") is not True
        or prior_manifest.get("immutable_inputs")
        != list(contract.immutable_inputs)
        or prior_manifest.get("bounded_lookup_inputs")
        != list(contract.bounded_lookup_inputs)
        or _output_manifest_shapes(prior_manifest.get("outputs"))
        != _output_manifest_shapes(current_manifest.get("outputs"))
        or set(prior_model.get("artifacts", {})) != head_identities
        or set(
            prior_model.get("commit_authority", {}).get(
                "expected_output_records", {}
            )
        ) != head_identities
        or _replay_output_commit_authority(
            scratchpad,
            project_root,
            prior_model,
            require_live_bytes=False,
        )
    ):
        return False

    current_inputs: dict[str, dict[str, Any]] = {}
    for input_identity in contract.immutable_inputs:
        current_inputs[input_identity] = _input_binding_record(
            scratchpad,
            project_root,
            input_identity,
            "IMMUTABLE",
            dict(ledger),
        )
    for input_identity in contract.bounded_lookup_inputs:
        current_inputs[input_identity] = _input_binding_record(
            scratchpad,
            project_root,
            input_identity,
            (
                "IMMUTABLE_AND_BOUNDED_LOOKUP"
                if input_identity in current_inputs
                else "BOUNDED_LOOKUP"
            ),
            dict(ledger),
        )
    if (
        any(row.get("status") != "ACTIVE" for row in current_inputs.values())
        or _input_set_digest(current_inputs)
        != prior_model.get("input_set_digest")
    ):
        return False

    prior_model_artifacts = prior_model.get("artifacts")
    if not isinstance(prior_model_artifacts, Mapping):
        return False

    def _manifest_outputs(manifest: object) -> set[str]:
        if not isinstance(manifest, Mapping):
            return set()
        outputs = manifest.get("outputs")
        if not isinstance(outputs, list):
            return set()
        return {
            str(row.get("identity") or "")
            for row in outputs
            if isinstance(row, Mapping)
        }

    def _stable_binding_snapshot(
        binding: object, artifact_identity: str,
    ) -> bool:
        if not isinstance(binding, Mapping):
            return False
        try:
            path = _path_for_identity(
                scratchpad, project_root, artifact_identity
            )
            snapshot, error = _stable_artifact_snapshot(path)
        except ArtifactLedgerError:
            return False
        return bool(
            not error
            and isinstance(snapshot, Mapping)
            and snapshot.get("sha256") == binding.get("sha256")
            and snapshot.get("size") == binding.get("size")
        )

    def _prestate_matches_source(
        prestate: object,
        source_key: str,
        source_unit: Mapping[str, Any],
        artifact_identity: str,
    ) -> bool:
        artifact = source_unit.get("artifacts", {}).get(artifact_identity)
        return bool(
            isinstance(prestate, Mapping)
            and prestate.get("identity") == artifact_identity
            and prestate.get("status") == "ACTIVE_REGISTERED_PREDECESSOR"
            and prestate.get("write_mode") == "REPLACE"
            and prestate.get("predecessor_owner_key") == source_key
            and prestate.get("predecessor_contract_digest")
            == source_unit.get("contract_digest")
            and prestate.get("predecessor_launch_digest")
            == source_unit.get("launch_digest")
            and isinstance(artifact, Mapping)
            and artifact.get("owner_key") == source_key
            and artifact.get("run_id") == run_id
            and artifact.get("sha256") == prestate.get("sha256")
            and artifact.get("size") == prestate.get("size")
        )

    expected_summary_receipt = (
        "scratchpad:report_index_summary_parity_receipt.json"
        if ordinal == 2
        else (
            "scratchpad:report_index_summary_parity_receipt."
            f"attempt-{ordinal - 1:04d}.json"
        )
    )

    def _complete_summary_authority(*, require_current_head: bool) -> bool:
        prior_driver = (
            work_units.get(prior_driver_key)
            if isinstance(work_units, Mapping)
            else None
        )
        if not isinstance(prior_driver, dict):
            return False
        driver_manifest = prior_driver.get("contract_manifest")
        expected_outputs = head_identities | {expected_summary_receipt}
        driver_prestates = prior_driver.get("output_prestates")
        driver_artifacts = prior_driver.get("artifacts")
        driver_commit = prior_driver.get("commit_authority")
        try:
            driver_prestate_digest = (
                _output_prestate_digest(driver_prestates)
                if isinstance(driver_prestates, Mapping)
                else ""
            )
        except (AttributeError, TypeError, ValueError):
            driver_prestate_digest = ""
        if not (
            _active_commit_receipt_is_valid(
                prior_driver,
                work_unit_key=prior_driver_key,
                run_id=run_id,
            )
            and prior_driver.get("model_invoked") is False
            and isinstance(driver_manifest, Mapping)
            and _contract_manifest_digest(dict(driver_manifest))
            == prior_driver.get("contract_digest")
            and driver_manifest.get("model_invoked") is False
            and driver_manifest.get("immutable_inputs") == []
            and driver_manifest.get("bounded_lookup_inputs") == []
            and _manifest_outputs(driver_manifest) == expected_outputs
            and isinstance(driver_prestates, Mapping)
            and set(driver_prestates) == expected_outputs
            and driver_prestate_digest
            == prior_driver.get("output_prestate_digest")
            and all(
                isinstance(prestate, Mapping)
                and prestate.get("identity") == prestate_identity
                and _output_prestate_is_clean(prestate)
                for prestate_identity, prestate
                in driver_prestates.items()
            )
            and isinstance(driver_artifacts, Mapping)
            and set(driver_artifacts) == expected_outputs
            and isinstance(driver_commit, Mapping)
            and set(driver_commit.get("expected_output_records", {}))
            == expected_outputs
            and all(
                _prestate_matches_source(
                    driver_prestates.get(head_identity),
                    prior_model_key,
                    prior_model,
                    head_identity,
                )
                for head_identity in head_identities
            )
            and all(
                isinstance(driver_artifacts.get(head_identity), Mapping)
                and driver_artifacts[head_identity].get("owner_key")
                == prior_driver_key
                and driver_artifacts[head_identity].get("run_id") == run_id
                and driver_artifacts[head_identity].get("writer") == "DRIVER"
                for head_identity in head_identities
            )
            and all(
                driver_artifacts[head_identity].get("sha256")
                == prior_model_artifacts[head_identity].get("sha256")
                and driver_artifacts[head_identity].get("size")
                == prior_model_artifacts[head_identity].get("size")
                for head_identity in head_identities
                if head_identity != "scratchpad:report_index.md"
            )
            and not _replay_output_commit_authority(
                scratchpad,
                project_root,
                prior_driver,
                require_live_bytes=require_current_head,
            )
        ):
            return False
        receipt_binding = ledger.get("artifact_bindings", {}).get(
            expected_summary_receipt
        )
        if not (
            isinstance(receipt_binding, Mapping)
            and receipt_binding.get("owner_key") == prior_driver_key
            and receipt_binding.get("run_id") == run_id
            and receipt_binding.get("writer") == "DRIVER"
            and _stable_binding_snapshot(
                receipt_binding, expected_summary_receipt
            )
            and _producer_authority_is_active(
                ledger,
                receipt_binding,
                identity=expected_summary_receipt,
                run_id=run_id,
            )
        ):
            return False
        if not require_current_head:
            return True
        bindings = ledger.get("artifact_bindings")
        return bool(
            isinstance(bindings, Mapping)
            and all(
                isinstance(bindings.get(head_identity), Mapping)
                and bindings[head_identity].get("owner_key")
                == prior_driver_key
                and bindings[head_identity].get("run_id") == run_id
                and bindings[head_identity].get("contract_digest")
                == prior_driver.get("contract_digest")
                and bindings[head_identity].get("launch_digest")
                == prior_driver.get("launch_digest")
                and bindings[head_identity].get("writer") == "DRIVER"
                and bindings[head_identity].get("sha256")
                == driver_artifacts[head_identity].get("sha256")
                and bindings[head_identity].get("size")
                == driver_artifacts[head_identity].get("size")
                and _producer_authority_is_active(
                    ledger,
                    bindings[head_identity],
                    identity=head_identity,
                    run_id=run_id,
                )
                for head_identity in head_identities
            )
        )

    if owner_key == prior_driver_key:
        return _complete_summary_authority(require_current_head=True)

    if owner_key == prior_canonical_key:
        prior_canonical = (
            work_units.get(prior_canonical_key)
            if isinstance(work_units, Mapping)
            else None
        )
        canonical_manifest = (
            prior_canonical.get("contract_manifest")
            if isinstance(prior_canonical, Mapping)
            else None
        )
        receipt_identity = (
            "scratchpad:report_index_canonicalization_receipt.json"
            if ordinal == 2
            else (
                "scratchpad:report_index_canonicalization_receipt."
                f"attempt-{ordinal - 1:04d}.json"
            )
        )
        expected_outputs = {
            "scratchpad:report_index.md",
            "scratchpad:report_coverage.md",
            "scratchpad:report_index_status_projection.json",
            "scratchpad:_severity_override_ledger.json",
            "scratchpad:severity_overrides.md",
            "scratchpad:report_dropout_retention.json",
            "scratchpad:report_semantic_report_dropouts.md",
            "scratchpad:report_index_canonicalization_journal.json",
            receipt_identity,
        }
        if contract.pipeline == "l1":
            expected_outputs.add("scratchpad:report_records.json")
        manifest_outputs = _manifest_outputs(canonical_manifest)
        canonical_prestates = (
            prior_canonical.get("output_prestates")
            if isinstance(prior_canonical, Mapping)
            else None
        )
        receipt_binding = ledger.get("artifact_bindings", {}).get(
            receipt_identity
        )
        journal_binding = ledger.get("artifact_bindings", {}).get(
            "scratchpad:report_index_canonicalization_journal.json"
        )
        try:
            receipt_path = _path_for_identity(
                scratchpad, project_root, receipt_identity
            )
            receipt_snapshot, receipt_snapshot_error = (
                _stable_artifact_snapshot(receipt_path)
                if receipt_path.is_file()
                else (None, "MISSING")
            )
            journal_identity = (
                "scratchpad:"
                "report_index_canonicalization_journal.json"
            )
            journal_path = _path_for_identity(
                scratchpad, project_root, journal_identity
            )
            journal_snapshot, journal_snapshot_error = (
                _stable_artifact_snapshot(journal_path)
                if journal_path.is_file()
                else (None, "MISSING")
            )
        except ArtifactLedgerError:
            receipt_snapshot = journal_snapshot = None
            receipt_snapshot_error = journal_snapshot_error = "UNSAFE"
        if not (
            isinstance(prior_canonical, dict)
            and _active_commit_receipt_is_valid(
                prior_canonical,
                work_unit_key=prior_canonical_key,
                run_id=run_id,
            )
            and prior_canonical.get("model_invoked") is False
            and isinstance(canonical_manifest, dict)
            and _contract_manifest_digest(canonical_manifest)
            == prior_canonical.get("contract_digest")
            and canonical_manifest.get("model_invoked") is False
            and manifest_outputs == expected_outputs
            and isinstance(canonical_prestates, Mapping)
            and len({
                str(canonical_prestates[output_identity].get(
                    "predecessor_owner_key"
                ) or "")
                for output_identity in head_identities
                if isinstance(
                    canonical_prestates.get(output_identity), Mapping
                )
            }) == 1
            and isinstance(receipt_binding, Mapping)
            and not receipt_snapshot_error
            and isinstance(receipt_snapshot, Mapping)
            and receipt_snapshot.get("sha256")
            == receipt_binding.get("sha256")
            and receipt_snapshot.get("size") == receipt_binding.get("size")
            and receipt_binding.get("owner_key") == prior_canonical_key
            and _producer_authority_is_active(
                ledger,
                receipt_binding,
                identity=receipt_identity,
                run_id=run_id,
            )
            and isinstance(journal_binding, Mapping)
            and not journal_snapshot_error
            and isinstance(journal_snapshot, Mapping)
            and journal_snapshot.get("sha256")
            == journal_binding.get("sha256")
            and journal_snapshot.get("size") == journal_binding.get("size")
            and journal_binding.get("owner_key") == prior_canonical_key
            and _producer_authority_is_active(
                ledger,
                journal_binding,
                identity=(
                    "scratchpad:"
                    "report_index_canonicalization_journal.json"
                ),
                run_id=run_id,
            )
            and all(
                isinstance(
                    ledger.get("artifact_bindings", {}).get(
                        output_identity
                    ),
                    Mapping,
                )
                and ledger["artifact_bindings"][output_identity].get(
                    "owner_key"
                ) == prior_canonical_key
                and _producer_authority_is_active(
                    ledger,
                    ledger["artifact_bindings"][output_identity],
                    identity=output_identity,
                    run_id=run_id,
                )
                for output_identity in head_identities
            )
            and not _replay_output_commit_authority(
                scratchpad,
                project_root,
                prior_canonical,
                require_live_bytes=True,
            )
        ):
            return False
        source_owners = {
            str(canonical_prestates[output_identity].get(
                "predecessor_owner_key"
            ) or "")
            for output_identity in head_identities
        }
        if len(source_owners) != 1:
            return False
        source_owner = next(iter(source_owners))
        if source_owner == prior_model_key:
            source_unit = prior_model
        elif source_owner == prior_driver_key:
            if not _complete_summary_authority(require_current_head=False):
                return False
            source_unit = work_units.get(prior_driver_key)
        else:
            return False
        if not isinstance(source_unit, Mapping) or not all(
            _prestate_matches_source(
                canonical_prestates.get(head_identity),
                source_owner,
                source_unit,
                head_identity,
            )
            and registered_projection_handoff(
                source_owner,
                prior_canonical_key,
                head_identity,
            )
            for head_identity in head_identities
        ):
            return False
        return True
    return False


def _authorized_model_retry_predecessor(
    scratchpad: Path,
    project_root: Path,
    contract: PhaseIOContract,
    ledger: Mapping[str, Any],
    *,
    identity: str,
    run_id: str,
) -> dict[str, str] | None:
    """Authorize an uncommitted prior MODEL attempt as retry prestate.

    A failed worker may leave useful but structurally incomplete bytes before
    it has any artifact authority.  The next execution must not retroactively
    bless those bytes, but it also must not be unable to repair them.  Retry
    work units therefore use an immutable ``.attempt-NNNN`` identity.  This
    helper accepts the existing canonical file only as an output *prestate*
    when the immediately preceding attempt has a clean, same-run,
    input-bound receipt, no committed artifacts, an identical semantic
    denominator, and the same output contract apart from owner identity.
    The old bytes remain untrusted; only the new attempt's post-execution
    output can become ACTIVE.
    """

    unit = str(contract.work_unit_id or "")
    if (
        contract.model_invoked is not True
        or ".attempt-" not in unit
    ):
        return None
    base, raw_ordinal = unit.rsplit(".attempt-", 1)
    registered_report_index_model = bool(
        contract.phase == "report_index" and base == "model"
    )
    if (
        (not base.startswith("worker.") and not registered_report_index_model)
        or ".attempt-" in base
        or len(raw_ordinal) != 4
        or not raw_ordinal.isdigit()
    ):
        return None
    ordinal = int(raw_ordinal)
    if ordinal < 2:
        return None
    prior_unit_id = (
        base
        if ordinal == 2
        else f"{base}.attempt-{ordinal - 1:04d}"
    )
    key_prefix = contract.key.rsplit("/", 1)[0]
    prior_key = f"{key_prefix}/{prior_unit_id}"
    work_units = ledger.get("work_units")
    prior = (
        work_units.get(prior_key)
        if isinstance(work_units, Mapping)
        else None
    )
    if (
        not isinstance(prior, dict)
        or prior.get("schema") != "plamen.artifact-work-unit.v2"
        or prior.get("work_unit_key") != prior_key
        or prior.get("run_id") != run_id
        or prior.get("model_invoked") is not True
        or prior.get("semantic_status") != "INPUTS_BOUND"
        or prior.get("execution_state") != "INPUTS_BOUND_PREEXECUTION"
        or prior.get("artifacts") != {}
    ):
        return None
    manifest = prior.get("contract_manifest")
    if (
        not isinstance(manifest, dict)
        or _contract_manifest_digest(manifest)
        != prior.get("contract_digest")
        or manifest.get("model_invoked") is not True
        or manifest.get("immutable_inputs")
        != list(contract.immutable_inputs)
        or manifest.get("bounded_lookup_inputs")
        != list(contract.bounded_lookup_inputs)
    ):
        return None

    if _output_manifest_shapes(manifest.get("outputs")) != _output_manifest_shapes(
        contract.to_dict().get("outputs")
    ):
        return None
    prior_prestates = prior.get("output_prestates")
    if (
        not isinstance(prior_prestates, dict)
        or set(prior_prestates)
        != {spec.identity for spec in contract.outputs}
        or _output_prestate_digest(prior_prestates)
        != prior.get("output_prestate_digest")
        or any(
            not isinstance(row, Mapping) or not _output_prestate_is_clean(row)
            for row in prior_prestates.values()
        )
    ):
        return None

    current_inputs: dict[str, dict[str, Any]] = {}
    for input_identity in contract.immutable_inputs:
        current_inputs[input_identity] = _input_binding_record(
            scratchpad,
            project_root,
            input_identity,
            "IMMUTABLE",
            dict(ledger),
        )
    for input_identity in contract.bounded_lookup_inputs:
        input_class = (
            "IMMUTABLE_AND_BOUNDED_LOOKUP"
            if input_identity in current_inputs
            else "BOUNDED_LOOKUP"
        )
        current_inputs[input_identity] = _input_binding_record(
            scratchpad,
            project_root,
            input_identity,
            input_class,
            dict(ledger),
        )
    if (
        any(row.get("status") != "ACTIVE" for row in current_inputs.values())
        or _input_set_digest(current_inputs)
        != prior.get("input_set_digest")
    ):
        return None
    return {
        "owner_key": prior_key,
        "contract_digest": str(prior.get("contract_digest") or ""),
        "launch_digest": str(prior.get("launch_digest") or ""),
    }


def _output_prestate_records(
    scratchpad: Path,
    project_root: Path,
    contract: PhaseIOContract,
    ledger: Mapping[str, Any],
    *,
    run_id: str,
    _validation_context: _ArtifactValidationContext | None = None,
) -> dict[str, dict[str, Any]]:
    records: dict[str, dict[str, Any]] = {}
    bindings = ledger.get("artifact_bindings", {})
    for spec in contract.outputs:
        identity = spec.identity
        row: dict[str, Any] = {
            "identity": identity,
            "write_mode": spec.write_mode,
            "status": "INVALID",
            "existed": False,
            "size": 0,
            "sha256": "",
            "physical_identity": "",
            "predecessor_owner_key": "",
            "predecessor_contract_digest": "",
            "predecessor_launch_digest": "",
            "external_preimage_validator": (
                spec.external_preimage_validator
            ),
            "external_preimage_receipt": None,
            "external_preimage_validation_error": "",
            "semantic_predecessor_authority": None,
        }
        try:
            path = (
                _path_for_identity(scratchpad, project_root, identity)
                if _validation_context is None
                else _validation_context.path_for_identity(identity)
            )
            row["physical_identity"] = (
                _physical_file_identity(path)
                if _validation_context is None
                else _validation_context.physical_identity(path)
            )
        except ArtifactLedgerError as exc:
            lexical_alias = any(
                isinstance(other_identity, str)
                and other_identity != identity
                and unicodedata.normalize(
                    "NFC", other_identity
                ).casefold()
                == unicodedata.normalize("NFC", identity).casefold()
                and isinstance(raw, Mapping)
                and raw.get("status") == "ACTIVE"
                for other_identity, raw in (
                    bindings.items()
                    if isinstance(bindings, Mapping)
                    else ()
                )
            )
            row["status"] = (
                "PHYSICAL_OWNER_CONFLICT"
                if lexical_alias
                else "UNSAFE_PHYSICAL_PATH"
            )
            row["snapshot_error"] = str(exc)
            records[identity] = row
            continue
        physical_conflict = False
        if isinstance(bindings, Mapping):
            for other_identity, raw in bindings.items():
                if (
                    other_identity == identity
                    or not isinstance(raw, Mapping)
                    or raw.get("status") != "ACTIVE"
                ):
                    continue
                try:
                    other_physical = str(raw.get("physical_identity") or "")
                    if not other_physical:
                        other_path = (
                            _path_for_identity(
                                scratchpad,
                                project_root,
                                str(other_identity),
                            )
                            if _validation_context is None
                            else _validation_context.path_for_identity(
                                str(other_identity)
                            )
                        )
                        other_physical = (
                            _physical_file_identity(other_path)
                            if _validation_context is None
                            else _validation_context.physical_identity(
                                other_path
                            )
                        )
                except ArtifactLedgerError:
                    continue
                if other_physical == row["physical_identity"]:
                    physical_conflict = True
                    break
        if physical_conflict:
            row["status"] = "PHYSICAL_OWNER_CONFLICT"
            records[identity] = row
            continue
        if not rooted_io.lexists(path):
            if spec.external_preimage_validator:
                try:
                    row["external_preimage_receipt"] = (
                        derive_external_preimage_receipt(
                            validator_id=spec.external_preimage_validator,
                            work_unit_key=contract.key,
                            contract_digest=contract.digest,
                            artifact_identity=identity,
                            raw=b"",
                            existed=False,
                        )
                    )
                    row["sha256"] = hashlib.sha256(b"").hexdigest()
                    row["status"] = "VALIDATED_EXTERNAL_EMPTY_PREIMAGE"
                except ExternalPreimageValidationError as exc:
                    row["external_preimage_validation_error"] = str(exc)
                    row["status"] = "EXTERNAL_PREIMAGE_VALIDATION_DEBT"
            else:
                row["status"] = (
                    "ABSENT"
                    if spec.write_mode in {"CREATE", "REPLACE"}
                    else "MISSING_REQUIRED_PREIMAGE"
                )
            records[identity] = row
            continue
        snapshot, snapshot_error = (
            _stable_artifact_snapshot(path)
            if _validation_context is None
            else _validation_context.snapshot(path)
        )
        if snapshot is None:
            row["status"] = snapshot_error or "UNSTABLE_OUTPUT_PRESTATE"
            records[identity] = row
            continue
        row.update(snapshot)
        row["existed"] = True
        predecessor = (
            bindings.get(identity) if isinstance(bindings, Mapping) else None
        )
        if not isinstance(predecessor, Mapping):
            retry_predecessor = _authorized_model_retry_predecessor(
                scratchpad,
                project_root,
                contract,
                ledger,
                identity=identity,
                run_id=run_id,
            )
            if retry_predecessor is not None:
                row.update({
                    "predecessor_owner_key": retry_predecessor["owner_key"],
                    "predecessor_contract_digest": (
                        retry_predecessor["contract_digest"]
                    ),
                    "predecessor_launch_digest": (
                        retry_predecessor["launch_digest"]
                    ),
                    "status": "AUTHORIZED_MODEL_RETRY_PRESTATE",
                })
                records[identity] = row
                continue
            if spec.external_preimage_validator:
                try:
                    raw = rooted_io.read_bytes(
                        path,
                        label="external output preimage",
                        require_single_link=True,
                    )
                    if (
                        len(raw) != int(snapshot["size"])
                        or hashlib.sha256(raw).hexdigest()
                        != snapshot["sha256"]
                    ):
                        raise ExternalPreimageValidationError(
                            "external preimage changed during stable snapshot"
                        )
                    row["external_preimage_receipt"] = (
                        derive_external_preimage_receipt(
                            validator_id=spec.external_preimage_validator,
                            work_unit_key=contract.key,
                            contract_digest=contract.digest,
                            artifact_identity=identity,
                            raw=raw,
                            existed=True,
                        )
                    )
                    row["status"] = "VALIDATED_EXTERNAL_PREIMAGE"
                except (OSError, ExternalPreimageValidationError) as exc:
                    row["external_preimage_validation_error"] = str(exc)
                    row["status"] = "EXTERNAL_PREIMAGE_VALIDATION_DEBT"
            else:
                row["status"] = "UNOWNED_EXISTING_OUTPUT"
            records[identity] = row
            continue
        row.update({
            "predecessor_owner_key": str(predecessor.get("owner_key") or ""),
            "predecessor_contract_digest": str(
                predecessor.get("contract_digest") or ""
            ),
            "predecessor_launch_digest": str(
                predecessor.get("launch_digest") or ""
            ),
        })
        exact_bytes = bool(
            predecessor.get("sha256") == snapshot.get("sha256")
            and predecessor.get("size") == snapshot.get("size")
        )
        active_predecessor = bool(
            exact_bytes
            and _producer_authority_is_active(
                ledger, predecessor, identity=identity, run_id=run_id
            )
        )
        semantic_predecessor_authority: Mapping[str, Any] | None = None
        authorized_stale_semantic_base = False
        if (
            not exact_bytes
            and spec.write_mode in {"REPLACE", "MERGE"}
            and predecessor.get("owner_key") == contract.key
            and predecessor.get("status") == "STALE_INPUT"
            and predecessor.get("run_id") == run_id
            and predecessor.get("writer") == spec.writer
            and predecessor.get("write_mode") == spec.write_mode
        ):
            prior_unit = (
                ledger.get("work_units", {}).get(contract.key)
                if isinstance(ledger.get("work_units"), Mapping)
                else None
            )
            if (
                isinstance(prior_unit, dict)
                and prior_unit.get("semantic_status") == "STALE_INPUT"
            ):
                try:
                    stale_authority = (
                        _validated_stale_reexecution_authorization(
                            ledger, prior_unit, contract, run_id=run_id
                        )
                    )
                except ArtifactLedgerError:
                    pass
                else:
                    authorized_stale_semantic_base = identity in set(
                        stale_authority.get("changed_input_identities") or ()
                    )
        if (
            not exact_bytes
            and spec.write_mode in {"REPLACE", "MERGE"}
            and predecessor.get("run_id") == run_id
            and (
                _producer_authority_is_active(
                    ledger, predecessor, identity=identity, run_id=run_id
                )
                or authorized_stale_semantic_base
            )
            and (
                predecessor.get("owner_key") == contract.key
                or _registered_projection_handoff(predecessor, spec)
            )
        ):
            mutation_producer = dict(predecessor)
            if authorized_stale_semantic_base:
                # The durable reexecution authorization was minted only after
                # validating this exact historical output and the contiguous
                # report-mutation successor.  Replay the historical snapshot
                # as ACTIVE for lineage derivation without rewriting or
                # reblessing the stored STALE_INPUT binding.
                mutation_producer["status"] = "ACTIVE"
            mutation_authority = _semantic_mutation_producer_authority(
                Path(scratchpad),
                project_root=Path(project_root),
                identity=identity,
                producer=mutation_producer,
                live_state={
                    "status": "ACTIVE",
                    "size": int(snapshot["size"]),
                    "sha256": str(snapshot["sha256"]),
                },
            )
            if isinstance(mutation_authority, Mapping):
                candidate = mutation_authority.get(
                    "semantic_predecessor_authority"
                )
                if isinstance(candidate, Mapping):
                    semantic_predecessor_authority = dict(candidate)
                    row["semantic_predecessor_authority"] = dict(candidate)
        # A deterministic same-owner refresh is deliberately marked
        # STALE_INPUT before it can overwrite its prior bytes.  That status is
        # not an unregistered predecessor: the digest-bound semantic
        # invalidation receipt is the narrow replacement authority.  Validate
        # the complete authorization here so an arbitrary stale/tampered row
        # cannot be laundered into a clean REPLACE prestate.
        authorized_stale_predecessor = False
        if (
            exact_bytes
            and spec.write_mode in {"REPLACE", "MERGE"}
            and predecessor.get("owner_key") == contract.key
            and predecessor.get("status") == "STALE_INPUT"
            and predecessor.get("run_id") == run_id
            and predecessor.get("writer") == spec.writer
            and predecessor.get("write_mode") == spec.write_mode
        ):
            prior_unit = (
                ledger.get("work_units", {}).get(contract.key)
                if isinstance(ledger.get("work_units"), Mapping)
                else None
            )
            if (
                isinstance(prior_unit, dict)
                and prior_unit.get("semantic_status") == "STALE_INPUT"
            ):
                try:
                    _validated_stale_reexecution_authorization(
                        ledger, prior_unit, contract, run_id=run_id
                    )
                except ArtifactLedgerError:
                    pass
                else:
                    authorized_stale_predecessor = True
        elif (
            exact_bytes
            and spec.write_mode == "REPLACE"
            and predecessor.get("status") == "STALE_INPUT"
            and predecessor.get("run_id") == run_id
            and predecessor.get("writer") == spec.writer
            and predecessor.get("write_mode") == spec.write_mode
            and _registered_projection_handoff(predecessor, spec)
        ):
            try:
                _validated_stale_projection_handoff_authorization(
                    ledger,
                    predecessor,
                    spec,
                    run_id=run_id,
                )
            except ArtifactLedgerError:
                pass
            else:
                authorized_stale_predecessor = True
        if spec.write_mode == "CREATE":
            row["status"] = "CREATE_PRESTATE_PRESENT"
        elif spec.write_mode == "REPLACE":
            registered_predecessor = bool(
                active_predecessor
                and _registered_projection_handoff(predecessor, spec)
            )
            retry_parts = _report_index_retry_parts(contract)
            if registered_predecessor and retry_parts is not None:
                registered_predecessor = (
                    _authorized_report_index_generation_predecessor(
                        scratchpad,
                        project_root,
                        contract,
                        ledger,
                        identity=identity,
                        predecessor=predecessor,
                        run_id=run_id,
                    )
                )
            row["status"] = (
                "AUTHORIZED_STALE_PREDECESSOR"
                if authorized_stale_predecessor
                else (
                    "ACTIVE_REGISTERED_SEMANTIC_PREDECESSOR"
                    if semantic_predecessor_authority is not None
                    else (
                        "ACTIVE_REGISTERED_PREDECESSOR"
                        if registered_predecessor
                        else "UNREGISTERED_REPLACEMENT_PREDECESSOR"
                    )
                )
            )
        elif spec.write_mode == "MERGE":
            row["status"] = (
                "AUTHORIZED_STALE_PREDECESSOR"
                if authorized_stale_predecessor
                else (
                    "ACTIVE_REGISTERED_SEMANTIC_PREDECESSOR"
                    if semantic_predecessor_authority is not None
                    else (
                        "ACTIVE_PREIMAGE"
                        if active_predecessor
                        else "PREIMAGE_AUTHORITY_MISMATCH"
                    )
                )
            )
        else:
            row["status"] = (
                "ACTIVE_PREIMAGE"
                if active_predecessor
                else "PREIMAGE_AUTHORITY_MISMATCH"
            )
        records[identity] = row
    return records


def _output_prestate_is_clean(record: Mapping[str, Any]) -> bool:
    return str(record.get("status") or "") in {
        "ABSENT", "ACTIVE_REGISTERED_PREDECESSOR", "ACTIVE_PREIMAGE",
        "ACTIVE_REGISTERED_SEMANTIC_PREDECESSOR",
        "AUTHORIZED_STALE_PREDECESSOR",
        "AUTHORIZED_MODEL_RETRY_PRESTATE",
        "VALIDATED_EXTERNAL_PREIMAGE",
        "VALIDATED_EXTERNAL_EMPTY_PREIMAGE",
    }


def _contract_manifest_digest(manifest: dict[str, Any]) -> str:
    encoded = json.dumps(
        manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _input_rebind_event_digest(event: dict[str, Any]) -> str:
    unsigned = {key: value for key, value in event.items() if key != "event_digest"}
    encoded = json.dumps(
        unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _is_digest(value: object) -> bool:
    text = str(value or "")
    return len(text) == 64 and all(char in "0123456789abcdef" for char in text)


def _semantic_invalidation_authorization_digest(
    authorization: dict[str, Any],
) -> str:
    unsigned = {
        key: value
        for key, value in authorization.items()
        if key != "authorization_digest"
    }
    encoded = json.dumps(
        unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _validated_stale_projection_handoff_authorization(
    ledger: dict[str, Any],
    predecessor: Mapping[str, Any],
    successor_spec: ArtifactSpec,
    *,
    run_id: str,
) -> dict[str, Any]:
    """Validate a stale predecessor before a registered projection refresh.

    Semantic invalidation marks a deterministic projection's complete output
    bundle stale.  The next phase-scoped projection owner is a registered
    successor, but it is intentionally a different work-unit key.  This
    validator lets that exact handoff consume the stale bytes without treating
    them as unowned, while retaining the same fail-closed invalidation checks
    used for same-owner re-execution.
    """

    owner = str(predecessor.get("owner_key") or "")
    units = ledger.get("work_units")
    unit = units.get(owner) if isinstance(units, Mapping) else None
    if not isinstance(unit, dict):
        raise ArtifactLedgerError(
            "stale projection predecessor work unit is absent"
        )
    manifest = unit.get("contract_manifest")
    artifacts = unit.get("artifacts")
    authorization = unit.get("semantic_invalidation")
    if (
        unit.get("run_id") != run_id
        or unit.get("semantic_status") != "STALE_INPUT"
        or unit.get("work_unit_key") != owner
        or predecessor.get("run_id") != run_id
        or predecessor.get("status") != "STALE_INPUT"
        or predecessor.get("contract_digest") != unit.get("contract_digest")
        or not isinstance(manifest, dict)
        or manifest.get("key") != owner
        or _contract_manifest_digest(manifest) != unit.get("contract_digest")
        or not isinstance(artifacts, dict)
        or not artifacts
    ):
        raise ArtifactLedgerError(
            "stale projection predecessor identity is malformed"
        )
    manifest_outputs = manifest.get("outputs")
    if not isinstance(manifest_outputs, list):
        raise ArtifactLedgerError(
            "stale projection predecessor output manifest is malformed"
        )
    manifest_by_identity = {
        str(row.get("identity") or ""): row
        for row in manifest_outputs
        if isinstance(row, dict)
    }
    if set(manifest_by_identity) != set(artifacts):
        raise ArtifactLedgerError(
            "stale projection predecessor output denominator differs"
        )
    predecessor_spec = manifest_by_identity.get(successor_spec.identity)
    if not (
        isinstance(predecessor_spec, dict)
        and predecessor_spec.get("owner_key") == owner
        and predecessor_spec.get("writer") == successor_spec.writer
        and predecessor_spec.get("write_mode") == successor_spec.write_mode
        and predecessor_spec.get("schema_version")
        == successor_spec.schema_version
        and predecessor_spec.get("minimum_gate")
        == successor_spec.minimum_gate
        and _registered_projection_handoff(predecessor, successor_spec)
    ):
        raise ArtifactLedgerError(
            "stale projection predecessor is not a registered handoff"
        )
    if (
        not isinstance(authorization, dict)
        or set(authorization) != _SEMANTIC_INVALIDATION_AUTH_FIELDS
        or authorization.get("schema") != _SEMANTIC_INVALIDATION_AUTH_SCHEMA
        or not _is_digest(authorization.get("plan_digest"))
        or authorization.get("run_id") != run_id
        or authorization.get("work_unit_key") != owner
        or authorization.get("authorization_digest")
        != _semantic_invalidation_authorization_digest(authorization)
    ):
        raise ArtifactLedgerError(
            "stale projection invalidation authority is malformed"
        )
    changed = authorization.get("changed_input_identities")
    invalidated = authorization.get("invalidated_artifact_identities")
    triggers = authorization.get("trigger_identities")
    stale = authorization.get("stale_artifact_identities")
    if (
        not all(isinstance(rows, list) for rows in (
            changed, invalidated, triggers, stale,
        ))
        or changed != sorted(set(changed))
        or invalidated != sorted(set(invalidated))
        or triggers != sorted(set(triggers))
        or stale != sorted(artifacts)
        or not triggers
        or not set(triggers).issubset(set(changed) | set(invalidated))
    ):
        raise ArtifactLedgerError(
            "stale projection invalidation denominator is malformed"
        )
    bindings = ledger.get("artifact_bindings")
    for identity, record in artifacts.items():
        binding = bindings.get(identity) if isinstance(bindings, Mapping) else None
        if not (
            isinstance(record, dict)
            and record.get("status") == "STALE_INPUT"
            and record.get("owner_key") == owner
            and isinstance(binding, dict)
            and binding.get("status") == "STALE_INPUT"
            and binding.get("owner_key") == owner
            and binding.get("sha256") == record.get("sha256")
            and binding.get("size") == record.get("size")
        ):
            raise ArtifactLedgerError(
                f"stale projection output {identity} is not exact"
            )
    return dict(authorization)


def _validated_stale_reexecution_authorization(
    ledger: dict[str, Any],
    unit: dict[str, Any],
    contract: PhaseIOContract,
    *,
    run_id: str,
) -> dict[str, Any]:
    """Validate the exact invalidation authority before output re-execution."""

    authorization = unit.get("semantic_invalidation")
    if (
        not isinstance(authorization, dict)
        or set(authorization) != _SEMANTIC_INVALIDATION_AUTH_FIELDS
        or authorization.get("schema") != _SEMANTIC_INVALIDATION_AUTH_SCHEMA
        or not _is_digest(authorization.get("plan_digest"))
        or authorization.get("run_id") != run_id
        or authorization.get("work_unit_key") != contract.key
    ):
        raise ArtifactLedgerError(
            f"work unit {contract.key} semantic invalidation metadata is malformed"
        )
    changed = authorization.get("changed_input_identities")
    invalidated = authorization.get("invalidated_artifact_identities")
    triggers = authorization.get("trigger_identities")
    stale_identities = authorization.get("stale_artifact_identities")
    expected_outputs = sorted(spec.identity for spec in contract.outputs)
    if (
        not isinstance(changed, list)
        or not isinstance(invalidated, list)
        or not isinstance(triggers, list)
        or not isinstance(stale_identities, list)
        or changed != sorted(set(changed))
        or invalidated != sorted(set(invalidated))
        or triggers != sorted(set(triggers))
        or stale_identities != expected_outputs
        or not triggers
        or not set(triggers).issubset(set(changed) | set(invalidated))
        or any(
            not isinstance(identity, str) or identity.count(":") != 1
            for identity in [
                *changed, *invalidated, *triggers, *stale_identities
            ]
        )
        or authorization.get("authorization_digest")
        != _semantic_invalidation_authorization_digest(authorization)
    ):
        raise ArtifactLedgerError(
            f"work unit {contract.key} semantic invalidation metadata integrity failure"
        )
    records = unit.get("artifacts")
    if not isinstance(records, dict) or set(records) != set(expected_outputs):
        raise ArtifactLedgerError(
            f"work unit {contract.key} STALE_INPUT output denominator is malformed"
        )
    for identity, record in records.items():
        if not isinstance(record, dict) or record.get("status") != "STALE_INPUT":
            raise ArtifactLedgerError(
                f"work unit {contract.key} output {identity} is not STALE_INPUT"
            )
        binding = ledger.get("artifact_bindings", {}).get(identity)
        stale_same_owner = bool(
            isinstance(binding, dict)
            and binding.get("owner_key") == contract.key
            and binding.get("status") == "STALE_INPUT"
        )
        active_registered_successor = False
        if (
            isinstance(binding, dict)
            and identity in set(changed)
            and binding.get("owner_key") != contract.key
            and binding.get("status") == "ACTIVE"
            and binding.get("run_id") == run_id
            and binding.get("writer") == "DRIVER"
            and registered_projection_handoff(
                str(binding.get("owner_key") or ""),
                contract.key,
                identity,
            )
        ):
            successor_unit = ledger.get("work_units", {}).get(
                str(binding.get("owner_key") or "")
            )
            active_registered_successor = bool(
                isinstance(successor_unit, Mapping)
                and _producer_authority_is_active(
                    ledger,
                    binding,
                    identity=identity,
                    run_id=run_id,
                )
            )
        if not stale_same_owner and not active_registered_successor:
            raise ArtifactLedgerError(
                f"work unit {contract.key} binding {identity} is not "
                "STALE_INPUT or an authenticated registered successor"
            )
        legacy = ledger.get("artifacts", {}).get(_legacy_name(identity))
        # ``artifacts`` is a legacy compatibility projection, not the typed
        # ownership authority.  Some compatibility writers legitimately
        # refresh an owner-less row after semantic invalidation.  It may only
        # constrain re-execution when it explicitly claims this work unit as
        # its owner; the mandatory typed ``artifact_bindings`` row above
        # remains the fail-closed authority in every case.
        if (
            isinstance(legacy, dict)
            and legacy.get("owner_key") == contract.key
            and legacy.get("status") != "STALE_INPUT"
        ):
            raise ArtifactLedgerError(
                f"work unit {contract.key} legacy binding {identity} is not STALE_INPUT"
            )
    return dict(authorization)


def _validated_input_rebind_history(
    unit: dict[str, Any], *, work_unit_key: str, run_id: str
) -> list[dict[str, Any]]:
    """Replay the bounded pre-output denominator replacement history."""

    raw = unit.get("input_rebind_history", [])
    if not isinstance(raw, list) or len(raw) > 32:
        raise ArtifactLedgerError("input rebind history is malformed or unbounded")
    validated: list[dict[str, Any]] = []
    prior_replacement_contract = ""
    prior_replacement_inputs = ""
    for ordinal, event in enumerate(raw, start=1):
        if not isinstance(event, dict) or set(event) != _INPUT_REBIND_EVENT_FIELDS:
            raise ArtifactLedgerError("input rebind history event schema is malformed")
        added = event.get("added_identities")
        removed = event.get("removed_identities")
        if (
            event.get("schema") != _INPUT_REBIND_HISTORY_SCHEMA
            or event.get("reason_code") not in _INPUT_REBIND_REASON_CODES
            or event.get("run_id") != run_id
            or event.get("work_unit_key") != work_unit_key
            or event.get("ordinal") != ordinal
            or not all(
                _is_digest(event.get(field))
                for field in (
                    "prior_contract_digest",
                    "replacement_contract_digest",
                    "prior_input_set_digest",
                    "replacement_input_set_digest",
                )
            )
            or not isinstance(added, list)
            or not isinstance(removed, list)
            or added != sorted(set(added))
            or removed != sorted(set(removed))
            or bool(set(added) & set(removed))
            or any(
                not isinstance(identity, str) or identity.count(":") != 1
                for identity in [*added, *removed]
            )
            or event.get("event_digest") != _input_rebind_event_digest(event)
        ):
            raise ArtifactLedgerError("input rebind history event integrity failure")
        if ordinal > 1 and (
            event.get("prior_contract_digest") != prior_replacement_contract
            or event.get("prior_input_set_digest") != prior_replacement_inputs
        ):
            raise ArtifactLedgerError("input rebind history chain is discontinuous")
        prior_replacement_contract = str(event["replacement_contract_digest"])
        prior_replacement_inputs = str(event["replacement_input_set_digest"])
        validated.append(dict(event))
    if validated and (
        prior_replacement_contract != str(unit.get("contract_digest") or "")
        or prior_replacement_inputs != str(unit.get("input_set_digest") or "")
    ):
        raise ArtifactLedgerError("input rebind history does not bind current unit")
    return validated


def _static_contract_manifest(contract: PhaseIOContract) -> dict[str, Any]:
    manifest = dict(contract.to_dict())
    manifest.pop("immutable_inputs", None)
    manifest.pop("bounded_lookup_inputs", None)
    manifest.pop("input_authority_requirements", None)
    return manifest


def _driver_rebind_contract_is_narrow(contract: PhaseIOContract) -> bool:
    return (
        contract.model_invoked is False
        and bool(contract.outputs)
        and all(spec.writer == "DRIVER" for spec in contract.outputs)
    )


def replace_uncommitted_driver_input_denominator(
    scratchpad: Path,
    project_root: Path,
    prior_contract: PhaseIOContract,
    replacement_contract: PhaseIOContract,
    launch: LaunchSpec,
    *,
    run_id: str,
    expected_prior_input_set_digest: str,
    reason_code: str,
) -> dict[str, Any]:
    """CAS-replace one driver-only input receipt before any output commit.

    This is deliberately narrower than semantic invalidation.  It may only
    replace a same-run, input-only, deterministic DRIVER work unit whose output
    denominator has never been recorded.  Once execution/artifact authority
    exists, ordinary invalidation and checkpoint reconciliation must be used.
    """

    prior_contract, launch = _replay_authority_pair(
        prior_contract, launch
    )
    replacement_contract, launch = _replay_authority_pair(
        replacement_contract, launch
    )
    run = str(run_id or "").strip()
    reason = str(reason_code or "").strip().upper()
    if not run or reason not in _INPUT_REBIND_REASON_CODES:
        raise ArtifactLedgerError("input rebind run/reason is invalid")
    if prior_contract.key != replacement_contract.key or launch.work_unit_key != prior_contract.key:
        raise ArtifactLedgerError("input rebind work-unit keys differ")
    if not _driver_rebind_contract_is_narrow(
        prior_contract
    ) or not _driver_rebind_contract_is_narrow(replacement_contract):
        raise ArtifactLedgerError("input rebind requires deterministic DRIVER ownership")
    if _static_contract_manifest(prior_contract) != _static_contract_manifest(
        replacement_contract
    ):
        raise ArtifactLedgerError("input rebind changed the static contract manifest")
    expected_prior = str(expected_prior_input_set_digest or "").strip()
    if not _is_digest(expected_prior):
        raise ArtifactLedgerError("input rebind compare-and-swap digest is invalid")

    with _ledger_transaction_lock(scratchpad):
        ledger = read_artifact_ledger(Path(scratchpad))
        prior = ledger["work_units"].get(prior_contract.key)
        if not isinstance(prior, dict):
            raise ArtifactLedgerError("input rebind prior work unit is missing")
        if prior.get("run_id") != run:
            raise ArtifactLedgerError(
                f"work unit {prior_contract.key} is already bound to another run"
            )
        if (
            prior.get("schema") != "plamen.artifact-work-unit.v2"
            or prior.get("work_unit_key") != prior_contract.key
            or prior.get("model_invoked") is not False
            or prior.get("contract_digest") != prior_contract.digest
            or prior.get("contract_manifest") != prior_contract.to_dict()
            or prior.get("input_set_digest") != expected_prior
        ):
            raise ArtifactLedgerError("input rebind compare-and-swap mismatch")
        if not _stored_launch_matches(prior, launch):
            raise ArtifactLedgerError("input rebind launch digest changed")
        artifacts = prior.get("artifacts")
        if artifacts != {}:
            raise ArtifactLedgerError("input rebind prior unit has recorded artifacts")
        if any(
            isinstance(row, dict) and row.get("owner_key") == prior_contract.key
            for table in ("artifact_bindings", "artifacts")
            for row in ledger.get(table, {}).values()
        ):
            raise ArtifactLedgerError("input rebind prior unit has recorded artifacts")
        if prior.get("execution_state") not in {
            None, "INPUTS_BOUND_PREEXECUTION",
        }:
            raise ArtifactLedgerError("input rebind prior execution is terminal")
        if prior.get("semantic_status") != "INPUTS_BOUND":
            raise ArtifactLedgerError("input rebind prior unit is not INPUTS_BOUND")
        prior_inputs = prior.get("input_bindings")
        if (
            not isinstance(prior_inputs, dict)
            or set(prior_inputs)
            != (
                set(prior_contract.immutable_inputs)
                | set(prior_contract.bounded_lookup_inputs)
            )
            or _input_set_digest(prior_inputs) != expected_prior
        ):
            raise ArtifactLedgerError("input rebind prior denominator is malformed")
        history = _validated_input_rebind_history(
            prior, work_unit_key=prior_contract.key, run_id=run
        )

        records: dict[str, dict[str, Any]] = {}
        for identity in replacement_contract.immutable_inputs:
            records[identity] = _input_binding_record(
                Path(scratchpad), Path(project_root), identity, "IMMUTABLE", ledger
            )
        for identity in replacement_contract.bounded_lookup_inputs:
            input_class = (
                "IMMUTABLE_AND_BOUNDED_LOOKUP"
                if identity in records
                else "BOUNDED_LOOKUP"
            )
            records[identity] = _input_binding_record(
                Path(scratchpad), Path(project_root), identity, input_class, ledger
            )
        if any(row.get("status") != "ACTIVE" for row in records.values()):
            raise ArtifactLedgerError("input rebind replacement denominator is incomplete")
        replacement_input_digest = _input_set_digest(records)
        if (
            replacement_contract.digest == prior_contract.digest
            and replacement_input_digest == expected_prior
        ):
            # Crash recovery may rediscover a provisional receipt whose live
            # denominator never changed.  Preserve it byte-for-byte and do not
            # invent a history event for a no-op compare-and-swap.
            return dict(prior)
        prior_identities = set(prior.get("input_bindings", {}))
        replacement_identities = set(records)
        event: dict[str, Any] = {
            "schema": _INPUT_REBIND_HISTORY_SCHEMA,
            "reason_code": reason,
            "run_id": run,
            "work_unit_key": prior_contract.key,
            "ordinal": len(history) + 1,
            "prior_contract_digest": prior_contract.digest,
            "replacement_contract_digest": replacement_contract.digest,
            "prior_input_set_digest": expected_prior,
            "replacement_input_set_digest": replacement_input_digest,
            "added_identities": sorted(replacement_identities - prior_identities),
            "removed_identities": sorted(prior_identities - replacement_identities),
        }
        event["event_digest"] = _input_rebind_event_digest(event)
        history.append(event)
        now = datetime.now(timezone.utc).isoformat()
        work_unit = {
            "schema": "plamen.artifact-work-unit.v2",
            "work_unit_key": replacement_contract.key,
            "run_id": run,
            "contract_digest": replacement_contract.digest,
            "contract_manifest": replacement_contract.to_dict(),
            "launch_digest": launch.digest,
            "launch_manifest": launch.to_dict(),
            "model_invoked": False,
            "recorded_at": prior.get("recorded_at", now),
            "input_recorded_at": now,
            "execution_state": "INPUTS_BOUND_PREEXECUTION",
            "semantic_status": "INPUTS_BOUND",
            "input_bindings": records,
            "input_set_digest": replacement_input_digest,
            "input_receipt_kind": (
                "BOUND_INPUTS" if records else "EXPLICIT_ZERO_INPUT"
            ),
            "input_rebind_history": history,
            # The output denominator was armed before the dynamic input set
            # drifted and may already bracket crash-persisted bytes.  Static
            # output specs are required equal above, so preserve—not
            # re-observe—the original pre-execution authority.
            "output_prestates": dict(prior.get("output_prestates") or {}),
            "output_prestate_digest": str(
                prior.get("output_prestate_digest") or ""
            ),
            "artifacts": {},
        }
        ledger["work_units"][replacement_contract.key] = work_unit
        write_artifact_ledger(Path(scratchpad), ledger)
        return work_unit


def recover_uncommitted_driver_input_denominator(
    scratchpad: Path,
    project_root: Path,
    replacement_contract: PhaseIOContract,
    launch: LaunchSpec,
    *,
    run_id: str,
    reason_code: str,
) -> dict[str, Any]:
    """Recover a crash-persisted provisional DRIVER input receipt.

    The prior dynamic input lists are recovered only from the digest-bound
    contract manifest already in the ledger.  All static fields and output
    specs come from the current resolved contract, then the ordinary CAS API
    performs the same same-run/no-output/history/live-input guards.
    """

    replacement_contract, launch = _replay_authority_pair(
        replacement_contract, launch
    )
    run = str(run_id or "").strip()
    if not run:
        raise ArtifactLedgerError("input recovery run_id must be non-empty")

    with _ledger_transaction_lock(scratchpad):
        ledger = read_artifact_ledger(Path(scratchpad))
        prior = ledger["work_units"].get(replacement_contract.key)
        if not isinstance(prior, dict):
            raise ArtifactLedgerError("input recovery prior work unit is missing")
        manifest = prior.get("contract_manifest")
        if not isinstance(manifest, dict):
            raise ArtifactLedgerError("input recovery contract manifest is malformed")
        try:
            requirement_rows = manifest.get(
                "input_authority_requirements", ()
            )
            if not isinstance(requirement_rows, (list, tuple)):
                raise ValueError(
                    "input_authority_requirements must be a sequence"
                )
            requirements: list[InputAuthorityRequirement] = []
            requirement_fields = {
                "identity",
                "allow_raw",
                "expected_producer_work_unit_key",
                "expected_writer",
                "require_same_run",
                "expected_contract_digest",
                "expected_launch_digest",
                "require_exact_contract",
                "require_exact_launch",
            }
            for row in requirement_rows:
                if (
                    not isinstance(row, dict)
                    or set(row) != requirement_fields
                ):
                    raise ValueError(
                        "input authority requirement manifest fields are "
                        "invalid"
                    )
                requirements.append(InputAuthorityRequirement(**row))
            prior_contract = PhaseIOContract(
                pipeline=replacement_contract.pipeline,
                mode=replacement_contract.mode,
                ecosystem=replacement_contract.ecosystem,
                backend=replacement_contract.backend,
                phase=replacement_contract.phase,
                work_unit_id=replacement_contract.work_unit_id,
                outputs=replacement_contract.outputs,
                immutable_inputs=tuple(manifest.get("immutable_inputs") or ()),
                bounded_lookup_inputs=tuple(
                    manifest.get("bounded_lookup_inputs") or ()
                ),
                model_invoked=manifest.get("model_invoked"),
                input_authority_requirements=tuple(requirements),
                launch_profile=str(manifest.get("launch_profile") or ""),
                required_commit_actor=str(
                    manifest.get("required_commit_actor") or ""
                ),
                contract_version=str(manifest.get("contract_version") or ""),
            )
        except (TypeError, ValueError) as exc:
            raise ArtifactLedgerError(
                f"input recovery contract manifest is invalid: {exc}"
            ) from exc
        if (
            prior_contract.to_dict() != manifest
            or prior_contract.digest != prior.get("contract_digest")
        ):
            raise ArtifactLedgerError(
                "input recovery contract manifest digest is invalid"
            )
        return replace_uncommitted_driver_input_denominator(
            Path(scratchpad),
            Path(project_root),
            prior_contract,
            replacement_contract,
            launch,
            run_id=run,
            expected_prior_input_set_digest=str(
                prior.get("input_set_digest") or ""
            ),
            reason_code=reason_code,
        )


def _canonical_preexecution_authority_extension(
    value: Mapping[str, Any],
) -> tuple[dict[str, Any], str]:
    """Return one exact JSON authority extension and its canonical digest.

    This is deliberately structure-agnostic: the owning producer validates its
    domain schema, while the ledger guarantees that the exact object supplied
    at first arm is atomic, canonical, and immutable on every replay.
    """

    if not isinstance(value, dict) or not value:
        raise ArtifactLedgerError(
            "preexecution authority extension must be a nonempty dict"
        )
    if any(not isinstance(key, str) or not key for key in value):
        raise ArtifactLedgerError(
            "preexecution authority extension keys must be nonempty strings"
        )
    try:
        raw = _canonical_json_bytes(value)
        replayed = json.loads(raw.decode("utf-8"))
    except (TypeError, ValueError, UnicodeError) as exc:
        raise ArtifactLedgerError(
            f"preexecution authority extension is not canonical JSON: {exc}"
        ) from exc
    if not isinstance(replayed, dict) or replayed != value:
        raise ArtifactLedgerError(
            "preexecution authority extension changes under JSON replay"
        )
    self_digest = replayed.get("authority_sha256")
    unsigned = dict(replayed)
    unsigned.pop("authority_sha256", None)
    if (
        not isinstance(self_digest, str)
        or re.fullmatch(r"[0-9a-f]{64}", self_digest) is None
        or self_digest != _canonical_json_digest(unsigned)
    ):
        raise ArtifactLedgerError(
            "preexecution authority extension self-digest is invalid"
        )
    return replayed, self_digest


def record_work_unit_inputs(
    scratchpad: Path,
    project_root: Path,
    contract: PhaseIOContract,
    launch: LaunchSpec,
    *,
    run_id: str,
    successor_plan: DriverSuccessorPlan | None = None,
    preexecution_authority: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Bind exact semantic inputs before launch or deterministic execution.

    Presence alone is never a completion authority.  The receipt covers both
    immutable and bounded-lookup inputs and survives the later output record.
    """

    contract, launch = _replay_authority_pair(contract, launch)
    launch_issues = _closed_launch_profile_issues(contract, launch)
    if launch_issues:
        raise ArtifactLedgerError(
            "launch violates the closed model-free launch profile: "
            + ", ".join(sorted(launch_issues))
        )
    run = str(run_id or "").strip()
    if not run:
        raise ArtifactLedgerError("run_id must be non-empty")
    canonical_preexecution_authority: dict[str, Any] | None = None
    preexecution_authority_digest = ""
    if preexecution_authority is not None:
        (
            canonical_preexecution_authority,
            preexecution_authority_digest,
        ) = _canonical_preexecution_authority_extension(
            preexecution_authority
        )
    replayed_successor_plan: DriverSuccessorPlan | None = None
    if successor_plan is not None:
        try:
            replayed_successor_plan = (
                replay_driver_successor_plan_authority(
                    successor_plan,
                    contract=contract,
                    launch=launch,
                )
            )
        except (TypeError, ValueError) as exc:
            raise ArtifactLedgerError(
                f"driver successor plan authority is invalid: {exc}"
            ) from exc
        if contract.model_invoked:
            raise ArtifactLedgerError(
                "model work units cannot arm a driver successor plan"
            )
        if replayed_successor_plan.run_id != run:
            raise ArtifactLedgerError(
                "driver successor plan run_id differs from the arm"
            )
    with _ledger_transaction_lock(scratchpad):
        ledger = read_artifact_ledger(scratchpad)
        prior = ledger["work_units"].get(contract.key)
        validated_recovery_history: list[dict[str, Any]] | None = None
        if isinstance(prior, dict):
            if prior.get("run_id") != run:
                raise ArtifactLedgerError(
                    f"work unit {contract.key} is already bound to another run"
                )
            stored_extension = prior.get("preexecution_authority")
            stored_extension_digest = prior.get(
                "preexecution_authority_digest"
            )
            if canonical_preexecution_authority is None:
                if (
                    stored_extension is not None
                    or stored_extension_digest is not None
                ):
                    raise ArtifactLedgerError(
                        f"work unit {contract.key} requires its exact "
                        "preexecution authority on resume"
                    )
            else:
                if (
                    stored_extension is None
                    or stored_extension_digest is None
                ):
                    raise ArtifactLedgerError(
                        f"work unit {contract.key} was previously armed "
                        "without preexecution authority"
                    )
                try:
                    replayed_extension, replayed_digest = (
                        _canonical_preexecution_authority_extension(
                            stored_extension
                        )
                    )
                except ArtifactLedgerError as exc:
                    raise ArtifactLedgerError(
                        f"work unit {contract.key} stored preexecution "
                        f"authority is invalid: {exc}"
                    ) from exc
                if (
                    replayed_digest != stored_extension_digest
                    or replayed_digest != preexecution_authority_digest
                    or replayed_extension
                    != canonical_preexecution_authority
                ):
                    raise ArtifactLedgerError(
                        f"work unit {contract.key} preexecution authority "
                        "changed on resume"
                    )
            if "quarantine_recovery_history" in prior:
                validated_recovery_history = (
                    _validated_quarantine_recovery_history(
                        prior,
                        work_unit_key=contract.key,
                        run_id=run,
                    )
                )
            if prior.get("contract_digest") != contract.digest:
                prior_manifest = prior.get("contract_manifest")
                prior_static = (
                    dict(prior_manifest)
                    if isinstance(prior_manifest, dict)
                    else {}
                )
                prior_static.pop("immutable_inputs", None)
                prior_static.pop("bounded_lookup_inputs", None)
                prior_static.pop("input_authority_requirements", None)
                if (
                    prior.get("semantic_status") != "STALE_INPUT"
                    or not isinstance(prior_manifest, dict)
                    or _contract_manifest_digest(prior_manifest)
                    != prior.get("contract_digest")
                    or prior_static != _static_contract_manifest(contract)
                ):
                    raise ArtifactLedgerError(
                        f"work unit {contract.key} contract digest changed"
                    )
            prior_successor = prior.get(
                "successor_consumption_authority"
            )
            if prior_successor is not None:
                if replayed_successor_plan is None:
                    raise ArtifactLedgerError(
                        f"work unit {contract.key} requires its exact "
                        "driver successor plan on resume"
                    )
                authority, stored_plan = (
                    _replay_driver_successor_authority(
                        Path(scratchpad),
                        Path(project_root),
                        ledger,
                        prior,
                        contract,
                        launch,
                        run_id=run,
                    )
                )
                if (
                    stored_plan.digest != replayed_successor_plan.digest
                    or stored_plan.to_dict()
                    != replayed_successor_plan.to_dict()
                ):
                    raise ArtifactLedgerError(
                        f"work unit {contract.key} successor plan changed "
                        "on resume"
                    )
                _synchronize_driver_successor_progress_projection(
                    Path(scratchpad), ledger
                )
                _validate_driver_successor_live_progress(
                    Path(scratchpad),
                    Path(project_root),
                    ledger,
                    prior,
                    authority,
                    require_complete=False,
                )
                return dict(prior)
            if replayed_successor_plan is not None:
                raise ArtifactLedgerError(
                    f"work unit {contract.key} was previously armed "
                    "without successor authority"
                )
        validation_context = (
            None
            if replayed_successor_plan is not None
            else _ArtifactValidationContext(
                Path(scratchpad),
                Path(project_root),
                ledger=ledger,
            )
        )

        def _finish_input_validation_epoch() -> None:
            if validation_context is None:
                return
            epoch_issues = validation_context.finish()
            if epoch_issues:
                raise ArtifactLedgerError("; ".join(epoch_issues))

        validation_ledger = (
            ledger
            if validation_context is None
            else validation_context.ledger
        )
        records: dict[str, dict[str, Any]] = {}
        for identity in contract.immutable_inputs:
            records[identity] = _input_binding_record(
                Path(scratchpad),
                Path(project_root),
                identity,
                "IMMUTABLE",
                validation_ledger,
                _validation_context=validation_context,
            )
        for identity in contract.bounded_lookup_inputs:
            input_class = (
                "IMMUTABLE_AND_BOUNDED_LOOKUP"
                if identity in records
                else "BOUNDED_LOOKUP"
            )
            records[identity] = _input_binding_record(
                Path(scratchpad),
                Path(project_root),
                identity,
                input_class,
                validation_ledger,
                _validation_context=validation_context,
            )
        if contract.input_authority_requirements:
            for requirement in contract.input_authority_requirements:
                record = records[requirement.identity]
                authority_issues = _input_authority_requirement_issues(
                    ledger,
                    record,
                    requirement,
                    run_id=run,
                )
                if authority_issues:
                    record["authority_requirement_issues"] = sorted(
                        authority_issues
                    )
                    record["status"] = "INPUT_AUTHORITY_MISMATCH"

        physical_to_identities: dict[str, list[str]] = {}
        for identity, record in records.items():
            if record.get("status") == "MISSING":
                continue
            try:
                if validation_context is None:
                    path = _path_for_identity(
                        Path(scratchpad),
                        Path(project_root),
                        identity,
                    )
                    physical = _physical_file_identity(path)
                else:
                    path = validation_context.path_for_identity(identity)
                    physical = validation_context.physical_identity(path)
            except ArtifactLedgerError:
                continue
            physical_to_identities.setdefault(
                physical, []
            ).append(identity)
        for identities in physical_to_identities.values():
            if len(identities) < 2:
                continue
            aliases = sorted(identities)
            for identity in aliases:
                records[identity][
                    "physical_alias_identities"
                ] = aliases
                records[identity]["status"] = (
                    "PHYSICAL_INPUT_ALIAS_CONFLICT"
                )
        output_prestates = _output_prestate_records(
            Path(scratchpad),
            Path(project_root),
            contract,
            ledger,
            run_id=run,
            _validation_context=validation_context,
        )
        for output_identity, prestate in output_prestates.items():
            prestate_physical = str(
                prestate.get("physical_identity") or ""
            )
            input_aliases = physical_to_identities.get(
                prestate_physical, []
            )
            if prestate_physical and any(
                identity != output_identity for identity in input_aliases
            ):
                prestate["status"] = (
                    "INPUT_OUTPUT_PRESTATE_PHYSICAL_ALIAS_CONFLICT"
                )
                prestate["physical_alias_identities"] = sorted({
                    output_identity,
                    *input_aliases,
                })
        output_prestate_digest = _output_prestate_digest(output_prestates)
        successor_authority: dict[str, Any] | None = None
        if replayed_successor_plan is not None:
            successor_authority, affected_inputs = (
                _issue_driver_successor_authority(
                    Path(scratchpad),
                    Path(project_root),
                    ledger,
                    contract,
                    launch,
                    run_id=run,
                    plan=replayed_successor_plan,
                    input_records=records,
                    output_prestates=output_prestates,
                )
            )
            for identity in affected_inputs:
                record = records.get(identity)
                if not isinstance(record, dict):
                    raise ArtifactLedgerError(
                        f"{identity}: successor input binding is absent"
                    )
                record["driver_successor_plan_digest"] = (
                    replayed_successor_plan.digest
                )
                record["driver_successor_authority_digest"] = (
                    successor_authority["authority_digest"]
                )
        reexecution_authorization: dict[str, Any] | None = None
        if isinstance(prior, dict):
            prior_artifacts = prior.get("artifacts")
            if not isinstance(prior_artifacts, dict):
                raise ArtifactLedgerError(
                    f"work unit {contract.key} artifacts record is malformed"
                )
            if (
                str(prior.get("execution_state") or "") in _COMMIT_TERMINAL_STATES
                and prior.get("semantic_status") != "STALE_INPUT"
                and not prior_artifacts
            ):
                # Never create a new pre-execution receipt after any output
                # commit attempt, including a proposal-only quarantine.
                prior_inputs = prior.get("input_bindings")
                prior_prestates = prior.get("output_prestates")
                current_digest = _input_set_digest(records)
                if (
                    isinstance(prior_inputs, dict)
                    and isinstance(prior_prestates, dict)
                    and set(prior_inputs) == set(records)
                    and _input_set_digest(prior_inputs)
                    == str(prior.get("input_set_digest") or "")
                    and current_digest == str(prior.get("input_set_digest") or "")
                    and _output_prestate_digest(prior_prestates)
                    == str(prior.get("output_prestate_digest") or "")
                    and output_prestate_digest
                    == str(prior.get("output_prestate_digest") or "")
                ):
                    _finish_input_validation_epoch()
                    return dict(prior)
                raise ArtifactLedgerError(
                    f"work unit {contract.key} output execution is terminal; "
                    "retroactive input binding is forbidden"
                )
            if not prior_artifacts and contract.model_invoked:
                # Once a model could have executed, even an output-less retry
                # is downstream of the first prelaunch receipt.  Re-recording
                # changed bytes here would let a model mutation become its own
                # newly blessed input.  Driver-only dynamic producers use the
                # explicit compare-and-swap API; a model retry must retain the
                # first denominator or use a separately authorized work unit.
                if not _stored_launch_matches(prior, launch):
                    raise ArtifactLedgerError(
                        f"work unit {contract.key} model prelaunch launch drift"
                    )
                prior_inputs = prior.get("input_bindings")
                prior_prestates = prior.get("output_prestates")
                prior_input_digest = str(prior.get("input_set_digest") or "")
                current_input_digest = _input_set_digest(records)
                if (
                    isinstance(prior_inputs, dict)
                    and isinstance(prior_prestates, dict)
                    and set(prior_inputs) == set(records)
                    and _input_set_digest(prior_inputs) == prior_input_digest
                    and current_input_digest == prior_input_digest
                    and _output_prestate_digest(prior_prestates)
                    == str(prior.get("output_prestate_digest") or "")
                    and output_prestate_digest
                    == str(prior.get("output_prestate_digest") or "")
                ):
                    _validated_input_rebind_history(
                        prior, work_unit_key=contract.key, run_id=run
                    )
                    _finish_input_validation_epoch()
                    return dict(prior)
                raise ArtifactLedgerError(
                    f"work unit {contract.key} model prelaunch input drift "
                    "requires a separately authorized retry work unit"
                )
            if prior_artifacts:
                if not _stored_launch_matches(prior, launch):
                    raise ArtifactLedgerError(
                        f"work unit {contract.key} launch digest changed"
                    )
                if prior.get("semantic_status") == "STALE_INPUT":
                    reexecution_authorization = (
                        _validated_stale_reexecution_authorization(
                            ledger, prior, contract, run_id=run
                        )
                    )
                else:
                    prior_inputs = prior.get("input_bindings")
                    current_input_digest = _input_set_digest(records)
                    prior_input_digest = str(prior.get("input_set_digest") or "")
                    if (
                        isinstance(prior_inputs, dict)
                        and set(prior_inputs) == set(records)
                        and _input_set_digest(prior_inputs) == prior_input_digest
                        and current_input_digest == prior_input_digest
                    ):
                        _validated_input_rebind_history(
                            prior, work_unit_key=contract.key, run_id=run
                        )
                        # A committed output denominator is immutable.  An exact
                        # replay is a read-only idempotent success; do not rewrite
                        # ACTIVE to INPUTS_BOUND or refresh receipt timestamps.
                        _finish_input_validation_epoch()
                        return dict(prior)
                    raise ArtifactLedgerError(
                        f"work unit {contract.key} committed input drift requires "
                        "semantic invalidation"
                    )
        now = datetime.now(timezone.utc).isoformat()
        work_unit = {
            "schema": "plamen.artifact-work-unit.v2",
            "work_unit_key": contract.key,
            "run_id": run,
            "contract_digest": contract.digest,
            "contract_manifest": contract.to_dict(),
            "launch_digest": launch.digest,
            "launch_manifest": launch.to_dict(),
            "model_invoked": contract.model_invoked,
            "recorded_at": (
                prior.get("recorded_at", now) if isinstance(prior, dict) else now
            ),
            "input_recorded_at": now,
            "execution_state": "INPUTS_BOUND_PREEXECUTION",
            "semantic_status": (
                "INPUT_DEBT"
                if (
                    any(row["status"] != "ACTIVE" for row in records.values())
                    or any(
                        not _output_prestate_is_clean(row)
                        for row in output_prestates.values()
                    )
                )
                else "INPUTS_BOUND"
            ),
            "input_bindings": records,
            "input_set_digest": _input_set_digest(records),
            "output_prestates": output_prestates,
            "output_prestate_digest": output_prestate_digest,
            "input_receipt_kind": (
                "BOUND_INPUTS" if records else "EXPLICIT_ZERO_INPUT"
            ),
            "artifacts": (
                {}
                if reexecution_authorization is not None
                else dict(prior.get("artifacts", {}))
                if isinstance(prior, dict)
                and isinstance(prior.get("artifacts"), dict)
                else {}
            ),
        }
        if canonical_preexecution_authority is not None:
            work_unit["preexecution_authority"] = copy.deepcopy(
                canonical_preexecution_authority
            )
            work_unit["preexecution_authority_digest"] = (
                preexecution_authority_digest
            )
        if successor_authority is not None:
            work_unit["successor_consumption_authority"] = dict(
                successor_authority
            )
            work_unit["successor_progress_authority"] = (
                _new_driver_successor_progress_authority(
                    successor_authority
                )
            )
            if (
                isinstance(prior, Mapping)
                and isinstance(
                    prior.get("successor_physical_rebind_history"),
                    list,
                )
            ):
                work_unit["successor_physical_rebind_history"] = (
                    copy.deepcopy(
                        prior["successor_physical_rebind_history"]
                    )
                )
        if reexecution_authorization is not None:
            history = prior.get("semantic_reexecution_history", [])
            if (
                not isinstance(history, list)
                or len(history) >= 32
                or any(not isinstance(row, dict) for row in history)
            ):
                raise ArtifactLedgerError(
                    f"work unit {contract.key} semantic reexecution history is malformed"
                )
            work_unit["semantic_reexecution_history"] = [
                *[dict(row) for row in history],
                reexecution_authorization,
            ]
        if isinstance(prior, dict) and "input_rebind_history" in prior:
            work_unit["input_rebind_history"] = _validated_input_rebind_history(
                prior, work_unit_key=contract.key, run_id=run
            )
        if validated_recovery_history is not None:
            work_unit["quarantine_recovery_history"] = copy.deepcopy(
                validated_recovery_history
            )
            recovery_count, recovery_head = (
                _quarantine_recovery_history_binding(
                    validated_recovery_history
                )
            )
            work_unit["quarantine_recovery_history_count"] = (
                recovery_count
            )
            work_unit[
                "quarantine_recovery_history_head_digest"
            ] = recovery_head
        _finish_input_validation_epoch()
        ledger["work_units"][contract.key] = work_unit
        write_artifact_ledger(scratchpad, ledger)
        return work_unit


def validate_work_unit_inputs(
    scratchpad: Path,
    project_root: Path,
    contract: PhaseIOContract,
    launch: LaunchSpec,
    *,
    run_id: str,
    preexecution_authority: Mapping[str, Any] | None = None,
    _validation_context: _ArtifactValidationContext | None = None,
) -> list[str]:
    """Compare live semantic inputs with the exact pre-execution receipt."""

    if _validation_context is None:
        try:
            validation_context = _ArtifactValidationContext(
                Path(scratchpad), Path(project_root)
            )
        except ArtifactLedgerError as exc:
            return [str(exc)]
        issues = validate_work_unit_inputs(
            Path(scratchpad),
            Path(project_root),
            contract,
            launch,
            run_id=run_id,
            preexecution_authority=preexecution_authority,
            _validation_context=validation_context,
        )
        issues.extend(validation_context.finish())
        return list(dict.fromkeys(issues))

    try:
        contract, launch = _replay_authority_pair(contract, launch)
        ledger = (
            read_artifact_ledger(scratchpad)
            if _validation_context is None
            else _validation_context.ledger
        )
    except ArtifactLedgerError as exc:
        return [str(exc)]
    unit = ledger["work_units"].get(contract.key)
    if not isinstance(unit, dict):
        return [f"{contract.key}: no exact work-unit input record"]
    issues: list[str] = []
    stored_extension = unit.get("preexecution_authority")
    stored_extension_digest = unit.get("preexecution_authority_digest")
    if preexecution_authority is None:
        if stored_extension is not None or stored_extension_digest is not None:
            issues.append(
                f"{contract.key}: exact preexecution authority is required"
            )
    else:
        try:
            expected_extension, expected_extension_digest = (
                _canonical_preexecution_authority_extension(
                    preexecution_authority
                )
            )
            replayed_extension, replayed_extension_digest = (
                _canonical_preexecution_authority_extension(
                    stored_extension
                )
            )
        except ArtifactLedgerError as exc:
            issues.append(
                f"{contract.key}: preexecution authority invalid: {exc}"
            )
        else:
            if (
                replayed_extension_digest != stored_extension_digest
                or replayed_extension_digest != expected_extension_digest
                or replayed_extension != expected_extension
            ):
                issues.append(
                    f"{contract.key}: preexecution authority mismatch"
                )
    if unit.get("run_id") != run_id:
        issues.append(f"{contract.key}: run_id mismatch")
    if unit.get("contract_digest") != contract.digest:
        issues.append(f"{contract.key}: contract digest mismatch")
    manifest = unit.get("contract_manifest")
    if manifest != contract.to_dict():
        issues.append(f"{contract.key}: contract manifest mismatch")
    elif _contract_manifest_digest(manifest) != unit.get("contract_digest"):
        issues.append(f"{contract.key}: contract manifest digest mismatch")
    if unit.get("launch_digest") != launch.digest:
        issues.append(f"{contract.key}: launch digest mismatch")
    if (
        unit.get("launch_manifest") != launch.to_dict()
        or not _launch_manifest_is_valid(
            unit.get("launch_manifest"),
            expected_digest=unit.get("launch_digest"),
        )
    ):
        issues.append(f"{contract.key}: launch manifest mismatch")
    for code in sorted(_closed_launch_profile_issues(contract, launch)):
        issues.append(f"{contract.key}: {code}")
    try:
        _validated_input_rebind_history(
            unit, work_unit_key=contract.key, run_id=run_id
        )
    except ArtifactLedgerError as exc:
        issues.append(f"{contract.key}: {exc}")
    records = unit.get("input_bindings")
    if not isinstance(records, dict):
        return issues + [f"{contract.key}: input bindings malformed"]
    expected = set(contract.immutable_inputs) | set(contract.bounded_lookup_inputs)
    if set(records) != expected:
        issues.append(f"{contract.key}: semantic input denominator mismatch")
    try:
        current_receipt_digest = _input_set_digest(records)
    except (AttributeError, TypeError, ValueError):
        current_receipt_digest = ""
        issues.append(f"{contract.key}: semantic input receipt malformed")
    if unit.get("input_set_digest") != current_receipt_digest:
        issues.append(f"{contract.key}: semantic input receipt digest mismatch")
    successor_affected: set[str] = set()
    successor_valid = False
    if "successor_consumption_authority" in unit:
        try:
            authority, _stored_plan = (
                _replay_driver_successor_authority(
                    Path(scratchpad),
                    Path(project_root),
                    ledger,
                    unit,
                    contract,
                    launch,
                    run_id=run_id,
                )
            )
            _validate_driver_successor_live_progress(
                Path(scratchpad),
                Path(project_root),
                ledger,
                unit,
                authority,
                require_complete=False,
            )
            successor_affected = set(
                authority["affected_input_identities"]
            )
            successor_valid = True
        except (
            ArtifactLedgerError,
            KeyError,
            OSError,
            TypeError,
            ValueError,
        ) as exc:
            issues.append(
                f"{contract.key}: "
                "SUCCESSOR_CONSUMPTION_AUTHORITY_INVALID: "
                f"{type(exc).__name__}: {exc}"
            )
    for identity in sorted(expected):
        record = records.get(identity)
        if not isinstance(record, dict):
            issues.append(f"{identity}: semantic input binding missing")
            continue
        path = _validation_context.path_for_identity(identity)
        present = rooted_io.is_file(path)
        if record.get("status") == "MISSING":
            issues.append(f"{identity}: semantic input missing at binding")
            continue
        if record.get("status") != "ACTIVE":
            issues.append(
                f"{identity}: semantic input binding is "
                f"{record.get('status') or 'INVALID'}"
            )
            continue
        if successor_valid and identity in successor_affected:
            if contract.input_authority_requirements:
                try:
                    requirement = contract.input_authority(identity)
                except KeyError:
                    issues.append(
                        f"{identity}: input authority requirement missing"
                    )
                else:
                    for code in sorted(
                        _input_authority_requirement_issues(
                            ledger,
                            record,
                            requirement,
                            run_id=run_id,
                        )
                    ):
                        issues.append(f"{identity}: {code}")
            continue
        current = _input_binding_record(
            Path(scratchpad),
            Path(project_root),
            identity,
            str(record.get("input_class") or "IMMUTABLE"),
            ledger,
            _validation_context=_validation_context,
        )
        if current.get("status") == "PRODUCER_AUTHORITY_MISMATCH":
            issues.append(f"{identity}: producer authority mismatch")
            continue
        if (
            record.get("producer_work_unit_key", "")
            != current.get("producer_work_unit_key", "")
            or record.get("producer_contract_digest", "")
            != current.get("producer_contract_digest", "")
            or record.get("producer_launch_digest", "")
            != current.get("producer_launch_digest", "")
            or record.get("producer_commit_receipt_digest", "")
            != current.get("producer_commit_receipt_digest", "")
        ):
            issues.append(f"{identity}: producer authority changed")
            continue
        if not present:
            issues.append(f"{identity}: semantic input missing")
            continue
        if record.get("sha256") != current.get("sha256"):
            issues.append(f"{identity}: semantic input hash changed")
    output_prestates = unit.get("output_prestates")
    expected_outputs = {spec.identity for spec in contract.outputs}
    if not isinstance(output_prestates, dict):
        issues.append(f"{contract.key}: output prestate receipt missing")
    elif set(output_prestates) != expected_outputs:
        issues.append(f"{contract.key}: output prestate denominator mismatch")
    else:
        try:
            digest = _output_prestate_digest(output_prestates)
        except (AttributeError, TypeError, ValueError):
            digest = ""
        if unit.get("output_prestate_digest") != digest:
            issues.append(f"{contract.key}: output prestate digest mismatch")
        for identity, record in sorted(output_prestates.items()):
            if not isinstance(record, dict) or not _output_prestate_is_clean(record):
                state = (
                    record.get("status")
                    if isinstance(record, dict)
                    else "MALFORMED"
                )
                issues.append(
                    f"{identity}: output prestate authority is {state}"
                )
    issues.extend(validate_work_unit_explicit_absence_bindings(
        Path(scratchpad),
        Path(project_root),
        contract,
        launch,
        run_id=run_id,
        _validation_context=_validation_context,
    ))
    return issues


def detect_semantic_input_drift(
    scratchpad: Path,
    project_root: Path,
    *,
    run_id: str,
) -> dict[str, Any]:
    """Inspect every stored input receipt without reconstructing its contract.

    Resume cannot safely depend on the caller remembering the exact dynamic
    ``PhaseIOContract`` used by every worker shard.  The ledger therefore keeps
    a self-contained denominator and this reader compares that denominator with
    current bytes and producer authority.  It is deliberately side-effect free;
    callers must separately plan and apply invalidation.
    """

    run = str(run_id or "").strip()
    if not run:
        raise ArtifactLedgerError("semantic drift detection run_id is empty")
    ledger = read_artifact_ledger(Path(scratchpad))
    work_units = ledger.get("work_units")
    if not isinstance(work_units, dict):
        raise ArtifactLedgerError("artifact ledger work_units are malformed")
    # Resume drift detection is one read-only, immutable-ledger epoch.  Share
    # its physical snapshots and producer-replay results across every stored
    # consumer binding.  Without this context, N consumers of the same typed
    # artifact each re-hash and replay the producer's complete output bundle,
    # turning a linear resume scan into an accidental quadratic hot path.
    validation_context = _ArtifactValidationContext(
        Path(scratchpad),
        Path(project_root),
        ledger=ledger,
    )

    changed: set[str] = set()
    stale_units: set[str] = set()
    cross_run: set[str] = set()
    rows: list[dict[str, Any]] = []
    allowed_classes = {
        "IMMUTABLE", "BOUNDED_LOOKUP", "IMMUTABLE_AND_BOUNDED_LOOKUP",
    }

    for key, unit in sorted(work_units.items()):
        if not isinstance(key, str) or not key or not isinstance(unit, dict):
            raise ArtifactLedgerError("artifact ledger work-unit row is malformed")
        if unit.get("run_id") != run:
            foreign_bindings = unit.get("input_bindings", {})
            if isinstance(foreign_bindings, dict) and foreign_bindings:
                cross_run.add(key)
            continue
        _validated_input_rebind_history(
            unit, work_unit_key=key, run_id=run
        )
        bindings = unit.get("input_bindings", {})
        if bindings in ({}, None):
            # A v1/compatibility output-only row has no semantic freshness
            # authority.  The driver retains legacy gate reconciliation for it.
            continue
        if not isinstance(bindings, dict):
            raise ArtifactLedgerError(f"{key}: input bindings malformed")

        manifest = unit.get("contract_manifest")
        if not isinstance(manifest, dict):
            raise ArtifactLedgerError(f"{key}: exact input receipt lacks contract manifest")
        if manifest.get("key") != key:
            raise ArtifactLedgerError(f"{key}: contract manifest key mismatch")
        if _contract_manifest_digest(manifest) != unit.get("contract_digest"):
            raise ArtifactLedgerError(f"{key}: contract manifest digest mismatch")
        immutable = manifest.get("immutable_inputs")
        bounded = manifest.get("bounded_lookup_inputs")
        if not isinstance(immutable, list) or not isinstance(bounded, list):
            raise ArtifactLedgerError(f"{key}: contract input denominator malformed")
        manifest_denominator = set(immutable) | set(bounded)
        if set(bindings) != manifest_denominator:
            raise ArtifactLedgerError(f"{key}: contract input denominator mismatch")

        unit_reasons: set[str] = set()
        unit_identities: set[str] = set()
        try:
            receipt_digest = _input_set_digest(bindings)
        except Exception as exc:
            raise ArtifactLedgerError(
                f"{key}: input receipt cannot be canonicalized: {exc}"
            ) from exc
        if unit.get("input_set_digest") != receipt_digest:
            unit_reasons.add("RECEIPT_DIGEST_MISMATCH")

        for identity, recorded in sorted(bindings.items()):
            if (
                not isinstance(identity, str)
                or ":" not in identity
                or not isinstance(recorded, dict)
                or recorded.get("identity") != identity
                or recorded.get("input_class") not in allowed_classes
            ):
                raise ArtifactLedgerError(
                    f"{key}: malformed semantic input binding for {identity!r}"
                )
            unit_identities.add(identity)
            current = _input_binding_record(
                Path(scratchpad), Path(project_root), identity,
                str(recorded["input_class"]), ledger,
                _validation_context=validation_context,
            )
            recorded_status = recorded.get("status")
            if recorded_status == "MISSING":
                unit_reasons.add("MISSING_AT_BINDING")
            elif recorded_status != "ACTIVE":
                unit_reasons.add("INVALID_RECORDED_STATUS")
            elif current.get("status") == "PRODUCER_AUTHORITY_MISMATCH":
                unit_reasons.add("PRODUCER_AUTHORITY_MISMATCH")
            elif current.get("status") != "ACTIVE":
                unit_reasons.add("INPUT_MISSING")
            elif recorded.get("sha256") != current.get("sha256"):
                unit_reasons.add("CONTENT_HASH_CHANGED")

            if (
                recorded.get("producer_work_unit_key", "")
                != current.get("producer_work_unit_key", "")
                or recorded.get("producer_contract_digest", "")
                != current.get("producer_contract_digest", "")
            ):
                unit_reasons.add("PRODUCER_AUTHORITY_CHANGED")

        if unit.get("semantic_status") == "STALE_INPUT":
            unit_reasons.add("ALREADY_INVALIDATED")
            prior = unit.get("semantic_invalidation")
            if isinstance(prior, dict):
                for identity in prior.get("changed_input_identities", []):
                    if isinstance(identity, str) and ":" in identity:
                        unit_identities.add(identity)

        if unit_reasons:
            stale_units.add(key)
            changed.update(unit_identities)
            rows.append({
                "work_unit_key": key,
                "input_identities": sorted(unit_identities),
                "reasons": sorted(unit_reasons),
            })

    return {
        "schema": "plamen.semantic_input_drift.v1",
        "run_id": run,
        "changed_input_identities": sorted(changed),
        "stale_work_unit_keys": sorted(stale_units),
        "cross_run_work_unit_keys": sorted(cross_run),
        "rows": rows,
    }


def semantic_dependency_invalidation_plan(
    ledger: dict[str, Any],
    changed_input_identities: list[str] | tuple[str, ...],
    *,
    run_id: str,
    excluded_work_unit_keys: Sequence[str] = (),
    changed_input_states: Mapping[str, Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    """Compute the exact versioned consumer set without deleting artifacts.

    When exact pre-mutation states are supplied, a root consumer is selected
    only if its stored input binding consumed that generation.  A missing
    preimage is an exact ``("MISSING", "", 0)`` generation, not wildcard
    authority and not an alias for an ACTIVE zero-byte file.  This preserves
    older immutable transaction proofs that happened to use the same artifact
    identity at an earlier generation.
    """

    if not isinstance(ledger, dict) or not isinstance(ledger.get("work_units"), dict):
        raise ArtifactLedgerError("artifact ledger work_units are malformed")
    run = str(run_id or "").strip()
    roots = sorted({str(item or "").strip() for item in changed_input_identities})
    if not run or not roots or any(not item or ":" not in item for item in roots):
        raise ArtifactLedgerError("invalidation run/changed identities are invalid")
    supplied_states = dict(changed_input_states or {})
    if not set(supplied_states).issubset(roots):
        raise ArtifactLedgerError(
            "invalidation changed-input states exceed the root denominator"
        )
    frontier: dict[str, set[tuple[str, str, int]] | None] = {}
    normalized_states: dict[str, dict[str, Any]] = {}
    for identity in roots:
        raw_state = supplied_states.get(identity)
        if raw_state is None:
            frontier[identity] = None
            continue
        status = (
            str(raw_state.get("status") or "")
            if isinstance(raw_state, Mapping)
            else ""
        )
        size = (
            raw_state.get("size")
            if isinstance(raw_state, Mapping)
            else None
        )
        sha256 = (
            str(raw_state.get("sha256") or "")
            if isinstance(raw_state, Mapping)
            else ""
        )
        if (
            not isinstance(raw_state, Mapping)
            or set(raw_state) != {"status", "size", "sha256"}
            or status not in {"ACTIVE", "MISSING"}
            or not isinstance(size, int)
            or isinstance(size, bool)
            or int(size or 0) < 0
            or (
                status == "ACTIVE"
                and not _is_digest(sha256)
            )
            or (
                status == "MISSING"
                and (int(size or 0) != 0 or sha256 != "")
            )
        ):
            raise ArtifactLedgerError(
                f"{identity}: invalidation preimage state is malformed"
            )
        normalized = {
            "status": status,
            "size": int(size),
            "sha256": sha256,
        }
        normalized_states[identity] = normalized
        frontier[identity] = {
            (
                str(normalized["status"]),
                str(normalized["sha256"]),
                int(normalized["size"]),
            )
        }
    excluded = {
        str(value or "").strip()
        for value in excluded_work_unit_keys
        if str(value or "").strip()
    }
    invalidated: set[str] = set()
    rows: dict[str, dict[str, Any]] = {}
    artifacts: set[str] = set()
    progress = True
    while progress:
        progress = False
        for key, unit in sorted(ledger["work_units"].items()):
            if (
                key in excluded
                or key in invalidated
                or not isinstance(unit, dict)
            ):
                continue
            if unit.get("run_id") != run:
                continue
            bindings = unit.get("input_bindings")
            if not isinstance(bindings, dict):
                continue
            triggers: list[str] = []
            for identity in sorted(set(bindings) & set(frontier)):
                generations = frontier[identity]
                binding = bindings.get(identity)
                if not isinstance(binding, Mapping):
                    continue
                if generations is None or (
                    str(binding.get("status") or ""),
                    str(binding.get("sha256") or ""),
                    int(binding.get("size") or 0),
                ) in generations:
                    triggers.append(identity)
            if not triggers:
                continue
            invalidated.add(key)
            rows[key] = {
                "work_unit_key": key,
                "trigger_identities": triggers,
            }
            outputs = unit.get("artifacts")
            if isinstance(outputs, dict):
                for identity, raw_output in outputs.items():
                    artifacts.add(identity)
                    if not isinstance(raw_output, Mapping):
                        continue
                    generation = (
                        str(raw_output.get("status") or ""),
                        str(raw_output.get("sha256") or ""),
                        int(raw_output.get("size") or 0),
                    )
                    if (
                        generation[0] != "ACTIVE"
                        or not _is_digest(generation[1])
                        or generation[2] < 0
                    ):
                        continue
                    existing = frontier.get(identity)
                    if existing is None and identity in frontier:
                        continue
                    frontier.setdefault(identity, set()).add(generation)
            progress = True
    unsigned = {
        "schema": "plamen.semantic_invalidation_plan.v1",
        "run_id": run,
        "changed_input_identities": roots,
        "changed_input_states": normalized_states,
        "excluded_work_unit_keys": sorted(excluded),
        "invalidated_work_unit_keys": sorted(invalidated),
        "invalidated_artifact_identities": sorted(artifacts),
        "work_unit_triggers": [rows[key] for key in sorted(rows)],
    }
    encoded = json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return {**unsigned, "plan_digest": hashlib.sha256(encoded).hexdigest()}


def apply_semantic_invalidation(
    scratchpad: Path,
    plan: dict[str, Any],
    *,
    run_id: str,
) -> dict[str, Any]:
    """Mark only planned receipts stale; preserve all semantic output bytes."""

    if not isinstance(plan, dict) or plan.get("schema") != "plamen.semantic_invalidation_plan.v1":
        raise ArtifactLedgerError("semantic invalidation plan schema mismatch")
    claimed = plan.get("plan_digest")
    unsigned = {key: value for key, value in plan.items() if key != "plan_digest"}
    encoded = json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if claimed != hashlib.sha256(encoded).hexdigest():
        raise ArtifactLedgerError("semantic invalidation plan digest mismatch")
    run = str(run_id or "").strip()
    if plan.get("run_id") != run:
        raise ArtifactLedgerError("semantic invalidation plan run mismatch")
    with _ledger_transaction_lock(scratchpad):
        ledger = read_artifact_ledger(scratchpad)
        trigger_rows = {
            str(row.get("work_unit_key") or ""): sorted(
                set(row.get("trigger_identities") or ())
            )
            for row in plan.get("work_unit_triggers", [])
            if isinstance(row, dict)
        }
        for key in plan.get("invalidated_work_unit_keys", []):
            unit = ledger["work_units"].get(key)
            if not isinstance(unit, dict) or unit.get("run_id") != run:
                raise ArtifactLedgerError(
                    f"semantic invalidation work unit missing or cross-run: {key}"
                )
            triggers = trigger_rows.get(str(key), [])
            if not triggers:
                raise ArtifactLedgerError(
                    f"semantic invalidation work unit trigger missing: {key}"
                )
            unit["semantic_status"] = "STALE_INPUT"
            outputs = unit.get("artifacts")
            stale_artifacts = sorted(outputs) if isinstance(outputs, dict) else []
            authorization: dict[str, Any] = {
                "schema": _SEMANTIC_INVALIDATION_AUTH_SCHEMA,
                "plan_digest": claimed,
                "run_id": run,
                "work_unit_key": str(key),
                "changed_input_identities": list(
                    plan.get("changed_input_identities", [])
                ),
                "invalidated_artifact_identities": list(
                    plan.get("invalidated_artifact_identities", [])
                ),
                "trigger_identities": triggers,
                "stale_artifact_identities": stale_artifacts,
            }
            authorization["authorization_digest"] = (
                _semantic_invalidation_authorization_digest(authorization)
            )
            unit["semantic_invalidation"] = authorization
            if not isinstance(outputs, dict):
                continue
            for identity, record in outputs.items():
                if not isinstance(record, dict):
                    continue
                record["status"] = "STALE_INPUT"
                binding = ledger["artifact_bindings"].get(identity)
                if isinstance(binding, dict) and binding.get("owner_key") == key:
                    binding["status"] = "STALE_INPUT"
                legacy = ledger["artifacts"].get(_legacy_name(identity))
                if isinstance(legacy, dict) and legacy.get("owner_key") == key:
                    legacy["status"] = "STALE_INPUT"
        write_artifact_ledger(scratchpad, ledger)
    return dict(plan)


def authorize_deterministic_work_unit_reexecution(
    scratchpad: Path,
    project_root: Path,
    contract: PhaseIOContract,
    launch: LaunchSpec,
    *,
    run_id: str,
    byte_identical_successor_owners: Mapping[str, Sequence[str]] | None = None,
    authenticated_successor_owners: Mapping[str, Sequence[str]] | None = None,
    durable_mutation_successor_identities: Sequence[str] = (),
) -> dict[str, Any] | None:
    """Arm one deterministic DRIVER consumer before input-driven refresh.

    This is intentionally narrower than source-mutation invalidation.  A
    mutable control-plane input such as the checkpoint can change between two
    terminal projections without authorizing a renderer to invalidate every
    unrelated work unit that also consulted that control-plane file.  The API
    proves that this exact deterministic consumer has real input drift, that
    its old outputs are still byte-identical and exclusively owned, and then
    marks only those outputs stale *before* re-execution.

    It cannot repair output-only tamper, model work, producer-authority debt,
    cross-run state, launch drift, or a static contract change.  A caller may
    name an exact, per-artifact set of deterministic sibling owners that are
    permitted to have *rebound the same bytes* since this work unit last ran.
    This is only an ownership hand-off for shared MERGE projections: any byte,
    run, writer, mode, or status drift still fails closed.

    ``durable_mutation_successor_identities`` is narrower still: it permits a
    changed output only when the existing arm-before-write semantic mutation
    chain starts at this work unit's exact recorded output and ends at the live
    bytes.  It cannot authorize raw output drift or a different historical
    producer.

    ``authenticated_successor_owners`` permits changed bytes only when the
    current exact owner is a resolver-registered successor whose complete
    output commit authority independently replays against the live file.  It
    is used for an explicit deterministic projection cycle such as final
    disposition -> final assurance, never for an unowned filesystem change.
    """

    contract, launch = _replay_authority_pair(contract, launch)
    run = str(run_id or "").strip()
    if not run or contract.model_invoked is not False or not contract.outputs:
        raise ArtifactLedgerError(
            "reexecution requires a same-run deterministic output producer"
        )
    if any(spec.writer != "DRIVER" for spec in contract.outputs):
        raise ArtifactLedgerError("reexecution requires DRIVER-only outputs")

    with _ledger_transaction_lock(scratchpad):
        root = Path(scratchpad)
        project = Path(project_root)
        ledger = read_artifact_ledger(root)
        prior = ledger.get("work_units", {}).get(contract.key)
        if not isinstance(prior, dict):
            return None
        if prior.get("semantic_status") == "STALE_INPUT":
            _validated_stale_reexecution_authorization(
                ledger, prior, contract, run_id=run
            )
            return dict(prior.get("semantic_invalidation") or {})
        if (
            prior.get("run_id") != run
            or prior.get("model_invoked") is not False
            or not _stored_launch_matches(prior, launch)
        ):
            raise ArtifactLedgerError("reexecution prior authority mismatch")
        prior_manifest = prior.get("contract_manifest")
        if (
            not isinstance(prior_manifest, dict)
            or _contract_manifest_digest(prior_manifest)
            != prior.get("contract_digest")
            or _static_contract_manifest(contract)
            != {
                key: value
                for key, value in prior_manifest.items()
                if key not in {"immutable_inputs", "bounded_lookup_inputs"}
            }
        ):
            raise ArtifactLedgerError("reexecution static contract drift")
        prior_inputs = prior.get("input_bindings")
        if (
            not isinstance(prior_inputs, dict)
            or _input_set_digest(prior_inputs)
            != prior.get("input_set_digest")
            or any(
                not isinstance(row, dict) or row.get("status") != "ACTIVE"
                for row in prior_inputs.values()
            )
        ):
            raise ArtifactLedgerError("reexecution prior input receipt is invalid")

        # Output-only drift is tamper, not refresh authority.  Validate every
        # old byte and owner before marking anything stale.
        prior_outputs = prior.get("artifacts")
        expected_outputs = {spec.identity for spec in contract.outputs}
        if not isinstance(prior_outputs, dict) or set(prior_outputs) != expected_outputs:
            raise ArtifactLedgerError("reexecution output denominator is invalid")
        allowed_successors = {
            str(identity): {str(owner) for owner in owners}
            for identity, owners in (byte_identical_successor_owners or {}).items()
        }
        authenticated_successor_allowlist = {
            str(identity): {str(owner) for owner in owners}
            for identity, owners in (
                authenticated_successor_owners or {}
            ).items()
        }
        durable_successor_set = {
            str(identity) for identity in durable_mutation_successor_identities
        }
        if not durable_successor_set.issubset(expected_outputs):
            raise ArtifactLedgerError(
                "durable mutation successor is outside the output denominator"
            )
        durable_successors: set[str] = set()
        authenticated_successors: set[str] = set()
        for identity, recorded in prior_outputs.items():
            binding = ledger.get("artifact_bindings", {}).get(identity)
            path = _path_for_identity(root, project, identity)
            binding_owner = (
                str(binding.get("owner_key") or "")
                if isinstance(binding, dict)
                else ""
            )
            owner_is_exact_or_allowed = (
                binding_owner == contract.key
                or binding_owner in allowed_successors.get(identity, set())
            )
            ordinary_authority = (
                not isinstance(recorded, dict)
            ) is False and (
                recorded.get("status") == "ACTIVE"
                and isinstance(binding, dict)
                and owner_is_exact_or_allowed
                and binding.get("status") == "ACTIVE"
                and binding.get("run_id") == run
                and binding.get("writer") == "DRIVER"
                and binding.get("write_mode") == recorded.get("write_mode")
                and path.is_file()
                and recorded.get("sha256") == _sha256(path)
                and binding.get("sha256") == recorded.get("sha256")
                and binding.get("size") == path.stat().st_size
            )
            durable_authority = False
            if not ordinary_authority and identity in durable_successor_set:
                current = _input_binding_record(
                    root, project, identity, "BOUNDED_LOOKUP", ledger
                )
                durable_authority = bool(
                    isinstance(recorded, dict)
                    and recorded.get("status") == "ACTIVE"
                    and isinstance(binding, dict)
                    and binding_owner == contract.key
                    and binding.get("status") == "ACTIVE"
                    and binding.get("run_id") == run
                    and binding.get("writer") == "DRIVER"
                    and binding.get("write_mode") == recorded.get("write_mode")
                    and binding.get("sha256") == recorded.get("sha256")
                    and binding.get("size") == recorded.get("size")
                    and path.is_file()
                    and current.get("status") == "ACTIVE"
                    and str(current.get("producer_work_unit_key") or "").startswith(
                        "semantic-mutation:"
                    )
                    and current.get("sha256") == _sha256(path)
                    and current.get("size") == path.stat().st_size
                )
                if durable_authority:
                    durable_successors.add(identity)
            authenticated_successor_authority = False
            if (
                not ordinary_authority
                and not durable_authority
                and isinstance(recorded, dict)
                and isinstance(binding, dict)
                and binding_owner
                in authenticated_successor_allowlist.get(identity, set())
                and registered_projection_handoff(
                    binding_owner, contract.key, identity
                )
                and binding.get("status") == "ACTIVE"
                and binding.get("run_id") == run
                and binding.get("writer") == "DRIVER"
                and binding.get("write_mode") == recorded.get("write_mode")
                and path.is_file()
                and binding.get("sha256") == _sha256(path)
                and binding.get("size") == path.stat().st_size
            ):
                successor_unit = ledger.get("work_units", {}).get(
                    binding_owner
                )
                authenticated_successor_authority = bool(
                    isinstance(successor_unit, Mapping)
                    and _producer_authority_is_active(
                        ledger,
                        binding,
                        identity=identity,
                        run_id=run,
                    )
                    and not _replay_output_commit_authority(
                        root,
                        project,
                        successor_unit,
                        require_live_bytes=True,
                    )
                )
                if authenticated_successor_authority:
                    authenticated_successors.add(identity)
            if (
                not ordinary_authority
                and not durable_authority
                and not authenticated_successor_authority
            ):
                raise ArtifactLedgerError(
                    f"reexecution output authority mismatch: {identity}"
                )

        current_inputs: dict[str, dict[str, Any]] = {}
        for identity in contract.immutable_inputs:
            current_inputs[identity] = _input_binding_record(
                root, project, identity, "IMMUTABLE", ledger
            )
        for identity in contract.bounded_lookup_inputs:
            input_class = (
                "IMMUTABLE_AND_BOUNDED_LOOKUP"
                if identity in current_inputs
                else "BOUNDED_LOOKUP"
            )
            current_inputs[identity] = _input_binding_record(
                root, project, identity, input_class, ledger
            )
        if any(row.get("status") != "ACTIVE" for row in current_inputs.values()):
            raise ArtifactLedgerError(
                "reexecution current input has missing producer authority"
            )
        semantic_keys = {
            "identity", "input_class", "status", "size", "sha256",
            "producer_work_unit_key", "producer_contract_digest",
            "producer_launch_digest", "producer_commit_receipt_digest",
        }
        changed = (
            (set(prior_inputs) ^ set(current_inputs))
            | durable_successors
            | authenticated_successors
        )
        for identity in set(prior_inputs) & set(current_inputs):
            if any(
                prior_inputs[identity].get(key) != current_inputs[identity].get(key)
                for key in semantic_keys
            ):
                changed.add(identity)
        if not changed:
            return None
        outputs = sorted(expected_outputs)
        unsigned = {
            "schema": "plamen.semantic_invalidation_plan.v1",
            "run_id": run,
            "changed_input_identities": sorted(changed),
            "invalidated_work_unit_keys": [contract.key],
            "invalidated_artifact_identities": outputs,
            "work_unit_triggers": [{
                "work_unit_key": contract.key,
                "trigger_identities": sorted(changed),
            }],
        }
        encoded = json.dumps(
            unsigned, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        plan = {
            **unsigned,
            "plan_digest": hashlib.sha256(encoded).hexdigest(),
        }
        apply_semantic_invalidation(root, plan, run_id=run)
        return plan


def recover_quarantined_deterministic_work_unit_prestate(
    scratchpad: Path,
    project_root: Path,
    contract: PhaseIOContract,
    launch: LaunchSpec,
    *,
    run_id: str,
) -> bool:
    """Restore exact predecessor ownership after a rejected DRIVER commit.

    This is deliberately narrower than ordinary deterministic reexecution.  It
    accepts only the same-run ``QUARANTINED/OUTPUT_QUARANTINED`` state produced
    by a failed output commit, requires the caller to have already restored
    every output path to its ledger-bound prestate bytes, replays each original
    predecessor work unit, and then returns this work unit to its original
    preexecution receipt.  It cannot adopt the quarantined bytes or authorize
    an output-only mutation.
    """

    contract, launch = _replay_authority_pair(contract, launch)
    if (
        contract.model_invoked is not False
        or any(spec.writer != "DRIVER" for spec in contract.outputs)
    ):
        raise ArtifactLedgerError(
            "quarantine recovery requires one deterministic DRIVER contract"
        )
    run = str(run_id or "").strip()
    if not run:
        raise ArtifactLedgerError("quarantine recovery run_id is absent")

    with _ledger_transaction_lock(Path(scratchpad)):
        root = Path(scratchpad)
        project = Path(project_root)
        ledger = read_artifact_ledger(root)
        unit = ledger.get("work_units", {}).get(contract.key)
        if not isinstance(unit, dict):
            return False
        if not (
            unit.get("run_id") == run
            and unit.get("contract_digest") == contract.digest
            and _stored_launch_matches(unit, launch)
            and unit.get("model_invoked") is False
            and unit.get("semantic_status") == "QUARANTINED"
            and unit.get("execution_state") == "OUTPUT_QUARANTINED"
        ):
            return False
        commit = unit.get("commit_authority")
        expected_outputs = {spec.identity for spec in contract.outputs}
        unit_records = unit.get("artifacts")
        artifact_bindings = ledger.get("artifact_bindings")
        legacy_records = ledger.get("artifacts")
        selected_bindings = {
            identity: artifact_bindings.get(identity)
            for identity in expected_outputs
        } if isinstance(artifact_bindings, Mapping) else None
        selected_legacy = {
            _legacy_name(identity): legacy_records.get(
                _legacy_name(identity)
            )
            for identity in expected_outputs
        } if isinstance(legacy_records, Mapping) else None
        if (
            not isinstance(commit, Mapping)
            or not _nested_output_records_have_exact_sizes(
                commit.get("expected_output_records"),
                expected_identities=expected_outputs,
            )
            or not _nested_output_records_have_exact_sizes(
                unit_records,
                expected_identities=expected_outputs,
            )
            or not _nested_output_records_have_exact_sizes(
                selected_bindings,
                expected_identities=expected_outputs,
            )
            or not _nested_output_records_have_exact_sizes(
                selected_legacy,
                expected_identities={
                    _legacy_name(identity)
                    for identity in expected_outputs
                },
            )
            or not _is_digest(commit.get("output_authority_key"))
            or not _is_digest(commit.get("output_authority_digest"))
        ):
            raise ArtifactLedgerError(
                "quarantine recovery expected-output authority is absent"
            )
        successor_affected_inputs: set[str] = set()
        if isinstance(
            unit.get("successor_consumption_authority"),
            Mapping,
        ):
            try:
                successor_authority, _successor_plan = (
                    _replay_driver_successor_authority(
                        root,
                        project,
                        ledger,
                        unit,
                        contract,
                        launch,
                        run_id=run,
                    )
                )
            except (
                ArtifactLedgerError,
                KeyError,
                OSError,
                TypeError,
                ValueError,
            ) as exc:
                raise ArtifactLedgerError(
                    "quarantine recovery successor authority is invalid: "
                    f"{exc}"
                ) from exc
            successor_affected_inputs = set(
                successor_authority.get(
                    "affected_input_identities", ()
                )
            )
        input_bindings = unit.get("input_bindings")
        if (
            not isinstance(input_bindings, dict)
            or _input_set_digest(input_bindings)
            != unit.get("input_set_digest")
            or any(
                not isinstance(row, dict)
                or row.get("status") != "ACTIVE"
                for row in input_bindings.values()
            )
        ):
            raise ArtifactLedgerError(
                "quarantine recovery input receipt is invalid"
            )
        current_inputs: dict[str, dict[str, Any]] = {}
        for identity in contract.immutable_inputs:
            current_inputs[identity] = _input_binding_record(
                root, project, identity, "IMMUTABLE", ledger
            )
        for identity in contract.bounded_lookup_inputs:
            input_class = (
                "IMMUTABLE_AND_BOUNDED_LOOKUP"
                if identity in current_inputs
                else "BOUNDED_LOOKUP"
            )
            current_inputs[identity] = _input_binding_record(
                root, project, identity, input_class, ledger
            )
        semantic_keys = {
            "identity",
            "input_class",
            "status",
            "size",
            "sha256",
            "producer_work_unit_key",
            "producer_contract_digest",
            "producer_launch_digest",
            "producer_commit_receipt_digest",
        }
        def _input_drift_fields(identity: str) -> list[str]:
            current = current_inputs.get(identity, {})
            prior = input_bindings.get(identity, {})
            fields = set(semantic_keys)
            if identity in successor_affected_inputs:
                fields.discard("status")
                if (
                    prior.get("status") != "ACTIVE"
                    or current.get("status")
                    not in {
                        "ACTIVE",
                        "PRODUCER_AUTHORITY_MISMATCH",
                    }
                ):
                    return ["status"]
            return sorted(
                key
                for key in fields
                if current.get(key) != prior.get(key)
            )

        input_drift = sorted(
            (
                identity,
                _input_drift_fields(identity),
            )
            for identity in set(current_inputs) | set(input_bindings)
            if identity not in current_inputs
            or identity not in input_bindings
            or _input_drift_fields(identity)
        )
        if input_drift:
            raise ArtifactLedgerError(
                "quarantine recovery immutable input denominator drifted: "
                + "; ".join(
                    f"{identity}({','.join(fields) or 'denominator'})"
                    for identity, fields in input_drift
                )
            )

        prestates = unit.get("output_prestates")
        specs_by_identity = {
            spec.identity: spec for spec in contract.outputs
        }
        if (
            not isinstance(prestates, dict)
            or set(prestates) != expected_outputs
            or _output_prestate_digest(prestates)
            != unit.get("output_prestate_digest")
        ):
            raise ArtifactLedgerError(
                "quarantine recovery output prestate receipt is invalid"
            )
        restored_bindings: dict[str, dict[str, Any] | None] = {}
        for identity in sorted(expected_outputs):
            prestate = prestates.get(identity)
            if not isinstance(prestate, dict):
                raise ArtifactLedgerError(
                    f"quarantine recovery prestate malformed: {identity}"
                )
            path = _path_for_identity(root, project, identity)
            status = str(prestate.get("status") or "")
            current_binding = ledger.get("artifact_bindings", {}).get(
                identity
            )
            if status == "ABSENT":
                if path.exists() or path.is_symlink():
                    raise ArtifactLedgerError(
                        f"quarantine recovery absent prestate exists: {identity}"
                    )
                if isinstance(current_binding, dict) and not (
                    current_binding.get("owner_key") == contract.key
                    and current_binding.get("status")
                    in {"MISSING", "QUARANTINED"}
                ):
                    raise ArtifactLedgerError(
                        f"quarantine recovery absent output owner drift: {identity}"
                    )
                restored_bindings[identity] = None
                continue
            if status not in {
                "ACTIVE_REGISTERED_PREDECESSOR",
                "ACTIVE_PREIMAGE",
            }:
                raise ArtifactLedgerError(
                    f"quarantine recovery unsupported prestate: {identity}"
                )
            if (
                status == "ACTIVE_PREIMAGE"
                and specs_by_identity[identity].write_mode != "MERGE"
            ):
                raise ArtifactLedgerError(
                    "quarantine recovery ACTIVE_PREIMAGE is not an "
                    f"exact MERGE output: {identity}"
                )
            if (
                not path.is_file()
                or path.is_symlink()
                or _sha256(path) != prestate.get("sha256")
                or path.stat().st_size != prestate.get("size")
            ):
                raise ArtifactLedgerError(
                    f"quarantine recovery predecessor bytes drift: {identity}"
                )
            predecessor_key = str(
                prestate.get("predecessor_owner_key") or ""
            )
            predecessor = ledger.get("work_units", {}).get(predecessor_key)
            predecessor_record = (
                predecessor.get("artifacts", {}).get(identity)
                if isinstance(predecessor, dict)
                and isinstance(predecessor.get("artifacts"), dict)
                else None
            )
            if not (
                isinstance(predecessor_record, dict)
                and predecessor.get("run_id") == run
                and predecessor.get("contract_digest")
                == prestate.get("predecessor_contract_digest")
                and predecessor.get("launch_digest")
                == prestate.get("predecessor_launch_digest")
                and predecessor_record.get("sha256")
                == prestate.get("sha256")
                and predecessor_record.get("size") == prestate.get("size")
            ):
                raise ArtifactLedgerError(
                    f"quarantine recovery predecessor authority drift: {identity}"
                )
            historical_issues = stored_committed_work_unit_authority_issues(
                ledger,
                work_unit_key=predecessor_key,
                run_id=run,
                expected_artifact_identities=tuple(
                    sorted(predecessor.get("artifacts", {}))
                ),
            )
            if historical_issues:
                raise ArtifactLedgerError(
                    "quarantine recovery historical predecessor does not "
                    "replay: " + "; ".join(historical_issues)
                )
            if not (
                isinstance(current_binding, dict)
                and current_binding.get("owner_key") == contract.key
                and current_binding.get("status") == "QUARANTINED"
            ):
                raise ArtifactLedgerError(
                    f"quarantine recovery output owner drift: {identity}"
                )
            restored = copy.deepcopy(predecessor_record)
            restored["status"] = "ACTIVE"
            restored.pop("superseded_by_owner_key", None)
            if restored.get("authority_level") == "RETIRED":
                restored["authority_level"] = str(
                    next(
                        (
                            row.get("authority_level")
                            for row in current_binding.get("history", [])
                            if isinstance(row, dict)
                            and row.get("owner_key") == predecessor_key
                            and row.get("sha256") == prestate.get("sha256")
                        ),
                        "PROPOSAL_ONLY",
                    )
                )
            history = [
                copy.deepcopy(row)
                for row in current_binding.get("history", [])
                if isinstance(row, dict)
                and not (
                    row.get("owner_key") == predecessor_key
                    and row.get("sha256") == prestate.get("sha256")
                )
            ]
            quarantined_snapshot = copy.deepcopy(current_binding)
            quarantined_snapshot.pop("history", None)
            history.append(quarantined_snapshot)
            restored["history"] = history[-32:]
            predecessor_record["status"] = "ACTIVE"
            predecessor_record.pop("superseded_by_owner_key", None)
            if predecessor_record.get("authority_level") == "RETIRED":
                predecessor_record["authority_level"] = restored.get(
                    "authority_level", "PROPOSAL_ONLY"
                )
            restored_bindings[identity] = restored

        # The quarantined issuance observed the rejected successor bytes, but
        # recovery requires the filesystem to contain every exact predecessor
        # prestate (or exact absence) before it can run.  Relax only that stale
        # live-byte comparison after the complete output denominator, current
        # quarantined ownership, same-run predecessor records, historical
        # commits/CAS, successor plan, and immutable inputs have all replayed.
        output_authority_issues = _replay_output_commit_authority(
            root,
            project,
            unit,
            require_live_bytes=True,
            # The rejected issuance observed successor bytes.  Immediately
            # above, recovery proves every output is instead at its exact
            # sealed prestate (including exact absence), and proves the
            # same-run predecessor/owner denominator.  Exempt precisely that
            # complete, already-validated denominator—not arbitrary outputs.
            live_byte_exempt_identities=tuple(sorted(expected_outputs)),
            allow_quarantined_expected_mismatch=True,
        )
        if output_authority_issues:
            raise ArtifactLedgerError(
                "quarantine recovery output authority is invalid: "
                + "; ".join(output_authority_issues)
            )

        now = datetime.now(timezone.utc).isoformat()
        for identity, restored in restored_bindings.items():
            legacy_name = _legacy_name(identity)
            if restored is None:
                ledger["artifact_bindings"].pop(identity, None)
                legacy = ledger["artifacts"].get(legacy_name)
                if (
                    isinstance(legacy, dict)
                    and legacy.get("owner_key") == contract.key
                ):
                    ledger["artifacts"].pop(legacy_name, None)
                continue
            ledger["artifact_bindings"][identity] = restored
            ledger["artifacts"][legacy_name] = {
                "path": legacy_name,
                "owner_phase": str(restored.get("owner_key") or "").split(
                    "/"
                )[4],
                "owner_key": restored.get("owner_key"),
                "status": "ACTIVE",
                "mtime_ns": restored.get("mtime_ns", 0),
                "size": restored.get("size", 0),
                "sha256": restored.get("sha256", ""),
                "updated_at": now,
                "contract_digest": restored.get("contract_digest", ""),
                "launch_digest": restored.get("launch_digest", ""),
                "run_id": run,
                "authority_level": restored.get(
                    "authority_level", "PROPOSAL_ONLY"
                ),
            }

        recovery_history = _validated_quarantine_recovery_history(
            unit,
            work_unit_key=contract.key,
            run_id=run,
        )
        if len(recovery_history) >= 32:
            raise ArtifactLedgerError(
                "quarantine recovery history is exhausted"
            )
        recovery_unsigned = {
            "schema": _QUARANTINE_RECOVERY_AUTHORITY_SCHEMA,
            "ordinal": len(recovery_history) + 1,
            "prior_recovery_authority_digest": (
                recovery_history[-1]["authority_digest"]
                if recovery_history else ""
            ),
            "recovered_at": now,
            "prior_commit_authority": copy.deepcopy(
                unit.get("commit_authority")
            ),
            "prior_artifacts_sha256": hashlib.sha256(
                json.dumps(
                    unit.get("artifacts", {}),
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
            ).hexdigest(),
        }
        recovery_row = {
            **recovery_unsigned,
            "authority_digest": _canonical_json_digest(recovery_unsigned),
        }
        next_recovery_history = [*recovery_history, recovery_row]
        reset = {
            key: copy.deepcopy(value)
            for key, value in unit.items()
            if key
            in {
                "schema",
                "work_unit_key",
                "run_id",
                "contract_digest",
                "contract_manifest",
                "launch_digest",
                "launch_manifest",
                "model_invoked",
                "recorded_at",
                "input_recorded_at",
                "input_bindings",
                "input_set_digest",
                "output_prestates",
                "output_prestate_digest",
                "input_receipt_kind",
                "explicit_absence_authority",
                "input_rebind_history",
            }
        }
        reset.update(
            {
                "execution_state": "INPUTS_BOUND_PREEXECUTION",
                "semantic_status": "INPUTS_BOUND",
                "artifacts": {},
                "quarantine_recovery_history": next_recovery_history,
                "quarantine_recovery_history_count": len(
                    next_recovery_history
                ),
                "quarantine_recovery_history_head_digest": (
                    recovery_row["authority_digest"]
                ),
            }
        )
        successor_authority = unit.get(
            "successor_consumption_authority"
        )
        if isinstance(successor_authority, Mapping):
            # Preserve the original sealed plan/claim for an exact retry while
            # retiring the failed ordered prefix.  Dropping the authority but
            # retaining its input markers creates an unrecoverable half-state.
            reset["successor_consumption_authority"] = copy.deepcopy(
                successor_authority
            )
            reset["successor_progress_authority"] = (
                _new_driver_successor_progress_authority(
                    successor_authority
                )
            )
            reset["successor_physical_rebind_history"] = (
                _issue_driver_successor_physical_rebind(
                    root,
                    project,
                    unit,
                    successor_authority,
                    reset["quarantine_recovery_history"],
                )
            )
        ledger["work_units"][contract.key] = reset
        write_artifact_ledger(root, ledger)
        _synchronize_driver_successor_progress_projection(
            root, ledger
        )
    return True


def _semantic_artifact_state(
    scratchpad: Path, project_root: Path, identity: str,
) -> dict[str, Any]:
    if not isinstance(identity, str) or identity.count(":") != 1:
        raise ArtifactLedgerError("semantic mutation artifact identity is invalid")
    root, relative = identity.split(":", 1)
    if root not in {"scratchpad", "project"} or not relative:
        raise ArtifactLedgerError("semantic mutation artifact identity is invalid")
    path = _path_for_identity(Path(scratchpad), Path(project_root), identity)
    present = rooted_io.is_file(path)
    return {
        "status": "ACTIVE" if present else "MISSING",
        "size": rooted_io.lstat(path).st_size if present else 0,
        "sha256": _sha256(path) if present else "",
    }


def _semantic_transition_authority(
    scratchpad: Path,
    project_root: Path,
    identity: str,
    *,
    before: Mapping[str, Any],
    after: Mapping[str, Any],
) -> dict[str, Any]:
    """Classify a terminal semantic write from the exact live byte stream.

    A mutation label is not evidence that a write was additive.  For active
    files, hash the historical-length prefix and the appended suffix while
    also re-hashing the full successor.  Only exact prefix preservation earns
    ``STRICT_APPEND`` authority; every other changed write is a replacement.
    """

    if (
        before.get("status") != "ACTIVE"
        or after.get("status") != "ACTIVE"
        or not isinstance(before.get("size"), int)
        or isinstance(before.get("size"), bool)
        or not isinstance(after.get("size"), int)
        or isinstance(after.get("size"), bool)
        or not isinstance(before.get("sha256"), str)
        or not isinstance(after.get("sha256"), str)
    ):
        return {}
    path = _path_for_identity(
        Path(scratchpad), Path(project_root), str(identity)
    )
    prefix_remaining = int(before["size"])
    prefix_digest = hashlib.sha256()
    suffix_digest = hashlib.sha256()
    successor_digest = hashlib.sha256()
    total = 0
    suffix_size = 0
    try:
        with path.open("rb") as stream:
            while True:
                chunk = stream.read(1024 * 1024)
                if not chunk:
                    break
                successor_digest.update(chunk)
                total += len(chunk)
                if prefix_remaining:
                    prefix = chunk[:prefix_remaining]
                    prefix_digest.update(prefix)
                    prefix_remaining -= len(prefix)
                    suffix = chunk[len(prefix):]
                else:
                    suffix = chunk
                if suffix:
                    suffix_digest.update(suffix)
                    suffix_size += len(suffix)
    except OSError as exc:
        raise ArtifactLedgerError(
            "semantic mutation transition bytes are unreadable: "
            f"{type(exc).__name__}: {exc}"
        ) from exc
    if (
        total != int(after["size"])
        or successor_digest.hexdigest() != str(after["sha256"])
    ):
        raise ArtifactLedgerError(
            "semantic mutation changed while transition authority was built"
        )
    empty_digest = hashlib.sha256(b"").hexdigest()
    if before == after:
        kind = "NO_CHANGE"
        appended_digest = empty_digest
        appended_size = 0
    elif (
        int(after["size"]) > int(before["size"])
        and prefix_remaining == 0
        and prefix_digest.hexdigest() == str(before["sha256"])
    ):
        kind = "STRICT_APPEND"
        appended_digest = suffix_digest.hexdigest()
        appended_size = suffix_size
    else:
        kind = "REPLACEMENT"
        appended_digest = empty_digest
        appended_size = 0
    return {
        "transition_kind": kind,
        "preimage_sha256": str(before["sha256"]),
        "preimage_size": int(before["size"]),
        "successor_sha256": str(after["sha256"]),
        "successor_size": int(after["size"]),
        "appended_sha256": appended_digest,
        "appended_size": appended_size,
    }


def arm_semantic_mutation(
    scratchpad: Path,
    project_root: Path,
    *,
    artifact_identity: str,
    mutation_kind: str,
    run_id: str,
) -> dict[str, Any]:
    """Durably arm a mutation before any semantic source bytes can change."""

    run = str(run_id or "").strip()
    kind = str(mutation_kind or "").strip().upper()
    if not run or not kind:
        raise ArtifactLedgerError("semantic mutation run/kind is empty")
    before = _semantic_artifact_state(
        Path(scratchpad), Path(project_root), artifact_identity
    )
    with _ledger_transaction_lock(scratchpad):
        payload = _read_semantic_mutations(Path(scratchpad))
        for event in payload["events"]:
            if (
                event.get("status") == "ARMED"
                and event.get("run_id") == run
                and event.get("mutation_kind") == kind
                and event.get("artifact_identity") == artifact_identity
                and event.get("before") == before
            ):
                return dict(event)
        ordinal = len(payload["events"]) + 1
        event: dict[str, Any] = {
            "schema": "plamen.semantic_mutation.v1",
            "event_id": "",
            "run_id": run,
            "mutation_kind": kind,
            "artifact_identity": artifact_identity,
            "status": "ARMED",
            "before": before,
            "after": {},
            "transition_authority": {},
            "affected_record_ids": [],
            "invalidated_work_unit_keys": [],
            "plan_digest": "",
            "checkpoint_reconciled": False,
            "reconciled_by_run_id": "",
        }
        event["event_id"] = _semantic_mutation_event_id(event, ordinal)
        event["event_digest"] = _mutation_event_digest(event)
        payload["events"].append(event)
        _write_semantic_mutations(Path(scratchpad), payload)
        return dict(event)


def find_semantic_mutation_event(
    scratchpad: Path,
    *,
    run_id: str,
    mutation_kind: str,
    artifact_identity: str,
) -> dict[str, Any] | None:
    """Return one exact transaction-owned semantic event, if it exists.

    Transaction recovery must not call :func:`arm_semantic_mutation` again
    after the canonical postimage has landed: the live bytes no longer equal
    the original ``before`` state, so the ordinary idempotence predicate would
    create a second event.  This lookup is deliberately exact and rejects
    duplicate event identities instead of choosing one.
    """

    run = str(run_id or "").strip()
    kind = str(mutation_kind or "").strip().upper()
    identity = str(artifact_identity or "").strip()
    if not run or not kind or not identity:
        raise ArtifactLedgerError(
            "semantic mutation lookup run/kind/identity is empty"
        )
    payload = _read_semantic_mutations(Path(scratchpad))
    matches = [
        dict(event)
        for event in payload["events"]
        if (
            event.get("run_id") == run
            and event.get("mutation_kind") == kind
            and event.get("artifact_identity") == identity
        )
    ]
    if len(matches) > 1:
        raise ArtifactLedgerError(
            "semantic mutation transaction has duplicate exact events"
        )
    return matches[0] if matches else None


def finalize_semantic_mutation(
    scratchpad: Path,
    project_root: Path,
    event_id: str,
    *,
    run_id: str,
    affected_record_ids: tuple[str, ...] | list[str] = (),
    closed_rmw_work_unit_keys: Sequence[str] = (),
) -> dict[str, Any]:
    """Finish one armed mutation and invalidate exact typed descendants."""

    run = str(run_id or "").strip()
    with _ledger_transaction_lock(scratchpad):
        payload = _read_semantic_mutations(Path(scratchpad))
        matches = [
            event for event in payload["events"]
            if event.get("event_id") == event_id
        ]
        if len(matches) != 1:
            raise ArtifactLedgerError("semantic mutation event is missing")
        event = matches[0]
        if event.get("run_id") != run:
            raise ArtifactLedgerError("semantic mutation event run mismatch")
        if event.get("status") in {"NO_CHANGE", "INVALIDATION_APPLIED"}:
            return dict(event)
        if event.get("status") != "ARMED":
            raise ArtifactLedgerError("semantic mutation event state is invalid")

        after = _semantic_artifact_state(
            Path(scratchpad), Path(project_root),
            str(event.get("artifact_identity") or ""),
        )
        transition = _semantic_transition_authority(
            Path(scratchpad),
            Path(project_root),
            str(event.get("artifact_identity") or ""),
            before=dict(event.get("before") or {}),
            after=after,
        )
        affected = sorted({
            str(item or "").strip() for item in affected_record_ids
            if str(item or "").strip()
        })
        invalidated: list[str] = []
        plan_digest = ""
        if after != event.get("before"):
            ledger = read_artifact_ledger(Path(scratchpad))
            closed_rmw = tuple(sorted({
                str(value or "").strip()
                for value in closed_rmw_work_unit_keys
                if str(value or "").strip()
            }))
            if closed_rmw:
                mutation_kind = str(event.get("mutation_kind") or "")
                allowed_suffixes = {
                    "/semantic_dedup/supplemental_proposals",
                    "/semantic_dedup/prequeue_apply",
                }
                if (
                    not mutation_kind.startswith(
                        "SEMANTIC_DEDUP_TRANSACTION_"
                    )
                    or not any(
                        key.endswith("/semantic_dedup/prequeue_apply")
                        for key in closed_rmw
                    )
                    or any(
                        not any(key.endswith(suffix) for suffix in allowed_suffixes)
                        for key in closed_rmw
                    )
                ):
                    raise ArtifactLedgerError(
                        "closed RMW invalidation exemption is not an exact "
                        "semantic-dedup transaction"
                    )
                event_identity = str(event.get("artifact_identity") or "")
                terminal_seen = False
                for key in closed_rmw:
                    unit = ledger.get("work_units", {}).get(key)
                    if not (
                        isinstance(unit, Mapping)
                        and unit.get("run_id") == run
                        and unit.get("execution_state") == "OUTPUT_COMMITTED"
                    ):
                        raise ArtifactLedgerError(
                            "closed RMW work unit is not terminal/current-run: "
                            + key
                        )
                    if key.endswith("/semantic_dedup/prequeue_apply"):
                        record = unit.get("artifacts", {}).get(event_identity)
                        terminal_seen = bool(
                            isinstance(record, Mapping)
                            and record.get("sha256") == after.get("sha256")
                            and record.get("size") == after.get("size")
                            and record.get("status") == "ACTIVE"
                        )
                if not terminal_seen:
                    raise ArtifactLedgerError(
                        "closed RMW terminal output does not bind the semantic "
                        "mutation postimage"
                    )
            plan = semantic_dependency_invalidation_plan(
                ledger,
                [str(event["artifact_identity"])],
                run_id=run,
                excluded_work_unit_keys=closed_rmw,
                changed_input_states={
                    str(event["artifact_identity"]): dict(event["before"])
                },
            )
            apply_semantic_invalidation(Path(scratchpad), plan, run_id=run)
            invalidated = list(plan.get("invalidated_work_unit_keys") or [])
            plan_digest = str(plan.get("plan_digest") or "")
            status = "INVALIDATION_APPLIED"
        else:
            status = "NO_CHANGE"
        event.update({
            "status": status,
            "after": after,
            "transition_authority": transition,
            "affected_record_ids": affected,
            "invalidated_work_unit_keys": sorted(invalidated),
            "plan_digest": plan_digest,
            "checkpoint_reconciled": status == "NO_CHANGE",
            "reconciled_by_run_id": run if status == "NO_CHANGE" else "",
        })
        event["event_digest"] = _mutation_event_digest(event)
        _write_semantic_mutations(Path(scratchpad), payload)
        return dict(event)


def recover_armed_semantic_mutations(
    scratchpad: Path,
    project_root: Path,
    *,
    run_id: str,
) -> list[dict[str, Any]]:
    """Recover crash-interrupted mutations before resume reconciliation."""

    payload = _read_semantic_mutations(Path(scratchpad))
    armed: list[str] = []
    transaction_recovered: list[dict[str, Any]] = []
    for event in payload["events"]:
        if event.get("run_id") != run_id or event.get("status") != "ARMED":
            continue
        # A report transaction owns its recovery order.  Canonical postimage
        # bytes alone are not commit authority: the exact inputs or sidecars
        # may have drifted after REPORT_REPLACED.  Replay the signed transaction
        # first so it validates and commits its entire denominator before the
        # semantic event becomes a virtual producer.  A semantic-arm-only crash
        # has no manifest yet and is safely left for the owning phase.
        if str(event.get("mutation_kind") or "").startswith(
            "REPORT_TRANSACTION_"
        ):
            try:
                from report_mutation_transaction import (
                    ReportMutationTransactionError,
                    recover_report_transaction_semantic_event,
                )

                recovered = recover_report_transaction_semantic_event(
                    scratchpad=Path(scratchpad),
                    project_root=Path(project_root),
                    run_id=run_id,
                    event=event,
                )
            except ReportMutationTransactionError as exc:
                raise ArtifactLedgerError(
                    f"report transaction recovery failed: {exc}"
                ) from exc
            if recovered is None:
                continue
            refreshed = _read_semantic_mutations(Path(scratchpad))
            matches = [
                row for row in refreshed["events"]
                if row.get("event_id") == event.get("event_id")
            ]
            if (
                len(matches) != 1
                or matches[0].get("status")
                not in {"NO_CHANGE", "INVALIDATION_APPLIED"}
            ):
                raise ArtifactLedgerError(
                    "report transaction recovery did not finalize its semantic event"
                )
            transaction_recovered.append(dict(matches[0]))
            continue
        # The L1 semantic-dedup RMW successor owns two canonical mutation
        # events plus three sidecars under one signed five-output transaction.
        # Finalizing either canonical event here would let generic recovery
        # certify only half of that publication before the transaction has
        # revalidated its pending pointer, generation manifest, exact
        # prestates, sidecars, and PhaseIO commit.  Leave both events ARMED;
        # ``semantic_dedup_transaction`` replays and finalizes them together.
        if str(event.get("mutation_kind") or "").startswith(
            "SEMANTIC_DEDUP_TRANSACTION_"
        ):
            continue
        armed.append(str(event["event_id"]))
    return transaction_recovered + [
        finalize_semantic_mutation(
            Path(scratchpad), Path(project_root), event_id, run_id=run_id
        )
        for event_id in armed
    ]


def pending_semantic_mutations(scratchpad: Path) -> list[dict[str, Any]]:
    """Return every mutation not yet durably reconciled with a checkpoint."""

    payload = _read_semantic_mutations(Path(scratchpad))
    return [
        dict(event) for event in payload["events"]
        if not event.get("checkpoint_reconciled")
    ]


def semantic_mutation_events(scratchpad: Path) -> list[dict[str, Any]]:
    """Return every structurally valid event for checkpoint cross-validation."""

    return [
        dict(event)
        for event in _read_semantic_mutations(Path(scratchpad))["events"]
    ]


def acknowledge_semantic_mutations(
    scratchpad: Path,
    event_ids: list[str] | tuple[str, ...],
    *,
    reconciled_by_run_id: str,
) -> list[dict[str, Any]]:
    """Bind mutation events only after the repaired checkpoint is durable."""

    identities = sorted(set(str(value) for value in event_ids if str(value)))
    if not identities:
        return []
    run = str(reconciled_by_run_id or "").strip()
    if not run:
        raise ArtifactLedgerError("semantic mutation reconciliation run is empty")
    with _ledger_transaction_lock(scratchpad):
        payload = _read_semantic_mutations(Path(scratchpad))
        by_id = {str(event["event_id"]): event for event in payload["events"]}
        if any(identity not in by_id for identity in identities):
            raise ArtifactLedgerError("semantic mutation acknowledgement identity missing")
        acknowledged: list[dict[str, Any]] = []
        for identity in identities:
            event = by_id[identity]
            if event.get("status") == "NO_CHANGE":
                acknowledged.append(dict(event))
                continue
            event["checkpoint_reconciled"] = True
            event["reconciled_by_run_id"] = run
            event["event_digest"] = _mutation_event_digest(event)
            acknowledged.append(dict(event))
        _write_semantic_mutations(Path(scratchpad), payload)
        return acknowledged


def quarantine_invalid_semantic_mutation_ledger(
    scratchpad: Path,
    *,
    reconciled_by_run_id: str,
    reason: str,
) -> dict[str, Any]:
    """Preserve invalid bytes once, then replace the active ledger cleanly."""

    root = Path(scratchpad)
    run = str(reconciled_by_run_id or "").strip()
    why = str(reason or "").strip()
    if not run or not why:
        raise ArtifactLedgerError("semantic mutation quarantine binding is empty")
    path = root / SEMANTIC_MUTATION_LEDGER_NAME
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise ArtifactLedgerError(
            f"cannot preserve invalid semantic mutation ledger: {exc}"
        ) from exc
    digest = hashlib.sha256(raw).hexdigest()
    quarantine_dir = root / "_semantic_mutation_quarantine"
    quarantine_dir.mkdir(parents=True, exist_ok=True)
    quarantine_path = quarantine_dir / f"{digest}.json"
    if not quarantine_path.is_file():
        with tempfile.NamedTemporaryFile(
            "wb", dir=str(quarantine_dir), delete=False,
            prefix=f".{digest}.", suffix=".tmp",
        ) as stream:
            stream.write(raw)
            temporary = Path(stream.name)
        os.replace(temporary, quarantine_path)
    if hashlib.sha256(quarantine_path.read_bytes()).hexdigest() != digest:
        raise ArtifactLedgerError("semantic mutation quarantine digest mismatch")

    receipt = {
        "schema": "plamen.semantic_mutation_migration.v1",
        "state": "QUARANTINED_AND_RESET",
        "source_name": SEMANTIC_MUTATION_LEDGER_NAME,
        "source_sha256": digest,
        "quarantine_path": quarantine_path.relative_to(root).as_posix(),
        "reconciled_by_run_id": run,
        "reason": why,
    }
    receipt["receipt_digest"] = hashlib.sha256(
        json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
    ).hexdigest()
    _write_semantic_mutations(
        root, {"schema": "plamen.semantic_mutations.v1", "events": []}
    )
    receipt_path = root / "semantic_mutation_migration.json"
    encoded = json.dumps(receipt, indent=2, sort_keys=True) + "\n"
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", newline="\n", dir=str(root), delete=False,
        prefix=f".{receipt_path.name}.", suffix=".tmp",
    ) as stream:
        stream.write(encoded)
        temporary = Path(stream.name)
    os.replace(temporary, receipt_path)
    return receipt


def validate_work_unit_artifacts(
    scratchpad: Path,
    project_root: Path,
    contract: PhaseIOContract,
    launch: LaunchSpec,
    *,
    run_id: str,
    actor: str | None = None,
    require_live_input_authority: bool = True,
    preexecution_authority: Mapping[str, Any] | None = None,
    _validation_context: _ArtifactValidationContext | None = None,
) -> list[str]:
    """Validate committed outputs; optionally require live input authority.

    The default remains the strict downstream freshness check.  A
    content-addressed transaction may set ``require_live_input_authority`` to
    false only while reconfirming an already-committed generation whose exact
    input bytes and producer receipts were frozen before publication.  That
    narrow recovery path still validates the immutable input receipt itself,
    the commit authority, every output binding, and the live output bytes.
    """
    if _validation_context is None:
        try:
            validation_context = _ArtifactValidationContext(
                Path(scratchpad), Path(project_root)
            )
        except ArtifactLedgerError as exc:
            return [str(exc)]
        issues = validate_work_unit_artifacts(
            Path(scratchpad),
            Path(project_root),
            contract,
            launch,
            run_id=run_id,
            actor=actor,
            require_live_input_authority=require_live_input_authority,
            preexecution_authority=preexecution_authority,
            _validation_context=validation_context,
        )
        issues.extend(validation_context.finish())
        return list(dict.fromkeys(issues))
    try:
        contract, launch = _replay_authority_pair(contract, launch)
        ledger = (
            read_artifact_ledger(scratchpad)
            if _validation_context is None
            else _validation_context.ledger
        )
    except ArtifactLedgerError as exc:
        return [str(exc)]
    unit = ledger["work_units"].get(contract.key)
    if not isinstance(unit, dict):
        return [f"{contract.key}: no exact work-unit artifact record"]
    issues: list[str] = []
    if unit.get("run_id") != run_id:
        issues.append(f"{contract.key}: run_id mismatch")
    if unit.get("contract_digest") != contract.digest:
        issues.append(f"{contract.key}: contract digest mismatch")
    manifest = unit.get("contract_manifest")
    if manifest != contract.to_dict():
        issues.append(f"{contract.key}: contract manifest mismatch")
    elif _contract_manifest_digest(manifest) != unit.get("contract_digest"):
        issues.append(f"{contract.key}: contract manifest digest mismatch")
    if unit.get("launch_digest") != launch.digest:
        issues.append(f"{contract.key}: launch digest mismatch")
    if (
        unit.get("launch_manifest") != launch.to_dict()
        or not _launch_manifest_is_valid(
            unit.get("launch_manifest"),
            expected_digest=unit.get("launch_digest"),
        )
    ):
        issues.append(f"{contract.key}: launch manifest mismatch")
    if unit.get("semantic_status") != "ACTIVE":
        issues.append(
            f"{contract.key}: output commit is not clean "
            f"(semantic_status={unit.get('semantic_status')})"
        )
    if unit.get("execution_state") != "OUTPUT_COMMITTED":
        issues.append(
            f"{contract.key}: output execution state is "
            f"{unit.get('execution_state') or 'MISSING'}"
        )
    actor_n = str(actor or "").strip().upper()
    if actor_n and actor_n not in {"MODEL", "DRIVER"}:
        return [f"{contract.key}: invalid validation actor {actor!r}"]
    selection_actor = actor_n
    if contract.required_commit_actor:
        if not actor_n:
            issues.append(
                f"{contract.key}: explicit validation actor is required"
            )
        elif actor_n != contract.required_commit_actor:
            issues.append(
                f"{contract.key}: validation actor disagrees with "
                "required commit actor"
            )
        selection_actor = contract.required_commit_actor
    commit = unit.get("commit_authority")
    if not isinstance(commit, dict):
        issues.append(f"{contract.key}: output commit authority receipt missing")
    else:
        if not _active_commit_receipt_is_valid(
            unit,
            work_unit_key=contract.key,
            run_id=run_id,
        ):
            issues.append(
                f"{contract.key}: active producer authority does not replay"
            )
        try:
            history_plan = _plan_output_authority_reconciliation(
                Path(scratchpad)
            )
            if any(history_plan[index] for index in range(1, 5)):
                issues.append(
                    f"{contract.key}: output authority history has an "
                    "unreconciled projection"
                )
        except ArtifactLedgerError as exc:
            issues.append(
                f"{contract.key}: output authority history is invalid: {exc}"
            )
        precommit_summary = _precommit_issue_receipt(())
        selected_identities = sorted(
            spec.identity
            for spec in contract.outputs
            if not selection_actor or spec.writer == selection_actor
        )
        if (
            commit.get("schema") != _COMMIT_AUTHORITY_SCHEMA
            or commit.get("state") != "ACTIVE"
            or commit.get("run_id") != run_id
            or commit.get("work_unit_key") != contract.key
            or commit.get("contract_digest") != contract.digest
            or commit.get("launch_digest") != launch.digest
            or commit.get("input_set_digest") != unit.get("input_set_digest")
            or commit.get("reason_codes") != []
            or commit.get("precommit_issues") != []
            or not _is_nonnegative_exact_int(
                commit.get("precommit_issue_count")
            )
            or commit.get("precommit_issue_count")
            != precommit_summary["count"]
            or commit.get("precommit_issue_digest")
            != precommit_summary["digest"]
            or commit.get("precommit_issue_overflow")
            != precommit_summary["overflow"]
            or commit.get("recorded_output_identities")
            != selected_identities
            or not _nested_output_records_have_exact_sizes(
                commit.get("expected_output_records"),
                expected_identities=set(selected_identities),
            )
            or (
                bool(contract.required_commit_actor)
                and commit.get("actor")
                != contract.required_commit_actor
            )
            or not _is_positive_exact_int(commit.get("attempt_ordinal"))
            or commit.get("receipt_digest") != _commit_receipt_digest(commit)
        ):
            issues.append(f"{contract.key}: output commit authority receipt invalid")
        issues.extend(
            f"{contract.key}: {issue}"
            for issue in _replay_output_commit_authority(
                Path(scratchpad),
                Path(project_root),
                unit,
                require_live_bytes=True,
                _validation_context=_validation_context,
            )
        )
        successor = unit.get("successor_consumption_authority")
        if isinstance(successor, Mapping):
            try:
                replayed_successor, replayed_plan = (
                    _replay_driver_successor_authority(
                        Path(scratchpad),
                        Path(project_root),
                        ledger,
                        unit,
                        contract,
                        launch,
                        run_id=run_id,
                    )
                )
                expected_merge_digests = {
                    transition.artifact_identity: (
                        transition.merge_event.digest
                    )
                    for transition in replayed_plan.transitions
                    if transition.merge_event is not None
                }
                successor_binding_valid = (
                    commit.get(
                        "successor_consumption_authority_digest"
                    )
                    == replayed_successor.get("authority_digest")
                    and commit.get("planned_merge_event_digests")
                    == expected_merge_digests
                    and "successor_consumption_authority_state"
                    not in commit
                )
            except (
                ArtifactLedgerError,
                KeyError,
                OSError,
                TypeError,
                ValueError,
            ):
                successor_binding_valid = False
            if not successor_binding_valid:
                issues.append(
                    f"{contract.key}: successor-specific commit binding "
                    "does not replay"
                )
        elif any(
            field in commit
            for field in (
                "successor_consumption_authority_digest",
                "planned_merge_event_digests",
                "successor_consumption_authority_state",
            )
        ):
            issues.append(
                f"{contract.key}: successor-specific commit binding exists "
                "without successor authority"
            )
    try:
        _validated_input_rebind_history(
            unit, work_unit_key=contract.key, run_id=run_id
        )
    except ArtifactLedgerError as exc:
        issues.append(f"{contract.key}: {exc}")
    records = unit.get("artifacts")
    if not isinstance(records, dict):
        return issues + [f"{contract.key}: artifacts record malformed"]
    committed_expected_outputs = (
        commit.get("expected_output_records")
        if isinstance(commit, dict)
        else None
    )
    selected_identities = {
        spec.identity
        for spec in contract.outputs
        if not selection_actor or spec.writer == selection_actor
    }
    if not _nested_output_records_have_exact_sizes(
        records,
        expected_identities=selected_identities,
    ):
        issues.append(
            f"{contract.key}: artifact record byte counts are invalid"
        )
    if (
        not isinstance(committed_expected_outputs, Mapping)
        or set(committed_expected_outputs) != selected_identities
        or not _nested_output_records_have_exact_sizes(
            committed_expected_outputs,
            expected_identities=selected_identities,
        )
    ):
        issues.append(
            f"{contract.key}: commit expected-output denominator mismatch"
        )
    else:
        for identity, expected_record in (
            committed_expected_outputs.items()
        ):
            record = records.get(identity)
            if (
                not isinstance(expected_record, Mapping)
                or set(expected_record) != {"sha256", "size"}
                or not isinstance(record, Mapping)
                or record.get("sha256")
                != expected_record.get("sha256")
                or record.get("size") != expected_record.get("size")
            ):
                issues.append(
                    f"{identity}: commit expected-output record mismatch"
                )
    repair_history_present = (
        "committed_output_repair_history" in unit
    )
    if repair_history_present:
        try:
            _validate_exact_repair_contract(contract, launch)
            repair_history = _exact_repair_history(unit)
        except ArtifactLedgerError as exc:
            issues.append(
                f"{contract.key}: committed output repair history invalid: "
                f"{exc}"
            )
            repair_history = []
        if repair_history:
            latest = repair_history[-1]
            if latest.get("state") != "REPAIRED_ACTIVE":
                issues.append(
                    f"{contract.key}: committed output repair remains ARMED"
                )
            else:
                finalize = latest.get("finalize_authority")
                expected_repair_digest = (
                    str(finalize.get("authority_digest") or "")
                    if isinstance(finalize, Mapping)
                    else ""
                )
                if (
                    not expected_repair_digest
                    or finalize.get("run_id") != run_id
                    or finalize.get("work_unit_key") != contract.key
                    or finalize.get("contract_digest") != contract.digest
                    or finalize.get("launch_digest") != launch.digest
                ):
                    issues.append(
                        f"{contract.key}: latest repair finalize authority "
                        "does not bind this work unit"
                    )
                for spec in contract.outputs:
                    identity = spec.identity
                    record = records.get(identity)
                    binding = ledger.get("artifact_bindings", {}).get(
                        identity
                    )
                    legacy = ledger.get("artifacts", {}).get(
                        _legacy_name(identity)
                    )
                    if any(
                        not isinstance(value, Mapping)
                        or value.get("repair_authority_digest")
                        != expected_repair_digest
                        for value in (record, binding, legacy)
                    ):
                        issues.append(
                            f"{identity}: repair authority projection mismatch"
                        )
    elif any(
        isinstance(record, Mapping)
        and record.get("repair_authority_digest")
        for record in records.values()
    ):
        issues.append(
            f"{contract.key}: repair digest exists without repair history"
        )
    output_prestates = unit.get("output_prestates")
    expected_output_identities = {spec.identity for spec in contract.outputs}
    if not isinstance(output_prestates, dict):
        issues.append(f"{contract.key}: output prestate receipt missing")
        output_prestates = {}
    else:
        if set(output_prestates) != expected_output_identities:
            issues.append(f"{contract.key}: output prestate denominator mismatch")
        try:
            prestate_digest = _output_prestate_digest(output_prestates)
        except (AttributeError, TypeError, ValueError):
            prestate_digest = ""
            issues.append(f"{contract.key}: output prestate receipt malformed")
        if prestate_digest != unit.get("output_prestate_digest"):
            issues.append(f"{contract.key}: output prestate digest mismatch")
        for identity, prestate in sorted(output_prestates.items()):
            if not isinstance(prestate, Mapping) or not _output_prestate_is_clean(
                prestate
            ):
                issues.append(
                    f"{identity}: output prestate authority is invalid"
                )
    transitions = (
        commit.get("read_modify_write_transitions")
        if isinstance(commit, dict)
        else None
    )
    if not isinstance(transitions, dict):
        issues.append(
            f"{contract.key}: read-modify-write transition receipt malformed"
        )
        transitions = {}
    for spec in contract.outputs:
        if selection_actor and spec.writer != selection_actor:
            continue
        record = records.get(spec.identity)
        if not isinstance(record, dict):
            issues.append(f"{spec.identity}: missing exact denominator record")
            continue
        try:
            path = _path_for_identity(
                scratchpad, project_root, spec.identity
            )
        except ArtifactLedgerError as exc:
            issues.append(f"{spec.identity}: unsafe physical path: {exc}")
            continue
        validation_snapshot: dict[str, Any] | None = None
        validation_snapshot_error = ""
        if _validation_context is None:
            present = rooted_io.is_file(path)
        else:
            validation_snapshot, validation_snapshot_error = (
                _validation_context.snapshot(path)
            )
            present = (
                validation_snapshot is not None
                or rooted_io.lexists(path)
            )
        if not present:
            if spec.artifact_class in {"REQUIRED", "DRIVER_GENERATED"}:
                issues.append(f"{spec.identity}: required output missing")
            elif spec.artifact_class == "CONDITIONAL":
                receipt = record.get("conditional_receipt")
                receipt_state = (
                    receipt.get("state") if isinstance(receipt, dict) else None
                )
                if receipt_state not in {"NOT_TRIGGERED", "TRIGGERED_EMPTY"}:
                    issues.append(
                        f"{spec.identity}: conditional output lacks a valid absent-state receipt"
                    )
            continue
        if spec.artifact_class == "CONDITIONAL":
            receipt = record.get("conditional_receipt")
            receipt_state = receipt.get("state") if isinstance(receipt, dict) else None
            if receipt_state != "PRODUCED":
                issues.append(
                    f"{spec.identity}: present conditional output is not bound to PRODUCED"
                )
        snapshot, snapshot_error = (
            _stable_artifact_snapshot(path)
            if _validation_context is None
            else (validation_snapshot, validation_snapshot_error)
        )
        if snapshot is None:
            issues.append(
                f"{spec.identity}: live output snapshot is unsafe: "
                f"{snapshot_error}"
            )
            continue
        current = str(snapshot["sha256"])
        try:
            current_physical = (
                _physical_file_identity(path)
                if _validation_context is None
                else _validation_context.physical_identity(path)
            )
        except OSError as exc:
            issues.append(
                f"{spec.identity}: physical identity unavailable: "
                f"{type(exc).__name__}"
            )
            current_physical = ""
        if record.get("status") != "ACTIVE":
            issues.append(f"{spec.identity}: status={record.get('status')}")
        if record.get("sha256") != current:
            issues.append(f"{spec.identity}: content hash changed since work-unit record")
        if record.get("physical_identity") != current_physical:
            issues.append(f"{spec.identity}: physical file identity changed")
        if record.get("owner_key") != contract.key:
            issues.append(f"{spec.identity}: owner work-unit mismatch")
        binding = ledger.get("artifact_bindings", {}).get(spec.identity)
        legacy = ledger.get("artifacts", {}).get(
            _legacy_name(spec.identity)
        )
        if (
            not isinstance(binding, dict)
            or not isinstance(legacy, Mapping)
            or not _nested_output_records_have_exact_sizes(
                {spec.identity: record}
            )
            or not _nested_output_records_have_exact_sizes(
                {spec.identity: binding}
            )
            or not _nested_output_records_have_exact_sizes(
                {spec.identity: legacy}
            )
        ):
            issues.append(f"{spec.identity}: global artifact binding missing")
        elif any(
            binding.get(field) != record.get(field)
            for field in (
                "identity", "owner_key", "run_id", "contract_digest",
                "launch_digest", "status", "size", "sha256", "writer",
                "write_mode", "authority_level", "physical_identity",
            )
        ):
            issues.append(f"{spec.identity}: global artifact binding mismatch")
        elif any(
            legacy.get(field) != record.get(field)
            for field in (
                "owner_key",
                "status",
                "size",
                "sha256",
                "contract_digest",
                "launch_digest",
                "run_id",
                "authority_level",
            )
        ):
            issues.append(f"{spec.identity}: legacy artifact projection mismatch")
        prestate = output_prestates.get(spec.identity)
        transition = transitions.get(spec.identity)
        if spec.write_mode == "APPEND":
            valid = bool(
                isinstance(prestate, Mapping)
                and isinstance(transition, Mapping)
                and transition.get("write_mode") == "APPEND"
                and transition.get("preimage_sha256")
                == prestate.get("sha256")
                and transition.get("preimage_size") == prestate.get("size")
                and transition.get("successor_sha256") == record.get("sha256")
                and transition.get("successor_size") == record.get("size")
                and transition.get("prefix_preserved") is True
            )
            if not valid:
                issues.append(
                    f"{spec.identity}: APPEND transition authority invalid"
                )
        elif spec.write_mode == "MERGE":
            identities_before = (
                transition.get("identities_before")
                if isinstance(transition, Mapping)
                else None
            )
            identities_after = (
                transition.get("identities_after")
                if isinstance(transition, Mapping)
                else None
            )
            sources = (
                transition.get("source_identities")
                if isinstance(transition, Mapping)
                else None
            )
            valid = bool(
                isinstance(prestate, Mapping)
                and isinstance(transition, Mapping)
                and transition.get("write_mode") == "MERGE"
                and transition.get("preimage_sha256")
                == prestate.get("sha256")
                and transition.get("successor_sha256") == record.get("sha256")
                and _is_digest(transition.get("merge_event_digest"))
                and isinstance(identities_before, list)
                and isinstance(identities_after, list)
                and isinstance(sources, list)
                and identities_before == sorted(set(identities_before))
                and identities_after == sorted(set(identities_after))
                and sources == sorted(set(sources))
                and set(identities_before).issubset(identities_after)
            )
            external_receipt = (
                prestate.get("external_preimage_receipt")
                if isinstance(prestate, Mapping)
                else None
            )
            if external_receipt is not None:
                try:
                    validate_external_preimage_receipt_integrity(
                        external_receipt
                    )
                except ExternalPreimageValidationError:
                    valid = False
                else:
                    valid = bool(
                        valid
                        and external_receipt.get("work_unit_key")
                        == contract.key
                        and external_receipt.get("contract_digest")
                        == contract.digest
                        and external_receipt.get("artifact_identity")
                        == spec.identity
                        and external_receipt.get("validator_id")
                        == spec.external_preimage_validator
                        and external_receipt.get("raw_sha256")
                        == transition.get("preimage_sha256")
                        and external_receipt.get("size")
                        == prestate.get("size")
                        and external_receipt.get("parsed_identities")
                        == identities_before
                    )
            if not valid:
                issues.append(
                    f"{spec.identity}: MERGE transition authority invalid"
                )
        elif spec.identity in transitions:
            issues.append(
                f"{spec.identity}: unexpected read-modify-write transition"
            )
    if require_live_input_authority:
        # Validation is defense in depth; commit already performs this check
        # under the ledger lock, but ordinary resume/report consumers must
        # also reject subsequent input or producer drift.
        issues.extend(
            validate_work_unit_inputs(
                scratchpad,
                project_root,
                contract,
                launch,
                run_id=run_id,
                preexecution_authority=preexecution_authority,
                _validation_context=_validation_context,
            )
        )
    return list(dict.fromkeys(issues))


__all__ = [
    "active_committed_work_unit_authority_issues",
    "apply_semantic_invalidation",
    "acknowledge_semantic_mutations",
    "arm_exact_committed_output_repair",
    "arm_semantic_mutation",
    "artifact_ledger_digest",
    "ArtifactLedgerError",
    "ArtifactLedgerCASMismatch",
    "begin_driver_successor_step",
    "authorize_exact_committed_output_repair",
    "authorize_deterministic_work_unit_reexecution",
    "recover_quarantined_deterministic_work_unit_prestate",
    "detect_semantic_input_drift",
    "finalize_semantic_mutation",
    "LEDGER_NAME",
    "LEDGER_VERSION",
    "load_driver_successor_plan",
    "pending_semantic_mutations",
    "plan_driver_successor_transaction",
    "quarantine_invalid_semantic_mutation_ledger",
    "read_artifact_ledger",
    "record_work_unit_explicit_absence_bindings",
    "record_work_unit_artifacts",
    "record_work_unit_inputs",
    "recover_uncommitted_driver_input_denominator",
    "replace_uncommitted_driver_input_denominator",
    "recover_armed_semantic_mutations",
    "SEMANTIC_MUTATION_LEDGER_NAME",
    "semantic_mutation_authority_digest",
    "semantic_mutation_events",
    "semantic_dependency_invalidation_plan",
    "semantic_import_authority_from_snapshot",
    "semantic_input_prebind_producer_authority_issues",
    "semantic_input_producer_authority_issues",
    "stored_committed_work_unit_authority_issues",
    "complete_driver_successor_step",
    "commit_immutable_generation_selection",
    "compare_and_swap_artifact_ledger",
    "validate_driver_successor_transaction",
    "validate_work_unit_artifacts",
    "validate_work_unit_explicit_absence_bindings",
    "validate_work_unit_inputs",
    "write_artifact_ledger",
]
