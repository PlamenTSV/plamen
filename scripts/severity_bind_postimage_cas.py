"""Immutable raw postimages for severity successor crash recovery.

This store is not execution, PhaseIO, or successor authority.  A caller first
derives and plans an exact severity-bind vector, seals its raw bytes here, and
then binds the returned reference into the work unit's immutable
pre-execution authority before any public output is changed.  Resume may load
only the exact stored vector selected by that authority and successor plan.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
from typing import Any, Mapping

from artifact_ledger import ArtifactLedgerError
from phase_io_contracts import DriverSuccessorPlan
import rooted_path_io as rio


CAS_DIRECTORY = "_severity_bind_postimage_cas"
REFERENCE_SCHEMA = "plamen.severity-bind-postimage-cas-reference.v1"
MANIFEST_SCHEMA = "plamen.severity-bind-postimage-cas-manifest.v1"
MAX_OBJECT_BYTES = 32 * 1024 * 1024
MAX_VECTOR_BYTES = 64 * 1024 * 1024
MAX_CAS_ENTRIES = 4096
_HEX64 = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
_BLOB = re.compile(r"^[0-9a-f]{64}\.blob$", re.ASCII)
_MANIFEST = re.compile(r"^[0-9a-f]{64}\.json$", re.ASCII)
_STAGE = re.compile(r"^\.plamen-write-once-[0-9a-f]{64}\.stage$", re.ASCII)
_ABANDONED = re.compile(
    r"^\.plamen-write-once-[0-9a-f]{64}\.stage\.abandoned$", re.ASCII,
)


def _canonical(value: Mapping[str, Any]) -> bytes:
    return json.dumps(
        dict(value), ensure_ascii=False, allow_nan=False,
        sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _strict_object(raw: bytes, *, label: str) -> dict[str, Any]:
    def pairs(rows: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in rows:
            if key in result:
                raise ArtifactLedgerError(f"{label} has duplicate key {key!r}")
            result[key] = value
        return result

    def constant(token: str) -> None:
        raise ArtifactLedgerError(f"{label} has non-finite value {token!r}")

    try:
        value = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=pairs, parse_constant=constant,
        )
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise ArtifactLedgerError(f"{label} is invalid JSON") from exc
    if not isinstance(value, dict) or _canonical(value) != raw:
        raise ArtifactLedgerError(f"{label} is not canonical JSON")
    return value


def _digest(value: Mapping[str, Any]) -> str:
    return _sha(_canonical(value))


def _cas_root(
    scratchpad: Path, *, create: bool,
    allowed_stages: frozenset[str] = frozenset(),
) -> tuple[Path, frozenset[str]]:
    root = rio.checked_directory(scratchpad, label="severity bind CAS scratchpad")
    directory = root / CAS_DIRECTORY
    try:
        if create:
            rio.ensure_directory(
                directory, parents=False, mode=0o700,
                label="severity bind postimage CAS directory",
            )
        directory = rio.checked_directory(
            directory, label="severity bind postimage CAS directory",
        )
        names: set[str] = set()
        folded: set[str] = set()
        with rio.scandir(directory) as entries:
            for entry in entries:
                name = entry.name
                names.add(name)
                folded.add(name.casefold())
                if len(names) > MAX_CAS_ENTRIES:
                    raise ArtifactLedgerError(
                        "severity bind postimage CAS is unbounded"
                    )
    except (OSError, rio.RootedPathIOError) as exc:
        raise ArtifactLedgerError(
            f"severity bind postimage CAS is unavailable: {exc}"
        ) from exc
    if (
        any(_STAGE.fullmatch(name) is None for name in allowed_stages)
        or len(names) != len(folded)
        or any(
            _BLOB.fullmatch(name) is None
            and _MANIFEST.fullmatch(name) is None
            and _ABANDONED.fullmatch(name) is None
            and name not in allowed_stages
            for name in names
        )
    ):
        raise ArtifactLedgerError(
            "severity bind postimage CAS census is malformed"
        )
    _validate_entry_metadata(directory, frozenset(names))
    return directory, frozenset(names)


def _durable_stage_name(final_name: str, raw: bytes) -> str:
    """Derive rooted_path_io's exact public write-once recovery stage name."""

    token = hashlib.sha256(os.fsencode(final_name) + b"\x00" + raw).hexdigest()
    return f".plamen-write-once-{token}.stage"


def _validate_entry_metadata(
    directory: Path, names: frozenset[str],
) -> None:
    """Bound every CAS name to one private file without adopting peer bytes."""

    for name in sorted(names):
        try:
            row = rio.lstat(directory / name)
        except OSError as exc:
            raise ArtifactLedgerError(
                "severity bind CAS entry is unavailable"
            ) from exc
        if (
            not stat.S_ISREG(row.st_mode)
            or int(getattr(row, "st_nlink", 1) or 1) != 1
            or int(getattr(row, "st_uid", os.geteuid())) != os.geteuid()
            or stat.S_IMODE(row.st_mode) != 0o600
        ):
            raise ArtifactLedgerError(
                "severity bind CAS entry lacks private ownership"
            )


def _validate_current_witnesses(
    directory: Path, names: frozenset[str], payloads: Mapping[str, bytes],
) -> None:
    """Authenticate witnesses for this exact vector, without reading peers."""

    for final_name, raw in payloads.items():
        witness = f"{_durable_stage_name(final_name, raw)}.abandoned"
        if witness in names and _read_exact(
            directory / witness, label="severity bind retained CAS witness",
            limit=MAX_OBJECT_BYTES,
        ) != raw:
            raise ArtifactLedgerError(
                "severity bind retained CAS witness differs from current vector"
            )


def _plan_rows(
    plan: DriverSuccessorPlan, output_bytes: Mapping[str, bytes] | None = None,
) -> list[dict[str, Any]]:
    if type(plan) is not DriverSuccessorPlan:
        raise ArtifactLedgerError("severity bind postimage plan type is invalid")
    if _HEX64.fullmatch(str(plan.digest or "")) is None:
        raise ArtifactLedgerError("severity bind postimage plan digest is invalid")
    transitions = tuple(plan.transitions)
    if len(transitions) != 3:
        raise ArtifactLedgerError("severity bind postimage denominator is not three")
    identities = tuple(row.artifact_identity for row in transitions)
    if len(set(identities)) != 3:
        raise ArtifactLedgerError("severity bind postimage identities are duplicate")
    supplied = dict(output_bytes) if output_bytes is not None else None
    if supplied is not None and set(supplied) != set(identities):
        raise ArtifactLedgerError("severity bind postimage byte denominator differs")
    rows: list[dict[str, Any]] = []
    total = 0
    for expected_ordinal, transition in enumerate(transitions, 1):
        identity = transition.artifact_identity
        digest = str(transition.after_sha256 or "")
        size = transition.after_size
        if (
            transition.ordinal != expected_ordinal
            or not isinstance(identity, str) or not identity.startswith("scratchpad:")
            or _HEX64.fullmatch(digest) is None
            or not isinstance(size, int) or isinstance(size, bool)
            or size < 0 or size > MAX_OBJECT_BYTES
        ):
            raise ArtifactLedgerError("severity bind postimage transition is invalid")
        if supplied is not None:
            raw = supplied.get(identity)
            if type(raw) is not bytes or len(raw) != size or _sha(raw) != digest:
                raise ArtifactLedgerError(
                    f"severity bind postimage bytes differ from plan: {identity}"
                )
        total += size
        rows.append({
            "ordinal": expected_ordinal,
            "artifact_identity": identity,
            "sha256": digest,
            "size": size,
            "blob": f"{digest}.blob",
        })
    if total > MAX_VECTOR_BYTES:
        raise ArtifactLedgerError("severity bind postimage vector is unbounded")
    return rows


def _manifest(
    *, run_id: str, work_unit_key: str, plan: DriverSuccessorPlan,
    invocation_digest: str, rows: list[dict[str, Any]],
) -> dict[str, Any]:
    if (
        not isinstance(run_id, str) or not run_id or run_id != run_id.strip()
        or not isinstance(work_unit_key, str) or not work_unit_key
        or work_unit_key != work_unit_key.strip()
        or _HEX64.fullmatch(invocation_digest) is None
        or plan.run_id != run_id or plan.work_unit_key != work_unit_key
    ):
        raise ArtifactLedgerError("severity bind postimage authority is invalid")
    return {
        "schema": MANIFEST_SCHEMA,
        "state": "SEALED_BEFORE_ARM",
        "run_id": run_id,
        "work_unit_key": work_unit_key,
        "plan_digest": plan.digest,
        "invocation_digest": invocation_digest,
        "object_count": len(rows),
        "total_size": sum(int(row["size"]) for row in rows),
        "objects": rows,
    }


def _reference(manifest: Mapping[str, Any]) -> dict[str, Any]:
    transaction_key = _digest({
        key: manifest[key]
        for key in ("run_id", "work_unit_key", "plan_digest", "invocation_digest")
    })
    unsigned = {
        "schema": REFERENCE_SCHEMA,
        "transaction_key": transaction_key,
        "manifest_file": f"{transaction_key}.json",
        "manifest_sha256": _digest(manifest),
        "plan_digest": manifest["plan_digest"],
        "invocation_digest": manifest["invocation_digest"],
        "object_count": manifest["object_count"],
        "total_size": manifest["total_size"],
    }
    return {**unsigned, "reference_sha256": _digest(unsigned)}


def _read_exact(path: Path, *, label: str, limit: int) -> bytes:
    try:
        return rio.read_bytes(
            path, label=label, max_bytes=limit, require_single_link=True,
        )
    except (OSError, rio.RootedPathIOError) as exc:
        raise ArtifactLedgerError(f"{label} is unavailable: {exc}") from exc


def seal_severity_bind_postimages(
    scratchpad: Path, *, run_id: str, work_unit_key: str,
    plan: DriverSuccessorPlan, invocation_digest: str,
    output_bytes: Mapping[str, bytes],
) -> Mapping[str, Any]:
    """Write the exact pre-arm vector once and return its immutable reference."""

    rows = _plan_rows(plan, output_bytes)
    manifest = _manifest(
        run_id=run_id, work_unit_key=work_unit_key, plan=plan,
        invocation_digest=invocation_digest, rows=rows,
    )
    reference = _reference(manifest)
    manifest_raw = _canonical(manifest)
    expected_payloads = {
        **{
            str(row["blob"]): output_bytes[row["artifact_identity"]]
            for row in rows
        },
        str(reference["manifest_file"]): manifest_raw,
    }
    allowed_stages = frozenset(
        _durable_stage_name(name, raw)
        for name, raw in expected_payloads.items()
    )
    possible_witnesses = {
        f"{_durable_stage_name(name, raw)}.abandoned"
        for name, raw in expected_payloads.items()
    }
    directory, names = _cas_root(
        Path(scratchpad), create=True, allowed_stages=allowed_stages,
    )
    _validate_current_witnesses(directory, names, expected_payloads)
    required_names = {
        *(str(row["blob"]) for row in rows),
        str(reference["manifest_file"]),
    }
    if len(names | required_names | possible_witnesses) > MAX_CAS_ENTRIES:
        raise ArtifactLedgerError(
            "severity bind postimage CAS has no capacity for the exact vector"
        )
    try:
        for row in rows:
            raw = output_bytes[row["artifact_identity"]]
            rio.durable_write_once_bytes(directory / row["blob"], raw)
            if _read_exact(
                directory / row["blob"], label="severity bind postimage blob",
                limit=MAX_OBJECT_BYTES,
            ) != raw:
                raise ArtifactLedgerError("severity bind postimage blob changed")
        rio.durable_write_once_bytes(
            directory / reference["manifest_file"], manifest_raw,
        )
    except (OSError, rio.RootedPathIOError) as exc:
        raise ArtifactLedgerError(
            f"severity bind postimage CAS publication failed: {exc}"
        ) from exc
    _directory, final_names = _cas_root(Path(scratchpad), create=False)
    _validate_current_witnesses(directory, final_names, expected_payloads)
    replay = load_severity_bind_postimages(
        Path(scratchpad), reference=reference, plan=plan,
        invocation_digest=invocation_digest,
    )
    if replay != dict(output_bytes):
        raise ArtifactLedgerError("severity bind postimage CAS did not replay")
    return reference


def load_severity_bind_postimages(
    scratchpad: Path, *, reference: Any, plan: DriverSuccessorPlan,
    invocation_digest: str,
) -> Mapping[str, bytes]:
    """Load only the exact vector bound by a stored arm and successor plan."""

    if not isinstance(reference, Mapping):
        raise ArtifactLedgerError("severity bind postimage reference is absent")
    fields = {
        "schema", "transaction_key", "manifest_file", "manifest_sha256",
        "plan_digest", "invocation_digest", "object_count", "total_size",
        "reference_sha256",
    }
    if set(reference) != fields:
        raise ArtifactLedgerError("severity bind postimage reference is malformed")
    unsigned = dict(reference)
    self_digest = unsigned.pop("reference_sha256")
    transaction_key = str(reference.get("transaction_key") or "")
    if (
        reference.get("schema") != REFERENCE_SCHEMA
        or self_digest != _digest(unsigned)
        or _HEX64.fullmatch(transaction_key) is None
        or reference.get("manifest_file") != f"{transaction_key}.json"
        or reference.get("plan_digest") != plan.digest
        or reference.get("invocation_digest") != invocation_digest
    ):
        raise ArtifactLedgerError("severity bind postimage reference differs")
    expected_rows = _plan_rows(plan)
    directory, names = _cas_root(Path(scratchpad), create=False)
    manifest_raw = _read_exact(
        directory / str(reference["manifest_file"]),
        label="severity bind postimage manifest", limit=256 * 1024,
    )
    if _sha(manifest_raw) != reference.get("manifest_sha256"):
        raise ArtifactLedgerError("severity bind postimage manifest digest differs")
    manifest = _strict_object(manifest_raw, label="severity bind postimage manifest")
    expected_manifest = _manifest(
        run_id=plan.run_id, work_unit_key=plan.work_unit_key, plan=plan,
        invocation_digest=invocation_digest, rows=expected_rows,
    )
    if manifest != expected_manifest or _reference(manifest) != dict(reference):
        raise ArtifactLedgerError("severity bind postimage manifest differs from plan")
    loaded: dict[str, bytes] = {}
    current_payloads = {str(reference["manifest_file"]): manifest_raw}
    for row in expected_rows:
        raw = _read_exact(
            directory / row["blob"], label="severity bind postimage blob",
            limit=MAX_OBJECT_BYTES,
        )
        if len(raw) != row["size"] or _sha(raw) != row["sha256"]:
            raise ArtifactLedgerError("severity bind postimage blob differs from plan")
        loaded[row["artifact_identity"]] = raw
        current_payloads[str(row["blob"])] = raw
    _validate_current_witnesses(directory, names, current_payloads)
    return loaded


__all__ = [
    "CAS_DIRECTORY", "MAX_CAS_ENTRIES", "MAX_OBJECT_BYTES", "MAX_VECTOR_BYTES",
    "load_severity_bind_postimages", "seal_severity_bind_postimages",
]
