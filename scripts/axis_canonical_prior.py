"""Immutable PRE_AXIS canonical-prior capture for P0-I.

The ordinary ``_canonical_finding_ids.json`` projection is intentionally
mutable: later phases refresh it as new candidates enter the pipeline.  A
disposition that cites prior work needs a historical pre-model authority
instead.  This module captures that authority once, binds it to one run and
worklist, and replays it solely from its two immutable files.

It does not decide whether an axis item is safe.  It only supplies exact
canonical identity aliases to the independent disposition reconciler.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
from typing import Any, Mapping, Sequence
import uuid

from bounded_artifact_io import read_bounded_regular_bytes
from exploration_clear_lifecycle import _canonical_alias_projection
from finding_producer_registry import (
    ProducerResolutionError,
    producer_for_artifact,
    read_registered_typed_actions,
)


SNAPSHOT_NAME = "axis_canonical_prior_snapshot.json"
AUTHORITY_NAME = "axis_canonical_prior_authority.json"
SNAPSHOT_SCHEMA = "plamen.axis_canonical_prior_snapshot.v1"
AUTHORITY_SCHEMA = "plamen.axis_canonical_prior_authority.v1"
CAPTURE_BOUNDARY = "PRE_AXIS_MODEL"

_MAX_SOURCE_BYTES = 64 * 1024 * 1024
_MAX_AUTHORITY_BYTES = 128 * 1024 * 1024
_HEX_RE = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
_CID_RE = re.compile(r"^CID-[A-F0-9]{16}$", re.ASCII)
_COMPONENT_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$", re.ASCII)
_AXIS_EXECUTION_ARTIFACTS = frozenset(
    {
        "axis_coverage_findings.md",
        "axis_coverage_dispositions.json",
        "axis_disposition_initial_receipt.json",
        "axis_repair_plan.json",
        "axis_coverage_repair_findings.md",
        "axis_coverage_repair_dispositions.json",
        "axis_repair_execution_receipt.json",
        "axis_disposition_receipt.json",
        "axis_repair_work.json",
        "axis_assurance_debt.json",
        "axis_assurance_limitations.md",
        "axis_coverage_promotion_receipt.json",
    }
)


class AxisCanonicalPriorError(ValueError):
    """The frozen PRE_AXIS identity authority cannot be trusted."""


@dataclass(frozen=True)
class AxisCanonicalPriorAuthority:
    status: str
    aliases: dict[str, str]
    ambiguous_aliases: dict[str, tuple[str, ...]]
    debt: tuple[str, ...]
    authority_digest: str
    snapshot_digest: str
    snapshot: dict[str, Any]
    payload: dict[str, Any]


def _canonical_json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical_json_bytes(value)).hexdigest()


def _file_bytes(payload: Mapping[str, Any]) -> bytes:
    return (
        json.dumps(
            dict(payload),
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            indent=2,
        )
        + "\n"
    ).encode("utf-8")


def _binding_component(value: str, label: str) -> str:
    normalized = str(value or "").strip().lower()
    if _COMPONENT_RE.fullmatch(normalized) is None:
        raise AxisCanonicalPriorError(
            f"axis canonical-prior {label} binding is invalid"
        )
    return normalized


def _run_binding(value: str) -> str:
    normalized = str(value or "").strip()
    if not normalized or len(normalized) > 256:
        raise AxisCanonicalPriorError(
            "axis canonical-prior run binding is invalid"
        )
    return normalized


def _worklist_binding(value: str) -> str:
    normalized = str(value or "").strip().lower()
    if _HEX_RE.fullmatch(normalized) is None:
        raise AxisCanonicalPriorError(
            "axis canonical-prior worklist binding is invalid"
        )
    return normalized


def _read_json_file(path: Path, *, label: str) -> tuple[bytes, dict[str, Any]]:
    try:
        raw = read_bounded_regular_bytes(path, _MAX_AUTHORITY_BYTES)
        payload = json.loads(raw.decode("utf-8", errors="strict"))
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise AxisCanonicalPriorError(
            f"{label} is unavailable or invalid: {exc}"
        ) from exc
    if not isinstance(payload, dict):
        raise AxisCanonicalPriorError(f"{label} root is not an object")
    return raw, payload


def _atomic_create_or_equal(path: Path, raw: bytes) -> None:
    """Create one immutable file, or prove an existing file is byte-identical."""

    target = Path(path)
    if target.exists() or target.is_symlink():
        try:
            current = read_bounded_regular_bytes(
                target, max(_MAX_AUTHORITY_BYTES, len(raw))
            )
        except (OSError, ValueError) as exc:
            raise AxisCanonicalPriorError(
                f"immutable authority path is invalid: {target.name}: {exc}"
            ) from exc
        if current != raw:
            raise AxisCanonicalPriorError(
                f"immutable authority already exists with different bytes: "
                f"{target.name}"
            )
        return

    temporary = target.with_name(f".{target.name}.{uuid.uuid4().hex}.tmp")
    try:
        with temporary.open("xb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        # Do not let a concurrent or preplanted authority get overwritten.
        if target.exists() or target.is_symlink():
            current = read_bounded_regular_bytes(
                target, max(_MAX_AUTHORITY_BYTES, len(raw))
            )
            if current != raw:
                raise AxisCanonicalPriorError(
                    f"immutable authority appeared with different bytes: "
                    f"{target.name}"
                )
            return
        os.replace(temporary, target)
    finally:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass


def _safe_direct_source(root: Path, raw_path: Path) -> tuple[Path, str]:
    candidate = Path(raw_path)
    if not candidate.is_absolute():
        candidate = root / candidate
    try:
        if candidate.is_symlink():
            raise AxisCanonicalPriorError(
                f"axis canonical-prior source is a link: {candidate.name}"
            )
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise AxisCanonicalPriorError(
            f"axis canonical-prior source path is unavailable: "
            f"{candidate.name}"
        ) from exc
    if resolved.parent != root:
        raise AxisCanonicalPriorError(
            "axis canonical-prior source is not a direct scratchpad artifact"
        )
    return resolved, resolved.name


def _source_paths(
    root: Path,
    explicit: Sequence[str | Path] | None,
) -> tuple[tuple[Path, str], ...]:
    if explicit is None:
        # Import lazily so the substrate can be loaded by the driver without
        # forming an import cycle through the large mechanical facade.
        import plamen_mechanical

        candidates: Sequence[str | Path] = (
            plamen_mechanical._producer_artifact_paths_for_identity(root)
        )
    else:
        candidates = explicit
    by_name: dict[str, tuple[Path, str]] = {}
    for raw in candidates:
        resolved, relative = _safe_direct_source(root, Path(raw))
        key = relative.casefold()
        prior = by_name.get(key)
        if prior is not None and prior[0] != resolved:
            raise AxisCanonicalPriorError(
                "axis canonical-prior source names are ambiguous"
            )
        by_name[key] = (resolved, relative)
    return tuple(
        by_name[key]
        for key in sorted(
            by_name,
            key=lambda value: (value, by_name[value][1]),
        )
    )


def _capture_source(
    path: Path,
    relative: str,
) -> tuple[dict[str, Any], list[dict[str, Any]], str]:
    raw: bytes | None = None
    try:
        raw = read_bounded_regular_bytes(path, _MAX_SOURCE_BYTES)
    except (OSError, ValueError) as exc:
        issue = f"SOURCE_READ_FAILED:{relative}:{type(exc).__name__}"
        return (
            {
                "relative_path": relative,
                "capture_state": "UNAVAILABLE",
                "sha256": "",
                "size_bytes": -1,
                "issue": issue,
            },
            [],
            issue,
        )

    sha = hashlib.sha256(raw).hexdigest()
    manifest = {
        "relative_path": relative,
        "capture_state": "CAPTURED",
        "sha256": sha,
        "size_bytes": len(raw),
        "issue": "",
    }
    try:
        producer = producer_for_artifact(
            relative, consumer="canonical_identity"
        )
        if producer is not None and getattr(
            producer, "artifact_format", "MARKDOWN_FINDINGS"
        ) != "MARKDOWN_FINDINGS":
            # The mechanical projection deliberately degrades malformed typed
            # producers to zero rows. Capture must expose that condition.
            read_registered_typed_actions(
                path, consumer="canonical_identity"
            )
        else:
            raw.decode("utf-8", errors="strict")

        import plamen_mechanical

        records = plamen_mechanical._canonical_identity_records_from_artifact(
            path
        )
        if not isinstance(records, list):
            raise TypeError("identity projection is not a list")
        return manifest, [dict(row) for row in records], ""
    except UnicodeError:
        issue = f"SOURCE_UTF8_INVALID:{relative}"
    except ProducerResolutionError:
        issue = f"SOURCE_PRODUCER_AMBIGUOUS:{relative}"
    except Exception as exc:
        issue = f"SOURCE_PROJECTION_FAILED:{relative}:{type(exc).__name__}"
    return (
        {
            **manifest,
            "capture_state": "UNAVAILABLE",
            "issue": issue,
        },
        [],
        issue,
    )


def _validate_source_manifest(
    value: Any,
) -> tuple[list[dict[str, Any]], set[str]]:
    if not isinstance(value, list):
        raise AxisCanonicalPriorError(
            "axis canonical-prior source manifest is not an array"
        )
    rows: list[dict[str, Any]] = []
    captured: set[str] = set()
    seen: set[str] = set()
    required = {
        "relative_path",
        "capture_state",
        "sha256",
        "size_bytes",
        "issue",
    }
    for index, raw in enumerate(value):
        if not isinstance(raw, Mapping) or set(raw) != required:
            raise AxisCanonicalPriorError(
                f"axis canonical-prior source row {index} shape mismatch"
            )
        relative = str(raw.get("relative_path") or "")
        if (
            not relative
            or Path(relative).name != relative
            or "/" in relative
            or "\\" in relative
            or relative.casefold() in seen
        ):
            raise AxisCanonicalPriorError(
                f"axis canonical-prior source row {index} path is invalid"
            )
        seen.add(relative.casefold())
        state = str(raw.get("capture_state") or "")
        sha = str(raw.get("sha256") or "")
        size = raw.get("size_bytes")
        issue = str(raw.get("issue") or "")
        if type(size) is not int:
            raise AxisCanonicalPriorError(
                f"axis canonical-prior source row {index} size is invalid"
            )
        if state == "CAPTURED":
            if _HEX_RE.fullmatch(sha) is None or size < 0 or issue:
                raise AxisCanonicalPriorError(
                    f"axis canonical-prior source row {index} capture is invalid"
                )
            captured.add(relative)
        elif state == "UNAVAILABLE":
            if (sha and _HEX_RE.fullmatch(sha) is None) or size < -1 or not issue:
                raise AxisCanonicalPriorError(
                    f"axis canonical-prior source row {index} debt is invalid"
                )
        else:
            raise AxisCanonicalPriorError(
                f"axis canonical-prior source row {index} state is invalid"
            )
        rows.append(dict(raw))
    expected_order = sorted(
        rows, key=lambda row: (str(row["relative_path"]).casefold(), row["relative_path"])
    )
    if rows != expected_order:
        raise AxisCanonicalPriorError(
            "axis canonical-prior source manifest order is not canonical"
        )
    return rows, captured


def _validate_records(
    value: Any,
    *,
    captured_sources: set[str],
) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise AxisCanonicalPriorError(
            "axis canonical-prior records are not an array"
        )
    records: list[dict[str, Any]] = []
    seen: set[bytes] = set()
    for index, raw in enumerate(value):
        if not isinstance(raw, Mapping):
            raise AxisCanonicalPriorError(
                f"axis canonical-prior record {index} is malformed"
            )
        required = ("canonical_id", "artifact", "local_id", "local_id_raw")
        if any(not isinstance(raw.get(key), str) for key in required):
            raise AxisCanonicalPriorError(
                f"axis canonical-prior record {index} field types are invalid"
            )
        canonical = str(raw["canonical_id"])
        artifact = str(raw["artifact"])
        if (
            _CID_RE.fullmatch(canonical) is None
            or artifact not in captured_sources
            or Path(artifact).name != artifact
            or not str(raw["local_id"]).strip()
            or not str(raw["local_id_raw"]).strip()
        ):
            raise AxisCanonicalPriorError(
                f"axis canonical-prior record {index} is not authority-shaped"
            )
        encoded = _canonical_json_bytes(dict(raw))
        if encoded in seen:
            raise AxisCanonicalPriorError(
                f"axis canonical-prior record {index} is duplicated"
            )
        seen.add(encoded)
        records.append(dict(raw))
    expected_order = sorted(
        records,
        key=lambda row: (
            str(row.get("artifact")),
            int(row.get("offset") or 0),
            str(row.get("local_id")),
        ),
    )
    if records != expected_order:
        raise AxisCanonicalPriorError(
            "axis canonical-prior record order is not canonical"
        )
    return records


def _validate_snapshot(
    payload: Mapping[str, Any],
    *,
    expected_run_id: str,
    expected_worklist_hash: str,
    expected_pipeline: str,
    expected_mode: str,
    expected_ecosystem: str,
) -> dict[str, Any]:
    required = {
        "schema_version",
        "run_id",
        "worklist_hash",
        "pipeline",
        "mode",
        "ecosystem",
        "capture_boundary",
        "source_artifacts",
        "record_count",
        "records",
        "capture_issues",
        "snapshot_status",
        "snapshot_digest",
    }
    candidate = dict(payload)
    if (
        set(candidate) != required
        or candidate.get("schema_version") != SNAPSHOT_SCHEMA
        or candidate.get("capture_boundary") != CAPTURE_BOUNDARY
    ):
        raise AxisCanonicalPriorError(
            "axis canonical-prior snapshot schema/key mismatch"
        )
    bindings = {
        "run_id": _run_binding(expected_run_id),
        "worklist_hash": _worklist_binding(expected_worklist_hash),
        "pipeline": _binding_component(expected_pipeline, "pipeline"),
        "mode": _binding_component(expected_mode, "mode"),
        "ecosystem": _binding_component(expected_ecosystem, "ecosystem"),
    }
    if any(candidate.get(key) != value for key, value in bindings.items()):
        raise AxisCanonicalPriorError(
            "axis canonical-prior snapshot binding mismatch"
        )
    unsigned = {
        key: value for key, value in candidate.items()
        if key != "snapshot_digest"
    }
    if candidate.get("snapshot_digest") != _digest(unsigned):
        raise AxisCanonicalPriorError(
            "axis canonical-prior snapshot digest mismatch"
        )
    _manifest, captured = _validate_source_manifest(
        candidate.get("source_artifacts")
    )
    records = _validate_records(
        candidate.get("records"), captured_sources=captured
    )
    if candidate.get("record_count") != len(records):
        raise AxisCanonicalPriorError(
            "axis canonical-prior snapshot record denominator mismatch"
        )
    issues = candidate.get("capture_issues")
    if (
        not isinstance(issues, list)
        or any(not isinstance(issue, str) or not issue for issue in issues)
        or issues != sorted(set(issues))
    ):
        raise AxisCanonicalPriorError(
            "axis canonical-prior snapshot issue ledger is invalid"
        )
    expected_status = "DEGRADED" if issues else "EXACT"
    if candidate.get("snapshot_status") != expected_status:
        raise AxisCanonicalPriorError(
            "axis canonical-prior snapshot status is not monotonic"
        )
    manifest_issues = sorted(
        str(row["issue"])
        for row in candidate["source_artifacts"]
        if row["capture_state"] == "UNAVAILABLE"
    )
    if manifest_issues != issues:
        raise AxisCanonicalPriorError(
            "axis canonical-prior snapshot debt differs from its manifest"
        )
    return candidate


def _build_authority(snapshot: Mapping[str, Any], snapshot_raw: bytes) -> dict[str, Any]:
    status = str(snapshot["snapshot_status"])
    if status == "EXACT":
        aliases, ambiguous = _canonical_alias_projection(snapshot["records"])
    else:
        aliases, ambiguous = {}, {}
    unsigned = {
        "schema_version": AUTHORITY_SCHEMA,
        "run_id": snapshot["run_id"],
        "worklist_hash": snapshot["worklist_hash"],
        "pipeline": snapshot["pipeline"],
        "mode": snapshot["mode"],
        "ecosystem": snapshot["ecosystem"],
        "capture_boundary": CAPTURE_BOUNDARY,
        "snapshot_artifact": SNAPSHOT_NAME,
        "snapshot_sha256": hashlib.sha256(snapshot_raw).hexdigest(),
        "snapshot_digest": snapshot["snapshot_digest"],
        "status": status,
        "aliases": dict(sorted(aliases.items())),
        "ambiguous_short_aliases": {
            key: list(values) for key, values in sorted(ambiguous.items())
        },
        "authority_debt": list(snapshot["capture_issues"]),
    }
    return {**unsigned, "authority_digest": _digest(unsigned)}


def _validated_authority(
    payload: Mapping[str, Any],
    *,
    snapshot: Mapping[str, Any],
    snapshot_raw: bytes,
) -> AxisCanonicalPriorAuthority:
    required = {
        "schema_version",
        "run_id",
        "worklist_hash",
        "pipeline",
        "mode",
        "ecosystem",
        "capture_boundary",
        "snapshot_artifact",
        "snapshot_sha256",
        "snapshot_digest",
        "status",
        "aliases",
        "ambiguous_short_aliases",
        "authority_debt",
        "authority_digest",
    }
    candidate = dict(payload)
    if (
        set(candidate) != required
        or candidate.get("schema_version") != AUTHORITY_SCHEMA
        or candidate.get("capture_boundary") != CAPTURE_BOUNDARY
        or candidate.get("snapshot_artifact") != SNAPSHOT_NAME
    ):
        raise AxisCanonicalPriorError(
            "axis canonical-prior authority schema/key mismatch"
        )
    unsigned = {
        key: value for key, value in candidate.items()
        if key != "authority_digest"
    }
    if candidate.get("authority_digest") != _digest(unsigned):
        raise AxisCanonicalPriorError(
            "axis canonical-prior authority digest mismatch"
        )
    expected = _build_authority(snapshot, snapshot_raw)
    if candidate != expected:
        raise AxisCanonicalPriorError(
            "axis canonical-prior authority differs from snapshot replay"
        )
    aliases = candidate.get("aliases")
    ambiguous = candidate.get("ambiguous_short_aliases")
    if not isinstance(aliases, dict) or not isinstance(ambiguous, dict):
        raise AxisCanonicalPriorError(
            "axis canonical-prior alias projection is malformed"
        )
    ambiguous_tuples: dict[str, tuple[str, ...]] = {}
    for key, values in ambiguous.items():
        if (
            not isinstance(key, str)
            or not isinstance(values, list)
            or len(values) < 2
            or any(not isinstance(value, str) for value in values)
            or values != sorted(set(values))
        ):
            raise AxisCanonicalPriorError(
                "axis canonical-prior ambiguous alias projection is malformed"
            )
        ambiguous_tuples[key] = tuple(values)
    return AxisCanonicalPriorAuthority(
        status=str(candidate["status"]),
        aliases={str(key): str(value) for key, value in aliases.items()},
        ambiguous_aliases=ambiguous_tuples,
        debt=tuple(str(value) for value in candidate["authority_debt"]),
        authority_digest=str(candidate["authority_digest"]),
        snapshot_digest=str(candidate["snapshot_digest"]),
        snapshot=dict(snapshot),
        payload=candidate,
    )


def load_axis_canonical_prior_authority(
    scratchpad: str | Path,
    *,
    expected_run_id: str,
    expected_worklist_hash: str,
    expected_pipeline: str,
    expected_mode: str,
    expected_ecosystem: str,
) -> AxisCanonicalPriorAuthority:
    """Replay the authority without consulting any mutable global projection."""

    root = Path(scratchpad).resolve(strict=True)
    snapshot_raw, snapshot_payload = _read_json_file(
        root / SNAPSHOT_NAME, label="axis canonical-prior snapshot"
    )
    snapshot = _validate_snapshot(
        snapshot_payload,
        expected_run_id=expected_run_id,
        expected_worklist_hash=expected_worklist_hash,
        expected_pipeline=expected_pipeline,
        expected_mode=expected_mode,
        expected_ecosystem=expected_ecosystem,
    )
    _authority_raw, authority_payload = _read_json_file(
        root / AUTHORITY_NAME, label="axis canonical-prior authority"
    )
    return _validated_authority(
        authority_payload,
        snapshot=snapshot,
        snapshot_raw=snapshot_raw,
    )


def _build_snapshot(
    root: Path,
    *,
    run_id: str,
    worklist_hash: str,
    pipeline: str,
    mode: str,
    ecosystem: str,
    source_paths: Sequence[str | Path] | None,
) -> dict[str, Any]:
    manifest: list[dict[str, Any]] = []
    records: list[dict[str, Any]] = []
    issues: list[str] = []
    for path, relative in _source_paths(root, source_paths):
        source_row, source_records, issue = _capture_source(path, relative)
        manifest.append(source_row)
        records.extend(source_records)
        if issue:
            issues.append(issue)
    records.sort(
        key=lambda row: (
            str(row.get("artifact")),
            int(row.get("offset") or 0),
            str(row.get("local_id")),
        )
    )
    normalized_issues = sorted(set(issues))
    unsigned = {
        "schema_version": SNAPSHOT_SCHEMA,
        "run_id": _run_binding(run_id),
        "worklist_hash": _worklist_binding(worklist_hash),
        "pipeline": _binding_component(pipeline, "pipeline"),
        "mode": _binding_component(mode, "mode"),
        "ecosystem": _binding_component(ecosystem, "ecosystem"),
        "capture_boundary": CAPTURE_BOUNDARY,
        "source_artifacts": manifest,
        "record_count": len(records),
        "records": records,
        "capture_issues": normalized_issues,
        "snapshot_status": "DEGRADED" if normalized_issues else "EXACT",
    }
    return {**unsigned, "snapshot_digest": _digest(unsigned)}


def capture_axis_canonical_prior_authority(
    scratchpad: str | Path,
    *,
    run_id: str,
    worklist_hash: str,
    pipeline: str,
    mode: str,
    ecosystem: str,
    source_paths: Sequence[str | Path] | None = None,
) -> AxisCanonicalPriorAuthority:
    """Create or replay one immutable pre-model identity capture.

    A complete pair is always replayed, never regenerated. A snapshot-only
    crash can be completed only before any axis execution artifact exists.
    """

    root = Path(scratchpad).resolve(strict=True)
    snapshot_path = root / SNAPSHOT_NAME
    authority_path = root / AUTHORITY_NAME
    snapshot_exists = snapshot_path.exists() or snapshot_path.is_symlink()
    authority_exists = authority_path.exists() or authority_path.is_symlink()

    if snapshot_exists and authority_exists:
        return load_axis_canonical_prior_authority(
            root,
            expected_run_id=run_id,
            expected_worklist_hash=worklist_hash,
            expected_pipeline=pipeline,
            expected_mode=mode,
            expected_ecosystem=ecosystem,
        )

    execution_present = sorted(
        name for name in _AXIS_EXECUTION_ARTIFACTS
        if (root / name).exists() or (root / name).is_symlink()
    )
    if execution_present:
        detail = ", ".join(execution_present)
        if snapshot_exists or authority_exists:
            raise AxisCanonicalPriorError(
                "axis canonical-prior authority is partial after axis execution: "
                + detail
            )
        raise AxisCanonicalPriorError(
            "fresh axis canonical-prior capture refused after axis execution: "
            + detail
        )
    if authority_exists and not snapshot_exists:
        raise AxisCanonicalPriorError(
            "axis canonical-prior authority is partial: authority exists "
            "without its snapshot"
        )

    if snapshot_exists:
        snapshot_raw, snapshot_payload = _read_json_file(
            snapshot_path, label="axis canonical-prior snapshot"
        )
        snapshot = _validate_snapshot(
            snapshot_payload,
            expected_run_id=run_id,
            expected_worklist_hash=worklist_hash,
            expected_pipeline=pipeline,
            expected_mode=mode,
            expected_ecosystem=ecosystem,
        )
    else:
        snapshot = _build_snapshot(
            root,
            run_id=run_id,
            worklist_hash=worklist_hash,
            pipeline=pipeline,
            mode=mode,
            ecosystem=ecosystem,
            source_paths=source_paths,
        )
        snapshot_raw = _file_bytes(snapshot)
        _atomic_create_or_equal(snapshot_path, snapshot_raw)

    authority = _build_authority(snapshot, snapshot_raw)
    _atomic_create_or_equal(authority_path, _file_bytes(authority))
    return load_axis_canonical_prior_authority(
        root,
        expected_run_id=run_id,
        expected_worklist_hash=worklist_hash,
        expected_pipeline=pipeline,
        expected_mode=mode,
        expected_ecosystem=ecosystem,
    )


__all__ = [
    "AUTHORITY_NAME",
    "AUTHORITY_SCHEMA",
    "CAPTURE_BOUNDARY",
    "SNAPSHOT_NAME",
    "SNAPSHOT_SCHEMA",
    "AxisCanonicalPriorAuthority",
    "AxisCanonicalPriorError",
    "capture_axis_canonical_prior_authority",
    "load_axis_canonical_prior_authority",
]
