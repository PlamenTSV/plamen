"""Strict application-skeptic stdout schema and packet context.

This module is deliberately small and stable.  The execution provider binds the
entire file and the exact parser callable before launch, so unrelated edits to
the large driver cannot invalidate an otherwise resumable provider receipt.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any, Iterable, Mapping

from application_skeptic import (
    ASSESSMENT_SCHEMA,
    ApplicationSkepticError,
    read_bound_methodology_bytes,
)
from methodology_citation import MethodologyCitationResolver


CONTEXT_SCHEMA = "plamen.application_skeptic_packet_context.v1"
OUTCOMES = (
    "AGREE_NEGATIVE",
    "DISAGREE_CANDIDATE",
    "UNAVAILABLE",
    "INCONCLUSIVE",
)
DEFAULT_CONTEXT_LIMIT_BYTES = 16 * 1024 * 1024
MAX_CONTEXT_FILE_BYTES = 4 * 1024 * 1024


def _stable_file_bytes(path: Path, label: str) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise ApplicationSkepticError(f"{label} is unavailable or unsafe")
    try:
        with path.open("rb") as handle:
            before = os.fstat(handle.fileno())
            raw = handle.read()
            after = os.fstat(handle.fileno())
        current = path.stat()
    except OSError as exc:
        raise ApplicationSkepticError(f"{label} cannot be read stably") from exc
    first = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    second = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
    final = (current.st_dev, current.st_ino, current.st_size, current.st_mtime_ns)
    if first != second or second != final:
        raise ApplicationSkepticError(f"{label} changed during exact-byte capture")
    return raw


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ApplicationSkepticError(f"duplicate JSON key {key!r}")
        value[key] = item
    return value


def application_skeptic_stdout_digest(path: Path, raw: bytes) -> str:
    """Return the semantic digest of one strict UTF-8 JSON object.

    JSON-Schema validation is provider-owned and runs before this callback.
    This second parser preserves the consumer's duplicate-key/non-finite-number
    rules and produces a stable semantic digest rather than trusting raw bytes.
    """

    def decode(document: bytes, label: str) -> Any:
        try:
            return json.loads(
                document.decode("utf-8", errors="strict"),
                object_pairs_hook=_strict_object,
                parse_constant=lambda item: (_ for _ in ()).throw(
                    ApplicationSkepticError(
                        f"invalid JSON constant {item!r} in {label}"
                    )
                ),
            )
        except ApplicationSkepticError:
            raise
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise ApplicationSkepticError(f"invalid {label} JSON: {exc}") from exc

    if not path.is_file():
        raise ApplicationSkepticError("bound skeptic stdin packet is missing")
    packet = decode(path.read_bytes(), "skeptic stdin packet")
    if not isinstance(packet, dict) or packet.get("schema_version") != (
        "plamen.skeptic_execution_packet.v2"
    ):
        raise ApplicationSkepticError("bound skeptic stdin packet is invalid")
    try:
        value = decode(raw, "assessor stdout")
    except ApplicationSkepticError:
        raise
    if not isinstance(value, dict):
        raise ApplicationSkepticError("assessor stdout must be one JSON object")

    plan = packet.get("plan")
    shard = packet.get("shard")
    assessor = packet.get("assessor")
    if not all(isinstance(item, dict) for item in (plan, shard, assessor)):
        raise ApplicationSkepticError("skeptic packet bindings are incomplete")
    expected_ids = shard.get("work_item_ids")
    if (
        not isinstance(expected_ids, list)
        or not expected_ids
        or any(not isinstance(item, str) or not item for item in expected_ids)
        or len(set(expected_ids)) != len(expected_ids)
    ):
        raise ApplicationSkepticError("skeptic packet denominator is invalid")
    rows = value.get("assessments")
    if not isinstance(rows, list):
        raise ApplicationSkepticError("assessor stdout assessments must be an array")
    observed_ids = [
        row.get("work_item_id") if isinstance(row, dict) else None for row in rows
    ]
    if observed_ids != expected_ids:
        raise ApplicationSkepticError(
            "assessor stdout does not match the exact ordered work-item denominator"
        )
    if (
        value.get("work_plan_digest") != plan.get("work_plan_digest")
        or value.get("shard_id") != shard.get("shard_id")
    ):
        raise ApplicationSkepticError("assessor stdout plan/shard binding changed")
    for row in rows:
        if (
            row.get("assessor_id") != assessor.get("identity")
            or row.get("assessor_invocation_id") != assessor.get("invocation_id")
        ):
            raise ApplicationSkepticError(
                "assessor stdout principal binding changed"
            )
    canonical = json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _candidate_schema() -> dict[str, Any]:
    return {
        "type": "object",
        "additionalProperties": False,
        "required": ["title", "mechanism", "harm"],
        "properties": {
            "title": {"type": "string"},
            "mechanism": {"type": "string"},
            "harm": {"type": "string"},
        },
    }


def _assessment_row_branch(
    *,
    work_item_ids: list[str],
    assessor_id: str,
    assessor_invocation_id: str,
    outcomes: list[str],
    decisive: bool,
    candidate: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "work_item_id",
            "assessor_id",
            "assessor_invocation_id",
            "outcome",
            "evidence_basis",
            "evidence",
            "rationale",
            "candidate",
        ],
        "properties": {
            "work_item_id": {"enum": work_item_ids},
            "assessor_id": {"const": assessor_id},
            "assessor_invocation_id": {"const": assessor_invocation_id},
            "outcome": {"enum": outcomes},
            "evidence_basis": {"type": "string"},
            "evidence": {
                "type": "string",
                **({"minLength": 1} if decisive else {}),
            },
            "rationale": {"type": "string"},
            "candidate": dict(candidate),
        },
    }


def application_skeptic_output_schema(
    plan: Mapping[str, Any],
    shard: Mapping[str, Any],
    *,
    assessor_id: str,
    assessor_invocation_id: str,
) -> dict[str, Any]:
    """Build the strict wire schema accepted by Claude and the consumer.

    Claude CLI 2.1.214 rejects Draft 2020-12 ``prefixItems`` while Anthropic's
    API rejects the Draft-07 tuple form.  The wire schema therefore constrains
    row count, allowed identities, principals, and outcome shapes using their
    common subset.  :func:`application_skeptic_stdout_digest` enforces the exact
    ordered denominator from the immutable provider-bound packet before the
    provider may emit a completion receipt.
    """

    expected_ids = list(shard.get("work_item_ids") or [])
    allowed_ids = [str(work_item_id) for work_item_id in expected_ids]
    row = {
        "oneOf": [
            _assessment_row_branch(
                work_item_ids=allowed_ids,
                assessor_id=assessor_id,
                assessor_invocation_id=assessor_invocation_id,
                outcomes=["AGREE_NEGATIVE"],
                decisive=True,
                candidate={"type": "null"},
            ),
            _assessment_row_branch(
                work_item_ids=allowed_ids,
                assessor_id=assessor_id,
                assessor_invocation_id=assessor_invocation_id,
                outcomes=["DISAGREE_CANDIDATE"],
                decisive=True,
                candidate=_candidate_schema(),
            ),
            _assessment_row_branch(
                work_item_ids=allowed_ids,
                assessor_id=assessor_id,
                assessor_invocation_id=assessor_invocation_id,
                outcomes=["UNAVAILABLE", "INCONCLUSIVE"],
                decisive=False,
                candidate={"type": "null"},
            ),
        ]
    }
    return {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "schema_version",
            "work_plan_digest",
            "shard_id",
            "assessments",
        ],
        "properties": {
            "schema_version": {"const": ASSESSMENT_SCHEMA},
            "work_plan_digest": {"const": str(plan["work_plan_digest"])},
            "shard_id": {"const": str(shard["shard_id"])},
            "assessments": {
                "type": "array",
                "items": row,
                "minItems": len(allowed_ids),
                "maxItems": len(allowed_ids),
            },
        },
    }


def application_skeptic_packet_context(
    plan: Mapping[str, Any],
    shard: Mapping[str, Any],
    *,
    trusted_methodology_roots: Iterable[Path],
    project_root: Path | None = None,
    scratchpad: Path | None = None,
    max_context_bytes: int = DEFAULT_CONTEXT_LIMIT_BYTES,
) -> dict[str, Any]:
    """Embed assigned authority, methodology, and cited source bytes in stdin.

    A no-tool assessor cannot independently check a location-shaped claim from
    prose alone.  Every mechanically resolvable source citation therefore binds
    the complete cited file, while the exact typed source-queue artifacts bind
    the producer-side context.  Unresolved citations remain explicit debt; they
    are never silently treated as an empty/complete source universe.
    """

    if (
        isinstance(max_context_bytes, bool)
        or not isinstance(max_context_bytes, int)
        or max_context_bytes < 1
    ):
        raise ApplicationSkepticError("source context byte limit must be positive")

    by_id = {
        str(item.get("work_item_id")): item
        for item in (plan.get("work_items") or [])
        if isinstance(item, Mapping)
    }
    bound_items: list[dict[str, Any]] = []
    total_bytes = 0
    for work_item_id in list(shard.get("work_item_ids") or []):
        item = by_id.get(str(work_item_id))
        if item is None:
            raise ApplicationSkepticError(
                f"shard references unknown application-skeptic work {work_item_id!r}"
            )
        raw = read_bound_methodology_bytes(item, trusted_methodology_roots)
        total_bytes += len(raw)
        try:
            methodology = raw.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise ApplicationSkepticError(
                f"bound methodology for {work_item_id} is not UTF-8"
            ) from exc
        bound_items.append(
            {
                "work_item": dict(item),
                "methodology_utf8": methodology,
                "methodology_bytes_sha256": hashlib.sha256(raw).hexdigest(),
                "methodology_size_bytes": len(raw),
            }
        )
    bound_queues: list[dict[str, Any]] = []
    queue_names = sorted(
        {
            str(name)
            for row in bound_items
            for name in (row["work_item"].get("source_queues") or [])
        }
    )
    scratch_root = Path(scratchpad).resolve() if scratchpad is not None else None
    for name in queue_names:
        if scratch_root is None or Path(name).name != name:
            raise ApplicationSkepticError(
                "bound source queue requires a safe scratchpad-relative identity"
            )
        path = (scratch_root / name).resolve()
        if path.parent != scratch_root or path.is_symlink() or not path.is_file():
            raise ApplicationSkepticError(f"bound source queue is unavailable: {name}")
        raw = _stable_file_bytes(path, f"bound source queue {name}")
        if len(raw) > MAX_CONTEXT_FILE_BYTES:
            raise ApplicationSkepticError(
                f"bound source queue exceeds context file limit: {name}"
            )
        try:
            text = raw.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise ApplicationSkepticError(
                f"bound source queue is not UTF-8: {name}"
            ) from exc
        total_bytes += len(raw)
        bound_queues.append(
            {
                "relative_path": name,
                "content_utf8": text,
                "sha256": hashlib.sha256(raw).hexdigest(),
                "size_bytes": len(raw),
            }
        )

    source_context: list[dict[str, Any]] = []
    source_rejections: list[dict[str, str]] = []
    if project_root is not None:
        project = Path(project_root).resolve()
        resolver = MethodologyCitationResolver(project, scratchpad=scratch_root)
        citations_by_path: dict[str, set[str]] = {}
        for row in bound_items:
            item = row["work_item"]
            evidence = "\n".join(
                str(value or "")
                for value in (
                    item.get("original_evidence"),
                    item.get("original_result"),
                    (item.get("reopen_candidate_seed") or {}).get("mechanism")
                    if isinstance(item.get("reopen_candidate_seed"), Mapping)
                    else "",
                )
            )
            resolution = resolver.resolve_evidence(evidence)
            for citation in resolution.citations:
                citations_by_path.setdefault(citation.relative_path, set()).add(
                    citation.canonical
                )
            source_rejections.extend(
                {
                    "work_item_id": str(item.get("work_item_id") or ""),
                    "raw": rejection.raw,
                    "reason": rejection.reason,
                }
                for rejection in resolution.rejections
            )
        for relative in sorted(citations_by_path, key=str.casefold):
            path = (project / relative).resolve()
            try:
                path.relative_to(project)
            except ValueError as exc:
                raise ApplicationSkepticError(
                    f"resolved source context escapes project root: {relative}"
                ) from exc
            if path.is_symlink() or not path.is_file():
                raise ApplicationSkepticError(
                    f"resolved source context is unavailable: {relative}"
                )
            raw = _stable_file_bytes(path, f"resolved source context {relative}")
            if len(raw) > MAX_CONTEXT_FILE_BYTES:
                raise ApplicationSkepticError(
                    f"resolved source context exceeds file limit: {relative}"
                )
            try:
                text = raw.decode("utf-8", errors="strict")
            except UnicodeDecodeError as exc:
                raise ApplicationSkepticError(
                    f"resolved source context is not UTF-8: {relative}"
                ) from exc
            total_bytes += len(raw)
            source_context.append(
                {
                    "relative_path": relative,
                    "content_utf8": text,
                    "sha256": hashlib.sha256(raw).hexdigest(),
                    "size_bytes": len(raw),
                    "cited_locations": sorted(citations_by_path[relative]),
                }
            )
    if total_bytes > max_context_bytes:
        raise ApplicationSkepticError(
            "bound methodology/source context exceeds deterministic packet limit"
        )
    return {
        "schema_version": CONTEXT_SCHEMA,
        "plan_schema_version": str(plan.get("schema_version") or ""),
        "work_plan_digest": str(plan.get("work_plan_digest") or ""),
        "shard": dict(shard),
        "assigned_work_items": bound_items,
        "bound_source_queues": bound_queues,
        "source_context": source_context,
        "source_context_rejections": source_rejections,
        "source_context_state": (
            "COMPLETE_FOR_ALL_RESOLVED_CITATIONS"
            if source_context and not source_rejections
            else "PARTIAL_WITH_REJECTED_CITATIONS"
            if source_context
            else "NO_RESOLVED_SOURCE_CITATION"
        ),
        "total_bound_context_bytes": total_bytes,
    }


__all__ = [
    "CONTEXT_SCHEMA",
    "DEFAULT_CONTEXT_LIMIT_BYTES",
    "MAX_CONTEXT_FILE_BYTES",
    "OUTCOMES",
    "application_skeptic_output_schema",
    "application_skeptic_packet_context",
    "application_skeptic_stdout_digest",
]
