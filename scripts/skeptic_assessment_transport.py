"""Strict application-skeptic stdout schema and packet context.

This module is deliberately small and stable.  The execution provider binds the
entire file and the exact parser callable before launch, so unrelated edits to
the large driver cannot invalidate an otherwise resumable provider receipt.
"""
from __future__ import annotations

import hashlib
import json
import os
import base64
from pathlib import Path
import re
from typing import Any, Iterable, Mapping, Sequence

from application_skeptic import (
    ASSESSMENT_SCHEMA,
    ApplicationSkepticError,
    read_bound_methodology_bytes,
)
from methodology_citation import MethodologyCitationResolver


CONTEXT_SCHEMA = "plamen.application_skeptic_packet_context.v2"
STAGED_CONTEXT_SCHEMA = "plamen.application_skeptic_staged_context.v1"
OUTCOMES = (
    "AGREE_NEGATIVE",
    "DISAGREE_CANDIDATE",
    "UNAVAILABLE",
    "INCONCLUSIVE",
)
DEFAULT_CONTEXT_LIMIT_BYTES = 16 * 1024 * 1024
MAX_CONTEXT_FILE_BYTES = 4 * 1024 * 1024
MAX_STAGED_PACKET_BYTES = 16 * 1024 * 1024
MAX_STAGED_OUTPUT_BYTES = 4 * 1024 * 1024
_HEX64 = re.compile(r"[0-9a-f]{64}")
_OUTPUT_IDENTITY = re.compile(
    r"scratchpad:(?:application|candidate_negative)_skeptic_assessments_[0-9]{4}\.json"
)


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

    if not path.is_file():
        raise ApplicationSkepticError("bound skeptic stdin packet is missing")
    packet = _strict_json_bytes(path.read_bytes(), "skeptic stdin packet")
    return _application_skeptic_payload_digest(packet, raw)


def _strict_json_bytes(document: bytes, label: str) -> Any:
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


def _application_skeptic_payload_digest(
    packet: Any,
    raw: bytes,
    *,
    reject_agree_negative: bool = False,
) -> str:
    """Validate one assessment against an already captured immutable packet."""

    if not isinstance(packet, dict) or packet.get("schema_version") != (
        "plamen.skeptic_execution_packet.v2"
    ):
        raise ApplicationSkepticError("bound skeptic stdin packet is invalid")
    value = _strict_json_bytes(raw, "assessor output")
    if not isinstance(value, dict):
        raise ApplicationSkepticError("assessor output must be one JSON object")

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
        raise ApplicationSkepticError("assessor output assessments must be an array")
    if set(value) != {
        "schema_version", "work_plan_digest", "shard_id", "assessments"
    } or value.get("schema_version") != ASSESSMENT_SCHEMA:
        raise ApplicationSkepticError("assessor output object shape is invalid")
    observed_ids = [
        row.get("work_item_id") if isinstance(row, dict) else None for row in rows
    ]
    if observed_ids != expected_ids:
        raise ApplicationSkepticError(
            "assessor output does not match the exact ordered work-item denominator"
        )
    if (
        value.get("work_plan_digest") != plan.get("work_plan_digest")
        or value.get("shard_id") != shard.get("shard_id")
    ):
        raise ApplicationSkepticError("assessor output plan/shard binding changed")
    for row in rows:
        if set(row) != {
            "work_item_id", "assessor_id", "assessor_invocation_id",
            "outcome", "evidence_basis", "evidence", "rationale", "candidate",
        }:
            raise ApplicationSkepticError("assessment row shape is invalid")
        if (
            row.get("assessor_id") != assessor.get("identity")
            or row.get("assessor_invocation_id") != assessor.get("invocation_id")
        ):
            raise ApplicationSkepticError(
                "assessor output principal binding changed"
            )
        outcome = row.get("outcome")
        if outcome not in OUTCOMES or any(
            not isinstance(row.get(field), str)
            for field in ("evidence_basis", "evidence", "rationale")
        ):
            raise ApplicationSkepticError("assessment row semantics are invalid")
        if outcome in {"AGREE_NEGATIVE", "DISAGREE_CANDIDATE"} and not row[
            "evidence"
        ]:
            raise ApplicationSkepticError(
                "decisive assessment requires concrete evidence"
            )
        candidate = row.get("candidate")
        if outcome == "DISAGREE_CANDIDATE":
            if (
                not isinstance(candidate, dict)
                or set(candidate) != {"title", "mechanism", "harm"}
                or any(not isinstance(candidate.get(key), str) for key in candidate)
            ):
                raise ApplicationSkepticError(
                    "disagreement assessment candidate is invalid"
                )
        elif candidate is not None:
            raise ApplicationSkepticError(
                "non-disagreement assessment must not carry a candidate"
            )
        if reject_agree_negative and outcome == "AGREE_NEGATIVE":
            raise ApplicationSkepticError(
                "Codex AGREE_NEGATIVE lacks equivalent terminal-negative authority; "
                "the work item must remain reopened"
            )
    canonical = json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def compile_application_skeptic_staged_context(
    packet_bytes: bytes,
    output_identity: str,
    *,
    reject_agree_negative: bool,
) -> dict[str, Any]:
    """Compile a JSON-safe, filesystem-free gate for one Codex skeptic shard."""

    if (
        type(packet_bytes) is not bytes
        or not packet_bytes
        or len(packet_bytes) > MAX_STAGED_PACKET_BYTES
    ):
        raise ValueError("staged skeptic packet bytes are invalid")
    if type(output_identity) is not str or not _OUTPUT_IDENTITY.fullmatch(
        output_identity
    ):
        raise ValueError("staged skeptic output identity is invalid")
    packet = _strict_json_bytes(packet_bytes, "skeptic stdin packet")
    if not isinstance(packet, dict) or packet.get("schema_version") != (
        "plamen.skeptic_execution_packet.v2"
    ):
        raise ValueError("staged skeptic packet schema is invalid")
    plan = packet.get("plan")
    shard = packet.get("shard")
    assessor = packet.get("assessor")
    if not all(isinstance(value, dict) for value in (plan, shard, assessor)):
        raise ValueError("staged skeptic packet bindings are incomplete")
    work_item_ids = shard.get("work_item_ids")
    if (
        not isinstance(work_item_ids, list)
        or not work_item_ids
        or any(not isinstance(value, str) or not value for value in work_item_ids)
        or len(set(work_item_ids)) != len(work_item_ids)
    ):
        raise ValueError("staged skeptic work-item denominator is invalid")
    for value, label in (
        (plan.get("work_plan_digest"), "plan digest"),
        (shard.get("shard_id"), "shard id"),
        (assessor.get("identity"), "assessor id"),
        (assessor.get("invocation_id"), "assessor invocation id"),
    ):
        if not isinstance(value, str) or not value:
            raise ValueError(f"staged skeptic {label} is invalid")
    context: dict[str, Any] = {
        "schema_version": STAGED_CONTEXT_SCHEMA,
        "packet_base64": base64.b64encode(packet_bytes).decode("ascii"),
        "packet_sha256": hashlib.sha256(packet_bytes).hexdigest(),
        "output_identity": output_identity,
        "work_plan_digest": str(plan["work_plan_digest"]),
        "shard_id": str(shard["shard_id"]),
        "assessor_id": str(assessor["identity"]),
        "assessor_invocation_id": str(assessor["invocation_id"]),
        "work_item_ids": list(work_item_ids),
        "reject_agree_negative": bool(reject_agree_negative),
    }
    context["context_digest"] = hashlib.sha256(
        json.dumps(
            context,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    ).hexdigest()
    return context


def staged_application_skeptic_assessment_validator(
    outputs: Mapping[str, bytes], context: Mapping[str, Any]
) -> Sequence[str]:
    """Validate one exact assessment output without consulting the filesystem."""

    fields = {
        "schema_version", "packet_base64", "packet_sha256", "output_identity",
        "work_plan_digest", "shard_id", "assessor_id",
        "assessor_invocation_id", "work_item_ids", "reject_agree_negative",
        "context_digest",
    }
    if not isinstance(context, Mapping) or set(context) != fields:
        return ("staged skeptic gate context shape is invalid",)
    unsigned = {key: context[key] for key in context if key != "context_digest"}
    try:
        expected_digest = hashlib.sha256(
            json.dumps(
                unsigned,
                ensure_ascii=True,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("ascii")
        ).hexdigest()
        packet_bytes = base64.b64decode(
            str(context["packet_base64"]).encode("ascii"), validate=True
        )
    except (TypeError, ValueError, UnicodeError):
        return ("staged skeptic gate context encoding is invalid",)
    output_identity = context.get("output_identity")
    if (
        context.get("schema_version") != STAGED_CONTEXT_SCHEMA
        or context.get("context_digest") != expected_digest
        or not _HEX64.fullmatch(str(context.get("packet_sha256") or ""))
        or hashlib.sha256(packet_bytes).hexdigest() != context["packet_sha256"]
        or type(output_identity) is not str
        or not _OUTPUT_IDENTITY.fullmatch(output_identity)
        or type(context.get("reject_agree_negative")) is not bool
    ):
        return ("staged skeptic gate context binding is invalid",)
    if not isinstance(outputs, Mapping) or set(outputs) != {output_identity}:
        return ("staged skeptic output denominator mismatch",)
    raw = outputs.get(output_identity)
    if type(raw) is not bytes or not raw or len(raw) > MAX_STAGED_OUTPUT_BYTES:
        return ("staged skeptic output bytes are invalid",)
    try:
        packet = _strict_json_bytes(packet_bytes, "skeptic stdin packet")
        plan = packet.get("plan")
        shard = packet.get("shard")
        assessor = packet.get("assessor")
        if (
            not isinstance(plan, dict)
            or not isinstance(shard, dict)
            or not isinstance(assessor, dict)
            or plan.get("work_plan_digest") != context.get("work_plan_digest")
            or shard.get("shard_id") != context.get("shard_id")
            or shard.get("work_item_ids") != context.get("work_item_ids")
            or assessor.get("identity") != context.get("assessor_id")
            or assessor.get("invocation_id")
            != context.get("assessor_invocation_id")
        ):
            raise ApplicationSkepticError(
                "staged skeptic packet/context binding changed"
            )
        _application_skeptic_payload_digest(
            packet,
            raw,
            reject_agree_negative=bool(context["reject_agree_negative"]),
        )
    except ApplicationSkepticError as exc:
        return (str(exc),)
    return ()


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
    allow_agree_negative: bool = True,
) -> dict[str, Any]:
    """Build the strict wire schema accepted by the provider and consumer.

    Claude CLI 2.1.214 rejects Draft 2020-12 ``prefixItems`` while Anthropic's
    API rejects the Draft-07 tuple form.  The wire schema therefore constrains
    row count, allowed identities, principals, and outcome shapes using their
    common subset.  :func:`application_skeptic_stdout_digest` enforces the exact
    ordered denominator from the immutable provider-bound packet before the
    provider may emit a completion receipt. ``allow_agree_negative`` projects
    the provider's actual semantic authority into the generation contract; a
    producer must never be shown an outcome that the staged gate will reject.
    """

    expected_ids = list(shard.get("work_item_ids") or [])
    allowed_ids = [str(work_item_id) for work_item_id in expected_ids]
    outcome_branches = []
    if allow_agree_negative:
        outcome_branches.append(
            _assessment_row_branch(
                work_item_ids=allowed_ids,
                assessor_id=assessor_id,
                assessor_invocation_id=assessor_invocation_id,
                outcomes=["AGREE_NEGATIVE"],
                decisive=True,
                candidate={"type": "null"},
            )
        )
    outcome_branches.extend([
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
        ])
    row = {"oneOf": outcome_branches}
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
    methodology_blobs: dict[str, dict[str, Any]] = {}
    methodology_cache: dict[tuple[str, str], bytes] = {}
    for work_item_id in list(shard.get("work_item_ids") or []):
        item = by_id.get(str(work_item_id))
        if item is None:
            raise ApplicationSkepticError(
                f"shard references unknown application-skeptic work {work_item_id!r}"
            )
        methodology_key = (
            str(item.get("methodology_path") or ""),
            str(item.get("methodology_sha256") or "").casefold(),
        )
        raw = methodology_cache.get(methodology_key)
        if raw is None:
            raw = read_bound_methodology_bytes(item, trusted_methodology_roots)
            methodology_cache[methodology_key] = raw
        try:
            methodology = raw.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise ApplicationSkepticError(
                f"bound methodology for {work_item_id} is not UTF-8"
            ) from exc
        methodology_sha256 = hashlib.sha256(raw).hexdigest()
        reference_only = item.get("application_subject") == "CANDIDATE_NEGATIVE"
        bound_items.append({
            "work_item": dict(item),
            "methodology_bytes_sha256": methodology_sha256,
            "methodology_size_bytes": len(raw),
            "methodology_context_mode": (
                "CONTENT_ADDRESSED_REFERENCE_WITH_TYPED_WORK_ITEM_PROJECTION"
                if reference_only
                else "CONTENT_ADDRESSED_BLOB"
            ),
        })
        if not reference_only:
            existing = methodology_blobs.get(methodology_sha256)
            claimed_path = str(item.get("methodology_path") or "")
            if existing is None:
                methodology_blobs[methodology_sha256] = {
                    "sha256": methodology_sha256,
                    "size_bytes": len(raw),
                    "bound_paths": [claimed_path],
                    "content_utf8": methodology,
                }
            elif claimed_path not in existing["bound_paths"]:
                existing["bound_paths"].append(claimed_path)
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
        source_binding = (
            plan.get("source_queues", {}).get(name)
            if isinstance(plan.get("source_queues"), Mapping)
            else None
        )
        if not isinstance(source_binding, Mapping):
            raise ApplicationSkepticError(
                f"bound source queue has no work-plan binding: {name}"
            )
        observed_sha256 = hashlib.sha256(raw).hexdigest()
        if source_binding.get("artifact_sha256") != observed_sha256:
            raise ApplicationSkepticError(
                f"bound source queue differs from work-plan binding: {name}"
            )
        assigned_input_ids = sorted({
            str(input_id)
            for row in bound_items
            if name in (row["work_item"].get("source_queues") or [])
            for input_id in (row["work_item"].get("input_row_ids") or [])
            if str(input_id)
        })
        bound_queues.append(
            {
                "relative_path": name,
                "sha256": observed_sha256,
                "size_bytes": len(raw),
                "work_plan_binding": dict(source_binding),
                "assigned_input_row_ids": assigned_input_ids,
                "content_projection": "DIGEST_BOUND_ASSIGNED_ROWS_IN_WORK_ITEMS",
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
            source_context.append(
                {
                    "relative_path": relative,
                    "content_utf8": text,
                    "sha256": hashlib.sha256(raw).hexdigest(),
                    "size_bytes": len(raw),
                    "cited_locations": sorted(citations_by_path[relative]),
                }
            )
    context = {
        "schema_version": CONTEXT_SCHEMA,
        "plan_schema_version": str(plan.get("schema_version") or ""),
        "work_plan_digest": str(plan.get("work_plan_digest") or ""),
        "shard": dict(shard),
        "assigned_work_items": bound_items,
        "methodology_blobs": [
            {
                **row,
                "bound_paths": sorted(set(row["bound_paths"])),
            }
            for _digest, row in sorted(methodology_blobs.items())
        ],
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
        "total_bound_context_bytes": 0,
    }
    # Enforce the actual serialized packet-context size, not the sum of source
    # files which may be digest-bound or content-addressed only once.
    for _ in range(4):
        serialized_size = len(json.dumps(
            context,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8"))
        if context["total_bound_context_bytes"] == serialized_size:
            break
        context["total_bound_context_bytes"] = serialized_size
    if int(context["total_bound_context_bytes"]) > max_context_bytes:
        raise ApplicationSkepticError(
            "bound methodology/source context exceeds deterministic packet limit"
        )
    return context


__all__ = [
    "CONTEXT_SCHEMA",
    "DEFAULT_CONTEXT_LIMIT_BYTES",
    "MAX_CONTEXT_FILE_BYTES",
    "OUTCOMES",
    "STAGED_CONTEXT_SCHEMA",
    "application_skeptic_output_schema",
    "application_skeptic_packet_context",
    "application_skeptic_stdout_digest",
    "compile_application_skeptic_staged_context",
    "staged_application_skeptic_assessment_validator",
]
