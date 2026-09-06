"""Deterministic P0-C work planning and adjudication for author negatives.

This module owns no model launch and no finding registry.  It binds the exact
methodology bytes and application rows that an independent assessor must read,
then converts assessments into a durable negative, visible debt, or a typed
candidate proposal delivered through an injected registry sink.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
from typing import Any, Callable, Iterable, Mapping, Sequence
import uuid

import methodology_application_states as application_states
from finding_producer_registry import (
    CandidateSchemaError,
    normalize_application_skeptic_proposal,
    validate_application_skeptic_candidate,
)
from negative_closure_policy import terminal_negative_authorized
from closure_broker_v2 import resolve_central_negative_closure


WORK_PLAN_SCHEMA = "plamen.application_skeptic_work_plan.v1"
RECEIPT_SCHEMA = "plamen.application_skeptic_receipt.v1"
ASSESSMENT_SCHEMA = "plamen.application_skeptic_assessments.v1"
REGISTRY_PROPOSAL_SCHEMA = "plamen.finding_candidate_proposal.v1"
MANDATORY_REVIEW_SCHEMA = "plamen.application_skeptic_mandatory_review.v1"
PRESERVATION_CONTEXT_SCHEMA = (
    "plamen.application_skeptic_preservation_context.v1"
)
DELIVERY_BINDING_SCHEMA = "plamen.application_skeptic_delivery_binding.v1"
WORK_PLAN_FILE = "application_skeptic_work_plan.json"
RECEIPT_FILE = "application_skeptic_receipt.json"

DEFAULT_QUEUE_PHASES = (
    "breadth",
    "breadth_repair",
    "rescan",
    "rescan_repair",
    "depth",
    "depth_repair",
)
SUPPORTED_NEGATIVE_EVIDENCE = frozenset(
    {"IN_SCOPE_SOURCE", "IN_SCOPE_EXECUTION", "PRIMARY_EXTERNAL_CITED"}
)

_HEX_RE = re.compile(r"^[0-9a-f]{64}$", re.ASCII)


class ApplicationSkepticError(ValueError):
    """An application-skeptic contract cannot be satisfied without guessing."""


def _canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _bytes_sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _text(value: Any) -> str:
    return str(value or "").strip()


def _candidate_seed_field(value: Any, *, limit: int, title: bool = False) -> str:
    text = re.sub(r"\s+", " ", _text(value)).strip()
    text = text.replace("<!--", "").replace("PLAMEN_STATUS:", "")
    if title:
        text = text.replace("[", "(").replace("]", ")")
    if not text:
        text = (
            "Reopened methodology-negative candidate"
            if title
            else "The methodology-negative conclusion lacks replayable closure authority."
        )
    while len(text.encode("utf-8")) > limit:
        text = text[:-1]
    return text.strip()


def _valid_digest(value: Any) -> bool:
    return isinstance(value, str) and bool(_HEX_RE.fullmatch(value))


def _row_digest_is_valid(row: Mapping[str, Any]) -> bool:
    claimed = row.get("row_digest")
    unsigned = {key: value for key, value in row.items() if key != "row_digest"}
    return _valid_digest(claimed) and claimed == _digest(unsigned)


def _write_json_if_changed(path: Path, payload: Mapping[str, Any]) -> None:
    content = json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    try:
        if path.read_text(encoding="utf-8") == content:
            return
    except OSError:
        pass
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    temporary.write_text(content, encoding="utf-8")
    os.replace(temporary, path)


def _input_row_id(queue_name: str, row: Mapping[str, Any]) -> str:
    identity = {
        "source_queue": queue_name,
        "obligation_id": row["obligation_id"],
        "row_digest": row["row_digest"],
    }
    return "ASI-" + _digest(identity)[:24].upper()


def _work_item_id(obligation_id: str, binding_digest: str) -> str:
    return "ASW-" + _digest(
        {"obligation_id": obligation_id, "binding_digest": binding_digest}
    )[:24].upper()


def _bound_fields(row: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "obligation_id": _text(row.get("obligation_id")),
        "skill": _text(row.get("skill")),
        "step": _text(row.get("step")),
        "methodology_path": _text(row.get("methodology_path")),
        "methodology_sha256": _text(row.get("methodology_sha256")).casefold(),
        "semantic_outcome": _text(row.get("semantic_outcome")).upper(),
        "evidence_basis": _text(row.get("evidence_basis")).upper(),
        "original_evidence": _text(row.get("original_evidence")),
        "original_result": _text(row.get("original_result")),
    }


def _validate_source_row(row: Any) -> dict[str, Any]:
    if not isinstance(row, dict):
        raise ApplicationSkepticError("skeptic queue row must be an object")
    if not _row_digest_is_valid(row):
        raise ApplicationSkepticError("skeptic queue row digest mismatch")
    if not _text(row.get("obligation_id")):
        raise ApplicationSkepticError("skeptic queue row has no obligation identity")
    if row.get("skeptic_required") is not True:
        raise ApplicationSkepticError("skeptic queue contains a non-skeptic row")
    if _text(row.get("semantic_outcome")).upper() not in {
        "NEGATIVE",
        "NOT_APPLICABLE",
    }:
        raise ApplicationSkepticError("skeptic queue row has no author-negative outcome")
    if not _text(row.get("methodology_path")):
        raise ApplicationSkepticError("skeptic queue row has no methodology path")
    if not _valid_digest(_text(row.get("methodology_sha256")).casefold()):
        raise ApplicationSkepticError("skeptic queue row has invalid methodology SHA-256")
    return row


def _read_source_queue(path: Path, expected_phase: str) -> tuple[dict[str, Any], bytes]:
    raw = path.read_bytes()
    try:
        payload = json.loads(raw.decode("utf-8"))
        application_states.validate_queue_payload(payload, expected_kind="skeptic")
    except (UnicodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        raise ApplicationSkepticError(str(exc)) from exc
    if payload.get("phase") != expected_phase:
        raise ApplicationSkepticError(
            f"skeptic queue phase mismatch: expected {expected_phase!r}"
        )
    for row in payload["rows"]:
        _validate_source_row(row)
    return payload, raw


def build_application_skeptic_work_plan(
    scratchpad: Path,
    *,
    max_items_per_shard: int = 20,
    queue_phases: Sequence[str] = DEFAULT_QUEUE_PHASES,
) -> dict[str, Any]:
    """Build an exact six-queue union without treating missing input as empty."""

    if isinstance(max_items_per_shard, bool) or max_items_per_shard < 1:
        raise ValueError("max_items_per_shard must be a positive integer")
    root = Path(scratchpad)
    issues: list[dict[str, Any]] = []
    source_queues: dict[str, dict[str, Any]] = {}
    inputs_by_obligation: dict[str, list[dict[str, Any]]] = {}
    input_row_count = 0

    for phase in queue_phases:
        name = f"methodology_skeptic_queue_{phase}.json"
        path = root / name
        if not path.is_file():
            issues.append(
                {"code": "MISSING_SOURCE_QUEUE", "source_queue": name}
            )
            continue
        try:
            payload, raw = _read_source_queue(path, phase)
        except (OSError, ApplicationSkepticError) as exc:
            issues.append(
                {
                    "code": "INVALID_SOURCE_QUEUE",
                    "source_queue": name,
                    "detail": str(exc),
                }
            )
            continue
        source_queues[name] = {
            "artifact_sha256": _bytes_sha256(raw),
            "queue_digest": payload["queue_digest"],
            "row_count": payload["row_count"],
        }
        for row in payload["rows"]:
            input_row_count += 1
            source = {
                "input_row_id": _input_row_id(name, row),
                "source_queue": name,
                "source_phase": phase,
                "source_row_digest": row["row_digest"],
                "row": row,
            }
            inputs_by_obligation.setdefault(row["obligation_id"], []).append(source)

    work_items: list[dict[str, Any]] = []
    for obligation_id in sorted(inputs_by_obligation):
        sources = sorted(
            inputs_by_obligation[obligation_id], key=lambda item: item["input_row_id"]
        )
        bindings: dict[str, list[dict[str, Any]]] = {}
        for source in sources:
            fields = _bound_fields(source["row"])
            binding_digest = _digest(fields)
            bindings.setdefault(binding_digest, []).append(source)

        if len(bindings) > 1:
            issues.append(
                {
                    "code": "CONFLICTING_OBLIGATION_BINDING",
                    "obligation_id": obligation_id,
                    "binding_digests": sorted(bindings),
                }
            )
        # Conflicting bindings remain separate work: combining them would make
        # the assessor read guessed methodology/evidence and lose input parity.
        for binding_digest in sorted(bindings):
            bound_sources = bindings[binding_digest]
            row = bound_sources[0]["row"]
            fields = _bound_fields(row)
            candidate_id = "ASUB-" + _digest(
                {
                    "obligation_id": obligation_id,
                    "binding_digest": binding_digest,
                }
            )[:24].upper()
            premise_ids = sorted(
                {
                    "ASPREM-"
                    + _digest(
                        {
                            "candidate_id": candidate_id,
                            "kind": kind,
                            "value": value,
                        }
                    )[:24].upper()
                    for kind, value in (
                        ("MECHANISM", f"{fields['skill']} | {fields['step']} | {fields['original_result']}"),
                        ("HARM", "security impact remains unresolved"),
                    )
                }
            )
            producers = sorted(
                {
                    (
                        _text(source["row"].get("worker_id")),
                        _text(source["row"].get("producer_invocation_id")),
                    )
                    for source in bound_sources
                }
            )
            work_items.append(
                {
                    "work_item_id": _work_item_id(obligation_id, binding_digest),
                    **fields,
                    "binding_digest": binding_digest,
                    "input_row_ids": sorted(
                        source["input_row_id"] for source in bound_sources
                    ),
                    "source_queues": sorted(
                        {source["source_queue"] for source in bound_sources}
                    ),
                    "producer_identities": sorted(
                        {worker for worker, _ in producers if worker}
                    ),
                    "producer_invocation_ids": sorted(
                        {invocation for _, invocation in producers if invocation}
                    ),
                    "original_evidence_sha256": hashlib.sha256(
                        fields["original_evidence"].encode("utf-8")
                    ).hexdigest(),
                    "candidate_id": candidate_id,
                    "candidate_premise_ids": premise_ids,
                    "reopen_candidate_seed": {
                        "title": _candidate_seed_field(
                            f"Reopened methodology-negative {obligation_id}",
                            limit=240,
                            title=True,
                        ),
                        "mechanism": _candidate_seed_field(
                            f"{fields['skill']} | {fields['step']} | "
                            f"{fields['original_result']}",
                            limit=6000,
                        ),
                        "harm": _candidate_seed_field(
                            "The security impact remains unresolved until the exact "
                            "methodology premise is independently verified with "
                            "replayable terminal evidence.",
                            limit=4000,
                        ),
                    },
                }
            )

    work_items.sort(key=lambda item: item["work_item_id"])
    shards = []
    for offset in range(0, len(work_items), max_items_per_shard):
        shard_items = work_items[offset : offset + max_items_per_shard]
        ordinal = len(shards) + 1
        unsigned_shard = {
            "shard_id": f"application-skeptic-{ordinal:04d}",
            "work_item_ids": [item["work_item_id"] for item in shard_items],
        }
        shards.append({**unsigned_shard, "shard_digest": _digest(unsigned_shard)})

    if issues:
        status = "INPUT_DEBT"
    elif not work_items:
        status = "NOT_TRIGGERED"
    else:
        status = "READY"
    unsigned_plan = {
        "schema_version": WORK_PLAN_SCHEMA,
        "status": status,
        "queue_phases": list(queue_phases),
        "source_queues": source_queues,
        "input_row_count": input_row_count,
        "work_item_count": len(work_items),
        "max_items_per_shard": max_items_per_shard,
        "work_items": work_items,
        "shards": shards,
        "issues": sorted(
            issues,
            key=lambda issue: (
                _text(issue.get("source_queue")),
                _text(issue.get("obligation_id")),
                _text(issue.get("code")),
            ),
        ),
    }
    return {**unsigned_plan, "work_plan_digest": _digest(unsigned_plan)}


def write_application_skeptic_work_plan(
    scratchpad: Path,
    *,
    max_items_per_shard: int = 20,
    queue_phases: Sequence[str] = DEFAULT_QUEUE_PHASES,
) -> dict[str, Any]:
    plan = build_application_skeptic_work_plan(
        scratchpad,
        max_items_per_shard=max_items_per_shard,
        queue_phases=queue_phases,
    )
    _write_json_if_changed(Path(scratchpad) / WORK_PLAN_FILE, plan)
    return plan


def _validate_plan(plan: Mapping[str, Any]) -> None:
    if plan.get("schema_version") != WORK_PLAN_SCHEMA:
        raise ApplicationSkepticError("application-skeptic work-plan schema mismatch")
    unsigned = {key: value for key, value in plan.items() if key != "work_plan_digest"}
    if plan.get("work_plan_digest") != _digest(unsigned):
        raise ApplicationSkepticError("application-skeptic work-plan digest mismatch")
    work_items = plan.get("work_items")
    if not isinstance(work_items, list):
        raise ApplicationSkepticError("application-skeptic work_items must be a list")
    ids = [item.get("work_item_id") for item in work_items if isinstance(item, dict)]
    if len(ids) != len(work_items) or len(ids) != len(set(ids)):
        raise ApplicationSkepticError("application-skeptic work identities are not exact")


def read_bound_methodology_bytes(
    work_item: Mapping[str, Any], trusted_roots: Iterable[Path]
) -> bytes:
    """Read only the path/hash pair recorded in the authoritative work item."""

    claimed_path = _text(work_item.get("methodology_path"))
    claimed_hash = _text(work_item.get("methodology_sha256")).casefold()
    if not claimed_path or not _valid_digest(claimed_hash):
        raise ApplicationSkepticError("methodology path/SHA-256 binding is invalid")
    try:
        path = Path(claimed_path).resolve(strict=True)
    except OSError as exc:
        raise ApplicationSkepticError(f"bound methodology is unavailable: {exc}") from exc
    roots = []
    for root in trusted_roots:
        try:
            roots.append(Path(root).resolve(strict=True))
        except OSError:
            continue
    if not roots or not any(path == root or path.is_relative_to(root) for root in roots):
        raise ApplicationSkepticError("bound methodology path is outside trusted roots")
    data = path.read_bytes()
    actual = _bytes_sha256(data)
    if actual != claimed_hash:
        raise ApplicationSkepticError(
            f"bound methodology SHA-256 mismatch: expected {claimed_hash}, got {actual}"
        )
    return data


def build_application_skeptic_shard_prompt(
    plan: Mapping[str, Any],
    shard_id: str,
    *,
    trusted_methodology_roots: Iterable[Path],
    output_path: Path | None,
    output_transport: str = "FILE",
    context_transport: str = "PROMPT",
    assessor_id: str = "application-skeptic-independent",
    assessor_invocation_id: str = "driver-bound-invocation",
) -> dict[str, Any]:
    """Render one content-bound independent-assessment prompt.

    The file read occurs here, immediately before launch planning.  A stale or
    relocated methodology therefore cannot be replaced by checklist prose.
    """

    _validate_plan(plan)
    shard = next(
        (row for row in plan.get("shards", []) if row.get("shard_id") == shard_id),
        None,
    )
    if shard is None:
        raise ApplicationSkepticError(f"unknown application-skeptic shard {shard_id!r}")
    context_mode = str(context_transport or "").strip().upper()
    if context_mode not in {"PROMPT", "PACKET"}:
        raise ApplicationSkepticError(
            "application-skeptic context transport must be PROMPT or PACKET"
        )
    by_id = {item["work_item_id"]: item for item in plan["work_items"]}
    blocks: list[str] = []
    for work_id in shard.get("work_item_ids", []):
        item = by_id.get(work_id)
        if item is None:
            raise ApplicationSkepticError(
                f"shard references unknown application-skeptic work {work_id!r}"
            )
        data = read_bound_methodology_bytes(item, trusted_methodology_roots)
        try:
            method_text = data.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ApplicationSkepticError(
                f"bound methodology for {work_id} is not UTF-8"
            ) from exc
        if context_mode == "PACKET":
            blocks.extend(
                [
                    f"- Assigned work item `{work_id}` is fully bound in the "
                    "immutable methodology_and_source_context packet field.",
                    "",
                ]
            )
            continue
        blocks.extend(
            [
                f"### Work item {work_id}",
                f"- Obligation: `{item['obligation_id']}`",
                f"- Skill: `{item['skill']}`",
                f"- Exact step: `{item['step']}`",
                f"- Methodology path: `{item['methodology_path']}`",
                f"- Methodology SHA-256: `{item['methodology_sha256']}`",
                f"- Original evidence basis: `{item['evidence_basis']}`",
                f"- Original evidence: {item['original_evidence']}",
                f"- Original result: {item['original_result']}",
                "- Exact methodology bytes (hash verified by the driver before this prompt):",
                f"<PLAMEN_METHOD_BYTES id=\"{work_id}\">",
                method_text,
                f"</PLAMEN_METHOD_BYTES id=\"{work_id}\">",
                "",
            ]
        )

    transport = str(output_transport or "").strip().upper()
    if transport not in {"FILE", "STDOUT"}:
        raise ApplicationSkepticError(
            "application-skeptic output transport must be FILE or STDOUT"
        )
    if transport == "FILE":
        if output_path is None:
            raise ApplicationSkepticError(
                "application-skeptic file transport requires an output path"
            )
        output = Path(output_path).as_posix()
        output_instruction = f"Write only: `{output}`"
    else:
        output = "PROVIDER_OWNED_STDOUT"
        output_instruction = (
            "Return only the one raw JSON object on stdout. Do not read, write, "
            "or name any filesystem artifact."
        )
    prompt = "\n".join(
        [
            "# INDEPENDENT METHODOLOGY-APPLICATION SKEPTIC",
            "",
            "Independently reassess each producer-authored NEGATIVE or NOT_APPLICABLE",
            "decision below. You are a discriminator, not the original producer. Do not",
            "self-certify, invent evidence, or delete an obligation. Agreement requires",
            "in-scope source, in-scope execution, or a primary external citation that",
            "directly proves the exact premise. Unsupported external assumptions remain",
            "UNAVAILABLE/INCONCLUSIVE; disagreement emits a low-confidence candidate for",
            "the normal registry, dedup, and verification lifecycle.",
            "",
            f"Work-plan digest: `{plan['work_plan_digest']}`",
            f"Shard: `{shard_id}`",
            f"Assessor ID (echo exactly): `{assessor_id}`",
            f"Assessor invocation ID (echo exactly): `{assessor_invocation_id}`",
            output_instruction,
            "",
            *blocks,
            "## Exact JSON output",
            "",
            "Write one JSON object with schema_version",
            "`plamen.application_skeptic_assessments.v1`, the exact work_plan_digest",
            "and shard_id above, and an `assessments` array containing exactly one row",
            "per work item. Each row must contain work_item_id, assessor_id,",
            "assessor_invocation_id, outcome (AGREE_NEGATIVE, DISAGREE_CANDIDATE,",
            "UNAVAILABLE, or INCONCLUSIVE), evidence_basis, evidence (the exact cited",
            "source/trace/premise support, not a hash), rationale,",
            "and candidate (null unless disagreeing; otherwise title/mechanism/harm).",
        ]
    )
    prompt_bytes = prompt.encode("utf-8")
    return {
        "shard_id": shard_id,
        "work_plan_digest": plan["work_plan_digest"],
        "work_item_ids": list(shard.get("work_item_ids", [])),
        "output_path": output,
        "output_transport": transport,
        "context_transport": context_mode,
        "prompt": prompt,
        "prompt_sha256": _bytes_sha256(prompt_bytes),
    }


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ApplicationSkepticError(f"duplicate JSON key {key!r}")
        value[key] = item
    return value


def load_application_skeptic_assessments(
    path: Path,
    plan: Mapping[str, Any],
    shard_id: str,
    *,
    assessor_id: str | None = None,
    assessor_invocation_id: str | None = None,
) -> list[dict[str, Any]]:
    """Load one assessor artifact with exact shard/tail coverage."""

    _validate_plan(plan)
    shard = next(
        (row for row in plan.get("shards", []) if row.get("shard_id") == shard_id),
        None,
    )
    if shard is None:
        raise ApplicationSkepticError(f"unknown application-skeptic shard {shard_id!r}")
    try:
        payload = json.loads(
            Path(path).read_text(encoding="utf-8"),
            object_pairs_hook=_strict_object,
            parse_constant=lambda value: (_ for _ in ()).throw(
                ApplicationSkepticError(f"invalid JSON constant {value!r}")
            ),
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ApplicationSkepticError(f"invalid assessor JSON: {exc}") from exc
    if not isinstance(payload, dict) or set(payload) != {
        "schema_version",
        "work_plan_digest",
        "shard_id",
        "assessments",
    }:
        raise ApplicationSkepticError("assessor artifact fields are not exact")
    if payload["schema_version"] != ASSESSMENT_SCHEMA:
        raise ApplicationSkepticError("assessor artifact schema mismatch")
    if payload["work_plan_digest"] != plan["work_plan_digest"]:
        raise ApplicationSkepticError("assessor artifact work-plan binding mismatch")
    if payload["shard_id"] != shard_id:
        raise ApplicationSkepticError("assessor artifact shard binding mismatch")
    assessments = payload["assessments"]
    if not isinstance(assessments, list):
        raise ApplicationSkepticError("assessments must be a list")
    expected_keys = {
        "work_item_id",
        "assessor_id",
        "assessor_invocation_id",
        "outcome",
        "evidence_basis",
        "evidence",
        "rationale",
        "candidate",
    }
    for row in assessments:
        if not isinstance(row, dict) or set(row) != expected_keys:
            raise ApplicationSkepticError("assessment row fields are not exact")
    observed = [row["work_item_id"] for row in assessments]
    expected = list(shard.get("work_item_ids", []))
    if observed != expected:
        raise ApplicationSkepticError(
            "assessment rows do not exactly cover the ordered shard tail"
        )
    normalized: list[dict[str, Any]] = []
    for row in assessments:
        if assessor_id is not None and row["assessor_id"] != assessor_id:
            raise ApplicationSkepticError("assessor identity binding mismatch")
        if (
            assessor_invocation_id is not None
            and row["assessor_invocation_id"] != assessor_invocation_id
        ):
            raise ApplicationSkepticError("assessor invocation binding mismatch")
        evidence = _text(row.get("evidence"))
        outcome = _text(row.get("outcome")).upper()
        if outcome in {"AGREE_NEGATIVE", "DISAGREE_CANDIDATE"} and not evidence:
            raise ApplicationSkepticError(
                "decisive assessment has no exact evidence to bind"
            )
        normalized.append(
            {
                **row,
                "evidence_sha256": hashlib.sha256(
                    evidence.encode("utf-8")
                ).hexdigest() if evidence else "",
            }
        )
    return normalized


def _single_or_list(values: Sequence[str]) -> str | list[str]:
    ordered = sorted(set(value for value in values if value))
    if len(ordered) == 1:
        return ordered[0]
    return ordered


def _candidate_proposal(
    item: Mapping[str, Any], assessment: Mapping[str, Any]
) -> dict[str, Any]:
    candidate = validate_application_skeptic_candidate(
        assessment.get("candidate")
    )
    unsigned = {
        "schema_version": REGISTRY_PROPOSAL_SCHEMA,
        "producer": "application_skeptic",
        "source_obligation_id": item["obligation_id"],
        "source_work_item_id": item["work_item_id"],
        "assessor_identity": _text(assessment.get("assessor_id")),
        "assessor_invocation_id": _text(assessment.get("assessor_invocation_id")),
        "assessor_evidence_sha256": _text(
            assessment.get("evidence_sha256")
        ).casefold(),
        "candidate": candidate,
    }
    proposal = {
        **unsigned,
        "proposal_id": "ASCP-" + _digest(unsigned)[:24].upper(),
        "proposal_digest": _digest(unsigned),
    }
    # The shared renderer is a separate trust boundary. Validate the exact
    # proposal shape before a sink can observe or persist it.
    return normalize_application_skeptic_proposal(proposal)


def _rejected_candidate_debt(
    item: Mapping[str, Any],
    assessment: Mapping[str, Any],
    reasons: Sequence[str],
) -> dict[str, Any]:
    candidate = assessment.get("candidate")
    try:
        serialized = _canonical_json(candidate).encode("utf-8")
    except (TypeError, ValueError):
        serialized = repr(candidate).encode("utf-8", errors="backslashreplace")
    field_sizes: dict[str, int] = {}
    if isinstance(candidate, Mapping):
        for key in ("title", "mechanism", "harm"):
            if key not in candidate:
                continue
            value = candidate[key]
            try:
                field_sizes[key] = len(str(value).encode("utf-8"))
            except Exception:
                field_sizes[key] = -1
    return {
        "work_item_id": item["work_item_id"],
        "obligation_id": item["obligation_id"],
        "assessor_identity": _text(assessment.get("assessor_id")),
        "assessor_invocation_id": _text(
            assessment.get("assessor_invocation_id")
        ),
        "candidate_sha256": hashlib.sha256(serialized).hexdigest(),
        "candidate_size_bytes": len(serialized),
        "candidate_field_count": (
            len(candidate) if isinstance(candidate, Mapping) else None
        ),
        "field_size_bytes": field_sizes,
        "reasons": sorted(dict.fromkeys(str(reason) for reason in reasons)),
    }


def _prior_dispositions(
    prior_receipt: Mapping[str, Any] | None, plan_digest: str
) -> tuple[
    dict[str, dict[str, Any]],
    list[dict[str, Any]],
    list[dict[str, Any]],
]:
    if prior_receipt is None:
        return {}, [], []
    if prior_receipt.get("schema_version") != RECEIPT_SCHEMA:
        raise ApplicationSkepticError("prior skeptic receipt schema mismatch")
    if prior_receipt.get("work_plan_digest") != plan_digest:
        raise ApplicationSkepticError("prior skeptic receipt binds another work plan")
    unsigned = {
        key: value for key, value in prior_receipt.items() if key != "receipt_digest"
    }
    if prior_receipt.get("receipt_digest") != _digest(unsigned):
        raise ApplicationSkepticError("prior skeptic receipt digest mismatch")
    dispositions: dict[str, dict[str, Any]] = {}
    for row in prior_receipt.get("work_dispositions", []):
        if not isinstance(row, dict) or not _text(row.get("work_item_id")):
            raise ApplicationSkepticError("prior skeptic disposition is malformed")
        work_id = row["work_item_id"]
        if work_id in dispositions:
            raise ApplicationSkepticError("prior skeptic receipt duplicates work")
        dispositions[work_id] = row
    proposals = list(prior_receipt.get("registry_candidate_proposals", []))
    rejected = list(prior_receipt.get("rejected_candidate_debt", []))
    return dispositions, proposals, rejected


def pending_work_item_ids(
    plan: Mapping[str, Any], receipt: Mapping[str, Any] | None
) -> list[str]:
    _validate_plan(plan)
    completed = {
        row.get("work_item_id")
        for row in (receipt or {}).get("work_dispositions", [])
        if isinstance(row, dict)
    }
    return [
        item["work_item_id"]
        for item in plan["work_items"]
        if item["work_item_id"] not in completed
    ]


def _debt_disposition(
    item: Mapping[str, Any],
    reason_code: str,
    detail: str = "",
    *,
    work_plan_digest: str = "",
) -> dict[str, Any]:
    source_binding = {
        "work_plan_digest": work_plan_digest,
        "source_work_item_id": item["work_item_id"],
        "source_obligation_id": item["obligation_id"],
        "binding_digest": _text(item.get("binding_digest")).casefold(),
        "input_row_ids": list(item["input_row_ids"]),
        "source_queues": list(item.get("source_queues") or []),
        "methodology_sha256": _text(item.get("methodology_sha256")).casefold(),
        "original_evidence_sha256": _text(
            item.get("original_evidence_sha256")
        ).casefold(),
        "candidate_id": _text(item.get("candidate_id")),
        "candidate_premise_ids": list(item.get("candidate_premise_ids") or []),
    }
    unsigned_review = {
        "schema_version": MANDATORY_REVIEW_SCHEMA,
        **source_binding,
        "source_binding_sha256": _digest(source_binding),
        "reason_code": reason_code,
        "detail_sha256": hashlib.sha256(detail.encode("utf-8")).hexdigest(),
        "required_action": "VERIFY_ADDITIVE_CANDIDATE",
        "proof_scope": "NONE",
        "terminal_negative_authorized": False,
    }
    return {
        "work_item_id": item["work_item_id"],
        "obligation_id": item["obligation_id"],
        "input_row_ids": list(item["input_row_ids"]),
        "disposition": "UNRESOLVED_DEBT",
        "reason_code": reason_code,
        "detail": detail,
        "mandatory_review_obligation": {
            **unsigned_review,
            "obligation_digest": _digest(unsigned_review),
        },
    }


def _policy_reopen_assessment(
    item: Mapping[str, Any],
    *,
    plan_digest: str,
    reason_code: str,
    detail: str,
    assessment: Mapping[str, Any] | None,
) -> dict[str, Any]:
    """Build a deterministic non-proof proposal from exact bound identities."""

    supplied = dict(assessment or {})
    evidence_binding = {
        "work_plan_digest": plan_digest,
        "work_item_id": item["work_item_id"],
        "obligation_id": item["obligation_id"],
        "binding_digest": _text(item.get("binding_digest")).casefold(),
        "input_row_ids": list(item["input_row_ids"]),
        "source_queues": list(item.get("source_queues") or []),
        "methodology_sha256": _text(item.get("methodology_sha256")).casefold(),
        "original_evidence_sha256": _text(
            item.get("original_evidence_sha256")
        ).casefold(),
        "reason_code": reason_code,
        "detail_sha256": hashlib.sha256(detail.encode("utf-8")).hexdigest(),
        "supplied_outcome": _text(supplied.get("outcome")).upper(),
        "supplied_assessor_identity": _text(supplied.get("assessor_id")),
        "supplied_assessor_invocation_id": _text(
            supplied.get("assessor_invocation_id")
        ),
        "supplied_evidence_sha256": _text(
            supplied.get("evidence_sha256")
        ).casefold(),
    }
    invocation_digest = _digest(evidence_binding)
    return {
        "work_item_id": item["work_item_id"],
        "assessor_id": "application-skeptic-recall-policy",
        "assessor_invocation_id": "policy-reopen-" + invocation_digest[:24],
        "outcome": "DISAGREE_CANDIDATE",
        "evidence_basis": "POLICY_NONPROOF_REOPEN",
        "evidence_sha256": invocation_digest,
        "rationale": reason_code,
        "candidate": dict(item["reopen_candidate_seed"]),
    }


def _deliver_policy_reopen_or_review(
    item: Mapping[str, Any],
    *,
    plan_digest: str,
    reason_code: str,
    detail: str,
    assessment: Mapping[str, Any] | None,
    candidate_sink: Callable[[dict[str, Any]], Any] | None,
    proposals: list[dict[str, Any]],
    rejected_candidate_debt: list[dict[str, Any]],
) -> dict[str, Any]:
    """Prefer an additive proposal; otherwise emit explicit proofless review debt."""

    policy_assessment = _policy_reopen_assessment(
        item,
        plan_digest=plan_digest,
        reason_code=reason_code,
        detail=detail,
        assessment=assessment,
    )
    try:
        proposal = _candidate_proposal(item, policy_assessment)
    except Exception as exc:  # deterministic seed failure must remain visible
        rejected_candidate_debt.append(
            _rejected_candidate_debt(
                item,
                policy_assessment,
                (
                    "policy reopen candidate normalization failed: "
                    f"{type(exc).__name__}: {exc}",
                ),
            )
        )
        return _debt_disposition(
            item,
            "POLICY_REOPEN_SCHEMA_REJECTED",
            str(exc),
            work_plan_digest=plan_digest,
        )
    if candidate_sink is None:
        return _debt_disposition(
            item,
            reason_code,
            "additive registry sink unavailable; " + detail,
            work_plan_digest=plan_digest,
        )
    try:
        candidate_sink(proposal)
    except Exception as exc:
        rejected_candidate_debt.append(
            _rejected_candidate_debt(
                item,
                policy_assessment,
                (
                    "registry sink rejected policy reopen proposal: "
                    f"{type(exc).__name__}: {exc}",
                ),
            )
        )
        return _debt_disposition(
            item,
            "REGISTRY_DELIVERY_FAILED",
            str(exc),
            work_plan_digest=plan_digest,
        )
    proposals.append(proposal)
    return {
        "work_item_id": item["work_item_id"],
        "obligation_id": item["obligation_id"],
        "input_row_ids": list(item["input_row_ids"]),
        "disposition": "REGISTRY_CANDIDATE_PROPOSED",
        "reason_code": reason_code,
        "proposal_id": proposal["proposal_id"],
        "producer_identity": _single_or_list(item["producer_identities"]),
        "assessor_identity": policy_assessment["assessor_id"],
        "assessor_invocation_id": policy_assessment[
            "assessor_invocation_id"
        ],
        "assessor_evidence_sha256": policy_assessment["evidence_sha256"],
        "assessor_evidence": "",
        "proof_scope": "NONE",
        "terminal_negative_authorized": False,
    }


def adjudicate_application_skeptic(
    plan: Mapping[str, Any],
    assessments: Iterable[Mapping[str, Any]],
    *,
    prior_receipt: Mapping[str, Any] | None = None,
    candidate_sink: Callable[[dict[str, Any]], Any] | None = None,
    defer_missing: bool = False,
    model_invoked: bool | None = None,
    closure_authorities: Mapping[str, Mapping[str, Any]] | None = None,
    closure_provider_validator: Callable[
        [Mapping[str, Any]], Mapping[str, Any]
    ]
    | None = None,
    closure_authority: Any = None,
) -> dict[str, Any]:
    """Apply independent assessments with exact input-to-disposition parity."""

    _validate_plan(plan)
    plan_digest = plan["work_plan_digest"]
    items = {item["work_item_id"]: item for item in plan["work_items"]}
    dispositions, proposals, rejected_candidate_debt = _prior_dispositions(
        prior_receipt, plan_digest
    )
    unknown_completed = set(dispositions) - set(items)
    if unknown_completed:
        raise ApplicationSkepticError("prior receipt contains work absent from plan")

    assessment_map: dict[str, Mapping[str, Any]] = {}
    for assessment in assessments:
        if not isinstance(assessment, Mapping):
            raise ApplicationSkepticError("skeptic assessment must be an object")
        work_id = _text(assessment.get("work_item_id"))
        if work_id not in items:
            raise ApplicationSkepticError(f"assessment has unknown work item {work_id!r}")
        if work_id in dispositions:
            raise ApplicationSkepticError(
                f"completed work item {work_id!r} cannot be re-adjudicated"
            )
        if work_id in assessment_map:
            raise ApplicationSkepticError(f"duplicate assessment for {work_id!r}")
        assessment_map[work_id] = assessment

    for work_id in [item["work_item_id"] for item in plan["work_items"]]:
        if work_id in dispositions:
            continue
        item = items[work_id]
        assessment = assessment_map.get(work_id)
        if assessment is None:
            if defer_missing:
                continue
            dispositions[work_id] = _deliver_policy_reopen_or_review(
                item,
                plan_digest=plan_digest,
                reason_code="ASSESSMENT_UNAVAILABLE",
                detail="no independent assessment received",
                assessment=None,
                candidate_sink=candidate_sink,
                proposals=proposals,
                rejected_candidate_debt=rejected_candidate_debt,
            )
            continue

        assessment = dict(assessment)
        assessor = _text(assessment.get("assessor_id"))
        invocation = _text(assessment.get("assessor_invocation_id"))
        outcome = _text(assessment.get("outcome")).upper()
        evidence_basis = _text(assessment.get("evidence_basis")).upper()
        evidence_hash = _text(assessment.get("evidence_sha256")).casefold()
        if not assessor or not invocation:
            dispositions[work_id] = _deliver_policy_reopen_or_review(
                item,
                plan_digest=plan_digest,
                reason_code="ASSESSOR_IDENTITY_MISSING",
                detail="assessor identity or invocation is absent",
                assessment=assessment,
                candidate_sink=candidate_sink,
                proposals=proposals,
                rejected_candidate_debt=rejected_candidate_debt,
            )
            continue
        if (
            assessor in item["producer_identities"]
            or invocation in item["producer_invocation_ids"]
        ):
            dispositions[work_id] = _deliver_policy_reopen_or_review(
                item,
                plan_digest=plan_digest,
                reason_code="SELF_ADJUDICATION",
                detail="producer and assessor identity are not independent",
                assessment=assessment,
                candidate_sink=candidate_sink,
                proposals=proposals,
                rejected_candidate_debt=rejected_candidate_debt,
            )
            continue

        reopened_support = False
        central_closure_resolution: Mapping[str, Any] | None = None
        legacy_closure_authority: Mapping[str, Any] | None = None
        if outcome == "AGREE_NEGATIVE":
            legacy_closure_authority = (closure_authorities or {}).get(work_id)
            try:
                authorized, policy_reason = terminal_negative_authorized(
                    work_item=item,
                    assessment=assessment,
                    authority=legacy_closure_authority,
                    provider_validator=closure_provider_validator,
                    closure_authority=closure_authority,
                    requested_effect="REFUTED_FULL",
                )
            except Exception as exc:
                authorized = False
                policy_reason = (
                    "NEGATIVE_CLOSURE_PROVIDER_FAILED_"
                    f"{type(exc).__name__.upper()}"
                )
            if not authorized:
                outcome = "DISAGREE_CANDIDATE"
                assessment["outcome"] = outcome
                assessment["candidate"] = dict(item["reopen_candidate_seed"])
                rationale = _text(assessment.get("rationale"))
                assessment["rationale"] = (
                    f"{policy_reason}: terminal negative authority unavailable"
                    + (f"; {rationale}" if rationale else "")
                )
                reopened_support = True
            elif closure_authority is not None:
                # The broker decision, not the assessor prose or legacy v1
                # mapping, is the sole terminal-negative receipt.  Resolve it
                # again here so the durable consumer row carries the exact
                # content-addressed authority used for this transition.
                central_closure_resolution = resolve_central_negative_closure(
                    closure_authority,
                    work_item=item,
                    requested_effect="REFUTED_FULL",
                )

        if outcome == "AGREE_NEGATIVE":
            if not _valid_digest(evidence_hash):
                dispositions[work_id] = _deliver_policy_reopen_or_review(
                    item,
                    plan_digest=plan_digest,
                    reason_code="ASSESSOR_EVIDENCE_INVALID",
                    detail="terminal assessment evidence digest is invalid",
                    assessment=assessment,
                    candidate_sink=candidate_sink,
                    proposals=proposals,
                    rejected_candidate_debt=rejected_candidate_debt,
                )
                continue
            dispositions[work_id] = {
                "work_item_id": work_id,
                "obligation_id": item["obligation_id"],
                "input_row_ids": list(item["input_row_ids"]),
                "disposition": "NEGATIVE_AGREEMENT",
                "reason_code": "INDEPENDENT_NEGATIVE_SUPPORTED",
                "producer_identity": _single_or_list(item["producer_identities"]),
                "producer_invocation_id": _single_or_list(
                    item["producer_invocation_ids"]
                ),
                "assessor_identity": assessor,
                "assessor_invocation_id": invocation,
                "original_evidence_sha256": item["original_evidence_sha256"],
                "assessor_evidence_sha256": evidence_hash,
                "assessor_evidence": _text(assessment.get("evidence")),
                "assessor_evidence_basis": evidence_basis,
                "rationale": _text(assessment.get("rationale")),
                "negative_closure_authority_digest": _text(
                    (central_closure_resolution or {}).get("resolution_digest")
                ),
                "negative_closure_provider_completion_sha256": _text(
                    (central_closure_resolution or {}).get(
                        "provider_completion_sha256"
                    )
                ),
                "negative_closure_provider_publish_sha256": _text(
                    (central_closure_resolution or {}).get(
                        "provider_publish_sha256"
                    )
                ),
            }
        elif outcome == "DISAGREE_CANDIDATE":
            if not _valid_digest(evidence_hash):
                dispositions[work_id] = _deliver_policy_reopen_or_review(
                    item,
                    plan_digest=plan_digest,
                    reason_code="ASSESSOR_EVIDENCE_INVALID",
                    detail="candidate assessment evidence digest is invalid",
                    assessment=assessment,
                    candidate_sink=candidate_sink,
                    proposals=proposals,
                    rejected_candidate_debt=rejected_candidate_debt,
                )
                continue
            try:
                proposal = _candidate_proposal(item, assessment)
            except CandidateSchemaError as exc:
                rejected_candidate_debt.append(
                    _rejected_candidate_debt(item, assessment, exc.reasons)
                )
                dispositions[work_id] = _deliver_policy_reopen_or_review(
                    item,
                    plan_digest=plan_digest,
                    reason_code="CANDIDATE_SCHEMA_REJECTED",
                    detail=str(exc),
                    assessment=assessment,
                    candidate_sink=candidate_sink,
                    proposals=proposals,
                    rejected_candidate_debt=rejected_candidate_debt,
                )
                continue
            except Exception as exc:
                rejected_candidate_debt.append(
                    _rejected_candidate_debt(
                        item,
                        assessment,
                        (f"candidate normalization failed: {type(exc).__name__}: {exc}",),
                    )
                )
                dispositions[work_id] = _deliver_policy_reopen_or_review(
                    item,
                    plan_digest=plan_digest,
                    reason_code="CANDIDATE_SCHEMA_REJECTED",
                    detail=str(exc),
                    assessment=assessment,
                    candidate_sink=candidate_sink,
                    proposals=proposals,
                    rejected_candidate_debt=rejected_candidate_debt,
                )
                continue
            if candidate_sink is None:
                dispositions[work_id] = _debt_disposition(
                    item,
                    "REGISTRY_SINK_UNAVAILABLE",
                    "independent disagreement candidate was not delivered",
                    work_plan_digest=plan_digest,
                )
                continue
            try:
                candidate_sink(proposal)
            except Exception as exc:
                rejected_candidate_debt.append(
                    _rejected_candidate_debt(
                        item,
                        assessment,
                        (f"registry sink rejected proposal: {type(exc).__name__}: {exc}",),
                    )
                )
                dispositions[work_id] = _debt_disposition(
                    item,
                    "REGISTRY_DELIVERY_FAILED",
                    str(exc),
                    work_plan_digest=plan_digest,
                )
                continue
            proposals.append(proposal)
            dispositions[work_id] = {
                "work_item_id": work_id,
                "obligation_id": item["obligation_id"],
                "input_row_ids": list(item["input_row_ids"]),
                "disposition": "REGISTRY_CANDIDATE_PROPOSED",
                "reason_code": (
                    "NONTERMINAL_NEGATIVE_SUPPORT_REOPENED"
                    if reopened_support
                    else "INDEPENDENT_DISAGREEMENT"
                ),
                "proposal_id": proposal["proposal_id"],
                "producer_identity": _single_or_list(item["producer_identities"]),
                "assessor_identity": assessor,
                "assessor_invocation_id": invocation,
                "assessor_evidence_sha256": evidence_hash,
                "assessor_evidence": _text(assessment.get("evidence")),
                "proof_scope": "NONE",
                "terminal_negative_authorized": False,
            }
        elif outcome in {"UNAVAILABLE", "INCONCLUSIVE"}:
            dispositions[work_id] = _deliver_policy_reopen_or_review(
                item,
                plan_digest=plan_digest,
                reason_code=f"ASSESSOR_{outcome}",
                detail=_text(assessment.get("rationale")),
                assessment=assessment,
                candidate_sink=candidate_sink,
                proposals=proposals,
                rejected_candidate_debt=rejected_candidate_debt,
            )
        else:
            dispositions[work_id] = _deliver_policy_reopen_or_review(
                item,
                plan_digest=plan_digest,
                reason_code="ASSESSMENT_OUTCOME_INVALID",
                detail=outcome,
                assessment=assessment,
                candidate_sink=candidate_sink,
                proposals=proposals,
                rejected_candidate_debt=rejected_candidate_debt,
            )

    ordered_dispositions = [
        dispositions[item["work_item_id"]]
        for item in plan["work_items"]
        if item["work_item_id"] in dispositions
    ]
    input_dispositions = sorted(
        (
            {
                "input_row_id": input_row_id,
                "work_item_id": row["work_item_id"],
                "disposition": row["disposition"],
            }
            for row in ordered_dispositions
            for input_row_id in row["input_row_ids"]
        ),
        key=lambda row: row["input_row_id"],
    )
    pending = [work_id for work_id in items if work_id not in dispositions]
    unresolved = sorted(
        row["work_item_id"]
        for row in ordered_dispositions
        if row["disposition"] == "UNRESOLVED_DEBT"
    )
    if plan["status"] == "NOT_TRIGGERED" and not items:
        status = "NOT_TRIGGERED"
    elif pending:
        status = "PARTIAL"
    elif unresolved or plan["status"] == "INPUT_DEBT":
        status = "COMPLETED_WITH_DEBT"
    else:
        status = "COMPLETE"
    unsigned_receipt = {
        "schema_version": RECEIPT_SCHEMA,
        "status": status,
        "work_plan_digest": plan_digest,
        "model_invoked": (
            bool(model_invoked)
            if model_invoked is not None
            else bool(assessment_map)
            or bool((prior_receipt or {}).get("model_invoked"))
        ),
        "work_dispositions": ordered_dispositions,
        "input_dispositions": input_dispositions,
        "pending_work_item_ids": pending,
        "unresolved_work_item_ids": unresolved,
        "source_input_issues": list(plan.get("issues", [])),
        "registry_candidate_proposals": sorted(
            proposals, key=lambda proposal: proposal["proposal_id"]
        ),
        "rejected_candidate_debt": sorted(
            rejected_candidate_debt,
            key=lambda row: (
                str(row.get("work_item_id")),
                str(row.get("candidate_sha256")),
            ),
        ),
    }
    return {**unsigned_receipt, "receipt_digest": _digest(unsigned_receipt)}


def write_application_skeptic_receipt(
    scratchpad: Path,
    receipt: Mapping[str, Any],
) -> None:
    _write_json_if_changed(Path(scratchpad) / RECEIPT_FILE, receipt)


def _application_source_binding_sha256(plan: Mapping[str, Any]) -> str:
    _validate_plan(plan)
    source_identity = {
        "work_plan_digest": plan["work_plan_digest"],
        "source_queues": plan.get("source_queues", {}),
        "work_items": [
            {
                "work_item_id": item["work_item_id"],
                "obligation_id": item["obligation_id"],
                "binding_digest": _text(item.get("binding_digest")).casefold(),
                "input_row_ids": list(item.get("input_row_ids") or []),
                "source_queues": list(item.get("source_queues") or []),
                "methodology_sha256": _text(
                    item.get("methodology_sha256")
                ).casefold(),
                "original_evidence_sha256": _text(
                    item.get("original_evidence_sha256")
                ).casefold(),
            }
            for item in plan["work_items"]
        ],
    }
    return _digest(source_identity)


def build_application_skeptic_preservation_context(
    plan: Mapping[str, Any],
    *,
    run_id: str,
    snapshot_id: str,
    snapshot_binding_sha256: str,
) -> dict[str, Any]:
    """Bind a resumable proposal cache to one exact run/snapshot/source set."""

    _validate_plan(plan)
    run = _text(run_id)
    snapshot = _text(snapshot_id)
    snapshot_sha = _text(snapshot_binding_sha256).casefold()
    if not run or not snapshot:
        raise ApplicationSkepticError(
            "preservation run and snapshot identities must be non-empty"
        )
    if len(run.encode("utf-8")) > 256 or len(snapshot.encode("utf-8")) > 256:
        raise ApplicationSkepticError(
            "preservation run or snapshot identity exceeds 256 bytes"
        )
    if not _valid_digest(snapshot_sha):
        raise ApplicationSkepticError(
            "preservation snapshot binding must be a SHA-256 digest"
        )
    unsigned = {
        "schema_version": PRESERVATION_CONTEXT_SCHEMA,
        "run_id": run,
        "snapshot_id": snapshot,
        "snapshot_binding_sha256": snapshot_sha,
        "source_binding_sha256": _application_source_binding_sha256(plan),
        "work_plan_digest": plan["work_plan_digest"],
    }
    return {**unsigned, "context_digest": _digest(unsigned)}


def _validate_preservation_context(
    plan: Mapping[str, Any], context: Mapping[str, Any]
) -> dict[str, Any]:
    expected = {
        "schema_version",
        "run_id",
        "snapshot_id",
        "snapshot_binding_sha256",
        "source_binding_sha256",
        "work_plan_digest",
        "context_digest",
    }
    if not isinstance(context, Mapping) or set(context) != expected:
        raise ApplicationSkepticError("preservation context fields are not exact")
    rebuilt = build_application_skeptic_preservation_context(
        plan,
        run_id=context.get("run_id"),
        snapshot_id=context.get("snapshot_id"),
        snapshot_binding_sha256=context.get("snapshot_binding_sha256"),
    )
    if dict(context) != rebuilt:
        raise ApplicationSkepticError(
            "preservation context does not bind the current plan/source bytes"
        )
    return rebuilt


def _validate_application_receipt_for_preservation(
    plan: Mapping[str, Any], receipt: Mapping[str, Any]
) -> dict[str, Any]:
    _validate_plan(plan)
    if not isinstance(receipt, Mapping):
        raise ApplicationSkepticError("application-skeptic receipt must be an object")
    if receipt.get("schema_version") != RECEIPT_SCHEMA:
        raise ApplicationSkepticError("application-skeptic receipt schema mismatch")
    if receipt.get("work_plan_digest") != plan["work_plan_digest"]:
        raise ApplicationSkepticError(
            "application-skeptic receipt binds another work plan"
        )
    unsigned = {key: value for key, value in receipt.items() if key != "receipt_digest"}
    if receipt.get("receipt_digest") != _digest(unsigned):
        raise ApplicationSkepticError("application-skeptic receipt digest mismatch")
    known = {item["work_item_id"] for item in plan["work_items"]}
    rows: dict[str, dict[str, Any]] = {}
    for raw in receipt.get("work_dispositions", []):
        if not isinstance(raw, Mapping):
            raise ApplicationSkepticError(
                "application-skeptic receipt disposition is malformed"
            )
        work_id = _text(raw.get("work_item_id"))
        if work_id not in known or work_id in rows:
            raise ApplicationSkepticError(
                "application-skeptic receipt disposition identity is invalid"
            )
        rows[work_id] = dict(raw)
    proposals: dict[str, dict[str, Any]] = {}
    for raw in receipt.get("registry_candidate_proposals", []):
        proposal = normalize_application_skeptic_proposal(raw)
        proposal_id = _text(proposal.get("proposal_id"))
        if proposal_id in proposals:
            raise ApplicationSkepticError(
                "application-skeptic receipt duplicates proposal identity"
            )
        proposals[proposal_id] = proposal
    disposition_proposals = {
        _text(row.get("proposal_id"))
        for row in rows.values()
        if _text(row.get("disposition")).upper()
        == "REGISTRY_CANDIDATE_PROPOSED"
    }
    if disposition_proposals != set(proposals):
        raise ApplicationSkepticError(
            "application-skeptic disposition/proposal parity mismatch"
        )
    return dict(receipt)


def build_application_skeptic_delivery_binding(
    plan: Mapping[str, Any],
    receipt: Mapping[str, Any],
    *,
    context: Mapping[str, Any],
    proposal_projection_sha256: str,
    delivered_proposal_ids: Sequence[str],
) -> dict[str, Any]:
    """Attest which additive proposal identities were actually projected."""

    validated_receipt = _validate_application_receipt_for_preservation(plan, receipt)
    validated_context = _validate_preservation_context(plan, context)
    projection_sha = _text(proposal_projection_sha256).casefold()
    if not _valid_digest(projection_sha):
        raise ApplicationSkepticError(
            "proposal projection binding must be a SHA-256 digest"
        )
    delivered = [_text(value) for value in delivered_proposal_ids]
    if any(not value for value in delivered) or delivered != sorted(set(delivered)):
        raise ApplicationSkepticError(
            "delivered proposal identities must be sorted, unique, and non-empty"
        )
    expected = sorted(
        _text(row.get("proposal_id"))
        for row in validated_receipt.get("registry_candidate_proposals", [])
    )
    if delivered != expected:
        raise ApplicationSkepticError(
            "delivery binding does not cover the exact additive proposal set"
        )
    unsigned = {
        "schema_version": DELIVERY_BINDING_SCHEMA,
        "context_digest": validated_context["context_digest"],
        "work_plan_digest": plan["work_plan_digest"],
        "receipt_digest": validated_receipt["receipt_digest"],
        "proposal_projection_sha256": projection_sha,
        "delivered_proposal_ids": delivered,
    }
    return {**unsigned, "delivery_binding_digest": _digest(unsigned)}


def preserve_last_good_application_candidates(
    plan: Mapping[str, Any],
    *,
    current_receipt: Mapping[str, Any],
    last_good_receipt: Mapping[str, Any] | None,
    current_context: Mapping[str, Any],
    last_good_delivery: Mapping[str, Any] | None,
) -> tuple[dict[str, Any], bool]:
    """Retain only exact, previously delivered additive proposals after debt.

    No text or verdict is matched.  A preserved proposal must bind the same
    work plan, source bytes, run, and snapshot as the current attempt, and its
    exact proposal identity must be present in a digest-bound delivery record.
    Prior terminal-negative dispositions are deliberately never cacheable.
    """

    try:
        current = _validate_application_receipt_for_preservation(
            plan, current_receipt
        )
        context = _validate_preservation_context(plan, current_context)
        if (
            last_good_receipt is None
            or last_good_delivery is None
            or not isinstance(last_good_delivery, Mapping)
        ):
            return current, False
        prior = _validate_application_receipt_for_preservation(
            plan, last_good_receipt
        )
        expected_delivery = build_application_skeptic_delivery_binding(
            plan,
            prior,
            context=context,
            proposal_projection_sha256=last_good_delivery.get(
                "proposal_projection_sha256"
            ),
            delivered_proposal_ids=last_good_delivery.get(
                "delivered_proposal_ids"
            )
            or [],
        )
        if dict(last_good_delivery) != expected_delivery:
            return current, False
    except Exception:
        # Preservation is an additive availability optimization.  Invalid or
        # tampered cache metadata can never halt the policy boundary and can
        # never authorize closure; the current typed debt remains authoritative.
        return dict(current_receipt), False

    prior_rows = {
        _text(row.get("work_item_id")): dict(row)
        for row in prior.get("work_dispositions", [])
        if isinstance(row, Mapping)
        and _text(row.get("disposition")).upper()
        == "REGISTRY_CANDIDATE_PROPOSED"
    }
    prior_proposals = {
        _text(row.get("proposal_id")): dict(row)
        for row in prior.get("registry_candidate_proposals", [])
        if isinstance(row, Mapping)
    }
    delivered_ids = set(last_good_delivery.get("delivered_proposal_ids") or [])
    current_rows = [
        dict(row)
        for row in current.get("work_dispositions", [])
        if isinstance(row, Mapping)
    ]
    selected: dict[str, dict[str, Any]] = {}
    changed = False
    for index, row in enumerate(current_rows):
        if _text(row.get("disposition")).upper() != "UNRESOLVED_DEBT":
            continue
        prior_row = prior_rows.get(_text(row.get("work_item_id")))
        if prior_row is None:
            continue
        proposal_id = _text(prior_row.get("proposal_id"))
        proposal = prior_proposals.get(proposal_id)
        if proposal is None or proposal_id not in delivered_ids:
            continue
        current_rows[index] = prior_row
        selected[proposal_id] = proposal
        changed = True
    if not changed:
        return current, False

    proposals = {
        _text(row.get("proposal_id")): dict(row)
        for row in current.get("registry_candidate_proposals", [])
        if isinstance(row, Mapping) and _text(row.get("proposal_id"))
    }
    proposals.update(selected)
    input_dispositions = sorted(
        (
            {
                "input_row_id": input_id,
                "work_item_id": row["work_item_id"],
                "disposition": row["disposition"],
            }
            for row in current_rows
            for input_id in row.get("input_row_ids", [])
        ),
        key=lambda row: row["input_row_id"],
    )
    unresolved = sorted(
        _text(row.get("work_item_id"))
        for row in current_rows
        if _text(row.get("disposition")).upper() == "UNRESOLVED_DEBT"
    )
    source_issues = [
        dict(row) if isinstance(row, Mapping) else {"code": _text(row)}
        for row in current.get("source_input_issues", [])
    ]
    source_issues.append(
        {
            "code": "LAST_GOOD_ADDITIVE_CANDIDATE_PRESERVED",
            "context_digest": context["context_digest"],
            "delivery_binding_digest": last_good_delivery[
                "delivery_binding_digest"
            ],
            "preserved_proposal_ids": sorted(selected),
            "proof_scope": "NONE",
            "terminal_negative_authorized": False,
        }
    )
    unsigned = {
        **{
            key: value
            for key, value in current.items()
            if key
            not in {
                "receipt_digest",
                "status",
                "work_dispositions",
                "input_dispositions",
                "unresolved_work_item_ids",
                "source_input_issues",
                "registry_candidate_proposals",
            }
        },
        "status": "COMPLETED_WITH_DEBT",
        "work_dispositions": current_rows,
        "input_dispositions": input_dispositions,
        "unresolved_work_item_ids": unresolved,
        "source_input_issues": source_issues,
        "registry_candidate_proposals": [
            proposals[key] for key in sorted(proposals)
        ],
    }
    return {**unsigned, "receipt_digest": _digest(unsigned)}, True


__all__ = [
    "ASSESSMENT_SCHEMA",
    "ApplicationSkepticError",
    "DELIVERY_BINDING_SCHEMA",
    "DEFAULT_QUEUE_PHASES",
    "MANDATORY_REVIEW_SCHEMA",
    "PRESERVATION_CONTEXT_SCHEMA",
    "RECEIPT_FILE",
    "RECEIPT_SCHEMA",
    "SUPPORTED_NEGATIVE_EVIDENCE",
    "WORK_PLAN_FILE",
    "WORK_PLAN_SCHEMA",
    "adjudicate_application_skeptic",
    "build_application_skeptic_delivery_binding",
    "build_application_skeptic_preservation_context",
    "build_application_skeptic_shard_prompt",
    "build_application_skeptic_work_plan",
    "pending_work_item_ids",
    "preserve_last_good_application_candidates",
    "load_application_skeptic_assessments",
    "read_bound_methodology_bytes",
    "write_application_skeptic_receipt",
    "write_application_skeptic_work_plan",
]
