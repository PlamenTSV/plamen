"""Typed P0-B/C/D methodology-application states and bounded queues.

The row is the semantic authority.  Legacy ``disposition`` strings and
Markdown gap tables are compatibility projections only.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
from typing import Any, Iterable, NamedTuple
import uuid


RECEIPT_SCHEMA = "plamen.skill_application_receipt.v2"
REPAIR_QUEUE_SCHEMA = "plamen.methodology_repair_queue.v2"
SKEPTIC_QUEUE_SCHEMA = "plamen.methodology_skeptic_queue.v2"

DELIVERY_INTEGRITY = frozenset({"CURRENT", "INVALID", "UNKNOWN"})
APPLICATION_COMPLETENESS = frozenset({"APPLIED", "MISSING", "INVALID", "UNKNOWN"})
SEMANTIC_OUTCOMES = frozenset(
    {"CANDIDATE", "NEGATIVE", "NOT_APPLICABLE", "INCONCLUSIVE"}
)
EVIDENCE_BASES = frozenset(
    {
        "IN_SCOPE_SOURCE",
        "IN_SCOPE_EXECUTION",
        "PRIMARY_EXTERNAL_CITED",
        "EXTERNAL_UNRESEARCHED",
        "NONE",
    }
)
NEGATIVE_CLOSURE_BASES = frozenset(
    {"IN_SCOPE_SOURCE", "IN_SCOPE_EXECUTION", "PRIMARY_EXTERNAL_CITED"}
)
TRACE_STATES = frozenset({"VALID", "MISSING", "INVALID", "UNKNOWN"})

_HEX_RE = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
_GENERIC_RESULT_RE = re.compile(
    r"(?i)^\s*(?:executed|checked|applied|reviewed|done|complete|completed|"
    r"safe|no\s+(?:issue|issues|finding|findings)|not\s+applicable|n/?a|"
    r"method(?:ology)?\s+(?:executed|applied|checked))\s*[.!]?\s*$"
)
_NEGATIVE_RESULT_RE = re.compile(
    r"(?i)^\s*(?:safe|no[_ -]?finding|no\s+(?:issue|issues|findings?))\s*[:\-]"
)
_NA_RESULT_RE = re.compile(r"(?i)^\s*(?:not\s+applicable|n/?a)\s*[.!]?\s*$")
_EXTERNAL_LANGUAGE_RE = re.compile(
    r"(?i)\b(?:factory|deployer|out[- ]of[- ]scope|external|assum(?:e|ed|ption)|"
    r"guaranteed|third[- ]party|off[- ]chain)\b"
)


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


def _text(value: Any) -> str:
    return str(value or "").strip()


def _obligation_identity(row: dict[str, Any]) -> str:
    semantic = {
        "phase": re.sub(r"_repair$", "", _text(row.get("phase")).casefold()),
        # The scheduled producer slot is part of the obligation.  Two
        # independent producers assigned the same method/step are redundancy,
        # not duplicate rows.  A repair attempt preserves the source
        # obligation_id explicitly rather than deriving a new identity.
        "worker_id": _text(row.get("worker_id")).casefold(),
        "output": Path(_text(row.get("output"))).as_posix().casefold(),
        "skill": _text(row.get("skill")).casefold(),
        "methodology_path": Path(_text(row.get("methodology_path"))).as_posix().casefold(),
        "methodology_sha256": _text(row.get("methodology_sha256")).casefold(),
        "step": _text(row.get("step")).casefold(),
    }
    return "MAO-" + _digest(semantic)[:20].upper()


def _finalize_row(row: dict[str, Any]) -> dict[str, Any]:
    out = dict(row)
    out["obligation_id"] = _text(out.get("obligation_id")) or _obligation_identity(out)
    unsigned = {key: value for key, value in out.items() if key != "row_digest"}
    out["row_digest"] = _digest(unsigned)
    return out


def _row_digest_is_valid(row: dict[str, Any]) -> bool:
    claimed = row.get("row_digest")
    unsigned = {key: value for key, value in row.items() if key != "row_digest"}
    return isinstance(claimed, str) and bool(_HEX_RE.fullmatch(claimed)) and claimed == _digest(unsigned)


def classify_application_row(raw: dict[str, Any]) -> dict[str, Any]:
    """Classify delivery, application, outcome, and evidence independently."""

    if not isinstance(raw, dict):
        raise TypeError("application row must be an object")
    delivery = _text(raw.get("delivery_integrity") or "UNKNOWN").upper()
    trace_state = _text(raw.get("trace_state") or "UNKNOWN").upper()
    evidence_basis = _text(raw.get("evidence_basis") or "NONE").upper()
    if delivery not in DELIVERY_INTEGRITY:
        raise ValueError(f"invalid delivery_integrity: {delivery!r}")
    if trace_state not in TRACE_STATES:
        raise ValueError(f"invalid trace_state: {trace_state!r}")
    if evidence_basis not in EVIDENCE_BASES:
        raise ValueError(f"invalid evidence_basis: {evidence_basis!r}")

    executed = _text(raw.get("executed")).casefold()
    evidence = _text(raw.get("evidence"))
    result = _text(raw.get("result"))
    generic = bool(_GENERIC_RESULT_RE.fullmatch(result))

    if delivery == "INVALID":
        application = "INVALID"
    elif delivery == "UNKNOWN" and trace_state == "UNKNOWN":
        application = "UNKNOWN"
    elif trace_state == "MISSING":
        application = "MISSING"
    elif trace_state == "INVALID":
        application = "INVALID"
    elif generic:
        application = "INVALID"
    elif trace_state == "VALID" and executed in {
        "yes", "safe", "not_applicable", "not applicable", "n/a", "na"
    } and result:
        application = "APPLIED"
    elif trace_state == "VALID":
        application = "MISSING"
    else:
        application = "UNKNOWN"

    if application != "APPLIED":
        outcome = "INCONCLUSIVE"
    elif executed in {"not_applicable", "not applicable", "n/a", "na"} or _NA_RESULT_RE.fullmatch(result):
        outcome = "NOT_APPLICABLE"
    elif executed == "safe" or _NEGATIVE_RESULT_RE.search(result):
        outcome = "NEGATIVE"
    else:
        outcome = "CANDIDATE"

    if evidence_basis == "NONE" and _EXTERNAL_LANGUAGE_RE.search(
        evidence + "\n" + result
    ):
        evidence_basis = "EXTERNAL_UNRESEARCHED"

    skeptic_required = outcome in {"NEGATIVE", "NOT_APPLICABLE"}
    closure_eligible = bool(
        outcome in {"NEGATIVE", "NOT_APPLICABLE"}
        and evidence_basis in NEGATIVE_CLOSURE_BASES
    )
    if skeptic_required and not closure_eligible:
        skeptic_reason = "UNSUPPORTED_NEGATIVE_CLEAR"
    elif skeptic_required:
        skeptic_reason = "AUTHOR_NEGATIVE_REQUIRES_INDEPENDENT_REVIEW"
    else:
        skeptic_reason = ""

    if application in {"MISSING", "INVALID"}:
        compatibility_disposition = "GAP"
    elif application == "APPLIED":
        compatibility_disposition = "ATTESTED"
    else:
        compatibility_disposition = "UNKNOWN"

    row = {
        "phase": _text(raw.get("phase")),
        "worker_id": _text(raw.get("worker_id")),
        "producer_invocation_id": _text(raw.get("producer_invocation_id")),
        "output": _text(raw.get("output")),
        "output_sha256": _text(raw.get("output_sha256")).casefold(),
        "prompt_sha256": _text(raw.get("prompt_sha256")).casefold(),
        "dispatch_contract_sha256": _text(
            raw.get("dispatch_contract_sha256")
        ).casefold(),
        "skill": _text(raw.get("skill")),
        "methodology_path": Path(_text(raw.get("methodology_path"))).as_posix(),
        "methodology_sha256": _text(raw.get("methodology_sha256")).casefold(),
        "step": _text(raw.get("step")),
        "delivery_integrity": delivery,
        "application_completeness": application,
        "semantic_outcome": outcome,
        "evidence_basis": evidence_basis,
        "skeptic_required": skeptic_required,
        "skeptic_reason": skeptic_reason,
        "negative_closure_eligible": closure_eligible,
        # Compatibility only.  Deterministic consumers must use the orthogonal
        # fields above; legacy driver/report readers may project this value.
        "disposition": compatibility_disposition,
        "executed": executed,
        "evidence": evidence,
        "result": result,
        "original_evidence": evidence,
        "original_result": result,
        "reason": _text(raw.get("reason")),
    }
    if _text(raw.get("obligation_id")):
        row["obligation_id"] = _text(raw.get("obligation_id"))
    return _finalize_row(row)


def _queue_payload(rows: Iterable[dict[str, Any]], *, phase: str, kind: str) -> dict[str, Any]:
    if kind not in {"repair", "skeptic"}:
        raise ValueError("queue kind must be repair or skeptic")
    by_id: dict[str, dict[str, Any]] = {}
    conflicts: list[dict[str, str]] = []
    for raw in rows:
        row = dict(raw)
        obligation = _text(row.get("obligation_id")) or _obligation_identity(row)
        row["obligation_id"] = obligation
        prior = by_id.get(obligation)
        if prior is None:
            by_id[obligation] = row
        elif prior.get("row_digest") != row.get("row_digest"):
            conflicts.append(
                {
                    "code": "CONFLICTING_DUPLICATE_OBLIGATION",
                    "obligation_id": obligation,
                    "first_row_digest": _text(prior.get("row_digest")),
                    "second_row_digest": _text(row.get("row_digest")),
                }
            )
    ordered = [by_id[key] for key in sorted(by_id)]
    schema = REPAIR_QUEUE_SCHEMA if kind == "repair" else SKEPTIC_QUEUE_SCHEMA
    unsigned = {
        "schema_version": schema,
        "phase": phase,
        "queue_kind": kind.upper(),
        "row_count": len(ordered),
        "rows": ordered,
        "issues": sorted(conflicts, key=lambda item: item["obligation_id"]),
    }
    return {**unsigned, "queue_digest": _digest(unsigned)}


class ApplicationQueues(NamedTuple):
    repair: dict[str, Any]
    skeptic: dict[str, Any]


def build_application_queues(
    states: Iterable[dict[str, Any]], *, phase: str
) -> ApplicationQueues:
    rows = list(states)
    for row in rows:
        if not isinstance(row, dict) or not _row_digest_is_valid(row):
            raise ValueError("application state row digest mismatch")
    repair = [
        row
        for row in rows
        if row.get("application_completeness") in {"MISSING", "INVALID"}
    ]
    skeptic = [row for row in rows if row.get("skeptic_required") is True]
    return ApplicationQueues(
        repair=_queue_payload(repair, phase=phase, kind="repair"),
        skeptic=_queue_payload(skeptic, phase=phase, kind="skeptic"),
    )


def build_application_receipt(
    states: Iterable[dict[str, Any]],
    *,
    phase: str,
    dispatch_sha256: str = "",
    status: str | None = None,
    reason: str = "",
    assurance: str = "PRODUCER_ATTESTATION_ONLY",
) -> dict[str, Any]:
    """Build the deterministic authoritative receipt over orthogonal states."""

    rows = sorted((dict(row) for row in states), key=lambda row: row["obligation_id"])
    for row in rows:
        if not _row_digest_is_valid(row):
            raise ValueError("application state row digest mismatch")
    identities = [row["obligation_id"] for row in rows]
    if len(identities) != len(set(identities)):
        raise ValueError("application receipt duplicates an obligation identity")
    repair = [
        row
        for row in rows
        if row.get("application_completeness") in {"MISSING", "INVALID"}
    ]
    unknown = [
        row
        for row in rows
        if row.get("application_completeness") == "UNKNOWN"
    ]
    skeptics = [row for row in rows if row.get("skeptic_required") is True]
    applied = [
        row for row in rows if row.get("application_completeness") == "APPLIED"
    ]
    author_closed = [
        row
        for row in applied
        if row.get("semantic_outcome") == "CANDIDATE"
        and row.get("skeptic_required") is not True
    ]
    if status is None:
        if repair:
            status = "GAPS"
        elif skeptics:
            status = "SKEPTIC_PENDING"
        elif rows:
            status = "ATTESTED"
        else:
            status = "NOT_APPLICABLE"
    unsigned = {
        "schema_version": RECEIPT_SCHEMA,
        "phase": _text(phase),
        "dispatch_sha256": _text(dispatch_sha256).casefold(),
        "status": _text(status).upper(),
        "assurance": _text(assurance),
        "attestation_is_proof": False,
        "reason": _text(reason),
        "expected_steps": len(rows),
        "applied_steps": len(applied),
        # Author-negative work cannot count as closed before independent review.
        "closed_steps": len(author_closed),
        # gap_steps is retained for compatibility and includes unmeasurable
        # debt.  repair_steps is the only repair-routing authority.
        "gap_steps": len(repair) + len(unknown),
        "repair_steps": len(repair),
        "unknown_steps": len(unknown),
        "skeptic_steps": len(skeptics),
        "rows": rows,
    }
    return {**unsigned, "receipt_digest": _digest(unsigned)}


def validate_queue_payload(payload: dict[str, Any], *, expected_kind: str) -> None:
    if not isinstance(payload, dict):
        raise TypeError("application queue must be an object")
    schema = REPAIR_QUEUE_SCHEMA if expected_kind == "repair" else SKEPTIC_QUEUE_SCHEMA
    if payload.get("schema_version") != schema:
        raise ValueError("application queue schema mismatch")
    if payload.get("queue_kind") != expected_kind.upper():
        raise ValueError("application queue kind mismatch")
    rows = payload.get("rows")
    if not isinstance(rows, list) or payload.get("row_count") != len(rows):
        raise ValueError("application queue row_count mismatch")
    unsigned = {key: value for key, value in payload.items() if key != "queue_digest"}
    if payload.get("queue_digest") != _digest(unsigned):
        raise ValueError("application queue digest mismatch")
    ids = [row.get("obligation_id") for row in rows if isinstance(row, dict)]
    if len(ids) != len(rows) or ids != sorted(set(ids)):
        raise ValueError("application queue obligation identities are not exact/unique")
    for row in rows:
        if not _row_digest_is_valid(row):
            raise ValueError("application queue row digest mismatch")
        if expected_kind == "repair" and row.get(
            "application_completeness"
        ) not in {"MISSING", "INVALID"}:
            raise ValueError("repair queue contains a non-repair application state")
        if expected_kind == "skeptic" and row.get("skeptic_required") is not True:
            raise ValueError("skeptic queue contains a non-skeptic application state")


def _write_json_if_changed(path: Path, payload: dict[str, Any]) -> None:
    content = json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    try:
        if path.read_text(encoding="utf-8") == content:
            return
    except OSError:
        pass
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    tmp.write_text(content, encoding="utf-8")
    os.replace(tmp, path)


def write_application_queues(
    scratchpad: Path,
    states: Iterable[dict[str, Any]],
    *,
    phase: str,
) -> ApplicationQueues:
    queues = build_application_queues(states, phase=phase)
    root = Path(scratchpad)
    _write_json_if_changed(
        root / f"methodology_repair_queue_{phase}.json", queues.repair
    )
    _write_json_if_changed(
        root / f"methodology_skeptic_queue_{phase}.json", queues.skeptic
    )
    return queues


def migrate_application_receipt(payload: dict[str, Any]) -> dict[str, Any]:
    """Conservatively migrate schema v1 without manufacturing semantics."""

    if not isinstance(payload, dict):
        raise TypeError("application receipt must be an object")
    if payload.get("schema_version") == RECEIPT_SCHEMA:
        return json.loads(_canonical_json(payload))
    if payload.get("schema_version") != 1:
        raise ValueError("unsupported application receipt schema")
    rows: list[dict[str, Any]] = []
    notes: list[str] = []
    for old in payload.get("rows", []):
        if not isinstance(old, dict):
            notes.append("ignored malformed non-object legacy row")
            continue
        disposition = _text(old.get("disposition")).upper()
        skeptic = bool(old.get("skeptic_required"))
        trace_state = "VALID" if disposition in {"ATTESTED", "GAP"} else "UNKNOWN"
        classified = classify_application_row(
            {
                **old,
                "delivery_integrity": "CURRENT" if trace_state == "VALID" else "UNKNOWN",
                "trace_state": trace_state,
                # Legacy evidence was never basis-authoritative.
                "evidence_basis": "NONE",
            }
        )
        if disposition == "ATTESTED":
            classified["application_completeness"] = "APPLIED"
            classified["semantic_outcome"] = "INCONCLUSIVE"
            classified["skeptic_required"] = False
            classified["skeptic_reason"] = ""
            classified["negative_closure_eligible"] = False
            notes.append(
                f"{classified['obligation_id']}: legacy ATTESTED migrated as "
                "APPLIED/INCONCLUSIVE; no semantic outcome inferred"
            )
        elif skeptic:
            classified["application_completeness"] = "APPLIED"
            classified["semantic_outcome"] = "NEGATIVE"
            classified["skeptic_required"] = True
            classified["skeptic_reason"] = "LEGACY_NEGATIVE_REQUIRES_REVIEW"
            classified["negative_closure_eligible"] = False
            notes.append(
                f"{classified['obligation_id']}: legacy skeptic row retained as "
                "unsupported APPLIED/NEGATIVE"
            )
        else:
            classified["application_completeness"] = "MISSING"
            classified["semantic_outcome"] = "INCONCLUSIVE"
            classified["skeptic_required"] = False
            notes.append(
                f"{classified['obligation_id']}: legacy GAP migrated as MISSING"
            )
        rows.append(_finalize_row(classified))
    rows.sort(key=lambda row: row["obligation_id"])
    unsigned = {
        "schema_version": RECEIPT_SCHEMA,
        "phase": _text(payload.get("phase")),
        "rows": rows,
        "row_count": len(rows),
        "migration_notes": notes,
        "migrated_from_schema": 1,
    }
    return {**unsigned, "receipt_digest": _digest(unsigned)}


_LEGACY_HEADERS = (
    "Worker", "Output", "Skill", "Step", "Methodology Path", "SHA-256", "Reason"
)


def parse_legacy_gap_projection(text: str) -> list[dict[str, str]]:
    """Section-scoped compatibility parser; unrelated tables are invisible."""

    lines = str(text or "").splitlines()
    heading = next(
        (index for index, line in enumerate(lines) if re.fullmatch(r"# Skill Execution Gaps - .+", line.strip())),
        None,
    )
    if heading is None:
        return []
    rows: list[dict[str, str]] = []
    header_seen = False
    for line in lines[heading + 1:]:
        if line.startswith("#"):
            break
        if not line.strip().startswith("|"):
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if tuple(cells) == _LEGACY_HEADERS:
            header_seen = True
            continue
        if not header_seen or len(cells) != len(_LEGACY_HEADERS):
            continue
        if all(re.fullmatch(r"-+", cell) for cell in cells):
            continue
        row = dict(zip(_LEGACY_HEADERS, cells))
        sha = row["SHA-256"].casefold()
        if not _HEX_RE.fullmatch(sha):
            continue
        rows.append(
            {
                "worker_id": row["Worker"],
                "output": row["Output"],
                "skill": row["Skill"],
                "step": row["Step"],
                "methodology_path": row["Methodology Path"],
                "methodology_sha256": sha,
                "reason": row["Reason"],
            }
        )
    return rows


__all__ = [
    "APPLICATION_COMPLETENESS",
    "ApplicationQueues",
    "DELIVERY_INTEGRITY",
    "EVIDENCE_BASES",
    "NEGATIVE_CLOSURE_BASES",
    "RECEIPT_SCHEMA",
    "REPAIR_QUEUE_SCHEMA",
    "SEMANTIC_OUTCOMES",
    "SKEPTIC_QUEUE_SCHEMA",
    "build_application_receipt",
    "build_application_queues",
    "classify_application_row",
    "migrate_application_receipt",
    "parse_legacy_gap_projection",
    "validate_queue_payload",
    "write_application_queues",
]
