"""Exact, recall-safe lifecycle for mandatory reopened candidates.

This authority is deliberately additive.  It can restore a candidate to a
verification denominator, bind it to one queue/roster assignment, and account
for exact completion and report delivery.  It cannot authorize a negative
disposition, a severity change, or a report exclusion.

The module keeps four facts separate because conflating them recreated the
NC-5 loss class:

* an exact reopen obligation exists;
* the obligation was routed/assigned to verifier work;
* the assigned verifier work completed with replayable authority; and
* the candidate was delivered to a public report route.

Report delivery therefore never satisfies verification, and a verifier output
that is not bound to the assigned work item can never satisfy an obligation.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import tempfile
from typing import Any, Iterable, Mapping, Sequence

from queue_work_items import QueueWorkItem, QueueWorkPlan, validate_queue_work_items
from closure_broker_v2 import load_central_negative_closure_authority
from preverify_inventory_successor import (
    DELIVERY_RECEIPT_NAME as PREVERIFY_DELIVERY_SUCCESSOR_NAME,
    FINAL_RECEIPT_NAME as PREVERIFY_INVENTORY_SUCCESSOR_NAME,
    PreverifyInventorySuccessorError,
    validate_preverify_successor_payloads,
)
from preverify_projection_authority import (
    resolve_active_preverify_projection,
    PreverifyProjectionAuthorityError,
    successor_projection_present,
)


DENOMINATOR_SCHEMA = "plamen.mandatory_reverification_denominator.v1"
ROUTING_SCHEMA = "plamen.mandatory_reverification_routing.v1"
ASSIGNMENT_SCHEMA = "plamen.mandatory_reverification_assignment.v1"
COMPLETION_SCHEMA = "plamen.mandatory_reverification_completion.v1"
DELIVERY_SCHEMA = "plamen.mandatory_reverification_delivery.v1"

DENOMINATOR_FILE = "mandatory_reverification_denominator.json"
ROUTING_FILE = "mandatory_reverification_routing.json"
ASSIGNMENT_FILE = "mandatory_reverification_assignment.json"
COMPLETION_FILE = "mandatory_reverification_completion.json"
DELIVERY_FILE = "mandatory_reverification_delivery.json"
REPORT_DENOMINATOR_FILE = "mandatory_reverification_report_denominator.json"
REPORT_COMPLETION_FILE = "mandatory_reverification_report_completion.json"
REPORT_DELIVERY_FILE = "mandatory_reverification_report_delivery.json"
QUEUE_TRANSACTION_JOURNAL_FILE = (
    "mandatory_reverification_queue_transaction.journal.json"
)
QUEUE_TRANSACTION_RECEIPT_FILE = (
    "mandatory_reverification_queue_transaction.receipt.json"
)

_HEX64 = frozenset("0123456789abcdef")
_KINDS = frozenset({
    "ADDITIVE_REOPEN",
    "RECOVERY_INDEPENDENT_VERIFICATION",
})
_CANDIDATE_INPUT_FIELDS = frozenset({
    "obligation_kind",
    "candidate_id",
    "source_candidate_id",
    "source_artifact",
    "source_artifact_sha256",
    "source_proposal_id",
    "source_obligation_id",
    "candidate_content_sha256",
    "premise",
    "harm",
    "evidence",
})
_CANDIDATE_FIELDS = _CANDIDATE_INPUT_FIELDS | frozenset({
    "obligation_id",
    "candidate_packet_sha256",
    "terminal_authority",
})
_SOURCE_FIELDS = frozenset({"artifact", "sha256"})


class MandatoryReverificationError(ValueError):
    """The reopen lifecycle cannot be replayed without semantic guessing."""


def _canonical(value: Any) -> str:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    except (TypeError, ValueError) as exc:
        raise MandatoryReverificationError(
            f"record is not canonical JSON: {exc}"
        ) from exc


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _exact(value: Any, fields: frozenset[str], label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise MandatoryReverificationError(f"{label} must be an object")
    missing = sorted(fields - set(value))
    extra = sorted(set(value) - fields)
    if missing or extra:
        raise MandatoryReverificationError(
            f"{label} fields are not exact; missing={missing}; extra={extra}"
        )
    return dict(value)


def _text(
    value: Any,
    field: str,
    *,
    allow_empty: bool = False,
    allow_tab: bool = False,
) -> str:
    if not isinstance(value, str) or value != value.strip():
        raise MandatoryReverificationError(f"{field} must be canonical text")
    if not allow_empty and not value:
        raise MandatoryReverificationError(f"{field} must be non-empty")
    if any(
        (ord(char) < 32 and not (allow_tab and char == "\t"))
        or ord(char) == 127
        for char in value
    ):
        raise MandatoryReverificationError(f"{field} contains control characters")
    if len(value.encode("utf-8")) > 16_384:
        raise MandatoryReverificationError(f"{field} exceeds the bounded text limit")
    return value


def _sha256(value: Any, field: str) -> str:
    text = _text(value, field)
    if len(text) != 64 or any(char not in _HEX64 for char in text):
        raise MandatoryReverificationError(
            f"{field} must be a lowercase SHA-256 digest"
        )
    return text


def _safe_id(value: Any, field: str) -> str:
    text = _text(value, field)
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}", text):
        raise MandatoryReverificationError(f"{field} is not a safe identity")
    return text


def _candidate_core(value: Mapping[str, Any]) -> dict[str, Any]:
    row = _exact(value, _CANDIDATE_INPUT_FIELDS, "reopen candidate")
    kind = _text(row["obligation_kind"], "obligation_kind").upper()
    if kind not in _KINDS:
        raise MandatoryReverificationError("obligation_kind is unsupported")
    normalized = {
        "obligation_kind": kind,
        "candidate_id": _safe_id(row["candidate_id"], "candidate_id"),
        "source_candidate_id": _safe_id(
            row["source_candidate_id"], "source_candidate_id"
        ),
        "source_artifact": _text(row["source_artifact"], "source_artifact"),
        "source_artifact_sha256": _sha256(
            row["source_artifact_sha256"], "source_artifact_sha256"
        ),
        "source_proposal_id": _safe_id(
            row["source_proposal_id"], "source_proposal_id"
        ),
        "source_obligation_id": _safe_id(
            row["source_obligation_id"], "source_obligation_id"
        ),
        "candidate_content_sha256": _sha256(
            row["candidate_content_sha256"], "candidate_content_sha256"
        ),
        # These prose fields originate in the typed producer projection, whose
        # canonical text contract permits an interior horizontal tab.  Keep
        # that producer/consumer contract aligned without relaxing identity,
        # path, digest, or schema fields.
        "premise": _text(row["premise"], "premise", allow_tab=True),
        "harm": _text(row["harm"], "harm", allow_tab=True),
        "evidence": _text(row["evidence"], "evidence", allow_tab=True),
    }
    return normalized


def _normalize_candidate(value: Mapping[str, Any]) -> dict[str, Any]:
    if set(value) == set(_CANDIDATE_INPUT_FIELDS):
        core = _candidate_core(value)
        packet = _digest(core)
        identity = _digest({
            "obligation_kind": core["obligation_kind"],
            "candidate_id": core["candidate_id"],
            "source_candidate_id": core["source_candidate_id"],
            "source_proposal_id": core["source_proposal_id"],
            "source_obligation_id": core["source_obligation_id"],
            "candidate_packet_sha256": packet,
        })
        return {
            **core,
            "obligation_id": "MRV-" + identity[:24].upper(),
            "candidate_packet_sha256": packet,
            "terminal_authority": False,
        }
    row = _exact(value, _CANDIDATE_FIELDS, "bound reopen candidate")
    core = _candidate_core({key: row[key] for key in _CANDIDATE_INPUT_FIELDS})
    expected = _normalize_candidate(core)
    if dict(row) != expected:
        raise MandatoryReverificationError(
            "bound reopen candidate does not replay from its exact packet"
        )
    return expected


def _bounded_debt_detail(prefix: str, exc: BaseException) -> str:
    """Render a deterministic diagnostic without reintroducing controls."""

    raw = f"{prefix} ({type(exc).__name__}: {exc})"
    escaped = "".join(
        char if ord(char) >= 32 and ord(char) != 127 else f"\\u{ord(char):04x}"
        for char in raw
    )
    # Four-byte UTF-8 code points remain below _text's 16 KiB bound.
    return escaped[:4000]


def _candidate_debt_identity(value: object, ordinal: int) -> str:
    """Name an invalid input row without trusting any malformed identity."""

    if isinstance(value, Mapping):
        for field in (
            "source_proposal_id",
            "source_candidate_id",
            "candidate_id",
            "source_obligation_id",
        ):
            candidate = value.get(field)
            if isinstance(candidate, str):
                try:
                    safe = _safe_id(candidate, field)
                except MandatoryReverificationError:
                    continue
                prefix = f"candidate-input:{ordinal:04d}:"
                if len((prefix + safe).encode("utf-8")) <= 256:
                    return prefix + safe
                digest = hashlib.sha256(safe.encode("utf-8")).hexdigest()[:24]
                return prefix + digest
    return f"candidate-input:{ordinal:04d}"


def build_mandatory_reverification_denominator(
    *,
    run_id: str,
    candidates: Sequence[Mapping[str, Any]],
    source_bindings: Sequence[Mapping[str, Any]],
    source_obligation_count: int | None = None,
    input_debts: Sequence[Mapping[str, Any]] = (),
) -> dict[str, Any]:
    run = _safe_id(run_id, "run_id")
    normalized_sources: list[dict[str, str]] = []
    for value in source_bindings:
        row = _exact(value, _SOURCE_FIELDS, "source binding")
        normalized_sources.append({
            "artifact": _text(row["artifact"], "artifact"),
            "sha256": _sha256(row["sha256"], "sha256"),
        })
    normalized_sources.sort(key=lambda row: (row["artifact"], row["sha256"]))
    if len({row["artifact"] for row in normalized_sources}) != len(
        normalized_sources
    ):
        raise MandatoryReverificationError("source binding artifact is duplicated")

    source_map = {row["artifact"]: row["sha256"] for row in normalized_sources}
    provisional: list[tuple[int, dict[str, Any]]] = []
    derived_debts: list[dict[str, str]] = []
    for ordinal, value in enumerate(candidates, start=1):
        try:
            candidate = _normalize_candidate(value)
        except MandatoryReverificationError as exc:
            derived_debts.append({
                "source_identity": _candidate_debt_identity(value, ordinal),
                "reason_code": "CANDIDATE_INPUT_MALFORMED",
                "detail": _bounded_debt_detail(
                    f"candidate input row {ordinal} is quarantined", exc
                ),
            })
            continue
        if source_map.get(candidate["source_artifact"]) != candidate[
            "source_artifact_sha256"
        ]:
            derived_debts.append({
                "source_identity": _candidate_debt_identity(value, ordinal),
                "reason_code": "CANDIDATE_SOURCE_BINDING_MISMATCH",
                "detail": (
                    f"candidate input row {ordinal} source artifact is outside "
                    "the exact denominator bindings"
                ),
            })
            continue
        provisional.append((ordinal, candidate))

    normalized: list[dict[str, Any]] = []
    seen_obligations: set[str] = set()
    for ordinal, candidate in provisional:
        obligation_id = str(candidate["obligation_id"])
        if obligation_id in seen_obligations:
            derived_debts.append({
                "source_identity": f"candidate-duplicate:{obligation_id}:{ordinal:04d}",
                "reason_code": "CANDIDATE_OBLIGATION_ID_DUPLICATE",
                "detail": (
                    f"candidate input row {ordinal} repeats exact obligation "
                    f"{obligation_id} and is quarantined"
                ),
            })
            continue
        seen_obligations.add(obligation_id)
        normalized.append(candidate)
    normalized.sort(key=lambda row: (row["obligation_id"], row["candidate_id"]))
    if source_obligation_count is None:
        expected_count = len(candidates) + len(input_debts)
    elif (
        isinstance(source_obligation_count, bool)
        or not isinstance(source_obligation_count, int)
        or source_obligation_count < 0
    ):
        raise MandatoryReverificationError(
            "source_obligation_count must cover every routed candidate"
        )
    else:
        expected_count = source_obligation_count
    normalized_debts: list[dict[str, str]] = []
    for value in (*input_debts, *derived_debts):
        if not isinstance(value, Mapping) or set(value) != {
            "source_identity", "reason_code", "detail"
        }:
            raise MandatoryReverificationError("input debt fields are not exact")
        normalized_debts.append({
            "source_identity": _safe_id(
                value["source_identity"], "source_identity"
            ),
            "reason_code": _safe_id(value["reason_code"], "reason_code"),
            "detail": _text(value["detail"], "detail"),
        })
    normalized_debts.sort(
        key=lambda row: (row["source_identity"], row["reason_code"], row["detail"])
    )
    if len(normalized) + len(normalized_debts) != expected_count:
        raise MandatoryReverificationError(
            "source obligation denominator is not exactly candidates plus debt"
        )
    unsigned: dict[str, Any] = {
        "schema_version": DENOMINATOR_SCHEMA,
        "run_id": run,
        "status": "READY" if not normalized_debts else "COMPLETED_WITH_DEBT",
        "source_binding_count": len(normalized_sources),
        "source_bindings": normalized_sources,
        "source_obligation_count": expected_count,
        "candidate_count": len(normalized),
        "candidates": normalized,
        "input_debt_count": len(normalized_debts),
        "input_debts": normalized_debts,
        "terminal_negative_authority": False,
    }
    return {**unsigned, "denominator_digest": _digest(unsigned)}


def validate_mandatory_reverification_denominator(
    value: Mapping[str, Any],
) -> dict[str, Any]:
    fields = frozenset({
        "schema_version",
        "run_id",
        "status",
        "source_binding_count",
        "source_bindings",
        "source_obligation_count",
        "candidate_count",
        "candidates",
        "input_debt_count",
        "input_debts",
        "terminal_negative_authority",
        "denominator_digest",
    })
    row = _exact(value, fields, "mandatory denominator")
    if row["schema_version"] != DENOMINATOR_SCHEMA:
        raise MandatoryReverificationError("mandatory denominator schema mismatch")
    if (
        not isinstance(row["source_bindings"], list)
        or not isinstance(row["candidates"], list)
        or not isinstance(row["input_debts"], list)
    ):
        raise MandatoryReverificationError("mandatory denominator arrays are invalid")
    rebuilt = build_mandatory_reverification_denominator(
        run_id=row["run_id"],
        candidates=row["candidates"],
        source_bindings=row["source_bindings"],
        source_obligation_count=row["source_obligation_count"],
        input_debts=row["input_debts"],
    )
    if rebuilt != dict(row):
        raise MandatoryReverificationError(
            "mandatory denominator does not replay from exact source packets"
        )
    return rebuilt


def _item_identities(item: QueueWorkItem) -> set[str]:
    return {
        item.work_item_id,
        item.candidate_identity,
        *item.aliases,
        *item.constituents,
        *(link.identity for link in item.lineage),
    }


def _routing_digest(row: Mapping[str, Any]) -> str:
    return _digest({key: value for key, value in row.items() if key != "route_binding_digest"})


def route_mandatory_reverification(
    *,
    denominator: Mapping[str, Any],
    active_items: Iterable[QueueWorkItem],
    fallback_items: Iterable[QueueWorkItem],
) -> tuple[tuple[QueueWorkItem, ...], dict[str, Any]]:
    """Route every reopen after ordinary confidence/mode/dedup filters.

    Existing grouped work is preserved byte-for-byte.  A missing direct item
    is restored only from a typed fallback item.  Any ambiguous identity keeps
    visible debt and is never guessed into a group.
    """

    authority = validate_mandatory_reverification_denominator(denominator)
    active = list(validate_queue_work_items(tuple(active_items)))
    fallback = list(validate_queue_work_items(tuple(fallback_items)))
    if len({item.work_item_id for item in active + fallback}) != len(active) + len(
        fallback
    ):
        # The same identity may exist on the active and excluded sides while a
        # filter transaction is in flight.  Prefer active only when records are
        # exact; otherwise fail closed.
        active_by_id = {item.work_item_id: item for item in active}
        reduced: list[QueueWorkItem] = []
        for item in fallback:
            prior = active_by_id.get(item.work_item_id)
            if prior is None:
                reduced.append(item)
            elif prior != item:
                raise MandatoryReverificationError(
                    f"active/fallback queue identity conflict for {item.work_item_id}"
                )
        fallback = reduced

    routes: list[dict[str, Any]] = []
    debt: list[dict[str, Any]] = []
    for candidate in authority["candidates"]:
        candidate_id = str(candidate["candidate_id"])
        matches = [item for item in active if candidate_id in _item_identities(item)]
        routing_kind = "DIRECT_ACTIVE"
        if len(matches) > 1:
            debt.append({
                "obligation_id": candidate["obligation_id"],
                "candidate_id": candidate_id,
                "reason_code": "AMBIGUOUS_ACTIVE_QUEUE_IDENTITY",
                "affected_work_item_ids": sorted(item.work_item_id for item in matches),
            })
            continue
        if not matches:
            restored = [
                item for item in fallback if candidate_id in _item_identities(item)
            ]
            if len(restored) != 1:
                debt.append({
                    "obligation_id": candidate["obligation_id"],
                    "candidate_id": candidate_id,
                    "reason_code": (
                        "AMBIGUOUS_FALLBACK_QUEUE_IDENTITY"
                        if len(restored) > 1
                        else "MANDATORY_CANDIDATE_HAS_NO_QUEUE_PACKET"
                    ),
                    "affected_work_item_ids": sorted(
                        item.work_item_id for item in restored
                    ),
                })
                continue
            item = restored[0]
            if any(existing.work_item_id == item.work_item_id for existing in active):
                debt.append({
                    "obligation_id": candidate["obligation_id"],
                    "candidate_id": candidate_id,
                    "reason_code": "RESTORE_OUTPUT_IDENTITY_COLLISION",
                    "affected_work_item_ids": [item.work_item_id],
                })
                continue
            active.append(item)
            matches = [item]
            routing_kind = "RESTORED_AFTER_FILTER"
        item = matches[0]
        members = [item.work_item_id, *item.constituents]
        if candidate_id not in _item_identities(item):
            raise MandatoryReverificationError(
                "internal route construction lost candidate identity"
            )
        if candidate_id != item.work_item_id:
            routing_kind = "GROUPED_ACTIVE"
        unsigned_route: dict[str, Any] = {
            "obligation_id": candidate["obligation_id"],
            "candidate_id": candidate_id,
            "candidate_packet_sha256": candidate["candidate_packet_sha256"],
            "source_obligation_id": candidate["source_obligation_id"],
            "assigned_work_item_id": item.work_item_id,
            "assigned_work_item_digest": item.digest,
            "assigned_constituent_ids": members,
            "routing_kind": routing_kind,
            "ordinary_filter_bypass": routing_kind == "RESTORED_AFTER_FILTER",
            "terminal_authority": False,
        }
        routes.append({
            **unsigned_route,
            "route_binding_digest": _digest(unsigned_route),
        })
    routes.sort(key=lambda row: row["obligation_id"])
    debt.sort(key=lambda row: (row["obligation_id"], row["reason_code"]))
    status = "READY" if (
        len(routes) == len(authority["candidates"])
        and not debt
        and not authority["input_debts"]
    ) else (
        "COMPLETED_WITH_DEBT"
    )
    unsigned = {
        "schema_version": ROUTING_SCHEMA,
        "run_id": authority["run_id"],
        "denominator_digest": authority["denominator_digest"],
        "status": status,
        "route_count": len(routes),
        "routes": routes,
        "source_input_debt_count": authority["input_debt_count"],
        "debt_count": len(debt),
        "debts": debt,
        "terminal_negative_authority": False,
    }
    routing = {**unsigned, "routing_digest": _digest(unsigned)}
    return tuple(active), routing


def _validate_routing(
    value: Mapping[str, Any], denominator: Mapping[str, Any]
) -> dict[str, Any]:
    fields = frozenset({
        "schema_version", "run_id", "denominator_digest", "status",
        "route_count", "routes", "source_input_debt_count", "debt_count", "debts",
        "terminal_negative_authority", "routing_digest",
    })
    row = _exact(value, fields, "mandatory routing")
    authority = validate_mandatory_reverification_denominator(denominator)
    if row["schema_version"] != ROUTING_SCHEMA:
        raise MandatoryReverificationError("mandatory routing schema mismatch")
    if row["run_id"] != authority["run_id"] or row[
        "denominator_digest"
    ] != authority["denominator_digest"]:
        raise MandatoryReverificationError("mandatory routing denominator is stale")
    if not isinstance(row["routes"], list) or not isinstance(row["debts"], list):
        raise MandatoryReverificationError("mandatory routing arrays are invalid")
    if any(
        type(row[field]) is not int or row[field] < 0
        for field in (
            "route_count",
            "source_input_debt_count",
            "debt_count",
        )
    ):
        raise MandatoryReverificationError("mandatory routing counts are invalid")
    if row["route_count"] != len(row["routes"]) or row["debt_count"] != len(
        row["debts"]
    ):
        raise MandatoryReverificationError("mandatory routing counts are invalid")
    if row["terminal_negative_authority"] is not False:
        raise MandatoryReverificationError("mandatory routing acquired authority")
    known = {candidate["obligation_id"] for candidate in authority["candidates"]}
    routed: set[str] = set()
    for route in row["routes"]:
        if not isinstance(route, Mapping):
            raise MandatoryReverificationError("mandatory route must be an object")
        obligation = route.get("obligation_id")
        if obligation not in known or obligation in routed:
            raise MandatoryReverificationError("mandatory route identity is invalid")
        routed.add(str(obligation))
        if route.get("route_binding_digest") != _routing_digest(route):
            raise MandatoryReverificationError("mandatory route digest mismatch")
        if route.get("terminal_authority") is not False:
            raise MandatoryReverificationError("mandatory route acquired authority")
    debt_ids = {
        str(debt.get("obligation_id"))
        for debt in row["debts"]
        if isinstance(debt, Mapping)
    }
    if routed & debt_ids or routed | debt_ids != known:
        raise MandatoryReverificationError(
            "mandatory routing does not account for the exact denominator"
        )
    if row["source_input_debt_count"] != authority["input_debt_count"]:
        raise MandatoryReverificationError("mandatory routing lost source input debt")
    expected_status = "READY" if (
        routed == known and not row["debts"] and not authority["input_debts"]
    ) else (
        "COMPLETED_WITH_DEBT"
    )
    if row["status"] != expected_status:
        raise MandatoryReverificationError("mandatory routing status mismatch")
    unsigned = {key: row[key] for key in fields if key != "routing_digest"}
    if row["routing_digest"] != _digest(unsigned):
        raise MandatoryReverificationError("mandatory routing digest mismatch")
    return row


def _roster_projection(roster: Any) -> dict[str, Any]:
    if hasattr(roster, "to_dict") and callable(roster.to_dict):
        raw = roster.to_dict()
    elif isinstance(roster, Mapping):
        raw = dict(roster)
    else:
        raise MandatoryReverificationError("verifier roster is unavailable")
    try:
        parent = _sha256(
            raw["parent_queue_work_plan_digest"],
            "parent_queue_work_plan_digest",
        )
        ordered = list(raw["ordered_work_item_ids"])
        units = list(raw["work_units"])
    except (KeyError, TypeError) as exc:
        raise MandatoryReverificationError("verifier roster is malformed") from exc
    normalized_units: list[dict[str, Any]] = []
    for unit in units:
        if not isinstance(unit, Mapping):
            raise MandatoryReverificationError("verifier roster unit is malformed")
        normalized_units.append({
            "work_unit_id": _safe_id(unit.get("work_unit_id"), "work_unit_id"),
            "ordered_work_item_ids": [
                _safe_id(value, "ordered_work_item_id")
                for value in unit.get("ordered_work_item_ids", [])
            ],
        })
    declared = raw.get("roster_digest")
    if declared is None and hasattr(roster, "digest"):
        declared = roster.digest
    digest = _sha256(declared, "roster_digest")
    return {
        "parent_queue_work_plan_digest": parent,
        "ordered_work_item_ids": [_safe_id(value, "roster work item") for value in ordered],
        "work_units": normalized_units,
        "roster_digest": digest,
    }


def bind_mandatory_reverification_assignments(
    *,
    denominator: Mapping[str, Any],
    routing: Mapping[str, Any],
    queue_plan: QueueWorkPlan,
    roster: Any,
) -> dict[str, Any]:
    authority = validate_mandatory_reverification_denominator(denominator)
    route_authority = _validate_routing(routing, authority)
    if not isinstance(queue_plan, QueueWorkPlan):
        raise MandatoryReverificationError("queue plan is unavailable")
    roster_row = _roster_projection(roster)
    if (
        roster_row["parent_queue_work_plan_digest"] != queue_plan.digest
        or roster_row["ordered_work_item_ids"]
        != list(queue_plan.ordered_work_item_ids)
    ):
        raise MandatoryReverificationError("verifier roster is stale for queue plan")
    owners: dict[str, list[str]] = {}
    for unit in roster_row["work_units"]:
        for work_id in unit["ordered_work_item_ids"]:
            owners.setdefault(work_id, []).append(unit["work_unit_id"])
    assignments: list[dict[str, Any]] = []
    debts = list(route_authority["debts"])
    for route in route_authority["routes"]:
        work_id = str(route["assigned_work_item_id"])
        plan_owners = [
            shard.shard_id
            for shard in queue_plan.shards
            if work_id in shard.ordered_work_item_ids
        ]
        runtime_owners = owners.get(work_id, [])
        if len(plan_owners) != 1 or len(runtime_owners) != 1:
            debts.append({
                "obligation_id": route["obligation_id"],
                "candidate_id": route["candidate_id"],
                "reason_code": "VERIFIER_ASSIGNMENT_CARDINALITY_INVALID",
                "affected_work_item_ids": [work_id],
            })
            continue
        unsigned_assignment = {
            "obligation_id": route["obligation_id"],
            "candidate_id": route["candidate_id"],
            "candidate_packet_sha256": route["candidate_packet_sha256"],
            "route_binding_digest": route["route_binding_digest"],
            "assigned_work_item_id": work_id,
            "assigned_constituent_ids": list(route["assigned_constituent_ids"]),
            "queue_shard_id": plan_owners[0],
            "runtime_work_unit_id": runtime_owners[0],
            "assignment_count": 1,
            "terminal_authority": False,
        }
        assignments.append({
            **unsigned_assignment,
            "assignment_binding_digest": _digest(unsigned_assignment),
        })
    assignments.sort(key=lambda row: row["obligation_id"])
    debts.sort(key=lambda row: (row["obligation_id"], row["reason_code"]))
    status = "ASSIGNED" if (
        len(assignments) == len(authority["candidates"])
        and not debts
        and not authority["input_debts"]
    ) else (
        "COMPLETED_WITH_DEBT"
    )
    unsigned = {
        "schema_version": ASSIGNMENT_SCHEMA,
        "run_id": authority["run_id"],
        "denominator_digest": authority["denominator_digest"],
        "routing_digest": route_authority["routing_digest"],
        "queue_work_plan_digest": queue_plan.digest,
        "verifier_roster_digest": roster_row["roster_digest"],
        "status": status,
        "assignment_count": len(assignments),
        "assignments": assignments,
        "source_input_debt_count": authority["input_debt_count"],
        "debt_count": len(debts),
        "debts": debts,
        "terminal_negative_authority": False,
    }
    return {**unsigned, "assignment_receipt_digest": _digest(unsigned)}


def _validate_assignment(
    value: Mapping[str, Any], denominator: Mapping[str, Any]
) -> dict[str, Any]:
    fields = frozenset({
        "schema_version", "run_id", "denominator_digest", "routing_digest",
        "queue_work_plan_digest", "verifier_roster_digest", "status",
        "assignment_count", "assignments", "source_input_debt_count",
        "debt_count", "debts",
        "terminal_negative_authority", "assignment_receipt_digest",
    })
    row = _exact(value, fields, "mandatory assignment")
    authority = validate_mandatory_reverification_denominator(denominator)
    if row["schema_version"] != ASSIGNMENT_SCHEMA:
        raise MandatoryReverificationError("mandatory assignment schema mismatch")
    if row["run_id"] != authority["run_id"] or row[
        "denominator_digest"
    ] != authority["denominator_digest"]:
        raise MandatoryReverificationError("mandatory assignment is stale")
    if not isinstance(row["assignments"], list) or not isinstance(row["debts"], list):
        raise MandatoryReverificationError("mandatory assignment arrays are invalid")
    if any(
        type(row[field]) is not int or row[field] < 0
        for field in (
            "assignment_count",
            "source_input_debt_count",
            "debt_count",
        )
    ):
        raise MandatoryReverificationError("mandatory assignment counts are invalid")
    if row["assignment_count"] != len(row["assignments"]) or row[
        "debt_count"
    ] != len(row["debts"]):
        raise MandatoryReverificationError("mandatory assignment counts mismatch")
    assigned: set[str] = set()
    for assignment in row["assignments"]:
        if not isinstance(assignment, Mapping):
            raise MandatoryReverificationError("mandatory assignment row is invalid")
        obligation = str(assignment.get("obligation_id") or "")
        per_obligation_count = assignment.get("assignment_count")
        if (
            obligation in assigned
            or type(per_obligation_count) is not int
            or per_obligation_count != 1
        ):
            raise MandatoryReverificationError("mandatory obligation is not assigned once")
        assigned.add(obligation)
        unsigned_assignment = {
            key: assignment[key]
            for key in assignment
            if key != "assignment_binding_digest"
        }
        if assignment.get("assignment_binding_digest") != _digest(unsigned_assignment):
            raise MandatoryReverificationError("mandatory assignment digest mismatch")
        if assignment.get("terminal_authority") is not False:
            raise MandatoryReverificationError("mandatory assignment acquired authority")
    known = {candidate["obligation_id"] for candidate in authority["candidates"]}
    debt_ids = {
        str(debt.get("obligation_id"))
        for debt in row["debts"]
        if isinstance(debt, Mapping)
    }
    if assigned & debt_ids or assigned | debt_ids != known:
        raise MandatoryReverificationError(
            "mandatory assignment does not account for denominator"
        )
    if row["source_input_debt_count"] != authority["input_debt_count"]:
        raise MandatoryReverificationError("mandatory assignment lost source input debt")
    expected = "ASSIGNED" if (
        assigned == known and not row["debts"] and not authority["input_debts"]
    ) else (
        "COMPLETED_WITH_DEBT"
    )
    if row["status"] != expected:
        raise MandatoryReverificationError("mandatory assignment status mismatch")
    for field in (
        "routing_digest", "queue_work_plan_digest", "verifier_roster_digest"
    ):
        _sha256(row[field], field)
    unsigned = {key: row[key] for key in fields if key != "assignment_receipt_digest"}
    if row["assignment_receipt_digest"] != _digest(unsigned):
        raise MandatoryReverificationError("mandatory assignment receipt mismatch")
    return row


def reconcile_mandatory_reverification_completion(
    *,
    denominator: Mapping[str, Any],
    assignment: Mapping[str, Any],
    completion_evidence: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    authority = validate_mandatory_reverification_denominator(denominator)
    assigned = _validate_assignment(assignment, authority)
    if not isinstance(completion_evidence, Mapping):
        raise MandatoryReverificationError("completion evidence must be a mapping")
    candidates = {
        row["obligation_id"]: row for row in authority["candidates"]
    }
    rows: list[dict[str, Any]] = []
    retry: list[str] = []
    for binding in assigned["assignments"]:
        candidate = candidates[binding["obligation_id"]]
        work_id = str(binding["assigned_work_item_id"])
        evidence = completion_evidence.get(work_id)
        authorized = isinstance(evidence, Mapping) and evidence.get(
            "completion_authorized"
        ) is True
        output_sha = None
        receipt_sha = None
        if authorized:
            try:
                output_sha = _sha256(evidence.get("output_sha256"), "output_sha256")
                receipt_sha = _sha256(evidence.get("receipt_sha256"), "receipt_sha256")
            except MandatoryReverificationError:
                authorized = False
                output_sha = None
                receipt_sha = None
        state = "EXACTLY_COMPLETED" if authorized else "RETRY_REQUIRED"
        if not authorized and work_id not in retry:
            retry.append(work_id)
        unsigned_row = {
            "obligation_id": binding["obligation_id"],
            "candidate_id": candidate["candidate_id"],
            "candidate_packet_sha256": candidate["candidate_packet_sha256"],
            "assignment_binding_digest": binding["assignment_binding_digest"],
            "assigned_work_item_id": work_id,
            "completion_state": state,
            "output_sha256": output_sha,
            "receipt_sha256": receipt_sha,
            "terminal_negative_authority": False,
        }
        rows.append({**unsigned_row, "completion_binding_digest": _digest(unsigned_row)})
    completed_ids = {row["obligation_id"] for row in rows}
    for candidate in authority["candidates"]:
        if candidate["obligation_id"] in completed_ids:
            continue
        unsigned_row = {
            "obligation_id": candidate["obligation_id"],
            "candidate_id": candidate["candidate_id"],
            "candidate_packet_sha256": candidate["candidate_packet_sha256"],
            "assignment_binding_digest": None,
            "assigned_work_item_id": None,
            "completion_state": "RETRY_REQUIRED",
            "output_sha256": None,
            "receipt_sha256": None,
            "terminal_negative_authority": False,
        }
        rows.append({**unsigned_row, "completion_binding_digest": _digest(unsigned_row)})
    rows.sort(key=lambda row: row["obligation_id"])
    completed_count = sum(
        row["completion_state"] == "EXACTLY_COMPLETED" for row in rows
    )
    status = "COMPLETED" if (
        completed_count == len(rows) and not authority["input_debts"]
    ) else "COMPLETED_WITH_DEBT"
    unsigned = {
        "schema_version": COMPLETION_SCHEMA,
        "run_id": authority["run_id"],
        "denominator_digest": authority["denominator_digest"],
        "assignment_authority_kind": "PRIMARY_QUEUE_ROSTER",
        "assignment_receipt_digest": assigned["assignment_receipt_digest"],
        "status": status,
        "obligation_count": len(rows),
        "completed_obligation_count": completed_count,
        "source_input_debt_count": authority["input_debt_count"],
        "rows": rows,
        "retry_work_item_ids": retry,
        "terminal_negative_authority": False,
    }
    return {**unsigned, "completion_receipt_digest": _digest(unsigned)}


_RECOVERY_EVIDENCE_FIELDS = frozenset({
    "obligation_id",
    "candidate_packet_sha256",
    "source_obligation_id",
    "work_item_id",
    "completion_authorized",
    "output_sha256",
    "receipt_sha256",
    "contract_digest",
    "execution_receipt_digest",
})


def reconcile_mandatory_recovery_completion(
    *,
    denominator: Mapping[str, Any],
    recovery_evidence: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    """Reconcile a distinct recovery launch against exact obligation packets.

    Evidence is keyed by the mandatory obligation identity.  An output for the
    right work item but the wrong obligation, source lifecycle obligation, or
    candidate packet is deliberately unrelated and cannot close the row.
    """

    authority = validate_mandatory_reverification_denominator(denominator)
    if not isinstance(recovery_evidence, Mapping):
        raise MandatoryReverificationError(
            "recovery completion evidence must be a mapping"
        )
    rows: list[dict[str, Any]] = []
    bindings: list[dict[str, Any]] = []
    retry: list[str] = []
    for candidate in authority["candidates"]:
        obligation_id = candidate["obligation_id"]
        work_id = "MRVW-" + obligation_id[4:]
        raw = recovery_evidence.get(obligation_id)
        binding: dict[str, Any] | None = None
        if isinstance(raw, Mapping) and set(raw) == set(_RECOVERY_EVIDENCE_FIELDS):
            try:
                if (
                    raw["obligation_id"] != obligation_id
                    or raw["candidate_packet_sha256"]
                    != candidate["candidate_packet_sha256"]
                    or raw["source_obligation_id"]
                    != candidate["source_obligation_id"]
                    or raw["work_item_id"] != work_id
                    or raw["completion_authorized"] is not True
                ):
                    raise MandatoryReverificationError(
                        "recovery evidence identity does not match obligation"
                    )
                binding = {
                    "obligation_id": obligation_id,
                    "candidate_packet_sha256": _sha256(
                        raw["candidate_packet_sha256"],
                        "candidate_packet_sha256",
                    ),
                    "source_obligation_id": _safe_id(
                        raw["source_obligation_id"], "source_obligation_id"
                    ),
                    "work_item_id": _safe_id(raw["work_item_id"], "work_item_id"),
                    "output_sha256": _sha256(
                        raw["output_sha256"], "output_sha256"
                    ),
                    "receipt_sha256": _sha256(
                        raw["receipt_sha256"], "receipt_sha256"
                    ),
                    "contract_digest": _sha256(
                        raw["contract_digest"], "contract_digest"
                    ),
                    "execution_receipt_digest": _sha256(
                        raw["execution_receipt_digest"],
                        "execution_receipt_digest",
                    ),
                }
            except MandatoryReverificationError:
                binding = None
        authorized = binding is not None
        assignment_digest = _digest(binding) if binding is not None else None
        if binding is not None:
            bindings.append({**binding, "assignment_binding_digest": assignment_digest})
        else:
            retry.append(work_id)
        unsigned_row = {
            "obligation_id": obligation_id,
            "candidate_id": candidate["candidate_id"],
            "candidate_packet_sha256": candidate["candidate_packet_sha256"],
            "assignment_binding_digest": assignment_digest,
            "assigned_work_item_id": work_id,
            "completion_state": (
                "EXACTLY_COMPLETED" if authorized else "RETRY_REQUIRED"
            ),
            "output_sha256": (
                binding["output_sha256"] if binding is not None else None
            ),
            "receipt_sha256": (
                binding["receipt_sha256"] if binding is not None else None
            ),
            "terminal_negative_authority": False,
        }
        rows.append({
            **unsigned_row,
            "completion_binding_digest": _digest(unsigned_row),
        })
    rows.sort(key=lambda row: row["obligation_id"])
    bindings.sort(key=lambda row: row["obligation_id"])
    completed = sum(
        row["completion_state"] == "EXACTLY_COMPLETED" for row in rows
    )
    clean = completed == len(rows) and not authority["input_debts"]
    unsigned = {
        "schema_version": COMPLETION_SCHEMA,
        "run_id": authority["run_id"],
        "denominator_digest": authority["denominator_digest"],
        "assignment_authority_kind": "RECOVERY_CONTRACT",
        "assignment_receipt_digest": _digest(bindings),
        "status": "COMPLETED" if clean else "COMPLETED_WITH_DEBT",
        "obligation_count": len(rows),
        "completed_obligation_count": completed,
        "source_input_debt_count": authority["input_debt_count"],
        "rows": rows,
        "retry_work_item_ids": retry,
        "terminal_negative_authority": False,
    }
    result = {**unsigned, "completion_receipt_digest": _digest(unsigned)}
    validated = _validate_completion(result, authority)
    assert validated is not None
    return validated


def _validate_completion(
    value: Mapping[str, Any] | None,
    denominator: Mapping[str, Any],
) -> dict[str, Any] | None:
    if value is None:
        return None
    fields = frozenset({
        "schema_version", "run_id", "denominator_digest",
        "assignment_authority_kind", "assignment_receipt_digest", "status", "obligation_count",
        "completed_obligation_count", "source_input_debt_count", "rows",
        "retry_work_item_ids",
        "terminal_negative_authority", "completion_receipt_digest",
    })
    row = _exact(value, fields, "mandatory completion")
    authority = validate_mandatory_reverification_denominator(denominator)
    if row["schema_version"] != COMPLETION_SCHEMA:
        raise MandatoryReverificationError("mandatory completion schema mismatch")
    if row["assignment_authority_kind"] not in {
        "PRIMARY_QUEUE_ROSTER", "RECOVERY_CONTRACT"
    }:
        raise MandatoryReverificationError(
            "mandatory completion assignment authority is invalid"
        )
    if row["run_id"] != authority["run_id"] or row[
        "denominator_digest"
    ] != authority["denominator_digest"]:
        raise MandatoryReverificationError("mandatory completion is stale")
    if any(
        type(row[field]) is not int or row[field] < 0
        for field in (
            "obligation_count",
            "completed_obligation_count",
            "source_input_debt_count",
        )
    ):
        raise MandatoryReverificationError("mandatory completion counts are invalid")
    if not isinstance(row["rows"], list) or row["obligation_count"] != len(row["rows"]):
        raise MandatoryReverificationError("mandatory completion rows are invalid")
    known = {candidate["obligation_id"] for candidate in authority["candidates"]}
    observed = {str(item.get("obligation_id")) for item in row["rows"] if isinstance(item, Mapping)}
    if observed != known or len(observed) != len(row["rows"]):
        raise MandatoryReverificationError("mandatory completion denominator mismatch")
    completed = 0
    candidates = {
        candidate["obligation_id"]: candidate
        for candidate in authority["candidates"]
    }
    retry_work_item_ids: list[str] = []
    completion_row_fields = frozenset({
        "obligation_id", "candidate_id", "candidate_packet_sha256",
        "assignment_binding_digest", "assigned_work_item_id",
        "completion_state", "output_sha256", "receipt_sha256",
        "terminal_negative_authority", "completion_binding_digest",
    })
    for raw_item in row["rows"]:
        item = _exact(raw_item, completion_row_fields, "mandatory completion row")
        candidate = candidates[str(item["obligation_id"])]
        if (
            item["candidate_id"] != candidate["candidate_id"]
            or item["candidate_packet_sha256"]
            != candidate["candidate_packet_sha256"]
        ):
            raise MandatoryReverificationError(
                "mandatory completion candidate packet is stale"
            )
        unsigned_item = {
            key: item[key] for key in item if key != "completion_binding_digest"
        }
        if item.get("completion_binding_digest") != _digest(unsigned_item):
            raise MandatoryReverificationError("mandatory completion row digest mismatch")
        assignment_binding = item["assignment_binding_digest"]
        work_item_id = item["assigned_work_item_id"]
        if assignment_binding is not None and work_item_id is None:
            raise MandatoryReverificationError(
                "mandatory completion assignment binding is partial"
            )
        if assignment_binding is not None:
            _sha256(assignment_binding, "assignment_binding_digest")
        if work_item_id is not None:
            _safe_id(work_item_id, "assigned_work_item_id")
        if item.get("completion_state") == "EXACTLY_COMPLETED":
            if assignment_binding is None:
                raise MandatoryReverificationError(
                    "exact mandatory completion lacks an assignment binding"
                )
            _sha256(item.get("output_sha256"), "output_sha256")
            _sha256(item.get("receipt_sha256"), "receipt_sha256")
            completed += 1
        elif item.get("completion_state") == "RETRY_REQUIRED":
            if item.get("output_sha256") is not None or item.get(
                "receipt_sha256"
            ) is not None:
                raise MandatoryReverificationError(
                    "retry-required mandatory completion acquired output authority"
                )
            if work_item_id is not None and work_item_id not in retry_work_item_ids:
                retry_work_item_ids.append(work_item_id)
        else:
            raise MandatoryReverificationError("mandatory completion state invalid")
        if item.get("terminal_negative_authority") is not False:
            raise MandatoryReverificationError("mandatory completion acquired authority")
    if row["completed_obligation_count"] != completed:
        raise MandatoryReverificationError("mandatory completed count mismatch")
    if row["source_input_debt_count"] != authority["input_debt_count"]:
        raise MandatoryReverificationError("mandatory completion lost source input debt")
    if (
        not isinstance(row["retry_work_item_ids"], list)
        or row["retry_work_item_ids"] != retry_work_item_ids
    ):
        raise MandatoryReverificationError(
            "mandatory completion retry denominator mismatch"
        )
    expected = "COMPLETED" if (
        completed == len(row["rows"]) and not authority["input_debts"]
    ) else "COMPLETED_WITH_DEBT"
    if row["status"] != expected:
        raise MandatoryReverificationError("mandatory completion status mismatch")
    _sha256(row["assignment_receipt_digest"], "assignment_receipt_digest")
    unsigned = {key: row[key] for key in fields if key != "completion_receipt_digest"}
    if row["completion_receipt_digest"] != _digest(unsigned):
        raise MandatoryReverificationError("mandatory completion digest mismatch")
    return row


def reconcile_mandatory_reverification_delivery(
    *,
    denominator: Mapping[str, Any],
    completion: Mapping[str, Any] | None,
    report_routes: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    authority = validate_mandatory_reverification_denominator(denominator)
    completed = _validate_completion(completion, authority)
    completion_by_obligation = {
        row["obligation_id"]: row for row in (completed or {}).get("rows", [])
    }
    rows: list[dict[str, Any]] = []
    for candidate in authority["candidates"]:
        verification = completion_by_obligation.get(candidate["obligation_id"])
        route = report_routes.get(candidate["candidate_id"])
        report_state = "REPORT_DELIVERY_DEBT"
        public_ids: list[str] = []
        if isinstance(route, Mapping):
            state = str(route.get("report_delivery_state") or "")
            raw_ids = route.get("public_report_ids")
            if (
                state in {"DELIVERED_BODY", "DELIVERED_HUMAN_REVIEW"}
                and isinstance(raw_ids, list)
                and raw_ids
                and all(isinstance(value, str) and value.strip() for value in raw_ids)
            ):
                report_state = state
                public_ids = sorted(set(value.strip() for value in raw_ids))
        verification_state = (
            verification["completion_state"]
            if verification is not None
            else "RETRY_REQUIRED"
        )
        unsigned_row = {
            "obligation_id": candidate["obligation_id"],
            "candidate_id": candidate["candidate_id"],
            "candidate_packet_sha256": candidate["candidate_packet_sha256"],
            "verification_state": verification_state,
            "completion_binding_digest": (
                verification.get("completion_binding_digest")
                if verification is not None
                else None
            ),
            "report_delivery_state": report_state,
            "public_report_ids": public_ids,
            "report_delivery_satisfies_verification": False,
            "terminal_negative_authority": False,
        }
        rows.append({**unsigned_row, "delivery_binding_digest": _digest(unsigned_row)})
    rows.sort(key=lambda row: row["obligation_id"])
    clean = not authority["input_debts"] and all(
        row["verification_state"] == "EXACTLY_COMPLETED"
        and row["report_delivery_state"]
        in {"DELIVERED_BODY", "DELIVERED_HUMAN_REVIEW"}
        for row in rows
    )
    unsigned = {
        "schema_version": DELIVERY_SCHEMA,
        "run_id": authority["run_id"],
        "denominator_digest": authority["denominator_digest"],
        "completion_receipt_digest": (
            completed.get("completion_receipt_digest") if completed else None
        ),
        "status": "COMPLETED" if clean else "COMPLETED_WITH_DEBT",
        "source_input_debt_count": authority["input_debt_count"],
        "row_count": len(rows),
        "rows": rows,
        "terminal_negative_authority": False,
    }
    result = {**unsigned, "delivery_receipt_digest": _digest(unsigned)}
    return _validate_delivery(result, authority)


def _validate_delivery(
    value: Mapping[str, Any],
    denominator: Mapping[str, Any],
) -> dict[str, Any]:
    fields = frozenset({
        "schema_version", "run_id", "denominator_digest",
        "completion_receipt_digest", "status", "source_input_debt_count",
        "row_count", "rows", "terminal_negative_authority",
        "delivery_receipt_digest",
    })
    row = _exact(value, fields, "mandatory delivery")
    authority = validate_mandatory_reverification_denominator(denominator)
    if row["schema_version"] != DELIVERY_SCHEMA:
        raise MandatoryReverificationError("mandatory delivery schema mismatch")
    if (
        row["run_id"] != authority["run_id"]
        or row["denominator_digest"] != authority["denominator_digest"]
    ):
        raise MandatoryReverificationError("mandatory delivery is stale")
    completion_digest = row["completion_receipt_digest"]
    if completion_digest is not None:
        _sha256(completion_digest, "completion_receipt_digest")
    if any(
        type(row[field]) is not int or row[field] < 0
        for field in ("source_input_debt_count", "row_count")
    ):
        raise MandatoryReverificationError("mandatory delivery counts are invalid")
    if not isinstance(row["rows"], list) or row["row_count"] != len(row["rows"]):
        raise MandatoryReverificationError("mandatory delivery rows are invalid")
    known = {candidate["obligation_id"] for candidate in authority["candidates"]}
    observed: set[str] = set()
    clean_rows = True
    row_fields = frozenset({
        "obligation_id", "candidate_id", "candidate_packet_sha256",
        "verification_state", "completion_binding_digest",
        "report_delivery_state", "public_report_ids",
        "report_delivery_satisfies_verification", "terminal_negative_authority",
        "delivery_binding_digest",
    })
    candidates = {item["obligation_id"]: item for item in authority["candidates"]}
    for raw in row["rows"]:
        item = _exact(raw, row_fields, "mandatory delivery row")
        obligation_id = _safe_id(item["obligation_id"], "obligation_id")
        if obligation_id in observed or obligation_id not in candidates:
            raise MandatoryReverificationError(
                "mandatory delivery obligation identity is invalid"
            )
        observed.add(obligation_id)
        candidate = candidates[obligation_id]
        if (
            item["candidate_id"] != candidate["candidate_id"]
            or item["candidate_packet_sha256"]
            != candidate["candidate_packet_sha256"]
        ):
            raise MandatoryReverificationError(
                "mandatory delivery candidate binding changed"
            )
        if item["verification_state"] not in {
            "EXACTLY_COMPLETED", "RETRY_REQUIRED"
        }:
            raise MandatoryReverificationError(
                "mandatory delivery verification state is invalid"
            )
        binding = item["completion_binding_digest"]
        if binding is not None:
            _sha256(binding, "completion_binding_digest")
        if item["report_delivery_state"] not in {
            "DELIVERED_BODY", "DELIVERED_HUMAN_REVIEW", "REPORT_DELIVERY_DEBT"
        }:
            raise MandatoryReverificationError(
                "mandatory report delivery state is invalid"
            )
        public_ids = item["public_report_ids"]
        if (
            not isinstance(public_ids, list)
            or public_ids != sorted(set(public_ids))
            or any(
                not isinstance(public_id, str)
                or not public_id.strip()
                or public_id != public_id.strip()
                for public_id in public_ids
            )
        ):
            raise MandatoryReverificationError(
                "mandatory public report identity set is invalid"
            )
        delivered = item["report_delivery_state"] in {
            "DELIVERED_BODY", "DELIVERED_HUMAN_REVIEW"
        }
        if delivered != bool(public_ids):
            raise MandatoryReverificationError(
                "mandatory report delivery identity/state mismatch"
            )
        if (
            item["report_delivery_satisfies_verification"] is not False
            or item["terminal_negative_authority"] is not False
        ):
            raise MandatoryReverificationError(
                "mandatory delivery acquired forbidden authority"
            )
        unsigned_item = {
            key: item[key] for key in row_fields
            if key != "delivery_binding_digest"
        }
        if item["delivery_binding_digest"] != _digest(unsigned_item):
            raise MandatoryReverificationError(
                "mandatory delivery row digest mismatch"
            )
        clean_rows = clean_rows and (
            item["verification_state"] == "EXACTLY_COMPLETED" and delivered
        )
    if observed != known:
        raise MandatoryReverificationError(
            "mandatory delivery denominator is incomplete"
        )
    if row["source_input_debt_count"] != authority["input_debt_count"]:
        raise MandatoryReverificationError("mandatory delivery lost source debt")
    expected = "COMPLETED" if (
        clean_rows and not authority["input_debts"]
    ) else "COMPLETED_WITH_DEBT"
    if row["status"] != expected:
        raise MandatoryReverificationError("mandatory delivery status mismatch")
    if row["terminal_negative_authority"] is not False:
        raise MandatoryReverificationError("mandatory delivery acquired authority")
    unsigned = {key: row[key] for key in fields if key != "delivery_receipt_digest"}
    if row["delivery_receipt_digest"] != _digest(unsigned):
        raise MandatoryReverificationError("mandatory delivery receipt mismatch")
    return row


def mandatory_recovery_rows(
    denominator: Mapping[str, Any],
    *,
    only_obligation_ids: Iterable[str] | None = None,
) -> list[dict[str, Any]]:
    """Project exact reopen packets into distinct bounded recovery work.

    Recovery work IDs are derived from obligation identity, never from the
    original candidate output filename.  This prevents an earlier primary
    verifier output from being adopted as recovery evidence on resume.
    """

    authority = validate_mandatory_reverification_denominator(denominator)
    selected = set(only_obligation_ids or ())
    rows: list[dict[str, Any]] = []
    for candidate in authority["candidates"]:
        if selected and candidate["obligation_id"] not in selected:
            continue
        rows.append({
            "work_item_id": "MRVW-" + candidate["obligation_id"][4:],
            "severity": "Unknown",
            "title": f"Mandatory re-verification of {candidate['candidate_id']}",
            "bug_class": "mandatory-reopen",
            "poc_class": "structural",
            "location": candidate["evidence"],
            "primary_artifact": candidate["source_artifact"],
            "mechanism": candidate["premise"],
            "harm": candidate["harm"],
            "evidence": candidate["evidence"],
            "source_candidate_digest": candidate["candidate_packet_sha256"],
            "source_work_item_id": candidate["candidate_id"],
            "source_identity": candidate["source_candidate_id"],
            "source_operator_receipt": None,
            "source_operator_receipt_sha256": None,
            "source_operator_receipt_digest": None,
            "finding_lifecycle_obligation_id": candidate["source_obligation_id"],
            "producer_identity": "mandatory-reopen-producer",
            "required_discriminator_identity": "independent-recovery-verifier",
            "independent_discriminator_required": True,
            "terminal_authority": False,
        })
    return rows


_PRIMARY_PROJECTIONS = (
    ("application_skeptic_proposals.md", "application_skeptic"),
    ("candidate_negative_skeptic_proposals.md", "candidate_negative_skeptic"),
)
_SECURITY_OBLIGATION_SOURCE = "security_obligation_authority.json"
_SECURITY_OBLIGATION_PENDING_FIELDS = frozenset({
    "obligation_id",
    "display_id",
    "alias_id",
    "relation_id",
    "object_id",
    "symbol",
    "finding_id",
    "receipt_id",
    "question",
    "source_artifact",
    "source_artifact_sha256",
    "alias_binding_sha256",
})
_INVENTORY_HEADING = re.compile(
    r"(?im)^#{2,4}\s+Finding\s+\[([A-Za-z0-9_.-]+)\]\s*:\s*(.*?)\s*$"
)


def _file_sha256(path: Path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as exc:
        raise MandatoryReverificationError(
            f"source artifact is unreadable: {path.name}"
        ) from exc


def _safe_scratch_source(root: Path, relative: str) -> Path:
    """Resolve one receipt-owned source without following symlink components."""

    normalized = str(relative or "")
    pure = PurePosixPath(normalized)
    if (
        not normalized
        or "\\" in normalized
        or pure.is_absolute()
        or ".." in pure.parts
        or pure.as_posix() != normalized
    ):
        raise MandatoryReverificationError(
            "registered source path is not safe and relative"
        )
    try:
        resolved_root = root.resolve(strict=True)
    except OSError as exc:
        raise MandatoryReverificationError(
            "registered source root is unavailable"
        ) from exc
    cursor = root
    if cursor.is_symlink():
        raise MandatoryReverificationError("registered source root is a symlink")
    for part in pure.parts:
        cursor = cursor / part
        if cursor.is_symlink():
            raise MandatoryReverificationError(
                "registered source path contains a symlink component"
            )
    try:
        resolved = cursor.resolve(strict=True)
        resolved.relative_to(resolved_root)
    except (OSError, ValueError) as exc:
        raise MandatoryReverificationError(
            "registered source path escapes or is unavailable"
        ) from exc
    if not cursor.is_file():
        raise MandatoryReverificationError(
            "registered source path is not a regular file"
        )
    return cursor


def _field(block: str, *labels: str) -> str:
    for label in labels:
        match = re.search(
            rf"(?im)^\s*(?:[-*]\s*)?\*\*{re.escape(label)}\*\*\s*:\s*(.*?)\s*$",
            block,
        )
        if match:
            return match.group(1).strip()
    return ""


def _inventory_records(path: Path) -> list[dict[str, str]]:
    try:
        text = path.read_text(encoding="utf-8", errors="strict")
    except (OSError, UnicodeError) as exc:
        raise MandatoryReverificationError(
            "findings inventory is unavailable or malformed"
        ) from exc
    headings = list(_INVENTORY_HEADING.finditer(text))
    rows: list[dict[str, str]] = []
    for index, heading in enumerate(headings):
        end = headings[index + 1].start() if index + 1 < len(headings) else len(text)
        block = text[heading.start():end]
        rows.append({
            "candidate_id": heading.group(1).strip().upper(),
            "title": heading.group(2).strip(),
            "source_ids": _field(block, "Source IDs", "Source ID"),
            "primary_artifact": Path(
                _field(block, "Primary Artifact", "Source Artifact", "Artifact")
            ).name,
            "location": _field(block, "Location", "Locations"),
            "premise": _field(block, "Description", "Mechanism", "Root Cause"),
            "harm": _field(block, "Impact", "Harm"),
        })
    return rows


def _source_id_tokens(value: str) -> set[str]:
    return {
        match.group(0).upper()
        for match in re.finditer(
            r"\b[A-Z][A-Z0-9_.]*(?:-[A-Z0-9_.]+)+\b",
            value or "",
            re.IGNORECASE,
        )
    }


def _load_current_delivery_receipt(
    root: Path,
    *,
    trusted_frozen_transaction_input: bool = False,
) -> dict[str, Any]:
    from finding_producer_registry import canonical_digest, registry_digest

    if successor_projection_present(root):
        try:
            if trusted_frozen_transaction_input:
                final_payload = json.loads(
                    (
                        root / PREVERIFY_INVENTORY_SUCCESSOR_NAME
                    ).read_text(encoding="utf-8", errors="strict")
                )
                successor_payload = json.loads(
                    (
                        root / PREVERIFY_DELIVERY_SUCCESSOR_NAME
                    ).read_text(encoding="utf-8", errors="strict")
                )
                validate_preverify_successor_payloads(
                    root,
                    final_payload=final_payload,
                    delivery_payload=successor_payload,
                    run_id=str(final_payload.get("run_id") or ""),
                )
            else:
                projection = resolve_active_preverify_projection(root)
                successor_payload = projection["delivery_payload"]
            payload = successor_payload.get("delivery_payload")
        except (
            OSError,
            UnicodeError,
            json.JSONDecodeError,
            AttributeError,
            PreverifyInventorySuccessorError,
            PreverifyProjectionAuthorityError,
            KeyError,
            TypeError,
        ) as exc:
            raise MandatoryReverificationError(
                "registered finding-delivery successor is unavailable"
            ) from exc
        if not isinstance(payload, dict):
            raise MandatoryReverificationError(
                "registered finding-delivery successor payload is malformed"
            )
        return payload

    path = root / "finding_delivery_receipt.json"
    try:
        payload = json.loads(path.read_text(encoding="utf-8", errors="strict"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise MandatoryReverificationError(
            "registered finding-delivery receipt is unavailable"
        ) from exc
    if not isinstance(payload, dict) or payload.get("schema_version") != (
        "plamen.finding_delivery.v2"
    ):
        raise MandatoryReverificationError(
            "registered finding-delivery receipt schema mismatch"
        )
    unsigned = {
        key: value for key, value in payload.items() if key != "receipt_digest"
    }
    if payload.get("receipt_digest") != canonical_digest(unsigned):
        raise MandatoryReverificationError(
            "registered finding-delivery receipt digest mismatch"
        )
    if payload.get("registry_digest") != registry_digest():
        raise MandatoryReverificationError(
            "registered finding-delivery registry binding is stale"
        )
    inventory = root / "findings_inventory.md"
    if payload.get("inventory_sha256") != "sha256:" + _file_sha256(inventory):
        raise MandatoryReverificationError(
            "registered finding-delivery inventory binding is stale"
        )
    artifacts = payload.get("artifacts")
    actions = payload.get("actions")
    if not isinstance(artifacts, list) or not isinstance(actions, list):
        raise MandatoryReverificationError(
            "registered finding-delivery denominator is malformed"
        )
    for artifact in artifacts:
        if not isinstance(artifact, Mapping):
            raise MandatoryReverificationError(
                "registered finding-delivery artifact row is malformed"
            )
        source = _safe_scratch_source(
            root, str(artifact.get("artifact") or "")
        )
        if artifact.get("sha256") != "sha256:" + _file_sha256(source):
            raise MandatoryReverificationError(
                f"registered source binding is stale: {source.name}"
            )
    for action in actions:
        if not isinstance(action, Mapping):
            raise MandatoryReverificationError(
                "registered finding-delivery action row is malformed"
            )
        unsigned_action = {
            key: value for key, value in action.items() if key != "action_digest"
        }
        if action.get("action_digest") != canonical_digest(unsigned_action):
            raise MandatoryReverificationError(
                "registered finding-delivery action digest mismatch"
            )
    return payload


def _projection_heading_count(path: Path) -> int:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return 1
    return max(
        1,
        len(re.findall(r"(?im)^#{2,4}\s+Finding\s+\[ASKP-\d+\]", text)),
    )


def _parse_primary_projection_candidates(
    path: Path,
    *,
    producer: str,
) -> tuple[list[dict[str, Any]], list[dict[str, str]], int]:
    """Parse projection rows independently so one bad row cannot erase peers.

    Global encoding/schema drift still fails the artifact.  Once that envelope
    is established, each heading block is normalized through the producer's
    typed candidate normalizer.  Malformed or repeated identities become exact
    non-authoritative denominator debt instead of aborting the whole source.
    """

    from finding_producer_registry import (
        APPLICATION_SKEPTIC_PROJECTION_SCHEMA,
        CandidateSchemaError,
        normalize_application_skeptic_proposal,
    )

    try:
        text = Path(path).read_text(encoding="utf-8", errors="strict")
    except (OSError, UnicodeError) as exc:
        raise MandatoryReverificationError(
            "application projection is unavailable or malformed"
        ) from exc
    schema_matches = list(
        re.finditer(
            r"(?im)^\*\*Projection Schema\*\*:\s*(.*?)\s*$",
            text,
        )
    )
    if (
        len(schema_matches) != 1
        or schema_matches[0].group(1).strip()
        != APPLICATION_SKEPTIC_PROJECTION_SCHEMA
    ):
        raise MandatoryReverificationError(
            "application projection schema binding is missing or ambiguous"
        )
    headings = list(
        re.finditer(
            r"(?m)^### Finding \[(ASKP-\d+)\]:\s*(.*?)\s*$",
            text,
        )
    )

    def projection_value(block: str, label: str) -> str:
        match = re.search(
            rf"(?im)^\*\*{re.escape(label)}\*\*:\s*(.*?)\s*$",
            block,
        )
        return match.group(1).strip() if match else ""

    proposals: list[dict[str, Any]] = []
    debts: list[dict[str, str]] = []
    seen_local_ids: set[str] = set()
    seen_proposal_ids: set[str] = set()
    for ordinal, heading in enumerate(headings, start=1):
        end = headings[ordinal].start() if ordinal < len(headings) else len(text)
        block = text[heading.start():end]
        local_id = heading.group(1).strip().upper()
        raw: dict[str, object] = {
            "schema_version": projection_value(block, "Proposal Schema"),
            "producer": "application_skeptic",
            "source_obligation_id": projection_value(
                block, "Source Obligation ID"
            ),
            "source_work_item_id": projection_value(
                block, "Source Work Item ID"
            ),
            "assessor_identity": projection_value(block, "Assessor Identity"),
            "assessor_invocation_id": projection_value(
                block, "Assessor Invocation ID"
            ),
            "assessor_evidence_sha256": projection_value(
                block, "Assessor Evidence SHA-256"
            ),
            "candidate": {
                "title": heading.group(2).strip(),
                "mechanism": projection_value(block, "Description"),
                "harm": projection_value(block, "Impact"),
            },
            "proposal_id": projection_value(block, "Proposal ID"),
            "proposal_digest": projection_value(block, "Proposal Digest"),
        }
        raw_identity = str(raw["proposal_id"] or "").strip().upper()
        source_identity = (
            raw_identity
            if re.fullmatch(r"ASCP-[A-F0-9]{24}", raw_identity)
            else f"{producer}:{ordinal:04d}"
        )
        try:
            normalized = normalize_application_skeptic_proposal(raw)
        except CandidateSchemaError as exc:
            debts.append({
                "source_identity": source_identity,
                "reason_code": "SOURCE_PROJECTION_CANDIDATE_MALFORMED",
                "detail": _bounded_debt_detail(
                    f"{path.name}:{local_id} candidate row is quarantined", exc
                ),
            })
            continue
        proposal_id = str(normalized["proposal_id"])
        duplicate_kinds = []
        if local_id in seen_local_ids:
            duplicate_kinds.append("local projection ID")
        if proposal_id in seen_proposal_ids:
            duplicate_kinds.append("proposal ID")
        if duplicate_kinds:
            debts.append({
                "source_identity": f"{producer}:{ordinal:04d}:{proposal_id}",
                "reason_code": "SOURCE_PROJECTION_CANDIDATE_ID_DUPLICATE",
                "detail": (
                    f"{path.name}:{local_id} repeats "
                    + " and ".join(duplicate_kinds)
                    + " and is quarantined"
                ),
            })
            continue
        seen_local_ids.add(local_id)
        seen_proposal_ids.add(proposal_id)
        proposals.append(dict(normalized))
    return proposals, debts, len(headings)


def _compile_security_obligation_reverification_sources(
    root: Path,
) -> tuple[
    list[dict[str, str]],
    list[dict[str, Any]],
    list[dict[str, str]],
    int,
]:
    """Adapt exact pending P1-C alias/receipt rows into the denominator.

    The security-obligation authority owns classification and application
    state.  This adapter owns only the independent-verification lifecycle.  It
    therefore consumes the authority's exact per-receipt binding without
    re-interpreting the underlying source relation.  A row that cannot be
    replayed becomes one denominator debt; it is never omitted or guessed.
    """

    source_path = root / _SECURITY_OBLIGATION_SOURCE
    actual_source_sha: str | None = None
    if source_path.is_file():
        try:
            actual_source_sha = _file_sha256(source_path)
        except MandatoryReverificationError:
            actual_source_sha = None
    source_bindings = (
        [{
            "artifact": _SECURITY_OBLIGATION_SOURCE,
            "sha256": actual_source_sha,
        }]
        if actual_source_sha is not None
        else []
    )
    try:
        from security_obligation_authority import (
            read_pending_security_obligation_verification,
        )
    except (ImportError, AttributeError) as exc:
        if not source_path.is_file():
            return [], [], [], 0
        return source_bindings, [], [{
            "source_identity": "security-obligation-authority",
            "reason_code": "SECURITY_OBLIGATION_AUTHORITY_UNAVAILABLE",
            "detail": (
                "pending security-obligation reader is unavailable "
                f"({type(exc).__name__})"
            ),
        }], 1

    try:
        raw_rows = read_pending_security_obligation_verification(root)
    except Exception as exc:
        if not source_path.is_file():
            return [], [], [], 0
        return source_bindings, [], [{
            "source_identity": "security-obligation-authority",
            "reason_code": "SECURITY_OBLIGATION_AUTHORITY_UNAVAILABLE",
            "detail": (
                "pending security-obligation authority cannot be replayed "
                f"({type(exc).__name__})"
            ),
        }], 1

    if not isinstance(raw_rows, list):
        return source_bindings, [], [{
            "source_identity": "security-obligation-authority",
            "reason_code": "SECURITY_OBLIGATION_AUTHORITY_MALFORMED",
            "detail": "pending security-obligation reader did not return a list",
        }], 1
    if not raw_rows:
        return source_bindings, [], [], 0

    candidates: list[dict[str, Any]] = []
    debts: list[dict[str, str]] = []
    seen_aliases: set[str] = set()
    for ordinal, value in enumerate(raw_rows, start=1):
        identity = f"security-obligation:{ordinal:04d}"
        if isinstance(value, Mapping):
            hinted = str(
                value.get("alias_id") or value.get("obligation_id") or ""
            )
            if hinted and re.fullmatch(
                r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}", hinted
            ):
                identity = hinted
            if (
                str(value.get("display_id") or "").upper() == "SO-000"
                or not str(value.get("finding_id") or "").strip()
            ):
                debts.append({
                    "source_identity": identity,
                    "reason_code": "SECURITY_OBLIGATION_AUTHORITY_DEBT",
                    "detail": (
                        "security-obligation authority returned a fail-visible "
                        "non-finding debt row"
                    ),
                })
                continue
        try:
            row = _exact(
                value,
                _SECURITY_OBLIGATION_PENDING_FIELDS,
                "pending security-obligation verification",
            )
            alias_id = _text(row["alias_id"], "alias_id", allow_empty=True)
            relation_id = _text(
                row["relation_id"], "relation_id", allow_empty=True
            )
            normalized = {
                "obligation_id": _safe_id(row["obligation_id"], "obligation_id"),
                "display_id": _safe_id(row["display_id"], "display_id"),
                "alias_id": _safe_id(alias_id, "alias_id") if alias_id else "",
                "relation_id": (
                    _safe_id(relation_id, "relation_id") if relation_id else ""
                ),
                "object_id": _text(row["object_id"], "object_id", allow_empty=True),
                "symbol": _text(row["symbol"], "symbol", allow_empty=True),
                "finding_id": _safe_id(row["finding_id"], "finding_id"),
                "receipt_id": _safe_id(row["receipt_id"], "receipt_id"),
                "question": _text(row["question"], "question"),
                "source_artifact": _text(
                    row["source_artifact"], "source_artifact"
                ),
                "source_artifact_sha256": _sha256(
                    row["source_artifact_sha256"],
                    "source_artifact_sha256",
                ),
                "alias_binding_sha256": _sha256(
                    row["alias_binding_sha256"], "alias_binding_sha256"
                ),
            }
            if normalized["source_artifact"] != _SECURITY_OBLIGATION_SOURCE:
                raise MandatoryReverificationError(
                    "pending security-obligation source artifact is not canonical"
                )
            alias_binding = {
                key: normalized[key]
                for key in _SECURITY_OBLIGATION_PENDING_FIELDS
                if key != "alias_binding_sha256"
            }
            if normalized["alias_binding_sha256"] != _digest(alias_binding):
                raise MandatoryReverificationError(
                    "pending security-obligation alias binding digest is stale"
                )
            if (
                actual_source_sha is None
                or normalized["source_artifact_sha256"] != actual_source_sha
            ):
                raise MandatoryReverificationError(
                    "pending security-obligation source authority binding is stale"
                )
            if normalized["alias_id"]:
                relation_bound = bool(normalized["relation_id"])
                symbol_bound = bool(normalized["symbol"])
                if (
                    not normalized["object_id"]
                    or relation_bound != symbol_bound
                ):
                    raise MandatoryReverificationError(
                        "pending security-obligation alias relation is incomplete"
                    )
            source_identity = normalized["alias_id"] or normalized["receipt_id"]
            if source_identity in seen_aliases:
                debts.append({
                    "source_identity": source_identity,
                    "reason_code": "SECURITY_OBLIGATION_DUPLICATE_ALIAS",
                    "detail": (
                        "pending security-obligation alias/receipt identity is "
                        "duplicated"
                    ),
                })
                continue
            seen_aliases.add(source_identity)
        except MandatoryReverificationError as exc:
            debts.append({
                "source_identity": identity,
                "reason_code": "SECURITY_OBLIGATION_SOURCE_MALFORMED_OR_STALE",
                "detail": str(exc),
            })
            continue

        exact_evidence = (
            f"security-obligation:{normalized['obligation_id']}; "
            f"display:{normalized['display_id']}; "
            f"alias:{normalized['alias_id'] or 'none'}; "
            f"relation:{normalized['relation_id'] or 'none'}; "
            f"object:{normalized['object_id'] or 'none'}; "
            f"symbol:{normalized['symbol'] or 'none'}; "
            f"finding:{normalized['finding_id']}; "
            f"receipt:{normalized['receipt_id']}; "
            f"alias-binding-sha256:{normalized['alias_binding_sha256']}"
        )
        candidates.append({
            "obligation_kind": "ADDITIVE_REOPEN",
            "candidate_id": normalized["finding_id"],
            "source_candidate_id": (
                normalized["alias_id"] or normalized["receipt_id"]
            ),
            "source_artifact": _SECURITY_OBLIGATION_SOURCE,
            "source_artifact_sha256": actual_source_sha,
            "source_proposal_id": normalized["receipt_id"],
            # Mandatory completion is alias/receipt-scoped.  Binding the
            # parent SOBL here would let one shared parent identity stand in
            # for an unexamined sibling alias during lifecycle reconciliation.
            "source_obligation_id": (
                normalized["alias_id"] or normalized["receipt_id"]
            ),
            "candidate_content_sha256": normalized["alias_binding_sha256"],
            "premise": normalized["question"],
            "harm": (
                "The security-relevant relation remains pending independent "
                "verification."
            ),
            "evidence": exact_evidence,
        })
    return source_bindings, candidates, debts, len(raw_rows)


def compile_primary_reopen_denominator(
    scratchpad: Path,
    *,
    run_id: str,
    trusted_frozen_transaction_input: bool = False,
) -> dict[str, Any]:
    """Join typed additive proposals through exact promotion/inventory bytes.

    A damaged projection, delivery receipt, or source-to-inventory join creates
    one denominator debt row per observed source obligation.  It never becomes
    a vacuous clean result and never guesses an inventory identity.
    """

    root = Path(scratchpad)
    (
        bindings,
        candidates,
        debts,
        observed,
    ) = _compile_security_obligation_reverification_sources(root)
    parsed_sources: list[tuple[str, str, list[dict[str, Any]]]] = []
    for name, producer in _PRIMARY_PROJECTIONS:
        path = root / name
        if not path.is_file():
            continue
        source_sha = _file_sha256(path)
        bindings.append({"artifact": name, "sha256": source_sha})
        try:
            proposals, projection_debts, projection_observed = (
                _parse_primary_projection_candidates(path, producer=producer)
            )
        except Exception as exc:
            count = _projection_heading_count(path)
            observed += count
            for ordinal in range(1, count + 1):
                debts.append({
                    "source_identity": f"{producer}:{ordinal:04d}",
                    "reason_code": "SOURCE_PROJECTION_UNBOUND_OR_MALFORMED",
                    "detail": f"{name} cannot be replayed ({type(exc).__name__})",
                })
            continue
        observed += projection_observed
        debts.extend(projection_debts)
        parsed_sources.append((name, producer, proposals))

    if not parsed_sources:
        return build_mandatory_reverification_denominator(
            run_id=run_id,
            candidates=candidates,
            source_bindings=bindings,
            source_obligation_count=observed,
            input_debts=debts,
        )

    try:
        delivery = _load_current_delivery_receipt(
            root,
            trusted_frozen_transaction_input=(
                trusted_frozen_transaction_input
            ),
        )
        inventory_path = root / "findings_inventory.md"
        if (
            not trusted_frozen_transaction_input
            and successor_projection_present(root)
        ):
            projection = resolve_active_preverify_projection(root)
            if projection.get("run_id") != run_id:
                raise MandatoryReverificationError(
                    "preverify projection run differs from primary reopen run"
                )
            inventory_path = root.joinpath(
                *PurePosixPath(
                    str(projection["inventory_source_artifact"])
                ).parts
            )
        inventory = _inventory_records(inventory_path)
    except MandatoryReverificationError as exc:
        for name, producer, proposals in parsed_sources:
            for ordinal, proposal in enumerate(proposals, start=1):
                debts.append({
                    "source_identity": str(proposal.get("proposal_id") or f"{producer}:{ordinal:04d}"),
                    "reason_code": "SOURCE_DELIVERY_AUTHORITY_UNAVAILABLE",
                    "detail": str(exc),
                })
        return build_mandatory_reverification_denominator(
            run_id=run_id,
            candidates=candidates,
            source_bindings=bindings,
            source_obligation_count=observed,
            input_debts=debts,
        )

    # The receipt and inventory are independent join authorities and remain
    # exact denominator inputs even though candidate.source_artifact names the
    # original typed proposal projection.
    delivery_authority_names = (
        (
            PREVERIFY_INVENTORY_SUCCESSOR_NAME,
            PREVERIFY_DELIVERY_SUCCESSOR_NAME,
        )
        if (root / PREVERIFY_INVENTORY_SUCCESSOR_NAME).is_file()
        and (root / PREVERIFY_DELIVERY_SUCCESSOR_NAME).is_file()
        else ("finding_delivery_receipt.json",)
    )
    for name in (*delivery_authority_names, "findings_inventory.md"):
        bindings.append({"artifact": name, "sha256": _file_sha256(root / name)})
    actions = [row for row in delivery["actions"] if isinstance(row, Mapping)]
    for name, producer, proposals in parsed_sources:
        source_sha = _file_sha256(root / name)
        for ordinal, proposal in enumerate(proposals, start=1):
            local_id = f"ASKP-{ordinal}"
            source_identity = str(proposal["proposal_id"])
            matching_actions = [
                row
                for row in actions
                if row.get("source_file") == name
                and row.get("producer_key") == producer
                and str(row.get("action_id") or "").upper() == local_id
                and row.get("source_artifact_hash") == "sha256:" + source_sha
            ]
            inventory_matches = [
                row
                for row in inventory
                if row["primary_artifact"] == name
                and local_id in _source_id_tokens(row["source_ids"])
            ]
            reason = ""
            if len(matching_actions) != 1:
                reason = "registered delivery action is missing or ambiguous"
            elif matching_actions[0].get("disposition") not in {
                "PROMOTED_FINDING", "PROMOTED_AMENDMENT"
            }:
                reason = "registered delivery action was not promoted to inventory"
            elif len(inventory_matches) != 1:
                reason = "source action to inventory identity join is missing or ambiguous"
            if reason:
                debts.append({
                    "source_identity": source_identity,
                    "reason_code": "SOURCE_TO_INVENTORY_JOIN_DEBT",
                    "detail": f"{name}:{local_id}: {reason}",
                })
                continue
            inventory_row = inventory_matches[0]
            candidate = proposal["candidate"]
            assert isinstance(candidate, Mapping)
            evidence = (
                "assessor-evidence-sha256:"
                + str(proposal["assessor_evidence_sha256"])
                + "; inventory:"
                + inventory_row["candidate_id"]
                + "; location:"
                + (inventory_row["location"] or "unresolved")
            )
            candidates.append({
                "obligation_kind": "ADDITIVE_REOPEN",
                "candidate_id": inventory_row["candidate_id"],
                "source_candidate_id": local_id,
                "source_artifact": name,
                "source_artifact_sha256": source_sha,
                "source_proposal_id": proposal["proposal_id"],
                "source_obligation_id": proposal["source_obligation_id"],
                "candidate_content_sha256": proposal["proposal_digest"],
                "premise": candidate["mechanism"],
                "harm": candidate["harm"],
                "evidence": evidence,
            })
    return build_mandatory_reverification_denominator(
        run_id=run_id,
        candidates=candidates,
        source_bindings=bindings,
        source_obligation_count=observed,
        input_debts=debts,
    )


def compile_report_reopen_denominator(
    scratchpad: Path,
    *,
    run_id: str,
    project_root: Path | None = None,
) -> dict[str, Any]:
    """Enumerate exact NC-2 recovery obligations from report authority.

    The report-disposition adapter has already kept these candidates in BODY;
    this compiler creates the distinct independent-verification denominator.
    A self-digest alone is insufficient: every bound source artifact and the
    embedded finding lifecycle are replayed before any recovery work is built.
    """

    from finding_lifecycle_authority import validate_finding_lifecycle
    from finding_producer_registry import canonical_digest
    from report_disposition_authority import validate_report_disposition_authority

    root = Path(scratchpad)
    path = root / "report_disposition_authority.json"
    if not path.is_file():
        return build_mandatory_reverification_denominator(
            run_id=run_id,
            candidates=(),
            source_bindings=(),
        )
    source_sha = _file_sha256(path)
    bindings = [{"artifact": path.name, "sha256": source_sha}]
    try:
        payload = json.loads(path.read_text(encoding="utf-8", errors="strict"))
        if not isinstance(payload, dict) or payload.get("run_id") != run_id:
            raise MandatoryReverificationError(
                "report disposition run identity mismatch"
            )
        unsigned = {
            key: value for key, value in payload.items() if key != "receipt_sha256"
        }
        if payload.get("receipt_sha256") != canonical_digest(unsigned):
            raise MandatoryReverificationError(
                "report disposition authority digest mismatch"
            )
        sources = payload.get("source_artifacts")
        if not isinstance(sources, list) or payload.get(
            "source_set_sha256"
        ) != canonical_digest(sources):
            raise MandatoryReverificationError(
                "report disposition source denominator mismatch"
            )
        for source in sources:
            if not isinstance(source, Mapping):
                raise MandatoryReverificationError(
                    "report disposition source row is malformed"
                )
            relative = str(source.get("path") or "")
            pure = PurePosixPath(relative)
            if (
                not relative
                or "\\" in relative
                or pure.is_absolute()
                or ".." in pure.parts
                or pure.as_posix() != relative
            ):
                raise MandatoryReverificationError(
                    "report disposition source path is not safe and relative"
                )
            source_path = root.joinpath(*pure.parts)
            cursor = root
            for part in pure.parts:
                cursor = cursor / part
                if cursor.is_symlink():
                    raise MandatoryReverificationError(
                        "report disposition source symlink components are not admissible"
                    )
            root_resolved = root.resolve(strict=True)
            source_resolved = source_path.resolve(strict=True)
            try:
                source_resolved.relative_to(root_resolved)
            except ValueError as exc:
                raise MandatoryReverificationError(
                    "report disposition source escapes scratchpad"
                ) from exc
            raw = source_path.read_bytes()
            if (
                source.get("sha256") != hashlib.sha256(raw).hexdigest()
                or source.get("size_bytes") != len(raw)
            ):
                raise MandatoryReverificationError(
                    f"report disposition source drift: {source_path.name}"
                )
        if project_root is not None:
            validated = validate_report_disposition_authority(
                root,
                Path(project_root),
                run_id=run_id,
            )
            if validated != payload:
                raise MandatoryReverificationError(
                    "public report disposition validator changed authority"
                )
        try:
            closure_authority = load_central_negative_closure_authority(root)
        except Exception:
            closure_authority = None
        lifecycle = validate_finding_lifecycle(
            payload["finding_lifecycle"],
            closure_authority=closure_authority,
        )
        states = {
            str(row["candidate_id"]): row
            for row in lifecycle["candidate_states"]
        }
        work = []
        for obligation in lifecycle["obligations"]:
            if obligation["obligation_kind"] != (
                "RECOVERY_INDEPENDENT_VERIFICATION"
            ):
                continue
            state = states[str(obligation["candidate_id"])]
            work.append({
                "obligation_id": obligation["obligation_id"],
                "obligation_kind": obligation["obligation_kind"],
                "candidate_id": state["candidate_id"],
                "candidate_content_sha256s": list(
                    state["candidate_content_sha256s"]
                ),
                "title": state["title"],
                "evidence_pointer": state["evidence_pointer"],
            })
    except Exception as exc:
        # Malformed prose is not an enumeration authority.  Preserve one
        # bounded, non-vacuous review debt without deriving cardinality from
        # arbitrary lexical substrings.
        count = 1
        debts = [
            {
                "source_identity": f"report-recovery:{ordinal:04d}",
                "reason_code": "REPORT_RECOVERY_AUTHORITY_UNAVAILABLE",
                "detail": f"report disposition lifecycle cannot replay ({type(exc).__name__})",
            }
            for ordinal in range(1, count + 1)
        ]
        return build_mandatory_reverification_denominator(
            run_id=run_id,
            candidates=(),
            source_bindings=bindings,
            source_obligation_count=count,
            input_debts=debts,
        )

    from post_verify_candidate_delta import (
        PostVerifyCandidateDeltaError,
        load_current_report_candidate_universe_authority,
    )

    try:
        universe = load_current_report_candidate_universe_authority(
            root,
            run_id=run_id,
            project_root=root.parent,
        )
        bound_by_id = {
            row.item.work_item_id: row for row in universe.candidates
        }
        for relative in universe.input_artifacts:
            candidate_binding = {
                "artifact": relative,
                "sha256": _file_sha256(
                    root.joinpath(*PurePosixPath(relative).parts)
                ),
            }
            if candidate_binding not in bindings:
                bindings.append(candidate_binding)
    except (PostVerifyCandidateDeltaError, OSError, UnicodeError, ValueError) as exc:
        debts = [
            {
                "source_identity": str(item["obligation_id"]),
                "reason_code": "REPORT_RECOVERY_CANDIDATE_UNIVERSE_UNAVAILABLE",
                "detail": (
                    "authenticated base-plus-post-verify universe is "
                    f"unavailable: {type(exc).__name__}: {exc}"
                ),
            }
            for item in work
        ]
        return build_mandatory_reverification_denominator(
            run_id=run_id,
            candidates=(),
            source_bindings=bindings,
            source_obligation_count=len(work),
            input_debts=debts,
        )

    base_work_ids = {
        str(item["candidate_id"])
        for item in work
        if (
            bound_by_id.get(str(item["candidate_id"])) is not None
            and bound_by_id[str(item["candidate_id"])].source_kind
            == "BASE_VERIFICATION_QUEUE"
        )
    }
    inventory_by_id: dict[str, dict[str, Any]] = {}
    debts: list[dict[str, str]] = []
    if base_work_ids:
        try:
            if successor_projection_present(root):
                projection = resolve_active_preverify_projection(root)
                if projection.get("run_id") != run_id:
                    raise PreverifyProjectionAuthorityError(
                        "preverify projection run differs from report recovery run"
                    )
                inventory_relative = str(
                    projection["inventory_source_artifact"]
                )
                inventory_path = root.joinpath(
                    *PurePosixPath(inventory_relative).parts
                )
            else:
                inventory_relative = "findings_inventory.md"
                inventory_path = root / inventory_relative
            inventory_sha = _file_sha256(inventory_path)
            inventory_rows = _inventory_records(inventory_path)
            inventory_by_id = {
                row["candidate_id"]: row for row in inventory_rows
            }
            inventory_binding = {
                "artifact": inventory_relative,
                "sha256": inventory_sha,
            }
            if inventory_binding not in bindings:
                bindings.append(inventory_binding)
        except (
            MandatoryReverificationError,
            PreverifyProjectionAuthorityError,
            KeyError,
            OSError,
            TypeError,
            UnicodeError,
            ValueError,
        ) as exc:
            debts.extend([
                {
                    "source_identity": str(item["obligation_id"]),
                    "reason_code": "REPORT_RECOVERY_INVENTORY_UNAVAILABLE",
                    "detail": str(exc),
                }
                for item in work
                if str(item["candidate_id"]) in base_work_ids
            ])
            # Delta claims remain joinable even when the frozen base projection
            # is unavailable.  Retain base failures as exact debt instead of
            # discarding successfully authenticated delta recovery work.
            inventory_by_id = {}
    authority_rows = {
        str(row.get("candidate_id") or ""): row
        for row in payload.get("rows", [])
        if isinstance(row, Mapping)
    }
    candidates: list[dict[str, Any]] = []
    for item in work:
        obligation_id = str(item["obligation_id"])
        candidate_id = str(item["candidate_id"])
        hashes = list(item.get("candidate_content_sha256s") or [])
        authority_row = authority_rows.get(candidate_id)
        bound = bound_by_id.get(candidate_id)
        inventory_row = inventory_by_id.get(candidate_id, {})
        if (
            bound is not None
            and bound.source_kind != "BASE_VERIFICATION_QUEUE"
        ):
            premise = str(bound.claim.get("premise") or "").strip()
            harm = str(bound.claim.get("harm") or "").strip()
            evidence = str(bound.claim.get("evidence") or "").strip()
            claim_available = bool(premise and harm and evidence)
        else:
            premise = str(inventory_row.get("premise") or "").strip()
            harm = str(inventory_row.get("harm") or "").strip()
            evidence = str(item.get("evidence_pointer") or "").strip()
            claim_available = bool(inventory_row and premise and harm)
        if (
            len(hashes) != 1
            or not isinstance(authority_row, Mapping)
            or bound is None
            or not claim_available
            or authority_row.get("mandatory_reverification_id") != obligation_id
            or authority_row.get("mandatory_reverification") is not True
        ):
            debts.append({
                "source_identity": obligation_id,
                "reason_code": "REPORT_RECOVERY_JOIN_DEBT",
                "detail": (
                    f"{candidate_id} lacks one exact lifecycle/content/report-row binding"
                ),
            })
            continue
        candidates.append({
            "obligation_kind": "RECOVERY_INDEPENDENT_VERIFICATION",
            "candidate_id": candidate_id,
            "source_candidate_id": candidate_id,
            "source_artifact": path.name,
            "source_artifact_sha256": source_sha,
            "source_proposal_id": str(
                authority_row.get("authority_event_id") or obligation_id
            ),
            "source_obligation_id": obligation_id,
            "candidate_content_sha256": hashes[0],
            "premise": premise,
            "harm": harm,
            "evidence": evidence,
        })
    return build_mandatory_reverification_denominator(
        run_id=run_id,
        candidates=candidates,
        source_bindings=bindings,
        source_obligation_count=len(work),
        input_debts=debts,
    )


def _write_bound_json(
    path: Path,
    payload: Mapping[str, Any],
    *,
    validate: Any,
) -> bool:
    normalized = validate(payload)
    rendered = json.dumps(
        normalized, indent=2, sort_keys=True, ensure_ascii=False
    ) + "\n"
    if path.is_file():
        try:
            existing = json.loads(path.read_text(encoding="utf-8", errors="strict"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise MandatoryReverificationError(
                f"existing {path.name} is unreadable"
            ) from exc
        if validate(existing) != normalized:
            raise MandatoryReverificationError(
                f"existing {path.name} differs from current authority"
            )
        if path.read_text(encoding="utf-8", errors="strict") != rendered:
            raise MandatoryReverificationError(
                f"existing {path.name} bytes are non-canonical"
            )
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(rendered, encoding="utf-8", newline="\n")
    os.replace(temporary, path)
    return True


_QUEUE_TRANSACTION_SCHEMA = "plamen.mandatory_reverification_queue_transaction.v1"
_QUEUE_TRANSACTION_RECEIPT_SCHEMA = (
    "plamen.mandatory_reverification_queue_transaction_receipt.v1"
)
_QUEUE_TRANSACTION_PATHS = (
    "verification_queue.md",
    "verification_queue.json",
    "verification_queue.work_items.json",
    "verification_queue_evidence_excluded.md",
    "verification_queue_evidence_excluded.json",
    ROUTING_FILE,
)


def _atomic_transaction_bytes(path: Path, raw: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _replace_mandatory_queue_transaction_file(path: Path, raw: bytes) -> None:
    """Patchable crash boundary: publish one fixed transaction postimage."""

    _atomic_transaction_bytes(path, raw)


def _transaction_payload_digest(value: Mapping[str, Any]) -> str:
    return _digest({key: value for key, value in value.items() if key != "digest"})


def _validate_queue_transaction(
    value: Mapping[str, Any],
    denominator: Mapping[str, Any],
) -> dict[str, Any]:
    fields = frozenset({
        "schema_version", "run_id", "denominator_digest", "state", "files",
        "digest",
    })
    row = _exact(value, fields, "mandatory queue transaction")
    authority = validate_mandatory_reverification_denominator(denominator)
    if (
        row["schema_version"] != _QUEUE_TRANSACTION_SCHEMA
        or row["state"] != "PREPARED"
        or row["run_id"] != authority["run_id"]
        or row["denominator_digest"] != authority["denominator_digest"]
    ):
        raise MandatoryReverificationError(
            "mandatory queue transaction authority is stale"
        )
    if not isinstance(row["files"], list):
        raise MandatoryReverificationError(
            "mandatory queue transaction files are invalid"
        )
    observed: list[str] = []
    for raw_file in row["files"]:
        file_row = _exact(
            raw_file,
            frozenset({
                "path", "pre_exists", "pre_sha256", "post_sha256", "post_b64",
            }),
            "mandatory queue transaction file",
        )
        relative = _text(file_row["path"], "transaction path")
        if relative not in _QUEUE_TRANSACTION_PATHS or relative in observed:
            raise MandatoryReverificationError(
                "mandatory queue transaction path set is invalid"
            )
        observed.append(relative)
        if not isinstance(file_row["pre_exists"], bool):
            raise MandatoryReverificationError(
                "mandatory queue transaction pre_exists is invalid"
            )
        if file_row["pre_exists"]:
            _sha256(file_row["pre_sha256"], "pre_sha256")
        elif file_row["pre_sha256"] is not None:
            raise MandatoryReverificationError(
                "absent mandatory preimage acquired a digest"
            )
        post_sha = _sha256(file_row["post_sha256"], "post_sha256")
        try:
            post = base64.b64decode(file_row["post_b64"], validate=True)
        except (TypeError, ValueError) as exc:
            raise MandatoryReverificationError(
                "mandatory queue transaction postimage is invalid"
            ) from exc
        if hashlib.sha256(post).hexdigest() != post_sha:
            raise MandatoryReverificationError(
                "mandatory queue transaction postimage digest mismatch"
            )
    if tuple(observed) != _QUEUE_TRANSACTION_PATHS:
        raise MandatoryReverificationError(
            "mandatory queue transaction denominator is incomplete"
        )
    if row["digest"] != _transaction_payload_digest(row):
        raise MandatoryReverificationError(
            "mandatory queue transaction digest mismatch"
        )
    return row


def _queue_transaction_receipt(
    transaction: Mapping[str, Any],
) -> dict[str, Any]:
    unsigned = {
        "schema_version": _QUEUE_TRANSACTION_RECEIPT_SCHEMA,
        "run_id": transaction["run_id"],
        "denominator_digest": transaction["denominator_digest"],
        "state": "COMMITTED",
        "files": [
            {
                "path": row["path"],
                "pre_exists": row["pre_exists"],
                "pre_sha256": row["pre_sha256"],
                "post_sha256": row["post_sha256"],
            }
            for row in transaction["files"]
        ],
        "terminal_negative_authority": False,
    }
    return {**unsigned, "digest": _digest(unsigned)}


def _publish_queue_transaction(
    root: Path,
    transaction: Mapping[str, Any],
) -> None:
    for row in transaction["files"]:
        path = root / str(row["path"])
        if path.is_symlink() or (path.exists() and not path.is_file()):
            raise MandatoryReverificationError(
                f"mandatory queue transaction path is unsafe: {row['path']}"
            )
        post = base64.b64decode(row["post_b64"], validate=True)
        actual = hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None
        if actual == row["post_sha256"]:
            continue
        allowed_pre = row["pre_sha256"] if row["pre_exists"] else None
        if actual != allowed_pre:
            raise MandatoryReverificationError(
                f"mandatory queue transaction found foreign bytes: {row['path']}"
            )
        _replace_mandatory_queue_transaction_file(path, post)
    # A publish is not a commit.  Re-read the complete fixed denominator after
    # the final replacement so a concurrent writer or crash hook cannot turn a
    # split/foreign queue state into a COMMITTED receipt.
    for row in transaction["files"]:
        path = root / str(row["path"])
        if path.is_symlink() or not path.is_file():
            raise MandatoryReverificationError(
                f"mandatory queue transaction postimage is unavailable: {row['path']}"
            )
        try:
            actual = hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError as exc:
            raise MandatoryReverificationError(
                f"mandatory queue transaction postimage is unreadable: {row['path']}"
            ) from exc
        if actual != row["post_sha256"]:
            raise MandatoryReverificationError(
                f"mandatory queue transaction foreign postimage: {row['path']}"
            )


def _recover_queue_transaction(
    root: Path,
    denominator: Mapping[str, Any],
) -> dict[str, Any] | None:
    journal_path = root / QUEUE_TRANSACTION_JOURNAL_FILE
    if not journal_path.is_file():
        return None
    try:
        raw = json.loads(journal_path.read_text(encoding="utf-8", errors="strict"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise MandatoryReverificationError(
            "mandatory queue transaction journal is unreadable"
        ) from exc
    transaction = _validate_queue_transaction(raw, denominator)
    _publish_queue_transaction(root, transaction)
    receipt = _queue_transaction_receipt(transaction)
    _write_bound_json(
        root / QUEUE_TRANSACTION_RECEIPT_FILE,
        receipt,
        validate=lambda value: value
        if value == receipt
        else (_ for _ in ()).throw(
            MandatoryReverificationError(
                "mandatory queue transaction receipt changed"
            )
        ),
    )
    journal_path.unlink()
    routing = json.loads(
        (root / ROUTING_FILE).read_text(encoding="utf-8", errors="strict")
    )
    return _validate_routing(routing, denominator)


def apply_primary_reopens_to_queue(
    scratchpad: Path,
    denominator: Mapping[str, Any],
) -> dict[str, Any]:
    """Apply the additive bypass after ordinary queue filters/grouping."""

    from plamen_parsers import (
        _queue_rows_from_inventory,
        _read_queue_json_sidecar,
        _read_typed_queue_work_items,
        _write_queue_excluded_manifest,
        _write_queue_work_item_records_manifest,
    )

    root = Path(scratchpad)
    authority = validate_mandatory_reverification_denominator(denominator)
    _recover_queue_transaction(root, authority)
    queue_path = root / "verification_queue.md"
    typed_path = root / "verification_queue.work_items.json"
    if typed_path.is_file():
        active = _read_typed_queue_work_items(queue_path)
    else:
        active = tuple(
            QueueWorkItem.from_legacy_row(row)
            for row in _queue_rows_from_inventory(root)
        )
    active = validate_queue_work_items(active)

    # An exact prior route is the resume authority.  Recomputing after a
    # restored item became active would change RESTORED_AFTER_FILTER into
    # DIRECT_ACTIVE and make byte-idempotent resume impossible.
    routing_path = root / ROUTING_FILE
    if routing_path.is_file():
        try:
            prior = json.loads(
                routing_path.read_text(encoding="utf-8", errors="strict")
            )
            validated = _validate_routing(prior, authority)
            by_id = {item.work_item_id: item for item in active}
            for route in validated["routes"]:
                item = by_id.get(str(route["assigned_work_item_id"]))
                if (
                    item is None
                    or item.digest != route["assigned_work_item_digest"]
                    or route["candidate_id"] not in _item_identities(item)
                ):
                    raise MandatoryReverificationError(
                        "prior mandatory route is stale for current typed queue"
                    )
            return validated
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise MandatoryReverificationError(
                "prior mandatory routing authority is malformed"
            ) from exc

    excluded_path = root / "verification_queue_evidence_excluded.md"
    excluded_rows = _read_queue_json_sidecar(excluded_path)
    full_rows = _queue_rows_from_inventory(root)
    fallback_by_id: dict[str, QueueWorkItem] = {}
    for row in [*excluded_rows, *full_rows]:
        try:
            item = QueueWorkItem.from_legacy_row(row)
        except Exception:
            continue
        prior = fallback_by_id.get(item.work_item_id)
        if prior is not None and prior != item:
            # Prefer the inventory reconstruction over an excluded projection
            # only when its executable record is exact.  A disagreement is
            # intentionally left ambiguous for route_mandatory_reverification.
            continue
        fallback_by_id[item.work_item_id] = item
    routed_items, routing = route_mandatory_reverification(
        denominator=authority,
        active_items=active,
        fallback_items=tuple(fallback_by_id.values()),
    )
    if routed_items != active:
        restored_candidates = {
            str(route["candidate_id"])
            for route in routing["routes"]
            if route["routing_kind"] == "RESTORED_AFTER_FILTER"
        }
        retained_excluded = [
            row
            for row in excluded_rows
            if str(row.get("finding id") or "") not in restored_candidates
        ]
        with tempfile.TemporaryDirectory(
            prefix=".mandatory-reverification-stage-", dir=root
        ) as temporary_name:
            stage = Path(temporary_name)
            _write_queue_work_item_records_manifest(
                stage / queue_path.name, routed_items
            )
            _write_queue_excluded_manifest(
                stage / excluded_path.name, retained_excluded
            )
            _write_bound_json(
                stage / ROUTING_FILE,
                routing,
                validate=lambda value: _validate_routing(value, authority),
            )
            file_rows: list[dict[str, Any]] = []
            for relative in _QUEUE_TRANSACTION_PATHS:
                target = root / relative
                post = (stage / relative).read_bytes()
                pre = target.read_bytes() if target.is_file() else None
                file_rows.append({
                    "path": relative,
                    "pre_exists": pre is not None,
                    "pre_sha256": (
                        hashlib.sha256(pre).hexdigest() if pre is not None else None
                    ),
                    "post_sha256": hashlib.sha256(post).hexdigest(),
                    "post_b64": base64.b64encode(post).decode("ascii"),
                })
        unsigned_transaction = {
            "schema_version": _QUEUE_TRANSACTION_SCHEMA,
            "run_id": authority["run_id"],
            "denominator_digest": authority["denominator_digest"],
            "state": "PREPARED",
            "files": file_rows,
        }
        transaction = {
            **unsigned_transaction,
            "digest": _digest(unsigned_transaction),
        }
        _atomic_transaction_bytes(
            root / QUEUE_TRANSACTION_JOURNAL_FILE,
            (
                json.dumps(
                    transaction, indent=2, sort_keys=True, ensure_ascii=False
                ) + "\n"
            ).encode("utf-8"),
        )
        recovered = _recover_queue_transaction(root, authority)
        if recovered is None:
            raise MandatoryReverificationError(
                "mandatory queue transaction did not publish routing authority"
            )
        return recovered
    _write_bound_json(
        routing_path,
        routing,
        validate=lambda value: _validate_routing(value, authority),
    )
    return routing


def bind_primary_reopen_assignments_from_scratchpad(
    scratchpad: Path,
    denominator: Mapping[str, Any],
    routing: Mapping[str, Any],
) -> dict[str, Any]:
    """Bind mandatory routes to the current queue plan and runtime roster."""

    from plamen_parsers import read_queue_work_plan
    from verifier_work_roster import VerifierWorkRoster

    root = Path(scratchpad)
    try:
        plan = read_queue_work_plan(root)
        roster = VerifierWorkRoster.from_json(
            (root / "verification_runtime_roster.json").read_text(
                encoding="utf-8", errors="strict"
            )
        )
    except Exception as exc:
        raise MandatoryReverificationError(
            f"mandatory verifier assignment authority unavailable: {type(exc).__name__}: {exc}"
        ) from exc
    assignment = bind_mandatory_reverification_assignments(
        denominator=denominator,
        routing=routing,
        queue_plan=plan,
        roster=roster,
    )
    _write_bound_json(
        root / ASSIGNMENT_FILE,
        assignment,
        validate=lambda value: _validate_assignment(value, denominator),
    )
    return assignment


def reconcile_primary_reopen_completion_from_scratchpad(
    scratchpad: Path,
    denominator: Mapping[str, Any],
    assignment: Mapping[str, Any],
    *,
    completion_validator: Any,
) -> dict[str, Any]:
    """Replay exact primary verifier completion for every assigned reopen.

    ``completion_validator(root, work_id)`` must return an empty sequence only
    after the queue identity, work plan, roster, per-output receipt, and PhaseIO
    authority replay.  This consumer never manufactures that authority.
    """

    root = Path(scratchpad)
    assigned = _validate_assignment(assignment, denominator)
    work_ids = sorted({
        str(row["assigned_work_item_id"])
        for row in assigned["assignments"]
    })
    evidence: dict[str, dict[str, Any]] = {}
    for work_id in work_ids:
        try:
            issues = list(completion_validator(root, work_id))
        except Exception:
            issues = ["completion validator failed"]
        if issues:
            continue
        output = root / f"verify_{work_id}.md"
        receipt = root / f"verify_{work_id}.receipt.json"
        try:
            evidence[work_id] = {
                "completion_authorized": True,
                "output_sha256": _file_sha256(output),
                "receipt_sha256": _file_sha256(receipt),
            }
        except MandatoryReverificationError:
            continue
    completion = reconcile_mandatory_reverification_completion(
        denominator=denominator,
        assignment=assigned,
        completion_evidence=evidence,
    )
    _write_or_advance_completion(
        root / COMPLETION_FILE,
        completion,
        denominator=denominator,
    )
    return completion


def _write_or_advance_completion(
    path: Path,
    value: Mapping[str, Any],
    *,
    denominator: Mapping[str, Any],
) -> bool:
    """Advance RETRY_REQUIRED to exact completion without negative caching."""

    target = Path(path)
    current = _validate_completion(value, denominator)
    assert current is not None
    if not target.is_file():
        return _write_bound_json(
            target,
            current,
            validate=lambda payload: _validate_completion(payload, denominator),
        )
    try:
        prior_raw = json.loads(
            target.read_text(encoding="utf-8", errors="strict")
        )
        prior = _validate_completion(prior_raw, denominator)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise MandatoryReverificationError(
            "existing mandatory completion is unreadable"
        ) from exc
    assert prior is not None
    immutable_fields = (
        "run_id", "denominator_digest", "assignment_authority_kind",
        "assignment_receipt_digest", "obligation_count",
        "source_input_debt_count", "terminal_negative_authority",
    )
    if any(prior[field] != current[field] for field in immutable_fields):
        raise MandatoryReverificationError(
            "mandatory completion advancement changed immutable authority"
        )
    prior_rows = {row["obligation_id"]: row for row in prior["rows"]}
    current_rows = {row["obligation_id"]: row for row in current["rows"]}
    if set(prior_rows) != set(current_rows):
        raise MandatoryReverificationError(
            "mandatory completion advancement changed denominator"
        )
    for obligation_id, old in prior_rows.items():
        new = current_rows[obligation_id]
        if old["completion_state"] == "EXACTLY_COMPLETED" and new != old:
            raise MandatoryReverificationError(
                "exact mandatory completion cannot regress or change bytes"
            )
    if prior == current:
        return False
    # Every permitted delta is strictly RETRY_REQUIRED -> EXACTLY_COMPLETED.
    for obligation_id, new in current_rows.items():
        old = prior_rows[obligation_id]
        if old != new and not (
            old["completion_state"] == "RETRY_REQUIRED"
            and new["completion_state"] == "EXACTLY_COMPLETED"
        ):
            raise MandatoryReverificationError(
                "mandatory completion attempted a non-monotone transition"
            )
    rendered = json.dumps(
        current, indent=2, sort_keys=True, ensure_ascii=False
    ) + "\n"
    temporary = target.with_suffix(target.suffix + ".tmp")
    temporary.write_text(rendered, encoding="utf-8", newline="\n")
    os.replace(temporary, target)
    return True


def write_or_advance_mandatory_completion(
    path: Path,
    value: Mapping[str, Any],
    *,
    denominator: Mapping[str, Any],
) -> bool:
    """Public bounded writer for monotone mandatory completion authority."""

    return _write_or_advance_completion(
        path, value, denominator=denominator
    )


def write_or_validate_mandatory_delivery(
    path: Path,
    value: Mapping[str, Any],
    *,
    denominator: Mapping[str, Any],
) -> bool:
    """Write immutable delivery accounting distinct from verification."""

    return _write_bound_json(
        Path(path),
        value,
        validate=lambda payload: _validate_delivery(payload, denominator),
    )


def load_mandatory_completion(
    path: Path,
    *,
    denominator: Mapping[str, Any],
) -> dict[str, Any]:
    """Load and replay a completion receipt against its exact denominator."""

    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8", errors="strict"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise MandatoryReverificationError(
            f"mandatory completion is unavailable: {type(exc).__name__}: {exc}"
        ) from exc
    validated = _validate_completion(payload, denominator)
    assert validated is not None
    return validated


def _validate_artifact(value: Mapping[str, Any]) -> dict[str, Any]:
    schema = value.get("schema_version") if isinstance(value, Mapping) else None
    if schema == DENOMINATOR_SCHEMA:
        return validate_mandatory_reverification_denominator(value)
    raise MandatoryReverificationError(
        f"unsupported mandatory artifact schema: {schema!r}"
    )


def write_or_validate_mandatory_artifact(
    path: Path, value: Mapping[str, Any]
) -> bool:
    """Atomically create an immutable authority; exact replay is a no-op."""

    target = Path(path)
    normalized = _validate_artifact(value)
    rendered = json.dumps(
        normalized, indent=2, sort_keys=True, ensure_ascii=False
    ) + "\n"
    if target.is_file():
        try:
            existing = json.loads(
                target.read_text(encoding="utf-8", errors="strict")
            )
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise MandatoryReverificationError(
                f"existing mandatory artifact is unreadable: {exc}"
            ) from exc
        if _validate_artifact(existing) != normalized:
            raise MandatoryReverificationError(
                "existing mandatory artifact differs from current authority"
            )
        if target.read_text(encoding="utf-8", errors="strict") != rendered:
            raise MandatoryReverificationError(
                "existing mandatory artifact bytes are non-canonical"
            )
        return False
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, raw = tempfile.mkstemp(
        prefix=f".{target.name}.", suffix=".tmp", dir=target.parent
    )
    temporary = Path(raw)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(rendered)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, target)
    finally:
        temporary.unlink(missing_ok=True)
    return True


__all__ = [
    "ASSIGNMENT_FILE",
    "ASSIGNMENT_SCHEMA",
    "COMPLETION_FILE",
    "COMPLETION_SCHEMA",
    "DELIVERY_FILE",
    "DELIVERY_SCHEMA",
    "DENOMINATOR_FILE",
    "DENOMINATOR_SCHEMA",
    "MandatoryReverificationError",
    "ROUTING_FILE",
    "ROUTING_SCHEMA",
    "REPORT_COMPLETION_FILE",
    "REPORT_DELIVERY_FILE",
    "REPORT_DENOMINATOR_FILE",
    "QUEUE_TRANSACTION_JOURNAL_FILE",
    "QUEUE_TRANSACTION_RECEIPT_FILE",
    "bind_mandatory_reverification_assignments",
    "bind_primary_reopen_assignments_from_scratchpad",
    "build_mandatory_reverification_denominator",
    "compile_primary_reopen_denominator",
    "compile_report_reopen_denominator",
    "apply_primary_reopens_to_queue",
    "mandatory_recovery_rows",
    "load_mandatory_completion",
    "reconcile_mandatory_recovery_completion",
    "reconcile_mandatory_reverification_completion",
    "reconcile_mandatory_reverification_delivery",
    "reconcile_primary_reopen_completion_from_scratchpad",
    "route_mandatory_reverification",
    "validate_mandatory_reverification_denominator",
    "write_or_advance_mandatory_completion",
    "write_or_validate_mandatory_artifact",
    "write_or_validate_mandatory_delivery",
]
