"""Typed, recall-safe authority for candidate disposition and delivery.

This module is deliberately independent from Markdown parsing and from the
driver.  It reconciles three authorities that must never be conflated:

* a producer may create a content-bearing candidate and record an advisory
  origin assessment;
* an independent discriminator may issue a claim disposition bound to the
  exact candidate content; and
* a report projector may prove that a retained claim was delivered.

The ledger is append-only across resume generations.  Missing or conflicting
authority fails visible: a candidate remains body/human-review work and gains
an exact obligation.  Citation quality, a producer-authored negative verdict,
or a lexical ``DEFERRED`` marker can therefore never manufacture exclusion.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import tempfile
from typing import Any, Iterable, Mapping, Sequence

from negative_closure_policy import supporting_negative_resolution


CANDIDATE_SCHEMA = "plamen.finding_lifecycle_candidate.v1"
DECISION_SCHEMA = "plamen.finding_lifecycle_decision.v1"
PROJECTION_SCHEMA = "plamen.finding_lifecycle_projection.v1"
OBLIGATION_SCHEMA = "plamen.finding_lifecycle_obligation.v1"
LEDGER_SCHEMA = "plamen.finding_lifecycle_authority.v1"

_HEX64 = frozenset("0123456789abcdef")
_CANDIDATE_FIELDS = (
    "schema_version",
    "run_id",
    "candidate_id",
    "lineage_ids",
    "source_artifact",
    "source_artifact_sha256",
    "source_record_sha256",
    "producer_identity",
    "producer_invocation_id",
    "producer_phase",
    "entry_reason",
    "origin_assessment",
    "upstream_severity",
    "title",
    "location",
    "evidence_pointer",
    "candidate_content_sha256",
    "location_quality",
    "source_provenance_quality",
    "scope_state",
)
_DECISION_FIELDS = (
    "schema_version",
    "run_id",
    "decision_id",
    "candidate_id",
    "candidate_content_sha256",
    "decision_kind",
    "evidence_basis",
    "evidence_sha256",
    "proof_scope",
    "discriminator_identity",
    "discriminator_invocation_id",
    "discriminator_phase",
    "alias_target_candidate_id",
    "reason_class",
    "next_action",
    "public_retention_target",
    "scope_snapshot_sha256",
)
_PROJECTION_FIELDS = (
    "schema_version",
    "run_id",
    "projection_id",
    "candidate_id",
    "candidate_content_sha256",
    "projection_kind",
    "artifact_path",
    "artifact_sha256",
    "public_reference",
    "projector_identity",
    "projector_invocation_id",
)
_LEDGER_FIELDS = (
    "schema_version",
    "run_id",
    "generation",
    "previous_receipt_sha256",
    "authority_identity",
    "authority_invocation_id",
    "source_records",
    "source_records_sha256",
    "candidate_states",
    "obligations",
    "rejected_decisions",
    "debt",
    "summary",
    "ledger_sha256",
)
_CENTRAL_CLOSURE_FIELDS = frozenset(
    {
        "schema_version", "status", "outcome", "requested_effect",
        "candidate_id", "work_item_id", "candidate_premise_ids",
        "candidate_content_sha256", "subject_digest",
        "evidence_manifest_digest", "provider_id", "provider_kind",
        "provider_completion_sha256", "provider_publish_sha256",
        "bundle_digest", "survivor_id", "survivor_identity_sha256",
        "reopen_required", "debt_reasons", "resolution_digest",
    }
)

_ENTRY_REASONS = frozenset(
    {
        "NORMAL_DISCOVERY",
        "POST_VERIFY_SIDE_OBSERVATION",
        "RESUME_QUEUE_DROPOUT",
        "REPORT_INDEX_DROPOUT",
        "CITATION_REPAIR_RECOVERY",
        "LEGACY_RECOVERY",
    }
)
_SEVERITIES = ("Critical", "High", "Medium", "Low", "Informational", "Unknown")
_SEVERITY_RANK = {name: index for index, name in enumerate(_SEVERITIES)}
_QUALITY = frozenset({"EXACT", "PARTIAL", "UNRESOLVED"})
_SCOPE_STATES = frozenset({"IN_SCOPE", "UNRESOLVED", "OUT_OF_SCOPE_CLAIMED"})
_DECISION_KINDS = frozenset(
    {
        "CONFIRMED",
        "CONTESTED",
        "REFUTED",
        "AUTHORIZED_ALIAS",
        "AUTHORIZED_SCOPE_EXCLUSION",
        "AUTHORIZED_DEFERRED",
        "AUTHORIZED_ZERO_HARM",
    }
)
_EVIDENCE_BASES = frozenset(
    {
        "INDEPENDENT_EXECUTION",
        "FORMAL_PROOF",
        "INDEPENDENT_ANALYSIS",
        "TYPED_EQUIVALENCE",
        "EXACT_SCOPE_PREDICATE",
        "CENTRAL_REPLAYED_AUTHORITY",
    }
)
_PROOF_SCOPES = frozenset(
    {"FULL_CLAIM", "PARTIAL_CLAIM", "MECHANISM_ONLY", "SCOPE_ONLY"}
)
_RETENTION_TARGETS = frozenset({"BODY", "HUMAN_REVIEW"})
_PROJECTION_KINDS = frozenset(
    {"BODY", "HUMAN_REVIEW", "APPENDIX", "EXCLUSION_INDEX", "ALIAS_INDEX"}
)
_DELIVERED_STATES = frozenset(
    {
        "DELIVERED_BODY",
        "DELIVERED_HUMAN_REVIEW",
        "DELIVERED_APPENDIX",
        "CONSOLIDATED_DELIVERED",
    }
)
_NEGATIVE_CLOSURE_REJECTION_REASONS = frozenset(
    {
        "REFUTATION_REQUIRES_TYPED_EXHAUSTIVE_NEGATIVE_AUTHORITY",
        "SCOPE_EXCLUSION_REQUIRES_TYPED_MECHANICAL_AUTHORITY",
        "ZERO_HARM_REQUIRES_TYPED_EXHAUSTIVE_NEGATIVE_AUTHORITY",
    }
)


class FindingLifecycleError(ValueError):
    """Lifecycle authority cannot be parsed, replayed, or advanced safely."""


def _canonical_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise FindingLifecycleError(f"record is not canonical JSON: {exc}") from exc


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _exact_record(
    value: Mapping[str, Any], fields: Sequence[str], *, label: str
) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise FindingLifecycleError(f"{label} must be an object")
    if set(value) != set(fields):
        missing = sorted(set(fields) - set(value))
        extra = sorted(set(value) - set(fields))
        raise FindingLifecycleError(
            f"{label} schema mismatch; missing={missing}; extra={extra}"
        )
    return {field: value[field] for field in fields}


def _text(value: Any, *, field: str, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or value != value.strip():
        raise FindingLifecycleError(f"{field} must be a canonical string")
    if not allow_empty and not value:
        raise FindingLifecycleError(f"{field} must be non-empty")
    if any(
        ord(char) < 32
        or ord(char) == 127
        or char in {"\u2028", "\u2029"}
        for char in value
    ):
        raise FindingLifecycleError(f"{field} contains control characters")
    return value


def _optional_text(value: Any, *, field: str) -> str | None:
    if value is None:
        return None
    return _text(value, field=field)


def _sha256(value: Any, *, field: str) -> str:
    item = _text(value, field=field)
    if len(item) != 64 or any(char not in _HEX64 for char in item):
        raise FindingLifecycleError(f"{field} must be a lowercase SHA-256 digest")
    return item


def _optional_sha256(value: Any, *, field: str) -> str | None:
    if value is None:
        return None
    return _sha256(value, field=field)


def _enum(value: Any, allowed: Iterable[str], *, field: str) -> str:
    item = _text(value, field=field)
    if item not in allowed:
        raise FindingLifecycleError(f"{field} enum is invalid: {item!r}")
    return item


def _text_list(value: Any, *, field: str) -> list[str]:
    if not isinstance(value, list):
        raise FindingLifecycleError(f"{field} must be an array")
    items = [_text(item, field=f"{field} item") for item in value]
    if not items:
        raise FindingLifecycleError(f"{field} must not be empty")
    if len({item.casefold() for item in items}) != len(items):
        raise FindingLifecycleError(f"{field} must not contain duplicates")
    return sorted(items, key=lambda item: (item.casefold(), item))


def candidate_content_sha256(value: Mapping[str, Any]) -> str:
    """Derive the stable claim digest; display aliases remain explicit lineage."""

    semantic = {
        "candidate_id": _text(value.get("candidate_id"), field="candidate_id"),
        "lineage_ids": _text_list(value.get("lineage_ids"), field="lineage_ids"),
        "source_record_sha256": _sha256(
            value.get("source_record_sha256"), field="source_record_sha256"
        ),
        "upstream_severity": _enum(
            value.get("upstream_severity"), _SEVERITIES, field="upstream_severity"
        ),
        "title": _text(value.get("title"), field="title"),
        "location": _text(value.get("location"), field="location", allow_empty=True),
        "evidence_pointer": _text(
            value.get("evidence_pointer"), field="evidence_pointer", allow_empty=True
        ),
    }
    if not semantic["location"] and not semantic["evidence_pointer"]:
        raise FindingLifecycleError(
            "content-bearing candidate requires a location or evidence pointer"
        )
    return _digest(semantic)


def _normalize_candidate(value: Mapping[str, Any], *, run_id: str) -> dict[str, Any]:
    row = _exact_record(value, _CANDIDATE_FIELDS, label="candidate")
    if row["schema_version"] != CANDIDATE_SCHEMA:
        raise FindingLifecycleError("candidate schema_version mismatch")
    row["run_id"] = _text(row["run_id"], field="candidate run_id")
    if row["run_id"] != run_id:
        raise FindingLifecycleError("candidate run_id does not match lifecycle run_id")
    for field in (
        "candidate_id",
        "source_artifact",
        "producer_identity",
        "producer_invocation_id",
        "producer_phase",
        "origin_assessment",
        "title",
    ):
        row[field] = _text(row[field], field=field)
    row["lineage_ids"] = _text_list(row["lineage_ids"], field="lineage_ids")
    if row["candidate_id"].casefold() not in {
        item.casefold() for item in row["lineage_ids"]
    }:
        raise FindingLifecycleError("lineage_ids must include candidate_id")
    for field in ("source_artifact_sha256", "source_record_sha256"):
        row[field] = _sha256(row[field], field=field)
    row["entry_reason"] = _enum(
        row["entry_reason"], _ENTRY_REASONS, field="entry_reason"
    )
    row["upstream_severity"] = _enum(
        row["upstream_severity"], _SEVERITIES, field="upstream_severity"
    )
    row["location"] = _text(
        row["location"], field="location", allow_empty=True
    )
    row["evidence_pointer"] = _text(
        row["evidence_pointer"], field="evidence_pointer", allow_empty=True
    )
    row["location_quality"] = _enum(
        row["location_quality"], _QUALITY, field="location_quality"
    )
    row["source_provenance_quality"] = _enum(
        row["source_provenance_quality"],
        _QUALITY,
        field="source_provenance_quality",
    )
    row["scope_state"] = _enum(
        row["scope_state"], _SCOPE_STATES, field="scope_state"
    )
    expected = candidate_content_sha256(row)
    supplied = _sha256(
        row["candidate_content_sha256"], field="candidate_content_sha256"
    )
    if supplied != expected:
        raise FindingLifecycleError(
            "candidate_content_sha256 does not match canonical candidate content"
        )
    row["candidate_content_sha256"] = supplied
    return row


def _normalize_decision(value: Mapping[str, Any], *, run_id: str) -> dict[str, Any]:
    row = _exact_record(value, _DECISION_FIELDS, label="decision")
    if row["schema_version"] != DECISION_SCHEMA:
        raise FindingLifecycleError("decision schema_version mismatch")
    row["run_id"] = _text(row["run_id"], field="decision run_id")
    if row["run_id"] != run_id:
        raise FindingLifecycleError("decision run_id does not match lifecycle run_id")
    for field in (
        "decision_id",
        "candidate_id",
        "discriminator_identity",
        "discriminator_invocation_id",
        "discriminator_phase",
        "reason_class",
    ):
        row[field] = _text(row[field], field=field)
    row["candidate_content_sha256"] = _sha256(
        row["candidate_content_sha256"], field="candidate_content_sha256"
    )
    row["decision_kind"] = _enum(
        row["decision_kind"], _DECISION_KINDS, field="decision_kind"
    )
    row["evidence_basis"] = _enum(
        row["evidence_basis"], _EVIDENCE_BASES, field="evidence_basis"
    )
    row["evidence_sha256"] = _sha256(
        row["evidence_sha256"], field="evidence_sha256"
    )
    row["proof_scope"] = _enum(
        row["proof_scope"], _PROOF_SCOPES, field="proof_scope"
    )
    row["alias_target_candidate_id"] = _optional_text(
        row["alias_target_candidate_id"], field="alias_target_candidate_id"
    )
    row["next_action"] = _optional_text(row["next_action"], field="next_action")
    if row["public_retention_target"] is not None:
        row["public_retention_target"] = _enum(
            row["public_retention_target"],
            _RETENTION_TARGETS,
            field="public_retention_target",
        )
    row["scope_snapshot_sha256"] = _optional_sha256(
        row["scope_snapshot_sha256"], field="scope_snapshot_sha256"
    )
    return row


def _normalize_closure_decision(value: Mapping[str, Any]) -> dict[str, Any]:
    row = _exact_record(value, _CENTRAL_CLOSURE_FIELDS, label="closure decision")
    if row["schema_version"] != "plamen.central_negative_closure_decision.v1":
        raise FindingLifecycleError("closure decision schema mismatch")
    if row["status"] != "AUTHORIZED" or row["reopen_required"] is not False:
        raise FindingLifecycleError("closure decision is not authorized")
    if row["debt_reasons"] != []:
        raise FindingLifecycleError("authorized closure decision carries debt")
    for field in (
        "candidate_content_sha256", "subject_digest",
        "evidence_manifest_digest", "provider_completion_sha256",
        "provider_publish_sha256", "bundle_digest", "resolution_digest",
    ):
        row[field] = _sha256(row[field], field=field)
    if row["survivor_identity_sha256"] is not None:
        row["survivor_identity_sha256"] = _sha256(
            row["survivor_identity_sha256"], field="survivor_identity_sha256"
        )
    unsigned = dict(row)
    supplied = unsigned.pop("resolution_digest")
    if supplied != _digest(unsigned):
        raise FindingLifecycleError("closure decision digest mismatch")
    row["resolution_digest"] = supplied
    return row


def _normalize_projection(value: Mapping[str, Any], *, run_id: str) -> dict[str, Any]:
    row = _exact_record(value, _PROJECTION_FIELDS, label="projection")
    if row["schema_version"] != PROJECTION_SCHEMA:
        raise FindingLifecycleError("projection schema_version mismatch")
    row["run_id"] = _text(row["run_id"], field="projection run_id")
    if row["run_id"] != run_id:
        raise FindingLifecycleError("projection run_id does not match lifecycle run_id")
    for field in (
        "projection_id",
        "candidate_id",
        "artifact_path",
        "public_reference",
        "projector_identity",
        "projector_invocation_id",
    ):
        row[field] = _text(row[field], field=field)
    row["candidate_content_sha256"] = _sha256(
        row["candidate_content_sha256"], field="candidate_content_sha256"
    )
    row["projection_kind"] = _enum(
        row["projection_kind"], _PROJECTION_KINDS, field="projection_kind"
    )
    row["artifact_sha256"] = _sha256(
        row["artifact_sha256"], field="artifact_sha256"
    )
    return row


def _record_union(
    existing: Sequence[Mapping[str, Any]], additions: Sequence[Mapping[str, Any]]
) -> list[dict[str, Any]]:
    by_digest: dict[str, dict[str, Any]] = {}
    for record in [*existing, *additions]:
        normalized = dict(record)
        by_digest[_digest(normalized)] = normalized
    return [by_digest[key] for key in sorted(by_digest)]


def _current_replayed_closure_decisions(
    decisions: Sequence[Mapping[str, Any]],
    embedded: Sequence[Mapping[str, Any]],
    *,
    closure_authority: Any,
) -> list[dict[str, Any]]:
    """Return only embedded decisions reproduced by the current central replay.

    A digest-valid row in ``source_records`` is an audit fact, not a capability.
    The root-bound central resolver rereads its provider denominator on every
    call.  Without that resolver (or after any source drift), terminal negative
    decisions are deliberately absent from the derivation and therefore reopen.
    """

    if closure_authority is None:
        return []
    # Lazy import keeps this generic lifecycle substrate independent of broker
    # construction while still requiring the broker's exact-type resolver.
    from closure_broker_v2 import resolve_central_negative_closure

    effects = {
        "REFUTED": "REFUTED_FULL",
        "AUTHORIZED_SCOPE_EXCLUSION": "OUT_OF_SCOPE",
        "AUTHORIZED_ALIAS": "ALIAS_TO_SURVIVOR",
        "AUTHORIZED_ZERO_HARM": "ZERO_HARM",
    }
    embedded_by_digest = {
        str(row.get("resolution_digest") or ""): dict(row) for row in embedded
    }
    replayed: list[dict[str, Any]] = []
    for decision in decisions:
        effect = effects.get(str(decision.get("decision_kind") or ""))
        if effect is None:
            continue
        supplied = embedded_by_digest.get(str(decision.get("evidence_sha256") or ""))
        if supplied is None:
            continue
        try:
            current = resolve_central_negative_closure(
                closure_authority,
                work_item={
                    "candidate_id": decision["candidate_id"],
                    "work_item_id": decision["candidate_id"],
                    "candidate_content_sha256": decision[
                        "candidate_content_sha256"
                    ],
                },
                requested_effect=effect,
            )
            normalized = _normalize_closure_decision(current)
        except Exception:
            continue
        if normalized == supplied:
            replayed.append(normalized)
    return _record_union([], replayed)


def _rejection(row: Mapping[str, Any], reason: str) -> dict[str, str]:
    return {
        "decision_id": str(row["decision_id"]),
        "candidate_id": str(row["candidate_id"]),
        "decision_record_sha256": _digest(row),
        "reason": reason,
    }


def _decision_authorization_reason(
    decision: Mapping[str, Any],
    *,
    candidates: Sequence[Mapping[str, Any]],
    known_candidate_ids: set[str],
    closure_decisions: Mapping[str, Mapping[str, Any]],
) -> str | None:
    producer_identities = {
        str(row["producer_identity"]).casefold() for row in candidates
    }
    producer_invocations = {
        str(row["producer_invocation_id"]).casefold() for row in candidates
    }
    if (
        str(decision["discriminator_identity"]).casefold() in producer_identities
        or str(decision["discriminator_invocation_id"]).casefold()
        in producer_invocations
    ):
        return "DISCRIMINATOR_NOT_INDEPENDENT"
    if decision["candidate_content_sha256"] not in {
        row["candidate_content_sha256"] for row in candidates
    }:
        return "CANDIDATE_CONTENT_MISMATCH"
    kind = str(decision["decision_kind"])
    basis = str(decision["evidence_basis"])
    scope = str(decision["proof_scope"])
    terminal_effects = {
        "REFUTED": "REFUTED_FULL",
        "AUTHORIZED_SCOPE_EXCLUSION": "OUT_OF_SCOPE",
        "AUTHORIZED_ALIAS": "ALIAS_TO_SURVIVOR",
        "AUTHORIZED_ZERO_HARM": "ZERO_HARM",
    }
    if kind in terminal_effects:
        effect = terminal_effects[kind]
        closure = closure_decisions.get(str(decision["evidence_sha256"]))
        if not isinstance(closure, Mapping):
            supporting_negative_resolution(
                requested_effect=effect, evidence_basis=basis
            )
            return {
                "REFUTED": "REFUTATION_REQUIRES_TYPED_EXHAUSTIVE_NEGATIVE_AUTHORITY",
                "AUTHORIZED_SCOPE_EXCLUSION": "SCOPE_EXCLUSION_REQUIRES_TYPED_MECHANICAL_AUTHORITY",
                "AUTHORIZED_ALIAS": "ALIAS_REQUIRES_APPLIED_LOSSLESS_EQUIVALENCE_AUTHORITY",
                "AUTHORIZED_ZERO_HARM": "ZERO_HARM_REQUIRES_TYPED_EXHAUSTIVE_NEGATIVE_AUTHORITY",
            }[kind]
        if (
            closure.get("requested_effect") != effect
            or closure.get("outcome") != effect
            or closure.get("candidate_id") != decision["candidate_id"]
            or closure.get("candidate_content_sha256")
            != decision["candidate_content_sha256"]
            or closure.get("subject_digest")
            != decision["scope_snapshot_sha256"]
            or closure.get("provider_id")
            != decision["discriminator_identity"]
            or closure.get("provider_completion_sha256")
            != decision["discriminator_invocation_id"]
            or basis != "CENTRAL_REPLAYED_AUTHORITY"
            or (kind == "REFUTED" and scope != "FULL_CLAIM")
            or (kind == "AUTHORIZED_ZERO_HARM" and scope != "FULL_CLAIM")
            or (kind == "AUTHORIZED_SCOPE_EXCLUSION" and scope != "SCOPE_ONLY")
            or (
                kind == "AUTHORIZED_ALIAS"
                and closure.get("survivor_id")
                != decision["alias_target_candidate_id"]
            )
        ):
            return "CENTRAL_NEGATIVE_CLOSURE_BINDING_MISMATCH"
    if kind == "AUTHORIZED_DEFERRED" and (
        not decision["next_action"]
        or decision["public_retention_target"] not in _RETENTION_TARGETS
    ):
        return "DEFERRED_LACKS_NEXT_ACTION_OR_PUBLIC_RETENTION"
    if kind in {"CONFIRMED", "CONTESTED"} and basis not in {
        "INDEPENDENT_EXECUTION",
        "FORMAL_PROOF",
        "INDEPENDENT_ANALYSIS",
    }:
        return "POSITIVE_DECISION_LACKS_INDEPENDENT_EVIDENCE"
    return None


def _fallback_target(candidates: Sequence[Mapping[str, Any]]) -> str:
    reasons = {str(row["entry_reason"]) for row in candidates}
    if reasons & {"RESUME_QUEUE_DROPOUT", "REPORT_INDEX_DROPOUT"}:
        return "BODY"
    severity = min(
        (str(row["upstream_severity"]) for row in candidates),
        key=lambda value: _SEVERITY_RANK[value],
    )
    return "BODY" if severity in {"Critical", "High", "Medium"} else "HUMAN_REVIEW"


def _obligation(
    *,
    run_id: str,
    candidate_id: str,
    content_sha256: str,
    kind: str,
    reason: str,
    retention_target: str,
    source_record_sha256s: Sequence[str],
) -> dict[str, Any]:
    identity = {
        "run_id": run_id,
        "candidate_id": candidate_id,
        "candidate_content_sha256": content_sha256,
        "obligation_kind": kind,
    }
    return {
        "schema_version": OBLIGATION_SCHEMA,
        "run_id": run_id,
        "obligation_id": f"FLO-{_digest(identity)[:24]}",
        "candidate_id": candidate_id,
        "candidate_content_sha256": content_sha256,
        "obligation_kind": kind,
        "required_actor_kind": {
            "LOCATION_REPAIR": "DETERMINISTIC_REPAIR_OR_INDEPENDENT_REVIEWER",
            "REPORT_PROJECTION": "REPORT_PROJECTOR",
            "REPORT_INDEX_ADJUDICATION": "INDEPENDENT_INDEX_DISCRIMINATOR",
            "ALIAS_TARGET_DELIVERY": "REPORT_PROJECTOR",
        }.get(kind, "INDEPENDENT_DISCRIMINATOR"),
        "reason": reason,
        "retention_target": retention_target,
        "source_record_sha256s": sorted(set(source_record_sha256s)),
    }


def _derive(
    *,
    run_id: str,
    candidates: Sequence[dict[str, Any]],
    decisions: Sequence[dict[str, Any]],
    projections: Sequence[dict[str, Any]],
    closure_decisions: Sequence[dict[str, Any]],
) -> tuple[
    list[dict[str, Any]],
    list[dict[str, Any]],
    list[dict[str, str]],
    list[str],
]:
    closure_by_digest = {
        str(row["resolution_digest"]): row for row in closure_decisions
    }
    candidate_groups: dict[str, list[dict[str, Any]]] = {}
    for row in candidates:
        candidate_groups.setdefault(row["candidate_id"], []).append(row)
    decision_groups: dict[str, list[dict[str, Any]]] = {}
    for row in decisions:
        decision_groups.setdefault(row["candidate_id"], []).append(row)
    projection_groups: dict[str, list[dict[str, Any]]] = {}
    for row in projections:
        projection_groups.setdefault(row["candidate_id"], []).append(row)

    rejected: list[dict[str, str]] = []
    debt: list[str] = []
    decision_identity_records: dict[str, set[str]] = {}
    for row in decisions:
        decision_identity_records.setdefault(str(row["decision_id"]), set()).add(
            _digest(row)
        )
    conflicting_decision_ids = {
        identity
        for identity, record_digests in decision_identity_records.items()
        if len(record_digests) > 1
    }
    projection_identity_records: dict[str, set[str]] = {}
    projection_reference_records: dict[str, set[tuple[str, str]]] = {}
    for row in projections:
        projection_identity_records.setdefault(str(row["projection_id"]), set()).add(
            _digest(row)
        )
        projection_reference_records.setdefault(
            str(row["public_reference"]).casefold(), set()
        ).add((str(row["candidate_id"]), _digest(row)))
    conflicting_projection_ids = {
        identity
        for identity, record_digests in projection_identity_records.items()
        if len(record_digests) > 1
    }
    conflicting_public_references = {
        reference
        for reference, records in projection_reference_records.items()
        if len(records) > 1
    }
    for identity in sorted(conflicting_projection_ids):
        debt.append(f"projection identity collision for {identity}")
    for reference in sorted(conflicting_public_references):
        debt.append(f"projection public-reference collision for {reference}")
    known_ids = set(candidate_groups)
    for candidate_id in sorted(set(decision_groups) - known_ids):
        for decision in decision_groups[candidate_id]:
            rejected.append(_rejection(decision, "CANDIDATE_NOT_FOUND"))
            debt.append(f"decision {decision['decision_id']} has no candidate authority")
    for candidate_id in sorted(set(projection_groups) - known_ids):
        debt.append(f"projection exists for unknown candidate {candidate_id}")

    states: list[dict[str, Any]] = []
    obligations: list[dict[str, Any]] = []
    accepted_by_candidate: dict[str, list[dict[str, Any]]] = {}
    for candidate_id in sorted(candidate_groups, key=lambda item: (item.casefold(), item)):
        group = sorted(candidate_groups[candidate_id], key=_digest)
        content_hashes = sorted({row["candidate_content_sha256"] for row in group})
        identity_conflict = len(content_hashes) != 1
        representative = group[0]
        source_hashes = sorted({row["source_record_sha256"] for row in group})
        target = _fallback_target(group)
        accepted: list[dict[str, Any]] = []
        local_rejected: list[dict[str, str]] = []
        for decision in sorted(decision_groups.get(candidate_id, []), key=_digest):
            if decision["decision_id"] in conflicting_decision_ids:
                reason = "DECISION_ID_CONFLICT"
            elif identity_conflict:
                reason = "IDENTITY_CONFLICT_PRECLUDES_DISPOSITION"
            else:
                reason = _decision_authorization_reason(
                    decision,
                    candidates=group,
                    known_candidate_ids=known_ids,
                    closure_decisions=closure_by_digest,
                )
            if reason is not None:
                item = _rejection(decision, reason)
                rejected.append(item)
                local_rejected.append(item)
            else:
                accepted.append(decision)

        deferred = [
            row for row in accepted
            if row["decision_kind"] == "AUTHORIZED_DEFERRED"
        ]
        dispositions = [
            row for row in accepted
            if row["decision_kind"] != "AUTHORIZED_DEFERRED"
        ]
        semantic_keys = {
            (
                row["decision_kind"],
                row["alias_target_candidate_id"],
                row["public_retention_target"],
            )
            for row in dispositions
        }
        decision_conflict = len(semantic_keys) > 1 or any(
            row["reason"] == "DECISION_ID_CONFLICT" for row in local_rejected
        )
        if decision_conflict:
            debt.append(f"{candidate_id} has conflicting independent dispositions")
        accepted_by_candidate[candidate_id] = dispositions

        matching_projections = [
            row
            for row in projection_groups.get(candidate_id, [])
            if row["candidate_content_sha256"] in content_hashes
            and row["projection_id"] not in conflicting_projection_ids
            and str(row["public_reference"]).casefold()
            not in conflicting_public_references
        ]
        stale_projection_count = len(projection_groups.get(candidate_id, [])) - len(
            matching_projections
        )
        if stale_projection_count:
            debt.append(
                f"{candidate_id} has {stale_projection_count} stale projection(s)"
            )
        projection_kinds = {row["projection_kind"] for row in matching_projections}
        if len(projection_kinds & {"BODY", "HUMAN_REVIEW"}) > 1:
            debt.append(f"{candidate_id} has conflicting public projections")

        if identity_conflict:
            claim_state = "IDENTITY_CONFLICT"
            decision = None
        elif decision_conflict:
            claim_state = "DISPOSITION_CONFLICT"
            decision = None
        elif dispositions:
            decision = dispositions[0]
            claim_state = {
                "AUTHORIZED_SCOPE_EXCLUSION": "OUT_OF_SCOPE",
                "AUTHORIZED_ALIAS": "AUTHORIZED_ALIAS",
                "AUTHORIZED_ZERO_HARM": "ZERO_SECURITY_CONSEQUENCE",
            }.get(str(decision["decision_kind"]), str(decision["decision_kind"]))
        elif deferred:
            decision = deferred[0]
            claim_state = {
                "AUTHORIZED_DEFERRED": "DEFERRED_VISIBLE",
            }.get(str(decision["decision_kind"]), str(decision["decision_kind"]))
        else:
            decision = None
            claim_state = (
                "UNRESOLVED_PIPELINE_DROPOUT"
                if "REPORT_INDEX_DROPOUT"
                in {row["entry_reason"] for row in group}
                else "UNVERIFIED"
            )

        if decision is not None and decision["decision_kind"] in {
            "REFUTED",
            "AUTHORIZED_SCOPE_EXCLUSION",
        }:
            target = "EXCLUDED"
        elif decision is not None and decision["decision_kind"] == "AUTHORIZED_ALIAS":
            target = "ALIAS_TARGET"
        elif decision is not None and decision["decision_kind"] == "AUTHORIZED_DEFERRED":
            target = str(decision["public_retention_target"])
        elif decision is not None and decision["decision_kind"] == "AUTHORIZED_ZERO_HARM":
            target = "APPENDIX"
        elif decision is not None and decision["decision_kind"] in {
            "CONFIRMED",
            "CONTESTED",
        }:
            target = "BODY"

        if target == "EXCLUDED":
            delivery_state = "AUTHORIZED_EXCLUDED"
            delivered = True
            terminal = True
        elif target == "ALIAS_TARGET":
            delivery_state = "CONSOLIDATED_TARGET_PENDING"
            delivered = False
            terminal = False
        elif target == "BODY" and "BODY" in projection_kinds:
            delivery_state = "DELIVERED_BODY"
            delivered = True
            terminal = (
                decision is not None
                and decision["decision_kind"] != "AUTHORIZED_DEFERRED"
                and not decision_conflict
            )
        elif target == "HUMAN_REVIEW" and "HUMAN_REVIEW" in projection_kinds:
            delivery_state = "DELIVERED_HUMAN_REVIEW"
            delivered = True
            terminal = (
                decision is not None
                and decision["decision_kind"] != "AUTHORIZED_DEFERRED"
                and not decision_conflict
            )
        elif target == "APPENDIX" and "APPENDIX" in projection_kinds:
            delivery_state = "DELIVERED_APPENDIX"
            delivered = True
            terminal = decision is not None and not decision_conflict
        else:
            delivery_state = f"PENDING_{target}"
            delivered = False
            terminal = False

        content_for_obligation = content_hashes[0]
        reasons = {row["entry_reason"] for row in group}
        quality_debt = any(
            row["location_quality"] != "EXACT"
            or row["source_provenance_quality"] != "EXACT"
            for row in group
        )
        if identity_conflict:
            obligations.append(
                _obligation(
                    run_id=run_id,
                    candidate_id=candidate_id,
                    content_sha256=content_for_obligation,
                    kind="IDENTITY_CONFLICT_REVIEW",
                    reason="one stable identity carries conflicting content digests",
                    retention_target="BODY",
                    source_record_sha256s=source_hashes,
                )
            )
            obligations.append(
                _obligation(
                    run_id=run_id,
                    candidate_id=candidate_id,
                    content_sha256=content_for_obligation,
                    kind="RECOVERY_INDEPENDENT_VERIFICATION",
                    reason="conflicting candidate variants cannot inherit a disposition",
                    retention_target="BODY",
                    source_record_sha256s=source_hashes,
                )
            )
        elif decision_conflict:
            obligations.append(
                _obligation(
                    run_id=run_id,
                    candidate_id=candidate_id,
                    content_sha256=content_for_obligation,
                    kind="DISPOSITION_CONFLICT_REVIEW",
                    reason="independent decisions disagree on terminal claim state",
                    retention_target="BODY",
                    source_record_sha256s=source_hashes,
                )
            )
            obligations.append(
                _obligation(
                    run_id=run_id,
                    candidate_id=candidate_id,
                    content_sha256=content_for_obligation,
                    kind="RECOVERY_INDEPENDENT_VERIFICATION",
                    reason="decision conflict requires a fresh bounded discriminator",
                    retention_target="BODY",
                    source_record_sha256s=source_hashes,
                )
            )
        elif decision is None:
            rejected_terminal_negative = any(
                row["reason"] in _NEGATIVE_CLOSURE_REJECTION_REASONS
                for row in local_rejected
            )
            if "POST_VERIFY_SIDE_OBSERVATION" in reasons:
                verify_kind = "LATE_INDEPENDENT_VERIFICATION"
            elif reasons & {"RESUME_QUEUE_DROPOUT", "REPORT_INDEX_DROPOUT"}:
                verify_kind = "RECOVERY_INDEPENDENT_VERIFICATION"
            else:
                verify_kind = "INDEPENDENT_VERIFICATION"
            obligations.append(
                _obligation(
                    run_id=run_id,
                    candidate_id=candidate_id,
                    content_sha256=content_for_obligation,
                    kind=verify_kind,
                    reason="candidate lacks an exact independent disposition",
                    retention_target=target,
                    source_record_sha256s=source_hashes,
                )
            )
            if rejected_terminal_negative:
                # Preserve the generic lifecycle obligation for compatibility
                # with existing verification consumers, and add the stronger
                # typed recovery obligation that NC-2/NC-5 can join exactly.
                obligations.append(
                    _obligation(
                        run_id=run_id,
                        candidate_id=candidate_id,
                        content_sha256=content_for_obligation,
                        kind="RECOVERY_INDEPENDENT_VERIFICATION",
                        reason=(
                            "terminal negative proposal lacked replayable typed "
                            "provider authority and must be independently re-verified"
                        ),
                        retention_target="BODY",
                        source_record_sha256s=source_hashes,
                    )
                )
        elif decision["decision_kind"] == "AUTHORIZED_DEFERRED":
            deferred_negative_reopen = str(decision["reason_class"]) in {
                "NEGATIVE_PROPOSAL_REQUIRES_TYPED_AUTHORITY",
                "ZERO_HARM_PROPOSAL_REQUIRES_TYPED_AUTHORITY",
            }
            obligations.append(
                _obligation(
                    run_id=run_id,
                    candidate_id=candidate_id,
                    content_sha256=content_for_obligation,
                    kind=(
                        "RECOVERY_INDEPENDENT_VERIFICATION"
                        if deferred_negative_reopen
                        else "INDEPENDENT_VERIFICATION"
                    ),
                    reason=(
                        "supporting-only negative proposal requires exact independent "
                        "re-verification"
                        if deferred_negative_reopen
                        else "deferred routing is visible but does not satisfy verification"
                    ),
                    retention_target=target,
                    source_record_sha256s=source_hashes,
                )
            )
            if not delivered:
                obligations.append(
                    _obligation(
                        run_id=run_id,
                        candidate_id=candidate_id,
                        content_sha256=content_for_obligation,
                        kind="REPORT_PROJECTION",
                        reason="visible deferred routing lacks delivered projection",
                        retention_target=target,
                        source_record_sha256s=source_hashes,
                    )
                )
        elif target in {*_RETENTION_TARGETS, "APPENDIX"} and not delivered:
            obligations.append(
                _obligation(
                    run_id=run_id,
                    candidate_id=candidate_id,
                    content_sha256=content_for_obligation,
                    kind="REPORT_PROJECTION",
                    reason="authorized retained disposition lacks delivered projection",
                    retention_target=target,
                    source_record_sha256s=source_hashes,
                )
            )
        if quality_debt and target != "EXCLUDED":
            obligations.append(
                _obligation(
                    run_id=run_id,
                    candidate_id=candidate_id,
                    content_sha256=content_for_obligation,
                    kind="LOCATION_REPAIR",
                    reason="citation quality is repair debt, not claim validity",
                    retention_target="BODY" if target == "ALIAS_TARGET" else target,
                    source_record_sha256s=source_hashes,
                )
            )
        if "REPORT_INDEX_DROPOUT" in reasons and not matching_projections:
            obligations.append(
                _obligation(
                    run_id=run_id,
                    candidate_id=candidate_id,
                    content_sha256=content_for_obligation,
                    kind="REPORT_INDEX_ADJUDICATION",
                    reason="identity accounting cannot substitute for index disposition/delivery",
                    retention_target=("BODY" if target in {"EXCLUDED", "ALIAS_TARGET"} else target),
                    source_record_sha256s=source_hashes,
                )
            )
            terminal = False

        severity = min(
            (str(row["upstream_severity"]) for row in group),
            key=lambda value: _SEVERITY_RANK[value],
        )
        states.append(
            {
                "candidate_id": candidate_id,
                "candidate_content_sha256s": content_hashes,
                "candidate_record_sha256s": sorted(_digest(row) for row in group),
                "source_record_sha256s": source_hashes,
                "lineage_ids": sorted(
                    {item for row in group for item in row["lineage_ids"]},
                    key=lambda item: (item.casefold(), item),
                ),
                "producer_identities": [
                    list(item)
                    for item in sorted(
                        {
                            (
                                row["producer_identity"],
                                row["producer_invocation_id"],
                                row["producer_phase"],
                            )
                            for row in group
                        }
                    )
                ],
                "entry_reasons": sorted(reasons),
                "origin_assessments": sorted(
                    {str(row["origin_assessment"]) for row in group}
                ),
                "upstream_severity": severity,
                "title": representative["title"],
                "location": representative["location"],
                "evidence_pointer": representative["evidence_pointer"],
                "content_bearing": True,
                "location_quality": sorted(
                    {str(row["location_quality"]) for row in group}
                ),
                "source_provenance_quality": sorted(
                    {str(row["source_provenance_quality"]) for row in group}
                ),
                "scope_states": sorted({str(row["scope_state"]) for row in group}),
                "identity_state": "CONFLICT" if identity_conflict else "UNIQUE",
                "claim_state": claim_state,
                "decision_ids": sorted(str(row["decision_id"]) for row in accepted),
                "accepted_decision_sha256s": sorted(_digest(row) for row in accepted),
                "rejected_decision_ids": sorted(
                    row["decision_id"] for row in local_rejected
                ),
                "independent_disposition": bool(dispositions) and not decision_conflict,
                "retention_target": target,
                "delivery_state": delivery_state,
                "projection_ids": sorted(
                    str(row["projection_id"]) for row in matching_projections
                ),
                "identity_accounted": True,
                "disposition_authorized": bool(dispositions) and not decision_conflict,
                "delivered_projection": delivered,
                "terminal_complete": terminal,
                "visible_debt": not terminal,
            }
        )

    # Alias delivery is inherited only from the exact applied target.  Cycles
    # and unresolved targets stay visible; they never become consolidation.
    by_id = {row["candidate_id"]: row for row in states}
    for row in states:
        accepted = accepted_by_candidate[row["candidate_id"]]
        if row["claim_state"] != "AUTHORIZED_ALIAS" or len(accepted) != 1:
            continue
        target_id = accepted[0]["alias_target_candidate_id"]
        target_row = by_id.get(target_id)
        if (
            target_row is not None
            and target_row["delivery_state"] in _DELIVERED_STATES
            and target_row["terminal_complete"]
        ):
            row["delivery_state"] = "CONSOLIDATED_DELIVERED"
            row["delivered_projection"] = True
            row["terminal_complete"] = True
            row["visible_debt"] = False
        else:
            obligations.append(
                _obligation(
                    run_id=run_id,
                    candidate_id=row["candidate_id"],
                    content_sha256=row["candidate_content_sha256s"][0],
                    kind="ALIAS_TARGET_DELIVERY",
                    reason=f"alias target {target_id} is not terminally delivered",
                    retention_target="BODY",
                    source_record_sha256s=row["source_record_sha256s"],
                )
            )

    obligations = sorted(
        {row["obligation_id"]: row for row in obligations}.values(),
        key=lambda row: (row["candidate_id"].casefold(), row["obligation_kind"]),
    )
    rejected.sort(key=lambda row: (row["candidate_id"].casefold(), row["decision_id"]))
    return states, obligations, rejected, sorted(set(debt))


def _build_from_normalized(
    *,
    run_id: str,
    candidates: Sequence[dict[str, Any]],
    decisions: Sequence[dict[str, Any]],
    projections: Sequence[dict[str, Any]],
    closure_decisions: Sequence[dict[str, Any]],
    authority_identity: str,
    authority_invocation_id: str,
    generation: int,
    previous_receipt_sha256: str | None,
    closure_authority: Any = None,
) -> dict[str, Any]:
    replayed_closure_decisions = _current_replayed_closure_decisions(
        decisions,
        closure_decisions,
        closure_authority=closure_authority,
    )
    states, obligations, rejected, debt = _derive(
        run_id=run_id,
        candidates=candidates,
        decisions=decisions,
        projections=projections,
        closure_decisions=replayed_closure_decisions,
    )
    source_records = {
        "candidates": list(candidates),
        "decisions": list(decisions),
        "projections": list(projections),
        "closure_decisions": list(closure_decisions),
    }
    payload: dict[str, Any] = {
        "schema_version": LEDGER_SCHEMA,
        "run_id": run_id,
        "generation": generation,
        "previous_receipt_sha256": previous_receipt_sha256,
        "authority_identity": authority_identity,
        "authority_invocation_id": authority_invocation_id,
        "source_records": source_records,
        "source_records_sha256": _digest(source_records),
        "candidate_states": states,
        "obligations": obligations,
        "rejected_decisions": rejected,
        "debt": debt,
        "summary": {
            "candidate_count": len(states),
            "terminal_count": sum(bool(row["terminal_complete"]) for row in states),
            "visible_debt_count": sum(bool(row["visible_debt"]) for row in states),
            "obligation_count": len(obligations),
            "rejected_decision_count": len(rejected),
            "identity_conflict_count": sum(
                row["identity_state"] == "CONFLICT" for row in states
            ),
            "disposition_conflict_count": sum(
                row["claim_state"] == "DISPOSITION_CONFLICT" for row in states
            ),
        },
    }
    payload["ledger_sha256"] = _digest(payload)
    return payload


def build_finding_lifecycle(
    *,
    run_id: str,
    candidates: Sequence[Mapping[str, Any]],
    decisions: Sequence[Mapping[str, Any]],
    projections: Sequence[Mapping[str, Any]],
    closure_decisions: Sequence[Mapping[str, Any]] = (),
    authority_identity: str,
    authority_invocation_id: str,
    closure_authority: Any = None,
) -> dict[str, Any]:
    """Build generation one from exact source records."""

    run = _text(run_id, field="run_id")
    authority = _text(authority_identity, field="authority_identity")
    invocation = _text(authority_invocation_id, field="authority_invocation_id")
    normalized_candidates = sorted(
        (_normalize_candidate(row, run_id=run) for row in candidates), key=_digest
    )
    normalized_decisions = sorted(
        (_normalize_decision(row, run_id=run) for row in decisions), key=_digest
    )
    normalized_projections = sorted(
        (_normalize_projection(row, run_id=run) for row in projections), key=_digest
    )
    normalized_closure_decisions = sorted(
        (_normalize_closure_decision(row) for row in closure_decisions), key=_digest
    )
    # Replayed identical records are one append-only fact, not new work.
    normalized_candidates = _record_union([], normalized_candidates)
    normalized_decisions = _record_union([], normalized_decisions)
    normalized_projections = _record_union([], normalized_projections)
    normalized_closure_decisions = _record_union(
        [], normalized_closure_decisions
    )
    return _build_from_normalized(
        run_id=run,
        candidates=normalized_candidates,
        decisions=normalized_decisions,
        projections=normalized_projections,
        closure_decisions=normalized_closure_decisions,
        authority_identity=authority,
        authority_invocation_id=invocation,
        generation=1,
        previous_receipt_sha256=None,
        closure_authority=closure_authority,
    )


def advance_finding_lifecycle(
    prior: Mapping[str, Any],
    *,
    candidates: Sequence[Mapping[str, Any]],
    decisions: Sequence[Mapping[str, Any]],
    projections: Sequence[Mapping[str, Any]],
    closure_decisions: Sequence[Mapping[str, Any]] = (),
    authority_identity: str,
    authority_invocation_id: str,
    closure_authority: Any = None,
) -> dict[str, Any]:
    """Append resume facts while retaining every prior candidate and decision."""

    old = validate_finding_lifecycle(
        prior, closure_authority=closure_authority
    )
    run = old["run_id"]
    authority = _text(authority_identity, field="authority_identity")
    invocation = _text(authority_invocation_id, field="authority_invocation_id")
    if authority.casefold() != str(old["authority_identity"]).casefold():
        raise FindingLifecycleError(
            "authority_identity cannot change while advancing one lifecycle chain"
        )
    new_candidates = [
        _normalize_candidate(row, run_id=run) for row in candidates
    ]
    new_decisions = [_normalize_decision(row, run_id=run) for row in decisions]
    new_projections = [
        _normalize_projection(row, run_id=run) for row in projections
    ]
    new_closure_decisions = [
        _normalize_closure_decision(row) for row in closure_decisions
    ]
    merged_candidates = _record_union(
        old["source_records"]["candidates"], new_candidates
    )
    merged_decisions = _record_union(old["source_records"]["decisions"], new_decisions)
    merged_projections = _record_union(
        old["source_records"]["projections"], new_projections
    )
    merged_closure_decisions = _record_union(
        old["source_records"]["closure_decisions"], new_closure_decisions
    )
    merged_source = {
        "candidates": merged_candidates,
        "decisions": merged_decisions,
        "projections": merged_projections,
        "closure_decisions": merged_closure_decisions,
    }
    if _digest(merged_source) == old["source_records_sha256"]:
        return old
    return _build_from_normalized(
        run_id=run,
        candidates=merged_candidates,
        decisions=merged_decisions,
        projections=merged_projections,
        closure_decisions=merged_closure_decisions,
        authority_identity=authority,
        authority_invocation_id=invocation,
        generation=old["generation"] + 1,
        previous_receipt_sha256=old["ledger_sha256"],
        closure_authority=closure_authority,
    )


def validate_finding_lifecycle(
    value: Mapping[str, Any],
    *,
    closure_authority: Any = None,
) -> dict[str, Any]:
    """Replay every derived state; digest validity alone is not sufficient."""

    row = _exact_record(value, _LEDGER_FIELDS, label="finding lifecycle ledger")
    if row["schema_version"] != LEDGER_SCHEMA:
        raise FindingLifecycleError("finding lifecycle ledger schema mismatch")
    run = _text(row["run_id"], field="run_id")
    if isinstance(row["generation"], bool) or not isinstance(row["generation"], int):
        raise FindingLifecycleError("generation must be an integer")
    if row["generation"] < 1:
        raise FindingLifecycleError("generation must be positive")
    previous = _optional_sha256(
        row["previous_receipt_sha256"], field="previous_receipt_sha256"
    )
    if (row["generation"] == 1) != (previous is None):
        raise FindingLifecycleError("generation/previous receipt linkage is invalid")
    authority = _text(row["authority_identity"], field="authority_identity")
    invocation = _text(
        row["authority_invocation_id"], field="authority_invocation_id"
    )
    if not isinstance(row["source_records"], Mapping) or set(
        row["source_records"]
    ) != {"candidates", "decisions", "projections", "closure_decisions"}:
        raise FindingLifecycleError("source_records schema mismatch")
    source = row["source_records"]
    if any(not isinstance(source[name], list) for name in source):
        raise FindingLifecycleError("source_records values must be arrays")
    candidates = _record_union(
        [], [_normalize_candidate(item, run_id=run) for item in source["candidates"]]
    )
    decisions = _record_union(
        [], [_normalize_decision(item, run_id=run) for item in source["decisions"]]
    )
    projections = _record_union(
        [], [_normalize_projection(item, run_id=run) for item in source["projections"]]
    )
    closure_decisions = _record_union(
        [], [_normalize_closure_decision(item) for item in source["closure_decisions"]]
    )
    normalized_source = {
        "candidates": candidates,
        "decisions": decisions,
        "projections": projections,
        "closure_decisions": closure_decisions,
    }
    supplied_source_digest = _sha256(
        row["source_records_sha256"], field="source_records_sha256"
    )
    if supplied_source_digest != _digest(normalized_source):
        raise FindingLifecycleError("source_records_sha256 mismatch")
    supplied_ledger_digest = _sha256(row["ledger_sha256"], field="ledger_sha256")
    without_digest = {field: row[field] for field in _LEDGER_FIELDS if field != "ledger_sha256"}
    if supplied_ledger_digest != _digest(without_digest):
        raise FindingLifecycleError("finding lifecycle ledger digest mismatch")
    replay = _build_from_normalized(
        run_id=run,
        candidates=candidates,
        decisions=decisions,
        projections=projections,
        closure_decisions=closure_decisions,
        authority_identity=authority,
        authority_invocation_id=invocation,
        generation=row["generation"],
        previous_receipt_sha256=previous,
        closure_authority=closure_authority,
    )
    if replay != dict(row):
        raise FindingLifecycleError("finding lifecycle derivation does not recompute")
    return replay


def finding_verification_work_items(
    value: Mapping[str, Any],
    *,
    closure_authority: Any = None,
) -> list[dict[str, Any]]:
    """Project only exact unresolved verification obligations for a launcher."""

    ledger = validate_finding_lifecycle(
        value, closure_authority=closure_authority
    )
    states = {row["candidate_id"]: row for row in ledger["candidate_states"]}
    verify_kinds = {
        "INDEPENDENT_VERIFICATION",
        "LATE_INDEPENDENT_VERIFICATION",
        "RECOVERY_INDEPENDENT_VERIFICATION",
    }
    priority = {
        "INDEPENDENT_VERIFICATION": 0,
        "LATE_INDEPENDENT_VERIFICATION": 1,
        "RECOVERY_INDEPENDENT_VERIFICATION": 2,
    }
    # A compatibility obligation and its stronger recovery obligation describe
    # one launch, not two.  Prefer the strongest exact route per candidate so
    # the ledger remains backward-readable without duplicating verifier work.
    selected: dict[str, Mapping[str, Any]] = {}
    for obligation in ledger["obligations"]:
        kind = str(obligation["obligation_kind"])
        if kind not in verify_kinds:
            continue
        candidate_id = str(obligation["candidate_id"])
        previous = selected.get(candidate_id)
        if previous is None or priority[kind] > priority[
            str(previous["obligation_kind"])
        ]:
            selected[candidate_id] = obligation
    work: list[dict[str, Any]] = []
    for candidate_id in sorted(selected, key=lambda item: (item.casefold(), item)):
        obligation = selected[candidate_id]
        state = states[obligation["candidate_id"]]
        work.append(
            {
                "run_id": ledger["run_id"],
                "obligation_id": obligation["obligation_id"],
                "obligation_kind": obligation["obligation_kind"],
                "candidate_id": state["candidate_id"],
                "candidate_content_sha256s": list(
                    state["candidate_content_sha256s"]
                ),
                "source_record_sha256s": list(state["source_record_sha256s"]),
                "lineage_ids": list(state["lineage_ids"]),
                "upstream_severity": state["upstream_severity"],
                "title": state["title"],
                "location": state["location"],
                "evidence_pointer": state["evidence_pointer"],
                "retention_target": obligation["retention_target"],
            }
        )
    return work


def finding_retention_work_items(
    value: Mapping[str, Any],
    *,
    closure_authority: Any = None,
) -> list[dict[str, Any]]:
    """Project every unresolved BODY/HUMAN_REVIEW fallback without guessing."""

    ledger = validate_finding_lifecycle(
        value, closure_authority=closure_authority
    )
    rows: list[dict[str, Any]] = []
    for state in ledger["candidate_states"]:
        if state["delivery_state"] not in {
            "PENDING_BODY",
            "PENDING_HUMAN_REVIEW",
        }:
            continue
        rows.append(
            {
                "run_id": ledger["run_id"],
                "candidate_id": state["candidate_id"],
                "candidate_content_sha256s": list(
                    state["candidate_content_sha256s"]
                ),
                "source_record_sha256s": list(state["source_record_sha256s"]),
                "lineage_ids": list(state["lineage_ids"]),
                "claim_state": state["claim_state"],
                "upstream_severity": state["upstream_severity"],
                "title": state["title"],
                "location": state["location"],
                "evidence_pointer": state["evidence_pointer"],
                "retention_target": state["retention_target"],
                "decision_ids": list(state["decision_ids"]),
            }
        )
    return rows


def authorized_finding_exclusions(
    value: Mapping[str, Any],
    *,
    closure_authority: Any = None,
) -> list[dict[str, Any]]:
    """Return exclusions authorized by exact independent negative decisions.

    A report-index dropout may still carry report-index work, but it no longer
    needs a second vulnerability verifier after an authentic full-claim/scope
    disposition.  The caller must consume remaining non-verification
    obligations separately.
    """

    ledger = validate_finding_lifecycle(
        value, closure_authority=closure_authority
    )
    return [
        {
            "run_id": ledger["run_id"],
            "candidate_id": state["candidate_id"],
            "candidate_content_sha256s": list(
                state["candidate_content_sha256s"]
            ),
            "source_record_sha256s": list(state["source_record_sha256s"]),
            "lineage_ids": list(state["lineage_ids"]),
            "claim_state": state["claim_state"],
            "decision_ids": list(state["decision_ids"]),
            "accepted_decision_sha256s": list(
                state["accepted_decision_sha256s"]
            ),
        }
        for state in ledger["candidate_states"]
        if state["delivery_state"] == "AUTHORIZED_EXCLUDED"
        and state["independent_disposition"]
    ]


def write_finding_lifecycle(
    path: Path,
    value: Mapping[str, Any],
    *,
    closure_authority: Any = None,
) -> bool:
    """Atomically create/advance the ledger with compare-and-swap semantics.

    Returns ``False`` only for byte-equivalent idempotent replay.  A tampered,
    stale, or skipped generation is never overwritten.
    """

    target = Path(path)
    candidate = validate_finding_lifecycle(
        value, closure_authority=closure_authority
    )
    candidate_bytes = _canonical_bytes(candidate) + b"\n"
    prior_bytes: bytes | None = None
    if target.exists():
        prior_bytes = target.read_bytes()
        try:
            prior_value = json.loads(prior_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise FindingLifecycleError(f"existing ledger is unreadable: {exc}") from exc
        prior = validate_finding_lifecycle(
            prior_value, closure_authority=closure_authority
        )
        if prior["ledger_sha256"] == candidate["ledger_sha256"]:
            return False
        if (
            candidate["generation"] != prior["generation"] + 1
            or candidate["previous_receipt_sha256"] != prior["ledger_sha256"]
        ):
            raise FindingLifecycleError(
                "finding lifecycle compare-and-swap predecessor mismatch"
            )
    elif candidate["generation"] != 1 or candidate["previous_receipt_sha256"] is not None:
        raise FindingLifecycleError(
            "finding lifecycle compare-and-swap requires generation one at a new path"
        )

    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(
        prefix=f".{target.name}.", suffix=".tmp", dir=str(target.parent)
    )
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(candidate_bytes)
            handle.flush()
            os.fsync(handle.fileno())
        if prior_bytes is None:
            if target.exists():
                raise FindingLifecycleError(
                    "finding lifecycle compare-and-swap target appeared during create"
                )
        elif not target.exists() or target.read_bytes() != prior_bytes:
            raise FindingLifecycleError(
                "finding lifecycle compare-and-swap target changed during advance"
            )
        os.replace(tmp, target)
        return True
    finally:
        try:
            tmp.unlink()
        except FileNotFoundError:
            pass


__all__ = [
    "CANDIDATE_SCHEMA",
    "DECISION_SCHEMA",
    "LEDGER_SCHEMA",
    "OBLIGATION_SCHEMA",
    "PROJECTION_SCHEMA",
    "FindingLifecycleError",
    "advance_finding_lifecycle",
    "authorized_finding_exclusions",
    "build_finding_lifecycle",
    "candidate_content_sha256",
    "finding_retention_work_items",
    "finding_verification_work_items",
    "validate_finding_lifecycle",
    "write_finding_lifecycle",
]
