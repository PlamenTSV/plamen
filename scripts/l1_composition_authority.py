"""Conditional typed cross-subsystem composition authority for L1 audits.

This is not the smart-contract postcondition/enabler matcher.  It indexes
explicit L1 state, event, timing, validation, rollback, shared-resource, and
trust-boundary atoms and emits bounded *reasoning obligations*.  It cannot
assert a compound vulnerability or infer combined harm.  Any new combined
claim must still enter the independent P0-AF compound verification lifecycle.
"""
from __future__ import annotations

import hashlib
import json
import re
from collections import defaultdict
from typing import Any, Iterable, Mapping, Sequence


L1_COMPOSITION_FACT_SCHEMA = "plamen.l1_composition_fact.v1"
L1_COMPOSITION_GRAPH_SCHEMA = "plamen.l1_composition_graph.v1"
L1_COMPOSITION_DISPOSITION_SCHEMA = "plamen.l1_composition_dispositions.v1"
L1_NEGATIVE_CLOSURE_RECEIPT_SCHEMA = (
    "plamen.l1_composition_negative_closure_shadow_receipt.v1"
)

_HEX64_RE = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
_IDENTITY_RE = re.compile(r"^[A-Z][A-Z0-9_]*(?:-[A-Z0-9_]+)+$", re.ASCII)
_TOKEN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,255}$", re.ASCII)
_LANGUAGES = frozenset({"GO", "RUST", "MIXED", "OTHER"})
_STATES = frozenset({"CONFIRMED", "CONTESTED", "UNRESOLVED", "REFUTED"})
_ATOM_KINDS = frozenset(
    {
        "STATE",
        "EVENT",
        "TIMING",
        "VALIDATION",
        "RESOURCE",
        "ACTIVATION",
        "ROLLBACK",
        "TRUST_BOUNDARY",
    }
)
_DISPOSITIONS = frozenset(
    {
        "COMPOUND_CANDIDATE",
        "RESTATEMENT",
        "INCOMPATIBLE",
        "UNREACHABLE",
        "NEEDS_EVIDENCE",
    }
)
_MAX_PRINCIPAL_CHARS = 4096
MAX_ATOMS_PER_FIELD = 512
MAX_L1_FACTS = 20_000
MAX_L1_DISPOSITIONS = 1_024
MAX_NEGATIVE_CLOSURE_RECEIPTS = 20_000

_NEGATIVE_AUTHORITY_STATES = frozenset(
    {
        "NOT_APPLICABLE",
        "UNBACKED_PRODUCER_REFUTATION_REOPENED",
        "MALFORMED_RECEIPT_REOPENED",
        "STALE_RECEIPT_REOPENED",
        "SHADOW_RECEIPT_REOPENED",
    }
)


class L1CompositionError(ValueError):
    """Typed L1 composition input or reconciliation is invalid."""


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _text(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise L1CompositionError(f"{field} must be a string")
    normalized = value.strip()
    if not normalized or not _TOKEN_RE.fullmatch(normalized):
        raise L1CompositionError(f"{field} must be a bounded token")
    return normalized


def _identity(value: Any) -> str:
    normalized = str(value or "").strip().upper()
    if not _IDENTITY_RE.fullmatch(normalized):
        raise L1CompositionError(f"invalid candidate identity: {value!r}")
    return normalized


def _principal(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise L1CompositionError(f"{field} must not be empty")
    result = value.strip()
    if len(result) > _MAX_PRINCIPAL_CHARS:
        raise L1CompositionError(f"{field} exceeds {_MAX_PRINCIPAL_CHARS} characters")
    if any(ord(char) < 32 or ord(char) == 127 for char in result):
        raise L1CompositionError(f"{field} contains control characters")
    return result


def _atoms(value: Any, field: str) -> list[dict[str, str]]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise L1CompositionError(f"{field} must be an array")
    if len(value) > MAX_ATOMS_PER_FIELD:
        raise L1CompositionError(
            f"{field} exceeds the {MAX_ATOMS_PER_FIELD} atom bound"
        )
    rows: set[tuple[str, str]] = set()
    for raw in value:
        if not isinstance(raw, Mapping) or set(raw) != {"kind", "atom_id"}:
            raise L1CompositionError(f"{field} atom schema mismatch")
        kind = str(raw.get("kind") or "").strip().upper()
        if kind not in _ATOM_KINDS:
            raise L1CompositionError(f"{field} atom kind is invalid")
        atom_id = _text(raw.get("atom_id"), f"{field}.atom_id")
        rows.add((kind, atom_id))
    return [
        {"kind": kind, "atom_id": atom_id}
        for kind, atom_id in sorted(rows)
    ]


def normalize_l1_composition_fact(value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise L1CompositionError("composition fact must be an object")
    language = str(value.get("language") or "").strip().upper()
    state = str(value.get("candidate_state") or "").strip().upper()
    if language not in _LANGUAGES:
        raise L1CompositionError("language is invalid")
    if state not in _STATES:
        raise L1CompositionError("candidate_state is invalid")
    source_sha = str(value.get("source_sha256") or "").strip()
    if not _HEX64_RE.fullmatch(source_sha):
        raise L1CompositionError("source_sha256 is invalid")
    normalized = {
        "schema_version": L1_COMPOSITION_FACT_SCHEMA,
        "candidate_id": _identity(value.get("candidate_id")),
        "language": language,
        "layer": _text(value.get("layer"), "layer"),
        "subsystem": _text(value.get("subsystem"), "subsystem"),
        "root_cause_id": _text(value.get("root_cause_id"), "root_cause_id"),
        "candidate_state": state,
        "requires": _atoms(value.get("requires", []), "requires"),
        "produces": _atoms(value.get("produces", []), "produces"),
        "touches": _atoms(value.get("touches", []), "touches"),
        "source_artifact": _text(value.get("source_artifact"), "source_artifact"),
        "source_sha256": source_sha,
        "producer_identity": _principal(
            value.get("producer_identity"), "producer_identity"
        ),
        "producer_invocation_id": _principal(
            value.get("producer_invocation_id"), "producer_invocation_id"
        ),
        "fact_digest": "",
    }
    unsigned = dict(normalized)
    unsigned["fact_digest"] = ""
    normalized["fact_digest"] = _digest(unsigned)
    return normalized


def validate_l1_composition_fact(value: Mapping[str, Any]) -> dict[str, Any]:
    expected = {
        "schema_version",
        "candidate_id",
        "language",
        "layer",
        "subsystem",
        "root_cause_id",
        "candidate_state",
        "requires",
        "produces",
        "touches",
        "source_artifact",
        "source_sha256",
        "producer_identity",
        "producer_invocation_id",
        "fact_digest",
    }
    if not isinstance(value, Mapping) or set(value) != expected:
        raise L1CompositionError("composition fact schema mismatch")
    if value.get("schema_version") != L1_COMPOSITION_FACT_SCHEMA:
        raise L1CompositionError("composition fact version mismatch")
    rebuilt = normalize_l1_composition_fact(value)
    if rebuilt != dict(value):
        raise L1CompositionError("composition fact is non-canonical or tampered")
    return rebuilt


def _shadow_resolution(value: Any) -> dict[str, Any]:
    """Validate broker-v2 telemetry without upgrading it to live authority."""

    expected = {
        "schema_version",
        "status",
        "outcome",
        "subject_sha256",
        "requested_effect",
        "claim_resolution",
        "harm_resolution",
        "scope_resolution",
        "identity_resolution",
        "debt_reasons",
        "authorities",
        "conflicts",
    }
    if not isinstance(value, Mapping) or set(value) != expected:
        raise L1CompositionError("negative closure broker resolution schema mismatch")
    if value.get("schema_version") != "plamen.closure_broker_resolution.v2":
        raise L1CompositionError("negative closure broker resolution version mismatch")
    exact = {
        "status": "DEBT",
        "outcome": "NO_AUTHORITY",
        "requested_effect": "REFUTED_FULL",
        "claim_resolution": "UNRESOLVED",
        "harm_resolution": "UNRESOLVED",
        "scope_resolution": "UNRESOLVED",
        "identity_resolution": "UNRESOLVED",
    }
    if any(value.get(field) != required for field, required in exact.items()):
        raise L1CompositionError(
            "broker-v2 is shadow-only and cannot issue terminal negative authority"
        )
    subject_sha = str(value.get("subject_sha256") or "").strip()
    if not _HEX64_RE.fullmatch(subject_sha):
        raise L1CompositionError("negative closure subject_sha256 is invalid")
    debt_reasons = value.get("debt_reasons")
    if (
        not isinstance(debt_reasons, Sequence)
        or isinstance(debt_reasons, (str, bytes))
        or not debt_reasons
        or len(debt_reasons) > 128
    ):
        raise L1CompositionError("negative closure debt reasons are invalid")
    normalized_reasons = sorted(
        {_text(reason, "negative closure debt reason") for reason in debt_reasons}
    )
    nested: dict[str, list[dict[str, Any]]] = {}
    for field in ("authorities", "conflicts"):
        rows = value.get(field)
        if (
            not isinstance(rows, Sequence)
            or isinstance(rows, (str, bytes))
            or len(rows) > 512
            or not all(isinstance(row, Mapping) for row in rows)
        ):
            raise L1CompositionError(f"negative closure {field} are invalid")
        try:
            # These rows are shadow telemetry only.  Canonical JSON conversion
            # bounds the accepted value domain and detaches caller-owned maps.
            nested[field] = json.loads(_canonical_bytes(list(rows)).decode("utf-8"))
        except (TypeError, ValueError, UnicodeError) as exc:
            raise L1CompositionError(
                f"negative closure {field} are not canonical JSON"
            ) from exc
    return {
        "schema_version": "plamen.closure_broker_resolution.v2",
        **exact,
        "subject_sha256": subject_sha,
        "debt_reasons": normalized_reasons,
        "authorities": nested["authorities"],
        "conflicts": nested["conflicts"],
    }


def normalize_l1_negative_closure_receipt(
    value: Mapping[str, Any],
) -> dict[str, Any]:
    """Normalize one exact broker-v2 *shadow* receipt.

    This receipt is an observability and future cutover seam.  The only broker
    implementation available today is ``SHADOW_PROPOSAL_ONLY``; consequently,
    a valid receipt can explain why a producer-authored REFUTED was reopened,
    but can never suppress the candidate.  A live central authority requires a
    new reviewed schema and provider-owned completion chain.
    """

    if not isinstance(value, Mapping):
        raise L1CompositionError("negative closure receipt must be an object")
    source_sha = str(value.get("source_sha256") or "").strip()
    fact_digest = str(value.get("fact_digest") or "").strip()
    if not _HEX64_RE.fullmatch(source_sha):
        raise L1CompositionError("negative closure source_sha256 is invalid")
    if not _HEX64_RE.fullmatch(fact_digest):
        raise L1CompositionError("negative closure fact_digest is invalid")
    if value.get("schema_version") != L1_NEGATIVE_CLOSURE_RECEIPT_SCHEMA:
        raise L1CompositionError("negative closure receipt version mismatch")
    if value.get("broker_mode") != "SHADOW_PROPOSAL_ONLY":
        raise L1CompositionError("untrusted live negative closure authority")
    normalized = {
        "schema_version": L1_NEGATIVE_CLOSURE_RECEIPT_SCHEMA,
        "candidate_id": _identity(value.get("candidate_id")),
        "fact_digest": fact_digest,
        "source_artifact": _text(
            value.get("source_artifact"), "negative closure source_artifact"
        ),
        "source_sha256": source_sha,
        "broker_mode": "SHADOW_PROPOSAL_ONLY",
        "broker_resolution": _shadow_resolution(value.get("broker_resolution")),
        "receipt_digest": "",
    }
    unsigned = dict(normalized)
    unsigned["receipt_digest"] = ""
    normalized["receipt_digest"] = _digest(unsigned)
    return normalized


def validate_l1_negative_closure_receipt(
    value: Mapping[str, Any],
) -> dict[str, Any]:
    expected = {
        "schema_version",
        "candidate_id",
        "fact_digest",
        "source_artifact",
        "source_sha256",
        "broker_mode",
        "broker_resolution",
        "receipt_digest",
    }
    if not isinstance(value, Mapping) or set(value) != expected:
        raise L1CompositionError("negative closure receipt schema mismatch")
    rebuilt = normalize_l1_negative_closure_receipt(value)
    if rebuilt != dict(value):
        raise L1CompositionError("negative closure receipt is non-canonical or tampered")
    return rebuilt


def _receipt_input_digest(value: Any, ordinal: int) -> str:
    try:
        return _digest(value)
    except (TypeError, ValueError, UnicodeError):
        return _digest(
            {
                "ordinal": ordinal,
                "malformed_input_type": type(value).__name__,
            }
        )


def _negative_closure_denominator(
    facts: Sequence[Mapping[str, Any]],
    receipts: Iterable[Mapping[str, Any]] | None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], int, str]:
    """Return an exact, non-destructive suppression denominator.

    There is intentionally no terminal path in this version: broker-v2 is
    shadow-only.  Every producer-local REFUTED is normalized to unresolved and
    remains composition-eligible; malformed, stale, duplicate, and shadow
    receipts are preserved as exact visible debt.
    """

    valid_by_id: dict[str, list[tuple[int, dict[str, Any]]]] = defaultdict(list)
    malformed_candidate_ids: set[str] = set()
    input_digests: list[str] = []
    debts: list[dict[str, Any]] = []
    receipt_count = 0

    for ordinal, raw in enumerate(receipts or (), 1):
        if ordinal > MAX_NEGATIVE_CLOSURE_RECEIPTS:
            raise L1CompositionError(
                f"negative closure receipt denominator exceeds {MAX_NEGATIVE_CLOSURE_RECEIPTS}"
            )
        receipt_count = ordinal
        input_digest = _receipt_input_digest(raw, ordinal)
        input_digests.append(input_digest)
        candidate_hint = ""
        if isinstance(raw, Mapping):
            candidate_hint = str(raw.get("candidate_id") or "").strip().upper()
            if not _IDENTITY_RE.fullmatch(candidate_hint):
                candidate_hint = ""
        try:
            receipt = validate_l1_negative_closure_receipt(raw)
        except (L1CompositionError, TypeError, ValueError) as exc:
            if candidate_hint:
                malformed_candidate_ids.add(candidate_hint)
            debts.append(
                {
                    "code": "MALFORMED_NEGATIVE_CLOSURE_RECEIPT",
                    "candidate_id": candidate_hint,
                    "receipt_ordinal": ordinal,
                    "receipt_digest": input_digest,
                    "detail": f"{type(exc).__name__}: {exc}",
                }
            )
            continue
        valid_by_id[receipt["candidate_id"]].append((ordinal, receipt))

    facts_by_id = {str(fact["candidate_id"]): fact for fact in facts}
    for candidate_id, rows in sorted(valid_by_id.items()):
        if candidate_id not in facts_by_id:
            for ordinal, receipt in rows:
                debts.append(
                    {
                        "code": "NEGATIVE_CLOSURE_RECEIPT_SUBJECT_ABSENT",
                        "candidate_id": candidate_id,
                        "receipt_ordinal": ordinal,
                        "receipt_digest": receipt["receipt_digest"],
                        "detail": "receipt subject is absent from the current fact denominator",
                    }
                )
        if len(rows) > 1:
            for ordinal, receipt in rows:
                debts.append(
                    {
                        "code": "DUPLICATE_NEGATIVE_CLOSURE_RECEIPT",
                        "candidate_id": candidate_id,
                        "receipt_ordinal": ordinal,
                        "receipt_digest": receipt["receipt_digest"],
                        "detail": "multiple receipts cannot establish unique terminal authority",
                    }
                )

    denominator: list[dict[str, Any]] = []
    for fact in sorted(facts, key=lambda row: row["candidate_id"]):
        candidate_id = str(fact["candidate_id"])
        producer_refuted = fact["candidate_state"] == "REFUTED"
        exact_receipts: list[tuple[int, dict[str, Any]]] = []
        stale_receipts: list[tuple[int, dict[str, Any]]] = []
        for ordinal, receipt in valid_by_id.get(candidate_id, []):
            if (
                receipt["fact_digest"] == fact["fact_digest"]
                and receipt["source_artifact"] == fact["source_artifact"]
                and receipt["source_sha256"] == fact["source_sha256"]
            ):
                exact_receipts.append((ordinal, receipt))
            else:
                stale_receipts.append((ordinal, receipt))
                debts.append(
                    {
                        "code": "STALE_NEGATIVE_CLOSURE_RECEIPT",
                        "candidate_id": candidate_id,
                        "receipt_ordinal": ordinal,
                        "receipt_digest": receipt["receipt_digest"],
                        "detail": "receipt does not bind the current fact/source bytes",
                    }
                )

        if not producer_refuted:
            authority_state = "NOT_APPLICABLE"
            for ordinal, receipt in exact_receipts:
                debts.append(
                    {
                        "code": "NEGATIVE_CLOSURE_RECEIPT_FOR_NON_REFUTED_FACT",
                        "candidate_id": candidate_id,
                        "receipt_ordinal": ordinal,
                        "receipt_digest": receipt["receipt_digest"],
                        "detail": "negative receipt cannot alter a non-refuted producer state",
                    }
                )
        elif exact_receipts:
            authority_state = "SHADOW_RECEIPT_REOPENED"
            for ordinal, receipt in exact_receipts:
                debts.append(
                    {
                        "code": "SHADOW_NEGATIVE_CLOSURE_RECEIPT",
                        "candidate_id": candidate_id,
                        "receipt_ordinal": ordinal,
                        "receipt_digest": receipt["receipt_digest"],
                        "detail": "broker-v2 is proposal-only; candidate remains eligible",
                    }
                )
        elif stale_receipts:
            authority_state = "STALE_RECEIPT_REOPENED"
        elif candidate_id in malformed_candidate_ids:
            authority_state = "MALFORMED_RECEIPT_REOPENED"
        else:
            authority_state = "UNBACKED_PRODUCER_REFUTATION_REOPENED"
            debts.append(
                {
                    "code": "UNBACKED_PRODUCER_REFUTATION",
                    "candidate_id": candidate_id,
                    "receipt_ordinal": 0,
                    "receipt_digest": "",
                    "detail": "producer-authored REFUTED has no terminal central authority",
                }
            )

        denominator.append(
            {
                "candidate_id": candidate_id,
                "fact_digest": fact["fact_digest"],
                "producer_state": fact["candidate_state"],
                "authority_state": authority_state,
                "terminal_suppression_authorized": False,
                "eligible_for_composition": True,
                "matched_receipt_digests": sorted(
                    receipt["receipt_digest"] for _, receipt in exact_receipts
                ),
            }
        )

    debts.sort(
        key=lambda row: (
            row["code"],
            row["candidate_id"],
            row["receipt_ordinal"],
            row["receipt_digest"],
            row["detail"],
        )
    )
    return denominator, debts, receipt_count, _digest(sorted(input_digests))


def _atom_key(value: Mapping[str, str]) -> tuple[str, str]:
    return str(value["kind"]), str(value["atom_id"])


def _relation_for(kind: str, *, shared: bool = False) -> str:
    if shared:
        return "SHARED_RESOURCE"
    return {
        "VALIDATION": "VALIDATION_PROPAGATION",
        "TIMING": "TIMING_ORDERING",
        "EVENT": "EVENT_ORDERING",
        "ACTIVATION": "ACTIVATION_ORDERING",
        "ROLLBACK": "ROLLBACK_REPLAY",
        "TRUST_BOUNDARY": "TRUST_BOUNDARY_CROSSING",
        "STATE": "STATE_DEPENDENCY",
        "RESOURCE": "RESOURCE_DEPENDENCY",
    }[kind]


def _pair_eligible(left: Mapping[str, Any], right: Mapping[str, Any]) -> bool:
    return (
        left["candidate_id"] != right["candidate_id"]
        and left["root_cause_id"] != right["root_cause_id"]
        and (
            left["layer"] != right["layer"]
            or left["subsystem"] != right["subsystem"]
        )
    )


def _obligation_id(prefix: str, value: Mapping[str, Any]) -> str:
    return f"{prefix}-{_digest(value)[:16].upper()}"


def enumerate_l1_composition_graph(
    facts: Iterable[Mapping[str, Any]],
    *,
    mode: str,
    negative_closure_receipts: Iterable[Mapping[str, Any]] | None = None,
    max_pair_fanout: int = 6,
    max_edges: int = 512,
    max_family_members: int = 128,
    max_family_obligations: int = 256,
) -> dict[str, Any]:
    """Enumerate exact-atom obligations without an all-pairs product."""

    mode_n = str(mode or "").strip().lower()
    if mode_n not in {"core", "thorough"}:
        raise L1CompositionError("L1 composition is conditional on Core/Thorough")
    if isinstance(max_pair_fanout, bool) or max_pair_fanout < 2:
        raise L1CompositionError("max_pair_fanout must be at least 2")
    if isinstance(max_edges, bool) or max_edges < 1:
        raise L1CompositionError("max_edges must be positive")
    if isinstance(max_family_members, bool) or max_family_members < 2:
        raise L1CompositionError("max_family_members must be at least 2")
    if isinstance(max_family_obligations, bool) or max_family_obligations < 1:
        raise L1CompositionError("max_family_obligations must be positive")
    canonical: list[dict[str, Any]] = []
    for ordinal, fact in enumerate(facts, 1):
        if ordinal > MAX_L1_FACTS:
            raise L1CompositionError(
                f"composition fact denominator exceeds {MAX_L1_FACTS}"
            )
        canonical.append(validate_l1_composition_fact(fact))
    by_id = {fact["candidate_id"]: fact for fact in canonical}
    if len(by_id) != len(canonical):
        raise L1CompositionError("candidate identities must be unique")
    (
        negative_denominator,
        negative_debt,
        negative_receipt_count,
        negative_receipts_digest,
    ) = _negative_closure_denominator(canonical, negative_closure_receipts)
    eligible_ids = {
        row["candidate_id"]
        for row in negative_denominator
        if row["eligible_for_composition"]
    }

    producer_index: dict[tuple[str, str], list[str]] = defaultdict(list)
    consumer_index: dict[tuple[str, str], list[str]] = defaultdict(list)
    touch_index: dict[tuple[str, str], list[str]] = defaultdict(list)
    for fact in canonical:
        if fact["candidate_id"] not in eligible_ids:
            continue
        for atom in fact["produces"]:
            producer_index[_atom_key(atom)].append(fact["candidate_id"])
        for atom in fact["requires"]:
            consumer_index[_atom_key(atom)].append(fact["candidate_id"])
        for atom in fact["touches"]:
            if atom["kind"] in {"STATE", "RESOURCE"}:
                touch_index[_atom_key(atom)].append(fact["candidate_id"])

    edges: list[dict[str, Any]] = []
    families: list[dict[str, Any]] = []
    suppressed: list[dict[str, Any]] = []
    budget_debt: list[dict[str, Any]] = []
    seen_edges: set[tuple[str, str, str, str, str]] = set()

    def emit_group(
        *,
        relation: str,
        atom: tuple[str, str],
        left_ids: Sequence[str],
        right_ids: Sequence[str],
        shared: bool,
    ) -> None:
        participants = sorted(set(left_ids) | set(right_ids))
        if len(participants) > max_pair_fanout:
            family_core = {
                "relation": relation,
                "atom": {"kind": atom[0], "atom_id": atom[1]},
                "candidate_ids": participants,
            }
            if len(participants) > max_family_members:
                debt_core = {
                    "relation": relation,
                    "atom": {"kind": atom[0], "atom_id": atom[1]},
                    "participant_count": len(participants),
                    "participants_digest": _digest(participants),
                }
                budget_debt.append(
                    {
                        "obligation_id": _obligation_id("L1CFB", debt_core),
                        **debt_core,
                        "reason": "FAMILY_PARTICIPANT_BUDGET_EXHAUSTED",
                    }
                )
                return
            families.append(
                {
                    "obligation_id": _obligation_id("L1CF", family_core),
                    **family_core,
                    "reason": "HUB_FANOUT_BOUNDED",
                }
            )
            return
        for left_id in sorted(set(left_ids)):
            for right_id in sorted(set(right_ids)):
                if shared and left_id >= right_id:
                    continue
                left = by_id[left_id]
                right = by_id[right_id]
                if not _pair_eligible(left, right):
                    reason = (
                        "SAME_ROOT_RESTATEMENT"
                        if left["root_cause_id"] == right["root_cause_id"]
                        else "SAME_SUBSYSTEM_LAYER"
                    )
                    suppressed.append(
                        {
                            "left_id": left_id,
                            "right_id": right_id,
                            "relation": relation,
                            "reason": reason,
                        }
                    )
                    continue
                key = (left_id, right_id, relation, atom[0], atom[1])
                if key in seen_edges:
                    continue
                seen_edges.add(key)
                edge_core = {
                    "predecessor_id": left_id,
                    "successor_id": right_id,
                    "relation": relation,
                    "atom": {"kind": atom[0], "atom_id": atom[1]},
                    "constituent_fact_digests": sorted(
                        [left["fact_digest"], right["fact_digest"]]
                    ),
                }
                edges.append(
                    {
                        "obligation_id": _obligation_id("L1CE", edge_core),
                        **edge_core,
                    }
                )

    for atom in sorted(set(producer_index) & set(consumer_index)):
        emit_group(
            relation=_relation_for(atom[0]),
            atom=atom,
            left_ids=producer_index[atom],
            right_ids=consumer_index[atom],
            shared=False,
        )
    for atom, ids in sorted(touch_index.items()):
        if len(set(ids)) < 2:
            continue
        emit_group(
            relation=_relation_for(atom[0], shared=True),
            atom=atom,
            left_ids=ids,
            right_ids=ids,
            shared=True,
        )

    edges.sort(key=lambda row: row["obligation_id"])
    families.sort(key=lambda row: row["obligation_id"])
    truncated = edges[max_edges:]
    edges = edges[:max_edges]
    truncated_families = families[max_family_obligations:]
    families = families[:max_family_obligations]
    budget_debt.extend(
        {
            "obligation_id": row["obligation_id"],
            "reason": "FAMILY_OBLIGATION_BUDGET_EXHAUSTED",
        }
        for row in truncated_families
    )
    status = (
        "BUDGET_DEBT"
        if truncated or budget_debt
        else "READY"
        if edges or families
        else "NOT_TRIGGERED"
    )
    graph = {
        "schema_version": L1_COMPOSITION_GRAPH_SCHEMA,
        "mode": mode_n,
        "status": status,
        "fact_count": len(canonical),
        "facts_digest": _digest(
            [fact["fact_digest"] for fact in sorted(canonical, key=lambda row: row["candidate_id"])]
        ),
        "negative_closure_receipt_count": negative_receipt_count,
        "negative_closure_receipts_digest": negative_receipts_digest,
        "negative_closure_suppression_denominator": negative_denominator,
        "negative_closure_debt": negative_debt,
        "edges": edges,
        "family_obligations": families,
        "suppressed_relations": sorted(
            suppressed,
            key=lambda row: (
                row["left_id"], row["right_id"], row["relation"], row["reason"]
            ),
        ),
        "coverage_debt": sorted(
            [
                {
                    "obligation_id": row["obligation_id"],
                    "reason": "EDGE_BUDGET_EXHAUSTED",
                }
                for row in truncated
            ]
            + budget_debt,
            key=lambda row: (str(row.get("obligation_id") or ""), str(row.get("reason") or "")),
        ),
        "graph_digest": "",
    }
    unsigned = dict(graph)
    unsigned["graph_digest"] = ""
    graph["graph_digest"] = _digest(unsigned)
    return graph


def validate_l1_composition_graph(value: Mapping[str, Any]) -> dict[str, Any]:
    expected = {
        "schema_version",
        "mode",
        "status",
        "fact_count",
        "facts_digest",
        "negative_closure_receipt_count",
        "negative_closure_receipts_digest",
        "negative_closure_suppression_denominator",
        "negative_closure_debt",
        "edges",
        "family_obligations",
        "suppressed_relations",
        "coverage_debt",
        "graph_digest",
    }
    if not isinstance(value, Mapping) or set(value) != expected:
        raise L1CompositionError("composition graph schema mismatch")
    if value.get("schema_version") != L1_COMPOSITION_GRAPH_SCHEMA:
        raise L1CompositionError("composition graph version mismatch")
    receipt_count = value.get("negative_closure_receipt_count")
    receipts_digest = str(value.get("negative_closure_receipts_digest") or "")
    denominator = value.get("negative_closure_suppression_denominator")
    debt = value.get("negative_closure_debt")
    if type(receipt_count) is not int or receipt_count < 0:
        raise L1CompositionError("negative closure receipt count is invalid")
    if not _HEX64_RE.fullmatch(receipts_digest):
        raise L1CompositionError("negative closure receipt denominator digest is invalid")
    if not isinstance(denominator, list) or len(denominator) != value.get("fact_count"):
        raise L1CompositionError("negative closure suppression denominator is incomplete")
    seen_candidate_ids: set[str] = set()
    denominator_fact_digests: list[str] = []
    expected_row_fields = {
        "candidate_id",
        "fact_digest",
        "producer_state",
        "authority_state",
        "terminal_suppression_authorized",
        "eligible_for_composition",
        "matched_receipt_digests",
    }
    for row in denominator:
        if not isinstance(row, Mapping) or set(row) != expected_row_fields:
            raise L1CompositionError("negative closure denominator row schema mismatch")
        candidate_id = _identity(row.get("candidate_id"))
        if candidate_id in seen_candidate_ids:
            raise L1CompositionError("negative closure candidate denominator is not unique")
        seen_candidate_ids.add(candidate_id)
        fact_digest = str(row.get("fact_digest") or "")
        if not _HEX64_RE.fullmatch(fact_digest):
            raise L1CompositionError("negative closure denominator fact digest is invalid")
        denominator_fact_digests.append(fact_digest)
        if row.get("producer_state") not in _STATES:
            raise L1CompositionError("negative closure producer state is invalid")
        if row.get("authority_state") not in _NEGATIVE_AUTHORITY_STATES:
            raise L1CompositionError("negative closure authority state is invalid")
        # Broker-v2 is shadow-only.  Accepting either opposite value would turn
        # a self-consistent graph into destructive authority.
        if row.get("terminal_suppression_authorized") is not False:
            raise L1CompositionError("live terminal negative authority is unavailable")
        if row.get("eligible_for_composition") is not True:
            raise L1CompositionError("shadow negative receipt suppressed a candidate")
        matched = row.get("matched_receipt_digests")
        if (
            not isinstance(matched, list)
            or matched != sorted(matched)
            or any(not _HEX64_RE.fullmatch(str(item or "")) for item in matched)
        ):
            raise L1CompositionError("negative closure matched receipt set is invalid")
    if _digest(denominator_fact_digests) != value.get("facts_digest"):
        raise L1CompositionError("negative closure fact denominator binding mismatch")
    if not isinstance(debt, list):
        raise L1CompositionError("negative closure debt must be an array")
    debt_fields = {
        "code",
        "candidate_id",
        "receipt_ordinal",
        "receipt_digest",
        "detail",
    }
    for row in debt:
        if not isinstance(row, Mapping) or set(row) != debt_fields:
            raise L1CompositionError("negative closure debt row schema mismatch")
        if not isinstance(row.get("code"), str) or not row["code"]:
            raise L1CompositionError("negative closure debt code is invalid")
        if not isinstance(row.get("candidate_id"), str):
            raise L1CompositionError("negative closure debt candidate is invalid")
        if type(row.get("receipt_ordinal")) is not int or row["receipt_ordinal"] < 0:
            raise L1CompositionError("negative closure debt ordinal is invalid")
        debt_digest = str(row.get("receipt_digest") or "")
        if debt_digest and not _HEX64_RE.fullmatch(debt_digest):
            raise L1CompositionError("negative closure debt receipt digest is invalid")
        if not isinstance(row.get("detail"), str) or not row["detail"]:
            raise L1CompositionError("negative closure debt detail is invalid")
    unsigned = dict(value)
    supplied = unsigned.pop("graph_digest", None)
    unsigned["graph_digest"] = ""
    if not _HEX64_RE.fullmatch(str(supplied or "")) or supplied != _digest(unsigned):
        raise L1CompositionError("composition graph digest mismatch")
    obligation_ids = [
        str(row.get("obligation_id") or "")
        for row in [
            *(value.get("edges") or []),
            *(value.get("family_obligations") or []),
        ]
        if isinstance(row, Mapping)
    ]
    if not all(obligation_ids) or len(obligation_ids) != len(set(obligation_ids)):
        raise L1CompositionError("composition obligation identities are invalid")
    return dict(value)


def reconcile_l1_composition_dispositions(
    graph: Mapping[str, Any], dispositions: Iterable[Mapping[str, Any]]
) -> dict[str, Any]:
    """Require one disposition for every bounded packet; judgment stays model-side."""

    canonical = validate_l1_composition_graph(graph)
    expected = {
        row["obligation_id"]
        for row in [
            *canonical["edges"],
            *canonical["family_obligations"],
        ]
    }
    rows: list[dict[str, str]] = []
    seen: set[str] = set()
    duplicates: set[str] = set()
    unexpected: set[str] = set()
    for ordinal, raw in enumerate(dispositions, 1):
        if ordinal > MAX_L1_DISPOSITIONS:
            raise L1CompositionError(
                f"composition dispositions exceed {MAX_L1_DISPOSITIONS}"
            )
        if not isinstance(raw, Mapping) or set(raw) != {
            "obligation_id",
            "disposition",
            "rationale",
        }:
            raise L1CompositionError("composition disposition schema mismatch")
        oid = _principal(raw.get("obligation_id"), "obligation_id")
        disposition = str(raw.get("disposition") or "").strip().upper()
        rationale = _principal(raw.get("rationale"), "rationale")
        if disposition not in _DISPOSITIONS:
            raise L1CompositionError("composition disposition is invalid")
        if oid in seen:
            duplicates.add(oid)
        seen.add(oid)
        if oid not in expected:
            unexpected.add(oid)
        rows.append(
            {
                "obligation_id": oid,
                "disposition": disposition,
                "rationale": rationale,
            }
        )
    payload = {
        "schema_version": L1_COMPOSITION_DISPOSITION_SCHEMA,
        "graph_digest": canonical["graph_digest"],
        "dispositions": sorted(rows, key=lambda row: row["obligation_id"]),
        "missing_obligation_ids": sorted(expected - seen),
        "duplicate_obligation_ids": sorted(duplicates),
        "unexpected_obligation_ids": sorted(unexpected),
        "exact_coverage": not (expected - seen or duplicates or unexpected),
        "payload_digest": "",
    }
    unsigned = dict(payload)
    unsigned["payload_digest"] = ""
    payload["payload_digest"] = _digest(unsigned)
    return payload


__all__ = [
    "L1_COMPOSITION_DISPOSITION_SCHEMA",
    "L1_COMPOSITION_FACT_SCHEMA",
    "L1_COMPOSITION_GRAPH_SCHEMA",
    "L1_NEGATIVE_CLOSURE_RECEIPT_SCHEMA",
    "L1CompositionError",
    "enumerate_l1_composition_graph",
    "normalize_l1_negative_closure_receipt",
    "normalize_l1_composition_fact",
    "reconcile_l1_composition_dispositions",
    "validate_l1_composition_fact",
    "validate_l1_composition_graph",
    "validate_l1_negative_closure_receipt",
]
