"""Pure P0-AF v2-to-verifier queue adapter.

The P1-M arm-before-trust consumer can nominate compound work whose
constituents are typed ``EVIDENCE_FACT`` records rather than finding IDs.  The
legacy P0-AF adapter accepts only finding constituents.  This module validates
the complete v2 authority tuple and constructs ordinary queue work without
granting proof, harm, verdict, severity, or report authority.

No file is written here.  The driver must commit the returned queue and the
receipt/debt in one phase transaction.  On every invalid input or identity
collision the input queue is returned byte-for-byte equivalent, so a haltless
degradation cannot become a partial delivery.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any, Iterable, Mapping

from compound_verification import (
    CompoundCandidate,
    ConstituentAuthorityBinding,
    compile_compound_work_plan,
)
from queue_work_items import (
    LineageLink,
    LocationRecord,
    QueueWorkItem,
    SeverityProposal,
    queue_record_set_digest,
    validate_queue_work_items,
)


CANDIDATE_FILE = "arm_before_trust_compound_candidates.json"
WORK_AUTHORITY_FILE = "arm_before_trust_compound_work_plan.json"
ROUTE_DEBT_FILE = "arm_before_trust_p0af_route_debt.json"
IDENTITY_DENOMINATOR_FILE = "_canonical_finding_ids.json"

RECEIPT_SCHEMA = "plamen.p0af_v2_queue_delivery.v1"
DEBT_SCHEMA = "plamen.p0af_v2_queue_delivery_debt.v1"
MAX_AUTHORITY_BYTES = 8 * 1024 * 1024
MAX_CANDIDATE_ROWS = 1024
MAX_ALIAS_RELATIONS = 1024
MAX_BINDINGS_PER_CANDIDATE = 1024
MAX_TOTAL_FACT_BINDINGS = 8192
MAX_FACT_ROWS_PER_AUTHORITY = 20_000
MAX_TYPED_LOCI_PER_FACT = 64

_HEX_RE = re.compile(r"^[0-9a-f]{64}$")
_IDENTITY_RE = re.compile(r"^[A-Z][A-Z0-9_]*(?:-[A-Z0-9_]+)+$")
_CHAIN_RE = re.compile(r"^CH-\d{1,6}$")
_TYPED_LOCUS_RE = re.compile(
    r"^(?P<artifact>.+):[Ll]"
    r"(?P<start>[1-9]\d*)(?:-[Ll]?(?P<end>[1-9]\d*))?$"
)

_CANDIDATE_KEYS = frozenset(
    {
        "schema_version",
        "source_analysis_digest",
        "source_composition_digest",
        "source_fact_authority_digest",
        "identity_denominator_artifact",
        "identity_denominator_digest",
        "proof_authority",
        "candidate_count",
        "candidates",
        "payload_digest",
    }
)
_WORK_KEYS = frozenset(
    {
        "schema_version",
        "candidate_payload_digest",
        "proof_authority",
        "compound_work_plan",
        "payload_digest",
    }
)
_ROUTE_KEYS = frozenset(
    {
        "schema_version",
        "status",
        "work_authority_digest",
        "ready_work_item_ids",
        "ordinary_verification_required",
        "route",
        "proof_authority",
        "payload_digest",
    }
)


class P0AFV2AdapterError(ValueError):
    """A stable, non-secret adapter disposition code plus bounded detail."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(detail)
        self.code = code


@dataclass(frozen=True, slots=True)
class P0AFV2QueueDelivery:
    queue_items: tuple[QueueWorkItem, ...]
    receipt: Mapping[str, Any] | None
    debt: Mapping[str, Any] | None


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _payload_digest(value: Mapping[str, Any]) -> str:
    return _digest({key: item for key, item in value.items() if key != "payload_digest"})


def _require_exact_keys(value: Mapping[str, Any], keys: frozenset[str], label: str) -> None:
    if set(value) != keys:
        raise P0AFV2AdapterError(
            "P0_AF_V2_INPUT_INVALID", f"{label} fields mismatch"
        )


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise P0AFV2AdapterError(
                "P0_AF_V2_INPUT_INVALID", f"duplicate JSON key: {key}"
            )
        result[key] = value
    return result


def _read_json_once(
    root: Path,
    name: str,
    cache: dict[str, tuple[bytes, Mapping[str, Any]]],
) -> tuple[bytes, Mapping[str, Any]]:
    if name in cache:
        return cache[name]
    if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}", name):
        raise P0AFV2AdapterError(
            "P0_AF_V2_INPUT_INVALID", "authority artifact name is unsafe"
        )
    path = root / name
    if path.is_symlink() or not path.is_file():
        raise P0AFV2AdapterError(
            "P0_AF_V2_INPUT_INVALID", f"required authority unavailable: {name}"
        )
    try:
        if path.stat().st_size > MAX_AUTHORITY_BYTES:
            raise P0AFV2AdapterError(
                "P0_AF_V2_INPUT_INVALID",
                f"required authority exceeds {MAX_AUTHORITY_BYTES} bytes: {name}",
            )
        raw = path.read_bytes()
        if len(raw) > MAX_AUTHORITY_BYTES:
            raise P0AFV2AdapterError(
                "P0_AF_V2_INPUT_INVALID",
                f"required authority exceeds {MAX_AUTHORITY_BYTES} bytes after read: {name}",
            )
        parsed = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_strict_object,
            parse_constant=lambda value: (_ for _ in ()).throw(
                P0AFV2AdapterError(
                    "P0_AF_V2_INPUT_INVALID", f"invalid JSON constant: {value}"
                )
            ),
        )
    except Exception as exc:
        raise P0AFV2AdapterError(
            "P0_AF_V2_INPUT_INVALID",
            f"required authority malformed: {name}:{type(exc).__name__}",
        ) from exc
    if not isinstance(parsed, Mapping):
        raise P0AFV2AdapterError(
            "P0_AF_V2_INPUT_INVALID", f"required authority is not an object: {name}"
        )
    cache[name] = (raw, parsed)
    return raw, parsed


def _validate_payload(
    payload: Mapping[str, Any],
    *,
    keys: frozenset[str],
    schema: str,
    label: str,
) -> None:
    _require_exact_keys(payload, keys, label)
    if payload.get("schema_version") != schema:
        raise P0AFV2AdapterError(
            "P0_AF_V2_INPUT_INVALID", f"{label} schema mismatch"
        )
    digest = payload.get("payload_digest")
    if not isinstance(digest, str) or not _HEX_RE.fullmatch(digest):
        raise P0AFV2AdapterError(
            "P0_AF_V2_INPUT_INVALID", f"{label} payload digest malformed"
        )
    if digest != _payload_digest(payload):
        raise P0AFV2AdapterError(
            "P0_AF_V2_INPUT_INVALID", f"{label} payload digest mismatch"
        )
    if payload.get("proof_authority") != "NONE":
        raise P0AFV2AdapterError(
            "P0_AF_V2_INPUT_INVALID", f"{label} attempted to grant proof authority"
        )
    malformed_declared = sorted(
        key for key, value in payload.items()
        if key.endswith("_digest")
        and (not isinstance(value, str) or not _HEX_RE.fullmatch(value))
    )
    if malformed_declared:
        raise P0AFV2AdapterError(
            "P0_AF_V2_INPUT_INVALID",
            f"{label} declared digest field(s) malformed: "
            + ", ".join(malformed_declared),
        )


def _identity_denominator(
    root: Path,
    cache: dict[str, tuple[bytes, Mapping[str, Any]]],
) -> tuple[set[str], str, dict[str, str]]:
    raw, payload = _read_json_once(root, IDENTITY_DENOMINATOR_FILE, cache)
    records = payload.get("records")
    if (
        payload.get("schema_version") != "plamen.canonical_finding_ids.v1"
        or not isinstance(records, list)
        or isinstance(payload.get("record_count"), bool)
        or payload.get("record_count") != len(records)
    ):
        raise P0AFV2AdapterError(
            "P0_AF_V2_INPUT_INVALID", "identity denominator is malformed"
        )
    identities: set[str] = set()
    source_artifacts: dict[str, str] = {}
    for row in records:
        if not isinstance(row, Mapping):
            raise P0AFV2AdapterError(
                "P0_AF_V2_INPUT_INVALID", "identity denominator row is malformed"
            )
        references = row.get("referenced_ids")
        if references is None:
            references = []
        if not isinstance(references, list):
            raise P0AFV2AdapterError(
                "P0_AF_V2_INPUT_INVALID", "identity references are malformed"
            )
        artifact = str(row.get("artifact") or "").strip()
        for value in (
            row.get("canonical_id"),
            row.get("local_id"),
            row.get("local_id_raw"),
            *references,
        ):
            identity = str(value or "").strip().upper()
            if _IDENTITY_RE.fullmatch(identity):
                identities.add(identity)
                if artifact:
                    source_artifacts.setdefault(identity, artifact)
    return identities, hashlib.sha256(raw).hexdigest(), source_artifacts


def _candidate_from_record(value: Mapping[str, Any]) -> CompoundCandidate:
    expected_keys = {
        "constituents",
        "severity_upgrade_justified",
        "ordering_edges",
        "preconditions",
        "postconditions",
        "combined_impact_claim",
        "proposed_severity",
        "source_lineage",
        "coverage_lineage",
        "pipeline",
        "mode",
        "chain_id",
        "evidence_constituent_bindings",
    }
    if set(value) != expected_keys:
        raise P0AFV2AdapterError(
            "P0_AF_V2_INPUT_INVALID", "typed compound candidate fields mismatch"
        )
    sequence_fields = (
        "constituents",
        "ordering_edges",
        "preconditions",
        "postconditions",
        "source_lineage",
        "coverage_lineage",
        "evidence_constituent_bindings",
    )
    if any(not isinstance(value.get(field), list) for field in sequence_fields):
        raise P0AFV2AdapterError(
            "P0_AF_V2_INPUT_INVALID", "typed compound candidate arrays malformed"
        )
    if len(value["evidence_constituent_bindings"]) > MAX_BINDINGS_PER_CANDIDATE:
        raise P0AFV2AdapterError(
            "P0_AF_V2_INPUT_INVALID",
            "typed compound candidate fact-binding denominator exceeds the bound",
        )
    if not isinstance(value.get("severity_upgrade_justified"), bool):
        raise P0AFV2AdapterError(
            "P0_AF_V2_INPUT_INVALID",
            "severity_upgrade_justified must be a JSON boolean",
        )
    edges: list[tuple[str, str, str]] = []
    for edge in value["ordering_edges"]:
        if not isinstance(edge, Mapping) or set(edge) != {
            "predecessor", "successor", "relation"
        }:
            raise P0AFV2AdapterError(
                "P0_AF_V2_INPUT_INVALID", "typed composition edge malformed"
            )
        edges.append((edge["predecessor"], edge["successor"], edge["relation"]))
    try:
        candidate = CompoundCandidate.create(
            chain_id=value["chain_id"],
            constituents=value["constituents"],
            severity_upgrade_justified=value["severity_upgrade_justified"],
            ordering_edges=edges,
            preconditions=value["preconditions"],
            postconditions=value["postconditions"],
            combined_impact_claim=value["combined_impact_claim"],
            proposed_severity=value["proposed_severity"],
            source_lineage=value["source_lineage"],
            coverage_lineage=value["coverage_lineage"],
            pipeline=value["pipeline"],
            mode=value["mode"],
            evidence_constituent_bindings=value["evidence_constituent_bindings"],
        )
    except (TypeError, ValueError, KeyError) as exc:
        raise P0AFV2AdapterError(
            "P0_AF_V2_INPUT_INVALID",
            f"typed compound candidate invalid:{type(exc).__name__}",
        ) from exc
    if candidate.to_record() != dict(value):
        raise P0AFV2AdapterError(
            "P0_AF_V2_INPUT_INVALID", "typed compound candidate is non-canonical"
        )
    return candidate


def _validate_binding_sources(
    root: Path,
    candidates: tuple[CompoundCandidate, ...],
    cache: dict[str, tuple[bytes, Mapping[str, Any]]],
) -> tuple[
    tuple[ConstituentAuthorityBinding, ...],
    Mapping[str, tuple[LocationRecord, ...]],
]:
    by_id: dict[str, ConstituentAuthorityBinding] = {}
    for candidate in candidates:
        for binding in candidate.evidence_constituent_bindings:
            prior = by_id.get(binding.constituent_id)
            if prior is not None and prior != binding:
                raise P0AFV2AdapterError(
                    "P0_AF_V2_INPUT_INVALID", "conflicting evidence fact binding"
                )
            by_id[binding.constituent_id] = binding
    authorities: dict[str, Mapping[str, Any]] = {}
    fact_indexes: dict[str, dict[str, Mapping[str, Any]]] = {}
    locations_by_id: dict[str, tuple[LocationRecord, ...]] = {}
    for binding in by_id.values():
        source = binding.source_artifact
        if source not in authorities:
            _, authority = _read_json_once(root, source, cache)
            authorities[source] = authority
            semantic_authority = {
                key: value for key, value in authority.items()
                if key != "authority_digest"
            }
            actual_authority_digest = hashlib.sha256(
                json.dumps(
                    semantic_authority,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=False,
                ).encode("utf-8")
            ).hexdigest()
            if authority.get("authority_digest") != binding.authority_digest:
                raise P0AFV2AdapterError(
                    "P0_AF_V2_INPUT_INVALID",
                    "evidence fact authority digest mismatch",
                )
            if actual_authority_digest != binding.authority_digest:
                raise P0AFV2AdapterError(
                    "P0_AF_V2_INPUT_INVALID",
                    "evidence fact authority digest is not reproducible",
                )
            facts = authority.get("facts")
            if (
                not isinstance(facts, list)
                or len(facts) > MAX_FACT_ROWS_PER_AUTHORITY
            ):
                raise P0AFV2AdapterError(
                    "P0_AF_V2_INPUT_INVALID",
                    "evidence fact authority rows malformed or oversized",
                )
            index: dict[str, Mapping[str, Any]] = {}
            for row in facts:
                if not isinstance(row, Mapping):
                    raise P0AFV2AdapterError(
                        "P0_AF_V2_INPUT_INVALID",
                        "evidence fact authority row is not an object",
                    )
                fact_id = str(row.get("fact_id") or "")
                if not fact_id or fact_id in index:
                    raise P0AFV2AdapterError(
                        "P0_AF_V2_INPUT_INVALID",
                        "evidence fact authority identity is missing or duplicated",
                    )
                index[fact_id] = row
            fact_indexes[source] = index
        elif authorities[source].get("authority_digest") != binding.authority_digest:
            raise P0AFV2AdapterError(
                "P0_AF_V2_INPUT_INVALID",
                "evidence fact bindings disagree on authority digest",
            )
        match = fact_indexes[source].get(binding.constituent_id)
        if match is None or match.get("fact_digest") != binding.fact_digest:
            raise P0AFV2AdapterError(
                "P0_AF_V2_INPUT_INVALID", "evidence fact binding is not exact"
            )
        semantic_fact = {
            key: value for key, value in match.items()
            if key != "fact_digest"
        }
        actual_fact_digest = hashlib.sha256(
            json.dumps(
                semantic_fact,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            ).encode("utf-8")
        ).hexdigest()
        if actual_fact_digest != binding.fact_digest:
            raise P0AFV2AdapterError(
                "P0_AF_V2_INPUT_INVALID",
                "evidence fact digest is not reproducible",
            )
        evidence_rows = match.get("evidence")
        if evidence_rows is None:
            locations_by_id[binding.constituent_id] = ()
        elif (
            not isinstance(evidence_rows, list)
            or len(evidence_rows) > MAX_TYPED_LOCI_PER_FACT
        ):
            raise P0AFV2AdapterError(
                "P0_AF_V2_INPUT_INVALID",
                "typed evidence locus denominator is malformed or oversized",
            )
        else:
            locations: list[LocationRecord] = []
            for evidence_row in evidence_rows:
                if not isinstance(evidence_row, Mapping):
                    raise P0AFV2AdapterError(
                        "P0_AF_V2_INPUT_INVALID",
                        "typed evidence locus row is not an object",
                    )
                locus = str(evidence_row.get("locus") or "").strip()
                if not locus:
                    continue
                if len(locus) > 1000:
                    raise P0AFV2AdapterError(
                        "P0_AF_V2_INPUT_INVALID",
                        "typed evidence locus exceeds the deterministic bound",
                    )
                match_locus = _TYPED_LOCUS_RE.fullmatch(locus)
                if match_locus is None:
                    raise P0AFV2AdapterError(
                        "P0_AF_V2_INPUT_INVALID",
                        "typed in-scope evidence locus is not structural",
                    )
                artifact = match_locus.group("artifact")
                windows_path = PureWindowsPath(artifact)
                posix_path = PurePosixPath(artifact)
                if (
                    artifact != artifact.strip()
                    or any(ord(char) < 32 for char in artifact)
                    or windows_path.is_absolute()
                    or posix_path.is_absolute()
                    or ".." in windows_path.parts
                    or ".." in posix_path.parts
                ):
                    raise P0AFV2AdapterError(
                        "P0_AF_V2_INPUT_INVALID",
                        "typed evidence locus path escapes the project",
                    )
                start_line = int(match_locus.group("start"))
                end_line = int(match_locus.group("end") or start_line)
                if end_line < start_line:
                    raise P0AFV2AdapterError(
                        "P0_AF_V2_INPUT_INVALID",
                        "typed evidence locus line range is reversed",
                    )
                locations.append(
                    LocationRecord(
                        artifact=artifact,
                        start_line=start_line,
                        end_line=end_line,
                        note=f"fact={binding.constituent_id};locus={locus}",
                    )
                )
            locations_by_id[binding.constituent_id] = tuple(locations)
    return tuple(by_id[key] for key in sorted(by_id)), locations_by_id


def enumerate_p0af_v2_dynamic_source_artifacts(
    candidate_payload: Mapping[str, Any],
) -> tuple[str, ...]:
    """Enumerate every typed candidate fact source without filesystem IO.

    This validates the same candidate denominator used by delivery and
    exposes only the canonical source-artifact identities that a caller must
    freeze before arming a successor transaction.
    """

    if not isinstance(candidate_payload, Mapping):
        raise P0AFV2AdapterError(
            "P0_AF_V2_INPUT_INVALID",
            "candidate authority is not an object",
        )
    _validate_payload(
        candidate_payload,
        keys=_CANDIDATE_KEYS,
        schema="plamen.arm_before_trust_compound_candidates.v1",
        label="candidate authority",
    )
    if (
        candidate_payload.get("identity_denominator_artifact")
        != IDENTITY_DENOMINATOR_FILE
    ):
        raise P0AFV2AdapterError(
            "P0_AF_V2_INPUT_INVALID",
            "candidate identity denominator artifact is not canonical",
        )
    rows = candidate_payload.get("candidates")
    count = candidate_payload.get("candidate_count")
    if (
        not isinstance(rows, list)
        or isinstance(count, bool)
        or not isinstance(count, int)
        or count != len(rows)
        or count > MAX_CANDIDATE_ROWS
    ):
        raise P0AFV2AdapterError(
            "P0_AF_V2_INPUT_INVALID",
            "candidate denominator mismatch",
        )
    candidates = tuple(
        _candidate_from_record(row)
        if isinstance(row, Mapping)
        else (_ for _ in ()).throw(
            P0AFV2AdapterError(
                "P0_AF_V2_INPUT_INVALID",
                "candidate row is not an object",
            )
        )
        for row in rows
    )
    if sum(
        len(candidate.evidence_constituent_bindings)
        for candidate in candidates
    ) > MAX_TOTAL_FACT_BINDINGS:
        raise P0AFV2AdapterError(
            "P0_AF_V2_INPUT_INVALID",
            "total evidence fact-binding denominator exceeds the bound",
        )
    return tuple(sorted({
        binding.source_artifact
        for candidate in candidates
        for binding in candidate.evidence_constituent_bindings
    }))


def _looks_adapter_owned(item: QueueWorkItem) -> bool:
    return (
        item.evidence_class == "p0af-v2-generator"
        and CANDIDATE_FILE in item.primary_artifacts
        and WORK_AUTHORITY_FILE in item.primary_artifacts
    )


def _validated_prior_ownership(
    current: tuple[QueueWorkItem, ...],
    prior_receipt: Mapping[str, Any] | None,
) -> tuple[set[str], list[str]]:
    """Authenticate prior owned rows without trusting lexical resemblance."""

    current_by_id = {item.work_item_id: item for item in current}
    authenticated: set[str] = set()
    issues: list[str] = []
    if prior_receipt is not None:
        try:
            if not isinstance(prior_receipt, Mapping):
                raise ValueError("prior receipt is not an object")
            if prior_receipt.get("schema_version") != RECEIPT_SCHEMA:
                raise ValueError("prior receipt schema mismatch")
            claimed = prior_receipt.get("payload_digest")
            if not isinstance(claimed, str) or not _HEX_RE.fullmatch(claimed):
                raise ValueError("prior receipt digest malformed")
            if claimed != _payload_digest(prior_receipt):
                raise ValueError("prior receipt digest mismatch")
            if prior_receipt.get("proof_authority") != "NONE":
                raise ValueError("prior receipt acquired proof authority")
            owned = prior_receipt.get("owned_work_item_digests")
            if not isinstance(owned, Mapping) or len(owned) > MAX_CANDIDATE_ROWS:
                raise ValueError("prior receipt ownership map malformed")
            for work_id, digest in owned.items():
                if (
                    not isinstance(work_id, str)
                    or not _CHAIN_RE.fullmatch(work_id)
                    or not isinstance(digest, str)
                    or not _HEX_RE.fullmatch(digest)
                ):
                    raise ValueError("prior receipt ownership row malformed")
                item = current_by_id.get(work_id)
                if item is None:
                    continue
                if item.digest != digest or not _looks_adapter_owned(item):
                    issues.append(f"PRIOR_OWNERSHIP_DRIFT:{work_id}")
                    continue
                authenticated.add(work_id)
        except (TypeError, ValueError) as exc:
            issues.append(f"PRIOR_RECEIPT_INVALID:{type(exc).__name__}:{exc}")
    for item in current:
        if _looks_adapter_owned(item) and item.work_item_id not in authenticated:
            issues.append(f"UNAUTHENTICATED_OWNERSHIP_LOOKALIKE:{item.work_item_id}")
    return authenticated, sorted(set(issues))


def _item_identity_namespace(item: QueueWorkItem) -> set[str]:
    identities = {
        item.candidate_identity,
        item.work_item_id,
        *item.aliases,
        *item.constituents,
    }
    for link in item.lineage:
        identities.add(link.identity)
        if link.parent_identity:
            identities.add(link.parent_identity)
    return identities


def _queue_item(
    work: Mapping[str, Any],
    *,
    priority: int,
    identity_artifacts: Mapping[str, str],
    evidence_locations: Mapping[str, tuple[LocationRecord, ...]],
    aliases: tuple[str, ...] = (),
) -> QueueWorkItem:
    subject = str(work["subject_id"])
    bindings = tuple(
        ConstituentAuthorityBinding.create(value)
        for value in work["constituent_authority_bindings"]
    )
    binding_by_id = {binding.constituent_id: binding for binding in bindings}
    constituent_ids = tuple(str(value) for value in work["constituent_ids"])
    artifacts = tuple(
        dict.fromkeys(
            (
                CANDIDATE_FILE,
                WORK_AUTHORITY_FILE,
                ROUTE_DEBT_FILE,
                IDENTITY_DENOMINATOR_FILE,
                *(binding.source_artifact for binding in bindings),
                *(
                    identity_artifacts[identity]
                    for identity in constituent_ids
                    if identity not in binding_by_id
                    and identity in identity_artifacts
                ),
            )
        )
    )
    lineage = [
        LineageLink(
            identity=subject,
            relation="ORIGIN",
            source_artifact=CANDIDATE_FILE,
        )
    ]
    lineage.extend(
        LineageLink(
            identity=identity,
            relation="CONSTITUENT",
            parent_identity=subject,
            source_artifact=(
                binding_by_id[identity].source_artifact
                if identity in binding_by_id
                else identity_artifacts.get(identity, CANDIDATE_FILE)
            ),
        )
        for identity in constituent_ids
    )
    lineage.extend(
        LineageLink(
            identity=identity,
            relation="ALIAS",
            parent_identity=subject,
            source_artifact=WORK_AUTHORITY_FILE,
        )
        for identity in aliases
    )
    return QueueWorkItem(
        candidate_identity=subject,
        work_item_id=subject,
        lineage=tuple(lineage),
        aliases=aliases,
        constituents=constituent_ids,
        severity_proposal=SeverityProposal(
            level=str(work["proposed_severity"]),
            rationale=(
                "Generator proposal only; independent composition and harm "
                "verification controls final severity."
            ),
        ),
        evidence_class="p0af-v2-generator",
        bug_class="chain-composition",
        preferred_tag="CODE-TRACE",
        queue_priority=priority,
        location_records=tuple(dict.fromkeys((
            LocationRecord(
                artifact=CANDIDATE_FILE,
                note=(
                    f"candidate={subject};claim_sha256={work['candidate_digest']}"
                ),
            ),
            *(
                location
                for identity in constituent_ids
                for location in evidence_locations.get(identity, ())
            ),
        ))),
        primary_artifacts=artifacts,
        poc_class="sequence",
        title=f"Independent verification of composed candidate {subject}",
        effective_evidence_scope="IN_SCOPE_SOURCE",
        effective_proof_scope="ANALYTICAL",
        effective_harm_scope="UNPROVEN",
    )


def _receipt(
    *,
    status: str,
    delivered: list[str],
    queue_items: tuple[QueueWorkItem, ...],
    cache: Mapping[str, tuple[bytes, Mapping[str, Any]]],
    owned_items: tuple[QueueWorkItem, ...],
    ownership_debts: list[str],
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "schema_version": RECEIPT_SCHEMA,
        "status": status,
        "source_sha256": {
            name: hashlib.sha256(raw).hexdigest()
            for name, (raw, _) in sorted(cache.items())
        },
        "delivered_work_item_ids": delivered,
        "ordinary_verification_required": bool(delivered),
        "proof_authority": "NONE",
        "queue_record_count": len(queue_items),
        "queue_record_set_digest": queue_record_set_digest(queue_items),
        "owned_work_item_digests": {
            item.work_item_id: item.digest
            for item in sorted(owned_items, key=lambda row: row.work_item_id)
        },
        "ownership_debts": ownership_debts,
    }
    payload["payload_digest"] = _payload_digest(payload)
    return payload


def _debt(
    *,
    error: P0AFV2AdapterError,
    queue_items: tuple[QueueWorkItem, ...],
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "schema_version": DEBT_SCHEMA,
        "status": "COMPLETED_WITH_DEBT",
        "error_code": error.code,
        "error_class": type(error).__name__,
        "error": str(error)[:500],
        "ordinary_verification_delivery_complete": False,
        "proof_authority": "NONE",
        "preserved_queue_record_count": len(queue_items),
        "preserved_queue_record_set_digest": queue_record_set_digest(queue_items),
    }
    payload["payload_digest"] = _payload_digest(payload)
    return payload


def plan_p0af_v2_queue_delivery(
    scratchpad: Path,
    existing_items: Iterable[QueueWorkItem],
    *,
    prior_receipt: Mapping[str, Any] | None = None,
) -> P0AFV2QueueDelivery:
    """Validate and plan one all-or-nothing ordinary-queue delivery."""

    root = Path(scratchpad)
    current = tuple(existing_items)
    try:
        current = validate_queue_work_items(current)
    except (TypeError, ValueError) as exc:
        error = P0AFV2AdapterError(
            "P0_AF_V2_INPUT_INVALID", f"existing queue invalid:{type(exc).__name__}"
        )
        # The caller supplied no valid denominator that this adapter may mutate.
        return P0AFV2QueueDelivery(current, None, _debt(error=error, queue_items=()))
    authenticated_owned, ownership_debts = (
        _validated_prior_ownership(current, prior_receipt)
    )

    cache: dict[str, tuple[bytes, Mapping[str, Any]]] = {}
    try:
        _, candidate_payload = _read_json_once(root, CANDIDATE_FILE, cache)
        _, work_payload = _read_json_once(root, WORK_AUTHORITY_FILE, cache)
        _, route_payload = _read_json_once(root, ROUTE_DEBT_FILE, cache)
        _validate_payload(
            candidate_payload,
            keys=_CANDIDATE_KEYS,
            schema="plamen.arm_before_trust_compound_candidates.v1",
            label="candidate authority",
        )
        _validate_payload(
            work_payload,
            keys=_WORK_KEYS,
            schema="plamen.arm_before_trust_compound_work_authority.v1",
            label="work authority",
        )
        _validate_payload(
            route_payload,
            keys=_ROUTE_KEYS,
            schema="plamen.arm_before_trust_p0af_route_debt.v1",
            label="route authority",
        )
        identities, denominator_sha, identity_artifacts = _identity_denominator(
            root, cache
        )
        if (
            candidate_payload["identity_denominator_artifact"]
            != IDENTITY_DENOMINATOR_FILE
            or candidate_payload["identity_denominator_digest"] != denominator_sha
        ):
            raise P0AFV2AdapterError(
                "P0_AF_V2_INPUT_INVALID", "identity denominator drift"
            )
        rows = candidate_payload["candidates"]
        count = candidate_payload["candidate_count"]
        if (
            not isinstance(rows, list)
            or isinstance(count, bool)
            or not isinstance(count, int)
            or count != len(rows)
            or count > MAX_CANDIDATE_ROWS
        ):
            raise P0AFV2AdapterError(
                "P0_AF_V2_INPUT_INVALID", "candidate denominator mismatch"
            )
        candidates = tuple(
            _candidate_from_record(row)
            if isinstance(row, Mapping)
            else (_ for _ in ()).throw(
                P0AFV2AdapterError(
                    "P0_AF_V2_INPUT_INVALID", "candidate row is not an object"
                )
            )
            for row in rows
        )
        if sum(
            len(candidate.evidence_constituent_bindings)
            for candidate in candidates
        ) > MAX_TOTAL_FACT_BINDINGS:
            raise P0AFV2AdapterError(
                "P0_AF_V2_INPUT_INVALID",
                "total evidence fact-binding denominator exceeds the bound",
            )
        if len({candidate.chain_id for candidate in candidates}) != len(candidates):
            raise P0AFV2AdapterError(
                "P0_AF_V2_INPUT_INVALID", "duplicate compound candidate identity"
            )
        binding_sources = {
            binding.source_artifact
            for candidate in candidates
            for binding in candidate.evidence_constituent_bindings
        }
        if len(binding_sources) > 1:
            raise P0AFV2AdapterError(
                "P0_AF_V2_INPUT_INVALID",
                "singular fact authority digest names multiple source artifacts",
            )
        bindings, evidence_locations = _validate_binding_sources(
            root, candidates, cache
        )
        fact_identity_collisions = sorted(
            {binding.constituent_id for binding in bindings} & identities
        )
        if fact_identity_collisions:
            raise P0AFV2AdapterError(
                "P0_AF_V2_IDENTITY_COLLISION",
                "evidence-fact identity collides with canonical finding identity: "
                + ",".join(fact_identity_collisions[:8]),
            )
        authority_digests = {binding.authority_digest for binding in bindings}
        if bindings and authority_digests != {
            candidate_payload["source_fact_authority_digest"]
        }:
            raise P0AFV2AdapterError(
                "P0_AF_V2_INPUT_INVALID", "candidate fact authority source mismatch"
            )
        expected_plan = compile_compound_work_plan(
            candidates,
            known_constituent_identities=identities,
            known_evidence_constituents=bindings,
        ).to_record()
        actual_plan = work_payload["compound_work_plan"]
        if not isinstance(actual_plan, Mapping):
            raise P0AFV2AdapterError(
                "P0_AF_V2_INPUT_INVALID", "compound work plan is not an object"
            )
        if actual_plan.get("issues") or actual_plan.get("blocked_candidates"):
            raise P0AFV2AdapterError(
                "P0_AF_V2_BLOCKED_WORK", "compound work contains blocked or issue rows"
            )
        if dict(actual_plan) != expected_plan:
            raise P0AFV2AdapterError(
                "P0_AF_V2_INPUT_INVALID", "compound work plan is not reproducible"
            )
        alias_rows = actual_plan.get("alias_relations")
        if (
            not isinstance(alias_rows, list)
            or len(alias_rows) > MAX_ALIAS_RELATIONS
        ):
            raise P0AFV2AdapterError(
                "P0_AF_V2_INPUT_INVALID",
                "compound alias denominator exceeds the deterministic bound",
            )
        if work_payload["candidate_payload_digest"] != candidate_payload["payload_digest"]:
            raise P0AFV2AdapterError(
                "P0_AF_V2_INPUT_INVALID", "work-to-candidate binding mismatch"
            )
        ready = sorted(
            str(row["subject_id"])
            for row in actual_plan["work_items"]
            if row.get("readiness") == "READY"
        )
        expected_status = "READY_PENDING_QUEUE_DELIVERY" if ready else "CLEAN_NO_NOMINATION"
        if (
            route_payload["work_authority_digest"] != work_payload["payload_digest"]
            or route_payload["ready_work_item_ids"] != ready
            or not isinstance(
                route_payload["ordinary_verification_required"], bool
            )
            or route_payload["ordinary_verification_required"] != bool(ready)
            or route_payload["status"] != expected_status
            or route_payload["route"] != "P0_AF_V2_QUEUE_ADAPTER_REQUIRED"
        ):
            raise P0AFV2AdapterError(
                "P0_AF_V2_INPUT_INVALID", "route denominator mismatch"
            )

        existing_by_id = {item.work_item_id: item for item in current}
        foreign_identity_namespace: set[str] = set()
        for item in current:
            if item.work_item_id not in authenticated_owned:
                foreign_identity_namespace.update(_item_identity_namespace(item))
        non_owned_priorities = [
            item.queue_priority
            for item in current
            if item.work_item_id not in authenticated_owned
        ]
        next_priority = max(non_owned_priorities, default=0) + 1
        replacements: dict[str, QueueWorkItem] = {}
        equivalent_aliases: dict[str, list[str]] = {}
        for alias in alias_rows:
            if not isinstance(alias, Mapping):
                raise P0AFV2AdapterError(
                    "P0_AF_V2_INPUT_INVALID", "compound alias row is malformed"
                )
            if alias.get("kind") != "EQUIVALENT_COMPOUND":
                continue
            alias_id = str(alias.get("alias_id") or "")
            targets = alias.get("target_ids")
            if (
                not _CHAIN_RE.fullmatch(alias_id)
                or not isinstance(targets, list)
                or len(targets) != 1
                or not _CHAIN_RE.fullmatch(str(targets[0]))
            ):
                raise P0AFV2AdapterError(
                    "P0_AF_V2_INPUT_INVALID",
                    "equivalent compound alias relation is malformed",
                )
            equivalent_aliases.setdefault(str(targets[0]), []).append(alias_id)
        ready_subjects = {
            str(row["subject_id"]) for row in actual_plan["work_items"]
        }
        alias_targets: dict[str, str] = {}
        for target, alias_ids in equivalent_aliases.items():
            for alias_id in alias_ids:
                prior_target = alias_targets.get(alias_id)
                if (
                    prior_target is not None
                    or alias_id in identities
                    or alias_id in foreign_identity_namespace
                    or alias_id in ready_subjects
                ):
                    raise P0AFV2AdapterError(
                        "P0_AF_V2_IDENTITY_COLLISION",
                        f"compound alias identity collision: {alias_id}",
                    )
                alias_targets[alias_id] = target
        for row in sorted(actual_plan["work_items"], key=lambda value: value["subject_id"]):
            subject = str(row["subject_id"])
            if not _CHAIN_RE.fullmatch(subject):
                raise P0AFV2AdapterError(
                    "P0_AF_V2_INPUT_INVALID", "work item identity is not CH-N"
                )
            if subject in foreign_identity_namespace:
                raise P0AFV2AdapterError(
                    "P0_AF_V2_IDENTITY_COLLISION",
                    f"ordinary queue lineage identity collision: {subject}",
                )
            old = existing_by_id.get(subject)
            if old is not None and subject not in authenticated_owned:
                raise P0AFV2AdapterError(
                    "P0_AF_V2_IDENTITY_COLLISION",
                    f"ordinary queue identity collision: {subject}",
                )
            priority = old.queue_priority if old is not None else next_priority
            if old is None:
                next_priority += 1
            replacements[subject] = _queue_item(
                row,
                priority=priority,
                identity_artifacts=identity_artifacts,
                evidence_locations=evidence_locations,
                aliases=tuple(sorted(equivalent_aliases.get(subject, ()))),
            )
        result_items = tuple(
            item for item in current
            if item.work_item_id not in authenticated_owned
            and item.work_item_id not in replacements
        ) + tuple(replacements[key] for key in sorted(replacements))
        result_items = validate_queue_work_items(result_items)
        receipt = _receipt(
            status="DELIVERED" if ready else "CLEAN_NO_OP",
            delivered=ready,
            queue_items=result_items,
            cache=cache,
            owned_items=tuple(replacements[key] for key in sorted(replacements)),
            ownership_debts=ownership_debts,
        )
        return P0AFV2QueueDelivery(result_items, receipt, None)
    except P0AFV2AdapterError as exc:
        return P0AFV2QueueDelivery(current, None, _debt(error=exc, queue_items=current))
    except Exception as exc:  # haltless, but never silently permissive
        error = P0AFV2AdapterError(
            "P0_AF_V2_INPUT_INVALID",
            f"unexpected adapter failure:{type(exc).__name__}:{str(exc)[:300]}",
        )
        return P0AFV2QueueDelivery(current, None, _debt(error=error, queue_items=current))


__all__ = [
    "CANDIDATE_FILE",
    "DEBT_SCHEMA",
    "IDENTITY_DENOMINATOR_FILE",
    "MAX_AUTHORITY_BYTES",
    "MAX_CANDIDATE_ROWS",
    "MAX_ALIAS_RELATIONS",
    "MAX_BINDINGS_PER_CANDIDATE",
    "MAX_TOTAL_FACT_BINDINGS",
    "MAX_FACT_ROWS_PER_AUTHORITY",
    "P0AFV2AdapterError",
    "P0AFV2QueueDelivery",
    "RECEIPT_SCHEMA",
    "ROUTE_DEBT_FILE",
    "WORK_AUTHORITY_FILE",
    "enumerate_p0af_v2_dynamic_source_artifacts",
    "plan_p0af_v2_queue_delivery",
]
