"""Typed, decision-neutral reconciliation for external precedent evidence.

Historical reports, methodology articles, and vulnerability databases are
useful for choosing what to investigate and for explaining that an independently
proved mechanism has prior art.  They are not evidence that the mechanism is
present in the audited code.  This module keeps those two evidence domains
separate.

The RAG worker proposes source classifications in a bounded JSON block.  A
deterministic consumer reconciles those proposals against independently derived
finding mechanism/precondition facts.  Even an exact match has no verdict,
severity, proof, or depth-reduction authority.  A family member inherits an
exact precedent signal only through a current typed equivalence record.
"""
from __future__ import annotations

import hashlib
import html
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import uuid
from typing import Any, Iterable, Mapping

from bounded_artifact_io import read_bounded_regular_bytes


PROPOSAL_SCHEMA = "plamen.precedent_evidence_proposals.v1"
FINDING_FACTS_SCHEMA = "plamen.precedent_finding_facts.v1"
EQUIVALENCE_SCHEMA = "plamen.precedent_typed_equivalence.v1"
AUTHORITY_SCHEMA = "plamen.precedent_evidence_authority.v1"
SOURCE_EVIDENCE_SCHEMA = "plamen.precedent_source_evidence.v1"

PROPOSAL_BLOCK_BEGIN = "<!-- PLAMEN_PRECEDENT_PROPOSALS_JSON_BEGIN -->"
PROPOSAL_BLOCK_END = "<!-- PLAMEN_PRECEDENT_PROPOSALS_JSON_END -->"
AUTHORITY_NAME = "precedent_evidence_authority.json"
CONTEXT_NAME = "precedent_context.md"
REPORT_CONTEXT_NAME = "precedent_report_context.md"
PROPOSALS_NAME = "precedent_evidence_proposals.json"
SOURCE_EVIDENCE_NAME = "precedent_source_evidence.json"

ASSURANCE = "INVESTIGATION_PRIORITY_AND_REPORT_CONTEXT_ONLY"
_MAX_PROPOSAL_BLOCK_BYTES = 2_000_000
_MAX_PROPOSAL_TRANSPORT_BYTES = 4_000_000
_MAX_PROPOSALS = 100_000
_MAX_PROPOSALS_PER_FINDING = 32
_MAX_AUTHORITY_BYTES = 32_000_000
_MAX_CAPTURE_BYTES = 8_000_000
_MAX_CAPTURE_TOTAL_BYTES = 64_000_000
_SHA_RE = re.compile(r"^[0-9a-f]{64}$")
_TOKEN_RE = re.compile(r"^[A-Z][A-Z0-9_]{1,95}$")
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_CAPTURE_PART_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$")

_SOURCE_KINDS = {
    "PRIMARY_PRECEDENT",
    "SECONDARY_PRECEDENT",
    "GENERIC_METHODOLOGY",
    "LITERATURE_CONTEXT",
    "UNAVAILABLE",
}
_RELATIONS = {"SUPPORTING", "REFUTING", "CONTEXT", "UNKNOWN"}
_AVAILABILITY = {"AVAILABLE", "OFFLINE", "TIMEOUT", "TOOL_ERROR"}

_PROPOSAL_FIELDS = frozenset(
    {
        "proposal_id",
        "finding_id",
        "source_kind",
        "source_ref",
        "source_sha256",
        "availability",
        "relation",
        "mechanism_class",
        "precondition_classes",
        "report_context",
    }
)
_FORBIDDEN_PROPOSAL_FIELDS = frozenset(
    {
        "confidence",
        "disposition",
        "mechanism_confidence_delta",
        "may_change_severity",
        "may_clear_or_demote",
        "may_force_contested",
        "may_reduce_investigation_depth",
        "proof_status",
        "severity",
        "verdict",
    }
)
SOURCE_EVIDENCE_ASSURANCE = "NEUTRAL_DRIVER_CAPTURED_SOURCE_BYTES"


def _safe_capture_path(value: Any) -> PurePosixPath | None:
    """Return one canonical cross-platform safe-relative capture path."""

    relative = str(value or "").strip()
    posix = PurePosixPath(relative)
    if (
        not relative
        or len(relative.encode("utf-8")) > 512
        or _CONTROL_RE.search(relative)
        or "\\" in relative
        or posix.is_absolute()
        or relative != posix.as_posix()
        or not posix.parts
        or any(
            part in {"", ".", ".."} or not _CAPTURE_PART_RE.fullmatch(part)
            for part in posix.parts
        )
    ):
        return None
    return posix


def canonical_json_bytes(value: Any) -> bytes:
    """Return the only byte representation used for authority digests."""

    return (
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")


def _digest(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _atomic_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(
        f".{path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp"
    )
    try:
        with open(temporary, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def _finite_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        raise ValueError(f"non-finite JSON number {value!r}")
    return parsed


def _reject_constant(value: str) -> None:
    raise ValueError(f"invalid JSON constant {value!r}")


def read_canonical_json_artifact(path: Path) -> dict[str, Any]:
    """Load one bounded, duplicate-key-safe canonical DRIVER artifact."""

    raw = read_bounded_regular_bytes(Path(path), _MAX_AUTHORITY_BYTES)
    try:
        payload = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_strict_object,
            parse_constant=_reject_constant,
            parse_float=_finite_float,
        )
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
        raise ValueError(f"{Path(path).name} is malformed canonical JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"{Path(path).name} root is not an object")
    if raw != canonical_json_bytes(payload):
        raise ValueError(f"{Path(path).name} bytes are not canonical")
    return payload


def extract_proposal_artifact(markdown: str) -> dict[str, Any]:
    """Extract exactly one bounded JSON proposal block from RAG Markdown."""

    if not isinstance(markdown, str):
        raise ValueError("precedent proposal transport is not text")
    if len(markdown.encode("utf-8")) > _MAX_PROPOSAL_TRANSPORT_BYTES:
        raise ValueError("precedent proposal transport exceeds the bounded size")
    if markdown.count(PROPOSAL_BLOCK_BEGIN) != 1 or markdown.count(
        PROPOSAL_BLOCK_END
    ) != 1:
        raise ValueError("precedent proposal transport must contain exactly one block")
    start = markdown.index(PROPOSAL_BLOCK_BEGIN) + len(PROPOSAL_BLOCK_BEGIN)
    end = markdown.index(PROPOSAL_BLOCK_END, start)
    body = markdown[start:end].strip()
    if not body:
        raise ValueError("precedent proposal block is empty")
    if len(body.encode("utf-8")) > _MAX_PROPOSAL_BLOCK_BYTES:
        raise ValueError("precedent proposal block exceeds the bounded size")
    try:
        payload = json.loads(
            body,
            object_pairs_hook=_strict_object,
            parse_constant=_reject_constant,
            parse_float=_finite_float,
        )
    except (ValueError, json.JSONDecodeError) as exc:
        raise ValueError(f"precedent proposal block is malformed JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError("precedent proposal block root is not an object")
    return payload


def _envelope_issues(
    artifact: Mapping[str, Any] | None,
    *,
    schema: str,
    run_id: str,
    snapshot_digest: str,
    label: str,
) -> list[str]:
    if not isinstance(artifact, Mapping):
        return [f"{label} root is not an object"]
    issues: list[str] = []
    if artifact.get("schema_version") != schema:
        issues.append(f"{label} schema mismatch")
    if str(artifact.get("run_id") or "") != run_id:
        issues.append(f"{label} run binding mismatch")
    if str(artifact.get("snapshot_digest") or "") != snapshot_digest:
        issues.append(f"{label} snapshot binding mismatch")
    return issues


def _canonical_tokens(value: Any) -> tuple[tuple[str, ...], str | None]:
    if not isinstance(value, list) or not value:
        return (), "precondition_classes must be a non-empty array"
    tokens: list[str] = []
    for raw in value:
        if not isinstance(raw, str):
            return (), f"invalid precondition class type: {type(raw).__name__}"
        token = raw.strip().upper()
        if not _TOKEN_RE.fullmatch(token):
            return (), f"invalid precondition class: {raw!r}"
        tokens.append(token)
    if len(tokens) != len(set(tokens)):
        return (), "precondition_classes contains duplicates"
    return tuple(sorted(tokens)), None


def _finding_denominator(
    artifact: Mapping[str, Any],
) -> tuple[dict[str, dict[str, Any]], list[dict[str, str]]]:
    rows = artifact.get("findings")
    debts: list[dict[str, str]] = []
    findings: dict[str, dict[str, Any]] = {}
    if not isinstance(rows, list):
        return {}, [
            {
                "code": "FINDING_DENOMINATOR_MALFORMED",
                "subject": "*",
                "detail": "findings must be an array",
            }
        ]
    raw_id_counts: dict[str, int] = {}
    for raw in rows:
        if not isinstance(raw, Mapping):
            continue
        raw_id = str(raw.get("finding_id") or "").strip().upper()
        if raw_id:
            raw_id_counts[raw_id] = raw_id_counts.get(raw_id, 0) + 1
    for index, raw in enumerate(rows):
        subject = f"row:{index}"
        if not isinstance(raw, Mapping):
            debts.append(
                {
                    "code": "FINDING_FACT_MALFORMED",
                    "subject": subject,
                    "detail": "finding fact is not an object",
                }
            )
            continue
        original_finding_id = str(raw.get("finding_id") or "").strip().upper()
        finding_id = original_finding_id
        duplicate_identity = raw_id_counts.get(original_finding_id, 0) > 1
        if duplicate_identity:
            finding_id = "UNMEASURABLE-" + hashlib.sha256(
                canonical_json_bytes(
                    {
                        "original_finding_id": original_finding_id,
                        "source_binding_sha256": raw.get("source_binding_sha256"),
                        "row_index": index,
                    }
                )
            ).hexdigest()[:20].upper()
        mechanism = str(raw.get("mechanism_class") or "").strip().upper()
        preconditions, precondition_issue = _canonical_tokens(
            raw.get("precondition_classes")
        )
        binding = str(raw.get("source_binding_sha256") or "").strip().lower()
        mechanism_origin = str(raw.get("mechanism_origin") or "").strip().upper()
        extraction_status = str(raw.get("extraction_status") or "").strip().upper()
        upstream_issues_raw = raw.get("fact_issues", [])
        issues: list[str] = []
        if not isinstance(upstream_issues_raw, list):
            issues.append("fact_issues is not an array")
            upstream_issues: list[str] = []
        else:
            upstream_issues = sorted(
                {
                    str(value).strip()
                    for value in upstream_issues_raw
                    if str(value).strip()
                }
            )
            issues.extend(upstream_issues)
        if not _ID_RE.fullmatch(original_finding_id):
            issues.append("finding_id is missing or malformed")
        if duplicate_identity:
            issues.append(
                f"finding_id is duplicated; occurrence retained as {finding_id}"
            )
        if not _TOKEN_RE.fullmatch(mechanism):
            issues.append("mechanism_class is missing or malformed")
        if precondition_issue:
            issues.append(precondition_issue)
        if not _SHA_RE.fullmatch(binding):
            issues.append("source_binding_sha256 is missing or malformed")
        fact = {
            "finding_id": finding_id,
            "mechanism_class": mechanism,
            "precondition_classes": list(preconditions),
            "source_binding_sha256": binding,
            "mechanism_origin": mechanism_origin,
            "extraction_status": extraction_status,
            "exact_match_eligible": (
                mechanism_origin == "EXPLICIT_TYPED_FIELDS"
                and extraction_status == "EXPLICIT_BOUND"
                and not duplicate_identity
                and not issues
            ),
            "fact_issues": sorted(set(issues)),
        }
        if finding_id and finding_id not in findings:
            findings[finding_id] = fact
        for issue in issues:
            debts.append(
                {
                    "code": "FINDING_FACT_MALFORMED",
                    "subject": original_finding_id or subject,
                    "detail": issue,
                }
            )
    provider_debts = artifact.get("debts")
    if provider_debts is not None:
        if not isinstance(provider_debts, list):
            debts.append(
                {
                    "code": "FINDING_FACT_PROVIDER_DEBT_INVALID",
                    "subject": "*",
                    "detail": "provider debts is not an array",
                }
            )
        else:
            for index, raw in enumerate(provider_debts):
                if not isinstance(raw, Mapping):
                    debts.append(
                        {
                            "code": "FINDING_FACT_PROVIDER_DEBT_INVALID",
                            "subject": f"row:{index}",
                            "detail": "provider debt is not an object",
                        }
                    )
                    continue
                code = str(raw.get("code") or "").strip().upper()
                subject = str(raw.get("subject") or "*").strip()
                detail = str(raw.get("detail") or "").strip()
                if (
                    not _TOKEN_RE.fullmatch(code)
                    or not subject
                    or len(subject.encode("utf-8")) > 128
                    or _CONTROL_RE.search(subject)
                    or not detail
                    or len(detail.encode("utf-8")) > 2_000
                    or _CONTROL_RE.search(detail)
                ):
                    debts.append(
                        {
                            "code": "FINDING_FACT_PROVIDER_DEBT_INVALID",
                            "subject": f"row:{index}",
                            "detail": "provider debt fields are malformed",
                        }
                    )
                    continue
                debts.append(
                    {
                        "code": "FINDING_FACT_PROVIDER_" + code,
                        "subject": subject,
                        "detail": detail,
                    }
                )
    return findings, debts


def normalize_precedent_proposal_transport(
    markdown: str,
    finding_facts: Mapping[str, Any],
    *,
    failure_detail: str = "",
) -> dict[str, Any]:
    """Normalize model transport into a complete, decision-neutral envelope.

    Invalid transport and missing finding rows become deterministic UNAVAILABLE
    proposals plus content-bound debt.  This preserves the denominator without
    manufacturing source support or a numeric confidence floor.
    """

    run_id = str(finding_facts.get("run_id") or "")
    snapshot_digest = str(finding_facts.get("snapshot_digest") or "")
    findings, finding_debts = _finding_denominator(finding_facts)
    transport_debts: list[dict[str, str]] = list(finding_debts)
    try:
        extracted = extract_proposal_artifact(markdown)
    except (TypeError, ValueError) as exc:
        extracted = {
            "schema_version": PROPOSAL_SCHEMA,
            "run_id": run_id,
            "snapshot_digest": snapshot_digest,
            "proposals": [],
        }
        detail = str(failure_detail or exc).strip()
        detail = _CONTROL_RE.sub(" ", detail)[:2_000] or "proposal transport failed"
        transport_debts.append(
            {
                "code": "PROPOSAL_TRANSPORT_FAILED",
                "subject": "*",
                "detail": detail,
            }
        )
    else:
        extracted = dict(extracted)

    envelope_issues: list[str] = []
    if extracted.get("schema_version") != PROPOSAL_SCHEMA:
        envelope_issues.append("proposal schema does not match the current contract")
    if str(extracted.get("run_id") or "") != run_id:
        envelope_issues.append("proposal run binding is stale or mismatched")
    if str(extracted.get("snapshot_digest") or "") != snapshot_digest:
        envelope_issues.append("proposal snapshot binding is stale or mismatched")
    unexpected_envelope = sorted(
        set(extracted) - {"schema_version", "run_id", "snapshot_digest", "proposals"}
    )
    if unexpected_envelope:
        envelope_issues.append(
            "proposal envelope has unexpected fields: "
            + ", ".join(unexpected_envelope)
        )
    for issue in envelope_issues:
        transport_debts.append(
            {
                "code": "PROPOSAL_TRANSPORT_BINDING_INVALID",
                "subject": "*",
                "detail": issue,
            }
        )

    rows = extracted.get("proposals")
    if envelope_issues:
        rows = []
    elif not isinstance(rows, list):
        rows = []
        transport_debts.append(
            {
                "code": "PROPOSAL_TRANSPORT_FAILED",
                "subject": "*",
                "detail": "proposal denominator is not an array",
            }
        )
    represented = {
        str(raw.get("finding_id") or "").strip().upper()
        for raw in rows
        if isinstance(raw, Mapping)
    }
    normalized_rows = list(rows)
    used_ids = {
        str(raw.get("proposal_id") or "").strip().upper()
        for raw in rows
        if isinstance(raw, Mapping)
    }
    for index, finding_id in enumerate(sorted(findings), 1):
        if finding_id in represented:
            continue
        fact = findings[finding_id]
        proposal_id = f"PR-FALLBACK-{index}"
        while proposal_id in used_ids:
            proposal_id += "X"
        used_ids.add(proposal_id)
        source_ref = f"unavailable:{finding_id.lower()}"
        mechanism = str(fact.get("mechanism_class") or "")
        preconditions = list(fact.get("precondition_classes") or [])
        if not _TOKEN_RE.fullmatch(mechanism) or not preconditions:
            mechanism = "UNAVAILABLE_RESEARCH"
            preconditions = ["RESEARCH_NOT_AVAILABLE"]
        source_sha = hashlib.sha256(
            canonical_json_bytes(
                {
                    "finding_id": finding_id,
                    "source_ref": source_ref,
                    "status": "UNAVAILABLE",
                    "snapshot_digest": snapshot_digest,
                }
            )
        ).hexdigest()
        normalized_rows.append(
            {
                "proposal_id": proposal_id,
                "finding_id": finding_id,
                "source_kind": "UNAVAILABLE",
                "source_ref": source_ref,
                "source_sha256": source_sha,
                "availability": "TOOL_ERROR",
                "relation": "UNKNOWN",
                "mechanism_class": mechanism,
                "precondition_classes": preconditions,
                "report_context": (
                    "External precedent research was unavailable; "
                    "this row has no decision authority."
                ),
            }
        )
        transport_debts.append(
            {
                "code": "PRECEDENT_PROPOSAL_MISSING",
                "subject": finding_id,
                "detail": "no valid transport row was supplied; deterministic UNSCORED fallback added",
            }
        )
    extracted["schema_version"] = PROPOSAL_SCHEMA
    extracted["run_id"] = run_id
    extracted["snapshot_digest"] = snapshot_digest
    extracted["proposals"] = normalized_rows
    extracted["transport_debts"] = sorted(
        transport_debts,
        key=lambda row: (row["code"], row["subject"], row["detail"]),
    )
    return extracted


def _proposal_transport_from_disk(scratchpad: Path) -> tuple[str, str]:
    """Read the bounded model transport once, preserving failure as data."""

    path = Path(scratchpad) / "rag_validation.md"
    try:
        raw = read_bounded_regular_bytes(path, _MAX_PROPOSAL_TRANSPORT_BYTES)
    except OSError as exc:
        return "", f"rag_validation.md is unavailable: {exc}"
    except ValueError as exc:
        return "", str(exc)
    try:
        return raw.decode("utf-8", errors="strict"), ""
    except UnicodeDecodeError as exc:
        return "", f"rag_validation.md is not strict UTF-8: {exc}"


def write_precedent_proposal_artifact(
    scratchpad: Path,
    finding_facts: Mapping[str, Any],
) -> dict[str, Any]:
    """Normalize model Markdown into a complete DRIVER-owned JSON envelope."""

    markdown, failure = _proposal_transport_from_disk(Path(scratchpad))
    payload = normalize_precedent_proposal_transport(
        markdown,
        finding_facts,
        failure_detail=failure,
    )
    _atomic_bytes(Path(scratchpad) / PROPOSALS_NAME, canonical_json_bytes(payload))
    return payload


def validate_precedent_proposal_artifact(
    scratchpad: Path,
    finding_facts: Mapping[str, Any],
) -> list[str]:
    """Re-derive the normalized proposal bytes from the current exact inputs."""

    root = Path(scratchpad)
    markdown, failure = _proposal_transport_from_disk(root)
    expected = normalize_precedent_proposal_transport(
        markdown,
        finding_facts,
        failure_detail=failure,
    )
    try:
        actual = read_bounded_regular_bytes(
            root / PROPOSALS_NAME, _MAX_AUTHORITY_BYTES
        )
    except (OSError, ValueError) as exc:
        return [f"normalized precedent proposal artifact is unavailable: {exc}"]
    if actual != canonical_json_bytes(expected):
        return ["normalized precedent proposal artifact is stale or non-canonical"]
    return []


def _proposal_rows(
    artifact: Mapping[str, Any],
    findings: Mapping[str, Mapping[str, Any]],
) -> tuple[dict[str, list[dict[str, Any]]], list[dict[str, str]], set[str]]:
    rows = artifact.get("proposals")
    debts: list[dict[str, str]] = []
    by_finding: dict[str, list[dict[str, Any]]] = {
        finding_id: [] for finding_id in findings
    }
    unmeasurable: set[str] = set()
    if not isinstance(rows, list):
        return by_finding, [
            {
                "code": "PROPOSAL_DENOMINATOR_MALFORMED",
                "subject": "*",
                "detail": "proposals must be an array",
            }
        ], set(findings)
    if len(rows) > _MAX_PROPOSALS:
        return by_finding, [
            {
                "code": "PROPOSAL_DENOMINATOR_OVERSIZED",
                "subject": "*",
                "detail": f"proposal count exceeds {_MAX_PROPOSALS}",
            }
        ], set(findings)

    seen_proposal_ids: dict[str, str] = {}
    seen_source_identities: set[tuple[str, str, str]] = set()
    proposal_count_by_finding: dict[str, int] = {
        finding_id: 0 for finding_id in findings
    }
    for index, raw in enumerate(rows):
        row_subject = f"row:{index}"
        if not isinstance(raw, Mapping):
            debts.append(
                {
                    "code": "PRECEDENT_PROPOSAL_MALFORMED",
                    "subject": row_subject,
                    "detail": "proposal is not an object",
                }
            )
            continue
        proposal_id = str(raw.get("proposal_id") or "").strip().upper()
        finding_id = str(raw.get("finding_id") or "").strip().upper()
        source_kind = str(raw.get("source_kind") or "").strip().upper()
        source_ref = str(raw.get("source_ref") or "").strip()
        source_sha = str(raw.get("source_sha256") or "").strip().lower()
        availability = str(raw.get("availability") or "").strip().upper()
        relation = str(raw.get("relation") or "").strip().upper()
        mechanism = str(raw.get("mechanism_class") or "").strip().upper()
        preconditions, precondition_issue = _canonical_tokens(
            raw.get("precondition_classes")
        )
        report_context = str(raw.get("report_context") or "").strip()
        issues: list[str] = []
        forbidden = sorted(set(raw) & _FORBIDDEN_PROPOSAL_FIELDS)
        unexpected = sorted(set(raw) - _PROPOSAL_FIELDS - _FORBIDDEN_PROPOSAL_FIELDS)
        for field in forbidden:
            debts.append(
                {
                    "code": "PRECEDENT_PROPOSAL_FORBIDDEN_FIELD",
                    "subject": finding_id or proposal_id or row_subject,
                    "detail": f"proposal contains decision field {field!r}",
                }
            )
        if forbidden:
            issues.append("proposal contains decision-authority fields")
        if unexpected:
            issues.append(
                "proposal contains unexpected fields: " + ", ".join(unexpected)
            )
        for field in _PROPOSAL_FIELDS - {"precondition_classes"}:
            if not isinstance(raw.get(field), str):
                issues.append(f"{field} must be a string")
        if not _ID_RE.fullmatch(proposal_id):
            issues.append("proposal_id is missing or malformed")
        if finding_id not in findings:
            issues.append("finding_id is outside the typed finding denominator")
        if source_kind not in _SOURCE_KINDS:
            issues.append("source_kind is unsupported")
        if (
            not source_ref
            or len(source_ref.encode("utf-8")) > 512
            or _CONTROL_RE.search(source_ref)
            or "|" in source_ref
        ):
            issues.append("source_ref is missing or oversized")
        if not _SHA_RE.fullmatch(source_sha):
            issues.append("source_sha256 is missing or malformed")
        if availability not in _AVAILABILITY:
            issues.append("availability is unsupported")
        if relation not in _RELATIONS:
            issues.append("relation is unsupported")
        if not _TOKEN_RE.fullmatch(mechanism):
            issues.append("mechanism_class is missing or malformed")
        if precondition_issue:
            issues.append(precondition_issue)
        if len(report_context.encode("utf-8")) > 2_000:
            issues.append("report_context exceeds the bounded size")
        if _CONTROL_RE.search(report_context):
            issues.append("report_context contains control characters")
        if finding_id in proposal_count_by_finding:
            proposal_count_by_finding[finding_id] += 1
            if proposal_count_by_finding[finding_id] > _MAX_PROPOSALS_PER_FINDING:
                issues.append(
                    "finding exceeds the bounded proposal cardinality"
                )
        if proposal_id in seen_proposal_ids:
            issues.append("proposal_id is duplicated")
            prior_finding = seen_proposal_ids[proposal_id]
            if prior_finding in findings:
                unmeasurable.add(prior_finding)
        elif proposal_id:
            seen_proposal_ids[proposal_id] = finding_id
        source_identity = (finding_id, source_ref, source_sha)
        if finding_id in findings and source_ref and source_sha:
            if source_identity in seen_source_identities:
                issues.append("finding/source identity is duplicated")
                unmeasurable.add(finding_id)
            else:
                seen_source_identities.add(source_identity)
        if issues:
            if finding_id in findings:
                unmeasurable.add(finding_id)
            for issue in issues:
                debts.append(
                    {
                        "code": "PRECEDENT_PROPOSAL_MALFORMED",
                        "subject": finding_id or proposal_id or row_subject,
                        "detail": issue,
                    }
                )
            continue
        by_finding[finding_id].append(
            {
                "proposal_id": proposal_id,
                "finding_id": finding_id,
                "source_kind": source_kind,
                "source_ref": source_ref,
                "source_sha256": source_sha,
                "availability": availability,
                "relation": relation,
                "mechanism_class": mechanism,
                "precondition_classes": list(preconditions),
                "report_context": report_context,
            }
        )
    for values in by_finding.values():
        values.sort(key=lambda row: row["proposal_id"])
    for finding_id in sorted(findings):
        if by_finding[finding_id] or finding_id in unmeasurable:
            continue
        debts.append(
            {
                "code": "PRECEDENT_PROPOSAL_MISSING",
                "subject": finding_id,
                "detail": "no valid proposal row represents this finding; it remains UNSCORED",
            }
        )
    return by_finding, debts, unmeasurable


def _equivalence_graph(
    artifact: Mapping[str, Any] | None,
    findings: Mapping[str, Mapping[str, Any]],
    *,
    run_id: str,
    snapshot_digest: str,
) -> tuple[dict[str, set[str]], list[dict[str, str]]]:
    graph = {finding_id: set() for finding_id in findings}
    if artifact is None:
        return graph, []
    debts: list[dict[str, str]] = []
    envelope = _envelope_issues(
        artifact,
        schema=EQUIVALENCE_SCHEMA,
        run_id=run_id,
        snapshot_digest=snapshot_digest,
        label="typed equivalence",
    )
    for issue in envelope:
        debts.append(
            {"code": "EQUIVALENCE_ARTIFACT_INVALID", "subject": "*", "detail": issue}
        )
    if envelope:
        return graph, debts
    rows = artifact.get("equivalences")
    if not isinstance(rows, list):
        return graph, [
            {
                "code": "EQUIVALENCE_ARTIFACT_INVALID",
                "subject": "*",
                "detail": "equivalences must be an array",
            }
        ]
    seen: set[tuple[str, str]] = set()
    for index, raw in enumerate(rows):
        issues: list[str] = []
        if not isinstance(raw, Mapping):
            issues.append("equivalence row is not an object")
            left = right = ""
        else:
            left = str(raw.get("left_finding_id") or "").strip().upper()
            right = str(raw.get("right_finding_id") or "").strip().upper()
            mechanism = str(raw.get("mechanism_class") or "").strip().upper()
            preconditions, precondition_issue = _canonical_tokens(
                raw.get("precondition_classes")
            )
            evidence = str(raw.get("evidence_sha256") or "").strip().lower()
            if left not in findings or right not in findings or left == right:
                issues.append("equivalence endpoints are invalid")
            if raw.get("relation") != "MECHANISM_PRECONDITION_EQUIVALENT":
                issues.append("equivalence relation is not exact")
            if raw.get("status") != "CURRENT":
                issues.append("equivalence record is not current")
            if not _SHA_RE.fullmatch(evidence):
                issues.append("equivalence evidence digest is malformed")
            if precondition_issue:
                issues.append(precondition_issue)
            if left in findings and right in findings:
                left_fact = findings[left]
                right_fact = findings[right]
                expected_preconditions = tuple(left_fact["precondition_classes"])
                if (
                    left_fact["fact_issues"]
                    or right_fact["fact_issues"]
                    or not left_fact.get("exact_match_eligible")
                    or not right_fact.get("exact_match_eligible")
                    or mechanism != left_fact["mechanism_class"]
                    or mechanism != right_fact["mechanism_class"]
                    or tuple(preconditions) != expected_preconditions
                    or tuple(preconditions)
                    != tuple(right_fact["precondition_classes"])
                ):
                    issues.append(
                        "equivalence does not match both typed finding facts"
                    )
            pair = tuple(sorted((left, right)))
            if pair in seen:
                issues.append("equivalence pair is duplicated")
            seen.add(pair)
        if issues:
            for issue in issues:
                debts.append(
                    {
                        "code": "TYPED_EQUIVALENCE_REJECTED",
                        "subject": f"{left or index}:{right or index}",
                        "detail": issue,
                    }
                )
            continue
        graph[left].add(right)
        graph[right].add(left)
    return graph, debts


def source_evidence_row_digest(row: Mapping[str, Any]) -> str:
    body = {
        key: value for key, value in row.items() if key != "evidence_digest"
    }
    return _digest(body)


def source_evidence_authority_digest(artifact: Mapping[str, Any]) -> str:
    body = {
        key: value for key, value in artifact.items() if key != "authority_digest"
    }
    return _digest(body)


def build_precedent_source_evidence_artifact(
    *,
    run_id: str,
    snapshot_digest: str,
    sources: Iterable[Mapping[str, Any]],
) -> dict[str, Any]:
    """Build a canonical receipt from driver-captured source-byte records.

    This factory supplies no ownership by itself. The live PhaseIO contract
    must restrict its caller/output writer to the neutral driver work unit.
    """

    rows: list[dict[str, Any]] = []
    for raw in sources:
        row = dict(raw)
        row.pop("evidence_digest", None)
        row["evidence_digest"] = source_evidence_row_digest(row)
        rows.append(row)
    rows.sort(
        key=lambda row: (
            str(row.get("source_ref") or ""),
            str(row.get("source_sha256") or ""),
            str(row.get("capture_artifact") or ""),
        )
    )
    artifact: dict[str, Any] = {
        "schema_version": SOURCE_EVIDENCE_SCHEMA,
        "run_id": str(run_id or ""),
        "snapshot_digest": str(snapshot_digest or ""),
        "assurance": SOURCE_EVIDENCE_ASSURANCE,
        "sources": rows,
    }
    artifact["authority_digest"] = source_evidence_authority_digest(artifact)
    accepted, debts = _source_evidence_index(
        artifact,
        run_id=str(run_id or ""),
        snapshot_digest=str(snapshot_digest or ""),
    )
    if debts or len(accepted) != len(rows):
        detail = "; ".join(
            f"{debt['code']}:{debt['subject']}:{debt['detail']}" for debt in debts
        )
        raise ValueError("source evidence records are invalid: " + detail)
    return artifact


def _source_evidence_index(
    artifact: Mapping[str, Any] | None,
    *,
    run_id: str,
    snapshot_digest: str,
) -> tuple[set[tuple[str, str, str]], list[dict[str, str]]]:
    """Validate neutral source-capture receipts without trusting proposal prose.

    PhaseIO must independently establish that the live driver owns this
    artifact.  This pure layer validates its content-addressed shape and exact
    run/snapshot binding; it never treats a proposal itself as a receipt.
    """

    if artifact is None:
        return set(), [
            {
                "code": "SOURCE_EVIDENCE_UNAVAILABLE",
                "subject": "*",
                "detail": "no neutral driver source-evidence receipt is available",
            }
        ]
    debts: list[dict[str, str]] = []
    for issue in _envelope_issues(
        artifact,
        schema=SOURCE_EVIDENCE_SCHEMA,
        run_id=run_id,
        snapshot_digest=snapshot_digest,
        label="source evidence",
    ):
        debts.append(
            {"code": "SOURCE_EVIDENCE_INVALID", "subject": "*", "detail": issue}
        )
    expected_envelope_fields = {
        "schema_version",
        "run_id",
        "snapshot_digest",
        "assurance",
        "sources",
        "authority_digest",
    }
    if set(artifact) != expected_envelope_fields:
        debts.append(
            {
                "code": "SOURCE_EVIDENCE_INVALID",
                "subject": "*",
                "detail": "source evidence envelope fields are not exact",
            }
        )
    if artifact.get("assurance") != SOURCE_EVIDENCE_ASSURANCE:
        debts.append(
            {
                "code": "SOURCE_EVIDENCE_INVALID",
                "subject": "*",
                "detail": "source evidence assurance is not neutral driver capture",
            }
        )
    stored_authority = str(artifact.get("authority_digest") or "").lower()
    if (
        not _SHA_RE.fullmatch(stored_authority)
        or source_evidence_authority_digest(artifact) != stored_authority
    ):
        debts.append(
            {
                "code": "SOURCE_EVIDENCE_INVALID",
                "subject": "*",
                "detail": "source evidence authority digest mismatch",
            }
        )
    rows = artifact.get("sources")
    if not isinstance(rows, list):
        debts.append(
            {
                "code": "SOURCE_EVIDENCE_INVALID",
                "subject": "*",
                "detail": "sources must be an array",
            }
        )
        return set(), debts
    if len(rows) > _MAX_PROPOSALS:
        debts.append(
            {
                "code": "SOURCE_EVIDENCE_INVALID",
                "subject": "*",
                "detail": "source evidence cardinality exceeds the bound",
            }
        )
        return set(), debts

    accepted: set[tuple[str, str, str]] = set()
    duplicate_keys: set[tuple[str, str, str]] = set()
    expected_fields = {
        "source_ref",
        "source_sha256",
        "source_kind",
        "capture_artifact",
        "capture_artifact_sha256",
        "evidence_digest",
    }
    for index, raw in enumerate(rows):
        subject = f"row:{index}"
        issues: list[str] = []
        if not isinstance(raw, Mapping):
            debts.append(
                {
                    "code": "SOURCE_EVIDENCE_ROW_INVALID",
                    "subject": subject,
                    "detail": "source evidence row is not an object",
                }
            )
            continue
        if set(raw) != expected_fields:
            issues.append("source evidence row fields are not exact")
        for field in expected_fields:
            if not isinstance(raw.get(field), str):
                issues.append(f"source evidence {field} must be a string")
        source_ref = str(raw.get("source_ref") or "").strip()
        source_sha = str(raw.get("source_sha256") or "").strip().lower()
        source_kind = str(raw.get("source_kind") or "").strip().upper()
        capture_artifact = str(raw.get("capture_artifact") or "").strip()
        capture_sha = str(raw.get("capture_artifact_sha256") or "").strip().lower()
        evidence_digest = str(raw.get("evidence_digest") or "").strip().lower()
        if (
            not source_ref
            or len(source_ref.encode("utf-8")) > 512
            or _CONTROL_RE.search(source_ref)
            or "|" in source_ref
        ):
            issues.append("source_ref is malformed")
        if not _SHA_RE.fullmatch(source_sha):
            issues.append("source_sha256 is malformed")
        if source_kind != "PRIMARY_PRECEDENT":
            issues.append("only primary precedent can receive exact source authority")
        if _safe_capture_path(capture_artifact) is None:
            issues.append("capture_artifact is malformed")
        if not _SHA_RE.fullmatch(capture_sha):
            issues.append("capture_artifact_sha256 is malformed")
        elif _SHA_RE.fullmatch(source_sha) and capture_sha != source_sha:
            issues.append("captured source bytes do not match source_sha256")
        if (
            not _SHA_RE.fullmatch(evidence_digest)
            or source_evidence_row_digest(raw) != evidence_digest
        ):
            issues.append("source evidence row digest mismatch")
        key = (source_ref, source_sha, source_kind)
        if key in accepted:
            issues.append("source evidence identity is duplicated")
            duplicate_keys.add(key)
        if issues:
            for issue in issues:
                debts.append(
                    {
                        "code": "SOURCE_EVIDENCE_ROW_INVALID",
                        "subject": source_ref or subject,
                        "detail": issue,
                    }
                )
            continue
        accepted.add(key)
    accepted.difference_update(duplicate_keys)
    if any(debt["code"] == "SOURCE_EVIDENCE_INVALID" for debt in debts):
        return set(), debts
    return accepted, debts


def validate_precedent_source_evidence_artifact(
    scratchpad: Path,
    artifact: Mapping[str, Any],
    *,
    run_id: str,
    snapshot_digest: str,
) -> list[str]:
    """Validate neutral receipt rows against the actual bounded capture bytes."""

    _accepted, debts = _source_evidence_index(
        artifact,
        run_id=run_id,
        snapshot_digest=snapshot_digest,
    )
    issues = [
        f"{row['code']}:{row['subject']}:{row['detail']}" for row in debts
    ]
    rows = artifact.get("sources") if isinstance(artifact, Mapping) else None
    if not isinstance(rows, list):
        return sorted(set(issues))
    total = 0
    root = Path(scratchpad).resolve(strict=True)
    for index, raw in enumerate(rows):
        if not isinstance(raw, Mapping):
            continue
        relative = str(raw.get("capture_artifact") or "")
        posix = _safe_capture_path(relative)
        if posix is None:
            issues.append(f"row:{index}: capture artifact path is not safe-relative")
            continue
        path = root.joinpath(*posix.parts)
        try:
            resolved_parent = path.parent.resolve(strict=True)
            resolved_parent.relative_to(root)
            captured = read_bounded_regular_bytes(path, _MAX_CAPTURE_BYTES)
        except (OSError, ValueError) as exc:
            issues.append(f"row:{index}: capture bytes unavailable: {exc}")
            continue
        total += len(captured)
        if total > _MAX_CAPTURE_TOTAL_BYTES:
            issues.append("source capture total exceeds the bounded byte budget")
            break
        digest = hashlib.sha256(captured).hexdigest()
        if str(raw.get("capture_artifact_sha256") or "").lower() != digest:
            issues.append(f"row:{index}: capture artifact digest mismatch")
        if str(raw.get("source_sha256") or "").lower() != digest:
            issues.append(f"row:{index}: source digest is not bound to capture bytes")
    return sorted(set(issues))


def _base_row(finding_id: str) -> dict[str, Any]:
    return {
        "finding_id": finding_id,
        "match_status": "UNSCORED",
        "precedent_strength": "NONE",
        "investigation_priority": "UNCHANGED",
        "report_context_eligible": False,
        "matching_proposal_ids": [],
        "context_source_refs": [],
        "context_sources": [],
        "propagated_from_finding_id": "",
        # These immutable zero/false fields are the core separation contract.
        "mechanism_confidence_delta": 0.0,
        "may_clear_or_demote": False,
        "may_force_contested": False,
        "may_change_severity": False,
        "may_reduce_investigation_depth": False,
    }


def _classify_direct(
    finding: Mapping[str, Any],
    proposals: Iterable[Mapping[str, Any]],
    source_evidence: set[tuple[str, str, str]],
) -> dict[str, Any]:
    row = _base_row(str(finding["finding_id"]))
    values = list(proposals)
    if finding.get("fact_issues"):
        row["match_status"] = "UNMEASURABLE"
        return row
    if not values:
        return row
    available = [value for value in values if value["availability"] == "AVAILABLE"]
    if not available:
        availability = sorted({value["availability"] for value in values})[0]
        row["match_status"] = f"SOURCE_{availability}"
        return row
    if not finding.get("exact_match_eligible"):
        return row

    target_mechanism = finding["mechanism_class"]
    target_preconditions = tuple(finding["precondition_classes"])
    proposed_exact = [
        value
        for value in available
        if value["source_kind"] == "PRIMARY_PRECEDENT"
        and value["relation"] == "SUPPORTING"
        and value["mechanism_class"] == target_mechanism
        and tuple(value["precondition_classes"]) == target_preconditions
    ]
    exact = [
        value
        for value in proposed_exact
        if (
            str(value["source_ref"]),
            str(value["source_sha256"]),
            str(value["source_kind"]),
        )
        in source_evidence
    ]
    unbound_exact = [value for value in proposed_exact if value not in exact]
    refuting = [value for value in available if value["relation"] == "REFUTING"]
    generic = [
        value
        for value in available
        if value["source_kind"] in {"GENERIC_METHODOLOGY", "LITERATURE_CONTEXT"}
    ]
    def context_record(value: Mapping[str, Any]) -> dict[str, Any]:
        key = (
            str(value["source_ref"]),
            str(value["source_sha256"]),
            str(value["source_kind"]),
        )
        return {
            "proposal_id": str(value["proposal_id"]),
            "source_ref": str(value["source_ref"]),
            "source_sha256": str(value["source_sha256"]),
            "source_kind": str(value["source_kind"]),
            "availability": str(value["availability"]),
            "relation": str(value["relation"]),
            "source_evidence_bound": key in source_evidence,
        }

    if exact:
        selected = sorted(exact, key=lambda value: str(value["proposal_id"]))
        row.update(
            {
                "match_status": "EXACT_PRIMARY_PRECEDENT",
                "precedent_strength": "EXACT",
                "investigation_priority": "ELEVATED",
                "report_context_eligible": True,
                "matching_proposal_ids": sorted(
                    {str(value["proposal_id"]) for value in exact}
                ),
                "context_source_refs": sorted(
                    {str(value["source_ref"]) for value in exact}
                ),
                "context_sources": [context_record(value) for value in selected],
            }
        )
    elif unbound_exact:
        selected = sorted(
            unbound_exact, key=lambda value: str(value["proposal_id"])
        )
        row.update(
            {
                "match_status": "SOURCE_UNBOUND_CONTEXT_ONLY",
                "context_source_refs": sorted(
                    {str(value["source_ref"]) for value in unbound_exact}
                ),
                "context_sources": [context_record(value) for value in selected],
            }
        )
    elif refuting:
        selected = sorted(refuting, key=lambda value: str(value["proposal_id"]))
        bound = [
            value
            for value in selected
            if context_record(value)["source_evidence_bound"]
        ]
        row["match_status"] = (
            "REFUTING_CONTEXT_ONLY" if bound else "SOURCE_UNBOUND_CONTEXT_ONLY"
        )
        row["report_context_eligible"] = bool(bound)
        row["context_source_refs"] = sorted(
            {str(value["source_ref"]) for value in selected}
        )
        row["context_sources"] = [context_record(value) for value in selected]
    elif generic:
        row["match_status"] = "GENERIC_CONTEXT_ONLY"
        selected = sorted(generic, key=lambda value: str(value["proposal_id"]))
        row["context_source_refs"] = sorted(
            {str(value["source_ref"]) for value in selected}
        )
        row["context_sources"] = [context_record(value) for value in selected]
    else:
        row["match_status"] = "NO_EXACT_MATCH"
        selected = sorted(available, key=lambda value: str(value["proposal_id"]))
        row["context_source_refs"] = sorted(
            {str(value["source_ref"]) for value in selected}
        )
        row["context_sources"] = [context_record(value) for value in selected]
    return row


def _components(graph: Mapping[str, set[str]]) -> list[list[str]]:
    result: list[list[str]] = []
    remaining = set(graph)
    while remaining:
        seed = min(remaining)
        stack = [seed]
        component: set[str] = set()
        while stack:
            current = stack.pop()
            if current in component:
                continue
            component.add(current)
            stack.extend(sorted(graph.get(current, set()), reverse=True))
        remaining.difference_update(component)
        result.append(sorted(component))
    return result


def reconcile_precedent_evidence(
    finding_facts: Mapping[str, Any],
    proposal_artifact: Mapping[str, Any],
    equivalence_artifact: Mapping[str, Any] | None = None,
    source_evidence_artifact: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Build deterministic precedent context with no finding-decision power."""

    run_id = str(finding_facts.get("run_id") or "")
    snapshot_digest = str(finding_facts.get("snapshot_digest") or "")
    debts: list[dict[str, str]] = []
    for issue in _envelope_issues(
        finding_facts,
        schema=FINDING_FACTS_SCHEMA,
        run_id=run_id,
        snapshot_digest=snapshot_digest,
        label="finding facts",
    ):
        debts.append(
            {"code": "FINDING_FACT_ARTIFACT_INVALID", "subject": "*", "detail": issue}
        )
    if not run_id:
        debts.append(
            {"code": "FINDING_FACT_ARTIFACT_INVALID", "subject": "*", "detail": "run_id is empty"}
        )
    if not _SHA_RE.fullmatch(snapshot_digest):
        debts.append(
            {
                "code": "FINDING_FACT_ARTIFACT_INVALID",
                "subject": "*",
                "detail": "snapshot_digest is malformed",
            }
        )

    findings, finding_debts = _finding_denominator(finding_facts)
    debts.extend(finding_debts)
    proposal_envelope = _envelope_issues(
        proposal_artifact,
        schema=PROPOSAL_SCHEMA,
        run_id=run_id,
        snapshot_digest=snapshot_digest,
        label="precedent proposal",
    )
    unexpected_proposal_envelope = (
        sorted(
            set(proposal_artifact)
            - {
                "schema_version",
                "run_id",
                "snapshot_digest",
                "proposals",
                "transport_debts",
            }
        )
        if isinstance(proposal_artifact, Mapping)
        else []
    )
    if unexpected_proposal_envelope:
        proposal_envelope.append(
            "precedent proposal envelope has unexpected fields: "
            + ", ".join(unexpected_proposal_envelope)
        )
    for issue in proposal_envelope:
        debts.append(
            {"code": "PROPOSAL_ARTIFACT_INVALID", "subject": "*", "detail": issue}
        )
    if proposal_envelope:
        proposals = {finding_id: [] for finding_id in findings}
        unmeasurable = set(findings)
    else:
        proposals, proposal_debts, unmeasurable = _proposal_rows(
            proposal_artifact, findings
        )
        debts.extend(proposal_debts)
    transport_debts = (
        proposal_artifact.get("transport_debts")
        if isinstance(proposal_artifact, Mapping)
        else None
    )
    if transport_debts is not None:
        if not isinstance(transport_debts, list):
            debts.append(
                {
                    "code": "PROPOSAL_TRANSPORT_DEBT_INVALID",
                    "subject": "*",
                    "detail": "transport_debts must be an array",
                }
            )
        else:
            for index, raw in enumerate(transport_debts):
                if not isinstance(raw, Mapping):
                    debts.append(
                        {
                            "code": "PROPOSAL_TRANSPORT_DEBT_INVALID",
                            "subject": f"row:{index}",
                            "detail": "transport debt is not an object",
                        }
                    )
                    continue
                code = str(raw.get("code") or "").strip().upper()
                subject = str(raw.get("subject") or "*").strip().upper()
                detail = str(raw.get("detail") or "").strip()
                if (
                    not _TOKEN_RE.fullmatch(code)
                    or not subject
                    or len(subject.encode("utf-8")) > 128
                    or _CONTROL_RE.search(subject)
                    or not detail
                    or len(detail.encode("utf-8")) > 2_000
                    or _CONTROL_RE.search(detail)
                ):
                    debts.append(
                        {
                            "code": "PROPOSAL_TRANSPORT_DEBT_INVALID",
                            "subject": f"row:{index}",
                            "detail": "transport debt fields are malformed",
                        }
                    )
                    continue
                debts.append({"code": code, "subject": subject, "detail": detail})

    graph, equivalence_debts = _equivalence_graph(
        equivalence_artifact,
        findings,
        run_id=run_id,
        snapshot_digest=snapshot_digest,
    )
    debts.extend(equivalence_debts)
    needs_source_evidence = any(
        value.get("source_kind") == "PRIMARY_PRECEDENT"
        and value.get("availability") == "AVAILABLE"
        for values in proposals.values()
        for value in values
    )
    if needs_source_evidence:
        source_evidence, source_evidence_debts = _source_evidence_index(
            source_evidence_artifact,
            run_id=run_id,
            snapshot_digest=snapshot_digest,
        )
    else:
        source_evidence, source_evidence_debts = set(), []
    debts.extend(source_evidence_debts)

    rows = {
        finding_id: _classify_direct(
            fact, proposals.get(finding_id, []), source_evidence
        )
        for finding_id, fact in findings.items()
    }
    for finding_id in unmeasurable:
        if finding_id in rows:
            rows[finding_id] = _base_row(finding_id)
            rows[finding_id]["match_status"] = "UNMEASURABLE"

    # Propagation is deliberately second-pass and only through accepted exact
    # typed equivalence edges.  Similar titles, families, locations, and model
    # prose never enter this graph.
    for component in _components(graph):
        exact_sources = sorted(
            finding_id
            for finding_id in component
            if rows[finding_id]["match_status"] == "EXACT_PRIMARY_PRECEDENT"
        )
        if not exact_sources:
            continue
        source_id = exact_sources[0]
        source = rows[source_id]
        for finding_id in component:
            if finding_id == source_id or finding_id in unmeasurable:
                continue
            target = rows[finding_id]
            if target["precedent_strength"] == "EXACT":
                continue
            target.update(
                {
                    "match_status": "TYPED_EQUIVALENT_EXACT_PRECEDENT",
                    "precedent_strength": "EXACT",
                    "investigation_priority": "ELEVATED",
                    "report_context_eligible": True,
                    "matching_proposal_ids": list(
                        source["matching_proposal_ids"]
                    ),
                    "context_source_refs": list(source["context_source_refs"]),
                    "context_sources": list(source["context_sources"]),
                    "propagated_from_finding_id": source_id,
                }
            )

    ordered_rows = [rows[finding_id] for finding_id in sorted(rows)]
    payload: dict[str, Any] = {
        "schema_version": AUTHORITY_SCHEMA,
        "run_id": run_id,
        "snapshot_digest": snapshot_digest,
        "assurance": ASSURANCE,
        "policy": {
            "generic_literature_mechanism_confidence_delta": 0.0,
            "exact_precedent_requires_primary_source": True,
            "exact_precedent_requires_mechanism_identity": True,
            "exact_precedent_requires_precondition_identity": True,
            "family_propagation_requires_typed_equivalence": True,
            "precedent_may_change_disposition": False,
            "precedent_may_change_severity": False,
            "precedent_may_reduce_depth": False,
            "precedent_may_force_contested": False,
        },
        "input_digests": {
            "finding_facts": _digest(finding_facts),
            "proposal_artifact": _digest(proposal_artifact),
            "equivalence_artifact": (
                _digest(equivalence_artifact)
                if equivalence_artifact is not None
                else ""
            ),
            "source_evidence_artifact": (
                _digest(source_evidence_artifact)
                if source_evidence_artifact is not None
                else ""
            ),
        },
        "finding_count": len(ordered_rows),
        "finding_precedent": ordered_rows,
        "debts": sorted(
            debts,
            key=lambda row: (row["code"], row["subject"], row["detail"]),
        ),
    }
    payload["authority_digest"] = _digest(payload)
    return payload


def validate_precedent_evidence_authority(
    payload: Mapping[str, Any],
    finding_facts: Mapping[str, Any],
    proposal_artifact: Mapping[str, Any],
    equivalence_artifact: Mapping[str, Any] | None = None,
    source_evidence_artifact: Mapping[str, Any] | None = None,
) -> list[str]:
    issues: list[str] = []
    if not isinstance(payload, Mapping):
        return ["precedent evidence authority is not an object"]
    if payload.get("schema_version") != AUTHORITY_SCHEMA:
        issues.append("precedent evidence authority schema mismatch")
    stored = str(payload.get("authority_digest") or "")
    body = {key: value for key, value in payload.items() if key != "authority_digest"}
    if not _SHA_RE.fullmatch(stored) or _digest(body) != stored:
        issues.append("precedent evidence authority digest mismatch")
    expected = reconcile_precedent_evidence(
        finding_facts,
        proposal_artifact,
        equivalence_artifact,
        source_evidence_artifact,
    )
    if dict(payload) != expected:
        issues.append("precedent evidence authority is stale or non-canonical")
    return sorted(set(issues))


def _markdown_cell(value: Any) -> str:
    text = str(value or "")
    text = _CONTROL_RE.sub(" ", text)
    text = html.escape(text, quote=True)
    return text.replace("\\", "\\\\").replace("|", "\\|").strip()


def render_precedent_context(payload: Mapping[str, Any]) -> str:
    lines = [
        "# Precedent Context (driver-derived)",
        "",
        f"> Schema: `{payload.get('schema_version', '')}`",
        f"> Authority digest: `{payload.get('authority_digest', '')}`",
        "> Precedent is investigation-priority/report context only. It is not ",
        "> mechanism proof and cannot change confidence, verdict, severity, or depth.",
        "> Refuting precedent is retained in the typed authority for human review but",
        "> withheld here until after code-derived plans and execution are sealed.",
        "",
        "| Finding ID | Match status | Strength | Priority | Context sources |",
        "|---|---|---|---|---|",
    ]
    rows = payload.get("finding_precedent")
    if isinstance(rows, list):
        for raw in rows:
            if not isinstance(raw, Mapping):
                continue
            if raw.get("match_status") == "REFUTING_CONTEXT_ONLY":
                continue
            source_rows = raw.get("context_sources")
            rendered_sources: list[str] = []
            if isinstance(source_rows, list):
                for source in source_rows:
                    if not isinstance(source, Mapping):
                        continue
                    if source.get("relation") == "REFUTING":
                        continue
                    rendered_sources.append(
                        "{proposal}:{kind}:{relation}:{bound}:{ref}:sha256={sha}".format(
                            proposal=_markdown_cell(source.get("proposal_id")),
                            kind=_markdown_cell(source.get("source_kind")),
                            relation=_markdown_cell(source.get("relation")),
                            bound=(
                                "BOUND"
                                if source.get("source_evidence_bound") is True
                                else "UNBOUND"
                            ),
                            ref=_markdown_cell(source.get("source_ref")),
                            sha=_markdown_cell(source.get("source_sha256")),
                        )
                    )
            sources = ", ".join(rendered_sources)
            lines.append(
                f"| {_markdown_cell(raw.get('finding_id', ''))} "
                f"| {_markdown_cell(raw.get('match_status', ''))} "
                f"| {_markdown_cell(raw.get('precedent_strength', 'NONE'))} "
                f"| {_markdown_cell(raw.get('investigation_priority', 'UNCHANGED'))} "
                f"| {sources or '-'} |"
            )
    if not any(line.startswith("| ") and "Finding ID" not in line and "---" not in line for line in lines):
        lines.append("| - | UNSCORED | NONE | UNCHANGED | - |")
    debts = payload.get("debts")
    lines.extend(["", "## Reconciliation debt", ""])
    if isinstance(debts, list) and debts:
        for raw in debts:
            if isinstance(raw, Mapping):
                lines.append(
                    f"- `{_markdown_cell(raw.get('code', ''))}` "
                    f"`{_markdown_cell(raw.get('subject', ''))}`: "
                    f"{_markdown_cell(raw.get('detail', ''))}"
                )
    else:
        lines.append("- None.")
    return "\n".join(lines) + "\n"


def render_precedent_report_context(payload: Mapping[str, Any]) -> str:
    """Project only receipt-bound, report-eligible precedent citations."""

    lines = [
        "# Report-Eligible Precedent Context (driver-derived)",
        "",
        f"> Authority digest: `{payload.get('authority_digest', '')}`",
        "> Only rows carrying deterministic report_context_eligible=true are",
        "> projected here. Absence is not evidence that audited code is safe.",
        "",
        "| Finding ID | Match status | Eligible sources |",
        "|---|---|---|",
    ]
    count = 0
    rows = payload.get("finding_precedent")
    if isinstance(rows, list):
        for raw in rows:
            if not isinstance(raw, Mapping) or raw.get("report_context_eligible") is not True:
                continue
            source_rows = raw.get("context_sources")
            rendered: list[str] = []
            if isinstance(source_rows, list):
                for source in source_rows:
                    if not isinstance(source, Mapping):
                        continue
                    if source.get("source_evidence_bound") is not True:
                        continue
                    rendered.append(
                        "{proposal}:{kind}:{relation}:{ref}:sha256={sha}".format(
                            proposal=_markdown_cell(source.get("proposal_id")),
                            kind=_markdown_cell(source.get("source_kind")),
                            relation=_markdown_cell(source.get("relation")),
                            ref=_markdown_cell(source.get("source_ref")),
                            sha=_markdown_cell(source.get("source_sha256")),
                        )
                    )
            if not rendered:
                continue
            lines.append(
                f"| {_markdown_cell(raw.get('finding_id'))} "
                f"| {_markdown_cell(raw.get('match_status'))} "
                f"| {', '.join(rendered)} |"
            )
            count += 1
    if count == 0:
        lines.append("| - | NONE_ELIGIBLE | - |")
    return "\n".join(lines) + "\n"


def write_precedent_evidence_artifacts(
    scratchpad: Path,
    finding_facts: Mapping[str, Any],
    proposal_artifact: Mapping[str, Any],
    equivalence_artifact: Mapping[str, Any] | None = None,
    source_evidence_artifact: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Write deterministic authority and its non-authoritative projection."""

    scratchpad = Path(scratchpad)
    payload = reconcile_precedent_evidence(
        finding_facts,
        proposal_artifact,
        equivalence_artifact,
        source_evidence_artifact,
    )
    # Projection is staged first and the typed authority is the commit marker.
    # A crash at either boundary is detectable by
    # validate_precedent_evidence_artifacts and repairable without a model rerun.
    _atomic_bytes(
        scratchpad / CONTEXT_NAME,
        render_precedent_context(payload).encode("utf-8"),
    )
    _atomic_bytes(
        scratchpad / REPORT_CONTEXT_NAME,
        render_precedent_report_context(payload).encode("utf-8"),
    )
    _atomic_bytes(scratchpad / AUTHORITY_NAME, canonical_json_bytes(payload))
    return payload


def validate_precedent_evidence_artifacts(
    scratchpad: Path,
    payload: Mapping[str, Any],
    finding_facts: Mapping[str, Any],
    proposal_artifact: Mapping[str, Any],
    equivalence_artifact: Mapping[str, Any] | None = None,
    source_evidence_artifact: Mapping[str, Any] | None = None,
) -> list[str]:
    """Validate both committed authority bytes and its exact projection."""

    issues = validate_precedent_evidence_authority(
        payload,
        finding_facts,
        proposal_artifact,
        equivalence_artifact,
        source_evidence_artifact,
    )
    root = Path(scratchpad)
    try:
        authority_bytes = read_bounded_regular_bytes(
            root / AUTHORITY_NAME, _MAX_AUTHORITY_BYTES
        )
    except (OSError, ValueError) as exc:
        issues.append(f"precedent authority artifact is unavailable: {exc}")
    else:
        if authority_bytes != canonical_json_bytes(payload):
            issues.append("precedent authority artifact bytes are stale or non-canonical")
    try:
        context_bytes = read_bounded_regular_bytes(
            root / CONTEXT_NAME, _MAX_AUTHORITY_BYTES
        )
    except (OSError, ValueError) as exc:
        issues.append(f"precedent context projection is unavailable: {exc}")
    else:
        expected_context = render_precedent_context(payload).encode("utf-8")
        if context_bytes != expected_context:
            issues.append("precedent context projection is stale or non-canonical")
    try:
        report_context_bytes = read_bounded_regular_bytes(
            root / REPORT_CONTEXT_NAME, _MAX_AUTHORITY_BYTES
        )
    except (OSError, ValueError) as exc:
        issues.append(f"precedent report context projection is unavailable: {exc}")
    else:
        expected_report_context = render_precedent_report_context(payload).encode("utf-8")
        if report_context_bytes != expected_report_context:
            issues.append(
                "precedent report context projection is stale or non-canonical"
            )
    return sorted(set(issues))


def repair_precedent_evidence_artifacts(
    scratchpad: Path,
    finding_facts: Mapping[str, Any],
    proposal_artifact: Mapping[str, Any],
    equivalence_artifact: Mapping[str, Any] | None = None,
    source_evidence_artifact: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Deterministically re-render a stale/missing pair from current inputs."""

    return write_precedent_evidence_artifacts(
        scratchpad,
        finding_facts,
        proposal_artifact,
        equivalence_artifact,
        source_evidence_artifact,
    )


def neutralize_precedent_consumer_projections(scratchpad: Path) -> None:
    """Atomically remove stale precedent content from downstream view.

    These deliberately non-authoritative placeholders are used only when the
    current typed authority cannot be validated or repaired.  Live PhaseIO
    omits both paths from the consumer denominator in that state.  Keeping a
    neutral file at the legacy path also prevents inherited prompts or manual
    readers from observing a prior run's stale positive/refuting context.
    """

    root = Path(scratchpad)
    investigation = (
        "# Precedent Context Unavailable\n\n"
        "> No external precedent context is authorized for this consumer.\n"
        "> Absence is not evidence that the audited code is safe. Continue\n"
        "> from current code, typed findings, and independently executed tests.\n"
    )
    report = (
        "# Report-Eligible Precedent Context Unavailable\n\n"
        "> No external precedent citation is authorized for this report pass.\n"
        "> Do not consult raw precedent research as a fallback.\n"
    )
    _atomic_bytes(root / CONTEXT_NAME, investigation.encode("utf-8"))
    _atomic_bytes(root / REPORT_CONTEXT_NAME, report.encode("utf-8"))


__all__ = [
    "ASSURANCE",
    "AUTHORITY_NAME",
    "AUTHORITY_SCHEMA",
    "CONTEXT_NAME",
    "EQUIVALENCE_SCHEMA",
    "FINDING_FACTS_SCHEMA",
    "PROPOSAL_BLOCK_BEGIN",
    "PROPOSAL_BLOCK_END",
    "PROPOSAL_SCHEMA",
    "PROPOSALS_NAME",
    "REPORT_CONTEXT_NAME",
    "SOURCE_EVIDENCE_NAME",
    "SOURCE_EVIDENCE_SCHEMA",
    "SOURCE_EVIDENCE_ASSURANCE",
    "build_precedent_source_evidence_artifact",
    "canonical_json_bytes",
    "extract_proposal_artifact",
    "normalize_precedent_proposal_transport",
    "neutralize_precedent_consumer_projections",
    "read_canonical_json_artifact",
    "reconcile_precedent_evidence",
    "render_precedent_context",
    "render_precedent_report_context",
    "repair_precedent_evidence_artifacts",
    "source_evidence_authority_digest",
    "source_evidence_row_digest",
    "validate_precedent_evidence_artifacts",
    "validate_precedent_evidence_authority",
    "validate_precedent_proposal_artifact",
    "validate_precedent_source_evidence_artifact",
    "write_precedent_evidence_artifacts",
    "write_precedent_proposal_artifact",
]
