"""Typed, direction-neutral severity decision substrate (P0-AG/P0-P/P0-V).

The module intentionally owns no Markdown parsing and launches no model.  It
turns already-typed assessment facts into a consistency calculation, a bounded
repair request, or an independently adjudicable challenge.  Candidate
retention is never conditional on the resulting severity.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any, Iterable, Mapping
import uuid
import re


ASSESSMENT_SCHEMA = "plamen.severity_assessment.v1"
PROPOSAL_SCHEMA = "plamen.severity_proposal.v1"
DECISION_SCHEMA = "plamen.severity_decision.v1"
ADJUDICATION_SCHEMA = "plamen.severity_adjudication.v1"
ADJUDICATION_PROPOSAL_SCHEMA = "plamen.severity_adjudication_proposal.v1"
REPAIR_SCHEMA = "plamen.severity_repair_request.v1"
LEDGER_SCHEMA = "plamen.severity_decision_ledger.v1"
COVERAGE_RECEIPT_SCHEMA = "plamen.severity_ledger_coverage_receipt.v1"
LAUNCH_RECEIPT_SCHEMA = "plamen.severity_launch_receipt.v2"
ASSESSOR_INPUT_SCHEMA = "plamen.severity_assessor_input.v1"
ADJUDICATOR_INPUT_SCHEMA = "plamen.severity_adjudicator_input.v1"

SEVERITIES = ("Critical", "High", "Medium", "Low", "Informational")
IMPACT_CLASSES = ("High", "Medium", "Low", "Informational")
LIKELIHOOD_CLASSES = ("High", "Medium", "Low")
PROOF_SCOPES = frozenset(
    {
        "IN_SCOPE_SOURCE",
        "IN_SCOPE_EXECUTION",
        "PRIMARY_EXTERNAL_CITED",
        "FORMAL_PROOF",
    }
)
PREMISE_KINDS = frozenset(
    {"INTERNAL", "EXTERNAL_FAVORABLE", "EXTERNAL_ADVERSE", "ENVIRONMENTAL"}
)
MODIFIER_KINDS = frozenset(
    {"ONCHAIN_STATE_ONLY", "VIEW_FUNCTION_ONLY", "FULLY_TRUSTED_ACTOR"}
)
EVIDENCE_CAPABILITIES = frozenset(
    {
        "MECHANISM",
        "REACHABILITY",
        "EXECUTION",
        "IMPACT",
        "LIKELIHOOD",
        "HARM",
        "COMPOSITION",
        "EXTERNAL_FACT",
        "MODIFIER_APPLICABILITY",
    }
)
MAX_SEVERITY_INGRESS_BYTES = 1_048_576
MAX_SEVERITY_FIELD_CHARS = 16_384
MAX_SEVERITY_LIST_ITEMS = 256
MAX_SEVERITY_JSON_DEPTH = 64
MAX_SEVERITY_JSON_NODES = 8_192
_ASSESSMENT_FIELDS = (
    "candidate_id",
    "constituent_ids",
    "upstream_severity",
    "assessor_identity",
    "assessor_invocation_id",
    "impact",
    "likelihood",
    "modifiers",
    "proposed_severity",
    "adjustment",
    "constituent_premise_outcomes",
)
_PROPOSAL_FIELDS = (
    "schema_version",
    "candidate_id",
    "constituent_ids",
    "impact",
    "likelihood",
    "modifiers",
    "proposed_severity",
    "adjustment",
    "constituent_premise_outcomes",
)
_ADJUDICATION_PROPOSAL_FIELDS = (
    "schema_version",
    "decision",
    "resolved_severity",
    "resolved_premise_ids",
    "evidence_ids",
    "proof_scope",
    "rationale",
    "resolved_axes",
    "constituent_resolutions",
)
_LAUNCH_RECEIPT_FIELDS = (
    "schema_version",
    "role",
    "run_id",
    "candidate_id",
    "constituent_ids",
    "worker_identity",
    "invocation_id",
    "backend",
    "launch_manifest_sha256",
    "input_sha256",
    "output_sha256",
)
_COVERAGE_RECEIPT_FIELDS = (
    "schema_version",
    "run_id",
    "queue_work_plan_digest",
    "expected_candidate_ids",
    "expected_source_receipt_digests_digest",
    "severity_ledger_digest",
    "ledger_authority_status",
    "denominator_status",
    "missing_candidate_ids",
    "extra_candidate_ids",
    "invalid_candidate_ids",
    "challenged_candidate_ids",
    "authority_status",
    "receipt_digest",
)
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
_DRIVER_AUTHORITY_TOKEN = object()


class SeverityDecisionError(ValueError):
    """Typed severity data is missing, contradictory, or tampered."""


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


def _severity(value: Any, *, field: str) -> str:
    text = _text(value).title()
    if text == "Info":
        text = "Informational"
    if text not in SEVERITIES:
        raise SeverityDecisionError(f"{field} is not a canonical severity")
    return text


def _string_list(value: Any, *, field: str, nonempty: bool = True) -> list[str]:
    if not isinstance(value, list):
        raise SeverityDecisionError(f"{field} must be a list")
    result = [_text(item) for item in value]
    if any(not item for item in result):
        raise SeverityDecisionError(f"{field} contains an empty identity")
    if len(result) != len({item.casefold() for item in result}):
        raise SeverityDecisionError(f"{field} contains duplicate identities")
    if nonempty and not result:
        raise SeverityDecisionError(f"{field} must not be empty")
    return result


def _proposal_string(value: Any, *, field: str, nonempty: bool = True) -> str:
    """Validate a model-authored JSON string without coercing its type.

    The compiled proposal contract is JSON Schema, where numbers and booleans
    are not strings.  Compatibility ingestion later in the pipeline may remain
    normalization-tolerant, but this boundary must accept exactly what the
    verifier was instructed to emit.
    """

    if not isinstance(value, str):
        raise SeverityDecisionError(f"{field} must be a string")
    result = value.strip()
    if nonempty and not result:
        raise SeverityDecisionError(f"{field} must not be empty")
    return result


def _proposal_identifier(value: Any, *, field: str) -> str:
    """Validate an exact single-line identifier at an artifact boundary."""

    result = _proposal_string(value, field=field)
    if value != result:
        raise SeverityDecisionError(
            f"{field} must not contain surrounding whitespace"
        )
    if any(
        ord(char) < 32 or ord(char) == 127 or char in {"\u2028", "\u2029"}
        for char in result
    ):
        raise SeverityDecisionError(
            f"{field} contains a forbidden control or line separator"
        )
    return result


def _proposal_string_list(
    value: Any, *, field: str, nonempty: bool = True
) -> list[str]:
    if not isinstance(value, list):
        raise SeverityDecisionError(f"{field} must be a list")
    result: list[str] = []
    for index, item in enumerate(value):
        result.append(_proposal_identifier(item, field=f"{field}[{index}]"))
    if len(result) != len({item.casefold() for item in result}):
        raise SeverityDecisionError(f"{field} contains duplicate identities")
    if nonempty and not result:
        raise SeverityDecisionError(f"{field} must not be empty")
    return result


def _strict_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise SeverityDecisionError(f"duplicate severity JSON key {key!r}")
        value[key] = item
    return value


def _reject_json_constant(value: str) -> None:
    raise SeverityDecisionError(f"non-finite severity JSON constant {value!r}")


def _validate_bounded_json(value: Any, *, field: str) -> None:
    stack: list[tuple[Any, int]] = [(value, 0)]
    nodes = 0
    while stack:
        current, depth = stack.pop()
        nodes += 1
        if nodes > MAX_SEVERITY_JSON_NODES:
            raise SeverityDecisionError(f"{field} exceeds the JSON node budget")
        if depth > MAX_SEVERITY_JSON_DEPTH:
            raise SeverityDecisionError(f"{field} exceeds the JSON depth budget")
        if isinstance(current, str):
            if len(current) > MAX_SEVERITY_FIELD_CHARS:
                raise SeverityDecisionError(f"{field} contains an oversized string")
            try:
                current.encode("utf-8", errors="strict")
            except UnicodeError as exc:
                raise SeverityDecisionError(
                    f"{field} contains invalid Unicode"
                ) from exc
        elif isinstance(current, Mapping):
            if len(current) > MAX_SEVERITY_LIST_ITEMS:
                raise SeverityDecisionError(f"{field} contains too many object fields")
            for key, item in current.items():
                stack.append((key, depth + 1))
                stack.append((item, depth + 1))
        elif isinstance(current, list):
            if len(current) > MAX_SEVERITY_LIST_ITEMS:
                raise SeverityDecisionError(f"{field} contains an oversized list")
            stack.extend((item, depth + 1) for item in current)
        elif isinstance(current, float) and (
            current != current or current in {float("inf"), float("-inf")}
        ):
            raise SeverityDecisionError(f"{field} contains a non-finite number")


def _bounded_raw_text(value: str | bytes, *, field: str) -> str:
    try:
        if isinstance(value, bytes):
            if len(value) > MAX_SEVERITY_INGRESS_BYTES:
                raise SeverityDecisionError(f"{field} exceeds the byte budget")
            return value.decode("utf-8", errors="strict")
        text = str(value)
        if len(text.encode("utf-8", errors="strict")) > MAX_SEVERITY_INGRESS_BYTES:
            raise SeverityDecisionError(f"{field} exceeds the byte budget")
        return text
    except UnicodeError as exc:
        raise SeverityDecisionError(f"{field} is not valid UTF-8") from exc


def _require_exact_keys(
    value: Any,
    expected: Iterable[str],
    *,
    field: str,
) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise SeverityDecisionError(f"{field} must be an object")
    expected_set = set(expected)
    observed = set(value)
    if observed != expected_set:
        missing = sorted(expected_set - observed)
        extra = sorted(observed - expected_set)
        detail = []
        if missing:
            detail.append("missing=" + ",".join(missing))
        if extra:
            detail.append("extra=" + ",".join(extra))
        raise SeverityDecisionError(
            f"{field} schema mismatch ({'; '.join(detail)})"
        )
    return value


def _validate_severity_proposal(
    value: Mapping[str, Any], *, allow_incomplete_axes: bool = False
) -> dict[str, Any]:
    _validate_bounded_json(value, field="severity proposal")
    proposal = dict(_require_exact_keys(
        value, _PROPOSAL_FIELDS, field="severity proposal"
    ))
    if proposal.get("schema_version") != PROPOSAL_SCHEMA:
        raise SeverityDecisionError("severity proposal schema mismatch")
    _proposal_string(
        proposal.get("candidate_id"), field="severity proposal candidate_id"
    )
    constituents = _proposal_string_list(
        proposal.get("constituent_ids"),
        field="severity proposal constituent_ids",
    )
    impact = proposal.get("impact")
    if impact is not None or not allow_incomplete_axes:
        _require_exact_keys(
            impact,
            (
                "class", "harmed_asset", "harmed_capability", "premise_id",
                "premise_kind", "evidence_ids", "proof_scope",
            ),
            field="severity proposal impact",
        )
        _proposal_string(
            impact.get("harmed_asset"),
            field="severity proposal impact harmed_asset",
        )
        _proposal_string(
            impact.get("harmed_capability"),
            field="severity proposal impact harmed_capability",
        )
        _proposal_string(
            impact.get("premise_id"),
            field="severity proposal impact premise_id",
        )
        normalized_impact, impact_missing = _validate_fact_axis(
            impact, axis="impact", allowed_classes=IMPACT_CLASSES
        )
        if normalized_impact is None or impact_missing:
            raise SeverityDecisionError(
                "severity proposal impact value schema invalid"
            )
        if (
            impact.get("class") not in IMPACT_CLASSES
            or impact.get("premise_kind") not in PREMISE_KINDS
            or impact.get("proof_scope") not in PROOF_SCOPES
        ):
            raise SeverityDecisionError(
                "severity proposal impact enum is invalid"
            )
        _proposal_string_list(
            impact.get("evidence_ids"),
            field="severity proposal impact evidence_ids",
        )
    likelihood = proposal.get("likelihood")
    if likelihood is not None or not allow_incomplete_axes:
        _require_exact_keys(
            likelihood,
            (
                "class", "actor", "preconditions", "premise_id",
                "premise_kind", "evidence_ids", "proof_scope",
            ),
            field="severity proposal likelihood",
        )
        _proposal_string(
            likelihood.get("actor"),
            field="severity proposal likelihood actor",
        )
        _proposal_string(
            likelihood.get("premise_id"),
            field="severity proposal likelihood premise_id",
        )
        normalized_likelihood, likelihood_missing = _validate_fact_axis(
            likelihood,
            axis="likelihood",
            allowed_classes=LIKELIHOOD_CLASSES,
        )
        if normalized_likelihood is None or likelihood_missing:
            raise SeverityDecisionError(
                "severity proposal likelihood value schema invalid"
            )
        if (
            likelihood.get("class") not in LIKELIHOOD_CLASSES
            or likelihood.get("premise_kind") not in PREMISE_KINDS
            or likelihood.get("proof_scope") not in PROOF_SCOPES
        ):
            raise SeverityDecisionError(
                "severity proposal likelihood enum is invalid"
            )
        _proposal_string_list(
            likelihood.get("preconditions"),
            field="severity proposal likelihood preconditions",
        )
        _proposal_string_list(
            likelihood.get("evidence_ids"),
            field="severity proposal likelihood evidence_ids",
        )
    modifiers = proposal.get("modifiers")
    if not isinstance(modifiers, list):
        raise SeverityDecisionError("severity proposal modifiers must be a list")
    for index, modifier in enumerate(modifiers):
        _require_exact_keys(
            modifier,
            (
                "kind", "applies", "applicability_predicate",
                "evidence_ids", "proof_scope",
            ),
            field=f"severity proposal modifier {index}",
        )
        if (
            modifier.get("kind") not in MODIFIER_KINDS
            or not isinstance(modifier.get("applies"), bool)
            or not isinstance(modifier.get("applicability_predicate"), str)
            or modifier.get("proof_scope") not in PROOF_SCOPES
        ):
            raise SeverityDecisionError(
                f"severity proposal modifier {index} value schema invalid"
            )
        _proposal_string_list(
            modifier.get("evidence_ids"),
            field=f"severity proposal modifier {index} evidence_ids",
            nonempty=False,
        )
    adjustment = proposal.get("adjustment")
    if adjustment is not None:
        _require_exact_keys(
            adjustment,
            (
                "direction", "premise_ids", "evidence_ids", "proof_scope",
                "rationale",
            ),
            field="severity proposal adjustment",
        )
        if (
            adjustment.get("direction") not in {"UP", "DOWN"}
            or adjustment.get("proof_scope") not in PROOF_SCOPES
            or not isinstance(adjustment.get("rationale"), str)
            or not adjustment.get("rationale")
        ):
            raise SeverityDecisionError(
                "severity proposal adjustment value schema invalid"
            )
        _proposal_string_list(
            adjustment.get("premise_ids"),
            field="severity proposal adjustment premise_ids",
        )
        _proposal_string_list(
            adjustment.get("evidence_ids"),
            field="severity proposal adjustment evidence_ids",
        )
    if proposal.get("proposed_severity") not in SEVERITIES:
        raise SeverityDecisionError(
            "severity proposal proposed_severity enum is invalid"
        )
    outcomes = proposal.get("constituent_premise_outcomes")
    if not isinstance(outcomes, Mapping):
        raise SeverityDecisionError(
            "severity proposal constituent outcomes must be an object"
        )
    if set(outcomes) != set(constituents):
        raise SeverityDecisionError(
            "severity proposal constituent outcomes do not match constituents"
        )
    for identity, row in outcomes.items():
        _proposal_string(
            identity,
            field="severity proposal constituent outcome identity",
        )
        _require_exact_keys(
            row, ("impact", "likelihood"),
            field=f"severity proposal outcome {identity}",
        )
        if row.get("impact") not in {"SUPPORTED", "REFUTED", "UNRESOLVED"} or row.get(
            "likelihood"
        ) not in {"SUPPORTED", "REFUTED", "UNRESOLVED"}:
            raise SeverityDecisionError(
                f"severity proposal outcome {identity} value schema invalid"
            )
    return proposal


def parse_severity_proposal(value: str | bytes | Mapping[str, Any]) -> dict[str, Any]:
    """Parse one strict model-authored proposal with no authority fields."""

    if isinstance(value, Mapping):
        return _validate_severity_proposal(value)
    try:
        text = _bounded_raw_text(value, field="severity proposal")
        payload = json.loads(
            text,
            object_pairs_hook=_strict_json_object,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise SeverityDecisionError(
            f"severity proposal JSON is invalid: {exc}"
        ) from exc
    if not isinstance(payload, Mapping):
        raise SeverityDecisionError("severity proposal must be a JSON object")
    return _validate_severity_proposal(payload)


def _normalize_launch_receipt(
    value: Any,
    *,
    role: str,
    run_id: str,
    candidate_id: str,
    constituent_ids: list[str],
    worker_identity: str,
    invocation_id: str,
    expected_input_sha256: str | None = None,
    expected_output_sha256: str | None = None,
) -> dict[str, Any] | None:
    if value is None:
        return None
    receipt = dict(_require_exact_keys(
        value, _LAUNCH_RECEIPT_FIELDS, field="severity launch receipt"
    ))
    normalized = {
        "schema_version": receipt.get("schema_version"),
        "role": _proposal_identifier(
            receipt.get("role"), field="severity launch receipt role"
        ),
        "run_id": _proposal_identifier(
            receipt.get("run_id"), field="severity launch receipt run_id"
        ),
        "candidate_id": _proposal_identifier(
            receipt.get("candidate_id"),
            field="severity launch receipt candidate_id",
        ),
        "constituent_ids": _proposal_string_list(
            receipt.get("constituent_ids"),
            field="severity launch receipt constituent_ids",
        ),
        "worker_identity": _proposal_identifier(
            receipt.get("worker_identity"),
            field="severity launch receipt worker_identity",
        ),
        "invocation_id": _proposal_identifier(
            receipt.get("invocation_id"),
            field="severity launch receipt invocation_id",
        ),
        "backend": _proposal_identifier(
            receipt.get("backend"), field="severity launch receipt backend"
        ),
        "launch_manifest_sha256": _proposal_identifier(
            receipt.get("launch_manifest_sha256"),
            field="severity launch receipt launch_manifest_sha256",
        ),
        "input_sha256": _proposal_identifier(
            receipt.get("input_sha256"),
            field="severity launch receipt input_sha256",
        ),
        "output_sha256": _proposal_identifier(
            receipt.get("output_sha256"),
            field="severity launch receipt output_sha256",
        ),
    }
    if (
        normalized["schema_version"] != LAUNCH_RECEIPT_SCHEMA
        or normalized["role"] != role
        or normalized["run_id"] != run_id
        or normalized["candidate_id"] != candidate_id
        or normalized["constituent_ids"] != constituent_ids
        or normalized["worker_identity"] != worker_identity
        or normalized["invocation_id"] != invocation_id
        or not normalized["backend"]
        or not _HEX64_RE.fullmatch(normalized["launch_manifest_sha256"])
        or not _HEX64_RE.fullmatch(normalized["input_sha256"])
        or not _HEX64_RE.fullmatch(normalized["output_sha256"])
        or (
            expected_input_sha256 is not None
            and normalized["input_sha256"] != expected_input_sha256
        )
        or (
            expected_output_sha256 is not None
            and normalized["output_sha256"] != expected_output_sha256
        )
    ):
        raise SeverityDecisionError("severity launch receipt authority mismatch")
    return normalized


def severity_assessor_input_digest(
    *,
    candidate_id: str,
    constituent_ids: Iterable[str],
    upstream_severity: str,
    run_id: str,
    source_receipt_digest: str,
    evidence_receipts: Iterable[Mapping[str, Any]],
) -> str:
    """Digest the complete driver-owned input universe for one assessment."""

    candidate = _text(candidate_id)
    constituents = [_text(item) for item in constituent_ids]
    run = _text(run_id)
    source_digest = _text(source_receipt_digest).casefold()
    upstream = _severity(upstream_severity, field="upstream_severity")
    if not candidate or not run or not _HEX64_RE.fullmatch(source_digest):
        raise SeverityDecisionError("severity assessor input context is invalid")
    if (
        not constituents
        or any(not item for item in constituents)
        or len(constituents) != len(set(constituents))
    ):
        raise SeverityDecisionError("severity assessor constituents are invalid")
    raw_receipts = list(evidence_receipts)
    normalized_receipts, attested = _normalize_evidence_receipts(
        {
            "evidence_receipts": raw_receipts,
            "evidence_receipts_attested": True,
        },
        constituents=constituents,
        impact=None,
        likelihood=None,
    )
    if not attested:
        raise SeverityDecisionError("severity assessor evidence is unattested")
    return _digest(
        {
            "schema_version": ASSESSOR_INPUT_SCHEMA,
            "run_id": run,
            "candidate_id": candidate,
            "constituent_ids": constituents,
            "upstream_severity": upstream,
            "source_receipt_digest": source_digest,
            "evidence_receipts": normalized_receipts,
        }
    )


def severity_adjudicator_input_digest(decision: Mapping[str, Any]) -> str:
    """Digest the exact source decision an adjudicator launch may resolve."""

    _validate_decision_semantics(decision)
    decision_digest = _text(decision.get("decision_digest")).casefold()
    source_digest = _text(decision.get("source_receipt_digest")).casefold()
    if (
        not _HEX64_RE.fullmatch(decision_digest)
        or not _HEX64_RE.fullmatch(source_digest)
    ):
        raise SeverityDecisionError("severity adjudicator input context is invalid")
    assessment = decision.get("assessment") or {}
    producer_binding = assessment.get("producer_authority_binding") or {}
    producer_receipt_digest = _text(
        producer_binding.get("receipt_digest")
    ).casefold()
    if not _HEX64_RE.fullmatch(producer_receipt_digest):
        raise SeverityDecisionError(
            "severity adjudicator source producer authority is invalid"
        )
    return _digest(
        {
            "schema_version": ADJUDICATOR_INPUT_SCHEMA,
            "run_id": _text(decision.get("run_id")),
            "candidate_id": _text(decision.get("candidate_id")),
            "constituent_ids": list(decision.get("constituent_ids") or []),
            "source_receipt_digest": source_digest,
            "source_decision_digest": decision_digest,
            "source_producer_receipt_digest": producer_receipt_digest,
            "prior_retention_severity": _severity(
                decision.get("retention_severity"),
                field="retention_severity",
            ),
        }
    )


def _authority_binding(receipt: Mapping[str, Any] | None) -> dict[str, Any]:
    if receipt is None:
        return {"status": "UNBOUND", "receipt": None, "receipt_digest": None}
    normalized = dict(receipt)
    return {
        "status": "EXACT",
        "receipt": normalized,
        "receipt_digest": _digest(normalized),
    }


def _normalize_authority_binding(
    value: Any,
    *,
    role: str,
    run_id: str,
    candidate_id: str,
    constituent_ids: list[str],
    worker_identity: str,
    invocation_id: str,
    expected_input_sha256: str | None = None,
    expected_output_sha256: str | None = None,
) -> dict[str, Any]:
    if value is None:
        return _authority_binding(None)
    binding = dict(_require_exact_keys(
        value,
        ("status", "receipt", "receipt_digest"),
        field="severity authority binding",
    ))
    status = _text(binding.get("status")).upper()
    if status == "UNBOUND":
        if binding.get("receipt") is not None or binding.get("receipt_digest") is not None:
            raise SeverityDecisionError("unbound severity authority carries a receipt")
        return _authority_binding(None)
    if status != "EXACT":
        raise SeverityDecisionError("severity authority binding status is invalid")
    receipt = _normalize_launch_receipt(
        binding.get("receipt"),
        role=role,
        run_id=run_id,
        candidate_id=candidate_id,
        constituent_ids=constituent_ids,
        worker_identity=worker_identity,
        invocation_id=invocation_id,
        expected_input_sha256=expected_input_sha256,
        expected_output_sha256=expected_output_sha256,
    )
    if receipt is None or binding.get("receipt_digest") != _digest(receipt):
        raise SeverityDecisionError("severity authority binding digest mismatch")
    return _authority_binding(receipt)


def bind_severity_proposal(
    proposal: Mapping[str, Any],
    *,
    candidate_id: str,
    constituent_ids: Iterable[str],
    upstream_severity: str,
    assessor_identity: str,
    assessor_invocation_id: str,
    run_id: str,
    source_receipt_digest: str,
    evidence_receipts: Iterable[Mapping[str, Any]],
    assessor_launch_receipt: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Bind a model proposal to authority supplied only by the driver.

    The direct mapping form deliberately permits a null impact or likelihood so
    a bounded repair can preserve every already-bound fact.  Runtime JSON first
    passes :func:`parse_severity_proposal`, whose producer contract requires
    complete axes.
    """

    if not isinstance(proposal, Mapping):
        raise SeverityDecisionError("severity proposal must be an object")
    normalized = _validate_severity_proposal(
        proposal, allow_incomplete_axes=True
    )
    expected_candidate = _text(candidate_id)
    expected_constituents = [
        _text(item) for item in constituent_ids
    ]
    if not expected_candidate:
        raise SeverityDecisionError("driver candidate identity is empty")
    if normalized.get("candidate_id") != expected_candidate:
        raise SeverityDecisionError("severity proposal candidate identity mismatch")
    if normalized.get("constituent_ids") != expected_constituents:
        raise SeverityDecisionError("severity proposal constituent identity mismatch")
    if not expected_constituents or any(not item for item in expected_constituents):
        raise SeverityDecisionError("driver constituent identity is invalid")
    if len(expected_constituents) != len(set(expected_constituents)):
        raise SeverityDecisionError("driver constituent identity is duplicated")
    run = _text(run_id)
    source_digest = _text(source_receipt_digest).casefold()
    assessor = _text(assessor_identity)
    invocation = _text(assessor_invocation_id)
    if not run or not assessor or not invocation:
        raise SeverityDecisionError("driver severity authority identity is incomplete")
    if not _HEX64_RE.fullmatch(source_digest):
        raise SeverityDecisionError("driver source receipt digest is invalid")
    receipts = list(evidence_receipts)
    if any(not isinstance(row, Mapping) for row in receipts):
        raise SeverityDecisionError("driver evidence receipt is malformed")
    assessor_input_sha256 = severity_assessor_input_digest(
        candidate_id=expected_candidate,
        constituent_ids=expected_constituents,
        upstream_severity=upstream_severity,
        run_id=run,
        source_receipt_digest=source_digest,
        evidence_receipts=receipts,
    )
    launch_receipt = _normalize_launch_receipt(
        assessor_launch_receipt,
        role="ASSESSOR",
        run_id=run,
        candidate_id=expected_candidate,
        constituent_ids=expected_constituents,
        worker_identity=assessor,
        invocation_id=invocation,
        expected_input_sha256=assessor_input_sha256,
        expected_output_sha256=_digest(normalized),
    )
    assessment = {
        "candidate_id": expected_candidate,
        "constituent_ids": expected_constituents,
        "upstream_severity": _severity(
            upstream_severity, field="upstream_severity"
        ),
        "assessor_identity": assessor,
        "assessor_invocation_id": invocation,
        "impact": normalized.get("impact"),
        "likelihood": normalized.get("likelihood"),
        "modifiers": normalized.get("modifiers"),
        "proposed_severity": normalized.get("proposed_severity"),
        "adjustment": normalized.get("adjustment"),
        "constituent_premise_outcomes": normalized.get(
            "constituent_premise_outcomes"
        ),
        "run_id": run,
        "source_receipt_digest": source_digest,
        "evidence_receipts": [dict(row) for row in receipts],
        "evidence_receipts_attested": True,
        "evidence_capabilities_required": True,
        "producer_authority_binding": _authority_binding(launch_receipt),
    }
    return build_severity_decision(
        assessment, _authority_token=_DRIVER_AUTHORITY_TOKEN
    )


def ingest_severity_proposal(
    value: str | bytes | Mapping[str, Any],
    *,
    trusted_context: Mapping[str, Any],
) -> dict[str, Any]:
    """Haltless strict ingress with upstream-retaining typed repair debt."""

    if not isinstance(trusted_context, Mapping):
        raise SeverityDecisionError("severity trusted context must be an object")
    candidate_id = _text(trusted_context.get("candidate_id"))
    constituents = _string_list(
        trusted_context.get("constituent_ids"),
        field="severity trusted context constituent_ids",
    )
    upstream = _severity(
        trusted_context.get("upstream_severity"), field="upstream_severity"
    )
    run_id = _text(trusted_context.get("run_id"))
    source_digest = _text(
        trusted_context.get("source_receipt_digest")
    ).casefold()
    if not candidate_id or not run_id or not _HEX64_RE.fullmatch(source_digest):
        raise SeverityDecisionError("severity trusted context authority is invalid")
    parse_error: SeverityDecisionError | None = None
    proposal: dict[str, Any] | None = None
    try:
        proposal = parse_severity_proposal(value)
        decision = bind_severity_proposal(
            proposal,
            candidate_id=candidate_id,
            constituent_ids=constituents,
            upstream_severity=upstream,
            assessor_identity=_text(trusted_context.get("assessor_identity"))
            or "UNBOUND_PRODUCER",
            assessor_invocation_id=_text(
                trusted_context.get("assessor_invocation_id")
            ) or "UNBOUND_INVOCATION",
            run_id=run_id,
            source_receipt_digest=source_digest,
            evidence_receipts=trusted_context.get("evidence_receipts") or [],
            assessor_launch_receipt=trusted_context.get(
                "assessor_launch_receipt"
            ),
        )
    except SeverityDecisionError as exc:
        parse_error = exc
        try:
            if isinstance(value, Mapping):
                _validate_bounded_json(value, field="severity proposal")
                payload: Mapping[str, Any] = value
            else:
                raw_text = _bounded_raw_text(
                    value, field="severity proposal"
                )
                decoded = json.loads(
                    raw_text,
                    object_pairs_hook=_strict_json_object,
                    parse_constant=_reject_json_constant,
                )
                _validate_bounded_json(decoded, field="severity proposal")
                payload = decoded if isinstance(decoded, Mapping) else {}
        except (
            UnicodeError,
            json.JSONDecodeError,
            SeverityDecisionError,
            RecursionError,
            TypeError,
            ValueError,
        ):
            payload = {}

        impact_value = payload.get("impact")
        likelihood_value = payload.get("likelihood")
        impact = impact_value if isinstance(impact_value, Mapping) else None
        likelihood = (
            likelihood_value if isinstance(likelihood_value, Mapping) else None
        )
        raw_outcomes = payload.get("constituent_premise_outcomes")
        outcome_states = {"SUPPORTED", "REFUTED", "UNRESOLVED"}
        outcomes_valid = (
            isinstance(raw_outcomes, Mapping)
            and set(raw_outcomes) == set(constituents)
            and all(
                isinstance(raw_outcomes.get(identity), Mapping)
                and set(raw_outcomes[identity]) == {"impact", "likelihood"}
                and _text(raw_outcomes[identity].get("impact")).upper()
                in outcome_states
                and _text(raw_outcomes[identity].get("likelihood")).upper()
                in outcome_states
                for identity in constituents
            )
        )
        if outcomes_valid:
            outcomes = dict(raw_outcomes)
        else:
            outcomes = {
                identity: {"impact": "UNRESOLVED", "likelihood": "UNRESOLVED"}
                for identity in constituents
            }
            # Malformed constituent scope makes both semantic axes unsafe to
            # retain, even if their individual object shapes happened to parse.
            impact = None
            likelihood = None
        if impact is not None and likelihood is not None and outcomes_valid:
            # The strict producer failed for identity, tier, or another
            # non-axis contract field.  No complete semantic assessment may be
            # reconstructed by guessing around that failure.
            impact = None
            likelihood = None
        try:
            proposed = _severity(
                payload.get("proposed_severity", upstream),
                field="proposed_severity",
            )
        except SeverityDecisionError:
            proposed = upstream
        assessment = {
            "candidate_id": candidate_id,
            "constituent_ids": constituents,
            "upstream_severity": upstream,
            "assessor_identity": _text(
                trusted_context.get("assessor_identity")
            ) or "UNBOUND_MALFORMED_PRODUCER",
            "assessor_invocation_id": _text(
                trusted_context.get("assessor_invocation_id")
            ) or "UNBOUND_MALFORMED_INVOCATION",
            "impact": impact,
            "likelihood": likelihood,
            "modifiers": (
                payload.get("modifiers")
                if isinstance(payload.get("modifiers"), list)
                else []
            ),
            "proposed_severity": proposed,
            "adjustment": (
                payload.get("adjustment")
                if isinstance(payload.get("adjustment"), Mapping)
                or payload.get("adjustment") is None
                else None
            ),
            "constituent_premise_outcomes": outcomes,
            "run_id": run_id,
            "source_receipt_digest": source_digest,
            "evidence_receipts": [],
            "evidence_receipts_attested": False,
            "evidence_capabilities_required": False,
            "producer_authority_binding": _authority_binding(None),
        }
        try:
            decision = build_severity_decision(assessment)
        except SeverityDecisionError:
            assessment.update(
                {
                    "impact": None,
                    "likelihood": None,
                    "modifiers": [],
                    "adjustment": None,
                    "proposed_severity": upstream,
                    "constituent_premise_outcomes": {
                        identity: {
                            "impact": "UNRESOLVED",
                            "likelihood": "UNRESOLVED",
                        }
                        for identity in constituents
                    },
                }
            )
            decision = build_severity_decision(assessment)

    repair = (
        build_severity_repair_request(decision)
        if decision.get("missing_fields")
        else None
    )
    return {
        "decision": decision,
        "repair_request": repair,
        "ingress_error": str(parse_error) if parse_error is not None else None,
    }


def _matrix(impact: str, likelihood: str) -> str:
    if impact == "Informational":
        return "Informational"
    table = {
        ("High", "High"): "Critical",
        ("High", "Medium"): "High",
        ("High", "Low"): "Medium",
        ("Medium", "High"): "High",
        ("Medium", "Medium"): "Medium",
        ("Medium", "Low"): "Medium",
        ("Low", "High"): "Medium",
        ("Low", "Medium"): "Low",
        ("Low", "Low"): "Low",
    }
    try:
        return table[(impact, likelihood)]
    except KeyError as exc:  # defensive; validation normally catches it
        raise SeverityDecisionError("impact/likelihood matrix input is invalid") from exc


def _demote_once(severity: str) -> str:
    index = SEVERITIES.index(severity)
    return SEVERITIES[min(index + 1, len(SEVERITIES) - 1)]


def _apply_modifiers(severity: str, kinds: Iterable[str]) -> str:
    result = severity
    ordered = set(kinds)
    if "ONCHAIN_STATE_ONLY" in ordered:
        result = _demote_once(result)
    if "VIEW_FUNCTION_ONLY" in ordered and SEVERITIES.index(result) < SEVERITIES.index("Medium"):
        result = "Medium"
    if "FULLY_TRUSTED_ACTOR" in ordered:
        result = _demote_once(result)
    return result


def _decision_with_digest(unsigned: Mapping[str, Any]) -> dict[str, Any]:
    payload = dict(unsigned)
    payload["decision_digest"] = _digest(unsigned)
    return payload


def _validate_fact_axis(
    value: Any,
    *,
    axis: str,
    allowed_classes: tuple[str, ...],
) -> tuple[dict[str, Any] | None, list[str]]:
    if value is None:
        return None, [axis]
    if not isinstance(value, Mapping):
        raise SeverityDecisionError(f"{axis} must be an object or null")
    required = (
        ("class", "harmed_asset", "harmed_capability", "premise_id", "premise_kind", "evidence_ids", "proof_scope")
        if axis == "impact"
        else ("class", "actor", "preconditions", "premise_id", "premise_kind", "evidence_ids", "proof_scope")
    )
    missing = [f"{axis}.{field}" for field in required if field not in value]
    if missing:
        return None, missing
    class_name = _text(value.get("class")).title()
    if class_name == "Info":
        class_name = "Informational"
    if class_name not in allowed_classes:
        return None, [f"{axis}.class"]
    premise_id = _text(value.get("premise_id"))
    premise_kind = _text(value.get("premise_kind")).upper()
    evidence_ids = value.get("evidence_ids")
    proof_scope = _text(value.get("proof_scope")).upper()
    if not premise_id:
        missing.append(f"{axis}.premise_id")
    if premise_kind not in PREMISE_KINDS:
        missing.append(f"{axis}.premise_kind")
    if not isinstance(evidence_ids, list) or not evidence_ids or any(
        not _text(item) for item in evidence_ids
    ):
        missing.append(f"{axis}.evidence_ids")
    if proof_scope not in PROOF_SCOPES:
        missing.append(f"{axis}.proof_scope")
    if axis == "impact":
        if not _text(value.get("harmed_asset")):
            missing.append("impact.harmed_asset")
        if not _text(value.get("harmed_capability")):
            missing.append("impact.harmed_capability")
    else:
        if not _text(value.get("actor")):
            missing.append("likelihood.actor")
        preconditions = value.get("preconditions")
        if not isinstance(preconditions, list) or not preconditions or any(
            not _text(item) for item in preconditions
        ):
            missing.append("likelihood.preconditions")
    normalized = dict(value)
    normalized["class"] = class_name
    normalized["premise_id"] = premise_id
    normalized["premise_kind"] = premise_kind
    normalized["evidence_ids"] = sorted({_text(item) for item in evidence_ids or [] if _text(item)})
    normalized["proof_scope"] = proof_scope
    return (normalized if not missing else None), sorted(set(missing))


def _normalize_modifiers(value: Any) -> tuple[list[dict[str, Any]], list[str], list[str]]:
    if not isinstance(value, list):
        raise SeverityDecisionError("modifiers must be a list")
    normalized: list[dict[str, Any]] = []
    codes: list[str] = []
    kinds: list[str] = []
    observed: set[str] = set()
    for row in value:
        if not isinstance(row, Mapping):
            codes.append("MODIFIER_SCHEMA_INVALID")
            continue
        kind = _text(row.get("kind")).upper()
        if kind not in MODIFIER_KINDS or kind in observed:
            codes.append("MODIFIER_SCHEMA_INVALID")
            continue
        observed.add(kind)
        applies = row.get("applies") is True
        predicate = _text(row.get("applicability_predicate"))
        evidence_ids = row.get("evidence_ids")
        proof_scope = _text(row.get("proof_scope")).upper()
        evidence = (
            sorted({_text(item) for item in evidence_ids if _text(item)})
            if isinstance(evidence_ids, list)
            else []
        )
        normalized.append(
            {
                "kind": kind,
                "applies": applies,
                "applicability_predicate": predicate,
                "evidence_ids": evidence,
                "proof_scope": proof_scope,
            }
        )
        if applies and (not predicate or not evidence or proof_scope not in PROOF_SCOPES):
            codes.append("MODIFIER_APPLICABILITY_UNPROVEN")
            continue
        if applies:
            kinds.append(kind)
    kind_set = set(kinds)
    if {"VIEW_FUNCTION_ONLY", "ONCHAIN_STATE_ONLY"}.issubset(kind_set):
        codes.append("INCOMPATIBLE_MODIFIER_SET")
        kinds = []
    return normalized, sorted(set(codes)), sorted(kinds)


def _normalize_adjustment(value: Any) -> tuple[dict[str, Any] | None, list[str]]:
    if value is None:
        return None, []
    if not isinstance(value, Mapping):
        return None, ["ADJUSTMENT_SCHEMA_INVALID"]
    direction = _text(value.get("direction")).upper()
    premise_ids = value.get("premise_ids")
    evidence_ids = value.get("evidence_ids")
    proof_scope = _text(value.get("proof_scope")).upper()
    rationale = _text(value.get("rationale"))
    normalized = {
        "direction": direction,
        "premise_ids": sorted(
            {_text(item) for item in premise_ids if _text(item)}
        ) if isinstance(premise_ids, list) else [],
        "evidence_ids": sorted(
            {_text(item) for item in evidence_ids if _text(item)}
        ) if isinstance(evidence_ids, list) else [],
        "proof_scope": proof_scope,
        "rationale": rationale,
    }
    codes: list[str] = []
    if direction not in {"UP", "DOWN"}:
        codes.append("ADJUSTMENT_DIRECTION_INVALID")
    if not normalized["premise_ids"]:
        codes.append("ADJUSTMENT_PREMISE_MISSING")
    if not normalized["evidence_ids"]:
        codes.append("ADJUSTMENT_EVIDENCE_MISSING")
    if proof_scope not in PROOF_SCOPES:
        codes.append("ADJUSTMENT_PROOF_SCOPE_INVALID")
    if not rationale:
        codes.append("ADJUSTMENT_RATIONALE_MISSING")
    return normalized, sorted(set(codes))


def _constituent_diverges(
    constituent_ids: list[str], outcomes: Any
) -> tuple[dict[str, Any], bool]:
    if not isinstance(outcomes, Mapping) or set(outcomes) != set(constituent_ids):
        raise SeverityDecisionError(
            "constituent_premise_outcomes must exactly cover constituents"
        )
    normalized: dict[str, Any] = {}
    signatures: set[tuple[str, str]] = set()
    for identity in constituent_ids:
        row = outcomes.get(identity)
        if not isinstance(row, Mapping) or set(row) != {"impact", "likelihood"}:
            raise SeverityDecisionError("constituent premise outcome schema is invalid")
        impact = _text(row.get("impact")).upper()
        likelihood = _text(row.get("likelihood")).upper()
        if impact not in {"SUPPORTED", "REFUTED", "UNRESOLVED"} or likelihood not in {
            "SUPPORTED",
            "REFUTED",
            "UNRESOLVED",
        }:
            raise SeverityDecisionError("constituent premise outcome is invalid")
        normalized[identity] = {"impact": impact, "likelihood": likelihood}
        signatures.add((impact, likelihood))
    return normalized, len(signatures) > 1


def _normalize_evidence_receipts(
    assessment: Mapping[str, Any],
    *,
    constituents: list[str],
    impact: Mapping[str, Any] | None,
    likelihood: Mapping[str, Any] | None,
) -> tuple[list[dict[str, Any]], bool]:
    """Return the authoritative evidence universe or a legacy single-member view.

    Production assessments carry ``evidence_receipts``.  A single-constituent
    compatibility assessment may omit it so old in-memory callers can still be
    challenged, but such a row is marked unattested and cannot be persisted as
    report authority without an exact run/source binding.
    """

    raw = assessment.get("evidence_receipts")
    if raw is not None and assessment.get("evidence_receipts_attested") is False:
        if not isinstance(raw, list):
            raise SeverityDecisionError("compatibility evidence receipts malformed")
        return [dict(row) for row in raw if isinstance(row, Mapping)], False
    if raw is None:
        receipts: list[dict[str, Any]] = []
        if len(constituents) == 1:
            for axis in (impact, likelihood):
                if axis is None:
                    continue
                for evidence_id in axis.get("evidence_ids", []):
                    receipts.append(
                        {
                            "evidence_id": evidence_id,
                            "content_sha256": "",
                            "premise_ids": [axis["premise_id"]],
                            "constituent_ids": list(constituents),
                            "proof_scope": axis["proof_scope"],
                            "capabilities": [],
                            "issuer_identity": "UNATTESTED_COMPATIBILITY",
                            "issuer_invocation_id": "UNATTESTED_COMPATIBILITY",
                        }
                    )
        unique = {row["evidence_id"]: row for row in receipts}
        return [unique[key] for key in sorted(unique)], False
    if not isinstance(raw, list):
        raise SeverityDecisionError("evidence_receipts must be a list")
    receipts = []
    observed: set[str] = set()
    for row in raw:
        if not isinstance(row, Mapping):
            raise SeverityDecisionError("evidence receipt must be an object")
        evidence_id = _text(row.get("evidence_id"))
        evidence_key = evidence_id.casefold()
        digest = _text(row.get("content_sha256")).casefold()
        premise_ids = _string_list(
            row.get("premise_ids"), field="evidence_receipt.premise_ids"
        )
        member_ids = _string_list(
            row.get("constituent_ids"), field="evidence_receipt.constituent_ids"
        )
        proof_scope = _text(row.get("proof_scope")).upper()
        raw_capabilities = row.get("capabilities", [])
        if (
            not isinstance(raw_capabilities, list)
            or any(not isinstance(item, str) for item in raw_capabilities)
        ):
            raise SeverityDecisionError(
                "evidence receipt capabilities are malformed"
            )
        capabilities = sorted({_text(item).upper() for item in raw_capabilities})
        if any(capability not in EVIDENCE_CAPABILITIES for capability in capabilities):
            raise SeverityDecisionError(
                "evidence receipt capability is invalid"
            )
        issuer = _text(row.get("issuer_identity"))
        invocation = _text(row.get("issuer_invocation_id"))
        if (
            not evidence_id
            or evidence_key in observed
            or not _HEX64_RE.fullmatch(digest)
            or proof_scope not in PROOF_SCOPES
            or not issuer
            or not invocation
        ):
            raise SeverityDecisionError("evidence receipt authority is invalid")
        if not set(member_ids).issubset(set(constituents)):
            raise SeverityDecisionError("evidence receipt names a foreign constituent")
        observed.add(evidence_key)
        receipts.append(
            {
                "evidence_id": evidence_id,
                "content_sha256": digest,
                "premise_ids": sorted(premise_ids),
                "constituent_ids": sorted(member_ids),
                "proof_scope": proof_scope,
                "capabilities": capabilities,
                "issuer_identity": issuer,
                "issuer_invocation_id": invocation,
            }
        )
    return sorted(receipts, key=lambda row: row["evidence_id"]), True


def _evidence_binds(
    receipts: Iterable[Mapping[str, Any]],
    evidence_ids: Iterable[str],
    premise_ids: Iterable[str],
    constituent_ids: Iterable[str],
    *,
    required_scope: str | None = None,
    required_any_capability: Iterable[str] | None = None,
) -> bool:
    evidence_set = set(evidence_ids)
    premise_set = set(premise_ids)
    selected = {
        row.get("evidence_id"): row
        for row in receipts
        if row.get("evidence_id") in evidence_set
    }
    if set(selected) != evidence_set or not selected:
        return False
    capability_set = {
        _text(item).upper() for item in (required_any_capability or [])
    }

    def _capable(row: Mapping[str, Any]) -> bool:
        return not capability_set or bool(
            capability_set & set(row.get("capabilities") or [])
        )

    members = set(constituent_ids)
    if not premise_set:
        covered = {
            member
            for row in selected.values()
            if required_scope is None or row.get("proof_scope") == required_scope
            if _capable(row)
            for member in row.get("constituent_ids") or []
        }
        return members.issubset(covered)
    for premise_id in premise_set:
        covered = {
            member
            for row in selected.values()
            if premise_id in set(row.get("premise_ids") or [])
            and (required_scope is None or row.get("proof_scope") == required_scope)
            and _capable(row)
            for member in row.get("constituent_ids") or []
        }
        if not members.issubset(covered):
            return False
    return True


def _evidence_is_independently_issued(
    receipts: Iterable[Mapping[str, Any]],
    *,
    assessor_identity: str,
    assessor_invocation_id: str,
) -> bool:
    """An assessment cannot manufacture the evidence that authorizes itself."""

    return all(
        _text(row.get("issuer_identity")).casefold()
        != _text(assessor_identity).casefold()
        and _text(row.get("issuer_invocation_id")).casefold()
        != _text(assessor_invocation_id).casefold()
        for row in receipts
    )


def _bound_modifier_kinds(
    modifiers: Iterable[Mapping[str, Any]],
    receipts: Iterable[Mapping[str, Any]],
    constituents: Iterable[str],
    *,
    capabilities_required: bool = False,
) -> tuple[list[str], list[str]]:
    """Return modifier kinds backed by an exact registered evidence receipt."""

    kinds: list[str] = []
    codes: list[str] = []
    for modifier in modifiers:
        if modifier.get("applies") is not True:
            continue
        # Schema/applicability defects are already represented by the
        # normalizer.  They remain terminal debt and must not affect a tier.
        if (
            not _text(modifier.get("applicability_predicate"))
            or not modifier.get("evidence_ids")
            or modifier.get("proof_scope") not in PROOF_SCOPES
        ):
            continue
        if not _evidence_binds(
            receipts,
            modifier.get("evidence_ids") or [],
            [],
            constituents,
            required_scope=_text(modifier.get("proof_scope")).upper(),
            required_any_capability=(
                {"MODIFIER_APPLICABILITY"} if capabilities_required else None
            ),
        ):
            codes.append(
                "MODIFIER_EVIDENCE_CAPABILITY_MISSING"
                if capabilities_required
                else "MODIFIER_EVIDENCE_UNBOUND"
            )
            continue
        kinds.append(_text(modifier.get("kind")).upper())
    kind_set = set(kinds)
    if {"VIEW_FUNCTION_ONLY", "ONCHAIN_STATE_ONLY"}.issubset(kind_set):
        kinds = []
    return sorted(set(kinds)), sorted(set(codes))


def _actual_direction(upstream: str, proposed: str) -> str:
    upstream_rank = SEVERITIES.index(upstream)
    proposed_rank = SEVERITIES.index(proposed)
    if proposed_rank < upstream_rank:
        return "UP"
    if proposed_rank > upstream_rank:
        return "DOWN"
    return "NONE"


def _constituent_dispositions(
    outcomes: Mapping[str, Mapping[str, Any]],
    *,
    resolved: bool,
    resolved_severity: str | None,
    retention_severity: str,
) -> dict[str, dict[str, Any]]:
    """Produce an additive, per-member report disposition.

    A refuted or unresolved member is retained as visible review debt.  It is
    never silently flattened into a grouped tier or deleted from the report
    projection.
    """

    result: dict[str, dict[str, Any]] = {}
    for member in sorted(outcomes):
        row = outcomes[member]
        impact = _text(row.get("impact")).upper()
        likelihood = _text(row.get("likelihood")).upper()
        if "UNRESOLVED" in {impact, likelihood}:
            disposition = "RETAINED_UNRESOLVED"
            severity = retention_severity
            severity_status = "UNRESOLVED_SEVERITY"
        elif "REFUTED" in {impact, likelihood}:
            disposition = "RETAINED_REFUTED_PREMISE"
            severity = retention_severity
            severity_status = "UNRESOLVED_SEVERITY"
        elif resolved and resolved_severity:
            disposition = "INCLUDED_RESOLVED"
            severity = resolved_severity
            severity_status = "RESOLVED"
        else:
            disposition = "RETAINED_UNRESOLVED"
            severity = retention_severity
            severity_status = "UNRESOLVED_SEVERITY"
        result[member] = {
            "impact": impact,
            "likelihood": likelihood,
            "disposition": disposition,
            "severity": severity,
            "severity_status": severity_status,
        }
    return result


def build_severity_decision(
    assessment: Mapping[str, Any], *, _authority_token: object | None = None
) -> dict[str, Any]:
    """Validate one typed assessment and produce a non-dropping decision."""

    if not isinstance(assessment, Mapping):
        raise SeverityDecisionError("severity assessment must be an object")
    missing_top = [field for field in _ASSESSMENT_FIELDS if field not in assessment]
    if missing_top:
        raise SeverityDecisionError("assessment missing fields: " + ", ".join(missing_top))
    candidate_id = _text(assessment.get("candidate_id"))
    if not candidate_id:
        raise SeverityDecisionError("candidate_id is empty")
    constituents = _string_list(
        assessment.get("constituent_ids"), field="constituent_ids"
    )
    upstream = _severity(assessment.get("upstream_severity"), field="upstream_severity")
    proposed = _severity(assessment.get("proposed_severity"), field="proposed_severity")
    assessor = _text(assessment.get("assessor_identity"))
    invocation = _text(assessment.get("assessor_invocation_id"))
    run_id = _text(assessment.get("run_id"))
    source_receipt_digest = _text(
        assessment.get("source_receipt_digest")
    ).casefold()
    if not assessor or not invocation:
        raise SeverityDecisionError("assessment author identity/invocation is required")
    impact, impact_missing = _validate_fact_axis(
        assessment.get("impact"), axis="impact", allowed_classes=IMPACT_CLASSES
    )
    likelihood, likelihood_missing = _validate_fact_axis(
        assessment.get("likelihood"),
        axis="likelihood",
        allowed_classes=LIKELIHOOD_CLASSES,
    )
    if (
        impact is not None
        and likelihood is not None
        and impact.get("premise_id") == likelihood.get("premise_id")
    ):
        raise SeverityDecisionError(
            "impact and likelihood premise IDs must be distinct"
        )
    modifiers, modifier_codes, normalized_modifier_kinds = _normalize_modifiers(
        assessment.get("modifiers")
    )
    adjustment, adjustment_codes = _normalize_adjustment(assessment.get("adjustment"))
    constituent_outcomes, divergent = _constituent_diverges(
        constituents, assessment.get("constituent_premise_outcomes")
    )
    evidence_receipts, evidence_receipts_attested = _normalize_evidence_receipts(
        assessment,
        constituents=constituents,
        impact=impact,
        likelihood=likelihood,
    )
    evidence_capabilities_required = (
        assessment.get("evidence_capabilities_required") is True
    )
    evidence_capabilities_attested = bool(evidence_receipts) and all(
        bool(row.get("capabilities")) for row in evidence_receipts
    )
    producer_authority_binding = _authority_binding(None)
    raw_producer_binding = assessment.get("producer_authority_binding")
    if _authority_token is _DRIVER_AUTHORITY_TOKEN:
        exact_producer = (
            isinstance(raw_producer_binding, Mapping)
            and _text(raw_producer_binding.get("status")).upper() == "EXACT"
        )
        expected_input_sha256 = None
        expected_output_sha256 = None
        if exact_producer:
            proposal_content = _validate_severity_proposal(
                {
                    "schema_version": PROPOSAL_SCHEMA,
                    "candidate_id": candidate_id,
                    "constituent_ids": constituents,
                    "impact": impact,
                    "likelihood": likelihood,
                    "modifiers": modifiers,
                    "proposed_severity": proposed,
                    "adjustment": adjustment,
                    "constituent_premise_outcomes": constituent_outcomes,
                },
                allow_incomplete_axes=True,
            )
            expected_output_sha256 = _digest(proposal_content)
            expected_input_sha256 = severity_assessor_input_digest(
                candidate_id=candidate_id,
                constituent_ids=constituents,
                upstream_severity=upstream,
                run_id=run_id,
                source_receipt_digest=source_receipt_digest,
                evidence_receipts=evidence_receipts,
            )
        producer_authority_binding = _normalize_authority_binding(
            raw_producer_binding,
            role="ASSESSOR",
            run_id=run_id,
            candidate_id=candidate_id,
            constituent_ids=constituents,
            worker_identity=assessor,
            invocation_id=invocation,
            expected_input_sha256=expected_input_sha256,
            expected_output_sha256=expected_output_sha256,
        )
    modifier_kinds, modifier_evidence_codes = _bound_modifier_kinds(
        modifiers,
        evidence_receipts,
        constituents,
        capabilities_required=evidence_capabilities_required,
    )
    # Invalid normalized modifier sets never become tier inputs even if an
    # evidence identifier happens to resolve.
    if set(modifier_codes) & {
        "MODIFIER_SCHEMA_INVALID",
        "MODIFIER_APPLICABILITY_UNPROVEN",
        "INCOMPATIBLE_MODIFIER_SET",
    }:
        modifier_kinds = []
    elif set(modifier_kinds) != set(normalized_modifier_kinds):
        # Keep the normalizer and receipt-binding views in exact agreement.
        modifier_evidence_codes.append("MODIFIER_EVIDENCE_UNBOUND")

    missing_fields = sorted(set(impact_missing + likelihood_missing))
    matrix_severity = None
    if impact is not None and likelihood is not None:
        matrix_severity = _apply_modifiers(
            _matrix(impact["class"], likelihood["class"]), modifier_kinds
        )

    challenge_codes = list(modifier_codes) + list(modifier_evidence_codes)
    if evidence_capabilities_required and not evidence_capabilities_attested:
        challenge_codes.append("EVIDENCE_CAPABILITIES_UNATTESTED")
    if evidence_receipts_attested and not _evidence_is_independently_issued(
        evidence_receipts,
        assessor_identity=assessor,
        assessor_invocation_id=invocation,
    ):
        challenge_codes.append("EVIDENCE_SELF_ATTESTED")
    if divergent:
        challenge_codes.append("CONSTITUENT_OUTCOME_DIVERGENCE")
    if any(
        value == "UNRESOLVED"
        for row in constituent_outcomes.values()
        for value in row.values()
    ):
        challenge_codes.append("CONSTITUENT_PREMISE_UNRESOLVED")
    if any(
        value == "REFUTED"
        for row in constituent_outcomes.values()
        for value in row.values()
    ):
        challenge_codes.append("CONSTITUENT_PREMISE_REFUTED")
    for axis_name, axis in (("impact", impact), ("likelihood", likelihood)):
        if axis is None:
            continue
        if not _evidence_binds(
            evidence_receipts,
            axis["evidence_ids"],
            [axis["premise_id"]],
            constituents,
            required_scope=axis["proof_scope"],
        ):
            challenge_codes.append(f"{axis_name.upper()}_EVIDENCE_UNBOUND")
        if evidence_capabilities_required:
            capabilities = (
                {"IMPACT", "HARM"}
                if axis_name == "impact"
                else {"LIKELIHOOD"}
            )
            if not _evidence_binds(
                evidence_receipts,
                axis["evidence_ids"],
                [axis["premise_id"]],
                constituents,
                required_scope=axis["proof_scope"],
                required_any_capability=capabilities,
            ):
                challenge_codes.append(
                    f"{axis_name.upper()}_EVIDENCE_CAPABILITY_MISSING"
                )
    if matrix_severity is not None and proposed != matrix_severity:
        challenge_codes.append("PROPOSED_MATRIX_DISAGREEMENT")
    if proposed != upstream:
        challenge_codes.append("UPSTREAM_SEVERITY_CHANGE")
        if adjustment is None:
            challenge_codes.append("ADJUSTMENT_BINDING_MISSING")
        challenge_codes.extend(adjustment_codes)
        if adjustment is not None:
            if adjustment.get("direction") != _actual_direction(upstream, proposed):
                challenge_codes.append("ADJUSTMENT_DIRECTION_MISMATCH")
            axis_premises = {
                _text((impact or {}).get("premise_id")),
                _text((likelihood or {}).get("premise_id")),
            } - {""}
            if not set(adjustment.get("premise_ids") or []).issubset(axis_premises):
                challenge_codes.append("ADJUSTMENT_PREMISE_UNBOUND")
            if not _evidence_binds(
                evidence_receipts,
                adjustment.get("evidence_ids") or [],
                adjustment.get("premise_ids") or [],
                constituents,
                required_scope=adjustment.get("proof_scope"),
            ):
                challenge_codes.append("ADJUSTMENT_EVIDENCE_UNBOUND")
            if evidence_capabilities_required:
                axis_capabilities = {
                    _text((impact or {}).get("premise_id")): {"IMPACT", "HARM"},
                    _text((likelihood or {}).get("premise_id")): {"LIKELIHOOD"},
                }
                for premise_id in adjustment.get("premise_ids") or []:
                    required_capabilities = axis_capabilities.get(premise_id)
                    if required_capabilities and not _evidence_binds(
                        evidence_receipts,
                        adjustment.get("evidence_ids") or [],
                        [premise_id],
                        constituents,
                        required_scope=adjustment.get("proof_scope"),
                        required_any_capability=required_capabilities,
                    ):
                        challenge_codes.append(
                            "ADJUSTMENT_EVIDENCE_CAPABILITY_MISSING"
                        )
    elif adjustment is not None:
        # A no-op adjustment is retained for review; it cannot silently affect
        # the decision and does not independently create a tier change.
        challenge_codes.extend(adjustment_codes)
    if modifier_kinds and matrix_severity is not None:
        unmodified = _matrix(impact["class"], likelihood["class"])
        if unmodified != matrix_severity:
            challenge_codes.append("MODIFIER_EFFECT_REQUIRES_ADJUDICATION")
    # R10 is expressed as a premise/evidence rule rather than a competing
    # severity authority.  A favorable fact about an external dependency may
    # not support a downward change unless its exact premise is resolved by a
    # capable external/experimental proof scope.
    if proposed != upstream and SEVERITIES.index(proposed) > SEVERITIES.index(upstream):
        favorable_axes = [
            axis
            for axis in (impact, likelihood)
            if axis is not None and axis.get("premise_kind") == "EXTERNAL_FAVORABLE"
        ]
        adjustment_scope = _text((adjustment or {}).get("proof_scope")).upper()
        capable_external_scopes = {
            "PRIMARY_EXTERNAL_CITED",
            "IN_SCOPE_EXECUTION",
            "FORMAL_PROOF",
        }
        if favorable_axes and (
            adjustment_scope not in capable_external_scopes
            or any(axis.get("proof_scope") not in capable_external_scopes for axis in favorable_axes)
        ):
            challenge_codes.append("EXTERNAL_FAVORABLE_PREMISE_UNPROVEN")
        if favorable_axes and evidence_capabilities_required:
            for axis in favorable_axes:
                if not _evidence_binds(
                    evidence_receipts,
                    axis.get("evidence_ids") or [],
                    [axis.get("premise_id")],
                    constituents,
                    required_scope=axis.get("proof_scope"),
                    required_any_capability={"EXTERNAL_FACT"},
                ):
                    challenge_codes.append("EXTERNAL_FACT_CAPABILITY_MISSING")

    known_premises = sorted({
        _text((impact or {}).get("premise_id")),
        _text((likelihood or {}).get("premise_id")),
    } - {""})
    if missing_fields:
        status = "INCOMPLETE"
        final = None
    elif challenge_codes:
        status = "CHALLENGE_REQUIRED"
        final = None
    else:
        status = "RESOLVED"
        final = proposed
    normalized_assessment = {
        "schema_version": ASSESSMENT_SCHEMA,
        "run_id": run_id,
        "source_receipt_digest": source_receipt_digest,
        "candidate_id": candidate_id,
        "constituent_ids": constituents,
        "upstream_severity": upstream,
        "assessor_identity": assessor,
        "assessor_invocation_id": invocation,
        "impact": impact,
        "likelihood": likelihood,
        "modifiers": modifiers,
        "proposed_severity": proposed,
        "adjustment": adjustment,
        "constituent_premise_outcomes": constituent_outcomes,
        "evidence_receipts": evidence_receipts,
        "evidence_receipts_attested": evidence_receipts_attested,
        "evidence_capabilities_required": evidence_capabilities_required,
        "evidence_capabilities_attested": evidence_capabilities_attested,
        "producer_authority_binding": producer_authority_binding,
    }
    unsigned = {
        "schema_version": DECISION_SCHEMA,
        "run_id": run_id,
        "source_receipt_digest": source_receipt_digest,
        "candidate_id": candidate_id,
        "constituent_ids": constituents,
        "assessment": normalized_assessment,
        "matrix_severity": matrix_severity,
        "upstream_severity": upstream,
        "proposed_severity": proposed,
        "retention_severity": upstream,
        "final_severity": final,
        "status": status,
        "missing_fields": missing_fields,
        "challenge_codes": sorted(set(challenge_codes)),
        "known_premise_ids": known_premises,
        "constituent_dispositions": _constituent_dispositions(
            constituent_outcomes,
            resolved=status == "RESOLVED",
            resolved_severity=final,
            retention_severity=upstream,
        ),
        "adjudication": None,
        "adjudication_history": [],
    }
    return _decision_with_digest(unsigned)


def _validate_decision(decision: Mapping[str, Any]) -> None:
    if decision.get("schema_version") != DECISION_SCHEMA:
        raise SeverityDecisionError("severity decision schema mismatch")
    claimed = decision.get("decision_digest")
    unsigned = {key: value for key, value in decision.items() if key != "decision_digest"}
    if claimed != _digest(unsigned):
        raise SeverityDecisionError("severity decision digest mismatch")


def build_severity_repair_request(decision: Mapping[str, Any]) -> dict[str, Any]:
    _validate_decision(decision)
    missing = list(decision.get("missing_fields") or [])
    if not missing:
        raise SeverityDecisionError("severity decision has no missing typed delta")
    unsigned = {
        "schema_version": REPAIR_SCHEMA,
        "candidate_id": decision["candidate_id"],
        "decision_digest": decision["decision_digest"],
        "missing_fields": missing,
        "instruction": "Return only the missing typed severity fields; preserve all bound facts.",
    }
    return {**unsigned, "repair_digest": _digest(unsigned)}


def _infer_compatibility_axes(
    source: Mapping[str, Any], premise_ids: list[str], target: str
) -> dict[str, str] | None:
    """Legacy-only inference for unattested, non-report-authoritative rows."""

    impact = source.get("impact")
    likelihood = source.get("likelihood")
    if not isinstance(impact, Mapping) or not isinstance(likelihood, Mapping):
        return None
    resolved = set(premise_ids)
    impact_values = (
        IMPACT_CLASSES if impact.get("premise_id") in resolved else (impact.get("class"),)
    )
    likelihood_values = (
        LIKELIHOOD_CLASSES
        if likelihood.get("premise_id") in resolved
        else (likelihood.get("class"),)
    )
    _, modifier_errors, modifier_kinds = _normalize_modifiers(
        source.get("modifiers", [])
    )
    if modifier_errors:
        modifier_kinds = []
    matches = [
        {"impact": impact_value, "likelihood": likelihood_value}
        for impact_value in impact_values
        for likelihood_value in likelihood_values
        if impact_value in IMPACT_CLASSES
        and likelihood_value in LIKELIHOOD_CLASSES
        and _apply_modifiers(
            _matrix(impact_value, likelihood_value), modifier_kinds
        ) == target
    ]
    return matches[0] if len(matches) == 1 else None


def _normalize_resolved_axes(value: Any) -> dict[str, str] | None:
    if not isinstance(value, Mapping) or set(value) != {"impact", "likelihood"}:
        return None
    impact = _text(value.get("impact")).title()
    likelihood = _text(value.get("likelihood")).title()
    if impact == "Info":
        impact = "Informational"
    if impact not in IMPACT_CLASSES or likelihood not in LIKELIHOOD_CLASSES:
        return None
    return {"impact": impact, "likelihood": likelihood}


def _normalize_constituent_resolutions(
    value: Any, members: list[str]
) -> dict[str, dict[str, str]] | None:
    if not isinstance(value, Mapping) or set(value) != set(members):
        return None
    normalized: dict[str, dict[str, str]] = {}
    for member in members:
        row = value.get(member)
        if not isinstance(row, Mapping) or set(row) != {"impact", "likelihood"}:
            return None
        impact = _text(row.get("impact")).upper()
        likelihood = _text(row.get("likelihood")).upper()
        if impact not in {"SUPPORTED", "REFUTED", "UNRESOLVED"} or likelihood not in {
            "SUPPORTED",
            "REFUTED",
            "UNRESOLVED",
        }:
            return None
        normalized[member] = {"impact": impact, "likelihood": likelihood}
    return normalized


def _event_context(decision: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "run_id": _text(decision.get("run_id")),
        "source_receipt_digest": _text(decision.get("source_receipt_digest")).casefold(),
        "source_decision_digest": _text(decision.get("decision_digest")).casefold(),
        "candidate_id": _text(decision.get("candidate_id")),
        "constituent_ids": list(decision.get("constituent_ids") or []),
        "prior_severity": _text(decision.get("retention_severity")).title(),
    }


def _validate_adjudication_proposal(value: Mapping[str, Any]) -> dict[str, Any]:
    _validate_bounded_json(value, field="severity adjudication proposal")
    proposal = dict(_require_exact_keys(
        value,
        _ADJUDICATION_PROPOSAL_FIELDS,
        field="severity adjudication proposal",
    ))
    if proposal.get("schema_version") != ADJUDICATION_PROPOSAL_SCHEMA:
        raise SeverityDecisionError("severity adjudication proposal schema mismatch")
    decision = proposal.get("decision")
    if not isinstance(decision, str) or decision not in {
        "ACCEPT_PROPOSED",
        "ACCEPT_MATRIX",
        "ACCEPT_UPSTREAM",
        "UNRESOLVED",
    }:
        raise SeverityDecisionError(
            "severity adjudication proposal decision enum is invalid"
        )
    resolved_severity = proposal.get("resolved_severity")
    if resolved_severity is not None:
        resolved_severity = _proposal_string(
            resolved_severity,
            field="severity adjudication resolved_severity",
        )
        if resolved_severity not in SEVERITIES:
            raise SeverityDecisionError(
                "severity adjudication resolved_severity enum is invalid"
            )
    elif decision != "UNRESOLVED":
        raise SeverityDecisionError(
            "severity adjudication resolved_severity is required"
        )
    if decision == "UNRESOLVED":
        if resolved_severity is not None or proposal.get("resolved_axes") is not None:
            raise SeverityDecisionError(
                "unresolved severity adjudication cannot claim resolved axes"
            )
        if proposal.get("proof_scope") is not None:
            raise SeverityDecisionError(
                "unresolved severity adjudication cannot claim a proof scope"
            )
    else:
        resolved_axes = _require_exact_keys(
            proposal.get("resolved_axes"),
            ("impact", "likelihood"),
            field="severity adjudication proposal resolved_axes",
        )
        impact_axis = resolved_axes.get("impact")
        likelihood_axis = resolved_axes.get("likelihood")
        if (
            not isinstance(impact_axis, str)
            or impact_axis not in IMPACT_CLASSES
            or not isinstance(likelihood_axis, str)
            or likelihood_axis not in LIKELIHOOD_CLASSES
        ):
            raise SeverityDecisionError(
                "severity adjudication resolved_axes enum is invalid"
            )
        proof_scope = proposal.get("proof_scope")
        if not isinstance(proof_scope, str) or proof_scope not in PROOF_SCOPES:
            raise SeverityDecisionError(
                "severity adjudication proof_scope enum is invalid"
            )
    _proposal_string(
        proposal.get("rationale"),
        field="severity adjudication rationale",
    )
    resolutions = proposal.get("constituent_resolutions")
    if not isinstance(resolutions, Mapping):
        raise SeverityDecisionError(
            "severity adjudication constituent resolutions must be an object"
        )
    if decision == "UNRESOLVED" and resolutions:
        raise SeverityDecisionError(
            "unresolved severity adjudication cannot claim constituent resolutions"
        )
    resolution_keys = list(resolutions)
    if len(resolution_keys) != len(
        {str(identity).casefold() for identity in resolution_keys}
    ):
        raise SeverityDecisionError(
            "severity adjudication constituent resolutions contain "
            "case-insensitive duplicate identities"
        )
    for identity, row in resolutions.items():
        normalized_identity = _proposal_identifier(
            identity,
            field="severity adjudication constituent identity",
        )
        _require_exact_keys(
            row,
            ("impact", "likelihood"),
            field=f"severity adjudication constituent {identity}",
        )
        impact_state = row.get("impact")
        likelihood_state = row.get("likelihood")
        if not isinstance(impact_state, str) or impact_state not in {
            "SUPPORTED", "REFUTED", "UNRESOLVED"
        } or not isinstance(likelihood_state, str) or likelihood_state not in {
            "SUPPORTED", "REFUTED", "UNRESOLVED"
        }:
            raise SeverityDecisionError(
                f"severity adjudication constituent {identity} enum is invalid"
            )
    for field in ("resolved_premise_ids", "evidence_ids"):
        values = _proposal_string_list(
            proposal.get(field),
            field=f"severity adjudication {field}",
            nonempty=False,
        )
        if decision == "UNRESOLVED" and values:
            raise SeverityDecisionError(
                f"unresolved severity adjudication cannot claim {field}"
            )
        if decision != "UNRESOLVED" and not values:
            raise SeverityDecisionError(
                f"resolved severity adjudication requires {field}"
            )
    return proposal


def parse_severity_adjudication_proposal(
    value: str | bytes | Mapping[str, Any],
) -> dict[str, Any]:
    if isinstance(value, Mapping):
        return _validate_adjudication_proposal(value)
    try:
        text = _bounded_raw_text(value, field="severity adjudication proposal")
        payload = json.loads(
            text,
            object_pairs_hook=_strict_json_object,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise SeverityDecisionError(
            f"severity adjudication proposal JSON is invalid: {exc}"
        ) from exc
    if not isinstance(payload, Mapping):
        raise SeverityDecisionError(
            "severity adjudication proposal must be a JSON object"
        )
    return _validate_adjudication_proposal(payload)


def bind_severity_adjudication(
    proposal: Mapping[str, Any],
    *,
    decision: Mapping[str, Any],
    adjudicator_launch_receipt: Mapping[str, Any],
) -> dict[str, Any]:
    """Bind content-only adjudication to a distinct driver launch receipt."""

    normalized = _validate_adjudication_proposal(proposal)
    _validate_decision_semantics(decision)
    receipt_value = dict(_require_exact_keys(
        adjudicator_launch_receipt,
        _LAUNCH_RECEIPT_FIELDS,
        field="severity adjudicator launch receipt",
    ))
    identity = _text(receipt_value.get("worker_identity"))
    invocation = _text(receipt_value.get("invocation_id"))
    context = _event_context(decision)
    receipt = _normalize_launch_receipt(
        receipt_value,
        role="ADJUDICATOR",
        run_id=context["run_id"],
        candidate_id=context["candidate_id"],
        constituent_ids=context["constituent_ids"],
        worker_identity=identity,
        invocation_id=invocation,
        expected_input_sha256=severity_adjudicator_input_digest(decision),
        expected_output_sha256=_digest(normalized),
    )
    source = decision.get("assessment") or {}
    producer_binding = source.get("producer_authority_binding") or {}
    producer_receipt = producer_binding.get("receipt") or {}
    if (
        not identity
        or not invocation
        or identity.casefold()
        == _text(source.get("assessor_identity")).casefold()
        or invocation.casefold()
        == _text(source.get("assessor_invocation_id")).casefold()
        or _text(receipt_value.get("launch_manifest_sha256")).casefold()
        == _text(producer_receipt.get("launch_manifest_sha256")).casefold()
    ):
        raise SeverityDecisionError(
            "severity adjudicator is not a distinct launcher principal"
        )
    event = {
        **{key: value for key, value in normalized.items() if key != "schema_version"},
        **context,
        "adjudicator_identity": identity,
        "adjudicator_invocation_id": invocation,
        "adjudicator_authority_binding": _authority_binding(receipt),
    }
    return adjudicate_severity_challenge(
        decision, event, _authority_token=_DRIVER_AUTHORITY_TOKEN
    )


def adjudicate_severity_challenge(
    decision: Mapping[str, Any],
    adjudication: Mapping[str, Any],
    *,
    _authority_token: object | None = None,
) -> dict[str, Any]:
    """Apply one independently authored, premise-bound severity decision."""

    _validate_decision(decision)
    updated = {key: value for key, value in decision.items() if key != "decision_digest"}
    challenge_codes = set(updated.get("challenge_codes") or [])
    if not isinstance(adjudication, Mapping):
        raise SeverityDecisionError("severity adjudication must be an object")
    source = updated["assessment"]
    identity = _text(adjudication.get("adjudicator_identity"))
    invocation = _text(adjudication.get("adjudicator_invocation_id"))
    adjudication_decision = _text(adjudication.get("decision")).upper()
    premise_ids = (
        [
            _text(item)
            for item in adjudication.get("resolved_premise_ids", [])
            if _text(item)
        ]
        if isinstance(adjudication.get("resolved_premise_ids"), list)
        else []
    )
    evidence_ids = (
        [
            _text(item)
            for item in adjudication.get("evidence_ids", [])
            if _text(item)
        ]
        if isinstance(adjudication.get("evidence_ids"), list)
        else []
    )
    proof_scope = (
        None
        if adjudication.get("proof_scope") is None
        else _text(adjudication.get("proof_scope")).upper()
    )
    raw_rationale = adjudication.get("rationale")
    # A launch receipt binds the exact proposal bytes.  Preserve legitimate
    # free-form whitespace here so the durable event remains replayable against
    # that receipt; identifier fields remain canonicalized separately.
    rationale = (
        raw_rationale
        if isinstance(raw_rationale, str)
        else _text(raw_rationale)
    )
    resolved_raw = adjudication.get("resolved_severity")
    members = list(updated.get("constituent_ids") or [])
    exact_context = _event_context(decision)
    attested = source.get("evidence_receipts_attested") is True
    raw_constituents = adjudication.get("constituent_ids")
    adjudicator_authority_binding = _authority_binding(None)
    raw_adjudicator_binding = adjudication.get("adjudicator_authority_binding")
    if _authority_token is _DRIVER_AUTHORITY_TOKEN:
        exact_adjudicator = (
            isinstance(raw_adjudicator_binding, Mapping)
            and _text(raw_adjudicator_binding.get("status")).upper() == "EXACT"
        )
        expected_input_sha256 = None
        expected_output_sha256 = None
        if exact_adjudicator:
            proposal_content = _validate_adjudication_proposal(
                {
                    "schema_version": ADJUDICATION_PROPOSAL_SCHEMA,
                    **{
                        field: adjudication.get(field)
                        for field in _ADJUDICATION_PROPOSAL_FIELDS
                        if field != "schema_version"
                    },
                }
            )
            expected_output_sha256 = _digest(proposal_content)
            expected_input_sha256 = severity_adjudicator_input_digest(decision)
        adjudicator_authority_binding = _normalize_authority_binding(
            raw_adjudicator_binding,
            role="ADJUDICATOR",
            run_id=exact_context["run_id"],
            candidate_id=exact_context["candidate_id"],
            constituent_ids=exact_context["constituent_ids"],
            worker_identity=identity,
            invocation_id=invocation,
            expected_input_sha256=expected_input_sha256,
            expected_output_sha256=expected_output_sha256,
        )
    supplied_context = {
        "run_id": _text(adjudication.get("run_id")),
        "source_receipt_digest": _text(
            adjudication.get("source_receipt_digest")
        ).casefold(),
        "source_decision_digest": _text(
            adjudication.get("source_decision_digest")
        ).casefold(),
        "candidate_id": _text(adjudication.get("candidate_id")),
        "constituent_ids": (
            [_text(item) for item in raw_constituents]
            if isinstance(raw_constituents, list)
            else []
        ),
        "prior_severity": _text(adjudication.get("prior_severity")).title(),
    }
    if attested:
        context = supplied_context
        binding_status = (
            "EXACT" if supplied_context == exact_context else "INVALID"
        )
        if binding_status != "EXACT":
            challenge_codes.add("ADJUDICATION_CONTEXT_UNBOUND")
    else:
        # Compatibility decisions may remain inspectable in memory, but the
        # auto-bound event and its source row can never gain report authority.
        context = exact_context
        binding_status = "UNATTESTED_COMPATIBILITY"

    explicit_axes = _normalize_resolved_axes(adjudication.get("resolved_axes"))

    normalized_adjudication = {
        "schema_version": ADJUDICATION_SCHEMA,
        **context,
        "binding_status": binding_status,
        "adjudicator_identity": identity,
        "adjudicator_invocation_id": invocation,
        "decision": adjudication_decision,
        "resolved_severity": _text(resolved_raw).title() if resolved_raw else None,
        "resolved_premise_ids": premise_ids,
        "evidence_ids": evidence_ids,
        "proof_scope": proof_scope,
        "rationale": rationale,
        "resolved_axes": explicit_axes,
        "constituent_resolutions": (
            dict(adjudication.get("constituent_resolutions"))
            if isinstance(adjudication.get("constituent_resolutions"), Mapping)
            else {}
        ),
        "adjudicator_authority_binding": adjudicator_authority_binding,
    }
    if (
        source.get("evidence_capabilities_required") is True
        and adjudicator_authority_binding.get("status") != "EXACT"
    ):
        challenge_codes.add("ADJUDICATION_AUTHORITY_UNBOUND")
    if (
        not identity
        or not invocation
        or identity.casefold()
        == _text(source["assessor_identity"]).casefold()
        or invocation.casefold()
        == _text(source["assessor_invocation_id"]).casefold()
    ):
        challenge_codes.add("SELF_ADJUDICATION")
    prior_history = list(updated.get("adjudication_history") or [])
    if prior_history:
        challenge_codes.add("ADJUDICATION_CONFLICT")
        history = [*prior_history, normalized_adjudication]
        source_outcomes = source.get("constituent_premise_outcomes") or {}
        updated.update(
            {
                "status": "UNRESOLVED_SEVERITY",
                "final_severity": None,
                "challenge_codes": sorted(challenge_codes),
                "adjudication": normalized_adjudication,
                "adjudication_history": history,
                "constituent_dispositions": _constituent_dispositions(
                    source_outcomes,
                    resolved=False,
                    resolved_severity=None,
                    retention_severity=updated["retention_severity"],
                ),
            }
        )
        return _decision_with_digest(updated)
    if adjudication_decision == "UNRESOLVED":
        history = [normalized_adjudication]
        source_outcomes = source.get("constituent_premise_outcomes") or {}
        updated.update(
            {
                "status": "UNRESOLVED_SEVERITY",
                "final_severity": None,
                "challenge_codes": sorted(challenge_codes),
                "adjudication": normalized_adjudication,
                "adjudication_history": history,
                "constituent_dispositions": _constituent_dispositions(
                    source_outcomes,
                    resolved=False,
                    resolved_severity=None,
                    retention_severity=updated["retention_severity"],
                ),
            }
        )
        return _decision_with_digest(updated)

    expected_by_decision = {
        "ACCEPT_PROPOSED": updated.get("proposed_severity"),
        "ACCEPT_MATRIX": updated.get("matrix_severity"),
        "ACCEPT_UPSTREAM": updated.get("upstream_severity"),
    }
    expected = expected_by_decision.get(adjudication_decision)
    if expected is None:
        challenge_codes.add("ADJUDICATION_DECISION_INVALID")
    if not premise_ids or not set(premise_ids).issubset(
        set(updated.get("known_premise_ids") or [])
    ):
        challenge_codes.add("ADJUDICATION_PREMISE_UNBOUND")
    if not evidence_ids or proof_scope not in PROOF_SCOPES:
        challenge_codes.add("ADJUDICATION_EVIDENCE_INCAPABLE")
    elif not _evidence_binds(
        source.get("evidence_receipts") or [],
        evidence_ids,
        premise_ids,
        updated.get("constituent_ids") or [],
        required_scope=proof_scope,
    ):
        challenge_codes.add("ADJUDICATION_EVIDENCE_UNBOUND")
    if source.get("evidence_capabilities_required") is True and premise_ids:
        axis_sources_for_capability = {
            _text((source.get("impact") or {}).get("premise_id")): (
                source.get("impact"), {"IMPACT", "HARM"}
            ),
            _text((source.get("likelihood") or {}).get("premise_id")): (
                source.get("likelihood"), {"LIKELIHOOD"}
            ),
        }
        capable_external_scopes = {
            "PRIMARY_EXTERNAL_CITED",
            "IN_SCOPE_EXECUTION",
            "FORMAL_PROOF",
        }
        for premise_id in premise_ids:
            axis_row = axis_sources_for_capability.get(premise_id)
            if axis_row is None:
                continue
            axis, required_capabilities = axis_row
            if not _evidence_binds(
                source.get("evidence_receipts") or [],
                evidence_ids,
                [premise_id],
                updated.get("constituent_ids") or [],
                required_scope=proof_scope,
                required_any_capability=required_capabilities,
            ):
                challenge_codes.add(
                    "ADJUDICATION_EVIDENCE_CAPABILITY_MISSING"
                )
            if (
                isinstance(axis, Mapping)
                and axis.get("premise_kind") == "EXTERNAL_FAVORABLE"
                and (
                    proof_scope not in capable_external_scopes
                    or not _evidence_binds(
                        source.get("evidence_receipts") or [],
                        evidence_ids,
                        [premise_id],
                        updated.get("constituent_ids") or [],
                        required_scope=proof_scope,
                        required_any_capability={"EXTERNAL_FACT"},
                    )
                )
            ):
                challenge_codes.add("ADJUDICATION_EXTERNAL_FACT_INCAPABLE")
    if not rationale.strip():
        challenge_codes.add("ADJUDICATION_RATIONALE_MISSING")
    try:
        resolved = _severity(resolved_raw, field="resolved_severity")
    except SeverityDecisionError:
        resolved = None
        challenge_codes.add("ADJUDICATION_SEVERITY_INVALID")
    if expected is not None and resolved != expected:
        challenge_codes.add("ADJUDICATION_SEVERITY_MISMATCH")
    resolved_axes = explicit_axes
    if resolved_axes is None and not attested and resolved is not None:
        resolved_axes = _infer_compatibility_axes(source, premise_ids, resolved)
    if resolved is not None and resolved_axes is None:
        challenge_codes.add("ADJUDICATION_AXES_UNRESOLVED")
    normalized_adjudication["resolved_axes"] = resolved_axes

    impact_axis = source.get("impact") if isinstance(source.get("impact"), Mapping) else {}
    likelihood_axis = (
        source.get("likelihood")
        if isinstance(source.get("likelihood"), Mapping)
        else {}
    )
    axis_sources = {"impact": impact_axis, "likelihood": likelihood_axis}
    if resolved_axes is not None:
        for axis_name, axis_source in axis_sources.items():
            if (
                axis_source.get("premise_id") not in set(premise_ids)
                and resolved_axes[axis_name] != axis_source.get("class")
            ):
                challenge_codes.add("ADJUDICATION_AXIS_SCOPE_INVALID")
        _, source_modifier_codes, _ = _normalize_modifiers(source.get("modifiers", []))
        bound_modifier_kinds, binding_codes = _bound_modifier_kinds(
            source.get("modifiers", []),
            source.get("evidence_receipts") or [],
            members,
            capabilities_required=(
                source.get("evidence_capabilities_required") is True
            ),
        )
        if source_modifier_codes or binding_codes:
            bound_modifier_kinds = []
        calculated = _apply_modifiers(
            _matrix(resolved_axes["impact"], resolved_axes["likelihood"]),
            bound_modifier_kinds,
        )
        if resolved is not None and calculated != resolved:
            challenge_codes.add("ADJUDICATION_AXES_SEVERITY_MISMATCH")

    source_outcomes = source.get("constituent_premise_outcomes") or {}
    source_signatures = {
        tuple(sorted((source_outcomes.get(member) or {}).items()))
        for member in members
    }
    needs_member_resolution = (
        len(source_signatures) > 1
        or any(
            state != "SUPPORTED"
            for member in members
            for state in (source_outcomes.get(member) or {}).values()
        )
    )
    raw_member_resolutions = adjudication.get("constituent_resolutions")
    member_resolutions = (
        _normalize_constituent_resolutions(raw_member_resolutions, members)
        if raw_member_resolutions
        else None
    )
    if raw_member_resolutions and member_resolutions is None:
        challenge_codes.add("ADJUDICATION_CONSTITUENT_SCOPE_UNRESOLVED")
    if needs_member_resolution and member_resolutions is None:
        challenge_codes.add("ADJUDICATION_CONSTITUENT_SCOPE_UNRESOLVED")
    effective_outcomes = member_resolutions or {
        member: dict(source_outcomes.get(member) or {}) for member in members
    }
    for member in members:
        for axis_name, axis_source in axis_sources.items():
            before = _text((source_outcomes.get(member) or {}).get(axis_name)).upper()
            after = _text((effective_outcomes.get(member) or {}).get(axis_name)).upper()
            premise_was_resolved = axis_source.get("premise_id") in set(premise_ids)
            if before != after and not premise_was_resolved:
                challenge_codes.add("ADJUDICATION_AXIS_SCOPE_INVALID")
            if before == "UNRESOLVED" and not premise_was_resolved:
                challenge_codes.add("ADJUDICATION_AXIS_SCOPE_INVALID")
            if after == "UNRESOLVED":
                challenge_codes.add("ADJUDICATION_CONSTITUENT_SCOPE_UNRESOLVED")
    normalized_adjudication["constituent_resolutions"] = (
        member_resolutions or {}
    )

    terminal_source_blockers = {
        "ADJUSTMENT_BINDING_MISSING",
        "ADJUSTMENT_SCHEMA_INVALID",
        "ADJUSTMENT_DIRECTION_INVALID",
        "ADJUSTMENT_PREMISE_MISSING",
        "ADJUSTMENT_EVIDENCE_MISSING",
        "ADJUSTMENT_PROOF_SCOPE_INVALID",
        "ADJUSTMENT_RATIONALE_MISSING",
        "ADJUSTMENT_DIRECTION_MISMATCH",
        "ADJUSTMENT_PREMISE_UNBOUND",
        "ADJUSTMENT_EVIDENCE_UNBOUND",
        "IMPACT_EVIDENCE_UNBOUND",
        "LIKELIHOOD_EVIDENCE_UNBOUND",
        "MODIFIER_SCHEMA_INVALID",
        "MODIFIER_APPLICABILITY_UNPROVEN",
        "MODIFIER_EVIDENCE_UNBOUND",
        "MODIFIER_EVIDENCE_CAPABILITY_MISSING",
        "INCOMPATIBLE_MODIFIER_SET",
        "EVIDENCE_SELF_ATTESTED",
        "EVIDENCE_CAPABILITIES_UNATTESTED",
        "IMPACT_EVIDENCE_CAPABILITY_MISSING",
        "LIKELIHOOD_EVIDENCE_CAPABILITY_MISSING",
        "ADJUSTMENT_EVIDENCE_CAPABILITY_MISSING",
        "EXTERNAL_FACT_CAPABILITY_MISSING",
    }
    if terminal_source_blockers & challenge_codes or updated.get("missing_fields"):
        challenge_codes.add("ADJUDICATION_SOURCE_AUTHORITY_INVALID")

    adjudication_errors = {
        code
        for code in challenge_codes
        if code.startswith("ADJUDICATION_") or code == "SELF_ADJUDICATION"
    }
    history = [normalized_adjudication]
    if adjudication_errors:
        updated.update(
            {
                "status": "UNRESOLVED_SEVERITY",
                "final_severity": None,
                "challenge_codes": sorted(challenge_codes),
                "adjudication": normalized_adjudication,
                "adjudication_history": history,
            }
        )
    else:
        updated.update(
            {
                "status": "RESOLVED",
                "final_severity": resolved,
                "challenge_codes": sorted(challenge_codes),
                "adjudication": normalized_adjudication,
                "adjudication_history": history,
            }
        )
    updated["constituent_dispositions"] = _constituent_dispositions(
        effective_outcomes,
        resolved=updated.get("status") == "RESOLVED",
        resolved_severity=updated.get("final_severity"),
        retention_severity=updated["retention_severity"],
    )
    return _decision_with_digest(updated)


def required_assessment_fields() -> tuple[str, ...]:
    return _ASSESSMENT_FIELDS


def required_proposal_fields() -> tuple[str, ...]:
    return _PROPOSAL_FIELDS


def compile_severity_prompt_contract() -> dict[str, Any]:
    """Compile the exact model proposal schema, excluding authority fields."""

    nonempty_string = {
        "type": "string",
        "minLength": 1,
        "pattern": r".*\S.*",
    }
    evidence_ids = {
        "type": "array",
        "items": dict(nonempty_string),
        "minItems": 1,
        "uniqueItems": True,
    }
    proof_scope = {"type": "string", "enum": sorted(PROOF_SCOPES)}
    premise_kind = {"type": "string", "enum": sorted(PREMISE_KINDS)}
    impact_properties = {
        "class": {"type": "string", "enum": list(IMPACT_CLASSES)},
        "harmed_asset": dict(nonempty_string),
        "harmed_capability": dict(nonempty_string),
        "premise_id": dict(nonempty_string),
        "premise_kind": premise_kind,
        "evidence_ids": evidence_ids,
        "proof_scope": proof_scope,
    }
    likelihood_properties = {
        "class": {"type": "string", "enum": list(LIKELIHOOD_CLASSES)},
        "actor": dict(nonempty_string),
        "preconditions": {
            "type": "array",
            "items": dict(nonempty_string),
            "minItems": 1,
            "uniqueItems": True,
        },
        "premise_id": dict(nonempty_string),
        "premise_kind": premise_kind,
        "evidence_ids": evidence_ids,
        "proof_scope": proof_scope,
    }
    modifier_properties = {
        "kind": {"type": "string", "enum": sorted(MODIFIER_KINDS)},
        "applies": {"type": "boolean"},
        "applicability_predicate": {"type": "string"},
        "evidence_ids": {
            "type": "array",
            "items": dict(nonempty_string),
            "uniqueItems": True,
        },
        "proof_scope": proof_scope,
    }
    adjustment_properties = {
        "direction": {"type": "string", "enum": ["UP", "DOWN"]},
        "premise_ids": evidence_ids,
        "evidence_ids": evidence_ids,
        "proof_scope": proof_scope,
        "rationale": dict(nonempty_string),
    }
    outcome_schema = {
        "type": "object",
        "additionalProperties": False,
        "required": ["impact", "likelihood"],
        "properties": {
            "impact": {
                "type": "string",
                "enum": ["SUPPORTED", "REFUTED", "UNRESOLVED"],
            },
            "likelihood": {
                "type": "string",
                "enum": ["SUPPORTED", "REFUTED", "UNRESOLVED"],
            },
        },
    }
    schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "additionalProperties": False,
        "required": list(_PROPOSAL_FIELDS),
        "properties": {
            "schema_version": {"const": PROPOSAL_SCHEMA},
            "candidate_id": dict(nonempty_string),
            "constituent_ids": {
                "type": "array",
                "items": dict(nonempty_string),
                "minItems": 1,
                "uniqueItems": True,
            },
            "impact": {
                "type": "object",
                "additionalProperties": False,
                "required": list(impact_properties),
                "properties": impact_properties,
            },
            "likelihood": {
                "type": "object",
                "additionalProperties": False,
                "required": list(likelihood_properties),
                "properties": likelihood_properties,
            },
            "modifiers": {
                "type": "array",
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": list(modifier_properties),
                    "properties": modifier_properties,
                },
            },
            "proposed_severity": {"type": "string", "enum": list(SEVERITIES)},
            "adjustment": {
                "anyOf": [
                    {"type": "null"},
                    {
                        "type": "object",
                        "additionalProperties": False,
                        "required": list(adjustment_properties),
                        "properties": adjustment_properties,
                    },
                ]
            },
            "constituent_premise_outcomes": {
                "type": "object",
                "minProperties": 1,
                "propertyNames": {"minLength": 1},
                "additionalProperties": outcome_schema,
            },
        },
    }
    schema_json = json.dumps(schema, sort_keys=True)
    lines = [
        "## Typed severity proposal (mandatory)",
        "",
        "Emit exactly one JSON object matching this schema. Candidate retention is independent of severity.",
        "The driver, not the model, binds run identity, source receipts, assessor identity, and evidence authority.",
        "",
        schema_json,
    ]
    return {
        "schema_version": PROPOSAL_SCHEMA,
        "required_fields": list(_PROPOSAL_FIELDS),
        "json_schema": schema,
        "markdown": "\n".join(lines) + "\n",
    }


def compile_severity_adjudication_prompt_contract() -> dict[str, Any]:
    """Compile the one content-only adjudicator schema and checklist.

    The compiler is backend-neutral and is deliberately sourced from the same
    field tuple and enum sets as :func:`parse_severity_adjudication_proposal`.
    Launcher identity, run binding, and source authority remain driver-owned.
    An honest ``UNRESOLVED`` result carries no invented severity, axes, premise
    resolution, evidence authority, or proof scope.
    """

    nonempty_string = {
        "type": "string",
        "minLength": 1,
        "pattern": r".*\S.*",
    }
    canonical_identifier = {
        "type": "string",
        "minLength": 1,
        "pattern": (
            r"^(?!.*[\u0000-\u001f\u007f\u2028\u2029])"
            r"\S(?:.*\S)?$"
        ),
    }
    string_array = {
        "type": "array",
        "items": dict(canonical_identifier),
        "uniqueItems": True,
    }
    axes_schema = {
        "type": "object",
        "additionalProperties": False,
        "required": ["impact", "likelihood"],
        "properties": {
            "impact": {"type": "string", "enum": list(IMPACT_CLASSES)},
            "likelihood": {
                "type": "string",
                "enum": list(LIKELIHOOD_CLASSES),
            },
        },
    }
    constituent_resolution_schema = {
        "type": "object",
        "additionalProperties": False,
        "required": ["impact", "likelihood"],
        "properties": {
            "impact": {
                "type": "string",
                "enum": ["SUPPORTED", "REFUTED", "UNRESOLVED"],
            },
            "likelihood": {
                "type": "string",
                "enum": ["SUPPORTED", "REFUTED", "UNRESOLVED"],
            },
        },
    }
    schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "additionalProperties": False,
        "required": list(_ADJUDICATION_PROPOSAL_FIELDS),
        "properties": {
            "schema_version": {"const": ADJUDICATION_PROPOSAL_SCHEMA},
            "decision": {
                "type": "string",
                "enum": [
                    "ACCEPT_PROPOSED",
                    "ACCEPT_MATRIX",
                    "ACCEPT_UPSTREAM",
                    "UNRESOLVED",
                ],
            },
            "resolved_severity": {
                "anyOf": [
                    {"type": "null"},
                    {"type": "string", "enum": list(SEVERITIES)},
                ]
            },
            "resolved_premise_ids": dict(string_array),
            "evidence_ids": dict(string_array),
            "proof_scope": {
                "anyOf": [
                    {"type": "null"},
                    {"type": "string", "enum": sorted(PROOF_SCOPES)},
                ]
            },
            "rationale": dict(nonempty_string),
            "resolved_axes": {
                "anyOf": [{"type": "null"}, axes_schema]
            },
            "constituent_resolutions": {
                "type": "object",
                "propertyNames": dict(canonical_identifier),
                "additionalProperties": constituent_resolution_schema,
            },
        },
        "allOf": [
            {
                "if": {
                    "properties": {"decision": {"const": "UNRESOLVED"}},
                    "required": ["decision"],
                },
                "then": {
                    "properties": {
                        "resolved_severity": {"type": "null"},
                        "resolved_premise_ids": {"maxItems": 0},
                        "evidence_ids": {"maxItems": 0},
                        "proof_scope": {"type": "null"},
                        "resolved_axes": {"type": "null"},
                        "constituent_resolutions": {"maxProperties": 0},
                    }
                },
                "else": {
                    "properties": {
                        "resolved_severity": {
                            "type": "string",
                            "enum": list(SEVERITIES),
                        },
                        "resolved_premise_ids": {"minItems": 1},
                        "evidence_ids": {"minItems": 1},
                        "proof_scope": {
                            "type": "string",
                            "enum": sorted(PROOF_SCOPES),
                        },
                        "resolved_axes": axes_schema,
                    }
                },
            }
        ],
    }
    unresolved_example = {
        "schema_version": ADJUDICATION_PROPOSAL_SCHEMA,
        "decision": "UNRESOLVED",
        "resolved_severity": None,
        "resolved_premise_ids": [],
        "evidence_ids": [],
        "proof_scope": None,
        "rationale": "Available evidence does not resolve the disputed premise.",
        "resolved_axes": None,
        "constituent_resolutions": {},
    }
    schema_json = json.dumps(schema, sort_keys=True)
    checklist = [
        "Emit exactly one JSON object matching the schema below.",
        "Resolve a premise only with a bound evidence receipt carrying the required capability.",
        "Treat upward and downward disagreements identically.",
        "Use UNRESOLVED with null severity, axes, and proof scope when evidence is insufficient.",
        "Treat identity and identifier duplicates as case-insensitive; do not vary casing to create a second principal or ID.",
        "Do not invent launcher identity, run binding, source receipts, or evidence capabilities.",
    ]
    lines = [
        "## Typed severity adjudication (mandatory)",
        "",
        *[f"- {item}" for item in checklist],
        "",
        schema_json,
    ]
    return {
        "schema_version": ADJUDICATION_PROPOSAL_SCHEMA,
        "required_fields": list(_ADJUDICATION_PROPOSAL_FIELDS),
        "json_schema": schema,
        "checklist": checklist,
        "unresolved_example": unresolved_example,
        "markdown": "\n".join(lines) + "\n",
    }


def _decision_authority_status(decision: Mapping[str, Any]) -> str:
    source = decision.get("assessment")
    if not isinstance(source, Mapping):
        return "UNATTESTED_COMPATIBILITY"
    receipts = source.get("evidence_receipts")
    producer_binding = source.get("producer_authority_binding")
    if (
        not _text(decision.get("run_id"))
        or not _HEX64_RE.fullmatch(_text(decision.get("source_receipt_digest")))
        or source.get("evidence_receipts_attested") is not True
        or not isinstance(receipts, list)
        or not _evidence_is_independently_issued(
            receipts,
            assessor_identity=_text(source.get("assessor_identity")),
            assessor_invocation_id=_text(source.get("assessor_invocation_id")),
        )
        or not isinstance(producer_binding, Mapping)
        or producer_binding.get("status") != "EXACT"
    ):
        return "UNATTESTED_COMPATIBILITY"
    if (
        source.get("evidence_capabilities_required") is True
        and source.get("evidence_capabilities_attested") is not True
    ):
        return "UNATTESTED_COMPATIBILITY"
    history = decision.get("adjudication_history") or []
    if any(
        not isinstance(event, Mapping)
        or event.get("binding_status") != "EXACT"
        or (
            source.get("evidence_capabilities_required") is True
            and (
                not isinstance(event.get("adjudicator_authority_binding"), Mapping)
                or event["adjudicator_authority_binding"].get("status") != "EXACT"
            )
        )
        for event in history
    ):
        return "UNATTESTED_COMPATIBILITY"
    return "REPORT_AUTHORITATIVE"


def project_report_severity(decision: Mapping[str, Any]) -> dict[str, Any]:
    """Project severity without allowing the report layer to author a tier."""

    _validate_decision_semantics(decision)
    if _decision_authority_status(decision) != "REPORT_AUTHORITATIVE":
        raise SeverityDecisionError(
            "severity decision lacks report-authoritative run/source/evidence binding"
        )
    if decision.get("status") == "RESOLVED" and decision.get("final_severity"):
        severity = decision["final_severity"]
        status = "RESOLVED"
    else:
        severity = decision["retention_severity"]
        status = "UNRESOLVED_SEVERITY"
    return {
        "candidate_id": decision["candidate_id"],
        "severity": severity,
        "severity_status": status,
        "decision_digest": decision["decision_digest"],
        "constituent_dispositions": dict(
            decision.get("constituent_dispositions") or {}
        ),
    }


def project_retention_severity(decision: Mapping[str, Any]) -> dict[str, Any]:
    """Project the fail-open retention tier without granting report authority."""

    _validate_decision_semantics(decision)
    return {
        "candidate_id": decision["candidate_id"],
        "severity": decision["retention_severity"],
        "severity_status": "UNRESOLVED_SEVERITY",
        "decision_digest": decision["decision_digest"],
        "constituent_dispositions": dict(
            decision.get("constituent_dispositions") or {}
        ),
    }


def validate_report_severity_projection(
    decision: Mapping[str, Any], projection: Mapping[str, Any]
) -> None:
    expected = project_report_severity(decision)
    if dict(projection) != expected:
        raise SeverityDecisionError("report severity projection drift")


def _semantic_rebuild(decision: Mapping[str, Any]) -> dict[str, Any]:
    source = decision.get("assessment")
    if not isinstance(source, Mapping):
        raise SeverityDecisionError("severity decision assessment is malformed")
    rebuilt = build_severity_decision(
        source, _authority_token=_DRIVER_AUTHORITY_TOKEN
    )
    history = decision.get("adjudication_history")
    if not isinstance(history, list):
        raise SeverityDecisionError("severity adjudication history is malformed")
    for event in history:
        if not isinstance(event, Mapping):
            raise SeverityDecisionError("severity adjudication event is malformed")
        rebuilt = adjudicate_severity_challenge(
            rebuilt, event, _authority_token=_DRIVER_AUTHORITY_TOKEN
        )
    return rebuilt


def _validate_decision_semantics(decision: Mapping[str, Any]) -> None:
    _validate_decision(decision)
    rebuilt = _semantic_rebuild(decision)
    if dict(rebuilt) != dict(decision):
        raise SeverityDecisionError("severity decision semantic replay mismatch")


def _bind_legacy_decision_to_run(
    decision: Mapping[str, Any], run_id: str
) -> dict[str, Any]:
    """One-way bind an old in-memory row before first persistence.

    This migration path is explicitly non-report-authoritative because its
    evidence receipts are unattested.  Mutating a dict caller prevents the
    same object from being rebound to a second run; new runtime callers supply
    run/source bindings at construction and never use this path.
    """

    if _text(decision.get("run_id")):
        return dict(decision)
    source = decision.get("assessment")
    if not isinstance(source, Mapping):
        raise SeverityDecisionError("unbound decision has no source assessment")
    migrated_source = dict(source)
    migrated_source["run_id"] = run_id
    migrated_source["source_receipt_digest"] = _digest(
        {"unbound_compatibility_assessment": source}
    )
    rebuilt = build_severity_decision(migrated_source)
    for event in decision.get("adjudication_history") or []:
        rebuilt = adjudicate_severity_challenge(rebuilt, event)
    if isinstance(decision, dict):
        decision.clear()
        decision.update(rebuilt)
    return rebuilt


def write_severity_decision_ledger(
    path: Path, run_id: str, decisions: Iterable[Mapping[str, Any]]
) -> dict[str, Any]:
    run = _text(run_id)
    if not run:
        raise SeverityDecisionError("ledger run ID is empty")
    rows = []
    identities: set[str] = set()
    for decision in decisions:
        bound = _bind_legacy_decision_to_run(decision, run)
        _validate_decision_semantics(bound)
        if bound.get("run_id") != run:
            raise SeverityDecisionError("severity decision row run binding mismatch")
        if not _HEX64_RE.fullmatch(_text(bound.get("source_receipt_digest"))):
            raise SeverityDecisionError("severity decision source binding is invalid")
        identity = _text(bound.get("candidate_id"))
        if identity in identities:
            raise SeverityDecisionError("ledger contains duplicate candidate identity")
        identities.add(identity)
        rows.append(dict(bound))
    rows.sort(key=lambda row: row["candidate_id"])
    unsigned = {
        "schema_version": LEDGER_SCHEMA,
        "run_id": run,
        "authority_status": (
            "REPORT_AUTHORITATIVE"
            if rows
            and all(
                _decision_authority_status(row) == "REPORT_AUTHORITATIVE"
                for row in rows
            )
            else "UNATTESTED_COMPATIBILITY"
        ),
        "decision_count": len(rows),
        "decisions": rows,
    }
    payload = {**unsigned, "ledger_digest": _digest(unsigned)}
    target = Path(path)
    content = json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True) + "\n"
    try:
        if target.read_text(encoding="utf-8") == content:
            return payload
    except OSError:
        pass
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_name(f".{target.name}.{uuid.uuid4().hex}.tmp")
    temporary.write_text(content, encoding="utf-8")
    os.replace(temporary, target)
    return payload


def load_severity_decision_ledger(
    path: Path,
    *,
    expected_run_id: str | None = None,
    expected_source_receipt_digests: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise SeverityDecisionError(f"severity ledger is unreadable: {exc}") from exc
    if not isinstance(payload, dict) or payload.get("schema_version") != LEDGER_SCHEMA:
        raise SeverityDecisionError("severity ledger schema mismatch")
    unsigned = {key: value for key, value in payload.items() if key != "ledger_digest"}
    if payload.get("ledger_digest") != _digest(unsigned):
        raise SeverityDecisionError("severity ledger digest mismatch")
    if expected_run_id is not None and payload.get("run_id") != expected_run_id:
        raise SeverityDecisionError("severity ledger run binding mismatch")
    rows = payload.get("decisions")
    if not isinstance(rows, list) or payload.get("decision_count") != len(rows):
        raise SeverityDecisionError("severity ledger count mismatch")
    identities: set[str] = set()
    derived_authoritative = bool(rows)
    for decision in rows:
        if not isinstance(decision, Mapping):
            raise SeverityDecisionError("severity ledger decision is malformed")
        _validate_decision(decision)
        _validate_decision_semantics(decision)
        if decision.get("run_id") != payload.get("run_id"):
            raise SeverityDecisionError("severity decision row run binding mismatch")
        if not _HEX64_RE.fullmatch(_text(decision.get("source_receipt_digest"))):
            raise SeverityDecisionError("severity decision source binding is invalid")
        identity = _text(decision.get("candidate_id"))
        if not identity or identity in identities:
            raise SeverityDecisionError("severity ledger contains duplicate identity")
        identities.add(identity)
        if _decision_authority_status(decision) != "REPORT_AUTHORITATIVE":
            derived_authoritative = False
    derived_status = (
        "REPORT_AUTHORITATIVE"
        if derived_authoritative
        else "UNATTESTED_COMPATIBILITY"
    )
    if payload.get("authority_status") != derived_status:
        raise SeverityDecisionError("severity ledger authority status mismatch")
    if derived_status == "REPORT_AUTHORITATIVE":
        if not isinstance(expected_source_receipt_digests, Mapping):
            raise SeverityDecisionError(
                "report-authoritative ledger requires external source authority"
            )
        expected = {
            _text(candidate): _text(digest).casefold()
            for candidate, digest in expected_source_receipt_digests.items()
        }
        observed = {
            _text(row.get("candidate_id")): _text(
                row.get("source_receipt_digest")
            ).casefold()
            for row in rows
        }
        if expected != observed or any(
            not candidate or not _HEX64_RE.fullmatch(digest)
            for candidate, digest in expected.items()
        ):
            raise SeverityDecisionError(
                "severity ledger external source authority mismatch"
            )
    return payload


def _normalize_coverage_expectations(
    expected_candidate_ids: Iterable[str],
    expected_source_receipt_digests: Mapping[str, str],
) -> tuple[list[str], dict[str, str]]:
    if isinstance(expected_candidate_ids, (str, bytes)):
        raise SeverityDecisionError("severity coverage candidate IDs must be a list")
    identities = [_text(item) for item in expected_candidate_ids]
    if any(not item for item in identities):
        raise SeverityDecisionError("severity coverage candidate identity is empty")
    if len(identities) != len(set(identities)):
        raise SeverityDecisionError("severity coverage contains duplicate candidate IDs")
    if not isinstance(expected_source_receipt_digests, Mapping):
        raise SeverityDecisionError("severity coverage source authority is missing")
    sources = {
        _text(candidate): _text(digest).casefold()
        for candidate, digest in expected_source_receipt_digests.items()
    }
    if set(sources) != set(identities) or any(
        not candidate or not _HEX64_RE.fullmatch(digest)
        for candidate, digest in sources.items()
    ):
        raise SeverityDecisionError("severity coverage source authority mismatch")
    return sorted(identities), {key: sources[key] for key in sorted(sources)}


def _read_coverage_ledger(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(
            Path(path).read_text(encoding="utf-8", errors="strict"),
            object_pairs_hook=_strict_json_object,
            parse_constant=_reject_json_constant,
        )
    except (OSError, UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise SeverityDecisionError(
            f"severity coverage ledger is unreadable: {exc}"
        ) from exc
    if not isinstance(payload, Mapping):
        raise SeverityDecisionError("severity coverage ledger must be an object")
    expected_keys = {
        "schema_version",
        "run_id",
        "authority_status",
        "decision_count",
        "decisions",
        "ledger_digest",
    }
    if set(payload) != expected_keys or payload.get("schema_version") != LEDGER_SCHEMA:
        raise SeverityDecisionError("severity coverage ledger schema mismatch")
    unsigned = {key: value for key, value in payload.items() if key != "ledger_digest"}
    if payload.get("ledger_digest") != _digest(unsigned):
        raise SeverityDecisionError("severity coverage ledger digest mismatch")
    rows = payload.get("decisions")
    if not isinstance(rows, list) or payload.get("decision_count") != len(rows):
        raise SeverityDecisionError("severity coverage ledger count mismatch")
    return dict(payload)


def reconcile_severity_ledger_coverage(
    ledger_path: Path,
    *,
    expected_run_id: str,
    queue_work_plan_digest: str,
    expected_candidate_ids: Iterable[str],
    expected_source_receipt_digests: Mapping[str, str],
) -> dict[str, Any]:
    """Reconcile row authority against the exact driver-owned denominator."""

    run_id = _text(expected_run_id)
    queue_digest = _text(queue_work_plan_digest).casefold()
    if not run_id:
        raise SeverityDecisionError("severity coverage run ID is empty")
    if not _HEX64_RE.fullmatch(queue_digest):
        raise SeverityDecisionError("severity coverage queue digest is invalid")
    expected_ids, expected_sources = _normalize_coverage_expectations(
        expected_candidate_ids, expected_source_receipt_digests
    )
    ledger = _read_coverage_ledger(ledger_path)
    if ledger.get("run_id") != run_id:
        raise SeverityDecisionError("severity coverage ledger run mismatch")
    rows = ledger["decisions"]
    observed_ids: list[str] = []
    invalid: set[str] = set()
    semantic_invalid: set[str] = set()
    challenged: set[str] = set()
    row_authorities: list[str] = []
    for index, row in enumerate(rows):
        if not isinstance(row, Mapping):
            invalid.add(f"<ROW-{index}>")
            continue
        candidate_id = _text(row.get("candidate_id"))
        if not candidate_id:
            invalid.add(f"<ROW-{index}>")
            continue
        if candidate_id in observed_ids:
            raise SeverityDecisionError(
                "severity coverage ledger contains duplicate candidate identity"
            )
        observed_ids.append(candidate_id)
        if row.get("run_id") != run_id:
            raise SeverityDecisionError(
                f"severity coverage decision run mismatch for {candidate_id}"
            )
        if candidate_id in expected_sources and _text(
            row.get("source_receipt_digest")
        ).casefold() != expected_sources[candidate_id]:
            raise SeverityDecisionError(
                f"severity coverage source authority mismatch for {candidate_id}"
            )
        try:
            _validate_decision_semantics(row)
        except (SeverityDecisionError, TypeError, ValueError):
            invalid.add(candidate_id)
            semantic_invalid.add(candidate_id)
            row_authorities.append("UNATTESTED_COMPATIBILITY")
            continue
        row_authority = _decision_authority_status(row)
        row_authorities.append(row_authority)
        if row_authority != "REPORT_AUTHORITATIVE":
            invalid.add(candidate_id)
        if row.get("status") != "RESOLVED" or not row.get("final_severity"):
            challenged.add(candidate_id)
    observed = set(observed_ids)
    expected = set(expected_ids)
    missing = sorted(expected - observed)
    extra = sorted(observed - expected)
    denominator_status = "NONEMPTY" if expected_ids else "EMPTY"
    claimed_ledger_authority = _text(ledger.get("authority_status"))
    ledger_authority = (
        "REPORT_AUTHORITATIVE"
        if rows
        and len(row_authorities) == len(rows)
        and all(status == "REPORT_AUTHORITATIVE" for status in row_authorities)
        else "UNATTESTED_COMPATIBILITY"
    )
    if claimed_ledger_authority != ledger_authority and not semantic_invalid:
        raise SeverityDecisionError(
            "severity coverage ledger authority status mismatch"
        )
    blockers = bool(missing or extra or invalid or challenged)
    if not expected_ids:
        authority_status = "EMPTY_DENOMINATOR"
    elif ledger_authority == "REPORT_AUTHORITATIVE" and not blockers:
        authority_status = "REPORT_AUTHORITATIVE"
    else:
        authority_status = "INCOMPLETE"
    unsigned = {
        "schema_version": COVERAGE_RECEIPT_SCHEMA,
        "run_id": run_id,
        "queue_work_plan_digest": queue_digest,
        "expected_candidate_ids": expected_ids,
        "expected_source_receipt_digests_digest": _digest(expected_sources),
        "severity_ledger_digest": ledger["ledger_digest"],
        "ledger_authority_status": ledger_authority,
        "denominator_status": denominator_status,
        "missing_candidate_ids": missing,
        "extra_candidate_ids": extra,
        "invalid_candidate_ids": sorted(invalid),
        "challenged_candidate_ids": sorted(challenged),
        "authority_status": authority_status,
    }
    return {**unsigned, "receipt_digest": _digest(unsigned)}


def _validate_coverage_receipt(receipt: Mapping[str, Any]) -> dict[str, Any]:
    value = dict(_require_exact_keys(
        receipt,
        _COVERAGE_RECEIPT_FIELDS,
        field="severity coverage receipt",
    ))
    if value.get("schema_version") != COVERAGE_RECEIPT_SCHEMA:
        raise SeverityDecisionError("severity coverage receipt schema mismatch")
    for field in (
        "queue_work_plan_digest",
        "expected_source_receipt_digests_digest",
        "severity_ledger_digest",
        "receipt_digest",
    ):
        if not _HEX64_RE.fullmatch(_text(value.get(field)).casefold()):
            raise SeverityDecisionError(f"severity coverage {field} is invalid")
    expected_ids = _string_list(
        value.get("expected_candidate_ids"),
        field="severity coverage expected_candidate_ids",
        nonempty=False,
    )
    if expected_ids != sorted(expected_ids):
        raise SeverityDecisionError("severity coverage expected IDs are not canonical")
    debt_lists: dict[str, list[str]] = {}
    for field in (
        "missing_candidate_ids",
        "extra_candidate_ids",
        "invalid_candidate_ids",
        "challenged_candidate_ids",
    ):
        rows = _string_list(
            value.get(field), field=f"severity coverage {field}", nonempty=False
        )
        if rows != sorted(rows):
            raise SeverityDecisionError(f"severity coverage {field} is not canonical")
        debt_lists[field] = rows
    denominator = _text(value.get("denominator_status")).upper()
    if denominator not in {"EMPTY", "NONEMPTY"} or (
        denominator == "EMPTY"
    ) != (not expected_ids):
        raise SeverityDecisionError("severity coverage denominator status mismatch")
    ledger_authority = _text(value.get("ledger_authority_status")).upper()
    if ledger_authority not in {
        "REPORT_AUTHORITATIVE",
        "UNATTESTED_COMPATIBILITY",
    }:
        raise SeverityDecisionError("severity coverage ledger authority is invalid")
    blockers = any(debt_lists.values())
    derived_authority = (
        "EMPTY_DENOMINATOR"
        if not expected_ids
        else (
            "REPORT_AUTHORITATIVE"
            if ledger_authority == "REPORT_AUTHORITATIVE" and not blockers
            else "INCOMPLETE"
        )
    )
    if value.get("authority_status") != derived_authority:
        raise SeverityDecisionError(
            "severity coverage authority is inconsistent with incomplete reconciliation"
        )
    unsigned = {key: item for key, item in value.items() if key != "receipt_digest"}
    if value.get("receipt_digest") != _digest(unsigned):
        raise SeverityDecisionError("severity coverage receipt digest mismatch")
    return value


def write_severity_ledger_coverage_receipt(
    path: Path, receipt: Mapping[str, Any]
) -> dict[str, Any]:
    value = _validate_coverage_receipt(receipt)
    target = Path(path)
    content = json.dumps(
        value, indent=2, ensure_ascii=False, allow_nan=False, sort_keys=True
    ) + "\n"
    try:
        if target.read_text(encoding="utf-8", errors="strict") == content:
            return value
    except OSError:
        pass
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_name(f".{target.name}.{uuid.uuid4().hex}.tmp")
    temporary.write_text(content, encoding="utf-8", newline="\n")
    os.replace(temporary, target)
    return value


def load_severity_ledger_coverage_receipt(
    path: Path,
    *,
    severity_ledger_path: Path,
    expected_run_id: str,
    expected_queue_work_plan_digest: str,
    expected_candidate_ids: Iterable[str],
    expected_source_receipt_digests: Mapping[str, str],
) -> dict[str, Any]:
    try:
        payload = json.loads(
            Path(path).read_text(encoding="utf-8", errors="strict"),
            object_pairs_hook=_strict_json_object,
            parse_constant=_reject_json_constant,
        )
    except (OSError, UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise SeverityDecisionError(
            f"severity coverage receipt is unreadable: {exc}"
        ) from exc
    if not isinstance(payload, Mapping):
        raise SeverityDecisionError("severity coverage receipt must be an object")
    receipt = _validate_coverage_receipt(payload)
    expected_ids, sources = _normalize_coverage_expectations(
        expected_candidate_ids, expected_source_receipt_digests
    )
    if receipt.get("run_id") != _text(expected_run_id):
        raise SeverityDecisionError("severity coverage receipt run mismatch")
    if receipt.get("queue_work_plan_digest") != _text(
        expected_queue_work_plan_digest
    ).casefold():
        raise SeverityDecisionError("severity coverage receipt queue mismatch")
    if receipt.get("expected_candidate_ids") != expected_ids:
        raise SeverityDecisionError("severity coverage receipt denominator mismatch")
    if receipt.get("expected_source_receipt_digests_digest") != _digest(sources):
        raise SeverityDecisionError("severity coverage receipt source mismatch")
    current = reconcile_severity_ledger_coverage(
        severity_ledger_path,
        expected_run_id=expected_run_id,
        queue_work_plan_digest=expected_queue_work_plan_digest,
        expected_candidate_ids=expected_ids,
        expected_source_receipt_digests=sources,
    )
    if receipt.get("severity_ledger_digest") != current.get(
        "severity_ledger_digest"
    ):
        raise SeverityDecisionError("severity coverage receipt ledger mismatch")
    if receipt != current:
        raise SeverityDecisionError("severity coverage receipt reconciliation mismatch")
    return dict(receipt)


__all__ = [
    "ADJUDICATION_SCHEMA",
    "ADJUDICATION_PROPOSAL_SCHEMA",
    "ADJUDICATOR_INPUT_SCHEMA",
    "ASSESSMENT_SCHEMA",
    "ASSESSOR_INPUT_SCHEMA",
    "COVERAGE_RECEIPT_SCHEMA",
    "DECISION_SCHEMA",
    "EVIDENCE_CAPABILITIES",
    "LEDGER_SCHEMA",
    "LAUNCH_RECEIPT_SCHEMA",
    "PROPOSAL_SCHEMA",
    "REPAIR_SCHEMA",
    "SeverityDecisionError",
    "adjudicate_severity_challenge",
    "bind_severity_adjudication",
    "bind_severity_proposal",
    "build_severity_decision",
    "build_severity_repair_request",
    "compile_severity_adjudication_prompt_contract",
    "compile_severity_prompt_contract",
    "load_severity_decision_ledger",
    "load_severity_ledger_coverage_receipt",
    "ingest_severity_proposal",
    "parse_severity_adjudication_proposal",
    "parse_severity_proposal",
    "project_report_severity",
    "project_retention_severity",
    "reconcile_severity_ledger_coverage",
    "required_assessment_fields",
    "required_proposal_fields",
    "severity_adjudicator_input_digest",
    "severity_assessor_input_digest",
    "validate_report_severity_projection",
    "write_severity_decision_ledger",
    "write_severity_ledger_coverage_receipt",
]
