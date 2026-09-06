"""Authentic typed evidence-capability providers for severity decisions.

The severity ledger deliberately accepts a small generic receipt shape.  This
module is the stricter issuance boundary: it derives capabilities from exact,
provider-specific facts and never accepts a caller-supplied capability list.
Model prose and candidate-authored labels therefore cannot mint evidence
authority merely by naming ``HARM``, ``IMPACT``, or another capability.

The providers are pure and backend-neutral.  Driver/runtime code is expected to
construct the typed source record from independently validated artifacts, then
persist both that record and the returned generic receipt.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Mapping
from urllib.parse import urlsplit


EXTERNAL_CITATION_EVIDENCE_SCHEMA = "plamen.external_citation_evidence.v1"
FORMAL_PROPERTY_EVIDENCE_SCHEMA = "plamen.formal_property_evidence.v1"
EXECUTED_POC_EVIDENCE_SCHEMA = "plamen.executed_poc_evidence.v1"
EXECUTED_POC_SCOPE_EVIDENCE_SCHEMA = "plamen.executed_poc_scope_evidence.v1"
EXECUTED_POC_SCOPE_ASSESSMENT_SCHEMA = (
    "plamen.executed_poc_scope_assessment.v1"
)
COMPOSITION_EVIDENCE_SCHEMA = "plamen.composition_evidence.v1"
EVIDENCE_RECEIPT_SCHEMA = "plamen.evidence_capability_receipt.v1"

PROOF_SCOPES = frozenset(
    {
        "IN_SCOPE_SOURCE",
        "IN_SCOPE_EXECUTION",
        "PRIMARY_EXTERNAL_CITED",
        "FORMAL_PROOF",
    }
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

_HEX64_RE = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
_RECEIPT_FIELDS = (
    "evidence_id",
    "content_sha256",
    "premise_ids",
    "constituent_ids",
    "proof_scope",
    "capabilities",
    "issuer_identity",
    "issuer_invocation_id",
)
_AUTHORITY_FIELDS = (
    "source_author_identity",
    "source_author_invocation_id",
    "issuer_identity",
    "issuer_invocation_id",
)
_EXTERNAL_FIELDS = (
    "schema_version",
    "evidence_id",
    "citation_row_id",
    "source_uri",
    "source_sha256",
    "excerpt_sha256",
    "fact_role",
    "premise_ids",
    "constituent_ids",
    "citation_status",
    *_AUTHORITY_FIELDS,
)
_FORMAL_FIELDS = (
    "schema_version",
    "evidence_id",
    "property_id",
    "property_statement_sha256",
    "source_snapshot_sha256",
    "toolchain_sha256",
    "proof_artifact_sha256",
    "proof_result",
    "declared_property_scope",
    "premise_ids",
    "constituent_ids",
    *_AUTHORITY_FIELDS,
)
_EXECUTED_POC_FIELDS = (
    "schema_version",
    "evidence_id",
    "source_snapshot_sha256",
    "build_sha256",
    "command_sha256",
    "oracle_sha256",
    "output_sha256",
    "execution_status",
    "execution_result",
    "exit_code",
    "oracle_provenance",
    "oracle_author_identity",
    "oracle_author_invocation_id",
    "oracle_review_status",
    "oracle_reviewer_identity",
    "oracle_reviewer_invocation_id",
    "reachability",
    "proof_target",
    "premise_ids",
    "constituent_ids",
    *_AUTHORITY_FIELDS,
)
_EXECUTED_POC_SCOPE_FIELDS = (
    "schema_version",
    "candidate_id",
    "evidence_id",
    "source_snapshot_sha256",
    "build_sha256",
    "command_sha256",
    "oracle_sha256",
    "output_sha256",
    "runner_receipt_sha256",
    "launch_receipt_sha256",
    "execution_status",
    "execution_result",
    "exit_code",
    "oracle_provenance",
    "oracle_derivation",
    "oracle_author_identity",
    "oracle_author_invocation_id",
    "oracle_review_status",
    "oracle_reviewer_identity",
    "oracle_reviewer_invocation_id",
    "reachability",
    "environment_fidelity",
    "proof_scope",
    "negative_exhaustiveness",
    "required_precondition_ids",
    "represented_precondition_ids",
    "external_evidence_receipts",
    "external_premises",
    "premise_ids",
    "constituent_ids",
    *_AUTHORITY_FIELDS,
)
_EXECUTED_POC_SCOPE_ASSESSMENT_FIELDS = (
    "schema_version",
    "candidate_id",
    "evidence_id",
    "source_record_sha256",
    "execution_authenticity",
    "execution_result",
    "oracle_provenance",
    "oracle_authority",
    "reachability",
    "environment_fidelity",
    "precondition_coverage",
    "proof_scope",
    "external_premise_state",
    "negative_exhaustiveness",
    "positive_capabilities",
    "maximum_negative_scope",
    "harm_evidence_eligible",
    "negative_disposition_eligible",
    "candidate_state",
    "debts",
    "evidence_receipt",
    "assessment_digest",
)
_COMPOSITION_FIELDS = (
    "schema_version",
    "evidence_id",
    "composition_id",
    "composition_method",
    "relation_graph_sha256",
    "artifact_sha256",
    "execution_result",
    "reachability",
    "premise_ids",
    "constituent_ids",
    *_AUTHORITY_FIELDS,
)

_EXTERNAL_FACT_CAPABILITIES = {
    "EXTERNAL_FACT_ONLY": ("EXTERNAL_FACT",),
    "LIKELIHOOD_FREQUENCY": ("EXTERNAL_FACT", "LIKELIHOOD"),
    "IMPACT_MAGNITUDE": ("EXTERNAL_FACT", "IMPACT"),
    "MATERIAL_HARM": ("EXTERNAL_FACT", "HARM"),
}
_FORMAL_SCOPE_CAPABILITIES = {
    "MECHANISM": ("MECHANISM",),
    "IMPACT": ("IMPACT",),
    "LIKELIHOOD": ("LIKELIHOOD",),
    "HARM": ("HARM",),
    "MODIFIER_APPLICABILITY": ("MODIFIER_APPLICABILITY",),
}
_ORACLE_PROVENANCE = frozenset(
    {
        "PROTOCOL_AUTHORED_INVARIANT",
        "INDEPENDENT_REVIEWER_ORACLE",
        "MODEL_GENERATED_ORACLE",
        "CANDIDATE_DERIVED_ORACLE",
        "HEURISTIC_ASSERTION",
    }
)
_ORACLE_DERIVATION = frozenset(
    {
        "PROTOCOL_SOURCE_BOUND",
        "IN_SCOPE_CLAIM_BOUND",
        "HEURISTIC",
        "UNBOUND",
    }
)
_REACHABILITY = frozenset(
    {
        "IN_SCOPE_REACHABLE",
        "PARTIAL_ENVIRONMENT",
        "UNREACHABLE",
        "EXTERNAL_ENVIRONMENT_UNPROVEN",
    }
)
_POC_TARGETS = frozenset(
    {"MECHANISM_ONLY", "REACHABILITY", "IMPACT", "LIKELIHOOD", "HARM"}
)
_SCOPED_PROOF_TARGETS = frozenset({"MECHANISM_ONLY", "REACHABILITY", "HARM"})
_ENVIRONMENT_FIDELITY = frozenset(
    {
        "FULL_IN_SCOPE",
        "PARTIAL_IN_SCOPE",
        "SYNTHETIC_ONLY",
        "EXTERNAL_UNPROVEN",
        "UNREACHABLE",
    }
)
_NEGATIVE_EXHAUSTIVENESS = frozenset(
    {
        "NOT_APPLICABLE",
        "SINGLE_PARAMETERIZATION",
        "BOUNDED_DOMAIN",
        "EXHAUSTIVE_IN_SCOPE",
    }
)
_EXTERNAL_PREMISE_STATES = frozenset(
    {"SUPPORTED", "REFUTED", "UNRESEARCHED", "CONFLICTING"}
)
_POSITIVE_EXECUTION_TAGS = frozenset(
    {
        "POC-PASS",
        "MEDUSA-PASS",
        "FUZZ-PASS",
        "NON-DET-PASS",
        "DIFF-PASS",
        "CONFORMANCE-PASS",
    }
)
_NEGATIVE_EXECUTION_TAGS = frozenset({"POC-FAIL"})
_EXECUTION_TAG_RE = re.compile(
    r"\[(POC-PASS|MEDUSA-PASS|FUZZ-PASS|NON-DET-PASS|DIFF-PASS|"
    r"CONFORMANCE-PASS|POC-FAIL)(?::[^\]]*)?\]",
    re.IGNORECASE,
)


class EvidenceCapabilityError(ValueError):
    """A typed source record cannot authorize the requested receipt."""


def _require_exact_record(
    value: Mapping[str, Any], fields: tuple[str, ...], *, label: str
) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise EvidenceCapabilityError(f"{label} must be an object")
    if set(value) != set(fields):
        missing = sorted(set(fields) - set(value))
        extra = sorted(set(value) - set(fields))
        raise EvidenceCapabilityError(
            f"{label} schema mismatch; missing={missing}; extra={extra}"
        )
    return {field: value[field] for field in fields}


def _string(value: Any, *, field: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or any(
            ord(char) < 32
            or ord(char) == 127
            or char in {"\u2028", "\u2029"}
            for char in value
        )
    ):
        raise EvidenceCapabilityError(f"{field} must be a non-empty string")
    return value


def _optional_string(value: Any, *, field: str) -> str | None:
    if value is None:
        return None
    return _string(value, field=field)


def _enum(value: Any, allowed: set[str] | frozenset[str] | dict[str, Any], *, field: str) -> str:
    item = _string(value, field=field)
    if item not in allowed:
        raise EvidenceCapabilityError(f"{field} enum is invalid")
    return item


def _sha256(value: Any, *, field: str) -> str:
    item = _string(value, field=field)
    if not _HEX64_RE.fullmatch(item):
        raise EvidenceCapabilityError(f"{field} must be a lowercase SHA-256 digest")
    return item


def _principal_key(value: str) -> str:
    """Compare local authority principals with filesystem-safe casing rules."""

    return value.casefold()


def _same_principal(left: str, right: str) -> bool:
    return _principal_key(left) == _principal_key(right)


def _string_list(
    value: Any, *, field: str, minimum: int = 1
) -> list[str]:
    if not isinstance(value, list) or isinstance(value, (str, bytes)):
        raise EvidenceCapabilityError(f"{field} must be an array")
    normalized = [_string(item, field=f"{field} item") for item in value]
    if len(normalized) < minimum:
        raise EvidenceCapabilityError(f"{field} requires at least {minimum} item(s)")
    if len({_principal_key(item) for item in normalized}) != len(normalized):
        raise EvidenceCapabilityError(f"{field} must not contain duplicates")
    return sorted(normalized)


def _canonical_sha256(value: Mapping[str, Any]) -> str:
    payload = json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _normalize_authority(record: dict[str, Any]) -> dict[str, str]:
    authority = {
        field: _string(record[field], field=field) for field in _AUTHORITY_FIELDS
    }
    if (
        _same_principal(
            authority["issuer_identity"], authority["source_author_identity"]
        )
        or _same_principal(
            authority["issuer_invocation_id"],
            authority["source_author_invocation_id"],
        )
    ):
        raise EvidenceCapabilityError(
            "evidence issuer must be independent from the source author"
        )
    return authority


def _normalize_common(record: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(record)
    normalized["evidence_id"] = _string(record["evidence_id"], field="evidence_id")
    normalized["premise_ids"] = _string_list(
        record["premise_ids"], field="premise_ids"
    )
    normalized["constituent_ids"] = _string_list(
        record["constituent_ids"], field="constituent_ids"
    )
    normalized.update(_normalize_authority(record))
    return normalized


def _receipt(
    record: Mapping[str, Any], *, proof_scope: str, capabilities: tuple[str, ...] | list[str]
) -> dict[str, Any]:
    capability_values = sorted(set(capabilities))
    if not capability_values or any(
        value not in EVIDENCE_CAPABILITIES for value in capability_values
    ):
        raise EvidenceCapabilityError("provider derived an invalid capability set")
    receipt = {
        "evidence_id": record["evidence_id"],
        "content_sha256": _canonical_sha256(record),
        "premise_ids": list(record["premise_ids"]),
        "constituent_ids": list(record["constituent_ids"]),
        "proof_scope": proof_scope,
        "capabilities": capability_values,
        "issuer_identity": record["issuer_identity"],
        "issuer_invocation_id": record["issuer_invocation_id"],
    }
    return validate_evidence_receipt(receipt)


def validate_evidence_receipt(value: Mapping[str, Any]) -> dict[str, Any]:
    """Validate the generic receipt shape consumed by the severity ledger."""

    record = _require_exact_record(value, _RECEIPT_FIELDS, label="evidence receipt")
    normalized = {
        "evidence_id": _string(record["evidence_id"], field="evidence_id"),
        "content_sha256": _sha256(
            record["content_sha256"], field="content_sha256"
        ),
        "premise_ids": _string_list(record["premise_ids"], field="premise_ids"),
        "constituent_ids": _string_list(
            record["constituent_ids"], field="constituent_ids"
        ),
        "proof_scope": _enum(
            record["proof_scope"], PROOF_SCOPES, field="proof_scope"
        ),
        "capabilities": _string_list(
            record["capabilities"], field="capabilities"
        ),
        "issuer_identity": _string(
            record["issuer_identity"], field="issuer_identity"
        ),
        "issuer_invocation_id": _string(
            record["issuer_invocation_id"], field="issuer_invocation_id"
        ),
    }
    if any(
        capability not in EVIDENCE_CAPABILITIES
        for capability in normalized["capabilities"]
    ):
        raise EvidenceCapabilityError("evidence receipt capability enum is invalid")
    return normalized


def issue_external_citation_receipt(value: Mapping[str, Any]) -> dict[str, Any]:
    """Issue capabilities from one exact, independently registered source row."""

    record = _normalize_common(
        _require_exact_record(value, _EXTERNAL_FIELDS, label="external citation")
    )
    if record["schema_version"] != EXTERNAL_CITATION_EVIDENCE_SCHEMA:
        raise EvidenceCapabilityError("external citation schema mismatch")
    record["citation_row_id"] = _string(
        record["citation_row_id"], field="citation_row_id"
    )
    record["source_sha256"] = _sha256(
        record["source_sha256"], field="source_sha256"
    )
    record["excerpt_sha256"] = _sha256(
        record["excerpt_sha256"], field="excerpt_sha256"
    )
    source_uri = _string(record["source_uri"], field="source_uri")
    parsed = urlsplit(source_uri)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise EvidenceCapabilityError("source_uri must name an HTTPS primary source")
    record["source_uri"] = source_uri
    record["citation_status"] = _enum(
        record["citation_status"],
        {"PRIMARY_SOURCE_VERIFIED"},
        field="citation_status",
    )
    fact_role = _enum(
        record["fact_role"], _EXTERNAL_FACT_CAPABILITIES, field="fact_role"
    )
    record["fact_role"] = fact_role
    return _receipt(
        record,
        proof_scope="PRIMARY_EXTERNAL_CITED",
        capabilities=_EXTERNAL_FACT_CAPABILITIES[fact_role],
    )


def issue_formal_property_receipt(value: Mapping[str, Any]) -> dict[str, Any]:
    """Issue exactly the declared capability of a completed formal proof."""

    record = _normalize_common(
        _require_exact_record(value, _FORMAL_FIELDS, label="formal property")
    )
    if record["schema_version"] != FORMAL_PROPERTY_EVIDENCE_SCHEMA:
        raise EvidenceCapabilityError("formal property schema mismatch")
    record["property_id"] = _string(record["property_id"], field="property_id")
    for field in (
        "property_statement_sha256",
        "source_snapshot_sha256",
        "toolchain_sha256",
        "proof_artifact_sha256",
    ):
        record[field] = _sha256(record[field], field=field)
    record["proof_result"] = _enum(
        record["proof_result"], {"PROVED"}, field="proof_result"
    )
    declared_scope = _enum(
        record["declared_property_scope"],
        _FORMAL_SCOPE_CAPABILITIES,
        field="declared_property_scope",
    )
    record["declared_property_scope"] = declared_scope
    return _receipt(
        record,
        proof_scope="FORMAL_PROOF",
        capabilities=_FORMAL_SCOPE_CAPABILITIES[declared_scope],
    )


def _review_is_independent(record: Mapping[str, Any]) -> bool:
    reviewer_identity = record["oracle_reviewer_identity"]
    reviewer_invocation = record["oracle_reviewer_invocation_id"]
    if reviewer_identity is None or reviewer_invocation is None:
        return False
    identities = {
        _principal_key(record["oracle_author_identity"]),
        _principal_key(record["source_author_identity"]),
        _principal_key(record["issuer_identity"]),
    }
    invocations = {
        _principal_key(record["oracle_author_invocation_id"]),
        _principal_key(record["source_author_invocation_id"]),
        _principal_key(record["issuer_invocation_id"]),
    }
    return (
        _principal_key(reviewer_identity) not in identities
        and _principal_key(reviewer_invocation) not in invocations
    )


def issue_executed_poc_receipt(value: Mapping[str, Any]) -> dict[str, Any]:
    """Issue execution and only provenance-supported semantic capabilities.

    Completed execution always proves that the named artifact ran.  In-scope
    reachability additionally supports mechanism evidence.  Impact, likelihood,
    and harm are issued only for an independently authored oracle or an exact
    independent validation of another oracle.  This prevents a generated test
    from auto-certifying the business claim it was generated to demonstrate.
    """

    record = _normalize_common(
        _require_exact_record(value, _EXECUTED_POC_FIELDS, label="executed PoC")
    )
    if record["schema_version"] != EXECUTED_POC_EVIDENCE_SCHEMA:
        raise EvidenceCapabilityError("executed PoC schema mismatch")
    for field in (
        "source_snapshot_sha256",
        "build_sha256",
        "command_sha256",
        "oracle_sha256",
        "output_sha256",
    ):
        record[field] = _sha256(record[field], field=field)
    record["execution_status"] = _enum(
        record["execution_status"], {"COMPLETED"}, field="execution_status"
    )
    record["execution_result"] = _enum(
        record["execution_result"],
        {"ESTABLISHED", "REFUTED"},
        field="execution_result",
    )
    if isinstance(record["exit_code"], bool) or not isinstance(record["exit_code"], int):
        raise EvidenceCapabilityError("exit_code must be an integer")
    provenance = _enum(
        record["oracle_provenance"],
        _ORACLE_PROVENANCE,
        field="oracle_provenance",
    )
    record["oracle_provenance"] = provenance
    for field in ("oracle_author_identity", "oracle_author_invocation_id"):
        record[field] = _string(record[field], field=field)
    if provenance == "INDEPENDENT_REVIEWER_ORACLE" and (
        _same_principal(
            record["oracle_author_identity"], record["source_author_identity"]
        )
        or _same_principal(
            record["oracle_author_invocation_id"],
            record["source_author_invocation_id"],
        )
    ):
        raise EvidenceCapabilityError(
            "independent reviewer oracle must be independent from source author"
        )
    if (
        _same_principal(
            record["issuer_identity"], record["oracle_author_identity"]
        )
        or _same_principal(
            record["issuer_invocation_id"],
            record["oracle_author_invocation_id"],
        )
    ):
        raise EvidenceCapabilityError(
            "execution receipt issuer must be independent from the oracle author"
        )
    review_status = _enum(
        record["oracle_review_status"],
        {"NOT_REVIEWED", "INDEPENDENTLY_VALIDATED"},
        field="oracle_review_status",
    )
    record["oracle_review_status"] = review_status
    record["oracle_reviewer_identity"] = _optional_string(
        record["oracle_reviewer_identity"], field="oracle_reviewer_identity"
    )
    record["oracle_reviewer_invocation_id"] = _optional_string(
        record["oracle_reviewer_invocation_id"],
        field="oracle_reviewer_invocation_id",
    )
    if review_status == "NOT_REVIEWED" and (
        record["oracle_reviewer_identity"] is not None
        or record["oracle_reviewer_invocation_id"] is not None
    ):
        raise EvidenceCapabilityError(
            "unreviewed oracle cannot carry reviewer authority"
        )
    if review_status == "INDEPENDENTLY_VALIDATED" and not _review_is_independent(record):
        raise EvidenceCapabilityError(
            "oracle review must be complete and independently issued"
        )
    reachability = _enum(
        record["reachability"], _REACHABILITY, field="reachability"
    )
    record["reachability"] = reachability
    proof_target = _enum(record["proof_target"], _POC_TARGETS, field="proof_target")
    record["proof_target"] = proof_target

    capabilities = {"EXECUTION"}
    establishes_target = record["execution_result"] == "ESTABLISHED"
    if (
        establishes_target
        and reachability == "IN_SCOPE_REACHABLE"
        and proof_target != "REACHABILITY"
    ):
        capabilities.add("MECHANISM")
    semantic_target = {
        "IMPACT": "IMPACT",
        "LIKELIHOOD": "LIKELIHOOD",
        "HARM": "HARM",
    }.get(proof_target)
    oracle_is_semantically_authoritative = (
        (
            provenance == "INDEPENDENT_REVIEWER_ORACLE"
            and not _same_principal(
                record["oracle_author_identity"],
                record["source_author_identity"],
            )
            and not _same_principal(
                record["oracle_author_invocation_id"],
                record["source_author_invocation_id"],
            )
        )
        or review_status == "INDEPENDENTLY_VALIDATED"
    )
    if (
        semantic_target is not None
        and establishes_target
        and reachability == "IN_SCOPE_REACHABLE"
        and oracle_is_semantically_authoritative
    ):
        capabilities.add(semantic_target)
    return _receipt(
        record,
        proof_scope="IN_SCOPE_EXECUTION",
        capabilities=sorted(capabilities),
    )


def _normalize_external_evidence_receipts(
    value: Any,
) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]]]:
    """Validate exact external-fact receipts before premise rows cite them."""

    if not isinstance(value, list) or isinstance(value, (str, bytes)):
        raise EvidenceCapabilityError(
            "external_evidence_receipts must be an array"
        )
    normalized: list[dict[str, Any]] = []
    by_id: dict[str, dict[str, Any]] = {}
    for raw in value:
        receipt = validate_evidence_receipt(raw)
        if receipt["proof_scope"] != "PRIMARY_EXTERNAL_CITED":
            raise EvidenceCapabilityError(
                "external evidence receipt must be primary-external scoped"
            )
        if "EXTERNAL_FACT" not in receipt["capabilities"]:
            raise EvidenceCapabilityError(
                "external evidence receipt lacks EXTERNAL_FACT capability"
            )
        key = _principal_key(receipt["evidence_id"])
        if key in by_id:
            raise EvidenceCapabilityError(
                "duplicate external evidence receipt identity"
            )
        normalized.append(receipt)
        by_id[key] = receipt
    normalized.sort(key=lambda row: _principal_key(row["evidence_id"]))
    return normalized, by_id


def _normalize_external_premises(
    value: Any,
    *,
    bound_premise_ids: set[str],
    evidence_receipts: Mapping[str, Mapping[str, Any]],
    candidate_id: str,
) -> list[dict[str, Any]]:
    """Validate premise state independently of the executed oracle result."""

    if not isinstance(value, list) or isinstance(value, (str, bytes)):
        raise EvidenceCapabilityError("external_premises must be an array")
    normalized: list[dict[str, Any]] = []
    seen: set[str] = set()
    fields = ("premise_id", "evidence_state", "evidence_ids")
    for index, raw in enumerate(value):
        row = _require_exact_record(
            raw, fields, label=f"external premise row {index}"
        )
        premise_id = _string(row["premise_id"], field="external premise_id")
        key = _principal_key(premise_id)
        if key in seen:
            raise EvidenceCapabilityError("duplicate external premise_id")
        seen.add(key)
        if not any(
            _same_principal(premise_id, bound) for bound in bound_premise_ids
        ):
            raise EvidenceCapabilityError(
                "external premise must be bound into premise_ids"
            )
        state = _enum(
            row["evidence_state"],
            _EXTERNAL_PREMISE_STATES,
            field="external premise evidence_state",
        )
        evidence_ids = _string_list(
            row["evidence_ids"], field="external premise evidence_ids", minimum=0
        )
        if state == "UNRESEARCHED" and evidence_ids:
            raise EvidenceCapabilityError(
                "unresearched external premise cannot cite resolved evidence"
            )
        if state in {"SUPPORTED", "REFUTED"} and not evidence_ids:
            raise EvidenceCapabilityError(
                "resolved external premise requires evidence_ids"
            )
        if state == "CONFLICTING" and len(evidence_ids) < 2:
            raise EvidenceCapabilityError(
                "conflicting external premise requires at least two evidence_ids"
            )
        for evidence_id in evidence_ids:
            receipt = evidence_receipts.get(_principal_key(evidence_id))
            if receipt is None:
                raise EvidenceCapabilityError(
                    "external premise cites an unregistered evidence receipt"
                )
            if not any(
                _same_principal(premise_id, bound)
                for bound in receipt["premise_ids"]
            ):
                raise EvidenceCapabilityError(
                    "external evidence receipt is not bound to its premise"
                )
            if not any(
                _same_principal(candidate_id, bound)
                for bound in receipt["constituent_ids"]
            ):
                raise EvidenceCapabilityError(
                    "external evidence receipt is not bound to the candidate"
                )
        normalized.append(
            {
                "premise_id": premise_id,
                "evidence_state": state,
                "evidence_ids": evidence_ids,
            }
        )
    return sorted(normalized, key=lambda row: _principal_key(row["premise_id"]))


def _normalize_scoped_poc_record(value: Mapping[str, Any]) -> dict[str, Any]:
    record = _normalize_common(
        _require_exact_record(
            value, _EXECUTED_POC_SCOPE_FIELDS, label="scoped executed PoC"
        )
    )
    if record["schema_version"] != EXECUTED_POC_SCOPE_EVIDENCE_SCHEMA:
        raise EvidenceCapabilityError("scoped executed PoC schema mismatch")
    record["candidate_id"] = _string(
        record["candidate_id"], field="candidate_id"
    )
    if not any(
        _same_principal(record["candidate_id"], constituent)
        for constituent in record["constituent_ids"]
    ):
        raise EvidenceCapabilityError(
            "candidate_id must be present in constituent_ids"
        )
    for field in (
        "source_snapshot_sha256",
        "build_sha256",
        "command_sha256",
        "oracle_sha256",
        "output_sha256",
        "runner_receipt_sha256",
        "launch_receipt_sha256",
    ):
        record[field] = _sha256(record[field], field=field)
    record["execution_status"] = _enum(
        record["execution_status"], {"COMPLETED"}, field="execution_status"
    )
    record["execution_result"] = _enum(
        record["execution_result"],
        {"ESTABLISHED", "NOT_ESTABLISHED", "EXECUTION_ERROR"},
        field="execution_result",
    )
    if isinstance(record["exit_code"], bool) or not isinstance(
        record["exit_code"], int
    ):
        raise EvidenceCapabilityError("exit_code must be an integer")
    provenance = _enum(
        record["oracle_provenance"],
        _ORACLE_PROVENANCE,
        field="oracle_provenance",
    )
    record["oracle_provenance"] = provenance
    record["oracle_derivation"] = _enum(
        record["oracle_derivation"],
        _ORACLE_DERIVATION,
        field="oracle_derivation",
    )
    for field in ("oracle_author_identity", "oracle_author_invocation_id"):
        record[field] = _string(record[field], field=field)
    if provenance == "INDEPENDENT_REVIEWER_ORACLE" and (
        _same_principal(
            record["oracle_author_identity"], record["source_author_identity"]
        )
        or _same_principal(
            record["oracle_author_invocation_id"],
            record["source_author_invocation_id"],
        )
    ):
        raise EvidenceCapabilityError(
            "independent reviewer oracle must be independent from source author"
        )
    if (
        _same_principal(record["issuer_identity"], record["oracle_author_identity"])
        or _same_principal(
            record["issuer_invocation_id"],
            record["oracle_author_invocation_id"],
        )
    ):
        raise EvidenceCapabilityError(
            "execution receipt issuer must be independent from oracle author"
        )
    review_status = _enum(
        record["oracle_review_status"],
        {"NOT_REVIEWED", "INDEPENDENTLY_VALIDATED"},
        field="oracle_review_status",
    )
    record["oracle_review_status"] = review_status
    record["oracle_reviewer_identity"] = _optional_string(
        record["oracle_reviewer_identity"], field="oracle_reviewer_identity"
    )
    record["oracle_reviewer_invocation_id"] = _optional_string(
        record["oracle_reviewer_invocation_id"],
        field="oracle_reviewer_invocation_id",
    )
    if review_status == "NOT_REVIEWED" and (
        record["oracle_reviewer_identity"] is not None
        or record["oracle_reviewer_invocation_id"] is not None
    ):
        raise EvidenceCapabilityError(
            "unreviewed oracle cannot carry reviewer authority"
        )
    if review_status == "INDEPENDENTLY_VALIDATED" and not _review_is_independent(
        record
    ):
        raise EvidenceCapabilityError(
            "oracle review must be complete and independently issued"
        )

    reachability = _enum(
        record["reachability"], _REACHABILITY, field="reachability"
    )
    environment = _enum(
        record["environment_fidelity"],
        _ENVIRONMENT_FIDELITY,
        field="environment_fidelity",
    )
    record["reachability"] = reachability
    record["environment_fidelity"] = environment
    if (reachability == "UNREACHABLE") != (environment == "UNREACHABLE"):
        raise EvidenceCapabilityError(
            "unreachable reachability and environment metadata must agree"
        )
    if environment == "FULL_IN_SCOPE" and reachability != "IN_SCOPE_REACHABLE":
        raise EvidenceCapabilityError(
            "full in-scope environment requires in-scope reachability"
        )
    record["proof_scope"] = _enum(
        record["proof_scope"], _SCOPED_PROOF_TARGETS, field="proof_scope"
    )
    exhaustiveness = _enum(
        record["negative_exhaustiveness"],
        _NEGATIVE_EXHAUSTIVENESS,
        field="negative_exhaustiveness",
    )
    record["negative_exhaustiveness"] = exhaustiveness
    if record["execution_result"] == "NOT_ESTABLISHED":
        if exhaustiveness == "NOT_APPLICABLE":
            raise EvidenceCapabilityError(
                "negative result requires explicit exhaustiveness"
            )
    elif exhaustiveness != "NOT_APPLICABLE":
        raise EvidenceCapabilityError(
            "non-negative result cannot claim negative exhaustiveness"
        )

    required = _string_list(
        record["required_precondition_ids"],
        field="required_precondition_ids",
        minimum=0,
    )
    represented = _string_list(
        record["represented_precondition_ids"],
        field="represented_precondition_ids",
        minimum=0,
    )
    required_keys = {_principal_key(item) for item in required}
    if any(_principal_key(item) not in required_keys for item in represented):
        raise EvidenceCapabilityError(
            "represented precondition is absent from required_precondition_ids"
        )
    record["required_precondition_ids"] = required
    record["represented_precondition_ids"] = represented
    external_receipts, external_receipts_by_id = (
        _normalize_external_evidence_receipts(
            record["external_evidence_receipts"]
        )
    )
    record["external_evidence_receipts"] = external_receipts
    record["external_premises"] = _normalize_external_premises(
        record["external_premises"],
        bound_premise_ids=set(record["premise_ids"]),
        evidence_receipts=external_receipts_by_id,
        candidate_id=record["candidate_id"],
    )
    cited_external_ids = {
        _principal_key(evidence_id)
        for row in record["external_premises"]
        for evidence_id in row["evidence_ids"]
    }
    if cited_external_ids != set(external_receipts_by_id):
        raise EvidenceCapabilityError(
            "external evidence receipts must reconcile exactly to premise rows"
        )
    return record


def _scoped_oracle_authority(record: Mapping[str, Any]) -> str:
    provenance = record["oracle_provenance"]
    derivation = record["oracle_derivation"]
    if (
        provenance == "PROTOCOL_AUTHORED_INVARIANT"
        and derivation == "PROTOCOL_SOURCE_BOUND"
    ):
        return "PROTOCOL_AUTHORED"
    if (
        provenance == "INDEPENDENT_REVIEWER_ORACLE"
        and derivation == "IN_SCOPE_CLAIM_BOUND"
    ):
        return "INDEPENDENTLY_AUTHORED"
    if (
        record["oracle_review_status"] == "INDEPENDENTLY_VALIDATED"
        and derivation == "IN_SCOPE_CLAIM_BOUND"
        and _review_is_independent(record)
    ):
        return "INDEPENDENTLY_VALIDATED"
    if provenance in {
        "MODEL_GENERATED_ORACLE",
        "CANDIDATE_DERIVED_ORACLE",
        "HEURISTIC_ASSERTION",
    }:
        return "GENERATED_UNREVIEWED"
    return "UNBOUND"


def _external_premise_state(rows: list[dict[str, Any]]) -> str:
    states = {row["evidence_state"] for row in rows}
    if not states or states == {"SUPPORTED"}:
        return "RESOLVED"
    if "CONFLICTING" in states:
        return "CONFLICTING"
    if "UNRESEARCHED" in states:
        return "UNRESOLVED"
    if "REFUTED" in states:
        return "REFUTED"
    return "UNRESOLVED"


def _assessment_digest(value: Mapping[str, Any]) -> str:
    return _canonical_sha256(
        {key: item for key, item in value.items() if key != "assessment_digest"}
    )


def _finalize_scope_assessment(value: dict[str, Any]) -> dict[str, Any]:
    value["assessment_digest"] = _assessment_digest(value)
    return validate_executed_poc_scope_assessment(value)


def issue_executed_poc_scope_assessment(
    value: Mapping[str, Any],
) -> dict[str, Any]:
    """Issue orthogonal execution/provenance/fidelity/scope authority.

    The result deliberately remains ``ADJUDICATION_REQUIRED``.  It describes
    what evidence may support or refute; it never assigns a verdict or severity.
    """

    record = _normalize_scoped_poc_record(value)
    authority = _scoped_oracle_authority(record)
    required = {_principal_key(item) for item in record["required_precondition_ids"]}
    represented = {
        _principal_key(item) for item in record["represented_precondition_ids"]
    }
    preconditions = "COMPLETE" if required == represented else "PARTIAL"
    external_state = _external_premise_state(record["external_premises"])
    debts: set[str] = set()
    if preconditions != "COMPLETE":
        debts.add("PRECONDITION_COVERAGE_PARTIAL")
    if record["reachability"] == "UNREACHABLE":
        debts.add("HARNESS_UNREACHABLE")
    elif record["reachability"] != "IN_SCOPE_REACHABLE":
        debts.add("REACHABILITY_NOT_IN_SCOPE")
    if record["environment_fidelity"] != "FULL_IN_SCOPE":
        debts.add("ENVIRONMENT_FIDELITY_INCOMPLETE")
    if external_state == "UNRESOLVED":
        debts.add("EXTERNAL_PREMISE_UNRESOLVED")
    elif external_state == "CONFLICTING":
        debts.add("EXTERNAL_PREMISE_CONFLICTING")
    elif external_state == "REFUTED":
        debts.add("EXTERNAL_PREMISE_REFUTED")
    if record["execution_result"] == "EXECUTION_ERROR":
        debts.add("EXECUTION_RESULT_ERROR")

    full_scope = (
        record["reachability"] == "IN_SCOPE_REACHABLE"
        and record["environment_fidelity"] == "FULL_IN_SCOPE"
        and preconditions == "COMPLETE"
        and external_state == "RESOLVED"
    )
    semantic_authority = authority in {
        "PROTOCOL_AUTHORED",
        "INDEPENDENTLY_AUTHORED",
        "INDEPENDENTLY_VALIDATED",
    }
    capabilities = {"EXECUTION"}
    if record["execution_result"] == "ESTABLISHED" and full_scope:
        if record["proof_scope"] == "MECHANISM_ONLY":
            capabilities.add("MECHANISM")
        elif record["proof_scope"] == "REACHABILITY":
            capabilities.add("REACHABILITY")
        else:
            capabilities.update({"MECHANISM", "REACHABILITY"})
            if semantic_authority:
                capabilities.add("HARM")
            else:
                debts.add("ORACLE_SEMANTIC_AUTHORITY_MISSING")
    elif record["execution_result"] == "ESTABLISHED" and (
        record["proof_scope"] == "HARM" and not semantic_authority
    ):
        debts.add("ORACLE_SEMANTIC_AUTHORITY_MISSING")

    maximum_negative_scope = "NONE"
    negative_eligible = False
    if record["execution_result"] == "NOT_ESTABLISHED":
        exhaustive = record["negative_exhaustiveness"]
        if exhaustive == "SINGLE_PARAMETERIZATION":
            maximum_negative_scope = "ENCODED_PARAMETERIZATION_ONLY"
        elif exhaustive == "BOUNDED_DOMAIN":
            maximum_negative_scope = "BOUNDED_DOMAIN_ONLY"
        elif exhaustive == "EXHAUSTIVE_IN_SCOPE":
            if full_scope and semantic_authority:
                maximum_negative_scope = record["proof_scope"]
                negative_eligible = True
            else:
                maximum_negative_scope = "ENCODED_ORACLE_ONLY"
        if not negative_eligible:
            debts.add("NEGATIVE_SCOPE_NOT_TERMINAL")

    receipt = _receipt(
        record,
        proof_scope="IN_SCOPE_EXECUTION",
        capabilities=sorted(capabilities),
    )
    assessment = {
        "schema_version": EXECUTED_POC_SCOPE_ASSESSMENT_SCHEMA,
        "candidate_id": record["candidate_id"],
        "evidence_id": record["evidence_id"],
        "source_record_sha256": _canonical_sha256(record),
        "execution_authenticity": "AUTHENTICATED",
        "execution_result": record["execution_result"],
        "oracle_provenance": record["oracle_provenance"],
        "oracle_authority": authority,
        "reachability": record["reachability"],
        "environment_fidelity": record["environment_fidelity"],
        "precondition_coverage": preconditions,
        "proof_scope": record["proof_scope"],
        "external_premise_state": external_state,
        "negative_exhaustiveness": record["negative_exhaustiveness"],
        "positive_capabilities": sorted(capabilities),
        "maximum_negative_scope": maximum_negative_scope,
        "harm_evidence_eligible": "HARM" in capabilities,
        "negative_disposition_eligible": negative_eligible,
        "candidate_state": "ADJUDICATION_REQUIRED",
        "debts": sorted(debts),
        "evidence_receipt": receipt,
    }
    return _finalize_scope_assessment(assessment)


def _debt_scope_assessment(
    candidate_id: str,
    value: Any,
    *,
    debts: list[str],
) -> dict[str, Any]:
    candidate = _string(candidate_id, field="candidate_id")
    evidence_id = "UNBOUND-EVIDENCE"
    if isinstance(value, Mapping):
        raw_id = value.get("evidence_id")
        try:
            evidence_id = _string(raw_id, field="evidence_id")
        except EvidenceCapabilityError:
            pass
    source_digest = None
    if isinstance(value, Mapping):
        try:
            source_digest = _canonical_sha256(dict(value))
        except (TypeError, ValueError):
            source_digest = None
    assessment = {
        "schema_version": EXECUTED_POC_SCOPE_ASSESSMENT_SCHEMA,
        "candidate_id": candidate,
        "evidence_id": evidence_id,
        "source_record_sha256": source_digest,
        "execution_authenticity": "UNPROVEN_METADATA",
        "execution_result": "UNKNOWN",
        "oracle_provenance": "UNKNOWN",
        "oracle_authority": "UNBOUND",
        "reachability": "UNKNOWN",
        "environment_fidelity": "UNKNOWN",
        "precondition_coverage": "UNKNOWN",
        "proof_scope": "UNPROVEN",
        "external_premise_state": "UNKNOWN",
        "negative_exhaustiveness": "UNKNOWN",
        "positive_capabilities": [],
        "maximum_negative_scope": "NONE",
        "harm_evidence_eligible": False,
        "negative_disposition_eligible": False,
        "candidate_state": "VISIBLE_EVIDENCE_DEBT",
        "debts": sorted(set(debts)),
        "evidence_receipt": None,
    }
    return _finalize_scope_assessment(assessment)


def assess_executed_poc_scope(
    candidate_id: str, value: Mapping[str, Any]
) -> dict[str, Any]:
    """Fail visible: missing metadata retains the candidate as typed debt."""

    candidate = _string(candidate_id, field="candidate_id")
    try:
        assessment = issue_executed_poc_scope_assessment(value)
    except (EvidenceCapabilityError, TypeError, ValueError):
        return _debt_scope_assessment(
            candidate,
            value,
            debts=["MISSING_OR_INVALID_SCOPE_METADATA"],
        )
    if not _same_principal(assessment["candidate_id"], candidate):
        return _debt_scope_assessment(
            candidate,
            value,
            debts=["CANDIDATE_ID_MISMATCH"],
        )
    return assessment


def validate_executed_poc_scope_assessment(
    value: Mapping[str, Any],
) -> dict[str, Any]:
    """Validate a persisted P1-E assessment before any consumer uses it."""

    record = _require_exact_record(
        value,
        _EXECUTED_POC_SCOPE_ASSESSMENT_FIELDS,
        label="executed PoC scope assessment",
    )
    if record["schema_version"] != EXECUTED_POC_SCOPE_ASSESSMENT_SCHEMA:
        raise EvidenceCapabilityError("executed PoC scope assessment schema mismatch")
    normalized = dict(record)
    normalized["candidate_id"] = _string(
        record["candidate_id"], field="candidate_id"
    )
    normalized["evidence_id"] = _string(
        record["evidence_id"], field="evidence_id"
    )
    if record["source_record_sha256"] is not None:
        normalized["source_record_sha256"] = _sha256(
            record["source_record_sha256"], field="source_record_sha256"
        )
    normalized["execution_authenticity"] = _enum(
        record["execution_authenticity"],
        {"AUTHENTICATED", "UNPROVEN_METADATA"},
        field="execution_authenticity",
    )
    normalized["execution_result"] = _enum(
        record["execution_result"],
        {"ESTABLISHED", "NOT_ESTABLISHED", "EXECUTION_ERROR", "UNKNOWN"},
        field="execution_result",
    )
    normalized["oracle_provenance"] = _enum(
        record["oracle_provenance"],
        set(_ORACLE_PROVENANCE) | {"UNKNOWN"},
        field="oracle_provenance",
    )
    normalized["oracle_authority"] = _enum(
        record["oracle_authority"],
        {
            "PROTOCOL_AUTHORED",
            "INDEPENDENTLY_AUTHORED",
            "INDEPENDENTLY_VALIDATED",
            "GENERATED_UNREVIEWED",
            "UNBOUND",
        },
        field="oracle_authority",
    )
    normalized["reachability"] = _enum(
        record["reachability"], set(_REACHABILITY) | {"UNKNOWN"}, field="reachability"
    )
    normalized["environment_fidelity"] = _enum(
        record["environment_fidelity"],
        set(_ENVIRONMENT_FIDELITY) | {"UNKNOWN"},
        field="environment_fidelity",
    )
    normalized["precondition_coverage"] = _enum(
        record["precondition_coverage"],
        {"COMPLETE", "PARTIAL", "UNKNOWN"},
        field="precondition_coverage",
    )
    normalized["proof_scope"] = _enum(
        record["proof_scope"],
        set(_SCOPED_PROOF_TARGETS) | {"UNPROVEN"},
        field="proof_scope",
    )
    normalized["external_premise_state"] = _enum(
        record["external_premise_state"],
        {"RESOLVED", "UNRESOLVED", "CONFLICTING", "REFUTED", "UNKNOWN"},
        field="external_premise_state",
    )
    normalized["negative_exhaustiveness"] = _enum(
        record["negative_exhaustiveness"],
        set(_NEGATIVE_EXHAUSTIVENESS) | {"UNKNOWN"},
        field="negative_exhaustiveness",
    )
    normalized["positive_capabilities"] = _string_list(
        record["positive_capabilities"],
        field="positive_capabilities",
        minimum=0,
    )
    if any(
        capability not in EVIDENCE_CAPABILITIES
        for capability in normalized["positive_capabilities"]
    ):
        raise EvidenceCapabilityError("assessment capability enum is invalid")
    normalized["maximum_negative_scope"] = _enum(
        record["maximum_negative_scope"],
        {
            "NONE",
            "ENCODED_PARAMETERIZATION_ONLY",
            "BOUNDED_DOMAIN_ONLY",
            "ENCODED_ORACLE_ONLY",
            "MECHANISM_ONLY",
            "REACHABILITY",
            "HARM",
        },
        field="maximum_negative_scope",
    )
    for field in ("harm_evidence_eligible", "negative_disposition_eligible"):
        if not isinstance(record[field], bool):
            raise EvidenceCapabilityError(f"{field} must be boolean")
    normalized["candidate_state"] = _enum(
        record["candidate_state"],
        {"ADJUDICATION_REQUIRED", "VISIBLE_EVIDENCE_DEBT"},
        field="candidate_state",
    )
    normalized["debts"] = _string_list(
        record["debts"], field="debts", minimum=0
    )
    receipt = record["evidence_receipt"]
    if receipt is not None:
        normalized["evidence_receipt"] = validate_evidence_receipt(receipt)
        if (
            normalized["source_record_sha256"] is None
            or normalized["evidence_receipt"]["content_sha256"]
            != normalized["source_record_sha256"]
        ):
            raise EvidenceCapabilityError(
                "assessment receipt is not bound to source_record_sha256"
            )
        if normalized["evidence_receipt"]["evidence_id"] != normalized[
            "evidence_id"
        ]:
            raise EvidenceCapabilityError(
                "assessment and receipt evidence identities disagree"
            )
        if normalized["evidence_receipt"]["capabilities"] != normalized[
            "positive_capabilities"
        ]:
            raise EvidenceCapabilityError(
                "assessment and receipt capability sets disagree"
            )
    if normalized["execution_authenticity"] == "AUTHENTICATED" and receipt is None:
        raise EvidenceCapabilityError(
            "authenticated assessment requires an evidence receipt"
        )
    if normalized["execution_authenticity"] == "UNPROVEN_METADATA" and (
        receipt is not None or normalized["positive_capabilities"]
    ):
        raise EvidenceCapabilityError(
            "unproven metadata cannot carry evidence capabilities"
        )
    if normalized["harm_evidence_eligible"] != (
        "HARM" in normalized["positive_capabilities"]
    ):
        raise EvidenceCapabilityError(
            "harm eligibility disagrees with the capability set"
        )
    if normalized["harm_evidence_eligible"] and (
        normalized["execution_result"] != "ESTABLISHED"
        or normalized["proof_scope"] != "HARM"
    ):
        raise EvidenceCapabilityError(
            "harm eligibility requires established HARM-scoped evidence"
        )
    if normalized["negative_disposition_eligible"] and (
        normalized["execution_result"] != "NOT_ESTABLISHED"
        or normalized["maximum_negative_scope"]
        not in {"MECHANISM_ONLY", "REACHABILITY", "HARM"}
    ):
        raise EvidenceCapabilityError(
            "negative disposition eligibility exceeds its encoded scope"
        )
    if normalized["candidate_state"] == "VISIBLE_EVIDENCE_DEBT" and not normalized[
        "debts"
    ]:
        raise EvidenceCapabilityError("visible evidence debt requires a debt code")
    declared_digest = _sha256(record["assessment_digest"], field="assessment_digest")
    if declared_digest != _assessment_digest(normalized):
        raise EvidenceCapabilityError("assessment_digest mismatch")
    normalized["assessment_digest"] = declared_digest
    return normalized


def reconcile_execution_evidence_tags(
    text: str, assessment: Mapping[str, Any] | None
) -> dict[str, Any]:
    """Reconcile legacy display tags against typed P1-E authority.

    Tags remain presentation/compatibility data.  A tag with no valid typed
    assessment has no proof or negative-disposition authority.
    """

    declared = sorted(
        {match.group(1).upper() for match in _EXECUTION_TAG_RE.finditer(text or "")}
    )
    positive = bool(set(declared) & _POSITIVE_EXECUTION_TAGS)
    negative = bool(set(declared) & _NEGATIVE_EXECUTION_TAGS)
    if assessment is None:
        debts = ["MISSING_TYPED_EXECUTION_EVIDENCE"] if declared else []
        return {
            "declared_tags": declared,
            "status": "MISSING_TYPED_EVIDENCE" if declared else "NO_EXECUTION_EVIDENCE",
            "effective_capabilities": [],
            "proof_grade_harm": False,
            "negative_disposition_eligible": False,
            "debts": debts,
        }
    try:
        scoped = validate_executed_poc_scope_assessment(assessment)
    except (EvidenceCapabilityError, TypeError, ValueError):
        return {
            "declared_tags": declared,
            "status": "INVALID_TYPED_EVIDENCE",
            "effective_capabilities": [],
            "proof_grade_harm": False,
            "negative_disposition_eligible": False,
            "debts": ["INVALID_TYPED_EXECUTION_EVIDENCE"],
        }
    debts = set(scoped["debts"])
    if scoped["candidate_state"] == "VISIBLE_EVIDENCE_DEBT":
        debts.add("TYPED_EXECUTION_EVIDENCE_DEBT")
        return {
            "declared_tags": declared,
            "status": "TYPED_EVIDENCE_DEBT",
            "effective_capabilities": [],
            "proof_grade_harm": False,
            "negative_disposition_eligible": False,
            "debts": sorted(debts),
        }
    if positive and negative:
        debts.add("CONFLICTING_EXECUTION_TAGS")
        status = "CONFLICTING_TAGS"
        matched = False
    elif positive:
        matched = scoped["execution_result"] == "ESTABLISHED"
        if matched:
            status = (
                "MATCHED_HARM_SCOPE"
                if scoped["harm_evidence_eligible"]
                else "MATCHED_LIMITED_SCOPE"
            )
        else:
            status = "POLARITY_MISMATCH"
    elif negative:
        matched = scoped["execution_result"] == "NOT_ESTABLISHED"
        status = "MATCHED_NEGATIVE_SCOPE" if matched else "POLARITY_MISMATCH"
    else:
        matched = False
        status = "MISSING_EVIDENCE_TAG"
        debts.add("TYPED_RESULT_WITHOUT_MATCHING_TAG")
    if status == "POLARITY_MISMATCH":
        debts.add("TAG_RESULT_POLARITY_MISMATCH")
    effective = list(scoped["positive_capabilities"]) if matched and positive else []
    proof_grade_harm = bool(
        matched and positive and scoped["harm_evidence_eligible"]
    )
    negative_eligible = bool(
        matched and negative and scoped["negative_disposition_eligible"]
    )
    return {
        "declared_tags": declared,
        "status": status,
        "effective_capabilities": effective,
        "proof_grade_harm": proof_grade_harm,
        "negative_disposition_eligible": negative_eligible,
        "debts": sorted(debts),
    }


def issue_composition_receipt(value: Mapping[str, Any]) -> dict[str, Any]:
    """Issue composition evidence without inferring business harm."""

    record = _normalize_common(
        _require_exact_record(value, _COMPOSITION_FIELDS, label="composition evidence")
    )
    if record["schema_version"] != COMPOSITION_EVIDENCE_SCHEMA:
        raise EvidenceCapabilityError("composition evidence schema mismatch")
    if len(record["constituent_ids"]) < 2:
        raise EvidenceCapabilityError(
            "composition evidence requires at least two constituents"
        )
    record["composition_id"] = _string(
        record["composition_id"], field="composition_id"
    )
    record["relation_graph_sha256"] = _sha256(
        record["relation_graph_sha256"], field="relation_graph_sha256"
    )
    record["artifact_sha256"] = _sha256(
        record["artifact_sha256"], field="artifact_sha256"
    )
    method = _enum(
        record["composition_method"],
        {"EXECUTED_COMPOSED_HARNESS", "FORMAL_RELATION_PROOF"},
        field="composition_method",
    )
    record["composition_method"] = method
    record["execution_result"] = _enum(
        record["execution_result"],
        {"ESTABLISHED", "REFUTED"},
        field="execution_result",
    )
    reachability = _enum(
        record["reachability"], _REACHABILITY, field="reachability"
    )
    record["reachability"] = reachability
    proof_scope = (
        "IN_SCOPE_EXECUTION"
        if method == "EXECUTED_COMPOSED_HARNESS"
        else "FORMAL_PROOF"
    )
    # A completed harness/proof can attest that its artifact ran.  Without a
    # polarity field in the generic receipt, REFUTED must never carry the
    # positive COMPOSITION semantic capability.
    capabilities = (
        {"EXECUTION"}
        if method == "EXECUTED_COMPOSED_HARNESS"
        else set()
    )
    if (
        record["execution_result"] == "ESTABLISHED"
        and reachability == "IN_SCOPE_REACHABLE"
    ):
        capabilities.add("COMPOSITION")
    # Composition proves the relationship only.  HARM/IMPACT/LIKELIHOOD require
    # a separate independently issued provider receipt bound to those premises.
    return _receipt(
        record,
        proof_scope=proof_scope,
        capabilities=sorted(capabilities),
    )


__all__ = [
    "COMPOSITION_EVIDENCE_SCHEMA",
    "EVIDENCE_RECEIPT_SCHEMA",
    "EXECUTED_POC_EVIDENCE_SCHEMA",
    "EXECUTED_POC_SCOPE_ASSESSMENT_SCHEMA",
    "EXECUTED_POC_SCOPE_EVIDENCE_SCHEMA",
    "EXTERNAL_CITATION_EVIDENCE_SCHEMA",
    "FORMAL_PROPERTY_EVIDENCE_SCHEMA",
    "EvidenceCapabilityError",
    "assess_executed_poc_scope",
    "issue_composition_receipt",
    "issue_executed_poc_receipt",
    "issue_executed_poc_scope_assessment",
    "issue_external_citation_receipt",
    "issue_formal_property_receipt",
    "reconcile_execution_evidence_tags",
    "validate_evidence_receipt",
    "validate_executed_poc_scope_assessment",
]
