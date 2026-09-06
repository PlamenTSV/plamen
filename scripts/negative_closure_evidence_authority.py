"""Typed, replayable authority for the three terminal-negative decisions.

This module is intentionally independent of the driver and skeptic workflows.
It cannot turn assessor prose, source citations, formal-proof labels, or a
bounded execution into a terminal safety decision.  Authority is issued only
from an exact candidate binding plus a trusted, driver-observed provider run,
and every input is content addressed for replay.

The runtime integration must own the provider allow-list and the provider
execution receipt.  A candidate or model output must never be allowed to mint
either of them.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Mapping
from typing import Any


AUTHORITY_SCHEMA = "plamen.negative_closure_evidence_authority.v1"
PROVIDER_OUTPUT_SCHEMA = "plamen.negative_closure_provider_output.v1"
PROVIDER_EXECUTION_RECEIPT_SCHEMA = (
    "plamen.negative_closure_provider_execution_receipt.v1"
)

MECHANICAL_SCOPE_EXCLUSION = "MECHANICAL_SCOPE_EXCLUSION"
APPLIED_LOSSLESS_EQUIVALENCE = "APPLIED_LOSSLESS_EQUIVALENCE"
AUTHENTICATED_EXHAUSTIVE_NEGATIVE_EXECUTION = (
    "AUTHENTICATED_EXHAUSTIVE_NEGATIVE_EXECUTION"
)

TERMINAL_AUTHORITY_KINDS = frozenset(
    {
        MECHANICAL_SCOPE_EXCLUSION,
        APPLIED_LOSSLESS_EQUIVALENCE,
        AUTHENTICATED_EXHAUSTIVE_NEGATIVE_EXECUTION,
    }
)

SUPPORTING_NONTERMINAL_BASES = frozenset(
    {
        "IN_SCOPE_SOURCE",
        "PRIMARY_EXTERNAL_CITED",
        "EXTERNAL_PROSE",
        "INDEPENDENT_ANALYSIS",
        "INDEPENDENT_MODEL_ANALYSIS",
        "IN_SCOPE_EXECUTION",
        "BOUNDED_EXECUTION",
        "SINGLE_EXECUTION",
        "FORMAL_PROOF",
    }
)

_HEX64 = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/@+-]{0,255}$", re.ASCII)

_BINDING_FIELDS = frozenset(
    {"candidate_id", "work_item_id", "candidate_premise_ids"}
)
_OUTPUT_FIELDS = frozenset(
    {
        "schema_version",
        "authority_kind",
        "provider_id",
        "provider_version",
        *_BINDING_FIELDS,
        "evidence_claims",
        "scope_completeness",
        "oracle_authority",
        "mechanical_scope",
        "survivor_identity",
        "negative_execution",
    }
)
_CLAIM_FIELDS = frozenset(
    {
        "claim_id",
        "claim_kind",
        "evidence_id",
        "evidence_sha256",
        "premise_ids",
        "outcome",
    }
)
_MECHANICAL_FIELDS = frozenset(
    {
        "exclusion_rule_id",
        "exclusion_rule_version",
        "evaluated_subject_sha256",
        "result",
    }
)
_SURVIVOR_FIELDS = frozenset(
    {
        "absorbed_candidate_id",
        "canonical_survivor_id",
        "canonical_survivor_identity_sha256",
        "canonical_survivor_state",
        "application_receipt_sha256",
        "application_result",
        "preservation_result",
    }
)
_EXECUTION_FIELDS = frozenset(
    {
        "execution_assessment_sha256",
        "execution_receipt_sha256",
        "execution_authenticity",
        "execution_result",
        "negative_exhaustiveness",
        "proof_scope",
        "required_precondition_ids",
        "represented_precondition_ids",
        "environment_fidelity",
        "oracle_authority",
        "candidate_state",
        "negative_disposition_eligible",
    }
)
_RECEIPT_FIELDS = frozenset(
    {
        "schema_version",
        "authority_kind",
        "provider_id",
        "provider_version",
        "invocation_id",
        "provider_input_sha256",
        "provider_output_sha256",
        "execution_status",
        "exit_code",
        "issuer_identity",
        "issuer_invocation_id",
        "receipt_origin",
        "receipt_digest",
    }
)
_AUTHORITY_FIELDS = frozenset(
    {
        "schema_version",
        "authority_kind",
        *_BINDING_FIELDS,
        "evidence_claims",
        "provider_id",
        "provider_version",
        "provider_invocation_id",
        "provider_input_sha256",
        "provider_output_sha256",
        "provider_execution_receipt_sha256",
        "scope_completeness",
        "oracle_authority",
        "survivor_identity",
        "terminal_negative_authorized",
        "authority_digest",
    }
)


class NegativeClosureAuthorityError(ValueError):
    """A proposed terminal-negative authority is absent, stale, or invalid."""


def _reject_constant(value: str) -> None:
    raise NegativeClosureAuthorityError(f"non-finite JSON number: {value}")


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise NegativeClosureAuthorityError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_nonfinite_tree(value: Any) -> None:
    if isinstance(value, float) and not math.isfinite(value):
        raise NegativeClosureAuthorityError("non-finite JSON number")
    if isinstance(value, Mapping):
        for item in value.values():
            _reject_nonfinite_tree(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            _reject_nonfinite_tree(item)


def strict_json_loads(raw: bytes | str) -> Any:
    """Load JSON without duplicate keys, non-finite values, or bad UTF-8."""

    try:
        text = raw.decode("utf-8") if isinstance(raw, bytes) else raw
    except UnicodeDecodeError as exc:
        raise NegativeClosureAuthorityError("provider JSON is not UTF-8") from exc
    try:
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except NegativeClosureAuthorityError:
        raise
    except (json.JSONDecodeError, TypeError) as exc:
        raise NegativeClosureAuthorityError(f"invalid JSON: {exc}") from exc
    _reject_nonfinite_tree(value)
    return value


def canonical_json_bytes(value: Any) -> bytes:
    """Return the one accepted JSON encoding, rejecting non-finite values."""

    _reject_nonfinite_tree(value)
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise NegativeClosureAuthorityError(f"value is not canonical JSON: {exc}") from exc


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _payload_digest(value: Mapping[str, Any], field: str) -> str:
    unsigned = dict(value)
    unsigned.pop(field, None)
    return _sha256(canonical_json_bytes(unsigned))


def _object(value: Any, *, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise NegativeClosureAuthorityError(f"{field} must be an object")
    return value


def _exact_fields(value: Mapping[str, Any], expected: frozenset[str], *, field: str) -> None:
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise NegativeClosureAuthorityError(
            f"{field} schema mismatch (missing={missing}, extra={extra})"
        )


def _token(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or not _TOKEN.fullmatch(value):
        raise NegativeClosureAuthorityError(f"{field} is not a valid token")
    return value


def _hex64(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or not _HEX64.fullmatch(value):
        raise NegativeClosureAuthorityError(f"{field} is not a SHA-256 digest")
    return value


def _token_vector(value: Any, *, field: str, nonempty: bool = True) -> list[str]:
    if not isinstance(value, list):
        raise NegativeClosureAuthorityError(f"{field} must be an array")
    result = [_token(item, field=f"{field}[]") for item in value]
    if nonempty and not result:
        raise NegativeClosureAuthorityError(f"{field} must not be empty")
    if len(result) != len(set(result)):
        raise NegativeClosureAuthorityError(f"{field} contains duplicate IDs")
    if result != sorted(result):
        raise NegativeClosureAuthorityError(f"{field} must be canonically sorted")
    return result


def _binding(value: Mapping[str, Any], *, field: str) -> dict[str, Any]:
    _exact_fields(value, _BINDING_FIELDS, field=field)
    return {
        "candidate_id": _token(value["candidate_id"], field=f"{field}.candidate_id"),
        "work_item_id": _token(value["work_item_id"], field=f"{field}.work_item_id"),
        "candidate_premise_ids": _token_vector(
            value["candidate_premise_ids"],
            field=f"{field}.candidate_premise_ids",
        ),
    }


def _canonical_object_bytes(raw: bytes, *, field: str) -> dict[str, Any]:
    value = _object(strict_json_loads(raw), field=field)
    if raw != canonical_json_bytes(value):
        raise NegativeClosureAuthorityError(f"{field} is not canonical JSON")
    return value


def _validate_claims(value: Any, premises: list[str], kind: str) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not value:
        raise NegativeClosureAuthorityError("evidence_claims must be a non-empty array")
    expected = {
        MECHANICAL_SCOPE_EXCLUSION: ("MECHANICAL_SCOPE_FACT", "OUT_OF_SCOPE"),
        APPLIED_LOSSLESS_EQUIVALENCE: (
            "LOSSLESS_EQUIVALENCE_APPLICATION",
            "EQUIVALENT_TO_LIVE_SURVIVOR",
        ),
        AUTHENTICATED_EXHAUSTIVE_NEGATIVE_EXECUTION: (
            "EXHAUSTIVE_NEGATIVE_EXECUTION",
            "NO_HARM",
        ),
    }[kind]
    claims: list[dict[str, Any]] = []
    claim_ids: set[str] = set()
    evidence_ids: set[str] = set()
    covered: set[str] = set()
    for index, item in enumerate(value):
        row = _object(item, field=f"evidence_claims[{index}]")
        _exact_fields(row, _CLAIM_FIELDS, field=f"evidence_claims[{index}]")
        claim_id = _token(row["claim_id"], field="claim_id")
        evidence_id = _token(row["evidence_id"], field="evidence_id")
        if claim_id in claim_ids or evidence_id in evidence_ids:
            raise NegativeClosureAuthorityError("duplicate evidence claim identity")
        claim_ids.add(claim_id)
        evidence_ids.add(evidence_id)
        claim_kind = _token(row["claim_kind"], field="claim_kind")
        outcome = _token(row["outcome"], field="outcome")
        if (claim_kind, outcome) != expected:
            raise NegativeClosureAuthorityError(
                "evidence claim cannot authorize this negative-closure kind"
            )
        claim_premises = _token_vector(row["premise_ids"], field="premise_ids")
        if not set(claim_premises) <= set(premises):
            raise NegativeClosureAuthorityError("evidence claim names an unknown premise")
        covered.update(claim_premises)
        claims.append(
            {
                "claim_id": claim_id,
                "claim_kind": claim_kind,
                "evidence_id": evidence_id,
                "evidence_sha256": _hex64(
                    row["evidence_sha256"], field="evidence_sha256"
                ),
                "premise_ids": claim_premises,
                "outcome": outcome,
            }
        )
    if covered != set(premises):
        raise NegativeClosureAuthorityError(
            "evidence claims do not provide exact candidate premise coverage"
        )
    if [row["claim_id"] for row in claims] != sorted(claim_ids):
        raise NegativeClosureAuthorityError("evidence_claims must be canonically sorted")
    return claims


def _validate_mechanical(output: Mapping[str, Any]) -> None:
    if output["scope_completeness"] != "EXACT_MECHANICAL_SCOPE":
        raise NegativeClosureAuthorityError("mechanical scope is not exact")
    if output["oracle_authority"] != "DETERMINISTIC_MECHANICAL_PROVIDER":
        raise NegativeClosureAuthorityError("mechanical provider is not deterministic")
    row = _object(output["mechanical_scope"], field="mechanical_scope")
    _exact_fields(row, _MECHANICAL_FIELDS, field="mechanical_scope")
    _token(row["exclusion_rule_id"], field="exclusion_rule_id")
    _token(row["exclusion_rule_version"], field="exclusion_rule_version")
    _hex64(row["evaluated_subject_sha256"], field="evaluated_subject_sha256")
    if row["result"] != "OUT_OF_SCOPE":
        raise NegativeClosureAuthorityError("mechanical provider did not exclude scope")
    if output["survivor_identity"] is not None or output["negative_execution"] is not None:
        raise NegativeClosureAuthorityError("mechanical authority contains foreign detail")


def _validate_equivalence(
    output: Mapping[str, Any], *, live_survivors: Mapping[str, str]
) -> None:
    if output["scope_completeness"] != "APPLIED_LOSSLESS_EQUIVALENCE":
        raise NegativeClosureAuthorityError("semantic equivalence is not applied and lossless")
    if output["oracle_authority"] != "DETERMINISTIC_APPLICATION_RECEIPT":
        raise NegativeClosureAuthorityError("equivalence lacks application-receipt authority")
    row = _object(output["survivor_identity"], field="survivor_identity")
    _exact_fields(row, _SURVIVOR_FIELDS, field="survivor_identity")
    if row["absorbed_candidate_id"] != output["candidate_id"]:
        raise NegativeClosureAuthorityError("absorbed candidate identity mismatch")
    survivor_id = _token(row["canonical_survivor_id"], field="canonical_survivor_id")
    survivor_digest = _hex64(
        row["canonical_survivor_identity_sha256"],
        field="canonical_survivor_identity_sha256",
    )
    if survivor_id == output["candidate_id"]:
        raise NegativeClosureAuthorityError("candidate cannot survive its own absorption")
    if survivor_id not in live_survivors:
        raise NegativeClosureAuthorityError("canonical live survivor is absent")
    if live_survivors[survivor_id] != survivor_digest:
        raise NegativeClosureAuthorityError("canonical survivor identity is stale")
    if row["canonical_survivor_state"] != "LIVE":
        raise NegativeClosureAuthorityError("canonical survivor is not live")
    _hex64(row["application_receipt_sha256"], field="application_receipt_sha256")
    if row["application_result"] != "APPLIED":
        raise NegativeClosureAuthorityError("equivalence proposal was not applied")
    if row["preservation_result"] != "LOSSLESS":
        raise NegativeClosureAuthorityError("equivalence application was lossy")
    if output["mechanical_scope"] is not None or output["negative_execution"] is not None:
        raise NegativeClosureAuthorityError("equivalence authority contains foreign detail")


def _validate_execution(output: Mapping[str, Any], premises: list[str]) -> None:
    if output["scope_completeness"] not in {"EXHAUSTIVE_FULL", "EXHAUSTIVE_HARM"}:
        raise NegativeClosureAuthorityError("negative execution is not FULL/HARM exhaustive")
    if output["oracle_authority"] not in {
        "PROTOCOL_AUTHORED_INVARIANT",
        "INDEPENDENT_REVIEWER_ORACLE",
    }:
        raise NegativeClosureAuthorityError(
            "negative execution lacks protocol or independent oracle authority"
        )
    row = _object(output["negative_execution"], field="negative_execution")
    _exact_fields(row, _EXECUTION_FIELDS, field="negative_execution")
    _hex64(row["execution_assessment_sha256"], field="execution_assessment_sha256")
    _hex64(row["execution_receipt_sha256"], field="execution_receipt_sha256")
    required = _token_vector(
        row["required_precondition_ids"], field="required_precondition_ids"
    )
    represented = _token_vector(
        row["represented_precondition_ids"], field="represented_precondition_ids"
    )
    if required != premises or represented != premises:
        raise NegativeClosureAuthorityError(
            "negative execution does not cover every candidate premise/precondition"
        )
    exact = {
        "execution_authenticity": "AUTHENTICATED",
        "execution_result": "NEGATIVE",
        "negative_exhaustiveness": "EXHAUSTIVE",
        "environment_fidelity": "FULL",
        "candidate_state": "REFUTED",
        "negative_disposition_eligible": True,
    }
    for field, expected in exact.items():
        if row[field] != expected:
            raise NegativeClosureAuthorityError(
                f"negative execution {field} is not terminal-authority eligible"
            )
    if row["proof_scope"] not in {"FULL", "HARM"}:
        raise NegativeClosureAuthorityError("negative execution proof scope is not FULL/HARM")
    expected_scope = "EXHAUSTIVE_" + row["proof_scope"]
    if output["scope_completeness"] != expected_scope:
        raise NegativeClosureAuthorityError("negative execution scope binding mismatch")
    if row["oracle_authority"] != output["oracle_authority"]:
        raise NegativeClosureAuthorityError("negative execution oracle binding mismatch")
    if output["mechanical_scope"] is not None or output["survivor_identity"] is not None:
        raise NegativeClosureAuthorityError("negative execution contains foreign detail")


def _validate_provider_output(
    output: Mapping[str, Any],
    *,
    expected_binding: Mapping[str, Any],
    trusted_providers: Mapping[str, tuple[str, str]],
    live_survivors: Mapping[str, str],
) -> tuple[str, list[dict[str, Any]]]:
    _exact_fields(output, _OUTPUT_FIELDS, field="provider output")
    if output["schema_version"] != PROVIDER_OUTPUT_SCHEMA:
        raise NegativeClosureAuthorityError("provider output schema mismatch")
    kind = output["authority_kind"]
    if kind not in TERMINAL_AUTHORITY_KINDS:
        raise NegativeClosureAuthorityError("unsupported terminal-negative authority kind")
    provider_id = _token(output["provider_id"], field="provider_id")
    provider_version = _token(output["provider_version"], field="provider_version")
    trust = trusted_providers.get(provider_id)
    if trust is None:
        raise NegativeClosureAuthorityError("provider is not in the trusted provider registry")
    if not isinstance(trust, tuple) or len(trust) != 2:
        raise NegativeClosureAuthorityError("trusted provider registry entry is malformed")
    if trust != (provider_version, kind):
        raise NegativeClosureAuthorityError("trusted provider version/kind mismatch")
    actual_binding = _binding(
        {key: output[key] for key in _BINDING_FIELDS}, field="provider candidate binding"
    )
    if actual_binding != dict(expected_binding):
        raise NegativeClosureAuthorityError("provider candidate binding mismatch")
    premises = actual_binding["candidate_premise_ids"]
    claims = _validate_claims(output["evidence_claims"], premises, kind)
    if kind == MECHANICAL_SCOPE_EXCLUSION:
        _validate_mechanical(output)
    elif kind == APPLIED_LOSSLESS_EQUIVALENCE:
        _validate_equivalence(output, live_survivors=live_survivors)
    else:
        _validate_execution(output, premises)
    return kind, claims


def _validate_provider_receipt(
    receipt: Mapping[str, Any],
    *,
    output: Mapping[str, Any],
    kind: str,
    provider_input_bytes: bytes,
    provider_output_bytes: bytes,
) -> None:
    _exact_fields(receipt, _RECEIPT_FIELDS, field="provider execution receipt")
    if receipt["schema_version"] != PROVIDER_EXECUTION_RECEIPT_SCHEMA:
        raise NegativeClosureAuthorityError("provider execution receipt schema mismatch")
    exact = {
        "authority_kind": kind,
        "provider_id": output["provider_id"],
        "provider_version": output["provider_version"],
        "provider_input_sha256": _sha256(provider_input_bytes),
        "provider_output_sha256": _sha256(provider_output_bytes),
        "execution_status": "COMPLETE",
        "exit_code": 0,
        "issuer_identity": "PLAMEN_DRIVER",
        "receipt_origin": "DRIVER_OBSERVED_PROVIDER_EXECUTION",
    }
    for field, expected in exact.items():
        if receipt[field] != expected:
            if field == "provider_input_sha256":
                detail = "provider input digest mismatch"
            elif field == "provider_output_sha256":
                detail = "provider output digest mismatch"
            else:
                detail = f"provider execution receipt {field} mismatch"
            raise NegativeClosureAuthorityError(detail)
    _token(receipt["invocation_id"], field="invocation_id")
    _token(receipt["issuer_invocation_id"], field="issuer_invocation_id")
    _hex64(receipt["provider_input_sha256"], field="provider_input_sha256")
    _hex64(receipt["provider_output_sha256"], field="provider_output_sha256")
    expected_digest = _payload_digest(receipt, "receipt_digest")
    if receipt["receipt_digest"] != expected_digest:
        raise NegativeClosureAuthorityError("provider execution receipt digest mismatch")


def classify_negative_evidence_basis(basis: str) -> dict[str, Any]:
    """Classify all non-provider proof shapes as supporting, never terminal."""

    normalized = str(basis or "").strip().upper()
    # Unknown/new labels are conservative too: adding a label cannot mint proof.
    _ = normalized in SUPPORTING_NONTERMINAL_BASES
    return {
        "basis": str(basis),
        "disposition": "SUPPORTING_NONTERMINAL",
        "terminal_negative_authorized": False,
    }


def issue_negative_closure_authority(
    *,
    candidate_binding: Mapping[str, Any],
    provider_input_bytes: bytes,
    provider_output_bytes: bytes,
    provider_execution_receipt_bytes: bytes,
    trusted_providers: Mapping[str, tuple[str, str]],
    live_survivors: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Issue one terminal-negative authority after exact provider replay checks."""

    expected_binding = _binding(candidate_binding, field="candidate_binding")
    output = _canonical_object_bytes(provider_output_bytes, field="provider output")
    kind, claims = _validate_provider_output(
        output,
        expected_binding=expected_binding,
        trusted_providers=trusted_providers,
        live_survivors=live_survivors or {},
    )
    receipt = _canonical_object_bytes(
        provider_execution_receipt_bytes, field="provider execution receipt"
    )
    _validate_provider_receipt(
        receipt,
        output=output,
        kind=kind,
        provider_input_bytes=provider_input_bytes,
        provider_output_bytes=provider_output_bytes,
    )
    authority: dict[str, Any] = {
        "schema_version": AUTHORITY_SCHEMA,
        "authority_kind": kind,
        **expected_binding,
        "evidence_claims": claims,
        "provider_id": output["provider_id"],
        "provider_version": output["provider_version"],
        "provider_invocation_id": receipt["invocation_id"],
        "provider_input_sha256": _sha256(provider_input_bytes),
        "provider_output_sha256": _sha256(provider_output_bytes),
        "provider_execution_receipt_sha256": _sha256(
            provider_execution_receipt_bytes
        ),
        "scope_completeness": output["scope_completeness"],
        "oracle_authority": output["oracle_authority"],
        "survivor_identity": output["survivor_identity"],
        "terminal_negative_authorized": True,
    }
    authority["authority_digest"] = _payload_digest(authority, "authority_digest")
    return authority


def validate_negative_closure_authority(
    authority_bytes: bytes,
    *,
    candidate_binding: Mapping[str, Any],
    provider_input_bytes: bytes,
    provider_output_bytes: bytes,
    provider_execution_receipt_bytes: bytes,
    trusted_providers: Mapping[str, tuple[str, str]],
    live_survivors: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Replay and validate a persisted authority against current exact inputs."""

    authority = _canonical_object_bytes(authority_bytes, field="negative closure authority")
    _exact_fields(authority, _AUTHORITY_FIELDS, field="negative closure authority")
    if authority["schema_version"] != AUTHORITY_SCHEMA:
        raise NegativeClosureAuthorityError("negative closure authority schema mismatch")
    if authority.get("authority_digest") != _payload_digest(
        authority, "authority_digest"
    ):
        raise NegativeClosureAuthorityError("negative closure authority digest mismatch")
    expected = issue_negative_closure_authority(
        candidate_binding=candidate_binding,
        provider_input_bytes=provider_input_bytes,
        provider_output_bytes=provider_output_bytes,
        provider_execution_receipt_bytes=provider_execution_receipt_bytes,
        trusted_providers=trusted_providers,
        live_survivors=live_survivors,
    )
    if authority != expected:
        raise NegativeClosureAuthorityError(
            "negative closure authority is stale, forged, or non-canonical"
        )
    return authority


__all__ = [
    "APPLIED_LOSSLESS_EQUIVALENCE",
    "AUTHENTICATED_EXHAUSTIVE_NEGATIVE_EXECUTION",
    "AUTHORITY_SCHEMA",
    "MECHANICAL_SCOPE_EXCLUSION",
    "NegativeClosureAuthorityError",
    "PROVIDER_EXECUTION_RECEIPT_SCHEMA",
    "PROVIDER_OUTPUT_SCHEMA",
    "SUPPORTING_NONTERMINAL_BASES",
    "TERMINAL_AUTHORITY_KINDS",
    "canonical_json_bytes",
    "classify_negative_evidence_basis",
    "issue_negative_closure_authority",
    "strict_json_loads",
    "validate_negative_closure_authority",
]
