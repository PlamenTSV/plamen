"""Typed report-evidence and presentation authority (P1-K).

The report writer may improve wording, but it must not mint evidence authority
from a Markdown label.  This module keeps four independent facts separate:

* the adjudicated verdict;
* whether evidence execution/authorship is authentic;
* the exact proposition that evidence supports; and
* the client-facing presentation assurance.

The module is deliberately renderer-neutral and haltless.  Incomplete records
remain deliverable as explicit quality debt; they never become proof-grade and
they are never silently discarded merely to make the report look complete.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence


REPORT_EVIDENCE_RECORD_SCHEMA = "plamen.report_evidence_record.v1"
REPORT_EVIDENCE_BUNDLE_SCHEMA = "plamen.report_evidence_bundle.v1"
REPORT_QUALITY_RECEIPT_SCHEMA = "plamen.report_quality_receipt.v1"
REPORT_EVIDENCE_REPAIR_REQUEST_SCHEMA = (
    "plamen.report_evidence_repair_request.v1"
)
REPORT_EVIDENCE_REPAIR_RESPONSE_SCHEMA = (
    "plamen.report_evidence_repair_response.v1"
)
REPORT_EVIDENCE_REPAIR_RECEIPT_SCHEMA = (
    "plamen.report_evidence_repair_receipt.v1"
)
REPORT_EVIDENCE_REPAIR_APPLY_PLAN_SCHEMA = (
    "plamen.report_evidence_repair_apply_plan.v1"
)
REPORT_EVIDENCE_MANIFEST_SCHEMA = "plamen.report_evidence_manifest.v1"
_REPORT_EVIDENCE_TRANSACTION_SCHEMA = (
    "plamen.report_evidence_projection_transaction.v1"
)
_REPORT_EVIDENCE_TRANSACTION_FILE = (
    ".report_evidence_projection_transaction.json"
)
_MAX_JSON_BYTES = 8 * 1024 * 1024
_MAX_REPORT_RECORDS = 10_000
_MAX_MANIFEST_ROWS = 30
_MAX_MANIFESTS = 512

_HEX64_RE = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
_REPORT_ID_RE = re.compile(r"^[CHMLI]-\d+$", re.ASCII)
_SEVERITIES = frozenset(
    {"Critical", "High", "Medium", "Low", "Informational"}
)
_VERDICTS = frozenset(
    {
        "VERIFIED",
        "CONFIRMED",
        "CONTESTED",
        "UNRESOLVED",
        "UNVERIFIED",
    }
)
_AUTHENTICITY = frozenset(
    {
        "AUTHENTICATED_EXECUTION",
        "FORMAL_PROOF",
        "CODE_TRACE",
        "PRIMARY_EXTERNAL_CITATION",
        "UNPROVEN_METADATA",
        "NOT_EXECUTED",
    }
)
_EVIDENCE_RESULTS = frozenset(
    {"ESTABLISHED", "NOT_ESTABLISHED", "INCONCLUSIVE", "NOT_EXECUTED"}
)
_PROOF_SCOPES = frozenset(
    {
        "HARM",
        "MECHANISM_ONLY",
        "REACHABILITY",
        "COMPOSITION",
        "FORMAL_PROPERTY",
        "EXTERNAL_FACT",
        "NONE",
    }
)
_CAPABILITIES = frozenset(
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
_PRESENTATION_ASSURANCE = frozenset(
    {"PROOF_GRADE_HARM", "CONFIRMED_MECHANISM", "EVIDENCE_LIMITED"}
)
_PRECONDITION_LABELS = (
    "Preconditions",
    "Precondition",
    "Precondition Analysis",
    "Required Conditions",
    "Exploitability",
)
_PLACEHOLDER_VALUES = frozenset(
    {
        "n/a",
        "na",
        "none",
        "unknown",
        "todo",
        "tbd",
        "missing",
        "not provided",
        "not available",
        "omitted",
        "see above",
        "see verification artifact",
        "upstream finding",
        "review the cited location",
        "impact was not separately summarized by the verifier",
        "impact follows from the verified constituent evidence and report-index severity assignment",
        "verified evidence is listed in the shard manifest",
        "apply the mitigation described by the verifier artifacts and add regression coverage",
    }
)
_GENERIC_IMPACT_RE = re.compile(
    r"^(?:this|the)\s+(?:issue|finding|bug|condition)\s+"
    r"(?:can|could|may|might)\s+(?:cause|lead\s+to|impact|affect|result\s+in)\s+"
    r"(?:an?\s+)?(?:issue|impact|problem|risk|security\s+(?:issue|impact|risk))s?[.!]?$",
    re.IGNORECASE,
)
_RECORD_FIELDS = (
    "schema_version",
    "report_id",
    "candidate_ids",
    "severity",
    "title",
    "verdict",
    "mechanism",
    "preconditions",
    "impact",
    "affected_locations",
    "recommendation",
    "constituent_semantics",
    "evidence_authenticity",
    "evidence_result",
    "proof_scope",
    "capabilities",
    "evidence_sources",
    "limitations",
    "presentation_assurance",
    "record_digest",
)


class ReportEvidenceError(ValueError):
    """A typed report record or receipt violates its executable contract."""


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


def _clean_text(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    text = value.strip()
    if any(ord(char) < 32 and char not in "\n\t" for char in text):
        return ""
    return text


def _substantive(value: Any) -> bool:
    text = _clean_text(value)
    if not text:
        return False
    normalized = re.sub(r"\s+", " ", text).strip(" .:;`)._*").casefold()
    if normalized in _PLACEHOLDER_VALUES:
        return False
    if re.fullmatch(
        r"(?:no|none|missing|not\s+(?:provided|available))\s+"
        r"(?:impact|mechanism|preconditions?|recommendation|evidence|description)s?",
        normalized,
    ):
        return False
    return bool(re.search(r"[A-Za-z0-9]", text))


def _substantive_impact(value: Any) -> bool:
    text = _clean_text(value)
    return _substantive(text) and not bool(
        _GENERIC_IMPACT_RE.fullmatch(re.sub(r"\s+", " ", text).strip())
    )


def _substantive_title(value: Any) -> bool:
    text = _clean_text(value)
    if not _substantive(text):
        return False
    normalized = re.sub(r"[^a-z0-9]+", " ", text.casefold()).strip()
    if normalized in {
        "verified finding",
        "unverified finding",
        "upstream finding",
        "security finding",
        "finding",
    }:
        return False
    if re.fullmatch(
        r"(?:verified|unverified)?\s*(?:critical|high|medium|low|informational)?"
        r"\s*(?:severity\s*)?finding(?:\s+[a-z]+\s*\d+)?",
        normalized,
    ):
        return False
    return True


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        return []
    result: list[str] = []
    seen: set[str] = set()
    for raw in value:
        item = _clean_text(raw)
        key = item.casefold()
        if not item or key in seen:
            continue
        seen.add(key)
        result.append(item)
    return result


def _evidence_sources(value: Any) -> list[dict[str, str]]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        return []
    rows: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for raw in value:
        if not isinstance(raw, Mapping) or set(raw) != {"artifact", "sha256"}:
            continue
        artifact = _clean_text(raw.get("artifact"))
        sha256 = _clean_text(raw.get("sha256"))
        if (
            not artifact
            or Path(artifact).is_absolute()
            or ".." in Path(artifact).parts
            or not _HEX64_RE.fullmatch(sha256)
        ):
            continue
        key = (artifact.casefold(), sha256)
        if key in seen:
            continue
        seen.add(key)
        rows.append({"artifact": artifact, "sha256": sha256})
    return sorted(rows, key=lambda row: (row["artifact"].casefold(), row["sha256"]))


def _constituent_semantics(
    value: Any,
    *,
    candidate_ids: Sequence[str],
    aggregate: Mapping[str, Any],
) -> list[dict[str, Any]]:
    """Canonical per-constituent semantic denominator.

    A consolidated report record is not allowed to collapse distinct impacts
    into the primary candidate's prose.  Callers that do not yet supply the
    typed rows receive a conservative compatibility projection of the
    aggregate fields for every candidate; the live adapter supplies rows
    parsed independently from each exact verifier artifact.
    """

    raw_rows = value
    if not isinstance(raw_rows, Sequence) or isinstance(raw_rows, (str, bytes)):
        raw_rows = []
    if not raw_rows:
        raw_rows = [
            {
                "candidate_id": candidate_id,
                "mechanism": aggregate.get("mechanism"),
                "preconditions": aggregate.get("preconditions"),
                "impact": aggregate.get("impact"),
                "affected_locations": aggregate.get("affected_locations"),
                "recommendation": aggregate.get("recommendation"),
            }
            for candidate_id in candidate_ids
        ]
    expected_fields = {
        "candidate_id",
        "mechanism",
        "preconditions",
        "impact",
        "affected_locations",
        "recommendation",
    }
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    allowed = {item.upper() for item in candidate_ids}
    for raw in raw_rows:
        if not isinstance(raw, Mapping) or set(raw) != expected_fields:
            raise ReportEvidenceError(
                "constituent semantic row schema mismatch"
            )
        candidate_id = _clean_text(raw.get("candidate_id")).upper()
        if not candidate_id or candidate_id not in allowed or candidate_id in seen:
            raise ReportEvidenceError(
                "constituent semantic identity is invalid or duplicate"
            )
        seen.add(candidate_id)
        rows.append(
            {
                "candidate_id": candidate_id,
                "mechanism": _clean_text(raw.get("mechanism")),
                "preconditions": _string_list(raw.get("preconditions")),
                "impact": _clean_text(raw.get("impact")),
                "affected_locations": _string_list(
                    raw.get("affected_locations")
                ),
                "recommendation": _clean_text(raw.get("recommendation")),
            }
        )
    if seen != allowed:
        raise ReportEvidenceError(
            "constituent semantic coverage does not match candidate_ids"
        )
    return sorted(rows, key=lambda row: row["candidate_id"].casefold())


def derive_presentation_assurance(record: Mapping[str, Any]) -> str:
    """Derive presentation assurance without consulting prose labels."""

    capabilities = set(_string_list(record.get("capabilities")))
    authenticity = _clean_text(record.get("evidence_authenticity"))
    result = _clean_text(record.get("evidence_result"))
    proof_scope = _clean_text(record.get("proof_scope"))
    limitations = _string_list(record.get("limitations"))

    # Evidence authority and report-prose completeness are independent.  A
    # missing explanatory field remains explicit quality debt (and is also
    # reflected by the quality receipt), but cannot revoke an authenticated
    # execution result.  Compound/constituent scope debt is different: it is
    # evidence-scope debt and therefore still limits report-level assurance.
    if any(
        item
        in {
            "MULTI_CANDIDATE_ASSESSMENT_COVERAGE_PARTIAL",
            "MULTI_CANDIDATE_PROOF_SCOPE_UNRECONCILED",
        }
        for item in limitations
    ):
        return "EVIDENCE_LIMITED"

    if (
        authenticity == "AUTHENTICATED_EXECUTION"
        and result == "ESTABLISHED"
        and proof_scope == "HARM"
        and {"EXECUTION", "HARM"}.issubset(capabilities)
        and not any(
            limitation.startswith(("EXTERNAL_PREMISE_", "PROOF_SCOPE_"))
            for limitation in limitations
        )
    ):
        return "PROOF_GRADE_HARM"
    if (
        result == "ESTABLISHED"
        and "MECHANISM" in capabilities
        and authenticity
        in {"AUTHENTICATED_EXECUTION", "FORMAL_PROOF", "CODE_TRACE"}
    ):
        return "CONFIRMED_MECHANISM"
    return "EVIDENCE_LIMITED"


def evidence_fields_from_execution_assessment(
    assessment: Mapping[str, Any],
) -> dict[str, Any]:
    """Translate validated P1-E scope authority into report-evidence fields.

    The adapter imports lazily to keep the report schema reusable in isolated
    tooling.  It never consults legacy PoC/Fuzz/Confirmed display tags.
    """

    try:
        from evidence_capabilities import validate_executed_poc_scope_assessment

        scoped = validate_executed_poc_scope_assessment(assessment)
    except (ImportError, TypeError, ValueError) as exc:
        raise ReportEvidenceError(
            f"execution-scope assessment is invalid: {type(exc).__name__}: {exc}"
        ) from exc
    authenticity = (
        "AUTHENTICATED_EXECUTION"
        if scoped["execution_authenticity"] == "AUTHENTICATED"
        else "UNPROVEN_METADATA"
    )
    result = {
        "ESTABLISHED": "ESTABLISHED",
        "NOT_ESTABLISHED": "NOT_ESTABLISHED",
        "EXECUTION_ERROR": "INCONCLUSIVE",
        "UNKNOWN": "INCONCLUSIVE",
    }[scoped["execution_result"]]
    proof_scope = scoped["proof_scope"]
    if proof_scope not in {"HARM", "MECHANISM_ONLY", "REACHABILITY"}:
        proof_scope = "NONE"
    return {
        "evidence_authenticity": authenticity,
        "evidence_result": result,
        "proof_scope": proof_scope,
        "capabilities": list(scoped["positive_capabilities"]),
        "limitations": list(scoped["debts"]),
    }


def required_semantic_fields(record: Mapping[str, Any]) -> list[str]:
    """Return exact missing/placeholder fields for one bounded repair delta."""

    severity = _clean_text(record.get("severity"))
    missing: list[str] = []
    if not _substantive_title(record.get("title")):
        missing.append("title")
    if not _substantive(record.get("mechanism")):
        missing.append("mechanism")
    if not _string_list(record.get("affected_locations")):
        missing.append("affected_locations")
    if severity in {"Critical", "High", "Medium", "Low"}:
        if not _substantive_impact(record.get("impact")):
            missing.append("impact")
        if not _substantive(record.get("recommendation")):
            missing.append("recommendation")
    if severity in {"Critical", "High", "Medium"} and not _string_list(
        record.get("preconditions")
    ):
        missing.append("preconditions")
    if _clean_text(record.get("evidence_authenticity")) not in _AUTHENTICITY:
        missing.append("evidence_authenticity")
    if _clean_text(record.get("evidence_result")) not in _EVIDENCE_RESULTS:
        missing.append("evidence_result")
    if _clean_text(record.get("proof_scope")) not in _PROOF_SCOPES:
        missing.append("proof_scope")
    return sorted(set(missing))


def normalize_report_evidence_record(value: Mapping[str, Any]) -> dict[str, Any]:
    """Normalize a proposed record and bind all fields with a self digest.

    This function intentionally permits semantic incompleteness.  Callers use
    :func:`required_semantic_fields` to request one exact repair delta and then
    deliver an explicit limitation if the delta remains unresolved.
    """

    if not isinstance(value, Mapping):
        raise ReportEvidenceError("report evidence record must be an object")
    report_id = _clean_text(value.get("report_id")).upper()
    if not _REPORT_ID_RE.fullmatch(report_id):
        raise ReportEvidenceError("report_id is invalid")
    severity = _clean_text(value.get("severity"))
    if severity not in _SEVERITIES:
        raise ReportEvidenceError("severity is invalid")
    verdict = _clean_text(value.get("verdict")).upper()
    if verdict not in _VERDICTS:
        raise ReportEvidenceError("verdict is invalid")
    candidate_ids = _string_list(value.get("candidate_ids"))
    if not candidate_ids:
        raise ReportEvidenceError("candidate_ids requires at least one identity")
    authenticity = _clean_text(value.get("evidence_authenticity")).upper()
    if authenticity not in _AUTHENTICITY:
        authenticity = "UNPROVEN_METADATA"
    evidence_result = _clean_text(value.get("evidence_result")).upper()
    if evidence_result not in _EVIDENCE_RESULTS:
        evidence_result = "INCONCLUSIVE"
    proof_scope = _clean_text(value.get("proof_scope")).upper()
    if proof_scope not in _PROOF_SCOPES:
        proof_scope = "NONE"
    capabilities = sorted(
        set(_string_list(value.get("capabilities"))) & _CAPABILITIES
    )
    normalized: dict[str, Any] = {
        "schema_version": REPORT_EVIDENCE_RECORD_SCHEMA,
        "report_id": report_id,
        "candidate_ids": sorted(candidate_ids, key=str.casefold),
        "severity": severity,
        "title": _clean_text(value.get("title")),
        "verdict": verdict,
        "mechanism": _clean_text(value.get("mechanism")),
        "preconditions": _string_list(value.get("preconditions")),
        "impact": _clean_text(value.get("impact")),
        "affected_locations": _string_list(value.get("affected_locations")),
        "recommendation": _clean_text(value.get("recommendation")),
        "constituent_semantics": [],
        "evidence_authenticity": authenticity,
        "evidence_result": evidence_result,
        "proof_scope": proof_scope,
        "capabilities": capabilities,
        "evidence_sources": _evidence_sources(value.get("evidence_sources")),
        "limitations": _string_list(value.get("limitations")),
        "presentation_assurance": "EVIDENCE_LIMITED",
        "record_digest": "",
    }
    normalized["constituent_semantics"] = _constituent_semantics(
        value.get("constituent_semantics"),
        candidate_ids=normalized["candidate_ids"],
        aggregate=normalized,
    )
    missing = required_semantic_fields(normalized)
    for field in missing:
        limitation = f"REPORT_FIELD_MISSING:{field}"
        if limitation not in normalized["limitations"]:
            normalized["limitations"].append(limitation)
    normalized["limitations"] = sorted(set(normalized["limitations"]))
    normalized["presentation_assurance"] = derive_presentation_assurance(
        normalized
    )
    unsigned = dict(normalized)
    unsigned["record_digest"] = ""
    normalized["record_digest"] = _digest(unsigned)
    return normalized


def validate_report_evidence_record(value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != set(_RECORD_FIELDS):
        raise ReportEvidenceError("report evidence record schema mismatch")
    if value.get("schema_version") != REPORT_EVIDENCE_RECORD_SCHEMA:
        raise ReportEvidenceError("report evidence record version mismatch")
    normalized = normalize_report_evidence_record(value)
    if normalized != dict(value):
        raise ReportEvidenceError("report evidence record is non-canonical or tampered")
    return normalized


def apply_semantic_repair_delta(
    record: Mapping[str, Any], delta: Mapping[str, Any]
) -> dict[str, Any]:
    """Apply only fields named by the exact current missing-field delta."""

    current = validate_report_evidence_record(record)
    allowed = set(required_semantic_fields(current))
    if not isinstance(delta, Mapping) or not delta:
        raise ReportEvidenceError("repair delta must be a non-empty object")
    if not set(delta).issubset(allowed):
        raise ReportEvidenceError(
            "repair delta may modify only currently missing semantic fields"
        )
    proposal = dict(current)
    proposal.update(delta)
    proposal["limitations"] = [
        limitation
        for limitation in current["limitations"]
        if not (
            limitation.startswith("REPORT_FIELD_MISSING:")
            and limitation.split(":", 1)[1] in delta
        )
    ]
    proposal.pop("record_digest", None)
    proposal.pop("presentation_assurance", None)
    return normalize_report_evidence_record(proposal)


def build_report_evidence_bundle(
    records: Iterable[Mapping[str, Any]], *, expected_report_ids: Iterable[str]
) -> dict[str, Any]:
    canonical = [validate_report_evidence_record(record) for record in records]
    ids = [record["report_id"] for record in canonical]
    if len(ids) != len(set(ids)):
        raise ReportEvidenceError("report evidence bundle contains duplicate report IDs")
    expected = sorted({_clean_text(item).upper() for item in expected_report_ids})
    actual = sorted(ids)
    bundle = {
        "schema_version": REPORT_EVIDENCE_BUNDLE_SCHEMA,
        "expected_report_ids": expected,
        "records": sorted(canonical, key=lambda row: row["report_id"]),
        "missing_report_ids": sorted(set(expected) - set(actual)),
        "extra_report_ids": sorted(set(actual) - set(expected)),
        "bundle_digest": "",
    }
    unsigned = dict(bundle)
    unsigned["bundle_digest"] = ""
    bundle["bundle_digest"] = _digest(unsigned)
    return bundle


def validate_report_evidence_bundle(value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {
        "schema_version",
        "expected_report_ids",
        "records",
        "missing_report_ids",
        "extra_report_ids",
        "bundle_digest",
    }:
        raise ReportEvidenceError("report evidence bundle schema mismatch")
    if value.get("schema_version") != REPORT_EVIDENCE_BUNDLE_SCHEMA:
        raise ReportEvidenceError("report evidence bundle version mismatch")
    rebuilt = build_report_evidence_bundle(
        value.get("records") or [],
        expected_report_ids=value.get("expected_report_ids") or [],
    )
    if rebuilt != dict(value):
        raise ReportEvidenceError("report evidence bundle is non-canonical or tampered")
    return rebuilt


def derive_quality_receipt(
    bundle: Mapping[str, Any],
    *,
    delivered_report_ids: Iterable[str],
    limitation_visible_report_ids: Iterable[str],
    repair_attempts: Mapping[str, int] | None = None,
    typed_manifest_markdown_parity: bool | None = None,
    markdown_semantic_parity: bool | None = None,
) -> dict[str, Any]:
    """Classify structural delivery separately from semantic completeness."""

    canonical = validate_report_evidence_bundle(bundle)
    expected = set(canonical["expected_report_ids"])
    delivered = {_clean_text(item).upper() for item in delivered_report_ids}
    visible = {
        _clean_text(item).upper() for item in limitation_visible_report_ids
    }
    attempts = {
        _clean_text(key).upper(): int(value)
        for key, value in (repair_attempts or {}).items()
        if not isinstance(value, bool) and isinstance(value, int) and value >= 0
    }
    missing_by_id = {
        record["report_id"]: required_semantic_fields(record)
        for record in canonical["records"]
        if required_semantic_fields(record)
    }
    evidence_limitations_by_id = {
        record["report_id"]: list(record["limitations"])
        for record in canonical["records"]
        if record["limitations"]
    }
    parity_ok = all(
        value is not False
        for value in (
            typed_manifest_markdown_parity,
            markdown_semantic_parity,
        )
    )
    structural_complete = (
        not canonical["missing_report_ids"]
        and not canonical["extra_report_ids"]
        and delivered == expected
        and parity_ok
    )
    semantically_limited = set(missing_by_id) | set(evidence_limitations_by_id)
    semantic_complete = structural_complete and not semantically_limited
    hidden_debt = sorted(semantically_limited - visible)
    if semantic_complete:
        delivery_state = "SEMANTICALLY_COMPLETE"
    elif structural_complete and not hidden_debt:
        delivery_state = "DEGRADED_DELIVERY"
    else:
        delivery_state = "STRUCTURAL_DELIVERY_INCOMPLETE"
    receipt = {
        "schema_version": REPORT_QUALITY_RECEIPT_SCHEMA,
        "bundle_digest": canonical["bundle_digest"],
        "expected_report_ids": sorted(expected),
        "delivered_report_ids": sorted(delivered),
        "missing_semantic_fields": missing_by_id,
        "evidence_limitations": evidence_limitations_by_id,
        "hidden_quality_debt_report_ids": hidden_debt,
        "repair_attempts": dict(sorted(attempts.items())),
        "typed_manifest_markdown_parity": typed_manifest_markdown_parity,
        "markdown_semantic_parity": markdown_semantic_parity,
        "structurally_delivered": structural_complete,
        "semantically_complete": semantic_complete,
        "delivery_state": delivery_state,
        "receipt_digest": "",
    }
    unsigned = dict(receipt)
    unsigned["receipt_digest"] = ""
    receipt["receipt_digest"] = _digest(unsigned)
    return receipt


def write_report_evidence_bundle(
    scratchpad: Path,
    records: Iterable[Mapping[str, Any]],
    *,
    expected_report_ids: Iterable[str],
) -> dict[str, Any]:
    bundle = build_report_evidence_bundle(
        records, expected_report_ids=expected_report_ids
    )
    path = Path(scratchpad) / "report_evidence_records.json"
    path.write_bytes(_canonical_bytes(bundle) + b"\n")
    return bundle


def _read_json_object(
    path: Path, *, label: str, byte_budget: int = _MAX_JSON_BYTES
) -> dict[str, Any]:
    def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise ReportEvidenceError(
                    f"{label} contains duplicate key {key!r}"
                )
            value[key] = item
        return value

    try:
        raw = path.read_bytes()
        if len(raw) > byte_budget:
            raise ReportEvidenceError(f"{label} exceeds byte budget")
        value = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_pairs,
            parse_constant=lambda token: (_ for _ in ()).throw(
                ReportEvidenceError(
                    f"{label} contains non-finite number {token}"
                )
            ),
        )
    except ReportEvidenceError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ReportEvidenceError(
            f"{label} is missing or invalid: {type(exc).__name__}: {exc}"
        ) from exc
    if not isinstance(value, dict):
        raise ReportEvidenceError(f"{label} must be a JSON object")
    return value


def _artifact_source(scratchpad: Path, path: Path) -> dict[str, str]:
    try:
        relative = path.resolve().relative_to(scratchpad.resolve()).as_posix()
        content = path.read_bytes()
    except (OSError, ValueError) as exc:
        raise ReportEvidenceError(
            f"evidence source is unavailable or outside the scratchpad: {path}"
        ) from exc
    return {"artifact": relative, "sha256": hashlib.sha256(content).hexdigest()}


def _markdown_section(text: str, labels: Sequence[str]) -> str:
    if not text:
        return ""
    names = "|".join(re.escape(label) for label in labels)
    match = re.search(
        rf"(?ims)^#{{1,6}}\s*(?:\*\*)?(?:{names})(?:\*\*)?\s*:?[ \t]*\n"
        rf"(?P<body>.*?)(?=^#{{1,6}}\s|\Z)",
        text,
    )
    if match:
        return _clean_text(match.group("body"))
    bold = re.search(
        rf"(?ims)^\s*\*\*(?:{names})\*\*\s*:\s*(?:\n)?"
        rf"(?P<body>.*?)(?=^\s*\*\*[^\n]+\*\*\s*:|^#{{1,6}}\s|"
        rf"^\s*<!--|^\s*>\s*\*\*|\Z)",
        text,
    )
    return _clean_text(bold.group("body")) if bold else ""


def _markdown_field(text: str, labels: Sequence[str]) -> str:
    if not text:
        return ""
    names = "|".join(re.escape(label) for label in labels)
    match = re.search(
        rf"(?im)^\s*(?:[-*]\s*)?(?:\*\*)?(?:{names})(?:\*\*)?\s*:\s*(.+?)\s*$",
        text,
    )
    return _clean_text(match.group(1)) if match else ""


def _field_or_section(
    text: str, field_labels: Sequence[str], section_labels: Sequence[str]
) -> str:
    section = _markdown_section(text, section_labels)
    return section if _substantive(section) else _markdown_field(text, field_labels)


def _precondition_list(text: str) -> list[str]:
    # A bold block begins with a syntactically valid one-line Markdown field;
    # preferring that scalar would silently drop every later bullet.  Consume
    # the complete section denominator first and use a scalar only when no
    # block exists.
    raw = _markdown_section(text, _PRECONDITION_LABELS) or _markdown_field(
        text, _PRECONDITION_LABELS
    )
    if not raw:
        return []
    bullet_rows: list[str] = []
    for line in raw.splitlines():
        match = re.match(r"^\s*(?:[-*+]\s+|\d+[.)]\s+)(?P<value>.+)$", line)
        if match and _substantive(match.group("value")):
            bullet_rows.append(match.group("value").strip())
    if bullet_rows:
        return _string_list(bullet_rows)
    return (
        [re.sub(r"\s+", " ", raw).strip()]
        if _substantive(raw)
        else []
    )


def _candidate_ids(value: Any) -> list[str]:
    """Normalize structured identity fields without substring extraction.

    Candidate IDs arrive in typed scalar/list fields.  Mining a scalar with a
    flat regex collapsed compound namespaces such as ``L1-C-01`` and
    ``F-L1-C-01`` to the same suffix.  Preserve each complete field value;
    malformed multi-ID prose must fail later set reconciliation rather than be
    guessed into authority.
    """

    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        candidates = _string_list(value)
    else:
        text = _clean_text(value)
        candidates = [text] if text else []
    return sorted({item.upper() for item in candidates}, key=str.casefold)


_POSITIVE_UPSTREAM_DISPOSITIONS = frozenset(
    {"CONFIRMED", "TRUE_POSITIVE", "VALID", "CONFIRMED_MECHANISM"}
)
_PROCEDURAL_CONTESTED_DISPOSITIONS = frozenset(
    {
        "APPENDIX_ONLY",
        "DROP_FALSE_POSITIVE",
        "DROP_NON_SECURITY",
        "DROP_DESIGN_CONFIRMATION",
        "DROP_UNACTIONABLE_SPECULATION",
        "FALSE_POSITIVE",
        "REFUTED",
        "INFEASIBLE",
        "CLEAR",
        "SCHEMA_INVALID",
        "LOCATION_INVALID",
        "LOW_CONFIDENCE",
        "UNCONFIRMED",
    }
)
_PROCEDURAL_UNRESOLVED_DISPOSITIONS = frozenset(
    {
        "PARTIAL",
        "INCONCLUSIVE",
        "NEEDS_REVIEW",
        "NEEDS_VERIFICATION",
        "DUPLICATE",
        "CONSOLIDATED",
    }
)


def _disposition_token(value: Any) -> str:
    raw = _clean_text(value)
    # Reuse the canonical verifier enum parser rather than growing a second
    # lexical status language in the report layer.  Report-only statuses are
    # normalized by the narrow fallback below.
    try:
        from plamen_parsers import _canonical_verifier_status_enum

        shared = _canonical_verifier_status_enum(raw)
    except ImportError:
        shared = ""
    if shared:
        return shared
    if re.fullmatch(
        r"(?i)CLEAR\s*\(\s*(?:NO|NOT\s+A)\s+FINDING\s*\)",
        raw.strip().strip("`*_"),
    ):
        return "CLEAR"
    token = raw.strip().strip("`*_[] ").upper()
    token = re.sub(r"[\s-]+", "_", token)
    return re.sub(r"_+", "_", token).strip("_")


def _verdict_disposition(value: Any) -> tuple[str, list[str]]:
    """Map every closed upstream disposition without silent defaulting.

    The report record has a deliberately smaller public verdict vocabulary.
    Procedural, negative-proposal, and duplicate states therefore retain their
    exact upstream semantics as typed limitations while mapping conservatively
    into that vocabulary.  Unknown values become visible schema debt instead
    of being mislabeled ``UNVERIFIED``.
    """

    token = _disposition_token(value)
    if token in _VERDICTS:
        return token, []
    if token in _POSITIVE_UPSTREAM_DISPOSITIONS:
        return "CONFIRMED", []
    if token in _PROCEDURAL_CONTESTED_DISPOSITIONS:
        return "CONTESTED", [f"UPSTREAM_DISPOSITION:{token}"]
    if token in _PROCEDURAL_UNRESOLVED_DISPOSITIONS:
        return "UNRESOLVED", [f"UPSTREAM_DISPOSITION:{token}"]
    safe = re.sub(r"[^A-Z0-9_]+", "_", token).strip("_") or "EMPTY"
    return "UNRESOLVED", [f"REPORT_VERDICT_SCHEMA_UNKNOWN:{safe}"]


def _verdict(value: Any) -> str:
    return _verdict_disposition(value)[0]


def _assessment_path_for_verify(scratchpad: Path, verify_name: str) -> Path:
    relative = Path(verify_name)
    if relative.is_absolute() or ".." in relative.parts:
        raise ReportEvidenceError("verify artifact path escapes the scratchpad")
    base = relative.with_suffix("")
    return scratchpad / f"{base.as_posix()}.execution_scope_assessment.json"


def _candidate_for_verify_name(verify_name: str) -> str:
    stem = Path(verify_name).stem
    if not stem.casefold().startswith("verify_"):
        return ""
    return stem[7:].strip().upper()


def _structured_evidence_tag(text: str) -> tuple[str, str | None]:
    """Parse one exact structured Evidence Tag field.

    Bracket text in analysis prose is not a tag.  A malformed explicit field
    is retained as schema debt rather than substring-mined into authority.
    Other well-formed tags are returned to the caller but never interpreted as
    CODE_TRACE by this adapter.
    """

    scrubbed = re.sub(
        r"(?ms)^\s*(?:```|~~~)[^\n]*\n.*?^\s*(?:```|~~~)\s*$",
        "",
        text or "",
    )
    scrubbed = re.sub(r"(?s)<!--.*?-->", "", scrubbed)
    rows = [
        _clean_text(match.group("value"))
        for match in re.finditer(
            r"(?im)^\s*(?:[-*]\s*)?(?:\*\*)?Evidence\ Tag(?:\*\*)?"
            r"\s*:\s*(?P<value>.+?)\s*$",
            scrubbed,
        )
    ]
    if not rows:
        return "", None
    if len(rows) != 1:
        return "", "EVIDENCE_TAG_SCHEMA_INVALID"
    raw = rows[0]
    match = re.fullmatch(r"\[([A-Z0-9]+(?:-[A-Z0-9]+)*)\]", raw.strip())
    if match is None:
        return "", "EVIDENCE_TAG_SCHEMA_INVALID"
    return match.group(1), None


def _runtime_debt_source_for_manifest(
    scratchpad: Path,
    manifest_row: Mapping[str, Any],
    candidate_ids: Sequence[str],
    verify_files: Sequence[str],
) -> tuple[dict[str, str] | None, list[str]]:
    """Validate proof-free verifier-debt provenance for absent outputs.

    This source can only explain why exact candidates remain report-visible as
    UNRESOLVED.  It cannot provide evidence authenticity, execution result, or
    any negative-disposition authority.
    """

    raw = manifest_row.get("verification_runtime_debt")
    if raw is None:
        return None, []
    if not isinstance(raw, Mapping):
        raise ReportEvidenceError("verification runtime debt binding is malformed")
    expected = {
        "artifact",
        "sha256",
        "covered_candidate_ids",
        "authority",
        "verifier_status",
        "proof_authority",
    }
    if set(raw) != expected:
        raise ReportEvidenceError("verification runtime debt binding schema is invalid")
    artifact = _clean_text(raw.get("artifact"))
    covered_ids = _candidate_ids(raw.get("covered_candidate_ids"))
    if (
        artifact != "verification_runtime_debt.json"
        or raw.get("authority") != "RETENTION_ONLY"
        or raw.get("verifier_status") != "UNRESOLVED"
        or raw.get("proof_authority") != "NONE"
        or not covered_ids
        or not set(covered_ids).issubset(set(candidate_ids))
    ):
        raise ReportEvidenceError("verification runtime debt authority is invalid")
    path = scratchpad / artifact
    source = _artifact_source(scratchpad, path)
    if raw.get("sha256") != source["sha256"]:
        raise ReportEvidenceError("verification runtime debt source hash is stale")
    try:
        from plamen_validators import _verifier_output_has_completion_authority
    except ImportError as exc:
        raise ReportEvidenceError(
            "verifier completion authority is unavailable"
        ) from exc
    missing_ids = {
        candidate_id
        for candidate_id in candidate_ids
        if not _verifier_output_has_completion_authority(
            scratchpad, candidate_id
        )
    }
    if set(covered_ids) != missing_ids:
        raise ReportEvidenceError(
            "verification runtime debt does not exactly bind absent verifier outputs"
        )
    try:
        from plamen_validators import _verification_runtime_debt_coverage
    except ImportError as exc:
        raise ReportEvidenceError(
            "verification runtime debt validator is unavailable"
        ) from exc
    replayed, issues = _verification_runtime_debt_coverage(
        scratchpad, covered_ids
    )
    if issues or set(replayed) != set(covered_ids):
        raise ReportEvidenceError(
            "verification runtime debt failed exact replay: "
            + "; ".join(issues or ["coverage mismatch"])
        )
    return source, covered_ids


def _best_evidence_fields(
    scratchpad: Path,
    verify_files: Sequence[str],
    candidate_ids: Sequence[str],
    verify_texts: Sequence[str],
) -> tuple[dict[str, Any], list[str], list[dict[str, str]]]:
    limitations: set[str] = set()
    sources: list[dict[str, str]] = []
    candidates = {item.casefold() for item in candidate_ids}
    scoped_by_candidate: dict[str, list[dict[str, Any]]] = {}
    try:
        from execution_scope_runtime import (
            RUNTIME_SOURCE_SUFFIX,
            load_execution_scope_assessment,
        )
    except ImportError as exc:
        raise ReportEvidenceError(
            "live execution-scope runtime is unavailable"
        ) from exc

    for verify_name in verify_files:
        path = scratchpad / verify_name
        if path.exists() and path.is_file():
            sources.append(_artifact_source(scratchpad, path))
        verify_stem = Path(verify_name).stem
        if not verify_stem.lower().startswith("verify_"):
            continue
        candidate_id = verify_stem[7:]
        if not candidate_id:
            continue
        assessment_path = _assessment_path_for_verify(scratchpad, verify_name)
        runtime_source_path = scratchpad / (
            f"verify_{candidate_id}{RUNTIME_SOURCE_SUFFIX}"
        )
        loaded = load_execution_scope_assessment(scratchpad, candidate_id)
        if loaded.get("assessment") is None:
            for issue in loaded.get("issues") or ():
                token = _clean_text(issue)
                if token.startswith("INVALID_TYPED_EXECUTION_EVIDENCE"):
                    limitations.add("INVALID_TYPED_EXECUTION_EVIDENCE")
                elif token == "MISSING_TYPED_EXECUTION_EVIDENCE":
                    # The prose fallback below decides whether this missing
                    # typed authority is material.  A bare execution claim is
                    # retained but never upgraded.
                    pass
            continue
        try:
            raw = loaded["assessment"]
            candidate = _clean_text(raw.get("candidate_id")).casefold()
            if candidates and candidate not in candidates:
                raise ReportEvidenceError(
                    "execution assessment candidate identity does not match report record"
                )
            fields = evidence_fields_from_execution_assessment(raw)
        except ReportEvidenceError:
            limitations.add("INVALID_TYPED_EXECUTION_EVIDENCE")
            continue
        # Bind only authority that passed the live candidate/runtime replay.
        # A self-consistent standalone v1 assessment is never admitted as a
        # report source.  Missing/invalid bytes remain visible debt instead.
        try:
            sources.append(_artifact_source(scratchpad, assessment_path))
            sources.append(_artifact_source(scratchpad, runtime_source_path))
        except ReportEvidenceError:
            limitations.add("INVALID_TYPED_EXECUTION_EVIDENCE")
            continue
        scoped_by_candidate.setdefault(candidate, []).append(fields)

    scoped_options = [
        item
        for rows in scoped_by_candidate.values()
        for item in rows
    ]
    if scoped_options:
        rank = {"EVIDENCE_LIMITED": 0, "CONFIRMED_MECHANISM": 1, "PROOF_GRADE_HARM": 2}
        fields = max(
            scoped_options,
            key=lambda row: rank[derive_presentation_assurance(row)],
        )
        if len(candidates) > 1:
            covered = set(scoped_by_candidate)
            selected = [
                max(
                    rows,
                    key=lambda row: rank[derive_presentation_assurance(row)],
                )
                for rows in scoped_by_candidate.values()
            ]
            if covered != candidates:
                limitations.add("MULTI_CANDIDATE_ASSESSMENT_COVERAGE_PARTIAL")
                fields = {
                    "evidence_authenticity": "UNPROVEN_METADATA",
                    "evidence_result": "INCONCLUSIVE",
                    "proof_scope": "NONE",
                    "capabilities": [],
                    "limitations": [],
                }
            else:
                scope_rank = {
                    "NONE": 0,
                    "REACHABILITY": 1,
                    "MECHANISM_ONLY": 2,
                    "HARM": 3,
                }
                common_capabilities = set(selected[0].get("capabilities") or [])
                for row in selected[1:]:
                    common_capabilities &= set(row.get("capabilities") or [])
                # Constituent harm/composition capabilities are not report-level
                # authority. Keep only their conservative common lower scope.
                common_capabilities.difference_update({"HARM", "COMPOSITION", "IMPACT"})
                minimum_scope = min(
                    (
                        str(row.get("proof_scope") or "NONE")
                        for row in selected
                    ),
                    key=lambda item: scope_rank.get(item, 0),
                )
                if scope_rank.get(minimum_scope, 0) > scope_rank["MECHANISM_ONLY"]:
                    minimum_scope = "MECHANISM_ONLY"
                result_set = {
                    str(row.get("evidence_result") or "INCONCLUSIVE")
                    for row in selected
                }
                fields = {
                    "evidence_authenticity": (
                        "AUTHENTICATED_EXECUTION"
                        if all(
                            row.get("evidence_authenticity")
                            == "AUTHENTICATED_EXECUTION"
                            for row in selected
                        )
                        else "UNPROVEN_METADATA"
                    ),
                    "evidence_result": (
                        next(iter(result_set))
                        if len(result_set) == 1
                        else "INCONCLUSIVE"
                    ),
                    "proof_scope": minimum_scope,
                    "capabilities": sorted(common_capabilities),
                    "limitations": sorted(
                        {
                            limitation
                            for row in selected
                            for limitation in _string_list(row.get("limitations"))
                        }
                    ),
                }
            # Constituent execution can establish each constituent, but it
            # cannot establish the merged/equivalent/compound report claim.
            # A future typed equivalence/composition provider may discharge
            # this debt; prose grouping and report-index absorption cannot.
            limitations.add("MULTI_CANDIDATE_PROOF_SCOPE_UNRECONCILED")
        limitations.update(_string_list(fields.get("limitations")))
        fields = dict(fields)
        fields["limitations"] = sorted(limitations)
        return fields, sorted(limitations), sources

    if len(candidates) > 1:
        limitations.update(
            {
                "MULTI_CANDIDATE_ASSESSMENT_COVERAGE_PARTIAL",
                "MULTI_CANDIDATE_PROOF_SCOPE_UNRECONCILED",
            }
        )
        return (
            {
                "evidence_authenticity": "UNPROVEN_METADATA",
                "evidence_result": "INCONCLUSIVE",
                "proof_scope": "NONE",
                "capabilities": [],
                "limitations": sorted(limitations),
            },
            sorted(limitations),
            sources,
        )
    bounded_texts: list[str] = []
    exact_code_trace_tag = False
    code_trace_explanations: list[str] = []
    for verify_name, verify_text in zip(verify_files, verify_texts):
        candidate = _candidate_for_verify_name(verify_name).casefold()
        if not candidate or candidate not in candidates:
            continue
        bounded_texts.append(verify_text)
        tag, tag_debt = _structured_evidence_tag(verify_text)
        if tag_debt:
            limitations.add(tag_debt)
        if tag == "CODE-TRACE":
            exact_code_trace_tag = True
        explanation = _field_or_section(
            verify_text,
            ("Code Trace", "Source Trace"),
            ("Code Trace", "Source Trace"),
        )
        if _substantive(explanation):
            code_trace_explanations.append(explanation)
    joined = "\n\n".join(bounded_texts)
    execution_claimed = bool(
        re.search(
            r"(?i)\[(?:POC|FUZZ|MEDUSA|TRIDENT|CARGO-FUZZ)[-_ ]?(?:PASS|FAIL|EXECUTED)\]"
            r"|\b(?:PoC|test|harness)\s+(?:passed|failed|executed)\b",
            joined,
        )
    )
    if execution_claimed:
        limitations.add("MISSING_TYPED_EXECUTION_EVIDENCE")
    if exact_code_trace_tag or code_trace_explanations:
        if exact_code_trace_tag and not code_trace_explanations:
            limitations.add("CODE_TRACE_EXPLANATION_MISSING")
        established = bool(code_trace_explanations)
        return (
            {
                "evidence_authenticity": "CODE_TRACE",
                "evidence_result": (
                    "ESTABLISHED" if established else "INCONCLUSIVE"
                ),
                "proof_scope": "MECHANISM_ONLY" if established else "NONE",
                "capabilities": ["MECHANISM"] if established else [],
                "limitations": sorted(limitations),
            },
            sorted(limitations),
            sources,
        )
    return (
        {
            "evidence_authenticity": "NOT_EXECUTED",
            "evidence_result": "NOT_EXECUTED",
            "proof_scope": "NONE",
            "capabilities": [],
            "limitations": sorted(limitations),
        },
        sorted(limitations),
        sources,
    )


def _record_from_runtime_rows(
    scratchpad: Path,
    active: Mapping[str, Any],
    manifest_row: Mapping[str, Any],
    *,
    records_source: dict[str, str],
    manifest_source: dict[str, str],
) -> dict[str, Any]:
    report_id = _clean_text(
        manifest_row.get("report_id") or active.get("report_id")
    ).upper()
    verify_files = _string_list(
        manifest_row.get("verify_files")
        or ([manifest_row.get("verify_file")] if manifest_row.get("verify_file") else [])
    )
    candidate_id_set: set[str] = set()
    for source in (
        active.get("finding_id"),
        active.get("candidate_ids"),
        manifest_row.get("finding_id"),
        manifest_row.get("candidate_ids"),
        active.get("absorbed_finding_ids"),
        manifest_row.get("absorbed_finding_ids"),
    ):
        candidate_id_set.update(_candidate_ids(source))
    for verify_name in verify_files:
        verify_stem = Path(verify_name).stem
        if verify_stem.lower().startswith("verify_"):
            candidate_id_set.update(_candidate_ids(verify_stem[7:]))
    candidate_ids = sorted(candidate_id_set, key=str.casefold) or [report_id]
    runtime_debt_source, runtime_debt_ids = _runtime_debt_source_for_manifest(
        scratchpad, manifest_row, candidate_ids, verify_files
    )
    if runtime_debt_ids and _verdict(active.get("verdict")) != "UNRESOLVED":
        raise ReportEvidenceError(
            "verification runtime debt report row must remain UNRESOLVED"
        )
    verify_texts: list[str] = []
    constituent_rows: dict[str, dict[str, Any]] = {}
    for name in verify_files:
        relative = Path(name)
        if relative.is_absolute() or ".." in relative.parts:
            raise ReportEvidenceError("verify artifact path escapes the scratchpad")
        path = scratchpad / relative
        try:
            verify_text = path.read_text(encoding="utf-8", errors="replace")
            verify_texts.append(verify_text)
        except OSError:
            verify_text = ""
            verify_texts.append(verify_text)
        verify_stem = relative.stem
        candidate_id = (
            verify_stem[7:].upper()
            if verify_stem.lower().startswith("verify_")
            else ""
        )
        if candidate_id in candidate_ids:
            row = constituent_rows.setdefault(
                candidate_id,
                {
                    "candidate_id": candidate_id,
                    "mechanism": "",
                    "preconditions": [],
                    "impact": "",
                    "affected_locations": [],
                    "recommendation": "",
                },
            )
            for field, labels in (
                (
                    "mechanism",
                    ("Mechanism", "Finding Summary", "Root Cause", "Description"),
                ),
                ("impact", ("Impact", "Security Impact", "Combined Impact", "Risk")),
                (
                    "recommendation",
                    ("Recommendation", "Suggested Fix", "Mitigation", "Fix"),
                ),
            ):
                value = _field_or_section(verify_text, labels, labels)
                if _substantive(value) and not _substantive(row[field]):
                    row[field] = value
            row["preconditions"] = _string_list(
                [*row["preconditions"], *_precondition_list(verify_text)]
            )
            location = _markdown_field(
                verify_text, ("Location", "Primary Location")
            )
            row["affected_locations"] = _string_list(
                [*row["affected_locations"], location]
            )
    joined = "\n\n".join(verify_texts)
    mechanism = _field_or_section(
        joined,
        ("Mechanism", "Finding Summary", "Root Cause", "Description"),
        ("Finding Summary", "Root Cause", "Description", "Analysis"),
    ) or _clean_text(manifest_row.get("description"))
    impact = _field_or_section(
        joined,
        ("Impact", "Security Impact", "Combined Impact", "Risk"),
        ("Impact", "Security Impact", "Combined Impact", "Risk"),
    ) or _clean_text(manifest_row.get("impact") or active.get("impact"))
    recommendation = _field_or_section(
        joined,
        ("Recommendation", "Suggested Fix", "Mitigation", "Fix"),
        ("Recommendation", "Suggested Fix", "Mitigation", "Fix"),
    ) or _clean_text(manifest_row.get("recommendation"))
    locations = _string_list(
        manifest_row.get("affected_locations")
        or [
            manifest_row.get("location")
            or active.get("location")
            or _markdown_field(joined, ("Location", "Primary Location"))
        ]
    )
    evidence, evidence_limitations, evidence_sources = _best_evidence_fields(
        scratchpad, verify_files, candidate_ids, verify_texts
    )
    sources = [records_source, manifest_source, *evidence_sources]
    if runtime_debt_source is not None:
        sources.append(runtime_debt_source)
    unique_sources = {
        (row["artifact"], row["sha256"]): row
        for row in sources
    }
    limitations = set(evidence_limitations)
    if bool(manifest_row.get("report_blocked") or active.get("report_blocked")):
        limitations.add("UPSTREAM_REPORT_EVIDENCE_BLOCKED")
    if runtime_debt_ids:
        limitations.add("VERIFICATION_RUNTIME_DEBT_UNRESOLVED")
    upstream_verdict, disposition_limitations = _verdict_disposition(
        active.get("verdict") or _markdown_field(joined, ("Verdict",))
    )
    limitations.update(disposition_limitations)
    proposed = {
        "report_id": report_id,
        "candidate_ids": candidate_ids,
        "severity": _clean_text(
            manifest_row.get("severity") or active.get("severity")
        ),
        "title": _clean_text(manifest_row.get("title") or active.get("title")),
        "verdict": upstream_verdict,
        "mechanism": mechanism,
        "preconditions": _precondition_list(joined),
        "impact": impact,
        "affected_locations": locations,
        "recommendation": recommendation,
        "constituent_semantics": [
            constituent_rows.get(
                candidate_id,
                {
                    "candidate_id": candidate_id,
                    "mechanism": "",
                    "preconditions": [],
                    "impact": "",
                    "affected_locations": [],
                    "recommendation": "",
                },
            )
            for candidate_id in candidate_ids
        ],
        **evidence,
        "evidence_sources": list(unique_sources.values()),
        "limitations": sorted(
            limitations | set(_string_list(evidence.get("limitations")))
        ),
    }
    return normalize_report_evidence_record(proposed)


def _repair_request(bundle: Mapping[str, Any]) -> dict[str, Any]:
    canonical = validate_report_evidence_bundle(bundle)
    items = []
    for record in canonical["records"]:
        missing = required_semantic_fields(record)
        if not missing:
            continue
        items.append(
            {
                "report_id": record["report_id"],
                "record_digest": record["record_digest"],
                "missing_fields": missing,
                "attempt": 1,
            }
        )
    request = {
        "schema_version": REPORT_EVIDENCE_REPAIR_REQUEST_SCHEMA,
        "bundle_digest": canonical["bundle_digest"],
        "items": items,
        "request_digest": "",
    }
    unsigned = dict(request)
    unsigned["request_digest"] = ""
    request["request_digest"] = _digest(unsigned)
    return request


def validate_report_evidence_repair_request(
    value: Mapping[str, Any], *, bundle_digest: str | None = None
) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {
        "schema_version", "bundle_digest", "items", "request_digest"
    }:
        raise ReportEvidenceError("report evidence repair request schema mismatch")
    out = dict(value)
    if out.get("schema_version") != REPORT_EVIDENCE_REPAIR_REQUEST_SCHEMA:
        raise ReportEvidenceError("report evidence repair request version mismatch")
    if (
        not isinstance(out.get("bundle_digest"), str)
        or _HEX64_RE.fullmatch(out["bundle_digest"]) is None
        or (bundle_digest is not None and out["bundle_digest"] != bundle_digest)
    ):
        raise ReportEvidenceError("report evidence repair request bundle mismatch")
    items = out.get("items")
    if not isinstance(items, list):
        raise ReportEvidenceError("report evidence repair request items are invalid")
    prior = ""
    for item in items:
        if not isinstance(item, Mapping) or set(item) != {
            "report_id", "record_digest", "missing_fields", "attempt"
        }:
            raise ReportEvidenceError("report evidence repair request item schema mismatch")
        rid = item.get("report_id")
        missing = item.get("missing_fields")
        if (
            not isinstance(rid, str)
            or _REPORT_ID_RE.fullmatch(rid) is None
            or rid <= prior
            or not isinstance(item.get("record_digest"), str)
            or _HEX64_RE.fullmatch(item["record_digest"]) is None
            or not isinstance(missing, list)
            or missing != sorted(set(missing))
            or not missing
            or any(field not in _RECORD_FIELDS for field in missing)
            or type(item.get("attempt")) is not int
            or item.get("attempt") != 1
        ):
            raise ReportEvidenceError("report evidence repair request item is invalid")
        prior = rid
    declared = out.get("request_digest")
    if declared != _digest({**out, "request_digest": ""}):
        raise ReportEvidenceError("report evidence repair request digest mismatch")
    return out


def validate_report_evidence_repair_response(
    value: Mapping[str, Any], *, request_digest: str
) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {
        "schema_version", "request_digest", "items"
    }:
        raise ReportEvidenceError("repair response schema mismatch")
    out = dict(value)
    if out.get("schema_version") != REPORT_EVIDENCE_REPAIR_RESPONSE_SCHEMA:
        raise ReportEvidenceError("repair response schema mismatch")
    if out.get("request_digest") != request_digest:
        raise ReportEvidenceError("repair response is not bound to the active request")
    items = out.get("items")
    if not isinstance(items, list):
        raise ReportEvidenceError("repair response items must be a list")
    for item in items:
        if not isinstance(item, Mapping) or set(item) != {
            "report_id", "record_digest", "delta"
        }:
            raise ReportEvidenceError("repair response item schema mismatch")
        if (
            not isinstance(item.get("report_id"), str)
            or _REPORT_ID_RE.fullmatch(item["report_id"]) is None
            or not isinstance(item.get("record_digest"), str)
            or _HEX64_RE.fullmatch(item["record_digest"]) is None
            or not isinstance(item.get("delta"), Mapping)
        ):
            raise ReportEvidenceError("repair response item is invalid")
    return out


def _write_json(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = _canonical_bytes(value) + b"\n"
    if path.is_file() and path.read_bytes() == raw:
        return
    temp = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    try:
        with temp.open("wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, path)
    finally:
        temp.unlink(missing_ok=True)


def _write_json_exact_or_missing(
    path: Path, value: Mapping[str, Any], *, label: str
) -> None:
    """Fill a missing derived file without laundering existing drift."""

    expected = _canonical_bytes(value) + b"\n"
    if path.exists():
        try:
            actual = path.read_bytes()
        except OSError as exc:
            raise ReportEvidenceError(f"{label} is unreadable: {exc}") from exc
        if actual != expected:
            raise ReportEvidenceError(
                f"{label} already exists with stale or tampered bytes"
            )
        return
    _write_json(path, value)


def _write_text_exact_or_missing(path: Path, value: str, *, label: str) -> None:
    expected = value.encode("utf-8")
    if path.exists():
        try:
            actual = path.read_bytes()
        except OSError as exc:
            raise ReportEvidenceError(f"{label} is unreadable: {exc}") from exc
        if actual != expected:
            raise ReportEvidenceError(
                f"{label} already exists with stale or tampered bytes"
            )
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(expected)


def _projection_transaction(
    *, source_boundary_digest: str, outputs: Mapping[str, bytes]
) -> dict[str, Any]:
    transaction = {
        "schema_version": _REPORT_EVIDENCE_TRANSACTION_SCHEMA,
        "source_boundary_digest": source_boundary_digest,
        "outputs": {
            name: {
                "size": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest(),
            }
            for name, raw in sorted(outputs.items())
        },
        "transaction_digest": "",
    }
    transaction["transaction_digest"] = _digest(
        {**transaction, "transaction_digest": ""}
    )
    return transaction


def _validate_projection_transaction(
    value: Mapping[str, Any], *, expected: Mapping[str, Any]
) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {
        "schema_version",
        "source_boundary_digest",
        "outputs",
        "transaction_digest",
    }:
        raise ReportEvidenceError("report evidence projection transaction schema mismatch")
    if value.get("schema_version") != _REPORT_EVIDENCE_TRANSACTION_SCHEMA:
        raise ReportEvidenceError("report evidence projection transaction version mismatch")
    if dict(value) != dict(expected):
        raise ReportEvidenceError(
            "report evidence projection transaction is stale or tampered"
        )
    return dict(value)


def _write_text_projection_transaction_member(
    path: Path, value: str, *, recovery_armed: bool
) -> None:
    """Write the sole non-JSON projection with replayable crash semantics."""

    expected = value.encode("utf-8")
    if path.exists():
        actual = path.read_bytes()
        if actual == expected:
            return
        if not recovery_armed:
            raise ReportEvidenceError(
                "typed report evidence projection already exists with stale or tampered bytes"
            )
        temp = path.with_name(f".{path.name}.tmp-{os.getpid()}")
        try:
            temp.write_bytes(expected)
            os.replace(temp, path)
        finally:
            temp.unlink(missing_ok=True)
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    # The initial write intentionally targets the destination.  If the host
    # fails mid-write, the durable transaction marker makes exactly this
    # deterministic member replayable; unrelated stale bytes remain rejected.
    path.write_bytes(expected)


def _validate_repair_receipt(value: Mapping[str, Any]) -> dict[str, Any]:
    fields = {
        "schema_version",
        "request_digest",
        "response_digest",
        "baseline_bundle_digest",
        "repaired_bundle_digest",
        "repair_attempts",
        "receipt_digest",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        raise ReportEvidenceError("report evidence repair receipt schema mismatch")
    out = dict(value)
    if out.get("schema_version") != REPORT_EVIDENCE_REPAIR_RECEIPT_SCHEMA:
        raise ReportEvidenceError("report evidence repair receipt version mismatch")
    if any(
        not isinstance(out.get(field), str)
        or _HEX64_RE.fullmatch(str(out.get(field))) is None
        for field in (
            "request_digest",
            "response_digest",
            "baseline_bundle_digest",
            "repaired_bundle_digest",
        )
    ):
        raise ReportEvidenceError("report evidence repair receipt digest is invalid")
    attempts = out.get("repair_attempts")
    if not isinstance(attempts, Mapping) or any(
        not _REPORT_ID_RE.fullmatch(str(key))
        or type(value) is not int
        or value != 1
        for key, value in attempts.items()
    ):
        raise ReportEvidenceError("report evidence repair attempts are invalid")
    if dict(sorted(attempts.items())) != dict(attempts):
        raise ReportEvidenceError("report evidence repair attempts are non-canonical")
    declared = out.get("receipt_digest")
    if declared != _digest({**out, "receipt_digest": ""}):
        raise ReportEvidenceError("report evidence repair receipt digest mismatch")
    return out


def _repair_apply_plan(
    bundle: Mapping[str, Any],
    request: Mapping[str, Any],
    response: Mapping[str, Any],
) -> dict[str, Any]:
    canonical_bundle = validate_report_evidence_bundle(bundle)
    canonical_request = validate_report_evidence_repair_request(
        request, bundle_digest=canonical_bundle["bundle_digest"]
    )
    canonical_response = validate_report_evidence_repair_response(
        response, request_digest=canonical_request["request_digest"]
    )
    plan = {
        "schema_version": REPORT_EVIDENCE_REPAIR_APPLY_PLAN_SCHEMA,
        "baseline_bundle": canonical_bundle,
        "request": canonical_request,
        "response_digest": _digest(canonical_response),
        "plan_digest": "",
    }
    plan["plan_digest"] = _digest({**plan, "plan_digest": ""})
    return plan


def _validate_repair_apply_plan(
    value: Mapping[str, Any], response: Mapping[str, Any]
) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {
        "schema_version", "baseline_bundle", "request", "response_digest",
        "plan_digest",
    }:
        raise ReportEvidenceError("report repair apply plan schema mismatch")
    if value.get("schema_version") != REPORT_EVIDENCE_REPAIR_APPLY_PLAN_SCHEMA:
        raise ReportEvidenceError("report repair apply plan version mismatch")
    rebuilt = _repair_apply_plan(
        value.get("baseline_bundle") or {},
        value.get("request") or {},
        response,
    )
    if rebuilt != dict(value):
        raise ReportEvidenceError("report repair apply plan is stale or tampered")
    return rebuilt


def prepare_report_evidence_repair_apply_plan(
    scratchpad: Path, response: Mapping[str, Any]
) -> dict[str, Any]:
    """Durably arm the deterministic repair mutation without applying it."""

    root = Path(scratchpad)
    bundle = validate_report_evidence_bundle(
        _read_json_object(
            root / "report_evidence_records.json",
            label="report evidence bundle",
        )
    )
    request = validate_report_evidence_repair_request(
        _read_json_object(
            root / "report_evidence_repair_request.json",
            label="report evidence repair request",
        ),
        bundle_digest=bundle["bundle_digest"],
    )
    plan = _repair_apply_plan(bundle, request, response)
    _write_json_exact_or_missing(
        root / "report_evidence_repair_apply_plan.json",
        plan,
        label="report repair apply plan",
    )
    return plan


def _write_typed_manifests(
    scratchpad: Path,
    bundle: Mapping[str, Any],
    source_manifests: Mapping[str, Mapping[str, Any]],
    *,
    write: bool = True,
) -> dict[str, dict[str, Any]]:
    canonical = validate_report_evidence_bundle(bundle)
    records = {row["report_id"]: row for row in canonical["records"]}
    out_dir = scratchpad / "report_evidence_manifests"
    if write:
        out_dir.mkdir(parents=True, exist_ok=True)
    written: dict[str, dict[str, Any]] = {}
    expected_names: set[str] = set()
    for name, manifest in sorted(source_manifests.items()):
        expected_names.add(name)
        source_path = scratchpad / "body_manifests" / name
        rows: list[dict[str, Any]] = []
        for raw in manifest.get("findings", []) or []:
            if not isinstance(raw, Mapping):
                continue
            rid = _clean_text(raw.get("report_id")).upper()
            if rid not in records:
                continue
            row = dict(raw)
            row["report_evidence_record_digest"] = records[rid]["record_digest"]
            row["report_evidence"] = records[rid]
            rows.append(row)
        typed = {
            "schema_version": REPORT_EVIDENCE_MANIFEST_SCHEMA,
            "shard": _clean_text(manifest.get("shard")) or Path(name).stem,
            "source_manifest": _artifact_source(scratchpad, source_path),
            "bundle_digest": canonical["bundle_digest"],
            "findings": rows,
            "manifest_digest": "",
        }
        unsigned = dict(typed)
        unsigned["manifest_digest"] = ""
        typed["manifest_digest"] = _digest(unsigned)
        if write:
            _write_json(out_dir / name, typed)
        written[name] = typed
    if write:
        for stale in out_dir.glob("*.json"):
            if stale.name not in expected_names:
                stale.unlink(missing_ok=True)
    return written


def _projection_for_bundle(bundle: Mapping[str, Any]) -> str:
    canonical = validate_report_evidence_bundle(bundle)
    lines = [
        "# Typed Report Evidence Projection",
        "",
        "This projection is derived from `report_evidence_records.json`; Markdown labels do not create evidence authority.",
        "",
    ]
    for record in canonical["records"]:
        lines.extend(
            [
                f"## [{record['report_id']}] {record['title'] or 'Evidence-limited finding'}",
                "",
                f"- Record digest: `{record['record_digest']}`",
                f"- Verdict: {record['verdict']}",
                f"- Evidence authenticity: {record['evidence_authenticity']}",
                f"- Evidence result: {record['evidence_result']}",
                f"- Proof scope: {record['proof_scope']}",
                f"- Presentation assurance: {record['presentation_assurance']}",
                f"- Missing semantic fields: {', '.join(required_semantic_fields(record)) or 'none'}",
                "",
            ]
        )
    return "\n".join(lines).rstrip() + "\n"


def _load_source_manifests(scratchpad: Path) -> dict[str, dict[str, Any]]:
    directory = scratchpad / "body_manifests"
    if not directory.exists():
        raise ReportEvidenceError("body_manifests directory is missing")
    manifests: dict[str, dict[str, Any]] = {}
    for path in directory.glob("report_*.json"):
        if len(manifests) >= _MAX_MANIFESTS:
            raise ReportEvidenceError("body manifest count exceeds budget")
        value = _read_json_object(path, label=f"body manifest {path.name}")
        findings = value.get("findings")
        is_canonical_empty = (
            path.name == "report_empty.json"
            and value.get("schema_version")
            == "plamen.empty_report_denominator.v1"
            and value.get("shard") == "report_empty"
            and value.get("denominator_state") == "EMPTY"
            and findings == []
        )
        if isinstance(findings, list) and (findings or is_canonical_empty):
            if len(findings) > _MAX_MANIFEST_ROWS:
                raise ReportEvidenceError(
                    f"body manifest {path.name} exceeds row budget"
                )
            manifests[path.name] = value
    if not manifests:
        raise ReportEvidenceError("no finding-bearing body manifest exists")
    empty_manifest = manifests.get("report_empty.json")
    if empty_manifest is not None and len(manifests) != 1:
        raise ReportEvidenceError(
            "empty report denominator cannot coexist with finding-bearing manifests"
        )
    return manifests


def materialize_report_evidence_runtime(scratchpad: Path) -> dict[str, Any]:
    """Build the typed report boundary before any body writer renders prose.

    Existing body manifests and ``report_records.json`` remain intact.  Typed
    manifests are a dual-write projection, so old recovery paths continue to
    operate while the new authority is independently reconcilable.
    """

    root = Path(scratchpad)
    records_path = root / "report_records.json"
    report_records = _read_json_object(records_path, label="report records")
    active_rows = report_records.get("active") or []
    if not isinstance(active_rows, list):
        raise ReportEvidenceError("report records active set must be a list")
    if len(active_rows) > _MAX_REPORT_RECORDS:
        raise ReportEvidenceError("report records active set exceeds row budget")
    active_by_id: dict[str, Mapping[str, Any]] = {}
    for raw in active_rows:
        if not isinstance(raw, Mapping):
            continue
        rid = _clean_text(raw.get("report_id")).upper()
        if not _REPORT_ID_RE.fullmatch(rid) or rid in active_by_id:
            raise ReportEvidenceError("report records contain an invalid/duplicate ID")
        active_by_id[rid] = raw
    manifests = _load_source_manifests(root)
    manifest_by_id: dict[str, tuple[Mapping[str, Any], dict[str, str]]] = {}
    for name in sorted(manifests):
        manifest = manifests[name]
        source = _artifact_source(root, root / "body_manifests" / name)
        for raw in manifest.get("findings", []) or []:
            if not isinstance(raw, Mapping):
                continue
            rid = _clean_text(raw.get("report_id")).upper()
            if not _REPORT_ID_RE.fullmatch(rid) or rid in manifest_by_id:
                raise ReportEvidenceError("body manifests contain an invalid/duplicate ID")
            manifest_by_id[rid] = (raw, source)
    if set(active_by_id) != set(manifest_by_id):
        missing_from_manifests = sorted(set(active_by_id) - set(manifest_by_id))
        missing_from_records = sorted(set(manifest_by_id) - set(active_by_id))
        raise ReportEvidenceError(
            "report dual-write coverage mismatch: "
            f"missing_from_manifests={missing_from_manifests}; "
            f"missing_from_records={missing_from_records}"
        )
    for rid in sorted(active_by_id):
        active = active_by_id[rid]
        manifest = manifest_by_id[rid][0]
        active_candidates: set[str] = set()
        manifest_candidates: set[str] = set()
        for source in (
            active.get("finding_id"),
            active.get("candidate_ids"),
            active.get("absorbed_finding_ids"),
        ):
            active_candidates.update(_candidate_ids(source))
        for source in (
            manifest.get("finding_id"),
            manifest.get("candidate_ids"),
            manifest.get("absorbed_finding_ids"),
        ):
            manifest_candidates.update(_candidate_ids(source))
        for verify_name in _string_list(
            manifest.get("verify_files")
            or (
                [manifest.get("verify_file")]
                if manifest.get("verify_file")
                else []
            )
        ):
            stem = Path(verify_name).stem
            if stem.lower().startswith("verify_"):
                manifest_candidates.update(_candidate_ids(stem[7:]))
        if active_candidates != manifest_candidates:
            raise ReportEvidenceError(
                f"report dual-write conflict for {rid}.candidate_ids"
            )
        for field in ("severity", "title", "location"):
            left = _clean_text(active.get(field))
            right = _clean_text(manifest.get(field))
            if left != right:
                raise ReportEvidenceError(
                    f"report dual-write conflict for {rid}.{field}"
                )
        for field in ("report_blocked",):
            left = active.get(field)
            right = manifest.get(field)
            if not isinstance(left, bool) or not isinstance(right, bool):
                raise ReportEvidenceError(
                    f"report dual-write {rid}.{field} must be boolean"
                )
            if left is not right:
                raise ReportEvidenceError(
                    f"report dual-write conflict for {rid}.{field}"
                )
    expected = sorted(set(active_by_id) | set(manifest_by_id))
    records_source = _artifact_source(root, records_path)
    records: list[dict[str, Any]] = []
    for rid in expected:
        active = active_by_id.get(rid, {"report_id": rid})
        manifest_row, manifest_source = manifest_by_id.get(
            rid,
            (
                {
                    "report_id": rid,
                    "finding_id": active.get("finding_id", ""),
                    "severity": active.get("severity", ""),
                    "title": active.get("title", ""),
                    "location": active.get("location", ""),
                    "report_blocked": True,
                },
                records_source,
            ),
        )
        records.append(
            _record_from_runtime_rows(
                root,
                active,
                manifest_row,
                records_source=records_source,
                manifest_source=manifest_source,
            )
        )
    baseline = build_report_evidence_bundle(records, expected_report_ids=expected)
    bundle = baseline
    prior_receipt_path = root / "report_evidence_repair_receipt.json"
    prior_bundle_path = root / "report_evidence_records.json"
    if prior_receipt_path.exists():
        if not prior_bundle_path.exists():
            raise ReportEvidenceError(
                "report repair receipt exists without its repaired bundle"
            )
        prior_receipt = _validate_repair_receipt(
            _read_json_object(
                prior_receipt_path, label="report evidence repair receipt"
            )
        )
        prior_bundle = validate_report_evidence_bundle(
            _read_json_object(prior_bundle_path, label="report evidence bundle")
        )
        if (
            prior_receipt["baseline_bundle_digest"]
            != baseline["bundle_digest"]
            or prior_receipt["repaired_bundle_digest"]
            != prior_bundle["bundle_digest"]
        ):
            raise ReportEvidenceError(
                "report repair receipt is stale against the current source boundary"
            )
        bundle = prior_bundle
    request = _repair_request(bundle)
    if bundle["bundle_digest"] != baseline["bundle_digest"]:
        request = {
            "schema_version": REPORT_EVIDENCE_REPAIR_REQUEST_SCHEMA,
            "bundle_digest": bundle["bundle_digest"],
            "items": [],
            "request_digest": "",
        }
        request["request_digest"] = _digest({**request, "request_digest": ""})
    typed_manifests = _write_typed_manifests(
        root, bundle, manifests, write=False
    )
    expected_typed_names = set(typed_manifests)
    typed_dir = root / "report_evidence_manifests"
    if typed_dir.exists():
        stale = sorted(
            path.name
            for path in typed_dir.glob("*.json")
            if path.name not in expected_typed_names
        )
        if stale:
            raise ReportEvidenceError(
                "stale report evidence manifest ownership: " + ", ".join(stale)
            )
    projection = _projection_for_bundle(bundle)
    expected_output_bytes: dict[str, bytes] = {
        "report_evidence_records.json": _canonical_bytes(bundle) + b"\n",
        "report_evidence_repair_request.json": _canonical_bytes(request) + b"\n",
        "report_evidence_projection.md": projection.encode("utf-8"),
        **{
            f"report_evidence_manifests/{name}": _canonical_bytes(manifest)
            + b"\n"
            for name, manifest in typed_manifests.items()
        },
    }
    source_boundary_digest = _digest(
        {
            "report_records": records_source,
            "body_manifests": {
                name: _artifact_source(root, root / "body_manifests" / name)
                for name in sorted(manifests)
            },
            "bundle_digest": bundle["bundle_digest"],
        }
    )
    expected_transaction = _projection_transaction(
        source_boundary_digest=source_boundary_digest,
        outputs=expected_output_bytes,
    )
    transaction_path = root / _REPORT_EVIDENCE_TRANSACTION_FILE
    recovery_armed = transaction_path.exists()
    if recovery_armed:
        _validate_projection_transaction(
            _read_json_object(
                transaction_path,
                label="report evidence projection transaction",
            ),
            expected=expected_transaction,
        )
    else:
        # Refuse to arm a transaction over pre-existing drift.  A marker is
        # recovery authority only for a write that this exact source boundary
        # started, never a generic way to rebless arbitrary current bytes.
        for relative, expected_bytes in expected_output_bytes.items():
            path = root / relative
            if path.exists() and path.read_bytes() != expected_bytes:
                raise ReportEvidenceError(
                    f"{relative} already exists with stale or tampered bytes"
                )
        _write_json_exact_or_missing(
            transaction_path,
            expected_transaction,
            label="report evidence projection transaction",
        )
    # All existing authority bytes are compare-only.  Crash recovery may fill
    # a missing derived half, but tamper/source drift requires explicit report
    # rewind and can never be silently reblessed on resume.
    _write_json_exact_or_missing(
        root / "report_evidence_records.json",
        bundle,
        label="report evidence bundle",
    )
    _write_json_exact_or_missing(
        root / "report_evidence_repair_request.json",
        request,
        label="report evidence repair request",
    )
    for name, manifest in typed_manifests.items():
        _write_json_exact_or_missing(
            typed_dir / name,
            manifest,
            label=f"typed report manifest {name}",
        )
    _write_text_projection_transaction_member(
        root / "report_evidence_projection.md",
        projection,
        recovery_armed=recovery_armed,
    )
    validate_report_evidence_runtime(root)
    try:
        transaction_path.unlink()
    except OSError as exc:
        raise ReportEvidenceError(
            "report evidence projection transaction could not commit"
        ) from exc
    return {
        "bundle": bundle,
        "repair_request": request,
        "typed_manifests": typed_manifests,
    }


def validate_report_evidence_runtime(scratchpad: Path) -> dict[str, Any]:
    root = Path(scratchpad)
    bundle = validate_report_evidence_bundle(
        _read_json_object(root / "report_evidence_records.json", label="report evidence bundle")
    )
    try:
        from execution_scope_runtime import load_execution_scope_assessment
    except ImportError as exc:
        raise ReportEvidenceError(
            "live execution-scope runtime is unavailable"
        ) from exc
    for record in bundle["records"]:
        source_names = {
            source["artifact"] for source in record["evidence_sources"]
        }
        for source in record["evidence_sources"]:
            path = root / source["artifact"]
            try:
                actual_digest = hashlib.sha256(path.read_bytes()).hexdigest()
            except OSError as exc:
                raise ReportEvidenceError(
                    f"report evidence source is unavailable: {source['artifact']}"
                ) from exc
            if actual_digest != source["sha256"]:
                raise ReportEvidenceError(
                    f"report evidence source digest drift: {source['artifact']}"
                )
        # An admitted execution-scope assessment remains authority only while
        # the live P1-E replay still binds the same candidate, runtime source,
        # immutable successor, command, oracle, output, and source snapshot.
        # Merely hashing the two derived JSON files would miss drift in those
        # underlying authorities.
        for candidate_id in record["candidate_ids"]:
            assessment_name = (
                f"verify_{candidate_id}.execution_scope_assessment.json"
            )
            if assessment_name not in source_names:
                continue
            runtime_name = (
                f"verify_{candidate_id}.execution_scope_runtime_source.json"
            )
            if runtime_name not in source_names:
                raise ReportEvidenceError(
                    "execution assessment lacks its candidate-bound runtime source"
                )
            loaded = load_execution_scope_assessment(root, candidate_id)
            if loaded.get("assessment") is None:
                detail = "; ".join(
                    str(item) for item in (loaded.get("issues") or [])
                )
                raise ReportEvidenceError(
                    "live execution-scope authority no longer validates for "
                    f"{candidate_id}: {detail or loaded.get('status', 'INVALID')}"
                )
    source_manifests = _load_source_manifests(root)
    expected_typed = _write_typed_manifests(
        root, bundle, source_manifests, write=False
    )
    # Compare without rewriting so partial/tampered writes can never be
    # mistaken for validation success.
    for name, expected in expected_typed.items():
        actual = _read_json_object(
            root / "report_evidence_manifests" / name,
            label=f"typed report manifest {name}",
        )
        if actual != expected:
            raise ReportEvidenceError(f"typed report manifest {name} is non-canonical")
    covered_ids = [
        _clean_text(row.get("report_id")).upper()
        for manifest in expected_typed.values()
        for row in manifest.get("findings", [])
        if isinstance(row, Mapping)
    ]
    if (
        len(covered_ids) != len(set(covered_ids))
        or set(covered_ids) != set(bundle["expected_report_ids"])
    ):
        raise ReportEvidenceError(
            "typed report manifest coverage does not exactly match the evidence bundle"
        )
    projected = _projection_for_bundle(bundle)
    try:
        actual_projection = (root / "report_evidence_projection.md").read_text(
            encoding="utf-8"
        )
    except OSError as exc:
        raise ReportEvidenceError("typed report evidence projection is missing") from exc
    if actual_projection != projected:
        raise ReportEvidenceError("typed report evidence projection parity failed")
    return {"bundle": bundle, "typed_manifests": expected_typed}


def load_typed_report_evidence_shard(
    scratchpad: Path,
    shard: str,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Load one already-produced typed shard without consulting legacy inputs.

    Report-body writers consume the P1-K transaction, not the raw verifier,
    inventory, queue, or report-index sources from which that transaction was
    produced.  This narrow replay is therefore suitable for a deterministic
    fallback whose PhaseIO denominator contains exactly the bundle and one
    typed manifest.
    """

    root = Path(scratchpad)
    shard_name = _clean_text(shard)
    if not re.fullmatch(r"report_[a-z0-9_]+", shard_name):
        raise ReportEvidenceError("typed report shard identity is invalid")
    bundle = validate_report_evidence_bundle(
        _read_json_object(
            root / "report_evidence_records.json",
            label="report evidence bundle",
        )
    )
    path = root / "report_evidence_manifests" / f"{shard_name}.json"
    manifest = _read_json_object(path, label=f"typed report manifest {shard_name}")
    expected_keys = {
        "schema_version",
        "shard",
        "source_manifest",
        "bundle_digest",
        "findings",
        "manifest_digest",
    }
    if set(manifest) != expected_keys:
        raise ReportEvidenceError("typed report manifest schema mismatch")
    if (
        manifest.get("schema_version") != REPORT_EVIDENCE_MANIFEST_SCHEMA
        or manifest.get("shard") != shard_name
        or manifest.get("bundle_digest") != bundle["bundle_digest"]
    ):
        raise ReportEvidenceError("typed report manifest authority is stale")
    unsigned = dict(manifest)
    unsigned["manifest_digest"] = ""
    if manifest.get("manifest_digest") != _digest(unsigned):
        raise ReportEvidenceError("typed report manifest digest is invalid")
    source_manifest = manifest.get("source_manifest")
    if (
        not isinstance(source_manifest, Mapping)
        or set(source_manifest) != {"artifact", "sha256"}
        or not _HEX64_RE.fullmatch(_clean_text(source_manifest.get("sha256")))
    ):
        raise ReportEvidenceError("typed report source provenance is malformed")
    rows = manifest.get("findings")
    if not isinstance(rows, list) or not rows or len(rows) > _MAX_MANIFEST_ROWS:
        raise ReportEvidenceError("typed report shard row denominator is invalid")
    records_by_id = {row["report_id"]: row for row in bundle["records"]}
    records: list[dict[str, Any]] = []
    seen: set[str] = set()
    for row in rows:
        if not isinstance(row, Mapping):
            raise ReportEvidenceError("typed report shard row is malformed")
        record = validate_report_evidence_record(
            row.get("report_evidence") or {}
        )
        rid = record["report_id"]
        if (
            rid in seen
            or row.get("report_evidence_record_digest")
            != record["record_digest"]
            or records_by_id.get(rid) != record
        ):
            raise ReportEvidenceError(
                "typed report shard record binding is stale or duplicate"
            )
        seen.add(rid)
        records.append(record)
    return bundle, records


def render_typed_report_evidence_shard(
    scratchpad: Path,
    shard: str,
) -> str:
    """Render an evidence-limited body from only the typed P1-K boundary."""

    _bundle, records = load_typed_report_evidence_shard(scratchpad, shard)
    label = {
        "report_critical_high": "Critical & High Findings",
        "report_medium": "Medium Findings",
        "report_low_info": "Low & Informational Findings",
    }.get(shard)
    if label is None:
        label = "Findings"
    lines = [f"# {label}", ""]
    for record in records:
        lines.extend(
            [
                f"### [{record['report_id']}] {record['title']}",
                "",
                f"**Severity**: {record['severity']}",
                f"**Verdict**: {record['verdict']}",
                f"**Evidence assurance**: {_friendly_assurance(record['presentation_assurance'])}",
                "**Confidence**: UNVERIFIED"
                if record["presentation_assurance"] == "EVIDENCE_LIMITED"
                else f"**Confidence**: {record['presentation_assurance']}",
                "**Fallback status**: Typed evidence-limited rendering; independent review remains required.",
                "",
            ]
        )
        if record["affected_locations"]:
            lines.extend(
                [
                    "**Affected Locations**:",
                    *[f"- {value}" for value in record["affected_locations"]],
                    "",
                ]
            )
        if record["mechanism"]:
            lines.extend(["**Mechanism**:", record["mechanism"], ""])
        if record["preconditions"]:
            lines.extend(
                [
                    "**Preconditions**:",
                    *[f"- {value}" for value in record["preconditions"]],
                    "",
                ]
            )
        if record["impact"]:
            lines.extend(["**Impact**:", record["impact"], ""])
        if record["recommendation"]:
            lines.extend(
                ["**Recommendation**:", record["recommendation"], ""]
            )
        for constituent in record["constituent_semantics"]:
            lines.extend(
                [
                    f"**Constituent {constituent['candidate_id']}**:",
                    constituent["mechanism"],
                    *[f"- Precondition: {value}" for value in constituent["preconditions"]],
                    constituent["impact"],
                    *[f"- Location: {value}" for value in constituent["affected_locations"]],
                    constituent["recommendation"],
                    "",
                ]
            )
        lines.extend(
            [
                "**Evidence state**:",
                f"- Authenticity: {record['evidence_authenticity']}",
                f"- Result: {record['evidence_result']}",
                f"- Proof scope: {record['proof_scope']}",
                f"- Limitations: {', '.join(record['limitations']) or 'none'}",
                "",
            ]
        )
        limitation = _friendly_limitation(record)
        if limitation:
            lines.extend(
                [f"> **Evidence and report limitation**: {limitation}", ""]
            )
        lines.extend(
            [
                f"<!-- PLAMEN_REPORT_EVIDENCE rid={record['report_id']} sha256={record['record_digest']} -->",
                "",
            ]
        )
    return "\n".join(lines).rstrip() + "\n"


def validate_typed_report_evidence_shard_markdown(
    scratchpad: Path,
    shard: str,
    markdown: str,
) -> list[str]:
    """Replay exact typed-record delivery parity for one rendered shard."""

    bundle, records = load_typed_report_evidence_shard(scratchpad, shard)
    sections = _section_by_id(str(markdown))
    expected_ids = {record["report_id"] for record in records}
    issues: list[str] = []
    if set(sections) != expected_ids:
        issues.append(
            "typed fallback report-ID coverage mismatch: "
            f"expected={sorted(expected_ids)} actual={sorted(sections)}"
        )
    unauthorized = set(
        unauthorized_proof_grade_report_ids(str(markdown), bundle)
    )
    for record in records:
        rid = record["report_id"]
        section = sections.get(rid, "")
        marker = (
            f"<!-- PLAMEN_REPORT_EVIDENCE rid={rid} "
            f"sha256={record['record_digest']} -->"
        )
        if marker not in section:
            issues.append(f"{rid}: typed evidence marker parity failed")
        if _friendly_assurance(record["presentation_assurance"]) not in section:
            issues.append(f"{rid}: presentation-assurance parity failed")
        if rid in unauthorized:
            issues.append(f"{rid}: unauthorized proof-grade language")
        if not _record_markdown_semantic_parity(section, record):
            issues.append(f"{rid}: semantic-field parity failed")
        if (
            record["presentation_assurance"] == "EVIDENCE_LIMITED"
            and "**Evidence and report limitation**:" not in section
        ):
            issues.append(f"{rid}: evidence limitation is not visible")
    return issues


def _derive_report_evidence_repair_transition(
    scratchpad: Path,
    response: Mapping[str, Any],
) -> dict[str, Any]:
    """Derive the complete repair postimage without mutating disk."""

    root = Path(scratchpad)
    plan_path = root / "report_evidence_repair_apply_plan.json"
    if not plan_path.is_file():
        raise ReportEvidenceError(
            "report repair apply plan must be armed before postimage derivation"
        )
    plan = _validate_repair_apply_plan(
        _read_json_object(plan_path, label="report repair apply plan"),
        response,
    )
    bundle = plan["baseline_bundle"]
    request = plan["request"]
    response = validate_report_evidence_repair_response(
        response, request_digest=request["request_digest"]
    )
    requested = {item["report_id"]: item for item in request.get("items", [])}
    raw_items = response.get("items")
    if not isinstance(raw_items, list):
        raise ReportEvidenceError("repair response items must be a list")
    responded: dict[str, Mapping[str, Any]] = {}
    for raw in raw_items:
        if not isinstance(raw, Mapping):
            raise ReportEvidenceError("repair response item must be an object")
        rid = _clean_text(raw.get("report_id")).upper()
        if rid in responded:
            raise ReportEvidenceError("repair response contains a duplicate report ID")
        responded[rid] = raw
    if set(responded) != set(requested):
        raise ReportEvidenceError("repair response must dispose the exact request set")
    updated: list[dict[str, Any]] = []
    for record in bundle["records"]:
        rid = record["report_id"]
        if rid not in requested:
            updated.append(record)
            continue
        item = responded[rid]
        if item.get("record_digest") != requested[rid].get("record_digest"):
            raise ReportEvidenceError("repair response record digest mismatch")
        delta = item.get("delta")
        if not isinstance(delta, Mapping) or set(delta) != set(
            requested[rid].get("missing_fields") or []
        ):
            raise ReportEvidenceError("repair response delta must cover the exact missing fields")
        updated.append(apply_semantic_repair_delta(record, delta))
    repaired = build_report_evidence_bundle(
        updated, expected_report_ids=bundle["expected_report_ids"]
    )
    response_digest = _digest(response)
    receipt = {
        "schema_version": REPORT_EVIDENCE_REPAIR_RECEIPT_SCHEMA,
        "request_digest": request["request_digest"],
        "response_digest": response_digest,
        "baseline_bundle_digest": bundle["bundle_digest"],
        "repaired_bundle_digest": repaired["bundle_digest"],
        "repair_attempts": {rid: 1 for rid in sorted(requested)},
        "receipt_digest": "",
    }
    receipt["receipt_digest"] = _digest({**receipt, "receipt_digest": ""})
    # Exactly one repair attempt is permitted.  Any fields the bounded worker
    # could not ground remain explicit limitations and are never silently
    # queued for an unbounded sequence of model retries.
    next_request = {
        "schema_version": REPORT_EVIDENCE_REPAIR_REQUEST_SCHEMA,
        "bundle_digest": repaired["bundle_digest"],
        "items": [],
        "request_digest": "",
    }
    next_request["request_digest"] = _digest(
        {**next_request, "request_digest": ""}
    )
    source_manifests = _load_source_manifests(root)
    typed = _write_typed_manifests(
        root, repaired, source_manifests, write=False
    )
    # Crash recovery accepts only the exact before or after transaction bytes.
    # Arbitrary third-state content is tamper, not a reason to mint a new
    # baseline.  The durable apply plan is written before this mutation block.
    before_after: tuple[tuple[Path, bytes, bytes], ...] = (
        (
            root / "report_evidence_records.json",
            _canonical_bytes(bundle) + b"\n",
            _canonical_bytes(repaired) + b"\n",
        ),
        (
            root / "report_evidence_repair_request.json",
            _canonical_bytes(request) + b"\n",
            _canonical_bytes(next_request) + b"\n",
        ),
        (
            root / "report_evidence_projection.md",
            _projection_for_bundle(bundle).encode("utf-8"),
            _projection_for_bundle(repaired).encode("utf-8"),
        ),
    )
    prior_typed = _write_typed_manifests(
        root, bundle, source_manifests, write=False
    )
    for name, manifest in typed.items():
        before_after += ((
            root / "report_evidence_manifests" / name,
            _canonical_bytes(prior_typed[name]) + b"\n",
            _canonical_bytes(manifest) + b"\n",
        ),)
    return {
        "bundle": bundle,
        "request": request,
        "response": response,
        "repaired": repaired,
        "receipt": receipt,
        "next_request": next_request,
        "typed": typed,
        "before_after": before_after,
    }


def plan_report_evidence_repair_output_bytes(
    scratchpad: Path,
    response: Mapping[str, Any],
) -> dict[str, bytes]:
    """Return the exact DRIVER output postimage for PhaseIO successor arming."""

    root = Path(scratchpad)
    transition = _derive_report_evidence_repair_transition(root, response)
    planned = {
        path.relative_to(root).as_posix(): after
        for path, _before, after in transition["before_after"]
    }
    planned["report_evidence_repair_receipt.json"] = (
        _canonical_bytes(transition["receipt"]) + b"\n"
    )
    return planned


def apply_report_evidence_repair_response(
    scratchpad: Path, response: Mapping[str, Any]
) -> dict[str, Any]:
    """Apply exactly one response to the exact missing-field delta."""

    root = Path(scratchpad)
    receipt_path = root / "report_evidence_repair_receipt.json"
    if receipt_path.exists():
        raise ReportEvidenceError("the bounded report evidence repair was already consumed")
    plan_path = root / "report_evidence_repair_apply_plan.json"
    if not plan_path.exists():
        prepare_report_evidence_repair_apply_plan(root, response)
    transition = _derive_report_evidence_repair_transition(root, response)
    bundle = transition["bundle"]
    repaired = transition["repaired"]
    next_request = transition["next_request"]
    typed = transition["typed"]
    receipt = transition["receipt"]
    before_after = transition["before_after"]
    for path, before, after in before_after:
        try:
            current = path.read_bytes()
        except OSError as exc:
            raise ReportEvidenceError(
                f"report repair transaction artifact unavailable: {path.name}"
            ) from exc
        if current not in {before, after}:
            raise ReportEvidenceError(
                f"report repair transaction artifact has third-state bytes: {path.name}"
            )
    _write_json(root / "report_evidence_records.json", repaired)
    _write_json(root / "report_evidence_repair_request.json", next_request)
    for name, manifest in typed.items():
        _write_json(root / "report_evidence_manifests" / name, manifest)
    projection_path = root / "report_evidence_projection.md"
    projection = _projection_for_bundle(repaired).encode("utf-8")
    if projection_path.read_bytes() != projection:
        temp = projection_path.with_name(
            f".{projection_path.name}.tmp-{os.getpid()}"
        )
        try:
            temp.write_bytes(projection)
            os.replace(temp, projection_path)
        finally:
            temp.unlink(missing_ok=True)
    # Receipt last is the transaction commit point.  An interrupted apply is
    # replayed from the immutable plan; a committed apply is never attempted a
    # second time.
    _write_json_exact_or_missing(
        receipt_path, receipt, label="report evidence repair receipt"
    )
    validate_report_evidence_runtime(root)
    return {
        "bundle": repaired,
        "repair_request": next_request,
        "repair_attempts": receipt["repair_attempts"],
        "typed_manifests": typed,
    }


def _report_sections(markdown: str) -> list[tuple[str, int, int]]:
    headings = list(
        re.finditer(
            r"(?im)^###\s*(?:\[REPORT-BLOCKED[^\]]*\]\s*)?\[([CHMLI]-\d+)\][^\n]*$",
            markdown or "",
        )
    )
    sections: list[tuple[str, int, int]] = []
    for index, match in enumerate(headings):
        next_finding = (
            headings[index + 1].start()
            if index + 1 < len(headings)
            else len(markdown)
        )
        # H1/H2 headings are report-level boundaries.  In particular, the
        # final finding must not absorb remediation summaries or appendices
        # merely because there is no later H3 finding heading.
        next_report_heading = re.search(
            r"(?m)^#{1,2}\s+\S.*$", markdown[match.end() : next_finding]
        )
        end = (
            match.end() + next_report_heading.start()
            if next_report_heading is not None
            else next_finding
        )
        sections.append((match.group(1).upper(), match.start(), end))
    return sections


def _friendly_assurance(value: str) -> str:
    return {
        "PROOF_GRADE_HARM": "Proof-grade harm evidence",
        "CONFIRMED_MECHANISM": "Confirmed mechanism; harm proof not established",
        "EVIDENCE_LIMITED": "Evidence limited",
    }.get(value, "Evidence limited")


def _friendly_limitation(record: Mapping[str, Any]) -> str:
    missing = required_semantic_fields(record)
    parts: list[str] = []
    if missing:
        if len(missing) == 1:
            fields = missing[0]
        elif len(missing) == 2:
            fields = " and ".join(missing)
        else:
            fields = ", ".join(missing[:-1]) + ", and " + missing[-1]
        parts.append(
            "The finding is retained, but the report could not substantively complete "
            f"{fields} within the bounded report-repair pass."
        )
    limitations = set(_string_list(record.get("limitations")))
    if "MISSING_TYPED_EXECUTION_EVIDENCE" in limitations:
        parts.append(
            "Execution labels were not backed by authenticated, scope-bound execution metadata; "
            "they do not establish proof-grade harm."
        )
    if "INVALID_TYPED_EXECUTION_EVIDENCE" in limitations:
        parts.append(
            "Execution metadata failed integrity validation and was not used as proof authority."
        )
    if "UPSTREAM_REPORT_EVIDENCE_BLOCKED" in limitations:
        parts.append(
            "Upstream evidence delivery was incomplete; the finding remains visible for review."
        )
    external = sorted(
        item for item in limitations if item.startswith("EXTERNAL_PREMISE_")
    )
    if external:
        parts.append(
            "One or more external premises remain unresolved, so the report preserves the finding "
            "without presenting those premises as proven."
        )
    if not parts and limitations:
        parts.append(
            "The available evidence has a bounded proof scope; the finding is retained without "
            "claiming stronger proof than the typed evidence supports."
        )
    return " ".join(parts)


def _ensure_field(section: str, label: str, value: str) -> str:
    if not _substantive(value):
        return section
    if _markdown_field(section, (label,)) or _markdown_section(section, (label,)):
        return section
    return section.rstrip() + f"\n\n**{label}**:\n{value.strip()}\n"


def project_report_evidence_markdown(
    markdown: str, bundle: Mapping[str, Any]
) -> str:
    """Deterministically bind typed evidence to report Markdown sections."""

    canonical = validate_report_evidence_bundle(bundle)
    records = {record["report_id"]: record for record in canonical["records"]}
    text = markdown or ""
    sections = _report_sections(text)
    if not sections:
        return text
    rebuilt: list[str] = []
    cursor = 0
    for rid, start, end in sections:
        rebuilt.append(text[cursor:start])
        section = text[start:end]
        record = records.get(rid)
        if record is None:
            rebuilt.append(section)
            cursor = end
            continue
        section = re.sub(
            r"(?im)^\*\*Evidence assurance\*\*:\s*.*\n?", "", section
        )
        section = re.sub(
            r"(?ims)\n?>\s*\*\*Evidence and report limitation\*\*:\s*.*?"
            r"(?=\n\n(?:\*\*[^\n]+\*\*:|<!-- PLAMEN_REPORT_EVIDENCE)|\Z)",
            "\n",
            section,
        )
        section = re.sub(
            r"(?im)^<!-- PLAMEN_REPORT_EVIDENCE rid=[CHMLI]-\d+ sha256=[0-9a-f]{64} -->\s*\n?",
            "",
            section,
        )
        assurance = _friendly_assurance(record["presentation_assurance"])
        verdict_match = re.search(r"(?im)^\*\*Verdict\*\*:[^\n]*$", section)
        assurance_line = f"**Evidence assurance**: {assurance}"
        if verdict_match:
            section = (
                section[: verdict_match.end()]
                + "\n"
                + assurance_line
                + section[verdict_match.end() :]
            )
        else:
            first_break = section.find("\n")
            insert_at = first_break + 1 if first_break >= 0 else len(section)
            section = section[:insert_at] + "\n" + assurance_line + "\n" + section[insert_at:]
        section = _ensure_field(section, "Mechanism", record["mechanism"])
        if record["preconditions"] and not (
            _markdown_field(section, _PRECONDITION_LABELS)
            or _markdown_section(section, _PRECONDITION_LABELS)
        ):
            section = section.rstrip() + "\n\n**Preconditions**:\n" + "\n".join(
                f"- {item}" for item in record["preconditions"]
            ) + "\n"
        section = _ensure_field(section, "Impact", record["impact"])
        section = _ensure_field(section, "Recommendation", record["recommendation"])
        limitation = _friendly_limitation(record)
        if limitation:
            section = section.rstrip() + (
                "\n\n> **Evidence and report limitation**: " + limitation + "\n"
            )
        section = section.rstrip() + (
            f"\n\n<!-- PLAMEN_REPORT_EVIDENCE rid={rid} "
            f"sha256={record['record_digest']} -->\n"
        )
        rebuilt.append(section)
        cursor = end
    rebuilt.append(text[cursor:])
    return "".join(rebuilt)


def _section_by_id(markdown: str) -> dict[str, str]:
    return {
        rid: markdown[start:end]
        for rid, start, end in _report_sections(markdown)
    }


def unauthorized_proof_grade_report_ids(
    markdown: str, bundle: Mapping[str, Any]
) -> list[str]:
    """Return sections whose prose claims more proof than typed authority."""

    canonical = validate_report_evidence_bundle(bundle)
    sections = _section_by_id(markdown)
    unauthorized: list[str] = []
    widened_claim = re.compile(
        r"(?i)\b(?:PoC|test|execution|harness|fuzz(?:er|ing)?)\s+"
        r"(?:proves?|proved|confirms?|confirmed|demonstrates?|establishes?)\s+"
        r"(?:the\s+)?(?:harm|impact|exploit(?:ability)?)\b"
    )
    for record in canonical["records"]:
        if record["presentation_assurance"] == "PROOF_GRADE_HARM":
            continue
        section = sections.get(record["report_id"], "")
        if (
            "**Evidence assurance**: Proof-grade harm evidence" in section
            or widened_claim.search(section)
        ):
            unauthorized.append(record["report_id"])
    return sorted(unauthorized)


def _semantic_text(value: Any) -> str:
    return re.sub(r"\s+", " ", _clean_text(value)).strip().casefold()


def _semantic_values_present(section: str, values: Iterable[Any]) -> bool:
    haystack = _semantic_text(section)
    return all(
        not _substantive(value) or _semantic_text(value) in haystack
        for value in values
    )


def _record_markdown_semantic_parity(
    section: str, record: Mapping[str, Any]
) -> bool:
    """Exact authoritative fields plus a per-constituent claim denominator."""

    heading = re.search(
        r"(?im)^###\s*(?:\[REPORT-BLOCKED[^\]]*\]\s*)?"
        r"\[[CHMLI]-\d+\]\s*(?P<title>[^\n]*)$",
        section,
    )
    if heading is None or _semantic_text(heading.group("title")) != _semantic_text(
        record.get("title")
    ):
        return False
    exact_scalar_fields = (
        (("Severity",), record.get("severity")),
        (("Verdict",), record.get("verdict")),
        (("Mechanism",), record.get("mechanism")),
        (("Impact", "Security Impact", "Combined Impact", "Risk"), record.get("impact")),
        (("Recommendation", "Suggested Fix", "Mitigation", "Fix"), record.get("recommendation")),
    )
    for labels, expected in exact_scalar_fields:
        if not _substantive(expected):
            continue
        actual = _field_or_section(section, labels, labels)
        if _semantic_text(actual) != _semantic_text(expected):
            return False
    expected_preconditions = {
        _semantic_text(value) for value in _string_list(record.get("preconditions"))
    }
    if expected_preconditions and {
        _semantic_text(value) for value in _precondition_list(section)
    } != expected_preconditions:
        return False
    expected_locations = _string_list(record.get("affected_locations"))
    location_text = _field_or_section(
        section,
        ("Location", "Affected Locations", "Primary Location"),
        ("Location", "Affected Locations", "Primary Location"),
    )
    if expected_locations and not _semantic_values_present(
        location_text, expected_locations
    ):
        return False
    for constituent in record.get("constituent_semantics") or []:
        if not isinstance(constituent, Mapping):
            return False
        semantic_values: list[Any] = [
            constituent.get("mechanism"),
            constituent.get("impact"),
            constituent.get("recommendation"),
            *(_string_list(constituent.get("preconditions"))),
            *(_string_list(constituent.get("affected_locations"))),
        ]
        if not _semantic_values_present(section, semantic_values):
            return False
    return True


def finalize_report_evidence_delivery(
    scratchpad: Path, *, report_path: Path, compare_only: bool = False
) -> dict[str, Any]:
    """Derive and optionally write the final typed delivery receipt.

    ``compare_only`` is the terminal/resume path: the receipt must already
    exist with the exact canonical bytes derived from the delivered report.
    It never fills a missing receipt and therefore cannot turn a later check
    into a new producer attempt or rebless missing/tampered terminal state.
    """

    root = Path(scratchpad)
    runtime = validate_report_evidence_runtime(root)
    bundle = runtime["bundle"]
    try:
        markdown = Path(report_path).read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise ReportEvidenceError("delivered report is missing or unreadable") from exc
    sections = _section_by_id(markdown)
    records = {record["report_id"]: record for record in bundle["records"]}
    unauthorized_proof = set(
        unauthorized_proof_grade_report_ids(markdown, bundle)
    )
    parity_by_id: dict[str, bool] = {}
    semantic_by_id: dict[str, bool] = {}
    visible: set[str] = set()
    for rid, record in records.items():
        section = sections.get(rid, "")
        parity_by_id[rid] = bool(
            re.search(
                rf"(?im)^<!-- PLAMEN_REPORT_EVIDENCE rid={re.escape(rid)} "
                rf"sha256={re.escape(record['record_digest'])} -->$",
                section,
            )
            and _friendly_assurance(record["presentation_assurance"]) in section
        )
        semantic_by_id[rid] = (
            rid not in unauthorized_proof
            and _record_markdown_semantic_parity(section, record)
        )
        if "**Evidence and report limitation**:" in section:
            visible.add(rid)
    repair_attempts: dict[str, int] = {}
    repair_receipt_path = root / "report_evidence_repair_receipt.json"
    if repair_receipt_path.exists():
        try:
            repair_receipt = _validate_repair_receipt(
                _read_json_object(
                    repair_receipt_path,
                    label="report evidence repair receipt",
                )
            )
            repair_attempts = {
                _clean_text(key).upper(): value
                for key, value in (repair_receipt.get("repair_attempts") or {}).items()
            }
        except (ReportEvidenceError, TypeError, ValueError):
            repair_attempts = {}
    receipt = derive_quality_receipt(
        bundle,
        delivered_report_ids=sections,
        limitation_visible_report_ids=visible,
        repair_attempts=repair_attempts,
        typed_manifest_markdown_parity=all(parity_by_id.values())
        and set(parity_by_id) == set(sections),
        markdown_semantic_parity=all(semantic_by_id.values()),
    )
    receipt["report_sha256"] = hashlib.sha256(
        Path(report_path).read_bytes()
    ).hexdigest()
    receipt["record_markdown_parity"] = dict(sorted(parity_by_id.items()))
    receipt["record_semantic_parity"] = dict(sorted(semantic_by_id.items()))
    receipt["unauthorized_proof_grade_report_ids"] = sorted(unauthorized_proof)
    unsigned = dict(receipt)
    unsigned["receipt_digest"] = ""
    receipt["receipt_digest"] = _digest(unsigned)
    receipt_path = root / "report_evidence_quality_receipt.json"
    if compare_only:
        expected = _canonical_bytes(receipt) + b"\n"
        try:
            actual = receipt_path.read_bytes()
        except OSError as exc:
            raise ReportEvidenceError(
                "final report evidence quality receipt is missing or unreadable"
            ) from exc
        if actual != expected:
            raise ReportEvidenceError(
                "final report evidence quality receipt has stale or tampered bytes"
            )
    else:
        _write_json_exact_or_missing(
            receipt_path,
            receipt,
            label="final report evidence quality receipt",
        )
    return receipt


__all__ = [
    "REPORT_EVIDENCE_BUNDLE_SCHEMA",
    "REPORT_EVIDENCE_MANIFEST_SCHEMA",
    "REPORT_EVIDENCE_RECORD_SCHEMA",
    "REPORT_EVIDENCE_REPAIR_APPLY_PLAN_SCHEMA",
    "REPORT_EVIDENCE_REPAIR_RECEIPT_SCHEMA",
    "REPORT_EVIDENCE_REPAIR_REQUEST_SCHEMA",
    "REPORT_EVIDENCE_REPAIR_RESPONSE_SCHEMA",
    "REPORT_QUALITY_RECEIPT_SCHEMA",
    "ReportEvidenceError",
    "apply_report_evidence_repair_response",
    "apply_semantic_repair_delta",
    "build_report_evidence_bundle",
    "derive_presentation_assurance",
    "derive_quality_receipt",
    "evidence_fields_from_execution_assessment",
    "finalize_report_evidence_delivery",
    "load_typed_report_evidence_shard",
    "materialize_report_evidence_runtime",
    "normalize_report_evidence_record",
    "plan_report_evidence_repair_output_bytes",
    "prepare_report_evidence_repair_apply_plan",
    "project_report_evidence_markdown",
    "required_semantic_fields",
    "render_typed_report_evidence_shard",
    "unauthorized_proof_grade_report_ids",
    "validate_report_evidence_bundle",
    "validate_report_evidence_record",
    "validate_report_evidence_repair_request",
    "validate_report_evidence_repair_response",
    "validate_report_evidence_runtime",
    "write_report_evidence_bundle",
]
