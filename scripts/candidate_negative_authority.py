"""Candidate-level authority boundary for producer-authored negative decisions.

Discovery workers are generators.  A structured SAFE/REFUTED/DISMISSED/etc.
decision in their Markdown is therefore harvested as an append-only proposal,
never accepted as terminal authority.  The proposal is projected into the
existing typed application-skeptic queue so an independent consumer must
either support the negative with evidence or re-emit a candidate into the
normal finding lifecycle.

The parser is deliberately structural.  It recognizes verdict fields,
verdict/status table columns, and strict obligation receipts; ordinary prose
that merely discusses negative vocabulary is not authority and is ignored.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
from typing import Any, Mapping, Sequence
import uuid

from negative_closure_policy import terminal_negative_authorized
import axis_canonical_prior as axis_prior_authority


LEDGER_SCHEMA = "plamen.candidate_negative_proposal_ledger.v1"
CANDIDATE_NEGATIVE_SKILL = "CANDIDATE_NEGATIVE_AUTHORITY"
LEDGER_PREFIX = "candidate_negative_proposals_"
CANDIDATE_PLAN_FILE = "candidate_negative_skeptic_work_plan.json"
CANDIDATE_DENOMINATOR_FILE = "candidate_negative_denominator.json"
APPLICATION_PLAN_SCHEMA = "plamen.application_skeptic_work_plan.v1"
AXIS_CLEAR_ADAPTER_SCHEMA = "plamen.axis_clear_candidate_negative_adapter.v1"
AXIS_CLEAR_PHASE = "axis_coverage"
AXIS_WORKLIST_ARTIFACT = "axis_disposition_worklist.json"
AXIS_APPLICATION_RECEIPT_ARTIFACT = "axis_disposition_receipt.json"
AXIS_EXECUTION_EVIDENCE_ARTIFACT = "axis_execution_evidence_authority.json"

_HEX_RE = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
_HEADING_RE = re.compile(r"(?m)^(#{2,6})\s+(.+?)\s*$")
_FIELD_RE = re.compile(
    r"(?im)^\s*(?:[-*]\s*)?\*{0,2}"
    r"(?P<field>Verdict|Status|Severity|Disposition|Result\s+Status|Assessment|"
    r"Conclusion|Exclusion|Outcome)\*{0,2}\s*:\s*(?P<value>[^\r\n]+)\r?$"
)
_RATIONALE_RE = re.compile(
    r"(?im)^\s*(?:[-*]\s*)?\*{0,2}"
    r"(?:Refutation\s+Basis|Reason|Rationale|Why\s+This\s+Blocks|Notes|Evidence)"
    r"\*{0,2}\s*:\s*(?P<value>[^\r\n]+)\r?$"
)
_VARIANTS_RE = re.compile(
    r"(?im)^\s*(?:[-*]\s*)?\*{0,2}(?:Variants?\s+(?:Examined|Checked)|"
    r"Paths?\s+(?:Examined|Checked))\*{0,2}\s*:\s*(?P<value>[^\r\n]+)\r?$"
)
_STRICT_OBLIG_RE = re.compile(
    r"(?im)^\s*\[OBLIG:(?P<obligation>[^\]\r\n]+)\]\s*"
    r"STATUS\s*:\s*(?P<status>D|DISMISSED)\b\s*"
    r"(?:KEY\s*:\s*)?(?P<premise>[^\r\n]*)\r?$"
)
_LOCATION_RE = re.compile(
    r"(?i)(?P<path>[A-Za-z0-9_@.+()\-\\/ ]+\."
    r"(?:sol|rs|move|go|ts|js|py|c|cc|cpp|h|hpp|wasm))"
    r"\s*:\s*L?(?P<line>\d+)(?:\s*[-:]\s*L?\d+)?"
)
_EXTERNAL_RE = re.compile(
    r"(?i)\b(?:external|upstream|downstream|third[- ]party|out[- ]of[- ]scope|"
    r"deployment|off[- ]chain|oracle|bridge|remote|assum(?:e|ed|ption))\b"
)
_EXPLICIT_ID_RE = re.compile(
    r"(?i)(?:Finding|Candidate|Issue)?\s*\[([A-Za-z][A-Za-z0-9_.:-]{0,95})\]"
)
_BRACKET_ID_RE = re.compile(r"\[([A-Za-z][A-Za-z0-9_.:-]{0,95})\]")
_OBLIGATION_IN_TEXT_RE = re.compile(r"\[OBLIG:([^\]\r\n]+)\]", re.IGNORECASE)
_AXW_RE = re.compile(r"^AXW-[0-9A-F]{24}$", re.ASCII)

_COMMITTED_INVARIANT_ID_PATTERN = r"(?:[A-Z][A-Z0-9]*-)*CI(?:-[A-Z0-9]+)+"
_CI_HEADER_RE = re.compile(
    r"(?im)^\s*committed-invariant\s*\[\s*(?P<id>[^\]\r\n]+)\s*\]\s*$"
)
_CI_FIELD_RE = re.compile(
    r"(?im)^\s*(?P<field>Locus|Shape|Assertion|Falsify Class|Provenance)\s*:\s*(?P<value>[^\r\n]+)\s*$"
)
_CI_DECLARATION_RE = re.compile(
    r"(?im)^\s*(?:[-*]\s*)?(?:\*{0,2})?Invariant Commitment(?:\*{0,2})?\s*:\s*(?P<value>[^\r\n]+)\s*$"
)
_CI_ID_RE = re.compile(rf"^{_COMMITTED_INVARIANT_ID_PATTERN}$", re.ASCII)
_CI_DECLARED_ID_RE = re.compile(
    rf"^CI\s*:\s*(?P<id>{_COMMITTED_INVARIANT_ID_PATTERN})$",
    re.IGNORECASE | re.ASCII,
)
_CI_NOT_REQUIRED_RE = re.compile(
    r"^NOT_REQUIRED_NON_VALUE_BEARING\s*:\s*(?P<reason>.+)$",
    re.IGNORECASE,
)
_NON_VALUE_CATEGORY_RE = re.compile(
    r"(?im)^\s*(?:[-*]\s*)?(?:\*{0,2})?Non-Value-Bearing Category"
    r"(?:\*{0,2})?\s*:\s*(?P<category>[A-Z][A-Z0-9_]*)\s*$"
)
_NON_VALUE_CATEGORIES = frozenset({
    "DOCUMENTATION_ONLY",
    "OBSERVABILITY_ONLY",
    "TEST_ONLY",
    "NON_PRODUCTION_ONLY",
})
_VALUE_BEARING_RE = re.compile(
    r"(?i)\b(?:funds?|assets?|tokens?|balances?|shares?|fees?|debt|accounting|"
    r"authori[sz](?:e|ed|ation)|access|privilege|ownership|transfer|withdraw|"
    r"deposit|mint|burn|settle|liquidat|solvency|liveness|availability|"
    r"denial.of.service|dos|revert|brick|loss|steal|stolen)\b"
)
_CI_LOCUS_RE = re.compile(
    r"^(?P<path>[^\r\n:]+(?:[\\/][^\r\n:]+)*\.(?:sol|rs|move|go|ts|js|py|c|cc|cpp|h|hpp|wasm))"
    r"\s*:\s*L?(?P<line>[1-9][0-9]*)(?:\b|\s)",
    re.IGNORECASE,
)
_CI_SHAPES = frozenset({
    "CONSERVATION",
    "REQUESTED_EQ_DELIVERED",
    "APPROVE_EQ_SPEND",
    "NO_REVERT_AT_BOUNDARY",
    "ROUNDTRIP",
    "FRESHNESS",
})
_CI_FALSIFY_CLASSES = frozenset(
    {"property", "boundary", "roundtrip", "conservation"}
)

_LEGACY_ALIASES = {
    "REFUTATION PROPOSAL": "REFUTATION_PROPOSAL",
    "NOT APPLICABLE PROPOSAL": "NOT_APPLICABLE_PROPOSAL",
    "UNRESOLVED": "UNRESOLVED",
    "REFUTED": "REFUTED",
    "DISMISSED": "DISMISSED",
    "SAFE": "SAFE",
    "CLEAR": "CLEAR",
    "NO FINDING": "NO_FINDING",
    "NO FINDINGS": "NO_FINDING",
    "NO ISSUE": "NO_FINDING",
    "NO ISSUES": "NO_FINDING",
    "FALSE POSITIVE": "FALSE_POSITIVE",
    "NOT EXPLOITABLE": "NOT_EXPLOITABLE",
    "INFEASIBLE": "INFEASIBLE",
    "UNREACHABLE": "UNREACHABLE",
    "BY DESIGN": "BY_DESIGN",
    "DUPLICATE": "DUPLICATE",
    "ABSORBED": "ABSORBED",
    "NOT APPLICABLE": "NOT_APPLICABLE",
    "N/A": "NOT_APPLICABLE",
    "NA": "NOT_APPLICABLE",
}
_TERMINAL_PROMPT_RE = re.compile(
    r"(?i)\b(?:SAFE|CLEAR|REFUTED|DISMISSED|NO[_ -]?FINDINGS?|"
    r"FALSE[_ -]?POSITIVE|NOT[_ -]?EXPLOITABLE|INFEASIBLE|UNREACHABLE|"
    r"BY[_ -]?DESIGN|DUPLICATE|ABSORBED|NOT[_ -]?APPLICABLE|N/A)\b"
)
_GENERATOR_CONTRACT_LINE_RE = re.compile(
    r"(?i)^\s*(?:#{1,6}\s*)?(?:\*{0,2})?"
    r"(?:Allowed\s+Verdicts?|Verdicts?|Allowed\s+Outcomes?|Outcomes?|"
    r"Disposition(?:s)?|Status(?:es)?)\*{0,2}\s*:\s*(.+)$"
)


class CandidateNegativeAuthorityError(ValueError):
    """The candidate-negative authority contract is malformed or unsafe."""


@dataclass(frozen=True)
class ArtifactInput:
    relative_path: str
    content: bytes
    producer_identity: str
    producer_invocation_id: str


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


def _bytes_sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _strict_json_loads(raw: bytes) -> Any:
    """Decode an authority artifact without JSON ambiguity or nonfinite values."""

    def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for key, value in pairs:
            if key in out:
                raise CandidateNegativeAuthorityError(
                    f"duplicate JSON object key: {key!r}"
                )
            out[key] = value
        return out

    def _constant(value: str) -> Any:
        raise CandidateNegativeAuthorityError(
            f"nonfinite JSON numeric constant: {value}"
        )

    return json.loads(
        raw.decode("utf-8"),
        object_pairs_hook=_pairs,
        parse_constant=_constant,
    )


def _text(value: Any) -> str:
    return str(value or "").strip()


def _candidate_seed_field(value: Any, *, limit: int, title: bool = False) -> str:
    text = re.sub(r"\s+", " ", _text(value)).strip()
    text = text.replace("<!--", "").replace("PLAMEN_STATUS:", "")
    if title:
        text = text.replace("[", "(").replace("]", ")")
    if not text:
        text = "Reopened producer-negative candidate" if title else (
            "The producer-authored negative lacks replayable closure authority."
        )
    while len(text.encode("utf-8")) > limit:
        text = text[:-1]
    return text.strip()


def _clean_inline(value: str) -> str:
    # Preserve underscores because they are semantic enum separators
    # (NO_FINDING / NOT_APPLICABLE), not only Markdown emphasis.
    value = re.sub(r"[`*]", "", str(value or ""))
    return re.sub(r"\s+", " ", value).strip(" |:-\t")


def _source_artifact_row(
    *,
    relative_path: str,
    sha256: str,
    size_bytes: int,
    producer_identity: str,
    producer_invocation_id: str,
) -> dict[str, Any]:
    unsigned = {
        "relative_path": Path(relative_path).as_posix(),
        "sha256": sha256,
        "size_bytes": size_bytes,
        "producer_identity": _text(producer_identity),
        "producer_invocation_id": _text(producer_invocation_id),
    }
    return {**unsigned, "binding_digest": _digest(unsigned)}


def _ci_blocks(text: str) -> tuple[list[dict[str, str]], set[str]]:
    """Parse CI blocks without granting malformed headers presence credit."""

    matches = list(_CI_HEADER_RE.finditer(text or ""))
    blocks: list[dict[str, str]] = []
    counts: dict[str, int] = {}
    for index, match in enumerate(matches):
        raw_id = _clean_inline(match.group("id")).upper()
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        # A following Markdown heading belongs to another negative identity.
        heading = re.search(r"(?m)^#{1,6}\s+", text[match.end():end])
        if heading:
            end = match.end() + heading.start()
        raw_block = text[match.start():end].strip()
        fields: dict[str, str] = {}
        for field_match in _CI_FIELD_RE.finditer(raw_block):
            key = re.sub(r"\s+", "_", field_match.group("field").strip().lower())
            if key in fields:
                fields[key] = ""
            else:
                fields[key] = field_match.group("value").strip()
        counts[raw_id] = counts.get(raw_id, 0) + 1
        blocks.append(
            {
                "ci_id": raw_id,
                "raw_block": raw_block,
                "ci_block_sha256": _bytes_sha(raw_block.encode("utf-8")),
                "locus": fields.get("locus", ""),
                "shape": fields.get("shape", "").upper(),
                "assertion": fields.get("assertion", ""),
                "falsify_class": fields.get("falsify_class", "").lower(),
                "provenance": fields.get("provenance", ""),
            }
        )
    return blocks, {ci_id for ci_id, count in counts.items() if count != 1}


def _production_ci_locus(value: str) -> bool:
    match = _CI_LOCUS_RE.match(_clean_inline(value))
    if not match:
        return False
    raw_path = match.group("path").replace("\\", "/")
    path = Path(raw_path)
    return not path.is_absolute() and ".." not in path.parts and ":" not in raw_path


def _depth_invariant_commitment(
    excerpt: str,
    *,
    source_item_id: str,
    source_artifact_sha256: str,
    source_excerpt_sha256: str,
    duplicate_ci_ids: set[str],
) -> dict[str, Any]:
    """Bind one depth negative to one strict CI or an explicit narrow exemption."""

    declarations = [
        match.group("value").strip()
        for match in _CI_DECLARATION_RE.finditer(excerpt or "")
    ]
    base: dict[str, Any] = {
        "status": "DEBT",
        "declaration": declarations[0] if len(declarations) == 1 else "",
        "reason": "",
        "ci_id": "",
        "ci_block_sha256": "",
        "locus": "",
        "shape": "",
        "assertion": "",
        "falsify_class": "",
        "provenance": "",
        "non_value_bearing_category": "",
        "source_item_id": source_item_id,
        "source_artifact_sha256": source_artifact_sha256,
        "source_excerpt_sha256": source_excerpt_sha256,
    }
    if len(declarations) != 1:
        base["reason"] = (
            "missing invariant commitment declaration"
            if not declarations
            else "duplicate invariant commitment declarations"
        )
    else:
        not_required = _CI_NOT_REQUIRED_RE.fullmatch(declarations[0])
        if not_required:
            reason = _clean_inline(not_required.group("reason"))
            categories = [
                match.group("category").upper()
                for match in _NON_VALUE_CATEGORY_RE.finditer(excerpt or "")
            ]
            category = categories[0] if len(categories) == 1 else ""
            if (
                reason
                and category in _NON_VALUE_CATEGORIES
                and not _VALUE_BEARING_RE.search(excerpt or "")
            ):
                base.update(
                    status="NOT_REQUIRED_NON_VALUE_BEARING",
                    reason=reason,
                    non_value_bearing_category=category,
                )
            else:
                defects: list[str] = []
                if not reason:
                    defects.append("reason")
                if len(categories) != 1 or category not in _NON_VALUE_CATEGORIES:
                    defects.append("allowlisted category")
                if _VALUE_BEARING_RE.search(excerpt or ""):
                    defects.append("value-bearing source content")
                base["reason"] = (
                    "non-value-bearing exemption lacks mechanical "
                    + ", ".join(defects or ["authority"])
                )
        else:
            declared = _CI_DECLARED_ID_RE.fullmatch(declarations[0])
            if not declared:
                base["reason"] = "invariant commitment declaration is malformed"
            else:
                ci_id = declared.group("id").upper()
                blocks, local_duplicates = _ci_blocks(excerpt)
                matches = [row for row in blocks if row["ci_id"] == ci_id]
                if ci_id in duplicate_ci_ids or ci_id in local_duplicates or len(matches) != 1:
                    base["reason"] = "committed-invariant identity is missing or duplicated"
                else:
                    block = matches[0]
                    provenance_tokens = {
                        token.upper()
                        for token in re.findall(r"[A-Za-z][A-Za-z0-9_.:-]{1,95}", block["provenance"])
                    }
                    malformed: list[str] = []
                    if not _CI_ID_RE.fullmatch(ci_id):
                        malformed.append("id")
                    if not _production_ci_locus(block["locus"]):
                        malformed.append("production locus")
                    if block["shape"] not in _CI_SHAPES:
                        malformed.append("shape")
                    if not _clean_inline(block["assertion"]):
                        malformed.append("assertion")
                    if block["falsify_class"] not in _CI_FALSIFY_CLASSES:
                        malformed.append("falsify class")
                    if source_item_id.upper() not in provenance_tokens:
                        malformed.append("provenance binding")
                    if malformed:
                        base["reason"] = "invalid committed-invariant " + ", ".join(malformed)
                    else:
                        base.update(
                            status="COMPLETE",
                            reason="",
                            **{
                                key: block[key]
                                for key in (
                                    "ci_id",
                                    "ci_block_sha256",
                                    "locus",
                                    "shape",
                                    "assertion",
                                    "falsify_class",
                                    "provenance",
                                )
                            },
                        )
    unsigned = dict(base)
    base["binding_digest"] = _digest(unsigned)
    return base


def _normalize_legacy(value: str) -> str | None:
    candidate = _clean_inline(value).upper().replace("-", " ").replace("_", " ")
    candidate = re.sub(r"\s+", " ", candidate).strip()
    # A field may add a parenthetical rationale after the enum.  Long prose
    # containing a token is not accepted; the terminal must lead the field.
    for alias in sorted(_LEGACY_ALIASES, key=len, reverse=True):
        if candidate == alias or candidate.startswith(alias + " "):
            return _LEGACY_ALIASES[alias]
    return None


def _proposal_disposition(legacy: str) -> str:
    if legacy in {"NOT_APPLICABLE", "NOT_APPLICABLE_PROPOSAL"}:
        return "NOT_APPLICABLE_PROPOSAL"
    if legacy == "UNRESOLVED":
        return "UNRESOLVED"
    return "REFUTATION_PROPOSAL"


def _blocks(text: str) -> list[tuple[str, str, int]]:
    matches = list(_HEADING_RE.finditer(text))
    result: list[tuple[str, str, int]] = []
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        result.append((match.group(2).strip(), text[match.start():end].strip(), match.start()))
    return result


def _source_item_id(label: str, *, fallback: Mapping[str, Any]) -> str:
    for pattern in (_EXPLICIT_ID_RE, _BRACKET_ID_RE):
        match = pattern.search(label)
        if match:
            return match.group(1).upper()
    normalized = re.sub(r"\s+", " ", _clean_inline(label).casefold())
    if normalized:
        return "ENTITY-" + hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:20].upper()
    return "ENTITY-" + _digest(dict(fallback))[:20].upper()


def _source_item_identity(
    label: str, *, fallback: Mapping[str, Any]
) -> tuple[str, str]:
    """Return a local identity and whether it was explicitly producer-bound.

    Heading hashes are useful for transporting an otherwise-lost negative, but
    they are not stable enough to authorize a terminal exclusion.  Keeping the
    distinction in the event lets the independent discriminator reopen the
    candidate while deterministically vetoing an unsafe agreement.
    """

    for pattern in (_EXPLICIT_ID_RE, _BRACKET_ID_RE):
        match = pattern.search(label)
        if match:
            return match.group(1).upper(), "EXACT"
    return _source_item_id(label, fallback=fallback), "DERIVED"


def _semantic_claim_sha256(
    label: str, *, exact_premise: str, guard_locus: str
) -> str:
    claim = _clean_inline(label)
    claim = _EXPLICIT_ID_RE.sub(" ", claim)
    claim = _BRACKET_ID_RE.sub(" ", claim)
    claim = re.sub(
        r"(?i)^\s*(?:finding|candidate|issue)\b\s*[:\-]*\s*", "", claim
    )
    claim = re.sub(r"\s+", " ", claim).strip(" :-\t").casefold()
    return _digest(
        {
            "claim": claim,
            "premise_or_mechanism": re.sub(
                r"\s+", " ", _clean_inline(exact_premise)
            ).casefold(),
            "guard_locus": re.sub(
                r"\s+", " ", _clean_inline(guard_locus)
            ).casefold(),
        }
    )


def _locations(text: str) -> list[str]:
    out = set()
    for match in _LOCATION_RE.finditer(text):
        path = re.sub(r"\s+", " ", match.group("path").strip()).replace("\\", "/")
        out.add(f"{path}:L{match.group('line')}")
    return sorted(out, key=str.casefold)


def _variants(text: str) -> list[str]:
    match = _VARIANTS_RE.search(text)
    if not match:
        return []
    values = re.split(r"[,;|]", _clean_inline(match.group("value")))
    return sorted({value.strip() for value in values if value.strip()}, key=str.casefold)


def _premise(text: str, fallback: str) -> str:
    values = [_clean_inline(match.group("value")) for match in _RATIONALE_RE.finditer(text)]
    values = [value for value in values if value]
    if values:
        return " | ".join(values)
    compact = re.sub(r"\s+", " ", _clean_inline(fallback))
    return compact[:4096] or "producer-authored terminal negative without an exact premise"


def _methodology_obligation(text: str, source_item_id: str) -> str:
    match = _OBLIGATION_IN_TEXT_RE.search(text)
    if match:
        return "OBLIG:" + _clean_inline(match.group(1))
    return "CANDIDATE:" + source_item_id


def _event(
    *,
    phase: str,
    artifact: ArtifactInput,
    artifact_sha: str,
    label: str,
    excerpt: str,
    legacy: str,
    methodology_path: Path,
    methodology_sha: str,
    harvest_kind: str,
    duplicate_ci_ids: set[str] | None = None,
) -> dict[str, Any]:
    locations = _locations(excerpt)
    item_id, identity_state = _source_item_identity(
        label,
        fallback={
            "phase": phase,
            "artifact": artifact.relative_path,
            "label": label,
            "legacy": legacy,
        },
    )
    obligation = _methodology_obligation(excerpt, item_id)
    family_identity = {
        "producer_phase": phase,
        "source_artifact": Path(artifact.relative_path).as_posix().casefold(),
        "source_item_id": item_id,
        "methodology_obligation_id": obligation,
    }
    family_id = "CNF-" + _digest(family_identity)[:24].upper()
    proposal_id = "CNP-" + _digest(
        {
            "family_id": family_id,
            "proposed_disposition": _proposal_disposition(legacy),
        }
    )[:24].upper()
    excerpt_clean = excerpt.strip()
    excerpt_sha = hashlib.sha256(excerpt_clean.encode("utf-8")).hexdigest()
    exact_premise = _premise(excerpt, label)
    guard_locus = locations[0] if locations else ""
    semantic_claim_sha = _semantic_claim_sha256(
        label,
        exact_premise=exact_premise,
        guard_locus=guard_locus,
    )
    event_id = "CNE-" + _digest(
        {
            "proposal_id": proposal_id,
            "source_artifact_sha256": artifact_sha,
            "source_excerpt_sha256": excerpt_sha,
        }
    )[:24].upper()
    invariant_commitment = (
        _depth_invariant_commitment(
            excerpt_clean,
            source_item_id=item_id,
            source_artifact_sha256=artifact_sha,
            source_excerpt_sha256=excerpt_sha,
            duplicate_ci_ids=set(duplicate_ci_ids or ()),
        )
        if phase == "depth" and _proposal_disposition(legacy) == "REFUTATION_PROPOSAL"
        else {
            "status": "NOT_APPLICABLE",
            "reason": "producer phase/disposition is outside the depth CI denominator",
            "source_item_id": item_id,
            "source_artifact_sha256": artifact_sha,
            "source_excerpt_sha256": excerpt_sha,
        }
    )
    if "binding_digest" not in invariant_commitment:
        invariant_commitment["binding_digest"] = _digest(invariant_commitment)
    unsigned = {
        "event_id": event_id,
        "family_id": family_id,
        "proposal_id": proposal_id,
        "producer_phase": phase,
        "producer_identity": _text(artifact.producer_identity),
        "producer_invocation_id": _text(artifact.producer_invocation_id),
        "source_artifact": Path(artifact.relative_path).as_posix(),
        "source_artifact_sha256": artifact_sha,
        "source_item_id": item_id,
        "identity_state": identity_state,
        "semantic_claim_sha256": semantic_claim_sha,
        "methodology_obligation_id": obligation,
        "methodology_path": methodology_path.as_posix(),
        "methodology_sha256": methodology_sha,
        "legacy_disposition": legacy,
        "proposed_disposition": _proposal_disposition(legacy),
        "exact_premise": exact_premise,
        "guard_locus": guard_locus,
        "variants_examined": _variants(excerpt),
        "evidence_refs": locations,
        "external_assumption": bool(_EXTERNAL_RE.search(excerpt)),
        "proof_scope": "NONE",
        "requires_independent_consumer": True,
        "harvest_kind": harvest_kind,
        "source_excerpt": excerpt_clean,
        "source_excerpt_sha256": excerpt_sha,
        "invariant_commitment": invariant_commitment,
    }
    return {**unsigned, "event_digest": _digest(unsigned)}


def _downgrade_globally_reused_commitments(
    events: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    """Make CI identity/block reuse debt across the entire ledger snapshot."""

    id_counts: dict[str, int] = {}
    block_counts: dict[str, int] = {}
    for event in events:
        commitment = event.get("invariant_commitment")
        if not isinstance(commitment, Mapping) or commitment.get("status") != "COMPLETE":
            continue
        ci_id = _text(commitment.get("ci_id")).upper()
        block_sha = _text(commitment.get("ci_block_sha256"))
        id_counts[ci_id] = id_counts.get(ci_id, 0) + 1
        block_counts[block_sha] = block_counts.get(block_sha, 0) + 1
    duplicate_ids = {key for key, count in id_counts.items() if count > 1}
    duplicate_blocks = {key for key, count in block_counts.items() if count > 1}
    result: list[dict[str, Any]] = []
    for original in events:
        event = dict(original)
        commitment_raw = event.get("invariant_commitment")
        commitment = dict(commitment_raw) if isinstance(commitment_raw, Mapping) else {}
        if (
            commitment.get("status") == "COMPLETE"
            and (
                _text(commitment.get("ci_id")).upper() in duplicate_ids
                or _text(commitment.get("ci_block_sha256")) in duplicate_blocks
            )
        ):
            commitment["status"] = "DEBT"
            commitment["reason"] = (
                "committed-invariant identity/block is reused across ledger events"
            )
            commitment_unsigned = {
                key: value for key, value in commitment.items()
                if key != "binding_digest"
            }
            commitment["binding_digest"] = _digest(commitment_unsigned)
            event["invariant_commitment"] = commitment
            event_unsigned = {
                key: value for key, value in event.items() if key != "event_digest"
            }
            event["event_digest"] = _digest(event_unsigned)
        result.append(event)
    return result


def _table_events(
    text: str,
    *,
    phase: str,
    artifact: ArtifactInput,
    artifact_sha: str,
    methodology_path: Path,
    methodology_sha: str,
    duplicate_ci_ids: set[str],
) -> list[dict[str, Any]]:
    lines = text.splitlines()
    header: list[str] | None = None
    status_indexes: list[int] = []
    events: list[dict[str, Any]] = []
    for line in lines:
        if not line.strip().startswith("|"):
            header = None
            status_indexes = []
            continue
        cells = [_clean_inline(cell) for cell in line.strip().strip("|").split("|")]
        normalized = [cell.casefold() for cell in cells]
        candidates = [
            index
            for index, cell in enumerate(normalized)
            if cell in {
                "verdict", "status", "severity", "disposition", "outcome", "assessment"
            }
        ]
        if candidates:
            header = cells
            status_indexes = candidates
            continue
        if all(not cell or re.fullmatch(r":?-{3,}:?", cell) for cell in cells):
            continue
        if header is None or not status_indexes:
            continue
        label_parts = [
            cell for index, cell in enumerate(cells)
            if index not in status_indexes and cell and cell not in {"-", "N/A"}
        ]
        label = " | ".join(label_parts[:3]) or f"table-row-{len(events) + 1}"
        excerpt = "| " + " | ".join(cells) + " |"
        for status_index in status_indexes:
            if status_index >= len(cells):
                continue
            legacy = _normalize_legacy(cells[status_index])
            if legacy is None:
                continue
            events.append(
                _event(
                    phase=phase,
                    artifact=artifact,
                    artifact_sha=artifact_sha,
                    label=label,
                    excerpt=excerpt,
                    legacy=legacy,
                    methodology_path=methodology_path,
                    methodology_sha=methodology_sha,
                    harvest_kind="STRUCTURED_TABLE_ROW",
                    duplicate_ci_ids=duplicate_ci_ids,
                )
            )
    return events


def _artifact_events(
    artifact: ArtifactInput,
    *,
    phase: str,
    methodology_path: Path,
    methodology_sha: str,
) -> list[dict[str, Any]]:
    text = artifact.content.decode("utf-8", errors="replace")
    artifact_sha = _bytes_sha(artifact.content)
    _artifact_ci_blocks, duplicate_ci_ids = _ci_blocks(text)
    events: list[dict[str, Any]] = []
    for label, block, _offset in _blocks(text):
        for match in _FIELD_RE.finditer(block):
            legacy = _normalize_legacy(match.group("value"))
            if legacy is None:
                continue
            events.append(
                _event(
                    phase=phase,
                    artifact=artifact,
                    artifact_sha=artifact_sha,
                    label=label,
                    excerpt=block,
                    legacy=legacy,
                    methodology_path=methodology_path,
                    methodology_sha=methodology_sha,
                    harvest_kind="STRUCTURED_ENTITY_FIELD",
                    duplicate_ci_ids=duplicate_ci_ids,
                )
            )
            break
    events.extend(
        _table_events(
            text,
            phase=phase,
            artifact=artifact,
            artifact_sha=artifact_sha,
            methodology_path=methodology_path,
            methodology_sha=methodology_sha,
            duplicate_ci_ids=duplicate_ci_ids,
        )
    )
    for match in _STRICT_OBLIG_RE.finditer(text):
        obligation = _clean_inline(match.group("obligation"))
        excerpt = match.group(0).strip()
        event = _event(
            phase=phase,
            artifact=artifact,
            artifact_sha=artifact_sha,
            label=obligation,
            excerpt=excerpt,
            legacy="DISMISSED",
            methodology_path=methodology_path,
            methodology_sha=methodology_sha,
            harvest_kind="STRICT_OBLIGATION_RECEIPT",
            duplicate_ci_ids=duplicate_ci_ids,
        )
        events.append(event)
    by_id: dict[str, dict[str, Any]] = {}
    for event in events:
        prior = by_id.get(event["event_id"])
        if prior is not None and prior != event:
            raise CandidateNegativeAuthorityError(
                f"conflicting derived event {event['event_id']}"
            )
        by_id[event["event_id"]] = event
    return [by_id[key] for key in sorted(by_id)]


def _validate_event_inner(event: Any) -> None:
    if not isinstance(event, dict):
        raise CandidateNegativeAuthorityError("candidate-negative event is not an object")
    if event.get("proof_scope") != "NONE":
        raise CandidateNegativeAuthorityError("producer event claimed proof scope")
    if event.get("requires_independent_consumer") is not True:
        raise CandidateNegativeAuthorityError("producer event bypasses independent review")
    if event.get("proposed_disposition") not in {
        "REFUTATION_PROPOSAL",
        "NOT_APPLICABLE_PROPOSAL",
        "UNRESOLVED",
    }:
        raise CandidateNegativeAuthorityError("event has terminal/invalid disposition")
    for key in (
        "source_artifact_sha256",
        "methodology_sha256",
        "source_excerpt_sha256",
        "event_digest",
    ):
        if not isinstance(event.get(key), str) or not _HEX_RE.fullmatch(event[key]):
            raise CandidateNegativeAuthorityError(f"event has malformed {key}")
    source_excerpt = event.get("source_excerpt")
    if not isinstance(source_excerpt, str):
        raise CandidateNegativeAuthorityError("candidate-negative source excerpt is not text")
    if event["source_excerpt_sha256"] != _bytes_sha(source_excerpt.encode("utf-8")):
        raise CandidateNegativeAuthorityError(
            "candidate-negative source excerpt digest mismatch"
        )
    unsigned = {key: value for key, value in event.items() if key != "event_digest"}
    if event["event_digest"] != _digest(unsigned):
        raise CandidateNegativeAuthorityError("candidate-negative event digest mismatch")
    expected_proposal = "CNP-" + _digest(
        {
            "family_id": event["family_id"],
            "proposed_disposition": event["proposed_disposition"],
        }
    )[:24].upper()
    if event.get("proposal_id") != expected_proposal:
        raise CandidateNegativeAuthorityError("candidate-negative proposal identity mismatch")
    expected_family = "CNF-" + _digest(
        {
            "producer_phase": event["producer_phase"],
            "source_artifact": Path(event["source_artifact"]).as_posix().casefold(),
            "source_item_id": event["source_item_id"],
            "methodology_obligation_id": event["methodology_obligation_id"],
        }
    )[:24].upper()
    if event.get("family_id") != expected_family:
        raise CandidateNegativeAuthorityError("candidate-negative family identity mismatch")
    if event.get("identity_state") not in {"EXACT", "DERIVED"}:
        raise CandidateNegativeAuthorityError("candidate-negative identity state invalid")
    if not _HEX_RE.fullmatch(str(event.get("semantic_claim_sha256") or "")):
        raise CandidateNegativeAuthorityError("candidate-negative claim digest invalid")
    commitment = event.get("invariant_commitment")
    if not isinstance(commitment, dict):
        raise CandidateNegativeAuthorityError("candidate-negative invariant commitment missing")
    commitment_unsigned = {
        key: value for key, value in commitment.items() if key != "binding_digest"
    }
    if commitment.get("binding_digest") != _digest(commitment_unsigned):
        raise CandidateNegativeAuthorityError(
            "candidate-negative invariant commitment digest mismatch"
        )
    if (
        commitment.get("source_item_id") != event.get("source_item_id")
        or commitment.get("source_artifact_sha256")
        != event.get("source_artifact_sha256")
        or commitment.get("source_excerpt_sha256")
        != event.get("source_excerpt_sha256")
    ):
        raise CandidateNegativeAuthorityError(
            "candidate-negative invariant commitment source binding mismatch"
        )
    commitment_status = _text(commitment.get("status")).upper()
    if event.get("producer_phase") == AXIS_CLEAR_PHASE and event.get(
        "proposed_disposition"
    ) == "REFUTATION_PROPOSAL":
        expected_axis_fields = {
            "status",
            "reason",
            "ci_id",
            "ci_block_sha256",
            "locus",
            "shape",
            "assertion",
            "falsify_class",
            "provenance",
            "source_item_id",
            "source_artifact_sha256",
            "source_excerpt_sha256",
            "axis",
            "axis_work_item_sha256",
            "axis_source_relpath",
            "axis_source_locus",
            "axis_source_hash",
            "axis_evidence_sha256",
            "axis_commitment_binding_digest",
            "binding_digest",
        }
        if (
            commitment_status != "COMPLETE"
            or set(commitment) != expected_axis_fields
            or _text(commitment.get("reason"))
            or not _CI_ID_RE.fullmatch(
                _text(commitment.get("ci_id")).upper()
            )
            or not _HEX_RE.fullmatch(
                _text(commitment.get("ci_block_sha256"))
            )
            or not _production_ci_locus(_text(commitment.get("locus")))
            or _text(commitment.get("shape")).upper() not in _CI_SHAPES
            or not _text(commitment.get("assertion"))
            or _text(commitment.get("falsify_class")).lower()
            not in _CI_FALSIFY_CLASSES
            or _text(commitment.get("provenance"))
            != f"AXW:{event.get('source_item_id')}"
            or _text(commitment.get("axis")) not in {
                "theft", "liveness", "accounting", "provenance",
                "boundary", "identity",
            }
            or any(
                not _HEX_RE.fullmatch(_text(commitment.get(key)))
                for key in (
                    "axis_work_item_sha256",
                    "axis_source_hash",
                    "axis_evidence_sha256",
                    "axis_commitment_binding_digest",
                )
            )
        ):
            raise CandidateNegativeAuthorityError(
                "axis invariant commitment is not structurally valid"
            )
    elif event.get("producer_phase") == "depth" and event.get(
        "proposed_disposition"
    ) == "REFUTATION_PROPOSAL":
        if commitment_status not in {
            "COMPLETE", "NOT_REQUIRED_NON_VALUE_BEARING", "DEBT"
        }:
            raise CandidateNegativeAuthorityError(
                "depth invariant commitment status invalid"
            )
        if commitment_status == "COMPLETE":
            parsed_blocks, duplicate_ids = _ci_blocks(source_excerpt)
            commitment_ci_id = _text(commitment.get("ci_id")).upper()
            matching_blocks = [
                row for row in parsed_blocks if row["ci_id"] == commitment_ci_id
            ]
            if (
                not _CI_ID_RE.fullmatch(commitment_ci_id)
                or not _HEX_RE.fullmatch(_text(commitment.get("ci_block_sha256")))
                or not _production_ci_locus(_text(commitment.get("locus")))
                or _text(commitment.get("shape")).upper() not in _CI_SHAPES
                or not _text(commitment.get("assertion"))
                or _text(commitment.get("falsify_class")).lower()
                not in _CI_FALSIFY_CLASSES
                or event["source_item_id"].upper()
                not in {
                    token.upper()
                    for token in re.findall(
                        r"[A-Za-z][A-Za-z0-9_.:-]{1,95}",
                        _text(commitment.get("provenance")),
                    )
                }
                or commitment_ci_id in duplicate_ids
                or len(matching_blocks) != 1
                or any(
                    commitment.get(key) != matching_blocks[0].get(key)
                    for key in (
                        "ci_block_sha256",
                        "locus",
                        "shape",
                        "assertion",
                        "falsify_class",
                        "provenance",
                    )
                )
            ):
                raise CandidateNegativeAuthorityError(
                    "complete depth invariant commitment is not structurally valid"
                )
        elif commitment_status == "NOT_REQUIRED_NON_VALUE_BEARING":
            categories = [
                match.group("category").upper()
                for match in _NON_VALUE_CATEGORY_RE.finditer(source_excerpt)
            ]
            category = _text(
                commitment.get("non_value_bearing_category")
            ).upper()
            if (
                not _text(commitment.get("reason"))
                or len(categories) != 1
                or category not in _NON_VALUE_CATEGORIES
                or categories[0] != category
                or _VALUE_BEARING_RE.search(source_excerpt)
            ):
                raise CandidateNegativeAuthorityError(
                    "non-value-bearing invariant exemption lacks mechanical authority"
                )
        elif not _text(commitment.get("reason")):
            raise CandidateNegativeAuthorityError(
                "depth invariant commitment debt lacks a reason"
            )
    elif commitment_status != "NOT_APPLICABLE":
        raise CandidateNegativeAuthorityError(
            "out-of-denominator invariant commitment status invalid"
        )
    expected_event = "CNE-" + _digest(
        {
            "proposal_id": expected_proposal,
            "source_artifact_sha256": event["source_artifact_sha256"],
            "source_excerpt_sha256": event["source_excerpt_sha256"],
        }
    )[:24].upper()
    if event.get("event_id") != expected_event:
        raise CandidateNegativeAuthorityError("candidate-negative event identity mismatch")


def _validate_event(event: Any) -> None:
    """Normalize malformed/missing-field failures to the typed authority error."""

    try:
        _validate_event_inner(event)
    except CandidateNegativeAuthorityError:
        raise
    except (KeyError, TypeError, AttributeError, ValueError) as exc:
        raise CandidateNegativeAuthorityError(
            f"candidate-negative event shape invalid: {type(exc).__name__}: {exc}"
        ) from exc


def _validate_axis_clear_ledger_shape(ledger: Mapping[str, Any]) -> None:
    """Validate the self-contained typed-axis projection.

    Full authority replay additionally requires the current worklist and final
    application-receipt bytes and is performed by
    :func:`validate_axis_clear_candidate_negative_ledger`.  This structural
    check prevents the generic Markdown harvester from impersonating that
    adapter when the ledger is later consumed by the shared skeptic.
    """

    expected_ledger_fields = {
        "schema_version",
        "phase",
        "methodology_path",
        "methodology_sha256",
        "source_artifacts",
        "status",
        "issues",
        "families",
        "event_count",
        "events",
        "axis_authority_binding",
        "ledger_digest",
    }
    if set(ledger) != expected_ledger_fields:
        raise CandidateNegativeAuthorityError(
            "axis candidate-negative ledger must come from the typed v2 adapter"
        )
    binding = ledger.get("axis_authority_binding")
    expected_binding_fields = {
        "schema_version",
        "run_id",
        "worklist_artifact",
        "worklist_artifact_sha256",
        "worklist_hash",
        "application_receipt_artifact",
        "application_receipt_artifact_sha256",
        "application_receipt_digest",
        "execution_evidence_artifact",
        "execution_evidence_artifact_sha256",
        "execution_evidence_authority_digest",
        "canonical_prior_snapshot_artifact",
        "canonical_prior_snapshot_sha256",
        "canonical_prior_snapshot_digest",
        "canonical_prior_authority_artifact",
        "canonical_prior_authority_sha256",
        "canonical_prior_authority_digest",
        "denominator_status",
        "application_status",
        "binding_digest",
    }
    if not isinstance(binding, Mapping) or set(binding) != expected_binding_fields:
        raise CandidateNegativeAuthorityError(
            "axis candidate-negative authority binding is malformed"
        )
    unsigned_binding = {
        key: value for key, value in binding.items()
        if key != "binding_digest"
    }
    run_id = _text(binding.get("run_id"))
    if (
        binding.get("schema_version") != AXIS_CLEAR_ADAPTER_SCHEMA
        or not run_id
        or binding.get("worklist_artifact") != AXIS_WORKLIST_ARTIFACT
        or binding.get("application_receipt_artifact")
        != AXIS_APPLICATION_RECEIPT_ARTIFACT
        or binding.get("execution_evidence_artifact")
        != AXIS_EXECUTION_EVIDENCE_ARTIFACT
        or binding.get("canonical_prior_snapshot_artifact")
        != axis_prior_authority.SNAPSHOT_NAME
        or binding.get("canonical_prior_authority_artifact")
        != axis_prior_authority.AUTHORITY_NAME
        or binding.get("denominator_status")
        not in {"EXACT", "DEGRADED", "UNKNOWN"}
        or binding.get("application_status")
        not in {"COMPLETE", "COMPLETED_WITH_DEBT"}
        or binding.get("binding_digest") != _digest(unsigned_binding)
    ):
        raise CandidateNegativeAuthorityError(
            "axis candidate-negative authority binding is invalid"
        )
    for key in (
        "worklist_artifact_sha256",
        "worklist_hash",
        "application_receipt_artifact_sha256",
        "application_receipt_digest",
        "execution_evidence_artifact_sha256",
        "execution_evidence_authority_digest",
        "canonical_prior_snapshot_sha256",
        "canonical_prior_snapshot_digest",
        "canonical_prior_authority_sha256",
        "canonical_prior_authority_digest",
    ):
        if not _HEX_RE.fullmatch(_text(binding.get(key))):
            raise CandidateNegativeAuthorityError(
                f"axis candidate-negative {key} is malformed"
            )
    sources = ledger.get("source_artifacts")
    expected_sources = [
        {
            "relative_path": AXIS_APPLICATION_RECEIPT_ARTIFACT,
            "sha256": binding["application_receipt_artifact_sha256"],
            "size_bytes": sources[0].get("size_bytes")
            if isinstance(sources, list)
            and len(sources) == 2
            and isinstance(sources[0], Mapping)
            else None,
            "producer_identity": "AXIS_DISPOSITION_APPLICATION_V2",
            "producer_invocation_id": run_id,
        },
        {
            "relative_path": AXIS_WORKLIST_ARTIFACT,
            "sha256": binding["worklist_artifact_sha256"],
            "size_bytes": sources[1].get("size_bytes")
            if isinstance(sources, list)
            and len(sources) == 2
            and isinstance(sources[1], Mapping)
            else None,
            "producer_identity": "AXIS_DISPOSITION_PLANNING_V2",
            "producer_invocation_id": run_id,
        },
    ]
    if (
        not isinstance(sources, list)
        or len(sources) != 2
        or any(
            not isinstance(row, Mapping)
            or type(row.get("size_bytes")) is not int
            or row.get("size_bytes") < 1
            for row in sources
        )
        or sources != expected_sources
    ):
        raise CandidateNegativeAuthorityError(
            "axis candidate-negative source lineage is malformed"
        )
    if (
        ledger.get("methodology_path") != AXIS_WORKLIST_ARTIFACT
        or ledger.get("methodology_sha256")
        != binding["worklist_artifact_sha256"]
    ):
        raise CandidateNegativeAuthorityError(
            "axis candidate-negative methodology binding mismatch"
        )
    for event in ledger.get("events", []):
        lineage = event.get("axis_lineage")
        if (
            not isinstance(lineage, Mapping)
            or set(lineage)
            != {
                "run_id",
                "worklist_hash",
                "application_receipt_digest",
                "work_item",
                "final_disposition",
            }
        ):
            raise CandidateNegativeAuthorityError(
                "axis candidate-negative event lineage is malformed"
            )
        work_item = lineage.get("work_item")
        disposition = lineage.get("final_disposition")
        work_id = _text(event.get("source_item_id"))
        if (
            lineage.get("run_id") != run_id
            or lineage.get("worklist_hash") != binding["worklist_hash"]
            or lineage.get("application_receipt_digest")
            != binding["application_receipt_digest"]
            or not isinstance(work_item, Mapping)
            or not isinstance(disposition, Mapping)
            or not _AXW_RE.fullmatch(work_id)
            or work_item.get("work_item_id") != work_id
            or disposition.get("work_item_id") != work_id
            or disposition.get("source_item") != work_item
            or disposition.get("disposition") != "CLEAR"
            or disposition.get("application_record_complete") is not True
            or event.get("identity_state") != "EXACT"
            or event.get("legacy_disposition") != "CLEAR"
            or event.get("proposed_disposition")
            != "REFUTATION_PROPOSAL"
            or event.get("producer_identity")
            != "AXIS_DISPOSITION_APPLICATION_V2"
            or event.get("producer_invocation_id") != run_id
            or event.get("source_artifact")
            != AXIS_APPLICATION_RECEIPT_ARTIFACT
            or event.get("source_artifact_sha256")
            != binding["application_receipt_artifact_sha256"]
            or event.get("methodology_path") != AXIS_WORKLIST_ARTIFACT
            or event.get("methodology_sha256")
            != binding["worklist_artifact_sha256"]
            or event.get("methodology_obligation_id")
            != f"AXISGAP:{work_id}"
            or event.get("harvest_kind") != "TYPED_AXIS_CLEAR_V2"
            or event.get("external_assumption") is not False
        ):
            raise CandidateNegativeAuthorityError(
                "axis candidate-negative event lineage mismatch"
            )
        excerpt = _canonical_json(dict(disposition))
        locus = (
            f"{work_item.get('source_relpath')}:{work_item.get('source_locus')}"
        )
        if (
            event.get("source_excerpt") != excerpt
            or event.get("source_excerpt_sha256")
            != _bytes_sha(excerpt.encode("utf-8"))
            or event.get("guard_locus") != locus
            or event.get("evidence_refs") != [locus]
            or event.get("exact_premise")
            != _text(disposition.get("rationale"))
        ):
            raise CandidateNegativeAuthorityError(
                "axis candidate-negative event projection mismatch"
            )
        expected_event = _axis_clear_event(
            item=work_item,
            disposition=disposition,
            run_id=run_id,
            worklist_hash=binding["worklist_hash"],
            worklist_sha256=binding["worklist_artifact_sha256"],
            application_receipt_digest=(
                binding["application_receipt_digest"]
            ),
            application_receipt_sha256=(
                binding["application_receipt_artifact_sha256"]
            ),
        )
        if event != expected_event:
            raise CandidateNegativeAuthorityError(
                "axis candidate-negative committed-invariant projection mismatch"
            )


def validate_candidate_negative_ledger(ledger: Any) -> None:
    if not isinstance(ledger, dict) or ledger.get("schema_version") != LEDGER_SCHEMA:
        raise CandidateNegativeAuthorityError("candidate-negative ledger schema mismatch")
    if ledger.get("phase") == AXIS_CLEAR_PHASE:
        _validate_axis_clear_ledger_shape(ledger)
    events = ledger.get("events")
    if not isinstance(events, list) or ledger.get("event_count") != len(events):
        raise CandidateNegativeAuthorityError("candidate-negative event count mismatch")
    ids = []
    for event in events:
        _validate_event(event)
        ids.append(event["event_id"])
    if ids != sorted(set(ids)):
        raise CandidateNegativeAuthorityError("candidate-negative events are not exact/unique")
    complete_commitments = [
        event["invariant_commitment"]
        for event in events
        if isinstance(event.get("invariant_commitment"), dict)
        and event["invariant_commitment"].get("status") == "COMPLETE"
    ]
    complete_ids = [
        _text(row.get("ci_id")).upper() for row in complete_commitments
    ]
    complete_blocks = [
        _text(row.get("ci_block_sha256")) for row in complete_commitments
    ]
    if len(complete_ids) != len(set(complete_ids)) or len(complete_blocks) != len(
        set(complete_blocks)
    ):
        raise CandidateNegativeAuthorityError(
            "committed-invariant identity/block is not ledger-global one-to-one"
        )
    if ledger.get("status") not in {"CLEAN", "INPUT_DEBT"}:
        raise CandidateNegativeAuthorityError("candidate-negative ledger status invalid")
    issues = ledger.get("issues")
    if not isinstance(issues, list) or any(not isinstance(row, dict) for row in issues):
        raise CandidateNegativeAuthorityError("candidate-negative ledger issues malformed")
    families = ledger.get("families")
    if not isinstance(families, list):
        raise CandidateNegativeAuthorityError("candidate-negative families malformed")
    event_ids = set(ids)
    observed_families: set[str] = set()
    covered_events: set[str] = set()
    membership_counts = {event_id: 0 for event_id in event_ids}
    events_by_id = {event["event_id"]: event for event in events}
    for family in families:
        if not isinstance(family, dict):
            raise CandidateNegativeAuthorityError("candidate-negative family is not an object")
        family_id = _text(family.get("family_id"))
        if not family_id or family_id in observed_families:
            raise CandidateNegativeAuthorityError("candidate-negative families are not unique")
        observed_families.add(family_id)
        family_events = family.get("event_ids")
        if (
            not isinstance(family_events, list)
            or family_events != sorted(set(family_events))
            or not set(family_events).issubset(event_ids)
        ):
            raise CandidateNegativeAuthorityError("candidate-negative family event vector invalid")
        covered_events.update(family_events)
        for event_id in family_events:
            membership_counts[event_id] += 1
            if events_by_id[event_id].get("family_id") != family_id:
                raise CandidateNegativeAuthorityError(
                    "candidate-negative family/event identity mismatch"
                )
        if family.get("identity_state") not in {"EXACT", "DERIVED", "CONFLICTED"}:
            raise CandidateNegativeAuthorityError("candidate-negative family state invalid")
    if covered_events != event_ids or any(
        count != 1 for count in membership_counts.values()
    ):
        raise CandidateNegativeAuthorityError("candidate-negative family denominator mismatch")
    if bool(issues) != (ledger.get("status") == "INPUT_DEBT"):
        raise CandidateNegativeAuthorityError("candidate-negative debt status mismatch")
    artifacts = ledger.get("source_artifacts")
    if not isinstance(artifacts, list):
        raise CandidateNegativeAuthorityError("candidate-negative source artifacts malformed")
    if ledger.get("phase") != AXIS_CLEAR_PHASE:
        expected_fields = {
            "relative_path",
            "sha256",
            "size_bytes",
            "producer_identity",
            "producer_invocation_id",
            "binding_digest",
        }
        artifact_pairs: set[tuple[str, str]] = set()
        artifact_actors: dict[tuple[str, str], tuple[str, str]] = {}
        for row in artifacts:
            if not isinstance(row, dict) or set(row) != expected_fields:
                raise CandidateNegativeAuthorityError(
                    "candidate-negative source artifact row malformed"
                )
            relative = _text(row.get("relative_path"))
            relative_path = Path(relative)
            if (
                not relative
                or relative_path.is_absolute()
                or ".." in relative_path.parts
                or relative_path.as_posix() != relative
                or not _HEX_RE.fullmatch(_text(row.get("sha256")))
                or isinstance(row.get("size_bytes"), bool)
                or not isinstance(row.get("size_bytes"), int)
                or row["size_bytes"] < 0
            ):
                raise CandidateNegativeAuthorityError(
                    "candidate-negative source artifact row values invalid"
                )
            unsigned_row = {
                key: value for key, value in row.items() if key != "binding_digest"
            }
            if row["binding_digest"] != _digest(unsigned_row):
                raise CandidateNegativeAuthorityError(
                    "candidate-negative source artifact binding digest mismatch"
                )
            pair = (relative.casefold(), row["sha256"])
            if pair in artifact_pairs:
                raise CandidateNegativeAuthorityError(
                    "candidate-negative source artifact binding duplicated"
                )
            artifact_pairs.add(pair)
            artifact_actors[pair] = (
                _text(row.get("producer_identity")),
                _text(row.get("producer_invocation_id")),
            )
        event_pairs = {
            (
                Path(_text(event.get("source_artifact"))).as_posix().casefold(),
                _text(event.get("source_artifact_sha256")),
            )
            for event in events
        }
        if artifact_pairs != event_pairs:
            raise CandidateNegativeAuthorityError(
                "candidate-negative source artifact/event denominator mismatch"
            )
        for event in events:
            pair = (
                Path(_text(event.get("source_artifact"))).as_posix().casefold(),
                _text(event.get("source_artifact_sha256")),
            )
            if artifact_actors.get(pair) != (
                _text(event.get("producer_identity")),
                _text(event.get("producer_invocation_id")),
            ):
                raise CandidateNegativeAuthorityError(
                    "candidate-negative source artifact producer binding mismatch"
                )
    unsigned = {key: value for key, value in ledger.items() if key != "ledger_digest"}
    if ledger.get("ledger_digest") != _digest(unsigned):
        raise CandidateNegativeAuthorityError("candidate-negative ledger digest mismatch")


def build_candidate_negative_ledger(
    *,
    phase: str,
    artifacts: Sequence[ArtifactInput],
    methodology_path: Path,
    prior_ledger: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    phase_n = _text(phase).casefold()
    if not phase_n:
        raise CandidateNegativeAuthorityError("candidate-negative phase is empty")
    if phase_n == AXIS_CLEAR_PHASE:
        raise CandidateNegativeAuthorityError(
            "axis_coverage negatives require the typed v2 adapter; "
            "Markdown is not an authority source"
        )
    try:
        method = Path(methodology_path).resolve(strict=True)
        method_bytes = method.read_bytes()
    except OSError as exc:
        raise CandidateNegativeAuthorityError(f"bound methodology unavailable: {exc}") from exc
    method_sha = _bytes_sha(method_bytes)

    prior_events: list[dict[str, Any]] = []
    if prior_ledger is not None:
        validate_candidate_negative_ledger(prior_ledger)
        if prior_ledger.get("phase") != phase_n:
            raise CandidateNegativeAuthorityError("prior ledger binds another phase")
        prior_events = [dict(row) for row in prior_ledger["events"]]

    artifact_rows: list[dict[str, Any]] = []
    derived: list[dict[str, Any]] = []
    seen_paths: set[str] = set()
    for artifact in sorted(artifacts, key=lambda row: Path(row.relative_path).as_posix().casefold()):
        relative = Path(artifact.relative_path).as_posix()
        key = relative.casefold()
        if not relative or Path(relative).is_absolute() or ".." in Path(relative).parts:
            raise CandidateNegativeAuthorityError("source artifact path is not safe/relative")
        if key in seen_paths:
            raise CandidateNegativeAuthorityError("duplicate source artifact path")
        seen_paths.add(key)
        sha = _bytes_sha(artifact.content)
        artifact_events = _artifact_events(
            artifact,
            phase=phase_n,
            methodology_path=method,
            methodology_sha=method_sha,
        )
        if artifact_events:
            artifact_rows.append(
                _source_artifact_row(
                    relative_path=relative,
                    sha256=sha,
                    size_bytes=len(artifact.content),
                    producer_identity=artifact.producer_identity,
                    producer_invocation_id=artifact.producer_invocation_id,
                )
            )
            derived.extend(artifact_events)

    by_id: dict[str, dict[str, Any]] = {}
    for event in [*prior_events, *derived]:
        prior = by_id.get(event["event_id"])
        if prior is not None and prior != event:
            raise CandidateNegativeAuthorityError(
                f"conflicting duplicate event {event['event_id']}"
            )
        by_id[event["event_id"]] = event
    events = _downgrade_globally_reused_commitments(
        [by_id[key] for key in sorted(by_id)]
    )
    current_event_ids = {event["event_id"] for event in derived}
    prior_issues = [
        dict(row) for row in (prior_ledger or {}).get("issues", [])
        if isinstance(row, dict)
    ]
    issues: list[dict[str, Any]] = list(prior_issues)
    family_events: dict[str, list[dict[str, Any]]] = {}
    for event in events:
        family_events.setdefault(event["family_id"], []).append(event)
        if event["identity_state"] == "DERIVED":
            issues.append(
                {
                    "code": "DERIVED_SOURCE_ITEM_ID",
                    "family_id": event["family_id"],
                    "event_id": event["event_id"],
                    "source_artifact": event["source_artifact"],
                }
            )
        if event.get("proposed_disposition") == "NOT_APPLICABLE_PROPOSAL":
            issues.append(
                {
                    "code": "EVENT_NOT_APPLICABLE_WITH_NONZERO_DENOMINATOR",
                    "family_id": event["family_id"],
                    "event_id": event["event_id"],
                    "source_artifact": event["source_artifact"],
                }
            )
        commitment = event.get("invariant_commitment") or {}
        if (
            event.get("producer_phase") == "depth"
            and event.get("proposed_disposition") == "REFUTATION_PROPOSAL"
            and event.get("identity_state") == "EXACT"
            and commitment.get("status") == "DEBT"
        ):
            issues.append(
                {
                    "code": "DEPTH_COMMITTED_INVARIANT_DEBT",
                    "family_id": event["family_id"],
                    "event_id": event["event_id"],
                    "source_artifact": event["source_artifact"],
                    "detail": _text(commitment.get("reason")),
                }
            )
    families: list[dict[str, Any]] = []
    for family_id in sorted(family_events):
        rows = family_events[family_id]
        current_rows = [row for row in rows if row["event_id"] in current_event_ids]
        claim_hashes = sorted({row["semantic_claim_sha256"] for row in rows})
        states = {row["identity_state"] for row in rows}
        family_state = "EXACT" if states == {"EXACT"} else "DERIVED"
        if len(current_rows) > 1:
            issues.append(
                {
                    "code": "DUPLICATE_SOURCE_ITEM_ID",
                    "family_id": family_id,
                    "event_ids": sorted(row["event_id"] for row in current_rows),
                }
            )
            family_state = "CONFLICTED"
        if len(claim_hashes) > 1:
            issues.append(
                {
                    "code": "CONFLICTING_ENTITY_CLAIM",
                    "family_id": family_id,
                    "semantic_claim_sha256s": claim_hashes,
                }
            )
            family_state = "CONFLICTED"
        families.append(
            {
                "family_id": family_id,
                "identity_state": family_state,
                "event_ids": sorted(row["event_id"] for row in rows),
                "current_event_ids": sorted(
                    row["event_id"] for row in current_rows
                ),
                "proposal_ids": sorted({row["proposal_id"] for row in rows}),
                "semantic_claim_sha256s": claim_hashes,
            }
        )
    issue_index = {
        _canonical_json(issue): issue for issue in issues
    }
    issues = [issue_index[key] for key in sorted(issue_index)]
    # Preserve every historical source-artifact binding too.  Rewrites append a
    # new hash record rather than making an earlier negative disappear.
    prior_artifacts = list((prior_ledger or {}).get("source_artifacts", []))
    artifact_index: dict[tuple[str, str], dict[str, Any]] = {}
    referenced_pairs = {
        (
            _text(event.get("source_artifact")).casefold(),
            _text(event.get("source_artifact_sha256")),
        )
        for event in events
    }
    for row in [*prior_artifacts, *artifact_rows]:
        if not isinstance(row, dict):
            raise CandidateNegativeAuthorityError("prior source artifact is malformed")
        pair = (
            str(row.get("relative_path", "")).casefold(),
            str(row.get("sha256", "")),
        )
        if pair in referenced_pairs:
            artifact_index[pair] = dict(row)
    sources = [artifact_index[key] for key in sorted(artifact_index)]
    unsigned = {
        "schema_version": LEDGER_SCHEMA,
        "phase": phase_n,
        "methodology_path": method.as_posix(),
        "methodology_sha256": method_sha,
        "source_artifacts": sources,
        "status": "INPUT_DEBT" if issues else "CLEAN",
        "issues": issues,
        "families": families,
        "event_count": len(events),
        "events": events,
    }
    ledger = {**unsigned, "ledger_digest": _digest(unsigned)}
    validate_candidate_negative_ledger(ledger)
    return ledger


def _load_axis_clear_authorities(
    *,
    worklist_path: Path,
    application_receipt_path: Path,
    expected_run_id: str,
    project_root: Path | None = None,
    expected_pipeline: str | None = None,
    expected_mode: str | None = None,
    expected_ecosystem: str | None = None,
) -> tuple[
    bytes,
    bytes,
    bytes,
    bytes,
    bytes,
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    Any,
]:
    """Load and semantically replay every authority behind a typed CLEAR."""

    run_id = _text(expected_run_id)
    if not run_id:
        raise CandidateNegativeAuthorityError(
            "axis candidate-negative expected run is empty"
        )
    work_path = Path(worklist_path)
    receipt_path = Path(application_receipt_path)
    if (
        work_path.name != AXIS_WORKLIST_ARTIFACT
        or receipt_path.name != AXIS_APPLICATION_RECEIPT_ARTIFACT
    ):
        raise CandidateNegativeAuthorityError(
            "axis candidate-negative authority artifact name mismatch"
        )
    try:
        if work_path.is_symlink() or receipt_path.is_symlink():
            raise OSError("authority path is a symbolic link")
        work_resolved = work_path.resolve(strict=True)
        receipt_resolved = receipt_path.resolve(strict=True)
        if (
            not work_resolved.is_file()
            or not receipt_resolved.is_file()
            or work_resolved.parent != receipt_resolved.parent
        ):
            raise OSError(
                "authority JSON files are not regular files in one scratchpad"
            )
        work_raw = work_resolved.read_bytes()
        receipt_raw = receipt_resolved.read_bytes()
        root = work_resolved.parent
        evidence_raw = (root / AXIS_EXECUTION_EVIDENCE_ARTIFACT).read_bytes()
        prior_snapshot_raw = (
            root / axis_prior_authority.SNAPSHOT_NAME
        ).read_bytes()
        prior_authority_raw = (
            root / axis_prior_authority.AUTHORITY_NAME
        ).read_bytes()
    except OSError as exc:
        raise CandidateNegativeAuthorityError(
            f"axis candidate-negative authority is unavailable: {exc}"
        ) from exc
    try:
        import axis_disposition as axis

        worklist = axis.load_axis_worklist_v2(work_resolved)
        receipt = axis.load_axis_disposition_v2_receipt(
            receipt_resolved,
            worklist=worklist,
        )
        evidence = axis.validate_axis_execution_evidence_authority(
            _strict_json_loads(evidence_raw),
            expected_run_id=run_id,
        )
        snapshot_binding = _strict_json_loads(prior_snapshot_raw)
        if not isinstance(snapshot_binding, Mapping):
            raise CandidateNegativeAuthorityError(
                "axis canonical-prior snapshot binding is malformed"
            )
        pipeline = _text(
            expected_pipeline or snapshot_binding.get("pipeline")
        ).casefold()
        mode = _text(
            expected_mode or snapshot_binding.get("mode")
        ).casefold()
        ecosystem = _text(
            expected_ecosystem or snapshot_binding.get("ecosystem")
        ).casefold()
        prior = (
            axis_prior_authority
            .load_axis_canonical_prior_authority(
                root,
                expected_run_id=run_id,
                expected_worklist_hash=str(worklist["worklist_hash"]),
                expected_pipeline=pipeline,
                expected_mode=mode,
                expected_ecosystem=ecosystem,
            )
        )
        axis.validate_axis_disposition_authority_v2(
            receipt,
            worklist,
            production_root=Path(project_root or root.parent),
            execution_evidence_authority=evidence,
            canonical_prior_ids=dict(prior.aliases),
            canonical_prior_authority_digest=prior.authority_digest,
        )
    except Exception as exc:
        raise CandidateNegativeAuthorityError(
            "axis candidate-negative worklist/application receipt is invalid: "
            f"{type(exc).__name__}: {exc}"
        ) from exc
    if (
        worklist.get("run_id") != run_id
        or receipt.get("run_id") != run_id
    ):
        raise CandidateNegativeAuthorityError(
            "axis candidate-negative authority run binding mismatch"
        )
    return (
        work_raw,
        receipt_raw,
        evidence_raw,
        prior_snapshot_raw,
        prior_authority_raw,
        worklist,
        receipt,
        evidence,
        prior,
    )


def _axis_clear_event(
    *,
    item: Mapping[str, Any],
    disposition: Mapping[str, Any],
    run_id: str,
    worklist_hash: str,
    worklist_sha256: str,
    application_receipt_digest: str,
    application_receipt_sha256: str,
) -> dict[str, Any]:
    work_id = _text(item.get("work_item_id"))
    if not _AXW_RE.fullmatch(work_id):
        raise CandidateNegativeAuthorityError(
            "axis CLEAR work item lacks an exact AXW identity"
        )
    obligation = f"AXISGAP:{work_id}"
    family_id = "CNF-" + _digest(
        {
            "producer_phase": AXIS_CLEAR_PHASE,
            "source_artifact": AXIS_APPLICATION_RECEIPT_ARTIFACT.casefold(),
            "source_item_id": work_id,
            "methodology_obligation_id": obligation,
        }
    )[:24].upper()
    proposal_id = "CNP-" + _digest(
        {
            "family_id": family_id,
            "proposed_disposition": "REFUTATION_PROPOSAL",
        }
    )[:24].upper()
    excerpt = _canonical_json(dict(disposition))
    excerpt_sha = _bytes_sha(excerpt.encode("utf-8"))
    locus = f"{item.get('source_relpath')}:{item.get('source_locus')}"
    axis_commitment = disposition.get("invariant_commitment")
    if not isinstance(axis_commitment, Mapping):
        raise CandidateNegativeAuthorityError(
            "axis CLEAR disposition lacks its normalized invariant commitment"
        )
    commitment_unsigned = {
        "status": "COMPLETE",
        "reason": "",
        "ci_id": _text(axis_commitment.get("ci_id")).upper(),
        "ci_block_sha256": _text(
            axis_commitment.get("ci_block_sha256")
        ),
        "locus": _text(axis_commitment.get("locus")),
        "shape": _text(axis_commitment.get("shape")).upper(),
        "assertion": _text(axis_commitment.get("assertion")),
        "falsify_class": _text(
            axis_commitment.get("falsify_class")
        ).lower(),
        "provenance": _text(axis_commitment.get("provenance")),
        "source_item_id": work_id,
        "source_artifact_sha256": application_receipt_sha256,
        "source_excerpt_sha256": excerpt_sha,
        "axis": _text(axis_commitment.get("axis")),
        "axis_work_item_sha256": _text(
            axis_commitment.get("work_item_sha256")
        ),
        "axis_source_relpath": _text(
            axis_commitment.get("source_relpath")
        ),
        "axis_source_locus": _text(
            axis_commitment.get("source_locus")
        ),
        "axis_source_hash": _text(axis_commitment.get("source_hash")),
        "axis_evidence_sha256": _text(
            axis_commitment.get("evidence_sha256")
        ),
        "axis_commitment_binding_digest": _text(
            axis_commitment.get("binding_digest")
        ),
    }
    invariant_commitment = {
        **commitment_unsigned,
        "binding_digest": _digest(commitment_unsigned),
    }
    lineage = {
        "run_id": run_id,
        "worklist_hash": worklist_hash,
        "application_receipt_digest": application_receipt_digest,
        "work_item": dict(item),
        "final_disposition": dict(disposition),
    }
    unsigned = {
        "event_id": "CNE-" + _digest(
            {
                "proposal_id": proposal_id,
                "source_artifact_sha256": application_receipt_sha256,
                "source_excerpt_sha256": excerpt_sha,
            }
        )[:24].upper(),
        "family_id": family_id,
        "proposal_id": proposal_id,
        "producer_phase": AXIS_CLEAR_PHASE,
        "producer_identity": "AXIS_DISPOSITION_APPLICATION_V2",
        "producer_invocation_id": run_id,
        "source_artifact": AXIS_APPLICATION_RECEIPT_ARTIFACT,
        "source_artifact_sha256": application_receipt_sha256,
        "source_item_id": work_id,
        "identity_state": "EXACT",
        "semantic_claim_sha256": _digest(
            {
                "work_item": dict(item),
                "final_disposition": dict(disposition),
            }
        ),
        "methodology_obligation_id": obligation,
        "methodology_path": AXIS_WORKLIST_ARTIFACT,
        "methodology_sha256": worklist_sha256,
        "legacy_disposition": "CLEAR",
        "proposed_disposition": "REFUTATION_PROPOSAL",
        "exact_premise": _text(disposition.get("rationale")),
        "guard_locus": locus,
        "variants_examined": [],
        "evidence_refs": [locus],
        "external_assumption": False,
        "proof_scope": "NONE",
        "requires_independent_consumer": True,
        "harvest_kind": "TYPED_AXIS_CLEAR_V2",
        "source_excerpt": excerpt,
        "source_excerpt_sha256": excerpt_sha,
        "invariant_commitment": invariant_commitment,
        "axis_lineage": lineage,
    }
    return {**unsigned, "event_digest": _digest(unsigned)}


def build_axis_clear_candidate_negative_ledger(
    *,
    worklist_path: Path,
    application_receipt_path: Path,
    expected_run_id: str,
    project_root: Path | None = None,
    expected_pipeline: str | None = None,
    expected_mode: str | None = None,
    expected_ecosystem: str | None = None,
) -> dict[str, Any]:
    """Project only typed, final v2 axis CLEAR rows into skeptic proposals.

    The adapter never reads ``axis_coverage_findings.md``.  Invalid JSON,
    signature drift, stale runs, and denominator debt cannot become invented
    CLEAR rows.  Valid row-level CLEAR application records remain proposals
    (proof scope ``NONE``) for an independent candidate-negative consumer.
    """

    (
        work_raw,
        receipt_raw,
        evidence_raw,
        prior_snapshot_raw,
        prior_authority_raw,
        worklist,
        receipt,
        evidence,
        prior,
    ) = _load_axis_clear_authorities(
        worklist_path=worklist_path,
        application_receipt_path=application_receipt_path,
        expected_run_id=expected_run_id,
        project_root=project_root,
        expected_pipeline=expected_pipeline,
        expected_mode=expected_mode,
        expected_ecosystem=expected_ecosystem,
    )
    run_id = _text(expected_run_id)
    work_sha = _bytes_sha(work_raw)
    receipt_sha = _bytes_sha(receipt_raw)
    binding_unsigned = {
        "schema_version": AXIS_CLEAR_ADAPTER_SCHEMA,
        "run_id": run_id,
        "worklist_artifact": AXIS_WORKLIST_ARTIFACT,
        "worklist_artifact_sha256": work_sha,
        "worklist_hash": worklist["worklist_hash"],
        "application_receipt_artifact": AXIS_APPLICATION_RECEIPT_ARTIFACT,
        "application_receipt_artifact_sha256": receipt_sha,
        "application_receipt_digest": receipt[
            "application_receipt_digest"
        ],
        "execution_evidence_artifact": AXIS_EXECUTION_EVIDENCE_ARTIFACT,
        "execution_evidence_artifact_sha256": _bytes_sha(evidence_raw),
        "execution_evidence_authority_digest": evidence[
            "authority_digest"
        ],
        "canonical_prior_snapshot_artifact": (
            axis_prior_authority.SNAPSHOT_NAME
        ),
        "canonical_prior_snapshot_sha256": _bytes_sha(prior_snapshot_raw),
        "canonical_prior_snapshot_digest": prior.snapshot_digest,
        "canonical_prior_authority_artifact": (
            axis_prior_authority.AUTHORITY_NAME
        ),
        "canonical_prior_authority_sha256": _bytes_sha(prior_authority_raw),
        "canonical_prior_authority_digest": prior.authority_digest,
        "denominator_status": worklist["denominator_status"],
        "application_status": receipt["status"],
    }
    binding = {
        **binding_unsigned,
        "binding_digest": _digest(binding_unsigned),
    }
    issues: list[dict[str, Any]] = []
    if worklist["denominator_status"] != "EXACT":
        issues.append(
            {
                "code": "AXIS_DENOMINATOR_NOT_EXACT",
                "detail": worklist["denominator_status"],
            }
        )
    for detail in worklist.get("input_debt", []):
        issues.append(
            {
                "code": "AXIS_DENOMINATOR_INPUT_DEBT",
                "detail": _text(detail),
            }
        )
    if (
        receipt["status"] != "COMPLETE"
        or receipt.get("application_record_complete") is not True
    ):
        issues.append(
            {
                "code": "AXIS_APPLICATION_AUTHORITY_DEBT",
                "detail": receipt["status"],
            }
        )
    for row in receipt.get("assurance_debt", {}).get("items", []):
        if isinstance(row, Mapping):
            issues.append(
                {
                    "code": "AXIS_APPLICATION_ASSURANCE_DEBT",
                    "detail": _text(row.get("message")),
                    "work_item_id": _text(row.get("work_item_id")),
                }
            )
    events: list[dict[str, Any]] = []
    for disposition in receipt["dispositions"]:
        if (
            disposition.get("disposition") != "CLEAR"
            or disposition.get("application_record_complete") is not True
        ):
            continue
        item = disposition.get("source_item")
        if not isinstance(item, Mapping):
            raise CandidateNegativeAuthorityError(
                "axis CLEAR disposition lost its typed source item"
            )
        events.append(
            _axis_clear_event(
                item=item,
                disposition=disposition,
                run_id=run_id,
                worklist_hash=worklist["worklist_hash"],
                worklist_sha256=work_sha,
                application_receipt_digest=receipt[
                    "application_receipt_digest"
                ],
                application_receipt_sha256=receipt_sha,
            )
        )
    events.sort(key=lambda row: row["event_id"])
    families = [
        {
            "family_id": event["family_id"],
            "identity_state": "EXACT",
            "event_ids": [event["event_id"]],
            "current_event_ids": [event["event_id"]],
            "proposal_ids": [event["proposal_id"]],
            "semantic_claim_sha256s": [
                event["semantic_claim_sha256"]
            ],
        }
        for event in sorted(events, key=lambda row: row["family_id"])
    ]
    issue_index = {
        _canonical_json(issue): issue
        for issue in issues
    }
    normalized_issues = [
        issue_index[key] for key in sorted(issue_index)
    ]
    unsigned = {
        "schema_version": LEDGER_SCHEMA,
        "phase": AXIS_CLEAR_PHASE,
        "methodology_path": AXIS_WORKLIST_ARTIFACT,
        "methodology_sha256": work_sha,
        "source_artifacts": [
            {
                "relative_path": AXIS_APPLICATION_RECEIPT_ARTIFACT,
                "sha256": receipt_sha,
                "size_bytes": len(receipt_raw),
                "producer_identity": "AXIS_DISPOSITION_APPLICATION_V2",
                "producer_invocation_id": run_id,
            },
            {
                "relative_path": AXIS_WORKLIST_ARTIFACT,
                "sha256": work_sha,
                "size_bytes": len(work_raw),
                "producer_identity": "AXIS_DISPOSITION_PLANNING_V2",
                "producer_invocation_id": run_id,
            },
        ],
        "status": "INPUT_DEBT" if normalized_issues else "CLEAN",
        "issues": normalized_issues,
        "families": families,
        "event_count": len(events),
        "events": events,
        "axis_authority_binding": binding,
    }
    ledger = {**unsigned, "ledger_digest": _digest(unsigned)}
    validate_candidate_negative_ledger(ledger)
    return ledger


def validate_axis_clear_candidate_negative_ledger(
    ledger: Mapping[str, Any],
    *,
    worklist_path: Path,
    application_receipt_path: Path,
    expected_run_id: str,
    project_root: Path | None = None,
    expected_pipeline: str | None = None,
    expected_mode: str | None = None,
    expected_ecosystem: str | None = None,
) -> dict[str, Any]:
    """Replay an axis CLEAR ledger from its current immutable JSON inputs."""

    validate_candidate_negative_ledger(ledger)
    expected = build_axis_clear_candidate_negative_ledger(
        worklist_path=worklist_path,
        application_receipt_path=application_receipt_path,
        expected_run_id=expected_run_id,
        project_root=project_root,
        expected_pipeline=expected_pipeline,
        expected_mode=expected_mode,
        expected_ecosystem=expected_ecosystem,
    )
    candidate = json.loads(_canonical_json(dict(ledger)))
    if candidate != expected:
        raise CandidateNegativeAuthorityError(
            "axis candidate-negative ledger is not an exact authority replay"
        )
    return candidate


def write_axis_clear_candidate_negative_ledger(
    scratchpad: Path,
    *,
    worklist_path: Path,
    application_receipt_path: Path,
    expected_run_id: str,
    project_root: Path | None = None,
    expected_pipeline: str | None = None,
    expected_mode: str | None = None,
    expected_ecosystem: str | None = None,
) -> Path:
    """Build and atomically emit the canonical axis CLEAR proposal ledger."""

    ledger = build_axis_clear_candidate_negative_ledger(
        worklist_path=worklist_path,
        application_receipt_path=application_receipt_path,
        expected_run_id=expected_run_id,
        project_root=project_root,
        expected_pipeline=expected_pipeline,
        expected_mode=expected_mode,
        expected_ecosystem=expected_ecosystem,
    )
    return write_candidate_negative_ledger(scratchpad, ledger)


def _write_json_if_changed(path: Path, payload: Mapping[str, Any]) -> None:
    content = json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    try:
        if path.read_text(encoding="utf-8") == content:
            return
    except OSError:
        pass
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    temporary.write_text(content, encoding="utf-8")
    os.replace(temporary, path)


def write_candidate_negative_ledger(scratchpad: Path, ledger: Mapping[str, Any]) -> Path:
    validate_candidate_negative_ledger(ledger)
    path = Path(scratchpad) / f"{LEDGER_PREFIX}{ledger['phase']}.json"
    _write_json_if_changed(path, ledger)
    return path


def parse_candidate_negative_ledger_bytes(
    raw: bytes, *, expected_phase: str | None = None
) -> dict[str, Any]:
    """Strictly decode and validate one content-addressed proposal ledger."""

    ledger = _strict_json_loads(raw)
    if not isinstance(ledger, dict):
        raise CandidateNegativeAuthorityError(
            "candidate-negative ledger root is not an object"
        )
    validate_candidate_negative_ledger(ledger)
    if expected_phase is not None and ledger.get("phase") != _text(
        expected_phase
    ).casefold():
        raise CandidateNegativeAuthorityError(
            f"ledger phase mismatch: expected {_text(expected_phase).casefold()!r}"
        )
    return ledger


def build_candidate_negative_application_plan(
    scratchpad: Path,
    *,
    phases: Sequence[str],
    max_items_per_shard: int = 20,
) -> dict[str, Any]:
    """Build a separate, application-skeptic-compatible exact work plan.

    The schema is intentionally the already-tested generic independent-negative
    plan schema, while the file, source ledgers, work identities, and PhaseIO
    work units remain separate from methodology-step application.  This reuses
    the discriminator without merging or mutating the methodology denominator.
    """

    if isinstance(max_items_per_shard, bool) or max_items_per_shard < 1:
        raise ValueError("max_items_per_shard must be a positive integer")
    root = Path(scratchpad)
    normalized_phases = []
    for phase in phases:
        phase_n = _text(phase).casefold()
        if not phase_n or phase_n in normalized_phases:
            raise CandidateNegativeAuthorityError(
                "candidate-negative phases must be exact and unique"
            )
        normalized_phases.append(phase_n)

    source_queues: dict[str, dict[str, Any]] = {}
    issues: list[dict[str, Any]] = []
    work_items: list[dict[str, Any]] = []
    input_row_count = 0
    seen_families: dict[str, str] = {}
    for phase_n in normalized_phases:
        name = f"{LEDGER_PREFIX}{phase_n}.json"
        path = root / name
        if not path.is_file():
            issues.append(
                {
                    "code": "MISSING_CANDIDATE_NEGATIVE_LEDGER",
                    "source_queue": name,
                }
            )
            continue
        try:
            raw = path.read_bytes()
            ledger = parse_candidate_negative_ledger_bytes(
                raw, expected_phase=phase_n
            )
        except (
            OSError,
            UnicodeError,
            json.JSONDecodeError,
            TypeError,
            CandidateNegativeAuthorityError,
        ) as exc:
            issues.append(
                {
                    "code": "INVALID_CANDIDATE_NEGATIVE_LEDGER",
                    "source_queue": name,
                    "detail": str(exc),
                }
            )
            continue
        source_queues[name] = {
            "artifact_sha256": _bytes_sha(raw),
            "queue_digest": ledger["ledger_digest"],
            "row_count": ledger["event_count"],
            "source_kind": "CANDIDATE_NEGATIVE_LEDGER",
        }
        for issue in ledger.get("issues", []):
            issues.append(
                {
                    **dict(issue),
                    "source_queue": name,
                }
            )
        events_by_id = {event["event_id"]: event for event in ledger["events"]}
        input_row_count += len(events_by_id)
        for family in ledger.get("families", []):
            family_id = family["family_id"]
            family_rows = [events_by_id[event_id] for event_id in family["event_ids"]]
            active_ids = list(family.get("current_event_ids") or family["event_ids"])
            active_rows = [events_by_id[event_id] for event_id in active_ids]
            binding_digest = _digest(
                {
                    "family_id": family_id,
                    "event_digests": sorted(
                        row["event_digest"] for row in family_rows
                    ),
                    "active_event_ids": sorted(active_ids),
                    "identity_state": family["identity_state"],
                }
            )
            prior_binding = seen_families.get(family_id)
            if prior_binding is not None:
                if prior_binding != binding_digest:
                    issues.append(
                        {
                            "code": "CONFLICTING_CANDIDATE_NEGATIVE_FAMILY",
                            "obligation_id": family_id,
                            "source_queue": name,
                        }
                    )
                continue
            seen_families[family_id] = binding_digest
            representative = sorted(active_rows, key=lambda row: row["event_id"])[-1]
            methodology_paths = sorted({row["methodology_path"] for row in active_rows})
            methodology_hashes = sorted(
                {row["methodology_sha256"] for row in active_rows}
            )
            if len(methodology_paths) != 1 or len(methodology_hashes) != 1:
                issues.append(
                    {
                        "code": "CONFLICTING_CANDIDATE_METHODOLOGY_BINDING",
                        "obligation_id": family_id,
                        "source_queue": name,
                    }
                )
            proposed = sorted({row["proposed_disposition"] for row in active_rows})
            premises = sorted({row["exact_premise"] for row in active_rows})
            evidence_refs = sorted(
                {
                    ref
                    for row in active_rows
                    for ref in row.get("evidence_refs", [])
                },
                key=str.casefold,
            )
            evidence_payload = {
                "application_subject": "CANDIDATE_NEGATIVE",
                "candidate_negative_family_id": family_id,
                "candidate_negative_event_ids": sorted(family["event_ids"]),
                "active_event_ids": sorted(active_ids),
                "candidate_negative_proposal_ids": sorted(family["proposal_ids"]),
                "source_artifacts": sorted(
                    {row["source_artifact"] for row in active_rows}
                ),
                "source_artifact_sha256s": sorted(
                    {row["source_artifact_sha256"] for row in active_rows}
                ),
                "source_item_ids": sorted(
                    {row["source_item_id"] for row in active_rows}
                ),
                "methodology_obligation_ids": sorted(
                    {row["methodology_obligation_id"] for row in active_rows}
                ),
                "legacy_dispositions": sorted(
                    {row["legacy_disposition"] for row in active_rows}
                ),
                "proposed_dispositions": proposed,
                "exact_premises": premises,
                "guard_loci": sorted(
                    {row["guard_locus"] for row in active_rows if row["guard_locus"]}
                ),
                "variants_examined": sorted(
                    {
                        variant
                        for row in active_rows
                        for variant in row.get("variants_examined", [])
                    },
                    key=str.casefold,
                ),
                "evidence_refs": evidence_refs,
                "external_assumption": any(
                    row["external_assumption"] for row in active_rows
                ),
                "proof_scope": "NONE",
                "invariant_commitments": [
                    row["invariant_commitment"]
                    for row in sorted(active_rows, key=lambda value: value["event_id"])
                ],
                "active_source_excerpts": [
                    row["source_excerpt"]
                    for row in sorted(active_rows, key=lambda value: value["event_id"])
                ],
            }
            original_evidence = _canonical_json(evidence_payload)
            evidence_basis = (
                "EXTERNAL_UNRESEARCHED"
                if evidence_payload["external_assumption"]
                else "IN_SCOPE_SOURCE" if evidence_refs else "NONE"
            )
            premise_ids = [
                "CNPREM-" + _digest(
                    {"family_id": family_id, "exact_premise": premise}
                )[:24].upper()
                for premise in premises
            ]
            seed_title_subject = (
                representative.get("source_item_id") or family_id
            )
            reopen_candidate_seed = {
                "title": _candidate_seed_field(
                    f"Reopened candidate negative {seed_title_subject}",
                    limit=240,
                    title=True,
                ),
                "mechanism": _candidate_seed_field(
                    " | ".join(premises), limit=6000
                ),
                "harm": _candidate_seed_field(
                    "The security impact remains unresolved until the exact "
                    "candidate is independently verified with replayable evidence.",
                    limit=4000,
                ),
            }
            # Reuse the registered application-skeptic candidate transport,
            # whose stable source-work identity contract is ASW-*.
            work_id = "ASW-" + _digest(
                {
                    "family_id": family_id,
                    "binding_digest": binding_digest,
                }
            )[:24].upper()
            work_items.append(
                {
                    "work_item_id": work_id,
                    "application_subject": "CANDIDATE_NEGATIVE",
                    "obligation_id": family_id,
                    "skill": CANDIDATE_NEGATIVE_SKILL,
                    "step": (
                        f"{' + '.join(evidence_payload['methodology_obligation_ids'])} / "
                        f"{' + '.join(proposed)} / "
                        f"{' + '.join(evidence_payload['source_item_ids'])}"
                    ),
                    "methodology_path": methodology_paths[0],
                    "methodology_sha256": methodology_hashes[0],
                    "semantic_outcome": (
                        "NOT_APPLICABLE"
                        if proposed == ["NOT_APPLICABLE_PROPOSAL"]
                        else "NEGATIVE"
                    ),
                    "evidence_basis": evidence_basis,
                    "original_evidence": original_evidence,
                    "original_result": (
                        f"{' + '.join(proposed)}: "
                        f"{' | '.join(premises)}"
                    ),
                    "binding_digest": binding_digest,
                    "input_row_ids": sorted(family["event_ids"]),
                    "source_queues": [name],
                    "producer_identities": sorted(
                        {row["producer_identity"] for row in family_rows if row["producer_identity"]}
                    ),
                    "producer_invocation_ids": sorted(
                        {
                            row["producer_invocation_id"]
                            for row in family_rows
                            if row["producer_invocation_id"]
                        }
                    ),
                    "original_evidence_sha256": hashlib.sha256(
                        original_evidence.encode("utf-8")
                    ).hexdigest(),
                    "candidate_negative_event_digests": sorted(
                        row["event_digest"] for row in family_rows
                    ),
                    "candidate_negative_family_binding_digest": binding_digest,
                    "candidate_negative_proposal_id": representative["proposal_id"],
                    "candidate_proposed_dispositions": proposed,
                    "candidate_premise_ids": premise_ids,
                    "reopen_candidate_seed": reopen_candidate_seed,
                    "candidate_negative_family_id": family_id,
                    "candidate_identity_state": representative["identity_state"],
                    "candidate_family_identity_state": family["identity_state"],
                    "candidate_invariant_commitment_statuses": sorted(
                        {
                            _text(row["invariant_commitment"].get("status")).upper()
                            for row in active_rows
                        }
                    ),
                }
            )

    work_items.sort(key=lambda item: item["work_item_id"])
    shards: list[dict[str, Any]] = []
    for offset in range(0, len(work_items), max_items_per_shard):
        items = work_items[offset : offset + max_items_per_shard]
        ordinal = len(shards) + 1
        unsigned_shard = {
            "shard_id": f"candidate-negative-{ordinal:04d}",
            "work_item_ids": [item["work_item_id"] for item in items],
        }
        shards.append(
            {**unsigned_shard, "shard_digest": _digest(unsigned_shard)}
        )
    status = "INPUT_DEBT" if issues else "READY" if work_items else "NOT_TRIGGERED"
    unsigned = {
        "schema_version": APPLICATION_PLAN_SCHEMA,
        "status": status,
        "queue_phases": normalized_phases,
        "source_queues": source_queues,
        "input_row_count": input_row_count,
        "work_item_count": len(work_items),
        "max_items_per_shard": max_items_per_shard,
        "work_items": work_items,
        "shards": shards,
        "issues": sorted(
            issues,
            key=lambda issue: (
                _text(issue.get("source_queue")),
                _text(issue.get("obligation_id")),
                _text(issue.get("code")),
            ),
        ),
    }
    return {**unsigned, "work_plan_digest": _digest(unsigned)}


def write_candidate_negative_application_plan(
    scratchpad: Path, plan: Mapping[str, Any]
) -> Path:
    # Recompute the generic plan digest locally rather than importing the
    # discriminator module and creating a circular authority dependency.
    if plan.get("schema_version") != APPLICATION_PLAN_SCHEMA:
        raise CandidateNegativeAuthorityError(
            "candidate-negative work-plan schema mismatch"
        )
    unsigned = {key: value for key, value in plan.items() if key != "work_plan_digest"}
    if plan.get("work_plan_digest") != _digest(unsigned):
        raise CandidateNegativeAuthorityError(
            "candidate-negative work-plan digest mismatch"
        )
    path = Path(scratchpad) / CANDIDATE_PLAN_FILE
    _write_json_if_changed(path, plan)
    return path


def adjudicate_candidate_negative(
    plan: Mapping[str, Any],
    assessments: Sequence[Mapping[str, Any]],
    *,
    prior_receipt: Mapping[str, Any] | None = None,
    candidate_sink: Any = None,
    defer_missing: bool = False,
    model_invoked: bool | None = None,
    closure_authorities: Mapping[str, Mapping[str, Any]] | None = None,
    closure_provider_validator: Any = None,
    closure_authority: Any = None,
) -> dict[str, Any]:
    """Apply the generic independent discriminator plus identity vetoes.

    The shared application skeptic owns the assessment schema and proposal
    normalization.  Candidate/entity negatives add a stricter rule: an
    agreement cannot terminally exclude a proposal whose producer identity was
    derived or whose revision family conflicts.  Disagreement remains allowed
    because reopening is recall-additive.
    """

    import application_skeptic as skeptic

    items = {
        _text(row.get("work_item_id")): row
        for row in plan.get("work_items", [])
        if isinstance(row, Mapping)
    }
    effective_assessments: list[dict[str, Any]] = []
    nonterminal_reopened: set[str] = set()
    identity_vetoes: dict[str, tuple[str, str]] = {}
    for raw in assessments:
        assessment = dict(raw)
        work_id = _text(assessment.get("work_item_id"))
        item = items.get(work_id, {})
        proposed = {
            _text(value).upper()
            for value in item.get("candidate_proposed_dispositions", [])
        }
        identity_exact = (
            _text(item.get("candidate_identity_state")).upper() == "EXACT"
            and _text(item.get("candidate_family_identity_state")).upper()
            == "EXACT"
            and "UNRESOLVED" not in proposed
        )
        if _text(assessment.get("outcome")).upper() == "AGREE_NEGATIVE":
            family_state = _text(
                item.get("candidate_family_identity_state")
            ).upper()
            item_state = _text(item.get("candidate_identity_state")).upper()
            veto: tuple[str, str] | None = None
            if "UNRESOLVED" in proposed:
                veto = (
                    "PRODUCER_UNRESOLVED_CANNOT_CLOSE",
                    "producer uncertainty requires reopen or human review",
                )
            elif family_state == "CONFLICTED":
                veto = (
                    "CANDIDATE_IDENTITY_CONFLICT",
                    "producer entity/revision identity conflicts",
                )
            elif item_state != "EXACT" or family_state != "EXACT":
                veto = (
                    "CANDIDATE_IDENTITY_UNRESOLVED",
                    "producer entity has no stable explicit identity",
                )
            elif "DEBT" in {
                _text(value).upper()
                for value in item.get(
                    "candidate_invariant_commitment_statuses", []
                )
            }:
                veto = (
                    "DEPTH_COMMITTED_INVARIANT_DEBT",
                    "value-bearing depth negative lacks one exact committed invariant",
                )
            if veto is not None:
                # Identity uncertainty can veto exclusion, never a reopening.
                # Route the exact family to the ordinary additive candidate
                # transport; if delivery is unavailable the shared policy
                # emits a typed proof-scope-NONE mandatory-review obligation.
                assessment["outcome"] = "DISAGREE_CANDIDATE"
                assessment["candidate"] = dict(item["reopen_candidate_seed"])
                rationale = _text(assessment.get("rationale"))
                assessment["rationale"] = (
                    f"{veto[0]}: {veto[1]}"
                    + (f"; {rationale}" if rationale else "")
                )
                identity_vetoes[work_id] = veto
            elif identity_exact:
                authorized, policy_reason = terminal_negative_authorized(
                    work_item=item,
                    assessment=assessment,
                    authority=(closure_authorities or {}).get(work_id),
                    provider_validator=closure_provider_validator,
                    closure_authority=closure_authority,
                    requested_effect="REFUTED_FULL",
                )
                if not authorized:
                    assessment["outcome"] = "DISAGREE_CANDIDATE"
                    assessment["candidate"] = dict(item["reopen_candidate_seed"])
                    rationale = _text(assessment.get("rationale"))
                    assessment["rationale"] = (
                        f"{policy_reason}: terminal negative authority unavailable"
                        + (f"; {rationale}" if rationale else "")
                    )
                    nonterminal_reopened.add(work_id)
        effective_assessments.append(assessment)

    receipt = skeptic.adjudicate_application_skeptic(
        plan,
        effective_assessments,
        prior_receipt=prior_receipt,
        candidate_sink=candidate_sink,
        defer_missing=defer_missing,
        model_invoked=model_invoked,
        closure_authorities=closure_authorities,
        closure_provider_validator=closure_provider_validator,
        closure_authority=closure_authority,
    )
    assessment_by_id = {
        _text(row.get("work_item_id")): row
        for row in effective_assessments
        if isinstance(row, Mapping)
    }
    changed = False
    dispositions = []
    for row in receipt.get("work_dispositions", []):
        disposition = dict(row)
        work_id = _text(disposition.get("work_item_id"))
        item = items.get(work_id, {})
        assessment = assessment_by_id.get(work_id, {})
        if work_id in identity_vetoes:
            reason_code, detail = identity_vetoes[work_id]
            # Preserve the shared policy's positive proposal or typed review
            # transport.  Replacing it with a bare debt row would lose the
            # exact reopen/review obligation and recreate the recall failure.
            disposition["reason_code"] = reason_code
            disposition["detail"] = detail
            if (
                _text(disposition.get("disposition")).upper()
                == "REGISTRY_CANDIDATE_PROPOSED"
            ):
                disposition["proof_scope"] = "NONE"
                disposition["terminal_negative_authorized"] = False
            changed = True
        if (
            work_id in nonterminal_reopened
            and disposition.get("disposition") == "REGISTRY_CANDIDATE_PROPOSED"
        ):
            disposition["reason_code"] = (
                "NONTERMINAL_NEGATIVE_SUPPORT_REOPENED"
            )
            changed = True
        if (
            _text(assessment.get("outcome")).upper() == "AGREE_NEGATIVE"
            and disposition.get("disposition") == "NEGATIVE_AGREEMENT"
        ):
            family_state = _text(
                item.get("candidate_family_identity_state")
            ).upper()
            item_state = _text(item.get("candidate_identity_state")).upper()
            proposed = {
                _text(value).upper()
                for value in item.get("candidate_proposed_dispositions", [])
            }
            if "UNRESOLVED" in proposed:
                disposition = {
                    "work_item_id": work_id,
                    "obligation_id": item.get("obligation_id"),
                    "input_row_ids": list(item.get("input_row_ids") or []),
                    "disposition": "UNRESOLVED_DEBT",
                    "reason_code": "PRODUCER_UNRESOLVED_CANNOT_CLOSE",
                    "detail": "producer uncertainty requires reopen or human review",
                }
                changed = True
            elif family_state == "CONFLICTED":
                disposition = {
                    "work_item_id": work_id,
                    "obligation_id": item.get("obligation_id"),
                    "input_row_ids": list(item.get("input_row_ids") or []),
                    "disposition": "UNRESOLVED_DEBT",
                    "reason_code": "CANDIDATE_IDENTITY_CONFLICT",
                    "detail": "producer entity/revision identity conflicts",
                }
                changed = True
            elif item_state != "EXACT" or family_state != "EXACT":
                disposition = {
                    "work_item_id": work_id,
                    "obligation_id": item.get("obligation_id"),
                    "input_row_ids": list(item.get("input_row_ids") or []),
                    "disposition": "UNRESOLVED_DEBT",
                    "reason_code": "CANDIDATE_IDENTITY_UNRESOLVED",
                    "detail": "producer entity has no stable explicit identity",
                }
                changed = True
        dispositions.append(disposition)
    if not changed:
        return receipt

    input_dispositions = sorted(
        (
            {
                "input_row_id": input_id,
                "work_item_id": row["work_item_id"],
                "disposition": row["disposition"],
            }
            for row in dispositions
            for input_id in row.get("input_row_ids", [])
        ),
        key=lambda row: row["input_row_id"],
    )
    unresolved = sorted(
        row["work_item_id"]
        for row in dispositions
        if row.get("disposition") == "UNRESOLVED_DEBT"
    )
    pending = list(receipt.get("pending_work_item_ids") or [])
    if pending:
        status = "PARTIAL"
    elif unresolved or plan.get("status") == "INPUT_DEBT":
        status = "COMPLETED_WITH_DEBT"
    else:
        status = receipt.get("status", "COMPLETE")
    unsigned = {
        **{
            key: value
            for key, value in receipt.items()
            if key
            not in {
                "receipt_digest",
                "status",
                "work_dispositions",
                "input_dispositions",
                "unresolved_work_item_ids",
            }
        },
        "status": status,
        "work_dispositions": dispositions,
        "input_dispositions": input_dispositions,
        "unresolved_work_item_ids": unresolved,
    }
    return {**unsigned, "receipt_digest": _digest(unsigned)}


def validate_candidate_negative_receipt_for_resume(
    plan: Mapping[str, Any], receipt: Mapping[str, Any]
) -> dict[str, Any]:
    """Replay the generic receipt contract without authoring new outcomes."""

    candidate = dict(receipt)
    replayed = adjudicate_candidate_negative(
        plan,
        (),
        prior_receipt=candidate,
        defer_missing=True,
        model_invoked=bool(candidate.get("model_invoked")),
    )
    if replayed != candidate:
        raise CandidateNegativeAuthorityError(
            "candidate-negative resume receipt is not a stable exact replay"
        )
    return candidate


def preserve_last_good_reopened_candidates(
    plan: Mapping[str, Any],
    *,
    current_receipt: Mapping[str, Any],
    last_good_receipt: Mapping[str, Any] | None,
) -> tuple[dict[str, Any], bool]:
    """Recall-safe fallback after a failed reassessment.

    Only already-delivered additive candidate proposals may survive from the
    previous receipt.  A prior NEGATIVE_AGREEMENT is never reused here because
    losing its current execution/provider authority must reopen as debt.
    """

    if last_good_receipt is None:
        return dict(current_receipt), False
    try:
        prior = validate_candidate_negative_receipt_for_resume(
            plan, last_good_receipt
        )
    except (CandidateNegativeAuthorityError, Exception):
        return dict(current_receipt), False

    prior_rows = {
        _text(row.get("work_item_id")): dict(row)
        for row in prior.get("work_dispositions", [])
        if isinstance(row, Mapping)
        and _text(row.get("disposition")).upper()
        == "REGISTRY_CANDIDATE_PROPOSED"
    }
    if not prior_rows:
        return dict(current_receipt), False
    prior_proposals = {
        _text(row.get("proposal_id")): dict(row)
        for row in prior.get("registry_candidate_proposals", [])
        if isinstance(row, Mapping) and _text(row.get("proposal_id"))
    }
    current_rows = [
        dict(row)
        for row in current_receipt.get("work_dispositions", [])
        if isinstance(row, Mapping)
    ]
    changed = False
    selected_prior_proposals: dict[str, dict[str, Any]] = {}
    for index, row in enumerate(current_rows):
        work_id = _text(row.get("work_item_id"))
        if _text(row.get("disposition")).upper() == "REGISTRY_CANDIDATE_PROPOSED":
            continue
        prior_row = prior_rows.get(work_id)
        if prior_row is None:
            continue
        proposal_id = _text(prior_row.get("proposal_id"))
        proposal = prior_proposals.get(proposal_id)
        if proposal is None:
            continue
        current_rows[index] = prior_row
        selected_prior_proposals[proposal_id] = proposal
        changed = True
    if not changed:
        return dict(current_receipt), False

    proposals = {
        _text(row.get("proposal_id")): dict(row)
        for row in current_receipt.get("registry_candidate_proposals", [])
        if isinstance(row, Mapping) and _text(row.get("proposal_id"))
    }
    proposals.update(selected_prior_proposals)
    input_dispositions = sorted(
        (
            {
                "input_row_id": input_id,
                "work_item_id": row["work_item_id"],
                "disposition": row["disposition"],
            }
            for row in current_rows
            for input_id in row.get("input_row_ids", [])
        ),
        key=lambda row: row["input_row_id"],
    )
    unresolved = sorted(
        _text(row.get("work_item_id"))
        for row in current_rows
        if _text(row.get("disposition")).upper() == "UNRESOLVED_DEBT"
    )
    source_issues = [
        dict(row) if isinstance(row, Mapping) else {"code": _text(row)}
        for row in current_receipt.get("source_input_issues", [])
    ]
    source_issues.append(
        {
            "code": "LAST_GOOD_REOPENED_CANDIDATE_PRESERVED",
            "detail": (
                "current reassessment failed; retained only prior additive "
                "candidate delivery, never a prior terminal negative"
            ),
        }
    )
    unsigned = {
        **{
            key: value
            for key, value in current_receipt.items()
            if key
            not in {
                "receipt_digest",
                "status",
                "work_dispositions",
                "input_dispositions",
                "unresolved_work_item_ids",
                "source_input_issues",
                "registry_candidate_proposals",
            }
        },
        "status": "COMPLETED_WITH_DEBT",
        "work_dispositions": current_rows,
        "input_dispositions": input_dispositions,
        "unresolved_work_item_ids": unresolved,
        "source_input_issues": source_issues,
        "registry_candidate_proposals": [
            proposals[key] for key in sorted(proposals)
        ],
    }
    return {**unsigned, "receipt_digest": _digest(unsigned)}, True


def validate_candidate_negative_denominator(
    *,
    ledgers: Sequence[Mapping[str, Any]],
    plan: Mapping[str, Any],
    receipt: Mapping[str, Any],
    projection_path: Path | None = None,
) -> dict[str, Any]:
    """Reconcile every harvested event to exactly one durable outcome."""

    issues: list[str] = []

    def _record_input_issue(prefix: str, issue: Any) -> None:
        if isinstance(issue, Mapping):
            code = _text(issue.get("code")) or "UNSPECIFIED_INPUT_DEBT"
            detail = _text(issue.get("detail"))
            source = _text(issue.get("source_queue"))
            obligation = _text(issue.get("obligation_id"))
            qualifiers = ", ".join(
                value
                for value in (
                    f"source={source}" if source else "",
                    f"obligation={obligation}" if obligation else "",
                    detail,
                )
                if value
            )
            issues.append(f"{prefix} {code}" + (f": {qualifiers}" if qualifiers else ""))
            return
        issues.append(f"{prefix} {_text(issue) or 'UNSPECIFIED_INPUT_DEBT'}")

    expected: set[str] = set()
    for ledger in ledgers:
        try:
            validate_candidate_negative_ledger(ledger)
        except CandidateNegativeAuthorityError as exc:
            issues.append(f"invalid ledger: {exc}")
            continue
        expected.update(event["event_id"] for event in ledger["events"])

    unsigned_plan = {
        key: value for key, value in plan.items() if key != "work_plan_digest"
    }
    if (
        plan.get("schema_version") != APPLICATION_PLAN_SCHEMA
        or plan.get("work_plan_digest") != _digest(unsigned_plan)
    ):
        issues.append("candidate-negative work plan is invalid")
    for issue in plan.get("issues", []):
        _record_input_issue("candidate-negative plan input debt:", issue)

    expected_receipt_fields = {
        "schema_version",
        "status",
        "work_plan_digest",
        "model_invoked",
        "work_dispositions",
        "input_dispositions",
        "pending_work_item_ids",
        "unresolved_work_item_ids",
        "source_input_issues",
        "registry_candidate_proposals",
        "rejected_candidate_debt",
        "receipt_digest",
    }
    if set(receipt) != expected_receipt_fields:
        issues.append("candidate-negative receipt fields are not exact")
    if receipt.get("schema_version") != "plamen.application_skeptic_receipt.v1":
        issues.append("candidate-negative receipt schema mismatch")
    if receipt.get("work_plan_digest") != plan.get("work_plan_digest"):
        issues.append("candidate-negative receipt work-plan binding mismatch")
    receipt_unsigned = {
        key: value for key, value in receipt.items() if key != "receipt_digest"
    }
    if receipt.get("receipt_digest") != _digest(receipt_unsigned):
        issues.append("candidate-negative receipt digest mismatch")
    for issue in receipt.get("source_input_issues", []):
        _record_input_issue("candidate-negative receipt input debt:", issue)

    expected_proposal_ids: set[str] = set()
    delivered_proposal_ids: list[str] = []
    projection_sha256: str | None = None
    try:
        from finding_producer_registry import (
            normalize_application_skeptic_proposal,
            parse_application_skeptic_proposal_projection,
        )

        normalized_proposals = [
            normalize_application_skeptic_proposal(row)
            for row in receipt.get("registry_candidate_proposals", [])
        ]
        expected_proposal_ids = {
            _text(row.get("proposal_id")) for row in normalized_proposals
        }
        if len(expected_proposal_ids) != len(normalized_proposals):
            issues.append("candidate-negative receipt duplicates proposal IDs")
    except Exception as exc:
        issues.append(
            "candidate-negative receipt proposals are invalid: "
            f"{type(exc).__name__}: {exc}"
        )

    disposition_proposal_ids = {
        _text(row.get("proposal_id"))
        for row in receipt.get("work_dispositions", [])
        if isinstance(row, Mapping)
        and _text(row.get("disposition")).upper()
        == "REGISTRY_CANDIDATE_PROPOSED"
    }
    if disposition_proposal_ids != expected_proposal_ids:
        issues.append(
            "candidate-negative receipt disposition/proposal parity mismatch"
        )

    if expected_proposal_ids:
        if projection_path is None:
            issues.append("candidate-negative reopened proposal projection is missing")
        else:
            try:
                projection = Path(projection_path)
                projection_bytes = projection.read_bytes()
                delivered = parse_application_skeptic_proposal_projection(projection)
                delivered_proposal_ids = sorted(
                    _text(row.get("proposal_id")) for row in delivered
                )
                projection_sha256 = hashlib.sha256(projection_bytes).hexdigest()
                if set(delivered_proposal_ids) != expected_proposal_ids:
                    issues.append(
                        "candidate-negative reopened proposal parity mismatch"
                    )
            except Exception as exc:
                issues.append(
                    "candidate-negative reopened proposal projection is invalid: "
                    f"{type(exc).__name__}: {exc}"
                )

    dispositions: dict[str, str] = {}
    for row in receipt.get("input_dispositions", []):
        if not isinstance(row, Mapping):
            issues.append("candidate-negative input disposition is malformed")
            continue
        event_id = _text(row.get("input_row_id"))
        if event_id in dispositions:
            issues.append(f"duplicate disposition for {event_id}")
            continue
        dispositions[event_id] = _text(row.get("disposition")).upper()
    for event_id in sorted(expected - set(dispositions)):
        issues.append(f"missing disposition for {event_id}")
    for event_id in sorted(set(dispositions) - expected):
        issues.append(f"unknown disposition for {event_id}")

    categories = {
        "NEGATIVE_AGREEMENT": "SUPPORTED_EXCLUSION",
        "REGISTRY_CANDIDATE_PROPOSED": "REOPENED_CANDIDATE",
        "UNRESOLVED_DEBT": "HUMAN_REVIEW",
    }
    outcomes = []
    for event_id in sorted(expected):
        disposition = dispositions.get(event_id, "")
        outcome = categories.get(disposition, "HUMAN_REVIEW")
        if disposition and disposition not in categories:
            issues.append(f"invalid disposition {disposition} for {event_id}")
        outcomes.append(
            {
                "event_id": event_id,
                "disposition": disposition or "MISSING",
                "outcome": outcome,
            }
        )
    counts = {
        "supported_exclusion_count": sum(
            row["outcome"] == "SUPPORTED_EXCLUSION" for row in outcomes
        ),
        "reopened_candidate_count": sum(
            row["outcome"] == "REOPENED_CANDIDATE" for row in outcomes
        ),
        "human_review_count": sum(
            row["outcome"] == "HUMAN_REVIEW" for row in outcomes
        ),
    }
    if issues:
        status = "INPUT_DEBT"
    elif receipt.get("status") in {"COMPLETED_WITH_DEBT", "PARTIAL"}:
        status = "COMPLETE_WITH_DEBT"
    else:
        status = "COMPLETE"
    unsigned = {
        "schema_version": "plamen.candidate_negative_denominator.v1",
        "status": status,
        "event_count": len(expected),
        **counts,
        "outcomes": outcomes,
        "issues": sorted(set(issues)),
        "plan_digest": plan.get("work_plan_digest"),
        "receipt_digest": receipt.get("receipt_digest"),
        "projection_sha256": projection_sha256,
        "delivered_proposal_ids": delivered_proposal_ids,
    }
    return {**unsigned, "denominator_digest": _digest(unsigned)}


def write_candidate_negative_denominator(
    scratchpad: Path, denominator: Mapping[str, Any]
) -> Path:
    unsigned = {
        key: value
        for key, value in denominator.items()
        if key != "denominator_digest"
    }
    if (
        denominator.get("schema_version")
        != "plamen.candidate_negative_denominator.v1"
        or denominator.get("denominator_digest") != _digest(unsigned)
    ):
        raise CandidateNegativeAuthorityError(
            "candidate-negative denominator is invalid"
        )
    path = Path(scratchpad) / CANDIDATE_DENOMINATOR_FILE
    _write_json_if_changed(path, denominator)
    return path


def validate_generator_prompt_negative_contract(prompt: str, *, phase: str) -> None:
    """Reject a rendered generator schema that grants terminal-negative authority.

    Negative words in prohibitions/explanations remain legal.  Only enum/schema
    contract lines are inspected.  Verifiers and independent discriminators are
    terminal consumers and therefore exempt.
    """

    phase_n = _text(phase).casefold()
    if phase_n.startswith("verify") or phase_n in {
        "application_skeptic",
        "skeptic_judge",
        "report_index",
    }:
        return
    violations = []
    for ordinal, line in enumerate(str(prompt or "").splitlines(), start=1):
        match = _GENERATOR_CONTRACT_LINE_RE.match(line)
        if match and _TERMINAL_PROMPT_RE.search(match.group(1)):
            violations.append(ordinal)
    if violations:
        raise CandidateNegativeAuthorityError(
            "generator prompt grants terminal-negative authority at line(s): "
            + ", ".join(map(str, violations))
        )


__all__ = [
    "ArtifactInput",
    "APPLICATION_PLAN_SCHEMA",
    "AXIS_CLEAR_ADAPTER_SCHEMA",
    "AXIS_CLEAR_PHASE",
    "CANDIDATE_PLAN_FILE",
    "CANDIDATE_DENOMINATOR_FILE",
    "CANDIDATE_NEGATIVE_SKILL",
    "CandidateNegativeAuthorityError",
    "LEDGER_PREFIX",
    "LEDGER_SCHEMA",
    "build_candidate_negative_ledger",
    "build_axis_clear_candidate_negative_ledger",
    "build_candidate_negative_application_plan",
    "adjudicate_candidate_negative",
    "validate_candidate_negative_denominator",
    "write_candidate_negative_denominator",
    "validate_candidate_negative_ledger",
    "validate_axis_clear_candidate_negative_ledger",
    "validate_generator_prompt_negative_contract",
    "write_candidate_negative_ledger",
    "write_axis_clear_candidate_negative_ledger",
    "write_candidate_negative_application_plan",
]
