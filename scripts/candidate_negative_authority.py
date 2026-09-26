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

import base64
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
from typing import Any, Mapping, Sequence
import uuid

import artifact_surface as AS
from negative_closure_policy import terminal_negative_authorized
import axis_canonical_prior as axis_prior_authority


LEDGER_SCHEMA = "plamen.candidate_negative_proposal_ledger.v1"
CANDIDATE_NEGATIVE_SKILL = "CANDIDATE_NEGATIVE_AUTHORITY"
LEDGER_PREFIX = "candidate_negative_proposals_"
CANDIDATE_PLAN_FILE = "candidate_negative_skeptic_work_plan.json"
CANDIDATE_DENOMINATOR_FILE = "candidate_negative_denominator.json"
CANDIDATE_PLANNING_DEBT_FILE = "candidate_negative_planning_debt.json"
APPLICATION_PLAN_SCHEMA = "plamen.application_skeptic_work_plan.v1"
AXIS_CLEAR_ADAPTER_SCHEMA = "plamen.axis_clear_candidate_negative_adapter.v1"
AXIS_CLEAR_PHASE = "axis_coverage"
AXIS_WORKLIST_ARTIFACT = "axis_disposition_worklist.json"
AXIS_APPLICATION_RECEIPT_ARTIFACT = "axis_disposition_receipt.json"
AXIS_EXECUTION_EVIDENCE_ARTIFACT = "axis_execution_evidence_authority.json"
DEPTH_CANDIDATE_NEGATIVE_STAGED_CONTEXT_SCHEMA = (
    "plamen.depth_candidate_negative_staged_context.v1"
)
CANDIDATE_NEGATIVE_STAGED_CONTEXT_SCHEMA = (
    "plamen.candidate_negative_staged_context.v2"
)
ATTENTION_REPAIR_ADAPTER_SCHEMA = (
    "plamen.attention_repair_candidate_negative_adapter.v1"
)
ATTENTION_REPAIR_PHASE = "attention_repair"
ATTENTION_REPAIR_QUEUE_ARTIFACT = "attention_repair_queue.md"
ATTENTION_REPAIR_PLAN_ARTIFACT = "attention_repair_shard_plan.json"
ATTENTION_REPAIR_APPLICATION_ARTIFACT = (
    "attention_repair_application_receipt.json"
)
ATTENTION_REPAIR_PRODUCER_IDENTITY = "ATTENTION_REPAIR_APPLICATION_V1"

_STAGED_METHODOLOGY_IDENTITY = "embedded:finding-output-format.md"
_STAGED_CANDIDATE_NEGATIVE_PHASES = frozenset({"breadth", "rescan", "depth"})
_MAX_STAGED_METHODOLOGY_BYTES = 512 * 1024
_MAX_STAGED_DEPTH_ARTIFACT_BYTES = 8 * 1024 * 1024
_MAX_STAGED_REASONS = 32
_MAX_STAGED_REASON_BYTES = 1024

_HEX_RE = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
_HEADING_RE = re.compile(r"(?m)^(#{1,6})\s+(.+?)\s*$")
_FIELD_RE = re.compile(
    r"(?im)^\s*(?:[-*]\s*)?\*{0,2}"
    r"(?P<field>Verdict|Status|Disposition|Result\s+Status|Assessment|"
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
# One allowlist, shared by both location readers.  A production language
# outside the list used to make a finding LOCATION-LESS, which then fed the
# blocking semantic-claim hash -- an extension spelling silently decided a
# fail-closed comparison.
_SOURCE_EXT = (
    "sol|vy|rs|move|go|ts|tsx|js|jsx|mjs|py|c|cc|cpp|h|hpp|wasm|cairo|sw|"
    "daml|huff|yul|fe|tact|func|clar|nr|java|kt|scala|sv|zig|ml|ex|exs"
)
_LOCATION_RE = re.compile(
    r"(?i)(?P<path>[A-Za-z0-9_@.+()\-\\/ ]+\."
    r"(?:" + _SOURCE_EXT + r"))"
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
_TABLE_ID_TOKEN = r"[A-Za-z][A-Za-z0-9_.:-]{0,95}"
_BARE_TABLE_ID_RE = re.compile(rf"^{_TABLE_ID_TOKEN}$", re.ASCII)
# An identity cell may carry the same Markdown decoration the heading
# recognizer already tolerates: `[DEPTH-TF-2]`, `Finding [DEPTH-TF-2]`,
# `Candidate DE-3`.  The ID token is the identity; the brackets and the role
# word are presentation.  Anything else (`[A]/[B]`, `[A] see B`, prose) stays
# DERIVED.
# Identity is read by MEANING, through exactly one resolver
# (`_identity_token`).  The retired `_DECORATED_TABLE_ID_RE` was a SECOND,
# independently-tolerant regex for the SAME property as the heading
# recognizer: `Finding DEPTH-TF-3` was an EXACT identity in a table cell
# and a DERIVED one in a heading, so the same string produced opposite
# verdicts depending on which Markdown construct carried it.
_ID_CAPTURE_TOKEN = r"[A-Za-z](?:[A-Za-z0-9_.:-]{0,94}[A-Za-z0-9])?"
_HEADING_LABELLED_ID_RE = re.compile(
    r"(?i)^(?:Finding|Candidate|Issue|Hypothesis)\b\s*[:#]?\s*"
    rf"\[?\s*(?P<id>{_ID_CAPTURE_TOKEN})\s*\]?"
)
# A BARE leading token is an identity only when it carries an ordinal.
# `DEPTH-TF-3` / `DS-6` do; `Cross-chain`, `Overview` and `Rounding` do
# not, so an ordinary English heading can never mint a candidate identity.
_HEADING_BARE_ID_RE = re.compile(
    rf"^\[?\s*(?P<id>{_ID_CAPTURE_TOKEN})\s*\]?\s*(?:[:\u2013\u2014]|-\s|$)"
)
# Columns whose cells carry a DISPOSITION.  `Severity` is deliberately absent:
# it is a tier column and never disposes of a candidate.
# A table row names a candidate ONLY when it carries a candidate identity.
# That single property retired BOTH representation proxies that used to
# stand in for it: a 30-word first-column vocabulary allowlist (renaming a
# column `Subject` or `Scenario` discarded the artifact) and a purity COUNT
# over every data row (appending one free-text self-report row RESCUED the
# artifact).  A methodology self-report carries no candidate identity, so
# it is skipped without a vocabulary; a real candidate reference carries
# one, so it is still harvested.
_TABLE_DISPOSITION_HEADERS = frozenset({
    "verdict", "status", "disposition", "outcome", "assessment",
    "result status", "conclusion", "exclusion",
})
_TABLE_ID_HEADERS = frozenset({"finding id", "candidate id", "issue id", "id"})
# A table whose SUBJECT column names a methodology step rather than a code
# artifact is the worker self-reporting which checks it performed -- e.g.
#   | Check | Status | Location |
#   | Replay check before state changes | n/a (absent) | - |
# That row asserts "this CHECK does not apply", not "this CANDIDATE is not
# applicable", and it carries no candidate denominator at all. Harvesting it
# minted a DERIVED-identity NOT_APPLICABLE candidate and rejected the whole
# artifact: DODO run34 discarded a 124KB breadth analysis carrying 17
# correctly-IDed findings over exactly this row. Recognised only when the
# table ALSO has no explicit ID column, so a real candidate table that happens
# to use one of these words still harvests normally.
# Zero-candidate attestation is read by MEANING through
# `AS.is_zero_candidate_placeholder`.  The retired two-string allowlist
# ({"—", "none new"}) minted a phantom candidate -- and therefore
# discarded the artifact -- for `–`, `-`, `N/A`, `(none)`, `&mdash;` and
# `no new candidates`, and it was column-position dependent when no ID
# column was declared.
_OBLIGATION_IN_TEXT_RE = re.compile(r"\[OBLIG:([^\]\r\n]+)\]", re.IGNORECASE)
_AXW_RE = re.compile(r"^AXW-[0-9A-F]{24}$", re.ASCII)
_STAGED_OUTPUT_ID_RE = re.compile(
    r"^scratchpad:[A-Za-z0-9][A-Za-z0-9_.-]{0,254}\.md$", re.ASCII
)

_COMMITTED_INVARIANT_ID_PATTERN = r"(?:[A-Z][A-Z0-9]*-)*CI(?:-[A-Z0-9]+)+"
# Decoration-tolerant: `**committed-invariant [CI-1]**`,
# `#### committed-invariant [CI-1]`, `- committed-invariant [CI-1]` and
# the bare canonical form are ONE header.  The retired whole-line anchor
# permitted no decoration at all, so bolding the header lost the entire
# committed invariant.
_CI_HEADER_RE = re.compile(
    r"(?im)^\s*(?:[-*+]\s+)?(?:\d+[.)]\s+)?(?:#{1,6}\s*)?(?:&gt;|>)?\s*"
    r"[*_`]{0,3}committed-invariant[*_`]{0,3}\s*"
    r"\[\s*(?P<id>[^\]\r\n]+?)\s*\][*_`]{0,3}\s*$"
)
# Same property, same tolerance as every other labelled field in this
# module: a list bullet, a numbered item, `**bold**` or a backticked label
# is presentation.  Writing the five mandated fields as a Markdown list
# used to lose ALL FIVE at once.
_CI_FIELD_RE = re.compile(
    r"(?im)^\s*(?:[-*+]\s+)?(?:\d+[.)]\s+)?[*_`]{0,3}"
    r"(?P<field>Locus|Shape|Assertion|Falsify\s+Class|Provenance)"
    r"[*_`]{0,3}\s*:\s*(?P<value>[^\r\n]+?)\s*$"
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
    r"^(?P<path>[^\r\n:]+(?:[\\/][^\r\n:]+)*\.(?:" + _SOURCE_EXT + r"))"
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
# Alias table keyed on the CANONICAL enum token (underscored, decoration
# and trailing punctuation already removed by `AS.normalize_enum`).  The
# measured one-character discard -- `NOT_APPLICABLE_PROPOSAL.` collapsing
# to the legacy terminal `NOT_APPLICABLE` because the alias-prefix test
# needed a SPACE and got a period -- is fixed here, at the root.
_ENUM_ALIASES = {
    "REFUTATION_PROPOSAL": "REFUTATION_PROPOSAL",
    "NOT_APPLICABLE_PROPOSAL": "NOT_APPLICABLE_PROPOSAL",
    "UNRESOLVED": "UNRESOLVED",
    "REFUTED": "REFUTED",
    "DISMISSED": "DISMISSED",
    "SAFE": "SAFE",
    "CLEAR": "CLEAR",
    "NO_FINDING": "NO_FINDING",
    "NO_FINDINGS": "NO_FINDING",
    "NO_ISSUE": "NO_FINDING",
    "NO_ISSUES": "NO_FINDING",
    "FALSE_POSITIVE": "FALSE_POSITIVE",
    "NOT_EXPLOITABLE": "NOT_EXPLOITABLE",
    "INFEASIBLE": "INFEASIBLE",
    "UNREACHABLE": "UNREACHABLE",
    "BY_DESIGN": "BY_DESIGN",
    "DUPLICATE": "DUPLICATE",
    "ABSORBED": "ABSORBED",
    "NOT_APPLICABLE": "NOT_APPLICABLE",
    "N_A": "NOT_APPLICABLE",
    "NA": "NOT_APPLICABLE",
}
# Column/field role maps passed to the shared reader.  Unknown columns are
# ignored, never fatal; an ABSENT role yields None, never a positional
# fallback.  `severity` stays a role of its own -- the one exclusion the
# measured gate got right: a tier column never disposes of a candidate.
_CN_COLUMN_ROLES = dict(AS.DEFAULT_COLUMN_ROLES)
# A table whose SUBJECT column names a methodology step, probe, register entry
# or ordinal is the worker self-reporting which checks it performed.  Those
# words are now `title`-ROLE SYNONYMS resolved through `normalize_label`
# (so `Skill&nbsp;Step`, `**Operator**` and `Criterion (v2)` all resolve),
# not a bespoke frozenset compared by raw case-folded equality.
#
# This is now a PRECISION filter only.  It can no longer discard anything:
# an unrecognised subject word makes the row a DERIVED candidate, and
# DERIVED identity is visible debt, not a staged rejection.  Under the old
# code renaming `Check` to `Subject`, `Mechanism`, `Scenario` or `Path`
# harvested a phantom and threw the whole artifact away.
_CN_COLUMN_ROLES["title"] = tuple(
    dict.fromkeys(
        AS.DEFAULT_COLUMN_ROLES["title"]
        + (
            "check", "checks", "step", "steps", "rule", "rules",
            "criterion", "criteria", "control", "question",
            "#", "no.", "num", "index", "ordinal",
            "operator", "probe", "mutation", "perturbation",
            "skill step", "skill", "task", "item", "test", "axis",
            "invariant", "property", "parameter", "variable", "symbol",
            "function", "contract", "file", "component", "area", "surface",
            "scenario", "path", "mechanism", "subject", "target area",
        )
    )
)
_CN_FIELD_ROLES = {
    "verdict": (
        "verdict", "status", "disposition", "result status", "assessment",
        "conclusion", "exclusion", "outcome", "determination",
        "finding status", "producer disposition", "proposal", "decision",
    ),
}
_CN_IDENTITY_FIELD_ROLES = {
    "candidate_id": (
        "finding id", "candidate id", "issue id", "hypothesis id",
        "finding identifier", "candidate identifier", "id",
    ),
}
# Obligation receipts are recognised on the NORMALIZED logical line, so a
# receipt the worker wrapped in backticks (the literal DODO run48
# behaviour), bolded, bulleted, numbered, blockquoted or laid out in a
# table cell is the same receipt.
_OBLIG_LINE_RE = re.compile(
    r"(?i)^\[?\s*OBLIG\s*:\s*(?P<obligation>[^\]\r\n|]+?)\s*\]?\s*[|,;]?\s*"
    r"STATUS\s*[:=]\s*(?P<status>D|DISMISSED)\b\s*[|,;.]?\s*"
    r"(?:KEY\s*[:=]\s*)?(?P<premise>.*)$"
)
_NEGATION_RE = re.compile(
    r"(?i)\b(?:no|not|never|without|irrelevant|unaffected|excluded|"
    r"excludes|n/a|none)\b"
)
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


def candidate_negative_planning_debt_bytes(
    *,
    run_id: str,
    plan_digest: str,
    planning_contract_digest: str,
    issues: Sequence[str],
) -> bytes:
    """Encode non-evidence debt when the exact planning union cannot bind."""

    unsigned = {
        "schema_version": "plamen.candidate_negative_planning_debt.v1",
        "authority_class": "NON_EVIDENCE_PLANNING_DEBT",
        "publication_eligible": False,
        "run_id": _text(run_id),
        "plan_digest": _text(plan_digest),
        "planning_contract_digest": _text(planning_contract_digest),
        "issues": sorted({_text(issue) for issue in issues if _text(issue)}),
    }
    payload = {**unsigned, "debt_digest": _digest(unsigned)}
    return (_canonical_json(payload) + "\n").encode("utf-8")


def validate_candidate_negative_planning_debt(raw: bytes) -> dict[str, Any]:
    """Validate the typed alternative to a candidate-negative work plan."""

    payload = _strict_json_loads(raw)
    if not isinstance(payload, dict):
        raise CandidateNegativeAuthorityError("planning debt is not an object")
    required = {
        "schema_version",
        "authority_class",
        "publication_eligible",
        "run_id",
        "plan_digest",
        "planning_contract_digest",
        "issues",
        "debt_digest",
    }
    if set(payload) != required:
        raise CandidateNegativeAuthorityError(
            "planning debt has an unexpected field set"
        )
    if (
        payload.get("schema_version")
        != "plamen.candidate_negative_planning_debt.v1"
        or payload.get("authority_class") != "NON_EVIDENCE_PLANNING_DEBT"
        or payload.get("publication_eligible") is not False
    ):
        raise CandidateNegativeAuthorityError(
            "planning debt has invalid authority metadata"
        )
    for field in ("plan_digest", "planning_contract_digest"):
        if not isinstance(payload.get(field), str) or not _HEX_RE.fullmatch(
            payload[field]
        ):
            raise CandidateNegativeAuthorityError(
                f"planning debt has malformed {field}"
            )
    issues = payload.get("issues")
    if (
        not isinstance(issues, list)
        or not issues
        or issues != sorted(set(issues))
        or any(not isinstance(issue, str) or not issue.strip() for issue in issues)
    ):
        raise CandidateNegativeAuthorityError(
            "planning debt must contain canonical non-empty issues"
        )
    unsigned = {
        key: value for key, value in payload.items() if key != "debt_digest"
    }
    if payload.get("debt_digest") != _digest(unsigned):
        raise CandidateNegativeAuthorityError("planning debt digest mismatch")
    if raw != (_canonical_json(payload) + "\n").encode("utf-8"):
        raise CandidateNegativeAuthorityError("planning debt is not canonical JSON")
    return payload


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
                # Digest the NORMALIZED block, so two invariants that differ
                # only in whitespace or decoration are one invariant.
                "ci_block_sha256": _bytes_sha(
                    AS.normalized_text(raw_block).encode("utf-8")
                ),
                "locus": _clean_inline(fields.get("locus", "")),
                # `Shape: conservation.` / `Shape: **CONSERVATION**` are the
                # same shape.  The enum token is extracted BEFORE the closed
                # vocabulary is consulted.
                "shape": AS.normalize_enum(fields.get("shape", "")),
                "assertion": fields.get("assertion", ""),
                "falsify_class": AS.normalize_enum(
                    fields.get("falsify_class", "")
                ).lower(),
                "provenance": _clean_inline(fields.get("provenance", "")),
            }
        )
    return blocks, {ci_id for ci_id, count in counts.items() if count != 1}


def _asserts_value_bearing(text: str) -> bool:
    """True when the excerpt AFFIRMS value-bearing content.

    Clause-scoped and negation-aware.  The retired whole-excerpt word scan
    voided the non-value-bearing exemption for a clause that explicitly DENIED
    harm ("(no revert possible)") and for a value-bearing word appearing only
    inside a function name or file path in a docstring reference.
    """

    for line in AS.surface(text or "").lines:
        for clause in re.split(r"[.;()\[\]]", line.text):
            if not _VALUE_BEARING_RE.search(clause):
                continue
            if _NEGATION_RE.search(clause):
                continue
            return True
    return False


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
        # `_clean_inline` here for the same reason the Locus value gets it:
        # a backticked declaration (``**Invariant Commitment**: `CI:CI-1` ``)
        # is the same declaration.  The retired code cleaned the sibling
        # fields but matched THIS one against the raw bytes.
        _clean_inline(match.group("value"))
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
                and not _asserts_value_bearing(excerpt or "")
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
                if _asserts_value_bearing(excerpt or ""):
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
    """Canonical legacy enum for a producer disposition value, or None.

    Property: `disposition.producer_enum` -- WHICH disposition the producer
    wrote.  It is read from the NORMALIZED enum token, never from the raw
    byte shape, so the measured one-character discards are gone at the root:

        NOT_APPLICABLE_PROPOSAL.              -> NOT_APPLICABLE_PROPOSAL
        NOT_APPLICABLE_PROPOSAL: no emission  -> NOT_APPLICABLE_PROPOSAL
        **NOT_APPLICABLE_PROPOSAL**. §5 is ... -> NOT_APPLICABLE_PROPOSAL
        REFUTATION_PROPOSAL.                  -> REFUTATION_PROPOSAL
        NOT_APPLICABLE                        -> NOT_APPLICABLE  (still distinct)

    The old implementation flattened `_` and `-` to spaces BEFORE matching, so
    a trailing period defeated the `alias + " "` prefix test and silently
    downgraded the correct nonterminal enum to the legacy terminal one -- which
    then fired EVENT_NOT_APPLICABLE_WITH_NONZERO_DENOMINATOR and discarded
    70,540 bytes of successful worker output (DODO run46 breadth).
    """

    token = AS.normalize_enum(value)
    if token:
        mapped = _ENUM_ALIASES.get(token)
        if mapped is not None:
            return mapped
    # Multi-WORD legacy spellings ("NO FINDING", "BY DESIGN") cannot be a
    # single enum token, so they keep the historic whole-value scan -- now on
    # the decoration-stripped value.
    candidate = AS.strip_decoration(value).strip(" |:*_-\t")
    candidate = candidate.upper().replace("-", " ").replace("_", " ")
    candidate = re.sub(r"\s+", " ", candidate).strip()
    for alias in sorted(_LEGACY_ALIASES, key=len, reverse=True):
        if candidate == alias or candidate.startswith(alias + " "):
            return _LEGACY_ALIASES[alias]
    return None


def _proposal_disposition(legacy: str) -> str:
    if legacy in {"NOT_APPLICABLE", "NOT_APPLICABLE_PROPOSAL"}:
        return "NOT_APPLICABLE_PROPOSAL"
    if legacy in {"UNRESOLVED", "DUPLICATE", "ABSORBED"}:
        # `DUPLICATE` / `ABSORBED` assert "same bug, different ID".  That is an
        # identity alias, not a claim about the code, so it carries no
        # falsifiable invariant and cannot be a refutation: demanding a
        # one-to-one committed invariant for it charged every worker that
        # followed the depth templates (which actively instruct this shape)
        # with DEPTH_COMMITTED_INVARIANT_DEBT.  UNRESOLVED already has the
        # exact fail-closed semantics required -- the adjudicator vetoes
        # AGREE_NEGATIVE on a producer-unresolved candidate -- so the
        # candidate stays open for independent review instead of being
        # silently closed or blocking the artifact.
        return "UNRESOLVED"
    return "REFUTATION_PROPOSAL"


def _identity_token(text: object, *, allow_bare: bool = False) -> str | None:
    """THE candidate-identity resolver for this module.  Never raises.

    Property: `identity.candidate_id` -- WHICH candidate a record is about.
    The decision is fail-closed (an unresolved identity is recorded as DERIVED
    and can never close a candidate) but it is NOT representation-bound: the
    bytes are normalized first and the closed comparison then runs on the
    normalized value.  All of these are ONE identity::

        Finding [DS-6]      Finding DS-6      `DS-6`      **Finding [DS-6]**
        #### Finding [DS-6] Candidate DS-6    Issue DS-6  | DS-6 |

    ``allow_bare`` is True only where the surrounding structure already
    declares the text to be an identity (a heading, or a cell under a declared
    `Finding ID` column).  Elsewhere a bare token is a title, not an identity
    -- `finding-output-format.md`: "IDs embedded in titles, notes, evidence or
    other columns do not establish identity".
    """

    cleaned = AS.strip_decoration(text)
    if not cleaned:
        return None
    for pattern in (_EXPLICIT_ID_RE, _BRACKET_ID_RE):
        match = pattern.search(cleaned)
        if match:
            return match.group(1).upper()
    match = _HEADING_LABELLED_ID_RE.match(cleaned)
    if match:
        token = match.group("id")
        # An unbracketed role word must be followed by something shaped like
        # an identifier, not by an ordinary noun: `Finding DS-6` is an
        # identity, `Finding summary` is a container heading.
        if any(ch.isdigit() for ch in token) or "-" in token:
            return token.upper()
    if allow_bare:
        match = _HEADING_BARE_ID_RE.match(cleaned)
        if match:
            token = match.group("id")
            if any(ch.isdigit() for ch in token):
                return token.upper()
    return None


_CELL_ID_RE = re.compile(
    r"(?i)^(?:(?:Finding|Candidate|Issue|Hypothesis)\s*[:#]?\s+)?"
    rf"(?:\[\s*(?P<bracketed>{_ID_CAPTURE_TOKEN})\s*\]"
    rf"|(?P<plain>{_ID_CAPTURE_TOKEN}))$"
)


def _whole_cell_identity(text: object) -> str | None:
    """Identity of a value whose SURROUNDING STRUCTURE declares it an identity.

    A declared `Finding ID` column, or a `**Finding ID**:` field.  The value
    must be the identity and nothing else, so `[A]/[B]` and `DE-1 see ST-9`
    stay DERIVED -- naming two candidates, or an ID plus prose, is genuinely
    ambiguous identity, which is the one thing the closed family must not
    guess at.  Decoration is removed first, so `` `DE-1` ``, `**[DE-1]**`,
    `Finding [DE-1]` and `Candidate DE-1` are ONE identity.
    """

    cleaned = AS.strip_decoration(text)
    if not cleaned:
        return None
    match = _CELL_ID_RE.match(cleaned)
    if not match:
        return None
    return (match.group("bracketed") or match.group("plain")).upper()


def _candidate_like_heading(label: str) -> bool:
    """Return whether a heading can own one candidate-negative entity.

    Candidate findings routinely contain nested headings (for example the
    mandated ``### Precondition Analysis`` beneath an H2 finding).  Container
    headings such as ``## Findings`` are not entities and must never inherit a
    descendant's disposition merely because their lexical section spans it.
    """

    cleaned = AS.strip_decoration(label)
    return bool(
        re.match(r"(?i)^(?:finding|candidate|issue)\b", cleaned)
        or _identity_token(cleaned, allow_bare=True)
    )


def _blocks(text: str) -> list[tuple[str, str, int]]:
    """Return heading-owned blocks with candidate-aware Markdown scoping.

    A candidate-like heading owns its nested explanatory subsections and ends
    at the next same-or-higher heading.  A deeper candidate-like heading also
    begins a new entity and therefore terminates the current entity.  Every
    non-candidate heading retains the old immediate-next-heading boundary so a
    parent/container cannot borrow a child's candidate fields.
    """

    matches = [
        match
        for match in _HEADING_RE.finditer(text)
        # A `#### committed-invariant [CI-6]` header is part of the candidate
        # that declared it, not a new entity.  Promoting the header to a
        # heading used to cut the invariant out of its own finding's block.
        if not _CI_HEADER_RE.match(match.group(0))
    ]
    result: list[tuple[str, str, int]] = []
    for index, match in enumerate(matches):
        label = match.group(2).strip()
        end = len(text)
        if index + 1 < len(matches):
            end = matches[index + 1].start()
        if _candidate_like_heading(label):
            level = len(match.group(1))
            end = len(text)
            for successor in matches[index + 1:]:
                successor_label = successor.group(2).strip()
                if (
                    len(successor.group(1)) <= level
                    or _candidate_like_heading(successor_label)
                ):
                    end = successor.start()
                    break
        result.append((label, text[match.start():end].strip(), match.start()))
    return result


def _source_item_id(label: str, *, fallback: Mapping[str, Any]) -> str:
    token = _identity_token(label, allow_bare=True)
    if token:
        return token
    return _derived_source_item_id(label, fallback=fallback)


def _derived_source_item_id(label: str, *, fallback: Mapping[str, Any]) -> str:
    """Derive transport identity without interpreting producer prose as an ID."""

    normalized = re.sub(r"\s+", " ", AS.strip_decoration(label).casefold())
    if normalized:
        return "ENTITY-" + hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:20].upper()
    return "ENTITY-" + _digest(dict(fallback))[:20].upper()


def _identity_bearing_field(block: str) -> str | None:
    """Identity declared by a labelled field inside a candidate block."""

    if not block:
        return None
    for field in AS.read_fields(
        AS.surface(block), "candidate_id", roles=_CN_IDENTITY_FIELD_ROLES
    ):
        if AS.is_zero_candidate_placeholder(field.value):
            continue
        token = _whole_cell_identity(field.value)
        if token:
            return token
    return None


def _source_item_identity(
    label: str, *, fallback: Mapping[str, Any], block: str = ""
) -> tuple[str, str]:
    """Return a local identity and whether it was explicitly producer-bound.

    FAIL_CLOSED property `identity.candidate_id`, applied to the NORMALIZED
    value.  A DERIVED identity still exists only to TRANSPORT an otherwise-lost
    negative: it is recorded as DERIVED on the event, so the independent
    discriminator deterministically vetoes agreement and the candidate stays
    open.  What changed is what the check READS -- `Finding [DS-6]`,
    `Finding DS-6`, `` `DS-6` `` and `**Finding [DS-6]**` are now ONE identity,
    where deleting two bracket characters used to discard a 126,589-byte depth
    analysis carrying three correctly-IDed candidates.
    """

    token = _identity_token(label, allow_bare=True)
    if token:
        return token, "EXACT"
    token = _identity_bearing_field(block)
    if token:
        return token, "EXACT"
    return _derived_source_item_id(label, fallback=fallback), "DERIVED"


def _claim_norm(value: object) -> str:
    """Canonical claim text: decoration, spacing and terminal punctuation out.

    The old normalizer already absorbed whitespace, `**bold**`, backticks and
    case, then stopped ONE character short of a trailing period -- so two
    restatements of one candidate differing only by `.` hashed differently and
    tripped the blocking CONFLICTING_ENTITY_CLAIM.
    """

    text = AS.strip_decoration(value)
    text = re.sub(r"\s+", " ", text)
    return text.strip(" \t:;,.!?\u2013\u2014-").casefold()


def _semantic_claim_sha256(
    label: str, *, exact_premise: str, guard_locus: str
) -> str:
    claim = AS.strip_decoration(label)
    claim = _EXPLICIT_ID_RE.sub(" ", claim)
    claim = _BRACKET_ID_RE.sub(" ", claim)
    claim = re.sub(
        r"(?i)^\s*(?:finding|candidate|issue)\b\s*[:\-]*\s*", "", claim
    )
    # Only the FIRST premise segment participates.  `_premise` joins EVERY
    # rationale line it can see, so two restatements that quoted a different
    # subset of Reason/Evidence lines used to diverge and be reported as
    # "conflicting semantic claims".
    premise_head = _text(exact_premise).split(" | ")[0]
    return _digest(
        {
            "claim": _claim_norm(claim),
            "premise_or_mechanism": _claim_norm(premise_head),
            "guard_locus": _claim_norm(guard_locus),
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
    """Family join key: the obligation this negative ANSWERS.

    An `[OBLIG:...]` token that merely appears inside a running sentence is a
    MENTION, not an assertion, and must not rewrite the ledger/plan join key.
    The measured defect: adding the explanatory clause
    "(this also answers the driver row [OBLIG:OB-9])" to a Reason line moved
    the candidate to a different family across retries.  Only a token that
    OPENS a logical line (or a labelled obligation field) asserts the binding.
    """

    for line in AS.surface(text).lines:
        stripped = line.text.strip()
        match = _OBLIGATION_IN_TEXT_RE.match(stripped)
        if match:
            return "OBLIG:" + _clean_inline(match.group(1))
        if line.cells:
            for cell in line.cells:
                cell_match = _OBLIGATION_IN_TEXT_RE.match(cell.strip())
                if cell_match:
                    return "OBLIG:" + _clean_inline(cell_match.group(1))
    return "CANDIDATE:" + source_item_id


def _external_assumption(text: str) -> bool:
    """Advisory flag: does this negative REST on an out-of-scope premise?

    Clause-scoped and negation-aware.  The old whole-excerpt vocabulary scan
    set the flag from a clause that explicitly DENIED an external dependency
    ("... (off-chain relayer irrelevant)").
    """

    for line in AS.surface(text).lines:
        if line.in_fence:
            continue
        for clause in re.split(r"[.;()\[\]]", line.text):
            if not _EXTERNAL_RE.search(clause):
                continue
            if _NEGATION_RE.search(clause):
                continue
            return True
    return False


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
    source_identity: tuple[str, str] | None = None,
) -> dict[str, Any]:
    locations = _locations(excerpt)
    fallback_identity = {
        "phase": phase,
        "artifact": artifact.relative_path,
        "label": label,
        "legacy": legacy,
    }
    if source_identity is None:
        item_id, identity_state = _source_item_identity(
            label,
            fallback=fallback_identity,
            block=excerpt,
        )
    else:
        item_id, identity_state = source_identity
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
        "external_assumption": _external_assumption(excerpt),
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
    # Block-DIGEST equality is not the property.  Two genuinely distinct
    # invariants that happen to be worded identically collided, and one
    # legitimately shared assertion restated verbatim downgraded BOTH.  Reuse
    # is an IDENTITY relation: the same CI id discharging two proposals.
    duplicate_blocks: set[str] = set()
    del block_counts
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


def _na_disposition(value: object) -> bool:
    legacy = _normalize_legacy(value)
    return legacy is not None and _proposal_disposition(legacy) == "NOT_APPLICABLE_PROPOSAL"


def _block_attests_zero_candidates(block: str) -> bool:
    """True when the block explicitly attests ZERO candidates.

    Property: `identity.zero_denominator` -- does this record name a candidate
    at all?  Read by MEANING, in EITHER representation: a table row under a
    declared ID column, a table row whose only subject cell is a placeholder,
    or the same two facts written as labelled fields
    (``**Finding ID**: —`` + ``**Disposition**: NOT_APPLICABLE_PROPOSAL``).

    The old predicate scanned only lines starting with ``|``, so the identical
    attestation written as fields was invisible and a 10,220-byte rescan
    artifact whose entire body was that attestation was discarded (DODO run46
    rescan pc5).  Placeholder recognition was also a two-string allowlist; it
    is now :func:`AS.is_zero_candidate_placeholder`.
    """

    if not block:
        return False
    surf = AS.surface(block)
    placeholder = False
    attests = False
    for table in AS.read_tables(surf, roles=_CN_COLUMN_ROLES):
        for row in table.rows:
            identity_cell = row.get("candidate_id")
            if identity_cell is not None:
                if AS.is_zero_candidate_placeholder(identity_cell):
                    placeholder = True
            elif any(AS.is_zero_candidate_placeholder(cell) for cell in row.cells):
                placeholder = True
            for cell in row.cells:
                if _na_disposition(cell):
                    attests = True
    for field in AS.read_fields(
        surf, "candidate_id", roles=_CN_IDENTITY_FIELD_ROLES
    ):
        if AS.is_zero_candidate_placeholder(field.value):
            placeholder = True
    for field in AS.read_fields(surf, "verdict", roles=_CN_FIELD_ROLES):
        if _na_disposition(field.value):
            attests = True
    return placeholder and attests


def _block_names_a_candidate(label: str, block: str) -> bool:
    """True when the block resolves a real candidate identity."""

    if _identity_token(label, allow_bare=True):
        return True
    return _identity_bearing_field(block) is not None


def _table_speaks_dispositions(table: "AS.Table") -> bool:
    """True when EVERY data row of the table carries a recognised disposition.

    A register whose status column carries free text (`**BROKEN** -> [B3-2]`,
    `HOLDS`) reports on invariants or checks, not candidates, so one incidental
    `N/A` in it names no candidate.  Precision filter only: a false answer now
    costs at most one extra flagged record, never an artifact.
    """

    saw_row = False
    for row in table.rows:
        if not any(cell for cell in row.cells):
            continue
        saw_row = True
        if _normalize_legacy(row.get("disposition") or "") is None:
            return False
    return saw_row


def _table_events(
    surf: "AS.ArtifactSurface",
    *,
    phase: str,
    artifact: ArtifactInput,
    artifact_sha: str,
    methodology_path: Path,
    methodology_sha: str,
    duplicate_ci_ids: set[str],
) -> list[dict[str, Any]]:
    """Harvest structured table dispositions, addressed by column ROLE.

    Every representation test this replaced is gone:

    * ``line.strip().startswith("|")`` -- a GFM table that omits its outer
      pipes is legal Markdown and used to be invisible, silently dropping the
      producer's negative from the denominator.
    * a 4-entry ID-header and a 7-entry disposition-header case-folded
      allowlist -- ``Finding&nbsp;ID``, ``Determination``, ``Verdict / Status``
      and ``Proposal`` now resolve by ROLE.
    * ``len(identity_indexes) != 1 -> identity dropped for EVERY row`` --
      adding a correct, MORE informative second ID column made the gate
      strictly worse.  An ambiguous role now resolves to the most specific
      header and records DEBT (``table.ambiguities``); nothing is dropped.
    * the two-string zero-placeholder allowlist and its column-position
      fallback -- replaced by ``AS.is_zero_candidate_placeholder``.
    """

    events: list[dict[str, Any]] = []
    for table in AS.read_tables(surf, roles=_CN_COLUMN_ROLES):
        disposition_index = table.role_index("disposition")
        if disposition_index is None:
            continue
        identity_index = table.role_index("candidate_id")
        if identity_index is None:
            first_role_is_subject = bool(
                table.headers
                and AS.normalize_label(table.headers[0])
                in {AS.normalize_label(x) for x in _CN_COLUMN_ROLES["title"]}
            )
            if first_role_is_subject or not _table_speaks_dispositions(table):
                # No candidate denominator: `finding-output-format.md`
                # establishes table identity ONLY through a declared ID column.
                continue
        for row in table.rows:
            cells = list(row.cells)
            legacy = _normalize_legacy(row.get("disposition") or "")
            if legacy is None:
                continue
            source_identity: tuple[str, str]
            if identity_index is not None:
                identity_cell = row.get("candidate_id") or ""
                if (
                    AS.is_zero_candidate_placeholder(identity_cell)
                    and _proposal_disposition(legacy) == "NOT_APPLICABLE_PROPOSAL"
                ):
                    # An explicit zero-candidate attestation names no
                    # candidate; harvesting it can only mint a phantom whose
                    # derived identity then discarded the artifact.
                    continue
                token = _whole_cell_identity(identity_cell)
            else:
                token = None
                non_status = [
                    cell
                    for index, cell in enumerate(cells)
                    if index != disposition_index
                ]
                if (
                    _proposal_disposition(legacy) == "NOT_APPLICABLE_PROPOSAL"
                    and any(
                        AS.is_zero_candidate_placeholder(cell)
                        for cell in non_status
                    )
                    and not any(_whole_cell_identity(cell) for cell in non_status)
                ):
                    # The row's SUBJECT is an explicit zero-candidate
                    # placeholder, so it names no candidate.  Column-position
                    # free: the retired rule only looked at `cells[0]`, so
                    # reordering two non-status columns flipped the verdict and
                    # discarded the artifact.
                    continue
            label_parts = [
                cell
                for index, cell in enumerate(cells)
                if index != disposition_index
                and cell
                and not AS.is_zero_candidate_placeholder(cell)
            ]
            label = " | ".join(label_parts[:3]) or f"table-row-{len(events) + 1}"
            excerpt = "| " + " | ".join(cells) + " |"
            if token:
                source_identity = (token, "EXACT")
            else:
                source_identity = (
                    _derived_source_item_id(
                        label,
                        fallback={
                            "phase": phase,
                            "artifact": artifact.relative_path,
                            "label": label,
                            "legacy": legacy,
                            "table_row": excerpt,
                        },
                    ),
                    "DERIVED",
                )
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
                    source_identity=source_identity,
                )
            )
    return events


def _obligation_receipt_events(
    surf: "AS.ArtifactSurface",
    *,
    phase: str,
    artifact: ArtifactInput,
    artifact_sha: str,
    methodology_path: Path,
    methodology_sha: str,
    duplicate_ci_ids: set[str],
) -> list[dict[str, Any]]:
    """Harvest obligation-dismissal receipts from NORMALIZED logical lines.

    The retired `_STRICT_OBLIG_RE` was whole-line anchored against raw bytes:
    the identical receipt wrapped in backticks so it renders as code -- the
    literal DODO run48 worker behaviour -- bolded, bulleted, numbered, or laid
    out in a table cell harvested ZERO events, silently dropping the producer's
    dismissal from the independent-review denominator.  Decoration is now
    removed before the receipt grammar is applied.
    """

    events: list[dict[str, Any]] = []
    for line in surf.lines:
        candidates = [line.text.strip()]
        if line.cells:
            candidates.append(" ".join(cell.strip() for cell in line.cells))
        for text in candidates:
            match = _OBLIG_LINE_RE.match(text)
            if not match:
                continue
            obligation = _clean_inline(match.group("obligation"))
            excerpt = match.group(0).strip()
            events.append(
                _event(
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
                    # An obligation receipt disposes a DRIVER-OWNED obligation
                    # row.  Its identity is stable by construction (the
                    # obligation key) and its independent-review denominator is
                    # the security-obligation authority, not the candidate
                    # ledger.  The state stays DERIVED, so a receipt can never
                    # CLOSE a candidate on its own.
                    source_identity=(
                        f"OBLIG:{obligation.strip().upper()}" or "OBLIG:UNKNOWN",
                        "DERIVED",
                    ),
                )
            )
            break
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
    # STEP 3 of the migration recipe: normalize ONCE, at the top, and thread
    # the parsed value down.  No gate below re-derives Markdown syntax.
    surf = AS.surface(text)
    _artifact_ci_blocks, duplicate_ci_ids = _ci_blocks(text)
    events: list[dict[str, Any]] = []
    for label, block, _offset in _blocks(text):
        block_surface = AS.surface(block)
        fields = AS.read_fields(block_surface, "verdict", roles=_CN_FIELD_ROLES)
        for field in fields:
            legacy = _normalize_legacy(field.value)
            if legacy is None:
                continue
            if (
                _proposal_disposition(legacy) == "NOT_APPLICABLE_PROPOSAL"
                and not _block_names_a_candidate(label, block)
                and _block_attests_zero_candidates(block)
            ):
                # A section whose body is the explicit zero-candidate
                # attestation names NO candidate.  The gate is now "does this
                # block resolve a candidate identity", not "does its heading
                # happen to contain a bracket" -- the old proxy lost the
                # exemption for any heading carrying brackets at all.
                break
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
            surf,
            phase=phase,
            artifact=artifact,
            artifact_sha=artifact_sha,
            methodology_path=methodology_path,
            methodology_sha=methodology_sha,
            duplicate_ci_ids=duplicate_ci_ids,
        )
    )
    # A heading is the richer representation because it carries the complete
    # entity block (including evidence and committed-invariant material).  A
    # same-artifact table summary of the same exact candidate and normalized
    # proposal adds no event.  Differing proposals are deliberately retained
    # so ledger construction can expose representation conflict as debt.
    heading_dispositions = {
        (event["source_item_id"], event["proposed_disposition"])
        for event in events
        if event["harvest_kind"] == "STRUCTURED_ENTITY_FIELD"
        and event["identity_state"] == "EXACT"
    }
    events = [
        event
        for event in events
        if not (
            event["harvest_kind"] == "STRUCTURED_TABLE_ROW"
            and event["identity_state"] == "EXACT"
            and (event["source_item_id"], event["proposed_disposition"])
            in heading_dispositions
        )
    ]
    events.extend(
        _obligation_receipt_events(
            surf,
            phase=phase,
            artifact=artifact,
            artifact_sha=artifact_sha,
            methodology_path=methodology_path,
            methodology_sha=methodology_sha,
            duplicate_ci_ids=duplicate_ci_ids,
        )
    )
    by_id: dict[str, dict[str, Any]] = {}
    for event in events:
        # Two harvested representations sharing an event_id already share the
        # proposal, artifact and excerpt digests, so they are the same event.
        # The old code RAISED here, and every raise on this path became the
        # opaque "staged candidate-negative parse failed" rejection with no
        # repair path and no partial publication.  Keeping the first
        # representation is loss-free and cannot close a candidate.
        by_id.setdefault(event["event_id"], event)
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
                or _asserts_value_bearing(source_excerpt)
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


def _build_candidate_negative_ledger_from_bytes(
    *,
    phase: str,
    artifacts: Sequence[ArtifactInput],
    methodology_bytes: bytes,
    methodology_identity: str,
    prior_ledger: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a ledger from already-captured methodology and artifact bytes."""

    phase_n = _text(phase).casefold()
    if not phase_n:
        raise CandidateNegativeAuthorityError("candidate-negative phase is empty")
    if phase_n == AXIS_CLEAR_PHASE:
        raise CandidateNegativeAuthorityError(
            "axis_coverage negatives require the typed v2 adapter; "
            "Markdown is not an authority source"
        )
    if type(methodology_bytes) is not bytes:
        raise CandidateNegativeAuthorityError("bound methodology is not exact bytes")
    method_name = _text(methodology_identity)
    if not method_name or "\x00" in method_name:
        raise CandidateNegativeAuthorityError("bound methodology identity is invalid")
    method = Path(method_name)
    method_sha = _bytes_sha(methodology_bytes)

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
        if (
            event["identity_state"] == "DERIVED"
            and event.get("harvest_kind") == "STRICT_OBLIGATION_RECEIPT"
        ):
            # The obligation key IS the stable identity for this event kind.
            # "This candidate has no explicit ID" is not a property of a
            # driver-owned obligation row, and charging it made every depth
            # worker that correctly dismissed an obligation fail its gate.
            # The event is still DERIVED, so it can never close a candidate.
            continue
        if event["identity_state"] == "DERIVED":
            issues.append(
                {
                    "code": "DERIVED_SOURCE_ITEM_ID",
                    "family_id": event["family_id"],
                    "event_id": event["event_id"],
                    "source_artifact": event["source_artifact"],
                }
            )
        if (
            event.get("proposed_disposition") == "NOT_APPLICABLE_PROPOSAL"
            and event.get("legacy_disposition") != "NOT_APPLICABLE_PROPOSAL"
        ):
            # Only the explicit producer proposal enum is admissible for a
            # real candidate.  Legacy terminal spellings such as N/A remain
            # debt; the zero-denominator table placeholder is filtered before
            # an event exists.
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
        representation_dispositions: dict[str, set[str]] = {}
        for row in current_rows:
            representation_dispositions.setdefault(
                row["harvest_kind"], set()
            ).add(row["proposed_disposition"])
        heading_proposals = representation_dispositions.get(
            "STRUCTURED_ENTITY_FIELD", set()
        )
        table_proposals = representation_dispositions.get(
            "STRUCTURED_TABLE_ROW", set()
        )
        if heading_proposals and table_proposals and (
            heading_proposals != table_proposals
        ):
            issues.append(
                {
                    "code": "CONFLICTING_REPRESENTATION",
                    "family_id": family_id,
                    "event_ids": sorted(row["event_id"] for row in current_rows),
                    "heading_proposals": sorted(heading_proposals),
                    "table_proposals": sorted(table_proposals),
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
        family_proposals = {
            row["proposed_disposition"] for row in rows
        }
        if (
            "NOT_APPLICABLE_PROPOSAL" in family_proposals
            and family_proposals != {"NOT_APPLICABLE_PROPOSAL"}
        ):
            issues.append(
                {
                    "code": "MIXED_CANDIDATE_PROPOSAL_DISPOSITIONS",
                    "family_id": family_id,
                    "event_ids": sorted(row["event_id"] for row in rows),
                    "proposed_dispositions": sorted(family_proposals),
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


def build_candidate_negative_ledger(
    *,
    phase: str,
    artifacts: Sequence[ArtifactInput],
    methodology_path: Path,
    prior_ledger: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a candidate-negative ledger bound to a filesystem methodology."""

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
        raise CandidateNegativeAuthorityError(
            f"bound methodology unavailable: {exc}"
        ) from exc
    return _build_candidate_negative_ledger_from_bytes(
        phase=phase_n,
        artifacts=artifacts,
        methodology_bytes=method_bytes,
        methodology_identity=method.as_posix(),
        prior_ledger=prior_ledger,
    )


def _valid_staged_actor_identity(value: Any, *, allow_empty: bool) -> bool:
    if type(value) is not str or value != value.strip():
        return False
    if not value:
        return allow_empty
    return (
        len(value.encode("utf-8")) <= 256
        and "\x00" not in value
        and value.isprintable()
    )


def compile_candidate_negative_staged_context(
    methodology_bytes: bytes,
    output_identity: str,
    producer_identity: str,
    *,
    phase: str,
    invocation_id: str | None = None,
) -> dict[str, Any]:
    """Compile a phase-bound, filesystem-free producer admission context."""

    phase_n = _text(phase).casefold()
    if phase_n not in _STAGED_CANDIDATE_NEGATIVE_PHASES:
        raise ValueError("staged candidate-negative producer phase is invalid")
    if (
        type(methodology_bytes) is not bytes
        or not methodology_bytes
        or len(methodology_bytes) > _MAX_STAGED_METHODOLOGY_BYTES
    ):
        raise ValueError("staged candidate-negative methodology bytes are invalid")
    if type(output_identity) is not str or not _STAGED_OUTPUT_ID_RE.fullmatch(
        output_identity
    ):
        raise ValueError("staged candidate-negative output identity is not canonical")
    if not _valid_staged_actor_identity(producer_identity, allow_empty=False):
        raise ValueError("staged candidate-negative producer identity is invalid")
    invocation = "" if invocation_id is None else invocation_id
    if not _valid_staged_actor_identity(invocation, allow_empty=True):
        raise ValueError("staged candidate-negative invocation identity is invalid")
    context: dict[str, Any] = {
        "schema_version": CANDIDATE_NEGATIVE_STAGED_CONTEXT_SCHEMA,
        "phase": phase_n,
        "methodology_identity": _STAGED_METHODOLOGY_IDENTITY,
        "methodology_base64": base64.b64encode(methodology_bytes).decode("ascii"),
        "methodology_sha256": _bytes_sha(methodology_bytes),
        "output_identity": output_identity,
        "producer_identity": producer_identity,
        "producer_invocation_id": invocation,
    }
    context["context_digest"] = _digest(context)
    return context


def _closed_candidate_negative_staged_context(
    raw: Any,
) -> tuple[str, bytes, str, str, str] | None:
    fields = {
        "schema_version",
        "phase",
        "methodology_identity",
        "methodology_base64",
        "methodology_sha256",
        "output_identity",
        "producer_identity",
        "producer_invocation_id",
        "context_digest",
    }
    if not isinstance(raw, Mapping) or set(raw) != fields:
        return None
    context = dict(raw)
    supplied_digest = context.pop("context_digest", None)
    encoded = context.get("methodology_base64")
    phase = context.get("phase")
    if (
        context.get("schema_version") != CANDIDATE_NEGATIVE_STAGED_CONTEXT_SCHEMA
        or phase not in _STAGED_CANDIDATE_NEGATIVE_PHASES
        or context.get("methodology_identity") != _STAGED_METHODOLOGY_IDENTITY
        or type(encoded) is not str
        or len(encoded) > ((_MAX_STAGED_METHODOLOGY_BYTES + 2) // 3) * 4
        or not _HEX_RE.fullmatch(str(context.get("methodology_sha256") or ""))
        or type(context.get("output_identity")) is not str
        or not _STAGED_OUTPUT_ID_RE.fullmatch(context["output_identity"])
        or not _valid_staged_actor_identity(
            context.get("producer_identity"), allow_empty=False
        )
        or not _valid_staged_actor_identity(
            context.get("producer_invocation_id"), allow_empty=True
        )
        or supplied_digest != _digest(context)
    ):
        return None
    try:
        methodology = base64.b64decode(encoded.encode("ascii"), validate=True)
    except (UnicodeError, ValueError):
        return None
    if (
        not methodology
        or len(methodology) > _MAX_STAGED_METHODOLOGY_BYTES
        or base64.b64encode(methodology).decode("ascii") != encoded
        or _bytes_sha(methodology) != context["methodology_sha256"]
    ):
        return None
    return (
        str(phase),
        methodology,
        context["output_identity"],
        context["producer_identity"],
        context["producer_invocation_id"],
    )


def compile_depth_candidate_negative_staged_context(
    methodology_bytes: bytes,
    output_identity: str,
    producer_identity: str,
    invocation_id: str | None = None,
) -> dict[str, Any]:
    """Compile a filesystem-free context for one staged depth artifact.

    Raw methodology bytes are carried in canonical base64 as well as bound by
    SHA-256.  The runtime freezes the returned plain mapping before producer
    launch; the validator can therefore replay the same parser without a path
    lookup or a closure over mutable process state.
    """

    if (
        type(methodology_bytes) is not bytes
        or not methodology_bytes
        or len(methodology_bytes) > _MAX_STAGED_METHODOLOGY_BYTES
    ):
        raise ValueError("staged candidate-negative methodology bytes are invalid")
    if type(output_identity) is not str or not _STAGED_OUTPUT_ID_RE.fullmatch(
        output_identity
    ):
        raise ValueError("staged candidate-negative output identity is not canonical")
    if not _valid_staged_actor_identity(producer_identity, allow_empty=False):
        raise ValueError("staged candidate-negative producer identity is invalid")
    invocation = "" if invocation_id is None else invocation_id
    if not _valid_staged_actor_identity(invocation, allow_empty=True):
        raise ValueError("staged candidate-negative invocation identity is invalid")
    context: dict[str, Any] = {
        "schema_version": DEPTH_CANDIDATE_NEGATIVE_STAGED_CONTEXT_SCHEMA,
        "phase": "depth",
        "methodology_identity": _STAGED_METHODOLOGY_IDENTITY,
        "methodology_base64": base64.b64encode(methodology_bytes).decode("ascii"),
        "methodology_sha256": _bytes_sha(methodology_bytes),
        "output_identity": output_identity,
        "producer_identity": producer_identity,
        "producer_invocation_id": invocation,
    }
    context["context_digest"] = _digest(context)
    return context


def _closed_depth_candidate_negative_staged_context(
    raw: Any,
) -> tuple[bytes, str, str, str] | None:
    fields = {
        "schema_version",
        "phase",
        "methodology_identity",
        "methodology_base64",
        "methodology_sha256",
        "output_identity",
        "producer_identity",
        "producer_invocation_id",
        "context_digest",
    }
    if not isinstance(raw, Mapping) or set(raw) != fields:
        return None
    context = dict(raw)
    supplied_digest = context.pop("context_digest", None)
    encoded = context.get("methodology_base64")
    if (
        context.get("schema_version")
        != DEPTH_CANDIDATE_NEGATIVE_STAGED_CONTEXT_SCHEMA
        or context.get("phase") != "depth"
        or context.get("methodology_identity") != _STAGED_METHODOLOGY_IDENTITY
        or type(encoded) is not str
        or len(encoded) > ((_MAX_STAGED_METHODOLOGY_BYTES + 2) // 3) * 4
        or not _HEX_RE.fullmatch(str(context.get("methodology_sha256") or ""))
        or type(context.get("output_identity")) is not str
        or not _STAGED_OUTPUT_ID_RE.fullmatch(context["output_identity"])
        or not _valid_staged_actor_identity(
            context.get("producer_identity"), allow_empty=False
        )
        or not _valid_staged_actor_identity(
            context.get("producer_invocation_id"), allow_empty=True
        )
        or supplied_digest != _digest(context)
    ):
        return None
    try:
        methodology = base64.b64decode(encoded.encode("ascii"), validate=True)
    except (UnicodeError, ValueError):
        return None
    if (
        not methodology
        or len(methodology) > _MAX_STAGED_METHODOLOGY_BYTES
        or base64.b64encode(methodology).decode("ascii") != encoded
        or _bytes_sha(methodology) != context["methodology_sha256"]
    ):
        return None
    return (
        methodology,
        context["output_identity"],
        context["producer_identity"],
        context["producer_invocation_id"],
    )


def _truncate_staged_reason(value: str) -> str:
    raw = value.replace("\x00", "\\0").encode("utf-8")
    if len(raw) <= _MAX_STAGED_REASON_BYTES:
        return raw.decode("utf-8")
    raw = raw[:_MAX_STAGED_REASON_BYTES]
    while raw:
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError:
            raw = raw[:-1]
    return "staged candidate-negative rejection reason exceeded its byte bound"


def _bounded_staged_candidate_negative_reasons(
    values: Sequence[str],
) -> tuple[str, ...]:
    reasons = sorted(
        {
            _truncate_staged_reason(str(value).strip())
            for value in values
            if str(value).strip()
        }
    )
    if len(reasons) <= _MAX_STAGED_REASONS:
        return tuple(reasons)
    return tuple(
        reasons[: _MAX_STAGED_REASONS - 1]
        + ["additional candidate-negative rejection reasons were truncated"]
    )


# Every candidate-negative input-debt code, mapped to the PROPERTY it
# protects.  The closure is not a judgement call: it is read from
# `AS.closure_for_property`, which returns FAIL_CLOSED iff the dotted name's
# first segment is one of {identity, dedup, severity, disposition}.
#
# WHY THESE NAMES.  The four closed families exist because a permissive answer
# there REMOVES a candidate from human attention.  Discarding the staged
# artifact is the *maximal* form of that removal: every OTHER candidate in the
# same worker output disappears with it.  So the closed identity decision this
# module owes is "a negative whose candidate cannot be re-addressed may never
# CLOSE that candidate" -- which is carried structurally by
# `identity_state: DERIVED` + `proof_scope: NONE` +
# `requires_independent_consumer: True`, and vetoed downstream.  It is NOT
# "the producer must have decorated its heading with brackets"; that residue
# is a producer FORMAT obligation, and its correct failure action is a repair
# hint, not the destruction of a 126,589-byte analysis.
_CANDIDATE_NEGATIVE_ISSUE_PROPERTIES: Mapping[str, str] = {
    "DEPTH_COMMITTED_INVARIANT_DEBT": "receipt.committed_invariant",
    "DERIVED_SOURCE_ITEM_ID": "format.explicit_candidate_id_binding",
    "DUPLICATE_SOURCE_ITEM_ID": "format.candidate_restatement",
    "CONFLICTING_REPRESENTATION": "format.representation_consistency",
    "CONFLICTING_ENTITY_CLAIM": "format.claim_restatement_consistency",
    "MIXED_CANDIDATE_PROPOSAL_DISPOSITIONS": "format.family_disposition_mix",
    "EVENT_NOT_APPLICABLE_WITH_NONZERO_DENOMINATOR": (
        "format.nonterminal_enum_spelling"
    ),
}
_CANDIDATE_NEGATIVE_REPAIR_HINTS: Mapping[str, str] = {
    "DEPTH_COMMITTED_INVARIANT_DEBT": (
        "Add one complete `committed-invariant [CI-N]` block (Locus, Shape, "
        "Assertion, Falsify Class, Provenance) bound to this candidate."
    ),
    "DERIVED_SOURCE_ITEM_ID": (
        "Name the candidate once, e.g. `## Finding [XX-1]: title` or a "
        "`Finding ID` column. Decoration does not matter; an explicit ID does."
    ),
    "DUPLICATE_SOURCE_ITEM_ID": (
        "One candidate is described more than once. Keep the richest "
        "description and delete the restatement, or give the second one its "
        "own ID."
    ),
    "CONFLICTING_REPRESENTATION": (
        "A heading and a table row give this candidate different "
        "dispositions. Make them agree."
    ),
    "CONFLICTING_ENTITY_CLAIM": (
        "One ID carries two different claims. Give the second claim its own "
        "candidate ID."
    ),
    "MIXED_CANDIDATE_PROPOSAL_DISPOSITIONS": (
        "This candidate is both 'not applicable' and refuted. Choose one."
    ),
    "EVENT_NOT_APPLICABLE_WITH_NONZERO_DENOMINATOR": (
        "Use the nonterminal `NOT_APPLICABLE_PROPOSAL` enum for a real "
        "candidate; bare `N/A` is a legacy terminal spelling."
    ),
}
# Kept for compatibility with existing callers/tests: the blocking set is now
# derived, so this is exactly "every code whose property is not FAIL_CLOSED".
_NON_BLOCKING_CANDIDATE_NEGATIVE_DEBT = frozenset(
    code
    for code, prop in _CANDIDATE_NEGATIVE_ISSUE_PROPERTIES.items()
    if AS.closure_for_property(prop) != AS.FAIL_CLOSED
)


def _candidate_negative_issue_defect(
    issue: Mapping[str, Any], *, phase_label: str
) -> "AS.Defect":
    code = _text(issue.get("code")) or "UNKNOWN_INPUT_DEBT"
    prop = _CANDIDATE_NEGATIVE_ISSUE_PROPERTIES.get(
        code, f"unclassified.{code.casefold()}"
    )
    observed = _text(issue.get("detail")) or code
    return AS.Defect(
        property_violated=prop,
        physical_line=0,
        observed=f"{phase_label}: {observed}",
        expected="a re-addressable candidate record",
        repair_hint=_CANDIDATE_NEGATIVE_REPAIR_HINTS.get(
            code, f"candidate-negative input debt remains: {code}"
        ),
        closure=AS.closure_for_property(prop),
    )


def candidate_negative_check_result(
    ledger: Mapping[str, Any], *, producer_phase: str = "depth"
) -> "AS.CheckResult":
    """Typed verdict for one candidate-negative ledger.

    `result.should_discard` is the ONLY question a staged validator may ask
    before throwing an artifact away.  Debt defects travel WITH the published
    artifact (they are already on the ledger as `issues` and
    `status: INPUT_DEBT`), so the candidate stays visible to human review
    instead of vanishing with its worker's whole analysis.
    """

    phase_label = _text(producer_phase).casefold() or "producer"
    defects: list[AS.Defect] = []
    for issue in ledger.get("issues", []):
        if not isinstance(issue, Mapping):
            defects.append(
                AS.Defect(
                    property_violated="format.ledger_issue_shape",
                    physical_line=0,
                    observed=repr(issue)[:120],
                    expected="an input-debt object",
                    repair_hint="Rebuild the ledger; this row is malformed.",
                    closure=AS.DEBT,
                )
            )
            continue
        defects.append(
            _candidate_negative_issue_defect(issue, phase_label=phase_label)
        )
    if ledger.get("status") != "CLEAN" and not defects:
        defects.append(
            AS.Defect(
                property_violated="format.ledger_status",
                physical_line=0,
                observed=_text(ledger.get("status")),
                expected="CLEAN, or at least one explaining issue row",
                repair_hint="Rebuild the ledger; its status has no explanation.",
                closure=AS.DEBT,
            )
        )
    return AS.CheckResult(tuple(defects))


def _candidate_negative_debt_reasons(
    ledger: Mapping[str, Any],
    *,
    producer_phase: str = "depth",
) -> tuple[str, ...]:
    """Reasons that DENY the staged artifact.

    STEP 6 of the migration recipe: branch on `should_discard`, not on
    `not accepted`.  Every presentation-derived code above now degrades with
    visible debt plus a targeted repair hint; only a FAIL_CLOSED property can
    still deny.
    """

    result = candidate_negative_check_result(
        ledger, producer_phase=producer_phase
    )
    if not result.should_discard:
        return ()
    return _bounded_staged_candidate_negative_reasons(
        tuple(defect.render() for defect in result.blocking_defects)
    )


def evaluate_staged_candidate_negative_receipt(
    outputs: Mapping[str, bytes], context: Mapping[str, Any]
) -> tuple[bool, tuple[str, ...]]:
    """Evaluate one breadth/rescan/depth producer artifact before commit."""

    closed = _closed_candidate_negative_staged_context(context)
    if closed is None:
        return False, ("staged candidate-negative gate context is invalid",)
    phase, methodology, output_identity, producer_identity, invocation_id = closed
    if not isinstance(outputs, Mapping) or set(outputs) != {output_identity}:
        return False, ("staged candidate-negative output denominator mismatch",)
    artifact_bytes = outputs.get(output_identity)
    if (
        type(artifact_bytes) is not bytes
        or not artifact_bytes
        or len(artifact_bytes) > _MAX_STAGED_DEPTH_ARTIFACT_BYTES
    ):
        return False, ("staged candidate-negative output bytes are invalid",)
    try:
        artifact_bytes.decode("utf-8", errors="strict")
    except UnicodeError:
        return False, ("staged candidate-negative output is not strict UTF-8",)
    try:
        ledger = _build_candidate_negative_ledger_from_bytes(
            phase=phase,
            artifacts=(
                ArtifactInput(
                    relative_path=output_identity,
                    content=artifact_bytes,
                    producer_identity=producer_identity,
                    producer_invocation_id=invocation_id,
                ),
            ),
            methodology_bytes=methodology,
            methodology_identity=_STAGED_METHODOLOGY_IDENTITY,
        )
    except (CandidateNegativeAuthorityError, TypeError, ValueError) as exc:
        reasons = _bounded_staged_candidate_negative_reasons(
            (f"staged candidate-negative parse failed: {type(exc).__name__}: {exc}",)
        )
        return False, reasons
    reasons = _candidate_negative_debt_reasons(
        ledger, producer_phase=phase
    )
    return not reasons, reasons


def staged_candidate_negative_receipt_validator(
    outputs: Mapping[str, bytes], context: Mapping[str, Any]
) -> tuple[str, ...]:
    """Runtime-compatible validator for breadth/rescan/depth producers."""

    _accepted, reasons = evaluate_staged_candidate_negative_receipt(
        outputs, context
    )
    return reasons


def evaluate_staged_depth_candidate_negative_receipt(
    outputs: Mapping[str, bytes], context: Mapping[str, Any]
) -> tuple[bool, tuple[str, ...]]:
    """Pure evaluation form returning an admission bit and bounded reasons."""

    closed = _closed_depth_candidate_negative_staged_context(context)
    if closed is None:
        reasons = ("staged candidate-negative gate context is invalid",)
        return False, reasons
    methodology, output_identity, producer_identity, invocation_id = closed
    if not isinstance(outputs, Mapping) or set(outputs) != {output_identity}:
        reasons = ("staged candidate-negative output denominator mismatch",)
        return False, reasons
    artifact_bytes = outputs.get(output_identity)
    if (
        type(artifact_bytes) is not bytes
        or not artifact_bytes
        or len(artifact_bytes) > _MAX_STAGED_DEPTH_ARTIFACT_BYTES
    ):
        reasons = ("staged candidate-negative output bytes are invalid",)
        return False, reasons
    try:
        artifact_bytes.decode("utf-8", errors="strict")
    except UnicodeError:
        reasons = ("staged candidate-negative output is not strict UTF-8",)
        return False, reasons
    try:
        ledger = _build_candidate_negative_ledger_from_bytes(
            phase="depth",
            artifacts=(
                ArtifactInput(
                    relative_path=output_identity,
                    content=artifact_bytes,
                    producer_identity=producer_identity,
                    producer_invocation_id=invocation_id,
                ),
            ),
            methodology_bytes=methodology,
            methodology_identity=_STAGED_METHODOLOGY_IDENTITY,
        )
    except (CandidateNegativeAuthorityError, TypeError, ValueError) as exc:
        reasons = _bounded_staged_candidate_negative_reasons(
            (f"staged candidate-negative parse failed: {type(exc).__name__}: {exc}",)
        )
        return False, reasons
    reasons = _candidate_negative_debt_reasons(ledger)
    return not reasons, reasons


def staged_depth_candidate_negative_receipt_validator(
    outputs: Mapping[str, bytes], context: Mapping[str, Any]
) -> tuple[str, ...]:
    """Runtime-compatible top-level validator for one staged depth artifact."""

    _accepted, reasons = evaluate_staged_depth_candidate_negative_receipt(
        outputs, context
    )
    return reasons


def _load_attention_repair_candidate_negative_authorities(
    *,
    queue_bytes: bytes,
    plan_bytes: bytes,
    application_receipt_bytes: bytes,
) -> tuple[dict[str, Any], dict[str, Any], list[dict[str, Any]]]:
    if (
        type(queue_bytes) is not bytes
        or not queue_bytes
        or len(queue_bytes) > _MAX_STAGED_DEPTH_ARTIFACT_BYTES
        or type(plan_bytes) is not bytes
        or not plan_bytes
        or len(plan_bytes) > _MAX_STAGED_DEPTH_ARTIFACT_BYTES
        or type(application_receipt_bytes) is not bytes
        or not application_receipt_bytes
        or len(application_receipt_bytes) > _MAX_STAGED_DEPTH_ARTIFACT_BYTES
    ):
        raise CandidateNegativeAuthorityError(
            "attention candidate-negative authority bytes are invalid"
        )
    try:
        plan_raw = _strict_json_loads(plan_bytes)
        receipt_raw = _strict_json_loads(application_receipt_bytes)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise CandidateNegativeAuthorityError(
            "attention candidate-negative authority JSON is invalid: "
            f"{type(exc).__name__}: {exc}"
        ) from exc
    if not isinstance(plan_raw, dict) or not isinstance(receipt_raw, dict):
        raise CandidateNegativeAuthorityError(
            "attention candidate-negative authorities are not JSON objects"
        )
    try:
        import attention_repair_shards as attention

        issues = attention.validate_application_receipt_mapping(
            plan_raw, receipt_raw
        )
        queue_binding, queue_rows = attention.parse_bound_queue_bytes(
            queue_bytes
        )
    except Exception as exc:
        if isinstance(exc, CandidateNegativeAuthorityError):
            raise
        raise CandidateNegativeAuthorityError(
            "attention candidate-negative authority replay failed: "
            f"{type(exc).__name__}: {exc}"
        ) from exc
    if issues:
        raise CandidateNegativeAuthorityError(
            "attention candidate-negative authority is invalid: "
            + "; ".join(issues)
        )
    plan_rows = [
        dict(row)
        for shard in plan_raw["shards"]
        for row in shard["rows"]
    ]
    if (
        _bytes_sha(queue_bytes) != plan_raw["queue_file_sha256"]
        or queue_binding != plan_raw["parent_queue_binding_sha256"]
        or queue_rows != plan_rows
    ):
        raise CandidateNegativeAuthorityError(
            "attention candidate-negative plan lost its exact queue binding"
        )
    rows = receipt_raw.get("rows")
    assert isinstance(rows, list)
    return plan_raw, receipt_raw, [dict(row) for row in rows]


def _attention_repair_source_item_id(
    *, queue_binding_sha256: str, row: Mapping[str, Any]
) -> str:
    """Derive one stable typed identity solely from driver-bound row authority."""

    row_no = int(row["row"])
    suffix = _digest(
        {
            "queue_binding_sha256": queue_binding_sha256,
            "row": row_no,
            "kind": row["kind"],
            "target": row["target"],
        }
    )[:16].upper()
    return f"ATNR-{row_no:06d}-{suffix}"


def build_attention_repair_candidate_negative_ledger(
    *,
    queue_bytes: bytes,
    plan_bytes: bytes,
    application_receipt_bytes: bytes,
) -> dict[str, Any]:
    """Adapt typed SAFE/NO_FINDING receipts into independent-review proposals.

    The narrative aggregate is intentionally absent from this authority path.
    Row identity comes from the self-bound shard plan and application receipt;
    CONFIRMED and NEEDS_HUMAN rows are outside the negative denominator.
    """

    plan, receipt, rows = _load_attention_repair_candidate_negative_authorities(
        queue_bytes=queue_bytes,
        plan_bytes=plan_bytes,
        application_receipt_bytes=application_receipt_bytes,
    )
    queue_binding = str(plan["parent_queue_binding_sha256"])
    plan_sha = _bytes_sha(plan_bytes)
    receipt_sha = _bytes_sha(application_receipt_bytes)
    producer_invocation_id = queue_binding
    artifact = ArtifactInput(
        relative_path=ATTENTION_REPAIR_APPLICATION_ARTIFACT,
        content=application_receipt_bytes,
        producer_identity=ATTENTION_REPAIR_PRODUCER_IDENTITY,
        producer_invocation_id=producer_invocation_id,
    )
    # The verdict is read through the SAME normalizer as every other
    # disposition in this module, so `NO_FINDINGS`, `no issue`, `SAFE.` and
    # `safe` are the enums they obviously are.  A second, narrower two-string
    # vocabulary silently dropped those rows from the negative denominator --
    # a fail-OPEN recall hole invisible in the receipt.
    negative_rows = [
        row
        for row in rows
        if _normalize_legacy(row.get("verdict")) in {"SAFE", "NO_FINDING"}
    ]
    events: list[dict[str, Any]] = []
    for row in negative_rows:
        source_item_id = _attention_repair_source_item_id(
            queue_binding_sha256=queue_binding,
            row=row,
        )
        label = (
            f"attention repair row {row['row']} {row['kind']} "
            f"{row['target']}: {row['notes'] or row['evidence']}"
        )
        events.append(
            _event(
                phase=ATTENTION_REPAIR_PHASE,
                artifact=artifact,
                artifact_sha=receipt_sha,
                label=label,
                excerpt=_canonical_json(row),
                legacy=str(row["verdict"]),
                methodology_path=Path(ATTENTION_REPAIR_PLAN_ARTIFACT),
                methodology_sha=plan_sha,
                harvest_kind="TYPED_ATTENTION_REPAIR_V1",
                source_identity=(source_item_id, "EXACT"),
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
            "semantic_claim_sha256s": [event["semantic_claim_sha256"]],
        }
        for event in sorted(events, key=lambda row: row["family_id"])
    ]
    negative_row_numbers = sorted(int(row["row"]) for row in negative_rows)
    binding_unsigned = {
        "schema_version": ATTENTION_REPAIR_ADAPTER_SCHEMA,
        "plan_artifact": ATTENTION_REPAIR_PLAN_ARTIFACT,
        "plan_artifact_sha256": plan_sha,
        "plan_sha256": plan["plan_sha256"],
        "queue_artifact": ATTENTION_REPAIR_QUEUE_ARTIFACT,
        "queue_artifact_sha256": _bytes_sha(queue_bytes),
        "application_receipt_artifact": ATTENTION_REPAIR_APPLICATION_ARTIFACT,
        "application_receipt_artifact_sha256": receipt_sha,
        "queue_binding_sha256": queue_binding,
        "queue_file_sha256": plan["queue_file_sha256"],
        "row_count": plan["row_count"],
        "negative_row_count": len(negative_rows),
        "negative_row_numbers": negative_row_numbers,
        "producer_identity": ATTENTION_REPAIR_PRODUCER_IDENTITY,
        "producer_invocation_id": producer_invocation_id,
    }
    binding = {
        **binding_unsigned,
        "binding_digest": _digest(binding_unsigned),
    }
    source_artifacts = (
        [
            _source_artifact_row(
                relative_path=ATTENTION_REPAIR_APPLICATION_ARTIFACT,
                sha256=receipt_sha,
                size_bytes=len(application_receipt_bytes),
                producer_identity=ATTENTION_REPAIR_PRODUCER_IDENTITY,
                producer_invocation_id=producer_invocation_id,
            )
        ]
        if events
        else []
    )
    unsigned = {
        "schema_version": LEDGER_SCHEMA,
        "phase": ATTENTION_REPAIR_PHASE,
        "methodology_path": ATTENTION_REPAIR_PLAN_ARTIFACT,
        "methodology_sha256": plan_sha,
        "source_artifacts": source_artifacts,
        "status": "CLEAN",
        "issues": [],
        "families": families,
        "event_count": len(events),
        "events": events,
        "attention_authority_binding": binding,
    }
    ledger = {**unsigned, "ledger_digest": _digest(unsigned)}
    validate_candidate_negative_ledger(ledger)
    return ledger


def validate_attention_repair_candidate_negative_ledger(
    ledger: Any,
    *,
    queue_bytes: bytes,
    plan_bytes: bytes,
    application_receipt_bytes: bytes,
) -> None:
    """Replay exact typed inputs and reject any adapted-ledger mutation."""

    validate_candidate_negative_ledger(ledger)
    expected = build_attention_repair_candidate_negative_ledger(
        queue_bytes=queue_bytes,
        plan_bytes=plan_bytes,
        application_receipt_bytes=application_receipt_bytes,
    )
    if ledger != expected:
        raise CandidateNegativeAuthorityError(
            "attention candidate-negative typed adapter projection mismatch"
        )


def _attention_repair_authority_bytes(
    scratchpad: Path,
) -> tuple[bytes, bytes, bytes]:
    root = Path(scratchpad)
    names = (
        ATTENTION_REPAIR_QUEUE_ARTIFACT,
        ATTENTION_REPAIR_PLAN_ARTIFACT,
        ATTENTION_REPAIR_APPLICATION_ARTIFACT,
    )
    captured: list[bytes] = []
    for name in names:
        path = root / name
        try:
            if path.is_symlink() or not path.is_file():
                raise OSError("not one regular file")
            with path.open("rb") as handle:
                before = os.fstat(handle.fileno())
                raw = handle.read()
                after = os.fstat(handle.fileno())
            current = path.stat()
            identity = lambda row: (  # noqa: E731 - immutable stat projection
                row.st_dev,
                row.st_ino,
                row.st_size,
                row.st_mtime_ns,
                row.st_ctime_ns,
            )
            if (
                identity(before) != identity(after)
                or identity(after) != identity(current)
            ):
                raise OSError("changed during exact-byte capture")
        except OSError as exc:
            raise CandidateNegativeAuthorityError(
                f"attention candidate-negative {name} is unavailable: {exc}"
            ) from exc
        captured.append(raw)
    return captured[0], captured[1], captured[2]


def build_attention_repair_candidate_negative_ledger_from_scratchpad(
    scratchpad: Path,
) -> dict[str, Any]:
    """Thin driver adapter over exact sibling authority files."""

    queue, plan, receipt = _attention_repair_authority_bytes(scratchpad)
    return build_attention_repair_candidate_negative_ledger(
        queue_bytes=queue,
        plan_bytes=plan,
        application_receipt_bytes=receipt,
    )


def validate_attention_repair_candidate_negative_ledger_from_scratchpad(
    ledger: Any,
    *,
    scratchpad: Path,
) -> None:
    """Replay a committed typed adapter ledger from its exact siblings."""

    queue, plan, receipt = _attention_repair_authority_bytes(scratchpad)
    validate_attention_repair_candidate_negative_ledger(
        ledger,
        queue_bytes=queue,
        plan_bytes=plan,
        application_receipt_bytes=receipt,
    )


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
                    "candidate_terminal_requested_effect": (
                        "OUT_OF_SCOPE"
                        if proposed == ["NOT_APPLICABLE_PROPOSAL"]
                        else "REFUTED_FULL"
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
                requested_effect = (
                    "OUT_OF_SCOPE"
                    if proposed == {"NOT_APPLICABLE_PROPOSAL"}
                    else "REFUTED_FULL"
                )
                authorized, policy_reason = terminal_negative_authorized(
                    work_item=item,
                    assessment=assessment,
                    authority=(closure_authorities or {}).get(work_id),
                    provider_validator=closure_provider_validator,
                    closure_authority=closure_authority,
                    requested_effect=requested_effect,
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


_PROMPT_PROHIBITION_RE = re.compile(
    r"(?i)\b(?:never|not|no|non|forbidden|prohibit(?:ed|s)?|disallow(?:ed|s)?|"
    r"ban(?:ned)?|must\s+not|do\s+not|don't|avoid|reject(?:ed|s)?|"
    r"excluded?|instead\s+of|rather\s+than)\b"
)


def validate_generator_prompt_negative_contract(prompt: str, *, phase: str) -> None:
    """Reject a rendered generator schema that GRANTS terminal-negative authority.

    Property: `disposition.generator_grant` -- does this contract line hand a
    discovery worker terminal-negative authority?  FAIL_CLOSED, and now read
    from the NORMALIZED logical line:

    * soft wraps are joined before matching, so moving a prohibition onto the
      next physical line no longer turns it into a grant (and no longer denies
      the phase launch over a template re-wrap);
    * a line that PROHIBITS the terminal vocabulary
      (``Verdicts: REFUTATION_PROPOSAL, UNRESOLVED (never SAFE)``) is a
      prohibition, not a grant;
    * a heading is not an enum contract line.

    Negative words in prohibitions/explanations remain legal.  Verifiers and
    independent discriminators are terminal consumers and therefore exempt.
    """

    phase_n = _text(phase).casefold()
    if phase_n.startswith("verify") or phase_n in {
        "application_skeptic",
        "skeptic_judge",
        "report_index",
    }:
        return
    violations: list[int] = []
    for line in AS.surface(prompt or "").lines:
        if line.kind == "HEADING" or line.heading_level:
            continue
        match = _GENERATOR_CONTRACT_LINE_RE.match(line.text)
        if not match:
            continue
        grant = match.group(1)
        if not _TERMINAL_PROMPT_RE.search(grant):
            continue
        if _PROMPT_PROHIBITION_RE.search(grant):
            # The line names the terminal vocabulary in order to FORBID it.
            continue
        violations.append(line.physical_start)
    if violations:
        raise CandidateNegativeAuthorityError(
            "generator prompt grants terminal-negative authority at line(s): "
            + ", ".join(str(ordinal) for ordinal in sorted(set(violations)))
        )


__all__ = [
    "ArtifactInput",
    "APPLICATION_PLAN_SCHEMA",
    "ATTENTION_REPAIR_ADAPTER_SCHEMA",
    "ATTENTION_REPAIR_APPLICATION_ARTIFACT",
    "ATTENTION_REPAIR_PHASE",
    "ATTENTION_REPAIR_PLAN_ARTIFACT",
    "ATTENTION_REPAIR_PRODUCER_IDENTITY",
    "ATTENTION_REPAIR_QUEUE_ARTIFACT",
    "AXIS_CLEAR_ADAPTER_SCHEMA",
    "AXIS_CLEAR_PHASE",
    "CANDIDATE_PLAN_FILE",
    "CANDIDATE_DENOMINATOR_FILE",
    "CANDIDATE_PLANNING_DEBT_FILE",
    "candidate_negative_planning_debt_bytes",
    "validate_candidate_negative_planning_debt",
    "CANDIDATE_NEGATIVE_SKILL",
    "CandidateNegativeAuthorityError",
    "CANDIDATE_NEGATIVE_STAGED_CONTEXT_SCHEMA",
    "DEPTH_CANDIDATE_NEGATIVE_STAGED_CONTEXT_SCHEMA",
    "LEDGER_PREFIX",
    "LEDGER_SCHEMA",
    "build_candidate_negative_ledger",
    "candidate_negative_check_result",
    "build_attention_repair_candidate_negative_ledger",
    "build_attention_repair_candidate_negative_ledger_from_scratchpad",
    "build_axis_clear_candidate_negative_ledger",
    "build_candidate_negative_application_plan",
    "compile_depth_candidate_negative_staged_context",
    "compile_candidate_negative_staged_context",
    "evaluate_staged_depth_candidate_negative_receipt",
    "evaluate_staged_candidate_negative_receipt",
    "adjudicate_candidate_negative",
    "staged_depth_candidate_negative_receipt_validator",
    "staged_candidate_negative_receipt_validator",
    "validate_candidate_negative_denominator",
    "write_candidate_negative_denominator",
    "validate_candidate_negative_ledger",
    "validate_attention_repair_candidate_negative_ledger",
    "validate_attention_repair_candidate_negative_ledger_from_scratchpad",
    "validate_axis_clear_candidate_negative_ledger",
    "validate_generator_prompt_negative_contract",
    "write_candidate_negative_ledger",
    "write_axis_clear_candidate_negative_ledger",
    "write_candidate_negative_application_plan",
]
