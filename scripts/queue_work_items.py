"""Typed queue work-item substrate for P0-AJ.

This module deliberately has no driver or filesystem dependencies.  It makes
the typed record authoritative, treats verifier filenames as computed output,
and exposes pure JSON, Markdown-projection, lineage, and partition checks for
later integration at the queue/shard boundary.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
import hashlib
import json
import re
from types import MappingProxyType
from typing import Any, Iterable, Mapping, Sequence

from finding_producer_registry import (
    EFFECTIVE_EVIDENCE_SCOPES,
    EFFECTIVE_HARM_SCOPES,
    EFFECTIVE_PROOF_SCOPES,
    normalize_evidence_scope,
    normalize_harm_scope,
    normalize_proof_scope,
)


QUEUE_SCHEMA_VERSION = "plamen.queue_work_item.v4"
QUEUE_RECORD_SET_SCHEMA_VERSION = "plamen.queue_work_items.v4"
_V3_QUEUE_SCHEMA_VERSION = "plamen.queue_work_item.v3"
_V3_QUEUE_RECORD_SET_SCHEMA_VERSION = "plamen.queue_work_items.v3"
_LEGACY_QUEUE_SCHEMA_VERSION = "plamen.queue_work_item.v2"
_LEGACY_QUEUE_RECORD_SET_SCHEMA_VERSION = "plamen.queue_work_items.v2"
QUEUE_WORK_PLAN_SCHEMA_VERSION = "plamen.queue_work_plan.v1"
QUEUE_WORK_SHARD_SCHEMA_VERSION = "plamen.queue_work_shard.v1"
OUTPUT_OWNERSHIP_SCHEMA_VERSION = "plamen.output_ownership.v1"
VERIFIER_OUTPUT_IDENTITY_SCHEMA_VERSION = "plamen.verifier_output_identity.v1"
VERIFIER_OUTPUT_RECEIPT_SCHEMA_VERSION = "plamen.verifier_output_receipt.v2"
EXCLUSION_DISPOSITION_SCHEMA_VERSION = "plamen.exclusion_disposition.v1"
REQUIRED_DISPOSITIONS = frozenset({"STANDARD", "VERIFY_INDEPENDENTLY"})

MARKDOWN_HEADERS = (
    "Work Item ID",
    "Candidate Identity",
    "Identity Lineage",
    "Severity Proposal",
    "Evidence Class",
    "Location Records",
    "Primary Artifacts",
    "PoC Class",
    "Title",
    "Expected Output File",
)

_ITEM_KEYS = frozenset(
    {
        "schema_version",
        "candidate_identity",
        "work_item_id",
        "lineage",
        "aliases",
        "constituents",
        "severity_proposal",
        "evidence_class",
        "bug_class",
        "preferred_tag",
        "queue_priority",
        "location_records",
        "primary_artifacts",
        "poc_class",
        "title",
        "effective_evidence_scope",
        "effective_proof_scope",
        "effective_harm_scope",
        "required_disposition",
        "expected_output_file",
    }
)
_V3_ITEM_KEYS = frozenset(
    _ITEM_KEYS - {"required_disposition"}
)
_LEGACY_ITEM_KEYS = frozenset(
    _V3_ITEM_KEYS
    - {
        "effective_evidence_scope",
        "effective_proof_scope",
        "effective_harm_scope",
    }
)
_LINEAGE_KEYS = frozenset(
    {"identity", "relation", "parent_identity", "source_artifact"}
)
_LOCATION_KEYS = frozenset(
    {"artifact", "start_line", "end_line", "symbol", "note"}
)
_SEVERITY_KEYS = frozenset(
    {"level", "impact", "likelihood", "rationale"}
)
_RECORD_SET_KEYS = frozenset(
    {"schema_version", "record_count", "record_set_digest", "rows"}
)
_IDENTITY_CELL_KEYS = frozenset(
    {"lineage", "aliases", "constituents", "queue_priority"}
)
_CLASSIFICATION_CELL_KEYS = frozenset(
    {
        "evidence_class",
        "bug_class",
        "preferred_tag",
        "effective_evidence_scope",
        "effective_proof_scope",
        "effective_harm_scope",
        "required_disposition",
    }
)
_OUTPUT_OWNERSHIP_KEYS = frozenset(
    {
        "schema_version",
        "work_item_id",
        "work_item_digest",
        "expected_output_file",
        "expected_output_identity",
    }
)
_WORK_SHARD_KEYS = frozenset(
    {
        "schema_version",
        "shard_id",
        "ordered_work_item_ids",
        "shard_record_digest",
        "projection_digest",
        "output_ownership",
    }
)
_WORK_PLAN_KEYS = frozenset(
    {
        "schema_version",
        "planner_version",
        "parent_record_set_digest",
        "ordered_work_item_ids",
        "shards",
        "work_plan_digest",
    }
)
_VERIFIER_OUTPUT_IDENTITY_KEYS = frozenset(
    {
        "schema_version",
        "work_item_id",
        "queue_record_digest",
        "work_plan_digest",
        "shard_id",
        "expected_output_file",
        "expected_output_identity",
    }
)
_VERIFIER_OUTPUT_RECEIPT_KEYS = frozenset(
    {
        "schema_version",
        "identity",
        "output_sha256",
        "output_size_bytes",
        "severity_proposal_file",
        "severity_proposal_sha256",
        "severity_proposal_size_bytes",
        "launch_digest",
        "verifier_backend",
        "receipt_digest",
    }
)
_EXCLUSION_DISPOSITION_KEYS = frozenset(
    {
        "schema_version",
        "identity",
        "status",
        "reason_class",
        "reason",
        "authority",
        "evidence_ids",
        "next_action",
        "public_retention_target",
        "disposition_digest",
    }
)

_SAFE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$", re.ASCII)
_CLASS_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$", re.ASCII)
_HEX_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
_SEVERITIES = frozenset({"Critical", "High", "Medium", "Low", "Informational"})
_LINEAGE_RELATIONS = frozenset(
    {
        "ORIGIN",
        "RELABEL",
        "GROUP",
        "SPLIT",
        "PROMOTION",
        "ALIAS",
        "CONSTITUENT",
        "SOURCE",
        "MIGRATION_DEBT",
    }
)


class MarkdownProjectionError(ValueError):
    """A Markdown queue projection cannot be parsed without guessing."""


def _require_exact_keys(
    value: Mapping[str, Any], expected: frozenset[str], context: str
) -> None:
    if not isinstance(value, Mapping):
        raise TypeError(f"{context} must be an object")
    actual = set(value)
    missing = sorted(expected - actual)
    extra = sorted(actual - expected)
    parts: list[str] = []
    if missing:
        parts.append(f"missing fields: {', '.join(missing)}")
    if extra:
        parts.append(f"unexpected fields: {', '.join(extra)}")
    if parts:
        raise ValueError(f"{context} " + "; ".join(parts))


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise ValueError(f"duplicate JSON object key: {key}")
        out[key] = value
    return out


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"invalid JSON constant: {value}")


def _strict_json_loads(text: str) -> Any:
    if not isinstance(text, str):
        raise TypeError("JSON input must be text")
    return json.loads(
        text,
        object_pairs_hook=_strict_object,
        parse_constant=_reject_json_constant,
    )


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


def _safe_identity(value: str, field: str) -> str:
    if not isinstance(value, str) or not _SAFE_ID_RE.fullmatch(value):
        raise ValueError(
            f"{field} must be a filename-safe identity containing only "
            "ASCII letters, digits, dot, underscore, or hyphen"
        )
    if value in {".", ".."}:
        raise ValueError(f"{field} cannot be a path segment")
    return value


def _optional_text(value: Any, field: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise TypeError(f"{field} must be text or null")
    return value


def _text(value: Any, field: str, *, nonempty: bool = False) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{field} must be text")
    if nonempty and not value:
        raise ValueError(f"{field} cannot be empty")
    return value


def _integer_or_none(value: Any, field: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{field} must be an integer or null")
    return value


def _nonnegative_integer(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{field} must be a non-negative integer")
    if value < 0:
        raise ValueError(f"{field} must be a non-negative integer")
    return value


def _sha256_digest(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _HEX_DIGEST_RE.fullmatch(value):
        raise ValueError(f"{field} must be a lowercase SHA-256 digest")
    return value


def _sha256_bytes(value: bytes) -> str:
    if not isinstance(value, bytes):
        raise TypeError("verifier output must be bytes")
    return hashlib.sha256(value).hexdigest()


def _identity_tuple(values: Iterable[str], field: str) -> tuple[str, ...]:
    result = tuple(_safe_identity(value, field) for value in values)
    if len(set(result)) != len(result):
        raise ValueError(f"{field} contains duplicate identities")
    return result


def _text_tuple(
    values: Iterable[str], field: str, *, require_nonempty_items: bool = True
) -> tuple[str, ...]:
    result = tuple(_text(value, field, nonempty=require_nonempty_items) for value in values)
    if len(set(result)) != len(result):
        raise ValueError(f"{field} contains duplicate values")
    return result


@dataclass(frozen=True, slots=True)
class LineageLink:
    """One explicit identity transition in a candidate family's history."""

    identity: str
    relation: str
    parent_identity: str | None = None
    source_artifact: str | None = None

    def __post_init__(self) -> None:
        _safe_identity(self.identity, "lineage.identity")
        if self.relation not in _LINEAGE_RELATIONS:
            raise ValueError(
                "lineage.relation must be one of "
                + ", ".join(sorted(_LINEAGE_RELATIONS))
            )
        if self.parent_identity is not None:
            _safe_identity(self.parent_identity, "lineage.parent_identity")
        if self.source_artifact is not None:
            _text(self.source_artifact, "lineage.source_artifact", nonempty=True)

    def to_dict(self) -> dict[str, Any]:
        return {
            "identity": self.identity,
            "relation": self.relation,
            "parent_identity": self.parent_identity,
            "source_artifact": self.source_artifact,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "LineageLink":
        _require_exact_keys(value, _LINEAGE_KEYS, "lineage link")
        return cls(
            identity=_text(value["identity"], "lineage.identity", nonempty=True),
            relation=_text(value["relation"], "lineage.relation", nonempty=True),
            parent_identity=_optional_text(
                value["parent_identity"], "lineage.parent_identity"
            ),
            source_artifact=_optional_text(
                value["source_artifact"], "lineage.source_artifact"
            ),
        )


@dataclass(frozen=True, slots=True)
class LocationRecord:
    """A lossless source location; paths remain ecosystem/OS-native text."""

    artifact: str
    start_line: int | None = None
    end_line: int | None = None
    symbol: str | None = None
    note: str | None = None

    def __post_init__(self) -> None:
        _text(self.artifact, "location.artifact", nonempty=True)
        _integer_or_none(self.start_line, "location.start_line")
        _integer_or_none(self.end_line, "location.end_line")
        if self.start_line is not None and self.start_line < 1:
            raise ValueError("location.start_line must be at least 1")
        if self.end_line is not None and self.end_line < 1:
            raise ValueError("location.end_line must be at least 1")
        if self.end_line is not None and self.start_line is None:
            raise ValueError("location.end_line requires start_line")
        if (
            self.start_line is not None
            and self.end_line is not None
            and self.end_line < self.start_line
        ):
            raise ValueError("location.end_line cannot precede start_line")
        _optional_text(self.symbol, "location.symbol")
        _optional_text(self.note, "location.note")

    def to_dict(self) -> dict[str, Any]:
        return {
            "artifact": self.artifact,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "symbol": self.symbol,
            "note": self.note,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "LocationRecord":
        _require_exact_keys(value, _LOCATION_KEYS, "location record")
        return cls(
            artifact=_text(value["artifact"], "location.artifact", nonempty=True),
            start_line=_integer_or_none(value["start_line"], "location.start_line"),
            end_line=_integer_or_none(value["end_line"], "location.end_line"),
            symbol=_optional_text(value["symbol"], "location.symbol"),
            note=_optional_text(value["note"], "location.note"),
        )


@dataclass(frozen=True, slots=True)
class SeverityProposal:
    """Upstream severity is a proposal, never a verifier disposition."""

    level: str
    impact: str | None = None
    likelihood: str | None = None
    rationale: str | None = None

    def __post_init__(self) -> None:
        if self.level not in _SEVERITIES:
            raise ValueError(
                "severity.level must be one of " + ", ".join(sorted(_SEVERITIES))
            )
        _optional_text(self.impact, "severity.impact")
        _optional_text(self.likelihood, "severity.likelihood")
        _optional_text(self.rationale, "severity.rationale")

    def to_dict(self) -> dict[str, Any]:
        return {
            "level": self.level,
            "impact": self.impact,
            "likelihood": self.likelihood,
            "rationale": self.rationale,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "SeverityProposal":
        _require_exact_keys(value, _SEVERITY_KEYS, "severity proposal")
        return cls(
            level=_text(value["level"], "severity.level", nonempty=True),
            impact=_optional_text(value["impact"], "severity.impact"),
            likelihood=_optional_text(value["likelihood"], "severity.likelihood"),
            rationale=_optional_text(value["rationale"], "severity.rationale"),
        )


def _coerce_lineage(values: Iterable[LineageLink]) -> tuple[LineageLink, ...]:
    result = tuple(values)
    if not result:
        raise ValueError("lineage must contain at least one link")
    if not all(isinstance(value, LineageLink) for value in result):
        raise TypeError("lineage entries must be LineageLink records")
    return result


def _coerce_locations(values: Iterable[LocationRecord]) -> tuple[LocationRecord, ...]:
    result = tuple(values)
    if not all(isinstance(value, LocationRecord) for value in result):
        raise TypeError("location_records entries must be LocationRecord records")
    return result


@dataclass(frozen=True, slots=True)
class QueueWorkItem:
    """Authoritative immutable verification work item.

    ``expected_output_file`` is intentionally not a constructor field.  It is
    computed only from ``work_item_id``; aliases and lineage can participate in
    joins but can never select an executable filename.
    """

    candidate_identity: str
    work_item_id: str
    lineage: tuple[LineageLink, ...]
    aliases: tuple[str, ...]
    constituents: tuple[str, ...]
    severity_proposal: SeverityProposal
    evidence_class: str
    bug_class: str
    preferred_tag: str
    queue_priority: int
    location_records: tuple[LocationRecord, ...]
    primary_artifacts: tuple[str, ...]
    poc_class: str
    title: str = ""
    effective_evidence_scope: str = "UNSPECIFIED"
    effective_proof_scope: str = "ANALYTICAL"
    effective_harm_scope: str = "UNPROVEN"
    required_disposition: str = "STANDARD"

    def __post_init__(self) -> None:
        _safe_identity(self.candidate_identity, "candidate_identity")
        _safe_identity(self.work_item_id, "work_item_id")
        lineage = _coerce_lineage(self.lineage)
        aliases = _identity_tuple(self.aliases, "aliases")
        constituents = _identity_tuple(self.constituents, "constituents")
        locations = _coerce_locations(self.location_records)
        artifacts = _text_tuple(self.primary_artifacts, "primary_artifacts")
        if not isinstance(self.severity_proposal, SeverityProposal):
            raise TypeError("severity_proposal must be a SeverityProposal")
        if not isinstance(self.evidence_class, str) or not _CLASS_RE.fullmatch(
            self.evidence_class
        ):
            raise ValueError("evidence_class must be a non-empty class token")
        _text(self.bug_class, "bug_class", nonempty=True)
        _text(self.preferred_tag, "preferred_tag", nonempty=True)
        _nonnegative_integer(self.queue_priority, "queue_priority")
        if not isinstance(self.poc_class, str) or not _CLASS_RE.fullmatch(self.poc_class):
            raise ValueError("poc_class must be a non-empty class token")
        _text(self.title, "title")
        if self.effective_evidence_scope not in EFFECTIVE_EVIDENCE_SCOPES:
            raise ValueError("effective_evidence_scope is outside the closed vocabulary")
        if self.effective_proof_scope not in EFFECTIVE_PROOF_SCOPES:
            raise ValueError("effective_proof_scope is outside the closed vocabulary")
        if self.effective_harm_scope not in EFFECTIVE_HARM_SCOPES:
            raise ValueError("effective_harm_scope is outside the closed vocabulary")
        if self.required_disposition not in REQUIRED_DISPOSITIONS:
            raise ValueError(
                "required_disposition is outside the closed vocabulary"
            )
        if (
            self.effective_proof_scope != "HARM"
            and self.effective_harm_scope == "MATERIAL_HARM"
        ):
            raise ValueError(
                "MATERIAL_HARM requires effective_proof_scope HARM"
            )
        lineage_ids = {link.identity for link in lineage}
        if self.candidate_identity not in lineage_ids:
            raise ValueError("lineage must contain candidate_identity")
        if self.work_item_id not in lineage_ids:
            raise ValueError("lineage must contain work_item_id")
        if self.work_item_id in aliases:
            raise ValueError("aliases cannot repeat the current work_item_id")
        if self.work_item_id in constituents:
            raise ValueError("constituents cannot repeat the current work_item_id")
        object.__setattr__(self, "lineage", lineage)
        object.__setattr__(self, "aliases", aliases)
        object.__setattr__(self, "constituents", constituents)
        object.__setattr__(self, "location_records", locations)
        object.__setattr__(self, "primary_artifacts", artifacts)

    @property
    def expected_output_file(self) -> str:
        return f"verify_{self.work_item_id}.md"

    @property
    def expected_output_identity(self) -> str:
        return f"scratchpad:{self.expected_output_file}"

    @property
    def digest(self) -> str:
        return _digest(self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": QUEUE_SCHEMA_VERSION,
            "candidate_identity": self.candidate_identity,
            "work_item_id": self.work_item_id,
            "lineage": [link.to_dict() for link in self.lineage],
            "aliases": list(self.aliases),
            "constituents": list(self.constituents),
            "severity_proposal": self.severity_proposal.to_dict(),
            "evidence_class": self.evidence_class,
            "bug_class": self.bug_class,
            "preferred_tag": self.preferred_tag,
            "queue_priority": self.queue_priority,
            "location_records": [location.to_dict() for location in self.location_records],
            "primary_artifacts": list(self.primary_artifacts),
            "poc_class": self.poc_class,
            "title": self.title,
            "effective_evidence_scope": self.effective_evidence_scope,
            "effective_proof_scope": self.effective_proof_scope,
            "effective_harm_scope": self.effective_harm_scope,
            "required_disposition": self.required_disposition,
            "expected_output_file": self.expected_output_file,
        }

    def to_json(self) -> str:
        return _canonical_json(self.to_dict())

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "QueueWorkItem":
        schema = value.get("schema_version") if isinstance(value, Mapping) else None
        expected_keys = {
            _LEGACY_QUEUE_SCHEMA_VERSION: _LEGACY_ITEM_KEYS,
            _V3_QUEUE_SCHEMA_VERSION: _V3_ITEM_KEYS,
            QUEUE_SCHEMA_VERSION: _ITEM_KEYS,
        }.get(schema, _ITEM_KEYS)
        _require_exact_keys(value, expected_keys, "queue work item")
        if schema not in {
            QUEUE_SCHEMA_VERSION,
            _V3_QUEUE_SCHEMA_VERSION,
            _LEGACY_QUEUE_SCHEMA_VERSION,
        }:
            raise ValueError(
                f"unsupported queue work item schema_version: {value['schema_version']!r}"
            )
        for field in ("lineage", "aliases", "constituents", "location_records", "primary_artifacts"):
            if not isinstance(value[field], list):
                raise TypeError(f"{field} must be a JSON array")
        if not isinstance(value["severity_proposal"], Mapping):
            raise TypeError("severity_proposal must be a JSON object")
        item = cls(
            candidate_identity=_text(
                value["candidate_identity"], "candidate_identity", nonempty=True
            ),
            work_item_id=_text(value["work_item_id"], "work_item_id", nonempty=True),
            lineage=tuple(LineageLink.from_dict(link) for link in value["lineage"]),
            aliases=tuple(value["aliases"]),
            constituents=tuple(value["constituents"]),
            severity_proposal=SeverityProposal.from_dict(value["severity_proposal"]),
            evidence_class=_text(
                value["evidence_class"], "evidence_class", nonempty=True
            ),
            bug_class=_text(value["bug_class"], "bug_class", nonempty=True),
            preferred_tag=_text(
                value["preferred_tag"], "preferred_tag", nonempty=True
            ),
            queue_priority=_nonnegative_integer(
                value["queue_priority"], "queue_priority"
            ),
            location_records=tuple(
                LocationRecord.from_dict(location) for location in value["location_records"]
            ),
            primary_artifacts=tuple(value["primary_artifacts"]),
            poc_class=_text(value["poc_class"], "poc_class", nonempty=True),
            title=_text(value["title"], "title"),
            effective_evidence_scope=(
                normalize_evidence_scope(value["effective_evidence_scope"])
                if schema in {QUEUE_SCHEMA_VERSION, _V3_QUEUE_SCHEMA_VERSION}
                else "UNSPECIFIED"
            ),
            effective_proof_scope=(
                normalize_proof_scope(value["effective_proof_scope"])
                if schema in {QUEUE_SCHEMA_VERSION, _V3_QUEUE_SCHEMA_VERSION}
                else "ANALYTICAL"
            ),
            effective_harm_scope=(
                normalize_harm_scope(value["effective_harm_scope"])
                if schema in {QUEUE_SCHEMA_VERSION, _V3_QUEUE_SCHEMA_VERSION}
                else "UNPROVEN"
            ),
            required_disposition=(
                _text(
                    value["required_disposition"],
                    "required_disposition",
                    nonempty=True,
                )
                if schema == QUEUE_SCHEMA_VERSION
                else "STANDARD"
            ),
        )
        expected = _text(
            value["expected_output_file"], "expected_output_file", nonempty=True
        )
        if expected != item.expected_output_file:
            raise ValueError(
                "expected_output_file must be the computed current-ID projection "
                f"{item.expected_output_file!r}, got {expected!r}"
            )
        return item

    @classmethod
    def from_json(cls, text: str) -> "QueueWorkItem":
        value = _strict_json_loads(text)
        if not isinstance(value, Mapping):
            raise TypeError("queue work item JSON must contain an object")
        return cls.from_dict(value)

    @classmethod
    def from_legacy_row(cls, row: Mapping[str, Any]) -> "QueueWorkItem":
        """Losslessly promote one legacy row while rejecting filename authority.

        A stale ``verify_INV-*.md`` contributes an alias/candidate lineage
        record only.  The returned filename is always recomputed from the row's
        current finding identity.
        """

        if not isinstance(row, Mapping):
            raise TypeError("legacy queue row must be an object")
        current = _text(row.get("finding id", ""), "finding id", nonempty=True)
        _safe_identity(current, "finding id")
        stale_identity: str | None = None
        old_output = row.get("expected output file")
        if old_output:
            old_output = _text(old_output, "expected output file", nonempty=True)
            match = re.fullmatch(r"verify_([A-Za-z0-9][A-Za-z0-9_.-]{0,127})\.md", old_output)
            if not match:
                raise ValueError("legacy expected output file is not a safe verifier filename")
            stale_identity = match.group(1)

        explicit_candidate: Any = None
        explicit_candidate_field = "candidate identity"
        for field in (
            "candidate identity",
            "source identity",
            "candidate id",
            "source id",
        ):
            if row.get(field):
                explicit_candidate = row[field]
                explicit_candidate_field = field
                break
        candidate = (
            _text(
                explicit_candidate,
                explicit_candidate_field,
                nonempty=True,
            )
            if explicit_candidate is not None
            else current
        )
        _safe_identity(candidate, "candidate identity")

        def legacy_ids(value: Any, field: str) -> tuple[str, ...]:
            if value is None or value == "":
                return ()
            if isinstance(value, (list, tuple)):
                return _identity_tuple(value, field)
            text_value = _text(value, field, nonempty=True)
            return _identity_tuple(
                (part for part in re.split(r"[,;|\s]+", text_value) if part),
                field,
            )

        aliases = list(legacy_ids(row.get("aliases"), "aliases"))
        for identity in (stale_identity, candidate):
            if identity and identity != current and identity not in aliases:
                aliases.append(identity)
        constituents = legacy_ids(row.get("constituents"), "constituents")

        lineage: list[LineageLink] = [
            LineageLink(
                identity=candidate,
                relation="ORIGIN",
                source_artifact="legacy-verification-queue",
            )
        ]
        if current != candidate:
            lineage.append(
                LineageLink(
                    identity=current,
                    relation="RELABEL",
                    parent_identity=candidate,
                    source_artifact="legacy-verification-queue",
                )
            )
        if stale_identity and stale_identity != current:
            lineage.append(
                LineageLink(
                    identity=stale_identity,
                    relation="MIGRATION_DEBT",
                    parent_identity=current,
                    source_artifact="legacy-expected-output-file",
                )
            )
        for constituent in constituents:
            if constituent == current:
                continue
            lineage.append(
                LineageLink(
                    identity=constituent,
                    relation="CONSTITUENT",
                    parent_identity=current,
                    source_artifact="legacy-verification-queue",
                )
            )

        level_raw = str(row.get("severity", "Medium") or "Medium").strip()
        level_aliases = {
            "critical": "Critical",
            "high": "High",
            "medium": "Medium",
            "low": "Low",
            "info": "Informational",
            "informational": "Informational",
        }
        level = level_aliases.get(level_raw.casefold(), level_raw)
        location_text = str(row.get("location", "") or "")
        locations = (
            (LocationRecord(artifact=location_text),) if location_text else ()
        )
        artifact_value = row.get("primary artifact", "")
        if isinstance(artifact_value, (list, tuple)):
            artifacts = tuple(str(value) for value in artifact_value if str(value))
        else:
            artifact_text = str(artifact_value or "")
            artifacts = (artifact_text,) if artifact_text else ()
        evidence_class = str(row.get("evidence class") or "unclassified").strip()
        evidence_class = re.sub(r"[^A-Za-z0-9_.-]+", "-", evidence_class).strip("-")
        if not evidence_class:
            evidence_class = "unclassified"
        bug_class = str(row.get("bug class") or "unclassified").strip()
        if not bug_class:
            bug_class = "unclassified"
        preferred_tag = str(
            row.get("preferred tag")
            or row.get("evidence tag")
            or "CODE-TRACE"
        ).strip()
        if not preferred_tag:
            preferred_tag = "CODE-TRACE"
        required_raw = str(
            row.get("required disposition")
            or row.get("required_disposition")
            or ""
        ).strip().upper().replace("-", "_").replace(" ", "_")
        relation_raw = str(
            row.get("relation kind")
            or row.get("relation_kind")
            or ""
        ).strip().upper().replace("-", "_").replace(" ", "_")
        if not required_raw:
            required_disposition = (
                "VERIFY_INDEPENDENTLY"
                if relation_raw == "ENABLER_CONSTITUENT"
                else "STANDARD"
            )
        elif required_raw in REQUIRED_DISPOSITIONS:
            required_disposition = required_raw
        else:
            raise ValueError(
                "required_disposition is outside the closed vocabulary"
            )
        priority_raw = row.get("queue #", row.get("queue priority", 0))
        try:
            queue_priority = int(str(priority_raw or "0").strip())
        except (TypeError, ValueError):
            queue_priority = 0
        if queue_priority < 0:
            queue_priority = 0
        poc_class = str(row.get("poc class", "structural") or "structural").strip()
        poc_class = re.sub(r"[^A-Za-z0-9_.-]+", "-", poc_class).strip("-")
        if not poc_class:
            poc_class = "structural"
        return cls(
            candidate_identity=candidate,
            work_item_id=current,
            lineage=tuple(lineage),
            aliases=tuple(aliases),
            constituents=constituents,
            severity_proposal=SeverityProposal(level=level),
            evidence_class=evidence_class,
            bug_class=bug_class,
            preferred_tag=preferred_tag,
            queue_priority=queue_priority,
            location_records=locations,
            primary_artifacts=artifacts,
            poc_class=poc_class,
            title=str(row.get("title", "") or ""),
            effective_evidence_scope=normalize_evidence_scope(
                row.get("effective evidence scope", "")
            ),
            effective_proof_scope=normalize_proof_scope(
                row.get("effective proof scope", "")
            ),
            effective_harm_scope=normalize_harm_scope(
                row.get("effective harm scope", "")
            ),
            required_disposition=required_disposition,
        )


def validate_queue_work_items(
    items: Iterable[QueueWorkItem],
) -> tuple[QueueWorkItem, ...]:
    """Validate queue-wide identity and output ownership invariants."""

    records = tuple(items)
    if not all(isinstance(item, QueueWorkItem) for item in records):
        raise TypeError("queue contains a non-QueueWorkItem value")
    seen_ids: set[str] = set()
    seen_outputs: dict[str, str] = {}
    for item in records:
        if item.work_item_id in seen_ids:
            raise ValueError(f"duplicate work_item_id: {item.work_item_id}")
        seen_ids.add(item.work_item_id)
        output_key = item.expected_output_file.casefold()
        if output_key in seen_outputs:
            raise ValueError(
                "output filename collision between "
                f"{seen_outputs[output_key]} and {item.work_item_id}: "
                f"{item.expected_output_file}"
            )
        seen_outputs[output_key] = item.work_item_id
    return records


@dataclass(frozen=True, slots=True)
class QueueLineageIndex:
    """Immutable many-to-one identity-to-current-work-item join index."""

    entries: tuple[tuple[str, tuple[str, ...]], ...]

    def resolve_all(self, identity: str) -> tuple[str, ...]:
        _safe_identity(identity, "lineage lookup identity")
        for key, values in self.entries:
            if key == identity:
                return values
        return ()

    def require_unique(self, identity: str) -> str:
        values = self.resolve_all(identity)
        if len(values) != 1:
            raise ValueError(
                f"lineage identity {identity!r} resolves to {len(values)} work items"
            )
        return values[0]

    def as_mapping(self) -> Mapping[str, tuple[str, ...]]:
        return MappingProxyType(dict(self.entries))


def build_lineage_index(items: Iterable[QueueWorkItem]) -> QueueLineageIndex:
    records = validate_queue_work_items(items)
    index: dict[str, set[str]] = defaultdict(set)
    for item in records:
        identities = {
            item.candidate_identity,
            item.work_item_id,
            *item.aliases,
            *item.constituents,
            *(link.identity for link in item.lineage),
            *(link.parent_identity for link in item.lineage if link.parent_identity),
        }
        for identity in identities:
            index[identity].add(item.work_item_id)
    return QueueLineageIndex(
        tuple(
            (identity, tuple(sorted(work_ids, key=lambda value: (value.casefold(), value))))
            for identity, work_ids in sorted(index.items(), key=lambda pair: (pair[0].casefold(), pair[0]))
        )
    )


def _sorted_records(items: Iterable[QueueWorkItem]) -> tuple[QueueWorkItem, ...]:
    records = validate_queue_work_items(items)
    return tuple(
        sorted(
            records,
            key=lambda item: (
                item.queue_priority,
                item.work_item_id.casefold(),
                item.work_item_id,
            ),
        )
    )


def queue_record_set_digest(items: Iterable[QueueWorkItem]) -> str:
    records = _sorted_records(items)
    return _digest([item.to_dict() for item in records])


def queue_records_to_json(items: Iterable[QueueWorkItem]) -> str:
    records = _sorted_records(items)
    rows = [item.to_dict() for item in records]
    payload = {
        "schema_version": QUEUE_RECORD_SET_SCHEMA_VERSION,
        "record_count": len(rows),
        "record_set_digest": _digest(rows),
        "rows": rows,
    }
    return _canonical_json(payload)


def queue_records_from_json(text: str) -> tuple[QueueWorkItem, ...]:
    payload = _strict_json_loads(text)
    if not isinstance(payload, Mapping):
        raise TypeError("queue record-set JSON must contain an object")
    _require_exact_keys(payload, _RECORD_SET_KEYS, "queue record set")
    record_schema = payload["schema_version"]
    if record_schema not in {
        QUEUE_RECORD_SET_SCHEMA_VERSION,
        _V3_QUEUE_RECORD_SET_SCHEMA_VERSION,
        _LEGACY_QUEUE_RECORD_SET_SCHEMA_VERSION,
    }:
        raise ValueError(
            f"unsupported queue record-set schema_version: {payload['schema_version']!r}"
        )
    count = payload["record_count"]
    if isinstance(count, bool) or not isinstance(count, int) or count < 0:
        raise TypeError("record_count must be a non-negative integer")
    rows = payload["rows"]
    if not isinstance(rows, list):
        raise TypeError("rows must be a JSON array")
    if count != len(rows):
        raise ValueError(f"record_count is {count}, but rows contains {len(rows)} records")
    digest = payload["record_set_digest"]
    if not isinstance(digest, str) or not _HEX_DIGEST_RE.fullmatch(digest):
        raise ValueError("record_set_digest must be a lowercase SHA-256 digest")
    if record_schema in {
        _V3_QUEUE_RECORD_SET_SCHEMA_VERSION,
        _LEGACY_QUEUE_RECORD_SET_SCHEMA_VERSION,
    }:
        actual_digest = _digest(rows)
    else:
        actual_digest = _digest(
            [item.to_dict() for item in _sorted_records(
                QueueWorkItem.from_dict(row) for row in rows
            )]
        )
    if digest != actual_digest:
        raise ValueError(
            f"record_set_digest mismatch: declared {digest}, computed {actual_digest}"
        )
    return _sorted_records(QueueWorkItem.from_dict(row) for row in rows)


def _escape_markdown_cell(value: str) -> str:
    out: list[str] = []
    for char in value:
        if char == "\\":
            out.append("\\\\")
        elif char == "|":
            out.append("\\|")
        elif char == "`":
            out.append("\\`")
        elif char == "\n":
            out.append("\\n")
        elif char == "\r":
            out.append("\\r")
        else:
            out.append(char)
    return "".join(out)


def _strip_markdown_padding(value: str) -> str:
    if value.startswith(" "):
        value = value[1:]
    if value.endswith(" "):
        value = value[:-1]
    return value


def _split_markdown_row(line: str, line_number: int) -> tuple[str, ...]:
    stripped = line.strip()
    if not stripped.startswith("|") or not stripped.endswith("|"):
        raise MarkdownProjectionError(
            f"line {line_number}: Markdown table row must start and end with |"
        )
    cells: list[str] = []
    current: list[str] = []
    index = 1
    end = len(stripped) - 1
    while index < end:
        char = stripped[index]
        if char == "\\":
            if index + 1 >= end:
                raise MarkdownProjectionError(
                    f"line {line_number}: dangling Markdown escape"
                )
            escaped = stripped[index + 1]
            translations = {
                "\\": "\\",
                "|": "|",
                "`": "`",
                "n": "\n",
                "r": "\r",
            }
            if escaped not in translations:
                raise MarkdownProjectionError(
                    f"line {line_number}: unsupported Markdown escape \\{escaped}"
                )
            current.append(translations[escaped])
            index += 2
            continue
        if char == "|":
            cells.append(_strip_markdown_padding("".join(current)))
            current = []
        else:
            current.append(char)
        index += 1
    cells.append(_strip_markdown_padding("".join(current)))
    return tuple(cells)


def _require_markdown_width(
    cells: Sequence[str], line_number: int, expected: int = len(MARKDOWN_HEADERS)
) -> None:
    if len(cells) != expected:
        raise MarkdownProjectionError(
            f"line {line_number}: expected {expected} cells, got {len(cells)}"
        )


def _markdown_cells(item: QueueWorkItem) -> tuple[Any, ...]:
    identity = {
        "lineage": [link.to_dict() for link in item.lineage],
        "aliases": list(item.aliases),
        "constituents": list(item.constituents),
        "queue_priority": item.queue_priority,
    }
    classification = {
        "evidence_class": item.evidence_class,
        "bug_class": item.bug_class,
        "preferred_tag": item.preferred_tag,
        "effective_evidence_scope": item.effective_evidence_scope,
        "effective_proof_scope": item.effective_proof_scope,
        "effective_harm_scope": item.effective_harm_scope,
        "required_disposition": item.required_disposition,
    }
    return (
        item.work_item_id,
        item.candidate_identity,
        identity,
        item.severity_proposal.to_dict(),
        classification,
        [location.to_dict() for location in item.location_records],
        list(item.primary_artifacts),
        item.poc_class,
        item.title,
        item.expected_output_file,
    )


def render_queue_markdown(items: Iterable[QueueWorkItem]) -> str:
    """Render the human projection through one lossless, escaped codec."""

    records = _sorted_records(items)
    lines = [
        "| " + " | ".join(MARKDOWN_HEADERS) + " |",
        "| " + " | ".join("---" for _ in MARKDOWN_HEADERS) + " |",
    ]
    for item in records:
        encoded = (
            _escape_markdown_cell(_canonical_json(value))
            for value in _markdown_cells(item)
        )
        lines.append("| " + " | ".join(encoded) + " |")
    projection = "\n".join(lines) + "\n"
    # The renderer is not trusted merely because it authored the projection.
    if parse_queue_markdown(projection) != records:
        raise MarkdownProjectionError("renderer/parser typed-field parity failure")
    return projection


def parse_queue_markdown(text: str) -> tuple[QueueWorkItem, ...]:
    """Parse only the canonical projection; malformed widths are fatal debt."""

    if not isinstance(text, str):
        raise TypeError("Markdown projection must be text")
    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    while lines and not lines[0].strip():
        lines.pop(0)
    while lines and not lines[-1].strip():
        lines.pop()
    if len(lines) < 2:
        raise MarkdownProjectionError("Markdown projection requires a header and separator")
    header = _split_markdown_row(lines[0], 1)
    _require_markdown_width(header, 1)
    if header != MARKDOWN_HEADERS:
        raise MarkdownProjectionError(
            "line 1: Markdown headers do not match the canonical 10-column schema"
        )
    separator = _split_markdown_row(lines[1], 2)
    _require_markdown_width(separator, 2)
    if not all(re.fullmatch(r":?-{3,}:?", cell.strip()) for cell in separator):
        raise MarkdownProjectionError("line 2: malformed Markdown separator")

    records: list[QueueWorkItem] = []
    for offset, line in enumerate(lines[2:], start=3):
        if not line.strip():
            raise MarkdownProjectionError(f"line {offset}: blank row inside projection")
        cells = _split_markdown_row(line, offset)
        _require_markdown_width(cells, offset)
        try:
            decoded = tuple(_strict_json_loads(cell) for cell in cells)
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise MarkdownProjectionError(
                f"line {offset}: cell is not canonical JSON: {exc}"
            ) from exc
        identity = decoded[2]
        if not isinstance(identity, Mapping):
            raise MarkdownProjectionError(
                f"line {offset}: Identity Lineage cell must be a JSON object"
            )
        classification = decoded[4]
        if not isinstance(classification, Mapping):
            raise MarkdownProjectionError(
                f"line {offset}: Evidence Class cell must be a JSON object"
            )
        try:
            _require_exact_keys(identity, _IDENTITY_CELL_KEYS, "identity lineage cell")
            _require_exact_keys(
                classification,
                _CLASSIFICATION_CELL_KEYS,
                "classification cell",
            )
            value = {
                "schema_version": QUEUE_SCHEMA_VERSION,
                "work_item_id": decoded[0],
                "candidate_identity": decoded[1],
                "lineage": identity["lineage"],
                "aliases": identity["aliases"],
                "constituents": identity["constituents"],
                "severity_proposal": decoded[3],
                "evidence_class": classification["evidence_class"],
                "bug_class": classification["bug_class"],
                "preferred_tag": classification["preferred_tag"],
                "effective_evidence_scope": classification[
                    "effective_evidence_scope"
                ],
                "effective_proof_scope": classification[
                    "effective_proof_scope"
                ],
                "effective_harm_scope": classification[
                    "effective_harm_scope"
                ],
                "required_disposition": classification[
                    "required_disposition"
                ],
                "queue_priority": identity["queue_priority"],
                "location_records": decoded[5],
                "primary_artifacts": decoded[6],
                "poc_class": decoded[7],
                "title": decoded[8],
                "expected_output_file": decoded[9],
            }
            records.append(QueueWorkItem.from_dict(value))
        except (TypeError, ValueError) as exc:
            raise MarkdownProjectionError(
                f"line {offset}: typed projection mismatch: {exc}"
            ) from exc
    return _sorted_records(records)


def markdown_projection_digest(text: str) -> str:
    """Digest a projection only after strict typed round-trip validation."""

    records = parse_queue_markdown(text)
    canonical_projection = render_queue_markdown(records)
    if text.replace("\r\n", "\n").replace("\r", "\n") != canonical_projection:
        raise MarkdownProjectionError("projection is parseable but not canonical")
    return hashlib.sha256(canonical_projection.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class PartitionConservation:
    """Exact queue-to-shard set and record conservation result."""

    expected_ids: tuple[str, ...]
    assigned_ids: tuple[str, ...]
    missing_ids: tuple[str, ...]
    extra_ids: tuple[str, ...]
    duplicate_ids: tuple[str, ...]
    mismatched_record_ids: tuple[str, ...]

    @property
    def ok(self) -> bool:
        return not (
            self.missing_ids
            or self.extra_ids
            or self.duplicate_ids
            or self.mismatched_record_ids
        )

    def require_valid(self) -> None:
        if self.ok:
            return
        details = {
            "missing": self.missing_ids,
            "extra": self.extra_ids,
            "duplicate": self.duplicate_ids,
            "mismatched_records": self.mismatched_record_ids,
        }
        raise ValueError(f"partition conservation failed: {details}")


def validate_exact_partition(
    items: Iterable[QueueWorkItem],
    partitions: Mapping[str, Iterable[str | QueueWorkItem]],
) -> PartitionConservation:
    """Require shard union equality, disjointness, and typed-record parity."""

    records = validate_queue_work_items(items)
    authoritative = {item.work_item_id: item for item in records}
    assigned: list[str] = []
    mismatched: set[str] = set()
    if not isinstance(partitions, Mapping):
        raise TypeError("partitions must be a mapping")
    for partition_name, members in partitions.items():
        _text(partition_name, "partition name", nonempty=True)
        for member in members:
            if isinstance(member, QueueWorkItem):
                work_id = member.work_item_id
                expected = authoritative.get(work_id)
                if expected is not None and member.digest != expected.digest:
                    mismatched.add(work_id)
            elif isinstance(member, str):
                work_id = _safe_identity(member, "partition work_item_id")
            else:
                raise TypeError(
                    "partition members must be work-item IDs or QueueWorkItem records"
                )
            assigned.append(work_id)

    expected_ids = set(authoritative)
    assigned_ids = set(assigned)
    counts = Counter(assigned)
    sort_key = lambda value: (value.casefold(), value)
    return PartitionConservation(
        expected_ids=tuple(sorted(expected_ids, key=sort_key)),
        assigned_ids=tuple(sorted(assigned_ids, key=sort_key)),
        missing_ids=tuple(sorted(expected_ids - assigned_ids, key=sort_key)),
        extra_ids=tuple(sorted(assigned_ids - expected_ids, key=sort_key)),
        duplicate_ids=tuple(
            sorted((identity for identity, count in counts.items() if count > 1), key=sort_key)
        ),
        mismatched_record_ids=tuple(sorted(mismatched, key=sort_key)),
    )


@dataclass(frozen=True, slots=True)
class OutputOwnership:
    """One current work item exclusively owns one verifier output identity."""

    work_item_id: str
    work_item_digest: str
    expected_output_file: str
    expected_output_identity: str

    def __post_init__(self) -> None:
        _safe_identity(self.work_item_id, "output ownership work_item_id")
        _sha256_digest(self.work_item_digest, "output ownership work_item_digest")
        expected_file = f"verify_{self.work_item_id}.md"
        expected_identity = f"scratchpad:{expected_file}"
        if self.expected_output_file != expected_file:
            raise ValueError(
                "output ownership expected_output_file must be the current-ID "
                f"projection {expected_file!r}"
            )
        if self.expected_output_identity != expected_identity:
            raise ValueError(
                "output ownership expected_output_identity must be "
                f"{expected_identity!r}"
            )

    @classmethod
    def for_item(cls, item: QueueWorkItem) -> "OutputOwnership":
        if not isinstance(item, QueueWorkItem):
            raise TypeError("output ownership requires a QueueWorkItem")
        return cls(
            work_item_id=item.work_item_id,
            work_item_digest=item.digest,
            expected_output_file=item.expected_output_file,
            expected_output_identity=item.expected_output_identity,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": OUTPUT_OWNERSHIP_SCHEMA_VERSION,
            "work_item_id": self.work_item_id,
            "work_item_digest": self.work_item_digest,
            "expected_output_file": self.expected_output_file,
            "expected_output_identity": self.expected_output_identity,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "OutputOwnership":
        _require_exact_keys(value, _OUTPUT_OWNERSHIP_KEYS, "output ownership")
        if value["schema_version"] != OUTPUT_OWNERSHIP_SCHEMA_VERSION:
            raise ValueError(
                "unsupported output ownership schema_version: "
                f"{value['schema_version']!r}"
            )
        return cls(
            work_item_id=_text(
                value["work_item_id"], "output ownership work_item_id", nonempty=True
            ),
            work_item_digest=_text(
                value["work_item_digest"],
                "output ownership work_item_digest",
                nonempty=True,
            ),
            expected_output_file=_text(
                value["expected_output_file"],
                "output ownership expected_output_file",
                nonempty=True,
            ),
            expected_output_identity=_text(
                value["expected_output_identity"],
                "output ownership expected_output_identity",
                nonempty=True,
            ),
        )


@dataclass(frozen=True, slots=True)
class QueueWorkShard:
    """Immutable, ordered shard projection within one queue work plan."""

    shard_id: str
    ordered_work_item_ids: tuple[str, ...]
    shard_record_digest: str
    projection_digest: str
    output_ownership: tuple[OutputOwnership, ...]

    def __post_init__(self) -> None:
        _safe_identity(self.shard_id, "shard_id")
        ids = _identity_tuple(self.ordered_work_item_ids, "ordered_work_item_ids")
        _sha256_digest(self.shard_record_digest, "shard_record_digest")
        _sha256_digest(self.projection_digest, "projection_digest")
        owners = tuple(self.output_ownership)
        if not all(isinstance(owner, OutputOwnership) for owner in owners):
            raise TypeError("output_ownership entries must be OutputOwnership records")
        if tuple(owner.work_item_id for owner in owners) != ids:
            raise ValueError(
                "output_ownership order must exactly match ordered_work_item_ids"
            )
        if len({owner.expected_output_file.casefold() for owner in owners}) != len(owners):
            raise ValueError("shard output_ownership contains a filename collision")
        object.__setattr__(self, "ordered_work_item_ids", ids)
        object.__setattr__(self, "output_ownership", owners)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": QUEUE_WORK_SHARD_SCHEMA_VERSION,
            "shard_id": self.shard_id,
            "ordered_work_item_ids": list(self.ordered_work_item_ids),
            "shard_record_digest": self.shard_record_digest,
            "projection_digest": self.projection_digest,
            "output_ownership": [owner.to_dict() for owner in self.output_ownership],
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "QueueWorkShard":
        _require_exact_keys(value, _WORK_SHARD_KEYS, "queue work shard")
        if value["schema_version"] != QUEUE_WORK_SHARD_SCHEMA_VERSION:
            raise ValueError(
                "unsupported queue work shard schema_version: "
                f"{value['schema_version']!r}"
            )
        for field in ("ordered_work_item_ids", "output_ownership"):
            if not isinstance(value[field], list):
                raise TypeError(f"queue work shard {field} must be a JSON array")
        return cls(
            shard_id=_text(value["shard_id"], "shard_id", nonempty=True),
            ordered_work_item_ids=tuple(value["ordered_work_item_ids"]),
            shard_record_digest=_text(
                value["shard_record_digest"], "shard_record_digest", nonempty=True
            ),
            projection_digest=_text(
                value["projection_digest"], "projection_digest", nonempty=True
            ),
            output_ownership=tuple(
                OutputOwnership.from_dict(owner) for owner in value["output_ownership"]
            ),
        )


@dataclass(frozen=True, slots=True)
class QueueWorkPlan:
    """Digest-bound active queue partition and verifier-output ownership plan."""

    planner_version: str
    parent_record_set_digest: str
    ordered_work_item_ids: tuple[str, ...]
    shards: tuple[QueueWorkShard, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.planner_version, str) or not _CLASS_RE.fullmatch(
            self.planner_version
        ):
            raise ValueError("planner_version must be a non-empty version token")
        _sha256_digest(self.parent_record_set_digest, "parent_record_set_digest")
        ids = _identity_tuple(self.ordered_work_item_ids, "ordered_work_item_ids")
        shards = tuple(self.shards)
        if not all(isinstance(shard, QueueWorkShard) for shard in shards):
            raise TypeError("shards entries must be QueueWorkShard records")
        shard_keys = [shard.shard_id.casefold() for shard in shards]
        if len(set(shard_keys)) != len(shard_keys):
            raise ValueError("work plan contains duplicate shard_id values")
        canonical_shards = tuple(
            sorted(shards, key=lambda shard: (shard.shard_id.casefold(), shard.shard_id))
        )
        if shards != canonical_shards:
            raise ValueError("work plan shards must be in canonical shard_id order")
        assigned = [
            work_id
            for shard in shards
            for work_id in shard.ordered_work_item_ids
        ]
        if Counter(assigned) != Counter(ids):
            raise ValueError(
                "work plan shard membership must be an exact partition of "
                "ordered_work_item_ids"
            )
        owners = [owner for shard in shards for owner in shard.output_ownership]
        if Counter(owner.work_item_id for owner in owners) != Counter(ids):
            raise ValueError(
                "work plan output ownership must cover each work item exactly once"
            )
        output_keys = [owner.expected_output_file.casefold() for owner in owners]
        if len(set(output_keys)) != len(output_keys):
            raise ValueError("work plan output ownership contains a filename collision")
        object.__setattr__(self, "ordered_work_item_ids", ids)
        object.__setattr__(self, "shards", shards)

    @property
    def output_ownership(self) -> tuple[OutputOwnership, ...]:
        by_id = {
            owner.work_item_id: owner
            for shard in self.shards
            for owner in shard.output_ownership
        }
        return tuple(by_id[work_id] for work_id in self.ordered_work_item_ids)

    def shard(self, shard_id: str) -> QueueWorkShard:
        _safe_identity(shard_id, "shard_id")
        for shard in self.shards:
            if shard.shard_id == shard_id:
                return shard
        raise ValueError(f"unknown shard_id: {shard_id}")

    def _unsigned_dict(self) -> dict[str, Any]:
        return {
            "schema_version": QUEUE_WORK_PLAN_SCHEMA_VERSION,
            "planner_version": self.planner_version,
            "parent_record_set_digest": self.parent_record_set_digest,
            "ordered_work_item_ids": list(self.ordered_work_item_ids),
            "shards": [shard.to_dict() for shard in self.shards],
        }

    @property
    def digest(self) -> str:
        return _digest(self._unsigned_dict())

    def to_dict(self) -> dict[str, Any]:
        return {**self._unsigned_dict(), "work_plan_digest": self.digest}

    def to_json(self) -> str:
        return _canonical_json(self.to_dict())

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "QueueWorkPlan":
        _require_exact_keys(value, _WORK_PLAN_KEYS, "queue work plan")
        if value["schema_version"] != QUEUE_WORK_PLAN_SCHEMA_VERSION:
            raise ValueError(
                "unsupported queue work plan schema_version: "
                f"{value['schema_version']!r}"
            )
        for field in ("ordered_work_item_ids", "shards"):
            if not isinstance(value[field], list):
                raise TypeError(f"queue work plan {field} must be a JSON array")
        plan = cls(
            planner_version=_text(
                value["planner_version"], "planner_version", nonempty=True
            ),
            parent_record_set_digest=_text(
                value["parent_record_set_digest"],
                "parent_record_set_digest",
                nonempty=True,
            ),
            ordered_work_item_ids=tuple(value["ordered_work_item_ids"]),
            shards=tuple(QueueWorkShard.from_dict(shard) for shard in value["shards"]),
        )
        declared = _text(
            value["work_plan_digest"], "work_plan_digest", nonempty=True
        )
        _sha256_digest(declared, "work_plan_digest")
        if declared != plan.digest:
            raise ValueError(
                f"work_plan_digest mismatch: declared {declared}, computed {plan.digest}"
            )
        return plan

    @classmethod
    def from_json(cls, text: str) -> "QueueWorkPlan":
        value = _strict_json_loads(text)
        if not isinstance(value, Mapping):
            raise TypeError("queue work plan JSON must contain an object")
        return cls.from_dict(value)

    def validate_against(self, items: Iterable[QueueWorkItem]) -> None:
        records = _sorted_records(items)
        expected_ids = tuple(item.work_item_id for item in records)
        if expected_ids != self.ordered_work_item_ids:
            raise ValueError(
                "ordered_work_item_ids mismatch against authoritative queue records"
            )
        parent_digest = queue_record_set_digest(records)
        if self.parent_record_set_digest != parent_digest:
            raise ValueError(
                "parent_record_set_digest mismatch against authoritative queue records"
            )
        by_id = {item.work_item_id: item for item in records}
        conservation = validate_exact_partition(
            records,
            {
                shard.shard_id: shard.ordered_work_item_ids
                for shard in self.shards
            },
        )
        conservation.require_valid()
        for shard in self.shards:
            shard_records = tuple(by_id[work_id] for work_id in shard.ordered_work_item_ids)
            canonical_shard_records = _sorted_records(shard_records)
            canonical_ids = tuple(item.work_item_id for item in canonical_shard_records)
            if shard.ordered_work_item_ids != canonical_ids:
                raise ValueError(
                    f"shard {shard.shard_id} ordered_work_item_ids are not canonical"
                )
            expected_record_digest = _digest(
                [item.to_dict() for item in canonical_shard_records]
            )
            if shard.shard_record_digest != expected_record_digest:
                raise ValueError(
                    f"shard {shard.shard_id} shard_record_digest mismatch"
                )
            expected_projection_digest = markdown_projection_digest(
                render_queue_markdown(canonical_shard_records)
            )
            if shard.projection_digest != expected_projection_digest:
                raise ValueError(
                    f"shard {shard.shard_id} projection_digest mismatch"
                )
            expected_owners = tuple(
                OutputOwnership.for_item(item) for item in canonical_shard_records
            )
            if shard.output_ownership != expected_owners:
                raise ValueError(
                    f"shard {shard.shard_id} output_ownership mismatch"
                )


def build_queue_work_plan(
    items: Iterable[QueueWorkItem],
    partitions: Mapping[str, Iterable[str | QueueWorkItem]],
    *,
    planner_version: str,
) -> QueueWorkPlan:
    """Compile and validate an immutable queue-to-shard work plan."""

    records = _sorted_records(items)
    if not isinstance(partitions, Mapping):
        raise TypeError("partitions must be a mapping")
    materialized_partitions = {
        shard_id: tuple(members) for shard_id, members in partitions.items()
    }
    conservation = validate_exact_partition(records, materialized_partitions)
    conservation.require_valid()
    by_id = {item.work_item_id: item for item in records}
    shards: list[QueueWorkShard] = []
    for shard_id, members in sorted(
        materialized_partitions.items(),
        key=lambda pair: (pair[0].casefold(), pair[0]),
    ):
        _safe_identity(shard_id, "shard_id")
        member_ids = [
            member.work_item_id if isinstance(member, QueueWorkItem) else member
            for member in members
        ]
        shard_records = _sorted_records(by_id[work_id] for work_id in member_ids)
        projection = render_queue_markdown(shard_records)
        shards.append(
            QueueWorkShard(
                shard_id=shard_id,
                ordered_work_item_ids=tuple(
                    item.work_item_id for item in shard_records
                ),
                shard_record_digest=_digest(
                    [item.to_dict() for item in shard_records]
                ),
                projection_digest=markdown_projection_digest(projection),
                output_ownership=tuple(
                    OutputOwnership.for_item(item) for item in shard_records
                ),
            )
        )
    plan = QueueWorkPlan(
        planner_version=planner_version,
        parent_record_set_digest=queue_record_set_digest(records),
        ordered_work_item_ids=tuple(item.work_item_id for item in records),
        shards=tuple(shards),
    )
    plan.validate_against(records)
    return plan


@dataclass(frozen=True, slots=True)
class VerifierOutputIdentity:
    """Identity block embedded in, or stored beside, one verifier output."""

    work_item_id: str
    queue_record_digest: str
    work_plan_digest: str
    shard_id: str
    expected_output_file: str
    expected_output_identity: str

    def __post_init__(self) -> None:
        _safe_identity(self.work_item_id, "verifier output work_item_id")
        _safe_identity(self.shard_id, "verifier output shard_id")
        _sha256_digest(self.queue_record_digest, "queue_record_digest")
        _sha256_digest(self.work_plan_digest, "work_plan_digest")
        expected_file = f"verify_{self.work_item_id}.md"
        expected_identity = f"scratchpad:{expected_file}"
        if self.expected_output_file != expected_file:
            raise ValueError(
                "verifier expected_output_file must be the current-ID projection"
            )
        if self.expected_output_identity != expected_identity:
            raise ValueError(
                "verifier expected_output_identity must be the current-ID projection"
            )

    @classmethod
    def for_assignment(
        cls,
        item: QueueWorkItem,
        plan: QueueWorkPlan,
        shard_id: str,
    ) -> "VerifierOutputIdentity":
        if not isinstance(item, QueueWorkItem):
            raise TypeError("verifier output identity requires a QueueWorkItem")
        if not isinstance(plan, QueueWorkPlan):
            raise TypeError("verifier output identity requires a QueueWorkPlan")
        shard = plan.shard(shard_id)
        owners = {
            owner.work_item_id: owner for owner in shard.output_ownership
        }
        owner = owners.get(item.work_item_id)
        if owner is None:
            raise ValueError(
                f"work item {item.work_item_id} is not assigned to shard {shard_id}"
            )
        if owner.work_item_digest != item.digest:
            raise ValueError(
                "queue_record_digest does not match the work plan output owner"
            )
        return cls(
            work_item_id=item.work_item_id,
            queue_record_digest=item.digest,
            work_plan_digest=plan.digest,
            shard_id=shard_id,
            expected_output_file=item.expected_output_file,
            expected_output_identity=item.expected_output_identity,
        )

    @property
    def digest(self) -> str:
        return _digest(self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": VERIFIER_OUTPUT_IDENTITY_SCHEMA_VERSION,
            "work_item_id": self.work_item_id,
            "queue_record_digest": self.queue_record_digest,
            "work_plan_digest": self.work_plan_digest,
            "shard_id": self.shard_id,
            "expected_output_file": self.expected_output_file,
            "expected_output_identity": self.expected_output_identity,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "VerifierOutputIdentity":
        _require_exact_keys(
            value, _VERIFIER_OUTPUT_IDENTITY_KEYS, "verifier output identity"
        )
        if value["schema_version"] != VERIFIER_OUTPUT_IDENTITY_SCHEMA_VERSION:
            raise ValueError(
                "unsupported verifier output identity schema_version: "
                f"{value['schema_version']!r}"
            )
        return cls(
            work_item_id=_text(value["work_item_id"], "work_item_id", nonempty=True),
            queue_record_digest=_text(
                value["queue_record_digest"], "queue_record_digest", nonempty=True
            ),
            work_plan_digest=_text(
                value["work_plan_digest"], "work_plan_digest", nonempty=True
            ),
            shard_id=_text(value["shard_id"], "shard_id", nonempty=True),
            expected_output_file=_text(
                value["expected_output_file"], "expected_output_file", nonempty=True
            ),
            expected_output_identity=_text(
                value["expected_output_identity"],
                "expected_output_identity",
                nonempty=True,
            ),
        )


@dataclass(frozen=True, slots=True)
class VerifierOutputReceipt:
    """Digest-bound receipt proving which exact bytes satisfy one assignment."""

    identity: VerifierOutputIdentity
    output_sha256: str
    output_size_bytes: int
    severity_proposal_file: str
    severity_proposal_sha256: str
    severity_proposal_size_bytes: int
    launch_digest: str
    verifier_backend: str

    def __post_init__(self) -> None:
        if not isinstance(self.identity, VerifierOutputIdentity):
            raise TypeError("identity must be a VerifierOutputIdentity")
        _sha256_digest(self.output_sha256, "output_sha256")
        _nonnegative_integer(self.output_size_bytes, "output_size_bytes")
        expected_proposal = (
            f"verify_{self.identity.work_item_id}.severity_proposal.json"
        )
        if self.severity_proposal_file != expected_proposal:
            raise ValueError(
                "severity_proposal_file must be the current-ID projection"
            )
        _sha256_digest(
            self.severity_proposal_sha256, "severity_proposal_sha256"
        )
        _nonnegative_integer(
            self.severity_proposal_size_bytes,
            "severity_proposal_size_bytes",
        )
        _sha256_digest(self.launch_digest, "launch_digest")
        if not isinstance(self.verifier_backend, str) or not _CLASS_RE.fullmatch(
            self.verifier_backend
        ):
            raise ValueError("verifier_backend must be a non-empty backend token")

    @classmethod
    def bind(
        cls,
        identity: VerifierOutputIdentity,
        output: bytes,
        *,
        severity_proposal: bytes,
        launch_digest: str,
        verifier_backend: str,
    ) -> "VerifierOutputReceipt":
        if not isinstance(output, bytes):
            raise TypeError("verifier output must be bytes")
        if not isinstance(severity_proposal, bytes):
            raise TypeError("severity proposal must be bytes")
        return cls(
            identity=identity,
            output_sha256=_sha256_bytes(output),
            output_size_bytes=len(output),
            severity_proposal_file=(
                f"verify_{identity.work_item_id}.severity_proposal.json"
            ),
            severity_proposal_sha256=_sha256_bytes(severity_proposal),
            severity_proposal_size_bytes=len(severity_proposal),
            launch_digest=launch_digest,
            verifier_backend=verifier_backend,
        )

    def _unsigned_dict(self) -> dict[str, Any]:
        return {
            "schema_version": VERIFIER_OUTPUT_RECEIPT_SCHEMA_VERSION,
            "identity": self.identity.to_dict(),
            "output_sha256": self.output_sha256,
            "output_size_bytes": self.output_size_bytes,
            "severity_proposal_file": self.severity_proposal_file,
            "severity_proposal_sha256": self.severity_proposal_sha256,
            "severity_proposal_size_bytes": self.severity_proposal_size_bytes,
            "launch_digest": self.launch_digest,
            "verifier_backend": self.verifier_backend,
        }

    @property
    def digest(self) -> str:
        return _digest(self._unsigned_dict())

    def to_dict(self) -> dict[str, Any]:
        return {**self._unsigned_dict(), "receipt_digest": self.digest}

    def to_json(self) -> str:
        return _canonical_json(self.to_dict())

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "VerifierOutputReceipt":
        _require_exact_keys(
            value, _VERIFIER_OUTPUT_RECEIPT_KEYS, "verifier output receipt"
        )
        if value["schema_version"] != VERIFIER_OUTPUT_RECEIPT_SCHEMA_VERSION:
            raise ValueError(
                "unsupported verifier output receipt schema_version: "
                f"{value['schema_version']!r}"
            )
        if not isinstance(value["identity"], Mapping):
            raise TypeError("verifier output receipt identity must be an object")
        receipt = cls(
            identity=VerifierOutputIdentity.from_dict(value["identity"]),
            output_sha256=_text(
                value["output_sha256"], "output_sha256", nonempty=True
            ),
            output_size_bytes=_nonnegative_integer(
                value["output_size_bytes"], "output_size_bytes"
            ),
            severity_proposal_file=_text(
                value["severity_proposal_file"],
                "severity_proposal_file",
                nonempty=True,
            ),
            severity_proposal_sha256=_text(
                value["severity_proposal_sha256"],
                "severity_proposal_sha256",
                nonempty=True,
            ),
            severity_proposal_size_bytes=_nonnegative_integer(
                value["severity_proposal_size_bytes"],
                "severity_proposal_size_bytes",
            ),
            launch_digest=_text(
                value["launch_digest"], "launch_digest", nonempty=True
            ),
            verifier_backend=_text(
                value["verifier_backend"], "verifier_backend", nonempty=True
            ),
        )
        declared = _text(value["receipt_digest"], "receipt_digest", nonempty=True)
        _sha256_digest(declared, "receipt_digest")
        if declared != receipt.digest:
            raise ValueError(
                f"receipt_digest mismatch: declared {declared}, computed {receipt.digest}"
            )
        return receipt

    @classmethod
    def from_json(cls, text: str) -> "VerifierOutputReceipt":
        value = _strict_json_loads(text)
        if not isinstance(value, Mapping):
            raise TypeError("verifier output receipt JSON must contain an object")
        return cls.from_dict(value)

    def validate_against(
        self,
        item: QueueWorkItem,
        plan: QueueWorkPlan,
        output: bytes,
        *,
        severity_proposal: bytes,
        launch_digest: str,
        verifier_backend: str,
    ) -> None:
        if self.identity.queue_record_digest != item.digest:
            raise ValueError("queue_record_digest mismatch against work item")
        expected_identity = VerifierOutputIdentity.for_assignment(
            item, plan, self.identity.shard_id
        )
        if self.identity != expected_identity:
            raise ValueError("verifier output identity mismatch against work plan")
        actual_output_digest = _sha256_bytes(output)
        if self.output_sha256 != actual_output_digest:
            raise ValueError("output_sha256 mismatch against verifier output bytes")
        if self.output_size_bytes != len(output):
            raise ValueError("output_size_bytes mismatch against verifier output bytes")
        actual_proposal_digest = _sha256_bytes(severity_proposal)
        if self.severity_proposal_sha256 != actual_proposal_digest:
            raise ValueError(
                "severity_proposal_sha256 mismatch against severity proposal bytes"
            )
        if self.severity_proposal_size_bytes != len(severity_proposal):
            raise ValueError(
                "severity_proposal_size_bytes mismatch against severity proposal bytes"
            )
        _sha256_digest(launch_digest, "launch_digest")
        if self.launch_digest != launch_digest:
            raise ValueError("launch_digest mismatch")
        if self.verifier_backend != verifier_backend:
            raise ValueError("verifier_backend mismatch")


@dataclass(frozen=True, slots=True)
class ExclusionDisposition:
    """Typed inactive-route decision; never an active verifier work item."""

    identity: str
    status: str
    reason_class: str
    reason: str
    authority: str
    evidence_ids: tuple[str, ...]
    next_action: str
    public_retention_target: str

    def __post_init__(self) -> None:
        _safe_identity(self.identity, "exclusion identity")
        for value, field in (
            (self.status, "exclusion status"),
            (self.reason_class, "exclusion reason_class"),
            (self.authority, "exclusion authority"),
            (self.next_action, "exclusion next_action"),
            (self.public_retention_target, "exclusion public_retention_target"),
        ):
            if not isinstance(value, str) or not _CLASS_RE.fullmatch(value):
                raise ValueError(f"{field} must be a non-empty token")
        _text(self.reason, "exclusion reason", nonempty=True)
        evidence_ids = _identity_tuple(self.evidence_ids, "exclusion evidence_ids")
        object.__setattr__(self, "evidence_ids", evidence_ids)

    def _unsigned_dict(self) -> dict[str, Any]:
        return {
            "schema_version": EXCLUSION_DISPOSITION_SCHEMA_VERSION,
            "identity": self.identity,
            "status": self.status,
            "reason_class": self.reason_class,
            "reason": self.reason,
            "authority": self.authority,
            "evidence_ids": list(self.evidence_ids),
            "next_action": self.next_action,
            "public_retention_target": self.public_retention_target,
        }

    @property
    def digest(self) -> str:
        return _digest(self._unsigned_dict())

    def to_dict(self) -> dict[str, Any]:
        return {**self._unsigned_dict(), "disposition_digest": self.digest}

    def to_json(self) -> str:
        return _canonical_json(self.to_dict())

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ExclusionDisposition":
        _require_exact_keys(
            value, _EXCLUSION_DISPOSITION_KEYS, "exclusion disposition"
        )
        if value["schema_version"] != EXCLUSION_DISPOSITION_SCHEMA_VERSION:
            raise ValueError(
                "unsupported exclusion disposition schema_version: "
                f"{value['schema_version']!r}"
            )
        if not isinstance(value["evidence_ids"], list):
            raise TypeError("exclusion evidence_ids must be a JSON array")
        disposition = cls(
            identity=_text(value["identity"], "exclusion identity", nonempty=True),
            status=_text(value["status"], "exclusion status", nonempty=True),
            reason_class=_text(
                value["reason_class"], "exclusion reason_class", nonempty=True
            ),
            reason=_text(value["reason"], "exclusion reason", nonempty=True),
            authority=_text(
                value["authority"], "exclusion authority", nonempty=True
            ),
            evidence_ids=tuple(value["evidence_ids"]),
            next_action=_text(
                value["next_action"], "exclusion next_action", nonempty=True
            ),
            public_retention_target=_text(
                value["public_retention_target"],
                "exclusion public_retention_target",
                nonempty=True,
            ),
        )
        declared = _text(
            value["disposition_digest"], "disposition_digest", nonempty=True
        )
        _sha256_digest(declared, "disposition_digest")
        if declared != disposition.digest:
            raise ValueError(
                "disposition_digest mismatch: "
                f"declared {declared}, computed {disposition.digest}"
            )
        return disposition

    @classmethod
    def from_json(cls, text: str) -> "ExclusionDisposition":
        value = _strict_json_loads(text)
        if not isinstance(value, Mapping):
            raise TypeError("exclusion disposition JSON must contain an object")
        return cls.from_dict(value)


__all__ = [
    "EXCLUSION_DISPOSITION_SCHEMA_VERSION",
    "MARKDOWN_HEADERS",
    "OUTPUT_OWNERSHIP_SCHEMA_VERSION",
    "QUEUE_RECORD_SET_SCHEMA_VERSION",
    "QUEUE_SCHEMA_VERSION",
    "QUEUE_WORK_PLAN_SCHEMA_VERSION",
    "QUEUE_WORK_SHARD_SCHEMA_VERSION",
    "REQUIRED_DISPOSITIONS",
    "VERIFIER_OUTPUT_IDENTITY_SCHEMA_VERSION",
    "VERIFIER_OUTPUT_RECEIPT_SCHEMA_VERSION",
    "ExclusionDisposition",
    "LineageLink",
    "LocationRecord",
    "MarkdownProjectionError",
    "OutputOwnership",
    "PartitionConservation",
    "QueueLineageIndex",
    "QueueWorkPlan",
    "QueueWorkShard",
    "QueueWorkItem",
    "SeverityProposal",
    "VerifierOutputIdentity",
    "VerifierOutputReceipt",
    "build_queue_work_plan",
    "build_lineage_index",
    "markdown_projection_digest",
    "parse_queue_markdown",
    "queue_record_set_digest",
    "queue_records_from_json",
    "queue_records_to_json",
    "render_queue_markdown",
    "validate_exact_partition",
    "validate_queue_work_items",
]
