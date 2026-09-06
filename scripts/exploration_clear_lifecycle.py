"""Typed, deterministic lifecycle for exploration-skeptic clear obligations.

This module is deliberately a substrate, not an adjudicator.  It translates
the legacy, human-readable coverage table into content-bound records, permits
one targeted repair attempt, and leaves every unsupported clear in an exact
queue for an independent consumer.  An exploration worker can add a candidate
to the normal pipeline, but it cannot certify that candidate or mutate an
inventory/report through this module.

The parser is section- and header-scoped on purpose.  Markdown remains a
projection at this boundary; table-shaped prose elsewhere in the artifact is
never operational input.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, replace
import hashlib
import json
import os
from pathlib import Path
import re
from typing import Any, Iterable, Mapping, Sequence
import uuid

RECEIPT_SCHEMA = "plamen.exploration_clear_receipt.v1"
REPAIR_PLAN_SCHEMA = "plamen.exploration_clear_repair_plan.v1"
OBLIGATION_QUEUE_SCHEMA = "plamen.exploration_clear_obligation_queue.v1"
CANONICAL_PRIOR_ALIAS_SCHEMA = "plamen.exploration_clear_prior_aliases.v1"
CANONICAL_PRIOR_ALIAS_NAME = "exploration_clear_prior_aliases.json"
CANONICAL_IDENTITY_MAP_SCHEMA = "plamen.canonical_finding_ids.v1"
CANONICAL_IDENTITY_MAP_NAME = "_canonical_finding_ids.json"

RECEIPT_NAME = "exploration_clear_receipt.json"
REPAIR_PLAN_NAME = "exploration_clear_repair_plan.json"
OBLIGATION_QUEUE_NAME = "exploration_clear_obligations.json"
LEGACY_SENTINEL_NAME = "exploration_skeptic.instance_gap"

_COVERAGE_HEADING = "coverage record"
_COVERAGE_HEADER = ("finding", "axis", "instance", "disposition", "evidence")
_COMMITMENT_HEADING = "invariant commitment record"
_COMMITMENT_HEADER = ("finding", "axis", "instance", "commitment", "reason")
_CI_COMMITMENT_RE = re.compile(r"^CI\s*:\s*(?P<id>.+)$", re.IGNORECASE)
_CI_NOT_REQUIRED_RE = re.compile(
    r"^NOT_REQUIRED_NON_VALUE_BEARING$", re.IGNORECASE
)
_COMMITTED_INVARIANT_ID_PATTERN = r"(?:[A-Z][A-Z0-9]*-)*CI(?:-[A-Z0-9]+)+"
_CI_ID_RE = re.compile(rf"^{_COMMITTED_INVARIANT_ID_PATTERN}$", re.ASCII)
_CI_HEADER_RE = re.compile(
    r"(?im)^\s*committed-invariant\s*\[\s*(?P<id>[^\]\r\n]+)\s*\]\s*$"
)
_CI_FIELD_RE = re.compile(
    r"(?im)^\s*(?P<field>Locus|Shape|Assertion|Falsify Class|Provenance)\s*:\s*(?P<value>[^\r\n]+)\s*$"
)
_CI_LOCUS_RE = re.compile(
    r"^(?P<path>[^\r\n:]+(?:[\\/][^\r\n:]+)*\.(?:sol|rs|move|go|ts|js|py|c|cc|cpp|h|hpp|wasm))"
    r"\s*:\s*L?(?P<line>[1-9][0-9]*)(?:\b|\s)",
    re.IGNORECASE,
)
_CI_SHAPES = frozenset({
    "CONSERVATION", "REQUESTED_EQ_DELIVERED", "APPROVE_EQ_SPEND",
    "NO_REVERT_AT_BOUNDARY", "ROUNDTRIP", "FRESHNESS",
})
_CI_FALSIFY_CLASSES = frozenset(
    {"property", "boundary", "roundtrip", "conservation"}
)
_CLEAR_DISPOSITIONS = frozenset({"NO-GAP", "NO_GAP", "ASSESSED", "CLEAR", "CLOSED"})
_ADDITIVE_DISPOSITIONS = frozenset(
    {
        "ADD", "ADDITIVE", "GAP-FILLED", "GAP_FILLED", "NEW", "UPGRADE",
        "RE-OPEN", "RE-OPENED", "REOPEN", "REOPENED",
    }
)
_UNRESOLVED_DISPOSITIONS = frozenset(
    {"UNRESOLVED", "UNKNOWN", "DEFERRED", "UNAVAILABLE", "NOT-ASSESSED", "NOT_ASSESSED"}
)
_HEX_RE = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
_HEADING_RE = re.compile(r"^(?P<marks>#{1,6})\s+(?P<title>.*?)\s*#*\s*$")
_SEPARATOR_CELL_RE = re.compile(r"^:?-{3,}:?$")
_ACTION_ID_RE = re.compile(
    r"(?<![A-Za-z0-9])([A-Z][A-Z0-9]*(?:-[A-Z0-9][A-Z0-9_-]*)+)(?![A-Za-z0-9_-])"
)
_LOCUS_RE = re.compile(
    r"(?<![A-Za-z0-9_:/\\])"
    r"(?P<path>(?![A-Za-z]:[\\/])(?:[A-Za-z0-9_. -]+[\\/])*[A-Za-z0-9_. -]+)"
    r"(?P<sep>:(?:L)?|#L)(?P<line>[1-9][0-9]*)"
    r"(?![A-Za-z0-9])",
    re.ASCII,
)


class ExplorationClearError(ValueError):
    """The lifecycle input cannot be consumed without guessing."""


@dataclass(frozen=True)
class CanonicalPriorAuthority:
    """Exact deterministic alias projection used by every ECLR consumer."""

    source_identity_map: str
    source_identity_map_sha256: str
    aliases: dict[str, str]
    ambiguous_aliases: dict[str, tuple[str, ...]]
    authority_digest: str

    @property
    def payload(self) -> dict[str, Any]:
        return {
            "schema_version": CANONICAL_PRIOR_ALIAS_SCHEMA,
            "source_identity_map": self.source_identity_map,
            "source_identity_map_sha256": self.source_identity_map_sha256,
            "aliases": dict(sorted(self.aliases.items())),
            "ambiguous_short_aliases": {
                key: list(values)
                for key, values in sorted(self.ambiguous_aliases.items())
            },
            "alias_receipt_sha256": self.authority_digest,
        }


@dataclass(frozen=True)
class ExplorationRow:
    source_finding: str
    axis: str
    instance: str
    disposition: str
    evidence: str
    source_line: int
    source_row_sha256: str
    artifact_sha256: str
    obligation_id: str
    resolution_kind: str
    resolved_reference: str = ""


@dataclass(frozen=True)
class ExplorationObligation:
    obligation_id: str
    source_finding: str
    axis: str
    instance: str
    disposition: str
    reason: str
    original_disposition: str
    original_evidence: str
    artifact_sha256: str
    source_row_sha256: str
    source_row_sha256s: tuple[str, ...]
    source_line: int


@dataclass(frozen=True)
class DuplicateConflict:
    obligation_id: str
    source_finding: str
    axis: str
    instance: str
    dispositions: tuple[str, ...]
    evidence_values: tuple[str, ...]
    source_row_sha256s: tuple[str, ...]


@dataclass(frozen=True)
class AdditiveAction:
    action_id: str
    obligation_id: str
    source_finding: str
    axis: str
    instance: str
    evidence: str
    rationale: str
    artifact_sha256: str
    source_row_sha256: str
    source_line: int
    proof_scope: str = "UNVERIFIED_GENERATOR_OUTPUT"
    requires_independent_consumer: bool = True


@dataclass(frozen=True)
class InvariantCommitment:
    obligation_id: str
    source_finding: str
    axis: str
    instance: str
    source_row_sha256: str
    source_artifact_sha256: str
    declaration: str
    status: str
    reason: str
    ci_id: str
    ci_block_sha256: str
    locus: str
    shape: str
    assertion: str
    falsify_class: str
    provenance: str
    binding_digest: str


@dataclass(frozen=True)
class LifecycleReceipt:
    schema_version: str
    source_artifact: str
    artifact_sha256: str
    source_row_count: int
    rows: tuple[ExplorationRow, ...]
    obligations: tuple[ExplorationObligation, ...]
    conflicts: tuple[DuplicateConflict, ...]
    additive_actions: tuple[AdditiveAction, ...]
    invariant_commitment_status: str
    invariant_commitment_denominator: int
    invariant_commitments: tuple[InvariantCommitment, ...]
    debt: tuple[str, ...]
    status: str
    repair_attempts: int
    repair_response_sha256: str
    receipt_hash: str


@dataclass(frozen=True)
class RepairItem:
    obligation_id: str
    source_finding: str
    axis: str
    instance: str
    original_disposition: str
    original_evidence: str
    artifact_sha256: str
    source_row_sha256s: tuple[str, ...]


@dataclass(frozen=True)
class RepairPlan:
    schema_version: str
    plan_id: str
    attempt: int
    source_receipt_hash: str
    source_artifact_sha256: str
    obligation_ids: tuple[str, ...]
    items: tuple[RepairItem, ...]
    plan_hash: str


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


def _bytes_digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _ci_blocks(text: str) -> tuple[list[dict[str, str]], set[str]]:
    matches = list(_CI_HEADER_RE.finditer(text or ""))
    blocks: list[dict[str, str]] = []
    counts: dict[str, int] = {}
    for index, match in enumerate(matches):
        ci_id = " ".join(match.group("id").strip().split()).upper()
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        heading = re.search(r"(?m)^#{1,6}\s+", text[match.end():end])
        if heading:
            end = match.end() + heading.start()
        raw_block = text[match.start():end].strip()
        fields: dict[str, str] = {}
        for field_match in _CI_FIELD_RE.finditer(raw_block):
            key = re.sub(r"\s+", "_", field_match.group("field").strip().lower())
            fields[key] = (
                "" if key in fields else field_match.group("value").strip()
            )
        counts[ci_id] = counts.get(ci_id, 0) + 1
        blocks.append({
            "ci_id": ci_id,
            "ci_block_sha256": _bytes_digest(raw_block.encode("utf-8")),
            "locus": fields.get("locus", ""),
            "shape": fields.get("shape", "").upper(),
            "assertion": fields.get("assertion", ""),
            "falsify_class": fields.get("falsify_class", "").lower(),
            "provenance": fields.get("provenance", ""),
        })
    return blocks, {ci_id for ci_id, count in counts.items() if count != 1}


def _production_ci_locus(value: str) -> bool:
    normalized = " ".join(str(value or "").strip().split())
    match = _CI_LOCUS_RE.match(normalized)
    if not match:
        return False
    raw_path = match.group("path").replace("\\", "/")
    path = Path(raw_path)
    return not path.is_absolute() and ".." not in path.parts and ":" not in raw_path


def _alias_payload_digest(payload: object) -> str:
    """Retain the v1 sidecar's original canonical JSON encoding."""

    encoded = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _canonical_alias_projection(
    records: Sequence[Mapping[str, Any]],
) -> tuple[dict[str, str], dict[str, tuple[str, ...]]]:
    """Build aliases under the resolver's case-insensitive equivalence."""

    candidates: dict[str, dict[str, Any]] = {}

    def add(alias: str, canonical: str) -> None:
        spelling = alias.strip()
        target = canonical.strip()
        if not spelling or not target:
            return
        bucket = candidates.setdefault(
            spelling.casefold(), {"spellings": set(), "targets": set()}
        )
        bucket["spellings"].add(spelling)
        bucket["targets"].add(target)

    for row in records:
        canonical = str(row["canonical_id"]).strip()
        artifact = str(row["artifact"]).strip()
        for field in ("local_id", "local_id_raw"):
            alias = str(row[field]).strip()
            add(alias, canonical)
            add(f"{artifact}:{alias}", canonical)
        add(canonical, canonical)

    aliases: dict[str, str] = {}
    ambiguous: dict[str, tuple[str, ...]] = {}
    for bucket in candidates.values():
        spelling = sorted(bucket["spellings"], key=lambda value: (value.casefold(), value))[0]
        targets = tuple(sorted(bucket["targets"]))
        if len(targets) == 1:
            aliases[spelling] = targets[0]
        else:
            ambiguous[spelling] = targets
    return dict(sorted(aliases.items())), dict(sorted(ambiguous.items()))


def derive_canonical_prior_authority(
    identity_map_path: str | Path,
) -> CanonicalPriorAuthority:
    """Derive the complete alias authority from a typed canonical CID map."""

    source = Path(identity_map_path)
    if not source.is_file():
        unsigned = {
            "schema_version": CANONICAL_PRIOR_ALIAS_SCHEMA,
            "source_identity_map": "",
            "source_identity_map_sha256": "",
            "aliases": {},
            "ambiguous_short_aliases": {},
        }
        return CanonicalPriorAuthority(
            source_identity_map="",
            source_identity_map_sha256="",
            aliases={},
            ambiguous_aliases={},
            authority_digest=_alias_payload_digest(unsigned),
        )
    if source.name != CANONICAL_IDENTITY_MAP_NAME:
        raise ExplorationClearError(
            "canonical-prior identity-map filename is not registered"
        )
    try:
        raw = source.read_bytes()
        payload = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ExplorationClearError(
            f"canonical-prior identity map is unreadable: {exc}"
        ) from exc
    if (
        not isinstance(payload, dict)
        or payload.get("schema_version") != CANONICAL_IDENTITY_MAP_SCHEMA
        or not isinstance(payload.get("records"), list)
        or not isinstance(payload.get("record_count"), int)
        or payload.get("record_count") != len(payload["records"])
    ):
        raise ExplorationClearError(
            "canonical-prior identity map schema or denominator mismatch"
        )

    records: list[Mapping[str, Any]] = []
    for index, row in enumerate(payload["records"]):
        if not isinstance(row, Mapping):
            raise ExplorationClearError(
                f"canonical-prior identity row {index} is malformed"
            )
        required = ("canonical_id", "artifact", "local_id", "local_id_raw")
        if any(not isinstance(row.get(key), str) for key in required):
            raise ExplorationClearError(
                f"canonical-prior identity row {index} has invalid field types"
            )
        canonical = str(row["canonical_id"]).strip()
        artifact = str(row["artifact"]).strip()
        local_id = str(row["local_id"]).strip()
        local_id_raw = str(row["local_id_raw"]).strip()
        if (
            re.fullmatch(r"CID-[A-F0-9]{16}", canonical) is None
            or not artifact
            or Path(artifact).name != artifact
            or not local_id
            or not local_id_raw
        ):
            raise ExplorationClearError(
                f"canonical-prior identity row {index} is not authority-shaped"
            )
        records.append(row)

    aliases, ambiguous = _canonical_alias_projection(records)
    unsigned = {
        "schema_version": CANONICAL_PRIOR_ALIAS_SCHEMA,
        "source_identity_map": source.name,
        "source_identity_map_sha256": _bytes_digest(raw),
        "aliases": aliases,
        "ambiguous_short_aliases": {
            key: list(values) for key, values in ambiguous.items()
        },
    }
    return CanonicalPriorAuthority(
        source_identity_map=source.name,
        source_identity_map_sha256=_bytes_digest(raw),
        aliases=aliases,
        ambiguous_aliases=ambiguous,
        authority_digest=_alias_payload_digest(unsigned),
    )


def load_canonical_prior_authority(
    scratchpad: str | Path,
) -> CanonicalPriorAuthority:
    """Load a sidecar only when exact re-derivation proves semantic parity."""

    root = Path(scratchpad)
    path = root / CANONICAL_PRIOR_ALIAS_NAME
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ExplorationClearError(
            f"cannot load exploration alias receipt: {exc}"
        ) from exc
    expected_keys = {
        "schema_version",
        "source_identity_map",
        "source_identity_map_sha256",
        "aliases",
        "ambiguous_short_aliases",
        "alias_receipt_sha256",
    }
    if (
        not isinstance(payload, dict)
        or payload.get("schema_version") != CANONICAL_PRIOR_ALIAS_SCHEMA
        or set(payload) != expected_keys
    ):
        raise ExplorationClearError("exploration alias receipt schema/key mismatch")
    unsigned = {
        key: value for key, value in payload.items()
        if key != "alias_receipt_sha256"
    }
    if payload.get("alias_receipt_sha256") != _alias_payload_digest(unsigned):
        raise ExplorationClearError("exploration alias receipt digest mismatch")
    source_name = str(payload.get("source_identity_map") or "")
    if source_name and source_name != CANONICAL_IDENTITY_MAP_NAME:
        raise ExplorationClearError(
            "exploration alias identity-map path is not canonical and local"
        )
    derived = derive_canonical_prior_authority(
        root / CANONICAL_IDENTITY_MAP_NAME
    )
    if payload != derived.payload:
        raise ExplorationClearError(
            "exploration alias receipt semantic parity mismatch"
        )
    return derived


def _normal(value: str) -> str:
    return " ".join(value.strip().split())


def _identity_part(value: str) -> str:
    return _normal(value).casefold()


def _obligation_id(source_finding: str, axis: str, instance: str) -> str:
    identity = {
        "source_finding": _identity_part(source_finding),
        "axis": _identity_part(axis),
        "instance": _identity_part(instance),
    }
    return "ECLR-" + _digest(identity)[:24].upper()


def _split_markdown_row(line: str) -> tuple[str, ...] | None:
    stripped = line.strip()
    if not stripped.startswith("|") or not stripped.endswith("|"):
        return None
    cells: list[str] = []
    current: list[str] = []
    escaped = False
    # Exclude the two boundary pipes.  Escaped pipes remain cell content.
    for char in stripped[1:-1]:
        if escaped:
            current.append(char)
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == "|":
            cells.append(_normal("".join(current)))
            current = []
        else:
            current.append(char)
    if escaped:
        current.append("\\")
    cells.append(_normal("".join(current)))
    return tuple(cells)


def _is_separator(cells: Sequence[str], width: int) -> bool:
    return len(cells) == width and all(_SEPARATOR_CELL_RE.fullmatch(cell) for cell in cells)


def _coverage_source_rows(text: str) -> tuple[list[tuple[int, str, tuple[str, ...]]], list[str]]:
    """Return only exact rows under the H2 Coverage Record table."""
    lines = text.splitlines()
    section_start: int | None = None
    section_end = len(lines)
    for index, line in enumerate(lines):
        heading = _HEADING_RE.match(line.strip())
        if not heading:
            continue
        level = len(heading.group("marks"))
        title = _identity_part(heading.group("title"))
        if section_start is None and level == 2 and title == _COVERAGE_HEADING:
            section_start = index + 1
            continue
        if section_start is not None and level <= 2:
            section_end = index
            break
    if section_start is None:
        return [], ["exploration coverage section is missing"]

    header_index: int | None = None
    for index in range(section_start, section_end):
        cells = _split_markdown_row(lines[index])
        if cells is not None and tuple(cell.casefold() for cell in cells) == _COVERAGE_HEADER:
            header_index = index
            break
    if header_index is None or header_index + 1 >= section_end:
        return [], ["exploration coverage header is missing or malformed"]
    separator = _split_markdown_row(lines[header_index + 1])
    if separator is None or not _is_separator(separator, len(_COVERAGE_HEADER)):
        return [], ["exploration coverage header separator is missing or malformed"]

    rows: list[tuple[int, str, tuple[str, ...]]] = []
    for index in range(header_index + 2, section_end):
        raw = lines[index]
        cells = _split_markdown_row(raw)
        if cells is None:
            if raw.strip():
                break
            if rows:
                break
            continue
        if len(cells) != len(_COVERAGE_HEADER):
            # A table row in the authoritative table with the wrong shape is
            # visible debt; callers must not silently realign its cells.
            return rows, [f"malformed exploration coverage row at line {index + 1}"]
        rows.append((index + 1, raw, cells))
    return rows, []


def _commitment_source_rows(
    text: str,
) -> tuple[list[tuple[int, str, tuple[str, ...]]], list[str]]:
    """Return the exact per-clear commitment declarations under their own H2."""

    lines = text.splitlines()
    section_start: int | None = None
    section_end = len(lines)
    for index, line in enumerate(lines):
        heading = _HEADING_RE.match(line.strip())
        if not heading:
            continue
        level = len(heading.group("marks"))
        title = _identity_part(heading.group("title"))
        if section_start is None and level == 2 and title == _COMMITMENT_HEADING:
            section_start = index + 1
            continue
        if section_start is not None and level <= 2:
            section_end = index
            break
    if section_start is None:
        return [], ["exploration invariant commitment section is missing"]
    header_index: int | None = None
    for index in range(section_start, section_end):
        cells = _split_markdown_row(lines[index])
        if cells is not None and tuple(cell.casefold() for cell in cells) == _COMMITMENT_HEADER:
            header_index = index
            break
    if header_index is None or header_index + 1 >= section_end:
        return [], ["exploration invariant commitment header is missing or malformed"]
    separator = _split_markdown_row(lines[header_index + 1])
    if separator is None or not _is_separator(separator, len(_COMMITMENT_HEADER)):
        return [], ["exploration invariant commitment separator is missing or malformed"]
    rows: list[tuple[int, str, tuple[str, ...]]] = []
    for index in range(header_index + 2, section_end):
        raw = lines[index]
        cells = _split_markdown_row(raw)
        if cells is None:
            if raw.strip() or rows:
                break
            continue
        if len(cells) != len(_COMMITMENT_HEADER):
            return rows, [f"malformed invariant commitment row at line {index + 1}"]
        rows.append((index + 1, raw, cells))
    return rows, []


def _canonical_prior_reference(
    evidence: str,
    canonical_prior_ids: Mapping[str, str],
) -> str:
    # Match only caller-supplied identities.  A finding-shaped token in prose
    # is not proof that the referenced canonical record exists.
    for alias in sorted(canonical_prior_ids, key=lambda item: (-len(str(item)), str(item))):
        alias_s = str(alias).strip()
        canonical = str(canonical_prior_ids[alias]).strip()
        if not alias_s or not canonical:
            continue
        pattern = re.compile(
            rf"(?<![A-Za-z0-9_-]){re.escape(alias_s)}(?![A-Za-z0-9_-])",
            re.IGNORECASE | re.ASCII,
        )
        if pattern.search(evidence):
            return canonical
    return ""


def _production_reference(evidence: str, production_root: Path) -> str:
    try:
        root = production_root.resolve(strict=True)
    except OSError:
        return ""
    for match in _LOCUS_RE.finditer(evidence):
        relative_text = match.group("path").strip(" `\"'")
        # Avoid treating the words before a path as part of a space-containing
        # path.  Prefer the shortest suffix that resolves to a real file.
        candidates = [relative_text]
        words = relative_text.split()
        candidates.extend(" ".join(words[index:]) for index in range(1, len(words)))
        for candidate in candidates:
            normalized = candidate.replace("\\", "/")
            relative = Path(normalized)
            if relative.is_absolute() or any(part == ".." for part in relative.parts):
                continue
            try:
                target = (root / relative).resolve(strict=True)
                target.relative_to(root)
            except (OSError, ValueError):
                continue
            if not target.is_file():
                continue
            try:
                line_count = len(target.read_bytes().splitlines())
            except OSError:
                continue
            line = int(match.group("line"))
            if line <= line_count:
                return f"{relative.as_posix()}:L{line}"
    return ""


def _resolve_evidence(
    evidence: str,
    *,
    production_root: Path,
    canonical_prior_ids: Mapping[str, str],
) -> tuple[str, str]:
    production = _production_reference(evidence, production_root)
    if production:
        return "PRODUCTION_LOCUS", production
    prior = _canonical_prior_reference(evidence, canonical_prior_ids)
    if prior:
        return "CANONICAL_PRIOR", prior
    return "INVALID_CLEAR", ""


def resolve_clear_evidence(
    evidence: str,
    *,
    production_root: str | Path,
    canonical_prior_ids: Mapping[str, str],
) -> tuple[str, str]:
    """Public, judgment-free evidence resolver shared by typed consumers."""
    return _resolve_evidence(
        evidence,
        production_root=Path(production_root),
        canonical_prior_ids=canonical_prior_ids,
    )


def _instance_is_named(source_finding: str, axis: str, instance: str) -> bool:
    empty_markers = {"", "-", "—", "n/a", "na", "none"}
    generic_instances = empty_markers | {
        "direction", "similar-mechanism", "similar mechanism", "neighbour", "neighbor"
    }
    return (
        _identity_part(source_finding) not in empty_markers
        and _identity_part(axis) not in empty_markers
        and _identity_part(instance) not in generic_instances
    )


def _action_id(value: str, *, source_finding: str = "") -> str:
    for match in _ACTION_ID_RE.finditer(value.upper()):
        candidate = match.group(1)
        if candidate.casefold() != source_finding.casefold():
            return candidate
    return ""


def _receipt_unsigned(receipt: LifecycleReceipt) -> dict[str, Any]:
    payload = asdict(receipt)
    payload.pop("receipt_hash", None)
    return payload


def _with_receipt_hash(receipt: LifecycleReceipt) -> LifecycleReceipt:
    return replace(receipt, receipt_hash=_digest(_receipt_unsigned(receipt)))


def _status(
    *,
    obligations: Sequence[ExplorationObligation],
    additive_actions: Sequence[AdditiveAction],
    debt: Sequence[str],
    conflicts: Sequence[DuplicateConflict],
    repair_attempts: int,
) -> str:
    if obligations:
        if repair_attempts == 0 and not debt and not conflicts and all(
            row.disposition in {
                "INVALID_CLEAR", "MISSING_COMMITTED_INVARIANT"
            }
            for row in obligations
        ):
            return "REPAIR_REQUIRED"
        return "DEGRADED"
    if debt or conflicts:
        return "DEGRADED"
    if additive_actions:
        return "ADDITIVE"
    return "CLEAN"


def _exploration_invariant_commitments(
    *,
    text: str,
    artifact_sha256: str,
    rows: Sequence[ExplorationRow],
) -> tuple[
    tuple[InvariantCommitment, ...],
    tuple[ExplorationObligation, ...],
    tuple[str, ...],
    str,
]:
    declaration_rows, declaration_debt = _commitment_source_rows(text)
    declaration_map: dict[tuple[str, str, str], list[tuple[str, str]]] = {}
    for _line, raw, cells in declaration_rows:
        finding, axis, instance, declaration, reason = cells
        identity = (
            _identity_part(finding),
            _identity_part(axis),
            _identity_part(instance),
        )
        declaration_map.setdefault(identity, []).append(
            (declaration, reason + "\0" + _bytes_digest(raw.encode("utf-8")))
        )

    denominator_rows = [
        row
        for row in rows
        if row.disposition in _CLEAR_DISPOSITIONS
        and row.resolution_kind == "PRODUCTION_LOCUS"
    ]
    # An honestly empty denominator is authoritative without requiring an
    # otherwise meaningless empty model-authored table.
    if not denominator_rows:
        return (), (), (), "NOT_APPLICABLE"

    blocks, duplicate_block_ids = _ci_blocks(text)
    blocks_by_id: dict[str, list[dict[str, str]]] = {}
    for block in blocks:
        blocks_by_id.setdefault(block["ci_id"], []).append(block)
    declared_ci_ids: list[str] = []
    commitments: list[InvariantCommitment] = []
    obligations: list[ExplorationObligation] = []
    used_identities: set[tuple[str, str, str]] = set()

    for row in sorted(denominator_rows, key=lambda item: item.obligation_id):
        identity = (
            _identity_part(row.source_finding),
            _identity_part(row.axis),
            _identity_part(row.instance),
        )
        used_identities.add(identity)
        declarations = declaration_map.get(identity, [])
        declaration = declarations[0][0] if len(declarations) == 1 else ""
        reason_field = declarations[0][1].split("\0", 1)[0] if len(declarations) == 1 else ""
        values: dict[str, str] = {
            "status": "DEBT",
            "reason": (
                "missing invariant commitment declaration"
                if not declarations
                else "duplicate invariant commitment declarations"
            ),
            "ci_id": "",
            "ci_block_sha256": "",
            "locus": "",
            "shape": "",
            "assertion": "",
            "falsify_class": "",
            "provenance": "",
        }
        if len(declarations) == 1:
            if _CI_NOT_REQUIRED_RE.fullmatch(declaration):
                if _normal(reason_field):
                    values.update(
                        status="NOT_REQUIRED_NON_VALUE_BEARING",
                        reason=_normal(reason_field),
                    )
                else:
                    values["reason"] = "non-value-bearing exemption lacks a reason"
            else:
                declared_match = _CI_COMMITMENT_RE.fullmatch(declaration)
                ci_id = (
                    _normal(declared_match.group("id")).upper()
                    if declared_match
                    else ""
                )
                if not ci_id or not _CI_ID_RE.fullmatch(ci_id):
                    values["reason"] = "invariant commitment declaration is malformed"
                else:
                    declared_ci_ids.append(ci_id)
                    matches = blocks_by_id.get(ci_id, [])
                    if ci_id in duplicate_block_ids or len(matches) != 1:
                        values["reason"] = "committed-invariant identity is missing or duplicated"
                    else:
                        block = matches[0]
                        provenance = _identity_part(block["provenance"])
                        malformed: list[str] = []
                        if not _production_ci_locus(block["locus"]):
                            malformed.append("production locus")
                        if block["shape"] not in _CI_SHAPES:
                            malformed.append("shape")
                        if not _normal(block["assertion"]):
                            malformed.append("assertion")
                        if block["falsify_class"] not in _CI_FALSIFY_CLASSES:
                            malformed.append("falsify class")
                        if (
                            _identity_part(row.source_finding) not in provenance
                            or _identity_part(row.instance) not in provenance
                        ):
                            malformed.append("provenance binding")
                        if malformed:
                            values["reason"] = (
                                "invalid committed-invariant " + ", ".join(malformed)
                            )
                        else:
                            values.update(
                                status="COMPLETE",
                                reason="",
                                **{
                                    key: block[key]
                                    for key in (
                                        "ci_id", "ci_block_sha256", "locus",
                                        "shape", "assertion", "falsify_class",
                                        "provenance",
                                    )
                                },
                            )

        unsigned = {
            "obligation_id": row.obligation_id,
            "source_finding": row.source_finding,
            "axis": row.axis,
            "instance": row.instance,
            "source_row_sha256": row.source_row_sha256,
            "source_artifact_sha256": artifact_sha256,
            "declaration": declaration,
            **values,
        }
        commitment = InvariantCommitment(
            **unsigned,
            binding_digest=_digest(unsigned),
        )
        commitments.append(commitment)
        if commitment.status == "DEBT":
            obligations.append(
                ExplorationObligation(
                    obligation_id=row.obligation_id,
                    source_finding=row.source_finding,
                    axis=row.axis,
                    instance=row.instance,
                    disposition="MISSING_COMMITTED_INVARIANT",
                    reason=commitment.reason,
                    original_disposition=row.disposition,
                    original_evidence=row.evidence,
                    artifact_sha256=artifact_sha256,
                    source_row_sha256=row.source_row_sha256,
                    source_row_sha256s=(row.source_row_sha256,),
                    source_line=row.source_line,
                )
            )

    reused_ids = {
        ci_id for ci_id in declared_ci_ids if declared_ci_ids.count(ci_id) != 1
    }
    if reused_ids:
        revised: list[InvariantCommitment] = []
        for commitment in commitments:
            if commitment.ci_id not in reused_ids:
                revised.append(commitment)
                continue
            unsigned = asdict(commitment)
            unsigned.pop("binding_digest", None)
            unsigned.update(
                status="DEBT",
                reason="committed-invariant identity is reused by multiple clears",
            )
            revised_commitment = InvariantCommitment(
                **unsigned, binding_digest=_digest(unsigned)
            )
            revised.append(revised_commitment)
            if commitment.obligation_id not in {
                item.obligation_id for item in obligations
            }:
                source = next(
                    row for row in denominator_rows
                    if row.obligation_id == commitment.obligation_id
                )
                obligations.append(
                    ExplorationObligation(
                        obligation_id=source.obligation_id,
                        source_finding=source.source_finding,
                        axis=source.axis,
                        instance=source.instance,
                        disposition="MISSING_COMMITTED_INVARIANT",
                        reason=revised_commitment.reason,
                        original_disposition=source.disposition,
                        original_evidence=source.evidence,
                        artifact_sha256=artifact_sha256,
                        source_row_sha256=source.source_row_sha256,
                        source_row_sha256s=(source.source_row_sha256,),
                        source_line=source.source_line,
                    )
                )
        commitments = revised

    unused = set(declaration_map) - used_identities
    debt = list(declaration_debt)
    debt.extend(
        "invariant commitment row has no exact exploration clear identity: "
        + " / ".join(identity)
        for identity in sorted(unused)
    )
    status = "DEBT" if obligations or debt else "COMPLETE"
    return (
        tuple(sorted(commitments, key=lambda item: item.obligation_id)),
        tuple(sorted(obligations, key=lambda item: item.obligation_id)),
        tuple(dict.fromkeys(debt)),
        status,
    )


def compile_initial_receipt(
    source_artifact: str | Path,
    *,
    production_root: str | Path,
    canonical_prior_ids: Mapping[str, str],
) -> LifecycleReceipt:
    """Compile the first accepted exploration artifact into typed state."""
    path = Path(source_artifact)
    try:
        artifact_bytes = path.read_bytes()
        text = artifact_bytes.decode("utf-8")
    except (OSError, UnicodeError) as exc:
        raise ExplorationClearError(f"cannot read exploration artifact: {exc}") from exc
    artifact_sha = _bytes_digest(artifact_bytes)
    raw_rows, parse_debt = _coverage_source_rows(text)

    parsed: list[ExplorationRow] = []
    for line_number, raw_line, cells in raw_rows:
        source_finding, axis, instance, disposition, evidence = cells
        oid = _obligation_id(source_finding, axis, instance)
        disposition_u = disposition.upper()
        resolution_kind = "IGNORED"
        resolved = ""
        if disposition_u in _CLEAR_DISPOSITIONS:
            if _instance_is_named(source_finding, axis, instance):
                resolution_kind, resolved = _resolve_evidence(
                    evidence,
                    production_root=Path(production_root),
                    canonical_prior_ids=canonical_prior_ids,
                )
            else:
                resolution_kind = "INVALID_CLEAR"
        elif disposition_u in _ADDITIVE_DISPOSITIONS:
            resolution_kind = "ADDITIVE_ACTION" if _action_id(
                evidence, source_finding=source_finding
            ) else "UNRESOLVED"
        elif disposition_u in _UNRESOLVED_DISPOSITIONS:
            resolution_kind = "UNRESOLVED"
        else:
            resolution_kind = "UNRESOLVED"
        parsed.append(
            ExplorationRow(
                source_finding=source_finding,
                axis=axis,
                instance=instance,
                disposition=disposition_u,
                evidence=evidence,
                source_line=line_number,
                source_row_sha256=_bytes_digest(raw_line.encode("utf-8")),
                artifact_sha256=artifact_sha,
                obligation_id=oid,
                resolution_kind=resolution_kind,
                resolved_reference=resolved,
            )
        )

    groups: dict[str, list[ExplorationRow]] = {}
    for row in parsed:
        groups.setdefault(row.obligation_id, []).append(row)

    rows: list[ExplorationRow] = []
    obligations: list[ExplorationObligation] = []
    conflicts: list[DuplicateConflict] = []
    actions: list[AdditiveAction] = []
    debt = list(parse_debt)
    for oid in sorted(groups):
        members = groups[oid]
        distinct = {
            (row.disposition, row.evidence, row.source_row_sha256) for row in members
        }
        semantic = {(row.disposition, row.evidence) for row in members}
        first = members[0]
        row_hashes = tuple(sorted({row.source_row_sha256 for row in members}))
        if len(semantic) > 1:
            conflict = DuplicateConflict(
                obligation_id=oid,
                source_finding=first.source_finding,
                axis=first.axis,
                instance=first.instance,
                dispositions=tuple(sorted({row.disposition for row in members})),
                evidence_values=tuple(sorted({row.evidence for row in members})),
                source_row_sha256s=row_hashes,
            )
            conflicts.append(conflict)
            conflict_row = replace(first, resolution_kind="UNRESOLVED_CONFLICT", resolved_reference="")
            rows.append(conflict_row)
            obligations.append(
                ExplorationObligation(
                    obligation_id=oid,
                    source_finding=first.source_finding,
                    axis=first.axis,
                    instance=first.instance,
                    disposition="UNRESOLVED_CONFLICT",
                    reason="conflicting duplicate coverage rows",
                    original_disposition=first.disposition,
                    original_evidence=first.evidence,
                    artifact_sha256=artifact_sha,
                    source_row_sha256=first.source_row_sha256,
                    source_row_sha256s=row_hashes,
                    source_line=first.source_line,
                )
            )
            debt.append(f"conflicting duplicate exploration identity {oid}")
            continue

        # Exact duplicate projections are one semantic row, not extra work.
        del distinct
        rows.append(first)
        if first.resolution_kind in {"INVALID_CLEAR", "UNRESOLVED"}:
            obligations.append(
                ExplorationObligation(
                    obligation_id=oid,
                    source_finding=first.source_finding,
                    axis=first.axis,
                    instance=first.instance,
                    disposition=first.resolution_kind,
                    reason=(
                        "clear lacks a canonical prior referent or real production locus"
                        if first.resolution_kind == "INVALID_CLEAR"
                        else "exploration row is unresolved"
                    ),
                    original_disposition=first.disposition,
                    original_evidence=first.evidence,
                    artifact_sha256=artifact_sha,
                    source_row_sha256=first.source_row_sha256,
                    source_row_sha256s=row_hashes,
                    source_line=first.source_line,
                )
            )
        elif first.resolution_kind == "ADDITIVE_ACTION":
            action_id = _action_id(first.evidence, source_finding=first.source_finding)
            actions.append(
                AdditiveAction(
                    action_id=action_id,
                    obligation_id=oid,
                    source_finding=first.source_finding,
                    axis=first.axis,
                    instance=first.instance,
                    evidence=first.evidence,
                    rationale="additive action declared by exploration producer",
                    artifact_sha256=first.artifact_sha256,
                    source_row_sha256=first.source_row_sha256,
                    source_line=first.source_line,
                )
            )

    obligations.sort(key=lambda item: item.obligation_id)
    actions.sort(key=lambda item: (item.action_id, item.obligation_id))
    (
        invariant_commitments,
        invariant_obligations,
        invariant_debt,
        invariant_status,
    ) = _exploration_invariant_commitments(
        text=text,
        artifact_sha256=artifact_sha,
        rows=rows,
    )
    existing_obligations = {item.obligation_id for item in obligations}
    obligations.extend(
        item
        for item in invariant_obligations
        if item.obligation_id not in existing_obligations
    )
    obligations.sort(key=lambda item: item.obligation_id)
    debt.extend(invariant_debt)
    receipt = LifecycleReceipt(
        schema_version=RECEIPT_SCHEMA,
        source_artifact=str(path.resolve()),
        artifact_sha256=artifact_sha,
        source_row_count=len(raw_rows),
        rows=tuple(rows),
        obligations=tuple(obligations),
        conflicts=tuple(conflicts),
        additive_actions=tuple(actions),
        invariant_commitment_status=invariant_status,
        invariant_commitment_denominator=len(invariant_commitments),
        invariant_commitments=invariant_commitments,
        debt=tuple(dict.fromkeys(debt)),
        status=_status(
            obligations=obligations,
            additive_actions=actions,
            debt=debt,
            conflicts=conflicts,
            repair_attempts=0,
        ),
        repair_attempts=0,
        repair_response_sha256="",
        receipt_hash="",
    )
    return _with_receipt_hash(receipt)


def _plan_unsigned(plan: RepairPlan) -> dict[str, Any]:
    payload = asdict(plan)
    payload.pop("plan_hash", None)
    return payload


def _plan_matches_receipt(plan: RepairPlan, receipt: LifecycleReceipt) -> bool:
    expected_ids = tuple(
        row.obligation_id
        for row in sorted(receipt.obligations, key=lambda item: item.obligation_id)
    )
    return (
        plan.schema_version == REPAIR_PLAN_SCHEMA
        and plan.attempt == 1
        and plan.source_receipt_hash == receipt.receipt_hash
        and plan.source_artifact_sha256 == receipt.artifact_sha256
        and plan.plan_hash == _digest(_plan_unsigned(plan))
        and plan.obligation_ids == expected_ids
        and tuple(item.obligation_id for item in plan.items) == plan.obligation_ids
    )


def build_repair_plan(
    receipt: LifecycleReceipt,
    *,
    prior_plan: RepairPlan | None = None,
) -> RepairPlan | None:
    """Return the sole allowed targeted plan, or ``None`` after one attempt."""
    if receipt.repair_attempts != 0 or not receipt.obligations or prior_plan is not None:
        return None
    items = tuple(
        RepairItem(
            obligation_id=row.obligation_id,
            source_finding=row.source_finding,
            axis=row.axis,
            instance=row.instance,
            original_disposition=row.original_disposition,
            original_evidence=row.original_evidence,
            artifact_sha256=row.artifact_sha256,
            source_row_sha256s=row.source_row_sha256s,
        )
        for row in sorted(receipt.obligations, key=lambda item: item.obligation_id)
    )
    ids = tuple(item.obligation_id for item in items)
    plan_id = "ECRP-" + _digest(
        {"receipt_hash": receipt.receipt_hash, "obligation_ids": ids, "attempt": 1}
    )[:24].upper()
    plan = RepairPlan(
        schema_version=REPAIR_PLAN_SCHEMA,
        plan_id=plan_id,
        attempt=1,
        source_receipt_hash=receipt.receipt_hash,
        source_artifact_sha256=receipt.artifact_sha256,
        obligation_ids=ids,
        items=items,
        plan_hash="",
    )
    return replace(plan, plan_hash=_digest(_plan_unsigned(plan)))


def _repair_response_rows(text: str) -> tuple[str, str, list[tuple[str, ...]], list[str]]:
    lines = text.splitlines()
    plan_id = ""
    plan_hash = ""
    plan_ids: list[str] = []
    plan_hashes: list[str] = []
    for line in lines:
        match = re.match(r"^\s*\*\*Plan ID\*\*\s*:\s*(\S+)\s*$", line, re.IGNORECASE)
        if match:
            plan_ids.append(match.group(1))
        match = re.match(r"^\s*\*\*Plan Hash\*\*\s*:\s*([0-9a-fA-F]+)\s*$", line, re.IGNORECASE)
        if match:
            plan_hashes.append(match.group(1).lower())
    metadata_debt: list[str] = []
    if len(set(plan_ids)) > 1 or len(plan_ids) > 1:
        metadata_debt.append("repair response has duplicate or conflicting Plan ID metadata")
    if len(set(plan_hashes)) > 1 or len(plan_hashes) > 1:
        metadata_debt.append("repair response has duplicate or conflicting Plan Hash metadata")
    if len(plan_ids) == 1:
        plan_id = plan_ids[0]
    if len(plan_hashes) == 1:
        plan_hash = plan_hashes[0]

    start: int | None = None
    end = len(lines)
    for index, line in enumerate(lines):
        heading = _HEADING_RE.match(line.strip())
        if not heading:
            continue
        level = len(heading.group("marks"))
        if start is None and level == 2 and _identity_part(heading.group("title")) == "repair dispositions":
            start = index + 1
            continue
        if start is not None and level <= 2:
            end = index
            break
    expected = ("obligation id", "disposition", "evidence", "action id", "rationale")
    if start is None:
        return plan_id, plan_hash, [], [*metadata_debt, "repair dispositions section is missing"]
    header: int | None = None
    for index in range(start, end):
        cells = _split_markdown_row(lines[index])
        if cells is not None and tuple(cell.casefold() for cell in cells) == expected:
            header = index
            break
    if header is None or header + 1 >= end:
        return plan_id, plan_hash, [], [*metadata_debt, "repair disposition header is missing or malformed"]
    separator = _split_markdown_row(lines[header + 1])
    if separator is None or not _is_separator(separator, len(expected)):
        return plan_id, plan_hash, [], [*metadata_debt, "repair disposition separator is missing or malformed"]
    rows: list[tuple[str, ...]] = []
    debt: list[str] = list(metadata_debt)
    for index in range(header + 2, end):
        cells = _split_markdown_row(lines[index])
        if cells is None:
            if lines[index].strip() or rows:
                break
            continue
        if len(cells) != len(expected):
            debt.append(f"malformed repair disposition at line {index + 1}")
            continue
        rows.append(cells)
    return plan_id, plan_hash, rows, debt


def _unresolved(row: ExplorationObligation, reason: str) -> ExplorationObligation:
    return replace(row, disposition="UNRESOLVED", reason=reason)


def reconcile_repair_attempt(
    receipt: LifecycleReceipt,
    plan: RepairPlan,
    response: str,
    *,
    production_root: str | Path,
    canonical_prior_ids: Mapping[str, str],
) -> LifecycleReceipt:
    """Reconcile one response mechanically; producer prose has no veto power."""
    if receipt.repair_attempts != 0:
        raise ExplorationClearError("exploration-clear repair was already attempted")
    if not _plan_matches_receipt(plan, receipt):
        raise ExplorationClearError("repair plan does not bind the current receipt exactly")

    plan_id, plan_hash, response_rows, response_debt = _repair_response_rows(response)
    debt = list(receipt.debt) + response_debt
    binding_ok = plan_id == plan.plan_id and plan_hash == plan.plan_hash
    if not binding_ok:
        debt.append("repair response does not bind the exact plan ID and hash")

    expected = {row.obligation_id: row for row in receipt.obligations}
    seen: dict[str, tuple[str, ...]] = {}
    duplicate_ids: set[str] = set()
    for cells in response_rows:
        oid = cells[0]
        if oid not in expected:
            debt.append(f"unexpected obligation {oid or '<blank>'} in repair response")
            continue
        if oid in seen:
            duplicate_ids.add(oid)
            debt.append(f"duplicate repair disposition for obligation {oid}")
            continue
        seen[oid] = cells
    for oid in sorted(set(expected) - set(seen)):
        debt.append(f"missing repair disposition for obligation {oid}")

    remaining: list[ExplorationObligation] = []
    actions = list(receipt.additive_actions)
    if not binding_ok:
        remaining = [_unresolved(row, "repair response binding mismatch") for row in receipt.obligations]
    else:
        for oid in sorted(expected):
            obligation = expected[oid]
            cells = seen.get(oid)
            if cells is None or oid in duplicate_ids:
                remaining.append(_unresolved(obligation, "repair response is missing or ambiguous"))
                continue
            _, disposition, evidence, action_id, rationale = cells
            disposition_u = disposition.upper()
            if disposition_u == "CLEAR":
                if obligation.disposition == "MISSING_COMMITTED_INVARIANT":
                    remaining.append(
                        _unresolved(
                            obligation,
                            "missing committed invariant cannot be repaired into another clear",
                        )
                    )
                else:
                    kind, resolved = _resolve_evidence(
                        evidence,
                        production_root=Path(production_root),
                        canonical_prior_ids=canonical_prior_ids,
                    )
                    if kind == "INVALID_CLEAR":
                        remaining.append(_unresolved(obligation, "repair supplied no exact resolvable evidence"))
                    # Exact mechanical evidence closes the obligation.  The model's
                    # stated rationale is deliberately not an adjudication input.
                    del resolved
            elif disposition_u in {"ADD", "ADDITIVE"}:
                normalized_action = _action_id(action_id, source_finding=obligation.source_finding)
                if not normalized_action or normalized_action != action_id.upper():
                    remaining.append(_unresolved(obligation, "repair ADD lacks one exact action identity"))
                else:
                    actions.append(
                        AdditiveAction(
                            action_id=normalized_action,
                            obligation_id=oid,
                            source_finding=obligation.source_finding,
                            axis=obligation.axis,
                            instance=obligation.instance,
                            evidence=evidence,
                            rationale=rationale,
                            artifact_sha256=obligation.artifact_sha256,
                            source_row_sha256=obligation.source_row_sha256,
                            source_line=obligation.source_line,
                        )
                    )
            elif disposition_u in {"UNRESOLVED", "UNAVAILABLE"}:
                remaining.append(
                    replace(
                        obligation,
                        disposition=disposition_u,
                        reason=rationale or "repair did not establish exact evidence",
                    )
                )
            else:
                debt.append(f"unsupported repair disposition {disposition or '<blank>'} for {oid}")
                remaining.append(_unresolved(obligation, "unsupported repair disposition"))

    # A repeated action identity with divergent obligation lineage is debt and
    # remains independent work; no arbitrary action wins.
    action_groups: dict[str, list[AdditiveAction]] = {}
    for action in actions:
        action_groups.setdefault(action.action_id, []).append(action)
    unique_actions: list[AdditiveAction] = []
    for action_id in sorted(action_groups):
        members = action_groups[action_id]
        if len({member.obligation_id for member in members}) > 1:
            debt.append(f"conflicting duplicate additive action identity {action_id}")
            for member in members:
                source = expected.get(member.obligation_id)
                if source is not None and source.obligation_id not in {
                    row.obligation_id for row in remaining
                }:
                    remaining.append(_unresolved(source, "additive action identity conflicts with another obligation"))
            continue
        unique_actions.append(members[0])

    remaining.sort(key=lambda item: item.obligation_id)
    additive_obligation_ids = {item.obligation_id for item in unique_actions}
    reconciled_commitments: list[InvariantCommitment] = []
    for commitment in receipt.invariant_commitments:
        if (
            commitment.status == "DEBT"
            and commitment.obligation_id in additive_obligation_ids
        ):
            unsigned = asdict(commitment)
            unsigned.pop("binding_digest", None)
            unsigned.update(
                status="REOPENED_AS_ADDITIVE",
                reason="missing commitment was reopened as an additive candidate",
            )
            commitment = InvariantCommitment(
                **unsigned, binding_digest=_digest(unsigned)
            )
        reconciled_commitments.append(commitment)
    invariant_status = (
        "DEBT"
        if any(item.status == "DEBT" for item in reconciled_commitments)
        else "REOPENED"
        if any(
            item.status == "REOPENED_AS_ADDITIVE"
            for item in reconciled_commitments
        )
        else receipt.invariant_commitment_status
    )
    repaired = replace(
        receipt,
        obligations=tuple(remaining),
        additive_actions=tuple(unique_actions),
        invariant_commitment_status=invariant_status,
        invariant_commitments=tuple(reconciled_commitments),
        debt=tuple(dict.fromkeys(debt)),
        status=_status(
            obligations=remaining,
            additive_actions=unique_actions,
            debt=debt,
            conflicts=(),  # original conflicts are provenance, not an open-state override
            repair_attempts=1,
        ),
        repair_attempts=1,
        repair_response_sha256=_bytes_digest(response.encode("utf-8")),
        receipt_hash="",
    )
    return _with_receipt_hash(repaired)


def record_repair_unavailable(
    receipt: LifecycleReceipt,
    plan: RepairPlan,
    *,
    reason: str,
) -> LifecycleReceipt:
    """Record timeout/unavailability as durable, haltless completeness debt."""
    if receipt.repair_attempts != 0:
        raise ExplorationClearError("exploration-clear repair was already attempted")
    if not _plan_matches_receipt(plan, receipt):
        raise ExplorationClearError("repair plan does not bind the current receipt exactly")
    reason_n = _normal(reason).upper()
    if not reason_n:
        raise ExplorationClearError("repair unavailability requires a reason")
    obligations = tuple(
        replace(row, disposition="UNAVAILABLE", reason=f"repair unavailable: {reason_n}")
        for row in receipt.obligations
    )
    debt = tuple(dict.fromkeys((*receipt.debt, f"exploration-clear repair unavailable: {reason_n}")))
    result = replace(
        receipt,
        obligations=obligations,
        debt=debt,
        status="DEGRADED",
        repair_attempts=1,
        repair_response_sha256="",
        receipt_hash="",
    )
    return _with_receipt_hash(result)


def obligation_queue(receipt: LifecycleReceipt) -> dict[str, Any]:
    """Return the exact independent-consumer denominator and tail."""
    items = [
        {
            "obligation_id": row.obligation_id,
            "source_finding": row.source_finding,
            "axis": row.axis,
            "instance": row.instance,
            "disposition": row.disposition,
            "reason": row.reason,
            "original_disposition": row.original_disposition,
            "original_evidence": row.original_evidence,
            "artifact_sha256": row.artifact_sha256,
            "source_row_sha256": row.source_row_sha256,
            "source_row_sha256s": list(row.source_row_sha256s),
            "source_line": row.source_line,
            "requires_independent_consumer": True,
        }
        for row in sorted(receipt.obligations, key=lambda item: item.obligation_id)
    ]
    payload: dict[str, Any] = {
        "schema_version": OBLIGATION_QUEUE_SCHEMA,
        "source_receipt_hash": receipt.receipt_hash,
        "source_artifact_sha256": receipt.artifact_sha256,
        "count": len(items),
        "tail": items[-1]["obligation_id"] if items else "",
        "items": items,
    }
    payload["queue_hash"] = _digest(payload)
    return payload


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


def _receipt_payload(receipt: LifecycleReceipt) -> dict[str, Any]:
    payload = asdict(receipt)
    if receipt.schema_version != RECEIPT_SCHEMA:
        raise ExplorationClearError("exploration-clear receipt schema mismatch")
    if receipt.receipt_hash != _digest(_receipt_unsigned(receipt)):
        raise ExplorationClearError("exploration-clear receipt digest mismatch")
    return payload


def _plan_payload(plan: RepairPlan) -> dict[str, Any]:
    payload = asdict(plan)
    if plan.schema_version != REPAIR_PLAN_SCHEMA:
        raise ExplorationClearError("exploration-clear repair plan schema mismatch")
    if plan.plan_hash != _digest(_plan_unsigned(plan)):
        raise ExplorationClearError("exploration-clear repair plan digest mismatch")
    return payload


def write_lifecycle_artifacts(
    output_directory: str | Path,
    receipt: LifecycleReceipt,
    *,
    plan: RepairPlan | None = None,
) -> tuple[Path, ...]:
    """Atomically dual-write typed state; never touch inventory/report files."""
    root = Path(output_directory)
    root.mkdir(parents=True, exist_ok=True)
    receipt_path = root / RECEIPT_NAME
    queue_path = root / OBLIGATION_QUEUE_NAME
    _write_json_if_changed(receipt_path, _receipt_payload(receipt))
    written: list[Path] = [receipt_path]
    if plan is not None:
        plan_path = root / REPAIR_PLAN_NAME
        _write_json_if_changed(plan_path, _plan_payload(plan))
        written.append(plan_path)
    _write_json_if_changed(queue_path, obligation_queue(receipt))
    written.append(queue_path)
    legacy = root / LEGACY_SENTINEL_NAME
    try:
        legacy.unlink()
    except FileNotFoundError:
        pass
    except OSError as exc:
        # Cleanup failure must not halt or erase the typed authority.  The
        # surviving legacy sentinel is rejected by the live resume validator
        # and becomes visible phase debt instead of an uncaught driver stop.
        # The JSON lifecycle artifacts above are already atomically durable.
        del exc
    return tuple(written)


def _require_exact_keys(payload: Mapping[str, Any], keys: Iterable[str], what: str) -> None:
    expected = set(keys)
    actual = set(payload)
    if actual != expected:
        raise ExplorationClearError(
            f"{what} fields are not exact (missing={sorted(expected - actual)}, "
            f"extra={sorted(actual - expected)})"
        )


def _tuple_records(
    values: Any,
    cls: type[Any],
    *,
    tuple_fields: Sequence[str] = (),
) -> tuple[Any, ...]:
    if not isinstance(values, list):
        raise ExplorationClearError(f"{cls.__name__} collection must be a list")
    result: list[Any] = []
    expected = tuple(cls.__dataclass_fields__)
    for raw in values:
        if not isinstance(raw, dict):
            raise ExplorationClearError(f"{cls.__name__} row must be an object")
        _require_exact_keys(raw, expected, cls.__name__)
        converted = dict(raw)
        for field in tuple_fields:
            if not isinstance(converted[field], list):
                raise ExplorationClearError(f"{cls.__name__}.{field} must be a list")
            converted[field] = tuple(converted[field])
        result.append(cls(**converted))
    return tuple(result)


def load_lifecycle_receipt(path: str | Path) -> LifecycleReceipt:
    """Load and fail closed on schema/digest/queue-relevant tampering."""
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ExplorationClearError(f"cannot load exploration-clear receipt: {exc}") from exc
    if not isinstance(payload, dict):
        raise ExplorationClearError("exploration-clear receipt must be an object")
    _require_exact_keys(payload, LifecycleReceipt.__dataclass_fields__, "LifecycleReceipt")
    if payload.get("schema_version") != RECEIPT_SCHEMA:
        raise ExplorationClearError("exploration-clear receipt schema mismatch")
    payload = dict(payload)
    payload["rows"] = _tuple_records(payload["rows"], ExplorationRow)
    payload["obligations"] = _tuple_records(
        payload["obligations"], ExplorationObligation, tuple_fields=("source_row_sha256s",)
    )
    payload["conflicts"] = _tuple_records(
        payload["conflicts"],
        DuplicateConflict,
        tuple_fields=("dispositions", "evidence_values", "source_row_sha256s"),
    )
    payload["additive_actions"] = _tuple_records(payload["additive_actions"], AdditiveAction)
    payload["invariant_commitments"] = _tuple_records(
        payload["invariant_commitments"], InvariantCommitment
    )
    if not isinstance(payload["debt"], list):
        raise ExplorationClearError("LifecycleReceipt.debt must be a list")
    payload["debt"] = tuple(payload["debt"])
    receipt = LifecycleReceipt(**payload)
    if not _HEX_RE.fullmatch(receipt.artifact_sha256):
        raise ExplorationClearError("exploration-clear artifact digest is malformed")
    if receipt.receipt_hash != _digest(_receipt_unsigned(receipt)):
        raise ExplorationClearError("exploration-clear receipt digest mismatch")
    if receipt.invariant_commitment_denominator != len(
        receipt.invariant_commitments
    ):
        raise ExplorationClearError(
            "exploration invariant commitment denominator mismatch"
        )
    allowed_commitment_statuses = {
        "COMPLETE", "NOT_REQUIRED_NON_VALUE_BEARING", "DEBT",
        "REOPENED_AS_ADDITIVE",
    }
    for commitment in receipt.invariant_commitments:
        unsigned = asdict(commitment)
        unsigned.pop("binding_digest", None)
        if commitment.binding_digest != _digest(unsigned):
            raise ExplorationClearError(
                "exploration invariant commitment binding digest mismatch"
            )
        if commitment.source_artifact_sha256 != receipt.artifact_sha256:
            raise ExplorationClearError(
                "exploration invariant commitment source digest mismatch"
            )
        if commitment.status not in allowed_commitment_statuses:
            raise ExplorationClearError(
                "exploration invariant commitment status is invalid"
            )
        if commitment.status == "COMPLETE" and (
            not _CI_ID_RE.fullmatch(commitment.ci_id)
            or not _HEX_RE.fullmatch(commitment.ci_block_sha256)
            or not _production_ci_locus(commitment.locus)
            or commitment.shape not in _CI_SHAPES
            or not _normal(commitment.assertion)
            or commitment.falsify_class not in _CI_FALSIFY_CLASSES
        ):
            raise ExplorationClearError(
                "complete exploration invariant commitment is malformed"
            )
        if commitment.status == "NOT_REQUIRED_NON_VALUE_BEARING" and not _normal(
            commitment.reason
        ):
            raise ExplorationClearError(
                "non-value-bearing exploration exemption lacks a reason"
            )
    complete_ci_ids = [
        item.ci_id for item in receipt.invariant_commitments
        if item.status == "COMPLETE"
    ]
    if len(complete_ci_ids) != len(set(complete_ci_ids)):
        raise ExplorationClearError(
            "one committed invariant is bound to multiple exploration clears"
        )
    expected_invariant_status = (
        "NOT_APPLICABLE"
        if not receipt.invariant_commitments
        else "DEBT"
        if any(item.status == "DEBT" for item in receipt.invariant_commitments)
        else "REOPENED"
        if any(
            item.status == "REOPENED_AS_ADDITIVE"
            for item in receipt.invariant_commitments
        )
        else "COMPLETE"
    )
    if receipt.invariant_commitment_status != expected_invariant_status:
        raise ExplorationClearError(
            "exploration invariant commitment aggregate status mismatch"
        )
    if tuple(sorted(receipt.obligations, key=lambda item: item.obligation_id)) != receipt.obligations:
        raise ExplorationClearError("exploration-clear obligations are not canonically ordered")
    try:
        source_digest = _bytes_digest(Path(receipt.source_artifact).read_bytes())
    except OSError as exc:
        raise ExplorationClearError(
            f"bound exploration source artifact is unavailable: {exc}"
        ) from exc
    if source_digest != receipt.artifact_sha256:
        raise ExplorationClearError("bound exploration source artifact digest mismatch")
    return receipt


def load_repair_plan(path: str | Path) -> RepairPlan:
    """Load a persisted one-shot plan and reject shape or digest drift."""
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ExplorationClearError(f"cannot load exploration-clear repair plan: {exc}") from exc
    if not isinstance(payload, dict):
        raise ExplorationClearError("exploration-clear repair plan must be an object")
    _require_exact_keys(payload, RepairPlan.__dataclass_fields__, "RepairPlan")
    if payload.get("schema_version") != REPAIR_PLAN_SCHEMA:
        raise ExplorationClearError("exploration-clear repair plan schema mismatch")
    converted = dict(payload)
    if not isinstance(converted["obligation_ids"], list):
        raise ExplorationClearError("RepairPlan.obligation_ids must be a list")
    converted["obligation_ids"] = tuple(converted["obligation_ids"])
    converted["items"] = _tuple_records(
        converted["items"], RepairItem, tuple_fields=("source_row_sha256s",)
    )
    plan = RepairPlan(**converted)
    if plan.plan_hash != _digest(_plan_unsigned(plan)):
        raise ExplorationClearError("exploration-clear repair plan digest mismatch")
    if plan.attempt != 1:
        raise ExplorationClearError("exploration-clear repair plan must be attempt one")
    if tuple(item.obligation_id for item in plan.items) != plan.obligation_ids:
        raise ExplorationClearError("exploration-clear repair plan item denominator mismatch")
    if tuple(sorted(set(plan.obligation_ids))) != plan.obligation_ids:
        raise ExplorationClearError("exploration-clear repair plan identities are not exact")
    return plan


__all__ = [
    "AdditiveAction",
    "CANONICAL_IDENTITY_MAP_NAME",
    "CANONICAL_IDENTITY_MAP_SCHEMA",
    "CANONICAL_PRIOR_ALIAS_NAME",
    "CANONICAL_PRIOR_ALIAS_SCHEMA",
    "CanonicalPriorAuthority",
    "DuplicateConflict",
    "ExplorationClearError",
    "ExplorationObligation",
    "ExplorationRow",
    "InvariantCommitment",
    "LEGACY_SENTINEL_NAME",
    "LifecycleReceipt",
    "OBLIGATION_QUEUE_NAME",
    "OBLIGATION_QUEUE_SCHEMA",
    "RECEIPT_NAME",
    "RECEIPT_SCHEMA",
    "REPAIR_PLAN_NAME",
    "REPAIR_PLAN_SCHEMA",
    "RepairItem",
    "RepairPlan",
    "build_repair_plan",
    "compile_initial_receipt",
    "derive_canonical_prior_authority",
    "load_canonical_prior_authority",
    "load_lifecycle_receipt",
    "load_repair_plan",
    "obligation_queue",
    "reconcile_repair_attempt",
    "record_repair_unavailable",
    "write_lifecycle_artifacts",
]
