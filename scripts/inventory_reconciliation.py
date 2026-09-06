"""Exact raw-discovery -> inventory disposition reconciliation (P0-L).

The inventory synthesizer is allowed to combine corroborating candidates, but
it is not allowed to make an assigned discovery identity disappear.  This
module constructs the mechanically decidable denominator from the current
shard manifests and source artifacts, follows concrete Source-ID references
through chunk blocks into final inventory blocks, validates narrowly typed
merge/refutation authority, and preserves every unresolved source block as
human-review debt.

No percentage is an authority boundary.  A threshold may still be useful to
choose a retry strategy, but one omitted candidate and fifty omitted
candidates have the same disposition requirement here.
"""
from __future__ import annotations

import hashlib
import html
import json
import os
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable, Mapping

from finding_producer_registry import (
    ProducerResolutionError,
    materialized_producer_paths,
    producer_accepts_local_id,
    producer_for_artifact,
    registry_digest,
)
from negative_closure_policy import supporting_negative_resolution
from closure_broker_v2 import resolve_central_negative_closure
from operational_markdown import operational_markdown_field_view
from plamen_markdown import (
    MarkdownParserContractError,
    mapped_headings,
)
from plamen_parsers import _INVENTORY_SOURCE_PATTERNS, _normalize_finding_id


RECONCILIATION_SCHEMA = "plamen.inventory_reconciliation.v1"
AUTHORITY_SCHEMA = "plamen.inventory_disposition_authority.v1"
NEGATIVE_EVIDENCE_SCHEMA = "plamen.inventory_negative_evidence.v1"
RECONCILIATION_FILE = "inventory_reconciliation.json"
HUMAN_REVIEW_FILE = "inventory_reconciliation_human_review.md"
AUTHORITY_FILE = "inventory_disposition_authority.json"
REEMIT_SCHEMA = "plamen.inventory_reemit_receipt.v1"
REEMIT_FILE = "inventory_reemit_receipt.json"

_HEX_RE = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
_SOURCE_FIELD_RE = re.compile(
    r"(?ims)^[ \t]*(?:[-*][ \t]+)?\*\*Source IDs?\*\*"
    r"(?:[ \t]+\([^()\r\n]{1,160}\))?[ \t]*:[ \t]*"
    r"(?P<value>.*?)"
    r"(?=^[ \t]*(?:[-*][ \t]+)?\*\*[^*\n]+\*\*"
    r"(?:[ \t]+\([^()\r\n]{1,160}\))?[ \t]*:|^#{1,6}[ \t]+|\Z)"
)
_FIELD_RE = re.compile(
    r"(?ims)^[ \t]*(?:[-*][ \t]+)?\*\*(?P<label>[^*\n]+)\*\*"
    r"(?:[ \t]+\([^()\r\n]{1,160}\))?[ \t]*:[ \t]*"
    r"(?P<value>.*?)"
    r"(?=^[ \t]*(?:[-*][ \t]+)?\*\*[^*\n]+\*\*"
    r"(?:[ \t]+\([^()\r\n]{1,160}\))?[ \t]*:|^#{1,6}[ \t]+|\Z)"
)
_FINDING_ID_ATOM_RE = re.compile(
    r"[A-Za-z][A-Za-z0-9_-]{0,95}-\d+", re.ASCII
)
_QUALIFIED_SOURCE_ATOM_RE = re.compile(
    r"(?P<artifact>[A-Za-z0-9_.-]+(?:[\\/][A-Za-z0-9_.-]+)*\.md)"
    r"[ \t]*(?:::|#|:)[ \t]*"
    r"(?P<finding>[A-Za-z][A-Za-z0-9_-]{0,95}-\d+)",
    re.IGNORECASE | re.ASCII,
)
_MANIFEST_ROW_RE = re.compile(
    r"(?m)^\s*\|\s*`?(?P<path>[A-Za-z0-9_.\\/-]+\.md)`?\s*\|"
)
_ALLOWED_NEGATIVE_EVIDENCE_SCOPES = frozenset(
    {"IN_SCOPE_SOURCE", "IN_SCOPE_EXECUTION"}
)
_IN_SCOPE_POINTER_RE = re.compile(
    r"(?i)(?:^|\s|`)(?:[A-Za-z0-9_.-]+[\\/])*"
    r"[A-Za-z0-9_.-]+\.(?:sol|rs|go|move|cairo|vy|c|cc|cpp|h|hpp|ts|js|py)"
    r"\s*:\s*L?[1-9][0-9]*\b"
)
_FINDING_HEADING_CONTENT_RE = re.compile(
    r"^Finding[ \t]+\[(?P<finding>[^\]\r\n]+)\]"
    r"(?P<separator>[ \t]*[:=\-\u2013\u2014]*[ \t]*)"
    r"(?P<title>.*)$",
    re.IGNORECASE,
)

# Exact Unicode Default_Ignorable_Code_Point ranges. Python's stdlib exposes
# general categories but not this derived property; treating every ``Cf`` as
# ignorable is overbroad (for example U+0600 is not default-ignorable).
# These ranges are used only for rendered emptiness. When visible content is
# present, the original field spelling and Unicode remain unchanged.
_DEFAULT_IGNORABLE_RANGES = (
    (0x00AD, 0x00AD),
    (0x034F, 0x034F),
    (0x061C, 0x061C),
    (0x115F, 0x1160),
    (0x17B4, 0x17B5),
    (0x180B, 0x180F),
    (0x200B, 0x200F),
    (0x202A, 0x202E),
    (0x2060, 0x206F),
    (0x3164, 0x3164),
    (0xFE00, 0xFE0F),
    (0xFEFF, 0xFEFF),
    (0xFFA0, 0xFFA0),
    (0xFFF0, 0xFFF8),
    (0x1BCA0, 0x1BCA3),
    (0x1D173, 0x1D17A),
    (0xE0000, 0xE0FFF),
)


class InventoryReconciliationError(ValueError):
    """A typed inventory authority or receipt is structurally invalid."""


def _canonical(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _sha_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _file_sha(path: Path) -> str:
    return _sha_bytes(path.read_bytes())


def _file_sha_or_empty(path: Path) -> str:
    try:
        return _file_sha(path)
    except OSError:
        return ""


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise InventoryReconciliationError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def _strict_json(path: Path) -> dict[str, Any]:
    def _reject(value: str) -> None:
        raise InventoryReconciliationError(f"invalid JSON constant {value}")

    try:
        payload = json.loads(
            path.read_text(encoding="utf-8", errors="strict"),
            object_pairs_hook=_strict_object,
            parse_constant=_reject,
        )
    except InventoryReconciliationError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise InventoryReconciliationError(
            f"{path.name} is unreadable: {type(exc).__name__}: {exc}"
        ) from exc
    if not isinstance(payload, dict):
        raise InventoryReconciliationError(f"{path.name} must contain one object")
    return payload


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.p0l.tmp")
    with open(temporary, "wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def _safe_artifact_name(value: str) -> str | None:
    surface = (value or "").strip()
    if len(surface) >= 2 and surface.startswith("`") and surface.endswith("`"):
        surface = surface[1:-1]
    normalized = surface.replace("\\", "/")
    if (
        not normalized
        or normalized.startswith("/")
        or normalized.endswith("/")
        or ":" in normalized
        or "//" in normalized
    ):
        return None
    parts = normalized.split("/")
    if (
        any(part in {"", ".", ".."} for part in parts)
        or any(not re.fullmatch(r"[A-Za-z0-9_.-]+", part, re.ASCII) for part in parts)
        or not normalized.lower().endswith(".md")
    ):
        return None
    return normalized


def _safe_evidence_name(value: str) -> str | None:
    normalized = (value or "").strip().strip("`").replace("\\", "/")
    if not normalized or normalized.startswith("/") or ":" in normalized:
        return None
    parts = [part for part in normalized.split("/") if part]
    if (
        len(parts) != 1
        or parts[0] in {".", ".."}
        or Path(parts[0]).suffix.lower() not in {".json", ".md"}
    ):
        return None
    return parts[0]


def _manifest_assignments(root: Path) -> tuple[dict[str, tuple[str, ...]], list[str]]:
    assignments: dict[str, tuple[str, ...]] = {}
    issues: list[str] = []
    for manifest in sorted(root.glob("inventory_chunk_*.manifest.md")):
        shard = manifest.name[: -len(".manifest.md")]
        try:
            text = manifest.read_text(encoding="utf-8", errors="strict")
        except (OSError, UnicodeError) as exc:
            issues.append(
                f"{manifest.name} unreadable: {type(exc).__name__}: {exc}"
            )
            assignments[shard] = ()
            continue
        sources: list[str] = []
        for match in _MANIFEST_ROW_RE.finditer(text):
            source = _safe_artifact_name(match.group("path"))
            if source and source not in sources:
                sources.append(source)
        declared = re.search(r"(?im)^\s*[-*]?\s*Assigned\s+files\s*:\s*(\d+)\s*$", text)
        if declared and int(declared.group(1)) != len(sources):
            issues.append(
                f"{manifest.name} declares {declared.group(1)} assigned files "
                f"but enumerates {len(sources)}"
            )
        assignments[shard] = tuple(sources)
    owners: dict[str, list[str]] = defaultdict(list)
    for shard, sources in assignments.items():
        for source in sources:
            owners[source].append(shard)
    for source, shards in sorted(owners.items()):
        if len(shards) != 1:
            issues.append(
                f"source artifact {source} is assigned to multiple shards: "
                + ", ".join(sorted(shards))
            )
    return assignments, issues


def _discovery_sources(
    root: Path,
    assignments: Mapping[str, tuple[str, ...]],
    *,
    phase_name: str | None,
) -> tuple[list[dict[str, str]], list[str]]:
    issues: list[str] = []
    names: list[tuple[str, str]] = []
    if phase_name and phase_name.startswith("inventory_chunk_"):
        for name in assignments.get(phase_name, ()):
            names.append((name, "SHARD_MANIFEST"))
    else:
        for shard in sorted(assignments):
            for name in assignments[shard]:
                names.append((name, f"SHARD_MANIFEST:{shard}"))

        # Registry-owned pre-inventory producers supplement the explicit shard
        # plan.  The plan remains the primary denominator for ordinary breadth
        # artifacts because current legacy breadth roles are not yet all
        # registered; that compatibility gap is made visible below rather than
        # silently switching to chunks.
        try:
            for path in materialized_producer_paths(root, "canonical_identity"):
                producer = producer_for_artifact(
                    path.name, consumer="canonical_identity"
                )
                if producer is not None and producer.owner_phase in {
                    "breadth", "rescan", "graph_sweeps", "inventory"
                }:
                    names.append((path.name, f"PRODUCER_REGISTRY:{producer.key}"))
        except (ProducerResolutionError, ValueError) as exc:
            issues.append(f"typed producer discovery failed: {exc}")

        # Compatibility for unsharded/legacy tests and old resumes.  This is
        # deliberately a denominator *widening*: every matched raw candidate
        # must still be retained or debt.  It never grants a negative
        # disposition.  The source record declares the compatibility route so
        # registry migration can be measured rather than hidden.
        if not names:
            legacy_chunks = sorted(root.glob("findings_inventory_chunk_*.md"))
            if legacy_chunks:
                # Old scratchpads predate shard manifests, so their raw shard
                # assignment denominator is unrecoverable.  Keep compatibility
                # exact over the only persisted pre-merge denominator instead
                # of pretending the chunks are raw-authoritative in current
                # runs.  Current runs always take the manifest branch above.
                for path in legacy_chunks:
                    if path.is_file():
                        names.append((path.name, "LEGACY_CHUNK_ONLY"))
            else:
                for pattern in _INVENTORY_SOURCE_PATTERNS:
                    for path in sorted(root.glob(pattern)):
                        if path.is_file():
                            names.append((path.name, "LEGACY_PATTERN_FALLBACK"))

    deduped: dict[str, str] = {}
    for name, method in names:
        deduped.setdefault(name, method)
    sources: list[dict[str, str]] = []
    for name in sorted(deduped):
        path = root / name
        if not path.is_file():
            issues.append(f"assigned source artifact {name} is missing")
            continue
        try:
            raw = path.read_bytes()
            raw.decode("utf-8", errors="strict")
        except (OSError, UnicodeError) as exc:
            issues.append(
                f"assigned source artifact {name} is unreadable: "
                f"{type(exc).__name__}: {exc}"
            )
            continue
        producer_key = "UNREGISTERED_MANIFEST_SOURCE"
        try:
            producer = producer_for_artifact(name, consumer="canonical_identity")
        except ProducerResolutionError as exc:
            producer = None
            issues.append(f"{name} has ambiguous typed producer: {exc}")
        if producer is not None:
            producer_key = producer.key
        sources.append(
            {
                "artifact": name,
                "sha256": _sha_bytes(raw),
                "discovery_method": deduped[name],
                "producer_key": producer_key,
                "registry_status": (
                    "REGISTERED"
                    if producer is not None
                    else "UNREGISTERED_MANIFEST_SOURCE"
                ),
                "registry_debt": (
                    ""
                    if producer is not None
                    else "register this manifest-assigned discovery producer and its local-ID grammar"
                ),
            }
        )
    return sources, issues


def _is_default_ignorable(char: str) -> bool:
    codepoint = ord(char)
    return any(
        start <= codepoint <= end
        for start, end in _DEFAULT_IGNORABLE_RANGES
    )


def _normalize_field_text(value: str) -> str:
    normalized = " ".join(str(value or "").strip().split())
    if not normalized:
        return ""
    # Decode entities only in the rendered-visibility probe. Returning the
    # decoded value would rewrite evidence bytes and could collapse distinct
    # producer claims; visible fields retain their exact normalized spelling.
    rendered = html.unescape(normalized)
    if not any(
        not char.isspace() and not _is_default_ignorable(char)
        for char in rendered
    ):
        return ""
    return normalized


def _field(block: str, *labels: str) -> str:
    wanted = {label.casefold() for label in labels}
    for match in _FIELD_RE.finditer(block):
        if " ".join(match.group("label").split()).casefold() in wanted:
            return _normalize_field_text(match.group("value"))
    return ""


def _canonical_blocks(
    path: Path,
    *,
    include_unsupported_headings: bool = False,
) -> tuple[list[dict[str, Any]], list[str]]:
    issues: list[str] = []
    try:
        raw = path.read_bytes()
        text = raw.decode("utf-8", errors="strict")
    except (OSError, UnicodeError) as exc:
        return [], [f"{path.name} is unreadable: {type(exc).__name__}: {exc}"]
    try:
        operational = operational_markdown_field_view(text)
        headings = mapped_headings(text)
        matches: list[tuple[int, dict[str, Any], re.Match[str]]] = []
        for heading_index, heading in enumerate(headings):
            match = _FINDING_HEADING_CONTENT_RE.fullmatch(
                str(heading["content"]).strip()
            )
            if match is not None:
                matches.append((heading_index, heading, match))
    except MarkdownParserContractError as exc:
        # A parser miss must never be persisted as a clean zero denominator.
        raise InventoryReconciliationError(
            f"{path.name} cannot be parsed by the reviewed Markdown grammar: {exc}"
        ) from exc
    id_counts: Counter[str] = Counter()
    blocks: list[dict[str, Any]] = []
    for heading_index, heading, match in matches:
        start = int(heading["start"])
        heading_depth = int(heading["level"])
        end = len(text)
        for later in headings[heading_index + 1 :]:
            if int(later["level"]) <= heading_depth:
                end = int(later["start"])
                break
        block = text[start:end].strip()
        operational_block = operational[start:end].strip()
        raw_id = match.group("finding").strip()
        finding_id = _normalize_finding_id(raw_id) or raw_id.upper()
        heading_supported = heading_depth in {2, 3}
        if not heading_supported:
            issues.append(
                f"{path.name}:{finding_id} uses unsupported explicit finding "
                f"heading depth H{heading_depth}"
            )
            if not include_unsupported_headings:
                continue
        id_counts[finding_id] += 1
        # Heading content comes from the token, so list markers and up to three
        # source indentation columns never contaminate the canonical title.
        title = match.group("title").strip()
        source_match = _SOURCE_FIELD_RE.search(operational_block)
        source_value = source_match.group("value") if source_match else ""
        bare, qualified, reference_issues = _source_references(source_value)
        description = _field(operational_block, "Description")
        # Description is mandatory in the canonical producer schema and
        # explicitly carries what the bug is.  Older and niche producers do
        # not always emit a separate Root Cause/Mechanism label, so preserve
        # that mechanism through the generic Description fallback instead of
        # declaring it absent.
        root_cause = (
            _field(operational_block, "Root Cause", "Mechanism") or description
        )
        record = {
                "finding_id": finding_id,
                "title": title,
                "severity": _field(operational_block, "Severity", "Risk Level"),
                "location": _field(
                    operational_block, "Location", "Code Location"
                ),
                "root_cause": root_cause,
                "description": description,
                "impact": _field(
                    operational_block, "Impact", "Material Harm"
                ),
                "preconditions": _field(
                    operational_block, "Preconditions", "Precondition Analysis"
                ),
                "block": block,
                "block_sha256": _sha_bytes(block.encode("utf-8")),
                "source_ids": sorted(bare),
                "qualified_source_ids": [
                    {"artifact": artifact, "finding_id": fid}
                    for artifact, fid in sorted(qualified)
                ],
                "source_reference_issues": sorted(reference_issues),
                "ordinal": id_counts[finding_id],
            }
        if not heading_supported:
            record["unsupported_heading_depth"] = heading_depth
        blocks.append(record)
    duplicate_ids = sorted(fid for fid, count in id_counts.items() if count > 1)
    for fid in duplicate_ids:
        issues.append(f"{path.name} contains duplicate canonical finding identity {fid}")
    return blocks, issues


def _source_references(
    value: str,
) -> tuple[set[str], set[tuple[str, str]], set[str]]:
    """Classify delimited Source-ID atoms exactly after one HTML unescape."""

    bare: set[str] = set()
    qualified: set[tuple[str, str]] = set()
    issues: set[str] = set()
    decoded = html.unescape(str(value or ""))
    for raw_atom in re.split(r"[,;\r\n]+", decoded):
        atom = raw_atom.strip()
        if not atom:
            continue
        if len(atom) >= 2 and atom.startswith("`") and atom.endswith("`"):
            atom = atom[1:-1].strip()
        qualified_match = _QUALIFIED_SOURCE_ATOM_RE.fullmatch(atom)
        if qualified_match is not None:
            artifact = _safe_artifact_name(qualified_match.group("artifact"))
            fid_surface = qualified_match.group("finding")
            fid = _normalize_finding_id(fid_surface) or fid_surface.upper()
            if artifact and fid:
                qualified.add((artifact, fid))
                continue
        if _FINDING_ID_ATOM_RE.fullmatch(atom):
            fid = _normalize_finding_id(atom) or atom.upper()
            if fid:
                bare.add(fid)
                continue
        words = atom.split()
        if len(words) > 1 and all(
            _FINDING_ID_ATOM_RE.fullmatch(word) for word in words
        ):
            bare.update(
                _normalize_finding_id(word) or word.upper() for word in words
            )
            continue
        # Invalid qualified-looking atoms never synthesize a bare-ID suffix.
        issues.add(f"INVALID_SOURCE_REFERENCE_ATOM:{atom}")
    return {item for item in bare if item}, qualified, issues


def _candidate_key(
    source_artifact: str,
    source_sha256: str,
    finding_id: str,
    block_sha256: str,
    ordinal: int,
) -> str:
    identity = {
        "source_artifact": source_artifact,
        "source_sha256": source_sha256,
        "source_finding_id": finding_id,
        "source_block_sha256": block_sha256,
        "source_ordinal": ordinal,
    }
    return "INVC-" + _digest(identity)[:24].upper()


def _source_candidates(
    root: Path,
    sources: Iterable[Mapping[str, str]],
) -> tuple[list[dict[str, Any]], list[str]]:
    candidates: list[dict[str, Any]] = []
    issues: list[str] = []
    for source in sources:
        name = str(source["artifact"])
        blocks, block_issues = _canonical_blocks(
            root / name,
            include_unsupported_headings=True,
        )
        issues.extend(block_issues)
        producer = None
        try:
            producer = producer_for_artifact(name, consumer="canonical_identity")
        except ProducerResolutionError:
            pass
        for block in blocks:
            local_id_valid = (
                producer is None
                or producer_accepts_local_id(producer, block["finding_id"])
            )
            if not local_id_valid:
                issues.append(
                    f"{name}:{block['finding_id']} violates registered producer "
                    f"{producer.key} local-ID grammar"
                )
            key = _candidate_key(
                name,
                str(source["sha256"]),
                str(block["finding_id"]),
                str(block["block_sha256"]),
                int(block["ordinal"]),
            )
            candidate = {
                    "candidate_key": key,
                    "source_artifact": name,
                    "source_sha256": str(source["sha256"]),
                    "source_finding_id": str(block["finding_id"]),
                    "source_ordinal": int(block["ordinal"]),
                    "source_block_sha256": str(block["block_sha256"]),
                    "source_title": str(block["title"]),
                    "source_severity": str(block["severity"]),
                    "source_location": str(block["location"]),
                    "source_root_cause": str(block["root_cause"]),
                    "source_description": str(block["description"]),
                    "source_impact": str(block["impact"]),
                    "source_preconditions": str(block["preconditions"]),
                    "source_block": str(block["block"]),
                    "producer_key": str(source["producer_key"]),
                    "producer_local_id_valid": local_id_valid,
                }
            if "unsupported_heading_depth" in block:
                candidate["source_heading_supported"] = False
                candidate["source_heading_depth"] = int(
                    block["unsupported_heading_depth"]
                )
            candidates.append(candidate)
    candidates.sort(key=lambda row: row["candidate_key"])
    return candidates, issues


def _artifact_blocks(root: Path, names: Iterable[str]) -> tuple[dict[str, list[dict[str, Any]]], list[str]]:
    result: dict[str, list[dict[str, Any]]] = {}
    issues: list[str] = []
    for name in sorted(set(names)):
        path = root / name
        if not path.is_file():
            issues.append(f"required reconciliation artifact {name} is missing")
            result[name] = []
            continue
        blocks, block_issues = _canonical_blocks(path)
        issues.extend(block_issues)
        result[name] = blocks
    return result, issues


def _permitted_artifact_names(artifacts: Iterable[str]) -> set[str]:
    return {
        normalized
        for item in artifacts
        if (normalized := _safe_artifact_name(str(item))) is not None
    }


def _artifact_reference_targets(named: str, permitted: set[str]) -> list[str]:
    if "/" in named:
        return [named] if named in permitted else []
    return sorted(item for item in permitted if item.rsplit("/", 1)[-1] == named)


def _source_reference_block_is_exact(
    block: Mapping[str, Any], permitted_artifacts: Iterable[str]
) -> bool:
    if list(block.get("source_reference_issues") or []):
        return False
    permitted = _permitted_artifact_names(permitted_artifacts)
    for reference in list(block.get("qualified_source_ids") or []):
        named = _safe_artifact_name(str(reference.get("artifact") or ""))
        if named is None or len(_artifact_reference_targets(named, permitted)) != 1:
            return False
    return True


def _qualified_reference(
    block: Mapping[str, Any],
    artifact: str,
    finding_id: str,
    permitted_artifacts: Iterable[str],
) -> bool:
    """Resolve full relative paths exactly and basenames only when unique."""

    actual = _safe_artifact_name(artifact)
    permitted = _permitted_artifact_names(permitted_artifacts)
    if (
        not _source_reference_block_is_exact(block, permitted)
        or actual is None
        or actual not in permitted
    ):
        return False
    for reference in list(block.get("qualified_source_ids") or []):
        if str(reference.get("finding_id") or "") != finding_id:
            continue
        named = _safe_artifact_name(str(reference.get("artifact") or ""))
        if named is None:
            continue
        targets = _artifact_reference_targets(named, permitted)
        if len(targets) == 1 and targets[0] == actual:
            return True
    return False


def _bare_reference(
    block: Mapping[str, Any], finding_id: str, permitted_artifacts: Iterable[str]
) -> bool:
    return _source_reference_block_is_exact(
        block, permitted_artifacts
    ) and finding_id in set(block.get("source_ids") or [])


def _semantic_preservation_deltas(
    candidate: Mapping[str, Any], target: Mapping[str, Any]
) -> list[str]:
    """Return exact material facets not losslessly present in the target.

    This is deliberately lexical and one-directional: it can prove that bytes
    survived synthesis, not that two differently worded claims are equivalent.
    Semantic similarity therefore never authorizes destructive absorption.
    """

    deltas: list[str] = []
    for source_field, target_field, axis in (
        ("source_root_cause", "root_cause", "ROOT_CAUSE"),
        ("source_impact", "impact", "IMPACT"),
        ("source_preconditions", "preconditions", "PRECONDITIONS"),
    ):
        source = re.sub(
            r"\s+", " ", str(candidate.get(source_field) or "")
        ).strip().casefold()
        target_surfaces = [str(target.get(target_field) or "")]
        if axis == "ROOT_CAUSE":
            # Description is a canonical mechanism-bearing field.  Keep it as
            # an alternate preservation surface even when the target also
            # provides a separately worded Root Cause.
            target_surfaces.append(str(target.get("description") or ""))
        target_value = re.sub(
            r"\s+", " ", " ".join(target_surfaces)
        ).strip().casefold()
        if not source:
            # Missing source facets are ambiguity, not evidence that nothing
            # needed preservation.
            if axis in {"ROOT_CAUSE", "IMPACT"}:
                deltas.append(f"UNPARSEABLE_{axis}")
            continue
        if source not in target_value:
            deltas.append(axis)
    return deltas


def _material_preservation_deltas(deltas: Iterable[str]) -> list[str]:
    """Return every mandatory facet that needs preservation or application.

    A missing mandatory mechanism/harm facet cannot be reproduced lexically,
    but removing it from this enforced set silently treats non-application as
    success.  Keep ``UNPARSEABLE_*`` in the denominator so the normal
    content-bearing human-review and mandatory re-verification contract can
    resolve it explicitly.  Description already acts as the generic mechanism
    fallback, so this debt is limited to genuinely absent mandatory content.
    """

    return [str(delta) for delta in deltas]


def _load_authority(root: Path) -> tuple[dict[str, dict[str, Any]], list[str], str]:
    path = root / AUTHORITY_FILE
    if not path.is_file():
        return {}, [], ""
    issues: list[str] = []
    try:
        payload = _strict_json(path)
    except InventoryReconciliationError as exc:
        return {}, [str(exc)], _file_sha_or_empty(path)
    if set(payload) != {"schema_version", "rows"}:
        return {}, [f"{AUTHORITY_FILE} has missing or unknown top-level fields"], _file_sha_or_empty(path)
    if payload.get("schema_version") != AUTHORITY_SCHEMA or not isinstance(payload.get("rows"), list):
        return {}, [f"{AUTHORITY_FILE} schema is invalid"], _file_sha_or_empty(path)
    expected = {
        "candidate_key", "source_artifact", "source_sha256",
        "source_finding_id", "source_block_sha256", "disposition",
        "target_artifact", "target_finding_id", "alias_union",
        "decision_provider_id", "evidence_provider_id", "evidence_artifact",
        "evidence_sha256", "evidence_record_id",
    }
    rows: dict[str, dict[str, Any]] = {}
    for index, raw in enumerate(payload["rows"]):
        if not isinstance(raw, dict) or set(raw) != expected:
            issues.append(f"authority row {index} has missing or unknown fields")
            continue
        key = str(raw.get("candidate_key") or "")
        if not key or key in rows:
            issues.append(f"authority row {index} has blank/duplicate candidate_key")
            continue
        if raw.get("disposition") not in {"MERGED_ALIAS", "SUPPORTED_REFUTATION"}:
            issues.append(f"authority row {index} has invalid disposition")
            continue
        if not isinstance(raw.get("alias_union"), list) or not all(
            isinstance(item, str) and item for item in raw.get("alias_union", [])
        ):
            issues.append(f"authority row {index} has malformed alias_union")
            continue
        rows[key] = raw
    return rows, issues, _file_sha_or_empty(path)


def _candidate_authority_matches(candidate: Mapping[str, Any], row: Mapping[str, Any]) -> bool:
    return all(
        str(row.get(field) or "") == str(candidate.get(field) or "")
        for field in (
            "candidate_key", "source_artifact", "source_sha256",
            "source_finding_id", "source_block_sha256",
        )
    )


def _load_reemit_receipt(
    root: Path,
    candidates: Iterable[Mapping[str, Any]],
    final_artifact: str,
    final_blocks: Iterable[Mapping[str, Any]],
    permitted_artifacts: Iterable[str],
) -> tuple[dict[str, dict[str, Any]], list[str], str]:
    """Replay driver-owned additive re-emission mappings against live bytes."""

    candidate_rows = list(candidates)
    permitted_source_artifacts = {
        str(row["source_artifact"]) for row in candidate_rows
    } | set(permitted_artifacts)
    path = root / REEMIT_FILE
    if not path.is_file():
        return {}, [], ""
    try:
        payload = _strict_json(path)
    except InventoryReconciliationError as exc:
        return {}, [str(exc)], _file_sha_or_empty(path)
    expected_top = {
        "schema_version", "status", "intent_sha256", "inventory_artifact",
        "inventory_before_sha256", "inventory_after_sha256",
        "input_reconciliation_digest", "rows", "receipt_digest",
    }
    if set(payload) != expected_top or payload.get("schema_version") != REEMIT_SCHEMA:
        return {}, [f"{REEMIT_FILE} schema is invalid"], _file_sha_or_empty(path)
    unsigned = dict(payload)
    claimed_digest = unsigned.pop("receipt_digest", None)
    if claimed_digest != _digest(unsigned):
        return {}, [f"{REEMIT_FILE} digest is invalid"], _file_sha_or_empty(path)
    if payload.get("status") != "APPLIED" or payload.get("inventory_artifact") != final_artifact:
        return {}, [f"{REEMIT_FILE} does not bind the live final inventory"], _file_sha_or_empty(path)
    inventory_path = root / final_artifact
    if not inventory_path.is_file() or _file_sha_or_empty(inventory_path) != payload.get(
        "inventory_after_sha256"
    ):
        return {}, [f"{REEMIT_FILE} inventory bytes are stale"], _file_sha_or_empty(path)
    rows = payload.get("rows")
    if not isinstance(rows, list):
        return {}, [f"{REEMIT_FILE} rows are malformed"], _file_sha_or_empty(path)
    candidates_by_key = {str(row["candidate_key"]): row for row in candidate_rows}
    blocks_by_id: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for block in final_blocks:
        blocks_by_id[str(block.get("finding_id") or "")].append(block)
    expected_row_fields = {
        "candidate_key", "source_artifact", "source_sha256",
        "source_finding_id", "source_block_sha256", "target_finding_id",
        "target_block_sha256", "effect", "delivery_state",
    }
    mappings: dict[str, dict[str, Any]] = {}
    issues: list[str] = []
    for index, raw in enumerate(rows):
        if not isinstance(raw, dict) or set(raw) != expected_row_fields:
            issues.append(f"{REEMIT_FILE} row {index} schema is invalid")
            continue
        key = str(raw.get("candidate_key") or "")
        candidate = candidates_by_key.get(key)
        if candidate is None or key in mappings:
            issues.append(f"{REEMIT_FILE} row {index} candidate is absent/duplicate")
            continue
        if not all(
            str(raw.get(field) or "") == str(candidate.get(field) or "")
            for field in (
                "source_artifact", "source_sha256", "source_finding_id",
                "source_block_sha256",
            )
        ):
            issues.append(f"{REEMIT_FILE} row {index} source binding is stale")
            continue
        if raw.get("effect") != "ADDITIVE_REEMIT" or raw.get(
            "delivery_state"
        ) != "INDEPENDENT_VERIFICATION_REQUIRED":
            issues.append(f"{REEMIT_FILE} row {index} effect is not recall-monotonic")
            continue
        target_id = str(raw.get("target_finding_id") or "")
        targets = blocks_by_id.get(target_id, [])
        preservation_deltas = (
            _semantic_preservation_deltas(candidate, targets[0])
            if len(targets) == 1 else ["TARGET_CARDINALITY"]
        )
        # Additive delivery cannot certify a mandatory facet the producer did
        # not encode.  Keep that application gap in the enforced loss set so
        # the ordinary content-bearing debt route, rather than a delivery
        # receipt alone, remains responsible for resolving it.
        material_loss = _material_preservation_deltas(preservation_deltas)
        if (
            len(targets) != 1
            or str(targets[0].get("block_sha256") or "")
            != str(raw.get("target_block_sha256") or "")
            or not _qualified_reference(
                targets[0],
                str(candidate["source_artifact"]),
                str(candidate["source_finding_id"]),
                permitted_source_artifacts,
            )
            or material_loss
        ):
            issues.append(f"{REEMIT_FILE} row {index} target is stale or lossy")
            continue
        mappings[key] = raw
    if issues:
        return {}, issues, _file_sha_or_empty(path)
    return mappings, [], _file_sha_or_empty(path)


def _validate_negative_authority(
    root: Path,
    candidate: Mapping[str, Any],
    row: Mapping[str, Any],
) -> tuple[bool, str]:
    decision_provider = str(row.get("decision_provider_id") or "").strip()
    evidence_provider = str(row.get("evidence_provider_id") or "").strip()
    evidence_artifact = _safe_evidence_name(str(row.get("evidence_artifact") or ""))
    if not decision_provider or not evidence_provider or decision_provider == evidence_provider:
        return False, "negative decision lacks distinct decision/evidence providers"
    if evidence_artifact in {
        None,
        str(candidate["source_artifact"]),
        "findings_inventory.md",
        AUTHORITY_FILE,
    }:
        return False, "negative evidence artifact is missing or not independent"
    path = root / evidence_artifact
    if not path.is_file():
        return False, "negative evidence artifact is missing"
    try:
        current_sha = _file_sha(path)
    except OSError:
        return False, "negative evidence artifact is unreadable"
    if current_sha != str(row.get("evidence_sha256") or ""):
        return False, "negative evidence artifact hash is stale"
    try:
        payload = _strict_json(path)
    except InventoryReconciliationError as exc:
        return False, str(exc)
    if set(payload) != {"schema_version", "provider_id", "records"}:
        return False, "negative evidence has missing or unknown top-level fields"
    if (
        payload.get("schema_version") != NEGATIVE_EVIDENCE_SCHEMA
        or payload.get("provider_id") != evidence_provider
        or not isinstance(payload.get("records"), list)
    ):
        return False, "negative evidence schema/provider is invalid"
    record_id = str(row.get("evidence_record_id") or "")
    matches = [
        record for record in payload["records"]
        if isinstance(record, dict) and record.get("record_id") == record_id
    ]
    if len(matches) != 1:
        return False, "negative evidence record is missing or ambiguous"
    record = matches[0]
    expected_fields = {
        "record_id", "candidate_key", "source_artifact", "source_sha256",
        "source_finding_id", "source_block_sha256", "verdict",
        "evidence_scope", "proof_scope", "evidence_pointer", "evidence_digest",
    }
    if set(record) != expected_fields:
        return False, "negative evidence record has missing or unknown fields"
    if not all(
        str(record.get(field) or "") == str(candidate.get(field) or "")
        for field in (
            "candidate_key", "source_artifact", "source_sha256",
            "source_finding_id", "source_block_sha256",
        )
    ):
        return False, "negative evidence record is not source-bound to candidate"
    if record.get("verdict") != "REFUTED":
        return False, "negative evidence verdict is not REFUTED"
    if record.get("evidence_scope") not in _ALLOWED_NEGATIVE_EVIDENCE_SCOPES:
        return False, "negative evidence scope is not in-scope source/execution"
    if record.get("proof_scope") != "HARM":
        return False, "negative evidence does not refute the full harm premise"
    if not _IN_SCOPE_POINTER_RE.search(str(record.get("evidence_pointer") or "")):
        return False, "negative evidence lacks a concrete in-scope file:line pointer"
    if not _HEX_RE.fullmatch(str(record.get("evidence_digest") or "")):
        return False, "negative evidence digest is malformed"
    policy = supporting_negative_resolution(
        requested_effect="REFUTED_FULL",
        evidence_basis=str(record.get("evidence_scope") or ""),
    )
    return (
        False,
        f"{policy['reason']}: source-bound evidence is supporting-only; "
        "terminal refutation requires authenticated exhaustive "
        "negative-execution authority",
    )


def _authority_disposition(
    root: Path,
    candidate: Mapping[str, Any],
    row: Mapping[str, Any] | None,
    target_blocks: Mapping[str, list[dict[str, Any]]],
    authority_rows: Mapping[str, Mapping[str, Any]],
    candidates: Iterable[Mapping[str, Any]],
    central_resolution: Mapping[str, Any] | None = None,
) -> tuple[str, str, str, str] | None:
    if row is None or not _candidate_authority_matches(candidate, row):
        return None
    disposition = str(row["disposition"])
    if disposition == "SUPPORTED_REFUTATION":
        _support_ok, support_reason = _validate_negative_authority(
            root, candidate, row
        )
        if (
            isinstance(central_resolution, Mapping)
            and central_resolution.get("status") == "AUTHORIZED"
            and central_resolution.get("outcome") == "REFUTED_FULL"
            and central_resolution.get("resolution_digest")
        ):
            return (
                "AUTHORIZED_REFUTATION",
                "",
                "CENTRAL_REPLAYED_REFUTATION_AUTHORITY",
                "authenticated exhaustive negative authority replayed; local "
                f"inventory evidence remains supporting-only ({support_reason})",
            )
        debt_reasons = (
            central_resolution.get("debt_reasons")
            if isinstance(central_resolution, Mapping)
            else None
        )
        central_reason = (
            ", ".join(str(value) for value in debt_reasons)
            if isinstance(debt_reasons, list) and debt_reasons
            else "NO_PROVIDER_AUTHORITY"
        )
        return (
            "HUMAN_REVIEW_DEBT",
            "",
            "INVALID_REFUTATION_AUTHORITY",
            f"{central_reason}: {support_reason}",
        )

    target_artifact = str(row.get("target_artifact") or "")
    target_id = str(row.get("target_finding_id") or "").upper()
    blocks = target_blocks.get(target_artifact, [])
    targets = [block for block in blocks if block["finding_id"] == target_id]
    if len(targets) != 1:
        return (
            "HUMAN_REVIEW_DEBT", "", "INVALID_MERGE_AUTHORITY",
            "merge target is missing or ambiguous",
        )
    authority_group = {
        key
        for key, other in authority_rows.items()
        if other.get("disposition") == "MERGED_ALIAS"
        and other.get("target_artifact") == target_artifact
        and str(other.get("target_finding_id") or "").upper() == target_id
        and key in authority_rows
    }
    target_block = targets[0]
    structurally_bound: set[str] = set()
    candidate_rows = list(candidates)
    permitted_source_artifacts = {
        str(item["source_artifact"]) for item in candidate_rows
    }
    permitted_reference_artifacts = (
        permitted_source_artifacts | set(target_blocks.keys())
    )
    raw_counts = Counter(
        str(item["source_finding_id"]) for item in candidate_rows
    )
    for item in candidate_rows:
        item_id = str(item["source_finding_id"])
        if _qualified_reference(
            target_block,
            str(item["source_artifact"]),
            item_id,
            permitted_reference_artifacts,
        ) or (
            raw_counts[item_id] == 1
            and int(item["source_ordinal"]) == 1
            and _bare_reference(
                target_block, item_id, permitted_reference_artifacts
            )
        ):
            structurally_bound.add(str(item["candidate_key"]))
    group = authority_group | structurally_bound
    alias_union = set(str(item) for item in row.get("alias_union") or [])
    if alias_union != group:
        return (
            "HUMAN_REVIEW_DEBT", "", "INCOMPLETE_ALIAS_UNION",
            "merge authority does not preserve the exact source-bound alias union",
        )
    if (
        isinstance(central_resolution, Mapping)
        and central_resolution.get("status") == "AUTHORIZED"
        and central_resolution.get("outcome") == "ALIAS_TO_SURVIVOR"
        and str(central_resolution.get("survivor_id") or "").upper()
        == target_id
        and central_resolution.get("resolution_digest")
    ):
        return (
            "AUTHORIZED_MERGE",
            target_id,
            "CENTRAL_APPLIED_EQUIVALENCE_AUTHORITY",
            "validated applied lossless-equivalence receipt resolves the exact "
            "absorbed identity to the live survivor",
        )
    debt_reasons = (
        central_resolution.get("debt_reasons")
        if isinstance(central_resolution, Mapping)
        else None
    )
    central_reason = (
        ", ".join(str(value) for value in debt_reasons)
        if isinstance(debt_reasons, list) and debt_reasons
        else "NO_APPLIED_EQUIVALENCE_AUTHORITY"
    )
    return (
        "HUMAN_REVIEW_DEBT",
        "",
        "MERGE_REQUIRES_APPLIED_EQUIVALENCE_AUTHORITY",
        "structural references and alias union nominate a merge but do not prove "
        "lossless semantic equivalence to the live survivor: " + central_reason,
    )


def _chunk_for_source(assignments: Mapping[str, tuple[str, ...]], source: str) -> list[str]:
    return sorted(shard for shard, sources in assignments.items() if source in sources)


def _structural_chunk_match(
    candidate: Mapping[str, Any],
    shard: str,
    chunk_blocks: Mapping[str, list[dict[str, Any]]],
    candidates: Iterable[Mapping[str, Any]],
) -> tuple[dict[str, Any] | None, str]:
    artifact = f"findings_{shard}.md"
    blocks = chunk_blocks.get(artifact, [])
    fid = str(candidate["source_finding_id"])
    source = str(candidate["source_artifact"])
    candidate_rows = list(candidates)
    permitted_source_artifacts = {
        str(row["source_artifact"]) for row in candidate_rows
    }
    # Exact qualification always wins, while bare IDs are accepted only when
    # unique among candidates assigned to this shard.
    qualified = [
        block
        for block in blocks
        if _qualified_reference(
            block, source, fid, permitted_source_artifacts
        )
    ]
    if len(qualified) == 1:
        return qualified[0], "qualified source reference"
    if len(qualified) > 1:
        return None, "candidate is referenced by multiple chunk blocks"
    # candidates passed to this helper are already the relevant phase
    # denominator for a chunk run; for a final run filter by manifest owner in
    # the caller before invoking.
    matching_candidates = [
        row for row in candidate_rows if row["source_finding_id"] == fid
    ]
    if len(matching_candidates) != 1 or int(candidate["source_ordinal"]) != 1:
        return None, "bare source ID is ambiguous across assigned source identities"
    bare = [
        block
        for block in blocks
        if _bare_reference(block, fid, permitted_source_artifacts)
    ]
    if len(bare) == 1:
        return bare[0], "unique bare source reference"
    if len(bare) > 1:
        return None, "candidate is referenced by multiple chunk blocks"
    return None, "candidate has no concrete chunk block disposition"


def _final_match(
    candidate: Mapping[str, Any],
    chunk_artifact: str,
    chunk_block: Mapping[str, Any] | None,
    final_blocks: list[dict[str, Any]],
    candidates: Iterable[Mapping[str, Any]],
    all_chunk_blocks: Mapping[str, list[dict[str, Any]]],
) -> tuple[dict[str, Any] | None, str]:
    source = str(candidate["source_artifact"])
    fid = str(candidate["source_finding_id"])
    candidate_rows = list(candidates)
    permitted_source_artifacts = {
        str(row["source_artifact"]) for row in candidate_rows
    }
    permitted_reference_artifacts = (
        permitted_source_artifacts | set(all_chunk_blocks.keys())
    )
    qualified = [
        block
        for block in final_blocks
        if _qualified_reference(
            block, source, fid, permitted_reference_artifacts
        )
    ]
    if len(qualified) == 1:
        return qualified[0], "qualified raw-source reference"
    if len(qualified) > 1:
        return None, "raw candidate is referenced by multiple final blocks"
    raw_id_candidates = [
        row
        for row in candidate_rows
        if row["source_finding_id"] == fid
    ]
    if not chunk_artifact and len(raw_id_candidates) == 1 and int(candidate["source_ordinal"]) == 1:
        direct_identity = [
            block for block in final_blocks if block["finding_id"] == fid
        ]
        if len(direct_identity) == 1:
            return direct_identity[0], "legacy unsharded final identity"
        if len(direct_identity) > 1:
            return None, "raw identity appears in multiple final finding blocks"
    if len(raw_id_candidates) == 1 and int(candidate["source_ordinal"]) == 1:
        bare = [
            block
            for block in final_blocks
            if _bare_reference(block, fid, permitted_reference_artifacts)
        ]
        if len(bare) == 1:
            return bare[0], "unique raw-source reference"
        if len(bare) > 1:
            return None, "raw candidate is referenced by multiple final blocks"
    if chunk_block is None:
        return None, "candidate has no chunk disposition or exact final reference"
    chunk_id = str(chunk_block["finding_id"])
    qualified_chunk = [
        block for block in final_blocks
        if _qualified_reference(
            block,
            chunk_artifact,
            chunk_id,
            permitted_reference_artifacts,
        )
    ]
    if len(qualified_chunk) == 1:
        return qualified_chunk[0], "qualified chunk-source reference"
    if len(qualified_chunk) > 1:
        return None, "chunk candidate is referenced by multiple final blocks"
    local_occurrences = sum(
        1
        for blocks in all_chunk_blocks.values()
        for block in blocks
        if block["finding_id"] == chunk_id
    )
    if local_occurrences == 1:
        bare_chunk = [
            block for block in final_blocks
            if _bare_reference(
                block, chunk_id, permitted_reference_artifacts
            )
        ]
        if len(bare_chunk) == 1:
            return bare_chunk[0], "unique chunk-source reference"
        if len(bare_chunk) > 1:
            return None, "chunk candidate is referenced by multiple final blocks"
    return None, "candidate has no concrete final inventory block disposition"


def _output_names(phase_name: str | None) -> tuple[str, str]:
    if phase_name and phase_name.startswith("inventory_chunk_"):
        return f"{phase_name}.reconciliation.json", f"{phase_name}.human_review.md"
    return RECONCILIATION_FILE, HUMAN_REVIEW_FILE


def _human_review_markdown(payload: Mapping[str, Any]) -> str:
    debt = [
        row for row in payload.get("candidates", [])
        if row.get("disposition") == "HUMAN_REVIEW_DEBT"
    ]
    lines = [
        "# Inventory Reconciliation Human Review",
        "",
        "This is a content-bearing preservation surface, not a safety or",
        "negative-disposition authority. Every block below remains active",
        "inventory repair/review work until independently resolved.",
        "",
        f"- Reconciliation scope: {payload.get('scope', 'final')}",
        f"- Unresolved candidates: {len(debt)}",
        f"- Denominator digest: {payload.get('denominator_digest', '')}",
        "",
    ]
    if not debt:
        lines.extend(["No unresolved discovery candidates remain.", ""])
        return "\n".join(lines)
    for row in debt:
        lines.extend(
            [
                f"## {row['candidate_key']} — {row['source_artifact']}:{row['source_finding_id']}",
                "",
                f"- Reason code: `{row['reason_code']}`",
                f"- Reason: {row['reason']}",
                f"- Source SHA-256: `{row['source_sha256']}`",
                f"- Source block SHA-256: `{row['source_block_sha256']}`",
                f"- Repair action ID: `{row.get('repair_action_id', '')}`",
                f"- Mandatory re-verification ID: "
                f"`{row.get('mandatory_reverification_id', '')}`",
                f"- Proposed relation: `{row.get('proposed_relation_kind') or 'UNRESOLVED'}`",
                f"- Proposed target: `{row.get('proposed_target_artifact') or 'NONE'}"
                f"#{row.get('proposed_target_finding_id') or 'NONE'}`",
                f"- Proposed target block SHA-256: "
                f"`{row.get('proposed_target_block_sha256') or 'NONE'}`",
                "- Required preservation axes: `"
                + ",".join(row.get("required_preservation_axes") or ["FULL_SOURCE_BLOCK"])
                + "`",
                "- Required routing: `INDEPENDENT_VERIFICATION_REQUIRED`",
                "",
                str(row["source_block"]).strip(),
                "",
            ]
        )
    return "\n".join(lines)


def reconcile_inventory(
    scratchpad: Path,
    *,
    phase_name: str | None = None,
    persist: bool = False,
    closure_authority: Any = None,
) -> dict[str, Any]:
    """Build the exact current reconciliation; optionally persist sidecars."""

    root = Path(scratchpad)
    if closure_authority is None:
        try:
            from closure_broker_v2 import load_central_negative_closure_authority

            closure_authority = load_central_negative_closure_authority(root)
        except Exception:
            # Inventory remains haltless: an unavailable broker simply cannot
            # authorize a destructive disposition, so the candidate becomes
            # content-bearing human-review debt below.
            closure_authority = None
    assignments, manifest_issues = _manifest_assignments(root)
    sources, source_issues = _discovery_sources(
        root, assignments, phase_name=phase_name
    )
    candidates, candidate_issues = _source_candidates(root, sources)

    if phase_name and phase_name.startswith("inventory_chunk_"):
        chunk_names = [f"findings_{phase_name}.md"]
        final_names: list[str] = []
        final_artifact = ""
    else:
        chunk_names = [
            f"findings_{shard}.md" for shard in sorted(assignments)
        ]
        # Preserve legacy chunks that predate/omit manifests as observable
        # artifacts, but they never replace the raw-source denominator.
        for path in sorted(root.glob("findings_inventory_chunk_*.md")):
            if path.name not in chunk_names:
                chunk_names.append(path.name)
        final_artifact = next(
            (
                name for name in (
                    "findings_inventory_base.md",
                    "findings_inventory_pre_dedup.md",
                    "findings_inventory.md",
                )
                if (root / name).is_file()
            ),
            "findings_inventory.md",
        )
        final_names = [final_artifact]

    chunk_blocks, chunk_issues = _artifact_blocks(root, chunk_names)
    final_blocks_by_artifact, final_issues = _artifact_blocks(root, final_names)
    final_blocks = final_blocks_by_artifact.get(final_artifact, [])
    target_blocks = {**chunk_blocks, **final_blocks_by_artifact}
    if final_artifact and final_artifact != "findings_inventory.md":
        target_blocks.setdefault("findings_inventory.md", final_blocks)
    authority_rows, authority_issues, authority_sha = _load_authority(root)
    reemit_rows, reemit_issues, reemit_sha = _load_reemit_receipt(
        root,
        candidates,
        final_artifact,
        final_blocks,
        target_blocks.keys(),
    ) if final_artifact else ({}, [], "")

    results: list[dict[str, Any]] = []
    artifact_issues = [
        *manifest_issues, *source_issues, *candidate_issues,
        *chunk_issues, *final_issues, *authority_issues, *reemit_issues,
    ]
    for candidate in candidates:
        row = dict(candidate)
        if candidate.get("source_heading_supported", True) is False:
            heading_depth = int(candidate.get("source_heading_depth") or 0)
            row.update(
                {
                    "disposition": "HUMAN_REVIEW_DEBT",
                    "target_inventory_id": "",
                    "reason_code": "UNSUPPORTED_FINDING_HEADING_DEPTH",
                    "reason": (
                        f"assigned source uses explicit H{heading_depth} finding "
                        "syntax outside the registered canonical H2/H3 producer "
                        "format; the source block remains active review debt"
                    ),
                    "chunk_artifact": "",
                    "chunk_finding_id": "",
                    "authority_artifact": "",
                    "reemit_authority_artifact": "",
                    "proposed_target_artifact": "",
                    "proposed_target_finding_id": "",
                    "proposed_target_block_sha256": "",
                    "proposed_relation_kind": "UNSUPPORTED_SOURCE_RECORD",
                    "required_preservation_axes": [
                        "FULL_SOURCE_BLOCK",
                        "INDEPENDENT_VERIFICATION_DELIVERY",
                    ],
                    "negative_closure_authority_digest": "",
                    "negative_closure_provider_completion_sha256": "",
                    "negative_closure_provider_publish_sha256": "",
                    "negative_closure_debt_reasons": [
                        "UNSUPPORTED_FINDING_HEADING_DEPTH"
                    ],
                    "closure_authority_effect": "",
                    "closure_authority_survivor_id": "",
                    "repair_action_id": "INVR-" + _digest(
                        {
                            "candidate_key": candidate["candidate_key"],
                            "source_block_sha256": candidate[
                                "source_block_sha256"
                            ],
                            "repair_kind": "CANONICAL_HEADING_REPAIR",
                        }
                    )[:24].upper(),
                }
            )
            results.append(row)
            continue
        source = str(candidate["source_artifact"])
        shards = _chunk_for_source(assignments, source)
        if phase_name and phase_name.startswith("inventory_chunk_"):
            shards = [phase_name] if source in assignments.get(phase_name, ()) else []
        stale_authority = any(
            str(value.get("source_artifact") or "") == source
            and str(value.get("source_finding_id") or "").upper()
            == str(candidate["source_finding_id"]).upper()
            for value in authority_rows.values()
        ) and candidate["candidate_key"] not in authority_rows
        authority = authority_rows.get(str(candidate["candidate_key"]))
        central_resolution: dict[str, Any] = {}
        if (
            isinstance(authority, Mapping)
            and authority.get("disposition") == "SUPPORTED_REFUTATION"
            and closure_authority is not None
        ):
            try:
                central_resolution = resolve_central_negative_closure(
                    closure_authority,
                    work_item={
                        "candidate_id": candidate["candidate_key"],
                        "work_item_id": candidate["candidate_key"],
                        "candidate_content_sha256": candidate[
                            "source_block_sha256"
                        ],
                    },
                    requested_effect="REFUTED_FULL",
                )
            except Exception as exc:
                central_resolution = {
                    "status": "DEBT",
                    "outcome": "NO_AUTHORITY",
                    "resolution_digest": "",
                    "debt_reasons": [
                        "CENTRAL_NEGATIVE_CLOSURE_REPLAY_FAILED_"
                        f"{type(exc).__name__.upper()}"
                    ],
                }
        elif (
            isinstance(authority, Mapping)
            and authority.get("disposition") == "MERGED_ALIAS"
            and closure_authority is not None
        ):
            lookup_ids = [
                str(candidate.get("source_finding_id") or "").upper(),
                str(candidate.get("candidate_key") or ""),
            ]
            for lookup_id in dict.fromkeys(value for value in lookup_ids if value):
                try:
                    candidate_resolution = resolve_central_negative_closure(
                        closure_authority,
                        work_item={
                            "candidate_id": lookup_id,
                            "work_item_id": lookup_id,
                            "candidate_content_sha256": candidate[
                                "source_block_sha256"
                            ],
                        },
                        requested_effect="ALIAS_TO_SURVIVOR",
                    )
                except Exception as exc:
                    candidate_resolution = {
                        "status": "DEBT",
                        "outcome": "NO_AUTHORITY",
                        "resolution_digest": "",
                        "debt_reasons": [
                            "CENTRAL_EQUIVALENCE_REPLAY_FAILED_"
                            f"{type(exc).__name__.upper()}"
                        ],
                    }
                central_resolution = dict(candidate_resolution)
                if candidate_resolution.get("status") == "AUTHORIZED":
                    break

        chunk_block: dict[str, Any] | None = None
        chunk_artifact = ""
        chunk_reason = ""
        proposed_target_artifact = ""
        proposed_target_finding_id = ""
        proposed_target_block_sha256 = ""
        proposed_relation_kind = ""
        required_preservation_axes: list[str] = []
        if len(shards) == 1:
            shard = shards[0]
            chunk_artifact = f"findings_{shard}.md"
            # Enforce uniqueness within the assigned shard before accepting a
            # bare Source-ID token. Qualified `file.md:ID` tokens remain exact.
            shard_candidates = [
                item for item in candidates
                if shard in _chunk_for_source(assignments, str(item["source_artifact"]))
            ]
            chunk_block, chunk_reason = _structural_chunk_match(
                candidate, shard, chunk_blocks, shard_candidates
            )
        elif not shards:
            chunk_reason = "source is absent from the current shard plan"
        else:
            chunk_reason = "source is assigned to multiple shards"

        if phase_name and phase_name.startswith("inventory_chunk_"):
            if chunk_block is not None:
                proposed_target_artifact = chunk_artifact
                proposed_target_finding_id = str(chunk_block["finding_id"])
                proposed_target_block_sha256 = str(chunk_block["block_sha256"])
                proposed_relation_kind = "ONE_TO_ONE_RETENTION_PROPOSAL"
                required_preservation_axes = _semantic_preservation_deltas(
                    candidate, chunk_block
                )
                material_preservation_axes = _material_preservation_deltas(
                    required_preservation_axes
                )
                if material_preservation_axes:
                    disposition = (
                        "HUMAN_REVIEW_DEBT", "",
                        "CHUNK_SEMANTIC_PRESERVATION_DEBT",
                        "chunk cites the source identity but does not preserve "
                        "its exact material facets: "
                        + ", ".join(material_preservation_axes),
                    )
                else:
                    disposition = (
                        "RETAINED", str(chunk_block["finding_id"]),
                        (
                            "RETAINED_WITH_SOURCE_FACET_AMBIGUITY"
                            if required_preservation_axes
                            else "RETAINED_IN_CHUNK"
                        ),
                        chunk_reason,
                    )
            else:
                disposition = _authority_disposition(
                    root, candidate, authority, target_blocks, authority_rows,
                    candidates, central_resolution,
                ) or (
                    "HUMAN_REVIEW_DEBT", "",
                    "STALE_DISPOSITION_AUTHORITY" if stale_authority else "MISSING_CHUNK_DISPOSITION",
                    chunk_reason,
                )
        else:
            reemit = reemit_rows.get(str(candidate["candidate_key"]))
            if reemit is not None:
                reemit_targets = [
                    block for block in final_blocks
                    if str(block.get("finding_id") or "")
                    == str(reemit["target_finding_id"])
                ]
                final_block = reemit_targets[0] if len(reemit_targets) == 1 else None
                final_reason = "driver-owned additive re-emission"
            else:
                final_block, final_reason = _final_match(
                    candidate,
                    chunk_artifact,
                    chunk_block,
                    final_blocks,
                    candidates,
                    chunk_blocks,
                )
            if final_block is not None:
                proposed_target_artifact = final_artifact
                proposed_target_finding_id = str(final_block["finding_id"])
                proposed_target_block_sha256 = str(final_block["block_sha256"])
                proposed_relation_kind = "ONE_TO_ONE_RETENTION_PROPOSAL"
                required_preservation_axes = _semantic_preservation_deltas(
                    candidate, final_block
                )
                if reemit is not None:
                    # `_load_reemit_receipt` already replayed the exact source,
                    # target, effect, delivery state, and every material facet
                    # the source actually encoded. It cannot turn a rendered-
                    # empty mandatory source facet into content: that remains
                    # content-bearing reconciliation and re-verification debt.
                    unparseable_axes = [
                        axis for axis in required_preservation_axes
                        if str(axis).startswith("UNPARSEABLE_")
                    ]
                    if unparseable_axes:
                        disposition = (
                            "HUMAN_REVIEW_DEBT",
                            "",
                            "REEMIT_UNPARSEABLE_SOURCE_DEBT",
                            "additive re-emission preserves source bytes but "
                            "cannot supply rendered-empty mandatory facets: "
                            + ", ".join(unparseable_axes),
                        )
                    else:
                        required_preservation_axes = []
                        disposition = (
                            "RETAINED", str(final_block["finding_id"]),
                            "RETAINED_BY_ADDITIVE_REEMIT", final_reason,
                        )
                elif _material_preservation_deltas(required_preservation_axes):
                    material_preservation_axes = _material_preservation_deltas(
                        required_preservation_axes
                    )
                    if (
                        central_resolution.get("status") == "AUTHORIZED"
                        and central_resolution.get("outcome")
                        == "ALIAS_TO_SURVIVOR"
                        and str(central_resolution.get("survivor_id") or "").upper()
                        == str(final_block["finding_id"]).upper()
                    ):
                        disposition = (
                            "AUTHORIZED_MERGE",
                            str(final_block["finding_id"]),
                            "CENTRAL_APPLIED_EQUIVALENCE_AUTHORITY",
                            "validated applied receipt preserves the source facets "
                            "in the live survivor's content-bound preservation card",
                        )
                    else:
                        disposition = (
                            "HUMAN_REVIEW_DEBT", "",
                            "FINAL_SEMANTIC_PRESERVATION_DEBT",
                            "final inventory cites the source identity but does not "
                            "preserve its exact material facets: "
                            + ", ".join(material_preservation_axes),
                        )
                else:
                    disposition = (
                        "RETAINED", str(final_block["finding_id"]),
                        (
                            "RETAINED_WITH_SOURCE_FACET_AMBIGUITY"
                            if required_preservation_axes
                            else "RETAINED_IN_FINAL"
                        ),
                        final_reason,
                    )
                if chunk_block is None and assignments and reemit is None:
                    artifact_issues.append(
                        f"{candidate['candidate_key']} is retained directly in final "
                        "inventory but lacks an exact chunk disposition"
                    )
            else:
                disposition = _authority_disposition(
                    root, candidate, authority, target_blocks, authority_rows,
                    candidates, central_resolution,
                ) or (
                    "HUMAN_REVIEW_DEBT", "",
                    "STALE_DISPOSITION_AUTHORITY" if stale_authority else (
                        "MISSING_CHUNK_DISPOSITION" if chunk_block is None
                        else "MISSING_FINAL_DISPOSITION"
                    ),
                    final_reason if chunk_block is not None else chunk_reason,
                )
        row.update(
            {
                "disposition": disposition[0],
                "target_inventory_id": disposition[1],
                "reason_code": disposition[2],
                "reason": disposition[3],
                "chunk_artifact": chunk_artifact,
                "chunk_finding_id": str(chunk_block["finding_id"]) if chunk_block else "",
                "authority_artifact": AUTHORITY_FILE if authority is not None else "",
                "reemit_authority_artifact": REEMIT_FILE if reemit_rows.get(
                    str(candidate["candidate_key"])
                ) is not None else "",
                "proposed_target_artifact": proposed_target_artifact,
                "proposed_target_finding_id": proposed_target_finding_id,
                "proposed_target_block_sha256": proposed_target_block_sha256,
                "proposed_relation_kind": proposed_relation_kind,
                "required_preservation_axes": required_preservation_axes,
                "negative_closure_authority_digest": str(
                    central_resolution.get("resolution_digest") or ""
                ),
                "negative_closure_provider_completion_sha256": str(
                    central_resolution.get("provider_completion_sha256") or ""
                ),
                "negative_closure_provider_publish_sha256": str(
                    central_resolution.get("provider_publish_sha256") or ""
                ),
                "negative_closure_debt_reasons": list(
                    central_resolution.get("debt_reasons") or []
                ),
                "closure_authority_effect": str(
                    central_resolution.get("outcome") or ""
                ),
                "closure_authority_survivor_id": str(
                    central_resolution.get("survivor_id") or ""
                ),
                "repair_action_id": "INVR-" + _digest(
                    {
                        "candidate_key": candidate["candidate_key"],
                        "target_artifact": proposed_target_artifact,
                        "target_finding_id": proposed_target_finding_id,
                        "target_block_sha256": proposed_target_block_sha256,
                    }
                )[:24].upper(),
            }
        )
        results.append(row)

    retained_groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in results:
        if row["disposition"] == "RETAINED" and row["target_inventory_id"]:
            retained_groups[str(row["target_inventory_id"])].append(row)
    for target_id, group in retained_groups.items():
        if len(group) <= 1:
            continue
        for row in group:
            row["disposition"] = "HUMAN_REVIEW_DEBT"
            row["proposed_target_artifact"] = final_artifact
            row["proposed_target_finding_id"] = target_id
            target_matches = [
                block for block in final_blocks
                if str(block.get("finding_id") or "") == target_id
            ]
            row["proposed_target_block_sha256"] = (
                str(target_matches[0]["block_sha256"])
                if len(target_matches) == 1 else ""
            )
            row["proposed_relation_kind"] = "AMBIGUOUS_MANY_TO_ONE"
            row["required_preservation_axes"] = sorted(
                set(row.get("required_preservation_axes") or [])
                | {"IDENTITY", "INDEPENDENT_VERIFICATION_DELIVERY"}
            )
            row["target_inventory_id"] = ""
            row["reason_code"] = "MULTI_SOURCE_COLLAPSE_REQUIRES_EQUIVALENCE"
            row["reason"] = (
                f"{len(group)} distinct source candidates map to {target_id}; "
                "structural Source-ID coverage does not prove every mechanism "
                "and harm premise survived losslessly"
            )

    for row in results:
        mandatory = row["disposition"] == "HUMAN_REVIEW_DEBT"
        binding = (
            {
                "candidate_key": row["candidate_key"],
                "source_block_sha256": row["source_block_sha256"],
            }
            if mandatory
            else None
        )
        row["mandatory_reverification"] = mandatory
        row["mandatory_reverification_id_binding"] = binding
        row["mandatory_reverification_id"] = (
            "INVRV-" + _digest(
                {
                    "candidate_key": row["candidate_key"],
                    "source_block_sha256": row["source_block_sha256"],
                    "obligation_kind": "INDEPENDENT_VERIFICATION_REQUIRED",
                }
            )[:24].upper()
            if mandatory
            else ""
        )
        if row["disposition"] != "HUMAN_REVIEW_DEBT":
            # The exact block hash remains in every receipt row. Full Markdown
            # is retained only where it is required to make unresolved debt
            # content-bearing, avoiding an O(all-source-text) happy-path
            # sidecar.
            row.pop("source_block", None)

    # One typed disposition per candidate key is guaranteed by construction;
    # duplicate source identities remain separate candidate keys and cannot be
    # silently satisfied by a single bare alias.
    counts = Counter(str(row["disposition"]) for row in results)
    summary = {
        "AUTHORIZED_MERGE": counts["AUTHORIZED_MERGE"],
        "AUTHORIZED_REFUTATION": counts["AUTHORIZED_REFUTATION"],
        "HUMAN_REVIEW_DEBT": counts["HUMAN_REVIEW_DEBT"],
        "RETAINED": counts["RETAINED"],
        "TOTAL": len(results),
    }
    source_artifacts = [
        {
            **source,
            "manifest_shards": _chunk_for_source(assignments, source["artifact"]),
        }
        for source in sources
    ]
    registry_debts = [
        {
            "artifact": source["artifact"],
            "producer_key": source["producer_key"],
            "registry_status": source["registry_status"],
            "debt": source["registry_debt"],
        }
        for source in sources
        if source.get("registry_debt")
    ]
    observed_artifacts: list[dict[str, str]] = []
    for name in sorted(set([*chunk_names, *final_names])):
        path = root / name
        if path.is_file():
            try:
                observed_artifacts.append({"artifact": name, "sha256": _file_sha(path)})
            except OSError:
                pass
    manifest_artifacts: list[dict[str, str]] = []
    if phase_name and phase_name.startswith("inventory_chunk_"):
        own_manifest = root / f"{phase_name}.manifest.md"
        manifest_paths = [own_manifest] if own_manifest.is_file() else []
    else:
        manifest_paths = sorted(root.glob("inventory_chunk_*.manifest.md"))
    plan_path = root / "inventory_shard_plan.md"
    if plan_path.is_file():
        manifest_paths.append(plan_path)
    for path in manifest_paths:
        try:
            manifest_artifacts.append(
                {"artifact": path.name, "sha256": _file_sha(path)}
            )
        except OSError:
            artifact_issues.append(f"{path.name} became unreadable during reconciliation")
    denominator = [
        {
            key: row[key]
            for key in (
                "candidate_key", "source_artifact", "source_sha256",
                "source_finding_id", "source_ordinal", "source_block_sha256",
            )
        }
        for row in results
    ]
    payload: dict[str, Any] = {
        "schema_version": RECONCILIATION_SCHEMA,
        "scope": phase_name or "final",
        "registry_digest": registry_digest(),
        "source_artifacts": source_artifacts,
        "registry_debts": registry_debts,
        "registry_debt_count": len(registry_debts),
        "manifest_artifacts": manifest_artifacts,
        "observed_artifacts": observed_artifacts,
        "authority_artifact": AUTHORITY_FILE if authority_sha else "",
        "authority_sha256": authority_sha,
        "reemit_authority_artifact": REEMIT_FILE if reemit_sha else "",
        "reemit_authority_sha256": reemit_sha,
        "denominator_count": len(denominator),
        "denominator_digest": _digest(denominator),
        "artifact_issues": sorted(set(artifact_issues)),
        "candidates": results,
        "summary": summary,
    }
    payload["receipt_digest"] = _digest(payload)
    if persist:
        receipt_name, human_name = _output_names(phase_name)
        _atomic_write(
            root / receipt_name,
            (json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8"),
        )
        _atomic_write(
            root / human_name,
            _human_review_markdown(payload).encode("utf-8"),
        )
    return payload


def write_inventory_reconciliation(
    scratchpad: Path,
    *,
    phase_name: str | None = None,
) -> dict[str, Any]:
    return reconcile_inventory(scratchpad, phase_name=phase_name, persist=True)


def validate_inventory_reconciliation(
    scratchpad: Path,
    *,
    phase_name: str | None = None,
) -> list[str]:
    root = Path(scratchpad)
    receipt_name, human_name = _output_names(phase_name)
    expected = reconcile_inventory(root, phase_name=phase_name, persist=False)
    issues: list[str] = []
    try:
        actual = _strict_json(root / receipt_name)
    except InventoryReconciliationError as exc:
        actual = None
        issues.append(str(exc))
    if actual is not None and actual != expected:
        issues.append(f"{receipt_name} differs from current exact reconciliation")
    expected_human = _human_review_markdown(expected).encode("utf-8")
    try:
        actual_human = (root / human_name).read_bytes()
    except OSError as exc:
        issues.append(f"{human_name} is unavailable: {type(exc).__name__}: {exc}")
    else:
        if actual_human != expected_human:
            issues.append(f"{human_name} differs from current content-bearing debt")
    return issues


__all__ = [
    "AUTHORITY_FILE",
    "AUTHORITY_SCHEMA",
    "HUMAN_REVIEW_FILE",
    "NEGATIVE_EVIDENCE_SCHEMA",
    "RECONCILIATION_FILE",
    "RECONCILIATION_SCHEMA",
    "InventoryReconciliationError",
    "reconcile_inventory",
    "validate_inventory_reconciliation",
    "write_inventory_reconciliation",
]
