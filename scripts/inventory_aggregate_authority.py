"""Pure canonical inventory derivation for the PhaseIO transaction boundary.

This module deliberately does not write files or touch the artifact ledger.
The driver owns prebinding, materialization, validation, and commit.  Persisting
the complete planned bytes makes a crash between output writes resumable
without re-reading a partially materialized output as an input.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any, Mapping, Sequence

from inventory_id_ledger_merge import (
    build_inventory_allocation_delta,
    encode_inventory_allocation_delta,
)
from inventory_source_action_authority import (
    InventorySourceActionError,
    bind_exact_source_actions,
)
from inventory_reconciliation import (
    DRIVER_RESTORABLE_AXIS_FIELDS,
    _canonical_blocks,
    _semantic_lexical_surface,
    driver_restorable_preservation_row,
    reconcile_inventory,
)
from plamen_mechanical import _records_from_inventory_text
from plamen_parsers import (
    EVIDENCE_TAG_DEFAULT,
    _OPTIONAL_FINDING_METADATA_FIELDS,
    _OPTIONAL_FINDING_METADATA_LABELS,
    _extract_first_tag,
    _merge_inventory_entries,
    _norm_loc,
    _normalize_finding_id,
    _parse_depth_finding_blocks,
    _parse_inventory_chunk,
    _severity_name_from_text,
    _strip_md,
    _title_hash,
)


PLAN_SCHEMA = "plamen.inventory_aggregate_derivation.v1"
OUTPUT_NAMES = (
    "findings_inventory.md",
    "finding_records.json",
    "inventory_merge_receipt.md",
    "inventory_id_allocation_delta.json",
)
DERIVATION_KINDS = {
    "multi_shard",
    "single_shard",
    "typed_empty",
    "floor_reconstruction",
}
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_FINAL_HEADING_RE = re.compile(
    r"(?m)^### Finding \[(?P<finding>INV-\d+)\]:[^\r\n]*$"
)
_SOURCE_ACTION_LINE_RE = re.compile(
    r"(?m)^\*\*Source Actions\*\*: (?P<value>[^\r\n]+)$"
)
_SOURCE_ACTION_TOKEN_RE = re.compile(
    r"(?P<artifact>[A-Za-z0-9_.-]+\.md):"
    r"(?P<finding>[A-Za-z][A-Za-z0-9_-]{0,95}-\d+)@"
    r"(?P<digest>sha256:[0-9a-f]{64})",
    re.ASCII,
)


class InventoryAggregateError(ValueError):
    """Raised when a canonical inventory plan is incomplete or inconsistent."""


def _material_text(value: object) -> str:
    """Keep mechanism/harm syntax while projecting it onto one Markdown line.

    ``_strip_md`` is appropriate for identifiers and display metadata, but it
    removes every ``*`` byte and therefore rewrites Solidity multiplication
    such as ``amount * feePercent``.  Material finding fields come from the
    canonical, operationally parsed chunk view; preserve their inline code and
    operator syntax while only normalizing whitespace for the line-oriented
    final inventory format.
    """

    return re.sub(r"\s+", " ", str(value or "")).strip()


def _json_bytes(payload: Mapping[str, Any], *, pretty: bool = False) -> bytes:
    if pretty:
        text = json.dumps(
            payload,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            indent=2,
        )
    else:
        text = json.dumps(
            payload,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    return (text + "\n").encode("utf-8")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _floor_entry(block: Mapping[str, Any]) -> dict[str, object]:
    source_id = str(block.get("id") or "").strip()
    return {
        "title": block.get("title", ""),
        "severity": block.get("severity", ""),
        "location": block.get("location", ""),
        "preferred_tag": block.get("preferred_tag", ""),
        "verdict": block.get("verdict", ""),
        "root_cause": (
            block.get("root_cause", "") or block.get("description", "")
        ),
        "description": block.get("description", ""),
        "impact": block.get("impact", ""),
        "preconditions": block.get("preconditions", ""),
        "local_id": source_id,
        "source_ids": [source_id] if source_id else [],
        "source_actions": [],
        **{
            field: block.get(field, "")
            for field in _OPTIONAL_FINDING_METADATA_FIELDS
            if block.get(field)
        },
    }


def _chunk_entries_with_exact_material_facets(
    path: Path,
) -> list[dict[str, object]]:
    """Overlay the reconciliation parser's accepted material field view.

    The legacy inventory parser intentionally flattens compact table/detail
    records, but it does not retain the canonical ``Preconditions`` /
    ``Precondition Analysis`` surface.  The chunk gate admits bytes using
    ``inventory_reconciliation._canonical_blocks``; the deterministic
    aggregate must consume the same accepted view or it can manufacture new
    final-inventory debt after a chunk has already passed 29/29 coverage.

    This is an overlay, not a second disposition decision.  Source identity,
    authenticated actions, severity and routing continue to come from the
    existing chunk parser and PhaseIO-bound source denominator.
    """

    entries = _parse_inventory_chunk(path)
    blocks, issues = _canonical_blocks(path)
    if issues:
        raise InventoryAggregateError(
            f"accepted chunk canonical replay failed for {path.name}: "
            + "; ".join(issues)
        )
    by_id: dict[str, Mapping[str, Any]] = {}
    for block in blocks:
        finding_id = _normalize_finding_id(
            str(block.get("finding_id") or "")
        )
        if not finding_id or finding_id in by_id:
            raise InventoryAggregateError(
                f"accepted chunk material identity is absent or duplicated: "
                f"{path.name}:{finding_id or 'UNKNOWN'}"
            )
        by_id[finding_id] = block

    matched: set[str] = set()
    for entry in entries:
        local_id = _normalize_finding_id(str(entry.get("local_id") or ""))
        block = by_id.get(local_id)
        if block is None:
            continue
        matched.add(local_id)
        # Preserve the exact normalized evidence surfaces used by the chunk
        # reconciliation gate.  In particular, do not silently drop a valid
        # precondition merely because it was rendered as a heading section.
        for field in (
            "root_cause", "description", "impact", "preconditions",
        ):
            value = str(block.get(field) or "")
            if value:
                entry[field] = value

    # Current V3 chunks require one detail block for every parsed row.  A
    # partial overlay would revive the same split-parser trust boundary this
    # helper closes.  Empty/table-only compatibility fixtures retain their
    # prior behavior because they expose no canonical detail blocks.
    if blocks and (
        len(matched) != len(entries)
        or len(matched) != len(blocks)
    ):
        raise InventoryAggregateError(
            f"accepted chunk material denominator differs from parsed rows: "
            f"{path.name} ({len(matched)}/{len(entries)} rows, "
            f"{len(blocks)} detail blocks)"
        )
    return entries


def _bind_exact_source_actions(
    root: Path,
    source_names: Sequence[str],
    entries: Sequence[dict[str, object]],
) -> None:
    """Authenticate chunk-declared artifact/local-ID provenance in place.

    Inventory chunks already carry ``artifact.md:LOCAL-ID`` tokens, and every
    manifest-assigned artifact is an exact PhaseIO input to this derivation.
    Only a token that also names a real finding block owned by the registered
    producer is projected into the canonical inventory.  An unresolved or
    colliding bare ID remains visible in ``Source IDs`` but gains no delivery
    authority.
    """

    try:
        bind_exact_source_actions(root, source_names, entries)
    except InventorySourceActionError as exc:
        raise InventoryAggregateError(str(exc)) from exc


# Facet axis -> the entry field rebuilt into findings_inventory.md. The source
# side is DRIVER_RESTORABLE_AXIS_FIELDS, shared with the gate so the set of
# exempted rows and the set of repaired rows are the same set by construction.
_RESTORABLE_FACET_FIELDS = {
    "ROOT_CAUSE": "root_cause",
    "IMPACT": "impact",
    "PRECONDITIONS": "preconditions",
}


def _restore_unpreserved_source_facets(
    root: Path, chunk_name: str | None, entries: Sequence[dict[str, object]],
) -> list[dict[str, str]]:
    """Splice verbatim source facet bytes the chunk shard did not carry.

    A chunk shard is asked to transcribe upstream facet text byte-for-byte into
    its own detail blocks. That is a data-bus task, not a judgment task, and a
    model will not do it reliably: DODO run35's attempt 2 was handed 11 exact
    source facets in its prompt and still reworded them. The bytes that go
    missing are the structured ones -- a 28-row privilege table, a
    boundary-substitution table -- precisely the evidence downstream phases
    need most.

    So the driver transcribes instead. This runs at the AGGREGATE, not on the
    chunk: `findings_inventory.md` is what every downstream phase reads, and
    `inventory/canonical_aggregate` is an already-registered projection.
    Repairing the chunk in place is refused by design -- no registered handoff
    exists for `findings_inventory_chunk_*.md`, and
    `inventory_reemit_authority._build_intent` rejects one-to-one chunk repair
    with "repair the canonical projection instead".

    Strictly additive: source bytes are appended to the field that should have
    carried them, never replacing model text, and only for unambiguous
    one-to-one retention rows. Ambiguous many-to-one, merge, and refutation
    authority rows are untouched -- restoring bytes there would manufacture the
    equivalence those dispositions exist to withhold.
    """

    # `chunk_name=None` selects the FINAL projection scope, whose denominator
    # is the whole raw discovery set rather than one chunk's assigned sources.
    phase_name = (
        chunk_name[len("findings_"):-len(".md")] if chunk_name else None
    )
    scope_label = chunk_name or "findings_inventory.md"
    try:
        payload = reconcile_inventory(root, phase_name=phase_name, persist=False)
    except Exception:
        # Restoration is a repair, never a new failure mode for the aggregate.
        # The unrestored facet stays visible as reconciliation debt.
        return []

    by_target: dict[str, list[Mapping[str, Any]]] = {}
    by_source: dict[tuple[str, str], list[Mapping[str, Any]]] = {}
    for row in payload.get("candidates", ()):
        if not isinstance(row, Mapping):
            continue
        # EXACTLY the rows the gate stopped blocking on. Sharing the
        # predicate is the safety property: an exemption the splice declines
        # would be silent content loss.
        if not driver_restorable_preservation_row(row):
            continue
        target = _normalize_finding_id(
            str(row.get("proposed_target_finding_id") or "")
        )
        if target:
            by_target.setdefault(target, []).append(row)
        # SOURCE-keyed index, required for the final projection.
        #
        # `proposed_target_finding_id` is an `INV-NNN` allocated inside
        # `_render_inventory`, so at merge time -- which is when this pass must
        # run, before the bytes are rendered -- no entry carries it yet. Keying
        # on the SOURCE identity works in both scopes, because the source is
        # what the entry already claims.
        source_key = (
            str(row.get("source_artifact") or ""),
            _normalize_finding_id(str(row.get("source_finding_id") or "")),
        )
        if all(source_key):
            by_source.setdefault(source_key, []).append(row)

    restored: list[dict[str, str]] = []
    for entry in entries:
        local_id = _normalize_finding_id(str(entry.get("local_id") or ""))
        rows = by_target.get(local_id) or []
        if not rows:
            # Fall back to the source-keyed index. An entry may claim several
            # sources after merging; require EXACTLY ONE of them to owe a
            # facet, or the one-to-one guarantee this repair depends on does
            # not hold and the row keeps its debt.
            # `source_actions` is still empty at merge time -- it is bound
            # later -- but `source_ids` already carries the upstream producer
            # IDs the entry claims (e.g. ['B3-13', 'CC-26']). Key on those.
            claimed_ids = {
                _normalize_finding_id(str(value))
                for value in (entry.get("source_ids") or ())
            }
            claimed_ids.discard("")
            claimed: list[Mapping[str, Any]] = []
            for (_artifact, source_id), source_rows in by_source.items():
                if source_id in claimed_ids:
                    claimed.extend(source_rows)
            unique = {id(row): row for row in claimed}
            rows = list(unique.values())
        if len(rows) != 1:
            # Zero rows: nothing owed. More than one: the identity relation is
            # not one-to-one after all, so no source owns this block's facets.
            continue
        row = rows[0]
        for axis in row.get("required_preservation_axes") or ():
            entry_field = _RESTORABLE_FACET_FIELDS.get(str(axis))
            source_field = DRIVER_RESTORABLE_AXIS_FIELDS.get(str(axis))
            if entry_field is None or source_field is None:
                # UNPARSEABLE_*: the source rendered no such facet. There are
                # no bytes to transcribe; it stays reconciliation debt. (The
                # shared predicate already refuses such rows, so this is a
                # belt-and-braces guard rather than the primary bound.)
                continue
            source = _semantic_lexical_surface(row.get(source_field))
            if not source:
                continue
            current = str(entry.get(entry_field) or "")
            if source in _semantic_lexical_surface(current):
                continue
            provenance = (
                f"{row.get('source_artifact') or '?'}:"
                f"{row.get('source_finding_id') or '?'}"
            )
            entry[entry_field] = (
                f"{current.rstrip()} " if current.strip() else ""
            ) + f"[source-preserved {provenance}] {source}"
            restored.append({
                "chunk": scope_label,
                "finding_id": local_id,
                "axis": str(axis),
                "source": provenance,
                "repair_action_id": str(row.get("repair_action_id") or ""),
            })
    return restored


def _derivation_entries(
    root: Path,
    kind: str,
    normalized_sources: Sequence[str],
) -> tuple[list[dict[str, object]], int, list[str]]:
    chunk_names = tuple(
        name for name in normalized_sources
        if re.fullmatch(r"findings_inventory_chunk_[abc]\.md", name)
    )
    entries: list[dict[str, object]] = []
    restored: list[dict[str, str]] = []
    for name in chunk_names:
        chunk_entries = _chunk_entries_with_exact_material_facets(root / name)
        # Avizienis et al. (IEEE TDSC 1(1), 2004): masking "will conceal a
        # possibly progressive and eventually fatal loss of protective
        # redundancy", so a compensating repair must be paired with detection
        # that REPORTS what it repaired -- "masking AND recovery", never
        # masking alone. A silent splice would train the pipeline to accept a
        # widening deviation, so every restored facet is carried out of this
        # pure derivation and into the committed receipt.
        restored.extend(
            _restore_unpreserved_source_facets(root, name, chunk_entries)
        )
        entries.extend(chunk_entries)
    parsed_chunk_count = len(entries)
    floor_source_names: list[str] = []
    if kind == "floor_reconstruction":
        for name in normalized_sources:
            if (
                name in chunk_names
                or re.fullmatch(r"inventory_chunk_[abc]\.manifest\.md", name)
                or name in {"_id_ledger.json", "inventory_shard_plan.md"}
            ):
                continue
            floor_source_names.append(name)
            for block in _parse_depth_finding_blocks(root / name):
                entry = _floor_entry(block)
                source_id = str(entry.get("local_id") or "").strip().upper()
                if source_id:
                    entry["source_actions"] = [(name, source_id)]
                entries.append(entry)
    _bind_exact_source_actions(root, normalized_sources, entries)
    return entries, parsed_chunk_count, floor_source_names, restored


def _rendered_delivery_issues(
    entries: Sequence[Mapping[str, object]],
    inventory_text: str,
    records_text: str,
) -> list[str]:
    """Require a one-to-one, content-addressed delivery for every chunk row."""

    expected: list[tuple[str, str, str]] = []
    issues: list[str] = []
    for index, entry in enumerate(entries, start=1):
        actions = list(entry.get("source_actions", []) or [])
        if len(actions) != 1 or len(actions[0]) != 3:
            issues.append(
                f"inventory source row {index} lacks exactly one authenticated source action"
            )
            continue
        expected.append(tuple(map(str, actions[0])))
    if len(set(expected)) != len(expected):
        issues.append("inventory source-action denominator contains duplicates")

    headings = list(_FINAL_HEADING_RE.finditer(inventory_text))
    observed: list[tuple[str, str, str]] = []
    observed_ids: list[str] = []
    observed_blocks: dict[tuple[str, str, str], str] = {}
    for index, heading in enumerate(headings):
        end = headings[index + 1].start() if index + 1 < len(headings) else len(
            inventory_text
        )
        block = inventory_text[heading.start():end]
        action_lines = list(_SOURCE_ACTION_LINE_RE.finditer(block))
        finding_id = heading.group("finding")
        if len(action_lines) != 1:
            issues.append(
                f"{finding_id} lacks exactly one Source Actions field"
            )
            continue
        tokens = [
            token.strip()
            for token in action_lines[0].group("value").split(",")
            if token.strip()
        ]
        if len(tokens) != 1:
            issues.append(
                f"{finding_id} does not carry exactly one source action"
            )
            continue
        match = _SOURCE_ACTION_TOKEN_RE.fullmatch(tokens[0])
        if match is None:
            issues.append(f"{finding_id} source action is malformed")
            continue
        source_action = (
            match.group("artifact"),
            match.group("finding").upper(),
            match.group("digest"),
        )
        observed.append(source_action)
        observed_blocks.setdefault(source_action, block)
        observed_ids.append(finding_id)

    expected_tokens = sorted(
        (artifact, finding.upper(), digest)
        for artifact, finding, digest in expected
    )
    if sorted(observed) != expected_tokens:
        issues.append("canonical inventory source-action denominator mismatch")
    if len(observed) != len(set(observed)):
        issues.append("canonical inventory repeats an upstream source action")
    if len(headings) != len(entries):
        issues.append(
            "canonical inventory finding count differs from the exact source-row denominator"
        )

    # One-to-one source-action coverage is necessary but not sufficient: the
    # DRIVER projection must also retain every material facet already accepted
    # in the chunk.  Validate this before the aggregate can be committed so a
    # later additive repair is never asked to duplicate an existing delivery.
    if len(headings) == len(entries):
        for index, entry in enumerate(entries, start=1):
            actions = list(entry.get("source_actions", []) or [])
            if len(actions) != 1 or len(actions[0]) != 3:
                continue
            source_action = tuple(map(str, actions[0]))
            block = observed_blocks.get(source_action)
            if block is None:
                # The exact denominator mismatch above owns this failure.
                continue
            normalized_block = _semantic_lexical_surface(block)
            for field, label in (
                ("root_cause", "root cause"),
                ("impact", "impact"),
                ("preconditions", "preconditions"),
            ):
                normalized_value = _semantic_lexical_surface(
                    entry.get(field)
                )
                if normalized_value and normalized_value not in normalized_block:
                    issues.append(
                        "canonical inventory source action "
                        f"{source_action[0]}:{source_action[1]} loses accepted "
                        f"{label} material (input row {index})"
                    )

    try:
        records = json.loads(records_text)
        record_rows = records.get("records") if isinstance(records, Mapping) else None
    except (TypeError, json.JSONDecodeError):
        record_rows = None
    if (
        not isinstance(record_rows, list)
        or len(record_rows) != len(headings)
        or [str(row.get("inventory_id") or "") for row in record_rows if isinstance(row, Mapping)]
        != observed_ids
    ):
        issues.append("finding_records is not an exact final-inventory projection")
    return list(dict.fromkeys(issues))


def validate_inventory_aggregate_delivery(
    scratchpad: Path,
    payload: Mapping[str, Any],
) -> list[str]:
    """Replay the exact source-action and cardinality boundary without writes."""

    validate_inventory_aggregate_derivation(payload)
    root = Path(scratchpad)
    names = tuple(
        str(row.get("artifact") or "")
        for row in payload.get("source_artifacts", [])
        if isinstance(row, Mapping)
    )
    entries, _parsed, _floor, _restored = _derivation_entries(
        root, str(payload.get("derivation_kind") or ""), names
    )
    output = payload["output_payloads"]
    return _rendered_delivery_issues(
        entries,
        str(output["findings_inventory.md"]),
        str(output["finding_records.json"]),
    )


def _empty_inventory_text(derivation_kind: str) -> str:
    return "\n".join(
        (
            "# Finding Inventory",
            "",
            "Generated mechanically from the exact canonical inventory "
            f"derivation `{derivation_kind}`.",
            "",
            "## Summary",
            "",
            "| Severity | Count |",
            "|----------|-------|",
            "| Critical | 0 |",
            "| High | 0 |",
            "| Medium | 0 |",
            "| Low | 0 |",
            "| Informational | 0 |",
            "| Total | 0 |",
            "",
            "## Findings",
            "",
            "_No findings._",
            "",
        )
    )


def _render_inventory(
    merged: Sequence[Mapping[str, object]],
    *,
    derivation_kind: str,
) -> tuple[str, list[tuple[str, str]]]:
    if not merged:
        return _empty_inventory_text(derivation_kind), []

    counts = {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0,
        "Informational": 0,
    }
    for item in merged:
        severity = _severity_name_from_text(
            "", {"severity": str(item.get("severity", ""))}
        )
        counts[severity] = counts.get(severity, 0) + 1

    lines = [
        "# Finding Inventory",
        "",
        "Generated mechanically from an exact PhaseIO-bound source denominator.",
        "Source IDs are preserved; evidence tags absent from MODEL output are",
        "defaulted only in this DRIVER-owned canonical projection.",
        "",
        "## Summary",
        "",
        "| Severity | Count |",
        "|----------|-------|",
    ]
    for severity in (
        "Critical",
        "High",
        "Medium",
        "Low",
        "Informational",
    ):
        lines.append(f"| {severity} | {counts.get(severity, 0)} |")
    lines.extend(
        (
            f"| Total | {len(merged)} |",
            "",
            "## Findings",
            "",
        )
    )

    allocations: list[tuple[str, str]] = []
    for index, item in enumerate(merged, start=1):
        finding_id = f"INV-{index:03d}"
        severity = _severity_name_from_text(
            "", {"severity": str(item.get("severity", ""))}
        )
        title = _strip_md(str(item.get("title", ""))) or "Untitled finding"
        location = _norm_loc(str(item.get("location", ""))) or "UNKNOWN"
        preferred_tag = (
            _extract_first_tag(str(item.get("preferred_tag", "")))
            or _strip_md(str(item.get("preferred_tag", "")))
            or EVIDENCE_TAG_DEFAULT
        )
        source_ids: list[str] = []
        for raw in item.get("source_ids", []) or []:
            source_id = _normalize_finding_id(str(raw)) or _strip_md(str(raw))
            if source_id and source_id not in source_ids:
                source_ids.append(source_id)
        local_raw = str(item.get("local_id", "") or "")
        local_id = _normalize_finding_id(local_raw) or _strip_md(local_raw)
        if local_id and local_id not in source_ids:
            source_ids.append(local_id)
        source_text = (
            ", ".join(source_ids) if source_ids else "SOURCE_UNVERIFIED"
        )
        source_actions: list[str] = []
        for raw in item.get("source_actions", []) or []:
            if not isinstance(raw, (tuple, list)) or len(raw) != 3:
                continue
            artifact, action_id, source_hash = map(str, raw)
            token = f"{artifact}:{action_id}@{source_hash}"
            if token not in source_actions:
                source_actions.append(token)
        root_cause = _material_text(item.get("root_cause")) or title
        description = (
            _material_text(item.get("description")) or root_cause
        )
        impact = (
            _material_text(item.get("impact"))
            or "Impact requires verifier confirmation."
        )
        verdict = (
            _strip_md(str(item.get("verdict", "")))
            or "NEEDS_VERIFICATION"
        )
        optional_lines: list[str] = []
        preconditions = _material_text(item.get("preconditions"))
        for field in _OPTIONAL_FINDING_METADATA_FIELDS:
            value = _strip_md(str(item.get(field, ""))).strip()
            if value:
                label = _OPTIONAL_FINDING_METADATA_LABELS[field][0]
                optional_lines.append(f"**{label}**: {value}")
        lines.extend(
            (
                f"### Finding [{finding_id}]: {title}",
                f"**Severity**: {severity}",
                f"**Location**: {location}",
                f"**Preferred Tag**: {preferred_tag}",
                f"**Source IDs**: {source_text}",
                *(
                    (f"**Source Actions**: {', '.join(source_actions)}",)
                    if source_actions
                    else ()
                ),
                f"**Verdict**: {verdict}",
                f"**Root Cause**: {root_cause}",
                f"**Description**: {description}",
                f"**Impact**: {impact}",
                *((f"**Preconditions**: {preconditions}",) if preconditions else ()),
                *optional_lines,
                "",
            )
        )
        allocations.append((finding_id, title))
    return "\n".join(lines), allocations


def _allocation_rows(
    allocations: Sequence[tuple[str, str]],
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    existing_ids: set[str] = set()
    for finding_id, title in allocations:
        if finding_id in existing_ids:
            raise InventoryAggregateError(
                f"canonical inventory allocation is duplicated: {finding_id}"
            )
        rows.append(
            {
                "id": finding_id,
                "prefix": "INV-",
                "owner_phase": "inventory",
                "owner_attempt": 1,
                "owning_artifact": "findings_inventory.md",
                "title_hash": _title_hash(title),
                "title_preview": title[:120],
                # Stable by design: the derivation plan, not wall time, is the
                # immutable allocation event for this canonical transition.
                "allocated_at": "1970-01-01T00:00:00+00:00",
            }
        )
        existing_ids.add(finding_id)
    return rows


def _finding_records_bytes(inventory_bytes: bytes) -> bytes:
    text = inventory_bytes.decode("utf-8", errors="strict")
    records = _records_from_inventory_text(text)
    return _json_bytes(
        {
            "schema_version": "plamen.finding_records.v2",
            "source": "findings_inventory.md",
            "source_sha256": _sha256(inventory_bytes),
            "records": records,
        }
    )


def build_inventory_aggregate_derivation(
    scratchpad: Path,
    *,
    derivation_kind: str,
    run_id: str,
    source_names: Sequence[str],
    source_bindings: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Derive all canonical output bytes without mutating disk."""

    root = Path(scratchpad)
    kind = str(derivation_kind or "").strip()
    if kind not in DERIVATION_KINDS:
        raise InventoryAggregateError(
            f"unsupported inventory derivation kind: {kind!r}"
        )
    if not str(run_id or "").strip():
        raise InventoryAggregateError("inventory aggregate requires run_id")
    normalized_sources = tuple(sorted({str(name) for name in source_names}))
    if (
        not normalized_sources
        or len(normalized_sources) != len(tuple(source_names))
        or any(
            not name
            or Path(name).name != name
            or not (root / name).is_file()
            for name in normalized_sources
        )
    ):
        raise InventoryAggregateError(
            "inventory aggregate source denominator is invalid"
        )

    chunk_names = tuple(
        name
        for name in normalized_sources
        if re.fullmatch(r"findings_inventory_chunk_[abc]\.md", name)
    )
    manifest_names = tuple(
        name
        for name in normalized_sources
        if re.fullmatch(r"inventory_chunk_[abc]\.manifest\.md", name)
    )
    manifest_letters = {
        re.search(r"_([abc])\.manifest", name).group(1)
        for name in manifest_names
    }
    chunk_letters = {
        re.search(r"_([abc])\.md", name).group(1) for name in chunk_names
    }
    if not chunk_names or manifest_letters != chunk_letters:
        raise InventoryAggregateError(
            "terminal inventory chunk/manifest roster is incomplete"
        )

    entries, parsed_chunk_count, floor_source_names, restored_facets = (
        _derivation_entries(root, kind, normalized_sources)
    )

    if kind == "multi_shard" and len(chunk_names) < 2:
        raise InventoryAggregateError("multi_shard requires at least two chunks")
    if kind in {"single_shard", "typed_empty", "floor_reconstruction"} and (
        len(chunk_names) != 1
    ):
        raise InventoryAggregateError(f"{kind} requires exactly one chunk")
    if kind == "typed_empty" and entries:
        raise InventoryAggregateError(
            "typed_empty cannot contain parseable finding entries"
        )

    merged = _merge_inventory_entries(entries)
    if kind not in {"typed_empty"} and not merged:
        raise InventoryAggregateError(
            f"{kind} produced no canonical inventory findings"
        )
    # Second restoration pass, at FINAL-projection scope.
    #
    # The per-chunk pass above compares each chunk against its assigned
    # sources. This one compares the merged projection against the whole raw
    # discovery denominator, which is a different question and finds different
    # rows -- merging can drop a facet that survived inside its chunk.
    #
    # Without it DODO run39 cleared all three chunks on attempt 1 and then died
    # here: 9/132 FINAL_SEMANTIC_PRESERVATION_DEBT rows, every one a
    # ONE_TO_ONE_RETENTION_PROPOSAL, which `inventory_reemit_authority`
    # refuses by design -- "additive re-emission refuses to duplicate
    # one-to-one final deliveries; repair the canonical projection instead."
    # This is that repair. All nine came from `analysis_percontract_reemit.md`,
    # the driver's own recall-safety re-emission, whose facets the shard then
    # did not transcribe.
    restored_facets.extend(
        _restore_unpreserved_source_facets(root, None, merged)
    )
    inventory_text, allocations = _render_inventory(
        merged, derivation_kind=kind
    )
    inventory_bytes = inventory_text.encode("utf-8")
    records_bytes = _finding_records_bytes(inventory_bytes)
    delivery_issues = _rendered_delivery_issues(
        entries,
        inventory_text,
        records_bytes.decode("utf-8", errors="strict"),
    )
    if delivery_issues:
        raise InventoryAggregateError("; ".join(delivery_issues))
    delta = build_inventory_allocation_delta(
        run_id=str(run_id),
        inventory_sha256=_sha256(inventory_bytes),
        records_sha256=_sha256(records_bytes),
        allocations=_allocation_rows(allocations),
    )
    delta_bytes = encode_inventory_allocation_delta(delta)
    receipt_text = "\n".join(
        (
            "# Canonical Inventory Aggregate Receipt",
            "",
            f"Derivation kind: {kind}",
            f"Consumed chunk files: {len(chunk_names)}",
            f"Parsed chunk findings: {parsed_chunk_count}",
            f"Floor source artifacts: {len(floor_source_names)}",
            f"Canonical inventory findings: {len(merged)}",
            f"Driver-restored source facets: {len(restored_facets)}",
            "",
            *(
                (
                    "## Driver-Restored Source Facets",
                    "",
                    "Verbatim upstream facet bytes the chunk shard did not "
                    "transcribe, spliced here by the driver. This repair is "
                    "reported, never silent: a masking step that hides what it "
                    "masked conceals a progressive loss of protection.",
                    "",
                    "| Chunk | Finding | Axis | Source |",
                    "|---|---|---|---|",
                    *(
                        f"| `{row['chunk']}` | `{row['finding_id']}` | "
                        f"{row['axis']} | `{row['source']}` |"
                        for row in restored_facets
                    ),
                    "",
                )
                if restored_facets else ()
            ),
            "## Exact Source Denominator",
            "",
            *(
                f"- `{name}`: `{_sha256((root / name).read_bytes())}`"
                for name in normalized_sources
            ),
            "",
        )
    )
    receipt_bytes = receipt_text.encode("utf-8")
    output_bytes = {
        "findings_inventory.md": inventory_bytes,
        "finding_records.json": records_bytes,
        "inventory_merge_receipt.md": receipt_bytes,
        "inventory_id_allocation_delta.json": delta_bytes,
    }
    bindings_by_artifact = {
        str(row.get("artifact") or ""): dict(row) for row in source_bindings
    }
    if (
        len(bindings_by_artifact) != len(source_bindings)
        or set(bindings_by_artifact) != set(normalized_sources)
    ):
        raise InventoryAggregateError(
            "inventory aggregate source producer bindings are incomplete or "
            "duplicated"
        )
    for name, row in bindings_by_artifact.items():
        if (
            row.get("artifact") != name
            or row.get("sha256") != _sha256((root / name).read_bytes())
            or not _SHA256_RE.fullmatch(str(row.get("sha256") or ""))
        ):
            raise InventoryAggregateError(
                f"inventory aggregate source binding drift: {name}"
            )

    return {
        "schema_version": PLAN_SCHEMA,
        "run_id": str(run_id),
        "derivation_kind": kind,
        "source_artifacts": [
            bindings_by_artifact[name] for name in normalized_sources
        ],
        "consumed_chunks": list(chunk_names),
        "floor_sources": floor_source_names,
        "parsed_chunk_finding_count": parsed_chunk_count,
        "finding_count": len(merged),
        # First-class telemetry, not a log line: alarm on TREND here, since a
        # repair count that keeps climbing is the signature of drift toward
        # whatever the gate forgives (Kali, ISSTA 2015), which is
        # indistinguishable from correct behaviour at any single point.
        "restored_source_facet_count": len(restored_facets),
        "restored_source_facets": restored_facets,
        "consumed_chunk_count": len(chunk_names),
        "output_sha256": {
            name: _sha256(output_bytes[name]) for name in OUTPUT_NAMES
        },
        "output_payloads": {
            name: output_bytes[name].decode("utf-8") for name in OUTPUT_NAMES
        },
    }


def encode_inventory_aggregate_derivation(payload: Mapping[str, Any]) -> bytes:
    validate_inventory_aggregate_derivation(payload)
    return _json_bytes(payload, pretty=True)


def validate_inventory_aggregate_derivation(
    payload: Mapping[str, Any],
) -> None:
    if (
        not isinstance(payload, Mapping)
        or payload.get("schema_version") != PLAN_SCHEMA
        or payload.get("derivation_kind") not in DERIVATION_KINDS
        or not str(payload.get("run_id") or "")
        or not isinstance(payload.get("source_artifacts"), list)
        or not isinstance(payload.get("consumed_chunks"), list)
        or not isinstance(payload.get("floor_sources"), list)
        or not isinstance(payload.get("output_sha256"), Mapping)
        or not isinstance(payload.get("output_payloads"), Mapping)
    ):
        raise InventoryAggregateError(
            "inventory aggregate derivation schema is invalid"
        )
    digests = payload["output_sha256"]
    output_payloads = payload["output_payloads"]
    if set(digests) != set(OUTPUT_NAMES) or set(output_payloads) != set(
        OUTPUT_NAMES
    ):
        raise InventoryAggregateError(
            "inventory aggregate output denominator is incomplete"
        )
    for name in OUTPUT_NAMES:
        value = output_payloads[name]
        if not isinstance(value, str):
            raise InventoryAggregateError(
                f"inventory aggregate planned output is not text: {name}"
            )
        observed = _sha256(value.encode("utf-8"))
        if digests[name] != observed:
            raise InventoryAggregateError(
                f"inventory aggregate planned output digest mismatch: {name}"
            )


def planned_inventory_output_bytes(
    payload: Mapping[str, Any],
) -> dict[str, bytes]:
    validate_inventory_aggregate_derivation(payload)
    return {
        name: str(payload["output_payloads"][name]).encode("utf-8")
        for name in OUTPUT_NAMES
    }
