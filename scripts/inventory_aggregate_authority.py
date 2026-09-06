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


class InventoryAggregateError(ValueError):
    """Raised when a canonical inventory plan is incomplete or inconsistent."""


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
        "local_id": source_id,
        "source_ids": [source_id] if source_id else [],
        **{
            field: block.get(field, "")
            for field in _OPTIONAL_FINDING_METADATA_FIELDS
            if block.get(field)
        },
    }


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
        root_cause = _strip_md(str(item.get("root_cause", ""))) or title
        description = (
            _strip_md(str(item.get("description", ""))) or root_cause
        )
        impact = (
            _strip_md(str(item.get("impact", "")))
            or "Impact requires verifier confirmation."
        )
        verdict = (
            _strip_md(str(item.get("verdict", "")))
            or "NEEDS_VERIFICATION"
        )
        optional_lines: list[str] = []
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
                f"**Verdict**: {verdict}",
                f"**Root Cause**: {root_cause}",
                f"**Description**: {description}",
                f"**Impact**: {impact}",
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

    entries: list[dict[str, object]] = []
    for name in chunk_names:
        entries.extend(_parse_inventory_chunk(root / name))
    parsed_chunk_count = len(entries)

    floor_source_names: list[str] = []
    if kind == "floor_reconstruction":
        for name in normalized_sources:
            if (
                name in chunk_names
                or name in manifest_names
                or name in {"_id_ledger.json", "inventory_shard_plan.md"}
            ):
                continue
            floor_source_names.append(name)
            for block in _parse_depth_finding_blocks(root / name):
                entries.append(_floor_entry(block))

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
    inventory_text, allocations = _render_inventory(
        merged, derivation_kind=kind
    )
    inventory_bytes = inventory_text.encode("utf-8")
    records_bytes = _finding_records_bytes(inventory_bytes)
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
            "",
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
    if set(bindings_by_artifact) != set(normalized_sources):
        raise InventoryAggregateError(
            "inventory aggregate source producer bindings are incomplete"
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
