"""Typed authority for finite semantic-invariant methodology application.

This module intentionally owns no model prompt and no phase transition.  It
constructs a stable, snapshot-bound state denominator before the invariant
pass and reconciles an exact typed application trace after the pass.  Markdown
is an exact human projection only; prose and bare-name token presence never
grant application authority.

The mechanical graph is authoritative.  State-write and legacy inventory
facts may add missing symbols or evidence, but cannot overwrite graph facts.
Disagreement is retained as typed conflict debt.  A deferral is likewise open
debt, never successful coverage.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any, Iterable, Mapping

from state_symbol_authority import (
    GRAPH_SCHEMA,
    build_typed_state_symbols,
    normalize_state_symbol,
    parse_legacy_state_symbols,
)


AUTHORITY_SCHEMA = "plamen.semantic_invariant_state_authority.v1"
WORKLIST_SCHEMA = "plamen.semantic_invariant_worklist.v1"
APPLICATION_TRACE_SCHEMA = "plamen.semantic_invariant_application_trace.v2"
INDEPENDENT_TRACE_SCHEMA = "plamen.semantic_invariant_independent_application_trace.v1"
APPLICATION_RECEIPT_SCHEMA = "plamen.semantic_invariant_application_receipt.v3"
PASS2_PRE_SCHEMA = "plamen.semantic_invariant_pass2_append_authority.v1"
FINAL_BYTE_AUTHORITY_SCHEMA = (
    "plamen.semantic_invariant_final_byte_authority.v1"
)

AUTHORITY_FILE = "semantic_invariant_authority.json"
WORKLIST_FILE = "semantic_invariant_worklist.json"
WORKLIST_PROJECTION_FILE = "semantic_invariant_worklist.md"
APPLICATION_RECEIPT_FILE = "semantic_invariant_application_receipt.json"
GAPS_PROJECTION_FILE = "semantic_invariant_coverage_gaps.md"
INDEPENDENT_TRACE_FILE = "semantic_invariant_independent_application.input.json"
PASS2_PRE_FILE = "semantic_invariant_pass2_append_authority.json"
FINAL_BYTE_AUTHORITY_FILE = "semantic_invariant_final_byte_authority.json"

TRACE_BEGIN = "<!-- PLAMEN_SEMANTIC_INVARIANT_TRACE_JSON_BEGIN -->"
TRACE_END = "<!-- PLAMEN_SEMANTIC_INVARIANT_TRACE_JSON_END -->"

_CHECKPOINT_FILE = "_v2_checkpoint.json"
_GRAPH_FILE = "_mechanical_graph.json"
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_UUID4 = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
_STATE_ID = re.compile(r"^STATE-[0-9A-F]{16}$")
_ALLOWED_DISPOSITIONS = {"DELIVERED", "DEFERRED", "UNMEASURABLE"}
_ALLOWED_WRITE_STATUS = {"COMPLETE", "INCOMPLETE", "BOUNDED", "UNKNOWN"}
_ALLOWED_SEMANTIC_STATUS = {
    "SEMANTICS_OK",
    "SEMANTICS_SUSPECT",
    "SEMANTICS_UNKNOWN",
    "NOT_APPLICABLE",
}
_APPLICATION_ROW_KEYS = {
    "state_id",
    "disposition",
    "evidence_loci",
    "write_site_status",
    "semantic_status",
    "result",
}
_APPLICATION_KEYS = {
    "schema_version",
    "run_binding_digest",
    "authority_digest",
    "worklist_digest",
    "producer_operator_digest",
    "rows",
    "payload_digest",
}
_INDEPENDENT_KEYS = {
    "schema_version",
    "run_binding_digest",
    "authority_digest",
    "worklist_digest",
    "producer_payload_digest",
    "consumer_kind",
    "consumer_operator_digest",
    "rows",
    "payload_digest",
}
_INDEPENDENT_ROW_KEYS = {
    "state_id",
    "disposition",
    "producer_row_digest",
    "evidence_loci",
    "result",
}
_INDEPENDENT_CONSUMERS = {"DEPTH_STATE_TRACE", "APPLICATION_SKEPTIC"}
_SOURCE_LOCUS = re.compile(
    r"^(?P<file>[A-Za-z0-9_./\\ -]+\.(?:sol|rs|move|go|vy|daml))"
    r":L(?P<line>[1-9]\d*)(?:-L?[1-9]\d*)?$"
)


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _pretty_json(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    ).encode("utf-8")


def payload_digest(payload: Mapping[str, Any]) -> str:
    """Return the exact digest of an application payload without self-digest."""
    unsigned = {key: value for key, value in payload.items() if key != "payload_digest"}
    return _sha256_bytes(_canonical_json(unsigned))


def producer_row_digest(row: Mapping[str, Any]) -> str:
    """Bind an independent consumer to one exact producer trace row."""
    return _sha256_bytes(_canonical_json(dict(row)))


def _finalize(payload: dict[str, Any], digest_field: str) -> dict[str, Any]:
    unsigned = {key: value for key, value in payload.items() if key != digest_field}
    payload[digest_field] = _sha256_bytes(_canonical_json(unsigned))
    return payload


def _dedupe(values: Iterable[object]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        text = re.sub(r"\s+", " ", str(value or "")).strip()
        if not text or text in seen:
            continue
        seen.add(text)
        out.append(text)
    return sorted(out)


def _binding(path: Path, role: str) -> dict[str, Any]:
    data = path.read_bytes()
    return {
        "artifact": path.name,
        "role": role,
        "sha256": _sha256_bytes(data),
        "byte_count": len(data),
    }


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8", errors="strict"))


def _normalized_ecosystem(value: object) -> str:
    return re.sub(r"[^a-z0-9_]+", "", str(value or "").strip().lower()) or "unknown"


def _load_run_binding(
    root: Path,
    *,
    run_id: str = "",
    source_snapshot_digest: str = "",
    ecosystem: str = "",
    mode: str = "",
) -> tuple[dict[str, str], list[str]]:
    issues: list[str] = []
    checkpoint: Mapping[str, Any] = {}
    path = root / _CHECKPOINT_FILE
    if path.is_file():
        try:
            raw = _load_json(path)
            if isinstance(raw, Mapping):
                checkpoint = raw
            else:
                issues.append("checkpoint root is not an object")
        except Exception as exc:
            issues.append(f"checkpoint parse failed: {type(exc).__name__}")
    else:
        issues.append("checkpoint missing")

    config = checkpoint.get("config") if isinstance(checkpoint.get("config"), Mapping) else {}
    snapshot = (
        checkpoint.get("audit_snapshot")
        if isinstance(checkpoint.get("audit_snapshot"), Mapping)
        else {}
    )
    components = snapshot.get("components") if isinstance(snapshot.get("components"), Mapping) else {}
    source_scope = components.get("source_scope") if isinstance(components.get("source_scope"), Mapping) else {}

    checkpoint_run = str(checkpoint.get("run_id") or "").strip().lower()
    selected_run = str(run_id or checkpoint_run).strip().lower()
    if run_id and checkpoint_run and selected_run != checkpoint_run:
        issues.append("explicit run_id differs from checkpoint run_id")
    if not _UUID4.fullmatch(selected_run):
        issues.append("run_id is missing or is not a canonical UUIDv4")

    checkpoint_snapshot = str(snapshot.get("snapshot_digest") or "").strip().lower()
    selected_snapshot = str(source_snapshot_digest or checkpoint_snapshot).strip().lower()
    if source_snapshot_digest and checkpoint_snapshot and selected_snapshot != checkpoint_snapshot:
        issues.append("explicit source snapshot differs from checkpoint snapshot")
    if not _HEX64.fullmatch(selected_snapshot):
        issues.append("source_snapshot_digest is missing or invalid")

    source_scope_digest = str(source_scope.get("digest") or "").strip().lower()
    if not _HEX64.fullmatch(source_scope_digest):
        issues.append("source_scope_digest is missing or invalid")

    binding: dict[str, str] = {
        "run_id": selected_run,
        "source_snapshot_digest": selected_snapshot,
        "source_scope_digest": source_scope_digest,
        "ecosystem": _normalized_ecosystem(ecosystem or config.get("language")),
        "mode": str(mode or config.get("mode") or "unknown").strip().lower(),
        "pipeline": str(config.get("pipeline") or "unknown").strip().lower(),
    }
    binding["binding_digest"] = _sha256_bytes(_canonical_json(binding))
    return binding, issues


def _bare_name(qualified_name: object) -> str:
    text = str(qualified_name or "").strip().rstrip(".#/")
    parts = re.split(r"::|[.#/]", text)
    return parts[-1] if parts and parts[-1] else text


def _state_class(raw: Mapping[str, Any], normalized: Mapping[str, Any]) -> str:
    explicit = str(
        raw.get("state_class")
        or raw.get("storage_class")
        or raw.get("mutability")
        or raw.get("classification")
        or ""
    ).strip().upper()
    aliases = {
        "MUTABLE": "MUTABLE",
        "STORAGE": "MUTABLE",
        "RESOURCE": "MUTABLE",
        "GLOBAL": "MUTABLE",
        "IMMUTABLE": "IMMUTABLE",
        "CONSTANT": "IMMUTABLE",
        "CONST": "IMMUTABLE",
        "CONFIG": "CONFIG",
        "CONFIGURATION": "CONFIG",
        "DERIVED": "DERIVED",
        "COMPUTED": "DERIVED",
        "CACHE": "DERIVED",
        "EXTERNAL": "EXTERNAL",
        "REMOTE": "EXTERNAL",
    }
    if explicit in aliases:
        return aliases[explicit]
    if raw.get("immutable") is True or raw.get("constant") is True:
        return "IMMUTABLE"
    if normalized.get("write_sites"):
        return "MUTABLE"
    return "UNKNOWN"


def _type_domain(raw: Mapping[str, Any]) -> str:
    return re.sub(
        r"\s+",
        " ",
        str(
            raw.get("type_domain")
            or raw.get("type_name")
            or raw.get("type")
            or raw.get("domain")
            or "UNKNOWN"
        ),
    ).strip()


def _location_file(value: object) -> str:
    text = str(value or "").strip().replace("\\", "/")
    text = re.sub(r":?[Ll]\d+(?:\s*[-:]\s*[Ll]?\d+)?\s*$", "", text)
    return text.lstrip("./").casefold()


def _scope_name(value: object) -> str:
    text = str(value or "").replace("\\", "/").strip()
    if "::" in text:
        prefix = text.rsplit("::", 1)[0]
    elif "." in text:
        prefix = text.rsplit(".", 1)[0]
    else:
        prefix = ""
    name = Path(prefix).stem if prefix else ""
    return name.casefold()


def _normalize_graph_row(raw: Mapping[str, Any], source: str) -> dict[str, Any]:
    normalized = normalize_state_symbol(
        str(raw.get("qualified_name") or ""), dict(raw), source=source
    )
    if not _STATE_ID.fullmatch(str(normalized.get("symbol_id") or "")):
        retry = dict(raw)
        retry.pop("symbol_id", None)
        normalized = normalize_state_symbol(
            str(raw.get("qualified_name") or ""), retry, source=source
        )
    normalized["state_id"] = normalized.pop("symbol_id")
    normalized["state_class"] = _state_class(raw, normalized)
    normalized["type_domain"] = _type_domain(raw)
    normalized["source_provenance"] = [
        {
            "artifact": _GRAPH_FILE,
            "provider_source": normalized["provider_source"],
            "authority": "MECHANICAL_GRAPH",
        }
    ]
    return normalized


def _normalize_legacy_row(raw: Mapping[str, Any]) -> dict[str, Any]:
    row = dict(raw)
    row["state_id"] = row.pop("symbol_id")
    row["state_class"] = "MUTABLE" if row.get("write_sites") else "UNKNOWN"
    row["type_domain"] = "UNKNOWN"
    row["source_provenance"] = [
        {
            "artifact": str(row.get("provider_source") or "legacy"),
            "provider_source": str(row.get("provider_source") or "legacy"),
            "authority": "LEGACY_COMPATIBILITY",
        }
    ]
    return row


def _load_graph_rows(root: Path) -> tuple[list[dict[str, Any]], bool, list[str]]:
    path = root / _GRAPH_FILE
    issues: list[str] = []
    if not path.is_file():
        return [], False, ["mechanical graph missing"]
    try:
        payload = _load_json(path)
    except Exception as exc:
        return [], False, [f"mechanical graph parse failed: {type(exc).__name__}"]
    if not isinstance(payload, Mapping):
        return [], False, ["mechanical graph root is not an object"]
    if payload.get("schema_version") != GRAPH_SCHEMA:
        return [], False, ["mechanical graph schema is unsupported"]
    source = str(payload.get("source") or "unknown")
    raw_rows: list[Mapping[str, Any]] = []
    typed = payload.get("state_symbols")
    if isinstance(typed, list):
        for index, raw in enumerate(typed):
            if not isinstance(raw, Mapping) or not str(raw.get("qualified_name") or "").strip():
                issues.append(f"mechanical graph state_symbols[{index}] is malformed")
                continue
            raw_rows.append(raw)
    elif typed is not None:
        issues.append("mechanical graph state_symbols is not a list")
    if not raw_rows and isinstance(payload.get("var_refs"), dict):
        raw_rows = [dict(row) for row in build_typed_state_symbols(source, payload["var_refs"])]
    elif not raw_rows and payload.get("var_refs") is not None and not isinstance(payload.get("var_refs"), dict):
        issues.append("mechanical graph var_refs is not an object")
    rows = [_normalize_graph_row(raw, source) for raw in raw_rows]
    seen_ids: set[str] = set()
    seen_names: set[str] = set()
    for row in rows:
        state_id = str(row["state_id"])
        qualified = str(row["qualified_name"])
        if state_id in seen_ids:
            issues.append(f"duplicate mechanical state ID: {state_id}")
        if qualified in seen_names:
            issues.append(f"duplicate mechanical qualified name: {qualified}")
        seen_ids.add(state_id)
        seen_names.add(qualified)
    healthy = not any(
        issue.startswith("mechanical graph state_symbols")
        or issue.startswith("mechanical graph var_refs")
        or issue.startswith("duplicate mechanical")
        for issue in issues
    )
    return rows, healthy, issues


def _legacy_match(row: Mapping[str, Any], graph_rows: list[dict[str, Any]]) -> dict[str, Any] | None:
    qualified = str(row.get("qualified_name") or "")
    exact = [item for item in graph_rows if str(item.get("qualified_name") or "") == qualified]
    if len(exact) == 1:
        return exact[0]
    aliases = {str(value).casefold() for value in row.get("bare_aliases") or []}
    candidates = [
        item
        for item in graph_rows
        if aliases & {str(value).casefold() for value in item.get("bare_aliases") or []}
    ]
    legacy_file = _location_file(row.get("declaration_locus"))
    if legacy_file:
        by_file = [
            item for item in candidates
            if _location_file(item.get("declaration_locus")) == legacy_file
        ]
        if len(by_file) == 1:
            return by_file[0]
    legacy_scope = _scope_name(qualified)
    if legacy_scope:
        by_scope = [
            item for item in candidates
            if _scope_name(item.get("qualified_name")) == legacy_scope
            or Path(_location_file(item.get("declaration_locus"))).stem.casefold() == legacy_scope
        ]
        if len(by_scope) == 1:
            return by_scope[0]
    return None


def _conflict(
    state_id: str,
    kind: str,
    graph_values: Iterable[object],
    compatibility_values: Iterable[object],
    source: str,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "state_id": state_id,
        "kind": kind,
        "graph_values": _dedupe(graph_values),
        "compatibility_values": _dedupe(compatibility_values),
        "compatibility_source": source,
    }
    payload["conflict_id"] = "SIC-" + _sha256_bytes(_canonical_json(payload))[:16].upper()
    return payload


def _merge_state_sources(
    graph_rows: list[dict[str, Any]], legacy_rows: list[dict[str, Any]]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], int]:
    states = [dict(row) for row in graph_rows]
    conflicts: list[dict[str, Any]] = []
    compatibility_added = 0
    for raw in legacy_rows:
        legacy = _normalize_legacy_row(raw)
        target = _legacy_match(legacy, states[: len(graph_rows)])
        if target is None:
            states.append(legacy)
            compatibility_added += 1
            conflicts.append(
                _conflict(
                    str(legacy["state_id"]),
                    "LEGACY_ONLY_SYMBOL",
                    [],
                    [str(legacy.get("qualified_name") or "")],
                    str(legacy.get("provider_source") or "legacy"),
                )
            )
            continue
        source = str(legacy.get("provider_source") or "legacy")
        graph_declaration = str(target.get("declaration_locus") or "")
        legacy_declaration = str(legacy.get("declaration_locus") or "")
        if graph_declaration and legacy_declaration and (
            _location_file(graph_declaration) != _location_file(legacy_declaration)
        ):
            conflicts.append(
                _conflict(
                    str(target["state_id"]),
                    "DECLARATION_SOURCE_DISAGREEMENT",
                    [graph_declaration],
                    [legacy_declaration],
                    source,
                )
            )
        elif not graph_declaration and legacy_declaration:
            target["declaration_locus"] = legacy_declaration

        graph_writes = set(str(value) for value in target.get("write_sites") or [])
        legacy_writes = set(str(value) for value in legacy.get("write_sites") or [])
        if graph_writes and legacy_writes and graph_writes != legacy_writes:
            conflicts.append(
                _conflict(
                    str(target["state_id"]),
                    "WRITE_SITE_SOURCE_DISAGREEMENT",
                    graph_writes,
                    legacy_writes,
                    source,
                )
            )
        target["write_sites"] = _dedupe([*graph_writes, *legacy_writes])
        target["read_sites"] = _dedupe(
            [*(target.get("read_sites") or []), *(legacy.get("read_sites") or [])]
        )
        target["reference_sites"] = _dedupe(
            [
                *(target.get("reference_sites") or []),
                *(legacy.get("reference_sites") or []),
                *target["write_sites"],
                *target["read_sites"],
            ]
        )
        target["bare_aliases"] = _dedupe(
            [*(target.get("bare_aliases") or []), *(legacy.get("bare_aliases") or [])]
        )
        target["source_provenance"] = sorted(
            [*(target.get("source_provenance") or []), *(legacy.get("source_provenance") or [])],
            key=lambda value: (
                str(value.get("artifact") or ""),
                str(value.get("authority") or ""),
            ),
        )
        if target.get("state_class") == "UNKNOWN" and legacy_writes:
            target["state_class"] = "MUTABLE"
    unique_conflicts = {
        str(row["conflict_id"]): row for row in conflicts
    }
    states.sort(key=lambda row: (str(row["qualified_name"]), str(row["state_id"])))
    return states, [unique_conflicts[key] for key in sorted(unique_conflicts)], compatibility_added


def derive_semantic_invariant_authority(
    scratchpad: Path,
    *,
    ecosystem: str = "",
    mode: str = "",
    run_id: str = "",
    source_snapshot_digest: str = "",
) -> tuple[dict[str, Any], dict[str, Any], str]:
    """Derive the typed state authority, finite worklist, and exact projection."""
    root = Path(scratchpad)
    run_binding, binding_issues = _load_run_binding(
        root,
        run_id=run_id,
        source_snapshot_digest=source_snapshot_digest,
        ecosystem=ecosystem,
        mode=mode,
    )
    graph_rows, graph_healthy, graph_issues = _load_graph_rows(root)
    legacy_raw, legacy_counts = parse_legacy_state_symbols(root)
    states, conflicts, compatibility_added = _merge_state_sources(
        graph_rows, legacy_raw
    )

    input_bindings: list[dict[str, Any]] = []
    for name, role in (
        (_CHECKPOINT_FILE, "RUN_BINDING"),
        (_GRAPH_FILE, "MECHANICAL_GRAPH"),
        ("state_write_map.md", "COMPATIBILITY_STATE_WRITES"),
        ("state_variables.md", "COMPATIBILITY_STATE_INVENTORY"),
    ):
        path = root / name
        if path.is_file():
            try:
                input_bindings.append(_binding(path, role))
            except OSError:
                graph_issues.append(f"input artifact unreadable: {name}")
    input_bindings.sort(key=lambda row: (str(row["artifact"]), str(row["role"])))

    issues = sorted(set(binding_issues + graph_issues))
    fatal = bool(binding_issues) or not graph_healthy or any(
        issue.startswith("input artifact unreadable") for issue in issues
    )
    status = "UNMEASURABLE" if fatal else ("CONFLICT" if conflicts else "READY")
    authority = _finalize(
        {
            "schema_version": AUTHORITY_SCHEMA,
            "run_binding": run_binding,
            "ecosystem": run_binding["ecosystem"],
            "mode": run_binding["mode"],
            "status": status,
            "graph_substrate_healthy": graph_healthy,
            "input_bindings": input_bindings,
            "legacy_parse_counts": legacy_counts,
            "compatibility_added_count": compatibility_added,
            "state_count": len(states),
            "conflict_count": len(conflicts),
            "states": states,
            "conflicts": conflicts,
            "issues": issues,
        },
        "authority_digest",
    )

    conflicts_by_state: dict[str, list[str]] = {}
    for row in conflicts:
        conflicts_by_state.setdefault(str(row["state_id"]), []).append(
            str(row["conflict_id"])
        )
    work_states = [
        {
            "state_id": str(row["state_id"]),
            "qualified_name": str(row["qualified_name"]),
            "bare_aliases": list(row.get("bare_aliases") or []),
            "state_class": str(row.get("state_class") or "UNKNOWN"),
            "type_domain": str(row.get("type_domain") or "UNKNOWN"),
            "declaration_locus": str(row.get("declaration_locus") or ""),
            "read_sites": list(row.get("read_sites") or []),
            "write_sites": list(row.get("write_sites") or []),
            "reference_sites": list(row.get("reference_sites") or []),
            "authority": str(row.get("authority") or ""),
            "conflict_ids": sorted(conflicts_by_state.get(str(row["state_id"]), [])),
            "analysis_required": True,
            "required_trace_dispositions": sorted(_ALLOWED_DISPOSITIONS),
        }
        for row in states
    ]
    denominator_digest = _sha256_bytes(
        _canonical_json([row["state_id"] for row in work_states])
    )
    worklist = _finalize(
        {
            "schema_version": WORKLIST_SCHEMA,
            "run_binding": run_binding,
            "status": status,
            "authority_digest": authority["authority_digest"],
            "denominator_digest": denominator_digest,
            "state_count": len(work_states),
            "open_state_count": len(work_states),
            "states": work_states,
            "issues": issues,
        },
        "worklist_digest",
    )
    return authority, worklist, render_semantic_invariant_worklist(worklist)


def _escape_cell(value: object) -> str:
    return re.sub(r"\s+", " ", str(value or "")).strip().replace("|", "/")


def render_semantic_invariant_worklist(worklist: Mapping[str, Any]) -> str:
    run_binding = worklist.get("run_binding") if isinstance(worklist.get("run_binding"), Mapping) else {}
    lines = [
        "# Semantic Invariant Worklist",
        "",
        "Typed JSON is authoritative. This Markdown is an exact projection and is never parsed for application authority.",
        "",
        f"**Status**: {_escape_cell(worklist.get('status'))}",
        f"**Run binding**: `{_escape_cell(run_binding.get('binding_digest'))}`",
        f"**Authority digest**: `{_escape_cell(worklist.get('authority_digest'))}`",
        f"**Worklist digest**: `{_escape_cell(worklist.get('worklist_digest'))}`",
        f"**State denominator**: {int(worklist.get('state_count') or 0)}",
        "",
        "| State ID | Qualified Name | Class | Type Domain | Declaration | Writes | Reads | Authority | Conflict IDs |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    rows = worklist.get("states") if isinstance(worklist.get("states"), list) else []
    if rows:
        for row in rows:
            if not isinstance(row, Mapping):
                continue
            lines.append(
                "| `{state_id}` | `{qualified}` | {klass} | {domain} | {decl} | {writes} | {reads} | {authority} | {conflicts} |".format(
                    state_id=_escape_cell(row.get("state_id")),
                    qualified=_escape_cell(row.get("qualified_name")),
                    klass=_escape_cell(row.get("state_class")),
                    domain=_escape_cell(row.get("type_domain")),
                    decl=_escape_cell(row.get("declaration_locus")) or "n/a",
                    writes=_escape_cell(", ".join(row.get("write_sites") or [])) or "none enumerated",
                    reads=_escape_cell(", ".join(row.get("read_sites") or [])) or "none enumerated",
                    authority=_escape_cell(row.get("authority")),
                    conflicts=_escape_cell(", ".join(row.get("conflict_ids") or [])) or "none",
                )
            )
    else:
        lines.append("| n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | none |")
    issues = worklist.get("issues") if isinstance(worklist.get("issues"), list) else []
    if issues:
        lines.extend(["", "## Authority debt", ""])
        lines.extend(f"- {_escape_cell(issue)}" for issue in issues)
    lines.extend(
        [
            "",
            "Every State ID requires one exact typed application row. `DEFERRED` and source conflicts remain open downstream obligations.",
        ]
    )
    return "\n".join(lines) + "\n"


def _atomic_write_if_changed(path: Path, data: bytes) -> None:
    try:
        if path.is_file() and path.read_bytes() == data:
            return
    except OSError:
        pass
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        temporary.write_bytes(data)
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass


def materialize_semantic_invariant_compatibility_inputs(
    scratchpad: Path,
) -> list[str]:
    """Create explicit unavailable placeholders for absent legacy inputs.

    The typed graph remains the only positive state authority.  These fixed,
    empty compatibility artifacts make the PRE PhaseIO denominator stable
    without fabricating a state symbol or overwriting a recon producer output.
    """
    root = Path(scratchpad)
    root.mkdir(parents=True, exist_ok=True)
    placeholders = {
        "state_variables.md": (
            "# State Variables Compatibility Input\n\n"
            "<!-- PLAMEN_STATUS: UNAVAILABLE_COMPATIBILITY_INPUT -->\n\n"
            "No legacy state-variable rows were available. No state fact is "
            "asserted by this placeholder.\n"
        ),
        "state_write_map.md": (
            "# State Write Map Compatibility Input\n\n"
            "<!-- PLAMEN_STATUS: UNAVAILABLE_COMPATIBILITY_INPUT -->\n\n"
            "No legacy state-write rows were available. No write fact is "
            "asserted by this placeholder.\n"
        ),
    }
    created: list[str] = []
    for name in sorted(placeholders):
        path = root / name
        if path.exists():
            continue
        _atomic_write_if_changed(path, placeholders[name].encode("utf-8"))
        created.append(name)
    return created


def write_semantic_invariant_authority(
    scratchpad: Path,
    *,
    ecosystem: str = "",
    mode: str = "",
    run_id: str = "",
    source_snapshot_digest: str = "",
) -> dict[str, Any]:
    root = Path(scratchpad)
    root.mkdir(parents=True, exist_ok=True)
    authority, worklist, projection = derive_semantic_invariant_authority(
        root,
        ecosystem=ecosystem,
        mode=mode,
        run_id=run_id,
        source_snapshot_digest=source_snapshot_digest,
    )
    _atomic_write_if_changed(root / AUTHORITY_FILE, _pretty_json(authority))
    _atomic_write_if_changed(root / WORKLIST_FILE, _pretty_json(worklist))
    _atomic_write_if_changed(
        root / WORKLIST_PROJECTION_FILE, projection.encode("utf-8")
    )
    return authority


def validate_semantic_invariant_authority(
    scratchpad: Path,
    *,
    ecosystem: str = "",
    mode: str = "",
    run_id: str = "",
    source_snapshot_digest: str = "",
) -> list[str]:
    root = Path(scratchpad)
    expected_authority, expected_worklist, expected_projection = (
        derive_semantic_invariant_authority(
            root,
            ecosystem=ecosystem,
            mode=mode,
            run_id=run_id,
            source_snapshot_digest=source_snapshot_digest,
        )
    )
    issues: list[str] = []
    for name, expected in (
        (AUTHORITY_FILE, expected_authority),
        (WORKLIST_FILE, expected_worklist),
    ):
        try:
            actual = _load_json(root / name)
        except Exception as exc:
            issues.append(f"{name} missing or malformed: {type(exc).__name__}")
            continue
        if actual != expected:
            issues.append(f"{name} differs from current inputs")
    try:
        actual_projection = (root / WORKLIST_PROJECTION_FILE).read_text(
            encoding="utf-8", errors="strict"
        )
    except Exception as exc:
        issues.append(
            f"{WORKLIST_PROJECTION_FILE} missing or malformed: {type(exc).__name__}"
        )
    else:
        if actual_projection != expected_projection:
            issues.append(
                f"{WORKLIST_PROJECTION_FILE} differs from current typed worklist"
            )
    return issues


def parse_semantic_invariant_application_trace(text: str) -> dict[str, Any]:
    if text.count(TRACE_BEGIN) != 1 or text.count(TRACE_END) != 1:
        raise ValueError("semantic invariant trace sentinels must occur exactly once")
    start = text.index(TRACE_BEGIN) + len(TRACE_BEGIN)
    end = text.index(TRACE_END, start)
    raw = text[start:end].strip()
    if not raw:
        raise ValueError("semantic invariant trace payload is empty")
    payload = json.loads(raw)
    if not isinstance(payload, dict):
        raise ValueError("semantic invariant trace payload must be an object")
    return payload


def _validate_application_payload(
    payload: Mapping[str, Any], worklist: Mapping[str, Any]
) -> tuple[dict[str, Mapping[str, Any]], set[str], list[str], bool]:
    issues: list[str] = []
    fatal = False
    if set(payload) != _APPLICATION_KEYS:
        issues.append("application trace schema fields mismatch")
        fatal = True
    if payload.get("schema_version") != APPLICATION_TRACE_SCHEMA:
        issues.append("application trace schema version mismatch")
        fatal = True
    if payload.get("payload_digest") != payload_digest(payload):
        issues.append("application trace payload digest mismatch")
        fatal = True
    producer_operator_digest = str(
        payload.get("producer_operator_digest") or ""
    ).strip().lower()
    if not _HEX64.fullmatch(producer_operator_digest):
        issues.append("application trace producer operator digest is missing or invalid")
        fatal = True
    for field, expected, label in (
        (
            "run_binding_digest",
            (worklist.get("run_binding") or {}).get("binding_digest")
            if isinstance(worklist.get("run_binding"), Mapping)
            else "",
            "run binding digest mismatch",
        ),
        ("authority_digest", worklist.get("authority_digest"), "authority digest mismatch"),
        ("worklist_digest", worklist.get("worklist_digest"), "worklist digest mismatch"),
    ):
        if str(payload.get(field) or "") != str(expected or ""):
            issues.append(f"application trace {label}")
            fatal = True
    rows = payload.get("rows")
    if not isinstance(rows, list):
        issues.append("application trace rows is not an array")
        return {}, set(), issues, True
    by_id: dict[str, Mapping[str, Any]] = {}
    invalid_ids: set[str] = set()
    expected_ids = {
        str(row.get("state_id") or "")
        for row in worklist.get("states") or []
        if isinstance(row, Mapping)
    }
    for index, row in enumerate(rows):
        if not isinstance(row, Mapping):
            issues.append(f"application row {index} is not an object")
            fatal = True
            continue
        state_id = str(row.get("state_id") or "")
        if set(row) != _APPLICATION_ROW_KEYS:
            issues.append(f"application row {state_id or index} fields mismatch")
            invalid_ids.add(state_id)
        if state_id not in expected_ids:
            issues.append(f"application trace contains unknown state ID: {state_id or '<empty>'}")
            fatal = True
            continue
        if state_id in by_id:
            issues.append(f"application trace duplicates state ID: {state_id}")
            invalid_ids.add(state_id)
            continue
        by_id[state_id] = row
    missing = sorted(expected_ids - set(by_id))
    for state_id in missing:
        issues.append(f"application trace missing state ID: {state_id}")
        invalid_ids.add(state_id)
    return by_id, invalid_ids, issues, fatal


def _source_file(value: object) -> str:
    match = _SOURCE_LOCUS.fullmatch(str(value or "").strip())
    if not match:
        return ""
    return match.group("file").replace("\\", "/").lstrip("./").casefold()


def _state_source_denominator(state: Mapping[str, Any]) -> set[str]:
    values = [
        state.get("declaration_locus"),
        *(state.get("read_sites") or []),
        *(state.get("write_sites") or []),
        *(state.get("reference_sites") or []),
    ]
    return {source for value in values if (source := _source_file(value))}


def _evidence_is_bound_to_state(
    evidence: object, state: Mapping[str, Any]
) -> bool:
    if not isinstance(evidence, list) or not evidence:
        return False
    denominator = _state_source_denominator(state)
    if not denominator:
        return False
    return all(
        isinstance(value, str)
        and bool(_source_file(value))
        and _source_file(value) in denominator
        for value in evidence
    )


def _row_status(
    row: Mapping[str, Any], state: Mapping[str, Any]
) -> tuple[str, list[str]]:
    issues: list[str] = []
    disposition = str(row.get("disposition") or "").strip().upper()
    write_status = str(row.get("write_site_status") or "").strip().upper()
    semantic_status = str(row.get("semantic_status") or "").strip().upper()
    evidence = row.get("evidence_loci")
    result = re.sub(r"\s+", " ", str(row.get("result") or "")).strip()
    if disposition not in _ALLOWED_DISPOSITIONS:
        issues.append("invalid disposition")
    if write_status not in _ALLOWED_WRITE_STATUS:
        issues.append("invalid write-site status")
    if semantic_status not in _ALLOWED_SEMANTIC_STATUS:
        issues.append("invalid semantic status")
    if not isinstance(evidence, list):
        issues.append("evidence loci is not an array")
    elif disposition == "DELIVERED" and not _evidence_is_bound_to_state(evidence, state):
        issues.append("evidence loci do not resolve within the bound state/source denominator")
    elif evidence and not _evidence_is_bound_to_state(evidence, state):
        issues.append("optional evidence loci do not resolve within the bound state/source denominator")
    if not result or result.casefold() in {"n/a", "none", "unknown", "tbd", "-"}:
        issues.append("result is missing or placeholder")
    if issues:
        return "UNMEASURABLE", issues
    if disposition == "UNMEASURABLE":
        return "UNMEASURABLE", issues
    if disposition == "DEFERRED":
        return "DEFERRED", issues
    if write_status != "COMPLETE" or semantic_status == "SEMANTICS_UNKNOWN":
        return "DEFERRED", ["application remains bounded or semantically unknown"]
    # Producer delivery is never independent proof that the methodology was
    # applied correctly. A separately bound state-trace/application-skeptic
    # receipt may close this exact producer row below.
    return "DELIVERED", issues


def _validate_independent_payload(
    payload: Mapping[str, Any],
    worklist: Mapping[str, Any],
    producer_payload: Mapping[str, Any],
) -> tuple[dict[str, Mapping[str, Any]], set[str], list[str], bool, str]:
    issues: list[str] = []
    fatal = False
    if set(payload) != _INDEPENDENT_KEYS:
        issues.append("independent application trace schema fields mismatch")
        fatal = True
    if payload.get("schema_version") != INDEPENDENT_TRACE_SCHEMA:
        issues.append("independent application trace schema version mismatch")
        fatal = True
    if payload.get("payload_digest") != payload_digest(payload):
        issues.append("independent application trace payload digest mismatch")
        fatal = True
    binding = worklist.get("run_binding") if isinstance(worklist.get("run_binding"), Mapping) else {}
    for field, expected, label in (
        ("run_binding_digest", binding.get("binding_digest"), "run binding digest mismatch"),
        ("authority_digest", worklist.get("authority_digest"), "authority digest mismatch"),
        ("worklist_digest", worklist.get("worklist_digest"), "worklist digest mismatch"),
        (
            "producer_payload_digest",
            producer_payload.get("payload_digest"),
            "producer payload digest mismatch",
        ),
    ):
        if str(payload.get(field) or "") != str(expected or ""):
            issues.append(f"independent application trace {label}")
            fatal = True
    consumer = str(payload.get("consumer_kind") or "").strip().upper()
    if consumer not in _INDEPENDENT_CONSUMERS:
        issues.append("independent application consumer is not authorized")
        fatal = True
    operator_digest = str(payload.get("consumer_operator_digest") or "").strip().lower()
    if not _HEX64.fullmatch(operator_digest):
        issues.append("independent consumer operator digest is missing or invalid")
        fatal = True
    producer_operator_digest = str(
        producer_payload.get("producer_operator_digest") or ""
    ).strip().lower()
    if operator_digest and operator_digest == producer_operator_digest:
        issues.append(
            "independent consumer operator must be distinct from the producer operator"
        )
        fatal = True
    rows = payload.get("rows")
    if not isinstance(rows, list):
        issues.append("independent application rows is not an array")
        return {}, set(), issues, True, consumer
    expected_ids = {
        str(row.get("state_id") or "")
        for row in worklist.get("states") or []
        if isinstance(row, Mapping)
    }
    by_id: dict[str, Mapping[str, Any]] = {}
    invalid_ids: set[str] = set()
    for index, row in enumerate(rows):
        if not isinstance(row, Mapping):
            issues.append(f"independent application row {index} is not an object")
            fatal = True
            continue
        state_id = str(row.get("state_id") or "")
        if set(row) != _INDEPENDENT_ROW_KEYS:
            issues.append(f"independent application row {state_id or index} fields mismatch")
            invalid_ids.add(state_id)
        if state_id not in expected_ids:
            issues.append(
                f"independent application trace contains unknown state ID: {state_id or '<empty>'}"
            )
            fatal = True
            continue
        if state_id in by_id:
            issues.append(f"independent application trace duplicates state ID: {state_id}")
            invalid_ids.add(state_id)
            continue
        by_id[state_id] = row
    return by_id, invalid_ids, issues, fatal, consumer


def _independent_row_status(
    row: Mapping[str, Any],
    state: Mapping[str, Any],
    producer_row: Mapping[str, Any],
) -> tuple[str, list[str]]:
    issues: list[str] = []
    disposition = str(row.get("disposition") or "").strip().upper()
    if disposition not in {"APPLIED", "DEFERRED"}:
        issues.append("independent disposition is invalid")
    if str(row.get("producer_row_digest") or "") != producer_row_digest(producer_row):
        issues.append("independent row is not bound to the exact producer row")
    if not _evidence_is_bound_to_state(row.get("evidence_loci"), state):
        issues.append("independent evidence is not bound to the state/source denominator")
    result = re.sub(r"\s+", " ", str(row.get("result") or "")).strip()
    if not result or result.casefold() in {"n/a", "none", "unknown", "tbd", "-"}:
        issues.append("independent result is missing or placeholder")
    if issues:
        return "DELIVERED", issues
    return disposition, []


def _receipt_projection(receipt: Mapping[str, Any]) -> str:
    lines = [
        "# Semantic Invariant Coverage Gaps",
        "",
        "Typed application receipt is authoritative. This projection cannot close or create coverage.",
        "",
        f"**Status**: {_escape_cell(receipt.get('status'))}",
        f"**Receipt digest**: `{_escape_cell(receipt.get('receipt_digest'))}`",
        f"**Open states**: {int(receipt.get('open_count') or 0)}",
        "",
    ]
    states = receipt.get("states") if isinstance(receipt.get("states"), list) else []
    open_rows = [
        row for row in states
        if isinstance(row, Mapping) and row.get("status") != "APPLIED"
    ]
    if not open_rows:
        lines.append("No open semantic-invariant application debt.")
    else:
        lines.extend(
            [
                "| State ID | Qualified Name | Status | Conflict IDs | Reason |",
                "|---|---|---|---|---|",
            ]
        )
        for row in open_rows:
            lines.append(
                "| `{state_id}` | `{qualified}` | {status} | {conflicts} | {reason} |".format(
                    state_id=_escape_cell(row.get("state_id")),
                    qualified=_escape_cell(row.get("qualified_name")),
                    status=_escape_cell(row.get("status")),
                    conflicts=_escape_cell(", ".join(row.get("conflict_ids") or [])) or "none",
                    reason=_escape_cell("; ".join(row.get("issues") or [])) or "open methodology obligation",
                )
            )
    issues = receipt.get("issues") if isinstance(receipt.get("issues"), list) else []
    if issues:
        lines.extend(["", "## Reconciliation debt", ""])
        lines.extend(f"- {_escape_cell(issue)}" for issue in issues)
    return "\n".join(lines) + "\n"


def derive_semantic_invariant_application(
    scratchpad: Path,
    *,
    application_payload: Mapping[str, Any] | None = None,
    independent_payload: Mapping[str, Any] | None = None,
    semantic_text: str | None = None,
    ecosystem: str = "",
    mode: str = "",
    run_id: str = "",
    source_snapshot_digest: str = "",
    load_independent_from_disk: bool = True,
) -> tuple[dict[str, Any], str]:
    root = Path(scratchpad)
    expected_authority, expected_worklist, _projection = (
        derive_semantic_invariant_authority(
            root,
            ecosystem=ecosystem,
            mode=mode,
            run_id=run_id,
            source_snapshot_digest=source_snapshot_digest,
        )
    )
    issues: list[str] = []
    fatal = False
    for name, expected in (
        (AUTHORITY_FILE, expected_authority),
        (WORKLIST_FILE, expected_worklist),
    ):
        try:
            actual = _load_json(root / name)
        except Exception as exc:
            issues.append(f"{name} missing or malformed: {type(exc).__name__}")
            fatal = True
            continue
        if actual != expected:
            issues.append(f"{name} differs from current inputs")
            fatal = True
    try:
        actual_projection = (root / WORKLIST_PROJECTION_FILE).read_text(
            encoding="utf-8", errors="strict"
        )
    except Exception as exc:
        issues.append(
            f"{WORKLIST_PROJECTION_FILE} missing or malformed: {type(exc).__name__}"
        )
        fatal = True
    else:
        if actual_projection != render_semantic_invariant_worklist(expected_worklist):
            issues.append(f"{WORKLIST_PROJECTION_FILE} differs from current inputs")
            fatal = True

    payload: Mapping[str, Any] | None = application_payload
    semantic_binding: dict[str, Any] | None = None
    if payload is None:
        if semantic_text is None:
            semantic_path = root / "semantic_invariants.md"
            try:
                raw = semantic_path.read_bytes()
                semantic_text = raw.decode("utf-8", errors="strict")
                semantic_binding = {
                    "artifact": semantic_path.name,
                    "role": "MODEL_APPLICATION_TRACE",
                    "sha256": _sha256_bytes(raw),
                    "byte_count": len(raw),
                }
            except Exception as exc:
                issues.append(
                    f"semantic invariant application trace unavailable: {type(exc).__name__}"
                )
                fatal = True
        if semantic_text is not None:
            try:
                payload = parse_semantic_invariant_application_trace(semantic_text)
            except Exception as exc:
                issues.append(f"semantic invariant application trace invalid: {exc}")
                fatal = True
    by_id: dict[str, Mapping[str, Any]] = {}
    invalid_ids: set[str] = set()
    if payload is not None:
        rows, invalid, payload_issues, payload_fatal = _validate_application_payload(
            payload, expected_worklist
        )
        by_id = rows
        invalid_ids = invalid
        issues.extend(payload_issues)
        fatal = fatal or payload_fatal

    independent = independent_payload
    independent_binding: dict[str, Any] | None = None
    if independent is None and load_independent_from_disk:
        independent_path = root / INDEPENDENT_TRACE_FILE
        if independent_path.is_file():
            try:
                loaded = _load_json(independent_path)
                if isinstance(loaded, Mapping):
                    independent = loaded
                    independent_binding = _binding(
                        independent_path, "INDEPENDENT_APPLICATION_TRACE"
                    )
                else:
                    issues.append("independent application trace root is not an object")
            except Exception as exc:
                issues.append(
                    f"independent application trace unavailable: {type(exc).__name__}"
                )
    independent_by_id: dict[str, Mapping[str, Any]] = {}
    independent_invalid_ids: set[str] = set()
    independent_fatal = False
    independent_consumer = ""
    if independent is not None:
        if payload is None:
            issues.append("independent application trace lacks a bound producer payload")
            independent_fatal = True
        else:
            (
                independent_by_id,
                independent_invalid_ids,
                independent_issues,
                independent_fatal,
                independent_consumer,
            ) = _validate_independent_payload(
                independent, expected_worklist, payload
            )
            issues.extend(independent_issues)

    conflicts_by_state: dict[str, list[str]] = {}
    for conflict in expected_authority.get("conflicts") or []:
        if isinstance(conflict, Mapping):
            conflicts_by_state.setdefault(str(conflict.get("state_id") or ""), []).append(
                str(conflict.get("conflict_id") or "")
            )
    state_results: list[dict[str, Any]] = []
    for state in expected_worklist.get("states") or []:
        if not isinstance(state, Mapping):
            continue
        state_id = str(state.get("state_id") or "")
        row = by_id.get(state_id)
        row_issues: list[str] = []
        if fatal or expected_authority.get("status") == "UNMEASURABLE":
            status = "UNMEASURABLE"
            row_issues.append("authority or application binding is unmeasurable")
        elif conflicts_by_state.get(state_id):
            status = "CONFLICT"
            row_issues.append("source conflict remains open")
        elif state_id in invalid_ids or row is None:
            status = "UNMEASURABLE"
            row_issues.append("exact typed application row is missing or invalid")
        else:
            status, row_issues = _row_status(row, state)
        independent_row = independent_by_id.get(state_id)
        independent_evidence: list[str] = []
        independent_result = ""
        if (
            status == "DELIVERED"
            and independent_row is not None
            and state_id not in independent_invalid_ids
            and not independent_fatal
            and row is not None
        ):
            status, independent_row_issues = _independent_row_status(
                independent_row, state, row
            )
            row_issues.extend(independent_row_issues)
            if isinstance(independent_row.get("evidence_loci"), list):
                independent_evidence = list(independent_row.get("evidence_loci") or [])
            independent_result = str(independent_row.get("result") or "")
        elif status == "DELIVERED" and state_id in independent_invalid_ids:
            row_issues.append("independent application row is invalid; producer remains delivered")
        state_results.append(
            {
                "state_id": state_id,
                "qualified_name": str(state.get("qualified_name") or ""),
                "status": status,
                "conflict_ids": sorted(conflicts_by_state.get(state_id, [])),
                "trace_disposition": str(row.get("disposition") or "") if row else "",
                "write_site_status": str(row.get("write_site_status") or "") if row else "",
                "semantic_status": str(row.get("semantic_status") or "") if row else "",
                "evidence_loci": list(row.get("evidence_loci") or []) if row and isinstance(row.get("evidence_loci"), list) else [],
                "result": str(row.get("result") or "") if row else "",
                "producer_row_digest": producer_row_digest(row) if row else "",
                "independent_consumer": independent_consumer if independent_row else "",
                "independent_evidence_loci": independent_evidence,
                "independent_result": independent_result,
                "issues": row_issues,
            }
        )

    counts = {
        status: sum(row["status"] == status for row in state_results)
        for status in (
            "APPLIED",
            "DELIVERED",
            "DEFERRED",
            "CONFLICT",
            "UNMEASURABLE",
        )
    }
    if fatal or independent_fatal or counts["UNMEASURABLE"]:
        overall = "UNMEASURABLE"
    elif counts["CONFLICT"]:
        overall = "CONFLICT"
    elif counts["DEFERRED"]:
        overall = "DEFERRED"
    elif counts["DELIVERED"]:
        overall = "DELIVERED"
    else:
        overall = "APPLIED"
    input_bindings = list(expected_authority.get("input_bindings") or [])
    if semantic_binding is not None:
        input_bindings.append(semantic_binding)
    if independent_binding is not None:
        input_bindings.append(independent_binding)
    receipt = _finalize(
        {
            "schema_version": APPLICATION_RECEIPT_SCHEMA,
            "run_binding": expected_worklist["run_binding"],
            "status": overall,
            "assurance": (
                "INDEPENDENT_TYPED_APPLICATION_RECONCILIATION"
                if independent is not None
                else "PRODUCER_DELIVERY_ENUMERATE_DIFF_ONLY"
            ),
            "semantic_correctness_proven": False,
            "independent_application_confirmed": overall == "APPLIED",
            "authority_digest": expected_worklist["authority_digest"],
            "worklist_digest": expected_worklist["worklist_digest"],
            "application_payload_digest": str(payload.get("payload_digest") or "") if payload else "",
            "producer_operator_digest": str(payload.get("producer_operator_digest") or "") if payload else "",
            "independent_payload_digest": str(independent.get("payload_digest") or "") if independent else "",
            "input_bindings": sorted(
                input_bindings,
                key=lambda row: (str(row.get("artifact") or ""), str(row.get("role") or "")),
            ),
            "expected_state_count": len(state_results),
            "applied_count": counts["APPLIED"],
            "delivered_count": counts["DELIVERED"],
            "deferred_count": counts["DEFERRED"],
            "conflict_count": counts["CONFLICT"],
            "unmeasurable_count": counts["UNMEASURABLE"],
            "open_count": len(state_results) - counts["APPLIED"],
            "states": state_results,
            "issues": sorted(set(issues)),
        },
        "receipt_digest",
    )
    return receipt, _receipt_projection(receipt)


def reconcile_semantic_invariant_application(
    scratchpad: Path,
    *,
    application_payload: Mapping[str, Any] | None = None,
    independent_payload: Mapping[str, Any] | None = None,
    semantic_text: str | None = None,
    ecosystem: str = "",
    mode: str = "",
    run_id: str = "",
    source_snapshot_digest: str = "",
    load_independent_from_disk: bool = True,
) -> dict[str, Any]:
    root = Path(scratchpad)
    receipt, projection = derive_semantic_invariant_application(
        root,
        application_payload=application_payload,
        independent_payload=independent_payload,
        semantic_text=semantic_text,
        ecosystem=ecosystem,
        mode=mode,
        run_id=run_id,
        source_snapshot_digest=source_snapshot_digest,
        load_independent_from_disk=load_independent_from_disk,
    )
    _atomic_write_if_changed(root / APPLICATION_RECEIPT_FILE, _pretty_json(receipt))
    _atomic_write_if_changed(
        root / GAPS_PROJECTION_FILE, projection.encode("utf-8")
    )
    return receipt


def validate_semantic_invariant_application(
    scratchpad: Path,
    *,
    ecosystem: str = "",
    mode: str = "",
    run_id: str = "",
    source_snapshot_digest: str = "",
    load_independent_from_disk: bool = True,
) -> list[str]:
    root = Path(scratchpad)
    try:
        expected, projection = derive_semantic_invariant_application(
            root,
            ecosystem=ecosystem,
            mode=mode,
            run_id=run_id,
            source_snapshot_digest=source_snapshot_digest,
            load_independent_from_disk=load_independent_from_disk,
        )
    except Exception as exc:
        return [f"semantic invariant reconciliation failed: {type(exc).__name__}"]
    issues: list[str] = []
    try:
        actual = _load_json(root / APPLICATION_RECEIPT_FILE)
    except Exception as exc:
        issues.append(f"{APPLICATION_RECEIPT_FILE} missing or malformed: {type(exc).__name__}")
    else:
        if actual != expected:
            issues.append(f"{APPLICATION_RECEIPT_FILE} differs from current inputs")
    try:
        actual_projection = (root / GAPS_PROJECTION_FILE).read_text(
            encoding="utf-8", errors="strict"
        )
    except Exception as exc:
        issues.append(f"{GAPS_PROJECTION_FILE} missing or malformed: {type(exc).__name__}")
    else:
        if actual_projection != projection:
            issues.append(f"{GAPS_PROJECTION_FILE} differs from current receipt")
    return issues


def _pass2_work_identities(
    run_binding: Mapping[str, Any], backend: str
) -> tuple[str, str]:
    prefix = "/".join(
        (
            str(run_binding.get("pipeline") or "unknown"),
            str(run_binding.get("mode") or "unknown"),
            str(run_binding.get("ecosystem") or "unknown"),
            _normalized_ecosystem(backend),
            "invariants_p2",
        )
    )
    return (
        f"{prefix}/worker.semantic_invariants_pass2",
        f"{prefix}/semantic_invariants.pass2_reconcile",
    )


def _receipt_digest_is_valid(receipt: Mapping[str, Any]) -> bool:
    actual = str(receipt.get("receipt_digest") or "")
    if not _HEX64.fullmatch(actual):
        return False
    unsigned = {
        key: value for key, value in receipt.items() if key != "receipt_digest"
    }
    return actual == _sha256_bytes(_canonical_json(unsigned))


def _semantic_binding_from_receipt(
    receipt: Mapping[str, Any],
) -> Mapping[str, Any] | None:
    matches = [
        row
        for row in receipt.get("input_bindings") or []
        if isinstance(row, Mapping)
        and str(row.get("artifact") or "") == "semantic_invariants.md"
    ]
    return matches[0] if len(matches) == 1 else None


def derive_semantic_invariant_pass2_pre_authority(
    scratchpad: Path,
    *,
    ecosystem: str = "",
    mode: str = "",
    run_id: str = "",
    source_snapshot_digest: str = "",
    backend: str = "claude",
) -> dict[str, Any]:
    """Bind the immutable Pass-1 receipt and bytes before the Pass-2 append."""
    root = Path(scratchpad)
    run_binding, issues = _load_run_binding(
        root,
        run_id=run_id,
        source_snapshot_digest=source_snapshot_digest,
        ecosystem=ecosystem,
        mode=mode,
    )
    append_identity, reconcile_identity = _pass2_work_identities(
        run_binding, backend
    )
    semantic_bytes = b""
    try:
        semantic_bytes = (root / "semantic_invariants.md").read_bytes()
    except Exception as exc:
        issues.append(f"Pass-1 semantic bytes unavailable: {type(exc).__name__}")

    receipt_bytes = b""
    receipt: Mapping[str, Any] = {}
    try:
        receipt_bytes = (root / APPLICATION_RECEIPT_FILE).read_bytes()
        loaded = json.loads(receipt_bytes.decode("utf-8", errors="strict"))
        if not isinstance(loaded, Mapping):
            raise ValueError("receipt root is not an object")
        receipt = loaded
    except Exception as exc:
        issues.append(f"prior application receipt unavailable: {type(exc).__name__}")

    if receipt:
        if receipt.get("schema_version") != APPLICATION_RECEIPT_SCHEMA:
            issues.append("prior application receipt schema mismatch")
        if not _receipt_digest_is_valid(receipt):
            issues.append("prior application receipt digest mismatch")
        if receipt.get("run_binding") != run_binding:
            issues.append("prior application receipt run binding mismatch")
        semantic_binding = _semantic_binding_from_receipt(receipt)
        if semantic_binding is None:
            issues.append(
                "prior application receipt lacks one exact semantic byte binding"
            )
        elif (
            str(semantic_binding.get("sha256") or "")
            != _sha256_bytes(semantic_bytes)
            or int(semantic_binding.get("byte_count") or -1)
            != len(semantic_bytes)
        ):
            issues.append("prior application receipt does not bind current Pass-1 bytes")

    payload = {
        "schema_version": PASS2_PRE_SCHEMA,
        "run_binding": run_binding,
        "status": "READY" if not issues else "UNMEASURABLE",
        "semantic_correctness_proven": False,
        "pre_semantic_sha256": _sha256_bytes(semantic_bytes),
        "pre_semantic_byte_count": len(semantic_bytes),
        "prior_application_receipt_digest": str(
            receipt.get("receipt_digest") or ""
        ),
        "prior_application_receipt": dict(receipt),
        "prior_application_receipt_sha256": _sha256_bytes(receipt_bytes),
        "prior_application_receipt_byte_count": len(receipt_bytes),
        "prior_application_payload_digest": str(
            receipt.get("application_payload_digest") or ""
        ),
        "append_producer_work_identity": append_identity,
        "reconciliation_work_identity": reconcile_identity,
        "issues": sorted(set(str(issue) for issue in issues)),
    }
    return _finalize(payload, "pre_authority_digest")


def _validate_pass2_pre_payload(
    payload: Mapping[str, Any],
    *,
    expected_run_binding: Mapping[str, Any] | None = None,
    backend: str = "claude",
) -> list[str]:
    issues: list[str] = []
    expected_fields = {
        "schema_version",
        "run_binding",
        "status",
        "semantic_correctness_proven",
        "pre_semantic_sha256",
        "pre_semantic_byte_count",
        "prior_application_receipt_digest",
        "prior_application_receipt",
        "prior_application_receipt_sha256",
        "prior_application_receipt_byte_count",
        "prior_application_payload_digest",
        "append_producer_work_identity",
        "reconciliation_work_identity",
        "issues",
        "pre_authority_digest",
    }
    if set(payload) != expected_fields:
        issues.append("Pass-2 pre-authority fields mismatch")
    if payload.get("schema_version") != PASS2_PRE_SCHEMA:
        issues.append("Pass-2 pre-authority schema mismatch")
    digest = str(payload.get("pre_authority_digest") or "")
    unsigned = {
        key: value for key, value in payload.items() if key != "pre_authority_digest"
    }
    if not _HEX64.fullmatch(digest) or digest != _sha256_bytes(
        _canonical_json(unsigned)
    ):
        issues.append("Pass-2 pre-authority digest mismatch")
    run_binding = payload.get("run_binding")
    if not isinstance(run_binding, Mapping):
        issues.append("Pass-2 pre-authority run binding malformed")
        run_binding = {}
    if expected_run_binding is not None and run_binding != expected_run_binding:
        issues.append("Pass-2 pre-authority run binding mismatch")
    append_identity, reconcile_identity = _pass2_work_identities(
        run_binding, backend
    )
    if payload.get("append_producer_work_identity") != append_identity:
        issues.append("Pass-2 append producer identity mismatch")
    if payload.get("reconciliation_work_identity") != reconcile_identity:
        issues.append("Pass-2 reconciliation identity mismatch")
    if payload.get("semantic_correctness_proven") is not False:
        issues.append("Pass-2 pre-authority cannot prove semantic correctness")
    receipt_snapshot = payload.get("prior_application_receipt")
    if not isinstance(receipt_snapshot, Mapping):
        issues.append("Pass-2 prior receipt snapshot malformed")
    elif payload.get("status") == "READY":
        if receipt_snapshot.get("schema_version") != APPLICATION_RECEIPT_SCHEMA:
            issues.append("Pass-2 prior receipt snapshot schema mismatch")
        if not _receipt_digest_is_valid(receipt_snapshot):
            issues.append("Pass-2 prior receipt snapshot digest mismatch")
        if (
            str(receipt_snapshot.get("receipt_digest") or "")
            != str(payload.get("prior_application_receipt_digest") or "")
        ):
            issues.append("Pass-2 prior receipt snapshot/digest mismatch")
        if receipt_snapshot.get("run_binding") != run_binding:
            issues.append("Pass-2 prior receipt snapshot run binding mismatch")
    if payload.get("status") not in {"READY", "UNMEASURABLE"}:
        issues.append("Pass-2 pre-authority status invalid")
    if not _HEX64.fullmatch(str(payload.get("pre_semantic_sha256") or "")):
        issues.append("Pass-2 pre semantic digest invalid")
    try:
        if int(payload.get("pre_semantic_byte_count")) < 0:
            raise ValueError
    except (TypeError, ValueError):
        issues.append("Pass-2 pre semantic byte count invalid")
    payload_issues = payload.get("issues")
    if not isinstance(payload_issues, list):
        issues.append("Pass-2 pre-authority issues is not an array")
    elif (
        (payload.get("status") == "READY" and payload_issues)
        or (payload.get("status") == "UNMEASURABLE" and not payload_issues)
    ):
        issues.append("Pass-2 pre-authority status/issues mismatch")
    return list(dict.fromkeys(issues))


def write_semantic_invariant_pass2_pre_authority(
    scratchpad: Path,
    **kwargs: Any,
) -> dict[str, Any]:
    """Create the immutable PRE authority once; exact resumes never rebind it."""
    root = Path(scratchpad)
    path = root / PASS2_PRE_FILE
    if path.is_file():
        loaded = _load_json(path)
        if not isinstance(loaded, Mapping):
            raise ValueError("existing Pass-2 pre-authority is not an object")
        issues = _validate_pass2_pre_payload(
            loaded, backend=str(kwargs.get("backend") or "claude")
        )
        if issues:
            raise ValueError("; ".join(issues))
        return dict(loaded)
    payload = derive_semantic_invariant_pass2_pre_authority(root, **kwargs)
    _atomic_write_if_changed(path, _pretty_json(payload))
    return payload


def validate_semantic_invariant_pass2_pre_authority(
    scratchpad: Path,
    *,
    ecosystem: str = "",
    mode: str = "",
    run_id: str = "",
    source_snapshot_digest: str = "",
    backend: str = "claude",
) -> list[str]:
    """Validate the frozen PRE record while permitting a pending append suffix."""
    root = Path(scratchpad)
    try:
        loaded = _load_json(root / PASS2_PRE_FILE)
        if not isinstance(loaded, Mapping):
            raise ValueError("root is not an object")
    except Exception as exc:
        return [f"Pass-2 pre-authority missing or malformed: {type(exc).__name__}"]
    run_binding, binding_issues = _load_run_binding(
        root,
        run_id=run_id,
        source_snapshot_digest=source_snapshot_digest,
        ecosystem=ecosystem,
        mode=mode,
    )
    issues = list(binding_issues)
    issues.extend(
        _validate_pass2_pre_payload(
            loaded, expected_run_binding=run_binding, backend=backend
        )
    )
    try:
        semantic = (root / "semantic_invariants.md").read_bytes()
        count = int(loaded.get("pre_semantic_byte_count") or 0)
        if (
            count <= 0
            or len(semantic) < count
            or _sha256_bytes(semantic[:count])
            != str(loaded.get("pre_semantic_sha256") or "")
        ):
            issues.append("Pass-2 current semantic bytes do not preserve PRE prefix")
    except Exception as exc:
        issues.append(f"Pass-2 current semantic bytes unavailable: {type(exc).__name__}")
    try:
        receipt = (root / APPLICATION_RECEIPT_FILE).read_bytes()
        if (
            _sha256_bytes(receipt)
            != str(loaded.get("prior_application_receipt_sha256") or "")
            or len(receipt)
            != int(loaded.get("prior_application_receipt_byte_count") or -1)
        ):
            issues.append("prior application receipt drifted before successor commit")
    except Exception as exc:
        issues.append(f"prior application receipt unavailable: {type(exc).__name__}")
    if loaded.get("status") != "READY":
        issues.extend(str(value) for value in loaded.get("issues") or [])
        if not loaded.get("issues"):
            issues.append("Pass-2 pre-authority is UNMEASURABLE")
    return list(dict.fromkeys(issues))


def derive_semantic_invariant_final_byte_authority(
    scratchpad: Path,
    *,
    ecosystem: str = "",
    mode: str = "",
    run_id: str = "",
    source_snapshot_digest: str = "",
    backend: str = "claude",
) -> dict[str, Any]:
    """Reconcile an exact prefix-preserving append into a typed successor."""
    root = Path(scratchpad)
    run_binding, issues = _load_run_binding(
        root,
        run_id=run_id,
        source_snapshot_digest=source_snapshot_digest,
        ecosystem=ecosystem,
        mode=mode,
    )
    append_identity, reconcile_identity = _pass2_work_identities(
        run_binding, backend
    )
    pre: Mapping[str, Any] = {}
    try:
        loaded = _load_json(root / PASS2_PRE_FILE)
        if not isinstance(loaded, Mapping):
            raise ValueError("pre-authority root is not an object")
        pre = loaded
        issues.extend(
            _validate_pass2_pre_payload(
                pre, expected_run_binding=run_binding, backend=backend
            )
        )
    except Exception as exc:
        issues.append(f"Pass-2 pre-authority unavailable: {type(exc).__name__}")

    receipt_bytes = b""
    try:
        receipt_bytes = (root / APPLICATION_RECEIPT_FILE).read_bytes()
    except Exception as exc:
        issues.append(f"prior application receipt unavailable: {type(exc).__name__}")
    if pre and (
        _sha256_bytes(receipt_bytes)
        != str(pre.get("prior_application_receipt_sha256") or "")
        or len(receipt_bytes)
        != int(pre.get("prior_application_receipt_byte_count") or 0)
    ):
        issues.append("prior application receipt drifted before Pass-2 reconciliation")

    post_bytes = b""
    try:
        post_bytes = (root / "semantic_invariants.md").read_bytes()
    except Exception as exc:
        issues.append(f"final semantic bytes unavailable: {type(exc).__name__}")
    try:
        pre_count = int(pre.get("pre_semantic_byte_count") or 0)
    except (TypeError, ValueError):
        pre_count = 0
    pre_sha = str(pre.get("pre_semantic_sha256") or "")
    prefix_preserved = (
        pre_count > 0
        and len(post_bytes) >= pre_count
        and _sha256_bytes(post_bytes[:pre_count]) == pre_sha
    )
    if not prefix_preserved:
        issues.append("Pass-2 append did not preserve the exact Pass-1 byte prefix")
    append_bytes = post_bytes[pre_count:] if prefix_preserved else b""
    if not append_bytes:
        issues.append("Pass-2 append is empty")
    if pre.get("status") != "READY":
        issues.append("Pass-2 pre-authority was not READY")

    payload = {
        "schema_version": FINAL_BYTE_AUTHORITY_SCHEMA,
        "run_binding": run_binding,
        "status": "VALID_FINAL_BYTES" if not issues else "UNMEASURABLE",
        "assurance": "EXACT_PREFIX_PRESERVING_APPEND_RECONCILIATION",
        "semantic_correctness_proven": False,
        "append_producer_self_certified": False,
        "pre_authority_digest": str(pre.get("pre_authority_digest") or ""),
        "prior_application_receipt_digest": str(
            pre.get("prior_application_receipt_digest") or ""
        ),
        "prior_application_receipt_sha256": str(
            pre.get("prior_application_receipt_sha256") or ""
        ),
        "prior_application_payload_digest": str(
            pre.get("prior_application_payload_digest") or ""
        ),
        "pre_semantic_sha256": pre_sha,
        "pre_semantic_byte_count": pre_count,
        "post_semantic_sha256": _sha256_bytes(post_bytes),
        "post_semantic_byte_count": len(post_bytes),
        "append_sha256": _sha256_bytes(append_bytes),
        "append_byte_count": len(append_bytes),
        "append_prefix_preserved": prefix_preserved,
        "append_producer_work_identity": append_identity,
        "reconciliation_work_identity": reconcile_identity,
        "issues": sorted(set(str(issue) for issue in issues)),
    }
    return _finalize(payload, "final_authority_digest")


def _validate_final_byte_payload(
    scratchpad: Path,
    payload: Mapping[str, Any],
    *,
    ecosystem: str = "",
    mode: str = "",
    run_id: str = "",
    source_snapshot_digest: str = "",
    backend: str = "claude",
) -> list[str]:
    root = Path(scratchpad)
    issues: list[str] = []
    expected_fields = {
        "schema_version", "run_binding", "status", "assurance",
        "semantic_correctness_proven", "append_producer_self_certified",
        "pre_authority_digest", "prior_application_receipt_digest",
        "prior_application_receipt_sha256", "prior_application_payload_digest",
        "pre_semantic_sha256", "pre_semantic_byte_count",
        "post_semantic_sha256", "post_semantic_byte_count", "append_sha256",
        "append_byte_count", "append_prefix_preserved",
        "append_producer_work_identity", "reconciliation_work_identity",
        "issues", "final_authority_digest",
    }
    if set(payload) != expected_fields:
        issues.append("final-byte authority fields mismatch")
    if payload.get("schema_version") != FINAL_BYTE_AUTHORITY_SCHEMA:
        issues.append("final-byte authority schema mismatch")
    digest = str(payload.get("final_authority_digest") or "")
    unsigned = {
        key: value for key, value in payload.items() if key != "final_authority_digest"
    }
    if not _HEX64.fullmatch(digest) or digest != _sha256_bytes(
        _canonical_json(unsigned)
    ):
        issues.append("final-byte authority digest mismatch")
    run_binding, binding_issues = _load_run_binding(
        root,
        run_id=run_id,
        source_snapshot_digest=source_snapshot_digest,
        ecosystem=ecosystem,
        mode=mode,
    )
    issues.extend(binding_issues)
    if payload.get("run_binding") != run_binding:
        issues.append("final-byte authority run binding mismatch")
    append_identity, reconcile_identity = _pass2_work_identities(
        run_binding, backend
    )
    if payload.get("append_producer_work_identity") != append_identity:
        issues.append("final-byte append producer identity mismatch")
    if payload.get("reconciliation_work_identity") != reconcile_identity:
        issues.append("final-byte reconciliation identity mismatch")
    if payload.get("semantic_correctness_proven") is not False:
        issues.append("final-byte authority cannot prove semantic correctness")
    if payload.get("append_producer_self_certified") is not False:
        issues.append("Pass-2 producer cannot self-certify its append")
    if payload.get("assurance") != "EXACT_PREFIX_PRESERVING_APPEND_RECONCILIATION":
        issues.append("final-byte authority assurance mismatch")
    if payload.get("status") not in {"VALID_FINAL_BYTES", "UNMEASURABLE"}:
        issues.append("final-byte authority status invalid")
    payload_issues = payload.get("issues")
    if not isinstance(payload_issues, list):
        issues.append("final-byte authority issues is not an array")
        payload_issues = []
    try:
        current = (root / "semantic_invariants.md").read_bytes()
    except Exception as exc:
        issues.append(f"final semantic bytes unavailable: {type(exc).__name__}")
        current = b""
    if (
        _sha256_bytes(current) != str(payload.get("post_semantic_sha256") or "")
        or len(current) != int(payload.get("post_semantic_byte_count") or -1)
    ):
        issues.append("final semantic bytes drift from successor authority")
    try:
        pre = _load_json(root / PASS2_PRE_FILE)
        if not isinstance(pre, Mapping):
            raise ValueError
        pre_issues = _validate_pass2_pre_payload(
            pre, expected_run_binding=run_binding, backend=backend
        )
        issues.extend(pre_issues)
        if payload.get("pre_authority_digest") != pre.get("pre_authority_digest"):
            issues.append("final-byte authority does not bind current pre-authority")
        for final_field, pre_field in (
            ("prior_application_receipt_digest", "prior_application_receipt_digest"),
            ("prior_application_receipt_sha256", "prior_application_receipt_sha256"),
            ("prior_application_payload_digest", "prior_application_payload_digest"),
            ("pre_semantic_sha256", "pre_semantic_sha256"),
            ("pre_semantic_byte_count", "pre_semantic_byte_count"),
        ):
            if payload.get(final_field) != pre.get(pre_field):
                issues.append(
                    f"final-byte authority {final_field} does not match PRE"
                )
        try:
            pre_count = int(pre.get("pre_semantic_byte_count") or 0)
        except (TypeError, ValueError):
            pre_count = 0
        prefix_preserved = (
            pre_count > 0
            and len(current) >= pre_count
            and _sha256_bytes(current[:pre_count])
            == str(pre.get("pre_semantic_sha256") or "")
        )
        append_bytes = current[pre_count:] if prefix_preserved else b""
        if payload.get("append_prefix_preserved") is not prefix_preserved:
            issues.append("final-byte prefix-preservation claim mismatch")
        try:
            claimed_append_count = int(payload.get("append_byte_count") or 0)
        except (TypeError, ValueError):
            claimed_append_count = -1
        if claimed_append_count != len(append_bytes):
            issues.append("final-byte append count mismatch")
        if str(payload.get("append_sha256") or "") != _sha256_bytes(append_bytes):
            issues.append("final-byte append digest mismatch")
        expected_valid = (
            not payload_issues
            and pre.get("status") == "READY"
            and prefix_preserved
            and bool(append_bytes)
        )
        if (payload.get("status") == "VALID_FINAL_BYTES") is not expected_valid:
            issues.append("final-byte authority status/evidence mismatch")
    except Exception as exc:
        issues.append(f"Pass-2 pre-authority unavailable: {type(exc).__name__}")
    return list(dict.fromkeys(issues))


def write_semantic_invariant_final_byte_authority(
    scratchpad: Path,
    **kwargs: Any,
) -> dict[str, Any]:
    """Write one immutable successor or validate the already-written successor."""
    root = Path(scratchpad)
    path = root / FINAL_BYTE_AUTHORITY_FILE
    if path.is_file():
        loaded = _load_json(path)
        if not isinstance(loaded, Mapping):
            raise ValueError("existing final-byte authority is not an object")
        issues = _validate_final_byte_payload(root, loaded, **kwargs)
        if issues:
            raise ValueError("; ".join(issues))
        return dict(loaded)
    payload = derive_semantic_invariant_final_byte_authority(root, **kwargs)
    _atomic_write_if_changed(path, _pretty_json(payload))
    return payload


def validate_semantic_invariant_final_byte_authority(
    scratchpad: Path,
    **kwargs: Any,
) -> list[str]:
    root = Path(scratchpad)
    try:
        loaded = _load_json(root / FINAL_BYTE_AUTHORITY_FILE)
        if not isinstance(loaded, Mapping):
            raise ValueError("root is not an object")
    except Exception as exc:
        return [f"final-byte authority missing or malformed: {type(exc).__name__}"]
    return _validate_final_byte_payload(root, loaded, **kwargs)


def semantic_invariant_pass2_debt_issues(
    payload: Mapping[str, Any],
) -> list[str]:
    if payload.get("status") == "VALID_FINAL_BYTES":
        return []
    details = [str(value) for value in payload.get("issues") or []]
    return details or ["Pass-2 final-byte authority is UNMEASURABLE"]


__all__ = [
    "APPLICATION_RECEIPT_FILE",
    "APPLICATION_RECEIPT_SCHEMA",
    "APPLICATION_TRACE_SCHEMA",
    "FINAL_BYTE_AUTHORITY_FILE",
    "FINAL_BYTE_AUTHORITY_SCHEMA",
    "INDEPENDENT_TRACE_FILE",
    "INDEPENDENT_TRACE_SCHEMA",
    "AUTHORITY_FILE",
    "AUTHORITY_SCHEMA",
    "GAPS_PROJECTION_FILE",
    "PASS2_PRE_FILE",
    "PASS2_PRE_SCHEMA",
    "TRACE_BEGIN",
    "TRACE_END",
    "WORKLIST_FILE",
    "WORKLIST_PROJECTION_FILE",
    "WORKLIST_SCHEMA",
    "derive_semantic_invariant_application",
    "derive_semantic_invariant_authority",
    "derive_semantic_invariant_final_byte_authority",
    "derive_semantic_invariant_pass2_pre_authority",
    "materialize_semantic_invariant_compatibility_inputs",
    "parse_semantic_invariant_application_trace",
    "payload_digest",
    "producer_row_digest",
    "reconcile_semantic_invariant_application",
    "render_semantic_invariant_worklist",
    "semantic_invariant_pass2_debt_issues",
    "validate_semantic_invariant_application",
    "validate_semantic_invariant_authority",
    "validate_semantic_invariant_final_byte_authority",
    "validate_semantic_invariant_pass2_pre_authority",
    "write_semantic_invariant_final_byte_authority",
    "write_semantic_invariant_pass2_pre_authority",
    "write_semantic_invariant_authority",
]
