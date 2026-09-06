"""Typed, ecosystem-neutral state-symbol authority for chain composition.

The mechanical graph is authoritative.  Driver-produced Markdown maps are a
temporary compatibility source: they may add a symbol missing from a partial
graph, but can never overwrite a graph row.  Resolution is deterministic and
additive: exact cited-location graph edges precede bounded prose alias matches.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any, Iterable


GRAPH_SCHEMA = "plamen.mechanical_graph.v2"
RECEIPT_SCHEMA = "plamen.chain_state_resolution.v1"
DEGRADED_STATUS = "DEGRADED_GRAPH_APPLICATION"
_GRAPH_NAME = "_mechanical_graph.json"
_RECEIPT_NAME = "chain_state_resolution.json"
_DEGRADED_NAME = "chain_state_resolution.degraded"
_PROSE_LIMIT = 8_000

_SOURCE_LOC_RE = re.compile(
    r"(?P<file>[A-Za-z0-9_./\\-]+\.(?:sol|rs|move|go|vy|daml))"
    r"\s*:?\s*[Ll]?(?P<start>\d{1,9})(?:\s*[-:]\s*[Ll]?(?P<end>\d{1,9}))?"
)
_IDENT_BOUNDARY = r"A-Za-z0-9_"


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_json(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")


def _stable_symbol_id(qualified_name: str) -> str:
    digest = hashlib.sha256(qualified_name.encode("utf-8", errors="replace")).hexdigest()[:16]
    return f"STATE-{digest.upper()}"


def _dedupe_strings(values: Iterable[Any]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        text = re.sub(r"\s+", " ", str(value or "")).strip()
        if not text or text in seen:
            continue
        seen.add(text)
        out.append(text)
    return sorted(out)


def _bare_name(qualified_name: str) -> str:
    text = str(qualified_name or "").strip()
    # SCIP symbols commonly end in punctuation; strip it only for the alias.
    trimmed = text.rstrip(".#/")
    pieces = re.split(r"::|[.#/]", trimmed)
    return pieces[-1] if pieces and pieces[-1] else trimmed


def normalize_state_symbol(
    qualified_name: str,
    raw: dict[str, Any] | None,
    *,
    source: str,
    authority: str = "MECHANICAL_GRAPH",
) -> dict[str, Any]:
    """Normalize a provider row without upgrading its evidence strength."""
    raw = raw if isinstance(raw, dict) else {}
    qualified = str(raw.get("qualified_name") or qualified_name or "").strip()
    bare = str(raw.get("bare") or raw.get("bare_name") or _bare_name(qualified)).strip()
    aliases = _dedupe_strings([
        bare,
        *(raw.get("aliases") or []),
        *(raw.get("bare_aliases") or []),
    ])
    declaration = str(
        raw.get("declaration_locus")
        or raw.get("declaration")
        or raw.get("decl")
        or ""
    ).strip()
    reads = _dedupe_strings(raw.get("read_sites") or raw.get("reads") or [])
    writes = _dedupe_strings(raw.get("write_sites") or raw.get("writes") or [])
    references = _dedupe_strings([
        *(raw.get("reference_sites") or []),
        *(raw.get("refs") or []),
        *reads,
        *writes,
    ])
    confidence = str(raw.get("graph_confidence") or raw.get("confidence") or "").strip()
    if not confidence:
        confidence = "REFERENCE_ONLY" if references and not (reads or writes) else "PROVIDER_DECLARED"
    return {
        "symbol_id": str(raw.get("symbol_id") or _stable_symbol_id(qualified)),
        "qualified_name": qualified,
        "bare_aliases": aliases,
        "declaration_locus": declaration,
        "read_sites": reads,
        "write_sites": writes,
        "reference_sites": references,
        "graph_confidence": confidence,
        "provider_source": str(raw.get("provider_source") or source or "unknown"),
        "authority": authority,
    }


def build_typed_state_symbols(source: str, var_refs: dict[str, Any]) -> list[dict[str, Any]]:
    """Projection used by every graph provider while retaining ``var_refs``."""
    if not isinstance(var_refs, dict):
        return []
    return [
        normalize_state_symbol(name, raw, source=source)
        for name, raw in sorted(var_refs.items())
        if str(name or "").strip()
    ]


def _table_cells(line: str) -> list[str]:
    if not line.lstrip().startswith("|"):
        return []
    return [cell.strip().strip("`") for cell in line.strip().split("|")[1:-1]]


def _separator(cells: list[str]) -> bool:
    return bool(cells) and all(not c or set(c) <= {"-", ":", " "} for c in cells)


def _descriptor_locations(text: str) -> list[str]:
    return _dedupe_strings(m.group(0).strip(" ()") for m in _SOURCE_LOC_RE.finditer(text or ""))


def parse_legacy_state_symbols(scratchpad: Path) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """Parse every currently driver-emitted legacy state table schema."""
    scratchpad = Path(scratchpad)
    rows: dict[str, dict[str, Any]] = {}
    counts = {
        "legacy_global_two_column": 0,
        "legacy_contract_scoped_multi_column": 0,
        "legacy_global_multi_column": 0,
        "recon_state_inventory": 0,
    }
    path = scratchpad / "state_write_map.md"
    if path.is_file():
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            lines = []
        scope = ""
        header: list[str] = []
        schema = ""
        for line in lines:
            heading = re.match(r"^##\s+(.+?)\s*$", line)
            if heading:
                scope = re.sub(r"\.(?:sol|rs|move|go|vy|daml)$", "", heading.group(1).strip())
                header = []
                schema = ""
                continue
            cells = _table_cells(line)
            if not cells:
                continue
            lowered = [cell.casefold() for cell in cells]
            if any(name in lowered for name in ("state variable", "variable")):
                header = lowered
                if scope and len(cells) >= 3:
                    schema = "legacy_contract_scoped_multi_column"
                elif len(cells) == 2:
                    schema = "legacy_global_two_column"
                else:
                    schema = "legacy_global_multi_column"
                continue
            if not header or _separator(cells):
                continue
            try:
                var_idx = next(i for i, cell in enumerate(header) if cell in {"state variable", "variable"})
            except StopIteration:
                continue
            if var_idx >= len(cells):
                continue
            name = re.sub(r"[\[(].*$", "", cells[var_idx]).strip()
            if not name or name.casefold() in {"none", "n/a"}:
                continue
            qualified = name if re.search(r"::|[.#/]", name) else (f"{scope}.{name}" if scope else name)
            writer_text = " ".join(cells[var_idx + 1 :])
            write_sites = _descriptor_locations(writer_text)
            row = normalize_state_symbol(
                qualified,
                {
                    "bare": _bare_name(name),
                    "write_sites": write_sites,
                    "refs": write_sites,
                    "confidence": "LEGACY_COMPATIBILITY",
                },
                source="state_write_map.md",
                authority="LEGACY_COMPATIBILITY",
            )
            rows[qualified] = row
            counts[schema] += 1

    inventory = scratchpad / "state_variables.md"
    if inventory.is_file():
        try:
            lines = inventory.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            lines = []
        header: list[str] = []
        for line in lines:
            cells = _table_cells(line)
            if not cells:
                if header:
                    header = []
                continue
            lowered = [cell.casefold() for cell in cells]
            if "file" in lowered and any(name in lowered for name in ("state variable", "variable")):
                header = lowered
                continue
            if not header or _separator(cells):
                continue
            try:
                file_idx = header.index("file")
                var_idx = next(i for i, cell in enumerate(header) if cell in {"state variable", "variable"})
            except (ValueError, StopIteration):
                continue
            if max(file_idx, var_idx) >= len(cells):
                continue
            locus, name = cells[file_idx], re.sub(r"[\[(].*$", "", cells[var_idx]).strip()
            if not name:
                continue
            line_value = ""
            if "line" in header and header.index("line") < len(cells):
                line_value = cells[header.index("line")]
            declaration = f"{locus}:L{line_value}" if locus and line_value.isdigit() else locus
            qualified = f"{locus}::{name}" if locus else name
            # A driver write-map projection and recon inventory often describe
            # the same symbol using contract-vs-file qualification.  Merge only
            # when the bare alias is unique and the scope names agree; two
            # contracts with the same field remain separate identities.
            compatible = [
                row
                for row in rows.values()
                if name in (row.get("bare_aliases") or [])
                and (
                    not locus
                    or _bare_name(str(row.get("qualified_name") or "")).casefold() == name.casefold()
                    and Path(locus).stem.casefold()
                    in str(row.get("qualified_name") or "").casefold()
                )
            ]
            if len(compatible) == 1:
                if declaration and not compatible[0].get("declaration_locus"):
                    compatible[0]["declaration_locus"] = declaration
                counts["recon_state_inventory"] += 1
                continue
            if qualified not in rows:
                rows[qualified] = normalize_state_symbol(
                    qualified,
                    {"bare": name, "declaration_locus": declaration, "confidence": "REGEX_INVENTORY"},
                    source="state_variables.md",
                    authority="LEGACY_COMPATIBILITY",
                )
                counts["recon_state_inventory"] += 1
    return [rows[key] for key in sorted(rows)], counts


def load_state_symbols(scratchpad: Path) -> tuple[list[dict[str, Any]], dict[str, Any], dict[str, str]]:
    """Load graph authority and merge only graph-missing compatibility rows."""
    scratchpad = Path(scratchpad)
    graph_path = scratchpad / _GRAPH_NAME
    graph_payload: dict[str, Any] = {}
    graph_digest = ""
    graph_parse_status = "MISSING"
    if graph_path.is_file():
        try:
            raw = graph_path.read_bytes()
            graph_digest = _sha256_bytes(raw)
            parsed = json.loads(raw.decode("utf-8"))
            if isinstance(parsed, dict):
                graph_payload = parsed
                graph_parse_status = "VALID"
            else:
                graph_parse_status = "INVALID"
        except (OSError, UnicodeError, json.JSONDecodeError):
            graph_payload = {}
            graph_parse_status = "INVALID"
    source = str(graph_payload.get("source") or "unknown")
    typed = graph_payload.get("state_symbols")
    graph_rows: list[dict[str, Any]] = []
    typed_count = 0
    compat_count = 0
    if isinstance(typed, list):
        for raw in typed:
            if not isinstance(raw, dict) or not str(raw.get("qualified_name") or "").strip():
                continue
            graph_rows.append(normalize_state_symbol(str(raw["qualified_name"]), raw, source=source))
            typed_count += 1
    if not graph_rows and isinstance(graph_payload.get("var_refs"), dict):
        graph_rows = build_typed_state_symbols(source, graph_payload["var_refs"])
        compat_count = len(graph_rows)

    legacy_rows, legacy_counts = parse_legacy_state_symbols(scratchpad)
    merged = {row["qualified_name"]: row for row in graph_rows}
    shadowed = 0
    added = 0
    for row in legacy_rows:
        key = row["qualified_name"]
        if key in merged:
            shadowed += 1
            continue
        merged[key] = row
        added += 1
    counts: dict[str, Any] = {
        "mechanical_graph_parse_status": graph_parse_status,
        "mechanical_graph_schema_version": str(graph_payload.get("schema_version") or "legacy-unversioned"),
        "mechanical_graph_typed_symbols": typed_count,
        "mechanical_graph_var_refs_compat": compat_count,
        "mechanical_graph_symbol_count": len(graph_rows),
        **legacy_counts,
        "legacy_added_to_partial_graph": added,
        "legacy_shadowed_by_graph": shadowed,
    }
    digests: dict[str, str] = {}
    if graph_path.is_file():
        digests[_GRAPH_NAME] = graph_digest
    for name in ("state_write_map.md", "state_variables.md"):
        path = scratchpad / name
        if path.is_file():
            try:
                digests[name] = _sha256_bytes(path.read_bytes())
            except OSError:
                digests[name] = "UNREADABLE"
    return [merged[key] for key in sorted(merged)], counts, digests


def _locations(text: str) -> list[tuple[str, int, int]]:
    out: list[tuple[str, int, int]] = []
    for match in _SOURCE_LOC_RE.finditer(str(text or "")):
        file_name = match.group("file").replace("\\", "/").lstrip("./")
        start = int(match.group("start"))
        end = int(match.group("end") or start)
        if end < start:
            start, end = end, start
        out.append((file_name, start, end))
    return out


def _same_file(left: str, right: str, ambiguous_basenames: set[str] | None = None) -> bool:
    # Exact relative path is preferred.  A basename-only citation is accepted
    # only when one side genuinely contains no directory component.
    a = left.casefold().replace("\\", "/").lstrip("./")
    b = right.casefold().replace("\\", "/").lstrip("./")
    if a == b:
        return True
    if "/" not in a or "/" not in b:
        basename = a.rsplit("/", 1)[-1]
        if basename != b.rsplit("/", 1)[-1]:
            return False
        return basename not in (ambiguous_basenames or set())
    return False


def _location_intersects(
    finding_locs: list[tuple[str, int, int]],
    symbol_locs: list[tuple[str, int, int]],
    ambiguous_basenames: set[str] | None = None,
) -> bool:
    for f_file, f_start, f_end in finding_locs:
        for s_file, s_start, s_end in symbol_locs:
            if _same_file(f_file, s_file, ambiguous_basenames) and max(f_start, s_start) <= min(f_end, s_end):
                return True
    return False


def _bounded_prose(entry: dict[str, Any]) -> str:
    values: list[str] = []
    for field in ("title", "root_cause", "description", "impact", "evidence", "mechanism"):
        value = entry.get(field, "")
        if isinstance(value, (list, tuple, set)):
            values.extend(str(item) for item in value)
        else:
            values.append(str(value or ""))
    return " ".join(values)[:_PROSE_LIMIT]


def _alias_match(text: str, alias: str) -> bool:
    alias = str(alias or "").strip()
    if not alias:
        return False
    return bool(re.search(rf"(?<![{_IDENT_BOUNDARY}]){re.escape(alias)}(?![{_IDENT_BOUNDARY}])", text))


def _finding_id(entry: dict[str, Any], index: int) -> str:
    return str(entry.get("local_id") or entry.get("finding_id") or entry.get("id") or f"INV-{index:03d}").strip()


def resolve_chain_state(
    scratchpad: Path,
    findings: list[dict[str, Any]],
    *,
    preserve_signal_counts: bool = True,
) -> dict[str, Any]:
    """Resolve exact state edges, emit an exact receipt, and stamp degradation."""
    scratchpad = Path(scratchpad)
    symbols, schema_counts, source_digests = load_state_symbols(scratchpad)
    inventory_artifact = scratchpad / "findings_inventory.md"
    if inventory_artifact.is_file():
        try:
            source_digests["findings_inventory.md"] = _sha256_bytes(
                inventory_artifact.read_bytes()
            )
        except OSError:
            source_digests["findings_inventory.md"] = "UNREADABLE"
    normalized_findings = [entry for entry in findings if isinstance(entry, dict)]
    finding_ids = [_finding_id(entry, index) for index, entry in enumerate(normalized_findings, start=1)]

    aliases_to_ids: dict[str, set[str]] = {}
    symbol_locations: dict[str, list[tuple[str, int, int]]] = {}
    paths_by_basename: dict[str, set[str]] = {}
    for symbol in symbols:
        for alias in symbol.get("bare_aliases") or []:
            aliases_to_ids.setdefault(str(alias), set()).add(str(symbol["symbol_id"]))
        sid = str(symbol["symbol_id"])
        locs: list[tuple[str, int, int]] = []
        for descriptor in [
            symbol.get("declaration_locus") or "",
            *(symbol.get("read_sites") or []),
            *(symbol.get("write_sites") or []),
            *(symbol.get("reference_sites") or []),
        ]:
            locs.extend(_locations(str(descriptor)))
        symbol_locations[sid] = locs
        for file_name, _start, _end in locs:
            normalized = file_name.casefold().replace("\\", "/").lstrip("./")
            paths_by_basename.setdefault(normalized.rsplit("/", 1)[-1], set()).add(normalized)
    ambiguous_basenames = {
        basename for basename, paths in paths_by_basename.items() if len(paths) > 1
    }

    edges: list[dict[str, str]] = []
    edge_keys: set[tuple[str, str]] = set()
    for index, entry in enumerate(normalized_findings, start=1):
        fid = _finding_id(entry, index)
        cited = _locations(str(entry.get("location") or ""))
        prose = _bounded_prose(entry)
        for symbol in symbols:
            sid = str(symbol["symbol_id"])
            locations_for_symbol = symbol_locations.get(sid, [])
            basis = ""
            if cited and locations_for_symbol and _location_intersects(
                cited, locations_for_symbol, ambiguous_basenames
            ):
                if symbol.get("authority") == "MECHANICAL_GRAPH":
                    confidence = str(symbol.get("graph_confidence") or "").upper()
                    basis = (
                        "GRAPH_APPROXIMATE_LOCATION"
                        if "APPROXIMATE" in confidence or "FUNCTION_SCOPE" in confidence
                        else "GRAPH_CITED_LOCATION"
                    )
                else:
                    basis = "LEGACY_CITED_LOCATION"
            elif _alias_match(prose, str(symbol.get("qualified_name") or "")):
                basis = "PROSE_QUALIFIED_ALIAS"
            else:
                for alias in symbol.get("bare_aliases") or []:
                    if len(aliases_to_ids.get(str(alias), set())) == 1 and _alias_match(prose, str(alias)):
                        basis = "PROSE_UNAMBIGUOUS_BARE_ALIAS"
                        break
            if not basis or (fid, sid) in edge_keys:
                continue
            edge_keys.add((fid, sid))
            edges.append({
                "finding_id": fid,
                "symbol_id": sid,
                "qualified_name": str(symbol["qualified_name"]),
                "basis": basis,
                "confidence": (
                    "HIGH" if basis == "GRAPH_CITED_LOCATION"
                    else "MEDIUM" if basis in {"LEGACY_CITED_LOCATION", "GRAPH_APPROXIMATE_LOCATION"}
                    else "LOW"
                ),
            })

    graph_edges = sum(1 for edge in edges if edge["basis"].startswith("GRAPH_"))
    exact_graph_edges = sum(1 for edge in edges if edge["basis"] == "GRAPH_CITED_LOCATION")
    prose_edges = sum(1 for edge in edges if edge["basis"].startswith("PROSE_"))
    resolved_symbol_ids = {edge["symbol_id"] for edge in edges}
    resolved_finding_ids = {edge["finding_id"] for edge in edges}
    deterministic_negative = bool(normalized_findings) and all(
        str(entry.get("state_touch_disposition") or "") == "DETERMINISTIC_NO_STATE_TOUCH"
        and bool(str(entry.get("state_touch_evidence") or "").strip())
        for entry in normalized_findings
    )
    graph_symbol_count = int(schema_counts.get("mechanical_graph_symbol_count") or 0)
    if schema_counts.get("mechanical_graph_parse_status") == "INVALID":
        status = "DEGRADED_GRAPH_SCHEMA"
    elif not symbols:
        status = "NO_STATE_SYMBOLS"
    elif not normalized_findings:
        status = "NO_FINDINGS"
    elif edges:
        status = "COMPLETE"
    elif deterministic_negative:
        status = "DETERMINISTIC_NEGATIVE"
    elif graph_symbol_count:
        status = DEGRADED_STATUS
    else:
        status = "DEGRADED_COMPATIBILITY_APPLICATION"

    inventory_bytes = _canonical_json(normalized_findings)
    digest_material = {
        "schema": RECEIPT_SCHEMA,
        "source_artifacts": source_digests,
        "inventory_sha256": _sha256_bytes(inventory_bytes),
        "schema_counts": schema_counts,
    }
    input_digest = _sha256_bytes(_canonical_json(digest_material))
    prior_pair_counts = {"STATE": 0, "TYPE": 0, "TOTAL": 0}
    prior_path = scratchpad / _RECEIPT_NAME
    if prior_path.is_file():
        try:
            prior = json.loads(prior_path.read_text(encoding="utf-8", errors="strict"))
            if (
                preserve_signal_counts
                and prior.get("input_digest") == input_digest
                and isinstance(prior.get("signal_family_pair_counts"), dict)
            ):
                prior_pair_counts = {
                    key: int(prior["signal_family_pair_counts"].get(key) or 0)
                    for key in ("STATE", "TYPE", "TOTAL")
                }
        except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError):
            pass
    receipt: dict[str, Any] = {
        "schema_version": RECEIPT_SCHEMA,
        "status": status,
        "input_digest": input_digest,
        "source_artifact_digests": source_digests,
        "inventory_sha256": digest_material["inventory_sha256"],
        "input_symbol_count": len(symbols),
        "input_finding_count": len(normalized_findings),
        "graph_edge_count": graph_edges,
        "exact_graph_edge_count": exact_graph_edges,
        "prose_edge_count": prose_edges,
        "legacy_location_edge_count": sum(1 for edge in edges if edge["basis"] == "LEGACY_CITED_LOCATION"),
        "total_edge_count": len(edges),
        "schema_counts": schema_counts,
        "signal_family_pair_counts": prior_pair_counts,
        "symbols": symbols,
        "resolution_edges": sorted(edges, key=lambda edge: (edge["finding_id"], edge["symbol_id"])),
        "unresolved_symbol_ids": sorted(str(row["symbol_id"]) for row in symbols if str(row["symbol_id"]) not in resolved_symbol_ids),
        "unresolved_finding_ids": sorted(fid for fid in finding_ids if fid not in resolved_finding_ids),
        "deterministic_negative": deterministic_negative,
        "degradation_reasons": (
            ["POPULATED_GRAPH_WITH_ZERO_RESOLVED_STATE_EDGES"] if status == DEGRADED_STATUS
            else ["MECHANICAL_GRAPH_UNREADABLE_OR_SCHEMA_INVALID"] if status == "DEGRADED_GRAPH_SCHEMA"
            else ["COMPATIBILITY_STATE_ROWS_WITH_ZERO_RESOLVED_EDGES"] if status == "DEGRADED_COMPATIBILITY_APPLICATION"
            else []
        ),
    }
    _atomic_json(prior_path, receipt)
    degraded_path = scratchpad / _DEGRADED_NAME
    if status.startswith("DEGRADED_"):
        degraded_path.write_text(
            f"{status}\ninput_digest={input_digest}\n"
            f"symbols={len(symbols)} findings={len(normalized_findings)} edges={len(edges)}\n",
            encoding="utf-8",
        )
    else:
        try:
            degraded_path.unlink()
        except FileNotFoundError:
            pass
    return receipt


def update_signal_family_pair_counts(scratchpad: Path, *, state_pairs: int, type_pairs: int) -> dict[str, Any]:
    """Bind the exact generated pair-family denominator into the receipt."""
    path = Path(scratchpad) / _RECEIPT_NAME
    payload = json.loads(path.read_text(encoding="utf-8", errors="strict"))
    if payload.get("schema_version") != RECEIPT_SCHEMA:
        raise ValueError("unsupported chain state resolution schema")
    payload["signal_family_pair_counts"] = {
        "STATE": int(state_pairs),
        "TYPE": int(type_pairs),
        "TOTAL": int(state_pairs) + int(type_pairs),
    }
    _atomic_json(path, payload)
    return payload


def validate_chain_state_resolution(scratchpad: Path) -> list[str]:
    """Validate receipt parity without making any semantic disposition."""
    path = Path(scratchpad) / _RECEIPT_NAME
    if not path.is_file():
        return ["chain_state_resolution.json is missing"]
    try:
        payload = json.loads(path.read_text(encoding="utf-8", errors="strict"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        return [f"chain_state_resolution.json unreadable: {type(exc).__name__}"]
    issues: list[str] = []
    if payload.get("schema_version") != RECEIPT_SCHEMA:
        issues.append("chain state resolution schema mismatch")
    edges = payload.get("resolution_edges") or []
    if int(payload.get("total_edge_count") or 0) != len(edges):
        issues.append("chain state resolution edge-count mismatch")
    pairs = payload.get("signal_family_pair_counts") or {}
    if int(pairs.get("TOTAL") or 0) != int(pairs.get("STATE") or 0) + int(pairs.get("TYPE") or 0):
        issues.append("chain state signal-family pair denominator mismatch")
    tail_path = Path(scratchpad) / "chain_tail_disposition_ledger.json"
    if tail_path.is_file():
        try:
            tail = json.loads(tail_path.read_text(encoding="utf-8", errors="strict"))
            rows = [row for row in (tail.get("pairs") or []) if isinstance(row, dict)]
            tail_state = sum(str(row.get("signal_family") or "").casefold() == "state" for row in rows)
            tail_type = sum(str(row.get("signal_family") or "").casefold() == "type" for row in rows)
            if tail_state != int(pairs.get("STATE") or 0) or tail_type != int(pairs.get("TYPE") or 0):
                issues.append("chain state receipt disagrees with exact tail-ledger signal families")
        except (OSError, UnicodeError, json.JSONDecodeError):
                issues.append("chain tail ledger unreadable during state-family reconciliation")
    for name, expected in sorted((payload.get("source_artifact_digests") or {}).items()):
        source_path = Path(scratchpad) / str(name)
        try:
            actual = _sha256_bytes(source_path.read_bytes())
        except OSError:
            actual = "UNREADABLE"
        if actual != str(expected):
            issues.append(f"chain state source digest drift: {name}")
    if payload.get("status") == DEGRADED_STATUS and not (Path(scratchpad) / _DEGRADED_NAME).is_file():
        issues.append("DEGRADED_GRAPH_APPLICATION lacks persistent debt sentinel")
    return issues


def _atomic_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


__all__ = [
    "GRAPH_SCHEMA",
    "RECEIPT_SCHEMA",
    "DEGRADED_STATUS",
    "build_typed_state_symbols",
    "load_state_symbols",
    "normalize_state_symbol",
    "parse_legacy_state_symbols",
    "resolve_chain_state",
    "update_signal_family_pair_counts",
    "validate_chain_state_resolution",
]
