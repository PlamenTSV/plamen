"""Deterministic Inventory-to-Depth handoff projections.

The inventory methodology requires four sidecars and the EVM depth methodology
requires four graph views.  Model-sharded inventory deliberately owns only the
canonical finding inventory, so the driver projects these recall-preserving
views from its already authenticated inputs before any depth worker launches.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any, Mapping, Sequence


OUTPUTS = (
    "depth_candidates.md",
    "file_coverage.md",
    "state_dependency_map.md",
    "phase4_gates.md",
    "caller_map.md",
    "callee_map.md",
    "state_write_map.md",
    "function_summary.md",
    "depth_handoff_receipt.json",
)

_FINDING_RE = re.compile(
    r"^### Finding \[(INV-[0-9]+)\]:\s*(.+?)\s*$\n"
    r"(?P<body>.*?)(?=^### Finding \[INV-[0-9]+\]:|\Z)",
    re.MULTILINE | re.DOTALL,
)
_FIELD_RE = re.compile(r"^\*\*([^*]+)\*\*:\s*(.*?)\s*$", re.MULTILINE)
_INVENTORY_ROW_RE = re.compile(
    r"^\|\s*[^|]+\|\s*`([^`]+\.(?:sol|vy|yul))`\s*\|",
    re.IGNORECASE | re.MULTILINE,
)


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical_json(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _cell(value: Any) -> str:
    text = str(value or "").replace("\r", " ").replace("\n", " ")
    return text.replace("|", "\\|").strip() or "-"


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item).strip() for item in value if str(item).strip()]


def _inventory_findings(text: str) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    seen: set[str] = set()
    for match in _FINDING_RE.finditer(text):
        finding_id = match.group(1)
        if finding_id in seen:
            # Additive re-emission can retain a byte-for-byte canonical card
            # later in the inventory.  Route the canonical identity once.
            continue
        seen.add(finding_id)
        fields = {
            key.strip().lower(): value.strip()
            for key, value in _FIELD_RE.findall(match.group("body"))
        }
        rows.append({
            "id": finding_id,
            "title": match.group(2).strip(),
            "severity": fields.get("severity", "Unknown"),
            "verdict": fields.get("verdict", "UNRESOLVED"),
            "location": fields.get("location", "UNKNOWN"),
            "root_cause": fields.get("root cause", "UNKNOWN"),
        })
    return rows


def _depth_domain(row: Mapping[str, str]) -> str:
    haystack = " ".join(str(row.get(k, "")) for k in (
        "title", "root_cause", "location",
    )).lower()
    scores = {
        "Token Flow": sum(term in haystack for term in (
            "token", "transfer", "balance", "fee", "refund", "swap",
            "withdraw", "approval", "asset", "amount",
        )),
        "State Trace": sum(term in haystack for term in (
            "state", "storage", "overwrite", "role", "bot", "allowlist",
            "admin", "initializ", "nonce", "replay",
        )),
        "Edge Case": sum(term in haystack for term in (
            "zero", "bound", "round", "overflow", "underflow", "length",
            "sentinel", "empty", "precision",
        )),
        "External": sum(term in haystack for term in (
            "cross-chain", "gateway", "callback", "external", "bridge",
            "router", "oracle", "mev", "revert message",
        )),
    }
    order = ("Token Flow", "State Trace", "Edge Case", "External")
    return max(order, key=lambda name: (scores[name], -order.index(name)))


def _graph_payload(raw: bytes) -> dict[str, Any]:
    value = json.loads(raw.decode("utf-8", errors="strict"))
    if not isinstance(value, dict):
        raise ValueError("mechanical graph root is not an object")
    if not isinstance(value.get("functions"), dict):
        raise ValueError("mechanical graph functions is not an object")
    if not isinstance(value.get("state_symbols"), list):
        raise ValueError("mechanical graph state_symbols is not an array")
    return value


def _depth_candidates(findings: Sequence[Mapping[str, str]]) -> bytes:
    lines = [
        "# Depth Candidates",
        "",
        "> **Status**: POPULATED",
        "",
        "Driver projection: every canonical inventory finding is routed once; "
        "domain assignment is a deterministic priority hint, not a security "
        "verdict. Depth workers must re-evaluate the underlying source.",
        "",
    ]
    for domain in ("Token Flow", "State Trace", "Edge Case", "External"):
        lines.extend((f"## {domain}", "", "| Finding ID | Severity | Verdict | Location | Title |", "|---|---|---|---|---|"))
        selected = [row for row in findings if _depth_domain(row) == domain]
        if selected:
            lines.extend(
                f"| {_cell(row['id'])} | {_cell(row['severity'])} | "
                f"{_cell(row['verdict'])} | {_cell(row['location'])} | "
                f"{_cell(row['title'])} |"
                for row in selected
            )
        else:
            lines.append("| - | - | - | - | No primary candidates |")
        lines.append("")
    refuted = [row for row in findings if row.get("verdict", "").upper() == "REFUTED"]
    lines.extend((
        "## Second Opinion Targets", "",
        "| Finding ID | Domain | Breadth Reasoning | Potential Enablers |",
        "|---|---|---|---|",
    ))
    if refuted:
        lines.extend(
            f"| {_cell(row['id'])} | {_cell(_depth_domain(row))} | "
            f"{_cell(row['root_cause'])} | Requires independent depth trace |"
            for row in refuted
        )
    else:
        lines.append("| - | - | No canonical REFUTED findings | - |")
    lines.extend((
        "", "## Chain-Escalated Findings", "",
        "No chain escalation is asserted mechanically. Chain-aware Depth must "
        "evaluate Low-severity postconditions against Medium+ missing preconditions.",
        "",
        f"Coverage: {len(findings)}/{len(findings)} canonical inventory findings routed.",
        "",
    ))
    return "\n".join(lines).encode("utf-8")


def _file_coverage(
    inventory_text: str,
    breadth_texts: Mapping[str, str],
) -> tuple[bytes, list[str]]:
    files = list(dict.fromkeys(_INVENTORY_ROW_RE.findall(inventory_text)))
    lines = [
        "# File Coverage Map", "", "> **Status**: POPULATED", "",
        "| Source File | Referenced in Analysis? | Referenced By |",
        "|---|---|---|",
    ]
    uncovered: list[str] = []
    for source in files:
        basename = Path(source).name
        refs = sorted(
            name for name, text in breadth_texts.items()
            if source in text or basename in text
        )
        if not refs:
            uncovered.append(source)
        lines.append(
            f"| `{_cell(source)}` | {'YES' if refs else 'NO'} | "
            f"{_cell(', '.join(refs) if refs else 'NONE')} |"
        )
    lines.extend(("", "## Uncovered Files", ""))
    lines.extend(
        (f"- `{name}` — mandatory Depth scope-gap target" for name in uncovered)
        if uncovered else ("NONE",)
    )
    lines.append("")
    return "\n".join(lines).encode("utf-8"), uncovered


def _graph_views(graph: Mapping[str, Any]) -> dict[str, bytes]:
    functions = graph.get("functions", {})
    states = graph.get("state_symbols", [])
    caller_rows: list[str] = []
    callee_rows: list[str] = []
    reads_by_function: dict[str, list[str]] = {}
    writes_by_function: dict[str, list[str]] = {}
    write_rows: list[str] = []
    for name, fact in sorted(functions.items()):
        fact = fact if isinstance(fact, dict) else {}
        loc = _cell(fact.get("loc"))
        callers = _string_list(fact.get("callers"))
        callees = _string_list(fact.get("callees"))
        caller_rows.append(f"| {_cell(name)} | {loc} | {_cell(', '.join(callers) if callers else 'NONE')} |")
        callee_rows.append(f"| {_cell(name)} | {loc} | {_cell(', '.join(callees) if callees else 'NONE')} |")
    for state in states:
        if not isinstance(state, dict):
            continue
        var = str(state.get("qualified_name") or state.get("symbol_id") or "UNKNOWN")
        read_sites = _string_list(state.get("read_sites"))
        write_sites = _string_list(state.get("write_sites"))
        for site in read_sites:
            reads_by_function.setdefault(site.split(" (")[0], []).append(var)
        for site in write_sites:
            writes_by_function.setdefault(site.split(" (")[0], []).append(var)
        write_rows.append(
            f"| {_cell(var)} | {_cell(', '.join(write_sites) if write_sites else 'UNKNOWN')} | "
            f"{_cell(state.get('declaration_locus') or 'UNKNOWN')} | {_cell(state.get('graph_confidence') or 'UNKNOWN')} |"
        )
    function_status = "POPULATED" if functions else "UNAVAILABLE: mechanical graph contains no function facts"
    state_write_count = sum(bool(_string_list(row.get("write_sites"))) for row in states if isinstance(row, dict))
    state_status = (
        "POPULATED" if state_write_count
        else "UNAVAILABLE: mechanical provider emitted no state write-site facts; use direct source"
    )
    summaries = []
    for name, fact in sorted(functions.items()):
        fact = fact if isinstance(fact, dict) else {}
        signature = fact.get("signature_fact") if isinstance(fact.get("signature_fact"), dict) else {}
        summaries.append(
            f"| {_cell(name)} | {_cell(fact.get('loc'))} | {_cell(signature.get('visibility') or 'UNKNOWN')} | "
            f"{len(_string_list(fact.get('callers')))} | {len(_string_list(fact.get('callees')))} | "
            f"{_cell(', '.join(sorted(set(reads_by_function.get(name, [])))) or 'UNKNOWN')} | "
            f"{_cell(', '.join(sorted(set(writes_by_function.get(name, [])))) or 'UNKNOWN')} | "
            f"{_cell(signature.get('authority') or 'UNKNOWN')} |"
        )
    return {
        "caller_map.md": ("\n".join([
            "# Caller Map", "", f"> **Status**: {function_status}", "",
            "| Function | Location | Callers |", "|---|---|---|", *caller_rows, "",
        ])).encode("utf-8"),
        "callee_map.md": ("\n".join([
            "# Callee Map", "", f"> **Status**: {function_status}", "",
            "| Function | Location | Callees |", "|---|---|---|", *callee_rows, "",
        ])).encode("utf-8"),
        "state_write_map.md": ("\n".join([
            "# State Write Map", "", f"> **Status**: {state_status}", "",
            "| State Variable | Written By | Declaration | Confidence |", "|---|---|---|---|", *write_rows, "",
        ])).encode("utf-8"),
        "function_summary.md": ("\n".join([
            "# Function Summary", "", f"> **Status**: {function_status}", "",
            "| Function | Location | Visibility | Caller Count | Callee Count | State Reads | State Writes | Authority |",
            "|---|---|---|---:|---:|---|---|---|", *summaries, "",
        ])).encode("utf-8"),
    }


def _state_dependency_map(graph: Mapping[str, Any]) -> bytes:
    rows: list[str] = []
    for state in graph.get("state_symbols", []):
        if not isinstance(state, dict):
            continue
        var = str(state.get("qualified_name") or state.get("symbol_id") or "UNKNOWN")
        writers = _string_list(state.get("write_sites"))
        readers = _string_list(state.get("read_sites"))
        for writer in writers:
            for reader in readers:
                if writer.split(" (")[0] == reader.split(" (")[0]:
                    continue
                rows.append(
                    f"| {_cell(var)} | {_cell(writer)} | {_cell(reader)} | "
                    "UNKNOWN — requires Depth judgment |"
                )
    status = (
        "POPULATED" if rows
        else "UNAVAILABLE: mechanical provider emitted no cross-function read/write pairs"
    )
    lines = [
        "# State Dependency Map", "", f"> **Status**: {status}", "",
        "| Variable | Writer Function | Consumer Function | Can Writer Break Consumer? |",
        "|---|---|---|---|",
        *(rows or ["| - | - | - | UNKNOWN — direct source analysis required |"]),
        "",
        "Mechanical projection does not assert safety. Every UNKNOWN row or "
        "unavailable provider result remains a direct-source Depth obligation.",
        "",
    ]
    return "\n".join(lines).encode("utf-8")


def _phase4_gates(
    manifest_text: str,
    breadth_texts: Mapping[str, str],
    findings: Sequence[Mapping[str, str]],
) -> bytes:
    expected = sorted(set(re.findall(r"\b(analysis_[A-Za-z0-9_.-]+\.md)\b", manifest_text)))
    missing = [name for name in expected if not breadth_texts.get(name, "").strip()]
    gate = "OPEN" if expected and not missing else "BLOCKED"
    decision = "PROCEED" if gate == "OPEN" else "RE-SPAWN MISSING AGENTS FIRST"
    lines = [
        "# Phase 4 Gate Status", "", "## Gate 1: Spawn Verification", "",
        "- **BINDING MANIFEST checked**: YES",
        f"- **Expected required agents**: {len(expected)}",
        f"- **Missing required agents**: {', '.join(missing) if missing else 'NONE'}",
        f"- **Status**: {gate}", "", "## Side Effect Trace Status", "",
        "- **Tokens with Side-Effect=YES/UNKNOWN**: UNMEASURABLE from canonical inventory",
        "- **Fully traced**: UNMEASURABLE from canonical inventory",
        "- **New [SE-N] findings**: 0 mechanically asserted",
        "- **Coverage gaps (UNKNOWN)**: retained as Depth obligations", "",
        "## Proceed to Step 4b?", "", f"- Gate 1: {gate}",
        f"- **Decision**: {decision}", "",
        f"- Canonical findings routed to Depth: {len(findings)}", "",
    ]
    return "\n".join(lines).encode("utf-8")


def render_depth_handoff(
    *,
    mechanical_graph_raw: bytes,
    findings_inventory_raw: bytes,
    contract_inventory_raw: bytes,
    spawn_manifest_raw: bytes,
    breadth_raw_by_name: Mapping[str, bytes],
) -> dict[str, bytes]:
    graph = _graph_payload(mechanical_graph_raw)
    finding_text = findings_inventory_raw.decode("utf-8", errors="replace")
    contract_text = contract_inventory_raw.decode("utf-8", errors="replace")
    manifest_text = spawn_manifest_raw.decode("utf-8", errors="replace")
    breadth_texts = {
        name: raw.decode("utf-8", errors="replace")
        for name, raw in breadth_raw_by_name.items()
    }
    findings = _inventory_findings(finding_text)
    if not findings:
        raise ValueError("canonical inventory contains no INV finding cards")
    views = _graph_views(graph)
    file_coverage, uncovered = _file_coverage(contract_text, breadth_texts)
    outputs: dict[str, bytes] = {
        "depth_candidates.md": _depth_candidates(findings),
        "file_coverage.md": file_coverage,
        "state_dependency_map.md": _state_dependency_map(graph),
        "phase4_gates.md": _phase4_gates(manifest_text, breadth_texts, findings),
        **views,
    }
    receipt = {
        "schema_version": "plamen.depth_handoff_receipt.v1",
        "source_sha256": {
            "_mechanical_graph.json": _sha256(mechanical_graph_raw),
            "findings_inventory.md": _sha256(findings_inventory_raw),
            "contract_inventory.md": _sha256(contract_inventory_raw),
            "spawn_manifest.md": _sha256(spawn_manifest_raw),
            **{name: _sha256(raw) for name, raw in sorted(breadth_raw_by_name.items())},
        },
        "finding_count": len(findings),
        "function_count": len(graph.get("functions", {})),
        "state_symbol_count": len(graph.get("state_symbols", [])),
        "uncovered_files": uncovered,
        "output_sha256": {name: _sha256(raw) for name, raw in sorted(outputs.items())},
    }
    outputs["depth_handoff_receipt.json"] = _canonical_json(receipt)
    if set(outputs) != set(OUTPUTS):
        raise AssertionError("depth handoff output roster drift")
    return outputs


def write_depth_handoff(scratchpad: Path, breadth_outputs: Sequence[str]) -> None:
    root = Path(scratchpad)
    outputs = render_depth_handoff(
        mechanical_graph_raw=(root / "_mechanical_graph.json").read_bytes(),
        findings_inventory_raw=(root / "findings_inventory.md").read_bytes(),
        contract_inventory_raw=(root / "contract_inventory.md").read_bytes(),
        spawn_manifest_raw=(root / "spawn_manifest.md").read_bytes(),
        breadth_raw_by_name={name: (root / name).read_bytes() for name in breadth_outputs},
    )
    for name, raw in outputs.items():
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)


def validate_depth_handoff(scratchpad: Path, breadth_outputs: Sequence[str]) -> list[str]:
    root = Path(scratchpad)
    try:
        expected = render_depth_handoff(
            mechanical_graph_raw=(root / "_mechanical_graph.json").read_bytes(),
            findings_inventory_raw=(root / "findings_inventory.md").read_bytes(),
            contract_inventory_raw=(root / "contract_inventory.md").read_bytes(),
            spawn_manifest_raw=(root / "spawn_manifest.md").read_bytes(),
            breadth_raw_by_name={name: (root / name).read_bytes() for name in breadth_outputs},
        )
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
        return [f"depth handoff derivation failed: {type(exc).__name__}: {exc}"]
    issues: list[str] = []
    for name, raw in expected.items():
        try:
            observed = (root / name).read_bytes()
        except OSError as exc:
            issues.append(f"{name}: handoff output unavailable: {exc}")
            continue
        if observed != raw:
            issues.append(f"{name}: bytes differ from exact deterministic handoff")
    gate = expected["phase4_gates.md"].decode("utf-8", errors="strict")
    if "- **Status**: OPEN" not in gate:
        issues.append("phase4_gates.md: breadth spawn verification is BLOCKED")
    return issues
