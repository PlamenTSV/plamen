"""Exact input-to-disposition reconciliation for enumgap exploration.

The model explores work; this module only enumerates, binds, diffs, and routes.
It unifies mechanical co-reference obligations with residual exploration-clear
obligations so neither can disappear behind a substantial Markdown artifact.
No row produced here asserts a vulnerability or grants proof authority.
"""
from __future__ import annotations

import hashlib
import json
import os
from bisect import bisect_left
from pathlib import Path
import re
from typing import Any, Mapping, Sequence
import uuid

from exploration_clear_lifecycle import (
    ExplorationClearError,
    load_lifecycle_receipt,
    obligation_queue as exploration_clear_obligation_queue,
    resolve_clear_evidence,
)
from operational_markdown import operational_markdown_field_view
from enumgap_markdown import enumgap_reference_heading_ids
from plamen_markdown import mapped_headings, source_line_offsets


WORKLIST_SCHEMA = "plamen.enumgap_worklist.v1"
RECEIPT_SCHEMA = "plamen.enumgap_disposition_receipt.v1"
RESIDUAL_SCHEMA = "plamen.enumgap_residual_obligations.v1"
RECEIPT_NAME = "enumgap_disposition_receipt.json"
RESIDUAL_NAME = "enumgap_residual_obligations.json"
WORKLIST_NAME = "enumgap_worklist.json"

_HEX_RE = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
_EXPECTED_HEADER = ("obligation", "relationship", "disposition", "evidence")
_SEPARATOR_RE = re.compile(r"^:?-{3,}:?$")


class EnumgapDispositionError(ValueError):
    """Typed enumgap state failed exact validation."""


def _canonical(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _bytes_digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _normal(value: object) -> str:
    return " ".join(str(value or "").strip().split())


def _split_row(line: str) -> tuple[str, ...] | None:
    stripped = line.strip()
    if not stripped.startswith("|") or not stripped.endswith("|"):
        return None
    cells: list[str] = []
    current: list[str] = []
    escaped = False
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


def _enumeration_input(root: Path) -> tuple[list[dict[str, Any]], list[str], str]:
    path = root / "_enumeration_obligations.json"
    if not path.is_file():
        return [], [], ""
    try:
        raw = path.read_bytes()
        payload = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        return [], [f"enumeration obligation input is unreadable: {type(exc).__name__}"], ""
    if not isinstance(payload, dict) or not isinstance(payload.get("obligations"), list):
        return [], ["enumeration obligation input schema is malformed"], _bytes_digest(raw)
    rows: list[dict[str, Any]] = []
    debt: list[str] = []
    for index, item in enumerate(payload["obligations"]):
        if not isinstance(item, dict):
            debt.append(f"enumeration obligation row {index} is not an object")
            continue
        finding = _normal(item.get("finding_id"))
        function = _normal(item.get("function"))
        symbol = _normal(item.get("symbol"))
        corefs_raw = item.get("required_corefs")
        if (
            not finding or not function or not symbol
            or not isinstance(corefs_raw, list)
            or not corefs_raw
            or any(not _normal(value) for value in corefs_raw)
        ):
            debt.append(f"enumeration obligation row {index} lacks exact fields")
            continue
        corefs = sorted({_normal(value) for value in corefs_raw})
        identity_payload = {
            "finding_id": finding,
            "function": function,
            "symbol": symbol,
            "required_corefs": corefs,
        }
        rows.append({
            "work_item_id": "EOBL-" + _digest(identity_payload)[:24].upper(),
            "kind": "ENUMERATION_COREFERENCE",
            "source_identity": finding,
            "relationship": f"{function} / {symbol} / {', '.join(corefs)}",
            "context": identity_payload,
            "proof_scope": "NONE",
            "requires_independent_consumer": True,
        })
    return rows, debt, _bytes_digest(raw)


def _exploration_input(root: Path) -> tuple[list[dict[str, Any]], list[str], str]:
    queue_path = root / "exploration_clear_obligations.json"
    receipt_path = root / "exploration_clear_receipt.json"
    if not queue_path.is_file() and not receipt_path.is_file():
        return [], [], ""
    try:
        receipt = load_lifecycle_receipt(receipt_path)
        expected = exploration_clear_obligation_queue(receipt)
    except ExplorationClearError as exc:
        return [], [f"exploration-clear source receipt is invalid: {exc}"], ""
    try:
        raw = queue_path.read_bytes()
        observed = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raw = b""
        observed = None
        debt = [f"exploration-clear obligation queue is unreadable: {type(exc).__name__}"]
    else:
        debt = [] if observed == expected else [
            "exploration-clear obligation queue does not match its bound receipt"
        ]
    rows = [
        {
            "work_item_id": item.obligation_id,
            "kind": "EXPLORATION_CLEAR",
            "source_identity": item.source_finding,
            "relationship": f"{item.axis} / {item.instance}",
            "context": {
                "obligation_id": item.obligation_id,
                "source_finding": item.source_finding,
                "axis": item.axis,
                "instance": item.instance,
                "reason": item.reason,
                "artifact_sha256": item.artifact_sha256,
                "source_row_sha256": item.source_row_sha256,
                "source_row_sha256s": list(item.source_row_sha256s),
                "source_line": item.source_line,
            },
            "proof_scope": "NONE",
            "requires_independent_consumer": True,
        }
        for item in receipt.obligations
    ]
    return rows, debt, _bytes_digest(raw) if raw else ""


def compile_enumgap_worklist(scratchpad: str | Path) -> dict[str, Any]:
    root = Path(scratchpad)
    enum_rows, enum_debt, enum_sha = _enumeration_input(root)
    clear_rows, clear_debt, clear_sha = _exploration_input(root)
    groups: dict[str, list[dict[str, Any]]] = {}
    for row in (*enum_rows, *clear_rows):
        groups.setdefault(row["work_item_id"], []).append(row)
    items: list[dict[str, Any]] = []
    debt = [*enum_debt, *clear_debt]
    for identity in sorted(groups):
        members = groups[identity]
        if len({_canonical(member) for member in members}) != 1:
            debt.append(f"conflicting enumgap work identity {identity}")
            continue
        items.append(members[0])
    unsigned: dict[str, Any] = {
        "schema_version": WORKLIST_SCHEMA,
        "input_artifacts": {
            "_enumeration_obligations.json": enum_sha,
            "exploration_clear_obligations.json": clear_sha,
        },
        "count": len(items),
        "tail": items[-1]["work_item_id"] if items else "",
        "items": items,
        "input_debt": list(dict.fromkeys(debt)),
        "requires_execution": bool(items or debt),
    }
    unsigned["worklist_hash"] = _digest(unsigned)
    return unsigned


def write_enumgap_worklist(
    scratchpad: str | Path, worklist: Mapping[str, Any]
) -> Path:
    _validate_worklist(worklist)
    path = Path(scratchpad) / WORKLIST_NAME
    _write_json(path, worklist)
    return path


def load_enumgap_worklist(path: str | Path) -> dict[str, Any]:
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise EnumgapDispositionError(f"cannot load enumgap worklist: {exc}") from exc
    if not isinstance(payload, dict):
        raise EnumgapDispositionError("enumgap worklist must be an object")
    _validate_worklist(payload)
    return payload


def _validate_worklist(worklist: Mapping[str, Any]) -> None:
    if worklist.get("schema_version") != WORKLIST_SCHEMA:
        raise EnumgapDispositionError("enumgap worklist schema mismatch")
    claimed = worklist.get("worklist_hash")
    unsigned = {key: value for key, value in worklist.items() if key != "worklist_hash"}
    if claimed != _digest(unsigned):
        raise EnumgapDispositionError("enumgap worklist digest mismatch")
    items = worklist.get("items")
    if not isinstance(items, list):
        raise EnumgapDispositionError("enumgap worklist items are malformed")
    identities = [str(item.get("work_item_id") or "") for item in items if isinstance(item, dict)]
    if len(identities) != len(items) or identities != sorted(identities) or len(set(identities)) != len(identities):
        raise EnumgapDispositionError("enumgap worklist identities are not exact and ordered")
    if worklist.get("count") != len(items):
        raise EnumgapDispositionError("enumgap worklist count mismatch")
    if worklist.get("tail") != (identities[-1] if identities else ""):
        raise EnumgapDispositionError("enumgap worklist tail mismatch")
    debt = worklist.get("input_debt")
    if not isinstance(debt, list):
        raise EnumgapDispositionError("enumgap worklist input debt is malformed")
    if bool(worklist.get("requires_execution")) != bool(items or debt):
        raise EnumgapDispositionError("enumgap worklist execution predicate mismatch")


def _coverage_rows(text: str) -> tuple[list[tuple[int, tuple[str, ...], str]], list[str]]:
    source_lines = text.splitlines()
    lines = operational_markdown_field_view(text).splitlines()
    headings = mapped_headings(text)
    coverage_index: int | None = None
    for index, heading in enumerate(headings):
        if (
            int(heading["level"]) == 2
            and _normal(heading["content"]).casefold() == "coverage record"
        ):
            coverage_index = index
            break
    if coverage_index is None:
        return [], ["enumgap Coverage Record section is missing"]
    coverage = headings[coverage_index]
    section_end = len(text)
    for heading in headings[coverage_index + 1 :]:
        if int(heading["level"]) <= 2:
            section_end = int(heading["start"])
            break
    offsets = source_line_offsets(text)
    start = min(
        bisect_left(offsets, int(coverage["end"])),
        len(lines),
    )
    end = min(bisect_left(offsets, section_end), len(lines))
    header: int | None = None
    for index in range(start, end):
        cells = _split_row(lines[index])
        if cells is not None and tuple(cell.casefold() for cell in cells) == _EXPECTED_HEADER:
            header = index
            break
    if header is None or header + 1 >= end:
        return [], ["enumgap Coverage Record header is missing or malformed"]
    separator = _split_row(lines[header + 1])
    if separator is None or len(separator) != 4 or not all(_SEPARATOR_RE.fullmatch(cell) for cell in separator):
        return [], ["enumgap Coverage Record separator is missing or malformed"]
    rows: list[tuple[int, tuple[str, ...], str]] = []
    debt: list[str] = []
    for index in range(header + 2, end):
        structural_raw = lines[index]
        raw = source_lines[index]
        cells = _split_row(structural_raw)
        if cells is None:
            if raw.strip() or rows:
                break
            continue
        if len(cells) != 4:
            debt.append(f"malformed enumgap disposition at line {index + 1}")
            continue
        rows.append((index + 1, cells, _bytes_digest(raw.encode("utf-8"))))
    return rows, debt


def _status(count: int, input_debt: Sequence[str], debt: Sequence[str], unresolved: Sequence[str]) -> str:
    if count == 0 and not input_debt:
        return "EMPTY" if not debt else "COMPLETED_WITH_DEBT"
    if input_debt or debt or unresolved:
        return "COMPLETED_WITH_DEBT"
    return "CLEAN"


def reconcile_enumgap_output(
    worklist: Mapping[str, Any],
    output: str,
    *,
    production_root: str | Path,
    canonical_prior_ids: Mapping[str, str],
) -> dict[str, Any]:
    _validate_worklist(worklist)
    items = {item["work_item_id"]: item for item in worklist["items"]}
    if not items and not worklist["input_debt"]:
        raw_rows, parse_debt = [], []
    else:
        raw_rows, parse_debt = _coverage_rows(output)
    emitted_ids = set(enumgap_reference_heading_ids(output))
    grouped: dict[str, list[tuple[int, tuple[str, ...], str]]] = {}
    debt = list(worklist["input_debt"]) + parse_debt
    for row in raw_rows:
        identity = row[1][0]
        if identity not in items:
            debt.append(f"unexpected enumgap disposition identity {identity or '<blank>'}")
            continue
        grouped.setdefault(identity, []).append(row)
    dispositions: list[dict[str, Any]] = []
    unresolved: list[str] = []
    for identity in sorted(items):
        item = items[identity]
        members = grouped.get(identity, [])
        resolution_kind = "MISSING"
        disposition = "UNRESOLVED"
        evidence = ""
        relationship = item["relationship"]
        resolved_reference = ""
        emitted_action_id = ""
        source_line = 0
        source_row_sha256 = ""
        reason = "output has no disposition for this work item"
        if len(members) > 1:
            resolution_kind = "DUPLICATE_CONFLICT"
            reason = "duplicate or conflicting output dispositions"
            debt.append(f"duplicate enumgap disposition for {identity}")
        elif len(members) == 1:
            source_line, cells, source_row_sha256 = members[0]
            _, relationship, disposition_raw, evidence = cells
            disposition = disposition_raw.strip().upper()
            if disposition in {"FINDING", "UNRESOLVED"}:
                action_matches = sorted({
                    action_id
                    for action_id in emitted_ids
                    if re.search(
                        rf"(?<![A-Za-z0-9_-]){re.escape(action_id)}(?![A-Za-z0-9_-])",
                        evidence,
                        re.IGNORECASE | re.ASCII,
                    )
                })
                if len(action_matches) == 1:
                    resolution_kind = "EMITTED_ACTION"
                    emitted_action_id = action_matches[0]
                    resolved_reference = emitted_action_id
                    reason = ""
                else:
                    resolution_kind = "INVALID_ACTION_REFERENCE"
                    reason = "finding/unresolved disposition lacks one emitted action heading"
                    debt.append(f"{identity} finding disposition lacks one emitted action heading")
            elif disposition == "CLEAR":
                resolution_kind, resolved_reference = resolve_clear_evidence(
                    evidence,
                    production_root=production_root,
                    canonical_prior_ids=canonical_prior_ids,
                )
                if resolution_kind == "INVALID_CLEAR":
                    reason = "clear lacks exact resolvable evidence"
                    debt.append(f"{identity} clear lacks exact resolvable evidence")
                else:
                    reason = ""
            else:
                resolution_kind = "INVALID_DISPOSITION"
                reason = f"unsupported disposition {disposition or '<blank>'}"
                debt.append(f"{identity} has unsupported disposition {disposition or '<blank>'}")
        if resolution_kind in {
            "MISSING", "DUPLICATE_CONFLICT", "INVALID_ACTION_REFERENCE",
            "INVALID_CLEAR", "INVALID_DISPOSITION",
        }:
            unresolved.append(identity)
        dispositions.append({
            "work_item_id": identity,
            "kind": item["kind"],
            "source_identity": item["source_identity"],
            "source_item": item,
            "relationship": relationship,
            "disposition": disposition,
            "evidence": evidence,
            "resolution_kind": resolution_kind,
            "resolved_reference": resolved_reference,
            "emitted_action_id": emitted_action_id,
            "source_line": source_line,
            "source_row_sha256": source_row_sha256,
            "reason": reason,
        })
    unsigned: dict[str, Any] = {
        "schema_version": RECEIPT_SCHEMA,
        "worklist": dict(worklist),
        "denominator_count": len(items),
        "denominator_tail": worklist["tail"],
        "output_sha256": _bytes_digest(output.encode("utf-8")),
        "dispositions": dispositions,
        "unresolved_work_item_ids": unresolved,
        "debt": list(dict.fromkeys(debt)),
        "status": _status(
            len(items), worklist["input_debt"], debt, unresolved
        ),
    }
    unsigned["receipt_hash"] = _digest(unsigned)
    return unsigned


def residual_enumgap_queue(receipt: Mapping[str, Any]) -> dict[str, Any]:
    _validate_receipt(receipt)
    unresolved = set(receipt["unresolved_work_item_ids"])
    items = [
        {
            "work_item_id": row["work_item_id"],
            "kind": row["kind"],
            "source_identity": row["source_identity"],
            "source_item": row["source_item"],
            "reason": row["reason"],
            "proof_scope": "NONE",
            "requires_independent_consumer": True,
        }
        for row in receipt["dispositions"]
        if row["work_item_id"] in unresolved
    ]
    unsigned: dict[str, Any] = {
        "schema_version": RESIDUAL_SCHEMA,
        "source_receipt_hash": receipt["receipt_hash"],
        "count": len(items),
        "tail": items[-1]["work_item_id"] if items else "",
        "items": items,
    }
    unsigned["queue_hash"] = _digest(unsigned)
    return unsigned


def _validate_receipt(receipt: Mapping[str, Any]) -> None:
    if receipt.get("schema_version") != RECEIPT_SCHEMA:
        raise EnumgapDispositionError("enumgap receipt schema mismatch")
    claimed = receipt.get("receipt_hash")
    unsigned = {key: value for key, value in receipt.items() if key != "receipt_hash"}
    if claimed != _digest(unsigned):
        raise EnumgapDispositionError("enumgap receipt digest mismatch")
    _validate_worklist(receipt.get("worklist") if isinstance(receipt.get("worklist"), dict) else {})
    dispositions = receipt.get("dispositions")
    unresolved = receipt.get("unresolved_work_item_ids")
    debt = receipt.get("debt")
    if not isinstance(dispositions, list) or not isinstance(unresolved, list) or not isinstance(debt, list):
        raise EnumgapDispositionError("enumgap receipt collections are malformed")
    work_ids = [item["work_item_id"] for item in receipt["worklist"]["items"]]
    disp_ids = [row.get("work_item_id") for row in dispositions if isinstance(row, dict)]
    if disp_ids != work_ids or len(disp_ids) != len(dispositions):
        raise EnumgapDispositionError("enumgap receipt disposition denominator mismatch")
    computed_unresolved = [
        row["work_item_id"]
        for row in dispositions
        if row.get("resolution_kind") in {
            "MISSING", "DUPLICATE_CONFLICT", "INVALID_ACTION_REFERENCE",
            "INVALID_CLEAR", "INVALID_DISPOSITION",
        }
    ]
    if unresolved != computed_unresolved:
        raise EnumgapDispositionError("enumgap unresolved set mismatch")
    if receipt.get("denominator_count") != len(work_ids):
        raise EnumgapDispositionError("enumgap receipt denominator count mismatch")
    tail = work_ids[-1] if work_ids else ""
    if receipt.get("denominator_tail") != tail:
        raise EnumgapDispositionError("enumgap receipt denominator tail mismatch")
    expected_status = _status(
        len(work_ids), receipt["worklist"]["input_debt"], debt, unresolved
    )
    if receipt.get("status") != expected_status:
        raise EnumgapDispositionError("enumgap receipt semantic status mismatch")
    if not _HEX_RE.fullmatch(str(receipt.get("output_sha256") or "")):
        raise EnumgapDispositionError("enumgap output digest is malformed")


def _write_json(path: Path, payload: Mapping[str, Any]) -> None:
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


def write_enumgap_disposition_artifacts(
    scratchpad: str | Path, receipt: Mapping[str, Any]
) -> tuple[Path, Path]:
    _validate_receipt(receipt)
    root = Path(scratchpad)
    receipt_path = root / RECEIPT_NAME
    residual_path = root / RESIDUAL_NAME
    _write_json(receipt_path, receipt)
    _write_json(residual_path, residual_enumgap_queue(receipt))
    return receipt_path, residual_path


def load_enumgap_disposition_receipt(
    path: str | Path,
    *,
    output_artifact: str | Path | None = None,
) -> dict[str, Any]:
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise EnumgapDispositionError(f"cannot load enumgap receipt: {exc}") from exc
    if not isinstance(payload, dict):
        raise EnumgapDispositionError("enumgap receipt must be an object")
    _validate_receipt(payload)
    if output_artifact is not None:
        try:
            output_sha = _bytes_digest(Path(output_artifact).read_bytes())
        except OSError as exc:
            raise EnumgapDispositionError(
                f"bound enumgap output is unavailable: {exc}"
            ) from exc
        if output_sha != payload["output_sha256"]:
            raise EnumgapDispositionError("bound enumgap output digest mismatch")
    return payload


def validate_enumgap_disposition_authority(
    scratchpad: str | Path,
    *,
    production_root: str | Path,
    canonical_prior_ids: Mapping[str, str],
) -> dict[str, Any]:
    """Recompute the complete persisted authority from current source facts.

    A receipt digest authenticates internal consistency, not freshness.  This
    validator closes the resume/cross-consumer boundary by requiring the
    persisted worklist to equal the current deterministic input union, the
    receipt to equal a fresh parse of the exact output, and the residual queue
    to equal the freshly validated receipt.  No model-authored disposition is
    trusted from a digest alone.
    """

    root = Path(scratchpad)
    worklist = load_enumgap_worklist(root / WORKLIST_NAME)
    current_worklist = compile_enumgap_worklist(root)
    if worklist != current_worklist:
        raise EnumgapDispositionError(
            "enumgap worklist does not match the current input union"
        )
    output_path = root / "enumgap_exploration_findings.md"
    receipt = load_enumgap_disposition_receipt(
        root / RECEIPT_NAME,
        output_artifact=output_path,
    )
    if receipt.get("worklist") != worklist:
        raise EnumgapDispositionError(
            "enumgap receipt does not bind the current exact worklist"
        )
    try:
        with output_path.open("r", encoding="utf-8", newline="") as handle:
            output = handle.read()
    except (OSError, UnicodeError) as exc:
        raise EnumgapDispositionError(
            f"cannot read bound enumgap output: {exc}"
        ) from exc
    recomputed = reconcile_enumgap_output(
        worklist,
        output,
        production_root=production_root,
        canonical_prior_ids=canonical_prior_ids,
    )
    if receipt != recomputed:
        raise EnumgapDispositionError(
            "enumgap receipt does not match recomputed output dispositions"
        )
    expected_residual = residual_enumgap_queue(receipt)
    try:
        observed_residual = json.loads(
            (root / RESIDUAL_NAME).read_text(encoding="utf-8")
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise EnumgapDispositionError(
            f"cannot read enumgap residual queue: {exc}"
        ) from exc
    if observed_residual != expected_residual:
        raise EnumgapDispositionError(
            "enumgap residual queue does not match the recomputed receipt"
        )
    return receipt
