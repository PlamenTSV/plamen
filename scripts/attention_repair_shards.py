"""Deterministic sharding and reconciliation for attention-repair work."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
from typing import Any, Mapping, Sequence

from plamen_types import (
    ALL_AUDIT_SOURCE_SUFFIXES,
    attention_queue_binding_sha256,
)


PLAN_SCHEMA = "plamen.attention-repair-shard-plan.v1"
STAGED_GATE_CONTEXT_SCHEMA = (
    "plamen.attention-repair-staged-gate-context.v1"
)
DEFAULT_SHARD_SIZE = 8
MIN_SHARD_SIZE = 6
MAX_SHARD_SIZE = 10
SHARD_THRESHOLD = 10
# This is a memory/receipt-size safety ceiling, not an agent-attention limit.
# The former 512-row cap accidentally switched large audits back to one
# monolithic model turn.  Exact 6-10 row leaves remain the only execution
# shape; inputs beyond this much higher administrative bound stay loud debt.
MAX_ROWS = 16_384


class AttentionRepairShardError(ValueError):
    """A shard plan, input, or worker receipt is not trustworthy."""


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_json(payload: Mapping[str, Any]) -> bytes:
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _split_table_row(raw: str) -> list[str]:
    body = raw.strip()
    if body.startswith("|"):
        body = body[1:]
    if body.endswith("|"):
        body = body[:-1]
    cells: list[str] = []
    current: list[str] = []
    escaped = False
    for char in body:
        if escaped:
            current.append(char)
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == "|":
            cells.append("".join(current).strip().strip("`"))
            current = []
        else:
            current.append(char)
    cells.append("".join(current).strip().strip("`"))
    return cells


def _escape_cell(value: object, *, code: bool = False) -> str:
    text = str(value).replace("|", "\\|").replace("\r", " ").replace("\n", " ")
    return f"`{text}`" if code else text


def parse_bound_queue_bytes(data: bytes) -> tuple[str, list[dict[str, object]]]:
    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise AttentionRepairShardError("attention queue is not valid UTF-8") from exc
    match = re.search(
        r"(?im)^\s*QUEUE_BINDING_SHA256:\s*([a-f0-9]{64})\s*$",
        text,
    )
    if match is None:
        raise AttentionRepairShardError("attention queue has no semantic binding")
    claimed = match.group(1)
    rows: list[dict[str, object]] = []
    for line in text.splitlines():
        if not re.match(r"^\|\s*\d+\s*\|", line.strip()):
            continue
        cells = _split_table_row(line)
        if len(cells) != 6:
            raise AttentionRepairShardError(
                "attention queue row does not have exactly six columns"
            )
        try:
            row_no = int(cells[0])
        except ValueError as exc:
            raise AttentionRepairShardError(
                "attention queue row number is invalid"
            ) from exc
        rows.append(
            {
                "row": row_no,
                "kind": cells[1],
                "target": cells[2],
                "reason": cells[3],
                "source": cells[4],
                "evidence": cells[5],
            }
        )
    if not rows or [row["row"] for row in rows] != list(range(1, len(rows) + 1)):
        raise AttentionRepairShardError(
            "attention queue rows are missing, duplicated, or non-sequential"
        )
    if len(rows) > MAX_ROWS:
        raise AttentionRepairShardError(
            f"attention queue exceeds the hard {MAX_ROWS}-row application bound"
        )
    if attention_queue_binding_sha256(rows) != claimed:
        raise AttentionRepairShardError(
            "attention queue semantic binding does not match its rows"
        )
    return claimed, rows


def build_plan(
    queue_path: Path,
    *,
    shard_size: int = DEFAULT_SHARD_SIZE,
) -> dict[str, Any]:
    if not MIN_SHARD_SIZE <= int(shard_size) <= MAX_SHARD_SIZE:
        raise AttentionRepairShardError(
            f"attention shard_size must be {MIN_SHARD_SIZE}..{MAX_SHARD_SIZE}"
        )
    queue_bytes = Path(queue_path).read_bytes()
    parent_binding, rows = parse_bound_queue_bytes(queue_bytes)
    shards: list[dict[str, Any]] = []
    for offset in range(0, len(rows), int(shard_size)):
        ordinal = len(shards) + 1
        shard_rows = rows[offset : offset + int(shard_size)]
        shard_binding = attention_queue_binding_sha256(shard_rows)
        shards.append(
            {
                "ordinal": ordinal,
                "shard_id": f"attention-{ordinal:04d}",
                "input_path": (
                    f"_attention_repair_shards/shard_{ordinal:04d}.input.md"
                ),
                "output_path": f"attention_repair_rows_{ordinal:04d}.md",
                "row_numbers": [int(row["row"]) for row in shard_rows],
                "row_binding_sha256": shard_binding,
                "rows": shard_rows,
            }
        )
    unsigned: dict[str, Any] = {
        "schema": PLAN_SCHEMA,
        "queue_path": "attention_repair_queue.md",
        "queue_file_sha256": _sha256(queue_bytes),
        "parent_queue_binding_sha256": parent_binding,
        "row_count": len(rows),
        "shard_size": int(shard_size),
        "shard_count": len(shards),
        "shards": shards,
    }
    unsigned["plan_sha256"] = _sha256(_canonical_json(unsigned))
    return unsigned


def render_shard_input(plan: Mapping[str, Any], shard: Mapping[str, Any]) -> bytes:
    lines = [
        "# Attention Repair Shard",
        "",
        "This is one exact, bounded subset of the parent attention queue.",
        "Analyze every row below and no other queue row.",
        "",
        "PARENT_QUEUE_BINDING_SHA256: "
        + str(plan["parent_queue_binding_sha256"]),
        "SHARD_BINDING_SHA256: " + str(shard["row_binding_sha256"]),
        "",
        "| # | Kind | Target | Reason | Source | Evidence hint |",
        "|---|------|--------|--------|--------|---------------|",
    ]
    for row in shard["rows"]:
        lines.append(
            "| {row} | {kind} | {target} | {reason} | {source} | {evidence} |".format(
                row=int(row["row"]),
                kind=_escape_cell(row["kind"]),
                target=_escape_cell(row["target"], code=True),
                reason=_escape_cell(row["reason"]),
                source=_escape_cell(row["source"], code=True),
                evidence=_escape_cell(row.get("evidence", ""), code=True),
            )
        )
    return ("\n".join(lines) + "\n").encode("utf-8")


def validate_plan(
    root: Path,
    plan: Mapping[str, Any],
) -> list[str]:
    issues: list[str] = []
    if plan.get("schema") != PLAN_SCHEMA:
        return ["attention shard plan schema is invalid"]
    supplied = str(plan.get("plan_sha256") or "")
    unsigned = dict(plan)
    unsigned.pop("plan_sha256", None)
    if supplied != _sha256(_canonical_json(unsigned)):
        issues.append("attention shard plan self-hash mismatch")
    queue_path = Path(root) / str(plan.get("queue_path") or "")
    try:
        queue_bytes = queue_path.read_bytes()
        binding, rows = parse_bound_queue_bytes(queue_bytes)
    except (OSError, AttentionRepairShardError) as exc:
        issues.append(f"attention shard parent queue is invalid: {exc}")
        return issues
    if _sha256(queue_bytes) != plan.get("queue_file_sha256"):
        issues.append("attention shard plan queue-file binding drift")
    if binding != plan.get("parent_queue_binding_sha256"):
        issues.append("attention shard plan parent semantic binding drift")
    if len(rows) != plan.get("row_count"):
        issues.append("attention shard plan row denominator mismatch")
    shards = plan.get("shards")
    if not isinstance(shards, list) or len(shards) != plan.get("shard_count"):
        issues.append("attention shard plan roster is invalid")
        return issues
    expected_rows: list[int] = []
    names: set[str] = set()
    for ordinal, shard in enumerate(shards, 1):
        if not isinstance(shard, Mapping) or shard.get("ordinal") != ordinal:
            issues.append("attention shard plan ordinals are non-canonical")
            continue
        input_name = str(shard.get("input_path") or "")
        output_name = str(shard.get("output_path") or "")
        if (
            not re.fullmatch(
                r"_attention_repair_shards/shard_\d{4}\.input\.md",
                input_name,
            )
            or not re.fullmatch(r"attention_repair_rows_\d{4}\.md", output_name)
            or input_name in names
            or output_name in names
        ):
            issues.append(f"attention shard {ordinal} filenames are invalid")
        names.update((input_name, output_name))
        shard_rows = shard.get("rows")
        if not isinstance(shard_rows, list) or not shard_rows:
            issues.append(f"attention shard {ordinal} has no row denominator")
            continue
        if len(shard_rows) > MAX_SHARD_SIZE:
            issues.append(f"attention shard {ordinal} exceeds the row bound")
        if (
            attention_queue_binding_sha256(shard_rows)
            != shard.get("row_binding_sha256")
        ):
            issues.append(f"attention shard {ordinal} semantic binding mismatch")
        row_numbers = [int(row["row"]) for row in shard_rows]
        if row_numbers != shard.get("row_numbers"):
            issues.append(f"attention shard {ordinal} row-number drift")
        expected_rows.extend(row_numbers)
        path = Path(root) / input_name
        try:
            current = path.read_bytes()
        except OSError:
            issues.append(f"attention shard {ordinal} input is missing")
        else:
            if current != render_shard_input(plan, shard):
                issues.append(f"attention shard {ordinal} input drift")
    if expected_rows != list(range(1, len(rows) + 1)):
        issues.append("attention shard union is not the exact parent denominator")
    return issues


def _path_literal_present(text: str, path: str) -> bool:
    if f"`{path}`" in text:
        return True
    # Queue targets may be basenames while workers are required to cite the
    # more useful project-relative path.  A separator immediately before a
    # basename is therefore a valid boundary.  Already-qualified targets must
    # still match as complete paths, not arbitrary suffixes of other paths.
    boundary = (
        r"A-Za-z0-9_@.\-"
        if Path(path).name == path
        else r"A-Za-z0-9_@./\\-"
    )
    return bool(
        re.search(
            rf"(?<![{boundary}]){re.escape(path)}(?![{boundary}])",
            text,
        )
    )


def parse_shard_output(
    text: str,
    *,
    plan: Mapping[str, Any],
    shard: Mapping[str, Any],
) -> tuple[list[list[str]], list[str]]:
    issues: list[str] = []
    parent = str(plan["parent_queue_binding_sha256"])
    binding = str(shard["row_binding_sha256"])
    if not re.search(
        rf"(?im)^\s*PARENT_QUEUE_BINDING_SHA256:\s*{parent}\s*$",
        text,
    ):
        issues.append("parent queue binding is missing or stale")
    if not re.search(
        rf"(?im)^\s*SHARD_BINDING_SHA256:\s*{binding}\s*$",
        text,
    ):
        issues.append("shard binding is missing or stale")
    received: dict[int, list[str]] = {}
    for line in text.splitlines():
        if not re.match(r"^\|\s*\d+\s*\|", line.strip()):
            continue
        cells = _split_table_row(line)
        if len(cells) != 6:
            issues.append("worker receipt row must have exactly six columns")
            continue
        try:
            row_no = int(cells[0])
        except ValueError:
            issues.append("worker receipt row number is invalid")
            continue
        if row_no in received:
            issues.append(f"worker receipt duplicates row {row_no}")
        received[row_no] = cells
    expected = {
        int(row["row"]): row
        for row in shard["rows"]
    }
    if set(received) != set(expected):
        issues.append("worker receipt row denominator does not match its shard")
    allowed = {"SAFE", "CONFIRMED", "NO_FINDING", "NEEDS_HUMAN"}
    for row_no, row in expected.items():
        cells = received.get(row_no)
        if cells is None:
            continue
        if cells[1] != str(row["kind"]) or cells[2] != str(row["target"]):
            issues.append(f"worker receipt row {row_no} identity drift")
        verdict = cells[3].strip().upper().replace(" ", "_")
        if verdict not in allowed:
            issues.append(f"worker receipt row {row_no} verdict is unsupported")
            continue
        target = str(row["target"])
        path_target = Path(target).suffix.lower() in ALL_AUDIT_SOURCE_SUFFIXES
        if path_target and not _path_literal_present(cells[4], target):
            issues.append(f"worker receipt row {row_no} omits exact target evidence")
        if (
            path_target
            and verdict != "NEEDS_HUMAN"
            and not re.search(rf"{re.escape(target)}:L?\d+\b", cells[4])
        ):
            issues.append(f"worker receipt row {row_no} lacks file:line evidence")
        if verdict == "CONFIRMED" and not re.search(
            rf"(?im)^###\s+(?:Finding\s+)?\[ATT-{row_no}\]"
            r"(?=\s*(?::|$))[^\r\n]*$",
            text,
        ):
            issues.append(
                f"worker receipt row {row_no} is CONFIRMED without ATT-{row_no}"
            )
    ordered = [received[row_no] for row_no in sorted(received) if row_no in expected]
    return ordered, issues


def shard_output_issues(
    root: Path,
    plan: Mapping[str, Any],
    shard: Mapping[str, Any],
) -> list[str]:
    path = Path(root) / str(shard["output_path"])
    try:
        text = path.read_text(encoding="utf-8", errors="strict")
    except (OSError, UnicodeError) as exc:
        return [f"shard output unavailable: {exc}"]
    _rows, issues = parse_shard_output(text, plan=plan, shard=shard)
    return issues


def staged_shard_output_validator(
    outputs: Mapping[str, bytes],
    context: Mapping[str, Any],
) -> Sequence[str]:
    """Validate one attempt-owned shard before canonical incorporation."""

    issues: list[str] = []
    if (
        not isinstance(context, Mapping)
        or set(context) != {"schema", "plan", "shard", "output_identity"}
        or context.get("schema") != STAGED_GATE_CONTEXT_SCHEMA
    ):
        return ["attention shard staged-gate context is malformed"]
    plan = context.get("plan")
    shard = context.get("shard")
    identity = context.get("output_identity")
    if (
        not isinstance(plan, Mapping)
        or not isinstance(shard, Mapping)
        or not isinstance(identity, str)
        or not re.fullmatch(
            r"scratchpad:attention_repair_rows_\d{4}\.md",
            identity,
        )
    ):
        return ["attention shard staged-gate authority is malformed"]
    unsigned = dict(plan)
    supplied_plan_hash = str(unsigned.pop("plan_sha256", ""))
    if (
        plan.get("schema") != PLAN_SCHEMA
        or supplied_plan_hash != _sha256(_canonical_json(unsigned))
    ):
        issues.append("attention shard staged-gate plan binding is invalid")
    roster = plan.get("shards")
    ordinal = shard.get("ordinal")
    if (
        not isinstance(roster, list)
        or not isinstance(ordinal, int)
        or isinstance(ordinal, bool)
        or ordinal < 1
        or ordinal > len(roster)
        or roster[ordinal - 1] != dict(shard)
    ):
        issues.append("attention shard staged-gate roster binding is invalid")
    rows = shard.get("rows")
    if (
        not isinstance(rows, list)
        or not rows
        or attention_queue_binding_sha256(rows)
        != shard.get("row_binding_sha256")
    ):
        issues.append("attention shard staged-gate row binding is invalid")
    if identity != f"scratchpad:{shard.get('output_path', '')}":
        issues.append("attention shard staged-gate output identity drift")
    if set(outputs) != {identity}:
        issues.append("attention shard staged output denominator mismatch")
        return issues
    raw = outputs.get(identity)
    if not isinstance(raw, bytes):
        return [*issues, "attention shard staged output is not bytes"]
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeError:
        return [*issues, "attention shard staged output is not strict UTF-8"]
    _rows, parse_issues = parse_shard_output(
        text,
        plan=plan,
        shard=shard,
    )
    issues.extend(parse_issues)
    return list(dict.fromkeys(issues))


def open_shards(root: Path, plan: Mapping[str, Any]) -> list[dict[str, Any]]:
    return [
        dict(shard)
        for shard in plan["shards"]
        if shard_output_issues(root, plan, shard)
    ]


_FINDING_HEADING_RE = re.compile(
    r"(?im)^###\s+(?:Finding\s+)?\[(ATT-\d+)\][^\r\n]*$"
)


def _finding_blocks(text: str) -> dict[str, str]:
    matches = list(_FINDING_HEADING_RE.finditer(text))
    blocks: dict[str, str] = {}
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        finding_id = match.group(1).upper()
        if finding_id in blocks:
            raise AttentionRepairShardError(
                f"attention shard duplicates finding ID {finding_id}"
            )
        blocks[finding_id] = text[match.start():end].strip()
    return blocks


def aggregate_outputs(
    root: Path,
    plan: Mapping[str, Any],
) -> tuple[bytes, bytes]:
    plan_issues = validate_plan(root, plan)
    if plan_issues:
        raise AttentionRepairShardError("; ".join(plan_issues))
    rows: dict[int, list[str]] = {}
    findings: dict[str, str] = {}
    for shard in plan["shards"]:
        path = Path(root) / str(shard["output_path"])
        try:
            text = path.read_text(encoding="utf-8", errors="strict")
        except (OSError, UnicodeError) as exc:
            raise AttentionRepairShardError(
                f"attention shard output unavailable: {path.name}"
            ) from exc
        parsed, issues = parse_shard_output(text, plan=plan, shard=shard)
        if issues:
            raise AttentionRepairShardError(
                f"{path.name}: " + "; ".join(issues)
            )
        for cells in parsed:
            row_no = int(cells[0])
            if row_no in rows:
                raise AttentionRepairShardError(
                    f"attention aggregate duplicates row {row_no}"
                )
            rows[row_no] = cells
        for finding_id, block in _finding_blocks(text).items():
            if finding_id in findings:
                raise AttentionRepairShardError(
                    f"attention aggregate duplicates finding ID {finding_id}"
                )
            findings[finding_id] = block
    expected_rows = list(range(1, int(plan["row_count"]) + 1))
    if sorted(rows) != expected_rows:
        raise AttentionRepairShardError(
            "attention aggregate is missing part of the parent denominator"
        )
    summary_lines = [
        "# Attention Repair",
        "",
        "QUEUE_BINDING_SHA256: "
        + str(plan["parent_queue_binding_sha256"]),
        "",
        "| Queue # | Kind | Target | Verdict | Evidence | Notes |",
        "|---|---|---|---|---|---|",
    ]
    for row_no in expected_rows:
        cells = rows[row_no]
        summary_lines.append(
            "| "
            + " | ".join(
                _escape_cell(cell, code=(index == 2))
                for index, cell in enumerate(cells)
            )
            + " |"
        )
    finding_lines = ["# Attention Repair Findings", ""]
    if findings:
        for finding_id in sorted(
            findings,
            key=lambda value: int(value.split("-", 1)[1]),
        ):
            finding_lines.extend([findings[finding_id], ""])
    else:
        finding_lines.extend(
            ["No confirmed findings were produced by the repair shards.", ""]
        )
    return (
        ("\n".join(summary_lines) + "\n").encode("utf-8"),
        "\n".join(finding_lines).encode("utf-8"),
    )
