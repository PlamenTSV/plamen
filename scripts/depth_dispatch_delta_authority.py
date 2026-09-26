"""Immutable additive dispatch authority for post-consensus Depth workers."""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any, Mapping, Sequence


SCHEMA = "plamen.depth-dispatch-delta.v1"
_SHA256 = re.compile(r"[0-9a-f]{64}")
_NAME = re.compile(r"depth_dispatch_da_iter2_attempt_([0-9]{4})\.json")


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def delta_name(attempt: int) -> str:
    ordinal = int(attempt)
    if ordinal < 1 or ordinal > 9999:
        raise ValueError("depth dispatch delta attempt is out of range")
    return f"depth_dispatch_da_iter2_attempt_{ordinal:04d}.json"


def build_delta(
    *,
    attempt: int,
    base_dispatch: bytes,
    base_pool_contract: bytes,
    entries: Sequence[Mapping[str, Any]],
    jobs: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    ordinal = int(attempt)
    normalized_entries = [dict(row) for row in entries]
    normalized_jobs = [dict(row) for row in jobs]
    payload: dict[str, Any] = {
        "schema_version": SCHEMA,
        "phase": "depth",
        "kind": "DA_ITER2",
        "attempt": ordinal,
        "base_dispatch_sha256": hashlib.sha256(base_dispatch).hexdigest(),
        "base_pool_contract_sha256": hashlib.sha256(
            base_pool_contract
        ).hexdigest(),
        "entries": normalized_entries,
        "jobs": normalized_jobs,
    }
    payload["payload_digest"] = _digest(payload)
    issues = validate_delta(payload, expected_attempt=ordinal)
    if issues:
        raise ValueError("; ".join(issues))
    return payload


def validate_delta(
    payload: Mapping[str, Any], *, expected_attempt: int | None = None,
) -> list[str]:
    issues: list[str] = []
    expected_keys = {
        "schema_version", "phase", "kind", "attempt",
        "base_dispatch_sha256", "base_pool_contract_sha256",
        "entries", "jobs", "payload_digest",
    }
    if set(payload) != expected_keys:
        return ["depth dispatch delta field set differs"]
    attempt = payload.get("attempt")
    if (
        payload.get("schema_version") != SCHEMA
        or payload.get("phase") != "depth"
        or payload.get("kind") != "DA_ITER2"
        or not isinstance(attempt, int)
        or isinstance(attempt, bool)
        or attempt < 1
        or attempt > 9999
        or (expected_attempt is not None and attempt != int(expected_attempt))
    ):
        issues.append("depth dispatch delta identity is invalid")
    for field in (
        "base_dispatch_sha256", "base_pool_contract_sha256", "payload_digest"
    ):
        if _SHA256.fullmatch(str(payload.get(field) or "")) is None:
            issues.append(f"depth dispatch delta {field} is invalid")
    entries = payload.get("entries")
    jobs = payload.get("jobs")
    if not isinstance(entries, list) or not entries:
        issues.append("depth dispatch delta entries are absent")
        entries = []
    if not isinstance(jobs, list) or not jobs:
        issues.append("depth dispatch delta jobs are absent")
        jobs = []
    entry_outputs: list[str] = []
    for row in entries:
        if not isinstance(row, Mapping):
            issues.append("depth dispatch delta entry is not an object")
            continue
        output = str(row.get("output") or "")
        if (
            not output
            or str(row.get("worker_id") or "") != "depth-da-iter2"
            or _SHA256.fullmatch(str(row.get("prompt_sha256") or "")) is None
            or _SHA256.fullmatch(
                str(row.get("dispatch_contract_sha256") or "")
            ) is None
        ):
            issues.append("depth dispatch delta entry is malformed")
        entry_outputs.append(output)
    job_outputs: list[str] = []
    for row in jobs:
        if not isinstance(row, Mapping):
            issues.append("depth dispatch delta job is not an object")
            continue
        output = str(row.get("output") or "")
        if (
            not output
            or str(row.get("agent_id") or "") != "depth-da-iter2"
            or str(row.get("role") or "") != "da_iter2"
            or str(row.get("category") or "") != "da"
            or _SHA256.fullmatch(str(row.get("prompt_sha256") or "")) is None
        ):
            issues.append("depth dispatch delta job is malformed")
        job_outputs.append(output)
    if (
        len(entry_outputs) != len(set(entry_outputs))
        or len(job_outputs) != len(set(job_outputs))
        or set(entry_outputs) != set(job_outputs)
    ):
        issues.append("depth dispatch delta output denominator differs")
    unsigned = dict(payload)
    stored = unsigned.pop("payload_digest", None)
    if stored != _digest(unsigned):
        issues.append("depth dispatch delta payload digest mismatch")
    return list(dict.fromkeys(issues))


def load_deltas(scratchpad: Path) -> tuple[list[dict[str, Any]], list[str]]:
    rows: list[dict[str, Any]] = []
    issues: list[str] = []
    root = Path(scratchpad)
    for path in sorted(root.glob("depth_dispatch_da_iter2_attempt_*.json")):
        match = _NAME.fullmatch(path.name)
        if match is None or path.is_symlink() or not path.is_file():
            issues.append(f"invalid depth dispatch delta path: {path.name}")
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8", errors="strict"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            issues.append(f"depth dispatch delta unreadable: {path.name}: {exc}")
            continue
        if not isinstance(payload, dict):
            issues.append(f"depth dispatch delta root is not an object: {path.name}")
            continue
        row_issues = validate_delta(
            payload, expected_attempt=int(match.group(1))
        )
        if row_issues:
            issues.extend(f"{path.name}: {issue}" for issue in row_issues)
            continue
        rows.append({**payload, "path": path.name})
    return rows, issues


__all__ = ["SCHEMA", "build_delta", "delta_name", "load_deltas", "validate_delta"]
