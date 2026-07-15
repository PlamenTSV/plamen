"""Deterministic coverage-shortfall receipts for bounded recall mechanisms.

The audit pipeline intentionally bounds several mechanical generators.  A bound
is operationally necessary, but an unreported bound hit is indistinguishable
from complete enumeration.  This module gives every producer one append-safe,
idempotent control-plane contract:

* structured truth in ``_coverage_shortfalls.json``;
* a deterministic projection in ``report_semantic_coverage_shortfalls.md``;
* producer-scoped replacement so resume does not preserve stale warnings; and
* explicit EXACT versus LOWER_BOUND count semantics.

It never creates findings or changes dispositions.  It only exposes work that
was not mechanically examined, for the existing Appendix-B human-review lane.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import threading
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Iterable

__all__ = [
    "CoverageShortfallError",
    "shortfall",
    "unknown_shortfall",
    "replace_producer_shortfalls",
    "coverage_shortfalls_projection",
]

_SCHEMA_VERSION = 1
_JSON_NAME = "_coverage_shortfalls.json"
_MARKDOWN_NAME = "report_semantic_coverage_shortfalls.md"
_SAMPLE_LIMIT = 5
_PROJECTION_ROW_LIMIT = 80
_PROCESS_LEDGER_LOCK = threading.RLock()


class CoverageShortfallError(ValueError):
    pass


def _clean(value: object) -> str:
    return re.sub(r"\s+", " ", str(value or "")).strip()


def _stable_id(producer: str, scope: str, cap: str, kind: str) -> str:
    raw = "\x1f".join((producer, scope, cap, kind)).encode("utf-8")
    return "CS-" + hashlib.sha256(raw).hexdigest()[:16].upper()


def shortfall(
    *,
    producer: str,
    scope: str,
    cap: str,
    limit: int,
    observed: int,
    retained: int,
    exact: bool,
    samples: Iterable[object] = (),
    detail: str = "bounded coverage was not fully enumerated",
    kind: str = "CAP_TRUNCATION",
) -> dict:
    """Build one normalized receipt row.

    ``observed`` is either the exact candidate population or the minimum known
    population.  For LOWER_BOUND rows, ``omitted`` is therefore also a minimum.
    Callers must not label a stopped-at-first-overflow scan as exact.
    """
    producer = _clean(producer)
    scope = _clean(scope)
    cap = _clean(cap)
    kind = _clean(kind).upper() or "CAP_TRUNCATION"
    if not producer or not scope or not cap:
        raise ValueError("producer, scope, and cap are required")
    limit = int(limit)
    observed = int(observed)
    retained = int(retained)
    if min(limit, observed, retained) < 0:
        raise CoverageShortfallError("coverage counts must be non-negative")
    if retained > observed:
        raise CoverageShortfallError("retained coverage cannot exceed observed coverage")
    if retained > limit:
        raise CoverageShortfallError("retained coverage cannot exceed the declared limit")
    omitted = max(0, observed - retained)
    normalized_samples = sorted({_clean(v) for v in samples if _clean(v)})[:_SAMPLE_LIMIT]
    return {
        "receipt_id": _stable_id(producer, scope, cap, kind),
        "producer": producer,
        "scope": scope,
        "kind": kind,
        "cap": cap,
        "limit": limit,
        "observed": observed,
        "retained": retained,
        "omitted": omitted,
        "count_semantics": "EXACT" if exact else "LOWER_BOUND",
        "samples": normalized_samples,
        "detail": _clean(detail),
        "disposition": "FLAGGED_FOR_HUMAN_REVIEW",
    }


def unknown_shortfall(
    *, producer: str, scope: str, kind: str, detail: str, samples: Iterable[object] = ()
) -> dict:
    """Build a loud receipt when coverage state cannot be measured.

    UNKNOWN is deliberately distinct from a clean zero and from a numerical
    lower bound. It is used for missing prerequisites and failed providers.
    """
    row = shortfall(
        producer=producer,
        scope=scope,
        cap="COVERAGE_STATE",
        limit=0,
        observed=0,
        retained=0,
        exact=True,
        samples=samples,
        detail=detail,
        kind=kind,
    )
    row["count_semantics"] = "UNKNOWN"
    return row


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict:
    out: dict = {}
    for key, value in pairs:
        if key in out:
            raise CoverageShortfallError(f"duplicate JSON key: {key}")
        out[key] = value
    return out


def _validate_row(row: dict) -> dict:
    required = {
        "receipt_id", "producer", "scope", "kind", "cap", "limit",
        "observed", "retained", "omitted", "count_semantics", "samples",
        "detail", "disposition",
    }
    if set(row) != required:
        raise CoverageShortfallError(
            f"coverage row has missing/unknown keys: {sorted(set(row) ^ required)}"
        )
    for key in ("receipt_id", "producer", "scope", "kind", "cap", "detail"):
        if not isinstance(row[key], str) or not row[key].strip():
            raise CoverageShortfallError(f"coverage row {key} must be a non-empty string")
    if row["count_semantics"] not in {"EXACT", "LOWER_BOUND", "UNKNOWN"}:
        raise CoverageShortfallError("invalid coverage count semantics")
    if row["disposition"] != "FLAGGED_FOR_HUMAN_REVIEW":
        raise CoverageShortfallError("invalid coverage disposition")
    for key in ("limit", "observed", "retained", "omitted"):
        if type(row[key]) is not int or row[key] < 0:
            raise CoverageShortfallError(f"coverage row {key} must be a non-negative integer")
    if not isinstance(row["samples"], list) or any(
        not isinstance(value, str) for value in row["samples"]
    ):
        raise CoverageShortfallError("coverage samples must be strings")
    if row["retained"] > row["observed"]:
        raise CoverageShortfallError("coverage retained count exceeds observed count")
    if row["retained"] > row["limit"]:
        raise CoverageShortfallError("coverage retained count exceeds declared limit")
    if row["count_semantics"] == "UNKNOWN" and any(
        row[key] != 0 for key in ("limit", "observed", "retained", "omitted")
    ):
        raise CoverageShortfallError("UNKNOWN coverage rows must have zero numeric counts")
    if row["count_semantics"] != "UNKNOWN" and row["omitted"] != (
        row["observed"] - row["retained"]
    ):
        raise CoverageShortfallError("coverage omitted count is inconsistent")
    expected_receipt_id = _stable_id(
        _clean(row["producer"]), _clean(row["scope"]),
        _clean(row["cap"]), _clean(row["kind"]),
    )
    if row["receipt_id"] != expected_receipt_id:
        raise CoverageShortfallError("coverage receipt ID does not match its identity fields")
    return row


def _read_rows(path: Path) -> list[dict]:
    if not path.exists():
        return []
    try:
        payload = json.loads(
            path.read_text(encoding="utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=lambda value: (_ for _ in ()).throw(
                CoverageShortfallError(f"non-finite JSON number: {value}")
            ),
        )
    except CoverageShortfallError:
        raise
    except Exception as exc:
        raise CoverageShortfallError(f"invalid coverage-shortfall JSON: {exc}") from exc
    if not isinstance(payload, dict) or payload.get("schema_version") != _SCHEMA_VERSION:
        raise CoverageShortfallError("unknown coverage-shortfall schema")
    if set(payload) != {"schema_version", "shortfalls"}:
        raise CoverageShortfallError("coverage-shortfall payload has unknown fields")
    rows = payload.get("shortfalls")
    if not isinstance(rows, list):
        raise CoverageShortfallError("coverage-shortfall rows must be an array")
    if any(not isinstance(row, dict) for row in rows):
        raise CoverageShortfallError("every coverage-shortfall row must be an object")
    return [_validate_row(row) for row in rows]


def _write_atomic(path: Path, text: str) -> None:
    """Replace one projection with a collision-free temporary file."""
    tmp = path.with_name(
        f".{path.name}.{os.getpid()}.{threading.get_ident()}.{uuid.uuid4().hex}.tmp"
    )
    try:
        tmp.write_text(text, encoding="utf-8")
        tmp.replace(path)
    finally:
        try:
            tmp.unlink(missing_ok=True)
        except Exception:
            pass


@contextmanager
def _ledger_lock(scratchpad: Path):
    """Serialize the producer-scoped read/merge/write transaction.

    The driver normally enforces one process per scratchpad, but this module is
    also used by focused replays and may later be called by parallel mechanical
    providers. A process-local lock protects threads; the advisory file lock
    protects independent processes on both supported OS families.
    """
    scratchpad = Path(scratchpad)
    scratchpad.mkdir(parents=True, exist_ok=True)
    lock_path = scratchpad / ".coverage_shortfalls.lock"
    with _PROCESS_LEDGER_LOCK:
        with lock_path.open("a+b") as handle:
            if os.name == "nt":
                import msvcrt

                handle.seek(0, os.SEEK_END)
                if handle.tell() == 0:
                    handle.write(b"0")
                    handle.flush()
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_LOCK, 1)
                try:
                    yield
                finally:
                    handle.seek(0)
                    msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
                try:
                    yield
                finally:
                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def _aggregate_projection_group(
    key: tuple[str, str, str, str], members: list[dict]
) -> dict:
    """Collapse repetitive rows without changing the structured JSON truth."""
    producer, cap, kind, semantics = key
    base = dict(members[0])
    scopes = sorted({_clean(row.get("scope")) for row in members if _clean(row.get("scope"))})
    base["scope"] = f"aggregate:{producer}:{cap}; affected_scopes:{len(scopes)}"
    base["receipt_id"] = _stable_id(producer, base["scope"], cap, kind)
    if semantics == "UNKNOWN":
        base["observed"] = base["retained"] = base["omitted"] = 0
    else:
        base["limit"] = sum(int(row.get("limit", 0)) for row in members)
        base["observed"] = sum(int(row.get("observed", 0)) for row in members)
        base["retained"] = sum(int(row.get("retained", 0)) for row in members)
        base["omitted"] = sum(int(row.get("omitted", 0)) for row in members)
    base["samples"] = scopes[:_SAMPLE_LIMIT]
    base["detail"] = (
        f"{base['detail']}; projection aggregates {len(scopes)} scopes; "
        "the structured coverage ledger retains every source row"
    )
    return base


def _projection_rows(rows: list[dict]) -> list[dict]:
    """Aggregate duplicate high-fan-in debt for the human projection only.

    JSON retains finding-level provenance. A common accounting symbol can be
    touched by many findings, so rendering one row per finding would bury more
    useful shortfalls in repetitive Appendix-B noise.
    """
    ordinary: list[dict] = []
    grouped: dict[tuple[str, str, str], list[tuple[dict, str]]] = {}
    scope_re = re.compile(r"^finding:([^:]+):symbol:([^:]+)$")
    for row in rows:
        match = scope_re.fullmatch(str(row.get("scope", "")))
        if row.get("kind") != "HIGH_FAN_IN_UNENUMERATED" or not match:
            ordinary.append(row)
            continue
        key = (str(row["producer"]), str(row["cap"]), match.group(2))
        grouped.setdefault(key, []).append((row, match.group(1)))
    for (producer, cap, symbol), members in grouped.items():
        base = dict(members[0][0])
        findings = sorted({finding for _row, finding in members})
        base["scope"] = f"symbol:{symbol}; affected_findings:{len(findings)}"
        base["receipt_id"] = _stable_id(
            producer, base["scope"], cap, str(base["kind"])
        )
        base["observed"] = max(int(row["observed"]) for row, _finding in members)
        base["retained"] = 0
        base["omitted"] = base["observed"]
        samples = {
            sample for row, _finding in members for sample in row.get("samples", [])
        }
        base["samples"] = sorted(samples)[:_SAMPLE_LIMIT]
        base["detail"] = (
            f"{base['detail']}; affected findings: "
            + ", ".join(findings[:_SAMPLE_LIMIT])
            + (" …" if len(findings) > _SAMPLE_LIMIT else "")
        )
        ordinary.append(base)
    projected = sorted(
        ordinary,
        key=lambda row: (
            0 if _clean(row.get("count_semantics")) == "UNKNOWN" else 1,
            _clean(row.get("producer")), _clean(row.get("scope")),
            _clean(row.get("cap")), _clean(row.get("receipt_id")),
        ),
    )
    if len(projected) <= _PROJECTION_ROW_LIMIT:
        return projected

    grouped_rows: dict[tuple[str, str, str, str], list[dict]] = {}
    for row in projected:
        key = (
            _clean(row.get("producer")),
            _clean(row.get("cap")),
            _clean(row.get("kind")),
            _clean(row.get("count_semantics")),
        )
        grouped_rows.setdefault(key, []).append(row)
    aggregated = sorted(
        (_aggregate_projection_group(key, members) for key, members in grouped_rows.items()),
        key=lambda row: (
            0 if _clean(row.get("count_semantics")) == "UNKNOWN" else 1,
            _clean(row.get("producer")), _clean(row.get("cap")),
            _clean(row.get("kind")), _clean(row.get("receipt_id")),
        ),
    )
    if len(aggregated) <= _PROJECTION_ROW_LIMIT:
        return aggregated

    omitted_groups = aggregated[_PROJECTION_ROW_LIMIT - 1:]
    summary = unknown_shortfall(
        producer="coverage_shortfalls",
        scope="human-projection",
        kind="PROJECTION_BOUNDED",
        detail=(
            f"{len(omitted_groups)} additional aggregate groups are present in "
            "the structured coverage ledger but omitted from this bounded projection"
        ),
        samples=[
            f"{row.get('producer', '')}:{row.get('cap', '')}:{row.get('kind', '')}"
            for row in omitted_groups
        ],
    )
    return aggregated[:_PROJECTION_ROW_LIMIT - 1] + [summary]


def _markdown(rows: list[dict]) -> str:
    lines = [
        "# Coverage Shortfalls",
        "",
        "Deterministic `COVERAGE-SHORTFALL` receipts from bounded mechanical "
        "analysis. These rows do not assert vulnerabilities. They identify "
        "coverage that was not enumerated and therefore requires human review "
        "or a higher-budget rerun.",
        "",
        "| Receipt | Producer | Scope | Kind | Cap | Count | Samples | Detail |",
        "|---------|----------|-------|------|-----|-------|---------|--------|",
    ]
    for row in _projection_rows(rows):
        def cell(key: str) -> str:
            return _clean(row.get(key, "")).replace("|", "/")

        semantics = cell("count_semantics")
        if semantics == "UNKNOWN":
            count = "coverage count unavailable"
        else:
            qualifier = "" if semantics == "EXACT" else ">="
            count = (
                f"observed {qualifier}{int(row.get('observed', 0))}; "
                f"retained {int(row.get('retained', 0))}; "
                f"omitted {qualifier}{int(row.get('omitted', 0))}"
            )
        samples = ", ".join(f"`{_clean(v).replace('|', '/')}`" for v in row.get("samples", [])) or "-"
        lines.append(
            f"| {cell('receipt_id')} | {cell('producer')} | {cell('scope')} | "
            f"{cell('kind')} | {cell('cap')}={int(row.get('limit', 0))} | "
            f"{count} ({semantics}) | {samples} | {cell('detail')} |"
        )
    return "\n".join(lines) + "\n"


def _coverage_shortfalls_projection_unlocked(scratchpad: Path) -> str:
    scratchpad = Path(scratchpad)
    json_path = scratchpad / _JSON_NAME
    md_path = scratchpad / _MARKDOWN_NAME
    if not json_path.exists():
        try:
            md_path.unlink(missing_ok=True)
        except Exception:
            pass
        return ""
    try:
        rows = _read_rows(json_path)
        text = _markdown(rows)
    except Exception as exc:
        message = _clean(exc).replace("|", "/")
        text = (
            "# Coverage Shortfalls\n\n"
            "`COVERAGE-SHORTFALL` control-plane corruption: the structured "
            "coverage ledger could not be validated. Treat bounded mechanical "
            "coverage as UNKNOWN and inspect `_coverage_shortfalls.json`.\n\n"
            "| Receipt | Producer | Scope | Kind | Cap | Count | Samples | Detail |\n"
            "|---------|----------|-------|------|-----|-------|---------|--------|\n"
            f"| CS-CONTROL-PLANE | coverage_shortfalls | ledger | "
            f"CONTROL_PLANE_CORRUPTION | - | coverage count unavailable "
            f"(UNKNOWN) | - | {message} |\n"
        )
    try:
        _write_atomic(md_path, text)
    except Exception:
        pass
    return text


def coverage_shortfalls_projection(scratchpad: Path) -> str:
    """Render the JSON source of truth and best-effort refresh its sidecar.

    The report assembler calls this directly and consumes the returned text, so
    a failed Markdown write cannot hide a valid JSON receipt. Corrupt JSON is
    converted to an in-memory control-plane warning rather than being treated
    as an empty/clean ledger.
    """
    with _ledger_lock(Path(scratchpad)):
        return _coverage_shortfalls_projection_unlocked(Path(scratchpad))


def replace_producer_shortfalls(
    scratchpad: Path, producer: str, rows: Iterable[dict]
) -> None:
    """Replace one producer's rows and regenerate both receipt projections.

    This is intentionally replacement, not blind append: a resumed run whose
    source population no longer exceeds a cap must clear its stale warning.
    Other producers are preserved.  Identical input is byte-idempotent.
    """
    scratchpad = Path(scratchpad)
    producer = _clean(producer)
    if not producer:
        raise ValueError("producer is required")
    with _ledger_lock(scratchpad):
        json_path = scratchpad / _JSON_NAME
        md_path = scratchpad / _MARKDOWN_NAME
        existing = [
            row for row in _read_rows(json_path)
            if _clean(row.get("producer")) != producer
        ]
        incoming = []
        for row in rows:
            if not isinstance(row, dict):
                raise CoverageShortfallError("coverage replacement rows must be objects")
            normalized = _validate_row(dict(row))
            if _clean(normalized.get("producer")) != producer:
                raise CoverageShortfallError(
                    "coverage row producer does not match replacement producer"
                )
            incoming.append(normalized)
        merged_by_id = {
            _clean(row.get("receipt_id")): row
            for row in existing + incoming
            if _clean(row.get("receipt_id"))
        }
        merged = sorted(
            merged_by_id.values(),
            key=lambda row: (
                _clean(row.get("producer")),
                _clean(row.get("scope")),
                _clean(row.get("cap")),
                _clean(row.get("receipt_id")),
            ),
        )
        if not merged:
            # A clean producer on a fresh scratchpad should create no ceremonial
            # artifact. If this call resolves the final stale row, remove both.
            json_path.unlink(missing_ok=True)
            try:
                md_path.unlink(missing_ok=True)
            except Exception:
                pass
            return
        payload = {"schema_version": _SCHEMA_VERSION, "shortfalls": merged}
        _write_atomic(json_path, json.dumps(payload, indent=2, sort_keys=True) + "\n")
        # Markdown is a cache/projection only. Report assembly always regenerates
        # it from JSON and consumes the returned text directly.
        _coverage_shortfalls_projection_unlocked(scratchpad)
