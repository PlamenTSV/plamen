"""Independent semantic validation for the canonical report-index bundle.

The canonical report transaction is a deterministic writer.  It must not also
be the sole authority deciding whether its own transforms succeeded.  This
module therefore contains read-only reconciliation gates that run after staged
derivation, after publication, and on committed replay.

The validator deliberately does not repair files.  A failed repair remains
visible as transaction debt and prevents a clean canonical receipt.
"""
from __future__ import annotations

import json
from pathlib import Path
import re
from typing import Any, Iterable, Mapping, Sequence


_REPORT_ID_RE = re.compile(r"^[CHMLI]-\d+$", re.IGNORECASE)
_SEVERITY_REPAIR_FAILURE_TOKENS = (
    "could not",
    "cannot",
    "failed",
    "failure",
    "skipped",
    "write error",
    "unavailable",
)
_SEVERITY_NAMES = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "informational": "Informational",
    "info": "Informational",
}
_EMPTY_QUEUE_HEADINGS = {
    "# verification queue",
    "# verification queue manifest",
}


def _normal_id(value: object) -> str:
    text = str(value or "").strip().strip("`[]() ").upper()
    return re.sub(r"-0+(\d)", r"-\1", text)


def _normal_severity(value: object, *, report_id: str = "") -> str:
    text = re.sub(r"[*_`\[\]()]+", "", str(value or "")).strip()
    match = re.search(
        r"\b(Critical|High|Medium|Low|Informational|Info)\b",
        text,
        re.IGNORECASE,
    )
    if match:
        return _SEVERITY_NAMES[match.group(1).casefold()]
    return {
        "C": "Critical",
        "H": "High",
        "M": "Medium",
        "L": "Low",
        "I": "Informational",
    }.get(str(report_id or "")[:1].upper(), "")


def _canonical_internal_ids(value: str) -> tuple[list[str], bool]:
    """Return context-free canonical IDs and whether the whole cell is valid.

    Master-table identity cells are structured data, not prose.  A broad
    ``TOKEN-TOKEN`` search accepts ordinary words as finding identities and
    can collapse a non-empty report denominator to zero.  Reuse the pipeline's
    closed context-free registry grammar, then require all remaining bytes to
    be only bounded list punctuation.
    """

    from plamen_parsers import _INTERNAL_FINDING_ID_RE

    text = re.sub(r"[*_`\[\]()]+", "", str(value or "")).strip()
    matches = [
        _normal_id(match.group(1))
        for match in _INTERNAL_FINDING_ID_RE.finditer(text)
    ]
    residue = _INTERNAL_FINDING_ID_RE.sub("", text)
    residue = re.sub(r"\s*(?:[,;+]|/|\band\b)\s*", "", residue, flags=re.I)
    return sorted(dict.fromkeys(matches)), bool(matches and not residue.strip())


def _is_exact_empty_queue_markdown(text: str) -> bool:
    """Recognize only the two deterministic zero-row queue projections."""

    normalized = str(text or "").replace("\r\n", "\n").replace("\r", "\n")
    meaningful = [line.strip() for line in normalized.splitlines() if line.strip()]
    if meaningful == ["# Verification Queue"]:
        return True
    if not meaningful or meaningful[0].casefold() not in _EMPTY_QUEUE_HEADINGS:
        return False
    if meaningful[0].casefold() != "# verification queue manifest":
        return False
    if len(meaningful) != 4:
        return False
    header = [cell.strip().casefold() for cell in meaningful[1].strip("|").split("|")]
    if "finding id" not in header or "queue #" not in header:
        return False
    if not re.fullmatch(
        r"\|?\s*:?-{3,}:?\s*(?:\|\s*:?-{3,}:?\s*)+\|?",
        meaningful[2],
    ):
        return False
    return bool(re.fullmatch(
        r"Total:\s*0\s+findings\s*\|\s*"
        r"Expected\s+verify_<ID>\.md\s+files:\s*0",
        meaningful[3],
        re.IGNORECASE,
    ))


def validate_report_candidate_denominator(
    root: Path,
) -> tuple[int | None, list[str]]:
    """Validate and count the exact base verification denominator.

    A typed record set is preferred.  Transitional legacy input remains
    readable, but zero is accepted only through an exact deterministic empty
    projection.  Therefore a parser miss cannot silently mean "no findings".
    """

    scratchpad = Path(root)
    queue_path = scratchpad / "verification_queue.md"
    typed_path = scratchpad / "verification_queue.work_items.json"
    try:
        queue_text = queue_path.read_text(encoding="utf-8", errors="strict")
    except (OSError, UnicodeError) as exc:
        return None, [
            "canonical verification queue denominator is unavailable: "
            f"{type(exc).__name__}: {exc}"
        ]

    if typed_path.is_file():
        try:
            from queue_work_items import (
                QUEUE_RECORD_SET_SCHEMA_VERSION,
                queue_records_from_json,
                queue_records_to_json,
            )

            typed_text = typed_path.read_text(encoding="utf-8", errors="strict")
            payload = _strict_json_object(
                typed_path, "canonical typed verification queue"
            )
            if payload.get("schema_version") != QUEUE_RECORD_SET_SCHEMA_VERSION:
                return None, [
                    "canonical typed verification queue uses a non-current schema"
                ]
            items = queue_records_from_json(typed_text)
            if typed_text.replace("\r\n", "\n") != queue_records_to_json(items) + "\n":
                return None, [
                    "canonical typed verification queue bytes are non-canonical"
                ]
        except (OSError, UnicodeError, ValueError, TypeError) as exc:
            return None, [
                "canonical typed verification queue is malformed: "
                f"{type(exc).__name__}: {exc}"
            ]
        if not items and not _is_exact_empty_queue_markdown(queue_text):
            return None, [
                "typed empty verification queue disagrees with its Markdown "
                "projection; nonempty or malformed bytes cannot mean empty"
            ]
        return len(items), []

    # Transitional legacy report-index fixtures/runs have no typed sidecar.
    # Parse non-empty input through the established queue parser, but never
    # infer an empty denominator from a generic parser miss.
    try:
        from plamen_parsers import parse_verification_queue_rows

        rows = parse_verification_queue_rows(scratchpad)
    except Exception as exc:
        return None, [
            "legacy verification queue denominator could not be parsed: "
            f"{type(exc).__name__}: {exc}"
        ]
    if rows:
        return len(rows), []
    if _is_exact_empty_queue_markdown(queue_text):
        return 0, []
    return None, [
        "nonempty or malformed verification queue has no canonical candidate "
        "denominator"
    ]


def _strict_json_object(path: Path, label: str) -> Mapping[str, Any]:
    raw = path.read_bytes()

    def pairs(rows: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in rows:
            if key in result:
                raise ValueError(f"{label} contains duplicate key {key!r}")
            result[key] = value
        return result

    value = json.loads(
        raw.decode("utf-8", errors="strict"),
        object_pairs_hook=pairs,
        parse_constant=lambda token: (_ for _ in ()).throw(
            ValueError(f"{label} contains non-finite number {token}")
        ),
    )
    if not isinstance(value, Mapping):
        raise ValueError(f"{label} must contain a JSON object")
    return value


def _markdown_master_rows(text: str) -> tuple[list[dict[str, Any]], list[str]]:
    """Parse the singular Master Finding Index without mutating its bytes."""

    lines = text.splitlines()
    issues: list[str] = []
    heading = next(
        (
            index
            for index, line in enumerate(lines)
            if re.match(
                r"^##\s+Master\s+Finding\s+Index\b",
                line.strip(),
                re.IGNORECASE,
            )
        ),
        -1,
    )
    if heading < 0:
        return [], ["canonical report index has no Master Finding Index"]
    end = next(
        (
            index
            for index in range(heading + 1, len(lines))
            if re.match(r"^##\s+", lines[index].strip())
        ),
        len(lines),
    )
    header_at = -1
    headers: list[str] = []
    for index in range(heading + 1, end):
        line = lines[index].strip()
        if not line.startswith("|"):
            continue
        candidate = [
            re.sub(r"\s+", " ", cell.strip().lower())
            for cell in line.strip("|").split("|")
        ]
        if "report id" in candidate:
            header_at = index
            headers = candidate
            break
    if header_at < 0:
        return [], ["canonical report index Master table has no header"]
    report_columns = [
        index for index, name in enumerate(headers) if name == "report id"
    ]
    internal_columns = [
        index
        for index, name in enumerate(headers)
        if name
        in {
            "internal hypothesis",
            "internal hypothesis id",
            "internal hypothesis ids",
            "finding id",
            "internal id",
            "hypothesis",
        }
    ]
    severity_columns = [
        index for index, name in enumerate(headers) if name == "severity"
    ]
    if len(report_columns) != 1:
        issues.append(
            "canonical report index Master table report-id column is not singular"
        )
    if len(internal_columns) != 1:
        issues.append(
            "canonical report index Master table internal-id column is not singular"
        )
    if len(severity_columns) != 1:
        issues.append(
            "canonical report index Master table severity column is not singular"
        )
    if issues:
        return [], issues
    report_column = report_columns[0]
    internal_column = internal_columns[0]
    severity_column = severity_columns[0]
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index in range(header_at + 2, end):
        line = lines[index].strip()
        if not line.startswith("|"):
            break
        cells = [cell.strip() for cell in line.strip("|").split("|")]
        if report_column >= len(cells):
            continue
        report_id = cells[report_column].upper()
        if not _REPORT_ID_RE.fullmatch(report_id):
            continue
        if report_id in seen:
            issues.append(
                f"canonical report index duplicates report identity {report_id}"
            )
        seen.add(report_id)
        internal = (
            cells[internal_column] if internal_column < len(cells) else ""
        )
        finding_ids, identity_valid = _canonical_internal_ids(internal)
        if not identity_valid:
            issues.append(
                "canonical report index Master row "
                f"{report_id} has no singular canonical internal finding "
                "identity list"
            )
        severity = _normal_severity(
            cells[severity_column] if severity_column < len(cells) else "",
        )
        if not severity:
            issues.append(
                f"canonical report index Master row {report_id} has invalid severity"
            )
        rows.append(
            {
                "report_id": report_id,
                "finding_ids": finding_ids,
                "severity": severity,
            }
        )
    return rows, issues


def _record_rows(
    payload: Mapping[str, Any],
    *,
    key: str,
) -> tuple[list[dict[str, str]], list[str]]:
    raw_rows = payload.get(key)
    if not isinstance(raw_rows, list):
        return [], [f"report_records.json {key!r} denominator is not a list"]
    rows: list[dict[str, str]] = []
    issues: list[str] = []
    for ordinal, raw in enumerate(raw_rows):
        if not isinstance(raw, Mapping):
            issues.append(
                f"report_records.json {key}[{ordinal}] is not an object"
            )
            continue
        report_id = str(raw.get("report_id") or "").strip().upper()
        finding_id = _normal_id(raw.get("finding_id"))
        canonical_ids, identity_valid = _canonical_internal_ids(finding_id)
        severity = _normal_severity(raw.get("severity"))
        if not _REPORT_ID_RE.fullmatch(report_id):
            issues.append(
                f"report_records.json {key}[{ordinal}] has invalid report_id"
            )
            continue
        if not finding_id or not identity_valid or canonical_ids != [finding_id]:
            issues.append(
                f"report_records.json {key}[{ordinal}] has no canonical finding_id"
            )
            continue
        if not severity:
            issues.append(
                f"report_records.json {key}[{ordinal}] has invalid severity"
            )
            continue
        rows.append(
            {
                "report_id": report_id,
                "finding_id": finding_id,
                "severity": severity,
            }
        )
    return rows, issues


def validate_l1_report_records_denominator(root: Path) -> list[str]:
    """Require exact L1 active-record parity with the canonical Master table."""

    scratchpad = Path(root)
    index_path = scratchpad / "report_index.md"
    records_path = scratchpad / "report_records.json"
    if not index_path.is_file():
        return ["L1 canonical report-record parity has no report_index.md"]
    if not records_path.is_file():
        return ["L1 canonical report-record parity has no report_records.json"]
    try:
        text = index_path.read_text(encoding="utf-8", errors="strict")
        master, issues = _markdown_master_rows(text)
        payload = _strict_json_object(
            records_path, "L1 canonical report records"
        )
        active, record_issues = _record_rows(payload, key="active")
        issues.extend(record_issues)
    except (OSError, UnicodeError, ValueError, TypeError) as exc:
        return [
            "L1 canonical report-record parity could not read its exact "
            f"denominator: {type(exc).__name__}: {exc}"
        ]

    expected_pairs = {
        (row["report_id"], finding_id, row["severity"])
        for row in master
        for finding_id in row["finding_ids"]
    }
    actual_pairs = {
        (row["report_id"], row["finding_id"], row["severity"])
        for row in active
    }
    if expected_pairs != actual_pairs:
        missing = sorted(expected_pairs - actual_pairs)
        extra = sorted(actual_pairs - expected_pairs)
        issues.append(
            "L1 report_records active denominator differs from the canonical "
            f"Master table (missing={missing[:6]}, extra={extra[:6]})"
        )
        if {
            (report_id, finding_id)
            for report_id, finding_id, _severity in expected_pairs
        } == {
            (report_id, finding_id)
            for report_id, finding_id, _severity in actual_pairs
        }:
            issues.append(
                "L1 report_records severity disagrees with the canonical Master table"
            )
    if len(active) != len(actual_pairs):
        issues.append("L1 report_records contains duplicate active identities")
    return list(dict.fromkeys(issues))


def _severity_repair_issues(
    repairs: Iterable[Mapping[str, Any]],
) -> list[str]:
    issues: list[str] = []
    for row in repairs:
        action = str(row.get("action") or "").strip()
        report_id = str(row.get("report_id") or "").strip()
        if (
            report_id == "*"
            or not action
            or any(
                token in action.casefold()
                for token in _SEVERITY_REPAIR_FAILURE_TOKENS
            )
        ):
            issues.append(
                "canonical severity repair did not apply cleanly for "
                f"{report_id or '(unknown)'}: {action or '(no action)'}"
            )
    return issues


def validate_report_index_canonical_bundle(
    scratchpad: Path,
    *,
    pipeline: str,
    run_id: str,
    transformation_issues: Sequence[str] = (),
    severity_repairs: Sequence[Mapping[str, Any]] = (),
    expected_severities: Mapping[str, str] | None = None,
) -> list[str]:
    """Read-only semantic gate for one fully derived canonical bundle.

    The function intentionally consumes the final bytes from ``scratchpad``.
    It does not trust the writer's transformation labels or receipt.
    """

    root = Path(scratchpad)
    issues = [
        f"canonical transform debt: {str(issue)}"
        for issue in transformation_issues
        if str(issue or "").strip()
    ]
    issues.extend(_severity_repair_issues(severity_repairs))
    candidate_count, denominator_issues = validate_report_candidate_denominator(
        root
    )
    issues.extend(denominator_issues)
    try:
        import plamen_validators as validators

        issues.extend(
            validators._validate_report_index_status_authority(root)
        )
        issues.extend(
            validators._report_index_status_projection_debt(root)
        )
        residual = validators._report_index_dropped_ids(
            root, run_id=run_id
        )
        if residual:
            issues.append(
                "canonical report index retains unaccounted candidate "
                f"identities: {', '.join(residual[:8])}"
            )
        # The repair writer may have returned an apparently successful row
        # while a second independent provenance pass still disagrees.  An
        # exact empty candidate denominator is a valid no-findings run; the
        # legacy prose validator treats an empty queue as malformed because it
        # was written for model admission, not deterministic empty projection.
        if candidate_count is not None and candidate_count > 0:
            issues.extend(validators._validate_report_index_inputs(
                root,
                expected_run_id=run_id,
                expected_severities=expected_severities,
            ))
    except Exception as exc:
        issues.append(
            "canonical semantic replay failed closed: "
            f"{type(exc).__name__}: {exc}"
        )
    if str(pipeline or "").strip().lower() == "l1":
        issues.extend(validate_l1_report_records_denominator(root))
    return list(dict.fromkeys(str(issue) for issue in issues if str(issue)))


__all__ = [
    "validate_l1_report_records_denominator",
    "validate_report_candidate_denominator",
    "validate_report_index_canonical_bundle",
]
