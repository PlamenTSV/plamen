"""P0-I exact hot-function-axis input-to-disposition reconciliation.

The model performs the analysis.  This module only enumerates, binds, diffs,
and routes the exact structured GAP denominator from
``_hot_function_axes.json``.  Raw matrix rows and fallback candidates never
prove methodology application.  A cell closes only through one current typed
disposition with mechanically resolvable evidence; everything else remains
content-bearing repair/report debt.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import uuid
from collections import Counter
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Mapping, Sequence

from coverage_shortfalls import (
    CoverageShortfallError,
    _validate_row as _validate_coverage_shortfall_row,
)
from evidence_capabilities import (
    EvidenceCapabilityError,
    validate_evidence_receipt,
)
from exploration_clear_lifecycle import resolve_clear_evidence
from operational_markdown import operational_markdown_view


WORKLIST_SCHEMA = "plamen.axis_disposition_worklist.v1"
RECEIPT_SCHEMA = "plamen.axis_disposition_receipt.v1"
REPAIR_SCHEMA = "plamen.axis_repair_work.v1"
ASSURANCE_DEBT_SCHEMA = "plamen.axis_assurance_debt.v1"
DEBT_ITEM_SCHEMA = "plamen.axis_assurance_debt_item.v1"

# P0-I schema-v2 authority.  The v1 names/functions below remain available only
# for legacy replay and migration fixtures; production integration must use the
# v2 entry points exported at the end of this module.
WORKLIST_V2_SCHEMA = "plamen.axis_disposition_worklist.v2"
POPULATION_AUTHORITY_SCHEMA = "plamen.axis_population.v2"
POPULATION_PROVIDER_VERSION = "enumeration.axis_population/2"
MODEL_DISPOSITIONS_SCHEMA = "plamen.axis_model_dispositions.v1"
REPAIR_MODEL_DISPOSITIONS_SCHEMA = (
    "plamen.axis_repair_model_dispositions.v1"
)
EXECUTION_EVIDENCE_AUTHORITY_SCHEMA = (
    "plamen.axis_execution_evidence_authority.v1"
)
INITIAL_RECEIPT_SCHEMA = "plamen.axis_disposition_initial_receipt.v1"
REPAIR_PLAN_SCHEMA = "plamen.axis_repair_plan.v1"
REPAIR_EXECUTION_RECEIPT_SCHEMA = (
    "plamen.axis_repair_execution_receipt.v1"
)
APPLICATION_RECEIPT_V2_SCHEMA = (
    "plamen.axis_disposition_application_receipt.v2"
)
REPAIR_WORK_V2_SCHEMA = "plamen.axis_repair_work.v2"
ASSURANCE_DEBT_V2_SCHEMA = "plamen.axis_assurance_debt.v2"
PROMOTION_RECEIPT_V2_SCHEMA = (
    "plamen.axis_coverage_promotion_receipt.v2"
)
PROMOTION_PLAN_SCHEMA = "plamen.axis_coverage_promotion_plan.v1"
LIMITATIONS_V2_SCHEMA = "plamen.axis_assurance_limitations.v2"

WORKLIST_NAME = "axis_disposition_worklist.json"
RECEIPT_NAME = "axis_disposition_receipt.json"
REPAIR_NAME = "axis_repair_work.json"
ASSURANCE_DEBT_NAME = "axis_assurance_debt.json"
LIMITATIONS_NAME = "axis_assurance_limitations.md"
OUTPUT_NAME = "axis_coverage_findings.md"
MATRIX_NAME = "_hot_function_axes.json"
HOT_CAP_NAME = "_hot_function_cap_receipt.json"
HOT_CAP_SCHEMA = "plamen.hot_function_cap_receipt.v1"

AXIS_EXECUTION_EVIDENCE_AUTHORITY_NAME = (
    "axis_execution_evidence_authority.json"
)
AXIS_MODEL_DISPOSITIONS_NAME = "axis_coverage_dispositions.json"
AXIS_INITIAL_RECEIPT_NAME = "axis_disposition_initial_receipt.json"
AXIS_REPAIR_PLAN_NAME = "axis_repair_plan.json"
AXIS_REPAIR_FINDINGS_NAME = "axis_coverage_repair_findings.md"
AXIS_REPAIR_MODEL_DISPOSITIONS_NAME = (
    "axis_coverage_repair_dispositions.json"
)
AXIS_REPAIR_EXECUTION_RECEIPT_NAME = (
    "axis_repair_execution_receipt.json"
)
AXIS_APPLICATION_RECEIPT_NAME = RECEIPT_NAME
AXIS_PROMOTION_PLAN_NAME = "axis_coverage_promotion_plan.json"
AXIS_PROMOTION_RECEIPT_NAME = "axis_coverage_promotion_receipt.json"

AXES = ("theft", "liveness", "accounting", "provenance", "boundary", "identity")
_AXIS_CI_ID_RE = re.compile(
    r"^(?:[A-Z][A-Z0-9]*-)*CI(?:-[A-Z0-9]+)+$", re.ASCII
)
_AXIS_CI_SHAPES = frozenset({
    "CONSERVATION",
    "REQUESTED_EQ_DELIVERED",
    "APPROVE_EQ_SPEND",
    "NO_REVERT_AT_BOUNDARY",
    "ROUNDTRIP",
    "FRESHNESS",
})
_AXIS_CI_FALSIFY_CLASSES = frozenset(
    {"property", "boundary", "roundtrip", "conservation"}
)
_CELL_STATES = frozenset({"GAP", "EXAMINED", "N/A"})
_HEX_RE = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
_HEADING_RE = re.compile(
    r"^(?P<marks>#{1,6})\s+(?P<title>.*?)\s*#*\s*$",
    re.MULTILINE,
)
_COVERAGE_HEADER = ("function", "axis", "disposition", "evidence")
_SEPARATOR_RE = re.compile(r"^:?-{3,}:?$")
_ACTION_HEADING_RE = re.compile(
    r"^(?P<marks>#{2,4})\s*Finding\s*\[\s*"
    r"(?P<id>AXIS-(?:[A-Za-z0-9]+-)*\d+)\s*\]\s*:\s*"
    r"(?P<title>.+?)\s*$",
    re.MULTILINE | re.IGNORECASE | re.ASCII,
)
_ACTION_ID_RE = re.compile(
    r"(?<![A-Za-z0-9_-])(AXIS-(?:[A-Za-z0-9]+-)*\d+)"
    r"(?![A-Za-z0-9_-])",
    re.IGNORECASE | re.ASCII,
)
_INVENTORY_HEADING_RE = re.compile(
    r"^#{2,4}\s*Finding\s*\[\s*"
    r"(?P<id>[A-Za-z][A-Za-z0-9_-]{1,95})\s*\]\s*:\s*.+?$",
    re.MULTILINE | re.ASCII,
)
_V2_AXISGAP_CLAIM_RE = re.compile(
    r"(?<![A-Za-z0-9_-])AXISGAP\s*:\s*"
    r"(?P<id>AXIS-(?:[A-Za-z0-9]+-)*\d+)"
    r"(?![A-Za-z0-9_-])",
    re.IGNORECASE | re.ASCII,
)
_FIELD_RE_TEMPLATE = (
    r"(?ims)^[ \t]*(?:[-*][ \t]+)?\*\*{name}\*\*[ \t]*:[ \t]*"
    r"(?P<value>.*?)(?=^[ \t]*(?:[-*][ \t]+)?\*\*[^*\n]+\*\*[ \t]*:"
    r"|^#{{2,6}}[ \t]+|\Z)"
)
_LOCUS_RE = re.compile(
    r"(?P<path>[A-Za-z0-9_./\\ -]+\.[A-Za-z0-9_]+)"
    r"\s*:\s*L?(?P<line>[1-9][0-9]*)",
    re.ASCII,
)
_EXTERNAL_CLEAR_RE = re.compile(
    r"\[\s*(?:UNPROVEN-EXTERNAL|EXTERNAL-ASSUMPTION\s*:|"
    r"CROSS-DOMAIN-DEP\s*:\s*external)"
    r"|\b(?:assuming|assume|provided\s+that)\b[^.\n]{0,100}\bexternal\b"
    r"|\bexternal\b[^.\n]{0,100}\b(?:assumed|trusted|favorable|correct)\b",
    re.IGNORECASE,
)


class AxisDispositionError(ValueError):
    """Typed axis work/disposition state failed exact validation."""


def _canonical(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _normalize_axis_invariant_commitment(
    value: Any,
    *,
    item: Mapping[str, Any],
    evidence: Any,
) -> dict[str, Any]:
    """Validate and normalize one model-authored axis CLEAR invariant.

    Axis gaps are never a non-value-bearing denominator: theft, liveness,
    accounting, provenance, boundary and identity can all close a material
    path.  A CLEAR therefore needs one source/evidence-bound committed
    invariant whose textual identity cannot be reused for another AXW row.
    """

    expected_fields = {
        "ci_id",
        "ci_block_sha256",
        "locus",
        "shape",
        "assertion",
        "falsify_class",
        "provenance",
        "source_hash",
        "evidence_sha256",
    }
    if not isinstance(value, Mapping) or set(value) != expected_fields:
        raise AxisDispositionError(
            "axis CLEAR invariant commitment shape mismatch"
        )
    work_item_id = str(item.get("work_item_id") or "")
    ci_id = _normal(value.get("ci_id")).upper()
    locus = _normal(value.get("locus"))
    shape = _normal(value.get("shape")).upper()
    assertion = _normal(value.get("assertion"))
    falsify_class = _normal(value.get("falsify_class")).lower()
    provenance = _normal(value.get("provenance"))
    source_hash = str(value.get("source_hash") or "")
    evidence_sha256 = str(value.get("evidence_sha256") or "")
    ci_block_sha256 = str(value.get("ci_block_sha256") or "")
    exact_locus = (
        f"{item.get('source_relpath')}:{item.get('source_locus')}"
    )
    block_unsigned = {
        "ci_id": ci_id,
        "locus": locus,
        "shape": shape,
        "assertion": assertion,
        "falsify_class": falsify_class,
        "provenance": provenance,
        "source_hash": source_hash,
        "evidence_sha256": evidence_sha256,
    }
    defects: list[str] = []
    if not _AXIS_CI_ID_RE.fullmatch(ci_id):
        defects.append("id")
    if locus != exact_locus or _LOCUS_RE.fullmatch(locus) is None:
        defects.append("production locus")
    if shape not in _AXIS_CI_SHAPES:
        defects.append("shape")
    if not assertion:
        defects.append("assertion")
    if falsify_class not in _AXIS_CI_FALSIFY_CLASSES:
        defects.append("falsify class")
    if provenance != f"AXW:{work_item_id}":
        defects.append("AXW provenance")
    if source_hash != item.get("source_hash") or not _HEX_RE.fullmatch(
        source_hash
    ):
        defects.append("source hash")
    if (
        not isinstance(evidence, list)
        or len(evidence) != 1
        or evidence_sha256 != _digest(evidence)
    ):
        defects.append("evidence hash")
    if (
        not _HEX_RE.fullmatch(ci_block_sha256)
        or ci_block_sha256 != _digest(block_unsigned)
    ):
        defects.append("block digest")
    if defects:
        raise AxisDispositionError(
            "invalid axis committed-invariant " + ", ".join(defects)
        )
    unsigned = {
        "status": "COMPLETE",
        "reason": "",
        **block_unsigned,
        "ci_block_sha256": ci_block_sha256,
        "axis": str(item.get("axis") or ""),
        "work_item_id": work_item_id,
        "work_item_sha256": _digest(dict(item)),
        "source_relpath": str(item.get("source_relpath") or ""),
        "source_locus": str(item.get("source_locus") or ""),
    }
    return {**unsigned, "binding_digest": _digest(unsigned)}


def _validate_normalized_axis_invariant_commitment(
    value: Any,
    *,
    item: Mapping[str, Any],
    evidence: Any,
) -> dict[str, Any]:
    expected_fields = {
        "status",
        "reason",
        "ci_id",
        "locus",
        "shape",
        "assertion",
        "falsify_class",
        "provenance",
        "source_hash",
        "evidence_sha256",
        "ci_block_sha256",
        "axis",
        "work_item_id",
        "work_item_sha256",
        "source_relpath",
        "source_locus",
        "binding_digest",
    }
    if not isinstance(value, Mapping) or set(value) != expected_fields:
        raise AxisDispositionError(
            "normalized axis invariant commitment shape mismatch"
        )
    raw = {
        key: value[key]
        for key in (
            "ci_id",
            "ci_block_sha256",
            "locus",
            "shape",
            "assertion",
            "falsify_class",
            "provenance",
            "source_hash",
            "evidence_sha256",
        )
    }
    normalized = _normalize_axis_invariant_commitment(
        raw,
        item=item,
        evidence=evidence,
    )
    if dict(value) != normalized:
        raise AxisDispositionError(
            "normalized axis invariant commitment binding mismatch"
        )
    return normalized


def _bytes_digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _normal(value: Any) -> str:
    return " ".join(str(value or "").strip().split())


def _identity_text(value: Any) -> str:
    return _normal(value).strip("` ")


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise AxisDispositionError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def _load_json_bytes(raw: bytes, *, label: str) -> dict[str, Any]:
    def _reject(value: str) -> None:
        raise AxisDispositionError(f"{label} contains invalid JSON constant {value}")

    try:
        payload = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_strict_object,
            parse_constant=_reject,
        )
    except AxisDispositionError:
        raise
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise AxisDispositionError(f"{label} is unreadable: {exc}") from exc
    if not isinstance(payload, dict):
        raise AxisDispositionError(f"{label} must contain one object")
    return payload


def _load_json(path: Path, *, label: str) -> dict[str, Any]:
    try:
        return _load_json_bytes(path.read_bytes(), label=label)
    except OSError as exc:
        raise AxisDispositionError(f"{label} is unavailable: {exc}") from exc


def _work_id(context: Mapping[str, Any]) -> str:
    return "AXW-" + _digest(context)[:24].upper()


def _matrix_rows(payload: Mapping[str, Any]) -> tuple[list[dict[str, Any]], list[str]]:
    if set(payload) != {"hot", "matrix", "gaps"}:
        raise AxisDispositionError("axis matrix has missing or unknown top-level fields")
    if not all(isinstance(payload.get(key), list) for key in ("hot", "matrix", "gaps")):
        raise AxisDispositionError("axis matrix collections are malformed")

    debt: list[str] = []
    hot_langs: dict[tuple[str, str], list[str]] = {}
    for index, raw in enumerate(payload["hot"]):
        if not isinstance(raw, Mapping):
            debt.append(f"hot row {index} is not an object")
            continue
        function = _identity_text(raw.get("function"))
        locus = _normal(raw.get("loc"))
        language = _normal(raw.get("lang")).casefold()
        if not function or not locus:
            debt.append(f"hot row {index} lacks function/location identity")
            continue
        hot_langs.setdefault((function.casefold(), locus.casefold()), []).append(language)

    expected: list[tuple[str, str, str, str]] = []
    matrix_seen: set[tuple[str, str]] = set()
    for index, raw in enumerate(payload["matrix"]):
        if not isinstance(raw, Mapping):
            debt.append(f"matrix row {index} is not an object")
            continue
        function = _identity_text(raw.get("function"))
        locus = _normal(raw.get("loc"))
        cells = raw.get("cells")
        key = (function.casefold(), locus.casefold())
        if not function or not locus or not isinstance(cells, Mapping):
            debt.append(f"matrix row {index} lacks exact fields")
            continue
        if key in matrix_seen:
            debt.append(f"duplicate matrix function/location {function} @ {locus}")
        matrix_seen.add(key)
        if set(cells) != set(AXES):
            debt.append(f"matrix row {function} @ {locus} has incomplete axis cells")
            continue
        if any(str(cells[axis]).upper() not in _CELL_STATES for axis in AXES):
            debt.append(f"matrix row {function} @ {locus} has invalid cell state")
            continue
        languages = sorted(set(hot_langs.get(key, [])))
        if len(languages) != 1:
            debt.append(f"matrix row {function} @ {locus} lacks one hot-set language")
            language = languages[0] if languages else ""
        else:
            language = languages[0]
        for axis in AXES:
            if str(cells[axis]).upper() == "GAP":
                expected.append((function, locus, axis, language))

    observed: list[tuple[str, str, str, str]] = []
    for index, raw in enumerate(payload["gaps"]):
        if not isinstance(raw, Mapping) or set(raw) != {"function", "loc", "axis", "lang"}:
            debt.append(f"gap row {index} has malformed fields")
            continue
        function = _identity_text(raw.get("function"))
        locus = _normal(raw.get("loc"))
        axis = _normal(raw.get("axis")).casefold()
        language = _normal(raw.get("lang")).casefold()
        if not function or not locus or axis not in AXES:
            debt.append(f"gap row {index} lacks exact identity")
            continue
        observed.append((function, locus, axis, language))

    def semantic(row: tuple[str, str, str, str]) -> tuple[str, str, str]:
        return (row[0].casefold(), row[1].casefold(), row[2])

    expected_by_semantic = {semantic(row): row for row in expected}
    observed_counts = Counter(semantic(row) for row in observed)
    observed_by_semantic: dict[tuple[str, str, str], tuple[str, str, str, str]] = {}
    for row in observed:
        observed_by_semantic.setdefault(semantic(row), row)
    for key, count in sorted(observed_counts.items()):
        if count != 1:
            debt.append(
                "duplicate structured GAP identity " + " / ".join(key)
            )
    missing = sorted(set(expected_by_semantic) - set(observed_by_semantic))
    extra = sorted(set(observed_by_semantic) - set(expected_by_semantic))
    for key in missing:
        debt.append("matrix GAP omitted from structured gaps: " + " / ".join(key))
    for key in extra:
        debt.append("structured gap absent from matrix GAP cells: " + " / ".join(key))

    # Union both representations.  A disagreement is debt, never permission to
    # drop either visible target from the independent-work denominator.
    union: dict[tuple[str, str, str], tuple[str, str, str, str]] = dict(expected_by_semantic)
    union.update(observed_by_semantic)
    rows: list[dict[str, Any]] = []
    for key, row in sorted(union.items()):
        function, locus, axis, language = row
        expected_row = expected_by_semantic.get(key)
        observed_row = observed_by_semantic.get(key)
        if expected_row is not None and observed_row is not None and expected_row[3] != observed_row[3]:
            debt.append(
                f"GAP language drift for {function} / {locus} / {axis}: "
                f"matrix={expected_row[3] or '<blank>'}, gaps={observed_row[3] or '<blank>'}"
            )
        context = {
            "function": function,
            "location": locus,
            "axis": axis,
            "language": language,
        }
        rows.append(
            {
                "work_item_id": _work_id(context),
                **context,
                "source_occurrence_count": observed_counts.get(key, 0),
                "matrix_gap_present": expected_row is not None,
                "structured_gap_present": observed_row is not None,
                "raw_fallback_authority": "CANDIDATE_ONLY",
                "methodology_application_proven": False,
            }
        )
    return rows, sorted(set(debt))


def _ascii_digest(value: Any) -> str:
    """Match the producer's ASCII-safe canonical JSON receipt digest."""

    encoded = json.dumps(
        value,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _cap_identity(item: Mapping[str, Any]) -> str:
    return f"{str(item.get('function') or '').strip()}@{str(item.get('loc') or '').strip()}"


def _validate_cap_receipt(
    payload: Mapping[str, Any],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    expected_fields = {
        "schema_version",
        "producer",
        "source_scope",
        "limit",
        "observed_count",
        "retained_count",
        "omitted_count",
        "population_tail",
        "retained_tail",
        "omitted_tail",
        "retained_identities",
        "omitted_identities",
        "observed_items",
        "retained_items",
        "omitted_items",
        "omitted_identities_sha256",
        "population_sha256",
        "raw_fallback_authority",
        "methodology_application_proven",
        "receipt_sha256",
    }
    if set(payload) != expected_fields:
        raise AxisDispositionError("hot-function cap receipt shape mismatch")
    if (
        payload.get("schema_version") != HOT_CAP_SCHEMA
        or payload.get("producer") != "enumeration.hot_function_set"
        or not _normal(payload.get("source_scope"))
        or payload.get("raw_fallback_authority") != "CANDIDATE_ONLY"
        or payload.get("methodology_application_proven") is not False
    ):
        raise AxisDispositionError("hot-function cap receipt authority mismatch")
    limit = payload.get("limit")
    if type(limit) is not int or limit < 0:
        raise AxisDispositionError("hot-function cap receipt limit is invalid")
    observed = payload.get("observed_items")
    retained = payload.get("retained_items")
    omitted = payload.get("omitted_items")
    retained_ids = payload.get("retained_identities")
    omitted_ids = payload.get("omitted_identities")
    if not all(isinstance(value, list) for value in (observed, retained, omitted, retained_ids, omitted_ids)):
        raise AxisDispositionError("hot-function cap receipt collections are malformed")
    if any(not isinstance(item, Mapping) for item in observed):
        raise AxisDispositionError("hot-function cap receipt item is malformed")
    if observed != [*retained, *omitted]:
        raise AxisDispositionError("hot-function cap receipt population partition mismatch")
    if retained != observed[:limit] or omitted != observed[limit:]:
        raise AxisDispositionError("hot-function cap receipt does not apply its exact cap")
    expected_retained_ids = [_cap_identity(item) for item in retained]
    expected_omitted_ids = [_cap_identity(item) for item in omitted]
    population_ids = [*expected_retained_ids, *expected_omitted_ids]
    if not all(identity and identity != "@" for identity in population_ids):
        raise AxisDispositionError("hot-function cap receipt has empty identities")
    if retained_ids != expected_retained_ids or omitted_ids != expected_omitted_ids:
        raise AxisDispositionError("hot-function cap receipt identity vector mismatch")
    if len(population_ids) != len(set(population_ids)):
        raise AxisDispositionError("hot-function cap receipt has duplicate identities")
    if (
        type(payload.get("observed_count")) is not int
        or type(payload.get("retained_count")) is not int
        or type(payload.get("omitted_count")) is not int
        or payload.get("observed_count") != len(observed)
        or payload.get("retained_count") != len(retained)
        or payload.get("omitted_count") != len(omitted)
    ):
        raise AxisDispositionError("hot-function cap receipt denominator mismatch")
    if payload.get("population_tail") != (population_ids[-1] if population_ids else ""):
        raise AxisDispositionError("hot-function cap receipt population tail mismatch")
    if payload.get("retained_tail") != (expected_retained_ids[-1] if expected_retained_ids else ""):
        raise AxisDispositionError("hot-function cap receipt retained tail mismatch")
    if payload.get("omitted_tail") != (expected_omitted_ids[-1] if expected_omitted_ids else ""):
        raise AxisDispositionError("hot-function cap receipt omitted tail mismatch")
    if payload.get("omitted_identities_sha256") != _ascii_digest(expected_omitted_ids):
        raise AxisDispositionError("hot-function cap receipt omitted vector digest mismatch")
    if payload.get("population_sha256") != _ascii_digest(population_ids):
        raise AxisDispositionError("hot-function cap receipt population digest mismatch")
    unsigned = {key: value for key, value in payload.items() if key != "receipt_sha256"}
    if payload.get("receipt_sha256") != _ascii_digest(unsigned):
        raise AxisDispositionError("hot-function cap receipt digest mismatch")
    return [dict(item) for item in retained], [dict(item) for item in omitted]


def _source_cap_records(
    root: Path,
) -> tuple[
    list[dict[str, Any]],
    str,
    str,
    list[dict[str, Any]],
    list[dict[str, Any]],
    list[str],
]:
    shortfall_path = root / "_coverage_shortfalls.json"
    shortfall_sha = ""
    selected: list[dict[str, Any]] = []
    debt: list[str] = []
    if shortfall_path.is_file():
        raw = shortfall_path.read_bytes()
        shortfall_sha = _bytes_digest(raw)
        payload = _load_json_bytes(raw, label="coverage-shortfall ledger")
        rows = payload.get("shortfalls")
        if (
            type(payload.get("schema_version")) is not int
            or payload.get("schema_version") != 1
            or not isinstance(rows, list)
        ):
            debt.append("coverage-shortfall ledger schema is invalid")
            rows = []
        for row in rows:
            if not isinstance(row, Mapping):
                debt.append("coverage-shortfall ledger row is invalid")
                continue
            try:
                row = _validate_coverage_shortfall_row(dict(row))
            except CoverageShortfallError:
                debt.append("coverage-shortfall ledger row is invalid")
                continue
            if row.get("producer") != "enumeration.hot_function_set":
                continue
            samples = [
                _normal(value)
                for value in row.get("samples") or []
                if _normal(value)
            ]
            omitted = row["omitted"]
            selected.append(
                {
                    "receipt_id": _normal(row.get("receipt_id")),
                    "count_semantics": _normal(row.get("count_semantics")),
                    "observed": row.get("observed"),
                    "retained": row.get("retained"),
                    "omitted": omitted,
                    "human_projection_samples": samples,
                    "human_projection_is_authoritative": False,
                }
            )

    cap_path = root / HOT_CAP_NAME
    cap_sha = ""
    retained_items: list[dict[str, Any]] = []
    omitted_items: list[dict[str, Any]] = []
    cap_payload: dict[str, Any] | None = None
    if cap_path.is_file():
        cap_raw = cap_path.read_bytes()
        cap_sha = _bytes_digest(cap_raw)
        try:
            cap_payload = _load_json_bytes(cap_raw, label="hot-function cap receipt")
            retained_items, omitted_items = _validate_cap_receipt(cap_payload)
        except AxisDispositionError as exc:
            # Preserve any syntactically available omitted rows only as raw
            # candidate work.  They cannot prove denominator completeness or
            # methodology application, and the validation failure remains debt.
            raw_omitted = (
                cap_payload.get("omitted_items")
                if isinstance(cap_payload, Mapping)
                else []
            )
            omitted_items = [
                dict(item) for item in raw_omitted or [] if isinstance(item, Mapping)
            ]
            retained_items = []
            cap_payload = None
            debt.append(str(exc))
    exact_rows = [
        row
        for row in selected
        if row["count_semantics"] == "EXACT" and row["omitted"] > 0
    ]
    if exact_rows and cap_payload is None:
        debt.append("hot-set cap omitted identities lack typed denominator authority")
    if cap_payload is not None and exact_rows:
        if len(exact_rows) != 1:
            debt.append("hot-set cap has multiple exact generic shortfalls")
        else:
            row = exact_rows[0]
            if (
                row["observed"] != cap_payload.get("observed_count")
                or row["retained"] != cap_payload.get("retained_count")
                or row["omitted"] != cap_payload.get("omitted_count")
            ):
                debt.append("typed hot-set cap denominator disagrees with generic shortfall")
    if cap_payload is not None:
        selected.append(
            {
                "typed_receipt": HOT_CAP_NAME,
                "receipt_sha256": cap_payload.get("receipt_sha256"),
                "observed": cap_payload.get("observed_count"),
                "retained": cap_payload.get("retained_count"),
                "omitted": cap_payload.get("omitted_count"),
                "omitted_identities": list(cap_payload.get("omitted_identities") or []),
                "all_omitted_identities_known": True,
                "raw_fallback_authority": "CANDIDATE_ONLY",
            }
        )
    return (
        selected,
        shortfall_sha,
        cap_sha,
        retained_items,
        omitted_items,
        sorted(set(debt)),
    )


def _cap_omission_work_items(omitted_items: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    work: list[dict[str, Any]] = []
    for index, raw in enumerate(omitted_items):
        function = _identity_text(raw.get("function"))
        location = _normal(raw.get("loc"))
        language = _normal(raw.get("lang")).casefold()
        if not function or not location:
            continue
        for axis in AXES:
            if axis == "theft" and not (raw.get("value_effect") or raw.get("writes")):
                continue
            if axis == "identity" and not (
                raw.get("value_effect") or raw.get("writes") or raw.get("elevate")
            ):
                continue
            context = {
                "function": function,
                "location": location,
                "axis": axis,
                "language": language,
            }
            work.append(
                {
                    "work_item_id": _work_id(context),
                    **context,
                    "source_occurrence_count": 0,
                    "matrix_gap_present": False,
                    "structured_gap_present": False,
                    "cap_omission_present": True,
                    "cap_omission_index": index,
                    "raw_fallback_authority": "CANDIDATE_ONLY",
                    "methodology_application_proven": False,
                }
            )
    return work


def compile_axis_worklist(scratchpad: str | Path) -> dict[str, Any]:
    root = Path(scratchpad)
    try:
        raw = (root / MATRIX_NAME).read_bytes()
    except OSError as exc:
        raise AxisDispositionError(f"axis matrix is unavailable: {exc}") from exc
    payload = _load_json_bytes(raw, label="axis matrix")
    items, debt = _matrix_rows(payload)
    for item in items:
        item["cap_omission_present"] = False
        item["cap_omission_index"] = None
    (
        cap_records,
        shortfall_sha,
        cap_sha,
        cap_retained_items,
        omitted_items,
        cap_debt,
    ) = _source_cap_records(root)
    if cap_retained_items and cap_retained_items != payload["hot"]:
        cap_debt.append("typed hot-set cap retained population differs from axis matrix")
    items.extend(_cap_omission_work_items(omitted_items))
    by_id: dict[str, list[dict[str, Any]]] = {}
    for item in items:
        by_id.setdefault(item["work_item_id"], []).append(item)
    normalized: list[dict[str, Any]] = []
    for identity in sorted(by_id):
        rows = by_id[identity]
        contexts = {
            _canonical(
                {
                    "function": row["function"],
                    "location": row["location"],
                    "axis": row["axis"],
                    "language": row["language"],
                }
            )
            for row in rows
        }
        if len(contexts) != 1:
            debt.append(f"hash-colliding axis work identity {identity}")
            continue
        merged = dict(rows[0])
        merged["source_occurrence_count"] = max(
            int(row["source_occurrence_count"]) for row in rows
        )
        for field in (
            "matrix_gap_present",
            "structured_gap_present",
            "cap_omission_present",
        ):
            merged[field] = any(bool(row[field]) for row in rows)
        cap_indexes = [
            row["cap_omission_index"]
            for row in rows
            if row["cap_omission_index"] is not None
        ]
        merged["cap_omission_index"] = min(cap_indexes) if cap_indexes else None
        if len({_canonical(row) for row in rows}) != 1:
            debt.append(f"overlapping axis work sources reconciled for {identity}")
        normalized.append(merged)
    unsigned: dict[str, Any] = {
        "schema_version": WORKLIST_SCHEMA,
        "matrix_sha256": _bytes_digest(raw),
        "coverage_shortfalls_sha256": shortfall_sha,
        "hot_function_cap_receipt_sha256": cap_sha,
        "source_cap_records": cap_records,
        "count": len(normalized),
        "tail": normalized[-1]["work_item_id"] if normalized else "",
        "items": normalized,
        "input_debt": sorted(set([*debt, *cap_debt])),
        "raw_fallback_authority": "CANDIDATE_ONLY",
        "requires_execution": bool(normalized or debt or cap_debt),
    }
    return {**unsigned, "worklist_hash": _digest(unsigned)}


def _validate_worklist(worklist: Mapping[str, Any]) -> None:
    if worklist.get("schema_version") != WORKLIST_SCHEMA:
        raise AxisDispositionError("axis worklist schema mismatch")
    unsigned = {key: value for key, value in worklist.items() if key != "worklist_hash"}
    if worklist.get("worklist_hash") != _digest(unsigned):
        raise AxisDispositionError("axis worklist digest mismatch")
    items = worklist.get("items")
    if not isinstance(items, list) or any(not isinstance(item, Mapping) for item in items):
        raise AxisDispositionError("axis worklist items are malformed")
    identities = [str(item.get("work_item_id") or "") for item in items]
    if identities != sorted(identities) or len(identities) != len(set(identities)):
        raise AxisDispositionError("axis worklist identities are not exact and ordered")
    if (
        type(worklist.get("count")) is not int
        or worklist.get("count") < 0
        or worklist.get("count") != len(items)
    ):
        raise AxisDispositionError("axis worklist count mismatch")
    if worklist.get("tail") != (identities[-1] if identities else ""):
        raise AxisDispositionError("axis worklist tail mismatch")
    expected_item_fields = {
        "work_item_id",
        "function",
        "location",
        "axis",
        "language",
        "source_occurrence_count",
        "matrix_gap_present",
        "structured_gap_present",
        "cap_omission_present",
        "cap_omission_index",
        "raw_fallback_authority",
        "methodology_application_proven",
    }
    for item in items:
        if set(item) != expected_item_fields:
            raise AxisDispositionError("axis worklist item shape mismatch")
        context = {
            "function": item.get("function"),
            "location": item.get("location"),
            "axis": item.get("axis"),
            "language": item.get("language"),
        }
        if (
            not _identity_text(context["function"])
            or not _normal(context["location"])
            or context["axis"] not in AXES
            or item.get("work_item_id") != _work_id(context)
        ):
            raise AxisDispositionError("axis worklist item identity mismatch")
        if type(item.get("source_occurrence_count")) is not int or item["source_occurrence_count"] < 0:
            raise AxisDispositionError("axis worklist source occurrence count mismatch")
        if any(type(item.get(field)) is not bool for field in (
            "matrix_gap_present", "structured_gap_present", "cap_omission_present"
        )):
            raise AxisDispositionError("axis worklist source flags are malformed")
        cap_index = item.get("cap_omission_index")
        if item["cap_omission_present"]:
            if type(cap_index) is not int or cap_index < 0:
                raise AxisDispositionError("axis worklist cap omission index mismatch")
        elif cap_index is not None:
            raise AxisDispositionError("axis worklist retained item has a cap index")
        if (
            item.get("raw_fallback_authority") != "CANDIDATE_ONLY"
            or item.get("methodology_application_proven") is not False
        ):
            raise AxisDispositionError("axis worklist item acquired application authority")
    input_debt = worklist.get("input_debt")
    if (
        not isinstance(input_debt, list)
        or any(not isinstance(value, str) or not value for value in input_debt)
        or input_debt != sorted(set(input_debt))
    ):
        raise AxisDispositionError("axis worklist input debt is malformed")
    if worklist.get("raw_fallback_authority") != "CANDIDATE_ONLY":
        raise AxisDispositionError("axis raw fallback acquired application authority")
    if bool(worklist.get("requires_execution")) != bool(items or worklist["input_debt"]):
        raise AxisDispositionError("axis worklist execution predicate mismatch")


def _atomic_json(path: Path, payload: Mapping[str, Any]) -> None:
    content = json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    try:
        if path.read_text(encoding="utf-8", errors="strict") == content:
            return
    except (OSError, UnicodeError):
        pass
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    temporary.write_text(content, encoding="utf-8")
    os.replace(temporary, path)


def _atomic_text(path: Path, content: str) -> None:
    try:
        if path.read_text(encoding="utf-8", errors="strict") == content:
            return
    except (OSError, UnicodeError):
        pass
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    temporary.write_text(content, encoding="utf-8")
    os.replace(temporary, path)


def write_axis_worklist(scratchpad: str | Path, worklist: Mapping[str, Any]) -> Path:
    _validate_worklist(worklist)
    path = Path(scratchpad) / WORKLIST_NAME
    _atomic_json(path, worklist)
    return path


def load_axis_worklist(path: str | Path) -> dict[str, Any]:
    payload = _load_json(Path(path), label="axis worklist")
    _validate_worklist(payload)
    return payload


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


def _coverage_rows(text: str) -> tuple[list[dict[str, Any]], list[str]]:
    source_lines = text.splitlines()
    structural_lines = operational_markdown_view(text).splitlines()
    start: int | None = None
    end = len(structural_lines)
    for index, line in enumerate(structural_lines):
        heading = _HEADING_RE.match(line.strip())
        if not heading:
            continue
        level = len(heading.group("marks"))
        title = _normal(heading.group("title")).casefold()
        if start is None and level == 2 and title == "coverage record":
            start = index + 1
            continue
        if start is not None and level <= 2:
            end = index
            break
    if start is None:
        return [], ["axis Coverage Record section is missing"]
    header: int | None = None
    for index in range(start, end):
        cells = _split_row(structural_lines[index])
        if cells is not None and tuple(cell.casefold() for cell in cells) == _COVERAGE_HEADER:
            header = index
            break
    if header is None or header + 1 >= end:
        return [], ["axis Coverage Record header is missing or malformed"]
    separator = _split_row(structural_lines[header + 1])
    if separator is None or len(separator) != 4 or not all(_SEPARATOR_RE.fullmatch(cell) for cell in separator):
        return [], ["axis Coverage Record separator is missing or malformed"]
    rows: list[dict[str, Any]] = []
    debt: list[str] = []
    for index in range(header + 2, end):
        structural = structural_lines[index]
        raw = source_lines[index]
        cells = _split_row(structural)
        if cells is None:
            if raw.strip() or rows:
                break
            continue
        if len(cells) != 4:
            debt.append(f"malformed axis disposition at line {index + 1}")
            continue
        function, axis, disposition, evidence = cells
        rows.append(
            {
                "source_line": index + 1,
                "source_row_utf8": raw,
                "source_row_sha256": _bytes_digest(raw.encode("utf-8")),
                "function": _identity_text(function),
                "axis": _normal(axis).casefold(),
                "disposition": _normal(disposition).upper(),
                "evidence": _normal(evidence),
            }
        )
    return rows, debt


def _field(block: str, name: str) -> str:
    structural = operational_markdown_view(block)
    match = re.search(
        _FIELD_RE_TEMPLATE.format(name=re.escape(name)), structural
    )
    return _normal(match.group("value")) if match else ""


def _action_records(text: str) -> tuple[dict[str, dict[str, Any]], set[str]]:
    structural = operational_markdown_view(text)
    matches = list(_ACTION_HEADING_RE.finditer(structural))
    counts = Counter(match.group("id").upper() for match in matches)
    records: dict[str, dict[str, Any]] = {}
    for index, match in enumerate(matches):
        action_id = match.group("id").upper()
        if counts[action_id] != 1:
            continue
        level = len(match.group("marks"))
        end = len(structural)
        for candidate in _HEADING_RE.finditer(structural, match.end()):
            if len(candidate.group("marks")) <= level:
                end = candidate.start()
                break
        block = text[match.start():end].strip()
        fields = {name: _field(block, name) for name in ("Severity", "Location", "Description")}
        if not all(fields.values()):
            continue
        records[action_id] = {
            "action_id": action_id,
            "title": _normal(match.group("title")),
            "block_utf8": block,
            "block_sha256": _bytes_digest(block.encode("utf-8")),
            "fields": fields,
        }
    return records, {identity for identity, count in counts.items() if count > 1}


def _promotion_links(root: Path) -> tuple[dict[str, str], list[str], dict[str, str]]:
    inventory_path = root / "findings_inventory.md"
    receipt_path = root / "axis_coverage_promotion_receipt.md"
    debt: list[str] = []
    hashes: dict[str, str] = {}
    for key, path in (
        ("findings_inventory_sha256", inventory_path),
        ("axis_coverage_promotion_receipt_sha256", receipt_path),
    ):
        try:
            hashes[key] = _bytes_digest(path.read_bytes()) if path.is_file() else ""
        except OSError as exc:
            hashes[key] = ""
            debt.append(f"promotion source {path.name} is unreadable: {exc}")
    inventory_links: dict[str, set[str]] = {}
    if inventory_path.is_file():
        try:
            text = inventory_path.read_text(encoding="utf-8", errors="strict")
            matches = list(_INVENTORY_HEADING_RE.finditer(text))
            for index, match in enumerate(matches):
                end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
                block = text[match.start():end]
                finding_id = match.group("id").upper()
                for action_id in _ACTION_ID_RE.findall(block):
                    if re.search(r"AXISGAP\s*:\s*" + re.escape(action_id), block, re.IGNORECASE):
                        inventory_links.setdefault(action_id.upper(), set()).add(finding_id)
        except (OSError, UnicodeError) as exc:
            debt.append(f"promotion inventory is unreadable: {exc}")
    receipt_links: dict[str, set[str]] = {}
    if receipt_path.is_file():
        try:
            text = receipt_path.read_text(encoding="utf-8", errors="strict")
            for match in re.finditer(
                r"(?im)^\s*(AXIS-(?:[A-Za-z0-9]+-)*\d+)\s*->\s*"
                r"([A-Za-z][A-Za-z0-9_-]{1,95})\s*$",
                text,
            ):
                receipt_links.setdefault(match.group(1).upper(), set()).add(match.group(2).upper())
        except (OSError, UnicodeError) as exc:
            debt.append(f"promotion receipt is unreadable: {exc}")
    links: dict[str, str] = {}
    for action_id in sorted(set(inventory_links) | set(receipt_links)):
        common = inventory_links.get(action_id, set()) & receipt_links.get(action_id, set())
        if len(common) == 1 and inventory_links.get(action_id) == common and receipt_links.get(action_id) == common:
            links[action_id] = next(iter(common))
        else:
            debt.append(f"promotion linkage for {action_id} is absent, partial, or ambiguous")
    return links, debt, hashes


def _validated_execution_receipts(
    receipts: Mapping[str, Mapping[str, Any]],
) -> tuple[dict[str, dict[str, Any]], list[str]]:
    valid: dict[str, dict[str, Any]] = {}
    debt: list[str] = []
    for key in sorted(receipts):
        try:
            receipt = validate_evidence_receipt(receipts[key])
        except (EvidenceCapabilityError, TypeError, ValueError) as exc:
            debt.append(f"executed evidence {key} is invalid: {exc}")
            continue
        evidence_id = str(receipt["evidence_id"])
        if key != evidence_id:
            debt.append(f"executed evidence map key differs from receipt identity {key}")
            continue
        if receipt["proof_scope"] != "IN_SCOPE_EXECUTION" or "EXECUTION" not in receipt["capabilities"]:
            debt.append(f"evidence {evidence_id} does not prove in-scope execution")
            continue
        valid[evidence_id] = receipt
    return valid, debt


def _evidence_reference(evidence: str, identities: Sequence[str]) -> str:
    found = []
    for identity in identities:
        if re.search(
            rf"(?<![A-Za-z0-9_-]){re.escape(identity)}(?![A-Za-z0-9_-])",
            evidence,
            re.IGNORECASE | re.ASCII,
        ):
            found.append(identity)
    return found[0] if len(found) == 1 else ""


def _source_excerpt(item: Mapping[str, Any], production_root: Path) -> dict[str, Any]:
    locus = str(item.get("location") or "")
    match = _LOCUS_RE.search(locus)
    empty = {
        "source_path": "",
        "source_file_sha256": "",
        "source_excerpt_utf8": "",
        "source_excerpt_sha256": _bytes_digest(b""),
        "source_excerpt_lines": [],
    }
    if not match:
        return empty
    relative = Path(match.group("path").replace("\\", "/"))
    if relative.is_absolute() or ".." in relative.parts:
        return empty
    try:
        root = production_root.resolve(strict=True)
        path = (root / relative).resolve(strict=True)
        path.relative_to(root)
        raw = path.read_bytes()
        text = raw.decode("utf-8", errors="strict")
    except (OSError, ValueError, UnicodeError):
        return empty
    lines = text.splitlines(keepends=True)
    line = int(match.group("line"))
    if line > len(lines):
        return empty
    start = max(0, line - 2)
    end = min(len(lines), line + 2)
    excerpt = "".join(lines[start:end])
    return {
        "source_path": relative.as_posix(),
        "source_file_sha256": _bytes_digest(raw),
        "source_excerpt_utf8": excerpt,
        "source_excerpt_sha256": _bytes_digest(excerpt.encode("utf-8")),
        "source_excerpt_lines": [start + 1, end],
    }


def _build_repair(
    unresolved_rows: Sequence[Mapping[str, Any]],
    *,
    receipt_identity: str,
    repair_cap: int,
) -> dict[str, Any]:
    if type(repair_cap) is not int or repair_cap < 0:
        raise AxisDispositionError("axis repair cap must be a non-negative integer")
    all_items = [
        {
            "work_item_id": row["work_item_id"],
            "source_item": row["source_item"],
            "reason": row["reason"],
            "required_action": "TARGETED_AXIS_REPAIR",
            "raw_fallback_authority": "CANDIDATE_ONLY",
            "methodology_application_proven": False,
        }
        for row in unresolved_rows
    ]
    retained = all_items[:repair_cap]
    omitted = all_items[repair_cap:]
    all_ids = [row["work_item_id"] for row in all_items]
    unsigned = {
        "schema_version": REPAIR_SCHEMA,
        "source_receipt_identity": receipt_identity,
        "observed_count": len(all_items),
        "count": len(retained),
        "omitted_count": len(omitted),
        "retained_work_item_ids": [row["work_item_id"] for row in retained],
        "omitted_work_item_ids": [row["work_item_id"] for row in omitted],
        "denominator_tail": all_ids[-1] if all_ids else "",
        "retained_tail": retained[-1]["work_item_id"] if retained else "",
        "items": retained,
        "overflow": bool(omitted),
        "raw_fallback_authority": "CANDIDATE_ONLY",
    }
    return {**unsigned, "queue_hash": _digest(unsigned)}


def _build_assurance_debt(
    unresolved_rows: Sequence[Mapping[str, Any]],
    *,
    receipt_identity: str,
    production_root: Path,
) -> dict[str, Any]:
    items: list[dict[str, Any]] = []
    for row in unresolved_rows:
        excerpt = _source_excerpt(row["source_item"], production_root)
        unsigned_item = {
            "schema_version": DEBT_ITEM_SCHEMA,
            "work_item_id": row["work_item_id"],
            "function": row["function"],
            "axis": row["axis"],
            "location": row["source_item"]["location"],
            "language": row["source_item"]["language"],
            "source_item": row["source_item"],
            "output_rows": row["output_rows"],
            "reason": row["reason"],
            **excerpt,
            "required_action": "TARGETED_AXIS_REPAIR_OR_HUMAN_REVIEW",
            "public_visibility": "REPORT_VISIBLE_ASSURANCE_DEBT",
            "raw_fallback_authority": "CANDIDATE_ONLY",
            "methodology_application_proven": False,
            "finding_disposition_authority": "NONE",
            "severity_effect": "NONE",
        }
        items.append({**unsigned_item, "debt_sha256": _digest(unsigned_item)})
    unsigned = {
        "schema_version": ASSURANCE_DEBT_SCHEMA,
        "source_receipt_identity": receipt_identity,
        "count": len(items),
        "tail": items[-1]["work_item_id"] if items else "",
        "items": items,
        "raw_fallback_authority": "CANDIDATE_ONLY",
    }
    return {**unsigned, "debt_hash": _digest(unsigned)}


def _status(work_count: int, input_debt: Sequence[str], debt: Sequence[str], unresolved: Sequence[str]) -> str:
    if work_count == 0 and not input_debt:
        return "EMPTY" if not debt else "COMPLETED_WITH_DEBT"
    return "COMPLETED_WITH_DEBT" if input_debt or debt or unresolved else "CLEAN"


def reconcile_axis_output(
    worklist: Mapping[str, Any],
    output: str,
    *,
    production_root: str | Path,
    canonical_prior_ids: Mapping[str, str],
    executed_evidence_receipts: Mapping[str, Mapping[str, Any]],
    repair_cap: int,
    scratchpad: str | Path,
) -> dict[str, Any]:
    _validate_worklist(worklist)
    root = Path(scratchpad)
    project = Path(production_root)
    # Bind the persisted artifact bytes when present.  Windows text writers may
    # materialize CRLF from a caller's LF string; permit only that reversible
    # newline transport difference, then hash and parse the exact disk text.
    output_path = root / OUTPUT_NAME
    if output_path.is_file():
        try:
            persisted_output = output_path.read_bytes().decode(
                "utf-8", errors="strict"
            )
        except (OSError, UnicodeError) as exc:
            raise AxisDispositionError(
                f"persisted axis output is unreadable: {exc}"
            ) from exc
        normalized = lambda value: value.replace("\r\n", "\n").replace("\r", "\n")
        if normalized(persisted_output) != normalized(output):
            raise AxisDispositionError(
                "caller axis output differs from persisted output artifact"
            )
        output = persisted_output
    prior = {
        _normal(key): _normal(value)
        for key, value in canonical_prior_ids.items()
        if _normal(key) and _normal(value)
    }
    execution, execution_debt = _validated_execution_receipts(executed_evidence_receipts)
    coverage, parse_debt = _coverage_rows(output)
    actions, duplicate_actions = _action_records(output)
    promotion_links, promotion_debt, promotion_hashes = _promotion_links(root)
    items = {item["work_item_id"]: item for item in worklist["items"]}
    by_key: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for item in worklist["items"]:
        by_key.setdefault((item["function"].casefold(), item["axis"]), []).append(item)
    output_by_id: dict[str, list[dict[str, Any]]] = {}
    debt = [*worklist["input_debt"], *parse_debt, *execution_debt]
    for row in coverage:
        key = (row["function"].casefold(), row["axis"])
        matches = by_key.get(key, [])
        if len(matches) != 1:
            debt.append(
                f"axis output row {row['source_line']} has "
                + ("unknown" if not matches else "ambiguous")
                + " function/axis identity"
            )
            continue
        output_by_id.setdefault(matches[0]["work_item_id"], []).append(row)

    dispositions: list[dict[str, Any]] = []
    unresolved_rows: list[dict[str, Any]] = []
    for identity in sorted(items):
        item = items[identity]
        rows = output_by_id.get(identity, [])
        disposition = "UNRESOLVED"
        evidence = ""
        resolution_kind = "MISSING"
        resolved_reference = ""
        emitted_action_id = ""
        emitted_action_sha256 = ""
        promoted_finding_id = ""
        reason = "output has no exact disposition for this axis work item"
        application_proven = False
        if len(rows) > 1:
            resolution_kind = "DUPLICATE_CONFLICT"
            reason = "duplicate or conflicting output dispositions"
            debt.append(f"duplicate axis disposition for {identity}")
        elif len(rows) == 1:
            row = rows[0]
            disposition = row["disposition"]
            evidence = row["evidence"]
            if disposition in {"FINDING", "UNRESOLVED"}:
                action_refs = sorted(set(match.upper() for match in _ACTION_ID_RE.findall(evidence)))
                valid_refs = [action_id for action_id in action_refs if action_id in actions]
                if len(valid_refs) == 1 and len(action_refs) == 1 and valid_refs[0] not in duplicate_actions:
                    emitted_action_id = valid_refs[0]
                    emitted_action_sha256 = actions[emitted_action_id]["block_sha256"]
                    promoted_finding_id = promotion_links.get(emitted_action_id, "")
                    resolution_kind = "PROMOTED_ACTION" if promoted_finding_id else "EMITTED_ACTION"
                    resolved_reference = promoted_finding_id or emitted_action_id
                    reason = ""
                    application_proven = True
                else:
                    resolution_kind = "INVALID_ACTION_REFERENCE"
                    reason = "finding/unresolved disposition lacks one complete unique emitted action"
                    debt.append(f"{identity} lacks one complete unique emitted action")
            elif disposition == "CLEAR":
                if _EXTERNAL_CLEAR_RE.search(evidence):
                    resolution_kind = "UNSUPPORTED_EXTERNAL_CLEAR"
                    reason = "favorable or external assumption cannot self-authorize CLEAR"
                    debt.append(f"{identity} attempted an unsupported external CLEAR")
                else:
                    execution_id = _evidence_reference(evidence, sorted(execution))
                    execution_receipt = execution.get(execution_id) if execution_id else None
                    if execution_receipt is not None and identity in execution_receipt.get("constituent_ids", []):
                        resolution_kind = "EXECUTED_EVIDENCE"
                        resolved_reference = execution_id
                        reason = ""
                        application_proven = True
                    else:
                        clear_kind, reference = resolve_clear_evidence(
                            evidence,
                            production_root=project,
                            canonical_prior_ids=prior,
                        )
                        if clear_kind == "PRODUCTION_LOCUS":
                            resolution_kind = "IN_SCOPE_SOURCE_LOCUS"
                            resolved_reference = reference
                            reason = ""
                            application_proven = True
                        elif clear_kind == "CANONICAL_PRIOR":
                            resolution_kind = "EXISTING_FINDING_IDENTITY"
                            resolved_reference = reference
                            reason = ""
                            application_proven = True
                        else:
                            resolution_kind = "INVALID_CLEAR"
                            reason = "CLEAR lacks in-scope locus, executed evidence, or existing finding identity"
                            debt.append(f"{identity} CLEAR lacks resolvable evidence")
            else:
                resolution_kind = "INVALID_DISPOSITION"
                reason = f"unsupported disposition {disposition or '<blank>'}"
                debt.append(f"{identity} has unsupported disposition {disposition or '<blank>'}")
        row_payload = {
            "work_item_id": identity,
            "function": item["function"],
            "axis": item["axis"],
            "source_item": item,
            "disposition": disposition,
            "evidence": evidence,
            "resolution_kind": resolution_kind,
            "resolved_reference": resolved_reference,
            "emitted_action_id": emitted_action_id,
            "emitted_action_sha256": emitted_action_sha256,
            "promoted_finding_id": promoted_finding_id,
            "output_rows": rows,
            "reason": reason,
            "methodology_application_proven": application_proven,
            "raw_fallback_authority": "CANDIDATE_ONLY",
        }
        dispositions.append(row_payload)
        if not application_proven:
            unresolved_rows.append(row_payload)

    unresolved_ids = [row["work_item_id"] for row in unresolved_rows]
    receipt_identity = _digest(
        {
            "worklist_hash": worklist["worklist_hash"],
            "output_sha256": _bytes_digest(output.encode("utf-8")),
            "repair_cap": repair_cap,
        }
    )
    repair = _build_repair(
        unresolved_rows,
        receipt_identity=receipt_identity,
        repair_cap=repair_cap,
    )
    assurance = _build_assurance_debt(
        unresolved_rows,
        receipt_identity=receipt_identity,
        production_root=project,
    )
    # Promotion-side inconsistencies do not invalidate a complete emitted
    # action: they remain delivery debt for the promotion consumer.  Record
    # them visibly without laundering application proof into delivery proof.
    promotion_issues = sorted(set(promotion_debt))
    unsigned: dict[str, Any] = {
        "schema_version": RECEIPT_SCHEMA,
        "worklist": dict(worklist),
        "denominator_count": len(items),
        "denominator_tail": worklist["tail"],
        "output_sha256": _bytes_digest(output.encode("utf-8")),
        "parameter_bindings": {
            "production_root": str(project.resolve()),
            "canonical_prior_ids": dict(sorted(prior.items())),
            "canonical_prior_ids_sha256": _digest(dict(sorted(prior.items()))),
            "executed_evidence_receipts": dict(sorted(execution.items())),
            "executed_evidence_receipts_sha256": _digest(dict(sorted(execution.items()))),
            "repair_cap": repair_cap,
        },
        "promotion_source_hashes": promotion_hashes,
        "dispositions": dispositions,
        "unresolved_work_item_ids": unresolved_ids,
        "repair_work": repair,
        "assurance_debt": assurance,
        "debt": sorted(set(debt)),
        "promotion_delivery_issues": promotion_issues,
        "raw_fallback_authority": "CANDIDATE_ONLY",
        "raw_fallback_proves_methodology_application": False,
        "status": _status(len(items), worklist["input_debt"], debt, unresolved_ids),
    }
    return {**unsigned, "receipt_hash": _digest(unsigned)}


def _validate_repair(repair: Mapping[str, Any]) -> None:
    if repair.get("schema_version") != REPAIR_SCHEMA:
        raise AxisDispositionError("axis repair schema mismatch")
    unsigned = {key: value for key, value in repair.items() if key != "queue_hash"}
    if repair.get("queue_hash") != _digest(unsigned):
        raise AxisDispositionError("axis repair digest mismatch")
    items = repair.get("items")
    if (
        not isinstance(items, list)
        or type(repair.get("count")) is not int
        or repair.get("count") < 0
        or repair.get("count") != len(items)
    ):
        raise AxisDispositionError("axis repair count mismatch")
    retained = repair.get("retained_work_item_ids")
    omitted = repair.get("omitted_work_item_ids")
    if not isinstance(retained, list) or not isinstance(omitted, list):
        raise AxisDispositionError("axis repair identity vectors are malformed")
    if retained != [item.get("work_item_id") for item in items]:
        raise AxisDispositionError("axis repair retained identity mismatch")
    if (
        type(repair.get("observed_count")) is not int
        or repair.get("observed_count") < 0
        or repair.get("observed_count") != len(retained) + len(omitted)
    ):
        raise AxisDispositionError("axis repair observed denominator mismatch")
    if (
        type(repair.get("omitted_count")) is not int
        or repair.get("omitted_count") < 0
        or repair.get("omitted_count") != len(omitted)
    ):
        raise AxisDispositionError("axis repair omitted denominator mismatch")
    all_ids = [*retained, *omitted]
    if len(all_ids) != len(set(all_ids)):
        raise AxisDispositionError("axis repair identity vector has duplicates")
    if repair.get("denominator_tail") != (all_ids[-1] if all_ids else ""):
        raise AxisDispositionError("axis repair denominator tail mismatch")
    if repair.get("retained_tail") != (retained[-1] if retained else ""):
        raise AxisDispositionError("axis repair retained tail mismatch")
    if bool(repair.get("overflow")) != bool(omitted):
        raise AxisDispositionError("axis repair overflow semantic mismatch")
    if repair.get("raw_fallback_authority") != "CANDIDATE_ONLY":
        raise AxisDispositionError("axis repair raw fallback authority mismatch")
    for item in items:
        if (
            not isinstance(item, Mapping)
            or item.get("raw_fallback_authority") != "CANDIDATE_ONLY"
            or item.get("methodology_application_proven") is not False
            or item.get("required_action") != "TARGETED_AXIS_REPAIR"
        ):
            raise AxisDispositionError("axis repair item acquired unsupported authority")


def _validate_assurance(assurance: Mapping[str, Any]) -> None:
    if assurance.get("schema_version") != ASSURANCE_DEBT_SCHEMA:
        raise AxisDispositionError("axis assurance debt schema mismatch")
    unsigned = {key: value for key, value in assurance.items() if key != "debt_hash"}
    if assurance.get("debt_hash") != _digest(unsigned):
        raise AxisDispositionError("axis assurance debt digest mismatch")
    items = assurance.get("items")
    if (
        not isinstance(items, list)
        or type(assurance.get("count")) is not int
        or assurance.get("count") < 0
        or assurance.get("count") != len(items)
    ):
        raise AxisDispositionError("axis assurance debt count mismatch")
    if assurance.get("tail") != (items[-1]["work_item_id"] if items else ""):
        raise AxisDispositionError("axis assurance debt tail mismatch")
    for item in items:
        if not isinstance(item, Mapping) or item.get("schema_version") != DEBT_ITEM_SCHEMA:
            raise AxisDispositionError("axis assurance debt item schema mismatch")
        item_unsigned = {key: value for key, value in item.items() if key != "debt_sha256"}
        if item.get("debt_sha256") != _digest(item_unsigned):
            raise AxisDispositionError("axis assurance debt item digest mismatch")
        excerpt = str(item.get("source_excerpt_utf8") or "")
        if item.get("source_excerpt_sha256") != _bytes_digest(excerpt.encode("utf-8")):
            raise AxisDispositionError("axis assurance debt source excerpt hash mismatch")
        if item.get("raw_fallback_authority") != "CANDIDATE_ONLY" or item.get("methodology_application_proven") is not False:
            raise AxisDispositionError("axis assurance debt acquired application authority")


def _validate_receipt(receipt: Mapping[str, Any]) -> None:
    if receipt.get("schema_version") != RECEIPT_SCHEMA:
        raise AxisDispositionError("axis disposition receipt schema mismatch")
    unsigned = {key: value for key, value in receipt.items() if key != "receipt_hash"}
    if receipt.get("receipt_hash") != _digest(unsigned):
        raise AxisDispositionError("axis disposition receipt digest mismatch")
    worklist = receipt.get("worklist")
    if not isinstance(worklist, Mapping):
        raise AxisDispositionError("axis receipt worklist is malformed")
    _validate_worklist(worklist)
    dispositions = receipt.get("dispositions")
    unresolved = receipt.get("unresolved_work_item_ids")
    debt = receipt.get("debt")
    if not isinstance(dispositions, list) or not isinstance(unresolved, list) or not isinstance(debt, list):
        raise AxisDispositionError("axis receipt collections are malformed")
    work_ids = [item["work_item_id"] for item in worklist["items"]]
    disp_ids = [row.get("work_item_id") for row in dispositions if isinstance(row, Mapping)]
    if disp_ids != work_ids or len(disp_ids) != len(dispositions):
        raise AxisDispositionError("axis receipt disposition denominator mismatch")
    computed_unresolved = [
        row["work_item_id"]
        for row in dispositions
        if row.get("methodology_application_proven") is not True
    ]
    if unresolved != computed_unresolved:
        raise AxisDispositionError("axis receipt unresolved identity mismatch")
    if (
        type(receipt.get("denominator_count")) is not int
        or receipt.get("denominator_count") < 0
        or receipt.get("denominator_count") != len(work_ids)
    ):
        raise AxisDispositionError("axis receipt denominator count mismatch")
    if receipt.get("denominator_tail") != (work_ids[-1] if work_ids else ""):
        raise AxisDispositionError("axis receipt denominator tail mismatch")
    if not _HEX_RE.fullmatch(str(receipt.get("output_sha256") or "")):
        raise AxisDispositionError("axis receipt output digest is malformed")
    for source_item, disposition in zip(worklist["items"], dispositions):
        if (
            disposition.get("source_item") != source_item
            or disposition.get("raw_fallback_authority") != "CANDIDATE_ONLY"
            or type(disposition.get("methodology_application_proven")) is not bool
        ):
            raise AxisDispositionError("axis receipt disposition authority mismatch")
    repair = receipt.get("repair_work") if isinstance(receipt.get("repair_work"), Mapping) else {}
    assurance = receipt.get("assurance_debt") if isinstance(receipt.get("assurance_debt"), Mapping) else {}
    _validate_repair(repair)
    _validate_assurance(assurance)
    repair_ids = [
        *repair["retained_work_item_ids"],
        *repair["omitted_work_item_ids"],
    ]
    if repair_ids != unresolved:
        raise AxisDispositionError("axis receipt repair denominator mismatch")
    assurance_ids = [row["work_item_id"] for row in assurance["items"]]
    if assurance_ids != unresolved:
        raise AxisDispositionError("axis receipt assurance debt denominator mismatch")
    parameters = receipt.get("parameter_bindings")
    if not isinstance(parameters, Mapping):
        raise AxisDispositionError("axis receipt parameter bindings are malformed")
    repair_cap = parameters.get("repair_cap")
    if type(repair_cap) is not int or repair_cap < 0:
        raise AxisDispositionError("axis receipt repair cap binding mismatch")
    expected_receipt_identity = _digest(
        {
            "worklist_hash": worklist["worklist_hash"],
            "output_sha256": receipt["output_sha256"],
            "repair_cap": repair_cap,
        }
    )
    if (
        repair.get("source_receipt_identity") != expected_receipt_identity
        or assurance.get("source_receipt_identity") != expected_receipt_identity
    ):
        raise AxisDispositionError("axis receipt successor binding mismatch")
    expected_status = _status(len(work_ids), worklist["input_debt"], debt, unresolved)
    if receipt.get("status") != expected_status:
        raise AxisDispositionError("axis receipt semantic status mismatch")
    if receipt.get("raw_fallback_authority") != "CANDIDATE_ONLY" or receipt.get("raw_fallback_proves_methodology_application") is not False:
        raise AxisDispositionError("axis raw fallback acquired application proof")


def _limitations(receipt: Mapping[str, Any], *, projection_cap: int = 80) -> str:
    assurance = receipt["assurance_debt"]
    items = assurance["items"]
    visible = items[:projection_cap]
    omitted = items[projection_cap:]
    lines = [
        "# Axis-Coverage Assurance Limitations (P0-I)",
        "",
        "Only exact unresolved hot-function × axis work identities appear here. "
        "The raw mechanical fallback is candidate-only and never proves that "
        "the methodology was applied.",
        "",
        f"**Report-visible assurance debt: {len(items)}**",
        f"**Authoritative debt receipt: `{assurance['debt_hash']}`**",
        "",
        "| Work Item | Function | Axis | Location | Reason | Content Hash |",
        "|---|---|---|---|---|---|",
    ]
    for item in visible:
        def cell(value: Any) -> str:
            return _normal(value).replace("|", "/")

        lines.append(
            f"| {cell(item['work_item_id'])} | {cell(item['function'])} | "
            f"{cell(item['axis'])} | {cell(item['location'])} | "
            f"{cell(item['reason'])} | {cell(item['debt_sha256'])} |"
        )
    if omitted:
        lines.extend(
            [
                "",
                f"Projection cap retained {len(visible)} of {len(items)} rows. "
                "The authoritative JSON retains every row.",
                f"Exact omitted identities: {', '.join(item['work_item_id'] for item in omitted)}",
                f"Denominator tail: {items[-1]['work_item_id']}",
            ]
        )
    lines.extend(
        [
            "",
            "These rows grant no authority to delete, merge, demote, or clear a finding.",
            "",
        ]
    )
    return "\n".join(lines)


def write_axis_disposition_artifacts(
    scratchpad: str | Path,
    receipt: Mapping[str, Any],
) -> tuple[Path, Path, Path, Path]:
    _validate_receipt(receipt)
    root = Path(scratchpad)
    receipt_path = root / RECEIPT_NAME
    repair_path = root / REPAIR_NAME
    debt_path = root / ASSURANCE_DEBT_NAME
    limitations_path = root / LIMITATIONS_NAME
    _atomic_json(receipt_path, receipt)
    _atomic_json(repair_path, receipt["repair_work"])
    _atomic_json(debt_path, receipt["assurance_debt"])
    _atomic_text(limitations_path, _limitations(receipt))
    return receipt_path, repair_path, debt_path, limitations_path


def load_axis_disposition_receipt(
    path: str | Path,
    *,
    output_artifact: str | Path | None = None,
) -> dict[str, Any]:
    receipt = _load_json(Path(path), label="axis disposition receipt")
    _validate_receipt(receipt)
    if output_artifact is not None:
        try:
            output_sha = _bytes_digest(Path(output_artifact).read_bytes())
        except OSError as exc:
            raise AxisDispositionError(f"bound axis output is unavailable: {exc}") from exc
        if output_sha != receipt["output_sha256"]:
            raise AxisDispositionError("bound axis output digest mismatch")
    return receipt


def validate_axis_disposition_authority(
    scratchpad: str | Path,
    *,
    production_root: str | Path,
    canonical_prior_ids: Mapping[str, str],
    executed_evidence_receipts: Mapping[str, Mapping[str, Any]],
    repair_cap: int,
) -> dict[str, Any]:
    root = Path(scratchpad)
    worklist = load_axis_worklist(root / WORKLIST_NAME)
    if worklist != compile_axis_worklist(root):
        raise AxisDispositionError("axis worklist does not match current matrix inputs")
    receipt = load_axis_disposition_receipt(
        root / RECEIPT_NAME,
        output_artifact=root / OUTPUT_NAME,
    )
    if receipt.get("worklist") != worklist:
        raise AxisDispositionError("axis receipt does not bind current worklist")
    try:
        # Preserve persisted newlines so the replay binds the same bytes that
        # produced ``output_sha256`` on every OS.
        with (root / OUTPUT_NAME).open(
            "r", encoding="utf-8", errors="strict", newline=""
        ) as handle:
            output = handle.read()
    except (OSError, UnicodeError) as exc:
        raise AxisDispositionError(f"cannot read bound axis output: {exc}") from exc
    recomputed = reconcile_axis_output(
        worklist,
        output,
        production_root=production_root,
        canonical_prior_ids=canonical_prior_ids,
        executed_evidence_receipts=executed_evidence_receipts,
        repair_cap=repair_cap,
        scratchpad=root,
    )
    if receipt != recomputed:
        raise AxisDispositionError("axis receipt does not replay from current sources")
    observed_repair = _load_json(root / REPAIR_NAME, label="axis repair work")
    if observed_repair != receipt["repair_work"]:
        raise AxisDispositionError("axis repair work does not match current receipt")
    observed_debt = _load_json(root / ASSURANCE_DEBT_NAME, label="axis assurance debt")
    if observed_debt != receipt["assurance_debt"]:
        raise AxisDispositionError("axis assurance debt does not match current receipt")
    try:
        projection = (root / LIMITATIONS_NAME).read_text(encoding="utf-8", errors="strict")
    except (OSError, UnicodeError) as exc:
        raise AxisDispositionError(f"axis assurance projection is unavailable: {exc}") from exc
    if projection != _limitations(receipt):
        raise AxisDispositionError("axis assurance projection drift")
    return receipt


_V2_POPULATION_STATES = frozenset({"EXACT", "DEGRADED", "UNKNOWN"})
_V2_DISPOSITIONS = frozenset({"FINDING", "UNRESOLVED", "CLEAR"})
_V2_REPAIR_STATES = frozenset(
    {"NOT_REQUIRED", "EXECUTED", "FAILED", "OVERFLOW"}
)
_V2_EVIDENCE_KINDS = frozenset(
    {"SOURCE_LOCUS", "CANONICAL_PRIOR", "EXECUTION_RECEIPT"}
)
_V2_RELATIVE_LOCUS_RE = re.compile(
    r"^(?P<path>.+?):(?P<locus>L[1-9][0-9]*)$", re.ASCII
)
_V2_GENERIC_CLEAR_RE = re.compile(
    r"^(?:"
    r"(?:it\s+)?(?:looks?|seems?|appears?)\s+safe"
    r"|safe"
    r"|no\s+(?:issue|bug|finding|problem)"
    r"|not\s+vulnerable"
    r"|works?\s+as\s+intended"
    r"|correct"
    r"|fine"
    r"|guard"
    r")[.!]?$",
    re.IGNORECASE | re.ASCII,
)


def _v2_signed(
    unsigned: Mapping[str, Any],
    digest_key: str,
) -> dict[str, Any]:
    normalized = json.loads(_canonical(dict(unsigned)))
    return {
        **normalized,
        digest_key: _digest(normalized),
    }


def _v2_validate_signed(
    value: Mapping[str, Any],
    *,
    schema: str,
    digest_key: str,
    label: str,
) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise AxisDispositionError(f"{label} must be an object")
    row = json.loads(_canonical(dict(value)))
    unsigned = dict(row)
    digest = str(unsigned.pop(digest_key, "") or "")
    if (
        row.get("schema_version") != schema
        or not _HEX_RE.fullmatch(digest)
        or digest != _digest(unsigned)
    ):
        raise AxisDispositionError(f"{label} schema or digest mismatch")
    return row


def _v2_string_list(
    values: Any,
    *,
    label: str,
    allow_empty: bool = True,
) -> list[str]:
    if not isinstance(values, list):
        raise AxisDispositionError(f"{label} must be a list")
    normalized = [str(value or "").strip() for value in values]
    if (
        any(not value for value in normalized)
        or normalized != sorted(set(normalized))
        or (not allow_empty and not normalized)
    ):
        raise AxisDispositionError(f"{label} is not exact, unique, and ordered")
    return normalized


def validate_axis_population_authority(
    value: Mapping[str, Any],
    *,
    expected_run_id: str,
) -> dict[str, Any]:
    """Validate the real enumeration provider contract, never a caller wrapper."""

    expected_fields = {
        "schema_version",
        "provider_version",
        "run_id",
        "denominator_status",
        "observed_hot_function_count",
        "gap_count",
        "exact_zero_proven",
        "requires_execution",
        "source_bindings",
        "cap_receipt_sha256",
        "examined_authority",
        "hot",
        "matrix",
        "gaps",
        "debt",
        "raw_fallback_authority",
        "methodology_application_proven_by_raw_prose",
        "population_digest",
    }
    if not isinstance(value, Mapping) or set(value) != expected_fields:
        raise AxisDispositionError("axis population authority shape mismatch")
    authority = json.loads(_canonical(dict(value)))
    unsigned = dict(authority)
    population_digest = str(unsigned.pop("population_digest", "") or "")
    provider_digest = hashlib.sha256(
        json.dumps(
            unsigned,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    debt = _v2_string_list(
        authority.get("debt"),
        label="axis population input debt",
    )
    hot = authority.get("hot")
    matrix = authority.get("matrix")
    gaps = authority.get("gaps")
    bindings = authority.get("source_bindings")
    if (
        not isinstance(hot, list)
        or not isinstance(matrix, list)
        or not isinstance(gaps, list)
        or not isinstance(bindings, Mapping)
    ):
        raise AxisDispositionError(
            "axis population collections are malformed"
        )
    if any(
        not isinstance(name, str)
        or not name
        or not isinstance(digest, str)
        or (
            digest
            and not _HEX_RE.fullmatch(digest)
        )
        for name, digest in bindings.items()
    ):
        raise AxisDispositionError(
            "axis population source bindings are malformed"
        )
    status = authority.get("denominator_status")
    observed = authority.get("observed_hot_function_count")
    gap_count = authority.get("gap_count")
    exact_zero = (
        status == "EXACT"
        and observed == 0
        and not gaps
        and not debt
    )
    if (
        authority.get("run_id") != str(expected_run_id)
        or authority.get("schema_version") != POPULATION_AUTHORITY_SCHEMA
        or authority.get("provider_version") != POPULATION_PROVIDER_VERSION
        or status not in _V2_POPULATION_STATES
        or type(observed) is not int
        or observed < 0
        or type(gap_count) is not int
        or gap_count < 0
        or observed != len(hot)
        or gap_count != len(gaps)
        or len(matrix) != len(hot)
        or authority.get("exact_zero_proven") is not exact_zero
        or authority.get("requires_execution")
        is not bool(gaps or debt or status != "EXACT")
        or authority.get("raw_fallback_authority") != "CANDIDATE_ONLY"
        or authority.get("methodology_application_proven_by_raw_prose")
        is not False
        or not _HEX_RE.fullmatch(population_digest)
        or population_digest != provider_digest
        or (status == "EXACT" and bool(debt))
        or (
            status == "EXACT"
            and any(not digest for digest in bindings.values())
        )
        or (
            status == "EXACT"
            and (
                not _HEX_RE.fullmatch(
                    str(authority.get("cap_receipt_sha256") or "")
                )
                or not {
                    "_mechanical_graph.json",
                    "_hot_function_cap_receipt.json",
                }.issubset(bindings)
            )
        )
    ):
        raise AxisDispositionError(
            "axis population authority does not bind the current denominator"
        )

    expected_matrix_fields = {
        "function_identity",
        "function",
        "loc",
        "lang",
        "score",
        "source_relpath",
        "source_locus",
        "source_sha256",
        "cells",
        "cell_authority",
    }
    expected_gap_fields = {
        "function_identity",
        "function",
        "loc",
        "axis",
        "lang",
        "source_relpath",
        "source_locus",
        "source_sha256",
    }
    matrix_by_identity: dict[str, Mapping[str, Any]] = {}
    enumerated_gaps: set[tuple[str, str]] = set()
    hot_keys: list[tuple[str, str]] = []
    for index, row in enumerate(hot):
        if not isinstance(row, Mapping):
            raise AxisDispositionError(
                f"axis population hot row {index} is malformed"
            )
        function = str(row.get("function") or "").strip()
        locus = str(row.get("loc") or "").strip()
        if not function or not locus:
            raise AxisDispositionError(
                f"axis population hot row {index} lacks identity"
            )
        hot_keys.append((function.casefold(), locus.casefold()))
    if len(hot_keys) != len(set(hot_keys)):
        raise AxisDispositionError(
            "axis population hot denominator contains duplicate identities"
        )
    for index, row in enumerate(matrix):
        if not isinstance(row, Mapping) or set(row) != expected_matrix_fields:
            raise AxisDispositionError(
                f"axis population matrix row {index} shape mismatch"
            )
        identity = str(row.get("function_identity") or "").strip()
        function = str(row.get("function") or "").strip()
        locus = str(row.get("loc") or "").strip()
        cells = row.get("cells")
        cell_authority = row.get("cell_authority")
        if (
            not identity
            or not function
            or not locus
            or not str(row.get("lang") or "").strip()
            or not isinstance(cells, Mapping)
            or set(cells) != set(AXES)
            or any(value not in _CELL_STATES for value in cells.values())
            or not isinstance(cell_authority, Mapping)
            or set(cell_authority) != set(AXES)
            or any(
                not isinstance(item, str) or not item
                for item in cell_authority.values()
            )
            or identity in matrix_by_identity
            or (
                status == "EXACT"
                and not _HEX_RE.fullmatch(
                    str(row.get("source_sha256") or "")
                )
            )
        ):
            raise AxisDispositionError(
                f"axis population matrix row {index} is not exact"
            )
        matrix_by_identity[identity] = row
        for axis in AXES:
            if cells[axis] == "GAP":
                enumerated_gaps.add((identity, axis))
    if sorted(hot_keys) != sorted(
        (
            str(row["function"]).casefold(),
            str(row["loc"]).casefold(),
        )
        for row in matrix
    ):
        raise AxisDispositionError(
            "axis population hot and matrix denominators differ"
        )
    observed_gaps: set[tuple[str, str]] = set()
    for index, row in enumerate(gaps):
        if not isinstance(row, Mapping) or set(row) != expected_gap_fields:
            raise AxisDispositionError(
                f"axis population gap row {index} shape mismatch"
            )
        identity = str(row.get("function_identity") or "").strip()
        axis = str(row.get("axis") or "")
        matrix_row = matrix_by_identity.get(identity)
        key = (identity, axis)
        if (
            matrix_row is None
            or axis not in AXES
            or key in observed_gaps
            or any(
                row.get(field) != matrix_row.get(field)
                for field in (
                    "function",
                    "loc",
                    "lang",
                    "source_relpath",
                    "source_locus",
                    "source_sha256",
                )
            )
            or (
                status == "EXACT"
                and not _HEX_RE.fullmatch(
                    str(row.get("source_sha256") or "")
                )
            )
        ):
            raise AxisDispositionError(
                f"axis population gap row {index} does not bind a matrix GAP"
            )
        observed_gaps.add(key)
    if observed_gaps != enumerated_gaps:
        raise AxisDispositionError(
            "axis population GAP enumeration differs from matrix"
        )
    return authority


def _v2_source_binding(
    production_root: Path,
    locus: str,
) -> tuple[str, str, str, str]:
    match = _V2_RELATIVE_LOCUS_RE.fullmatch(str(locus or "").strip())
    if match is None:
        return "", "", "", "source locus is not canonical relative-path:Lline"
    relative_text = match.group("path").replace("\\", "/")
    relative = PurePosixPath(relative_text)
    if (
        relative.is_absolute()
        or not relative.parts
        or any(part in {"", ".", ".."} for part in relative.parts)
        or ":" in relative.parts[0]
    ):
        return "", "", "", "source path escapes or is not canonical"
    root = Path(production_root).resolve(strict=True)
    candidate = root.joinpath(*relative.parts)
    try:
        if candidate.is_symlink():
            raise OSError("source path is a symbolic link")
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root)
        if not resolved.is_file():
            raise OSError("source is not one regular in-root file")
        # Match the provider's cross-checkout identity: universal-newline
        # normalization makes semantically identical CRLF/LF source checkouts
        # bind to the same work item on every supported host OS.
        text = resolved.read_text(encoding="utf-8", errors="strict")
        line = int(match.group("locus")[1:])
        if line > len(text.splitlines()):
            raise OSError("source locus is beyond end-of-file")
    except (OSError, UnicodeError, ValueError) as exc:
        return (
            relative.as_posix(),
            match.group("locus"),
            "",
            f"source input is unavailable or unsafe: {exc}",
        )
    return (
        relative.as_posix(),
        match.group("locus"),
        _bytes_digest(text.encode("utf-8")),
        "",
    )


def _v2_work_item_id(context: Mapping[str, Any]) -> str:
    return "AXW-" + _digest(context)[:24].upper()


def _v2_action_id(work_item_id: str) -> str:
    numeric = int(_bytes_digest(work_item_id.encode("utf-8"))[:15], 16)
    return f"AXIS-V2-{numeric}"


def compile_axis_worklist_v2(
    matrix: Mapping[str, Any],
    *,
    matrix_raw: bytes,
    production_root: str | Path,
    population_authority: Mapping[str, Any],
    run_id: str,
) -> dict[str, Any]:
    """Compile the exact typed GAP denominator into immutable AXW identities."""

    if not isinstance(matrix, Mapping):
        raise AxisDispositionError("axis v2 matrix must be an object")
    parsed_matrix = _load_json_bytes(
        bytes(matrix_raw),
        label="axis v2 population",
    )
    if parsed_matrix != dict(matrix):
        raise AxisDispositionError(
            "axis v2 population object differs from its bound bytes"
        )
    hot = matrix.get("hot")
    matrix_rows = matrix.get("matrix")
    gaps = matrix.get("gaps")
    if not all(isinstance(value, list) for value in (hot, matrix_rows, gaps)):
        raise AxisDispositionError("axis v2 matrix collections are malformed")
    matrix_digest = _bytes_digest(bytes(matrix_raw))
    authority = validate_axis_population_authority(
        population_authority,
        expected_run_id=str(run_id),
    )
    if authority != dict(matrix):
        raise AxisDispositionError(
            "axis v2 population authority differs from the provider artifact"
        )
    status = str(authority["denominator_status"])
    input_debt = list(authority["debt"])
    items: list[dict[str, Any]] = []
    seen_contexts: set[str] = set()
    for index, raw in enumerate(gaps):
        if not isinstance(raw, Mapping):
            input_debt.append(f"gap row {index} is not an object")
            continue
        function = _identity_text(raw.get("function"))
        function_identity = _identity_text(raw.get("function_identity"))
        location = _normal(raw.get("loc"))
        axis = _normal(raw.get("axis")).casefold()
        language = _normal(raw.get("lang")).casefold()
        if not function_identity:
            input_debt.append(
                f"gap row {index} lacks typed function_identity"
            )
            status = "UNKNOWN"
        source_relpath, source_locus, source_hash, source_issue = (
            _v2_source_binding(Path(production_root), location)
        )
        provider_source_locus = (
            f"{source_relpath}:{source_locus}"
            if source_relpath and source_locus
            else ""
        )
        if (
            str(raw.get("source_relpath") or "") != source_relpath
            or str(raw.get("source_locus") or "") != provider_source_locus
            or str(raw.get("source_sha256") or "") != source_hash
        ):
            source_issue = (
                "provider source binding differs from current production input"
            )
        if source_issue:
            input_debt.append(f"gap row {index}: {source_issue}")
            status = "UNKNOWN"
        if (
            not function
            or not function_identity
            or axis not in AXES
            or not language
        ):
            input_debt.append(f"gap row {index} lacks exact identity fields")
            continue
        matrix_cell_hash = _digest(dict(raw))
        identity_context = {
            "function_identity": function_identity,
            "axis": axis,
            "source_relpath": source_relpath,
            "source_locus": source_locus,
            "source_hash": source_hash,
            "matrix_cell_hash": matrix_cell_hash,
        }
        context_digest = _canonical(identity_context)
        if context_digest in seen_contexts:
            input_debt.append(
                f"duplicate axis v2 work identity at gap row {index}"
            )
            continue
        seen_contexts.add(context_digest)
        work_item_id = _v2_work_item_id(identity_context)
        items.append(
            {
                "work_item_id": work_item_id,
                "function_identity": function_identity,
                "function": function,
                "axis": axis,
                "language": language,
                "source_relpath": source_relpath,
                "source_locus": source_locus,
                "source_hash": source_hash,
                "matrix_cell_hash": matrix_cell_hash,
                "required_action_id": _v2_action_id(work_item_id),
            }
        )
    items.sort(key=lambda row: row["work_item_id"])
    item_ids = [row["work_item_id"] for row in items]
    if len(item_ids) != len(set(item_ids)):
        raise AxisDispositionError("axis v2 work-item digest collision")
    input_debt = sorted(set(input_debt))
    if status == "EXACT" and input_debt:
        status = "DEGRADED"
    clean_empty = status == "EXACT" and not items and not input_debt
    unsigned = {
        "schema_version": WORKLIST_V2_SCHEMA,
        "run_id": str(run_id),
        "matrix_sha256": matrix_digest,
        "population_authority": authority,
        "population_authority_digest": authority["population_digest"],
        "denominator_status": status,
        "observed_hot_function_count": len(hot),
        "gap_count": len(gaps),
        "input_debt": input_debt,
        "count": len(items),
        "tail": item_ids[-1] if item_ids else "",
        "items": items,
        "clean_empty": clean_empty,
        "requires_execution": not clean_empty,
    }
    return _v2_signed(unsigned, "worklist_hash")


def _validate_axis_worklist_v2(
    value: Mapping[str, Any],
) -> dict[str, Any]:
    worklist = _v2_validate_signed(
        value,
        schema=WORKLIST_V2_SCHEMA,
        digest_key="worklist_hash",
        label="axis worklist v2",
    )
    expected_worklist_fields = {
        "schema_version",
        "run_id",
        "matrix_sha256",
        "population_authority",
        "population_authority_digest",
        "denominator_status",
        "observed_hot_function_count",
        "gap_count",
        "input_debt",
        "count",
        "tail",
        "items",
        "clean_empty",
        "requires_execution",
        "worklist_hash",
    }
    if set(worklist) != expected_worklist_fields:
        raise AxisDispositionError("axis worklist v2 shape mismatch")
    items = worklist.get("items")
    if not isinstance(items, list):
        raise AxisDispositionError("axis worklist v2 items are malformed")
    ids: list[str] = []
    expected_fields = {
        "work_item_id",
        "function_identity",
        "function",
        "axis",
        "language",
        "source_relpath",
        "source_locus",
        "source_hash",
        "matrix_cell_hash",
        "required_action_id",
    }
    for item in items:
        if not isinstance(item, Mapping) or set(item) != expected_fields:
            raise AxisDispositionError("axis worklist v2 item shape mismatch")
        identity_context = {
            "function_identity": item.get("function_identity"),
            "axis": item.get("axis"),
            "source_relpath": item.get("source_relpath"),
            "source_locus": item.get("source_locus"),
            "source_hash": item.get("source_hash"),
            "matrix_cell_hash": item.get("matrix_cell_hash"),
        }
        identity = str(item.get("work_item_id") or "")
        relative = PurePosixPath(str(item.get("source_relpath") or ""))
        if (
            not str(item.get("function_identity") or "").strip()
            or not str(item.get("function") or "").strip()
            or item.get("axis") not in AXES
            or not str(item.get("language") or "").strip()
            or relative.is_absolute()
            or not relative.parts
            or any(part in {"", ".", ".."} for part in relative.parts)
            or ":" in relative.parts[0]
            or str(item.get("source_relpath") or "")
            != relative.as_posix()
            or not re.fullmatch(
                r"L[1-9][0-9]*",
                str(item.get("source_locus") or ""),
                re.ASCII,
            )
            or not _HEX_RE.fullmatch(str(item.get("matrix_cell_hash") or ""))
            or (
                item.get("source_hash")
                and not _HEX_RE.fullmatch(str(item.get("source_hash")))
            )
            or identity != _v2_work_item_id(identity_context)
            or item.get("required_action_id") != _v2_action_id(identity)
        ):
            raise AxisDispositionError("axis worklist v2 item identity mismatch")
        ids.append(identity)
    debt = _v2_string_list(
        worklist.get("input_debt"),
        label="axis worklist v2 input debt",
    )
    status = worklist.get("denominator_status")
    clean_empty = status == "EXACT" and not items and not debt
    if (
        ids != sorted(set(ids))
        or type(worklist.get("count")) is not int
        or worklist.get("count") < 0
        or worklist.get("count") != len(ids)
        or worklist.get("tail") != (ids[-1] if ids else "")
        or type(worklist.get("gap_count")) is not int
        or worklist.get("gap_count") < 0
        or worklist.get("gap_count") < len(ids)
        or (
            status == "EXACT"
            and worklist.get("gap_count") != len(ids)
        )
        or type(worklist.get("observed_hot_function_count")) is not int
        or worklist.get("observed_hot_function_count") < 0
        or status not in _V2_POPULATION_STATES
        or (status == "EXACT" and any(not row["source_hash"] for row in items))
        or bool(worklist.get("clean_empty")) != clean_empty
        or bool(worklist.get("requires_execution")) != (not clean_empty)
        or not _HEX_RE.fullmatch(str(worklist.get("matrix_sha256") or ""))
        or not str(worklist.get("run_id") or "").strip()
    ):
        raise AxisDispositionError("axis worklist v2 denominator mismatch")
    authority = worklist.get("population_authority")
    validate_axis_population_authority(
        authority if isinstance(authority, Mapping) else {},
        expected_run_id=str(worklist["run_id"]),
    )
    if (
        authority.get("observed_hot_function_count")
        != worklist.get("observed_hot_function_count")
        or authority.get("gap_count") != worklist.get("gap_count")
        or (
            authority.get("denominator_status")
            != worklist.get("denominator_status")
            and worklist.get("denominator_status") == "EXACT"
        )
        or authority.get("population_digest")
        != worklist.get("population_authority_digest")
    ):
        raise AxisDispositionError(
            "axis worklist v2 provider binding mismatch"
        )
    return worklist


def load_axis_worklist_v2(path: str | Path) -> dict[str, Any]:
    return _validate_axis_worklist_v2(
        _load_json(Path(path), label="axis worklist v2")
    )


def build_axis_execution_evidence_authority(
    *,
    run_id: str,
    receipt_bindings: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Build an exact current-run pre-axis execution-evidence denominator."""

    run = str(run_id or "").strip()
    if not run:
        raise AxisDispositionError(
            "axis execution-evidence authority run_id is absent"
        )
    normalized: list[dict[str, Any]] = []
    for index, binding in enumerate(receipt_bindings):
        if not isinstance(binding, Mapping) or set(binding) != {
            "receipt",
            "owner_run_id",
            "owner_work_unit_key",
            "owner_phase",
            "eligible_before_axis",
        }:
            raise AxisDispositionError(
                f"axis execution binding {index} shape mismatch"
            )
        try:
            receipt = validate_evidence_receipt(binding["receipt"])
        except (EvidenceCapabilityError, TypeError, ValueError) as exc:
            raise AxisDispositionError(
                f"axis execution binding {index} receipt is invalid: {exc}"
            ) from exc
        if (
            binding.get("owner_run_id") != run
            or binding.get("eligible_before_axis") is not True
            or receipt.get("proof_scope") != "IN_SCOPE_EXECUTION"
            or "EXECUTION" not in receipt.get("capabilities", ())
            or not str(binding.get("owner_work_unit_key") or "").strip()
            or not str(binding.get("owner_phase") or "").strip()
        ):
            raise AxisDispositionError(
                f"axis execution binding {index} is not current pre-axis evidence"
            )
        normalized.append(
            {
                "evidence_id": str(receipt["evidence_id"]),
                "receipt": receipt,
                "receipt_sha256": _digest(receipt),
                "owner_run_id": run,
                "owner_work_unit_key": str(
                    binding["owner_work_unit_key"]
                ),
                "owner_phase": str(binding["owner_phase"]),
                "eligible_before_axis": True,
            }
        )
    normalized.sort(key=lambda row: row["evidence_id"])
    evidence_ids = [row["evidence_id"] for row in normalized]
    if len(evidence_ids) != len(set(evidence_ids)):
        raise AxisDispositionError(
            "axis execution-evidence denominator contains duplicate IDs"
        )
    unsigned = {
        "schema_version": EXECUTION_EVIDENCE_AUTHORITY_SCHEMA,
        "run_id": run,
        "state": "EXACT",
        "boundary": "PRE_AXIS",
        "receipt_count": len(normalized),
        "exact_zero": not normalized,
        "evidence_ids": evidence_ids,
        "receipts": normalized,
    }
    return _v2_signed(unsigned, "authority_digest")


def validate_axis_execution_evidence_authority(
    value: Mapping[str, Any],
    *,
    expected_run_id: str,
) -> dict[str, Any]:
    authority = _v2_validate_signed(
        value,
        schema=EXECUTION_EVIDENCE_AUTHORITY_SCHEMA,
        digest_key="authority_digest",
        label="axis execution-evidence authority",
    )
    if set(authority) != {
        "schema_version",
        "run_id",
        "state",
        "boundary",
        "receipt_count",
        "exact_zero",
        "evidence_ids",
        "receipts",
        "authority_digest",
    }:
        raise AxisDispositionError(
            "axis execution-evidence authority shape mismatch"
        )
    rows = authority.get("receipts")
    if not isinstance(rows, list):
        raise AxisDispositionError(
            "axis execution-evidence receipt collection is malformed"
        )
    ids: list[str] = []
    for index, row in enumerate(rows):
        if not isinstance(row, Mapping) or set(row) != {
            "evidence_id",
            "receipt",
            "receipt_sha256",
            "owner_run_id",
            "owner_work_unit_key",
            "owner_phase",
            "eligible_before_axis",
        }:
            raise AxisDispositionError(
                f"axis execution-evidence row {index} shape mismatch"
            )
        try:
            receipt = validate_evidence_receipt(row["receipt"])
        except (EvidenceCapabilityError, TypeError, ValueError) as exc:
            raise AxisDispositionError(
                f"axis execution-evidence row {index} is invalid: {exc}"
            ) from exc
        if (
            row.get("evidence_id") != receipt.get("evidence_id")
            or row.get("receipt_sha256") != _digest(receipt)
            or row.get("owner_run_id") != str(expected_run_id)
            or row.get("eligible_before_axis") is not True
            or not str(row.get("owner_work_unit_key") or "").strip()
            or not str(row.get("owner_phase") or "").strip()
            or receipt.get("proof_scope") != "IN_SCOPE_EXECUTION"
            or "EXECUTION" not in receipt.get("capabilities", ())
        ):
            raise AxisDispositionError(
                f"axis execution-evidence row {index} binding mismatch"
            )
        ids.append(str(row["evidence_id"]))
    if (
        authority.get("run_id") != str(expected_run_id)
        or authority.get("state") != "EXACT"
        or authority.get("boundary") != "PRE_AXIS"
        or ids != sorted(set(ids))
        or authority.get("evidence_ids") != ids
        or type(authority.get("receipt_count")) is not int
        or authority.get("receipt_count") < 0
        or authority.get("receipt_count") != len(rows)
        or bool(authority.get("exact_zero")) != (not rows)
    ):
        raise AxisDispositionError(
            "axis execution-evidence authority run or denominator mismatch"
        )
    return authority


def parse_axis_model_dispositions(
    raw: bytes,
    *,
    worklist: Mapping[str, Any],
    expected_run_id: str,
    repair_plan_digest: str = "",
) -> dict[str, Any]:
    """Strictly parse the model-owned JSON sidecar.

    Row-level semantic admissibility is reconciled separately so a malformed or
    conflicting row becomes bounded repair work instead of aborting the entire
    phase.  The document itself must still be strict canonical JSON authority.
    """

    checked_worklist = _validate_axis_worklist_v2(worklist)
    payload = _load_json_bytes(bytes(raw), label="axis model dispositions")
    schema = (
        REPAIR_MODEL_DISPOSITIONS_SCHEMA
        if repair_plan_digest
        else MODEL_DISPOSITIONS_SCHEMA
    )
    expected_fields = {
        "schema_version",
        "run_id",
        "worklist_hash",
        "producer",
        "items",
        "sidecar_digest",
    }
    if repair_plan_digest:
        expected_fields.add("repair_plan_digest")
    unsigned = {
        key: value for key, value in payload.items()
        if key != "sidecar_digest"
    }
    if (
        set(payload) != expected_fields
        or payload.get("schema_version") != schema
        or payload.get("run_id") != str(expected_run_id)
        or payload.get("worklist_hash") != checked_worklist["worklist_hash"]
        or payload.get("producer") != "MODEL"
        or not isinstance(payload.get("items"), list)
        or payload.get("sidecar_digest") != _digest(unsigned)
        or (
            repair_plan_digest
            and payload.get("repair_plan_digest") != repair_plan_digest
        )
    ):
        raise AxisDispositionError(
            "axis model dispositions document binding mismatch"
        )
    return payload


def _v2_actions(
    raw: bytes,
) -> tuple[dict[str, dict[str, Any]], set[str], list[str]]:
    try:
        text = bytes(raw).decode("utf-8", errors="strict")
    except UnicodeError as exc:
        return {}, set(), [f"axis action Markdown is not UTF-8: {exc}"]
    actions, duplicate = _action_records(text)
    issues = [
        f"duplicate action heading {identity}"
        for identity in sorted(duplicate)
    ]
    for identity, action in actions.items():
        work_item = _field(action["block_utf8"], "Work Item ID")
        action["work_item_id"] = work_item
        if not work_item:
            issues.append(f"{identity} lacks exact Work Item ID")
    return actions, duplicate, issues


def _v2_execution_by_id(
    authority: Mapping[str, Any],
    *,
    run_id: str,
) -> dict[str, Mapping[str, Any]]:
    validated = validate_axis_execution_evidence_authority(
        authority,
        expected_run_id=run_id,
    )
    return {
        str(row["evidence_id"]): row
        for row in validated["receipts"]
    }


def _v2_clear_evidence_issue(
    evidence: Any,
    *,
    item: Mapping[str, Any],
    execution_by_id: Mapping[str, Mapping[str, Any]],
    canonical_prior_ids: Mapping[str, str],
    canonical_prior_authority_digest: str,
    rationale: str,
) -> tuple[str, str]:
    if (
        not isinstance(evidence, list)
        or len(evidence) != 1
        or not isinstance(evidence[0], Mapping)
    ):
        return "", "CLEAR requires exactly one typed evidence object"
    row = dict(evidence[0])
    kind = str(row.get("kind") or "")
    if kind not in _V2_EVIDENCE_KINDS:
        return "", "CLEAR evidence kind is unsupported"
    if _EXTERNAL_CLEAR_RE.search(str(rationale or "")):
        return "", "favorable external assumptions cannot authorize CLEAR"
    if _V2_GENERIC_CLEAR_RE.fullmatch(_normal(rationale)):
        return "", "generic safe prose cannot authorize CLEAR"
    if kind == "SOURCE_LOCUS":
        if set(row) != {
            "kind",
            "source_relpath",
            "source_locus",
            "source_hash",
        }:
            return "", "SOURCE_LOCUS evidence shape mismatch"
        if (
            row.get("source_relpath") != item.get("source_relpath")
            or row.get("source_locus") != item.get("source_locus")
            or row.get("source_hash") != item.get("source_hash")
            or not _HEX_RE.fullmatch(str(row.get("source_hash") or ""))
        ):
            return "", "SOURCE_LOCUS evidence differs from the work item"
        return "SOURCE_LOCUS", _digest(row)
    if kind == "CANONICAL_PRIOR":
        if set(row) != {
            "kind",
            "canonical_id",
            "authority_digest",
        }:
            return "", "CANONICAL_PRIOR evidence shape mismatch"
        canonical_id = str(row.get("canonical_id") or "")
        valid_ids = {
            str(value)
            for value in canonical_prior_ids.values()
            if str(value)
        }
        if (
            canonical_id not in valid_ids
            or row.get("authority_digest")
            != canonical_prior_authority_digest
            or not _HEX_RE.fullmatch(canonical_prior_authority_digest)
        ):
            return "", "CANONICAL_PRIOR evidence authority is invalid"
        return "CANONICAL_PRIOR", canonical_id
    if set(row) != {
        "kind",
        "evidence_id",
        "receipt_sha256",
    }:
        return "", "EXECUTION_RECEIPT evidence shape mismatch"
    evidence_id = str(row.get("evidence_id") or "")
    binding = execution_by_id.get(evidence_id)
    receipt = binding.get("receipt") if isinstance(binding, Mapping) else None
    if (
        not isinstance(binding, Mapping)
        or row.get("receipt_sha256") != binding.get("receipt_sha256")
        or not isinstance(receipt, Mapping)
        or item.get("work_item_id") not in receipt.get("constituent_ids", ())
    ):
        return "", "EXECUTION_RECEIPT is absent from the current exact authority"
    return "EXECUTION_RECEIPT", evidence_id


def _v2_reconcile_rows(
    worklist: Mapping[str, Any],
    payload: Mapping[str, Any] | None,
    findings_raw: bytes,
    *,
    execution_authority: Mapping[str, Any],
    canonical_prior_ids: Mapping[str, str],
    canonical_prior_authority_digest: str,
    allowed_ids: set[str] | None = None,
    source: str,
) -> tuple[dict[str, dict[str, Any]], list[str]]:
    items = {
        str(item["work_item_id"]): item
        for item in worklist["items"]
    }
    execution_by_id = _v2_execution_by_id(
        execution_authority,
        run_id=str(worklist["run_id"]),
    )
    actions, duplicate_actions, action_issues = _v2_actions(findings_raw)
    issues = list(action_issues)
    raw_rows = payload.get("items", []) if isinstance(payload, Mapping) else []
    rows_by_id: dict[str, list[Mapping[str, Any]]] = {}
    for index, row in enumerate(raw_rows):
        if not isinstance(row, Mapping):
            issues.append(f"{source} disposition row {index} is not an object")
            continue
        identity = str(row.get("work_item_id") or "")
        if identity not in items:
            issues.append(
                f"{source} disposition row {index} has unknown work_item_id"
            )
            continue
        rows_by_id.setdefault(identity, []).append(row)
    action_references = Counter(
        str(row.get("action_id") or "")
        for row in raw_rows
        if isinstance(row, Mapping) and str(row.get("action_id") or "")
    )
    results: dict[str, dict[str, Any]] = {}
    identities = sorted(items)
    if allowed_ids is not None:
        identities = sorted(allowed_ids)
    for identity in identities:
        item = items[identity]
        rows = rows_by_id.get(identity, [])
        base = {
            "work_item_id": identity,
            "source_item": item,
            "source": source,
            "disposition": "",
            "action_id": "",
            "action_block_sha256": "",
            "evidence": [],
            "evidence_kind": "",
            "evidence_reference": "",
            "invariant_commitment": None,
            "rationale": "",
            "application_record_complete": False,
            "reason": "missing disposition",
        }
        if len(rows) != 1:
            if len(rows) > 1:
                base["reason"] = "duplicate or conflicting dispositions"
                issues.append(f"{source} duplicate disposition for {identity}")
            results[identity] = base
            continue
        row = rows[0]
        if set(row) != {
            "work_item_id",
            "disposition",
            "action_id",
            "evidence",
            "invariant_commitment",
            "rationale",
        }:
            base["reason"] = "disposition row shape mismatch"
            results[identity] = base
            continue
        disposition = str(row.get("disposition") or "").upper()
        action_id = str(row.get("action_id") or "").upper()
        rationale = str(row.get("rationale") or "").strip()
        evidence = row.get("evidence")
        raw_commitment = row.get("invariant_commitment")
        base.update(
            {
                "disposition": disposition,
                "action_id": action_id,
                "evidence": evidence if isinstance(evidence, list) else [],
                "rationale": rationale,
            }
        )
        if disposition not in _V2_DISPOSITIONS or not rationale:
            base["reason"] = "invalid disposition enum or empty rationale"
            results[identity] = base
            continue
        if disposition in {"FINDING", "UNRESOLVED"}:
            action = actions.get(action_id)
            if (
                action_id != item["required_action_id"]
                or action_id in duplicate_actions
                or action_references.get(action_id) != 1
                or not isinstance(action, Mapping)
                or action.get("work_item_id") != identity
                or not isinstance(evidence, list)
                or raw_commitment is not None
            ):
                base["reason"] = (
                    "finding/unresolved disposition lacks one unique exact action"
                )
                results[identity] = base
                continue
            base.update(
                {
                    "action_block_sha256": action["block_sha256"],
                    "application_record_complete": True,
                    "reason": "",
                }
            )
            results[identity] = base
            continue
        if action_id:
            base["reason"] = "CLEAR must not reference an action"
            results[identity] = base
            continue
        try:
            invariant_commitment = _normalize_axis_invariant_commitment(
                raw_commitment,
                item=item,
                evidence=evidence,
            )
        except AxisDispositionError as exc:
            base["reason"] = str(exc)
            issues.append(f"{source} {identity}: {exc}")
            results[identity] = base
            continue
        evidence_kind, reference = _v2_clear_evidence_issue(
            evidence,
            item=item,
            execution_by_id=execution_by_id,
            canonical_prior_ids=canonical_prior_ids,
            canonical_prior_authority_digest=(
                canonical_prior_authority_digest
            ),
            rationale=rationale,
        )
        if not evidence_kind:
            base["reason"] = reference
            results[identity] = base
            continue
        base.update(
            {
                "evidence_kind": evidence_kind,
                "evidence_reference": reference,
                "invariant_commitment": invariant_commitment,
                "application_record_complete": True,
                "reason": "",
            }
        )
        results[identity] = base
    id_counts = Counter(
        str(row.get("invariant_commitment", {}).get("ci_id") or "")
        for row in results.values()
        if row.get("application_record_complete") is True
        and row.get("disposition") == "CLEAR"
        and isinstance(row.get("invariant_commitment"), Mapping)
    )
    block_counts = Counter(
        str(
            row.get("invariant_commitment", {}).get(
                "ci_block_sha256"
            ) or ""
        )
        for row in results.values()
        if row.get("application_record_complete") is True
        and row.get("disposition") == "CLEAR"
        and isinstance(row.get("invariant_commitment"), Mapping)
    )
    duplicate_ids = {key for key, count in id_counts.items() if key and count > 1}
    duplicate_blocks = {
        key for key, count in block_counts.items() if key and count > 1
    }
    for identity, row in results.items():
        commitment = row.get("invariant_commitment")
        if (
            row.get("application_record_complete") is True
            and row.get("disposition") == "CLEAR"
            and isinstance(commitment, Mapping)
            and (
                commitment.get("ci_id") in duplicate_ids
                or commitment.get("ci_block_sha256") in duplicate_blocks
            )
        ):
            row["application_record_complete"] = False
            row["reason"] = (
                "axis committed-invariant identity/block is reused across rows"
            )
            issues.append(f"{source} {identity}: {row['reason']}")
    if allowed_ids is not None:
        for identity in sorted(set(rows_by_id) - set(allowed_ids)):
            issues.append(
                f"{source} disposition {identity} is outside the repair plan"
            )
    return results, sorted(set(issues))


def _v2_repair_plan(
    worklist: Mapping[str, Any],
    initial_digest: str,
    unresolved: Sequence[str],
    *,
    repair_cap: int,
    reasons: Mapping[str, str],
) -> dict[str, Any]:
    if type(repair_cap) is not int or repair_cap < 0:
        raise AxisDispositionError("axis v2 repair cap is invalid")
    all_ids = list(unresolved)
    retained = all_ids[:repair_cap]
    omitted = all_ids[repair_cap:]
    items_by_id = {
        row["work_item_id"]: row for row in worklist["items"]
    }
    unsigned = {
        "schema_version": REPAIR_PLAN_SCHEMA,
        "run_id": worklist["run_id"],
        "worklist_hash": worklist["worklist_hash"],
        "initial_receipt_digest": initial_digest,
        "repair_cap": repair_cap,
        "observed_count": len(all_ids),
        "retained_count": len(retained),
        "omitted_count": len(omitted),
        "retained_work_item_ids": retained,
        "omitted_work_item_ids": omitted,
        "items": [
            {
                "work_item_id": identity,
                "source_item": items_by_id[identity],
                "reason": reasons.get(identity, "unresolved disposition"),
            }
            for identity in retained
        ],
        "overflow": bool(omitted),
    }
    return _v2_signed(unsigned, "plan_digest")


def _validate_v2_disposition_projection(
    dispositions: Any,
    worklist: Mapping[str, Any],
    *,
    allowed_sources: frozenset[str],
) -> list[dict[str, Any]]:
    if not isinstance(dispositions, list):
        raise AxisDispositionError(
            "axis disposition projection is not a list"
        )
    expected_fields = {
        "work_item_id",
        "source_item",
        "source",
        "disposition",
        "action_id",
        "action_block_sha256",
        "evidence",
        "evidence_kind",
        "evidence_reference",
        "invariant_commitment",
        "rationale",
        "application_record_complete",
        "reason",
    }
    work_items = {
        str(row["work_item_id"]): row for row in worklist["items"]
    }
    expected_ids = list(work_items)
    observed_ids: list[str] = []
    normalized: list[dict[str, Any]] = []
    for index, raw in enumerate(dispositions):
        if not isinstance(raw, Mapping) or set(raw) != expected_fields:
            raise AxisDispositionError(
                f"axis disposition projection row {index} shape mismatch"
            )
        row = dict(raw)
        identity = str(row.get("work_item_id") or "")
        complete = row.get("application_record_complete")
        disposition = str(row.get("disposition") or "")
        action_id = str(row.get("action_id") or "")
        action_hash = str(row.get("action_block_sha256") or "")
        if (
            identity not in work_items
            or row.get("source_item") != work_items[identity]
            or row.get("source") not in allowed_sources
            or complete not in {True, False}
            or not isinstance(row.get("evidence"), list)
            or not isinstance(row.get("rationale"), str)
            or not isinstance(row.get("reason"), str)
            or not isinstance(row.get("evidence_kind"), str)
            or not isinstance(row.get("evidence_reference"), str)
        ):
            raise AxisDispositionError(
                f"axis disposition projection row {index} binding mismatch"
            )
        if complete is True:
            if not row["rationale"] or row["reason"]:
                raise AxisDispositionError(
                    f"axis disposition projection row {index} lacks rationale"
                )
            if disposition in {"FINDING", "UNRESOLVED"}:
                if (
                    action_id != work_items[identity]["required_action_id"]
                    or not _HEX_RE.fullmatch(action_hash)
                    or row["evidence_kind"]
                    or row["evidence_reference"]
                    or row["invariant_commitment"] is not None
                ):
                    raise AxisDispositionError(
                        f"axis disposition projection row {index} action mismatch"
                    )
            elif disposition == "CLEAR":
                if (
                    action_id
                    or action_hash
                    or row["evidence_kind"] not in _V2_EVIDENCE_KINDS
                    or not row["evidence_reference"]
                    or not isinstance(
                        row.get("invariant_commitment"), Mapping
                    )
                ):
                    raise AxisDispositionError(
                        f"axis disposition projection row {index} CLEAR mismatch"
                    )
                _validate_normalized_axis_invariant_commitment(
                    row["invariant_commitment"],
                    item=work_items[identity],
                    evidence=row["evidence"],
                )
            else:
                raise AxisDispositionError(
                    f"axis disposition projection row {index} enum mismatch"
                )
        elif not row["reason"]:
            raise AxisDispositionError(
                f"axis incomplete disposition row {index} lacks debt reason"
            )
        observed_ids.append(identity)
        normalized.append(row)
    if observed_ids != expected_ids:
        raise AxisDispositionError(
            "axis disposition projection denominator mismatch"
        )
    complete_clear_commitments = [
        row["invariant_commitment"]
        for row in normalized
        if row.get("application_record_complete") is True
        and row.get("disposition") == "CLEAR"
    ]
    ci_ids = [str(row.get("ci_id") or "") for row in complete_clear_commitments]
    block_digests = [
        str(row.get("ci_block_sha256") or "")
        for row in complete_clear_commitments
    ]
    if len(ci_ids) != len(set(ci_ids)) or len(block_digests) != len(
        set(block_digests)
    ):
        raise AxisDispositionError(
            "axis committed-invariant identity/block is not row-global one-to-one"
        )
    return normalized


def reconcile_axis_dispositions_initial(
    worklist: Mapping[str, Any],
    *,
    base_dispositions_raw: bytes,
    base_findings_raw: bytes,
    execution_evidence_authority: Mapping[str, Any],
    canonical_prior_ids: Mapping[str, str],
    canonical_prior_authority_digest: str,
    repair_cap: int,
) -> tuple[dict[str, Any], dict[str, Any]]:
    checked = _validate_axis_worklist_v2(worklist)
    authority = validate_axis_execution_evidence_authority(
        execution_evidence_authority,
        expected_run_id=str(checked["run_id"]),
    )
    document_issues: list[str] = []
    try:
        payload = parse_axis_model_dispositions(
            bytes(base_dispositions_raw),
            worklist=checked,
            expected_run_id=str(checked["run_id"]),
        )
    except AxisDispositionError as exc:
        payload = None
        document_issues.append(str(exc))
    rows, row_issues = _v2_reconcile_rows(
        checked,
        payload,
        bytes(base_findings_raw),
        execution_authority=authority,
        canonical_prior_ids=canonical_prior_ids,
        canonical_prior_authority_digest=(
            canonical_prior_authority_digest
        ),
        source="BASE",
    )
    dispositions = [rows[item["work_item_id"]] for item in checked["items"]]
    unresolved = [
        row["work_item_id"]
        for row in dispositions
        if row["application_record_complete"] is not True
    ]
    reasons = {row["work_item_id"]: row["reason"] for row in dispositions}
    issues = sorted(set([*document_issues, *row_issues]))
    status = "REPAIR_REQUIRED" if unresolved else "COMPLETE"
    unsigned = {
        "schema_version": INITIAL_RECEIPT_SCHEMA,
        "run_id": checked["run_id"],
        "worklist_hash": checked["worklist_hash"],
        "base_dispositions_sha256": _bytes_digest(
            bytes(base_dispositions_raw)
        ),
        "base_findings_sha256": _bytes_digest(bytes(base_findings_raw)),
        "execution_evidence_authority_digest": authority[
            "authority_digest"
        ],
        "canonical_prior_authority_digest": str(
            canonical_prior_authority_digest
        ),
        "dispositions": dispositions,
        "unresolved_work_item_ids": unresolved,
        "issues": issues,
        "application_record_complete": not unresolved,
        "status": status,
    }
    initial = _v2_signed(unsigned, "initial_receipt_digest")
    plan = _v2_repair_plan(
        checked,
        initial["initial_receipt_digest"],
        unresolved,
        repair_cap=repair_cap,
        reasons=reasons,
    )
    return initial, plan


def _validate_v2_initial_receipt(
    value: Mapping[str, Any],
    worklist: Mapping[str, Any],
) -> dict[str, Any]:
    receipt = _v2_validate_signed(
        value,
        schema=INITIAL_RECEIPT_SCHEMA,
        digest_key="initial_receipt_digest",
        label="axis initial disposition receipt",
    )
    if set(receipt) != {
        "schema_version",
        "run_id",
        "worklist_hash",
        "base_dispositions_sha256",
        "base_findings_sha256",
        "execution_evidence_authority_digest",
        "canonical_prior_authority_digest",
        "dispositions",
        "unresolved_work_item_ids",
        "issues",
        "application_record_complete",
        "status",
        "initial_receipt_digest",
    }:
        raise AxisDispositionError(
            "axis initial disposition receipt shape mismatch"
        )
    _v2_string_list(
        receipt.get("issues"),
        label="axis initial disposition issues",
    )
    dispositions = _validate_v2_disposition_projection(
        receipt.get("dispositions"),
        worklist,
        allowed_sources=frozenset({"BASE"}),
    )
    work_ids = [row["work_item_id"] for row in worklist["items"]]
    row_ids = [
        str(row.get("work_item_id") or "")
        for row in dispositions
    ]
    unresolved = [
        str(row["work_item_id"])
        for row in dispositions
        if row.get("application_record_complete") is not True
    ]
    if (
        receipt.get("run_id") != worklist["run_id"]
        or receipt.get("worklist_hash") != worklist["worklist_hash"]
        or row_ids != work_ids
        or len(row_ids) != len(dispositions)
        or receipt.get("unresolved_work_item_ids") != unresolved
        or bool(receipt.get("application_record_complete"))
        != (not unresolved)
        or receipt.get("status")
        != ("REPAIR_REQUIRED" if unresolved else "COMPLETE")
    ):
        raise AxisDispositionError(
            "axis initial disposition receipt denominator mismatch"
        )
    return receipt


def _validate_v2_repair_plan(
    value: Mapping[str, Any],
    worklist: Mapping[str, Any],
    initial_receipt: Mapping[str, Any],
) -> dict[str, Any]:
    plan = _v2_validate_signed(
        value,
        schema=REPAIR_PLAN_SCHEMA,
        digest_key="plan_digest",
        label="axis repair plan",
    )
    if set(plan) != {
        "schema_version",
        "run_id",
        "worklist_hash",
        "initial_receipt_digest",
        "repair_cap",
        "observed_count",
        "retained_count",
        "omitted_count",
        "retained_work_item_ids",
        "omitted_work_item_ids",
        "items",
        "overflow",
        "plan_digest",
    }:
        raise AxisDispositionError("axis repair plan shape mismatch")
    retained = _v2_string_list(
        plan.get("retained_work_item_ids"),
        label="axis repair retained identities",
    )
    omitted = _v2_string_list(
        plan.get("omitted_work_item_ids"),
        label="axis repair omitted identities",
    )
    all_ids = [*retained, *omitted]
    repair_cap = plan.get("repair_cap")
    expected_unresolved = list(initial_receipt["unresolved_work_item_ids"])
    expected_retained = (
        expected_unresolved[:repair_cap]
        if type(repair_cap) is int and repair_cap >= 0
        else []
    )
    expected_omitted = (
        expected_unresolved[repair_cap:]
        if type(repair_cap) is int and repair_cap >= 0
        else []
    )
    work_by_id = {
        str(row["work_item_id"]): row for row in worklist["items"]
    }
    reasons = {
        str(row.get("work_item_id") or ""): str(row.get("reason") or "")
        for row in initial_receipt["dispositions"]
        if isinstance(row, Mapping)
    }
    expected_items = [
        {
            "work_item_id": identity,
            "source_item": work_by_id[identity],
            "reason": reasons[identity],
        }
        for identity in expected_retained
    ]
    if (
        type(repair_cap) is not int
        or repair_cap < 0
        or any(
            type(plan.get(field)) is not int or plan.get(field) < 0
            for field in (
                "observed_count",
                "retained_count",
                "omitted_count",
            )
        )
        or len(all_ids) != len(set(all_ids))
        or all_ids != expected_unresolved
        or retained != expected_retained
        or omitted != expected_omitted
        or plan.get("run_id") != worklist["run_id"]
        or plan.get("worklist_hash") != worklist["worklist_hash"]
        or plan.get("initial_receipt_digest")
        != initial_receipt["initial_receipt_digest"]
        or plan.get("observed_count") != len(all_ids)
        or plan.get("retained_count") != len(retained)
        or plan.get("omitted_count") != len(omitted)
        or bool(plan.get("overflow")) != bool(omitted)
        or plan.get("items") != expected_items
    ):
        raise AxisDispositionError("axis repair plan denominator mismatch")
    return plan


def validate_axis_repair_model_outputs(
    worklist: Mapping[str, Any],
    *,
    initial_receipt: Mapping[str, Any],
    repair_plan: Mapping[str, Any],
    repair_dispositions_raw: bytes,
    repair_findings_raw: bytes,
    execution_evidence_authority: Mapping[str, Any],
    canonical_prior_ids: Mapping[str, str],
    canonical_prior_authority_digest: str,
) -> dict[str, Any]:
    """Validate one complete bounded repair pair before MODEL commit.

    A PhaseIO artifact receipt proves only that bytes were written by the
    contracted producer.  It is not semantic authority.  This gate therefore
    applies the same strict parser and row/action/evidence reconciliation used
    by final reconciliation *before* the repair worker can be stamped
    ``EXECUTED``.  Every retained plan identity must occur exactly once, in
    plan order, and must yield a complete application record.
    """

    checked = _validate_axis_worklist_v2(worklist)
    initial = _validate_v2_initial_receipt(initial_receipt, checked)
    plan = _validate_v2_repair_plan(repair_plan, checked, initial)
    authority = validate_axis_execution_evidence_authority(
        execution_evidence_authority,
        expected_run_id=str(checked["run_id"]),
    )
    dispositions_raw = bytes(repair_dispositions_raw)
    findings_raw = bytes(repair_findings_raw)
    if not dispositions_raw or not findings_raw:
        raise AxisDispositionError(
            "axis repair semantic pair is incomplete"
        )
    payload = parse_axis_model_dispositions(
        dispositions_raw,
        worklist=checked,
        expected_run_id=str(checked["run_id"]),
        repair_plan_digest=str(plan["plan_digest"]),
    )
    retained = [
        str(value) for value in plan["retained_work_item_ids"]
    ]
    raw_ids = [
        str(row.get("work_item_id") or "")
        for row in payload.get("items", ())
        if isinstance(row, Mapping)
    ]
    if (
        len(raw_ids) != len(payload.get("items", ()))
        or raw_ids != retained
        or len(raw_ids) != len(set(raw_ids))
    ):
        raise AxisDispositionError(
            "axis repair disposition denominator differs from the retained "
            "repair plan"
        )
    action_rows, duplicate_actions, action_issues = _v2_actions(findings_raw)
    referenced_action_ids = {
        str(row.get("action_id") or "").upper()
        for row in payload.get("items", ())
        if isinstance(row, Mapping)
        and str(row.get("disposition") or "").upper()
        in {"FINDING", "UNRESOLVED"}
        and str(row.get("action_id") or "").strip()
    }
    observed_action_ids = set(action_rows)
    if (
        duplicate_actions
        or action_issues
        or observed_action_ids != referenced_action_ids
    ):
        details = list(action_issues)
        if duplicate_actions:
            details.append(
                "duplicate repair action(s): "
                + ", ".join(sorted(duplicate_actions))
            )
        extras = sorted(observed_action_ids - referenced_action_ids)
        missing = sorted(referenced_action_ids - observed_action_ids)
        if extras:
            details.append(
                "unreferenced repair action(s): " + ", ".join(extras)
            )
        if missing:
            details.append(
                "missing referenced repair action(s): " + ", ".join(missing)
            )
        raise AxisDispositionError(
            "axis repair action denominator is not exact: "
            + "; ".join(sorted(set(details)))
        )
    rows, row_issues = _v2_reconcile_rows(
        checked,
        payload,
        findings_raw,
        execution_authority=authority,
        canonical_prior_ids=canonical_prior_ids,
        canonical_prior_authority_digest=(
            canonical_prior_authority_digest
        ),
        allowed_ids=set(retained),
        source="REPAIR",
    )
    incomplete = [
        identity for identity in retained
        if not isinstance(rows.get(identity), Mapping)
        or rows[identity].get("application_record_complete") is not True
    ]
    if row_issues or incomplete:
        details = list(row_issues)
        if incomplete:
            details.append(
                "incomplete retained repair disposition(s): "
                + ", ".join(incomplete)
            )
        raise AxisDispositionError(
            "axis repair semantic validation failed: "
            + "; ".join(sorted(set(details)))
        )
    return {
        "payload": payload,
        "rows": [rows[identity] for identity in retained],
        "retained_work_item_ids": retained,
    }


def _validate_axis_repair_execution_plan_identity(
    repair_plan: Mapping[str, Any],
) -> dict[str, Any]:
    """Validate the self-contained plan identity used at terminal boundaries."""

    plan = _v2_validate_signed(
        repair_plan,
        schema=REPAIR_PLAN_SCHEMA,
        digest_key="plan_digest",
        label="axis repair execution plan",
    )
    if set(plan) != {
        "schema_version",
        "run_id",
        "worklist_hash",
        "initial_receipt_digest",
        "repair_cap",
        "observed_count",
        "retained_count",
        "omitted_count",
        "retained_work_item_ids",
        "omitted_work_item_ids",
        "items",
        "overflow",
        "plan_digest",
    }:
        raise AxisDispositionError("axis repair execution plan shape mismatch")
    retained = _v2_string_list(
        plan.get("retained_work_item_ids"),
        label="axis repair execution retained identities",
    )
    omitted = _v2_string_list(
        plan.get("omitted_work_item_ids"),
        label="axis repair execution omitted identities",
    )
    items = plan.get("items")
    item_ids = (
        [
            str(item.get("work_item_id") or "")
            for item in items
            if isinstance(item, Mapping)
        ]
        if isinstance(items, list)
        else []
    )
    integer_fields = (
        plan.get("repair_cap"),
        plan.get("observed_count"),
        plan.get("retained_count"),
        plan.get("omitted_count"),
    )
    if (
        not str(plan.get("run_id") or "").strip()
        or not _HEX_RE.fullmatch(str(plan.get("worklist_hash") or ""))
        or not _HEX_RE.fullmatch(
            str(plan.get("initial_receipt_digest") or "")
        )
        or any(type(value) is not int or value < 0 for value in integer_fields)
        or len([*retained, *omitted]) != len(set([*retained, *omitted]))
        or int(plan["observed_count"]) != len(retained) + len(omitted)
        or int(plan["retained_count"]) != len(retained)
        or int(plan["omitted_count"]) != len(omitted)
        or int(plan["retained_count"]) > int(plan["repair_cap"])
        or type(plan.get("overflow")) is not bool
        or bool(plan["overflow"]) != bool(omitted)
        or not isinstance(items, list)
        or len(item_ids) != len(items)
        or item_ids != retained
    ):
        raise AxisDispositionError(
            "axis repair execution plan denominator mismatch"
        )
    return plan


def build_axis_repair_execution_receipt(
    repair_plan: Mapping[str, Any],
    *,
    state: str,
    repair_dispositions_raw: bytes | None = None,
    repair_findings_raw: bytes | None = None,
    issues: Sequence[str] = (),
) -> dict[str, Any]:
    plan = _validate_axis_repair_execution_plan_identity(repair_plan)
    terminal = str(state or "").upper()
    if terminal not in _V2_REPAIR_STATES:
        raise AxisDispositionError("axis repair execution state is invalid")
    observed = int(plan.get("observed_count") or 0)
    overflow = bool(plan.get("overflow"))
    dispositions_raw = (
        bytes(repair_dispositions_raw)
        if repair_dispositions_raw is not None else b""
    )
    findings_raw = (
        bytes(repair_findings_raw)
        if repair_findings_raw is not None else b""
    )
    issue_rows = sorted(
        set(str(value).strip() for value in issues if str(value).strip())
    )
    if terminal == "NOT_REQUIRED" and observed != 0:
        raise AxisDispositionError(
            "axis repair cannot be NOT_REQUIRED with pending work"
        )
    if terminal == "NOT_REQUIRED" and (
        dispositions_raw or findings_raw or issue_rows
    ):
        raise AxisDispositionError(
            "axis NOT_REQUIRED repair receipt cannot claim execution or debt"
        )
    if terminal == "EXECUTED" and (
        observed == 0
        or overflow
        or not dispositions_raw
        or not findings_raw
        or issue_rows
    ):
        raise AxisDispositionError(
            "axis EXECUTED repair receipt is not exact"
        )
    if terminal == "FAILED" and not issue_rows:
        raise AxisDispositionError(
            "axis FAILED repair receipt lacks debt"
        )
    if terminal == "OVERFLOW" and (observed == 0 or not overflow):
        raise AxisDispositionError(
            "axis OVERFLOW repair receipt lacks overflow authority"
        )
    if (
        terminal == "OVERFLOW"
        and int(plan.get("retained_count") or 0) > 0
        and (not dispositions_raw or not findings_raw)
    ):
        raise AxisDispositionError(
            "axis OVERFLOW repair did not execute its retained denominator"
        )
    if (
        terminal == "OVERFLOW"
        and int(plan.get("retained_count") or 0) == 0
        and (dispositions_raw or findings_raw)
    ):
        raise AxisDispositionError(
            "axis cap-zero OVERFLOW cannot claim repair execution bytes"
        )
    unsigned = {
        "schema_version": REPAIR_EXECUTION_RECEIPT_SCHEMA,
        "run_id": str(plan.get("run_id") or ""),
        "repair_plan_digest": str(plan.get("plan_digest") or ""),
        "state": terminal,
        "worker_executed": bool(dispositions_raw or findings_raw),
        "repair_dispositions_sha256": (
            _bytes_digest(dispositions_raw) if dispositions_raw else ""
        ),
        "repair_findings_sha256": (
            _bytes_digest(findings_raw) if findings_raw else ""
        ),
        "issues": issue_rows,
    }
    return _v2_signed(unsigned, "execution_digest")


def validate_axis_repair_execution_receipt(
    value: Mapping[str, Any],
    repair_plan: Mapping[str, Any],
    *,
    expected_run_id: str,
    repair_dispositions_raw: bytes | None = None,
    repair_findings_raw: bytes | None = None,
) -> dict[str, Any]:
    plan = _validate_axis_repair_execution_plan_identity(repair_plan)
    if str(plan.get("run_id") or "") != str(expected_run_id):
        raise AxisDispositionError(
            "axis repair execution plan run binding mismatch"
        )
    receipt = _v2_validate_signed(
        value,
        schema=REPAIR_EXECUTION_RECEIPT_SCHEMA,
        digest_key="execution_digest",
        label="axis repair execution receipt",
    )
    if set(receipt) != {
        "schema_version",
        "run_id",
        "repair_plan_digest",
        "state",
        "worker_executed",
        "repair_dispositions_sha256",
        "repair_findings_sha256",
        "issues",
        "execution_digest",
    }:
        raise AxisDispositionError(
            "axis repair execution receipt shape mismatch"
        )
    issue_rows = _v2_string_list(
        receipt.get("issues"),
        label="axis repair execution issues",
    )
    state = receipt.get("state")
    observed = int(plan.get("observed_count") or 0)
    overflow = bool(plan.get("overflow"))
    dispositions_raw = (
        bytes(repair_dispositions_raw)
        if repair_dispositions_raw is not None else b""
    )
    findings_raw = (
        bytes(repair_findings_raw)
        if repair_findings_raw is not None else b""
    )
    # FAILED is the terminal authority for an attempted worker whose outputs
    # were not accepted. Partial/malformed bytes may remain for forensics, but
    # they are not execution evidence and cannot poison valid BASE rows.
    bound_dispositions_raw = (
        b"" if state == "FAILED" else dispositions_raw
    )
    bound_findings_raw = b"" if state == "FAILED" else findings_raw
    if (
        state not in _V2_REPAIR_STATES
        or receipt.get("run_id") != plan.get("run_id")
        or receipt.get("repair_plan_digest") != plan.get("plan_digest")
        or receipt.get("repair_dispositions_sha256")
        != (
            _bytes_digest(bound_dispositions_raw)
            if bound_dispositions_raw else ""
        )
        or receipt.get("repair_findings_sha256")
        != (_bytes_digest(bound_findings_raw) if bound_findings_raw else "")
        or bool(receipt.get("worker_executed"))
        != bool(bound_dispositions_raw or bound_findings_raw)
        or (state == "NOT_REQUIRED" and observed != 0)
        or (
            state == "EXECUTED"
            and (
                observed == 0
                or overflow
                or not dispositions_raw
                or not findings_raw
                or issue_rows
            )
        )
        or (
            state == "NOT_REQUIRED"
            and (
                dispositions_raw
                or findings_raw
                or issue_rows
            )
        )
        or (state == "FAILED" and not issue_rows)
        or (
            state == "OVERFLOW"
            and (
                observed == 0
                or not overflow
                or (
                    int(plan.get("retained_count") or 0) > 0
                    and (not dispositions_raw or not findings_raw)
                )
                or (
                    int(plan.get("retained_count") or 0) == 0
                    and (dispositions_raw or findings_raw)
                )
            )
        )
    ):
        raise AxisDispositionError(
            "axis repair execution receipt binding mismatch"
        )
    return receipt


def _v2_debt_item(
    *,
    debt_kind: str,
    message: str,
    work_item_id: str = "",
) -> dict[str, Any]:
    unsigned = {
        "debt_kind": str(debt_kind),
        "work_item_id": str(work_item_id),
        "message": str(message),
        "finding_disposition_authority": "NONE",
        "severity_effect": "NONE",
    }
    return _v2_signed(unsigned, "debt_digest")


def _v2_residual_and_assurance(
    worklist: Mapping[str, Any],
    dispositions: Sequence[Mapping[str, Any]],
    issues: Sequence[str],
    repair_execution: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    residual = [
        str(row["work_item_id"])
        for row in dispositions
        if row.get("application_record_complete") is not True
    ]
    repair_unsigned = {
        "schema_version": REPAIR_WORK_V2_SCHEMA,
        "run_id": worklist["run_id"],
        "worklist_hash": worklist["worklist_hash"],
        "count": len(residual),
        "work_item_ids": residual,
        "items": [
            {
                "work_item_id": row["work_item_id"],
                "source_item": row["source_item"],
                "reason": row["reason"],
            }
            for row in dispositions
            if row.get("application_record_complete") is not True
        ],
    }
    repair_work = _v2_signed(repair_unsigned, "repair_work_digest")
    debt_items: list[dict[str, Any]] = []
    if worklist["denominator_status"] != "EXACT":
        debt_items.append(
            _v2_debt_item(
                debt_kind="POPULATION_STATUS",
                message=(
                    "axis population denominator is "
                    f"{worklist['denominator_status']}"
                ),
            )
        )
    for message in worklist["input_debt"]:
        debt_items.append(
            _v2_debt_item(
                debt_kind="POPULATION_INPUT",
                message=message,
            )
        )
    for row in dispositions:
        if row.get("application_record_complete") is not True:
            debt_items.append(
                _v2_debt_item(
                    debt_kind="UNRESOLVED_WORK_ITEM",
                    message=str(row.get("reason") or "unresolved"),
                    work_item_id=str(row["work_item_id"]),
                )
            )
    if repair_execution.get("state") in {"FAILED", "OVERFLOW"}:
        debt_items.append(
            _v2_debt_item(
                debt_kind=f"REPAIR_{repair_execution['state']}",
                message=(
                    "; ".join(repair_execution.get("issues") or ())
                    or f"repair ended {repair_execution['state']}"
                ),
            )
        )
    for issue in sorted(set(str(value) for value in issues if str(value))):
        debt_items.append(
            _v2_debt_item(
                debt_kind="RECONCILIATION_ISSUE",
                message=issue,
            )
        )
    unique = {
        row["debt_digest"]: row
        for row in debt_items
    }
    ordered = [unique[key] for key in sorted(unique)]
    assurance_unsigned = {
        "schema_version": ASSURANCE_DEBT_V2_SCHEMA,
        "run_id": worklist["run_id"],
        "worklist_hash": worklist["worklist_hash"],
        "count": len(ordered),
        "items": ordered,
    }
    assurance = _v2_signed(assurance_unsigned, "assurance_digest")
    return repair_work, assurance


def reconcile_axis_dispositions_final(
    worklist: Mapping[str, Any],
    *,
    initial_receipt: Mapping[str, Any],
    repair_plan: Mapping[str, Any],
    repair_execution_receipt: Mapping[str, Any],
    base_findings_raw: bytes,
    execution_evidence_authority: Mapping[str, Any],
    canonical_prior_ids: Mapping[str, str],
    canonical_prior_authority_digest: str,
    repair_dispositions_raw: bytes | None = None,
    repair_findings_raw: bytes | None = None,
) -> dict[str, Any]:
    """Merge one bounded repair without permitting base-row replacement."""

    checked = _validate_axis_worklist_v2(worklist)
    initial = _validate_v2_initial_receipt(initial_receipt, checked)
    if initial.get("base_findings_sha256") != _bytes_digest(
        bytes(base_findings_raw)
    ):
        raise AxisDispositionError(
            "axis base finding bytes differ from the initial receipt"
        )
    authority = validate_axis_execution_evidence_authority(
        execution_evidence_authority,
        expected_run_id=str(checked["run_id"]),
    )
    if (
        initial.get("execution_evidence_authority_digest")
        != authority["authority_digest"]
        or initial.get("canonical_prior_authority_digest")
        != canonical_prior_authority_digest
    ):
        raise AxisDispositionError(
            "axis final reconciliation authority changed"
        )
    plan = _validate_v2_repair_plan(
        repair_plan,
        checked,
        initial,
    )
    execution = validate_axis_repair_execution_receipt(
        repair_execution_receipt,
        plan,
        expected_run_id=str(checked["run_id"]),
        repair_dispositions_raw=repair_dispositions_raw,
        repair_findings_raw=repair_findings_raw,
    )
    base_by_id = {
        str(row["work_item_id"]): dict(row)
        for row in initial["dispositions"]
    }
    final_by_id = dict(base_by_id)
    # Retain initial problems in the audit trail.  A successful exact repair
    # may close those problems, so only defects observed in the repair/merge
    # transaction remain assurance debt.
    issues = list(initial.get("issues") or ())
    assurance_issues: list[str] = []
    repair_rows: dict[str, dict[str, Any]] = {}
    if execution["state"] in {"EXECUTED", "OVERFLOW"} and (
        repair_dispositions_raw or repair_findings_raw
    ):
        try:
            repair_payload = parse_axis_model_dispositions(
                bytes(repair_dispositions_raw or b""),
                worklist=checked,
                expected_run_id=str(checked["run_id"]),
                repair_plan_digest=plan["plan_digest"],
            )
        except AxisDispositionError as exc:
            repair_payload = None
            issues.append(str(exc))
            assurance_issues.append(str(exc))
        repair_rows, repair_issues = _v2_reconcile_rows(
            checked,
            repair_payload,
            bytes(repair_findings_raw or b""),
            execution_authority=authority,
            canonical_prior_ids=canonical_prior_ids,
            canonical_prior_authority_digest=(
                canonical_prior_authority_digest
            ),
            allowed_ids=set(plan["retained_work_item_ids"]),
            source="REPAIR",
        )
        issues.extend(repair_issues)
        assurance_issues.extend(repair_issues)
        raw_repair_ids = {
            str(row.get("work_item_id") or "")
            for row in (
                repair_payload.get("items", [])
                if isinstance(repair_payload, Mapping) else []
            )
            if isinstance(row, Mapping)
        }
        for identity in sorted(
            raw_repair_ids - set(plan["retained_work_item_ids"])
        ):
            issues.append(
                f"REPAIR disposition {identity} is outside the repair plan"
            )
            assurance_issues.append(
                f"REPAIR disposition {identity} is outside the repair plan"
            )
    for identity in plan["retained_work_item_ids"]:
        base = base_by_id[identity]
        repair = repair_rows.get(identity)
        if base.get("application_record_complete") is True:
            if repair is not None:
                issues.append(
                    f"repair attempted to override valid base row {identity}"
                )
                assurance_issues.append(
                    f"repair attempted to override valid base row {identity}"
                )
            continue
        if (
            isinstance(repair, Mapping)
            and repair.get("application_record_complete") is True
        ):
            final_by_id[identity] = dict(repair)
        elif isinstance(repair, Mapping):
            final_by_id[identity] = dict(repair)
    dispositions = [
        final_by_id[item["work_item_id"]]
        for item in checked["items"]
    ]
    final_ci_ids = Counter(
        str(row.get("invariant_commitment", {}).get("ci_id") or "")
        for row in dispositions
        if row.get("application_record_complete") is True
        and row.get("disposition") == "CLEAR"
        and isinstance(row.get("invariant_commitment"), Mapping)
    )
    final_ci_blocks = Counter(
        str(
            row.get("invariant_commitment", {}).get(
                "ci_block_sha256"
            ) or ""
        )
        for row in dispositions
        if row.get("application_record_complete") is True
        and row.get("disposition") == "CLEAR"
        and isinstance(row.get("invariant_commitment"), Mapping)
    )
    reused_ids = {key for key, count in final_ci_ids.items() if key and count > 1}
    reused_blocks = {
        key for key, count in final_ci_blocks.items() if key and count > 1
    }
    if reused_ids or reused_blocks:
        for row in dispositions:
            commitment = row.get("invariant_commitment")
            if (
                row.get("application_record_complete") is True
                and row.get("disposition") == "CLEAR"
                and isinstance(commitment, Mapping)
                and (
                    commitment.get("ci_id") in reused_ids
                    or commitment.get("ci_block_sha256") in reused_blocks
                )
            ):
                row["application_record_complete"] = False
                row["reason"] = (
                    "axis committed-invariant identity/block is reused across "
                    "base/repair rows"
                )
                issue = f"FINAL {row['work_item_id']}: {row['reason']}"
                issues.append(issue)
                assurance_issues.append(issue)
    repair_work, assurance = _v2_residual_and_assurance(
        checked,
        dispositions,
        assurance_issues,
        execution,
    )
    residual = repair_work["work_item_ids"]
    complete = (
        checked["denominator_status"] == "EXACT"
        and not checked["input_debt"]
        and not residual
        and not assurance["items"]
    )
    unsigned = {
        "schema_version": APPLICATION_RECEIPT_V2_SCHEMA,
        "run_id": checked["run_id"],
        "worklist_hash": checked["worklist_hash"],
        "initial_receipt_digest": initial["initial_receipt_digest"],
        "repair_plan_digest": plan["plan_digest"],
        "repair_execution_digest": execution["execution_digest"],
        "execution_evidence_authority_digest": authority[
            "authority_digest"
        ],
        "canonical_prior_authority_digest": str(
            canonical_prior_authority_digest
        ),
        "dispositions": dispositions,
        "residual_work_item_ids": residual,
        "issues": sorted(set(str(value) for value in issues if str(value))),
        "repair_work": repair_work,
        "assurance_debt": assurance,
        "application_record_complete": complete,
        "status": "COMPLETE" if complete else "COMPLETED_WITH_DEBT",
    }
    return _v2_signed(unsigned, "application_receipt_digest")


def _validate_v2_application_receipt(
    value: Mapping[str, Any],
    worklist: Mapping[str, Any],
) -> dict[str, Any]:
    receipt = _v2_validate_signed(
        value,
        schema=APPLICATION_RECEIPT_V2_SCHEMA,
        digest_key="application_receipt_digest",
        label="axis application receipt",
    )
    if set(receipt) != {
        "schema_version",
        "run_id",
        "worklist_hash",
        "initial_receipt_digest",
        "repair_plan_digest",
        "repair_execution_digest",
        "execution_evidence_authority_digest",
        "canonical_prior_authority_digest",
        "dispositions",
        "residual_work_item_ids",
        "issues",
        "repair_work",
        "assurance_debt",
        "application_record_complete",
        "status",
        "application_receipt_digest",
    }:
        raise AxisDispositionError(
            "axis application receipt shape mismatch"
        )
    dispositions = _validate_v2_disposition_projection(
        receipt.get("dispositions"),
        worklist,
        allowed_sources=frozenset({"BASE", "REPAIR"}),
    )
    expected_ids = [row["work_item_id"] for row in worklist["items"]]
    observed_ids = [
        str(row.get("work_item_id") or "")
        for row in dispositions
    ]
    residual = [
        str(row["work_item_id"])
        for row in dispositions
        if row.get("application_record_complete") is not True
    ]
    assurance = receipt.get("assurance_debt")
    repair_work = receipt.get("repair_work")
    if (
        receipt.get("run_id") != worklist["run_id"]
        or receipt.get("worklist_hash") != worklist["worklist_hash"]
        or observed_ids != expected_ids
        or len(observed_ids) != len(dispositions)
        or receipt.get("residual_work_item_ids") != residual
        or not isinstance(assurance, Mapping)
        or not isinstance(repair_work, Mapping)
        or repair_work.get("work_item_ids") != residual
        or receipt.get("status")
        not in {"COMPLETE", "COMPLETED_WITH_DEBT"}
        or bool(receipt.get("application_record_complete"))
        != (receipt.get("status") == "COMPLETE")
    ):
        raise AxisDispositionError(
            "axis application receipt denominator mismatch"
        )
    _v2_validate_signed(
        assurance,
        schema=ASSURANCE_DEBT_V2_SCHEMA,
        digest_key="assurance_digest",
        label="axis assurance debt v2",
    )
    _v2_validate_signed(
        repair_work,
        schema=REPAIR_WORK_V2_SCHEMA,
        digest_key="repair_work_digest",
        label="axis repair work v2",
    )
    if set(assurance) != {
        "schema_version",
        "run_id",
        "worklist_hash",
        "count",
        "items",
        "assurance_digest",
    } or set(repair_work) != {
        "schema_version",
        "run_id",
        "worklist_hash",
        "count",
        "work_item_ids",
        "items",
        "repair_work_digest",
    }:
        raise AxisDispositionError(
            "axis application nested authority shape mismatch"
        )
    debt_items = assurance.get("items")
    repair_items = repair_work.get("items")
    expected_debt_fields = {
        "debt_kind",
        "work_item_id",
        "message",
        "finding_disposition_authority",
        "severity_effect",
        "debt_digest",
    }
    debt_digests = (
        [str(row.get("debt_digest") or "") for row in debt_items]
        if isinstance(debt_items, list)
        and all(isinstance(row, Mapping) for row in debt_items)
        else []
    )
    debt_rows_valid = bool(
        isinstance(debt_items, list)
        and all(
            set(row) == expected_debt_fields
            and bool(str(row.get("debt_kind") or ""))
            and bool(str(row.get("message") or ""))
            and row.get("finding_disposition_authority") == "NONE"
            and row.get("severity_effect") == "NONE"
            and row.get("debt_digest")
            == _digest(
                {
                    key: value for key, value in row.items()
                    if key != "debt_digest"
                }
            )
            for row in debt_items
        )
    )
    work_by_id = {
        str(row["work_item_id"]): row for row in worklist["items"]
    }
    expected_repair_items = [
        {
            "work_item_id": row["work_item_id"],
            "source_item": work_by_id[row["work_item_id"]],
            "reason": row["reason"],
        }
        for row in dispositions
        if row.get("application_record_complete") is not True
    ]
    if (
        not isinstance(debt_items, list)
        or type(assurance.get("count")) is not int
        or assurance.get("count") < 0
        or assurance.get("count") != len(debt_items)
        or assurance.get("run_id") != worklist["run_id"]
        or assurance.get("worklist_hash") != worklist["worklist_hash"]
        or not debt_rows_valid
        or debt_digests != sorted(set(debt_digests))
        or not isinstance(repair_items, list)
        or type(repair_work.get("count")) is not int
        or repair_work.get("count") < 0
        or repair_work.get("count") != len(repair_items)
        or repair_work.get("run_id") != worklist["run_id"]
        or repair_work.get("worklist_hash") != worklist["worklist_hash"]
        or repair_items != expected_repair_items
        or (
            receipt.get("status") == "COMPLETE"
            and (
                debt_items
                or residual
                or worklist["denominator_status"] != "EXACT"
                or worklist["input_debt"]
            )
        )
        or (
            receipt.get("status") == "COMPLETED_WITH_DEBT"
            and not debt_items
        )
    ):
        raise AxisDispositionError(
            "axis application receipt debt inventory mismatch"
        )
    return receipt


def validate_axis_disposition_authority_v2(
    application_receipt: Mapping[str, Any],
    worklist: Mapping[str, Any],
    *,
    production_root: str | Path,
    execution_evidence_authority: Mapping[str, Any],
    canonical_prior_ids: Mapping[str, str],
    canonical_prior_authority_digest: str,
) -> dict[str, Any]:
    """Replay immutable application authority without consulting inventory."""

    checked = _validate_axis_worklist_v2(worklist)
    receipt = _validate_v2_application_receipt(
        application_receipt,
        checked,
    )
    evidence = validate_axis_execution_evidence_authority(
        execution_evidence_authority,
        expected_run_id=str(checked["run_id"]),
    )
    if (
        receipt.get("execution_evidence_authority_digest")
        != evidence["authority_digest"]
        or receipt.get("canonical_prior_authority_digest")
        != canonical_prior_authority_digest
    ):
        raise AxisDispositionError(
            "axis application receipt external authority changed"
        )
    root = Path(production_root).resolve(strict=True)
    for item in checked["items"]:
        relative = PurePosixPath(str(item["source_relpath"]))
        try:
            path = root.joinpath(*relative.parts).resolve(strict=True)
            path.relative_to(root)
            text = path.read_text(encoding="utf-8", errors="strict")
        except (OSError, UnicodeError, ValueError) as exc:
            raise AxisDispositionError(
                f"axis source authority is unavailable: {exc}"
            ) from exc
        if _bytes_digest(text.encode("utf-8")) != item["source_hash"]:
            raise AxisDispositionError(
                f"axis source hash drift for {item['work_item_id']}"
            )
    execution_by_id = _v2_execution_by_id(
        evidence,
        run_id=str(checked["run_id"]),
    )
    for row in receipt["dispositions"]:
        if (
            row.get("application_record_complete") is True
            and row.get("disposition") == "CLEAR"
        ):
            kind, reference = _v2_clear_evidence_issue(
                row.get("evidence"),
                item=row["source_item"],
                execution_by_id=execution_by_id,
                canonical_prior_ids=canonical_prior_ids,
                canonical_prior_authority_digest=(
                    canonical_prior_authority_digest
                ),
                rationale=str(row.get("rationale") or ""),
            )
            if (
                not kind
                or kind != row.get("evidence_kind")
                or reference != row.get("evidence_reference")
            ):
                raise AxisDispositionError(
                    "axis CLEAR evidence no longer replays from current authority"
                )
    return receipt


def _axis_assurance_projection_v2(
    application_receipt: Mapping[str, Any],
    *,
    projection_cap: int = 80,
) -> str:
    if type(projection_cap) is not int or projection_cap < 0:
        raise AxisDispositionError(
            "axis assurance projection cap is invalid"
        )
    application = _v2_validate_signed(
        application_receipt,
        schema=APPLICATION_RECEIPT_V2_SCHEMA,
        digest_key="application_receipt_digest",
        label="axis application receipt",
    )
    assurance = _v2_validate_signed(
        application.get("assurance_debt")
        if isinstance(application.get("assurance_debt"), Mapping)
        else {},
        schema=ASSURANCE_DEBT_V2_SCHEMA,
        digest_key="assurance_digest",
        label="axis assurance debt v2",
    )
    items = assurance.get("items")
    if not isinstance(items, list):
        raise AxisDispositionError(
            "axis assurance projection debt denominator is malformed"
        )
    visible = items[:projection_cap]
    omitted = items[projection_cap:]

    def cell(value: Any) -> str:
        return _normal(value).replace("|", "/")

    lines = [
        "# Axis-Coverage Assurance Limitations",
        "",
        f"<!-- plamen-schema:{LIMITATIONS_V2_SCHEMA} -->",
        (
            "<!-- authority:"
            f"{assurance['assurance_digest']} -->"
        ),
        "",
        (
            "This file is a deterministic human projection only. "
            "`axis_assurance_debt.json` is authoritative; these rows grant "
            "no authority to delete, merge, demote, or clear a finding."
        ),
        "",
        f"**Application status:** {application.get('status')}",
        f"**Assurance debt count:** {len(items)}",
        (
            "**Authoritative assurance digest:** "
            f"`{assurance['assurance_digest']}`"
        ),
        "",
        "| Debt Kind | Work Item | Limitation | Content Hash |",
        "|---|---|---|---|",
    ]
    for item in visible:
        if not isinstance(item, Mapping):
            raise AxisDispositionError(
                "axis assurance projection debt row is malformed"
            )
        lines.append(
            f"| {cell(item.get('debt_kind'))} | "
            f"{cell(item.get('work_item_id'))} | "
            f"{cell(item.get('message'))} | "
            f"{cell(item.get('debt_digest'))} |"
        )
    if omitted:
        lines.extend(
            [
                "",
                (
                    f"Projection cap retained {len(visible)} of "
                    f"{len(items)} rows; authoritative JSON retains all rows."
                ),
                (
                    "Omitted debt tail: "
                    f"`{omitted[-1].get('debt_digest', '')}`"
                ),
            ]
        )
    lines.append("")
    return "\n".join(lines)


def validate_axis_assurance_projection_v2(
    text: str,
    application_receipt: Mapping[str, Any],
    *,
    projection_cap: int = 80,
) -> str:
    expected = _axis_assurance_projection_v2(
        application_receipt,
        projection_cap=projection_cap,
    )
    if str(text) != expected:
        raise AxisDispositionError(
            "axis assurance limitations projection drift"
        )
    return expected


def write_axis_disposition_v2_artifacts(
    scratchpad: str | Path,
    *,
    worklist: Mapping[str, Any] | None = None,
    execution_evidence_authority: Mapping[str, Any] | None = None,
    initial_receipt: Mapping[str, Any] | None = None,
    repair_plan: Mapping[str, Any] | None = None,
    repair_execution_receipt: Mapping[str, Any] | None = None,
    application_receipt: Mapping[str, Any] | None = None,
) -> tuple[Path, ...]:
    """Persist already-validated v2 artifacts for standalone/PhaseIO adapters."""

    root = Path(scratchpad)
    writes: list[tuple[str, Mapping[str, Any]]] = []
    if worklist is not None:
        writes.append(
            (WORKLIST_NAME, _validate_axis_worklist_v2(worklist))
        )
    if execution_evidence_authority is not None:
        expected_run = (
            str(worklist["run_id"])
            if isinstance(worklist, Mapping)
            else str(execution_evidence_authority.get("run_id") or "")
        )
        writes.append(
            (
                AXIS_EXECUTION_EVIDENCE_AUTHORITY_NAME,
                validate_axis_execution_evidence_authority(
                    execution_evidence_authority,
                    expected_run_id=expected_run,
                ),
            )
        )
    if initial_receipt is not None:
        if worklist is None:
            raise AxisDispositionError(
                "writing an axis initial receipt requires its worklist"
            )
        writes.append(
            (
                AXIS_INITIAL_RECEIPT_NAME,
                _validate_v2_initial_receipt(initial_receipt, worklist),
            )
        )
    if repair_plan is not None:
        if worklist is None or initial_receipt is None:
            raise AxisDispositionError(
                "writing an axis repair plan requires predecessor authority"
            )
        writes.append(
            (
                AXIS_REPAIR_PLAN_NAME,
                _validate_v2_repair_plan(
                    repair_plan,
                    worklist,
                    initial_receipt,
                ),
            )
        )
    if repair_execution_receipt is not None:
        # The execution receipt's exact output bytes are PhaseIO inputs and are
        # validated at final reconciliation.  Its signed shape is still checked.
        writes.append(
            (
                AXIS_REPAIR_EXECUTION_RECEIPT_NAME,
                _v2_validate_signed(
                    repair_execution_receipt,
                    schema=REPAIR_EXECUTION_RECEIPT_SCHEMA,
                    digest_key="execution_digest",
                    label="axis repair execution receipt",
                ),
            )
        )
    if application_receipt is not None:
        if worklist is None:
            raise AxisDispositionError(
                "writing an axis application receipt requires its worklist"
            )
        checked_receipt = _validate_v2_application_receipt(
            application_receipt,
            worklist,
        )
        writes.extend(
            (
                (AXIS_APPLICATION_RECEIPT_NAME, checked_receipt),
                (REPAIR_NAME, checked_receipt["repair_work"]),
                (ASSURANCE_DEBT_NAME, checked_receipt["assurance_debt"]),
            )
        )
        limitations = _axis_assurance_projection_v2(checked_receipt)
    else:
        limitations = ""
    paths: list[Path] = []
    for name, payload in writes:
        path = root / name
        _atomic_json(path, payload)
        paths.append(path)
    if application_receipt is not None:
        limitations_path = root / LIMITATIONS_NAME
        _atomic_text(limitations_path, limitations)
        paths.append(limitations_path)
    return tuple(paths)


def load_axis_disposition_v2_receipt(
    path: str | Path,
    *,
    worklist: Mapping[str, Any],
) -> dict[str, Any]:
    return _validate_v2_application_receipt(
        _load_json(Path(path), label="axis application receipt v2"),
        _validate_axis_worklist_v2(worklist),
    )


def _v2_inventory_blocks(text: str) -> list[dict[str, Any]]:
    source = str(text or "")
    structural = operational_markdown_view(source)
    matches = list(_INVENTORY_HEADING_RE.finditer(structural))
    rows: list[dict[str, Any]] = []
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(source)
        block = source[match.start():end].strip()
        rows.append(
            {
                "inventory_id": match.group("id").upper(),
                "block_utf8": block,
                "block_sha256": _bytes_digest(block.encode("utf-8")),
                "source_ids": _field(block, "Source IDs"),
            }
        )
    return rows


def render_axis_inventory_block(
    action: Mapping[str, Any],
    inventory_id: str,
) -> str:
    """Render the canonical inventory projection for one v2 axis action."""

    if not isinstance(action, Mapping):
        raise AxisDispositionError("axis inventory action is malformed")
    action_id = str(action.get("action_id") or "")
    identity = str(inventory_id or "").upper()
    raw_source = str(action.get("block_utf8") or "").strip()
    source = raw_source.replace("\r\n", "\n").replace("\r", "\n")
    if (
        not _ACTION_ID_RE.fullmatch(action_id)
        or not re.fullmatch(r"[A-Z][A-Z0-9_-]{1,95}", identity, re.ASCII)
        or not source
    ):
        raise AxisDispositionError(
            "axis inventory projection identity is invalid"
        )
    claimed_digest = str(action.get("block_sha256") or "")
    if (
        claimed_digest
        and claimed_digest != _bytes_digest(raw_source.encode("utf-8"))
    ):
        raise AxisDispositionError(
            f"axis action {action_id} block digest is invalid"
        )
    heading = re.compile(
        r"^#{2,4}\s*Finding\s*\[\s*"
        + re.escape(action_id)
        + r"\s*\]\s*:\s*(?P<title>.+)$",
        re.IGNORECASE | re.MULTILINE | re.ASCII,
    )
    match = heading.search(source)
    if match is None:
        raise AxisDispositionError(
            f"axis action {action_id} lacks its exact heading"
        )
    replacement = (
        f"### Finding [{identity}]: {match.group('title').strip()}\n"
        f"**Source IDs**: AXISGAP:{action_id}\n"
        "**Verdict**: NEEDS_VERIFICATION"
    )
    return heading.sub(replacement, source, count=1).strip()


def _v2_inventory_claim_matches_action(
    claim: Mapping[str, Any],
    action: Mapping[str, Any],
) -> bool:
    """Require the claim to contain the exact authorized action projection."""

    try:
        expected = render_axis_inventory_block(
            action,
            str(claim.get("inventory_id") or ""),
        )
    except AxisDispositionError:
        return False
    observed = str(claim.get("block_utf8") or "").replace(
        "\r\n", "\n"
    ).replace("\r", "\n").strip()
    if observed == expected or observed.startswith(expected + "\n"):
        return True
    # Historical inventory projectors legitimately rewrote the title/location
    # and omitted Work Item ID. Preserve those receipts only when the material
    # action content itself remains exact; a shared AXISGAP label alone never
    # supplies delivery authority.
    source = str(action.get("block_utf8") or "")
    for field in ("Severity", "Description", "Impact"):
        expected_field = _field(source, field).strip()
        observed_field = _field(observed, field).strip()
        if not expected_field or observed_field != expected_field:
            return False
    observed_work_item = _field(observed, "Work Item ID").strip()
    expected_work_item = _field(source, "Work Item ID").strip()
    return not observed_work_item or observed_work_item == expected_work_item


def _v2_exact_source_claim(source_ids: str, action_id: str) -> bool:
    return action_id.upper() in {
        match.group("id").upper()
        for match in _V2_AXISGAP_CLAIM_RE.finditer(
            str(source_ids or "")
        )
    }


def resolve_axis_action_blocks(
    application_receipt: Mapping[str, Any],
    *,
    base_findings_raw: bytes,
    repair_findings_raw: bytes,
) -> tuple[tuple[dict[str, Any], ...], tuple[dict[str, str], ...]]:
    """Resolve each independently valid action and retain exact source debt.

    One unavailable or tampered repair source must not suppress an unrelated
    BASE action.  The signed application remains the complete denominator;
    unresolved source rows are returned as content-bearing debt and never
    fabricated from similar inventory prose.
    """

    application = _v2_validate_signed(
        application_receipt,
        schema=APPLICATION_RECEIPT_V2_SCHEMA,
        digest_key="application_receipt_digest",
        label="axis application receipt",
    )
    if set(application) != {
        "schema_version",
        "run_id",
        "worklist_hash",
        "initial_receipt_digest",
        "repair_plan_digest",
        "repair_execution_digest",
        "execution_evidence_authority_digest",
        "canonical_prior_authority_digest",
        "dispositions",
        "residual_work_item_ids",
        "issues",
        "repair_work",
        "assurance_debt",
        "application_record_complete",
        "status",
        "application_receipt_digest",
    }:
        raise AxisDispositionError(
            "axis application receipt shape mismatch"
        )
    rows = application.get("dispositions")
    if not isinstance(rows, list):
        raise AxisDispositionError(
            "axis application dispositions are malformed"
        )
    required: dict[str, Mapping[str, Any]] = {}
    for index, row in enumerate(rows):
        if not isinstance(row, Mapping):
            raise AxisDispositionError(
                f"axis application disposition row {index} is malformed"
            )
        if (
            row.get("application_record_complete") is True
            and row.get("disposition") in {"FINDING", "UNRESOLVED"}
        ):
            action_id = str(row.get("action_id") or "")
            if (
                not action_id
                or action_id in required
                or not _HEX_RE.fullmatch(
                    str(row.get("action_block_sha256") or "")
                )
            ):
                raise AxisDispositionError(
                    "axis application action denominator is not exact"
                )
            required[action_id] = row
    base_actions, base_duplicates, _base_issues = _v2_actions(
        bytes(base_findings_raw)
    )
    repair_actions, repair_duplicates, _repair_issues = _v2_actions(
        bytes(repair_findings_raw)
    )
    blocks: list[dict[str, Any]] = []
    unavailable: list[dict[str, str]] = []
    for action_id in sorted(required):
        row = required[action_id]
        expected_source = str(row.get("source") or "")
        source_actions = (
            base_actions if expected_source == "BASE" else repair_actions
        )
        source_duplicates = (
            base_duplicates
            if expected_source == "BASE" else repair_duplicates
        )
        other_actions = (
            repair_actions if expected_source == "BASE" else base_actions
        )
        action = source_actions.get(action_id)
        reason = ""
        if (
            expected_source not in {"BASE", "REPAIR"}
            or action_id in source_duplicates
        ):
            reason = "DUPLICATE_OR_INVALID_ACTION_SOURCE"
        elif not isinstance(action, Mapping):
            reason = "SOURCE_ACTION_UNAVAILABLE"
        elif (
            action.get("work_item_id") != row.get("work_item_id")
            or action.get("block_sha256")
            != row.get("action_block_sha256")
        ):
            reason = "SOURCE_ACTION_AUTHORITY_MISMATCH"
        if reason:
            unavailable.append(
                {
                    "action_id": action_id,
                    "source": expected_source,
                    "reason": reason,
                    "expected_block_sha256": str(
                        row.get("action_block_sha256") or ""
                    ),
                }
            )
            continue
        if (
            not isinstance(action, Mapping)
        ):
            continue
        blocks.append(
            {
                "action_id": action_id,
                "work_item_id": str(row.get("work_item_id") or ""),
                "source": expected_source,
                "block_sha256": str(action["block_sha256"]),
                "block_utf8": str(action["block_utf8"]),
            }
        )
        if action_id in other_actions:
            # The application-selected source remains authoritative.  A later
            # unselected-source copy is debt, never veto power over an earlier
            # independently valid action.
            unavailable.append(
                {
                    "action_id": action_id,
                    "source": (
                        "REPAIR" if expected_source == "BASE" else "BASE"
                    ),
                    "reason": "CROSS_SOURCE_IMPOSTOR_IGNORED",
                    "expected_block_sha256": str(
                        row.get("action_block_sha256") or ""
                    ),
                }
            )
    return tuple(blocks), tuple(unavailable)


def referenced_axis_action_blocks(
    application_receipt: Mapping[str, Any],
    *,
    base_findings_raw: bytes,
    repair_findings_raw: bytes,
) -> tuple[dict[str, Any], ...]:
    """Return the complete exact action denominator or fail closed.

    This strict compatibility helper remains appropriate for consumers that
    cannot represent partial source debt.  Promotion uses
    :func:`resolve_axis_action_blocks` so one unavailable action cannot erase
    independent deliveries.
    """

    blocks, unavailable = resolve_axis_action_blocks(
        application_receipt,
        base_findings_raw=base_findings_raw,
        repair_findings_raw=repair_findings_raw,
    )
    if unavailable:
        first = unavailable[0]
        raise AxisDispositionError(
            f"axis action {first['action_id']} differs from application "
            f"authority or is unavailable from signed {first['source']} "
            f"source: {first['reason']}"
        )
    return blocks


def build_axis_promotion_plan(
    application_receipt: Mapping[str, Any],
    *,
    run_id: str,
    base_findings_raw: bytes,
    repair_findings_raw: bytes,
    inventory_raw: bytes,
    phaseio_authority: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Plan the exact inventory successor before any promotion mutation.

    Operational inventory blocks, rather than raw label regexes, decide whether
    an action is absent, already delivered, or blocked by a conflicting or
    duplicate claim.  The signed plan carries the immutable predecessor and
    successor CAS plus the exact append suffix, so a crash after the inventory
    replace can finish the original PhaseIO transaction without reconstructing
    its preimage from already-mutated bytes.
    """

    application = _v2_validate_signed(
        application_receipt,
        schema=APPLICATION_RECEIPT_V2_SCHEMA,
        digest_key="application_receipt_digest",
        label="axis application receipt",
    )
    if application.get("run_id") != str(run_id):
        raise AxisDispositionError("axis promotion plan run_id mismatch")
    before_raw = bytes(inventory_raw)
    try:
        before_text = before_raw.decode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise AxisDispositionError(
            f"axis promotion inventory is not strict UTF-8: {exc}"
        ) from exc
    actions, unavailable = resolve_axis_action_blocks(
        application,
        base_findings_raw=bytes(base_findings_raw),
        repair_findings_raw=bytes(repair_findings_raw),
    )
    required_rows = sorted(
        (
            dict(row)
            for row in application.get("dispositions", ())
            if isinstance(row, Mapping)
            and row.get("application_record_complete") is True
            and row.get("disposition") in {"FINDING", "UNRESOLVED"}
        ),
        key=lambda row: str(row.get("action_id") or ""),
    )
    required_action_ids = [
        str(row.get("action_id") or "") for row in required_rows
    ]
    if (
        any(not identity for identity in required_action_ids)
        or len(required_action_ids) != len(set(required_action_ids))
    ):
        raise AxisDispositionError(
            "axis promotion plan action denominator is not exact"
        )
    blocks = _v2_inventory_blocks(before_text)
    numeric_ids = [
        int(match.group(1))
        for block in blocks
        for match in [
            re.fullmatch(
                r"INV-([0-9]+)",
                str(block.get("inventory_id") or ""),
                re.ASCII,
            )
        ]
        if match is not None
    ]
    next_id = max(numeric_ids, default=0)
    appended_blocks: list[str] = []
    planned_deliveries: list[dict[str, str]] = []
    preexisting: list[str] = []
    blocked: list[str] = [
        str(row["action_id"])
        for row in unavailable
        if row.get("reason") != "CROSS_SOURCE_IMPOSTOR_IGNORED"
    ]
    conflicting: list[str] = []
    for action in actions:
        action_id = str(action["action_id"])
        claims = [
            block
            for block in blocks
            if _v2_exact_source_claim(
                str(block.get("source_ids") or ""), action_id
            )
        ]
        exact = [
            block
            for block in claims
            if _v2_inventory_claim_matches_action(block, action)
        ]
        if len(exact) == 0:
            next_id += 1
            inventory_id = f"INV-{next_id:03d}"
            rendered = render_axis_inventory_block(action, inventory_id)
            appended_blocks.append(rendered)
            planned_deliveries.append(
                {
                    "action_id": action_id,
                    "inventory_id": inventory_id,
                    "inventory_block_sha256": _bytes_digest(
                        rendered.encode("utf-8")
                    ),
                }
            )
            if claims:
                conflicting.append(action_id)
        elif len(exact) == 1:
            preexisting.append(action_id)
            if len(claims) != 1:
                conflicting.append(action_id)
        else:
            # Multiple exact projections are an identity collision. Never
            # create a third; keep the action and collision report-visible.
            blocked.append(action_id)
            conflicting.append(action_id)
    suffix = ""
    if appended_blocks:
        separator = "" if before_text.endswith("\n") else "\n"
        suffix = (
            separator
            + "\n## Multi-Axis Coverage Candidates\n\n"
            + "\n\n".join(appended_blocks)
            + "\n"
        )
    suffix_raw = suffix.encode("utf-8")
    after_raw = before_raw + suffix_raw
    after_text = after_raw.decode("utf-8", errors="strict")
    phaseio = dict(phaseio_authority or {})
    if phaseio:
        expected_roles = {"application", "plan", "promotion"}
        if set(phaseio) != expected_roles:
            raise AxisDispositionError(
                "axis promotion PhaseIO authority role denominator differs"
            )
        for role, raw_binding in phaseio.items():
            if (
                not isinstance(raw_binding, Mapping)
                or set(raw_binding)
                != {
                    "work_unit_key",
                    "contract_digest",
                    "launch_digest",
                }
                or not str(raw_binding.get("work_unit_key") or "").endswith(
                    {
                        "application": "/axis_disposition/reconcile.final",
                        "plan": "/axis_disposition/promotion.plan",
                        "promotion": "/axis_disposition/promotion",
                    }[role]
                )
                or not _HEX_RE.fullmatch(
                    str(raw_binding.get("contract_digest") or "")
                )
                or not _HEX_RE.fullmatch(
                    str(raw_binding.get("launch_digest") or "")
                )
            ):
                raise AxisDispositionError(
                    f"axis promotion PhaseIO {role} authority is malformed"
                )
        phaseio = {
            role: {
                key: str(value)
                for key, value in dict(phaseio[role]).items()
            }
            for role in sorted(phaseio)
        }
    unsigned = {
        "schema_version": PROMOTION_PLAN_SCHEMA,
        "run_id": str(run_id),
        "phaseio_authority": phaseio,
        "application_receipt_digest": str(
            application["application_receipt_digest"]
        ),
        "base_findings_sha256": _bytes_digest(bytes(base_findings_raw)),
        "repair_findings_sha256": _bytes_digest(bytes(repair_findings_raw)),
        "action_ids": required_action_ids,
        "action_block_sha256s": {
            str(row["action_id"]): str(row["action_block_sha256"])
            for row in required_rows
        },
        "action_sources": {
            str(row["action_id"]): str(row["source"])
            for row in required_rows
        },
        "inventory_before": {
            "sha256": _bytes_digest(before_raw),
            "size": len(before_raw),
            "identities": [
                str(row["inventory_id"]) for row in blocks
            ],
        },
        "inventory_successor": {
            "sha256": _bytes_digest(after_raw),
            "size": len(after_raw),
            "identities": [
                str(row["inventory_id"])
                for row in _v2_inventory_blocks(after_text)
            ],
        },
        "append_suffix_utf8": suffix,
        "planned_deliveries": planned_deliveries,
        "preexisting_action_ids": preexisting,
        "blocked_action_ids": sorted(set(blocked)),
        "conflicting_claim_action_ids": sorted(set(conflicting)),
        "source_debt": sorted(
            (dict(row) for row in unavailable),
            key=lambda row: (
                str(row.get("action_id") or ""),
                str(row.get("source") or ""),
                str(row.get("reason") or ""),
            ),
        ),
        "status": (
            "READY"
            if not blocked and not conflicting and not unavailable
            else "READY_WITH_DEBT"
        ),
    }
    return _v2_signed(unsigned, "plan_digest")


def _validate_axis_promotion_plan_replay(
    value: Mapping[str, Any],
    application_receipt: Mapping[str, Any] | None,
    *,
    run_id: str,
    current_inventory_raw: bytes,
    downstream_tail_authorizer: (
        Callable[
            [Mapping[str, Any], bytes],
            Mapping[str, Any] | None,
        ] | None
    ) = None,
) -> tuple[dict[str, Any], bytes, dict[str, Any] | None]:
    """Validate immutable plan semantics without mutable producer sources.

    This validator is deliberately insufficient to authorize a newly observed
    plan: PhaseIO must first prove that the exact plan bytes were committed.
    Once that external commit authority exists, this routine proves the
    committed plan is internally coherent and can replay from exactly its
    predecessor or successor even when the original BASE/REPAIR files have
    subsequently disappeared.
    """

    plan = _v2_validate_signed(
        value,
        schema=PROMOTION_PLAN_SCHEMA,
        digest_key="plan_digest",
        label="axis promotion plan",
    )
    expected_fields = {
        "schema_version",
        "run_id",
        "phaseio_authority",
        "application_receipt_digest",
        "base_findings_sha256",
        "repair_findings_sha256",
        "action_ids",
        "action_block_sha256s",
        "action_sources",
        "inventory_before",
        "inventory_successor",
        "append_suffix_utf8",
        "planned_deliveries",
        "preexisting_action_ids",
        "blocked_action_ids",
        "conflicting_claim_action_ids",
        "source_debt",
        "status",
        "plan_digest",
    }
    if set(plan) != expected_fields:
        raise AxisDispositionError("axis promotion plan shape mismatch")
    if plan.get("run_id") != str(run_id):
        raise AxisDispositionError("axis promotion plan run_id mismatch")
    phaseio = plan.get("phaseio_authority")
    if not isinstance(phaseio, Mapping):
        raise AxisDispositionError(
            "axis promotion plan PhaseIO authority is malformed"
        )
    if phaseio:
        expected_roles = {"application", "plan", "promotion"}
        if set(phaseio) != expected_roles:
            raise AxisDispositionError(
                "axis promotion plan PhaseIO role denominator differs"
            )
        for role, raw_binding in phaseio.items():
            if (
                not isinstance(raw_binding, Mapping)
                or set(raw_binding)
                != {
                    "work_unit_key",
                    "contract_digest",
                    "launch_digest",
                }
                or not str(raw_binding.get("work_unit_key") or "").endswith(
                    {
                        "application": "/axis_disposition/reconcile.final",
                        "plan": "/axis_disposition/promotion.plan",
                        "promotion": "/axis_disposition/promotion",
                    }[str(role)]
                )
                or not _HEX_RE.fullmatch(
                    str(raw_binding.get("contract_digest") or "")
                )
                or not _HEX_RE.fullmatch(
                    str(raw_binding.get("launch_digest") or "")
                )
            ):
                raise AxisDispositionError(
                    f"axis promotion plan PhaseIO {role} authority is malformed"
                )

    application_digest = str(
        plan.get("application_receipt_digest") or ""
    )
    if not _HEX_RE.fullmatch(application_digest):
        raise AxisDispositionError(
            "axis promotion plan application digest is malformed"
        )
    action_ids = _v2_string_list(
        plan.get("action_ids"),
        label="axis promotion plan action_ids",
    )
    action_hashes = plan.get("action_block_sha256s")
    action_sources = plan.get("action_sources")
    if (
        any(
            not _ACTION_ID_RE.fullmatch(action_id)
            for action_id in action_ids
        )
        or not isinstance(action_hashes, Mapping)
        or set(action_hashes) != set(action_ids)
        or any(
            not _HEX_RE.fullmatch(str(block_hash or ""))
            for block_hash in action_hashes.values()
        )
        or not isinstance(action_sources, Mapping)
        or set(action_sources) != set(action_ids)
        or any(
            source not in {"BASE", "REPAIR"}
            for source in action_sources.values()
        )
    ):
        raise AxisDispositionError(
            "axis promotion plan action denominator is not exact"
        )
    required_hashes = {
        str(action_id): str(action_hashes[action_id])
        for action_id in action_ids
    }
    required_sources = {
        str(action_id): str(action_sources[action_id])
        for action_id in action_ids
    }
    if application_receipt is not None:
        application = _v2_validate_signed(
            application_receipt,
            schema=APPLICATION_RECEIPT_V2_SCHEMA,
            digest_key="application_receipt_digest",
            label="axis application receipt",
        )
        if (
            application.get("run_id") != str(run_id)
            or application_digest
            != application.get("application_receipt_digest")
        ):
            raise AxisDispositionError(
                "axis promotion plan application authority mismatch"
            )
        rows = application.get("dispositions")
        if not isinstance(rows, list):
            raise AxisDispositionError(
                "axis promotion application dispositions are malformed"
            )
        required_rows = sorted(
            (
                dict(row)
                for row in rows
                if isinstance(row, Mapping)
                and row.get("application_record_complete") is True
                and row.get("disposition") in {"FINDING", "UNRESOLVED"}
            ),
            key=lambda row: str(row.get("action_id") or ""),
        )
        application_action_ids = [
            str(row.get("action_id") or "") for row in required_rows
        ]
        application_hashes = {
            str(row.get("action_id") or ""): str(
                row.get("action_block_sha256") or ""
            )
            for row in required_rows
        }
        application_sources = {
            str(row.get("action_id") or ""): str(
                row.get("source") or ""
            )
            for row in required_rows
        }
        if (
            action_ids != application_action_ids
            or required_hashes != application_hashes
            or required_sources != application_sources
        ):
            raise AxisDispositionError(
                "axis promotion plan action authority differs from "
                "application receipt"
            )
    if (
        not _HEX_RE.fullmatch(
            str(plan.get("base_findings_sha256") or "")
        )
        or not _HEX_RE.fullmatch(
            str(plan.get("repair_findings_sha256") or "")
        )
    ):
        raise AxisDispositionError(
            "axis promotion plan producer source digests are malformed"
        )

    before = plan.get("inventory_before")
    successor = plan.get("inventory_successor")
    if (
        not isinstance(before, Mapping)
        or not isinstance(successor, Mapping)
        or set(before) != {"sha256", "size", "identities"}
        or set(successor) != {"sha256", "size", "identities"}
        or not _HEX_RE.fullmatch(str(before.get("sha256") or ""))
        or not _HEX_RE.fullmatch(str(successor.get("sha256") or ""))
        or not isinstance(before.get("size"), int)
        or isinstance(before.get("size"), bool)
        or int(before["size"]) < 0
        or not isinstance(successor.get("size"), int)
        or isinstance(successor.get("size"), bool)
        or int(successor["size"]) < 0
        or not isinstance(before.get("identities"), list)
        or not isinstance(successor.get("identities"), list)
        or any(
            not isinstance(identity, str) or not identity
            for identity in (
                list(before.get("identities") or [])
                + list(successor.get("identities") or [])
            )
        )
    ):
        raise AxisDispositionError("axis promotion plan CAS is malformed")
    suffix = plan.get("append_suffix_utf8")
    if not isinstance(suffix, str):
        raise AxisDispositionError("axis promotion append suffix is malformed")
    live = bytes(current_inventory_raw)
    live_sha = _bytes_digest(live)
    suffix_raw = suffix.encode("utf-8")
    if (
        live_sha == str(before.get("sha256") or "")
        and len(live) == before.get("size")
    ):
        predecessor = live
    elif (
        live_sha == str(successor.get("sha256") or "")
        and len(live) == successor.get("size")
        and len(live) >= len(suffix_raw)
        and (not suffix_raw or live.endswith(suffix_raw))
    ):
        predecessor = (
            live[:-len(suffix_raw)] if suffix_raw else live
        )
    elif (
        len(live) > int(successor.get("size") or 0)
        and _bytes_digest(
            live[: int(successor.get("size") or 0)]
        )
        == str(successor.get("sha256") or "")
    ):
        if downstream_tail_authorizer is None:
            raise AxisDispositionError(
                "axis promotion successor prefix has an unauthorized "
                "downstream inventory tail"
            )
        try:
            downstream_tail_authorizer(plan, live)
        except AxisDispositionError:
            raise
        except Exception as exc:
            raise AxisDispositionError(
                "axis promotion downstream inventory tail authority "
                f"failed: {type(exc).__name__}: {exc}"
            ) from exc
        successor_prefix = live[: int(successor["size"])]
        if (
            len(successor_prefix) < len(suffix_raw)
            or (
                suffix_raw
                and not successor_prefix.endswith(suffix_raw)
            )
        ):
            raise AxisDispositionError(
                "axis promotion authorized tail does not preserve the "
                "exact planned successor prefix"
            )
        predecessor = (
            successor_prefix[:-len(suffix_raw)]
            if suffix_raw else successor_prefix
        )
    else:
        if downstream_tail_authorizer is None:
            raise AxisDispositionError(
                "axis promotion inventory is neither the planned predecessor "
                "nor the planned successor"
            )
        try:
            semantic_successor = downstream_tail_authorizer(plan, live)
        except AxisDispositionError:
            raise
        except Exception as exc:
            raise AxisDispositionError(
                "axis promotion semantic successor authority failed: "
                f"{type(exc).__name__}: {exc}"
            ) from exc
        deliverable = {
            str(row.get("action_id") or "")
            for row in plan.get("planned_deliveries", ())
            if isinstance(row, Mapping)
        } | {
            str(value)
            for value in plan.get("preexisting_action_ids", ())
            if str(value)
        }
        if (
            not isinstance(semantic_successor, Mapping)
            or semantic_successor.get("authority_kind")
            != "RECEIPT_AUTHORIZED_SEMANTIC_SUCCESSOR"
            or set(
                semantic_successor.get("preserved_action_ids") or ()
            )
            != deliverable
        ):
            raise AxisDispositionError(
                "axis promotion semantic successor does not preserve the "
                "exact deliverable action denominator"
            )
        # The immutable PhaseIO plan and original promotion commit already
        # proved predecessor+suffix.  The external authority proves a
        # contiguous receipt-authorized successor and exact live action
        # preservation, so mutable predecessor bytes are no longer required.
        return plan, b"", dict(semantic_successor)
    if (
        _bytes_digest(predecessor) != str(before.get("sha256") or "")
        or len(predecessor) != before.get("size")
    ):
        raise AxisDispositionError(
            "axis promotion successor cannot recover its exact predecessor"
        )
    planned_successor = predecessor + suffix_raw
    if (
        _bytes_digest(planned_successor)
        != str(successor.get("sha256") or "")
        or len(planned_successor) != successor.get("size")
    ):
        raise AxisDispositionError(
            "axis promotion successor does not equal predecessor plus suffix"
        )
    try:
        predecessor_text = predecessor.decode("utf-8", errors="strict")
        successor_text = planned_successor.decode(
            "utf-8", errors="strict"
        )
    except UnicodeError as exc:
        raise AxisDispositionError(
            f"axis promotion plan CAS is not strict UTF-8: {exc}"
        ) from exc
    predecessor_blocks = _v2_inventory_blocks(predecessor_text)
    successor_blocks = _v2_inventory_blocks(successor_text)
    predecessor_identities = [
        str(row["inventory_id"]) for row in predecessor_blocks
    ]
    successor_identities = [
        str(row["inventory_id"]) for row in successor_blocks
    ]
    if (
        predecessor_identities != list(before["identities"])
        or successor_identities != list(successor["identities"])
    ):
        raise AxisDispositionError(
            "axis promotion plan CAS identities mismatch exact bytes"
        )

    planned = plan.get("planned_deliveries")
    if not isinstance(planned, list):
        raise AxisDispositionError(
            "axis promotion planned deliveries are malformed"
        )
    planned_action_ids: list[str] = []
    planned_inventory_ids: list[str] = []
    for index, delivery in enumerate(planned):
        if (
            not isinstance(delivery, Mapping)
            or set(delivery)
            != {
                "action_id",
                "inventory_id",
                "inventory_block_sha256",
            }
        ):
            raise AxisDispositionError(
                f"axis promotion planned delivery {index} is malformed"
            )
        action_id = str(delivery.get("action_id") or "")
        inventory_id = str(delivery.get("inventory_id") or "")
        block_hash = str(delivery.get("inventory_block_sha256") or "")
        if (
            action_id not in required_hashes
            or not re.fullmatch(
                r"[A-Z][A-Z0-9_-]{1,95}", inventory_id, re.ASCII
            )
            or not _HEX_RE.fullmatch(block_hash)
        ):
            raise AxisDispositionError(
                f"axis promotion planned delivery {index} is invalid"
            )
        planned_action_ids.append(action_id)
        planned_inventory_ids.append(inventory_id)
    if (
        planned_action_ids != sorted(set(planned_action_ids))
        or len(planned_inventory_ids) != len(set(planned_inventory_ids))
    ):
        raise AxisDispositionError(
            "axis promotion planned delivery denominator is not exact"
        )
    if any(
        inventory_id in predecessor_identities
        for inventory_id in planned_inventory_ids
    ):
        raise AxisDispositionError(
            "axis promotion planned delivery reuses predecessor identity"
        )
    appended_blocks = successor_blocks[len(predecessor_blocks):]
    if [
        str(row["inventory_id"]) for row in appended_blocks
    ] != planned_inventory_ids:
        raise AxisDispositionError(
            "axis promotion suffix delivery identities mismatch plan"
        )
    for delivery, block in zip(planned, appended_blocks):
        action_id = str(delivery["action_id"])
        source_claims = [
            match.group("id").upper()
            for match in _V2_AXISGAP_CLAIM_RE.finditer(
                str(block.get("source_ids") or "")
            )
        ]
        if (
            str(block.get("block_sha256") or "")
            != str(delivery["inventory_block_sha256"])
            or source_claims != [action_id.upper()]
        ):
            raise AxisDispositionError(
                f"axis promotion planned delivery {action_id} block "
                "differs from its committed suffix"
            )
    expected_suffix = ""
    if appended_blocks:
        separator = "" if predecessor_text.endswith("\n") else "\n"
        expected_suffix = (
            separator
            + "\n## Multi-Axis Coverage Candidates\n\n"
            + "\n\n".join(
                str(block["block_utf8"]) for block in appended_blocks
            )
            + "\n"
        )
    if suffix != expected_suffix:
        raise AxisDispositionError(
            "axis promotion append suffix is not the exact canonical "
            "delivery projection"
        )

    preexisting = _v2_string_list(
        plan.get("preexisting_action_ids"),
        label="axis promotion preexisting_action_ids",
    )
    blocked = _v2_string_list(
        plan.get("blocked_action_ids"),
        label="axis promotion blocked_action_ids",
    )
    conflicting = _v2_string_list(
        plan.get("conflicting_claim_action_ids"),
        label="axis promotion conflicting_claim_action_ids",
    )
    if (
        set(planned_action_ids) & set(preexisting)
        or set(planned_action_ids) & set(blocked)
        or set(preexisting) & set(blocked)
        or (
            set(planned_action_ids)
            | set(preexisting)
            | set(blocked)
        )
        != set(action_ids)
        or not set(conflicting) <= set(action_ids)
    ):
        raise AxisDispositionError(
            "axis promotion action disposition partition is malformed"
        )
    for action_id in preexisting:
        claims = [
            row
            for row in predecessor_blocks
            if _v2_exact_source_claim(
                str(row.get("source_ids") or ""), action_id
            )
        ]
        if len(claims) != 1:
            raise AxisDispositionError(
                f"axis promotion preexisting action {action_id} lacks "
                "one predecessor claim"
            )

    source_debt = plan.get("source_debt")
    allowed_debt_reasons = {
        "DUPLICATE_OR_INVALID_ACTION_SOURCE",
        "SOURCE_ACTION_UNAVAILABLE",
        "SOURCE_ACTION_AUTHORITY_MISMATCH",
        "CROSS_SOURCE_IMPOSTOR_IGNORED",
    }
    if not isinstance(source_debt, list):
        raise AxisDispositionError(
            "axis promotion source_debt must be a list"
        )
    normalized_debt: list[dict[str, str]] = []
    for index, item in enumerate(source_debt):
        if (
            not isinstance(item, Mapping)
            or set(item)
            != {
                "action_id",
                "source",
                "reason",
                "expected_block_sha256",
            }
        ):
            raise AxisDispositionError(
                f"axis promotion source_debt row {index} is malformed"
            )
        debt = {
            key: str(item.get(key) or "")
            for key in (
                "action_id",
                "source",
                "reason",
                "expected_block_sha256",
            )
        }
        action_id = debt["action_id"]
        if (
            action_id not in required_hashes
            or debt["reason"] not in allowed_debt_reasons
            or debt["source"] not in {"BASE", "REPAIR"}
            or debt["expected_block_sha256"]
            != required_hashes[action_id]
        ):
            raise AxisDispositionError(
                f"axis promotion source_debt row {index} is invalid"
            )
        if debt["reason"] == "CROSS_SOURCE_IMPOSTOR_IGNORED":
            expected_other = (
                "REPAIR"
                if required_sources[action_id] == "BASE"
                else "BASE"
            )
            if debt["source"] != expected_other or action_id in blocked:
                raise AxisDispositionError(
                    "axis promotion ignored impostor cannot block the "
                    "application-selected action"
                )
        elif (
            debt["source"] != required_sources[action_id]
            or action_id not in blocked
        ):
            raise AxisDispositionError(
                "axis promotion unavailable source debt must remain blocked"
            )
        normalized_debt.append(debt)
    if normalized_debt != sorted(
        normalized_debt,
        key=lambda row: (
            row["action_id"],
            row["source"],
            row["reason"],
        ),
    ) or len(
        {
            (row["action_id"], row["source"], row["reason"])
            for row in normalized_debt
        }
    ) != len(normalized_debt):
        raise AxisDispositionError(
            "axis promotion source_debt is not exact, unique, and ordered"
        )
    expected_status = (
        "READY"
        if not blocked and not conflicting and not normalized_debt
        else "READY_WITH_DEBT"
    )
    if plan.get("status") != expected_status:
        raise AxisDispositionError(
            "axis promotion plan status differs from recorded debt"
        )
    return plan, predecessor, None


def validate_axis_promotion_plan_replay(
    value: Mapping[str, Any],
    application_receipt: Mapping[str, Any] | None,
    *,
    run_id: str,
    current_inventory_raw: bytes,
    downstream_tail_authorizer: (
        Callable[
            [Mapping[str, Any], bytes],
            Mapping[str, Any] | None,
        ] | None
    ) = None,
) -> dict[str, Any]:
    """Replay a PhaseIO-committed plan without mutable source re-derivation.

    The caller must separately prove that ``value`` is the exact committed
    plan artifact.  A recomputable self-digest is integrity, not commit
    authority.
    """

    plan, _predecessor, _semantic_successor = (
        _validate_axis_promotion_plan_replay(
        value,
        application_receipt,
        run_id=str(run_id),
        current_inventory_raw=bytes(current_inventory_raw),
        downstream_tail_authorizer=downstream_tail_authorizer,
        )
    )
    return plan


def validate_axis_promotion_plan(
    value: Mapping[str, Any],
    application_receipt: Mapping[str, Any],
    *,
    run_id: str,
    base_findings_raw: bytes,
    repair_findings_raw: bytes,
    current_inventory_raw: bytes,
) -> dict[str, Any]:
    """Strictly validate a new plan against current producer sources.

    Unlike :func:`validate_axis_promotion_plan_replay`, this pre-commit
    validator re-derives the full plan from BASE/REPAIR authority.  Keep this
    strict boundary for plan creation; use replay-only validation solely
    after PhaseIO has committed the exact plan bytes.
    """

    plan, predecessor, _semantic_successor = (
        _validate_axis_promotion_plan_replay(
        value,
        application_receipt,
        run_id=str(run_id),
        current_inventory_raw=bytes(current_inventory_raw),
        )
    )
    replay = build_axis_promotion_plan(
        application_receipt,
        run_id=str(run_id),
        base_findings_raw=bytes(base_findings_raw),
        repair_findings_raw=bytes(repair_findings_raw),
        inventory_raw=predecessor,
    )
    if plan != replay:
        raise AxisDispositionError(
            "axis promotion plan differs from current exact authority"
        )
    return plan


def load_axis_promotion_plan(
    path: str | Path,
    application_receipt: Mapping[str, Any],
    *,
    run_id: str,
    base_findings_raw: bytes,
    repair_findings_raw: bytes,
    current_inventory_raw: bytes,
) -> dict[str, Any]:
    return validate_axis_promotion_plan(
        _load_json(Path(path), label="axis promotion plan"),
        application_receipt,
        run_id=str(run_id),
        base_findings_raw=bytes(base_findings_raw),
        repair_findings_raw=bytes(repair_findings_raw),
        current_inventory_raw=bytes(current_inventory_raw),
    )


def build_axis_promotion_authority(
    application_receipt: Mapping[str, Any] | None,
    *,
    run_id: str,
    base_findings_raw: bytes | None = None,
    repair_findings_raw: bytes | None = None,
    inventory_text: str,
    promotion_plan: Mapping[str, Any] | None = None,
    downstream_tail_authorizer: (
        Callable[
            [Mapping[str, Any], bytes],
            Mapping[str, Any] | None,
        ] | None
    ) = None,
) -> dict[str, Any]:
    """Reconcile exact referenced actions to inventory blocks.

    A committed ``promotion_plan`` is the preferred authority: it binds the
    immutable application digest, action denominator and hashes, exact
    predecessor/successor CAS, and delivery blocks.  BASE/REPAIR files are not
    consulted on that path, so later producer-source drift cannot erase a
    delivery already captured by the committed plan.

    The source-derived path remains for pre-cutover callers, but requires the
    application and both producer byte strings.  It emits an empty
    ``plan_digest`` so it cannot be confused with plan-backed authority.
    """

    inventory_raw = str(inventory_text).encode("utf-8", errors="strict")
    blocks = _v2_inventory_blocks(inventory_text)
    deliveries: list[dict[str, Any]] = []
    missing: list[str] = []
    if promotion_plan is not None:
        plan = validate_axis_promotion_plan_replay(
            promotion_plan,
            None,
            run_id=str(run_id),
            current_inventory_raw=inventory_raw,
            downstream_tail_authorizer=downstream_tail_authorizer,
        )
        required = list(plan["action_ids"])
        action_hashes = {
            str(key): str(value)
            for key, value in plan["action_block_sha256s"].items()
        }
        planned = {
            str(row["action_id"]): dict(row)
            for row in plan["planned_deliveries"]
        }
        preexisting = set(plan["preexisting_action_ids"])
        blocked = set(plan["blocked_action_ids"])
        conflicting = list(plan["conflicting_claim_action_ids"])
        source_debt = [dict(row) for row in plan["source_debt"]]
        for action_id in required:
            claims = [
                block
                for block in blocks
                if _v2_exact_source_claim(
                    str(block.get("source_ids") or ""), action_id
                )
            ]
            delivery = planned.get(action_id)
            if delivery is not None:
                exact_claims = [
                    claim
                    for claim in claims
                    if (
                        claim.get("inventory_id")
                        == delivery.get("inventory_id")
                        and claim.get("block_sha256")
                        == delivery.get("inventory_block_sha256")
                    )
                ]
            elif action_id in preexisting:
                exact_claims = claims
            else:
                exact_claims = []
            if action_id in blocked or len(exact_claims) != 1:
                missing.append(action_id)
                continue
            claim = exact_claims[0]
            deliveries.append(
                {
                    "action_id": action_id,
                    "source_block_sha256": action_hashes[action_id],
                    "inventory_id": str(claim["inventory_id"]),
                    "inventory_block_sha256": str(
                        claim["block_sha256"]
                    ),
                }
            )
        application_digest = str(
            plan["application_receipt_digest"]
        )
        plan_digest = str(plan["plan_digest"])
    else:
        if (
            application_receipt is None
            or base_findings_raw is None
            or repair_findings_raw is None
        ):
            raise AxisDispositionError(
                "legacy axis promotion requires application and both "
                "producer sources"
            )
        application = _v2_validate_signed(
            application_receipt,
            schema=APPLICATION_RECEIPT_V2_SCHEMA,
            digest_key="application_receipt_digest",
            label="axis application receipt",
        )
        if application.get("run_id") != str(run_id):
            raise AxisDispositionError("axis promotion run_id mismatch")
        required = sorted(
            str(row.get("action_id") or "")
            for row in application.get("dispositions", [])
            if isinstance(row, Mapping)
            and row.get("application_record_complete") is True
            and row.get("disposition") in {"FINDING", "UNRESOLVED"}
        )
        if (
            any(not value for value in required)
            or len(required) != len(set(required))
        ):
            raise AxisDispositionError(
                "axis promotion action denominator is not unique"
            )
        action_blocks, unavailable = resolve_axis_action_blocks(
            application,
            base_findings_raw=bytes(base_findings_raw),
            repair_findings_raw=bytes(repair_findings_raw),
        )
        actions = {
            str(row["action_id"]): row for row in action_blocks
        }
        unavailable_ids = {
            str(row["action_id"])
            for row in unavailable
            if row.get("reason")
            != "CROSS_SOURCE_IMPOSTOR_IGNORED"
        }
        conflicting = []
        for action_id in required:
            claims = [
                block for block in blocks
                if _v2_exact_source_claim(
                    str(block.get("source_ids") or ""), action_id
                )
            ]
            action = actions.get(action_id)
            exact_claims = (
                [
                    claim
                    for claim in claims
                    if _v2_inventory_claim_matches_action(claim, action)
                ]
                if isinstance(action, Mapping)
                else []
            )
            if (
                action_id not in unavailable_ids
                and (
                    len(claims) != len(exact_claims)
                    or len(exact_claims) > 1
                )
            ):
                conflicting.append(action_id)
            if (
                len(exact_claims) != 1
                or not isinstance(action, Mapping)
            ):
                missing.append(action_id)
                continue
            claim = exact_claims[0]
            deliveries.append(
                {
                    "action_id": action_id,
                    "source_block_sha256": str(
                        action["block_sha256"]
                    ),
                    "inventory_id": str(claim["inventory_id"]),
                    "inventory_block_sha256": str(
                        claim["block_sha256"]
                    ),
                }
            )
        application_digest = str(
            application["application_receipt_digest"]
        )
        plan_digest = ""
        source_debt = sorted(
            (dict(row) for row in unavailable),
            key=lambda row: (
                str(row.get("action_id") or ""),
                str(row.get("source") or ""),
                str(row.get("reason") or ""),
            ),
        )
    required_set = set(required)
    orphan_claims = sorted(
        {
            match.group("id").upper()
            for block in blocks
            for match in _V2_AXISGAP_CLAIM_RE.finditer(
                str(block.get("source_ids") or "")
            )
            if match.group("id").upper() not in required_set
        }
    )
    unsigned = {
        "schema_version": PROMOTION_RECEIPT_V2_SCHEMA,
        "run_id": str(run_id),
        "application_receipt_digest": application_digest,
        "plan_digest": plan_digest,
        "action_count": len(required),
        "action_ids": required,
        "delivery_count": len(deliveries),
        "deliveries": deliveries,
        "missing_action_ids": missing,
        "conflicting_claim_action_ids": conflicting,
        "orphan_delivered_action_ids": orphan_claims,
        "source_debt": source_debt,
        "status": (
            "COMPLETE"
            if (
                not missing
                and not conflicting
                and not orphan_claims
                and not source_debt
            )
            else "COMPLETED_WITH_DEBT"
        ),
    }
    return _v2_signed(unsigned, "promotion_receipt_digest")


def _validate_semantic_successor_promotion_authority(
    receipt: Mapping[str, Any],
    plan: Mapping[str, Any],
    semantic_successor: Mapping[str, Any],
) -> dict[str, Any]:
    """Validate the original receipt through an authorized semantic successor.

    The receipt and immutable plan describe the exact originally committed
    promotion.  A later receipt-authorized semantic dedup may legitimately
    change inventory identities and block hashes, so it is unsound to rebuild
    that historical receipt from the current bytes.  Instead, prove the full
    receipt/plan linkage and require the external lineage authority to preserve
    exactly every deliverable action.
    """

    expected_receipt_fields = {
        "schema_version",
        "run_id",
        "application_receipt_digest",
        "plan_digest",
        "action_count",
        "action_ids",
        "delivery_count",
        "deliveries",
        "missing_action_ids",
        "conflicting_claim_action_ids",
        "orphan_delivered_action_ids",
        "source_debt",
        "status",
        "promotion_receipt_digest",
    }
    if set(receipt) != expected_receipt_fields:
        raise AxisDispositionError(
            "axis promotion semantic-successor receipt shape mismatch"
        )
    action_ids = _v2_string_list(
        receipt.get("action_ids"),
        label="axis promotion receipt action_ids",
    )
    plan_action_ids = _v2_string_list(
        plan.get("action_ids"),
        label="axis promotion plan action_ids",
    )
    if (
        receipt.get("run_id") != plan.get("run_id")
        or receipt.get("application_receipt_digest")
        != plan.get("application_receipt_digest")
        or receipt.get("plan_digest") != plan.get("plan_digest")
        or type(receipt.get("action_count")) is not int
        or receipt.get("action_count") != len(action_ids)
        or action_ids != plan_action_ids
    ):
        raise AxisDispositionError(
            "axis promotion semantic-successor receipt/plan binding mismatch"
        )

    action_hashes = plan.get("action_block_sha256s")
    action_sources = plan.get("action_sources")
    if (
        not isinstance(action_hashes, Mapping)
        or set(action_hashes) != set(action_ids)
        or not isinstance(action_sources, Mapping)
        or set(action_sources) != set(action_ids)
    ):
        raise AxisDispositionError(
            "axis promotion semantic-successor action authority is malformed"
        )
    normalized_hashes = {
        str(action_id): str(action_hashes[action_id])
        for action_id in action_ids
    }
    if any(
        not _HEX_RE.fullmatch(block_hash)
        for block_hash in normalized_hashes.values()
    ) or any(
        str(action_sources[action_id]) not in {"BASE", "REPAIR"}
        for action_id in action_ids
    ):
        raise AxisDispositionError(
            "axis promotion semantic-successor action authority is invalid"
        )

    planned_raw = plan.get("planned_deliveries")
    if not isinstance(planned_raw, list):
        raise AxisDispositionError(
            "axis promotion semantic-successor planned deliveries are malformed"
        )
    planned: dict[str, dict[str, str]] = {}
    planned_order: list[str] = []
    planned_inventory_ids: list[str] = []
    for index, raw in enumerate(planned_raw):
        if (
            not isinstance(raw, Mapping)
            or set(raw)
            != {
                "action_id",
                "inventory_id",
                "inventory_block_sha256",
            }
        ):
            raise AxisDispositionError(
                "axis promotion semantic-successor planned delivery "
                f"{index} is malformed"
            )
        row = {
            "action_id": str(raw.get("action_id") or ""),
            "inventory_id": str(raw.get("inventory_id") or ""),
            "inventory_block_sha256": str(
                raw.get("inventory_block_sha256") or ""
            ),
        }
        if (
            row["action_id"] not in normalized_hashes
            or not re.fullmatch(
                r"[A-Z][A-Z0-9_-]{1,95}",
                row["inventory_id"],
                re.ASCII,
            )
            or not _HEX_RE.fullmatch(row["inventory_block_sha256"])
        ):
            raise AxisDispositionError(
                "axis promotion semantic-successor planned delivery "
                f"{index} is invalid"
            )
        planned[row["action_id"]] = row
        planned_order.append(row["action_id"])
        planned_inventory_ids.append(row["inventory_id"])
    if (
        planned_order != sorted(set(planned_order))
        or len(planned) != len(planned_raw)
        or len(planned_inventory_ids) != len(set(planned_inventory_ids))
    ):
        raise AxisDispositionError(
            "axis promotion semantic-successor planned denominator is not exact"
        )

    preexisting = _v2_string_list(
        plan.get("preexisting_action_ids"),
        label="axis promotion preexisting_action_ids",
    )
    blocked = _v2_string_list(
        plan.get("blocked_action_ids"),
        label="axis promotion blocked_action_ids",
    )
    plan_conflicting = _v2_string_list(
        plan.get("conflicting_claim_action_ids"),
        label="axis promotion conflicting_claim_action_ids",
    )
    deliverable = set(planned) | set(preexisting)
    if (
        set(planned) & set(preexisting)
        or deliverable & set(blocked)
        or deliverable | set(blocked) != set(action_ids)
        or not set(plan_conflicting) <= set(action_ids)
    ):
        raise AxisDispositionError(
            "axis promotion semantic-successor action partition is malformed"
        )
    before = plan.get("inventory_before")
    successor = plan.get("inventory_successor")
    before_ids = (
        set(str(value) for value in before.get("identities", ()))
        if isinstance(before, Mapping)
        and isinstance(before.get("identities"), list)
        else set()
    )
    successor_ids = (
        set(str(value) for value in successor.get("identities", ()))
        if isinstance(successor, Mapping)
        and isinstance(successor.get("identities"), list)
        else set()
    )
    if (
        not before_ids <= successor_ids
        or not set(planned_inventory_ids) <= successor_ids
        or set(planned_inventory_ids) & before_ids
    ):
        raise AxisDispositionError(
            "axis promotion semantic-successor CAS identities are malformed"
        )

    plan_debt_raw = plan.get("source_debt")
    if not isinstance(plan_debt_raw, list):
        raise AxisDispositionError(
            "axis promotion semantic-successor source debt is malformed"
        )
    plan_debt: list[dict[str, str]] = []
    allowed_debt_reasons = {
        "DUPLICATE_OR_INVALID_ACTION_SOURCE",
        "SOURCE_ACTION_UNAVAILABLE",
        "SOURCE_ACTION_AUTHORITY_MISMATCH",
        "CROSS_SOURCE_IMPOSTOR_IGNORED",
    }
    for index, raw in enumerate(plan_debt_raw):
        if (
            not isinstance(raw, Mapping)
            or set(raw)
            != {
                "action_id",
                "source",
                "reason",
                "expected_block_sha256",
            }
        ):
            raise AxisDispositionError(
                "axis promotion semantic-successor source debt row "
                f"{index} is malformed"
            )
        row = {
            key: str(raw.get(key) or "")
            for key in (
                "action_id",
                "source",
                "reason",
                "expected_block_sha256",
            )
        }
        action_id = row["action_id"]
        if (
            action_id not in normalized_hashes
            or row["source"] not in {"BASE", "REPAIR"}
            or row["reason"] not in allowed_debt_reasons
            or row["expected_block_sha256"] != normalized_hashes[action_id]
        ):
            raise AxisDispositionError(
                "axis promotion semantic-successor source debt row "
                f"{index} is invalid"
            )
        required_source = str(action_sources[action_id])
        if row["reason"] == "CROSS_SOURCE_IMPOSTOR_IGNORED":
            if (
                row["source"]
                != ("REPAIR" if required_source == "BASE" else "BASE")
                or action_id in blocked
            ):
                raise AxisDispositionError(
                    "axis promotion semantic-successor ignored impostor debt "
                    "is invalid"
                )
        elif row["source"] != required_source or action_id not in blocked:
            raise AxisDispositionError(
                "axis promotion semantic-successor unavailable source debt "
                "is invalid"
            )
        plan_debt.append(row)
    if plan_debt != sorted(
        plan_debt,
        key=lambda row: (
            row["action_id"],
            row["source"],
            row["reason"],
        ),
    ) or len(
        {
            (row["action_id"], row["source"], row["reason"])
            for row in plan_debt
        }
    ) != len(plan_debt):
        raise AxisDispositionError(
            "axis promotion semantic-successor source debt is not exact"
        )
    expected_plan_status = (
        "READY"
        if not blocked and not plan_conflicting and not plan_debt
        else "READY_WITH_DEBT"
    )
    if plan.get("status") != expected_plan_status:
        raise AxisDispositionError(
            "axis promotion semantic-successor plan status differs from debt"
        )

    preserved = _v2_string_list(
        semantic_successor.get("preserved_action_ids"),
        label="axis promotion semantic-successor preserved action_ids",
    )
    if set(preserved) != deliverable:
        raise AxisDispositionError(
            "axis promotion semantic successor does not preserve the exact "
            "deliverable action denominator"
        )

    deliveries_raw = receipt.get("deliveries")
    if not isinstance(deliveries_raw, list):
        raise AxisDispositionError(
            "axis promotion semantic-successor deliveries are malformed"
        )
    delivery_action_ids: list[str] = []
    for index, raw in enumerate(deliveries_raw):
        if (
            not isinstance(raw, Mapping)
            or set(raw)
            != {
                "action_id",
                "source_block_sha256",
                "inventory_id",
                "inventory_block_sha256",
            }
        ):
            raise AxisDispositionError(
                "axis promotion semantic-successor delivery "
                f"{index} is malformed"
            )
        action_id = str(raw.get("action_id") or "")
        inventory_id = str(raw.get("inventory_id") or "")
        block_hash = str(raw.get("inventory_block_sha256") or "")
        if (
            action_id not in deliverable
            or str(raw.get("source_block_sha256") or "")
            != normalized_hashes.get(action_id)
            or not re.fullmatch(
                r"[A-Z][A-Z0-9_-]{1,95}", inventory_id, re.ASCII
            )
            or not _HEX_RE.fullmatch(block_hash)
        ):
            raise AxisDispositionError(
                "axis promotion semantic-successor delivery "
                f"{index} is invalid"
            )
        if action_id in planned:
            expected = planned[action_id]
            if (
                inventory_id != expected["inventory_id"]
                or block_hash != expected["inventory_block_sha256"]
            ):
                raise AxisDispositionError(
                    "axis promotion semantic-successor planned delivery "
                    f"{action_id} differs from its immutable plan"
                )
        elif inventory_id not in before_ids:
            raise AxisDispositionError(
                "axis promotion semantic-successor preexisting delivery "
                f"{action_id} is outside the immutable predecessor"
            )
        delivery_action_ids.append(action_id)
    if (
        type(receipt.get("delivery_count")) is not int
        or receipt.get("delivery_count") != len(deliveries_raw)
        or delivery_action_ids != sorted(deliverable)
    ):
        raise AxisDispositionError(
            "axis promotion semantic-successor delivery denominator differs"
        )

    missing = _v2_string_list(
        receipt.get("missing_action_ids"),
        label="axis promotion receipt missing_action_ids",
    )
    receipt_conflicting = _v2_string_list(
        receipt.get("conflicting_claim_action_ids"),
        label="axis promotion receipt conflicting_claim_action_ids",
    )
    orphan = _v2_string_list(
        receipt.get("orphan_delivered_action_ids"),
        label="axis promotion receipt orphan_delivered_action_ids",
    )
    receipt_debt = receipt.get("source_debt")
    if (
        missing != blocked
        or receipt_conflicting != plan_conflicting
        or set(orphan) & set(action_ids)
        or receipt_debt != plan_debt
    ):
        raise AxisDispositionError(
            "axis promotion semantic-successor receipt debt differs from plan"
        )
    expected_receipt_status = (
        "COMPLETE"
        if not missing
        and not receipt_conflicting
        and not orphan
        and not receipt_debt
        else "COMPLETED_WITH_DEBT"
    )
    if receipt.get("status") != expected_receipt_status:
        raise AxisDispositionError(
            "axis promotion semantic-successor receipt status differs from debt"
        )
    return dict(receipt)


def validate_axis_promotion_authority(
    value: Mapping[str, Any],
    application_receipt: Mapping[str, Any] | None,
    *,
    base_findings_raw: bytes | None = None,
    repair_findings_raw: bytes | None = None,
    inventory_text: str,
    promotion_plan: Mapping[str, Any] | None = None,
    downstream_tail_authorizer: (
        Callable[
            [Mapping[str, Any], bytes],
            Mapping[str, Any] | None,
        ] | None
    ) = None,
) -> dict[str, Any]:
    receipt = _v2_validate_signed(
        value,
        schema=PROMOTION_RECEIPT_V2_SCHEMA,
        digest_key="promotion_receipt_digest",
        label="axis promotion authority",
    )
    if promotion_plan is not None:
        plan, _predecessor, semantic_successor = (
            _validate_axis_promotion_plan_replay(
                promotion_plan,
                application_receipt,
                run_id=str(receipt.get("run_id") or ""),
                current_inventory_raw=str(inventory_text).encode(
                    "utf-8", errors="strict"
                ),
                downstream_tail_authorizer=downstream_tail_authorizer,
            )
        )
        if semantic_successor is not None:
            return _validate_semantic_successor_promotion_authority(
                receipt,
                plan,
                semantic_successor,
            )
    replay = build_axis_promotion_authority(
        application_receipt,
        run_id=str(receipt.get("run_id") or ""),
        base_findings_raw=base_findings_raw,
        repair_findings_raw=repair_findings_raw,
        inventory_text=inventory_text,
        promotion_plan=promotion_plan,
        downstream_tail_authorizer=downstream_tail_authorizer,
    )
    if receipt != replay:
        raise AxisDispositionError(
            "axis promotion authority differs from current exact deliveries"
        )
    return receipt


__all__ = [
    "APPLICATION_RECEIPT_V2_SCHEMA",
    "ASSURANCE_DEBT_NAME",
    "ASSURANCE_DEBT_SCHEMA",
    "ASSURANCE_DEBT_V2_SCHEMA",
    "AXIS_APPLICATION_RECEIPT_NAME",
    "AXIS_EXECUTION_EVIDENCE_AUTHORITY_NAME",
    "AXIS_INITIAL_RECEIPT_NAME",
    "AXIS_MODEL_DISPOSITIONS_NAME",
    "AXIS_PROMOTION_PLAN_NAME",
    "AXIS_PROMOTION_RECEIPT_NAME",
    "AXIS_REPAIR_EXECUTION_RECEIPT_NAME",
    "AXIS_REPAIR_FINDINGS_NAME",
    "AXIS_REPAIR_MODEL_DISPOSITIONS_NAME",
    "AXIS_REPAIR_PLAN_NAME",
    "EXECUTION_EVIDENCE_AUTHORITY_SCHEMA",
    "INITIAL_RECEIPT_SCHEMA",
    "LIMITATIONS_NAME",
    "LIMITATIONS_V2_SCHEMA",
    "MODEL_DISPOSITIONS_SCHEMA",
    "POPULATION_AUTHORITY_SCHEMA",
    "PROMOTION_PLAN_SCHEMA",
    "PROMOTION_RECEIPT_V2_SCHEMA",
    "RECEIPT_NAME",
    "RECEIPT_SCHEMA",
    "REPAIR_EXECUTION_RECEIPT_SCHEMA",
    "REPAIR_MODEL_DISPOSITIONS_SCHEMA",
    "REPAIR_NAME",
    "REPAIR_PLAN_SCHEMA",
    "REPAIR_SCHEMA",
    "REPAIR_WORK_V2_SCHEMA",
    "WORKLIST_NAME",
    "WORKLIST_SCHEMA",
    "WORKLIST_V2_SCHEMA",
    "AxisDispositionError",
    "build_axis_execution_evidence_authority",
    "build_axis_promotion_plan",
    "build_axis_promotion_authority",
    "build_axis_repair_execution_receipt",
    "compile_axis_worklist",
    "compile_axis_worklist_v2",
    "load_axis_disposition_receipt",
    "load_axis_disposition_v2_receipt",
    "load_axis_promotion_plan",
    "load_axis_worklist",
    "load_axis_worklist_v2",
    "parse_axis_model_dispositions",
    "reconcile_axis_output",
    "reconcile_axis_dispositions_final",
    "reconcile_axis_dispositions_initial",
    "render_axis_inventory_block",
    "referenced_axis_action_blocks",
    "resolve_axis_action_blocks",
    "validate_axis_disposition_authority",
    "validate_axis_disposition_authority_v2",
    "validate_axis_execution_evidence_authority",
    "validate_axis_assurance_projection_v2",
    "validate_axis_population_authority",
    "validate_axis_promotion_authority",
    "validate_axis_promotion_plan",
    "validate_axis_promotion_plan_replay",
    "validate_axis_repair_execution_receipt",
    "validate_axis_repair_model_outputs",
    "write_axis_disposition_artifacts",
    "write_axis_disposition_v2_artifacts",
    "write_axis_worklist",
]
