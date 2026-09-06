"""Deterministic, decision-neutral finding facts for precedent reconciliation.

The precedent reconciler needs a complete finding denominator, but it must not
learn current-code facts from the precedent/RAG worker that it is evaluating.
This provider therefore reads only the final inventory and its mechanically
derived typed record sidecar.  It binds every row to an exact source block and
uses opaque, per-finding identities when no explicit typed mechanism contract
exists.  It does not infer semantics from titles, descriptions, root-cause
prose, locations, external reports, or shared vocabulary.

Malformed or ambiguous inputs degrade to content-bound ``UNMEASURABLE`` rows
and explicit debt.  They never disappear and never acquire verdict, severity,
proof, or family-equivalence authority.
"""
from __future__ import annotations

from collections import Counter, defaultdict
import hashlib
import json
import math
import os
from pathlib import Path
import re
from typing import Any, Mapping
import uuid

from bounded_artifact_io import read_bounded_regular_bytes


FINDING_FACTS_SCHEMA = "plamen.precedent_finding_facts.v1"
FACTS_NAME = "precedent_finding_facts.json"
INVENTORY_NAME = "findings_inventory.md"
TYPED_RECORDS_NAME = "finding_records.json"
TYPED_RECORDS_SCHEMAS = frozenset(
    {"plamen.finding_records.v1", "plamen.finding_records.v2"}
)

ASSURANCE = "CODE_FACT_BINDING_ONLY_NO_DECISION_AUTHORITY"
MAX_INVENTORY_BYTES = 64 * 1024 * 1024
MAX_TYPED_RECORD_BYTES = 64 * 1024 * 1024
MAX_FINDINGS = 100_000

_HEX64_RE = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$", re.ASCII)
_TOKEN_RE = re.compile(r"^[A-Z][A-Z0-9_]{1,95}$", re.ASCII)
_HEADING_RE = re.compile(
    r"^\s*#{2,4}\s+Finding\s+\[(?P<finding_id>[^\]\r\n]+)\]"
    r"[^\r\n]*$",
    re.IGNORECASE | re.ASCII,
)
_FENCE_RE = re.compile(r"^\s*(?P<marker>`{3,}|~{3,})")

_CAPABILITIES = {
    "may_change_severity": False,
    "may_clear_or_demote": False,
    "may_force_contested": False,
    "may_grant_proof": False,
    "may_propagate_family_equivalence": False,
}


class FindingFactProviderError(ValueError):
    """A supplied provider artifact cannot be validated without guessing."""


def canonical_json_bytes(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")


def _digest(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _sha_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(
        f".{path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp"
    )
    try:
        with open(temporary, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass


def _debt(code: str, subject: str, detail: str) -> dict[str, str]:
    return {"code": code, "subject": subject, "detail": detail}


def _normalize_id(value: Any) -> str:
    token = str(value or "").strip().upper()
    return token if _ID_RE.fullmatch(token) else ""


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise FindingFactProviderError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def _strict_json_bytes(raw: bytes, *, artifact: str) -> Mapping[str, Any]:
    def reject_constant(value: str) -> None:
        raise FindingFactProviderError(f"invalid JSON constant {value!r}")

    def finite_float(value: str) -> float:
        parsed = float(value)
        if not math.isfinite(parsed):
            raise FindingFactProviderError(
                f"invalid non-finite JSON number {value!r}"
            )
        return parsed

    try:
        text = raw.decode("utf-8", errors="strict")
        payload = json.loads(
            text,
            object_pairs_hook=_strict_object,
            parse_constant=reject_constant,
            parse_float=finite_float,
        )
    except FindingFactProviderError:
        raise
    except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise FindingFactProviderError(
            f"{artifact} is malformed: {type(exc).__name__}: {exc}"
        ) from exc
    if not isinstance(payload, Mapping):
        raise FindingFactProviderError(f"{artifact} root must be an object")
    return payload


def _input_descriptor(artifact: str, raw: bytes | None) -> dict[str, Any] | None:
    """Describe the already-read bytes; never re-open across a TOCTOU seam."""

    if raw is None:
        return None
    return {
        "artifact": artifact,
        "sha256": _sha_bytes(raw),
        "size_bytes": len(raw),
    }


def _inventory_blocks(
    raw: bytes,
) -> tuple[list[dict[str, Any]], list[dict[str, str]], bool]:
    """Return exact, fence-aware source blocks without normalizing bytes."""

    debts: list[dict[str, str]] = []
    if len(raw) > MAX_INVENTORY_BYTES:
        debts.append(
            _debt(
                "INVENTORY_ARTIFACT_OVERSIZED",
                INVENTORY_NAME,
                f"artifact exceeds {MAX_INVENTORY_BYTES} bytes",
            )
        )
        return [], debts, False
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeError as exc:
        debts.append(
            _debt(
                "INVENTORY_ARTIFACT_MALFORMED",
                INVENTORY_NAME,
                f"strict UTF-8 decode failed: {type(exc).__name__}: {exc}",
            )
        )
        return [], debts, False

    lines = text.splitlines(keepends=True)
    starts: list[tuple[int, str]] = []
    fence_character = ""
    fence_length = 0
    for index, line in enumerate(lines):
        fence = _FENCE_RE.match(line)
        if fence:
            marker = fence.group("marker")
            character = marker[0]
            if not fence_character:
                fence_character = character
                fence_length = len(marker)
            elif character == fence_character and len(marker) >= fence_length:
                fence_character = ""
                fence_length = 0
            continue
        if fence_character:
            continue
        match = _HEADING_RE.match(line.rstrip("\r\n"))
        if match:
            starts.append((index, match.group("finding_id").strip()))

    parse_ok = True
    if fence_character:
        debts.append(
            _debt(
                "INVENTORY_ARTIFACT_MALFORMED",
                INVENTORY_NAME,
                "inventory contains an unclosed Markdown fence",
            )
        )
        parse_ok = False

    blocks: list[dict[str, Any]] = []
    for ordinal, (start, raw_id) in enumerate(starts, 1):
        end = starts[ordinal][0] if ordinal < len(starts) else len(lines)
        block_text = "".join(lines[start:end])
        block_raw = block_text.encode("utf-8")
        normalized = _normalize_id(raw_id)
        block_sha = _sha_bytes(block_raw)
        if normalized:
            finding_id = normalized
            issues: list[str] = []
        else:
            finding_id = "UNMEASURABLE-" + block_sha[:20].upper()
            issues = ["finding_id is missing or malformed"]
            debts.append(
                _debt(
                    "FINDING_ID_MALFORMED",
                    finding_id,
                    "inventory heading identity is malformed; a content-bound debt identity was assigned",
                )
            )
        blocks.append(
            {
                "finding_id": finding_id,
                "raw_finding_id": raw_id,
                "source_ordinal": ordinal,
                "source_block_start_line": start + 1,
                "source_block_end_line": start + max(1, len(block_text.splitlines())),
                "source_block_sha256": block_sha,
                "identity_issues": issues,
            }
        )
    return blocks, debts, parse_ok


def _typed_records(
    raw: bytes,
    *,
    inventory_sha256: str,
) -> tuple[list[dict[str, Any]], list[dict[str, str]], bool]:
    debts: list[dict[str, str]] = []
    if len(raw) > MAX_TYPED_RECORD_BYTES:
        return [], [
            _debt(
                "TYPED_RECORD_ARTIFACT_OVERSIZED",
                TYPED_RECORDS_NAME,
                f"artifact exceeds {MAX_TYPED_RECORD_BYTES} bytes",
            )
        ], False
    try:
        payload = _strict_json_bytes(raw, artifact=TYPED_RECORDS_NAME)
    except FindingFactProviderError as exc:
        return [], [
            _debt(
                "TYPED_RECORD_ARTIFACT_MALFORMED",
                TYPED_RECORDS_NAME,
                str(exc),
            )
        ], False
    structural_issues: list[str] = []
    if payload.get("schema_version") not in TYPED_RECORDS_SCHEMAS:
        structural_issues.append("schema_version is unsupported")
    rows = payload.get("records")
    if not isinstance(rows, list):
        structural_issues.append("records must be an array")
    if structural_issues:
        return [], [
            _debt("TYPED_RECORD_ARTIFACT_MALFORMED", TYPED_RECORDS_NAME, issue)
            for issue in structural_issues
        ], False

    binding_issues: list[str] = []
    source = str(payload.get("source") or "")
    if source != INVENTORY_NAME:
        binding_issues.append("source does not bind findings_inventory.md")
    source_sha = str(payload.get("source_sha256") or "").strip().lower()
    if not _HEX64_RE.fullmatch(source_sha) or source_sha != inventory_sha256:
        binding_issues.append(
            "source_sha256 must exactly bind the current findings_inventory.md bytes"
        )
    debts.extend(
        [
            _debt("TYPED_RECORD_ARTIFACT_MALFORMED", TYPED_RECORDS_NAME, issue)
            for issue in binding_issues
        ]
    )
    source_binding_ok = not binding_issues

    records: list[dict[str, Any]] = []
    for ordinal, raw_row in enumerate(rows, 1):
        subject = f"row:{ordinal}"
        if not isinstance(raw_row, Mapping):
            debts.append(
                _debt(
                    "TYPED_RECORD_ROW_MALFORMED",
                    subject,
                    "typed record is not an object",
                )
            )
            continue
        record = dict(raw_row)
        finding_id = _normalize_id(record.get("inventory_id"))
        record_sha = _digest(record)
        if not finding_id:
            finding_id = "UNMEASURABLE-" + record_sha[:20].upper()
            debts.append(
                _debt(
                    "TYPED_RECORD_ID_MALFORMED",
                    finding_id,
                    "typed record inventory_id is malformed; a content-bound debt identity was assigned",
                )
            )
        records.append(
            {
                "finding_id": finding_id,
                "record": record,
                "record_sha256": record_sha,
                "record_ordinal": ordinal,
                "source_binding_ok": source_binding_ok,
            }
        )
    return records, debts, True


def _typed_semantics(
    typed: Mapping[str, Any] | None,
) -> tuple[str, list[str], str, str | None]:
    """Consume only an explicit all-or-nothing typed semantic contract."""

    if typed is None:
        return "", [], "OPAQUE_SOURCE_IDENTITY", None
    if typed.get("source_binding_ok") is not True:
        return "", [], "OPAQUE_SOURCE_IDENTITY", None
    record = typed.get("record")
    if not isinstance(record, Mapping):
        return "", [], "OPAQUE_SOURCE_IDENTITY", "typed record is unavailable"
    mechanism_raw = record.get("mechanism_class")
    preconditions_raw = record.get("precondition_classes")
    if mechanism_raw is None and preconditions_raw is None:
        return "", [], "OPAQUE_SOURCE_IDENTITY", None
    if not isinstance(mechanism_raw, str):
        return "", [], "OPAQUE_SOURCE_IDENTITY", "mechanism_class must be a string"
    mechanism = mechanism_raw.strip().upper()
    if not _TOKEN_RE.fullmatch(mechanism):
        return "", [], "OPAQUE_SOURCE_IDENTITY", "mechanism_class is malformed"
    if not isinstance(preconditions_raw, list) or not preconditions_raw:
        return "", [], "OPAQUE_SOURCE_IDENTITY", "precondition_classes must be a non-empty array"
    preconditions: list[str] = []
    for raw in preconditions_raw:
        if not isinstance(raw, str):
            return "", [], "OPAQUE_SOURCE_IDENTITY", "precondition_classes contains a non-string token"
        token = raw.strip().upper()
        if not _TOKEN_RE.fullmatch(token):
            return "", [], "OPAQUE_SOURCE_IDENTITY", "precondition_classes contains a malformed token"
        preconditions.append(token)
    if len(preconditions) != len(set(preconditions)):
        return "", [], "OPAQUE_SOURCE_IDENTITY", "precondition_classes contains duplicates"
    return mechanism, sorted(preconditions), "EXPLICIT_TYPED_FIELDS", None


def source_binding_digest(row: Mapping[str, Any]) -> str:
    """Digest the exact source and occurrence coordinates used by one fact."""

    binding = {
        "finding_id": str(row.get("finding_id") or ""),
        "source_artifact": str(row.get("source_artifact") or ""),
        "source_artifact_sha256": str(row.get("source_artifact_sha256") or ""),
        "source_block_sha256": str(row.get("source_block_sha256") or ""),
        "source_block_start_line": int(row.get("source_block_start_line") or 0),
        "source_block_end_line": int(row.get("source_block_end_line") or 0),
        "source_ordinal": int(row.get("source_ordinal") or 0),
        "typed_record_sha256": str(row.get("typed_record_sha256") or ""),
    }
    return _digest(binding)


def _opaque_semantics(binding: str) -> tuple[str, list[str]]:
    mechanism = "OPAQUE_MECHANISM_" + binding[:24].upper()
    precondition = "OPAQUE_PRECONDITION_" + binding[24:48].upper()
    return mechanism, [precondition]


def _finish_row(row: dict[str, Any]) -> dict[str, Any]:
    row["source_binding_sha256"] = source_binding_digest(row)
    issues = [str(value) for value in row.get("fact_issues", []) if str(value)]
    if row.get("extraction_status") == "UNMEASURABLE":
        row["mechanism_class"] = ""
        row["precondition_classes"] = []
        row["mechanism_origin"] = "UNMEASURABLE"
    elif not row.get("mechanism_class"):
        mechanism, preconditions = _opaque_semantics(row["source_binding_sha256"])
        row["mechanism_class"] = mechanism
        row["precondition_classes"] = preconditions
        row["mechanism_origin"] = "OPAQUE_SOURCE_IDENTITY"
    row["fact_issues"] = sorted(set(issues))
    row["family_equivalence_authority"] = False
    row["fact_digest"] = _digest(
        {
            "finding_id": row["finding_id"],
            "mechanism_class": row["mechanism_class"],
            "precondition_classes": row["precondition_classes"],
            "source_binding_sha256": row["source_binding_sha256"],
            "extraction_status": row["extraction_status"],
            "fact_issues": row["fact_issues"],
        }
    )
    return row


def _unmeasurable_from_typed(
    typed: Mapping[str, Any],
    *,
    typed_artifact_sha: str,
    issue: str,
) -> dict[str, Any]:
    record_sha = str(typed.get("record_sha256") or "")
    return _finish_row(
        {
            "finding_id": str(typed["finding_id"]),
            "mechanism_class": "",
            "precondition_classes": [],
            "mechanism_origin": "UNMEASURABLE",
            "extraction_status": "UNMEASURABLE",
            "source_artifact": TYPED_RECORDS_NAME,
            "source_artifact_sha256": typed_artifact_sha,
            "source_block_sha256": record_sha,
            "source_block_start_line": 0,
            "source_block_end_line": 0,
            "source_ordinal": int(typed.get("record_ordinal") or 0),
            "typed_record_sha256": record_sha,
            "fact_issues": [issue],
        }
    )


def derive_precedent_finding_facts(
    scratchpad: Path,
    *,
    run_id: str,
    snapshot_digest: str,
) -> dict[str, Any]:
    """Derive the complete current-code denominator without precedent input."""

    root = Path(scratchpad)
    normalized_run = str(run_id or "").strip()
    normalized_snapshot = str(snapshot_digest or "").strip().lower()
    debts: list[dict[str, str]] = []
    if not normalized_run:
        debts.append(_debt("RUN_BINDING_MALFORMED", "*", "run_id is empty"))
    if not _HEX64_RE.fullmatch(normalized_snapshot):
        debts.append(
            _debt(
                "SNAPSHOT_BINDING_MALFORMED",
                "*",
                "snapshot_digest is not a lowercase SHA-256 digest",
            )
        )

    inventory_path = root / INVENTORY_NAME
    typed_path = root / TYPED_RECORDS_NAME
    try:
        inventory_raw = read_bounded_regular_bytes(
            inventory_path, MAX_INVENTORY_BYTES
        )
    except OSError:
        inventory_raw = None
        inventory_sha = ""
        inventory_ok = False
        blocks: list[dict[str, Any]] = []
        debts.append(
            _debt(
                "INVENTORY_ARTIFACT_ABSENT",
                INVENTORY_NAME,
                "final inventory is unavailable",
            )
        )
    except ValueError as exc:
        inventory_raw = None
        inventory_sha = ""
        inventory_ok = False
        blocks = []
        code = (
            "INVENTORY_ARTIFACT_OVERSIZED"
            if "exceeds" in str(exc)
            else "INVENTORY_ARTIFACT_MALFORMED"
        )
        debts.append(_debt(code, INVENTORY_NAME, str(exc)))
    else:
        inventory_sha = _sha_bytes(inventory_raw)
        blocks, inventory_debts, inventory_ok = _inventory_blocks(inventory_raw)
        debts.extend(inventory_debts)

    try:
        typed_raw = read_bounded_regular_bytes(
            typed_path, MAX_TYPED_RECORD_BYTES
        )
    except OSError:
        typed_raw = None
        typed_sha = ""
        typed_ok = False
        typed_rows: list[dict[str, Any]] = []
        debts.append(
            _debt(
                "TYPED_RECORD_ARTIFACT_ABSENT",
                TYPED_RECORDS_NAME,
                "typed finding records are unavailable; exact source blocks use opaque identities",
            )
        )
    except ValueError as exc:
        typed_raw = None
        typed_sha = ""
        typed_ok = False
        typed_rows = []
        code = (
            "TYPED_RECORD_ARTIFACT_OVERSIZED"
            if "exceeds" in str(exc)
            else "TYPED_RECORD_ARTIFACT_MALFORMED"
        )
        debts.append(_debt(code, TYPED_RECORDS_NAME, str(exc)))
    else:
        typed_sha = _sha_bytes(typed_raw)
        typed_rows, typed_debts, typed_ok = _typed_records(
            typed_raw,
            inventory_sha256=inventory_sha,
        )
        debts.extend(typed_debts)

    typed_by_id: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for typed in typed_rows:
        typed_by_id[str(typed["finding_id"])].append(typed)
    duplicate_typed = {
        finding_id for finding_id, values in typed_by_id.items() if len(values) > 1
    }
    for finding_id in sorted(duplicate_typed):
        debts.append(
            _debt(
                "DUPLICATE_TYPED_ID",
                finding_id,
                f"typed artifact contains {len(typed_by_id[finding_id])} rows for one identity",
            )
        )

    block_counts = Counter(str(block["finding_id"]) for block in blocks)
    duplicate_blocks = {
        finding_id for finding_id, count in block_counts.items() if count > 1
    }
    for finding_id in sorted(duplicate_blocks):
        debts.append(
            _debt(
                "DUPLICATE_INVENTORY_ID",
                finding_id,
                f"inventory contains {block_counts[finding_id]} source blocks for one identity",
            )
        )

    findings: list[dict[str, Any]] = []
    consumed_typed_ordinals: set[int] = set()
    # The byte limit is the hard resource bound. Within that bound every block
    # remains visible; a high-cardinality input is degraded, never truncated.
    for block in blocks:
        finding_id = str(block["finding_id"])
        typed_matches = typed_by_id.get(finding_id, [])
        typed = typed_matches[0] if len(typed_matches) == 1 else None
        if typed is not None:
            consumed_typed_ordinals.add(int(typed["record_ordinal"]))
        row: dict[str, Any] = {
            "finding_id": finding_id,
            "mechanism_class": "",
            "precondition_classes": [],
            "mechanism_origin": "OPAQUE_SOURCE_IDENTITY",
            "extraction_status": "OPAQUE_BOUND",
            "source_artifact": INVENTORY_NAME,
            "source_artifact_sha256": inventory_sha,
            "source_block_sha256": str(block["source_block_sha256"]),
            "source_block_start_line": int(block["source_block_start_line"]),
            "source_block_end_line": int(block["source_block_end_line"]),
            "source_ordinal": int(block["source_ordinal"]),
            "typed_record_sha256": str(typed.get("record_sha256") or "") if typed else "",
            "fact_issues": list(block.get("identity_issues") or []),
        }
        if typed is not None and typed.get("source_binding_ok") is not True:
            row["fact_issues"].append(
                "typed semantic fields are not bound to the current inventory bytes"
            )
        ambiguous = bool(block.get("identity_issues")) or finding_id in duplicate_blocks
        if finding_id in duplicate_typed:
            ambiguous = True
            row["fact_issues"].append("typed finding identity is duplicated")
        if not inventory_ok:
            ambiguous = True
            row["fact_issues"].append("inventory artifact is not parseable")
        if ambiguous:
            row["extraction_status"] = "UNMEASURABLE"
        else:
            mechanism, preconditions, origin, semantic_issue = _typed_semantics(typed)
            if semantic_issue:
                debts.append(
                    _debt(
                        "TYPED_SEMANTIC_FIELDS_INVALID",
                        finding_id,
                        semantic_issue + "; opaque source identity retained",
                    )
                )
            row["mechanism_class"] = mechanism
            row["precondition_classes"] = preconditions
            row["mechanism_origin"] = origin
            if origin == "EXPLICIT_TYPED_FIELDS":
                row["extraction_status"] = "EXPLICIT_BOUND"
            if typed_ok and typed is None:
                debts.append(
                    _debt(
                        "TYPED_RECORD_MISSING",
                        finding_id,
                        "inventory block has no corresponding typed record; opaque source identity retained",
                    )
                )
        findings.append(_finish_row(row))

    if len(blocks) > MAX_FINDINGS:
        debts.append(
            _debt(
                "FINDING_DENOMINATOR_HIGH_CARDINALITY",
                "*",
                f"{len(blocks)} source blocks exceed the {MAX_FINDINGS} review threshold; all remain visible",
            )
        )

    # Every typed identity not matched to exactly one inventory block remains
    # visible, but cannot be compared to precedent without its source block.
    for typed in typed_rows:
        ordinal = int(typed["record_ordinal"])
        finding_id = str(typed["finding_id"])
        if ordinal in consumed_typed_ordinals:
            continue
        if blocks and block_counts.get(finding_id, 0) == 1 and finding_id in duplicate_typed:
            # The inventory row already carries the duplicate-typed debt. Do
            # not multiply the finding denominator by ambiguous sidecar rows.
            continue
        detail = "typed finding has no unique exact inventory source block"
        findings.append(
            _unmeasurable_from_typed(
                typed,
                typed_artifact_sha=typed_sha,
                issue=detail,
            )
        )
        debts.append(_debt("SOURCE_BLOCK_MISSING", finding_id, detail))

    # If an inventory artifact was present but could not expose any identity,
    # retain one content-bound sentinel so the parse failure cannot look like a
    # clean empty audit. Typed identities above remain separately visible.
    if inventory_raw is not None and not inventory_ok and not findings:
        sentinel_id = "UNMEASURABLE-" + inventory_sha[:20].upper()
        findings.append(
            _finish_row(
                {
                    "finding_id": sentinel_id,
                    "mechanism_class": "",
                    "precondition_classes": [],
                    "mechanism_origin": "UNMEASURABLE",
                    "extraction_status": "UNMEASURABLE",
                    "source_artifact": INVENTORY_NAME,
                    "source_artifact_sha256": inventory_sha,
                    "source_block_sha256": inventory_sha,
                    "source_block_start_line": 0,
                    "source_block_end_line": 0,
                    "source_ordinal": 0,
                    "typed_record_sha256": "",
                    "fact_issues": ["inventory identities could not be extracted"],
                }
            )
        )

    if not findings:
        debts.append(
            _debt(
                "EMPTY_FINDING_DENOMINATOR",
                "*",
                "no exact inventory finding blocks or typed debt identities are available",
            )
        )

    inputs = [
        descriptor
        for descriptor in (
            _input_descriptor(INVENTORY_NAME, inventory_raw),
            _input_descriptor(TYPED_RECORDS_NAME, typed_raw),
        )
        if descriptor is not None
    ]
    denominator = [
        {
            "finding_id": row["finding_id"],
            "source_binding_sha256": row["source_binding_sha256"],
            "fact_digest": row["fact_digest"],
        }
        for row in findings
    ]
    degraded = (
        not findings
        or not normalized_run
        or not _HEX64_RE.fullmatch(normalized_snapshot)
        or any(row["extraction_status"] == "UNMEASURABLE" for row in findings)
        or any(
            debt["code"].endswith(("MALFORMED", "OVERSIZED"))
            for debt in debts
        )
        or any(
            debt["code"] == "FINDING_DENOMINATOR_HIGH_CARDINALITY"
            for debt in debts
        )
    )
    payload: dict[str, Any] = {
        "schema_version": FINDING_FACTS_SCHEMA,
        "run_id": normalized_run,
        "snapshot_digest": normalized_snapshot,
        "assurance": ASSURANCE,
        "status": "DEGRADED" if degraded else "COMPLETE",
        "capabilities": dict(_CAPABILITIES),
        "input_artifacts": inputs,
        "denominator_count": len(findings),
        "denominator_digest": _digest(denominator),
        "findings": findings,
        "debts": sorted(
            debts,
            key=lambda row: (row["code"], row["subject"], row["detail"]),
        ),
    }
    payload["provider_digest"] = _digest(payload)
    return payload


def validate_precedent_finding_facts(
    payload: Mapping[str, Any],
    scratchpad: Path,
    *,
    run_id: str,
    snapshot_digest: str,
) -> list[str]:
    issues: list[str] = []
    if not isinstance(payload, Mapping):
        return ["precedent finding facts root is not an object"]
    if payload.get("schema_version") != FINDING_FACTS_SCHEMA:
        issues.append("precedent finding facts schema mismatch")
    stored = str(payload.get("provider_digest") or "")
    body = {key: value for key, value in payload.items() if key != "provider_digest"}
    if not _HEX64_RE.fullmatch(stored) or _digest(body) != stored:
        issues.append("precedent finding facts provider digest mismatch")
    if payload.get("capabilities") != _CAPABILITIES:
        issues.append("precedent finding facts capabilities were broadened")
    expected = derive_precedent_finding_facts(
        scratchpad,
        run_id=run_id,
        snapshot_digest=snapshot_digest,
    )
    if dict(payload) != expected:
        issues.append("precedent finding facts are stale or non-canonical")
    return sorted(set(issues))


def write_precedent_finding_facts(
    scratchpad: Path,
    *,
    run_id: str,
    snapshot_digest: str,
) -> dict[str, Any]:
    payload = derive_precedent_finding_facts(
        scratchpad,
        run_id=run_id,
        snapshot_digest=snapshot_digest,
    )
    _atomic_write(Path(scratchpad) / FACTS_NAME, canonical_json_bytes(payload))
    return payload


__all__ = [
    "ASSURANCE",
    "FACTS_NAME",
    "FINDING_FACTS_SCHEMA",
    "FindingFactProviderError",
    "INVENTORY_NAME",
    "TYPED_RECORDS_NAME",
    "derive_precedent_finding_facts",
    "source_binding_digest",
    "validate_precedent_finding_facts",
    "write_precedent_finding_facts",
]
