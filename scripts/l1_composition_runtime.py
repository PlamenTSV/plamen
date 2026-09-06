"""Deterministic L1 composition fact provider and proposal-only runtime.

The L1 composition authority operates on typed atoms.  Existing L1 audit
artifacts are Markdown and do not provide a trustworthy typed atom producer,
so this module deliberately does *not* recover semantics from prose, headings,
chain-summary tables, titles, paths, or shared vocabulary.  It builds a
complete, exact-byte-bound occurrence denominator from the authoritative L1
inventory/depth artifacts and accepts semantics only from a strict sidecar row
bound to one exact source block and the current run/snapshot.

Every missing or ambiguous semantic row survives as a stable opaque identity
and visible UNMEASURABLE debt.  Model dispositions can only propose a bounded
compound handoff for the independent P0-AF lifecycle; this provider has no
finding, proof, verdict, severity, deletion, or queue-delivery authority.
"""
from __future__ import annotations

from collections import Counter, defaultdict
import hashlib
import json
import os
from pathlib import Path
import re
from typing import Any, Iterable, Mapping, Sequence
import uuid

from l1_composition_authority import (
    L1CompositionError,
    enumerate_l1_composition_graph,
    normalize_l1_composition_fact,
    reconcile_l1_composition_dispositions,
    validate_l1_composition_fact,
    validate_l1_composition_graph,
)


RUNTIME_SCHEMA = "plamen.l1_composition_runtime.v1"
TYPED_RECORDS_SCHEMA = "plamen.l1_composition_typed_records.v1"
FACT_WORKLIST_SCHEMA = "plamen.l1_composition_fact_worklist.v1"
WORK_PACKET_SCHEMA = "plamen.l1_composition_work_packet.v1"
MODEL_DISPOSITIONS_SCHEMA = "plamen.l1_composition_model_dispositions.v1"
RECEIPT_SCHEMA = "plamen.l1_composition_runtime_receipt.v1"
COMPOUND_HANDOFF_SCHEMA = "plamen.l1_compound_proposal_handoff.v1"

INVENTORY_NAME = "findings_inventory.md"
TYPED_RECORDS_NAME = "l1_composition_fact_records.json"
FACT_WORKLIST_NAME = "l1_composition_fact_worklist.json"
RUNTIME_NAME = "l1_composition_runtime.json"
MODEL_DISPOSITIONS_NAME = "l1_composition_model_dispositions.json"
RECEIPT_NAME = "l1_composition_receipt.json"

MAX_SOURCE_ARTIFACT_BYTES = 32 * 1024 * 1024
MAX_TYPED_RECORD_BYTES = 32 * 1024 * 1024
MAX_TOTAL_INPUT_BYTES = 96 * 1024 * 1024
MAX_SOURCE_FINDINGS = 20_000
MAX_TYPED_RECORDS = 20_000
MAX_WORK_PACKETS = 768
MAX_OUTPUT_BYTES = 96 * 1024 * 1024

MAX_GRAPH_PAIR_FANOUT = 6
MAX_GRAPH_EDGES = 512
MAX_GRAPH_FAMILY_MEMBERS = 128
MAX_GRAPH_FAMILIES = 256

PROPOSAL_ONLY_CAPABILITIES = {
    "may_assert_finding": False,
    "may_grant_proof": False,
    "may_change_verdict": False,
    "may_change_severity": False,
    "may_clear_or_demote": False,
    "may_delete_candidate": False,
    "may_deliver_to_queue": False,
}

_HEX64_RE = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
_ID_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.:-]{1,127}$", re.ASCII)
_DEPTH_NAME_RE = re.compile(
    r"^depth_[A-Za-z0-9_]{1,160}_findings\.md$", re.ASCII
)
_SUPPLEMENTAL_DEPTH_NAME_RE = re.compile(
    r"^(?:"
    r"depth_findings|"
    r"blind_spot_[A-Za-z0-9_]{1,160}_findings|"
    r"niche_[A-Za-z0-9_]{1,160}_findings|"
    r"scanner_[A-Za-z0-9_]{1,160}_findings|"
    r"validation_sweep_findings|"
    r"design_stress_findings|"
    r"perturbation_findings"
    r")\.md$",
    re.ASCII,
)
_HEADING_RE = re.compile(
    r"^\s*#{2,4}\s+(?:Finding\s+)?\[(?P<candidate_id>[^\]\r\n]+)\]"
    r"[^\r\n]*$",
    re.IGNORECASE | re.ASCII,
)
_FENCE_RE = re.compile(r"^\s*(?P<marker>`{3,}|~{3,})")


class L1CompositionRuntimeError(ValueError):
    """A runtime input is structurally invalid and cannot be guessed."""


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
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp")
    with open(temporary, "wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def _debt(code: str, subject: str, detail: str) -> dict[str, str]:
    return {"code": code, "subject": subject, "detail": detail}


def _bounded_text(value: Any, field: str, *, maximum: int = 4096) -> str:
    if not isinstance(value, str) or not value.strip():
        raise L1CompositionRuntimeError(f"{field} must be a non-empty string")
    result = value.strip()
    if len(result) > maximum:
        raise L1CompositionRuntimeError(f"{field} exceeds {maximum} characters")
    if any(ord(char) < 32 or ord(char) == 127 for char in result):
        raise L1CompositionRuntimeError(f"{field} contains control characters")
    return result


def _snapshot(value: Any) -> str:
    result = str(value or "").strip().lower()
    if not _HEX64_RE.fullmatch(result):
        raise L1CompositionRuntimeError("snapshot_digest must be lowercase SHA-256")
    return result


def _candidate_id(value: Any) -> str:
    result = str(value or "").strip().upper()
    return result if _ID_RE.fullmatch(result) else ""


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise L1CompositionRuntimeError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def _strict_json_bytes(raw: bytes, *, artifact: str) -> Mapping[str, Any]:
    def reject_constant(value: str) -> None:
        raise L1CompositionRuntimeError(f"invalid JSON constant {value!r}")

    try:
        payload = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_strict_object,
            parse_constant=reject_constant,
        )
    except L1CompositionRuntimeError:
        raise
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise L1CompositionRuntimeError(
            f"{artifact} is malformed: {type(exc).__name__}: {exc}"
        ) from exc
    if not isinstance(payload, Mapping):
        raise L1CompositionRuntimeError(f"{artifact} root must be an object")
    return payload


def _descriptor(artifact: str, role: str, raw: bytes) -> dict[str, Any]:
    return {
        "artifact": artifact,
        "role": role,
        "sha256": _sha_bytes(raw),
        "size_bytes": len(raw),
    }


def _is_finding_source_name(name: str) -> bool:
    return bool(
        name == INVENTORY_NAME
        or _DEPTH_NAME_RE.fullmatch(name)
        or _SUPPLEMENTAL_DEPTH_NAME_RE.fullmatch(name)
    )


def _discover_source_names(root: Path) -> list[str]:
    names: list[str] = []
    inventory = root / INVENTORY_NAME
    if inventory.exists() or inventory.is_symlink():
        names.append(INVENTORY_NAME)
    for path in sorted(root.glob("*.md"), key=lambda row: row.name):
        if _is_finding_source_name(path.name) and path.name not in names:
            names.append(path.name)
    return names


def l1_composition_source_artifacts(
    scratchpad: Path | str,
    *,
    pipeline: str,
    mode: str,
) -> tuple[str, ...]:
    """Return the exact live source denominator without reading file bytes.

    Inactive branches deliberately enumerate nothing.  The caller can bind the
    returned identities in PhaseIO before any worker is launched.
    """

    if str(pipeline or "").strip().lower() != "l1":
        return ()
    if str(mode or "").strip().lower() not in {"core", "thorough"}:
        return ()
    return tuple(_discover_source_names(Path(scratchpad)))


def _read_exact_inputs(
    root: Path, source_names: Sequence[str], *, include_typed: bool = True
) -> tuple[dict[str, bytes], bytes | None, list[dict[str, Any]], list[dict[str, str]]]:
    """Read every selected source at most once and retain those exact bytes."""

    raw_sources: dict[str, bytes] = {}
    descriptors: list[dict[str, Any]] = []
    debts: list[dict[str, str]] = []
    total = 0
    for name in source_names:
        path = root / name
        if path.is_symlink() or not path.is_file():
            debts.append(
                _debt(
                    "SOURCE_ARTIFACT_NOT_REGULAR",
                    name,
                    "authoritative source must be a regular in-scratchpad file",
                )
            )
            continue
        try:
            raw = path.read_bytes()
        except OSError as exc:
            debts.append(
                _debt(
                    "SOURCE_ARTIFACT_UNREADABLE",
                    name,
                    f"exact-byte read failed: {type(exc).__name__}: {exc}",
                )
            )
            continue
        total += len(raw)
        descriptors.append(_descriptor(name, "AUTHORITATIVE_L1_FINDINGS", raw))
        if len(raw) > MAX_SOURCE_ARTIFACT_BYTES:
            debts.append(
                _debt(
                    "SOURCE_ARTIFACT_OVERSIZED",
                    name,
                    f"artifact exceeds {MAX_SOURCE_ARTIFACT_BYTES} bytes",
                )
            )
            continue
        if total > MAX_TOTAL_INPUT_BYTES:
            debts.append(
                _debt(
                    "TOTAL_INPUT_BUDGET_EXHAUSTED",
                    name,
                    f"selected input bytes exceed {MAX_TOTAL_INPUT_BYTES}",
                )
            )
            continue
        raw_sources[name] = raw

    typed_raw: bytes | None = None
    if not include_typed:
        return raw_sources, None, sorted(
            descriptors, key=lambda row: row["artifact"]
        ), debts
    typed_path = root / TYPED_RECORDS_NAME
    if typed_path.exists() or typed_path.is_symlink():
        if typed_path.is_symlink() or not typed_path.is_file():
            debts.append(
                _debt(
                    "TYPED_RECORD_ARTIFACT_NOT_REGULAR",
                    TYPED_RECORDS_NAME,
                    "typed records must be a regular in-scratchpad file",
                )
            )
        else:
            try:
                raw = typed_path.read_bytes()
            except OSError as exc:
                debts.append(
                    _debt(
                        "TYPED_RECORD_ARTIFACT_UNREADABLE",
                        TYPED_RECORDS_NAME,
                        f"exact-byte read failed: {type(exc).__name__}: {exc}",
                    )
                )
            else:
                total += len(raw)
                descriptors.append(_descriptor(TYPED_RECORDS_NAME, "TYPED_FACT_PROPOSALS", raw))
                if len(raw) > MAX_TYPED_RECORD_BYTES:
                    debts.append(
                        _debt(
                            "TYPED_RECORD_ARTIFACT_OVERSIZED",
                            TYPED_RECORDS_NAME,
                            f"artifact exceeds {MAX_TYPED_RECORD_BYTES} bytes",
                        )
                    )
                elif total > MAX_TOTAL_INPUT_BYTES:
                    debts.append(
                        _debt(
                            "TOTAL_INPUT_BUDGET_EXHAUSTED",
                            TYPED_RECORDS_NAME,
                            f"selected input bytes exceed {MAX_TOTAL_INPUT_BYTES}",
                        )
                    )
                else:
                    typed_raw = raw
    else:
        debts.append(
            _debt(
                "TYPED_RECORD_ARTIFACT_ABSENT",
                TYPED_RECORDS_NAME,
                "no typed L1 atom producer artifact exists; prose was not parsed",
            )
        )
    return raw_sources, typed_raw, sorted(descriptors, key=lambda row: row["artifact"]), debts


def _parse_source_blocks(
    artifact: str,
    raw: bytes,
    *,
    artifact_sha256: str,
) -> tuple[list[dict[str, Any]], list[dict[str, str]], bool]:
    debts: list[dict[str, str]] = []
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeError as exc:
        return [], [
            _debt(
                "SOURCE_ARTIFACT_MALFORMED",
                artifact,
                f"strict UTF-8 decode failed: {type(exc).__name__}: {exc}",
            )
        ], False
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
            starts.append((index, match.group("candidate_id").strip()))

    artifact_clean = True
    if fence_character:
        artifact_clean = False
        debts.append(
            _debt(
                "SOURCE_ARTIFACT_MALFORMED",
                artifact,
                "source contains an unclosed Markdown fence",
            )
        )

    rows: list[dict[str, Any]] = []
    for ordinal, (start, raw_id) in enumerate(starts, 1):
        end = starts[ordinal][0] if ordinal < len(starts) else len(lines)
        block_raw = "".join(lines[start:end]).encode("utf-8")
        block_sha = _sha_bytes(block_raw)
        normalized = _candidate_id(raw_id)
        issues: list[str] = []
        if not normalized:
            normalized = "UNMEASURABLE-" + block_sha[:20].upper()
            issues.append("CANDIDATE_ID_MALFORMED")
            debts.append(
                _debt(
                    "CANDIDATE_ID_MALFORMED",
                    normalized,
                    "heading identity is malformed; a content-bound identity was assigned",
                )
            )
        if not artifact_clean:
            issues.append("SOURCE_ARTIFACT_MALFORMED")
        rows.append(
            {
                "candidate_id": normalized,
                "raw_candidate_id": raw_id,
                "source_artifact": artifact,
                "source_artifact_sha256": artifact_sha256,
                "source_block_sha256": block_sha,
                "source_ordinal": ordinal,
                "source_block_start_line": start + 1,
                "source_block_end_line": start + max(1, len(block_raw.decode("utf-8").splitlines())),
                "issues": issues,
            }
        )
    return rows, debts, artifact_clean


def derive_l1_composition_fact_worklist(
    scratchpad: Path | str,
    *,
    pipeline: str,
    mode: str,
    language: str,
    run_id: str,
    snapshot_digest: str,
) -> dict[str, Any]:
    """Enumerate every typed-fact application row before the model runs.

    This provider uses only finding headings and exact byte boundaries.  It
    never infers a semantic atom from Markdown, so the worklist is an
    application denominator rather than a finding or composition authority.
    """

    root = Path(scratchpad)
    pipeline_n = str(pipeline or "").strip().lower()
    mode_n = str(mode or "").strip().lower()
    language_n = str(language or "").strip().upper()
    run_id_n = _bounded_text(run_id, "run_id", maximum=256)
    snapshot_n = _snapshot(snapshot_digest)
    triggered = pipeline_n == "l1" and mode_n in {"core", "thorough"}
    descriptors: list[dict[str, Any]] = []
    occurrences: list[dict[str, Any]] = []
    debts: list[dict[str, str]] = []
    if triggered:
        source_names = _discover_source_names(root)
        raw_sources, _typed_raw, raw_descriptors, read_debts = _read_exact_inputs(
            root, source_names, include_typed=False
        )
        # The fact worklist precedes the typed producer.  Absence or drift of a
        # prior typed output is outside this denominator and must not poison it.
        descriptors = [
            row for row in raw_descriptors
            if row.get("role") == "AUTHORITATIVE_L1_FINDINGS"
        ]
        debts.extend(read_debts)
        descriptor_by_name = {
            str(row["artifact"]): row for row in descriptors
        }
        for name in source_names:
            raw = raw_sources.get(name)
            descriptor = descriptor_by_name.get(name)
            if raw is None or descriptor is None:
                continue
            rows, parse_debts, _clean = _parse_source_blocks(
                name, raw, artifact_sha256=str(descriptor["sha256"])
            )
            debts.extend(parse_debts)
            occurrences.extend(
                {
                    "candidate_id": str(row["candidate_id"]),
                    "source_artifact": str(row["source_artifact"]),
                    "source_artifact_sha256": str(row["source_artifact_sha256"]),
                    "source_block_sha256": str(row["source_block_sha256"]),
                    "source_ordinal": int(row["source_ordinal"]),
                    "source_block_start_line": int(row["source_block_start_line"]),
                    "source_block_end_line": int(row["source_block_end_line"]),
                    "occurrence_id": "L1FO-" + _digest(_source_binding(row))[:20].upper(),
                }
                for row in rows
            )
    occurrences.sort(
        key=lambda row: (
            0 if row["source_artifact"] == INVENTORY_NAME else 1,
            row["source_artifact"],
            row["source_ordinal"],
            row["candidate_id"],
        )
    )
    unique_debts = sorted(
        {canonical_json_bytes(row): row for row in debts}.values(),
        key=lambda row: (row["code"], row["subject"], row["detail"]),
    )
    result: dict[str, Any] = {
        "schema_version": FACT_WORKLIST_SCHEMA,
        "run_id": run_id_n,
        "snapshot_digest": snapshot_n,
        "pipeline": pipeline_n,
        "mode": mode_n,
        "language": language_n,
        "status": (
            "NOT_TRIGGERED" if not triggered else
            "DEGRADED" if unique_debts else "READY"
        ),
        "input_artifacts": descriptors,
        "occurrence_count": len(occurrences),
        "occurrences": occurrences,
        "debts": unique_debts,
        "capabilities": dict(PROPOSAL_ONLY_CAPABILITIES),
        "worklist_digest": "",
    }
    unsigned = dict(result)
    unsigned["worklist_digest"] = ""
    result["worklist_digest"] = _digest(unsigned)
    return result


def validate_l1_composition_fact_worklist(
    value: Mapping[str, Any],
    scratchpad: Path | str,
    **context: str,
) -> list[str]:
    try:
        expected = derive_l1_composition_fact_worklist(scratchpad, **context)
    except (L1CompositionRuntimeError, OSError, TypeError, ValueError) as exc:
        return [f"fact worklist re-derivation failed: {type(exc).__name__}: {exc}"]
    return [] if dict(value) == expected else [
        "fact worklist is stale, tampered, or denominator-mismatched"
    ]


def write_l1_composition_fact_worklist(
    scratchpad: Path | str,
    **context: str,
) -> dict[str, Any]:
    root = Path(scratchpad)
    payload = derive_l1_composition_fact_worklist(root, **context)
    _atomic_write(root / FACT_WORKLIST_NAME, canonical_json_bytes(payload))
    return payload


def validate_l1_composition_fact_records(
    scratchpad: Path | str,
    *,
    pipeline: str,
    mode: str,
    language: str,
    run_id: str,
    snapshot_digest: str,
    expected_producer_identity: str = "",
    expected_producer_invocation_id: str = "",
) -> list[str]:
    """Require exactly one structurally valid typed row per worklist row."""

    root = Path(scratchpad)
    worklist_path = root / FACT_WORKLIST_NAME
    typed_path = root / TYPED_RECORDS_NAME
    try:
        worklist = _strict_json_bytes(
            worklist_path.read_bytes(), artifact=FACT_WORKLIST_NAME
        )
    except (OSError, L1CompositionRuntimeError) as exc:
        return [f"fact worklist missing/malformed: {type(exc).__name__}: {exc}"]
    worklist_issues = validate_l1_composition_fact_worklist(
        worklist,
        root,
        pipeline=pipeline,
        mode=mode,
        language=language,
        run_id=run_id,
        snapshot_digest=snapshot_digest,
    )
    if worklist_issues:
        return worklist_issues
    try:
        raw = typed_path.read_bytes()
        records, producer, invocation, _sha, debts, valid = _typed_records(
            raw, run_id=run_id, snapshot_digest=snapshot_digest
        )
    except OSError as exc:
        return [f"typed fact records missing: {type(exc).__name__}: {exc}"]
    issues = [
        f"typed fact record debt {row['code']}: {row['subject']}"
        for row in debts
    ]
    if expected_producer_identity and producer != expected_producer_identity:
        issues.append("typed fact producer identity is not driver-bound")
    if (
        expected_producer_invocation_id
        and invocation != expected_producer_invocation_id
    ):
        issues.append("typed fact producer invocation is not driver-bound")
    expected = [
        (
            str(row["candidate_id"]),
            str(row["source_artifact"]),
            str(row["source_block_sha256"]),
        )
        for row in worklist.get("occurrences", [])
    ]
    actual = [
        (
            str(row.get("candidate_id") or ""),
            str(row.get("source_artifact") or ""),
            str(row.get("source_block_sha256") or ""),
        )
        for row in records
    ]
    if not valid or actual != expected:
        issues.append("typed fact records do not exactly cover the fact worklist")
    # Reuse the runtime normalizer so syntactically present but semantically
    # invalid atoms cannot satisfy methodology application.
    try:
        runtime = derive_l1_composition_runtime(
            root,
            pipeline=pipeline,
            mode=mode,
            language=language,
            run_id=run_id,
            snapshot_digest=snapshot_digest,
        )
    except (L1CompositionRuntimeError, OSError, TypeError, ValueError) as exc:
        issues.append(f"typed fact runtime projection failed: {type(exc).__name__}: {exc}")
    else:
        if runtime.get("represented_denominator_count") != len(expected):
            issues.append("typed fact runtime lost a worklist occurrence")
        application_unmeasurable = [
            row for row in runtime.get("facts") or []
            if isinstance(row, Mapping)
            and row.get("extraction_status") == "UNMEASURABLE"
            and set(row.get("issues") or [])
            != {"DUPLICATE_SOURCE_CANDIDATE_SHADOWED_BY_INVENTORY"}
        ]
        if application_unmeasurable:
            issues.append("typed fact runtime contains unmeasurable model rows")
    return sorted(set(issues))


def _typed_records(
    raw: bytes | None,
    *,
    run_id: str,
    snapshot_digest: str,
) -> tuple[list[dict[str, Any]], str, str, str, list[dict[str, str]], bool]:
    if raw is None:
        return [], "", "", "", [], False
    debts: list[dict[str, str]] = []
    try:
        payload = _strict_json_bytes(raw, artifact=TYPED_RECORDS_NAME)
    except L1CompositionRuntimeError as exc:
        return [], "", "", "", [
            _debt("TYPED_RECORD_ARTIFACT_MALFORMED", TYPED_RECORDS_NAME, str(exc))
        ], False
    expected = {
        "schema_version",
        "run_id",
        "snapshot_digest",
        "producer_identity",
        "producer_invocation_id",
        "records",
    }
    if set(payload) != expected or payload.get("schema_version") != TYPED_RECORDS_SCHEMA:
        return [], "", "", "", [
            _debt(
                "TYPED_RECORD_ARTIFACT_MALFORMED",
                TYPED_RECORDS_NAME,
                "typed-record root schema mismatch",
            )
        ], False
    try:
        producer_identity = _bounded_text(payload.get("producer_identity"), "producer_identity", maximum=256)
        producer_invocation_id = _bounded_text(
            payload.get("producer_invocation_id"), "producer_invocation_id", maximum=256
        )
    except L1CompositionRuntimeError as exc:
        return [], "", "", "", [
            _debt("TYPED_RECORD_ARTIFACT_MALFORMED", TYPED_RECORDS_NAME, str(exc))
        ], False
    if payload.get("run_id") != run_id or payload.get("snapshot_digest") != snapshot_digest:
        return [], producer_identity, producer_invocation_id, _sha_bytes(raw), [
            _debt(
                "TYPED_RECORD_CONTEXT_MISMATCH",
                TYPED_RECORDS_NAME,
                "typed records do not bind the current run_id and snapshot_digest",
            )
        ], False
    records = payload.get("records")
    if not isinstance(records, list):
        return [], producer_identity, producer_invocation_id, _sha_bytes(raw), [
            _debt(
                "TYPED_RECORD_ARTIFACT_MALFORMED",
                TYPED_RECORDS_NAME,
                "records must be an array",
            )
        ], False
    if len(records) > MAX_TYPED_RECORDS:
        debts.append(
            _debt(
                "TYPED_RECORD_BUDGET_EXHAUSTED",
                TYPED_RECORDS_NAME,
                f"{len(records)} rows exceed the {MAX_TYPED_RECORDS} row bound; no row was trusted",
            )
        )
        return [], producer_identity, producer_invocation_id, _sha_bytes(raw), debts, False
    normalized: list[dict[str, Any]] = []
    row_expected = {
        "candidate_id",
        "source_artifact",
        "source_block_sha256",
        "language",
        "layer",
        "subsystem",
        "root_cause_id",
        "candidate_state",
        "requires",
        "produces",
        "touches",
    }
    for ordinal, raw_row in enumerate(records, 1):
        subject = f"row:{ordinal}"
        if not isinstance(raw_row, Mapping) or set(raw_row) != row_expected:
            debts.append(
                _debt(
                    "TYPED_RECORD_ROW_MALFORMED",
                    subject,
                    "typed row schema mismatch",
                )
            )
            continue
        row = dict(raw_row)
        candidate = _candidate_id(row.get("candidate_id"))
        artifact = str(row.get("source_artifact") or "").strip()
        block_sha = str(row.get("source_block_sha256") or "").strip().lower()
        if (
            not candidate
            or not _is_finding_source_name(artifact)
            or not _HEX64_RE.fullmatch(block_sha)
        ):
            debts.append(
                _debt(
                    "TYPED_RECORD_ROW_MALFORMED",
                    subject,
                    "candidate/source binding fields are invalid",
                )
            )
            continue
        row["candidate_id"] = candidate
        row["source_artifact"] = artifact
        row["source_block_sha256"] = block_sha
        row["record_ordinal"] = ordinal
        row["typed_record_digest"] = _digest(dict(raw_row))
        normalized.append(row)
    return (
        normalized,
        producer_identity,
        producer_invocation_id,
        _sha_bytes(raw),
        debts,
        True,
    )


def _source_binding(row: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "candidate_id": str(row.get("candidate_id") or ""),
        "source_artifact": str(row.get("source_artifact") or ""),
        "source_artifact_sha256": str(row.get("source_artifact_sha256") or ""),
        "source_block_sha256": str(row.get("source_block_sha256") or ""),
        "source_ordinal": int(row.get("source_ordinal") or 0),
        "source_block_start_line": int(row.get("source_block_start_line") or 0),
        "source_block_end_line": int(row.get("source_block_end_line") or 0),
    }


def _opaque_identity(row: Mapping[str, Any]) -> str:
    return "L1OPAQUE-" + _digest(_source_binding(row))[:20].upper()


def _finalize_fact_row(
    source: Mapping[str, Any],
    *,
    composition_fact: Mapping[str, Any] | None,
    typed_record_digest: str,
    typed_artifact_sha256: str,
    issues: Sequence[str],
) -> dict[str, Any]:
    result = {
        **_source_binding(source),
        "source_block_start_line": int(source.get("source_block_start_line") or 0),
        "source_block_end_line": int(source.get("source_block_end_line") or 0),
        "opaque_identity": _opaque_identity(source),
        "extraction_status": "MEASURABLE" if composition_fact is not None and not issues else "UNMEASURABLE",
        "typed_record_digest": typed_record_digest,
        "typed_artifact_sha256": typed_artifact_sha256,
        "composition_fact": dict(composition_fact) if composition_fact is not None and not issues else None,
        "issues": sorted(set(str(issue) for issue in issues if issue)),
        "row_digest": "",
    }
    unsigned = dict(result)
    unsigned["row_digest"] = ""
    result["row_digest"] = _digest(unsigned)
    return result


def _work_packet(
    obligation: Mapping[str, Any],
    *,
    graph: Mapping[str, Any],
    fact_rows_by_id: Mapping[str, Mapping[str, Any]],
    run_id: str,
    snapshot_digest: str,
) -> dict[str, Any]:
    if "predecessor_id" in obligation:
        kind = "EDGE"
        candidate_ids = sorted(
            {str(obligation["predecessor_id"]), str(obligation["successor_id"])}
        )
        relation = str(obligation["relation"])
        atom = dict(obligation["atom"])
        constituent_fact_digests = sorted(
            str(value) for value in obligation.get("constituent_fact_digests", [])
        )
    else:
        kind = "FAMILY"
        candidate_ids = sorted(str(value) for value in obligation.get("candidate_ids", []))
        relation = str(obligation["relation"])
        atom = dict(obligation["atom"])
        constituent_fact_digests = sorted(
            str(fact_rows_by_id[candidate]["composition_fact"]["fact_digest"])
            for candidate in candidate_ids
        )
    bindings = [
        {
            **_source_binding(fact_rows_by_id[candidate]),
            "fact_digest": str(
                fact_rows_by_id[candidate]["composition_fact"]["fact_digest"]
            ),
            "fact_row_digest": str(fact_rows_by_id[candidate]["row_digest"]),
        }
        for candidate in candidate_ids
    ]
    result = {
        "schema_version": WORK_PACKET_SCHEMA,
        "obligation_id": str(obligation["obligation_id"]),
        "packet_kind": kind,
        "run_id": run_id,
        "snapshot_digest": snapshot_digest,
        "graph_digest": str(graph["graph_digest"]),
        "facts_digest": str(graph["facts_digest"]),
        "candidate_ids": candidate_ids,
        "constituent_fact_digests": constituent_fact_digests,
        "constituent_source_bindings": bindings,
        "relation": relation,
        "atom": atom,
        "authority": "REASONING_OBLIGATION_ONLY",
        "capabilities": dict(PROPOSAL_ONLY_CAPABILITIES),
        "packet_digest": "",
    }
    unsigned = dict(result)
    unsigned["packet_digest"] = ""
    result["packet_digest"] = _digest(unsigned)
    return result


def _not_triggered_runtime(
    *,
    pipeline: str,
    mode: str,
    language: str,
    run_id: str,
    snapshot_digest: str,
    reason: str,
) -> dict[str, Any]:
    payload = {
        "schema_version": RUNTIME_SCHEMA,
        "run_id": run_id,
        "snapshot_digest": snapshot_digest,
        "pipeline": pipeline,
        "mode": mode,
        "language": language,
        "status": "NOT_TRIGGERED",
        "activation": {"triggered": False, "reason": reason},
        "input_artifacts": [],
        "denominator_count": 0,
        "represented_denominator_count": 0,
        "measurable_count": 0,
        "unmeasurable_count": 0,
        "facts": [],
        "graph": None,
        "work_packets": [],
        "work_packets_digest": _digest([]),
        "debts": [],
        "capabilities": dict(PROPOSAL_ONLY_CAPABILITIES),
        "runtime_digest": "",
    }
    unsigned = dict(payload)
    unsigned["runtime_digest"] = ""
    payload["runtime_digest"] = _digest(unsigned)
    return payload


def derive_l1_composition_runtime(
    scratchpad: Path | str,
    *,
    pipeline: str,
    mode: str,
    language: str,
    run_id: str,
    snapshot_digest: str,
) -> dict[str, Any]:
    """Build a conservative L1 composition runtime from one exact input read."""

    root = Path(scratchpad)
    pipeline_n = str(pipeline or "").strip().lower()
    mode_n = str(mode or "").strip().lower()
    language_n = str(language or "").strip().upper()
    run_id_n = _bounded_text(run_id, "run_id", maximum=256)
    snapshot_n = _snapshot(snapshot_digest)
    if pipeline_n != "l1":
        return _not_triggered_runtime(
            pipeline=pipeline_n,
            mode=mode_n,
            language=language_n,
            run_id=run_id_n,
            snapshot_digest=snapshot_n,
            reason="NON_L1_PIPELINE",
        )
    if mode_n not in {"core", "thorough"}:
        return _not_triggered_runtime(
            pipeline=pipeline_n,
            mode=mode_n,
            language=language_n,
            run_id=run_id_n,
            snapshot_digest=snapshot_n,
            reason="LIGHT_MODE_EXCLUDED" if mode_n == "light" else "UNSUPPORTED_MODE",
        )
    if language_n not in {"GO", "RUST", "MIXED", "OTHER"}:
        language_n = "OTHER"

    source_names = _discover_source_names(root)
    raw_sources, typed_raw, descriptors, debts = _read_exact_inputs(root, source_names)
    if INVENTORY_NAME not in source_names:
        debts.append(
            _debt(
                "INVENTORY_ARTIFACT_ABSENT",
                INVENTORY_NAME,
                "the authoritative L1 inventory is absent; depth fallbacks remain visible",
            )
        )
    if not source_names:
        debts.append(
            _debt(
                "AUTHORITATIVE_SOURCE_SET_EMPTY",
                "l1-findings",
                "neither findings_inventory.md nor bounded depth findings exist",
            )
        )

    source_rows: list[dict[str, Any]] = []
    total_occurrences = 0
    remaining = max(0, int(MAX_SOURCE_FINDINGS))
    for name in source_names:
        raw = raw_sources.get(name)
        if raw is None:
            continue
        parsed, parse_debts, _ = _parse_source_blocks(
            name, raw, artifact_sha256=_sha_bytes(raw)
        )
        debts.extend(parse_debts)
        total_occurrences += len(parsed)
        if len(parsed) > remaining:
            omitted = len(parsed) - remaining
            debts.append(
                _debt(
                    "SOURCE_FINDING_BUDGET_EXHAUSTED",
                    name,
                    f"{omitted} parsed occurrence(s) omitted beyond the {MAX_SOURCE_FINDINGS} global bound; provider is not complete",
                )
            )
            parsed = parsed[:remaining]
        source_rows.extend(parsed)
        remaining = max(0, remaining - len(parsed))
    if total_occurrences == 0:
        debts.append(
            _debt(
                "EMPTY_FINDING_DENOMINATOR",
                "l1-findings",
                "no parseable finding headings were present in the bounded authoritative sources",
            )
        )

    candidate_counts = Counter(row["candidate_id"] for row in source_rows)
    canonical_duplicate_binding: dict[str, tuple[str, str]] = {}
    for candidate, count in sorted(candidate_counts.items()):
        if count > 1:
            inventory_rows = [
                row for row in source_rows
                if row["candidate_id"] == candidate
                and row["source_artifact"] == INVENTORY_NAME
            ]
            if len(inventory_rows) == 1:
                canonical_duplicate_binding[candidate] = (
                    str(inventory_rows[0]["source_artifact"]),
                    str(inventory_rows[0]["source_block_sha256"]),
                )
            debts.append(
                _debt(
                    "DUPLICATE_SOURCE_CANDIDATE_ID",
                    candidate,
                    (
                        f"{count} exact source occurrences share this identity; "
                        "the unique inventory occurrence is the canonical graph "
                        "fact and every supplemental occurrence remains visible"
                        if candidate in canonical_duplicate_binding
                        else f"{count} exact source occurrences share this identity; none can be selected by order"
                    ),
                )
            )

    (
        typed_rows,
        producer_identity,
        producer_invocation_id,
        typed_artifact_sha,
        typed_debts,
        typed_valid,
    ) = _typed_records(typed_raw, run_id=run_id_n, snapshot_digest=snapshot_n)
    debts.extend(typed_debts)
    typed_by_binding: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in typed_rows:
        typed_by_binding[(row["source_artifact"], row["source_block_sha256"])].append(row)
    for binding, rows in sorted(typed_by_binding.items()):
        if len(rows) > 1:
            debts.append(
                _debt(
                    "DUPLICATE_TYPED_SOURCE_BINDING",
                    f"{binding[0]}:{binding[1]}",
                    f"{len(rows)} typed rows bind the same source occurrence; none can be selected by order",
                )
            )

    known_bindings = {
        (row["source_artifact"], row["source_block_sha256"]): row
        for row in source_rows
    }
    for binding, rows in sorted(typed_by_binding.items()):
        if binding not in known_bindings:
            debts.append(
                _debt(
                    "TYPED_RECORD_SOURCE_UNKNOWN",
                    f"{binding[0]}:{binding[1]}",
                    f"{len(rows)} typed row(s) do not bind an exact selected source block",
                )
            )

    fact_rows: list[dict[str, Any]] = []
    for source in source_rows:
        issues = list(source.get("issues") or [])
        candidate = source["candidate_id"]
        binding = (source["source_artifact"], source["source_block_sha256"])
        if (
            candidate_counts[candidate] > 1
            and canonical_duplicate_binding.get(candidate) != binding
        ):
            issues.append(
                "DUPLICATE_SOURCE_CANDIDATE_SHADOWED_BY_INVENTORY"
                if candidate in canonical_duplicate_binding
                else "DUPLICATE_SOURCE_CANDIDATE_ID"
            )
        candidates = typed_by_binding.get(binding, []) if typed_valid else []
        if len(candidates) != 1:
            issues.append(
                "DUPLICATE_TYPED_SOURCE_BINDING" if len(candidates) > 1 else "TYPED_FACT_UNAVAILABLE"
            )
        record = candidates[0] if len(candidates) == 1 else None
        composition_fact: dict[str, Any] | None = None
        typed_record_digest = ""
        if record is not None:
            typed_record_digest = str(record["typed_record_digest"])
            if record["candidate_id"] != candidate:
                issues.append("TYPED_RECORD_CANDIDATE_MISMATCH")
                debts.append(
                    _debt(
                        "TYPED_RECORD_CANDIDATE_MISMATCH",
                        candidate,
                        "typed candidate_id does not equal the exact heading identity",
                    )
                )
            if not issues:
                try:
                    composition_fact = normalize_l1_composition_fact(
                        {
                            "candidate_id": candidate,
                            "language": record["language"],
                            "layer": record["layer"],
                            "subsystem": record["subsystem"],
                            "root_cause_id": record["root_cause_id"],
                            "candidate_state": record["candidate_state"],
                            "requires": record["requires"],
                            "produces": record["produces"],
                            "touches": record["touches"],
                            "source_artifact": source["source_artifact"],
                            "source_sha256": source["source_artifact_sha256"],
                            "producer_identity": producer_identity,
                            "producer_invocation_id": producer_invocation_id,
                        }
                    )
                except (L1CompositionError, TypeError, ValueError) as exc:
                    issues.append("TYPED_RECORD_SEMANTICS_INVALID")
                    debts.append(
                        _debt(
                            "TYPED_RECORD_SEMANTICS_INVALID",
                            candidate,
                            f"strict typed semantic validation failed: {type(exc).__name__}: {exc}",
                        )
                    )
        if composition_fact is None and not any(
            debt["subject"] == candidate and debt["code"].startswith("TYPED_")
            for debt in debts
        ):
            debts.append(
                _debt(
                    "TYPED_FACT_UNMEASURABLE",
                    candidate,
                    "no unique valid exact-block-bound typed atom row exists; prose was not inferred",
                )
            )
        fact_rows.append(
            _finalize_fact_row(
                source,
                composition_fact=composition_fact,
                typed_record_digest=typed_record_digest,
                typed_artifact_sha256=typed_artifact_sha,
                issues=issues,
            )
        )

    fact_rows.sort(
        key=lambda row: (
            0 if row["source_artifact"] == INVENTORY_NAME else 1,
            row["source_artifact"],
            row["source_ordinal"],
            row["candidate_id"],
        )
    )
    measurable = [row for row in fact_rows if row["composition_fact"] is not None]
    graph = enumerate_l1_composition_graph(
        [row["composition_fact"] for row in measurable],
        mode=mode_n,
        max_pair_fanout=MAX_GRAPH_PAIR_FANOUT,
        max_edges=MAX_GRAPH_EDGES,
        max_family_members=MAX_GRAPH_FAMILY_MEMBERS,
        max_family_obligations=MAX_GRAPH_FAMILIES,
    )
    if graph["coverage_debt"]:
        debts.append(
            _debt(
                "GRAPH_COVERAGE_BUDGET_EXHAUSTED",
                graph["graph_digest"],
                f"{len(graph['coverage_debt'])} graph obligation(s) remain as bounded coverage debt",
            )
        )

    fact_rows_by_id = {row["candidate_id"]: row for row in measurable}
    obligations = sorted(
        [*graph["edges"], *graph["family_obligations"]],
        key=lambda row: row["obligation_id"],
    )
    work_packets: list[dict[str, Any]] = []
    max_packets = max(0, int(MAX_WORK_PACKETS))
    for obligation in obligations[:max_packets]:
        work_packets.append(
            _work_packet(
                obligation,
                graph=graph,
                fact_rows_by_id=fact_rows_by_id,
                run_id=run_id_n,
                snapshot_digest=snapshot_n,
            )
        )
    if len(obligations) > max_packets:
        omitted_ids = [row["obligation_id"] for row in obligations[max_packets:]]
        debts.append(
            _debt(
                "WORK_PACKET_BUDGET_EXHAUSTED",
                graph["graph_digest"],
                f"{len(omitted_ids)} obligation(s) omitted; ids_digest={_digest(omitted_ids)}",
            )
        )

    unique_debts = sorted(
        {canonical_json_bytes(row): row for row in debts}.values(),
        key=lambda row: (row["code"], row["subject"], row["detail"]),
    )
    if unique_debts:
        status = "DEGRADED"
    elif graph["status"] == "NOT_TRIGGERED":
        status = "NOT_TRIGGERED"
    else:
        status = "READY"
    payload = {
        "schema_version": RUNTIME_SCHEMA,
        "run_id": run_id_n,
        "snapshot_digest": snapshot_n,
        "pipeline": pipeline_n,
        "mode": mode_n,
        "language": language_n,
        "status": status,
        "activation": {"triggered": True, "reason": "L1_CORE_OR_THOROUGH"},
        "input_artifacts": descriptors,
        "denominator_count": total_occurrences,
        "represented_denominator_count": len(fact_rows),
        "measurable_count": len(measurable),
        "unmeasurable_count": len(fact_rows) - len(measurable),
        "facts": fact_rows,
        "graph": graph,
        "work_packets": work_packets,
        "work_packets_digest": _digest(
            [row["packet_digest"] for row in work_packets]
        ),
        "debts": unique_debts,
        "capabilities": dict(PROPOSAL_ONLY_CAPABILITIES),
        "runtime_digest": "",
    }
    unsigned = dict(payload)
    unsigned["runtime_digest"] = ""
    payload["runtime_digest"] = _digest(unsigned)
    if len(canonical_json_bytes(payload)) > MAX_OUTPUT_BYTES:
        # Do not emit a partially trusted graph when the bounded artifact cannot
        # carry its exact denominator.  The descriptors/digest still make the
        # failure resumable and visible.
        compact = {
            "schema_version": RUNTIME_SCHEMA,
            "run_id": run_id_n,
            "snapshot_digest": snapshot_n,
            "pipeline": pipeline_n,
            "mode": mode_n,
            "language": language_n,
            "status": "DEGRADED",
            "activation": {"triggered": True, "reason": "L1_CORE_OR_THOROUGH"},
            "input_artifacts": descriptors,
            "denominator_count": total_occurrences,
            "represented_denominator_count": 0,
            "measurable_count": 0,
            "unmeasurable_count": 0,
            "facts": [],
            "graph": enumerate_l1_composition_graph([], mode=mode_n),
            "work_packets": [],
            "work_packets_digest": _digest([]),
            "debts": [
                _debt(
                    "RUNTIME_OUTPUT_BUDGET_EXHAUSTED",
                    RUNTIME_NAME,
                    f"canonical runtime exceeded {MAX_OUTPUT_BYTES} bytes; no partial authority emitted",
                )
            ],
            "capabilities": dict(PROPOSAL_ONLY_CAPABILITIES),
            "runtime_digest": "",
        }
        compact_unsigned = dict(compact)
        compact_unsigned["runtime_digest"] = ""
        compact["runtime_digest"] = _digest(compact_unsigned)
        return compact
    return payload


def _validate_runtime_self(value: Mapping[str, Any]) -> list[str]:
    issues: list[str] = []
    expected_root = {
        "schema_version",
        "run_id",
        "snapshot_digest",
        "pipeline",
        "mode",
        "language",
        "status",
        "activation",
        "input_artifacts",
        "denominator_count",
        "represented_denominator_count",
        "measurable_count",
        "unmeasurable_count",
        "facts",
        "graph",
        "work_packets",
        "work_packets_digest",
        "debts",
        "capabilities",
        "runtime_digest",
    }
    if (
        not isinstance(value, Mapping)
        or set(value) != expected_root
        or value.get("schema_version") != RUNTIME_SCHEMA
    ):
        return ["runtime schema mismatch"]
    supplied = str(value.get("runtime_digest") or "")
    unsigned = dict(value)
    unsigned["runtime_digest"] = ""
    if not _HEX64_RE.fullmatch(supplied) or supplied != _digest(unsigned):
        issues.append("runtime digest mismatch")
    if value.get("capabilities") != PROPOSAL_ONLY_CAPABILITIES:
        issues.append("runtime capabilities mismatch")
    if value.get("status") not in {"READY", "DEGRADED", "NOT_TRIGGERED"}:
        issues.append("runtime status is invalid")
    if not isinstance(value.get("run_id"), str) or not str(value.get("run_id") or "").strip():
        issues.append("runtime run_id is invalid")
    if not _HEX64_RE.fullmatch(str(value.get("snapshot_digest") or "")):
        issues.append("runtime snapshot digest is invalid")
    activation = value.get("activation")
    if not isinstance(activation, Mapping) or set(activation) != {"triggered", "reason"}:
        issues.append("runtime activation schema mismatch")
    descriptors = value.get("input_artifacts")
    if not isinstance(descriptors, list):
        issues.append("input_artifacts must be an array")
    else:
        descriptor_names: list[str] = []
        for ordinal, descriptor in enumerate(descriptors, 1):
            if not isinstance(descriptor, Mapping) or set(descriptor) != {
                "artifact", "role", "sha256", "size_bytes"
            }:
                issues.append(f"input descriptor {ordinal} schema mismatch")
                continue
            name = str(descriptor.get("artifact") or "")
            if name != TYPED_RECORDS_NAME and not _is_finding_source_name(name):
                issues.append(f"input descriptor {ordinal} artifact is invalid")
            if not _HEX64_RE.fullmatch(str(descriptor.get("sha256") or "")):
                issues.append(f"input descriptor {ordinal} digest is invalid")
            if descriptor.get("role") not in {
                "AUTHORITATIVE_L1_FINDINGS", "TYPED_FACT_PROPOSALS"
            }:
                issues.append(f"input descriptor {ordinal} role is invalid")
            if isinstance(descriptor.get("size_bytes"), bool) or not isinstance(
                descriptor.get("size_bytes"), int
            ) or int(descriptor.get("size_bytes") or 0) < 0:
                issues.append(f"input descriptor {ordinal} size is invalid")
            descriptor_names.append(name)
        if descriptor_names != sorted(descriptor_names) or len(descriptor_names) != len(set(descriptor_names)):
            issues.append("input descriptors are non-canonical or duplicated")

    debts = value.get("debts")
    if not isinstance(debts, list):
        issues.append("debts must be an array")
    else:
        for ordinal, debt in enumerate(debts, 1):
            if not isinstance(debt, Mapping) or set(debt) != {"code", "subject", "detail"}:
                issues.append(f"debt {ordinal} schema mismatch")
        if all(isinstance(row, Mapping) for row in debts):
            expected_debts = sorted(
                {canonical_json_bytes(row): dict(row) for row in debts}.values(),
                key=lambda row: (
                    str(row.get("code") or ""),
                    str(row.get("subject") or ""),
                    str(row.get("detail") or ""),
                ),
            )
            if debts != expected_debts:
                issues.append("debts are non-canonical or duplicated")

    facts = value.get("facts")
    valid_fact_rows: list[Mapping[str, Any]] = []
    measurable_rows: list[Mapping[str, Any]] = []
    fact_expected = {
        "candidate_id",
        "source_artifact",
        "source_artifact_sha256",
        "source_block_sha256",
        "source_ordinal",
        "source_block_start_line",
        "source_block_end_line",
        "opaque_identity",
        "extraction_status",
        "typed_record_digest",
        "typed_artifact_sha256",
        "composition_fact",
        "issues",
        "row_digest",
    }
    if not isinstance(facts, list):
        issues.append("facts must be an array")
        facts = []
    for ordinal, row in enumerate(facts, 1):
        if not isinstance(row, Mapping) or set(row) != fact_expected:
            issues.append(f"fact row {ordinal} schema mismatch")
            continue
        valid_fact_rows.append(row)
        unsigned_row = dict(row)
        supplied_row = str(unsigned_row.get("row_digest") or "")
        unsigned_row["row_digest"] = ""
        if not _HEX64_RE.fullmatch(supplied_row) or supplied_row != _digest(unsigned_row):
            issues.append(f"fact row {ordinal} digest mismatch")
        if row.get("opaque_identity") != _opaque_identity(row):
            issues.append(f"fact row {ordinal} opaque identity mismatch")
        if not _HEX64_RE.fullmatch(str(row.get("source_artifact_sha256") or "")):
            issues.append(f"fact row {ordinal} source artifact digest is invalid")
        if not _HEX64_RE.fullmatch(str(row.get("source_block_sha256") or "")):
            issues.append(f"fact row {ordinal} source block digest is invalid")
        composition_fact = row.get("composition_fact")
        status = str(row.get("extraction_status") or "")
        row_issues = row.get("issues")
        if (
            not isinstance(row_issues, list)
            or any(not isinstance(issue, str) for issue in row_issues)
            or row_issues != sorted(set(row_issues))
        ):
            issues.append(f"fact row {ordinal} issues are non-canonical")
        if composition_fact is None:
            if status != "UNMEASURABLE":
                issues.append(f"fact row {ordinal} status/fact mismatch")
        else:
            if status != "MEASURABLE" or row_issues:
                issues.append(f"fact row {ordinal} status/fact mismatch")
            try:
                canonical_fact = validate_l1_composition_fact(composition_fact)
            except (L1CompositionError, TypeError, ValueError) as exc:
                issues.append(
                    f"fact row {ordinal} composition fact invalid: {type(exc).__name__}: {exc}"
                )
            else:
                if canonical_fact.get("candidate_id") != row.get("candidate_id"):
                    issues.append(f"fact row {ordinal} candidate binding mismatch")
                if canonical_fact.get("source_artifact") != row.get("source_artifact"):
                    issues.append(f"fact row {ordinal} source artifact binding mismatch")
                if canonical_fact.get("source_sha256") != row.get("source_artifact_sha256"):
                    issues.append(f"fact row {ordinal} source digest binding mismatch")
                measurable_rows.append(row)
    raw_counts = [
        value.get("denominator_count"),
        value.get("represented_denominator_count"),
        value.get("measurable_count"),
        value.get("unmeasurable_count"),
    ]
    try:
        if any(isinstance(item, bool) for item in raw_counts):
            raise ValueError("boolean count")
        denominator = int(value.get("denominator_count"))
        represented = int(value.get("represented_denominator_count"))
        measurable_count = int(value.get("measurable_count"))
        unmeasurable_count = int(value.get("unmeasurable_count"))
    except (TypeError, ValueError):
        issues.append("runtime denominator counts are invalid")
        denominator = represented = measurable_count = unmeasurable_count = -1
    else:
        if min(denominator, represented, measurable_count, unmeasurable_count) < 0:
            issues.append("runtime denominator counts must be non-negative")
        if represented != len(valid_fact_rows) or denominator < represented:
            issues.append("represented denominator count mismatch")
        if measurable_count != len(measurable_rows):
            issues.append("measurable count mismatch")
        if unmeasurable_count != len(valid_fact_rows) - len(measurable_rows):
            issues.append("unmeasurable count mismatch")
    expected_fact_order = sorted(
        valid_fact_rows,
        key=lambda row: (
            0 if row.get("source_artifact") == INVENTORY_NAME else 1,
            str(row.get("source_artifact") or ""),
            int(row.get("source_ordinal") or 0),
            str(row.get("candidate_id") or ""),
        ),
    )
    if valid_fact_rows != expected_fact_order:
        issues.append("fact rows are non-canonical")

    graph = value.get("graph")
    if graph is not None:
        try:
            validate_l1_composition_graph(graph)
        except (L1CompositionError, TypeError, ValueError) as exc:
            issues.append(f"graph validation failed: {type(exc).__name__}: {exc}")
        else:
            try:
                expected_graph = enumerate_l1_composition_graph(
                    [row["composition_fact"] for row in measurable_rows],
                    mode=str(value.get("mode") or ""),
                    max_pair_fanout=MAX_GRAPH_PAIR_FANOUT,
                    max_edges=MAX_GRAPH_EDGES,
                    max_family_members=MAX_GRAPH_FAMILY_MEMBERS,
                    max_family_obligations=MAX_GRAPH_FAMILIES,
                )
            except (L1CompositionError, TypeError, ValueError) as exc:
                issues.append(f"graph re-enumeration failed: {type(exc).__name__}: {exc}")
            else:
                if graph != expected_graph:
                    issues.append("graph does not match the exact typed fact rows")
    elif bool((activation or {}).get("triggered")):
        issues.append("active runtime must contain a graph")

    packets = value.get("work_packets")
    if not isinstance(packets, list):
        issues.append("work_packets must be an array")
    else:
        packet_digests: list[str] = []
        for ordinal, packet in enumerate(packets, 1):
            if not isinstance(packet, Mapping):
                issues.append(f"work packet {ordinal} is not an object")
                continue
            unsigned_packet = dict(packet)
            supplied_packet = str(unsigned_packet.get("packet_digest") or "")
            unsigned_packet["packet_digest"] = ""
            if supplied_packet != _digest(unsigned_packet):
                issues.append(f"work packet {ordinal} digest mismatch")
            if packet.get("capabilities") != PROPOSAL_ONLY_CAPABILITIES:
                issues.append(f"work packet {ordinal} capabilities mismatch")
            packet_digests.append(supplied_packet)
        if value.get("work_packets_digest") != _digest(packet_digests):
            issues.append("work packet denominator digest mismatch")
        if isinstance(graph, Mapping) and not any(
            item.startswith("graph ") for item in issues
        ):
            measurable_by_id = {
                str(row["candidate_id"]): row for row in measurable_rows
            }
            obligations = sorted(
                [*graph.get("edges", []), *graph.get("family_obligations", [])],
                key=lambda row: row["obligation_id"],
            )
            try:
                expected_packets = [
                    _work_packet(
                        obligation,
                        graph=graph,
                        fact_rows_by_id=measurable_by_id,
                        run_id=str(value.get("run_id") or ""),
                        snapshot_digest=str(value.get("snapshot_digest") or ""),
                    )
                    for obligation in obligations[: max(0, int(MAX_WORK_PACKETS))]
                ]
            except (KeyError, TypeError, ValueError) as exc:
                issues.append(f"work packet re-derivation failed: {type(exc).__name__}: {exc}")
            else:
                if packets != expected_packets:
                    issues.append("work packets do not match the exact graph obligations")
    if value.get("status") == "NOT_TRIGGERED" and bool((activation or {}).get("triggered")):
        if debts or graph is None or graph.get("status") != "NOT_TRIGGERED":
            issues.append("active NOT_TRIGGERED status is inconsistent")
    if value.get("status") == "READY" and (
        debts or graph is None or graph.get("status") == "NOT_TRIGGERED"
    ):
        issues.append("READY status is inconsistent")
    if value.get("status") == "DEGRADED" and not debts:
        issues.append("DEGRADED status requires visible debt")
    triggered = bool((activation or {}).get("triggered"))
    if triggered and (
        value.get("pipeline") != "l1"
        or value.get("mode") not in {"core", "thorough"}
    ):
        issues.append("active runtime pipeline/mode is inconsistent")
    if not triggered and (
        value.get("status") != "NOT_TRIGGERED"
        or descriptors
        or facts
        or graph is not None
        or packets
        or debts
        or any(count != 0 for count in raw_counts if isinstance(count, int))
    ):
        issues.append("inactive runtime must be an empty NOT_TRIGGERED authority")
    return issues


def validate_l1_composition_runtime(
    value: Mapping[str, Any],
    scratchpad: Path | str,
    *,
    pipeline: str,
    mode: str,
    language: str,
    run_id: str,
    snapshot_digest: str,
) -> list[str]:
    issues = _validate_runtime_self(value)
    try:
        expected = derive_l1_composition_runtime(
            scratchpad,
            pipeline=pipeline,
            mode=mode,
            language=language,
            run_id=run_id,
            snapshot_digest=snapshot_digest,
        )
    except (L1CompositionRuntimeError, OSError, ValueError, TypeError) as exc:
        issues.append(f"runtime re-derivation failed: {type(exc).__name__}: {exc}")
        return sorted(set(issues))
    if dict(value) != expected:
        issues.append("runtime is stale or mismatched against current exact inputs")
    return sorted(set(issues))


def write_l1_composition_runtime(
    scratchpad: Path | str,
    *,
    pipeline: str,
    mode: str,
    language: str,
    run_id: str,
    snapshot_digest: str,
) -> dict[str, Any]:
    root = Path(scratchpad)
    payload = derive_l1_composition_runtime(
        root,
        pipeline=pipeline,
        mode=mode,
        language=language,
        run_id=run_id,
        snapshot_digest=snapshot_digest,
    )
    _atomic_write(root / RUNTIME_NAME, canonical_json_bytes(payload))
    return payload


def _empty_disposition_receipt(graph_digest: str) -> dict[str, Any]:
    payload = {
        "schema_version": "plamen.l1_composition_dispositions.v1",
        "graph_digest": graph_digest,
        "dispositions": [],
        "missing_obligation_ids": [],
        "duplicate_obligation_ids": [],
        "unexpected_obligation_ids": [],
        "exact_coverage": True,
        "payload_digest": "",
    }
    unsigned = dict(payload)
    unsigned["payload_digest"] = ""
    payload["payload_digest"] = _digest(unsigned)
    return payload


def _compound_handoff(
    packet: Mapping[str, Any],
    *,
    runtime: Mapping[str, Any],
    disposition_receipt_digest: str,
    rationale: str,
) -> dict[str, Any]:
    core = {
        "obligation_id": str(packet["obligation_id"]),
        "candidate_ids": list(packet["candidate_ids"]),
        "constituent_fact_digests": list(packet["constituent_fact_digests"]),
        "constituent_source_bindings": list(packet["constituent_source_bindings"]),
        "relation": str(packet["relation"]),
        "atom": dict(packet["atom"]),
    }
    result = {
        "schema_version": COMPOUND_HANDOFF_SCHEMA,
        "proposal_id": "L1CH-" + _digest(core)[:20].upper(),
        "run_id": str(runtime["run_id"]),
        "snapshot_digest": str(runtime["snapshot_digest"]),
        "runtime_digest": str(runtime["runtime_digest"]),
        "graph_digest": str(runtime["graph"]["graph_digest"]),
        "disposition_receipt_digest": disposition_receipt_digest,
        **core,
        "model_rationale": rationale,
        "authority": "PROPOSAL_ONLY",
        "required_adapter": "L1_COMPOSITION_QUEUE_TRANSACTION",
        "capabilities": dict(PROPOSAL_ONLY_CAPABILITIES),
        "handoff_digest": "",
    }
    unsigned = dict(result)
    unsigned["handoff_digest"] = ""
    result["handoff_digest"] = _digest(unsigned)
    return result


def reconcile_l1_composition_runtime(
    runtime: Mapping[str, Any], model_dispositions: Mapping[str, Any]
) -> dict[str, Any]:
    """Reconcile exact packet coverage; never convert a proposal into a finding."""

    debts: list[dict[str, str]] = []
    runtime_issues = _validate_runtime_self(runtime)
    graph = runtime.get("graph") if isinstance(runtime, Mapping) else None
    graph_digest = str(graph.get("graph_digest") or "") if isinstance(graph, Mapping) else ""
    context_valid = not runtime_issues
    if runtime_issues:
        debts.append(
            _debt(
                "RUNTIME_AUTHORITY_INVALID",
                RUNTIME_NAME,
                "; ".join(runtime_issues),
            )
        )
    proposal_expected = {
        "schema_version",
        "run_id",
        "snapshot_digest",
        "producer_identity",
        "producer_invocation_id",
        "runtime_digest",
        "graph_digest",
        "work_packets_digest",
        "dispositions",
    }
    if not isinstance(model_dispositions, Mapping) or set(model_dispositions) != proposal_expected:
        context_valid = False
        debts.append(
            _debt(
                "MODEL_DISPOSITION_ARTIFACT_MALFORMED",
                "model-dispositions",
                "model disposition root schema mismatch",
            )
        )
    elif model_dispositions.get("schema_version") != MODEL_DISPOSITIONS_SCHEMA:
        context_valid = False
        debts.append(
            _debt(
                "MODEL_DISPOSITION_ARTIFACT_MALFORMED",
                "model-dispositions",
                "model disposition schema version mismatch",
            )
        )
    else:
        try:
            disposition_producer_identity = _bounded_text(
                model_dispositions.get("producer_identity"),
                "producer_identity",
                maximum=256,
            )
            disposition_producer_invocation_id = _bounded_text(
                model_dispositions.get("producer_invocation_id"),
                "producer_invocation_id",
                maximum=256,
            )
        except L1CompositionRuntimeError as exc:
            context_valid = False
            disposition_producer_identity = ""
            disposition_producer_invocation_id = ""
            debts.append(
                _debt(
                    "MODEL_DISPOSITION_ARTIFACT_MALFORMED",
                    "model-dispositions",
                    str(exc),
                )
            )
    if context_valid and (
        any(
            model_dispositions.get(field) != runtime.get(runtime_field)
            for field, runtime_field in (
                ("run_id", "run_id"),
                ("snapshot_digest", "snapshot_digest"),
                ("runtime_digest", "runtime_digest"),
                ("work_packets_digest", "work_packets_digest"),
            )
        )
        or model_dispositions.get("graph_digest") != graph_digest
    ):
        context_valid = False
        debts.append(
            _debt(
                "MODEL_DISPOSITION_CONTEXT_MISMATCH",
                "model-dispositions",
                "model dispositions do not bind the current run/snapshot/runtime/graph/packet denominator",
            )
        )

    if context_valid:
        raw_dispositions = model_dispositions.get("dispositions")
        if (
            not isinstance(raw_dispositions, list)
            or len(raw_dispositions) > max(0, int(MAX_WORK_PACKETS))
        ):
            context_valid = False
            debts.append(
                _debt(
                    "MODEL_DISPOSITION_ARTIFACT_MALFORMED",
                    "model-dispositions",
                    f"dispositions must be an array bounded to {max(0, int(MAX_WORK_PACKETS))} rows",
                )
            )

    fact_producer_identities = {
        str(fact.get("producer_identity") or "")
        for row in runtime.get("facts", [])
        if isinstance(row, Mapping)
        for fact in [row.get("composition_fact")]
        if isinstance(fact, Mapping)
    }
    fact_producer_invocations = {
        str(fact.get("producer_invocation_id") or "")
        for row in runtime.get("facts", [])
        if isinstance(row, Mapping)
        for fact in [row.get("composition_fact")]
        if isinstance(fact, Mapping)
    }
    if context_valid and (
        disposition_producer_identity in fact_producer_identities
        or disposition_producer_invocation_id in fact_producer_invocations
    ):
        context_valid = False
        debts.append(
            _debt(
                "MODEL_DISPOSITION_SELF_CERTIFICATION",
                disposition_producer_identity,
                "the typed-fact producer cannot disposition its own composition obligations",
            )
        )

    if context_valid and isinstance(graph, Mapping):
        try:
            disposition_receipt = reconcile_l1_composition_dispositions(
                graph, model_dispositions.get("dispositions", [])
            )
        except (L1CompositionError, TypeError, ValueError) as exc:
            context_valid = False
            debts.append(
                _debt(
                    "MODEL_DISPOSITION_ARTIFACT_MALFORMED",
                    "model-dispositions",
                    f"disposition reconciliation failed: {type(exc).__name__}: {exc}",
                )
            )
            disposition_receipt = _empty_disposition_receipt(graph_digest)
            disposition_receipt["exact_coverage"] = False
    else:
        disposition_receipt = _empty_disposition_receipt(graph_digest)
        if graph is not None:
            disposition_receipt["exact_coverage"] = False

    packet_ids = {
        str(row.get("obligation_id") or "")
        for row in runtime.get("work_packets", [])
        if isinstance(row, Mapping)
    }
    graph_ids = {
        str(row.get("obligation_id") or "")
        for row in [
            *((graph or {}).get("edges") or []),
            *((graph or {}).get("family_obligations") or []),
        ]
        if isinstance(row, Mapping)
    }
    graph_debt = bool((graph or {}).get("coverage_debt"))
    runtime_complete = bool(
        runtime.get("status") in {"READY", "NOT_TRIGGERED"}
        and int(runtime.get("represented_denominator_count") or 0)
        == int(runtime.get("denominator_count") or 0)
        and int(runtime.get("unmeasurable_count") or 0) == 0
    )
    # Keep global extraction completeness distinct from the positive-work
    # denominator.  An unrelated opaque finding is visible coverage debt, but
    # it is not negative authority over an exact, fully bound graph edge.  The
    # latter is only a proposal and still passes through P0-AF plus ordinary
    # verification, so suppressing it would turn uncertainty into recall loss.
    deliverable_obligation_coverage_exact = bool(
        context_valid
        and disposition_receipt.get("exact_coverage")
        and packet_ids == graph_ids
        and not graph_debt
    )
    exact_coverage = bool(
        deliverable_obligation_coverage_exact and runtime_complete
    )
    if context_valid and not runtime_complete:
        debts.append(
            _debt(
                "RUNTIME_COVERAGE_DEGRADED",
                str(runtime.get("runtime_digest") or "runtime"),
                "the exact finding denominator is incomplete or contains UNMEASURABLE facts",
            )
        )
    if context_valid and not exact_coverage:
        debts.append(
            _debt(
                "L1_COMPOSITION_COVERAGE_INCOMPLETE",
                graph_digest or "no-graph",
                "model, packet, or graph obligation coverage is not exact",
            )
        )

    packet_by_id = {
        str(row["obligation_id"]): row
        for row in runtime.get("work_packets", [])
        if isinstance(row, Mapping) and row.get("obligation_id")
    }
    dispositions_by_id = {
        str(row["obligation_id"]): row
        for row in disposition_receipt.get("dispositions", [])
        if isinstance(row, Mapping)
    }
    compound_handoffs: list[dict[str, Any]] = []
    if deliverable_obligation_coverage_exact:
        for oid in sorted(packet_by_id):
            disposition = dispositions_by_id.get(oid)
            if not disposition or disposition.get("disposition") != "COMPOUND_CANDIDATE":
                continue
            compound_handoffs.append(
                _compound_handoff(
                    packet_by_id[oid],
                    runtime=runtime,
                    disposition_receipt_digest=str(disposition_receipt["payload_digest"]),
                    rationale=str(disposition["rationale"]),
                )
            )
    if compound_handoffs:
        debts.append(
            _debt(
                "L1_COMPOSITION_QUEUE_TRANSACTION_REQUIRED",
                "l1-compound-proposals",
                f"{len(compound_handoffs)} proposal-only handoff(s) require independent compound planning and queue delivery",
            )
        )

    unique_debts = sorted(
        {canonical_json_bytes(row): row for row in debts}.values(),
        key=lambda row: (row["code"], row["subject"], row["detail"]),
    )
    if not exact_coverage:
        status = "DEGRADED"
    elif compound_handoffs:
        status = "P0_AF_ADAPTER_REQUIRED"
    else:
        status = "COMPLETE_NO_COMPOUND_CANDIDATES"
    receipt = {
        "schema_version": RECEIPT_SCHEMA,
        "run_id": str(runtime.get("run_id") or ""),
        "snapshot_digest": str(runtime.get("snapshot_digest") or ""),
        "runtime_digest": str(runtime.get("runtime_digest") or ""),
        "graph_digest": graph_digest,
        "work_packets_digest": str(runtime.get("work_packets_digest") or ""),
        "model_dispositions_digest": _digest(model_dispositions),
        "model_producer_identity": str(
            model_dispositions.get("producer_identity") or ""
        ),
        "model_producer_invocation_id": str(
            model_dispositions.get("producer_invocation_id") or ""
        ),
        "status": status,
        "exact_coverage": exact_coverage,
        "deliverable_obligation_coverage_exact": (
            deliverable_obligation_coverage_exact
        ),
        "disposition_receipt": disposition_receipt,
        "compound_handoffs": compound_handoffs,
        "debts": unique_debts,
        "capabilities": dict(PROPOSAL_ONLY_CAPABILITIES),
        "receipt_digest": "",
    }
    unsigned = dict(receipt)
    unsigned["receipt_digest"] = ""
    receipt["receipt_digest"] = _digest(unsigned)
    return receipt


def validate_l1_composition_receipt(
    value: Mapping[str, Any],
    runtime: Mapping[str, Any],
    model_dispositions: Mapping[str, Any],
) -> list[str]:
    issues: list[str] = []
    if not isinstance(value, Mapping) or value.get("schema_version") != RECEIPT_SCHEMA:
        return ["receipt schema mismatch"]
    unsigned = dict(value)
    supplied = str(unsigned.get("receipt_digest") or "")
    unsigned["receipt_digest"] = ""
    if not _HEX64_RE.fullmatch(supplied) or supplied != _digest(unsigned):
        issues.append("receipt digest mismatch")
    if value.get("capabilities") != PROPOSAL_ONLY_CAPABILITIES:
        issues.append("receipt capabilities mismatch")
    expected = reconcile_l1_composition_runtime(runtime, model_dispositions)
    if dict(value) != expected:
        issues.append("receipt is stale, tampered, or context-mismatched")
    return sorted(set(issues))


def write_l1_composition_receipt(
    scratchpad: Path | str,
    runtime: Mapping[str, Any],
    model_dispositions: Mapping[str, Any],
) -> dict[str, Any]:
    root = Path(scratchpad)
    receipt = reconcile_l1_composition_runtime(runtime, model_dispositions)
    _atomic_write(root / RECEIPT_NAME, canonical_json_bytes(receipt))
    return receipt


def driver_integration_contract() -> dict[str, Any]:
    """Machine-readable contract for the live L1 verification-queue boundary."""

    return {
        "schema_version": "plamen.l1_composition_driver_contract.v1",
        "integrated": True,
        "pipeline": "l1",
        "modes": ["core", "thorough"],
        "inactive_behavior": "NO_READ_NOT_TRIGGERED",
        "authoritative_sources": [
            INVENTORY_NAME,
            "depth_*_findings.md",
            "depth_findings.md",
            "blind_spot_*_findings.md",
            "niche_*_findings.md",
            "scanner_*_findings.md",
            "validation_sweep_findings.md",
            "design_stress_findings.md",
            "perturbation_findings.md",
        ],
        "typed_producer_artifact": TYPED_RECORDS_NAME,
        "fact_worklist_artifact": FACT_WORKLIST_NAME,
        "runtime_artifact": RUNTIME_NAME,
        "receipt_artifact": RECEIPT_NAME,
        "must_run_after": "application_skeptic",
        "must_run_before": "verify_queue",
        "independent_fact_and_disposition_workers": True,
        "compound_delivery": "L1_COMPOSITION_QUEUE_TRANSACTION",
        "failure_policy": "HALTLESS_VISIBLE_UNMEASURABLE_DEBT",
        "capabilities": dict(PROPOSAL_ONLY_CAPABILITIES),
    }


__all__ = [
    "COMPOUND_HANDOFF_SCHEMA",
    "FACT_WORKLIST_NAME",
    "FACT_WORKLIST_SCHEMA",
    "INVENTORY_NAME",
    "L1CompositionRuntimeError",
    "MODEL_DISPOSITIONS_SCHEMA",
    "MODEL_DISPOSITIONS_NAME",
    "PROPOSAL_ONLY_CAPABILITIES",
    "RECEIPT_NAME",
    "RECEIPT_SCHEMA",
    "RUNTIME_NAME",
    "RUNTIME_SCHEMA",
    "TYPED_RECORDS_NAME",
    "TYPED_RECORDS_SCHEMA",
    "WORK_PACKET_SCHEMA",
    "canonical_json_bytes",
    "derive_l1_composition_fact_worklist",
    "derive_l1_composition_runtime",
    "driver_integration_contract",
    "l1_composition_source_artifacts",
    "reconcile_l1_composition_runtime",
    "validate_l1_composition_receipt",
    "validate_l1_composition_fact_records",
    "validate_l1_composition_fact_worklist",
    "validate_l1_composition_runtime",
    "write_l1_composition_receipt",
    "write_l1_composition_fact_worklist",
    "write_l1_composition_runtime",
]
