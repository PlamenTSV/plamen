"""Typed consumers for compiled verifier operator receipts.

The verifier is authoritative only for evidence that it applied a method.  A
new observation is therefore registered as a candidate in the independent
finding lifecycle, while a blocked operator becomes exact report-visible
verification-confidence debt.  Neither projection can certify a verdict,
severity, report disposition, or finding evidence tag.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import tempfile
from typing import Any, Mapping, Sequence

from finding_lifecycle_authority import (
    CANDIDATE_SCHEMA,
    build_finding_lifecycle,
    candidate_content_sha256,
    finding_verification_work_items,
    validate_finding_lifecycle,
)
from verification_method_compiler import (
    OPERATOR_RECEIPT_SCHEMA,
    stable_digest,
)


AUTHORITY_SCHEMA = "plamen.verification_operator_consumer_authority.v1"
LATE_SHARD_SCHEMA = "plamen.verification_operator_late_shard.v1"
ASSURANCE_DEBT_SCHEMA = "plamen.verification_operator_assurance_debt.v1"
DEFAULT_MAX_ROWS_PER_SHARD = 4

_HEX64 = frozenset("0123456789abcdef")
_AUTHORITY_FIELDS = frozenset({
    "schema_version", "run_id", "status", "source_receipt_count",
    "source_receipts", "candidate_count", "candidates",
    "finding_lifecycle", "late_verification_shards",
    "assurance_debt_count", "assurance_debts", "max_rows_per_shard",
    "authority_digest",
})
_SOURCE_FIELDS = frozenset({
    "path", "sha256", "receipt_digest", "work_item_id",
    "method_dispatch_id", "launch_digest",
})
_OBSERVATION_FIELDS = frozenset({
    "title", "mechanism", "location", "evidence", "candidate_state",
    "terminal_authority", "source_work_item_id",
})
_RECEIPT_FIELDS = frozenset({
    "schema_version", "work_item_id", "method_dispatch_id",
    "dispatch_receipt_digest", "launch_digest", "proposal_sha256",
    "verifier_sha256", "selected_module_hashes", "context_packet_digest",
    "context_status", "operators", "debts", "new_observations",
    "application_authority", "terminal_authority", "receipt_digest",
})
_DEBT_FIELDS = frozenset({
    "operator_id", "debt_code", "blocker_evidence", "report_visible",
    "terminal_authority",
})
_CANDIDATE_FIELDS = frozenset({
    "candidate_id", "candidate_digest", "candidate_state",
    "terminal_authority", "severity_proposal", "source_work_item_id",
    "source_observation_index", "source_operator_receipt",
    "source_operator_receipt_sha256", "source_operator_receipt_digest",
    "title", "mechanism", "location", "evidence",
})
_LATE_WORK_FIELDS = frozenset({
    "work_item_id", "source_candidate_digest", "source_work_item_id",
    "source_identity", "source_operator_receipt",
    "source_operator_receipt_sha256", "source_operator_receipt_digest",
    "title", "mechanism", "evidence", "bug_class", "location",
    "primary_artifact", "poc_class",
    "severity", "producer_identity", "required_discriminator_identity",
    "independent_discriminator_required", "terminal_authority",
    "finding_lifecycle_obligation_id",
})
_SHARD_FIELDS = frozenset({
    "schema_version", "shard_id", "row_count", "rows", "shard_digest",
})
_ASSURANCE_FIELDS = frozenset({
    "schema_version", "debt_id", "affected_work_item_id", "operator_id",
    "debt_code", "blocker_evidence", "context_status",
    "source_operator_receipt", "source_operator_receipt_sha256",
    "source_operator_receipt_digest", "report_visible",
    "terminal_authority", "verification_confidence_effect", "debt_digest",
})
_STATUSES = frozenset({
    "CLEAN_NO_OP", "LATE_VERIFICATION_REQUIRED", "ASSURANCE_DEBT_ONLY",
    "LATE_VERIFICATION_AND_ASSURANCE_DEBT",
})


class ConsumerAuthorityError(ValueError):
    """A verifier receipt cannot be consumed without semantic guessing."""


def _canonical_json(value: Any) -> str:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    except (TypeError, ValueError) as exc:
        raise ConsumerAuthorityError(f"record is not canonical JSON: {exc}") from exc


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _bytes_digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _exact(value: Any, fields: frozenset[str], label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ConsumerAuthorityError(f"{label} must be an object")
    if set(value) != set(fields):
        raise ConsumerAuthorityError(
            f"{label} schema mismatch; missing={sorted(fields - set(value))}; "
            f"extra={sorted(set(value) - fields)}"
        )
    return dict(value)


def _text(value: Any, field: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or value != value.strip():
        raise ConsumerAuthorityError(f"{field} must be canonical text")
    if not allow_empty and not value:
        raise ConsumerAuthorityError(f"{field} must be non-empty")
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ConsumerAuthorityError(f"{field} contains control characters")
    return value


def _sha256(value: Any, field: str) -> str:
    item = _text(value, field)
    if len(item) != 64 or any(char not in _HEX64 for char in item):
        raise ConsumerAuthorityError(f"{field} must be a lowercase SHA-256 digest")
    return item


def _relative_source_path(path: Path, scratchpad: Path) -> str:
    try:
        relative = path.resolve().relative_to(scratchpad.resolve())
    except (OSError, ValueError) as exc:
        raise ConsumerAuthorityError(
            f"source receipt is outside scratchpad: {path}"
        ) from exc
    rendered = PurePosixPath(*relative.parts).as_posix()
    if not rendered or rendered.startswith("../"):
        raise ConsumerAuthorityError("source receipt path is not canonical relative")
    return rendered


def _load_receipt(path: Path) -> tuple[dict[str, Any], bytes]:
    try:
        raw = Path(path).read_bytes()
        value = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ConsumerAuthorityError(f"source receipt is unreadable: {path}: {exc}") from exc
    receipt = _exact(value, _RECEIPT_FIELDS, "operator receipt")
    if receipt["schema_version"] != OPERATOR_RECEIPT_SCHEMA:
        raise ConsumerAuthorityError("source receipt schema is unsupported")
    if receipt["application_authority"] != "APPLICATION_EVIDENCE_ONLY":
        raise ConsumerAuthorityError("source receipt application authority is invalid")
    if receipt["terminal_authority"] is not False:
        raise ConsumerAuthorityError("source receipt cannot have terminal authority")
    claimed = _sha256(receipt["receipt_digest"], "receipt_digest")
    unsigned = {key: value for key, value in receipt.items() if key != "receipt_digest"}
    if stable_digest(unsigned) != claimed:
        raise ConsumerAuthorityError("source receipt digest mismatch")
    for field in (
        "dispatch_receipt_digest", "launch_digest", "proposal_sha256",
        "verifier_sha256", "context_packet_digest",
    ):
        _sha256(receipt[field], field)
    _text(receipt["work_item_id"], "work_item_id")
    _text(receipt["method_dispatch_id"], "method_dispatch_id")
    if receipt["context_status"] not in {
        "RESOLVED", "EXPANDED_RESOLVED", "CONTEXT_UNRESOLVED",
    }:
        raise ConsumerAuthorityError("source receipt context_status is invalid")
    if not isinstance(receipt["new_observations"], list):
        raise ConsumerAuthorityError("source receipt new_observations must be an array")
    if not isinstance(receipt["debts"], list):
        raise ConsumerAuthorityError("source receipt debts must be an array")
    return receipt, raw


def _candidate_identity(source: Mapping[str, Any], observation: Mapping[str, Any]) -> str:
    seed = {
        "source_work_item_id": source["work_item_id"],
        "source_receipt_digest": source["receipt_digest"],
        "observation": observation,
    }
    # Decimal IDs retain compatibility with legacy display-ID consumers while
    # the full candidate digest remains the relational identity.
    number = int(_digest(seed)[:15], 16)
    return f"VER-{number}"


def _finding_candidate(
    *,
    run_id: str,
    row: Mapping[str, Any],
    producer_invocation_id: str,
) -> dict[str, Any]:
    candidate = {
        "schema_version": CANDIDATE_SCHEMA,
        "run_id": run_id,
        "candidate_id": row["candidate_id"],
        "lineage_ids": [row["candidate_id"], row["source_work_item_id"]],
        "source_artifact": row["source_operator_receipt"],
        "source_artifact_sha256": row["source_operator_receipt_sha256"],
        "source_record_sha256": row["candidate_digest"],
        "producer_identity": f"verifier-producer:{row['source_work_item_id']}",
        "producer_invocation_id": producer_invocation_id,
        "producer_phase": "verification",
        "entry_reason": "POST_VERIFY_SIDE_OBSERVATION",
        "origin_assessment": "NEW_OBSERVATION_PROPOSAL",
        "upstream_severity": "Unknown",
        "title": row["title"],
        "location": row["location"],
        "evidence_pointer": row["evidence"],
        "candidate_content_sha256": "",
        "location_quality": "EXACT" if row["location"] else "UNRESOLVED",
        "source_provenance_quality": "EXACT",
        "scope_state": "UNRESOLVED",
    }
    candidate["candidate_content_sha256"] = candidate_content_sha256(candidate)
    return candidate


def build_verifier_operator_consumer_authority(
    *,
    run_id: str,
    receipt_paths: Sequence[Path],
    scratchpad: Path,
    max_rows_per_shard: int = DEFAULT_MAX_ROWS_PER_SHARD,
) -> dict[str, Any]:
    """Consume an exact receipt denominator into candidates and assurance debt."""

    run = _text(run_id, "run_id")
    root = Path(scratchpad)
    if isinstance(max_rows_per_shard, bool) or not isinstance(max_rows_per_shard, int):
        raise ConsumerAuthorityError("max_rows_per_shard must be an integer")
    if not 1 <= max_rows_per_shard <= 16:
        raise ConsumerAuthorityError("max_rows_per_shard must be between 1 and 16")
    normalized_paths = [Path(path) for path in receipt_paths]
    relative_paths = [_relative_source_path(path, root) for path in normalized_paths]
    if len(relative_paths) != len(set(relative_paths)):
        raise ConsumerAuthorityError("duplicate source receipt path")

    sources: list[dict[str, Any]] = []
    candidate_rows: list[dict[str, Any]] = []
    assurance_rows: list[dict[str, Any]] = []
    candidate_ids: set[str] = set()
    for path, relative in sorted(zip(normalized_paths, relative_paths), key=lambda row: row[1]):
        receipt, raw = _load_receipt(path)
        source_sha = _bytes_digest(raw)
        source = {
            "path": relative,
            "sha256": source_sha,
            "receipt_digest": receipt["receipt_digest"],
            "work_item_id": receipt["work_item_id"],
            "method_dispatch_id": receipt["method_dispatch_id"],
            "launch_digest": receipt["launch_digest"],
        }
        sources.append(source)
        for index, value in enumerate(receipt["new_observations"]):
            observation = _exact(value, _OBSERVATION_FIELDS, "new observation")
            for field in ("title", "mechanism", "location", "evidence", "source_work_item_id"):
                observation[field] = _text(
                    observation[field], field, allow_empty=field == "location"
                )
            if observation["candidate_state"] != "PROPOSED":
                raise ConsumerAuthorityError("new observation is not proposal-only")
            if observation["terminal_authority"] is not False:
                raise ConsumerAuthorityError("new observation has terminal authority")
            if observation["source_work_item_id"] != receipt["work_item_id"]:
                raise ConsumerAuthorityError("new observation source identity mismatch")
            candidate_id = _candidate_identity(receipt, observation)
            semantic = {
                "candidate_id": candidate_id,
                "source_work_item_id": receipt["work_item_id"],
                "source_observation_index": index,
                "source_operator_receipt": relative,
                "source_operator_receipt_sha256": source_sha,
                "source_operator_receipt_digest": receipt["receipt_digest"],
                "title": observation["title"],
                "mechanism": observation["mechanism"],
                "location": observation["location"],
                "evidence": observation["evidence"],
            }
            candidate_digest = _digest(semantic)
            row = {
                **semantic,
                "candidate_digest": candidate_digest,
                "candidate_state": "PROPOSED_REQUIRES_INDEPENDENT_VERIFICATION",
                "terminal_authority": False,
                "severity_proposal": "Unknown",
            }
            if candidate_id in candidate_ids:
                raise ConsumerAuthorityError("candidate identity collision")
            candidate_ids.add(candidate_id)
            candidate_rows.append(row)
        for value in receipt["debts"]:
            debt = _exact(value, _DEBT_FIELDS, "operator debt")
            _text(debt["operator_id"], "operator_id")
            _text(debt["debt_code"], "debt_code")
            if (
                not isinstance(debt["blocker_evidence"], list)
                or not debt["blocker_evidence"]
                or any(not isinstance(item, str) or not item.strip() for item in debt["blocker_evidence"])
            ):
                raise ConsumerAuthorityError("operator debt lacks blocker evidence")
            if debt["report_visible"] is not True or debt["terminal_authority"] is not False:
                raise ConsumerAuthorityError("operator debt visibility/authority mismatch")
            semantic = {
                "affected_work_item_id": receipt["work_item_id"],
                "operator_id": debt["operator_id"],
                "debt_code": debt["debt_code"],
                "blocker_evidence": list(debt["blocker_evidence"]),
                "context_status": receipt["context_status"],
                "source_operator_receipt": relative,
                "source_operator_receipt_sha256": source_sha,
                "source_operator_receipt_digest": receipt["receipt_digest"],
                "report_visible": True,
                "terminal_authority": False,
                "verification_confidence_effect": "REDUCED",
            }
            debt_digest = _digest(semantic)
            assurance_rows.append({
                "schema_version": ASSURANCE_DEBT_SCHEMA,
                "debt_id": "VDEBT-" + debt_digest.upper(),
                **semantic,
                "debt_digest": debt_digest,
            })

    candidate_rows.sort(key=lambda row: (row["candidate_id"], row["candidate_digest"]))
    assurance_rows.sort(key=lambda row: row["debt_id"])
    finding_candidates = [
        _finding_candidate(
            run_id=run,
            row=row,
            producer_invocation_id=next(
                source["launch_digest"]
                for source in sources
                if source["path"] == row["source_operator_receipt"]
            ),
        )
        for row in candidate_rows
    ]
    invocation = _digest({"run_id": run, "source_receipts": sources})
    lifecycle = build_finding_lifecycle(
        run_id=run,
        candidates=finding_candidates,
        decisions=[],
        projections=[],
        authority_identity="verification-operator-consumer",
        authority_invocation_id=invocation,
    )
    obligations = {
        row["candidate_id"]: row for row in finding_verification_work_items(lifecycle)
    }
    late_rows: list[dict[str, Any]] = []
    for candidate in candidate_rows:
        obligation = obligations.get(candidate["candidate_id"])
        if obligation is None:
            raise ConsumerAuthorityError("candidate lifecycle did not create verification work")
        late_rows.append({
            "work_item_id": candidate["candidate_id"],
            "source_candidate_digest": candidate["candidate_digest"],
            "source_work_item_id": candidate["source_work_item_id"],
            "source_identity": candidate["source_work_item_id"],
            "source_operator_receipt": candidate["source_operator_receipt"],
            "source_operator_receipt_sha256": candidate[
                "source_operator_receipt_sha256"
            ],
            "source_operator_receipt_digest": candidate[
                "source_operator_receipt_digest"
            ],
            "title": candidate["title"],
            "mechanism": candidate["mechanism"],
            "evidence": candidate["evidence"],
            "bug_class": "verifier-side-observation",
            "location": candidate["location"],
            "primary_artifact": candidate["source_operator_receipt"],
            "poc_class": "structural",
            "severity": "Unknown",
            "producer_identity": f"verifier-producer:{candidate['source_work_item_id']}",
            "required_discriminator_identity": "late-independent-verifier",
            "independent_discriminator_required": True,
            "terminal_authority": False,
            "finding_lifecycle_obligation_id": obligation["obligation_id"],
        })
    shards: list[dict[str, Any]] = []
    for offset in range(0, len(late_rows), max_rows_per_shard):
        rows = late_rows[offset: offset + max_rows_per_shard]
        unsigned = {
            "schema_version": LATE_SHARD_SCHEMA,
            "shard_id": f"late-{len(shards) + 1:04d}",
            "row_count": len(rows),
            "rows": rows,
        }
        shards.append({**unsigned, "shard_digest": _digest(unsigned)})
    status = (
        "LATE_VERIFICATION_AND_ASSURANCE_DEBT"
        if candidate_rows and assurance_rows
        else "LATE_VERIFICATION_REQUIRED"
        if candidate_rows
        else "ASSURANCE_DEBT_ONLY"
        if assurance_rows
        else "CLEAN_NO_OP"
    )
    unsigned = {
        "schema_version": AUTHORITY_SCHEMA,
        "run_id": run,
        "status": status,
        "source_receipt_count": len(sources),
        "source_receipts": sources,
        "candidate_count": len(candidate_rows),
        "candidates": candidate_rows,
        "finding_lifecycle": lifecycle,
        "late_verification_shards": shards,
        "assurance_debt_count": len(assurance_rows),
        "assurance_debts": assurance_rows,
        "max_rows_per_shard": max_rows_per_shard,
    }
    payload = {**unsigned, "authority_digest": _digest(unsigned)}
    return validate_verifier_operator_consumer_authority(payload)


def validate_verifier_operator_consumer_authority(
    value: Mapping[str, Any],
    *,
    scratchpad: Path | None = None,
) -> dict[str, Any]:
    row = _exact(value, _AUTHORITY_FIELDS, "consumer authority")
    if row["schema_version"] != AUTHORITY_SCHEMA:
        raise ConsumerAuthorityError("consumer authority schema mismatch")
    _text(row["run_id"], "run_id")
    if row["status"] not in _STATUSES:
        raise ConsumerAuthorityError("consumer authority status is invalid")
    if not isinstance(row["max_rows_per_shard"], int) or isinstance(row["max_rows_per_shard"], bool):
        raise ConsumerAuthorityError("max_rows_per_shard must be an integer")
    if not 1 <= row["max_rows_per_shard"] <= 16:
        raise ConsumerAuthorityError("max_rows_per_shard is out of bounds")
    for field in ("source_receipts", "candidates", "late_verification_shards", "assurance_debts"):
        if not isinstance(row[field], list):
            raise ConsumerAuthorityError(f"{field} must be an array")
    if row["source_receipt_count"] != len(row["source_receipts"]):
        raise ConsumerAuthorityError("source receipt count mismatch")
    if row["candidate_count"] != len(row["candidates"]):
        raise ConsumerAuthorityError("candidate count mismatch")
    if row["assurance_debt_count"] != len(row["assurance_debts"]):
        raise ConsumerAuthorityError("assurance debt count mismatch")
    source_paths: set[str] = set()
    for value in row["source_receipts"]:
        source = _exact(value, _SOURCE_FIELDS, "source receipt")
        path = _text(source["path"], "source path")
        if "\\" in path or PurePosixPath(path).is_absolute() or ".." in PurePosixPath(path).parts:
            raise ConsumerAuthorityError("source receipt path is not canonical relative")
        if path in source_paths:
            raise ConsumerAuthorityError("duplicate source receipt path")
        source_paths.add(path)
        for field in ("sha256", "receipt_digest", "launch_digest"):
            _sha256(source[field], field)
        _text(source["work_item_id"], "work_item_id")
        _text(source["method_dispatch_id"], "method_dispatch_id")
    candidate_ids: set[str] = set()
    for value in row["candidates"]:
        candidate = _exact(value, _CANDIDATE_FIELDS, "candidate")
        for field in (
            "candidate_id", "candidate_state", "severity_proposal",
            "source_work_item_id", "source_operator_receipt", "title",
            "mechanism", "evidence",
        ):
            _text(candidate[field], field)
        _text(candidate["location"], "location", allow_empty=True)
        if candidate["candidate_id"] in candidate_ids:
            raise ConsumerAuthorityError("duplicate candidate identity")
        candidate_ids.add(candidate["candidate_id"])
        if candidate["candidate_state"] != "PROPOSED_REQUIRES_INDEPENDENT_VERIFICATION":
            raise ConsumerAuthorityError("candidate state is not proposal-only")
        if candidate["terminal_authority"] is not False or candidate["severity_proposal"] != "Unknown":
            raise ConsumerAuthorityError("candidate acquired terminal/severity authority")
        if candidate["source_operator_receipt"] not in source_paths:
            raise ConsumerAuthorityError("candidate source receipt is outside denominator")
        for field in (
            "candidate_digest", "source_operator_receipt_sha256",
            "source_operator_receipt_digest",
        ):
            _sha256(candidate[field], field)
        semantic = {
            key: candidate[key]
            for key in (
                "candidate_id", "source_work_item_id", "source_observation_index",
                "source_operator_receipt", "source_operator_receipt_sha256",
                "source_operator_receipt_digest", "title", "mechanism",
                "location", "evidence",
            )
        }
        if candidate["candidate_digest"] != _digest(semantic):
            raise ConsumerAuthorityError("candidate digest mismatch")
    lifecycle = validate_finding_lifecycle(row["finding_lifecycle"])
    if lifecycle["run_id"] != row["run_id"]:
        raise ConsumerAuthorityError("finding lifecycle run identity mismatch")
    lifecycle_ids = {state["candidate_id"] for state in lifecycle["candidate_states"]}
    if lifecycle_ids != candidate_ids:
        raise ConsumerAuthorityError("candidate/finding lifecycle denominator mismatch")
    flattened: list[dict[str, Any]] = []
    for value in row["late_verification_shards"]:
        shard = _exact(value, _SHARD_FIELDS, "late shard")
        if shard["schema_version"] != LATE_SHARD_SCHEMA:
            raise ConsumerAuthorityError("late shard schema mismatch")
        _text(shard["shard_id"], "shard_id")
        if not isinstance(shard["rows"], list) or shard["row_count"] != len(shard["rows"]):
            raise ConsumerAuthorityError("late shard row count mismatch")
        if not 1 <= len(shard["rows"]) <= row["max_rows_per_shard"]:
            raise ConsumerAuthorityError("late shard violates bounded row count")
        for work in shard["rows"]:
            flattened.append(_exact(work, _LATE_WORK_FIELDS, "late work row"))
        unsigned = {key: shard[key] for key in _SHARD_FIELDS if key != "shard_digest"}
        if _sha256(shard["shard_digest"], "shard_digest") != _digest(unsigned):
            raise ConsumerAuthorityError("late shard digest mismatch")
    if {work["work_item_id"] for work in flattened} != candidate_ids:
        raise ConsumerAuthorityError("late queue/candidate denominator mismatch")
    if any(
        work["independent_discriminator_required"] is not True
        or work["terminal_authority"] is not False
        or work["producer_identity"] == work["required_discriminator_identity"]
        for work in flattened
    ):
        raise ConsumerAuthorityError("late work does not enforce independence")
    for value in row["assurance_debts"]:
        debt = _exact(value, _ASSURANCE_FIELDS, "assurance debt")
        if debt["schema_version"] != ASSURANCE_DEBT_SCHEMA:
            raise ConsumerAuthorityError("assurance debt schema mismatch")
        if debt["source_operator_receipt"] not in source_paths:
            raise ConsumerAuthorityError("assurance debt source is outside denominator")
        if debt["report_visible"] is not True or debt["terminal_authority"] is not False:
            raise ConsumerAuthorityError("assurance debt visibility/authority mismatch")
        if debt["verification_confidence_effect"] != "REDUCED":
            raise ConsumerAuthorityError("assurance debt confidence effect mismatch")
        semantic = {
            key: debt[key]
            for key in _ASSURANCE_FIELDS
            if key not in {"schema_version", "debt_id", "debt_digest"}
        }
        if _sha256(debt["debt_digest"], "debt_digest") != _digest(semantic):
            raise ConsumerAuthorityError("assurance debt digest mismatch")
        if debt["debt_id"] != "VDEBT-" + debt["debt_digest"].upper():
            raise ConsumerAuthorityError("assurance debt identity mismatch")
    expected_status = (
        "LATE_VERIFICATION_AND_ASSURANCE_DEBT"
        if row["candidates"] and row["assurance_debts"]
        else "LATE_VERIFICATION_REQUIRED"
        if row["candidates"]
        else "ASSURANCE_DEBT_ONLY"
        if row["assurance_debts"]
        else "CLEAN_NO_OP"
    )
    if row["status"] != expected_status:
        raise ConsumerAuthorityError("consumer authority status/count mismatch")
    unsigned = {key: row[key] for key in _AUTHORITY_FIELDS if key != "authority_digest"}
    if _sha256(row["authority_digest"], "authority_digest") != _digest(unsigned):
        raise ConsumerAuthorityError("consumer authority digest mismatch")
    if scratchpad is not None:
        root = Path(scratchpad)
        try:
            rebuilt = build_verifier_operator_consumer_authority(
                run_id=row["run_id"],
                receipt_paths=[
                    root / PurePosixPath(source["path"])
                    for source in row["source_receipts"]
                ],
                scratchpad=root,
                max_rows_per_shard=row["max_rows_per_shard"],
            )
        except ConsumerAuthorityError as exc:
            raise ConsumerAuthorityError(
                f"source receipt recomputation failed: {exc}"
            ) from exc
        if rebuilt != row:
            raise ConsumerAuthorityError(
                "consumer authority derived projections differ from recomputed "
                "source receipts"
            )
    return row


def _validate_current_sources(target: Path, authority: Mapping[str, Any]) -> None:
    for source in authority["source_receipts"]:
        path = target.parent / PurePosixPath(source["path"])
        try:
            actual = _bytes_digest(path.read_bytes())
        except OSError as exc:
            raise ConsumerAuthorityError(
                f"source receipt is unavailable during commit: {source['path']}"
            ) from exc
        if actual != source["sha256"]:
            raise ConsumerAuthorityError(
                f"source receipt changed during commit: {source['path']}"
            )


def write_or_validate_verifier_operator_consumer_authority(
    path: Path, value: Mapping[str, Any]
) -> bool:
    """Create exact authority once; unchanged replay is a byte-stable no-op."""

    target = Path(path)
    authority = validate_verifier_operator_consumer_authority(
        value, scratchpad=target.parent
    )
    _validate_current_sources(target, authority)
    rendered = json.dumps(
        authority, indent=2, sort_keys=True, ensure_ascii=False
    ) + "\n"
    if target.is_file():
        try:
            existing = json.loads(target.read_text(encoding="utf-8", errors="strict"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise ConsumerAuthorityError(f"existing consumer authority is unreadable: {exc}") from exc
        if validate_verifier_operator_consumer_authority(
            existing, scratchpad=target.parent
        ) != authority:
            raise ConsumerAuthorityError("existing consumer authority differs from current inputs")
        if target.read_text(encoding="utf-8", errors="strict") != rendered:
            raise ConsumerAuthorityError("existing consumer authority bytes are non-canonical")
        return False
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, raw = tempfile.mkstemp(prefix=f".{target.name}.", suffix=".tmp", dir=target.parent)
    temporary = Path(raw)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(rendered)
            handle.flush()
            os.fsync(handle.fileno())
        _validate_current_sources(target, authority)
        os.replace(temporary, target)
    finally:
        temporary.unlink(missing_ok=True)
    return True


__all__ = [
    "ASSURANCE_DEBT_SCHEMA",
    "AUTHORITY_SCHEMA",
    "ConsumerAuthorityError",
    "DEFAULT_MAX_ROWS_PER_SHARD",
    "LATE_SHARD_SCHEMA",
    "build_verifier_operator_consumer_authority",
    "validate_verifier_operator_consumer_authority",
    "write_or_validate_verifier_operator_consumer_authority",
]
