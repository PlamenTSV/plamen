"""Crash-recoverable proposal-only L1 composition queue delivery.

The typed L1 provider and independent disposition worker may nominate a
composition obligation, but neither can grant proof, severity, or a finding
verdict.  This adapter authenticates their deterministic reconciliation and
adds the resulting work item to the ordinary typed verification queue.  It
never rewrites the finding inventory and never removes an ordinary queue row.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
from typing import Any, Callable, Mapping, Sequence

import l1_composition_runtime as composition
from plamen_parsers import (
    _read_typed_queue_work_items,
    _write_queue_work_item_records_manifest,
)
from queue_work_items import (
    LineageLink,
    LocationRecord,
    QueueWorkItem,
    SeverityProposal,
    queue_record_set_digest,
    queue_records_from_json,
    queue_records_to_json,
)


DELIVERY_RECEIPT_NAME = "l1_composition_queue_delivery_receipt.json"
DELIVERY_DEBT_NAME = "l1_composition_queue_delivery_debt.json"
DELIVERY_STATUS_NAME = "l1_composition_queue_delivery_status.json"
DELIVERY_JOURNAL_NAME = "l1_composition_queue_delivery_transaction.json"
QUEUE_INPUT_NAME = "l1_composition_queue_input.work_items.json"

DELIVERY_SCHEMA = "plamen.l1_composition_queue_delivery.v1"
DEBT_SCHEMA = "plamen.l1_composition_queue_delivery_debt.v1"
STATUS_SCHEMA = "plamen.l1_composition_queue_delivery_status.v1"
JOURNAL_SCHEMA = "plamen.l1_composition_queue_transaction.v1"
MAX_CONTROL_BYTES = 96 * 1024 * 1024
MAX_QUEUE_ITEMS = 20_768
_HEX64 = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$", re.ASCII)
_QUEUE_PROJECTIONS = (
    "verification_queue.md",
    "verification_queue.json",
    "verification_queue.work_items.json",
)
_PUBLISH_ORDER = (
    *_QUEUE_PROJECTIONS,
    DELIVERY_RECEIPT_NAME,
    DELIVERY_DEBT_NAME,
    DELIVERY_STATUS_NAME,
)
_PRODUCER_BINDING_FIELDS = {
    "fact_producer_identity",
    "fact_producer_invocation_id",
    "disposition_producer_identity",
    "disposition_producer_invocation_id",
}


class L1CompositionQueueRuntimeError(RuntimeError):
    """The prepared queue successor cannot yet be consumed safely."""


@dataclass(frozen=True, slots=True)
class L1CompositionQueueOutcome:
    committed: bool
    safe_to_shard: bool
    authorized_work_item_ids: tuple[str, ...]
    issues: tuple[str, ...]
    status: Mapping[str, Any]


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=True, allow_nan=False,
        sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _signed(value: Mapping[str, Any], key: str) -> dict[str, Any]:
    payload = dict(value)
    payload[key] = ""
    payload[key] = _digest(payload)
    return payload


def _json_bytes(value: Mapping[str, Any]) -> bytes:
    return json.dumps(
        value, ensure_ascii=True, allow_nan=False, sort_keys=True, indent=2
    ).encode("utf-8") + b"\n"


def _bytes_record(raw: bytes) -> dict[str, Any]:
    return {"sha256": hashlib.sha256(raw).hexdigest(), "size_bytes": len(raw)}


def _atomic_bytes(path: Path, raw: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "wb", dir=str(path.parent), delete=False,
        prefix=f".{path.name}.", suffix=".tmp",
    ) as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())
        temporary = Path(handle.name)
    try:
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _read_bytes(path: Path) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"required regular artifact unavailable: {path.name}")
    before = path.stat()
    if before.st_size > MAX_CONTROL_BYTES:
        raise ValueError(f"control artifact oversized: {path.name}")
    raw = path.read_bytes()
    after = path.stat()
    if (
        len(raw) > MAX_CONTROL_BYTES
        or before.st_size != after.st_size
        or before.st_mtime_ns != after.st_mtime_ns
        or after.st_size != len(raw)
    ):
        raise ValueError(f"control artifact changed during read: {path.name}")
    return raw


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _read_json(path: Path) -> dict[str, Any]:
    value = json.loads(
        _read_bytes(path).decode("utf-8", errors="strict"),
        object_pairs_hook=_strict_object,
        parse_constant=lambda token: (_ for _ in ()).throw(
            ValueError(f"invalid JSON constant: {token}")
        ),
    )
    if not isinstance(value, dict):
        raise ValueError(f"control artifact is not an object: {path.name}")
    return value


def _context(config: Mapping[str, Any]) -> dict[str, str]:
    snapshot = config.get("_audit_snapshot") or config.get("audit_snapshot") or {}
    snapshot_digest = (
        str(snapshot.get("snapshot_digest") or "")
        if isinstance(snapshot, Mapping) else ""
    )
    return {
        "pipeline": str(config.get("pipeline") or "l1"),
        "mode": str(config.get("mode") or "core"),
        "language": str(config.get("language") or "other"),
        "run_id": str(config.get("_run_id") or ""),
        "snapshot_digest": snapshot_digest,
    }


def _producer_bindings(value: Mapping[str, Any] | None) -> dict[str, str]:
    if not isinstance(value, Mapping) or set(value) != _PRODUCER_BINDING_FIELDS:
        raise ValueError("driver-bound L1 composition producer denominator missing")
    result: dict[str, str] = {}
    for field in sorted(_PRODUCER_BINDING_FIELDS):
        raw = value.get(field)
        if (
            not isinstance(raw, str)
            or not raw.strip()
            or len(raw) > 4096
            or any(ord(char) < 32 or ord(char) == 127 for char in raw)
        ):
            raise ValueError(f"invalid driver-bound producer field: {field}")
        result[field] = raw.strip()
    if (
        result["fact_producer_identity"]
        == result["disposition_producer_identity"]
        or result["fact_producer_invocation_id"]
        == result["disposition_producer_invocation_id"]
    ):
        raise ValueError("fact and disposition producers are not independent")
    return result


def _no_work_reason(root: Path, config: Mapping[str, Any]) -> str:
    """Return a current exact conditional-no-work reason, never by absence alone."""

    context = _context(config)
    worklist_path = root / composition.FACT_WORKLIST_NAME
    if worklist_path.is_file() and not worklist_path.is_symlink():
        worklist = _read_json(worklist_path)
        if not composition.validate_l1_composition_fact_worklist(
            worklist, root, **context
        ):
            if (
                int(worklist.get("occurrence_count") or 0) == 0
                and not composition.l1_composition_source_artifacts(
                    root,
                    pipeline=context["pipeline"],
                    mode=context["mode"],
                )
            ):
                return "NO_SOURCE_OCCURRENCES"
    runtime_path = root / composition.RUNTIME_NAME
    if runtime_path.is_file() and not runtime_path.is_symlink():
        runtime = _read_json(runtime_path)
        if not composition.validate_l1_composition_runtime(
            runtime, root, **context
        ) and not runtime.get("work_packets"):
            return "NO_COMPOSITION_OBLIGATIONS"
    return ""


def _validated_upstream(
    root: Path,
    config: Mapping[str, Any],
    producer_bindings: Mapping[str, Any] | None,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    bindings = _producer_bindings(producer_bindings)
    runtime = _read_json(root / composition.RUNTIME_NAME)
    dispositions = _read_json(root / composition.MODEL_DISPOSITIONS_NAME)
    receipt = _read_json(root / composition.RECEIPT_NAME)
    fact_issues = composition.validate_l1_composition_fact_records(
        root,
        **_context(config),
        expected_producer_identity=bindings["fact_producer_identity"],
        expected_producer_invocation_id=bindings["fact_producer_invocation_id"],
    )
    runtime_issues = composition.validate_l1_composition_runtime(
        runtime, root, **_context(config)
    )
    receipt_issues = composition.validate_l1_composition_receipt(
        receipt, runtime, dispositions
    )
    principal_issues: list[str] = []
    if (
        dispositions.get("producer_identity")
        != bindings["disposition_producer_identity"]
    ):
        principal_issues.append("disposition producer identity is foreign")
    if (
        dispositions.get("producer_invocation_id")
        != bindings["disposition_producer_invocation_id"]
    ):
        principal_issues.append("disposition producer invocation is foreign")
    if fact_issues or runtime_issues or receipt_issues or principal_issues:
        raise ValueError(
            "; ".join(
                [*fact_issues, *runtime_issues, *receipt_issues, *principal_issues]
            )
        )
    if receipt.get("capabilities") != composition.PROPOSAL_ONLY_CAPABILITIES:
        raise ValueError("composition receipt acquired unregistered authority")
    return runtime, dispositions, receipt


def _safe_constituent(identity: str) -> str:
    return (
        identity if _SAFE_ID.fullmatch(identity)
        else "L1SRC-" + hashlib.sha256(identity.encode("utf-8")).hexdigest()[:20].upper()
    )


def _queue_item(handoff: Mapping[str, Any], *, priority: int) -> QueueWorkItem:
    proposal_id = str(handoff["proposal_id"])
    constituent_ids = tuple(
        dict.fromkeys(
            _safe_constituent(str(value))
            for value in handoff.get("candidate_ids") or []
        )
    )
    bindings = [
        row for row in handoff.get("constituent_source_bindings") or []
        if isinstance(row, Mapping)
    ]
    source_by_candidate = {
        _safe_constituent(str(row.get("candidate_id") or "")): row
        for row in bindings
    }
    lineage = [
        LineageLink(
            identity=proposal_id,
            relation="ORIGIN",
            source_artifact=composition.RECEIPT_NAME,
        )
    ]
    lineage.extend(
        LineageLink(
            identity=identity,
            relation="CONSTITUENT",
            parent_identity=proposal_id,
            source_artifact=str(
                source_by_candidate.get(identity, {}).get("source_artifact")
                or composition.RECEIPT_NAME
            ),
        )
        for identity in constituent_ids
    )
    locations = [
        LocationRecord(
            artifact=composition.RECEIPT_NAME,
            note=(
                f"proposal={proposal_id};handoff_sha256="
                f"{handoff.get('handoff_digest')}"
            ),
        )
    ]
    for row in bindings:
        start = int(row.get("source_block_start_line") or 0) or None
        end = int(row.get("source_block_end_line") or 0) or None
        locations.append(
            LocationRecord(
                artifact=str(row.get("source_artifact") or composition.RECEIPT_NAME),
                start_line=start,
                end_line=end if start else None,
                note=(
                    f"source_candidate={row.get('candidate_id')};"
                    f"fact_sha256={row.get('fact_digest')}"
                ),
            )
        )
    source_artifacts = tuple(
        dict.fromkeys(
            str(row.get("source_artifact") or "")
            for row in bindings if str(row.get("source_artifact") or "")
        )
    )
    relation = str(handoff.get("relation") or "cross-subsystem")
    atom = handoff.get("atom") if isinstance(handoff.get("atom"), Mapping) else {}
    atom_kind = str(atom.get("kind") or "unknown")
    return QueueWorkItem(
        candidate_identity=proposal_id,
        work_item_id=proposal_id,
        lineage=tuple(lineage),
        aliases=(),
        constituents=constituent_ids,
        severity_proposal=SeverityProposal(
            level="Medium",
            rationale=(
                "Low-confidence composition proposal only; ordinary independent "
                "verification determines mechanism, harm, and final severity."
            ),
        ),
        evidence_class="l1-composition-generator",
        bug_class="cross-subsystem-composition",
        preferred_tag="CODE-TRACE",
        queue_priority=priority,
        location_records=tuple(locations),
        primary_artifacts=(
            composition.RUNTIME_NAME,
            composition.RECEIPT_NAME,
            *source_artifacts,
        ),
        poc_class="sequence",
        title=(
            f"Verify {relation} composition over {atom_kind} atom "
            f"({proposal_id})"
        ),
        effective_evidence_scope="ANALYTICAL",
        effective_proof_scope="NONE",
        effective_harm_scope="UNPROVEN",
    )


def _looks_owned(item: QueueWorkItem) -> bool:
    return (
        item.evidence_class == "l1-composition-generator"
        and composition.RUNTIME_NAME in item.primary_artifacts
        and composition.RECEIPT_NAME in item.primary_artifacts
    )


def _validated_prior_owned(root: Path) -> dict[str, str]:
    path = root / DELIVERY_RECEIPT_NAME
    if not path.is_file() or path.is_symlink():
        return {}
    prior = _read_json(path)
    supplied = str(prior.get("delivery_digest") or "")
    unsigned = dict(prior)
    unsigned["delivery_digest"] = ""
    if (
        prior.get("schema_version") != DELIVERY_SCHEMA
        or not _HEX64.fullmatch(supplied)
        or supplied != _digest(unsigned)
        or prior.get("proof_authority") != "NONE"
        or not isinstance(prior.get("owned_work_item_digests"), Mapping)
    ):
        raise ValueError("prior L1 composition delivery receipt is invalid")
    return {
        str(key): str(value)
        for key, value in prior["owned_work_item_digests"].items()
        if isinstance(key, str) and isinstance(value, str)
    }


def _plan(
    root: Path,
    config: Mapping[str, Any],
    before: Sequence[QueueWorkItem],
    producer_bindings: Mapping[str, Any] | None,
) -> tuple[tuple[QueueWorkItem, ...], dict[str, Any], dict[str, Any], list[str]]:
    _runtime, _dispositions, receipt = _validated_upstream(
        root, config, producer_bindings
    )
    prior_owned = _validated_prior_owned(root)
    ordinary: list[QueueWorkItem] = []
    issues: list[str] = []
    for item in before:
        if not _looks_owned(item):
            ordinary.append(item)
            continue
        if prior_owned.get(item.work_item_id) == item.digest:
            continue
        ordinary.append(item)
        issues.append(f"UNAUTHENTICATED_L1_COMPOSITION_LOOKALIKE:{item.work_item_id}")
    by_id = {item.work_item_id: item for item in ordinary}
    priority = max((item.queue_priority for item in ordinary), default=0)
    delivered: list[QueueWorkItem] = []
    for handoff in receipt.get("compound_handoffs") or []:
        priority += 1
        try:
            item = _queue_item(handoff, priority=priority)
        except (TypeError, ValueError, KeyError) as exc:
            issues.append(
                "HANDOFF_NOT_DELIVERABLE:"
                + str(handoff.get("proposal_id") or "unknown")
                + f":{type(exc).__name__}:{exc}"
            )
            continue
        existing = by_id.get(item.work_item_id)
        if existing is not None:
            issues.append(f"QUEUE_IDENTITY_COLLISION:{item.work_item_id}")
            continue
        by_id[item.work_item_id] = item
        delivered.append(item)
    after = tuple([*ordinary, *delivered])
    if len(after) > MAX_QUEUE_ITEMS:
        raise ValueError("L1 composition queue successor exceeds cardinality bound")
    delivery = _signed({
        "schema_version": DELIVERY_SCHEMA,
        "run_id": str(receipt.get("run_id") or ""),
        "runtime_digest": str(receipt.get("runtime_digest") or ""),
        "composition_receipt_digest": str(receipt.get("receipt_digest") or ""),
        "status": "DELIVERED" if delivered else "COMPLETE_NO_DELIVERY",
        "authorized_work_item_ids": sorted(item.work_item_id for item in delivered),
        "owned_work_item_digests": {
            item.work_item_id: item.digest for item in sorted(
                delivered, key=lambda value: value.work_item_id
            )
        },
        "ordinary_queue_digest": queue_record_set_digest(tuple(ordinary)),
        "successor_queue_digest": queue_record_set_digest(after),
        "issues": sorted(set(issues)),
        "proof_authority": "NONE",
        "terminal_authority": False,
        "delivery_digest": "",
    }, "delivery_digest")
    debt = _signed({
        "schema_version": DEBT_SCHEMA,
        "run_id": str(receipt.get("run_id") or ""),
        "composition_receipt_digest": str(receipt.get("receipt_digest") or ""),
        "issues": sorted(set(issues)),
        "delivery_blocked": bool(issues),
        "proof_authority": "NONE",
        "debt_digest": "",
    }, "debt_digest")
    return after, delivery, debt, issues


def _render_queue(root: Path, stage: Path, items: tuple[QueueWorkItem, ...]) -> None:
    stage.mkdir(parents=True, exist_ok=True)
    _write_queue_work_item_records_manifest(stage / "verification_queue.md", items)


def _journal_valid(value: Mapping[str, Any]) -> bool:
    expected = {
        "schema_version",
        "state",
        "transaction_id",
        "run_id",
        "composition_receipt_digest",
        "before_queue_digest",
        "after_queue_digest",
        "stage_directory",
        "destinations",
        "publish_order",
        "proof_authority",
        "journal_digest",
    }
    supplied = str(value.get("journal_digest") or "")
    unsigned = dict(value)
    unsigned["journal_digest"] = ""
    transaction_id = str(value.get("transaction_id") or "")
    run_id = value.get("run_id")
    destinations = value.get("destinations")
    destination_rows_valid = bool(
        isinstance(destinations, Mapping)
        and set(destinations) == set(_PUBLISH_ORDER)
        and all(
            isinstance(row, Mapping)
            and set(row) == {"sha256", "size_bytes"}
            and _HEX64.fullmatch(str(row.get("sha256") or ""))
            and type(row.get("size_bytes")) is int
            and 0 <= int(row["size_bytes"]) <= MAX_CONTROL_BYTES
            for row in destinations.values()
        )
    )
    return bool(
        set(value) == expected
        and value.get("schema_version") == JOURNAL_SCHEMA
        and value.get("state") in {"PREPARED", "COMMITTED"}
        and _HEX64.fullmatch(transaction_id)
        and isinstance(run_id, str)
        and bool(run_id.strip())
        and len(run_id) <= 256
        and not any(ord(char) < 32 or ord(char) == 127 for char in run_id)
        and _HEX64.fullmatch(str(value.get("composition_receipt_digest") or ""))
        and _HEX64.fullmatch(str(value.get("before_queue_digest") or ""))
        and _HEX64.fullmatch(str(value.get("after_queue_digest") or ""))
        and value.get("stage_directory")
        == f"_l1_composition_queue_transaction/{transaction_id}"
        and destination_rows_valid
        and value.get("proof_authority") == "NONE"
        and _HEX64.fullmatch(supplied)
        and supplied == _digest(unsigned)
        and value.get("publish_order") == list(_PUBLISH_ORDER)
    )


def _validated_journal_stage(root: Path, journal: Mapping[str, Any]) -> Path:
    """Resolve only the deterministic in-scratchpad transaction stage.

    The journal digest detects accidental byte drift; it is not a keyed
    authentication primitive.  Recovery therefore re-derives the only legal
    stage path instead of trusting a checksum-valid persisted path.
    """

    stage_parent = root / "_l1_composition_queue_transaction"
    stage = stage_parent / str(journal["transaction_id"])
    if stage_parent.is_symlink() or stage.is_symlink():
        raise L1CompositionQueueRuntimeError(
            "L1 queue journal stage contains a symlink component"
        )
    try:
        root_resolved = root.resolve(strict=True)
        if not stage.resolve(strict=False).is_relative_to(root_resolved):
            raise L1CompositionQueueRuntimeError(
                "L1 queue journal stage escapes its scratchpad"
            )
    except OSError as exc:
        raise L1CompositionQueueRuntimeError(
            f"L1 queue journal stage cannot be resolved: {exc}"
        ) from exc
    return stage


def _recover_prepared(
    root: Path,
    config: Mapping[str, Any],
    *,
    producer_bindings: Mapping[str, Any] | None,
    fault_hook: Callable[[str], None] | None = None,
) -> dict[str, Any] | None:
    journal_path = root / DELIVERY_JOURNAL_NAME
    if not journal_path.is_file():
        return None
    journal = _read_json(journal_path)
    if not _journal_valid(journal):
        raise L1CompositionQueueRuntimeError("L1 queue journal is stale or tampered")
    if journal.get("state") == "COMMITTED":
        return journal
    stage_root = _validated_journal_stage(root, journal)
    before = queue_records_from_json(
        _read_bytes(root / QUEUE_INPUT_NAME).decode("utf-8", errors="strict")
    )
    if queue_record_set_digest(before) != journal.get("before_queue_digest"):
        raise L1CompositionQueueRuntimeError("L1 queue preimage digest mismatch")
    after, delivery, debt, issues = _plan(
        root, config, before, producer_bindings
    )
    if queue_record_set_digest(after) != journal.get("after_queue_digest"):
        raise L1CompositionQueueRuntimeError("L1 queue semantic replay drift")
    expected_transaction_id = _digest({
        "run_id": delivery["run_id"],
        "composition_receipt_digest": delivery["composition_receipt_digest"],
        "before_queue_digest": journal["before_queue_digest"],
        "after_queue_digest": journal["after_queue_digest"],
    })
    if (
        journal.get("run_id") != delivery.get("run_id")
        or journal.get("composition_receipt_digest")
        != delivery.get("composition_receipt_digest")
        or journal.get("transaction_id") != expected_transaction_id
    ):
        raise L1CompositionQueueRuntimeError(
            "L1 queue journal is foreign to the current run/receipt transaction"
        )
    transaction_id = str(journal.get("transaction_id") or "")
    status = _signed({
        "schema_version": STATUS_SCHEMA,
        "state": "COMMITTED_WITH_DEBT" if issues else "COMMITTED",
        "transaction_id": transaction_id,
        "run_id": str(delivery.get("run_id") or ""),
        "before_queue_digest": str(journal["before_queue_digest"]),
        "after_queue_digest": str(journal["after_queue_digest"]),
        "authorized_work_item_ids": list(delivery["authorized_work_item_ids"]),
        "safe_to_shard": True,
        "proof_authority": "NONE",
        "issues": sorted(set(issues)),
        "status_digest": "",
    }, "status_digest")
    expected: dict[str, bytes] = {}
    with tempfile.TemporaryDirectory(dir=str(root), prefix="._l1cq_replay.") as temp:
        replay = Path(temp)
        _render_queue(root, replay, after)
        expected.update({name: (replay / name).read_bytes() for name in _QUEUE_PROJECTIONS})
    expected[DELIVERY_RECEIPT_NAME] = _json_bytes(delivery)
    expected[DELIVERY_DEBT_NAME] = _json_bytes(debt)
    expected[DELIVERY_STATUS_NAME] = _json_bytes(status)
    destinations = journal["destinations"]
    for name in _PUBLISH_ORDER:
        if name not in destinations or _bytes_record(expected[name]) != destinations[name]:
            raise L1CompositionQueueRuntimeError(
                f"L1 queue prepared destination is not reproducible: {name}"
            )
        destination = root / name
        if destination.is_file() and _bytes_record(_read_bytes(destination)) == destinations[name]:
            continue
        staged = stage_root / name
        if not staged.is_file() or _bytes_record(_read_bytes(staged)) != destinations[name]:
            # Repair a missing staged byte only from the independently replayed
            # semantic successor, never from a partial destination.
            _atomic_bytes(staged, expected[name])
        os.replace(staged, destination)
        if fault_hook is not None:
            fault_hook(f"published:{name}")
    # Publication is not authority.  Reread the complete fixed postimage after
    # every replace and before the COMMITTED marker so a path swap, external
    # mutation, or partial projection can never be blessed by the journal.
    for name in _PUBLISH_ORDER:
        destination = root / name
        if _bytes_record(_read_bytes(destination)) != destinations[name]:
            raise L1CompositionQueueRuntimeError(
                f"L1 queue published postimage drift: {name}"
            )
    committed = _signed({**journal, "state": "COMMITTED", "journal_digest": ""}, "journal_digest")
    _atomic_bytes(journal_path, _json_bytes(committed))
    return committed


def apply_l1_composition_queue_delivery(
    scratchpad: Path | str,
    config: Mapping[str, Any],
    *,
    producer_bindings: Mapping[str, Any] | None = None,
    fault_hook: Callable[[str], None] | None = None,
) -> L1CompositionQueueOutcome:
    root = Path(scratchpad)
    if producer_bindings is None:
        candidate = config.get("_l1_composition_producer_bindings")
        producer_bindings = candidate if isinstance(candidate, Mapping) else None
    if root.is_symlink() or not root.is_dir():
        raise L1CompositionQueueRuntimeError("scratchpad is missing or a symlink")
    try:
        recovered = _recover_prepared(
            root,
            config,
            producer_bindings=producer_bindings,
            fault_hook=fault_hook,
        )
        if recovered is not None and recovered.get("state") == "PREPARED":
            raise L1CompositionQueueRuntimeError("prepared queue transaction did not recover")
        queue_path = root / "verification_queue.md"
        before = _read_typed_queue_work_items(queue_path)
        no_work_reason = _no_work_reason(root, config)
        if no_work_reason and not any(_looks_owned(item) for item in before):
            return L1CompositionQueueOutcome(
                committed=False,
                safe_to_shard=True,
                authorized_work_item_ids=(),
                issues=(),
                status={"state": "NOT_TRIGGERED", "reason": no_work_reason},
            )
        after, delivery, debt, issues = _plan(
            root, config, before, producer_bindings
        )
        snapshot_raw = (queue_records_to_json(before) + "\n").encode("utf-8")
        _atomic_bytes(root / QUEUE_INPUT_NAME, snapshot_raw)
        before_digest = queue_record_set_digest(before)
        after_digest = queue_record_set_digest(after)
        transaction_id = _digest({
            "run_id": delivery["run_id"],
            "composition_receipt_digest": delivery["composition_receipt_digest"],
            "before_queue_digest": before_digest,
            "after_queue_digest": after_digest,
        })
        status = _signed({
            "schema_version": STATUS_SCHEMA,
            "state": "COMMITTED_WITH_DEBT" if issues else "COMMITTED",
            "transaction_id": transaction_id,
            "run_id": delivery["run_id"],
            "before_queue_digest": before_digest,
            "after_queue_digest": after_digest,
            "authorized_work_item_ids": list(delivery["authorized_work_item_ids"]),
            "safe_to_shard": True,
            "proof_authority": "NONE",
            "issues": sorted(set(issues)),
            "status_digest": "",
        }, "status_digest")
        stage_relative = f"_l1_composition_queue_transaction/{transaction_id}"
        stage = root / stage_relative
        stage_parent = root / "_l1_composition_queue_transaction"
        if stage_parent.is_symlink() or stage.is_symlink():
            raise L1CompositionQueueRuntimeError(
                "queue transaction stage contains a symlink component"
            )
        try:
            if not stage.resolve(strict=False).is_relative_to(root.resolve(strict=True)):
                raise L1CompositionQueueRuntimeError(
                    "queue transaction stage escapes its scratchpad"
                )
        except OSError as exc:
            raise L1CompositionQueueRuntimeError(
                f"queue transaction stage cannot be resolved: {exc}"
            ) from exc
        if stage.exists():
            if not stage.is_dir():
                raise L1CompositionQueueRuntimeError("queue transaction stage is unsafe")
        else:
            stage.mkdir(parents=True)
        _render_queue(root, stage, after)
        _atomic_bytes(stage / DELIVERY_RECEIPT_NAME, _json_bytes(delivery))
        _atomic_bytes(stage / DELIVERY_DEBT_NAME, _json_bytes(debt))
        _atomic_bytes(stage / DELIVERY_STATUS_NAME, _json_bytes(status))
        destinations = {
            name: _bytes_record(_read_bytes(stage / name)) for name in _PUBLISH_ORDER
        }
        journal = _signed({
            "schema_version": JOURNAL_SCHEMA,
            "state": "PREPARED",
            "transaction_id": transaction_id,
            "run_id": delivery["run_id"],
            "composition_receipt_digest": delivery["composition_receipt_digest"],
            "before_queue_digest": before_digest,
            "after_queue_digest": after_digest,
            "stage_directory": stage_relative,
            "destinations": destinations,
            "publish_order": list(_PUBLISH_ORDER),
            "proof_authority": "NONE",
            "journal_digest": "",
        }, "journal_digest")
        _atomic_bytes(root / DELIVERY_JOURNAL_NAME, _json_bytes(journal))
        if fault_hook:
            fault_hook("journal_prepared")
        committed = _recover_prepared(
            root,
            config,
            producer_bindings=producer_bindings,
            fault_hook=fault_hook,
        )
        if committed is None or committed.get("state") != "COMMITTED":
            raise L1CompositionQueueRuntimeError("queue transaction did not commit")
        return L1CompositionQueueOutcome(
            committed=True,
            safe_to_shard=True,
            authorized_work_item_ids=tuple(delivery["authorized_work_item_ids"]),
            issues=tuple(sorted(set(issues))),
            status=status,
        )
    except (OSError, UnicodeError, TypeError, ValueError, L1CompositionQueueRuntimeError) as exc:
        issue = f"L1_COMPOSITION_QUEUE_DEBT:{type(exc).__name__}:{exc}"
        # A prepared transaction may have partially replaced queue projections;
        # it is never safe to shard until a later deterministic replay commits.
        prepared = False
        try:
            journal = _read_json(root / DELIVERY_JOURNAL_NAME)
            prepared = (
                not _journal_valid(journal)
                or journal.get("state") == "PREPARED"
            )
        except Exception:
            prepared = (root / DELIVERY_JOURNAL_NAME).is_file()
        queue_consumable = True
        try:
            _read_typed_queue_work_items(root / "verification_queue.md")
        except Exception:
            queue_consumable = False
        debt = _signed({
            "schema_version": DEBT_SCHEMA,
            "run_id": str(config.get("_run_id") or ""),
            "composition_receipt_digest": "",
            "issues": [issue],
            "delivery_blocked": True,
            "proof_authority": "NONE",
            "debt_digest": "",
        }, "debt_digest")
        if not prepared:
            _atomic_bytes(root / DELIVERY_DEBT_NAME, _json_bytes(debt))
        return L1CompositionQueueOutcome(
            committed=False,
            safe_to_shard=not prepared and queue_consumable,
            authorized_work_item_ids=(),
            issues=(issue,),
            status={"state": "PREPARED" if prepared else "COMPLETED_WITH_DEBT"},
        )


def validated_authorized_work_item_ids(
    scratchpad: Path | str,
    config: Mapping[str, Any],
    *,
    producer_bindings: Mapping[str, Any] | None = None,
) -> tuple[str, ...]:
    """Return only IDs authenticated by current upstream and queue bytes."""

    root = Path(scratchpad)
    if producer_bindings is None:
        candidate = config.get("_l1_composition_producer_bindings")
        producer_bindings = candidate if isinstance(candidate, Mapping) else None
    _runtime, _dispositions, receipt = _validated_upstream(
        root, config, producer_bindings
    )
    delivery = _read_json(root / DELIVERY_RECEIPT_NAME)
    expected_delivery_fields = {
        "schema_version",
        "run_id",
        "runtime_digest",
        "composition_receipt_digest",
        "status",
        "authorized_work_item_ids",
        "owned_work_item_digests",
        "ordinary_queue_digest",
        "successor_queue_digest",
        "issues",
        "proof_authority",
        "terminal_authority",
        "delivery_digest",
    }
    supplied = str(delivery.get("delivery_digest") or "")
    unsigned = dict(delivery)
    unsigned["delivery_digest"] = ""
    if (
        set(delivery) != expected_delivery_fields
        or delivery.get("schema_version") != DELIVERY_SCHEMA
        or supplied != _digest(unsigned)
        or delivery.get("composition_receipt_digest") != receipt.get("receipt_digest")
        or delivery.get("proof_authority") != "NONE"
        or delivery.get("terminal_authority") is not False
    ):
        raise ValueError("L1 composition queue delivery authority invalid")
    current_rows = _read_typed_queue_work_items(root / "verification_queue.md")
    planned_rows, planned_delivery, _planned_debt, _planned_issues = _plan(
        root, config, current_rows, producer_bindings
    )
    if tuple(current_rows) != planned_rows or delivery != planned_delivery:
        raise ValueError(
            "L1 composition delivery authority does not replay the exact queue successor"
        )
    current = {item.work_item_id: item for item in current_rows}
    owned = delivery.get("owned_work_item_digests")
    ids = delivery.get("authorized_work_item_ids")
    if not isinstance(owned, Mapping) or not isinstance(ids, list) or ids != sorted(owned):
        raise ValueError("L1 composition delivery identity denominator invalid")
    for work_id in ids:
        item = current.get(str(work_id))
        if item is None or item.digest != owned.get(work_id) or not _looks_owned(item):
            raise ValueError(f"L1 composition delivered work drift: {work_id}")
    return tuple(str(value) for value in ids)


__all__ = [
    "DELIVERY_DEBT_NAME",
    "DELIVERY_JOURNAL_NAME",
    "DELIVERY_RECEIPT_NAME",
    "DELIVERY_STATUS_NAME",
    "L1CompositionQueueOutcome",
    "L1CompositionQueueRuntimeError",
    "QUEUE_INPUT_NAME",
    "apply_l1_composition_queue_delivery",
    "validated_authorized_work_item_ids",
]
