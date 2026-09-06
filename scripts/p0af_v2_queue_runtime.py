"""Live, ledger-bound P0-AF v2 queue delivery transaction.

The pure adapter decides *what* the next queue denominator is.  This module
owns the driver boundary: it authenticates the upstream P1-M producer in the
artifact ledger, stages all fixed queue projections, publishes them under a
PREPARED journal, and publishes the committed successor status last.  Neither
the journal nor the adapter's proposal grants proof or terminal authority.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
from typing import Any, Mapping

from artifact_ledger import (
    ArtifactLedgerError,
    read_artifact_ledger,
    record_work_unit_artifacts,
    record_work_unit_inputs,
    validate_work_unit_artifacts,
    validate_work_unit_inputs,
)
from p0af_v2_queue_adapter import (
    CANDIDATE_FILE,
    DEBT_SCHEMA,
    RECEIPT_SCHEMA,
    ROUTE_DEBT_FILE,
    WORK_AUTHORITY_FILE,
    plan_p0af_v2_queue_delivery,
)
from phase_io_contracts import LaunchSpec, resolve_phase_io_contract
from plamen_parsers import (
    _ensure_typed_queue_authority,
    _read_typed_queue_work_items,
    _typed_queue_item_legacy_row,
    _write_queue_subset_manifest,
    parse_verification_queue_rows,
)
from queue_work_items import (
    QueueWorkItem,
    queue_record_set_digest,
    queue_records_from_json,
    queue_records_to_json,
)


RECEIPT_FILE = "p0af_v2_queue_delivery_receipt.json"
DEBT_FILE = "p0af_v2_queue_delivery_debt.json"
STATUS_FILE = "p0af_v2_queue_delivery_status.json"
JOURNAL_FILE = "p0af_v2_queue_delivery_transaction.json"
INPUT_SNAPSHOT_FILE = "p0af_v2_queue_input.work_items.json"

STATUS_SCHEMA = "plamen.p0af_v2_queue_runtime_status.v1"
JOURNAL_SCHEMA = "plamen.p0af_v2_queue_transaction.v1"
INACTIVE_SCHEMA = "plamen.p0af_v2_queue_inactive_successor.v1"
MAX_CONTROL_BYTES = 8 * 1024 * 1024
MAX_QUEUE_RECORDS = 16_384
_HEX_RE = re.compile(r"^[0-9a-f]{64}$")
_STAGE_RE = re.compile(r"^_p0af_v2_queue_transaction/[0-9a-f]{64}$")

_UPSTREAM_INPUTS = (
    "arm_before_trust_chain_analysis.input.json",
    "arm_before_trust_composition_obligations.json",
    "authentication_role_authority.json",
    "_canonical_finding_ids.json",
)
_UPSTREAM_OUTPUTS = (CANDIDATE_FILE, WORK_AUTHORITY_FILE, ROUTE_DEBT_FILE)
_ADAPTER_INPUTS = (*_UPSTREAM_OUTPUTS, INPUT_SNAPSHOT_FILE)
_QUEUE_PROJECTIONS = (
    "verification_queue.md",
    "verification_queue.json",
    "verification_queue.work_items.json",
)
_ADAPTER_OUTPUTS = (
    RECEIPT_FILE,
    DEBT_FILE,
    STATUS_FILE,
    JOURNAL_FILE,
)
_PUBLISH_ORDER = (*_QUEUE_PROJECTIONS, RECEIPT_FILE, DEBT_FILE, STATUS_FILE)
_JOURNAL_FIELDS = frozenset({
    "schema_version", "state", "transaction_id", "run_id",
    "upstream_work_unit_digest", "before_queue_digest", "after_queue_digest",
    "stage_directory", "destinations", "publish_order", "proof_authority",
    "terminal_authority", "payload_digest",
})
_COMMITTED_STATUS_FIELDS = frozenset({
    "schema_version", "state", "transaction_id", "run_id",
    "upstream_contract_digest", "upstream_launch_digest",
    "upstream_work_unit_digest", "before_queue_digest", "after_queue_digest",
    "active_successor", "active_successor_sha256",
    "ordinary_verification_delivery_complete", "proof_authority",
    "terminal_authority", "issues", "payload_digest",
})


class P0AFV2QueueRuntimeError(RuntimeError):
    """A recoverable interrupted publish, never a finding disposition."""


@dataclass(frozen=True, slots=True)
class P0AFV2QueueRuntimeOutcome:
    committed: bool
    status: Mapping[str, Any]
    issues: tuple[str, ...]


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _payload_digest(value: Mapping[str, Any]) -> str:
    return _digest({key: item for key, item in value.items() if key != "payload_digest"})


def _bytes_record(raw: bytes) -> dict[str, Any]:
    return {"sha256": hashlib.sha256(raw).hexdigest(), "size_bytes": len(raw)}


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _read_json(path: Path) -> dict[str, Any]:
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
    value = json.loads(
        raw.decode("utf-8", errors="strict"),
        object_pairs_hook=_strict_object,
        parse_constant=lambda token: (_ for _ in ()).throw(
            ValueError(f"non-finite JSON constant: {token}")
        ),
    )
    if not isinstance(value, dict):
        raise ValueError(f"control artifact is not an object: {path.name}")
    return value


def _read_bounded_bytes(path: Path) -> bytes:
    """Read one stable bounded artifact without materializing overflow."""
    before = path.stat()
    if before.st_size > MAX_CONTROL_BYTES:
        raise ValueError(f"control artifact oversized: {path.name}")
    with path.open("rb") as stream:
        opened_before = os.fstat(stream.fileno())
        if opened_before.st_size > MAX_CONTROL_BYTES:
            raise ValueError(f"control artifact oversized: {path.name}")
        raw = stream.read(MAX_CONTROL_BYTES + 1)
        opened_after = os.fstat(stream.fileno())
    after = path.stat()
    stable_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns")
    if (
        len(raw) > MAX_CONTROL_BYTES
        or any(
            getattr(opened_before, field) != getattr(opened_after, field)
            or getattr(opened_after, field) != getattr(after, field)
            for field in stable_fields
        )
        or after.st_size != len(raw)
    ):
        raise ValueError(f"control artifact changed during read: {path.name}")
    return raw


def _read_bounded_utf8(path: Path) -> str:
    return _read_bounded_bytes(path).decode("utf-8", errors="strict")


def _json_object_from_bytes(raw: bytes, label: str) -> dict[str, Any]:
    value = json.loads(
        raw.decode("utf-8", errors="strict"),
        object_pairs_hook=_strict_object,
        parse_constant=lambda token: (_ for _ in ()).throw(
            ValueError(f"non-finite JSON constant: {token}")
        ),
    )
    if not isinstance(value, dict):
        raise ValueError(f"{label} is not an object")
    return value


def _json_bytes(value: Mapping[str, Any]) -> bytes:
    return json.dumps(
        value, indent=2, sort_keys=True, ensure_ascii=True
    ).encode("utf-8") + b"\n"


def _atomic_bytes(path: Path, raw: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_file() and path.read_bytes() == raw:
        return
    with tempfile.NamedTemporaryFile(
        "wb", dir=str(path.parent), delete=False,
        prefix=f".{path.name}.", suffix=".tmp",
    ) as stream:
        stream.write(raw)
        temporary = Path(stream.name)
    os.replace(temporary, path)


def _atomic_json(path: Path, value: Mapping[str, Any]) -> None:
    _atomic_bytes(path, _json_bytes(value))


def _runtime_components(config: Mapping[str, Any]) -> tuple[str, str, str, str]:
    pipeline = "l1" if str(config.get("pipeline") or "sc").lower() == "l1" else "sc"
    mode = str(config.get("mode") or "core").lower()
    ecosystem = str(config.get("language") or "unknown").lower()
    backend = str(config.get("cli_backend") or "claude").lower()
    return pipeline, mode, ecosystem, backend


def p0af_v2_upstream_contract_and_launch(
    config: Mapping[str, Any],
) -> tuple[Any, LaunchSpec]:
    pipeline, mode, ecosystem, backend = _runtime_components(config)
    contract = resolve_phase_io_contract(
        pipeline=pipeline,
        mode=mode,
        ecosystem=ecosystem,
        backend=backend,
        phase="chain",
        work_unit_id="authentication_roles.compound_work",
        exact_inputs=_UPSTREAM_INPUTS,
        exact_outputs=_UPSTREAM_OUTPUTS,
    )
    launch = LaunchSpec(
        work_unit_key=contract.key,
        pipeline=contract.pipeline,
        mode=contract.mode,
        ecosystem=contract.ecosystem,
        backend=contract.backend,
        model="driver",
        timeout_s=120,
        exec_mode="python",
        tool_policy=("filesystem",),
    )
    return contract, launch


def _adapter_contract_and_launch(
    config: Mapping[str, Any],
) -> tuple[Any, LaunchSpec]:
    pipeline, mode, ecosystem, backend = _runtime_components(config)
    if pipeline != "sc":
        raise ValueError("P0-AF v2 queue adapter is registered only for SC")
    contract = resolve_phase_io_contract(
        pipeline=pipeline,
        mode=mode,
        ecosystem=ecosystem,
        backend=backend,
        phase="sc_verify_queue",
        work_unit_id="p0af_v2_queue_adapter",
        exact_inputs=_ADAPTER_INPUTS,
        exact_outputs=_ADAPTER_OUTPUTS,
    )
    launch = LaunchSpec(
        work_unit_key=contract.key,
        pipeline=contract.pipeline,
        mode=contract.mode,
        ecosystem=contract.ecosystem,
        backend=contract.backend,
        model="driver",
        timeout_s=120,
        exec_mode="python",
        tool_policy=("filesystem",),
    )
    return contract, launch


def _validated_upstream(
    root: Path, project_root: Path, config: Mapping[str, Any], run_id: str
) -> tuple[Any, LaunchSpec, str, list[str]]:
    contract, launch = p0af_v2_upstream_contract_and_launch(config)
    issues = validate_work_unit_inputs(
        root, project_root, contract, launch, run_id=run_id
    )
    issues.extend(validate_work_unit_artifacts(
        root, project_root, contract, launch, run_id=run_id, actor="DRIVER"
    ))
    ledger_digest = ""
    try:
        ledger = read_artifact_ledger(root)
        row = ledger.get("work_units", {}).get(contract.key)
        if not isinstance(row, dict):
            issues.append(f"{contract.key}: upstream ledger row absent")
        else:
            ledger_digest = _digest(row)
    except ArtifactLedgerError as exc:
        issues.append(str(exc))
    return contract, launch, ledger_digest, list(dict.fromkeys(issues))


def _current_queue(root: Path) -> tuple[QueueWorkItem, ...]:
    queue_path = root / "verification_queue.md"
    rows = parse_verification_queue_rows(root)
    if not queue_path.is_file() or not rows:
        # An exact typed zero-row queue is valid, but a missing projection is not.
        if not queue_path.is_file():
            raise ValueError("canonical verification queue is absent")
    items = _ensure_typed_queue_authority(queue_path, rows)
    recorded = _read_typed_queue_work_items(queue_path)
    if items != recorded:
        raise ValueError("canonical queue projections disagree")
    return recorded


def _precondition_debt(root: Path, issues: list[str]) -> P0AFV2QueueRuntimeOutcome:
    bounded = [str(issue)[:500] for issue in list(dict.fromkeys(issues))[:32]]
    debt = {
        "schema_version": DEBT_SCHEMA,
        "status": "COMPLETED_WITH_DEBT",
        "error_code": "P0_AF_V2_UPSTREAM_AUTHORITY_INVALID",
        "ordinary_verification_delivery_complete": False,
        "proof_authority": "NONE",
        "issues": bounded,
    }
    debt["payload_digest"] = _payload_digest(debt)
    status = {
        "schema_version": STATUS_SCHEMA,
        "state": "COMPLETED_WITH_DEBT",
        "transaction_id": None,
        "retryable": True,
        "active_successor": DEBT_FILE,
        "active_successor_sha256": hashlib.sha256(_json_bytes(debt)).hexdigest(),
        "proof_authority": "NONE",
        "terminal_authority": False,
        "issues": bounded,
    }
    status["payload_digest"] = _payload_digest(status)
    _atomic_json(root / DEBT_FILE, debt)
    _atomic_json(root / STATUS_FILE, status)
    return P0AFV2QueueRuntimeOutcome(False, status, tuple(bounded))


def _validated_payload(value: Mapping[str, Any], schema: str, label: str) -> None:
    if value.get("schema_version") != schema:
        raise ValueError(f"{label} schema mismatch")
    claimed = value.get("payload_digest")
    if not isinstance(claimed, str) or not _HEX_RE.fullmatch(claimed):
        raise ValueError(f"{label} payload digest malformed")
    if claimed != _payload_digest(value):
        raise ValueError(f"{label} payload digest mismatch")
    if value.get("proof_authority") != "NONE":
        raise ValueError(f"{label} acquired proof authority")


def _is_reparse_or_symlink(path: Path) -> bool:
    if path.is_symlink():
        return True
    try:
        attributes = int(getattr(path.stat(), "st_file_attributes", 0) or 0)
    except OSError:
        return True
    return bool(attributes & 0x400)


def _validated_stage_root(root: Path, relative: Any) -> Path:
    if not isinstance(relative, str) or not _STAGE_RE.fullmatch(relative):
        raise ValueError("queue transaction stage path is invalid")
    root_resolved = root.resolve(strict=True)
    candidate = root / Path(relative)
    # Every existing component must be an ordinary in-root directory.  This is
    # checked before reading or moving any staged byte.
    cursor = root
    for part in Path(relative).parts:
        cursor = cursor / part
        if _is_reparse_or_symlink(cursor):
            raise ValueError("queue transaction stage contains a reparse point")
    resolved = candidate.resolve(strict=True)
    try:
        resolved.relative_to(root_resolved)
    except ValueError as exc:
        raise ValueError("queue transaction stage escapes scratchpad") from exc
    if not resolved.is_dir():
        raise ValueError("queue transaction stage is not a directory")
    return resolved


def _inactive(active: str) -> dict[str, Any]:
    value = {
        "schema_version": INACTIVE_SCHEMA,
        "state": "INACTIVE",
        "active_successor": active,
        "proof_authority": "NONE",
    }
    value["payload_digest"] = _payload_digest(value)
    return value


def _stage_queue(root: Path, stage: Path, items: tuple[QueueWorkItem, ...]) -> None:
    stage.mkdir(parents=True, exist_ok=True)
    rows = [_typed_queue_item_legacy_row(item) for item in items]
    _write_queue_subset_manifest(stage / "verification_queue.md", rows)
    staged = _read_typed_queue_work_items(stage / "verification_queue.md")
    if staged != items:
        raise ValueError("staged typed queue differs from adapter denominator")
    if queue_record_set_digest(staged) != queue_record_set_digest(items):
        raise ValueError("staged queue record digest mismatch")
    if len(parse_verification_queue_rows(stage)) != len(items):
        raise ValueError("staged legacy queue projection row-count mismatch")


def _journal_transaction_id(
    *, run_id: str, upstream_digest: str, before_digest: str,
    after_digest: str, destinations: Mapping[str, Mapping[str, Any]],
) -> str:
    return _digest({
        "run_id": run_id,
        "upstream_work_unit_digest": upstream_digest,
        "before_queue_digest": before_digest,
        "after_queue_digest": after_digest,
        "destinations": destinations,
    })


def _validated_prepared_destination_bytes(
    root: Path, journal: Mapping[str, Any]
) -> tuple[Path, dict[str, bytes]]:
    """Validate every desired destination before any canonical replacement."""

    if set(journal) != _JOURNAL_FIELDS:
        raise ValueError("queue transaction journal fields mismatch")
    if journal.get("state") != "PREPARED":
        raise ValueError("queue transaction is not PREPARED")
    destinations = journal.get("destinations")
    publish_order = journal.get("publish_order")
    if (
        not isinstance(destinations, dict)
        or publish_order != list(_PUBLISH_ORDER)
        or set(destinations) != set(_PUBLISH_ORDER)
    ):
        raise ValueError("queue transaction destination order mismatch")
    if (
        not isinstance(journal.get("run_id"), str)
        or not journal["run_id"]
        or not _HEX_RE.fullmatch(str(journal.get("upstream_work_unit_digest") or ""))
        or not _HEX_RE.fullmatch(str(journal.get("before_queue_digest") or ""))
        or not _HEX_RE.fullmatch(str(journal.get("after_queue_digest") or ""))
        or journal.get("proof_authority") != "NONE"
        or journal.get("terminal_authority") is not False
    ):
        raise ValueError("queue transaction authority fields are malformed")
    expected_transaction_id = _journal_transaction_id(
        run_id=journal["run_id"],
        upstream_digest=journal["upstream_work_unit_digest"],
        before_digest=journal["before_queue_digest"],
        after_digest=journal["after_queue_digest"],
        destinations={
            name: destinations[name]
            for name in _PUBLISH_ORDER
            if name != STATUS_FILE
        },
    )
    if journal.get("transaction_id") != expected_transaction_id:
        raise ValueError("queue transaction identity is not reproducible")
    stage_root = _validated_stage_root(root, journal.get("stage_directory"))
    desired: dict[str, bytes] = {}
    for name in publish_order:
        record = destinations[name]
        if (
            not isinstance(record, dict)
            or set(record) != {"sha256", "size_bytes"}
            or not _HEX_RE.fullmatch(str(record.get("sha256") or ""))
            or isinstance(record.get("size_bytes"), bool)
            or not isinstance(record.get("size_bytes"), int)
            or record["size_bytes"] < 0
            or record["size_bytes"] > MAX_CONTROL_BYTES
        ):
            raise ValueError(f"queue transaction record malformed: {name}")
        destination = root / name
        raw: bytes | None = None
        if destination.is_file():
            candidate = _read_bounded_bytes(destination)
            if _bytes_record(candidate) == record:
                raw = candidate
        if raw is None:
            staged = stage_root / name
            raw = _read_bounded_bytes(staged)
        if _bytes_record(raw) != record:
            raise ValueError(f"staged queue transaction bytes invalid: {name}")
        desired[name] = raw
    return stage_root, desired


def _validate_prepared_transaction_semantics(
    root: Path,
    journal: Mapping[str, Any],
    config: Mapping[str, Any],
) -> None:
    """Reproduce and compare the complete successor before publication."""

    _stage_root, desired = _validated_prepared_destination_bytes(root, journal)
    before_items = queue_records_from_json(
        _read_bounded_utf8(root / INPUT_SNAPSHOT_FILE)
    )
    if len(before_items) > MAX_QUEUE_RECORDS:
        raise ValueError("queue transaction input snapshot cardinality exceeded")
    before_digest = queue_record_set_digest(before_items)
    if before_digest != journal.get("before_queue_digest"):
        raise ValueError("prepared queue input snapshot digest mismatch")
    replay = plan_p0af_v2_queue_delivery(root, before_items)
    replay_items = tuple(replay.queue_items)
    if len(replay_items) > MAX_QUEUE_RECORDS:
        raise ValueError("prepared queue successor cardinality exceeded")
    after_digest = queue_record_set_digest(replay_items)
    if after_digest != journal.get("after_queue_digest"):
        raise ValueError("prepared queue output digest differs from pure replay")

    # Render the deterministic legacy and typed projections out of tree, then
    # compare every desired byte.  This also covers a partially published
    # PREPARED transaction because `desired` is the journal-authenticated union
    # of matching destinations and remaining stage files.
    with tempfile.TemporaryDirectory(
        dir=str(root), prefix="._p0af_v2_semantic_validate."
    ) as temporary:
        expected_root = Path(temporary)
        _stage_queue(root, expected_root, replay_items)
        for name in _QUEUE_PROJECTIONS:
            if desired[name] != (expected_root / name).read_bytes():
                raise ValueError(
                    f"prepared queue projection differs from pure replay: {name}"
                )

    selected_name = RECEIPT_FILE if replay.receipt is not None else DEBT_FILE
    selected = dict(replay.receipt or replay.debt or {})
    inactive_name = DEBT_FILE if selected_name == RECEIPT_FILE else RECEIPT_FILE
    selected_raw = _json_bytes(selected)
    if desired[selected_name] != selected_raw:
        raise ValueError("prepared active successor differs from pure replay")
    if desired[inactive_name] != _json_bytes(_inactive(selected_name)):
        raise ValueError("prepared inactive successor differs from pure replay")

    run_id = str(config.get("_run_id") or "").strip()
    project_root = Path(str(config.get("project_root") or root.parent))
    upstream_contract, upstream_launch, upstream_digest, upstream_issues = (
        _validated_upstream(root, project_root, config, run_id)
    )
    if upstream_issues:
        raise ValueError("; ".join(upstream_issues))
    if upstream_digest != journal.get("upstream_work_unit_digest"):
        raise ValueError("prepared upstream work-unit binding changed")
    adapter_contract, adapter_launch = _adapter_contract_and_launch(config)
    adapter_input_issues = validate_work_unit_inputs(
        root,
        project_root,
        adapter_contract,
        adapter_launch,
        run_id=run_id,
    )
    if adapter_input_issues:
        raise ValueError("; ".join(adapter_input_issues))
    state = "COMMITTED" if replay.receipt is not None else "COMPLETED_WITH_DEBT"
    expected_status: dict[str, Any] = {
        "schema_version": STATUS_SCHEMA,
        "state": state,
        "transaction_id": journal["transaction_id"],
        "run_id": run_id,
        "upstream_contract_digest": upstream_contract.digest,
        "upstream_launch_digest": upstream_launch.digest,
        "upstream_work_unit_digest": upstream_digest,
        "before_queue_digest": before_digest,
        "after_queue_digest": after_digest,
        "active_successor": selected_name,
        "active_successor_sha256": hashlib.sha256(selected_raw).hexdigest(),
        "ordinary_verification_delivery_complete": replay.receipt is not None,
        "proof_authority": "NONE",
        "terminal_authority": False,
        "issues": [] if replay.receipt is not None else [
            str(selected.get("error_code") or "P0_AF_V2_DELIVERY_DEBT")
        ],
    }
    expected_status["payload_digest"] = _payload_digest(expected_status)
    actual_status = _json_object_from_bytes(
        desired[STATUS_FILE], "prepared queue successor status"
    )
    if actual_status != expected_status:
        raise ValueError("prepared queue status differs from pure replay")


def _commit_prepared(root: Path, journal: dict[str, Any]) -> dict[str, Any]:
    stage_root, desired = _validated_prepared_destination_bytes(root, journal)
    destinations = journal["destinations"]
    for name in journal["publish_order"]:
        record = destinations[name]
        destination = root / name
        if destination.is_file():
            if _bytes_record(_read_bounded_bytes(destination)) == record:
                continue
        staged = stage_root / name
        if _bytes_record(desired[name]) != record:
            raise ValueError(f"staged queue transaction bytes invalid: {name}")
        os.replace(staged, destination)
    committed = dict(journal)
    committed["state"] = "COMMITTED"
    committed["payload_digest"] = _payload_digest(committed)
    _atomic_json(root / JOURNAL_FILE, committed)
    return committed


def _record_adapter_outputs(
    root: Path, project_root: Path, config: Mapping[str, Any], run_id: str
) -> list[str]:
    contract, launch = _adapter_contract_and_launch(config)
    issues = validate_work_unit_inputs(
        root, project_root, contract, launch, run_id=run_id
    )
    record_work_unit_artifacts(
        root,
        project_root,
        contract,
        launch,
        run_id=run_id,
        actor="DRIVER",
        precommit_issues=issues,
    )
    return list(dict.fromkeys(issues + validate_work_unit_artifacts(
        root, project_root, contract, launch, run_id=run_id, actor="DRIVER"
    )))


def _validate_transaction_semantic_replay(
    root: Path,
    *,
    status: Mapping[str, Any],
    journal: Mapping[str, Any],
) -> None:
    """Re-derive the successor from frozen inputs; envelopes cannot self-certify."""

    snapshot_path = root / INPUT_SNAPSHOT_FILE
    before_items = queue_records_from_json(_read_bounded_utf8(snapshot_path))
    if len(before_items) > MAX_QUEUE_RECORDS:
        raise ValueError("queue transaction input snapshot cardinality exceeded")
    if queue_record_set_digest(before_items) != journal.get("before_queue_digest"):
        raise ValueError("queue transaction input snapshot digest mismatch")
    replay = plan_p0af_v2_queue_delivery(root, before_items)
    current_items = _current_queue(root)
    if tuple(replay.queue_items) != current_items:
        raise ValueError("queue transaction output differs from pure adapter replay")
    expected_selected_name = (
        RECEIPT_FILE if replay.receipt is not None else DEBT_FILE
    )
    expected_selected = dict(replay.receipt or replay.debt or {})
    expected_inactive_name = (
        DEBT_FILE if expected_selected_name == RECEIPT_FILE else RECEIPT_FILE
    )
    if _read_json(root / expected_selected_name) != expected_selected:
        raise ValueError("active queue successor differs from pure adapter replay")
    if _read_json(root / expected_inactive_name) != _inactive(expected_selected_name):
        raise ValueError("inactive queue successor differs from deterministic tombstone")
    if status.get("active_successor") != expected_selected_name:
        raise ValueError("queue status selected the wrong semantic successor")
    if status.get("after_queue_digest") != queue_record_set_digest(current_items):
        raise ValueError("queue status output digest differs from semantic replay")


def _validated_committed_transaction_bytes(
    root: Path,
    *,
    run_id: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    status = _read_json(root / STATUS_FILE)
    _validated_payload(status, STATUS_SCHEMA, "queue successor status")
    if set(status) != _COMMITTED_STATUS_FIELDS:
        raise ValueError("queue successor status fields mismatch")
    if (
        status.get("state") not in {"COMMITTED", "COMPLETED_WITH_DEBT"}
        or status.get("transaction_id") is None
        or status.get("run_id") != run_id
        or status.get("terminal_authority") is not False
        or not isinstance(status.get("ordinary_verification_delivery_complete"), bool)
        or not isinstance(status.get("issues"), list)
    ):
        raise ValueError("queue successor status is not an exact terminal record")
    journal = _read_json(root / JOURNAL_FILE)
    _validated_payload(journal, JOURNAL_SCHEMA, "queue transaction journal")
    if set(journal) != _JOURNAL_FIELDS or journal.get("state") != "COMMITTED":
        raise ValueError("queue transaction journal is not exact/committed")
    if (
        journal.get("run_id") != run_id
        or journal.get("terminal_authority") is not False
        or journal.get("transaction_id") != status.get("transaction_id")
    ):
        raise ValueError("queue successor/journal authority mismatch")
    destinations = journal.get("destinations")
    if (
        not isinstance(destinations, dict)
        or journal.get("publish_order") != list(_PUBLISH_ORDER)
        or set(destinations) != set(_PUBLISH_ORDER)
    ):
        raise ValueError("queue transaction destination denominator mismatch")
    for name in _PUBLISH_ORDER:
        record = destinations[name]
        if (
            not isinstance(record, dict)
            or set(record) != {"sha256", "size_bytes"}
            or _bytes_record(_read_bounded_bytes(root / name)) != record
        ):
            raise ValueError(f"committed queue output drift: {name}")
    expected_transaction_id = _journal_transaction_id(
        run_id=run_id,
        upstream_digest=str(journal.get("upstream_work_unit_digest") or ""),
        before_digest=str(journal.get("before_queue_digest") or ""),
        after_digest=str(journal.get("after_queue_digest") or ""),
        destinations={
            name: destinations[name]
            for name in _PUBLISH_ORDER
            if name != STATUS_FILE
        },
    )
    if journal.get("transaction_id") != expected_transaction_id:
        raise ValueError("committed queue transaction identity is not reproducible")
    if (
        status.get("before_queue_digest") != journal.get("before_queue_digest")
        or status.get("after_queue_digest") != journal.get("after_queue_digest")
        or status.get("upstream_work_unit_digest")
        != journal.get("upstream_work_unit_digest")
    ):
        raise ValueError("queue successor/journal denominator mismatch")
    items = _current_queue(root)
    if queue_record_set_digest(items) != status.get("after_queue_digest"):
        raise ValueError("committed queue denominator digest mismatch")
    active = str(status.get("active_successor") or "")
    if active not in {RECEIPT_FILE, DEBT_FILE}:
        raise ValueError("committed active successor is invalid")
    if hashlib.sha256(_read_bounded_bytes(root / active)).hexdigest() != status.get(
        "active_successor_sha256"
    ):
        raise ValueError("committed active successor hash mismatch")
    if (
        (status["state"] == "COMMITTED")
        != bool(status["ordinary_verification_delivery_complete"])
        or (active == RECEIPT_FILE) != (status["state"] == "COMMITTED")
    ):
        raise ValueError("queue successor state/active artifact mismatch")
    _validate_transaction_semantic_replay(
        root, status=status, journal=journal
    )
    return status, journal


def validate_p0af_v2_queue_commit(
    scratchpad: Path, config: Mapping[str, Any]
) -> list[str]:
    root = Path(scratchpad)
    run_id = str(config.get("_run_id") or "").strip()
    project_root = Path(str(config.get("project_root") or root.parent))
    issues: list[str] = []
    if not run_id:
        return ["P0-AF v2 queue commit has no run_id"]
    try:
        status, _journal = _validated_committed_transaction_bytes(
            root, run_id=run_id
        )
        _upstream_contract, _upstream_launch, upstream_digest, upstream_issues = (
            _validated_upstream(root, project_root, config, run_id)
        )
        issues.extend(upstream_issues)
        if upstream_digest != status.get("upstream_work_unit_digest"):
            issues.append("committed upstream work-unit binding changed")
        if (
            status.get("upstream_contract_digest") != _upstream_contract.digest
            or status.get("upstream_launch_digest") != _upstream_launch.digest
        ):
            issues.append("committed upstream contract/launch binding changed")
        contract, launch = _adapter_contract_and_launch(config)
        issues.extend(validate_work_unit_inputs(
            root, project_root, contract, launch, run_id=run_id
        ))
        issues.extend(validate_work_unit_artifacts(
            root, project_root, contract, launch, run_id=run_id, actor="DRIVER"
        ))
    except Exception as exc:
        issues.append(
            f"P0-AF v2 committed queue invalid: {type(exc).__name__}: {exc}"
        )
    return list(dict.fromkeys(issues))


def authorized_p0af_v2_work_item_ids(
    scratchpad: Path, config: Mapping[str, Any]
) -> tuple[str, ...]:
    """Return only receipt-authenticated delivered IDs from a current commit."""

    root = Path(scratchpad)
    issues = validate_p0af_v2_queue_commit(root, config)
    if issues:
        raise ValueError("; ".join(issues))
    status = _read_json(root / STATUS_FILE)
    if status.get("state") != "COMMITTED" or status.get("active_successor") != RECEIPT_FILE:
        return ()
    receipt = _read_json(root / RECEIPT_FILE)
    _validated_payload(receipt, RECEIPT_SCHEMA, "queue delivery receipt")
    delivered = receipt.get("delivered_work_item_ids")
    if (
        not isinstance(delivered, list)
        or len(delivered) != len(set(delivered))
        or any(not isinstance(value, str) or not value for value in delivered)
    ):
        raise ValueError("queue delivery receipt identity denominator malformed")
    active = {item.work_item_id for item in _current_queue(root)}
    if any(value not in active for value in delivered):
        raise ValueError("queue delivery receipt names a non-active work item")
    return tuple(delivered)


def _delivery_debt_issues(
    root: Path, status: Mapping[str, Any]
) -> tuple[str, ...]:
    if status.get("state") != "COMPLETED_WITH_DEBT":
        return ()
    debt = _read_json(root / DEBT_FILE)
    _validated_payload(debt, DEBT_SCHEMA, "queue delivery debt")
    code = str(debt.get("error_code") or "P0_AF_V2_DELIVERY_DEBT")[:120]
    detail = str(debt.get("error") or "ordinary verification delivery incomplete")[
        :500
    ]
    return (f"P0-AF v2 delivery debt: {code}: {detail}",)


def p0af_v2_resume_contract_issues(
    scratchpad: Path, config: Mapping[str, Any]
) -> list[str]:
    """Side-effect-free resume contract for a typed P1-M queue route.

    A clean authenticated producer is a no-op.  Once that producer nominates
    ordinary verification work, however, a completed queue phase is resumable
    only from the exact current committed successor and receipt denominator.
    """

    root = Path(scratchpad)
    if not (root / ROUTE_DEBT_FILE).is_file():
        return []
    run_id = str(config.get("_run_id") or "").strip()
    project_root = Path(str(config.get("project_root") or root.parent))
    if not run_id:
        return ["P1-M resume authority has no run_id"]
    _contract, _launch, _digest_value, upstream_issues = _validated_upstream(
        root, project_root, config, run_id
    )
    if upstream_issues:
        return [
            "P1-M authenticated producer invalid on resume: " + issue
            for issue in upstream_issues
        ]

    # Reproduce the producer's requested denominator independently of the
    # current queue and any successor envelope.  Empty foreign input is enough
    # to validate all candidate/work/route bindings and obtain exact ready IDs.
    expected = plan_p0af_v2_queue_delivery(root, ())
    if expected.receipt is None:
        code = str((expected.debt or {}).get("error_code") or "UNKNOWN")
        return [f"P1-M route cannot be reproduced on resume: {code}"]
    expected_ids = tuple(expected.receipt.get("delivered_work_item_ids") or ())
    required = expected.receipt.get("ordinary_verification_required")
    if required is not bool(expected_ids):
        return ["P1-M route has inconsistent ordinary-verification authority"]
    if not required:
        return []

    commit_issues = validate_p0af_v2_queue_commit(root, config)
    if commit_issues:
        return [
            "P0-AF v2 resume successor invalid: " + issue
            for issue in commit_issues
        ]
    status = _read_json(root / STATUS_FILE)
    if status.get("state") == "COMPLETED_WITH_DEBT":
        # A deterministic collision/ownership debt is a durable explicit
        # disposition.  Rewinding the same immutable denominator forever would
        # not recover it; ordinary work may resume while the debt stays visible.
        return []
    try:
        delivered_ids = authorized_p0af_v2_work_item_ids(root, config)
    except Exception as exc:
        return [
            "P0-AF v2 resume receipt unavailable: "
            f"{type(exc).__name__}: {exc}"
        ]
    if delivered_ids != expected_ids:
        return [
            "P0-AF v2 resume receipt does not contain the exact P1-M ready "
            "identity denominator"
        ]
    return []


def p0af_v2_runtime_state_present(
    scratchpad: Path, config: Mapping[str, Any]
) -> bool:
    """Return whether a prior adapter attempt owns durable runtime state."""

    root = Path(scratchpad)
    if any(
        (root / name).exists()
        for name in (*_ADAPTER_OUTPUTS, INPUT_SNAPSHOT_FILE)
    ) or (root / "_p0af_v2_queue_transaction").exists():
        return True
    try:
        contract, _launch = _adapter_contract_and_launch(config)
        units = read_artifact_ledger(root).get("work_units", {})
        return isinstance(units, Mapping) and contract.key in units
    except (ArtifactLedgerError, OSError, TypeError, ValueError):
        return (root / "_artifact_state.json").is_file()


def run_p0af_v2_queue_delivery(
    scratchpad: Path, config: Mapping[str, Any]
) -> P0AFV2QueueRuntimeOutcome:
    root = Path(scratchpad)
    project_root = Path(str(config.get("project_root") or root.parent))
    run_id = str(config.get("_run_id") or "").strip()
    if not run_id:
        return _precondition_debt(root, ["P0-AF v2 queue adapter has no run_id"])

    # A committed journal is immutable authority.  Never overwrite a malformed
    # or tampered status merely to make the next invocation green.
    if (root / JOURNAL_FILE).is_file():
        try:
            journal = _read_json(root / JOURNAL_FILE)
            _validated_payload(journal, JOURNAL_SCHEMA, "queue transaction journal")
            if journal.get("state") == "PREPARED":
                _upstream, _launch, current_upstream, upstream_issues = (
                    _validated_upstream(root, project_root, config, run_id)
                )
                if upstream_issues or current_upstream != journal.get(
                    "upstream_work_unit_digest"
                ):
                    raise P0AFV2QueueRuntimeError(
                        "prepared queue transaction upstream authority changed"
                    )
                try:
                    _validate_prepared_transaction_semantics(
                        root, journal, config
                    )
                except (OSError, TypeError, ValueError, UnicodeError) as exc:
                    return P0AFV2QueueRuntimeOutcome(
                        False,
                        {},
                        (
                            "P0-AF v2 prepared transaction semantic validation "
                            f"failed: {type(exc).__name__}: {exc}",
                        ),
                    )
                _commit_prepared(root, journal)
                output_issues = _record_adapter_outputs(
                    root, project_root, config, run_id
                )
                if output_issues:
                    raise P0AFV2QueueRuntimeError("; ".join(output_issues))
            elif journal.get("state") == "COMMITTED":
                # Receipt-last bytes may be durable while the process crashes
                # immediately before the neutral ledger records DRIVER
                # outputs.  Repair only that missing-output case: the exact
                # committed transaction, current upstream authority, and the
                # already-recorded adapter input denominator must all validate.
                committed_status, _ = _validated_committed_transaction_bytes(
                    root, run_id=run_id
                )
                upstream_contract, upstream_launch, current_upstream, upstream_issues = (
                    _validated_upstream(root, project_root, config, run_id)
                )
                if (
                    upstream_issues
                    or current_upstream
                    != committed_status.get("upstream_work_unit_digest")
                    or upstream_contract.digest
                    != committed_status.get("upstream_contract_digest")
                    or upstream_launch.digest
                    != committed_status.get("upstream_launch_digest")
                ):
                    raise ValueError(
                        "committed queue transaction upstream authority changed"
                    )
                adapter_contract, adapter_launch = _adapter_contract_and_launch(config)
                adapter_input_issues = validate_work_unit_inputs(
                    root, project_root, adapter_contract, adapter_launch,
                    run_id=run_id,
                )
                if adapter_input_issues:
                    raise ValueError("; ".join(adapter_input_issues))
                ledger = read_artifact_ledger(root)
                adapter_row = ledger.get("work_units", {}).get(adapter_contract.key)
                if not isinstance(adapter_row, dict):
                    raise ValueError("adapter input ledger row is absent")
                output_bindings = adapter_row.get("artifacts")
                if output_bindings == {}:
                    output_issues = _record_adapter_outputs(
                        root, project_root, config, run_id
                    )
                    if output_issues:
                        raise ValueError("; ".join(output_issues))
                elif not isinstance(output_bindings, dict):
                    raise ValueError("adapter output ledger denominator is malformed")
            commit_issues = validate_p0af_v2_queue_commit(root, config)
            if commit_issues:
                return P0AFV2QueueRuntimeOutcome(
                    False,
                    _read_json(root / STATUS_FILE) if (root / STATUS_FILE).is_file() else {},
                    tuple(commit_issues),
                )
            status = _read_json(root / STATUS_FILE)
            return P0AFV2QueueRuntimeOutcome(
                status.get("state") == "COMMITTED",
                status,
                _delivery_debt_issues(root, status),
            )
        except P0AFV2QueueRuntimeError:
            raise
        except Exception as exc:
            if isinstance(locals().get("journal"), Mapping) and journal.get(
                "state"
            ) == "PREPARED":
                raise P0AFV2QueueRuntimeError(
                    "P0-AF v2 prepared transaction recovery failed: "
                    f"{type(exc).__name__}: {exc}"
                ) from exc
            return P0AFV2QueueRuntimeOutcome(
                False,
                {},
                (f"P0-AF v2 transaction validation failed: {type(exc).__name__}: {exc}",),
            )

    upstream_contract, upstream_launch, upstream_digest, upstream_issues = (
        _validated_upstream(root, project_root, config, run_id)
    )
    if upstream_issues:
        return _precondition_debt(root, upstream_issues)

    try:
        current = _current_queue(root)
        if len(current) > MAX_QUEUE_RECORDS:
            return _precondition_debt(
                root, ["P0-AF v2 queue input cardinality exceeded"]
            )
        snapshot_raw = queue_records_to_json(current).encode("utf-8") + b"\n"
        if len(snapshot_raw) > MAX_CONTROL_BYTES:
            return _precondition_debt(
                root, ["P0-AF v2 queue input snapshot byte budget exceeded"]
            )
        snapshot_path = root / INPUT_SNAPSHOT_FILE
        if (
            snapshot_path.is_file()
            and _read_bounded_bytes(snapshot_path) != snapshot_raw
        ):
            return _precondition_debt(
                root, ["P0-AF v2 queue input snapshot drifted before commit"]
            )
        _atomic_bytes(snapshot_path, snapshot_raw)
        adapter_contract, adapter_launch = _adapter_contract_and_launch(config)
        record_work_unit_inputs(
            root, project_root, adapter_contract, adapter_launch, run_id=run_id
        )
        input_issues = validate_work_unit_inputs(
            root, project_root, adapter_contract, adapter_launch, run_id=run_id
        )
        if input_issues:
            return _precondition_debt(root, input_issues)

        delivery = plan_p0af_v2_queue_delivery(root, current)
        after = tuple(delivery.queue_items)
        before_digest = queue_record_set_digest(current)
        after_digest = queue_record_set_digest(after)
        selected_name = RECEIPT_FILE if delivery.receipt is not None else DEBT_FILE
        selected = dict(delivery.receipt or delivery.debt or {})
        selected_schema = RECEIPT_SCHEMA if delivery.receipt is not None else DEBT_SCHEMA
        _validated_payload(selected, selected_schema, "adapter successor")
        inactive_name = DEBT_FILE if selected_name == RECEIPT_FILE else RECEIPT_FILE
        inactive = _inactive(selected_name)

        seed = _digest({
            "run_id": run_id,
            "upstream_work_unit_digest": upstream_digest,
            "before_queue_digest": before_digest,
            "after_queue_digest": after_digest,
            "selected_successor": selected_name,
            "selected_payload_digest": selected["payload_digest"],
        })
        stage_relative = f"_p0af_v2_queue_transaction/{seed}"
        stage = root / stage_relative
        _stage_queue(root, stage, after)
        _atomic_json(stage / selected_name, selected)
        _atomic_json(stage / inactive_name, inactive)

        # The committed successor is published last and binds the exact queue
        # denominator plus the authenticated upstream ledger row.
        staged_selected_raw = (stage / selected_name).read_bytes()
        status: dict[str, Any] = {
            "schema_version": STATUS_SCHEMA,
            "state": "COMMITTED" if delivery.receipt is not None else "COMPLETED_WITH_DEBT",
            "transaction_id": "",  # filled after destination hashes are known
            "run_id": run_id,
            "upstream_contract_digest": upstream_contract.digest,
            "upstream_launch_digest": upstream_launch.digest,
            "upstream_work_unit_digest": upstream_digest,
            "before_queue_digest": before_digest,
            "after_queue_digest": after_digest,
            "active_successor": selected_name,
            "active_successor_sha256": hashlib.sha256(staged_selected_raw).hexdigest(),
            "ordinary_verification_delivery_complete": delivery.receipt is not None,
            "proof_authority": "NONE",
            "terminal_authority": False,
            "issues": [] if delivery.receipt is not None else [str(selected.get("error_code") or "P0_AF_V2_DELIVERY_DEBT")],
        }
        # First collect all non-status bytes.  Transaction identity includes
        # the status bytes, so compute a fixed point with identity excluded
        # from its own digest and then render the final status once.
        destination_records: dict[str, dict[str, Any]] = {}
        for name in _PUBLISH_ORDER:
            if name == STATUS_FILE:
                continue
            destination_records[name] = _bytes_record((stage / name).read_bytes())
        transaction_id = _journal_transaction_id(
            run_id=run_id,
            upstream_digest=upstream_digest,
            before_digest=before_digest,
            after_digest=after_digest,
            destinations=destination_records,
        )
        status["transaction_id"] = transaction_id
        status["payload_digest"] = _payload_digest(status)
        _atomic_json(stage / STATUS_FILE, status)
        destination_records[STATUS_FILE] = _bytes_record(
            (stage / STATUS_FILE).read_bytes()
        )
        # Preserve the declared publish order independently of sorted JSON.
        destinations = {
            name: destination_records[name] for name in _PUBLISH_ORDER
        }
        journal: dict[str, Any] = {
            "schema_version": JOURNAL_SCHEMA,
            "state": "PREPARED",
            "transaction_id": transaction_id,
            "run_id": run_id,
            "upstream_work_unit_digest": upstream_digest,
            "before_queue_digest": before_digest,
            "after_queue_digest": after_digest,
            "stage_directory": stage_relative,
            "destinations": destinations,
            "publish_order": list(_PUBLISH_ORDER),
            "proof_authority": "NONE",
            "terminal_authority": False,
        }
        journal["payload_digest"] = _payload_digest(journal)
        _atomic_json(root / JOURNAL_FILE, journal)
        _validate_prepared_transaction_semantics(root, journal, config)
        _commit_prepared(root, journal)
        output_issues = _record_adapter_outputs(root, project_root, config, run_id)
        if output_issues:
            return P0AFV2QueueRuntimeOutcome(False, status, tuple(output_issues))
        final_issues = validate_p0af_v2_queue_commit(root, config)
        visible_issues = tuple(final_issues)
        if not final_issues:
            visible_issues = _delivery_debt_issues(root, status)
        return P0AFV2QueueRuntimeOutcome(
            bool(delivery.receipt) and not final_issues,
            status,
            visible_issues,
        )
    except P0AFV2QueueRuntimeError:
        raise
    except OSError as exc:
        # A replacement failure after PREPARED is a deterministic resume point;
        # do not publish a competing debt/status over the partial transaction.
        if (root / JOURNAL_FILE).is_file():
            raise P0AFV2QueueRuntimeError(
                f"P0-AF v2 queue publish interrupted: {exc}"
            ) from exc
        return _precondition_debt(root, [f"P0-AF v2 queue I/O debt: {exc}"])
    except (ArtifactLedgerError, TypeError, ValueError, UnicodeError) as exc:
        if (root / JOURNAL_FILE).is_file():
            raise P0AFV2QueueRuntimeError(
                "P0-AF v2 prepared/committed transaction requires exact recovery: "
                f"{type(exc).__name__}: {exc}"
            ) from exc
        return _precondition_debt(
            root, [f"P0-AF v2 queue validation debt: {type(exc).__name__}: {exc}"]
        )


__all__ = [
    "DEBT_FILE",
    "INPUT_SNAPSHOT_FILE",
    "JOURNAL_FILE",
    "P0AFV2QueueRuntimeError",
    "P0AFV2QueueRuntimeOutcome",
    "p0af_v2_resume_contract_issues",
    "p0af_v2_runtime_state_present",
    "RECEIPT_FILE",
    "STATUS_FILE",
    "authorized_p0af_v2_work_item_ids",
    "p0af_v2_upstream_contract_and_launch",
    "run_p0af_v2_queue_delivery",
    "validate_p0af_v2_queue_commit",
]
