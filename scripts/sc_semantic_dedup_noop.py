"""Authenticated conservative SC semantic-dedup passthrough.

This transaction records only that semantic review authority was unavailable.
It preserves every inventory byte and never asserts that duplicates are absent.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
from typing import Any, Callable, Mapping

from artifact_ledger import (
    ArtifactLedgerError,
    read_artifact_ledger,
    record_work_unit_artifacts,
    record_work_unit_inputs,
    semantic_input_producer_authority_issues,
    validate_work_unit_artifacts,
    validate_work_unit_inputs,
)
from phase_io_contracts import LaunchSpec, resolve_phase_io_contract


OUTPUT_NAMES = ("dedup_decisions.md", "findings_inventory_deduped.md")
FAULT_POINTS = (
    "after_arm",
    "after_output_1",
    "after_output_2",
    "before_commit",
    "after_commit",
)

_DECISIONS = (
    "# Semantic Dedup Decisions\n\n"
    "**Status**: PASSTHROUGH\n\n"
    "**Signal Authority**: UNAVAILABLE\n\n"
    "**Semantic Review**: NOT PERFORMED\n\n"
    "No absence-of-duplicates conclusion is asserted. No semantic merge, drop, "
    "or alias decision was applied. Every upstream finding remains active.\n"
).encode("utf-8")


def _digest(value: Mapping[str, Any]) -> str:
    raw = json.dumps(
        dict(value), sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _invocation_authority(reason: str, outputs: Mapping[str, Any]) -> dict[str, Any]:
    reason_raw = reason.encode("utf-8")
    unsigned: dict[str, Any] = {
        "schema": "plamen.sc-semantic-dedup-noop-invocation.v1",
        "reason_sha256": hashlib.sha256(reason_raw).hexdigest(),
        "reason_size": len(reason_raw),
        "expected_outputs": dict(outputs),
    }
    return {**unsigned, "authority_sha256": _digest(unsigned)}


def _read_inventory(path: Path) -> bytes:
    try:
        row = path.lstat()
    except OSError as exc:
        raise ArtifactLedgerError(
            f"SC semantic-dedup passthrough inventory is unavailable: {exc}"
        ) from exc
    if not stat.S_ISREG(row.st_mode) or path.is_symlink():
        raise ArtifactLedgerError(
            "SC semantic-dedup passthrough inventory is not a regular file"
        )
    try:
        raw = path.read_bytes()
        after = path.lstat()
    except OSError as exc:
        raise ArtifactLedgerError(
            f"SC semantic-dedup passthrough inventory cannot be read: {exc}"
        ) from exc
    before_identity = (row.st_dev, row.st_ino, row.st_size, row.st_mtime_ns)
    after_identity = (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    )
    if before_identity != after_identity or not stat.S_ISREG(after.st_mode):
        raise ArtifactLedgerError(
            "SC semantic-dedup passthrough inventory changed while read"
        )
    if not raw:
        raise ArtifactLedgerError(
            "SC semantic-dedup passthrough inventory is empty"
        )
    return raw


def _atomic_bytes(path: Path, raw: bytes) -> None:
    try:
        if path.is_file() and path.read_bytes() == raw:
            return
    except OSError:
        pass
    descriptor = -1
    temporary = ""
    try:
        descriptor, temporary = tempfile.mkstemp(
            prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
        )
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = -1
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        temporary = ""
        if os.name != "nt":
            directory_fd = os.open(
                os.fspath(path.parent), os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
            )
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
    except OSError as exc:
        raise ArtifactLedgerError(
            f"SC semantic-dedup passthrough publication failed: {exc}"
        ) from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary:
            try:
                os.unlink(temporary)
            except OSError:
                pass


def _contract_and_launch(config: Mapping[str, Any]):
    contract = resolve_phase_io_contract(
        pipeline="sc",
        mode=str(config.get("mode") or "core"),
        ecosystem=str(config.get("language") or config.get("ecosystem") or "evm"),
        backend=str(config.get("cli_backend") or config.get("backend") or "claude"),
        phase="sc_semantic_dedup",
        work_unit_id="noop_passthrough",
        exact_inputs=("findings_inventory.md",),
        exact_outputs=OUTPUT_NAMES,
        exact_writer="DRIVER",
    )
    launch = LaunchSpec(
        work_unit_key=contract.key,
        pipeline=contract.pipeline,
        mode=contract.mode,
        ecosystem=contract.ecosystem,
        backend=contract.backend,
        model="driver",
        timeout_s=60,
        exec_mode="python",
        tool_policy=(),
    )
    return contract, launch


def _require_inventory_producer(root: Path, contract, run_id: str, inventory: bytes) -> None:
    ledger = read_artifact_ledger(root)
    unit = ledger.get("work_units", {}).get(contract.key)
    inputs = unit.get("input_bindings") if isinstance(unit, Mapping) else None
    record = (
        inputs.get("scratchpad:findings_inventory.md")
        if isinstance(inputs, Mapping)
        else None
    )
    if not isinstance(record, Mapping):
        raise ArtifactLedgerError(
            "SC semantic-dedup passthrough inventory input binding is absent"
        )
    if record.get("sha256") != hashlib.sha256(inventory).hexdigest() or record.get("size") != len(inventory):
        raise ArtifactLedgerError(
            "SC semantic-dedup passthrough inventory bytes differ from bound input"
        )
    issues = semantic_input_producer_authority_issues(
        ledger, record, run_id=run_id
    )
    if issues:
        raise ArtifactLedgerError(
            "SC semantic-dedup passthrough inventory producer is invalid: "
            + "; ".join(issues)
        )


def run_sc_semantic_dedup_noop(
    *,
    scratchpad: Path,
    project_root: Path,
    config: Mapping[str, Any],
    run_id: str,
    reason: str,
    fault_hook: Callable[[str], None] | None = None,
) -> list[str]:
    """Publish and replay one exact preserve-all SC no-op transaction."""

    root = Path(scratchpad)
    project = Path(project_root)
    run = str(run_id or "").strip()
    why = str(reason or "").strip()
    if not run or not why:
        raise ArtifactLedgerError(
            "SC semantic-dedup passthrough run/reason is absent"
        )
    configured_pipeline = str(config.get("pipeline") or "sc").strip().lower()
    configured_run = str(config.get("_run_id") or "").strip()
    if configured_pipeline != "sc":
        raise ArtifactLedgerError(
            "SC semantic-dedup passthrough received a non-SC configuration"
        )
    if configured_run and configured_run != run:
        raise ArtifactLedgerError(
            "SC semantic-dedup passthrough run differs from configuration"
        )
    inventory = _read_inventory(root / "findings_inventory.md")
    outputs = {
        "scratchpad:dedup_decisions.md": _DECISIONS,
        "scratchpad:findings_inventory_deduped.md": inventory,
    }
    expected_records = {
        identity: {"sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw)}
        for identity, raw in outputs.items()
    }
    contract, launch = _contract_and_launch(config)
    invocation = _invocation_authority(why, expected_records)
    ledger = read_artifact_ledger(root)
    prior = ledger.get("work_units", {}).get(contract.key)

    if not isinstance(prior, Mapping):
        bindings = ledger.get("artifact_bindings", {})
        collisions = [
            identity
            for identity in outputs
            if os.path.lexists(root / identity.split(":", 1)[1])
            or isinstance(bindings.get(identity), Mapping)
        ]
        if collisions:
            raise ArtifactLedgerError(
                "SC semantic-dedup passthrough refuses pre-existing output "
                "authority: " + ", ".join(sorted(collisions))
            )
        record_work_unit_inputs(
            root,
            project,
            contract,
            launch,
            run_id=run,
            preexecution_authority=invocation,
        )
    else:
        if prior.get("run_id") != run:
            raise ArtifactLedgerError(
                "SC semantic-dedup passthrough is bound to another run"
            )
        if prior.get("contract_digest") != contract.digest or prior.get("launch_digest") != launch.digest:
            raise ArtifactLedgerError(
                "SC semantic-dedup passthrough contract/launch changed"
            )
    input_issues = validate_work_unit_inputs(
        root,
        project,
        contract,
        launch,
        run_id=run,
        preexecution_authority=invocation,
    )
    if input_issues:
        raise ArtifactLedgerError(
            "SC semantic-dedup passthrough input replay failed: "
            + "; ".join(input_issues)
        )
    _require_inventory_producer(root, contract, run, inventory)

    ledger = read_artifact_ledger(root)
    unit = ledger.get("work_units", {}).get(contract.key)
    if (
        isinstance(unit, Mapping)
        and unit.get("semantic_status") == "ACTIVE"
        and unit.get("execution_state") == "OUTPUT_COMMITTED"
    ):
        output_issues = validate_work_unit_artifacts(
            root,
            project,
            contract,
            launch,
            run_id=run,
            actor="DRIVER",
            preexecution_authority=invocation,
        )
        if output_issues:
            raise ArtifactLedgerError(
                "SC semantic-dedup passthrough output replay failed: "
                + "; ".join(output_issues)
            )
        return list(OUTPUT_NAMES)

    if not (
        isinstance(unit, Mapping)
        and unit.get("semantic_status") == "INPUTS_BOUND"
        and unit.get("execution_state") == "INPUTS_BOUND_PREEXECUTION"
        and unit.get("artifacts") == {}
    ):
        raise ArtifactLedgerError("SC semantic-dedup passthrough is not an armed transaction")
    prestates = unit.get("output_prestates", {})
    if set(prestates) != set(outputs) or any(
        not isinstance(prestates[identity], Mapping)
        or prestates[identity].get("status") != "ABSENT"
        for identity in outputs
    ):
        raise ArtifactLedgerError("SC semantic-dedup passthrough requires exact absent output prestates")
    # A new-output transaction has no historical producer bundle to supersede.
    # Recover only the original ABSENT state or the exact input-derived target;
    # never adopt third-state bytes or rewrite a committed damaged output.
    for identity, raw in outputs.items():
        path = root / identity.split(":", 1)[1]
        if os.path.lexists(path) and (
            path.is_symlink() or not path.is_file() or path.read_bytes() != raw
        ):
            raise ArtifactLedgerError("SC semantic-dedup passthrough has arbitrary partial output bytes")
    hook = fault_hook or (lambda _point: None)
    hook("after_arm")
    for ordinal, (identity, raw) in enumerate(outputs.items(), start=1):
        path = root / identity.split(":", 1)[1]
        if not path.exists():
            _atomic_bytes(root / identity.split(":", 1)[1], raw)
        hook(f"after_output_{ordinal}")
    hook("before_commit")
    record_work_unit_artifacts(
        root,
        project,
        contract,
        launch,
        run_id=run,
        actor="DRIVER",
        expected_output_records=expected_records,
    )
    output_issues = validate_work_unit_artifacts(
        root,
        project,
        contract,
        launch,
        run_id=run,
        actor="DRIVER",
        preexecution_authority=invocation,
    )
    if output_issues:
        raise ArtifactLedgerError(
            "SC semantic-dedup passthrough commit replay failed: "
            + "; ".join(output_issues)
        )
    hook("after_commit")
    return list(OUTPUT_NAMES)


__all__ = ["FAULT_POINTS", "OUTPUT_NAMES", "run_sc_semantic_dedup_noop"]
