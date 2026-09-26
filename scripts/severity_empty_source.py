"""Authenticated zero-row severity source for an exact empty SC or L1 queue."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Callable, Mapping

import rooted_path_io as rooted_io
from artifact_ledger import (
    ArtifactLedgerError,
    read_artifact_ledger,
    record_work_unit_artifacts,
    record_work_unit_inputs,
    semantic_input_prebind_producer_authority_issues,
    semantic_input_producer_authority_issues,
    validate_work_unit_artifacts,
    validate_work_unit_inputs,
)
from phase_io_contracts import (
    LaunchSpec,
    canonical_work_unit_key,
    resolve_phase_io_contract,
)
from queue_work_items import (
    QueueWorkPlan,
    queue_records_from_json,
)
from plamen_parsers import render_verification_queue_work_item_markdown
from severity_decision_ledger import build_severity_decision_ledger


OUTPUT_NAME = "severity_decision_ledger.shadow.json"
INITIAL_SNAPSHOT_NAME = (
    "_severity_adjudication_inputs/source_ledger.initial.json"
)
OUTPUT_NAMES = (OUTPUT_NAME, INITIAL_SNAPSHOT_NAME)
INPUT_NAMES = (
    "verification_queue.md",
    "verification_queue.work_items.json",
    "verification_queue.work_plan.json",
)
FAULT_POINTS = (
    "after_arm",
    "after_output_1",
    "after_output_2",
    "before_commit",
    "after_commit",
)

_MAX_INPUT_BYTES = 32 * 1024 * 1024


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical_digest(value: Mapping[str, Any]) -> str:
    return _sha(json.dumps(
        dict(value),
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8"))


def _ledger_bytes(run_id: str) -> bytes:
    payload = build_severity_decision_ledger(run_id, ())
    return (json.dumps(
        payload,
        indent=2,
        ensure_ascii=False,
        sort_keys=True,
    ) + "\n").encode("utf-8")


def _read_inputs(root: Path) -> dict[str, bytes]:
    try:
        return {
            relative: rooted_io.read_bytes(
                root / relative,
                label=f"empty severity source input {relative}",
                require_single_link=True,
                max_bytes=_MAX_INPUT_BYTES,
            )
            for relative in INPUT_NAMES
        }
    except (OSError, rooted_io.RootedPathIOError) as exc:
        raise ArtifactLedgerError(
            f"empty severity source cannot read required queue input: {exc}"
        ) from exc


def _validate_empty_queue(raw: Mapping[str, bytes]) -> tuple[str, str]:
    try:
        markdown_raw = raw["verification_queue.md"]
        typed_items = queue_records_from_json(
            raw["verification_queue.work_items.json"].decode(
                "utf-8", errors="strict"
            )
        )
        plan = QueueWorkPlan.from_json(
            raw["verification_queue.work_plan.json"].decode(
                "utf-8", errors="strict"
            )
        )
        plan.validate_against(typed_items)
    except (KeyError, TypeError, ValueError, UnicodeError) as exc:
        raise ArtifactLedgerError(
            "empty severity source queue denominator is invalid: "
            f"{type(exc).__name__}: {exc}"
        ) from exc
    # T9 publishes the full human-readable queue document, not the lossless
    # table-only codec. Typed records and their plan retain the complete
    # denominator; require exact bytes from the same production projection.
    if markdown_raw != (
        render_verification_queue_work_item_markdown(typed_items).encode("utf-8")
    ):
        raise ArtifactLedgerError(
            "empty severity source Markdown is not the canonical projection"
        )
    if typed_items or plan.ordered_work_item_ids:
        return "NONEMPTY", plan.digest
    return "EMPTY", plan.digest


def _contract_and_launch(config: Mapping[str, Any]):
    pipeline = str(config.get("pipeline") or "").strip().lower()
    contract = resolve_phase_io_contract(
        pipeline=pipeline,
        mode=str(config.get("mode") or "core"),
        ecosystem=str(
            config.get("language") or config.get("ecosystem") or "evm"
        ),
        backend=str(
            config.get("cli_backend") or config.get("backend") or "claude"
        ),
        phase="severity_adjudication_shadow",
        work_unit_id="source_empty",
        exact_inputs=INPUT_NAMES,
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


def _reject_stale_decisions(root: Path) -> None:
    checked = rooted_io.checked_directory(
        root, label="empty severity source scratchpad"
    )
    with rooted_io.scandir(checked) as entries:
        stale = sorted(
            entry.name
            for entry in entries
            if entry.name.casefold().startswith("verify_")
            and entry.name.casefold().endswith(".severity_decision.json")
        )
    if stale:
        raise ArtifactLedgerError(
            "empty severity source refuses stale per-candidate decisions: "
            + ", ".join(stale[:16])
        )


def _require_bound_queue_producer(
    root: Path,
    *,
    contract: Any,
    config: Mapping[str, Any],
    run_id: str,
    raw: Mapping[str, bytes],
) -> None:
    ledger = read_artifact_ledger(root)
    unit = ledger.get("work_units", {}).get(contract.key)
    bindings = unit.get("input_bindings") if isinstance(unit, Mapping) else None
    if not isinstance(bindings, Mapping) or set(bindings) != {
        f"scratchpad:{relative}" for relative in INPUT_NAMES
    }:
        raise ArtifactLedgerError(
            "empty severity source input binding denominator differs"
        )
    expected_owner = _expected_queue_owner(config)
    for relative in INPUT_NAMES:
        identity = f"scratchpad:{relative}"
        record = bindings.get(identity)
        if not isinstance(record, Mapping):
            raise ArtifactLedgerError(
                f"empty severity source input binding is absent: {identity}"
            )
        if (
            record.get("sha256") != _sha(raw[relative])
            or record.get("size") != len(raw[relative])
            or record.get("producer_work_unit_key") != expected_owner
            or record.get("producer_writer") != "DRIVER"
            or record.get("producer_run_id") != run_id
        ):
            raise ArtifactLedgerError(
                f"empty severity source queue producer mismatch: {identity}"
            )
        issues = semantic_input_producer_authority_issues(
            ledger, record, run_id=run_id
        )
        if issues:
            raise ArtifactLedgerError(
                f"empty severity source queue producer invalid for {identity}: "
                + "; ".join(issues)
            )


def _expected_queue_owner(config: Mapping[str, Any]) -> str:
    pipeline = str(config.get("pipeline") or "").strip().lower()
    return canonical_work_unit_key(
        pipeline,
        str(config.get("mode") or "core"),
        str(config.get("language") or config.get("ecosystem") or "evm"),
        str(config.get("cli_backend") or config.get("backend") or "claude"),
        "sc_verify_queue" if pipeline == "sc" else "verify_queue",
        "t9.live_receipt_last_cas",
    )


def _require_current_queue_producer(
    root: Path,
    project: Path,
    *,
    config: Mapping[str, Any],
    run_id: str,
    raw: Mapping[str, bytes],
) -> None:
    identities = tuple(f"scratchpad:{name}" for name in INPUT_NAMES)
    issues = semantic_input_prebind_producer_authority_issues(
        root, project, identities, run_id=run_id
    )
    if issues:
        raise ArtifactLedgerError(
            "empty severity source queue prebind authority is invalid: "
            + "; ".join(issues)
        )
    ledger = read_artifact_ledger(root)
    bindings = ledger.get("artifact_bindings")
    expected_owner = _expected_queue_owner(config)
    if not isinstance(bindings, Mapping):
        raise ArtifactLedgerError(
            "empty severity source queue binding table is absent"
        )
    for relative in INPUT_NAMES:
        identity = f"scratchpad:{relative}"
        binding = bindings.get(identity)
        if not isinstance(binding, Mapping) or (
            binding.get("owner_key") != expected_owner
            or binding.get("writer") != "DRIVER"
            or binding.get("run_id") != run_id
            or binding.get("sha256") != _sha(raw[relative])
            or binding.get("size") != len(raw[relative])
        ):
            raise ArtifactLedgerError(
                f"empty severity source has a false queue producer: {identity}"
            )


def _revalidate_denominator(
    root: Path,
    *,
    expected_raw: Mapping[str, bytes],
    expected_plan_digest: str,
) -> None:
    current = _read_inputs(root)
    if current != expected_raw:
        raise ArtifactLedgerError("empty severity source inputs changed after arm")
    state, plan_digest = _validate_empty_queue(current)
    if state != "EMPTY" or plan_digest != expected_plan_digest:
        raise ArtifactLedgerError("empty severity source queue changed after arm")
    if _read_inputs(root) != current:
        raise ArtifactLedgerError(
            "empty severity source inputs changed during semantic replay"
        )
    _reject_stale_decisions(root)


def run_empty_severity_source(
    *,
    scratchpad: Path,
    project_root: Path,
    config: Mapping[str, Any],
    fault_hook: Callable[[str], None] | None = None,
) -> bool:
    """Publish or replay the severity ledger for a typed empty SC or L1 queue."""

    root = rooted_io.checked_directory(
        scratchpad, label="empty severity source scratchpad"
    )
    project = rooted_io.checked_directory(
        project_root, label="empty severity source project"
    )
    raw_run_id = config.get("_run_id")
    pipeline = str(config.get("pipeline") or "").strip().lower()
    if (
        pipeline not in {"sc", "l1"}
        or not isinstance(raw_run_id, str)
        or not raw_run_id
        or raw_run_id != raw_run_id.strip()
    ):
        raise ArtifactLedgerError(
            "empty severity source requires an exact SC or L1 run"
        )
    run_id = raw_run_id
    configured_root = rooted_io.checked_directory(
        str(config.get("scratchpad") or ""),
        label="configured empty severity source scratchpad",
    )
    configured_project = rooted_io.checked_directory(
        str(config.get("project_root") or ""),
        label="configured empty severity source project",
    )
    if configured_root != root or configured_project != project:
        raise ArtifactLedgerError(
            "empty severity source roots differ from configuration"
        )

    contract, launch = _contract_and_launch(config)
    ledger = read_artifact_ledger(root)
    prior = ledger.get("work_units", {}).get(contract.key)
    initial_raw = _read_inputs(root)
    queue_state, plan_digest = _validate_empty_queue(initial_raw)
    if queue_state != "EMPTY":
        if isinstance(prior, Mapping):
            raise ArtifactLedgerError(
                "armed empty severity source no longer has an empty queue"
            )
        return False
    _reject_stale_decisions(root)
    _require_current_queue_producer(
        root,
        project,
        config=config,
        run_id=run_id,
        raw=initial_raw,
    )

    output = _ledger_bytes(run_id)
    output_identities = tuple(
        f"scratchpad:{name}" for name in OUTPUT_NAMES
    )
    expected_records = {
        identity: {"sha256": _sha(output), "size": len(output)}
        for identity in output_identities
    }
    authority_core = {
        "schema": "plamen.empty-severity-source-invocation.v1",
        "run_id": run_id,
        "queue_work_plan_digest": plan_digest,
        "input_records": {
            f"scratchpad:{name}": {
                "sha256": _sha(raw),
                "size": len(raw),
            }
            for name, raw in initial_raw.items()
        },
        "expected_outputs": expected_records,
    }
    invocation = {
        **authority_core,
        "authority_sha256": _canonical_digest(authority_core),
    }

    if not isinstance(prior, Mapping):
        bindings = ledger.get("artifact_bindings", {})
        if any(
            rooted_io.lexists(root / name)
            or isinstance(bindings.get(identity), Mapping)
            for name, identity in zip(
                OUTPUT_NAMES, output_identities, strict=True
            )
        ):
            raise ArtifactLedgerError(
                "empty severity source refuses pre-existing output authority"
            )
        rooted_io.ensure_directory(
            root / Path(INITIAL_SNAPSHOT_NAME).parent,
            mode=0o700,
            label="empty severity source snapshot directory",
        )
        record_work_unit_inputs(
            root,
            project,
            contract,
            launch,
            run_id=run_id,
            preexecution_authority=invocation,
        )
    elif (
        prior.get("run_id") != run_id
        or prior.get("contract_digest") != contract.digest
        or prior.get("launch_digest") != launch.digest
    ):
        raise ArtifactLedgerError("empty severity source transaction identity changed")

    input_issues = validate_work_unit_inputs(
        root,
        project,
        contract,
        launch,
        run_id=run_id,
        preexecution_authority=invocation,
    )
    if input_issues:
        raise ArtifactLedgerError(
            "empty severity source input replay failed: "
            + "; ".join(input_issues)
        )
    _require_bound_queue_producer(
        root,
        contract=contract,
        config=config,
        run_id=run_id,
        raw=initial_raw,
    )
    _revalidate_denominator(
        root,
        expected_raw=initial_raw,
        expected_plan_digest=plan_digest,
    )

    unit = read_artifact_ledger(root).get("work_units", {}).get(contract.key)
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
            run_id=run_id,
            actor="DRIVER",
            preexecution_authority=invocation,
        )
        if output_issues:
            raise ArtifactLedgerError(
                "empty severity source output replay failed: "
                + "; ".join(output_issues)
            )
        return True
    if not (
        isinstance(unit, Mapping)
        and unit.get("semantic_status") == "INPUTS_BOUND"
        and unit.get("execution_state") == "INPUTS_BOUND_PREEXECUTION"
        and unit.get("artifacts") == {}
    ):
        raise ArtifactLedgerError("empty severity source transaction is not armed")
    prestates = unit.get("output_prestates")
    if (
        not isinstance(prestates, Mapping)
        or set(prestates) != set(output_identities)
        or any(
            not isinstance(prestates.get(identity), Mapping)
            or prestates[identity].get("status") != "ABSENT"
            for identity in output_identities
        )
    ):
        raise ArtifactLedgerError(
            "empty severity source requires an absent output prestate"
        )
    for name in OUTPUT_NAMES:
        destination = root / name
        if rooted_io.lexists(destination):
            try:
                observed = rooted_io.read_bytes(
                    destination,
                    label=f"empty severity source partial output {name}",
                    require_single_link=True,
                    max_bytes=len(output),
                )
            except (OSError, rooted_io.RootedPathIOError) as exc:
                raise ArtifactLedgerError(
                    f"empty severity source partial output is invalid: {exc}"
                ) from exc
            if observed != output:
                raise ArtifactLedgerError(
                    "empty severity source has arbitrary partial output bytes"
                )

    hook = fault_hook or (lambda _point: None)
    hook("after_arm")
    _revalidate_denominator(
        root,
        expected_raw=initial_raw,
        expected_plan_digest=plan_digest,
    )
    for ordinal, name in enumerate(OUTPUT_NAMES, 1):
        rooted_io.durable_write_once_bytes(root / name, output)
        hook(f"after_output_{ordinal}")
        _revalidate_denominator(
            root,
            expected_raw=initial_raw,
            expected_plan_digest=plan_digest,
        )
    hook("before_commit")
    _revalidate_denominator(
        root,
        expected_raw=initial_raw,
        expected_plan_digest=plan_digest,
    )
    record_work_unit_artifacts(
        root,
        project,
        contract,
        launch,
        run_id=run_id,
        actor="DRIVER",
        expected_output_records=expected_records,
    )
    output_issues = validate_work_unit_artifacts(
        root,
        project,
        contract,
        launch,
        run_id=run_id,
        actor="DRIVER",
        preexecution_authority=invocation,
    )
    if output_issues:
        raise ArtifactLedgerError(
            "empty severity source commit replay failed: "
            + "; ".join(output_issues)
        )
    hook("after_commit")
    return True


__all__ = [
    "FAULT_POINTS",
    "INITIAL_SNAPSHOT_NAME",
    "INPUT_NAMES",
    "OUTPUT_NAME",
    "OUTPUT_NAMES",
    "run_empty_severity_source",
]
