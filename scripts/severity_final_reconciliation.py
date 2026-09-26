"""Typed nonempty severity reconciliation publisher.

The read-only completed-bind validator supplies the exact current-byte input
set and ordered authority. Publication and replay never adopt ambient outputs.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Callable, Mapping

from artifact_ledger import (
    _canonical_json_digest,
    ArtifactLedgerError, read_artifact_ledger, record_work_unit_artifacts,
    record_work_unit_explicit_absence_bindings, record_work_unit_inputs,
    validate_work_unit_artifacts, validate_work_unit_explicit_absence_bindings,
    validate_work_unit_inputs,
)
from phase_io_contracts import LaunchSpec, resolve_phase_io_contract
import rooted_path_io as rio
from severity_adjudication_work import (
    MANIFEST_NAME, RECONCILIATION_NAME, WORK_PLAN_NAME,
    build_adjudication_work_reconciliation,
)
from severity_bind_transaction import validate_completed_severity_bind_prefix


FAULT_POINTS = (
    "after_input_arm", "after_arm", "after_output_1", "before_commit",
    "after_commit",
)
WORK_UNIT_ID = "reconcile_final"
OUTPUT_NAME = RECONCILIATION_NAME
_MAX_BYTES = 32 * 1024 * 1024
_INITIAL_SNAPSHOT = "_severity_adjudication_inputs/source_ledger.initial.json"


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _read(root: Path, name: str) -> bytes:
    try:
        return rio.read_bytes(root / name, label=f"final severity {name}",
                              max_bytes=_MAX_BYTES, require_single_link=True)
    except (OSError, rio.RootedPathIOError) as exc:
        raise ArtifactLedgerError(f"final severity input unavailable: {name}: {exc}") from exc


def _encoded(value: Mapping[str, Any]) -> bytes:
    return (json.dumps(dict(value), ensure_ascii=False, allow_nan=False,
                       sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def _invocation_authority(core: Mapping[str, Any]) -> dict[str, Any]:
    # Authority uses the ledger's canonical JSON, not the newline-terminated
    # artifact encoding. Keep this identical for first arm and every replay.
    return {**dict(core), "authority_sha256": _canonical_json_digest(core)}


def _dimensions(config: Mapping[str, Any]) -> tuple[str, str, str, str, str]:
    run = config.get("_run_id")
    values = (
        str(config.get("pipeline") or "").strip().lower(),
        str(config.get("mode") or "").strip().lower(),
        str(config.get("language") or config.get("ecosystem") or "").strip().lower(),
        str(config.get("cli_backend") or config.get("backend") or "").strip().lower(),
    )
    if not isinstance(run, str) or not run or run != run.strip() or not all(values):
        raise ArtifactLedgerError("final severity dimensions are invalid")
    return run, *values


def _contract(config: Mapping[str, Any], names: tuple[str, ...]):
    run, pipeline, mode, ecosystem, backend = _dimensions(config)
    contract = resolve_phase_io_contract(
        pipeline=pipeline, mode=mode, ecosystem=ecosystem, backend=backend,
        phase="severity_adjudication_shadow", work_unit_id=WORK_UNIT_ID,
        exact_inputs=names, exact_outputs=(OUTPUT_NAME,), exact_writer="DRIVER",
    )
    launch = LaunchSpec(
        work_unit_key=contract.key, pipeline=pipeline, mode=mode,
        ecosystem=ecosystem, backend=backend, model="driver", timeout_s=60,
        exec_mode="python", tool_policy=(),
    )
    return run, contract, launch


def run_final_severity_reconciliation(
    *, scratchpad: Path, project_root: Path, config: Mapping[str, Any],
    fault_hook: Callable[[str], None] | None = None,
) -> bool:
    """Publish/replay reconciliation only after the exact bind prefix commits."""
    root = rio.checked_directory(scratchpad, label="final severity scratchpad")
    project = rio.checked_directory(project_root, label="final severity project")
    if rio.checked_directory(str(config.get("scratchpad") or "")) != root or rio.checked_directory(
        str(config.get("project_root") or "")
    ) != project:
        raise ArtifactLedgerError("final severity configured roots differ")

    # Required wrapper returns only after every planned ordinal has passed the
    # public historical completion validator with its exact invocation. Its
    # read_set contains planning artifacts, final canonical ledger, every
    # candidate decision/receipt/proposal, and actual worker/control evidence.
    prefix = validate_completed_severity_bind_prefix(root, project, config)
    denominator = tuple(prefix.candidate_ids)
    captured = dict(prefix.read_set)
    if not denominator:
        raise ArtifactLedgerError("final severity publisher refuses zero denominator")
    if dict(prefix.absence_records) != {"skeptic_challenges.json": "MISSING"}:
        raise ArtifactLedgerError("final severity skeptic absence authority differs")
    if set(captured) != set(prefix.input_names) or any(type(raw) is not bytes for raw in captured.values()):
        raise ArtifactLedgerError("final severity bind read-set is incomplete")
    if (
        MANIFEST_NAME not in captured or WORK_PLAN_NAME not in captured
        or _INITIAL_SNAPSHOT not in captured
    ):
        raise ArtifactLedgerError("final severity planning inputs are absent")
    if any(_read(root, name) != raw for name, raw in captured.items()):
        raise ArtifactLedgerError("final severity input changed before derivation")

    result = build_adjudication_work_reconciliation(root)
    if (
        result.get("denominator_ids") != list(denominator)
        or result.get("bind_ready_ids") != []
        or result.get("pending_ids") != []
        or result.get("all_terminal") is not True
        or set(result.get("states") or {}) != set(denominator)
        or any(state not in {"COMPLETED", "COMPLETED_UNRESOLVED"}
               for state in (result.get("states") or {}).values())
    ):
        raise ArtifactLedgerError("final severity bind denominator is not terminal")
    # COMPLETED_UNRESOLVED remains a valid published business result. Its
    # debt_ids/all_resolved fields remain untouched and visible downstream.
    output = _encoded(result)
    if any(_read(root, name) != raw for name, raw in captured.items()):
        raise ArtifactLedgerError("final severity input changed during derivation")

    names = tuple(prefix.input_names)
    run_id, contract, launch = _contract(config, names)
    invocation_core = {
        "schema": "plamen.final-severity-reconciliation-invocation.v1",
        "run_id": run_id,
        "candidate_ids": list(prefix.candidate_ids),
        "bind_authority_digests": list(prefix.bind_authority_digests),
        "bind_prefix_digest": prefix.authority_digest,
        "inputs": {f"scratchpad:{name}": {"sha256": _sha(captured[name]), "size": len(captured[name])}
                   for name in names},
        "expected_outputs": {f"scratchpad:{OUTPUT_NAME}": {"sha256": _sha(output), "size": len(output)}},
    }
    invocation = _invocation_authority(invocation_core)
    hook = fault_hook or (lambda _point: None)
    ledger = read_artifact_ledger(root)
    prior = ledger.get("work_units", {}).get(contract.key)
    destination = root / OUTPUT_NAME
    if not isinstance(prior, Mapping):
        if rio.lexists(destination):
            raise ArtifactLedgerError("final severity refuses unowned reconciliation")
        record_work_unit_inputs(root, project, contract, launch, run_id=run_id,
                                preexecution_authority=invocation)
    hook("after_input_arm")
    input_issues = validate_work_unit_inputs(
        root, project, contract, launch, run_id=run_id,
        preexecution_authority=invocation,
    )
    if input_issues:
        raise ArtifactLedgerError(
            "final severity input replay failed: " + "; ".join(input_issues)
        )
    armed = read_artifact_ledger(root).get("work_units", {}).get(contract.key)
    if not isinstance(armed, Mapping):
        raise ArtifactLedgerError("final severity input arm disappeared")
    if armed.get("explicit_absence_authority") is None:
        if armed.get("execution_state") != "INPUTS_BOUND_PREEXECUTION":
            raise ArtifactLedgerError(
                "final severity committed transaction lacks absence authority"
            )
        if rio.lexists(root / "skeptic_challenges.json"):
            raise ArtifactLedgerError(
                "final severity skeptic absence changed before binding"
            )
        record_work_unit_explicit_absence_bindings(
            root, project, contract, launch, run_id=run_id,
            presence_roster=(
                *(f"scratchpad:{name}" for name in names),
                "scratchpad:skeptic_challenges.json",
            ),
        )
    issues = validate_work_unit_inputs(root, project, contract, launch, run_id=run_id,
                                      preexecution_authority=invocation)
    issues.extend(validate_work_unit_explicit_absence_bindings(
        root, project, contract, launch, run_id=run_id, require=True,
    ))
    if issues:
        raise ArtifactLedgerError("final severity input replay failed: " + "; ".join(issues))
    unit = read_artifact_ledger(root).get("work_units", {}).get(contract.key)
    if not isinstance(unit, Mapping):
        raise ArtifactLedgerError("final severity arm is absent")
    if unit.get("execution_state") == "OUTPUT_COMMITTED":
        if _read(root, OUTPUT_NAME) != output:
            raise ArtifactLedgerError("final severity committed output differs")
        issues = validate_work_unit_artifacts(root, project, contract, launch,
            run_id=run_id, actor="DRIVER", preexecution_authority=invocation)
        issues.extend(validate_work_unit_explicit_absence_bindings(
            root, project, contract, launch, run_id=run_id, require=True,
        ))
        if issues:
            raise ArtifactLedgerError("final severity committed replay failed: " + "; ".join(issues))
        if validate_completed_severity_bind_prefix(root, project, config) != prefix:
            raise ArtifactLedgerError("final severity committed bind authority changed")
        return True
    prestates = unit.get("output_prestates")
    identity = f"scratchpad:{OUTPUT_NAME}"
    if (unit.get("execution_state") != "INPUTS_BOUND_PREEXECUTION"
            or not isinstance(prestates, Mapping) or set(prestates) != {identity}
            or prestates[identity].get("status") != "ABSENT"):
        raise ArtifactLedgerError("final severity partial state is not recoverable")
    if rio.lexists(destination) and _read(root, OUTPUT_NAME) != output:
        raise ArtifactLedgerError("final severity partial output differs")
    hook("after_arm")
    absence_issues = validate_work_unit_explicit_absence_bindings(
        root, project, contract, launch, run_id=run_id, require=True,
    )
    if absence_issues:
        raise ArtifactLedgerError("final severity absence replay failed: " + "; ".join(absence_issues))
    if any(_read(root, name) != raw for name, raw in captured.items()):
        raise ArtifactLedgerError("final severity input changed before output")
    rio.durable_write_once_bytes(destination, output)
    hook("after_output_1")
    hook("before_commit")
    # Re-run the read-only prefix proof at the commit boundary; equal frozen
    # result prevents mixing two valid but different bind heads.
    if validate_completed_severity_bind_prefix(root, project, config) != prefix:
        raise ArtifactLedgerError("final severity bind authority changed")
    if any(_read(root, name) != raw for name, raw in captured.items()):
        raise ArtifactLedgerError("final severity input changed before commit")
    absence_issues = validate_work_unit_explicit_absence_bindings(
        root, project, contract, launch, run_id=run_id, require=True,
    )
    if absence_issues:
        raise ArtifactLedgerError("final severity absence changed before commit: " + "; ".join(absence_issues))
    expected = {identity: {"sha256": _sha(output), "size": len(output)}}
    record_work_unit_artifacts(root, project, contract, launch, run_id=run_id,
                               actor="DRIVER", expected_output_records=expected)
    hook("after_commit")
    issues = validate_work_unit_artifacts(root, project, contract, launch,
        run_id=run_id, actor="DRIVER", preexecution_authority=invocation)
    if issues:
        raise ArtifactLedgerError("final severity commit replay failed: " + "; ".join(issues))
    absence_issues = validate_work_unit_explicit_absence_bindings(
        root, project, contract, launch, run_id=run_id, require=True,
    )
    if absence_issues:
        raise ArtifactLedgerError("final severity postcommit absence replay failed: " + "; ".join(absence_issues))
    if validate_completed_severity_bind_prefix(root, project, config) != prefix:
        raise ArtifactLedgerError("final severity postcommit bind authority changed")
    return True


__all__ = ["FAULT_POINTS", "OUTPUT_NAME", "WORK_UNIT_ID", "run_final_severity_reconciliation"]
