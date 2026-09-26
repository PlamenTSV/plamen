"""Typed zero-row reconciliation for severity adjudication planning."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Callable, Mapping

import rooted_path_io as rio
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
from phase_io_contracts import LaunchSpec, canonical_work_unit_key, resolve_phase_io_contract
from severity_adjudication_work import (
    MANIFEST_NAME,
    RECONCILIATION_NAME,
    SOURCE_LEDGER_NAME,
    WORK_PLAN_NAME,
    build_adjudication_work_reconciliation,
    validate_prepared_work,
)


INPUT_NAMES = (SOURCE_LEDGER_NAME, MANIFEST_NAME, WORK_PLAN_NAME)
OUTPUT_NAME = RECONCILIATION_NAME
FAULT_POINTS = ("after_arm", "after_output_1", "before_commit", "after_commit")
_MAX_BYTES = 32 * 1024 * 1024


def _strict_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ArtifactLedgerError(
                f"duplicate zero severity reconciliation key {key!r}"
            )
        result[key] = value
    return result


def _reject_constant(token: str) -> None:
    raise ArtifactLedgerError(
        f"non-finite zero severity reconciliation constant {token!r}"
    )


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _authority_digest(value: Mapping[str, Any]) -> str:
    return _sha(json.dumps(
        dict(value), ensure_ascii=True, allow_nan=False,
        sort_keys=True, separators=(",", ":"),
    ).encode("ascii"))


def _read(root: Path, name: str) -> bytes:
    try:
        return rio.read_bytes(
            root / name, label=f"zero severity reconciliation {name}",
            max_bytes=_MAX_BYTES, require_single_link=True,
        )
    except (OSError, rio.RootedPathIOError) as exc:
        raise ArtifactLedgerError(f"zero severity reconciliation cannot read {name}: {exc}") from exc


def _json(raw: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_strict_pairs,
            parse_constant=_reject_constant,
        )
    except (UnicodeError, ValueError, TypeError, RecursionError) as exc:
        raise ArtifactLedgerError(f"{label} is invalid JSON") from exc
    if not isinstance(value, dict):
        raise ArtifactLedgerError(f"{label} is not an object")
    return value


def _dimensions(config: Mapping[str, Any]) -> tuple[str, str, str, str]:
    values = (
        str(config.get("pipeline") or "").strip().lower(),
        str(config.get("mode") or "").strip().lower(),
        str(config.get("language") or config.get("ecosystem") or "").strip().lower(),
        str(config.get("cli_backend") or config.get("backend") or "").strip().lower(),
    )
    if not all(values) or values[0] not in {"sc", "l1"}:
        raise ArtifactLedgerError("zero severity reconciliation dimensions are invalid")
    return values


def _contract(config: Mapping[str, Any]):
    pipeline, mode, ecosystem, backend = _dimensions(config)
    contract = resolve_phase_io_contract(
        pipeline=pipeline, mode=mode, ecosystem=ecosystem, backend=backend,
        phase="severity_adjudication_shadow", work_unit_id="reconcile_empty",
        exact_inputs=INPUT_NAMES, exact_outputs=(OUTPUT_NAME,), exact_writer="DRIVER",
    )
    launch = LaunchSpec(
        work_unit_key=contract.key, pipeline=pipeline, mode=mode,
        ecosystem=ecosystem, backend=backend, model="driver", timeout_s=60,
        exec_mode="python", tool_policy=(),
    )
    return contract, launch


def _expected_owners(config: Mapping[str, Any]) -> dict[str, str]:
    pipeline, mode, ecosystem, backend = _dimensions(config)
    prefix = (pipeline, mode, ecosystem, backend, "severity_adjudication_shadow")
    return {
        SOURCE_LEDGER_NAME: canonical_work_unit_key(*prefix, "source_empty"),
        MANIFEST_NAME: canonical_work_unit_key(*prefix, "planning"),
        WORK_PLAN_NAME: canonical_work_unit_key(*prefix, "planning"),
    }


def _reject_stale_zero_artifacts(root: Path) -> None:
    """Reject only files belonging to a nonzero severity worker transaction."""

    prefixes = (
        "severity_adjudication_context.",
        "severity_adjudication_prompt.",
        "severity_adjudication_launch_intent.",
        "severity_adjudication_tool_policy.",
        "severity_adjudication_worker_run.",
    )
    suffixes = (
        ".severity_adjudication_proposal.json",
        ".severity_adjudication_receipt.json",
    )
    checked = rio.checked_directory(root, label="zero severity scratchpad")
    with rio.scandir(checked) as entries:
        stale = sorted(
            entry.name
            for entry in entries
            if (
                entry.name.casefold().startswith(prefixes)
                or (
                    entry.name.casefold().startswith("verify_")
                    and entry.name.casefold().endswith(suffixes)
                )
                or (
                    entry.name.casefold().startswith("verify_")
                    and entry.name.casefold().endswith(
                        ".severity_decision.json"
                    )
                )
            )
        )
    if stale:
        raise ArtifactLedgerError(
            "zero severity reconciliation refuses stale worker artifacts: "
            + ", ".join(stale[:16])
        )


def _require_zero(raw: Mapping[str, bytes], root: Path) -> bytes:
    ledger = _json(raw[SOURCE_LEDGER_NAME], SOURCE_LEDGER_NAME)
    manifest = _json(raw[MANIFEST_NAME], MANIFEST_NAME)
    plan = _json(raw[WORK_PLAN_NAME], WORK_PLAN_NAME)
    if ledger.get("decisions") != []:
        raise ArtifactLedgerError("zero severity source ledger is nonempty")
    expected = (
        type(manifest.get("denominator_count")) is int
        and manifest.get("denominator_count") == 0
        and manifest.get("denominator_ids") == []
        and manifest.get("work_items") == []
        and type(plan.get("denominator_count")) is int
        and plan.get("denominator_count") == 0
        and plan.get("denominator_ids") == []
        and plan.get("shards") == []
        and plan.get("debt_items") == []
        and type(plan.get("launch_count")) is int
        and plan.get("launch_count") == 0
        and plan.get("zero_row_no_launch") is True
    )
    if not expected:
        raise ArtifactLedgerError("severity plan is not an exact zero-row plan")
    issues = validate_prepared_work(root)
    if issues:
        raise ArtifactLedgerError("zero severity prepared work is invalid: " + "; ".join(issues))
    result = build_adjudication_work_reconciliation(root)
    if not (
        type(result.get("denominator_count")) is int
        and result.get("denominator_count") == 0
        and result.get("denominator_ids") == []
        and result.get("states") == {}
        and result.get("details") == {}
        and result.get("pending_ids") == []
        and result.get("bind_ready_ids") == []
        and result.get("completed_ids") == []
        and result.get("debt_ids") == []
        and result.get("all_terminal") is True
        and result.get("all_resolved") is True
    ):
        raise ArtifactLedgerError("derived zero severity reconciliation is nonzero")
    return (json.dumps(
        result, ensure_ascii=False, allow_nan=False,
        sort_keys=True, separators=(",", ":"),
    ) + "\n").encode("utf-8")


def _require_producers(
    root: Path, project: Path, contract: Any, config: Mapping[str, Any],
    run_id: str, raw: Mapping[str, bytes],
) -> None:
    identities = tuple(f"scratchpad:{name}" for name in INPUT_NAMES)
    issues = semantic_input_prebind_producer_authority_issues(
        root, project, identities, run_id=run_id,
    )
    if issues:
        raise ArtifactLedgerError("zero severity producer prebind failed: " + "; ".join(issues))
    ledger = read_artifact_ledger(root)
    unit = ledger.get("work_units", {}).get(contract.key)
    bindings = unit.get("input_bindings") if isinstance(unit, Mapping) else None
    if not isinstance(bindings, Mapping) or set(bindings) != set(identities):
        raise ArtifactLedgerError("zero severity bound input denominator differs")
    owners = _expected_owners(config)
    for name in INPUT_NAMES:
        identity = f"scratchpad:{name}"
        row = bindings.get(identity)
        if not isinstance(row, Mapping) or (
            row.get("sha256") != _sha(raw[name])
            or row.get("size") != len(raw[name])
            or row.get("producer_work_unit_key") != owners[name]
            or row.get("producer_writer") != "DRIVER"
            or row.get("producer_run_id") != run_id
        ):
            raise ArtifactLedgerError(f"zero severity input producer mismatch: {identity}")
        replay = semantic_input_producer_authority_issues(ledger, row, run_id=run_id)
        if replay:
            raise ArtifactLedgerError(f"zero severity producer invalid for {identity}: " + "; ".join(replay))


def _require_current_producers(
    root: Path, project: Path, config: Mapping[str, Any], run_id: str,
    raw: Mapping[str, bytes],
) -> None:
    identities = tuple(f"scratchpad:{name}" for name in INPUT_NAMES)
    issues = semantic_input_prebind_producer_authority_issues(
        root, project, identities, run_id=run_id,
    )
    if issues:
        raise ArtifactLedgerError(
            "zero severity current producer replay failed: " + "; ".join(issues)
        )
    ledger = read_artifact_ledger(root)
    bindings = ledger.get("artifact_bindings")
    if not isinstance(bindings, Mapping):
        raise ArtifactLedgerError("zero severity artifact binding table is absent")
    owners = _expected_owners(config)
    for name in INPUT_NAMES:
        identity = f"scratchpad:{name}"
        row = bindings.get(identity)
        if not isinstance(row, Mapping) or (
            row.get("owner_key") != owners[name]
            or row.get("writer") != "DRIVER"
            or row.get("run_id") != run_id
            or row.get("sha256") != _sha(raw[name])
            or row.get("size") != len(raw[name])
            or row.get("status") != "ACTIVE"
        ):
            raise ArtifactLedgerError(
                f"zero severity current producer mismatch: {identity}"
            )


def run_zero_severity_reconciliation(
    *, scratchpad: Path, project_root: Path, config: Mapping[str, Any],
    fault_hook: Callable[[str], None] | None = None,
) -> bool:
    """Commit or replay reconciliation for an authenticated zero work plan."""
    root = rio.checked_directory(scratchpad, label="zero severity scratchpad")
    project = rio.checked_directory(project_root, label="zero severity project")
    if rio.checked_directory(str(config.get("scratchpad") or ""), label="configured scratchpad") != root:
        raise ArtifactLedgerError("zero severity configured scratchpad differs")
    if rio.checked_directory(str(config.get("project_root") or ""), label="configured project") != project:
        raise ArtifactLedgerError("zero severity configured project differs")
    configured_run_id = config.get("_run_id")
    run_id = configured_run_id if isinstance(configured_run_id, str) else ""
    if not run_id or run_id != run_id.strip():
        raise ArtifactLedgerError("zero severity run is absent")
    contract, launch = _contract(config)
    initial = {name: _read(root, name) for name in INPUT_NAMES}
    output = _require_zero(initial, root)
    _reject_stale_zero_artifacts(root)
    _require_current_producers(root, project, config, run_id, initial)
    identity = f"scratchpad:{OUTPUT_NAME}"
    expected = {identity: {"sha256": _sha(output), "size": len(output)}}
    invocation_core = {
        "schema": "plamen.zero-severity-reconciliation-invocation.v1",
        "run_id": run_id,
        "inputs": {f"scratchpad:{n}": {"sha256": _sha(v), "size": len(v)} for n, v in initial.items()},
        "expected_outputs": expected,
    }
    invocation = {
        **invocation_core,
        "authority_sha256": _authority_digest(invocation_core),
    }
    ledger = read_artifact_ledger(root)
    prior = ledger.get("work_units", {}).get(contract.key)
    if not isinstance(prior, Mapping):
        bindings = ledger.get("artifact_bindings")
        if rio.lexists(root / OUTPUT_NAME) or (
            isinstance(bindings, Mapping)
            and isinstance(bindings.get(identity), Mapping)
        ):
            raise ArtifactLedgerError("zero severity reconciliation refuses foreign output")
        record_work_unit_inputs(root, project, contract, launch, run_id=run_id, preexecution_authority=invocation)
    elif prior.get("run_id") != run_id or prior.get("contract_digest") != contract.digest or prior.get("launch_digest") != launch.digest:
        raise ArtifactLedgerError("zero severity reconciliation identity changed")
    problems = validate_work_unit_inputs(root, project, contract, launch, run_id=run_id, preexecution_authority=invocation)
    if problems:
        raise ArtifactLedgerError("zero severity input replay failed: " + "; ".join(problems))
    _require_producers(root, project, contract, config, run_id, initial)
    _require_current_producers(root, project, config, run_id, initial)
    _reject_stale_zero_artifacts(root)
    if {name: _read(root, name) for name in INPUT_NAMES} != initial or _require_zero(initial, root) != output:
        raise ArtifactLedgerError("zero severity inputs changed after arm")
    unit = read_artifact_ledger(root).get("work_units", {}).get(contract.key)
    if isinstance(unit, Mapping) and unit.get("semantic_status") == "ACTIVE" and unit.get("execution_state") == "OUTPUT_COMMITTED":
        if _read(root, OUTPUT_NAME) != output:
            raise ArtifactLedgerError(
                "zero severity committed output differs from fresh derivation"
            )
        issues = validate_work_unit_artifacts(root, project, contract, launch, run_id=run_id, actor="DRIVER", preexecution_authority=invocation)
        if issues:
            raise ArtifactLedgerError("zero severity committed replay failed: " + "; ".join(issues))
        return True
    if not (isinstance(unit, Mapping) and unit.get("semantic_status") == "INPUTS_BOUND" and unit.get("execution_state") == "INPUTS_BOUND_PREEXECUTION" and unit.get("artifacts") == {}):
        raise ArtifactLedgerError("zero severity reconciliation is not armed")
    prestates = unit.get("output_prestates")
    prestate = prestates.get(identity) if isinstance(prestates, Mapping) else None
    if (
        not isinstance(prestates, Mapping)
        or set(prestates) != {identity}
        or not isinstance(prestate, Mapping)
        or prestate.get("status") != "ABSENT"
    ):
        raise ArtifactLedgerError("zero severity reconciliation requires absent prestate")
    destination = root / OUTPUT_NAME
    if rio.lexists(destination) and _read(root, OUTPUT_NAME) != output:
        raise ArtifactLedgerError("zero severity reconciliation partial bytes differ")
    hook = fault_hook or (lambda _point: None)
    hook("after_arm")
    _require_current_producers(root, project, config, run_id, initial)
    _require_producers(root, project, contract, config, run_id, initial)
    _reject_stale_zero_artifacts(root)
    if {name: _read(root, name) for name in INPUT_NAMES} != initial:
        raise ArtifactLedgerError("zero severity inputs changed before output")
    rio.durable_write_once_bytes(destination, output)
    hook("after_output_1")
    hook("before_commit")
    _require_current_producers(root, project, config, run_id, initial)
    _require_producers(root, project, contract, config, run_id, initial)
    _reject_stale_zero_artifacts(root)
    if {name: _read(root, name) for name in INPUT_NAMES} != initial or _require_zero(initial, root) != output:
        raise ArtifactLedgerError("zero severity inputs changed before commit")
    record_work_unit_artifacts(root, project, contract, launch, run_id=run_id, actor="DRIVER", expected_output_records=expected)
    issues = validate_work_unit_artifacts(root, project, contract, launch, run_id=run_id, actor="DRIVER", preexecution_authority=invocation)
    if issues:
        raise ArtifactLedgerError("zero severity commit replay failed: " + "; ".join(issues))
    hook("after_commit")
    return True


__all__ = ["FAULT_POINTS", "INPUT_NAMES", "OUTPUT_NAME", "run_zero_severity_reconciliation"]
