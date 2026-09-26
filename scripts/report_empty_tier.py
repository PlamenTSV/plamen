"""Typed DRIVER publication for one authentically empty report tier."""
from __future__ import annotations

import hashlib
import json
import re
import stat
from pathlib import Path
from typing import Any, Callable, Mapping

import rooted_path_io as rooted_io
from artifact_ledger import (
    _ArtifactValidationContext,
    _artifact_validation_epoch,
    ArtifactLedgerError,
    read_artifact_ledger,
    record_work_unit_artifacts,
    record_work_unit_inputs,
    semantic_input_prebind_producer_authority_issues,
    semantic_input_producer_authority_issues,
    validate_work_unit_artifacts,
    validate_work_unit_inputs,
)
from phase_io_contracts import LaunchSpec, resolve_phase_io_contract
from report_evidence_authority import (
    ReportEvidenceError,
    validate_report_evidence_runtime,
)


TIERS = ("critical_high", "medium", "low_info")
FAULT_POINTS = ("after_arm", "after_output", "before_commit", "after_commit")
_MAX_INPUT_BYTES = 32 * 1024 * 1024
_SEVERITIES = {
    "critical_high": frozenset(("Critical", "High")),
    "medium": frozenset(("Medium",)),
    "low_info": frozenset(("Low", "Informational")),
}


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _digest(value: Mapping[str, Any]) -> str:
    return _sha(json.dumps(
        dict(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8"))


def _directory_identity(path: Path, *, label: str) -> dict[str, Any]:
    checked = rooted_io.checked_directory(path, label=label)
    row = rooted_io.lstat(checked)
    if not stat.S_ISDIR(row.st_mode):
        raise ArtifactLedgerError(f"{label} is not a directory")
    return {
        "absolute_path": str(checked),
        "device": int(row.st_dev),
        "inode": int(row.st_ino),
        "file_type": stat.S_IFMT(row.st_mode),
        "mode": stat.S_IMODE(row.st_mode),
    }


def _context(
    scratchpad: Path,
    project_root: Path,
    config: Mapping[str, Any],
) -> tuple[str, str, str, str, str, dict[str, Any], dict[str, Any]]:
    run_id = config.get("_run_id")
    pipeline = config.get("pipeline")
    mode = config.get("mode") or "core"
    ecosystem = config.get("language") or config.get("ecosystem") or "unknown"
    backend = config.get("cli_backend") or config.get("backend") or "claude"
    if (
        not isinstance(run_id, str)
        or not run_id
        or run_id != run_id.strip()
        or not isinstance(pipeline, str)
        or pipeline not in {"sc", "l1"}
        or not all(
            isinstance(value, str) and value and value == value.strip()
            for value in (mode, ecosystem, backend)
        )
    ):
        raise ArtifactLedgerError("empty report-tier run dimensions are invalid")
    configured_root = rooted_io.checked_directory(
        str(config.get("scratchpad") or ""),
        label="configured empty report-tier scratchpad",
    )
    configured_project = rooted_io.checked_directory(
        str(config.get("project_root") or ""),
        label="configured empty report-tier project",
    )
    if configured_root != scratchpad or configured_project != project_root:
        raise ArtifactLedgerError("empty report-tier roots differ from configuration")
    return (
        run_id,
        pipeline,
        mode,
        ecosystem,
        backend,
        _directory_identity(scratchpad, label="empty report-tier scratchpad"),
        _directory_identity(project_root, label="empty report-tier project"),
    )


def _relative(identity: str) -> str:
    if not isinstance(identity, str) or not identity.startswith("scratchpad:"):
        raise ArtifactLedgerError("empty report-tier input identity is invalid")
    relative = identity.split(":", 1)[1]
    path = Path(relative)
    if (
        not relative
        or path.is_absolute()
        or ".." in path.parts
        or "\\" in relative
    ):
        raise ArtifactLedgerError("empty report-tier relative path is invalid")
    return relative


def _stored_pair(
    unit: Mapping[str, Any],
    *,
    expected_key: str,
    expected_run_id: str,
) -> tuple[Any, LaunchSpec, tuple[str, ...]]:
    manifest = unit.get("contract_manifest")
    launch_manifest = unit.get("launch_manifest")
    parts = expected_key.split("/")
    if (
        len(parts) != 6
        or unit.get("work_unit_key") != expected_key
        or unit.get("run_id") != expected_run_id
        or not isinstance(manifest, Mapping)
        or not isinstance(launch_manifest, Mapping)
        or manifest.get("key") != expected_key
    ):
        raise ArtifactLedgerError("empty report-tier predecessor identity differs")
    immutable = manifest.get("immutable_inputs")
    bounded = manifest.get("bounded_lookup_inputs")
    outputs = manifest.get("outputs")
    if (
        not isinstance(immutable, list)
        or not isinstance(bounded, list)
        or bounded
        or not isinstance(outputs, list)
        or any(not isinstance(value, str) for value in immutable)
        or any(not isinstance(row, Mapping) for row in outputs)
    ):
        raise ArtifactLedgerError("empty report-tier predecessor contract is malformed")
    exact_inputs = tuple(_relative(value) for value in immutable)
    exact_outputs = tuple(_relative(str(row.get("identity") or "")) for row in outputs)
    conditional = tuple(
        relative
        for relative, row in zip(exact_outputs, outputs, strict=True)
        if str(row.get("condition_id") or "")
    )
    condition_ids = {
        str(row.get("condition_id") or "")
        for row in outputs
        if str(row.get("condition_id") or "")
    }
    if len(condition_ids) > 1:
        raise ArtifactLedgerError("empty report-tier predecessor conditions differ")
    writers = {
        str(row.get("writer") or "") for row in outputs
        if isinstance(row, Mapping)
    }
    if writers != {"DRIVER"}:
        raise ArtifactLedgerError("empty report-tier predecessor writer differs")
    contract = resolve_phase_io_contract(
        pipeline=parts[0],
        mode=parts[1],
        ecosystem=parts[2],
        backend=parts[3],
        phase=parts[4],
        work_unit_id=parts[5],
        exact_inputs=exact_inputs,
        exact_outputs=exact_outputs,
        conditional_output_ids=conditional,
        condition_id=next(iter(condition_ids), ""),
        exact_writer="DRIVER",
    )
    expected_launch_keys = {
        "launch_version", "work_unit_key", "pipeline", "mode", "ecosystem",
        "backend", "model", "timeout_s", "exec_mode", "tool_policy",
    }
    if set(launch_manifest) != expected_launch_keys:
        raise ArtifactLedgerError("empty report-tier predecessor launch is malformed")
    launch = LaunchSpec(
        launch_version=launch_manifest["launch_version"],
        work_unit_key=launch_manifest["work_unit_key"],
        pipeline=launch_manifest["pipeline"],
        mode=launch_manifest["mode"],
        ecosystem=launch_manifest["ecosystem"],
        backend=launch_manifest["backend"],
        model=launch_manifest["model"],
        timeout_s=launch_manifest["timeout_s"],
        exec_mode=launch_manifest["exec_mode"],
        tool_policy=tuple(launch_manifest["tool_policy"]),
    )
    if (
        contract.to_dict() != dict(manifest)
        or contract.digest != unit.get("contract_digest")
        or launch.to_dict() != dict(launch_manifest)
        or launch.digest != unit.get("launch_digest")
        or launch.work_unit_key != contract.key
        or unit.get("semantic_status") != "ACTIVE"
        or unit.get("execution_state") != "OUTPUT_COMMITTED"
    ):
        raise ArtifactLedgerError("empty report-tier predecessor replay differs")
    return contract, launch, exact_outputs


def _upstream(
    root: Path,
    project: Path,
    *,
    dimensions: tuple[str, str, str, str],
    run_id: str,
    _validation_context: _ArtifactValidationContext | None = None,
) -> tuple[tuple[str, ...], dict[str, bytes], dict[str, Any]]:
    if _validation_context is None:
        with _artifact_validation_epoch(root, project) as validation_context:
            return _upstream(
                root,
                project,
                dimensions=dimensions,
                run_id=run_id,
                _validation_context=validation_context,
            )
    pipeline, mode, ecosystem, backend = dimensions
    prefix = f"{pipeline}/{mode}/{ecosystem}/{backend}"
    routing_key = f"{prefix}/report_index/routing"
    evidence_identity = "scratchpad:report_evidence_records.json"
    validation_context = _validation_context
    ledger = validation_context.ledger
    work_units = ledger.get("work_units")
    bindings = ledger.get("artifact_bindings")
    if not isinstance(work_units, Mapping) or not isinstance(bindings, Mapping):
        raise ArtifactLedgerError("empty report-tier ledger tables are malformed")
    routing = work_units.get(routing_key)
    evidence_binding = bindings.get(evidence_identity)
    if not isinstance(routing, Mapping) or not isinstance(evidence_binding, Mapping):
        raise ArtifactLedgerError("empty report-tier upstream transaction is absent")
    evidence_key = evidence_binding.get("owner_key")
    if evidence_key not in {
        f"{prefix}/report_body/evidence_pre",
        f"{prefix}/report_body/evidence_repair.apply",
    }:
        raise ArtifactLedgerError("empty report-tier evidence owner is unauthorized")
    evidence = work_units.get(evidence_key)
    if not isinstance(evidence, Mapping):
        raise ArtifactLedgerError("empty report-tier evidence unit is absent")
    pairs = (
        _stored_pair(routing, expected_key=routing_key, expected_run_id=run_id),
        _stored_pair(evidence, expected_key=evidence_key, expected_run_id=run_id),
    )
    exact_inputs: list[str] = []
    for (contract, launch, outputs), unit in zip(
        pairs, (routing, evidence), strict=True
    ):
        input_issues = validate_work_unit_inputs(
            root,
            project,
            contract,
            launch,
            run_id=run_id,
            _validation_context=validation_context,
        )
        output_issues = validate_work_unit_artifacts(
            root,
            project,
            contract,
            launch,
            run_id=run_id,
            actor="DRIVER",
            _validation_context=validation_context,
        )
        if input_issues or output_issues:
            raise ArtifactLedgerError(
                "empty report-tier predecessor authority is invalid: "
                + "; ".join((*input_issues, *output_issues))
            )
        artifacts = unit.get("artifacts")
        if not isinstance(artifacts, Mapping) or set(artifacts) != {
            f"scratchpad:{relative}" for relative in outputs
        }:
            raise ArtifactLedgerError("empty report-tier predecessor denominator differs")
        exact_inputs.extend(outputs)
    if len(exact_inputs) != len(set(name.casefold() for name in exact_inputs)):
        raise ArtifactLedgerError("empty report-tier input denominator aliases")
    if "report_records.json" not in exact_inputs:
        raise ArtifactLedgerError("empty report-tier report records are absent")
    body = sorted(
        name for name in exact_inputs
        if re.fullmatch(r"body_manifests/report_[a-z_]+\.json", name)
    )
    typed = sorted(
        name for name in exact_inputs
        if re.fullmatch(r"report_evidence_manifests/report_[a-z_]+\.json", name)
    )
    if not body or {
        Path(name).name for name in body
    } != {Path(name).name for name in typed}:
        raise ArtifactLedgerError("empty report-tier manifest pair denominator differs")
    identities = tuple(f"scratchpad:{name}" for name in exact_inputs)
    authority_issues = semantic_input_prebind_producer_authority_issues(
        root,
        project,
        identities,
        run_id=run_id,
        _validation_context=validation_context,
    )
    if authority_issues:
        raise ArtifactLedgerError(
            "empty report-tier upstream producer is invalid: "
            + "; ".join(authority_issues)
        )
    raw = {
        name: rooted_io.read_bytes(
            root / name,
            label=f"empty report-tier input {name}",
            require_single_link=True,
            max_bytes=_MAX_INPUT_BYTES,
        )
        for name in exact_inputs
    }
    try:
        runtime = validate_report_evidence_runtime(root)
    except (OSError, ReportEvidenceError, TypeError, ValueError) as exc:
        raise ArtifactLedgerError(
            f"empty report-tier evidence replay failed: {type(exc).__name__}: {exc}"
        ) from exc
    if read_artifact_ledger(root) != ledger:
        raise ArtifactLedgerError("empty report-tier ledger changed during replay")
    return tuple(exact_inputs), raw, runtime


def _tier_is_empty(
    root: Path,
    *,
    tier: str,
    inputs: tuple[str, ...],
    runtime: Mapping[str, Any],
) -> bool:
    bundle = runtime.get("bundle")
    records = bundle.get("records") if isinstance(bundle, Mapping) else None
    if not isinstance(records, list):
        raise ArtifactLedgerError("empty report-tier evidence records are malformed")
    has_record = any(
        isinstance(row, Mapping) and row.get("severity") in _SEVERITIES[tier]
        for row in records
    )
    manifest_re = re.compile(
        rf"^(?:body_manifests|report_evidence_manifests)/report_{re.escape(tier)}(?:_[a-z])?\.json$"
    )
    has_manifest = any(manifest_re.fullmatch(name) for name in inputs)
    if has_record != has_manifest:
        raise ArtifactLedgerError(
            "empty report-tier record and manifest assignment disagree"
        )
    if has_record:
        return False
    global_pair = {
        "body_manifests/report_empty.json",
        "report_evidence_manifests/report_empty.json",
    }
    if global_pair & set(inputs) and not global_pair <= set(inputs):
        raise ArtifactLedgerError("empty report-tier global manifest pair is incomplete")
    if global_pair <= set(inputs) and records:
        raise ArtifactLedgerError("empty report-tier global manifest contradicts records")
    return True


def _body_bytes(phase_name: str, tier: str) -> bytes:
    shard = f"report_{tier}"
    pretty = tier.replace("_", " ").title()
    text = (
        f"# {pretty} Findings\n\n"
        "_No findings of this severity tier were produced by the verification "
        "stage in this run. This is an authentic empty tier; it is not a "
        "placeholder for a missing finding. The driver deterministically "
        "skipped the body writer phase because the exact authenticated report "
        "routing and typed evidence denominators assign zero rows to this "
        "tier._\n\n"
        "## Provenance\n\n"
        f"Phase: {phase_name} (skipped via typed empty-tier transaction)\n"
        f"Manifest: exact authenticated denominator excludes {shard}\n"
        "Validator: typed empty-tier PhaseIO replay\n"
        "Empty-Tier-Auth: PLAMEN-DRIVER-AUTHENTIC-EMPTY-TIER\n"
    )
    return text.encode("utf-8")


def _transaction_pair(
    *,
    pipeline: str,
    mode: str,
    ecosystem: str,
    backend: str,
    tier: str,
    exact_inputs: tuple[str, ...],
):
    contract = resolve_phase_io_contract(
        pipeline=pipeline,
        mode=mode,
        ecosystem=ecosystem,
        backend=backend,
        phase="report_body",
        work_unit_id=f"empty.report_{tier}",
        exact_inputs=exact_inputs,
        exact_outputs=(f"report_{tier}.md",),
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


def _require_bound_inputs(
    root: Path,
    *,
    contract: Any,
    run_id: str,
    raw_inputs: Mapping[str, bytes],
) -> None:
    ledger = read_artifact_ledger(root)
    unit = ledger.get("work_units", {}).get(contract.key)
    bindings = unit.get("input_bindings") if isinstance(unit, Mapping) else None
    if not isinstance(bindings, Mapping) or set(bindings) != {
        f"scratchpad:{name}" for name in raw_inputs
    }:
        raise ArtifactLedgerError("empty report-tier bound input denominator differs")
    for name, raw in raw_inputs.items():
        identity = f"scratchpad:{name}"
        record = bindings.get(identity)
        if (
            not isinstance(record, Mapping)
            or record.get("sha256") != _sha(raw)
            or record.get("size") != len(raw)
            or record.get("producer_run_id") != run_id
        ):
            raise ArtifactLedgerError(f"empty report-tier bound input differs: {identity}")
        issues = semantic_input_producer_authority_issues(
            ledger, record, run_id=run_id
        )
        if issues:
            raise ArtifactLedgerError(
                f"empty report-tier bound producer invalid for {identity}: "
                + "; ".join(issues)
            )


def run_empty_report_tier(
    *,
    scratchpad: Path,
    project_root: Path,
    config: Mapping[str, Any],
    phase_name: str,
    fault_hook: Callable[[str], None] | None = None,
) -> bool:
    """Publish or read-only replay one exact authenticated empty tier."""

    match = re.fullmatch(r"report_body_writer_(critical_high|medium|low_info)", phase_name)
    if match is None:
        return False
    tier = match.group(1)
    root = rooted_io.checked_directory(
        scratchpad, label="empty report-tier scratchpad"
    )
    project = rooted_io.checked_directory(
        project_root, label="empty report-tier project"
    )
    (
        run_id, pipeline, mode, ecosystem, backend,
        root_identity, project_identity,
    ) = _context(root, project, config)
    exact_inputs, raw_inputs, runtime = _upstream(
        root,
        project,
        dimensions=(pipeline, mode, ecosystem, backend),
        run_id=run_id,
    )
    contract, launch = _transaction_pair(
        pipeline=pipeline,
        mode=mode,
        ecosystem=ecosystem,
        backend=backend,
        tier=tier,
        exact_inputs=exact_inputs,
    )
    ledger = read_artifact_ledger(root)
    prior = ledger.get("work_units", {}).get(contract.key)
    if not _tier_is_empty(
        root, tier=tier, inputs=exact_inputs, runtime=runtime
    ):
        if isinstance(prior, Mapping):
            raise ArtifactLedgerError(
                "armed empty report-tier no longer has an empty denominator"
            )
        return False
    body = _body_bytes(phase_name, tier)
    output_name = f"report_{tier}.md"
    output_identity = f"scratchpad:{output_name}"
    expected_record = {"sha256": _sha(body), "size": len(body)}
    authority_core = {
        "schema": "plamen.empty-report-tier-invocation.v1",
        "run_id": run_id,
        "pipeline": pipeline,
        "tier": tier,
        "phase_name": phase_name,
        "scratchpad_identity": root_identity,
        "project_identity": project_identity,
        "input_records": {
            f"scratchpad:{name}": {
                "sha256": _sha(raw), "size": len(raw)
            }
            for name, raw in raw_inputs.items()
        },
        "expected_outputs": {output_identity: expected_record},
    }
    invocation = {
        **authority_core,
        "authority_sha256": _digest(authority_core),
    }
    if not isinstance(prior, Mapping):
        binding = ledger.get("artifact_bindings", {}).get(output_identity)
        if rooted_io.lexists(root / output_name) or isinstance(binding, Mapping):
            raise ArtifactLedgerError("empty report-tier refuses a pre-existing body")
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
        raise ArtifactLedgerError("empty report-tier transaction identity changed")

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
            "empty report-tier input replay failed: " + "; ".join(input_issues)
        )
    _require_bound_inputs(
        root, contract=contract, run_id=run_id, raw_inputs=raw_inputs
    )

    def revalidate() -> None:
        if (
            _directory_identity(root, label="empty report-tier scratchpad")
            != root_identity
            or _directory_identity(project, label="empty report-tier project")
            != project_identity
        ):
            raise ArtifactLedgerError("empty report-tier root identity changed")
        current_inputs, current_raw, current_runtime = _upstream(
            root,
            project,
            dimensions=(pipeline, mode, ecosystem, backend),
            run_id=run_id,
        )
        if current_inputs != exact_inputs or current_raw != raw_inputs:
            raise ArtifactLedgerError("empty report-tier inputs changed after arm")
        if not _tier_is_empty(
            root, tier=tier, inputs=current_inputs, runtime=current_runtime
        ):
            raise ArtifactLedgerError("empty report-tier assignment changed after arm")

    revalidate()
    unit = read_artifact_ledger(root).get("work_units", {}).get(contract.key)
    if (
        isinstance(unit, Mapping)
        and unit.get("semantic_status") == "ACTIVE"
        and unit.get("execution_state") == "OUTPUT_COMMITTED"
    ):
        issues = validate_work_unit_artifacts(
            root,
            project,
            contract,
            launch,
            run_id=run_id,
            actor="DRIVER",
            preexecution_authority=invocation,
        )
        if issues:
            raise ArtifactLedgerError(
                "empty report-tier output replay failed: " + "; ".join(issues)
            )
        revalidate()
        return True
    if not (
        isinstance(unit, Mapping)
        and unit.get("semantic_status") == "INPUTS_BOUND"
        and unit.get("execution_state") == "INPUTS_BOUND_PREEXECUTION"
        and unit.get("artifacts") == {}
        and isinstance(unit.get("output_prestates"), Mapping)
        and set(unit["output_prestates"]) == {output_identity}
        and unit["output_prestates"][output_identity].get("status") == "ABSENT"
    ):
        raise ArtifactLedgerError("empty report-tier transaction is not exactly armed")
    destination = root / output_name
    if rooted_io.lexists(destination):
        observed = rooted_io.read_bytes(
            destination,
            label="empty report-tier partial body",
            require_single_link=True,
            max_bytes=len(body),
        )
        if observed != body:
            raise ArtifactLedgerError("empty report-tier partial body differs")
    hook = fault_hook or (lambda _point: None)
    hook("after_arm")
    revalidate()
    rooted_io.durable_write_once_bytes(destination, body)
    hook("after_output")
    revalidate()
    hook("before_commit")
    revalidate()
    record_work_unit_artifacts(
        root,
        project,
        contract,
        launch,
        run_id=run_id,
        actor="DRIVER",
        expected_output_records={output_identity: expected_record},
    )
    hook("after_commit")
    issues = validate_work_unit_artifacts(
        root,
        project,
        contract,
        launch,
        run_id=run_id,
        actor="DRIVER",
        preexecution_authority=invocation,
    )
    if issues:
        raise ArtifactLedgerError(
            "empty report-tier commit replay failed: " + "; ".join(issues)
        )
    revalidate()
    return True


def validate_committed_empty_report_tier(
    *,
    scratchpad: Path,
    project_root: Path,
    config: Mapping[str, Any],
    phase_name: str,
) -> bool:
    """Read-only replay one committed typed empty-tier transaction."""

    match = re.fullmatch(
        r"report_body_writer_(critical_high|medium|low_info)", phase_name
    )
    if match is None:
        return False
    tier = match.group(1)
    root = rooted_io.checked_directory(
        scratchpad, label="empty report-tier scratchpad"
    )
    project = rooted_io.checked_directory(
        project_root, label="empty report-tier project"
    )
    (
        run_id, pipeline, mode, ecosystem, backend,
        root_identity, project_identity,
    ) = _context(root, project, config)
    exact_inputs, raw_inputs, runtime = _upstream(
        root, project,
        dimensions=(pipeline, mode, ecosystem, backend), run_id=run_id,
    )
    if not _tier_is_empty(
        root, tier=tier, inputs=exact_inputs, runtime=runtime
    ):
        return False
    contract, launch = _transaction_pair(
        pipeline=pipeline, mode=mode, ecosystem=ecosystem, backend=backend,
        tier=tier, exact_inputs=exact_inputs,
    )
    body = _body_bytes(phase_name, tier)
    output_name = f"report_{tier}.md"
    output_identity = f"scratchpad:{output_name}"
    authority_core = {
        "schema": "plamen.empty-report-tier-invocation.v1",
        "run_id": run_id,
        "pipeline": pipeline,
        "tier": tier,
        "phase_name": phase_name,
        "scratchpad_identity": root_identity,
        "project_identity": project_identity,
        "input_records": {
            f"scratchpad:{name}": {"sha256": _sha(raw), "size": len(raw)}
            for name, raw in raw_inputs.items()
        },
        "expected_outputs": {
            output_identity: {"sha256": _sha(body), "size": len(body)}
        },
    }
    invocation = {
        **authority_core, "authority_sha256": _digest(authority_core),
    }
    ledger_before = read_artifact_ledger(root)
    unit = ledger_before.get("work_units", {}).get(contract.key)
    if not (
        isinstance(unit, Mapping)
        and unit.get("semantic_status") == "ACTIVE"
        and unit.get("execution_state") == "OUTPUT_COMMITTED"
    ):
        return False
    input_issues = validate_work_unit_inputs(
        root, project, contract, launch, run_id=run_id,
        preexecution_authority=invocation,
    )
    if input_issues:
        raise ArtifactLedgerError(
            "empty report-tier input replay failed: " + "; ".join(input_issues)
        )
    _require_bound_inputs(
        root, contract=contract, run_id=run_id, raw_inputs=raw_inputs
    )
    output_issues = validate_work_unit_artifacts(
        root, project, contract, launch, run_id=run_id, actor="DRIVER",
        preexecution_authority=invocation,
    )
    if output_issues:
        raise ArtifactLedgerError(
            "empty report-tier output replay failed: " + "; ".join(output_issues)
        )
    actual = rooted_io.read_bytes(
        root / output_name, label="committed empty report-tier body",
        require_single_link=True, max_bytes=len(body),
    )
    if actual != body:
        raise ArtifactLedgerError("committed empty report-tier body differs")
    current_inputs, current_raw, current_runtime = _upstream(
        root, project,
        dimensions=(pipeline, mode, ecosystem, backend), run_id=run_id,
    )
    if (
        _directory_identity(root, label="empty report-tier scratchpad")
        != root_identity
        or _directory_identity(project, label="empty report-tier project")
        != project_identity
        or current_inputs != exact_inputs or current_raw != raw_inputs
        or not _tier_is_empty(
            root, tier=tier, inputs=current_inputs, runtime=current_runtime
        )
        or read_artifact_ledger(root) != ledger_before
    ):
        raise ArtifactLedgerError("empty report-tier replay changed after validation")
    return True


__all__ = [
    "FAULT_POINTS", "TIERS", "run_empty_report_tier",
    "validate_committed_empty_report_tier",
]
