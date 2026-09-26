"""Typed initial severity decisions derived from committed verifier units."""
from __future__ import annotations

import hashlib
import json
import stat
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Mapping, Sequence

import rooted_path_io as rooted
from artifact_ledger import (
    ArtifactLedgerError,
    _ArtifactValidationContext,
    _artifact_validation_epoch,
    _canonical_json_digest,
    _producer_authority_is_active,
    _registered_successor_bundle_member_authority,
    _replay_output_commit_authority,
    read_artifact_ledger,
    record_work_unit_artifacts,
    record_work_unit_inputs,
    semantic_input_prebind_producer_authority_issues,
    stored_committed_work_unit_authority_issues,
    validate_work_unit_artifacts,
    validate_work_unit_inputs,
)
from phase_io_contracts import LaunchSpec, resolve_phase_io_contract
from plamen_parsers import _read_typed_queue_work_items, read_queue_work_plan
from queue_work_items import VerifierOutputReceipt
from severity_decision_ledger import (
    LAUNCH_RECEIPT_SCHEMA,
    bind_severity_proposal,
    parse_severity_proposal,
    severity_assessor_input_digest,
    severity_proposal_authority_digest,
)
from severity_runtime import _proposal_evidence_receipts, _strict_json_bytes
from verifier_model_execution_authority import (
    replay_verifier_gate_model_execution_authority,
    validated_verifier_model_execution_read_set,
)
from verifier_work_roster import (
    VerifierLaunchSpec,
    VerifierUnitReceipt,
    VerifierWorkRoster,
    VerifierWorkUnit,
)


ROSTER_NAME = "verification_runtime_roster.json"
UNIT_ROOT = "_verifier_runtime_units"
QUEUE_INPUTS = (
    "verification_queue.md",
    "verification_queue.work_items.json",
    "verification_queue.work_plan.json",
)
FAULT_POINTS = (
    "after_arm",
    "after_output",
    "after_output_<ordinal>",
    "before_commit",
    "after_commit",
)
_MAX_BYTES = 32 * 1024 * 1024


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, allow_nan=False,
        sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")


def _digest(value: Any) -> str:
    return _sha(_canonical(value))


def _invocation_authority(core: Mapping[str, Any]) -> dict[str, Any]:
    unsigned = dict(core)
    return {
        **unsigned,
        "authority_sha256": _canonical_json_digest(unsigned),
    }


def _relative(identity: str) -> str:
    scope, separator, relative = str(identity).partition(":")
    candidate = PurePosixPath(relative)
    if (
        separator != ":" or scope != "scratchpad" or not relative
        or candidate.as_posix() != relative or candidate.is_absolute()
        or any(part in {"", ".", ".."} for part in candidate.parts)
    ):
        raise ArtifactLedgerError(
            f"severity initial source identity is unsupported: {identity}"
        )
    return relative


def _read(root: Path, relative: str, *, label: str) -> bytes:
    try:
        return rooted.read_bytes(
            rooted.safe_descendant(
                root, relative, allow_missing=False, label=label,
            ),
            label=label,
            require_single_link=True,
            max_bytes=_MAX_BYTES,
        )
    except (OSError, rooted.RootedPathIOError) as exc:
        raise ArtifactLedgerError(f"{label} is unavailable: {exc}") from exc


def _directory_identity(path: Path, *, label: str) -> dict[str, Any]:
    checked = rooted.checked_directory(path, label=label)
    try:
        row = rooted.lstat(checked)
    except OSError as exc:
        raise ArtifactLedgerError(f"{label} identity is unavailable: {exc}") from exc
    if not stat.S_ISDIR(row.st_mode):
        raise ArtifactLedgerError(f"{label} is not a directory")
    return {
        "absolute_path": str(checked),
        "device": int(row.st_dev),
        "inode": int(row.st_ino),
        "file_type": stat.S_IFMT(row.st_mode),
        "mode": stat.S_IMODE(row.st_mode),
    }


def _configured_roots(
    root: Path, project: Path, config: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    configured_root = rooted.checked_directory(
        str(config.get("scratchpad") or ""),
        label="configured severity initial source root",
    )
    configured_project = rooted.checked_directory(
        str(config.get("project_root") or ""),
        label="configured severity initial source project",
    )
    if configured_root != root or configured_project != project:
        raise ArtifactLedgerError(
            "severity initial source roots differ from configuration"
        )
    return (
        _directory_identity(root, label="severity initial source root"),
        _directory_identity(project, label="severity initial source project"),
    )


def _unit_paths(unit_id: str) -> dict[str, str]:
    prefix = f"{UNIT_ROOT}/{unit_id}"
    return {
        "launch": f"{prefix}/launch_spec.json",
        "dispatch": f"{prefix}/method_dispatch.json",
        "gate": f"{prefix}/gate_receipt.json",
        "receipt": f"{prefix}/unit_receipt.json",
        "debt": f"{prefix}/debt.json",
    }


def _exact_run(config: Mapping[str, Any]) -> tuple[str, str]:
    run_id = config.get("_run_id")
    pipeline = config.get("pipeline")
    if (
        not isinstance(run_id, str) or not run_id
        or run_id != run_id.strip()
        or not isinstance(pipeline, str)
        or pipeline not in {"sc", "l1"}
    ):
        raise ArtifactLedgerError(
            "severity initial source requires an exact SC or L1 run"
        )
    return run_id, pipeline


def _replay_pair(
    root: Path,
    project: Path,
    *,
    config: Mapping[str, Any],
    unit: VerifierWorkUnit,
    model_contract: Any,
    model_launch: LaunchSpec,
    control_contract: Any,
    control_launch: LaunchSpec,
) -> tuple[str, str]:
    run_id, pipeline = _exact_run(config)
    expected_dimensions = (
        pipeline,
        str(config.get("mode") or "core"),
        str(config.get("language") or config.get("ecosystem") or "unknown"),
        str(config.get("cli_backend") or config.get("backend") or "claude"),
    )
    for contract, launch, prefix, writer in (
        (model_contract, model_launch, "method_model.", "MODEL"),
        (control_contract, control_launch, "method_receipt.", "DRIVER"),
    ):
        if (
            tuple(
                getattr(contract, field, None)
                for field in ("pipeline", "mode", "ecosystem", "backend")
            ) != expected_dimensions
            or getattr(contract, "phase", None) != str(config.get("_severity_phase") or "")
            or getattr(contract, "work_unit_id", None)
            != prefix + unit.work_unit_id
            or getattr(launch, "work_unit_key", None)
            != getattr(contract, "key", None)
            or (writer == "MODEL") != bool(getattr(contract, "model_invoked", False))
        ):
            raise ArtifactLedgerError(
                f"severity initial source {writer} contract is not exact"
            )
    if model_launch.model == "driver" or control_launch.model != "driver":
        raise ArtifactLedgerError(
            "severity initial source launch writers are invalid"
        )
    # These four checks form one read-only epoch. Keep every validator and
    # finish-time drift check, but share their exact producer/file snapshots.
    # Never carry this context across a source arm, write, commit, or retry.
    with _artifact_validation_epoch(root, project) as validation_context:
        model_issues = validate_work_unit_inputs(
            root, project, model_contract, model_launch, run_id=run_id,
            _validation_context=validation_context,
        )
        model_issues.extend(validate_work_unit_artifacts(
            root, project, model_contract, model_launch,
            run_id=run_id, actor="MODEL",
            _validation_context=validation_context,
        ))
        control_issues = validate_work_unit_inputs(
            root, project, control_contract, control_launch, run_id=run_id,
            _validation_context=validation_context,
        )
        control_issues.extend(validate_work_unit_artifacts(
            root, project, control_contract, control_launch,
            run_id=run_id, actor="DRIVER",
            _validation_context=validation_context,
        ))
        issues = [*model_issues, *control_issues]
    if issues:
        raise ArtifactLedgerError(
            "severity initial source verifier PhaseIO replay failed: "
            + "; ".join(issues)
        )
    return run_id, pipeline


def _derive(
    root: Path,
    project: Path,
    *,
    config: Mapping[str, Any],
    phase_name: str,
    unit: VerifierWorkUnit,
    model_contract: Any,
    model_launch: LaunchSpec,
    control_contract: Any,
    control_launch: LaunchSpec,
) -> tuple[dict[str, bytes], tuple[str, ...], dict[str, Any]]:
    run_id, pipeline = _exact_run(config)
    if (
        not isinstance(phase_name, str) or not phase_name
        or phase_name != phase_name.strip()
    ):
        raise ArtifactLedgerError("severity initial source phase is invalid")
    replay_config = dict(config)
    replay_config["_severity_phase"] = phase_name
    _replay_pair(
        root, project, config=replay_config, unit=unit,
        model_contract=model_contract, model_launch=model_launch,
        control_contract=control_contract, control_launch=control_launch,
    )

    roster_raw = _read(root, ROSTER_NAME, label="severity verifier roster")
    roster = VerifierWorkRoster.from_json(
        roster_raw.decode("utf-8", errors="strict")
    )
    try:
        canonical_unit = VerifierWorkUnit.from_dict(unit.to_dict())
    except (AttributeError, TypeError, ValueError) as exc:
        raise ArtifactLedgerError(
            f"severity initial source unit is malformed: {exc}"
        ) from exc
    if canonical_unit != unit:
        raise ArtifactLedgerError("severity initial source unit changes on replay")
    roster_units = [row for row in roster.work_units if row.work_unit_id == unit.work_unit_id]
    if (
        len(roster_units) != 1 or roster_units[0] != unit
        or roster.pipeline != pipeline
        or roster.mode != str(config.get("mode") or "core")
        or roster.ecosystem
        != str(config.get("language") or config.get("ecosystem") or "unknown")
    ):
        raise ArtifactLedgerError(
            "severity initial source verifier roster/unit differs"
        )
    plan = read_queue_work_plan(root)
    if (
        plan.digest != roster.parent_queue_work_plan_digest
        or tuple(plan.ordered_work_item_ids) != roster.ordered_work_item_ids
    ):
        raise ArtifactLedgerError(
            "severity initial source queue/roster assignment differs"
        )
    queue_items = _read_typed_queue_work_items(root / "verification_queue.md")
    plan.validate_against(queue_items)
    items = {item.work_item_id: item for item in queue_items}
    if tuple(items[work_id].digest for work_id in unit.ordered_work_item_ids) != (
        unit.queue_record_digests
    ):
        raise ArtifactLedgerError(
            "severity initial source queue records differ from unit"
        )
    shard_by_work_id = {
        work_id: shard.shard_id
        for shard in plan.shards
        for work_id in shard.ordered_work_item_ids
    }
    expected_source_shards = tuple(dict.fromkeys(
        shard_by_work_id[work_id] for work_id in unit.ordered_work_item_ids
    ))
    if unit.source_shard_ids != expected_source_shards:
        raise ArtifactLedgerError(
            "severity initial source shard provenance differs from queue plan"
        )

    paths = _unit_paths(unit.work_unit_id)
    launch_raw = _read(root, paths["launch"], label="severity verifier launch")
    launch_spec = VerifierLaunchSpec.from_json(
        launch_raw.decode("utf-8", errors="strict")
    )
    gate_raw = _read(root, paths["gate"], label="severity verifier gate")
    gate = _strict_json_bytes(gate_raw)
    receipt_raw = _read(root, paths["receipt"], label="severity verifier unit receipt")
    unit_receipt = VerifierUnitReceipt.from_json(
        receipt_raw.decode("utf-8", errors="strict")
    )
    dispatch_raw = _read(root, paths["dispatch"], label="severity method dispatch")
    dispatch = _strict_json_bytes(dispatch_raw)
    if not isinstance(gate, Mapping) or not isinstance(dispatch, Mapping):
        raise ArtifactLedgerError("severity verifier gate/dispatch is malformed")
    if (
        unit_receipt.status != "COMPLETED"
        or unit_receipt.work_unit_id != unit.work_unit_id
        or unit_receipt.work_unit_resume_digest != unit.resume_digest
        or unit_receipt.launch_spec_digest != launch_spec.digest
        or unit_receipt.gate_receipt_digests != (_sha(gate_raw),)
        or gate.get("state") != "CLEAN"
        or gate.get("work_unit_id") != unit.work_unit_id
        or gate.get("work_unit_resume_digest") != unit.resume_digest
        or gate.get("roster_digest") != roster.digest
        or gate.get("launch_spec_digest") != launch_spec.digest
        or gate.get("method_dispatch_id") != dispatch.get("dispatch_id")
        or gate.get("method_dispatch_sha256") != _sha(dispatch_raw)
        or gate.get("ordered_work_item_ids") != list(unit.ordered_work_item_ids)
        or launch_spec.work_unit_id != unit.work_unit_id
        or launch_spec.work_unit_resume_digest != unit.resume_digest
        or launch_spec.expected_output_files != unit.expected_output_files
        or launch_spec.backend != model_launch.backend
        or launch_spec.model != model_launch.model
        or launch_spec.timeout_seconds != model_launch.timeout_s
        or launch_spec.transport != model_launch.exec_mode
    ):
        raise ArtifactLedgerError(
            "severity verifier completion binding differs"
        )

    ledger = read_artifact_ledger(root)
    model_unit = ledger.get("work_units", {}).get(model_contract.key)
    if not isinstance(model_unit, Mapping):
        raise ArtifactLedgerError("severity verifier MODEL unit is absent")
    execution_paths = validated_verifier_model_execution_read_set(
        root, owner_key=model_contract.key, unit=model_unit,
    )
    authority_names = {
        ROSTER_NAME, *paths.values(), *execution_paths,
    }
    input_names = {ROSTER_NAME, *QUEUE_INPUTS}
    input_names.update(_relative(spec.identity) for spec in model_contract.outputs)
    input_names.update(_relative(spec.identity) for spec in control_contract.outputs)
    model_output_names = {
        _relative(spec.identity) for spec in model_contract.outputs
    }
    control_output_names = {
        _relative(spec.identity) for spec in control_contract.outputs
    }
    if not {paths["gate"], paths["receipt"], paths["debt"]}.issubset(
        control_output_names
    ):
        raise ArtifactLedgerError(
            "severity verifier control output denominator is incomplete"
        )

    outputs: dict[str, bytes] = {}
    verified_output_hashes: dict[str, str] = {}
    receipt_digests: list[str] = []
    gate_authority = ""
    for work_id, output_name, output_identity in zip(
        unit.ordered_work_item_ids,
        unit.expected_output_files,
        unit.expected_output_identities,
        strict=True,
    ):
        if output_identity != f"scratchpad:{output_name}":
            raise ArtifactLedgerError(
                "severity verifier output identity differs from roster"
            )
        item = items[work_id]
        output_raw = _read(root, output_name, label=f"severity verifier output {work_id}")
        verified_output_hashes[output_name] = _sha(output_raw)
        proposal_name = f"verify_{work_id}.severity_proposal.json"
        receipt_name = f"verify_{work_id}.receipt.json"
        if (
            output_name not in model_output_names
            or proposal_name not in model_output_names
            or receipt_name not in control_output_names
        ):
            raise ArtifactLedgerError(
                f"severity verifier producer denominator is incomplete for {work_id}"
            )
        proposal_raw = _read(root, proposal_name, label=f"severity proposal {work_id}")
        proposal = parse_severity_proposal(proposal_raw)
        verifier_receipt_raw = _read(
            root, receipt_name, label=f"severity verifier receipt {work_id}",
        )
        verifier_receipt = VerifierOutputReceipt.from_json(
            verifier_receipt_raw.decode("utf-8", errors="strict")
        )
        verifier_receipt.validate_against(
            item, plan, output_raw, severity_proposal=proposal_raw,
            launch_digest=launch_spec.digest,
            verifier_backend=launch_spec.backend,
        )
        replayed = replay_verifier_gate_model_execution_authority(
            root, gate,
            selected_output_identity=output_identity,
            expected_run_id=run_id,
            expected_owner_suffix=f"/method_model.{unit.work_unit_id}",
        )
        if gate_authority and replayed != gate_authority:
            raise ArtifactLedgerError(
                "severity verifier outputs have different MODEL authority"
            )
        gate_authority = replayed
        constituents = [item.work_item_id, *item.constituents]
        evidence = _proposal_evidence_receipts(
            proposal,
            constituents=constituents,
            verify_receipt=verifier_receipt,
            verify_markdown=output_raw.decode("utf-8", errors="strict"),
            launch_digest=launch_spec.digest,
        )
        assessor = f"verifier-{launch_spec.backend}-{phase_name}"
        invocation = f"{launch_spec.digest}-{work_id}"
        launch_receipt = {
            "schema_version": LAUNCH_RECEIPT_SCHEMA,
            "role": "ASSESSOR",
            "run_id": run_id,
            "candidate_id": work_id,
            "constituent_ids": constituents,
            "worker_identity": assessor,
            "invocation_id": invocation,
            "backend": launch_spec.backend,
            "launch_manifest_sha256": launch_spec.digest,
            "input_sha256": severity_assessor_input_digest(
                candidate_id=work_id,
                constituent_ids=constituents,
                upstream_severity=item.severity_proposal.level,
                run_id=run_id,
                source_receipt_digest=verifier_receipt.digest,
                evidence_receipts=evidence,
            ),
            "output_sha256": severity_proposal_authority_digest(proposal),
        }
        decision = bind_severity_proposal(
            proposal,
            candidate_id=work_id,
            constituent_ids=constituents,
            upstream_severity=item.severity_proposal.level,
            assessor_identity=assessor,
            assessor_invocation_id=invocation,
            run_id=run_id,
            source_receipt_digest=verifier_receipt.digest,
            evidence_receipts=evidence,
            assessor_launch_receipt=launch_receipt,
        )
        outputs[f"verify_{work_id}.severity_decision.json"] = _canonical(decision)
        receipt_digests.append(_sha(verifier_receipt_raw))
        input_names.update((output_name, proposal_name, receipt_name))

    if unit_receipt.output_receipt_digests != tuple(receipt_digests):
        raise ArtifactLedgerError(
            "severity verifier output receipt denominator differs"
        )
    producer_issues = semantic_input_prebind_producer_authority_issues(
        root,
        project,
        tuple(f"scratchpad:{name}" for name in sorted(input_names - {ROSTER_NAME})),
        run_id=run_id,
    )
    if producer_issues:
        raise ArtifactLedgerError(
            "severity initial source producer authority failed: "
            + "; ".join(producer_issues)
        )
    if gate.get("output_sha256") != verified_output_hashes:
        raise ArtifactLedgerError("severity verifier gate output denominator differs")
    authority_rows: dict[str, dict[str, Any]] = {}
    for name in sorted(authority_names):
        raw = _read(root, name, label=f"severity authority {name}")
        authority_rows[name] = {"sha256": _sha(raw), "size": len(raw)}
    root_identity, project_identity = _configured_roots(root, project, config)
    authority = {
        "schema": "plamen.severity-initial-source-authority.v1",
        "run_id": run_id,
        "pipeline": pipeline,
        "phase_name": phase_name,
        "verifier_unit": unit.to_dict(),
        "roster_digest": roster.digest,
        "launch_spec_digest": launch_spec.digest,
        "model_execution_authority_digest": gate_authority,
        "scratchpad_identity": root_identity,
        "project_root_identity": project_identity,
        "authority_read_set": authority_rows,
    }
    return outputs, tuple(sorted(input_names)), authority


def _source_contract(
    config: Mapping[str, Any], unit: VerifierWorkUnit,
    inputs: tuple[str, ...], outputs: tuple[str, ...],
):
    contract = resolve_phase_io_contract(
        pipeline=str(config["pipeline"]),
        mode=str(config.get("mode") or "core"),
        ecosystem=str(config.get("language") or config.get("ecosystem") or "unknown"),
        backend=str(config.get("cli_backend") or config.get("backend") or "claude"),
        phase="severity_adjudication_shadow",
        work_unit_id=f"source_decisions.{unit.work_unit_id}",
        exact_inputs=inputs,
        exact_outputs=outputs,
        exact_writer="DRIVER",
    )
    launch = LaunchSpec(
        work_unit_key=contract.key, pipeline=contract.pipeline,
        mode=contract.mode, ecosystem=contract.ecosystem,
        backend=contract.backend, model="driver", timeout_s=60,
        exec_mode="python", tool_policy=(),
    )
    return contract, launch


def _expected_records(outputs: Mapping[str, bytes]) -> dict[str, dict[str, Any]]:
    return {
        f"scratchpad:{name}": {"sha256": _sha(raw), "size": len(raw)}
        for name, raw in outputs.items()
    }


def publish_source_decisions(
    *, scratchpad: Path, project_root: Path, config: Mapping[str, Any],
    phase_name: str, unit: VerifierWorkUnit,
    model_contract: Any, model_launch: LaunchSpec,
    control_contract: Any, control_launch: LaunchSpec,
    fault_hook: Callable[[str], None] | None = None,
) -> tuple[Path, ...]:
    """Publish exact per-unit decision sidecars without an aggregate write."""

    root = rooted.checked_directory(scratchpad, label="severity initial source root")
    project = rooted.checked_directory(project_root, label="severity initial source project")
    if not isinstance(unit, VerifierWorkUnit):
        raise ArtifactLedgerError("severity initial source unit type is invalid")
    outputs, inputs, authority = _derive(
        root, project, config=config, phase_name=phase_name, unit=unit,
        model_contract=model_contract, model_launch=model_launch,
        control_contract=control_contract, control_launch=control_launch,
    )
    output_names = tuple(outputs)
    records = _expected_records(outputs)
    authority_core = {**authority, "expected_outputs": records}
    invocation = _invocation_authority(authority_core)
    contract, launch = _source_contract(config, unit, inputs, output_names)
    run_id, _pipeline = _exact_run(config)
    ledger = read_artifact_ledger(root)
    prior = ledger.get("work_units", {}).get(contract.key)
    if not isinstance(prior, Mapping):
        bindings = ledger.get("artifact_bindings", {})
        if any(
            rooted.lexists(root / name)
            or isinstance(bindings.get(f"scratchpad:{name}"), Mapping)
            for name in output_names
        ):
            raise ArtifactLedgerError(
                "severity initial source refuses pre-existing decision bytes"
            )
        record_work_unit_inputs(
            root, project, contract, launch, run_id=run_id,
            preexecution_authority=invocation,
        )
    elif (
        prior.get("run_id") != run_id
        or prior.get("contract_digest") != contract.digest
        or prior.get("launch_digest") != launch.digest
    ):
        raise ArtifactLedgerError(
            "severity initial source transaction identity changed"
        )
    issues = validate_work_unit_inputs(
        root, project, contract, launch, run_id=run_id,
        preexecution_authority=invocation,
    )
    if issues:
        raise ArtifactLedgerError(
            "severity initial source input replay failed: " + "; ".join(issues)
        )
    current = _derive(
        root, project, config=config, phase_name=phase_name, unit=unit,
        model_contract=model_contract, model_launch=model_launch,
        control_contract=control_contract, control_launch=control_launch,
    )
    if current != (outputs, inputs, authority):
        raise ArtifactLedgerError("severity initial source changed after arm")
    unit_record = read_artifact_ledger(root).get("work_units", {}).get(contract.key)
    if (
        isinstance(unit_record, Mapping)
        and unit_record.get("semantic_status") == "ACTIVE"
        and unit_record.get("execution_state") == "OUTPUT_COMMITTED"
    ):
        replay_issues = validate_work_unit_artifacts(
            root, project, contract, launch, run_id=run_id,
            actor="DRIVER", preexecution_authority=invocation,
        )
        if replay_issues:
            raise ArtifactLedgerError(
                "severity initial source output replay failed: "
                + "; ".join(replay_issues)
            )
        return tuple(root / name for name in output_names)
    if not (
        isinstance(unit_record, Mapping)
        and unit_record.get("semantic_status") == "INPUTS_BOUND"
        and unit_record.get("execution_state") == "INPUTS_BOUND_PREEXECUTION"
        and unit_record.get("artifacts") == {}
    ):
        raise ArtifactLedgerError("severity initial source is not armed")
    prestates = unit_record.get("output_prestates")
    if (
        not isinstance(prestates, Mapping) or set(prestates) != set(records)
        or any(
            not isinstance(prestates.get(identity), Mapping)
            or prestates[identity].get("status") != "ABSENT"
            for identity in records
        )
    ):
        raise ArtifactLedgerError(
            "severity initial source requires absent decision prestates"
        )
    for name, raw in outputs.items():
        if rooted.lexists(root / name) and _read(
            root, name, label=f"severity initial partial {name}"
        ) != raw:
            raise ArtifactLedgerError(
                f"severity initial source partial output differs: {name}"
            )
    hook = fault_hook or (lambda _point: None)
    hook("after_arm")
    if _derive(
        root, project, config=config, phase_name=phase_name, unit=unit,
        model_contract=model_contract, model_launch=model_launch,
        control_contract=control_contract, control_launch=control_launch,
    ) != (outputs, inputs, authority):
        raise ArtifactLedgerError("severity initial source changed after arm")
    published: dict[str, bytes] = {}
    for ordinal, (name, raw) in enumerate(outputs.items(), start=1):
        rooted.durable_write_once_bytes(root / name, raw)
        published[name] = raw
        hook(f"after_output_{ordinal}")
        for published_name, published_raw in published.items():
            if _read(
                root, published_name,
                label=f"severity initial published {published_name}",
            ) != published_raw:
                raise ArtifactLedgerError(
                    f"severity initial source output changed: {published_name}"
                )
        if _derive(
            root, project, config=config, phase_name=phase_name, unit=unit,
            model_contract=model_contract, model_launch=model_launch,
            control_contract=control_contract, control_launch=control_launch,
        ) != (outputs, inputs, authority):
            raise ArtifactLedgerError(
                f"severity initial source changed after output {ordinal}"
            )
    hook("after_output")
    for name, raw in outputs.items():
        if _read(root, name, label=f"severity initial published {name}") != raw:
            raise ArtifactLedgerError(
                f"severity initial source output changed: {name}"
            )
    hook("before_commit")
    for name, raw in outputs.items():
        if _read(root, name, label=f"severity initial published {name}") != raw:
            raise ArtifactLedgerError(
                f"severity initial source output changed: {name}"
            )
    if _derive(
        root, project, config=config, phase_name=phase_name, unit=unit,
        model_contract=model_contract, model_launch=model_launch,
        control_contract=control_contract, control_launch=control_launch,
    ) != (outputs, inputs, authority):
        raise ArtifactLedgerError("severity initial source changed before commit")
    record_work_unit_artifacts(
        root, project, contract, launch, run_id=run_id,
        actor="DRIVER", expected_output_records=records,
    )
    replay_issues = validate_work_unit_artifacts(
        root, project, contract, launch, run_id=run_id,
        actor="DRIVER", preexecution_authority=invocation,
    )
    if replay_issues:
        raise ArtifactLedgerError(
            "severity initial source commit replay failed: "
            + "; ".join(replay_issues)
        )
    hook("after_commit")
    if _derive(
        root, project, config=config, phase_name=phase_name, unit=unit,
        model_contract=model_contract, model_launch=model_launch,
        control_contract=control_contract, control_launch=control_launch,
    ) != (outputs, inputs, authority):
        raise ArtifactLedgerError("severity initial source changed after commit")
    final_issues = validate_work_unit_artifacts(
        root, project, contract, launch, run_id=run_id,
        actor="DRIVER", preexecution_authority=invocation,
    )
    if final_issues:
        raise ArtifactLedgerError(
            "severity initial source post-commit replay failed: "
            + "; ".join(final_issues)
        )
    return tuple(root / name for name in output_names)


def _historical_source_output_issues(
    root: Path, project: Path, contract: Any, *, run_id: str,
    expected_records: Mapping[str, Mapping[str, Any]],
    validation_context: _ArtifactValidationContext,
) -> list[str]:
    ledger = validation_context.ledger
    issues = stored_committed_work_unit_authority_issues(
        ledger, work_unit_key=contract.key, run_id=run_id,
        expected_artifact_identities=tuple(expected_records),
    )
    if issues:
        return issues
    unit = ledger["work_units"][contract.key]
    commit = unit["commit_authority"]
    if (
        commit.get("output_authority_actor") != "DRIVER"
        or commit.get("expected_output_records") != expected_records
        or unit.get("successor_consumption_authority") is not None
        or unit.get("committed_output_repair_history") is not None
    ):
        return [f"{contract.key}: historical initial-source commit differs"]
    exemptions: list[str] = []
    binding_fields = (
        "identity", "owner_key", "run_id", "contract_digest",
        "launch_digest", "status", "size", "sha256", "writer",
        "write_mode", "authority_level", "physical_identity",
    )
    for identity, expected in expected_records.items():
        historical = unit["artifacts"][identity]
        current = ledger.get("artifact_bindings", {}).get(identity)
        if not isinstance(current, Mapping):
            issues.append(f"{identity}: current source/successor binding missing")
            continue
        if current.get("owner_key") == contract.key:
            if (
                any(current.get(field) != historical.get(field)
                    for field in binding_fields)
                or not _producer_authority_is_active(
                    ledger, current, identity=identity, run_id=run_id,
                )
            ):
                issues.append(f"{identity}: unchanged source binding differs")
            # The original whole-bundle CAS replay below witnesses unchanged
            # live bytes and physical identity, including finish-time drift.
            continue
        if not _registered_successor_bundle_member_authority(
            root, project, ledger, historical,
            identity=identity, expected_record=expected,
            _validation_context=validation_context,
        ):
            issues.append(f"{identity}: registered source successor proof failed")
            continue
        exemptions.append(identity)
    if issues:
        return issues
    issues.extend(_replay_output_commit_authority(
        root, project, unit, require_live_bytes=True,
        live_byte_exempt_identities=tuple(sorted(exemptions)),
        _validation_context=validation_context,
    ))
    return list(dict.fromkeys(issues))


def _source_authority_failures(issues: Sequence[str]) -> tuple[str, ...]:
    """Keep failed source authority non-consumable at the driver gate.

    These are artifact-authority failures, not severity conclusions. Historical
    replay diagnostics must retain the same blocking class as strict replay;
    their human-readable wording is not permission to consume partial outputs.
    """
    return tuple(dict.fromkeys(
        f"PRODUCER_AUTHORITY_MISMATCH: severity initial source: {issue}"
        for issue in issues if str(issue).strip()
    ))


def validate_source_decisions(
    *, scratchpad: Path, project_root: Path, config: Mapping[str, Any],
    phase_name: str, unit: VerifierWorkUnit,
    model_contract: Any, model_launch: LaunchSpec,
    control_contract: Any, control_launch: LaunchSpec,
    allow_registered_successors: bool = False,
) -> tuple[str, ...]:
    """Replay source authority, optionally through registered decision successors.

    Only completed-verifier gates opt into historical output replay. Initial
    aggregate publication must still require the unchanged current source.
    """

    try:
        root = rooted.checked_directory(scratchpad, label="severity initial source root")
        project = rooted.checked_directory(project_root, label="severity initial source project")
        if not isinstance(unit, VerifierWorkUnit):
            raise ArtifactLedgerError("severity initial source unit type is invalid")
        outputs, inputs, authority = _derive(
            root, project, config=config, phase_name=phase_name, unit=unit,
            model_contract=model_contract, model_launch=model_launch,
            control_contract=control_contract, control_launch=control_launch,
        )
        contract, launch = _source_contract(
            config, unit, inputs, tuple(outputs),
        )
        records = _expected_records(outputs)
        authority_core = {**authority, "expected_outputs": records}
        invocation = _invocation_authority(authority_core)
        run_id, _pipeline = _exact_run(config)
        with _artifact_validation_epoch(
            root, project
        ) as validation_context:
            issues = validate_work_unit_inputs(
                root, project, contract, launch, run_id=run_id,
                preexecution_authority=invocation,
                _validation_context=validation_context,
            )
            if allow_registered_successors:
                issues.extend(_historical_source_output_issues(
                    root, project, contract, run_id=run_id,
                    expected_records=records,
                    validation_context=validation_context,
                ))
            else:
                issues.extend(validate_work_unit_artifacts(
                    root, project, contract, launch, run_id=run_id,
                    actor="DRIVER", preexecution_authority=invocation,
                    _validation_context=validation_context,
                ))
        return _source_authority_failures(issues)
    except Exception as exc:
        return _source_authority_failures((
            f"severity initial source authority invalid: {type(exc).__name__}: {exc}",
        ))


__all__ = [
    "FAULT_POINTS", "QUEUE_INPUTS", "ROSTER_NAME", "UNIT_ROOT",
    "publish_source_decisions", "validate_source_decisions",
]
