"""Authenticated nonempty severity-source aggregation.

This module composes only current, typed ``source_decisions.<unit>`` outputs.
It never adopts raw decision files and never authorizes later decision
successors; adjudication remains a separate transaction.
"""
from __future__ import annotations

import hashlib
import json
import stat
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Mapping

import rooted_path_io as rooted
from artifact_ledger import (
    ArtifactLedgerError,
    _canonical_json_digest,
    active_committed_work_unit_authority_issues,
    read_artifact_ledger,
    record_work_unit_artifacts,
    record_work_unit_inputs,
    semantic_input_prebind_producer_authority_issues,
    validate_work_unit_artifacts,
    validate_work_unit_inputs,
)
from phase_io_contracts import (
    LaunchSpec,
    canonical_work_unit_key,
    resolve_phase_io_contract,
)
from plamen_parsers import render_verification_queue_work_item_markdown
from queue_work_items import QueueWorkPlan, queue_records_from_json
from severity_decision_ledger import build_severity_decision_ledger
from severity_initial_source import validate_source_decisions
from verifier_work_roster import VerifierWorkRoster, VerifierWorkUnit


ROSTER_NAME = "verification_runtime_roster.json"
OUTPUT_NAME = "severity_decision_ledger.shadow.json"
INITIAL_SNAPSHOT_NAME = (
    "_severity_adjudication_inputs/source_ledger.initial.json"
)
OUTPUT_NAMES = (OUTPUT_NAME, INITIAL_SNAPSHOT_NAME)
QUEUE_INPUTS = (
    "verification_queue.md",
    "verification_queue.work_items.json",
    "verification_queue.work_plan.json",
)
FAULT_POINTS = (
    "after_arm", "after_output_1", "after_output_2", "after_output",
    "before_commit", "after_commit",
)
_SOURCE_SCHEMA = "plamen.severity-source-aggregate-authority.v1"
_INITIAL_SCHEMA = "plamen.severity-initial-source-authority.v1"
_MAX_BYTES = 64 * 1024 * 1024


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, allow_nan=False,
        sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")


def _digest(value: Any) -> str:
    return _sha(_canonical(value))


def _strict_object(raw: bytes, *, label: str) -> dict[str, Any]:
    def pairs(rows: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in rows:
            if key in value:
                raise ArtifactLedgerError(f"{label} contains duplicate key {key!r}")
            value[key] = item
        return value

    def constant(value: str) -> None:
        raise ArtifactLedgerError(f"{label} contains non-finite value {value!r}")

    try:
        value = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=pairs,
            parse_constant=constant,
        )
    except (UnicodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        raise ArtifactLedgerError(f"{label} is invalid JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise ArtifactLedgerError(f"{label} must contain one JSON object")
    return value


def _read(root: Path, relative: str, *, label: str) -> bytes:
    try:
        target = rooted.safe_descendant(
            root, relative, allow_missing=False, label=label,
        )
        return rooted.read_bytes(
            target, label=label, require_single_link=True, max_bytes=_MAX_BYTES,
        )
    except (OSError, rooted.RootedPathIOError) as exc:
        raise ArtifactLedgerError(f"{label} is unavailable: {exc}") from exc


def _relative(identity: str) -> str:
    scope, separator, relative = str(identity).partition(":")
    candidate = PurePosixPath(relative)
    if (
        separator != ":" or scope != "scratchpad" or not relative
        or candidate.as_posix() != relative or candidate.is_absolute()
        or any(part in {"", ".", ".."} for part in candidate.parts)
    ):
        raise ArtifactLedgerError(
            f"severity aggregate identity is unsupported: {identity}"
        )
    return relative


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


def _run_context(
    root: Path, project: Path, config: Mapping[str, Any],
) -> tuple[str, str, str, str, str, dict[str, Any], dict[str, Any]]:
    run_id = config.get("_run_id")
    pipeline = config.get("pipeline")
    mode = config.get("mode") or "core"
    ecosystem = config.get("language") or config.get("ecosystem") or "unknown"
    backend = config.get("cli_backend") or config.get("backend") or "claude"
    if (
        not isinstance(run_id, str) or not run_id or run_id != run_id.strip()
        or not isinstance(pipeline, str) or pipeline not in {"sc", "l1"}
        or not all(
            isinstance(value, str) and value and value == value.strip()
            for value in (mode, ecosystem, backend)
        )
    ):
        raise ArtifactLedgerError("severity aggregate run dimensions are invalid")
    configured_root = rooted.checked_directory(
        str(config.get("scratchpad") or ""),
        label="configured severity aggregate root",
    )
    configured_project = rooted.checked_directory(
        str(config.get("project_root") or ""),
        label="configured severity aggregate project",
    )
    if configured_root != root or configured_project != project:
        raise ArtifactLedgerError("severity aggregate roots differ from configuration")
    root_identity = _directory_identity(root, label="severity aggregate root")
    project_identity = _directory_identity(project, label="severity aggregate project")
    return (
        run_id, pipeline, mode, ecosystem, backend,
        root_identity, project_identity,
    )


def _stored_contract_launch(
    ledger: Mapping[str, Any], *, key: str, run_id: str, writer: str,
):
    unit = ledger.get("work_units", {}).get(key)
    if not isinstance(unit, Mapping):
        raise ArtifactLedgerError(f"severity aggregate predecessor is absent: {key}")
    manifest = unit.get("contract_manifest")
    launch_manifest = unit.get("launch_manifest")
    if not isinstance(manifest, Mapping) or not isinstance(launch_manifest, Mapping):
        raise ArtifactLedgerError(f"severity aggregate predecessor manifests are absent: {key}")
    parts = key.split("/")
    if len(parts) != 6 or manifest.get("key") != key:
        raise ArtifactLedgerError("severity aggregate predecessor key is malformed")
    immutable = manifest.get("immutable_inputs")
    bounded = manifest.get("bounded_lookup_inputs")
    output_rows = manifest.get("outputs")
    if (
        not isinstance(immutable, list) or not isinstance(bounded, list)
        or bounded or not isinstance(output_rows, list)
        or any(not isinstance(value, str) for value in immutable)
        or any(not isinstance(row, Mapping) for row in output_rows)
    ):
        raise ArtifactLedgerError("severity aggregate predecessor contract is malformed")
    exact_inputs = tuple(_relative(value) for value in immutable)
    exact_outputs = tuple(_relative(str(row.get("identity") or "")) for row in output_rows)
    conditional = tuple(
        relative for relative, row in zip(exact_outputs, output_rows, strict=True)
        if str(row.get("condition_id") or "")
    )
    condition_ids = {
        str(row.get("condition_id") or "")
        for row in output_rows if str(row.get("condition_id") or "")
    }
    if len(condition_ids) > 1:
        raise ArtifactLedgerError("severity aggregate predecessor conditions differ")
    contract = resolve_phase_io_contract(
        pipeline=parts[0], mode=parts[1], ecosystem=parts[2], backend=parts[3],
        phase=parts[4], work_unit_id=parts[5],
        exact_inputs=exact_inputs, exact_outputs=exact_outputs,
        conditional_output_ids=conditional,
        condition_id=next(iter(condition_ids), ""),
        exact_writer=writer,
    )
    expected_launch_keys = {
        "launch_version", "work_unit_key", "pipeline", "mode", "ecosystem",
        "backend", "model", "timeout_s", "exec_mode", "tool_policy",
    }
    if set(launch_manifest) != expected_launch_keys:
        raise ArtifactLedgerError("severity aggregate predecessor launch is malformed")
    launch = LaunchSpec(
        launch_version=launch_manifest["launch_version"],
        work_unit_key=launch_manifest["work_unit_key"],
        pipeline=launch_manifest["pipeline"], mode=launch_manifest["mode"],
        ecosystem=launch_manifest["ecosystem"], backend=launch_manifest["backend"],
        model=launch_manifest["model"], timeout_s=launch_manifest["timeout_s"],
        exec_mode=launch_manifest["exec_mode"],
        tool_policy=tuple(launch_manifest["tool_policy"]),
    )
    if (
        contract.to_dict() != dict(manifest)
        or contract.digest != unit.get("contract_digest")
        or launch.to_dict() != dict(launch_manifest)
        or launch.digest != unit.get("launch_digest")
        or launch.work_unit_key != contract.key
    ):
        raise ArtifactLedgerError("severity aggregate predecessor manifests differ")
    issues = active_committed_work_unit_authority_issues(
        ledger, work_unit_key=key, run_id=run_id,
        expected_artifact_identities=tuple(spec.identity for spec in contract.outputs),
    )
    if issues:
        raise ArtifactLedgerError(
            "severity aggregate predecessor commit is invalid: " + "; ".join(issues)
        )
    return contract, launch, unit


def _decision_names(root: Path) -> tuple[str, ...]:
    try:
        names: list[str] = []
        with rooted.scandir(root) as rows:
            for ordinal, entry in enumerate(rows, start=1):
                if ordinal > 1_000_000:
                    raise ArtifactLedgerError(
                        "severity aggregate root census exceeds its bound"
                    )
                names.append(entry.name)
    except OSError as exc:
        raise ArtifactLedgerError(f"severity aggregate census failed: {exc}") from exc
    selected = tuple(
        name for name in names
        if name.casefold().startswith("verify_")
        and name.casefold().endswith(".severity_decision.json")
    )
    if len(selected) != len({name.casefold() for name in selected}):
        raise ArtifactLedgerError("severity aggregate decision census has aliases")
    return selected


def _queue_roster(
    root: Path, *, pipeline: str, mode: str, ecosystem: str,
):
    queue_raw = {name: _read(root, name, label=f"severity aggregate {name}") for name in QUEUE_INPUTS}
    items = queue_records_from_json(
        queue_raw["verification_queue.work_items.json"].decode("utf-8", errors="strict")
    )
    expected_markdown = render_verification_queue_work_item_markdown(items).encode("utf-8")
    if queue_raw["verification_queue.md"] != expected_markdown:
        raise ArtifactLedgerError("severity aggregate queue Markdown differs")
    plan = QueueWorkPlan.from_json(
        queue_raw["verification_queue.work_plan.json"].decode("utf-8", errors="strict")
    )
    plan.validate_against(items)
    roster_raw = _read(root, ROSTER_NAME, label="severity aggregate verifier roster")
    roster = VerifierWorkRoster.from_json(roster_raw.decode("utf-8", errors="strict"))
    if (
        roster.pipeline != pipeline or roster.mode != mode or roster.ecosystem != ecosystem
        or roster.parent_queue_work_plan_digest != plan.digest
        or roster.ordered_work_item_ids != plan.ordered_work_item_ids
    ):
        raise ArtifactLedgerError("severity aggregate roster differs from queue/config")
    shard_by_id = {
        work_id: shard.shard_id
        for shard in plan.shards for work_id in shard.ordered_work_item_ids
    }
    for unit in roster.work_units:
        expected_shards = tuple(dict.fromkeys(
            shard_by_id[work_id] for work_id in unit.ordered_work_item_ids
        ))
        if unit.source_shard_ids != expected_shards:
            raise ArtifactLedgerError(
                f"severity aggregate unit shard provenance differs: {unit.work_unit_id}"
            )
    return queue_raw, items, plan, roster_raw, roster


def _validate_initial_unit(
    root: Path, project: Path, *, config: Mapping[str, Any], run_id: str,
    pipeline: str, mode: str, ecosystem: str, backend: str,
    roster_digest: str, unit: VerifierWorkUnit, ledger: Mapping[str, Any],
) -> dict[str, Any]:
    source_key = canonical_work_unit_key(
        pipeline, mode, ecosystem, backend, "severity_adjudication_shadow",
        f"source_decisions.{unit.work_unit_id}",
    )
    source_record = ledger.get("work_units", {}).get(source_key)
    if not isinstance(source_record, Mapping):
        raise ArtifactLedgerError(
            f"severity aggregate source unit is absent: {unit.work_unit_id}"
        )
    authority = source_record.get("preexecution_authority")
    bindings = source_record.get("input_bindings")
    if (
        not isinstance(authority, Mapping) or not isinstance(bindings, Mapping)
        or authority.get("schema") != _INITIAL_SCHEMA
        or authority.get("run_id") != run_id
        or authority.get("pipeline") != pipeline
        or authority.get("roster_digest") != roster_digest
        or authority.get("verifier_unit") != unit.to_dict()
    ):
        raise ArtifactLedgerError(
            f"severity aggregate source authority is malformed: {unit.work_unit_id}"
        )
    phase_name = authority.get("phase_name")
    if not isinstance(phase_name, str) or not phase_name or phase_name != phase_name.strip():
        raise ArtifactLedgerError("severity aggregate source phase is malformed")

    def producer(relative: str) -> str:
        row = bindings.get(f"scratchpad:{relative}")
        if not isinstance(row, Mapping):
            raise ArtifactLedgerError(
                f"severity aggregate source input is absent: {relative}"
            )
        value = row.get("producer_work_unit_key")
        if not isinstance(value, str) or not value:
            raise ArtifactLedgerError(
                f"severity aggregate source producer is absent: {relative}"
            )
        return value

    first_id = unit.ordered_work_item_ids[0]
    model_key = producer(unit.expected_output_files[0])
    control_key = producer(f"verify_{first_id}.receipt.json")
    expected_model = canonical_work_unit_key(
        pipeline, mode, ecosystem, backend, phase_name,
        f"method_model.{unit.work_unit_id}",
    )
    expected_control = canonical_work_unit_key(
        pipeline, mode, ecosystem, backend, phase_name,
        f"method_receipt.{unit.work_unit_id}",
    )
    if model_key != expected_model or control_key != expected_control:
        raise ArtifactLedgerError("severity aggregate source producer keys differ")
    for work_id, output_name in zip(
        unit.ordered_work_item_ids, unit.expected_output_files, strict=True,
    ):
        if (
            producer(output_name) != model_key
            or producer(f"verify_{work_id}.severity_proposal.json") != model_key
            or producer(f"verify_{work_id}.receipt.json") != control_key
        ):
            raise ArtifactLedgerError(
                f"severity aggregate source producer denominator differs: {work_id}"
            )
    model_contract, model_launch, _ = _stored_contract_launch(
        ledger, key=model_key, run_id=run_id, writer="MODEL",
    )
    control_contract, control_launch, _ = _stored_contract_launch(
        ledger, key=control_key, run_id=run_id, writer="DRIVER",
    )
    source_issues = validate_source_decisions(
        scratchpad=root, project_root=project, config=config,
        phase_name=phase_name, unit=unit,
        model_contract=model_contract, model_launch=model_launch,
        control_contract=control_contract, control_launch=control_launch,
    )
    if source_issues:
        raise ArtifactLedgerError(
            "severity aggregate initial source replay failed: "
            + "; ".join(source_issues)
        )
    output_identities = tuple(
        f"scratchpad:verify_{work_id}.severity_decision.json"
        for work_id in unit.ordered_work_item_ids
    )
    source_commit_issues = active_committed_work_unit_authority_issues(
        ledger, work_unit_key=source_key, run_id=run_id,
        expected_artifact_identities=output_identities,
    )
    if source_commit_issues:
        raise ArtifactLedgerError(
            "severity aggregate source commit is invalid: "
            + "; ".join(source_commit_issues)
        )
    commit = source_record.get("commit_authority")
    return {
        "work_unit_id": unit.work_unit_id,
        "source_work_unit_key": source_key,
        "source_contract_digest": source_record.get("contract_digest"),
        "source_launch_digest": source_record.get("launch_digest"),
        "source_preexecution_authority_digest": source_record.get(
            "preexecution_authority_digest"
        ),
        "source_commit_receipt_digest": (
            commit.get("receipt_digest") if isinstance(commit, Mapping) else None
        ),
        "model_work_unit_key": model_key,
        "control_work_unit_key": control_key,
    }


def _derive(
    root: Path, project: Path, *, config: Mapping[str, Any],
) -> dict[str, Any]:
    (
        run_id, pipeline, mode, ecosystem, backend,
        root_identity, project_identity,
    ) = _run_context(root, project, config)
    queue_raw, items, plan, roster_raw, roster = _queue_roster(
        root, pipeline=pipeline, mode=mode, ecosystem=ecosystem,
    )
    expected_names = tuple(
        f"verify_{item.work_item_id}.severity_decision.json" for item in items
    )
    observed_names = _decision_names(root)
    if set(observed_names) != set(expected_names):
        raise ArtifactLedgerError(
            "severity aggregate decision census differs from the typed queue"
        )
    if not items:
        return {
            "empty": True, "run_id": run_id, "pipeline": pipeline,
            "mode": mode, "ecosystem": ecosystem, "backend": backend,
        }
    ledger = read_artifact_ledger(root)
    source_rows = [
        _validate_initial_unit(
            root, project, config=config, run_id=run_id,
            pipeline=pipeline, mode=mode, ecosystem=ecosystem, backend=backend,
            roster_digest=roster.digest, unit=unit, ledger=ledger,
        )
        for unit in roster.work_units
    ]
    decisions: list[dict[str, Any]] = []
    input_rows: dict[str, dict[str, Any]] = {
        name: {"sha256": _sha(raw), "size": len(raw)}
        for name, raw in queue_raw.items()
    }
    input_rows[ROSTER_NAME] = {
        "sha256": _sha(roster_raw), "size": len(roster_raw),
    }
    for item, name in zip(items, expected_names, strict=True):
        raw = _read(root, name, label=f"severity aggregate decision {item.work_item_id}")
        decision = _strict_object(raw, label=f"severity decision {item.work_item_id}")
        if (
            decision.get("candidate_id") != item.work_item_id
            or decision.get("run_id") != run_id
        ):
            raise ArtifactLedgerError(
                f"severity aggregate decision identity differs: {item.work_item_id}"
            )
        decisions.append(decision)
        input_rows[name] = {"sha256": _sha(raw), "size": len(raw)}
    payload = build_severity_decision_ledger(run_id, decisions)
    if payload.get("authority_status") != "REPORT_AUTHORITATIVE":
        raise ArtifactLedgerError(
            "severity aggregate decisions are not current nonlegacy authority"
        )
    if [row.get("candidate_id") for row in payload.get("decisions", [])] != sorted(
        item.work_item_id for item in items
    ):
        raise ArtifactLedgerError("severity aggregate ledger denominator differs")
    output_raw = (
        json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True) + "\n"
    ).encode("utf-8")
    exact_inputs = (*QUEUE_INPUTS, ROSTER_NAME, *expected_names)
    strict_identities = tuple(
        f"scratchpad:{name}" for name in (*QUEUE_INPUTS, *expected_names)
    )
    producer_issues = semantic_input_prebind_producer_authority_issues(
        root, project, strict_identities, run_id=run_id,
    )
    if producer_issues:
        raise ArtifactLedgerError(
            "severity aggregate producer authority failed: "
            + "; ".join(producer_issues)
        )
    authority = {
        "schema": _SOURCE_SCHEMA,
        "run_id": run_id,
        "pipeline": pipeline,
        "queue_work_plan_digest": plan.digest,
        "verifier_roster_digest": roster.digest,
        "ordered_candidate_ids": list(plan.ordered_work_item_ids),
        "source_units": source_rows,
        "input_records": {name: input_rows[name] for name in sorted(input_rows)},
        "scratchpad_identity": root_identity,
        "project_root_identity": project_identity,
        "expected_outputs": {
            name: {"sha256": _sha(output_raw), "size": len(output_raw)}
            for name in OUTPUT_NAMES
        },
    }
    return {
        "empty": False,
        "run_id": run_id,
        "pipeline": pipeline,
        "mode": mode,
        "ecosystem": ecosystem,
        "backend": backend,
        "inputs": exact_inputs,
        "output": output_raw,
        "authority": authority,
    }


def _contract_launch(derived: Mapping[str, Any]):
    contract = resolve_phase_io_contract(
        pipeline=derived["pipeline"], mode=derived["mode"],
        ecosystem=derived["ecosystem"], backend=derived["backend"],
        phase="severity_adjudication_shadow", work_unit_id="source_aggregate",
        exact_inputs=tuple(derived["inputs"]), exact_outputs=OUTPUT_NAMES,
        exact_writer="DRIVER",
    )
    launch = LaunchSpec(
        work_unit_key=contract.key, pipeline=contract.pipeline, mode=contract.mode,
        ecosystem=contract.ecosystem, backend=contract.backend,
        model="driver", timeout_s=60, exec_mode="python", tool_policy=(),
    )
    return contract, launch


def _invocation(derived: Mapping[str, Any]) -> dict[str, Any]:
    core = dict(derived["authority"])
    return {**core, "authority_sha256": _canonical_json_digest(core)}


def run_severity_source_aggregate(
    *, scratchpad: Path, project_root: Path, config: Mapping[str, Any],
    fault_hook: Callable[[str], None] | None = None,
) -> bool:
    """Publish or replay the one authenticated nonempty source ledger."""

    root = rooted.checked_directory(scratchpad, label="severity aggregate root")
    project = rooted.checked_directory(project_root, label="severity aggregate project")
    derived = _derive(root, project, config=config)
    ledger = read_artifact_ledger(root)
    empty_key = canonical_work_unit_key(
        derived["pipeline"], derived["mode"], derived["ecosystem"], derived["backend"],
        "severity_adjudication_shadow", "source_aggregate",
    )
    if derived["empty"]:
        if isinstance(ledger.get("work_units", {}).get(empty_key), Mapping):
            raise ArtifactLedgerError(
                "nonempty severity aggregate transaction now has an empty queue"
            )
        return False
    contract, launch = _contract_launch(derived)
    invocation = _invocation(derived)
    prior = ledger.get("work_units", {}).get(contract.key)
    output_identities = tuple(
        f"scratchpad:{name}" for name in OUTPUT_NAMES
    )
    if not isinstance(prior, Mapping):
        if (
            any(rooted.lexists(root / name) for name in OUTPUT_NAMES)
            or any(
                isinstance(ledger.get("artifact_bindings", {}).get(identity), Mapping)
                for identity in output_identities
            )
        ):
            raise ArtifactLedgerError("severity aggregate refuses a pre-existing ledger")
        rooted.ensure_directory(
            root / Path(INITIAL_SNAPSHOT_NAME).parent,
            mode=0o700,
            label="severity aggregate snapshot directory",
        )
        record_work_unit_inputs(
            root, project, contract, launch, run_id=derived["run_id"],
            preexecution_authority=invocation,
        )
    elif (
        prior.get("run_id") != derived["run_id"]
        or prior.get("contract_digest") != contract.digest
        or prior.get("launch_digest") != launch.digest
    ):
        raise ArtifactLedgerError("severity aggregate transaction identity changed")
    issues = validate_work_unit_inputs(
        root, project, contract, launch, run_id=derived["run_id"],
        preexecution_authority=invocation,
    )
    if issues:
        raise ArtifactLedgerError("severity aggregate input replay failed: " + "; ".join(issues))
    if _derive(root, project, config=config) != derived:
        raise ArtifactLedgerError("severity aggregate source changed after arm")
    record = read_artifact_ledger(root).get("work_units", {}).get(contract.key)
    if (
        isinstance(record, Mapping)
        and record.get("semantic_status") == "ACTIVE"
        and record.get("execution_state") == "OUTPUT_COMMITTED"
    ):
        replay = validate_work_unit_artifacts(
            root, project, contract, launch, run_id=derived["run_id"],
            actor="DRIVER", preexecution_authority=invocation,
        )
        if replay:
            raise ArtifactLedgerError(
                "severity aggregate output replay failed: " + "; ".join(replay)
            )
        return True
    if not (
        isinstance(record, Mapping)
        and record.get("semantic_status") == "INPUTS_BOUND"
        and record.get("execution_state") == "INPUTS_BOUND_PREEXECUTION"
        and record.get("artifacts") == {}
    ):
        raise ArtifactLedgerError("severity aggregate is not armed")
    prestates = record.get("output_prestates")
    if (
        not isinstance(prestates, Mapping) or set(prestates) != set(output_identities)
        or any(
            not isinstance(prestates.get(identity), Mapping)
            or prestates[identity].get("status") != "ABSENT"
            for identity in output_identities
        )
    ):
        raise ArtifactLedgerError("severity aggregate requires an absent output prestate")
    for name in OUTPUT_NAMES:
        if rooted.lexists(root / name) and _read(
            root, name, label=f"severity aggregate partial output {name}",
        ) != derived["output"]:
            raise ArtifactLedgerError("severity aggregate partial output differs")
    hook = fault_hook or (lambda _point: None)
    hook("after_arm")
    if _derive(root, project, config=config) != derived:
        raise ArtifactLedgerError("severity aggregate source changed after arm")
    for ordinal, name in enumerate(OUTPUT_NAMES, 1):
        rooted.durable_write_once_bytes(root / name, derived["output"])
        hook(f"after_output_{ordinal}")
        if (
            _read(root, name, label=f"severity aggregate output {name}")
            != derived["output"]
            or _derive(root, project, config=config) != derived
        ):
            raise ArtifactLedgerError("severity aggregate changed after output")
    hook("after_output")
    if (
        any(
            _read(root, name, label=f"severity aggregate output {name}")
            != derived["output"] for name in OUTPUT_NAMES
        )
        or _derive(root, project, config=config) != derived
    ):
        raise ArtifactLedgerError("severity aggregate changed after output")
    hook("before_commit")
    if (
        any(
            _read(root, name, label=f"severity aggregate output {name}")
            != derived["output"] for name in OUTPUT_NAMES
        )
        or _derive(root, project, config=config) != derived
    ):
        raise ArtifactLedgerError("severity aggregate changed before commit")
    expected = {
        identity: {
            "sha256": _sha(derived["output"]), "size": len(derived["output"]),
        }
        for identity in output_identities
    }
    record_work_unit_artifacts(
        root, project, contract, launch, run_id=derived["run_id"], actor="DRIVER",
        expected_output_records=expected,
    )
    replay = validate_work_unit_artifacts(
        root, project, contract, launch, run_id=derived["run_id"],
        actor="DRIVER", preexecution_authority=invocation,
    )
    if replay:
        raise ArtifactLedgerError("severity aggregate commit replay failed: " + "; ".join(replay))
    hook("after_commit")
    if _derive(root, project, config=config) != derived:
        raise ArtifactLedgerError("severity aggregate source changed after commit")
    final = validate_work_unit_artifacts(
        root, project, contract, launch, run_id=derived["run_id"],
        actor="DRIVER", preexecution_authority=invocation,
    )
    if final:
        raise ArtifactLedgerError("severity aggregate post-commit replay failed: " + "; ".join(final))
    return True


def validate_severity_source_aggregate(
    *, scratchpad: Path, project_root: Path, config: Mapping[str, Any],
) -> tuple[str, ...]:
    """Read-only replay of the current nonempty severity source aggregate."""

    try:
        root = rooted.checked_directory(scratchpad, label="severity aggregate root")
        project = rooted.checked_directory(project_root, label="severity aggregate project")
        derived = _derive(root, project, config=config)
        ledger = read_artifact_ledger(root)
        key = canonical_work_unit_key(
            derived["pipeline"], derived["mode"], derived["ecosystem"], derived["backend"],
            "severity_adjudication_shadow", "source_aggregate",
        )
        if derived["empty"]:
            if isinstance(ledger.get("work_units", {}).get(key), Mapping):
                return ("empty queue has a nonempty severity aggregate producer",)
            return ()
        contract, launch = _contract_launch(derived)
        invocation = _invocation(derived)
        issues = validate_work_unit_inputs(
            root, project, contract, launch, run_id=derived["run_id"],
            preexecution_authority=invocation,
        )
        issues.extend(validate_work_unit_artifacts(
            root, project, contract, launch, run_id=derived["run_id"],
            actor="DRIVER", preexecution_authority=invocation,
        ))
        return tuple(dict.fromkeys(str(issue) for issue in issues if str(issue)))
    except Exception as exc:
        return (f"severity source aggregate invalid: {type(exc).__name__}: {exc}",)


__all__ = [
    "FAULT_POINTS", "INITIAL_SNAPSHOT_NAME", "OUTPUT_NAME", "OUTPUT_NAMES",
    "QUEUE_INPUTS", "ROSTER_NAME",
    "run_severity_source_aggregate", "validate_severity_source_aggregate",
]
