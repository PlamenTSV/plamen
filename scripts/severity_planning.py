"""Typed DRIVER publication boundary for immutable severity planning.

The publisher consumes the registered initial severity-source snapshot and
the exact live snapshot/config/methodology capture. It derives every planning
postimage before arming, then supports only sealed partial recovery or strict
read-only committed replay. It does not execute adjudication workers and does
not establish MODEL or candidate-execution authority.
"""
from __future__ import annotations

import hashlib
import json
import stat
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Mapping

import rooted_path_io as rio
from artifact_ledger import (
    ArtifactLedgerError,
    _canonical_json_digest,
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
from severity_adjudication_work import (
    MANIFEST_NAME,
    WORK_PLAN_NAME,
    derive_adjudication_work,
    validate_prepared_work,
)
from severity_planning_inputs import (
    SOURCE_LEDGER_INPUT,
    capture_severity_planning_inputs,
    validate_initial_severity_source_input,
)


FAULT_POINTS = (
    "after_arm",
    "after_output_N",
    "before_commit",
    "after_commit",
)
PHASE = "severity_adjudication_shadow"
WORK_UNIT = "planning"
_MAX_BYTES = 32 * 1024 * 1024
_REQUIRED_ARGS = frozenset({
    "backend",
    "transport",
    "effective_model",
    "working_directory",
    "source_root",
    "tool_policy",
    "environment_allowlist_digest",
    "adjudicator_identity",
    "invocation_prefix",
    "timeout_seconds_per_worker",
    "max_items_per_worker",
    "max_weight_per_worker",
    "max_context_bytes_per_worker",
})


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _digest(value: Mapping[str, Any]) -> str:
    return _sha(_canonical(dict(value)))


def _dimensions(config: Mapping[str, Any]) -> tuple[str, str, str, str, str]:
    run_id = config.get("_run_id")
    pipeline = str(config.get("pipeline") or "").strip().lower()
    mode = str(config.get("mode") or "").strip().lower()
    ecosystem = str(
        config.get("language") or config.get("ecosystem") or ""
    ).strip().lower()
    backend = str(
        config.get("cli_backend") or config.get("backend") or ""
    ).strip().lower()
    if (
        not isinstance(run_id, str)
        or not run_id
        or run_id != run_id.strip()
        or pipeline not in {"sc", "l1"}
        or not mode
        or not ecosystem
        or not backend
    ):
        raise ArtifactLedgerError("severity planning dimensions are invalid")
    return run_id, pipeline, mode, ecosystem, backend


def _relative(value: Any, *, label: str) -> str:
    raw = str(value or "")
    path = PurePosixPath(raw)
    if (
        not raw
        or path.is_absolute()
        or path.as_posix() != raw
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise ArtifactLedgerError(f"{label} is not a safe relative path")
    return raw


def _read(root: Path, relative: str, *, label: str) -> bytes:
    try:
        return rio.read_bytes(
            root / relative,
            label=label,
            require_single_link=True,
            max_bytes=_MAX_BYTES,
        )
    except (OSError, rio.RootedPathIOError) as exc:
        raise ArtifactLedgerError(f"{label} is unavailable: {exc}") from exc


def _planning_key(config: Mapping[str, Any]) -> str:
    _run, pipeline, mode, ecosystem, backend = _dimensions(config)
    return canonical_work_unit_key(
        pipeline, mode, ecosystem, backend, PHASE, WORK_UNIT,
    )


def _launch(contract: Any) -> LaunchSpec:
    return LaunchSpec(
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


def _contract(
    config: Mapping[str, Any],
    *,
    inputs: tuple[str, ...],
    outputs: tuple[str, ...],
) -> tuple[Any, LaunchSpec]:
    _run, pipeline, mode, ecosystem, backend = _dimensions(config)
    contract = resolve_phase_io_contract(
        pipeline=pipeline,
        mode=mode,
        ecosystem=ecosystem,
        backend=backend,
        phase=PHASE,
        work_unit_id=WORK_UNIT,
        exact_inputs=inputs,
        exact_outputs=outputs,
        exact_writer="DRIVER",
    )
    return contract, _launch(contract)


def _normalize_planning_args(value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != _REQUIRED_ARGS:
        raise ArtifactLedgerError("severity planning argument denominator differs")
    # The pure derivation API owns the field-specific type/range validation.
    # Freeze the JSON-domain representation here so mutable caller objects
    # cannot change the invocation after arm.
    try:
        normalized = json.loads(_canonical(dict(value)).decode("utf-8"))
    except (TypeError, ValueError, UnicodeError) as exc:
        raise ArtifactLedgerError("severity planning arguments are invalid") from exc
    if not isinstance(normalized, dict) or set(normalized) != _REQUIRED_ARGS:
        raise ArtifactLedgerError("severity planning arguments changed on freeze")
    return normalized


def _require_planning_arg_authority(
    args: Mapping[str, Any],
    *,
    root: Path,
    project: Path,
    config_backend: str,
) -> None:
    if args.get("backend") != config_backend:
        raise ArtifactLedgerError(
            "severity planning backend differs from its PhaseIO contract"
        )
    try:
        source = rio.checked_directory(
            str(args.get("source_root") or ""),
            label="severity planning source root",
        )
        working = rio.checked_directory(
            str(args.get("working_directory") or ""),
            label="severity planning working directory",
        )
    except (OSError, rio.RootedPathIOError) as exc:
        raise ArtifactLedgerError(
            f"severity planning argument root is invalid: {exc}"
        ) from exc
    if source != project:
        raise ArtifactLedgerError(
            "severity planning source root differs from project authority"
        )
    if working not in {root, project}:
        raise ArtifactLedgerError(
            "severity planning working directory is outside admitted roots"
        )


def _capture_view(value: Mapping[str, Any]) -> dict[str, Any]:
    required = {
        "schema",
        "phase_io_owner_key",
        "exact_inputs",
        "methodology_files",
        "audit_snapshot_digest",
        "audit_config_digest",
        "source_ledger_path",
        "source_ledger_digest",
    }
    if not isinstance(value, Mapping) or set(value) != required:
        raise ArtifactLedgerError("severity planning capture result is incomplete")
    exact_inputs = tuple(
        _relative(item, label="severity planning input")
        for item in value["exact_inputs"]
    )
    if len(exact_inputs) != len(set(exact_inputs)) or len(exact_inputs) != len({
        item.casefold() for item in exact_inputs
    }):
        raise ArtifactLedgerError("severity planning inputs collide")
    if exact_inputs[0] != SOURCE_LEDGER_INPUT:
        raise ArtifactLedgerError("immutable source snapshot is outside exact inputs")
    return {
        **dict(value),
        "exact_inputs": exact_inputs,
        "source_ledger_snapshot": SOURCE_LEDGER_INPUT,
    }


def _owner_keys(
    root: Path,
    project: Path,
    config: Mapping[str, Any],
    capture: Mapping[str, Any],
) -> dict[str, str]:
    _raw, source_binding = validate_initial_severity_source_input(
        root, project, config=config,
    )
    if not isinstance(source_binding, Mapping):
        raise ArtifactLedgerError("severity planning source binding is absent")
    owners = {SOURCE_LEDGER_INPUT: str(source_binding.get("owner_key") or "")}
    for name in capture["exact_inputs"][1:]:
        owners[name] = str(capture["phase_io_owner_key"])
    if not all(owners.values()):
        raise ArtifactLedgerError("severity planning producer owner is absent")
    return owners


def _read_inputs(root: Path, names: tuple[str, ...]) -> dict[str, bytes]:
    return {
        name: _read(root, name, label=f"severity planning input {name}")
        for name in names
    }


def _directory_identity(path: Path, *, label: str) -> dict[str, Any]:
    """Return the stable identity fields that publication must conserve.

    Directory timestamps and link counts legitimately change as the durable
    transaction writes children, so they are deliberately not authority
    fields.  Type, mode, owner, device, and inode must remain exact.
    """

    try:
        observed = path.lstat()
    except OSError as exc:
        raise ArtifactLedgerError(f"{label} identity is unavailable: {exc}") from exc
    if not stat.S_ISDIR(observed.st_mode):
        raise ArtifactLedgerError(f"{label} is not a directory")
    return {
        "path": str(path),
        "device": int(observed.st_dev),
        "inode": int(observed.st_ino),
        "mode": stat.S_IMODE(observed.st_mode),
        "uid": int(observed.st_uid),
        "gid": int(observed.st_gid),
    }


def _root_identities(
    root: Path, project: Path, implementation: Path,
) -> dict[str, dict[str, Any]]:
    return {
        "scratchpad": _directory_identity(
            root, label="severity planning scratchpad",
        ),
        "project": _directory_identity(
            project, label="severity planning project",
        ),
        "implementation": _directory_identity(
            implementation, label="severity planning implementation root",
        ),
    }


def _require_producers(
    root: Path,
    project: Path,
    *,
    contract: Any,
    run_id: str,
    inputs: Mapping[str, bytes],
    owner_keys: Mapping[str, str],
) -> None:
    identities = tuple(f"scratchpad:{name}" for name in inputs)
    prebind = semantic_input_prebind_producer_authority_issues(
        root, project, identities, run_id=run_id,
    )
    if prebind:
        raise ArtifactLedgerError(
            "severity planning producer prebind failed: " + "; ".join(prebind)
        )
    ledger = read_artifact_ledger(root)
    unit = ledger.get("work_units", {}).get(contract.key)
    bindings = unit.get("input_bindings") if isinstance(unit, Mapping) else None
    if not isinstance(bindings, Mapping) or set(bindings) != set(identities):
        raise ArtifactLedgerError("severity planning input binding roster differs")
    for name, raw in inputs.items():
        identity = f"scratchpad:{name}"
        row = bindings.get(identity)
        if not isinstance(row, Mapping) or (
            row.get("sha256") != _sha(raw)
            or row.get("size") != len(raw)
            or row.get("producer_work_unit_key") != owner_keys[name]
            or row.get("producer_writer") != "DRIVER"
            or row.get("producer_run_id") != run_id
        ):
            raise ArtifactLedgerError(
                f"severity planning input producer mismatch: {identity}"
            )
        issues = semantic_input_producer_authority_issues(
            ledger, row, run_id=run_id,
        )
        if issues:
            raise ArtifactLedgerError(
                f"severity planning producer invalid for {identity}: "
                + "; ".join(issues)
            )


def _require_current_producers(
    root: Path,
    project: Path,
    *,
    run_id: str,
    inputs: Mapping[str, bytes],
    owner_keys: Mapping[str, str],
) -> None:
    identities = tuple(f"scratchpad:{name}" for name in inputs)
    prebind = semantic_input_prebind_producer_authority_issues(
        root, project, identities, run_id=run_id,
    )
    if prebind:
        raise ArtifactLedgerError(
            "severity planning current producer prebind failed: "
            + "; ".join(prebind)
        )
    ledger = read_artifact_ledger(root)
    bindings = ledger.get("artifact_bindings")
    if not isinstance(bindings, Mapping):
        raise ArtifactLedgerError(
            "severity planning artifact binding table is absent"
        )
    for name, raw in inputs.items():
        identity = f"scratchpad:{name}"
        row = bindings.get(identity)
        if not isinstance(row, Mapping) or (
            row.get("owner_key") != owner_keys[name]
            or row.get("writer") != "DRIVER"
            or row.get("run_id") != run_id
            or row.get("sha256") != _sha(raw)
            or row.get("size") != len(raw)
            or row.get("status") != "ACTIVE"
        ):
            raise ArtifactLedgerError(
                f"severity planning current producer mismatch: {identity}"
            )


_PLANNING_NAMESPACES = (
    ("severity_adjudication_context.", ".json"),
    ("severity_adjudication_prompt.", ".md"),
    ("severity_adjudication_launch_intent.", ".json"),
    ("severity_adjudication_tool_policy.", ".json"),
)


def _is_planning_namespace(name: str) -> bool:
    folded = name.casefold()
    return any(
        folded.startswith(prefix) and folded.endswith(suffix)
        for prefix, suffix in _PLANNING_NAMESPACES
    )


def _require_planning_census(
    root: Path,
    output_names: tuple[str, ...],
    *,
    require_complete: bool,
) -> None:
    expected = {
        name.casefold(): name
        for name in output_names
        if _is_planning_namespace(name)
    }
    observed: dict[str, str] = {}
    try:
        with rio.scandir(root) as entries:
            for entry in entries:
                if not _is_planning_namespace(entry.name):
                    continue
                folded = entry.name.casefold()
                if folded in observed:
                    raise ArtifactLedgerError(
                        "severity planning namespace has a case collision"
                    )
                observed[folded] = entry.name
    except OSError as exc:
        raise ArtifactLedgerError(
            f"severity planning namespace census failed: {exc}"
        ) from exc
    foreign = sorted(
        name
        for folded, name in observed.items()
        if folded not in expected or expected[folded] != name
    )
    if foreign:
        raise ArtifactLedgerError(
            "severity planning refuses stale namespace files: "
            + ", ".join(foreign[:16])
        )
    if require_complete and set(observed) != set(expected):
        raise ArtifactLedgerError(
            "severity planning namespace output roster is incomplete"
        )


def _require_source_state(
    root: Path,
    project: Path,
    implementation: Path,
    *,
    run_id: str,
    input_names: tuple[str, ...],
    inputs: Mapping[str, bytes],
    owner_keys: Mapping[str, str],
    root_identities: Mapping[str, Mapping[str, Any]],
) -> None:
    if _root_identities(root, project, implementation) != root_identities:
        raise ArtifactLedgerError("severity planning root identity changed")
    if rio.lexists(root / "skeptic_challenges.json"):
        raise ArtifactLedgerError(
            "severity planning refuses an unauthenticated skeptic input"
        )
    if _read_inputs(root, input_names) != inputs:
        raise ArtifactLedgerError("severity planning immutable inputs changed")
    _require_current_producers(
        root,
        project,
        run_id=run_id,
        inputs=inputs,
        owner_keys=owner_keys,
    )


def _require_boundary(
    root: Path,
    project: Path,
    implementation: Path,
    *,
    contract: Any,
    run_id: str,
    input_names: tuple[str, ...],
    inputs: Mapping[str, bytes],
    owner_keys: Mapping[str, str],
    root_identities: Mapping[str, Mapping[str, Any]],
    output_names: tuple[str, ...],
    require_complete: bool = False,
) -> None:
    _require_source_state(
        root,
        project,
        implementation,
        run_id=run_id,
        input_names=input_names,
        inputs=inputs,
        owner_keys=owner_keys,
        root_identities=root_identities,
    )
    _require_producers(
        root,
        project,
        contract=contract,
        run_id=run_id,
        inputs=inputs,
        owner_keys=owner_keys,
    )
    _require_planning_census(
        root, output_names, require_complete=require_complete,
    )


def _expected_records(outputs: Mapping[str, bytes]) -> dict[str, dict[str, Any]]:
    return {
        f"scratchpad:{name}": {"sha256": _sha(raw), "size": len(raw)}
        for name, raw in outputs.items()
    }


def _output_roster(plan: Mapping[str, Any]) -> tuple[str, ...]:
    shards = plan.get("shards")
    if not isinstance(shards, list):
        raise ArtifactLedgerError("severity planning shard roster is malformed")
    names = [MANIFEST_NAME, WORK_PLAN_NAME]
    for shard in shards:
        if not isinstance(shard, Mapping):
            raise ArtifactLedgerError("severity planning shard row is malformed")
        names.extend((
            _relative(shard.get("context_file"), label="planning context file"),
            _relative(shard.get("prompt_file"), label="planning prompt file"),
            _relative(
                shard.get("tool_policy_file"), label="planning tool-policy file",
            ),
            _relative(
                shard.get("launch_intent_file"), label="planning launch-intent file",
            ),
        ))
    if len(names) != len(set(names)) or len(names) != len({
        name.casefold() for name in names
    }):
        raise ArtifactLedgerError("severity planning output roster collides")
    return tuple(names)


def _invocation(
    *,
    run_id: str,
    capture: Mapping[str, Any],
    inputs: Mapping[str, bytes],
    outputs: Mapping[str, bytes],
    planning_args: Mapping[str, Any],
    root_identities: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    core = {
        "schema": "plamen.severity-planning-invocation.v1",
        "run_id": run_id,
        "capture_owner_key": capture["phase_io_owner_key"],
        "source_ledger_snapshot": capture["source_ledger_snapshot"],
        "source_ledger_digest": capture["source_ledger_digest"],
        "inputs": {
            f"scratchpad:{name}": {"sha256": _sha(raw), "size": len(raw)}
            for name, raw in inputs.items()
        },
        "planning_args_sha256": _digest(planning_args),
        "root_identities": dict(root_identities),
        "output_names": list(outputs),
        "expected_outputs": _expected_records(outputs),
    }
    return {**core, "authority_sha256": _canonical_json_digest(core)}


def _authority_from_prior(prior: Mapping[str, Any]) -> Mapping[str, Any]:
    authority = prior.get("preexecution_authority")
    if not isinstance(authority, Mapping):
        raise ArtifactLedgerError("committed severity planning authority is absent")
    unsigned = {key: value for key, value in authority.items() if key != "authority_sha256"}
    if (
        authority.get("schema") != "plamen.severity-planning-invocation.v1"
        or authority.get("authority_sha256")
        != _canonical_json_digest(unsigned)
    ):
        raise ArtifactLedgerError("committed severity planning authority is invalid")
    return authority


def _replay_committed(
    *,
    root: Path,
    project: Path,
    config: Mapping[str, Any],
    prior: Mapping[str, Any],
    capture: Mapping[str, Any],
    inputs: Mapping[str, bytes],
    owner_keys: Mapping[str, str],
    planning_args: Mapping[str, Any],
    implementation: Path,
    root_identities: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    run_id, _pipeline, _mode, _ecosystem, _backend = _dimensions(config)
    authority = _authority_from_prior(prior)
    output_names = tuple(
        _relative(name, label="committed severity planning output")
        for name in authority.get("output_names", ())
    )
    if not output_names or len(output_names) != len(set(output_names)):
        raise ArtifactLedgerError("committed severity planning output roster differs")
    contract, launch = _contract(
        config, inputs=tuple(inputs), outputs=output_names,
    )
    if (
        prior.get("run_id") != run_id
        or prior.get("contract_digest") != contract.digest
        or prior.get("launch_digest") != launch.digest
        or authority.get("capture_owner_key") != capture["phase_io_owner_key"]
        or authority.get("source_ledger_snapshot")
        != capture["source_ledger_snapshot"]
        or authority.get("source_ledger_digest") != capture["source_ledger_digest"]
        or authority.get("planning_args_sha256") != _digest(planning_args)
        or authority.get("root_identities") != root_identities
        or authority.get("inputs") != {
            f"scratchpad:{name}": {"sha256": _sha(raw), "size": len(raw)}
            for name, raw in inputs.items()
        }
    ):
        raise ArtifactLedgerError("committed severity planning identity changed")
    input_names = tuple(inputs)
    _require_boundary(
        root,
        project,
        implementation,
        contract=contract,
        run_id=run_id,
        input_names=input_names,
        inputs=inputs,
        owner_keys=owner_keys,
        root_identities=root_identities,
        output_names=output_names,
        require_complete=True,
    )
    input_issues = validate_work_unit_inputs(
        root, project, contract, launch, run_id=run_id,
        preexecution_authority=authority,
    )
    if input_issues:
        raise ArtifactLedgerError(
            "committed severity planning input replay failed: "
            + "; ".join(input_issues)
        )
    _require_producers(
        root, project, contract=contract, run_id=run_id,
        inputs=inputs, owner_keys=owner_keys,
    )
    output_issues = validate_work_unit_artifacts(
        root, project, contract, launch, run_id=run_id,
        actor="DRIVER", preexecution_authority=authority,
    )
    if output_issues:
        raise ArtifactLedgerError(
            "committed severity planning output replay failed: "
            + "; ".join(output_issues)
        )
    issues = validate_prepared_work(root)
    if issues:
        raise ArtifactLedgerError(
            "committed severity planning semantic replay failed: "
            + "; ".join(issues)
        )
    try:
        plan = json.loads(_read(
            root, WORK_PLAN_NAME, label="committed severity work plan",
        ).decode("utf-8", errors="strict"))
    except (UnicodeError, ValueError, TypeError) as exc:
        raise ArtifactLedgerError("committed severity work plan is invalid") from exc
    if not isinstance(plan, dict):
        raise ArtifactLedgerError("committed severity work plan is not an object")
    if _output_roster(plan) != output_names:
        raise ArtifactLedgerError("committed severity planning roster changed")
    _require_boundary(
        root,
        project,
        implementation,
        contract=contract,
        run_id=run_id,
        input_names=input_names,
        inputs=inputs,
        owner_keys=owner_keys,
        root_identities=root_identities,
        output_names=output_names,
        require_complete=True,
    )
    return plan


def run_severity_planning(
    *,
    scratchpad: Path,
    project_root: Path,
    implementation_root: Path,
    config: Mapping[str, Any],
    planning_args: Mapping[str, Any],
    fault_hook: Callable[[str], None] | None = None,
    expected_source_ledger_digest: str | None = None,
) -> dict[str, Any]:
    """Publish or read-only replay one immutable severity planning unit."""

    if (
        expected_source_ledger_digest is not None
        and (
            type(expected_source_ledger_digest) is not str
            or len(expected_source_ledger_digest) != 64
            or any(
                character not in "0123456789abcdef"
                for character in expected_source_ledger_digest
            )
        )
    ):
        raise ArtifactLedgerError(
            "expected severity source digest is not lowercase SHA-256"
        )
    root = rio.checked_directory(scratchpad, label="severity planning scratchpad")
    project = rio.checked_directory(project_root, label="severity planning project")
    implementation = rio.checked_directory(
        implementation_root, label="severity planning implementation root",
    )
    if rio.checked_directory(
        str(config.get("scratchpad") or ""), label="configured severity scratchpad",
    ) != root or rio.checked_directory(
        str(config.get("project_root") or ""), label="configured severity project",
    ) != project:
        raise ArtifactLedgerError("severity planning configured roots differ")
    run_id, _pipeline, _mode, _ecosystem, config_backend = _dimensions(config)
    args = _normalize_planning_args(planning_args)
    _require_planning_arg_authority(
        args, root=root, project=project, config_backend=config_backend,
    )
    root_identities = _root_identities(root, project, implementation)
    capture = _capture_view(capture_severity_planning_inputs(
        scratchpad=root,
        project_root=project,
        implementation_root=implementation,
        config=config,
    ))
    # Rejoin the selector against this invocation's authenticated fresh
    # capture, before deriving, arming or replaying the planning transaction.
    # An expected digest is a constraint, never a replacement for capture.
    if (
        expected_source_ledger_digest is not None
        and capture["source_ledger_digest"] != expected_source_ledger_digest
    ):
        raise ArtifactLedgerError(
            "severity planning capture differs from selected source"
        )
    if Path(capture["source_ledger_path"]) != root / SOURCE_LEDGER_INPUT:
        raise ArtifactLedgerError("severity planning source path differs")
    input_names = tuple(capture["exact_inputs"])
    inputs = _read_inputs(root, input_names)
    if _sha(inputs[SOURCE_LEDGER_INPUT]) != capture["source_ledger_digest"]:
        raise ArtifactLedgerError("severity planning source snapshot digest differs")
    if rio.lexists(root / "skeptic_challenges.json"):
        raise ArtifactLedgerError(
            "severity planning refuses an unauthenticated skeptic input"
        )
    owner_keys = _owner_keys(root, project, config, capture)
    key = _planning_key(config)
    prior = read_artifact_ledger(root).get("work_units", {}).get(key)
    if isinstance(prior, Mapping) and (
        prior.get("semantic_status") == "ACTIVE"
        and prior.get("execution_state") == "OUTPUT_COMMITTED"
    ):
        # Deliberately no postimage derivation on committed replay.
        return _replay_committed(
            root=root, project=project, config=config, prior=prior,
            capture=capture, inputs=inputs, owner_keys=owner_keys,
            planning_args=args, implementation=implementation,
            root_identities=root_identities,
        )

    manifest, plan, raw_outputs = derive_adjudication_work(
        root,
        run_id=run_id,
        audit_snapshot_digest=capture["audit_snapshot_digest"],
        audit_config_digest=capture["audit_config_digest"],
        methodology_files=capture["methodology_files"],
        source_ledger_path=SOURCE_LEDGER_INPUT,
        expected_source_ledger_digest=capture["source_ledger_digest"],
        **args,
    )
    if not isinstance(manifest, Mapping) or not isinstance(plan, Mapping):
        raise ArtifactLedgerError("severity planning pure derivation is malformed")
    outputs = {
        _relative(name, label="severity planning output"): bytes(raw)
        for name, raw in raw_outputs.items()
    }
    if (
        not outputs
        or len(outputs) != len({name.casefold() for name in outputs})
        or any(not raw for raw in outputs.values())
    ):
        raise ArtifactLedgerError("severity planning output denominator is invalid")
    output_names = tuple(outputs)
    if any(PurePosixPath(name).parent != PurePosixPath(".") for name in output_names):
        raise ArtifactLedgerError("severity planning outputs are not flat")
    if _output_roster(plan) != output_names:
        raise ArtifactLedgerError("severity planning pure output roster differs")
    contract, launch = _contract(
        config, inputs=input_names, outputs=output_names,
    )
    invocation = _invocation(
        run_id=run_id, capture=capture, inputs=inputs,
        outputs=outputs, planning_args=args,
        root_identities=root_identities,
    )
    expected = _expected_records(outputs)
    # Pure derivation may be expensive. Revalidate the exact current global
    # producers and root authorities after it and before leaving any armed row.
    _require_source_state(
        root,
        project,
        implementation,
        run_id=run_id,
        input_names=input_names,
        inputs=inputs,
        owner_keys=owner_keys,
        root_identities=root_identities,
    )
    _require_planning_census(
        root, output_names, require_complete=False,
    )
    ledger = read_artifact_ledger(root)
    prior = ledger.get("work_units", {}).get(contract.key)
    if not isinstance(prior, Mapping):
        bindings = ledger.get("artifact_bindings")
        if any(
            rio.lexists(root / name)
            or (
                isinstance(bindings, Mapping)
                and isinstance(bindings.get(f"scratchpad:{name}"), Mapping)
            )
            for name in output_names
        ):
            raise ArtifactLedgerError("severity planning refuses foreign outputs")
        record_work_unit_inputs(
            root, project, contract, launch, run_id=run_id,
            preexecution_authority=invocation,
        )
    elif (
        prior.get("run_id") != run_id
        or prior.get("contract_digest") != contract.digest
        or prior.get("launch_digest") != launch.digest
        or prior.get("preexecution_authority") != invocation
    ):
        raise ArtifactLedgerError("severity planning armed transaction changed")
    input_issues = validate_work_unit_inputs(
        root, project, contract, launch, run_id=run_id,
        preexecution_authority=invocation,
    )
    if input_issues:
        raise ArtifactLedgerError(
            "severity planning input replay failed: " + "; ".join(input_issues)
        )
    _require_producers(
        root, project, contract=contract, run_id=run_id,
        inputs=inputs, owner_keys=owner_keys,
    )
    unit = read_artifact_ledger(root).get("work_units", {}).get(contract.key)
    if not (
        isinstance(unit, Mapping)
        and unit.get("semantic_status") == "INPUTS_BOUND"
        and unit.get("execution_state") == "INPUTS_BOUND_PREEXECUTION"
        and unit.get("artifacts") == {}
    ):
        raise ArtifactLedgerError("severity planning transaction is not armed")
    prestates = unit.get("output_prestates")
    if (
        not isinstance(prestates, Mapping)
        or set(prestates) != set(expected)
        or any(
            not isinstance(prestates.get(identity), Mapping)
            or prestates[identity].get("status") != "ABSENT"
            for identity in expected
        )
    ):
        raise ArtifactLedgerError("severity planning requires absent prestates")
    for name, raw in outputs.items():
        if rio.lexists(root / name) and _read(
            root, name, label=f"severity planning partial {name}",
        ) != raw:
            raise ArtifactLedgerError(
                f"severity planning partial output differs: {name}"
            )

    hook = fault_hook or (lambda _point: None)
    hook("after_arm")
    _require_boundary(
        root, project, implementation, contract=contract, run_id=run_id,
        input_names=input_names, inputs=inputs, owner_keys=owner_keys,
        root_identities=root_identities,
        output_names=output_names,
    )
    for ordinal, (name, raw) in enumerate(outputs.items(), 1):
        _require_boundary(
            root, project, implementation, contract=contract, run_id=run_id,
            input_names=input_names, inputs=inputs, owner_keys=owner_keys,
            root_identities=root_identities,
            output_names=output_names,
        )
        destination = root / name
        if not rio.lexists(destination):
            rio.durable_write_once_bytes(destination, raw)
        elif _read(root, name, label=f"severity planning partial {name}") != raw:
            raise ArtifactLedgerError(
                f"severity planning partial output differs: {name}"
            )
        hook(f"after_output_{ordinal}")
        _require_boundary(
            root, project, implementation, contract=contract, run_id=run_id,
            input_names=input_names, inputs=inputs, owner_keys=owner_keys,
            root_identities=root_identities,
            output_names=output_names,
        )
    hook("before_commit")
    _require_boundary(
        root, project, implementation, contract=contract, run_id=run_id,
        input_names=input_names, inputs=inputs, owner_keys=owner_keys,
        root_identities=root_identities,
        output_names=output_names,
        require_complete=True,
    )
    if {
        name: _read(root, name, label=f"severity planning output {name}")
        for name in output_names
    } != outputs:
        raise ArtifactLedgerError("severity planning output bytes changed before commit")
    record_work_unit_artifacts(
        root, project, contract, launch, run_id=run_id, actor="DRIVER",
        expected_output_records=expected,
    )
    output_issues = validate_work_unit_artifacts(
        root, project, contract, launch, run_id=run_id,
        actor="DRIVER", preexecution_authority=invocation,
    )
    if output_issues:
        raise ArtifactLedgerError(
            "severity planning commit replay failed: " + "; ".join(output_issues)
        )
    validation_issues = validate_prepared_work(root)
    if validation_issues:
        raise ArtifactLedgerError(
            "severity planning semantic validation failed: "
            + "; ".join(validation_issues)
        )
    hook("after_commit")
    committed = read_artifact_ledger(root).get("work_units", {}).get(contract.key)
    if not isinstance(committed, Mapping):
        raise ArtifactLedgerError("committed severity planning row is absent")
    current_inputs = _read_inputs(root, input_names)
    if current_inputs != inputs:
        raise ArtifactLedgerError("severity planning inputs changed after commit")
    return _replay_committed(
        root=root,
        project=project,
        config=config,
        prior=committed,
        capture=capture,
        inputs=current_inputs,
        owner_keys=owner_keys,
        planning_args=args,
        implementation=implementation,
        root_identities=root_identities,
    )


__all__ = ["FAULT_POINTS", "run_severity_planning"]
