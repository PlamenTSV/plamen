"""Ordered successor transaction for one severity candidate.

This deterministic component binds the next exact planning-denominator item
using the completed worker's authority and sealed successor postimages. It
does not itself establish MODEL/provider execution authority. The live audit
handler cutover is separate from this component's integration validation.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
import os
from pathlib import Path, PurePosixPath
import re
import stat
from types import MappingProxyType
from typing import Any, Callable, Mapping

from artifact_ledger import (
    ArtifactLedgerError,
    _canonical_json_digest,
    begin_driver_successor_step,
    complete_driver_successor_step,
    load_driver_successor_plan,
    plan_driver_successor_transaction,
    read_artifact_ledger,
    record_work_unit_artifacts,
    record_work_unit_inputs,
    validate_driver_successor_transaction,
    validate_historical_driver_successor_transaction,
    validate_work_unit_artifacts,
    validate_work_unit_inputs,
)
from phase_io_contracts import (
    LaunchSpec,
    canonical_work_unit_key,
    driver_successor_plan_from_dict,
    resolve_phase_io_contract,
)
import rooted_path_io as rio
from driver_successor_io import materialize_driver_successor_transition
from severity_adjudication_work import (
    AdjudicationWorkError,
    MANIFEST_NAME,
    WORK_PLAN_NAME,
    validate_completed_worker_run_for_candidate,
    validate_prepared_work,
)
from severity_bind_postimage_cas import (
    load_severity_bind_postimages,
    seal_severity_bind_postimages,
)
from severity_bind_postimages import (
    SeverityBindPostimageError,
    _worker_authority_paths,
    derive_shadow_adjudication_postimages,
)


PHASE = "severity_adjudication_shadow"
FAULT_POINTS = (
    "after_stage", "after_arm", "after_output_1", "after_output_2",
    "after_output_3", "before_commit", "after_commit",
)
_INITIAL_SNAPSHOT = "_severity_adjudication_inputs/source_ledger.initial.json"
_AGGREGATE = "severity_decision_ledger.shadow.json"
_CANDIDATE = re.compile(r"^[A-Za-z][A-Za-z0-9-]{0,95}$", re.ASCII)
_HEX64 = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
_MAX_BYTES = 32 * 1024 * 1024
_AUTHORITY_FIELDS = frozenset({
    "schema", "run_id", "ordinal", "candidate_id",
    "denominator_sha256", "work_unit_key", "contract_digest",
    "launch_digest", "worker_run_digest", "worker_arguments",
    "input_names", "output_names", "read_set", "expected_outputs",
    "successor_plan_digest", "invocation_digest", "postimage_cas",
    "authority_sha256",
})
_PLANNING_AUTHORITY_FIELDS = frozenset({
    "schema", "run_id", "capture_owner_key", "source_ledger_snapshot",
    "source_ledger_digest", "inputs", "planning_args_sha256",
    "root_identities", "output_names", "expected_outputs",
    "authority_sha256",
})
_UNOWNED_RUNTIME_INPUT_FIELDS = frozenset({
    "identity", "input_class", "mtime_ns", "status", "sha256", "size",
    "producer_commit_receipt_digest", "producer_contract_digest",
    "producer_launch_digest", "producer_run_id", "producer_work_unit_key",
    "producer_writer",
})
_EMPTY_PRODUCER_FIELDS = frozenset({
    "producer_commit_receipt_digest", "producer_contract_digest",
    "producer_launch_digest", "producer_run_id", "producer_work_unit_key",
    "producer_writer",
})
_RUNTIME_EVIDENCE_KINDS = frozenset({
    "WORKER_RUN", "POSIX_COMPAT_RECEIPT", "TRANSACTION_COMPLETION",
    "PROVIDER_COMPLETION", "TRANSACTION_INCORPORATION", "TRANSACTION_PLAN",
    "PROVIDER_ARM", "PROVIDER_PUBLISH",
})
_COMPAT_WORKER_SCHEMA = "plamen.severity_adjudication_worker_run.posix_compat.v1"
_NATIVE_WORKER_SCHEMA = "plamen.severity_adjudication_worker_run.v2"


@dataclass(frozen=True)
class CompletedSeverityBindPrefix:
    """Immutable current-state view after exact historical bind replay."""

    candidate_ids: tuple[str, ...]
    input_names: tuple[str, ...]
    read_set: Mapping[str, bytes]
    bind_authority_digests: tuple[str, ...]
    absence_records: Mapping[str, str]
    authority_digest: str


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical(value: Mapping[str, Any]) -> bytes:
    return json.dumps(
        dict(value), ensure_ascii=False, allow_nan=False,
        sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")


def _digest(value: Mapping[str, Any]) -> str:
    return _sha(_canonical(value))


def _denominator_digest(denominator: tuple[str, ...]) -> str:
    return _sha(_canonical({"candidate_ids": list(denominator)}))


def _strict_object(raw: bytes, *, label: str) -> dict[str, Any]:
    def pairs(rows: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in rows:
            if key in result:
                raise ArtifactLedgerError(f"{label} has duplicate key {key!r}")
            result[key] = value
        return result

    def constant(token: str) -> None:
        raise ArtifactLedgerError(f"{label} has non-finite value {token!r}")

    try:
        value = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=pairs,
            parse_constant=constant,
        )
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise ArtifactLedgerError(f"{label} is invalid JSON") from exc
    if not isinstance(value, dict):
        raise ArtifactLedgerError(f"{label} is not an object")
    return value


def _read(root: Path, name: str, *, label: str) -> bytes:
    name = _relative(name, label=label)
    path = PurePosixPath(name)
    try:
        return rio.read_bytes(
            root.joinpath(*path.parts), label=label,
            max_bytes=_MAX_BYTES, require_single_link=True,
        )
    except (OSError, rio.RootedPathIOError) as exc:
        raise ArtifactLedgerError(f"{label} is unavailable: {exc}") from exc


def _relative(name: Any, *, label: str) -> str:
    if not isinstance(name, str) or not name:
        raise ArtifactLedgerError(f"{label} path is invalid")
    path = PurePosixPath(name)
    if (
        "\x00" in name or "\\" in name or ":" in name
        or path.is_absolute() or path.as_posix() != name
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise ArtifactLedgerError(f"{label} path is invalid")
    return name


def _dimensions(config: Mapping[str, Any]) -> tuple[str, str, str, str, str]:
    run_id = config.get("_run_id")
    pipeline = str(config.get("pipeline") or "").strip().lower()
    mode = str(config.get("mode") or "").strip().lower()
    ecosystem = str(config.get("language") or config.get("ecosystem") or "").strip().lower()
    backend = str(config.get("cli_backend") or config.get("backend") or "").strip().lower()
    if (
        not isinstance(run_id, str) or not run_id or run_id != run_id.strip()
        or pipeline not in {"sc", "l1"} or not mode or not ecosystem or not backend
    ):
        raise ArtifactLedgerError("severity bind dimensions are invalid")
    return run_id, pipeline, mode, ecosystem, backend


def _directory_stamp(path: Path, *, label: str) -> tuple[int, ...]:
    try:
        observed = rio.lstat(path)
    except OSError as exc:
        raise ArtifactLedgerError(f"{label} identity is unavailable: {exc}") from exc
    if not stat.S_ISDIR(observed.st_mode):
        raise ArtifactLedgerError(f"{label} is not a directory")
    return (
        int(observed.st_dev), int(observed.st_ino),
        stat.S_IMODE(observed.st_mode), int(observed.st_uid),
        int(observed.st_gid),
    )


def _physical_file_stamp(path: Path, *, label: str) -> tuple[str, tuple[int, ...]]:
    try:
        observed = rio.lstat(path)
    except OSError as exc:
        raise ArtifactLedgerError(f"{label} identity is unavailable: {exc}") from exc
    if not stat.S_ISREG(observed.st_mode):
        raise ArtifactLedgerError(f"{label} is not a regular file")
    inode = int(getattr(observed, "st_ino", 0) or 0)
    device = int(getattr(observed, "st_dev", 0) or 0)
    physical = (
        f"file:{device}:{inode}"
        if inode
        else f"path:{os.path.normcase(os.path.abspath(os.fspath(path)))}"
    )
    return physical, (
        device, inode, int(observed.st_size), stat.S_IMODE(observed.st_mode),
        int(observed.st_uid), int(observed.st_gid),
        int(getattr(observed, "st_nlink", 1) or 1),
    )


def _planning_denominator(
    root: Path, project: Path, config: Mapping[str, Any],
) -> tuple[str, ...]:
    issues = validate_prepared_work(root)
    if issues:
        raise ArtifactLedgerError(
            "severity bind planning authority is invalid: " + "; ".join(issues)
        )
    manifest_raw = _read(root, MANIFEST_NAME, label="severity bind manifest")
    plan_raw = _read(root, WORK_PLAN_NAME, label="severity bind plan")
    manifest = _strict_object(manifest_raw, label="severity bind manifest")
    plan = _strict_object(plan_raw, label="severity bind plan")
    manifest_ids = manifest.get("denominator_ids")
    plan_ids = plan.get("denominator_ids")
    if (
        not isinstance(manifest_ids, list) or not isinstance(plan_ids, list)
        or manifest_ids != plan_ids
        or any(not isinstance(item, str) or _CANDIDATE.fullmatch(item) is None for item in plan_ids)
        or len(plan_ids) > 9_999
        or len(plan_ids) != len(set(plan_ids))
        or len(plan_ids) != len({item.casefold() for item in plan_ids})
    ):
        raise ArtifactLedgerError("severity bind planning denominator differs")
    _run, pipeline, mode, ecosystem, backend = _dimensions(config)
    selected_method = (
        "l1-severity-matrix.md" if pipeline == "l1" else "report-template.md"
    )
    planning_inputs = (
        _INITIAL_SNAPSHOT,
        "_severity_adjudication_inputs/audit_snapshot.json",
        "_severity_adjudication_inputs/audit_config.json",
        "_severity_adjudication_inputs/finding-output-format.md",
        "_severity_adjudication_inputs/poc-execution.md",
        f"_severity_adjudication_inputs/{selected_method}",
    )
    planning_outputs = [MANIFEST_NAME, WORK_PLAN_NAME]
    for shard in plan.get("shards") or []:
        if not isinstance(shard, Mapping):
            raise ArtifactLedgerError("severity bind planning shard is malformed")
        planning_outputs.extend(
            _relative(shard.get(field), label=f"severity planning {field}")
            for field in (
                "context_file", "prompt_file", "tool_policy_file",
                "launch_intent_file",
            )
        )
    planning_contract = resolve_phase_io_contract(
        pipeline=pipeline, mode=mode, ecosystem=ecosystem, backend=backend,
        phase=PHASE, work_unit_id="planning", exact_inputs=planning_inputs,
        exact_outputs=tuple(planning_outputs), exact_writer="DRIVER",
    )
    planning_launch = LaunchSpec(
        work_unit_key=planning_contract.key, pipeline=pipeline, mode=mode,
        ecosystem=ecosystem, backend=backend, model="driver", timeout_s=60,
        exec_mode="python", tool_policy=(),
    )
    ledger = read_artifact_ledger(root)
    units = ledger.get("work_units")
    unit = units.get(planning_contract.key) if isinstance(units, Mapping) else None
    authority = (
        unit.get("preexecution_authority")
        if isinstance(unit, Mapping)
        else None
    )
    if (
        not isinstance(authority, Mapping)
        or set(authority) != _PLANNING_AUTHORITY_FIELDS
    ):
        raise ArtifactLedgerError(
            "severity bind planning preexecution authority is absent"
        )
    unsigned = dict(authority)
    self_digest = unsigned.pop("authority_sha256", None)
    planning_input_bytes = {
        name: _read(root, name, label=f"severity bind planning input {name}")
        for name in planning_inputs
    }
    planning_output_bytes = {
        name: _read(root, name, label=f"severity bind planning output {name}")
        for name in planning_outputs
    }
    bindings = ledger.get("artifact_bindings")
    capture_owner = authority.get("capture_owner_key")
    captured_owner_exact = bool(
        isinstance(bindings, Mapping)
        and isinstance(capture_owner, str)
        and capture_owner
        and all(
            isinstance(bindings.get(f"scratchpad:{name}"), Mapping)
            and bindings[f"scratchpad:{name}"].get("owner_key")
            == capture_owner
            for name in planning_inputs[1:]
        )
    )
    if (
        authority.get("schema") != "plamen.severity-planning-invocation.v1"
        or authority.get("run_id") != _run
        or self_digest != _canonical_json_digest(unsigned)
        or not captured_owner_exact
        or authority.get("source_ledger_snapshot") != _INITIAL_SNAPSHOT
        or _HEX64.fullmatch(
            str(authority.get("source_ledger_digest") or "")
        ) is None
        or _HEX64.fullmatch(
            str(authority.get("planning_args_sha256") or "")
        ) is None
        or not isinstance(authority.get("root_identities"), Mapping)
        or authority.get("output_names") != planning_outputs
        or authority.get("inputs") != {
            f"scratchpad:{name}": {"sha256": _sha(raw), "size": len(raw)}
            for name, raw in planning_input_bytes.items()
        }
        or authority.get("expected_outputs") != {
            f"scratchpad:{name}": {"sha256": _sha(raw), "size": len(raw)}
            for name, raw in planning_output_bytes.items()
        }
    ):
        raise ArtifactLedgerError(
            "severity bind planning preexecution authority differs"
        )
    planning_issues = validate_work_unit_inputs(
        root, project, planning_contract, planning_launch, run_id=_run,
        preexecution_authority=authority,
    )
    planning_issues.extend(validate_work_unit_artifacts(
        root, project, planning_contract, planning_launch, run_id=_run,
        actor="DRIVER",
        preexecution_authority=authority,
    ))
    if planning_issues:
        raise ArtifactLedgerError(
            "severity bind planning PhaseIO replay failed: "
            + "; ".join(planning_issues)
        )
    if (
        {
            name: _read(root, name, label=f"severity bind planning replay {name}")
            for name in planning_inputs
        }
        != planning_input_bytes
        or {
            name: _read(root, name, label=f"severity bind planning replay {name}")
            for name in planning_outputs
        }
        != planning_output_bytes
    ):
        raise ArtifactLedgerError("severity bind planning bytes changed during replay")
    return tuple(plan_ids)


def _work_id(ordinal: int, candidate: str) -> str:
    return f"bind.{ordinal:04d}.{candidate.casefold()}"


def _key(config: Mapping[str, Any], ordinal: int, candidate: str) -> str:
    _run, pipeline, mode, ecosystem, backend = _dimensions(config)
    return canonical_work_unit_key(
        pipeline, mode, ecosystem, backend, PHASE, _work_id(ordinal, candidate),
    )


def _select_next(
    root: Path, config: Mapping[str, Any], denominator: tuple[str, ...],
) -> tuple[int, str, Mapping[str, Any] | None] | None:
    units = read_artifact_ledger(root).get("work_units", {})
    selected: tuple[int, str, Mapping[str, Any] | None] | None = None
    for ordinal, candidate in enumerate(denominator, 1):
        row = units.get(_key(config, ordinal, candidate)) if isinstance(units, Mapping) else None
        committed = bool(
            isinstance(row, Mapping)
            and row.get("semantic_status") == "ACTIVE"
            and row.get("execution_state") == "OUTPUT_COMMITTED"
        )
        if selected is None and not committed:
            selected = (ordinal, candidate, row if isinstance(row, Mapping) else None)
        elif selected is not None and row is not None:
            raise ArtifactLedgerError("severity bind units are missing or reordered")
    return selected


def _worker_arguments(root: Path, candidate: str) -> tuple[dict[str, str], Mapping[str, Any]]:
    try:
        worker = validate_completed_worker_run_for_candidate(root, candidate)
    except (AdjudicationWorkError, KeyError, OSError, TypeError, ValueError) as exc:
        raise ArtifactLedgerError(
            f"severity bind worker authority failed: {exc}"
        ) from exc
    arguments = {
        "backend": str(worker.get("backend") or ""),
        "launch_digest": str(worker.get("receipt_digest") or ""),
        "run_id": str(worker.get("run_id") or ""),
        "worker_identity": str(worker.get("worker_identity") or ""),
        "invocation_id": str(worker.get("invocation_id") or ""),
    }
    if any(not value for value in arguments.values()) or _HEX64.fullmatch(
        arguments["launch_digest"]
    ) is None:
        raise ArtifactLedgerError("severity bind worker identity is incomplete")
    return arguments, worker


def _output_names(candidate: str) -> tuple[str, str, str]:
    return (
        f"verify_{candidate}.severity_adjudication_receipt.json",
        f"verify_{candidate}.severity_decision.json",
        _AGGREGATE,
    )


def _contract(
    config: Mapping[str, Any], *, ordinal: int, candidate: str,
    input_names: tuple[str, ...], output_names: tuple[str, ...],
):
    _run, pipeline, mode, ecosystem, backend = _dimensions(config)
    contract = resolve_phase_io_contract(
        pipeline=pipeline, mode=mode, ecosystem=ecosystem, backend=backend,
        phase=PHASE, work_unit_id=_work_id(ordinal, candidate),
        exact_inputs=input_names, exact_outputs=output_names,
        exact_writer="DRIVER",
    )
    expected_identities = tuple(f"scratchpad:{name}" for name in output_names)
    if (
        tuple(spec.identity for spec in contract.outputs) != expected_identities
        or tuple(spec.write_mode for spec in contract.outputs)
        != ("CREATE", "REPLACE", "REPLACE")
    ):
        raise ArtifactLedgerError(
            "severity bind contract output order/write modes differ"
        )
    launch = LaunchSpec(
        work_unit_key=contract.key, pipeline=pipeline, mode=mode,
        ecosystem=ecosystem, backend=backend, model="driver", timeout_s=60,
        exec_mode="python", tool_policy=(),
    )
    return contract, launch


def _merge_read_set(postimages: Any, *, candidate: str) -> dict[str, bytes]:
    merged: dict[str, bytes] = {}
    successor_prestates = {
        f"verify_{candidate}.severity_decision.json", _AGGREGATE,
    }
    for source in (postimages.transaction_input_bytes, postimages.authority_read_set):
        for name, raw in source.items():
            name = _relative(name, label="severity bind read-set")
            if name == _INITIAL_SNAPSHOT:
                raise ArtifactLedgerError("severity bind cannot consume the initial snapshot directly")
            if name in successor_prestates:
                # These mutable artifacts are authenticated by the exact
                # successor output prestates/history, never as immutable
                # PhaseIO inputs to their own replacement transaction.
                continue
            exact = bytes(raw)
            if name in merged and merged[name] != exact:
                raise ArtifactLedgerError(f"severity bind read-set bytes differ: {name}")
            merged[name] = exact
    if len(merged) != len({name.casefold() for name in merged}):
        raise ArtifactLedgerError("severity bind read-set has a case collision")
    return merged


def _revalidate_fresh_read_set(
    root: Path, read_set: Mapping[str, bytes],
) -> None:
    for name, expected in read_set.items():
        if _read(root, name, label=f"severity bind current input {name}") != expected:
            raise ArtifactLedgerError(f"severity bind current input changed: {name}")


def _materialize_armed_transition(root: Path, transition: Any, raw: bytes) -> None:
    """Publish one already-armed exact transition through the shared byte IO."""

    identity = str(transition.artifact_identity or "")
    if not identity.startswith("scratchpad:"):
        raise ArtifactLedgerError("severity bind transition is not scratchpad-rooted")
    name = _relative(
        identity.removeprefix("scratchpad:"), label="severity bind output",
    )
    if (
        type(raw) is not bytes
        or len(raw) != transition.after_size
        or _sha(raw) != transition.after_sha256
    ):
        raise ArtifactLedgerError("severity bind transition postimage differs")
    path = root.joinpath(*PurePosixPath(name).parts)
    if rio.lexists(path):
        live = _read(root, name, label="severity bind live output")
        current = ("ACTIVE", _sha(live), len(live))
    else:
        current = ("MISSING", "", 0)
    before = (
        transition.before_status, transition.before_sha256,
        transition.before_size,
    )
    after = ("ACTIVE", transition.after_sha256, transition.after_size)
    if current not in {before, after}:
        raise ArtifactLedgerError("severity bind transition prestate changed")
    materialize_driver_successor_transition(path, raw)
    if _read(root, name, label="severity bind published output") != raw:
        raise ArtifactLedgerError("severity bind transition publication changed")


def _fresh_derivation(
    root: Path, project: Path, config: Mapping[str, Any], *,
    ordinal: int, candidate: str, denominator: tuple[str, ...],
):
    run_id, _pipeline, _mode, _ecosystem, backend = _dimensions(config)
    arguments, worker = _worker_arguments(root, candidate)
    if arguments["run_id"] != run_id or arguments["backend"] != backend:
        raise ArtifactLedgerError("severity bind worker dimensions differ")
    try:
        derived = derive_shadow_adjudication_postimages(root, candidate, **arguments)
    except SeverityBindPostimageError as exc:
        raise ArtifactLedgerError(f"severity bind derivation failed: {exc}") from exc
    if derived.mode != "NEW_BIND" or derived.candidate_id != candidate or derived.run_id != run_id:
        raise ArtifactLedgerError("severity bind refuses legacy or replay adoption")
    output_names = _output_names(candidate)
    if set(derived.output_bytes) != set(output_names):
        raise ArtifactLedgerError("severity bind output denominator differs")
    outputs = {f"scratchpad:{name}": bytes(derived.output_bytes[name]) for name in output_names}
    read_set = _merge_read_set(derived, candidate=candidate)
    input_names = tuple(sorted(read_set, key=lambda item: (item.casefold(), item)))
    contract, launch = _contract(
        config, ordinal=ordinal, candidate=candidate,
        input_names=input_names, output_names=output_names,
    )
    plan = plan_driver_successor_transaction(
        root, project, contract, launch, run_id=run_id,
        planned_output_bytes=outputs, merge_events={},
    )
    if tuple(row.artifact_identity for row in plan.transitions) != tuple(outputs):
        raise ArtifactLedgerError("severity bind successor order differs")
    core = {
        "schema": "plamen.severity-bind-successor-authority.v1",
        "run_id": run_id,
        "ordinal": ordinal,
        "candidate_id": candidate,
        "denominator_sha256": _denominator_digest(denominator),
        "work_unit_key": contract.key,
        "contract_digest": contract.digest,
        "launch_digest": launch.digest,
        "worker_run_digest": derived.worker_run_digest,
        "worker_arguments": arguments,
        "input_names": list(input_names),
        "output_names": list(output_names),
        "read_set": {name: {"sha256": _sha(raw), "size": len(raw)} for name, raw in read_set.items()},
        "expected_outputs": plan.expected_output_records,
        "successor_plan_digest": plan.digest,
    }
    invocation_digest = _digest(core)
    reference = seal_severity_bind_postimages(
        root, run_id=run_id, work_unit_key=contract.key, plan=plan,
        invocation_digest=invocation_digest, output_bytes=outputs,
    )
    authority = {
        **core,
        "invocation_digest": invocation_digest,
        "postimage_cas": dict(reference),
    }
    authority["authority_sha256"] = _canonical_json_digest(authority)
    _revalidate_fresh_read_set(root, read_set)
    return contract, launch, plan, authority, outputs, worker


def _stored_authority(
    root: Path, project: Path, config: Mapping[str, Any], *,
    ordinal: int, candidate: str, denominator: tuple[str, ...],
    row: Mapping[str, Any],
):
    authority = row.get("preexecution_authority")
    if not isinstance(authority, Mapping) or set(authority) != _AUTHORITY_FIELDS:
        raise ArtifactLedgerError("severity bind stored authority is absent")
    unsigned = dict(authority)
    self_digest = unsigned.pop("authority_sha256", None)
    if self_digest != _canonical_json_digest(unsigned):
        raise ArtifactLedgerError("severity bind stored authority is invalid")
    if (
        authority.get("schema") != "plamen.severity-bind-successor-authority.v1"
        or authority.get("ordinal") != ordinal
        or authority.get("candidate_id") != candidate
        or authority.get("denominator_sha256")
        != _denominator_digest(denominator)
    ):
        raise ArtifactLedgerError("severity bind stored candidate order differs")
    run_id, _pipeline, _mode, _ecosystem, _backend = _dimensions(config)
    if authority.get("run_id") != run_id:
        raise ArtifactLedgerError("severity bind stored run differs")
    raw_inputs = authority.get("input_names")
    raw_outputs = authority.get("output_names")
    if not isinstance(raw_inputs, list) or not isinstance(raw_outputs, list):
        raise ArtifactLedgerError("severity bind stored denominator is malformed")
    input_names = tuple(
        _relative(name, label="severity bind stored input") for name in raw_inputs
    )
    output_names = tuple(
        _relative(name, label="severity bind stored output") for name in raw_outputs
    )
    if (
        output_names != _output_names(candidate)
        or _INITIAL_SNAPSHOT in input_names
        or len(input_names) != len(set(input_names))
        or len(input_names) != len({name.casefold() for name in input_names})
    ):
        raise ArtifactLedgerError("severity bind stored denominator differs")
    contract, launch = _contract(
        config, ordinal=ordinal, candidate=candidate,
        input_names=input_names, output_names=output_names,
    )
    if (
        authority.get("work_unit_key") != contract.key
        or authority.get("contract_digest") != contract.digest
        or authority.get("launch_digest") != launch.digest
    ):
        raise ArtifactLedgerError("severity bind stored PhaseIO authority differs")
    read_set = authority.get("read_set")
    if not isinstance(read_set, Mapping) or set(read_set) != set(input_names):
        raise ArtifactLedgerError("severity bind stored read-set denominator differs")
    for name, record in read_set.items():
        if (
            not isinstance(record, Mapping)
            or set(record) != {"sha256", "size"}
            or _HEX64.fullmatch(str(record.get("sha256") or "")) is None
            or not isinstance(record.get("size"), int)
            or isinstance(record.get("size"), bool)
            or int(record["size"]) < 0
        ):
            raise ArtifactLedgerError(
                f"severity bind stored read-set record is invalid: {name}"
            )
    arguments, worker = _worker_arguments(root, candidate)
    if (
        authority.get("worker_arguments") != arguments
        or authority.get("worker_run_digest") != worker.get("receipt_digest")
    ):
        raise ArtifactLedgerError("severity bind stored worker authority differs")
    core = {
        key: authority[key]
        for key in _AUTHORITY_FIELDS
        if key not in {"invocation_digest", "postimage_cas", "authority_sha256"}
    }
    invocation_digest = authority.get("invocation_digest")
    if invocation_digest != _digest(core):
        raise ArtifactLedgerError("severity bind stored invocation digest differs")
    expected = authority.get("expected_outputs")
    expected_identities = tuple(f"scratchpad:{name}" for name in output_names)
    if (
        not isinstance(expected, Mapping)
        or set(expected) != set(expected_identities)
        or _HEX64.fullmatch(
            str(authority.get("successor_plan_digest") or "")
        ) is None
        or not isinstance(authority.get("postimage_cas"), Mapping)
    ):
        raise ArtifactLedgerError(
            "severity bind stored successor denominator differs"
        )
    for identity in expected_identities:
        record = expected.get(identity)
        if (
            not isinstance(record, Mapping)
            or set(record) != {"sha256", "size"}
            or _HEX64.fullmatch(str(record.get("sha256") or "")) is None
            or not isinstance(record.get("size"), int)
            or isinstance(record.get("size"), bool)
            or int(record["size"]) < 0
        ):
            raise ArtifactLedgerError(
                f"severity bind stored output record is invalid: {identity}"
            )
    return contract, launch, dict(authority), worker


def _stored_transaction(
    root: Path, project: Path, config: Mapping[str, Any], *,
    ordinal: int, candidate: str, denominator: tuple[str, ...],
    row: Mapping[str, Any], load_outputs: bool = True,
):
    contract, launch, authority, worker = _stored_authority(
        root, project, config, ordinal=ordinal, candidate=candidate,
        denominator=denominator, row=row,
    )
    run_id, _pipeline, _mode, _ecosystem, _backend = _dimensions(config)
    output_names = tuple(authority["output_names"])
    plan = load_driver_successor_plan(
        root, project, contract, launch, run_id=run_id,
    )
    if authority.get("successor_plan_digest") != plan.digest:
        raise ArtifactLedgerError("severity bind stored plan differs")
    if (
        authority.get("expected_outputs") != plan.expected_output_records
        or tuple(transition.artifact_identity for transition in plan.transitions)
        != tuple(f"scratchpad:{name}" for name in output_names)
    ):
        raise ArtifactLedgerError("severity bind stored successor denominator differs")
    invocation_digest = authority.get("invocation_digest")
    outputs: Mapping[str, bytes] = {}
    if load_outputs:
        outputs = load_severity_bind_postimages(
            root, reference=authority.get("postimage_cas"), plan=plan,
            invocation_digest=str(invocation_digest or ""),
        )
        if plan.expected_output_records != {
            identity: {"sha256": _sha(raw), "size": len(raw)}
            for identity, raw in outputs.items()
        }:
            raise ArtifactLedgerError("severity bind stored postimages differ")
    return contract, launch, plan, dict(authority), dict(outputs), worker


def _terminal_replay(
    root: Path, project: Path, contract: Any, launch: LaunchSpec, *,
    run_id: str, authority: Mapping[str, Any],
) -> None:
    issues = validate_driver_successor_transaction(
        root, project, contract, launch, run_id=run_id, require_complete=True,
    )
    issues.extend(validate_work_unit_artifacts(
        root, project, contract, launch, run_id=run_id, actor="DRIVER",
        preexecution_authority=authority, require_live_input_authority=False,
    ))
    if issues:
        raise ArtifactLedgerError("severity bind terminal replay failed: " + "; ".join(issues))


def _historical_replay(
    root: Path, project: Path, contract: Any, launch: LaunchSpec, *,
    run_id: str, authority: Mapping[str, Any],
) -> None:
    """Replay a committed bind through its registered successor history."""

    issues = validate_historical_driver_successor_transaction(
        root, project, contract, launch, run_id=run_id,
        preexecution_authority=authority,
    )
    if issues:
        raise ArtifactLedgerError(
            "severity bind historical replay failed: " + "; ".join(issues)
        )


def _validate_committed_prefix(
    root: Path,
    project: Path,
    config: Mapping[str, Any],
    denominator: tuple[str, ...],
    *,
    count: int,
) -> None:
    run_id, _pipeline, _mode, _ecosystem, _backend = _dimensions(config)
    units = read_artifact_ledger(root).get("work_units", {})
    if not isinstance(units, Mapping):
        raise ArtifactLedgerError("severity bind work-unit ledger is absent")
    for ordinal, candidate in enumerate(denominator[:count], 1):
        row = units.get(_key(config, ordinal, candidate))
        if not (
            isinstance(row, Mapping)
            and row.get("semantic_status") == "ACTIVE"
            and row.get("execution_state") == "OUTPUT_COMMITTED"
        ):
            raise ArtifactLedgerError("severity bind committed prefix differs")
        contract, launch, authority, _worker = (
            _stored_authority(
                root,
                project,
                config,
                ordinal=ordinal,
                candidate=candidate,
                denominator=denominator,
                row=row,
            )
        )
        _historical_replay(
            root,
            project,
            contract,
            launch,
            run_id=run_id,
            authority=authority,
        )


def _bind_namespace_keys(
    units: Mapping[str, Any], config: Mapping[str, Any],
) -> tuple[str, ...]:
    """Return every case-insensitive bind-family key in this dimension."""

    _run, pipeline, mode, ecosystem, backend = _dimensions(config)
    phase_prefix = canonical_work_unit_key(
        pipeline, mode, ecosystem, backend, PHASE, "placeholder",
    ).rsplit("placeholder", 1)[0]
    bind_prefix = phase_prefix + "bind."
    return tuple(sorted(
        (
            key for key in units
            if isinstance(key, str)
            and key.casefold().startswith(bind_prefix.casefold())
        ),
        key=lambda key: (key.casefold(), key),
    ))


def _source_aggregate_snapshot(
    root: Path, config: Mapping[str, Any], ledger: Mapping[str, Any],
) -> tuple[bytes, dict[str, Any], str, tuple[int, ...]]:
    """Authenticate the retained snapshot without live aggregate derivation."""

    run_id, pipeline, mode, ecosystem, backend = _dimensions(config)
    owner_key = canonical_work_unit_key(
        pipeline, mode, ecosystem, backend, PHASE, "source_aggregate",
    )
    identity = f"scratchpad:{_INITIAL_SNAPSHOT}"
    units = ledger.get("work_units")
    bindings = ledger.get("artifact_bindings")
    source = units.get(owner_key) if isinstance(units, Mapping) else None
    binding = bindings.get(identity) if isinstance(bindings, Mapping) else None
    artifacts = source.get("artifacts") if isinstance(source, Mapping) else None
    artifact = artifacts.get(identity) if isinstance(artifacts, Mapping) else None
    raw = _read(root, _INITIAL_SNAPSHOT, label="severity bind retained source snapshot")
    physical, stamp = _physical_file_stamp(
        root / _INITIAL_SNAPSHOT, label="severity bind retained source snapshot",
    )
    exact_fields = (
        "identity", "owner_key", "writer", "run_id", "contract_digest",
        "launch_digest", "status", "sha256", "size", "physical_identity",
    )
    if (
        not isinstance(source, Mapping)
        or source.get("run_id") != run_id
        or source.get("semantic_status") != "ACTIVE"
        or source.get("execution_state") != "OUTPUT_COMMITTED"
        or not isinstance(binding, Mapping)
        or not isinstance(artifact, Mapping)
        or binding.get("identity") != identity
        or binding.get("owner_key") != owner_key
        or binding.get("writer") != "DRIVER"
        or binding.get("run_id") != run_id
        or binding.get("status") != "ACTIVE"
        or binding.get("sha256") != _sha(raw)
        or binding.get("size") != len(raw)
        or binding.get("physical_identity") != physical
        or any(binding.get(field) != artifact.get(field) for field in exact_fields)
        or set(artifacts) != {f"scratchpad:{_AGGREGATE}", identity}
    ):
        raise ArtifactLedgerError(
            "severity bind retained source snapshot authority differs"
        )
    invocation = source.get("preexecution_authority")
    if not isinstance(invocation, Mapping):
        raise ArtifactLedgerError("severity bind retained source invocation is absent")
    unsigned = dict(invocation)
    self_digest = unsigned.pop("authority_sha256", None)
    expected = invocation.get("expected_outputs")
    expected_snapshot = {"sha256": _sha(raw), "size": len(raw)}
    if (
        invocation.get("schema")
        != "plamen.severity-source-aggregate-authority.v1"
        or invocation.get("run_id") != run_id
        or self_digest != _canonical_json_digest(unsigned)
        or not isinstance(expected, Mapping)
        or expected.get(_INITIAL_SNAPSHOT) != expected_snapshot
        or expected.get(_AGGREGATE) != expected_snapshot
    ):
        raise ArtifactLedgerError(
            "severity bind retained source invocation differs"
        )
    return raw, dict(binding), owner_key, stamp


def validate_severity_bind_resume_state(
    scratchpad: Path,
    project_root: Path,
    config: Mapping[str, Any],
) -> dict[str, Any]:
    """Replay a committed prefix and optional armed bind without mutation."""

    try:
        root = rio.checked_directory(
            scratchpad, label="severity bind resume scratchpad",
        )
        project = rio.checked_directory(
            project_root, label="severity bind resume project",
        )
        configured_root = rio.checked_directory(
            str(config.get("scratchpad") or ""),
            label="severity bind resume configured scratchpad",
        )
        configured_project = rio.checked_directory(
            str(config.get("project_root") or ""),
            label="severity bind resume configured project",
        )
    except (OSError, rio.RootedPathIOError) as exc:
        raise ArtifactLedgerError(
            f"severity bind resume root authority is invalid: {exc}"
        ) from exc
    if configured_root != root or configured_project != project:
        raise ArtifactLedgerError("severity bind resume configured roots differ")
    root_stamp = _directory_stamp(root, label="severity bind resume scratchpad")
    project_stamp = _directory_stamp(project, label="severity bind resume project")
    run_id, _pipeline, _mode, _ecosystem, _backend = _dimensions(config)
    denominator = _planning_denominator(root, project, config)
    ledger = read_artifact_ledger(root)
    ledger_digest = _digest(ledger)
    units = ledger.get("work_units")
    if not isinstance(units, Mapping):
        raise ArtifactLedgerError("severity bind resume work-unit ledger is absent")
    expected_keys = tuple(
        _key(config, ordinal, candidate)
        for ordinal, candidate in enumerate(denominator, 1)
    )
    observed_keys = _bind_namespace_keys(units, config)
    expected_key_set = set(expected_keys)
    if not observed_keys:
        raise ArtifactLedgerError("severity bind resume has no bind transaction")
    if any(key not in expected_key_set for key in observed_keys):
        raise ArtifactLedgerError("severity bind resume namespace has an extra unit")

    completed: list[str] = []
    active: tuple[int, str] | None = None
    gap_seen = False
    for ordinal, (candidate, key) in enumerate(
        zip(denominator, expected_keys, strict=True), 1,
    ):
        row = units.get(key)
        if row is None:
            gap_seen = True
            continue
        if not isinstance(row, Mapping) or gap_seen or active is not None:
            raise ArtifactLedgerError("severity bind resume units are missing or reordered")
        if (
            row.get("semantic_status") == "ACTIVE"
            and row.get("execution_state") == "OUTPUT_COMMITTED"
        ):
            completed.append(candidate)
            continue
        if not (
            row.get("semantic_status") == "INPUTS_BOUND"
            and row.get("execution_state") == "INPUTS_BOUND_PREEXECUTION"
            and row.get("artifacts") == {}
        ):
            raise ArtifactLedgerError("severity bind resume active unit state differs")
        active = (ordinal, candidate)

    def replay_rows() -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
        bind_rows: list[dict[str, Any]] = []
        for ordinal, candidate in enumerate(completed, 1):
            row = read_artifact_ledger(root).get("work_units", {}).get(
                _key(config, ordinal, candidate)
            )
            if not isinstance(row, Mapping):
                raise ArtifactLedgerError("severity bind resume committed row disappeared")
            contract, launch, authority, _worker = _stored_authority(
                root, project, config, ordinal=ordinal, candidate=candidate,
                denominator=denominator, row=row,
            )
            _historical_replay(
                root, project, contract, launch, run_id=run_id,
                authority=authority,
            )
            bind_rows.append({
                "ordinal": ordinal,
                "candidate_id": candidate,
                "state": "OUTPUT_COMMITTED",
                "work_unit_key": contract.key,
                "authority_sha256": authority["authority_sha256"],
                "successor_plan_digest": authority["successor_plan_digest"],
            })
        active_row: dict[str, Any] | None = None
        if active is not None:
            ordinal, candidate = active
            row = read_artifact_ledger(root).get("work_units", {}).get(
                _key(config, ordinal, candidate)
            )
            if not isinstance(row, Mapping):
                raise ArtifactLedgerError("severity bind resume active row disappeared")
            contract, launch, authority, worker = _stored_authority(
                root, project, config, ordinal=ordinal, candidate=candidate,
                denominator=denominator, row=row,
            )
            issues = validate_driver_successor_transaction(
                root, project, contract, launch, run_id=run_id,
                require_complete=False,
                allow_reconstructible_progress_projection_lag=True,
            )
            if issues:
                raise ArtifactLedgerError(
                    "severity bind resume active transaction failed: "
                    + "; ".join(issues)
                )
            successor = row.get("successor_consumption_authority")
            if not isinstance(successor, Mapping):
                raise ArtifactLedgerError("severity bind resume successor authority is absent")
            try:
                plan = driver_successor_plan_from_dict(
                    successor.get("plan"), contract=contract, launch=launch,
                )
            except (TypeError, ValueError) as exc:
                raise ArtifactLedgerError(
                    f"severity bind resume stored plan is invalid: {exc}"
                ) from exc
            if (
                plan.digest != successor.get("plan_digest")
                or plan.digest != authority.get("successor_plan_digest")
                or authority.get("expected_outputs") != plan.expected_output_records
                or tuple(item.artifact_identity for item in plan.transitions)
                != tuple(
                    f"scratchpad:{name}" for name in authority["output_names"]
                )
            ):
                raise ArtifactLedgerError("severity bind resume stored plan differs")
            outputs = load_severity_bind_postimages(
                root, reference=authority.get("postimage_cas"), plan=plan,
                invocation_digest=str(authority.get("invocation_digest") or ""),
            )
            if plan.expected_output_records != {
                identity: {"sha256": _sha(raw), "size": len(raw)}
                for identity, raw in outputs.items()
            }:
                raise ArtifactLedgerError("severity bind resume CAS postimages differ")
            for transition in plan.transitions:
                identity = str(transition.artifact_identity)
                if not identity.startswith("scratchpad:"):
                    raise ArtifactLedgerError("severity bind resume output is not rooted")
                name = _relative(
                    identity.removeprefix("scratchpad:"),
                    label="severity bind resume output",
                )
                if rio.lexists(root / name):
                    live = _read(root, name, label=f"severity bind resume live {name}")
                    if (
                        _sha(live) == transition.after_sha256
                        and len(live) == transition.after_size
                        and live != outputs[identity]
                    ):
                        raise ArtifactLedgerError(
                            "severity bind resume applied postimage differs from CAS"
                        )
            active_row = {
                "ordinal": ordinal,
                "candidate_id": candidate,
                "state": "INPUTS_BOUND_PREEXECUTION",
                "work_unit_key": contract.key,
                "authority_sha256": authority["authority_sha256"],
                "successor_plan_digest": authority["successor_plan_digest"],
                "worker_run_digest": worker.get("receipt_digest"),
            }
        return bind_rows, active_row

    bind_rows, active_row = replay_rows()
    source_raw, source_binding, source_owner, source_stamp = (
        _source_aggregate_snapshot(root, config, read_artifact_ledger(root))
    )
    replayed_rows, replayed_active = replay_rows()
    final_raw, final_binding, final_owner, final_stamp = (
        _source_aggregate_snapshot(root, config, read_artifact_ledger(root))
    )
    if (
        bind_rows != replayed_rows
        or active_row != replayed_active
        or final_raw != source_raw
        or final_binding != source_binding
        or final_owner != source_owner
        or final_stamp != source_stamp
        or _digest(read_artifact_ledger(root)) != ledger_digest
        or _directory_stamp(root, label="severity bind resume scratchpad") != root_stamp
        or _directory_stamp(project, label="severity bind resume project") != project_stamp
    ):
        raise ArtifactLedgerError("severity bind resume authority changed during replay")
    core = {
        "schema": "plamen.severity-bind-resume-state.v1",
        "run_id": run_id,
        "source_owner_key": source_owner,
        "source_ledger_sha256": _sha(source_raw),
        "source_ledger_size": len(source_raw),
        "source_binding": source_binding,
        "candidate_ids": list(denominator),
        "completed_candidate_ids": list(completed),
        "armed_candidate_id": None if active is None else active[1],
        "binds": bind_rows,
        "active_bind": active_row,
        "bind_authority_digests": [
            item["authority_sha256"]
            for item in (*bind_rows, *((active_row,) if active_row else ()))
        ],
    }
    return {
        **core,
        "source_ledger_bytes": source_raw,
        "authority_digest": _digest(core),
    }


def _runtime_evidence_names(
    root: Path,
    *,
    candidate: str,
    worker: Mapping[str, Any],
    plan: Mapping[str, Any],
    ledger: Mapping[str, Any],
) -> dict[str, str]:
    """Derive the exact unowned runtime evidence set from typed worker authority."""

    shards = plan.get("shards")
    if not isinstance(shards, list):
        raise ArtifactLedgerError("severity bind runtime shard roster is malformed")
    matches = [
        shard for shard in shards
        if isinstance(shard, Mapping)
        and isinstance(shard.get("candidate_ids"), list)
        and candidate in shard["candidate_ids"]
    ]
    if len(matches) != 1:
        raise ArtifactLedgerError("severity bind runtime shard is not unique")
    shard = matches[0]
    try:
        authority_paths = _worker_authority_paths(root, worker, shard)
    except (OSError, SeverityBindPostimageError) as exc:
        raise ArtifactLedgerError(
            f"severity bind runtime evidence authority is invalid: {exc}"
        ) from exc

    launch_name = _relative(
        shard.get("launch_intent_file"),
        label="severity bind runtime launch intent",
    )
    worker_suffix = Path(launch_name).name.removeprefix(
        "severity_adjudication_launch_intent."
    ).removesuffix(".json")
    expected: dict[str, str] = {
        f"severity_adjudication_worker_run.{worker_suffix}.json": "WORKER_RUN",
    }
    worker_schema = worker.get("schema_version")
    if worker_schema == _COMPAT_WORKER_SCHEMA:
        receipt = _relative(
            worker.get("compatibility_receipt_relative_path"),
            label="severity bind compatibility receipt",
        )
        expected[receipt] = "POSIX_COMPAT_RECEIPT"
        units = ledger.get("work_units")
        owner = worker.get("phase_io_owner_key")
        unit = units.get(owner) if isinstance(units, Mapping) else None
        execution = unit.get("execution_authority") if isinstance(unit, Mapping) else None
        if not isinstance(execution, Mapping):
            raise ArtifactLedgerError(
                "severity bind runtime execution authority is absent"
            )
        attempt_parent: PurePosixPath | None = None
        for field, kind in (
            ("attempt_completion_relative_path", "TRANSACTION_COMPLETION"),
            ("provider_completion_relative_path", "PROVIDER_COMPLETION"),
            ("incorporation_relative_path", "TRANSACTION_INCORPORATION"),
        ):
            name = _relative(
                execution.get(field), label=f"severity bind runtime {field}"
            )
            expected[name] = kind
            if field == "attempt_completion_relative_path":
                attempt_parent = PurePosixPath(name).parent
        if attempt_parent is None:
            raise ArtifactLedgerError("severity bind runtime attempt is absent")
        expected[(attempt_parent / "plan.json").as_posix()] = "TRANSACTION_PLAN"
    elif worker_schema == _NATIVE_WORKER_SCHEMA:
        for field, kind in (
            ("provider_arm_file", "PROVIDER_ARM"),
            ("provider_completion_file", "PROVIDER_COMPLETION"),
            ("provider_publish_file", "PROVIDER_PUBLISH"),
        ):
            expected[
                _relative(worker.get(field), label=f"severity bind runtime {field}")
            ] = kind
    else:
        raise ArtifactLedgerError("severity bind runtime worker schema differs")

    if not set(expected).issubset(authority_paths):
        raise ArtifactLedgerError(
            "severity bind runtime evidence denominator differs"
        )
    for name in expected:
        expected_path = root.joinpath(*PurePosixPath(name).parts)
        if authority_paths[name] != expected_path:
            raise ArtifactLedgerError(
                "severity bind runtime evidence path authority differs"
            )
    return expected


def _runtime_evidence_witness(
    *,
    identity: str,
    raw: bytes,
    input_binding: Any,
    candidate: str,
    run_id: str,
    worker: Mapping[str, Any],
    evidence_kind: str,
) -> dict[str, Any]:
    """Bind an unowned input only through its already-replayed worker authority."""

    digest = worker.get("receipt_digest")
    schema = worker.get("schema_version")
    principal: dict[str, str]
    if schema == _COMPAT_WORKER_SCHEMA:
        owner = worker.get("phase_io_owner_key")
        if not isinstance(owner, str) or not owner:
            owner = ""
        principal = {"kind": "PHASE_IO_OWNER", "phase_io_owner_key": owner}
    elif schema == _NATIVE_WORKER_SCHEMA:
        fields = {
            name: worker.get(name)
            for name in ("shard_id", "worker_identity", "invocation_id", "backend")
        }
        principal = (
            {
                "kind": "NATIVE_PROVIDER_WORKER",
                **{name: str(value) for name, value in fields.items()},
            }
            if all(isinstance(value, str) and value for value in fields.values())
            else {}
        )
    else:
        principal = {}
    if (
        _CANDIDATE.fullmatch(candidate) is None
        or worker.get("run_id") != run_id
        or schema not in {_COMPAT_WORKER_SCHEMA, _NATIVE_WORKER_SCHEMA}
        or not principal
        or any(not value for value in principal.values())
        or not isinstance(digest, str) or _HEX64.fullmatch(digest) is None
        or evidence_kind not in _RUNTIME_EVIDENCE_KINDS
        or not isinstance(input_binding, Mapping)
        or set(input_binding) != _UNOWNED_RUNTIME_INPUT_FIELDS
        or input_binding.get("identity") != identity
        or input_binding.get("input_class") != "IMMUTABLE"
        or input_binding.get("status") != "ACTIVE"
        or input_binding.get("sha256") != _sha(raw)
        or input_binding.get("size") != len(raw)
        or not isinstance(input_binding.get("mtime_ns"), int)
        or isinstance(input_binding.get("mtime_ns"), bool)
        or int(input_binding["mtime_ns"]) < 0
        or any(input_binding.get(field) != "" for field in _EMPTY_PRODUCER_FIELDS)
    ):
        raise ArtifactLedgerError(
            f"completed severity bind runtime evidence differs: {identity}"
        )
    return {
        "candidate_id": candidate,
        "run_id": run_id,
        "worker_schema": schema,
        "worker_principal": principal,
        "worker_run_digest": digest,
        "evidence_kind": evidence_kind,
        "input_binding": dict(input_binding),
    }


def validate_completed_severity_bind_prefix(
    scratchpad: Path,
    project_root: Path,
    config: Mapping[str, Any],
) -> CompletedSeverityBindPrefix:
    """Return current bytes only after every ordered bind replays historically."""

    try:
        root = rio.checked_directory(
            scratchpad, label="completed severity bind scratchpad",
        )
        project = rio.checked_directory(
            project_root, label="completed severity bind project",
        )
        configured_root = rio.checked_directory(
            str(config.get("scratchpad") or ""),
            label="completed severity bind configured scratchpad",
        )
        configured_project = rio.checked_directory(
            str(config.get("project_root") or ""),
            label="completed severity bind configured project",
        )
    except (OSError, rio.RootedPathIOError) as exc:
        raise ArtifactLedgerError(
            f"completed severity bind root authority is invalid: {exc}"
        ) from exc
    if configured_root != root or configured_project != project:
        raise ArtifactLedgerError("completed severity bind configured roots differ")
    root_stamp = _directory_stamp(root, label="completed severity bind scratchpad")
    project_stamp = _directory_stamp(project, label="completed severity bind project")
    run_id, pipeline, mode, ecosystem, backend = _dimensions(config)
    denominator = _planning_denominator(root, project, config)
    ledger = read_artifact_ledger(root)
    ledger_observation = _digest(ledger)
    units = ledger.get("work_units")
    if not isinstance(units, Mapping):
        raise ArtifactLedgerError("completed severity bind work-unit ledger is absent")

    expected_keys = tuple(
        _key(config, ordinal, candidate)
        for ordinal, candidate in enumerate(denominator, 1)
    )
    bind_prefix = canonical_work_unit_key(
        pipeline, mode, ecosystem, backend, PHASE, "bind.0001.placeholder",
    ).rsplit("bind.0001.placeholder", 1)[0] + "bind."
    observed_keys = {
        key for key in units
        if isinstance(key, str) and key.casefold().startswith(bind_prefix.casefold())
    }
    if observed_keys != set(expected_keys):
        raise ArtifactLedgerError(
            "completed severity bind work-unit denominator differs"
        )

    names: set[str] = set()
    bind_rows: list[dict[str, Any]] = []
    bind_authority_digests: list[str] = []
    runtime_witnesses: dict[str, list[dict[str, Any]]] = {}
    work_plan = _strict_object(
        _read(root, WORK_PLAN_NAME, label="completed severity bind work plan"),
        label="completed severity bind work plan",
    )
    for ordinal, (candidate, key) in enumerate(
        zip(denominator, expected_keys, strict=True), 1,
    ):
        row = units.get(key)
        if not (
            isinstance(row, Mapping)
            and row.get("semantic_status") == "ACTIVE"
            and row.get("execution_state") == "OUTPUT_COMMITTED"
        ):
            raise ArtifactLedgerError(
                f"completed severity bind is absent: {ordinal:04d}.{candidate}"
            )
        contract, launch, authority, worker = _stored_authority(
            root, project, config, ordinal=ordinal, candidate=candidate,
            denominator=denominator, row=row,
        )
        _historical_replay(
            root, project, contract, launch, run_id=run_id,
            authority=authority,
        )
        authority_digest = str(authority["authority_sha256"])
        bind_authority_digests.append(authority_digest)
        bind_rows.append({
            "ordinal": ordinal,
            "candidate_id": candidate,
            "work_unit_key": contract.key,
            "contract_digest": contract.digest,
            "launch_digest": launch.digest,
            "authority_sha256": authority_digest,
            "successor_plan_digest": authority["successor_plan_digest"],
        })
        names.update(str(name) for name in authority["input_names"])
        names.update(str(name) for name in authority["output_names"])
        input_bindings = row.get("input_bindings")
        if not isinstance(input_bindings, Mapping):
            raise ArtifactLedgerError(
                "completed severity bind input bindings are absent"
            )
        for name, evidence_kind in _runtime_evidence_names(
            root, candidate=candidate, worker=worker, plan=work_plan,
            ledger=ledger,
        ).items():
            identity = f"scratchpad:{name}"
            if name not in authority["input_names"] or identity not in input_bindings:
                raise ArtifactLedgerError(
                    "completed severity bind runtime evidence is outside the read set"
                )
            runtime_witnesses.setdefault(identity, []).append({
                "candidate": candidate,
                "worker": worker,
                "evidence_kind": evidence_kind,
                "input_binding": input_bindings[identity],
            })

    # The pure final reconciliation builder calls validate_prepared_work,
    # which rereads the immutable planning snapshot. It is therefore a direct
    # final-reconciliation input even though bind transactions consume it only
    # transitively through the planning producer.
    names.add(_INITIAL_SNAPSHOT)
    input_names = tuple(sorted(names, key=lambda name: (name.casefold(), name)))
    if len(input_names) != len({name.casefold() for name in input_names}):
        raise ArtifactLedgerError("completed severity bind input names collide")
    current = {
        name: _read(root, name, label=f"completed severity bind input {name}")
        for name in input_names
    }
    skeptic_name = "skeptic_challenges.json"
    skeptic_path = root / skeptic_name
    if rio.lexists(skeptic_path):
        raise ArtifactLedgerError(
            "completed severity bind snapshot-mode skeptic absence changed"
        )
    absence_records = {skeptic_name: "MISSING"}
    bindings = ledger.get("artifact_bindings")
    if not isinstance(bindings, Mapping):
        raise ArtifactLedgerError("completed severity bind bindings are absent")
    binding_rows: dict[str, Mapping[str, Any]] = {}
    runtime_rows: dict[str, list[dict[str, Any]]] = {}
    physical_stamps: dict[str, tuple[int, ...]] = {}
    for name in input_names:
        identity = f"scratchpad:{name}"
        binding = bindings.get(identity)
        raw = current[name]
        physical, physical_stamp = _physical_file_stamp(
            root / name, label=f"completed severity bind input {name}",
        )
        if identity in bindings:
            if (
                not isinstance(binding, Mapping)
                or binding.get("identity") != identity
                or binding.get("run_id") != run_id
                or binding.get("status") != "ACTIVE"
                or not isinstance(binding.get("owner_key"), str)
                or not binding.get("owner_key")
                or binding.get("sha256") != _sha(raw)
                or binding.get("size") != len(raw)
                or binding.get("physical_identity") != physical
            ):
                raise ArtifactLedgerError(
                    f"completed severity bind producer differs: {identity}"
                )
            binding_rows[identity] = dict(binding)
        else:
            witnesses = runtime_witnesses.get(identity)
            if not isinstance(witnesses, list) or not witnesses:
                raise ArtifactLedgerError(
                    f"completed severity bind producer differs: {identity}"
                )
            runtime_rows[identity] = []
            for witness in witnesses:
                record = _runtime_evidence_witness(
                    identity=identity,
                    raw=raw,
                    input_binding=witness.get("input_binding"),
                    candidate=str(witness.get("candidate") or ""),
                    run_id=run_id,
                    worker=witness.get("worker") or {},
                    evidence_kind=str(witness.get("evidence_kind") or ""),
                )
                record["physical_identity"] = physical
                runtime_rows[identity].append(record)
        physical_stamps[name] = physical_stamp

    if (
        _digest(read_artifact_ledger(root)) != ledger_observation
        or _directory_stamp(root, label="completed severity bind scratchpad")
        != root_stamp
        or _directory_stamp(project, label="completed severity bind project")
        != project_stamp
        or {
            name: _read(
                root, name, label=f"completed severity bind rejoin {name}",
            )
            for name in input_names
        }
        != current
        or {
            name: _physical_file_stamp(
                root / name,
                label=f"completed severity bind rejoin {name}",
            )[1]
            for name in input_names
        }
        != physical_stamps
        or rio.lexists(skeptic_path)
    ):
        raise ArtifactLedgerError(
            "completed severity bind authority changed during capture"
        )
    authority_core = {
        "schema": "plamen.completed-severity-bind-prefix.v1",
        "run_id": run_id,
        "pipeline": pipeline,
        "mode": mode,
        "ecosystem": ecosystem,
        "backend": backend,
        "candidate_ids": list(denominator),
        "binds": bind_rows,
        "inputs": {
            name: {"sha256": _sha(raw), "size": len(raw)}
            for name, raw in current.items()
        },
        "producer_bindings": binding_rows,
        "runtime_evidence_bindings": runtime_rows,
        "explicit_absences": dict(absence_records),
    }
    return CompletedSeverityBindPrefix(
        candidate_ids=denominator,
        input_names=input_names,
        read_set=MappingProxyType(dict(current)),
        bind_authority_digests=tuple(bind_authority_digests),
        absence_records=MappingProxyType(dict(absence_records)),
        authority_digest=_digest(authority_core),
    )


def run_next_severity_bind_transaction(
    *, scratchpad: Path, project_root: Path, config: Mapping[str, Any],
    fault_hook: Callable[[str], None] | None = None,
) -> str | None:
    """Commit the next exact planning-denominator candidate, or return None."""

    try:
        root = rio.checked_directory(scratchpad, label="severity bind scratchpad")
        project = rio.checked_directory(project_root, label="severity bind project")
        configured_root = rio.checked_directory(
            str(config.get("scratchpad") or ""),
            label="severity bind configured scratchpad",
        )
        configured_project = rio.checked_directory(
            str(config.get("project_root") or ""),
            label="severity bind configured project",
        )
    except (OSError, rio.RootedPathIOError) as exc:
        raise ArtifactLedgerError(
            f"severity bind root authority is invalid: {exc}"
        ) from exc
    if configured_root != root or configured_project != project:
        raise ArtifactLedgerError("severity bind configured roots differ")
    run_id, _pipeline, _mode, _ecosystem, _backend = _dimensions(config)
    denominator = _planning_denominator(root, project, config)
    selected = _select_next(root, config, denominator)
    if selected is None:
        _validate_committed_prefix(
            root, project, config, denominator, count=len(denominator),
        )
        return None
    ordinal, candidate, prior = selected
    _validate_committed_prefix(
        root, project, config, denominator, count=ordinal - 1,
    )
    if isinstance(prior, Mapping):
        contract, launch, plan, authority, outputs, worker = _stored_transaction(
            root, project, config, ordinal=ordinal, candidate=candidate,
            denominator=denominator, row=prior,
        )
    else:
        contract, launch, plan, authority, outputs, worker = _fresh_derivation(
            root, project, config, ordinal=ordinal, candidate=candidate,
            denominator=denominator,
        )
    hook = fault_hook or (lambda _point: None)
    hook("after_stage")
    record_work_unit_inputs(
        root, project, contract, launch, run_id=run_id,
        successor_plan=plan, preexecution_authority=authority,
    )
    hook("after_arm")
    armed_issues = validate_driver_successor_transaction(
        root, project, contract, launch, run_id=run_id,
        require_complete=False,
    )
    if armed_issues:
        raise ArtifactLedgerError(
            "severity bind armed transaction failed replay: "
            + "; ".join(armed_issues)
        )
    for transition in plan.transitions:
        progress = begin_driver_successor_step(
            root, project, contract, launch, run_id=run_id,
            ordinal=int(transition.ordinal),
        )
        if progress.get("state") != "STEP_APPLIED":
            raw = outputs.get(transition.artifact_identity)
            if type(raw) is not bytes:
                raise ArtifactLedgerError("severity bind stored output is absent")
            _materialize_armed_transition(root, transition, raw)
            complete_driver_successor_step(
                root, project, contract, launch, run_id=run_id,
                ordinal=int(transition.ordinal),
            )
        hook(f"after_output_{transition.ordinal}")
        replayed_worker = validate_completed_worker_run_for_candidate(root, candidate)
        if replayed_worker != worker:
            raise ArtifactLedgerError("severity bind worker authority changed")
    hook("before_commit")
    issues = validate_driver_successor_transaction(
        root, project, contract, launch, run_id=run_id, require_complete=True,
    )
    if issues:
        raise ArtifactLedgerError("severity bind successor replay failed: " + "; ".join(issues))
    record_work_unit_artifacts(
        root, project, contract, launch, run_id=run_id, actor="DRIVER",
        expected_output_records=plan.expected_output_records,
    )
    hook("after_commit")
    _terminal_replay(
        root, project, contract, launch, run_id=run_id, authority=authority,
    )
    return candidate


__all__ = [
    "CompletedSeverityBindPrefix",
    "FAULT_POINTS",
    "run_next_severity_bind_transaction",
    "validate_completed_severity_bind_prefix",
    "validate_severity_bind_resume_state",
]
