"""Typed successor for deterministic report-body evidence projection.

This transaction consumes one already-committed report-body MODEL unit.  It
retains and authenticates that MODEL unit's original bytes, derives the exact
deterministic repair/projection postimage, and publishes a DRIVER successor.
It deliberately does not launch a model and does not make verifier semantics.

The report-body attempt authority assigns one exact MODEL and one exact
projection identity to each ordinal.  This runner accepts only their
same-ordinal handoff, retains that exact MODEL generation, and never relabels
retry bytes or DRIVER bytes as MODEL output.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Mapping

import rooted_path_io as rio
from portable_path_contract import assert_lexically_bounded_relative_path
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
    semantic_input_prebind_producer_authority_issues,
    validate_driver_successor_transaction,
    validate_work_unit_artifacts,
    validate_work_unit_inputs,
)
from driver_successor_io import materialize_driver_successor_transition
from phase_io_contracts import (
    LaunchSpec,
    canonical_work_unit_key,
    driver_successor_plan_from_dict,
    parse_report_body_attempt_work_unit,
    report_body_attempt_work_unit_id,
    resolve_phase_io_contract,
)
from plamen_mechanical import derive_report_body_evidence_projection
from report_evidence_authority import (
    ReportEvidenceError,
    validate_typed_report_evidence_shard_markdown,
)
from report_evidence_runtime_witness import (
    ReportEvidenceRuntimeWitnessError,
    capture_report_evidence_runtime_authority,
    validate_report_evidence_runtime_authority,
)
from report_model_preimages import (
    ReportModelPreimageError,
    ReportModelPreimages,
    capture_report_model_preimages,
    read_report_model_preimages,
)


FAULT_POINTS = (
    "after_arm",
    "after_output_1",
    "after_output_2",
    "before_commit",
    "after_commit",
)
PHASE = "report_body"
_SHARD_RE = re.compile(
    r"report_(?:critical_high|medium|low_info)(?:_[a-z])?"
)
_VERIFY_RE = re.compile(r"verify_[A-Za-z0-9_.-]+\.md")
_HEX64 = re.compile(r"[0-9a-f]{64}")
_RUNTIME_DOMAIN_RE = re.compile(r"(?:scratchpad|project|build\.[0-9a-f]{24})")
_MAX_BYTES = 32 * 1024 * 1024


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


def _strict_object(raw: bytes, *, label: str) -> dict[str, Any]:
    def pairs(rows: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in rows:
            if key in value:
                raise ArtifactLedgerError(f"{label} has duplicate key {key!r}")
            value[key] = item
        return value

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
        raise ArtifactLedgerError(f"{label} must be an object")
    return value


def _relative(name: Any, *, label: str) -> str:
    if not isinstance(name, str) or not name:
        raise ArtifactLedgerError(f"{label} is invalid")
    try:
        assert_lexically_bounded_relative_path(name, label=label)
    except ValueError as exc:
        raise ArtifactLedgerError(
            f"{label} is not a canonical relative path"
        ) from exc
    path = PurePosixPath(name)
    if (
        "\x00" in name
        or "\\" in name
        or ":" in name
        or path.is_absolute()
        or path.as_posix() != name
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise ArtifactLedgerError(f"{label} is not a canonical relative path")
    return name


def _read(root: Path, name: str, *, label: str) -> bytes:
    relative = _relative(name, label=label)
    try:
        return rio.read_bytes(
            root.joinpath(*PurePosixPath(relative).parts),
            label=label,
            require_single_link=True,
            max_bytes=_MAX_BYTES,
        )
    except (OSError, rio.RootedPathIOError) as exc:
        raise ArtifactLedgerError(f"{label} is unavailable: {exc}") from exc


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
        raise ArtifactLedgerError("report body projection dimensions are invalid")
    return run_id, pipeline, mode, ecosystem, backend


def _shard(phase_name: str) -> str:
    prefix = "report_body_writer_"
    if not isinstance(phase_name, str) or not phase_name.startswith(prefix):
        raise ArtifactLedgerError("report body projection phase is invalid")
    shard = "report_" + phase_name[len(prefix):]
    if _SHARD_RE.fullmatch(shard) is None:
        raise ArtifactLedgerError("report body projection shard is invalid")
    return shard


def _model_denominator(
    model_contract: Any, model_launch: Any, shard: str,
) -> tuple[tuple[str, ...], int]:
    expected_body = f"scratchpad:{shard}.md"
    expected_body_manifest = f"scratchpad:body_manifests/{shard}.json"
    expected_typed_manifest = (
        f"scratchpad:report_evidence_manifests/{shard}.json"
    )
    inputs = tuple(getattr(model_contract, "immutable_inputs", ()))
    outputs = tuple(getattr(model_contract, "outputs", ()))
    verifier_inputs = tuple(
        sorted(
            identity.removeprefix("scratchpad:")
            for identity in inputs
            if identity.startswith("scratchpad:")
            and _VERIFY_RE.fullmatch(identity.removeprefix("scratchpad:"))
        )
    )
    parsed = parse_report_body_attempt_work_unit(
        getattr(model_contract, "work_unit_id", None)
    )
    if (
        getattr(model_contract, "phase", None) != PHASE
        or parsed is None
        or parsed[0] != "model"
        or parsed[1] != shard
        or getattr(model_contract, "model_invoked", None) is not True
        or getattr(model_launch, "work_unit_key", None) != getattr(model_contract, "key", None)
        or len(outputs) != 1
        or outputs[0].identity != expected_body
        or outputs[0].writer != "MODEL"
        or set(inputs)
        != {
            expected_body_manifest,
            expected_typed_manifest,
            *(f"scratchpad:{name}" for name in verifier_inputs),
        }
    ):
        raise ArtifactLedgerError(
            "report body projection MODEL contract/launch denominator differs"
        )
    return verifier_inputs, parsed[2]


def _projection_receipt_name(shard: str, ordinal: int) -> str:
    suffix = "" if ordinal == 1 else f".attempt-{ordinal:04d}"
    return f"report_evidence_projection_receipts/{shard}{suffix}.json"


def _successor_contract(
    config: Mapping[str, Any], *, shard: str, ordinal: int,
    input_names: tuple[str, ...],
) -> tuple[Any, LaunchSpec]:
    _run, pipeline, mode, ecosystem, backend = _dimensions(config)
    receipt_name = _projection_receipt_name(shard, ordinal)
    contract = resolve_phase_io_contract(
        pipeline=pipeline,
        mode=mode,
        ecosystem=ecosystem,
        backend=backend,
        phase=PHASE,
        work_unit_id=report_body_attempt_work_unit_id(
            "evidence_projection", shard, ordinal,
        ),
        exact_inputs=input_names,
        exact_outputs=(f"{shard}.md", receipt_name),
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


def _manifest_verifier_files(manifest: Mapping[str, Any]) -> tuple[str, ...]:
    rows = manifest.get("findings")
    if not isinstance(rows, list) or not rows:
        raise ArtifactLedgerError("report body source manifest is empty or malformed")
    names: list[str] = []
    folded: dict[str, str] = {}
    for row in rows:
        if not isinstance(row, Mapping):
            raise ArtifactLedgerError("report body source manifest row is malformed")
        raw_names = row.get("verify_files")
        if raw_names is None:
            one = row.get("verify_file")
            raw_names = [one] if one else []
        if not isinstance(raw_names, list):
            raise ArtifactLedgerError(
                "report body source manifest verifier denominator is malformed"
            )
        for raw in raw_names:
            name = _relative(raw, label="report body verifier input")
            if _VERIFY_RE.fullmatch(name) is None:
                raise ArtifactLedgerError(
                    f"report body verifier input is outside grammar: {name}"
                )
            prior = folded.get(name.casefold())
            if prior is not None and prior != name:
                raise ArtifactLedgerError(
                    "report body verifier input denominator has a case alias"
                )
            folded[name.casefold()] = name
            if name not in names:
                names.append(name)
    return tuple(names)


def _read_set(root: Path, names: tuple[str, ...]) -> dict[str, bytes]:
    return {name: _read(root, name, label=f"report body projection input {name}") for name in names}


def _preimage_read_set(root: Path, view: ReportModelPreimages) -> dict[str, dict[str, Any]]:
    rows: dict[str, dict[str, Any]] = {}
    for name in view.read_set:
        raw = _read(root, name, label=f"report MODEL retained authority {name}")
        rows[name] = {"sha256": _sha(raw), "size": len(raw)}
    return rows


def _runtime_view(value: Mapping[str, Any]) -> dict[str, Any]:
    """Freeze the public full semantic-runtime witness without approximation."""

    required = {
        "schema",
        "candidate_ids",
        "root_identities",
        "read_set",
        "absent_identities",
        "namespace_members",
        "implementation_identities",
        "semantic_witnesses",
        "runtime",
        "authority_digest",
    }
    if not isinstance(value, Mapping) or set(value) != required:
        raise ArtifactLedgerError("report evidence runtime witness schema differs")
    digest = value.get("authority_digest")
    read_set = value.get("read_set")
    if (
        value.get("schema") != "plamen.report-evidence-runtime-authority.v1"
        or not isinstance(digest, str)
        or _HEX64.fullmatch(digest) is None
        or not isinstance(read_set, Mapping)
        or not read_set
        or not isinstance(value.get("candidate_ids"), list)
        or not all(
            isinstance(candidate, str) and candidate
            for candidate in value["candidate_ids"]
        )
        or value["candidate_ids"] != sorted(set(value["candidate_ids"]))
        or not isinstance(value.get("root_identities"), Mapping)
        or set(value["root_identities"]) != {"scratchpad", "project", "builds"}
        or not isinstance(value.get("absent_identities"), list)
        or not isinstance(value.get("namespace_members"), Mapping)
        or not isinstance(value.get("implementation_identities"), Mapping)
        or not isinstance(value.get("semantic_witnesses"), Mapping)
        or not isinstance(value.get("runtime"), Mapping)
    ):
        raise ArtifactLedgerError("report evidence runtime witness is invalid")
    for name in ("scratchpad", "project"):
        identity = value["root_identities"][name]
        if (
            not isinstance(identity, Mapping)
            or set(identity) != {"resolved_path", "physical_identity"}
            or not isinstance(identity.get("resolved_path"), str)
            or not identity["resolved_path"]
            or not isinstance(identity.get("physical_identity"), list)
            or len(identity["physical_identity"]) != 5
            or not all(
                isinstance(item, int) and not isinstance(item, bool) and item >= 0
                for item in identity["physical_identity"]
            )
        ):
            raise ArtifactLedgerError(
                "report evidence runtime root identity is invalid"
            )
    builds = value["root_identities"]["builds"]
    if not isinstance(builds, Mapping):
        raise ArtifactLedgerError("report evidence runtime build roots are invalid")
    for domain, identity in builds.items():
        if (
            not isinstance(domain, str)
            or re.fullmatch(r"build\.[0-9a-f]{24}", domain) is None
            or not isinstance(identity, Mapping)
            or set(identity)
            != {"candidate_id", "resolved_path", "physical_identity"}
            or identity.get("candidate_id") not in value["candidate_ids"]
            or not isinstance(identity.get("resolved_path"), str)
            or not identity["resolved_path"]
            or not isinstance(identity.get("physical_identity"), list)
            or len(identity["physical_identity"]) != 5
            or not all(
                isinstance(item, int) and not isinstance(item, bool) and item >= 0
                for item in identity["physical_identity"]
            )
        ):
            raise ArtifactLedgerError(
                "report evidence runtime build-root identity is invalid"
            )
    if sorted(
        identity["candidate_id"] for identity in builds.values()
    ) != value["candidate_ids"]:
        raise ArtifactLedgerError(
            "report evidence runtime build-root candidate roster differs"
        )
    absent = value["absent_identities"]
    if any(
        not isinstance(identity, str)
        or ":" not in identity
        or _RUNTIME_DOMAIN_RE.fullmatch(identity.split(":", 1)[0]) is None
        or identity in read_set
        for identity in absent
    ) or absent != sorted(set(absent)):
        raise ArtifactLedgerError("report evidence runtime absence witness is invalid")
    for identity, record in read_set.items():
        if (
            not isinstance(identity, str)
            or ":" not in identity
            or _RUNTIME_DOMAIN_RE.fullmatch(identity.split(":", 1)[0]) is None
            or not isinstance(record, Mapping)
            or set(record) != {"sha256", "size", "physical_identity"}
            or _HEX64.fullmatch(str(record.get("sha256") or "")) is None
            or not isinstance(record.get("size"), int)
            or isinstance(record.get("size"), bool)
            or int(record["size"]) < 0
            or not isinstance(record.get("physical_identity"), list)
            or len(record["physical_identity"]) != 9
            or not all(
                isinstance(item, int) and not isinstance(item, bool) and item >= 0
                for item in record["physical_identity"]
            )
        ):
            raise ArtifactLedgerError(
                f"report evidence runtime read-set row is invalid: {identity!r}"
            )
    for identity, members in value["namespace_members"].items():
        if (
            not isinstance(identity, str)
            or ":" not in identity
            or _RUNTIME_DOMAIN_RE.fullmatch(identity.split(":", 1)[0]) is None
            or not isinstance(members, list)
            or members != sorted(set(members))
            or not all(isinstance(member, str) and member for member in members)
        ):
            raise ArtifactLedgerError("report evidence runtime namespace witness is invalid")
    if any(
        not isinstance(name, str)
        or not name
        or _HEX64.fullmatch(str(identity or "")) is None
        for name, identity in value["implementation_identities"].items()
    ):
        raise ArtifactLedgerError(
            "report evidence runtime implementation witness is invalid"
        )
    semantic_witnesses = value["semantic_witnesses"]
    expected_semantic_keys = (
        {"scratchpad:_v2_checkpoint.json#runtime"}
        if value["candidate_ids"]
        else set()
    )
    checkpoint = semantic_witnesses.get(
        "scratchpad:_v2_checkpoint.json#runtime"
    )
    if (
        set(semantic_witnesses) != expected_semantic_keys
        or (
            checkpoint is not None
            and (
                not isinstance(checkpoint, Mapping)
                or set(checkpoint) != {"source_snapshot_sha256", "project_root"}
                or _HEX64.fullmatch(
                    str(checkpoint.get("source_snapshot_sha256") or "")
                )
                is None
                or not isinstance(checkpoint.get("project_root"), str)
                or not checkpoint["project_root"]
            )
        )
    ):
        raise ArtifactLedgerError(
            "report evidence runtime semantic witness is invalid"
        )
    unsigned = dict(value)
    unsigned.pop("authority_digest")
    if _canonical_json_digest(unsigned) != digest:
        raise ArtifactLedgerError("report evidence runtime witness digest differs")
    return json.loads(_canonical(dict(value)).decode("utf-8"))


def _receipt(
    *, run_id: str, shard: str, ordinal: int,
    model_contract: Any, model_launch: Any,
    model_raw: bytes, inputs: Mapping[str, bytes], view: ReportModelPreimages,
    runtime_authority: Mapping[str, Any], derivation: Any,
) -> dict[str, Any]:
    repaired = tuple(getattr(derivation, "repaired_report_ids", ()))
    consumed = tuple(getattr(derivation, "consumed_verify_files", ()))
    output = getattr(derivation, "output_bytes", None)
    repair_count = getattr(derivation, "repair_count", None)
    projected = getattr(derivation, "evidence_projection_applied", None)
    if (
        type(output) is not bytes
        or not isinstance(repair_count, int)
        or isinstance(repair_count, bool)
        or repair_count < 0
        or not all(isinstance(item, str) and item for item in repaired)
        or not all(isinstance(item, str) and item for item in consumed)
        or type(projected) is not bool
    ):
        raise ArtifactLedgerError("report body pure derivation result is malformed")
    core = {
        "schema": "plamen.report_body_evidence_projection.v1",
        "run_id": run_id,
        "shard": shard,
        "attempt_ordinal": ordinal,
        "model_work_unit_key": model_contract.key,
        "model_contract_digest": model_contract.digest,
        "model_launch_digest": model_launch.digest,
        "model_execution_authority_digest": view.execution_authority_digest,
        "report_evidence_runtime_authority_digest": runtime_authority[
            "authority_digest"
        ],
        "model_preimage": {"sha256": _sha(model_raw), "size": len(model_raw)},
        "inputs": {
            name: {"sha256": _sha(raw), "size": len(raw)}
            for name, raw in sorted(inputs.items())
        },
        "consumed_verify_files": list(consumed),
        "repair_count": repair_count,
        "repaired_report_ids": list(repaired),
        "evidence_projection_applied": projected,
        "output": {"sha256": _sha(output), "size": len(output)},
    }
    return {**core, "receipt_digest": _canonical_json_digest(core)}


def _receipt_bytes(receipt: Mapping[str, Any]) -> bytes:
    return _canonical(dict(receipt)) + b"\n"


def _invocation(
    *, run_id: str, shard: str, ordinal: int,
    model_contract: Any, model_launch: Any,
    view: ReportModelPreimages, preimage_rows: Mapping[str, Any],
    runtime_authority: Mapping[str, Any],
    inputs: Mapping[str, bytes], receipt: Mapping[str, Any],
    outputs: Mapping[str, bytes], plan: Any,
) -> dict[str, Any]:
    core = {
        "schema": "plamen.report-body-evidence-projection-authority.v1",
        "run_id": run_id,
        "shard": shard,
        "attempt_ordinal": ordinal,
        "model_work_unit_key": model_contract.key,
        "model_contract_digest": model_contract.digest,
        "model_launch_digest": model_launch.digest,
        "model_execution_authority_digest": view.execution_authority_digest,
        "model_preimage_read_set": dict(preimage_rows),
        "report_evidence_runtime_authority": dict(runtime_authority),
        "inputs": {
            name: {"sha256": _sha(raw), "size": len(raw)}
            for name, raw in sorted(inputs.items())
        },
        "receipt_digest": receipt["receipt_digest"],
        "expected_outputs": {
            identity: {"sha256": _sha(raw), "size": len(raw)}
            for identity, raw in outputs.items()
        },
        "successor_plan_digest": plan.digest,
    }
    return {**core, "authority_sha256": _canonical_json_digest(core)}


def _require_current(
    root: Path, project: Path, contract: Any, launch: LaunchSpec, *,
    run_id: str, authority: Mapping[str, Any], input_names: tuple[str, ...],
    inputs: Mapping[str, bytes], model_contract: Any, model_launch: Any,
    expected_view: ReportModelPreimages,
    expected_runtime_authority: Mapping[str, Any],
) -> None:
    if _read_set(root, input_names) != inputs:
        raise ArtifactLedgerError("report body projection input bytes changed")
    replay = read_report_model_preimages(
        root, contract=model_contract, launch=model_launch, run_id=run_id,
    )
    if (
        replay.execution_authority_digest != expected_view.execution_authority_digest
        or dict(replay.preimages) != dict(expected_view.preimages)
        or replay.read_set != expected_view.read_set
        or authority.get("model_preimage_read_set") != _preimage_read_set(root, replay)
    ):
        raise ArtifactLedgerError("report MODEL retained preimage authority changed")
    try:
        runtime = _runtime_view(
            validate_report_evidence_runtime_authority(
                root,
                project_root=project,
                expected=expected_runtime_authority,
            )
        )
    except (
        OSError,
        ReportEvidenceError,
        ReportEvidenceRuntimeWitnessError,
        TypeError,
        ValueError,
    ) as exc:
        raise ArtifactLedgerError(
            f"report evidence runtime authority changed: {exc}"
        ) from exc
    if runtime != dict(expected_runtime_authority):
        raise ArtifactLedgerError("report evidence runtime witness changed")
    issues = validate_work_unit_inputs(
        root,
        project,
        contract,
        launch,
        run_id=run_id,
        preexecution_authority=authority,
    )
    if issues:
        raise ArtifactLedgerError(
            "report body projection input authority failed: " + "; ".join(issues)
        )


def _materialize(root: Path, transition: Any, raw: bytes) -> None:
    identity = str(transition.artifact_identity)
    if not identity.startswith("scratchpad:"):
        raise ArtifactLedgerError("report body projection output is not scratchpad-rooted")
    name = _relative(identity.removeprefix("scratchpad:"), label="report body projection output")
    if _sha(raw) != transition.after_sha256 or len(raw) != transition.after_size:
        raise ArtifactLedgerError("report body projection output differs from sealed transition")
    path = root.joinpath(*PurePosixPath(name).parts)
    try:
        if path.parent != root:
            rio.ensure_directory(path.parent, mode=0o700, label="report body projection output parent")
        materialize_driver_successor_transition(path, raw)
        observed = rio.read_bytes(
            path,
            label="report body projection output postimage",
            require_single_link=True,
            max_bytes=_MAX_BYTES,
        )
    except (OSError, rio.RootedPathIOError) as exc:
        raise ArtifactLedgerError(f"report body projection materialization failed: {exc}") from exc
    if observed != raw:
        raise ArtifactLedgerError("report body projection postimage differs")


def _report_body_evidence_projection(
    *, scratchpad: Path, project_root: Path, config: Mapping[str, Any],
    phase_name: str, model_contract: Any, model_launch: Any,
    require_committed: bool,
    fault_hook: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    """Publish/replay, or read-only validate, one exact body successor."""

    try:
        root = rio.checked_directory(scratchpad, label="report body projection scratchpad")
        project = rio.checked_directory(project_root, label="report body projection project")
        configured_root = rio.checked_directory(
            str(config.get("scratchpad") or ""),
            label="report body projection configured scratchpad",
        )
        configured_project = rio.checked_directory(
            str(config.get("project_root") or ""),
            label="report body projection configured project",
        )
    except (OSError, rio.RootedPathIOError) as exc:
        raise ArtifactLedgerError(f"report body projection root authority is invalid: {exc}") from exc
    if configured_root != root or configured_project != project:
        raise ArtifactLedgerError("report body projection configured roots differ")
    run_id, _pipeline, _mode, _ecosystem, _backend = _dimensions(config)
    shard = _shard(phase_name)
    model_verify, ordinal = _model_denominator(
        model_contract, model_launch, shard,
    )
    if (
        model_contract.pipeline != _pipeline
        or model_contract.mode != _mode
        or model_contract.ecosystem != _ecosystem
        or model_contract.backend != _backend
    ):
        raise ArtifactLedgerError(
            "report body MODEL dimensions differ from projection config"
        )

    successor_key = canonical_work_unit_key(
        _pipeline,
        _mode,
        _ecosystem,
        _backend,
        PHASE,
        report_body_attempt_work_unit_id(
            "evidence_projection", shard, ordinal,
        ),
    )
    ledger = read_artifact_ledger(root)
    units = ledger.get("work_units")
    if not isinstance(units, Mapping):
        raise ArtifactLedgerError("report body projection work-unit ledger is absent")
    aliases = tuple(
        key for key in units
        if isinstance(key, str)
        and key.casefold() == successor_key.casefold()
        and key != successor_key
    )
    if aliases:
        raise ArtifactLedgerError("report body projection work-unit key is aliased")
    existing = units.get(successor_key)
    committed = bool(
        isinstance(existing, Mapping)
        and existing.get("semantic_status") == "ACTIVE"
        and existing.get("execution_state") == "OUTPUT_COMMITTED"
    )
    if require_committed and not committed:
        raise ArtifactLedgerError(
            "report body evidence projection is not committed"
        )
    if existing is None:
        capture_report_model_preimages(
            root, contract=model_contract, launch=model_launch, run_id=run_id,
        )
    view = read_report_model_preimages(
        root, contract=model_contract, launch=model_launch, run_id=run_id,
    )
    model_identity = f"scratchpad:{shard}.md"
    model_raw = view.preimages.get(model_identity)
    if type(model_raw) is not bytes or set(view.preimages) != {model_identity}:
        raise ArtifactLedgerError("report MODEL retained output denominator differs")

    body_name = f"body_manifests/{shard}.json"
    typed_name = f"report_evidence_manifests/{shard}.json"
    bundle_name = "report_evidence_records.json"
    input_names = tuple(sorted((body_name, typed_name, bundle_name, *model_verify)))
    inputs = _read_set(root, input_names)
    manifest = _strict_object(inputs[body_name], label="report body source manifest")
    declared_verify = _manifest_verifier_files(manifest)
    if tuple(sorted(declared_verify)) != model_verify:
        raise ArtifactLedgerError(
            "report body manifest verifier denominator differs from MODEL contract"
        )
    typed_manifest = _strict_object(inputs[typed_name], label="typed report evidence manifest")
    evidence_bundle = _strict_object(inputs[bundle_name], label="typed report evidence bundle")
    verifier_artifacts = {name: inputs[name] for name in model_verify}
    try:
        derivation = derive_report_body_evidence_projection(
            phase_name=phase_name,
            model_body=model_raw,
            body_manifest_bytes=inputs[body_name],
            typed_manifest=typed_manifest,
            verifier_artifacts=verifier_artifacts,
            evidence_bundle=evidence_bundle,
        )
    except (ReportEvidenceError, TypeError, UnicodeError, ValueError) as exc:
        raise ArtifactLedgerError(
            f"report body evidence projection derivation failed: {exc}"
        ) from exc
    projected = getattr(derivation, "output_bytes", None)
    if type(projected) is not bytes:
        raise ArtifactLedgerError("report body evidence projection output is invalid")
    if tuple(getattr(derivation, "consumed_verify_files", ())) != declared_verify:
        raise ArtifactLedgerError("report body projection consumed verifier denominator differs")
    try:
        markdown = projected.decode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise ArtifactLedgerError("projected report body is not UTF-8") from exc
    parity = validate_typed_report_evidence_shard_markdown(root, shard, markdown)
    if parity:
        raise ArtifactLedgerError(
            "projected report body typed parity failed: " + "; ".join(parity)
        )
    # Authenticate the bundle that names execution-scope runtime sources
    # before the runtime witness follows any persisted build/oracle path.  The
    # same prebind is repeated immediately before arm to close the capture
    # interval; neither call writes ledger state.
    initial_prebind = semantic_input_prebind_producer_authority_issues(
        root,
        project,
        tuple(f"scratchpad:{name}" for name in input_names),
        run_id=run_id,
    )
    if initial_prebind:
        raise ArtifactLedgerError(
            "report body projection producer prebind failed: "
            + "; ".join(initial_prebind)
        )
    try:
        runtime_authority = _runtime_view(
            capture_report_evidence_runtime_authority(
                root, project_root=project,
            )
        )
    except (
        OSError,
        ReportEvidenceError,
        ReportEvidenceRuntimeWitnessError,
        TypeError,
        ValueError,
    ) as exc:
        raise ArtifactLedgerError(
            f"report evidence semantic runtime replay failed: {exc}"
        ) from exc

    receipt = _receipt(
        run_id=run_id,
        shard=shard,
        ordinal=ordinal,
        model_contract=model_contract,
        model_launch=model_launch,
        model_raw=model_raw,
        inputs=inputs,
        view=view,
        runtime_authority=runtime_authority,
        derivation=derivation,
    )
    receipt_name = _projection_receipt_name(shard, ordinal)
    successor, successor_launch = _successor_contract(
        config, shard=shard, ordinal=ordinal, input_names=input_names,
    )
    outputs = {
        f"scratchpad:{shard}.md": projected,
        f"scratchpad:{receipt_name}": _receipt_bytes(receipt),
    }
    if committed:
        successor_authority = existing.get("successor_consumption_authority")
        if not isinstance(successor_authority, Mapping):
            raise ArtifactLedgerError("committed report projection successor authority is absent")
        try:
            plan = driver_successor_plan_from_dict(
                successor_authority.get("plan"),
                contract=successor,
                launch=successor_launch,
            )
        except (TypeError, ValueError) as exc:
            raise ArtifactLedgerError(
                f"committed report projection plan is invalid: {exc}"
            ) from exc
        if plan.digest != successor_authority.get("plan_digest"):
            raise ArtifactLedgerError("committed report projection plan digest differs")
    elif existing is None:
        plan = plan_driver_successor_transaction(
            root,
            project,
            successor,
            successor_launch,
            run_id=run_id,
            planned_output_bytes=outputs,
        )
    else:
        plan = load_driver_successor_plan(
            root, project, successor, successor_launch, run_id=run_id,
        )
    if plan.expected_output_records != {
        identity: {"sha256": _sha(raw), "size": len(raw)}
        for identity, raw in outputs.items()
    }:
        raise ArtifactLedgerError("report body projection stored plan differs")
    preimage_rows = _preimage_read_set(root, view)
    authority = _invocation(
        run_id=run_id,
        shard=shard,
        ordinal=ordinal,
        model_contract=model_contract,
        model_launch=model_launch,
        view=view,
        preimage_rows=preimage_rows,
        runtime_authority=runtime_authority,
        inputs=inputs,
        receipt=receipt,
        outputs=outputs,
        plan=plan,
    )
    if committed:
        if existing.get("preexecution_authority") != authority:
            raise ArtifactLedgerError(
                "committed report body projection invocation differs"
            )
        _require_current(
            root,
            project,
            successor,
            successor_launch,
            run_id=run_id,
            authority=authority,
            input_names=input_names,
            inputs=inputs,
            model_contract=model_contract,
            model_launch=model_launch,
            expected_view=view,
            expected_runtime_authority=runtime_authority,
        )
        issues = validate_driver_successor_transaction(
            root,
            project,
            successor,
            successor_launch,
            run_id=run_id,
            require_complete=True,
        )
        issues.extend(
            validate_work_unit_artifacts(
                root,
                project,
                successor,
                successor_launch,
                run_id=run_id,
                actor="DRIVER",
                preexecution_authority=authority,
            )
        )
        if issues:
            raise ArtifactLedgerError(
                "committed report body projection replay failed: "
                + "; ".join(issues)
            )
        return dict(receipt)
    prebind = semantic_input_prebind_producer_authority_issues(
        root,
        project,
        tuple(f"scratchpad:{name}" for name in input_names),
        run_id=run_id,
    )
    if prebind:
        raise ArtifactLedgerError(
            "report body projection producer prebind failed: " + "; ".join(prebind)
        )
    if _read_set(root, input_names) != inputs:
        raise ArtifactLedgerError(
            "report body projection inputs changed before arm"
        )
    prearm_view = read_report_model_preimages(
        root, contract=model_contract, launch=model_launch, run_id=run_id,
    )
    if (
        prearm_view.execution_authority_digest
        != view.execution_authority_digest
        or dict(prearm_view.preimages) != dict(view.preimages)
        or prearm_view.read_set != view.read_set
        or _preimage_read_set(root, prearm_view) != preimage_rows
    ):
        raise ArtifactLedgerError(
            "report MODEL retained authority changed before projection arm"
        )
    try:
        prearm_runtime = _runtime_view(
            validate_report_evidence_runtime_authority(
                root,
                project_root=project,
                expected=runtime_authority,
            )
        )
    except (
        OSError,
        ReportEvidenceError,
        ReportEvidenceRuntimeWitnessError,
        TypeError,
        ValueError,
    ) as exc:
        raise ArtifactLedgerError(
            f"report evidence runtime changed before projection arm: {exc}"
        ) from exc
    if prearm_runtime != runtime_authority:
        raise ArtifactLedgerError(
            "report evidence runtime witness changed before projection arm"
        )

    hook = fault_hook or (lambda _point: None)
    record_work_unit_inputs(
        root,
        project,
        successor,
        successor_launch,
        run_id=run_id,
        successor_plan=plan,
        preexecution_authority=authority,
    )
    hook("after_arm")
    _require_current(
        root,
        project,
        successor,
        successor_launch,
        run_id=run_id,
        authority=authority,
        input_names=input_names,
        inputs=inputs,
        model_contract=model_contract,
        model_launch=model_launch,
        expected_view=view,
        expected_runtime_authority=runtime_authority,
    )
    for transition in plan.transitions:
        progress = begin_driver_successor_step(
            root,
            project,
            successor,
            successor_launch,
            run_id=run_id,
            ordinal=int(transition.ordinal),
        )
        if progress.get("state") != "STEP_APPLIED":
            raw = outputs.get(transition.artifact_identity)
            if type(raw) is not bytes:
                raise ArtifactLedgerError("report body projection postimage is absent")
            _materialize(root, transition, raw)
            complete_driver_successor_step(
                root,
                project,
                successor,
                successor_launch,
                run_id=run_id,
                ordinal=int(transition.ordinal),
            )
        hook(f"after_output_{transition.ordinal}")
        _require_current(
            root,
            project,
            successor,
            successor_launch,
            run_id=run_id,
            authority=authority,
            input_names=input_names,
            inputs=inputs,
            model_contract=model_contract,
            model_launch=model_launch,
            expected_view=view,
            expected_runtime_authority=runtime_authority,
        )
    hook("before_commit")
    _require_current(
        root,
        project,
        successor,
        successor_launch,
        run_id=run_id,
        authority=authority,
        input_names=input_names,
        inputs=inputs,
        model_contract=model_contract,
        model_launch=model_launch,
        expected_view=view,
        expected_runtime_authority=runtime_authority,
    )
    issues = validate_driver_successor_transaction(
        root,
        project,
        successor,
        successor_launch,
        run_id=run_id,
        require_complete=True,
    )
    if issues:
        raise ArtifactLedgerError(
            "report body projection successor replay failed: " + "; ".join(issues)
        )
    record_work_unit_artifacts(
        root,
        project,
        successor,
        successor_launch,
        run_id=run_id,
        actor="DRIVER",
        expected_output_records=plan.expected_output_records,
    )
    hook("after_commit")
    _require_current(
        root,
        project,
        successor,
        successor_launch,
        run_id=run_id,
        authority=authority,
        input_names=input_names,
        inputs=inputs,
        model_contract=model_contract,
        model_launch=model_launch,
        expected_view=view,
        expected_runtime_authority=runtime_authority,
    )
    issues = validate_driver_successor_transaction(
        root,
        project,
        successor,
        successor_launch,
        run_id=run_id,
        require_complete=True,
    )
    issues.extend(
        validate_work_unit_artifacts(
            root,
            project,
            successor,
            successor_launch,
            run_id=run_id,
            actor="DRIVER",
            preexecution_authority=authority,
        )
    )
    if issues:
        raise ArtifactLedgerError(
            "report body projection terminal replay failed: " + "; ".join(issues)
        )
    return dict(receipt)


def run_report_body_evidence_projection(
    *, scratchpad: Path, project_root: Path, config: Mapping[str, Any],
    phase_name: str, model_contract: Any, model_launch: Any,
    fault_hook: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    """Publish or exactly replay one report-body evidence projection."""

    return _report_body_evidence_projection(
        scratchpad=scratchpad,
        project_root=project_root,
        config=config,
        phase_name=phase_name,
        model_contract=model_contract,
        model_launch=model_launch,
        require_committed=False,
        fault_hook=fault_hook,
    )


def validate_committed_report_body_evidence_projection(
    *, scratchpad: Path, project_root: Path, config: Mapping[str, Any],
    phase_name: str, model_contract: Any, model_launch: Any,
) -> dict[str, Any]:
    """Validate a committed projection without capture, arm, or publication."""

    return _report_body_evidence_projection(
        scratchpad=scratchpad,
        project_root=project_root,
        config=config,
        phase_name=phase_name,
        model_contract=model_contract,
        model_launch=model_launch,
        require_committed=True,
    )


__all__ = [
    "FAULT_POINTS",
    "run_report_body_evidence_projection",
    "validate_committed_report_body_evidence_projection",
]
