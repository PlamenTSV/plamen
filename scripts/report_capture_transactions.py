"""Resume-safe CREATE transactions for report source and final captures.

This component publishes only the two capture artifacts. It does not derive
or publish report outputs and must not be selected as a partial live
report-assembly mode.
"""
from __future__ import annotations

import hashlib
import json
import stat
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

import rooted_path_io as rio
from artifact_ledger import (
    ArtifactLedgerError,
    read_artifact_ledger,
    record_work_unit_artifacts,
    record_work_unit_inputs,
    validate_work_unit_artifacts,
    validate_work_unit_inputs,
)
from phase_io_contracts import LaunchSpec, resolve_phase_io_contract
from report_capture_phaseio_authority import (
    PreparedReportSourceCapture,
    build_report_capture_preexecution_authority,
    build_report_final_capture_bytes,
    load_committed_report_final_capture_bytes,
    load_committed_report_source_capture_bytes,
    prepare_report_source_capture,
    validate_report_final_candidate_bytes,
    validate_report_source_candidate_bytes,
)


SOURCE_CAPTURE_NAME = "report_assembly_source_capture.json"
FINAL_CAPTURE_NAME = "report_assembly_final_capture.json"
FAULT_POINTS = ("after_arm", "after_output", "before_commit", "after_commit")
# Keep the transaction reader aligned with the adapter's bounded capture
# envelope.  The schema/adapter remains the authority for the actual payload.
_MAX_CAPTURE_BYTES = 192 * 1024 * 1024


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _root_identity(path: Path, *, label: str) -> tuple[Any, ...]:
    checked = rio.checked_directory(path, label=label)
    row = rio.lstat(checked)
    if not stat.S_ISDIR(row.st_mode):
        raise ArtifactLedgerError(f"{label} is not a directory")
    return (
        str(checked),
        int(row.st_dev),
        int(row.st_ino),
        stat.S_IFMT(row.st_mode),
        stat.S_IMODE(row.st_mode),
        int(getattr(row, "st_uid", 0)),
        int(getattr(row, "st_gid", 0)),
    )


def _roots(
    scratchpad: Path,
    project_root: Path,
    expected_config: Mapping[str, Any],
) -> tuple[Path, Path, tuple[Any, ...], tuple[Any, ...]]:
    if not isinstance(expected_config, Mapping):
        raise TypeError("expected_config must be a mapping")
    try:
        root = rio.checked_directory(
            scratchpad, label="report capture transaction scratchpad"
        )
        project = rio.checked_directory(
            project_root, label="report capture transaction project"
        )
        configured_root = rio.checked_directory(
            str(expected_config.get("scratchpad") or ""),
            label="configured report capture scratchpad",
        )
        configured_project = rio.checked_directory(
            str(expected_config.get("project_root") or ""),
            label="configured report capture project",
        )
    except (OSError, rio.RootedPathIOError) as exc:
        raise ArtifactLedgerError(
            f"report capture root authority is invalid: {exc}"
        ) from exc
    if configured_root != root or configured_project != project:
        raise ArtifactLedgerError("report capture configured roots differ")
    return (
        root,
        project,
        _root_identity(root, label="report capture scratchpad"),
        _root_identity(project, label="report capture project"),
    )


def _run_id(value: Any) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ArtifactLedgerError("report capture run_id must be exact and non-empty")
    return value


def _config_stamp(config: Mapping[str, Any]) -> bytes:
    snapshot = config.get("_audit_snapshot")
    if not isinstance(snapshot, Mapping):
        raise ArtifactLedgerError("report capture config has no audit snapshot")
    digest = snapshot.get("snapshot_digest")
    core = {
        "run_id": config.get("_run_id"),
        "pipeline": config.get("pipeline"),
        "mode": config.get("mode"),
        "ecosystem": config.get("language") or config.get("ecosystem"),
        "backend": config.get("cli_backend") or config.get("backend"),
        "project_root": config.get("project_root"),
        "scratchpad": config.get("scratchpad"),
        "audit_snapshot_digest": digest,
    }
    try:
        return json.dumps(
            core,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ArtifactLedgerError(
            f"report capture config authority is not canonical: {exc}"
        ) from exc


def _final_contract_and_launch(
    config: Mapping[str, Any], *, timeout_s: int
) -> tuple[Any, LaunchSpec]:
    contract = resolve_phase_io_contract(
        pipeline=str(config.get("pipeline") or ""),
        mode=str(config.get("mode") or ""),
        ecosystem=str(config.get("language") or config.get("ecosystem") or ""),
        backend=str(config.get("cli_backend") or config.get("backend") or ""),
        phase="report_assemble",
        work_unit_id="final_capture",
        exact_inputs=(SOURCE_CAPTURE_NAME,),
        exact_outputs=(FINAL_CAPTURE_NAME,),
    )
    launch = LaunchSpec(
        work_unit_key=contract.key,
        pipeline=contract.pipeline,
        mode=contract.mode,
        ecosystem=contract.ecosystem,
        backend=contract.backend,
        model="driver",
        timeout_s=max(1, int(timeout_s)),
        exec_mode="python",
        tool_policy=("filesystem",),
    )
    return contract, launch


def _expected_records(identity: str, raw: bytes) -> dict[str, dict[str, Any]]:
    return {identity: {"sha256": _sha(raw), "size": len(raw)}}


def _assert_stable_roots_and_config(
    root: Path,
    project: Path,
    config: Mapping[str, Any],
    *,
    root_identity: tuple[Any, ...],
    project_identity: tuple[Any, ...],
    config_stamp: bytes,
    contract: Any,
    launch: LaunchSpec,
    run_id: str,
    preexecution_authority: Mapping[str, Any],
    expected_output_records: Mapping[str, Mapping[str, Any]],
) -> None:
    if (
        _root_identity(root, label="report capture scratchpad") != root_identity
        or _root_identity(project, label="report capture project")
        != project_identity
        or _config_stamp(config) != config_stamp
        or build_report_capture_preexecution_authority(
            scratchpad=root,
            project_root=project,
            run_id=run_id,
            contract=contract,
            launch=launch,
            expected_output_records=expected_output_records,
        )
        != dict(preexecution_authority)
    ):
        raise ArtifactLedgerError("report capture root or config authority changed")


def _stored_unit(root: Path, key: str) -> Mapping[str, Any] | None:
    ledger = read_artifact_ledger(root)
    units = ledger.get("work_units")
    if not isinstance(units, Mapping):
        raise ArtifactLedgerError("report capture work-unit table is malformed")
    row = units.get(key)
    if row is None:
        return None
    if not isinstance(row, Mapping):
        raise ArtifactLedgerError("report capture work-unit row is malformed")
    return row


def _is_committed(row: Mapping[str, Any] | None) -> bool:
    return bool(
        isinstance(row, Mapping)
        and row.get("semantic_status") == "ACTIVE"
        and row.get("execution_state") == "OUTPUT_COMMITTED"
    )


def _require_transaction_identity(
    row: Mapping[str, Any],
    contract: Any,
    launch: LaunchSpec,
    run_id: str,
    preexecution_authority: Mapping[str, Any],
) -> None:
    if (
        row.get("work_unit_key") != contract.key
        or row.get("run_id") != run_id
        or row.get("contract_digest") != contract.digest
        or row.get("contract_manifest") != contract.to_dict()
        or row.get("launch_digest") != launch.digest
        or row.get("launch_manifest") != launch.to_dict()
        or row.get("preexecution_authority")
        != dict(preexecution_authority)
        or row.get("preexecution_authority_digest")
        != preexecution_authority.get("authority_sha256")
    ):
        raise ArtifactLedgerError("report capture transaction identity differs")


def _require_absent_create_prestate(
    row: Mapping[str, Any], *, identity: str
) -> None:
    prestates = row.get("output_prestates")
    prestate = prestates.get(identity) if isinstance(prestates, Mapping) else None
    if (
        row.get("semantic_status") != "INPUTS_BOUND"
        or row.get("execution_state") != "INPUTS_BOUND_PREEXECUTION"
        or row.get("artifacts") != {}
        or not isinstance(prestates, Mapping)
        or set(prestates) != {identity}
        or not isinstance(prestate, Mapping)
        or prestate.get("status") != "ABSENT"
        or prestate.get("existed") is not False
    ):
        raise ArtifactLedgerError(
            "report capture CREATE transaction is not exactly armed"
        )


def _require_input_authority(
    root: Path,
    project: Path,
    contract: Any,
    launch: LaunchSpec,
    *,
    run_id: str,
    preexecution_authority: Mapping[str, Any],
) -> None:
    issues = validate_work_unit_inputs(
        root,
        project,
        contract,
        launch,
        run_id=run_id,
        preexecution_authority=preexecution_authority,
    )
    if issues:
        raise ArtifactLedgerError(
            "report capture input replay failed: "
            + "; ".join(dict.fromkeys(issues))
        )


def _materialize_create(root: Path, identity: str, raw: bytes) -> None:
    if not identity.startswith("scratchpad:"):
        raise ArtifactLedgerError("report capture output is not scratchpad-rooted")
    relative = identity.split(":", 1)[1]
    if relative not in {SOURCE_CAPTURE_NAME, FINAL_CAPTURE_NAME}:
        raise ArtifactLedgerError("report capture output identity is unauthorized")
    destination = root / relative
    if rio.lexists(destination):
        try:
            current = rio.read_bytes(
                destination,
                label="report capture partial output",
                require_single_link=True,
                max_bytes=_MAX_CAPTURE_BYTES,
            )
        except (OSError, rio.RootedPathIOError) as exc:
            raise ArtifactLedgerError(
                f"report capture partial output is unsafe: {exc}"
            ) from exc
        if current != raw:
            raise ArtifactLedgerError("report capture partial output bytes differ")
    try:
        rio.durable_write_once_bytes(destination, raw)
        observed = rio.read_bytes(
            destination,
            label="report capture output postimage",
            require_single_link=True,
            max_bytes=_MAX_CAPTURE_BYTES,
        )
    except (OSError, rio.RootedPathIOError) as exc:
        raise ArtifactLedgerError(
            f"report capture durable materialization failed: {exc}"
        ) from exc
    if observed != raw:
        raise ArtifactLedgerError("report capture output postimage differs")


def _committed_replay(
    *,
    root: Path,
    project: Path,
    config: Mapping[str, Any],
    contract: Any,
    launch: LaunchSpec,
    run_id: str,
    identity: str,
    raw: bytes,
    load_committed: Callable[[], bytes],
    validate_candidate: Callable[[], bytes],
    root_identity: tuple[Any, ...],
    project_identity: tuple[Any, ...],
    config_stamp: bytes,
    preexecution_authority: Mapping[str, Any],
    expected_output_records: Mapping[str, Mapping[str, Any]],
) -> bytes:
    ledger_before = read_artifact_ledger(root)
    row = _stored_unit(root, contract.key)
    if not _is_committed(row):
        raise ArtifactLedgerError("report capture transaction is not committed")
    assert row is not None
    _require_transaction_identity(
        row, contract, launch, run_id, preexecution_authority
    )
    if validate_candidate() != raw:
        raise ArtifactLedgerError("report capture candidate replay changed")
    _require_input_authority(
        root,
        project,
        contract,
        launch,
        run_id=run_id,
        preexecution_authority=preexecution_authority,
    )
    output_issues = validate_work_unit_artifacts(
        root,
        project,
        contract,
        launch,
        run_id=run_id,
        actor="DRIVER",
        preexecution_authority=preexecution_authority,
    )
    if output_issues:
        raise ArtifactLedgerError(
            "report capture committed output replay failed: "
            + "; ".join(output_issues)
        )
    if load_committed() != raw:
        raise ArtifactLedgerError("report capture committed adapter bytes differ")
    _assert_stable_roots_and_config(
        root,
        project,
        config,
        root_identity=root_identity,
        project_identity=project_identity,
        config_stamp=config_stamp,
        contract=contract,
        launch=launch,
        run_id=run_id,
        preexecution_authority=preexecution_authority,
        expected_output_records=expected_output_records,
    )
    actual = rio.read_bytes(
        root / identity.split(":", 1)[1],
        label="committed report capture output",
        require_single_link=True,
        max_bytes=_MAX_CAPTURE_BYTES,
    )
    if actual != raw or read_artifact_ledger(root) != ledger_before:
        raise ArtifactLedgerError("report capture committed replay changed state")
    return raw


def _run_create(
    *,
    root: Path,
    project: Path,
    config: Mapping[str, Any],
    contract: Any,
    launch: LaunchSpec,
    run_id: str,
    identity: str,
    raw: bytes,
    validate_candidate: Callable[[], bytes],
    load_committed: Callable[[], bytes],
    root_identity: tuple[Any, ...],
    project_identity: tuple[Any, ...],
    config_stamp: bytes,
    preexecution_authority: Mapping[str, Any],
    fault_hook: Callable[[str], None] | None,
) -> bytes:
    _assert_stable_roots_and_config(
        root,
        project,
        config,
        root_identity=root_identity,
        project_identity=project_identity,
        config_stamp=config_stamp,
        contract=contract,
        launch=launch,
        run_id=run_id,
        preexecution_authority=preexecution_authority,
        expected_output_records=_expected_records(identity, raw),
    )
    row = _stored_unit(root, contract.key)
    if _is_committed(row):
        return _committed_replay(
            root=root,
            project=project,
            config=config,
            contract=contract,
            launch=launch,
            run_id=run_id,
            identity=identity,
            raw=raw,
            load_committed=load_committed,
            validate_candidate=validate_candidate,
            root_identity=root_identity,
            project_identity=project_identity,
            config_stamp=config_stamp,
            preexecution_authority=preexecution_authority,
            expected_output_records=_expected_records(identity, raw),
        )

    destination = root / identity.split(":", 1)[1]
    if row is None:
        ledger = read_artifact_ledger(root)
        bindings = ledger.get("artifact_bindings")
        if rio.lexists(destination) or (
            isinstance(bindings, Mapping)
            and isinstance(bindings.get(identity), Mapping)
        ):
            raise ArtifactLedgerError(
                "report capture refuses an unarmed pre-existing output"
            )
        record_work_unit_inputs(
            root,
            project,
            contract,
            launch,
            run_id=run_id,
            preexecution_authority=preexecution_authority,
        )
    else:
        _require_transaction_identity(
            row, contract, launch, run_id, preexecution_authority
        )

    armed = _stored_unit(root, contract.key)
    if armed is None:
        raise ArtifactLedgerError("report capture arm disappeared")
    _require_transaction_identity(
        armed, contract, launch, run_id, preexecution_authority
    )
    _require_absent_create_prestate(armed, identity=identity)
    _require_input_authority(
        root,
        project,
        contract,
        launch,
        run_id=run_id,
        preexecution_authority=preexecution_authority,
    )
    if validate_candidate() != raw:
        raise ArtifactLedgerError("report capture candidate changed after arm")
    _assert_stable_roots_and_config(
        root,
        project,
        config,
        root_identity=root_identity,
        project_identity=project_identity,
        config_stamp=config_stamp,
        contract=contract,
        launch=launch,
        run_id=run_id,
        preexecution_authority=preexecution_authority,
        expected_output_records=_expected_records(identity, raw),
    )

    hook = fault_hook or (lambda _point: None)
    hook("after_arm")
    if validate_candidate() != raw:
        raise ArtifactLedgerError("report capture candidate changed after arm hook")
    _assert_stable_roots_and_config(
        root,
        project,
        config,
        root_identity=root_identity,
        project_identity=project_identity,
        config_stamp=config_stamp,
        contract=contract,
        launch=launch,
        run_id=run_id,
        preexecution_authority=preexecution_authority,
        expected_output_records=_expected_records(identity, raw),
    )

    _materialize_create(root, identity, raw)
    hook("after_output")
    if validate_candidate() != raw:
        raise ArtifactLedgerError("report capture candidate changed after output")
    _assert_stable_roots_and_config(
        root,
        project,
        config,
        root_identity=root_identity,
        project_identity=project_identity,
        config_stamp=config_stamp,
        contract=contract,
        launch=launch,
        run_id=run_id,
        preexecution_authority=preexecution_authority,
        expected_output_records=_expected_records(identity, raw),
    )
    hook("before_commit")
    if validate_candidate() != raw:
        raise ArtifactLedgerError("report capture candidate changed before commit")
    _assert_stable_roots_and_config(
        root,
        project,
        config,
        root_identity=root_identity,
        project_identity=project_identity,
        config_stamp=config_stamp,
        contract=contract,
        launch=launch,
        run_id=run_id,
        preexecution_authority=preexecution_authority,
        expected_output_records=_expected_records(identity, raw),
    )
    _require_input_authority(
        root,
        project,
        contract,
        launch,
        run_id=run_id,
        preexecution_authority=preexecution_authority,
    )
    record_work_unit_artifacts(
        root,
        project,
        contract,
        launch,
        run_id=run_id,
        actor="DRIVER",
        expected_output_records=_expected_records(identity, raw),
    )
    hook("after_commit")
    return _committed_replay(
        root=root,
        project=project,
        config=config,
        contract=contract,
        launch=launch,
        run_id=run_id,
        identity=identity,
        raw=raw,
        load_committed=load_committed,
        validate_candidate=validate_candidate,
        root_identity=root_identity,
        project_identity=project_identity,
        config_stamp=config_stamp,
        preexecution_authority=preexecution_authority,
        expected_output_records=_expected_records(identity, raw),
    )


def run_report_source_capture_transaction(
    *,
    scratchpad: Path,
    project_root: Path,
    run_id: str,
    expected_config: Mapping[str, Any],
    metadata: Mapping[str, str],
    fixed_source_roles: Mapping[str, str] | None = None,
    namespace_roles: Mapping[str, str] | None = None,
    timeout_s: int = 120,
    fault_hook: Callable[[str], None] | None = None,
) -> bytes:
    """Create or exactly replay the committed report source capture."""

    root, project, root_id, project_id = _roots(
        scratchpad, project_root, expected_config
    )
    run = _run_id(run_id)
    stamp = _config_stamp(expected_config)

    def prepare() -> PreparedReportSourceCapture:
        return prepare_report_source_capture(
            scratchpad=root,
            project_root=project,
            run_id=run,
            expected_config=expected_config,
            metadata=metadata,
            fixed_source_roles=fixed_source_roles,
            namespace_roles=namespace_roles,
            timeout_s=timeout_s,
        )

    candidate = prepare()
    identity = f"scratchpad:{SOURCE_CAPTURE_NAME}"
    preexecution_authority = build_report_capture_preexecution_authority(
        scratchpad=root,
        project_root=project,
        run_id=run,
        contract=candidate.contract,
        launch=candidate.launch,
        expected_output_records=_expected_records(
            identity, candidate.capture_bytes
        ),
    )

    def validate() -> bytes:
        return validate_report_source_candidate_bytes(
            scratchpad=root,
            project_root=project,
            run_id=run,
            expected_config=expected_config,
            source_capture_bytes=candidate.capture_bytes,
            expected_contract=candidate.contract,
            expected_launch=candidate.launch,
            timeout_s=timeout_s,
        )

    return _run_create(
        root=root,
        project=project,
        config=expected_config,
        contract=candidate.contract,
        launch=candidate.launch,
        run_id=run,
        identity=identity,
        raw=candidate.capture_bytes,
        validate_candidate=validate,
        load_committed=lambda: load_committed_report_source_capture_bytes(
            scratchpad=root,
            project_root=project,
            run_id=run,
            expected_config=expected_config,
        ),
        root_identity=root_id,
        project_identity=project_id,
        config_stamp=stamp,
        preexecution_authority=preexecution_authority,
        fault_hook=fault_hook,
    )


def validate_committed_report_source_capture_transaction(
    *,
    scratchpad: Path,
    project_root: Path,
    run_id: str,
    expected_config: Mapping[str, Any],
    metadata: Mapping[str, str],
    fixed_source_roles: Mapping[str, str] | None = None,
    namespace_roles: Mapping[str, str] | None = None,
    timeout_s: int = 120,
) -> bytes:
    """Read-only committed source replay; absence/uncommitted state rejects."""

    # The common runner's first action after deriving the candidate is a
    # committed-state branch.  Guard that state before delegation so this API
    # can never arm an absent transaction.
    root, _project, _root_id, _project_id = _roots(
        scratchpad, project_root, expected_config
    )
    prepared = prepare_report_source_capture(
        scratchpad=scratchpad,
        project_root=project_root,
        run_id=run_id,
        expected_config=expected_config,
        metadata=metadata,
        fixed_source_roles=fixed_source_roles,
        namespace_roles=namespace_roles,
        timeout_s=timeout_s,
    )
    if not _is_committed(_stored_unit(root, prepared.contract.key)):
        raise ArtifactLedgerError("report source capture is not committed")
    return run_report_source_capture_transaction(
        scratchpad=scratchpad,
        project_root=project_root,
        run_id=run_id,
        expected_config=expected_config,
        metadata=metadata,
        fixed_source_roles=fixed_source_roles,
        namespace_roles=namespace_roles,
        timeout_s=timeout_s,
    )


def run_report_final_capture_transaction(
    *,
    scratchpad: Path,
    project_root: Path,
    run_id: str,
    expected_config: Mapping[str, Any],
    derived_outputs: dict[str, tuple[str, bytes]],
    location_decisions: tuple[dict[str, Any], ...] = (),
    timeout_s: int = 120,
    fault_hook: Callable[[str], None] | None = None,
) -> bytes:
    """Create or exactly replay the committed report final capture."""

    root, project, root_id, project_id = _roots(
        scratchpad, project_root, expected_config
    )
    run = _run_id(run_id)
    stamp = _config_stamp(expected_config)
    raw = build_report_final_capture_bytes(
        scratchpad=root,
        project_root=project,
        run_id=run,
        expected_config=expected_config,
        derived_outputs=derived_outputs,
        location_decisions=location_decisions,
    )
    contract, launch = _final_contract_and_launch(
        expected_config, timeout_s=timeout_s
    )
    identity = f"scratchpad:{FINAL_CAPTURE_NAME}"
    preexecution_authority = build_report_capture_preexecution_authority(
        scratchpad=root,
        project_root=project,
        run_id=run,
        contract=contract,
        launch=launch,
        expected_output_records=_expected_records(identity, raw),
    )

    def validate() -> bytes:
        return validate_report_final_candidate_bytes(
            scratchpad=root,
            project_root=project,
            run_id=run,
            expected_config=expected_config,
            final_capture_bytes=raw,
        )

    return _run_create(
        root=root,
        project=project,
        config=expected_config,
        contract=contract,
        launch=launch,
        run_id=run,
        identity=identity,
        raw=raw,
        validate_candidate=validate,
        load_committed=lambda: load_committed_report_final_capture_bytes(
            scratchpad=root,
            project_root=project,
            run_id=run,
            expected_config=expected_config,
        ),
        root_identity=root_id,
        project_identity=project_id,
        config_stamp=stamp,
        preexecution_authority=preexecution_authority,
        fault_hook=fault_hook,
    )


def validate_committed_report_final_capture_transaction(
    *,
    scratchpad: Path,
    project_root: Path,
    run_id: str,
    expected_config: Mapping[str, Any],
    derived_outputs: dict[str, tuple[str, bytes]],
    location_decisions: tuple[dict[str, Any], ...] = (),
    timeout_s: int = 120,
) -> bytes:
    """Read-only committed final replay; absence/uncommitted state rejects."""

    root, _project, _root_id, _project_id = _roots(
        scratchpad, project_root, expected_config
    )
    contract, _launch = _final_contract_and_launch(
        expected_config, timeout_s=timeout_s
    )
    if not _is_committed(_stored_unit(root, contract.key)):
        raise ArtifactLedgerError("report final capture is not committed")
    return run_report_final_capture_transaction(
        scratchpad=scratchpad,
        project_root=project_root,
        run_id=run_id,
        expected_config=expected_config,
        derived_outputs=derived_outputs,
        location_decisions=location_decisions,
        timeout_s=timeout_s,
    )


__all__ = [
    "FAULT_POINTS",
    "FINAL_CAPTURE_NAME",
    "SOURCE_CAPTURE_NAME",
    "run_report_final_capture_transaction",
    "run_report_source_capture_transaction",
    "validate_committed_report_final_capture_transaction",
    "validate_committed_report_source_capture_transaction",
]
