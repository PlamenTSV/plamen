"""Authenticated immutable inputs for deterministic severity planning."""
from __future__ import annotations

import hashlib
import json
import stat
from pathlib import Path
from typing import Any, Callable, Mapping

import rooted_path_io as rooted_io
from artifact_ledger import (
    ArtifactLedgerError,
    _canonical_json_digest,
    read_artifact_ledger,
    record_work_unit_artifacts,
    record_work_unit_inputs,
    semantic_input_prebind_producer_authority_issues,
    validate_work_unit_artifacts,
    validate_work_unit_inputs,
)
from audit_snapshot import (
    build_audit_snapshot,
    canonical_semantic_config_bytes,
)
from phase_io_contracts import LaunchSpec, canonical_work_unit_key, resolve_phase_io_contract


INPUT_DIRECTORY = "_severity_adjudication_inputs"
SOURCE_LEDGER_INPUT = f"{INPUT_DIRECTORY}/source_ledger.initial.json"
AUDIT_SNAPSHOT_INPUT = f"{INPUT_DIRECTORY}/audit_snapshot.json"
AUDIT_CONFIG_INPUT = f"{INPUT_DIRECTORY}/audit_config.json"
FINDING_FORMAT_INPUT = f"{INPUT_DIRECTORY}/finding-output-format.md"
POC_EXECUTION_INPUT = f"{INPUT_DIRECTORY}/poc-execution.md"
REPORT_TEMPLATE_INPUT = f"{INPUT_DIRECTORY}/report-template.md"
L1_SEVERITY_MATRIX_INPUT = f"{INPUT_DIRECTORY}/l1-severity-matrix.md"

COMMON_INPUTS = (
    AUDIT_SNAPSHOT_INPUT,
    AUDIT_CONFIG_INPUT,
    FINDING_FORMAT_INPUT,
    POC_EXECUTION_INPUT,
)
PIPELINE_INPUT = {
    "sc": REPORT_TEMPLATE_INPUT,
    "l1": L1_SEVERITY_MATRIX_INPUT,
}
FAULT_POINTS = (
    "after_arm",
    "after_output_1",
    "after_output_2",
    "after_output_3",
    "after_output_4",
    "after_output_5",
    "before_commit",
    "after_commit",
)

_METHODOLOGY_SOURCES = {
    "finding_output_format": (
        "rules/finding-output-format.md",
        FINDING_FORMAT_INPUT,
    ),
    "poc_execution": (
        "rules/phase5-poc-execution.md",
        POC_EXECUTION_INPUT,
    ),
    "report_template": (
        "rules/report-template.md",
        REPORT_TEMPLATE_INPUT,
    ),
    "l1_severity_matrix": (
        "docs/l1-mode/severity-matrix.md",
        L1_SEVERITY_MATRIX_INPUT,
    ),
}
_PIPELINE_METHODS = {
    "sc": ("finding_output_format", "poc_execution", "report_template"),
    "l1": ("finding_output_format", "poc_execution", "l1_severity_matrix"),
}
_MAX_CAPTURE_BYTES = 16 * 1024 * 1024


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _canonical_digest(value: Mapping[str, Any]) -> str:
    return _sha(_canonical_json(dict(value)))


def _invocation_authority(core: Mapping[str, Any]) -> dict[str, Any]:
    unsigned = dict(core)
    return {
        **unsigned,
        "authority_sha256": _canonical_json_digest(unsigned),
    }


def validate_initial_severity_source_input(
    root: Path, project: Path, *, config: Mapping[str, Any],
) -> tuple[bytes, dict[str, Any]]:
    """Read exact immutable bytes from a same-run initial source producer.

    This is not a copy of the mutable canonical ledger, nor an import path for
    arbitrary snapshot files. Full current producer ancestry must replay before
    capture can arm. Historical successor replay belongs to PhaseIO, not here.
    """
    identity = f"scratchpad:{SOURCE_LEDGER_INPUT}"
    run_id = config.get("_run_id")
    if not isinstance(run_id, str) or not run_id or run_id != run_id.strip():
        raise ArtifactLedgerError("severity planning source requires an exact run")
    try:
        raw = rooted_io.read_bytes(
            rooted_io.safe_descendant(
                root, SOURCE_LEDGER_INPUT, allow_missing=False,
                label="severity planning initial source",
            ),
            label="severity planning initial source",
            require_single_link=True, max_bytes=32 * 1024 * 1024,
        )
    except (OSError, rooted_io.RootedPathIOError) as exc:
        raise ArtifactLedgerError(f"severity planning initial source unavailable: {exc}") from exc
    issues = semantic_input_prebind_producer_authority_issues(
        root, project, (identity,), run_id=run_id,
    )
    if issues:
        raise ArtifactLedgerError(
            "severity planning initial source producer invalid: " + "; ".join(issues)
        )
    ledger = read_artifact_ledger(root)
    binding = ledger.get("artifact_bindings", {}).get(identity)
    expected_owners = {
        canonical_work_unit_key(
            str(config.get("pipeline") or "").strip().lower(),
            str(config.get("mode") or "core"),
            str(config.get("language") or config.get("ecosystem") or "evm"),
            str(config.get("cli_backend") or config.get("backend") or "claude"),
            "severity_adjudication_shadow", source,
        )
        for source in ("source_empty", "source_aggregate")
    }
    if not isinstance(binding, Mapping) or (
        binding.get("owner_key") not in expected_owners
        or binding.get("writer") != "DRIVER"
        or binding.get("run_id") != run_id
        or binding.get("sha256") != _sha(raw)
        or binding.get("size") != len(raw)
    ):
        raise ArtifactLedgerError("severity planning initial source owner/bytes differ")
    return raw, {
        field: binding.get(field)
        for field in (
            "owner_key", "writer", "run_id", "contract_digest",
            "launch_digest", "sha256", "size",
        )
    }


def _directory_identity(path: Path, *, label: str) -> dict[str, Any]:
    checked = rooted_io.checked_directory(path, label=label)
    try:
        row = rooted_io.lstat(checked)
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


def _read_methodology(
    implementation: Path,
    *,
    pipeline: str,
) -> tuple[dict[str, bytes], dict[str, str]]:
    captured: dict[str, bytes] = {}
    sources: dict[str, str] = {}
    for logical in _PIPELINE_METHODS[pipeline]:
        source_relative, captured_relative = _METHODOLOGY_SOURCES[logical]
        try:
            raw = rooted_io.read_bytes(
                implementation / source_relative,
                label=f"severity planning methodology {logical}",
                require_single_link=True,
                max_bytes=_MAX_CAPTURE_BYTES,
            )
            text = raw.decode("utf-8", errors="strict")
        except (OSError, UnicodeError, rooted_io.RootedPathIOError) as exc:
            raise ArtifactLedgerError(
                f"severity planning methodology {logical} is invalid: {exc}"
            ) from exc
        if not text.strip():
            raise ArtifactLedgerError(
                f"severity planning methodology {logical} is empty"
            )
        captured[captured_relative] = raw
        sources[logical] = source_relative
    return captured, sources


def _snapshot_and_outputs(
    implementation: Path,
    *,
    config: Mapping[str, Any],
    pipeline: str,
) -> tuple[dict[str, Any], dict[str, bytes], dict[str, str]]:
    bound_snapshot = config.get("_audit_snapshot")
    if not isinstance(bound_snapshot, Mapping):
        raise ArtifactLedgerError(
            "severity planning requires a bound audit snapshot"
        )
    try:
        live_snapshot = build_audit_snapshot(config, implementation)
    except Exception as exc:
        raise ArtifactLedgerError(
            f"severity planning live audit snapshot is unavailable: {exc}"
        ) from exc
    if dict(bound_snapshot) != live_snapshot:
        raise ArtifactLedgerError(
            "severity planning bound audit snapshot differs from live inputs"
        )

    config_raw = canonical_semantic_config_bytes(config)
    try:
        decoded_config = json.loads(config_raw.decode("utf-8"))
    except (UnicodeError, ValueError) as exc:
        raise ArtifactLedgerError(
            f"severity planning audit-config preimage is invalid: {exc}"
        ) from exc
    if not isinstance(decoded_config, dict):
        raise ArtifactLedgerError(
            "severity planning audit-config preimage is not an object"
        )
    config_component = {
        "digest": _sha(config_raw),
        "field_count": len(decoded_config),
    }
    snapshot_config = live_snapshot.get("components", {}).get("audit_config")
    if (
        not isinstance(snapshot_config, Mapping)
        or dict(snapshot_config) != config_component
    ):
        raise ArtifactLedgerError(
            "severity planning audit-config preimage differs from snapshot"
        )

    methodology, sources = _read_methodology(
        implementation, pipeline=pipeline
    )
    outputs = {
        AUDIT_SNAPSHOT_INPUT: _canonical_json(live_snapshot),
        AUDIT_CONFIG_INPUT: config_raw,
        **methodology,
    }
    return live_snapshot, outputs, sources


def _contract_and_launch(config: Mapping[str, Any], outputs: tuple[str, ...]):
    contract = resolve_phase_io_contract(
        pipeline=str(config.get("pipeline") or "").strip().lower(),
        mode=str(config.get("mode") or "core"),
        ecosystem=str(
            config.get("language") or config.get("ecosystem") or "evm"
        ),
        backend=str(
            config.get("cli_backend") or config.get("backend") or "claude"
        ),
        phase="severity_adjudication_shadow",
        work_unit_id="planning_inputs",
        exact_inputs=(SOURCE_LEDGER_INPUT,),
        exact_outputs=outputs,
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


def _revalidate_sources(
    implementation: Path,
    *,
    root: Path,
    project: Path,
    expected_source: tuple[bytes, dict[str, Any]],
    config: Mapping[str, Any],
    pipeline: str,
    expected_snapshot: Mapping[str, Any],
    expected_outputs: Mapping[str, bytes],
    expected_implementation_identity: Mapping[str, Any],
) -> None:
    if validate_initial_severity_source_input(root, project, config=config) != expected_source:
        raise ArtifactLedgerError("severity planning initial source changed after capture")
    if _directory_identity(
        implementation, label="severity planning implementation root"
    ) != dict(expected_implementation_identity):
        raise ArtifactLedgerError(
            "severity planning implementation root identity changed"
        )
    snapshot, outputs, _sources = _snapshot_and_outputs(
        implementation, config=config, pipeline=pipeline
    )
    if snapshot != dict(expected_snapshot) or outputs != dict(expected_outputs):
        raise ArtifactLedgerError(
            "severity planning source inputs changed after capture"
        )


def capture_severity_planning_inputs(
    *,
    scratchpad: Path,
    project_root: Path,
    implementation_root: Path,
    config: Mapping[str, Any],
    fault_hook: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    """Capture and authenticate the exact immutable severity-planning inputs."""

    root = rooted_io.checked_directory(
        scratchpad, label="severity planning scratchpad"
    )
    project = rooted_io.checked_directory(
        project_root, label="severity planning project"
    )
    implementation = rooted_io.checked_directory(
        implementation_root, label="severity planning implementation root"
    )
    pipeline = str(config.get("pipeline") or "").strip().lower()
    raw_run_id = config.get("_run_id")
    if (
        pipeline not in {"sc", "l1"}
        or not isinstance(raw_run_id, str)
        or not raw_run_id
        or raw_run_id != raw_run_id.strip()
    ):
        raise ArtifactLedgerError(
            "severity planning capture requires an exact SC or L1 run"
        )
    run_id = raw_run_id
    configured_root = rooted_io.checked_directory(
        str(config.get("scratchpad") or ""),
        label="configured severity planning scratchpad",
    )
    configured_project = rooted_io.checked_directory(
        str(config.get("project_root") or ""),
        label="configured severity planning project",
    )
    if configured_root != root or configured_project != project:
        raise ArtifactLedgerError(
            "severity planning capture roots differ from configuration"
        )

    root_identity = _directory_identity(
        root, label="severity planning scratchpad"
    )
    project_identity = _directory_identity(
        project, label="severity planning project"
    )
    implementation_identity = _directory_identity(
        implementation, label="severity planning implementation root"
    )
    snapshot, output_bytes, source_relatives = _snapshot_and_outputs(
        implementation, config=config, pipeline=pipeline
    )
    initial_source = validate_initial_severity_source_input(root, project, config=config)
    output_names = (*COMMON_INPUTS, PIPELINE_INPUT[pipeline])
    if tuple(output_bytes) != output_names:
        raise ArtifactLedgerError(
            "severity planning capture output order differs"
        )
    expected_records = {
        f"scratchpad:{relative}": {
            "sha256": _sha(output_bytes[relative]),
            "size": len(output_bytes[relative]),
        }
        for relative in output_names
    }
    authority_core = {
        "schema": "plamen.severity-planning-input-capture.v1",
        "run_id": run_id,
        "pipeline": pipeline,
        "root_identities": {
            "scratchpad": root_identity,
            "project": project_identity,
            "implementation": implementation_identity,
        },
        "audit_snapshot_digest": snapshot["snapshot_digest"],
        "audit_config_digest": snapshot["components"]["audit_config"][
            "digest"
        ],
        "methodology_sources": source_relatives,
        "initial_source": {"path": SOURCE_LEDGER_INPUT, **initial_source[1]},
        "expected_outputs": expected_records,
    }
    invocation = _invocation_authority(authority_core)
    contract, launch = _contract_and_launch(config, output_names)
    rooted_io.ensure_directory(
        root / INPUT_DIRECTORY,
        mode=0o700,
        label="severity planning capture directory",
    )

    ledger = read_artifact_ledger(root)
    prior = ledger.get("work_units", {}).get(contract.key)
    if not isinstance(prior, Mapping):
        bindings = ledger.get("artifact_bindings", {})
        if any(
            rooted_io.lexists(root / relative)
            or isinstance(bindings.get(f"scratchpad:{relative}"), Mapping)
            for relative in output_names
        ):
            raise ArtifactLedgerError(
                "severity planning capture refuses pre-existing output authority"
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
        raise ArtifactLedgerError(
            "severity planning capture transaction identity changed"
        )

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
            "severity planning capture input replay failed: "
            + "; ".join(input_issues)
        )
    _revalidate_sources(
        implementation,
        root=root, project=project, expected_source=initial_source,
        config=config,
        pipeline=pipeline,
        expected_snapshot=snapshot,
        expected_outputs=output_bytes,
        expected_implementation_identity=implementation_identity,
    )
    if (
        _directory_identity(root, label="severity planning scratchpad")
        != root_identity
        or _directory_identity(project, label="severity planning project")
        != project_identity
    ):
        raise ArtifactLedgerError(
            "severity planning capture root identity changed"
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
                "severity planning capture output replay failed: "
                + "; ".join(output_issues)
            )
    else:
        if not (
            isinstance(unit, Mapping)
            and unit.get("semantic_status") == "INPUTS_BOUND"
            and unit.get("execution_state") == "INPUTS_BOUND_PREEXECUTION"
            and unit.get("artifacts") == {}
        ):
            raise ArtifactLedgerError(
                "severity planning capture transaction is not armed"
            )
        prestates = unit.get("output_prestates")
        if (
            not isinstance(prestates, Mapping)
            or set(prestates) != set(expected_records)
            or any(
                not isinstance(prestates.get(identity), Mapping)
                or prestates[identity].get("status") != "ABSENT"
                for identity in expected_records
            )
        ):
            raise ArtifactLedgerError(
                "severity planning capture requires absent output prestates"
            )
        for relative in output_names:
            destination = root / relative
            if rooted_io.lexists(destination):
                try:
                    observed = rooted_io.read_bytes(
                        destination,
                        label=f"severity planning partial output {relative}",
                        require_single_link=True,
                        max_bytes=len(output_bytes[relative]),
                    )
                except (OSError, rooted_io.RootedPathIOError) as exc:
                    raise ArtifactLedgerError(
                        f"severity planning partial output is invalid: {exc}"
                    ) from exc
                if observed != output_bytes[relative]:
                    raise ArtifactLedgerError(
                        "severity planning capture has arbitrary partial bytes: "
                        f"{relative}"
                    )

        hook = fault_hook or (lambda _point: None)
        hook("after_arm")
        if (
            _directory_identity(root, label="severity planning scratchpad")
            != root_identity
            or _directory_identity(project, label="severity planning project")
            != project_identity
        ):
            raise ArtifactLedgerError(
                "severity planning capture root identity changed"
            )
        _revalidate_sources(
            implementation,
            root=root, project=project, expected_source=initial_source,
            config=config,
            pipeline=pipeline,
            expected_snapshot=snapshot,
            expected_outputs=output_bytes,
            expected_implementation_identity=implementation_identity,
        )
        for ordinal, relative in enumerate(output_names, 1):
            rooted_io.durable_write_once_bytes(
                root / relative, output_bytes[relative]
            )
            hook(f"after_output_{ordinal}")
            if (
                _directory_identity(
                    root, label="severity planning scratchpad"
                )
                != root_identity
                or _directory_identity(
                    project, label="severity planning project"
                )
                != project_identity
            ):
                raise ArtifactLedgerError(
                    "severity planning capture root identity changed"
                )
            _revalidate_sources(
                implementation,
                root=root, project=project, expected_source=initial_source,
                config=config,
                pipeline=pipeline,
                expected_snapshot=snapshot,
                expected_outputs=output_bytes,
                expected_implementation_identity=implementation_identity,
            )
        hook("before_commit")
        if (
            _directory_identity(root, label="severity planning scratchpad")
            != root_identity
            or _directory_identity(project, label="severity planning project")
            != project_identity
        ):
            raise ArtifactLedgerError(
                "severity planning capture root identity changed"
            )
        _revalidate_sources(
            implementation,
            root=root, project=project, expected_source=initial_source,
            config=config,
            pipeline=pipeline,
            expected_snapshot=snapshot,
            expected_outputs=output_bytes,
            expected_implementation_identity=implementation_identity,
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
                "severity planning capture commit replay failed: "
                + "; ".join(output_issues)
            )
        hook("after_commit")

    # A returned capture is authority, including when a fault hook mutates an
    # input/output after the commit. Never return stale success from that edge.
    _revalidate_sources(
        implementation, root=root, project=project, expected_source=initial_source,
        config=config, pipeline=pipeline, expected_snapshot=snapshot,
        expected_outputs=output_bytes,
        expected_implementation_identity=implementation_identity,
    )
    if (
        _directory_identity(root, label="severity planning scratchpad") != root_identity
        or _directory_identity(project, label="severity planning project") != project_identity
    ):
        raise ArtifactLedgerError("severity planning capture root identity changed")
    final_issues = validate_work_unit_inputs(
        root, project, contract, launch, run_id=run_id,
        preexecution_authority=invocation,
    )
    final_issues.extend(validate_work_unit_artifacts(
        root, project, contract, launch, run_id=run_id, actor="DRIVER",
        preexecution_authority=invocation,
    ))
    if final_issues:
        raise ArtifactLedgerError(
            "severity planning capture final replay failed: " + "; ".join(final_issues)
        )

    return {
        "schema": "plamen.severity-planning-inputs.v1",
        "phase_io_owner_key": contract.key,
        "exact_inputs": (SOURCE_LEDGER_INPUT, *output_names),
        "source_ledger_path": root / SOURCE_LEDGER_INPUT,
        "source_ledger_digest": _sha(initial_source[0]),
        "methodology_files": {
            logical: root / captured
            for logical, (_source, captured) in _METHODOLOGY_SOURCES.items()
            if logical in _PIPELINE_METHODS[pipeline]
        },
        "audit_snapshot_digest": snapshot["snapshot_digest"],
        "audit_config_digest": snapshot["components"]["audit_config"][
            "digest"
        ],
    }


__all__ = [
    "AUDIT_CONFIG_INPUT",
    "AUDIT_SNAPSHOT_INPUT",
    "COMMON_INPUTS",
    "FAULT_POINTS",
    "FINDING_FORMAT_INPUT",
    "INPUT_DIRECTORY",
    "L1_SEVERITY_MATRIX_INPUT",
    "PIPELINE_INPUT",
    "POC_EXECUTION_INPUT",
    "REPORT_TEMPLATE_INPUT",
    "SOURCE_LEDGER_INPUT",
    "capture_severity_planning_inputs",
    "validate_initial_severity_source_input",
]
