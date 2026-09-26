"""Crash-safe publication of committed-authority Program Facts v2 bytes."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
from typing import Any, Callable, Mapping

from jsonschema import Draft202012Validator

from artifact_ledger import (
    ArtifactLedgerError,
    read_artifact_ledger,
    record_work_unit_artifacts,
    record_work_unit_inputs,
    validate_work_unit_artifacts,
    validate_work_unit_inputs,
)
from evm_analysis_workspace_authority import (
    WORKSPACE_RECEIPT_PATH,
    load_evm_analysis_workspace_authority,
    require_admitted_workspace_tool,
    workspace_public_reference,
)
from phase_io_contracts import LaunchSpec, PhaseIOContract, resolve_phase_io_contract
from program_facts_types import canonical_file_bytes, canonical_json_bytes, strict_json_loads
from program_facts_workspace_v2 import (
    PROGRAM_FACTS_V2_ACTIVATION_AUTHORITY_PATH,
    PROGRAM_FACTS_V2_WORKER_OUTPUT_PATH,
    V2_ARTIFACT_IDENTITIES,
    WORKSPACE_CANDIDATE_SCHEMA,
    compose_workspace_bound_program_facts_v2,
)
import rooted_path_io


PROGRAM_FACTS_V2_AUTHORITY_CAPTURE_PATH = (
    "_program_facts_inputs/program_facts_v2_authority_capture.v1.json"
)
_CAPTURE_UNIT = "program_facts_v2_authority_capture"
_BAKE_UNIT = "program_facts_bake_v2"
_FaultInjector = Callable[[str], None]
_CAPTURE_SCHEMA_PATH = (
    Path(__file__).resolve().parents[1] / "rules" / "schemas"
    / "program_facts_v2_authority_capture.v1.schema.json"
)


class ProgramFactsV2DriverIntegrationError(RuntimeError):
    pass


@dataclass(frozen=True)
class ProgramFactsV2DriverOutcome:
    state: str
    valid: bool
    reused: bool
    reason_code: str = ""
    consumer_activation: bool = False

    def __post_init__(self) -> None:
        if self.consumer_activation:
            raise ProgramFactsV2DriverIntegrationError(
                "Program Facts v2 publication cannot activate consumers"
            )


def _fail(message: str, exc: BaseException | None = None) -> None:
    if exc is None:
        raise ProgramFactsV2DriverIntegrationError(message)
    raise ProgramFactsV2DriverIntegrationError(message) from exc


def _dimensions(config: Mapping[str, Any]) -> tuple[str, str, str, str]:
    language = str(config.get("language") or "").strip().lower()
    return (
        str(config.get("pipeline") or "sc").strip().lower(),
        str(config.get("mode") or "core").strip().lower(),
        {"solidity": "evm", "ethereum": "evm"}.get(language, language),
        str(config.get("cli_backend") or "claude").strip().lower(),
    )


def _resolve(
    config: Mapping[str, Any], unit: str, inputs: tuple[str, ...], outputs: tuple[str, ...]
) -> tuple[PhaseIOContract, LaunchSpec]:
    pipeline, mode, ecosystem, backend = _dimensions(config)
    contract = resolve_phase_io_contract(
        pipeline=pipeline, mode=mode, ecosystem=ecosystem, backend=backend,
        phase="recon", work_unit_id=unit, exact_inputs=inputs,
        exact_outputs=outputs, exact_writer="DRIVER",
    )
    return contract, LaunchSpec(
        work_unit_key=contract.key, pipeline=contract.pipeline, mode=contract.mode,
        ecosystem=contract.ecosystem, backend=contract.backend, model="driver",
        timeout_s=30, exec_mode="python", tool_policy=(),
    )


def _exact(path: Path, raw: bytes) -> bool:
    try:
        return rooted_path_io.read_bytes(
            path, label="Program Facts v2 output", require_single_link=True
        ) == raw
    except (FileNotFoundError, OSError, rooted_path_io.RootedPathIOError):
        return False


def _materialize(path: Path, raw: bytes) -> None:
    if _exact(path, raw):
        return
    rooted_path_io.ensure_directory(path.parent, parents=True, label="PF v2 parent")
    descriptor, temporary = rooted_path_io.exclusive_temp_file(
        path.parent, prefix=".program-facts-v2.", suffix=".publishing.tmp"
    )
    try:
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = -1
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        rooted_path_io.durable_replace(temporary, path)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if rooted_path_io.lexists(temporary):
            rooted_path_io.unlink(temporary)


def _publish(
    *, scratchpad: Path, project_root: Path, contract: PhaseIOContract,
    launch: LaunchSpec, run_id: str, outputs: Mapping[str, bytes],
    fault_injector: _FaultInjector | None,
) -> bool:
    if tuple(outputs) != tuple(row.path for row in contract.outputs):
        _fail(f"{contract.key}: publication denominator/order drift")
    unit = read_artifact_ledger(scratchpad).get("work_units", {}).get(contract.key)
    if unit is None:
        try:
            unit = record_work_unit_inputs(
                scratchpad, project_root, contract, launch, run_id=run_id
            )
        except ArtifactLedgerError as exc:
            _fail(f"{contract.key}: input arm failed", exc)
    if not isinstance(unit, Mapping):
        _fail(f"{contract.key}: stored authority malformed")
    if unit.get("semantic_status") == "ACTIVE":
        issues = validate_work_unit_artifacts(
            scratchpad, project_root, contract, launch,
            run_id=run_id, actor="DRIVER", require_live_input_authority=False,
        )
        if issues or any(
            not _exact(scratchpad / path, raw) for path, raw in outputs.items()
        ):
            _fail(f"{contract.key}: committed replay failed:" + ";".join(issues))
        return True
    issues = validate_work_unit_inputs(
        scratchpad, project_root, contract, launch, run_id=run_id
    )
    if issues:
        _fail(f"{contract.key}: input replay failed:" + ";".join(issues))
    for ordinal, (path, raw) in enumerate(outputs.items(), start=1):
        _materialize(scratchpad / path, raw)
        if fault_injector:
            fault_injector(f"{contract.work_unit_id}:published:{ordinal}")
    try:
        record_work_unit_artifacts(
            scratchpad, project_root, contract, launch, run_id=run_id,
            actor="DRIVER", expected_output_records={
                f"scratchpad:{path}": {
                    "sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw)
                } for path, raw in outputs.items()
            },
        )
    except ArtifactLedgerError as exc:
        _fail(f"{contract.key}: output commit failed", exc)
    return False


def _capture_contract(
    config: Mapping[str, Any],
) -> tuple[PhaseIOContract, LaunchSpec]:
    return _resolve(
        config, _CAPTURE_UNIT, (WORKSPACE_RECEIPT_PATH,),
        (PROGRAM_FACTS_V2_AUTHORITY_CAPTURE_PATH,),
    )


def _capture_schema(value: Mapping[str, Any]) -> None:
    schema = json.loads(_CAPTURE_SCHEMA_PATH.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    errors = list(Draft202012Validator(schema).iter_errors(value))
    if errors:
        _fail(f"Program Facts v2 capture schema:{errors[0].message}")


def _candidate_preimage(candidate: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": candidate["schema_version"],
        "workspace_reference": candidate["workspace_reference"],
        "execution_authority": candidate["execution_authority"],
        "dependency_closure": candidate["dependency_closure"],
        "artifacts": [
            {"identity": identity, "size": len(raw),
             "sha256": hashlib.sha256(raw).hexdigest()}
            for identity, raw in candidate["artifacts"]
        ],
    }


def _capture_from_candidate(
    *, scratchpad: Path, candidate: Mapping[str, Any], run_id: str,
) -> dict[str, Any]:
    owner = str(candidate["workspace_reference"]["owner_work_unit_key"])
    prefix = owner.split("/")[:4]
    ledger = read_artifact_ledger(scratchpad)
    worker_key = "/".join((*prefix, "recon", "program_facts_provider"))
    activation_key = "/".join(
        (*prefix, "recon", "program_facts_v2_activation_authority")
    )
    worker = ledger.get("work_units", {}).get(worker_key)
    activation = ledger.get("work_units", {}).get(activation_key)
    if not isinstance(worker, Mapping) or not isinstance(activation, Mapping):
        _fail("Program Facts v2 committed lineage disappeared before capture")
    worker_raw = rooted_path_io.read_bytes(
        scratchpad / PROGRAM_FACTS_V2_WORKER_OUTPUT_PATH,
        label="PF v2 worker output", require_single_link=True,
    )
    activation_raw = rooted_path_io.read_bytes(
        scratchpad / PROGRAM_FACTS_V2_ACTIVATION_AUTHORITY_PATH,
        label="PF v2 activation authority", require_single_link=True,
    )
    public_artifacts = [
        {"logical_identity": identity, "document": strict_json_loads(
            raw, require_final_lf=True
        )}
        for identity, raw in candidate["artifacts"]
    ]
    unsigned = {
        "schema_version": "plamen.program_facts_v2_authority_capture.v2",
        "run_id": run_id,
        "workspace_reference": candidate["workspace_reference"],
        "worker_owner_work_unit_key": worker_key,
        "worker_execution_authority": worker["execution_authority"],
        "worker_contract_manifest": worker["contract_manifest"],
        "worker_launch_manifest": worker["launch_manifest"],
        "worker_output": strict_json_loads(worker_raw, require_final_lf=True),
        "activation_owner_work_unit_key": activation_key,
        "activation_authority": strict_json_loads(
            activation_raw, require_final_lf=True
        ),
        "candidate": {
            key: value for key, value in candidate.items() if key != "artifacts"
        },
        "public_artifacts": public_artifacts,
        "terminal_negative_authority": False,
    }
    return {**unsigned, "capture_sha256": hashlib.sha256(
        canonical_json_bytes(unsigned)
    ).hexdigest()}


def _candidate_from_capture(
    *, capture: Mapping[str, Any], workspace: Mapping[str, Any], run_id: str,
) -> dict[str, Any]:
    _capture_schema(capture)
    unsigned = dict(capture)
    claimed = unsigned.pop("capture_sha256")
    if hashlib.sha256(canonical_json_bytes(unsigned)).hexdigest() != claimed:
        _fail("Program Facts v2 capture self-digest differs")
    reference = workspace_public_reference(workspace)
    if capture["run_id"] != run_id or capture["workspace_reference"] != reference:
        _fail("Program Facts v2 capture workspace/run differs")
    artifacts = tuple(
        (row["logical_identity"], canonical_file_bytes(row["document"]))
        for row in capture["public_artifacts"]
    )
    if tuple(identity for identity, _raw in artifacts) != V2_ARTIFACT_IDENTITIES:
        _fail("Program Facts v2 capture output denominator differs")
    candidate = {**capture["candidate"], "artifacts": artifacts}
    if candidate.get("schema_version") != WORKSPACE_CANDIDATE_SCHEMA:
        _fail("V1_DOWNGRADE_REJECTED")
    if candidate.get("candidate_sha256") != hashlib.sha256(
        canonical_json_bytes(_candidate_preimage(candidate))
    ).hexdigest():
        _fail("Program Facts v2 captured candidate digest differs")
    execution = candidate["execution_authority"]
    worker_authority = capture["worker_execution_authority"]
    worker_output_raw = canonical_file_bytes(capture["worker_output"])
    activation = capture["activation_authority"]
    if (
        worker_authority.get("authority_digest")
        != execution.get("worker_execution_authority_sha256")
        or hashlib.sha256(worker_output_raw).hexdigest()
        != execution.get("worker_output_sha256")
        or activation.get("activation_authority_sha256")
        != execution.get("activation_authority_sha256")
    ):
        _fail("Program Facts v2 captured WTX/activation lineage differs")
    for tool_id, field in (
        ("slither", "slither_tool_row_sha256"),
        ("solc", "solc_tool_row_sha256"),
    ):
        if require_admitted_workspace_tool(workspace, tool_id)[
            "tool_row_sha256"
        ] != execution[field]:
            _fail("Program Facts v2 captured tool lineage differs")
    if (
        execution["build_variant_sha256"] != reference["build_variant_sha256"]
        or execution["dependency_closure_sha256"]
        != reference["dependency_closure_sha256"]
    ):
        _fail("Program Facts v2 captured build lineage differs")
    # Reuse the public validator over the exact captured bytes.  This is the
    # recovery authority after mutable WTX attempt sidecars are gone.
    values = [strict_json_loads(raw, require_final_lf=True) for _identity, raw in artifacts]
    receipt = values[1]
    validate_program_facts_v2_representation_v1 = __import__(
        "program_facts_types", fromlist=["validate_program_facts_v2_representation_v1"]
    ).validate_program_facts_v2_representation_v1
    validate_program_facts_v2_representation_v1(
        {
            "schema_version": "plamen.program_facts_public_v2_bundle.v1",
            "payload": values[0], "receipt": receipt, "debt": values[2],
            "expected_provider_lineage": receipt["provider_executions"],
            "legacy_projection": {
                "source_snapshot_digest": reference["snapshot_sha256"],
                "provider_id": "evm.slither.typed", "status": receipt["status"],
            },
            "ledger_binding": {
                "receipt_full_file_size": len(artifacts[1][1]),
                "receipt_full_file_sha256": hashlib.sha256(
                    artifacts[1][1]
                ).hexdigest(),
            },
        },
        captured_authority=receipt["authority_bindings"],
        current_authority=receipt["authority_bindings"],
    )
    return candidate


def ensure_program_facts_v2_workspace_bound(
    *, config: Mapping[str, Any], scratchpad: Path, project_root: Path,
    run_id: str, audit_snapshot_digest: str,
    fault_injector: _FaultInjector | None = None,
) -> ProgramFactsV2DriverOutcome:
    root, project = Path(scratchpad), Path(project_root)
    workspace = load_evm_analysis_workspace_authority(
        root, expected_run_id=run_id,
        expected_snapshot_sha256=audit_snapshot_digest,
    )
    capture_contract, capture_launch = _capture_contract(config)
    capture_unit = read_artifact_ledger(root).get("work_units", {}).get(
        capture_contract.key
    )
    if isinstance(capture_unit, Mapping) and capture_unit.get(
        "semantic_status"
    ) == "ACTIVE":
        issues = validate_work_unit_artifacts(
            root, project, capture_contract, capture_launch, run_id=run_id,
            actor="DRIVER", require_live_input_authority=False,
        )
        if issues:
            _fail("Program Facts v2 committed capture replay failed:" + ";".join(issues))
        capture = strict_json_loads(
            rooted_path_io.read_bytes(
                root / PROGRAM_FACTS_V2_AUTHORITY_CAPTURE_PATH,
                label="PF v2 authority capture", require_single_link=True,
            ), require_final_lf=True,
        )
        candidate = _candidate_from_capture(
            capture=capture, workspace=workspace, run_id=run_id
        )
        capture_reused = True
    else:
        try:
            candidate = compose_workspace_bound_program_facts_v2(
                workspace_scratchpad=root, project_root=project,
                expected_run_id=run_id,
                expected_snapshot_sha256=audit_snapshot_digest,
                expected_owner_work_unit_key=str(workspace["owner"]["work_unit_key"]),
            )
        except Exception as exc:
            reason = str(exc)
            if "COMMITTED_AUTHORITY_MISSING" in reason:
                return ProgramFactsV2DriverOutcome(
                    state="TYPED_DEBT", valid=False, reused=False,
                    reason_code=reason, consumer_activation=False,
                )
            _fail("Program Facts v2 authority derivation failed", exc)
        if candidate.get("schema_version") != WORKSPACE_CANDIDATE_SCHEMA:
            return ProgramFactsV2DriverOutcome(
                state="TYPED_DEBT", valid=False, reused=False,
                reason_code="WORKSPACE_TOOL_UNADMITTED", consumer_activation=False,
            )
        capture = _capture_from_candidate(
            scratchpad=root, candidate=candidate, run_id=run_id
        )
        _capture_schema(capture)
        capture_reused = _publish(
            scratchpad=root, project_root=project, contract=capture_contract,
            launch=capture_launch, run_id=run_id,
            outputs={
                PROGRAM_FACTS_V2_AUTHORITY_CAPTURE_PATH: canonical_file_bytes(capture)
            }, fault_injector=fault_injector,
        )
        # Re-read the durable capture before any public publication.
        candidate = _candidate_from_capture(
            capture=strict_json_loads(
                rooted_path_io.read_bytes(
                    root / PROGRAM_FACTS_V2_AUTHORITY_CAPTURE_PATH,
                    label="PF v2 authority capture", require_single_link=True,
                ), require_final_lf=True,
            ), workspace=workspace, run_id=run_id,
        )
    bake_contract, bake_launch = _resolve(
        config, _BAKE_UNIT,
        (WORKSPACE_RECEIPT_PATH, PROGRAM_FACTS_V2_AUTHORITY_CAPTURE_PATH),
        V2_ARTIFACT_IDENTITIES,
    )
    bake_reused = _publish(
        scratchpad=root, project_root=project, contract=bake_contract,
        launch=bake_launch, run_id=run_id,
        outputs={identity: raw for identity, raw in candidate["artifacts"]},
        fault_injector=fault_injector,
    )
    receipt = strict_json_loads(candidate["artifacts"][1][1], require_final_lf=True)
    state = str(receipt["status"])
    return ProgramFactsV2DriverOutcome(
        state=state, valid=True, reused=capture_reused and bake_reused,
        reason_code=("ACTIVATION_PERMIT_ABSENT_DENIED" if state == "UNAVAILABLE" else ""),
        consumer_activation=False,
    )


__all__ = [
    "PROGRAM_FACTS_V2_AUTHORITY_CAPTURE_PATH",
    "ProgramFactsV2DriverIntegrationError",
    "ProgramFactsV2DriverOutcome",
    "ensure_program_facts_v2_workspace_bound",
]
