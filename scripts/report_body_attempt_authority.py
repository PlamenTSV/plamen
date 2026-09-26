"""Closed retry identity authority for report-body MODEL generations."""
from __future__ import annotations

from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Mapping

from artifact_ledger import ArtifactLedgerError, read_artifact_ledger
from phase_io_contracts import (
    LaunchSpec,
    PhaseIOContract,
    canonical_work_unit_key,
    parse_report_body_attempt_work_unit,
    report_body_attempt_work_unit_id,
    resolve_phase_io_contract,
)
from report_model_preimages import read_report_model_preimages


@dataclass(frozen=True)
class ReportBodyAttemptAuthority:
    shard: str
    ordinal: int
    model_work_unit_id: str
    projection_work_unit_id: str
    predecessor_owner_key: str
    predecessor_model_execution_authority_digest: str
    resume_existing: bool


def report_body_shard_for_phase(phase_name: str) -> str:
    prefix = "report_body_writer_"
    if type(phase_name) is not str or not phase_name.startswith(prefix):
        raise ArtifactLedgerError("report-body phase name is unsupported")
    shard = "report_" + phase_name[len(prefix):]
    # Reuse the canonical builder as the one closed shard grammar.
    report_body_attempt_work_unit_id("model", shard, 1)
    return shard


def _unit_is_exact(
    unit: Any, *, key: str, run_id: str, role: str,
) -> bool:
    if not isinstance(unit, Mapping):
        return False
    manifest = unit.get("contract_manifest")
    return bool(
        unit.get("schema") == "plamen.artifact-work-unit.v2"
        and unit.get("work_unit_key") == key
        and unit.get("run_id") == run_id
        and unit.get("model_invoked") is (role == "model")
        and isinstance(manifest, Mapping)
        and manifest.get("key") == key
        and manifest.get("model_invoked") is (role == "model")
    )


def _report_body_history_relative(
    key: Any, *, key_prefix: str, shard: str,
) -> str | None:
    """Return one exact report-body row, rejecting target-shaped aliases."""

    if type(key) is not str:
        return None
    expected = key_prefix.split("/")
    parts = key.split("/")
    if len(expected) != 5 or len(parts) < 6:
        return None
    if tuple(part.casefold() for part in parts[:5]) != tuple(
        part.casefold() for part in expected
    ):
        return None
    target_prefixes = (
        f"model.{shard}".casefold(),
        f"evidence_projection.{shard}".casefold(),
    )
    target_shaped = any(
        component.casefold().startswith(target_prefixes)
        for component in parts[5:]
    )
    if not target_shaped:
        return None
    if len(parts) != 6 or parts[:5] != expected:
        raise ArtifactLedgerError(
            "report-body attempt history has a non-canonical target key"
        )
    return parts[5]


def resolve_report_body_model_attempt_ordinal(
    scratchpad: Path,
    *,
    pipeline: str,
    mode: str,
    ecosystem: str,
    backend: str,
    run_id: str,
    shard: str,
    configured_ordinal: int | None = None,
) -> int:
    """Recover the current MODEL generation when no live request is present.

    ``configured_ordinal`` is an execution-local request.  It may name the
    exact next generation before that generation has a ledger row, so its
    relationship to history remains the responsibility of
    :func:`require_report_body_attempt_authority`.  Without that request, only
    exact admitted same-run MODEL rows may restore the resume ordinal.
    """

    dimensions = (pipeline, mode, ecosystem, backend)
    if any(type(value) is not str or not value for value in dimensions):
        raise ArtifactLedgerError("report-body attempt dimensions are invalid")
    if type(run_id) is not str or not run_id:
        raise ArtifactLedgerError("report-body attempt run_id is invalid")
    try:
        initial_id = report_body_attempt_work_unit_id("model", shard, 1)
        initial_key = canonical_work_unit_key(
            pipeline, mode, ecosystem, backend, "report_body", initial_id,
        )
    except ValueError as exc:
        raise ArtifactLedgerError(
            f"report-body attempt dimensions are invalid: {exc}"
        ) from exc
    supplied_key = "/".join((
        pipeline, mode, ecosystem, backend, "report_body", initial_id,
    ))
    if initial_key != supplied_key:
        raise ArtifactLedgerError(
            "report-body attempt dimensions are not canonical"
        )
    if configured_ordinal is not None:
        if (
            type(configured_ordinal) is not int
            or configured_ordinal < 1
            or configured_ordinal > 9999
        ):
            raise ArtifactLedgerError(
                "configured report-body attempt ordinal is outside 1..9999"
            )
        return configured_ordinal

    ledger = read_artifact_ledger(Path(scratchpad))
    work_units = ledger.get("work_units")
    if not isinstance(work_units, Mapping):
        raise ArtifactLedgerError("artifact work-unit ledger is malformed")
    key_prefix = initial_key.rsplit("/", 1)[0]
    models: dict[int, Mapping[str, Any]] = {}
    for key, unit in work_units.items():
        relative = _report_body_history_relative(
            key, key_prefix=key_prefix, shard=shard,
        )
        if relative is None:
            continue
        parsed = parse_report_body_attempt_work_unit(relative)
        if parsed is None:
            raise ArtifactLedgerError(
                "report-body attempt history has a malformed identity"
            )
        role, row_shard, ordinal = parsed
        if role != "model" or row_shard != shard:
            continue
        if ordinal in models:
            raise ArtifactLedgerError(
                "report-body MODEL attempt identity is duplicated"
            )
        if not _unit_is_exact(unit, key=key, run_id=run_id, role="model"):
            raise ArtifactLedgerError(
                f"report-body MODEL attempt {ordinal} receipt differs"
            )
        state = (
            unit.get("semantic_status"), unit.get("execution_state"),
        )
        artifacts = unit.get("artifacts")
        admitted = bool(
            state == ("INPUTS_BOUND", "INPUTS_BOUND_PREEXECUTION")
            and artifacts == {}
        )
        committed = bool(
            state == ("ACTIVE", "OUTPUT_COMMITTED")
            and isinstance(artifacts, Mapping)
            and f"scratchpad:{shard}.md" in artifacts
        )
        if not (admitted or committed):
            raise ArtifactLedgerError(
                f"report-body MODEL attempt {ordinal} is not current/admitted"
            )
        models[ordinal] = unit

    if not models:
        return 1
    highest = max(models)
    if set(models) != set(range(1, highest + 1)):
        raise ArtifactLedgerError(
            "report-body MODEL attempt history is not contiguous"
        )
    return highest


def require_report_body_attempt_authority(
    scratchpad: Path,
    *,
    contract: PhaseIOContract,
    launch: LaunchSpec,
    run_id: str,
) -> ReportBodyAttemptAuthority:
    """Require same-attempt resume or the exact next report-body generation.

    This is ordinal authority only.  It does not claim that another MODEL
    launch is needed and does not replace normal PhaseIO predecessor, input,
    execution, output-commit, or retained-preimage validation.
    """

    if type(run_id) is not str or not run_id:
        raise ArtifactLedgerError("report-body attempt run_id is invalid")
    if contract.phase != "report_body" or contract.model_invoked is not True:
        raise ArtifactLedgerError("report-body attempt contract is not MODEL")
    if launch.work_unit_key != contract.key:
        raise ArtifactLedgerError("report-body attempt contract/launch differs")
    parsed = parse_report_body_attempt_work_unit(contract.work_unit_id)
    if parsed is None or parsed[0] != "model":
        raise ArtifactLedgerError("report-body MODEL attempt identity is invalid")
    _role, shard, requested = parsed
    expected_output = f"scratchpad:{shard}.md"
    if tuple(spec.identity for spec in contract.outputs) != (expected_output,):
        raise ArtifactLedgerError("report-body MODEL output denominator differs")

    ledger = read_artifact_ledger(Path(scratchpad))
    work_units = ledger.get("work_units")
    if not isinstance(work_units, Mapping):
        raise ArtifactLedgerError("artifact work-unit ledger is malformed")
    key_prefix = contract.key.rsplit("/", 1)[0]
    models: dict[int, tuple[str, Mapping[str, Any]]] = {}
    projections: dict[int, tuple[str, Mapping[str, Any]]] = {}
    for key, unit in work_units.items():
        relative = _report_body_history_relative(
            key, key_prefix=key_prefix, shard=shard,
        )
        if relative is None:
            continue
        parsed_row = parse_report_body_attempt_work_unit(relative)
        if parsed_row is None:
            raise ArtifactLedgerError("report-body attempt history has a malformed identity")
        if parsed_row[1] != shard:
            continue
        role, _row_shard, ordinal = parsed_row
        if not _unit_is_exact(
            unit, key=key, run_id=run_id, role=role,
        ):
            raise ArtifactLedgerError(
                f"report-body {role} attempt {ordinal} receipt differs"
            )
        rows = models if role == "model" else projections
        if ordinal in rows:
            raise ArtifactLedgerError("report-body attempt identity is duplicated")
        rows[ordinal] = (key, unit)

    for ordinal, (_key, unit) in models.items():
        expected_contract = resolve_phase_io_contract(
            pipeline=contract.pipeline,
            mode=contract.mode,
            ecosystem=contract.ecosystem,
            backend=contract.backend,
            phase="report_body",
            work_unit_id=report_body_attempt_work_unit_id(
                "model", shard, ordinal,
            ),
            exact_inputs=tuple(
                identity.removeprefix("scratchpad:")
                for identity in contract.immutable_inputs
            ),
            exact_outputs=(f"{shard}.md",),
        )
        expected_launch = replace(
            launch, work_unit_key=expected_contract.key,
        )
        if (
            unit.get("contract_digest") != expected_contract.digest
            or unit.get("contract_manifest") != expected_contract.to_dict()
            or unit.get("launch_digest") != expected_launch.digest
            or unit.get("launch_manifest") != expected_launch.to_dict()
        ):
            raise ArtifactLedgerError(
                f"report-body MODEL attempt {ordinal} authority differs"
            )

    if models:
        highest = max(models)
        if set(models) != set(range(1, highest + 1)):
            raise ArtifactLedgerError("report-body MODEL attempt history is not contiguous")
        if not set(projections).issubset(models):
            raise ArtifactLedgerError("report-body projection has no same-attempt MODEL")
        if requested not in {highest, highest + 1}:
            raise ArtifactLedgerError(
                "report-body attempt must resume the current generation or "
                "be its exact successor"
            )
        resume = requested == highest
    else:
        if projections or requested != 1:
            raise ArtifactLedgerError(
                "report-body history is absent; only attempt 1 may start"
            )
        highest = 0
        resume = False

    predecessor = ""
    predecessor_execution_digest = ""
    if resume:
        current = models[highest][1]
        if highest in projections:
            raise ArtifactLedgerError(
                "report-body projection is already armed for this MODEL attempt"
            )
        if not (
            current.get("semantic_status") == "INPUTS_BOUND"
            and current.get("execution_state") == "INPUTS_BOUND_PREEXECUTION"
            and current.get("artifacts") == {}
        ):
            raise ArtifactLedgerError(
                "report-body MODEL attempt is already committed; resume its successor"
            )
    if not resume and highest:
        prior_key, prior_model_unit = models[highest]
        prior_committed = bool(
            prior_model_unit.get("semantic_status") == "ACTIVE"
            and prior_model_unit.get("execution_state") == "OUTPUT_COMMITTED"
            and isinstance(prior_model_unit.get("artifacts"), Mapping)
        )
        prior_uncommitted = bool(
            prior_model_unit.get("semantic_status") == "INPUTS_BOUND"
            and prior_model_unit.get("execution_state")
            == "INPUTS_BOUND_PREEXECUTION"
            and prior_model_unit.get("artifacts") == {}
        )
        if not (prior_committed or prior_uncommitted):
            raise ArtifactLedgerError(
                "report-body prior MODEL generation is not resumable"
            )
        if highest in projections:
            projection_key, projection_unit = projections[highest]
            if not (
                prior_committed
                and projection_unit.get("semantic_status") == "ACTIVE"
                and projection_unit.get("execution_state") == "OUTPUT_COMMITTED"
            ):
                raise ArtifactLedgerError(
                    "report-body prior projection is not a completed predecessor"
                )
            predecessor = projection_key
        else:
            predecessor = prior_key
        if prior_committed:
            prior_id = report_body_attempt_work_unit_id("model", shard, highest)
            prior_contract = resolve_phase_io_contract(
                pipeline=contract.pipeline,
                mode=contract.mode,
                ecosystem=contract.ecosystem,
                backend=contract.backend,
                phase="report_body",
                work_unit_id=prior_id,
                exact_inputs=tuple(
                    identity.removeprefix("scratchpad:")
                    for identity in contract.immutable_inputs
                ),
                exact_outputs=(f"{shard}.md",),
            )
            prior_launch = replace(launch, work_unit_key=prior_contract.key)
            retained = read_report_model_preimages(
                Path(scratchpad), contract=prior_contract,
                launch=prior_launch, run_id=run_id,
            )
            predecessor_execution_digest = retained.execution_authority_digest
    return ReportBodyAttemptAuthority(
        shard=shard,
        ordinal=requested,
        model_work_unit_id=contract.work_unit_id,
        projection_work_unit_id=report_body_attempt_work_unit_id(
            "evidence_projection", shard, requested,
        ),
        predecessor_owner_key=predecessor,
        predecessor_model_execution_authority_digest=(
            predecessor_execution_digest
        ),
        resume_existing=resume,
    )


__all__ = [
    "ReportBodyAttemptAuthority",
    "report_body_shard_for_phase",
    "resolve_report_body_model_attempt_ordinal",
    "require_report_body_attempt_authority",
]
