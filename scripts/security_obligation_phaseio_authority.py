"""Registered PhaseIO authority for checkpoint-independent P1-C context.

This adapter does not create semantic authority.  It binds the six-field
security-obligation run context to one exact registered contract/launch/run,
and replays the committed source or lifecycle producer before returning it.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
from typing import Any, Mapping, Sequence

from artifact_ledger import (
    ArtifactLedgerError,
    read_artifact_ledger,
    record_work_unit_artifacts,
    record_work_unit_inputs,
    recover_uncommitted_driver_input_denominator,
    replace_uncommitted_driver_input_denominator,
    validate_work_unit_artifacts,
    validate_work_unit_inputs,
)
from phase_io_contracts import LaunchSpec, PhaseIOContract, resolve_phase_io_contract
import security_obligation_authority as source_authority
import security_obligation_lifecycle as lifecycle


PHASEIO_CONTEXT_SCHEMA = "plamen.security-obligation-phaseio-context.v1"
_HEX64 = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
_EXTENSION_FIELDS = frozenset({
    "schema_version",
    "run_context",
    "work_unit_key",
    "contract_digest",
    "launch_digest",
    "run_id",
    "authority_sha256",
})
_SOURCE_OUTPUTS = (
    source_authority.FEATURE_FACT_FILE,
    source_authority.AUTHORITY_FILE,
    source_authority.PROJECTION_FILE,
)


def _digest(value: Mapping[str, Any]) -> str:
    raw = json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _dimension(config: Mapping[str, Any], key: str, default: str) -> str:
    aliases = {"ecosystem": "language", "backend": "cli_backend"}
    return str(
        config.get(key) or config.get(aliases.get(key, key)) or default
    ).strip().lower()


def build_run_context_from_config(
    config: Mapping[str, Any], *, run_id: str
) -> dict[str, str]:
    """Build context only from the caller's already-admitted run/snapshot."""

    if not isinstance(config, Mapping):
        raise ValueError("security-obligation config must be a mapping")
    selected_run = str(run_id or "").strip()
    configured_run = str(config.get("_run_id") or selected_run).strip()
    if not selected_run or configured_run != selected_run:
        raise ValueError("security-obligation config run differs from caller run")
    snapshot = config.get("_audit_snapshot") or config.get("audit_snapshot")
    if not isinstance(snapshot, Mapping):
        raise ValueError("security-obligation audit snapshot is absent")
    components = snapshot.get("components")
    source_scope = (
        components.get("source_scope")
        if isinstance(components, Mapping)
        else None
    )
    if not isinstance(source_scope, Mapping):
        raise ValueError("security-obligation source-scope snapshot is absent")
    return source_authority.build_security_obligation_run_context_authority(
        run_id=selected_run,
        source_snapshot_digest=str(snapshot.get("snapshot_digest") or ""),
        source_scope_digest=str(source_scope.get("digest") or ""),
        ecosystem=_dimension(config, "ecosystem", "unknown"),
        mode=_dimension(config, "mode", "core"),
        pipeline=_dimension(config, "pipeline", "sc"),
    )


def build_phaseio_context_extension(
    run_context: Mapping[str, Any],
    contract: PhaseIOContract,
    launch: LaunchSpec,
    *,
    run_id: str,
) -> dict[str, Any]:
    """Bind one validated semantic context to an exact PhaseIO authority pair."""

    context = source_authority.validate_security_obligation_run_context_authority(
        run_context
    )
    run = str(run_id or "").strip()
    if (
        context["run_id"] != run
        or contract.key != launch.work_unit_key
        or contract.pipeline != context["pipeline"]
        or contract.mode != context["mode"]
        or contract.ecosystem != context["ecosystem"]
        or launch.pipeline != contract.pipeline
        or launch.mode != contract.mode
        or launch.ecosystem != contract.ecosystem
        or launch.backend != contract.backend
    ):
        raise ValueError("security-obligation PhaseIO context dimensions differ")
    unsigned: dict[str, Any] = {
        "schema_version": PHASEIO_CONTEXT_SCHEMA,
        "run_context": context,
        "work_unit_key": contract.key,
        "contract_digest": contract.digest,
        "launch_digest": launch.digest,
        "run_id": run,
    }
    return {**unsigned, "authority_sha256": _digest(unsigned)}


def validate_phaseio_context_extension(
    value: Mapping[str, Any],
    contract: PhaseIOContract,
    launch: LaunchSpec,
    *,
    run_id: str,
) -> tuple[dict[str, Any], dict[str, str]]:
    if not isinstance(value, Mapping) or set(value) != _EXTENSION_FIELDS:
        raise ValueError("security-obligation PhaseIO context fields are not exact")
    replayed = build_phaseio_context_extension(
        value.get("run_context") if isinstance(value, Mapping) else {},
        contract,
        launch,
        run_id=run_id,
    )
    if dict(value) != replayed:
        raise ValueError("security-obligation PhaseIO context is invalid")
    return replayed, dict(replayed["run_context"])


def security_obligation_contract_and_launch(
    scratchpad: Path,
    config: Mapping[str, Any],
    *,
    stage: str,
    run_context: Mapping[str, Any] | None = None,
    exact_inputs: Sequence[str] | None = None,
) -> tuple[PhaseIOContract, LaunchSpec]:
    stage_n = str(stage or "").strip().lower()
    if stage_n not in {
        source_authority.PRE_DEPTH_STAGE,
        source_authority.POST_DEPTH_STAGE,
    }:
        raise ValueError(f"unsupported security-obligation stage: {stage!r}")
    context = (
        source_authority.validate_security_obligation_run_context_authority(
            run_context
        )
        if run_context is not None
        else None
    )
    inputs = tuple(
        exact_inputs
        if exact_inputs is not None
        else source_authority.security_obligation_input_artifacts(
            Path(scratchpad),
            stage=stage_n,
            run_context_authority=context,
        )
    )
    contract = resolve_phase_io_contract(
        pipeline=(
            context["pipeline"]
            if context
            else _dimension(config, "pipeline", "sc")
        ),
        mode=(
            context["mode"]
            if context
            else _dimension(config, "mode", "core")
        ),
        ecosystem=(
            context["ecosystem"]
            if context
            else _dimension(config, "ecosystem", "unknown")
        ),
        backend=_dimension(config, "backend", "claude"),
        phase="depth",
        work_unit_id=f"security_obligations.{stage_n}",
        exact_inputs=inputs,
    )
    launch = LaunchSpec(
        work_unit_key=contract.key,
        pipeline=contract.pipeline,
        mode=contract.mode,
        ecosystem=contract.ecosystem,
        backend=contract.backend,
        model="driver",
        timeout_s=120,
        exec_mode="python",
        tool_policy=("filesystem",),
    )
    return contract, launch


def lifecycle_contract_and_launch(
    scratchpad: Path,
    config: Mapping[str, Any],
    *,
    run_context: Mapping[str, Any] | None = None,
    exact_inputs: Sequence[str] | None = None,
) -> tuple[PhaseIOContract, LaunchSpec]:
    context = (
        source_authority.validate_security_obligation_run_context_authority(
            run_context
        )
        if run_context is not None
        else None
    )
    inputs = tuple(
        exact_inputs
        if exact_inputs is not None
        else lifecycle.security_obligation_lifecycle_input_artifacts(
            Path(scratchpad), run_context_authority=context
        )
    )
    outputs = (
        lifecycle.AUTHORITY_FILE,
        lifecycle.PROJECTION_FILE,
        lifecycle.REPORT_RETENTION_FILE,
    )
    contract = resolve_phase_io_contract(
        pipeline=(
            context["pipeline"]
            if context
            else _dimension(config, "pipeline", "sc")
        ),
        mode=(
            context["mode"]
            if context
            else _dimension(config, "mode", "core")
        ),
        ecosystem=(
            context["ecosystem"]
            if context
            else _dimension(config, "ecosystem", "unknown")
        ),
        backend=_dimension(config, "backend", "claude"),
        phase="report_index",
        work_unit_id="security_obligation_lifecycle.final",
        exact_inputs=inputs,
        exact_outputs=outputs,
    )
    launch = LaunchSpec(
        work_unit_key=contract.key,
        pipeline=contract.pipeline,
        mode=contract.mode,
        ecosystem=contract.ecosystem,
        backend=contract.backend,
        model="driver",
        timeout_s=120,
        exec_mode="python",
        tool_policy=("filesystem",),
    )
    return contract, launch


def source_outputs_present(scratchpad: Path) -> bool:
    root = Path(scratchpad)
    return any(os.path.lexists(root / name) for name in _SOURCE_OUTPUTS)


def require_committed_source_context(
    scratchpad: Path,
    project_root: Path,
    config: Mapping[str, Any],
    *,
    stage: str,
    run_context: Mapping[str, Any],
) -> dict[str, str]:
    """Return context only after exact current source semantics and receipt."""

    root = Path(scratchpad)
    context = source_authority.validate_security_obligation_run_context_authority(
        run_context
    )
    contract, launch = security_obligation_contract_and_launch(
        root, config, stage=stage, run_context=context
    )
    unit = (read_artifact_ledger(root).get("work_units") or {}).get(
        contract.key
    )
    if (
        isinstance(unit, Mapping)
        and str(unit.get("run_id") or "") != context["run_id"]
    ):
        raise ValueError(
            "registered security-obligation source run_id differs from "
            "expected driver run"
        )
    extension = build_phaseio_context_extension(
        context, contract, launch, run_id=context["run_id"]
    )
    issues = source_authority.validate_security_obligation_authority(
        root,
        mode=context["mode"],
        ecosystem=context["ecosystem"],
        run_id=context["run_id"],
        source_snapshot_digest=context["source_snapshot_digest"],
        stage=stage,
        run_context_authority=context,
    )
    issues.extend(validate_work_unit_inputs(
        root,
        Path(project_root),
        contract,
        launch,
        run_id=context["run_id"],
        preexecution_authority=extension,
    ))
    issues.extend(validate_work_unit_artifacts(
        root,
        Path(project_root),
        contract,
        launch,
        run_id=context["run_id"],
        actor="DRIVER",
        preexecution_authority=extension,
    ))
    if issues:
        raise ValueError(
            "registered security-obligation source is invalid: "
            + "; ".join(dict.fromkeys(str(issue) for issue in issues))
        )
    return context


def lifecycle_run_context_for_driver(
    scratchpad: Path,
    project_root: Path,
    config: Mapping[str, Any],
    *,
    run_id: str,
) -> dict[str, str]:
    """Build expected context and require a producer for any source outputs."""

    context = build_run_context_from_config(config, run_id=run_id)
    if source_outputs_present(Path(scratchpad)):
        require_committed_source_context(
            Path(scratchpad),
            Path(project_root),
            config,
            stage=source_authority.POST_DEPTH_STAGE,
            run_context=context,
        )
    return context


def _scratchpad_input_digests(unit: Mapping[str, Any]) -> dict[str, str]:
    return {
        str(identity).split(":", 1)[1]: str(binding.get("sha256") or "")
        for identity, binding in (unit.get("input_bindings") or {}).items()
        if str(identity).startswith("scratchpad:")
        and isinstance(binding, Mapping)
        and _HEX64.fullmatch(str(binding.get("sha256") or "")) is not None
    }


def _normalized_issues(issues: Sequence[Any]) -> list[str]:
    return list(dict.fromkeys(str(issue) for issue in issues if str(issue)))


def record_security_obligation_source_transaction(
    scratchpad: Path,
    project_root: Path,
    config: Mapping[str, Any],
    *,
    run_id: str,
    stage: str,
) -> list[str]:
    """Derive and commit one exact PRE/POST source with stable context."""

    root = Path(scratchpad)
    project = Path(project_root)
    run = str(run_id or "").strip()
    if not run:
        return ["security-obligation PhaseIO cannot bind without a run_id"]
    stage_n = str(stage or "").strip().lower()
    if all((root / name).is_file() for name in _SOURCE_OUTPUTS):
        resume_issues = validate_security_obligation_source_transaction(
            root, project, config, run_id=run, stage=stage_n
        )
        if not resume_issues:
            return []
    prior_contract: PhaseIOContract | None = None
    prior_unit: Mapping[str, Any] | None = None
    prior_extension: Mapping[str, Any] | None = None
    contract: PhaseIOContract | None = None
    launch: LaunchSpec | None = None
    extension: Mapping[str, Any] | None = None
    authority_payload: Mapping[str, Any] | None = None
    stabilized = False
    issues: list[str] = []
    try:
        context = build_run_context_from_config(config, run_id=run)
        for _attempt in range(3):
            before = source_authority.security_obligation_input_artifacts(
                root,
                stage=stage_n,
                run_context_authority=context,
            )
            contract, launch = security_obligation_contract_and_launch(
                root,
                config,
                stage=stage_n,
                run_context=context,
                exact_inputs=before,
            )
            extension = build_phaseio_context_extension(
                context, contract, launch, run_id=run
            )
            if prior_contract is not None and prior_unit is not None:
                bound_unit = replace_uncommitted_driver_input_denominator(
                    root,
                    project,
                    prior_contract,
                    contract,
                    launch,
                    run_id=run,
                    expected_prior_input_set_digest=str(
                        prior_unit.get("input_set_digest") or ""
                    ),
                    reason_code=(
                        "DYNAMIC_INPUT_DENOMINATOR_DRIFT_BEFORE_OUTPUT_COMMIT"
                    ),
                    expected_prior_preexecution_authority=prior_extension,
                    replacement_preexecution_authority=extension,
                )
            else:
                existing = (read_artifact_ledger(root).get("work_units") or {}).get(
                    contract.key
                )
                if (
                    isinstance(existing, Mapping)
                    and existing.get("semantic_status") == "INPUTS_BOUND"
                    and existing.get("execution_state")
                    == "INPUTS_BOUND_PREEXECUTION"
                    and existing.get("artifacts") == {}
                    and existing.get("contract_digest") == contract.digest
                    and existing.get("contract_manifest") == contract.to_dict()
                    and existing.get("launch_digest") == launch.digest
                    and existing.get("launch_manifest") == launch.to_dict()
                ):
                    armed_issues = validate_work_unit_inputs(
                        root,
                        project,
                        contract,
                        launch,
                        run_id=run,
                        preexecution_authority=extension,
                    )
                    if armed_issues:
                        raise ArtifactLedgerError("; ".join(armed_issues))
                    bound_unit = dict(existing)
                elif (
                    isinstance(existing, Mapping)
                    and existing.get("semantic_status") == "INPUTS_BOUND"
                    and existing.get("artifacts") == {}
                    and existing.get("contract_digest") != contract.digest
                ):
                    bound_unit = recover_uncommitted_driver_input_denominator(
                        root,
                        project,
                        contract,
                        launch,
                        run_id=run,
                        reason_code=(
                            "DYNAMIC_INPUT_DENOMINATOR_DRIFT_BEFORE_OUTPUT_COMMIT"
                        ),
                        replacement_preexecution_authority=extension,
                    )
                else:
                    bound_unit = record_work_unit_inputs(
                        root,
                        project,
                        contract,
                        launch,
                        run_id=run,
                        preexecution_authority=extension,
                    )
            authority_payload = source_authority.write_security_obligation_authority(
                root,
                mode=context["mode"],
                ecosystem=context["ecosystem"],
                run_id=run,
                source_snapshot_digest=context["source_snapshot_digest"],
                stage=stage_n,
                run_context_authority=context,
            )
            after = source_authority.security_obligation_input_artifacts(
                root,
                stage=stage_n,
                run_context_authority=context,
            )
            if after == before:
                stabilized = True
                break
            prior_contract = contract
            prior_unit = bound_unit
            prior_extension = extension
        if (
            not stabilized
            or contract is None
            or launch is None
            or extension is None
        ):
            return [
                "security-obligation inputs did not stabilize before output commit"
            ]
        issues.extend(validate_work_unit_inputs(
            root,
            project,
            contract,
            launch,
            run_id=run,
            preexecution_authority=extension,
        ))
        issues.extend(source_authority.validate_security_obligation_authority(
            root,
            mode=context["mode"],
            ecosystem=context["ecosystem"],
            run_id=run,
            source_snapshot_digest=context["source_snapshot_digest"],
            stage=stage_n,
            run_context_authority=context,
        ))
        if isinstance(authority_payload, Mapping):
            issues.extend(
                "security-obligation authority debt: " + str(issue).strip()
                for issue in authority_payload.get("issues") or []
                if str(issue).strip()
            )
        if build_run_context_from_config(config, run_id=run) != context:
            raise ValueError(
                "security-obligation context changed before output commit"
            )
        record_work_unit_artifacts(
            root, project, contract, launch, run_id=run, actor="DRIVER"
        )
        issues.extend(validate_work_unit_artifacts(
            root,
            project,
            contract,
            launch,
            run_id=run,
            actor="DRIVER",
            preexecution_authority=extension,
        ))
    except (ArtifactLedgerError, OSError, TypeError, ValueError) as exc:
        issues.append(
            "security-obligation PhaseIO transaction failed: "
            f"{type(exc).__name__}: {exc}"
        )
    return _normalized_issues(issues)


def validate_security_obligation_source_transaction(
    scratchpad: Path,
    project_root: Path,
    config: Mapping[str, Any],
    *,
    run_id: str,
    stage: str,
) -> list[str]:
    """Side-effect-free current source semantic and PhaseIO replay."""

    root = Path(scratchpad)
    project = Path(project_root)
    run = str(run_id or "").strip()
    if not run:
        return ["security-obligation PhaseIO cannot validate without a run_id"]
    issues: list[str] = []
    try:
        context = build_run_context_from_config(config, run_id=run)
        contract, launch = security_obligation_contract_and_launch(
            root,
            config,
            stage=stage,
            run_context=context,
        )
        extension = build_phaseio_context_extension(
            context, contract, launch, run_id=run
        )
        issues.extend(source_authority.validate_security_obligation_authority(
            root,
            mode=context["mode"],
            ecosystem=context["ecosystem"],
            run_id=run,
            source_snapshot_digest=context["source_snapshot_digest"],
            stage=stage,
            run_context_authority=context,
        ))
        issues.extend(validate_work_unit_inputs(
            root,
            project,
            contract,
            launch,
            run_id=run,
            preexecution_authority=extension,
        ))
        issues.extend(validate_work_unit_artifacts(
            root,
            project,
            contract,
            launch,
            run_id=run,
            actor="DRIVER",
            preexecution_authority=extension,
        ))
    except (ArtifactLedgerError, OSError, TypeError, ValueError) as exc:
        issues.append(
            "security-obligation PhaseIO validation failed: "
            f"{type(exc).__name__}: {exc}"
        )
    return _normalized_issues(issues)


def record_security_obligation_lifecycle_transaction(
    scratchpad: Path,
    project_root: Path,
    config: Mapping[str, Any],
    *,
    run_id: str,
) -> list[str]:
    """Publish exact lifecycle authority or explicit missing-source debt."""

    root = Path(scratchpad)
    project = Path(project_root)
    run = str(run_id or "").strip()
    if not run:
        return ["security-obligation lifecycle cannot bind without a run_id"]
    if all(
        (root / name).is_file()
        for name in (
            lifecycle.AUTHORITY_FILE,
            lifecycle.PROJECTION_FILE,
            lifecycle.REPORT_RETENTION_FILE,
        )
    ):
        resume_issues = validate_security_obligation_lifecycle_transaction(
            root, project, config, run_id=run
        )
        if not resume_issues:
            return []
    prior_contract: PhaseIOContract | None = None
    prior_unit: Mapping[str, Any] | None = None
    prior_extension: Mapping[str, Any] | None = None
    contract: PhaseIOContract | None = None
    launch: LaunchSpec | None = None
    extension: Mapping[str, Any] | None = None
    authority: Mapping[str, Any] | None = None
    stabilized = False
    issues: list[str] = []
    context: Mapping[str, Any] | None = None
    try:
        context = lifecycle_run_context_for_driver(
            root, project, config, run_id=run
        )
        for _attempt in range(3):
            if lifecycle_run_context_for_driver(
                root, project, config, run_id=run
            ) != context:
                raise ValueError(
                    "security-obligation source context changed before "
                    "lifecycle arm"
                )
            before = lifecycle.security_obligation_lifecycle_input_artifacts(
                root, run_context_authority=context
            )
            contract, launch = lifecycle_contract_and_launch(
                root,
                config,
                run_context=context,
                exact_inputs=before,
            )
            extension = build_phaseio_context_extension(
                context, contract, launch, run_id=run
            )
            if prior_contract is not None and prior_unit is not None:
                bound_unit = replace_uncommitted_driver_input_denominator(
                    root,
                    project,
                    prior_contract,
                    contract,
                    launch,
                    run_id=run,
                    expected_prior_input_set_digest=str(
                        prior_unit.get("input_set_digest") or ""
                    ),
                    reason_code=(
                        "DYNAMIC_INPUT_DENOMINATOR_DRIFT_BEFORE_OUTPUT_COMMIT"
                    ),
                    expected_prior_preexecution_authority=prior_extension,
                    replacement_preexecution_authority=extension,
                )
            else:
                existing = (read_artifact_ledger(root).get("work_units") or {}).get(
                    contract.key
                )
                if (
                    isinstance(existing, Mapping)
                    and existing.get("semantic_status") == "INPUTS_BOUND"
                    and existing.get("execution_state")
                    == "INPUTS_BOUND_PREEXECUTION"
                    and existing.get("artifacts") == {}
                    and existing.get("contract_digest") == contract.digest
                    and existing.get("contract_manifest") == contract.to_dict()
                    and existing.get("launch_digest") == launch.digest
                    and existing.get("launch_manifest") == launch.to_dict()
                ):
                    armed_issues = validate_work_unit_inputs(
                        root,
                        project,
                        contract,
                        launch,
                        run_id=run,
                        preexecution_authority=extension,
                    )
                    if armed_issues:
                        raise ArtifactLedgerError("; ".join(armed_issues))
                    bound_unit = dict(existing)
                elif (
                    isinstance(existing, Mapping)
                    and existing.get("semantic_status") == "INPUTS_BOUND"
                    and existing.get("artifacts") == {}
                    and existing.get("contract_digest") != contract.digest
                ):
                    bound_unit = recover_uncommitted_driver_input_denominator(
                        root,
                        project,
                        contract,
                        launch,
                        run_id=run,
                        reason_code=(
                            "DYNAMIC_INPUT_DENOMINATOR_DRIFT_BEFORE_OUTPUT_COMMIT"
                        ),
                        replacement_preexecution_authority=extension,
                    )
                else:
                    bound_unit = record_work_unit_inputs(
                        root,
                        project,
                        contract,
                        launch,
                        run_id=run,
                        preexecution_authority=extension,
                    )
            expected_inputs = _scratchpad_input_digests(bound_unit)
            authority = lifecycle.write_security_obligation_lifecycle(
                root,
                expected_input_sha256=expected_inputs,
                expected_run_id=run,
                run_context_authority=context,
            )
            after = lifecycle.security_obligation_lifecycle_input_artifacts(
                root, run_context_authority=context
            )
            live_input_issues = validate_work_unit_inputs(
                root,
                project,
                contract,
                launch,
                run_id=run,
                preexecution_authority=extension,
            )
            binding_drift = any(
                isinstance(binding, Mapping)
                and binding.get("expected_sha256") is not None
                and binding.get("binding_state") != "CURRENT"
                for binding in authority.get("input_bindings") or []
            )
            if after == before and not live_input_issues and not binding_drift:
                stabilized = True
                break
            prior_contract = contract
            prior_unit = bound_unit
            prior_extension = extension
        if (
            not stabilized
            or contract is None
            or launch is None
            or extension is None
        ):
            return [
                "security-obligation lifecycle inputs did not stabilize "
                "before output commit"
            ]
        if not isinstance(authority, Mapping) or authority.get("run_id") != run:
            raise ValueError(
                "security-obligation lifecycle run_id differs from driver run_id"
            )
        final_input_issues = validate_work_unit_inputs(
            root,
            project,
            contract,
            launch,
            run_id=run,
            preexecution_authority=extension,
        )
        if final_input_issues:
            return [
                "security-obligation lifecycle inputs changed before output "
                "commit: " + "; ".join(final_input_issues)
            ]
        issues.extend(lifecycle.validate_security_obligation_lifecycle(
            root,
            expected_input_sha256=expected_inputs,
            expected_run_id=run,
            run_context_authority=context,
        ))
        if authority.get("status") == "DEGRADED_HUMAN_REVIEW":
            issues.append(
                "security-obligation lifecycle retained unresolved/debt aliases "
                "for human review"
            )
        if lifecycle_run_context_for_driver(
            root, project, config, run_id=run
        ) != context:
            raise ValueError(
                "security-obligation source context changed before lifecycle commit"
            )
        record_work_unit_artifacts(
            root, project, contract, launch, run_id=run, actor="DRIVER"
        )
        issues.extend(validate_work_unit_artifacts(
            root,
            project,
            contract,
            launch,
            run_id=run,
            actor="DRIVER",
            preexecution_authority=extension,
        ))
    except (ArtifactLedgerError, OSError, TypeError, ValueError) as exc:
        issues.append(
            "security-obligation lifecycle PhaseIO transaction failed "
            f"haltlessly: {type(exc).__name__}: {exc}"
        )
        if source_outputs_present(root):
            return _normalized_issues(issues)
        try:
            if context is None:
                context = build_run_context_from_config(config, run_id=run)
            lifecycle.write_security_obligation_lifecycle(
                root,
                expected_run_id=run,
                run_context_authority=context,
            )
        except Exception as fallback_exc:
            issues.append(
                "security-obligation lifecycle fallback publication failed: "
                f"{type(fallback_exc).__name__}: {fallback_exc}"
            )
    return _normalized_issues(issues)


def validate_security_obligation_lifecycle_transaction(
    scratchpad: Path,
    project_root: Path,
    config: Mapping[str, Any],
    *,
    run_id: str,
) -> list[str]:
    """Side-effect-free lifecycle semantic and PhaseIO replay."""

    root = Path(scratchpad)
    project = Path(project_root)
    run = str(run_id or "").strip()
    if not run:
        return ["security-obligation lifecycle cannot validate without a run_id"]
    issues: list[str] = []
    try:
        context = lifecycle_run_context_for_driver(
            root, project, config, run_id=run
        )
        contract, launch = lifecycle_contract_and_launch(
            root, config, run_context=context
        )
        extension = build_phaseio_context_extension(
            context, contract, launch, run_id=run
        )
        unit = (read_artifact_ledger(root).get("work_units") or {}).get(
            contract.key
        )
        expected_inputs = (
            _scratchpad_input_digests(unit)
            if isinstance(unit, Mapping)
            else {}
        )
        issues.extend(lifecycle.validate_security_obligation_lifecycle(
            root,
            expected_input_sha256=expected_inputs,
            expected_run_id=run,
            run_context_authority=context,
        ))
        try:
            recorded = json.loads(
                (root / lifecycle.AUTHORITY_FILE).read_text(
                    encoding="utf-8", errors="strict"
                )
            )
        except (OSError, TypeError, ValueError, UnicodeError):
            recorded = {}
        if recorded.get("run_id") != run:
            issues.append(
                "security-obligation lifecycle run_id differs from driver run_id"
            )
        issues.extend(validate_work_unit_inputs(
            root,
            project,
            contract,
            launch,
            run_id=run,
            preexecution_authority=extension,
        ))
        issues.extend(validate_work_unit_artifacts(
            root,
            project,
            contract,
            launch,
            run_id=run,
            actor="DRIVER",
            preexecution_authority=extension,
        ))
    except (ArtifactLedgerError, OSError, TypeError, ValueError) as exc:
        issues.append(
            "security-obligation lifecycle PhaseIO validation failed: "
            f"{type(exc).__name__}: {exc}"
        )
    return _normalized_issues(issues)


def load_committed_lifecycle_run_context(
    scratchpad: Path, *, project_root: Path | None = None
) -> dict[str, str]:
    """Recover context through one exact committed lifecycle transaction."""

    root = Path(scratchpad)
    project = Path(project_root) if project_root is not None else root.parent
    ledger = read_artifact_ledger(root)
    suffix = "/report_index/security_obligation_lifecycle.final"
    matches = [
        (key, row)
        for key, row in (ledger.get("work_units") or {}).items()
        if isinstance(key, str)
        and key.casefold().endswith(suffix.casefold())
        and isinstance(row, Mapping)
        and row.get("work_unit_key") == key
        and row.get("semantic_status") == "ACTIVE"
        and row.get("execution_state") == "OUTPUT_COMMITTED"
    ]
    if len(matches) != 1:
        raise ValueError("exact committed security-obligation lifecycle is absent")
    stored_key, unit = matches[0]
    key_parts = str(unit["work_unit_key"]).split("/")
    if len(key_parts) != 6:
        raise ValueError("security-obligation lifecycle work-unit key is malformed")
    stored = unit.get("preexecution_authority")
    if not isinstance(stored, Mapping):
        raise ValueError("security-obligation lifecycle context is absent")
    raw_context = stored.get("run_context")
    context = source_authority.validate_security_obligation_run_context_authority(
        raw_context if isinstance(raw_context, Mapping) else {}
    )
    config: dict[str, Any] = {
        "pipeline": key_parts[0],
        "mode": key_parts[1],
        "language": key_parts[2],
        "cli_backend": key_parts[3],
        "project_root": str(project),
        "scratchpad": str(root),
        "_run_id": str(unit.get("run_id") or ""),
        "_audit_snapshot": {
            "snapshot_digest": context["source_snapshot_digest"],
            "components": {
                "source_scope": {"digest": context["source_scope_digest"]}
            },
        },
    }
    contract, launch = lifecycle_contract_and_launch(
        root, config, run_context=context
    )
    if stored_key != contract.key:
        raise ValueError(
            "security-obligation lifecycle work-unit identity is noncanonical"
        )
    extension, _ = validate_phaseio_context_extension(
        stored, contract, launch, run_id=str(unit.get("run_id") or "")
    )
    expected_inputs = {
        str(identity).split(":", 1)[1]: str(binding.get("sha256") or "")
        for identity, binding in (unit.get("input_bindings") or {}).items()
        if str(identity).startswith("scratchpad:")
        and isinstance(binding, Mapping)
        and _HEX64.fullmatch(str(binding.get("sha256") or "")) is not None
    }
    if source_outputs_present(root):
        require_committed_source_context(
            root,
            project,
            config,
            stage=source_authority.POST_DEPTH_STAGE,
            run_context=context,
        )
    issues = lifecycle.validate_security_obligation_lifecycle(
        root,
        expected_input_sha256=expected_inputs,
        expected_run_id=context["run_id"],
        run_context_authority=context,
    )
    issues.extend(validate_work_unit_inputs(
        root,
        project,
        contract,
        launch,
        run_id=context["run_id"],
        preexecution_authority=extension,
    ))
    issues.extend(validate_work_unit_artifacts(
        root,
        project,
        contract,
        launch,
        run_id=context["run_id"],
        actor="DRIVER",
        preexecution_authority=extension,
    ))
    if issues:
        raise ValueError(
            "committed security-obligation lifecycle is invalid: "
            + "; ".join(dict.fromkeys(str(issue) for issue in issues))
        )
    return context


__all__ = [
    "PHASEIO_CONTEXT_SCHEMA",
    "build_phaseio_context_extension",
    "build_run_context_from_config",
    "lifecycle_contract_and_launch",
    "lifecycle_run_context_for_driver",
    "load_committed_lifecycle_run_context",
    "record_security_obligation_lifecycle_transaction",
    "record_security_obligation_source_transaction",
    "require_committed_source_context",
    "security_obligation_contract_and_launch",
    "source_outputs_present",
    "validate_phaseio_context_extension",
    "validate_security_obligation_lifecycle_transaction",
    "validate_security_obligation_source_transaction",
]
