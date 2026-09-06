"""PhaseIO authority for the live verify-queue T0--T9 transaction.

Status files are resumability projections, not consumption authority.  This
module deterministically reconstructs each child (and the zero-output parent)
as a :class:`PhaseIOContract`, binds its exact inputs before execution, records
its exact outputs after execution, and validates the resulting current-run
artifact-ledger authority.

The helpers deliberately accept resolved plan records rather than enumerating
the filesystem.  A caller may supply ``effective_inputs`` only for a
state-selected denominator already resolved by the transaction executor.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Mapping, Sequence

from artifact_ledger import (
    _ArtifactValidationContext,
    ArtifactLedgerError,
    read_artifact_ledger,
    record_work_unit_explicit_absence_bindings,
    record_work_unit_artifacts,
    record_work_unit_inputs,
    semantic_input_prebind_producer_authority_issues,
    validate_work_unit_artifacts,
    validate_work_unit_explicit_absence_bindings,
    validate_work_unit_inputs,
)
from phase_io_contracts import (
    ArtifactSpec,
    ConditionalOutputReceipt,
    LaunchSpec,
    PhaseIOContract,
    canonical_artifact_identity,
    canonical_work_unit_key,
)


_SCAFFOLD_CHILD_IDS = (
    "t0.input_authority",
    "t1.base_queue",
    "t2.policy_disposition",
    "t3.mandatory_reverification",
    "t4.composition_delivery",
    "t5.compound_projection",
    "t6.final_work_item_plan",
    "t7.context_and_shard_plan",
    "t8.transaction_validation",
    "t9.final_assembler",
)
_LIVE_CHILD_IDS = (
    "t0.live_upstream_authority",
    "t1.live_base_queue",
    "t2.live_policy_disposition",
    "t3.live_mandatory_delta",
    "t4.live_pipeline_composition_delta",
    "t5.live_generic_compound_delta",
    "t6.live_final_typed_merge",
    "t7.live_frozen_context_and_shard_plan",
    "t8.live_immutable_publication_bundle",
    "t9.live_receipt_last_cas",
)
_PARENT_BY_CHILD_ROSTER = {
    _SCAFFOLD_CHILD_IDS: "routing.parent_commit",
    _LIVE_CHILD_IDS: "routing.live_parent_commit",
}
_DRIVER_MODEL = "driver"
_DRIVER_TIMEOUT_S = 300
_DRIVER_EXEC_MODE = "python"
_DRIVER_TOOL_POLICY = ("filesystem",)
_STRICT_PRODUCER_BINDING_POLICY = {
    "owner": True,
    "writer": True,
    "run_id": True,
    "contract_digest": True,
    "launch_digest": True,
    "sha256": True,
    "size": True,
    "explicit_absence": True,
}


class VerifyQueuePhaseIOAuthorityError(ValueError):
    """A resolved transaction cannot be represented by exact PhaseIO."""


def _canonical_json_bytes(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")


def _stable_digest(value: Any) -> str:
    return hashlib.sha256(_canonical_json_bytes(value)).hexdigest()


def _identity(value: Any, *, default_root: str = "scratchpad") -> str:
    text = str(value or "").strip().replace("\\", "/")
    if text.startswith("project::"):
        return canonical_artifact_identity("project", text[len("project::"):])
    if text.startswith("scratchpad::"):
        return canonical_artifact_identity(
            "scratchpad", text[len("scratchpad::"):]
        )
    if text.startswith("project:") or text.startswith("scratchpad:"):
        root, relative = text.split(":", 1)
        return canonical_artifact_identity(root, relative)
    return canonical_artifact_identity(default_root, text)


def _plan_dimensions(plan: Mapping[str, Any]) -> tuple[str, str, str, str, str]:
    if not isinstance(plan, Mapping):
        raise VerifyQueuePhaseIOAuthorityError(
            "verify-queue transaction plan must be a mapping"
        )
    dimensions = (
        str(plan.get("pipeline") or "").strip().lower(),
        str(plan.get("mode") or "").strip().lower(),
        str(plan.get("ecosystem") or "").strip().lower(),
        str(plan.get("backend") or "").strip().lower(),
        str(plan.get("phase_name") or plan.get("phase") or "").strip().lower(),
    )
    if not all(dimensions):
        raise VerifyQueuePhaseIOAuthorityError(
            "verify-queue transaction identity is incomplete"
        )
    expected_phase = (
        "sc_verify_queue" if dimensions[0] == "sc" else "verify_queue"
    )
    if dimensions[0] not in {"sc", "l1"} or dimensions[4] != expected_phase:
        raise VerifyQueuePhaseIOAuthorityError(
            "verify-queue pipeline/phase identity is inconsistent"
        )
    if dimensions[3] not in {"claude", "codex"}:
        raise VerifyQueuePhaseIOAuthorityError(
            "verify-queue backend must be claude or codex"
        )
    return dimensions


def _validate_plan_digest(plan: Mapping[str, Any]) -> None:
    digest = str(plan.get("plan_digest") or "").strip().lower()
    if not digest:
        return
    unsigned = {key: value for key, value in plan.items() if key != "plan_digest"}
    if len(digest) != 64 or digest != _stable_digest(unsigned):
        raise VerifyQueuePhaseIOAuthorityError(
            "verify-queue transaction plan digest is malformed or stale"
        )


def _unit_work_id(unit: Mapping[str, Any]) -> str:
    if not isinstance(unit, Mapping):
        raise VerifyQueuePhaseIOAuthorityError(
            "verify-queue transaction unit must be a mapping"
        )
    value = str(unit.get("work_unit_id") or "").strip().lower()
    if not value:
        raise VerifyQueuePhaseIOAuthorityError(
            "verify-queue transaction work_unit_id is absent"
        )
    return value


def _output_specs(
    *,
    owner_key: str,
    unit: Mapping[str, Any],
) -> tuple[ArtifactSpec, ...]:
    raw_outputs = unit.get("outputs")
    if not isinstance(raw_outputs, Sequence) or isinstance(
        raw_outputs, (str, bytes)
    ):
        raise VerifyQueuePhaseIOAuthorityError(
            f"{_unit_work_id(unit)}: outputs must be an exact sequence"
        )
    specs: list[ArtifactSpec] = []
    seen: set[str] = set()
    for raw in raw_outputs:
        if not isinstance(raw, Mapping):
            raise VerifyQueuePhaseIOAuthorityError(
                f"{_unit_work_id(unit)}: output row is malformed"
            )
        root = str(raw.get("root") or "scratchpad").strip().lower()
        path_value = raw.get("path")
        if path_value is None and raw.get("identity") is not None:
            identity = _identity(raw["identity"])
            root, path_value = identity.split(":", 1)
        path = str(path_value or "").strip().replace("\\", "/")
        identity = canonical_artifact_identity(root, path)
        if identity in seen:
            raise VerifyQueuePhaseIOAuthorityError(
                f"{_unit_work_id(unit)}: duplicate output {identity}"
            )
        seen.add(identity)
        artifact_class = str(
            raw.get("artifact_class") or "DRIVER_GENERATED"
        ).strip().upper()
        writer = str(raw.get("writer") or "DRIVER").strip().upper()
        write_mode = str(raw.get("write_mode") or "CREATE").strip().upper()
        if writer != "DRIVER":
            raise VerifyQueuePhaseIOAuthorityError(
                f"{_unit_work_id(unit)}: live transaction output {identity} "
                "is not DRIVER-owned"
            )
        specs.append(ArtifactSpec(
            root=root,
            path=path,
            owner_key=owner_key,
            artifact_class=artifact_class,
            writer=writer,
            write_mode=write_mode,
            schema_version=str(
                raw.get("schema_version") or "unstructured.v1"
            ).strip(),
            minimum_gate=str(
                raw.get("minimum_gate") or "STRUCTURAL"
            ).strip(),
            consumers=tuple(str(value) for value in raw.get("consumers", ())),
            condition_id=str(raw.get("condition_id") or "").strip(),
            external_preimage_validator=str(
                raw.get("external_preimage_validator") or ""
            ).strip(),
        ))
    return tuple(specs)


def _conditional_selector_path(
    plan: Mapping[str, Any],
    unit: Mapping[str, Any],
) -> str:
    explicit = unit.get("delivery_state_status_path")
    if explicit:
        return str(explicit)
    children = plan.get("children")
    if isinstance(children, Sequence) and not isinstance(
        children, (str, bytes)
    ):
        for child in children:
            if not isinstance(child, Mapping):
                continue
            if not str(child.get("work_unit_id") or "").startswith("t4."):
                continue
            outputs = child.get("outputs")
            if not isinstance(outputs, Sequence):
                continue
            status_paths = [
                str(row.get("path") or "")
                for row in outputs
                if isinstance(row, Mapping)
                and str(row.get("path") or "").endswith("/status.json")
            ]
            if len(status_paths) == 1:
                return status_paths[0]
    raise VerifyQueuePhaseIOAuthorityError(
        f"{_unit_work_id(unit)}: state-selected input denominator has no "
        "exact selector artifact"
    )


def _effective_input_values(
    *,
    plan: Mapping[str, Any],
    unit: Mapping[str, Any],
    scratchpad: Path,
    project_root: Path,
    effective_inputs: Sequence[str] | None,
) -> tuple[str, ...]:
    if effective_inputs is not None:
        values = tuple(str(value) for value in effective_inputs)
    else:
        raw = unit.get("exact_inputs")
        if not isinstance(raw, Sequence) or isinstance(raw, (str, bytes)):
            raise VerifyQueuePhaseIOAuthorityError(
                f"{_unit_work_id(unit)}: exact_inputs must be a sequence"
            )
        values = tuple(str(value) for value in raw)
        declared = unit.get("declared_input_denominator")
        if declared is not None:
            if not isinstance(declared, Sequence) or isinstance(
                declared, (str, bytes)
            ):
                raise VerifyQueuePhaseIOAuthorityError(
                    f"{_unit_work_id(unit)}: declared input denominator is malformed"
                )
            declared_values = tuple(str(value) for value in declared)
            if not set(values).issubset(set(declared_values)):
                raise VerifyQueuePhaseIOAuthorityError(
                    f"{_unit_work_id(unit)}: physical inputs escape the "
                    "declared input denominator"
                )
        presence_roster = unit.get("presence_roster")
        required_inputs = unit.get("required_inputs")
        if presence_roster is not None or required_inputs is not None:
            if (
                not isinstance(presence_roster, Sequence)
                or isinstance(presence_roster, (str, bytes))
                or not isinstance(required_inputs, Sequence)
                or isinstance(required_inputs, (str, bytes))
            ):
                raise VerifyQueuePhaseIOAuthorityError(
                    f"{_unit_work_id(unit)}: presence/required input roster "
                    "is malformed"
                )
            optional = {str(value) for value in presence_roster}
            required = {str(value) for value in required_inputs}
            if optional & required or set(values) != optional | required:
                raise VerifyQueuePhaseIOAuthorityError(
                    f"{_unit_work_id(unit)}: presence/required roster does "
                    "not partition the exact input denominator"
                )
            physical: list[str] = []
            authority = unit.get("prearm_presence_authority")
            optional_states: dict[str, str] = {}
            if isinstance(authority, Mapping):
                entries = authority.get("entries")
                if not isinstance(entries, Sequence) or isinstance(
                    entries, (str, bytes)
                ):
                    raise VerifyQueuePhaseIOAuthorityError(
                        f"{_unit_work_id(unit)}: presence authority entries "
                        "are malformed"
                    )
                for row in entries:
                    if not isinstance(row, Mapping):
                        raise VerifyQueuePhaseIOAuthorityError(
                            f"{_unit_work_id(unit)}: presence authority row "
                            "is malformed"
                        )
                    identity = str(row.get("identity") or "")
                    if identity.startswith("scratchpad:"):
                        optional_states[
                            identity[len("scratchpad:"):]
                        ] = str(row.get("state") or "")
            for value in sorted(required):
                path = _path_for_input(
                    value,
                    scratchpad=scratchpad,
                    project_root=project_root,
                )
                if not path.is_file():
                    raise VerifyQueuePhaseIOAuthorityError(
                        f"{_unit_work_id(unit)}: required input is absent: "
                        f"{value}"
                    )
                physical.append(value)
            for value in sorted(optional):
                path = _path_for_input(
                    value,
                    scratchpad=scratchpad,
                    project_root=project_root,
                )
                state = optional_states.get(value)
                if state == "PRESENT_UNAUTHORIZED_QUARANTINED":
                    # Preserve the bytes on disk for review, but never grant
                    # them PhaseIO input authority merely because they exist.
                    continue
                if state == "ABSENT":
                    continue
                if path.exists() and not path.is_file():
                    raise VerifyQueuePhaseIOAuthorityError(
                        f"{_unit_work_id(unit)}: optional input is not a file: "
                        f"{value}"
                    )
                if state in {"PRESENT", "PRESENT_AUTHORIZED"}:
                    if not path.is_file():
                        raise VerifyQueuePhaseIOAuthorityError(
                            f"{_unit_work_id(unit)}: authorized optional input "
                            f"is absent: {value}"
                        )
                    physical.append(value)
                elif state is None and path.is_file():
                    # Compatibility for plans predating the committed
                    # prearm-presence authority.
                    physical.append(value)
                elif state not in {None, "ABSENT"}:
                    raise VerifyQueuePhaseIOAuthorityError(
                        f"{_unit_work_id(unit)}: optional input has unsupported "
                        f"presence state {state!r}: {value}"
                    )
            values = tuple(physical)
        selected = unit.get("delivery_state_exact_inputs")
        if selected is not None:
            if not isinstance(selected, Mapping):
                raise VerifyQueuePhaseIOAuthorityError(
                    f"{_unit_work_id(unit)}: state-selected input map is malformed"
                )
            selector = Path(scratchpad) / _conditional_selector_path(plan, unit)
            try:
                payload = json.loads(
                    selector.read_text(encoding="utf-8", errors="strict")
                )
            except (OSError, UnicodeError, json.JSONDecodeError) as exc:
                raise VerifyQueuePhaseIOAuthorityError(
                    f"{_unit_work_id(unit)}: state selector is unavailable: "
                    f"{type(exc).__name__}: {exc}"
                ) from exc
            state_field = str(
                unit.get("delivery_state_field") or "state"
            ).strip()
            state = str(payload.get(state_field) or "").strip()
            state_values = selected.get(state)
            if not isinstance(state_values, Sequence) or isinstance(
                state_values, (str, bytes)
            ):
                raise VerifyQueuePhaseIOAuthorityError(
                    f"{_unit_work_id(unit)}: selector state {state!r} has no "
                    "exact input denominator"
                )
            values = (*values, *(str(value) for value in state_values))
        conditional_groups = unit.get("conditional_input_groups")
        if conditional_groups is not None:
            selected_values = _committed_conditional_input_values(
                plan=plan,
                unit=unit,
                scratchpad=scratchpad,
                groups=conditional_groups,
            )
            values = (*values, *selected_values)
            if declared is not None and not {
                _identity(value) for value in values
            }.issubset({_identity(value) for value in declared_values}):
                raise VerifyQueuePhaseIOAuthorityError(
                    f"{_unit_work_id(unit)}: selected physical inputs escape "
                    "the declared input denominator"
                )
    identities = tuple(sorted({_identity(value) for value in values}))
    if len(identities) != len(set(identities)):
        raise VerifyQueuePhaseIOAuthorityError(
            f"{_unit_work_id(unit)}: duplicate effective input identity"
        )
    return identities


def _path_for_input(
    value: Any,
    *,
    scratchpad: Path,
    project_root: Path,
) -> Path:
    identity = _identity(value)
    root, relative = identity.split(":", 1)
    return (
        Path(project_root) / relative
        if root == "project"
        else Path(scratchpad) / relative
    )


def _committed_conditional_input_values(
    *,
    plan: Mapping[str, Any],
    unit: Mapping[str, Any],
    scratchpad: Path,
    groups: Any,
) -> tuple[str, ...]:
    """Resolve physical branch inputs only from committed PhaseIO receipts."""

    if not isinstance(groups, Mapping) or not groups:
        raise VerifyQueuePhaseIOAuthorityError(
            f"{_unit_work_id(unit)}: conditional input groups are malformed"
        )
    pipeline, mode, ecosystem, backend, phase = _plan_dimensions(plan)
    plan_run = str(plan.get("run_id") or "").strip()
    try:
        ledger = read_artifact_ledger(Path(scratchpad))
    except ArtifactLedgerError as exc:
        raise VerifyQueuePhaseIOAuthorityError(
            f"{_unit_work_id(unit)}: conditional producer ledger is invalid: {exc}"
        ) from exc
    work_units = ledger.get("work_units")
    if not isinstance(work_units, Mapping):
        raise VerifyQueuePhaseIOAuthorityError(
            f"{_unit_work_id(unit)}: conditional producer table is malformed"
        )
    selected_values: list[str] = []
    for group_name, raw in sorted(groups.items(), key=lambda row: str(row[0])):
        if not isinstance(raw, Mapping):
            raise VerifyQueuePhaseIOAuthorityError(
                f"{_unit_work_id(unit)}: conditional group {group_name!r} "
                "is malformed"
            )
        if (
            str(raw.get("selection") or "") != "EXACTLY_ONE"
            or str(raw.get("effective_input_policy") or "")
            != "COMMITTED_PHASEIO_CONDITIONAL_STATE"
            or raw.get("bind_selected_output_sha256_size") is not True
            or raw.get("bind_unselected_absence_record") is not True
            or raw.get("status_json_alone_is_authority") is not False
        ):
            raise VerifyQueuePhaseIOAuthorityError(
                f"{_unit_work_id(unit)}: conditional group {group_name!r} "
                "does not require committed PhaseIO authority"
            )
        candidates = raw.get("candidates")
        if not isinstance(candidates, Sequence) or isinstance(
            candidates, (str, bytes)
        ) or len(candidates) != 2:
            raise VerifyQueuePhaseIOAuthorityError(
                f"{_unit_work_id(unit)}: conditional group {group_name!r} "
                "does not declare exactly two candidates"
            )
        candidate_identities = tuple(_identity(value) for value in candidates)
        if len(set(candidate_identities)) != len(candidate_identities):
            raise VerifyQueuePhaseIOAuthorityError(
                f"{_unit_work_id(unit)}: conditional group {group_name!r} "
                "contains duplicate candidates"
            )
        producer_id = str(raw.get("authority_work_unit_id") or "").strip()
        producer_key = canonical_work_unit_key(
            pipeline, mode, ecosystem, backend, phase, producer_id
        )
        producer = work_units.get(producer_key)
        if (
            not isinstance(producer, Mapping)
            or not plan_run
            or producer.get("run_id") != plan_run
            or producer.get("semantic_status") != "ACTIVE"
            or producer.get("execution_state") != "OUTPUT_COMMITTED"
        ):
            raise VerifyQueuePhaseIOAuthorityError(
                f"{_unit_work_id(unit)}: conditional producer {producer_key} "
                "is not an active current-run commit"
            )
        artifacts = producer.get("artifacts")
        if not isinstance(artifacts, Mapping):
            raise VerifyQueuePhaseIOAuthorityError(
                f"{producer_key}: conditional artifact denominator is malformed"
            )
        selected: list[str] = []
        absent: list[str] = []
        for identity in candidate_identities:
            record = artifacts.get(identity)
            receipt = (
                record.get("conditional_receipt")
                if isinstance(record, Mapping)
                else None
            )
            receipt_state = (
                str(receipt.get("state") or "")
                if isinstance(receipt, Mapping)
                else ""
            )
            if (
                isinstance(record, Mapping)
                and record.get("owner_key") == producer_key
                and record.get("run_id") == plan_run
                and record.get("status") == "ACTIVE"
                and receipt_state == "PRODUCED"
                and isinstance(record.get("sha256"), str)
                and len(str(record.get("sha256"))) == 64
                and isinstance(record.get("size"), int)
            ):
                selected.append(identity)
            elif (
                isinstance(record, Mapping)
                and record.get("owner_key") == producer_key
                and record.get("run_id") == plan_run
                and record.get("status") == "MISSING"
                and receipt_state in {"NOT_TRIGGERED", "TRIGGERED_EMPTY"}
            ):
                absent.append(identity)
            else:
                raise VerifyQueuePhaseIOAuthorityError(
                    f"{_unit_work_id(unit)}: conditional candidate {identity} "
                    "lacks exact committed produced/absence authority"
                )
        if len(selected) != 1 or len(absent) != 1:
            raise VerifyQueuePhaseIOAuthorityError(
                f"{_unit_work_id(unit)}: conditional group {group_name!r} "
                "does not close as exactly one produced and one absent"
            )
        selected_values.append(selected[0])
    return tuple(selected_values)


def resolve_transaction_unit_authority(
    plan: Mapping[str, Any],
    unit: Mapping[str, Any],
    project_root: Path,
    scratchpad: Path,
    run_id: str,
    effective_inputs: Sequence[str] | None = None,
) -> tuple[PhaseIOContract, LaunchSpec]:
    """Construct the exact deterministic PhaseIO contract and launch.

    ``project_root`` and ``run_id`` are validated here even though neither is
    embedded in the immutable contract manifest.  This prevents callers from
    resolving a seemingly valid authority object without a current execution
    identity or a concrete project boundary.
    """

    _validate_plan_digest(plan)
    pipeline, mode, ecosystem, backend, phase = _plan_dimensions(plan)
    project = Path(project_root)
    root = Path(scratchpad)
    if not str(run_id or "").strip():
        raise VerifyQueuePhaseIOAuthorityError(
            "verify-queue PhaseIO run_id is absent"
        )
    plan_run = str(plan.get("run_id") or "").strip()
    if plan_run and plan_run != str(run_id).strip():
        raise VerifyQueuePhaseIOAuthorityError(
            "verify-queue plan/run identity mismatch"
        )
    if project == root:
        raise VerifyQueuePhaseIOAuthorityError(
            "project_root and scratchpad must be distinct authority roots"
        )
    work_unit_id = _unit_work_id(unit)
    owner_key = canonical_work_unit_key(
        pipeline, mode, ecosystem, backend, phase, work_unit_id
    )
    contract = PhaseIOContract(
        pipeline=pipeline,
        mode=mode,
        ecosystem=ecosystem,
        backend=backend,
        phase=phase,
        work_unit_id=work_unit_id,
        outputs=_output_specs(owner_key=owner_key, unit=unit),
        immutable_inputs=_effective_input_values(
            plan=plan,
            unit=unit,
            scratchpad=root,
            project_root=project,
            effective_inputs=effective_inputs,
        ),
        bounded_lookup_inputs=(),
        model_invoked=False,
    )
    launch_raw = unit.get("launch")
    launch = launch_raw if isinstance(launch_raw, Mapping) else {}
    model = str(launch.get("model") or _DRIVER_MODEL).strip()
    timeout = launch.get("timeout_s", _DRIVER_TIMEOUT_S)
    if not isinstance(timeout, int) or isinstance(timeout, bool):
        raise VerifyQueuePhaseIOAuthorityError(
            f"{work_unit_id}: launch timeout_s must be an integer"
        )
    raw_tools = launch.get("tool_policy", _DRIVER_TOOL_POLICY)
    if not isinstance(raw_tools, Sequence) or isinstance(
        raw_tools, (str, bytes)
    ):
        raise VerifyQueuePhaseIOAuthorityError(
            f"{work_unit_id}: launch tool_policy must be a sequence"
        )
    return contract, LaunchSpec(
        work_unit_key=contract.key,
        pipeline=pipeline,
        mode=mode,
        ecosystem=ecosystem,
        backend=backend,
        model=model,
        timeout_s=timeout,
        exec_mode=str(
            launch.get("exec_mode") or _DRIVER_EXEC_MODE
        ).strip(),
        tool_policy=tuple(str(value) for value in raw_tools),
    )


def arm_transaction_unit(
    *,
    scratchpad: Path,
    project_root: Path,
    plan: Mapping[str, Any],
    unit: Mapping[str, Any],
    run_id: str,
    effective_inputs: Sequence[str] | None = None,
) -> tuple[bool, list[str], PhaseIOContract, LaunchSpec]:
    """Bind one unit before its first output write.

    Returns ``(execute, issues, contract, launch)``.  A byte-current committed
    unit returns ``execute=False``.  An exact pre-output unit left by a crash
    returns ``execute=True`` without rebinding its output prestates.
    """

    contract, launch = resolve_transaction_unit_authority(
        plan,
        unit,
        Path(project_root),
        Path(scratchpad),
        run_id,
        effective_inputs,
    )
    root = Path(scratchpad)
    project = Path(project_root)
    producer_policy = unit.get("producer_binding_policy")
    explicit_absence_required = producer_policy is not None
    presence_roster = tuple(
        str(value) for value in unit.get("presence_roster", ())
    )
    explicit_absence_roster = tuple(
        str(value)
        for value in unit.get(
            "explicit_absence_roster",
            presence_roster,
        )
    )
    if producer_policy is not None:
        if producer_policy != _STRICT_PRODUCER_BINDING_POLICY:
            return (
                False,
                [
                    f"{contract.key}: strict producer_binding_policy is "
                    "partial or malformed"
                ],
                contract,
                launch,
            )
        producer_issues = (
            semantic_input_prebind_producer_authority_issues(
                root,
                project,
                contract.immutable_inputs,
                run_id=run_id,
            )
        )
        if producer_issues:
            return False, producer_issues, contract, launch
    absence_issues = (
        validate_work_unit_explicit_absence_bindings(
            root,
            project,
            contract,
            launch,
            run_id=run_id,
            require=True,
        )
        if explicit_absence_required
        else []
    )
    input_issues = validate_work_unit_inputs(
        root, project, contract, launch, run_id=run_id
    )
    output_issues = validate_work_unit_artifacts(
        root,
        project,
        contract,
        launch,
        run_id=run_id,
        actor="DRIVER",
    )
    if not input_issues and not output_issues:
        return (
            False,
            list(dict.fromkeys(absence_issues)),
            contract,
            launch,
        )
    try:
        ledger = read_artifact_ledger(root)
        prior = ledger.get("work_units", {}).get(contract.key)
    except ArtifactLedgerError as exc:
        return (
            False,
            [f"{contract.key}: PhaseIO ledger read failed: {exc}"],
            contract,
            launch,
        )
    if isinstance(prior, Mapping):
        exact_preexecution = bool(
            prior.get("run_id") == str(run_id)
            and prior.get("contract_digest") == contract.digest
            and prior.get("launch_digest") == launch.digest
            and prior.get("semantic_status") == "INPUTS_BOUND"
            and prior.get("execution_state") == "INPUTS_BOUND_PREEXECUTION"
            and prior.get("artifacts") == {}
        )
        if exact_preexecution:
            refreshed = validate_work_unit_inputs(
                root, project, contract, launch, run_id=run_id
            )
            refreshed_absence = (
                validate_work_unit_explicit_absence_bindings(
                    root,
                    project,
                    contract,
                    launch,
                    run_id=run_id,
                    require=True,
                )
                if explicit_absence_required
                else []
            )
            return (
                not refreshed and not refreshed_absence,
                list(dict.fromkeys([*refreshed, *refreshed_absence])),
                contract,
                launch,
            )
        # Never convert a malformed, foreign-run, or externally-mutated
        # committed unit into fresh authority.  The transaction must quarantine
        # or be explicitly invalidated by its owner.
        return (
            False,
            list(dict.fromkeys([
                *input_issues,
                *output_issues,
                *absence_issues,
            ])),
            contract,
            launch,
        )
    try:
        bound = record_work_unit_inputs(
            root, project, contract, launch, run_id=run_id
        )
    except (ArtifactLedgerError, OSError, TypeError, ValueError) as exc:
        return (
            False,
            [f"{contract.key}: PhaseIO input arm failed: "
             f"{type(exc).__name__}: {exc}"],
            contract,
            launch,
        )
    if explicit_absence_required:
        try:
            record_work_unit_explicit_absence_bindings(
                root,
                project,
                contract,
                launch,
                run_id=run_id,
                presence_roster=explicit_absence_roster,
            )
        except (ArtifactLedgerError, OSError, TypeError, ValueError) as exc:
            return (
                False,
                [
                    f"{contract.key}: explicit absence arm failed: "
                    f"{type(exc).__name__}: {exc}"
                ],
                contract,
                launch,
            )
    issues = validate_work_unit_inputs(
        root, project, contract, launch, run_id=run_id
    )
    if explicit_absence_required:
        issues.extend(
            validate_work_unit_explicit_absence_bindings(
                root,
                project,
                contract,
                launch,
                run_id=run_id,
                require=True,
            )
        )
    execute = bool(
        not issues
        and bound.get("semantic_status") == "INPUTS_BOUND"
        and bound.get("execution_state") == "INPUTS_BOUND_PREEXECUTION"
        and bound.get("artifacts") == {}
    )
    return execute, list(dict.fromkeys(issues)), contract, launch


def _conditional_receipts(
    contract: PhaseIOContract,
    conditional_states: Mapping[str, Any],
) -> dict[str, ConditionalOutputReceipt]:
    declared = {
        spec.identity: spec
        for spec in contract.outputs
        if spec.artifact_class == "CONDITIONAL"
    }
    normalized: dict[str, Any] = {}
    for key, value in conditional_states.items():
        identity = _identity(key)
        if identity in normalized:
            raise VerifyQueuePhaseIOAuthorityError(
                f"{contract.key}: duplicate conditional state for {identity}"
            )
        normalized[identity] = value
    if set(normalized) != set(declared):
        missing = sorted(set(declared) - set(normalized))
        extra = sorted(set(normalized) - set(declared))
        raise VerifyQueuePhaseIOAuthorityError(
            f"{contract.key}: conditional-state denominator mismatch; "
            f"missing={missing}, extra={extra}"
        )
    receipts: dict[str, ConditionalOutputReceipt] = {}
    state_by_condition: dict[str, str] = {}
    for identity, spec in declared.items():
        raw = normalized[identity]
        details = raw if isinstance(raw, Mapping) else {}
        state = str(
            details.get("state") if details else raw
        ).strip().upper()
        if state == "PRODUCED":
            denominator = int(details.get("expected_denominator", 1))
            produced = tuple(
                str(value)
                for value in details.get("produced_identities", (identity,))
            )
            failures: tuple[str, ...] = ()
        elif state in {"NOT_TRIGGERED", "TRIGGERED_EMPTY"}:
            denominator = int(details.get("expected_denominator", 0))
            produced = ()
            failures = ()
        elif state == "FAILED":
            denominator = int(details.get("expected_denominator", 1))
            produced = ()
            failures = tuple(
                str(value)
                for value in details.get(
                    "failure_ids", ("conditional-output-failed",)
                )
            )
        else:
            raise VerifyQueuePhaseIOAuthorityError(
                f"{contract.key}: unsupported conditional state {state!r}"
            )
        receipts[identity] = ConditionalOutputReceipt(
            work_unit_key=contract.key,
            contract_digest=contract.digest,
            artifact_identity=identity,
            condition_id=spec.condition_id,
            state=state,
            expected_denominator=denominator,
            produced_identities=produced,
            failure_ids=failures,
        )
        state_by_condition[spec.condition_id] = state
    live_compound_conditions = {"receipt_selected", "debt_selected"}
    if set(state_by_condition) == live_compound_conditions:
        produced = {
            condition
            for condition, state in state_by_condition.items()
            if state == "PRODUCED"
        }
        absent = {
            condition
            for condition, state in state_by_condition.items()
            if state in {"NOT_TRIGGERED", "TRIGGERED_EMPTY"}
        }
        if len(produced) != 1 or len(absent) != 1:
            raise VerifyQueuePhaseIOAuthorityError(
                f"{contract.key}: compound delivery does not close as "
                "exactly one produced receipt/debt branch"
            )
    return receipts


def commit_transaction_unit(
    *,
    scratchpad: Path,
    project_root: Path,
    contract: PhaseIOContract,
    launch: LaunchSpec,
    run_id: str,
    conditional_states: Mapping[str, Any] | None = None,
    precommit_issues: Sequence[str] = (),
) -> list[str]:
    """Commit one armed unit and replay the exact ledger-backed authority."""

    issues = [
        str(value).strip()
        for value in precommit_issues
        if str(value).strip()
    ]
    issues.extend(
        validate_work_unit_explicit_absence_bindings(
            Path(scratchpad),
            Path(project_root),
            contract,
            launch,
            run_id=run_id,
            require=False,
        )
    )
    try:
        receipts = _conditional_receipts(
            contract, dict(conditional_states or {})
        )
        record_work_unit_artifacts(
            Path(scratchpad),
            Path(project_root),
            contract,
            launch,
            run_id=run_id,
            actor="DRIVER",
            precommit_issues=issues,
            conditional_receipts=receipts,
        )
        issues.extend(validate_work_unit_artifacts(
            Path(scratchpad),
            Path(project_root),
            contract,
            launch,
            run_id=run_id,
            actor="DRIVER",
        ))
    except (
        ArtifactLedgerError,
        OSError,
        TypeError,
        ValueError,
        VerifyQueuePhaseIOAuthorityError,
    ) as exc:
        issues.append(
            f"{contract.key}: PhaseIO output commit failed: "
            f"{type(exc).__name__}: {exc}"
        )
    return list(dict.fromkeys(issues))


def _transaction_units(
    plan: Mapping[str, Any],
    *,
    require_parent_commit: bool,
) -> tuple[Mapping[str, Any], ...]:
    children = plan.get("children")
    if not isinstance(children, Sequence) or isinstance(
        children, (str, bytes)
    ):
        raise VerifyQueuePhaseIOAuthorityError(
            "verify-queue child roster is absent"
        )
    if any(not isinstance(unit, Mapping) for unit in children):
        raise VerifyQueuePhaseIOAuthorityError(
            "verify-queue child roster contains a malformed unit"
        )
    child_ids = tuple(_unit_work_id(unit) for unit in children)
    expected_parent = _PARENT_BY_CHILD_ROSTER.get(child_ids)
    if expected_parent is None:
        raise VerifyQueuePhaseIOAuthorityError(
            "verify-queue child roster is not exact T0--T9"
        )
    output_paths: list[str] = []
    for child in children:
        raw_outputs = child.get("outputs")
        if not isinstance(raw_outputs, Sequence) or isinstance(
            raw_outputs, (str, bytes)
        ):
            raise VerifyQueuePhaseIOAuthorityError(
                f"{_unit_work_id(child)}: exact output denominator is absent"
            )
        child_paths = [
            str(row.get("path") or "")
            for row in raw_outputs
            if isinstance(row, Mapping)
        ]
        if len(child_paths) != len(raw_outputs):
            raise VerifyQueuePhaseIOAuthorityError(
                f"{_unit_work_id(child)}: output row is malformed"
            )
        status_paths = [
            path for path in child_paths if path.endswith("/status.json")
        ]
        if len(status_paths) != 1:
            raise VerifyQueuePhaseIOAuthorityError(
                f"{_unit_work_id(child)}: expected one exact status projection"
            )
        output_paths.extend(child_paths)
    if len(output_paths) != len(set(output_paths)):
        raise VerifyQueuePhaseIOAuthorityError(
            "verify-queue child output authority is not disjoint"
        )
    outer = plan.get("outer_output_denominator")
    if (
        not isinstance(outer, Sequence)
        or isinstance(outer, (str, bytes))
        or set(str(value) for value in outer) != set(output_paths)
    ):
        raise VerifyQueuePhaseIOAuthorityError(
            "verify-queue outer output denominator is not exact"
        )
    parent = plan.get("parent")
    if not isinstance(parent, Mapping):
        raise VerifyQueuePhaseIOAuthorityError(
            "verify-queue read-only parent is absent"
        )
    if (
        _unit_work_id(parent) != expected_parent
        or parent.get("read_only") is not True
        or parent.get("outputs") != []
    ):
        raise VerifyQueuePhaseIOAuthorityError(
            "verify-queue parent is not the exact zero-output read-only join"
        )
    validates = parent.get("validates_work_units")
    if not isinstance(validates, Sequence) or isinstance(
        validates, (str, bytes)
    ) or tuple(str(value) for value in validates) != child_ids:
        raise VerifyQueuePhaseIOAuthorityError(
            "verify-queue parent child-authority denominator is not exact"
        )
    return (
        *tuple(children),
        *((parent,) if require_parent_commit else ()),
    )


def _transaction_edge_issues(
    *,
    ledger: Mapping[str, Any],
    contracts: Sequence[PhaseIOContract],
    run_id: str,
) -> list[str]:
    output_owner: dict[str, str] = {}
    for contract in contracts:
        for spec in contract.outputs:
            prior = output_owner.get(spec.identity)
            if prior is not None and prior != contract.key:
                return [
                    f"{spec.identity}: transaction output has multiple owners"
                ]
            output_owner[spec.identity] = contract.key
    issues: list[str] = []
    work_units = ledger.get("work_units")
    if not isinstance(work_units, Mapping):
        return ["verify-queue artifact ledger work_units table is malformed"]
    for contract in contracts:
        unit = work_units.get(contract.key)
        bindings = unit.get("input_bindings") if isinstance(unit, Mapping) else None
        if not isinstance(bindings, Mapping):
            continue
        for identity in contract.immutable_inputs:
            expected_owner = output_owner.get(identity)
            if expected_owner is None:
                continue
            binding = bindings.get(identity)
            if (
                not isinstance(binding, Mapping)
                or binding.get("producer_work_unit_key") != expected_owner
            ):
                issues.append(
                    f"{contract.key}: {identity} is not bound to its exact "
                    f"transaction producer {expected_owner}"
                )
                continue
            producer = work_units.get(expected_owner)
            if (
                not isinstance(producer, Mapping)
                or producer.get("run_id") != run_id
                or producer.get("semantic_status") != "ACTIVE"
                or producer.get("execution_state") != "OUTPUT_COMMITTED"
            ):
                issues.append(
                    f"{contract.key}: {identity} producer is not an active "
                    "current-run commit"
                )
    return issues


def validate_transaction_authority(
    *,
    scratchpad: Path,
    project_root: Path,
    plan: Mapping[str, Any],
    run_id: str,
    require_parent_commit: bool = True,
) -> list[str]:
    """Validate exact current-run authority for T0--T9 and the parent.

    The function is deliberately side-effect free and returns bounded,
    deterministic issue strings.  It never treats transaction status JSON or
    an in-memory ``parent_commit`` mapping as authority.
    """

    issues: list[str] = []
    contracts: list[PhaseIOContract] = []
    try:
        if plan.get("schema_version") not in {
            "plamen.verify_queue_transaction_plan.v1",
            "plamen.live_verify_queue_plan.v1",
        }:
            raise VerifyQueuePhaseIOAuthorityError(
                "verify-queue transaction plan schema is not authoritative"
            )
        if not str(plan.get("plan_digest") or "").strip():
            raise VerifyQueuePhaseIOAuthorityError(
                "verify-queue transaction plan digest is absent"
            )
        _validate_plan_digest(plan)
        units = _transaction_units(
            plan, require_parent_commit=require_parent_commit
        )
    except (TypeError, ValueError, VerifyQueuePhaseIOAuthorityError) as exc:
        return [
            "verify-queue PhaseIO topology invalid: "
            f"{type(exc).__name__}: {exc}"
        ]
    try:
        validation_context = _ArtifactValidationContext(
            Path(scratchpad), Path(project_root)
        )
    except ArtifactLedgerError as exc:
        return [f"verify-queue PhaseIO ledger invalid: {exc}"]
    for unit in units:
        try:
            contract, launch = resolve_transaction_unit_authority(
                plan,
                unit,
                Path(project_root),
                Path(scratchpad),
                run_id,
            )
            contracts.append(contract)
            issues.extend(validate_work_unit_inputs(
                Path(scratchpad),
                Path(project_root),
                contract,
                launch,
                run_id=run_id,
                _validation_context=validation_context,
            ))
            issues.extend(validate_work_unit_artifacts(
                Path(scratchpad),
                Path(project_root),
                contract,
                launch,
                run_id=run_id,
                actor="DRIVER",
                require_live_input_authority=False,
                _validation_context=validation_context,
            ))
        except (
            ArtifactLedgerError,
            OSError,
            TypeError,
            ValueError,
            VerifyQueuePhaseIOAuthorityError,
        ) as exc:
            work_id = str(unit.get("work_unit_id") or "<unknown>")
            issues.append(
                f"{work_id}: PhaseIO authority resolution failed: "
                f"{type(exc).__name__}: {exc}"
            )
    issues.extend(_transaction_edge_issues(
        ledger=validation_context.ledger,
        contracts=contracts,
        run_id=str(run_id),
    ))
    # This must remain the final filesystem authority operation.  In-memory
    # edge reconciliation is intentionally complete before the terminal epoch
    # so no callback can mutate a cached artifact after its last revalidation.
    issues.extend(validation_context.finish())
    return list(dict.fromkeys(issues))


__all__ = [
    "VerifyQueuePhaseIOAuthorityError",
    "arm_transaction_unit",
    "commit_transaction_unit",
    "resolve_transaction_unit_authority",
    "validate_transaction_authority",
]
