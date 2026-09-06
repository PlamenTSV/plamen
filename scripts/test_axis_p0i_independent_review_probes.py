"""Independent P0-I probes for promotion-domain and lineage authority.

These fixtures launch no model, subprocess, network request, or audit.  They
exercise real PhaseIO records in temporary directories and do not edit
production state.
"""
from __future__ import annotations

from dataclasses import replace
import hashlib
import json
from pathlib import Path

import pytest

import axis_disposition as AXIS
import axis_promotion_lineage as LINEAGE
import plamen_driver as DRIVER
from artifact_ledger import (
    read_artifact_ledger,
    record_work_unit_artifacts,
    record_work_unit_inputs,
    write_artifact_ledger,
)
from phase_io_contracts import (
    ArtifactSpec,
    DriverMergeEvent,
    LaunchSpec,
    PhaseIOContract,
)
from test_axis_promotion_assurance_blockers_red_p0_i import (
    _fully_committed_without_promotion,
)
from test_axis_repair_promotion_fault_red_p0_i import (
    _axis_phase,
    _complete_base_application,
)
from test_axis_repair_promotion_boundary_red_p0_i import (
    _promotion_fixture,
)
from test_axis_resume_canonical_recovery_red_p0_i import (
    RUN_ID,
    _committed_model_fixture,
)


def _inventory_ids(raw: bytes) -> tuple[str, ...]:
    return tuple(
        str(row["inventory_id"])
        for row in AXIS._v2_inventory_blocks(
            raw.decode("utf-8", errors="strict")
        )
    )


def _commit_tail(
    *,
    project: Path,
    scratchpad: Path,
    ordinal: int,
) -> str:
    source_name = f"_review_tail_source_{ordinal}.md"
    (scratchpad / source_name).write_text(
        f"independent tail source {ordinal}\n",
        encoding="utf-8",
    )
    key = (
        f"sc/thorough/evm/claude/review_tail/append-{ordinal:04d}"
    )
    contract = PhaseIOContract(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        phase="review_tail",
        work_unit_id=f"append-{ordinal:04d}",
        outputs=(
            ArtifactSpec(
                root="scratchpad",
                path="findings_inventory.md",
                owner_key=key,
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                write_mode="MERGE",
            ),
        ),
        immutable_inputs=(f"scratchpad:{source_name}",),
        model_invoked=False,
    )
    launch = LaunchSpec(
        work_unit_key=contract.key,
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        model="driver",
        timeout_s=30,
        exec_mode="python",
    )
    record_work_unit_inputs(
        scratchpad,
        project,
        contract,
        launch,
        run_id=RUN_ID,
    )
    inventory = scratchpad / "findings_inventory.md"
    before = inventory.read_bytes()
    block = (
        f"\n### Finding [INV-{900 + ordinal}]: review tail {ordinal}\n"
        f"**Source IDs**: REVIEW:{ordinal}\n"
        "**Verdict**: NEEDS_VERIFICATION\n"
        "**Severity**: Low\n"
        "**Location**: contracts/Review.sol:L1\n"
        "**Description**: independently committed tail\n"
        "**Impact**: independently committed impact\n"
    ).encode("utf-8")
    inventory.write_bytes(before + block)
    after = inventory.read_bytes()
    event = DriverMergeEvent(
        work_unit_key=contract.key,
        contract_digest=contract.digest,
        artifact_identity="scratchpad:findings_inventory.md",
        before_sha256=hashlib.sha256(before).hexdigest(),
        after_sha256=hashlib.sha256(after).hexdigest(),
        source_identities=(f"scratchpad:{source_name}",),
        identities_before=_inventory_ids(before),
        identities_after=_inventory_ids(after),
    )
    committed = record_work_unit_artifacts(
        scratchpad,
        project,
        contract,
        launch,
        run_id=RUN_ID,
        actor="DRIVER",
        merge_events={event.artifact_identity: event},
    )
    assert committed["semantic_status"] == "ACTIVE"
    return key


@pytest.mark.parametrize("mutation", ("empty", "omit_project_sources"))
def test_reconcile_final_self_signed_empty_input_contract_is_rejected(
    tmp_path: Path,
    mutation: str,
) -> None:
    """Generic commit validity cannot replace the expected domain contract."""

    scratchpad, config, _worklist, _application, _findings = (
        _complete_base_application(tmp_path)
    )
    project = Path(config["project_root"])
    exact_inputs = DRIVER._axis_disposition_exact_inputs(
        scratchpad,
        work_unit_id="reconcile.final",
        project_root=project,
    )
    expected, launch = DRIVER._axis_disposition_contract_and_launch(
        phase=_axis_phase(),
        config=config,
        scratchpad=scratchpad,
        work_unit_id="reconcile.final",
        exact_inputs=exact_inputs,
    )
    if mutation == "empty":
        forged = replace(
            expected,
            immutable_inputs=(),
            bounded_lookup_inputs=(),
        )
    else:
        forged = replace(
            expected,
            immutable_inputs=tuple(
                value
                for value in expected.immutable_inputs
                if not value.startswith("project:")
            ),
            bounded_lookup_inputs=tuple(
                value
                for value in expected.bounded_lookup_inputs
                if not value.startswith("project:")
            ),
        )
        assert forged.immutable_inputs != expected.immutable_inputs

    # Replace the correct producer with a real, internally consistent PhaseIO
    # producer at the same key and with the same outputs, but no semantic input
    # denominator.  Generic commit validation accepts this shape; the axis
    # domain boundary must not.
    output_bytes = {
        spec.path: (scratchpad / spec.path).read_bytes()
        for spec in expected.outputs
    }
    ledger = read_artifact_ledger(scratchpad)
    ledger["work_units"].pop(expected.key, None)
    for spec in expected.outputs:
        ledger["artifact_bindings"].pop(spec.identity, None)
        ledger["artifacts"].pop(Path(spec.path).name, None)
        (scratchpad / spec.path).unlink()
    write_artifact_ledger(scratchpad, ledger)
    armed = record_work_unit_inputs(
        scratchpad,
        project,
        forged,
        launch,
        run_id=str(config["_run_id"]),
    )
    assert armed["semantic_status"] == "INPUTS_BOUND"
    for relative, raw in output_bytes.items():
        path = scratchpad / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
    committed = record_work_unit_artifacts(
        scratchpad,
        project,
        forged,
        launch,
        run_id=str(config["_run_id"]),
        actor="DRIVER",
    )
    assert committed["semantic_status"] == "ACTIVE"

    with pytest.raises(
        AXIS.AxisDispositionError,
        match=r"(?i)(domain contract|manifest differs|reconcile\.final)",
    ) as raised:
        DRIVER._axis_require_committed_application_owner(
            scratchpad,
            phase=_axis_phase(),
            config=config,
            project_root=project,
            run_id=str(config["_run_id"]),
        )
    assert "denominator" in str(raised.value).lower(), str(raised.value)


def test_reconcile_final_cannot_omit_authorized_repair_pair(
    tmp_path: Path,
) -> None:
    """An EXECUTED repair receipt makes both repair artifacts mandatory."""

    scratchpad, config, _application, _findings = _promotion_fixture(
        tmp_path,
        state="EXECUTED",
    )
    project = Path(config["project_root"])
    exact_inputs = DRIVER._axis_disposition_exact_inputs(
        scratchpad,
        work_unit_id="reconcile.final",
        project_root=project,
    )
    expected, launch = DRIVER._axis_disposition_contract_and_launch(
        phase=_axis_phase(),
        config=config,
        scratchpad=scratchpad,
        work_unit_id="reconcile.final",
        exact_inputs=exact_inputs,
    )
    repair_pair = {
        "scratchpad:axis_coverage_repair_findings.md",
        "scratchpad:axis_coverage_repair_dispositions.json",
    }
    assert repair_pair.issubset(expected.immutable_inputs)
    forged = replace(
        expected,
        immutable_inputs=tuple(
            value
            for value in expected.immutable_inputs
            if value not in repair_pair
        ),
        bounded_lookup_inputs=tuple(
            value
            for value in expected.bounded_lookup_inputs
            if value not in repair_pair
        ),
    )

    output_bytes = {
        spec.path: (scratchpad / spec.path).read_bytes()
        for spec in expected.outputs
    }
    ledger = read_artifact_ledger(scratchpad)
    ledger["work_units"].pop(expected.key, None)
    for spec in expected.outputs:
        ledger["artifact_bindings"].pop(spec.identity, None)
        ledger["artifacts"].pop(Path(spec.path).name, None)
        (scratchpad / spec.path).unlink()
    write_artifact_ledger(scratchpad, ledger)
    armed = record_work_unit_inputs(
        scratchpad,
        project,
        forged,
        launch,
        run_id=str(config["_run_id"]),
    )
    assert armed["semantic_status"] == "INPUTS_BOUND"
    for relative, raw in output_bytes.items():
        path = scratchpad / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
    committed = record_work_unit_artifacts(
        scratchpad,
        project,
        forged,
        launch,
        run_id=str(config["_run_id"]),
        actor="DRIVER",
    )
    assert committed["semantic_status"] == "ACTIVE"

    with pytest.raises(
        AXIS.AxisDispositionError,
        match=r"(?i)(domain contract|manifest differs|reconcile\.final)",
    ):
        DRIVER._axis_require_committed_application_owner(
            scratchpad,
            phase=_axis_phase(),
            config=config,
            project_root=project,
            run_id=str(config["_run_id"]),
        )


def test_intermediate_tail_artifact_history_writer_mismatch_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A historical row and its signed manifest must have one exact writer."""

    (
        project,
        scratchpad,
        phase,
        config,
        _worklist,
        _frozen,
        _digest,
    ) = _committed_model_fixture(
        tmp_path,
        monkeypatch,
        backend="claude",
        disposition="FINDING",
    )
    _application, issues = DRIVER._finalize_axis_coverage_boundary(
        phase=phase,
        config=config,
        scratchpad=scratchpad,
    )
    assert issues == []
    first_owner = _commit_tail(
        project=project,
        scratchpad=scratchpad,
        ordinal=1,
    )
    _commit_tail(
        project=project,
        scratchpad=scratchpad,
        ordinal=2,
    )
    plan = json.loads(
        (scratchpad / AXIS.AXIS_PROMOTION_PLAN_NAME).read_text(
            encoding="utf-8"
        )
    )

    forged = read_artifact_ledger(scratchpad)
    identity = LINEAGE.INVENTORY_IDENTITY
    forged["work_units"][first_owner]["artifacts"][identity][
        "writer"
    ] = "MODEL"
    history = forged["artifact_bindings"][identity]["history"]
    matching = [
        row for row in history if row.get("owner_key") == first_owner
    ]
    assert len(matching) == 1
    matching[0]["writer"] = "MODEL"
    monkeypatch.setattr(LINEAGE, "read_artifact_ledger", lambda _root: forged)

    with pytest.raises(
        LINEAGE.AxisPromotionLineageError,
        match=r"(?i)(malformed|tuple|lineage)",
    ):
        LINEAGE.authorize_downstream_inventory_tail(
            scratchpad=scratchpad,
            project_root=project,
            run_id=RUN_ID,
            promotion_plan=plan,
            current_inventory_raw=(
                scratchpad / "findings_inventory.md"
            ).read_bytes(),
        )


def test_foreign_backend_pending_plan_does_not_poison_claude_replay(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Plan lookup is exact-namespace, not global suffix uniqueness."""

    project, scratchpad, phase, config, _worklist = (
        _fully_committed_without_promotion(tmp_path, monkeypatch)
    )
    foreign_config = {**config, "cli_backend": "codex"}
    exact_inputs = DRIVER._axis_disposition_exact_inputs(
        scratchpad,
        work_unit_id="promotion.plan",
        project_root=project,
    )
    foreign_contract, foreign_launch = (
        DRIVER._axis_disposition_contract_and_launch(
            phase=phase,
            config=foreign_config,
            scratchpad=scratchpad,
            work_unit_id="promotion.plan",
            exact_inputs=exact_inputs,
        )
    )
    execute, arm_issues = DRIVER._arm_deterministic_driver_work_unit(
        scratchpad=scratchpad,
        project_root=project,
        contract=foreign_contract,
        launch=foreign_launch,
        run_id=RUN_ID,
    )
    assert execute is True
    assert arm_issues == []

    application, first_issues = DRIVER._finalize_axis_coverage_boundary(
        phase=phase,
        config=config,
        scratchpad=scratchpad,
    )
    assert application["application_record_complete"] is True
    assert "no unique current-run" not in "\n".join(first_issues).lower()
    replay = DRIVER._axis_committed_promotion_plan_if_replayable(
        scratchpad=scratchpad,
        project_root=project,
        run_id=RUN_ID,
        config=config,
    )
    assert replay is not None

    _replayed_application, replay_issues = (
        DRIVER._finalize_axis_coverage_boundary(
            phase=phase,
            config=config,
            scratchpad=scratchpad,
        )
    )
    joined = "\n".join(replay_issues).lower()
    assert "no unique current-run" not in joined
    assert "backend namespace" not in joined
