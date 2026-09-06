"""Independent RED specifications for the remaining P0-I promotion boundary.

These tests intentionally pin properties that the current implementation does
not yet satisfy.  They launch no model, subprocess, network request, install,
or audit.  Production code is not changed by this file.
"""
from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

import axis_disposition as AXIS
import plamen_driver as DRIVER
from artifact_ledger import (
    read_artifact_ledger,
    record_work_unit_artifacts,
    record_work_unit_inputs,
)
from assurance_limitations import (
    assurance_projection_input_paths,
    build_current_assurance_manifest,
)
from phase_io_contracts import (
    ArtifactSpec,
    DriverMergeEvent,
    LaunchSpec,
    PhaseIOContract,
)
from plamen_types import Checkpoint
from test_axis_assurance_projection_p0_i import (
    _axis_rows,
    _manifest,
    _persist_v2_authority,
    _seed_project,
)
from test_axis_promotion_plan_replay_authority_p0_i import _plan_fixture
from test_axis_repair_promotion_fault_red_p0_i import (
    _axis_phase,
    _complete_base_application,
)
from test_axis_resume_canonical_recovery_red_p0_i import (
    RUN_ID as COMMITTED_RUN_ID,
    _committed_model_fixture,
    _harvest_negative,
)


def _later_inventory_block(*, inventory_id: str = "INV-999") -> bytes:
    return (
        f"\n### Finding [{inventory_id}]: later downstream candidate\n"
        "**Source IDs**: DOWNSTREAM:fixture\n"
        "**Verdict**: NEEDS_VERIFICATION\n"
        "**Severity**: Low\n"
        "**Location**: contracts/Later.sol:L1\n"
        "**Description**: independently produced later candidate\n"
        "**Impact**: independently verified later impact\n"
    ).encode("utf-8")


def _axis_manifest(project: Path, scratchpad: Path) -> dict:
    return build_current_assurance_manifest(
        Checkpoint(run_id=COMMITTED_RUN_ID),
        scratchpad,
        project,
    )


def _fully_committed_without_promotion(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[Path, Path, object, dict, dict]:
    (
        project,
        scratchpad,
        phase,
        config,
        worklist,
        _frozen,
        _digest,
    ) = _committed_model_fixture(
        tmp_path,
        monkeypatch,
        backend="claude",
        disposition="FINDING",
    )
    promote = DRIVER._promote_axis_disposition_actions
    monkeypatch.setattr(
        DRIVER,
        "_promote_axis_disposition_actions",
        lambda **_kwargs: ({}, []),
    )
    application, issues = DRIVER._finalize_axis_coverage_boundary(
        phase=phase,
        config=config,
        scratchpad=scratchpad,
    )
    monkeypatch.setattr(
        DRIVER,
        "_promote_axis_disposition_actions",
        promote,
    )
    assert issues == []
    assert application["application_record_complete"] is True
    return project, scratchpad, phase, config, worklist


def _commit_authorized_downstream_tail(
    project: Path,
    scratchpad: Path,
) -> None:
    """Append one tail through a real ACTIVE DRIVER/MERGE transition."""

    source_name = "_fixture_downstream_inventory_source.md"
    (scratchpad / source_name).write_text(
        "independent later candidate\n",
        encoding="utf-8",
    )
    key = "sc/thorough/evm/claude/fixture_tail/append"
    contract = PhaseIOContract(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        phase="fixture_tail",
        work_unit_id="append",
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
        run_id=COMMITTED_RUN_ID,
    )
    inventory = scratchpad / "findings_inventory.md"
    before = inventory.read_bytes()
    before_ids = tuple(
        str(row["inventory_id"])
        for row in AXIS._v2_inventory_blocks(
            before.decode("utf-8", errors="strict")
        )
    )
    inventory.write_bytes(before + _later_inventory_block())
    after = inventory.read_bytes()
    after_ids = tuple(
        str(row["inventory_id"])
        for row in AXIS._v2_inventory_blocks(
            after.decode("utf-8", errors="strict")
        )
    )
    event = DriverMergeEvent(
        work_unit_key=contract.key,
        contract_digest=contract.digest,
        artifact_identity="scratchpad:findings_inventory.md",
        before_sha256=hashlib.sha256(before).hexdigest(),
        after_sha256=hashlib.sha256(after).hexdigest(),
        source_identities=(f"scratchpad:{source_name}",),
        identities_before=before_ids,
        identities_after=after_ids,
    )
    committed = record_work_unit_artifacts(
        scratchpad,
        project,
        contract,
        launch,
        run_id=COMMITTED_RUN_ID,
        actor="DRIVER",
        merge_events={event.artifact_identity: event},
    )
    assert committed["semantic_status"] == "ACTIVE"


def test_assurance_exact_input_denominator_includes_committed_promotion_plan(
    tmp_path: Path,
) -> None:
    """The replay consumer must bind the plan it treats as authority."""

    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    (scratchpad / AXIS.AXIS_PROMOTION_PLAN_NAME).write_text(
        "{}\n",
        encoding="utf-8",
    )

    assert AXIS.AXIS_PROMOTION_PLAN_NAME in set(
        assurance_projection_input_paths(scratchpad)
    ), (
        "assurance can currently consume axis_coverage_promotion_plan.json "
        "without declaring it in its exact PhaseIO input denominator"
    )


def test_uncommitted_receipt_and_inventory_cannot_self_authorize_assurance(
    tmp_path: Path,
) -> None:
    """Valid-looking bytes written before promotion commit remain debt."""

    project, scratchpad = _seed_project(tmp_path)
    _persist_v2_authority(
        project,
        scratchpad,
        gap_axes=("theft",),
        disposition="FINDING",
        promotion=True,
    )

    rows = _axis_rows(_manifest(project, scratchpad))
    assert {row["gate_id"] for row in rows} == {
        "axis_promotion_delivery_invalid"
    }, (
        "a self-signed promotion receipt plus matching inventory bytes were "
        "accepted without a committed promotion.plan -> promotion PhaseIO "
        "ownership chain"
    )


def test_preplan_application_requires_committed_reconcile_final_owner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A signed application file is not its own producer authority."""

    scratchpad, config, _worklist, application, _findings = (
        _complete_base_application(tmp_path)
    )
    real_read_ledger = DRIVER.read_artifact_ledger
    ledger = real_read_ledger(scratchpad)
    ledger["work_units"] = {
        str(key): value
        for key, value in dict(ledger.get("work_units") or {}).items()
        if not str(key).endswith("/axis_disposition/reconcile.final")
    }
    monkeypatch.setattr(
        DRIVER,
        "read_artifact_ledger",
        lambda _root: ledger,
    )

    with pytest.raises(
        AXIS.AxisDispositionError,
        match=r"(?i)(reconcile\.final|committed|phaseio|owner)",
    ):
        DRIVER._promote_axis_disposition_actions(
            phase=_axis_phase(),
            config=config,
            scratchpad=scratchpad,
            application_receipt=application,
        )

    assert not (
        scratchpad / AXIS.AXIS_PROMOTION_PLAN_NAME
    ).exists(), "an owner-less application must not influence a committed plan"


def test_shared_successor_prefix_does_not_authorize_arbitrary_tail(
    tmp_path: Path,
) -> None:
    """Prefix equality proves history, not authority for later bytes."""

    application, predecessor, _repair, plan = _plan_fixture(tmp_path)
    successor = predecessor + plan["append_suffix_utf8"].encode("utf-8")
    receipt = AXIS.build_axis_promotion_authority(
        None,
        run_id=str(application["run_id"]),
        inventory_text=successor.decode("utf-8", errors="strict"),
        promotion_plan=plan,
    )
    unauthorized = successor + _later_inventory_block()

    with pytest.raises(
        AXIS.AxisDispositionError,
        match=r"(?i)(tail|downstream|authority|phaseio|successor)",
    ):
        AXIS.validate_axis_promotion_authority(
            receipt,
            None,
            inventory_text=unauthorized.decode("utf-8", errors="strict"),
            promotion_plan=plan,
        )


def test_signed_source_debt_is_projected_not_hidden_by_missing_alias(
    tmp_path: Path,
) -> None:
    """Missing-action is an outcome; source_debt is the signed cause."""

    application, predecessor, repair_findings, _complete_plan = _plan_fixture(
        tmp_path
    )
    plan = AXIS.build_axis_promotion_plan(
        application,
        run_id=str(application["run_id"]),
        base_findings_raw=b"",
        repair_findings_raw=repair_findings,
        inventory_raw=predecessor,
    )
    successor = predecessor + plan["append_suffix_utf8"].encode("utf-8")
    receipt = AXIS.build_axis_promotion_authority(
        None,
        run_id=str(application["run_id"]),
        inventory_text=successor.decode("utf-8", errors="strict"),
        promotion_plan=plan,
    )
    assert receipt["source_debt"], "fixture did not create signed source debt"

    projected = "\n".join(
        DRIVER._axis_promotion_semantic_issues(receipt)
    )
    for row in receipt["source_debt"]:
        assert str(row["action_id"]) in projected
        assert str(row["source"]) in projected
        assert str(row["reason"]) in projected


def test_assurance_distinguishes_authorized_tail_from_uncommitted_tail(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A later tail is accepted only through an exact ACTIVE MERGE chain."""

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
    application, issues = DRIVER._finalize_axis_coverage_boundary(
        phase=phase,
        config=config,
        scratchpad=scratchpad,
    )
    assert application["application_record_complete"] is True
    assert issues == []
    _harvest_negative(
        phase=phase,
        config=config,
        scratchpad=scratchpad,
    )

    _commit_authorized_downstream_tail(project, scratchpad)
    assert _axis_rows(_axis_manifest(project, scratchpad)) == [], (
        "the exact promotion successor prefix plus an ACTIVE downstream "
        "DRIVER/MERGE tail must remain valid"
    )

    # The same byte shape without a ledger transition is not authority.
    inventory = scratchpad / "findings_inventory.md"
    inventory.write_bytes(
        inventory.read_bytes()
        + _later_inventory_block(inventory_id="INV-998")
    )
    assert {
        row["gate_id"]
        for row in _axis_rows(_axis_manifest(project, scratchpad))
    } == {"axis_promotion_delivery_invalid"}


def test_conflict_debt_has_first_run_resume_and_assurance_parity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A conflict cannot disappear merely because delivery itself succeeded."""

    project, scratchpad, phase, config, worklist = (
        _fully_committed_without_promotion(tmp_path, monkeypatch)
    )
    action_id = str(worklist["items"][0]["required_action_id"])
    inventory = scratchpad / "findings_inventory.md"
    inventory.write_bytes(
        inventory.read_bytes()
        + (
            "\n### Finding [INV-041]: conflicting preexisting claim\n"
            f"**Source IDs**: AXISGAP:{action_id}\n"
            "**Verdict**: NEEDS_VERIFICATION\n"
            "**Severity**: Low\n"
            "**Location**: contracts/Wrong.sol:L9\n"
            "**Description**: not the committed action body\n"
            "**Impact**: unrelated impact\n"
        ).encode("utf-8")
    )
    application = AXIS.load_axis_disposition_v2_receipt(
        scratchpad / AXIS.AXIS_APPLICATION_RECEIPT_NAME,
        worklist=worklist,
    )
    first, first_issues = DRIVER._promote_axis_disposition_actions(
        phase=phase,
        config=config,
        scratchpad=scratchpad,
        application_receipt=application,
    )
    replay, replay_issues = DRIVER._promote_axis_disposition_actions(
        phase=phase,
        config=config,
        scratchpad=scratchpad,
        application_receipt=application,
    )
    assert first["conflicting_claim_action_ids"] == [action_id]
    assert replay == first
    assert replay_issues == first_issues
    assert action_id in "\n".join(first_issues)
    _harvest_negative(phase=phase, config=config, scratchpad=scratchpad)

    resume = DRIVER._axis_disposition_resume_issues(
        scratchpad=scratchpad,
        project_root=project,
        pipeline="sc",
        mode="thorough",
        language="evm",
        backend="claude",
        run_id=COMMITTED_RUN_ID,
    )
    assert action_id in "\n".join(resume), (
        "resume accepted the signed conflict without projecting its identity"
    )
    rows = _axis_rows(_axis_manifest(project, scratchpad))
    assert {row["gate_id"] for row in rows} == {
        "axis_promotion_delivery_invalid"
    }
    assert {
        identity
        for row in rows
        for identity in row["affected_identities"]
    } == {action_id}


def test_plan_first_assurance_survives_loss_of_mutable_producer_sources(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A committed plan remains canonical after its mutable inputs disappear."""

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
    application, issues = DRIVER._finalize_axis_coverage_boundary(
        phase=phase,
        config=config,
        scratchpad=scratchpad,
    )
    assert issues == []
    _harvest_negative(phase=phase, config=config, scratchpad=scratchpad)
    original_receipt = (
        scratchpad / AXIS.AXIS_PROMOTION_RECEIPT_NAME
    ).read_bytes()
    for name in (
        AXIS.AXIS_APPLICATION_RECEIPT_NAME,
        AXIS.OUTPUT_NAME,
        AXIS.AXIS_MODEL_DISPOSITIONS_NAME,
        AXIS.AXIS_REPAIR_FINDINGS_NAME,
        AXIS.AXIS_REPAIR_MODEL_DISPOSITIONS_NAME,
    ):
        (scratchpad / name).unlink(missing_ok=True)

    replay, _replay_issues = DRIVER._promote_axis_disposition_actions(
        phase=phase,
        config=config,
        scratchpad=scratchpad,
        application_receipt=application,
    )
    assert (
        scratchpad / AXIS.AXIS_PROMOTION_RECEIPT_NAME
    ).read_bytes() == original_receipt
    assert replay["plan_digest"]

    recovered_application, recovery_issues = (
        DRIVER._finalize_axis_coverage_boundary(
            phase=phase,
            config=config,
            scratchpad=scratchpad,
        )
    )
    assert recovered_application == {}
    assert (
        scratchpad / AXIS.AXIS_PROMOTION_RECEIPT_NAME
    ).read_bytes() == original_receipt
    assert "final reconciliation failed" not in "\n".join(
        recovery_issues
    ).lower()
    assert "retained delivery" in "\n".join(recovery_issues).lower()

    resume_issues = DRIVER._axis_disposition_resume_issues(
        scratchpad=scratchpad,
        project_root=project,
        pipeline="sc",
        mode="thorough",
        language="evm",
        backend="claude",
        run_id=COMMITTED_RUN_ID,
    )
    assert "lifecycle invalid" not in "\n".join(resume_issues).lower()
    assert "retained delivery" in "\n".join(resume_issues).lower()

    rows = _axis_rows(_axis_manifest(project, scratchpad))
    assert "axis_disposition_authority_invalid" not in {
        row["gate_id"] for row in rows
    }, (
        "assurance re-entered mutable application/BASE/REPAIR replay after "
        "the canonical committed plan was already available"
    )


def test_input_bound_promotion_plan_crash_resumes_normal_finalization(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An armed but uncommitted plan is resumable, not bad commit authority."""

    project, scratchpad, phase, config, _worklist = (
        _fully_committed_without_promotion(tmp_path, monkeypatch)
    )
    exact_inputs = DRIVER._axis_disposition_exact_inputs(
        scratchpad,
        work_unit_id="promotion.plan",
        project_root=project,
    )
    contract, launch = DRIVER._axis_disposition_contract_and_launch(
        phase=phase,
        config=config,
        scratchpad=scratchpad,
        work_unit_id="promotion.plan",
        exact_inputs=exact_inputs,
    )
    execute, arm_issues = DRIVER._arm_deterministic_driver_work_unit(
        scratchpad=scratchpad,
        project_root=project,
        contract=contract,
        launch=launch,
        run_id=COMMITTED_RUN_ID,
    )
    assert execute is True
    assert arm_issues == []
    armed = read_artifact_ledger(scratchpad)["work_units"][contract.key]
    assert armed["semantic_status"] == "INPUTS_BOUND"
    assert armed["execution_state"] == "INPUTS_BOUND_PREEXECUTION"
    assert not (
        scratchpad / AXIS.AXIS_PROMOTION_PLAN_NAME
    ).exists()

    application, issues = DRIVER._finalize_axis_coverage_boundary(
        phase=phase,
        config=config,
        scratchpad=scratchpad,
    )
    assert application["application_record_complete"] is True
    assert (
        scratchpad / AXIS.AXIS_PROMOTION_PLAN_NAME
    ).is_file()
    assert (
        scratchpad / AXIS.AXIS_PROMOTION_RECEIPT_NAME
    ).is_file()
    assert "failed plan-first replay" not in "\n".join(issues)
