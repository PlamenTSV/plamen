"""Fault matrix for the repair -> final reconcile -> promotion boundary.

No subprocess, model, network, install, or production mutation occurs here.
"""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

import pytest

import axis_disposition as AXIS
import plamen_driver as DRIVER
from artifact_ledger import read_artifact_ledger
from test_axis_repair_promotion_fault_red_p0_i import (
    _axis_phase,
    _final_application,
    _seed_base,
)
from test_axis_repair_runtime_containment_red_p0_i import (
    _install_ledger_seam,
    _missing_then_clean_artifacts,
    _valid_repair_outputs,
)


PAIR = {
    "axis_coverage_repair_findings.md",
    "axis_coverage_repair_dispositions.json",
}


def _overflow_plan(
    scratchpad: Path,
    worklist: Mapping[str, Any],
    evidence: Mapping[str, Any],
    base_findings: bytes,
    base_dispositions: bytes,
    prior_digest: str,
) -> dict[str, Any]:
    initial, plan = AXIS.reconcile_axis_dispositions_initial(
        worklist,
        base_dispositions_raw=base_dispositions,
        base_findings_raw=base_findings,
        execution_evidence_authority=evidence,
        canonical_prior_ids={},
        canonical_prior_authority_digest=prior_digest,
        repair_cap=1,
    )
    assert plan["overflow"] is True
    assert plan["retained_count"] == 1
    AXIS.write_axis_disposition_v2_artifacts(
        scratchpad,
        worklist=worklist,
        initial_receipt=initial,
        repair_plan=plan,
    )
    return plan


def _runtime_repair(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    state: str,
) -> tuple[Path, Path, dict[str, Any], dict[str, Any], dict[str, Any]]:
    (
        project,
        scratchpad,
        config,
        worklist,
        evidence,
        base_findings,
        base_dispositions,
    ) = _seed_base(tmp_path, omit_after_first=True)
    plan = json.loads(
        (scratchpad / "axis_repair_plan.json").read_text(encoding="utf-8")
    )
    if state == "OVERFLOW":
        plan = _overflow_plan(
            scratchpad,
            worklist,
            evidence,
            base_findings,
            base_dispositions,
            str(config["_fixture_axis_prior_digest"]),
        )
    _install_ledger_seam(
        monkeypatch,
        input_issues=lambda *_args, **_kwargs: [],
        artifact_issues=_missing_then_clean_artifacts(),
    )

    def worker(**kwargs: Any) -> int:
        worker_root = Path(kwargs["scratchpad"])
        if state == "FAILED":
            (worker_root / "axis_coverage_repair_findings.md").write_text(
                "invalid repair residue",
                encoding="utf-8",
            )
            (
                worker_root
                / "axis_coverage_repair_dispositions.json"
            ).write_text(
                "{}",
                encoding="utf-8",
            )
        else:
            _valid_repair_outputs(worker_root, worklist, plan)
        return 0

    monkeypatch.setattr(DRIVER, "_run_one_codex_exec", worker)
    monkeypatch.setattr(
        DRIVER,
        "_run_one_claude_headless_breadth_worker",
        worker,
    )
    receipt, _issues = DRIVER._run_axis_disposition_repair(
        phase=_axis_phase(),
        config=config,
        scratchpad=scratchpad,
        repair_plan=plan,
    )
    assert receipt["state"] == state
    return project, scratchpad, config, plan, receipt


def _exact_pair_inputs(
    scratchpad: Path,
    project: Path,
) -> dict[str, set[str]]:
    return {
        unit: set(
            DRIVER._axis_disposition_exact_inputs(
                scratchpad,
                work_unit_id=unit,
                project_root=project,
            )
        )
        for unit in (
            "repair.execution",
            "reconcile.final",
            "promotion.plan",
            "promotion",
        )
    }


def test_failed_repair_residue_is_absent_from_all_downstream_exact_inputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project, scratchpad, _config, _plan, receipt = _runtime_repair(
        tmp_path,
        monkeypatch,
        state="FAILED",
    )
    assert receipt["repair_dispositions_sha256"] == ""
    assert receipt["repair_findings_sha256"] == ""
    assert not any((scratchpad / name).exists() for name in PAIR)
    # Invalid outputs existed only in disposable staging; deletion of that
    # workspace is the quarantine boundary, so no live residue is expected.
    exact = _exact_pair_inputs(scratchpad, project)
    assert all(not (PAIR & values) for values in exact.values())
    assert exact["repair.execution"] == {"axis_repair_plan.json"}


@pytest.mark.parametrize("residue", ("partial", "pair"))
def test_failed_receipt_state_excludes_reappearing_untrusted_repair_pair(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    residue: str,
) -> None:
    project, scratchpad, _config, _plan, receipt = _runtime_repair(
        tmp_path,
        monkeypatch,
        state="FAILED",
    )
    assert receipt["state"] == "FAILED"
    # Model a failed quarantine move, external residue restoration, or stale
    # files from a torn cleanup. Presence must not override terminal authority.
    (scratchpad / "axis_coverage_repair_findings.md").write_text(
        "untrusted residue after FAILED",
        encoding="utf-8",
    )
    if residue == "pair":
        (scratchpad / "axis_coverage_repair_dispositions.json").write_text(
            "{}",
            encoding="utf-8",
        )

    exact = _exact_pair_inputs(scratchpad, project)
    assert all(not (PAIR & values) for values in exact.values())


@pytest.mark.parametrize("state", ("EXECUTED", "OVERFLOW"))
def test_terminal_valid_repair_pair_remains_bound_to_every_consumer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    state: str,
) -> None:
    project, scratchpad, _config, _plan, receipt = _runtime_repair(
        tmp_path / state.lower(),
        monkeypatch,
        state=state,
    )
    assert receipt["repair_dispositions_sha256"]
    assert receipt["repair_findings_sha256"]
    assert all((scratchpad / name).is_file() for name in PAIR)
    exact = _exact_pair_inputs(scratchpad, project)
    assert all(
        PAIR <= exact[unit]
        for unit in (
            "repair.execution",
            "reconcile.final",
            "promotion.plan",
        )
    )
    assert PAIR.isdisjoint(exact["promotion"])
    assert exact["promotion"] == {
        DRIVER._AXIS_PROMOTION_PLAN_OUTPUT
    }


def _promotion_fixture(
    tmp_path: Path,
    *,
    state: str,
    backend: str = "claude",
) -> tuple[Path, dict[str, Any], dict[str, Any], bytes]:
    (
        project,
        scratchpad,
        config,
        worklist,
        evidence,
        base_findings,
        base_dispositions,
    ) = _seed_base(tmp_path, omit_after_first=True)
    config["cli_backend"] = backend
    plan = json.loads(
        (scratchpad / "axis_repair_plan.json").read_text(encoding="utf-8")
    )
    if state == "OVERFLOW":
        plan = _overflow_plan(
            scratchpad,
            worklist,
            evidence,
            base_findings,
            base_dispositions,
            str(config["_fixture_axis_prior_digest"]),
        )
    _valid_repair_outputs(scratchpad, worklist, plan)
    repair = AXIS.build_axis_repair_execution_receipt(
        plan,
        state=state,
        repair_dispositions_raw=(
            scratchpad / "axis_coverage_repair_dispositions.json"
        ).read_bytes(),
        repair_findings_raw=(
            scratchpad / "axis_coverage_repair_findings.md"
        ).read_bytes(),
        issues=(
            [f"repair plan overflow omitted {plan['omitted_count']} AXW item(s)"]
            if state == "OVERFLOW"
            else ()
        ),
    )
    AXIS.write_axis_disposition_v2_artifacts(
        scratchpad,
        repair_execution_receipt=repair,
    )
    application = _final_application(
        project=project,
        config=config,
        scratchpad=scratchpad,
        worklist=worklist,
        evidence=evidence,
        findings_raw=base_findings,
        repair_execution=repair,
    )
    return scratchpad, config, application, base_findings


@pytest.mark.parametrize("state", ("EXECUTED", "OVERFLOW"))
def test_promotion_plan_is_idempotent_with_bound_terminal_repair_pair(
    tmp_path: Path,
    state: str,
) -> None:
    scratchpad, config, application, base_findings = _promotion_fixture(
        tmp_path / state.lower(),
        state=state,
    )
    repair_findings = (
        scratchpad / "axis_coverage_repair_findings.md"
    ).read_bytes()
    expected_actions = AXIS.referenced_axis_action_blocks(
        application,
        base_findings_raw=base_findings,
        repair_findings_raw=repair_findings,
    )
    assert any(row["source"] == "REPAIR" for row in expected_actions)

    first, first_issues = DRIVER._promote_axis_disposition_actions(
        phase=_axis_phase(),
        config=config,
        scratchpad=scratchpad,
        application_receipt=application,
    )
    inventory_after = (scratchpad / "findings_inventory.md").read_bytes()
    plan_after = (
        scratchpad / "axis_coverage_promotion_plan.json"
    ).read_bytes()
    second, second_issues = DRIVER._promote_axis_disposition_actions(
        phase=_axis_phase(),
        config=config,
        scratchpad=scratchpad,
        application_receipt=application,
    )

    assert first["status"] == "COMPLETE"
    assert first["delivery_count"] == len(expected_actions)
    assert first_issues == []
    assert second == first
    assert second_issues == []
    assert (scratchpad / "findings_inventory.md").read_bytes() == inventory_after
    assert (
        scratchpad / "axis_coverage_promotion_plan.json"
    ).read_bytes() == plan_after


def _base_and_repair_actions(
    *,
    scratchpad: Path,
    application: Mapping[str, Any],
    base_findings: bytes,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    repair_findings = (
        scratchpad / "axis_coverage_repair_findings.md"
    ).read_bytes()
    actions = list(AXIS.referenced_axis_action_blocks(
        application,
        base_findings_raw=base_findings,
        repair_findings_raw=repair_findings,
    ))
    base = [dict(row) for row in actions if row["source"] == "BASE"]
    repair = [dict(row) for row in actions if row["source"] == "REPAIR"]
    assert base and repair
    return base, repair


@pytest.mark.parametrize("mutation", ("delete_pair", "tamper_pair"))
def test_broken_repair_source_does_not_abort_independent_base_promotion(
    tmp_path: Path,
    mutation: str,
) -> None:
    scratchpad, config, application, base_findings = _promotion_fixture(
        tmp_path / mutation,
        state="EXECUTED",
    )
    base, repair = _base_and_repair_actions(
        scratchpad=scratchpad,
        application=application,
        base_findings=base_findings,
    )
    repair_ids = {str(row["action_id"]) for row in repair}
    findings_path = scratchpad / "axis_coverage_repair_findings.md"
    dispositions_path = scratchpad / "axis_coverage_repair_dispositions.json"
    if mutation == "delete_pair":
        findings_path.unlink()
        dispositions_path.unlink()
    else:
        findings_path.write_text(
            "tampered repair finding source",
            encoding="utf-8",
        )
        dispositions_path.write_text("{}", encoding="utf-8")

    promotion, issues = DRIVER._promote_axis_disposition_actions(
        phase=_axis_phase(),
        config=config,
        scratchpad=scratchpad,
        application_receipt=application,
    )
    replay, _replay_issues = DRIVER._promote_axis_disposition_actions(
        phase=_axis_phase(),
        config=config,
        scratchpad=scratchpad,
        application_receipt=application,
    )

    delivered = {
        str(row["action_id"]) for row in promotion["deliveries"]
    }
    base_ids = {str(row["action_id"]) for row in base}
    inventory = (scratchpad / "findings_inventory.md").read_text(
        encoding="utf-8",
        errors="strict",
    )
    assert promotion["status"] == "COMPLETED_WITH_DEBT"
    assert replay == promotion
    assert delivered == base_ids
    assert set(promotion["missing_action_ids"]) == repair_ids
    assert all(
        inventory.count(f"AXISGAP:{action_id}") == 1
        for action_id in base_ids
    )
    assert all(
        f"AXISGAP:{action_id}" not in inventory
        for action_id in repair_ids
    )
    assert all(any(action_id in issue for issue in issues) for action_id in repair_ids)


def test_already_promoted_base_replays_once_when_repair_source_is_missing(
    tmp_path: Path,
) -> None:
    scratchpad, config, application, base_findings = _promotion_fixture(
        tmp_path,
        state="EXECUTED",
    )
    base, repair = _base_and_repair_actions(
        scratchpad=scratchpad,
        application=application,
        base_findings=base_findings,
    )
    base_ids = {str(row["action_id"]) for row in base}
    repair_ids = {str(row["action_id"]) for row in repair}
    preexisting = [
        AXIS.render_axis_inventory_block(action, f"INV-{index:03d}")
        for index, action in enumerate(base, 1)
    ]
    inventory_path = scratchpad / "findings_inventory.md"
    inventory_path.write_text(
        "# Findings Inventory\n\n" + "\n\n".join(preexisting) + "\n",
        encoding="utf-8",
    )
    before = inventory_path.read_bytes()
    (scratchpad / "axis_coverage_repair_findings.md").unlink()
    (scratchpad / "axis_coverage_repair_dispositions.json").unlink()

    promotion, issues = DRIVER._promote_axis_disposition_actions(
        phase=_axis_phase(),
        config=config,
        scratchpad=scratchpad,
        application_receipt=application,
    )
    replay, _replay_issues = DRIVER._promote_axis_disposition_actions(
        phase=_axis_phase(),
        config=config,
        scratchpad=scratchpad,
        application_receipt=application,
    )

    delivered = {
        str(row["action_id"]) for row in promotion["deliveries"]
    }
    text = inventory_path.read_text(encoding="utf-8", errors="strict")
    assert promotion["status"] == "COMPLETED_WITH_DEBT"
    assert replay == promotion
    assert delivered == base_ids
    assert set(promotion["missing_action_ids"]) == repair_ids
    assert inventory_path.read_bytes() == before
    assert all(text.count(f"AXISGAP:{action_id}") == 1 for action_id in base_ids)
    assert all(f"AXISGAP:{action_id}" not in text for action_id in repair_ids)
    assert all(any(action_id in issue for issue in issues) for action_id in repair_ids)


@pytest.mark.parametrize("backend", ("claude", "codex"))
def test_missing_base_before_plan_does_not_suppress_valid_repair(
    tmp_path: Path,
    backend: str,
) -> None:
    """Source-level loss is symmetric at the action-level plan boundary."""

    scratchpad, config, application, base_findings = _promotion_fixture(
        tmp_path / backend,
        state="EXECUTED",
        backend=backend,
    )
    config["cli_backend"] = backend
    base, repair = _base_and_repair_actions(
        scratchpad=scratchpad,
        application=application,
        base_findings=base_findings,
    )
    base_ids = {str(row["action_id"]) for row in base}
    repair_ids = {str(row["action_id"]) for row in repair}
    (scratchpad / "axis_coverage_findings.md").unlink()

    promotion, issues = DRIVER._promote_axis_disposition_actions(
        phase=_axis_phase(),
        config=config,
        scratchpad=scratchpad,
        application_receipt=application,
    )
    inventory_path = scratchpad / "findings_inventory.md"
    inventory_after = inventory_path.read_bytes()
    replay, replay_issues = DRIVER._promote_axis_disposition_actions(
        phase=_axis_phase(),
        config=config,
        scratchpad=scratchpad,
        application_receipt=application,
    )

    delivered = {
        str(row["action_id"]) for row in promotion["deliveries"]
    }
    inventory_text = inventory_after.decode("utf-8", errors="strict")
    assert promotion["status"] == "COMPLETED_WITH_DEBT"
    assert delivered == repair_ids
    assert set(promotion["missing_action_ids"]) == base_ids
    assert all(
        inventory_text.count(f"AXISGAP:{action_id}") == 1
        for action_id in repair_ids
    )
    assert all(
        f"AXISGAP:{action_id}" not in inventory_text
        for action_id in base_ids
    )
    assert all(
        any(action_id in issue for issue in issues)
        for action_id in base_ids
    )
    assert replay == promotion
    assert replay_issues == issues
    assert inventory_path.read_bytes() == inventory_after


@pytest.mark.parametrize("backend", ("claude", "codex"))
@pytest.mark.parametrize("mutation", ("delete_pair", "tamper_pair"))
def test_committed_plan_replay_preserves_full_successor_when_source_breaks(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    backend: str,
    mutation: str,
) -> None:
    """A committed plan is replay authority, not a request to re-derive.

    This is the crash state immediately after ``promotion.plan`` commits and
    before ``promotion`` can arm.  The immutable plan already bound the exact
    BASE+REPAIR suffix, so later source loss cannot amend that successor or
    make either planned action disappear.
    """

    scratchpad, config, application, base_findings = _promotion_fixture(
        tmp_path / backend / mutation,
        state="EXECUTED",
        backend=backend,
    )
    config["cli_backend"] = backend
    base, repair = _base_and_repair_actions(
        scratchpad=scratchpad,
        application=application,
        base_findings=base_findings,
    )
    base_ids = {str(row["action_id"]) for row in base}
    repair_ids = {str(row["action_id"]) for row in repair}
    inventory_path = scratchpad / "findings_inventory.md"
    inventory_before = inventory_path.read_bytes()

    original_arm = DRIVER._arm_deterministic_driver_work_unit
    promotion_crashed = False

    def crash_after_plan_commit(**kwargs: Any) -> tuple[bool, list[str]]:
        nonlocal promotion_crashed
        contract = kwargs["contract"]
        if (
            contract.work_unit_id == "promotion"
            and not promotion_crashed
        ):
            promotion_crashed = True
            raise RuntimeError("fixture crash after promotion.plan commit")
        return original_arm(**kwargs)

    monkeypatch.setattr(
        DRIVER,
        "_arm_deterministic_driver_work_unit",
        crash_after_plan_commit,
    )
    with pytest.raises(RuntimeError, match="after promotion.plan commit"):
        DRIVER._promote_axis_disposition_actions(
            phase=_axis_phase(),
            config=config,
            scratchpad=scratchpad,
            application_receipt=application,
        )
    monkeypatch.setattr(
        DRIVER,
        "_arm_deterministic_driver_work_unit",
        original_arm,
    )

    plan_path = scratchpad / "axis_coverage_promotion_plan.json"
    plan_before = plan_path.read_bytes()
    assert plan_before
    assert inventory_path.read_bytes() == inventory_before
    plan_inputs = DRIVER._axis_disposition_exact_inputs(
        scratchpad,
        work_unit_id="promotion.plan",
        project_root=Path(config["project_root"]),
    )
    plan_contract, _plan_launch = (
        DRIVER._axis_disposition_contract_and_launch(
            phase=_axis_phase(),
            config=config,
            scratchpad=scratchpad,
            work_unit_id="promotion.plan",
            exact_inputs=plan_inputs,
        )
    )
    plan_record = read_artifact_ledger(scratchpad)["work_units"][
        plan_contract.key
    ]["artifacts"]["scratchpad:axis_coverage_promotion_plan.json"]
    assert plan_record["sha256"] == hashlib.sha256(plan_before).hexdigest()
    assert plan_record["size"] == len(plan_before)
    assert plan_record["owner_key"] == plan_contract.key
    assert plan_record["run_id"] == config["_run_id"]

    findings_path = scratchpad / "axis_coverage_repair_findings.md"
    dispositions_path = (
        scratchpad / "axis_coverage_repair_dispositions.json"
    )
    if mutation == "delete_pair":
        findings_path.unlink()
        dispositions_path.unlink()
    else:
        findings_path.write_text(
            "tampered repair finding source",
            encoding="utf-8",
        )
        dispositions_path.write_text("{}", encoding="utf-8")

    promotion, issues = DRIVER._promote_axis_disposition_actions(
        phase=_axis_phase(),
        config=config,
        scratchpad=scratchpad,
        application_receipt=application,
    )
    inventory_after = inventory_path.read_bytes()
    replay, replay_issues = DRIVER._promote_axis_disposition_actions(
        phase=_axis_phase(),
        config=config,
        scratchpad=scratchpad,
        application_receipt=application,
    )

    delivered = {
        str(row["action_id"]) for row in promotion["deliveries"]
    }
    planned_ids = base_ids | repair_ids
    inventory_text = inventory_after.decode("utf-8", errors="strict")
    assert plan_path.read_bytes() == plan_before
    assert promotion["status"] == "COMPLETE"
    assert delivered == planned_ids
    assert promotion["missing_action_ids"] == []
    assert all(
        inventory_text.count(f"AXISGAP:{action_id}") == 1
        for action_id in planned_ids
    )
    assert any(
        token in " ".join(issues).casefold()
        for token in ("source drift", "source unavailable", "repair source")
    )
    assert replay == promotion
    assert inventory_path.read_bytes() == inventory_after
    assert any(
        token in " ".join(replay_issues).casefold()
        for token in ("source drift", "source unavailable", "repair source")
    )


@pytest.mark.parametrize("backend", ("claude", "codex"))
def test_committed_plan_live_bytes_must_match_phaseio_artifact(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    backend: str,
) -> None:
    """A self-signed file cannot replace the PhaseIO-committed plan bytes."""

    scratchpad, config, application, _base_findings = _promotion_fixture(
        tmp_path / backend,
        state="EXECUTED",
        backend=backend,
    )
    config["cli_backend"] = backend
    inventory_path = scratchpad / "findings_inventory.md"
    inventory_before = inventory_path.read_bytes()
    original_arm = DRIVER._arm_deterministic_driver_work_unit
    promotion_crashed = False

    def crash_after_plan_commit(**kwargs: Any) -> tuple[bool, list[str]]:
        nonlocal promotion_crashed
        if (
            kwargs["contract"].work_unit_id == "promotion"
            and not promotion_crashed
        ):
            promotion_crashed = True
            raise RuntimeError("fixture crash after promotion.plan commit")
        return original_arm(**kwargs)

    monkeypatch.setattr(
        DRIVER,
        "_arm_deterministic_driver_work_unit",
        crash_after_plan_commit,
    )
    with pytest.raises(RuntimeError, match="after promotion.plan commit"):
        DRIVER._promote_axis_disposition_actions(
            phase=_axis_phase(),
            config=config,
            scratchpad=scratchpad,
            application_receipt=application,
        )
    monkeypatch.setattr(
        DRIVER,
        "_arm_deterministic_driver_work_unit",
        original_arm,
    )

    plan_path = scratchpad / "axis_coverage_promotion_plan.json"
    plan = json.loads(plan_path.read_text(encoding="utf-8", errors="strict"))
    plan["status"] = (
        "READY_WITH_DEBT"
        if plan["status"] == "READY"
        else "READY"
    )
    plan["plan_digest"] = AXIS._digest({
        key: value for key, value in plan.items()
        if key != "plan_digest"
    })
    plan_path.write_text(
        json.dumps(plan, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(
        AXIS.AxisDispositionError,
        match=r"(?i)promotion plan.*(phaseio|committed artifact|ledger)",
    ):
        DRIVER._promote_axis_disposition_actions(
            phase=_axis_phase(),
            config=config,
            scratchpad=scratchpad,
            application_receipt=application,
        )

    assert inventory_path.read_bytes() == inventory_before
    assert not (
        scratchpad / "axis_coverage_promotion_receipt.json"
    ).exists()


@pytest.mark.parametrize("backend", ("claude", "codex"))
def test_disk_application_drift_is_rejected_before_promotion_mutation(
    tmp_path: Path,
    backend: str,
) -> None:
    """The PhaseIO-bound disk receipt must be the semantic authority."""

    scratchpad, config, application, _base_findings = _promotion_fixture(
        tmp_path / backend,
        state="EXECUTED",
        backend=backend,
    )
    config["cli_backend"] = backend
    inventory_path = scratchpad / "findings_inventory.md"
    inventory_before = inventory_path.read_bytes()
    application_path = scratchpad / "axis_disposition_receipt.json"
    application_path.write_text("{}", encoding="utf-8")

    with pytest.raises(
        AXIS.AxisDispositionError,
        match=r"(?i)(application|authority).*(drift|differ|mismatch|input)",
    ):
        DRIVER._promote_axis_disposition_actions(
            phase=_axis_phase(),
            config=config,
            scratchpad=scratchpad,
            application_receipt=application,
        )

    assert inventory_path.read_bytes() == inventory_before
    assert not (
        scratchpad / "axis_coverage_promotion_plan.json"
    ).exists()
    assert not (
        scratchpad / "axis_coverage_promotion_receipt.json"
    ).exists()


@pytest.mark.parametrize("backend", ("claude", "codex"))
def test_repair_source_drift_before_plan_prebind_cannot_use_stale_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    backend: str,
) -> None:
    """Bytes read before the lock cannot escape the PhaseIO denominator."""

    scratchpad, config, application, base_findings = _promotion_fixture(
        tmp_path / backend,
        state="EXECUTED",
        backend=backend,
    )
    config["cli_backend"] = backend
    base, repair = _base_and_repair_actions(
        scratchpad=scratchpad,
        application=application,
        base_findings=base_findings,
    )
    base_ids = {str(row["action_id"]) for row in base}
    repair_ids = {str(row["action_id"]) for row in repair}

    @contextmanager
    def drift_on_lock(_scratchpad: Path):
        (
            scratchpad / "axis_coverage_repair_findings.md"
        ).write_text("drift-before-plan-prebind", encoding="utf-8")
        (
            scratchpad / "axis_coverage_repair_dispositions.json"
        ).write_text("{}", encoding="utf-8")
        yield

    monkeypatch.setattr(
        DRIVER.enumeration_gate_authority,
        "_inventory_append_lock",
        drift_on_lock,
    )
    promotion, issues = DRIVER._promote_axis_disposition_actions(
        phase=_axis_phase(),
        config=config,
        scratchpad=scratchpad,
        application_receipt=application,
    )

    delivered = {
        str(row["action_id"]) for row in promotion["deliveries"]
    }
    inventory_text = (
        scratchpad / "findings_inventory.md"
    ).read_text(encoding="utf-8", errors="strict")
    assert promotion["status"] == "COMPLETED_WITH_DEBT"
    assert delivered == base_ids
    assert set(promotion["missing_action_ids"]) == repair_ids
    assert all(
        inventory_text.count(f"AXISGAP:{action_id}") == 1
        for action_id in base_ids
    )
    assert all(
        f"AXISGAP:{action_id}" not in inventory_text
        for action_id in repair_ids
    )
    assert all(
        any(action_id in issue for issue in issues)
        for action_id in repair_ids
    )


def _append_unreferenced_base_action_to_repair_source(
    *,
    scratchpad: Path,
    application: Mapping[str, Any],
    base_findings: bytes,
) -> str:
    base, _repair = _base_and_repair_actions(
        scratchpad=scratchpad,
        application=application,
        base_findings=base_findings,
    )
    injected = base[0]
    repair_path = scratchpad / "axis_coverage_repair_findings.md"
    repair_path.write_text(
        repair_path.read_text(encoding="utf-8", errors="strict")
        + "\n\n"
        + str(injected["block_utf8"])
        + "\n",
        encoding="utf-8",
    )
    return str(injected["action_id"])


def test_repair_semantic_gate_rejects_unreferenced_base_action_copy(
    tmp_path: Path,
) -> None:
    """The repair action denominator must exactly equal its sidecar rows."""

    scratchpad, _config, application, base_findings = _promotion_fixture(
        tmp_path,
        state="EXECUTED",
    )
    injected_id = _append_unreferenced_base_action_to_repair_source(
        scratchpad=scratchpad,
        application=application,
        base_findings=base_findings,
    )
    worklist = json.loads(
        (scratchpad / "axis_disposition_worklist.json").read_text(
            encoding="utf-8",
            errors="strict",
        )
    )
    initial = json.loads(
        (scratchpad / "axis_disposition_initial_receipt.json").read_text(
            encoding="utf-8",
            errors="strict",
        )
    )
    repair_plan = json.loads(
        (scratchpad / "axis_repair_plan.json").read_text(
            encoding="utf-8",
            errors="strict",
        )
    )
    evidence = json.loads(
        (scratchpad / "axis_execution_evidence_authority.json").read_text(
            encoding="utf-8",
            errors="strict",
        )
    )

    with pytest.raises(
        AXIS.AxisDispositionError,
        match=r"(?i)(unreferenced|unexpected|extra|denominator)",
    ) as error:
        AXIS.validate_axis_repair_model_outputs(
            worklist,
            initial_receipt=initial,
            repair_plan=repair_plan,
            repair_dispositions_raw=(
                scratchpad
                / "axis_coverage_repair_dispositions.json"
            ).read_bytes(),
            repair_findings_raw=(
                scratchpad / "axis_coverage_repair_findings.md"
            ).read_bytes(),
            execution_evidence_authority=evidence,
            canonical_prior_ids={},
            canonical_prior_authority_digest="c" * 64,
        )

    assert injected_id in str(error.value)


def test_other_source_impostor_cannot_veto_application_selected_base(
    tmp_path: Path,
) -> None:
    """Legacy residue is debt, never negative authority over valid BASE."""

    scratchpad, _config, application, base_findings = _promotion_fixture(
        tmp_path,
        state="EXECUTED",
    )
    injected_id = _append_unreferenced_base_action_to_repair_source(
        scratchpad=scratchpad,
        application=application,
        base_findings=base_findings,
    )
    actions, source_debt = AXIS.resolve_axis_action_blocks(
        application,
        base_findings_raw=base_findings,
        repair_findings_raw=(
            scratchpad / "axis_coverage_repair_findings.md"
        ).read_bytes(),
    )

    resolved = {
        str(row["action_id"]): row for row in actions
    }
    collision_debt = [
        row for row in source_debt
        if str(row.get("action_id") or "") == injected_id
    ]
    assert injected_id in resolved
    assert resolved[injected_id]["source"] == "BASE"
    assert collision_debt
    assert any(
        token in str(collision_debt).casefold()
        for token in ("collision", "duplicate", "source")
    )
