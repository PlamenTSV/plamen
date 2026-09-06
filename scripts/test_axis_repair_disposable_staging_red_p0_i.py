"""RED specifications for the P0-I axis-repair disposable worker boundary.

Implementation contract
=======================

The repair model runs in a fresh, disposable workspace that is not the live
project and is not the live scratchpad.  Before launch the driver copies every
PhaseIO immutable input, byte-for-byte, into explicit ``scratchpad/`` and
``project/`` namespaces in that workspace.  A required input is represented as
exactly one of PRESENT, ABSENT, or READ_ERROR; READ_ERROR aborts launch and is
never treated as ABSENT.

The worker can read only those copies and can write only the two declared
outputs:

* ``axis_coverage_repair_findings.md``
* ``axis_coverage_repair_dispositions.json``

Process logs and supervisor receipts live outside the disposable workspace.
The worker receives no live project/scratchpad path through its working,
analysis, or writable-directory arguments.  After exit, the driver validates
the two staged outputs, copies accepted bytes into the live scratchpad, and
deletes the disposable workspace.  Live inputs are therefore never restored
after model mutation: they were never model-writable in the first place.

For deterministic repair execution, stale or partial repair bytes are not part
of the input denominator for NOT_REQUIRED or zero-retained OVERFLOW.  Failure
to arm ``repair.execution`` degrades to a digest-bound FAILED/debt receipt
instead of escaping the haltless finalizer.

These fixtures launch no process, model, network request, install, or audit.
They write only under pytest's temporary directory.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

import pytest

import axis_disposition as AXIS
import plamen_driver as DRIVER
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


REPAIR_OUTPUTS = {
    "axis_coverage_repair_findings.md",
    "axis_coverage_repair_dispositions.json",
}


def _replace_plan(
    *,
    scratchpad: Path,
    worklist: Mapping[str, Any],
    evidence: Mapping[str, Any],
    base_findings_raw: bytes,
    base_dispositions_raw: bytes,
    cap: int,
    canonical_prior_authority_digest: str | None = None,
) -> dict[str, Any]:
    if canonical_prior_authority_digest is None:
        canonical_prior_authority_digest = str(
            json.loads(
                (
                    scratchpad
                    / "axis_disposition_initial_receipt.json"
                ).read_text(encoding="utf-8", errors="strict")
            )["canonical_prior_authority_digest"]
        )
    initial, plan = AXIS.reconcile_axis_dispositions_initial(
        worklist,
        base_dispositions_raw=base_dispositions_raw,
        base_findings_raw=base_findings_raw,
        execution_evidence_authority=evidence,
        canonical_prior_ids={},
        canonical_prior_authority_digest=(
            canonical_prior_authority_digest
        ),
        repair_cap=cap,
    )
    AXIS.write_axis_disposition_v2_artifacts(
        scratchpad,
        worklist=worklist,
        initial_receipt=initial,
        repair_plan=plan,
    )
    return plan


def _assert_signed_repair_receipt(
    scratchpad: Path,
    receipt: Mapping[str, Any],
) -> None:
    stored = json.loads(
        (scratchpad / "axis_repair_execution_receipt.json").read_text(
            encoding="utf-8",
            errors="strict",
        )
    )
    assert stored == receipt
    assert DRIVER._axis_validate_repair_execution_receipt_signature(
        stored
    ) == stored


def test_immutable_input_read_error_aborts_before_worker_and_never_deletes_input(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (
        project,
        scratchpad,
        config,
        worklist,
        _evidence,
        _base_findings,
        _base_dispositions,
    ) = _seed_base(tmp_path, omit_after_first=True)
    plan_path = scratchpad / "axis_repair_plan.json"
    before = plan_path.read_bytes()
    plan = json.loads(before.decode("utf-8"))
    _install_ledger_seam(
        monkeypatch,
        input_issues=lambda *_args, **_kwargs: [],
        artifact_issues=_missing_then_clean_artifacts(),
    )

    original_read_bytes = Path.read_bytes
    injected = False

    def read_bytes(path: Path) -> bytes:
        nonlocal injected
        if Path(path) == plan_path and not injected:
            injected = True
            raise OSError("fixture immutable-input read failure")
        return original_read_bytes(path)

    monkeypatch.setattr(Path, "read_bytes", read_bytes)
    launches: list[dict[str, Any]] = []

    def forbidden_worker(**kwargs: Any) -> int:
        launches.append(dict(kwargs))
        _valid_repair_outputs(scratchpad, worklist, plan)
        return 0

    monkeypatch.setattr(
        DRIVER,
        "_run_one_claude_headless_breadth_worker",
        forbidden_worker,
    )
    monkeypatch.setattr(DRIVER, "_run_one_codex_exec", forbidden_worker)

    receipt, issues = DRIVER._run_axis_disposition_repair(
        phase=_axis_phase(),
        config=config,
        scratchpad=scratchpad,
        repair_plan=plan,
    )

    assert injected is True
    assert launches == [], "READ_ERROR must prevent model launch"
    assert plan_path.is_file(), "READ_ERROR must never be restored as ABSENT"
    assert plan_path.read_bytes() == before
    assert receipt["state"] == "FAILED"
    assert any("read" in issue.casefold() for issue in issues)
    _assert_signed_repair_receipt(scratchpad, receipt)


@pytest.mark.parametrize(
    ("terminal_state", "omit_after_first"),
    (("OVERFLOW", True), ("NOT_REQUIRED", False)),
)
def test_nonexecuting_repair_states_exclude_stale_partial_pair_and_promote_base(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    terminal_state: str,
    omit_after_first: bool,
) -> None:
    (
        project,
        scratchpad,
        config,
        worklist,
        evidence,
        base_findings,
        base_dispositions,
    ) = _seed_base(
        tmp_path / terminal_state.casefold(),
        omit_after_first=omit_after_first,
    )
    if terminal_state == "OVERFLOW":
        plan = _replace_plan(
            scratchpad=scratchpad,
            worklist=worklist,
            evidence=evidence,
            base_findings_raw=base_findings,
            base_dispositions_raw=base_dispositions,
            cap=0,
            canonical_prior_authority_digest=str(
                config["_fixture_axis_prior_digest"]
            ),
        )
        assert plan["observed_count"] > 0
        assert plan["retained_count"] == 0
        assert plan["overflow"] is True
    else:
        plan = json.loads(
            (scratchpad / "axis_repair_plan.json").read_text(
                encoding="utf-8",
                errors="strict",
            )
        )
        assert plan["observed_count"] == 0
        assert plan["retained_count"] == 0
        assert plan["overflow"] is False

    # A crashed/uncommitted prior attempt left only one half of the pair.
    stale = scratchpad / "axis_coverage_repair_findings.md"
    stale.write_text("stale partial repair residue", encoding="utf-8")
    observed_inputs: list[set[str]] = []

    def arm(**kwargs: Any) -> tuple[bool, list[str]]:
        contract = kwargs["contract"]
        if str(contract.key).endswith("/repair.execution"):
            observed_inputs.append(
                {
                    str(identity).split(":", 1)[-1]
                    for identity in contract.immutable_inputs
                }
            )
        return True, []

    monkeypatch.setattr(
        DRIVER, "_arm_deterministic_driver_work_unit", arm
    )
    monkeypatch.setattr(
        DRIVER,
        "_commit_deterministic_driver_work_unit",
        lambda **_kwargs: [],
    )
    launches: list[dict[str, Any]] = []
    monkeypatch.setattr(
        DRIVER,
        "_run_one_claude_headless_breadth_worker",
        lambda **kwargs: launches.append(dict(kwargs)) or 0,
    )
    monkeypatch.setattr(
        DRIVER,
        "_run_one_codex_exec",
        lambda **kwargs: launches.append(dict(kwargs)) or 0,
    )

    receipt, issues = DRIVER._run_axis_disposition_repair(
        phase=_axis_phase(),
        config=config,
        scratchpad=scratchpad,
        repair_plan=plan,
    )

    assert launches == []
    assert receipt["state"] == terminal_state
    assert receipt["worker_executed"] is False
    assert observed_inputs
    assert REPAIR_OUTPUTS.isdisjoint(observed_inputs[-1])
    _assert_signed_repair_receipt(scratchpad, receipt)
    if terminal_state == "OVERFLOW":
        assert receipt["issues"] == [
            f"repair plan overflow omitted "
            f"{plan['omitted_count']} AXW item(s)"
        ]
        assert issues in (
            [],
            list(receipt["issues"]),
        )
    else:
        assert issues == []

    # Promotion consumes the signed terminal state, not the stale pair.
    stale.unlink(missing_ok=True)
    application = _final_application(
        project=project,
        config=config,
        scratchpad=scratchpad,
        worklist=worklist,
        evidence=evidence,
        findings_raw=base_findings,
        repair_execution=receipt,
    )
    inventory_raw = (scratchpad / "findings_inventory.md").read_bytes()
    promotion = AXIS.build_axis_promotion_plan(
        application,
        run_id=str(config["_run_id"]),
        base_findings_raw=base_findings,
        repair_findings_raw=b"",
        inventory_raw=inventory_raw,
    )
    action_id = str(worklist["items"][0]["required_action_id"])
    planned = {
        str(row["action_id"])
        for row in promotion["planned_deliveries"]
    }
    assert action_id in planned
    assert action_id not in promotion["blocked_action_ids"]
    assert f"AXISGAP:{action_id}" in promotion["append_suffix_utf8"]


def test_repair_execution_arm_failure_degrades_to_signed_failed_debt_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (
        _project,
        scratchpad,
        config,
        worklist,
        evidence,
        base_findings,
        base_dispositions,
    ) = _seed_base(tmp_path, omit_after_first=True)
    plan = _replace_plan(
        scratchpad=scratchpad,
        worklist=worklist,
        evidence=evidence,
        base_findings_raw=base_findings,
        base_dispositions_raw=base_dispositions,
        cap=0,
    )
    assert plan["observed_count"] > 0
    assert plan["retained_count"] == 0

    def arm(**kwargs: Any) -> tuple[bool, list[str]]:
        if str(kwargs["contract"].key).endswith("/repair.execution"):
            raise OSError("fixture repair.execution ledger outage")
        return True, []

    monkeypatch.setattr(
        DRIVER, "_arm_deterministic_driver_work_unit", arm
    )
    monkeypatch.setattr(
        DRIVER,
        "_commit_deterministic_driver_work_unit",
        lambda **_kwargs: [],
    )
    monkeypatch.setattr(
        DRIVER,
        "record_work_unit_inputs",
        lambda *_args, **_kwargs: {
            "semantic_status": "INPUTS_BOUND",
            "execution_state": "INPUTS_BOUND_PREEXECUTION",
            "artifacts": {},
        },
    )
    monkeypatch.setattr(
        DRIVER,
        "validate_work_unit_inputs",
        lambda *_args, **_kwargs: [],
    )

    receipt, issues = DRIVER._run_axis_disposition_repair(
        phase=_axis_phase(),
        config=config,
        scratchpad=scratchpad,
        repair_plan=plan,
    )

    assert receipt["state"] == "FAILED"
    assert receipt["worker_executed"] is False
    assert any(
        "repair.execution" in issue
        and ("arm" in issue.casefold() or "ledger" in issue.casefold())
        for issue in issues
    )
    assert receipt["issues"] == issues
    _assert_signed_repair_receipt(scratchpad, receipt)


@pytest.mark.parametrize("backend", ("claude", "codex"))
def test_repair_worker_uses_disposable_staging_without_live_path_exposure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    backend: str,
) -> None:
    (
        project,
        scratchpad,
        config,
        worklist,
        _evidence,
        _base_findings,
        _base_dispositions,
    ) = _seed_base(tmp_path / backend, omit_after_first=True)
    config["cli_backend"] = backend
    plan_path = scratchpad / "axis_repair_plan.json"
    before = plan_path.read_bytes()
    plan = json.loads(before.decode("utf-8"))
    _install_ledger_seam(
        monkeypatch,
        input_issues=lambda *_args, **_kwargs: [],
        artifact_issues=_missing_then_clean_artifacts(),
    )
    observed: dict[str, Any] = {}

    def worker(**kwargs: Any) -> int:
        observed.update(kwargs)
        worker_root = Path(kwargs["scratchpad"]).resolve()
        _valid_repair_outputs(worker_root, worklist, plan)
        # This mutation is intentionally hostile.  Under the contract it
        # changes only the staged input copy.
        (worker_root / "axis_repair_plan.json").write_text(
            "staged mutation",
            encoding="utf-8",
        )
        return 0

    monkeypatch.setattr(
        DRIVER,
        "_run_one_claude_headless_breadth_worker",
        worker,
    )
    monkeypatch.setattr(DRIVER, "_run_one_codex_exec", worker)

    receipt, issues = DRIVER._run_axis_disposition_repair(
        phase=_axis_phase(),
        config=config,
        scratchpad=scratchpad,
        repair_plan=plan,
    )

    assert observed
    worker_root = Path(observed["scratchpad"]).resolve()
    working_directory = Path(observed["working_directory"]).resolve()
    assert worker_root != scratchpad.resolve()
    assert working_directory != scratchpad.resolve()
    assert not worker_root.is_relative_to(project.resolve())
    assert not working_directory.is_relative_to(project.resolve())
    exposed = {
        Path(value).resolve()
        for key in ("analysis_directories", "writable_directories")
        for value in (observed.get(key) or ())
    }
    assert project.resolve() not in exposed
    assert scratchpad.resolve() not in exposed
    assert observed["phase_io_contract"].key.endswith(
        "/axis_coverage/repair.worker.0001"
    )
    assert (
        observed["phase_io_launch"].work_unit_key
        == observed["phase_io_contract"].key
    )
    if backend == "claude":
        assert set(observed["expected_outputs"]) == REPAIR_OUTPUTS
    assert receipt["state"] == "EXECUTED"
    assert issues == []
    assert plan_path.read_bytes() == before
    for name in REPAIR_OUTPUTS:
        assert (scratchpad / name).is_file()
    assert not worker_root.exists(), "disposable worker root must be removed"
    _assert_signed_repair_receipt(scratchpad, receipt)
