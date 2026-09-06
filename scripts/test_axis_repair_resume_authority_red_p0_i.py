"""RED-only repair-resume authority specifications for P0-I.

These fixtures exercise a real, hermetic axis lifecycle from a committed base
MODEL proposal through deterministic reconciliation, a manually committed
repair MODEL proposal, finalization, and resume.  No model, subprocess,
network request, install, audit, or production artifact is launched or
modified.

The boundary under test is intentionally narrower than semantic final
reconciliation.  When the terminal repair-execution state proves that retained
repair work ran (``EXECUTED`` or retained ``OVERFLOW``), resume must replay the
active committed MODEL authority for ``repair.worker.0001`` directly.  It must
not rely only on DRIVER descendants that consumed the repair bytes.  Conversely
``FAILED`` and ``NOT_REQUIRED`` do not claim a committed repair MODEL result
and therefore must not demand one.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

import pytest

import axis_disposition as AXIS
import plamen_driver as DRIVER
import test_axis_resume_canonical_recovery_red_p0_i as BASE
from artifact_ledger import (
    LEDGER_NAME,
    read_artifact_ledger,
    record_work_unit_artifacts,
    record_work_unit_inputs,
    write_artifact_ledger,
)
from test_axis_repair_runtime_containment_red_p0_i import (
    _valid_repair_outputs,
)


def _unresolved_sidecar(
    worklist: Mapping[str, Any],
    _ignored_rows: list[dict[str, Any]],
) -> bytes:
    """Produce strict base MODEL authority that requires bounded repair."""

    rows = [
        {
            "work_item_id": item["work_item_id"],
            "disposition": "UNRESOLVED",
            "action_id": "",
            "evidence": [],
            "rationale": "hermetic fixture retains this item for repair",
        }
        for item in worklist["items"]
    ]
    unsigned = {
        "schema_version": AXIS.MODEL_DISPOSITIONS_SCHEMA,
        "run_id": BASE.RUN_ID,
        "worklist_hash": worklist["worklist_hash"],
        "producer": "MODEL",
        "items": rows,
    }
    return BASE._canonical(
        {
            **unsigned,
            "sidecar_digest": BASE._sha(BASE._canonical(unsigned)),
        }
    )


def _terminal_repair_fixture(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    backend: str,
    state: str,
) -> tuple[Path, Path, dict[str, Any], str]:
    """Build one terminal axis lifecycle without invoking a real worker."""

    monkeypatch.setattr(BASE, "_sidecar", _unresolved_sidecar)
    (
        project,
        scratchpad,
        phase,
        config,
        worklist,
        _frozen_files,
        _frozen_digest,
    ) = BASE._committed_model_fixture(
        tmp_path / state.casefold(),
        monkeypatch,
        backend=backend,
        disposition="CLEAR",
    )

    if state == "OVERFLOW":
        config["axis_repair_cap"] = 1
    elif state != "EXECUTED":
        raise AssertionError(f"unsupported successful repair state: {state}")

    _initial, plan, reconcile_issues = DRIVER._reconcile_axis_dispositions(
        phase=phase,
        config=config,
        scratchpad=scratchpad,
    )
    assert reconcile_issues == []
    assert plan["observed_count"] > 0
    assert plan["retained_count"] > 0
    assert bool(plan["overflow"]) is (state == "OVERFLOW")

    exact_inputs = DRIVER._axis_disposition_exact_inputs(
        scratchpad,
        work_unit_id="repair.worker.0001",
        project_root=project,
    )
    contract, launch = DRIVER._axis_disposition_contract_and_launch(
        phase=phase,
        config=config,
        scratchpad=scratchpad,
        work_unit_id="repair.worker.0001",
        exact_inputs=exact_inputs,
    )
    record_work_unit_inputs(
        scratchpad,
        project,
        contract,
        launch,
        run_id=BASE.RUN_ID,
    )
    _valid_repair_outputs(scratchpad, worklist, plan)
    DRIVER._axis_validate_repair_semantics(
        root=scratchpad,
        config=config,
        worklist=worklist,
        repair_plan=plan,
        repair_dispositions=(
            scratchpad / "axis_coverage_repair_dispositions.json"
        ).read_bytes(),
        repair_findings=(
            scratchpad / "axis_coverage_repair_findings.md"
        ).read_bytes(),
    )
    record_work_unit_artifacts(
        scratchpad,
        project,
        contract,
        launch,
        run_id=BASE.RUN_ID,
        actor="MODEL",
    )

    model_calls = BASE._forbid_model_execution(monkeypatch)
    _application, _finalization_issues = (
        DRIVER._finalize_axis_coverage_boundary(
            phase=phase,
            config=config,
            scratchpad=scratchpad,
        )
    )
    assert model_calls == []
    receipt = json.loads(
        (scratchpad / "axis_repair_execution_receipt.json").read_text(
            encoding="utf-8",
            errors="strict",
        )
    )
    assert receipt["state"] == state
    assert receipt["worker_executed"] is True

    if state == "EXECUTED":
        # A complete application can also bind the independent CLEAR-negative
        # denominator.  Retained OVERFLOW is intentionally assurance debt.
        BASE._harvest_negative(
            phase=phase,
            config=config,
            scratchpad=scratchpad,
        )
    return project, scratchpad, config, contract.key


@pytest.mark.parametrize("backend", ("claude", "codex"))
@pytest.mark.parametrize("state", ("EXECUTED", "OVERFLOW"))
def test_terminal_retained_repair_resume_directly_replays_model_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    backend: str,
    state: str,
) -> None:
    project, scratchpad, _config, repair_key = _terminal_repair_fixture(
        tmp_path,
        monkeypatch,
        backend=backend,
        state=state,
    )
    real_replay = DRIVER.active_committed_work_unit_authority_issues
    calls: list[str] = []
    sentinel = "REPAIR_MODEL_ACTIVE_COMMIT_SENTINEL"

    def replay(
        ledger: Mapping[str, Any],
        *,
        work_unit_key: str,
        run_id: str,
        expected_artifact_identities: tuple[str, ...] | None = None,
    ) -> list[str]:
        calls.append(work_unit_key)
        if work_unit_key == repair_key:
            return [sentinel]
        return real_replay(
            ledger,
            work_unit_key=work_unit_key,
            run_id=run_id,
            expected_artifact_identities=expected_artifact_identities,
        )

    monkeypatch.setattr(
        DRIVER,
        "active_committed_work_unit_authority_issues",
        replay,
    )
    issues = BASE._resume_issues(
        project=project,
        scratchpad=scratchpad,
        backend=backend,
    )
    assert repair_key in calls
    assert sentinel in issues


@pytest.mark.parametrize("state", ("EXECUTED", "OVERFLOW"))
@pytest.mark.parametrize("fault", ("missing", "tampered"))
def test_terminal_retained_repair_resume_names_invalid_model_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    state: str,
    fault: str,
) -> None:
    project, scratchpad, _config, repair_key = _terminal_repair_fixture(
        tmp_path,
        monkeypatch,
        backend="claude",
        state=state,
    )
    ledger = read_artifact_ledger(scratchpad)
    if fault == "missing":
        del ledger["work_units"][repair_key]
    else:
        ledger["work_units"][repair_key]["commit_authority"][
            "receipt_digest"
        ] = "0" * 64
    write_artifact_ledger(scratchpad, ledger)

    issues = BASE._resume_issues(
        project=project,
        scratchpad=scratchpad,
        backend="claude",
    )
    assert issues
    assert any(repair_key in issue for issue in issues), (
        "resume detected only derivative producer drift; it did not identify "
        "the invalid repair MODEL authority directly: " + "; ".join(issues)
    )


def _failed_repair_fixture(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    backend: str,
) -> tuple[Path, Path, str]:
    monkeypatch.setattr(BASE, "_sidecar", _unresolved_sidecar)
    (
        project,
        scratchpad,
        phase,
        config,
        _worklist,
        _frozen_files,
        _frozen_digest,
    ) = BASE._committed_model_fixture(
        tmp_path / "failed",
        monkeypatch,
        backend=backend,
        disposition="CLEAR",
    )

    def failed_worker(*_args: object, **_kwargs: object) -> int:
        return 1

    monkeypatch.setattr(DRIVER, "_run_one_codex_exec", failed_worker)
    monkeypatch.setattr(
        DRIVER,
        "_run_one_claude_headless_breadth_worker",
        failed_worker,
    )
    DRIVER._finalize_axis_coverage_boundary(
        phase=phase,
        config=config,
        scratchpad=scratchpad,
    )
    receipt = json.loads(
        (scratchpad / "axis_repair_execution_receipt.json").read_text(
            encoding="utf-8",
            errors="strict",
        )
    )
    assert receipt["state"] == "FAILED"
    exact_inputs = DRIVER._axis_disposition_exact_inputs(
        scratchpad,
        work_unit_id="repair.worker.0001",
        project_root=project,
    )
    contract, _launch = DRIVER._axis_disposition_contract_and_launch(
        phase=phase,
        config=config,
        scratchpad=scratchpad,
        work_unit_id="repair.worker.0001",
        exact_inputs=exact_inputs,
    )
    return project, scratchpad, contract.key


@pytest.mark.parametrize("backend", ("claude", "codex"))
@pytest.mark.parametrize("state", ("FAILED", "NOT_REQUIRED"))
def test_nonexecuted_repair_states_do_not_require_model_repair_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    backend: str,
    state: str,
) -> None:
    if state == "FAILED":
        project, scratchpad, repair_key = _failed_repair_fixture(
            tmp_path,
            monkeypatch,
            backend=backend,
        )
    else:
        (
            project,
            scratchpad,
            phase,
            config,
            _worklist,
            _frozen_files,
            _frozen_digest,
        ) = BASE._committed_model_fixture(
            tmp_path / "not-required",
            monkeypatch,
            backend=backend,
            disposition="CLEAR",
        )
        _application, finalization_issues = (
            DRIVER._finalize_axis_coverage_boundary(
                phase=phase,
                config=config,
                scratchpad=scratchpad,
            )
        )
        assert finalization_issues == []
        BASE._harvest_negative(
            phase=phase,
            config=config,
            scratchpad=scratchpad,
        )
        receipt = json.loads(
            (scratchpad / "axis_repair_execution_receipt.json").read_text(
                encoding="utf-8",
                errors="strict",
            )
        )
        assert receipt["state"] == "NOT_REQUIRED"
        exact_inputs = DRIVER._axis_disposition_exact_inputs(
            scratchpad,
            work_unit_id="repair.worker.0001",
            project_root=project,
        )
        contract, _launch = DRIVER._axis_disposition_contract_and_launch(
            phase=phase,
            config=config,
            scratchpad=scratchpad,
            work_unit_id="repair.worker.0001",
            exact_inputs=exact_inputs,
        )
        repair_key = contract.key

    calls: list[str] = []
    real_replay = DRIVER.active_committed_work_unit_authority_issues

    def replay(
        ledger: Mapping[str, Any],
        *,
        work_unit_key: str,
        run_id: str,
        expected_artifact_identities: tuple[str, ...] | None = None,
    ) -> list[str]:
        calls.append(work_unit_key)
        if work_unit_key == repair_key:
            return ["NONEXECUTED_REPAIR_MUST_NOT_REQUIRE_MODEL_AUTHORITY"]
        return real_replay(
            ledger,
            work_unit_key=work_unit_key,
            run_id=run_id,
            expected_artifact_identities=expected_artifact_identities,
        )

    monkeypatch.setattr(
        DRIVER,
        "active_committed_work_unit_authority_issues",
        replay,
    )
    issues = BASE._resume_issues(
        project=project,
        scratchpad=scratchpad,
        backend=backend,
    )
    assert repair_key not in calls
    assert "NONEXECUTED_REPAIR_MUST_NOT_REQUIRE_MODEL_AUTHORITY" not in issues


@pytest.mark.parametrize("backend", ("claude", "codex"))
def test_executed_repair_same_backend_resume_is_idempotent_and_backend_bound(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    backend: str,
) -> None:
    project, scratchpad, config, repair_key = _terminal_repair_fixture(
        tmp_path,
        monkeypatch,
        backend=backend,
        state="EXECUTED",
    )
    ledger_path = scratchpad / LEDGER_NAME
    ledger_before = ledger_path.read_bytes()
    first = BASE._resume_issues(
        project=project,
        scratchpad=scratchpad,
        backend=backend,
    )
    second = BASE._resume_issues(
        project=project,
        scratchpad=scratchpad,
        backend=backend,
    )
    assert first == second == []
    assert ledger_path.read_bytes() == ledger_before
    assert f"/{backend}/" in repair_key

    other = "codex" if backend == "claude" else "claude"
    other_config = {**config, "cli_backend": other}
    exact_inputs = DRIVER._axis_disposition_exact_inputs(
        scratchpad,
        work_unit_id="repair.worker.0001",
        project_root=project,
    )
    other_contract, _launch = DRIVER._axis_disposition_contract_and_launch(
        phase=BASE._axis_phase(),
        config=other_config,
        scratchpad=scratchpad,
        work_unit_id="repair.worker.0001",
        exact_inputs=exact_inputs,
    )
    assert other_contract.key != repair_key
    assert f"/{other}/" in other_contract.key
    assert BASE._resume_issues(
        project=project,
        scratchpad=scratchpad,
        backend=other,
    )
