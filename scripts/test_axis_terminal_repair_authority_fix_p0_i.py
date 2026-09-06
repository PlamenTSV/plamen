"""RED specifications for terminal P0-I repair authority.

These fixtures are hermetic.  They launch no process, model, network request,
install, or audit and write only below pytest's temporary directory.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

import pytest

import axis_disposition as AXIS
import plamen_driver as DRIVER
from test_axis_repair_disposable_staging_red_p0_i import _replace_plan
from test_axis_repair_promotion_fault_red_p0_i import (
    _axis_phase,
    _seed_base,
)
from test_axis_repair_runtime_containment_red_p0_i import (
    _missing_then_clean_artifacts,
    _valid_repair_outputs,
)


PAIR = {
    "axis_coverage_repair_findings.md",
    "axis_coverage_repair_dispositions.json",
}


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _resign(receipt: Mapping[str, Any], **changes: Any) -> dict[str, Any]:
    unsigned = {
        key: value
        for key, value in {**dict(receipt), **changes}.items()
        if key != "execution_digest"
    }
    return {
        **unsigned,
        "execution_digest": hashlib.sha256(_canonical(unsigned)).hexdigest(),
    }


def _write_receipt(scratchpad: Path, receipt: Mapping[str, Any]) -> None:
    (scratchpad / "axis_repair_execution_receipt.json").write_bytes(
        _canonical(receipt)
    )


def _plan_with_cap(
    tmp_path: Path,
    *,
    cap: int,
) -> tuple[
    Path,
    Path,
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
]:
    (
        project,
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
        cap=cap,
    )
    return project, scratchpad, config, worklist, evidence, plan


def test_cap_zero_overflow_cannot_claim_or_validate_repair_bytes(
    tmp_path: Path,
) -> None:
    (
        _project,
        _scratchpad,
        config,
        _worklist,
        _evidence,
        plan,
    ) = _plan_with_cap(tmp_path, cap=0)
    assert plan["overflow"] is True
    assert plan["retained_count"] == 0

    with pytest.raises(AXIS.AxisDispositionError):
        AXIS.build_axis_repair_execution_receipt(
            plan,
            state="OVERFLOW",
            repair_dispositions_raw=b"{}",
            repair_findings_raw=b"not-authorized",
            issues=(
                f"repair plan overflow omitted "
                f"{plan['omitted_count']} AXW item(s)",
            ),
        )

    legitimate = AXIS.build_axis_repair_execution_receipt(
        plan,
        state="OVERFLOW",
        issues=(
            f"repair plan overflow omitted "
            f"{plan['omitted_count']} AXW item(s)",
        ),
    )
    forged = _resign(
        legitimate,
        worker_executed=True,
        repair_dispositions_sha256=hashlib.sha256(b"{}").hexdigest(),
        repair_findings_sha256=hashlib.sha256(b"not-authorized").hexdigest(),
    )
    with pytest.raises(AXIS.AxisDispositionError):
        AXIS.validate_axis_repair_execution_receipt(
            forged,
            plan,
            expected_run_id=str(config["_run_id"]),
            repair_dispositions_raw=b"{}",
            repair_findings_raw=b"not-authorized",
        )


@pytest.mark.parametrize("stale_kind", ("plan", "run"))
def test_stale_signed_receipt_never_authorizes_live_repair_pair(
    tmp_path: Path,
    stale_kind: str,
) -> None:
    (
        _project,
        scratchpad,
        config,
        worklist,
        evidence,
        plan,
    ) = _plan_with_cap(tmp_path / stale_kind, cap=16)
    _valid_repair_outputs(scratchpad, worklist, plan)
    findings = (
        scratchpad / "axis_coverage_repair_findings.md"
    ).read_bytes()
    dispositions = (
        scratchpad / "axis_coverage_repair_dispositions.json"
    ).read_bytes()
    receipt = AXIS.build_axis_repair_execution_receipt(
        plan,
        state="EXECUTED",
        repair_dispositions_raw=dispositions,
        repair_findings_raw=findings,
    )
    if stale_kind == "plan":
        current = _replace_plan(
            scratchpad=scratchpad,
            worklist=worklist,
            evidence=evidence,
            base_findings_raw=(
                scratchpad / "axis_coverage_findings.md"
            ).read_bytes(),
            base_dispositions_raw=(
                scratchpad / "axis_coverage_dispositions.json"
            ).read_bytes(),
            cap=0,
        )
        assert current["plan_digest"] != receipt["repair_plan_digest"]
    else:
        receipt = _resign(receipt, run_id="run-stale-signed")
        assert receipt["run_id"] != str(config["_run_id"])
    _write_receipt(scratchpad, receipt)

    assert DRIVER._axis_authorized_repair_inputs(scratchpad) == ()


@pytest.mark.parametrize("backend", ("claude", "codex"))
def test_current_accepted_pair_is_explicit_in_terminal_denominator(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    backend: str,
) -> None:
    (
        _project,
        scratchpad,
        config,
        worklist,
        _evidence,
        plan,
    ) = _plan_with_cap(tmp_path / backend, cap=16)
    config["cli_backend"] = backend
    stale_failed = AXIS.build_axis_repair_execution_receipt(
        plan,
        state="FAILED",
        issues=("stale prior-attempt debt",),
    )
    _write_receipt(scratchpad, stale_failed)

    monkeypatch.setattr(
        DRIVER, "record_work_unit_inputs", lambda *_args, **_kwargs: None
    )
    monkeypatch.setattr(
        DRIVER, "record_work_unit_artifacts", lambda *_args, **_kwargs: None
    )
    monkeypatch.setattr(
        DRIVER, "validate_work_unit_inputs", lambda *_args, **_kwargs: []
    )
    monkeypatch.setattr(
        DRIVER,
        "validate_work_unit_artifacts",
        _missing_then_clean_artifacts(),
    )
    observed: list[set[str]] = []

    def arm(**kwargs: Any) -> tuple[bool, list[str]]:
        contract = kwargs["contract"]
        if str(contract.key).endswith("/repair.execution"):
            observed.append({
                str(identity).split(":", 1)[-1]
                for identity in contract.immutable_inputs
            })
        return True, []

    monkeypatch.setattr(
        DRIVER, "_arm_deterministic_driver_work_unit", arm
    )
    monkeypatch.setattr(
        DRIVER,
        "_commit_deterministic_driver_work_unit",
        lambda **_kwargs: [],
    )

    def worker(**kwargs: Any) -> int:
        _valid_repair_outputs(Path(kwargs["scratchpad"]), worklist, plan)
        return 0

    monkeypatch.setattr(DRIVER, "_run_one_codex_exec", worker)
    monkeypatch.setattr(
        DRIVER, "_run_one_claude_headless_breadth_worker", worker
    )

    receipt, issues = DRIVER._run_axis_disposition_repair(
        phase=_axis_phase(),
        config=config,
        scratchpad=scratchpad,
        repair_plan=plan,
    )

    assert receipt["state"] == "EXECUTED"
    assert issues == []
    assert observed
    assert PAIR <= observed[-1]


@pytest.mark.parametrize("backend", ("claude", "codex"))
@pytest.mark.parametrize("retained", (False, True))
def test_arm_false_with_debt_writes_current_signed_failed_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    backend: str,
    retained: bool,
) -> None:
    (
        _project,
        scratchpad,
        config,
        worklist,
        _evidence,
        plan,
    ) = _plan_with_cap(
        tmp_path / backend / str(retained),
        cap=16 if retained else 0,
    )
    config["cli_backend"] = backend
    monkeypatch.setattr(
        DRIVER, "record_work_unit_inputs", lambda *_args, **_kwargs: None
    )
    monkeypatch.setattr(
        DRIVER, "record_work_unit_artifacts", lambda *_args, **_kwargs: None
    )
    monkeypatch.setattr(
        DRIVER, "validate_work_unit_inputs", lambda *_args, **_kwargs: []
    )
    monkeypatch.setattr(
        DRIVER,
        "validate_work_unit_artifacts",
        _missing_then_clean_artifacts(),
    )

    def arm(**kwargs: Any) -> tuple[bool, list[str]]:
        if str(kwargs["contract"].key).endswith("/repair.execution"):
            return False, ["fixture terminal arm debt"]
        return True, []

    monkeypatch.setattr(
        DRIVER, "_arm_deterministic_driver_work_unit", arm
    )
    monkeypatch.setattr(
        DRIVER,
        "_commit_deterministic_driver_work_unit",
        lambda **_kwargs: [],
    )

    def worker(**kwargs: Any) -> int:
        _valid_repair_outputs(Path(kwargs["scratchpad"]), worklist, plan)
        return 0

    monkeypatch.setattr(DRIVER, "_run_one_codex_exec", worker)
    monkeypatch.setattr(
        DRIVER, "_run_one_claude_headless_breadth_worker", worker
    )

    receipt, issues = DRIVER._run_axis_disposition_repair(
        phase=_axis_phase(),
        config=config,
        scratchpad=scratchpad,
        repair_plan=plan,
    )

    assert receipt["state"] == "FAILED"
    assert receipt["worker_executed"] is False
    assert receipt["run_id"] == str(config["_run_id"])
    assert receipt["repair_plan_digest"] == plan["plan_digest"]
    assert "fixture terminal arm debt" in receipt["issues"]
    assert "fixture terminal arm debt" in issues
    assert DRIVER._axis_authorized_repair_inputs(scratchpad) == ()
    assert (
        DRIVER._axis_validate_repair_execution_receipt_signature(receipt)
        == receipt
    )
    assert AXIS.validate_axis_repair_execution_receipt(
        receipt,
        plan,
        expected_run_id=str(config["_run_id"]),
    ) == receipt


@pytest.mark.parametrize("retained", (False, True))
def test_double_prebind_failure_still_writes_schema_valid_debt_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    retained: bool,
) -> None:
    (
        _project,
        scratchpad,
        config,
        _worklist,
        _evidence,
        plan,
    ) = _plan_with_cap(tmp_path / str(retained), cap=16 if retained else 0)
    monkeypatch.setattr(
        DRIVER,
        "_arm_deterministic_driver_work_unit",
        lambda **_kwargs: (_ for _ in ()).throw(
            OSError("fixture first prebind failure")
        ),
    )
    monkeypatch.setattr(
        DRIVER,
        "record_work_unit_inputs",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            OSError("fixture fallback prebind failure")
        ),
    )
    monkeypatch.setattr(
        DRIVER,
        "_commit_deterministic_driver_work_unit",
        lambda **_kwargs: [],
    )

    receipt, issues = DRIVER._run_axis_disposition_repair(
        phase=_axis_phase(),
        config=config,
        scratchpad=scratchpad,
        repair_plan=plan,
    )

    assert receipt["state"] == "FAILED"
    assert receipt["worker_executed"] is False
    assert receipt["run_id"] == str(config["_run_id"])
    assert receipt["repair_plan_digest"] == plan["plan_digest"]
    assert any("first prebind failure" in issue for issue in issues)
    assert any("fallback prebind failure" in issue for issue in issues)
    assert receipt["issues"] == issues
    assert (
        DRIVER._axis_validate_repair_execution_receipt_signature(receipt)
        == receipt
    )
    assert AXIS.validate_axis_repair_execution_receipt(
        receipt,
        plan,
        expected_run_id=str(config["_run_id"]),
    ) == receipt
