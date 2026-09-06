"""RED-only P0-I specifications for the bounded repair model runtime.

These tests isolate the repair worker's supervisor boundary.  No real model,
subprocess, network request, install, audit, or production file is touched.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Mapping

import pytest

import axis_disposition as AXIS
import plamen_driver as DRIVER
from test_axis_repair_promotion_fault_red_p0_i import (
    _action,
    _axis_phase,
    _seed_base,
)


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _valid_repair_outputs(
    scratchpad: Path,
    worklist: Mapping[str, Any],
    plan: Mapping[str, Any],
) -> None:
    by_id = {
        str(item["work_item_id"]): item for item in worklist["items"]
    }
    retained = [str(value) for value in plan["retained_work_item_ids"]]
    rows = [
        {
            "work_item_id": identity,
            "disposition": "FINDING",
            "action_id": by_id[identity]["required_action_id"],
            "evidence": [],
            "rationale": "bounded repair candidate requires verification",
        }
        for identity in retained
    ]
    unsigned = {
        "schema_version": AXIS.REPAIR_MODEL_DISPOSITIONS_SCHEMA,
        "run_id": worklist["run_id"],
        "worklist_hash": worklist["worklist_hash"],
        "repair_plan_digest": plan["plan_digest"],
        "producer": "MODEL",
        "items": rows,
    }
    sidecar = {
        **unsigned,
        "sidecar_digest": hashlib.sha256(_canonical(unsigned)).hexdigest(),
    }
    (scratchpad / "axis_coverage_repair_dispositions.json").write_bytes(
        _canonical(sidecar)
    )
    (scratchpad / "axis_coverage_repair_findings.md").write_text(
        "".join(_action(by_id[identity]) for identity in retained),
        encoding="utf-8",
    )


def _install_ledger_seam(
    monkeypatch: pytest.MonkeyPatch,
    *,
    input_issues: Any,
    artifact_issues: Any,
) -> None:
    monkeypatch.setattr(
        DRIVER, "record_work_unit_inputs", lambda *_args, **_kwargs: None
    )
    monkeypatch.setattr(
        DRIVER, "record_work_unit_artifacts", lambda *_args, **_kwargs: None
    )
    monkeypatch.setattr(DRIVER, "validate_work_unit_inputs", input_issues)
    monkeypatch.setattr(DRIVER, "validate_work_unit_artifacts", artifact_issues)
    monkeypatch.setattr(
        DRIVER,
        "_arm_deterministic_driver_work_unit",
        lambda **_kwargs: (True, []),
    )
    monkeypatch.setattr(
        DRIVER,
        "_commit_deterministic_driver_work_unit",
        lambda **_kwargs: [],
    )


def _missing_then_clean_artifacts() -> Any:
    calls = 0

    def validate(*_args: Any, **_kwargs: Any) -> list[str]:
        nonlocal calls
        calls += 1
        return ["repair outputs are not committed"] if calls == 1 else []

    return validate


def _forbid_model_launches(
    monkeypatch: pytest.MonkeyPatch,
) -> list[str]:
    calls: list[str] = []

    def forbidden(*_args: Any, **kwargs: Any) -> int:
        calls.append(
            str(
                kwargs.get("label")
                or kwargs.get("label_prefix")
                or "model"
            )
        )
        raise AssertionError(
            "the committed repair transaction must resume without relaunch"
        )

    monkeypatch.setattr(DRIVER, "_run_one_codex_exec", forbidden)
    monkeypatch.setattr(
        DRIVER, "_run_one_claude_headless_breadth_worker", forbidden
    )
    return calls


def test_repair_worker_mutates_only_disposable_copy_of_immutable_input(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (
        _project,
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

    def validate_inputs(*_args: Any, **_kwargs: Any) -> list[str]:
        return (
            []
            if plan_path.is_file() and plan_path.read_bytes() == before
            else ["repair worker mutated immutable input axis_repair_plan.json"]
        )

    _install_ledger_seam(
        monkeypatch,
        input_issues=validate_inputs,
        artifact_issues=_missing_then_clean_artifacts(),
    )
    monkeypatch.setattr(
        DRIVER,
        "_axis_repair_restore_immutable_inputs",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError(
                "disposable worker isolation must not rely on live rollback"
            )
        ),
    )

    stages: list[Path] = []

    def worker(**kwargs: Any) -> int:
        stage = Path(kwargs["scratchpad"])
        stages.append(stage)
        assert stage.resolve() != scratchpad.resolve()
        _valid_repair_outputs(stage, worklist, plan)
        (stage / plan_path.name).write_text(
            "model-corruption",
            encoding="utf-8",
        )
        return 0

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
    assert plan_path.read_bytes() == before
    assert stages and all(not stage.exists() for stage in stages)


def test_repair_worker_deletes_only_disposable_copy_of_immutable_input(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (
        _project,
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

    def validate_inputs(*_args: Any, **_kwargs: Any) -> list[str]:
        return (
            []
            if plan_path.is_file() and plan_path.read_bytes() == before
            else ["repair worker deleted immutable input axis_repair_plan.json"]
        )

    _install_ledger_seam(
        monkeypatch,
        input_issues=validate_inputs,
        artifact_issues=_missing_then_clean_artifacts(),
    )
    monkeypatch.setattr(
        DRIVER,
        "_axis_repair_restore_immutable_inputs",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError(
                "disposable worker isolation must not rely on live rollback"
            )
        ),
    )

    stages: list[Path] = []

    def worker(**kwargs: Any) -> int:
        stage = Path(kwargs["scratchpad"])
        stages.append(stage)
        assert stage.resolve() != scratchpad.resolve()
        _valid_repair_outputs(stage, worklist, plan)
        (stage / plan_path.name).unlink()
        return 0

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
    assert plan_path.read_bytes() == before
    assert stages and all(not stage.exists() for stage in stages)


def test_repair_worker_rejects_foreign_staged_output_and_deletes_stage(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (
        _project,
        scratchpad,
        config,
        worklist,
        _evidence,
        _base_findings,
        _base_dispositions,
    ) = _seed_base(tmp_path, omit_after_first=True)
    plan = json.loads(
        (scratchpad / "axis_repair_plan.json").read_text(encoding="utf-8")
    )
    _install_ledger_seam(
        monkeypatch,
        input_issues=lambda *_args, **_kwargs: [],
        artifact_issues=_missing_then_clean_artifacts(),
    )
    foreign_name = "unowned_axis_repair_output.md"
    stages: list[Path] = []

    def worker(**kwargs: Any) -> int:
        stage = Path(kwargs["scratchpad"])
        stages.append(stage)
        assert stage.resolve() != scratchpad.resolve()
        _valid_repair_outputs(stage, worklist, plan)
        (stage / foreign_name).write_text(
            "foreign model write",
            encoding="utf-8",
        )
        return 0

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
    assert any("containment" in issue.casefold() for issue in issues)
    assert not (scratchpad / foreign_name).exists()
    assert stages and all(not stage.exists() for stage in stages)
    assert not any(
        path.name == foreign_name
        for path in (scratchpad / "_quarantine").rglob(foreign_name)
    ), "foreign staged bytes must disappear with the stage, not enter live quarantine"


def test_nonempty_but_semantically_invalid_repair_pair_is_not_executed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (
        _project,
        scratchpad,
        config,
        _worklist,
        _evidence,
        _base_findings,
        _base_dispositions,
    ) = _seed_base(tmp_path, omit_after_first=True)
    plan = json.loads(
        (scratchpad / "axis_repair_plan.json").read_text(encoding="utf-8")
    )
    _install_ledger_seam(
        monkeypatch,
        input_issues=lambda *_args, **_kwargs: [],
        artifact_issues=_missing_then_clean_artifacts(),
    )

    def worker(**kwargs: Any) -> int:
        stage = Path(kwargs["scratchpad"])
        (stage / "axis_coverage_repair_findings.md").write_text(
            "not a finding block", encoding="utf-8"
        )
        (stage / "axis_coverage_repair_dispositions.json").write_text(
            "{}", encoding="utf-8"
        )
        return 0

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
    assert any(
        token in " ".join(issues).casefold()
        for token in ("semantic", "schema", "disposition", "finding")
    )


def test_partial_repair_residue_still_commits_a_haltless_failed_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (
        _project,
        scratchpad,
        config,
        _worklist,
        _evidence,
        _base_findings,
        _base_dispositions,
    ) = _seed_base(tmp_path, omit_after_first=True)
    plan = json.loads(
        (scratchpad / "axis_repair_plan.json").read_text(encoding="utf-8")
    )
    _install_ledger_seam(
        monkeypatch,
        input_issues=lambda *_args, **_kwargs: [],
        artifact_issues=lambda *_args, **_kwargs: [
            "paired repair outputs are incomplete"
        ],
    )

    def worker(**kwargs: Any) -> int:
        stage = Path(kwargs["scratchpad"])
        (stage / "axis_coverage_repair_findings.md").write_text(
            "partial residue", encoding="utf-8"
        )
        return 0

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
    assert issues
    assert (
        scratchpad / "axis_repair_execution_receipt.json"
    ).is_file()
    assert not (
        scratchpad / "axis_coverage_repair_findings.md"
    ).exists()


def test_precommit_crash_residue_is_never_retroactively_blessed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (
        _project,
        scratchpad,
        config,
        worklist,
        _evidence,
        _base_findings,
        _base_dispositions,
    ) = _seed_base(tmp_path, omit_after_first=True)
    plan = json.loads(
        (scratchpad / "axis_repair_plan.json").read_text(encoding="utf-8")
    )
    _valid_repair_outputs(scratchpad, worklist, plan)
    dispositions_path = (
        scratchpad / "axis_coverage_repair_dispositions.json"
    )
    stale_sidecar = json.loads(
        dispositions_path.read_text(encoding="utf-8")
    )
    stale_sidecar["items"][0]["rationale"] = (
        "valid bytes left by a crashed, uncommitted model process"
    )
    unsigned = {
        key: value
        for key, value in stale_sidecar.items()
        if key != "sidecar_digest"
    }
    stale_sidecar["sidecar_digest"] = hashlib.sha256(
        _canonical(unsigned)
    ).hexdigest()
    dispositions_path.write_bytes(_canonical(stale_sidecar))
    stale_pair = {
        "axis_coverage_repair_findings.md": (
            scratchpad / "axis_coverage_repair_findings.md"
        ).read_bytes(),
        "axis_coverage_repair_dispositions.json": (
            dispositions_path.read_bytes()
        ),
    }

    units: list[str] = []
    launches: list[str] = []
    recorded_artifacts: set[str] = set()
    original_contract = DRIVER._axis_disposition_contract_and_launch

    def contract_and_launch(**kwargs: Any) -> Any:
        units.append(str(kwargs["work_unit_id"]))
        return original_contract(**kwargs)

    def record_inputs(
        _root: Path,
        _project: Path,
        contract: Any,
        _launch: Any,
        **_kwargs: Any,
    ) -> None:
        if str(contract.key).endswith("/repair.worker.0001"):
            raise DRIVER.ArtifactLedgerError(
                "uncommitted repair.worker.0001 output prestate drift"
            )

    def validate_artifacts(
        _root: Path,
        _project: Path,
        contract: Any,
        _launch: Any,
        **_kwargs: Any,
    ) -> list[str]:
        key = str(contract.key)
        if key.endswith("/repair.worker.0001"):
            return ["repair.worker.0001 has no committed MODEL artifacts"]
        if key.endswith("/repair.worker.0002") and key not in recorded_artifacts:
            return ["repair.worker.0002 MODEL artifacts are not committed"]
        return []

    def record_artifacts(
        _root: Path,
        _project: Path,
        contract: Any,
        _launch: Any,
        **_kwargs: Any,
    ) -> None:
        recorded_artifacts.add(str(contract.key))

    def bounded_retry(**kwargs: Any) -> int:
        label = str(
            kwargs.get("label")
            or kwargs.get("label_prefix")
            or "model"
        )
        launches.append(label)
        assert "0002" in label
        assert not any(
            (scratchpad / name).exists() for name in stale_pair
        ), "stale repair.worker.0001 bytes must be quarantined before retry"
        _valid_repair_outputs(
            Path(kwargs["scratchpad"]),
            worklist,
            plan,
        )
        return 0

    monkeypatch.setattr(
        DRIVER,
        "_axis_disposition_contract_and_launch",
        contract_and_launch,
    )
    monkeypatch.setattr(
        DRIVER,
        "validate_work_unit_inputs",
        lambda *_args, **_kwargs: [],
    )
    monkeypatch.setattr(
        DRIVER, "validate_work_unit_artifacts", validate_artifacts
    )
    monkeypatch.setattr(DRIVER, "record_work_unit_inputs", record_inputs)
    monkeypatch.setattr(
        DRIVER, "record_work_unit_artifacts", record_artifacts
    )
    monkeypatch.setattr(
        DRIVER,
        "_arm_deterministic_driver_work_unit",
        lambda **_kwargs: (True, []),
    )
    monkeypatch.setattr(
        DRIVER,
        "_commit_deterministic_driver_work_unit",
        lambda **_kwargs: [],
    )
    monkeypatch.setattr(DRIVER, "_run_one_codex_exec", bounded_retry)
    monkeypatch.setattr(
        DRIVER, "_run_one_claude_headless_breadth_worker", bounded_retry
    )

    receipt, issues = DRIVER._run_axis_disposition_repair(
        phase=_axis_phase(),
        config=config,
        scratchpad=scratchpad,
        repair_plan=plan,
    )

    assert len(launches) <= 1
    assert not any("0001" in label for label in launches)
    quarantine = scratchpad / "_quarantine" / "axis_repair"
    for name, raw in stale_pair.items():
        assert any(
            candidate.read_bytes() == raw
            for candidate in quarantine.rglob(Path(name).name)
        ), f"precommit residue {name} was not retained in quarantine"
    if receipt["state"] in {"EXECUTED", "OVERFLOW"}:
        assert launches
        assert "repair.worker.0002" in units
    else:
        assert receipt["state"] == "FAILED"
        assert issues
        assert (
            scratchpad / "axis_repair_execution_receipt.json"
        ).is_file()


def test_committed_model_pair_without_execution_receipt_resumes_without_relaunch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (
        _project,
        scratchpad,
        config,
        worklist,
        _evidence,
        _base_findings,
        _base_dispositions,
    ) = _seed_base(tmp_path, omit_after_first=True)
    plan = json.loads(
        (scratchpad / "axis_repair_plan.json").read_text(encoding="utf-8")
    )
    _valid_repair_outputs(scratchpad, worklist, plan)
    _install_ledger_seam(
        monkeypatch,
        input_issues=lambda *_args, **_kwargs: [],
        artifact_issues=lambda *_args, **_kwargs: [],
    )
    launches = _forbid_model_launches(monkeypatch)

    receipt, issues = DRIVER._run_axis_disposition_repair(
        phase=_axis_phase(),
        config=config,
        scratchpad=scratchpad,
        repair_plan=plan,
    )

    assert launches == []
    assert issues == []
    assert receipt["state"] == "EXECUTED"
    stored = json.loads(
        (scratchpad / "axis_repair_execution_receipt.json").read_text(
            encoding="utf-8"
        )
    )
    assert stored == receipt


def test_execution_receipt_before_final_reconciliation_replays_deterministically(
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
        _base_dispositions,
    ) = _seed_base(tmp_path, omit_after_first=True)
    plan = json.loads(
        (scratchpad / "axis_repair_plan.json").read_text(encoding="utf-8")
    )
    initial = json.loads(
        (
            scratchpad / "axis_disposition_initial_receipt.json"
        ).read_text(encoding="utf-8")
    )
    _valid_repair_outputs(scratchpad, worklist, plan)
    repair_findings = (
        scratchpad / "axis_coverage_repair_findings.md"
    ).read_bytes()
    repair_dispositions = (
        scratchpad / "axis_coverage_repair_dispositions.json"
    ).read_bytes()
    execution = AXIS.build_axis_repair_execution_receipt(
        plan,
        state="EXECUTED",
        repair_dispositions_raw=repair_dispositions,
        repair_findings_raw=repair_findings,
        issues=(),
    )
    AXIS.write_axis_disposition_v2_artifacts(
        scratchpad,
        repair_execution_receipt=execution,
    )
    execution_before = (
        scratchpad / "axis_repair_execution_receipt.json"
    ).read_bytes()

    monkeypatch.setattr(
        DRIVER,
        "_reconcile_axis_dispositions",
        lambda **_kwargs: (initial, plan, []),
    )
    monkeypatch.setattr(
        DRIVER,
        "_load_axis_canonical_prior",
        lambda *_args, **_kwargs: SimpleNamespace(
            aliases={},
            authority_digest=str(
                config["_fixture_axis_prior_digest"]
            ),
        ),
    )
    monkeypatch.setattr(
        DRIVER,
        "validate_work_unit_inputs",
        lambda *_args, **_kwargs: [],
    )
    monkeypatch.setattr(
        DRIVER,
        "validate_work_unit_artifacts",
        lambda *_args, **_kwargs: [],
    )
    monkeypatch.setattr(
        DRIVER,
        "record_work_unit_inputs",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("committed MODEL inputs must not be rebound")
        ),
    )
    monkeypatch.setattr(
        DRIVER,
        "record_work_unit_artifacts",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("committed MODEL outputs must not be recommitted")
        ),
    )
    launches = _forbid_model_launches(monkeypatch)
    committed = {"repair.execution"}

    def arm(**kwargs: Any) -> tuple[bool, list[str]]:
        unit = str(kwargs["contract"].key).rsplit("/", 1)[-1]
        return (unit not in committed, [])

    def commit(**kwargs: Any) -> list[str]:
        committed.add(
            str(kwargs["contract"].key).rsplit("/", 1)[-1]
        )
        return []

    monkeypatch.setattr(
        DRIVER, "_arm_deterministic_driver_work_unit", arm
    )
    monkeypatch.setattr(
        DRIVER, "_commit_deterministic_driver_work_unit", commit
    )
    monkeypatch.setattr(
        DRIVER,
        "_promote_axis_disposition_actions",
        lambda **_kwargs: ({"status": "COMPLETE"}, []),
    )

    first, first_issues = DRIVER._finalize_axis_coverage_boundary(
        phase=_axis_phase(),
        config=config,
        scratchpad=scratchpad,
    )
    final_before = (
        scratchpad / "axis_disposition_receipt.json"
    ).read_bytes()
    second, second_issues = DRIVER._finalize_axis_coverage_boundary(
        phase=_axis_phase(),
        config=config,
        scratchpad=scratchpad,
    )

    assert launches == []
    assert first_issues == []
    assert second_issues == []
    assert first == second
    assert first["run_id"] == worklist["run_id"]
    assert (
        scratchpad / "axis_repair_execution_receipt.json"
    ).read_bytes() == execution_before
    assert (
        scratchpad / "axis_disposition_receipt.json"
    ).read_bytes() == final_before
    assert "reconcile.final" in committed
    assert evidence["run_id"] == worklist["run_id"]
    assert base_findings


@pytest.mark.parametrize("backend", ("claude", "codex"))
def test_repair_prompt_carries_the_exact_phaseio_contract_on_both_backends(
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
        _base_findings,
        _base_dispositions,
    ) = _seed_base(tmp_path / backend, omit_after_first=True)
    config["cli_backend"] = backend
    plan = json.loads(
        (scratchpad / "axis_repair_plan.json").read_text(encoding="utf-8")
    )
    _install_ledger_seam(
        monkeypatch,
        input_issues=lambda *_args, **_kwargs: [],
        artifact_issues=_missing_then_clean_artifacts(),
    )
    observed: dict[str, Any] = {}

    def worker(**kwargs: Any) -> int:
        observed.update(kwargs)
        _valid_repair_outputs(
            Path(kwargs["scratchpad"]),
            worklist,
            plan,
        )
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
    prompt = str(observed["prompt"])
    assert "<!-- PLAMEN_PHASE_IO_CONTRACT_BEGIN -->" in prompt
    assert "axis_coverage_repair_findings.md" in prompt
    assert "axis_coverage_repair_dispositions.json" in prompt
    assert "axis_repair_plan.json" in prompt
