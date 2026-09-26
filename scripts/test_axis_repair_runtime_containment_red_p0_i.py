"""RED-only P0-I specifications for the bounded repair model runtime.

These tests isolate the repair worker's supervisor boundary.  No real model,
subprocess, network request, install, audit, or production file is touched.
"""
from __future__ import annotations

import hashlib
import json
import os
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
            "invariant_commitment": None,
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


def test_axis_repair_timeout_uses_scaled_phase_budget_for_large_worklist(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = tmp_path / "project"
    scratchpad = project / ".scratchpad"
    scratchpad.mkdir(parents=True)
    (scratchpad / "axis_repair_plan.json").write_text(
        json.dumps({
            "retained_count": 396,
            "retained_work_item_ids": [f"AXW-{index:04d}" for index in range(396)],
        }),
        encoding="utf-8",
    )
    observed: dict[str, Any] = {}

    def scaled(base: int, project_root: str, language: str, **kwargs: Any) -> int:
        observed.update({
            "base": base,
            "project_root": project_root,
            "language": language,
            **kwargs,
        })
        return 21_600

    monkeypatch.setattr(DRIVER, "scale_timeout", scaled)
    timeout = DRIVER._axis_repair_timeout_seconds(
        phase=SimpleNamespace(base_timeout_s=3_600),
        config={
            "project_root": str(project),
            "language": "evm",
            "mode": "thorough",
            "cli_backend": "codex",
        },
        scratchpad=scratchpad,
    )

    assert timeout == 21_600
    assert observed["base"] == 3_600
    assert observed["hypothesis_count"] == 396
    assert observed["backend"] == "codex"


def test_axis_repair_timeout_never_falls_below_phase_base_or_exceeds_cap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = tmp_path / "project"
    scratchpad = project / ".scratchpad"
    scratchpad.mkdir(parents=True)
    (scratchpad / "axis_repair_plan.json").write_text(
        '{"retained_count":1,"retained_work_item_ids":["AXW-1"]}',
        encoding="utf-8",
    )
    monkeypatch.setattr(DRIVER, "scale_timeout", lambda *_args, **_kwargs: 60)
    common = {
        "project_root": str(project),
        "language": "evm",
        "mode": "thorough",
        "cli_backend": "codex",
    }
    assert DRIVER._axis_repair_timeout_seconds(
        phase=SimpleNamespace(base_timeout_s=3_600),
        config={**common, "axis_repair_timeout_s": 120},
        scratchpad=scratchpad,
    ) == 3_600
    assert DRIVER._axis_repair_timeout_seconds(
        phase=SimpleNamespace(base_timeout_s=3_600),
        config={**common, "axis_repair_timeout_s": 99_999},
        scratchpad=scratchpad,
    ) == 21_600


def test_axis_repair_runtime_admits_exact_provider_prompt_name_only() -> None:
    assert DRIVER._axis_repair_runtime_allowed(
        "_provider_prompt_axis_repair_worker_0001.attempt1.md"
    )
    assert not DRIVER._axis_repair_runtime_allowed(
        "_provider_prompt_axis_repair_worker_0001.attempt2.md"
    )


def _seed_axis_compat_runtime_footprint(
    tmp_path: Path,
) -> tuple[Path, dict[str, Any], Any, Any, str, Any, dict[str, Any]]:
    stage = tmp_path / "stage"
    project = stage / "project"
    scratchpad = stage / "scratchpad"
    project.mkdir(parents=True)
    scratchpad.mkdir()
    stage.chmod(0o700)
    private = scratchpad / ".posix_v2_compat_private"
    receipts = scratchpad / ".posix_v2_compat_receipts"
    private.mkdir(mode=0o700)
    receipts.mkdir(mode=0o700)
    run_id = "run-axis-compat"
    label = "axis_repair_worker_0001"
    prompt = "bounded repair prompt"
    prompt_raw = prompt.encode()
    provider_prompt_raw = b"provider-effective bounded repair prompt"
    log_raw = b"provider stdout"
    output_last_raw = b"done\n"
    (scratchpad / f"_prompt_{label}.attempt1.md").write_bytes(prompt_raw)
    (scratchpad / f"_provider_prompt_{label}.attempt1.md").write_bytes(
        provider_prompt_raw
    )
    (scratchpad / f"_stdio_{label}.attempt1.log").write_bytes(log_raw)
    (scratchpad / f"_codex_output_{label}.attempt1.md").write_bytes(
        output_last_raw
    )
    output_names = (
        "axis_coverage_repair_findings.md",
        "axis_coverage_repair_dispositions.json",
    )
    for name in output_names:
        (scratchpad / name).write_bytes((name + "\n").encode())
    contract = SimpleNamespace(
        key="sc/thorough/evm/codex/axis_coverage/repair.worker.0001",
        phase="axis_coverage",
        backend="codex",
        digest="1" * 64,
        immutable_inputs=(),
        bounded_lookup_inputs=(),
        outputs=tuple(
            SimpleNamespace(identity=f"scratchpad:{name}", write_mode="REPLACE")
            for name in output_names
        ),
    )
    launch = SimpleNamespace(model="gpt-test", digest="2" * 64)
    prestates = {
        f"scratchpad:{name}": {
            "status": "ABSENT",
            "existed": False,
            "sha256": "",
            "size": 0,
        }
        for name in output_names
    }
    unit = {
        "input_set_digest": "3" * 64,
        "output_prestate_digest": "4" * 64,
        "input_bindings": {},
        "output_prestates": prestates,
    }
    binding = {
        "schema": "plamen.posix_v2_compat_derived_staging_session.v1",
        "mode": "V2_COMPATIBILITY_REDUCED_ISOLATION",
        "purpose": "AXIS_DISPOSABLE_STAGING",
        "run_id": run_id,
        "backend": "codex",
        "parent_session_binding_sha256": "5" * 64,
        "staging_root": str(stage.resolve()),
        "staging_root_identity_sha256": "6" * 64,
        "project_root": str(project.resolve()),
        "project_root_identity_sha256": "7" * 64,
        "scratchpad": str(scratchpad.resolve()),
        "scratchpad_identity_sha256": "8" * 64,
        "writable_namespace": str(scratchpad.resolve()),
        "creator_pid": os.getpid(),
        "interpreter_nonce_sha256": "9" * 64,
        "native_broker_authority": False,
        "wer_authority": False,
        "population_zero_proven": False,
    }
    binding["session_binding_sha256"] = hashlib.sha256(
        _canonical(binding)
    ).hexdigest()
    session = SimpleNamespace(binding=binding)
    invocation_id = "a" * 32
    input_routes: list[dict[str, Any]] = []
    output_routes = []
    evidence = []
    for name in output_names:
        identity = f"scratchpad:{name}"
        output_routes.append({
            "identity": identity,
            "path": str(
                (
                    private / invocation_id / "staged-output" / name
                ).resolve(strict=False)
            ),
            "canonical_path": str((scratchpad / name).resolve()),
            "write_mode": "REPLACE",
            "prestate_status": "ABSENT",
            "prestate_existed": False,
            "prestate_sha256": "",
            "prestate_size": 0,
        })
        raw = (scratchpad / name).read_bytes()
        evidence.append({
            "path": str((scratchpad / name).resolve()),
            "sha256": hashlib.sha256(raw).hexdigest(),
            "size": len(raw),
        })
    routing = {
        "schema": "plamen.posix_v2_codex_local_phaseio.v1",
        "project_source_root": str(project.resolve()),
        "project_source_access": "READ_ONLY_BY_INSTRUCTION",
        "input_routes": input_routes,
        "output_routes": output_routes,
        "codex_working_directory": str(scratchpad.resolve()),
    }
    receipt = {
        "schema": "plamen.posix_v2_compat_execution_receipt.v1",
        "mode": "V2_COMPATIBILITY_REDUCED_ISOLATION",
        "status": "COMPLETED",
        "failure_code": None,
        "run_id": run_id,
        "phase": "axis_coverage",
        "label": label,
        "attempt": 1,
        "invocation_id": invocation_id,
        "session_binding_sha256": binding["session_binding_sha256"],
        "backend": "codex",
        "requested_model": "gpt-test",
        "model_binding": "EXPLICIT_CLI_ARGUMENT",
        "observed_model": None,
        "model_observation": "NOT_OBSERVED",
        "provider_event_profile": None,
        "methodology_prompt_sha256": hashlib.sha256(prompt_raw).hexdigest(),
        "methodology_prompt_size": len(prompt_raw),
        "provider_effective_prompt_sha256": hashlib.sha256(
            provider_prompt_raw
        ).hexdigest(),
        "provider_effective_prompt_size": len(provider_prompt_raw),
        "phase_io_contract_digest": contract.digest,
        "phase_io_launch_digest": launch.digest,
        "phase_io_input_set_digest": unit["input_set_digest"],
        "phase_io_output_prestate_digest": unit["output_prestate_digest"],
        "phase_io_input_routes_digest": hashlib.sha256(
            _canonical({"routes": input_routes})
        ).hexdigest(),
        "phase_io_output_routes_digest": hashlib.sha256(
            _canonical({"routes": output_routes})
        ).hexdigest(),
        "phase_io_routing_digest": hashlib.sha256(_canonical(routing)).hexdigest(),
        "phase_io_input_routes": input_routes,
        "phase_io_output_routes": output_routes,
        "prompt_sha256": hashlib.sha256(prompt_raw).hexdigest(),
        "prompt_size": len(prompt_raw),
        "completed_output_evidence": evidence,
        "isolation": {
            "native_broker_authority": False,
            "wer_authority": False,
            "dangerous_bypass_requested": False,
        },
        "returncode": 0,
        "compatibility_return_value": 0,
        "timed_out": False,
        "overflowed_stream": None,
        "stdout_sha256": hashlib.sha256(log_raw).hexdigest(),
        "stdout_size": len(log_raw),
        "stderr_sha256": hashlib.sha256(b"").hexdigest(),
        "stderr_size": 0,
        "output_last_message_sha256": hashlib.sha256(
            output_last_raw
        ).hexdigest(),
        "output_last_message_size": len(output_last_raw),
    }
    receipt["receipt_sha256"] = hashlib.sha256(_canonical(receipt)).hexdigest()
    receipt_path = receipts / (
        f"axis_coverage.{label}.attempt1.{invocation_id}.json"
    )
    receipt_path.write_bytes(_canonical(receipt) + b"\n")
    config = {
        "_run_id": run_id,
        "project_root": str(project.resolve()),
    }
    return scratchpad, config, contract, launch, prompt, session, unit


def _axis_compat_runtime_issues(
    seeded: tuple[Path, dict[str, Any], Any, Any, str, Any, dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
) -> list[str]:
    scratchpad, config, contract, launch, prompt, session, unit = seeded
    monkeypatch.setattr(
        DRIVER,
        "read_artifact_ledger",
        lambda _root: {"work_units": {contract.key: unit}},
    )
    return DRIVER._axis_repair_posix_compat_runtime_issues(
        scratchpad=scratchpad,
        config=config,
        contract=contract,
        launch=launch,
        prompt=prompt,
        session_authority=session,
        return_value=0,
    )


def test_axis_repair_compat_runtime_accepts_only_exact_control_footprint(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seeded = _seed_axis_compat_runtime_footprint(tmp_path)
    assert _axis_compat_runtime_issues(seeded, monkeypatch) == []


@pytest.mark.parametrize("mode", (None, "FOREIGN_MODE"))
def test_axis_repair_compat_runtime_requires_exact_session_mode(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: str | None,
) -> None:
    seeded = _seed_axis_compat_runtime_footprint(tmp_path)
    binding = dict(seeded[5].binding)
    if mode is None:
        binding.pop("mode")
    else:
        binding["mode"] = mode
    unsigned = {
        key: value for key, value in binding.items()
        if key != "session_binding_sha256"
    }
    binding["session_binding_sha256"] = hashlib.sha256(
        _canonical(unsigned)
    ).hexdigest()
    session = SimpleNamespace(binding=binding)
    mutated = (*seeded[:5], session, seeded[6])
    assert "axis repair compat staging session binding is foreign" in (
        _axis_compat_runtime_issues(mutated, monkeypatch)
    )


@pytest.mark.parametrize(
    "mutation",
    ("extra_receipt", "forged_receipt", "symlink_receipt", "nonempty_private"),
)
def test_axis_repair_compat_runtime_rejects_foreign_or_forged_control_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    seeded = _seed_axis_compat_runtime_footprint(tmp_path)
    scratchpad = seeded[0]
    receipt_root = scratchpad / ".posix_v2_compat_receipts"
    receipt_path = next(receipt_root.iterdir())
    if mutation == "extra_receipt":
        (receipt_root / "foreign.json").write_text("{}", encoding="utf-8")
    elif mutation == "forged_receipt":
        receipt = json.loads(receipt_path.read_text(encoding="ascii"))
        receipt["requested_model"] = "forged-model"
        receipt_path.write_bytes(_canonical(receipt) + b"\n")
    elif mutation == "symlink_receipt":
        target = tmp_path / "external-receipt.json"
        target.write_bytes(receipt_path.read_bytes())
        receipt_path.unlink()
        receipt_path.symlink_to(target)
    else:
        (scratchpad / ".posix_v2_compat_private" / "foreign").write_text(
            "foreign", encoding="utf-8"
        )
    assert _axis_compat_runtime_issues(seeded, monkeypatch)


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
    quarantine = scratchpad / "_quarantine" / "axis_repair"
    rejected = list(quarantine.glob("rejected-staged-*/quarantine_receipt.json"))
    assert len(rejected) == 1
    receipt_payload = json.loads(rejected[0].read_text(encoding="utf-8"))
    assert receipt_payload["schema_version"] == (
        "plamen.axis_repair_rejected_staged_pair.v1"
    )
    retained = rejected[0].parent
    assert (
        retained / "axis_coverage_repair_findings.md"
    ).read_text(encoding="utf-8") == "not a finding block"
    assert json.loads(
        (
            retained / "axis_coverage_repair_dispositions.json"
        ).read_text(encoding="utf-8")
    ) == {}


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
