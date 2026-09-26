"""Run20: DA iter2 reuses one persisted authority across every lifecycle seam."""
from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

import plamen_driver as D
from phase_attempt_plan import load_phase_attempt_plan, phase_attempt_plan_path


DA_JOB = {
    "agent_id": "depth-da-iter2",
    "role": "da_iter2",
    "output": "depth_da_iter2_findings.md",
    "category": "da",
    "focus": "adversarial second pass",
}
ORDINARY_JOB = {
    "agent_id": "depth-state-trace",
    "role": "state_trace",
    "output": "depth_state_trace_findings.md",
    "category": "standard",
    "focus": "state transitions",
}


def _phase() -> D.Phase:
    return next(item for item in D.SC_PHASES if item.name == "depth")


def test_da_iter2_freezes_once_and_reuses_plan_after_scratchpad_growth(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    config: dict[str, Any] = {
        "pipeline": "sc",
        "mode": "thorough",
        "language": "evm",
        "cli_backend": "codex",
        "scratchpad": str(scratchpad),
        "project_root": str(tmp_path),
        "_run_id": "run20-frozen-da-plan",
        "pty_continuation_budget": 3,
    }
    da_complete = False
    selector_calls = 0
    seen: dict[str, Any] = {}
    original_selector = D._typed_worker_registered_input_paths

    def selector(**kwargs: Any) -> tuple[str, ...]:
        nonlocal selector_calls
        selector_calls += 1
        return original_selector(**kwargs)

    monkeypatch.setattr(D, "_typed_worker_registered_input_paths", selector)
    monkeypatch.setattr(D, "_depth_worker_jobs", lambda *_a, **_k: [dict(ORDINARY_JOB)])
    monkeypatch.setattr(D, "_prepare_depth_fuzz_workspaces", lambda jobs, **_k: jobs)
    monkeypatch.setattr(
        D,
        "_depth_worker_output_complete",
        lambda _root, _phase, job, **_k: (
            str(job.get("output")) == ORDINARY_JOB["output"]
            or (str(job.get("output")) == DA_JOB["output"] and da_complete)
        ),
    )
    monkeypatch.setattr(D, "_depth_da_job_if_required", lambda *_a, **_k: [dict(DA_JOB)])

    def dispatch(**kwargs: Any) -> list[dict[str, Any]]:
        frozen = tuple(kwargs["exact_inputs_by_output"][DA_JOB["output"]])
        seen["prompt_inputs"] = frozen
        return [
            {"job": dict(job), "prompt": "bounded"}
            for job in kwargs["jobs"]
        ]

    monkeypatch.setattr(D, "_depth_dispatch_plan", dispatch)
    monkeypatch.setattr(D, "_write_depth_dispatch_contract", lambda *_a, **_k: None)
    monkeypatch.setattr(D, "_write_and_record_depth_da_dispatch_delta", lambda **_k: [])
    monkeypatch.setattr(D, "_quarantine_incomplete_depth_retry_output", lambda *_a, **_k: None)
    monkeypatch.setattr(D, "_canonicalize_depth_iter_filenames", lambda *_a, **_k: None)
    monkeypatch.setattr(D, "_finalize_depth_fuzz_result_authority", lambda **_k: None)
    monkeypatch.setattr(D, "_synthesize_depth_lifecycle_artifacts", lambda *_a, **_k: None)
    monkeypatch.setattr(D, "phase_model", lambda *_a, **_k: "gpt-5.6-sol")
    monkeypatch.setattr(D, "scale_timeout", lambda *_a, **_k: 211)

    def prepare(**kwargs: Any) -> list[str]:
        plan = kwargs["attempt_plan"]
        seen["prepare"] = plan
        # This optional DA input appears after planning. A live recomputation
        # would silently widen the denominator at launch or record time.
        (scratchpad / "skill_execution_gaps.md").write_text(
            "late post-plan file\n", encoding="utf-8"
        )
        return []

    def staged(**kwargs: Any) -> tuple[dict[str, Any], tuple[str, ...]]:
        seen["staged_inputs"] = tuple(kwargs["registered_inputs"])
        return {}, ()

    def launch(**kwargs: Any) -> int:
        nonlocal da_complete
        seen["launch_contract"] = kwargs["phase_io_contract"]
        seen["launch_spec"] = kwargs["phase_io_launch"]
        da_complete = True
        return 0

    def record(**kwargs: Any) -> list[str]:
        seen["record"] = kwargs["attempt_plan"]
        return []

    monkeypatch.setattr(D, "_prepare_typed_model_worker_launch", prepare)
    monkeypatch.setattr(D, "_compile_depth_worker_staged_gate_context", staged)
    monkeypatch.setattr(D, "_run_one_codex_exec", launch)
    monkeypatch.setattr(D, "_record_typed_model_worker_artifact", record)

    assert D._run_depth_codex_fanout(
        phase=_phase(), config=config, scratchpad=scratchpad, attempt=1
    ) == 0
    frozen = seen["prepare"]
    assert selector_calls == 1
    assert seen["record"] is frozen
    assert seen["launch_contract"] is frozen.contract
    assert seen["launch_spec"] is frozen.launch
    assert seen["prompt_inputs"] == frozen.selected_inputs
    assert seen["staged_inputs"] == frozen.selected_inputs
    assert "skill_execution_gaps.md" not in frozen.selected_inputs
    assert frozen.contract.digest == frozen.to_dict()["contract_digest"]
    assert [row["identity"] for row in frozen.output_manifest] == [
        "scratchpad:depth_da_iter2_findings.md"
    ]

    plan_path = phase_attempt_plan_path(
        scratchpad,
        phase="depth",
        work_unit_id=frozen.contract.work_unit_id,
        attempt=1,
    )
    replayed = load_phase_attempt_plan(plan_path)
    assert replayed.to_dict() == frozen.to_dict()


def test_da_iter2_resume_loads_plan_without_recomputing_denominator(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    config: dict[str, Any] = {
        "pipeline": "sc",
        "mode": "thorough",
        "language": "evm",
        "cli_backend": "codex",
        "project_root": str(tmp_path),
        "_run_id": "run20-frozen-da-resume",
    }
    monkeypatch.setattr(D, "_depth_worker_jobs", lambda *_a, **_k: [dict(ORDINARY_JOB)])
    monkeypatch.setattr(D, "phase_model", lambda *_a, **_k: "gpt-5.6-sol")
    monkeypatch.setattr(D, "scale_timeout", lambda *_a, **_k: 211)
    first = D._typed_model_worker_attempt_plan(
        phase=_phase(), config=config, scratchpad=scratchpad,
        project_root=str(tmp_path), agent_id=DA_JOB["agent_id"],
        agent_role=DA_JOB["role"], output=DA_JOB["output"], timeout_s=211,
        work_category=DA_JOB["category"], focus_area=DA_JOB["focus"], attempt=1,
    )
    (scratchpad / "skill_execution_gaps.md").write_text("late\n", encoding="utf-8")
    monkeypatch.setattr(
        D,
        "_typed_worker_registered_input_paths",
        lambda **_kwargs: pytest.fail("resume recomputed the frozen denominator"),
    )
    replayed = D._typed_model_worker_attempt_plan(
        phase=_phase(), config=config, scratchpad=scratchpad,
        project_root=str(tmp_path), agent_id=DA_JOB["agent_id"],
        agent_role=DA_JOB["role"], output=DA_JOB["output"], timeout_s=999,
        work_category=DA_JOB["category"], focus_area=DA_JOB["focus"], attempt=1,
    )
    assert replayed.to_dict() == first.to_dict()
    assert replayed.launch.timeout_s == first.launch.timeout_s
