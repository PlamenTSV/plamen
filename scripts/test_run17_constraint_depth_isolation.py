"""Run17 regressions for Depth prelaunch and provider-row isolation."""

from __future__ import annotations

import threading
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import plamen_driver as D


def _phase() -> D.Phase:
    return D.Phase(
        name="depth",
        section_markers=["Depth"],
        expected_artifacts=["depth_*_findings.md"],
        base_timeout_s=30,
        min_artifact_bytes=1,
    )


def _config(root: Path) -> dict[str, Any]:
    return {
        "cli_backend": "codex",
        "mode": "core",
        "pipeline": "sc",
        "language": "evm",
        "scratchpad": str(root),
        "project_root": str(root),
        "_run_id": "12345678-1234-4123-8123-123456789abc",
        "pty_continuation_budget": 3,
    }


def _job(index: int, *, role: str = "standard") -> dict[str, str]:
    return {
        "agent_id": f"depth-{index}",
        "role": role,
        "output": f"depth_{index}_findings.md",
        "category": "scanner" if role == "validation_sweep" else "standard",
        "focus": f"focus {index}",
    }


def _patch_fanout_shell(monkeypatch, jobs, complete, committed) -> None:
    monkeypatch.setattr(D, "_depth_worker_jobs", lambda *_a, **_k: jobs)
    monkeypatch.setattr(D, "_prepare_depth_fuzz_workspaces", lambda rows, **_k: rows)
    monkeypatch.setattr(
        D,
        "_depth_worker_output_complete",
        lambda _sp, _phase, job, **_k: str(job["output"]) in complete,
    )
    monkeypatch.setattr(
        D,
        "_record_typed_model_worker_artifact",
        lambda **kwargs: committed.append(str(kwargs["output"])) or [],
    )
    monkeypatch.setattr(D, "_finalize_depth_fuzz_workspace", lambda *_a, **_k: None)
    monkeypatch.setattr(D, "_finalize_depth_fuzz_result_authority", lambda **_k: None)
    monkeypatch.setattr(D, "_synthesize_depth_lifecycle_artifacts", lambda *_a, **_k: [])
    monkeypatch.setattr(D, "_depth_da_job_if_required", lambda *_a, **_k: [])


def test_depth_missing_semantic_input_never_enters_provider_wave(
    tmp_path: Path, monkeypatch,
) -> None:
    state = _job(1, role="state_trace")
    scanner = _job(2, role="validation_sweep")
    jobs = [state, scanner]
    complete: set[str] = set()
    committed: list[str] = []
    launched: list[str] = []
    _patch_fanout_shell(monkeypatch, jobs, complete, committed)
    monkeypatch.setattr(
        D,
        "_depth_dispatch_plan",
        lambda **kwargs: [
            {"job": dict(job), "prompt": f"prompt {job['output']}"}
            for job in kwargs["jobs"]
        ],
    )
    monkeypatch.setattr(D, "_write_depth_dispatch_contract", lambda *_a, **_k: None)
    monkeypatch.setattr(D, "_quarantine_incomplete_depth_retry_output", lambda *_a, **_k: None)
    monkeypatch.setattr(D, "_invalidate_derived_step_trace_for_job", lambda *_a, **_k: None)
    monkeypatch.setattr(D, "_depth_worker_launch_cwd", lambda **_k: str(tmp_path))
    monkeypatch.setattr(
        D,
        "_prepare_typed_model_worker_launch",
        lambda **kwargs: (
            ["semantic input missing at binding: scratchpad:constraint_variables.md"]
            if kwargs["output"] == state["output"]
            else []
        ),
    )
    monkeypatch.setattr(
        D,
        "_typed_worker_registered_input_paths",
        lambda **_k: ("constraint_variables.md",),
    )
    monkeypatch.setattr(
        D,
        "_compile_depth_worker_staged_gate_context",
        lambda **_k: ({}, ("scratchpad:constraint_variables.md",)),
    )

    def launch(**kwargs):
        output = str(kwargs["expected_outputs"][0])
        launched.append(output)
        complete.add(output)
        return 0

    monkeypatch.setattr(D, "_run_one_codex_exec", launch)

    rc = D._run_depth_codex_fanout(
        phase=_phase(), config=_config(tmp_path), scratchpad=tmp_path, attempt=1
    )

    assert rc == 0
    assert launched == [scanner["output"]]
    assert committed == [scanner["output"]]
    assert state["output"] not in launched


def test_depth_prepare_requires_exact_inputs_bound_and_fresh_retry_can_bind(
    tmp_path: Path, monkeypatch,
) -> None:
    rows = {
        "depth/worker.state": {
            "semantic_status": "INPUT_DEBT",
            "execution_state": "INPUT_DEBT_PREEXECUTION",
        },
        "depth/worker.state.attempt-0002": {
            "semantic_status": "INPUTS_BOUND",
            "execution_state": "INPUTS_BOUND_PREEXECUTION",
        },
    }
    historical = dict(rows["depth/worker.state"])
    monkeypatch.setattr(D, "_materialize_impact_map_evidence", lambda **_k: [])
    monkeypatch.setattr(
        D,
        "_bind_typed_model_worker_inputs",
        lambda **kwargs: (
            ["semantic input missing at binding: scratchpad:constraint_variables.md"]
            if int(kwargs["attempt"]) == 1
            else []
        ),
    )
    monkeypatch.setattr(
        D,
        "_typed_model_worker_contract_and_launch",
        lambda **kwargs: (
            SimpleNamespace(
                key=(
                    "depth/worker.state"
                    if int(kwargs["attempt"]) == 1
                    else "depth/worker.state.attempt-0002"
                )
            ),
            SimpleNamespace(),
        ),
    )
    monkeypatch.setattr(
        D, "read_artifact_ledger", lambda _root: {"work_units": rows}
    )
    monkeypatch.setattr(D, "_append_phase_io_debt", lambda *_a, **_k: None)
    kwargs = {
        "phase": _phase(),
        "config": _config(tmp_path),
        "scratchpad": tmp_path,
        "project_root": str(tmp_path),
        "agent_id": "state",
        "agent_role": "state_trace",
        "output": "depth_state_trace_findings.md",
        "timeout_s": 30,
        "work_category": "standard",
        "focus_area": "state trace",
    }

    first = D._prepare_typed_model_worker_launch(**kwargs, attempt=1)
    second = D._prepare_typed_model_worker_launch(**kwargs, attempt=2)

    assert any("not INPUTS_BOUND" in issue for issue in first)
    assert second == []
    assert rows["depth/worker.state"] == historical


def test_depth_wave_exit_error_is_row_local_and_concurrency_is_bounded(
    monkeypatch,
) -> None:
    rows = [{"output": f"out-{index}"} for index in range(5)]
    active = 0
    maximum = 0
    starts = 0
    lock = threading.Lock()
    first_wave = threading.Barrier(3)
    monkeypatch.setattr(D.display, "spin", lambda *_a, **_k: None)

    def invoke(row):
        nonlocal active, maximum, starts
        with lock:
            active += 1
            starts += 1
            start_ordinal = starts
            maximum = max(maximum, active)
        try:
            if start_ordinal <= first_wave.parties:
                first_wave.wait(timeout=5)
        finally:
            with lock:
                active -= 1
        return D.EXIT_ERROR if row["output"] == "out-0" else 0

    results, terminal = D._run_bounded_headless_provider_wave(
        rows=rows,
        row_key=lambda row: str(row["output"]),
        invoke=invoke,
        concurrency=3,
        thread_name_prefix="run17-depth-wave",
        exit_error_is_nonterminal=lambda _row: True,
    )

    assert terminal is None
    assert set(results) == {row["output"] for row in rows}
    assert results["out-0"] == D.EXIT_ERROR
    assert maximum == 3


def test_depth_retries_only_failed_row_and_clears_error_on_success(
    tmp_path: Path, monkeypatch,
) -> None:
    jobs = [_job(index) for index in range(5)]
    failed = jobs[0]["output"]
    complete: set[str] = set()
    committed: list[str] = []
    waves: list[tuple[int, tuple[str, ...]]] = []
    _patch_fanout_shell(monkeypatch, jobs, complete, committed)

    def batch(**kwargs):
        attempt = int(kwargs["attempt"])
        outputs = tuple(str(job["output"]) for job in kwargs["jobs"])
        waves.append((attempt, outputs))
        outcomes = {}
        for output in outputs:
            if output == failed and attempt == 1:
                outcomes[output] = D._DepthSerialLaunchOutcome(
                    D.EXIT_ERROR, True, False
                )
            else:
                complete.add(output)
                outcomes[output] = D._DepthSerialLaunchOutcome(0, True, False)
        return outcomes, None

    monkeypatch.setattr(D, "_run_depth_headless_batch", batch)

    rc = D._run_depth_codex_fanout(
        phase=_phase(), config=_config(tmp_path), scratchpad=tmp_path, attempt=1
    )

    assert rc == 0
    assert waves == [(1, tuple(job["output"] for job in jobs)), (2, (failed,))]
    assert sorted(committed) == sorted(job["output"] for job in jobs)


def test_depth_persistent_row_error_drains_healthy_rows_then_aggregates_error(
    tmp_path: Path, monkeypatch,
) -> None:
    jobs = [_job(index) for index in range(5)]
    failed = jobs[0]["output"]
    complete: set[str] = set()
    committed: list[str] = []
    waves: list[tuple[int, tuple[str, ...]]] = []
    _patch_fanout_shell(monkeypatch, jobs, complete, committed)

    def batch(**kwargs):
        attempt = int(kwargs["attempt"])
        outputs = tuple(str(job["output"]) for job in kwargs["jobs"])
        waves.append((attempt, outputs))
        outcomes = {}
        for output in outputs:
            if output == failed:
                outcomes[output] = D._DepthSerialLaunchOutcome(
                    D.EXIT_ERROR, True, False
                )
            else:
                complete.add(output)
                outcomes[output] = D._DepthSerialLaunchOutcome(0, True, False)
        return outcomes, None

    monkeypatch.setattr(D, "_run_depth_headless_batch", batch)

    rc = D._run_depth_codex_fanout(
        phase=_phase(), config=_config(tmp_path), scratchpad=tmp_path, attempt=1
    )

    assert rc == D.EXIT_ERROR
    assert waves == [(1, tuple(job["output"] for job in jobs)), (2, (failed,))]
    assert sorted(committed) == sorted(
        job["output"] for job in jobs if job["output"] != failed
    )
