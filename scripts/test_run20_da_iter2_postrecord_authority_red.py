"""Run20 regression: DA iter2 must retain one authority through post-record.

The live failure bound the complete post-wave denominator before provider
launch, then reconstructed the same work-unit key without the DA role metadata
at the legacy post-record seam.  That smaller denominator replaced the active
unit and invalidated its already-committed output plus downstream authorities.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

import pytest

import plamen_driver as D
from phase_io_contracts import resolve_phase_io_contract


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


def _authority_fingerprint(
    *,
    scratchpad: Path,
    config: Mapping[str, Any],
    agent_id: str,
    output: str | None = None,
    expected_outputs: tuple[str, ...] | list[str] = (),
    agent_role: str | None = None,
    work_category: str = "*",
    focus_area: str = "",
    attempt: int = 1,
    **_ignored: Any,
) -> tuple[str, str, tuple[str, ...]]:
    """Rebuild the authority-sensitive portion of the worker contract."""

    output_name = str(output or "")
    if not output_name and len(expected_outputs) == 1:
        output_name = str(expected_outputs[0])
    assert output_name
    inputs = D._typed_worker_registered_input_paths(
        phase_name="depth",
        scratchpad=scratchpad,
        config=dict(config),
        agent_id=agent_id,
        agent_role=agent_role,
        output=output_name,
        work_category=work_category,
        focus_area=focus_area,
        attempt=attempt,
    )
    work_unit_id = D._typed_worker_work_unit_selector(
        pipeline="sc",
        phase_name="depth",
        agent_id=agent_id,
        role=agent_role,
        output=output_name,
        attempt=attempt,
    )
    contract = resolve_phase_io_contract(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="codex",
        phase="depth",
        work_unit_id=work_unit_id,
        exact_outputs=(output_name,),
        exact_inputs=inputs,
    )
    # This mirrors the semantic input-set property relevant to the regression:
    # the finite identity denominator is hashed canonically.  File-byte binding
    # is covered by the artifact-ledger suites; this test owns scheduler parity.
    denominator_digest = hashlib.sha256(
        json.dumps(
            list(inputs), ensure_ascii=True, separators=(",", ":")
        ).encode("utf-8")
    ).hexdigest()
    # ``_typed_worker_registered_input_paths`` returns relative paths.  The
    # PhaseIO compiler is the authority boundary that canonicalizes those
    # paths into scratchpad identities; assert the launched contract's actual
    # immutable denominator rather than the selector's pre-canonical form.
    return contract.digest, denominator_digest, tuple(contract.immutable_inputs)


def test_da_iter2_postrecord_preserves_launch_denominator_and_downstream_order(
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
        "_run_id": "run20-da-authority-regression",
        "pty_continuation_budget": 3,
    }
    da_complete = False
    fingerprints: dict[str, tuple[str, str, tuple[str, ...]]] = {}
    events: list[str] = []

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
    monkeypatch.setattr(
        D,
        "_depth_dispatch_plan",
        lambda **kwargs: [
            {"job": dict(job), "prompt": "bounded"} for job in kwargs["jobs"]
        ],
    )
    monkeypatch.setattr(D, "_write_depth_dispatch_contract", lambda *_a, **_k: None)
    monkeypatch.setattr(
        D, "_write_and_record_depth_da_dispatch_delta", lambda **_k: []
    )
    monkeypatch.setattr(D, "_quarantine_incomplete_depth_retry_output", lambda *_a, **_k: None)
    monkeypatch.setattr(D, "_compile_depth_worker_staged_gate_context", lambda **_k: ({}, ()))
    monkeypatch.setattr(D, "_canonicalize_depth_iter_filenames", lambda *_a, **_k: None)
    monkeypatch.setattr(D, "phase_model", lambda *_a, **_k: "gpt-5.6-sol")
    monkeypatch.setattr(D, "scale_timeout", lambda *_a, **_k: 211)

    def prepare(**kwargs: Any) -> list[str]:
        fingerprints["prelaunch"] = _authority_fingerprint(**kwargs)
        return []

    def launch(**kwargs: Any) -> int:
        nonlocal da_complete
        fingerprints["launch"] = _authority_fingerprint(**kwargs)
        da_complete = True
        events.append("provider")
        return 0

    def record(**kwargs: Any) -> list[str]:
        fingerprints["postrecord"] = _authority_fingerprint(**kwargs)
        events.append("record")
        return []

    synth_count = 0

    def synth(*_args: Any, **_kwargs: Any) -> None:
        nonlocal synth_count
        synth_count += 1
        if synth_count == 2:
            # The post-DA confidence consensus must observe the exact authority
            # that launched the producer, not a reconstructed smaller unit.
            assert fingerprints["postrecord"] == fingerprints["launch"]
            events.append("consensus-replay")

    def finalize_fuzz(**_kwargs: Any) -> None:
        events.append("fuzz-replay")

    monkeypatch.setattr(D, "_prepare_typed_model_worker_launch", prepare)
    monkeypatch.setattr(D, "_run_one_codex_exec", launch)
    monkeypatch.setattr(D, "_record_typed_model_worker_artifact", record)
    monkeypatch.setattr(D, "_synthesize_depth_lifecycle_artifacts", synth)
    monkeypatch.setattr(D, "_finalize_depth_fuzz_result_authority", finalize_fuzz)

    assert D._run_depth_codex_fanout(
        phase=_phase(), config=config, scratchpad=scratchpad, attempt=1
    ) == 0
    assert fingerprints["prelaunch"] == fingerprints["launch"]
    assert fingerprints["postrecord"] == fingerprints["launch"]
    assert "scratchpad:confidence_scores.md" in fingerprints["launch"][2]
    assert (
        "scratchpad:step_execution_gaps_mechanical.md"
        in fingerprints["launch"][2]
    )
    assert events == ["fuzz-replay", "provider", "record", "consensus-replay"]
