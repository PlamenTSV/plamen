"""Run20 regressions for immutable post-consensus Depth dispatch authority."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from artifact_ledger import (
    authorize_deterministic_work_unit_reexecution,
    record_work_unit_artifacts,
    record_work_unit_inputs,
    validate_work_unit_artifacts,
    validate_work_unit_inputs,
)
import confidence_consensus_authority as C
import depth_dispatch_delta_authority as A
from methodology_application import (
    phase_dispatch_sha256,
    worker_dispatch_contract_sha256,
)
from phase_io_contracts import LaunchSpec, resolve_phase_io_contract


RUN_ID = "run20-depth-dispatch-delta"


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")


def _base_dispatch(root: Path) -> tuple[bytes, bytes]:
    base_entry = {
        "worker_id": "depth-state-trace",
        "output": "depth_state_trace_findings.md",
        "prompt_sha256": "1" * 64,
        "prompt_snapshot_required": True,
        "prompt_snapshot_glob": "_prompt_depth_worker_*.attempt*.md",
        "methodologies": [],
    }
    base_entry["dispatch_contract_sha256"] = worker_dispatch_contract_sha256(
        "depth", base_entry
    )
    phase = {"backend": "codex", "entries": [base_entry]}
    phase["dispatch_sha256"] = phase_dispatch_sha256(phase)
    dispatch = {
        "schema_version": 1,
        "updated_at": "2026-09-15T00:00:00+00:00",
        "phases": {"depth": phase},
    }
    dispatch_path = root / "skill_dispatch.json"
    _write_json(dispatch_path, dispatch)
    pool = {
        "version": 2,
        "phase": "depth",
        "backend": "codex",
        "pipeline": "sc",
        "mode": "thorough",
        "canonical_outputs": ["depth_state_trace_findings.md"],
        "outputs": ["depth_state_trace_findings.md"],
        "jobs": [{
            "agent_id": "depth-state-trace",
            "role": "state_trace",
            "category": "standard",
            "output": "depth_state_trace_findings.md",
            "prompt_sha256": "1" * 64,
        }],
        "skill_dispatch_file": "skill_dispatch.json",
        "skill_dispatch_sha256": phase["dispatch_sha256"],
        "created_at": "2026-09-15T00:00:00+00:00",
    }
    pool_path = root / "_depth_worker_pool_contract.json"
    _write_json(pool_path, pool)
    return dispatch_path.read_bytes(), pool_path.read_bytes()


def _delta(base_dispatch: bytes, base_pool: bytes, attempt: int = 1):
    entry = {
        "worker_id": "depth-da-iter2",
        "output": "depth_da_iter2_findings.md",
        "prompt_sha256": "2" * 64,
        "prompt_snapshot_required": True,
        "prompt_snapshot_glob": "_prompt_depth_worker_*.attempt*.md",
        "methodologies": [],
    }
    entry["dispatch_contract_sha256"] = worker_dispatch_contract_sha256(
        "depth", entry
    )
    return A.build_delta(
        attempt=attempt,
        base_dispatch=base_dispatch,
        base_pool_contract=base_pool,
        entries=(entry,),
        jobs=({
            "agent_id": "depth-da-iter2",
            "role": "da_iter2",
            "category": "da",
            "focus": "adversarial second pass",
            "output": "depth_da_iter2_findings.md",
            "prompt_sha256": "2" * 64,
        },),
    )


def _launch(contract, model: str = "driver") -> LaunchSpec:
    return LaunchSpec(
        work_unit_key=contract.key,
        pipeline=contract.pipeline,
        mode=contract.mode,
        ecosystem=contract.ecosystem,
        backend=contract.backend,
        model=model,
        timeout_s=120,
        exec_mode="python",
        tool_policy=(),
    )


def test_da_delta_is_additive_and_base_hashes_remain_exact(tmp_path: Path) -> None:
    tmp_path = tmp_path.resolve()
    before_dispatch, before_pool = _base_dispatch(tmp_path)
    payload = _delta(before_dispatch, before_pool)
    _write_json(tmp_path / A.delta_name(1), payload)

    entries, owners, issues = C._dispatch_state(tmp_path)

    assert issues == []
    assert entries["depth_da_iter2_findings.md"]["worker_id"] == "depth-da-iter2"
    assert owners["depth_da_iter2_findings.md"] == "depth-da-iter2"
    assert (tmp_path / "skill_dispatch.json").read_bytes() == before_dispatch
    assert (
        tmp_path / "_depth_worker_pool_contract.json"
    ).read_bytes() == before_pool


def test_da_delta_base_hash_mismatch_fails_closed(tmp_path: Path) -> None:
    tmp_path = tmp_path.resolve()
    before_dispatch, before_pool = _base_dispatch(tmp_path)
    _write_json(tmp_path / A.delta_name(1), _delta(before_dispatch, before_pool))
    (tmp_path / "_depth_worker_pool_contract.json").write_bytes(before_pool + b" ")

    _entries, _owners, issues = C._dispatch_state(tmp_path)

    assert any("delta base binding differs" in issue for issue in issues)


def test_consensus_reexecution_accepts_new_phaseio_owned_da_delta(
    tmp_path: Path,
) -> None:
    tmp_path = tmp_path.resolve()
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    base_dispatch, base_pool = _base_dispatch(scratchpad)
    project = tmp_path

    (scratchpad / "fuzz_workspace_index.json").write_text(
        "{}\n", encoding="utf-8"
    )
    (scratchpad / "invariant_fuzz_results.md").write_text(
        "fuzz evidence\n", encoding="utf-8"
    )
    fuzz = resolve_phase_io_contract(
        pipeline="sc", mode="thorough", ecosystem="evm", backend="codex",
        phase="depth", work_unit_id="fuzz_workspace.finalize.all",
        exact_inputs=(
            "fuzz_workspace_index.json", "invariant_fuzz_results.md",
        ),
        exact_outputs=("fuzz_workspace_result_index.json",),
    )
    fuzz_launch = _launch(fuzz)
    record_work_unit_inputs(
        scratchpad, project, fuzz, fuzz_launch, run_id=RUN_ID
    )
    (scratchpad / "fuzz_workspace_result_index.json").write_text(
        "{}\n", encoding="utf-8"
    )
    record_work_unit_artifacts(
        scratchpad, project, fuzz, fuzz_launch, run_id=RUN_ID, actor="DRIVER"
    )

    first = resolve_phase_io_contract(
        pipeline="sc", mode="thorough", ecosystem="evm", backend="codex",
        phase="depth", work_unit_id="confidence_consensus",
        exact_inputs=("skill_dispatch.json", "_depth_worker_pool_contract.json"),
    )
    first_launch = _launch(first)
    record_work_unit_inputs(
        scratchpad, project, first, first_launch, run_id=RUN_ID
    )
    for spec in first.outputs:
        (scratchpad / spec.path).write_text(
            f"initial:{spec.path}\n", encoding="utf-8"
        )
    record_work_unit_artifacts(
        scratchpad, project, first, first_launch, run_id=RUN_ID, actor="DRIVER"
    )

    delta_name = A.delta_name(1)
    delta_contract = resolve_phase_io_contract(
        pipeline="sc", mode="thorough", ecosystem="evm", backend="codex",
        phase="depth", work_unit_id="dispatch_delta.da_iter2.attempt-0001",
        exact_inputs=("skill_dispatch.json", "_depth_worker_pool_contract.json"),
        exact_outputs=(delta_name,),
    )
    delta_launch = _launch(delta_contract)
    record_work_unit_inputs(
        scratchpad, project, delta_contract, delta_launch, run_id=RUN_ID
    )
    _write_json(scratchpad / delta_name, _delta(base_dispatch, base_pool))
    record_work_unit_artifacts(
        scratchpad, project, delta_contract, delta_launch,
        run_id=RUN_ID, actor="DRIVER",
    )

    refreshed = resolve_phase_io_contract(
        pipeline="sc", mode="thorough", ecosystem="evm", backend="codex",
        phase="depth", work_unit_id="confidence_consensus",
        exact_inputs=(
            "skill_dispatch.json", "_depth_worker_pool_contract.json", delta_name,
        ),
    )
    refreshed_launch = _launch(refreshed)
    authorization = authorize_deterministic_work_unit_reexecution(
        scratchpad, project, refreshed, refreshed_launch, run_id=RUN_ID
    )
    assert authorization is not None
    record_work_unit_inputs(
        scratchpad, project, refreshed, refreshed_launch, run_id=RUN_ID
    )
    assert validate_work_unit_inputs(
        scratchpad, project, refreshed, refreshed_launch, run_id=RUN_ID
    ) == []
    for spec in refreshed.outputs:
        (scratchpad / spec.path).write_text(
            f"refreshed:{spec.path}\n", encoding="utf-8"
        )
    record_work_unit_artifacts(
        scratchpad, project, refreshed, refreshed_launch,
        run_id=RUN_ID, actor="DRIVER",
    )
    assert validate_work_unit_artifacts(
        scratchpad, project, refreshed, refreshed_launch, run_id=RUN_ID
    ) == []
    assert validate_work_unit_inputs(
        scratchpad, project, fuzz, fuzz_launch, run_id=RUN_ID
    ) == []
    assert validate_work_unit_artifacts(
        scratchpad, project, fuzz, fuzz_launch, run_id=RUN_ID
    ) == []
    assert hashlib.sha256(
        (scratchpad / "skill_dispatch.json").read_bytes()
    ).hexdigest() == hashlib.sha256(base_dispatch).hexdigest()
    assert hashlib.sha256(
        (scratchpad / "_depth_worker_pool_contract.json").read_bytes()
    ).hexdigest() == hashlib.sha256(base_pool).hexdigest()


def test_consensus_uses_exact_canonical_worker_prompt_snapshot(
    tmp_path: Path,
) -> None:
    tmp_path = tmp_path.resolve()
    output = "depth_state_trace_findings.md"
    worker = "depth-state-trace"
    prompt = b"worker prompt\n"
    entry = {
        "worker_id": worker,
        "output": output,
        "prompt_sha256": hashlib.sha256(prompt).hexdigest(),
        "prompt_snapshot_required": True,
        "prompt_snapshot_glob": "_prompt_depth_worker_*.attempt*.md",
        "methodologies": [],
    }
    entry["dispatch_contract_sha256"] = worker_dispatch_contract_sha256(
        "depth", entry
    )
    text = (
        "<!-- PLAMEN_DISPATCH_PHASE: depth -->\n"
        f"<!-- PLAMEN_DISPATCH_WORKER: {worker} -->\n"
        f"<!-- PLAMEN_DISPATCH_OUTPUT: {output} -->\n"
        "<!-- PLAMEN_DISPATCH_CONTRACT_SHA256: "
        f"{entry['dispatch_contract_sha256']} -->\n"
        f"<!-- PLAMEN_OWNER: {worker} -->\n"
        "<!-- PLAMEN_STATUS: COMPLETE -->\n"
    )
    (tmp_path / f"_prompt_depth_worker_{worker}.attempt1.md").write_bytes(prompt)
    assert C._entry_issues(
        tmp_path, output=output, text=text, entry=entry,
        expected_owner=worker, global_issues=[],
    ) == []

    (tmp_path / f"_prompt_depth_worker_{worker}.attempt1.md").unlink()
    (tmp_path / "_prompt_depth_worker_depth_state_trace_findings.attempt1.md").write_bytes(
        prompt
    )
    assert "worker-specific prompt snapshot is missing" in C._entry_issues(
        tmp_path, output=output, text=text, entry=entry,
        expected_owner=worker, global_issues=[],
    )


def test_consensus_rejects_noncanonical_worker_id_without_glob_expansion(
    tmp_path: Path,
) -> None:
    tmp_path = tmp_path.resolve()
    prompt = b"worker prompt\n"
    entry = {
        "worker_id": "depth-*",
        "output": "depth_state_trace_findings.md",
        "prompt_sha256": hashlib.sha256(prompt).hexdigest(),
        "prompt_snapshot_required": True,
        "prompt_snapshot_glob": "_prompt_depth_worker_*.attempt*.md",
        "methodologies": [],
    }
    entry["dispatch_contract_sha256"] = worker_dispatch_contract_sha256(
        "depth", entry
    )
    (tmp_path / "_prompt_depth_worker_depth-safe.attempt1.md").write_bytes(prompt)
    issues = C._entry_issues(
        tmp_path,
        output="depth_state_trace_findings.md",
        text="<!-- PLAMEN_STATUS: COMPLETE -->\n",
        entry=entry,
        expected_owner="depth-*",
        global_issues=[],
    )
    assert "dispatch worker id is not a canonical filename component" in issues
