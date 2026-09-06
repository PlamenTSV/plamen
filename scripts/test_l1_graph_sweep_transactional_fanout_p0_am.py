"""L1 graph sweeps must be exact, bounded, single-writer work units."""
from __future__ import annotations

import json
from pathlib import Path

import plamen_driver as D
import pytest
from phase_io_contracts import resolve_phase_io_contract


def _config(root: Path, *, backend: str = "codex") -> dict:
    return {
        "pipeline": "l1",
        "mode": "thorough",
        "language": "rust",
        "cli_backend": backend,
        "project_root": str(root),
        "scratchpad": str(root),
        "_run_id": "run-l1-graph-sweeps",
    }


def _seed_graph_inputs(root: Path) -> None:
    (root / "scip").mkdir()
    coverage_rows = "\n".join(
        f"| `src/module_{index}.rs` | 20 | UNCITED | graph queue |"
        for index in range(95)
    )
    (root / "subsystem_coverage_gap.md").write_text(
        "# Coverage\n\n"
        "Coverage: 25.0%\n\n"
        "| File | LOC | Status | Reason |\n"
        "|---|---:|---|---|\n"
        + coverage_rows
        + "\n",
        encoding="utf-8",
    )
    panic_rows = "\n".join(
        f"| `src/panic_{index}.rs:{index + 1}` | unwrap | caller |"
        for index in range(301)
    )
    (root / "scip" / "panic_sites.md").write_text(
        "# Panic Sites\n\n"
        "| Location | Kind | Caller |\n"
        "|---|---|---|\n"
        + panic_rows
        + "\n",
        encoding="utf-8",
    )
    for name in (
        "repo_map.md",
        "xref_map.md",
        "call_graph_p2p.md",
        "call_graph_consensus.md",
        "call_graph_execution.md",
        "type_hierarchy.md",
        "concurrency_inventory.md",
    ):
        (root / "scip" / name).write_text(
            f"# {name}\n\n`src/lib.rs:1` network transaction proof cache replay\n",
            encoding="utf-8",
        )


def test_l1_graph_plan_exactly_shards_dynamic_denominators(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _seed_graph_inputs(tmp_path)
    monkeypatch.setattr(
        D,
        "_parse_subsystem_coverage_gap",
        lambda _root: {"coverage": 25.0, "uncited": 95.0, "total": 100.0},
    )
    monkeypatch.setattr(D, "_panic_sites_available", lambda _root: True)
    monkeypatch.setattr(D, "_field_validation_sweep_relevant", lambda _root: True)
    monkeypatch.setattr(D, "_primitive_sweep_relevant", lambda _root: True)
    monkeypatch.setattr(
        D, "_network_amplification_sweep_relevant", lambda _root: True
    )
    monkeypatch.setattr(D, "_lifecycle_replay_sweep_relevant", lambda _root: True)

    jobs = D._prepare_l1_graph_sweep_plan(tmp_path, _config(tmp_path))
    outputs = [row["output"] for row in jobs]
    assert len(outputs) == len(set(outputs)) == 11
    assert outputs[:3] == [
        "coverage_fill_1.md",
        "coverage_fill_2.md",
        "coverage_fill_3.md",
    ]
    assert outputs[3:6] == [
        "panic_audit_1.md",
        "panic_audit_2.md",
        "panic_audit_3.md",
    ]
    assert {
        "symmetric_pair_findings.md",
        "field_validation_matrix.md",
        "primitive_correctness_findings.md",
        "network_amplification_findings.md",
        "lifecycle_replay_findings.md",
    }.issubset(outputs)

    plan = json.loads((tmp_path / "_graph_sweep_plan.json").read_text())
    assert plan["expected_outputs"] == outputs
    assert plan["coverage_denominator"] == 95
    assert plan["panic_denominator"] == 301
    assert sum(
        len(json.loads((tmp_path / row["queue"]).read_text())["rows"])
        for row in jobs
        if row["role"] == "coverage_fill"
    ) == 95
    assert sum(
        len(json.loads((tmp_path / row["queue"]).read_text())["rows"])
        for row in jobs
        if row["role"] == "panic_audit"
    ) == 301


def test_l1_graph_worker_prompt_is_one_output_and_no_orchestration(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _seed_graph_inputs(tmp_path)
    monkeypatch.setattr(
        D,
        "_parse_subsystem_coverage_gap",
        lambda _root: {"coverage": 25.0, "uncited": 95.0, "total": 100.0},
    )
    monkeypatch.setattr(D, "_panic_sites_available", lambda _root: False)
    monkeypatch.setattr(D, "_field_validation_sweep_relevant", lambda _root: False)
    monkeypatch.setattr(D, "_primitive_sweep_relevant", lambda _root: False)
    monkeypatch.setattr(
        D, "_network_amplification_sweep_relevant", lambda _root: False
    )
    monkeypatch.setattr(D, "_lifecycle_replay_sweep_relevant", lambda _root: False)
    (tmp_path / "scip" / "xref_map.md").unlink()
    jobs = D._prepare_l1_graph_sweep_plan(tmp_path, _config(tmp_path))
    prompt = D._build_l1_graph_sweep_worker_prompt(
        job=jobs[0],
        scratchpad=tmp_path,
        project_root=str(tmp_path),
        config=_config(tmp_path),
        attempt=1,
    )
    assert "Write exactly this file and no other scratchpad artifact" in prompt
    assert jobs[0]["output"] in prompt
    assert jobs[0]["queue"] in prompt
    assert "do not spawn" in prompt.lower()
    for other in jobs[1:]:
        assert f"`{tmp_path.as_posix()}/{other['output']}`" not in prompt


def test_l1_graph_worker_phaseio_binds_exact_plan_and_queue() -> None:
    contract = resolve_phase_io_contract(
        pipeline="l1",
        mode="thorough",
        ecosystem="rust",
        backend="claude",
        phase="graph_sweeps",
        work_unit_id="worker.g001",
        exact_outputs=("coverage_fill_1.md",),
    )
    assert contract.immutable_inputs == (
        "scratchpad:_graph_sweep_plan.json",
        "scratchpad:_graph_sweep_queue_coverage_fill_1.json",
    )
    assert contract.outputs[0].identity == "scratchpad:coverage_fill_1.md"
    assert contract.outputs[0].writer == "MODEL"


def test_l1_graph_finalize_is_deterministic_and_transport_free(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _seed_graph_inputs(tmp_path)
    monkeypatch.setattr(
        D,
        "_parse_subsystem_coverage_gap",
        lambda _root: {"coverage": 25.0, "uncited": 95.0, "total": 100.0},
    )
    monkeypatch.setattr(D, "_panic_sites_available", lambda _root: True)
    monkeypatch.setattr(D, "_field_validation_sweep_relevant", lambda _root: False)
    monkeypatch.setattr(D, "_primitive_sweep_relevant", lambda _root: False)
    monkeypatch.setattr(
        D, "_network_amplification_sweep_relevant", lambda _root: False
    )
    monkeypatch.setattr(D, "_lifecycle_replay_sweep_relevant", lambda _root: False)
    jobs = D._prepare_l1_graph_sweep_plan(tmp_path, _config(tmp_path))
    for row in jobs:
        (tmp_path / row["output"]).write_text(
            f"<!-- PLAMEN_ARTIFACT: {row['output']} -->\n"
            f"<!-- PLAMEN_OWNER: {row['agent_id']} -->\n"
            "<!-- PLAMEN_STATUS: IN_PROGRESS -->\n"
            "<!-- PLAMEN_PHASE: graph_sweeps -->\n"
            f"# {row['role']}\n\n"
            "| Entry | Verdict | Evidence |\n"
            "|---|---|---|\n"
            "| row | NEEDS_REVIEW | `src/lib.rs:1` |\n\n"
            "<!-- PLAMEN_STATUS: COMPLETE -->\n",
            encoding="utf-8",
        )
    written = D._finalize_l1_graph_sweep_outputs(
        tmp_path, _config(tmp_path), jobs
    )
    assert {"graph_sweep_summary.md", "panic_audit_summary.md"}.issubset(written)
    for name in written:
        text = (tmp_path / name).read_text(encoding="utf-8")
        if name.endswith("summary.md"):
            assert "PLAMEN_STATUS" not in text
    first = (tmp_path / "graph_sweep_summary.md").read_bytes()
    D._finalize_l1_graph_sweep_outputs(tmp_path, _config(tmp_path), jobs)
    assert (tmp_path / "graph_sweep_summary.md").read_bytes() == first


@pytest.mark.parametrize("backend", ["codex", "claude-headless"])
def test_l1_graph_headless_runner_executes_every_exact_leaf(
    tmp_path: Path,
    monkeypatch,
    backend: str,
) -> None:
    _seed_graph_inputs(tmp_path)
    monkeypatch.setattr(
        D,
        "_parse_subsystem_coverage_gap",
        lambda _root: {"coverage": 100.0, "uncited": 0.0, "total": 10.0},
    )
    monkeypatch.setattr(D, "_panic_sites_available", lambda _root: False)
    monkeypatch.setattr(D, "_field_validation_sweep_relevant", lambda _root: True)
    monkeypatch.setattr(D, "_primitive_sweep_relevant", lambda _root: False)
    monkeypatch.setattr(
        D, "_network_amplification_sweep_relevant", lambda _root: False
    )
    monkeypatch.setattr(D, "_lifecycle_replay_sweep_relevant", lambda _root: False)
    monkeypatch.setattr(D, "_prepare_typed_model_worker_launch", lambda **_kw: [])
    monkeypatch.setattr(D, "_record_typed_model_worker_artifact", lambda **_kw: [])
    monkeypatch.setattr(D, "gate_passes", lambda *_args, **_kw: (True, []))

    seen: list[str] = []

    def _write(**kwargs) -> int:
        output = (
            kwargs["expected_outputs"][0]
            if "expected_outputs" in kwargs
            else kwargs["job"]["output"]
        )
        job_id = (
            kwargs.get("agent_id")
            or kwargs.get("job", {}).get("agent_id")
        )
        seen.append(output)
        (tmp_path / output).write_text(
            f"<!-- PLAMEN_ARTIFACT: {output} -->\n"
            f"<!-- PLAMEN_OWNER: {job_id} -->\n"
            "<!-- PLAMEN_STATUS: IN_PROGRESS -->\n"
            "<!-- PLAMEN_PHASE: graph_sweeps -->\n"
            "# Exact queue dispositions\n\n"
            + ("evidence `src/lib.rs:1` NEEDS_REVIEW\n" * 8)
            + "<!-- PLAMEN_STATUS: COMPLETE -->\n",
            encoding="utf-8",
        )
        return 0

    monkeypatch.setattr(D, "_run_one_codex_exec", _write)
    monkeypatch.setattr(D, "_run_one_claude_headless_breadth_worker", _write)
    phase = next(row for row in D.L1_PHASES if row.name == "graph_sweeps")
    assert D._run_l1_graph_sweep_backend_fanout(
        backend=backend,
        phase=phase,
        config=_config(tmp_path, backend=backend),
        scratchpad=tmp_path,
        attempt=1,
        timeout=900,
        effective_model="fixture",
    ) == 0
    plan = json.loads((tmp_path / "_graph_sweep_plan.json").read_text())
    assert seen == plan["expected_outputs"]
