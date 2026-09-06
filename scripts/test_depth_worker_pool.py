from __future__ import annotations

import json
import sys
import time
import threading
from pathlib import Path

import pytest

SCRIPTS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS_DIR))

import plamen_driver as D  # noqa: E402


def _phase() -> D.Phase:
    return D.Phase(
        name="depth",
        section_markers=["Phase 4b"],
        expected_artifacts=["depth_*_findings.md"],
        base_timeout_s=60,
        min_artifact_bytes=200,
        min_artifacts_count=4,
        example_tokens=["token_flow", "state_trace", "edge_case", "external"],
    )


def _fresh(sp: Path) -> None:
    sp.mkdir(parents=True, exist_ok=True)
    (sp / "_audit_started_with_markers.json").write_text("{}", encoding="utf-8")
    (sp / "findings_inventory.md").write_text(
        "# Inventory\n\nNo prior findings.\n", encoding="utf-8"
    )
    # The production phase loop creates the three driver-owned security
    # obligation inputs before invoking the lower-level worker pool.
    (sp / "security_feature_facts.json").write_text(
        '{"schema":"fixture.security-feature-facts.v1","facts":[]}\n',
        encoding="utf-8",
    )
    (sp / "security_obligation_authority.json").write_text(
        '{"schema":"fixture.security-obligations.v1","obligations":[]}\n',
        encoding="utf-8",
    )
    (sp / "security_obligations.md").write_text(
        "# Security Obligations\n\nNo obligations.\n", encoding="utf-8"
    )


def _complete(sp: Path, name: str, owner: str) -> None:
    (sp / name).write_text(
        f"<!-- PLAMEN_ARTIFACT: {name} -->\n"
        f"<!-- PLAMEN_OWNER: {owner} -->\n"
        "<!-- PLAMEN_STATUS: IN_PROGRESS -->\n"
        "<!-- PLAMEN_PHASE: depth -->\n"
        "<!-- PLAMEN_VERSION: 1 -->\n"
        f"<!-- AGENT_ROW: {owner} -->\n"
        f"<!-- EXPECTED_OUTPUT: {name} -->\n\n"
        f"# Depth Output: {name}\n\n"
        "## No Findings\n\n"
        + ("No exploitable issue was found for this assigned depth scope. " * 14)
        + "\n\n"
        "## Semantic Proof Checks\n\nNo reportable candidates required proof.\n\n"
        "## Graph Artifact Consumption\n\n"
        "- [GRAPH-ARTIFACT: UNAVAILABLE:caller_map.md] - absent\n"
        "- [GRAPH-ARTIFACT: UNAVAILABLE:callee_map.md] - absent\n"
        "- [GRAPH-ARTIFACT: UNAVAILABLE:state_write_map.md] - absent\n"
        "- [GRAPH-ARTIFACT: UNAVAILABLE:function_summary.md] - absent\n\n"
        "## Chain Summary\n\n"
        "| Finding ID | Postconditions Created | Preconditions Required | Cross-Domain Dependencies |\n"
        "| --- | --- | --- | --- |\n"
        "| none | none | none | none |\n\n"
        "<!-- PLAMEN_FINDINGS_COUNT: 0 -->\n"
        "<!-- PLAMEN_STATUS: COMPLETE -->\n",
        encoding="utf-8",
    )


def test_depth_worker_jobs_are_mode_and_pipeline_aware(tmp_path: Path):
    sp = tmp_path / ".scratchpad"
    _fresh(sp)

    sc_light = D._depth_worker_jobs(sp, {"pipeline": "sc", "mode": "light"})
    assert [job["output"] for job in sc_light] == [
        "depth_token_flow_findings.md",
        "depth_state_trace_findings.md",
        "depth_edge_case_findings.md",
        "depth_external_findings.md",
    ]

    sc_core = D._depth_worker_jobs(sp, {"pipeline": "sc", "mode": "core"})
    outputs = {job["output"] for job in sc_core}
    assert "blind_spot_a_findings.md" in outputs
    assert "validation_sweep_findings.md" in outputs
    assert "design_stress_findings.md" not in outputs

    l1_thorough = D._depth_worker_jobs(sp, {"pipeline": "l1", "mode": "thorough"})
    l1_outputs = {job["output"] for job in l1_thorough}
    assert "depth_consensus_invariant_findings.md" in l1_outputs
    assert "depth_network_surface_findings.md" in l1_outputs
    assert "skill_execution_checklist.md" in l1_outputs


def test_depth_worker_batch_rate_limit_fails_fast(tmp_path: Path, monkeypatch):
    sp = tmp_path / ".scratchpad"
    _fresh(sp)
    stop_event = threading.Event()
    cancel_called = {"value": False}

    jobs = [
        {
            "agent_id": "depth-token-flow",
            "role": "token_flow",
            "output": "depth_token_flow_findings.md",
            "category": "core",
            "focus": "token flow",
        },
        {
            "agent_id": "depth-state-trace",
            "role": "state_trace",
            "output": "depth_state_trace_findings.md",
            "category": "core",
            "focus": "state trace",
        },
    ]

    def _fake_worker(**kwargs):
        output = kwargs["job"]["output"]
        if output == "depth_token_flow_findings.md":
            return {"output": output, "rc": 1, "status": "rate_limited"}
        stop_event.wait(timeout=10)
        return {"output": output, "rc": -2, "status": "incomplete"}

    def _fake_cancel(pending_futs, executor):
        cancel_called["value"] = True
        stop_event.set()

    monkeypatch.setattr(D, "_run_single_depth_worker_pty", _fake_worker)
    monkeypatch.setattr(D, "_cancel_pending_worker_futures", _fake_cancel)

    started = time.time()
    rc, results = D._run_depth_worker_batch(
        scratchpad=sp,
        project_root=str(tmp_path),
        config={"mode": "light", "language": "evm", "pipeline": "sc"},
        phase=_phase(),
        base_cmd=["claude", "--session-id", "base"],
        env={},
        timeout=1.0,
        quiescence_s=0.0,
        jobs=jobs,
        attempt=1,
        pool_started=time.time(),
        retry_reasons_by_output={},
    )

    assert rc == 1
    assert cancel_called["value"]
    assert any(r.get("status") == "rate_limited" for r in results)
    assert time.time() - started < 2.0


def test_depth_worker_prompt_is_single_artifact_allowlist(tmp_path: Path):
    sp = tmp_path / ".scratchpad"
    _fresh(sp)
    job = D._depth_worker_jobs(sp, {"pipeline": "sc", "mode": "light"})[0]

    prompt = D._build_depth_worker_prompt(
        job=job,
        scratchpad=sp,
        project_root=str(tmp_path),
        config={"language": "evm", "mode": "light", "pipeline": "sc"},
        attempt=1,
    )

    assert "AGENT_ROW: depth-token-flow" in prompt
    assert "EXPECTED_OUTPUT: depth_token_flow_findings.md" in prompt
    assert "PLAMEN_STATUS: IN_PROGRESS" in prompt
    assert "PLAMEN_STATUS: COMPLETE" in prompt
    assert "do not spawn" in prompt.lower()
    assert "Task(" not in prompt
    assert "run_in_background" not in prompt
    forbidden = [
        "rag_sweep",
        "verification",
        "report_",
        "AUDIT_REPORT.md",
    ]
    hits = [token for token in forbidden if token.lower() in prompt.lower()]
    assert not hits


def test_depth_worker_prompt_makes_perturbation_gate_top_level_contract(tmp_path: Path):
    sp = tmp_path / ".scratchpad"
    _fresh(sp)
    job = D._depth_worker_jobs(sp, {"pipeline": "sc", "mode": "thorough"})[0]

    prompt = D._build_depth_worker_prompt(
        job=job,
        scratchpad=sp,
        project_root=str(tmp_path),
        config={"language": "evm", "mode": "thorough", "pipeline": "sc"},
        attempt=1,
    )

    assert "hard structural gate" in prompt
    assert "### Perturbation Block - <finding_id>" in prompt
    assert "A separate `perturbation_findings.md`" in prompt
    assert "self-check" in prompt


def test_depth_worker_retry_prompt_repairs_all_perturbation_blocks(tmp_path: Path):
    sp = tmp_path / ".scratchpad"
    _fresh(sp)
    job = D._depth_worker_jobs(sp, {"pipeline": "sc", "mode": "thorough"})[0]

    prompt = D._build_depth_worker_prompt(
        job=job,
        scratchpad=sp,
        project_root=str(tmp_path),
        config={"language": "evm", "mode": "thorough", "pipeline": "sc"},
        attempt=2,
        retry_reasons=[
            "status=structural_fail",
            "missing perturbation block(s) for Medium+ CONFIRMED finding(s): DT-3",
        ],
    )

    assert "Perturbation Repair Is Mandatory" in prompt
    assert "Repair ALL Medium/Critical/High CONFIRMED findings" in prompt
    assert "If you rename, split, merge, or add" in prompt
    assert "Do not mark the file COMPLETE" in prompt


def test_depth_worker_retry_prompt_keeps_exact_structural_reason_bounded(
    tmp_path: Path,
):
    sp = tmp_path / ".scratchpad"
    _fresh(sp)
    job = D._depth_worker_jobs(sp, {"pipeline": "sc", "mode": "light"})[2]
    exact_reason = (
        "no '## Finding [' / '### Finding [' blocks (and no "
        "'## Findings' section) and no '## No Findings' / "
        "'## Negative Result' rationale -- artifact is empty/incomplete"
    )
    oversized_tail = "Z" * 5000

    prompt = D._build_depth_worker_prompt(
        job=job,
        scratchpad=sp,
        project_root=str(tmp_path),
        config={"language": "evm", "mode": "light", "pipeline": "sc"},
        attempt=2,
        retry_reasons=["status=structural_fail", exact_reason, oversized_tail],
    )

    assert exact_reason in prompt
    assert oversized_tail not in prompt
    retry_section = prompt.split("## Previous Gate Failure", 1)[1].split(
        "## Methodology", 1
    )[0]
    assert len(retry_section) <= D._WORKER_RETRY_TOTAL_MAX_CHARS + 256


def test_depth_worker_validation_result_preserves_structural_gate_reason(
    tmp_path: Path,
):
    sp = tmp_path / ".scratchpad"
    _fresh(sp)
    job = D._depth_worker_jobs(sp, {"pipeline": "sc", "mode": "light"})[2]
    output = job["output"]
    (sp / "_depth_worker_pool_contract.json").write_text(
        json.dumps({
            "phase": "depth",
            "canonical_outputs": [output],
            "jobs": [job],
        }),
        encoding="utf-8",
    )
    (sp / output).write_text(
        f"<!-- PLAMEN_ARTIFACT: {output} -->\n"
        f"<!-- PLAMEN_OWNER: {job['agent_id']} -->\n"
        "<!-- PLAMEN_STATUS: IN_PROGRESS -->\n"
        "<!-- PLAMEN_PHASE: depth -->\n"
        "<!-- PLAMEN_VERSION: 1 -->\n"
        f"<!-- AGENT_ROW: {job['agent_id']} -->\n"
        f"<!-- EXPECTED_OUTPUT: {output} -->\n\n"
        "# Edge-case analysis\n\n"
        + ("Substantive boundary analysis without a disposition block. " * 20)
        + "\n\n<!-- PLAMEN_STATUS: COMPLETE -->\n",
        encoding="utf-8",
    )

    status, reasons = D._depth_worker_validation_result(
        sp, _phase(), job, final_turn_complete=True
    )

    assert status == "structural_fail"
    assert any("artifact is empty/incomplete" in reason for reason in reasons)


def test_depth_worker_pool_feeds_structural_reason_to_next_attempt(
    tmp_path: Path, monkeypatch
):
    sp = tmp_path / ".scratchpad"
    _fresh(sp)
    jobs = D._depth_worker_jobs(sp, {"pipeline": "sc", "mode": "light"})
    target = jobs[2]
    for job in jobs:
        if job is not target:
            _complete(sp, job["output"], job["agent_id"])
    retry_feedback: list[list[str]] = []

    def _fake_worker(**kwargs):
        job = kwargs["job"]
        reasons = list(kwargs.get("retry_reasons") or [])
        retry_feedback.append(reasons)
        if len(retry_feedback) == 1:
            output = job["output"]
            (sp / output).write_text(
                f"<!-- PLAMEN_ARTIFACT: {output} -->\n"
                f"<!-- PLAMEN_OWNER: {job['agent_id']} -->\n"
                "<!-- PLAMEN_STATUS: IN_PROGRESS -->\n"
                "<!-- PLAMEN_PHASE: depth -->\n"
                "<!-- PLAMEN_VERSION: 1 -->\n"
                f"<!-- AGENT_ROW: {job['agent_id']} -->\n"
                f"<!-- EXPECTED_OUTPUT: {output} -->\n\n"
                "# Edge-case analysis\n\n"
                + ("Substantive analysis without a disposition block. " * 20)
                + "\n\n<!-- PLAMEN_STATUS: COMPLETE -->\n",
                encoding="utf-8",
            )
        else:
            _complete(sp, job["output"], job["agent_id"])
        status, gate_reasons = D._depth_worker_validation_result(
            sp, kwargs["phase"], job, final_turn_complete=True
        )
        return {
            "output": job["output"],
            "rc": 0 if status == "complete" else -2,
            "status": status,
            "reasons": gate_reasons,
        }

    monkeypatch.setattr(D, "_run_single_depth_worker_pty", _fake_worker)

    rc = D._run_depth_worker_pool_pty(
        scratchpad=sp,
        project_root=str(tmp_path),
        config={"mode": "light", "language": "evm", "pipeline": "sc"},
        phase=_phase(),
        base_cmd=["claude", "--session-id", "base"],
        env={},
        timeout=1.0,
        quiescence_s=0.0,
        attempt=1,
    )

    assert rc == 0
    assert retry_feedback[0] == []
    assert "status=structural_fail" in retry_feedback[1]
    assert any(
        "artifact is empty/incomplete" in reason
        for reason in retry_feedback[1]
    )


def test_depth_worker_contract_rejects_cross_row_owner(tmp_path: Path):
    sp = tmp_path / ".scratchpad"
    _fresh(sp)
    jobs = D._depth_worker_jobs(sp, {"pipeline": "sc", "mode": "light"})
    (sp / "_depth_worker_pool_contract.json").write_text(
        json.dumps({
            "phase": "depth",
            "canonical_outputs": [job["output"] for job in jobs],
            "jobs": jobs,
        }),
        encoding="utf-8",
    )
    _complete(sp, "depth_token_flow_findings.md", "depth-state-trace")

    statuses = {
        row["name"]: row
        for row in D.compute_depth_row_statuses(sp, _phase())
    }

    row = statuses["depth_token_flow_findings.md"]
    assert row["status"] == "structural_fail"
    assert any("PLAMEN_OWNER" in reason for reason in row["reasons"])
    assert any("AGENT_ROW" in reason for reason in row["reasons"])


def test_depth_worker_gate_rejects_missing_perturbation_block(tmp_path: Path):
    sp = tmp_path / ".scratchpad"
    _fresh(sp)
    _complete(sp, "depth_state_trace_findings.md", "depth-state-trace")
    _complete(sp, "depth_edge_case_findings.md", "depth-edge-case")
    _complete(sp, "depth_external_findings.md", "depth-external")
    (sp / "depth_token_flow_findings.md").write_text(
        "<!-- PLAMEN_ARTIFACT: depth_token_flow_findings.md -->\n"
        "<!-- PLAMEN_OWNER: depth-token-flow -->\n"
        "<!-- PLAMEN_STATUS: IN_PROGRESS -->\n"
        "<!-- PLAMEN_PHASE: depth -->\n"
        "<!-- PLAMEN_VERSION: 1 -->\n"
        "<!-- AGENT_ROW: depth-token-flow -->\n"
        "<!-- EXPECTED_OUTPUT: depth_token_flow_findings.md -->\n\n"
        "# Depth Token Flow Findings\n\n"
        "## Finding [DT-1]: Missing comparison\n"
        "**Verdict**: CONFIRMED\n"
        "**Severity**: Medium\n\n"
        + ("Detailed trace evidence. " * 30)
        + "\n\n<!-- PLAMEN_STATUS: COMPLETE -->\n",
        encoding="utf-8",
    )

    statuses = {
        row["name"]: row
        for row in D.compute_depth_row_statuses(sp, _phase())
    }

    row = statuses["depth_token_flow_findings.md"]
    assert row["status"] == "structural_fail"
    assert any("missing perturbation block" in reason for reason in row["reasons"])


def test_depth_worker_gate_accepts_inline_perturbation_block(tmp_path: Path):
    sp = tmp_path / ".scratchpad"
    _fresh(sp)
    (sp / "depth_token_flow_findings.md").write_text(
        "<!-- PLAMEN_ARTIFACT: depth_token_flow_findings.md -->\n"
        "<!-- PLAMEN_OWNER: depth-token-flow -->\n"
        "<!-- PLAMEN_STATUS: IN_PROGRESS -->\n"
        "<!-- PLAMEN_PHASE: depth -->\n"
        "<!-- PLAMEN_VERSION: 1 -->\n"
        "<!-- AGENT_ROW: depth-token-flow -->\n"
        "<!-- EXPECTED_OUTPUT: depth_token_flow_findings.md -->\n\n"
        "# Depth Token Flow Findings\n\n"
        "## Finding [DT-1]: Missing comparison\n"
        "**Verdict**: CONFIRMED\n"
        "**Severity**: Medium\n\n"
        + ("Detailed trace evidence. " * 30)
        + "\n\n### Perturbation Block - DT-1\n"
        "| Operator | Target | Result |\n"
        "| --- | --- | --- |\n"
        "| SIBLING | sibling function | Same invariant fails |\n\n"
        "<!-- PLAMEN_STATUS: COMPLETE -->\n",
        encoding="utf-8",
    )
    _complete(sp, "depth_state_trace_findings.md", "depth-state-trace")
    _complete(sp, "depth_edge_case_findings.md", "depth-edge-case")
    _complete(sp, "depth_external_findings.md", "depth-external")

    statuses = {
        row["name"]: row
        for row in D.compute_depth_row_statuses(sp, _phase())
    }

    assert statuses["depth_token_flow_findings.md"]["status"] == "complete"


def test_depth_worker_pool_runs_only_open_standard_rows(tmp_path: Path, monkeypatch):
    sp = tmp_path / ".scratchpad"
    _fresh(sp)
    jobs = D._depth_worker_jobs(sp, {"pipeline": "sc", "mode": "light"})
    _complete(sp, "depth_state_trace_findings.md", "depth-state-trace")
    _complete(sp, "depth_edge_case_findings.md", "depth-edge-case")
    _complete(sp, "depth_external_findings.md", "depth-external")
    calls: list[str] = []

    def _fake_worker(**kwargs):
        job = kwargs["job"]
        calls.append(job["output"])
        _complete(sp, job["output"], job["agent_id"])
        return {"output": job["output"], "rc": 0, "status": "complete"}

    monkeypatch.setattr(D, "_run_single_depth_worker_pty", _fake_worker)

    rc = D._run_depth_worker_pool_pty(
        scratchpad=sp,
        project_root=str(tmp_path),
        config={"mode": "light", "language": "evm", "pipeline": "sc"},
        phase=_phase(),
        base_cmd=["claude", "--session-id", "base"],
        env={},
        timeout=1.0,
        quiescence_s=0.0,
        attempt=1,
    )

    assert rc == 0
    assert calls == ["depth_token_flow_findings.md"]


def test_depth_worker_input_snapshot_restores_prior_phase_artifact(tmp_path: Path):
    sp = tmp_path / ".scratchpad"
    _fresh(sp)
    prior = sp / "analysis_percontract_3.md"
    prior.write_text("original prior-phase analysis\n", encoding="utf-8")
    output_names = {"depth_token_flow_findings.md"}

    snapshot = D._snapshot_worker_input_artifacts(sp, output_names)
    prior.write_text("worker-corrupted prior-phase analysis\n", encoding="utf-8")

    restored = D._restore_worker_input_artifacts(sp, snapshot)

    assert restored == ["analysis_percontract_3.md"]
    assert prior.read_text(encoding="utf-8") == "original prior-phase analysis\n"


# ---------------------------------------------------------------------------
# L1-4 / L1-5 — L1 scanner floor + sibling propagation job dispatch
# ---------------------------------------------------------------------------

_L1_SCANNER_OUTPUTS = (
    "blind_spot_a_findings.md",
    "blind_spot_b_findings.md",
    "blind_spot_c_findings.md",
    "validation_sweep_findings.md",
)


def test_depth_worker_jobs_l1_core_includes_scanner_and_sibling(tmp_path: Path):
    sp = tmp_path / ".scratchpad"
    _fresh(sp)
    jobs = D._depth_worker_jobs(sp, {"pipeline": "l1", "mode": "core"})
    outputs = {job["output"] for job in jobs}
    for name in (*_L1_SCANNER_OUTPUTS, "sibling_propagation_findings.md"):
        assert name in outputs, f"missing {name} in L1 core jobs: {outputs}"
    by_output = {job["output"]: job for job in jobs}
    for name in _L1_SCANNER_OUTPUTS:
        assert by_output[name]["category"] == "scanner"
    assert by_output["sibling_propagation_findings.md"]["category"] == "sibling"


def test_depth_worker_jobs_l1_thorough_includes_scanner_and_sibling(tmp_path: Path):
    sp = tmp_path / ".scratchpad"
    _fresh(sp)
    jobs = D._depth_worker_jobs(sp, {"pipeline": "l1", "mode": "thorough"})
    outputs = {job["output"] for job in jobs}
    for name in (
        *_L1_SCANNER_OUTPUTS,
        "sibling_propagation_findings.md",
        "design_stress_findings.md",
    ):
        assert name in outputs, f"missing {name} in L1 thorough jobs: {outputs}"


def test_depth_worker_jobs_l1_light_excludes_scanner_and_sibling(tmp_path: Path):
    sp = tmp_path / ".scratchpad"
    _fresh(sp)
    jobs = D._depth_worker_jobs(sp, {"pipeline": "l1", "mode": "light"})
    outputs = {job["output"] for job in jobs}
    for name in (*_L1_SCANNER_OUTPUTS, "sibling_propagation_findings.md"):
        assert name not in outputs, f"unexpected {name} in L1 light jobs: {outputs}"


@pytest.mark.parametrize(
    ("pipeline", "language"),
    (("sc", "evm"), ("l1", "go")),
)
def test_sibling_propagation_waits_for_complete_producer_barrier(
    tmp_path: Path,
    monkeypatch,
    pipeline: str,
    language: str,
):
    sp = tmp_path / ".scratchpad"
    _fresh(sp)
    jobs = D._depth_worker_jobs(
        sp,
        {"pipeline": pipeline, "language": language, "mode": "core"},
    )
    sibling = next(job for job in jobs if job["role"] == "sibling_propagation")
    producers = [
        job
        for job in jobs
        if job["category"] in D._DEPTH_PRODUCER_CATEGORIES
    ]
    assert producers
    assert sibling["role"] in D._DEPTH_POST_PRODUCER_ROLES

    complete_outputs: set[str] = set()
    monkeypatch.setattr(
        D,
        "_depth_worker_output_complete",
        lambda _sp, _phase, job, **_kwargs: job["output"] in complete_outputs,
    )

    ready = D._depth_jobs_ready_after_producer_barrier(
        sp, _phase(), jobs, jobs
    )
    assert sibling not in ready

    complete_outputs.update(job["output"] for job in producers)
    ready = D._depth_jobs_ready_after_producer_barrier(
        sp, _phase(), jobs, jobs
    )
    assert sibling in ready

    # A missing or quarantined/incomplete predecessor is absent from the
    # complete set and must close the aggregate-consumer barrier again.
    complete_outputs.remove(producers[0]["output"])
    ready = D._depth_jobs_ready_after_producer_barrier(
        sp, _phase(), jobs, jobs
    )
    assert sibling not in ready


def test_depth_worker_prompt_scanner_points_to_l1_heading(tmp_path: Path):
    sp = tmp_path / ".scratchpad"
    _fresh(sp)
    jobs = D._depth_worker_jobs(sp, {"pipeline": "l1", "mode": "core"})
    job = next(j for j in jobs if j["output"] == "blind_spot_a_findings.md")

    prompt = D._build_depth_worker_prompt(
        job=job,
        scratchpad=sp,
        project_root=str(tmp_path),
        config={"language": "go", "mode": "core", "pipeline": "l1"},
        attempt=1,
    )

    assert "## Scanner: Boundary and Wire Format" in prompt
    assert "prompts/l1/phase4b-scanner-templates.md" in prompt.replace("\\", "/")
    assert "EXPECTED_OUTPUT: blind_spot_a_findings.md" in prompt


def test_depth_worker_prompt_scanner_points_to_sc_heading(tmp_path: Path):
    sp = tmp_path / ".scratchpad"
    _fresh(sp)
    jobs = D._depth_worker_jobs(sp, {"pipeline": "sc", "mode": "core"})
    job = next(j for j in jobs if j["output"] == "blind_spot_a_findings.md")

    prompt = D._build_depth_worker_prompt(
        job=job,
        scratchpad=sp,
        project_root=str(tmp_path),
        config={"language": "evm", "mode": "core", "pipeline": "sc"},
        attempt=1,
    )

    assert "## Blind Spot Scanner A" in prompt
    assert "prompts/evm/phase4b-scanner-templates.md" in prompt.replace("\\", "/")


def test_l1_never_cut_scanner_group_gate(tmp_path: Path):
    """A missing scanner artifact FAILS the L1 Core never-cut gate; writing
    all 4 makes it PASS (mirrors the SC blind-spot/validation-sweep floor)."""
    sp = tmp_path / ".scratchpad"
    sp.mkdir(parents=True, exist_ok=True)
    base_files = (
        "depth_consensus_invariant_findings.md",
        "depth_network_surface_findings.md",
        "depth_state_trace_findings.md",
        "depth_external_findings.md",
        "depth_edge_case_findings.md",
        "confidence_scores.md",
    )
    for f in base_files:
        (sp / f).write_text("# Findings\n\nSome content here.\n", encoding="utf-8")

    missing = D._assert_never_cut_artifacts(sp, D.l1_never_cut_groups("core"))
    assert any("blind_spot_a_findings.md" in m for m in missing), missing
    assert any("validation_sweep_findings.md" in m for m in missing), missing

    for f in _L1_SCANNER_OUTPUTS:
        (sp / f).write_text("# Findings\n\nSome content here.\n", encoding="utf-8")

    missing_after = D._assert_never_cut_artifacts(sp, D.l1_never_cut_groups("core"))
    assert missing_after == [], missing_after


def test_scanner_finding_promotes_to_inventory(tmp_path: Path):
    """A synthetic blind_spot_a_findings.md [BLIND-A-1] block ACTUALLY lands
    in findings_inventory.md via `_promote_depth_findings_to_inventory`."""
    sp = tmp_path / ".scratchpad"
    _fresh(sp)
    (sp / "blind_spot_a_findings.md").write_text(
        "<!-- PLAMEN_ARTIFACT: blind_spot_a_findings.md -->\n"
        "<!-- PLAMEN_OWNER: blind-spot-a -->\n"
        "<!-- PLAMEN_STATUS: IN_PROGRESS -->\n"
        "<!-- PLAMEN_PHASE: depth -->\n"
        "<!-- PLAMEN_VERSION: 1 -->\n"
        "<!-- AGENT_ROW: blind-spot-a -->\n"
        "<!-- EXPECTED_OUTPUT: blind_spot_a_findings.md -->\n\n"
        "### Finding [BLIND-A-1]: Missing length check before allocation\n"
        "**Verdict**: CONFIRMED\n"
        "**Severity**: High\n"
        "**Location**: p2p/codec.go:L120\n"
        "**Preferred Tag**: CODE-TRACE\n\n"
        "**Description**: " + ("Detailed trace evidence. " * 20) + "\n\n"
        "<!-- PLAMEN_STATUS: COMPLETE -->\n",
        encoding="utf-8",
    )

    promoted = D._promote_depth_findings_to_inventory(sp)

    assert "BLIND-A-1" in promoted, promoted
    inv_text = (sp / "findings_inventory.md").read_text(encoding="utf-8")
    assert "BLIND-A-1" in inv_text
    assert "### Finding [INV-" in inv_text
