"""Finite worker-prompt evidence and PhaseIO alignment regressions."""
from __future__ import annotations

from pathlib import Path
import hashlib

import claude_worker_prompt_consistency as C
import plamen_driver as D
import pytest
from phase_contract_compiler import extract_compiled_phase_io
from phase_io_contracts import resolve_phase_io_contract


def _config(root: Path, scratchpad: Path) -> dict[str, str]:
    return {
        "pipeline": "sc",
        "mode": "light",
        "language": "evm",
        "cli_backend": "claude",
        "project_root": str(root),
        "scratchpad": str(scratchpad),
    }


def _assert_static_consistency(
    prompt: str,
    *,
    phase: str,
    job: dict,
    root: Path,
    scratchpad: Path,
    config: dict,
) -> None:
    inputs = D._typed_worker_registered_input_paths(
        phase_name=phase,
        scratchpad=scratchpad,
        config=config,
        agent_id=str(job["agent_id"]),
        agent_role=str(job.get("role") or "") or None,
        output=str(job["output"]),
        work_category=str(job.get("category") or "*"),
        focus_area=str(job.get("focus_area") or job.get("focus") or ""),
    )
    methodology = D._trusted_methodology_paths_named_by_prompt(
        prompt, {"methodology_read_roots": [str(D.plamen_home())]}
    )
    issues = C.validate_claude_worker_prompt_consistency(
        prompt,
        phase_io_inputs=[*(scratchpad / name for name in inputs), *methodology],
        phase_io_outputs=[scratchpad / str(job["output"])],
        policy_tools=["Read", "Write", "Glob", "Grep"],
        safe_search_roots=[root / "src"],
        project_root=root,
        scratchpad_root=scratchpad,
    )
    assert issues == ()


def test_breadth_prompt_and_contract_share_one_exact_shard(tmp_path: Path):
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    (tmp_path / "src").mkdir()
    config = _config(tmp_path, scratchpad)
    job = {
        "agent_id": "B3",
        "focus_area": "cross_chain_integrity",
        "output": "analysis_cross_chain_integrity.md",
    }
    prompt = D._build_breadth_worker_prompt(
        job=job,
        scratchpad=scratchpad,
        project_root=str(tmp_path),
        config=config,
        attempt=1,
    )
    contract = extract_compiled_phase_io(prompt)
    shard = "scratchpad:opengrep_obligations_B3_cross_chain_integrity.md"
    assert shard in contract["immutable_inputs"]
    assert sum("opengrep_obligations_" in row for row in contract["immutable_inputs"]) == 1
    assert "as needed" not in prompt
    assert "MUST use `[B3-<N>]`" in prompt
    assert "add another hyphen-delimited" in prompt
    _assert_static_consistency(
        prompt, phase="breadth", job=job, root=tmp_path,
        scratchpad=scratchpad, config=config,
    )


def test_rescan_and_scanner_depth_have_finite_registered_evidence(tmp_path: Path):
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    (tmp_path / "src").mkdir()
    config = _config(tmp_path, scratchpad)
    (scratchpad / "rescan_manifest.md").write_text(
        "# Rescan Manifest\n\n- analysis_rescan_1.md\n",
        encoding="utf-8",
    )
    rescan_job = D._rescan_worker_jobs(scratchpad)[0]
    rescan_prompt = D._build_rescan_worker_prompt(
        job=rescan_job,
        scratchpad=scratchpad,
        project_root=str(tmp_path),
        config=config,
        attempt=1,
    )
    assert "do not search, glob, list,\nor enumerate the scratchpad root" in rescan_prompt
    assert "findings_inventory.md" not in rescan_prompt
    assert "MUST use `[RS1-<N>]`" in rescan_prompt
    _assert_static_consistency(
        rescan_prompt, phase="rescan", job=rescan_job, root=tmp_path,
        scratchpad=scratchpad, config=config,
    )
    config["mode"] = "core"
    for name in ("constraint_variables.md", "modifiers.md"):
        (scratchpad / name).write_text(f"# {name}\n", encoding="utf-8")
    scanner_job = next(
        job for job in D._depth_worker_jobs(scratchpad, config)
        if job.get("category") == "scanner"
    )
    depth_prompt = D._build_depth_worker_prompt(
        job=scanner_job,
        scratchpad=scratchpad,
        project_root=str(tmp_path),
        config=config,
        attempt=1,
    )
    inputs = set(extract_compiled_phase_io(depth_prompt)["immutable_inputs"])
    for name in (
        "attack_surface.md", "constraint_variables.md", "function_list.md",
        "modifiers.md", "state_variables.md",
    ):
        assert f"scratchpad:{name}" in inputs
    _assert_static_consistency(
        depth_prompt, phase="depth", job=scanner_job, root=tmp_path,
        scratchpad=scratchpad, config=config,
    )


def test_sc_phase_graph_runs_rescan_before_inventory():
    names = [phase.name for phase in D.SC_PHASES]
    assert names.index("breadth") < names.index("rescan_prepare")
    assert names.index("rescan_prepare") < names.index("rescan")
    assert names.index("rescan") < names.index("inventory_prepare")
    assert names.index("inventory_prepare") < names.index("inventory")


def test_standard_depth_embeds_leaf_projection_without_coordinator_calls(
    tmp_path: Path,
):
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    (tmp_path / "src").mkdir()
    config = _config(tmp_path, scratchpad)
    job = D._depth_worker_jobs(scratchpad, config)[0]
    prompt = D._build_depth_worker_prompt(
        job=job,
        scratchpad=scratchpad,
        project_root=str(tmp_path),
        config=config,
        attempt=1,
    )
    assert "Driver-Rendered Iteration-1 Worker Methodology" in prompt
    assert "Task(" not in prompt
    assert "depth_{type}_findings.md" not in prompt
    assert "_mechanical_graph.json" in prompt
    assert "depth_candidates.md" in prompt
    for required_graph in (
        "caller_map.md",
        "callee_map.md",
        "state_write_map.md",
        "function_summary.md",
    ):
        assert required_graph in prompt
    _assert_static_consistency(
        prompt, phase="depth", job=job, root=tmp_path,
        scratchpad=scratchpad, config=config,
    )


def test_rescan_phaseio_is_complete_before_inventory_and_rejects_foreign_inputs(
    tmp_path: Path,
):
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    config = _config(tmp_path, scratchpad)
    job = {
        "agent_id": "RS-1",
        "role": "rescan",
        "focus_area": "auth",
        "output": "analysis_rescan_auth.md",
    }
    exact = D._typed_worker_registered_input_paths(
        phase_name="rescan",
        scratchpad=scratchpad,
        config=config,
        agent_id=job["agent_id"],
        agent_role=job["role"],
        output=job["output"],
        work_category="rescan",
        focus_area=job["focus_area"],
    )
    assert "findings_inventory.md" not in exact
    assert not (scratchpad / "findings_inventory.md").exists()
    contract = resolve_phase_io_contract(
        pipeline="sc", mode="light", ecosystem="evm",
        backend="claude", phase="rescan", work_unit_id="worker.rs-1",
        exact_outputs=(job["output"],), exact_inputs=exact,
    )
    assert "scratchpad:findings_inventory.md" not in contract.immutable_inputs
    with pytest.raises(ValueError, match="unregistered prior artifacts"):
        resolve_phase_io_contract(
            pipeline="sc", mode="light", ecosystem="evm",
            backend="claude", phase="rescan", work_unit_id="worker.rs-1",
            exact_outputs=(job["output"],),
            exact_inputs=(*exact, "threat_model.md"),
        )


def test_inventory_planning_consumes_rescan_and_percontract_outputs(
    tmp_path: Path,
):
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    for name in (
        "analysis_primary.md",
        "analysis_rescan_1.md",
        "analysis_percontract_Gateway.md",
    ):
        (scratchpad / name).write_text(
            f"## Finding [{name[:2].upper()}-1]: retained candidate\n\n"
            "**Description**: substantive candidate evidence.\n",
            encoding="utf-8",
        )

    plan = D.ensure_inventory_shard_plan(scratchpad, 70, 3)
    assigned = {
        str(row["path"])
        for rows in plan.values()
        for row in rows
    }
    assert assigned == {
        "analysis_primary.md",
        "analysis_rescan_1.md",
        "analysis_percontract_Gateway.md",
    }


@pytest.mark.parametrize("phase", ("breadth", "rescan", "depth"))
def test_legacy_worker_fallbacks_are_pipeline_specific(phase: str):
    common = {
        "mode": "light",
        "ecosystem": "evm",
        "backend": "claude",
        "phase": phase,
        "work_unit_id": "worker.compatibility",
        "exact_outputs": (f"{'depth' if phase == 'depth' else 'analysis'}_compatibility.md",),
    }
    sc = resolve_phase_io_contract(pipeline="sc", **common)
    l1 = resolve_phase_io_contract(pipeline="l1", **common)
    sc_inputs = set(sc.immutable_inputs)
    l1_inputs = set(l1.immutable_inputs)

    assert "scratchpad:contract_inventory.md" in sc_inputs
    assert "scratchpad:contract_inventory.md" not in l1_inputs
    assert "scratchpad:subsystem_map.md" in l1_inputs
    assert "scratchpad:subsystem_map.md" not in sc_inputs
    if phase == "rescan":
        assert "scratchpad:opengrep_findings.md" in sc_inputs
        assert "scratchpad:opengrep_findings.md" not in l1_inputs
        assert "scratchpad:opengrep_hits_ranked.md" in l1_inputs
        assert "scratchpad:opengrep_hits_ranked.md" not in sc_inputs
    if phase == "depth":
        assert "scratchpad:security_obligations.md" in sc_inputs
        assert "scratchpad:security_obligations.md" not in l1_inputs
        assert "scratchpad:instantiation.json" in l1_inputs
        assert "scratchpad:instantiation.json" not in sc_inputs


def test_exact_depth_inputs_reject_opposing_pipeline_evidence(tmp_path: Path):
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    for pipeline, forbidden in (
        ("sc", "opengrep_hits_ranked.md"),
        ("l1", "opengrep_findings.md"),
    ):
        config = _config(tmp_path, scratchpad)
        config["pipeline"] = pipeline
        job = D._depth_worker_jobs(scratchpad, config)[0]
        exact = D._typed_worker_registered_input_paths(
            phase_name="depth",
            scratchpad=scratchpad,
            config=config,
            agent_id=str(job["agent_id"]),
            agent_role=str(job.get("role") or ""),
            output=str(job["output"]),
            work_category=str(job.get("category") or "*"),
            focus_area=str(job.get("focus_area") or job.get("focus") or ""),
        )
        with pytest.raises(ValueError, match="unregistered evidence"):
            resolve_phase_io_contract(
                pipeline=pipeline,
                mode="light",
                ecosystem="evm",
                backend="claude",
                phase="depth",
                work_unit_id="worker.cross-pipeline",
                exact_outputs=(str(job["output"]),),
                exact_inputs=(*exact, forbidden),
            )


@pytest.mark.parametrize("pipeline", ("sc", "l1"))
@pytest.mark.parametrize("mode", ("core", "thorough"))
def test_every_depth_role_renders_with_its_exact_registered_inputs(
    tmp_path: Path, pipeline: str, mode: str,
):
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    (tmp_path / "src").mkdir()
    config = _config(tmp_path, scratchpad)
    config.update({
        "pipeline": pipeline,
        "mode": mode,
        "language": "rust" if pipeline == "l1" else "evm",
    })
    for job in D._depth_worker_jobs(scratchpad, config):
        prompt = D._build_depth_worker_prompt(
            job=job,
            scratchpad=scratchpad,
            project_root=str(tmp_path),
            config=config,
            attempt=1,
        )
        compiled = set(extract_compiled_phase_io(prompt)["immutable_inputs"])
        selected = D._typed_worker_registered_input_paths(
            phase_name="depth",
            scratchpad=scratchpad,
            config=config,
            agent_id=str(job["agent_id"]),
            agent_role=str(job.get("role") or ""),
            output=str(job["output"]),
            work_category=str(job.get("category") or "*"),
            focus_area=str(job.get("focus_area") or job.get("focus") or ""),
        )
        assert compiled == {f"scratchpad:{name}" for name in selected}
        _assert_static_consistency(
            prompt,
            phase="depth",
            job=job,
            root=tmp_path,
            scratchpad=scratchpad,
            config=config,
        )


def test_impact_map_is_a_bound_scratchpad_projection_with_source_digest(
    tmp_path: Path,
):
    project = tmp_path / "project with spaces"
    scratchpad = project / ".scratchpad"
    scratchpad.mkdir(parents=True)
    (project / "src").mkdir()
    source = project / "impact_map.md"
    first = b"# Impact map\n\n| Payable impacts | Tier |\n|---|---|\n| loss | high |\n"
    source.write_bytes(first)
    config = _config(project, scratchpad)
    job = {
        "agent_id": "B3",
        "focus_area": "cross_chain_integrity",
        "output": "analysis_cross_chain_integrity.md",
    }

    prompt = D._build_breadth_worker_prompt(
        job=job,
        scratchpad=scratchpad,
        project_root=str(project),
        config=config,
        attempt=1,
    )
    identity = f"scratchpad:{D._IMPACT_MAP_EVIDENCE_FILE}"
    assert identity in extract_compiled_phase_io(prompt)["immutable_inputs"]
    assert str((scratchpad / D._IMPACT_MAP_EVIDENCE_FILE).as_posix()) in prompt
    assert "present in PROJECT_ROOT. Read it" not in prompt
    assert D._materialize_impact_map_evidence(
        project_root=str(project), scratchpad=scratchpad,
    ) == []
    projection = scratchpad / D._IMPACT_MAP_EVIDENCE_FILE
    payload = projection.read_bytes()
    assert hashlib.sha256(first).hexdigest().encode() in payload
    assert payload.endswith(first)

    second = first.replace(b"high", b"critical")
    source.write_bytes(second)
    assert D._materialize_impact_map_evidence(
        project_root=str(project), scratchpad=scratchpad,
    ) == []
    updated = projection.read_bytes()
    assert updated != payload
    assert hashlib.sha256(second).hexdigest().encode() in updated
    assert updated.endswith(second)


def test_absent_impact_map_adds_no_projection_or_phaseio_input(tmp_path: Path):
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    config = _config(tmp_path, scratchpad)
    selected = D._typed_worker_registered_input_paths(
        phase_name="breadth",
        scratchpad=scratchpad,
        config=config,
        agent_id="B3",
        output="analysis_cross_chain_integrity.md",
        focus_area="cross_chain_integrity",
    )
    assert D._IMPACT_MAP_EVIDENCE_FILE not in selected
    assert D._materialize_impact_map_evidence(
        project_root=str(tmp_path), scratchpad=scratchpad,
    ) == []
    assert not (scratchpad / D._IMPACT_MAP_EVIDENCE_FILE).exists()


def test_impact_map_projection_rejects_outside_symlink_and_oversize(
    tmp_path: Path,
):
    project = tmp_path / "project"
    scratchpad = project / ".scratchpad"
    scratchpad.mkdir(parents=True)
    outside = tmp_path / "outside.md"
    outside.write_text("# outside\n", encoding="utf-8")
    source = project / "impact_map.md"
    source.symlink_to(outside)
    issues = D._materialize_impact_map_evidence(
        project_root=str(project), scratchpad=scratchpad,
    )
    assert issues and "outside its exact project-root name" in issues[0]
    assert not (scratchpad / D._IMPACT_MAP_EVIDENCE_FILE).exists()

    source.unlink()
    source.write_bytes(b"x" * (D._IMPACT_MAP_MAX_BYTES + 1))
    issues = D._materialize_impact_map_evidence(
        project_root=str(project), scratchpad=scratchpad,
    )
    assert issues and "exceeds" in issues[0]
    assert not (scratchpad / D._IMPACT_MAP_EVIDENCE_FILE).exists()


def test_impact_map_projection_rejects_concurrent_source_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
):
    project = tmp_path / "project"
    scratchpad = project / ".scratchpad"
    scratchpad.mkdir(parents=True)
    source = project / "impact_map.md"
    source.write_text("# original impact\n", encoding="utf-8")
    original_read = D.rooted_io.read_bytes

    def read_then_mutate(path, **kwargs):
        raw = original_read(path, **kwargs)
        source.write_text("# mutated impact with different bytes\n", encoding="utf-8")
        return raw

    monkeypatch.setattr(D.rooted_io, "read_bytes", read_then_mutate)
    issues = D._materialize_impact_map_evidence(
        project_root=str(project), scratchpad=scratchpad,
    )
    assert issues and "changed during its bounded read" in issues[0]
    assert not (scratchpad / D._IMPACT_MAP_EVIDENCE_FILE).exists()


def test_impact_map_projection_rejects_symlink_destination_before_binding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
):
    project = tmp_path / "project"
    scratchpad = project / ".scratchpad"
    scratchpad.mkdir(parents=True)
    (project / "impact_map.md").write_text("# valid impact\n", encoding="utf-8")
    outside = tmp_path / "outside-destination.md"
    outside.write_text("do not overwrite\n", encoding="utf-8")
    destination = scratchpad / D._IMPACT_MAP_EVIDENCE_FILE
    destination.symlink_to(outside)

    issues = D._materialize_impact_map_evidence(
        project_root=str(project), scratchpad=scratchpad,
    )
    assert issues and "safe regular file" in issues[0]
    assert outside.read_text(encoding="utf-8") == "do not overwrite\n"
    assert destination.is_symlink()

    monkeypatch.setattr(
        D,
        "_bind_typed_model_worker_inputs",
        lambda **_kwargs: pytest.fail("PhaseIO binding followed unsafe destination"),
    )
    phase = D.Phase(
        name="breadth",
        section_markers=[],
        expected_artifacts=["analysis_*.md"],
        base_timeout_s=30,
    )
    fatal = D._prepare_typed_model_worker_launch(
        phase=phase,
        config=_config(project, scratchpad),
        scratchpad=scratchpad,
        project_root=str(project),
        agent_id="B1",
        output="analysis_test.md",
        timeout_s=30,
    )
    assert fatal and "safe regular file" in fatal[0]


def test_rooted_bounded_reader_rejects_oversized_regular_file(tmp_path: Path):
    source = tmp_path / "bounded.bin"
    source.write_bytes(b"x" * 65)
    with pytest.raises(D.rooted_io.RootedPathIOError, match="read bound"):
        D.rooted_io.read_bytes(source, max_bytes=64)
