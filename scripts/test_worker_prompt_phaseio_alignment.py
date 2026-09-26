"""Finite worker-prompt evidence and PhaseIO alignment regressions."""
from __future__ import annotations

import hashlib
from pathlib import Path

import claude_worker_prompt_consistency as C
import plamen_driver as D
import phase_io_contracts as PIO
import pytest
from phase_contract_compiler import extract_compiled_phase_io
from phase_io_contracts import resolve_phase_io_contract
from tool_coverage_ledger import (
    ToolOutcome,
    ToolOutcomeState,
    record_tool_outcome,
)


def _config(root: Path, scratchpad: Path) -> dict[str, str]:
    return {
        "pipeline": "sc",
        "mode": "light",
        "language": "evm",
        "cli_backend": "claude",
        "project_root": str(root),
        "scratchpad": str(scratchpad),
    }


def test_finding_format_methodology_pins_bind_exact_current_rule_bytes():
    rule = D.plamen_home() / "rules" / "finding-output-format.md"
    observed = hashlib.sha256(rule.read_bytes()).hexdigest()
    assert D._BOUND_BREADTH_METHODOLOGY_SOURCE_SHA256["finding_format"] == observed
    assert D._BOUND_RESCAN_METHODOLOGY_SOURCE_SHA256["finding_format"] == observed


def _materialize_governed_opengrep_absence(
    scratchpad: Path,
    *,
    state: ToolOutcomeState = ToolOutcomeState.UNAVAILABLE,
) -> None:
    record_tool_outcome(
        scratchpad,
        ToolOutcome.debt(
            "opengrep.static-analysis",
            "opengrep",
            state,
            "governed scanner absence for downstream PhaseIO test",
        ),
    )
    authority = D._opengrep_zero_row_authority(scratchpad)
    assert authority is not None
    D._write_opengrep_shard_file(
        scratchpad / D._OPENGREP_UNASSIGNED_FILENAME,
        owner_id="UNASSIGNED",
        focus_area="unassigned",
        rows=[],
        unassigned=True,
        absence_authority=authority,
    )


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


def test_da_iter2_prompt_and_phaseio_bind_post_wave_denominator(tmp_path: Path):
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    (tmp_path / "src").mkdir()
    for name in (
        "notread_priority_gaps.md",
        "perturbation_findings.md",
    ):
        (scratchpad / name).write_text(f"# {name}\n", encoding="utf-8")
    config = {
        **_config(tmp_path, scratchpad),
        "mode": "thorough",
    }
    job = {
        "agent_id": "depth-da-iter2",
        "role": "da_iter2",
        "output": "depth_da_iter2_findings.md",
        "category": "da",
        "focus": "adversarial second pass",
    }

    inputs = D._typed_worker_registered_input_paths(
        phase_name="depth",
        scratchpad=scratchpad,
        config=config,
        agent_id=job["agent_id"],
        agent_role=job["role"],
        output=job["output"],
        work_category=job["category"],
        focus_area=job["focus"],
    )
    prompt = D._build_depth_worker_prompt(
        job=job,
        scratchpad=scratchpad,
        project_root=str(tmp_path),
        config=config,
        attempt=1,
    )

    for name in (
        "confidence_scores.md",
        "step_execution_gaps_mechanical.md",
        "notread_priority_gaps.md",
        "perturbation_findings.md",
        "depth_token_flow_findings.md",
        "depth_state_trace_findings.md",
    ):
        assert name in inputs
        assert f"/{name}`" in prompt
    assert "do not substitute `depth_candidates.md`" in prompt
    normalized_prompt = " ".join(prompt.split())
    assert "pre-verification iteration-2 worker" in normalized_prompt
    assert "Their absence is `NOT_APPLICABLE`" in normalized_prompt
    assert (
        "Mechanical step-execution gaps are the separate mandatory input"
        in normalized_prompt
    )

    # The PhaseIO compiler accepts the same finite denominator used to render
    # the prompt; no post-wave artifact can disappear at the launch boundary.
    PIO._registered_worker_inputs(
        "depth",
        "sc",
        inputs,
        exact_outputs=(job["output"],),
        mode="thorough",
    )


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
    assert "## Intent and Harm Check" in prompt
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
    assert "## Intent and Harm Check" in rescan_prompt
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
    assert "## Intent and Harm Check" in depth_prompt
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


@pytest.mark.parametrize(
    ("agent_id", "role", "category", "output", "required_inputs"),
    (
        (
            "blind-spot-a", "blind_spot_a", "scanner",
            "blind_spot_a_findings.md", {"findings_inventory.md"},
        ),
        (
            "blind-spot-b", "blind_spot_b", "scanner",
            "blind_spot_b_findings.md", {"findings_inventory.md"},
        ),
        (
            "blind-spot-c", "blind_spot_c", "scanner",
            "blind_spot_c_findings.md", {"findings_inventory.md"},
        ),
        (
            "medusa-fuzz", "medusa_fuzz", "fuzz",
            "medusa_fuzz_findings.md",
            {"findings_inventory.md", "constraint_variables.md"},
        ),
        (
            "depth-state-trace", "state_trace", "standard",
            "depth_state_trace_findings.md", {"constraint_variables.md"},
        ),
        (
            "validation-sweep", "validation_sweep", "scanner",
            "validation_sweep_findings.md",
            {"depth_inventory_snapshot.md", "modifiers.md"},
        ),
    ),
)
def test_sc_depth_methodology_required_inputs_are_always_phaseio_registered(
    tmp_path: Path,
    agent_id: str,
    role: str,
    category: str,
    output: str,
    required_inputs: set[str],
):
    """A required methodology input cannot disappear when its file is absent."""
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    (tmp_path / "src").mkdir()
    config = _config(tmp_path, scratchpad)
    config["mode"] = "thorough"
    job = {
        "agent_id": agent_id,
        "role": role,
        "output": output,
        "category": category,
        "focus": f"exact {role} PhaseIO",
    }

    selected = D._typed_worker_registered_input_paths(
        phase_name="depth",
        scratchpad=scratchpad,
        config=config,
        agent_id=agent_id,
        agent_role=role,
        output=output,
        work_category=category,
        focus_area=str(job["focus"]),
    )
    assert required_inputs <= set(selected)

    resolved = resolve_phase_io_contract(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        phase="depth",
        work_unit_id=f"worker.{agent_id}",
        exact_outputs=(output,),
        exact_inputs=selected,
    )
    expected_identities = {f"scratchpad:{name}" for name in required_inputs}
    assert expected_identities <= set(resolved.immutable_inputs)

    prompt = D._build_depth_worker_prompt(
        job=job,
        scratchpad=scratchpad,
        project_root=str(tmp_path),
        config=config,
        attempt=1,
    )
    compiled_inputs = set(extract_compiled_phase_io(prompt)["immutable_inputs"])
    assert expected_identities <= compiled_inputs
    if role == "validation_sweep":
        frozen = (scratchpad / "depth_inventory_snapshot.md").as_posix()
        live = (scratchpad / "findings_inventory.md").as_posix()
        assert frozen in prompt
        assert live not in prompt
        assert "immutable byte-for-byte snapshot" in prompt
        assert "separately bound `modifiers.md`" in prompt


def test_constraint_projection_has_one_canonical_recon_producer_and_consumers():
    recon_phase = next(phase for phase in D.SC_PHASES if phase.name == "recon")

    assert "constraint_variables.md" in D._SC_RECON_DOWNSTREAM_INPUTS
    assert "constraint_variables.md" in PIO._SC_RECON_EVIDENCE_INPUTS
    assert "constraint_variables.md" in PIO._RECON_CANONICAL_OUTPUTS
    assert "constraint_variables.md" in recon_phase.expected_artifacts


def test_modifier_map_has_canonical_recon_producer_and_depth_consumer():
    recon_phase = next(phase for phase in D.SC_PHASES if phase.name == "recon")

    assert "modifiers.md" in D._SC_RECON_WORKER_INPUTS
    assert "modifiers.md" in D._SC_RECON_DOWNSTREAM_INPUTS
    assert "modifiers.md" in PIO._SC_RECON_EVIDENCE_INPUTS
    assert "modifiers.md" in PIO._RECON_CANONICAL_OUTPUTS
    assert "modifiers.md" in recon_phase.expected_artifacts


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


def test_depth_return_protocol_is_owned_only_by_driver(tmp_path: Path):
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    (tmp_path / "src").mkdir()
    config = _config(tmp_path, scratchpad)
    role_path = D.plamen_home() / "agents" / "depth-edge-case.md"
    assert "h2:return-protocol" not in D._skill_checklist_step_ids(role_path)

    job = {
        "agent_id": "depth-edge-case",
        "role": "edge_case",
        "output": "depth_edge_case_findings.md",
        "category": "standard",
        "focus": "edge cases",
    }
    prompt = D._build_depth_worker_prompt(
        job=job,
        scratchpad=scratchpad,
        project_root=str(tmp_path),
        config=config,
        attempt=1,
    )
    assert "## Return Protocol" not in role_path.read_text(encoding="utf-8")
    assert "legacy role methodology is transport" not in prompt
    assert "`DONE: depth_edge_case_findings.md complete`" in prompt


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


@pytest.mark.parametrize("phase", ("rescan", "depth"))
def test_sc_downstream_uses_governed_absence_despite_stale_raw_and_ledger_growth(
    tmp_path: Path,
    phase: str,
):
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    config = _config(tmp_path, scratchpad)
    _materialize_governed_opengrep_absence(scratchpad)
    (scratchpad / "opengrep_findings.md").write_text(
        "# stale scanner output\n\n| Rule | Severity | Location | Notes |\n",
        encoding="utf-8",
    )
    # An unrelated later tool outcome changes the aggregate ledger digest but
    # must not invalidate the stable OpenGrep outcome-specific authority.
    record_tool_outcome(
        scratchpad,
        ToolOutcome.debt(
            "slither.evm-reference-graph",
            "slither",
            ToolOutcomeState.UNAVAILABLE,
            "unrelated optional graph tool unavailable",
        ),
    )

    exact = D._typed_worker_registered_input_paths(
        phase_name=phase,
        scratchpad=scratchpad,
        config=config,
        agent_id="RS-1" if phase == "rescan" else "D1",
        agent_role="rescan" if phase == "rescan" else "token_flow",
        output=(
            "analysis_rescan_auth.md"
            if phase == "rescan" else "depth_token_flow_findings.md"
        ),
        work_category="rescan" if phase == "rescan" else "standard",
        focus_area="auth" if phase == "rescan" else "token flow",
    )
    assert D._OPENGREP_UNASSIGNED_FILENAME in exact
    assert "opengrep_findings.md" not in exact
    if phase == "rescan":
        per_contract = D._typed_worker_registered_input_paths(
            phase_name="rescan",
            scratchpad=scratchpad,
            config=config,
            agent_id="PC1",
            agent_role="rescan",
            output="analysis_percontract_Gateway.md",
            work_category="per_contract",
            focus_area="Gateway",
        )
        assert D._OPENGREP_UNASSIGNED_FILENAME in per_contract
        assert "opengrep_findings.md" not in per_contract


@pytest.mark.parametrize("phase", ("rescan", "depth"))
def test_sc_downstream_unexplained_or_unmaterialized_absence_fails_closed(
    tmp_path: Path,
    phase: str,
):
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    config = _config(tmp_path, scratchpad)
    output = (
        "analysis_rescan_auth.md"
        if phase == "rescan" else "depth_token_flow_findings.md"
    )

    # No governed scanner outcome means legacy raw identity, even when the
    # raw file is absent.  The later transaction prebind owns MISSING debt.
    unexplained = D._typed_worker_registered_input_paths(
        phase_name=phase,
        scratchpad=scratchpad,
        config=config,
        agent_id="T1",
        agent_role="rescan" if phase == "rescan" else "token_flow",
        output=output,
        work_category="rescan" if phase == "rescan" else "standard",
        focus_area="auth",
    )
    assert "opengrep_findings.md" in unexplained
    assert D._OPENGREP_UNASSIGNED_FILENAME not in unexplained
    assert not (scratchpad / "opengrep_findings.md").exists()

    # Once governed debt exists, a missing projection never falls back to a
    # stale raw file; its exact UNASSIGNED identity remains MISSING for PhaseIO.
    _materialize_governed_opengrep_absence(scratchpad)
    (scratchpad / D._OPENGREP_UNASSIGNED_FILENAME).unlink()
    (scratchpad / "opengrep_findings.md").write_text(
        "# stale raw bytes\n", encoding="utf-8"
    )
    governed = D._typed_worker_registered_input_paths(
        phase_name=phase,
        scratchpad=scratchpad,
        config=config,
        agent_id="T1",
        agent_role="rescan" if phase == "rescan" else "token_flow",
        output=output,
        work_category="rescan" if phase == "rescan" else "standard",
        focus_area="auth",
    )
    assert D._OPENGREP_UNASSIGNED_FILENAME in governed
    assert "opengrep_findings.md" not in governed
    assert not (scratchpad / D._OPENGREP_UNASSIGNED_FILENAME).exists()


def test_governed_absence_projection_structure_is_replayed(tmp_path: Path):
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    _materialize_governed_opengrep_absence(scratchpad)
    path = scratchpad / D._OPENGREP_UNASSIGNED_FILENAME
    path.write_text(
        path.read_text(encoding="utf-8")
        + "<!-- DEDUP_KEY: opengrep:999 -->\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="does not replay"):
        D._sc_downstream_opengrep_input(scratchpad)


def test_governed_absence_binds_complete_tool_outcome_record(tmp_path: Path):
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    _materialize_governed_opengrep_absence(scratchpad)

    # Keep state/reason/count identical while changing both artifact authority
    # and provider/context provenance.  The old projection must not replay.
    record_tool_outcome(
        scratchpad,
        ToolOutcome(
            capability_id="opengrep.static-analysis",
            tool="opengrep",
            state=ToolOutcomeState.UNAVAILABLE,
            reason="governed scanner absence for downstream PhaseIO test",
            finding_count=None,
            schema_validated=False,
            artifacts=("opengrep-new-context.json",),
            provider_ref='{"context":"replacement"}',
        ),
    )
    with pytest.raises(ValueError, match="does not replay"):
        D._sc_downstream_opengrep_input(scratchpad)


def test_governed_absence_atomic_write_replaces_name_not_symlink_target(
    tmp_path: Path,
):
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    target = tmp_path / "outside.txt"
    target.write_text("outside must remain unchanged\n", encoding="utf-8")
    projection = scratchpad / D._OPENGREP_UNASSIGNED_FILENAME
    projection.symlink_to(target)
    record_tool_outcome(
        scratchpad,
        ToolOutcome.debt(
            "opengrep.static-analysis",
            "opengrep",
            ToolOutcomeState.UNAVAILABLE,
            "governed scanner absence for downstream PhaseIO test",
        ),
    )
    authority = D._opengrep_zero_row_authority(scratchpad)
    assert authority is not None
    D._write_opengrep_shard_file(
        projection,
        owner_id="UNASSIGNED",
        focus_area="unassigned",
        rows=[],
        unassigned=True,
        absence_authority=authority,
    )
    assert not projection.is_symlink()
    assert target.read_text(encoding="utf-8") == "outside must remain unchanged\n"
    assert D._sc_downstream_opengrep_input(scratchpad) == projection.name


@pytest.mark.parametrize("alias_kind", ("symlink", "hardlink"))
def test_governed_absence_replay_rejects_link_alias(
    tmp_path: Path,
    alias_kind: str,
):
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    _materialize_governed_opengrep_absence(scratchpad)
    projection = scratchpad / D._OPENGREP_UNASSIGNED_FILENAME
    peer = tmp_path / "projection-peer.md"
    if alias_kind == "symlink":
        body = projection.read_bytes()
        peer.write_bytes(body)
        projection.unlink()
        projection.symlink_to(peer)
    else:
        import os

        os.link(projection, peer)
    with pytest.raises(ValueError, match="stable, bounded, single-link"):
        D._sc_downstream_opengrep_input(scratchpad)


def test_governed_absence_replay_rejects_mid_read_replacement(
    tmp_path: Path,
    monkeypatch,
):
    import os

    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    _materialize_governed_opengrep_absence(scratchpad)
    projection = scratchpad / D._OPENGREP_UNASSIGNED_FILENAME
    replacement = scratchpad / "replacement.md"
    replacement.write_bytes(projection.read_bytes())

    def _replace_during_read(_path: Path) -> None:
        os.replace(replacement, projection)

    monkeypatch.setattr(
        D.rooted_io,
        "_bounded_read_pre_read_hook",
        _replace_during_read,
    )
    with pytest.raises(ValueError, match="stable, bounded, single-link"):
        D._sc_downstream_opengrep_input(scratchpad)


@pytest.mark.parametrize("phase", ("rescan", "depth"))
def test_sc_exact_downstream_contract_requires_one_scanner_identity(
    tmp_path: Path,
    phase: str,
):
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    config = _config(tmp_path, scratchpad)
    _materialize_governed_opengrep_absence(scratchpad)
    output = (
        "analysis_rescan_auth.md"
        if phase == "rescan" else "depth_token_flow_findings.md"
    )
    exact = D._typed_worker_registered_input_paths(
        phase_name=phase,
        scratchpad=scratchpad,
        config=config,
        agent_id="T1",
        agent_role="rescan" if phase == "rescan" else "token_flow",
        output=output,
        work_category="rescan" if phase == "rescan" else "standard",
        focus_area="auth",
    )
    common = {
        "pipeline": "sc",
        "mode": "light",
        "ecosystem": "evm",
        "backend": "claude",
        "phase": phase,
        "work_unit_id": f"worker.{phase}-scanner-one-of",
        "exact_outputs": (output,),
    }
    resolve_phase_io_contract(**common, exact_inputs=exact)
    with pytest.raises(ValueError, match="requires exactly one"):
        resolve_phase_io_contract(
            **common,
            exact_inputs=(*exact, "opengrep_findings.md"),
        )
    with pytest.raises(ValueError, match="requires exactly one"):
        resolve_phase_io_contract(
            **common,
            exact_inputs=tuple(
                name for name in exact
                if name != D._OPENGREP_UNASSIGNED_FILENAME
            ),
        )


@pytest.mark.parametrize("phase", ("rescan", "depth"))
def test_l1_downstream_scanner_identity_is_unchanged(tmp_path: Path, phase: str):
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    _materialize_governed_opengrep_absence(scratchpad)
    config = _config(tmp_path, scratchpad)
    config.update({"pipeline": "l1", "language": "rust"})
    output = (
        "analysis_rescan_runtime.md"
        if phase == "rescan" else "depth_consensus_invariant_findings.md"
    )
    exact = D._typed_worker_registered_input_paths(
        phase_name=phase,
        scratchpad=scratchpad,
        config=config,
        agent_id="L1-T1",
        agent_role="rescan" if phase == "rescan" else "consensus_invariant",
        output=output,
        work_category="rescan" if phase == "rescan" else "standard",
        focus_area="consensus",
    )
    assert "opengrep_hits_ranked.md" in exact
    assert "opengrep_findings.md" not in exact
    assert D._OPENGREP_UNASSIGNED_FILENAME not in exact
    resolve_phase_io_contract(
        pipeline="l1",
        mode="light",
        ecosystem="rust",
        backend="claude",
        phase=phase,
        work_unit_id=f"worker.l1-{phase}",
        exact_outputs=(output,),
        exact_inputs=exact,
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


def test_inventory_planning_never_declares_unassignable_empty_shards(
    tmp_path: Path,
):
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    (scratchpad / "analysis_dense.md").write_text(
        "\n".join(
            f"## Finding [DENSE-{index}]: candidate {index}"
            for index in range(1, 7)
        ),
        encoding="utf-8",
    )

    plan = D.ensure_inventory_shard_plan(
        scratchpad, target_per_shard=1, max_shards=3
    )
    plan_text = (scratchpad / "inventory_shard_plan.md").read_text(
        encoding="utf-8"
    )

    assert "- Active shard count: 1" in plan_text
    assert [row["path"] for row in plan["inventory_chunk_a"]] == [
        "analysis_dense.md"
    ]
    assert plan["inventory_chunk_b"] == []
    assert plan["inventory_chunk_c"] == []


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
        assert "scratchpad:security_obligations.md" in l1_inputs
        assert "scratchpad:instantiation.json" in l1_inputs
        assert "scratchpad:instantiation.json" not in sc_inputs


def test_l1_depth_obligation_sidecars_are_bound_and_prompted(tmp_path: Path):
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    (tmp_path / "src").mkdir()
    config = _config(tmp_path, scratchpad)
    config.update({"pipeline": "l1", "language": "go", "mode": "core"})
    job = {
        "agent_id": "depth-state-trace",
        "role": "state_trace",
        "output": "depth_state_trace_findings.md",
        "category": "standard",
        "focus": "L1 exact obligation binding",
    }
    sidecars = {
        "security_feature_facts.json",
        "security_obligation_authority.json",
        "security_obligations.md",
    }

    registered = D._typed_worker_registered_input_paths(
        phase_name="depth",
        scratchpad=scratchpad,
        config=config,
        agent_id=str(job["agent_id"]),
        agent_role=str(job["role"]),
        output=str(job["output"]),
        work_category=str(job["category"]),
        focus_area=str(job["focus"]),
    )
    assert sidecars <= set(registered)

    resolved = resolve_phase_io_contract(
        pipeline="l1",
        mode="core",
        ecosystem="go",
        backend="claude",
        phase="depth",
        work_unit_id="worker.depth-state-trace",
        exact_outputs=(str(job["output"]),),
        exact_inputs=registered,
    )
    expected_identities = {f"scratchpad:{name}" for name in sidecars}
    assert expected_identities <= set(resolved.immutable_inputs)
    for omitted in sidecars:
        with pytest.raises(ValueError, match="omit the pipeline base denominator"):
            resolve_phase_io_contract(
                pipeline="l1",
                mode="core",
                ecosystem="go",
                backend="claude",
                phase="depth",
                work_unit_id="worker.depth-state-trace",
                exact_outputs=(str(job["output"]),),
                exact_inputs=tuple(
                    name for name in registered if name != omitted
                ),
            )

    prompt = D._build_depth_worker_prompt(
        job=job,
        scratchpad=scratchpad,
        project_root=str(tmp_path),
        config=config,
        attempt=1,
    )
    compiled_inputs = set(extract_compiled_phase_io(prompt)["immutable_inputs"])
    assert expected_identities <= compiled_inputs
    assert "PLAMEN_SECURITY_OBLIGATION_EVIDENCE" in prompt
    assert "missing, partial, or changed marker leaves it queueable" in prompt


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
