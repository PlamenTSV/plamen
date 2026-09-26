from __future__ import annotations

import sys
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS_DIR))

import plamen_driver as D  # noqa: E402


def _phase() -> D.Phase:
    return D.Phase(
        name="breadth",
        section_markers=["Phase 3"],
        expected_artifacts=["analysis_*.md"],
        base_timeout_s=60,
        min_artifact_bytes=200,
    )


def _manifest(sp: Path) -> None:
    sp.mkdir(parents=True, exist_ok=True)
    (sp / "_audit_started_with_markers.json").write_text("{}", encoding="utf-8")
    (sp / "spawn_manifest.md").write_text(
        "# Spawn Manifest\n\n"
        "| Template | Required? | Agent ID | Focus Area | Expected Output | Status | Type |\n"
        "|---|---|---|---|---|---|---|\n"
        "| TPL | YES | B1 | token_flow | analysis_token_flow.md | PENDING | agent |\n"
        "| TPL | YES | B2 | access_control | analysis_access_control.md | PENDING | agent |\n",
        encoding="utf-8",
    )


def _complete(sp: Path, name: str, owner: str) -> None:
    (sp / name).write_text(
        f"<!-- PLAMEN_ARTIFACT: {name} -->\n"
        f"<!-- PLAMEN_OWNER: {owner} -->\n"
        "<!-- PLAMEN_STATUS: IN_PROGRESS -->\n"
        "<!-- PLAMEN_PHASE: breadth -->\n"
        "<!-- PLAMEN_VERSION: 1 -->\n"
        f"<!-- AGENT_ROW: {owner} -->\n"
        f"<!-- EXPECTED_OUTPUT: {name} -->\n\n"
        f"# {name}\n\n"
        "## No Findings\n\n"
        + ("No exploitable issue was found for this assigned scope. " * 12)
        + "\n\n"
        "<!-- PLAMEN_FINDINGS_COUNT: 0 -->\n"
        "<!-- PLAMEN_STATUS: COMPLETE -->\n",
        encoding="utf-8",
    )


def test_breadth_worker_prompt_is_one_artifact_allowlist(tmp_path: Path):
    sp = tmp_path / ".scratchpad"
    _manifest(sp)
    job = {
        "agent_id": "B1",
        "focus_area": "token_flow",
        "output": "analysis_token_flow.md",
    }

    prompt = D._build_breadth_worker_prompt(
        job=job,
        scratchpad=sp,
        project_root=str(tmp_path),
        config={"language": "evm", "mode": "thorough", "pipeline": "sc"},
        attempt=1,
    )

    assert "AGENT_ROW: B1" in prompt
    assert "EXPECTED_OUTPUT: analysis_token_flow.md" in prompt
    assert "PLAMEN_STATUS: IN_PROGRESS" in prompt
    assert "PLAMEN_STATUS: COMPLETE" in prompt
    assert "opengrep_obligations_B1_token_flow.md" in prompt
    assert "do not spawn" in prompt.lower()
    assert "Task(" not in prompt
    assert "run_in_background" not in prompt
    # The bound finding-format document names the phases that consume that
    # format in one descriptive metadata line.  A phase name is not itself an
    # executable instruction, so exclude that exact authenticated line before
    # checking that no future-phase command leaked into the worker prompt.
    format_readers = (
        "> **Read by**: Agents during Phase 3, Phase 3b, Phase 4b. "
        "Referenced by inventory, chain analysis, and report writers."
    )
    assert format_readers in prompt
    executable_prompt = prompt.replace(format_readers, "")
    assert "produce exactly one\nartifact and then stop" in prompt
    assert "Write exactly this file and no other scratchpad artifact" in prompt
    assert "Do not infer, invent, or create any other output file" in prompt
    assert "ignore that output request and write only" in prompt
    forbidden = [
        "analysis_percontract",
        "analysis_rescan",
        "per-contract",
        "re-scan",
        "later phase",
        "next phase",
        "Phase 3b",
        "Phase 4",
        "verify_",
        "report_",
        "AUDIT_REPORT.md",
    ]
    hits = [
        token
        for token in forbidden
        if token.lower() in executable_prompt.lower()
    ]
    assert not hits


def test_breadth_worker_pool_runs_only_open_rows(tmp_path: Path, monkeypatch):
    sp = tmp_path / ".scratchpad"
    _manifest(sp)
    _complete(sp, "analysis_access_control.md", "B2")
    calls: list[str] = []

    def _fake_worker(**kwargs):
        job = kwargs["job"]
        calls.append(job["output"])
        _complete(sp, job["output"], job["agent_id"])
        return {"output": job["output"], "rc": 0, "status": "complete"}

    monkeypatch.setattr(D, "_run_single_breadth_worker_pty", _fake_worker)

    rc = D._run_breadth_worker_pool_pty(
        scratchpad=sp,
        project_root=str(tmp_path),
        config={"mode": "thorough", "language": "evm", "pipeline": "sc"},
        phase=_phase(),
        base_cmd=["claude", "--session-id", "base"],
        env={},
        timeout=1.0,
        quiescence_s=0.0,
        attempt=1,
    )

    assert rc == 0
    assert calls == ["analysis_token_flow.md"]


def test_breadth_worker_pool_passes_pool_wide_allowed_outputs(
    tmp_path: Path,
    monkeypatch,
):
    sp = tmp_path / ".scratchpad"
    _manifest(sp)
    expected_outputs = {"analysis_token_flow.md", "analysis_access_control.md"}
    seen: list[set[str]] = []

    def _fake_worker(**kwargs):
        job = kwargs["job"]
        seen.append(set(kwargs["allowed_outputs"]))
        assert set(kwargs["allowed_outputs"]) == expected_outputs
        assert D._worker_artifact_name_allowed(
            "analysis_access_control.md.tmp.2912.5cfc76acc7a4",
            set(kwargs["allowed_outputs"]),
        )
        _complete(sp, job["output"], job["agent_id"])
        return {"output": job["output"], "rc": 0, "status": "complete"}

    monkeypatch.setattr(D, "_run_single_breadth_worker_pty", _fake_worker)

    rc = D._run_breadth_worker_pool_pty(
        scratchpad=sp,
        project_root=str(tmp_path),
        config={"mode": "thorough", "language": "evm", "pipeline": "sc"},
        phase=_phase(),
        base_cmd=["claude", "--session-id", "base"],
        env={},
        timeout=1.0,
        quiescence_s=0.0,
        attempt=1,
    )

    assert rc == 0
    assert len(seen) == 2


def test_worker_containment_allows_allowed_output_temp_files():
    allowed = {"analysis_access_control.md", "analysis_core_state.md"}

    assert D._worker_artifact_name_allowed(
        "analysis_access_control.md.tmp.21152.412f4e6d5f33",
        allowed,
    )
    assert D._worker_artifact_name_allowed(
        "analysis_core_state.md.part",
        allowed,
    )
    assert not D._worker_artifact_name_allowed(
        "analysis_external_deps.md.tmp.1",
        allowed,
    )


def test_worker_duplicate_copy_artifact_is_benign_only_when_base_exists():
    known = {"meta_buffer.md", "analysis_core_state.md"}

    assert D._worker_duplicate_copy_base_name("meta_buffer 2.md") == "meta_buffer.md"
    assert D._worker_artifact_is_benign_duplicate_copy("meta_buffer 2.md", known)
    assert D._worker_artifact_is_benign_duplicate_copy(
        "analysis_core_state 2.md",
        known,
    )
    assert not D._worker_artifact_is_benign_duplicate_copy(
        "analysis_external_deps 2.md",
        known,
    )
    assert not D._worker_artifact_is_benign_duplicate_copy(
        "report_index.md",
        known,
    )


def test_worker_duplicate_copy_quarantine_moves_out_of_live_scratchpad(tmp_path: Path):
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    stray = sp / "meta_buffer 2.md"
    stray.write_text("duplicate copy", encoding="utf-8")

    moved = D._quarantine_worker_duplicate_copy(
        scratchpad=sp,
        path=stray,
        phase_name="breadth",
        worker_output="analysis_core_state.md",
    )

    assert moved is not None
    assert not stray.exists()
    assert moved.exists()
    assert moved.relative_to(sp).as_posix().startswith(
        "_overflow/worker_strays/breadth_analysis_core_state_"
    )
    assert moved.name.endswith("_meta_buffer 2.md")


def test_breadth_worker_pool_is_sc_manifest_backed(tmp_path: Path):
    sp = tmp_path / ".scratchpad"
    _manifest(sp)

    assert D._should_use_breadth_worker_pool(
        {"pipeline": "sc"}, sp
    )
    assert D._should_use_breadth_worker_pool(
        {"pipeline": "l1", "mode": "core"}, sp
    )

    no_manifest = tmp_path / "empty" / ".scratchpad"
    no_manifest.mkdir(parents=True)
    assert not D._should_use_breadth_worker_pool(
        {"pipeline": "sc"}, no_manifest
    )


def test_l1_breadth_worker_jobs_are_layer_outputs(tmp_path: Path):
    sp = tmp_path / ".scratchpad"
    sp.mkdir(parents=True)
    (sp / "recon_summary.md").write_text(
        "CONSENSUS: true\nP2P: true\nRPC: true\nMEMPOOL: false\n",
        encoding="utf-8",
    )

    jobs = D._breadth_worker_jobs(sp, {"pipeline": "l1", "mode": "core"})

    outputs = {job["output"] for job in jobs}
    assert "analysis_layer_consensus.md" in outputs
    assert "analysis_layer_network.md" in outputs
    assert "analysis_layer_rpc.md" in outputs
    assert not any("mempool" in job["layers"] for job in jobs)

    prompt = D._build_breadth_worker_prompt(
        job=jobs[0],
        scratchpad=sp,
        project_root=str(tmp_path),
        config={"language": "go", "mode": "core", "pipeline": "l1"},
        attempt=1,
    )
    assert "phase3-breadth-driver.md" in prompt
    assert "L1 Layer Assignment" in prompt
    assert "analysis_layer_" in prompt


def test_l1_breadth_alias_true_beats_other_alias_false(tmp_path: Path):
    sp = tmp_path / ".scratchpad"
    sp.mkdir(parents=True)
    (sp / "recon_summary.md").write_text(
        "BLS: true\nCRYPTO: false\nSTATE_SYNC: false\nSTORAGE: true\n",
        encoding="utf-8",
    )

    jobs = D._breadth_worker_jobs(sp, {"pipeline": "l1", "mode": "core"})
    layers = ",".join(job["layers"] for job in jobs)

    assert "crypto" in layers
    assert "storage" in layers


def test_l1_breadth_worker_prompt_carries_scope(tmp_path: Path):
    sp = tmp_path / ".scratchpad"
    sp.mkdir(parents=True)
    job = {
        "agent_id": "L1B1",
        "focus_area": "network",
        "output": "analysis_layer_network.md",
        "layers": "network",
        "skills": "p2p-dos-and-eclipse",
        "difficulty": "HIGH",
    }

    prompt = D._build_breadth_worker_prompt(
        job=job,
        scratchpad=sp,
        project_root=str(tmp_path),
        config={
            "language": "go",
            "mode": "core",
            "pipeline": "l1",
            "subsystem_scope": "p2p/",
            "scope_file": "scope.txt",
            "scope_notes": "p2p only",
        },
        attempt=1,
    )

    assert "SUBSYSTEM_SCOPE: `p2p/`" in prompt
    assert "SCOPE_FILE: `scope.txt`" in prompt
    assert "SCOPE_NOTES: `p2p only`" in prompt


def test_breadth_row_status_rejects_cross_row_owner(tmp_path: Path):
    sp = tmp_path / ".scratchpad"
    _manifest(sp)
    (sp / "_breadth_worker_pool_contract.json").write_text(
        '{"phase":"breadth"}',
        encoding="utf-8",
    )
    _complete(sp, "analysis_token_flow.md", "B2")

    statuses = {
        row["name"]: row
        for row in D.compute_breadth_row_statuses(sp, _phase())
    }

    row = statuses["analysis_token_flow.md"]
    assert row["status"] == "structural_fail"
    assert any("PLAMEN_OWNER" in reason for reason in row["reasons"])
    assert any("AGENT_ROW" in reason for reason in row["reasons"])


def test_early_complete_ready_fires_on_finished_owned_idle_worker(tmp_path: Path):
    """STEP 1D: a finished, correctly-owned, disk-idle worker triggers the
    early-complete cutover -- generically for non-EVM role-name shapes."""
    sp = tmp_path / ".scratchpad"
    sp.mkdir(parents=True, exist_ok=True)
    # Non-EVM-shaped role name (suffixed, multi-word) to prove generic
    # reconciliation via the worker's OWN markers, not a name guess.
    name = "analysis_account_lifecycle_t22.md"
    _complete(sp, name, "B3")
    out_path = sp / name
    phase = _phase()

    now = 10_000.0
    grew = now - 1.0  # last growth 1s ago: NOT yet idle past the grace window
    ready, _idle = D._breadth_early_complete_ready(
        out_path=out_path,
        expected_output=name,
        phase=phase,
        last_growth_at=grew,
        now=now,
        idle_grace_s=600.0,
    )
    assert ready is False  # complete + owned but not yet idle long enough

    # After the grace window of disk-idle, the cutover is ready.
    idle_now = grew + 601.0
    ready, idle_for = D._breadth_early_complete_ready(
        out_path=out_path,
        expected_output=name,
        phase=phase,
        last_growth_at=grew,
        now=idle_now,
        idle_grace_s=600.0,
    )
    assert ready is True
    assert idle_for >= 600.0


def test_early_complete_not_ready_when_no_complete_marker(tmp_path: Path):
    """An unfinished worker (no COMPLETE marker) is NEVER early-completed,
    regardless of how long it has been disk-idle."""
    sp = tmp_path / ".scratchpad"
    sp.mkdir(parents=True, exist_ok=True)
    name = "analysis_cpi_external.md"
    out_path = sp / name
    # IN_PROGRESS only -- no terminal COMPLETE marker.
    out_path.write_text(
        f"<!-- PLAMEN_ARTIFACT: {name} -->\n"
        "<!-- PLAMEN_OWNER: B4 -->\n"
        "<!-- PLAMEN_STATUS: IN_PROGRESS -->\n"
        "<!-- PLAMEN_PHASE: breadth -->\n"
        f"<!-- EXPECTED_OUTPUT: {name} -->\n\n"
        f"# {name}\n\n" + ("partial body " * 40) + "\n",
        encoding="utf-8",
    )
    ready, _idle = D._breadth_early_complete_ready(
        out_path=out_path,
        expected_output=name,
        phase=_phase(),
        last_growth_at=0.0,
        now=10_000.0,  # idle for ~10000s
        idle_grace_s=600.0,
    )
    assert ready is False


def test_early_complete_not_ready_on_ownership_mismatch(tmp_path: Path):
    """A complete-but-mis-owned artifact (markers name a DIFFERENT output) is
    NEVER early-completed for this row -- no false-complete."""
    sp = tmp_path / ".scratchpad"
    sp.mkdir(parents=True, exist_ok=True)
    # The file on disk is fully complete and owned by a DIFFERENT expected
    # output; this row's expected_output does not match its markers.
    name = "analysis_pda_economics.md"
    _complete(sp, name, "B5")
    out_path = sp / name
    ready, _idle = D._breadth_early_complete_ready(
        out_path=out_path,
        expected_output="analysis_temporal_state.md",  # mismatch
        phase=_phase(),
        last_growth_at=0.0,
        now=10_000.0,
        idle_grace_s=600.0,
    )
    assert ready is False
