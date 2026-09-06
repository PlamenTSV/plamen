"""Tests for Ship 6 of the artifact-complete PTY supervision plan.

Covers the continuation-message builder and the supervised PTY loop.
Numbered tests 19-25 match the plan's ``test_pty_supervision.py``
section.

All PTY/subprocess interactions are mocked. ``ClaudePtySession`` is
replaced with a ``_MockSession`` that exposes the methods the loop
calls (``wait_for_turn_complete``, ``is_alive``, ``send_continuation``,
``terminate``) and lets each test script the per-iteration behavior.

Gate behavior is driven by REAL file state in a tmp scratchpad +
``plamen_driver.gate_passes`` -- no string parsing, no mock of the
gate. This proves the supervised loop interacts with the gate exactly
as it will in production.
"""
from __future__ import annotations

import json
import sys
import types
from pathlib import Path
from typing import Any

import pytest

SCRIPTS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS_DIR))

import plamen_driver as D  # noqa: E402


_SENTINEL = "_audit_started_with_markers.json"


def test_worker_pool_status_omits_misleading_completion_fraction():
    status = D._format_worker_pool_progress_status(
        complete=0,
        total=7,
        active_outputs=[
            "analysis_core_state.md",
            "analysis_access_control.md",
            "analysis_token_flow.md",
        ],
        queued=4,
        phase_label="breadth",
    )

    assert "0/7 complete" not in status
    assert status.startswith("worker pool:")
    assert "3 running" in status
    assert "4 queued/missing" in status
    assert "active core_state, access_control, token_flow" in status


# ---------------------------------------------------------------------------
# Test helpers -- mock session and scratchpad builders
# ---------------------------------------------------------------------------


class _TurnState:
    """Minimal stand-in for pty_exec.TurnCompleteState."""
    def __init__(self, complete: bool = True, rate_limited: bool = False):
        self.complete = complete
        self.rate_limited = rate_limited
        self.line_count = 0
        self.last_event_time = None


class _MockSession:
    """Mock for ClaudePtySession with scripted per-call behavior.

    Each iteration of the supervised loop calls ``wait_for_turn_complete``
    then potentially ``send_continuation`` or ``terminate``. The
    ``script`` list provides a callable per iteration: that callable
    is invoked with this session as its argument and may mutate
    on-disk state (e.g. flip a row from in_progress -> complete) so
    the gate sees the change on the next iteration.
    """

    def __init__(
        self,
        transcript_path: Path,
        session_id: str = "test-session",
        script: list | None = None,
        alive_during_wait: bool = True,
        wait_complete: bool = True,
    ):
        self.transcript_path = transcript_path
        self.session_id = session_id
        self._alive = True
        self.send_continuation_calls: list[str] = []
        self.terminate_calls = 0
        self.spawn_calls = 0
        self.send_bootstrap_calls = 0
        self.wait_calls = 0
        self._script = script or []
        self._alive_during_wait = alive_during_wait
        self._wait_complete = wait_complete
        # Loop entry expects the session to already be alive and
        # bootstrapped; the tests pre-spawn here.
        self.spawn_calls += 1
        self.send_bootstrap_calls += 1

    def spawn(self):
        self.spawn_calls += 1

    def send_bootstrap(self):
        self.send_bootstrap_calls += 1

    def is_alive(self) -> bool:
        return self._alive

    def write(self, text):
        pass

    def send_continuation(self, message: str) -> None:
        self.send_continuation_calls.append(message)

    def terminate(self, grace_s: float = 5.0) -> None:
        self.terminate_calls += 1
        self._alive = False

    def wait_for_turn_complete(self, *args, **kwargs) -> _TurnState:
        idx = self.wait_calls
        self.wait_calls += 1
        # Run the script step for this iteration (if provided). The
        # step may write/edit files in the scratchpad to flip row
        # statuses between gate checks.
        if idx < len(self._script):
            step = self._script[idx]
            step(self)
        return _TurnState(complete=self._wait_complete, rate_limited=False)


def _write_breadth_manifest(sp: Path, rows: list[tuple[str, str]]) -> None:
    """Synthesize a minimal spawn_manifest.md for parse_breadth_manifest_outputs."""
    header = (
        "# Spawn Manifest\n\n"
        "| Template | Required? | Agent ID | Focus Area | "
        "Expected Output | Status | Type |\n"
        "|----------|-----------|----------|------------|"
        "-----------------|--------|------|\n"
    )
    body = "\n".join(
        f"| TPL | YES | {aid} | {focus} | analysis_{focus}.md | "
        f"PENDING | agent |"
        for aid, focus in rows
    )
    (sp / "spawn_manifest.md").write_text(header + body + "\n", encoding="utf-8")


def _write_complete_artifact(sp: Path, name: str, agent_id: str) -> None:
    body = (
        f"<!-- PLAMEN_ARTIFACT: {name} -->\n"
        f"<!-- PLAMEN_OWNER: {agent_id} -->\n"
        f"<!-- PLAMEN_STATUS: IN_PROGRESS -->\n"
        f"<!-- PLAMEN_PHASE: breadth -->\n"
        f"<!-- PLAMEN_VERSION: 1 -->\n"
        f"<!-- AGENT_ROW: {agent_id} -->\n"
        f"<!-- EXPECTED_OUTPUT: {name} -->\n\n"
        f"# {name}\n\n"
        f"## Findings\n\n"
        + (f"[{agent_id}-1] Real finding body content. " * 30)
        + "\n\n"
        f"## Obligation Receipts\n\n"
        f"(none in scope)\n\n"
        f"<!-- PLAMEN_STATUS: COMPLETE -->\n"
        f"<!-- PLAMEN_FINDINGS_COUNT: 1 -->\n"
    )
    (sp / name).write_text(body, encoding="utf-8")


def _write_in_progress_artifact(sp: Path, name: str, agent_id: str) -> None:
    body = (
        f"<!-- PLAMEN_ARTIFACT: {name} -->\n"
        f"<!-- PLAMEN_OWNER: {agent_id} -->\n"
        f"<!-- PLAMEN_STATUS: IN_PROGRESS -->\n"
        f"<!-- PLAMEN_PHASE: breadth -->\n"
        f"<!-- PLAMEN_VERSION: 1 -->\n\n"
        f"# {name}\n\n"
        f"## Findings\n\n"
        + ("partial work-in-progress body " * 30)
        + "\n"
    )
    (sp / name).write_text(body, encoding="utf-8")


def _touch_sentinel(sp: Path) -> None:
    (sp / _SENTINEL).write_text("{}", encoding="utf-8")


def _empty_transcript(sp: Path) -> Path:
    p = sp / "session-transcript.jsonl"
    p.write_text("", encoding="utf-8")
    return p


def _make_breadth_phase(min_bytes: int = 200) -> Any:
    return D.Phase(
        name="breadth",
        section_markers=["Phase 3"],
        expected_artifacts=["analysis_*.md"],
        base_timeout_s=60,
        min_artifact_bytes=min_bytes,
    )


def _make_depth_phase(min_bytes: int = 200) -> Any:
    return D.Phase(
        name="depth",
        section_markers=["Phase 4b"],
        expected_artifacts=["depth_*_findings.md"],
        base_timeout_s=60,
        min_artifact_bytes=min_bytes,
        example_tokens=["token_flow", "state_trace", "edge_case", "external"],
    )


def _make_sc_verify_medium_phase() -> Any:
    return next(p for p in D.SC_PHASES if p.name == "sc_verify_medium_a")


def _write_sc_verification_queue(sp: Path, rows: list[tuple[str, str, str]]) -> None:
    body = [
        "# Verification Queue",
        "",
        "| Queue # | Finding ID | Severity | Title | Bug Class | Preferred Tag | Location | Primary Artifact | PoC Class |",
        "|---------|------------|----------|-------|-----------|---------------|----------|------------------|-----------|",
    ]
    for idx, (fid, severity, title) in enumerate(rows, start=1):
        body.append(
            f"| {idx} | {fid} | {severity} | {title} | logic | CODE-TRACE | "
            f"contracts/A.sol:L{idx} | hypotheses.md | unit |"
        )
    (sp / "verification_queue.md").write_text("\n".join(body), encoding="utf-8")


def _write_verify_file(sp: Path, fid: str) -> None:
    (sp / f"verify_{fid}.md").write_text(
        f"# Verification {fid}\n\n"
        f"Finding ID: {fid}\n"
        "Severity: Medium\n"
        "Verdict: CONFIRMED\n"
        "Evidence Tag: CODE-TRACE\n"
        "Preferred Tag: CODE-TRACE\n\n"
        + ("substantive verifier evidence " * 20),
        encoding="utf-8",
    )


def _write_depth_contract(sp: Path) -> None:
    jobs = [
        {
            "agent_id": "depth-token-flow",
            "role": "token_flow",
            "output": "depth_token_flow_findings.md",
            "category": "standard",
        },
        {
            "agent_id": "depth-state-trace",
            "role": "state_trace",
            "output": "depth_state_trace_findings.md",
            "category": "standard",
        },
        {
            "agent_id": "depth-edge-case",
            "role": "edge_case",
            "output": "depth_edge_case_findings.md",
            "category": "standard",
        },
        {
            "agent_id": "depth-external",
            "role": "external",
            "output": "depth_external_findings.md",
            "category": "standard",
        },
    ]
    (sp / "_depth_worker_pool_contract.json").write_text(
        json.dumps({
            "phase": "depth",
            "jobs": jobs,
            "canonical_outputs": [j["output"] for j in jobs],
        }),
        encoding="utf-8",
    )


def _make_config(project_root: Path) -> dict:
    return {
        "project_root": str(project_root),
        "scratchpad": str(project_root / ".scratchpad"),
        "claude_pty_quiescence_s": 0.0,
        "pty_continuation_budget": 3,
    }


# ---------------------------------------------------------------------------
# Test 19 -- continuation lists ONLY incomplete rows
# ---------------------------------------------------------------------------


def test_continuation_lists_only_incomplete_rows():
    """_build_continuation_message MUST list only rows whose status
    is not 'complete'. Completed rows MUST NOT appear in any line of
    the continuation message."""
    row_statuses = [
        {"name": "analysis_core_state.md", "status": "complete", "reasons": []},
        {"name": "analysis_access_control.md", "status": "in_progress", "reasons": []},
        {"name": "analysis_centralization.md", "status": "missing", "reasons": []},
        {"name": "analysis_cross_chain_msg.md", "status": "complete", "reasons": []},
        {
            "name": "analysis_storage_layout.md",
            "status": "structural_fail",
            "reasons": ["missing required heading: ## Findings"],
        },
    ]
    msg = D._build_continuation_message(
        phase_name="breadth",
        row_statuses=row_statuses,
        handles_by_row={},
        agentid_resume_supported=False,
    )
    # Completed rows absent
    assert "analysis_core_state.md" not in msg
    assert "analysis_cross_chain_msg.md" not in msg
    # Incomplete rows present
    assert "analysis_access_control.md" in msg
    assert "analysis_centralization.md" in msg
    assert "analysis_storage_layout.md" in msg
    # Status labels surface
    assert "IN_PROGRESS" in msg
    assert "MISSING" in msg
    assert "STRUCTURAL_FAIL" in msg


# ---------------------------------------------------------------------------
# Test 20 -- handle column ONLY when agentid_resume_supported
# ---------------------------------------------------------------------------


def test_continuation_includes_handles_only_when_agentid_resume_supported():
    """When the preflight reports agentid_resume_supported=True AND a
    handle is known for the row, the continuation message lists the
    handle and tells the coordinator to attempt SendMessage."""
    row_statuses = [
        {"name": "analysis_access_control.md", "status": "in_progress", "reasons": []},
    ]
    handles = {
        "B3": {
            "agent_id": "B3",
            "expected_output": "analysis_access_control.md",
            "handle": "a3909332747545d53",
            "description": "B3 dispatch",
        }
    }
    msg = D._build_continuation_message(
        phase_name="breadth",
        row_statuses=row_statuses,
        handles_by_row=handles,
        agentid_resume_supported=True,
    )
    assert "Handle" in msg
    assert "a3909332747545d53" in msg
    assert "SendMessage" in msg


# ---------------------------------------------------------------------------
# Test 21 -- handle column is DROPPED when resume unsupported
# ---------------------------------------------------------------------------


def test_continuation_drops_handle_column_when_resume_unsupported():
    """When agentid_resume_supported=False the handle column MUST NOT
    appear in the continuation table at all; the coordinator is told
    to respawn only."""
    row_statuses = [
        {"name": "analysis_access_control.md", "status": "in_progress", "reasons": []},
    ]
    handles = {
        "B3": {
            "agent_id": "B3",
            "expected_output": "analysis_access_control.md",
            "handle": "a39093",
            "description": "B3 dispatch",
        }
    }
    msg = D._build_continuation_message(
        phase_name="breadth",
        row_statuses=row_statuses,
        handles_by_row=handles,
        agentid_resume_supported=False,
    )
    # The handle string must NOT leak into the message body even
    # though the parser captured one.
    assert "a39093" not in msg
    # The header line announcing SendMessage MUST NOT appear.
    assert "SendMessage" not in msg
    # The "respawn is the only continuation path" instruction MUST.
    assert "respawn" in msg.lower()


# ---------------------------------------------------------------------------
# Test 22 -- supervision loop exits on first-pass success
# ---------------------------------------------------------------------------


def test_supervision_loop_exits_on_first_pass(tmp_path: Path):
    """When the in-session gate passes on the FIRST turn, the
    supervision loop returns rc=0 immediately without sending any
    continuation."""
    project = tmp_path
    sp = project / ".scratchpad"
    sp.mkdir(parents=True)
    _touch_sentinel(sp)
    _write_breadth_manifest(sp, [("B1", "core_state"), ("B2", "access_control")])
    # Both COMPLETE before the loop starts -- first wait returns
    # end_turn and the gate already passes.
    _write_complete_artifact(sp, "analysis_core_state.md", "B1")
    _write_complete_artifact(sp, "analysis_access_control.md", "B2")
    transcript = _empty_transcript(sp)
    session = _MockSession(transcript_path=transcript, script=[])
    rc, final = D._run_supervised_pty_loop(
        session=session,
        scratchpad=sp,
        project_root=str(project),
        phase=_make_breadth_phase(),
        config=_make_config(project),
        preflight={
            "live_pty_continue_supported": True,
            "agentid_resume_supported": False,
        },
        timeout=5.0,
        quiescence_s=0.0,
        on_poll=None,
        base_cmd=["claude", "--session-id", "test"],
        cwd=str(project),
        env={},
        log_file=None,
        prompt_path=sp / "prompt.md",
    )
    assert rc == 0
    assert final is session  # no respawn
    assert session.send_continuation_calls == []  # no continuation
    assert session.wait_calls == 1


# ---------------------------------------------------------------------------
# Test 23 -- supervision loop respects the budget
# ---------------------------------------------------------------------------


def test_supervision_loop_respects_budget(tmp_path: Path, monkeypatch):
    """If the gate keeps failing, the supervision loop must give up
    after `pty_continuation_budget` iterations and return rc=-2 for
    whole-phase retry. Recovery is always fresh missing-only PTY, never
    live continuation, so the number of missing-only respawns must equal
    the budget."""
    project = tmp_path
    sp = project / ".scratchpad"
    sp.mkdir(parents=True)
    _touch_sentinel(sp)
    _write_breadth_manifest(sp, [("B1", "core_state"), ("B2", "access_control")])
    # B1 in_progress permanently; B2 in_progress permanently.
    # Gate fails every iteration; no script step changes state.
    _write_in_progress_artifact(sp, "analysis_core_state.md", "B1")
    _write_in_progress_artifact(sp, "analysis_access_control.md", "B2")
    transcript = _empty_transcript(sp)
    config = _make_config(project)
    config["pty_continuation_budget"] = 3
    respawn_calls = {"n": 0}

    def _fake_respawn(**kwargs):
        respawn_calls["n"] += 1
        return _MockSession(transcript_path=transcript, script=[lambda s: None])

    monkeypatch.setattr(D, "_respawn_missing_only", _fake_respawn)
    session = _MockSession(transcript_path=transcript, script=[lambda s: None])
    rc, final = D._run_supervised_pty_loop(
        session=session,
        scratchpad=sp,
        project_root=str(project),
        phase=_make_breadth_phase(),
        config=config,
        preflight={
            "live_pty_continue_supported": True,
            "agentid_resume_supported": False,
        },
        timeout=5.0,
        quiescence_s=0.0,
        on_poll=None,
        base_cmd=["claude", "--session-id", "test"],
        cwd=str(project),
        env={},
        log_file=None,
        prompt_path=sp / "prompt.md",
    )
    assert rc == -2
    assert respawn_calls["n"] == 3
    assert session.wait_calls == 1
    assert session.send_continuation_calls == []


# ---------------------------------------------------------------------------
# Test 24 -- no transport falls back to whole-phase retry
# ---------------------------------------------------------------------------


def test_supervision_loop_missing_only_when_no_transport(tmp_path, monkeypatch):
    """SHIP 8.11/8.12 CRITICAL PROOF.

    Scenario replays an observed verified failure: the coordinator emits a
    false DONE (every turn reaches end_turn / complete=True), the Ship 8.2
    gate correctly catches that not all manifest rows are COMPLETE, AND the
    preflight reported BOTH transports unsupported (live=False, resume=False
    -- the false-negative that previously forced an immediate whole-phase
    retry).

    Before Ship 8.11/8.12 this returned rc=-2 on the first failing
    iteration. Now it MUST instead invoke the missing-only continuation
    subprocess (fresh session, only the incomplete rows) and NOT return
    rc=-2 immediately. This test is the exact proof the operating
    instruction demands.

    Also asserts (Correction 3): the OLD PTY is terminated and confirmed
    dead BEFORE the missing-only respawn -- never two coordinators in one
    scratchpad."""
    project = tmp_path
    sp = project / ".scratchpad"
    sp.mkdir(parents=True)
    _touch_sentinel(sp)
    _write_breadth_manifest(sp, [("B1", "core_state"), ("B2", "access_control")])
    # B1 already COMPLETE; B2 only IN_PROGRESS -> gate fails on B2.
    _write_complete_artifact(sp, "analysis_core_state.md", "B1")
    _write_in_progress_artifact(sp, "analysis_access_control.md", "B2")
    transcript = _empty_transcript(sp)

    invocations: list[dict] = []

    def _fake_respawn(*, phase, scratchpad, row_statuses, base_cmd,
                      cwd, env, log_file, prompt_path, gate_missing=None):
        # Correction 3 proof: the old session must be DEAD at call time.
        assert not old_session.is_alive(), (
            "missing-only respawn invoked while the old PTY was still alive"
        )
        # Capture WHAT the missing-only subprocess was asked to do: it must
        # be scoped to ONLY the incomplete rows (B2), never the COMPLETE one.
        incomplete = {
            r["name"] for r in row_statuses if r.get("status") != "complete"
        }
        complete = {
            r["name"] for r in row_statuses if r.get("status") == "complete"
        }
        invocations.append({"incomplete": incomplete, "complete": complete})
        # Simulate the missing-only subprocess doing its job: it fills the
        # one missing row, so the NEXT gate passes.
        _write_complete_artifact(sp, "analysis_access_control.md", "B2")
        return _MockSession(transcript_path=transcript, script=[lambda s: None])

    monkeypatch.setattr(D, "_respawn_missing_only", _fake_respawn)

    old_session = _MockSession(transcript_path=transcript, script=[lambda s: None])
    rc, final = D._run_supervised_pty_loop(
        session=old_session,
        scratchpad=sp,
        project_root=str(project),
        phase=_make_breadth_phase(),
        config=_make_config(project),
        preflight={
            "live_pty_continue_supported": False,
            "agentid_resume_supported": False,
        },
        timeout=5.0,
        quiescence_s=0.0,
        on_poll=None,
        base_cmd=["claude", "--session-id", "test"],
        cwd=str(project),
        env={},
        log_file=None,
        prompt_path=sp / "prompt.md",
    )

    # CRITICAL ASSERTION: missing-only was invoked; the loop did NOT take
    # the immediate rc=-2 path on the first failing iteration.
    assert len(invocations) == 1, (
        "missing-only subprocess was NOT invoked -- the loop took the old "
        "immediate-rc=-2 path"
    )
    # The missing-only subprocess was scoped to ONLY the incomplete row.
    assert invocations[0]["incomplete"] == {"analysis_access_control.md"}
    assert "analysis_core_state.md" not in invocations[0]["incomplete"]
    # Old PTY was terminated before respawn.
    assert old_session.terminate_calls >= 1
    # The fresh missing-only session filled the row; the loop converged.
    assert rc == 0
    assert final is not old_session  # respawned session is returned
    # No live/resume continuation was ever sent (both transports False).
    assert old_session.send_continuation_calls == []


def test_supervision_loop_missing_only_is_budget_bounded(tmp_path, monkeypatch):
    """The missing-only transport is bounded by pty_continuation_budget,
    exactly like the live/resume transports. If the missing-only
    subprocess never fills the row, the loop gives up after `budget`
    respawns and returns rc=-2 for whole-phase retry. This guarantees the
    new transport cannot loop forever."""
    project = tmp_path
    sp = project / ".scratchpad"
    sp.mkdir(parents=True)
    _touch_sentinel(sp)
    _write_breadth_manifest(sp, [("B1", "core_state")])
    _write_in_progress_artifact(sp, "analysis_core_state.md", "B1")
    transcript = _empty_transcript(sp)

    config = _make_config(project)
    config["pty_continuation_budget"] = 3

    respawn_calls = {"n": 0}

    def _fake_respawn(**kwargs):
        # Never fills the row -> gate keeps failing every iteration.
        respawn_calls["n"] += 1
        return _MockSession(transcript_path=transcript, script=[lambda s: None])

    monkeypatch.setattr(D, "_respawn_missing_only", _fake_respawn)

    session = _MockSession(transcript_path=transcript, script=[lambda s: None] * 6)
    rc, final = D._run_supervised_pty_loop(
        session=session,
        scratchpad=sp,
        project_root=str(project),
        phase=_make_breadth_phase(),
        config=config,
        preflight={
            "live_pty_continue_supported": False,
            "agentid_resume_supported": False,
        },
        timeout=5.0,
        quiescence_s=0.0,
        on_poll=None,
        base_cmd=["claude", "--session-id", "test"],
        cwd=str(project),
        env={},
        log_file=None,
        prompt_path=sp / "prompt.md",
    )
    # attempt 1 waits on the original session; respawns #1-3 each create a
    # fresh mock that waits once; attempt 4 (> budget=3) returns -2 before a
    # 4th respawn. So the ORIGINAL session waited exactly once, and there
    # were exactly `budget` missing-only respawns.
    assert rc == -2
    assert respawn_calls["n"] == 3
    assert session.wait_calls == 1


def test_verify_row_statuses_track_missing_outputs_from_queue(tmp_path: Path):
    """Verifier shard supervision derives its rows from verification_queue.md.

    A partially completed verifier shard must expose only the unwritten
    verify_<ID>.md files as incomplete so recovery does not re-run rows that
    already landed on disk.
    """
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    _write_sc_verification_queue(
        sp,
        [
            ("HM-01", "Medium", "first medium bug"),
            ("HM-02", "Medium", "second medium bug"),
        ],
    )
    _write_verify_file(sp, "HM-01")

    statuses = D.compute_verify_row_statuses(sp, "sc_verify_medium_a")

    by_name = {row["name"]: row for row in statuses}
    assert by_name["verify_HM-01.md"]["status"] == "complete"
    assert by_name["verify_HM-02.md"]["status"] == "missing"
    assert by_name["verify_HM-02.md"]["finding_id"] == "HM-02"
    assert by_name["verify_HM-02.md"]["row"]["title"] == "second medium bug"


def test_verify_missing_only_prompt_lists_only_missing_rows(tmp_path: Path):
    """The missing-only verifier prompt preserves methodology but narrows work."""
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    _write_sc_verification_queue(
        sp,
        [
            ("HM-01", "Medium", "already verified"),
            ("HM-02", "Medium", "missing verifier"),
        ],
    )
    _write_verify_file(sp, "HM-01")
    prompt = sp / "_prompt_sc_verify_medium_a.attempt1.md"
    prompt.write_text("# Original verifier methodology\n", encoding="utf-8")
    phase = _make_sc_verify_medium_phase()

    snapshot = D._build_missing_only_prompt(
        phase,
        sp,
        D.compute_verify_row_statuses(sp, phase.name),
        prompt,
        gate_missing=["verify completion: wrote 1/2 verifier files"],
        now_ts=123,
    )
    text = snapshot.read_text(encoding="utf-8")

    assert "Missing Verifier Rows" in text
    assert "HM-02" in text
    assert "verify_HM-02.md" in text
    assert "missing verifier" in text
    missing_section = text.split("## Missing Verifier Rows", 1)[1].split(
        "## Gate Failure Detail",
        1,
    )[0]
    assert "HM-01" not in missing_section
    assert "Preserve every existing `verify_*.md` file" in text
    assert "Do not advance to later pipeline phases" in text


def test_verify_timeout_recovers_missing_only_instead_of_whole_shard_retry(
    tmp_path: Path,
    monkeypatch,
):
    """A verifier timeout after partial output should recover only gaps.

    This is the live failure mode from large SC medium shards: the PTY never
    reaches end_turn, but several verify_<ID>.md files are already on disk.
    For verifier shards only, the driver should terminate that PTY and start a
    fresh missing-only verifier turn instead of spending a whole-shard retry.
    """
    project = tmp_path
    sp = project / ".scratchpad"
    sp.mkdir(parents=True)
    _write_sc_verification_queue(
        sp,
        [
            ("HM-01", "Medium", "first medium bug"),
            ("HM-02", "Medium", "second medium bug"),
        ],
    )
    _write_verify_file(sp, "HM-01")
    transcript = _empty_transcript(sp)
    phase = _make_sc_verify_medium_phase()
    invocations: list[set[str]] = []

    def _fake_respawn(*, row_statuses, **kwargs):
        assert not old_session.is_alive()
        incomplete = {
            r["name"] for r in row_statuses if r.get("status") != "complete"
        }
        invocations.append(incomplete)
        _write_verify_file(sp, "HM-02")
        return _MockSession(transcript_path=transcript, script=[lambda s: None])

    monkeypatch.setattr(D, "_respawn_missing_only", _fake_respawn)
    old_session = _MockSession(
        transcript_path=transcript,
        script=[lambda s: None],
        wait_complete=False,
    )

    rc, final = D._run_supervised_pty_loop(
        session=old_session,
        scratchpad=sp,
        project_root=str(project),
        phase=phase,
        config=_make_config(project),
        preflight={
            "live_pty_continue_supported": False,
            "agentid_resume_supported": False,
        },
        timeout=5.0,
        quiescence_s=0.0,
        on_poll=None,
        base_cmd=["claude", "--session-id", "test"],
        cwd=str(project),
        env={},
        log_file=None,
        prompt_path=sp / "prompt.md",
    )

    assert rc == 0
    assert final is not old_session
    assert old_session.terminate_calls >= 1
    assert invocations == [{"verify_HM-02.md"}]


def test_sc_medium_verify_timeout_bump_is_pinned():
    phases = {p.name: p for p in D.SC_PHASES}

    for name in (
        "sc_verify_medium_a",
        "sc_verify_medium_b",
        "sc_verify_medium_c",
        "sc_verify_medium_d",
    ):
        assert phases[name].base_timeout_s == 4800


# ---------------------------------------------------------------------------
# Test 25 -- non-PTY phase / non-supervised: should_run_preflight gates correctly
# ---------------------------------------------------------------------------


def test_non_pty_phase_uses_legacy_path():
    """The gate function used at the supervised-PTY entry point MUST
    return False for the non-PTY branch even on a supervised phase.
    This is the contract that lets run_phase route to the legacy
    linear PTY block (preserves existing rate-limit / timeout /
    EXIT_ERROR semantics) without any supervision wiring kicking in.

    Counterpart positive case is in test_preflight_pty.py test 29
    (claude + PTY + breadth -> True)."""
    # Non-PTY breadth -> supervision gate is False -> legacy path.
    assert (
        D.should_run_preflight(
            backend="claude",
            is_claude_pty=False,
            phase_name="breadth",
            supervised_phases=D.PTY_SUPERVISED_PHASES,
        )
        is False
    )
    # Codex backend on PTY for breadth -> still False (codex isn't
    # supervised at all in Ship 6).
    assert (
        D.should_run_preflight(
            backend="codex",
            is_claude_pty=True,
            phase_name="breadth",
            supervised_phases=D.PTY_SUPERVISED_PHASES,
        )
        is False
    )
    # Unsupervised phase (recon) on claude+PTY -> False -> legacy path.
    assert (
        D.should_run_preflight(
            backend="claude",
            is_claude_pty=True,
            phase_name="recon",
            supervised_phases=D.PTY_SUPERVISED_PHASES,
        )
        is False
    )
    # Happy path -- the only combination that supervises.
    assert (
        D.should_run_preflight(
            backend="claude",
            is_claude_pty=True,
            phase_name="breadth",
            supervised_phases=D.PTY_SUPERVISED_PHASES,
        )
        is True
    )


# ---------------------------------------------------------------------------
# Bonus -- supervised loop converges when missing-only respawn fills rows
# ---------------------------------------------------------------------------


def test_supervision_loop_converges_when_missing_only_completes_row(
    tmp_path: Path, monkeypatch
):
    """Sanity check that the supervision loop's happy path actually
    works end-to-end: start with one IN_PROGRESS row, fresh missing-only
    recovery fills it, and the loop converges with rc=0 on iteration 2.
    No continuation is sent into the old PTY."""
    project = tmp_path
    sp = project / ".scratchpad"
    sp.mkdir(parents=True)
    _touch_sentinel(sp)
    _write_breadth_manifest(sp, [("B1", "core_state")])
    _write_in_progress_artifact(sp, "analysis_core_state.md", "B1")
    transcript = _empty_transcript(sp)

    def _fake_respawn(**kwargs):
        _write_complete_artifact(sp, "analysis_core_state.md", "B1")
        return _MockSession(transcript_path=transcript, script=[lambda s: None])

    monkeypatch.setattr(D, "_respawn_missing_only", _fake_respawn)
    session = _MockSession(transcript_path=transcript, script=[lambda s: None])
    rc, final = D._run_supervised_pty_loop(
        session=session,
        scratchpad=sp,
        project_root=str(project),
        phase=_make_breadth_phase(),
        config=_make_config(project),
        preflight={
            "live_pty_continue_supported": True,
            "agentid_resume_supported": False,
        },
        timeout=5.0,
        quiescence_s=0.0,
        on_poll=None,
        base_cmd=["claude", "--session-id", "test"],
        cwd=str(project),
        env={},
        log_file=None,
        prompt_path=sp / "prompt.md",
    )
    assert rc == 0
    assert session.wait_calls == 1
    assert session.terminate_calls >= 1
    assert len(session.send_continuation_calls) == 0
    assert final is not session


def test_supervision_loop_repairs_generic_phase_from_gate_missing(
    tmp_path: Path, monkeypatch
):
    """Non-row phases with concrete expected artifacts still get the
    disposable PTY repair loop. When row status is empty, gate_missing is
    passed into the fresh missing-only session instead of forcing a whole
    phase retry."""
    project = tmp_path
    sp = project / ".scratchpad"
    sp.mkdir(parents=True)
    _touch_sentinel(sp)
    transcript = _empty_transcript(sp)
    prompt_path = sp / "_prompt_instantiate.attempt1.md"
    prompt_path.write_text("original instantiate prompt", encoding="utf-8")
    phase = D.Phase(
        name="instantiate",
        section_markers=["Phase 2"],
        expected_artifacts=["spawn_manifest.md"],
        base_timeout_s=60,
        min_artifact_bytes=40,
    )
    invocations: list[dict[str, Any]] = []

    def _fake_respawn(*, phase, scratchpad, row_statuses, base_cmd,
                      cwd, env, log_file, prompt_path, gate_missing=None):
        assert phase.name == "instantiate"
        assert row_statuses == []
        assert gate_missing
        assert any(
            "spawn_manifest_proposal.md" in str(item)
            for item in gate_missing
        )
        assert not old_session.is_alive()
        invocations.append({"gate_missing": list(gate_missing)})
        (scratchpad / "spawn_manifest_proposal.md").write_text(
            "# Spawn Manifest\n\n"
            "| Agent | Output |\n"
            "| --- | --- |\n"
            "| A1 | analysis_core_state.md |\n\n"
            + ("substantive manifest detail " * 20),
            encoding="utf-8",
        )
        return _MockSession(transcript_path=transcript, script=[lambda s: None])

    monkeypatch.setattr(D, "_respawn_missing_only", _fake_respawn)

    old_session = _MockSession(transcript_path=transcript, script=[lambda s: None])
    rc, final = D._run_supervised_pty_loop(
        session=old_session,
        scratchpad=sp,
        project_root=str(project),
        phase=phase,
        config=_make_config(project),
        preflight={},
        timeout=5.0,
        quiescence_s=0.0,
        on_poll=None,
        base_cmd=["claude", "--session-id", "test"],
        cwd=str(project),
        env={},
        log_file=None,
        prompt_path=prompt_path,
    )

    assert rc == 0
    assert len(invocations) == 1
    assert old_session.terminate_calls >= 1
    assert final is not old_session


def test_missing_only_generic_phase_uses_artifact_repair_prompt(tmp_path: Path):
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    prompt_path = sp / "_prompt_instantiate.attempt1.md"
    prompt_path.write_text("orig", encoding="utf-8")
    phase = D.Phase(
        name="instantiate",
        section_markers=["Phase 2"],
        expected_artifacts=["spawn_manifest.md"],
        base_timeout_s=60,
    )
    phase = D._model_owned_supervision_phase(phase)

    snap = D._build_missing_only_prompt(
        phase,
        sp,
        [],
        prompt_path,
        gate_missing=["spawn_manifest_proposal.md (stub only)"],
        now_ts=1_700_000_000,
    )
    txt = snap.read_text(encoding="utf-8")
    assert "Gate failure detail" in txt
    assert "spawn_manifest_proposal.md (stub only)" in txt
    assert "`spawn_manifest_proposal.md`" in txt
    assert "`spawn_manifest.md`" not in txt
    assert "Read the original phase prompt snapshot" in txt
    assert "Do not create any artifact outside the listed expected outputs" in txt


def test_depth_worker_normalizes_status_only_complete_marker(tmp_path: Path):
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    _touch_sentinel(sp)
    _write_depth_contract(sp)
    phase = _make_depth_phase(min_bytes=100)
    job = {
        "agent_id": "depth-token-flow",
        "role": "token_flow",
        "output": "depth_token_flow_findings.md",
        "category": "standard",
    }
    (sp / job["output"]).write_text(
        "<!-- PLAMEN_STATUS: COMPLETE -->\n"
        "# Depth Token-Flow Findings\n\n"
        "## Finding [DT-1]: Refund authorization bypass\n\n"
        + ("substantive trace evidence " * 20),
        encoding="utf-8",
    )

    assert D._depth_worker_output_complete(sp, phase, job) is True
    text = (sp / job["output"]).read_text(encoding="utf-8")
    assert "<!-- PLAMEN_ARTIFACT: depth_token_flow_findings.md -->" in text
    assert "<!-- PLAMEN_OWNER: depth-token-flow -->" in text
    assert "<!-- PLAMEN_PHASE: depth -->" in text
    assert "<!-- EXPECTED_OUTPUT: depth_token_flow_findings.md -->" in text
    assert text.rstrip().endswith("<!-- PLAMEN_STATUS: COMPLETE -->")


def test_depth_worker_normalizes_legacy_phase4b_complete_marker(tmp_path: Path):
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    _touch_sentinel(sp)
    _write_depth_contract(sp)
    phase = _make_depth_phase(min_bytes=100)
    job = {
        "agent_id": "depth-state-trace",
        "role": "state_trace",
        "output": "depth_state_trace_findings.md",
        "category": "standard",
    }
    (sp / job["output"]).write_text(
        "# Depth State-Trace Findings\n\n"
        "<!-- PLAMEN:PHASE4B:depth_state_trace_findings:COMPLETE:12 -->\n\n"
        "## Finding [DS-1]: Fee state can exceed denominator\n\n"
        + ("state trace evidence " * 25),
        encoding="utf-8",
    )

    assert D._depth_worker_output_complete(sp, phase, job) is True
    text = (sp / job["output"]).read_text(encoding="utf-8")
    assert "PLAMEN:PHASE4B" not in text
    assert "<!-- PLAMEN_ARTIFACT: depth_state_trace_findings.md -->" in text
    assert "<!-- PLAMEN_PHASE: depth -->" in text


def test_depth_worker_normalizes_phase_4b_to_depth(tmp_path: Path):
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    _touch_sentinel(sp)
    _write_depth_contract(sp)
    phase = _make_depth_phase(min_bytes=100)
    job = {
        "agent_id": "depth-external",
        "role": "external",
        "output": "depth_external_findings.md",
        "category": "standard",
    }
    (sp / job["output"]).write_text(
        "# Depth External Findings\n\n"
        "<!-- PLAMEN_ARTIFACT: depth_external_findings.md -->\n"
        "<!-- PLAMEN_OWNER: depth-external -->\n"
        "<!-- PLAMEN_STATUS: COMPLETE -->\n"
        "<!-- PLAMEN_PHASE: 4b -->\n\n"
        "## Finding [DX-1]: Cross-chain callback can leak value\n\n"
        + ("external call evidence " * 25),
        encoding="utf-8",
    )

    assert D._depth_worker_output_complete(sp, phase, job) is True
    text = (sp / job["output"]).read_text(encoding="utf-8")
    assert "<!-- PLAMEN_PHASE: 4b -->" not in text
    assert "<!-- PLAMEN_PHASE: depth -->" in text
    assert "<!-- EXPECTED_OUTPUT: depth_external_findings.md -->" in text


def test_depth_worker_preserves_valid_transactional_envelope_bytes(tmp_path: Path):
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    _touch_sentinel(sp)
    _write_depth_contract(sp)
    phase = _make_depth_phase(min_bytes=100)
    job = {
        "agent_id": "depth-token-flow",
        "role": "token_flow",
        "output": "depth_token_flow_findings.md",
        "category": "standard",
    }
    raw = (
        "<!-- PLAMEN_DISPATCH_PHASE: depth -->\n"
        "<!-- PLAMEN_DISPATCH_WORKER: depth-token-flow -->\n"
        "<!-- PLAMEN_ARTIFACT: depth_token_flow_findings.md -->\n"
        "<!-- PLAMEN_OWNER: depth-token-flow -->\n"
        "<!-- PLAMEN_STATUS: IN_PROGRESS -->\n"
        "<!-- PLAMEN_PHASE: depth -->\n"
        "<!-- PLAMEN_VERSION: 1 -->\n"
        "<!-- AGENT_ROW: depth-token-flow -->\n"
        "<!-- EXPECTED_OUTPUT: depth_token_flow_findings.md -->\n\n"
        "# Depth Token-Flow Findings\n\n"
        "## Finding [DT-1]: Refund authorization bypass\n\n"
        + ("substantive trace evidence " * 20)
        + "\n<!-- PLAMEN_STATUS: COMPLETE -->\n"
    ).encode()
    path = sp / job["output"]
    path.write_bytes(raw)
    before_stat = path.stat()

    assert D._depth_worker_output_complete(sp, phase, job) is True
    after_stat = path.stat()
    assert path.read_bytes() == raw
    assert after_stat.st_ino == before_stat.st_ino



def test_depth_worker_wraps_substantive_markerless_file_only_after_final_turn(tmp_path: Path):
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    _touch_sentinel(sp)
    _write_depth_contract(sp)
    phase = _make_depth_phase(min_bytes=100)
    job = {
        "agent_id": "depth-state-trace",
        "role": "state_trace",
        "output": "depth_state_trace_findings.md",
        "category": "standard",
    }
    (sp / job["output"]).write_text(
        "# Depth State Trace Findings\n\n"
        "## Finding [DS-1]: Cross-function invariant break\n\n"
        + ("state mutation evidence with concrete call path " * 25),
        encoding="utf-8",
    )

    assert D._depth_worker_output_complete(sp, phase, job) is False
    assert D._depth_worker_output_complete(
        sp,
        phase,
        job,
        final_turn_complete=True,
    ) is True
    text = (sp / job["output"]).read_text(encoding="utf-8")
    assert "<!-- PLAMEN_ARTIFACT: depth_state_trace_findings.md -->" in text
    assert "<!-- PLAMEN_OWNER: depth-state-trace -->" in text
    assert text.rstrip().endswith("<!-- PLAMEN_STATUS: COMPLETE -->")


def test_depth_worker_does_not_complete_in_progress_file(tmp_path: Path):
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    _touch_sentinel(sp)
    _write_depth_contract(sp)
    phase = _make_depth_phase(min_bytes=100)
    job = {
        "agent_id": "depth-edge-case",
        "role": "edge_case",
        "output": "depth_edge_case_findings.md",
        "category": "standard",
    }
    (sp / job["output"]).write_text(
        "# Depth Edge Case Findings\n\n"
        "<!-- PLAMEN_STATUS: IN_PROGRESS -->\n\n"
        "## Finding [DE-1]: Boundary case trace\n\n"
        + ("boundary evidence " * 25),
        encoding="utf-8",
    )

    assert D._depth_worker_output_complete(sp, phase, job) is False
    text = (sp / job["output"]).read_text(encoding="utf-8")
    assert "<!-- PLAMEN_ARTIFACT: depth_edge_case_findings.md -->" not in text
    assert "<!-- PLAMEN_STATUS: IN_PROGRESS -->" in text


def test_live_containment_protects_chain_agent2_outputs(tmp_path: Path):
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    active = ["chain", "chain_agent2", "chain_iter2", "sc_verify_queue"]

    protected = set(
        D._live_protected_phase_write_patterns(sp, "sc", "chain", active)
    )

    assert "chain_hypotheses.md" in protected
    assert "composition_coverage.md" in protected
    assert "synthesis_full.md" in protected
    assert "hypotheses.md" not in protected
    assert "finding_mapping.md" not in protected
    assert "enabler_results.md" not in protected


def test_live_containment_preserves_depth_benign_chain_quarantine(tmp_path: Path):
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    active = ["depth", "rag_sweep", "chain", "chain_agent2", "sc_verify_queue"]

    protected = set(
        D._live_protected_phase_write_patterns(sp, "sc", "depth", active)
    )

    assert "rag_validation.md" in protected
    assert "verification_queue.md" in protected
    assert "hypotheses.md" not in protected
    assert "chain_hypotheses.md" not in protected
    assert "composition_coverage.md" not in protected
    assert "synthesis_full.md" not in protected


def test_live_containment_preserves_inventory_chunk_benign_handoffs(tmp_path: Path):
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    active = [
        "inventory_chunk_a",
        "inventory_chunk_b",
        "inventory",
        "invariants",
        "depth",
    ]

    protected = set(
        D._live_protected_phase_write_patterns(
            sp, "sc", "inventory_chunk_a", active
        )
    )

    assert "findings_inventory_chunk_b.md" not in protected
    assert "findings_inventory.md" not in protected
    assert "semantic_invariants.md" not in protected
    assert "depth_*_findings.md" in protected


def test_phase_isolation_block_is_universal_and_output_scoped():
    phase = D.Phase(
        name="inventory_chunk_a",
        section_markers=["Phase 3"],
        expected_artifacts=[
            "findings_inventory_chunk_a.md",
        ],
        base_timeout_s=60,
    )

    block = D._render_phase_isolation_block(phase)
    low = block.lower()

    assert "exactly one driver-owned phase: `inventory_chunk_a`" in block
    assert "ONLY the files/patterns in the EXPECTED OUTPUT FILES contract" in block
    assert "Do NOT perform work for any other pipeline phase" in block
    assert "Do NOT create, modify, repair, or pre-fill scratchpad artifacts" in block
    assert "prior-phase artifacts as read-only inputs" in block
    for forbidden in (
        "verification",
        "chain analysis",
        "report",
        "skeptic",
        "cross-batch",
        "rag validation",
    ):
        assert forbidden not in low
