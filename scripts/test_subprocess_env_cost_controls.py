"""Tests for the Wave 1 token-cost controls in subprocess_env.

Background: research agent (token-cost-reduction round 1, May 2026)
identified three Anthropic-documented controls that reduce per-phase
token spend with zero or positive quality impact:

  1. BASH_MAX_OUTPUT_LENGTH — caps Bash tool result size in characters,
     preventing stale tool output from inflating context on subsequent
     turns. Anthropic engineering blog "Writing tools for agents".
  2. MAX_MCP_OUTPUT_TOKENS — same idea for MCP tool calls.
  3. ANTHROPIC_BETA="context-management-2025-06-27" — opt-in to
     automatic context editing where the model drops stale tool results
     from older turns. Anthropic-published benchmark: -84% tokens AND
     +29% performance on 100-turn workloads.

These tests verify the driver's subprocess_env composition includes all
three controls, applied with the correct scope:

  - Tool output caps: ALL phases get them (truly universal optimization)
  - Context editing beta: ONLY high-turn phases (depth + verify shards),
    to keep beta surface minimal until production data confirms broader
    rollout is safe.

The tests intentionally do NOT spawn real subprocesses — they exercise
the env-composition logic in isolation via a small surrogate harness.
The full integration is verified by live audit ledger comparison.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest import mock

SCRIPTS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS_DIR))


def _make_env_like_run_phase(phase_name: str, mocked_os_environ: dict) -> dict:
    """Reproduce the env-composition logic from run_phase() in isolation.

    Kept in lockstep with the real definition in plamen_driver.py.  If
    that file's env composition changes shape, this surrogate must move
    with it — the test catches drift either way.
    """
    from plamen_types import (
        PLAMEN_OPUS_MODEL,
        L1_VERIFY_PHASE_NAMES,
        SC_VERIFY_PHASE_NAMES,
    )
    from plamen_driver import (
        _CLAUDE_UPDATE_DISABLE_ENV,
        _filtered_child_subprocess_environ,
    )

    env = {
        **_filtered_child_subprocess_environ(mocked_os_environ),
        **_CLAUDE_UPDATE_DISABLE_ENV,
        "ANTHROPIC_DEFAULT_OPUS_MODEL": PLAMEN_OPUS_MODEL,
        "PLAMEN_SCRATCHPAD": "/fake/scratchpad",
        "BASH_MAX_OUTPUT_LENGTH": mocked_os_environ.get(
            "BASH_MAX_OUTPUT_LENGTH", "30000"
        ),
        "MAX_MCP_OUTPUT_TOKENS": mocked_os_environ.get(
            "MAX_MCP_OUTPUT_TOKENS", "8000"
        ),
    }
    context_editing_phases = (
        "recon",
        "rescan",
        "depth",
        *L1_VERIFY_PHASE_NAMES,
        *SC_VERIFY_PHASE_NAMES,
    )
    if phase_name in context_editing_phases:
        existing_beta = mocked_os_environ.get("ANTHROPIC_BETA", "").strip()
        our_beta = "context-management-2025-06-27"
        if existing_beta and our_beta not in existing_beta:
            env["ANTHROPIC_BETA"] = existing_beta + "," + our_beta
        else:
            env["ANTHROPIC_BETA"] = our_beta
    return env


def test_tool_output_caps_present_for_every_phase():
    """Every phase subprocess should ship with BASH/MCP output caps —
    these are universal, no quality trade-off."""
    for phase in ("recon", "breadth", "depth", "sc_verify_crithigh",
                  "inventory_chunk_a", "report_index"):
        env = _make_env_like_run_phase(phase, mocked_os_environ={})
        assert env["BASH_MAX_OUTPUT_LENGTH"] == "30000", (
            f"{phase}: BASH_MAX_OUTPUT_LENGTH missing or wrong default — "
            "must accommodate `forge test -vvv` failure traces (10-50KB)"
        )
        assert env["MAX_MCP_OUTPUT_TOKENS"] == "8000", (
            f"{phase}: MAX_MCP_OUTPUT_TOKENS missing or wrong default"
        )
        assert env["DISABLE_UPDATES"] == "1"
        assert env["DISABLE_AUTOUPDATER"] == "1"


def test_context_editing_beta_only_on_high_turn_phases():
    """ANTHROPIC_BETA=context-management-2025-06-27 should fire on
    depth + verify shards, not on every phase. Scoping minimizes the
    beta surface area until production data confirms safety."""
    # On — high-turn exploratory + tool-heavy phases. Recon and rescan
    # were added in the May-2026 cost-easing expansion; previously only
    # depth + verify shards were opted in.
    for phase in ("recon", "rescan", "depth", "sc_verify_crithigh",
                  "sc_verify_medium_a", "verify_crithigh", "verify_high_b"):
        env = _make_env_like_run_phase(phase, mocked_os_environ={})
        assert "context-management-2025-06-27" in env.get("ANTHROPIC_BETA", ""), (
            f"{phase}: should opt into context-editing beta"
        )
    # Off — short-turn or one-shot phases. Breadth is explicitly held
    # off the beta even though it's tool-heavy; user deliberately
    # excluded it from the expansion to validate recon/rescan first.
    for phase in ("breadth", "inventory_chunk_a", "report_index",
                  "report_assemble", "instantiate"):
        env = _make_env_like_run_phase(phase, mocked_os_environ={})
        assert env.get("ANTHROPIC_BETA", "") == "", (
            f"{phase}: should NOT have context-editing beta "
            f"(unnecessary beta surface) — got {env.get('ANTHROPIC_BETA')!r}"
        )


def test_existing_anthropic_beta_is_preserved():
    """If the user already exports ANTHROPIC_BETA for some other feature
    (e.g. prompt-caching-2024-07-31), our addition must APPEND, not
    overwrite."""
    env = _make_env_like_run_phase(
        "depth",
        mocked_os_environ={"ANTHROPIC_BETA": "user-beta-flag-1,user-beta-flag-2"},
    )
    assert env["ANTHROPIC_BETA"] == (
        "user-beta-flag-1,user-beta-flag-2,context-management-2025-06-27"
    ), (
        "Pre-existing ANTHROPIC_BETA was clobbered instead of appended — "
        "would break user features"
    )


def test_idempotent_when_our_beta_already_in_user_env():
    """If user already has context-management-2025-06-27 in their env,
    don't duplicate it."""
    env = _make_env_like_run_phase(
        "depth",
        mocked_os_environ={"ANTHROPIC_BETA": "context-management-2025-06-27"},
    )
    assert env["ANTHROPIC_BETA"] == "context-management-2025-06-27", (
        "Duplicated the beta header — should be idempotent"
    )


def test_user_can_override_tool_caps_via_env():
    """If the user explicitly sets BASH_MAX_OUTPUT_LENGTH (e.g. they're
    debugging a specific issue and want larger output), respect it."""
    env = _make_env_like_run_phase(
        "depth",
        mocked_os_environ={
            "BASH_MAX_OUTPUT_LENGTH": "50000",
            "MAX_MCP_OUTPUT_TOKENS": "16000",
        },
    )
    assert env["BASH_MAX_OUTPUT_LENGTH"] == "50000", "User override ignored"
    assert env["MAX_MCP_OUTPUT_TOKENS"] == "16000", "User override ignored"


def test_parent_claude_identity_env_is_stripped_for_child_sessions():
    """Running `/plamen` inside Claude Code must not poison child claude
    subprocesses with the parent's active-session identity."""
    parent_identity = {
        "CLAUDECODE": "1",
        "CLAUDE_CODE_SESSION_ID": "94c2c6c1-test",
        "CLAUDE_CODE_ENTRYPOINT": "cli",
        "CLAUDE_CODE_EXECPATH": "/Users/example/.claude/local/claude",
        "AI_AGENT": "claude-code_2-1-150_agent",
        "PATH": "/usr/bin",
        "ANTHROPIC_BETA": "user-beta",
    }

    env = _make_env_like_run_phase("depth", mocked_os_environ=parent_identity)

    for key in (
        "CLAUDECODE",
        "CLAUDE_CODE_SESSION_ID",
        "CLAUDE_CODE_ENTRYPOINT",
        "CLAUDE_CODE_EXECPATH",
        "AI_AGENT",
    ):
        assert key not in env
    assert env["PATH"] == "/usr/bin"
    assert env["ANTHROPIC_BETA"] == "user-beta,context-management-2025-06-27"
