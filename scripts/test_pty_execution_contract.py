"""Ship 8.8: PTY-aware execution contract.

The default claude exec mode is "pty" -- a PERSISTENT interactive session, NOT
`claude -p` single-turn. The supervision loop (Ship 6) may CONTINUE a phase
after a turn, and completion is derived from disk artifacts. The old
single-turn / one-wave / "exiting orphans agents" framing is therefore FALSE
under PTY and pushes the coordinator toward a premature DONE (an observed verified
failure). Ship 8.8 selects a PTY variant by exec mode.

These tests assert on BOTH levels:
  1. `_render_execution_contract` constant dispatch (backend x exec_mode).
  2. The fully RENDERED breadth / depth prompt via `build_phase_prompt` -- the
     thing the coordinator actually reads -- has no surviving single-turn /
     one-wave contradiction and DOES carry the disk-derived completion rule.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

SCRIPTS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS_DIR))

import plamen_prompt as p  # noqa: E402
from plamen_prompt import (  # noqa: E402
    _PLAMEN_EXECUTION_CONTRACT_CLAUDE,
    _PLAMEN_EXECUTION_CONTRACT_CLAUDE_PTY,
    _PLAMEN_EXECUTION_CONTRACT_CLAUDE_PTY_BREADTH,
    _PLAMEN_EXECUTION_CONTRACT_CLAUDE_PTY_UNSUPERVISED,
    _derive_claude_exec_mode,
    _render_execution_contract,
)
from plamen_types import SC_PHASES  # noqa: E402

# Phrases that MUST NOT appear in a PTY contract (they are false under PTY).
_FORBIDDEN_PTY_PHRASES = (
    "single-turn",
    "exactly ONE turn",
    "one wave",
    "Wave 1",
    "Wave 2",
    "claude -p` single-turn",
)
# The load-bearing disk-derived completion signal the PTY variant MUST carry.
_DISK_DERIVED_MARKERS = (
    "DISK-derived",
    "PLAMEN_STATUS: COMPLETE",
    "compaction summary",
)


# ---------------------------------------------------------------------------
# Level 1 -- constant dispatch
# ---------------------------------------------------------------------------


def test_pty_variant_drops_single_turn_and_wave_language():
    block = _render_execution_contract(
        "breadth", "sc", backend="claude", exec_mode="pty"
    )
    assert block, "PTY breadth contract should be non-empty (Task-using phase)"
    low = block.lower()
    assert "single-turn" not in low
    assert "single turn" not in low
    assert "exactly one turn" not in low
    assert "one wave" not in low
    assert "wave 1" not in low and "wave 2" not in low


def test_pty_variant_has_disk_derived_completion():
    block = _render_execution_contract(
        "depth", "sc", backend="claude", exec_mode="pty"
    )
    for marker in _DISK_DERIVED_MARKERS:
        assert marker in block, f"PTY contract missing disk-derived marker: {marker!r}"
    assert "spawn_manifest.md" not in block
    assert "required output list / canonical role list" in block


def test_depth_pty_variant_keeps_foreground_rule():
    """Depth still uses foreground Task calls under PTY."""
    block = _render_execution_contract(
        "depth", "sc", backend="claude", exec_mode="pty"
    )
    assert "run_in_background" in block  # foreground rule preserved
    assert "expected_artifacts" in block  # stay-in-scope preserved
    assert "crash recovery" in block  # reservation-header rule preserved


def test_unsupervised_pty_variant_does_not_promise_continuation():
    block = _render_execution_contract(
        "rescan", "sc", backend="claude", exec_mode="pty"
    )
    assert block == _PLAMEN_EXECUTION_CONTRACT_CLAUDE_PTY_UNSUPERVISED
    assert "NOT one of the driver's supervised continuation phases" in block
    assert "do not rely" in block.lower()
    assert "future continuation turn" in block
    assert "run_in_background: true" in block
    assert "spawn_manifest.md" not in block


def test_breadth_pty_variant_requires_background_full_roster():
    """Breadth is different from depth: its agents are independent manifest
    rows, so Claude PTY must launch the full missing roster in background
    rather than serializing foreground workers."""
    block = _render_execution_contract(
        "breadth", "sc", backend="claude", exec_mode="pty"
    )
    assert block == _PLAMEN_EXECUTION_CONTRACT_CLAUDE_PTY_BREADTH
    assert "run_in_background: true" in block
    assert "Spawn every missing breadth row immediately" in block
    assert "Do NOT split 7+ rows into waves" in block


def test_headless_variant_retains_legacy_single_turn():
    """Headless `claude -p` IS single-turn -- the legacy contract is correct
    there and MUST be preserved verbatim."""
    block = _render_execution_contract(
        "breadth", "sc", backend="claude", exec_mode="headless"
    )
    assert block == _PLAMEN_EXECUTION_CONTRACT_CLAUDE
    assert "single-turn" in block
    assert "exactly ONE turn" in block


def test_codex_variant_unchanged_regardless_of_exec_mode():
    """Codex `exec` is single-shot; its contract is exec-mode-independent."""
    for mode in ("pty", "headless"):
        block = _render_execution_contract(
            "depth", "sc", backend="codex", exec_mode=mode
        )
        assert "spawn_agent" in block
        assert "wait_agent" in block
        assert "run_in_background" not in block


def test_default_exec_mode_is_pty():
    """Omitting exec_mode defaults to the PTY variant (the common case)."""
    block = _render_execution_contract("depth", "sc", backend="claude")
    assert block == _PLAMEN_EXECUTION_CONTRACT_CLAUDE_PTY


def test_derive_exec_mode_precedence(monkeypatch):
    monkeypatch.delenv("PLAMEN_CLAUDE_EXEC_MODE", raising=False)
    assert _derive_claude_exec_mode({}) == "pty"
    assert _derive_claude_exec_mode({"claude_exec_mode": "headless"}) == "headless"
    # explicit config wins over env
    monkeypatch.setenv("PLAMEN_CLAUDE_EXEC_MODE", "headless")
    assert _derive_claude_exec_mode({"claude_exec_mode": "pty"}) == "pty"
    # env used when config absent
    assert _derive_claude_exec_mode({}) == "headless"
    # malformed explicit authority is never silently downgraded
    monkeypatch.setenv("PLAMEN_CLAUDE_EXEC_MODE", "nonsense")
    with pytest.raises(ValueError, match="invalid claude_exec_mode"):
        _derive_claude_exec_mode({})


# ---------------------------------------------------------------------------
# Level 2 -- fully rendered prompt (what the coordinator actually reads)
# ---------------------------------------------------------------------------


def _render_prompt(tmp_root: Path, phase_name: str, exec_mode: str,
                   backend: str = "claude") -> str:
    scratch = tmp_root / ".scratchpad"
    project = tmp_root / "proj"
    scratch.mkdir(parents=True, exist_ok=True)
    project.mkdir(parents=True, exist_ok=True)
    section = {
        "recon": (Path(__file__).resolve().parents[1] / "prompts" / "evm" / "v2" / "phase1-recon-prompt.md").read_text(encoding="utf-8"),
        "breadth": "## Phase 3: Parallel Breadth Analysis\n\nSpawn agents.\n",
        "depth": "## Phase 4b: Depth Analysis Loop\n\nSpawn depth agents.\n",
    }[phase_name]
    v1 = scratch / "v1.md"
    v1.write_text(section + ("BODY " * 80), encoding="utf-8")
    cfg = {
        "project_root": str(project),
        "scratchpad": str(scratch),
        "language": "evm",
        "mode": "thorough",
        "pipeline": "sc",
        "proven_only": False,
        "cli_backend": backend,
        "claude_exec_mode": exec_mode,
    }
    phase = next(ph for ph in SC_PHASES if ph.name == phase_name)
    return p.build_phase_prompt(v1, phase, cfg)


def test_rendered_pty_breadth_prompt_has_no_single_turn_contradiction(tmp_path):
    rendered = _render_prompt(tmp_path, "breadth", exec_mode="pty")
    low = rendered.lower()
    assert "single-turn" not in low
    assert "exactly one turn" not in low
    assert "one wave" not in low
    # disk-derived completion directive present in the rendered prompt
    assert "DISK-derived" in rendered
    assert "spawn_manifest.md" in rendered
    assert "PLAMEN_STATUS: COMPLETE" in rendered
    assert "run_in_background: true" in rendered
    assert "Spawn every missing breadth row immediately" in rendered
    assert "at most 6 parallel Task calls per batch" not in rendered
    assert "All Task calls MUST be foreground" not in rendered


def test_rendered_pty_recon_prompt_has_no_spawn_manifest_leakage(tmp_path):
    rendered = _render_prompt(tmp_path, "recon", exec_mode="pty")
    assert "spawn_manifest.md" not in rendered
    assert "Use the Task tool" not in rendered
    assert "MUST spawn an agent" not in rendered
    assert "Orchestrator MUST spawn" not in rendered
    assert "dynamic shard outputs named by this phase" not in rendered
    assert "Do NOT use the Task tool" in rendered
    assert "Recommendation Summary" in rendered


def test_rendered_pty_depth_prompt_has_no_single_turn_contradiction(tmp_path):
    rendered = _render_prompt(tmp_path, "depth", exec_mode="pty")
    low = rendered.lower()
    assert "single-turn" not in low
    assert "exactly one turn" not in low
    assert "one wave" not in low
    assert "DISK-derived" in rendered
    assert "PLAMEN_STATUS: COMPLETE" in rendered
    assert "required output list / canonical role list" in rendered
    assert "spawn_manifest.md" not in rendered.split("## PLAMEN V2 EXECUTION CONTRACT", 1)[1].split("## Phase", 1)[0]


def test_rendered_pty_rescan_does_not_claim_supervised_continuation(tmp_path):
    scratch = tmp_path / ".scratchpad"
    project = tmp_path / "proj"
    scratch.mkdir(parents=True, exist_ok=True)
    project.mkdir(parents=True, exist_ok=True)
    v1 = scratch / "v1.md"
    v1.write_text("## Phase 3b: Breadth Re-Scan\n\nSpawn rescan agents.\n", encoding="utf-8")
    cfg = {
        "project_root": str(project),
        "scratchpad": str(scratch),
        "language": "evm",
        "mode": "thorough",
        "pipeline": "sc",
        "proven_only": False,
        "cli_backend": "claude",
        "claude_exec_mode": "pty",
    }
    phase = next(ph for ph in SC_PHASES if ph.name == "rescan")
    rendered = p.build_phase_prompt(v1, phase, cfg)
    assert "NOT one of the driver's supervised continuation phases" in rendered
    assert "do not rely" in rendered.lower()
    assert "future continuation turn" in rendered
    assert "driver may CONTINUE this phase" not in rendered


def test_rendered_headless_breadth_prompt_retains_single_turn(tmp_path):
    """A headless render still carries the legacy single-turn contract --
    correct, because `claude -p` really is single-turn."""
    rendered = _render_prompt(tmp_path, "breadth", exec_mode="headless")
    assert "single-turn" in rendered
    assert "exactly ONE turn" in rendered
