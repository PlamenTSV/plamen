"""2026-06-02: Codex depth Expected-Output-Contract widening.

Root cause: the base depth prompt's `OUTPUT ALLOWLIST (HARD)` and `PHASE
ISOLATION CONTRACT` derive their allowed/writable set from "this phase's
Expected Output Contract", which lists only the `depth_*_findings.md` core glob
(from `phase.expected_artifacts`). On Codex (single-turn, full base prompt) the
model reads the allowlist literally and refuses the never-cut secondaries
(blind-spot scanners, validation sweep, confidence, niche) as "outside the
allowlist" — failing the never-cut gate even though it precreated them and the
checklist asked for them. Claude PTY never hits this: its depth prompt is
replaced by the worker-pool stub (one allowlisted worker per artifact).

Fix: `_codex_widen_depth_output_contract` lists the secondaries INSIDE the
Expected Output Contract so both downstream HARD references include them. It
runs ONLY inside `_translate_prompt_for_codex` (the `backend == "codex"` path),
so it cannot affect a Claude run.
"""
from __future__ import annotations

from pathlib import Path

import plamen_driver as D
from plamen_prompt import _render_forbidden_output_block, _render_phase_isolation_block
from plamen_types import Phase


_HEADER = "## EXPECTED OUTPUT FILES (HARD CONTRACT -- GATE WILL FAIL IF VIOLATED)"
_SECONDARIES = ["blind_spot_a_findings.md", "blind_spot_b_findings.md",
                "blind_spot_c_findings.md", "validation_sweep_findings.md"]
_DRIVER_ONLY = {
    "confidence_scores.md",
    "confidence_consensus_authority.json",
    "consensus_map.md",
}


# ---------- name-list helper (single source of truth) ----------

def test_secondary_names_sc_core_include_only_model_owned_outputs():
    names = D._codex_mandatory_secondary_names("depth", "sc", "core", None)
    for n in _SECONDARIES:
        assert n in names, f"{n} missing from sc-core secondary names"
    assert _DRIVER_ONLY.isdisjoint(names)


def test_secondary_names_recon_and_non_depth():
    # recon returns its worker shards; an unrelated phase returns nothing.
    assert D._codex_mandatory_secondary_names("verify", "sc", "core", None) == []


def test_widen_list_excludes_core_depth_glob():
    # The list fed to the contract widening (computed in _translate_prompt_for_codex)
    # drops depth_*_findings.md reps since the core glob already covers them.
    names = D._codex_mandatory_secondary_names("depth", "sc", "core", None)
    widen = [n for n in names
             if not (n.startswith("depth_") and n.endswith("_findings.md"))]
    assert set(widen) == set(_SECONDARIES)
    assert not any(n.startswith("depth_") for n in widen)


# ---------- the widening transform ----------

def test_widen_injects_secondaries_after_header():
    base = (
        "# DEPTH\n\n"
        + _HEADER + "\n\n"
        + "### Required outputs\n\n- **`depth_*_findings.md`** -- glob.\n\n"
        + "## OUTPUT ALLOWLIST (HARD)\n\nYour allowed output files are exactly "
          "the artifacts listed in this phase's Expected Output Contract.\n"
    )
    out = D._codex_widen_depth_output_contract(base, _SECONDARIES)
    # secondaries now appear, and within the contract section (before the allowlist)
    for n in _SECONDARIES:
        assert f"`{n}`" in out
    assert not any(f"`{name}`" in out for name in _DRIVER_ONLY)
    contract_idx = out.index(_HEADER)
    allowlist_idx = out.index("## OUTPUT ALLOWLIST (HARD)")
    for n in _SECONDARIES:
        assert contract_idx < out.index(f"`{n}`") < allowlist_idx, \
            f"{n} not inside the Expected Output Contract section"


def test_widen_noop_without_header():
    base = "# DEPTH\n\nno contract header here\n"
    assert D._codex_widen_depth_output_contract(base, _SECONDARIES) == base


def test_widen_noop_empty_names():
    base = _HEADER + "\n\nstuff\n"
    assert D._codex_widen_depth_output_contract(base, []) == base


def test_widen_idempotent_single_injection():
    base = _HEADER + "\n\nx\n## OUTPUT ALLOWLIST (HARD)\ny\n"
    out = D._codex_widen_depth_output_contract(base, _SECONDARIES)
    # header replaced exactly once -> only one injected block
    assert out.count("### Mandatory secondary outputs") == 1


# ---------- Claude isolation: shared prompt builders are untouched ----------

def test_shared_depth_allowlist_block_unchanged():
    # The shared builder must NOT have learned about secondaries — the fix lives
    # only in the Codex translation path.
    block = _render_forbidden_output_block("depth")
    assert "OUTPUT ALLOWLIST (HARD)" in block
    assert "blind_spot" not in block
    assert "confidence_scores" not in block
    assert "validation_sweep" not in block


def test_shared_depth_isolation_block_unchanged():
    phase = Phase("depth", ["x"], ["depth_*_findings.md"],
                  base_timeout_s=60, min_artifact_bytes=200)
    block = _render_phase_isolation_block(phase)
    assert "blind_spot" not in block
    assert "validation_sweep" not in block


# ---------- end-to-end translation (only when a codex home exists) ----------

def _fake_codex_home(monkeypatch, tmp_path) -> Path:
    home = tmp_path / "home"
    (home / ".codex" / "plamen").mkdir(parents=True)
    monkeypatch.setattr(Path, "home", lambda: home)
    return home


def test_translate_depth_widens_contract(monkeypatch, tmp_path):
    _fake_codex_home(monkeypatch, tmp_path)
    base = (
        "# DEPTH PHASE\n\n"
        + _HEADER + "\n\n- **`depth_*_findings.md`** -- glob.\n\n"
        + "## OUTPUT ALLOWLIST (HARD)\n\nallowed = Expected Output Contract.\n"
    )
    out = D._translate_prompt_for_codex(
        base, phase_name="depth", pipeline="sc", mode="core", scratchpad=None
    )
    for n in _SECONDARIES:
        assert f"`{n}`" in out


def test_translate_non_depth_does_not_widen(monkeypatch, tmp_path):
    _fake_codex_home(monkeypatch, tmp_path)
    base = _HEADER + "\n\n- **`verify_*.md`** -- glob.\n"
    out = D._translate_prompt_for_codex(
        base, phase_name="verify", pipeline="sc", mode="core", scratchpad=None
    )
    assert "### Mandatory secondary outputs" not in out
    assert "blind_spot_a_findings.md" not in out
