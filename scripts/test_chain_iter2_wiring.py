"""Wiring + soft-validation tests for Phase 4c iteration 2.

Same V1→V2 wiring gap class as Phase 4a.5 Pass 2: the prompt file
exists, the documentation in rules/phase4c-chain-prompt.md describes
the iteration-2 spawn explicitly, but the V2 driver had no Phase entry
to schedule it. Mode matrix (orchestrator-rules.md L41) says Thorough
gets "2 agents + iteration 2" — V2 only delivered "2 agents."

These tests lock in:

  1. The prompt mapping in `_STANDALONE_PROMPT_MAP`.
  2. The Phase entry in `SC_PHASES` (L1 has NO chain analysis per
     design.md §4, so no L1 entry is needed and we test that absence).
  3. Thorough-only mode gating.
  4. Soft validator never returns hard issues.
  5. Driver pre-spawn early-exit when composition_coverage.md has 0
     unexplored cross-class Medium+ pairs (the ITERATIVE_CHAIN_COMPOSITION
     early-exit rule). This avoids wasting ~$1-2 of sonnet on a
     no-op iteration.
"""
from __future__ import annotations

import sys
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS_DIR))


# -------- Wiring ----------------------------------------------------------

def test_chain_iter2_standalone_prompt_mapped():
    from plamen_prompt import _STANDALONE_PROMPT_MAP, _STANDALONE_V2_DIR
    assert "chain_iter2" in _STANDALONE_PROMPT_MAP
    prompt_path = _STANDALONE_V2_DIR / _STANDALONE_PROMPT_MAP["chain_iter2"]
    assert prompt_path.exists(), (
        f"Mapped prompt file missing on disk: {prompt_path}."
    )


def test_chain_iter2_phase_entry_in_sc_phases():
    from plamen_types import SC_PHASES
    p = next((p for p in SC_PHASES if p.name == "chain_iter2"), None)
    assert p is not None, "chain_iter2 phase missing from SC_PHASES"
    assert p.modes == {"thorough"}, (
        f"chain_iter2 mode set should be {{thorough}}, got {p.modes!r}."
    )
    assert p.critical is False, (
        "chain_iter2.critical MUST be False — iteration 2 is enrichment."
    )
    assert p.model == "sonnet"


def test_chain_iter2_NOT_in_l1_phases():
    """L1 mode has NO chain analysis (per design.md §4 — L1 bugs are
    point vulnerabilities, not enabler chains). Therefore L1 must NOT
    have a chain_iter2 entry. Locking this in so a future refactor
    doesn't accidentally add one."""
    from plamen_types import L1_PHASES
    for p in L1_PHASES:
        assert p.name != "chain_iter2", (
            "L1 must not include chain_iter2 — L1 has no chain analysis."
        )


def test_chain_iter2_runs_after_chain_agent2():
    from plamen_types import SC_PHASES
    names = [p.name for p in SC_PHASES]
    assert "chain_agent2" in names and "chain_iter2" in names
    i1 = names.index("chain_agent2")
    i2 = names.index("chain_iter2")
    assert i2 > i1, (
        f"chain_iter2 must run after chain_agent2 (got positions "
        f"{i1} → {i2}); the iteration needs Agent 2's "
        f"composition_coverage.md as input."
    )


# -------- Soft validator --------------------------------------------------

def _write(p: Path, body: str) -> None:
    p.write_text(body, encoding="utf-8")


def test_validator_soft_pass_when_artifact_present(tmp_path: Path):
    import plamen_validators as V
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    _write(
        sp / "chain_iteration2.md",
        "# Chain Iteration 2 Results\n\n"
        "- Pairs evaluated: 3\n- New chains identified: 1\n",
    )
    assert V._validate_chain_iter2(sp, "thorough") == []


def test_validator_soft_pass_in_non_thorough(tmp_path: Path):
    import plamen_validators as V
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    # Light/Core skip the phase. Validator must be a no-op even with no artifact.
    assert V._validate_chain_iter2(sp, "core") == []
    assert V._validate_chain_iter2(sp, "light") == []


def test_validator_never_halts_on_missing_artifact(tmp_path: Path):
    import plamen_validators as V
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    # No chain_iteration2.md at all. Must return [] + write sentinel.
    issues = V._validate_chain_iter2(sp, "thorough")
    assert issues == [], (
        f"Missing chain_iteration2.md should not halt; got: {issues}"
    )
    sentinel = sp / "chain_iter2.degraded"
    assert sentinel.exists(), (
        "Missing artifact must leave a degraded sentinel for observability."
    )


def test_validator_treats_near_empty_as_degraded(tmp_path: Path):
    """5-byte file isn't real output. Validator should still NOT halt but
    leave a sentinel so the next audit run can investigate."""
    import plamen_validators as V
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    _write(sp / "chain_iteration2.md", "tiny")
    assert V._validate_chain_iter2(sp, "thorough") == []
    assert (sp / "chain_iter2.degraded").exists()


# -------- Pre-spawn skip detector ----------------------------------------

def test_no_coverage_file_remains_unresolved(tmp_path: Path):
    """Missing coverage is debt, never authority to skip iteration 2."""
    from plamen_parsers import _chain_iter2_has_no_unexplored_pairs
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    assert _chain_iter2_has_no_unexplored_pairs(sp) is False


def test_markdown_all_explored_cannot_authorize_skip(tmp_path: Path):
    """Producer Markdown cannot self-certify complete pair coverage."""
    from plamen_parsers import _chain_iter2_has_no_unexplored_pairs
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    _write(
        sp / "composition_coverage.md",
        "# Composition Coverage\n\n"
        "| Finding A | Finding B | Explored? | Result | Notes |\n"
        "|-----------|-----------|-----------|--------|-------|\n"
        "| H-01 (High) | M-05 (Medium) | YES | chain CH-1 | — |\n"
        "| H-02 (High) | M-07 (Medium) | YES | no match | — |\n",
    )
    assert _chain_iter2_has_no_unexplored_pairs(sp) is False


def test_unexplored_medium_plus_triggers_spawn(tmp_path: Path):
    """One unexplored cross-class Medium+ row → iteration 2 should
    spawn. (Helper returns False here meaning "do NOT skip".)"""
    from plamen_parsers import _chain_iter2_has_no_unexplored_pairs
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    _write(
        sp / "composition_coverage.md",
        "# Composition Coverage\n\n"
        "| Finding A | Finding B | Explored? | Result | Notes |\n"
        "|-----------|-----------|-----------|--------|-------|\n"
        "| H-01 (High) | M-05 (Medium) | NO | — | unexplored cross-class |\n",
    )
    assert _chain_iter2_has_no_unexplored_pairs(sp) is False


def test_untyped_low_severity_rows_cannot_authorize_skip(tmp_path: Path):
    """Severity does not convert Markdown into chain-tail authority."""
    from plamen_parsers import _chain_iter2_has_no_unexplored_pairs
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    _write(
        sp / "composition_coverage.md",
        "# Composition Coverage\n\n"
        "| Finding A | Finding B | Explored? | Result | Notes |\n"
        "|-----------|-----------|-----------|--------|-------|\n"
        "| L-01 (Low) | I-02 (Info) | NO | — | unexplored low-only |\n",
    )
    assert _chain_iter2_has_no_unexplored_pairs(sp) is False
