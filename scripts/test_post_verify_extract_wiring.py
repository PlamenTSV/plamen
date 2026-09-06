"""Wiring + soft-validation tests for Phase 5.5 (post-verify extraction).

Same V1→V2 wiring gap class. The phase is documented in
`commands/plamen.md:1224` (6-step recipe to extract `[VER-NEW-*]`
observations from verify_*.md and promote them into `hypotheses.md`).
No V2 driver phase consumed the directive.

Tests lock in the wiring, mode gating (Thorough only per user
direction), soft-only error semantics, and Phase 5.5's required
runtime position (after verify_aggregate, before skeptic — so promoted
findings can be skeptic-reviewed).
"""
from __future__ import annotations

import sys
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS_DIR))


def _write(p: Path, body: str) -> None:
    p.write_text(body, encoding="utf-8")


def test_standalone_prompt_mapped():
    from plamen_prompt import _STANDALONE_PROMPT_MAP, _STANDALONE_V2_DIR
    assert "post_verify_extract" in _STANDALONE_PROMPT_MAP
    p = _STANDALONE_V2_DIR / _STANDALONE_PROMPT_MAP["post_verify_extract"]
    assert p.exists(), f"Mapped prompt file missing: {p}"


def test_sc_phase_entry():
    from plamen_types import SC_PHASES
    p = next((p for p in SC_PHASES if p.name == "post_verify_extract"), None)
    assert p is not None, "post_verify_extract missing from SC_PHASES"
    assert p.modes == {"thorough"}
    assert p.critical is False
    assert p.model == "sonnet"


def test_l1_phase_entry():
    from plamen_types import L1_PHASES
    p = next((p for p in L1_PHASES if p.name == "post_verify_extract"), None)
    assert p is not None, "post_verify_extract missing from L1_PHASES"
    assert p.modes == {"thorough"}
    assert p.critical is False


def test_runs_after_verify_aggregate_before_skeptic():
    """Required position: after verify aggregation (so all verify_*.md
    files are settled) but before skeptic-judge (so promoted findings
    can be skeptic-reviewed at standard severity calibration). Lock
    this in — a future refactor that moves Phase 5.5 to after skeptic
    would silently lose skeptic coverage on promoted findings."""
    from plamen_types import SC_PHASES, L1_PHASES
    cases = [
        ("SC", SC_PHASES, "sc_verify_aggregate"),
        ("L1", L1_PHASES, "verify_aggregate"),
    ]
    for label, lst, aggregate in cases:
        names = [p.name for p in lst]
        i_agg = names.index(aggregate)
        i_pve = names.index("post_verify_extract")
        i_skp = names.index("skeptic")
        assert i_agg < i_pve < i_skp, (
            f"{label}: bad order {aggregate}={i_agg}, "
            f"post_verify_extract={i_pve}, skeptic={i_skp}"
        )


def test_validator_soft_pass_with_artifact(tmp_path: Path):
    import plamen_validators as V
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    _write(
        sp / "post_verify_extract.md",
        "# Post-Verification Extraction Summary\n\n"
        "- verify files scanned: 12\n- candidate observations: 0\n"
        "- promoted: 0\n",
    )
    assert V._validate_post_verify_extract(sp, "thorough") == []


def test_validator_soft_pass_non_thorough(tmp_path: Path):
    import plamen_validators as V
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    assert V._validate_post_verify_extract(sp, "core") == []
    assert V._validate_post_verify_extract(sp, "light") == []


def test_validator_never_halts_on_missing_artifact(tmp_path: Path):
    import plamen_validators as V
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    assert V._validate_post_verify_extract(sp, "thorough") == []
    assert (sp / "post_verify_extract.degraded").exists()


def test_prompt_instructs_dedup_and_independent_reverification():
    """Two contracts in the prompt body that affect downstream report
    integrity: (1) dedupe against existing inventory + hypotheses, (2)
    re-queue through an independent verifier without self-verdict. Both can
    a future edit. Lock them in."""
    from plamen_prompt import _STANDALONE_PROMPT_MAP, _STANDALONE_V2_DIR
    text = (_STANDALONE_V2_DIR / _STANDALONE_PROMPT_MAP["post_verify_extract"]).read_text(
        encoding="utf-8",
    )
    assert "Dedupe" in text or "dedup" in text or "dedupe" in text.lower(), (
        "Prompt must instruct dedup against existing inventory/hypotheses"
    )
    lowered = text.lower()
    assert "independently re-queued" in lowered
    assert "do not self-verify" in lowered
    assert "terminal verdict" in lowered
