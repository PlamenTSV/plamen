"""Wiring + soft-validation tests for Phase 4b.6 (exploration completeness).

The exploration_skeptic phase is an independent, recall-positive /
ADDITIVE exploration-completeness verifier. It runs Thorough-only, after
the depth loop and its post-depth sub-phases (attention_repair, rag_sweep)
and before dedup/chain, so any added/upgraded/re-opened finding propagates
through the rest of the pipeline.

These tests lock in:

  1. The prompt mapping in `_STANDALONE_PROMPT_MAP` resolving via
     `_resolve_standalone_prompt`, with the prompt file present on disk.
  2. The Phase entry in `SC_PHASES`, Thorough-only + soft (critical=False).
  3. Placement: AFTER rag_sweep, BEFORE sc_semantic_dedup.
  4. Mode gating: absent in light/core scheduling, present in thorough.
  5. The soft validator never returns hard issues in any branch.

No protocol-specific content appears in these assertions.
"""
from __future__ import annotations

import sys
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS_DIR))


# -------- Wiring ----------------------------------------------------------

def test_exploration_skeptic_resolves_to_prompt_file():
    import plamen_prompt as P
    assert "exploration_skeptic" in P._STANDALONE_PROMPT_MAP
    assert (
        P._STANDALONE_PROMPT_MAP["exploration_skeptic"]
        == "phase4b6-exploration-skeptic.md"
    )
    # Resolve via the module-internal resolver (not imported by name, to
    # avoid the structural-integrity external-import gate).
    resolved = P._resolve_standalone_prompt("exploration_skeptic")
    assert resolved is not None, (
        "exploration_skeptic must resolve to a real prompt file on disk."
    )
    assert resolved.name == "phase4b6-exploration-skeptic.md"
    assert resolved.exists()


def test_exploration_skeptic_phase_entry_in_sc_phases():
    from plamen_types import SC_PHASES
    p = next((p for p in SC_PHASES if p.name == "exploration_skeptic"), None)
    assert p is not None, "exploration_skeptic phase missing from SC_PHASES"
    assert p.modes == {"thorough"}, (
        f"exploration_skeptic mode set should be {{thorough}}, got {p.modes!r}."
    )
    assert p.critical is False, (
        "exploration_skeptic.critical MUST be False — recall-positive soft phase."
    )
    assert p.model == "sonnet", (
        "exploration_skeptic must stay sonnet (not in the Thorough opus "
        "promotion set)."
    )
    assert p.expected_artifacts == ["exploration_skeptic_findings.md"]


def test_exploration_skeptic_precedes_freeze_and_precedent_context():
    from plamen_types import SC_PHASES
    names = [p.name for p in SC_PHASES]
    for required in ("rag_sweep", "exploration_skeptic", "sc_semantic_dedup"):
        assert required in names, f"{required} missing from SC_PHASES"
    i_rag = names.index("rag_sweep")
    i_es = names.index("exploration_skeptic")
    i_dedup = names.index("sc_semantic_dedup")
    assert i_es < i_dedup < i_rag, (
        f"exploration_skeptic must run before semantic freeze; post-freeze "
        f"precedent is context-only (positions rag={i_rag}, es={i_es}, "
        f"dedup={i_dedup})."
    )


def test_exploration_skeptic_NOT_in_l1_phases():
    """SC-only feature per task scope — L1 must not include it."""
    from plamen_types import L1_PHASES
    for p in L1_PHASES:
        assert p.name != "exploration_skeptic", (
            "L1 must not include exploration_skeptic (SC-only feature)."
        )


def test_exploration_skeptic_thorough_only_scheduling():
    from plamen_types import SC_PHASES
    light = {p.name for p in SC_PHASES if "light" in p.modes}
    core = {p.name for p in SC_PHASES if "core" in p.modes}
    thorough = {p.name for p in SC_PHASES if "thorough" in p.modes}
    assert "exploration_skeptic" not in light
    assert "exploration_skeptic" not in core
    assert "exploration_skeptic" in thorough


def test_exploration_skeptic_in_validators_all():
    import plamen_validators as V
    assert "_validate_exploration_skeptic" in V.__all__


# -------- Soft validator --------------------------------------------------

def _write(p: Path, body: str) -> None:
    p.write_text(body, encoding="utf-8")


def test_validator_soft_pass_when_artifact_present(tmp_path: Path):
    import plamen_validators as V
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    _write(
        sp / "exploration_skeptic_findings.md",
        "# Exploration Completeness Findings\n\n"
        "## Coverage Record\n\n"
        "| Finding | Axis 1 | Axis 2 | Axis 3 |\n"
        "|---------|--------|--------|--------|\n"
        "| 1 | ASSESSED | NO-GAP | GAP-FILLED |\n",
    )
    assert V._validate_exploration_skeptic(sp, "thorough") == []


def test_validator_soft_pass_in_non_thorough(tmp_path: Path):
    import plamen_validators as V
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    assert V._validate_exploration_skeptic(sp, "core") == []
    assert V._validate_exploration_skeptic(sp, "light") == []


def test_validator_never_halts_on_missing_artifact(tmp_path: Path):
    import plamen_validators as V
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    issues = V._validate_exploration_skeptic(sp, "thorough")
    assert issues == [], (
        f"Missing artifact must not halt an additive phase; got: {issues}"
    )
    assert (sp / "exploration_skeptic.degraded").exists(), (
        "Missing artifact must leave a degraded sentinel for observability."
    )


def test_validator_treats_near_empty_as_degraded(tmp_path: Path):
    import plamen_validators as V
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    _write(sp / "exploration_skeptic_findings.md", "tiny")
    assert V._validate_exploration_skeptic(sp, "thorough") == []
    assert (sp / "exploration_skeptic.degraded").exists()


# -------- Instance-level rubber-stamp gate (root fix for an observed FP) -------
#
# LIVE FLAW: the phase judged completeness at the AXIS level — "was the
# area/direction touched somewhere?" — and wrote blanket NO-GAP rows like
# "direction flip explored" / "boundary shift explored" that cleared an axis
# whose SPECIFIC instance mechanism was never resolved to a finding. The root
# fix requires per-INSTANCE enumeration with a NAMED instance + concrete
# evidence locus for every clearing disposition. The soft validator flags a
# clearing row (NO-GAP / ASSESSED) lacking that as recall-positive (re-surface
# as an ADD) — WARNING-only, never halting, never dropping a finding.
#
# Generic-only: no protocol/contract/function/token literals.


def _coverage_doc(rows: str) -> str:
    return (
        "# Exploration Completeness Findings\n\n"
        "## Coverage Record\n\n"
        "| Finding | Axis | Instance | Disposition | Evidence |\n"
        "|---------|------|----------|-------------|----------|\n"
        + rows
    )


def test_instance_gap_flags_axis_level_rubberstamp(tmp_path: Path):
    """REPRODUCES THE FP NOW RESOLVED: a clearing row that asserts the axis
    was 'explored' without naming the specific instance + a concrete locus is
    surfaced to the instance_gap sentinel (recall-positive). Still never halts.
    """
    import plamen_validators as V
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    # Two rubber-stamps mirroring the live flaw: a direction-flip NO-GAP with
    # only "explored" wording, and a NO-GAP with an unnamed instance cell.
    rows = (
        "| B1-1 | Direction | inverse direction | NO-GAP | direction flip explored |\n"
        "| B1-1 | Direction | - | NO-GAP | boundary shift explored |\n"
    )
    _write(sp / "exploration_skeptic_findings.md", _coverage_doc(rows))
    issues = V._validate_exploration_skeptic(sp, "thorough")
    # WARNING-only: never halts.
    assert issues == [], f"instance-gap gate must be WARNING-only; got {issues}"
    gap = sp / "exploration_skeptic.instance_gap"
    assert gap.exists(), "rubber-stamp clearing rows must surface to the sentinel"
    body = gap.read_text(encoding="utf-8")
    # Both rows flagged; observability text present.
    assert body.count("- finding=") == 2
    assert "EXPLORATION_SKEPTIC_INSTANCE_GAP" in body
    assert "re-surfaced as an ADD" in body


def test_instance_gap_negative_control_real_evidence_not_flagged(tmp_path: Path):
    """NEGATIVE CONTROL: a properly-explored instance with a NAMED instance +
    concrete evidence locus (file:line, function, or prior finding ID) must
    still be allowed an evidence-bearing NO-GAP / ASSESSED without false ADD
    spam — the fix must not become a rubber-stamp in the other direction.

    Also asserts the gate does NOT suppress a genuine ADD: a GAP-FILLED row is
    additive and is never written to the instance_gap sentinel.
    """
    import plamen_validators as V
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    rows = (
        # NO-GAP with a concrete file:line locus -> resolved, not flagged.
        "| B2-1 | Neighbour | sibling close path | NO-GAP | Vault.sol:L210 reverts on empty |\n"
        # ASSESSED captured by a prior finding ID -> resolved, not flagged.
        "| B2-1 | Similar-Mechanism | second occurrence | ASSESSED | already captured by RS3-2 |\n"
        # NO-GAP citing a concrete function locus -> resolved, not flagged.
        "| B2-2 | Direction | decrease direction | NO-GAP | bounded in setLimit() check |\n"
        # A genuine gap, emitted as ADD -> additive, must not be flagged.
        "| B2-2 | Direction | increase direction | GAP-FILLED | new finding ES-1 |\n"
    )
    _write(sp / "exploration_skeptic_findings.md", _coverage_doc(rows))
    issues = V._validate_exploration_skeptic(sp, "thorough")
    assert issues == []
    gap = sp / "exploration_skeptic.instance_gap"
    assert not gap.exists(), (
        "evidence-bearing NO-GAP/ASSESSED and additive GAP-FILLED rows must NOT "
        "be flagged — the fix must not become an over-eager rubber-stamp that "
        "spams false ADDs"
    )


def test_instance_gap_unnamed_instance_with_locus_still_flagged(tmp_path: Path):
    """A clearing row must name the SPECIFIC instance even if it carries a
    locus — an unnamed instance is the axis-level collapse the fix forbids.
    Recall-positive: surface it rather than trust a blank instance cell.
    """
    import plamen_validators as V
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    rows = "| B3-1 | Neighbour |  | NO-GAP | Foo.sol:L10 |\n"
    _write(sp / "exploration_skeptic_findings.md", _coverage_doc(rows))
    assert V._validate_exploration_skeptic(sp, "thorough") == []
    assert (sp / "exploration_skeptic.instance_gap").exists()


def test_instance_gap_positional_table_without_header(tmp_path: Path):
    """Coverage record parsed positionally when the header row is absent —
    the gate must still catch a rubber-stamp under the canonical column order.
    """
    import plamen_validators as V
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    body = (
        "# Exploration Completeness Findings\n\n"
        "| B4-1 | Direction | inverse | NO-GAP | explored |\n"
    )
    _write(sp / "exploration_skeptic_findings.md", body)
    assert V._validate_exploration_skeptic(sp, "thorough") == []
    assert (sp / "exploration_skeptic.instance_gap").exists()
