"""Wiring + haltless-fallback tests for Phase 4b.7 (enumeration-obligation
exploration).

The recall fix re-routes the mechanical enumeration-gate OBLIGATIONS away from
the verify precision-filter (which dismisses raw hints) and INTO a targeted
depth EXPLORATION pass that TRACES each obligation to a real finding or a
reasoned clear, BEFORE verify. These tests lock in:

  1. The phase is on the REAL execution route for BOTH SC and L1 — present in
     the phase list, resolvable to a prompt, AND positioned AFTER depth (where
     the enumeration gate fires) and BEFORE the verify queue.
  2. The phase is soft (never halts) and additive.
  3. The driver dispatches the skip pre-check, the soft validator, and the
     inventory promotion (so the explored finding flows inventory->...->verify).
  4. HALTLESS fallback: with no obligations the phase is skipped (degrades to
     the prior candidate->verify behavior); with no exploration artifact the
     promotion is a no-op; neither raises.
  5. RECALL-SAFE: a real explored finding is promoted into findings_inventory.md
     so it reaches the verify queue.

No protocol-specific content appears in these assertions.
"""
from __future__ import annotations

import sys
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS_DIR))


# -------- Wiring / real-route -------------------------------------------------

def test_resolves_to_prompt_file():
    import plamen_prompt as P
    assert P._STANDALONE_PROMPT_MAP.get("enumgap_exploration") == \
        "phase4b7-enumgap-exploration.md"
    resolved = P._resolve_standalone_prompt("enumgap_exploration")
    assert resolved is not None and resolved.exists()
    assert resolved.name == "phase4b7-enumgap-exploration.md"


def test_phase_entry_present_both_pipelines_soft():
    from plamen_types import SC_PHASES, L1_PHASES
    for label, phases in (("SC", SC_PHASES), ("L1", L1_PHASES)):
        p = next((x for x in phases if x.name == "enumgap_exploration"), None)
        assert p is not None, f"{label} missing enumgap_exploration phase"
        assert p.critical is False, f"{label} enumgap_exploration must be soft"
        assert p.model == "sonnet"
        assert p.expected_artifacts == ["enumgap_exploration_findings.md"]
        assert "thorough" in p.modes and "core" in p.modes


def test_runs_before_verify_after_depth_sc():
    from plamen_types import SC_PHASES
    names = [p.name for p in SC_PHASES]
    i_depth = names.index("depth")
    i_es = names.index("enumgap_exploration")
    i_dedup = names.index("sc_semantic_dedup")
    i_verify = names.index("sc_verify_queue")
    assert i_depth < i_es < i_dedup < i_verify, (
        f"SC order broken: depth={i_depth} enumgap={i_es} "
        f"dedup={i_dedup} verify={i_verify}"
    )


def test_runs_before_verify_after_depth_l1():
    from plamen_types import L1_PHASES
    names = [p.name for p in L1_PHASES]
    i_depth = names.index("depth")
    i_es = names.index("enumgap_exploration")
    i_verify = names.index("verify_queue")
    assert i_depth < i_es < i_verify, (
        f"L1 order broken: depth={i_depth} enumgap={i_es} verify={i_verify}"
    )


def test_driver_dispatches_skip_validator_and_promotion():
    src = (SCRIPTS_DIR / "plamen_driver.py").read_text(encoding="utf-8")
    # skip pre-check
    assert "_enumgap_exploration_has_no_obligations(scratchpad)" in src
    # soft validator dispatch
    assert "_validate_enumgap_exploration(scratchpad" in src
    # inventory promotion (the seam that makes the explored finding reach verify)
    assert "_promote_enumgap_exploration_transaction(" in src


def test_validator_in_all_and_soft():
    import plamen_validators as V
    assert "_validate_enumgap_exploration" in V.__all__


# -------- Haltless fallback ---------------------------------------------------

def test_validator_never_halts_missing_artifact(tmp_path):
    import plamen_validators as V
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    assert V._validate_enumgap_exploration(sp, "thorough") == []
    assert (sp / "enumgap_exploration.degraded").exists()


def test_skip_signal_true_when_no_obligations(tmp_path):
    from plamen_parsers import _enumgap_exploration_has_no_obligations
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    # Nothing on disk -> no obligations -> skip (degrade to fallback).
    assert _enumgap_exploration_has_no_obligations(sp) is True


def test_skip_signal_false_when_obligations_present(tmp_path):
    import json
    from plamen_parsers import _enumgap_exploration_has_no_obligations
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    (sp / "_enumeration_obligations.json").write_text(
        json.dumps({"obligations": [{"finding_id": "INV-001",
                                      "function": "fnA", "symbol": "s",
                                      "required_corefs": ["fnB"]}]}),
        encoding="utf-8",
    )
    assert _enumgap_exploration_has_no_obligations(sp) is False


def test_promotion_noop_without_artifact(tmp_path):
    import enumeration_gate as eg
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    (sp / "findings_inventory.md").write_text("# Inv\n", encoding="utf-8")
    res = eg.promote_enumgap_exploration_to_inventory(sp)
    assert res == {"parsed": 0, "emitted": 0}


# -------- Recall-safe: explored finding flows into the inventory --------------

def test_promotion_appends_explored_finding_to_inventory(
    tmp_path, monkeypatch
):
    import enumeration_gate as eg
    # This unit fixture exercises only structural append rendering. Exact
    # MODEL->reconcile authority is covered by the integration/adversarial lane.
    monkeypatch.setattr(eg, "_promotion_phaseio_issues", lambda _root: [])
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    (sp / "findings_inventory.md").write_text(
        "# Findings Inventory\n\n"
        "### Finding [INV-001]: existing\n"
        "**Severity**: Medium\n**Location**: `a` :: `f`\n"
        "**Description**: x\n**Impact**: y\n",
        encoding="utf-8",
    )
    (sp / "enumgap_exploration_findings.md").write_text(
        "# Enumeration-Obligation Exploration\n\n"
        "### Finding [NEXP-1]: traced cross-function inconsistency\n"
        "**Severity**: Medium\n"
        "**Location**: `mod` :: `fnA` / `fnB`\n"
        "**Preferred Tag**: [CODE-TRACE]\n"
        "**Root Cause**: both write the shared total without sync\n"
        "**Description**: [TRACE:fnB->stale read] divergence over shared total\n"
        "**Impact**: accounting drift; users withdraw more than owed\n"
        "**Material Harm**: late withdrawers lose pro-rata share\n\n"
        "## Coverage Record\n\n"
        "| Obligation | Relationship | Disposition | Evidence |\n"
        "|---|---|---|---|\n"
        "| INV-001 | shared-symbol | FINDING | NEXP-1 |\n",
        encoding="utf-8",
    )
    res = eg.promote_enumgap_exploration_to_inventory(sp)
    assert res["emitted"] == 1
    inv = (sp / "findings_inventory.md").read_text(encoding="utf-8")
    assert "INV-002" in inv  # explored finding now an inventory entry
    assert "traced cross-function inconsistency" in inv
    assert "NEXP-1" in inv  # source id preserved for traceability
    # Idempotent: a second run promotes nothing more.
    res2 = eg.promote_enumgap_exploration_to_inventory(sp)
    assert res2["emitted"] == 0


def test_chain_summaries_includes_exploration_artifact():
    src = (SCRIPTS_DIR / "plamen_parsers.py").read_text(encoding="utf-8")
    # The artifact must be a chain-summary source so the explored finding's
    # Chain Summary reaches composition analysis.
    assert "enumgap_exploration_findings.md" in src
