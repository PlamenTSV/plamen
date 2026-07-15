"""Fixtures for the R10 demotion-side gate (external-best-case un-demotion veto).

Mirror of the assert-side EXTERNAL-ASSUMPTION-CAP brake
(`_external_assumption_cap_applies`). A finding that is CONFIRMED/PARTIAL
in-scope AT DEPTH but DEMOTED (verdict CONTESTED / harm dismissed) by the
verifier PURELY on an UNCITED best-case external assumption must not silently
lose its disposition. The gate:
  1. writes a row to `external_assumption_undemotions.md`
     (Finding ID | Depth Verdict | Verifier Sev | Restored Floor | Basis),
  2. STAMPS [EXTERNAL-ASSUMPTION] + [UNPROVEN-EXTERNAL] into the verify file
     (idempotent), routing the finding through the existing consume block that
     keeps it IN BODY at proven severity, flagged for human review,
  3. FLOORS the report severity to the depth-claimed (queue) severity via
     `_expected_report_index_severities` and `continue`s past the proven-only
     Low-cap.

Precision guards (each a standalone no-fire):
  * G1 EXT-CITED grounding present + matching surface -> no fire
  * G2 in-scope-grounded demotion (no external tag/cue) -> no fire
  * G3 in-scope PoC executed (Attempted:YES, PASS or FAIL) -> no fire
  * G4 depth REFUTED -> no fire
  * proof-grade evidence -> no fire

All fixtures are synthetic/generic (no protocol/token/contract/function names).

Run: pytest scripts/test_r10_demotion_gate.py -v
"""
from __future__ import annotations

import importlib
import json
import os
import sys
from pathlib import Path

import pytest


def _v():
    sys.path.insert(0, os.path.join(os.path.dirname(__file__)))
    if "plamen_validators" in sys.modules:
        del sys.modules["plamen_validators"]
    return importlib.import_module("plamen_validators")


def _scratch(tmp_path: Path) -> Path:
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    (sp / "config.json").write_text(json.dumps({}), encoding="utf-8")
    return sp


def _queue(sp: Path, rows: list[tuple[str, str, str]]) -> None:
    """rows: (finding_id, severity, poc_class)."""
    out = [
        "| Queue # | Finding ID | Severity | Title | PoC Class |",
        "|---------|------------|----------|-------|-----------|",
    ]
    for i, (fid, sev, pc) in enumerate(rows, start=1):
        out.append(f"| {i} | {fid} | {sev} | example finding | {pc} |")
    (sp / "verification_queue.md").write_text("\n".join(out) + "\n", encoding="utf-8")


def _inventory(
    sp: Path,
    fid: str,
    *,
    verdict: str,
    severity: str = "Low",
    ext_tag: bool = True,
) -> None:
    """Write a findings_inventory.md fixture with one finding block."""
    desc = "The consumer prices off a returned external figure without a "
    if ext_tag:
        desc += (
            "balance-delta check. "
            "[EXTERNAL-ASSUMPTION: external pool rate is not a guaranteed "
            "time-invariant] "
            "NEEDS_DEPENDENCY_RESEARCH: external-pool: is the rate monotone?"
        )
    else:
        desc += (
            "registry policy check. Harm is conditional on the in-scope "
            "registry configuration only."
        )
    text = (
        f"### Finding [{fid}] Example finding title\n\n"
        f"**Severity**: {severity}\n\n"
        f"**Verdict**: {verdict}\n\n"
        f"**Location**: `src/lib.rs:L42`\n\n"
        f"**Description**: {desc}\n\n"
    )
    (sp / "findings_inventory.md").write_text(text, encoding="utf-8")


def _verify(
    sp: Path,
    fid: str,
    *,
    verdict: str = "CONTESTED",
    severity: str = "Low",
    tag: str = "[CODE-TRACE]",
    attempted: str = "NO",
    skip: str = "STRUCTURAL_NO_EXECUTABLE_HARM_ASSERTION",
    result: str = "NOT_EXECUTED",
    external_cue: bool = True,
    stability_cue: bool = False,
    ext_cited: bool = False,
    unproven_stamp: bool = False,
    location: str = "src/lib.rs:L42",
) -> None:
    """Write a verify_{fid}.md fixture."""
    lines = [
        f"**Severity**: {severity}\n\n",
        f"**Verdict**: {verdict}\n\n",
        f"**Location**: `{location}`\n\n",
        f"**Evidence Tag**: {tag}\n\n",
    ]
    if stability_cue:
        # H-22-shape: no [EXTERNAL-ASSUMPTION] tag, no return-trust vocabulary;
        # the demotion rests purely on an assumed within-window stability.
        lines.append(
            "Verdict CONTESTED: a real code inconsistency between the cached and "
            "the fresh read, but no harm demonstrated because the value is "
            "time-invariant within a ledger timestamp, so this is defensive.\n\n"
        )
    elif external_cue:
        lines.append(
            "The harm is priced off the cached returned value; it is safe only "
            "as long as the external pool rate is time-invariant. This is a "
            "worst-case external dependency assumption (R10). "
            "[EXTERNAL-ASSUMPTION: external best-case rate stability]\n\n"
        )
    else:
        lines.append(
            "The harm is conditional on the registry policy, an in-scope config "
            "value bounded by the admin setter. No external dependency involved.\n\n"
        )
    if ext_cited:
        lines.append(
            "[EXT-CITED: external-pool, source=https://docs.example/spec, "
            "fetched=2026-07-15]\n\n"
        )
    if unproven_stamp:
        lines.append("[UNPROVEN-EXTERNAL]\n\n")
    lines.append(
        "### PoC Attempt\n"
        "- PoC Required: YES\n"
        f"- Attempted: {attempted}\n"
        f"- PoC Not Attempted Because: {skip}\n\n"
        "### Execution Result\n"
        f"- Result: {result}\n"
    )
    (sp / f"verify_{fid}.md").write_text("".join(lines), encoding="utf-8")


def _research_stub(sp: Path) -> None:
    """Header-only external_dependency_research.md (0 data rows)."""
    (sp / "external_dependency_research.md").write_text(
        "# External Dependency Research\n\n"
        "| Dependency | Integration Surface |\n"
        "|------------|---------------------|\n",
        encoding="utf-8",
    )


def _research_with_surface(sp: Path, dep: str, surface: str) -> None:
    (sp / "external_dependency_research.md").write_text(
        "# External Dependency Research\n\n"
        "| Dependency | Integration Surface |\n"
        "|------------|---------------------|\n"
        f"| {dep} | {surface} |\n",
        encoding="utf-8",
    )


# ===========================================================================
# F1 — FIRES: confirmed + external-best-case-demoted + stub research ledger
# ===========================================================================

def test_f1_fires(tmp_path):
    V = _v()
    sp = _scratch(tmp_path)
    _queue(sp, [("INV-900", "Low", "unit")])
    _inventory(sp, "INV-900", verdict="CONFIRMED", severity="Low", ext_tag=True)
    _verify(sp, "INV-900", verdict="CONTESTED", severity="Low")
    _research_stub(sp)

    fired = V._apply_external_assumption_undemotions(sp, "core")
    ids = {f["finding_id"] for f in fired}
    assert "INV-900" in ids, f"expected INV-900 to fire, got {fired}"

    ledger = sp / "external_assumption_undemotions.md"
    assert ledger.exists()
    ltxt = ledger.read_text(encoding="utf-8")
    assert "INV-900" in ltxt
    # Restored floor == claimed (Low on this class)
    rec = next(f for f in fired if f["finding_id"] == "INV-900")
    assert rec["restored_floor"] == "Low"

    # verify file now stamped [UNPROVEN-EXTERNAL]
    vtxt = (sp / "verify_INV-900.md").read_text(encoding="utf-8")
    assert "[UNPROVEN-EXTERNAL]" in vtxt

    # expected severity map: key present, floored-to-claimed (Low), NOT dropped
    sev = V._expected_report_index_severities(sp)
    assert "INV-900" in sev
    assert sev["INV-900"] == "Low"

    # ledger reader round-trips
    loaded = V._load_external_assumption_undemotions(sp)
    assert loaded.get("INV-900") == "Low"


# ===========================================================================
# F1b — FIRES via stability cue (H-22 shape: no tag, no return-trust cue,
#       demotion rests purely on assumed within-window time-invariance)
# ===========================================================================

def test_f1b_stability_cue_fires(tmp_path):
    V = _v()
    sp = _scratch(tmp_path)
    _queue(sp, [("INV-901", "Low", "unit")])
    # inventory: CONFIRMED, but NO [EXTERNAL-ASSUMPTION] tag in the block
    _inventory(sp, "INV-901", verdict="CONFIRMED", severity="Low", ext_tag=False)
    # verify: CONTESTED, stability-only cue, no tag, no return-trust, no EXT-CITED
    _verify(
        sp, "INV-901", verdict="CONTESTED", severity="Low",
        external_cue=False, stability_cue=True,
    )
    _research_stub(sp)

    fired = V._apply_external_assumption_undemotions(sp, "core")
    assert "INV-901" in {f["finding_id"] for f in fired}
    vtxt = (sp / "verify_INV-901.md").read_text(encoding="utf-8")
    assert "[UNPROVEN-EXTERNAL]" in vtxt
    sev = V._expected_report_index_severities(sp)
    assert sev.get("INV-901") == "Low"


# ===========================================================================
# F2 — NO FIRE: EXT-CITED exists + matching surface (G1)
# ===========================================================================

def test_f2_ext_cited_no_fire(tmp_path):
    V = _v()
    sp = _scratch(tmp_path)
    _queue(sp, [("INV-900", "Low", "unit")])
    _inventory(sp, "INV-900", verdict="CONFIRMED", severity="Low", ext_tag=True)
    _verify(
        sp, "INV-900", verdict="CONTESTED", severity="Low",
        ext_cited=True, location="src/lib.rs:L10",
    )
    _research_with_surface(sp, "external-pool", "src/lib.rs:L10")

    fired = V._apply_external_assumption_undemotions(sp, "core")
    assert {f["finding_id"] for f in fired} == set() or "INV-900" not in {
        f["finding_id"] for f in fired
    }
    assert not (sp / "external_assumption_undemotions.md").exists()
    vtxt = (sp / "verify_INV-900.md").read_text(encoding="utf-8")
    assert "[UNPROVEN-EXTERNAL]" not in vtxt


# ===========================================================================
# F3 — NO FIRE: in-scope-grounded demotion (no external tag/cue) (G2)
# ===========================================================================

def test_f3_in_scope_grounded_no_fire(tmp_path):
    V = _v()
    sp = _scratch(tmp_path)
    _queue(sp, [("INV-900", "Low", "unit")])
    _inventory(sp, "INV-900", verdict="CONFIRMED", severity="Low", ext_tag=False)
    _verify(
        sp, "INV-900", verdict="CONTESTED", severity="Low", external_cue=False,
    )
    _research_stub(sp)

    fired = V._apply_external_assumption_undemotions(sp, "core")
    assert "INV-900" not in {f["finding_id"] for f in fired}
    assert not (sp / "external_assumption_undemotions.md").exists()


# ===========================================================================
# F4a — NO FIRE: depth REFUTED (G4)
# ===========================================================================

def test_f4a_depth_refuted_no_fire(tmp_path):
    V = _v()
    sp = _scratch(tmp_path)
    _queue(sp, [("INV-900", "Low", "unit")])
    _inventory(sp, "INV-900", verdict="REFUTED", severity="Low", ext_tag=True)
    _verify(sp, "INV-900", verdict="CONTESTED", severity="Low")
    _research_stub(sp)

    fired = V._apply_external_assumption_undemotions(sp, "core")
    assert "INV-900" not in {f["finding_id"] for f in fired}
    assert not (sp / "external_assumption_undemotions.md").exists()


# ===========================================================================
# F4b — NO FIRE: in-scope PoC executed (Attempted:YES), FAIL and PASS (G3)
# ===========================================================================

def test_f4b_attempted_fail_no_fire(tmp_path):
    """H-5 shape: Attempted:YES + FAIL (safe behavior confirmed)."""
    V = _v()
    sp = _scratch(tmp_path)
    _queue(sp, [("INV-900", "Low", "unit")])
    _inventory(sp, "INV-900", verdict="CONFIRMED", severity="Low", ext_tag=True)
    _verify(
        sp, "INV-900", verdict="CONTESTED", severity="Low",
        attempted="YES", skip="N/A", result="FAIL (safe behavior confirmed)",
    )
    _research_stub(sp)

    fired = V._apply_external_assumption_undemotions(sp, "core")
    assert "INV-900" not in {f["finding_id"] for f in fired}
    assert not (sp / "external_assumption_undemotions.md").exists()


def test_f4b_attempted_pass_no_fire(tmp_path):
    """H-14 shape: Attempted:YES + PASS."""
    V = _v()
    sp = _scratch(tmp_path)
    _queue(sp, [("INV-900", "Low", "unit")])
    _inventory(sp, "INV-900", verdict="CONFIRMED", severity="Low", ext_tag=True)
    _verify(
        sp, "INV-900", verdict="CONTESTED", severity="Low",
        attempted="YES", skip="N/A", result="PASS",
    )
    _research_stub(sp)

    fired = V._apply_external_assumption_undemotions(sp, "core")
    assert "INV-900" not in {f["finding_id"] for f in fired}
    assert not (sp / "external_assumption_undemotions.md").exists()


# ===========================================================================
# F5 — recall-safe no-op: absent inputs
# ===========================================================================

def test_f5_absent_inputs_noop(tmp_path):
    V = _v()
    sp = _scratch(tmp_path)  # no inventory, no queue, no research ledger
    fired = V._apply_external_assumption_undemotions(sp, "core")
    assert fired == []
    assert not (sp / "external_assumption_undemotions.md").exists()
    assert V._load_external_assumption_undemotions(sp) == {}


# ===========================================================================
# Light mode skip + idempotence
# ===========================================================================

def test_light_mode_skips(tmp_path):
    V = _v()
    sp = _scratch(tmp_path)
    _queue(sp, [("INV-900", "Low", "unit")])
    _inventory(sp, "INV-900", verdict="CONFIRMED", severity="Low", ext_tag=True)
    _verify(sp, "INV-900", verdict="CONTESTED", severity="Low")
    _research_stub(sp)
    fired = V._apply_external_assumption_undemotions(sp, "light")
    assert fired == []


def test_idempotent_double_run(tmp_path):
    """Second run on the same scratchpad: identical ledger, single stamp."""
    V = _v()
    sp = _scratch(tmp_path)
    _queue(sp, [("INV-900", "Low", "unit")])
    _inventory(sp, "INV-900", verdict="CONFIRMED", severity="Low", ext_tag=True)
    _verify(sp, "INV-900", verdict="CONTESTED", severity="Low")
    _research_stub(sp)

    V._apply_external_assumption_undemotions(sp, "core")
    ledger1 = (sp / "external_assumption_undemotions.md").read_text(encoding="utf-8")
    vtxt1 = (sp / "verify_INV-900.md").read_text(encoding="utf-8")

    V._apply_external_assumption_undemotions(sp, "core")
    ledger2 = (sp / "external_assumption_undemotions.md").read_text(encoding="utf-8")
    vtxt2 = (sp / "verify_INV-900.md").read_text(encoding="utf-8")

    assert ledger1 == ledger2
    # single stamp, not doubled
    assert vtxt1.upper().count("[UNPROVEN-EXTERNAL]") == 1
    assert vtxt2.upper().count("[UNPROVEN-EXTERNAL]") == 1


def test_load_external_assumption_undemotions_missing_file(tmp_path):
    V = _v()
    sp = _scratch(tmp_path)
    assert V._load_external_assumption_undemotions(sp) == {}


def _mapping(sp: Path, rows: list[tuple[str, str]]) -> None:
    """finding_mapping.md: rows of (inventory_id, hypothesis_id). Also seeds an
    empty hypotheses.md so the constituent parser's fallback is inert."""
    out = [
        "# Finding Mapping\n\n## INV Finding -> Hypothesis\n\n",
        "| Finding ID | Hypothesis ID | Mapping Status |\n",
        "|------------|---------------|----------------|\n",
    ]
    for inv, hyp in rows:
        out.append(f"| {inv} | {hyp} | PRIMARY |\n")
    (sp / "finding_mapping.md").write_text("".join(out), encoding="utf-8")
    (sp / "hypotheses.md").write_text("# Hypotheses\n", encoding="utf-8")


# ===========================================================================
# J1 — FIRES via hypothesis-id join: queue id H-NN, inventory INV-NNN, bridged
#      through finding_mapping.md; condition-1 resolves to CONFIRMED (not
#      inv-absent) so the depth anchor is genuinely active.
# ===========================================================================

def test_hypothesis_id_join_fires_with_depth_confirmed(tmp_path):
    V = _v()
    sp = _scratch(tmp_path)
    _queue(sp, [("H-90", "Low", "unit")])           # queue id is a hypothesis id
    _inventory(sp, "INV-910", verdict="CONFIRMED", severity="Low", ext_tag=True)
    _verify(sp, "H-90", verdict="CONTESTED", severity="Low")
    _mapping(sp, [("INV-910", "H-90")])             # H-90 -> INV-910
    _research_stub(sp)

    fired = V._apply_external_assumption_undemotions(sp, "thorough")
    rec = next((f for f in fired if f["finding_id"] == "H-90"), None)
    assert rec is not None, f"expected H-90 to fire via join, got {fired}"
    assert rec["depth_verdict"] == "CONFIRMED", "depth anchor must resolve via join"


# ===========================================================================
# J2 — NO FIRE via join: G4 now BITES — every constituent REFUTED at depth,
#      even though the verifier-side external cue is present.
# ===========================================================================

def test_hypothesis_id_join_g4_blocks_all_refuted(tmp_path):
    V = _v()
    sp = _scratch(tmp_path)
    _queue(sp, [("H-91", "Low", "unit")])
    _inventory(sp, "INV-911", verdict="REFUTED", severity="Low", ext_tag=True)
    _verify(sp, "H-91", verdict="CONTESTED", severity="Low")  # ext cue present
    _mapping(sp, [("INV-911", "H-91")])
    _research_stub(sp)

    fired = V._apply_external_assumption_undemotions(sp, "thorough")
    assert "H-91" not in {f["finding_id"] for f in fired}, "G4 must block all-REFUTED"
    assert not (sp / "external_assumption_undemotions.md").exists()


# ===========================================================================
# J3 — FIRES via join (split, recall-safe): mixed constituents, ANY CONFIRMED
#      => mechanism real in at least one split => fire.
# ===========================================================================

def test_hypothesis_id_join_any_confirmed_fires(tmp_path):
    V = _v()
    sp = _scratch(tmp_path)
    _queue(sp, [("H-92", "Low", "unit")])
    # two constituents of the same (split) hypothesis: one REFUTED, one CONFIRMED
    inv_a = (
        "### Finding [INV-920] a\n\n**Severity**: Low\n\n**Verdict**: REFUTED\n\n"
        "**Location**: `src/lib.rs:L1`\n\n**Description**: x "
        "[EXTERNAL-ASSUMPTION: rate stable] NEEDS_DEPENDENCY_RESEARCH: dep: ?\n\n"
    )
    inv_b = (
        "### Finding [INV-921] b\n\n**Severity**: Low\n\n**Verdict**: CONFIRMED\n\n"
        "**Location**: `src/lib.rs:L2`\n\n**Description**: y "
        "[EXTERNAL-ASSUMPTION: rate stable] NEEDS_DEPENDENCY_RESEARCH: dep: ?\n\n"
    )
    (sp / "findings_inventory.md").write_text(inv_a + inv_b, encoding="utf-8")
    _verify(sp, "H-92", verdict="CONTESTED", severity="Low")
    _mapping(sp, [("INV-920", "H-92"), ("INV-921", "H-92")])
    _research_stub(sp)

    fired = V._apply_external_assumption_undemotions(sp, "thorough")
    assert "H-92" in {f["finding_id"] for f in fired}, "any-confirmed split must fire"


def test_fires_clean_with_mechanical_loaded(tmp_path):
    """Regression lock: with `plamen_mechanical` also imported (the real driver
    state), the gate fires and writes ONLY its own artifacts — it must not call
    into a cross-module router with a mismatched schema, mutate the queue, or
    write a promotion ledger. Guards against re-introducing the removed broken
    `route_promotion_orphans` re-emit."""
    V = _v()
    sys.path.insert(0, os.path.join(os.path.dirname(__file__)))
    importlib.import_module("plamen_mechanical")  # present in sys.modules
    sp = _scratch(tmp_path)
    _queue(sp, [("INV-900", "Low", "unit")])
    _inventory(sp, "INV-900", verdict="CONFIRMED", severity="Low", ext_tag=True)
    _verify(sp, "INV-900", verdict="CONTESTED", severity="Low")
    _research_stub(sp)
    queue_before = (sp / "verification_queue.md").read_text(encoding="utf-8")

    fired = V._apply_external_assumption_undemotions(sp, "core")

    assert "INV-900" in {f["finding_id"] for f in fired}
    assert (sp / "external_assumption_undemotions.md").exists()
    # queue untouched (no re-emit side effect); no promotion-orphan ledger
    assert (sp / "verification_queue.md").read_text(encoding="utf-8") == queue_before
    assert not (sp / "promotion_orphans.md").exists()
