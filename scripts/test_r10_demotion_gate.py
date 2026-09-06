"""Fixtures for the R10 demotion-side gate (external-best-case un-demotion veto).

Mirror of the assert-side EXTERNAL-ASSUMPTION-CAP brake
(`_external_assumption_cap_applies`). A finding that is CONFIRMED/PARTIAL
in-scope AT DEPTH but DEMOTED (verdict CONTESTED / harm dismissed) by the
verifier PURELY on an UNCITED best-case external assumption must not silently
lose its disposition. The gate:
  1. writes a source-bound canonical typed JSON sidecar and an optional
     non-authoritative Markdown compatibility view,
  2. leaves receipt-bound `verify_*.md` bytes unchanged,
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

import copy
import importlib
import hashlib
import json
import os
import re
import stat
import sys
import unicodedata
from pathlib import Path
from types import SimpleNamespace

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
        f"### Finding [{fid}]: Example finding title\n\n"
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
    verify_path = sp / "verify_INV-900.md"
    verify_before = verify_path.read_bytes()

    fired = V._apply_external_assumption_undemotions(sp, "core")
    ids = {f["finding_id"] for f in fired}
    assert "INV-900" in ids, f"expected INV-900 to fire, got {fired}"

    ledger = sp / "external_assumption_undemotions.md"
    sidecar = sp / "external_assumption_undemotions.json"
    assert ledger.exists() and sidecar.exists()
    ltxt = ledger.read_text(encoding="utf-8")
    assert "INV-900" in ltxt
    # Restored floor == claimed (Low on this class)
    rec = next(f for f in fired if f["finding_id"] == "INV-900")
    assert rec["restored_floor"] == "Low"

    # Receipt-bound verifier evidence is immutable. The authoritative marker
    # and source identity live only in the typed sidecar.
    assert verify_path.read_bytes() == verify_before
    assert b"[UNPROVEN-EXTERNAL]" not in verify_path.read_bytes()
    payload = json.loads(sidecar.read_text(encoding="utf-8"))
    assert payload["schema_version"] == "plamen.external_assumption_undemotions.v1"
    assert payload["row_count"] == 1
    typed = payload["rows"][0]
    assert typed["finding_id"] == "INV-900"
    assert typed["source_verify"]["relative_path"] == "verify_INV-900.md"
    assert typed["source_verify"]["byte_length"] == len(verify_before)
    import hashlib
    assert typed["source_verify"]["sha256"] == hashlib.sha256(verify_before).hexdigest()
    assert typed["successor_binding"]["state"] == "PRE_MECHANICAL_UNRECONCILED"

    # expected severity map: key present, floored-to-claimed (Low), NOT dropped
    sev = V._expected_report_index_severities(sp)
    assert "INV-900" in sev
    assert sev["INV-900"] == "Low"

    # ledger reader round-trips
    loaded = V._load_external_assumption_undemotions(sp)
    assert loaded == {}
    skeptic_row = next(
        row for row in V._skeptic_expected_findings(sp)
        if row["finding_id"] == "INV-900"
    )
    assert "UNRESOLVED_EXTERNAL_PREMISE" in skeptic_row["challenge_triggers"]


# ===========================================================================
# F1b — NO FIRE via stability cue alone (R10.1 defect 5): no mapped external
#       provenance means the language may describe an internal invariant.
# ===========================================================================

def test_f1b_stability_cue_without_external_provenance_no_fire(tmp_path):
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
    assert "INV-901" not in {f["finding_id"] for f in fired}
    vtxt = (sp / "verify_INV-901.md").read_text(encoding="utf-8")
    assert "[UNPROVEN-EXTERNAL]" not in vtxt
    assert not (sp / "external_assumption_undemotions.md").exists()


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
    """Second run: identical canonical artifacts and unchanged verifier bytes."""
    V = _v()
    sp = _scratch(tmp_path)
    _queue(sp, [("INV-900", "Low", "unit")])
    _inventory(sp, "INV-900", verdict="CONFIRMED", severity="Low", ext_tag=True)
    _verify(sp, "INV-900", verdict="CONTESTED", severity="Low")
    _research_stub(sp)

    verify_before = (sp / "verify_INV-900.md").read_bytes()
    V._apply_external_assumption_undemotions(sp, "core")
    ledger1 = (sp / "external_assumption_undemotions.md").read_text(encoding="utf-8")
    sidecar1 = (sp / "external_assumption_undemotions.json").read_bytes()
    compute1 = (sp / "external_assumption_undemotion_compute.json").read_bytes()
    vbytes1 = (sp / "verify_INV-900.md").read_bytes()

    V._apply_external_assumption_undemotions(sp, "core")
    ledger2 = (sp / "external_assumption_undemotions.md").read_text(encoding="utf-8")
    sidecar2 = (sp / "external_assumption_undemotions.json").read_bytes()
    compute2 = (sp / "external_assumption_undemotion_compute.json").read_bytes()
    vbytes2 = (sp / "verify_INV-900.md").read_bytes()

    assert ledger1 == ledger2
    assert sidecar1 == sidecar2
    assert compute1 == compute2
    assert vbytes1 == vbytes2 == verify_before


def _high_firing_fixture(tmp_path: Path):
    V = _v()
    sp = _scratch(tmp_path)
    _queue(sp, [("INV-950", "High", "unit")])
    _inventory(sp, "INV-950", verdict="CONFIRMED", severity="High", ext_tag=True)
    _verify(sp, "INV-950", verdict="CONTESTED", severity="Low")
    _research_stub(sp)
    assert V._apply_external_assumption_undemotions(sp, "core")
    return V, sp


@pytest.mark.parametrize("failure", ["corrupt", "missing", "digest", "source"])
def test_typed_sidecar_failure_degrades_loudly_without_recall_loss(tmp_path, failure):
    """Invalid state grants no severity authority, but remains visible as
    explicit non-authoritative human-review debt."""
    V, sp = _high_firing_fixture(tmp_path)
    sidecar = sp / "external_assumption_undemotions.json"
    verify_path = sp / "verify_INV-950.md"
    if failure == "corrupt":
        sidecar.write_bytes(b"{not-json\n")
    elif failure == "missing":
        sidecar.unlink()
    elif failure == "digest":
        payload = json.loads(sidecar.read_text(encoding="utf-8"))
        payload["receipt_digest"] = "0" * 64
        sidecar.write_text(json.dumps(payload), encoding="utf-8")
    else:
        verify_path.write_bytes(verify_path.read_bytes() + b"\nlate mutation\n")

    assert V._load_external_assumption_undemotions(sp) == {}
    # The invalid receipt cannot authorize a floor or bypass normal caps.
    assert V._expected_report_index_severities(sp)["INV-950"] == "Low"
    debt = json.loads(
        (sp / "external_assumption_undemotion_debt.json").read_text(encoding="utf-8")
    )
    assert debt["authority"] == "NONE_HUMAN_REVIEW_ONLY"
    assert debt["report_authoritative"] is False
    assert debt["issue_count"] >= 1
    assert debt["severity_authority"] == "NONE"
    assert debt["review_candidates"] == ["INV-950"]
    skeptic_row = next(
        row for row in V._skeptic_expected_findings(sp)
        if row["finding_id"] == "INV-950"
    )
    assert "UNRESOLVED_EXTERNAL_PREMISE" in skeptic_row["challenge_triggers"]
    assert "EVIDENCE_INTEGRITY_REVIEW" in skeptic_row["challenge_triggers"]


def test_recomputed_result_digest_cannot_change_restored_floor(tmp_path):
    """A receipt digest authenticates bytes, not the R10 decision. Replacing
    High with Critical and recomputing that digest must fail re-derivation."""
    V, sp = _high_firing_fixture(tmp_path)
    sidecar = sp / "external_assumption_undemotions.json"
    payload = json.loads(sidecar.read_text(encoding="utf-8"))
    payload["rows"][0]["restored_floor"] = "Critical"
    unsigned = {k: v for k, v in payload.items() if k != "receipt_digest"}
    payload["receipt_digest"] = hashlib.sha256(
        V._canonical_validator_json_bytes(unsigned)
    ).hexdigest()
    sidecar.write_bytes(V._canonical_validator_json_bytes(payload))

    assert V._load_external_assumption_undemotions(sp) == {}
    assert V._expected_report_index_severities(sp)["INV-950"] == "Low"
    debt = json.loads(
        (sp / "external_assumption_undemotion_debt.json").read_text("utf-8")
    )
    assert any(
        issue["code"] == "INPUT_AUTHORITY_INVALID"
        for issue in debt["issues"]
    )


def test_marker_only_state_is_visible_but_has_zero_severity_authority(tmp_path):
    """Compatibility Markdown is never a severity source, even when the queue
    proposed High and the ordinary proven-only projection is Low."""
    V = _v()
    sp = _scratch(tmp_path)
    (sp / "config.json").write_text(json.dumps({"proven_only": True}), "utf-8")
    _queue(sp, [("INV-951", "High", "unit")])
    _inventory(sp, "INV-951", verdict="CONFIRMED", severity="High", ext_tag=False)
    _verify(
        sp,
        "INV-951",
        verdict="CONTESTED",
        severity="Low",
        external_cue=False,
    )
    (sp / "external_assumption_undemotions.md").write_text(
        "# arbitrary compatibility marker\n\n| INV-951 | Critical |\n",
        encoding="utf-8",
    )

    assert V._load_external_assumption_undemotions(sp) == {}
    assert V._expected_report_index_severities(sp)["INV-951"] == "Low"
    debt = json.loads(
        (sp / "external_assumption_undemotion_debt.json").read_text("utf-8")
    )
    assert debt["authority"] == "NONE_HUMAN_REVIEW_ONLY"
    assert debt["severity_authority"] == "NONE"
    assert debt["review_candidates"] == ["INV-951"]


def test_clean_zero_compute_attestation_is_canonical_and_authority_free(tmp_path):
    V = _v()
    sp = _scratch(tmp_path)
    _queue(sp, [("INV-952", "High", "unit")])
    _inventory(sp, "INV-952", verdict="CONFIRMED", severity="High", ext_tag=False)
    _verify(
        sp,
        "INV-952",
        verdict="CONTESTED",
        severity="Low",
        external_cue=False,
    )
    _research_stub(sp)

    assert V._apply_external_assumption_undemotions(sp, "core") == []
    compute_path = sp / "external_assumption_undemotion_compute.json"
    compute = json.loads(compute_path.read_text("utf-8"))
    assert compute["outcome"] == "CLEAN_ZERO"
    assert compute["fired_count"] == 0
    assert compute["source_denominator"][0]["finding_id"] == "INV-952"
    projection = V._external_assumption_undemotion_projection(sp)
    assert projection["valid_floors"] == {}
    assert projection["debt_ids"] == {"INV-952"}
    assert projection["issues"]


def test_all_r10_artifacts_deleted_after_fire_becomes_typed_debt(tmp_path):
    V, sp = _high_firing_fixture(tmp_path)
    for name in (
        "external_assumption_undemotions.json",
        "external_assumption_undemotions.md",
        "external_assumption_undemotion_compute.json",
        "external_assumption_undemotion_debt.json",
    ):
        (sp / name).unlink(missing_ok=True)

    projection = V._external_assumption_undemotion_projection(sp)
    assert projection["valid_floors"] == {}
    assert projection["debt_ids"] == {"INV-950"}
    debt = json.loads(
        (sp / "external_assumption_undemotion_debt.json").read_text("utf-8")
    )
    assert any(i["code"] == "COMPUTE_RECEIPT_MISSING" for i in debt["issues"])
    assert V._expected_report_index_severities(sp)["INV-950"] == "Low"


def test_clean_zero_source_drift_invalidates_compute_attestation(tmp_path):
    V = _v()
    sp = _scratch(tmp_path)
    _queue(sp, [("INV-953", "High", "unit")])
    _inventory(sp, "INV-953", verdict="CONFIRMED", severity="High", ext_tag=False)
    _verify(
        sp,
        "INV-953",
        verdict="CONTESTED",
        severity="Low",
        external_cue=False,
    )
    _research_stub(sp)
    V._apply_external_assumption_undemotions(sp, "core")
    (sp / "verify_INV-953.md").write_text(
        (sp / "verify_INV-953.md").read_text("utf-8") + "\nlate source drift\n",
        encoding="utf-8",
    )

    projection = V._external_assumption_undemotion_projection(sp)
    assert projection["valid_floors"] == {}
    assert projection["debt_ids"] == {"INV-953"}
    assert any(
        i["code"] == "INPUT_AUTHORITY_INVALID"
        for i in projection["issues"]
    )


def test_typed_queue_drift_cannot_supply_r10_floor_authority(tmp_path):
    V = _v()
    sp = _scratch(tmp_path)
    V._write_queue_subset_manifest(
        sp / "verification_queue.md",
        [{
            "queue #": "1",
            "finding id": "INV-954",
            "severity": "High",
            "title": "example finding",
            "bug class": "state consistency",
            "preferred tag": "[CODE-TRACE]",
            "location": "src/lib.rs:L42",
            "primary artifact": "findings_inventory.md",
            "poc class": "unit",
        }],
    )
    _inventory(sp, "INV-954", verdict="CONFIRMED", severity="High", ext_tag=True)
    _verify(sp, "INV-954", verdict="CONTESTED", severity="Low")
    _research_stub(sp)
    assert V._apply_external_assumption_undemotions(sp, "core")

    queue_path = sp / "verification_queue.md"
    queue_path.write_text(
        queue_path.read_text("utf-8").replace("| High |", "| Critical |"),
        encoding="utf-8",
    )
    # A second compute observes typed/Markdown disagreement and cannot retain
    # the prior result as authority.
    assert V._apply_external_assumption_undemotions(sp, "core") == []
    projection = V._external_assumption_undemotion_projection(sp)
    assert projection["valid_floors"] == {}
    assert projection["debt_ids"] == {"INV-954"}
    assert any(i["code"] == "QUEUE_AUTHORITY_INVALID" for i in projection["issues"])


def test_typed_queue_with_raw_semantic_sources_has_zero_r10_authority(tmp_path):
    """A typed queue is not a provenance umbrella for the other R10 inputs."""
    V = _v()
    sp = _scratch(tmp_path)
    V._write_queue_subset_manifest(
        sp / "verification_queue.md",
        [{
            "queue #": "1",
            "finding id": "H-990",
            "severity": "High",
            "title": "example finding",
            "bug class": "state consistency",
            "preferred tag": "[CODE-TRACE]",
            "location": "src/lib.rs:L42",
            "primary artifact": "findings_inventory.md",
            "poc class": "unit",
        }],
    )
    _inventory(sp, "INV-990", verdict="CONFIRMED", severity="High")
    _mapping(sp, [("INV-990", "H-990")])
    _verify(sp, "H-990", verdict="CONTESTED", severity="Low")
    _research_stub(sp)

    assert V._apply_external_assumption_undemotions(sp, "core")
    projection = V._external_assumption_undemotion_projection(sp)
    assert projection["valid_floors"] == {}
    assert projection["debt_ids"] == {"H-990"}
    assert any(
        issue["code"] == "INPUT_AUTHORITY_INVALID"
        for issue in projection["issues"]
    )


def test_forged_research_cannot_authorize_clean_zero(tmp_path):
    """A matching raw research row cannot suppress an otherwise firing row."""
    V = _v()
    sp = _scratch(tmp_path)
    V._write_queue_subset_manifest(
        sp / "verification_queue.md",
        [{
            "queue #": "1",
            "finding id": "H-991",
            "severity": "High",
            "title": "example finding",
            "bug class": "state consistency",
            "preferred tag": "[CODE-TRACE]",
            "location": "src/lib.rs:L42",
            "primary artifact": "findings_inventory.md",
            "poc class": "unit",
        }],
    )
    _inventory(sp, "INV-991", verdict="CONFIRMED", severity="High")
    _mapping(sp, [("INV-991", "H-991")])
    _verify(
        sp,
        "H-991",
        verdict="CONTESTED",
        severity="Low",
        ext_cited=True,
        location="src/lib.rs:L42",
    )
    _research_with_surface(sp, "forged", "src/lib.rs:L42")

    assert V._apply_external_assumption_undemotions(sp, "core") == []
    projection = V._external_assumption_undemotion_projection(sp)
    assert projection["valid_floors"] == {}
    assert projection["debt_ids"] == {"H-991"}
    assert projection["issues"]


def test_light_mode_is_explicitly_disabled_without_spurious_compute_debt(tmp_path):
    V = _v()
    sp = _scratch(tmp_path)
    _queue(sp, [("INV-992", "High", "unit")])
    _inventory(sp, "INV-992", verdict="CONFIRMED", severity="High")
    _verify(sp, "INV-992", verdict="CONTESTED", severity="Low")

    assert V._apply_external_assumption_undemotions(sp, "light") == []
    projection = V._external_assumption_undemotion_projection(sp)
    assert projection["valid_floors"] == {}
    assert projection["debt_ids"] == set()
    assert projection["issues"]
    assert not (sp / "external_assumption_undemotion_debt.json").exists()


def _r10_driver_fixture(tmp_path: Path, *, backend: str = "claude"):
    V = _v()
    if "plamen_driver" in sys.modules:
        del sys.modules["plamen_driver"]
    D = importlib.import_module("plamen_driver")
    sp = _scratch(tmp_path)
    V._write_queue_subset_manifest(
        sp / "verification_queue.md",
        [{
            "queue #": "1",
            "finding id": "H-993",
            "severity": "High",
            "title": "example finding",
            "bug class": "state consistency",
            "preferred tag": "[CODE-TRACE]",
            "location": "src/lib.rs:L42",
            "primary artifact": "findings_inventory.md",
            "poc class": "structural",
        }],
    )
    _inventory(sp, "INV-993", verdict="CONFIRMED", severity="High")
    _mapping(sp, [("INV-993", "H-993")])
    _verify(
        sp,
        "H-993",
        verdict="CONTESTED",
        severity="Low",
        skip="EXTERNAL_DEPENDENCY_NO_FORK_OR_ADDRESS",
    )
    _research_stub(sp)
    config = {
        "_run_id": "run-r10-phaseio-test",
        "project_root": str(tmp_path),
        "pipeline": "sc",
        "mode": "core",
        "language": "evm",
        "cli_backend": backend,
    }
    phase = SimpleNamespace(name="sc_verify_aggregate", base_timeout_s=30)
    return V, D, sp, config, phase


def _fixture_metadata_state(metadata):
    return (
        int(metadata.st_mode),
        int(metadata.st_size),
        int(metadata.st_mtime_ns),
        int(getattr(metadata, "st_ctime_ns", 0) or 0),
        int(getattr(metadata, "st_dev", 0) or 0),
        int(getattr(metadata, "st_ino", 0) or 0),
        int(getattr(metadata, "st_nlink", 1) or 1),
        int(getattr(metadata, "st_file_attributes", 0) or 0),
    )


def _fixture_existing_spellings(candidate: Path, normalized: str):
    """Read the exact on-disk final-component spelling without following it."""

    if os.name == "nt":
        rooted_io = importlib.import_module("rooted_path_io")
        data = rooted_io._WIN32_FIND_DATAW()
        handle = rooted_io._FindFirstFileW(
            rooted_io.native_path(candidate),
            rooted_io.ctypes.byref(data),
        )
        if handle == rooted_io._INVALID_HANDLE_VALUE:
            return (
                "<UNREADABLE_DIRECTORY_ENTRY>",
                str(rooted_io.ctypes.get_last_error()),
            )
        try:
            observed = str(data.cFileName)
        finally:
            rooted_io._FindClose(handle)
        return (observed,)
    try:
        with os.scandir(candidate.parent) as entries:
            return tuple(sorted(
                entry.name
                for entry in entries
                if unicodedata.normalize("NFC", entry.name).casefold()
                == normalized.casefold()
            ))
    except OSError as exc:
        return (
            "<UNREADABLE_DIRECTORY>",
            type(exc).__name__,
            str(exc.errno),
        )


def _fixture_live_windows_path_spelling(candidate: Path):
    """Read every stored component spelling in one live Win32 path query."""

    function = getattr(
        _fixture_live_windows_path_spelling, "_get_long_path_name", None
    )
    if function is None:
        rooted_io = sys.modules.get("rooted_path_io")
        if rooted_io is None:
            rooted_io = importlib.import_module("rooted_path_io")
        function = rooted_io.ctypes.WinDLL(
            "kernel32", use_last_error=True
        ).GetLongPathNameW
        function.argtypes = (
            rooted_io.wintypes.LPCWSTR,
            rooted_io.wintypes.LPWSTR,
            rooted_io.wintypes.DWORD,
        )
        function.restype = rooted_io.wintypes.DWORD
        _fixture_live_windows_path_spelling._get_long_path_name = function
        _fixture_live_windows_path_spelling._create_buffer = (
            rooted_io.ctypes.create_unicode_buffer
        )
        _fixture_live_windows_path_spelling._get_last_error = (
            rooted_io.ctypes.get_last_error
        )
        _fixture_live_windows_path_spelling._buffer = (
            rooted_io.ctypes.create_unicode_buffer(32768)
        )
        _fixture_live_windows_path_spelling._native_lexical_inputs = {}
    get_last_error = _fixture_live_windows_path_spelling._get_last_error
    lexical = os.fspath(candidate)
    native_inputs = _fixture_live_windows_path_spelling._native_lexical_inputs
    native = native_inputs.get(lexical)
    if native is None:
        native = (
            "\\\\?\\UNC\\" + lexical[2:]
            if lexical.startswith("\\\\")
            else "\\\\?\\" + lexical
        )
        native_inputs[lexical] = native
    buffer = _fixture_live_windows_path_spelling._buffer
    written = function(native, buffer, len(buffer))
    if not written or written >= len(buffer):
        return "<UNREADABLE_PATH:%s>" % get_last_error()
    observed = buffer.value
    if observed.startswith("\\\\?\\UNC\\"):
        observed = "\\\\" + observed[8:]
    elif observed.startswith("\\\\?\\"):
        observed = observed[4:]
    return observed


def _full_no_follow_path_witness(
    path: Path,
    *,
    exact_name_cache=None,
):
    """Bind every lexical component without following an unsafe ancestor."""

    candidate = Path(os.path.abspath(os.fspath(path)))
    spelling_cache = exact_name_cache if exact_name_cache is not None else {}
    rows = []
    status = "SAFE_PRESENT"
    current = Path(candidate.anchor)
    try:
        anchor_metadata = os.lstat(current)
    except OSError as exc:
        return (
            str(candidate),
            ((str(current), "UNREADABLE", type(exc).__name__, exc.errno),),
            "UNREADABLE",
        )
    parent_state = _fixture_metadata_state(anchor_metadata)
    anchor_reparse = bool(
        stat.S_ISLNK(anchor_metadata.st_mode) or parent_state[-1] & 0x400
    )
    rows.append((str(current), "ANCHOR", (
        parent_state[0], parent_state[4], parent_state[5], parent_state[7]
    ), anchor_reparse))
    if anchor_reparse:
        status = "SYMLINK_OR_REPARSE"
    for component in candidate.parts[1:]:
        current = current / component
        normalized = unicodedata.normalize("NFC", component)
        lexical = (
            component,
            normalized,
            component == normalized,
            component.casefold(),
        )
        if status not in {"SAFE_PRESENT"}:
            rows.append((str(current), "BLOCKED_DESCENDANT", lexical, status))
            continue
        try:
            metadata = os.lstat(current)
        except FileNotFoundError:
            status = "SAFE_MISSING"
            rows.append((str(current), "MISSING", lexical))
            continue
        except OSError as exc:
            status = "UNREADABLE"
            rows.append(
                (str(current), "UNREADABLE", lexical, type(exc).__name__, exc.errno)
            )
            continue
        state = _fixture_metadata_state(metadata)
        identity = (state[0], state[4], state[5], state[7])
        reparse = bool(stat.S_ISLNK(metadata.st_mode) or state[-1] & 0x400)
        exact_key = (str(current.parent), parent_state, lexical)
        if exact_key not in spelling_cache:
            spelling_cache[exact_key] = _fixture_existing_spellings(
                current, normalized
            )
        spellings = spelling_cache[exact_key]
        exact = (
            lexical[2]
            and len(spellings) == 1
            and spellings[0] == component
        )
        rows.append(
            (str(current), "PRESENT", lexical, spellings, exact, identity, reparse)
        )
        if reparse:
            status = "SYMLINK_OR_REPARSE"
        elif not exact:
            status = "CASE_OR_NFC_ALIAS"
        else:
            parent_state = state
    return (str(candidate), tuple(rows), status)


def _typed_no_follow_path_witness(
    path: Path,
    *,
    include_bytes: bool = True,
    exact_name_cache=None,
):
    """Return typed leaf state plus its complete no-follow physical chain."""

    candidate = Path(os.path.abspath(os.fspath(path)))
    chain = _full_no_follow_path_witness(
        candidate,
        exact_name_cache=exact_name_cache,
    )
    if chain[-1] not in {"SAFE_PRESENT", "SAFE_MISSING"}:
        return (str(candidate), "PATH_POLICY_INVALID", chain)
    if chain[-1] == "SAFE_MISSING":
        return (str(candidate), "MISSING", chain)
    try:
        metadata = os.lstat(candidate)
    except FileNotFoundError:
        return (str(candidate), "MISSING_AFTER_CHAIN", chain)
    except OSError as exc:
        return (
            str(candidate), "UNREADABLE", chain, type(exc).__name__, exc.errno
        )
    identity = _fixture_metadata_state(metadata)
    if stat.S_ISDIR(metadata.st_mode):
        return (str(candidate), "DIRECTORY", chain, identity)
    if not stat.S_ISREG(metadata.st_mode):
        return (str(candidate), "OTHER", chain, identity)
    if not include_bytes:
        return (str(candidate), "REGULAR_FILE", chain, identity)
    try:
        raw = candidate.read_bytes()
    except OSError as exc:
        return (
            str(candidate),
            "UNREADABLE",
            chain,
            identity,
            type(exc).__name__,
            exc.errno,
        )
    return (
        str(candidate),
        "REGULAR_FILE",
        chain,
        identity,
        len(raw),
        hashlib.sha256(raw).hexdigest(),
    )


def _presence_path_witness(
    path: Path,
    *,
    exact_name_cache=None,
):
    """Bind both an optional leaf and the physical directory containing it."""

    candidate = Path(os.path.abspath(os.fspath(path)))
    return (
        "FULL_CHAIN_PRESENCE",
        _typed_no_follow_path_witness(
            candidate,
            exact_name_cache=exact_name_cache,
        ),
    )


def _frozen_fixture_projection(
    delegate,
    source_root: Path,
    source_rows,
    *,
    source_paths=(),
    context=None,
):
    """Reuse a fixture projection only while its exact authority is unchanged.

    The projection binds every declared source's bytes and physical identity,
    the full row denominator, and caller context.  A changed witness is replayed
    through the real delegate and becomes the next copy-isolated snapshot.
    """

    expected_root = Path(source_root).resolve()
    expected_rows = copy.deepcopy(list(source_rows))
    declared_sources = tuple(str(value) for value in source_paths)

    def live_context():
        value = context() if callable(context) else context
        return copy.deepcopy(value)

    def normalized_sources(payload):
        values = set(declared_sources)
        if isinstance(payload, dict):
            for key in ("exact_input_paths", "producer_bound_paths"):
                rows = payload.get(key, ())
                if isinstance(rows, (list, tuple)):
                    values.update(str(value) for value in rows)
        return tuple(sorted(values))

    def source_witness(names):
        observed = []
        exact_name_cache = {}
        for name in names:
            path = Path(name)
            candidate = path if path.is_absolute() else expected_root / path
            lexical_candidate = Path(os.path.abspath(os.fspath(candidate)))
            assert os.path.commonpath((
                str(expected_root), str(lexical_candidate)
            )) == str(expected_root), (
                "frozen fixture projection source path escaped its root"
            )
            observed.append(_typed_no_follow_path_witness(
                candidate,
                exact_name_cache=exact_name_cache,
            ))
        rows_bytes = json.dumps(
            expected_rows,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        context_bytes = json.dumps(
            live_context(),
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return (
            tuple(observed),
            (len(rows_bytes), hashlib.sha256(rows_bytes).hexdigest()),
            (len(context_bytes), hashlib.sha256(context_bytes).hexdigest()),
        )

    frozen = copy.deepcopy(delegate(expected_root, copy.deepcopy(expected_rows)))
    bound_sources = normalized_sources(frozen)
    frozen_witness = source_witness(bound_sources)

    def replay(observed_root, observed_rows):
        nonlocal frozen, frozen_witness, bound_sources
        assert Path(observed_root).resolve() == expected_root, (
            "frozen fixture projection source root changed"
        )
        assert list(observed_rows) == expected_rows, (
            "frozen fixture projection row denominator changed"
        )
        current_witness = source_witness(bound_sources)
        if current_witness != frozen_witness:
            refreshed = copy.deepcopy(
                delegate(expected_root, copy.deepcopy(expected_rows))
            )
            bound_sources = normalized_sources(refreshed)
            frozen = refreshed
            frozen_witness = source_witness(bound_sources)
        return copy.deepcopy(frozen)

    replay._fixture_witness = lambda: source_witness(bound_sources)
    return replay


def _install_bounded_r10_prework_replay_cache(
    driver,
    monkeypatch,
    source_root: Path,
    *,
    expected_run_id: str,
    expected_mode: str,
    known_paths,
    semantic_source_paths=(),
    semantic_projection=None,
) -> None:
    """Memoize only one exactly witnessed R10 report-consumer view.

    The key binds typed R10 roster state, current ledger bytes and physical
    identity, semantic source bytes, projection context, run ID, and mode.
    Corruption or source drift therefore enters the production replay.
    """

    expected_root = Path(source_root).resolve()
    roster = tuple(driver._R10_REPORT_PREWORK_ROSTER)
    original = driver._r10_report_prework_input_paths

    semantic_names = tuple(sorted(str(value) for value in semantic_source_paths))

    def fingerprint(root: Path):
        observed = []
        exact_name_cache = {}
        for name in roster:
            observed.append(_presence_path_witness(
                root / name,
                exact_name_cache=exact_name_cache,
            ))
        return tuple(observed)

    def authority_witness(root: Path):
        exact_name_cache = {}
        projection = (
            semantic_projection._fixture_witness()
            if semantic_projection is not None
            else None
        )
        return (
            _typed_no_follow_path_witness(
                root / "_artifact_state.json",
                exact_name_cache=exact_name_cache,
            ),
            tuple(
                _typed_no_follow_path_witness(
                    root / name,
                    exact_name_cache=exact_name_cache,
                )
                for name in semantic_names
            ),
            projection,
        )

    initial_key = (
        str(expected_run_id),
        str(expected_mode),
        fingerprint(expected_root),
        authority_witness(expected_root),
    )
    cache = {initial_key: tuple(known_paths)}

    def replay(root, *, expected_run_id, expected_mode):
        resolved = Path(root).resolve()
        assert resolved == expected_root, "bounded R10 prework source root changed"
        key = (
            str(expected_run_id),
            str(expected_mode),
            fingerprint(resolved),
            authority_witness(resolved),
        )
        if key not in cache:
            cache[key] = tuple(original(
                resolved,
                expected_run_id=expected_run_id,
                expected_mode=expected_mode,
            ))
        return tuple(cache[key])

    monkeypatch.setattr(driver, "_r10_report_prework_input_paths", replay)


def _install_bounded_phaseio_validation_cache(
    driver,
    monkeypatch,
    source_root: Path,
    project_root: Path,
) -> None:
    """Deduplicate exact PhaseIO replays inside the synthetic unit fixture.

    The cache witnesses the ledger, immutable and bounded inputs, outputs, and
    every explicit-absence roster leaf plus its physical parent.  Typed states
    keep missing, regular, directory, reparse, and unreadable paths distinct.
    """

    expected_root = Path(source_root).resolve()
    expected_project = Path(project_root).resolve()

    def contract_witness(root: Path, project: Path, contract):
        exact_name_cache = {}
        identities = list(contract.immutable_inputs)
        identities.extend(contract.bounded_lookup_inputs)
        identities.extend(spec.identity for spec in contract.outputs)
        ledger_path = root / "_artifact_state.json"
        rows = [_typed_no_follow_path_witness(
            ledger_path,
            exact_name_cache=exact_name_cache,
        )]
        for identity in sorted(set(identities)):
            root_name, relative = str(identity).split(":", 1)
            base = root if root_name == "scratchpad" else project
            rows.append(_presence_path_witness(
                base / relative,
                exact_name_cache=exact_name_cache,
            ))
        try:
            ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
            unit = ledger.get("work_units", {}).get(contract.key, {})
            receipt = unit.get("explicit_absence_authority", {})
            roster = receipt.get("roster_identities", ())
        except (OSError, UnicodeError, ValueError, AttributeError, TypeError):
            rows.append(("EXPLICIT_ABSENCE_ROSTER", "UNREADABLE"))
        else:
            if not isinstance(roster, list):
                rows.append(("EXPLICIT_ABSENCE_ROSTER", "MALFORMED", repr(roster)))
            else:
                rows.append(("EXPLICIT_ABSENCE_ROSTER", tuple(roster)))
                for identity in roster:
                    if not isinstance(identity, str) or ":" not in identity:
                        rows.append(("MALFORMED_IDENTITY", repr(identity)))
                        continue
                    root_name, relative = identity.split(":", 1)
                    if root_name not in {"scratchpad", "project"}:
                        rows.append(("MALFORMED_IDENTITY", identity))
                        continue
                    base = root if root_name == "scratchpad" else project
                    rows.append(_presence_path_witness(
                        base / relative,
                        exact_name_cache=exact_name_cache,
                    ))
        return tuple(rows)

    for attribute in (
        "validate_work_unit_inputs",
        "validate_work_unit_explicit_absence_bindings",
        "validate_work_unit_artifacts",
    ):
        original = getattr(driver, attribute)
        cache = {}

        def replay(*args, __attribute=attribute, __original=original, **kwargs):
            root = Path(args[0]).resolve()
            project = Path(args[1]).resolve()
            if root != expected_root or project != expected_project:
                return __original(*args, **kwargs)
            contract = args[2]
            launch = args[3]
            key = (
                __attribute,
                contract.digest,
                launch.digest,
                repr(args[4:]),
                repr(sorted(kwargs.items())),
                contract_witness(root, project, contract),
            )
            if key not in cache:
                cache[key] = copy.deepcopy(__original(*args, **kwargs))
            return copy.deepcopy(cache[key])

        monkeypatch.setattr(driver, attribute, replay)


def _install_bounded_lexical_chain_cache(
    monkeypatch,
    project_root: Path,
) -> None:
    """Reuse hardened path-chain results only inside one controlled fixture.

    Every live ancestor identity, reparse bit, and exact case/NFC spelling is in
    the key.  Exact-name scans are reused only while the containing directory's
    physical and change state are identical.  Paths outside the project remain
    uncached.
    """

    import artifact_ledger as ledger_module

    expected_project = Path(project_root).absolute()
    original = ledger_module._lexical_no_follow_chain
    cache = {}
    lexical_plan_cache = {}

    def chain_identity_witness(candidate: Path):
        candidate_text = str(candidate)
        plan = lexical_plan_cache.get(candidate_text)
        if plan is None:
            current = Path(candidate.anchor)
            components = []
            for index, component in enumerate(candidate.parts[1:], start=1):
                current = current / component
                normalized = unicodedata.normalize("NFC", component)
                components.append((
                    index,
                    current,
                    str(current),
                    (
                        component,
                        normalized,
                        component == normalized,
                        component.casefold(),
                    ),
                ))
            plan = (Path(candidate.anchor), tuple(components))
            lexical_plan_cache[candidate_text] = plan
        anchor, components = plan
        observations = []
        blocked = None
        try:
            anchor_state = _fixture_metadata_state(os.lstat(anchor))
        except OSError as exc:
            anchor_witness = (
                str(anchor), "UNREADABLE", type(exc).__name__, exc.errno
            )
        else:
            anchor_identity = (
                anchor_state[0],
                anchor_state[4],
                anchor_state[5],
                anchor_state[7],
            )
            anchor_witness = (
                str(anchor),
                anchor_identity,
                bool(
                    stat.S_ISLNK(anchor_state[0])
                    or anchor_identity[-1] & 0x400
                ),
            )
        deepest_safe = anchor
        for index, current, path_text, lexical in components:
            if blocked is not None:
                observations.append(
                    (index, path_text, "BLOCKED_DESCENDANT", lexical, blocked)
                )
                continue
            try:
                metadata = os.lstat(current)
            except FileNotFoundError:
                blocked = "MISSING"
                observations.append((index, path_text, "MISSING", lexical))
                continue
            except OSError as exc:
                observations.append(
                    (
                        index,
                        path_text,
                        "UNREADABLE",
                        lexical,
                        type(exc).__name__,
                        exc.errno,
                    )
                )
                continue
            state = _fixture_metadata_state(metadata)
            identity = (state[0], state[4], state[5], state[7])
            reparse = bool(
                stat.S_ISLNK(metadata.st_mode) or identity[-1] & 0x400
            )
            observations.append(
                (
                    index,
                    path_text,
                    "PRESENT",
                    identity,
                    lexical,
                    reparse,
                )
            )
            if reparse:
                blocked = "SYMLINK_OR_REPARSE"
            else:
                deepest_safe = current
        return ((anchor_witness, tuple(observations)), observations, deepest_safe)

    def live_exact_name_witness(observations, deepest_safe):
        actual_safe = (
            _fixture_live_windows_path_spelling(deepest_safe)
            if os.name == "nt"
            else os.fspath(deepest_safe)
        )
        expected_safe = os.fspath(deepest_safe)
        safe_exact = actual_safe == expected_safe
        rows = [("SAFE_PREFIX", expected_safe, actual_safe, safe_exact)]
        all_exact = safe_exact
        safe_part_count = len(deepest_safe.parts)
        for observation in observations:
            index, path_text, kind, payload, *tail = observation
            if kind == "PRESENT":
                identity = payload
                lexical = tail[0]
                reparse = tail[1]
                if index >= safe_part_count:
                    spellings = _fixture_existing_spellings(
                        Path(path_text), lexical[1]
                    )
                    exact = (
                        lexical[2]
                        and len(spellings) == 1
                        and spellings[0] == lexical[0]
                    )
                    all_exact = all_exact and exact
                    rows.append(
                        (
                            path_text,
                            identity,
                            lexical,
                            spellings,
                            exact,
                            reparse,
                        )
                    )
                continue
            if kind == "MISSING":
                lexical = payload
                spellings = _fixture_existing_spellings(
                    Path(path_text), lexical[1]
                )
                absent = (
                    os.name == "nt"
                    and len(spellings) == 2
                    and spellings[0] == "<UNREADABLE_DIRECTORY_ENTRY>"
                    and spellings[1] in {"2", "3"}
                ) or (os.name != "nt" and not spellings)
                all_exact = all_exact and absent
                rows.append((path_text, kind, lexical, spellings, absent))
                continue
            rows.append((path_text, kind, payload, *tail))
        return (tuple(rows), all_exact)

    def replay(path):
        candidate = Path(path).absolute()
        try:
            candidate.relative_to(expected_project)
        except ValueError:
            return original(path)
        identity_witness, observations, deepest_safe = (
            chain_identity_witness(candidate)
        )
        key = (
            str(candidate),
            identity_witness,
        )
        if key in cache:
            _spelling_witness, exact = live_exact_name_witness(
                observations, deepest_safe
            )
            if exact:
                return cache[key]
            return original(path)
        result = original(path)
        cache[key] = result
        return result

    monkeypatch.setattr(ledger_module, "_lexical_no_follow_chain", replay)


def _install_bounded_artifact_observation_cache(
    monkeypatch,
    fixture_root: Path,
) -> None:
    """Reuse stable artifact observations only inside one synthetic fixture.

    A cache hit still performs a fresh typed, no-follow observation.  Its key
    binds the lexical path, exact case/NFC spelling, every ancestor's physical
    identity and reparse state, the leaf identity and metadata, and the leaf's
    exact length and SHA-256.  Missing, aliased, reparse, unreadable, unstable,
    or out-of-root paths always run the production delegate.
    """

    import artifact_ledger as ledger_module

    expected_root = Path(os.path.abspath(os.fspath(fixture_root)))
    original_snapshot = ledger_module._stable_artifact_snapshot
    original_physical = ledger_module._physical_file_identity
    snapshot_cache = {}
    physical_cache = {}

    def stable_key(path):
        candidate = Path(os.path.abspath(os.fspath(path)))
        try:
            common = os.path.commonpath((str(expected_root), str(candidate)))
        except (OSError, ValueError):
            return candidate, None
        if os.path.normcase(common) != os.path.normcase(str(expected_root)):
            return candidate, None
        witness = _typed_no_follow_path_witness(candidate)
        if len(witness) < 6 or witness[1] != "REGULAR_FILE":
            return candidate, None
        try:
            confirmed_metadata = os.lstat(candidate)
        except OSError:
            return candidate, None
        if (
            _fixture_metadata_state(confirmed_metadata) != witness[3]
            or not stat.S_ISREG(confirmed_metadata.st_mode)
        ):
            return candidate, None
        return candidate, (str(candidate), witness)

    def replay_snapshot(
        path,
        *,
        confirmation_reads=True,
        _known_chain=None,
        _captured_chain=None,
    ):
        # Caller-supplied chain authority is a distinct observation contract
        # and must always run the production delegate.  Reduced confirmation
        # reads remain cacheable when their mode and captured-chain side effect
        # are both retained in the cache entry.
        if _known_chain is not None or confirmation_reads not in {True, False}:
            return original_snapshot(
                path,
                confirmation_reads=confirmation_reads,
                _known_chain=_known_chain,
                _captured_chain=_captured_chain,
            )
        candidate, key = stable_key(path)
        path_key = (str(candidate), confirmation_reads)
        cached = snapshot_cache.get(path_key)
        if key is not None and cached is not None and cached[0] == key:
            if _captured_chain is not None:
                _captured_chain.append(copy.deepcopy(cached[2]))
            return copy.deepcopy(cached[1])
        snapshot_cache.pop(path_key, None)
        captured_chain = []
        result = original_snapshot(
            path,
            confirmation_reads=confirmation_reads,
            _captured_chain=captured_chain,
        )
        if _captured_chain is not None:
            _captured_chain.extend(copy.deepcopy(captured_chain))
        if result[0] is not None and result[1] == "":
            _confirmed_candidate, confirmed_key = stable_key(path)
            if key is not None and confirmed_key == key and captured_chain:
                snapshot_cache[path_key] = (
                    key,
                    copy.deepcopy(result),
                    copy.deepcopy(captured_chain[0]),
                )
        return copy.deepcopy(result)

    def replay_physical(path):
        candidate, key = stable_key(path)
        path_key = str(candidate)
        cached = physical_cache.get(path_key)
        if key is not None and cached is not None and cached[0] == key:
            return cached[1]
        physical_cache.pop(path_key, None)
        try:
            result = original_physical(path)
        except (ledger_module.ArtifactLedgerError, OSError):
            raise
        _confirmed_candidate, confirmed_key = stable_key(path)
        if key is not None and confirmed_key == key:
            physical_cache[path_key] = (key, result)
        return result

    monkeypatch.setattr(
        ledger_module, "_stable_artifact_snapshot", replay_snapshot
    )
    monkeypatch.setattr(
        ledger_module, "_physical_file_identity", replay_physical
    )


def test_bounded_snapshot_cache_replays_chain_and_invalidates_on_mutation(
    tmp_path,
    monkeypatch,
):
    import artifact_ledger as ledger_module

    target = tmp_path / "artifact.md"
    target.write_bytes(b"first-current-bytes\n")
    production_snapshot = ledger_module._stable_artifact_snapshot
    calls = []

    def counted_snapshot(path, **kwargs):
        calls.append((Path(path), dict(kwargs)))
        return production_snapshot(path, **kwargs)

    monkeypatch.setattr(
        ledger_module, "_stable_artifact_snapshot", counted_snapshot
    )
    _install_bounded_artifact_observation_cache(
        monkeypatch, tmp_path
    )

    first_chain = []
    first = ledger_module._stable_artifact_snapshot(
        target,
        confirmation_reads=False,
        _captured_chain=first_chain,
    )
    replay_chain = []
    replay = ledger_module._stable_artifact_snapshot(
        target,
        confirmation_reads=False,
        _captured_chain=replay_chain,
    )

    assert len(calls) == 1
    assert first == replay
    assert first_chain and replay_chain == first_chain

    target.write_bytes(b"second-mutated-bytes\n")
    mutated_chain = []
    mutated = ledger_module._stable_artifact_snapshot(
        target,
        confirmation_reads=False,
        _captured_chain=mutated_chain,
    )

    assert len(calls) == 2
    assert mutated_chain
    assert mutated != first


def test_r10_fixture_projection_is_single_scan_copy_isolated_and_bounded(
    tmp_path,
):
    """The unit seam must not turn one immutable source set into N scans."""

    sp = _scratch(tmp_path)
    rows = [{"finding id": "H-993", "severity": "High"}]
    calls = []

    def delegate(root, observed_rows):
        calls.append((Path(root), list(observed_rows)))
        return {"candidates": [{"finding_id": "H-993"}], "issues": []}

    replay = _frozen_fixture_projection(delegate, sp, rows)
    first = replay(sp, rows)
    first["candidates"][0]["finding_id"] = "MUTATED"
    second = replay(sp, rows)

    assert calls == [(sp, rows)]
    assert second["candidates"] == [{"finding_id": "H-993"}]
    with pytest.raises(AssertionError, match="source root"):
        replay(tmp_path / "different", rows)
    with pytest.raises(AssertionError, match="row denominator"):
        replay(sp, [{"finding id": "H-994", "severity": "High"}])


def test_r10_phaseio_contract_has_mandatory_and_conditional_outputs():
    sys.path.insert(0, os.path.join(os.path.dirname(__file__)))
    P = importlib.import_module("phase_io_contracts")
    contract = P.resolve_phase_io_contract(
        pipeline="sc",
        mode="core",
        ecosystem="evm",
        backend="claude",
        phase="sc_verify_aggregate",
        work_unit_id="external_assumption_undemotion_reconcile",
        exact_inputs=("verification_queue.md",),
    )
    outputs = {item.path: item for item in contract.outputs}

    assert contract.model_invoked is False
    assert contract.immutable_inputs == (
        "scratchpad:verification_queue.md",
    )
    assert set(outputs) == {
        "external_assumption_undemotion_compute.json",
        "external_assumption_undemotions.json",
        "external_assumption_undemotions.md",
        "external_assumption_undemotion_debt.json",
    }
    assert outputs["external_assumption_undemotion_compute.json"].artifact_class == (
        "DRIVER_GENERATED"
    )
    assert outputs["external_assumption_undemotions.json"].condition_id == (
        "r10_fired"
    )
    assert outputs["external_assumption_undemotions.md"].condition_id == (
        "r10_fired"
    )
    assert outputs["external_assumption_undemotion_debt.json"].condition_id == (
        "r10_authority_debt"
    )


def test_r10_source_mutation_after_arm_is_rejected_before_output(tmp_path):
    V, D, sp, config, phase = _r10_driver_fixture(tmp_path)
    queue_rows = V.parse_verification_queue_rows(sp)
    authority = V._r10_semantic_input_authority(sp, queue_rows)
    contract, launch = D._r10_contract_and_launch(
        scratchpad=sp,
        config=config,
        phase=phase,
        exact_inputs=authority["exact_input_paths"],
    )
    execute, arm_issues = D._arm_deterministic_driver_work_unit(
        scratchpad=sp,
        project_root=tmp_path,
        contract=contract,
        launch=launch,
        run_id=config["_run_id"],
    )
    assert execute is True
    assert arm_issues == []

    verify_path = sp / "verify_H-993.md"
    verify_path.write_bytes(verify_path.read_bytes() + b"\nlate mutation\n")
    compute, issues = D._write_and_record_r10_phase_io(
        scratchpad=sp,
        config=config,
        phase=phase,
    )

    assert compute == {}
    assert issues
    assert any("input" in issue.lower() for issue in issues)
    assert not (sp / "external_assumption_undemotion_compute.json").exists()
    assert not (sp / "external_assumption_undemotions.json").exists()
    assert not (sp / "external_assumption_undemotions.md").exists()
    assert not (sp / "external_assumption_undemotion_debt.json").exists()


def test_r10_resume_removes_stale_optional_outputs_and_commits_debt(tmp_path):
    V, D, sp, config, phase = _r10_driver_fixture(tmp_path)
    queue_rows = V.parse_verification_queue_rows(sp)
    authority = V._r10_semantic_input_authority(sp, queue_rows)
    contract, launch = D._r10_contract_and_launch(
        scratchpad=sp,
        config=config,
        phase=phase,
        exact_inputs=authority["exact_input_paths"],
    )
    verifier_before = (sp / "verify_H-993.md").read_bytes()
    execute, arm_issues = D._arm_deterministic_driver_work_unit(
        scratchpad=sp,
        project_root=tmp_path,
        contract=contract,
        launch=launch,
        run_id=config["_run_id"],
    )
    assert execute is True
    assert arm_issues == []

    # Simulate a crash after optional files were emitted but before the
    # mandatory compute/debt transaction was committed.
    (sp / "external_assumption_undemotions.json").write_text(
        "{}\n", encoding="utf-8"
    )
    (sp / "external_assumption_undemotions.md").write_text(
        "stale\n", encoding="utf-8"
    )
    compute, issues = D._write_and_record_r10_phase_io(
        scratchpad=sp,
        config=config,
        phase=phase,
    )

    assert compute["outcome"] == "CLEAN_ZERO"
    assert issues
    assert (sp / "external_assumption_undemotion_compute.json").is_file()
    assert (sp / "external_assumption_undemotion_debt.json").is_file()
    assert not (sp / "external_assumption_undemotions.json").exists()
    assert not (sp / "external_assumption_undemotions.md").exists()
    assert (sp / "verify_H-993.md").read_bytes() == verifier_before

    ledger = json.loads((sp / "_artifact_state.json").read_text("utf-8"))
    key = next(
        key for key in ledger["work_units"]
        if key.endswith("/external_assumption_undemotion_reconcile")
    )
    unit = ledger["work_units"][key]
    assert unit["semantic_status"] == "ACTIVE"
    assert unit["execution_state"] == "OUTPUT_COMMITTED"
    debt_before = (sp / "external_assumption_undemotion_debt.json").read_bytes()
    projection = V._external_assumption_undemotion_projection(sp)
    assert projection["valid_floors"] == {}
    assert projection["debt_ids"] == {"H-993"}
    assert projection["issues"]
    assert (sp / "external_assumption_undemotion_debt.json").read_bytes() == debt_before


def test_r10_light_driver_commits_clean_absence_without_authority_debt(tmp_path):
    V, D, sp, config, phase = _r10_driver_fixture(tmp_path)
    config["mode"] = "light"

    compute, issues = D._write_and_record_r10_phase_io(
        scratchpad=sp,
        config=config,
        phase=phase,
    )

    assert compute["mode"] == "light"
    assert compute["outcome"] == "CLEAN_ZERO"
    assert compute["fired_count"] == 0
    assert issues == []
    assert (sp / "external_assumption_undemotion_compute.json").is_file()
    assert not (sp / "external_assumption_undemotion_debt.json").exists()
    assert not (sp / "external_assumption_undemotions.json").exists()
    assert not (sp / "external_assumption_undemotions.md").exists()
    assert V._external_assumption_undemotion_projection(sp) == {
        "valid_floors": {},
        "fallback_floors": {},
        "debt_ids": set(),
        "issues": [],
    }


def test_r10_authenticated_driver_fired_phaseio_happy_path(
    tmp_path, monkeypatch
):
    """Isolate the DRIVER transaction after the semantic authority gate.

    Raw-producer rejection is covered separately.  This fixture supplies the
    authenticated gate result and verifies that FIRED commits exactly the
    compute/result/compatibility universe, with no authority-debt output.
    """

    V, D, sp, config, phase = _r10_driver_fixture(tmp_path)
    original_authority = V._r10_semantic_input_authority

    def authenticated_authority(root, rows):
        payload = original_authority(root, rows)
        candidates = []
        for row in payload["candidates"]:
            candidate = dict(row)
            candidate["verifier_authority_issues"] = []
            candidates.append(candidate)
        payload["candidates"] = candidates
        payload["candidate_digest"] = hashlib.sha256(
            V._canonical_validator_json_bytes({"candidates": candidates})
        ).hexdigest()
        payload["issues"] = []
        payload["producer_bound_paths"] = []
        payload["run_id"] = config["_run_id"]
        payload["status"] = "AUTHENTICATED_CURRENT"
        payload["strict"] = True
        return payload

    monkeypatch.setattr(V, "_r10_semantic_input_authority", authenticated_authority)
    monkeypatch.setattr(D, "_r10_semantic_input_authority", authenticated_authority)
    verifier_before = (sp / "verify_H-993.md").read_bytes()

    compute, issues = D._write_and_record_r10_phase_io(
        scratchpad=sp,
        config=config,
        phase=phase,
    )

    assert issues == []
    assert compute["outcome"] == "FIRED"
    assert compute["fired_ids"] == ["H-993"]
    assert (sp / "external_assumption_undemotion_compute.json").is_file()
    assert (sp / "external_assumption_undemotions.json").is_file()
    assert (sp / "external_assumption_undemotions.md").is_file()
    assert not (sp / "external_assumption_undemotion_debt.json").exists()
    assert (sp / "verify_H-993.md").read_bytes() == verifier_before

    projection = V._external_assumption_undemotion_projection(sp)
    assert projection["valid_floors"] == {"H-993": "High"}
    assert projection["debt_ids"] == set()
    assert projection["issues"] == []
    ledger = json.loads((sp / "_artifact_state.json").read_text("utf-8"))
    key = next(
        key for key in ledger["work_units"]
        if key.endswith("/external_assumption_undemotion_reconcile")
    )
    assert ledger["work_units"][key]["semantic_status"] == "ACTIVE"
    assert ledger["work_units"][key]["execution_state"] == "OUTPUT_COMMITTED"


def test_legacy_raw_r10_is_diagnostic_only_and_cannot_mint_report_floor(
    tmp_path,
):
    """Receipt-only compatibility state is never production authority."""

    V = _v()
    sp = _scratch(tmp_path)
    (sp / "config.json").write_text(
        json.dumps({"proven_only": True}), encoding="utf-8"
    )
    _queue(sp, [("INV-994", "High", "unit")])
    _inventory(
        sp, "INV-994", verdict="CONFIRMED", severity="High", ext_tag=True
    )
    _verify(sp, "INV-994", verdict="CONTESTED", severity="Low")
    _research_stub(sp)

    assert V._apply_external_assumption_undemotions(sp, "core")
    projection = V._external_assumption_undemotion_projection(sp)

    assert not (sp / "verification_queue.work_items.json").exists()
    assert not (sp / "_artifact_state.json").exists()
    assert projection["valid_floors"] == {}
    assert projection["fallback_floors"] == {}
    assert projection["debt_ids"] == {"INV-994"}
    assert projection["issues"]
    assert V._load_external_assumption_undemotions(sp) == {}
    assert V._expected_report_index_severities(sp)["INV-994"] != "High"


def _seed_r10_split_parent_sources(
    V, sp: Path, project_root: Path, *, run_id: str
) -> None:
    """Seed the R0-2b split-parent shape plus the real no-provider overlay."""

    (sp / "verify_H-993.md").unlink(missing_ok=True)
    V._write_queue_subset_manifest(
        sp / "verification_queue.md",
        [{
            "queue #": "1",
            "finding id": "H-22",
            "severity": "High",
            "title": "split-parent external premise",
            "bug class": "state consistency",
            "preferred tag": "[CODE-TRACE]",
            "location": "src/lib.rs:L42",
            "primary artifact": "findings_inventory.md",
            "poc class": "structural",
        }],
    )
    inventory_blocks: list[str] = []
    for finding_id, verdict in (
        ("INV-041", "CONFIRMED"),
        ("INV-042", "REFUTED"),
        ("INV-116", "REFUTED"),
        ("INV-239", "REFUTED"),
    ):
        _inventory(
            sp,
            finding_id,
            verdict=verdict,
            severity="High",
            ext_tag=True,
        )
        inventory_blocks.append(
            (sp / "findings_inventory.md").read_text(
                encoding="utf-8", errors="strict"
            )
        )
    (sp / "findings_inventory.md").write_text(
        "".join(inventory_blocks), encoding="utf-8"
    )
    (sp / "finding_mapping.md").write_text(
        "".join([
            "# Finding Mapping\n\n",
            "| Finding | Hypothesis ID | Mapping Status |\n",
            "|---------|---------------|----------------|\n",
            "| INV-041 | GRP-022A | ABSORBED_DEDUP (SPLIT from H-22) |\n",
            "| INV-042 | GRP-022A | PRIMARY (SPLIT from H-22) |\n",
            "| INV-116 | GRP-022B | PRIMARY (SPLIT from H-22) |\n",
            "| INV-239 | GRP-022A | ABSORBED_DEDUP (SPLIT from H-22) |\n",
        ]),
        encoding="utf-8",
    )
    (sp / "hypotheses.md").write_text("# Hypotheses\n", encoding="utf-8")
    _research_stub(sp)
    _verify(
        sp,
        "H-22",
        verdict="CONTESTED",
        severity="Low",
        stability_cue=True,
        ext_cited=False,
        skip="EXTERNAL_DEPENDENCY_NO_FORK_OR_ADDRESS",
    )

    from chain_grouping_assurance import write_chain_grouping_assurance
    from chain_grouping_authority import write_chain_grouping_relations
    from plamen_parsers import _parse_hypothesis_constituents

    active_mapping = _parse_hypothesis_constituents(
        sp, apply_chain_grouping_authority=False
    )
    write_chain_grouping_relations(
        sp,
        active_mapping,
        V._parse_inventory_finding_meta(sp),
        (sp / "hypotheses.md").read_text(encoding="utf-8", errors="strict"),
    )
    assurance = write_chain_grouping_assurance(
        sp, project_root, run_id=run_id
    )
    assert assurance["may_delete_demote_or_collapse"] is False
    assert assurance["authority"] == "DRIVER_RECONCILIATION_ONLY"


def _r10_low_external_severity_proposal(item) -> bytes:
    """Return the verifier's typed Low proposal for the uncited premise."""

    constituents = [item.work_item_id, *item.constituents]
    payload = {
        "schema_version": "plamen.severity_proposal.v1",
        "candidate_id": item.work_item_id,
        "constituent_ids": constituents,
        "impact": {
            "class": "Low",
            "harmed_asset": "state-consistency guarantee",
            "harmed_capability": "consistent reads within one operation",
            "premise_id": f"PREM-{item.work_item_id}-IMPACT",
            "premise_kind": "EXTERNAL_FAVORABLE",
            "evidence_ids": [f"EVID-{item.work_item_id}-IMPACT"],
            "proof_scope": "IN_SCOPE_SOURCE",
        },
        "likelihood": {
            "class": "Low",
            "actor": "unprivileged caller",
            "preconditions": ["the external value changes within the window"],
            "premise_id": f"PREM-{item.work_item_id}-LIKELIHOOD",
            "premise_kind": "EXTERNAL_FAVORABLE",
            "evidence_ids": [f"EVID-{item.work_item_id}-LIKELIHOOD"],
            "proof_scope": "IN_SCOPE_SOURCE",
        },
        "modifiers": [],
        "proposed_severity": "Low",
        "adjustment": None,
        "constituent_premise_outcomes": {
            identity: {"impact": "SUPPORTED", "likelihood": "UNRESOLVED"}
            for identity in constituents
        },
    }
    return json.dumps(payload, sort_keys=True).encode("utf-8")


def _write_r10_operator_application(
    sp: Path, work_unit_id: str, work_item_id: str
) -> None:
    """Emit the exact model-owned application required by the live unit."""

    dispatch = json.loads(
        (
            sp
            / "_verifier_runtime_units"
            / work_unit_id
            / "method_dispatch.json"
        ).read_text(encoding="utf-8", errors="strict")
    )
    row = next(
        item for item in dispatch["rows"]
        if item["work_item_id"] == work_item_id
    )
    operators = []
    for operator_id in row["operator_ids"]:
        if (
            operator_id == "context-closure"
            and row["context_state"] == "CONTEXT_UNRESOLVED"
        ):
            operators.append({
                "operator_id": operator_id,
                "status": "BLOCKED",
                "evidence": [],
                "predicate": None,
                "debt_code": "CONTEXT_UNRESOLVED",
                "blocker_evidence": [
                    "Fixture repository has no additional caller graph edge."
                ],
            })
        else:
            operators.append({
                "operator_id": operator_id,
                "status": "APPLIED",
                "evidence": [{
                    "source": "src/lib.rs:42",
                    "detail": (
                        "Fixture exercised the dispatched verification operator."
                    ),
                }],
                "predicate": None,
                "debt_code": None,
                "blocker_evidence": [],
            })
    payload = {
        "schema_version": "plamen.verification_operator_application.v1",
        "work_item_id": work_item_id,
        "method_dispatch_id": dispatch["dispatch_id"],
        "selected_module_hashes": row["module_hashes"],
        "context_packet_digest": row["context_packet_digest"],
        "context_status": row["context_state"],
        "context_expansion": [],
        "operators": operators,
        "new_observations": [],
    }
    (sp / f"verify_{work_item_id}.operator_application.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _bind_current_r10_queue_authority(
    D,
    sp: Path,
    config: dict,
    *,
    live_t9: bool = False,
) -> object:
    """Publish real preverify successors and the real SC queue transaction."""

    if live_t9:
        from live_verify_queue_driver_adapter import (
            run_live_verify_queue_driver_cutover,
        )

        # The focused report-consumer fixture needs the same authenticated T9
        # publication capability as production.  Its compact project does not
        # run the startup snapshot phase, so bind a deterministic fixture
        # snapshot identity into the otherwise production-only cutover.
        cutover_config = {
            **config,
            "_audit_snapshot": {"snapshot_digest": "a" * 64},
        }
        fixture_source = Path(config["project_root"]) / "src" / "Fixture.sol"
        fixture_source.parent.mkdir(parents=True, exist_ok=True)
        fixture_source.write_text(
            "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.20;\n",
            encoding="utf-8",
        )
        chain_pair_projection = D.prepare_preverify_chain_pair_projection(
            scratchpad=sp,
            project_root=Path(config["project_root"]),
            pipeline="sc",
            mode=config["mode"],
            ecosystem=config["language"],
            backend=config["cli_backend"],
            phase_name="sc_verify_queue",
            run_id=config["_run_id"],
        )
        assert chain_pair_projection["safe_to_consume"] is True
        frozen_projection = D.prepare_preverify_frozen_projection(
            scratchpad=sp,
            project_root=Path(config["project_root"]),
            pipeline="sc",
            mode=config["mode"],
            ecosystem=config["language"],
            backend=config["cli_backend"],
            phase_name="sc_verify_queue",
            run_id=config["_run_id"],
            chain_pair_projection=chain_pair_projection,
        )
        assert D._finalize_preverify_inventory_successors(
            sp,
            cutover_config,
            phase_name="sc_verify_queue",
            frozen_projection=frozen_projection,
        ) == []
        routing_contract, _routing_launch = (
            D._typed_verify_queue_routing_contract_and_launch(
                "sc_verify_queue", sp, cutover_config
            )
        )
        for spec in routing_contract.outputs:
            (sp / spec.path).unlink(missing_ok=True)
        armed, arm_issues = D._arm_typed_verify_queue_routing_artifacts(
            "sc_verify_queue",
            sp,
            cutover_config,
            materialize_context_status=False,
        )
        assert armed is True, arm_issues
        assert arm_issues == []
        result = run_live_verify_queue_driver_cutover(
            scratchpad=sp,
            project_root=Path(config["project_root"]),
            config=cutover_config,
            run_id=config["_run_id"],
        )
        assert result["state"] == "OUTPUT_COMMITTED"
        assert result["safe_to_consume"] is True
        return result["plan"]

    from plamen_parsers import (
        SC_VERIFY_SHARD_MANIFESTS,
        _read_typed_queue_work_items,
        _write_or_validate_queue_work_plan,
        _write_queue_subset_manifest,
        compute_sc_verify_shards,
    )

    frozen_projection = D.prepare_preverify_frozen_projection(
        scratchpad=sp,
        project_root=Path(config["project_root"]),
        pipeline="sc",
        mode=config["mode"],
        ecosystem=config["language"],
        backend=config["cli_backend"],
        phase_name="sc_verify_queue",
        run_id=config["_run_id"],
    )
    assert D._finalize_preverify_inventory_successors(
        sp,
        config,
        phase_name="sc_verify_queue",
        frozen_projection=frozen_projection,
    ) == []

    shards = compute_sc_verify_shards(sp)
    for phase_name, rows in shards.items():
        _write_queue_subset_manifest(
            sp / SC_VERIFY_SHARD_MANIFESTS[phase_name], rows
        )
    items = _read_typed_queue_work_items(sp / "verification_queue.md")
    plan = _write_or_validate_queue_work_plan(sp, items, shards, "sc")

    contract, _launch = D._typed_verify_queue_routing_contract_and_launch(
        "sc_verify_queue", sp, config
    )
    generated_by_commit = {
        "verification_context_packets.json",
        "verification_methodology_reachability.json",
    }
    for spec in contract.outputs:
        path = sp / spec.path
        if not path.is_file() and spec.path not in generated_by_commit:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(
                "# Fixture projection\n" if path.suffix == ".md" else "{}\n",
                encoding="utf-8",
            )
    output_bytes = {
        spec.path: (sp / spec.path).read_bytes()
        for spec in contract.outputs
        if (sp / spec.path).is_file()
    }
    for relative in output_bytes:
        (sp / relative).unlink()
    execute, issues = D._arm_typed_verify_queue_routing_artifacts(
        "sc_verify_queue", sp, config
    )
    assert execute is True, issues
    assert issues == []
    restore_order = sorted(
        output_bytes,
        key=lambda relative: (
            not relative.endswith(".md"),
            relative,
        ),
    )
    for relative in restore_order:
        raw = output_bytes[relative]
        path = sp / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
    record_issues = D._record_typed_verify_queue_routing_artifacts(
        "sc_verify_queue", sp, config
    )
    assert record_issues == [], record_issues
    return plan


def _run_current_r10_verifier(
    D,
    sp: Path,
    config: dict,
    monkeypatch,
    *,
    verify_bytes: bytes,
) -> None:
    """Complete the real dynamic verifier unit with deterministic model bytes."""

    items = {
        item.work_item_id: item
        for item in D._read_typed_queue_work_items(sp / "verification_queue.md")
    }
    phase = next(
        item for item in D.SC_PHASES if item.name == "sc_verify_crithigh"
    )
    outcome = D._prepare_dynamic_verifier_roster(sp, config, phase)
    assert outcome.roster is not None
    assert outcome.debts == ()
    roster = outcome.roster

    def deterministic_no_provider_execute(spec, **_kwargs):
        unit = roster.work_unit(spec.work_unit_id)
        for work_id in unit.ordered_work_item_ids:
            (sp / f"verify_{work_id}.md").write_bytes(verify_bytes)
            (sp / f"verify_{work_id}.severity_proposal.json").write_bytes(
                _r10_low_external_severity_proposal(items[work_id])
            )
            _write_r10_operator_application(sp, spec.work_unit_id, work_id)
        return 0

    units = [unit for unit in roster.work_units if unit.tier_pool == "critical_high"]
    assert len(units) == 1
    # R10 is specifically the Attempted:NO external-premise case, while the
    # generic Core execution policy independently mandates attempts for every
    # High queue row. The established dynamic-runtime fixture seam suppresses
    # only that orthogonal policy check while all identity, receipt, roster,
    # operator, gate, and PhaseIO completion checks remain production code.
    with monkeypatch.context() as runtime_patch:
        runtime_patch.setattr(
            D,
            "_execute_dynamic_verifier_launch",
            deterministic_no_provider_execute,
        )
        runtime_patch.setattr(
            sys.modules["plamen_validators"],
            "_validate_poc_contract_for_rows",
            lambda *_a, **_k: [],
        )
        assert D._run_dynamic_verifier_unit(
            phase, sp, config, roster, units[0]
        ) == []
    assert D._verifier_completion_authority_issues(
        sp, units[0].ordered_work_item_ids[0], min_bytes=1
    ) == []


def _legacy_authenticated_r10_report_prework_fixture(
    V,
    D,
    sp: Path,
    config: dict,
    phase,
    tmp_path: Path,
    monkeypatch,
    *,
    fired: bool,
    backend: str,
    suppress_candidate_inputs: bool,
):
    """Retain the bounded unit-fixture seam for non-integration callers."""

    if suppress_candidate_inputs:
        monkeypatch.setattr(
            D, "_report_candidate_input_paths", lambda *_args, **_kwargs: ()
        )
    (sp / "dedup_decisions.md").write_text(
        "# Dedup Decisions\n", encoding="utf-8"
    )
    from artifact_ledger import record_work_unit_artifacts, record_work_unit_inputs
    from phase_io_contracts import ArtifactSpec, LaunchSpec, PhaseIOContract

    source_names = tuple(sorted(
        path.name
        for path in sp.iterdir()
        if path.is_file()
        and path.name in {
            "verification_queue.md",
            "verification_queue.json",
            "verification_queue.work_items.json",
            "findings_inventory.md",
            "finding_mapping.md",
            "hypotheses.md",
            "chain_grouping_relations.json",
            "chain_anti_absorption_applied_receipt.json",
            "chain_grouping_debt.md",
            "chain_grouping_assurance_reconciliation.json",
            "chain_grouping_assurance_limitations.md",
            "external_dependency_research.md",
            "verify_H-993.md",
        }
    ))
    producer_key = f"sc/core/evm/{backend}/verify/r10_report_fixture_sources"
    producer = PhaseIOContract(
        pipeline="sc",
        mode="core",
        ecosystem="evm",
        backend=backend,
        phase="verify",
        work_unit_id="r10_report_fixture_sources",
        outputs=tuple(
            ArtifactSpec(
                root="scratchpad",
                path=name,
                owner_key=producer_key,
                artifact_class="REQUIRED",
                writer="MODEL",
                write_mode="REPLACE",
                schema_version="unstructured.v1",
            )
            for name in source_names
        ),
        immutable_inputs=(),
        model_invoked=True,
    )
    producer_launch = LaunchSpec(
        work_unit_key=producer.key,
        pipeline="sc",
        mode="core",
        ecosystem="evm",
        backend=backend,
        model="fixture-model",
        timeout_s=30,
        exec_mode="pty",
    )
    source_bytes = {name: (sp / name).read_bytes() for name in source_names}
    for name in source_names:
        (sp / name).unlink()
    record_work_unit_inputs(
        sp, tmp_path, producer, producer_launch, run_id=config["_run_id"]
    )
    for name in sorted(
        source_names,
        key=lambda value: (value != "verification_queue.md", value),
    ):
        (sp / name).write_bytes(source_bytes[name])
    record_work_unit_artifacts(
        sp,
        tmp_path,
        producer,
        producer_launch,
        run_id=config["_run_id"],
        actor="MODEL",
    )
    semantic_projection = None
    if fired:
        original_authority = V._r10_semantic_input_authority
        inventory_text = (sp / "findings_inventory.md").read_text(
            encoding="utf-8", errors="strict"
        )
        monkeypatch.setattr(
            V,
            "_authoritative_postcutover_inventory",
            lambda _root: (inventory_text, "findings_inventory.md", []),
        )

        def unit_authenticated_authority(root, rows):
            payload = original_authority(root, rows)
            candidates = []
            for row in payload["candidates"]:
                candidate = dict(row)
                candidate["verifier_authority_issues"] = []
                candidates.append(candidate)
            payload["candidates"] = candidates
            payload["candidate_digest"] = hashlib.sha256(
                V._canonical_validator_json_bytes({"candidates": candidates})
            ).hexdigest()
            payload["issues"] = []
            payload["producer_bound_paths"] = sorted(
                set(payload["producer_bound_paths"]) & set(source_names)
            )
            payload["run_id"] = config["_run_id"]
            payload["status"] = "AUTHENTICATED_CURRENT"
            payload["strict"] = True
            return payload

        unit_authenticated_authority = _frozen_fixture_projection(
            unit_authenticated_authority,
            sp,
            V.parse_verification_queue_rows(sp),
            source_paths=source_names,
            context=lambda: {
                "run_id": config["_run_id"],
                "mode": config["mode"],
            },
        )
        semantic_projection = unit_authenticated_authority
        monkeypatch.setattr(
            V, "_r10_semantic_input_authority", unit_authenticated_authority
        )
        monkeypatch.setattr(
            D, "_r10_semantic_input_authority", unit_authenticated_authority
        )

    compute, _issues = D._write_and_record_r10_phase_io(
        scratchpad=sp, config=config, phase=phase
    )
    assert compute["outcome"] == ("FIRED" if fired else "CLEAN_ZERO")
    contract, launch = D._report_index_prework_contract_and_launch(sp, config)
    known_r10_paths = tuple(
        name
        for name in D._R10_REPORT_PREWORK_ROSTER
        if f"scratchpad:{name}" in contract.immutable_inputs
    )
    _install_bounded_r10_prework_replay_cache(
        D,
        monkeypatch,
        sp,
        expected_run_id=config["_run_id"],
        expected_mode=config["mode"],
        known_paths=known_r10_paths,
        semantic_source_paths=source_names,
        semantic_projection=semantic_projection,
    )
    _install_bounded_phaseio_validation_cache(
        D,
        monkeypatch,
        sp,
        tmp_path,
    )
    return V, D, sp, config, contract, launch


def _authenticated_r10_report_prework_fixture(
    tmp_path: Path,
    monkeypatch,
    *,
    fired: bool,
    backend: str = "claude",
    suppress_candidate_inputs: bool = True,
    split_parent_linkage: bool = False,
    use_runtime_caches: bool = True,
    live_t9: bool = False,
):
    V, D, sp, config, phase = _r10_driver_fixture(
        tmp_path, backend=backend
    )
    candidate_id = "H-993"
    if split_parent_linkage:
        assert fired is True
        candidate_id = "H-22"
        _seed_r10_split_parent_sources(
            V, sp, tmp_path, run_id=config["_run_id"]
        )
    else:
        return _legacy_authenticated_r10_report_prework_fixture(
            V,
            D,
            sp,
            config,
            phase,
            tmp_path,
            monkeypatch,
            fired=fired,
            backend=backend,
            suppress_candidate_inputs=suppress_candidate_inputs,
    )
    config["scratchpad"] = str(sp)
    config["claude_exec_mode"] = "headless"
    if suppress_candidate_inputs:
        monkeypatch.setattr(
            D, "_report_candidate_input_paths", lambda *_args, **_kwargs: ()
        )
    (sp / "dedup_decisions.md").write_text(
        "# Dedup Decisions\n", encoding="utf-8"
    )
    verify_bytes = (sp / f"verify_{candidate_id}.md").read_bytes()
    inventory_text = (sp / "findings_inventory.md").read_text(
        encoding="utf-8", errors="strict"
    )
    inventory_text = re.sub(
        r"(?m)^(### Finding \[INV-(\d+)\]:[^\r\n]*\r?\n)",
        lambda match: (
            match.group(1)
            + f"\n**Source IDs**: DST-{match.group(2)}\n"
            + "\n**Primary Artifact**: depth_state_trace_findings.md\n"
        ),
        inventory_text,
    )
    depth_inventory_text = inventory_text
    if live_t9:
        # The legacy split-parent fixture predates the live queue's closed
        # identity denominator.  Its mapping legitimately materializes two
        # group identities and its verifier targets their retained parent;
        # make those three identities explicit inventory candidates so T2/T6
        # can conserve them rather than synthesizing identities downstream.
        for live_id in ("GRP-022A", "GRP-022B", "H-22"):
            inventory_text += (
                f"### Finding [{live_id}]: split-parent queue identity\n\n"
                "**Severity**: High\n\n"
                "**Verdict**: CONFIRMED\n\n"
                "**Location**: `src/lib.rs:L42`\n\n"
                "**Primary Artifact**: findings_inventory.md\n\n"
                "**Description**: Explicit current-run queue denominator "
                "identity for the split-parent fixture.\n\n"
            )
    (sp / "findings_inventory.md").write_text(
        inventory_text, encoding="utf-8"
    )
    (sp / "depth_state_trace_findings.md").write_text(
        re.sub(
            r"(?m)^(### Finding \[)INV-(\d+)(\]:)",
            r"\1DST-\2\3",
            depth_inventory_text,
        ),
        encoding="utf-8",
    )
    D._write_finding_records_from_inventory(sp)
    assert (sp / "finding_records.json").is_file()

    # Give the upstream semantic sources real current-run ancestry. The queue
    # is subsequently published by its production routing transaction, while
    # the inventory pair feeds the production frozen successor. Verifier bytes
    # are deliberately omitted because the dynamic MODEL unit owns them below.
    from artifact_ledger import record_work_unit_artifacts, record_work_unit_inputs
    from phase_io_contracts import ArtifactSpec, LaunchSpec, PhaseIOContract

    # The production chain model publishes one atomic trio.  Keep that exact
    # producer shape here so the live preverify projection can authenticate the
    # hypothesis/mapping pair without granting a fixture-only owner exception.
    (sp / "enabler_results.md").write_text(
        "# Enabler Results\n", encoding="utf-8"
    )
    chain_model_names = (
        "enabler_results.md",
        "finding_mapping.md",
        "hypotheses.md",
    )
    source_names = tuple(sorted(
        path.name
        for path in sp.iterdir()
        if path.is_file()
        and path.name in {
            "depth_state_trace_findings.md",
            "chain_grouping_relations.json",
            "chain_anti_absorption_applied_receipt.json",
            "chain_grouping_debt.md",
            "chain_grouping_assurance_reconciliation.json",
            "chain_grouping_assurance_limitations.md",
            "external_dependency_research.md",
        }
    ))
    inventory_pair = ("findings_inventory.md", "finding_records.json")
    inventory_bytes = {
        name: (sp / name).read_bytes() for name in inventory_pair
    }
    inventory_key = f"sc/core/evm/{backend}/inventory/r10_report_fixture_pair"
    inventory_contract = PhaseIOContract(
        pipeline="sc",
        mode="core",
        ecosystem="evm",
        backend=backend,
        phase="inventory",
        work_unit_id="r10_report_fixture_pair",
        outputs=tuple(
            ArtifactSpec(
                root="scratchpad",
                path=name,
                owner_key=inventory_key,
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                write_mode="CREATE",
                schema_version="plamen.fixture_upstream.v1",
                minimum_gate="FIXTURE_EXACT_BYTES",
            )
            for name in inventory_pair
        ),
        immutable_inputs=(),
        model_invoked=False,
    )
    inventory_launch = LaunchSpec(
        work_unit_key=inventory_contract.key,
        pipeline="sc",
        mode="core",
        ecosystem="evm",
        backend=backend,
        model="fixture-driver",
        timeout_s=30,
        exec_mode="python",
    )
    for name in inventory_pair:
        (sp / name).unlink()
    record_work_unit_inputs(
        sp,
        tmp_path,
        inventory_contract,
        inventory_launch,
        run_id=config["_run_id"],
    )
    for name, raw in inventory_bytes.items():
        (sp / name).write_bytes(raw)
    record_work_unit_artifacts(
        sp,
        tmp_path,
        inventory_contract,
        inventory_launch,
        run_id=config["_run_id"],
        actor="DRIVER",
    )
    chain_model_key = f"sc/core/evm/{backend}/chain/model"
    chain_model_contract = PhaseIOContract(
        pipeline="sc",
        mode="core",
        ecosystem="evm",
        backend=backend,
        phase="chain",
        work_unit_id="model",
        outputs=tuple(
            ArtifactSpec(
                root="scratchpad",
                path=name,
                owner_key=chain_model_key,
                artifact_class="REQUIRED",
                writer="MODEL",
                write_mode="CREATE",
                schema_version="fixture.chain-canonical-pair.v1",
                minimum_gate="ATOMIC_HYPOTHESIS_MAPPING_PAIR",
                consumers=(
                    "sc_verify_queue/prearm_presence_authority",
                    "sc_verify_queue/t0.live_upstream_authority",
                ),
            )
            for name in chain_model_names
        ),
        immutable_inputs=(),
        bounded_lookup_inputs=(),
        model_invoked=True,
    )
    chain_model_launch = LaunchSpec(
        work_unit_key=chain_model_contract.key,
        pipeline="sc",
        mode="core",
        ecosystem="evm",
        backend=backend,
        model="fixture-model",
        timeout_s=30,
        exec_mode="pty",
        tool_policy=("filesystem",),
    )
    chain_model_bytes = {
        name: (sp / name).read_bytes() for name in chain_model_names
    }
    for name in chain_model_names:
        (sp / name).unlink()
    record_work_unit_inputs(
        sp,
        tmp_path,
        chain_model_contract,
        chain_model_launch,
        run_id=config["_run_id"],
    )
    for name, raw in chain_model_bytes.items():
        (sp / name).write_bytes(raw)
    record_work_unit_artifacts(
        sp,
        tmp_path,
        chain_model_contract,
        chain_model_launch,
        run_id=config["_run_id"],
        actor="MODEL",
    )
    producer_key = (
        f"sc/core/evm/{backend}/verify/r10_report_fixture_sources"
    )
    producer = PhaseIOContract(
        pipeline="sc",
        mode="core",
        ecosystem="evm",
        backend=backend,
        phase="verify",
        work_unit_id="r10_report_fixture_sources",
        outputs=tuple(
            ArtifactSpec(
                root="scratchpad",
                path=name,
                owner_key=producer_key,
                artifact_class="REQUIRED",
                writer="MODEL",
                write_mode="REPLACE",
                schema_version="unstructured.v1",
            )
            for name in source_names
        ),
        immutable_inputs=(),
        model_invoked=True,
    )
    producer_launch = LaunchSpec(
        work_unit_key=producer.key,
        pipeline="sc",
        mode="core",
        ecosystem="evm",
        backend=backend,
        model="fixture-model",
        timeout_s=30,
        exec_mode="pty",
    )
    source_bytes = {name: (sp / name).read_bytes() for name in source_names}
    for name in source_names:
        (sp / name).unlink()
    record_work_unit_inputs(
        sp, tmp_path, producer, producer_launch, run_id=config["_run_id"]
    )
    # The queue JSON is a freshness-checked projection of the Markdown. Restore
    # the source first and its sidecars afterward so equal-content PhaseIO
    # replay cannot intermittently look stale on a high-resolution filesystem.
    restore_order = sorted(
        source_names,
        key=lambda name: (name != "verification_queue.md", name),
    )
    for name in restore_order:
        (sp / name).write_bytes(source_bytes[name])
    record_work_unit_artifacts(
        sp,
        tmp_path,
        producer,
        producer_launch,
        run_id=config["_run_id"],
        actor="MODEL",
    )
    if use_runtime_caches:
        _install_bounded_lexical_chain_cache(monkeypatch, tmp_path)
        _install_bounded_phaseio_validation_cache(
            D,
            monkeypatch,
            sp,
            tmp_path,
        )
        _install_bounded_artifact_observation_cache(monkeypatch, sp)
    _bind_current_r10_queue_authority(
        D, sp, config, live_t9=live_t9
    )
    (sp / f"verify_{candidate_id}.md").unlink(missing_ok=True)
    for suffix in (
        ".identity.json",
        ".receipt.json",
        ".severity_proposal.json",
        ".operator_application.json",
        ".operator_receipt.json",
    ):
        (sp / f"verify_{candidate_id}{suffix}").unlink(missing_ok=True)
    _run_current_r10_verifier(
        D,
        sp,
        config,
        monkeypatch,
        verify_bytes=verify_bytes,
    )

    compute, r10_issues = D._write_and_record_r10_phase_io(
        scratchpad=sp, config=config, phase=phase
    )
    assert r10_issues == []
    assert compute["outcome"] == ("FIRED" if fired else "CLEAN_ZERO")
    strict_semantic_authority = V._r10_semantic_input_authority
    if use_runtime_caches:
        strict_semantic_authority = _frozen_fixture_projection(
            strict_semantic_authority,
            sp,
            V.parse_verification_queue_rows(sp),
            source_paths=(
                *source_names,
                *chain_model_names,
                *inventory_pair,
                "verification_queue.md",
                f"verify_{candidate_id}.md",
            ),
            context=lambda: {
                "run_id": config["_run_id"],
                "mode": config["mode"],
            },
        )
        monkeypatch.setattr(
            V, "_r10_semantic_input_authority", strict_semantic_authority
        )
        monkeypatch.setattr(
            D, "_r10_semantic_input_authority", strict_semantic_authority
        )
    contract, launch = D._report_index_prework_contract_and_launch(sp, config)
    known_r10_paths = tuple(
        name
        for name in D._R10_REPORT_PREWORK_ROSTER
        if f"scratchpad:{name}" in contract.immutable_inputs
    )
    if use_runtime_caches:
        _install_bounded_r10_prework_replay_cache(
            D,
            monkeypatch,
            sp,
            expected_run_id=config["_run_id"],
            expected_mode=config["mode"],
            known_paths=known_r10_paths,
            semantic_source_paths=(
                *source_names,
                *chain_model_names,
                *inventory_pair,
                "verification_queue.md",
                f"verify_{candidate_id}.md",
            ),
            semantic_projection=strict_semantic_authority,
        )
    return V, D, sp, config, contract, launch


def _materialize_and_commit_report_prework(D, sp: Path, config: dict) -> None:
    ready, issues = D._run_report_index_prework_transaction(sp, config)
    assert ready is True
    assert issues == []


def test_report_consumers_reject_mode_drift_after_authenticated_r10_fire(
    tmp_path, monkeypatch
):
    V, D, sp, config, _contract, _launch = (
        _authenticated_r10_report_prework_fixture(
            tmp_path, monkeypatch, fired=True
        )
    )
    execute, issues = D._arm_report_index_prework_artifacts(sp, config)
    assert execute is True
    assert issues == []

    config["mode"] = "light"
    execute, issues = D._arm_report_index_prework_artifacts(sp, config)
    assert execute is False
    assert issues
    assert V._expected_report_index_severities(
        sp,
        expected_run_id=config["_run_id"],
        expected_mode=config["mode"],
    )["H-993"] != "High"
    assert D._r10_report_consumer_ready_issues(sp, config)
    assert not (sp / "severity_binding.md").exists()


def test_report_consumers_reject_different_run_r10_authority(
    tmp_path, monkeypatch
):
    V, D, sp, config, _contract, _launch = (
        _authenticated_r10_report_prework_fixture(
            tmp_path, monkeypatch, fired=True
        )
    )
    config["_run_id"] = "run-r10-different"

    assert V._expected_report_index_severities(
        sp,
        expected_run_id=config["_run_id"],
        expected_mode=config["mode"],
    )["H-993"] != "High"
    ready, issues = D._run_report_index_prework_transaction(sp, config)
    assert ready is False
    assert issues
    assert not (sp / "severity_binding.md").exists()


def test_report_prework_current_commit_resumes_without_rewriting_outputs(
    tmp_path, monkeypatch
):
    _V, D, sp, config, _contract, _launch = (
        _authenticated_r10_report_prework_fixture(
            tmp_path, monkeypatch, fired=True
        )
    )
    _materialize_and_commit_report_prework(D, sp, config)
    before = {
        name: (sp / name).read_bytes()
        for name in (
            "severity_binding.md",
            "status_binding.md",
            "report_index_coverage_seed.md",
            "candidate_semantic_facets.md",
            "candidate_semantic_facets.json",
        )
    }

    ready, issues = D._run_report_index_prework_transaction(sp, config)

    assert ready is True
    assert issues == []
    assert D._r10_report_consumer_ready_issues(sp, config) == []
    assert {
        name: (sp / name).read_bytes() for name in before
    } == before


@pytest.mark.parametrize(
    ("relative", "operation"),
    [
        ("external_assumption_undemotion_compute.json", "mutate"),
        ("external_assumption_undemotion_compute.json", "delete"),
        ("external_assumption_undemotions.json", "mutate"),
        ("external_assumption_undemotions.json", "delete"),
        ("external_assumption_undemotions.md", "mutate"),
        ("external_assumption_undemotions.md", "delete"),
        ("external_assumption_undemotion_debt.json", "create"),
    ],
)
def test_report_consumers_revalidate_r10_after_prework_commit(
    tmp_path, monkeypatch, relative, operation
):
    _V, D, sp, config, _contract, _launch = (
        _authenticated_r10_report_prework_fixture(
            tmp_path, monkeypatch, fired=True
        )
    )
    verifier_before = (sp / "verify_H-993.md").read_bytes()
    _materialize_and_commit_report_prework(D, sp, config)
    report_prework_before = {
        name: (sp / name).read_bytes()
        for name in (
            "severity_binding.md",
            "status_binding.md",
            "report_index_coverage_seed.md",
            "candidate_semantic_facets.md",
            "candidate_semantic_facets.json",
        )
    }

    path = sp / relative
    if operation == "mutate":
        path.write_bytes(path.read_bytes() + b"\nlate mutation\n")
    elif operation == "delete":
        path.unlink()
    else:
        path.write_text("{}\n", encoding="utf-8")

    assert D._r10_report_consumer_ready_issues(sp, config)
    report_phase = next(
        item for item in D.SC_PHASES if item.name == "report_index"
    )
    with pytest.raises(D.ArtifactLedgerError, match="R10 consumer"):
        D._typed_model_phase_contract_and_launch(report_phase, sp, config)
    with pytest.raises(D.ArtifactLedgerError, match="R10 consumer"):
        D._report_index_mechanical_contract_and_launch(sp, config)
    with pytest.raises(D.ArtifactLedgerError, match="R10 consumer"):
        D._report_index_canonical_contract_and_launch(sp, config)
    assert (sp / "verify_H-993.md").read_bytes() == verifier_before
    assert {
        name: (sp / name).read_bytes() for name in report_prework_before
    } == report_prework_before


@pytest.mark.parametrize(
    ("field", "value"),
    [("mode", "light"), ("_run_id", "run-r10-after-commit")],
)
def test_report_consumers_reject_context_change_after_prework_commit(
    tmp_path, monkeypatch, field, value
):
    _V, D, sp, config, _contract, _launch = (
        _authenticated_r10_report_prework_fixture(
            tmp_path, monkeypatch, fired=True
        )
    )
    _materialize_and_commit_report_prework(D, sp, config)
    before = {
        path.name: path.read_bytes()
        for path in sp.iterdir()
        if path.is_file() and path.name != "_artifact_state.json"
    }

    config[field] = value

    assert D._r10_report_consumer_ready_issues(sp, config)
    with pytest.raises(D.ArtifactLedgerError, match="R10 consumer"):
        D._report_index_canonical_contract_and_launch(sp, config)
    assert {
        name: (sp / name).read_bytes() for name in before
    } == before


def test_report_prework_clean_zero_cannot_inflate_severity_or_mutate_evidence(
    tmp_path, monkeypatch
):
    V, D, sp, config, _contract, _launch = (
        _authenticated_r10_report_prework_fixture(
            tmp_path, monkeypatch, fired=False
        )
    )
    verifier_before = (sp / "verify_H-993.md").read_bytes()
    r10_before = {
        name: (sp / name).read_bytes()
        for name in D._R10_REPORT_PREWORK_ROSTER
        if (sp / name).is_file()
    }

    _materialize_and_commit_report_prework(D, sp, config)

    assert V._expected_report_index_severities(
        sp,
        expected_run_id=config["_run_id"],
        expected_mode=config["mode"],
    )["H-993"] != "High"
    assert "| H-993 | High |" not in (
        sp / "severity_binding.md"
    ).read_text(encoding="utf-8", errors="strict")
    assert (sp / "verify_H-993.md").read_bytes() == verifier_before
    assert {
        name: (sp / name).read_bytes() for name in r10_before
    } == r10_before


def test_current_committed_r10_prework_unlocks_each_report_consumer_builder(
    tmp_path, monkeypatch
):
    _V, D, sp, config, prework_contract, _launch = (
        _authenticated_r10_report_prework_fixture(
            tmp_path, monkeypatch, fired=True
        )
    )
    _materialize_and_commit_report_prework(D, sp, config)
    report_phase = next(
        item for item in D.SC_PHASES if item.name == "report_index"
    )

    model, _ = D._typed_model_phase_contract_and_launch(
        report_phase, sp, config
    )
    mechanical, _ = D._report_index_mechanical_contract_and_launch(
        sp, config
    )
    canonical, _ = D._report_index_canonical_contract_and_launch(
        sp, config
    )

    assert model.key != prework_contract.key
    assert mechanical.key != prework_contract.key
    assert canonical.key != prework_contract.key
    assert D._r10_report_consumer_ready_issues(sp, config) == []


def test_fired_r10_floor_survives_off_live_severity_repair_without_replay(
    tmp_path, monkeypatch
):
    V, D, sp, config, _contract, _launch = (
        _authenticated_r10_report_prework_fixture(
            tmp_path, monkeypatch, fired=True
        )
    )
    _materialize_and_commit_report_prework(D, sp, config)
    live_projection = V._expected_report_index_severities(
        sp,
        expected_run_id=config["_run_id"],
        expected_mode=config["mode"],
    )
    assert live_projection["H-993"] == "High"

    stage = tmp_path / "off-live-stage"
    stage.mkdir()
    (stage / "report_index.md").write_text(
        "\n".join([
            "# Report Index",
            "",
            "## Master Finding Index",
            "",
            "| Report ID | Title | Severity | Location | Verification | "
            "Trust Adj. | Internal Hypothesis |",
            "|---|---|---|---|---|---|---|",
            "| L-01 | external premise | Low | src/lib.rs:L42 | "
            "CONTESTED | - | H-993 |",
            "",
        ]),
        encoding="utf-8",
    )

    def forbid_stage_r10_replay(*_args, **_kwargs):
        raise AssertionError("off-live R10 replay is forbidden")

    monkeypatch.setattr(
        V, "_expected_report_index_severities", forbid_stage_r10_replay
    )
    repairs = V._repair_report_index_severity_provenance(
        stage,
        expected_run_id=config["_run_id"],
        expected_mode=config["mode"],
        expected_severities=live_projection,
    )

    assert repairs
    assert repairs[0]["upstream_severity"] == "High"
    assert "SEVERITY_OVERRIDE(upstream=High" in (
        stage / "report_index.md"
    ).read_text(encoding="utf-8", errors="strict")
    assert not (stage / "external_assumption_undemotion_debt.json").exists()


def test_fired_r10_live_projection_survives_full_canonical_receipt_replay(
    tmp_path, monkeypatch
):
    """Every off-live canonical pass consumes one authenticated live map.

    Exercise the real non-empty Core/FIRED transaction through publication,
    crash recovery, commit, and committed-receipt replay.  Any attempt to
    recompute R10 authority from the isolated staging root is a hard fixture
    failure: the stage has copied evidence bytes, but it is not the live
    physical/CAS authority root.
    """

    V, D, sp, config, _contract, _launch = (
        _authenticated_r10_report_prework_fixture(
            tmp_path,
            monkeypatch,
            fired=True,
            backend="codex",
            suppress_candidate_inputs=False,
        )
    )
    _materialize_and_commit_report_prework(D, sp, config)
    report_phase = next(
        item for item in D.SC_PHASES if item.name == "report_index"
    )
    assert D._bind_typed_model_phase_inputs(
        report_phase, sp, config
    ) == []
    (sp / "report_index.md").write_text(
        "\n".join([
            "# Report Index",
            "",
            "## Summary Counts",
            "",
            "| Severity | Count |",
            "|---|---|",
            "| Critical | 0 |",
            "| High | 0 |",
            "| Medium | 0 |",
            "| Low | 1 |",
            "| Informational | 0 |",
            "| Total | 1 |",
            "",
            "## Master Finding Index",
            "",
            (
                "| Report ID | Title | Severity | Location | Verification | "
                "Trust Adj. | Internal Hypothesis |"
            ),
            "|---|---|---|---|---|---|---|",
            (
                "| L-01 | external premise | Low | src/lib.rs:L42 | "
                "CONTESTED | - | H-993 |"
            ),
            "",
            "## Excluded Findings",
            "",
            "| Source ID | Reason |",
            "|---|---|",
            "",
            "## Fixture Padding",
            "",
            "canonical-r10-receipt-retention " * 24,
            "",
        ]),
        encoding="utf-8",
    )
    (sp / "report_coverage.md").write_text(
        "# Report Coverage\n\n"
        "## Raw Candidate Ledger\n\n"
        "| Source Artifact | Candidate ID | Disposition |\n"
        "|---|---|---|\n"
        "| verify_H-993.md | H-993 | PROMOTED L-01 |\n\n"
        + ("canonical-r10-coverage-retention " * 24)
        + "\n",
        encoding="utf-8",
    )

    live_root = sp.resolve()
    original_driver_expected = D._expected_report_index_severities
    original_validator_expected = V._expected_report_index_severities
    original_projection = V._external_assumption_undemotion_projection

    # The focused R10 producer fixture predates the dynamic-verifier roster
    # receipt substrate.  Its verifier semantic bytes and producer ancestry
    # are real, but it deliberately does not fabricate that unrelated runtime
    # control plane.  Keep only that orthogonal denominator out of this test;
    # every canonical transform, receipt, publication, and R10 check remains
    # production code.
    monkeypatch.setattr(
        V, "_validate_report_verification_denominator", lambda *_a, **_k: []
    )

    def live_driver_expected(root, *args, **kwargs):
        assert Path(root).resolve() == live_root, (
            "off-live R10 severity recomputation is forbidden"
        )
        return original_driver_expected(root, *args, **kwargs)

    def live_validator_expected(root, *args, **kwargs):
        assert Path(root).resolve() == live_root, (
            "off-live R10 severity recomputation is forbidden"
        )
        return original_validator_expected(root, *args, **kwargs)

    def live_projection(root, *args, **kwargs):
        assert Path(root).resolve() == live_root, (
            "off-live R10 projection replay is forbidden"
        )
        return original_projection(root, *args, **kwargs)

    monkeypatch.setattr(
        D, "_expected_report_index_severities", live_driver_expected
    )
    monkeypatch.setattr(
        V, "_expected_report_index_severities", live_validator_expected
    )
    monkeypatch.setattr(
        V, "_external_assumption_undemotion_projection", live_projection
    )

    def crash_before_commit(point: str) -> None:
        if point == "before_canonical_commit":
            raise RuntimeError("fixture crash before canonical commit")

    try:
        first_issues = D._run_report_index_canonicalization_transaction(
            report_phase,
            sp,
            config,
            fault_inject=crash_before_commit,
        )
    except RuntimeError as exc:
        assert "fixture crash" in str(exc)
    else:
        pytest.fail(
            "canonical transaction did not reach the injected crash: "
            f"{first_issues}"
        )

    canonical_contract, _ = D._report_index_canonical_contract_and_launch(
        sp, config
    )
    stage = (
        D._report_index_canonical_recovery_dir(sp, canonical_contract)
        / "staged_target"
    )
    assert stage.is_dir()
    assert not (
        stage / "external_assumption_undemotion_debt.json"
    ).exists()
    for name in (
        "external_assumption_undemotion_compute.json",
        "external_assumption_undemotions.json",
        "external_assumption_undemotions.md",
    ):
        assert (stage / name).read_bytes() == (sp / name).read_bytes()

    assert D._run_report_index_canonicalization_transaction(
        report_phase, sp, config
    ) == []
    # A third invocation takes the committed-replay receipt path rather than
    # deriving a new target, and must consume the same kind of live map.
    assert D._run_report_index_canonicalization_transaction(
        report_phase, sp, config
    ) == []
    assert "SEVERITY_OVERRIDE(upstream=High" in (
        sp / "report_index.md"
    ).read_text(encoding="utf-8", errors="strict")
    assert not (sp / "external_assumption_undemotion_debt.json").exists()


def test_strict_phaseio_split_parent_source_projection(
    tmp_path, monkeypatch
):
    """R0-2b split lookup must reach the exact strict R10 authority."""

    V, D, sp, config, _contract, _launch = (
        _authenticated_r10_report_prework_fixture(
            tmp_path,
            monkeypatch,
            fired=True,
            backend="codex",
            suppress_candidate_inputs=False,
            split_parent_linkage=True,
        )
    )
    from plamen_parsers import _parse_hypothesis_constituents

    exact_union = ["INV-041", "INV-042", "INV-239", "INV-116"]
    before_overlay = _parse_hypothesis_constituents(
        sp,
        include_split_parent_aliases=True,
        include_composition_aliases=True,
        apply_chain_grouping_authority=False,
    )
    after_overlay = _parse_hypothesis_constituents(
        sp,
        include_split_parent_aliases=True,
        include_composition_aliases=True,
    )
    assert before_overlay["H-22"] == exact_union
    assert after_overlay["H-22"] == exact_union

    relation = json.loads(
        (sp / "chain_grouping_relations.json").read_text(
            encoding="utf-8", errors="strict"
        )
    )
    assert relation["groups"]
    assert all(
        group["active_identity_mode"] == "INDEPENDENT_MEMBERS"
        and group["equivalence_authority"] == "NONE"
        for group in relation["groups"]
    )

    compute = json.loads(
        (sp / "external_assumption_undemotion_compute.json").read_text(
            encoding="utf-8", errors="strict"
        )
    )
    assert compute["input_projection"][
        "proposal_hypothesis_constituents"
    ]["H-22"] == exact_union
    assert compute["fired_ids"] == ["H-22"]
    assert compute["input_projection"]["semantic_authority"]["status"] == (
        "AUTHENTICATED_CURRENT"
    )
    assert compute["input_projection"]["semantic_authority"]["run_id"] == (
        config["_run_id"]
    )
    assert compute["input_projection"]["semantic_authority"]["issues"] == []

    undemotions = json.loads(
        (sp / "external_assumption_undemotions.json").read_text(
            encoding="utf-8", errors="strict"
        )
    )
    assert undemotions["row_count"] == 1
    assert [row["finding_id"] for row in undemotions["rows"]] == ["H-22"]
    undemotion = undemotions["rows"][0]
    assert undemotion["depth_state"] == {"verdict": "CONFIRMED"}
    assert undemotion["verifier_state"] == {
        "poc_attempted": "NO",
        "severity": "Low",
        "verdict": "CONTESTED",
    }
    assert undemotion["evidence_class"] == "UNPROVEN_EXTERNAL_PREMISE"
    assert "uncited" in undemotion["basis"].casefold()


def test_strict_phaseio_split_parent_report_candidate_projection(
    tmp_path, monkeypatch
):
    """The strict report candidate projection keeps the split parent only."""

    V, _D, sp, _config, _contract, _launch = (
        _authenticated_r10_report_prework_fixture(
            tmp_path,
            monkeypatch,
            fired=True,
            backend="codex",
            suppress_candidate_inputs=False,
            split_parent_linkage=True,
        )
    )
    report_candidate_ids = [
        row["finding id"]
        for row in V._report_candidate_rows_for_validator(sp)
    ]
    assert report_candidate_ids == ["H-22"]


def test_strict_phaseio_split_parent_artifact_authority(
    tmp_path, monkeypatch
):
    """Every split-parent source and R10 output keeps exact ownership."""

    _V, _D, sp, config, _contract, _launch = (
        _authenticated_r10_report_prework_fixture(
            tmp_path,
            monkeypatch,
            fired=True,
            backend="codex",
            suppress_candidate_inputs=False,
            split_parent_linkage=True,
        )
    )
    owned_sources = {
        "verification_queue.md",
        "verification_queue.work_items.json",
        "findings_inventory.md",
        "finding_mapping.md",
        "hypotheses.md",
        "chain_grouping_relations.json",
        "chain_grouping_assurance_reconciliation.json",
        "external_dependency_research.md",
        "verify_H-22.md",
    }
    ledger = json.loads((sp / "_artifact_state.json").read_text("utf-8"))
    for name in owned_sources:
        binding = ledger["artifact_bindings"][f"scratchpad:{name}"]
        assert binding["status"] == "ACTIVE"
        assert binding["run_id"] == config["_run_id"]
    for name in (
        "preverify_inventory_successor.json",
        "finding_delivery_successor.json",
        "verification_queue.work_plan.json",
        "external_assumption_undemotion_compute.json",
        "external_assumption_undemotions.json",
        "external_assumption_undemotions.md",
    ):
        binding = ledger["artifact_bindings"][f"scratchpad:{name}"]
        assert binding["status"] == "ACTIVE"
        assert binding["run_id"] == config["_run_id"]
        assert binding["writer"] == "DRIVER"
    for name in (
        "external_assumption_undemotion_compute.json",
        "external_assumption_undemotions.json",
        "external_assumption_undemotions.md",
    ):
        assert ledger["artifact_bindings"][f"scratchpad:{name}"][
            "owner_key"
        ].endswith("/external_assumption_undemotion_reconcile")


def test_strict_phaseio_split_parent_prework_floor(tmp_path, monkeypatch):
    """The strict prework consumer retains the split-parent High floor."""

    V, D, sp, config, _contract, _launch = (
        _authenticated_r10_report_prework_fixture(
            tmp_path,
            monkeypatch,
            fired=True,
            backend="codex",
            suppress_candidate_inputs=False,
            split_parent_linkage=True,
        )
    )
    _materialize_and_commit_report_prework(D, sp, config)
    queue_severity = V.parse_verification_queue_rows(sp)[0]["severity"]
    expected = V._expected_report_index_severities(
        sp,
        expected_run_id=config["_run_id"],
        expected_mode=config["mode"],
    )
    assert expected["H-22"] == queue_severity == "High"


def _strict_phaseio_split_parent_canonical_case(
    tmp_path, monkeypatch
):
    """Prepare the exact R0-2b report predecessor for commit/replay probes."""

    V, D, sp, config, _contract, _launch = (
        _authenticated_r10_report_prework_fixture(
            tmp_path,
            monkeypatch,
            fired=True,
            backend="codex",
            suppress_candidate_inputs=False,
            split_parent_linkage=True,
        )
    )
    _materialize_and_commit_report_prework(D, sp, config)
    queue_severity = V.parse_verification_queue_rows(sp)[0]["severity"]
    report_phase = next(
        item for item in D.SC_PHASES if item.name == "report_index"
    )
    assert D._bind_typed_model_phase_inputs(report_phase, sp, config) == []
    (sp / "report_index.md").write_text(
        "\n".join([
            "# Report Index",
            "",
            "## Summary Counts",
            "",
            "| Severity | Count |",
            "|---|---|",
            "| Critical | 0 |",
            "| High | 0 |",
            "| Medium | 0 |",
            "| Low | 1 |",
            "| Informational | 0 |",
            "| Total | 1 |",
            "",
            "## Master Finding Index",
            "",
            (
                "| Report ID | Title | Severity | Location | Verification | "
                "Trust Adj. | Internal Hypothesis |"
            ),
            "|---|---|---|---|---|---|---|",
            (
                "| L-01 | split-parent external premise | Low | "
                "src/lib.rs:L42 | CONTESTED | - | H-22 |"
            ),
            "",
            "## Excluded Findings",
            "",
            "| Source ID | Reason |",
            "|---|---|",
            "",
            "## Fixture Padding",
            "",
            "strict-split-parent-r10-retention " * 24,
            "",
        ]),
        encoding="utf-8",
    )
    (sp / "report_coverage.md").write_text(
        "# Report Coverage\n\n"
        "## Raw Candidate Ledger\n\n"
        "| Source Artifact | Candidate ID | Disposition |\n"
        "|---|---|---|\n"
        "| verify_H-22.md | H-22 | PROMOTED L-01 |\n\n"
        + ("strict-split-parent-r10-coverage " * 24)
        + "\n",
        encoding="utf-8",
    )

    return V, D, sp, config, report_phase, queue_severity


def test_strict_phaseio_split_parent_canonical_commit_projection(
    tmp_path, monkeypatch
):
    """Canonical commit retains the split-parent floor and child routing."""

    V, D, sp, config, report_phase, queue_severity = (
        _strict_phaseio_split_parent_canonical_case(tmp_path, monkeypatch)
    )
    assert D._run_report_index_canonicalization_transaction(
        report_phase, sp, config
    ) == []

    report_index = (sp / "report_index.md").read_text(
        encoding="utf-8", errors="strict"
    )
    report_coverage = (sp / "report_coverage.md").read_text(
        encoding="utf-8", errors="strict"
    )
    assert "SEVERITY_OVERRIDE(upstream=High" in report_index
    assert "H-22" in report_index


def test_strict_phaseio_split_parent_canonical_master_projection(
    tmp_path, monkeypatch
):
    """Canonical commit preserves the parent and routes both child groups."""

    V, D, sp, config, report_phase, _queue_severity = (
        _strict_phaseio_split_parent_canonical_case(tmp_path, monkeypatch)
    )
    assert D._run_report_index_canonicalization_transaction(
        report_phase, sp, config
    ) == []
    report_index = (sp / "report_index.md").read_text(
        encoding="utf-8", errors="strict"
    )
    report_coverage = (sp / "report_coverage.md").read_text(
        encoding="utf-8", errors="strict"
    )
    master_rows = V._parse_master_finding_index_rows(sp)
    assert len(master_rows) == 1
    assert master_rows[0]["internal"] == "H-22"
    assert master_rows[0]["severity"] == "High"
    for child_id in ("GRP-022A", "GRP-022B"):
        assert child_id not in report_index
        child_coverage = [
            line for line in report_coverage.splitlines()
            if f"| {child_id} |" in line
        ]
        assert child_coverage
        assert all(
            "HUMAN_REVIEW_DELIVERED" in line
            and "PROMOTED" not in line
            for line in child_coverage
        )


def test_strict_phaseio_split_parent_canonical_ledger_projection(
    tmp_path, monkeypatch
):
    """Canonical commit keeps every R10 output active in the live ledger."""

    _V, D, sp, config, report_phase, _queue_severity = (
        _strict_phaseio_split_parent_canonical_case(tmp_path, monkeypatch)
    )
    assert D._run_report_index_canonicalization_transaction(
        report_phase, sp, config
    ) == []
    final_ledger = json.loads(
        (sp / "_artifact_state.json").read_text(encoding="utf-8")
    )
    for name in (
        "external_assumption_undemotion_compute.json",
        "external_assumption_undemotions.json",
        "external_assumption_undemotions.md",
    ):
        binding = final_ledger["artifact_bindings"][f"scratchpad:{name}"]
        assert binding["status"] == "ACTIVE"
        assert binding["run_id"] == config["_run_id"]


def test_strict_phaseio_split_parent_canonical_floor_projection(
    tmp_path, monkeypatch
):
    """Canonical commit retains the exact strict High severity projection."""

    V, D, sp, config, report_phase, queue_severity = (
        _strict_phaseio_split_parent_canonical_case(tmp_path, monkeypatch)
    )
    assert D._run_report_index_canonicalization_transaction(
        report_phase, sp, config
    ) == []
    assert V._expected_report_index_severities(
        sp,
        expected_run_id=config["_run_id"],
        expected_mode=config["mode"],
    )["H-22"] == queue_severity


def test_strict_phaseio_split_parent_floor_survives_canonical_report_replay(
    tmp_path, monkeypatch
):
    """The exact committed R0-2b report projection replays read-only."""

    _V, D, sp, config, report_phase, _queue_severity = (
        _strict_phaseio_split_parent_canonical_case(tmp_path, monkeypatch)
    )
    assert D._run_report_index_canonicalization_transaction(
        report_phase, sp, config
    ) == []
    assert D._run_report_index_canonicalization_transaction(
        report_phase, sp, config
    ) == []


def test_report_prework_contract_exposes_exact_r10_authority_inputs(
    tmp_path, monkeypatch
):
    _V, D, sp, config, contract, _launch = (
        _authenticated_r10_report_prework_fixture(
            tmp_path, monkeypatch, fired=True
        )
    )
    r10_inputs = {
        value.split(":", 1)[1]
        for value in contract.immutable_inputs
        if "external_assumption_undemotion" in value
    }
    assert r10_inputs == {
        "external_assumption_undemotion_compute.json",
        "external_assumption_undemotions.json",
        "external_assumption_undemotions.md",
    }
    execute, issues = D._arm_report_index_prework_artifacts(sp, config)
    assert execute is True
    assert issues == []
    ledger = json.loads((sp / "_artifact_state.json").read_text("utf-8"))
    unit = ledger["work_units"][contract.key]
    absence = unit["explicit_absence_authority"]
    assert absence["roster_identities"] == sorted(
        f"scratchpad:{name}"
        for name in D._R10_REPORT_PREWORK_ROSTER
    )
    assert absence["absent_identities"] == [
        "scratchpad:external_assumption_undemotion_debt.json"
    ]


@pytest.mark.parametrize(
    ("relative", "operation"),
    [
        ("external_assumption_undemotion_compute.json", "mutate"),
        ("external_assumption_undemotion_compute.json", "delete"),
        ("external_assumption_undemotions.json", "mutate"),
        ("external_assumption_undemotions.json", "delete"),
        ("external_assumption_undemotions.md", "mutate"),
        ("external_assumption_undemotions.md", "delete"),
        ("external_assumption_undemotion_debt.json", "create"),
    ],
)
def test_r10_change_after_report_prework_arm_fails_closed(
    tmp_path, monkeypatch, relative, operation
):
    _V, D, sp, config, contract, launch = (
        _authenticated_r10_report_prework_fixture(
            tmp_path, monkeypatch, fired=True
        )
    )
    execute, issues = D._arm_report_index_prework_artifacts(sp, config)
    assert execute is True
    assert issues == []

    path = sp / relative
    if operation == "mutate":
        path.write_bytes(path.read_bytes() + b"\nlate mutation\n")
    elif operation == "delete":
        path.unlink()
    else:
        path.write_text("{}\n", encoding="utf-8")

    replay = D.validate_work_unit_inputs(
        sp,
        tmp_path,
        contract,
        launch,
        run_id=config["_run_id"],
    )
    domain = D._r10_report_prework_authority_issues(sp, config)
    assert replay or domain


@pytest.mark.parametrize("operation", ["mutate", "delete"])
def test_r10_debt_change_after_report_prework_arm_fails_closed(
    tmp_path, monkeypatch, operation
):
    _V, D, sp, config, contract, launch = (
        _authenticated_r10_report_prework_fixture(
            tmp_path, monkeypatch, fired=False
        )
    )
    debt = sp / "external_assumption_undemotion_debt.json"
    assert debt.is_file()
    execute, issues = D._arm_report_index_prework_artifacts(sp, config)
    assert execute is True
    assert issues == []

    if operation == "mutate":
        debt.write_bytes(debt.read_bytes() + b"\nlate mutation\n")
    else:
        debt.unlink()

    replay = D.validate_work_unit_inputs(
        sp,
        tmp_path,
        contract,
        launch,
        run_id=config["_run_id"],
    )
    domain = D._r10_report_prework_authority_issues(sp, config)
    assert replay or domain


def test_r10_mode_switch_after_report_prework_arm_fails_closed(
    tmp_path, monkeypatch
):
    _V, D, sp, config, _contract, _launch = (
        _authenticated_r10_report_prework_fixture(
            tmp_path, monkeypatch, fired=True
        )
    )
    execute, issues = D._arm_report_index_prework_artifacts(sp, config)
    assert execute is True
    assert issues == []

    config["mode"] = "light"
    domain = D._r10_report_prework_authority_issues(sp, config)
    assert domain


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


# ===========================================================================
# Runtime-cache adversarial controls.  These deliberately compare each bounded
# test seam with the production validator whose answer it is allowed to reuse.
# ===========================================================================


def test_phaseio_cache_revalidates_bounded_lookup_input_bytes(
    tmp_path, monkeypatch
):
    import artifact_ledger as ledger_module
    from phase_io_contracts import LaunchSpec, PhaseIOContract

    sp = _scratch(tmp_path)
    immutable = sp / "immutable.txt"
    bounded = sp / "bounded.txt"
    immutable.write_text("immutable-0\n", encoding="utf-8")
    bounded.write_text("bound-0\n", encoding="utf-8")
    owner = "sc/core/evm/claude/verify/runtime_cache_probe"
    contract = PhaseIOContract(
        pipeline="sc",
        mode="core",
        ecosystem="evm",
        backend="claude",
        phase="verify",
        work_unit_id="runtime_cache_probe",
        outputs=(),
        immutable_inputs=("scratchpad:immutable.txt",),
        bounded_lookup_inputs=("scratchpad:bounded.txt",),
        model_invoked=False,
    )
    assert contract.key == owner
    launch = LaunchSpec(
        work_unit_key=contract.key,
        pipeline="sc",
        mode="core",
        ecosystem="evm",
        backend="claude",
        model="fixture-driver",
        timeout_s=30,
        exec_mode="python",
    )
    ledger_module.record_work_unit_inputs(
        sp, tmp_path, contract, launch, run_id="probe-run"
    )
    driver = SimpleNamespace(
        validate_work_unit_inputs=ledger_module.validate_work_unit_inputs,
        validate_work_unit_explicit_absence_bindings=(
            ledger_module.validate_work_unit_explicit_absence_bindings
        ),
        validate_work_unit_artifacts=ledger_module.validate_work_unit_artifacts,
    )
    _install_bounded_phaseio_validation_cache(
        driver, monkeypatch, sp, tmp_path
    )
    call = (sp, tmp_path, contract, launch)
    kwargs = {"run_id": "probe-run"}
    assert driver.validate_work_unit_inputs(*call, **kwargs) == []
    baseline_artifacts = driver.validate_work_unit_artifacts(
        *call, actor="DRIVER", **kwargs
    )

    bounded.write_text("bound-1\n", encoding="utf-8")
    live_inputs = ledger_module.validate_work_unit_inputs(*call, **kwargs)
    live_artifacts = ledger_module.validate_work_unit_artifacts(
        *call, actor="DRIVER", **kwargs
    )

    assert any("semantic input hash changed" in issue for issue in live_inputs)
    assert live_artifacts != baseline_artifacts
    assert driver.validate_work_unit_inputs(*call, **kwargs) == live_inputs
    assert driver.validate_work_unit_artifacts(
        *call, actor="DRIVER", **kwargs
    ) == live_artifacts


def test_phaseio_cache_revalidates_explicit_absence_directory_appearance(
    tmp_path, monkeypatch
):
    import artifact_ledger as ledger_module

    _V, D, sp, config, contract, launch = (
        _authenticated_r10_report_prework_fixture(
            tmp_path, monkeypatch, fired=True
        )
    )
    execute, issues = D._arm_report_index_prework_artifacts(sp, config)
    assert execute is True
    assert issues == []
    call = (sp, tmp_path, contract, launch)
    kwargs = {"run_id": config["_run_id"], "require": True}
    assert D.validate_work_unit_explicit_absence_bindings(
        *call, **kwargs
    ) == []
    assert ledger_module.validate_work_unit_explicit_absence_bindings(
        *call, **kwargs
    ) == []

    (sp / "external_assumption_undemotion_debt.json").mkdir()
    live = ledger_module.validate_work_unit_explicit_absence_bindings(
        *call, **kwargs
    )

    assert any("presence drift" in issue for issue in live)
    assert D.validate_work_unit_explicit_absence_bindings(
        *call, **kwargs
    ) == live


def test_r10_prework_cache_revalidates_corrupted_artifact_ledger(
    tmp_path, monkeypatch
):
    _V, D, sp, config, _contract, _launch = (
        _authenticated_r10_report_prework_fixture(
            tmp_path, monkeypatch, fired=True
        )
    )
    kwargs = {
        "expected_run_id": config["_run_id"],
        "expected_mode": config["mode"],
    }
    assert D._r10_report_prework_input_paths(sp, **kwargs)

    (sp / "_artifact_state.json").write_bytes(b"{not-json")

    with pytest.raises(ValueError, match="ledger is unavailable"):
        D._r10_report_prework_input_paths(sp, **kwargs)


def test_frozen_fixture_projection_revalidates_exact_source_bytes(tmp_path):
    sp = _scratch(tmp_path)
    source = sp / "semantic_source.txt"
    source.write_text("source-0\n", encoding="utf-8")
    rows = [{"finding id": "H-993", "severity": "High"}]
    calls = []

    def delegate(root, observed_rows):
        calls.append((Path(root), list(observed_rows)))
        return {"source": (Path(root) / source.name).read_text(encoding="utf-8")}

    replay = _frozen_fixture_projection(
        delegate,
        sp,
        rows,
        source_paths=(source.name,),
        context={"run_id": "probe-run", "mode": "core"},
    )
    assert replay(sp, rows) == {"source": "source-0\n"}

    source.write_text("source-1\n", encoding="utf-8")

    assert replay(sp, rows) == {"source": "source-1\n"}
    assert calls == [(sp, rows), (sp, rows)]


def test_lexical_cache_revalidates_same_leaf_after_ancestor_swap(
    tmp_path, monkeypatch
):
    import artifact_ledger as ledger_module

    parent = tmp_path / "parent"
    parent.mkdir()
    leaf = parent / "leaf.txt"
    leaf.write_text("same leaf\n", encoding="utf-8")
    original = ledger_module._lexical_no_follow_chain
    leaf_identity = tuple(os.lstat(leaf)[field] for field in range(3))
    parent_identity = tuple(os.lstat(parent)[field] for field in range(3))
    _install_bounded_lexical_chain_cache(monkeypatch, tmp_path)
    cached_before = ledger_module._lexical_no_follow_chain(leaf)

    displaced = tmp_path / "displaced"
    parent.rename(displaced)
    parent.mkdir()
    (displaced / leaf.name).replace(leaf)
    assert tuple(os.lstat(leaf)[field] for field in range(3)) == leaf_identity
    assert tuple(os.lstat(parent)[field] for field in range(3)) != parent_identity
    live = original(leaf)

    assert ledger_module._lexical_no_follow_chain(leaf) == live
    assert live != cached_before


def _case_rename_preserving_object(path: Path, alias_name: str) -> None:
    """Perform a Windows case-only entry rename without replacing the object."""

    intermediate = path.with_name(path.name + ".case-swap")
    alias = path.with_name(alias_name)
    path.rename(intermediate)
    intermediate.rename(alias)


def test_phaseio_cache_revalidates_bounded_input_exact_name_alias(
    tmp_path, monkeypatch
):
    import artifact_ledger as ledger_module
    from phase_io_contracts import LaunchSpec, PhaseIOContract

    sp = _scratch(tmp_path)
    bounded = sp / "bounded.txt"
    bounded.write_text("bound-0\n", encoding="utf-8")
    contract = PhaseIOContract(
        pipeline="sc",
        mode="core",
        ecosystem="evm",
        backend="claude",
        phase="verify",
        work_unit_id="runtime_exact_name_probe",
        outputs=(),
        bounded_lookup_inputs=("scratchpad:bounded.txt",),
        model_invoked=False,
    )
    launch = LaunchSpec(
        work_unit_key=contract.key,
        pipeline="sc",
        mode="core",
        ecosystem="evm",
        backend="claude",
        model="fixture-driver",
        timeout_s=30,
        exec_mode="python",
    )
    ledger_module.record_work_unit_inputs(
        sp, tmp_path, contract, launch, run_id="probe-run"
    )
    driver = SimpleNamespace(
        validate_work_unit_inputs=ledger_module.validate_work_unit_inputs,
        validate_work_unit_explicit_absence_bindings=(
            ledger_module.validate_work_unit_explicit_absence_bindings
        ),
        validate_work_unit_artifacts=ledger_module.validate_work_unit_artifacts,
    )
    _install_bounded_phaseio_validation_cache(
        driver, monkeypatch, sp, tmp_path
    )
    call = (sp, tmp_path, contract, launch)
    kwargs = {"run_id": "probe-run"}
    assert driver.validate_work_unit_inputs(*call, **kwargs) == []
    driver.validate_work_unit_artifacts(*call, actor="DRIVER", **kwargs)
    before = os.lstat(bounded)

    _case_rename_preserving_object(bounded, "BOUNDED.txt")
    after = os.lstat(bounded)
    assert (before.st_dev, before.st_ino) == (after.st_dev, after.st_ino)

    with pytest.raises(
        ledger_module.ArtifactLedgerError, match="case/NFC alias"
    ):
        ledger_module.validate_work_unit_inputs(*call, **kwargs)
    with pytest.raises(
        ledger_module.ArtifactLedgerError, match="case/NFC alias"
    ):
        driver.validate_work_unit_inputs(*call, **kwargs)
    with pytest.raises(
        ledger_module.ArtifactLedgerError, match="case/NFC alias"
    ):
        ledger_module.validate_work_unit_artifacts(
            *call, actor="DRIVER", **kwargs
        )
    with pytest.raises(
        ledger_module.ArtifactLedgerError, match="case/NFC alias"
    ):
        driver.validate_work_unit_artifacts(
            *call, actor="DRIVER", **kwargs
        )


@pytest.mark.parametrize("alias_target", ("parent", "leaf"))
def test_phaseio_cache_revalidates_explicit_absence_exact_name_alias(
    tmp_path, monkeypatch, alias_target
):
    import artifact_ledger as ledger_module
    from phase_io_contracts import LaunchSpec, PhaseIOContract

    sp = _scratch(tmp_path)
    nested = sp / "nested"
    nested.mkdir()
    optional = nested / "optional.json"
    contract = PhaseIOContract(
        pipeline="sc",
        mode="core",
        ecosystem="evm",
        backend="claude",
        phase="verify",
        work_unit_id="runtime_absence_exact_name_probe",
        outputs=(),
        model_invoked=False,
    )
    launch = LaunchSpec(
        work_unit_key=contract.key,
        pipeline="sc",
        mode="core",
        ecosystem="evm",
        backend="claude",
        model="fixture-driver",
        timeout_s=30,
        exec_mode="python",
    )
    ledger_module.record_work_unit_inputs(
        sp, tmp_path, contract, launch, run_id="probe-run"
    )
    ledger_module.record_work_unit_explicit_absence_bindings(
        sp,
        tmp_path,
        contract,
        launch,
        run_id="probe-run",
        presence_roster=("scratchpad:nested/optional.json",),
    )
    driver = SimpleNamespace(
        validate_work_unit_inputs=ledger_module.validate_work_unit_inputs,
        validate_work_unit_explicit_absence_bindings=(
            ledger_module.validate_work_unit_explicit_absence_bindings
        ),
        validate_work_unit_artifacts=ledger_module.validate_work_unit_artifacts,
    )
    _install_bounded_phaseio_validation_cache(
        driver, monkeypatch, sp, tmp_path
    )
    call = (sp, tmp_path, contract, launch)
    kwargs = {"run_id": "probe-run", "require": True}
    if alias_target == "leaf":
        optional.write_text("appeared\n", encoding="utf-8")
        baseline = driver.validate_work_unit_explicit_absence_bindings(
            *call, **kwargs
        )
        assert any("presence drift" in issue for issue in baseline)
        _case_rename_preserving_object(optional, "OPTIONAL.json")
    else:
        assert driver.validate_work_unit_explicit_absence_bindings(
            *call, **kwargs
        ) == []
        _case_rename_preserving_object(nested, "NESTED")

    live = ledger_module.validate_work_unit_explicit_absence_bindings(
        *call, **kwargs
    )

    assert any("case/NFC alias" in issue for issue in live)
    assert driver.validate_work_unit_explicit_absence_bindings(
        *call, **kwargs
    ) == live


def test_r10_prework_cache_revalidates_ledger_exact_name_alias(
    tmp_path, monkeypatch
):
    import artifact_ledger as ledger_module

    _V, D, sp, config, _contract, _launch = (
        _authenticated_r10_report_prework_fixture(
            tmp_path, monkeypatch, fired=True
        )
    )
    kwargs = {
        "expected_run_id": config["_run_id"],
        "expected_mode": config["mode"],
    }
    assert D._r10_report_prework_input_paths(sp, **kwargs)
    ledger = sp / "_artifact_state.json"

    _case_rename_preserving_object(ledger, "_ARTIFACT_STATE.json")

    with pytest.raises(ValueError, match="ledger is unavailable"):
        D._r10_report_prework_input_paths(sp, **kwargs)
    with pytest.raises(
        ledger_module.ArtifactLedgerError, match="case/NFC alias"
    ):
        ledger_module.read_artifact_ledger(sp)


def test_frozen_fixture_projection_revalidates_source_exact_name_alias(
    tmp_path,
):
    import artifact_ledger as ledger_module

    sp = _scratch(tmp_path)
    source = sp / "source.txt"
    source.write_text("source-0\n", encoding="utf-8")
    rows = [{"finding id": "H-993", "severity": "High"}]

    def delegate(root, _rows):
        candidate = Path(root) / source.name
        ledger_module._lexical_no_follow_chain(candidate)
        return candidate.read_text(encoding="utf-8")

    replay = _frozen_fixture_projection(
        delegate, sp, rows, source_paths=(source.name,)
    )
    assert replay(sp, rows) == "source-0\n"

    _case_rename_preserving_object(source, "SOURCE.txt")

    with pytest.raises(
        ledger_module.ArtifactLedgerError, match="case/NFC alias"
    ):
        delegate(sp, rows)
    with pytest.raises(
        ledger_module.ArtifactLedgerError, match="case/NFC alias"
    ):
        replay(sp, rows)


def test_phaseio_and_frozen_caches_revalidate_non_immediate_reparse_ancestor(
    tmp_path, monkeypatch
):
    import artifact_ledger as ledger_module
    from phase_io_contracts import LaunchSpec, PhaseIOContract

    sp = _scratch(tmp_path)
    ancestor = sp / "a"
    parent = ancestor / "b"
    parent.mkdir(parents=True)
    source = parent / "source.txt"
    source.write_text("source-0\n", encoding="utf-8")
    contract = PhaseIOContract(
        pipeline="sc",
        mode="core",
        ecosystem="evm",
        backend="claude",
        phase="verify",
        work_unit_id="runtime_ancestor_reparse_probe",
        outputs=(),
        bounded_lookup_inputs=("scratchpad:a/b/source.txt",),
        model_invoked=False,
    )
    launch = LaunchSpec(
        work_unit_key=contract.key,
        pipeline="sc",
        mode="core",
        ecosystem="evm",
        backend="claude",
        model="fixture-driver",
        timeout_s=30,
        exec_mode="python",
    )
    ledger_module.record_work_unit_inputs(
        sp, tmp_path, contract, launch, run_id="probe-run"
    )
    ledger_module.record_work_unit_explicit_absence_bindings(
        sp,
        tmp_path,
        contract,
        launch,
        run_id="probe-run",
        presence_roster=("scratchpad:a/b/optional.json",),
    )
    driver = SimpleNamespace(
        validate_work_unit_inputs=ledger_module.validate_work_unit_inputs,
        validate_work_unit_explicit_absence_bindings=(
            ledger_module.validate_work_unit_explicit_absence_bindings
        ),
        validate_work_unit_artifacts=ledger_module.validate_work_unit_artifacts,
    )
    _install_bounded_phaseio_validation_cache(
        driver, monkeypatch, sp, tmp_path
    )
    call = (sp, tmp_path, contract, launch)
    run_kwargs = {"run_id": "probe-run"}
    assert driver.validate_work_unit_inputs(*call, **run_kwargs) == []
    driver.validate_work_unit_artifacts(
        *call, actor="DRIVER", **run_kwargs
    )
    assert driver.validate_work_unit_explicit_absence_bindings(
        *call, require=True, **run_kwargs
    ) == []
    rows = [{"finding id": "H-993", "severity": "High"}]

    def delegate(root, _rows):
        candidate = Path(root) / "a" / "b" / "source.txt"
        ledger_module._lexical_no_follow_chain(candidate)
        return candidate.read_text(encoding="utf-8")

    replay = _frozen_fixture_projection(
        delegate, sp, rows, source_paths=("a/b/source.txt",)
    )
    assert replay(sp, rows) == "source-0\n"
    target = sp / "a-target"
    ancestor.rename(target)
    os.symlink(target, ancestor, target_is_directory=True)

    with pytest.raises(
        ledger_module.ArtifactLedgerError, match="symlink/reparse component"
    ):
        ledger_module.validate_work_unit_inputs(*call, **run_kwargs)
    with pytest.raises(
        ledger_module.ArtifactLedgerError, match="symlink/reparse component"
    ):
        driver.validate_work_unit_inputs(*call, **run_kwargs)
    with pytest.raises(
        ledger_module.ArtifactLedgerError, match="symlink/reparse component"
    ):
        driver.validate_work_unit_artifacts(
            *call, actor="DRIVER", **run_kwargs
        )
    live_absence = ledger_module.validate_work_unit_explicit_absence_bindings(
        *call, require=True, **run_kwargs
    )
    assert any("symlink/reparse component" in issue for issue in live_absence)
    assert driver.validate_work_unit_explicit_absence_bindings(
        *call, require=True, **run_kwargs
    ) == live_absence
    with pytest.raises(
        ledger_module.ArtifactLedgerError, match="symlink/reparse component"
    ):
        delegate(sp, rows)
    with pytest.raises(
        ledger_module.ArtifactLedgerError, match="symlink/reparse component"
    ):
        replay(sp, rows)


def _case_rename_with_parent_times_restored(
    path: Path, alias_name: str
) -> tuple[Path, tuple[int, ...]]:
    """Case-rename one entry while restoring its parent's stat witness."""

    parent = path.parent
    parent_metadata = os.lstat(parent)
    parent_state = _fixture_metadata_state(parent_metadata)
    _case_rename_preserving_object(path, alias_name)
    os.utime(
        parent,
        ns=(parent_metadata.st_atime_ns, parent_metadata.st_mtime_ns),
    )
    assert _fixture_metadata_state(os.lstat(parent)) == parent_state
    return path.with_name(alias_name), parent_state


@pytest.mark.parametrize(
    "rename_level", ("outer", "intermediate", "parent", "leaf")
)
def test_all_fixture_caches_revalidate_restored_timestamp_case_alias(
    tmp_path, monkeypatch, rename_level
):
    import artifact_ledger as ledger_module
    from phase_io_contracts import LaunchSpec, PhaseIOContract

    sp = _scratch(tmp_path)
    outer = sp / "scope"
    intermediate = outer / "a"
    parent = intermediate / "b"
    parent.mkdir(parents=True)
    source = parent / "source.txt"
    source.write_text("same\n", encoding="utf-8")
    source_bytes = source.read_bytes()
    optional = parent / "optional.json"
    contract = PhaseIOContract(
        pipeline="sc",
        mode="core",
        ecosystem="evm",
        backend="claude",
        phase="verify",
        work_unit_id="runtime_restored_timestamp_alias_probe",
        outputs=(),
        bounded_lookup_inputs=("scratchpad:scope/a/b/source.txt",),
        model_invoked=False,
    )
    launch = LaunchSpec(
        work_unit_key=contract.key,
        pipeline="sc",
        mode="core",
        ecosystem="evm",
        backend="claude",
        model="fixture-driver",
        timeout_s=30,
        exec_mode="python",
    )
    ledger_module.record_work_unit_inputs(
        sp, tmp_path, contract, launch, run_id="probe-run"
    )
    ledger_module.record_work_unit_explicit_absence_bindings(
        sp,
        tmp_path,
        contract,
        launch,
        run_id="probe-run",
        presence_roster=("scratchpad:scope/a/b/optional.json",),
    )
    optional.write_text("appeared\n", encoding="utf-8")
    driver = SimpleNamespace(
        validate_work_unit_inputs=ledger_module.validate_work_unit_inputs,
        validate_work_unit_explicit_absence_bindings=(
            ledger_module.validate_work_unit_explicit_absence_bindings
        ),
        validate_work_unit_artifacts=ledger_module.validate_work_unit_artifacts,
    )
    _install_bounded_phaseio_validation_cache(
        driver, monkeypatch, sp, tmp_path
    )
    call = (sp, tmp_path, contract, launch)
    run_kwargs = {"run_id": "probe-run"}
    input_baseline = driver.validate_work_unit_inputs(*call, **run_kwargs)
    assert any("presence drift" in issue for issue in input_baseline)
    artifact_baseline = driver.validate_work_unit_artifacts(
        *call, actor="DRIVER", **run_kwargs
    )
    absence_baseline = driver.validate_work_unit_explicit_absence_bindings(
        *call, require=True, **run_kwargs
    )
    assert any("presence drift" in issue for issue in absence_baseline)
    rows = [{"finding id": "H-993", "severity": "High"}]

    def delegate(root, _rows):
        candidate = Path(root) / "scope" / "a" / "b" / "source.txt"
        ledger_module._lexical_no_follow_chain(candidate)
        return candidate.read_bytes()

    replay = _frozen_fixture_projection(
        delegate, sp, rows, source_paths=("scope/a/b/source.txt",)
    )
    assert replay(sp, rows) == source_bytes
    renamed = []
    if rename_level == "outer":
        renamed.append(_case_rename_with_parent_times_restored(outer, "SCOPE"))
    elif rename_level == "intermediate":
        renamed.append(_case_rename_with_parent_times_restored(intermediate, "A"))
    elif rename_level == "parent":
        renamed.append(_case_rename_with_parent_times_restored(parent, "B"))
    else:
        renamed.append(_case_rename_with_parent_times_restored(source, "SOURCE.txt"))
        renamed.append(_case_rename_with_parent_times_restored(optional, "OPTIONAL.json"))

    with pytest.raises(
        ledger_module.ArtifactLedgerError, match="case/NFC alias"
    ):
        ledger_module.validate_work_unit_inputs(*call, **run_kwargs)
    with pytest.raises(
        ledger_module.ArtifactLedgerError, match="case/NFC alias"
    ):
        driver.validate_work_unit_inputs(*call, **run_kwargs)
    with pytest.raises(
        ledger_module.ArtifactLedgerError, match="case/NFC alias"
    ):
        ledger_module.validate_work_unit_artifacts(
            *call, actor="DRIVER", **run_kwargs
        )
    with pytest.raises(
        ledger_module.ArtifactLedgerError, match="case/NFC alias"
    ):
        driver.validate_work_unit_artifacts(
            *call, actor="DRIVER", **run_kwargs
        )
    live_absence = ledger_module.validate_work_unit_explicit_absence_bindings(
        *call, require=True, **run_kwargs
    )
    assert any("case/NFC alias" in issue for issue in live_absence)
    assert driver.validate_work_unit_explicit_absence_bindings(
        *call, require=True, **run_kwargs
    ) == live_absence
    with pytest.raises(
        ledger_module.ArtifactLedgerError, match="case/NFC alias"
    ):
        delegate(sp, rows)
    with pytest.raises(
        ledger_module.ArtifactLedgerError, match="case/NFC alias"
    ):
        replay(sp, rows)

    for alias, _parent_state in reversed(renamed):
        _case_rename_with_parent_times_restored(
            alias,
            {
                "SCOPE": "scope",
                "A": "a",
                "B": "b",
                "SOURCE.txt": "source.txt",
                "OPTIONAL.json": "optional.json",
            }[alias.name],
        )
    assert driver.validate_work_unit_inputs(
        *call, **run_kwargs
    ) == input_baseline
    assert driver.validate_work_unit_artifacts(
        *call, actor="DRIVER", **run_kwargs
    ) == artifact_baseline
    assert driver.validate_work_unit_explicit_absence_bindings(
        *call, require=True, **run_kwargs
    ) == absence_baseline
    assert replay(sp, rows) == source_bytes


def test_r10_prework_cache_revalidates_restored_timestamp_ledger_alias(
    tmp_path, monkeypatch
):
    _V, D, sp, config, _contract, _launch = (
        _authenticated_r10_report_prework_fixture(
            tmp_path, monkeypatch, fired=True
        )
    )
    kwargs = {
        "expected_run_id": config["_run_id"],
        "expected_mode": config["mode"],
    }
    baseline = D._r10_report_prework_input_paths(sp, **kwargs)
    ledger = sp / "_artifact_state.json"

    alias, _parent_state = _case_rename_with_parent_times_restored(
        ledger, "_ARTIFACT_STATE.json"
    )

    with pytest.raises(ValueError, match="ledger is unavailable"):
        D._r10_report_prework_input_paths(sp, **kwargs)
    _case_rename_with_parent_times_restored(alias, "_artifact_state.json")
    assert D._r10_report_prework_input_paths(sp, **kwargs) == baseline


@pytest.mark.parametrize(
    "rename_level", ("outer", "intermediate", "parent", "leaf")
)
def test_lexical_cache_revalidates_restored_timestamp_case_alias(
    tmp_path, monkeypatch, rename_level
):
    import artifact_ledger as ledger_module

    outer = tmp_path / "scope"
    intermediate = outer / "a"
    parent = intermediate / "b"
    parent.mkdir(parents=True)
    leaf = parent / "source.txt"
    leaf.write_text("same\n", encoding="utf-8")
    original = ledger_module._lexical_no_follow_chain
    _install_bounded_lexical_chain_cache(monkeypatch, tmp_path)
    baseline = ledger_module._lexical_no_follow_chain(leaf)
    targets = {
        "outer": (outer, "SCOPE"),
        "intermediate": (intermediate, "A"),
        "parent": (parent, "B"),
        "leaf": (leaf, "SOURCE.txt"),
    }
    target, alias_name = targets[rename_level]
    alias, _parent_state = _case_rename_with_parent_times_restored(
        target, alias_name
    )

    with pytest.raises(
        ledger_module.ArtifactLedgerError, match="case/NFC alias"
    ):
        original(leaf)
    with pytest.raises(
        ledger_module.ArtifactLedgerError, match="case/NFC alias"
    ):
        ledger_module._lexical_no_follow_chain(leaf)

    exact_name = {
        "SCOPE": "scope",
        "A": "a",
        "B": "b",
        "SOURCE.txt": "source.txt",
    }[alias.name]
    _case_rename_with_parent_times_restored(alias, exact_name)
    assert ledger_module._lexical_no_follow_chain(leaf) == baseline
