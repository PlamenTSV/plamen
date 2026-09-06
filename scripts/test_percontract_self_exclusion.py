"""BUG 2 / M-04 — Phase 3c per-contract belief-based self-exclusion.

A per-contract agent is GIVEN an orchestrator-built exclusion list (finding IDs
+ locations from analysis_*.md + analysis_rescan_*.md) and told "do not
re-report exclusion-list findings". Nothing constrains the PROVENANCE of an
exclusion, so an agent self-generated an "## Exclusion List (Already Found)"
section asserting a real bug was already known when NO provided finding
contained it — silently dropping a true positive.

Fix:
- PROMPT: an exclusion is valid only if it cites a concrete entry present in the
  provided exclusion list; a believed-known bug with no provided-list referent
  MUST be emitted (rules/phase3b-rescan-prompt.md + prompts/shared/v2/...).
- GATE: _validate_percontract_self_exclusion flags referent-less exclusions and
  the driver re-emits them to analysis_percontract_reemit.md (declared into
  rescan_manifest.md so the exact gate still accepts it).

Recall-safe: the validator ONLY ever adds candidates; never removes/refutes a
finding, never hard-fails a clean run.
"""

from __future__ import annotations

import sys
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS_DIR))

import plamen_driver as D  # noqa: E402
from plamen_validators import (  # noqa: E402
    _validate_percontract_self_exclusion,
    _rescan_manifest_exact_missing,
    gate_passes,
)

RESCAN = next(p for p in D.SC_PHASES if p.name == "rescan")


def _write(sp: Path, name: str, text: str) -> None:
    (sp / name).write_text(text, encoding="utf-8")


# A first-pass breadth finding the per-contract agent could legitimately cite.
PROVIDED_BREADTH = (
    "# Breadth Agent 1\n\n"
    "## Findings\n\n"
    "## Finding [B1-4]: Reentrancy in withdraw\n\n"
    "**Severity**: High\n"
    "**Location**: vault.sol:L120\n"
    "**Description**: classic reentrancy.\n"
)

RESCAN_FINDING = (
    "# Re-Scan Agent 1\n\n"
    "## Findings\n\n"
    "## Finding [RS1-3]: Stale price\n\n"
    "**Severity**: Medium\n"
    "**Location**: PayloadCodec.sol:L88\n"
    "**Description**: stale.\n"
)


# --------------------------------------------------------------------------
# (a) DROP-REPRODUCTION: referent-less self-exclusion -> flagged + re-emitted
# --------------------------------------------------------------------------

def test_drop_reproduction_referentless_exclusion_flagged_and_reemitted(tmp_path):
    _write(tmp_path, "analysis_1.md", PROVIDED_BREADTH)
    _write(tmp_path, "analysis_rescan_1.md", RESCAN_FINDING)
    # The agent invents an exclusion for a bug (isWritable byte-width) whose only
    # "referent" is an ID/location absent from analysis_*/analysis_rescan_*.
    _write(
        tmp_path,
        "analysis_percontract_3.md",
        "# Per-Contract Agent 3\n\n"
        "## Findings\n\n"
        "## Finding [PC3-1]: Some real finding\n\n"
        "**Severity**: Low\n"
        "**Location**: PayloadCodec.sol:L200\n"
        "**Description**: ok.\n\n"
        "## Exclusion List (Already Found - Not Duplicated)\n\n"
        "- EXCLUDED [PC3-9] isWritable byte-width mismatch at "
        "PayloadCodec.sol:L412 (dup of SL-1/CC-7)\n",
    )

    warnings, recovered = _validate_percontract_self_exclusion(tmp_path)
    assert warnings, "referent-less exclusion must produce a warning"
    assert recovered, "the suppressed candidate must be recovered for re-emit"

    # Driver side effect writes the re-emit artifact.
    out = D._reemit_percontract_self_exclusions(tmp_path, recovered)
    assert out is not None and out.exists()
    body = out.read_text(encoding="utf-8")
    assert "## Finding [PCRE-1]" in body
    assert "[RE-EMITTED: self-excluded without real referent]" in body
    assert "PayloadCodec.sol:L412".lower() in body.lower()
    # Declared into the manifest so the exact gate accepts it.
    manifest = (tmp_path / "rescan_manifest.md").read_text(encoding="utf-8")
    assert "analysis_percontract_reemit.md" in manifest


# --------------------------------------------------------------------------
# (b) HEALTHY NO-OP: exclusion citing a real provided ID -> no flag
# --------------------------------------------------------------------------

def test_healthy_noop_real_referent_by_id(tmp_path):
    _write(tmp_path, "analysis_1.md", PROVIDED_BREADTH)
    _write(
        tmp_path,
        "analysis_percontract_2.md",
        "# Per-Contract Agent 2\n\n"
        "## Findings\n\n"
        "## Finding [PC2-1]: real one\n\n"
        "**Severity**: Medium\n"
        "**Location**: vault.sol:L5\n"
        "**Description**: x.\n\n"
        "## Exclusion List\n\n"
        "- EXCLUDED [PC2-7] reentrancy in withdraw dup of [B1-4]\n",
    )
    warnings, recovered = _validate_percontract_self_exclusion(tmp_path)
    assert warnings == []
    assert recovered == []
    assert not (tmp_path / "analysis_percontract_reemit.md").exists()


def test_healthy_noop_real_referent_by_location(tmp_path):
    _write(tmp_path, "analysis_1.md", PROVIDED_BREADTH)
    _write(tmp_path, "analysis_rescan_1.md", RESCAN_FINDING)
    _write(
        tmp_path,
        "analysis_percontract_2.md",
        "# Per-Contract Agent 2\n\n"
        "## Findings\n\n"
        "## Exclusion List\n\n"
        "- EXCLUDED [PC2-3] stale price dup of PayloadCodec.sol:L88\n",
    )
    warnings, recovered = _validate_percontract_self_exclusion(tmp_path)
    assert warnings == []
    assert recovered == []


def test_healthy_noop_real_referent_by_location_pathprefix(tmp_path):
    # Location in universe is a/b/PayloadCodec.sol:L88; citation uses basename.
    _write(tmp_path, "analysis_1.md", PROVIDED_BREADTH)
    _write(
        tmp_path,
        "analysis_rescan_1.md",
        "# Re-Scan 1\n\n## Findings\n\n"
        "## Finding [RS1-3]: stale\n\n"
        "**Severity**: Medium\n"
        "**Location**: contracts/PayloadCodec.sol:L88\n"
        "**Description**: x.\n",
    )
    _write(
        tmp_path,
        "analysis_percontract_1.md",
        "# PC 1\n\n## Findings\n\n## Exclusion List\n\n"
        "- EXCLUDED [PC1-2] dup of PayloadCodec.sol:88\n",
    )
    warnings, recovered = _validate_percontract_self_exclusion(tmp_path)
    assert warnings == []
    assert recovered == []


# --------------------------------------------------------------------------
# (c) RECALL-SAFETY: never false-fire / never crash on a clean run
# --------------------------------------------------------------------------

def test_recall_safe_no_exclusion_section(tmp_path):
    _write(tmp_path, "analysis_1.md", PROVIDED_BREADTH)
    _write(
        tmp_path,
        "analysis_percontract_1.md",
        "# PC 1\n\n## Findings\n\n"
        "## Finding [PC1-1]: only findings here\n\n"
        "**Severity**: Low\n**Location**: vault.sol:L9\n**Description**: x.\n",
    )
    warnings, recovered = _validate_percontract_self_exclusion(tmp_path)
    assert warnings == []
    assert recovered == []
    assert not (tmp_path / "analysis_percontract_reemit.md").exists()


def test_recall_safe_no_percontract_files(tmp_path):
    _write(tmp_path, "analysis_1.md", PROVIDED_BREADTH)
    warnings, recovered = _validate_percontract_self_exclusion(tmp_path)
    assert warnings == []
    assert recovered == []


def test_recall_safe_empty_scratchpad(tmp_path):
    warnings, recovered = _validate_percontract_self_exclusion(tmp_path)
    assert (warnings, recovered) == ([], [])


def test_recall_safe_unparseable_percontract_file(tmp_path):
    # Binary / non-UTF8 content must not raise.
    (tmp_path / "analysis_percontract_1.md").write_bytes(b"\xff\xfe\x00\x01garbage")
    warnings, recovered = _validate_percontract_self_exclusion(tmp_path)
    assert isinstance(warnings, list) and isinstance(recovered, list)


def test_reemit_noop_on_empty_recovered(tmp_path):
    assert D._reemit_percontract_self_exclusions(tmp_path, []) is None
    assert not (tmp_path / "analysis_percontract_reemit.md").exists()


# --------------------------------------------------------------------------
# (mixed) only the referent-less entry is flagged; the valid one is left alone
# --------------------------------------------------------------------------

def test_mixed_only_referentless_entry_flagged(tmp_path):
    _write(tmp_path, "analysis_1.md", PROVIDED_BREADTH)
    _write(
        tmp_path,
        "analysis_percontract_4.md",
        "# PC 4\n\n## Findings\n\n## Exclusion List (Already Found)\n\n"
        "- EXCLUDED [PC4-1] reentrancy dup of [B1-4]\n"
        "- EXCLUDED [PC4-2] isWritable byte-width at Enc.sol:L9 (believed known)\n",
    )
    warnings, recovered = _validate_percontract_self_exclusion(tmp_path)
    assert len(recovered) == 1, "exactly one referent-less entry expected"
    assert "isWritable" in recovered[0]["title"] or "isWritable" in recovered[0]["line_text"]
    # The validly-excluded [B1-4] entry must NOT be re-emitted.
    joined = " ".join(c["line_text"] for c in recovered)
    assert "B1-4" not in joined


# --------------------------------------------------------------------------
# GATE-ACCEPTANCE: re-emit file + manifest declaration still passes the gate
# --------------------------------------------------------------------------

def test_gate_acceptance_after_reemit_non_fresh(tmp_path):
    # Non-fresh scratchpad (no sentinel): exact gate uses presence+size.
    sub = "Checked declared scope. " * 30
    _write(tmp_path, "analysis_rescan_1.md", "# RS1\n\n## No Findings\n\n" + sub)
    _write(
        tmp_path,
        "analysis_percontract_1.md",
        "# PC1\n\n## Findings\n\n## Exclusion List\n\n"
        "- EXCLUDED [PC1-9] isWritable at Enc.sol:L9 (believed known)\n" + sub,
    )
    (tmp_path / "rescan_manifest.md").write_text(
        "# Rescan Manifest\n- analysis_rescan_1.md\n- analysis_percontract_1.md\n",
        encoding="utf-8",
    )
    warnings, recovered = _validate_percontract_self_exclusion(tmp_path)
    assert recovered
    D._reemit_percontract_self_exclusions(tmp_path, recovered)

    # Exact gate must still pass: the driver-written re-emit file is substantive,
    # marked COMPLETE, and structurally complete (has a ## Finding block).
    missing = _rescan_manifest_exact_missing(tmp_path, RESCAN)
    assert missing == [], f"exact gate stranded on: {missing}"
    passed, gmissing = gate_passes(tmp_path, str(tmp_path), RESCAN)
    assert passed, f"gate_passes(rescan) failed: {gmissing}"


# --------------------------------------------------------------------------
# TASK E ROOT FIX (observed finding-pair flaw): content-less re-emit must NOT reach the
# Medium body — it routes to a LOW-confidence appendix disposition. A
# content-bearing re-emit keeps its severity for dedup/resolution. Both are
# KEPT (re-emitted); neither is dropped.
# --------------------------------------------------------------------------

def test_e_flaw_resolved_contentless_reemit_routes_to_appendix_not_medium(tmp_path):
    """FP/flaw-now-resolved: a content-LESS self-exclusion stub (no concrete
    location, no harm) must re-emit at Informational with an APPENDIX_ONLY
    marker — NOT default to a Medium body finding (an observed finding-pair flaw)."""
    _write(tmp_path, "analysis_1.md", PROVIDED_BREADTH)
    # Bare "already known" assertion: no concrete file:line, no mechanism/harm.
    _write(
        tmp_path,
        "analysis_percontract_1.md",
        "# PC 1\n\n## Findings\n\n## Exclusion List (Already Found)\n\n"
        "- EXCLUDED [PC1-7] some thing already known\n",
    )
    warnings, recovered = _validate_percontract_self_exclusion(tmp_path)
    assert recovered, "content-less stub must still be recovered (never dropped)"
    assert recovered[0]["content_bearing"] is False, (
        "no location + no harm → content-less"
    )

    out = D._reemit_percontract_self_exclusions(tmp_path, recovered)
    assert out is not None and out.exists()
    body = out.read_text(encoding="utf-8")
    # The flaw was: defaulted to **Severity**: Medium → reached body. Root fix
    # pins content-less stubs to Informational + APPENDIX_ONLY routing.
    assert "**Severity**: Informational" in body
    assert "**Severity**: Medium" not in body
    assert "CONTENT-LESS" in body and "APPENDIX_ONLY" in body
    # Kept, not dropped: the candidate is present for human review.
    assert "[PCRE-1]" in body


def test_e_negative_control_contentbearing_reemit_keeps_severity_for_dedup(tmp_path):
    """NEGATIVE CONTROL: a content-BEARING re-emit (own location + harm) must
    keep its own severity so it can be dedup'd against existing findings or
    resolved into a concrete finding — the fix must NOT rubber-stamp every
    re-emit to Informational/appendix."""
    _write(tmp_path, "analysis_1.md", PROVIDED_BREADTH)
    # Carries its OWN content: concrete location + mechanism/harm vocabulary.
    _write(
        tmp_path,
        "analysis_percontract_1.md",
        "# PC 1\n\n## Findings\n\n## Exclusion List (Already Found)\n\n"
        "- EXCLUDED [PC1-9] Medium reward accounting drains funds at "
        "Vault.sol:L412 — stale balance lets attacker steal rewards\n",
    )
    warnings, recovered = _validate_percontract_self_exclusion(tmp_path)
    assert recovered, "content-bearing stub must be recovered"
    assert recovered[0]["content_bearing"] is True, (
        "concrete location + harm vocabulary → content-bearing"
    )

    out = D._reemit_percontract_self_exclusions(tmp_path, recovered)
    body = out.read_text(encoding="utf-8")
    # NOT downgraded to Informational/appendix: severity preserved (Medium here)
    # so it flows through normal dedup/resolution rather than being buried.
    assert "**Severity**: Medium" in body
    assert "CONTENT-LESS" not in body
    assert "Vault.sol:L412".lower() in body.lower()


def test_e_mixed_contentless_and_contentbearing_routed_separately(tmp_path):
    """Both kinds coexist: content-less → Informational/appendix, content-bearing
    → severity preserved. Neither is dropped."""
    _write(tmp_path, "analysis_1.md", PROVIDED_BREADTH)
    _write(
        tmp_path,
        "analysis_percontract_1.md",
        "# PC 1\n\n## Findings\n\n## Exclusion List (Already Found)\n\n"
        "- EXCLUDED [PC1-1] already known nothing concrete\n"
        "- EXCLUDED [PC1-2] High overflow drains funds at Token.sol:L77 "
        "— mint inflation lets attacker steal\n",
    )
    warnings, recovered = _validate_percontract_self_exclusion(tmp_path)
    assert len(recovered) == 2
    by_id = {c["own_id"]: c for c in recovered}
    assert by_id["PC1-1"]["content_bearing"] is False
    assert by_id["PC1-2"]["content_bearing"] is True

    out = D._reemit_percontract_self_exclusions(tmp_path, recovered)
    body = out.read_text(encoding="utf-8")
    # Content-less → Informational; content-bearing without a labeled severity
    # → default Medium (NOT downgraded to Informational/appendix). Both present.
    assert "**Severity**: Informational" in body
    assert "**Severity**: Medium" in body
    assert "CONTENT-LESS" in body  # only the content-less one is marked
    assert body.count("CONTENT-LESS") <= 4  # not stamped on the content-bearing
    # Both candidates surfaced — recall preserved.
    assert "[PCRE-1]" in body and "[PCRE-2]" in body


def test_e_triage_allows_contentless_marker_for_medium_plus_exclusion():
    """report_index triage: a content-less PCRE row kept at Medium+ in Excluded
    Findings with a CONTENT_LESS reason is an allowed appendix disposition (it
    is KEPT, not dropped). A content-bearing PCRE row excluded at Medium+ with
    NO evidence/dedup reason is STILL flagged (negative control)."""
    import re
    src = (
        Path(__file__).resolve().parent / "plamen_validators.py"
    ).read_text(encoding="utf-8")
    # The allowed-token set must include the content-less marker.
    assert "CONTENT_LESS" in src

    from plamen_validators import _validate_report_index_triage_safety

    import tempfile

    with tempfile.TemporaryDirectory() as d:
        sp = Path(d)
        # A content-less PCRE excluded at Medium with CONTENT_LESS reason → allowed.
        (sp / "report_index.md").write_text(
            "# Report Index\n\n"
            "## Excluded Findings\n\n"
            "| Internal ID | Severity | Title | Exclusion Reason |\n"
            "|---|---|---|---|\n"
            "| PCRE-1 | Medium | content-less stub | APPENDIX_ONLY CONTENT_LESS no concrete location |\n",
            encoding="utf-8",
        )
        assert _validate_report_index_triage_safety(sp), (
            "CONTENT_LESS prose is not independent non-body authority"
        )

        # NEGATIVE CONTROL: a real Medium finding excluded with a non-evidence
        # "not client worthy" reason must STILL be flagged (no rubber-stamp).
        (sp / "report_index.md").write_text(
            "# Report Index\n\n"
            "## Excluded Findings\n\n"
            "| Internal ID | Severity | Title | Exclusion Reason |\n"
            "|---|---|---|---|\n"
            "| H-3 | Medium | reward drain | not client worthy |\n",
            encoding="utf-8",
        )
        issues = _validate_report_index_triage_safety(sp)
        assert issues, "non-evidence Medium+ exclusion must still be flagged"


if __name__ == "__main__":
    import pytest

    sys.exit(pytest.main([__file__, "-q"]))
