"""v2.8.17 — L1 report_index haltless-parity.

Covers the L1 report_index stage fix (plamen_driver.py ~13327-13404) and the
rescan PLAMEN_STATUS write-flush wasted-retry fix (plamen_validators.py ~1620).

The driver branch under test is `pipeline == "l1" and phase.name ==
"report_index"`. Rather than booting the full phase loop, these tests exercise
the exact validator/repair functions that branch calls and assert the
HARD-vs-SOFT partition the fix relies on:

  - HALT-1 (prewrite, mechanical verify-file parity): _validate_verify_files_for_queue
  - HALT-2 (post-write, prose severity provenance): _validate_report_index_inputs
        + _repair_report_index_severity_provenance (repair-then-revalidate)
  - HALT-3 (coverage UNACCOUNTED, mechanical): _validate_report_coverage_accounting

The fix's contract:
  1. A PROSE-only issue (severity provenance that repair cannot safely auto-fix,
     e.g. an inflation) must NOT be a hard verify-file-parity issue — so the
     driver can flag it to report_semantic_severity_repairs.md and CONTINUE.
  2. A MECHANICAL issue (missing verify file for a queued ID, or an UNACCOUNTED
     coverage row) MUST still surface as a hard issue — silent-drop protection
     is preserved.
  3. A downgrade-only provenance violation is auto-repaired so attempt 1 clears
     (no wasted retry, no flag).

Fixtures are realistic: real verification_queue.md tables, real verify_<ID>.md
files with explicit Severity/Verdict fields, real report_index.md Master Finding
Index rows, and a real report_coverage.md ledger.
"""
from __future__ import annotations

from pathlib import Path
import json

import pytest

import plamen_parsers as P

from plamen_validators import (
    _validate_verify_files_for_queue,
    _validate_report_index_inputs,
    _validate_report_coverage_accounting,
    _repair_report_index_severity_provenance,
    _rescan_manifest_exact_missing,
)
from plamen_types import L1_VERIFY_SHARD_MANIFESTS, Phase
from queue_work_items import VerifierOutputIdentity, VerifierOutputReceipt
from test_verifier_output_receipt_runtime_p0_aj import (
    LAUNCH_DIGEST,
    _proposal_bytes,
)


# --------------------------------------------------------------------------- #
# Fixture builders                                                            #
# --------------------------------------------------------------------------- #
def _write_queue(sp: Path, ids_sevs: list[tuple[str, str]]) -> None:
    rows = []
    for number, (fid, sev) in enumerate(ids_sevs, 1):
        rows.append({
            "queue #": str(number),
            "finding id": fid,
            "expected output file": f"verify_{fid}.md",
            "severity": sev,
            "title": f"Some bug in {fid}",
            "bug class": "state-transition",
            "preferred tag": "CODE-TRACE",
            "location": "src/Mod.go:100",
            "primary artifact": "findings_inventory.md",
            "poc class": "structural",
        })
    P._write_queue_subset_manifest(sp / "verification_queue.md", rows)


def _write_verify(sp: Path, fid: str, severity: str, verdict: str = "CONFIRMED") -> None:
    # No Impact/Likelihood axes -> matrix base is None -> explicit Severity
    # field is authoritative (see _enforce_severity_matrix fallback).
    body = (
        f"# Verification: {fid}\n\n"
        f"**Verdict**: {verdict}\n"
        f"**Severity**: {severity}\n"
        f"**Location**: src/Mod.go:L100-L140\n\n"
        "## Finding\n\n"
        f"Detailed analysis of {fid}: the function fails to validate its input "
        "before applying a state transition, which a caller can exploit. "
        "This block exists so the verify file is well over the 100-byte floor "
        "and parses as a substantive verification artifact for the parity gate.\n\n"
        "### PoC Attempt\n"
        "- PoC Required: NO\n"
        "- PoC Class: structural\n"
        "- Attempted: NO\n"
        "- PoC Not Attempted Because: NO_BUILD_ENVIRONMENT\n"
        "- Test File: N/A\n"
        "- Command: N/A\n\n"
        "### Execution Result\n"
        "- Compiled: N/A\n"
        "- Result: NOT_EXECUTED\n"
        "- Evidence Tag: [CODE-TRACE]\n"
    )
    output_path = sp / f"verify_{fid}.md"
    output_path.write_text(body, encoding="utf-8")

    # A plausible Markdown file is no longer verifier-completion authority.
    # Bind the fixture through the same typed queue/work-plan/output-receipt
    # contract consumed by the report denominator.  This deliberately uses the
    # pre-roster compatibility branch: these unit fixtures exercise report
    # provenance, not the dynamic worker coordinator.
    items = P._read_typed_queue_work_items(sp / "verification_queue.md")
    owner = next(iter(L1_VERIFY_SHARD_MANIFESTS))
    partitions = {name: [] for name in L1_VERIFY_SHARD_MANIFESTS}
    partitions[owner] = [
        {"finding id": item.work_item_id}
        for item in items
    ]
    plan = P._write_or_validate_queue_work_plan(sp, items, partitions, "l1")
    item = next(item for item in items if item.work_item_id == fid)
    identity = VerifierOutputIdentity.for_assignment(item, plan, owner)
    proposal_path = sp / f"verify_{fid}.severity_proposal.json"
    proposal_path.write_bytes(_proposal_bytes(item))
    receipt = VerifierOutputReceipt.bind(
        identity,
        output_path.read_bytes(),
        severity_proposal=proposal_path.read_bytes(),
        launch_digest=LAUNCH_DIGEST,
        verifier_backend="claude",
    )
    (sp / f"verify_{fid}.identity.json").write_text(
        json.dumps(identity.to_dict(), sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )
    (sp / f"verify_{fid}.receipt.json").write_text(
        receipt.to_json(),
        encoding="utf-8",
    )


def _write_report_index(sp: Path, rows: list[tuple[str, str, str, str]]) -> None:
    """rows = (report_id, severity, trust_adj, internal_id)."""
    lines = [
        "# Report Index",
        "",
        "## Summary Counts",
        "",
        "| Severity | Count |",
        "|----------|-------|",
        f"| Total | {len(rows)} |",
        "",
        "## Master Finding Index",
        "",
        "| Report ID | Title | Severity | Location | Verification | Trust Adj. | Internal Hypothesis ID |",
        "|-----------|-------|----------|----------|--------------|------------|------------------------|",
    ]
    for rid, sev, trust, internal in rows:
        lines.append(
            f"| {rid} | Bug {internal} | {sev} | src/Mod.go:L100 | VERIFIED | {trust} | {internal} |"
        )
    (sp / "report_index.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def _write_coverage(sp: Path, rows: list[tuple[str, str, str]]) -> None:
    """rows = (candidate_id, status, report_id_or_reason)."""
    lines = [
        "# Report Coverage Audit",
        "",
        "## Raw Candidate Ledger",
        "",
        "| Source File | Candidate ID | Status | Report ID / Reason |",
        "|-------------|--------------|--------|--------------------|",
    ]
    for cand, status, rid in rows:
        lines.append(f"| depth_state_trace_findings.md | {cand} | {status} | {rid} |")
    (sp / "report_coverage.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


# --------------------------------------------------------------------------- #
# HALT-2 — PROSE-only severity provenance: must be flaggable+degradeable       #
# --------------------------------------------------------------------------- #
def test_l1_prose_provenance_inflation_is_soft_not_mechanical(tmp_path: Path):
    """An inflation provenance violation (verify=Medium, index=High, empty Trust
    Adj.) is a PROSE issue. The mechanical verify-file parity gate must PASS
    (so the driver routes it to the degrade-with-flag path, not sys.exit)."""
    sp = tmp_path
    _write_queue(sp, [("H-01", "Medium")])
    _write_verify(sp, "H-01", "Medium")
    # Index over-rates to High with no Trust Adj. justification.
    _write_report_index(sp, [("H-01", "High", "-", "H-01")])

    # Prose gate flags it.
    prose_issues = _validate_report_index_inputs(sp)
    assert prose_issues, "expected a severity-provenance prose issue"
    assert any("provenance" in i.lower() for i in prose_issues), prose_issues

    # Repair cannot fix an inflation (only downgrades) -> still flagged.
    _repair_report_index_severity_provenance(sp)
    assert _validate_report_index_inputs(sp), "inflation must survive repair"

    # The MECHANICAL hard gate (verify-file parity) must PASS — proving the
    # residual issue is prose-only and the driver may degrade-with-flag.
    hard_issues = _validate_verify_files_for_queue(sp)
    assert not hard_issues, (
        "verify-file parity must pass for a prose-only provenance case; "
        f"got {hard_issues}"
    )


def test_l1_prose_provenance_downgrade_auto_repairs_attempt1(tmp_path: Path):
    """A downgrade provenance violation (verify=Medium, index=Low, empty Trust
    Adj.) is auto-repaired -> attempt 1 clears with no flag and no wasted
    retry."""
    sp = tmp_path
    _write_queue(sp, [("L-01", "Medium")])
    _write_verify(sp, "L-01", "Medium")
    _write_report_index(sp, [("L-01", "Low", "-", "L-01")])

    assert _validate_report_index_inputs(sp), "pre-repair downgrade should flag"
    repairs = _repair_report_index_severity_provenance(sp)
    assert any(str(r.get("action", "")).startswith("applied") for r in repairs), repairs
    assert not _validate_report_index_inputs(sp), (
        "downgrade provenance must clear after auto-repair (no halt, no retry)"
    )


# --------------------------------------------------------------------------- #
# HALT-1 — MECHANICAL verify-file parity: must STILL block (silent-drop)       #
# --------------------------------------------------------------------------- #
def test_l1_missing_verify_file_still_hard_blocks(tmp_path: Path):
    """A queued ID with no verify_<ID>.md on disk is a silent-drop risk and
    MUST remain a hard mechanical issue (the driver still sys.exit's)."""
    sp = tmp_path
    _write_queue(sp, [("H-01", "Medium"), ("H-02", "High")])
    _write_verify(sp, "H-01", "Medium")
    # H-02 verify file deliberately absent.

    hard_issues = _validate_verify_files_for_queue(sp)
    assert hard_issues, "missing verify file must surface as a hard parity issue"
    assert any("H-02" in i for i in hard_issues), hard_issues


# --------------------------------------------------------------------------- #
# HALT-3 — MECHANICAL coverage accounting: UNACCOUNTED must STILL block        #
# --------------------------------------------------------------------------- #
def test_l1_unaccounted_coverage_still_hard_blocks(tmp_path: Path):
    sp = tmp_path
    _write_coverage(sp, [
        ("ST-1", "PROMOTED", "H-01"),
        ("ST-2", "UNACCOUNTED", "n/a"),
    ])
    cov_issues = _validate_report_coverage_accounting(sp)
    assert cov_issues, "UNACCOUNTED candidate must be a hard coverage issue"
    assert any("UNACCOUNTED" in i for i in cov_issues), cov_issues


def test_l1_fully_accounted_coverage_passes(tmp_path: Path):
    sp = tmp_path
    _write_coverage(sp, [
        ("ST-1", "PROMOTED", "H-01"),
        ("ST-2", "MERGED", "H-01"),
    ])
    assert not _validate_report_coverage_accounting(sp), (
        "fully-accounted ledger must not produce hard issues"
    )


# --------------------------------------------------------------------------- #
# Rescan PLAMEN_STATUS contract (NOT changed by v2.8.17).                      #
#                                                                             #
# The audit flagged the rescan PLAMEN_STATUS check as a wasted-retry source   #
# (worker writes body then COMPLETE; attempt 1 races the flush). On           #
# investigation the only state that actually false-fails is a mid-flush with  #
# NO marker yet — and the existing `if markers and ...` guard already skips    #
# that (presence+size+structural decide). An EXPLICIT non-COMPLETE marker     #
# (IN_PROGRESS) is a deliberate "worker not done" signal: shipping it as       #
# complete would deliver partial rescan output = silent-incomplete recall      #
# loss. Per FIX PRINCIPLE 2 (do not weaken silent-drop protection) this        #
# behavior is PRESERVED. These tests lock the preserved contract in so a       #
# future "haltless" change cannot silently drop partial rescan work.          #
# --------------------------------------------------------------------------- #
_RESCAN_SUBSTANTIVE = (
    "# Per-Contract Agent 1\n\n"
    "## Finding [PC1-1]: Missing validation in deposit path\n\n"
    "**Verdict**: CONFIRMED\n"
    "**Severity**: Medium\n"
    "**Location**: src/Vault.sol:L40\n"
    "**Description**: deposit() does not check that amount is non-zero before "
    "minting shares, so a zero-amount deposit mints a dust position that "
    "complicates accounting and can be used to grief share-price math.\n"
    "**Impact**: Accounting drift and potential griefing of first-depositor "
    "share math.\n"
) + ("x" * 1200)


def _rescan_phase() -> Phase:
    return Phase(
        name="rescan",
        section_markers=["## Phase 3c"],
        expected_artifacts=["analysis_percontract_*.md"],
        base_timeout_s=600,
        modes={"core", "thorough"},
        min_artifact_bytes=100,
    )


def _write_manifest(sp: Path) -> None:
    (sp / "rescan_manifest.md").write_text(
        "# Rescan Manifest\n\n"
        "| File |\n|------|\n| analysis_percontract_1.md |\n",
        encoding="utf-8",
    )


def test_rescan_explicit_in_progress_marker_still_blocks(tmp_path: Path):
    """An EXPLICIT IN_PROGRESS marker on an otherwise substantive rescan file
    must STILL block — it is a deliberate "worker not done" signal and shipping
    it as complete would silently drop partial rescan output. (Mirrors the
    contract asserted by test_ship_8_17_rescan_exact_gate.py.)"""
    sp = tmp_path
    (sp / "_audit_started_with_markers.json").write_text("{}", encoding="utf-8")
    _write_manifest(sp)
    body = _RESCAN_SUBSTANTIVE + "\n\n<!-- PLAMEN_STATUS: IN_PROGRESS -->\n"
    (sp / "analysis_percontract_1.md").write_text(body, encoding="utf-8")

    missing = _rescan_manifest_exact_missing(sp, _rescan_phase())
    assert any("PLAMEN_STATUS" in m for m in missing), (
        "an explicit IN_PROGRESS marker must block (silent-incomplete "
        f"protection preserved); got {missing}"
    )


def test_rescan_no_marker_mid_flush_uses_structural_gate(tmp_path: Path):
    """The genuine mid-flush race (body written, NO marker yet) must NOT
    false-fail when the file is already structurally complete — the
    `if markers and ...` guard defers to presence+size+structural."""
    sp = tmp_path
    (sp / "_audit_started_with_markers.json").write_text("{}", encoding="utf-8")
    _write_manifest(sp)
    # No PLAMEN markers at all, but substantive + structurally complete.
    (sp / "analysis_percontract_1.md").write_text(_RESCAN_SUBSTANTIVE, encoding="utf-8")
    assert _rescan_manifest_exact_missing(sp, _rescan_phase()) == [], (
        "a no-marker but structurally-complete file must pass (not a false "
        "wasted-retry)"
    )


def test_rescan_complete_status_marker_passes(tmp_path: Path):
    sp = tmp_path
    (sp / "_audit_started_with_markers.json").write_text("{}", encoding="utf-8")
    _write_manifest(sp)
    body = _RESCAN_SUBSTANTIVE + "\n\n<!-- PLAMEN_STATUS: COMPLETE -->\n"
    (sp / "analysis_percontract_1.md").write_text(body, encoding="utf-8")
    assert _rescan_manifest_exact_missing(sp, _rescan_phase()) == []


def test_rescan_genuine_stub_fails_structurally_even_with_complete_marker(tmp_path: Path):
    """Silent-drop protection: a COMPLETE-marked but genuinely incomplete (stub)
    rescan file must STILL fail the structural content gate. A worker cannot
    claim COMPLETE on empty work to dodge the gate."""
    sp = tmp_path
    (sp / "_audit_started_with_markers.json").write_text("{}", encoding="utf-8")
    _write_manifest(sp)
    # No findings, no negative-result rationale, contains a placeholder TODO.
    stub = (
        "# Per-Contract Agent 1\n\nTODO\n" + ("x" * 1200)
        + "\n\n<!-- PLAMEN_STATUS: COMPLETE -->\n"
    )
    (sp / "analysis_percontract_1.md").write_text(stub, encoding="utf-8")
    missing = _rescan_manifest_exact_missing(sp, _rescan_phase())
    assert missing, "a genuine stub must still fail the structural content gate"
    assert any("structural_fail" in m for m in missing), missing


# --------------------------------------------------------------------------- #
# SC regression — the SC report_index gate path must be unchanged              #
# --------------------------------------------------------------------------- #
def _driver_source() -> str:
    import plamen_driver
    return Path(plamen_driver.__file__).read_text(encoding="utf-8")


def test_sc_report_index_gate_has_no_sys_exit_unchanged():
    """The SC report_index completeness gate must remain a degrade-with-flag
    path (passed=False, no sys.exit). The L1 fix is scoped to the
    `pipeline == "l1"` branch and must not have leaked a halt into the SC gate.
    """
    src = _driver_source()
    start = src.index("# --- report_index: completeness gate ---")
    end = src.index("# --- report_assemble: quality gate", start)
    sc_block = src[start:end]
    assert "sys.exit" not in sc_block, (
        "SC report_index gate must never sys.exit — it degrades via passed=False"
    )
    # SC still routes through its own mechanical repair-from-prior helper.
    assert "_repair_sc_report_index_from_prior" in src


def test_l1_report_index_branch_uses_repair_then_degrade():
    """The L1 report_index branch must now (a) call the severity-provenance
    repair before any degrade decision, and (b) write the human-review artifact
    on the prose-degrade path instead of an unconditional sys.exit on the
    post-write gate."""
    src = _driver_source()
    l1_start = src.index(
        'if config["pipeline"] == "l1" and phase.name == "report_index":'
    )
    # Bound the branch at the next top-level `if phase.name.startswith(`.
    l1_end = src.index('if phase.name.startswith("report_body_writer_")', l1_start)
    l1_block = src[l1_start:l1_end]
    assert "_run_report_index_canonicalization_transaction" in l1_block, (
        "L1 report_index must route all deterministic repairs through the "
        "canonical staged successor before degrading"
    )
    canonical_start = src.index(
        "def _derive_report_index_canonical_staged_target("
    )
    canonical_end = src.index(
        "\ndef _report_index_canonical_journal_digest", canonical_start
    )
    canonical_block = src[canonical_start:canonical_end]
    assert "_repair_report_index_severity_provenance" in canonical_block, (
        "the canonical staged successor must apply severity-provenance repair"
    )
    assert "report_semantic_severity_repairs.md" in l1_block, (
        "L1 report_index must flag prose provenance to a human-review artifact"
    )
    # The mechanical verify-file parity check must still be present as the hard
    # gate that retains sys.exit (silent-drop protection).
    assert "_validate_verify_files_for_queue" in l1_block
    # HALT-1 (prewrite) and HALT-3 (coverage) remain hard mechanical halts.
    assert "_validate_report_index_prewrite_inputs" in l1_block
    assert "_validate_report_coverage_accounting" in l1_block


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
