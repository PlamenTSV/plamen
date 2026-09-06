"""Tests for v2.4.7 fixes: SC body-writer manifests, ID normalization, recon content gate.

Covers:
  P0: _build_sc_body_writer_manifests — builds manifests from LLM-authored report_index.md
  P1: _check_index_completeness — leading-zero normalization prevents false dropouts
  P2: _validate_recon_content_structure — structural section headers in recon artifacts

Run: python -m pytest test_v2_4_7_fixes.py -v
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import patch

SCRIPTS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS_DIR))

import plamen_mechanical as M
import plamen_validators as V
import plamen_parsers as P
from queue_work_items import (
    QueueWorkItem,
    VerifierOutputIdentity,
    VerifierOutputReceipt,
    build_queue_work_plan,
)

import tempfile
import shutil


def _make_scratchpad() -> Path:
    """Create a temp scratchpad directory."""
    return Path(tempfile.mkdtemp(prefix="plamen_test_"))


def _cleanup(sp: Path):
    shutil.rmtree(sp, ignore_errors=True)


# ─── P0: SC body-writer manifests ─────────────────────────────────────


def _write_sc_report_index(sp: Path, rows: list[tuple[str, str, str, str, str]]):
    """Write a minimal SC-style report_index.md with Master Finding Index table.

    Each row: (report_id, title, severity, location, internal_id)
    """
    lines = [
        "# Report Index\n",
        "## Summary Counts\n",
        "| Severity | Count |",
        "|----------|-------|",
    ]
    sev_counts: dict[str, int] = {}
    for rid, _, sev, _, _ in rows:
        letter = rid[0]
        sev_counts[letter] = sev_counts.get(letter, 0) + 1
    for label, letter in [("Critical", "C"), ("High", "H"), ("Medium", "M"),
                          ("Low", "L"), ("Informational", "I")]:
        lines.append(f"| {label} | {sev_counts.get(letter, 0)} |")
    lines.append("")
    lines.append("## Master Finding Index\n")
    lines.append("| Report ID | Title | Severity | Location | Verification | Trust Adj. | Internal Hypothesis |")
    lines.append("|-----------|-------|----------|----------|--------------|-----------|---------------------|")
    for rid, title, sev, loc, iid in rows:
        lines.append(f"| {rid} | {title} | {sev} | {loc} | VERIFIED | - | {iid} |")
    (sp / "report_index.md").write_text("\n".join(lines), encoding="utf-8")


def _write_verify_file(sp: Path, finding_id: str, title: str = "Test finding",
                       location: str = "src/Vault.sol:L42"):
    """Write a minimal verify file for a finding."""
    content = f"""# Verification: {finding_id}

**Verdict**: CONFIRMED
**Evidence Tag**: [POC-PASS]
**Location**: {location}
**Description**: This is a test vulnerability description for {finding_id}.
**Recommendation**: Fix the issue by adding validation.
"""
    (sp / f"verify_{finding_id}.md").write_text(content, encoding="utf-8")
    _bind_existing_verifiers(sp)


def _proposal_bytes(item: QueueWorkItem) -> bytes:
    constituents = [item.work_item_id, *item.constituents]
    payload = {
        "schema_version": "plamen.severity_proposal.v1",
        "candidate_id": item.work_item_id,
        "constituent_ids": constituents,
        "impact": {
            "class": "High",
            "harmed_asset": "protected asset",
            "harmed_capability": "asset integrity",
            "premise_id": f"PREM-{item.work_item_id}-IMPACT",
            "premise_kind": "INTERNAL",
            "evidence_ids": [f"EVID-{item.work_item_id}-IMPACT"],
            "proof_scope": "IN_SCOPE_SOURCE",
        },
        "likelihood": {
            "class": "Medium",
            "actor": "unprivileged actor",
            "preconditions": ["reachable state"],
            "premise_id": f"PREM-{item.work_item_id}-LIKELIHOOD",
            "premise_kind": "INTERNAL",
            "evidence_ids": [f"EVID-{item.work_item_id}-LIKELIHOOD"],
            "proof_scope": "IN_SCOPE_SOURCE",
        },
        "modifiers": [],
        "proposed_severity": "High",
        "adjustment": None,
        "constituent_premise_outcomes": {
            value: {"impact": "SUPPORTED", "likelihood": "SUPPORTED"}
            for value in constituents
        },
    }
    return json.dumps(payload, sort_keys=True).encode("utf-8")


def _bind_existing_verifiers(sp: Path) -> None:
    queue = sp / "verification_queue.md"
    if not queue.is_file() or not P._typed_queue_sidecar_path(queue).is_file():
        return
    items = P._read_typed_queue_work_items(queue)
    if not items:
        return
    shard = "sc_verify_crithigh"
    plan = build_queue_work_plan(
        items,
        {shard: tuple(item.work_item_id for item in items)},
        planner_version="test.sc-body.v1",
    )
    (sp / "verification_queue.work_plan.json").write_text(
        plan.to_json(), encoding="utf-8"
    )
    for item in items:
        output_path = sp / item.expected_output_file
        if not output_path.is_file():
            continue
        proposal = _proposal_bytes(item)
        proposal_path = sp / f"verify_{item.work_item_id}.severity_proposal.json"
        proposal_path.write_bytes(proposal)
        identity = VerifierOutputIdentity.for_assignment(item, plan, shard)
        receipt = VerifierOutputReceipt.bind(
            identity,
            output_path.read_bytes(),
            severity_proposal=proposal,
            launch_digest="a" * 64,
            verifier_backend="claude",
        )
        (sp / f"verify_{item.work_item_id}.identity.json").write_text(
            json.dumps(identity.to_dict(), sort_keys=True, separators=(",", ":")),
            encoding="utf-8",
        )
        (sp / f"verify_{item.work_item_id}.receipt.json").write_text(
            receipt.to_json(), encoding="utf-8"
        )


def _write_verification_queue(sp: Path, ids: list[tuple[str, str]]):
    """Write verification_queue.md. ids: list of (finding_id, severity_letter)."""
    severity = {
        "C": "Critical", "H": "High", "M": "Medium",
        "L": "Low", "I": "Informational",
    }
    rows = [
        {
            "queue #": str(index),
            "finding id": fid,
            "severity": severity.get(sev.upper(), sev),
            "title": f"Fixture {fid}",
            "bug class": "structural",
            "preferred tag": "[POC-PASS]",
            "location": "",
            "primary artifact": "findings_inventory.md",
            "poc class": "structural",
        }
        for index, (fid, sev) in enumerate(ids, 1)
    ]
    P._write_queue_subset_manifest(sp / "verification_queue.md", rows)
    _bind_existing_verifiers(sp)


def test_sc_manifests_basic():
    """SC manifest builder produces correct shard structure."""
    sp = _make_scratchpad()
    try:
        _write_sc_report_index(sp, [
            ("C-01", "Critical Bug", "Critical", "src/A.sol:L10", "H-1"),
            ("H-01", "High Bug", "High", "src/B.sol:L20", "H-2"),
            ("M-01", "Medium Bug", "Medium", "src/C.sol:L30", "H-3"),
            ("L-01", "Low Bug", "Low", "src/D.sol:L40", "H-4"),
        ])
        _write_verify_file(sp, "H-1", "Critical Bug", "src/A.sol:L10")
        _write_verify_file(sp, "H-2", "High Bug", "src/B.sol:L20")
        _write_verify_file(sp, "H-3", "Medium Bug", "src/C.sol:L30")
        _write_verify_file(sp, "H-4", "Low Bug", "src/D.sol:L40")
        _write_verification_queue(sp, [("H-1", "C"), ("H-2", "H"), ("H-3", "M"), ("H-4", "L")])

        result = M._build_sc_body_writer_manifests(sp)

        assert "report_critical_high" in result
        assert "report_medium" in result
        assert "report_low_info" in result

        ch = result["report_critical_high"]["findings"]
        assert len(ch) == 2
        assert ch[0]["report_id"] == "C-01"
        assert ch[1]["report_id"] == "H-01"

        med = result["report_medium"]["findings"]
        assert len(med) == 1
        assert med[0]["report_id"] == "M-01"

        li = result["report_low_info"]["findings"]
        assert len(li) == 1
        assert li[0]["report_id"] == "L-01"

        # Verify manifest files on disk
        assert (sp / "body_manifests" / "report_critical_high.json").exists()
        assert (sp / "body_manifests" / "report_medium.json").exists()
        assert (sp / "body_manifests" / "report_low_info.json").exists()
    finally:
        _cleanup(sp)


def test_sc_manifests_enrichment():
    """SC manifest builder enriches title/location from index table and verify files."""
    sp = _make_scratchpad()
    try:
        _write_sc_report_index(sp, [
            ("H-01", "Access Control Missing", "High", "src/Auth.sol:L55", "H-7"),
        ])
        _write_verify_file(sp, "H-7", "Access Control Missing", "src/Auth.sol:L55")
        _write_verification_queue(sp, [("H-7", "H")])

        result = M._build_sc_body_writer_manifests(sp)

        ch = result["report_critical_high"]["findings"]
        assert len(ch) == 1
        f = ch[0]
        assert f["title"] == "Access Control Missing"
        assert f["location"] == "src/Auth.sol:L55"
        assert f["finding_id"] == "H-7"
        assert f["evidence_tag"] == "[POC-PASS]"
        assert "test vulnerability" in f["description"]
        assert "validation" in f["recommendation"]
    finally:
        _cleanup(sp)


def test_sc_manifests_empty_index():
    """SC manifest builder emits an explicit typed empty denominator."""
    sp = _make_scratchpad()
    try:
        result = M._build_sc_body_writer_manifests(sp)
        assert result == {
            "report_empty": {
                "schema_version": "plamen.empty_report_denominator.v1",
                "denominator_state": "EMPTY",
                "shard": "report_empty",
                "findings": [],
            }
        }
        assert json.loads(
            (sp / "body_manifests" / "report_empty.json").read_text(
                encoding="utf-8"
            )
        ) == result["report_empty"]
    finally:
        _cleanup(sp)


def test_sc_manifests_shard_splitting():
    """SC manifest builder splits shards when count exceeds cap."""
    sp = _make_scratchpad()
    try:
        # Create 20 medium findings (cap is 20, so should NOT split)
        rows = []
        ids = []
        for i in range(1, 21):
            fid = f"H-{i}"
            rid = f"M-{i:02d}"
            rows.append((rid, f"Bug {i}", "Medium", f"src/F{i}.sol:L{i}", fid))
            ids.append((fid, "M"))
            _write_verify_file(sp, fid, f"Bug {i}", f"src/F{i}.sol:L{i}")
        _write_sc_report_index(sp, rows)
        _write_verification_queue(sp, ids)

        result = M._build_sc_body_writer_manifests(sp)
        assert "report_medium" in result
        assert "report_medium_a" not in result

        _cleanup(sp)
        sp = _make_scratchpad()

        # Create 25 medium findings (cap is 20, should split into _a/_b)
        rows = []
        ids = []
        for i in range(1, 26):
            fid = f"H-{i}"
            rid = f"M-{i:02d}"
            rows.append((rid, f"Bug {i}", "Medium", f"src/F{i}.sol:L{i}", fid))
            ids.append((fid, "M"))
            _write_verify_file(sp, fid, f"Bug {i}", f"src/F{i}.sol:L{i}")
        _write_sc_report_index(sp, rows)
        _write_verification_queue(sp, ids)

        result = M._build_sc_body_writer_manifests(sp)
        assert "report_medium_a" in result
        assert "report_medium_b" in result
        assert "report_medium" not in result  # replaced by shards
        total = (len(result["report_medium_a"]["findings"])
                 + len(result["report_medium_b"]["findings"]))
        assert total == 25
    finally:
        _cleanup(sp)


def test_sc_manifests_no_verify_file():
    """SC manifest builder handles missing verify files gracefully."""
    sp = _make_scratchpad()
    try:
        _write_sc_report_index(sp, [
            ("H-01", "Some Bug", "High", "src/X.sol:L10", "H-99"),
        ])
        # No verify file for H-99
        _write_verification_queue(sp, [("H-99", "H")])

        result = M._build_sc_body_writer_manifests(sp)
        assert "report_critical_high" in result
        f = result["report_critical_high"]["findings"][0]
        assert f["title"] == "Some Bug"  # from index table
        assert f["location"] == "src/X.sol:L10"  # from index table
        assert f["description"] == ""  # no verify file
        assert f["report_blocked"] is True  # no description or rec
    finally:
        _cleanup(sp)


# ─── P1: ID normalization in completeness gate ──────────────────────────


def test_sc_manifests_recover_shifted_index_location_and_multi_id_chain():
    """SC body manifests recover from shifted index cells and multi-ID chain rows."""
    sp = _make_scratchpad()
    try:
        lines = [
            "# Report Index",
            "",
            "## Summary Counts",
            "| Severity | Count |",
            "|----------|-------|",
            "| Critical | 1 |",
            "| High | 0 |",
            "| Medium | 0 |",
            "| Low | 0 |",
            "| Informational | 0 |",
            "",
            "## Master Finding Index",
            "| Report ID | Title | Severity | Location | Verification | Trust Adj. | Internal Hypothesis |",
            "|-----------|-------|----------|----------|--------------|------------|---------------------|",
            "| C-01 | Oracle chain | Critical | Critical, [CODE-TRACE], POC-PASS chain | VERIFIED | - | H-1+H-3 |",
        ]
        (sp / "report_index.md").write_text("\n".join(lines), encoding="utf-8")
        _write_verification_queue(sp, [("H-1", "C"), ("H-3", "C")])
        _write_verify_file(sp, "H-1", "Oracle chain", "contracts/Oracle.sol:L88")
        _write_verify_file(sp, "H-3", "Oracle chain", "contracts/Vault.sol:L144")

        assignments, source = P.get_tier_assignments(sp)
        assert source == "index"
        assert assignments == [
            {"report_id": "C-01", "finding_id": "H-1+H-3", "severity": "C"}
        ]
        assert V._check_index_completeness(sp) == []

        result = M._build_sc_body_writer_manifests(sp)
        findings = result["report_critical_high"]["findings"]
        assert len(findings) == 1
        f = findings[0]
        assert f["location"] == "contracts/Oracle.sol:L88"
        assert f["verify_files"] == ["verify_H-1.md", "verify_H-3.md"]
        assert f["report_blocked"] is False

        body = """### [C-01] Oracle chain

**Severity**: Critical
**Location**: contracts/Oracle.sol:L88

The body uses the recovered code location and does not need a blocked tag.

**Impact**: A stale oracle price lets an attacker borrow against inflated collateral.
**PoC Result**: Test confirms the inflated borrow; assertion passed.
"""
        validation = V._validate_report_body(body, result["report_critical_high"])
        assert validation["ok"] is True
    finally:
        _cleanup(sp)


def test_sc_manifests_do_not_treat_severity_evidence_cell_as_location():
    """Compact SC index rows without a Location column must recover verifier locations."""
    sp = _make_scratchpad()
    try:
        lines = [
            "# Report Index",
            "",
            "## Summary Counts",
            "| Severity | Count |",
            "|----------|-------|",
            "| Critical | 0 |",
            "| High | 0 |",
            "| Medium | 3 |",
            "| Low | 0 |",
            "| Informational | 0 |",
            "",
            "## Master Finding Index",
            "| Report ID | Title | Severity / Evidence | Internal Hypothesis |",
            "|-----------|-------|---------------------|---------------------|",
            "| M-01 | Medium Bug 1 | Medium, [POC-PASS] | H-1 |",
            "| M-02 | Medium Bug 2 | Medium, [POC-PASS] | H-2 |",
            "| M-03 | Medium Bug 3 | Medium, [POC-PASS] | H-3 |",
        ]
        (sp / "report_index.md").write_text("\n".join(lines), encoding="utf-8")
        _write_verification_queue(sp, [("H-1", "M"), ("H-2", "M"), ("H-3", "M")])
        _write_verify_file(sp, "H-1", "Medium Bug 1", "contracts/A.sol:L10")
        _write_verify_file(sp, "H-2", "Medium Bug 2", "contracts/B.sol:L20")
        _write_verify_file(sp, "H-3", "Medium Bug 3", "contracts/C.sol:L30")

        result = M._build_sc_body_writer_manifests(sp)
        findings = result["report_medium"]["findings"]
        assert [f["report_id"] for f in findings] == ["M-01", "M-02", "M-03"]
        assert [f["location"] for f in findings] == [
            "contracts/A.sol:L10",
            "contracts/B.sol:L20",
            "contracts/C.sol:L30",
        ]
        assert all(f["location"] != "Medium, [POC-PASS]" for f in findings)
        assert all(f["report_blocked"] is False for f in findings)
    finally:
        _cleanup(sp)


def test_sc_report_index_tier_assignment_tables_do_not_duplicate_body_manifests():
    """Tier Assignment routing tables repeat IDs but are not report assignments."""
    sp = _make_scratchpad()
    try:
        lines = [
            "# Report Index",
            "",
            "## Summary Counts",
            "| Severity | Count |",
            "|----------|-------|",
            "| Critical | 0 |",
            "| High | 0 |",
            "| Medium | 2 |",
            "| Low | 0 |",
            "| Informational | 0 |",
            "",
            "## Master Finding Index",
            "| Report ID | Title | Severity | Location | Verification | Trust Adj. | Internal Hypothesis |",
            "|-----------|-------|----------|----------|--------------|------------|---------------------|",
            "| M-01 | Medium Bug 1 | Medium | contracts/A.sol:L10 | VERIFIED | - | H-1 |",
            "| M-02 | Medium Bug 2 | Medium | contracts/B.sol:L20 | VERIFIED | - | H-2 |",
            "",
            "## Tier Assignments",
            "",
            "### Medium Tier (for Sonnet writer)",
            "| Report ID | Internal Ref | Verification File | Notes |",
            "|-----------|--------------|-------------------|-------|",
            "| M-01 | H-1 | verify_H-1.md | Medium, [POC-PASS] |",
            "| M-02 | H-2 | verify_H-2.md | Medium, [POC-PASS] |",
        ]
        (sp / "report_index.md").write_text("\n".join(lines), encoding="utf-8")
        _write_verification_queue(sp, [("H-1", "M"), ("H-2", "M")])
        _write_verify_file(sp, "H-1", "Medium Bug 1", "contracts/A.sol:L10")
        _write_verify_file(sp, "H-2", "Medium Bug 2", "contracts/B.sol:L20")

        assignments, source = P.get_tier_assignments(sp)
        manifests = M._build_sc_body_writer_manifests(sp)
        findings = manifests["report_medium"]["findings"]

        assert source == "index"
        assert [a["report_id"] for a in assignments] == ["M-01", "M-02"]
        assert [f["report_id"] for f in findings] == ["M-01", "M-02"]
    finally:
        _cleanup(sp)


def test_sc_report_e2e_rejects_untyped_consolidation_as_delivery_authority():
    """Raw consolidation prose cannot account for a second verified identity."""
    sp = _make_scratchpad()
    try:
        project = sp / "project"
        project.mkdir()
        (sp / "verification_queue.md").write_text(
            "# Verification Queue\n\n"
            "| # | Hypothesis ID | Severity | Status |\n"
            "|---|---------------|----------|--------|\n"
            "| 1 | H-1 | Critical | PENDING |\n"
            "| 2 | H-3 | Critical | PENDING |\n",
            encoding="utf-8",
        )
        (sp / "verify_H-1.md").write_text(
            "# Oracle update is unchecked\n"
            "**Verdict**: CONFIRMED\n"
            "**Severity**: Critical\n"
            "**Evidence Tag**: [POC-PASS]\n"
            "**Location**: contracts/Oracle.sol:L88\n"
            "**Description**: The oracle update path accepts manipulated input and immediately feeds the vault accounting path. The verifier reproduced the unsafe transition with a bounded scenario. The same root cause controls the paired vault accounting failure.\n"
            "**Impact**: Manipulated pricing can drain the protected accounting path before operators can react.\n"
            "**PoC Result**: PASS - the proof demonstrated the manipulated price changes the withdrawal result.\n"
            "**Recommendation**: Validate oracle freshness and clamp accepted price movement before updating accounting state.\n",
            encoding="utf-8",
        )
        (sp / "verify_H-3.md").write_text(
            "# Vault accounting trusts oracle state\n"
            "**Verdict**: CONFIRMED\n"
            "**Severity**: Critical\n"
            "**Evidence Tag**: [CODE-TRACE]\n"
            "**Location**: contracts/Vault.sol:L144\n"
            "**Description**: The vault consumes the updated oracle state without an independent freshness or deviation check. This is the second half of the same exploit path and requires the same validation boundary.\n"
            "**Impact**: Shares can be mispriced during withdrawal and redemption flows.\n"
            "**PoC Result**: Code trace confirms the stale manipulated oracle value reaches share conversion.\n"
            "**Recommendation**: Re-check oracle bounds at the vault boundary and reject stale conversion inputs.\n",
            encoding="utf-8",
        )
        _write_verification_queue(sp, [("H-1", "C"), ("H-3", "C")])
        (sp / "report_index.md").write_text(
            "# Report Index\n\n"
            "## Summary Counts\n"
            "| Severity | Count |\n"
            "|----------|-------|\n"
            "| Critical | 1 |\n"
            "| High | 0 |\n"
            "| Medium | 0 |\n"
            "| Low | 0 |\n"
            "| Informational | 0 |\n\n"
            "## Master Finding Index\n"
            "| Report ID | Title | Severity | Location | Verification | Trust Adj. | Internal Hypothesis |\n"
            "|-----------|-------|----------|----------|--------------|------------|---------------------|\n"
            "| C-01 | Oracle manipulation can corrupt vault accounting | Critical | Critical, [CODE-TRACE], POC-PASS chain | VERIFIED | - | H-1+H-3 |\n\n"
            "## Consolidation Map\n"
            "| Report ID | Consolidated From | Consolidation Reason |\n"
            "|-----------|-------------------|----------------------|\n"
            "| C-01 | H-1, H-3 | Same exploit path and same validation boundary |\n\n"
            "## Excluded Findings (for Appendix A)\n"
            "| Internal ID | Severity | Title | Exclusion Reason |\n"
            "|-------------|----------|-------|------------------|\n",
            encoding="utf-8",
        )

        assert V._check_index_completeness(sp) == []
        manifests = M._build_sc_body_writer_manifests(sp)
        manifest = manifests["report_critical_high"]
        finding = manifest["findings"][0]
        assert finding["verify_files"] == ["verify_H-1.md", "verify_H-3.md"]
        assert finding["location"] == "contracts/Oracle.sol:L88"
        assert finding["report_blocked"] is False

        long_body = (
            "### [C-01] Oracle manipulation can corrupt vault accounting [VERIFIED]\n\n"
            "**Severity**: Critical\n"
            "**Location**: contracts/Oracle.sol:L88\n"
            "**Confidence**: HIGH (PoC: PASS, code trace confirms paired vault path)\n\n"
            "**Description**:\n"
            "The oracle update boundary accepts manipulated pricing data and the vault later consumes that state during accounting. The paired verifier evidence shows the issue spans both the oracle update and the vault conversion path, but it has one remediation boundary: validate freshness and deviation before state is trusted. The body intentionally avoids internal pipeline identifiers while preserving both proven locations. The vault-side evidence is represented as an affected-location detail rather than a second duplicate report finding.\n\n"
            "**Affected locations**:\n"
            "| Component | Location | Evidence |\n"
            "|-----------|----------|----------|\n"
            "| Oracle | contracts/Oracle.sol:L88 | PoC demonstrated manipulated price acceptance |\n"
            "| Vault | contracts/Vault.sol:L144 | Code trace showed manipulated state reaches conversion |\n\n"
            "**Impact**:\n"
            "An attacker able to influence the oracle update can force incorrect vault accounting and misprice withdrawals or redemptions. The highest-impact path is loss of funds from conversions performed against manipulated state before operators can intervene.\n\n"
            "**PoC Result**:\n"
            "PASS - the oracle proof changed the withdrawal result, and the paired code trace confirmed the vault consumes the manipulated value in share conversion.\n\n"
            "**Evidence Tag**: [POC-PASS]\n\n"
            "**Recommendation**:\n"
            "Validate oracle freshness, clamp accepted price movement, and repeat the bounds check at the vault conversion boundary. Add regression tests covering manipulated oracle updates followed by withdrawal and redemption operations.\n"
        )
        (sp / "report_critical_high.md").write_text(
            "# Critical and High Findings\n\n## Critical Findings\n\n" + long_body,
            encoding="utf-8",
        )

        assert V._validate_tier_body_against_manifest(sp, "report_critical_high") == []
        assert M._assemble_report_python(sp, str(project)) is True
        quality_issues = V._run_report_quality_gate(sp, str(project))
        assert any(
            "promotion dropout" in issue and "H-3" in issue
            for issue in quality_issues
        )
        symmetry_issues = V._check_promotion_symmetry(sp, str(project))
        assert any(
            "promotion dropout" in issue and "H-3" in issue
            for issue in symmetry_issues
        )
        report = (project / "AUDIT_REPORT.md").read_text(encoding="utf-8")
        assert "contracts/Oracle.sol:L88" in report
        assert "contracts/Vault.sol:L144" in report
        assert "H-1" not in report
        assert "H-3" not in report
    finally:
        _cleanup(sp)


def test_completeness_gate_leading_zero_mismatch():
    """IDs with different zero-padding should match (H-1 vs H-01)."""
    sp = _make_scratchpad()
    try:
        # verify file: H-1 (no zero padding)
        _write_verify_file(sp, "H-1")
        # report_index.md: H-01 (zero padded)
        _write_sc_report_index(sp, [
            ("H-01", "Bug", "High", "src/A.sol:L10", "H-01"),
        ])

        issues = V._check_index_completeness(sp)
        # Should NOT report H-1 as dropped
        dropout_issues = [i for i in issues if "dropout" in i.lower()]
        assert len(dropout_issues) == 0, f"False dropout: {dropout_issues}"
    finally:
        _cleanup(sp)


def test_completeness_gate_leading_zero_reverse():
    """IDs with different zero-padding: H-01 file vs H-1 in index."""
    sp = _make_scratchpad()
    try:
        # verify file: H-01 (zero padded)
        _write_verify_file(sp, "H-01")
        # report_index.md: H-1 (no padding) — unusual but possible
        lines = [
            "# Report Index\n",
            "## Master Finding Index\n",
            "| Report ID | Title | Severity | Location | Internal Hypothesis |",
            "|-----------|-------|----------|----------|---------------------|",
            "| H-01 | Bug | High | src/A.sol:L10 | H-1 |",
        ]
        (sp / "report_index.md").write_text("\n".join(lines), encoding="utf-8")

        issues = V._check_index_completeness(sp)
        dropout_issues = [i for i in issues if "dropout" in i.lower()]
        assert len(dropout_issues) == 0, f"False dropout: {dropout_issues}"
    finally:
        _cleanup(sp)


def test_completeness_gate_multi_zero_padding():
    """INV-002 vs INV-2 should match."""
    sp = _make_scratchpad()
    try:
        _write_verify_file(sp, "INV-2")
        lines = [
            "# Report Index\n",
            "## Master Finding Index\n",
            "| Report ID | Title | Severity | Location | Internal Hypothesis |",
            "|-----------|-------|----------|----------|---------------------|",
            "| M-01 | Bug | Medium | src/A.sol:L10 | INV-002 |",
        ]
        (sp / "report_index.md").write_text("\n".join(lines), encoding="utf-8")

        issues = V._check_index_completeness(sp)
        dropout_issues = [i for i in issues if "dropout" in i.lower()]
        assert len(dropout_issues) == 0, f"False dropout: {dropout_issues}"
    finally:
        _cleanup(sp)


def test_completeness_gate_real_dropout_still_detected():
    """Genuine dropouts (different base ID) should still be caught."""
    sp = _make_scratchpad()
    try:
        _write_verify_file(sp, "H-1")
        _write_verify_file(sp, "H-5")  # This one is NOT in the index
        _write_sc_report_index(sp, [
            ("H-01", "Bug", "High", "src/A.sol:L10", "H-1"),
        ])

        issues = V._check_index_completeness(sp)
        dropout_issues = [i for i in issues if "dropout" in i.lower()]
        assert len(dropout_issues) == 1
        assert "H-5" in dropout_issues[0]
    finally:
        _cleanup(sp)


# ─── P2: Recon content structure gate ───────────────────────────────────


def test_recon_content_good():
    """Well-structured design_context.md passes validation."""
    sp = _make_scratchpad()
    try:
        (sp / "design_context.md").write_text(
            "# Design Context\n\n"
            "## Key Invariants\n\n"
            "- totalSupply == sum(balances)\n\n"
            "## Operational Implications\n\n"
            "The totalSupply invariant means...\n",
            encoding="utf-8",
        )
        (sp / "attack_surface.md").write_text(
            "# Attack Surface\n\n"
            "## External Entry Points\n\n"
            "- deposit()\n- withdraw()\n",
            encoding="utf-8",
        )
        hard, soft = V._validate_recon_content_structure(sp)
        assert hard == [] and soft == []
    finally:
        _cleanup(sp)


def test_recon_content_missing_operational_implications():
    """design_context.md without Operational Implications section is flagged as hard."""
    sp = _make_scratchpad()
    try:
        (sp / "design_context.md").write_text(
            "# Design Context\n\n"
            "## Key Invariants\n\n"
            "- totalSupply == sum(balances)\n",
            encoding="utf-8",
        )
        hard, _soft = V._validate_recon_content_structure(sp)
        assert any("Operational Implications" in i for i in hard)
    finally:
        _cleanup(sp)


def test_recon_content_missing_invariants():
    """design_context.md without Key Invariants section is flagged as hard."""
    sp = _make_scratchpad()
    try:
        (sp / "design_context.md").write_text(
            "# Design Context\n\n"
            "## Operational Implications\n\n"
            "Implications here.\n",
            encoding="utf-8",
        )
        hard, _soft = V._validate_recon_content_structure(sp)
        assert any("Invariant" in i for i in hard)
    finally:
        _cleanup(sp)


def test_recon_content_empty_attack_surface():
    """attack_surface.md without section headers is flagged as soft."""
    sp = _make_scratchpad()
    try:
        (sp / "attack_surface.md").write_text(
            "Some text without any headings.\n"
            "Just prose about the contract.\n",
            encoding="utf-8",
        )
        _hard, soft = V._validate_recon_content_structure(sp)
        assert any("attack_surface" in i for i in soft)
    finally:
        _cleanup(sp)


def test_recon_content_missing_files():
    """Missing files don't crash the validator (they're caught by gate_passes)."""
    sp = _make_scratchpad()
    try:
        hard, soft = V._validate_recon_content_structure(sp)
        assert hard == [] and soft == []
    finally:
        _cleanup(sp)


def test_recon_content_variant_headings():
    """Variant heading styles (Core Invariants, Protocol Invariants) are accepted."""
    sp = _make_scratchpad()
    try:
        (sp / "design_context.md").write_text(
            "# Design Context\n\n"
            "## Core Invariants\n\n"
            "- X == Y\n\n"
            "## Operational Implications\n\n"
            "Stuff here.\n",
            encoding="utf-8",
        )
        hard, _soft = V._validate_recon_content_structure(sp)
        assert not any("Invariant" in i for i in hard)
    finally:
        _cleanup(sp)


def test_recon_content_attack_surface_variants():
    """Various attack_surface heading styles are accepted (soft check)."""
    sp = _make_scratchpad()
    for heading in [
        "## Public Functions",
        "## Attack Surface Overview",
        "## Entry Points",
        "## External Functions",
    ]:
        try:
            (sp / "attack_surface.md").write_text(
                f"# Attack Surface\n\n{heading}\n\n- stuff\n",
                encoding="utf-8",
            )
            _hard, soft = V._validate_recon_content_structure(sp)
            assert not any("attack_surface" in i for i in soft), \
                f"False alarm for heading: {heading}"
        finally:
            pass
    _cleanup(sp)
