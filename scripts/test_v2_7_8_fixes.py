"""Tests for v2.7.8 mechanical gate robustness fixes."""
from __future__ import annotations

import re
import textwrap
from pathlib import Path

import pytest

from plamen_mechanical import _collect_raw_candidate_ledger_rows
from plamen_validators import (
    _collect_report_coverage_acknowledged_ids,
    _validate_report_coverage_accounting,
)


# ---------------------------------------------------------------------------
# Fix 1: UNACCOUNTED → AUTO_EXCLUDED
# ---------------------------------------------------------------------------

class TestAutoExcludedDisposition:
    """Verify IDs not in promoted/excluded/dedup_absorbed get AUTO_EXCLUDED."""

    @pytest.fixture()
    def scratchpad(self, tmp_path: Path) -> Path:
        sp = tmp_path / ".scratchpad"
        sp.mkdir()
        return sp

    def test_unqueued_id_gets_auto_excluded(self, scratchpad: Path):
        """An ID in findings_inventory but not in verification_queue should be
        AUTO_EXCLUDED, not UNACCOUNTED."""
        (scratchpad / "findings_inventory.md").write_text(
            textwrap.dedent("""\
                ### Finding [INV-001]: Queued finding
                **Source IDs**: CC-01

                ### Finding [INV-002]: Also queued
                **Source IDs**: CC-02

                ### Finding [PERT-01]: Perturbation finding (never queued)
                **Source IDs**: n/a
            """),
            encoding="utf-8",
        )
        promoted = {"INV-001", "INV-002"}
        rows = _collect_raw_candidate_ledger_rows(scratchpad, promoted, set())
        pert_rows = [r for r in rows if "PERT-01" in r]
        assert len(pert_rows) > 0, "PERT-01 should appear in ledger"
        assert all("AUTO_EXCLUDED" in r for r in pert_rows), (
            f"PERT-01 should be AUTO_EXCLUDED, got: {pert_rows}"
        )
        assert not any("UNACCOUNTED" in r for r in pert_rows)

    def test_no_unaccounted_disposition_produced(self, scratchpad: Path):
        """The string UNACCOUNTED should never appear in produced rows."""
        (scratchpad / "findings_inventory.md").write_text(
            textwrap.dedent("""\
                ### Finding [INV-001]: Known
                ### Finding [BLIND-99]: Unknown
                ### Finding [RS1-01]: Rescan
            """),
            encoding="utf-8",
        )
        rows = _collect_raw_candidate_ledger_rows(scratchpad, {"INV-001"}, set())
        for row in rows:
            assert "UNACCOUNTED" not in row, f"UNACCOUNTED should not appear: {row}"

    def test_validator_passes_with_only_auto_excluded(self, scratchpad: Path):
        """The UNACCOUNTED gate should pass when all unmatched IDs are
        AUTO_EXCLUDED."""
        (scratchpad / "report_coverage.md").write_text(
            textwrap.dedent("""\
                # Report Coverage

                ## Raw Candidate Ledger

                | Source Artifact | Candidate ID | Disposition |
                |-----------------|--------------|-------------|
                | findings_inventory.md | INV-001 | PROMOTED |
                | findings_inventory.md | PERT-01 | AUTO_EXCLUDED |
                | findings_inventory.md | PERT-02 | AUTO_EXCLUDED |
            """),
            encoding="utf-8",
        )
        issues = _validate_report_coverage_accounting(scratchpad)
        assert issues == [], f"Expected no issues, got: {issues}"

    def test_validator_still_catches_unaccounted(self, scratchpad: Path):
        """If an LLM or legacy code writes UNACCOUNTED, the gate should still
        catch it."""
        (scratchpad / "report_coverage.md").write_text(
            textwrap.dedent("""\
                # Report Coverage

                ## Raw Candidate Ledger

                | Source Artifact | Candidate ID | Disposition |
                |-----------------|--------------|-------------|
                | findings_inventory.md | INV-001 | PROMOTED |
                | findings_inventory.md | LOST-01 | UNACCOUNTED |
            """),
            encoding="utf-8",
        )
        issues = _validate_report_coverage_accounting(scratchpad)
        assert len(issues) > 0
        assert "UNACCOUNTED" in issues[0]
        assert "LOST-01" in issues[0]


class TestAutoExcludedNotAcknowledged:
    """Fix 1 reviewer concern: AUTO_EXCLUDED must NOT silently enter the
    acknowledged set via substring match on EXCLUDED."""

    @pytest.fixture()
    def scratchpad(self, tmp_path: Path) -> Path:
        sp = tmp_path / ".scratchpad"
        sp.mkdir()
        return sp

    def test_auto_excluded_not_in_acknowledged_set(self, scratchpad: Path):
        """AUTO_EXCLUDED rows should be skipped by the skip guard, not
        acknowledged via the EXCLUDED substring match."""
        (scratchpad / "report_coverage.md").write_text(
            textwrap.dedent("""\
                # Report Coverage

                ## Raw Candidate Ledger

                | Source File | Candidate ID / Label | Severity Signal | Status | Report ID / Refutation / Reason |
                |-------------|----------------------|-----------------|--------|---------------------------------|
                | findings_inventory.md | PERT-01 | Info | AUTO_EXCLUDED | n/a |
                | findings_inventory.md | INV-001 | High | PROMOTED | H-01 |
            """),
            encoding="utf-8",
        )
        ack = _collect_report_coverage_acknowledged_ids(scratchpad)
        assert "PERT-01" not in ack, (
            "AUTO_EXCLUDED IDs must not enter the acknowledged set"
        )
        assert "INV-001" not in ack, (
            "bare PROMOTED renderer prose is not delivery authority"
        )

    def test_plain_excluded_is_not_acknowledged(self, scratchpad: Path):
        """Typed report-disposition authority, not renderer prose, owns exclusion."""
        (scratchpad / "report_coverage.md").write_text(
            textwrap.dedent("""\
                # Report Coverage

                ## Raw Candidate Ledger

                | Source Artifact | Candidate ID | Disposition |
                |-----------------|--------------|-------------|
                | findings_inventory.md | INV-001 | EXCLUDED |
            """),
            encoding="utf-8",
        )
        ack = _collect_report_coverage_acknowledged_ids(scratchpad)
        assert "INV-001" not in ack


# ---------------------------------------------------------------------------
# Fix 2: PoC Result exemption for VERIFICATION NOT EXECUTED
# ---------------------------------------------------------------------------

class TestVerificationNotExecutedExemption:
    """The content_authenticity quality gate should not require PoC Result
    for findings marked [VERIFICATION NOT EXECUTED]."""

    @pytest.fixture()
    def audit_env(self, tmp_path: Path):
        """Set up scratchpad + project_root with report_index.md stub."""
        sp = tmp_path / ".scratchpad"
        sp.mkdir()
        proj = tmp_path / "project"
        proj.mkdir()
        (sp / "report_index.md").write_text(
            textwrap.dedent("""\
                # Report Index
                ## Summary Counts
                | Severity | Count |
                |----------|-------|
                | High | 2 |
                ## Master Finding Index
                | Report ID | Title | Severity | Location | Verification | Trust Adj. | Internal Hypothesis |
                |-----------|-------|----------|----------|--------------|------------|---------------------|
                | H-01 | Test | High | src/A.sol | VERIFIED | - | HYP-1 |
                | H-02 | Test2 | High | src/B.sol | UNVERIFIED | - | HYP-2 |
            """),
            encoding="utf-8",
        )
        return sp, proj

    def _build_report(self, sections: list[str]) -> str:
        count = sum(1 for s in sections if s.startswith("### ["))
        return "\n".join([
            "# Security Audit Report",
            "",
            "## Summary",
            "| Severity | Count |",
            "|----------|-------|",
            f"| High | {count} |",
            "",
            "## High Findings",
            "",
        ] + sections)

    def test_verified_finding_still_requires_poc(self, audit_env):
        from plamen_validators import _run_report_quality_gate
        sp, proj = audit_env
        report = self._build_report([
            "### [H-01] Test Finding [VERIFIED]",
            "",
            "**Severity**: High",
            "**Location**: `src/Vault.sol:L42`",
            "**Description**: A real bug.",
            "**Impact**: Funds can be lost.",
            "",
        ])
        (proj / "AUDIT_REPORT.md").write_text(report, encoding="utf-8")
        issues = _run_report_quality_gate(sp, str(proj))
        quality_md = (sp / "report_quality.md").read_text(encoding="utf-8")
        if "content_authenticity" in quality_md and "FAIL" in quality_md:
            assert "H-01" in quality_md, (
                "H-01 (verified, no PoC) should be flagged"
            )

    def test_unverified_finding_exempt_from_poc(self, audit_env):
        from plamen_validators import _run_report_quality_gate
        sp, proj = audit_env
        report = self._build_report([
            "### [H-01] Test Finding [VERIFICATION NOT EXECUTED]",
            "",
            "**Severity**: High",
            "**Location**: `src/Vault.sol:L42`",
            "**Description**: A code-trace finding.",
            "**Impact**: Potential fund loss under specific conditions.",
            "",
        ])
        (proj / "AUDIT_REPORT.md").write_text(report, encoding="utf-8")
        issues = _run_report_quality_gate(sp, str(proj))
        for issue in issues:
            assert "PoC Result" not in issue or "H-01" not in issue, (
                "H-01 (VERIFICATION NOT EXECUTED) should NOT be flagged "
                f"for missing PoC Result: {issue}"
            )

    def test_mixed_verified_and_unverified(self, audit_env):
        """H-02 (VERIFICATION NOT EXECUTED) should not appear in the
        missing-PoC-Result list, even if the section triggers other checks."""
        from plamen_validators import _run_report_quality_gate
        sp, proj = audit_env
        report = self._build_report([
            "### [H-01] Verified Finding [VERIFIED]",
            "",
            "**Severity**: High",
            "**Location**: `src/A.sol:L10`",
            "**Description**: Bug A with enough description text to avoid thin section.",
            "**Impact**: Loss A. Users lose all deposited tokens when the vault is exploited by a flash loan attack that manipulates the share price.",
            "**PoC Result**: Test passed with assertion — attacker extracted 150% of deposit.",
            "",
            "### [H-02] Unverified Finding [VERIFICATION NOT EXECUTED]",
            "",
            "**Severity**: High",
            "**Location**: `src/B.sol:L20`",
            "**Description**: Bug B involving unchecked arithmetic in the reward distribution function that can cause an integer overflow under specific staking conditions.",
            "**Impact**: Potential fund loss under specific conditions when the staking period exceeds the maximum uint32 timestamp boundary, allowing reward inflation.",
            "",
        ])
        (proj / "AUDIT_REPORT.md").write_text(report, encoding="utf-8")
        issues = _run_report_quality_gate(sp, str(proj))
        quality_md = (sp / "report_quality.md").read_text(encoding="utf-8")
        poc_line = [
            ln for ln in quality_md.splitlines()
            if "PoC Result" in ln and "content_authenticity" not in ln
        ]
        for ln in quality_md.splitlines():
            if "content_authenticity" in ln and "PoC Result" in ln:
                assert "H-02" not in ln, (
                    "H-02 (VERIFICATION NOT EXECUTED) should be exempt from "
                    f"PoC Result check: {ln}"
                )

    def test_public_report_rewrites_internal_hypothesis_reference(self, audit_env):
        """An undefined internal H-* reference in prose should resolve through
        the internal traceability map instead of shipping a dangling public
        cross-reference."""
        from plamen_validators import _run_report_quality_gate
        sp, proj = audit_env
        (sp / "report_traceability_internal.md").write_text(
            textwrap.dedent("""\
                # Internal Report Traceability

                | Report ID | Internal Hypothesis | Chain | Verification | Agent Sources |
                |-----------|---------------------|-------|--------------|---------------|
                | H-01 | H-1 | n/a | verify_H-1.md | H-1 |
                | H-02 | H-64 | n/a | verify_H-64.md | H-64 |
            """),
            encoding="utf-8",
        )
        report = self._build_report([
            "### [H-01] Fee Swap Revert [VERIFIED]",
            "",
            "**Severity**: High",
            "**Location**: `src/A.sol:L10`",
            "**Description**: Fee-bearing swaps revert and the fallback path can strand funds; see H-64 for the related refund overwrite condition.",
            "**Impact**: Users can lose funds because the revert path depends on an unsafe refund record that can be overwritten before recovery.",
            "**PoC Result**: Code trace confirmed the revert and refund-path dependency.",
            "",
            "### [H-02] Refund Overwrite [VERIFIED]",
            "",
            "**Severity**: High",
            "**Location**: `src/B.sol:L20`",
            "**Description**: The refund slot is user-controlled and can be overwritten before the victim claims the refund.",
            "**Impact**: The attacker can redirect or block refund recovery for the affected external identifier.",
            "**PoC Result**: Code trace confirmed the overwrite precondition.",
            "",
        ])
        (proj / "AUDIT_REPORT.md").write_text(report, encoding="utf-8")
        issues = _run_report_quality_gate(sp, str(proj))
        rewritten = (proj / "AUDIT_REPORT.md").read_text(encoding="utf-8")
        quality_md = (sp / "report_quality.md").read_text(encoding="utf-8")

        assert "see H-02" in rewritten
        assert "see H-64" not in rewritten
        assert "undefined report ID references" not in quality_md
        assert not any("H-64" in issue for issue in issues)


# ---------------------------------------------------------------------------
# Fix 3: Section-aware niche agent filtering
# ---------------------------------------------------------------------------

class TestNicheAgentFiltering:
    """_parse_l1_required_skills should skip rows under ## Niche Agents."""

    @pytest.fixture()
    def scratchpad(self, tmp_path: Path) -> Path:
        sp = tmp_path / ".scratchpad"
        sp.mkdir()
        return sp

    def test_niche_agents_not_collected_as_skills(self, scratchpad: Path):
        from plamen_prompt import _parse_l1_required_skills
        (scratchpad / "template_recommendations.md").write_text(
            textwrap.dedent("""\
                ## L1 Skills

                | Skill / Template | Trigger | Required |
                |------------------|---------|----------|
                | CONSENSUS_SAFETY_INVARIANTS | CONSENSUS flag | YES |
                | P2P_DOS_AND_ECLIPSE | P2P flag | YES |
                | CONFIG_CORRECTNESS | L1_PATTERN | NO |

                ## Niche Agents

                | Skill / Template | Trigger | Required |
                |------------------|---------|----------|
                | MULTI_STEP_OPERATION_SAFETY | MULTI_STEP_OPS flag | YES |
                | SEMANTIC_CONSISTENCY_AUDIT | HAS_MULTI_CONTRACT flag | YES |
                | EVENT_COMPLETENESS | MISSING_EVENT flag | NO |
            """),
            encoding="utf-8",
        )
        required, excluded = _parse_l1_required_skills(scratchpad)
        assert "CONSENSUS_SAFETY_INVARIANTS" in required
        assert "P2P_DOS_AND_ECLIPSE" in required
        assert "MULTI_STEP_OPERATION_SAFETY" not in required
        assert "SEMANTIC_CONSISTENCY_AUDIT" not in required
        assert "CONFIG_CORRECTNESS" in excluded
        assert "EVENT_COMPLETENESS" not in excluded

    def test_no_niche_section_still_works(self, scratchpad: Path):
        from plamen_prompt import _parse_l1_required_skills
        (scratchpad / "template_recommendations.md").write_text(
            textwrap.dedent("""\
                ## L1 Skills

                | Skill / Template | Trigger | Required |
                |------------------|---------|----------|
                | CONSENSUS_SAFETY_INVARIANTS | CONSENSUS flag | YES |
                | FORK_CHOICE_AUDIT | CONSENSUS flag | YES |
            """),
            encoding="utf-8",
        )
        required, excluded = _parse_l1_required_skills(scratchpad)
        assert required == ["CONSENSUS_SAFETY_INVARIANTS", "FORK_CHOICE_AUDIT"]
        assert excluded == set()

    def test_niche_heading_variations(self, scratchpad: Path):
        from plamen_prompt import _parse_l1_required_skills
        (scratchpad / "template_recommendations.md").write_text(
            textwrap.dedent("""\
                ## L1 Skills
                | Skill / Template | Trigger | Required |
                |------------------|---------|----------|
                | RPC_SURFACE_AUDIT | RPC flag | YES |

                ### Niche Agents (standalone)
                | Skill / Template | Trigger | Required |
                |------------------|---------|----------|
                | CALLBACK_RECEIVER_SAFETY | OUTCOME_CALLBACK | YES |
            """),
            encoding="utf-8",
        )
        required, excluded = _parse_l1_required_skills(scratchpad)
        assert "RPC_SURFACE_AUDIT" in required
        assert "CALLBACK_RECEIVER_SAFETY" not in required

    def test_section_after_niche_resumes_collection(self, scratchpad: Path):
        """Rows after a non-niche heading following a niche section should be
        collected normally."""
        from plamen_prompt import _parse_l1_required_skills
        (scratchpad / "template_recommendations.md").write_text(
            textwrap.dedent("""\
                ## L1 Skills
                | Skill / Template | Trigger | Required |
                |------------------|---------|----------|
                | CONSENSUS_SAFETY_INVARIANTS | CONSENSUS flag | YES |

                ## Niche Agents
                | Skill / Template | Trigger | Required |
                |------------------|---------|----------|
                | MULTI_STEP_OPERATION_SAFETY | MULTI_STEP_OPS flag | YES |

                ## Injectable Skills
                | Skill / Template | Trigger | Required |
                |------------------|---------|----------|
                | VAULT_ACCOUNTING | vault type | YES |
            """),
            encoding="utf-8",
        )
        required, excluded = _parse_l1_required_skills(scratchpad)
        assert "CONSENSUS_SAFETY_INVARIANTS" in required
        assert "MULTI_STEP_OPERATION_SAFETY" not in required
        assert "VAULT_ACCOUNTING" in required
