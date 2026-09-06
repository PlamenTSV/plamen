"""Tests for proposal-only skeptic challenges + mechanical dedup fallback."""
from __future__ import annotations

import re
from pathlib import Path
from textwrap import dedent

import pytest

import plamen_validators as V
import plamen_mechanical as M
from plamen_types import plamen_home
from semantic_dedup_authority import extract_finding_records


def _live_ids(text: str) -> set[str]:
    return set(extract_finding_records(text))


# ═══════════════════════════════════════════════════════════════════════
# P0: Skeptic-Judge DOWNGRADE severity integration
# ═══════════════════════════════════════════════════════════════════════

class TestSkepticJudgeDowngrade:
    """Legacy Markdown proposals cannot directly alter report severity."""

    def _write_judge(self, tmp_path: Path, content: str) -> None:
        (tmp_path / "skeptic_judge_decisions.md").write_text(
            content, encoding="utf-8",
        )

    # -- Parser tests --

    def test_parse_standard_table(self, tmp_path):
        self._write_judge(tmp_path, dedent("""\
            # Skeptic Judge Decisions

            | Finding ID | Original Severity | Final Severity | Decision | Rationale |
            |------------|-------------------|----------------|----------|-----------|
            | INV-001 | High | High | KEEP | reason |
            | INV-002 | High | Medium | DOWNGRADE | reason |
            | INV-003 | High | Low | DOWNGRADE | reason |
            | INV-004 | High | Medium | UNRESOLVED | reason |
        """))
        result = V._collect_judge_downgrade_map(tmp_path)
        assert result == {}

    def test_empty_file(self, tmp_path):
        self._write_judge(tmp_path, "")
        assert V._collect_judge_downgrade_map(tmp_path) == {}

    def test_missing_file(self, tmp_path):
        assert V._collect_judge_downgrade_map(tmp_path) == {}

    def test_no_downgrade_rows(self, tmp_path):
        self._write_judge(tmp_path, dedent("""\
            | Finding ID | Original Severity | Final Severity | Decision | Rationale |
            |------------|-------------------|----------------|----------|-----------|
            | INV-001 | High | High | KEEP | reason |
            | INV-002 | High | Medium | UNRESOLVED | reason |
        """))
        assert V._collect_judge_downgrade_map(tmp_path) == {}

    def test_severity_normalization(self, tmp_path):
        self._write_judge(tmp_path, dedent("""\
            | Finding ID | Original Severity | Final Severity | Decision | Rationale |
            |------------|-------------------|----------------|----------|-----------|
            | INV-005 | high | medium | DOWNGRADE | reason |
            | INV-006 | High | low | DOWNGRADE | reason |
        """))
        result = V._collect_judge_downgrade_map(tmp_path)
        assert result == {}

    def test_l1_judge_format(self, tmp_path):
        """Parse a representative format from an L1 Codex audit."""
        self._write_judge(tmp_path, dedent("""\
            # Skeptic Judge Decisions

            | Finding ID | Original Severity | Final Severity | Decision | Rationale |
            |------------|-------------------|----------------|----------|-----------|
            | INV-001 | High | High | KEEP | reason one |
            | INV-002 | High | Medium | DOWNGRADE | reason two |
            | INV-003 | High | Medium | DOWNGRADE | reason three |
            | INV-004 | High | High | KEEP | reason four |
            | INV-011 | High | Medium | UNRESOLVED | reason five |
            | INV-012 | High | Low | DOWNGRADE | reason six |
        """))
        result = V._collect_judge_downgrade_map(tmp_path)
        assert result == {}

    def test_malformed_rows_skipped(self, tmp_path):
        self._write_judge(tmp_path, dedent("""\
            | Finding ID | Original Severity | Final Severity | Decision | Rationale |
            |------------|-------------------|----------------|----------|-----------|
            | INV-001 | High | Medium | DOWNGRADE | reason |
            | bad row |
            not a table row
            | INV-002 | High | Medium | DOWNGRADE | reason |
        """))
        result = V._collect_judge_downgrade_map(tmp_path)
        assert result == {}

    # -- Integration with _write_mechanical_report_index --

    def _make_report_index_scratchpad(self, tmp_path, downgrades=None):
        """Build minimal scratchpad for _write_mechanical_report_index."""
        # verification_queue.md
        queue_lines = [
            "# Verification Queue",
            "",
            "| Finding ID | Title | Severity | Location | Preferred Verification | Evidence Tag |",
            "|------------|-------|----------|----------|----------------------|--------------|",
            "| INV-001 | Bug One | High | file.rs:L10 | CODE-TRACE | [CODE-TRACE] |",
            "| INV-002 | Bug Two | High | file.rs:L20 | CODE-TRACE | [CODE-TRACE] |",
            "| INV-003 | Bug Three | High | file.rs:L30 | CODE-TRACE | [CODE-TRACE] |",
        ]
        (tmp_path / "verification_queue.md").write_text(
            "\n".join(queue_lines), encoding="utf-8",
        )
        # verify files (minimal CONFIRMED stubs)
        for fid in ("INV-001", "INV-002", "INV-003"):
            (tmp_path / f"verify_{fid}.md").write_text(
                f"# Verification: {fid}\n\n"
                f"**Verdict**: CONFIRMED\n"
                f"**Severity**: High\n"
                f"**Location**: file.rs:L10\n"
                f"**Evidence Tag**: [CODE-TRACE]\n",
                encoding="utf-8",
            )
        # skeptic_judge_decisions.md
        if downgrades:
            lines = [
                "| Finding ID | Original Severity | Final Severity | Decision | Rationale |",
                "|------------|-------------------|----------------|----------|-----------|",
            ]
            for fid, orig, final, dec in downgrades:
                lines.append(f"| {fid} | {orig} | {final} | {dec} | reason |")
            self._write_judge(tmp_path, "\n".join(lines))

    def test_downgrade_proposal_does_not_change_report_index(self, tmp_path):
        self._make_report_index_scratchpad(tmp_path, downgrades=[
            ("INV-002", "High", "Medium", "DOWNGRADE"),
        ])
        count = M._write_mechanical_report_index(tmp_path)
        assert count > 0
        text = (tmp_path / "report_index.md").read_text(encoding="utf-8")
        # Both remain High until separate typed adjudication authorizes a change.
        lines = [l for l in text.splitlines() if l.strip().startswith("|")]
        inv002_line = [l for l in lines if "INV-002" in l]
        assert inv002_line, "INV-002 should be in report_index.md"
        assert "High" in inv002_line[0] and "H-" in inv002_line[0]
        assert "Medium" not in inv002_line[0]

    def test_downgrade_proposal_produces_no_adjustment_tag(self, tmp_path):
        self._make_report_index_scratchpad(tmp_path, downgrades=[
            ("INV-002", "High", "Medium", "DOWNGRADE"),
        ])
        M._write_mechanical_report_index(tmp_path)
        text = (tmp_path / "report_index.md").read_text(encoding="utf-8")
        assert "SKEPTIC-DOWNGRADE" not in text

    def test_keep_not_applied(self, tmp_path):
        self._make_report_index_scratchpad(tmp_path, downgrades=[
            ("INV-002", "High", "High", "KEEP"),
        ])
        M._write_mechanical_report_index(tmp_path)
        text = (tmp_path / "report_index.md").read_text(encoding="utf-8")
        assert "SKEPTIC-DOWNGRADE" not in text

    def test_unresolved_takes_precedence_over_downgrade(self, tmp_path):
        """If a finding is UNRESOLVED, the DOWNGRADE should NOT additionally apply."""
        self._make_report_index_scratchpad(tmp_path, downgrades=[
            ("INV-002", "High", "Medium", "DOWNGRADE"),
        ])
        # Make INV-002's verify file show UNRESOLVED
        (tmp_path / "verify_INV-002.md").write_text(
            "# Verification: INV-002\n\n"
            "**Verdict**: UNRESOLVED\n"
            "**Severity**: High\n"
            "**Location**: file.rs:L20\n"
            "**Evidence Tag**: [CODE-TRACE]\n",
            encoding="utf-8",
        )
        M._write_mechanical_report_index(tmp_path)
        text = (tmp_path / "report_index.md").read_text(encoding="utf-8")
        # UNRESOLVED should apply (demote once: High→Medium)
        # DOWNGRADE should NOT apply on top
        assert "UNRESOLVED" in text
        assert "SKEPTIC-DOWNGRADE" not in text

    def test_no_judge_file_is_noop(self, tmp_path):
        self._make_report_index_scratchpad(tmp_path, downgrades=None)
        M._write_mechanical_report_index(tmp_path)
        text = (tmp_path / "report_index.md").read_text(encoding="utf-8")
        assert "SKEPTIC-DOWNGRADE" not in text

    def test_downgrade_does_not_upgrade(self, tmp_path):
        """If finding is already Medium and judge says Medium, no change."""
        (tmp_path / "verification_queue.md").write_text(
            "# Verification Queue\n\n"
            "| Finding ID | Title | Severity | Location | Preferred Verification | Evidence Tag |\n"
            "|------------|-------|----------|----------|----------------------|--------------||\n"
            "| INV-001 | Bug | Medium | file.rs:L10 | CODE-TRACE | [CODE-TRACE] |\n",
            encoding="utf-8",
        )
        (tmp_path / "verify_INV-001.md").write_text(
            "# Verification: INV-001\n\n"
            "**Verdict**: CONFIRMED\n"
            "**Severity**: Medium\n"
            "**Evidence Tag**: [CODE-TRACE]\n",
            encoding="utf-8",
        )
        self._write_judge(tmp_path, dedent("""\
            | Finding ID | Original Severity | Final Severity | Decision | Rationale |
            |------------|-------------------|----------------|----------|-----------|
            | INV-001 | High | Medium | DOWNGRADE | reason |
        """))
        M._write_mechanical_report_index(tmp_path)
        text = (tmp_path / "report_index.md").read_text(encoding="utf-8")
        # Already Medium, cap at Medium = no change, no tag
        assert "SKEPTIC-DOWNGRADE" not in text


# ═══════════════════════════════════════════════════════════════════════
# P1: Mechanical dedup fallback on PASSTHROUGH
# ═══════════════════════════════════════════════════════════════════════

class TestMechanicalDedupFallback:
    """_apply_mechanical_dedup_from_pairs tests."""

    def _write_pairs(self, tmp_path: Path, content: str) -> None:
        (tmp_path / "dedup_candidate_pairs.md").write_text(
            content, encoding="utf-8",
        )

    def _write_inventory(self, tmp_path: Path, ids: list[str]) -> None:
        lines = [
            "# Findings Inventory",
            "",
            "| Finding ID | Title | Severity | Location |",
            "|------------|-------|----------|----------|",
        ]
        for fid in ids:
            lines.append(f"| {fid} | Bug {fid} | High | file.rs:L10 |")
        (tmp_path / "findings_inventory.md").write_text(
            "\n".join(lines), encoding="utf-8",
        )

    def test_source_id_subset_merge(self, tmp_path):
        self._write_pairs(tmp_path, dedent("""\
            # Dedup Candidate Pairs

            | Finding A | Finding B | Title Score | Signal(s) | Same Sev? |
            |-----------|-----------|-------------|-----------|-----------|
            | INV-001: Bug One | INV-002: Bug Two | 0.30 | source-ID subset (D-1 ⊂ D-1, D-2) | Yes |
        """))
        self._write_inventory(tmp_path, ["INV-001", "INV-002", "INV-003"])
        n = M._apply_mechanical_dedup_from_pairs(tmp_path, "semantic_dedup")
        assert n == 1
        dec = (tmp_path / "dedup_decisions.md").read_text(encoding="utf-8")
        assert "MECHANICAL_MERGE" in dec
        assert "MECHANICAL_FALLBACK" in dec
        deduped = (tmp_path / "findings_inventory_deduped.md").read_text(encoding="utf-8")
        # INV-001 is the subset → absorbed
        assert "INV-001" not in _live_ids(deduped)
        assert "INV-002" in deduped
        assert "INV-003" in deduped

    def test_pert_lineage_merge(self, tmp_path):
        self._write_pairs(tmp_path, dedent("""\
            # Dedup Candidate Pairs

            | Finding A | Finding B | Title Score | Signal(s) | Same Sev? |
            |-----------|-----------|-------------|-----------|-----------|
            | INV-005: Parent bug | INV-006: PERT variant | 0.45 | PERT lineage (shared depth source IDs) | Yes |
        """))
        self._write_inventory(tmp_path, ["INV-005", "INV-006"])
        n = M._apply_mechanical_dedup_from_pairs(tmp_path, "semantic_dedup")
        assert n == 1

    def test_different_severity_not_merged(self, tmp_path):
        self._write_pairs(tmp_path, dedent("""\
            # Dedup Candidate Pairs

            | Finding A | Finding B | Title Score | Signal(s) | Same Sev? |
            |-----------|-----------|-------------|-----------|-----------|
            | INV-001: Bug | INV-002: Bug | 0.80 | source-ID subset (D-1 ⊂ D-1, D-2) | No |
        """))
        self._write_inventory(tmp_path, ["INV-001", "INV-002"])
        n = M._apply_mechanical_dedup_from_pairs(tmp_path, "semantic_dedup")
        assert n == 0

    def test_title_overlap_only_not_merged(self, tmp_path):
        self._write_pairs(tmp_path, dedent("""\
            # Dedup Candidate Pairs

            | Finding A | Finding B | Title Score | Signal(s) | Same Sev? |
            |-----------|-----------|-------------|-----------|-----------|
            | INV-001: Bug | INV-002: Bug | 0.90 | title overlap 0.90 | Yes |
        """))
        self._write_inventory(tmp_path, ["INV-001", "INV-002"])
        n = M._apply_mechanical_dedup_from_pairs(tmp_path, "semantic_dedup")
        assert n == 0

    def test_location_overlap_only_not_merged(self, tmp_path):
        self._write_pairs(tmp_path, dedent("""\
            # Dedup Candidate Pairs

            | Finding A | Finding B | Title Score | Signal(s) | Same Sev? |
            |-----------|-----------|-------------|-----------|-----------|
            | INV-001: Bug | INV-002: Bug | 0.10 | location overlap (L10-15 vs L12-18) | Yes |
        """))
        self._write_inventory(tmp_path, ["INV-001", "INV-002"])
        n = M._apply_mechanical_dedup_from_pairs(tmp_path, "semantic_dedup")
        assert n == 0

    def test_no_pairs_file(self, tmp_path):
        n = M._apply_mechanical_dedup_from_pairs(tmp_path, "semantic_dedup")
        assert n == 0

    def test_no_candidate_pairs(self, tmp_path):
        self._write_pairs(tmp_path, "# Dedup Candidate Pairs\n\nNo candidate duplicate pairs found.\n")
        n = M._apply_mechanical_dedup_from_pairs(tmp_path, "semantic_dedup")
        assert n == 0

    def test_sc_dedup_phase(self, tmp_path):
        """SC dedup reads findings_inventory.md, writes findings_inventory_deduped.md."""
        self._write_pairs(tmp_path, dedent("""\
            # Dedup Candidate Pairs

            | Finding A | Finding B | Title Score | Signal(s) | Same Sev? |
            |-----------|-----------|-------------|-----------|-----------|
            | INV-001: Bug | INV-002: Bug | 0.30 | source-ID subset (D-1 ⊂ D-1, D-2) | Yes |
        """))
        self._write_inventory(tmp_path, ["INV-001", "INV-002", "INV-003"])
        n = M._apply_mechanical_dedup_from_pairs(tmp_path, "sc_semantic_dedup")
        assert n == 1
        deduped = (tmp_path / "findings_inventory_deduped.md").read_text(encoding="utf-8")
        assert "INV-001" not in _live_ids(deduped)
        assert "INV-002" in deduped

    def test_multi_merge_no_double_absorb(self, tmp_path):
        """If INV-001 matches both INV-002 and INV-003, only first absorb applies."""
        self._write_pairs(tmp_path, dedent("""\
            # Dedup Candidate Pairs

            | Finding A | Finding B | Title Score | Signal(s) | Same Sev? |
            |-----------|-----------|-------------|-----------|-----------|
            | INV-001: Bug | INV-002: Bug | 0.30 | source-ID subset (D-1 ⊂ D-1, D-2) | Yes |
            | INV-001: Bug | INV-003: Bug | 0.30 | PERT lineage (shared depth source IDs) | Yes |
        """))
        self._write_inventory(tmp_path, ["INV-001", "INV-002", "INV-003"])
        n = M._apply_mechanical_dedup_from_pairs(tmp_path, "semantic_dedup")
        # INV-001 absorbed once (into INV-002), second pair skipped
        assert n == 1

    def test_combined_signals_merge(self, tmp_path):
        """source-ID subset + location overlap should merge (strong signal present)."""
        self._write_pairs(tmp_path, dedent("""\
            # Dedup Candidate Pairs

            | Finding A | Finding B | Title Score | Signal(s) | Same Sev? |
            |-----------|-----------|-------------|-----------|-----------|
            | INV-001: Bug | INV-002: Bug | 0.60 | source-ID subset (D-1 ⊂ D-1, D-2) + location overlap (L10-15 vs L12-18) | Yes |
        """))
        self._write_inventory(tmp_path, ["INV-001", "INV-002"])
        n = M._apply_mechanical_dedup_from_pairs(tmp_path, "semantic_dedup")
        assert n == 1


# ═══════════════════════════════════════════════════════════════════════
# P1 prompt rule: phase6-report-prompts.md DOWNGRADE rule
# ═══════════════════════════════════════════════════════════════════════

class TestPromptDowngradeRule:

    def test_skeptic_rule_is_proposal_only(self):
        path = plamen_home() / "rules" / "phase6-report-prompts.md"
        assert path.is_file(), "report authority prompt is required packaging"
        text = path.read_text(encoding="utf-8")
        assert "skeptic artifacts are proposal-only" in text
        assert "absent/stale/ambiguous authority preserves severity and body placement" in text
        assert "MUST NOT lower severity, exclude, refute, merge, or close" in text
        assert "skeptic_judge_decisions.md" not in text

    def test_challenge_boundary_precedes_poc_caps(self):
        path = plamen_home() / "rules" / "phase6-report-prompts.md"
        assert path.is_file(), "report authority prompt is required packaging"
        text = path.read_text(encoding="utf-8")
        unresolved_pos = text.find("**UNRESOLVED/PARTIAL**")
        challenge_pos = text.find("**Skeptic boundary**")
        poc_pos = text.find("**PoC-fail proposal boundary**")
        assert min(unresolved_pos, challenge_pos, poc_pos) >= 0
        assert unresolved_pos < challenge_pos < poc_pos
