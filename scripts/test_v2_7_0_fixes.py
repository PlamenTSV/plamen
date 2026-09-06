"""Tests for v2.7.0 supplemental mechanical dedup feature.

Covers the ``supplemental=True`` keyword argument added to
``_apply_mechanical_dedup_from_pairs`` in plamen_mechanical.py.
"""
from __future__ import annotations

import re
from pathlib import Path
from textwrap import dedent

import pytest

import plamen_mechanical as M
from semantic_dedup_authority import extract_finding_records


def _live_ids(text: str) -> set[str]:
    return set(extract_finding_records(text))


# ═══════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════

_FULL_HEADER = (
    "| Finding A | Finding B | Title Score | Signal(s) | Same Sev? |\n"
    "|-----------|-----------|-------------|-----------|-----------|"
)

_INV_HEADER = (
    "| Finding ID | Title | Severity | Location |\n"
    "|------------|-------|----------|----------|"
)


def _write_full_pairs(scratchpad: Path, rows: list[str]) -> None:
    """Write ``dedup_candidate_pairs_full.md`` with header + rows."""
    lines = ["# Dedup Candidate Pairs (Full)", "", _FULL_HEADER]
    lines.extend(rows)
    lines.append("")
    (scratchpad / "dedup_candidate_pairs_full.md").write_text(
        "\n".join(lines), encoding="utf-8",
    )


def _write_live_pairs(scratchpad: Path, rows: list[str]) -> None:
    """Write ``dedup_candidate_pairs.md`` with header + rows."""
    lines = ["# Dedup Candidate Pairs", "", _FULL_HEADER]
    lines.extend(rows)
    lines.append("")
    (scratchpad / "dedup_candidate_pairs.md").write_text(
        "\n".join(lines), encoding="utf-8",
    )


def _write_inventory(scratchpad: Path, finding_ids: list[str]) -> None:
    """Write ``findings_inventory.md`` with pipe-delimited table."""
    lines = ["# Findings Inventory", "", _INV_HEADER]
    for fid in finding_ids:
        lines.append(f"| {fid} | Bug {fid} | Critical | file.rs:L10 |")
    lines.append("")
    (scratchpad / "findings_inventory.md").write_text(
        "\n".join(lines), encoding="utf-8",
    )


def _write_decisions(scratchpad: Path, content: str) -> None:
    """Write ``dedup_decisions.md`` with given content."""
    (scratchpad / "dedup_decisions.md").write_text(
        content, encoding="utf-8",
    )


# ═══════════════════════════════════════════════════════════════════════
# TestSupplementalMechanicalDedup
# ═══════════════════════════════════════════════════════════════════════

class TestSupplementalMechanicalDedup:
    """Tests for the ``supplemental=True`` mode of
    ``_apply_mechanical_dedup_from_pairs``."""

    # ------------------------------------------------------------------
    # 1. supplemental reads the _full file preferentially
    # ------------------------------------------------------------------
    def test_supplemental_reads_full_file(self, tmp_path: Path):
        """Create both _full.md (with a mergeable pair) and regular _pairs.md
        (empty table). supplemental=True should read the full file."""
        _write_full_pairs(tmp_path, [
            "| INV-001: CUDA kernel writes | INV-002: CUDA Kernel Writes"
            " | 1.00 | location overlap (L117-120 vs L117-120)"
            " + title overlap 1.00 | Yes |",
        ])
        # Regular file has an empty table (no data rows)
        _write_live_pairs(tmp_path, [])
        _write_inventory(tmp_path, ["INV-001", "INV-002"])
        n = M._apply_mechanical_dedup_from_pairs(
            tmp_path, "semantic_dedup", supplemental=True,
        )
        assert n == 1, "Should merge from the full file"

    # ------------------------------------------------------------------
    # 2. supplemental falls back to regular pairs file but live-pair
    #    exclusion blocks everything (all pairs were LLM-evaluated)
    # ------------------------------------------------------------------
    def test_supplemental_fallback_to_regular_returns_zero(self, tmp_path: Path):
        """No full file exists. Falls back to dedup_candidate_pairs.md but
        all pairs in that file are also in the live exclusion set → 0 merges.
        This is correct: if the full file doesn't exist, the LLM already
        evaluated every pair."""
        _write_live_pairs(tmp_path, [
            "| INV-001: Bug A | INV-002: Bug A"
            " | 1.00 | location overlap (L10-20 vs L10-20)"
            " + title overlap 1.00 | Yes |",
        ])
        _write_inventory(tmp_path, ["INV-001", "INV-002"])
        n = M._apply_mechanical_dedup_from_pairs(
            tmp_path, "semantic_dedup", supplemental=True,
        )
        assert n == 0, "Live-pair exclusion should block all pairs from the live file"

    # ------------------------------------------------------------------
    # 3. location overlap + title 1.00 + same sev merges
    # ------------------------------------------------------------------
    def test_supplemental_accepts_location_overlap_title_1(self, tmp_path: Path):
        """Location overlap + title_score >= 1.00 + same sev should merge.
        Higher INV# (INV-002) absorbed into lower (INV-001)."""
        _write_full_pairs(tmp_path, [
            "| INV-001: CUDA kernel writes | INV-002: CUDA Kernel Writes"
            " | 1.00 | location overlap (L117-120 vs L117-120)"
            " + title overlap 1.00 | Yes |",
        ])
        _write_inventory(tmp_path, ["INV-001", "INV-002"])
        n = M._apply_mechanical_dedup_from_pairs(
            tmp_path, "semantic_dedup", supplemental=True,
        )
        assert n == 1
        inventory = (tmp_path / "findings_inventory.md").read_text(encoding="utf-8")
        assert "INV-001" in inventory, "Lower INV# should be kept"
        assert "INV-002" not in _live_ids(inventory), "Higher INV# should be absorbed"

    # ------------------------------------------------------------------
    # 4. location overlap + low title score rejects
    # ------------------------------------------------------------------
    def test_supplemental_rejects_location_overlap_low_title(self, tmp_path: Path):
        """Overlapping-but-NOT-exact location with title 0.60 (< 1.0) must NOT
        merge.

        v2.x FIX #5 narrowly relaxed supplemental dedup so an EXACT file:line
        match (identical line range) + same severity tier merges at title >=
        0.5. This test guards the boundary: when the two line ranges overlap
        but are NOT identical (L117-120 vs L118-121), the relaxed path must not
        fire and the strict title>=1.0 path also does not apply, so n == 0.
        """
        _write_full_pairs(tmp_path, [
            "| INV-001: Bug Alpha | INV-002: Bug Beta"
            " | 0.60 | location overlap (L117-120 vs L118-121)"
            " + title overlap 0.60 | Yes |",
        ])
        _write_inventory(tmp_path, ["INV-001", "INV-002"])
        n = M._apply_mechanical_dedup_from_pairs(
            tmp_path, "semantic_dedup", supplemental=True,
        )
        assert n == 0

    def test_supplemental_exact_location_same_tier_low_title_merges(self, tmp_path: Path):
        """v2.x FIX #5: EXACT file:line + same severity tier merges at title
        >= 0.5 even though title < 1.0 (the prior strict threshold)."""
        _write_full_pairs(tmp_path, [
            "| INV-001: Bug Alpha | INV-002: Bug Beta"
            " | 0.60 | location overlap (L117-120 vs L117-120)"
            " + title overlap 0.60 | Yes |",
        ])
        _write_inventory(tmp_path, ["INV-001", "INV-002"])
        n = M._apply_mechanical_dedup_from_pairs(
            tmp_path, "semantic_dedup", supplemental=True,
        )
        assert n == 1

    def test_supplemental_exact_single_line_merges(self, tmp_path: Path):
        """v2.x FIX #5 boundary: a single-line exact match (L42-42 vs L42-42)
        is still an exact endpoint match and merges at title >= 0.5."""
        _write_full_pairs(tmp_path, [
            "| INV-001: Bug Alpha | INV-002: Bug Beta"
            " | 0.55 | location overlap (L42-42 vs L42-42)"
            " + title overlap 0.55 | Yes |",
        ])
        _write_inventory(tmp_path, ["INV-001", "INV-002"])
        n = M._apply_mechanical_dedup_from_pairs(
            tmp_path, "semantic_dedup", supplemental=True,
        )
        assert n == 1

    def test_supplemental_exact_location_title_below_floor_rejects(self, tmp_path: Path):
        """v2.x FIX #5 recall guard: even an EXACT line range must NOT merge
        when title score is below the 0.5 relaxed floor. The relax never
        merges purely on location identity; a title-similarity floor remains."""
        _write_full_pairs(tmp_path, [
            "| INV-001: Bug Alpha | INV-002: Wholly Unrelated Issue"
            " | 0.40 | location overlap (L117-120 vs L117-120)"
            " + title overlap 0.40 | Yes |",
        ])
        _write_inventory(tmp_path, ["INV-001", "INV-002"])
        n = M._apply_mechanical_dedup_from_pairs(
            tmp_path, "semantic_dedup", supplemental=True,
        )
        assert n == 0, "exact line range alone (title < 0.5) must NOT merge"

    def test_supplemental_adjacent_exact_subrange_rejects(self, tmp_path: Path):
        """v2.x FIX #5 recall guard: a contained-but-not-identical range
        (L10-30 vs L15-20) shares lines but is NOT an exact endpoint match,
        so the relaxed path must not fire at title 0.9 (< strict 1.0)."""
        _write_full_pairs(tmp_path, [
            "| INV-001: Bug Alpha | INV-002: Bug Beta"
            " | 0.90 | location overlap (L10-30 vs L15-20)"
            " + title overlap 0.90 | Yes |",
        ])
        _write_inventory(tmp_path, ["INV-001", "INV-002"])
        n = M._apply_mechanical_dedup_from_pairs(
            tmp_path, "semantic_dedup", supplemental=True,
        )
        assert n == 0, "contained-but-not-identical range must NOT merge below title 1.0"

    def test_supplemental_exact_match_absorbed_recorded_as_merged(self, tmp_path: Path):
        """v2.x FIX #5 recall guard: a relax-merged finding is recorded as
        MERGED in the coverage ledger (via dedup_decisions.md), never silently
        dropped. The absorbed ID must be recoverable downstream."""
        _write_full_pairs(tmp_path, [
            "| INV-001: Bug Alpha | INV-002: Bug Beta"
            " | 0.55 | location overlap (L117-120 vs L117-120)"
            " + title overlap 0.55 | Yes |",
        ])
        _write_inventory(tmp_path, ["INV-001", "INV-002"])
        n = M._apply_mechanical_dedup_from_pairs(
            tmp_path, "semantic_dedup", supplemental=True,
        )
        assert n == 1
        absorbed = M._extract_dedup_absorbed_ids(tmp_path)
        assert "INV-002" in absorbed, \
            "relax-merged finding must be recorded as absorbed (MERGED), not dropped"

    # ------------------------------------------------------------------
    # 5. different severity rejects
    # ------------------------------------------------------------------
    def test_supplemental_rejects_different_severity(self, tmp_path: Path):
        """Location overlap + title 1.00 but Same Sev = No should NOT merge."""
        _write_full_pairs(tmp_path, [
            "| INV-001: CUDA kernel writes | INV-002: CUDA Kernel Writes"
            " | 1.00 | location overlap (L117-120 vs L117-120)"
            " + title overlap 1.00 | No |",
        ])
        _write_inventory(tmp_path, ["INV-001", "INV-002"])
        n = M._apply_mechanical_dedup_from_pairs(
            tmp_path, "semantic_dedup", supplemental=True,
        )
        assert n == 0

    # ------------------------------------------------------------------
    # 6. already-merged ID skipped
    # ------------------------------------------------------------------
    def test_supplemental_skips_already_merged(self, tmp_path: Path):
        """Inventory has only INV-001 (INV-002 already removed by LLM dedup).
        Pair file has INV-001/INV-002. Should return 0 because INV-002 is
        not present in the target file."""
        _write_full_pairs(tmp_path, [
            "| INV-001: CUDA kernel writes | INV-002: CUDA Kernel Writes"
            " | 1.00 | location overlap (L117-120 vs L117-120)"
            " + title overlap 1.00 | Yes |",
        ])
        # Only INV-001 in queue — INV-002 was already removed
        _write_inventory(tmp_path, ["INV-001"])
        n = M._apply_mechanical_dedup_from_pairs(
            tmp_path, "semantic_dedup", supplemental=True,
        )
        assert n == 0

    # ------------------------------------------------------------------
    # 7. appends to existing decisions file
    # ------------------------------------------------------------------
    def test_supplemental_appends_to_decisions(self, tmp_path: Path):
        """Existing dedup_decisions.md should be preserved and the new
        MECHANICAL_SUPPLEMENT section appended."""
        existing_content = dedent("""\
            # Semantic Dedup Decisions

            **Status**: LLM_PASS

            ## Decisions

            | Action | Absorbed | Into | Signal |
            |--------|----------|------|--------|
            | LLM_MERGE | INV-010 | INV-009 | duplicate |
        """)
        _write_decisions(tmp_path, existing_content)

        _write_full_pairs(tmp_path, [
            "| INV-001: Bug A | INV-002: Bug A"
            " | 1.00 | location overlap (L10-20 vs L10-20)"
            " + title overlap 1.00 | Yes |",
        ])
        _write_inventory(tmp_path, ["INV-001", "INV-002"])
        M._apply_mechanical_dedup_from_pairs(
            tmp_path, "semantic_dedup", supplemental=True,
        )
        text = (tmp_path / "dedup_decisions.md").read_text(encoding="utf-8")
        # Original content preserved
        assert "LLM_PASS" in text
        assert "LLM_MERGE" in text
        assert "INV-010" in text
        # New section appended
        assert "MECHANICAL_SUPPLEMENT" in text
        assert "Supplemental Mechanical Dedup" in text

    # ------------------------------------------------------------------
    # 8. in-place write (no *_deduped.md created)
    # ------------------------------------------------------------------
    def test_supplemental_inplace_write(self, tmp_path: Path):
        """Supplemental mode mutates the prequeue inventory, never a queue."""
        _write_full_pairs(tmp_path, [
            "| INV-001: Bug A | INV-002: Bug A"
            " | 1.00 | location overlap (L10-20 vs L10-20)"
            " + title overlap 1.00 | Yes |",
        ])
        _write_inventory(tmp_path, ["INV-001", "INV-002", "INV-003"])
        M._apply_mechanical_dedup_from_pairs(
            tmp_path, "semantic_dedup", supplemental=True,
        )
        inventory = (tmp_path / "findings_inventory.md").read_text(encoding="utf-8")
        assert "INV-001" in inventory
        assert "INV-003" in inventory
        assert "INV-002" not in _live_ids(inventory)
        # The supplemental legacy unit operates in-place. The live L1 driver
        # wraps this proposal in the five-output prequeue transaction.
        assert not any(tmp_path.glob("verification_queue*")), \
            "L1 semantic dedup must never create or mutate a queue artifact"

    # ------------------------------------------------------------------
    # 9. source-ID subset is REJECTED in supplemental mode
    # ------------------------------------------------------------------
    def test_supplemental_rejects_source_id_subset(self, tmp_path: Path):
        """Full file has a source-ID subset pair with same-sev but no
        location overlap. Supplemental mode accepts ONLY location overlap
        + title >= 1.0; source-ID alone is too noisy for deferred pairs."""
        _write_full_pairs(tmp_path, [
            "| INV-001: Bug One | INV-002: Bug Two"
            " | 0.30 | source-ID subset (D-1 ⊂ D-1, D-2) | Yes |",
        ])
        _write_inventory(tmp_path, ["INV-001", "INV-002"])
        n = M._apply_mechanical_dedup_from_pairs(
            tmp_path, "semantic_dedup", supplemental=True,
        )
        assert n == 0, "source-ID subset without location overlap should NOT merge"

    # ------------------------------------------------------------------
    # 10. absorb direction for location overlap: higher INV# absorbed
    # ------------------------------------------------------------------
    def test_supplemental_absorb_direction_location(self, tmp_path: Path):
        """Pair: INV-005 vs INV-003 with location overlap.
        INV-005 (higher #) should be absorbed into INV-003 (lower #)."""
        _write_full_pairs(tmp_path, [
            "| INV-005: Bug X | INV-003: Bug X"
            " | 1.00 | location overlap (L50-60 vs L50-60)"
            " + title overlap 1.00 | Yes |",
        ])
        _write_inventory(tmp_path, ["INV-003", "INV-005"])
        n = M._apply_mechanical_dedup_from_pairs(
            tmp_path, "semantic_dedup", supplemental=True,
        )
        assert n == 1
        inventory = (tmp_path / "findings_inventory.md").read_text(encoding="utf-8")
        assert "INV-003" in inventory, "Lower INV# should remain"
        assert "INV-005" not in _live_ids(inventory), "Higher INV# should be absorbed"

    # ------------------------------------------------------------------
    # 11. no pair files at all -> returns 0
    # ------------------------------------------------------------------
    def test_supplemental_noop_no_full_file(self, tmp_path: Path):
        """No pair files exist at all. supplemental=True returns 0."""
        _write_inventory(tmp_path, ["INV-001", "INV-002"])
        n = M._apply_mechanical_dedup_from_pairs(
            tmp_path, "semantic_dedup", supplemental=True,
        )
        assert n == 0

    # ------------------------------------------------------------------
    # 12. regression: supplemental=False behavior unchanged
    # ------------------------------------------------------------------
    def test_regression_fallback_unchanged(self, tmp_path: Path):
        """Non-supplemental (fallback) mode should write *_deduped.md
        and overwrite dedup_decisions.md with MECHANICAL_FALLBACK."""
        _write_live_pairs(tmp_path, [
            "| INV-001: Bug One | INV-002: Bug Two"
            " | 0.30 | source-ID subset (D-1 ⊂ D-1, D-2) | Yes |",
        ])
        _write_inventory(tmp_path, ["INV-001", "INV-002"])
        n = M._apply_mechanical_dedup_from_pairs(
            tmp_path, "semantic_dedup", supplemental=False,
        )
        assert n == 1
        # Should create deduped copy (source -> target, not in-place)
        assert (tmp_path / "findings_inventory_deduped.md").exists(), \
            "fallback should derive the prequeue inventory successor"
        # Decisions file should have MECHANICAL_FALLBACK (overwrite, not append)
        dec = (tmp_path / "dedup_decisions.md").read_text(encoding="utf-8")
        assert "MECHANICAL_FALLBACK" in dec
        assert "MECHANICAL_MERGE" in dec

    # ------------------------------------------------------------------
    # 13. SC phase uses findings_inventory.md
    # ------------------------------------------------------------------
    def test_supplemental_sc_phase(self, tmp_path: Path):
        """sc_semantic_dedup phase uses findings_inventory.md as target."""
        _write_full_pairs(tmp_path, [
            "| INV-001: CUDA kernel writes | INV-002: CUDA Kernel Writes"
            " | 1.00 | location overlap (L117-120 vs L117-120)"
            " + title overlap 1.00 | Yes |",
        ])
        _write_inventory(tmp_path, ["INV-001", "INV-002"])
        n = M._apply_mechanical_dedup_from_pairs(
            tmp_path, "sc_semantic_dedup", supplemental=True,
        )
        assert n == 1
        inv = (tmp_path / "findings_inventory.md").read_text(encoding="utf-8")
        assert "INV-001" in inv, "Lower INV# should remain"
        assert "INV-002" not in _live_ids(inv), "Higher INV# should be absorbed"
        # No deduped copy for in-place mode
        assert not (tmp_path / "findings_inventory_deduped.md").exists()

    # ------------------------------------------------------------------
    # 14. multiple independent pairs all merge
    # ------------------------------------------------------------------
    def test_supplemental_multi_merge(self, tmp_path: Path):
        """Full file has 3 independent pairs all meeting criteria.
        Inventory has all 6 IDs. Should return 3."""
        _write_full_pairs(tmp_path, [
            "| INV-001: Bug A | INV-002: Bug A"
            " | 1.00 | location overlap (L10-20 vs L10-20)"
            " + title overlap 1.00 | Yes |",
            "| INV-003: Bug B | INV-004: Bug B"
            " | 1.00 | location overlap (L30-40 vs L30-40)"
            " + title overlap 1.00 | Yes |",
            "| INV-005: Bug C | INV-006: Bug C"
            " | 1.00 | location overlap (L50-60 vs L50-60)"
            " + title overlap 1.00 | Yes |",
        ])
        _write_inventory(
            tmp_path,
            ["INV-001", "INV-002", "INV-003", "INV-004", "INV-005", "INV-006"],
        )
        n = M._apply_mechanical_dedup_from_pairs(
            tmp_path, "semantic_dedup", supplemental=True,
        )
        assert n == 3
        inventory = (tmp_path / "findings_inventory.md").read_text(encoding="utf-8")
        # Lower IDs kept, higher IDs absorbed
        for kept in ("INV-001", "INV-003", "INV-005"):
            assert kept in inventory, f"{kept} should remain (lower #)"
        for absorbed in ("INV-002", "INV-004", "INV-006"):
            assert absorbed not in _live_ids(inventory), f"{absorbed} should be absorbed (higher #)"

    # ------------------------------------------------------------------
    # 15. PERT lineage rejected in supplemental mode
    # ------------------------------------------------------------------
    def test_supplemental_rejects_pert_lineage(self, tmp_path: Path):
        """PERT lineage without location overlap should NOT merge in
        supplemental mode. Source-ID and PERT are too noisy for deferred
        pairs (they share agent provenance, not root cause)."""
        _write_full_pairs(tmp_path, [
            "| INV-001: Bug One | INV-002: Bug Two"
            " | 0.50 | PERT lineage (BOUNDARY_SHIFT variant) | Yes |",
        ])
        _write_inventory(tmp_path, ["INV-001", "INV-002"])
        n = M._apply_mechanical_dedup_from_pairs(
            tmp_path, "semantic_dedup", supplemental=True,
        )
        assert n == 0, "PERT lineage without location overlap should NOT merge"

    # ------------------------------------------------------------------
    # 16. live-pair exclusion: pair in both full and live -> skipped
    # ------------------------------------------------------------------
    def test_supplemental_skips_live_pairs(self, tmp_path: Path):
        """A pair appears in both dedup_candidate_pairs_full.md and
        dedup_candidate_pairs.md (the live set). The supplemental pass
        should skip it because the LLM already evaluated it."""
        pair_row = (
            "| INV-001: Bug A | INV-002: Bug A"
            " | 1.00 | location overlap (L10-20 vs L10-20)"
            " + title overlap 1.00 | Yes |"
        )
        _write_full_pairs(tmp_path, [pair_row])
        _write_live_pairs(tmp_path, [pair_row])
        _write_inventory(tmp_path, ["INV-001", "INV-002"])
        n = M._apply_mechanical_dedup_from_pairs(
            tmp_path, "semantic_dedup", supplemental=True,
        )
        assert n == 0, "Pair already in live set should be skipped"

    # ------------------------------------------------------------------
    # 17. live-pair exclusion does not block deferred pairs
    # ------------------------------------------------------------------
    def test_supplemental_allows_deferred_pairs(self, tmp_path: Path):
        """Full file has 2 pairs: one also in live (skipped) and one
        deferred-only (merged). Verifies live exclusion is selective."""
        _write_full_pairs(tmp_path, [
            "| INV-001: Bug A | INV-002: Bug A"
            " | 1.00 | location overlap (L10-20 vs L10-20)"
            " + title overlap 1.00 | Yes |",
            "| INV-003: Bug B | INV-004: Bug B"
            " | 1.00 | location overlap (L30-40 vs L30-40)"
            " + title overlap 1.00 | Yes |",
        ])
        # Only the first pair is in the live set
        _write_live_pairs(tmp_path, [
            "| INV-001: Bug A | INV-002: Bug A"
            " | 1.00 | location overlap (L10-20 vs L10-20)"
            " + title overlap 1.00 | Yes |",
        ])
        _write_inventory(tmp_path, ["INV-001", "INV-002", "INV-003", "INV-004"])
        n = M._apply_mechanical_dedup_from_pairs(
            tmp_path, "semantic_dedup", supplemental=True,
        )
        assert n == 1, "Only deferred pair should merge; live pair should be skipped"
        inventory = (tmp_path / "findings_inventory.md").read_text(encoding="utf-8")
        assert "INV-001" in inventory, "Live-pair member should remain"
        assert "INV-002" in inventory, "Live-pair member should remain"
        assert "INV-003" in inventory, "Deferred keeper should remain"
        assert "INV-004" not in _live_ids(inventory), "Deferred absorbed should be removed"

    # ------------------------------------------------------------------
    # 18. double-absorb guard
    # ------------------------------------------------------------------
    def test_supplemental_double_absorb_guard(self, tmp_path: Path):
        """Two pairs share INV-002: INV-001/INV-002 and INV-002/INV-003.
        Only the first pair should merge; second is skipped because INV-002
        is already in the absorbed set."""
        _write_full_pairs(tmp_path, [
            "| INV-001: Bug A | INV-002: Bug A"
            " | 1.00 | location overlap (L10-20 vs L10-20)"
            " + title overlap 1.00 | Yes |",
            "| INV-002: Bug A | INV-003: Bug A"
            " | 1.00 | location overlap (L10-20 vs L10-20)"
            " + title overlap 1.00 | Yes |",
        ])
        _write_inventory(tmp_path, ["INV-001", "INV-002", "INV-003"])
        n = M._apply_mechanical_dedup_from_pairs(
            tmp_path, "semantic_dedup", supplemental=True,
        )
        assert n == 1, (
            "Second pair should be skipped because INV-002 is already absorbed"
        )
        inventory = (tmp_path / "findings_inventory.md").read_text(encoding="utf-8")
        assert "INV-001" in inventory
        assert "INV-003" in inventory
        # INV-002 absorbed by first pair
        assert "INV-002" not in _live_ids(inventory)


# ═══════════════════════════════════════════════════════════════════════
# v2.7.2: Codex depth checklist parity tests
# ═══════════════════════════════════════════════════════════════════════

from plamen_driver import _codex_depth_artifact_checklist


class TestCodexDepthChecklist:
    """Verify Codex depth checklists mention confidence_scores.md for Core."""

    def test_l1_core_mentions_confidence(self):
        text = _codex_depth_artifact_checklist("l1", "core")
        assert "confidence_scores.md" in text, (
            "L1 Core checklist must mention confidence_scores.md"
        )
        assert "2-axis" in text, (
            "L1 Core should use 2-axis, not 4-axis scoring"
        )

    def test_l1_thorough_mentions_confidence(self):
        text = _codex_depth_artifact_checklist("l1", "thorough")
        assert "confidence_scores.md" in text
        assert "3 code-evidence axes" in text

    def test_l1_core_no_design_stress(self):
        text = _codex_depth_artifact_checklist("l1", "core")
        assert "design_stress" not in text, (
            "Design stress is Thorough-only for L1"
        )

    def test_l1_core_has_post_wait_verification(self):
        text = _codex_depth_artifact_checklist("l1", "core")
        assert "Post-wait output verification" in text

    def test_sc_core_mentions_confidence(self):
        text = _codex_depth_artifact_checklist("sc", "core")
        assert "confidence_scores.md" in text, (
            "SC Core checklist must mention confidence_scores.md"
        )
        assert "2-axis" in text

    def test_sc_core_mentions_scanners(self):
        text = _codex_depth_artifact_checklist("sc", "core")
        assert "blind_spot_a" in text
        assert "blind_spot_b" in text
        assert "blind_spot_c" in text
        assert "validation_sweep" in text

    def test_sc_thorough_mentions_confidence(self):
        text = _codex_depth_artifact_checklist("sc", "thorough")
        assert "confidence_scores.md" in text
        assert "3 code-evidence axes" in text

    def test_sc_core_has_post_wait_verification(self):
        text = _codex_depth_artifact_checklist("sc", "core")
        assert "Post-wait output verification" in text

    def test_l1_thorough_has_post_wait_verification(self):
        text = _codex_depth_artifact_checklist("l1", "thorough")
        assert "Post-wait output verification" in text

    def test_l1_light_no_confidence(self):
        text = _codex_depth_artifact_checklist("l1", "light")
        assert "confidence_scores.md" not in text, (
            "Light mode should not require confidence scoring"
        )


# ═══════════════════════════════════════════════════════════════════════
# v2.7.3 tests: placeholder diagnostic + table-cell exemption
# ═══════════════════════════════════════════════════════════════════════

from plamen_validators import _has_live_placeholder_language


class TestPlaceholderDiagnostics:
    """v2.7.3: _has_live_placeholder_language returns offending line."""

    def test_returns_none_for_clean_text(self):
        assert _has_live_placeholder_language("This is normal content.") is None

    def test_returns_offending_line_not_bool(self):
        result = _has_live_placeholder_language("TODO: fill this in later")
        assert isinstance(result, str)
        assert "todo" in result.lower()

    def test_returns_specific_line(self):
        text = "Line one is fine.\nThis is a placeholder summary.\nLine three ok."
        result = _has_live_placeholder_language(text)
        assert result is not None
        assert "placeholder summary" in result

    def test_negation_still_exempts(self):
        assert _has_live_placeholder_language(
            "No placeholder markers remain."
        ) is None

    def test_code_reference_still_exempts(self):
        assert _has_live_placeholder_language(
            "The crates/validator/src/lib.rs file has a TODO comment"
        ) is None

    def test_determiner_followon_still_exempts(self):
        assert _has_live_placeholder_language(
            "the TODO about staked address check"
        ) is None


class TestTableCellExemption:
    """v2.7.3: parenthesized (todo)/(tbd) in table rows are exempted."""

    def test_table_todo_status_exempted(self):
        line = "| AS-02a | block validation | stake not verified (todo) | high |"
        assert _has_live_placeholder_language(line) is None

    def test_table_tbd_status_exempted(self):
        line = "| EP-5 | token transfer | amount check (tbd) | medium |"
        assert _has_live_placeholder_language(line) is None

    def test_table_stub_status_exempted(self):
        line = "| F-1 | auth module | admin check (stub) | low |"
        assert _has_live_placeholder_language(line) is None

    def test_non_table_todo_not_exempted(self):
        result = _has_live_placeholder_language("stake check (todo)")
        assert result is not None

    def test_table_bare_todo_not_exempted(self):
        result = _has_live_placeholder_language(
            "| col1 | todo: fill this section | col3 |"
        )
        assert result is not None

    def test_table_with_negation_word_exempted(self):
        line = "| AS-02a | block validation | not verified (todo) | high |"
        assert _has_live_placeholder_language(line) is None

    def test_real_attack_surface_line(self):
        line = (
            "| as-02a | block validation | system tx: stake not verified "
            "(todo) | high | consensus |"
        )
        assert _has_live_placeholder_language(line) is None

    def test_multiline_table_only_todo_row_matters(self):
        text = (
            "| ID | Area | Issue | Sev |\n"
            "|---|---|---|---|\n"
            "| AS-01 | networking | peer discovery | high |\n"
            "| AS-02 | consensus | validator check (todo) | medium |\n"
            "| AS-03 | storage | pruning | low |\n"
        )
        assert _has_live_placeholder_language(text) is None


# ═══════════════════════════════════════════════════════════════════════
# v2.7.4: Dedup-absorbed ID coverage accounting
# ═══════════════════════════════════════════════════════════════════════

class TestDedupAbsorbedCoverage:
    """Only receipt-accepted absorptions may receive MERGED disposition."""

    def test_extract_dedup_absorbed_ids_basic(self, tmp_path):
        (tmp_path / "dedup_decisions.md").write_text(dedent("""\
            ## Dedup Status Table
            | Finding ID | Status | Notes |
            |------------|--------|-------|
            | INV-001 | PASS | unchanged |
            | INV-003 | PASS | absorbs INV-25 |
            | INV-24 | MERGED into INV-004 | same root cause |
            | INV-25 | MERGED into INV-003 | same root cause |
        """), encoding="utf-8")
        result = M._extract_dedup_absorbed_ids(tmp_path)
        assert result == set(), "raw proposal rows are not applied authority"

    def test_extract_dedup_absorbed_ids_empty(self, tmp_path):
        result = M._extract_dedup_absorbed_ids(tmp_path)
        assert result == set()

    def test_extract_dedup_absorbed_ids_no_merges(self, tmp_path):
        (tmp_path / "dedup_decisions.md").write_text(dedent("""\
            ## Dedup Status Table
            | Finding ID | Status | Notes |
            |------------|--------|-------|
            | INV-001 | PASS | unchanged |
            | INV-002 | PASS | unchanged |
        """), encoding="utf-8")
        result = M._extract_dedup_absorbed_ids(tmp_path)
        assert result == set()

    def test_coverage_marks_absorbed_as_merged(self, tmp_path):
        (tmp_path / "dedup_decisions.md").write_text(dedent("""\
            ## Dedup Status Table
            | Finding ID | Status | Notes |
            |------------|--------|-------|
            | INV-001 | PASS | absorbs INV-24 |
            | INV-24 | MERGED into INV-001 | same root cause |
        """), encoding="utf-8")
        (tmp_path / "findings_inventory.md").write_text(
            "## Finding INV-001\nsome text\n## Finding INV-24\nsome text\n",
            encoding="utf-8",
        )
        rows = M._collect_raw_candidate_ledger_rows(
            tmp_path,
            promoted_ids={"INV-001"},
            excluded_ids=set(),
        )
        dispositions = {}
        for row in rows:
            cells = [c.strip() for c in row.strip().strip("|").split("|")]
            if len(cells) >= 3:
                dispositions[cells[1]] = cells[2]
        assert dispositions.get("INV-001") == "PROMOTED"
        assert dispositions.get("INV-24") != "MERGED"

    def test_coverage_no_unaccounted_for_absorbed(self, tmp_path):
        (tmp_path / "dedup_decisions.md").write_text(dedent("""\
            ## Dedup Status Table
            | Finding ID | Status | Notes |
            |------------|--------|-------|
            | INV-003 | PASS | absorbs INV-25, INV-28 |
            | INV-004 | PASS | absorbs INV-24, INV-32 |
            | INV-26 | PASS | absorbs INV-27 |
            | INV-24 | MERGED into INV-004 | same root cause |
            | INV-25 | MERGED into INV-003 | same root cause |
            | INV-27 | MERGED into INV-26 | same root cause |
            | INV-28 | MERGED into INV-003 | same root cause |
            | INV-32 | MERGED into INV-004 | same root cause |
        """), encoding="utf-8")
        (tmp_path / "findings_inventory.md").write_text(
            "\n".join(
                f"## Finding {fid}\nsome text"
                for fid in [
                    "INV-003", "INV-004", "INV-24", "INV-25",
                    "INV-26", "INV-27", "INV-28", "INV-32",
                ]
            ),
            encoding="utf-8",
        )
        rows = M._collect_raw_candidate_ledger_rows(
            tmp_path,
            promoted_ids={"INV-003", "INV-004", "INV-26"},
            excluded_ids=set(),
        )
        # The raw Markdown may affect ordinary ledger classification through
        # independent rules, but it can never authorize a MERGED disposition.
        assert not any("MERGED" in row for row in rows)

    def test_l1_exact_scenario(self, tmp_path):
        """Reproduce an observed L1 Codex halt: 5 dedup-absorbed IDs
        appearing in findings_inventory.md and verification_queue_pre_dedup.md
        but not in the active report set."""
        (tmp_path / "dedup_decisions.md").write_text(dedent("""\
            ## Dedup Status Table
            | Finding ID | Status | Notes |
            |------------|--------|-------|
            | INV-004 | PASS | absorbs INV-24 and INV-32 |
            | INV-003 | PASS | absorbs INV-25 and INV-28 |
            | INV-26 | PASS | absorbs INV-27 |
            | INV-24 | MERGED into INV-004 | same admission root cause |
            | INV-25 | MERGED into INV-003 | same payload provenance |
            | INV-27 | MERGED into INV-26 | derivative sync-target |
            | INV-28 | MERGED into INV-003 | derivative payload-cache |
            | INV-32 | MERGED into INV-004 | derivative compatibility |
        """), encoding="utf-8")
        # Representative IDs: padded INV-001..INV-023, unpadded INV-24..INV-33
        all_ids = [f"INV-{i:03d}" for i in range(1, 24)] + [
            f"INV-{i}" for i in range(24, 34)
        ]
        (tmp_path / "findings_inventory.md").write_text(
            "\n".join(f"## Finding {fid}\ntext" for fid in all_ids),
            encoding="utf-8",
        )
        (tmp_path / "verification_queue_pre_dedup.md").write_text(
            "\n".join(f"row with {fid}" for fid in all_ids),
            encoding="utf-8",
        )
        absorbed = {"INV-24", "INV-25", "INV-27", "INV-28", "INV-32"}
        promoted = {fid for fid in all_ids if fid not in absorbed}
        rows = M._collect_raw_candidate_ledger_rows(
            tmp_path,
            promoted_ids=promoted,
            excluded_ids=set(),
        )
        merged = [r for r in rows if "MERGED" in r]
        assert len(merged) == 0


class TestCoverageGapFixes:
    """Tests for v2.7.5 coverage accounting gap fixes (Gaps 1-8)."""

    @staticmethod
    def _dispositions(rows):
        out = {}
        for row in rows:
            cells = [c.strip() for c in row.strip().strip("|").split("|")]
            if len(cells) >= 3:
                out[cells[1]] = cells[2]
        return out

    # -- Gap 1: Case insensitivity -------------------------------------------

    def test_case_insensitive_promoted(self, tmp_path):
        """Lowercase IDs in source files match uppercase promoted_ids."""
        (tmp_path / "findings_inventory.md").write_text(
            "## Finding inv-10\ntext\n## Finding INV-11\ntext\n",
            encoding="utf-8",
        )
        rows = M._collect_raw_candidate_ledger_rows(
            tmp_path,
            promoted_ids={"INV-10", "INV-11"},
            excluded_ids=set(),
        )
        d = self._dispositions(rows)
        assert d.get("INV-10") == "PROMOTED"
        assert d.get("INV-11") == "PROMOTED"

    def test_case_insensitive_excluded(self, tmp_path):
        (tmp_path / "findings_inventory.md").write_text(
            "## Finding inv-05\ntext\n", encoding="utf-8",
        )
        rows = M._collect_raw_candidate_ledger_rows(
            tmp_path,
            promoted_ids=set(),
            excluded_ids={"INV-05"},
        )
        d = self._dispositions(rows)
        assert d.get("INV-05") == "EXCLUDED"

    def test_case_insensitive_dedup_absorbed(self, tmp_path):
        (tmp_path / "dedup_decisions.md").write_text(dedent("""\
            | Finding ID | Status | Notes |
            |------------|--------|-------|
            | inv-07 | MERGED into INV-001 | same root cause |
        """), encoding="utf-8")
        (tmp_path / "findings_inventory.md").write_text(
            "## Finding inv-07\ntext\n## Finding INV-001\ntext\n",
            encoding="utf-8",
        )
        rows = M._collect_raw_candidate_ledger_rows(
            tmp_path,
            promoted_ids={"INV-001"},
            excluded_ids=set(),
        )
        d = self._dispositions(rows)
        assert d.get("INV-001") == "PROMOTED"
        assert d.get("INV-07") != "MERGED"

    # -- Gap 2: Mechanical dedup format ---------------------------------------

    def test_extract_mechanical_merge_format(self, tmp_path):
        (tmp_path / "dedup_decisions.md").write_text(dedent("""\
            # Semantic Dedup Decisions
            **Status**: MECHANICAL_FALLBACK
            ## Decisions
            | Action | Absorbed | Into | Signal |
            |--------|----------|------|--------|
            | MECHANICAL_MERGE | INV-10 | INV-05 | source-id subset |
            | MECHANICAL_MERGE | INV-12 | INV-03 | pert lineage |
        """), encoding="utf-8")
        result = M._extract_dedup_absorbed_ids(tmp_path)
        assert result == set()

    def test_extract_mechanical_supplement_format(self, tmp_path):
        (tmp_path / "dedup_decisions.md").write_text(dedent("""\
            ## Supplemental Mechanical Dedup
            **Status**: MECHANICAL_SUPPLEMENT
            | Action | Absorbed | Into | Signal |
            |--------|----------|------|--------|
            | MECHANICAL_SUPPLEMENT | INV-20 | INV-15 | location overlap |
        """), encoding="utf-8")
        result = M._extract_dedup_absorbed_ids(tmp_path)
        assert result == set()

    def test_extract_mixed_formats(self, tmp_path):
        """Both LLM and mechanical formats parsed from same file."""
        (tmp_path / "dedup_decisions.md").write_text(dedent("""\
            ## Dedup Status Table
            | Finding ID | Status | Notes |
            |------------|--------|-------|
            | INV-24 | MERGED into INV-004 | same root cause |
            | INV-25 | MERGED into INV-003 | same root cause |
            ---
            ## Supplemental Mechanical Dedup
            | Action | Absorbed | Into | Signal |
            |--------|----------|------|--------|
            | MECHANICAL_SUPPLEMENT | INV-30 | INV-15 | location overlap |
        """), encoding="utf-8")
        result = M._extract_dedup_absorbed_ids(tmp_path)
        assert result == set()

    def test_mechanical_absorbed_marks_merged_in_coverage(self, tmp_path):
        """Raw mechanical proposal rows do not authorize MERGED coverage."""
        (tmp_path / "dedup_decisions.md").write_text(dedent("""\
            | Action | Absorbed | Into | Signal |
            |--------|----------|------|--------|
            | MECHANICAL_MERGE | INV-10 | INV-05 | source-id subset |
        """), encoding="utf-8")
        (tmp_path / "findings_inventory.md").write_text(
            "## Finding INV-05\ntext\n## Finding INV-10\ntext\n",
            encoding="utf-8",
        )
        rows = M._collect_raw_candidate_ledger_rows(
            tmp_path,
            promoted_ids={"INV-05"},
            excluded_ids=set(),
        )
        d = self._dispositions(rows)
        assert d.get("INV-05") == "PROMOTED"
        assert d.get("INV-10") != "MERGED"

    # -- Gap 3+4: Evidence-excluded and pre-dedup backup skip ----------------

    def test_evidence_excluded_skipped(self, tmp_path):
        """verification_queue_evidence_excluded.md is not scanned."""
        (tmp_path / "verification_queue_evidence_excluded.md").write_text(
            "| INV-99 | Low | title | excluded evidence |\n",
            encoding="utf-8",
        )
        (tmp_path / "findings_inventory.md").write_text(
            "## Finding INV-01\ntext\n", encoding="utf-8",
        )
        rows = M._collect_raw_candidate_ledger_rows(
            tmp_path, promoted_ids={"INV-01"}, excluded_ids=set(),
        )
        ids_in_rows = {
            c.strip()
            for row in rows
            for c in row.strip().strip("|").split("|")
            if "INV-" in c
        }
        assert "INV-99" not in ids_in_rows

    def test_pre_dedup_backup_skipped(self, tmp_path):
        """verification_queue_pre_dedup.md is not scanned."""
        (tmp_path / "verification_queue_pre_dedup.md").write_text(
            "| INV-88 | Medium | pre-dedup title |\n",
            encoding="utf-8",
        )
        (tmp_path / "findings_inventory.md").write_text(
            "## Finding INV-01\ntext\n", encoding="utf-8",
        )
        rows = M._collect_raw_candidate_ledger_rows(
            tmp_path, promoted_ids={"INV-01"}, excluded_ids=set(),
        )
        ids_in_rows = {
            c.strip()
            for row in rows
            for c in row.strip().strip("|").split("|")
            if "INV-" in c
        }
        assert "INV-88" not in ids_in_rows

    def test_real_verification_queue_not_skipped(self, tmp_path):
        """verification_queue.md is still scanned (not a backup/excluded)."""
        (tmp_path / "verification_queue.md").write_text(
            "| INV-01 | High | title | location |\n", encoding="utf-8",
        )
        rows = M._collect_raw_candidate_ledger_rows(
            tmp_path, promoted_ids={"INV-01"}, excluded_ids=set(),
        )
        d = self._dispositions(rows)
        assert d.get("INV-01") == "PROMOTED"

    # -- Gap 5/6/8: Chain structural artifacts excluded ----------------------

    def test_hypotheses_not_scanned(self, tmp_path):
        """hypotheses.md (chain structural artifact) is not a candidate source."""
        (tmp_path / "hypotheses.md").write_text(
            "| H-5 | title | Medium | INV-15 |\n",
            encoding="utf-8",
        )
        (tmp_path / "findings_inventory.md").write_text(
            "## Finding INV-15\ntext\n", encoding="utf-8",
        )
        rows = M._collect_raw_candidate_ledger_rows(
            tmp_path, promoted_ids={"INV-15"}, excluded_ids=set(),
        )
        ids_in_rows = {
            c.strip()
            for row in rows
            for c in row.strip().strip("|").split("|")
            if re.match(r"[A-Z]+-\d+", c.strip())
        }
        assert "H-5" not in ids_in_rows, "Hypothesis ID should not be scanned"

    def test_chain_hypotheses_not_scanned(self, tmp_path):
        """chain_hypotheses.md is not a candidate source."""
        (tmp_path / "chain_hypotheses.md").write_text(
            "## Chain CH-1\nCombines INV-15 + INV-20\n",
            encoding="utf-8",
        )
        (tmp_path / "findings_inventory.md").write_text(
            "## Finding INV-15\ntext\n", encoding="utf-8",
        )
        rows = M._collect_raw_candidate_ledger_rows(
            tmp_path, promoted_ids={"INV-15"}, excluded_ids=set(),
        )
        ids_in_rows = {
            c.strip()
            for row in rows
            for c in row.strip().strip("|").split("|")
            if re.match(r"[A-Z]+-\d+", c.strip())
        }
        assert "CH-1" not in ids_in_rows

    def test_finding_mapping_not_scanned(self, tmp_path):
        """finding_mapping.md is not a candidate source."""
        (tmp_path / "finding_mapping.md").write_text(
            "| H-3 | INV-15, EN-2 | depth analysis |\n",
            encoding="utf-8",
        )
        (tmp_path / "findings_inventory.md").write_text(
            "## Finding INV-15\ntext\n", encoding="utf-8",
        )
        rows = M._collect_raw_candidate_ledger_rows(
            tmp_path, promoted_ids={"INV-15"}, excluded_ids=set(),
        )
        ids_in_rows = {
            c.strip()
            for row in rows
            for c in row.strip().strip("|").split("|")
            if re.match(r"[A-Z]+-\d+", c.strip())
        }
        assert "EN-2" not in ids_in_rows
        assert "H-3" not in ids_in_rows

    # -- Integration: full-pipeline scenario ---------------------------------

    def test_full_pipeline_no_unaccounted(self, tmp_path):
        """End-to-end: LLM dedup + mechanical supplement + evidence excluded
        + pre-dedup backup — zero UNACCOUNTED."""
        # LLM dedup absorbed INV-24 into INV-004
        # Mechanical supplement absorbed INV-30 into INV-015
        (tmp_path / "dedup_decisions.md").write_text(dedent("""\
            ## Dedup Status Table
            | Finding ID | Status | Notes |
            |------------|--------|-------|
            | INV-24 | MERGED into INV-004 | same root cause |
            ---
            ## Supplemental Mechanical Dedup
            | Action | Absorbed | Into | Signal |
            |--------|----------|------|--------|
            | MECHANICAL_SUPPLEMENT | INV-30 | INV-015 | location overlap |
        """), encoding="utf-8")
        # Active findings in inventory
        active_ids = ["INV-004", "INV-015", "INV-024", "INV-030"]
        absorbed_ids = ["INV-24", "INV-30"]
        (tmp_path / "findings_inventory.md").write_text(
            "\n".join(f"## Finding {fid}\ntext" for fid in active_ids + absorbed_ids),
            encoding="utf-8",
        )
        # Verification queue (post-dedup)
        (tmp_path / "verification_queue.md").write_text(
            "\n".join(f"| {fid} | High | title | loc |" for fid in active_ids),
            encoding="utf-8",
        )
        # Pre-dedup backup (should be skipped)
        (tmp_path / "verification_queue_pre_dedup.md").write_text(
            "\n".join(f"| {fid} | High | title | loc |" for fid in active_ids + absorbed_ids),
            encoding="utf-8",
        )
        # Evidence excluded (should be skipped)
        (tmp_path / "verification_queue_evidence_excluded.md").write_text(
            "| INV-999 | Low | excluded |\n", encoding="utf-8",
        )
        # Chain artifacts (should not be scanned)
        (tmp_path / "hypotheses.md").write_text(
            "| H-1 | INV-004, INV-024 | chain grouping |\n",
            encoding="utf-8",
        )
        promoted = {fid.upper() for fid in active_ids}
        rows = M._collect_raw_candidate_ledger_rows(
            tmp_path, promoted_ids=promoted, excluded_ids=set(),
        )
        unaccounted = [r for r in rows if "UNACCOUNTED" in r]
        assert len(unaccounted) == 0, f"UNACCOUNTED rows: {unaccounted}"
        # Raw proposal rows cannot authorize MERGED coverage.
        d = self._dispositions(rows)
        assert d.get("INV-24") != "MERGED"
        assert d.get("INV-30") != "MERGED"
        # Verify no chain/backup/excluded IDs leaked in
        all_ids_in_rows = set(d.keys())
        assert "INV-999" not in all_ids_in_rows
        assert "INV-88" not in all_ids_in_rows
        assert "H-1" not in all_ids_in_rows


# ═══════════════════════════════════════════════════════════════════════
# v2.7.5b — L1 never-cut mode-awareness (confidence_scores.md)
# ═══════════════════════════════════════════════════════════════════════

class TestL1NeverCutModeAwareness:
    """confidence_scores.md required in Core/Thorough but NOT Light."""

    def test_light_mode_no_confidence_scores(self):
        from plamen_types import l1_never_cut_groups
        groups = l1_never_cut_groups("light")
        flat = [f for g in groups for f in g]
        assert "confidence_scores.md" not in flat

    def test_core_mode_has_confidence_scores(self):
        from plamen_types import l1_never_cut_groups
        groups = l1_never_cut_groups("core")
        flat = [f for g in groups for f in g]
        assert "confidence_scores.md" in flat

    def test_thorough_mode_has_confidence_scores(self):
        from plamen_types import l1_never_cut_groups
        groups = l1_never_cut_groups("thorough")
        flat = [f for g in groups for f in g]
        assert "confidence_scores.md" in flat

    def test_light_mode_has_5_depth_agents(self):
        from plamen_types import l1_never_cut_groups
        groups = l1_never_cut_groups("light")
        assert len(groups) == 5
        flat = [g[0] for g in groups]
        assert "depth_consensus_invariant_findings.md" in flat
        assert "depth_network_surface_findings.md" in flat
        assert "depth_state_trace_findings.md" in flat
        assert "depth_external_findings.md" in flat
        assert "depth_edge_case_findings.md" in flat

    def test_core_mode_has_10_groups(self):
        from plamen_types import l1_never_cut_groups
        # L1-4: 5 depth + 4 scanner (blind-spot A/B/C + validation sweep) +
        # confidence_scores.
        groups = l1_never_cut_groups("core")
        assert len(groups) == 10

    def test_thorough_mode_has_13_groups(self):
        from plamen_types import l1_never_cut_groups
        # 5 depth + 4 scanner + confidence + 3 thorough extras.
        groups = l1_never_cut_groups("thorough")
        assert len(groups) == 13

    def test_sc_pattern_parity(self):
        """L1 now mirrors SC's 3-tier architecture."""
        from plamen_types import sc_never_cut_groups, l1_never_cut_groups
        # Light: neither has confidence_scores
        sc_light = [f for g in sc_never_cut_groups("light") for f in g]
        l1_light = [f for g in l1_never_cut_groups("light") for f in g]
        assert ("confidence_scores.md" in sc_light) == ("confidence_scores.md" in l1_light)
        # Core: both have confidence_scores
        sc_core = [f for g in sc_never_cut_groups("core") for f in g]
        l1_core = [f for g in l1_never_cut_groups("core") for f in g]
        assert "confidence_scores.md" in sc_core
        assert "confidence_scores.md" in l1_core


# ═══════════════════════════════════════════════════════════════════════
# v2.7.5b — Evidence Tag accepted as PoC Result substitute in quality gate
# ═══════════════════════════════════════════════════════════════════════

class TestEvidenceTagAsPoC:
    """Evidence Tag is a valid substitute for PoC Result in the quality gate."""

    def _run(self, tmp_path, report_text):
        import textwrap
        from plamen_validators import _run_report_quality_gate

        scratchpad = tmp_path / "sp"
        scratchpad.mkdir(exist_ok=True)
        project = tmp_path / "proj"
        project.mkdir(exist_ok=True)

        (project / "AUDIT_REPORT.md").write_text(
            textwrap.dedent(report_text), encoding="utf-8"
        )
        (scratchpad / "report_index.md").write_text(textwrap.dedent("""\
            ## Summary Counts
            | Severity | Count |
            |----------|-------|
            | High | 1 |

            ## Master Finding Index
            | Report ID | Title | Severity | Internal Hypothesis |
            |-----------|-------|----------|---------------------|
            | H-01 | DoS | High | H-1 |
        """), encoding="utf-8")

        return _run_report_quality_gate(scratchpad, str(project))

    def test_evidence_tag_accepted_for_high(self, tmp_path):
        report = """\
            # Security Audit Report — Test

            ## Summary
            | Severity | Count |
            |----------|-------|
            | High | 1 |

            ### Components Audited
            | Component | Path |
            |-----------|------|
            | test | src/Test.rs |

            ## High Findings

            ### [H-01] DoS via unbounded body [VERIFIED]

            **Severity**: High
            **Location**: `src/server.rs:L42`

            **Description**:
            Unbounded body parsing allows memory exhaustion.

            **Impact**:
            Unauthenticated DoS on gossip API.

            **Evidence Tag**: [CODE-TRACE]

            **Recommendation**:
            Add body size limits.
        """
        issues = self._run(tmp_path, report)
        rich_issues = [i for i in issues if "rich finding fields" in i]
        assert not rich_issues, f"Evidence Tag should satisfy PoC field: {rich_issues}"

    def test_no_poc_no_evidence_is_warn(self, tmp_path):
        """v2.8.5: missing PoC/Evidence is WARN, not FAIL."""
        report = """\
            # Security Audit Report — Test

            ## Summary
            | Severity | Count |
            |----------|-------|
            | High | 1 |

            ### Components Audited
            | Component | Path |
            |-----------|------|
            | test | src/Test.rs |

            ## High Findings

            ### [H-01] DoS via unbounded body [VERIFIED]

            **Severity**: High
            **Location**: `src/server.rs:L42`

            **Description**:
            Unbounded body parsing allows memory exhaustion.

            **Impact**:
            Unauthenticated DoS on gossip API.

            **Recommendation**:
            Add body size limits.
        """
        issues = self._run(tmp_path, report)
        rich_issues = [i for i in issues if "rich finding fields" in i]
        assert not rich_issues, (
            "v2.8.5: missing PoC/Evidence is WARN-only, not FAIL"
        )


# ═══════════════════════════════════════════════════════════════════════
# v2.7.5b — body_assignment_count WARN-not-FAIL when body > assignments
# ═══════════════════════════════════════════════════════════════════════

class TestBodyAssignmentWarn:
    """body > assignments is a WARN (body recovered extra findings), not FAIL."""

    def test_body_gt_assignments_no_issue(self, tmp_path):
        """3 body sections but only 2 in index → WARN, zero issues."""
        import textwrap
        from plamen_validators import _run_report_quality_gate

        sp = tmp_path / "sp"
        sp.mkdir()
        proj = tmp_path / "proj"
        proj.mkdir()

        (proj / "AUDIT_REPORT.md").write_text(textwrap.dedent("""\
            # Security Audit Report

            ## Summary
            | Severity | Count |
            |----------|-------|
            | Medium | 3 |

            ## Medium Findings

            ### [M-01] Bug one
            **Severity**: Medium
            **Location**: src:10
            **Impact**: Loss
            **PoC Result**: PASS

            ### [M-02] Bug two
            **Severity**: Medium
            **Location**: src:20
            **Impact**: Loss
            **PoC Result**: PASS

            ### [M-03] Recovered bug
            **Severity**: Medium
            **Location**: src:30
            **Impact**: Loss
            **PoC Result**: PASS
        """), encoding="utf-8")

        (sp / "report_index.md").write_text(textwrap.dedent("""\
            ## Summary Counts
            | Severity | Count |
            |----------|-------|
            | Medium | 2 |

            ## Master Finding Index
            | Report ID | Title | Severity | Internal Hypothesis |
            |-----------|-------|----------|---------------------|
            | M-01 | Bug one | Medium | H-1 |
            | M-02 | Bug two | Medium | H-2 |
        """), encoding="utf-8")

        issues = _run_report_quality_gate(sp, str(proj))
        count_issues = [i for i in issues if "body count mismatch" in i]
        assert not count_issues, f"body > assignments should WARN not FAIL: {count_issues}"

    def test_body_lt_assignments_still_fails(self, tmp_path):
        """1 body section but 2 in index → FAIL (tier writer dropped findings)."""
        import textwrap
        from plamen_validators import _run_report_quality_gate

        sp = tmp_path / "sp"
        sp.mkdir()
        proj = tmp_path / "proj"
        proj.mkdir()

        (proj / "AUDIT_REPORT.md").write_text(textwrap.dedent("""\
            # Security Audit Report

            ## Summary
            | Severity | Count |
            |----------|-------|
            | Medium | 1 |

            ## Medium Findings

            ### [M-01] Bug one
            **Severity**: Medium
            **Location**: src:10
            **Impact**: Loss
            **PoC Result**: PASS
        """), encoding="utf-8")

        (sp / "report_index.md").write_text(textwrap.dedent("""\
            ## Summary Counts
            | Severity | Count |
            |----------|-------|
            | Medium | 2 |

            ## Master Finding Index
            | Report ID | Title | Severity | Internal Hypothesis |
            |-----------|-------|----------|---------------------|
            | M-01 | Bug one | Medium | H-1 |
            | M-02 | Bug two | Medium | H-2 |
        """), encoding="utf-8")

        issues = _run_report_quality_gate(sp, str(proj))
        count_issues = [i for i in issues if "body count" in i.lower() or "mismatch" in i.lower() or "missing" in i.lower()]
        assert count_issues, "body < assignments should still FAIL"


# ═══════════════════════════════════════════════════════════════════════
# v2.7.5b — body_assignment_exact_ids: extra IDs WARN not FAIL
# ═══════════════════════════════════════════════════════════════════════

class TestBodyAssignmentExactIds:
    """Missing IDs FAIL, but extra IDs in body WARN only."""

    def test_extra_ids_no_issue(self, tmp_path):
        """Body has M-03 not in index → WARN, zero issues."""
        import textwrap
        from plamen_validators import _run_report_quality_gate

        sp = tmp_path / "sp"
        sp.mkdir()
        proj = tmp_path / "proj"
        proj.mkdir()

        (proj / "AUDIT_REPORT.md").write_text(textwrap.dedent("""\
            # Security Audit Report

            ## Summary
            | Severity | Count |
            |----------|-------|
            | Medium | 3 |

            ## Medium Findings

            ### [M-01] Bug one
            **Severity**: Medium
            **Location**: src:10
            **Impact**: Loss
            **PoC Result**: PASS

            ### [M-02] Bug two
            **Severity**: Medium
            **Location**: src:20
            **Impact**: Loss
            **PoC Result**: PASS

            ### [M-03] Recovered
            **Severity**: Medium
            **Location**: src:30
            **Impact**: Loss
            **PoC Result**: PASS
        """), encoding="utf-8")

        (sp / "report_index.md").write_text(textwrap.dedent("""\
            ## Summary Counts
            | Severity | Count |
            |----------|-------|
            | Medium | 2 |

            ## Master Finding Index
            | Report ID | Title | Severity | Internal Hypothesis |
            |-----------|-------|----------|---------------------|
            | M-01 | Bug one | Medium | H-1 |
            | M-02 | Bug two | Medium | H-2 |
        """), encoding="utf-8")

        issues = _run_report_quality_gate(sp, str(proj))
        exact_issues = [i for i in issues if "exact" in i.lower() and "extra" in i.lower()]
        assert not exact_issues, f"extra IDs should WARN not FAIL: {exact_issues}"


# ═══════════════════════════════════════════════════════════════════════
# v2.7.5b — GAP-8: tier body gate no longer vacuously passes
# ═══════════════════════════════════════════════════════════════════════

class TestTierBodyGateVacuousPass:
    """When both manifest dir and body file absent, gate should not pass vacuously."""

    def test_double_absent_with_expected_findings_fails(self, tmp_path):
        """No body_manifests dir, no body file, but index says findings exist → issue."""
        from plamen_validators import _validate_tier_body_against_manifest

        sp = tmp_path / "sp"
        sp.mkdir()
        # Write report_index.md saying 1 critical finding exists
        (sp / "report_index.md").write_text(
            "## Master Finding Index\n"
            "| Report ID | Title | Severity | Internal Hypothesis |\n"
            "|-----------|-------|----------|---------------------|\n"
            "| C-01 | Bug | Critical | H-1 |\n",
            encoding="utf-8",
        )
        issues = _validate_tier_body_against_manifest(sp, "report_critical_high")
        assert issues, "double-absent should fail when index says findings exist"

    def test_double_absent_with_zero_findings_passes(self, tmp_path):
        """No body_manifests dir, no body file, index says 0 findings → pass."""
        from plamen_validators import _validate_tier_body_against_manifest

        sp = tmp_path / "sp"
        sp.mkdir()
        # Write report_index.md with no critical/high findings
        (sp / "report_index.md").write_text(
            "## Master Finding Index\n"
            "| Report ID | Title | Severity | Internal Hypothesis |\n"
            "|-----------|-------|----------|---------------------|\n"
            "| M-01 | Bug | Medium | H-1 |\n",
            encoding="utf-8",
        )
        issues = _validate_tier_body_against_manifest(sp, "report_critical_high")
        assert not issues, f"double-absent with 0 expected findings should pass: {issues}"


# ═══════════════════════════════════════════════════════════════════════
# v2.7.5b — GAP-7: verify_core.md written even when no verify files
# ═══════════════════════════════════════════════════════════════════════

class TestVerifyCoreEmptyFallback:
    """_generate_verify_core_if_missing writes empty verify_core.md when no verify files."""

    def test_empty_verify_core_written(self, tmp_path):
        from plamen_validators import _generate_verify_core_if_missing

        sp = tmp_path / "sp"
        sp.mkdir()
        result = _generate_verify_core_if_missing(sp)
        assert result is False  # still returns False (no verify files)
        vc = sp / "verify_core.md"
        assert vc.exists(), "verify_core.md should be written as empty fallback"
        content = vc.read_text(encoding="utf-8")
        assert "No `verify_*.md` files found" in content

    def test_does_not_overwrite_existing(self, tmp_path):
        from plamen_validators import _generate_verify_core_if_missing

        sp = tmp_path / "sp"
        sp.mkdir()
        existing = sp / "verify_core.md"
        existing.write_text("# Existing content\n", encoding="utf-8")
        result = _generate_verify_core_if_missing(sp)
        assert result is False
        assert existing.read_text(encoding="utf-8") == "# Existing content\n"


# ═══════════════════════════════════════════════════════════════════════
# v2.7.6: Inventory chunk containment retry hint + prompt fix
# ═══════════════════════════════════════════════════════════════════════


class TestInventoryChunkContainment:
    """Verify the containment retry hint and prompt allowlist directive."""

    def test_retry_hint_inventory_chunk_c(self):
        from plamen_driver import _generate_containment_retry_hint

        missing = ["phase containment: wrote later-phase artifacts: findings_inventory.md"]
        hint = _generate_containment_retry_hint("inventory_chunk_c", missing)
        assert "findings_inventory_chunk_c.md" in hint
        assert "findings_inventory.md" in hint
        assert "Do not create, update, or repair any other scratchpad artifact" in hint
        assert "work outside this shard" in hint

    def test_retry_hint_inventory_chunk_a(self):
        from plamen_driver import _generate_containment_retry_hint

        missing = ["phase containment: wrote later-phase artifacts: findings_inventory.md"]
        hint = _generate_containment_retry_hint("inventory_chunk_a", missing)
        assert "findings_inventory_chunk_a.md" in hint

    def test_retry_hint_inventory_chunk_b(self):
        from plamen_driver import _generate_containment_retry_hint

        missing = ["phase containment: wrote later-phase artifacts: findings_inventory.md"]
        hint = _generate_containment_retry_hint("inventory_chunk_b", missing)
        assert "findings_inventory_chunk_b.md" in hint

    def test_retry_hint_depth_still_works(self):
        """Existing depth-specific hint must not regress."""
        from plamen_driver import _generate_containment_retry_hint

        missing = ["phase containment: wrote later-phase artifacts: rag_validation.md"]
        hint = _generate_containment_retry_hint("depth", missing)
        assert "rag_validation.md" in hint
        assert "Depth retry boundary" in hint

    def test_prompt_allowlist_file_directive(self):
        """The inventory chunk prompt must contain the output allowlist warning."""
        from plamen_prompt import _render_expected_output_block
        from plamen_prompt import build_phase_prompt  # noqa: F401
        # Just verify the template text contains the forbidden directive
        import plamen_prompt as pp
        import inspect
        source = inspect.getsource(pp)
        assert "OUTPUT ALLOWLIST" in source
        assert "Any non-allowlisted write triggers phase containment" in source


# ═══════════════════════════════════════════════════════════════════════
# v2.7.7: Codex content-filter detection
# ═══════════════════════════════════════════════════════════════════════

class TestCodexContentFilterDetection:
    """Verify _detect_codex_content_filter recognises the safety-filter error."""

    def test_exact_codex_error_message(self, tmp_path):
        from plamen_driver import _detect_codex_content_filter

        log = tmp_path / "stdio.log"
        log.write_text(
            '{"type":"error","message":"This content was flagged for possible '
            'cybersecurity risk. If this seems wrong, try rephrasing your '
            'request. To get authorized for security work, join the Trusted '
            'Access for Cyber program: https://chatgpt.com/cyber"}\n'
        )
        assert _detect_codex_content_filter(log) is True

    def test_partial_match_flagged(self, tmp_path):
        from plamen_driver import _detect_codex_content_filter

        log = tmp_path / "stdio.log"
        log.write_text(
            '{"type":"error","message":"flagged for cybersecurity risk"}\n'
        )
        assert _detect_codex_content_filter(log) is True

    def test_trusted_access_match(self, tmp_path):
        from plamen_driver import _detect_codex_content_filter

        log = tmp_path / "stdio.log"
        log.write_text(
            '{"type":"error","message":"Join Trusted Access for Cyber"}\n'
        )
        assert _detect_codex_content_filter(log) is True

    def test_normal_error_no_match(self, tmp_path):
        from plamen_driver import _detect_codex_content_filter

        log = tmp_path / "stdio.log"
        log.write_text('{"type":"error","message":"rate_limit_exceeded"}\n')
        assert _detect_codex_content_filter(log) is False

    def test_missing_file(self, tmp_path):
        from plamen_driver import _detect_codex_content_filter

        assert _detect_codex_content_filter(tmp_path / "nonexistent.log") is False

    def test_normal_success_no_match(self, tmp_path):
        from plamen_driver import _detect_codex_content_filter

        log = tmp_path / "stdio.log"
        log.write_text(
            '{"type":"turn.completed","usage":{"input_tokens":100}}\n'
        )
        assert _detect_codex_content_filter(log) is False

    def test_turn_failed_with_filter(self, tmp_path):
        """The turn.failed event also carries the filter message."""
        from plamen_driver import _detect_codex_content_filter

        log = tmp_path / "stdio.log"
        log.write_text(
            '{"type":"turn.failed","error":{"message":"This content was '
            'flagged for possible cybersecurity risk."}}\n'
        )
        assert _detect_codex_content_filter(log) is True
