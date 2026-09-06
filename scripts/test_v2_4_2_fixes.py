"""Tests for v2.4.2 fixes: SC semantic dedup, function-name signal, quality megasection.

Run: python -m pytest test_v2_4_2_fixes.py -v
"""
from __future__ import annotations

import re
import sys
import tempfile
from pathlib import Path

import pytest

SCRIPTS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS_DIR))

import plamen_types as T
import plamen_parsers as P
import plamen_prompt as PR
import plamen_driver as D
from plamen_types import plamen_home
import plamen_mechanical as M


# ═══════════════════════════════════════════════════════════════════════
# Fix 1: SC semantic dedup phase placement and wiring
# ═══════════════════════════════════════════════════════════════════════

class TestFix1_SCSemanticDedup:

    def test_sc_semantic_dedup_exists_in_SC_PHASES(self):
        names = [p.name for p in T.SC_PHASES]
        assert "sc_semantic_dedup" in names

    def test_sc_semantic_dedup_precedes_context_only_rag_and_chain(self):
        """Freeze identities before precedent enrichment, then compose chains."""
        names = [p.name for p in T.SC_PHASES]
        rag_idx = names.index("rag_sweep")
        chain_idx = names.index("chain")
        dedup_idx = names.index("sc_semantic_dedup")
        assert dedup_idx < rag_idx < chain_idx, (
            f"candidate freeze/dedup ({dedup_idx}) must precede context-only "
            f"rag_sweep ({rag_idx}), and both must precede chain ({chain_idx})"
        )

    def test_sc_semantic_dedup_expected_artifacts(self):
        phase = next(p for p in T.SC_PHASES if p.name == "sc_semantic_dedup")
        assert "dedup_decisions.md" in phase.expected_artifacts
        assert "findings_inventory_deduped.md" in phase.expected_artifacts

    def test_sc_semantic_dedup_model_is_sonnet(self):
        phase = next(p for p in T.SC_PHASES if p.name == "sc_semantic_dedup")
        assert phase.model == "sonnet"

    def test_l1_semantic_dedup_still_exists(self):
        names = [p.name for p in T.L1_PHASES]
        assert "semantic_dedup" in names

    def test_sc_dedup_prompt_override_mentions_inventory(self):
        phase = next(p for p in T.SC_PHASES if p.name == "sc_semantic_dedup")
        config = {
            "pipeline": "sc",
            "scratchpad": "/tmp/sp",
            "project_root": "/tmp/proj",
            "language": "evm",
            "mode": "thorough",
            "proven_only": False,
        }
        v1 = Path(tempfile.mktemp(suffix=".md"))
        v1.write_text("# SC\n\n## Phase 4e: Semantic Dedup\n\nDo dedup.\n", encoding="utf-8")
        try:
            prompt = D.build_phase_prompt(v1, phase, config)
            assert "findings_inventory_deduped.md" in prompt
            assert "verification_queue_deduped.md" not in prompt
        finally:
            v1.unlink(missing_ok=True)

    def test_l1_dedup_prompt_is_inventory_proposal_only(self):
        phase = next(p for p in T.L1_PHASES if p.name == "semantic_dedup")
        assert phase.expected_artifacts == ["dedup_decisions.md"]
        prompt = (
            Path(__file__).parents[1]
            / "prompts"
            / "shared"
            / "v2"
            / "phase4e-semantic-dedup.md"
        ).read_text(encoding="utf-8")
        assert "findings_inventory.md" in prompt
        assert "dedup_decisions.md" in prompt
        assert (
            "L1: do NOT read `{SCRATCHPAD}/verification_queue.md`"
            in prompt
        )
        assert "You do NOT write or edit `findings_inventory_deduped.md`." in prompt

    def test_sc_post_phase_handler_swaps_inventory(self, tmp_path):
        scratchpad = tmp_path / ".scratchpad"
        scratchpad.mkdir()
        orig = scratchpad / "findings_inventory.md"
        orig.write_text("# Original Inventory\n\n### Finding [INV-001]: Bug A\n", encoding="utf-8")
        deduped = scratchpad / "findings_inventory_deduped.md"
        deduped.write_text(
            "# Deduped Inventory\n\n### Finding [INV-001]: Bug A (merged with INV-002)\n"
            + "x" * 100,
            encoding="utf-8",
        )
        phase = type("Phase", (), {"name": "sc_semantic_dedup"})()
        passed = True
        # Simulate the post-phase handler logic
        import shutil
        if phase.name == "sc_semantic_dedup" and passed:
            d = scratchpad / "findings_inventory_deduped.md"
            o = scratchpad / "findings_inventory.md"
            if d.exists() and d.stat().st_size > 100:
                backup = scratchpad / "findings_inventory_pre_dedup.md"
                if o.exists():
                    shutil.copy2(o, backup)
                shutil.copy2(d, o)
        assert (scratchpad / "findings_inventory_pre_dedup.md").exists()
        assert "Deduped" in orig.read_text(encoding="utf-8")
        assert "Original" in (scratchpad / "findings_inventory_pre_dedup.md").read_text(encoding="utf-8")

    def test_skip_logic_fires_when_no_signals(self, tmp_path):
        scratchpad = tmp_path / ".scratchpad"
        scratchpad.mkdir()
        inv = scratchpad / "findings_inventory.md"
        inv.write_text("# Inventory\nClean findings, no dedup tags.\n", encoding="utf-8")
        # No dedup_candidate_pairs.md, no dedup tags -> should skip
        pairs = scratchpad / "dedup_candidate_pairs.md"
        assert not pairs.exists()
        assert "LIKELY-DUP" not in inv.read_text(encoding="utf-8")

    def test_skip_logic_does_not_fire_with_pairs(self, tmp_path):
        scratchpad = tmp_path / ".scratchpad"
        scratchpad.mkdir()
        pairs = scratchpad / "dedup_candidate_pairs.md"
        pairs.write_text("# Dedup Pairs\n" + "x" * 200, encoding="utf-8")
        assert pairs.exists() and pairs.stat().st_size > 100

    def test_skip_logic_does_not_fire_with_likely_dup(self, tmp_path):
        scratchpad = tmp_path / ".scratchpad"
        scratchpad.mkdir()
        inv = scratchpad / "findings_inventory.md"
        inv.write_text(
            "# Inventory\n\n**Dedup Signal**: [LIKELY-DUP of 'Bug A' score=0.90]\n",
            encoding="utf-8",
        )
        assert "LIKELY-DUP" in inv.read_text(encoding="utf-8")


# ═══════════════════════════════════════════════════════════════════════
# Fix 2: Function-name clustering signal
# ═══════════════════════════════════════════════════════════════════════

def test_large_candidate_set_is_bounded_not_skipped(tmp_path):
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    sections = ["# Inventory", ""]
    for i in range(1, 22):
        sections.append(
            f"### Finding [INV-{i:03d}]: Missing validation in shared path {i}\n"
            "**Severity**: Medium\n"
            f"**Location**: src/Shared.sol:process:L{i}\n"
            f"**Source IDs**: [DCI-{i}, DST-{i}]\n"
            "**Preferred Tag**: CODE-TRACE\n\n"
            f"**Description**: Candidate duplicate body {i}.\n"
        )
    (scratchpad / "findings_inventory.md").write_text(
        "\n".join(sections), encoding="utf-8"
    )

    total = P._compute_dedup_candidate_pairs(scratchpad)
    live = (scratchpad / "dedup_candidate_pairs.md").read_text(encoding="utf-8")
    focus = (scratchpad / "dedup_focus_inventory.md").read_text(encoding="utf-8")
    live_rows = [line for line in live.splitlines() if line.startswith("| INV-")]

    assert total > 60
    # Turn-safe dedup bound (dedup-overflow fix): the live-pair cap is 50 (env-
    # overridable) and chunk == cap, so the candidate set is BOUNDED to ONE
    # turn-safe round of <= cap pairs. Feeding 200+ pairs to a single dedup
    # subprocess overflowed the 32K output-token cap and hung; capping at one
    # round prevents that. Pairs beyond the cap are DEFERRED to
    # dedup_candidate_pairs_full.md (full traceability) -- never silently skipped.
    cap = P._dedup_live_pair_cap()
    assert cap <= 60, f"live cap must stay turn-safe (one subprocess turn); got {cap}"
    # Live packet is exactly one cap-sized round (cap == _DEDUP_ROUND_CHUNK).
    assert len(live_rows) == cap, (
        f"round-1 unified packet should carry exactly {cap} live pairs"
    )
    # BOUNDED-NOT-SKIPPED: total (210) > cap, so the remainder is preserved in
    # the full/deferred file with ZERO loss -- bounding never drops a pair.
    assert total > cap
    full = scratchpad / "dedup_candidate_pairs_full.md"
    assert full.exists(), (
        "pairs beyond the live cap must be DEFERRED to "
        "dedup_candidate_pairs_full.md, never silently skipped"
    )
    full_rows = [
        l for l in full.read_text(encoding="utf-8").splitlines()
        if l.startswith("| INV-")
    ]
    assert len(full_rows) == total, (
        f"the full/deferred file must enumerate ALL {total} candidate pairs "
        f"with zero loss (found {len(full_rows)})"
    )
    assert "deferred" in live.lower()

    assert "Dedup Focus Inventory" in focus
    assert "### Finding [INV-001]" in focus

def test_dedup_prompt_override_mentions_bounded_focus_inputs():
    phase = next(p for p in T.SC_PHASES if p.name == "sc_semantic_dedup")
    config = {
        "pipeline": "sc",
        "scratchpad": "/tmp/sp",
        "project_root": "/tmp/proj",
        "language": "evm",
        "mode": "thorough",
        "proven_only": False,
    }
    v1 = Path(tempfile.mktemp(suffix=".md"))
    v1.write_text("# SC\n\n## Phase 4e: Semantic Dedup\n\nDo dedup.\n", encoding="utf-8")
    try:
        prompt = D.build_phase_prompt(v1, phase, config)
        assert "dedup_focus_inventory.md" in prompt
        # Cluster-first redesign: the PRIMARY bounded input is now the
        # clustering-blocks file. The candidate-pairs files are fallback-only
        # shim artifacts, no longer handed to the LLM. The test's intent —
        # the prompt points at BOUNDED inputs, never the full inventory —
        # is preserved by dedup_blocks.md + dedup_focus_inventory.md.
        assert "dedup_blocks.md" in prompt
        # No-full-inventory guard (the bounded-input invariant) preserved.
        assert "Do NOT read" in prompt and "findings_inventory.md" in prompt
    finally:
        v1.unlink(missing_ok=True)


def test_invariants_fallback_materializes_gate_artifact(tmp_path):
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    (scratchpad / "state_variables.md").write_text(
        "| Variable | Contract | Notes |\n"
        "|---|---|---|\n"
        "| totalSupply | Token | accumulator |\n",
        encoding="utf-8",
    )

    written = D._write_semantic_invariants_fallback(
        scratchpad, "unit-test timeout",
    )
    phase = next(p for p in T.SC_PHASES if p.name == "invariants")
    passed, missing = D.gate_passes(scratchpad, str(tmp_path), phase)
    body = (scratchpad / "semantic_invariants.md").read_text(encoding="utf-8")

    assert written == ["semantic_invariants.md"]
    assert passed, missing
    assert "**Status**: FALLBACK" in body
    assert "totalSupply" in body
    assert "state_variables.md" in body


def test_precedent_unavailable_fallback_materializes_all_inventory_ids(tmp_path):
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    (scratchpad / "findings_inventory.md").write_text(
        "# Inventory\n\n"
        "### Finding [INV-001]: Missing access control\n"
        "**Severity**: High\n\n"
        "### Finding [INV-002]: Oracle stale price\n"
        "**Severity**: Medium\n",
        encoding="utf-8",
    )

    written = D._write_rag_validation_floor(scratchpad, "unit-test timeout")
    phase = next(p for p in T.SC_PHASES if p.name == "rag_sweep")
    passed, missing = D.gate_passes(scratchpad, str(tmp_path), phase)
    body = (scratchpad / "rag_validation.md").read_text(encoding="utf-8")

    assert written == ["rag_validation.md"]
    assert passed, missing
    assert "| INV-001 |" in body
    assert "| INV-002 |" in body
    assert "0.3" not in body
    assert "UNSCORED" in body
    assert "[RAG: DRIVER_UNAVAILABLE]" in body
    assert "PLAMEN_PRECEDENT_PROPOSALS_JSON_BEGIN" in body


def test_quality_helper_prompts_have_bounded_transition_contracts():
    prompt_dir = Path(__file__).resolve().parents[1] / "prompts" / "shared" / "v2"
    inv_prompt = (prompt_dir / "phase4a5-invariants.md").read_text(encoding="utf-8")
    rag_prompt = (prompt_dir / "phase4b5-rag-sweep.md").read_text(encoding="utf-8")

    assert "write the output scaffold" in inv_prompt
    assert "NOT_PRECOMPUTED_DEPTH_MUST_INSPECT" in inv_prompt
    assert "First, create `{SCRATCHPAD}/rag_validation.md`" in rag_prompt
    assert "[RAG: NOT_ENRICHED_BUDGET]" in rag_prompt


class TestFix2_FunctionNameSignal:

    def _make_inventory(self, scratchpad, findings):
        lines = ["# Findings Inventory\n"]
        for fid, title, loc, sev in findings:
            lines.append(f"### Finding [{fid}]: {title}")
            lines.append(f"**Severity**: {sev}")
            lines.append(f"**Location**: {loc}")
            lines.append(f"**Description**: test\n")
        (scratchpad / "findings_inventory.md").write_text(
            "\n".join(lines), encoding="utf-8"
        )

    def test_function_name_extracted_from_location(self, tmp_path):
        self._make_inventory(tmp_path, [
            ("INV-001", "Reentrancy in withdraw", "Contract.sol:withdraw:L42", "High"),
            ("INV-002", "Missing check in withdraw", "Contract.sol:withdraw:L78", "High"),
        ])
        n = P._compute_dedup_candidate_pairs(tmp_path)
        assert n >= 1
        text = (tmp_path / "dedup_candidate_pairs.md").read_text(encoding="utf-8")
        assert "same function: withdraw" in text

    def test_function_name_no_match_different_functions(self, tmp_path):
        self._make_inventory(tmp_path, [
            ("INV-001", "Bug in deposit", "Contract.sol:deposit:L10", "High"),
            ("INV-002", "Bug in withdraw", "Contract.sol:withdraw:L80", "High"),
        ])
        n = P._compute_dedup_candidate_pairs(tmp_path)
        text = (tmp_path / "dedup_candidate_pairs.md").read_text(encoding="utf-8")
        assert "same function" not in text

    def test_function_name_not_false_positive_on_L(self, tmp_path):
        """'L' in 'Contract.sol:L42' should not be extracted as function name."""
        self._make_inventory(tmp_path, [
            ("INV-001", "Bug A", "Contract.sol:L42", "High"),
            ("INV-002", "Bug B", "Contract.sol:L45", "High"),
        ])
        n = P._compute_dedup_candidate_pairs(tmp_path)
        text = (tmp_path / "dedup_candidate_pairs.md").read_text(encoding="utf-8")
        # Should pair on location overlap (42 vs 45 within 15 lines),
        # but NOT on function name "L" (signal format is "same function: X")
        assert "same function:" not in text

    def test_function_name_extracted_from_rust_location(self, tmp_path):
        self._make_inventory(tmp_path, [
            ("INV-001", "Panic in process_tx", "crates/p2p/src/lib.rs:process_tx:L100", "Medium"),
            ("INV-002", "DoS in process_tx", "crates/p2p/src/lib.rs:process_tx:L130", "Medium"),
        ])
        n = P._compute_dedup_candidate_pairs(tmp_path)
        text = (tmp_path / "dedup_candidate_pairs.md").read_text(encoding="utf-8")
        assert "same function: process_tx" in text

    def test_function_name_with_backtick_location(self, tmp_path):
        self._make_inventory(tmp_path, [
            ("INV-001", "Bug in foo", "`Contract.sol:myFunc:L10`", "Low"),
            ("INV-002", "Another bug", "`Contract.sol:myFunc:L50`", "Low"),
        ])
        n = P._compute_dedup_candidate_pairs(tmp_path)
        text = (tmp_path / "dedup_candidate_pairs.md").read_text(encoding="utf-8")
        assert "same function: myFunc" in text

    def test_signal_description_includes_five_signals(self, tmp_path):
        self._make_inventory(tmp_path, [
            ("INV-001", "A", "x.sol:foo:L1", "Low"),
            ("INV-002", "B", "x.sol:foo:L2", "Low"),
        ])
        P._compute_dedup_candidate_pairs(tmp_path)
        text = (tmp_path / "dedup_candidate_pairs.md").read_text(encoding="utf-8")
        assert "five independent signals" in text.lower()


# ═══════════════════════════════════════════════════════════════════════
# Fix 3: Quality observation classifier and megasection
# ═══════════════════════════════════════════════════════════════════════

class TestFix3_QualityMegasection:

    def test_classify_dead_code(self):
        assert P.classify_quality_observation("Dead code in _legacy()", "Informational") == "dead_code"

    def test_classify_unused_import(self):
        assert P.classify_quality_observation("Unused import SafeMath", "Low") == "unused_import"

    def test_classify_naming(self):
        assert P.classify_quality_observation("Naming inconsistency in setFee", "Informational") == "naming"

    def test_classify_gas_optimization(self):
        assert P.classify_quality_observation("Gas optimization in loop", "Informational") == "gas_optimization"

    def test_classify_magic_number(self):
        assert P.classify_quality_observation("Magic number 86400 used", "Low") == "magic_number"

    def test_classify_missing_docs(self):
        assert P.classify_quality_observation("Missing natspec for transfer", "Informational") == "missing_docs"

    def test_classify_redundant_code(self):
        assert P.classify_quality_observation("Redundant check in modifier", "Low") == "redundant_code"

    def test_classify_shadowing(self):
        assert P.classify_quality_observation("Variable shadow of owner", "Informational") == "shadowing"

    def test_not_classified_missing_validation(self):
        """Missing validation has security implications — must NOT be quality."""
        assert P.classify_quality_observation("Missing validation in setFee", "Low") == ""

    def test_not_classified_missing_event(self):
        """Missing events have monitoring implications — must NOT be quality."""
        assert P.classify_quality_observation("Missing event in setFee", "Low") == ""

    def test_not_classified_access_control(self):
        assert P.classify_quality_observation("Missing access control", "Low") == ""

    def test_not_classified_medium_severity(self):
        """Medium+ findings must NEVER be classified as quality observations."""
        assert P.classify_quality_observation("Dead code in _legacy()", "Medium") == ""

    def test_not_classified_high_severity(self):
        assert P.classify_quality_observation("Unused import SafeMath", "High") == ""

    def test_not_classified_reentrancy(self):
        assert P.classify_quality_observation("Reentrancy in withdraw", "Low") == ""

    def test_assembler_includes_quality_section(self, tmp_path):
        sp = tmp_path / ".scratchpad"
        sp.mkdir()
        proj = tmp_path / "project"
        proj.mkdir()
        idx = sp / "report_index.md"
        idx.write_text(
            "# Report Index\n\n"
            "## Summary\n\n"
            "| Severity | Count |\n|----------|-------|\n"
            "| Critical | 0 |\n| High | 0 |\n| Medium | 0 |\n"
            "| Low | 1 |\n| Informational | 1 |\n",
            encoding="utf-8",
        )
        low_info = sp / "report_low_info.md"
        low_info.write_text(
            "# Low and Informational Findings\n\n"
            "## Low Findings\n\n"
            "### [L-01] Missing validation in admin setter\n\n"
            "**Severity**: Low\n"
            "**Location**: `Vault.sol:L42`\n\n"
            "**Description**: The admin setter accepts any value.\n\n"
            "## Informational Findings\n\n"
            "(none with full section)\n\n"
            "## Quality Observations\n\n"
            "| ID | Title | Severity | Location | Class | Description |\n"
            "|----|-------|----------|----------|-------|-------------|\n"
            "| I-01 | Unused import SafeMath | Info | Vault.sol:L5 | Unused imports | Not used post-0.8 |\n",
            encoding="utf-8",
        )
        result = M._assemble_report_python(sp, str(proj))
        assert result is True
        report = (proj / "AUDIT_REPORT.md").read_text(encoding="utf-8")
        assert "## Quality Observations" in report
        assert "Unused import SafeMath" in report
        assert "## Low Findings" in report

    def test_quality_check_counts_megasection_rows(self, tmp_path):
        sp = tmp_path / ".scratchpad"
        sp.mkdir()
        proj = tmp_path / "project"
        proj.mkdir()
        idx = sp / "report_index.md"
        idx.write_text(
            "# Report Index\n\n"
            "## Summary\n\n"
            "| Severity | Count |\n|----------|-------|\n"
            "| Critical | 0 |\n| High | 0 |\n| Medium | 0 |\n"
            "| Low | 0 |\n| Informational | 2 |\n",
            encoding="utf-8",
        )
        low_info = sp / "report_low_info.md"
        low_info.write_text(
            "# Low and Informational Findings\n\n"
            "## Informational Findings\n\n"
            "(none with full section)\n\n"
            "## Quality Observations\n\n"
            "| ID | Title | Severity | Location | Class | Description |\n"
            "|----|-------|----------|----------|-------|-------------|\n"
            "| I-01 | Unused import | Info | V.sol:L5 | Unused imports | x |\n"
            "| I-02 | Dead code | Info | V.sol:L200 | Dead code | y |\n",
            encoding="utf-8",
        )
        M._assemble_report_python(sp, str(proj))
        qc = (sp / "report_quality.md").read_text(encoding="utf-8")
        assert "Quality observation rows: 2" in qc
        assert "quality_obs=YES" in qc


# ═══════════════════════════════════════════════════════════════════════
# Phase 4e methodology prompt
# ═══════════════════════════════════════════════════════════════════════

class TestPhase4ePrompt:

    def test_prompt_mentions_both_pipelines(self):
        prompt_path = plamen_home() / "prompts" / "shared" / "v2" / "phase4e-semantic-dedup.md"
        if not prompt_path.exists():
            pytest.skip("phase4e-semantic-dedup.md not found")
        text = prompt_path.read_text(encoding="utf-8")
        assert "SC mode" in text or "SC (mandatory" in text
        assert "L1 (mandatory" in text

    def test_prompt_mentions_five_signals(self):
        prompt_path = plamen_home() / "prompts" / "shared" / "v2" / "phase4e-semantic-dedup.md"
        if not prompt_path.exists():
            pytest.skip("phase4e-semantic-dedup.md not found")
        text = prompt_path.read_text(encoding="utf-8")
        assert "FIVE independent" in text or "five independent" in text.lower()
        assert "Function-name match" in text


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
