"""Tests for the depth-phase structural fix — Stage 1 safety net.

Covers:
  S1.1  _depth_artifact_is_stub / _validate_depth_artifact_substance
  S1.2  _split_nonblocking_foreign_writes (depth containment-as-quarantine)
  S1.3  _compute_depth_confidence (driver-owned mechanical scoring)
        + _synthesize_depth_lifecycle_artifacts confidence path

Run: `python -m pytest test_depth_phase_recovery.py -q`
"""
from __future__ import annotations

import sys
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS_DIR))

from plamen_driver import (  # noqa: E402
    _archive_orphan_stubs,
    _compute_depth_confidence,
    _depth_core_artifacts_present,
    _find_transcript_jsonl,
    _generate_depth_repair_hint,
    _is_header_only_stub,
    _is_valid_inventory_chunk_output,
    _resolve_never_cut_targets,
    _scan_transcript_for_background_orphan,
    _slugify_cwd_for_transcript,
    _split_nonblocking_foreign_writes,
    _synthesize_depth_lifecycle_artifacts,
    _try_adopt_inventory_sibling,
    detect_background_orphan,
)
from plamen_prompt import (  # noqa: E402
    PLAMEN_STUB_SENTINEL,
    _PLAMEN_EXECUTION_CONTRACT_CLAUDE,
    _PLAMEN_EXECUTION_CONTRACT_CODEX,
    _is_direct_execution_phase,
    _phase_uses_task,
    _render_execution_contract,
    _render_reservation_header,
)
from plamen_validators import (  # noqa: E402
    _depth_artifact_is_stub,
    _generate_depth_retry_hint,
    _generate_orphan_repair_hint,
    _validate_confidence_scores_quality,
    _validate_depth_artifact_substance,
)

_CORE_ARTIFACTS = (
    "depth_token_flow_findings.md", "depth_state_trace_findings.md",
    "depth_edge_case_findings.md", "depth_external_findings.md",
    "blind_spot_a_findings.md", "blind_spot_b_findings.md",
    "blind_spot_c_findings.md",
)

_FINDINGS = (
    "## Finding [DT-1] Reentrancy in withdraw\n"
    "**Severity**: High\n**Verdict**: CONFIRMED\n"
    "**Evidence**: [CODE-TRACE] external call before state write\n"
    "[BOUNDARY:amount=0] [TRACE:withdraw->revert]\n\n"
    "## Finding [DT-2] Rounding drift\n"
    "**Severity**: Medium\n**Verdict**: CONFIRMED\n"
    "**Evidence**: [POC-PASS] assert mismatch\n"
    "[BOUNDARY:shares=1] [VARIATION:decimals 18->6] [TRACE:mint]\n\n"
)


# ---------------------------------------------------------------------------
# S1.1 — stub detection
# ---------------------------------------------------------------------------

def test_s11_perturbation_stub_rejected(tmp_path):
    p = tmp_path / "perturbation_findings.md"
    p.write_text("# Perturbation Findings\n", encoding="utf-8")  # ~22 B
    assert _depth_artifact_is_stub(p) is not None


def test_s11_writing_in_progress_rejected(tmp_path):
    p = tmp_path / "depth_token_flow_findings.md"
    p.write_text("# Depth Token Flow\n_Writing in progress_\n" + "x" * 4000,
                 encoding="utf-8")
    assert _depth_artifact_is_stub(p) is not None


def test_s11_substantive_perturbation_accepted(tmp_path):
    p = tmp_path / "perturbation_findings.md"
    p.write_text("# Perturbation Findings\n\n### Perturbation Block — DT-3\n"
                 + "| Operator | Probe | Verdict |\n" + "x" * 1200,
                 encoding="utf-8")
    assert _depth_artifact_is_stub(p) is None


def test_s11_synthesized_confidence_rejected(tmp_path):
    p = tmp_path / "confidence_scores.md"
    p.write_text(
        "# Confidence Scores\n\n> **Status**: SYNTHESIZED — driver stub\n\n"
        "| Finding ID | Composite |\n| DT-1 | 0.50 |\n",
        encoding="utf-8",
    )
    assert _depth_artifact_is_stub(p) is not None


def test_s11_uniform_confidence_rejected(tmp_path):
    rows = "\n".join(
        f"| DT-{i} | 0.50 | 0.50 | 0.50 | 0.30 | 0.50 | UNCERTAIN | x |"
        for i in range(1, 6)
    )
    p = tmp_path / "confidence_scores.md"
    p.write_text(
        "# Confidence Scores\n\n> **Status**: DRIVER-COMPUTED\n\n"
        "| Finding ID | Evidence | Consensus | Quality | RAG | Composite "
        "| Classification | Source |\n"
        "|--|--|--|--|--|--|--|--|\n" + rows + "\n",
        encoding="utf-8",
    )
    assert _depth_artifact_is_stub(p) is not None


def test_s11_substantive_findings_file_accepted(tmp_path):
    p = tmp_path / "depth_state_trace_findings.md"
    p.write_text("# Depth State Trace\n\n" + _FINDINGS, encoding="utf-8")
    assert _depth_artifact_is_stub(p) is None


def test_s11_substance_gate_flags_only_stub_group(tmp_path):
    # All 4 core depth files substantive; perturbation a stub.
    for name in (
        "depth_token_flow_findings.md", "depth_state_trace_findings.md",
        "depth_edge_case_findings.md", "depth_external_findings.md",
        "blind_spot_a_findings.md", "blind_spot_b_findings.md",
        "blind_spot_c_findings.md", "validation_sweep_findings.md",
        "design_stress_findings.md", "skill_execution_gaps.md",
    ):
        (tmp_path / name).write_text("# F\n\n" + _FINDINGS, encoding="utf-8")
    (tmp_path / "perturbation_findings.md").write_text("# P\n", encoding="utf-8")
    _compute_depth_confidence(tmp_path, "thorough")  # real confidence file
    stubs = _validate_depth_artifact_substance(tmp_path, "thorough", "sc")
    assert len(stubs) == 1 and "perturbation_findings.md" in stubs[0]


# ---------------------------------------------------------------------------
# S1.2 — containment-as-quarantine
# ---------------------------------------------------------------------------

def test_s12_chain_artifacts_benign_for_depth():
    benign, blocking = _split_nonblocking_foreign_writes(
        "depth",
        ["hypotheses.md", "finding_mapping.md", "enabler_results.md",
         "chain_hypotheses.md", "synthesis_full.md", "composition_coverage.md"],
    )
    assert blocking == []
    assert set(benign) == {
        "hypotheses.md", "finding_mapping.md", "enabler_results.md",
        "chain_hypotheses.md", "synthesis_full.md", "composition_coverage.md",
    }


def test_s12_verify_report_stay_blocking_for_depth():
    benign, blocking = _split_nonblocking_foreign_writes(
        "depth", ["hypotheses.md", "verify_H-1.md", "report_index.md"]
    )
    assert benign == ["hypotheses.md"]
    assert set(blocking) == {"verify_H-1.md", "report_index.md"}


# ---------------------------------------------------------------------------
# S1.3 — mechanical confidence
# ---------------------------------------------------------------------------

def test_s13_confidence_is_differentiated(tmp_path):
    (tmp_path / "depth_token_flow_findings.md").write_text(
        "# F\n\n" + _FINDINGS, encoding="utf-8"
    )
    n = _compute_depth_confidence(tmp_path, "thorough")
    assert n == 2
    text = (tmp_path / "confidence_scores.md").read_text(encoding="utf-8")
    assert "DRIVER-COMPUTED" in text
    # Two findings with different evidence/quality -> different composites.
    composites = [
        line.split("|")[5].strip()
        for line in text.splitlines()
        if line.startswith("| DT-")
    ]
    assert len(composites) == 2 and len(set(composites)) == 2


def test_s13_driver_confidence_passes_quality_gate(tmp_path):
    findings = "\n".join(
        f"## Finding [DT-{i}] Bug {i}\n**Severity**: Medium\n"
        f"**Evidence**: {tag}\n{dtags}\n"
        for i, (tag, dtags) in enumerate([
            ("[POC-PASS]", "[BOUNDARY:a] [TRACE:b] [VARIATION:c]"),
            ("[CODE-TRACE]", "[BOUNDARY:a]"),
            ("[DOC]", ""),
            ("[CODE]", "[TRACE:b] [BOUNDARY:a]"),
            ("[MOCK]", ""),
        ], start=1)
    )
    (tmp_path / "depth_external_findings.md").write_text(
        "# F\n\n" + findings, encoding="utf-8"
    )
    _compute_depth_confidence(tmp_path, "thorough")
    # Differentiated scores must NOT be flagged as a formulaic stub.
    assert _validate_confidence_scores_quality(tmp_path, "thorough") == []


def test_s13_synthesize_replaces_synthesized_stub(tmp_path):
    (tmp_path / "depth_token_flow_findings.md").write_text(
        "# F\n\n" + _FINDINGS, encoding="utf-8"
    )
    (tmp_path / "confidence_scores.md").write_text(
        "# Confidence Scores\n\n> **Status**: SYNTHESIZED — old stub\n\n"
        "| DT-1 | 0.50 |\n",
        encoding="utf-8",
    )
    _synthesize_depth_lifecycle_artifacts(tmp_path, "sc", mode="thorough")
    text = (tmp_path / "confidence_scores.md").read_text(encoding="utf-8")
    assert "DRIVER-COMPUTED" in text and "SYNTHESIZED" not in text


# ---------------------------------------------------------------------------
# S1.6 — depth core-artifact presence (degrade-not-halt decision)
# ---------------------------------------------------------------------------

def _write_core(tmp_path, omit=(), stub=()):
    for name in _CORE_ARTIFACTS:
        if name in omit:
            continue
        body = "# F\n" if name in stub else "# F\n\n" + _FINDINGS + "x" * 400
        (tmp_path / name).write_text(body, encoding="utf-8")


def test_s16_core_present_when_all_substantive(tmp_path):
    _write_core(tmp_path)
    assert _depth_core_artifacts_present(tmp_path) is True


def test_s16_core_absent_when_one_missing(tmp_path):
    _write_core(tmp_path, omit=("depth_external_findings.md",))
    assert _depth_core_artifacts_present(tmp_path) is False


def test_s16_core_absent_when_one_is_stub(tmp_path):
    _write_core(tmp_path, stub=("blind_spot_c_findings.md",))
    assert _depth_core_artifacts_present(tmp_path) is False


def test_s16_core_absent_on_empty_scratchpad(tmp_path):
    assert _depth_core_artifacts_present(tmp_path) is False


def test_s16_l1_core_uses_l1_role_files(tmp_path):
    l1_core = (
        "depth_consensus_invariant_findings.md",
        "depth_network_surface_findings.md",
        "depth_state_trace_findings.md",
        "depth_external_findings.md",
        "depth_edge_case_findings.md",
    )
    for name in l1_core:
        (tmp_path / name).write_text("# F\n\n" + _FINDINGS + "x" * 400, encoding="utf-8")

    assert _depth_core_artifacts_present(tmp_path, pipeline="l1", mode="core") is True
    assert _depth_core_artifacts_present(tmp_path, pipeline="sc", mode="core") is False


# ---------------------------------------------------------------------------
# S1.5 — targeted repair hint
# ---------------------------------------------------------------------------

def test_s15_repair_hint_names_gaps_and_forbids_chain(tmp_path):
    hint = _generate_depth_repair_hint([
        "perturbation_findings.md (stub - 79 bytes)",
        "confidence iter2: Medium+ UNCERTAIN findings",
    ])
    assert "perturbation_findings.md (stub - 79 bytes)" in hint
    assert "iteration 2" in hint
    # The repair attempt must not overrun the phase boundary.
    assert "Do NOT write `hypotheses.md`" in hint
    # And must not redo the expensive core findings.
    assert "DO NOT regenerate" in hint


def test_s15_repair_hint_handles_empty_missing():
    # Defensive: empty gap list still yields a usable hint.
    hint = _generate_depth_repair_hint([])
    assert "depth targeted repair" in hint and "perturbation_findings.md" in hint


def test_s13_synthesize_replaces_llm_confidence_with_driver_authority(tmp_path):
    (tmp_path / "depth_token_flow_findings.md").write_text(
        "# F\n\n" + _FINDINGS, encoding="utf-8"
    )
    real = (
        "# Confidence Scores\n\n> **Status**: complete (LLM per-finding)\n\n"
        "| Finding ID | Evidence | Consensus | Quality | RAG | Composite "
        "| Classification | Source |\n"
        "|--|--|--|--|--|--|--|--|\n"
        "| DT-1 | 0.80 | 1.00 | 0.70 | 0.90 | 0.84 | CONFIDENT | x |\n"
        "| DT-2 | 0.40 | 1.00 | 0.40 | 0.30 | 0.49 | UNCERTAIN | x |\n"
    )
    (tmp_path / "confidence_scores.md").write_text(real, encoding="utf-8")
    _synthesize_depth_lifecycle_artifacts(tmp_path, "sc", mode="thorough")
    # An LLM-written score table is a proposal, not agreement authority.  The
    # deterministic finalizer replaces it even when it is substantive.
    rebuilt = (tmp_path / "confidence_scores.md").read_text(encoding="utf-8")
    assert rebuilt != real
    assert "DRIVER-COMPUTED" in rebuilt
    assert "Mode: THOROUGH_3_AXIS" in rebuilt
    assert "| DT-1 |" in rebuilt and "| DT-2 |" in rebuilt
    rows = [line for line in rebuilt.splitlines() if line.startswith("| DT-")]
    assert rows and all(line.split("|")[3].strip() == "0.00" for line in rows)


# ---------------------------------------------------------------------------
# F2 — depth lifecycle recompute (post-audit hardening)
# ---------------------------------------------------------------------------

def test_f2_0_blind_spot_findings_are_counted(tmp_path):
    """F2.0: the broadened _FINDING_HEADING_RE must score BLIND-A-N style IDs
    (the prior regex rejected them — 0/14 in a past audit)."""
    (tmp_path / "blind_spot_a_findings.md").write_text(
        "# F\n\n"
        "## Finding [BLIND-A-1] Some bug\n"
        "**Severity**: Medium\n**Evidence**: [CODE-TRACE]\n[BOUNDARY:x]\n\n"
        "## Finding [BLIND-A-2] Another bug\n"
        "**Severity**: High\n**Evidence**: [POC-PASS]\n[BOUNDARY:y] [TRACE:z]\n",
        encoding="utf-8",
    )
    n = _compute_depth_confidence(tmp_path, "thorough")
    assert n == 2
    text = (tmp_path / "confidence_scores.md").read_text(encoding="utf-8")
    assert "BLIND-A-1" in text and "BLIND-A-2" in text


def test_f2_0_dedupes_on_normalized_id(tmp_path):
    """The same finding surfacing in two files (different prefix shapes that
    normalize to the same canonical ID) must yield ONE row, not two."""
    # Same INV-001 from two source files (sometimes happens when promotion
    # writes both `## Finding [INV-001]` and an inventory-style heading).
    (tmp_path / "depth_token_flow_findings.md").write_text(
        "## Finding [INV-001] Foo\n**Severity**: High\n**Evidence**: [CODE-TRACE]\n",
        encoding="utf-8",
    )
    (tmp_path / "scanner_validation_findings.md").write_text(
        "## Finding [INV-001] Same Foo (rediscovered)\n**Evidence**: [CODE-TRACE]\n",
        encoding="utf-8",
    )
    n = _compute_depth_confidence(tmp_path, "thorough")
    assert n == 1


def test_f2_a_rebuild_order_confidence_before_checkpoint(tmp_path):
    """F2.a: confidence_scores.md must be rebuilt BEFORE never_cut_checkpoint
    so the checkpoint records `confidence-scoring: SPAWNED` (not SKIPPED).

    v2.0.3 (A3): fixture made substantive (>1 KB) so the lifecycle synth's
    new substance-aware status check classifies it as SPAWNED, not STUB.
    F2.a's intent is rebuild ORDER, not content shape — making the fixture
    substantive preserves that intent.
    """
    (tmp_path / "depth_token_flow_findings.md").write_text(
        (
            "## Finding [DT-1] Bug\n**Severity**: High\n"
            "**Evidence**: [CODE-TRACE]\n[BOUNDARY:x]\n"
            "**Description**: A real and substantive finding with enough "
            "content to survive the v2.0.3 substance-aware lifecycle check. "
            "The depth_token_flow agent traced a token leak across the "
            "boundary between deposit() and withdraw(); the leak occurs "
            "when the recipient address callback re-enters before the "
            "shares accounting is updated.\n"
        ) * 4,
        encoding="utf-8",
    )
    # Pre-existing stale checkpoint claiming everything is SKIPPED.
    (tmp_path / "never_cut_checkpoint.md").write_text(
        "# Never-Cut Checkpoint\n- depth-token-flow: SKIPPED NO_APPLICABLE_FLAG\n"
        "- confidence-scoring: SKIPPED NO_APPLICABLE_FLAG\n",
        encoding="utf-8",
    )
    _synthesize_depth_lifecycle_artifacts(tmp_path, "sc", mode="thorough")
    ncc = (tmp_path / "never_cut_checkpoint.md").read_text(encoding="utf-8")
    cs = (tmp_path / "confidence_scores.md").read_text(encoding="utf-8")
    # Both updated; checkpoint reflects the just-rebuilt confidence file.
    assert "confidence-scoring: SPAWNED" in ncc
    assert "depth-token-flow: SPAWNED" in ncc
    assert "DRIVER-COMPUTED" in cs and "DT-1" in cs


def test_f2_b_placeholder_is_stub_when_real_findings_exist(tmp_path):
    """F2.b: a DRIVER-COMPUTED `(no findings produced)` placeholder is a
    stub WHEN real depth findings exist on disk."""
    (tmp_path / "depth_token_flow_findings.md").write_text(
        "## Finding [DT-1] Bug\n**Severity**: High\n**Evidence**: [CODE-TRACE]\n",
        encoding="utf-8",
    )
    (tmp_path / "confidence_scores.md").write_text(
        "# Confidence Scores (driver-computed)\n\n"
        "> **Status**: DRIVER-COMPUTED — placeholder\n\n"
        "| Finding ID | Evidence | Consensus | Quality | RAG | Composite "
        "| Classification | Source |\n"
        "|--|--|--|--|--|--|--|--|\n"
        "| - | - | - | - | - | - | - | (no findings produced) |\n",
        encoding="utf-8",
    )
    assert _depth_artifact_is_stub(tmp_path / "confidence_scores.md") is not None


def test_f2_b_placeholder_NOT_stub_on_clean_codebase(tmp_path):
    """F2.b regression guard: the same placeholder file with NO real depth
    findings on disk is a LEGITIMATE clean-codebase result, not a stub."""
    # No depth_*_findings.md / blind_spot_*_findings.md exist on disk.
    (tmp_path / "confidence_scores.md").write_text(
        "# Confidence Scores (driver-computed)\n\n"
        "> **Status**: DRIVER-COMPUTED — placeholder\n\n"
        "| Finding ID | Evidence | Consensus | Quality | RAG | Composite "
        "| Classification | Source |\n"
        "|--|--|--|--|--|--|--|--|\n"
        "| - | - | - | - | - | - | - | (no findings produced) |\n",
        encoding="utf-8",
    )
    assert _depth_artifact_is_stub(tmp_path / "confidence_scores.md") is None


# ---------------------------------------------------------------------------
# F7 — live-containment dual-path downgrade
# ---------------------------------------------------------------------------

def test_f7_benign_helper_matches_chain_synthesis_artifacts():
    """F7.a helper: depth's chain/synthesis post-completion writes are benign;
    far-downstream artifacts (verify/report) stay blocking."""
    from plamen_driver import _is_benign_depth_foreign_artifact
    # Benign — quarantined post-run, must NOT kill subprocess mid-run.
    for name in (
        "hypotheses.md", "finding_mapping.md", "enabler_results.md",
        "chain_hypotheses.md", "chain_iter2.md", "synthesis_full.md",
        "composition_coverage.md",
    ):
        assert _is_benign_depth_foreign_artifact(name) is True, name
    # Still blocking — a depth phase writing these is a severe boundary breach.
    for name in (
        "verify_H-1.md", "verify_core.md",
        "report_index.md", "report_critical_high.md", "report_assemble.md",
        "AUDIT_REPORT.md",
        # Unrelated phase outputs are not "benign" for depth.
        "findings_inventory.md", "spawn_manifest.md",
    ):
        assert _is_benign_depth_foreign_artifact(name) is False, name


def test_f7_split_uses_centralized_helper_for_depth():
    """F7: post-run classifier and live ticks share the same source of truth.
    Verify _split_nonblocking_foreign_writes uses _is_benign_depth_foreign_artifact."""
    from plamen_driver import _split_nonblocking_foreign_writes
    benign, blocking = _split_nonblocking_foreign_writes(
        "depth",
        ["hypotheses.md", "verify_H-1.md", "chain_hypotheses.md",
         "synthesis_full.md", "AUDIT_REPORT.md", "report_index.md"],
    )
    assert set(benign) == {"hypotheses.md", "chain_hypotheses.md", "synthesis_full.md"}
    assert set(blocking) == {"verify_H-1.md", "AUDIT_REPORT.md", "report_index.md"}


# ---------------------------------------------------------------------------
# F4 — opengrep obligation receipts: table-form relaxation
# ---------------------------------------------------------------------------

def _make_opengrep(tmp_path, n_rows=3):
    """Write a minimal opengrep_findings.md with N numeric data rows."""
    lines = ["# OpenGrep Findings\n",
             "| Row | Rule | Severity | Location | Message |",
             "|-----|------|----------|----------|---------|"]
    for i in range(1, n_rows + 1):
        lines.append(f"| {i} | rule-{i} | info | Foo.sol:L{i} | msg-{i} |")
    (tmp_path / "opengrep_findings.md").write_text(
        "\n".join(lines) + "\n", encoding="utf-8"
    )


def test_f4_table_form_receipts_are_parsed(tmp_path):
    """F4: a markdown-table-form receipts section under the
    `## Obligation Receipts ... opengrep` heading is now recognized."""
    from plamen_validators import _collect_obligation_receipts
    _make_opengrep(tmp_path, n_rows=3)
    (tmp_path / "analysis_x.md").write_text(
        "# Access Control\n\nSome analysis.\n\n"
        "## Obligation Receipts — opengrep_findings.md\n\n"
        "| Row | Rule | Location | Addressed By | Notes |\n"
        "|-----|------|----------|--------------|-------|\n"
        "| 1 | rule-1 | Foo.sol:L1 | AC-4 | raised |\n"
        "| 2 | rule-2 | Foo.sol:L2 | (none) | style only, gas optimization |\n"
        "| 3 | rule-3 | Foo.sol:L3 | (none) | deferred to verify phase |\n",
        encoding="utf-8",
    )
    receipts = _collect_obligation_receipts(
        tmp_path, "opengrep_findings.md", ("analysis_*.md",)
    )
    assert receipts == {"1": "REPORTED", "2": "DISMISSED", "3": "CARRIED"}


def test_f4_strict_line_form_still_works(tmp_path):
    """F4: strict-line form (the canonical shape) parses identically — the
    table parser is additive only."""
    from plamen_validators import _collect_obligation_receipts
    _make_opengrep(tmp_path, n_rows=2)
    (tmp_path / "analysis_x.md").write_text(
        "[OBLIG:opengrep_findings.md:1] STATUS:R KEY:rule-1@Foo.sol:L1 -> AC-1\n"
        "[OBLIG:opengrep_findings.md:2] STATUS:D KEY:rule-2 -> style only\n",
        encoding="utf-8",
    )
    receipts = _collect_obligation_receipts(
        tmp_path, "opengrep_findings.md", ("analysis_*.md",)
    )
    assert receipts == {"1": "REPORTED", "2": "DISMISSED"}


def test_f4_unrelated_table_not_absorbed(tmp_path):
    """F4 conservative guard: a markdown table that's NOT under the
    `Obligation Receipts ... opengrep` heading must not be parsed as
    receipts (otherwise unrelated finding-summary tables would become
    fake receipts)."""
    from plamen_validators import _collect_obligation_receipts
    _make_opengrep(tmp_path, n_rows=3)
    (tmp_path / "analysis_x.md").write_text(
        "# Findings Summary\n\n"
        "| Row | Title | Severity |\n"
        "|-----|-------|----------|\n"
        "| 1 | unrelated finding | high |\n"
        "| 2 | another finding | medium |\n"
        "\n## Some Other Section\n\nNo receipts here either.\n",
        encoding="utf-8",
    )
    receipts = _collect_obligation_receipts(
        tmp_path, "opengrep_findings.md", ("analysis_*.md",)
    )
    assert receipts == {}, receipts


def test_f4_mixed_forms_dedupe_strict_wins(tmp_path):
    """F4: if BOTH the strict line form and the table form mention the same
    row, strict-line wins (it's canonical and unambiguous)."""
    from plamen_validators import _collect_obligation_receipts
    _make_opengrep(tmp_path, n_rows=2)
    (tmp_path / "analysis_x.md").write_text(
        "[OBLIG:opengrep_findings.md:1] STATUS:C KEY:rule-1 -> later\n\n"
        "## Obligation Receipts — opengrep_findings.md\n\n"
        "| Row | Notes |\n|-----|-------|\n"
        "| 1 | this is a different table row stating REPORTED |\n"
        "| 2 | style only — gas optimization |\n",
        encoding="utf-8",
    )
    receipts = _collect_obligation_receipts(
        tmp_path, "opengrep_findings.md", ("analysis_*.md",)
    )
    # Row 1 from strict-line wins (CARRIED), row 2 from table (DISMISSED).
    assert receipts == {"1": "CARRIED", "2": "DISMISSED"}


def test_f4_empty_addressed_by_cells_not_counted(tmp_path):
    """F4: rows whose every non-first cell is empty / N/A / `-` are NOT
    receipts (likely template placeholders)."""
    from plamen_validators import _collect_obligation_receipts
    _make_opengrep(tmp_path, n_rows=3)
    (tmp_path / "analysis_x.md").write_text(
        "## Obligation Receipts — opengrep_findings.md\n\n"
        "| Row | Addressed By | Notes |\n|-----|--------------|-------|\n"
        "| 1 | (none) | (none) |\n"
        "| 2 |  |  |\n"
        "| 3 | AC-7 | real receipt |\n",
        encoding="utf-8",
    )
    receipts = _collect_obligation_receipts(
        tmp_path, "opengrep_findings.md", ("analysis_*.md",)
    )
    # Only row 3 is a real receipt; row 1 and 2 are empty-cell templates.
    assert receipts == {"3": "REPORTED"}


def test_f5_anti_absorption_retry_hint_states_jaccard_threshold():
    """F5.b: the retry-hint recap must state the 0.30 numeric threshold + the
    Jaccard metric definition (prior wording said 'overlap' vaguely)."""
    from plamen_validators import _generate_anti_absorption_retry_hint
    hint = _generate_anti_absorption_retry_hint(
        ["GRP-01 absorbs 2 constituents with root-cause Jaccard 0.10 < 0.30"]
    )
    assert "0.30" in hint
    # Metric definition for clarity.
    assert "Jaccard" in hint
    assert "|A" in hint and "B|" in hint  # the |A ∩ B|/|A ∪ B| formula


def test_f7_non_depth_phases_unaffected():
    """F7 is depth-only — non-depth phases still see the full protected set
    as blocking (no behavior change)."""
    from plamen_driver import _split_nonblocking_foreign_writes
    # rag_sweep (or any non-depth/non-breadth/non-report_index phase) gets
    # default behavior — everything blocking.
    benign, blocking = _split_nonblocking_foreign_writes(
        "rag_sweep", ["hypotheses.md", "verify_H-1.md"]
    )
    assert benign == []
    assert set(blocking) == {"hypotheses.md", "verify_H-1.md"}


def test_f2_c_depth_exit_does_not_bloat_across_repeated_calls(tmp_path):
    """F2.c: calling _synthesize_depth_lifecycle_artifacts repeatedly must
    not grow depth_exit.md unboundedly. Anti-recursive preservation strips
    any prior driver wrapper before re-preserving the LLM body."""
    (tmp_path / "depth_token_flow_findings.md").write_text(
        "## Finding [DT-1] Bug\n**Severity**: High\n", encoding="utf-8"
    )
    # LLM-authored depth_exit body.
    (tmp_path / "depth_exit.md").write_text(
        "# My LLM exit\nrationale: I did the depth analysis\n", encoding="utf-8"
    )
    sizes = []
    for _ in range(5):
        _synthesize_depth_lifecycle_artifacts(tmp_path, "sc", mode="thorough")
        sizes.append((tmp_path / "depth_exit.md").stat().st_size)
    # Bounded — no unbounded growth across 5 calls (allow ≤ 5 bytes drift).
    assert max(sizes) - min(sizes) <= 5, sizes
    text = (tmp_path / "depth_exit.md").read_text(encoding="utf-8")
    # Exactly ONE "Original LLM" heading — no recursive nesting.
    assert text.count("## Original LLM depth exit (preserved)") == 1
    # Driver header + LLM body both present.
    assert "Depth Exit (auto-synthesized by driver)" in text
    assert "My LLM exit" in text


# ---------------------------------------------------------------------------
# v2.0.3 / Phase A — orphan-background closure
# ---------------------------------------------------------------------------

import json as _json  # local alias to keep top-import block stable

# Enumerate via the canonical phase tables — keeps the test honest if a new
# phase is added in either direction.
from plamen_types import SC_PHASES, L1_PHASES  # noqa: E402


def _all_phase_names():
    seen = set()
    for phase_list in (SC_PHASES, L1_PHASES):
        for ph in phase_list:
            seen.add(ph.name)
    return sorted(seen)


def test_a1_phase_uses_task_inverse_of_direct_execution():
    """v2.0.3 (A1) test 1 / Codex Round-2 Claim 9: the two predicates must
    be mutually exclusive across every (phase, pipeline, backend) tuple.

    A new phase added to one set without removal from the other implies
    the contract-injection gate disagrees with the wrapper-execution gate
    — which would silently drop or duplicate the contract. This test is
    the mechanical enforcement of consistency.
    """
    for phase in _all_phase_names():
        for pipeline in ("sc", "l1"):
            for backend in ("claude", "codex"):
                a = _phase_uses_task(phase, pipeline, backend=backend)
                b = _is_direct_execution_phase(phase, pipeline, backend=backend)
                assert a != b, (
                    f"predicate drift: phase={phase} pipeline={pipeline} "
                    f"backend={backend} both returned {a}"
                )


def test_a1_execution_contract_claude_for_task_phases():
    """v2.0.3 (A1) test 2: Claude Task-using phases receive the Claude variant."""
    # depth is the canonical Task-using SC phase.
    assert "run_in_background" in _render_execution_contract(
        "depth", "sc", backend="claude"
    )
    # breadth is Task-using on Claude.
    assert "run_in_background" in _render_execution_contract(
        "breadth", "sc", backend="claude"
    )
    # Recon is driver-owned worker-pool/direct handoff now; do not reintroduce
    # a coordinator Task contract.
    assert _render_execution_contract("recon", "sc", backend="claude") == ""


def test_a1_execution_contract_codex_for_multi_agent_phases():
    """v2.0.3 (A1) test 3: Codex multi-agent phases receive the Codex variant
    (spawn_agent / wait_agent vocabulary, NOT Task / run_in_background).
    """
    block = _render_execution_contract("depth", "sc", backend="codex")
    assert "spawn_agent" in block
    assert "wait_agent" in block
    assert "run_in_background" not in block


def test_a1_execution_contract_absent_from_direct_phases():
    """v2.0.3 (A1) test 4 / Codex Round-2 Claim 9: the contract is
    INJECTED iff `_phase_uses_task` returns True. Direct-execution phases
    get an empty string; multi-agent phases get a non-empty contract.

    Important: this test does NOT enumerate a hand-coded list — it uses
    the predicate directly. If predicates disagree it's caught by
    test_a1_phase_uses_task_inverse_of_direct_execution above.
    """
    for phase in _all_phase_names():
        for pipeline in ("sc", "l1"):
            for backend in ("claude", "codex"):
                expects_contract = _phase_uses_task(
                    phase, pipeline, backend=backend
                )
                block = _render_execution_contract(
                    phase, pipeline, backend=backend
                )
                if expects_contract:
                    assert block, (
                        f"missing contract: phase={phase} pipeline={pipeline} "
                        f"backend={backend}"
                    )
                else:
                    assert block == "", (
                        f"contract leaked into direct-exec phase: "
                        f"phase={phase} pipeline={pipeline} backend={backend}"
                    )


def test_a2_detect_orphan_heuristic_path(tmp_path):
    """v2.0.3 (A2): heuristic path — rc=0 + ≥2 header-only stubs in
    never-cut groups → emit diagnostic with evidence="heuristic".
    """
    # Substantive token-flow file (one real depth output)
    (tmp_path / "depth_token_flow_findings.md").write_text(
        "## Finding [DT-1] Real bug\n**Severity**: High\n"
        "[BOUNDARY:x=0] [TRACE:f->revert]\n" * 30,
        encoding="utf-8",
    )
    # 5 stub files (the orphan-background fingerprint)
    for name in (
        "depth_state_trace_findings.md",
        "depth_edge_case_findings.md",
        "depth_external_findings.md",
        "blind_spot_a_findings.md",
        "validation_sweep_findings.md",
    ):
        (tmp_path / name).write_text(f"# {name}\n", encoding="utf-8")
    fake_log = tmp_path / "_stdio.log"
    fake_log.write_text("")
    diag = detect_background_orphan(
        fake_log, tmp_path, "depth", "thorough", "sc", rc=0
    )
    assert diag is not None
    assert diag["evidence"] == "heuristic"
    assert diag["stub_count"] >= 5
    # Diagnostic file written to scratchpad
    assert (tmp_path / "_diagnostic_orphan_depth.json").exists()


def test_a2_detect_orphan_rc_nonzero_suppressed(tmp_path):
    """v2.0.3 (A2) / Codex Round-2 Claim 10: heuristic path requires rc==0.
    rc≠0 means timeout/crash — a different failure class, not orphan.

    Note: Phase B will add the definitive-evidence (transcript JSONL) path
    which works regardless of rc. A2 ships heuristic-only.
    """
    (tmp_path / "depth_token_flow_findings.md").write_text(
        "## Finding [DT-1]\n" * 30, encoding="utf-8"
    )
    for name in ("depth_state_trace_findings.md",
                 "depth_edge_case_findings.md",
                 "depth_external_findings.md"):
        (tmp_path / name).write_text(f"# {name}\n", encoding="utf-8")
    fake_log = tmp_path / "_stdio.log"
    fake_log.write_text("")
    # rc=-2 (timeout sentinel) → no detection
    diag = detect_background_orphan(
        fake_log, tmp_path, "depth", "thorough", "sc", rc=-2
    )
    assert diag is None
    assert not (tmp_path / "_diagnostic_orphan_depth.json").exists()


def test_a2_detect_orphan_non_depth_phase_returns_none(tmp_path):
    """v2.0.3 (A2): orphan detection only applies to depth (the only phase
    with a never-cut artifact group). Other phases return None silently.
    """
    fake_log = tmp_path / "_stdio.log"
    fake_log.write_text("")
    for phase_name in ("breadth", "rescan", "chain", "inventory_chunk_a"):
        diag = detect_background_orphan(
            fake_log, tmp_path, phase_name, "thorough", "sc", rc=0
        )
        assert diag is None, f"unexpected detection for {phase_name}"


def test_a3_lifecycle_marks_stubs_as_stub(tmp_path):
    """v2.0.3 (A3) / Codex Claim 7: never_cut_checkpoint.md must report
    STUB for header-only files, not SPAWNED. The existence-only check
    that was there pre-v2.0.3 hid the orphan signature from the
    diagnostic surface.
    """
    # 1 substantive + 3 stubs (a prior audit's attempt-2 shape)
    (tmp_path / "depth_token_flow_findings.md").write_text(
        "## Finding [DT-1] Real bug\n**Severity**: High\n" * 30,
        encoding="utf-8",
    )
    (tmp_path / "depth_state_trace_findings.md").write_text(
        "# Depth State Trace Findings\n", encoding="utf-8"
    )
    (tmp_path / "depth_edge_case_findings.md").write_text(
        "# Depth Edge Case Findings\n", encoding="utf-8"
    )
    (tmp_path / "depth_external_findings.md").write_text(
        "# Depth External Findings\n", encoding="utf-8"
    )
    # confidence_scores.md must exist so the synth doesn't rewrite it
    (tmp_path / "confidence_scores.md").write_text(
        "# Confidence Scores\n"
        "Status: DRIVER-COMPUTED\n\n"
        "| Finding | Composite |\n|---|---|\n| DT-1 | 0.65 |\n",
        encoding="utf-8",
    )
    _synthesize_depth_lifecycle_artifacts(tmp_path, "sc", mode="thorough")
    ncc = (tmp_path / "never_cut_checkpoint.md").read_text(encoding="utf-8")
    # The substantive role is SPAWNED
    assert "depth-token-flow: SPAWNED" in ncc
    # Stubs are STUB, not SPAWNED
    assert "depth-state-trace: STUB" in ncc
    assert "depth-edge-case: STUB" in ncc
    assert "depth-external: STUB" in ncc
    # depth_exit.md splits substantive vs stub
    dep = (tmp_path / "depth_exit.md").read_text(encoding="utf-8")
    assert "depth_token_flow_findings.md" in dep
    assert "stub_paths" in dep
    assert "depth_state_trace_findings.md" in dep  # listed under stubs


def test_a4_orphan_retry_hint_reads_diagnostic(tmp_path):
    """v2.0.3 (A4) / Codex Round-2 Claim 6: retry hint dispatch reads
    the driver-written diagnostic file. The validator-side hint generator
    has no detection logic of its own — it only consumes.
    """
    diag = {
        "phase": "depth",
        "evidence": "heuristic",
        "rc": 0,
        "backend": "claude",
        "stub_count": 5,
        "stub_files": [
            "depth_state_trace_findings.md",
            "depth_edge_case_findings.md",
            "depth_external_findings.md",
            "blind_spot_a_findings.md",
            "validation_sweep_findings.md",
        ],
        "fingerprint": "header_only_files_with_clean_rc",
    }
    (tmp_path / "_diagnostic_orphan_depth.json").write_text(
        _json.dumps(diag), encoding="utf-8"
    )
    # Pass a junk issue list — the orphan dispatch should override
    hint = _generate_depth_retry_hint(
        ["never-cut artifacts are stubs: x"],
        backend="claude",
        scratchpad=tmp_path,
    )
    assert "FOREGROUND" in hint
    assert "run_in_background" in hint
    # All five stub files cited
    for name in diag["stub_files"]:
        assert name in hint
    # Codex variant cites spawn_agent
    hint_codex = _generate_depth_retry_hint(
        ["x"], backend="codex", scratchpad=tmp_path
    )
    assert "spawn_agent" in hint_codex
    assert "wait_agent" in hint_codex
    # No diagnostic file → falls through to existing quality-gate hint
    (tmp_path / "_diagnostic_orphan_depth.json").unlink()
    hint_fallback = _generate_depth_retry_hint(
        ["never-cut artifacts are stubs: y"],
        backend="claude",
        scratchpad=tmp_path,
    )
    assert "FOREGROUND" not in hint_fallback
    assert "depth quality gate" in hint_fallback


def _substantive_inventory_chunk(letter: str, n: int = 5) -> str:
    """Build a chunk file that passes _is_valid_inventory_chunk_output."""
    head = f"# Chunk {letter.upper()}\n\n## Source Summary\n| source | count |\n|---|---|\n| analysis_x.md | {n} |\n\n## Master Table\n"
    head += "| CC ID | Title | Severity |\n|---|---|---|\n"
    for i in range(1, n + 1):
        head += f"| CC-{i:02d} | Finding {i} | High |\n"
    head += "\n## Per-Finding Detail\n\n"
    for i in range(1, n + 1):
        head += (
            f"### Finding [CC-{i:02d}]: Finding {i}\n"
            f"**Source IDs**: H-{i}\n"
            f"**Severity**: High\n"
            f"**Location**: src/X.sol:{i*10}\n"
            f"**Preferred Tag**: CODE\n"
            f"**Verdict**: CONFIRMED\n"
            f"**Root Cause**: thing\n"
            f"**Description**: a real finding with content\n"
            f"**Impact**: User loses funds (substantive)\n\n"
        )
    return head


def test_aprime1_inventory_split_classifies_siblings_as_benign():
    """v2.0.4 (A'1) / Codex 12: inventory_chunk_a's overrun into sibling
    chunks + downstream merge + invariants must be classified benign.
    """
    benign, blocking = _split_nonblocking_foreign_writes(
        "inventory_chunk_a",
        [
            "findings_inventory_chunk_b.md",
            "findings_inventory_chunk_c.md",
            "findings_inventory.md",
            "semantic_invariants.md",
        ],
    )
    assert blocking == []
    assert set(benign) == {
        "findings_inventory_chunk_b.md",
        "findings_inventory_chunk_c.md",
        "findings_inventory.md",
        "semantic_invariants.md",
    }


def test_aprime1_inventory_keeps_verify_blocking():
    """v2.0.4 (A'1): inventory benign-set MUST NOT swallow verify/report
    writes (those are real boundary breaches even from inventory).
    """
    benign, blocking = _split_nonblocking_foreign_writes(
        "inventory_chunk_a",
        ["findings_inventory_chunk_b.md", "verify_H-1.md", "AUDIT_REPORT.md"],
    )
    assert "findings_inventory_chunk_b.md" in benign
    assert set(blocking) == {"verify_H-1.md", "AUDIT_REPORT.md"}


def test_aprime2_is_valid_inventory_chunk_output_accepts_substantive(tmp_path):
    """v2.0.4 (A'2): the lightweight validator accepts a substantive
    chunk output (no side effects, no recursion into general validators).
    """
    p = tmp_path / "findings_inventory_chunk_b.md"
    p.write_text(_substantive_inventory_chunk("b"), encoding="utf-8")
    assert _is_valid_inventory_chunk_output(p)


def test_aprime2_is_valid_inventory_chunk_output_rejects_malformed(tmp_path):
    """v2.0.4 (A'2): missing CC heading, Impact, or Source IDs → reject.
    Tests the four-condition gate from the inventory prompt body.
    """
    p = tmp_path / "x.md"
    # Too small
    p.write_text("# Tiny\n")
    assert not _is_valid_inventory_chunk_output(p)
    # Has size but no CC heading
    p.write_text("# Big enough\n" + ("filler line\n" * 30))
    assert not _is_valid_inventory_chunk_output(p)
    # Has CC heading but no Impact
    p.write_text(
        "### Finding [CC-01]: x\n**Source IDs**: H-1\n**Severity**: High\n"
        + ("filler\n" * 50)
    )
    assert not _is_valid_inventory_chunk_output(p)
    # Has CC + Impact but no Source IDs
    p.write_text(
        "### Finding [CC-01]: x\n**Impact**: y\n"
        + ("filler\n" * 50)
    )
    assert not _is_valid_inventory_chunk_output(p)


def test_aprime2_chunk_a_writes_valid_sibling_b_adopted(tmp_path):
    """v2.0.4 (A'2): chunk_a wrote a valid chunk_b output → adoption
    succeeds → file stays in scratchpad root → provenance recorded.
    """
    (tmp_path / "findings_inventory_chunk_a.md").write_text(
        _substantive_inventory_chunk("a"), encoding="utf-8"
    )
    (tmp_path / "findings_inventory_chunk_b.md").write_text(
        _substantive_inventory_chunk("b"), encoding="utf-8"
    )
    ok = _try_adopt_inventory_sibling(
        tmp_path, str(tmp_path),
        "inventory_chunk_a", "findings_inventory_chunk_b.md"
    )
    assert ok
    # File stays in place (NOT quarantined)
    assert (tmp_path / "findings_inventory_chunk_b.md").exists()
    # Provenance recorded
    state = _json.loads((tmp_path / "_artifact_state.json").read_text())
    rec = state.get("artifacts", {}).get("findings_inventory_chunk_b.md", {})
    assert rec.get("adopted_from") == "inventory_chunk_a"
    assert rec.get("adoption_owning_phase") == "inventory_chunk_b"
    assert "adopted_at" in rec


def test_aprime2_chunk_a_writes_malformed_sibling_rejected(tmp_path):
    """v2.0.4 (A'2): adoption rejected if the validator fails. Caller
    will quarantine in the gate flow.
    """
    (tmp_path / "findings_inventory_chunk_b.md").write_text(
        "# Malformed B — no CC headings\n" + "filler\n" * 50,
        encoding="utf-8",
    )
    ok = _try_adopt_inventory_sibling(
        tmp_path, str(tmp_path),
        "inventory_chunk_a", "findings_inventory_chunk_b.md"
    )
    assert not ok
    # No provenance recorded
    state_file = tmp_path / "_artifact_state.json"
    if state_file.exists():
        state = _json.loads(state_file.read_text())
        assert "findings_inventory_chunk_b.md" not in state.get("artifacts", {})


def test_aprime2_own_output_not_adoptable(tmp_path):
    """v2.0.4 (A'2): the current phase's own expected output is NOT
    treated as a sibling — adoption returns False without touching state.
    """
    (tmp_path / "findings_inventory_chunk_a.md").write_text(
        _substantive_inventory_chunk("a"), encoding="utf-8"
    )
    ok = _try_adopt_inventory_sibling(
        tmp_path, str(tmp_path),
        "inventory_chunk_a", "findings_inventory_chunk_a.md"
    )
    assert not ok


def test_aprime2_downstream_not_adoptable_in_aprime(tmp_path):
    """v2.0.4 (A'2): downstream artifacts (findings_inventory.md,
    semantic_invariants.md) are CLASSIFIED benign in A'1 but are NOT
    adoptable in A' — they require the full inventory_merge / invariants
    phase validators which have side effects (Phase C's
    _run_phase_validators_readonly will enable that).

    A' adopts ONLY sibling chunk outputs.
    """
    (tmp_path / "findings_inventory.md").write_text(
        "# merged inventory\n" + "filler\n" * 50, encoding="utf-8"
    )
    ok = _try_adopt_inventory_sibling(
        tmp_path, str(tmp_path),
        "inventory_chunk_a", "findings_inventory.md"
    )
    assert not ok  # not a chunk file → name regex fails


# ---------------------------------------------------------------------------
# v2.0.5 / Phase B — JSONL introspection + WRITE-THEN-VERIFY sentinel
# ---------------------------------------------------------------------------


def test_b1_slugify_cwd_for_transcript():
    """v2.0.5 (B1): Claude Code transcript directory slug mirrors path
    separators, drive colons, AND spaces collapsing to dashes.
    """
    assert _slugify_cwd_for_transcript(
        r"D:\Programming\Web3\Contests\Sample Audit Project\sub"
    ) == "D--Programming-Web3-Contests-Sample-Audit-Project-sub"
    assert _slugify_cwd_for_transcript("/home/user/work") == "-home-user-work"
    # No spaces, no Windows drive
    assert _slugify_cwd_for_transcript("/usr/local") == "-usr-local"


def test_b1_find_transcript_jsonl_picks_most_recent(tmp_path, monkeypatch):
    """v2.0.5 (B1): _find_transcript_jsonl returns the most recent file
    by mtime so a just-finished subprocess's transcript wins over stale
    historical sessions.
    """
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    monkeypatch.setattr(Path, "home", lambda: fake_home)
    slug = _slugify_cwd_for_transcript(r"X:\fake\project")
    sd = fake_home / ".claude" / "projects" / slug
    sd.mkdir(parents=True)
    old = sd / "old.jsonl"
    new = sd / "new.jsonl"
    old.write_text("{}\n")
    new.write_text("{}\n")
    import os as _os, time as _time
    # Make `old` strictly older by setting its mtime to 1 day ago
    one_day = 24 * 3600
    _os.utime(old, (_time.time() - one_day, _time.time() - one_day))
    found = _find_transcript_jsonl(r"X:\fake\project")
    assert found is not None
    assert found.name == "new.jsonl"


def test_b1_scan_transcript_detects_background_pattern(tmp_path):
    """v2.0.5 (B1): scan accepts BOTH tool name spellings (Task | Agent)
    AND requires ≥2 background calls + end_turn before declaring the
    orphan pattern.
    """
    p = tmp_path / "session.jsonl"
    lines = []
    # 2 background Agent calls
    for sub in ("depth-state-trace", "depth-edge-case"):
        lines.append(_json.dumps({
            "type": "assistant",
            "message": {
                "stop_reason": "tool_use",
                "content": [{
                    "type": "tool_use",
                    "id": f"toolu_{sub}",
                    "name": "Agent",
                    "input": {
                        "subagent_type": sub,
                        "description": f"depth role {sub}",
                        "prompt": "do work",
                        "run_in_background": True,
                    },
                }],
            },
        }))
    # Final assistant message ends with end_turn (no collection)
    lines.append(_json.dumps({
        "type": "assistant",
        "message": {
            "stop_reason": "end_turn",
            "content": [{"type": "text", "text": "Wave 1 launched, waiting."}],
        },
    }))
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    ev = _scan_transcript_for_background_orphan(p)
    assert ev is not None
    assert ev["task_count_background"] == 2
    assert ev["turn_ended_at"] == "end_turn"
    assert "depth-state-trace" in ev["subagent_types"]


def test_b1_scan_transcript_requires_end_turn(tmp_path):
    """v2.0.5 (B1): if the last assistant message is NOT end_turn (e.g.
    crash / rate_limit / tool_use), the orphan pattern doesn't match.
    """
    p = tmp_path / "session.jsonl"
    lines = []
    for sub in ("depth-state-trace", "depth-edge-case"):
        lines.append(_json.dumps({
            "type": "assistant",
            "message": {
                "stop_reason": "tool_use",
                "content": [{
                    "type": "tool_use", "id": f"toolu_{sub}",
                    "name": "Agent",
                    "input": {"subagent_type": sub, "run_in_background": True,
                              "description": "x", "prompt": "y"},
                }],
            },
        }))
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    # No end_turn at all → no orphan match
    ev = _scan_transcript_for_background_orphan(p)
    assert ev is None


def test_b1_definitive_path_overrides_rc_nonzero(tmp_path, monkeypatch):
    """v2.0.5 (B1) / Codex Round-2 Claim 10: when transcript evidence is
    definitive (≥2 background + end_turn), the diagnostic is emitted
    regardless of rc. Otherwise a wrapper rc quirk could hide the cause.
    """
    # Build a fake home/projects with a transcript carrying the orphan signature
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    monkeypatch.setattr(Path, "home", lambda: fake_home)
    project_root = r"Y:\fake\proj"
    slug = _slugify_cwd_for_transcript(project_root)
    sd = fake_home / ".claude" / "projects" / slug
    sd.mkdir(parents=True)
    transcript = sd / "session.jsonl"
    lines = []
    for sub in ("depth-state-trace", "depth-edge-case", "depth-external"):
        lines.append(_json.dumps({
            "type": "assistant",
            "message": {
                "stop_reason": "tool_use",
                "content": [{
                    "type": "tool_use", "id": f"toolu_{sub}",
                    "name": "Agent",
                    "input": {"subagent_type": sub, "run_in_background": True,
                              "description": "x", "prompt": "y"},
                }],
            },
        }))
    lines.append(_json.dumps({
        "type": "assistant",
        "message": {"stop_reason": "end_turn",
                    "content": [{"type": "text", "text": "Waiting."}]},
    }))
    transcript.write_text("\n".join(lines) + "\n", encoding="utf-8")
    # Build a scratchpad with stubs
    scratchpad = tmp_path / "scratchpad"
    scratchpad.mkdir()
    for name in ("depth_state_trace_findings.md", "depth_edge_case_findings.md",
                 "depth_external_findings.md", "blind_spot_a_findings.md",
                 "validation_sweep_findings.md"):
        (scratchpad / name).write_text(f"# {name}\n", encoding="utf-8")
    (scratchpad / "depth_token_flow_findings.md").write_text(
        "## Finding [TF-1]\nReal\n" * 50, encoding="utf-8"
    )
    # rc=124 (timeout) — heuristic path would have rejected; definitive path accepts
    diag = detect_background_orphan(
        scratchpad / "_stdio.log", scratchpad, "depth", "thorough", "sc",
        rc=124, project_root=project_root,
    )
    assert diag is not None
    assert diag["evidence"] == "transcript_jsonl"
    assert diag["task_count_background"] == 3
    assert diag["rc"] == 124  # rc preserved in the diagnostic


def test_b2_render_reservation_header_carries_sentinel():
    """v2.0.5 (B2): the source-of-truth helper for reservation headers
    includes the PLAMEN-STUB sentinel comment.
    """
    h = _render_reservation_header("Depth State Trace Findings")
    assert "# Depth State Trace Findings" in h
    assert PLAMEN_STUB_SENTINEL in h
    # Two-line shape (header + sentinel)
    assert h.count("\n") >= 2


def test_b2_stub_sentinel_detected_by_substance_gate(tmp_path):
    """v2.0.5 (B2): a file with the PLAMEN-STUB sentinel is classified
    as a stub by `_depth_artifact_is_stub` regardless of size, since
    the sentinel is an explicit "header-only, content to follow" marker.
    """
    p = tmp_path / "depth_state_trace_findings.md"
    # Substantive size + content BUT sentinel present → still a stub
    p.write_text(
        "# Depth State Trace Findings\n"
        f"{PLAMEN_STUB_SENTINEL}\n"
        + "Some preamble that hasn't been replaced yet.\n" * 100,
        encoding="utf-8",
    )
    reason = _depth_artifact_is_stub(p)
    assert reason is not None
    assert "PLAMEN-STUB" in reason


def test_b2_legacy_files_without_sentinel_use_existing_heuristic(tmp_path):
    """v2.0.5 (B2): backward-compat — files written by pre-v2.0.5
    audits don't carry the sentinel. Substantive content without the
    sentinel must NOT be classified as a stub.
    """
    p = tmp_path / "depth_token_flow_findings.md"
    p.write_text(
        "## Finding [DT-1] Real bug\n**Severity**: High\n"
        "**Evidence**: [CODE-TRACE] external call before state write\n"
        "[BOUNDARY:amount=0] [TRACE:withdraw->revert]\n\n"
        "## Finding [DT-2] Another real bug\n**Severity**: Medium\n"
        + "Real analytical content here.\n" * 50,
        encoding="utf-8",
    )
    assert _depth_artifact_is_stub(p) is None


def test_a4_archive_orphan_stubs_moves_files_and_writes_manifest(tmp_path):
    """v2.0.3 (A4): orphan stubs are moved out of the scratchpad root into
    `_overflow/{phase}/orphan_stubs/{ts}/` so the retry attempt cannot
    re-read them as partial work. Manifest records detection metadata.
    """
    stub_names = [
        "depth_state_trace_findings.md",
        "depth_edge_case_findings.md",
    ]
    for name in stub_names:
        (tmp_path / name).write_text(f"# {name}\n", encoding="utf-8")
    diag = {
        "phase": "depth", "evidence": "heuristic", "rc": 0,
        "backend": "claude", "stub_files": stub_names,
        "stub_count": 2,
        "fingerprint": "header_only_files_with_clean_rc",
        "detected_at": "2026-05-20T17:13:00Z",
    }
    archive_dir = _archive_orphan_stubs(tmp_path, "depth", diag)
    assert archive_dir is not None
    # Stubs moved out of scratchpad root
    for name in stub_names:
        assert not (tmp_path / name).exists()
        assert (archive_dir / name).exists()
    # Manifest written
    manifest = (archive_dir / "manifest.txt").read_text(encoding="utf-8")
    assert "Orphan-background stub archive" in manifest
    assert "Detected at: 2026-05-20T17:13:00Z" in manifest
    for name in stub_names:
        assert name in manifest
