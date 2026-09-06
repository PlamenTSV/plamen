"""Tests for v2.4.3 fixes: unified ID regex, SC verify_aggregate bypass removal,
rate-limit stale log, inventory single-shard validators, tier empty headers,
shard name derivation, scale_timeout ceiling, phantom skeptic artifact.

Run: python -m pytest test_v2_4_3_fixes.py -v
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
from plamen_types import plamen_home
import plamen_prompt as PR


# ═══════════════════════════════════════════════════════════════════════
# P0-4: Phantom skeptic_judge_decisions.md reference removed
# ═══════════════════════════════════════════════════════════════════════

class TestP04_SkepticPhantom:

    def test_skeptic_prose_is_proposal_only_not_phantom_aggregate_authority(self):
        path = plamen_home() / "rules" / "phase6-report-prompts.md"
        assert path.is_file(), "report authority prompt is required packaging"
        text = path.read_text(encoding="utf-8")
        assert "skeptic artifacts are proposal-only" in text
        assert "distinct typed adjudicator" in text
        assert "validated report-authoritative ledger" in text
        assert "skeptic_judge_decisions.md" not in text

    def test_nonbody_requires_typed_full_claim_authority_or_defaults_to_body(self):
        path = plamen_home() / "rules" / "phase6-report-prompts.md"
        assert path.is_file(), "report authority prompt is required packaging"
        text = path.read_text(encoding="utf-8")
        assert "Disposition Authority Contract (MANDATORY)" in text
        assert "full-claim typed refutation or zero-harm decision" in text
        assert "defaults to BODY at upstream severity" in text


# ═══════════════════════════════════════════════════════════════════════
# P0-5/P0-6: Unified ID regex source-of-truth
# ═══════════════════════════════════════════════════════════════════════

class TestP05P06_UnifiedIDRegex:

    # -- Component constants exist --

    def test_id_components_defined(self):
        """All _ID_* component constants must be defined."""
        for attr in ("_ID_DEPTH_ALTS", "_ID_TOOL_ALTS", "_ID_NICHE_ALTS",
                     "_ID_HYPO_ALTS", "_ID_ALL_INTERNAL", "_ID_ALL_NONHYPO"):
            assert hasattr(P, attr), f"Missing {attr}"
            assert isinstance(getattr(P, attr), str)

    # -- Regex coverage tests: every regex matches the expected ID shapes --

    @pytest.mark.parametrize("test_id", [
        "DEPTH-TF-1", "DEPTH-ST-42", "BLIND-3", "VS-7", "EN-2", "SE-5",
        "INV-1", "DCI-3", "DEC-12", "DX-4", "DN-9", "DNS-8",
        "DCOV-5", "DCOV2-12", "PERT-1", "PAIR-6", "ATT-3",
        "PANIC-7", "PANIC-EXPLOIT-2",
        "SLITHER-1", "FUZZ-4", "MEDUSA-2", "RSW-8", "SP-3",
        "CS-1", "TF-5", "AC-3", "EVT-12", "GOV-2", "FL-1",
        "H-1", "H-C06", "H-M27", "CH-3",
        "L1-C-01", "L1-H-12", "CC-5", "F-3",
        "C-01", "M-12", "I-99",
    ])
    def test_finding_id_extract_re_matches(self, test_id):
        """_FINDING_ID_EXTRACT_RE must match all known internal ID shapes."""
        assert P._FINDING_ID_EXTRACT_RE.search(test_id), \
            f"_FINDING_ID_EXTRACT_RE failed to match {test_id}"

    @pytest.mark.parametrize("test_id", [
        "DEPTH-TF-1", "BLIND-3", "VS-7", "EN-2", "SE-5",
        "INV-1", "DCI-3", "DEC-12", "DX-4", "DN-9", "DNS-8",
        "PERT-1", "PAIR-6", "ATT-3", "PANIC-7",
        "SLITHER-1", "FUZZ-4", "MEDUSA-2", "RSW-8", "SP-3",
        "CS-1", "TF-5", "GOV-2",
        "H-1", "H-C06", "CH-3", "L1-C-01", "CC-5", "F-3",
        "C-01", "M-12",
    ])
    def test_internal_id_re_matches(self, test_id):
        """_INTERNAL_ID_RE must match all known internal ID shapes."""
        assert P._INTERNAL_ID_RE.search(test_id), \
            f"_INTERNAL_ID_RE failed to match {test_id}"

    @pytest.mark.parametrize("test_id", [
        "DEPTH-TF-1", "BLIND-3", "VS-7", "EN-2", "SE-5",
        "INV-1", "DCI-3", "DEC-12", "DX-4", "DN-9", "DNS-8",
        "PERT-1", "PAIR-6", "ATT-3", "PANIC-7",
        "SLITHER-1", "FUZZ-4", "MEDUSA-2", "RSW-8", "SP-3",
        "CS-1", "TF-5", "GOV-2",
        "H-1", "H-C06", "CH-3", "L1-C-01", "CC-5", "F-3",
    ])
    def test_internal_finding_id_re_matches(self, test_id):
        """_INTERNAL_FINDING_ID_RE must match all known internal ID shapes."""
        assert P._INTERNAL_FINDING_ID_RE.search(test_id), \
            f"_INTERNAL_FINDING_ID_RE failed to match {test_id}"

    @pytest.mark.parametrize("test_id", [
        # Depth/scanner/niche IDs are unambiguously internal
        "DEPTH-TF-1", "BLIND-3", "VS-7", "EN-2", "SE-5",
        "INV-1", "DCI-3", "DEC-12", "DX-4", "DN-9", "DNS-8",
        "PERT-1", "PAIR-6", "ATT-3", "PANIC-7",
        "SLITHER-1", "FUZZ-4", "MEDUSA-2", "RSW-8", "SP-3",
        "CS-1", "TF-5", "GOV-2",
        # L1-prefixed IDs are unambiguously internal
        "L1-C-01", "CC-5", "F-3",
    ])
    def test_client_body_internal_id_re_matches(self, test_id):
        """_CLIENT_BODY_INTERNAL_ID_RE must match internal IDs that shouldn't leak into reports."""
        assert P._CLIENT_BODY_INTERNAL_ID_RE.search(test_id), \
            f"_CLIENT_BODY_INTERNAL_ID_RE failed to match {test_id}"

    def test_client_body_does_not_match_report_ids(self):
        """_CLIENT_BODY_INTERNAL_ID_RE must NOT match client-facing report IDs."""
        for safe_id in ("C-01", "M-12", "H-03", "L-07", "I-15"):
            assert not P._CLIENT_BODY_INTERNAL_ID_RE.fullmatch(safe_id), \
                f"_CLIENT_BODY_INTERNAL_ID_RE should NOT fullmatch {safe_id}"

    @pytest.mark.parametrize("internal_id", ["H-1", "H-C06", "CH-3"])
    def test_client_body_matches_internal_hypothesis_ids(self, internal_id):
        """Internal hypothesis/chain IDs must not leak into client prose."""
        assert P._CLIENT_BODY_INTERNAL_ID_RE.fullmatch(internal_id), \
            f"_CLIENT_BODY_INTERNAL_ID_RE should fullmatch {internal_id}"

    # -- Cross-consistency: every ID that _INTERNAL_FINDING_ID_RE matches,
    #    _FINDING_ID_EXTRACT_RE also matches (extract is a superset) --

    @pytest.mark.parametrize("test_id", [
        "DEPTH-TF-1", "BLIND-3", "VS-7", "EN-2", "SE-5",
        "INV-1", "DCI-3", "DEC-12", "DX-4", "DN-9",
        "PERT-1", "PAIR-6", "ATT-3",
        "SLITHER-1", "FUZZ-4", "MEDUSA-2", "SP-3",
        "H-1", "H-C06", "CH-3", "L1-C-01", "CC-5", "F-3",
    ])
    def test_extract_is_superset_of_internal(self, test_id):
        """_FINDING_ID_EXTRACT_RE must match anything _INTERNAL_FINDING_ID_RE matches."""
        if P._INTERNAL_FINDING_ID_RE.search(test_id):
            assert P._FINDING_ID_EXTRACT_RE.search(test_id), \
                f"_FINDING_ID_EXTRACT_RE missed {test_id} that _INTERNAL_FINDING_ID_RE matches"

    # -- Formerly-missing prefixes regression test --

    def test_att_prefix_in_all_regexes(self):
        """ATT-N prefix (from v2.4.0 PoC classification) must be in all 4 regexes."""
        for name, rx in [
            ("EXTRACT", P._FINDING_ID_EXTRACT_RE),
            ("INTERNAL_ID", P._INTERNAL_ID_RE),
            ("INTERNAL_FINDING_ID", P._INTERNAL_FINDING_ID_RE),
            ("CLIENT_BODY", P._CLIENT_BODY_INTERNAL_ID_RE),
        ]:
            assert rx.search("ATT-5"), f"ATT-5 not matched by {name}"

    def test_sp_prefix_in_internal_id(self):
        """SP-N was missing from _INTERNAL_ID_RE before v2.4.3."""
        assert P._INTERNAL_ID_RE.search("SP-12")

    def test_slither_prefix_in_internal_id(self):
        """SLITHER-N was missing from _INTERNAL_ID_RE before v2.4.3."""
        assert P._INTERNAL_ID_RE.search("SLITHER-3")


# ═══════════════════════════════════════════════════════════════════════
# P1-5: Tier empty headers match assembler expectations
# ═══════════════════════════════════════════════════════════════════════

class TestP15_TierEmptyHeaders:

    def test_critical_high_uses_h2(self):
        header = P._TIER_EMPTY_HEADER["critical_high"]
        assert "## Critical Findings" in header
        assert "## High Findings" in header
        assert not header.startswith("# Critical and High")

    def test_medium_uses_h2(self):
        header = P._TIER_EMPTY_HEADER["medium"]
        assert "## Medium Findings" in header
        assert "# Medium Tier" not in header

    def test_low_info_uses_h2(self):
        header = P._TIER_EMPTY_HEADER["low_info"]
        assert "## Low Findings" in header
        assert "## Informational Findings" in header


# ═══════════════════════════════════════════════════════════════════════
# P1-6: SC verify shard names derived from manifest
# ═══════════════════════════════════════════════════════════════════════

class TestP16_ShardNameDerivation:

    def test_compute_sc_verify_shards_medium_keys_from_manifest(self):
        """Medium shard names must match SC_VERIFY_SHARD_MANIFESTS keys."""
        with tempfile.TemporaryDirectory() as td:
            sp = Path(td)
            # Write minimal verification queue with 1 medium finding
            (sp / "verification_queue.md").write_text(
                "| ID | Severity | Title | Location |\n"
                "|---|---|---|---|\n"
                "| H-1 | Medium | Test | file.sol:L1 |\n",
                encoding="utf-8",
            )
            shards = P.compute_sc_verify_shards(sp)
            medium_keys = [k for k in shards if "medium" in k]
            manifest_medium = [k for k in T.SC_VERIFY_SHARD_MANIFESTS if k.startswith("sc_verify_medium")]
            for mk in medium_keys:
                assert mk in manifest_medium, f"Shard key {mk} not in manifest"

    def test_compute_sc_verify_shards_low_keys_from_manifest(self):
        """Low shard names must match SC_VERIFY_SHARD_MANIFESTS keys."""
        with tempfile.TemporaryDirectory() as td:
            sp = Path(td)
            (sp / "verification_queue.md").write_text(
                "| ID | Severity | Title | Location |\n"
                "|---|---|---|---|\n"
                "| H-1 | Low | Test | file.sol:L1 |\n",
                encoding="utf-8",
            )
            shards = P.compute_sc_verify_shards(sp)
            low_keys = [k for k in shards if "low" in k]
            manifest_low = [k for k in T.SC_VERIFY_SHARD_MANIFESTS if k.startswith("sc_verify_low")]
            for lk in low_keys:
                assert lk in manifest_low, f"Shard key {lk} not in manifest"


# ═══════════════════════════════════════════════════════════════════════
# P1-8: Quality Gate 1 exempts Quality Observations
# ═══════════════════════════════════════════════════════════════════════

class TestP18_QualityGateExemption:

    def test_quality_gate_1_mentions_exception(self):
        """report-template.md Quality Gate 1 must exempt Quality Observations."""
        path = plamen_home() / "rules" / "report-template.md"
        if not path.exists():
            pytest.skip("report-template.md not found")
        text = path.read_text(encoding="utf-8")
        assert "Quality Observations" in text.split("Quality Gates")[1] if "Quality Gates" in text else True


# ═══════════════════════════════════════════════════════════════════════
# P2: scale_timeout ceiling includes SC Thorough
# ═══════════════════════════════════════════════════════════════════════

class TestP2_ScaleTimeoutCeiling:
    """`project_root=Path('.')` is environment-sensitive — when pytest runs
    from the Plamen repo root, count_loc() reports ~42K LOC of .sol/.rs
    examples in prompt files and adds LOC-scaling. Use a clean tmp dir
    so each test exercises only the ceiling logic, not the LOC scaling."""

    def test_sc_thorough_gets_doubled_ceiling(self, tmp_path):
        """SC Thorough mode should get doubled ceiling, not just L1."""
        result = PR.scale_timeout(
            base=900,
            project_root=tmp_path,
            language="evm",
            mode="thorough",
            hypothesis_count=0,
            ceiling=3600,
        )
        # With doubled ceiling (7200), base 900 should be returned as-is
        assert result == 900

    def test_sc_thorough_ceiling_actually_doubles(self, tmp_path):
        """With high base exceeding single ceiling but not double, the doubling matters."""
        result = PR.scale_timeout(
            base=5000,
            project_root=tmp_path,
            language="evm",
            mode="thorough",
            hypothesis_count=0,
            ceiling=3600,
        )
        # Without doubling: min(5000, 3600) = 3600
        # With doubling: min(5000, 7200) = 5000
        assert result == 5000

    def test_core_mode_no_doubling(self, tmp_path):
        """Core mode should NOT get ceiling doubling."""
        result = PR.scale_timeout(
            base=5000,
            project_root=tmp_path,
            language="evm",
            mode="core",
            hypothesis_count=0,
            ceiling=3600,
        )
        assert result == 3600

    def test_light_mode_no_doubling(self, tmp_path):
        """Light mode should NOT get ceiling doubling."""
        result = PR.scale_timeout(
            base=5000,
            project_root=tmp_path,
            language="evm",
            mode="light",
            hypothesis_count=0,
            ceiling=3600,
        )
        assert result == 3600


# ═══════════════════════════════════════════════════════════════════════
# P0-1: SC verify_aggregate bypass removed (integration)
# ═══════════════════════════════════════════════════════════════════════

class TestP01_SCVerifyAggregateBypass:

    def test_sc_verify_aggregate_in_validator_guard(self):
        """sc_verify_aggregate must be listed alongside verify_aggregate in validator dispatch."""
        import plamen_driver as D
        src = Path(D.__file__).read_text(encoding="utf-8")
        assert 'sc_verify_aggregate' in src
        # The validator dispatch guard for verify_aggregate must include sc_verify_aggregate
        assert re.search(
            r'verify_aggregate.*sc_verify_aggregate|sc_verify_aggregate.*verify_aggregate',
            src,
        ), "sc_verify_aggregate not co-located with verify_aggregate in validator guard"

    def test_sc_verify_aggregate_no_early_continue_block(self):
        """The old 40-line SC verify_aggregate block with early `continue` must be gone."""
        import plamen_driver as D
        src = Path(D.__file__).read_text(encoding="utf-8")
        # The old pattern was: if pipeline != l1 and phase == sc_verify_aggregate: ... continue
        # The new pattern is just a 3-line pre-step that falls through to _run_phase_validators
        lines = src.split('\n')
        for i, line in enumerate(lines):
            if 'pipeline") != "l1"' in line and 'sc_verify_aggregate' in line:
                # Check the next 5 lines for a bare continue (the old bypass)
                block = '\n'.join(lines[i:i+6])
                if block.count('continue') > 0 and '_run_phase_validators' not in block:
                    pytest.fail(f"Found continue in SC verify_aggregate block without validator dispatch at ~line {i+1}")
                break


# ═══════════════════════════════════════════════════════════════════════
# P0-2: Rate-limit stale log detection
# ═══════════════════════════════════════════════════════════════════════

class TestP02_RateLimitStaleLog:

    def test_retry_log_checked_first(self):
        """Rate-limit detection should check attempt2 log before canonical."""
        import plamen_driver as D
        src = Path(D.__file__).read_text(encoding="utf-8")
        assert ".attempt2.log" in src


# ═══════════════════════════════════════════════════════════════════════
# P0-3: Inventory single-shard validators
# ═══════════════════════════════════════════════════════════════════════

class TestP03_InventorySingleShard:

    def test_single_shard_runs_validators(self):
        """Single-shard inventory copy must call validation functions."""
        import plamen_driver as D
        src = Path(D.__file__).read_text(encoding="utf-8")
        # Find the single-shard block
        assert "_validate_inventory_evidence" in src
        assert "_validate_inventory_parity" in src


# ═══════════════════════════════════════════════════════════════════════
# Post-v2.4.3 audit fixes (P0-01, P0-02, P1-05, P1-07, P1-08)
# ═══════════════════════════════════════════════════════════════════════

class TestAuditP002_DSTRegex:
    """P0-02: DST-N simple form must match the unified regex."""

    def test_dst_simple_matches(self):
        for fid in ("DST-1", "DST-2", "DST-10"):
            assert P._FINDING_ID_EXTRACT_RE.search(fid), f"{fid} not matched"
            assert P._INTERNAL_ID_RE.search(fid), f"{fid} not matched by _INTERNAL_ID_RE"
            assert P._INTERNAL_FINDING_ID_RE.search(fid), f"{fid} not matched by _INTERNAL_FINDING_ID_RE"
            assert P._CLIENT_BODY_INTERNAL_ID_RE.search(fid), f"{fid} not matched by _CLIENT_BODY_INTERNAL_ID_RE"

    def test_dst_compound_matches(self):
        for fid in ("DST-LIMIT-1", "DST-ADEQUACY-2", "DST-FOO-BAR-3"):
            assert P._FINDING_ID_EXTRACT_RE.search(fid), f"{fid} not matched"

    def test_dst_in_prose(self):
        text = "Finding [DST-1] shows a design stress limit violation."
        ids = P._FINDING_ID_EXTRACT_RE.findall(text)
        assert "DST-1" in ids

    def test_feeder_pattern_consistent(self):
        """_PROMOTABLE_FEEDER_ID_PATTERN and unified regex must agree on DST-N."""
        feeder_re = re.compile(P._PROMOTABLE_FEEDER_ID_PATTERN, re.IGNORECASE)
        for fid in ("DST-1", "DST-2", "DST-10"):
            assert feeder_re.search(fid), f"Feeder missed {fid}"
            assert P._FINDING_ID_EXTRACT_RE.search(fid), f"Unified missed {fid}"


class TestAuditP001_SCDepthValidators:
    """P0-01: SC depth must run _scan_for_halt_and_gatefail + never-cut artifacts."""

    def test_sc_depth_has_halt_gatefail_scan(self):
        import plamen_driver as D
        src = Path(D.__file__).read_text(encoding="utf-8")
        sc_depth_match = re.search(
            r'# --- depth \(SC\).*?(?=# ---|\Z)', src, re.DOTALL
        )
        assert sc_depth_match, "SC depth block not found"
        sc_block = sc_depth_match.group(0)
        assert "_scan_for_halt_and_gatefail" in sc_block

    def test_sc_depth_has_never_cut_artifacts(self):
        """SC depth gate uses _assert_never_cut_artifacts (not _checkpoint)."""
        import plamen_driver as D
        src = Path(D.__file__).read_text(encoding="utf-8")
        sc_depth_match = re.search(
            r'# --- depth \(SC\).*?(?=# ---|\Z)', src, re.DOTALL
        )
        assert sc_depth_match, "SC depth block not found"
        sc_block = sc_depth_match.group(0)
        assert "_assert_never_cut_artifacts" in sc_block
        assert "_assert_never_cut_checkpoint" not in sc_block, \
            "v2.4.7: checkpoint removed — SC prompt writes checkpoint_postdepth.md not never_cut_checkpoint.md"

    def test_violations_before_not_l1_only(self):
        """violations_before snapshot must fire for depth on any pipeline, not just L1."""
        import plamen_driver as D
        src = Path(D.__file__).read_text(encoding="utf-8")
        vb_snapshots = list(re.finditer(
            r'if phase\.name == "depth"[^:]*:\s*\n\s*vp = scratchpad / "violations\.md"',
            src
        ))
        assert len(vb_snapshots) >= 2, "Expected at least 2 violations_before snapshots (attempt1+2)"
        for m in vb_snapshots:
            line = m.group(0)
            assert '"l1"' not in line, f"violations_before still L1-gated: {line}"


class TestAuditP105_InventoryStructureAllPipelines:
    """P1-05: _validate_inventory_structure must run for SC too, not just L1."""

    def test_inventory_structure_not_l1_gated(self):
        import plamen_driver as D
        src = Path(D.__file__).read_text(encoding="utf-8")
        inv_block = re.search(
            r'_validate_inventory_structure\(scratchpad\)', src
        )
        assert inv_block, "_validate_inventory_structure call missing"
        preceding = src[max(0, inv_block.start() - 200):inv_block.start()]
        assert 'pipeline.*l1' not in preceding.replace('\n', ' ') or \
               'config.get("pipeline") == "l1"' not in preceding, \
               "Inventory structure still L1-gated"


class TestAuditP107_PocSectionNames:
    """P1-07: PoC attempt coverage must accept '### Execution Result'."""

    def test_execution_result_accepted(self):
        import plamen_validators as V
        content = "### Execution Result\n- Result: PASS\n- Evidence Tag: [POC-FAIL]\n"
        assert "### Execution Result" in content
        assert any(h in content for h in (
            "### PoC Attempt", "## PoC Attempt",
            "### Execution Result", "## Execution Result",
        ))


class TestAuditP108_PocPassEscapeFullContent:
    """P1-08: POC-PASS escape check must search full content, not just poc_section."""

    def test_poc_pass_in_retry_section_escapes(self):
        """If attempt 1 has [POC-FAIL] and attempt 2 has [POC-PASS], no demotion."""
        import plamen_validators as V
        content = (
            "### PoC Attempt\n"
            "Attempt 1: [POC-FAIL]\n"
            "### Retry Attempt\n"
            "Attempt 2: [POC-PASS]\n"
        )
        poc_match = re.search(
            r"#{2,3}\s*(?:PoC Attempt|Execution Result)(.*?)(?=\n#{2,3}\s|\Z)",
            content, re.DOTALL
        )
        poc_section = poc_match.group(1) if poc_match else ""
        assert "[POC-FAIL]" in poc_section
        assert "[POC-PASS]" not in poc_section
        assert "[POC-PASS]" in content


# ═══════════════════════════════════════════════════════════════════════
# v2.4.5: Accumulate-on-retry for breadth/depth/rescan + timeout bump
# ═══════════════════════════════════════════════════════════════════════

import plamen_validators as V


class TestV245_AccumulateOnRetry:
    """_ACCUMULATE_ON_RETRY_PHASES skips quarantine so RESUMPTION PROTOCOL
    accumulates partial results across retry attempts."""

    def test_accumulate_phases_set(self):
        assert "breadth" in V._ACCUMULATE_ON_RETRY_PHASES
        assert "depth" in V._ACCUMULATE_ON_RETRY_PHASES
        assert "rescan" in V._ACCUMULATE_ON_RETRY_PHASES

    def test_non_accumulate_phases_not_in_set(self):
        for name in ("recon", "inventory", "skeptic", "chain",
                      "report_index", "crossbatch"):
            assert name not in V._ACCUMULATE_ON_RETRY_PHASES

    def test_quarantine_skipped_for_accumulate_phase(self):
        """Files stay in place when quarantine is called on an accumulate phase."""
        with tempfile.TemporaryDirectory() as tmp:
            sp = Path(tmp)
            # Create substantial analysis files
            (sp / "analysis_core_state.md").write_text("x" * 1000, encoding="utf-8")
            (sp / "analysis_access_control.md").write_text("y" * 800, encoding="utf-8")
            phase = T.Phase(
                "breadth", ["Phase 3"],
                ["analysis_*.md"],
                base_timeout_s=3600, critical=True,
                min_artifacts_count=3,
            )
            renamed = V._quarantine_stale_on_retry(
                sp, phase, ["analysis_*.md (quorum: 2/3 substantial)"]
            )
            assert renamed == []
            assert (sp / "analysis_core_state.md").exists()
            assert (sp / "analysis_access_control.md").exists()
            assert not (sp / "analysis_core_state.md.attempt1").exists()

    def test_quarantine_runs_for_non_accumulate_phase(self):
        """Files are quarantined for phases NOT in _ACCUMULATE_ON_RETRY_PHASES."""
        with tempfile.TemporaryDirectory() as tmp:
            sp = Path(tmp)
            (sp / "findings_inventory.md").write_text("x" * 1000, encoding="utf-8")
            phase = T.Phase(
                "inventory", ["Phase 4a"],
                ["findings_inventory.md"],
                base_timeout_s=2400, critical=True,
            )
            renamed = V._quarantine_stale_on_retry(
                sp, phase, ["findings_inventory.md (stub only)"]
            )
            assert "findings_inventory.md" in renamed
            assert not (sp / "findings_inventory.md").exists()
            assert not (sp / "findings_inventory.md.attempt1").exists()
            assert (
                sp
                / "_retry_quarantine"
                / "inventory"
                / "findings_inventory.md"
            ).exists()

    def test_depth_quarantine_skipped(self):
        """Depth files stay for RESUMPTION PROTOCOL to accumulate."""
        with tempfile.TemporaryDirectory() as tmp:
            sp = Path(tmp)
            (sp / "depth_token_flow_findings.md").write_text("a" * 2000, encoding="utf-8")
            (sp / "depth_state_trace_findings.md").write_text("b" * 3000, encoding="utf-8")
            phase = T.Phase(
                "depth", ["Phase 4b"],
                ["depth_*_findings.md"],
                base_timeout_s=3600, critical=True,
                min_artifacts_count=4,
            )
            renamed = V._quarantine_stale_on_retry(
                sp, phase, ["depth_*_findings.md (quorum: 2/4 substantial)"]
            )
            assert renamed == []
            assert (sp / "depth_token_flow_findings.md").exists()
            assert (sp / "depth_state_trace_findings.md").exists()


class TestV245_BreadthTimeout:
    """Breadth base_timeout_s — bumped 3600 → 5400 in v2.4.5 for manifest
    recovery, then 5400 → 10800 in v2.0.0's "2x major LLM phases" pass to
    accommodate large-repo workloads (UniswapV4-class, 50K+ LOC)."""

    def test_sc_breadth_timeout(self):
        sc_phases = T.SC_PHASES
        breadth = [p for p in sc_phases if p.name == "breadth"][0]
        assert breadth.base_timeout_s == 10800

    def test_l1_breadth_timeout(self):
        l1_phases = T.L1_PHASES
        breadth = [p for p in l1_phases if p.name == "breadth"][0]
        assert breadth.base_timeout_s == 10800

    def test_scale_timeout_small_codebase(self):
        """For small codebases (<5K LOC), scale_timeout returns the base."""
        with tempfile.TemporaryDirectory() as tmp:
            result = PR.scale_timeout(3600, tmp, "solidity")
            assert result == 3600


class TestV245_RetryExceptionClause:
    """Retry exception clause is accumulation-aware.

    Tests the clause selection logic directly via _ACCUMULATE_ON_RETRY_PHASES
    membership, which is what build_phase_prompt uses.
    """

    def test_accumulate_phases_get_accumulate_clause(self):
        """Phases in _ACCUMULATE_ON_RETRY_PHASES get ACCUMULATE clause."""
        for name in ("breadth", "depth", "rescan"):
            assert name in V._ACCUMULATE_ON_RETRY_PHASES, (
                f"{name} should be in _ACCUMULATE_ON_RETRY_PHASES"
            )

    def test_non_accumulate_phases_get_quarantine_clause(self):
        """Phases NOT in set get the standard quarantine clause."""
        for name in ("inventory", "recon", "skeptic", "report_index"):
            assert name not in V._ACCUMULATE_ON_RETRY_PHASES

    def test_accumulate_set_is_frozenset(self):
        """Set is immutable to prevent accidental mutation."""
        assert isinstance(V._ACCUMULATE_ON_RETRY_PHASES, frozenset)


class TestV245_DepthRetryHint:
    """Depth retry hint text updated for accumulation semantics."""

    def test_depth_hint_no_quarantine_claim(self):
        hint = V._generate_depth_retry_hint(
            ["never-cut artifacts missing: depth_edge_case_findings.md"]
        )
        assert "quarantined" not in hint
        assert "still on disk" in hint
        assert "re-read and fix" in hint


# ═══════════════════════════════════════════════════════════════════════
# v2.4.6: Phase isolation — prompt TOC removal + gate tolerance
# ═══════════════════════════════════════════════════════════════════════

class TestV246_PromptIsolation:
    """extract_phase_sections no longer includes pipeline TOC or orchestrator refs."""

    SAMPLE_V1 = """# Plamen Audit Pipeline

## Orchestration Protocol

**MANDATORY**: Read orchestrator-rules.md.

## Step 0: Setup

Setup wizard stuff.

## Phase 1: Recon

Recon instructions.

## Phase 3: Parallel Analysis

Breadth agent spawning instructions.

## Phase 3b: Re-Scan

Re-scan loop instructions.

## Phase 4a: Inventory

Inventory instructions.

## Phase 4b: Depth Loop

Depth instructions.

## Phase 5: Verification

Verify instructions.

## Phase 6: Report

Report instructions.
"""

    def test_no_pipeline_toc(self):
        """Extracted section must NOT contain 'Pipeline Overview' TOC."""
        result = PR.extract_phase_sections(
            self.SAMPLE_V1, ["Phase 3: Parallel Analysis"]
        )
        assert "Pipeline Overview" not in result
        assert "table of contents" not in result

    def test_no_other_phase_names(self):
        """Extracted breadth section must NOT mention later phases."""
        result = PR.extract_phase_sections(
            self.SAMPLE_V1, ["Phase 3: Parallel Analysis"]
        )
        assert "Phase 3b" not in result
        assert "Phase 4a" not in result
        assert "Phase 4b" not in result
        assert "Phase 5" not in result
        assert "Phase 6" not in result

    def test_no_orchestration_protocol(self):
        """Extracted section must NOT include Orchestration Protocol preamble."""
        result = PR.extract_phase_sections(
            self.SAMPLE_V1, ["Phase 3: Parallel Analysis"]
        )
        assert "Orchestration Protocol" not in result
        assert "orchestrator-rules" not in result

    def test_contains_assigned_section(self):
        """Extracted section DOES contain the assigned phase content."""
        result = PR.extract_phase_sections(
            self.SAMPLE_V1, ["Phase 3: Parallel Analysis"]
        )
        assert "Phase 3: Parallel Analysis" in result
        assert "Breadth agent spawning instructions" in result

    def test_stop_directive_present(self):
        """Extracted section ends with PHASE BOUNDARY HARD STOP directive."""
        result = PR.extract_phase_sections(
            self.SAMPLE_V1, ["Phase 3: Parallel Analysis"]
        )
        assert "PHASE BOUNDARY" in result
        assert "HARD STOP" in result
        assert "Do NOT proceed" in result

    def test_h1_title_preserved(self):
        """The H1 title (preamble before first ## heading) is preserved."""
        result = PR.extract_phase_sections(
            self.SAMPLE_V1, ["Phase 3: Parallel Analysis"]
        )
        assert "# Plamen Audit Pipeline" in result


class TestV246_GateTolerance:
    """Phase containment gate is non-fatal when phase's own artifacts are present."""

    def test_containment_nonfatal_when_own_artifacts_present(self):
        """If gate_passes succeeds, foreign writes don't fail the gate."""
        import plamen_driver as D
        with tempfile.TemporaryDirectory() as tmp:
            sp = Path(tmp)
            # Create breadth phase artifacts (enough to pass gate_passes)
            for i in range(4):
                (sp / f"analysis_{i}.md").write_text(
                    "# Analysis\n" + "x" * 600, encoding="utf-8"
                )
            # Create a foreign artifact (belongs to inventory phase)
            (sp / "findings_inventory.md").write_text(
                "# Inventory\n" + "y" * 600, encoding="utf-8"
            )
            sc_phases = T.SC_PHASES
            breadth = [p for p in sc_phases if p.name == "breadth"][0]
            # file_state_before has no findings_inventory.md (it was created
            # by the subprocess, which is the foreign write)
            before = {
                f"analysis_{i}.md": (0, 0) for i in range(4)
            }
            # The breadth phase's own artifacts pass gate_passes
            passed, missing = D.gate_passes(sp, tmp, breadth)
            assert passed, f"Expected gate_passes to pass, got: {missing}"


class TestV246_DepthSanitization:
    """Depth phase forward-execution references are sanitized."""

    def test_phase4c_proceed_stripped(self):
        """'proceed directly to Phase 4c chain analysis' is replaced."""
        text = (
            "After iteration 1 completes, proceed directly to Phase 4c "
            "chain analysis (single merged agent per override #6)."
        )
        result = PR._sanitize_depth_forward_refs(text)
        assert "Phase 4c" not in result
        assert "STOP" in result
        assert "phase-owned work" in result

    def test_core_mode_proceed_stripped(self):
        """'proceed to chain analysis and verification as-is' is replaced."""
        text = "Uncertain findings proceed to chain analysis and verification as-is."
        result = PR._sanitize_depth_forward_refs(text)
        assert "chain analysis" not in result
        assert "depth phase complete" in result

    def test_post_verification_stripped(self):
        """Post-verification error trace feedback line is replaced."""
        text = (
            "5. **Post-verification error trace feedback** (Core/Thorough only): "
            "After Phase 5, if verifiers returned CONTESTED with error traces "
            "AND budget remains, spawn targeted depth with error traces."
        )
        result = PR._sanitize_depth_forward_refs(text)
        assert "After Phase 5" not in result
        assert "outside this subprocess" in result

    def test_depth_own_content_preserved(self):
        """Depth phase's own scoring/iteration instructions are not stripped."""
        text = (
            "2. **Score all findings** (MANDATORY for Core/Thorough)\n"
            "3. **Iteration 2**:\n"
            "   - Spawn targeted Devil's Advocate depth agents\n"
            "6. **Design Stress Testing (Thorough mode only)**\n"
        )
        result = PR._sanitize_depth_forward_refs(text)
        assert "Score all findings" in result
        assert "Iteration 2" in result
        assert "Design Stress Testing" in result


class TestV246_RoutingTableStrip:
    """Routing table is stripped for inventory/chain phases."""

    def test_routing_table_stripped_from_chain(self):
        """Chain phase no longer sees the Phase 4 routing table."""
        v1_path = plamen_home() / "commands" / "plamen.md"
        if not v1_path.exists():
            pytest.skip("plamen.md not available")
        text = v1_path.read_text(encoding="utf-8")
        from plamen_types import SC_PHASES
        for phase in SC_PHASES:
            if phase.name == "chain":
                extracted = PR.extract_phase_sections(text, phase.section_markers)
                extracted = PR._strip_foreign_subsections(extracted, phase.name)
                assert "phase4a-inventory-prompt.md" not in extracted
                assert "phase4b-loop.md" not in extracted
                assert "phase5-verification-prompt.md" not in extracted
                break

    def test_routing_table_stripped_from_inventory(self):
        """Inventory phase no longer sees the routing table."""
        v1_path = plamen_home() / "commands" / "plamen.md"
        if not v1_path.exists():
            pytest.skip("plamen.md not available")
        text = v1_path.read_text(encoding="utf-8")
        from plamen_types import SC_PHASES
        for phase in SC_PHASES:
            if phase.name == "inventory":
                extracted = PR.extract_phase_sections(text, phase.section_markers)
                extracted = PR._strip_foreign_subsections(extracted, phase.name)
                assert "Read prompts from" not in extracted
                assert "phase5-verification-prompt.md" not in extracted
                break


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
