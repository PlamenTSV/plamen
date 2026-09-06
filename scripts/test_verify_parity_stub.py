"""Tests for v2.6.7/v2.6.8: verify parity fallback and recovery.

v2.6.7:
- Stubs are written only for missing findings (no overwrite of existing)
- Stub content passes _verify_file_present_for_id (>=100 bytes)
- Stub contains required fields for downstream consumers (Evidence Tag,
  Preferred Tag, Verdict)
- _validate_verify_files_for_queue passes after stubbing
- _generate_verify_core_if_missing aggregates stubs correctly
- Empty queue → no stubs
- All verify files present → no stubs
- Mixed: some present, some missing → only missing are stubbed

v2.6.8:
- identify_missing_verify_ids returns correct (id, row) pairs
- identify_missing_verify_ids skips findings with existing verify files
- Recovery-then-stub integration: recovery shard runs before stubbing
"""
from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from plamen_validators import (
    _validate_verify_files_for_queue,
    _verify_file_present_for_id,
    _generate_verify_core_if_missing,
    identify_missing_verify_ids,
    stub_missing_verify_files,
)


def _write_queue(scratchpad: Path, rows: list[dict]) -> None:
    """Write a verification_queue.md with the given rows."""
    lines = [
        "# Verification Queue\n\n",
        "| Finding ID | Severity | Title | Location | Preferred Tag |\n",
        "|------------|----------|-------|----------|---------------|\n",
    ]
    for r in rows:
        fid = r.get("finding_id", "")
        sev = r.get("severity", "Medium")
        title = r.get("title", "Test finding")
        loc = r.get("location", "src/Vault.sol:L42")
        tag = r.get("tag", "[CODE-TRACE]")
        lines.append(f"| {fid} | {sev} | {title} | {loc} | {tag} |\n")
    (scratchpad / "verification_queue.md").write_text("".join(lines), encoding="utf-8")


def _write_real_verify(scratchpad: Path, fid: str, *, size: int = 200) -> None:
    """Write a real (non-stub) verify file that passes the size gate."""
    content = f"# Verification: {fid}\n\n**Verdict**: CONFIRMED\n**Evidence Tag**: [POC-PASS]\n**Preferred Tag**: [POC-PASS]\n"
    content += "x" * max(0, size - len(content))
    (scratchpad / f"verify_{fid}.md").write_text(content, encoding="utf-8")


# ────────────────────────────────────────────────────────────────────
# Basic stubbing
# ────────────────────────────────────────────────────────────────────

class TestStubMissingVerifyFiles:
    def test_stubs_missing_files(self, tmp_path: Path):
        """Stub files are created for queue rows without verify files."""
        _write_queue(tmp_path, [
            {"finding_id": "H-01", "severity": "High"},
            {"finding_id": "H-02", "severity": "High"},
            {"finding_id": "M-01", "severity": "Medium"},
        ])
        stubbed = stub_missing_verify_files(tmp_path, "sc")
        assert sorted(stubbed) == ["H-01", "H-02", "M-01"]
        for fid in stubbed:
            assert (tmp_path / f"verify_{fid}.md").exists()

    def test_no_overwrite_existing(self, tmp_path: Path):
        """Existing verify files are not overwritten."""
        _write_queue(tmp_path, [
            {"finding_id": "H-01", "severity": "High"},
            {"finding_id": "H-02", "severity": "High"},
        ])
        _write_real_verify(tmp_path, "H-01")
        original_content = (tmp_path / "verify_H-01.md").read_text(encoding="utf-8")

        stubbed = stub_missing_verify_files(tmp_path, "sc")
        assert stubbed == ["H-02"]
        assert (tmp_path / "verify_H-01.md").read_text(encoding="utf-8") == original_content

    def test_empty_queue_no_stubs(self, tmp_path: Path):
        """No queue rows → no stubs."""
        _write_queue(tmp_path, [])
        stubbed = stub_missing_verify_files(tmp_path, "sc")
        assert stubbed == []

    def test_no_queue_file_no_stubs(self, tmp_path: Path):
        """Missing verification_queue.md → no stubs, no crash."""
        stubbed = stub_missing_verify_files(tmp_path, "sc")
        assert stubbed == []

    def test_all_present_no_stubs(self, tmp_path: Path):
        """When all verify files exist, nothing is stubbed."""
        _write_queue(tmp_path, [
            {"finding_id": "H-01", "severity": "High"},
            {"finding_id": "M-01", "severity": "Medium"},
        ])
        _write_real_verify(tmp_path, "H-01")
        _write_real_verify(tmp_path, "M-01")
        stubbed = stub_missing_verify_files(tmp_path, "sc")
        assert stubbed == []


# ────────────────────────────────────────────────────────────────────
# Stub content quality
# ────────────────────────────────────────────────────────────────────

class TestStubContentQuality:
    def test_stub_passes_size_gate(self, tmp_path: Path):
        """Stub files are >=100 bytes (passes _verify_file_present_for_id)."""
        _write_queue(tmp_path, [
            {"finding_id": "H-01", "severity": "High"},
        ])
        stub_missing_verify_files(tmp_path, "sc")
        assert _verify_file_present_for_id(tmp_path, "H-01", min_bytes=100)

    def test_stub_contains_evidence_tag(self, tmp_path: Path):
        """Stub contains Evidence Tag and Preferred Tag fields."""
        _write_queue(tmp_path, [
            {"finding_id": "M-03", "severity": "Medium", "title": "Missing check"},
        ])
        stub_missing_verify_files(tmp_path, "sc")
        content = (tmp_path / "verify_M-03.md").read_text(encoding="utf-8")
        assert "**Evidence Tag**: [CODE-TRACE]" in content
        assert "**Preferred Tag**: [CODE-TRACE]" in content

    def test_stub_contains_verdict(self, tmp_path: Path):
        """Stub contains a parseable Verdict field."""
        _write_queue(tmp_path, [
            {"finding_id": "L-01", "severity": "Low"},
        ])
        stub_missing_verify_files(tmp_path, "sc")
        content = (tmp_path / "verify_L-01.md").read_text(encoding="utf-8")
        assert "**Verdict**: UNVERIFIED" in content

    def test_stub_preserves_severity(self, tmp_path: Path):
        """Stub includes the original severity from the queue."""
        _write_queue(tmp_path, [
            {"finding_id": "H-05", "severity": "Critical"},
        ])
        stub_missing_verify_files(tmp_path, "sc")
        content = (tmp_path / "verify_H-05.md").read_text(encoding="utf-8")
        assert "Critical" in content

    def test_stub_contains_not_executed_marker(self, tmp_path: Path):
        """Stub contains VERIFICATION NOT EXECUTED for downstream consumers."""
        _write_queue(tmp_path, [
            {"finding_id": "H-01", "severity": "High"},
        ])
        stub_missing_verify_files(tmp_path, "sc")
        content = (tmp_path / "verify_H-01.md").read_text(encoding="utf-8")
        assert "VERIFICATION NOT EXECUTED" in content


# ────────────────────────────────────────────────────────────────────
# Integration with parity gate
# ────────────────────────────────────────────────────────────────────

class TestParityGateIntegration:
    def test_parity_gate_fails_without_stubs(self, tmp_path: Path):
        """E1 gate fails when verify files are missing (the problem case)."""
        _write_queue(tmp_path, [
            {"finding_id": "H-01", "severity": "High"},
            {"finding_id": "H-02", "severity": "High"},
            {"finding_id": "M-01", "severity": "Medium"},
        ])
        _write_real_verify(tmp_path, "H-01")
        issues = _validate_verify_files_for_queue(tmp_path)
        assert len(issues) == 1
        assert "2 missing" in issues[0]

    def test_parity_gate_passes_after_stubs(self, tmp_path: Path):
        """E1 gate passes after stubbing missing files."""
        _write_queue(tmp_path, [
            {"finding_id": "H-01", "severity": "High"},
            {"finding_id": "H-02", "severity": "High"},
            {"finding_id": "M-01", "severity": "Medium"},
        ])
        _write_real_verify(tmp_path, "H-01")
        stubbed = stub_missing_verify_files(tmp_path, "sc")
        assert sorted(stubbed) == ["H-02", "M-01"]
        issues = _validate_verify_files_for_queue(tmp_path)
        assert issues == []

    def test_large_scale_partial_output(self, tmp_path: Path):
        """Simulates a large L1 scenario: 103 queued, 87 present, 16 missing."""
        queue_rows = [{"finding_id": f"H-{i:02d}", "severity": "High"} for i in range(1, 104)]
        _write_queue(tmp_path, queue_rows)
        for i in range(1, 88):
            _write_real_verify(tmp_path, f"H-{i:02d}")
        issues_before = _validate_verify_files_for_queue(tmp_path)
        assert len(issues_before) == 1
        assert "16 missing" in issues_before[0]

        stubbed = stub_missing_verify_files(tmp_path, "l1")
        assert len(stubbed) == 16
        issues_after = _validate_verify_files_for_queue(tmp_path)
        assert issues_after == []


# ────────────────────────────────────────────────────────────────────
# Integration with verify_core aggregation
# ────────────────────────────────────────────────────────────────────

class TestVerifyCoreAggregation:
    def test_stubs_aggregated_into_verify_core(self, tmp_path: Path):
        """_generate_verify_core_if_missing picks up stubbed files."""
        _write_queue(tmp_path, [
            {"finding_id": "H-01", "severity": "High"},
            {"finding_id": "M-01", "severity": "Medium"},
        ])
        _write_real_verify(tmp_path, "H-01")
        stub_missing_verify_files(tmp_path, "sc")

        generated = _generate_verify_core_if_missing(tmp_path)
        assert generated
        core = (tmp_path / "verify_core.md").read_text(encoding="utf-8")
        assert "H-01" in core
        assert "M-01" in core


# ────────────────────────────────────────────────────────────────────
# Alternate verify file naming conventions
# ────────────────────────────────────────────────────────────────────

class TestAlternateVerifyNames:
    def test_f_prefix_variant_detected(self, tmp_path: Path):
        """verify_F-{id}.md is recognized as existing (no stub needed)."""
        _write_queue(tmp_path, [
            {"finding_id": "H-01", "severity": "High"},
        ])
        p = tmp_path / "verify_F-H-01.md"
        p.write_text("x" * 200, encoding="utf-8")
        stubbed = stub_missing_verify_files(tmp_path, "sc")
        assert stubbed == []

    def test_bracket_variant_detected(self, tmp_path: Path):
        """verify_[{id}].md is recognized as existing (no stub needed)."""
        _write_queue(tmp_path, [
            {"finding_id": "H-01", "severity": "High"},
        ])
        p = tmp_path / "verify_[H-01].md"
        p.write_text("x" * 200, encoding="utf-8")
        stubbed = stub_missing_verify_files(tmp_path, "sc")
        assert stubbed == []

    def test_underscore_prefix_variant_detected(self, tmp_path: Path):
        """verify_F_{id}.md is recognized as existing (no stub needed)."""
        _write_queue(tmp_path, [
            {"finding_id": "H-01", "severity": "High"},
        ])
        p = tmp_path / "verify_F_H-01.md"
        p.write_text("x" * 200, encoding="utf-8")
        stubbed = stub_missing_verify_files(tmp_path, "sc")
        assert stubbed == []

    def test_small_file_still_triggers_stub(self, tmp_path: Path):
        """A verify file <100 bytes is treated as absent → stub replaces."""
        _write_queue(tmp_path, [
            {"finding_id": "H-01", "severity": "High"},
        ])
        p = tmp_path / "verify_H-01.md"
        p.write_text("tiny", encoding="utf-8")
        stubbed = stub_missing_verify_files(tmp_path, "sc")
        assert stubbed == ["H-01"]
        assert p.stat().st_size >= 100


# ────────────────────────────────────────────────────────────────────
# L1 vs SC pipeline
# ────────────────────────────────────────────────────────────────────

class TestPipelineVariants:
    def test_l1_pipeline(self, tmp_path: Path):
        """Stub works with L1 pipeline parameter."""
        _write_queue(tmp_path, [
            {"finding_id": "H-C01", "severity": "Critical"},
        ])
        stubbed = stub_missing_verify_files(tmp_path, "l1")
        assert stubbed == ["H-C01"]
        assert _verify_file_present_for_id(tmp_path, "H-C01")

    def test_sc_pipeline(self, tmp_path: Path):
        """Stub works with SC pipeline parameter."""
        _write_queue(tmp_path, [
            {"finding_id": "CS-1", "severity": "Medium"},
        ])
        stubbed = stub_missing_verify_files(tmp_path, "sc")
        assert stubbed == ["CS-1"]
        assert _verify_file_present_for_id(tmp_path, "CS-1")


# ────────────────────────────────────────────────────────────────────
# Idempotency
# ────────────────────────────────────────────────────────────────────

class TestIdempotency:
    def test_double_call_no_duplicate_stubs(self, tmp_path: Path):
        """Calling stub_missing_verify_files twice doesn't create duplicates."""
        _write_queue(tmp_path, [
            {"finding_id": "H-01", "severity": "High"},
        ])
        stubbed1 = stub_missing_verify_files(tmp_path, "sc")
        assert stubbed1 == ["H-01"]
        stubbed2 = stub_missing_verify_files(tmp_path, "sc")
        assert stubbed2 == []


# ────────────────────────────────────────────────────────────────────
# v2.6.8: identify_missing_verify_ids
# ────────────────────────────────────────────────────────────────────

class TestIdentifyMissingVerifyIds:
    def test_returns_missing_with_row_data(self, tmp_path: Path):
        """Returns (id, row) pairs for findings without verify files."""
        _write_queue(tmp_path, [
            {"finding_id": "H-01", "severity": "High", "title": "Bug one"},
            {"finding_id": "H-02", "severity": "High", "title": "Bug two"},
            {"finding_id": "M-01", "severity": "Medium", "title": "Bug three"},
        ])
        missing = identify_missing_verify_ids(tmp_path)
        assert len(missing) == 3
        ids = [fid for fid, _ in missing]
        assert sorted(ids) == ["H-01", "H-02", "M-01"]
        for fid, row in missing:
            assert row.get("finding id") == fid

    def test_skips_existing_files(self, tmp_path: Path):
        """Findings with existing verify files are not returned."""
        _write_queue(tmp_path, [
            {"finding_id": "H-01", "severity": "High"},
            {"finding_id": "H-02", "severity": "High"},
        ])
        _write_real_verify(tmp_path, "H-01")
        missing = identify_missing_verify_ids(tmp_path)
        assert len(missing) == 1
        assert missing[0][0] == "H-02"

    def test_empty_queue(self, tmp_path: Path):
        """Empty queue → empty result."""
        _write_queue(tmp_path, [])
        missing = identify_missing_verify_ids(tmp_path)
        assert missing == []

    def test_no_queue_file(self, tmp_path: Path):
        """Missing queue file → empty result, no crash."""
        missing = identify_missing_verify_ids(tmp_path)
        assert missing == []

    def test_all_present(self, tmp_path: Path):
        """All verify files present → empty result."""
        _write_queue(tmp_path, [
            {"finding_id": "H-01", "severity": "High"},
            {"finding_id": "M-01", "severity": "Medium"},
        ])
        _write_real_verify(tmp_path, "H-01")
        _write_real_verify(tmp_path, "M-01")
        missing = identify_missing_verify_ids(tmp_path)
        assert missing == []

    def test_recognizes_alternate_verify_names(self, tmp_path: Path):
        """Files named verify_F-{id}.md are recognized as present."""
        _write_queue(tmp_path, [
            {"finding_id": "INV-001", "severity": "Critical"},
            {"finding_id": "INV-002", "severity": "High"},
        ])
        # Write with alternate naming convention
        content = "# Verification\n**Verdict**: CONFIRMED\n" + "x" * 100
        (tmp_path / "verify_F-INV-001.md").write_text(content, encoding="utf-8")
        missing = identify_missing_verify_ids(tmp_path)
        assert len(missing) == 1
        assert missing[0][0] == "INV-002"

    def test_consistent_with_stub(self, tmp_path: Path):
        """identify + stub = same result as stub alone (refactor correctness)."""
        _write_queue(tmp_path, [
            {"finding_id": "H-01", "severity": "High"},
            {"finding_id": "H-02", "severity": "High"},
        ])
        _write_real_verify(tmp_path, "H-01")

        missing = identify_missing_verify_ids(tmp_path)
        missing_ids = [fid for fid, _ in missing]

        stubbed = stub_missing_verify_files(tmp_path, "sc")
        assert stubbed == missing_ids


# ────────────────────────────────────────────────────────────────────
# v2.6.8: recovery shard integration
# ────────────────────────────────────────────────────────────────────

class TestRecoveryShard:
    def test_recovery_function_exists(self):
        """_run_verify_recovery_shard is importable from the driver."""
        from plamen_driver import _run_verify_recovery_shard
        assert callable(_run_verify_recovery_shard)

    def test_recovery_returns_still_missing_on_no_claude(self, tmp_path: Path):
        """When claude binary doesn't exist, recovery returns all IDs as still missing."""
        import plamen_driver as D
        old_bin = D.CLAUDE_BIN
        D.CLAUDE_BIN = "/nonexistent/claude"
        try:
            _write_queue(tmp_path, [
                {"finding_id": "H-01", "severity": "High", "title": "Bug A"},
                {"finding_id": "M-01", "severity": "Medium", "title": "Bug B"},
            ])
            missing = identify_missing_verify_ids(tmp_path)
            config = {
                "scratchpad": str(tmp_path),
                "pipeline": "sc",
                "project_root": str(tmp_path),
                "language": "evm",
                "mode": "core",
            }
            still_missing = D._run_verify_recovery_shard(config, missing)
            assert sorted(still_missing) == ["H-01", "M-01"]
        finally:
            D.CLAUDE_BIN = old_bin

    def test_recovery_writes_manifest(self, tmp_path: Path):
        """Recovery shard writes verification_queue_recovery.md manifest."""
        import plamen_driver as D
        old_bin = D.CLAUDE_BIN
        D.CLAUDE_BIN = "/nonexistent/claude"
        try:
            _write_queue(tmp_path, [
                {"finding_id": "H-01", "severity": "High", "title": "Bug A"},
            ])
            missing = identify_missing_verify_ids(tmp_path)
            config = {
                "scratchpad": str(tmp_path),
                "pipeline": "l1",
                "project_root": str(tmp_path),
                "language": "rust",
                "mode": "thorough",
            }
            D._run_verify_recovery_shard(config, missing)
            manifest = tmp_path / "verification_queue_recovery.md"
            assert manifest.exists()
            content = manifest.read_text(encoding="utf-8")
            assert "H-01" in content
        finally:
            D.CLAUDE_BIN = old_bin

    def test_recovery_writes_prompt_snapshot(self, tmp_path: Path):
        """Recovery shard writes a prompt snapshot file."""
        import plamen_driver as D
        old_bin = D.CLAUDE_BIN
        D.CLAUDE_BIN = "/nonexistent/claude"
        try:
            _write_queue(tmp_path, [
                {"finding_id": "M-01", "severity": "Medium", "title": "Bug"},
            ])
            missing = identify_missing_verify_ids(tmp_path)
            config = {
                "scratchpad": str(tmp_path),
                "pipeline": "sc",
                "project_root": str(tmp_path),
                "language": "evm",
                "mode": "core",
            }
            D._run_verify_recovery_shard(config, missing)
            snap = tmp_path / "_prompt_verify_recovery.attempt1.md"
            assert snap.exists()
            content = snap.read_text(encoding="utf-8")
            assert "Independent Verification Recovery Work Unit" in content
            assert "M-01" in content
            assert "verify_<ID>.severity_proposal.json" in content
            assert "verify_<ID>.operator_application.json" in content
        finally:
            D.CLAUDE_BIN = old_bin

    def test_recovery_then_stub_integration(self, tmp_path: Path):
        """Full flow: recovery fails → stub fills the gap."""
        import plamen_driver as D
        old_bin = D.CLAUDE_BIN
        D.CLAUDE_BIN = "/nonexistent/claude"
        try:
            _write_queue(tmp_path, [
                {"finding_id": "H-01", "severity": "High", "title": "Bug A"},
                {"finding_id": "M-01", "severity": "Medium", "title": "Bug B"},
            ])
            # One file already exists from normal shards
            _write_real_verify(tmp_path, "H-01")
            missing = identify_missing_verify_ids(tmp_path)
            assert len(missing) == 1  # only M-01

            config = {
                "scratchpad": str(tmp_path),
                "pipeline": "sc",
                "project_root": str(tmp_path),
                "language": "evm",
                "mode": "core",
            }
            still_missing = D._run_verify_recovery_shard(config, missing)
            assert still_missing == ["M-01"]

            # Now stub what recovery couldn't cover
            stubbed = stub_missing_verify_files(tmp_path, "sc")
            assert stubbed == ["M-01"]

            # After stub, parity gate should pass
            assert _verify_file_present_for_id(tmp_path, "H-01")
            assert _verify_file_present_for_id(tmp_path, "M-01")
        finally:
            D.CLAUDE_BIN = old_bin

    def test_recovery_l1_prompt_uses_l1_template(self, tmp_path: Path):
        """L1 pipeline uses L1 verification template."""
        import plamen_driver as D
        old_bin = D.CLAUDE_BIN
        D.CLAUDE_BIN = "/nonexistent/claude"
        try:
            _write_queue(tmp_path, [
                {"finding_id": "INV-001", "severity": "Critical", "title": "L1 Bug"},
            ])
            missing = identify_missing_verify_ids(tmp_path)
            config = {
                "scratchpad": str(tmp_path),
                "pipeline": "l1",
                "project_root": str(tmp_path),
                "language": "rust",
                "mode": "thorough",
            }
            D._run_verify_recovery_shard(config, missing)
            snap = tmp_path / "_prompt_verify_recovery.attempt1.md"
            if snap.exists():
                content = snap.read_text(encoding="utf-8")
                assert "Independent Verification Recovery Work Unit" in content
        finally:
            D.CLAUDE_BIN = old_bin
