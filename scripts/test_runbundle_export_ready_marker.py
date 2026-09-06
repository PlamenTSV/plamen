"""Fixture-first export-ready marker tests."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

import runbundle_contracts as C
import runbundle_export_ready as R


def _write_inputs(root: Path) -> tuple[Path, Path, Path]:
    scratchpad = root / ".scratchpad"
    scratchpad.mkdir()
    checkpoint = scratchpad / "checkpoint.json"
    checkpoint.write_text(
        '{"schema_version":"plamen.checkpoint.v1","phase":"report"}\n',
        encoding="utf-8",
    )
    ledger = scratchpad / "_artifact_state.json"
    ledger.write_text(
        '{"schema_version":"plamen.artifact-state.v1","generation":7}\n',
        encoding="utf-8",
    )
    report = root / "AUDIT_REPORT.md"
    report.write_text("# Audit report\n\nNo findings.\n", encoding="utf-8")
    return checkpoint, ledger, report


def test_export_ready_marker_is_tiny_gt_blind_and_digest_bound(tmp_path: Path):
    checkpoint, ledger, report = _write_inputs(tmp_path)
    marker = R.build_export_ready_marker(
        run_id="run-public-001",
        checkpoint=checkpoint,
        artifact_ledger=ledger,
        report=report,
        report_gate_state="PASSED",
    )
    assert marker["schema_version"] == R.EXPORT_READY_SCHEMA
    assert marker["checkpoint_sha256"] == C.sha256_bytes(checkpoint.read_bytes())
    assert marker["artifact_ledger_sha256"] == C.sha256_bytes(ledger.read_bytes())
    assert marker["final_report_sha256"] == C.sha256_bytes(report.read_bytes())
    assert len(C.canonical_document_bytes(marker)) < 4096
    R.validate_export_ready_marker(marker)

    out = tmp_path / ".scratchpad" / "run_export_ready.json"
    written = R.write_export_ready_marker(out=out, marker=marker)
    assert written == out.resolve()
    assert json.loads(out.read_text(encoding="utf-8")) == marker
    with pytest.raises(R.RunBundleExportReadyError, match="exists|overwrite"):
        R.write_export_ready_marker(out=out, marker=marker)


def test_export_ready_marker_detects_post_build_input_mutation(tmp_path: Path):
    checkpoint, ledger, report = _write_inputs(tmp_path)
    marker = R.build_export_ready_marker(
        run_id="run-public-002",
        checkpoint=checkpoint,
        artifact_ledger=ledger,
        report=report,
        report_gate_state="PASSED",
    )
    report.write_text("# Changed\n", encoding="utf-8")
    with pytest.raises(R.RunBundleExportReadyError, match="drift|changed"):
        R.verify_export_ready_inputs(
            marker,
            checkpoint=checkpoint,
            artifact_ledger=ledger,
            report=report,
        )
