"""Tests for P4: Sec3 X-Ray Solana scanner integration.

Tests skip/fail paths, SARIF parsing, Docker probe, and prepass wiring.
"""
from __future__ import annotations

import json
import hashlib
import os
import sys
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import recon_prepass as RP
from recon_prepass import (
    _run_sec3_xray,
    _parse_sec3_sarif,
    run_recon_prepass,
    _write_text,
)

_TEST_SEC3_IMAGE = (
    "ghcr.io/sec3-product/x-ray@sha256:" + ("2" * 64)
)


@pytest.fixture(autouse=True)
def _governed_sec3_image(monkeypatch):
    monkeypatch.setattr(RP, "_SEC3_XRAY_IMAGE", _TEST_SEC3_IMAGE)

# ── helpers ──────────────────────────────────────────────────────────────


def _mkscratch(tmp_path: Path) -> Path:
    s = tmp_path / ".scratchpad"
    s.mkdir()
    return s


def _mkproj(tmp_path: Path, *, lang: str = "solana") -> Path:
    p = tmp_path / "project"
    p.mkdir()
    src = p / "src"
    src.mkdir()
    ext = {"solana": ".rs", "evm": ".sol", "soroban": ".rs"}
    (src / f"program{ext.get(lang, '.rs')}").write_text("// source", encoding="utf-8")
    return p


def _context(project: Path) -> dict[str, str]:
    identity = os.path.normcase(str(project.resolve())).replace("\\", "/")
    return {
        "run_id": "sec3-fixture",
        "phase": "recon-prebreadth",
        "snapshot_sha256": "1" * 64,
        "project_root_sha256": hashlib.sha256(
            identity.encode("utf-8")
        ).hexdigest(),
        "ecosystem": "solana",
        "pipeline": "sc",
        "mode": "thorough",
        "platform": (
            "windows"
            if sys.platform == "win32"
            else "macos"
            if sys.platform == "darwin"
            else "linux"
            if sys.platform.startswith("linux")
            else sys.platform
        ),
    }


_SAMPLE_SEC3_SARIF = {
    "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    "version": "2.1.0",
    "runs": [{
        "tool": {"driver": {"name": "sec3-x-ray", "version": "0.5.0"}},
        "results": [
            {
                "ruleId": "sec3.integer-overflow",
                "level": "error",
                "message": {"text": "Potential integer overflow in arithmetic operation"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": "src/processor.rs"},
                        "region": {"startLine": 42, "startColumn": 5}
                    }
                }]
            },
            {
                "ruleId": "sec3.missing-signer-check",
                "level": "warning",
                "message": {"text": "Account missing signer verification"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": "src/instructions/transfer.rs"},
                        "region": {"startLine": 18, "startColumn": 1}
                    }
                }]
            },
            {
                "ruleId": "sec3.unsafe-arithmetic",
                "level": "error",
                "message": {"text": "Unchecked math in token amount calculation"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": "src/math.rs"},
                        "region": {"startLine": 77, "startColumn": 12}
                    }
                }]
            },
        ]
    }]
}


# ── skip / fail paths ────────────────────────────────────────────────────


def test_scan_skip_no_docker(tmp_path):
    scratch = _mkscratch(tmp_path)
    proj = _mkproj(tmp_path)
    with mock.patch("shutil.which", return_value=None):
        result = _run_sec3_xray(
            scratch, proj, context=_context(proj)
        )
    assert "SKIPPED" in result
    assert "docker not found" in result


def test_scan_skip_docker_daemon_not_running(tmp_path):
    scratch = _mkscratch(tmp_path)
    proj = _mkproj(tmp_path)
    with mock.patch("shutil.which", return_value="/usr/bin/docker"):
        with mock.patch("recon_prepass._run_hardened", return_value=(1, "Cannot connect")):
            result = _run_sec3_xray(
                scratch, proj, context=_context(proj)
            )
    assert "SKIPPED" in result
    assert "daemon not running" in result


def test_scan_skip_docker_probe_timeout(tmp_path):
    scratch = _mkscratch(tmp_path)
    proj = _mkproj(tmp_path)
    # _run_hardened returns the 124 sentinel when the docker-info probe is
    # tree-killed on timeout.
    with mock.patch("shutil.which", return_value="/usr/bin/docker"):
        with mock.patch("recon_prepass._run_hardened",
                        return_value=(124, "[hardened: timed out after 15s, tree-killed]")):
            result = _run_sec3_xray(
                scratch, proj, context=_context(proj)
            )
    assert "SKIPPED" in result
    assert "not available" in result


def test_scan_skip_no_rs_files(tmp_path):
    scratch = _mkscratch(tmp_path)
    proj = tmp_path / "empty_project"
    proj.mkdir()
    (proj / "README.md").write_text("# hello", encoding="utf-8")
    with mock.patch("shutil.which", return_value="/usr/bin/docker"):
        with mock.patch("recon_prepass._run_hardened", return_value=(0, "")):
            result = _run_sec3_xray(
                scratch, proj, context=_context(proj)
            )
    assert "SKIPPED" in result
    assert "no .rs files" in result


def test_scan_fail_timeout(tmp_path):
    scratch = _mkscratch(tmp_path)
    proj = _mkproj(tmp_path)
    call_count = [0]

    def side_effect(*args, **kwargs):
        call_count[0] += 1
        if call_count[0] == 1:
            return (0, "")  # docker info succeeds
        return (124, "[hardened: timed out after 600s, tree-killed]")

    with mock.patch("shutil.which", return_value="/usr/bin/docker"):
        with mock.patch("recon_prepass._run_hardened", side_effect=side_effect):
            result = _run_sec3_xray(
                scratch, proj, context=_context(proj)
            )
    assert "FAILED" in result
    assert "timeout" in result


def test_scan_fail_nonzero_no_sarif(tmp_path):
    scratch = _mkscratch(tmp_path)
    proj = _mkproj(tmp_path)
    call_count = [0]

    def side_effect(*args, **kwargs):
        call_count[0] += 1
        if call_count[0] == 1:
            return (0, "")  # docker info
        return (2, "error")

    with mock.patch("shutil.which", return_value="/usr/bin/docker"):
        with mock.patch("recon_prepass._run_hardened", side_effect=side_effect):
            result = _run_sec3_xray(
                scratch, proj, context=_context(proj)
            )
    assert "FAILED" in result
    assert "exit 2" in result


# ── SARIF parsing ────────────────────────────────────────────────────────


def test_parse_sarif_valid(tmp_path):
    scratch = _mkscratch(tmp_path)
    sarif_path = scratch / "raw.sarif"
    sarif_path.write_text(json.dumps(_SAMPLE_SEC3_SARIF), encoding="utf-8")
    count = _parse_sec3_sarif(scratch, sarif_path)
    assert count == 3
    md = (scratch / "sec3_findings.md").read_text(encoding="utf-8")
    assert "sec3.integer-overflow" in md
    assert "sec3.missing-signer-check" in md
    assert "sec3.unsafe-arithmetic" in md
    assert "src/processor.rs:L42" in md
    assert "src/math.rs:L77" in md


def test_parse_sarif_empty(tmp_path):
    scratch = _mkscratch(tmp_path)
    sarif_path = scratch / "raw.sarif"
    empty_sarif = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "sec3"}}, "results": []}]}
    sarif_path.write_text(json.dumps(empty_sarif), encoding="utf-8")
    count = _parse_sec3_sarif(scratch, sarif_path)
    assert count == 0
    md = (scratch / "sec3_findings.md").read_text(encoding="utf-8")
    assert "Total**: 0" in md


def test_parse_sarif_invalid_json(tmp_path):
    scratch = _mkscratch(tmp_path)
    sarif_path = scratch / "raw.sarif"
    sarif_path.write_text("not json {{{", encoding="utf-8")
    count = _parse_sec3_sarif(scratch, sarif_path)
    assert count == 0
    md = (scratch / "sec3_findings.md").read_text(encoding="utf-8")
    assert "parse failed" in md


def test_parse_sarif_pipe_in_message(tmp_path):
    scratch = _mkscratch(tmp_path)
    sarif = {
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "sec3"}}, "results": [
            {
                "ruleId": "test.pipe",
                "level": "warning",
                "message": {"text": "has | pipe | chars"},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": "a.rs"},
                    "region": {"startLine": 1}
                }}]
            }
        ]}]
    }
    sarif_path = scratch / "raw.sarif"
    sarif_path.write_text(json.dumps(sarif), encoding="utf-8")
    count = _parse_sec3_sarif(scratch, sarif_path)
    assert count == 1
    md = (scratch / "sec3_findings.md").read_text(encoding="utf-8")
    assert "\\|" in md  # pipes escaped


# ── prepass wiring ───────────────────────────────────────────────────────


def test_prepass_solana_triggers_sec3(tmp_path):
    """Sec3 X-Ray runs for Solana SC pipeline."""
    scratch = tmp_path / ".scratchpad"
    proj = _mkproj(tmp_path, lang="solana")
    config = {"scratchpad": str(scratch), "project_root": str(proj),
              "language": "solana", "pipeline": "sc",
              "prepass_external_scanners": True}  # RECON-1: exercise opt-in startup scan

    with mock.patch("recon_prepass._run_sec3_xray", return_value="SKIPPED:test") as m:
        with mock.patch("recon_prepass._run_opengrep_scan", return_value="SKIPPED:test"):
            run_recon_prepass(config)
    m.assert_called_once()


def test_prepass_evm_does_not_trigger_sec3(tmp_path):
    """Sec3 X-Ray does NOT run for EVM."""
    scratch = tmp_path / ".scratchpad"
    proj = _mkproj(tmp_path, lang="solana")  # has .rs files but lang=evm
    config = {"scratchpad": str(scratch), "project_root": str(proj),
              "language": "evm", "pipeline": "sc"}

    with mock.patch("recon_prepass._run_sec3_xray", return_value="SKIPPED:test") as m:
        with mock.patch("recon_prepass._run_opengrep_scan", return_value="SKIPPED:test"):
            run_recon_prepass(config)
    m.assert_not_called()


def test_prepass_l1_does_not_trigger_sec3(tmp_path):
    """Sec3 X-Ray does NOT run for L1 pipeline."""
    scratch = tmp_path / ".scratchpad"
    proj = _mkproj(tmp_path, lang="solana")
    config = {"scratchpad": str(scratch), "project_root": str(proj),
              "language": "solana", "pipeline": "l1"}

    with mock.patch("recon_prepass._run_sec3_xray", return_value="SKIPPED:test") as m:
        with mock.patch("recon_prepass._run_opengrep_scan", return_value="SKIPPED:test"):
            run_recon_prepass(config)
    m.assert_not_called()


def test_prepass_sec3_failure_does_not_crash(tmp_path):
    """Sec3 failure is caught by _safe wrapper."""
    scratch = tmp_path / ".scratchpad"
    proj = _mkproj(tmp_path, lang="solana")
    config = {"scratchpad": str(scratch), "project_root": str(proj),
              "language": "solana", "pipeline": "sc",
              "prepass_external_scanners": True}  # RECON-1: exercise opt-in startup scan

    def boom():
        raise RuntimeError("Docker exploded")

    with mock.patch("recon_prepass._run_sec3_xray", side_effect=RuntimeError("Docker exploded")):
        with mock.patch("recon_prepass._run_opengrep_scan", return_value="SKIPPED:test"):
            result = run_recon_prepass(config)
    assert "sec3_xray" in result
    assert "FAILED" in result["sec3_xray"]


# ── end-to-end with mocked Docker ───────────────────────────────────────


def test_scan_success_writes_sarif_and_summary(tmp_path):
    """Full success path: Docker runs, SARIF appears, summary written."""
    scratch = _mkscratch(tmp_path)
    proj = _mkproj(tmp_path)
    # Pre-create build_status.md
    _write_text(scratch / "build_status.md", "# Build Status\n\n- compiled: true\n")

    call_count = [0]
    sarif_path = scratch / ".sec3-output" / "sec3-report.sarif"

    def side_effect(cmd, *args, **kwargs):
        call_count[0] += 1
        if call_count[0] == 1:
            return (0, "")  # docker info
        # Simulate X-Ray writing SARIF
        sarif_path.write_text(json.dumps(_SAMPLE_SEC3_SARIF), encoding="utf-8")
        return (0, "")

    with mock.patch("shutil.which", return_value="/usr/bin/docker"):
        with mock.patch("recon_prepass._run_hardened", side_effect=side_effect):
            result = _run_sec3_xray(
                scratch, proj, context=_context(proj)
            )

    assert "WRITTEN:3 findings" in result
    assert (scratch / "sec3_results.sarif").exists()
    assert (scratch / "sec3_findings.md").exists()
    md = (scratch / "sec3_findings.md").read_text(encoding="utf-8")
    assert "sec3.integer-overflow" in md
    assert "sec3.missing-signer-check" in md

    # build_status updated
    bs = (scratch / "build_status.md").read_text(encoding="utf-8")
    assert "SEC3_XRAY_AVAILABLE: true" in bs
    assert "SEC3_FINDINGS: 3" in bs


def test_scan_alt_sarif_filename(tmp_path):
    """X-Ray writing to alternate filename still gets picked up."""
    scratch = _mkscratch(tmp_path)
    proj = _mkproj(tmp_path)

    call_count = [0]

    def side_effect(cmd, *args, **kwargs):
        call_count[0] += 1
        if call_count[0] == 1:
            return (0, "")  # docker info
        # Write to alternate filename
        alt = scratch / ".sec3-output" / "x-ray-report.sarif"
        alt.write_text(json.dumps(_SAMPLE_SEC3_SARIF), encoding="utf-8")
        return (0, "")

    with mock.patch("shutil.which", return_value="/usr/bin/docker"):
        with mock.patch("recon_prepass._run_hardened", side_effect=side_effect):
            result = _run_sec3_xray(
                scratch, proj, context=_context(proj)
            )

    assert "WRITTEN:3 findings" in result
    assert (scratch / "sec3_results.sarif").exists()


def test_scan_zero_findings(tmp_path):
    """A valid empty SARIF, not output absence, proves a clean scan."""
    scratch = _mkscratch(tmp_path)
    proj = _mkproj(tmp_path)
    call_count = [0]

    def side_effect(cmd, *args, **kwargs):
        call_count[0] += 1
        if call_count[0] == 1:
            return (0, "")  # docker info
        output = scratch / ".sec3-output"
        output.mkdir(parents=True, exist_ok=True)
        (output / "sec3-report.sarif").write_text(
            json.dumps({
                "version": "2.1.0",
                "runs": [{
                    "tool": {"driver": {"name": "sec3-x-ray"}},
                    "results": [],
                }],
            }),
            encoding="utf-8",
        )
        return (0, "")

    with mock.patch("shutil.which", return_value="/usr/bin/docker"):
        with mock.patch("recon_prepass._run_hardened", side_effect=side_effect):
            result = _run_sec3_xray(
                scratch, proj, context=_context(proj)
            )

    assert "WRITTEN:0 findings" in result


def test_prepass_soroban_does_not_trigger_sec3(tmp_path):
    """Sec3 X-Ray is Solana-specific, not for Soroban (despite both being Rust)."""
    scratch = tmp_path / ".scratchpad"
    proj = _mkproj(tmp_path, lang="soroban")
    config = {"scratchpad": str(scratch), "project_root": str(proj),
              "language": "soroban", "pipeline": "sc"}

    with mock.patch("recon_prepass._run_sec3_xray", return_value="SKIPPED:test") as m:
        with mock.patch("recon_prepass._run_opengrep_scan", return_value="SKIPPED:test"):
            run_recon_prepass(config)
    m.assert_not_called()
