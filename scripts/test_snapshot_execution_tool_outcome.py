"""Operational snapshot execution remains orthogonal to clean authority."""

from __future__ import annotations

import hashlib
from pathlib import Path
from types import SimpleNamespace

import pytest

import tool_coverage_ledger as ledger


def _context() -> dict[str, str]:
    return {
        "run_id": "snapshot-evidence-run",
        "phase": "recon-prebreadth",
        "snapshot_sha256": "1" * 64,
        "project_root_sha256": "2" * 64,
        "ecosystem": "evm",
        "pipeline": "sc",
        "mode": "core",
        "platform": "macos",
    }


def _evidence(*, returncode: int = 0) -> dict[str, object]:
    terminal = {
        "schema": "plamen.snapshot-bound-tool-execution-terminal.v3",
        "request_sha256": "3" * 64,
        "run_id": "snapshot-evidence-run",
        "audit_snapshot_sha256": "1" * 64,
        "tool_id": "opengrep",
        "source_descriptor_sha256": "4" * 64,
        "materialization_lineage_sha256": "5" * 64,
        "toolchain_governance_sha256": "6" * 64,
        "toolchain_version_lock_sha256": "7" * 64,
        "native_runtime_identity_sha256": "8" * 64,
        "argv_sha256": "9" * 64,
        "environment_sha256": "a" * 64,
        "cwd_sha256": "b" * 64,
        "mounts_sha256": "c" * 64,
        "source_scope_sha256": "d" * 64,
        "post_spawn_dynamic_identity_sha256": "e" * 64,
        "egress_policy": "DENY_ALL",
        "egress_denied": True,
        "exit_state": "COMPLETED",
        "returncode": returncode,
        "duration_ms": 10,
        "peak_memory_bytes": 1024,
        "stdout_sha256": "f" * 64,
        "stdout_observed_bytes": 0,
        "stdout_retained_bytes": 0,
        "stderr_sha256": "0" * 64,
        "stderr_observed_bytes": 0,
        "stderr_retained_bytes": 0,
        "output_tree_sha256": "1" * 64,
        "output_file_count": 2,
        "output_bytes": 20,
        "output_limit_exceeded": False,
        "population_zero": True,
        "cleanup_complete": True,
        "truncation_debt": None,
    }
    return {
        "schema": "plamen.snapshot-bound-tool-execution-evidence.v1",
        "evidence_only": True,
        "execution_authority_reusable": False,
        "authority_tier": "SNAPSHOT_BOUND_LOCAL",
        "authentic_content_authority": False,
        "can_certify_clean": False,
        "request_sha256": terminal["request_sha256"],
        "terminal_sha256": hashlib.sha256(
            ledger._compact_canonical_json(terminal)
        ).hexdigest(),
        "terminal": terminal,
    }


def _patch_controls(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        ledger._toolchain_controls,
        "load_toolchain_controls",
        lambda *_args, **_kwargs: SimpleNamespace(
            governance_sha256="6" * 64,
            lock_sha256="7" * 64,
        ),
    )
    monkeypatch.setattr(
        ledger,
        "_workspace_success_reference",
        lambda *_args, **_kwargs: {
            "schema": "plamen.test-workspace-reference.v1",
            "reference_sha256": "8" * 64,
        },
    )
    monkeypatch.setattr(
        ledger,
        "_governed_capability",
        lambda capability_id, tool, **_kwargs: {
            "capability_id": capability_id,
            "tools": [tool],
            "applicability": {
                "pipelines": ["sc"],
                "ecosystems": ["evm"],
                "platforms": ["macos"],
                "modes": ["core"],
                "phases": ["recon-prebreadth"],
            },
        },
    )


def test_authenticated_execution_counts_without_minting_clean_authority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_controls(monkeypatch)
    (tmp_path / "opengrep_results.sarif").write_text("{}\n", encoding="utf-8")
    (tmp_path / "opengrep_findings.md").write_text("# Findings\n", encoding="utf-8")
    envelope = ledger.build_snapshot_execution_tool_outcome_envelope(
        tmp_path,
        capability_id="opengrep.static-analysis",
        tool="opengrep",
        evidence=_evidence(),
        context=_context(),
        artifacts=("opengrep_results.sarif", "opengrep_findings.md"),
        finding_count=0,
    )
    assert "deterministic_provider_authority" not in envelope
    assert envelope["assurance_limitations"] == {
        "authentic_content_authority": False,
        "can_certify_clean": False,
        "positive_findings": "REVIEWABLE_CANDIDATES_ONLY",
        "zero_findings": "INSUFFICIENT_FOR_CLEAN_CONCLUSION",
    }
    assert ledger.replay_snapshot_execution_tool_outcome_envelope(
        tmp_path, envelope, expected_context=_context()
    ) == []


def test_boolean_returncode_and_truncated_stream_cannot_replay() -> None:
    forged = _evidence(returncode=False)
    with pytest.raises(ledger.ToolCoverageLedgerError, match="stream completion"):
        ledger._validated_snapshot_execution_evidence(forged, tool="opengrep")

    truncated = _evidence()
    truncated["terminal"]["stdout_observed_bytes"] = 1
    truncated["terminal_sha256"] = hashlib.sha256(
        ledger._compact_canonical_json(truncated["terminal"])
    ).hexdigest()
    with pytest.raises(ledger.ToolCoverageLedgerError, match="stream completion"):
        ledger._validated_snapshot_execution_evidence(truncated, tool="opengrep")
