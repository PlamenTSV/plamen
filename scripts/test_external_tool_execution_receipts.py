"""Focused run, replay, and tamper coverage for external-tool receipts."""

from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

import recon_prepass as recon
import tool_coverage_ledger as ledger
from test_support.tool_execution_receipt import fixture_execution_receipt


def _context(
    project: Path, *, ecosystem: str = "solana", pipeline: str = "sc"
) -> dict[str, str]:
    identity = os.path.normcase(str(project.resolve())).replace("\\", "/")
    return {
        "run_id": "execution-receipt-fixture",
        "phase": "recon-prebreadth",
        "snapshot_sha256": "1" * 64,
        "project_root_sha256": hashlib.sha256(
            identity.encode("utf-8")
        ).hexdigest(),
        "ecosystem": ecosystem,
        "pipeline": pipeline,
        "mode": "thorough",
        "platform": (
            "windows" if os.name == "nt" else "macos" if os.sys.platform == "darwin" else "linux"
        ),
    }


@pytest.mark.parametrize(
    ("executable", "cwd"),
    (
        ("/opt/plamen/bin/opengrep", "/audit/project"),
        (r"C:\\Program Files\\Plamen\\opengrep.exe", r"C:\\audit\\project"),
        (r"\\server\\plamen\\opengrep.exe", r"\\server\\audit\\project"),
    ),
)
def test_execution_receipt_replays_portably(executable: str, cwd: str) -> None:
    receipt = fixture_execution_receipt(
        executable_path=executable, cwd=cwd
    )
    assert ledger.replay_external_tool_execution_receipt(receipt) == []
    assert "\\" not in receipt["cwd"]


def test_hardened_run_emits_process_bound_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable = tmp_path / "opengrep"
    executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    executable.chmod(0o755)
    authority = copy.deepcopy(
        fixture_execution_receipt(
            executable_path=str(executable)
        )["provider_authority_before"]
    )

    def capture(*_args, **_kwargs):
        return copy.deepcopy(authority)

    def run(argv, **_kwargs):
        return SimpleNamespace(
            args=tuple(argv),
            returncode=0,
            stdout="scan-complete",
            stderr="warning",
            duration_s=0.125,
            process_tree_terminated=True,
            containment_capability={"platform": "TEST", "scope": "OWNED"},
            stdout_observed_bytes=len(b"scan-complete"),
            stderr_observed_bytes=len(b"warning"),
            stdout_retained_bytes=len(b"scan-complete"),
            stderr_retained_bytes=len(b"warning"),
            stdout_sha256=hashlib.sha256(b"scan-complete").hexdigest(),
            stderr_sha256=hashlib.sha256(b"warning").hexdigest(),
            stdout_truncated=False,
            stderr_truncated=False,
            executable_binding_sha256="e" * 64,
        )

    monkeypatch.setattr(recon, "_capture_command_provider_authority", capture)
    monkeypatch.setattr(recon, "run_owned_process", run)
    receipt: dict = {}
    env = {
        "PATH": str(tmp_path),
        "PLAMEN_TEST_TOKEN": "must-not-appear",
        "GOTOOLCHAIN": "local",
    }
    rc, output = recon._run_hardened(
        ["opengrep", "scan"],
        tmp_path,
        env=env,
        execution_receipt=receipt,
        execution_tool="opengrep",
        version_command=("opengrep", "--version"),
        project_root=tmp_path,
        workspace_root=tmp_path,
    )
    assert rc == 0
    assert output == "scan-completewarning"
    assert ledger.replay_external_tool_execution_receipt(receipt) == []
    serialized = json.dumps(receipt)
    assert "must-not-appear" not in serialized
    assert "PLAMEN_TEST_TOKEN" not in serialized
    assert receipt["environment"]["excluded_secret_key_count"] == 1
    assert receipt["stdout_receipt"]["retained_bytes"] == len("scan-complete")


def test_artifact_only_success_is_rejected(tmp_path: Path) -> None:
    (tmp_path / "opengrep_results.sarif").write_text("{}", encoding="utf-8")
    (tmp_path / "opengrep_findings.md").write_text("clean", encoding="utf-8")
    outcome = ledger.ToolOutcome.succeeded(
        "opengrep.static-analysis",
        "opengrep",
        0,
        artifacts=("opengrep_results.sarif", "opengrep_findings.md"),
    )
    with pytest.raises(
        ledger.ToolCoverageLedgerError, match="execution authority"
    ):
        ledger.bind_succeeded_tool_outcome(
            tmp_path, outcome, context=_context(tmp_path)
        )


def test_legacy_artifact_only_envelope_is_rejected_on_replay(
    tmp_path: Path,
) -> None:
    for name in ("opengrep_results.sarif", "opengrep_findings.md"):
        (tmp_path / name).write_text(name, encoding="utf-8")
    bound = ledger.bind_succeeded_tool_outcome(
        tmp_path,
        ledger.ToolOutcome.succeeded(
            "opengrep.static-analysis",
            "opengrep",
            0,
            artifacts=("opengrep_results.sarif", "opengrep_findings.md"),
        ),
        context=_context(tmp_path),
        execution_receipt=fixture_execution_receipt(),
    )
    legacy = json.loads(bound.provider_ref)
    legacy.pop("execution_receipt")
    legacy["schema_version"] = ledger.LEGACY_GENERIC_SUCCESS_OUTCOME_SCHEMA
    unsigned = dict(legacy)
    unsigned.pop("envelope_sha256")
    legacy["envelope_sha256"] = hashlib.sha256(
        (json.dumps(
            unsigned,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ) + "\n").encode("utf-8")
    ).hexdigest()
    stale = ledger.ToolOutcome.succeeded(
        bound.capability_id,
        bound.tool,
        0,
        artifacts=bound.artifacts,
        provider_ref=json.dumps(legacy),
    )
    with pytest.raises(
        ledger.ToolCoverageLedgerError, match="LEGACY_UNBOUND_EXECUTION"
    ):
        ledger.record_tool_outcome(tmp_path, stale)


@pytest.mark.parametrize(
    ("language", "capability_id", "tool", "scanner_name", "accepted"),
    (
        ("go", "govulncheck.dependency-audit", "govulncheck", "_govulncheck_scan", (0, 3)),
        ("rust", "cargo-audit.dependency-audit", "cargo-audit", "_cargo_audit_scan", (0, 1)),
    ),
)
def test_dependency_success_consumes_real_execution_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    language: str,
    capability_id: str,
    tool: str,
    scanner_name: str,
    accepted: tuple[int, ...],
) -> None:
    scratch = tmp_path / "scratch"
    project = tmp_path / "project"
    scratch.mkdir()
    project.mkdir()

    def scanner(_project: Path, *, execution_receipt: dict):
        execution_receipt.update(
            fixture_execution_receipt(
                tool,
                executable_path=f"/opt/plamen/bin/{tool}",
                accepted_returncodes=accepted,
            )
        )
        return "WRITTEN", []

    provider = json.dumps({
        "schema_version": "plamen.advisory_source.v1",
        "source_id": (
            "govulndb-local" if language == "go" else "rustsec-local"
        ),
        "provider": (
            "Go Vulnerability Database"
            if language == "go"
            else "RustSec Advisory Database"
        ),
        "content_sha256": "d" * 64,
        "as_of": "2026-09-15T09:00:00Z",
        "expires_at": "2026-09-16T09:00:00Z",
    })
    monkeypatch.setattr(recon, scanner_name, scanner)
    monkeypatch.setattr(
        recon,
        "_resolve_advisory_source",
        lambda _source: (Path("/opt/plamen/advisories"), provider, ""),
    )
    context = _context(project, ecosystem=language, pipeline="l1")
    assert "WRITTEN" in recon._run_dependency_audit_l1(
        scratch, project, language, context=context
    )
    outcome = ledger.load_tool_coverage_ledger(
        scratch, expected_context=context
    )[capability_id]
    assert outcome.state is ledger.ToolOutcomeState.SUCCEEDED
    envelope = json.loads(outcome.provider_ref)
    assert envelope["execution_receipt"]["execution_tool"] == tool


def test_execution_receipt_tamper_survives_outer_rehash_but_fails_replay(
    tmp_path: Path,
) -> None:
    for name in ("opengrep_results.sarif", "opengrep_findings.md"):
        (tmp_path / name).write_text(name, encoding="utf-8")
    bound = ledger.bind_succeeded_tool_outcome(
        tmp_path,
        ledger.ToolOutcome.succeeded(
            "opengrep.static-analysis",
            "opengrep",
            0,
            artifacts=("opengrep_results.sarif", "opengrep_findings.md"),
        ),
        context=_context(tmp_path),
        execution_receipt=fixture_execution_receipt(),
    )
    envelope = json.loads(bound.provider_ref)
    envelope["execution_receipt"]["argv"].append("--tampered")
    unsigned = dict(envelope)
    unsigned.pop("envelope_sha256")
    envelope["envelope_sha256"] = hashlib.sha256(
        (json.dumps(
            unsigned,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ) + "\n").encode("utf-8")
    ).hexdigest()
    issues = ledger.replay_generic_success_outcome_envelope(
        tmp_path, envelope, expected_context=_context(tmp_path)
    )
    assert any("execution receipt digest drifted" in issue for issue in issues)
    assert any("execution argv digest drifted" in issue for issue in issues)
