from __future__ import annotations

import json
import hashlib
import os
import sys
from pathlib import Path

import recon_prepass as RP
from tool_coverage_ledger import ToolOutcomeState, load_tool_coverage_ledger


_EMPTY_SARIF = {
    "version": "2.1.0",
    "runs": [{
        "tool": {"driver": {"name": "scanner"}},
        "results": [],
    }],
}


def _context(
    project: Path,
    *,
    ecosystem: str,
    pipeline: str,
) -> dict[str, str]:
    identity = os.path.normcase(str(project.resolve())).replace("\\", "/")
    return {
        "run_id": "scanner-lifecycle-fixture",
        "phase": "recon-prebreadth",
        "snapshot_sha256": "1" * 64,
        "project_root_sha256": hashlib.sha256(
            identity.encode("utf-8")
        ).hexdigest(),
        "ecosystem": ecosystem,
        "pipeline": pipeline,
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


def test_semgrep_windows_adapter_records_validated_clean_coverage(
    tmp_path: Path,
    monkeypatch,
) -> None:
    scratch = tmp_path / "scratch"
    project = tmp_path / "project"
    source = project / "sources" / "m.move"
    rules = tmp_path / "rules"
    (rules / "rules").mkdir(parents=True)
    source.parent.mkdir(parents=True)
    scratch.mkdir()
    source.write_text("module 0x1::m {}", encoding="utf-8")

    def which(name: str):
        return "C:/Tools/semgrep.exe" if name == "semgrep" else None

    seen: list[list[str]] = []

    def run(command, _cwd, _timeout, **_kwargs):
        seen.append(command)
        destination = Path(command[command.index("--sarif-output") + 1])
        destination.write_text(
            json.dumps(_EMPTY_SARIF), encoding="utf-8",
        )
        return 0, ""

    monkeypatch.setattr(RP.shutil, "which", which)
    monkeypatch.setattr(
        RP, "_ensure_opengrep_rules", lambda: {"aptos-move-rules": rules},
    )
    monkeypatch.setattr(
        RP, "_production_source_files", lambda _project, _exts: [source],
    )
    monkeypatch.setattr(RP, "_run_hardened", run)

    status = RP._run_opengrep_scan(
        scratch,
        project,
        "aptos",
        context=_context(
            project, ecosystem="aptos", pipeline="sc"
        ),
    )
    outcome = load_tool_coverage_ledger(scratch)["opengrep.static-analysis"]

    assert status == "WRITTEN:0 findings"
    assert seen[0][0].lower().endswith("semgrep.exe")
    assert "--config" in seen[0]
    assert outcome.state is ToolOutcomeState.SUCCEEDED
    assert outcome.schema_validated is True
    assert outcome.finding_count == 0


def test_malformed_scanner_output_is_durable_failed_debt(
    tmp_path: Path,
    monkeypatch,
) -> None:
    scratch = tmp_path / "scratch"
    project = tmp_path / "project"
    source = project / "src" / "c.sol"
    rules = tmp_path / "rules"
    (rules / "solidity").mkdir(parents=True)
    source.parent.mkdir(parents=True)
    scratch.mkdir()
    source.write_text("contract C {}", encoding="utf-8")

    monkeypatch.setattr(RP.shutil, "which", lambda _name: "/tool/opengrep")
    monkeypatch.setattr(
        RP,
        "_ensure_opengrep_rules",
        lambda: {"opengrep-rules": rules, "decurity-rules": rules},
    )
    monkeypatch.setattr(
        RP, "_production_source_files", lambda _project, _exts: [source],
    )

    def run(command, _cwd, _timeout, **_kwargs):
        destination = Path(command[command.index("--sarif-output") + 1])
        destination.write_text(
            "{broken", encoding="utf-8",
        )
        return 0, ""

    monkeypatch.setattr(RP, "_run_hardened", run)
    status = RP._run_opengrep_scan(
        scratch,
        project,
        "evm",
        context=_context(
            project, ecosystem="evm", pipeline="sc"
        ),
    )
    outcome = load_tool_coverage_ledger(scratch)["opengrep.static-analysis"]

    assert status.startswith("FAILED:")
    assert outcome.state is ToolOutcomeState.FAILED
    assert outcome.schema_validated is False
    assert outcome.finding_count is None


def test_scanner_failure_removes_stale_outputs_and_records_containment_debt(
    tmp_path: Path,
    monkeypatch,
) -> None:
    scratch = tmp_path / "scratch"
    project = tmp_path / "project"
    source = project / "src" / "c.sol"
    rules = tmp_path / "rules"
    (rules / "solidity").mkdir(parents=True)
    source.parent.mkdir(parents=True)
    scratch.mkdir()
    source.write_text("contract C {}", encoding="utf-8")
    (scratch / "opengrep_results.sarif").write_text(
        json.dumps(_EMPTY_SARIF), encoding="utf-8",
    )
    (scratch / "opengrep_findings.md").write_text(
        "stale success", encoding="utf-8",
    )

    monkeypatch.setattr(RP.shutil, "which", lambda _name: "/tool/opengrep")
    monkeypatch.setattr(
        RP,
        "_ensure_opengrep_rules",
        lambda: {"opengrep-rules": rules, "decurity-rules": rules},
    )
    monkeypatch.setattr(
        RP, "_production_source_files", lambda _project, _exts: [source],
    )
    monkeypatch.setattr(
        RP,
        "_run_hardened",
        lambda *_args, **_kwargs: (
            1,
            "hardened: contained execution failed: "
            "WINDOWS_LOW_INTEGRITY_LEASE_FAILED",
        ),
    )

    status = RP._run_opengrep_scan(
        scratch,
        project,
        "evm",
        context=_context(project, ecosystem="evm", pipeline="sc"),
    )
    outcome = load_tool_coverage_ledger(scratch)["opengrep.static-analysis"]

    assert status.startswith("FAILED:exit 1:")
    assert "WINDOWS_LOW_INTEGRITY_LEASE_FAILED" in outcome.reason
    assert not (scratch / "opengrep_results.sarif").exists()
    assert not (scratch / "opengrep_findings.md").exists()
    assert list(scratch.glob(".og-*")) == []


def test_unpinned_sec3_is_unavailable_without_docker_execution(
    tmp_path: Path,
    monkeypatch,
) -> None:
    scratch = tmp_path / "scratch"
    project = tmp_path / "project"
    scratch.mkdir()
    project.mkdir()
    monkeypatch.setattr(
        RP,
        "_run_hardened",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("docker must not execute without a governed digest")
        ),
    )

    status = RP._run_sec3_xray(scratch, project)
    outcome = load_tool_coverage_ledger(scratch)[
        "sec3-xray.solana-static-analysis"
    ]

    assert status.startswith("SKIPPED:")
    assert outcome.state is ToolOutcomeState.UNAVAILABLE
    assert "digest" in outcome.reason


def test_mixed_dependency_capabilities_fail_independently(
    tmp_path: Path,
    monkeypatch,
) -> None:
    scratch = tmp_path / "scratch"
    project = tmp_path / "project"
    scratch.mkdir()
    project.mkdir()
    (project / "go.mod").write_text("module example.invalid/x\n", encoding="utf-8")
    (project / "Cargo.toml").write_text("[workspace]\n", encoding="utf-8")

    monkeypatch.setattr(
        RP,
        "_govulncheck_scan",
        lambda _project: (_ for _ in ()).throw(RuntimeError("go broke")),
    )
    monkeypatch.setattr(
        RP,
        "_cargo_audit_scan",
        lambda _project: (
            "WRITTEN",
            [{
                "id": "RUSTSEC-test",
                "package": "p",
                "version": "1",
                "severity": "",
                "patched": "",
                "title": "retained",
            }],
        ),
    )
    advisory = json.dumps(
        {
            "schema_version": "plamen.advisory_source.v1",
            "source_id": "rustsec-local",
            "provider": "RustSec Advisory Database",
            "content_sha256": "2" * 64,
            "as_of": "2026-01-01T00:00:00Z",
            "expires_at": "2026-12-31T00:00:00Z",
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    monkeypatch.setattr(
        RP,
        "_resolve_advisory_source",
        lambda source_id: (
            tmp_path / "advisory",
            advisory if source_id == "rustsec-local" else "",
            "" if source_id == "rustsec-local" else "fixture unavailable",
        ),
    )

    status = RP._run_dependency_audit_l1(
        scratch,
        project,
        "mixed",
        context=_context(
            project, ecosystem="mixed", pipeline="l1"
        ),
    )
    ledger = load_tool_coverage_ledger(scratch)
    report = (scratch / "dependency_audit_findings.md").read_text(
        encoding="utf-8",
    )

    assert "go=FAILED:" in status
    assert "rust=WRITTEN:1" in status
    assert ledger["govulncheck.dependency-audit"].state is ToolOutcomeState.FAILED
    assert ledger["cargo-audit.dependency-audit"].state is ToolOutcomeState.SUCCEEDED
    assert "RUSTSEC-test" in report
