"""Fixture-first reds for the cross-OS/toolchain adversarial review.

These fixtures deliberately describe behavior that production does not yet
provide.  Keep them isolated until each corresponding implementation change
turns the fixture red -> green.
"""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest

import recon_prepass as RECON
import security_obligation_authority as SECURITY_AUTHORITY
import supply_chain_gate as SUPPLY


_SEC3_IMAGE = "ghcr.io/example/sec3@sha256:" + ("a" * 64)


def _empty_sarif(driver_name: str) -> str:
    return json.dumps(
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": driver_name}},
                    "invocations": [{"executionSuccessful": True}],
                    "results": [],
                }
            ],
        }
    )


def test_opengrep_abnormal_exit_with_valid_empty_sarif_is_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scratch = tmp_path / "scratch"
    project = tmp_path / "project"
    rules = tmp_path / "rules"
    source = project / "sources" / "module.move"
    scratch.mkdir()
    source.parent.mkdir(parents=True)
    source.write_text("module 0x1::module {}", encoding="utf-8")
    (rules / "rules").mkdir(parents=True)

    monkeypatch.setattr(
        RECON.shutil,
        "which",
        lambda name: f"/trusted/{name}" if name == "opengrep" else None,
    )
    monkeypatch.setattr(
        RECON,
        "_ensure_opengrep_rules",
        lambda: {"aptos-move-rules": rules},
    )
    monkeypatch.setattr(
        RECON,
        "_production_source_files",
        lambda _project, _extensions: [source],
    )

    def abnormal_scan(_command, _cwd, _timeout, **_kwargs):
        (scratch / "opengrep_results.sarif").write_text(
            _empty_sarif("OpenGrep"),
            encoding="utf-8",
        )
        return 2, "fatal scanner error"

    monkeypatch.setattr(RECON, "_run_hardened", abnormal_scan)

    status = RECON._run_opengrep_scan(scratch, project, "aptos")

    assert status.startswith("FAILED:"), status


def test_sec3_abnormal_exit_with_valid_empty_sarif_is_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scratch = tmp_path / "scratch"
    project = tmp_path / "project"
    source = project / "src" / "lib.rs"
    scratch.mkdir()
    source.parent.mkdir(parents=True)
    source.write_text("pub fn f() {}", encoding="utf-8")

    monkeypatch.setattr(
        RECON.shutil,
        "which",
        lambda name: "/trusted/docker" if name == "docker" else None,
    )

    def abnormal_scan(command, _cwd, _timeout):
        if command[:2] == ["docker", "info"]:
            return 0, "daemon available"
        output = scratch / ".sec3-output"
        output.mkdir(parents=True, exist_ok=True)
        (output / RECON._SEC3_SARIF_FILENAME).write_text(
            _empty_sarif("Sec3 X-Ray"),
            encoding="utf-8",
        )
        return 2, "fatal scanner error"

    monkeypatch.setattr(RECON, "_run_hardened", abnormal_scan)

    status = RECON._run_sec3_xray(
        scratch,
        project,
        image_ref=_SEC3_IMAGE,
    )

    assert status.startswith("FAILED:"), status


def test_target_checkout_scanner_is_not_executable_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A scanner resolved from the untrusted target must never be executed."""

    (tmp_path / "package-lock.json").write_text(
        '{"lockfileVersion":3,"packages":{}}\n',
        encoding="utf-8",
    )
    target_scanner = tmp_path / "osv-scanner.exe"
    target_scanner.write_bytes(b"target-controlled executable")

    monkeypatch.setattr(
        SUPPLY.shutil,
        "which",
        lambda name: str(target_scanner) if name == "osv-scanner" else None,
    )
    invoked: list[str] = []

    def would_false_clean(binary: str, _lockfile: Path):
        invoked.append(binary)
        return SUPPLY.OfflineScanResult(
            SUPPLY.OfflineScanState.SUCCEEDED,
            output='{"results":[]}',
            returncode=0,
        )

    monkeypatch.setattr(SUPPLY, "_call_offline_scanner", would_false_clean)

    with pytest.raises(SUPPLY.SupplyChainAbortError):
        SUPPLY.gate_supply_chain(tmp_path, denylist=[])
    assert invoked == []


def test_lockfile_enumeration_error_is_not_silently_ignored(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`os.walk` ignores scandir errors unless an onerror callback is supplied."""

    def walk_with_hidden_error(_root, *args, **kwargs):
        onerror = kwargs.get("onerror")
        if onerror is not None:
            onerror(PermissionError("synthetic unreadable subtree"))
        return iter(())

    monkeypatch.setattr(SUPPLY.os, "walk", walk_with_hidden_error)

    with pytest.raises(SUPPLY.SupplyChainAbortError):
        SUPPLY._find_lockfiles(tmp_path)


@pytest.mark.skipif(
    os.path.normcase("PACKAGE-LOCK.JSON")
    != os.path.normcase("package-lock.json"),
    reason="case variants are distinct files on this host",
)
def test_case_insensitive_host_cannot_hide_lockfile_with_case_variant(
    tmp_path: Path,
) -> None:
    lockfile = tmp_path / "PACKAGE-LOCK.JSON"
    lockfile.write_text(
        '{"lockfileVersion":3,"packages":{}}\n',
        encoding="utf-8",
    )

    assert SUPPLY._find_lockfiles(tmp_path) == [lockfile]


def test_reparse_directory_is_rejected_without_path_is_junction_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Python 3.11 lacks Path.is_junction; reparse metadata must still win."""

    junction = tmp_path / "junction"
    junction.mkdir()
    original_lstat = SUPPLY.os.lstat
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)

    class ReparseStat:
        def __init__(self, wrapped):
            self._wrapped = wrapped
            self.st_file_attributes = (
                getattr(wrapped, "st_file_attributes", 0) | reparse_flag
            )
            self.st_reparse_tag = 0xA0000003

        def __getattr__(self, name):
            return getattr(self._wrapped, name)

    def synthetic_lstat(path, *args, **kwargs):
        observed = original_lstat(path, *args, **kwargs)
        if Path(path).name == junction.name:
            return ReparseStat(observed)
        return observed

    monkeypatch.setattr(SUPPLY.os, "lstat", synthetic_lstat)
    if hasattr(Path, "is_junction"):
        monkeypatch.setattr(Path, "is_junction", lambda _self: False)

    with pytest.raises(SUPPLY.SupplyChainAbortError):
        SUPPLY._find_lockfiles(tmp_path)


def test_positive_dependency_artifact_is_in_security_obligation_denominator(
    tmp_path: Path,
) -> None:
    """Minimum reachability: a detector hit must enter downstream authority."""

    artifact = tmp_path / "dependency_audit_findings.md"
    artifact.write_text(
        "# Dependency Audit Findings\n\n"
        "## Go (govulncheck)\n\n"
        "| ID | Package | Function | Evidence |\n"
        "|---|---|---|---|\n"
        "| GO-TEST-0001 | example.invalid/module | vulnerable.Call | "
        "`src/main.go:L12` |\n",
        encoding="utf-8",
    )

    inputs = SECURITY_AUTHORITY.security_obligation_input_artifacts(tmp_path)

    assert artifact.name in inputs
