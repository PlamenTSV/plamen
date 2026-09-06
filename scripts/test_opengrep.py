"""Tests for P2: OpenGrep cross-ecosystem scanner integration.

Tests skip/fail paths, SARIF parsing, and prepass wiring.
"""
from __future__ import annotations

import json
import hashlib
import os
import subprocess
import sys
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from recon_prepass import (
    _run_opengrep_scan,
    _parse_opengrep_sarif,
    _ensure_opengrep_rules,
    _write_build_status,
    run_recon_prepass,
    _write_text,
)

# ── helpers ──────────────────────────────────────────────────────────────

def _mkscratch(tmp_path: Path) -> Path:
    s = tmp_path / ".scratchpad"
    s.mkdir()
    return s


def _mkproj(tmp_path: Path, *, lang: str = "evm") -> Path:
    p = tmp_path / "project"
    p.mkdir()
    ext = {"evm": ".sol", "solana": ".rs", "soroban": ".rs", "aptos": ".move", "sui": ".move"}
    src = p / "src"
    src.mkdir()
    (src / f"Contract{ext.get(lang, '.sol')}").write_text("// source", encoding="utf-8")
    return p


def _context(project: Path, ecosystem: str) -> dict[str, str]:
    identity = os.path.normcase(str(project.resolve())).replace("\\", "/")
    return {
        "run_id": "opengrep-fixture",
        "phase": "recon-prebreadth",
        "snapshot_sha256": "1" * 64,
        "project_root_sha256": hashlib.sha256(
            identity.encode("utf-8")
        ).hexdigest(),
        "ecosystem": ecosystem,
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


_SAMPLE_SARIF = {
    "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    "version": "2.1.0",
    "runs": [{
        "tool": {"driver": {"name": "opengrep", "version": "1.16.4"}},
        "results": [
            {
                "ruleId": "solidity.security.reentrancy",
                "level": "error",
                "message": {"text": "Potential reentrancy in external call"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": "src/Vault.sol"},
                        "region": {"startLine": 42, "startColumn": 5},
                    }
                }],
            },
            {
                "ruleId": "solidity.security.unchecked-return",
                "level": "warning",
                "message": {"text": "Unchecked return value from transfer"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": "src/Token.sol"},
                        "region": {"startLine": 88, "startColumn": 9},
                    }
                }],
            },
        ],
    }],
}


def _fake_popen_factory(*, sarif=None, returncode=0, timeout=False, seen=None):
    def _factory(cmd, **kwargs):
        if seen is not None:
            seen.append(cmd)
        if sarif is not None:
            for i, arg in enumerate(cmd):
                if arg == "--sarif-output" and i + 1 < len(cmd):
                    Path(cmd[i + 1]).write_text(json.dumps(sarif), encoding="utf-8")
                    break
        proc = mock.Mock()
        proc.pid = 12345
        proc.returncode = returncode
        if timeout:
            proc.communicate.side_effect = [
                subprocess.TimeoutExpired("opengrep", 300),
                ("", ""),
            ]
        else:
            proc.communicate.return_value = ("", "")
        return proc
    return _factory


def _fake_hardened_factory(*, sarif=None, returncode=0, timeout=False, seen=None):
    def _runner(cmd, *args, **kwargs):
        if seen is not None:
            seen.append(cmd)
        if sarif is not None:
            for i, arg in enumerate(cmd):
                if arg == "--sarif-output" and i + 1 < len(cmd):
                    Path(cmd[i + 1]).write_text(
                        json.dumps(sarif), encoding="utf-8"
                    )
                    break
        if timeout:
            return 124, "fixture timeout"
        return returncode, ""
    return _runner


# ── _run_opengrep_scan: skip/fail paths ─────────────────────────────────

def test_build_status_forge_uses_bounded_production_compile(tmp_path):
    """Recon forge prepass compiles explicit production sources with one worker."""
    scratch = _mkscratch(tmp_path)
    proj = _mkproj(tmp_path)
    (proj / "foundry.toml").write_text("[profile.default]\n", encoding="utf-8")
    for rel in ("test/Vault.t.sol", "fuzz/VaultFuzz.sol", "src/MockToken.sol"):
        path = proj / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("// excluded", encoding="utf-8")

    seen = []

    def fake_hardened(cmd, *args, **kwargs):
        seen.append(cmd)
        return (0, "")

    with mock.patch("shutil.which", side_effect=lambda name: "/usr/bin/forge" if name == "forge" else None), \
         mock.patch("recon_prepass._run_hardened", side_effect=fake_hardened):
        result = _write_build_status(scratch, proj, "evm")

    assert result == "WRITTEN"
    cmd = seen[0]
    assert cmd[:2] == ["forge", "build"]
    assert "src/Contract.sol" in cmd
    assert "--threads" in cmd
    assert "1" in cmd
    assert all("test/" not in arg and "fuzz/" not in arg and "MockToken.sol" not in arg for arg in cmd)


def test_scan_skip_no_opengrep(tmp_path):
    """No opengrep binary -> SKIPPED."""
    scratch = _mkscratch(tmp_path)
    proj = _mkproj(tmp_path)
    with mock.patch("shutil.which", return_value=None):
        result = _run_opengrep_scan(
            scratch, proj, "evm", context=_context(proj, "evm")
        )
    assert result.startswith("SKIPPED:")
    assert "opengrep" in result


def test_scan_skip_no_rules_for_lang(tmp_path):
    """Language with no rules -> SKIPPED."""
    scratch = _mkscratch(tmp_path)
    proj = _mkproj(tmp_path, lang="sui")
    with mock.patch("shutil.which", return_value="/usr/bin/opengrep"):
        result = _run_opengrep_scan(
            scratch, proj, "sui", context=_context(proj, "sui")
        )
    assert result.startswith("SKIPPED:")
    assert "no OpenGrep rules" in result


def test_scan_skip_no_source_files(tmp_path):
    """No relevant source files -> SKIPPED."""
    scratch = _mkscratch(tmp_path)
    proj = tmp_path / "empty_proj"
    proj.mkdir()
    (proj / "README.md").write_text("hello", encoding="utf-8")

    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "solidity").mkdir()
    (rules_dir / "solidity" / "test.yaml").write_text("rules: []", encoding="utf-8")

    with mock.patch("shutil.which", return_value="/usr/bin/opengrep"), \
         mock.patch("recon_prepass._ensure_opengrep_rules",
                    return_value={"opengrep-rules": rules_dir, "decurity-rules": rules_dir}):
        result = _run_opengrep_scan(
            scratch, proj, "evm", context=_context(proj, "evm")
        )
    assert result.startswith("SKIPPED:")
    assert ".sol" in result


def test_scan_targets_only_production_source_files(tmp_path):
    """OpenGrep receives explicit production files, not the whole project tree."""
    scratch = _mkscratch(tmp_path)
    proj = _mkproj(tmp_path)
    for rel in ("test/Vault.t.sol", "fuzz/VaultFuzz.sol", ".medusa-tests/Medusa.sol"):
        path = proj / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("// excluded", encoding="utf-8")

    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    sol_dir = rules_dir / "solidity"
    sol_dir.mkdir()
    (sol_dir / "test.yaml").write_text("rules: []", encoding="utf-8")
    sec_dir = rules_dir / "solidity" / "security"
    sec_dir.mkdir()
    (sec_dir / "test.yaml").write_text("rules: []", encoding="utf-8")

    seen = []
    with mock.patch("shutil.which", return_value="/usr/bin/opengrep"), \
         mock.patch("recon_prepass._ensure_opengrep_rules",
                    return_value={"opengrep-rules": rules_dir, "decurity-rules": rules_dir}), \
             mock.patch(
                 "recon_prepass._run_hardened",
                 side_effect=_fake_hardened_factory(
                     sarif=_SAMPLE_SARIF, seen=seen
                 ),
             ):
        result = _run_opengrep_scan(
            scratch, proj, "evm", context=_context(proj, "evm")
        )

    assert result == "WRITTEN:2 findings"
    cmd = seen[0]
    assert str(proj) not in cmd
    assert "src/Contract.sol" in cmd
    assert all("test/" not in arg and "fuzz/" not in arg and ".medusa-tests" not in arg for arg in cmd)


def test_scan_fail_timeout(tmp_path):
    """Scan times out -> FAILED."""
    scratch = _mkscratch(tmp_path)
    proj = _mkproj(tmp_path)

    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    sol_dir = rules_dir / "solidity"
    sol_dir.mkdir()
    (sol_dir / "test.yaml").write_text("rules: []", encoding="utf-8")
    sec_dir = rules_dir / "solidity" / "security"
    sec_dir.mkdir()
    (sec_dir / "test.yaml").write_text("rules: []", encoding="utf-8")

    # _run_hardened returns the 124 sentinel on a tree-killed timeout.
    with mock.patch("shutil.which", return_value="/usr/bin/opengrep"), \
         mock.patch("recon_prepass._ensure_opengrep_rules",
                    return_value={"opengrep-rules": rules_dir, "decurity-rules": rules_dir}), \
         mock.patch("recon_prepass._run_hardened",
                    return_value=(124, "[hardened: timed out after 300s, tree-killed]")):
        result = _run_opengrep_scan(
            scratch, proj, "evm", context=_context(proj, "evm")
        )
    assert result.startswith("FAILED:")
    assert "timeout" in result


def test_scan_fail_nonzero_no_sarif(tmp_path):
    """Opengrep exits nonzero and no SARIF -> FAILED."""
    scratch = _mkscratch(tmp_path)
    proj = _mkproj(tmp_path)

    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    sol_dir = rules_dir / "solidity"
    sol_dir.mkdir()
    (sol_dir / "test.yaml").write_text("rules: []", encoding="utf-8")
    sec_dir = rules_dir / "solidity" / "security"
    sec_dir.mkdir()
    (sec_dir / "test.yaml").write_text("rules: []", encoding="utf-8")

    with mock.patch("shutil.which", return_value="/usr/bin/opengrep"), \
         mock.patch("recon_prepass._ensure_opengrep_rules",
                    return_value={"opengrep-rules": rules_dir, "decurity-rules": rules_dir}), \
             mock.patch(
                 "recon_prepass._run_hardened",
                 side_effect=_fake_hardened_factory(returncode=2),
             ):
        result = _run_opengrep_scan(
            scratch, proj, "evm", context=_context(proj, "evm")
        )
    assert "FAILED:" in result or "WRITTEN:0" in result


# ── _parse_opengrep_sarif ────────────────────────────────────────────────

def test_parse_sarif_valid(tmp_path):
    """Valid SARIF produces correct finding count and summary."""
    scratch = _mkscratch(tmp_path)
    sarif_path = scratch / "opengrep_results.sarif"
    sarif_path.write_text(json.dumps(_SAMPLE_SARIF), encoding="utf-8")

    count = _parse_opengrep_sarif(scratch, sarif_path)
    assert count == 2

    summary = (scratch / "opengrep_findings.md").read_text(encoding="utf-8")
    assert "reentrancy" in summary
    assert "unchecked-return" in summary
    assert "src/Vault.sol:L42" in summary
    assert "src/Token.sol:L88" in summary
    assert "Total**: 2" in summary


def test_parse_sarif_empty(tmp_path):
    """Empty results list -> 0 findings."""
    scratch = _mkscratch(tmp_path)
    empty_sarif = {
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "opengrep"}}, "results": []}],
    }
    sarif_path = scratch / "opengrep_results.sarif"
    sarif_path.write_text(json.dumps(empty_sarif), encoding="utf-8")

    count = _parse_opengrep_sarif(scratch, sarif_path)
    assert count == 0

    summary = (scratch / "opengrep_findings.md").read_text(encoding="utf-8")
    assert "Total**: 0" in summary


def test_parse_sarif_invalid_json(tmp_path):
    """Invalid JSON -> 0 findings + error note."""
    scratch = _mkscratch(tmp_path)
    sarif_path = scratch / "opengrep_results.sarif"
    sarif_path.write_text("not json {{{", encoding="utf-8")

    count = _parse_opengrep_sarif(scratch, sarif_path)
    assert count == 0

    summary = (scratch / "opengrep_findings.md").read_text(encoding="utf-8")
    assert "parse failed" in summary


def test_parse_sarif_pipe_in_message(tmp_path):
    """Pipe characters in messages are escaped for table rendering."""
    scratch = _mkscratch(tmp_path)
    sarif_with_pipe = {
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "opengrep"}},
            "results": [{
                "ruleId": "test.rule",
                "level": "warning",
                "message": {"text": "found A | B in expression"},
                "locations": [],
            }],
        }],
    }
    sarif_path = scratch / "opengrep_results.sarif"
    sarif_path.write_text(json.dumps(sarif_with_pipe), encoding="utf-8")

    count = _parse_opengrep_sarif(scratch, sarif_path)
    assert count == 1
    summary = (scratch / "opengrep_findings.md").read_text(encoding="utf-8")
    assert "\\|" in summary


# ── _ensure_opengrep_rules ──────────────────────────────────────────────

def test_opengrep_rules_follow_selected_runtime_not_hostile_home(
    tmp_path: Path,
) -> None:
    staged = tmp_path / "selected-runtime"
    staged.mkdir()
    ambient = tmp_path / "ambient-home"
    (ambient / ".plamen" / "opengrep-rules").mkdir(parents=True)
    environment = {
        **os.environ,
        "PLAMEN_HOME": str(staged),
        "HOME": str(ambient),
        "USERPROFILE": str(ambient),
        "PYTHONPATH": str(Path(__file__).resolve().parent),
    }
    script_dir = str(Path(__file__).resolve().parent)
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            "-c",
            (
                f"import sys; sys.path.insert(0, {script_dir!r}); "
                "import recon_prepass; "
                "print(recon_prepass._opengrep_rules_base())"
            ),
        ],
        cwd=tmp_path,
        env=environment,
        check=True,
        text=True,
        capture_output=True,
    )
    assert Path(result.stdout.strip()) == staged / "opengrep-rules"


def test_ensure_rules_skip_if_present(tmp_path):
    """Release-pinned, pre-populated rule submodules are accepted read-only."""
    with mock.patch("recon_prepass._OPENGREP_RULES_BASE", tmp_path):
        for name in ("opengrep-rules", "decurity-rules", "aptos-move-rules"):
            d = tmp_path / name
            d.mkdir()
            (d / ".git").mkdir()
            (d / "rules.yaml").write_text("rules: []", encoding="utf-8")

        def revision_probe(cmd, *_args, **_kwargs):
            name = Path(cmd[2]).name
            return 0, __import__("recon_prepass")._OPENGREP_RULE_REVISIONS[name]

        with mock.patch(
            "recon_prepass._run_hardened", side_effect=revision_probe,
        ) as mock_run:
            result = _ensure_opengrep_rules()
        assert mock_run.call_count == 3
        assert "opengrep-rules" in result
        assert "decurity-rules" in result
        assert "aptos-move-rules" in result


def test_ensure_rules_reports_missing_without_runtime_materialization(tmp_path):
    """Missing rule submodules are coverage debt; audit-time repair is forbidden."""
    with mock.patch("recon_prepass._OPENGREP_RULES_BASE", tmp_path):
        with mock.patch("recon_prepass._run_hardened") as mock_run:
            result = _ensure_opengrep_rules()
        mock_run.assert_not_called()
        assert result == {}
        failures = __import__("recon_prepass")._OPENGREP_RULE_FAILURES
        assert set(failures) == {
            "opengrep-rules", "decurity-rules", "aptos-move-rules",
        }


# ── run_recon_prepass wiring ─────────────────────────────────────────────

def test_prepass_evm_skips_opengrep_by_default(tmp_path):
    """Startup pre-pass does not block on external OpenGrep scans by default."""
    scratch = _mkscratch(tmp_path)
    proj = _mkproj(tmp_path)
    config = {
        "scratchpad": str(scratch),
        "project_root": str(proj),
        "language": "evm",
        "pipeline": "sc",
        "_run_id": "opengrep-prepass-fixture",
        "_audit_snapshot": {"snapshot_digest": "1" * 64},
    }
    with mock.patch("recon_prepass._run_opengrep_scan", return_value="SKIPPED:test") as m:
        results = run_recon_prepass(config)
    m.assert_not_called()
    assert "opengrep_scan" not in results


def test_prepass_evm_triggers_opengrep_when_enabled(tmp_path):
    """Explicit startup scanner opt-in still triggers OpenGrep."""
    scratch = _mkscratch(tmp_path)
    proj = _mkproj(tmp_path)
    config = {
        "scratchpad": str(scratch),
        "project_root": str(proj),
        "language": "evm",
        "pipeline": "sc",
        "_run_id": "opengrep-prepass-fixture",
        "_audit_snapshot": {"snapshot_digest": "1" * 64},
        "prepass_external_scanners": True,
    }
    with mock.patch("recon_prepass._run_opengrep_scan", return_value="SKIPPED:test") as m:
        results = run_recon_prepass(config)
    m.assert_called_once_with(mock.ANY, proj, "evm", context=mock.ANY)
    assert Path(m.call_args.args[0]).parent == scratch
    assert results.get("opengrep_scan") == "SKIPPED:test"


def test_prepass_solana_triggers_opengrep_when_enabled(tmp_path):
    """SC Solana startup OpenGrep runs only with explicit opt-in."""
    scratch = _mkscratch(tmp_path)
    proj = _mkproj(tmp_path, lang="solana")
    config = {
        "scratchpad": str(scratch),
        "project_root": str(proj),
        "language": "solana",
        "pipeline": "sc",
        "_run_id": "opengrep-prepass-fixture",
        "_audit_snapshot": {"snapshot_digest": "1" * 64},
        "prepass_external_scanners": True,
    }
    with mock.patch("recon_prepass._run_opengrep_scan", return_value="SKIPPED:test") as m, \
         mock.patch("recon_prepass._bake_rust_scip", return_value="SKIPPED:test"):
        results = run_recon_prepass(config)
    m.assert_called_once_with(
        mock.ANY, proj, "solana", context=mock.ANY
    )
    assert Path(m.call_args.args[0]).parent == scratch


def test_prepass_l1_does_not_trigger_opengrep(tmp_path):
    """L1 pipeline does NOT trigger opengrep scan."""
    scratch = _mkscratch(tmp_path)
    proj = _mkproj(tmp_path)
    config = {
        "scratchpad": str(scratch),
        "project_root": str(proj),
        "language": "solana",
        "pipeline": "l1",
        "_run_id": "opengrep-prepass-fixture",
        "_audit_snapshot": {"snapshot_digest": "1" * 64},
    }
    with mock.patch("recon_prepass._run_opengrep_scan", return_value="SKIPPED:test") as m:
        results = run_recon_prepass(config)
    m.assert_not_called()


def test_prepass_opengrep_failure_does_not_crash(tmp_path):
    """Opt-in OpenGrep exception doesn't crash prepass."""
    scratch = _mkscratch(tmp_path)
    proj = _mkproj(tmp_path)
    config = {
        "scratchpad": str(scratch),
        "project_root": str(proj),
        "language": "evm",
        "pipeline": "sc",
        "_run_id": "opengrep-prepass-fixture",
        "_audit_snapshot": {"snapshot_digest": "1" * 64},
        "prepass_external_scanners": True,
    }
    with mock.patch("recon_prepass._run_opengrep_scan", side_effect=RuntimeError("boom")):
        results = run_recon_prepass(config)
    assert "FAILED:" in results.get("opengrep_scan", "")
    assert "contract_inventory.md" in results


# ── end-to-end with mock subprocess ──────────────────────────────────────

def test_scan_success_writes_sarif_and_summary(tmp_path):
    """Full success path: subprocess writes SARIF, parser writes summary."""
    scratch = _mkscratch(tmp_path)
    proj = _mkproj(tmp_path)

    # Pre-write build_status.md
    (scratch / "build_status.md").write_text("# Build Status\n\n**Status**: SUCCESS\n",
                                              encoding="utf-8")

    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    sol_dir = rules_dir / "solidity"
    sol_dir.mkdir()
    (sol_dir / "test.yaml").write_text("rules: []", encoding="utf-8")
    sec_dir = rules_dir / "solidity" / "security"
    sec_dir.mkdir()
    (sec_dir / "test.yaml").write_text("rules: []", encoding="utf-8")

    with mock.patch("shutil.which", return_value="/usr/bin/opengrep"), \
         mock.patch("recon_prepass._ensure_opengrep_rules",
                    return_value={"opengrep-rules": rules_dir, "decurity-rules": rules_dir}), \
             mock.patch(
                 "recon_prepass._run_hardened",
                 side_effect=_fake_hardened_factory(sarif=_SAMPLE_SARIF),
             ):
        result = _run_opengrep_scan(
            scratch, proj, "evm", context=_context(proj, "evm")
        )

    assert result == "WRITTEN:2 findings"
    assert (scratch / "opengrep_results.sarif").exists()
    assert (scratch / "opengrep_findings.md").exists()

    summary = (scratch / "opengrep_findings.md").read_text(encoding="utf-8")
    assert "reentrancy" in summary

    # Pre-breadth providers must not rewrite a committed canonical recon
    # sibling. OpenGrep has its own governed artifacts and outcome receipt.
    bs = (scratch / "build_status.md").read_text(encoding="utf-8")
    assert bs == "# Build Status\n\n**Status**: SUCCESS\n"
    assert "OPENGREP_AVAILABLE" not in bs
    assert "OPENGREP_FINDINGS" not in bs


# ── P5: Aptos Move rules via OpenGrep ───────────────────────────────────

def test_aptos_resolves_move_rules(tmp_path):
    """Aptos lang uses aptos-move-rules repo for OpenGrep scan."""
    scratch = _mkscratch(tmp_path)
    proj = _mkproj(tmp_path, lang="aptos")

    rules_base = tmp_path / "aptos_rules"
    rules_base.mkdir()
    move_rules = rules_base / "rules"
    move_rules.mkdir()
    (move_rules / "signer-leak.yaml").write_text("rules: []", encoding="utf-8")

    _MOVE_SARIF = {
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "opengrep"}}, "results": [{
            "ruleId": "signer-leak",
            "level": "error",
            "message": {"text": "Public function returning signer"},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": "src/module.move"},
                "region": {"startLine": 10},
            }}],
        }]}],
    }

    with mock.patch("shutil.which", return_value="/usr/bin/opengrep"), \
         mock.patch("recon_prepass._ensure_opengrep_rules",
                    return_value={"aptos-move-rules": rules_base}), \
             mock.patch(
                 "recon_prepass._run_hardened",
                 side_effect=_fake_hardened_factory(sarif=_MOVE_SARIF),
             ):
        result = _run_opengrep_scan(
            scratch, proj, "aptos", context=_context(proj, "aptos")
        )

    assert result == "WRITTEN:1 findings"
    summary = (scratch / "opengrep_findings.md").read_text(encoding="utf-8")
    assert "signer-leak" in summary
    assert "src/module.move:L10" in summary


def test_sui_still_skipped_no_rules(tmp_path):
    """Sui lang has no rules -> SKIPPED even with opengrep available."""
    scratch = _mkscratch(tmp_path)
    proj = _mkproj(tmp_path, lang="sui")
    with mock.patch("shutil.which", return_value="/usr/bin/opengrep"):
        result = _run_opengrep_scan(
            scratch, proj, "sui", context=_context(proj, "sui")
        )
    assert result.startswith("SKIPPED:")


def test_prepass_aptos_triggers_opengrep_when_enabled(tmp_path):
    """SC Aptos startup OpenGrep runs only with explicit opt-in."""
    scratch = _mkscratch(tmp_path)
    proj = _mkproj(tmp_path, lang="aptos")
    config = {
        "scratchpad": str(scratch),
        "project_root": str(proj),
        "language": "aptos",
        "pipeline": "sc",
        "_run_id": "opengrep-prepass-fixture",
        "_audit_snapshot": {"snapshot_digest": "1" * 64},
        "prepass_external_scanners": True,
    }
    with mock.patch("recon_prepass._run_opengrep_scan", return_value="SKIPPED:test") as m:
        results = run_recon_prepass(config)
    m.assert_called_once_with(
        mock.ANY, proj, "aptos", context=mock.ANY
    )
    assert Path(m.call_args.args[0]).parent == scratch
    assert results.get("opengrep_scan") == "SKIPPED:test"
