"""Regression coverage for recon build write-authority isolation."""

from __future__ import annotations

import os
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

import isolated_execution_host
import recon_prepass as recon
import owned_process_runner


def test_hardened_runner_uses_disposable_isolated_executor() -> None:
    expected = (
        owned_process_runner.run_owned_process_isolated
        if os.name == "nt"
        else owned_process_runner.run_owned_process
    )
    assert (
        recon.run_owned_process
        is expected
    )


def test_hardened_cwd_is_not_implicit_write_authority(
    tmp_path: Path, monkeypatch
) -> None:
    cwd = tmp_path / "source"
    output = tmp_path / "output"
    cwd.mkdir()
    output.mkdir()
    calls: list[dict] = []

    def fake_run_owned_process(*_args, **kwargs):
        calls.append(kwargs)
        return SimpleNamespace(returncode=0, stdout="ok", stderr="")

    monkeypatch.setattr(recon, "run_owned_process", fake_run_owned_process)

    assert recon._run_hardened(["probe"], cwd=cwd) == (0, "ok")
    assert calls[-1]["writable_roots"] == ()

    assert recon._run_hardened(
        ["probe"], cwd=cwd, writable_roots=(output,)
    ) == (0, "ok")
    assert calls[-1]["writable_roots"] == (output.resolve(),)
    assert cwd.resolve() not in calls[-1]["writable_roots"]


def test_hardened_runner_types_isolated_authority_debt(
    monkeypatch,
) -> None:
    def failed_authority(*_args, **_kwargs):
        raise owned_process_runner.OwnedProcessRunnerError(
            "isolated owned-process debt: EXECUTOR_RECEIPT_BINDING_INVALID"
        )

    monkeypatch.setattr(recon, "run_owned_process", failed_authority)
    rc, output = recon._run_hardened(["probe"])
    assert rc == recon._TOOL_EXECUTION_AUTHORITY_DEBT_RC
    assert "TOOL_EXECUTION_AUTHORITY_DEBT" in output
    assert "EXECUTOR_RECEIPT_BINDING_INVALID" in output


@pytest.mark.skipif(os.name != "nt", reason="Windows disposable executor")
def test_executor_startup_failure_is_typed_debt_and_clears_active_latch(
    monkeypatch,
) -> None:
    def startup_failure():
        raise RuntimeError("fixture startup closure failure")

    monkeypatch.setattr(
        isolated_execution_host,
        "_windows_cpython_executor_paths",
        startup_failure,
    )
    rc, output = recon._run_hardened(
        [sys.executable, "-I", "-S", "-c", "print('not-launched')"],
        timeout=5,
    )
    assert rc == recon._TOOL_EXECUTION_AUTHORITY_DEBT_RC
    assert "EXECUTOR_LAUNCH_FAILED" in output
    assert isolated_execution_host._ACTIVE_EXECUTOR_REQUEST_ID is None
    assert isolated_execution_host._AMBIGUOUS_EXECUTOR_LATCH is False


def test_forge_build_routes_every_product_to_disposable_root(
    tmp_path: Path, monkeypatch
) -> None:
    project = tmp_path / "project"
    scratch = tmp_path / "scratch"
    contract = project / "contracts" / "Vault.sol"
    contract.parent.mkdir(parents=True)
    scratch.mkdir()
    (project / "foundry.toml").write_text(
        "[profile.default]\nsolc = '0.8.20'\n", encoding="utf-8"
    )
    contract.write_text(
        "// SPDX-License-Identifier: MIT\npragma solidity 0.8.20;\n"
        "contract Vault {}\n",
        encoding="utf-8",
    )
    calls: list[tuple[list[str], Path, dict]] = []

    monkeypatch.setattr(
        recon.shutil,
        "which",
        lambda name: "C:/tools/forge.exe" if name == "forge" else None,
    )

    def fake_hardened(cmd, cwd=None, timeout=120, env=None, **kwargs):
        calls.append((list(cmd), Path(cwd), dict(kwargs)))
        return 0, "Compiler run successful"

    monkeypatch.setattr(recon, "_run_hardened", fake_hardened)

    assert recon._write_build_status(scratch, project, "evm") == "WRITTEN"
    assert len(calls) == 1
    command, cwd, kwargs = calls[0]
    disposable = scratch / ".fb"
    assert cwd == project
    assert kwargs["writable_roots"] == (disposable,)
    assert project not in kwargs["writable_roots"]
    assert command[command.index("--out") + 1] == str(disposable / "out")
    assert command[command.index("--cache-path") + 1] == str(
        disposable / "cache"
    )
    assert "--build-info" in command
    assert command[command.index("--build-info-path") + 1] == str(
        disposable / "build-info"
    )


def test_forge_authority_debt_is_not_retried_or_reported_as_tool_failure(
    tmp_path: Path, monkeypatch
) -> None:
    project = tmp_path / "project"
    scratch = tmp_path / "scratch"
    contract = project / "contracts" / "Vault.sol"
    contract.parent.mkdir(parents=True)
    scratch.mkdir()
    (project / "foundry.toml").write_text(
        "[profile.default]\nsolc = '0.8.20'\n", encoding="utf-8"
    )
    contract.write_text(
        "// SPDX-License-Identifier: MIT\npragma solidity 0.8.20;\n"
        "contract Vault {}\n",
        encoding="utf-8",
    )
    calls: list[list[str]] = []
    monkeypatch.setattr(
        recon.shutil,
        "which",
        lambda name: "C:/tools/forge.exe" if name == "forge" else None,
    )

    def authority_debt(cmd, *_args, **_kwargs):
        calls.append(list(cmd))
        return (
            recon._TOOL_EXECUTION_AUTHORITY_DEBT_RC,
            "hardened: TOOL_EXECUTION_AUTHORITY_DEBT: "
            "EXECUTOR_RECEIPT_BINDING_INVALID",
        )

    monkeypatch.setattr(recon, "_run_hardened", authority_debt)
    assert recon._write_build_status(scratch, project, "evm") == "WRITTEN"
    assert len(calls) == 1
    status = (scratch / "build_status.md").read_text(encoding="utf-8")
    assert "**Status**: DEGRADED_AUTHORITY_DEBT" in status
    assert "**Exit Code**: N/A (tool completion authority unavailable)" in status
    assert "TOOL_EXECUTION_AUTHORITY_DEBT" in status
    assert "**Status**: FAILED" not in status


def test_real_tool_exit_125_is_not_confused_with_authority_debt(
    tmp_path: Path, monkeypatch
) -> None:
    project = tmp_path / "project"
    scratch = tmp_path / "scratch"
    contract = project / "contracts" / "Vault.sol"
    contract.parent.mkdir(parents=True)
    scratch.mkdir()
    (project / "foundry.toml").write_text(
        "[profile.default]\nsolc = '0.8.20'\n", encoding="utf-8"
    )
    contract.write_text(
        "pragma solidity 0.8.20; contract Vault {}\n", encoding="utf-8"
    )
    outcomes = iter(((125, "tool exit 125"), (125, "tool exit 125 again")))
    calls = 0
    monkeypatch.setattr(
        recon.shutil,
        "which",
        lambda name: "C:/tools/forge.exe" if name == "forge" else None,
    )

    def real_exit(*_args, **_kwargs):
        nonlocal calls
        calls += 1
        return next(outcomes)

    monkeypatch.setattr(recon, "_run_hardened", real_exit)
    assert recon._write_build_status(scratch, project, "evm") == "WRITTEN"
    assert calls == 2
    status = (scratch / "build_status.md").read_text(encoding="utf-8")
    assert "**Exit Code**: 125" in status
    assert "**Status**: FAILED" in status
    assert "DEGRADED_AUTHORITY_DEBT" not in status
