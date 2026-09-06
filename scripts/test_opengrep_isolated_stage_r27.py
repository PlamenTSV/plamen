"""Regressions for the r27 OpenGrep containment-lease failure."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

import isolated_execution_host as H
import owned_process_runner as O
import recon_prepass as RP


def _python(code: str) -> tuple[str, ...]:
    return (sys.executable, "-I", "-S", "-c", code)


def test_lease_setup_and_child_share_one_timeout_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    waits: list[float] = []

    class FakeProcess:
        def wait(self, *, timeout: float) -> int:
            waits.append(timeout)
            return 0

    class FakeScope:
        attached = False
        terminated = False
        write_confinement_proven = True

        def __init__(self, **_kwargs: object) -> None:
            pass

        def wrap_argv(self, argv: tuple[str, ...]) -> tuple[str, ...]:
            return argv

        def popen_kwargs(self) -> dict[str, object]:
            return {}

        def create_process(self, *_args: object, **_kwargs: object) -> FakeProcess:
            return FakeProcess()

        def attach(self, _process: FakeProcess) -> None:
            self.attached = True

        def terminate_created_process(self) -> None:
            raise AssertionError("successful fixture must not pre-terminate")

        def terminate(self) -> None:
            self.terminated = True

        def close(self) -> None:
            pass

    ticks = iter((100.0, 101.0, 102.0, 102.5, 103.0))
    monkeypatch.setattr(O.time, "monotonic", lambda: next(ticks))
    monkeypatch.setattr(O, "OwnedProcessScope", FakeScope)
    monkeypatch.setattr(
        O,
        "process_tree_termination_capability",
        lambda: {
            "platform": "FIXTURE",
            "pre_execution_assignment": True,
            "exhaustive_descendant_termination_authority": True,
            "exhaustive_write_confinement_authority": True,
        },
    )

    result = O.run_owned_process(
        [sys.executable, "-c", "pass"], timeout=5,
    )

    assert waits == [pytest.approx(2.5)]
    assert result.duration_s == pytest.approx(3.0)
    assert result.process_tree_terminated is True


def test_expired_lease_budget_never_creates_child(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []

    class FakeScope:
        attached = False

        def __init__(self, **_kwargs: object) -> None:
            events.append("scope")

        def create_process(self, *_args: object, **_kwargs: object) -> object:
            events.append("create")
            raise AssertionError("expired budget must not create a process")

        def close(self) -> None:
            events.append("close")

    ticks = iter((100.0, 106.0))
    monkeypatch.setattr(O.time, "monotonic", lambda: next(ticks))
    monkeypatch.setattr(O, "OwnedProcessScope", FakeScope)
    monkeypatch.setattr(
        O,
        "process_tree_termination_capability",
        lambda: {
            "platform": "FIXTURE",
            "pre_execution_assignment": True,
            "exhaustive_descendant_termination_authority": True,
            "exhaustive_write_confinement_authority": True,
        },
    )

    with pytest.raises(subprocess.TimeoutExpired):
        O.run_owned_process(
            [sys.executable, "-c", "pass"], timeout=5,
        )

    assert events == ["scope", "close"]


def test_expiry_while_child_is_gated_reaps_without_attach(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []

    class FakeProcess:
        pass

    class FakeScope:
        attached = False

        def __init__(self, **_kwargs: object) -> None:
            events.append("scope")

        def wrap_argv(self, argv: tuple[str, ...]) -> tuple[str, ...]:
            return argv

        def popen_kwargs(self) -> dict[str, object]:
            return {}

        def create_process(self, *_args: object, **_kwargs: object) -> FakeProcess:
            events.append("create-gated")
            return FakeProcess()

        def terminate_created_process(self) -> None:
            events.append("reap-gated")

        def attach(self, _process: FakeProcess) -> None:
            events.append("attach")

        def close(self) -> None:
            events.append("close")

    ticks = iter((100.0, 101.0, 106.0))
    monkeypatch.setattr(O.time, "monotonic", lambda: next(ticks))
    monkeypatch.setattr(O, "OwnedProcessScope", FakeScope)
    monkeypatch.setattr(
        O,
        "process_tree_termination_capability",
        lambda: {
            "platform": "FIXTURE",
            "pre_execution_assignment": True,
            "exhaustive_descendant_termination_authority": True,
            "exhaustive_write_confinement_authority": True,
        },
    )

    with pytest.raises(subprocess.TimeoutExpired):
        O.run_owned_process(
            [sys.executable, "-c", "pass"], timeout=5,
        )

    assert events == ["scope", "create-gated", "reap-gated", "close"]


def test_isolated_adapter_surfaces_closed_schema_debt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail(*_args: object, **_kwargs: object) -> object:
        raise H.IsolatedExecutionHostError(
            "opaque isolated failure",
            receipt={
                "payload": {
                    "reason_code": "WINDOWS_LOW_INTEGRITY_LEASE_FAILED"
                }
            },
        )

    monkeypatch.setattr(H, "run_isolated_owned_process", fail)
    with pytest.raises(
        O.OwnedProcessRunnerError,
        match="WINDOWS_LOW_INTEGRITY_LEASE_FAILED",
    ):
        O.run_owned_process_isolated(
            [sys.executable, "-c", "pass"], timeout=5,
        )


def test_owned_process_debt_preserves_low_integrity_lease_class(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request = H._build_request(
        command=_python("print('unused')"),
        cwd=None,
        env={},
        timeout=2,
        encoding="utf-8",
        errors="replace",
        output_limit_bytes=4096,
        writable_roots=(),
    )

    class WindowsLowIntegrityLeaseError(RuntimeError):
        pass

    def fail(*_args: object, **_kwargs: object) -> object:
        try:
            raise WindowsLowIntegrityLeaseError("secret path omitted")
        except WindowsLowIntegrityLeaseError as cause:
            raise O.OwnedProcessRunnerError("contained failure") from cause

    monkeypatch.setattr(O, "run_owned_process", fail)
    receipt = H._execute_owned_process(request)

    assert receipt["receipt_type"] == "DEBT"
    assert receipt["payload"] == {
        "reason_code": "WINDOWS_LOW_INTEGRITY_LEASE_FAILED"
    }
    assert "secret path omitted" not in json.dumps(receipt)


def test_locked_stale_scanner_artifact_blocks_launch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scratch = tmp_path / "scratch"
    project = tmp_path / "project"
    source = project / "src" / "Contract.sol"
    rules = tmp_path / "rules"
    scratch.mkdir()
    source.parent.mkdir(parents=True)
    source.write_text("contract Contract {}", encoding="utf-8")
    (rules / "solidity" / "security").mkdir(parents=True)
    stale_sarif = scratch / "opengrep_results.sarif"
    stale_findings = scratch / "opengrep_findings.md"
    stale_sarif.write_text("stale", encoding="utf-8")
    stale_findings.write_text("stale", encoding="utf-8")

    monkeypatch.setattr(RP.shutil, "which", lambda _name: "/tool/opengrep")
    monkeypatch.setattr(
        RP,
        "_ensure_opengrep_rules",
        lambda: {"opengrep-rules": rules, "decurity-rules": rules},
    )
    monkeypatch.setattr(
        RP, "_production_source_files", lambda _project, _exts: [source],
    )
    real_unlink = Path.unlink

    def locked_unlink(path: Path, *args: object, **kwargs: object) -> None:
        if path in {stale_sarif, stale_findings}:
            raise PermissionError("fixture lock")
        real_unlink(path, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", locked_unlink)
    monkeypatch.setattr(
        RP,
        "_run_hardened",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("scanner must not launch with stale outputs")
        ),
    )

    status = RP._run_opengrep_scan(scratch, project, "evm")

    assert status == "FAILED:stale scanner artifacts could not be cleared"
    assert stale_sarif.exists()
    assert stale_findings.exists()
    assert list(scratch.glob(".og-*")) == []


@pytest.mark.skipif(os.name != "nt", reason="Windows low-integrity MIC")
def test_low_integrity_child_can_write_all_redirected_stage_paths(
    tmp_path: Path,
) -> None:
    stage = tmp_path / ".og-integration"
    stage.mkdir()
    env = dict(os.environ)
    env.update({
        "TEMP": str(stage),
        "TMP": str(stage),
        "TMPDIR": str(stage),
        "XDG_CACHE_HOME": str(stage),
        "SEMGREP_SETTINGS_FILE": str(stage / "settings.yml"),
        "SEMGREP_VERSION_CACHE_PATH": str(stage / "version"),
        "SEMGREP_LOG_FILE": str(stage / "scanner.log"),
    })
    code = (
        "import os,pathlib;"
        "root=pathlib.Path(os.environ['TEMP']);"
        "(root/'temp-child').mkdir();"
        "(pathlib.Path(os.environ['XDG_CACHE_HOME'])/'cache-child').mkdir();"
        "pathlib.Path(os.environ['SEMGREP_SETTINGS_FILE']).write_text('s');"
        "pathlib.Path(os.environ['SEMGREP_VERSION_CACHE_PATH']).write_text('v');"
        "pathlib.Path(os.environ['SEMGREP_LOG_FILE']).write_text('l')"
    )

    result = O.run_owned_process_isolated(
        _python(code),
        env=env,
        timeout=10,
        coordinator_timeout=30,
        writable_roots=(stage,),
    )

    assert result.returncode == 0
    assert (stage / "temp-child").is_dir()
    assert (stage / "cache-child").is_dir()
    assert (stage / "settings.yml").read_text() == "s"
    assert (stage / "version").read_text() == "v"
    assert (stage / "scanner.log").read_text() == "l"


@pytest.mark.skipif(os.name != "nt", reason="Windows isolated host integration")
def test_isolated_runner_resolves_relative_executable_before_receipt_binding() -> None:
    result = O.run_owned_process_isolated(
        ["cmd", "/d", "/c", "exit", "0"],
        timeout=20,
    )

    assert result.returncode == 0
    assert Path(result.args[0]).is_absolute()
    assert Path(result.args[0]).name.lower() == "cmd.exe"
