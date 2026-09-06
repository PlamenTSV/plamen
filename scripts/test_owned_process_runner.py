"""Focused cross-platform tests for the central owned-process runner."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

import owned_process_runner as O
import isolated_execution_host as H
from windows_low_integrity_lease import (
    LEASE_DIRECTORY_ENV,
    LEASE_TEST_OVERRIDE_ENV,
)


def test_owned_runner_captures_streams_and_closes_scope() -> None:
    result = O.run_owned_process(
        [
            sys.executable,
            "-c",
            (
                "import sys;"
                "print('owned-stdout');"
                "print('owned-stderr', file=sys.stderr)"
            ),
        ],
        timeout=10,
    )

    assert result.returncode == 0
    assert "owned-stdout" in result.stdout
    assert "owned-stderr" in result.stderr
    assert result.process_tree_terminated is True
    assert result.containment_capability["platform"] in {
        "WINDOWS",
        "LINUX",
        "MACOS",
    }


def test_isolated_adapter_preserves_requested_executable_spelling(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: dict[str, object] = {}
    sentinel = object()

    def fake_run(command, **kwargs):
        observed["command"] = tuple(command)
        observed["kwargs"] = kwargs
        return sentinel

    monkeypatch.setattr(H, "run_isolated_owned_process", fake_run)
    result = O.run_owned_process_isolated(
        ("bare-tool", "--version"),
        env={"PATH": "signed-path"},
        timeout=5,
    )

    assert result is sentinel
    assert observed["command"] == ("bare-tool", "--version")
    assert observed["kwargs"]["env"] == {"PATH": "signed-path"}


def test_explicit_environment_without_path_never_uses_ambient_path() -> None:
    with pytest.raises(FileNotFoundError):
        O.resolve_owned_process_command(("python", "--version"), env={})


@pytest.mark.skipif(os.name != "nt", reason="Windows PATHEXT semantics")
def test_windows_resolution_uses_case_insensitive_signed_path_and_pathext(
    tmp_path: Path,
) -> None:
    executable = tmp_path / "signed-tool.custom"
    executable.write_bytes(b"fixture")

    resolved = O.resolve_owned_process_command(
        ("signed-tool", "--version"),
        env={"path": str(tmp_path), "pathext": ".custom"},
    )

    assert resolved == (str(executable.resolve()), "--version")


@pytest.mark.skipif(os.name != "nt", reason="Windows PATHEXT semantics")
def test_windows_explicit_environment_never_borrows_ambient_pathext(
    tmp_path: Path,
) -> None:
    executable = tmp_path / "signed-tool.exe"
    executable.write_bytes(b"fixture")

    with pytest.raises(FileNotFoundError):
        O.resolve_owned_process_command(
            ("signed-tool.exe",),
            env={"PATH": str(tmp_path)},
        )


@pytest.mark.skipif(os.name != "nt", reason="Windows environment semantics")
def test_windows_resolution_rejects_ambiguous_casefolded_path_keys(
    tmp_path: Path,
) -> None:
    with pytest.raises(ValueError, match="ambiguous PATH"):
        O.resolve_owned_process_command(
            ("signed-tool.exe",),
            env={"PATH": str(tmp_path), "path": str(tmp_path)},
        )


def test_timeout_terminates_descendant_before_it_can_write(
    tmp_path,
) -> None:
    sentinel = tmp_path / "escaped-descendant.txt"
    grandchild = (
        "import pathlib,time;"
        "time.sleep(3);"
        f"pathlib.Path({str(sentinel)!r}).write_text('escaped')"
    )
    parent = (
        "import subprocess,sys,time;"
        f"subprocess.Popen([sys.executable,'-c',{grandchild!r}]);"
        "print('spawned', flush=True);"
        "time.sleep(60)"
    )
    started = time.monotonic()

    with pytest.raises(subprocess.TimeoutExpired) as caught:
        O.run_owned_process(
            [sys.executable, "-c", parent],
            # Suspended Job assignment plus token-integrity verification is
            # intentionally completed before user code runs.
            timeout=1.2,
        )

    assert time.monotonic() - started < 5
    assert "spawned" in str(caught.value.output)
    time.sleep(3.2)
    assert not sentinel.exists()


def test_output_retention_is_bounded() -> None:
    result = O.run_owned_process(
        [sys.executable, "-c", "print('x' * 10000)"],
        timeout=10,
        output_limit_bytes=1024,
    )

    assert "output truncated" in result.stdout
    assert len(result.stdout.encode("utf-8")) < 1200
    assert result.stdout.rstrip().endswith("x" * 128)


def test_unsupported_platform_capability_fails_before_spawn(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        O,
        "process_tree_termination_capability",
        lambda: {
            "platform": "POSIX_UNSUPPORTED",
            "pre_execution_assignment": True,
        },
    )

    with pytest.raises(
        O.OwnedProcessRunnerError,
        match="unsupported|pre-execution",
    ):
        O.run_owned_process(
            [sys.executable, "-c", "raise SystemExit(0)"],
            timeout=10,
        )


def test_test_override_namespace_is_not_production_write_authority() -> None:
    capability = {
        "platform": "WINDOWS",
        "exhaustive_write_confinement_authority": False,
        "serialized_low_integrity_stage_authority": True,
        "medium_integrity_source_and_canonical_protection": True,
        "write_confinement": (
            "LOW_INTEGRITY_TOKEN_PLUS_SERIALIZED_PLAMEN_STAGE_LEASE"
        ),
        "write_confinement_limitation": (
            "UNRELATED_PREEXISTING_LOW_INTEGRITY_OBJECTS_OUT_OF_SCOPE"
        ),
        "low_integrity_lease": {
            "protocol": "PLAMEN_WINDOWS_LOW_INTEGRITY_GLOBAL_LEASE_V1",
            "namespace_authority": (
                "TEST_ONLY_EXPLICIT_DIRECTORY_OVERRIDE"
            ),
            "namespace_limitation": (
                "TEST_OVERRIDE_NOT_PRODUCTION_AUTHORITY"
            ),
            "scope": "TEST_PROCESS_EXPLICIT_NAMESPACE_ONLY",
        },
    }

    assert O._transaction_write_authority(capability) is None


@pytest.mark.skipif(sys.platform != "win32", reason="Windows MIC lease")
def test_popen_failure_closes_unattached_scope_without_quarantining_lease(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A pre-process launch failure has a proof of zero: nothing was attached."""

    lease_directory = tmp_path / "lease-authority"
    writable = tmp_path / "owned-output"
    writable.mkdir()
    monkeypatch.setenv(LEASE_TEST_OVERRIDE_ENV, "1")
    monkeypatch.setenv(LEASE_DIRECTORY_ENV, str(lease_directory))
    real_capability = O.process_tree_termination_capability
    capability = real_capability()
    capability["low_integrity_lease"] = {
        **capability["low_integrity_lease"],
        "namespace_authority": "WINDOWS_KNOWN_FOLDER_LOCAL_APP_DATA",
        "namespace_limitation": (
            "SAME_USER_MEDIUM_INTEGRITY_MUTATION_OUT_OF_SCOPE"
        ),
        "scope": (
            "ALL_PLAMEN_LOW_INTEGRITY_LIFETIMES_FOR_THIS_WINDOWS_USER_PROFILE"
        ),
    }
    monkeypatch.setattr(
        O,
        "process_tree_termination_capability",
        lambda: capability,
    )
    real_popen = O.subprocess.Popen
    unattached_terminate_calls: list[bool] = []
    real_terminate = O.OwnedProcessScope.terminate

    def observe_terminate(scope: O.OwnedProcessScope) -> None:
        if not scope.attached:
            unattached_terminate_calls.append(True)
        real_terminate(scope)

    def fail_popen(*_args: object, **_kwargs: object) -> object:
        raise OSError("injected Popen failure before process creation")

    monkeypatch.setattr(O.OwnedProcessScope, "terminate", observe_terminate)
    monkeypatch.setattr(O.subprocess, "Popen", fail_popen)
    with pytest.raises(O.OwnedProcessRunnerError, match="OSError"):
        O.run_owned_process(
            [sys.executable, "-I", "-S", "-c", "raise SystemExit(0)"],
            writable_roots=(writable,),
            timeout=2,
        )

    assert unattached_terminate_calls == []
    state = json.loads(
        (lease_directory / "state.json").read_text(encoding="utf-8")
    )
    assert state["status"] == "IDLE"

    # The exact same provider process can acquire the released lease again.
    monkeypatch.setattr(O.subprocess, "Popen", real_popen)
    completed = O.run_owned_process(
        [sys.executable, "-I", "-S", "-c", "print('next-run')"],
        writable_roots=(writable,),
        timeout=5,
    )
    assert completed.returncode == 0
    assert "next-run" in completed.stdout


@pytest.mark.skipif(sys.platform != "win32", reason="Windows Job kill-on-close")
def test_terminate_failure_emergency_closes_job_and_kills_descendant(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    child_marker = "PLAMEN_OWNED_RUNNER_TERMINATE_FAILURE_CHILD"
    if os.environ.get(child_marker) != "1":
        env = dict(os.environ)
        env[child_marker] = "1"
        completed = subprocess.run(
            [
                sys.executable,
                "-m",
                "pytest",
                "-q",
                f"{Path(__file__).resolve()}::"
                "test_terminate_failure_emergency_closes_job_and_kills_descendant",
            ],
            cwd=str(Path(__file__).resolve().parents[1]),
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=30,
            check=False,
        )
        assert completed.returncode == 0, completed.stdout
        return
    writable = tmp_path / "owned-output"
    writable.mkdir()
    marker = writable / "late-descendant.txt"
    child = (
        "import pathlib,time; time.sleep(0.7); "
        f"pathlib.Path({str(marker)!r}).write_text('late')"
    )
    parent = (
        "import subprocess,sys; "
        f"subprocess.Popen([sys.executable,'-c',{child!r}], "
        "stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,"
        "stderr=subprocess.DEVNULL)"
    )

    def fail_terminate(_scope: object) -> None:
        raise O.OwnedProcessScopeError("injected TerminateJobObject failure")

    monkeypatch.setattr(O.OwnedProcessScope, "terminate", fail_terminate)
    with pytest.raises(O.OwnedProcessRunnerError, match="closed|terminated"):
        O.run_owned_process(
            [sys.executable, "-c", parent],
            cwd=tmp_path,
            writable_roots=(writable,),
            timeout=10,
        )

    time.sleep(0.9)
    assert not marker.exists()
