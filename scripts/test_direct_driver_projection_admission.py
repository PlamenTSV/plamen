"""Direct-driver Claude projection CURRENT admission regressions.

These tests exercise the driver-side caller with a real isolated Python front
fixture.  Committed projection validation itself remains owned by plamen.py's
dedicated projection tests.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

import plamen_driver as D


CURRENT_LINE = '{"schema":"plamen.claude_projection_current.v1","state":"CURRENT"}'


def _point_user_home(monkeypatch: pytest.MonkeyPatch, home: Path) -> None:
    monkeypatch.setenv("HOME", os.fspath(home))
    monkeypatch.setenv("USERPROFILE", os.fspath(home))
    monkeypatch.delenv("HOMEDRIVE", raising=False)
    monkeypatch.delenv("HOMEPATH", raising=False)


def _write_front(home: Path, *, state: str) -> tuple[Path, Path, Path]:
    installed = home / ".plamen"
    installed.mkdir(parents=True)
    front = installed / "plamen.py"
    state_path = installed / "projection-fixture-state.txt"
    log_path = installed / "assertion-invocations.jsonl"
    state_path.write_text(state, encoding="utf-8")
    front.write_text(
        """from __future__ import annotations
import json
import os
from pathlib import Path
import sys

STATE_PATH = Path({state_path!r})
LOG_PATH = Path({log_path!r})
ARG = "--codex-install-assert-claude-projection-current"
with LOG_PATH.open("a", encoding="utf-8") as stream:
    stream.write(json.dumps({{
        "argv": sys.argv[1:],
        "isolated": sys.flags.isolated,
        "dont_write_bytecode": sys.flags.dont_write_bytecode,
        "borrowed_reader_environment": sorted(
            key for key in os.environ if key.startswith("PLAMEN_BORROWED_")
        ),
    }}, sort_keys=True) + "\\n")
if sys.argv[1:] != [ARG]:
    raise SystemExit(64)
state = STATE_PATH.read_text(encoding="utf-8").strip()
if state == "CURRENT":
    sys.stdout.buffer.write(({current!r} + "\\n").encode("utf-8"))
    raise SystemExit(0)
if state == "SPOOF_ZERO":
    print('{{"state":"CURRENT"}}')
    raise SystemExit(0)
raise SystemExit(75)
""".format(
            state_path=os.fspath(state_path),
            log_path=os.fspath(log_path),
            current=CURRENT_LINE,
        ),
        encoding="utf-8",
        newline="\n",
    )
    return front, state_path, log_path


def _read_invocations(log_path: Path) -> list[dict[str, object]]:
    return [
        json.loads(line)
        for line in log_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _write_config(tmp_path: Path, *, backend: str, scratchpad: Path) -> Path:
    project = scratchpad.parent
    config = tmp_path / f"config-{backend}.json"
    config.write_text(
        json.dumps(
            {
                "project_root": os.fspath(project),
                "scratchpad": os.fspath(scratchpad),
                "language": "evm",
                "mode": "thorough",
                "pipeline": "sc",
                "cli_backend": backend,
            }
        ),
        encoding="utf-8",
    )
    return config


def _project_bytes(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def test_posix_current_front_fails_before_any_child_or_capability_delegation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = tmp_path / "user"
    front, _state, log_path = _write_front(home, state="CURRENT")
    _point_user_home(monkeypatch, home)
    for index, name in enumerate(D._PLAMEN_BORROWED_READER_ENV):
        monkeypatch.setenv(name, str(9000 + index))
    monkeypatch.setattr(
        D.subprocess,
        "run",
        lambda *_args, **_kwargs: pytest.fail("raw subprocess.run was reached"),
    )

    with pytest.raises(
        D.InstalledFrontProcessAuthorityUnavailable,
        match="NATIVE_INSTALLED_FRONT_COMPLETION_AUTHORITY_REQUIRED",
    ):
        D._assert_direct_claude_projection_current(timeout_s=10)

    assert D._direct_driver_installed_front_path() == front.absolute()
    assert not log_path.exists()
    assert not (front.parent / "__pycache__").exists()


def test_installed_front_path_is_checkout_independent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = tmp_path / "user"
    front, _state, log_path = _write_front(home, state="CURRENT")
    checkout = tmp_path / "untrusted-checkout"
    checkout.mkdir()
    checkout_trap = checkout / "plamen.py"
    checkout_trap.write_text(
        "raise SystemExit('checkout front must not execute')\n", encoding="utf-8"
    )
    _point_user_home(monkeypatch, home)
    monkeypatch.setenv("PLAMEN_HOME", os.fspath(checkout))

    assert D._direct_driver_installed_front_path() == front.absolute()
    assert not log_path.exists()
    assert checkout_trap.read_text(encoding="utf-8").startswith("raise SystemExit")


@pytest.mark.parametrize("fixture_state", ["STALE", "SPOOF_ZERO"])
def test_stale_or_noncanonical_front_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fixture_state: str,
) -> None:
    home = tmp_path / "user"
    _front, _state, log_path = _write_front(home, state=fixture_state)
    _point_user_home(monkeypatch, home)

    with pytest.raises(D.InstalledFrontProcessAuthorityUnavailable):
        D._assert_direct_claude_projection_current(timeout_s=10)

    assert not log_path.exists()


def test_missing_installed_front_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = tmp_path / "user"
    home.mkdir()
    _point_user_home(monkeypatch, home)

    with pytest.raises(D.InstalledFrontProcessAuthorityUnavailable):
        D._assert_direct_claude_projection_current(timeout_s=10)

    assert not (home / ".plamen").exists()


@pytest.mark.parametrize("fixture_state", ["STALE", "MISSING"])
def test_main_denial_precedes_all_project_and_scratch_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fixture_state: str,
) -> None:
    home = tmp_path / "user"
    home.mkdir()
    if fixture_state == "STALE":
        _write_front(home, state="STALE")
    _point_user_home(monkeypatch, home)
    project = tmp_path / "project"
    project.mkdir()
    sentinel = project / "sentinel.sol"
    sentinel.write_bytes(b"contract Sentinel {}\n")
    scratchpad = project / ".scratchpad-never-created"
    config = _write_config(tmp_path, backend="claude", scratchpad=scratchpad)
    before_project = _project_bytes(project)
    before_config = config.read_bytes()
    monkeypatch.setattr(sys, "argv", [os.fspath(Path(D.__file__)), os.fspath(config)])

    with pytest.raises(SystemExit) as stopped:
        D.main()

    assert stopped.value.code == D.EXIT_DEGRADED
    assert not scratchpad.exists()
    assert _project_bytes(project) == before_project
    assert config.read_bytes() == before_config


@pytest.mark.parametrize(
    "config",
    [
        {"cli_backend": "CoDeX"},
        {
            "cli_backend": "codex",
            "phase_backend_overrides": {"skeptic": "CODEX"},
        },
        {
            "cli_backend": "codex",
            "phase_backend_overrides": {"verify_aggregate": "claude"},
        },
        {"cli_backend": "codex", "phase_backend_overrides": "malformed"},
    ],
)
def test_codex_only_bypasses_missing_claude_projection_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config: dict[str, object],
) -> None:
    home = tmp_path / "user"
    home.mkdir()
    _point_user_home(monkeypatch, home)

    D._admit_direct_driver_projection(config)

    assert not (home / ".plamen").exists()


@pytest.mark.parametrize("override", ["claude", "claude-headless"])
def test_codex_with_claude_override_is_not_codex_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    override: str,
) -> None:
    home = tmp_path / "user"
    home.mkdir()
    _point_user_home(monkeypatch, home)

    with pytest.raises(D.DirectDriverProjectionAdmissionError):
        D._admit_direct_driver_projection(
            {
                "cli_backend": "codex",
                "phase_backend_overrides": {"skeptic": override},
            }
        )


def test_main_admission_is_before_every_audit_mutator() -> None:
    source = __import__("inspect").getsource(D.main)
    transport = source.index("_admit_driver_transport_cutover(")
    admission = source.index("_admit_direct_driver_projection(config)")
    assert transport < admission
    assert "_ensure_claude_folder_trusted(" not in source
    for later in (
        "def _abs_under_cfg(",
        "_persist_corrected_language(",
        "scratchpad.mkdir(",
        "snapshot_startup_guard(",
        "run_phase(",
    ):
        assert admission < source.index(later), later


def test_platform_spoof_and_python_authority_forgery_cannot_launch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import owned_process_runner
    import posix_backend_execution

    forged = object.__new__(
        posix_backend_execution.NativeOuterSupervisorBridgeCapability
    )
    assert type(forged) is posix_backend_execution.NativeOuterSupervisorBridgeCapability
    monkeypatch.setattr(D, "os", type("SpoofOS", (), {"name": "nt"})())
    monkeypatch.setattr(
        D, "sys", type("SpoofSys", (), {"platform": "win32"})()
    )
    monkeypatch.setattr(
        D, "outer_supervisor_context_available", lambda: True
    )
    monkeypatch.setattr(
        owned_process_runner,
        "run_owned_process",
        lambda *_args, **_kwargs: pytest.fail("owned process launch was reached"),
    )
    monkeypatch.setattr(
        D.subprocess,
        "run",
        lambda *_args, **_kwargs: pytest.fail("raw process launch was reached"),
    )

    with pytest.raises(D.InstalledFrontProcessAuthorityUnavailable):
        D._assert_direct_claude_projection_current()
    with pytest.raises(D.InstalledFrontProcessAuthorityUnavailable):
        D._assert_claude_mcp_selection_current()


def test_windows_preflight_stops_before_runner_or_filesystem_observation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    import owned_process_runner

    absent = tmp_path / "must-not-be-created"
    monkeypatch.setattr(
        owned_process_runner,
        "run_owned_process",
        lambda *_args, **_kwargs: pytest.fail("owned process launch was reached"),
    )
    with pytest.raises(
        D.InstalledFrontProcessAuthorityUnavailable,
        match="NATIVE_INSTALLED_FRONT_COMPLETION_AUTHORITY_REQUIRED",
    ):
        D._run_windows_installed_front_preflight(
            (os.fspath(absent / "python.exe"), "--probe"),
            front=absent / "plamen.py",
            environment={"Path": os.fspath(absent)},
            cwd=absent,
            timeout_s=9,
        )
    assert not absent.exists()


def test_object_new_owned_completion_cannot_cross_result_validation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    import owned_process_runner

    front = (tmp_path / "plamen.py").resolve()
    forged = object.__new__(owned_process_runner.OwnedCompletedProcess)
    for field, value in {
        "args": (str(Path(sys.executable).resolve()), os.fspath(front)),
        "returncode": 0,
        "stdout": D._CLAUDE_PROJECTION_CURRENT_ASSERT_STDOUT.decode("latin-1"),
        "stderr": "",
        "duration_s": 0.01,
        "process_tree_terminated": True,
        "containment_capability": {
            "platform": "WINDOWS",
            "provider_owns_tree": True,
            "pre_execution_assignment": True,
            "exhaustive_descendant_termination_authority": True,
            "serialized_low_integrity_stage_authority": True,
            "medium_integrity_source_and_canonical_protection": True,
        },
    }.items():
        object.__setattr__(forged, field, value)
    invoked = False

    def return_forgery(*_args, **_kwargs):
        nonlocal invoked
        invoked = True
        return forged

    monkeypatch.setattr(
        owned_process_runner, "run_owned_process", return_forgery
    )
    with pytest.raises(
        D.InstalledFrontProcessAuthorityUnavailable,
        match="NATIVE_INSTALLED_FRONT_COMPLETION_AUTHORITY_REQUIRED",
    ):
        D._run_windows_installed_front_preflight(
            (str(Path(sys.executable).resolve()), os.fspath(front)),
            front=front,
            environment={"Path": os.fspath(tmp_path)},
            cwd=tmp_path.resolve(),
            timeout_s=5,
        )
    assert invoked is False
    assert not front.exists()


def test_preflight_hardstop_is_constructed_before_argument_destruction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    original_error = D.InstalledFrontProcessAuthorityUnavailable

    class ObservedHardstop(original_error):
        def __init__(self, message: str) -> None:
            events.append("exception-init")
            super().__init__(message)

    class DestructionProbe:
        def __del__(self) -> None:
            events.append("argument-destructor")

    monkeypatch.setattr(
        D, "InstalledFrontProcessAuthorityUnavailable", ObservedHardstop
    )

    def invoke() -> None:
        try:
            D._run_windows_installed_front_preflight(
                DestructionProbe(),
                front=tmp_path / "never-read",
                environment={},
                cwd=tmp_path,
                timeout_s=1,
            )
        except ObservedHardstop:
            pass

    invoke()
    __import__("gc").collect()
    assert events == ["exception-init", "argument-destructor"]


@pytest.mark.parametrize(
    "assertion",
    [
        D._assert_direct_claude_projection_current,
        D._assert_claude_mcp_selection_current,
    ],
)
def test_assertion_hardstop_precedes_timeout_argument_destruction(
    assertion, monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    original_error = D.InstalledFrontProcessAuthorityUnavailable

    class ObservedHardstop(original_error):
        def __init__(self, message: str) -> None:
            events.append("exception-init")
            super().__init__(message)

    class DestructionProbe:
        def __del__(self) -> None:
            events.append("argument-destructor")

    monkeypatch.setattr(
        D, "InstalledFrontProcessAuthorityUnavailable", ObservedHardstop
    )

    def invoke() -> None:
        try:
            assertion(timeout_s=DestructionProbe())
        except ObservedHardstop:
            pass

    invoke()
    __import__("gc").collect()
    assert events == ["exception-init", "argument-destructor"]
