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


def test_current_installed_front_isolated_exact_and_nonrecursive(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = tmp_path / "user"
    front, _state, log_path = _write_front(home, state="CURRENT")
    _point_user_home(monkeypatch, home)
    for index, name in enumerate(D._PLAMEN_BORROWED_READER_ENV):
        monkeypatch.setenv(name, str(9000 + index))

    D._assert_direct_claude_projection_current(timeout_s=10)

    assert D._direct_driver_installed_front_path() == front.absolute()
    invocations = _read_invocations(log_path)
    assert invocations == [
        {
            "argv": [D._CLAUDE_PROJECTION_CURRENT_ASSERT_ARG],
            "borrowed_reader_environment": [],
            "dont_write_bytecode": 1,
            "isolated": 1,
        }
    ]
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

    D._assert_direct_claude_projection_current(timeout_s=10)

    assert D._direct_driver_installed_front_path() == front.absolute()
    assert len(_read_invocations(log_path)) == 1
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

    with pytest.raises(D.DirectDriverProjectionAdmissionError):
        D._assert_direct_claude_projection_current(timeout_s=10)

    assert len(_read_invocations(log_path)) == 1


def test_missing_installed_front_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = tmp_path / "user"
    home.mkdir()
    _point_user_home(monkeypatch, home)

    with pytest.raises(D.DirectDriverProjectionAdmissionError):
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
