"""Exact, read-only source discovery policy on POSIX."""

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]
pytestmark = pytest.mark.skipif(os.name == "nt", reason="POSIX policy only")


def _load_front():
    spec = importlib.util.spec_from_file_location(
        "plamen_public_source_discovery_posix_v2", ROOT / "plamen.py"
    )
    module = importlib.util.module_from_spec(spec)
    saved = sys.argv
    sys.argv = ["plamen.py"]
    try:
        spec.loader.exec_module(module)
    finally:
        sys.argv = saved
    return module


def _environment(home, bin_root=None):
    path = os.defpath
    if bin_root is not None:
        path = str(bin_root) + os.pathsep + path
    return {
        "HOME": str(home),
        "PATH": path,
        "NO_COLOR": "1",
        "PLAMEN_PLAIN_OUTPUT": "1",
        "PYTHONHASHSEED": "0",
        "PYTHONNOUSERSITE": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONPATH": "",
    }


@pytest.mark.parametrize(
    "argv",
    (
        ("plan", "core", "/project", "--codex", "--json"),
        ("doctor",),
        ("--detect-language", "/project"),
        ("help",),
        ("--help",),
        ("version",),
        ("--version",),
        ("core", "--help"),
    ),
)
def test_exact_documented_discovery_policy(argv):
    front = _load_front()
    assert (
        front._public_cli_route_policy(argv)
        == front._PUBLIC_CLI_SOURCE_DISCOVERY
    )


@pytest.mark.parametrize(
    "argv",
    (
        (),
        ("doctor", "extra"),
        ("verify",),
        ("check",),
        ("--detect-language",),
        ("--detect-language", ""),
        ("core", "/project", "--codex"),
        ("resume",),
    ),
)
def test_unknown_or_malformed_discovery_argv_remains_governed(argv):
    front = _load_front()
    assert front._public_cli_route_policy(argv) == front._PUBLIC_CLI_GOVERNED


def test_installed_identity_retains_projection_preflight(monkeypatch):
    front = _load_front()
    monkeypatch.setattr(
        front, "_installed_runtime_root", lambda: {"address": Path("/installed")}
    )
    assert not front._source_discovery_without_installed_runtime(("doctor",))
    assert not front._source_discovery_without_installed_runtime(
        ("--detect-language", "/project")
    )
    monkeypatch.setattr(front, "_installed_runtime_root", lambda: None)
    assert front._source_discovery_without_installed_runtime(("doctor",))


def test_main_enforces_installed_doctor_but_not_source_doctor(monkeypatch):
    front = _load_front()
    events = []
    monkeypatch.setattr(front.sys, "argv", ["plamen.py", "doctor"])
    monkeypatch.setattr(front, "run_doctor", lambda: events.append("doctor") or 0)
    monkeypatch.setattr(
        front,
        "_enforce_public_claude_projection_preflight",
        lambda: events.append("projection"),
    )
    monkeypatch.setattr(
        front, "_installed_runtime_root", lambda: {"address": Path("/installed")}
    )
    with pytest.raises(SystemExit) as installed:
        front.main()
    assert installed.value.code == 0
    assert events == ["projection", "doctor"]

    events.clear()
    monkeypatch.setattr(front, "_installed_runtime_root", lambda: None)
    with pytest.raises(SystemExit) as source:
        front.main()
    assert source.value.code == 0
    assert events == ["doctor"]


def test_cold_source_doctor_is_deterministic_and_read_only(tmp_path):
    home = tmp_path / "home"
    bin_root = tmp_path / "bin"
    home.mkdir()
    bin_root.mkdir()
    marker = tmp_path / "provider-invoked"
    codex = bin_root / "codex"
    codex.write_text(
        '#!/bin/sh\n: > "$PLAMEN_TEST_PROVIDER_MARKER"\nexit 99\n',
        encoding="utf-8",
    )
    codex.chmod(0o700)
    environment = _environment(home, bin_root)
    environment["PLAMEN_TEST_PROVIDER_MARKER"] = str(marker)
    command = [sys.executable, "-B", str(ROOT / "plamen.py"), "doctor"]

    first = subprocess.run(
        command, cwd=ROOT, env=environment, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        timeout=30, check=False,
    )
    second = subprocess.run(
        command, cwd=ROOT, env=environment, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        timeout=30, check=False,
    )

    assert first.returncode == second.returncode == 1
    assert first.stdout == second.stdout
    assert first.stderr == second.stderr == ""
    assert "~/.plamen missing; running from" in first.stdout
    assert "hard failure(s)" in first.stdout
    assert "Traceback" not in first.stdout
    assert not marker.exists()
    assert list(home.iterdir()) == []


def test_source_doctor_reports_legacy_v2_projection_without_traceback(tmp_path):
    home = tmp_path / "home"
    bin_root = tmp_path / "bin"
    bin_root.mkdir()
    claude = bin_root / "claude"
    claude.write_text("#!/bin/sh\nexit 99\n", encoding="utf-8")
    claude.chmod(0o700)
    claude_home = home / ".claude"
    claude_home.mkdir(parents=True)
    manifest = claude_home / ".plamen-manifest.json"
    manifest.write_text("{}\n", encoding="utf-8")
    before = manifest.read_bytes()

    completed = subprocess.run(
        [sys.executable, "-B", str(ROOT / "plamen.py"), "doctor"],
        cwd=ROOT, env=_environment(home, bin_root), stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        timeout=30, check=False,
    )

    assert completed.returncode == 1
    assert completed.stderr == ""
    assert "Traceback" not in completed.stdout
    assert "Plamen manifest at" in completed.stdout
    assert "runtime package incomplete" in completed.stdout
    assert manifest.read_bytes() == before
    assert sorted(path.relative_to(home) for path in home.rglob("*")) == [
        Path(".claude"), Path(".claude/.plamen-manifest.json")
    ]


def test_cold_source_detection_is_provider_free_and_read_only(tmp_path):
    home = tmp_path / "home"
    target = tmp_path / "target"
    bin_root = tmp_path / "bin"
    home.mkdir()
    target.mkdir()
    bin_root.mkdir()
    (target / "Dodo.sol").write_text("contract Dodo {}\n", encoding="utf-8")
    marker = tmp_path / "provider-invoked"
    codex = bin_root / "codex"
    codex.write_text(
        '#!/bin/sh\n: > "$PLAMEN_TEST_PROVIDER_MARKER"\nexit 99\n',
        encoding="utf-8",
    )
    codex.chmod(0o700)
    environment = _environment(home, bin_root)
    environment["PLAMEN_TEST_PROVIDER_MARKER"] = str(marker)

    completed = subprocess.run(
        [
            sys.executable, "-B", str(ROOT / "plamen.py"),
            "--detect-language", str(target),
        ],
        cwd=target, env=environment, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        timeout=30, check=False,
    )

    assert completed.returncode == 0, completed.stderr
    assert completed.stderr == ""
    payload = json.loads(completed.stdout)
    assert payload == {
        "language": "evm",
        "project": str(target),
        "provider_invocations": 0,
        "schema": "plamen.front_detect.v1",
    }
    assert not marker.exists()
    assert list(home.iterdir()) == []


@pytest.mark.parametrize(
    ("argument", "needle"),
    (("--help", "Usage:"), ("--version", "plamen 3.0.0")),
)
def test_cold_help_and_version_are_read_only(tmp_path, argument, needle):
    home = tmp_path / "home"
    home.mkdir()
    completed = subprocess.run(
        [sys.executable, "-B", str(ROOT / "plamen.py"), argument],
        cwd=ROOT, env=_environment(home), stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        timeout=30, check=False,
    )
    assert completed.returncode == 0
    assert completed.stderr == ""
    assert needle in completed.stdout
    assert list(home.iterdir()) == []
