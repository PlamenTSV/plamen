"""Public-front integration tests for the POSIX native handoffs.

Every successful handoff targets a fake dispatcher in an isolated source copy;
these tests must never invoke the real native installer or launcher.
"""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import types

import pytest


ROOT = Path(__file__).resolve().parents[1]
POSIX_ONLY = pytest.mark.skipif(os.name == "nt", reason="POSIX dispatch only")


def _load_front():
    spec = importlib.util.spec_from_file_location(
        "plamen_public_native_dispatch_front", ROOT / "plamen.py",
    )
    module = importlib.util.module_from_spec(spec)
    saved = sys.argv
    sys.argv = ["plamen.py"]
    try:
        spec.loader.exec_module(module)
    finally:
        sys.argv = saved
    return module


def _environment(home: Path) -> dict[str, str]:
    return {
        "HOME": str(home),
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "PYTHONHASHSEED": "0",
        "PYTHONNOUSERSITE": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONPATH": "",
    }


def _fake_source(tmp_path: Path, *, installed: bool) -> tuple[Path, Path]:
    home = tmp_path / "account"
    home.mkdir()
    source = home / ".plamen" if installed else tmp_path / "source"
    scripts = source / "scripts"
    scripts.mkdir(parents=True)
    shutil.copyfile(ROOT / "plamen.py", source / "plamen.py")
    return home, source


def _run(script: Path, argv: list[str], *, home: Path, cwd: Path):
    return subprocess.run(
        [sys.executable, "-B", str(script), *argv],
        cwd=cwd,
        env=_environment(home),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=30,
        check=False,
    )


@POSIX_ONLY
def test_exact_public_codex_install_hands_off_once_to_fake_native_dispatch(
    tmp_path: Path,
) -> None:
    home, source = _fake_source(tmp_path, installed=False)
    (source / "scripts/posix_native_install_dispatch.py").write_text(
        "import json\n"
        "def exec_posix_install(argv):\n"
        "    print(json.dumps({'kind':'install','argv':argv},sort_keys=True))\n"
        "    raise SystemExit(41)\n",
        encoding="ascii",
    )
    before = sorted(
        path.relative_to(source).as_posix() for path in source.rglob("*")
    )

    completed = _run(
        source / "plamen.py", ["install", "--codex"],
        home=home, cwd=source,
    )

    assert completed.returncode == 41
    assert completed.stderr == ""
    assert json.loads(completed.stdout) == {
        "argv": ["install", "--codex"], "kind": "install",
    }
    assert sorted(
        path.relative_to(source).as_posix() for path in source.rglob("*")
    ) == before
    assert list(home.iterdir()) == []


@POSIX_ONLY
def test_public_native_install_failure_is_bounded_and_never_falls_back(
    tmp_path: Path,
) -> None:
    home, source = _fake_source(tmp_path, installed=False)
    (source / "scripts/posix_native_install_dispatch.py").write_text(
        "def exec_posix_install(argv):\n"
        "    raise RuntimeError('private injected diagnostic')\n",
        encoding="ascii",
    )

    completed = _run(
        source / "plamen.py", ["install", "--codex"],
        home=home, cwd=source,
    )

    assert completed.returncode == 75
    assert completed.stdout == ""
    assert completed.stderr == "Plamen POSIX native install admission denied.\n"
    assert "private injected diagnostic" not in completed.stderr
    assert list(home.iterdir()) == []


@pytest.mark.parametrize("command", ("start-config", "resume"))
@POSIX_ONLY
def test_identity_matched_installed_front_reaches_fake_native_launcher_handoff(
    tmp_path: Path, command: str,
) -> None:
    home, installed = _fake_source(tmp_path, installed=True)
    project = tmp_path / "project"
    config = project / ".scratchpad/config.json"
    config.parent.mkdir(parents=True)
    config.write_bytes(b"{}\n")
    config.chmod(0o600)
    (installed / "scripts/posix_native_front_dispatch.py").write_text(
        "import json\n"
        "def exec_native_audit(command, config_path):\n"
        "    print(json.dumps({'command':command,'config':config_path},sort_keys=True))\n"
        "    raise SystemExit(42)\n",
        encoding="ascii",
    )

    completed = _run(
        installed / "plamen.py", [command, str(config)],
        home=home, cwd=project,
    )

    assert completed.returncode == 42
    assert completed.stderr == ""
    assert json.loads(completed.stdout) == {
        "command": command, "config": str(config),
    }


@POSIX_ONLY
def test_compatibility_provenance_is_not_bypassed_by_native_front_exemption(
    tmp_path: Path,
) -> None:
    home, installed = _fake_source(tmp_path, installed=True)
    project = tmp_path / "project"
    config = project / ".scratchpad/config.json"
    config.parent.mkdir(parents=True)
    config.write_bytes(b"{}\n")
    config.chmod(0o600)
    (installed / ".plamen-posix-compat-v2-provenance.json").write_bytes(b"{}\n")
    (installed / "scripts/posix_native_front_dispatch.py").write_text(
        "def exec_native_audit(*args):\n"
        "    raise SystemExit(99)\n",
        encoding="ascii",
    )

    completed = _run(
        installed / "plamen.py", ["resume", str(config)],
        home=home, cwd=project,
    )

    assert completed.returncode == 75
    assert completed.stdout == ""
    assert completed.stderr.startswith(
        "Plamen POSIX compatibility admission denied:"
    )


@POSIX_ONLY
def test_unsupported_claude_selector_remains_visible_pending_distinct_abi(
    tmp_path: Path,
) -> None:
    home, source = _fake_source(tmp_path, installed=False)

    completed = _run(
        source / "plamen.py", ["install", "--claude"],
        home=home, cwd=source,
    )

    assert completed.returncode == 3
    assert "qualified only on Windows" in completed.stderr
    assert completed.stdout == ""
    assert list(home.iterdir()) == []


@pytest.mark.parametrize(
    "argv",
    (
        ["install"],
        ["install", "--codex", "extra"],
        ["INSTALL", "--codex"],
    ),
)
@POSIX_ONLY
def test_nonexact_native_requests_never_reach_fake_dispatchers(
    tmp_path: Path, argv: list[str],
) -> None:
    home, source = _fake_source(tmp_path, installed=False)
    marker = tmp_path / "dispatcher-called"
    body = (
        "from pathlib import Path\n"
        f"MARKER = Path({str(marker)!r})\n"
        "def exec_posix_install(*args):\n"
        "    MARKER.write_bytes(b'called')\n"
        "    raise SystemExit(91)\n"
        "def exec_native_audit(*args):\n"
        "    MARKER.write_bytes(b'called')\n"
        "    raise SystemExit(92)\n"
    )
    (source / "scripts/posix_native_install_dispatch.py").write_text(
        body, encoding="ascii",
    )
    (source / "scripts/posix_native_front_dispatch.py").write_text(
        body, encoding="ascii",
    )

    completed = _run(source / "plamen.py", argv, home=home, cwd=source)

    assert completed.returncode not in {91, 92}
    assert not marker.exists()


@pytest.mark.parametrize(
    "argv",
    (
        ["install", "--codex"],
        ["install", "--codex", "--check"],
        ["install", "--codex", "--check", "--json"],
        ["INSTALL", "--codex", "--check"],
    ),
)
def test_windows_installed_bootstrap_preserves_existing_codex_exemptions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, argv: list[str],
) -> None:
    front = _load_front()
    installed = tmp_path / ".plamen"
    installed.mkdir()
    monkeypatch.setattr(
        front,
        "_installed_runtime_root",
        lambda: {
            "address": installed,
            "module_authority": {},
            "installed_authority": {},
        },
    )
    monkeypatch.setattr(
        front,
        "_codex_install_committed_descriptor",
        lambda *_args, **_kwargs: pytest.fail(
            "Windows Codex install/check exemption entered receipt admission"
        ),
    )
    monkeypatch.setitem(front.__dict__, "os", types.SimpleNamespace(name="nt"))
    monkeypatch.setitem(
        front.__dict__, "sys",
        types.SimpleNamespace(argv=["plamen.py", *argv], platform="win32"),
    )

    front._admit_installed_runtime_before_bootstrap()


@pytest.mark.parametrize(
    "argv",
    (
        ["install", "--codex"],
        ["install", "--codex", "--check"],
        ["install", "--codex", "--check", "--json"],
        ["start-config", "/project/.scratchpad/config.json"],
        ["resume", "/project/.scratchpad/config.json"],
    ),
)
def test_posix_installed_bootstrap_checks_compat_then_exempts_exact_native_routes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, argv: list[str],
) -> None:
    front = _load_front()
    installed = tmp_path / ".plamen"
    installed.mkdir()
    observed = []

    def descriptor(root, components, **_kwargs):
        observed.append((Path(root), tuple(components)))
        if tuple(components) == (front._POSIX_V2_COMPAT_PROVENANCE,):
            raise FileNotFoundError
        pytest.fail("exact native route entered legacy Codex receipt admission")

    monkeypatch.setattr(
        front,
        "_installed_runtime_root",
        lambda: {
            "address": installed,
            "module_authority": {},
            "installed_authority": {},
        },
    )
    monkeypatch.setattr(front, "_codex_install_committed_descriptor", descriptor)
    monkeypatch.setitem(front.__dict__, "os", types.SimpleNamespace(name="posix"))
    monkeypatch.setitem(
        front.__dict__, "sys",
        types.SimpleNamespace(argv=["plamen.py", *argv], platform="darwin"),
    )

    front._admit_installed_runtime_before_bootstrap()

    assert observed == [(installed, (front._POSIX_V2_COMPAT_PROVENANCE,))]
