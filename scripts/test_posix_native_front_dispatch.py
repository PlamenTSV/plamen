"""Focused tests for the stdlib-only POSIX native front handoff."""

from __future__ import annotations

import inspect
import os
from pathlib import Path
import types

import pytest

import posix_native_front_dispatch as D


pytestmark = pytest.mark.skipif(os.name != "posix", reason="POSIX only")


class _ExecIntercept(BaseException):
    pass


def _layout(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    home = tmp_path / "account"
    launcher = home / ".local/share/plamen/bin/plamen-native-launcher"
    launcher.parent.mkdir(parents=True)
    launcher.write_bytes(b"native-launcher")
    launcher.chmod(D.LAUNCHER_MODE)
    generation_link = tmp_path / "generation-launcher"
    os.link(launcher, generation_link)

    config = tmp_path / "project/.scratchpad/config.json"
    config.parent.mkdir(parents=True)
    config.write_bytes(b"{}\n")
    config.chmod(0o600)
    record = types.SimpleNamespace(pw_uid=os.getuid(), pw_dir=str(home))
    monkeypatch.setattr(D.pwd, "getpwuid", lambda uid: record)
    return home, launcher, generation_link, config


def test_exact_exec_uses_pwd_home_closed_environment_and_no_descriptor(
    tmp_path, monkeypatch,
):
    home, launcher, _generation_link, config = _layout(tmp_path, monkeypatch)
    monkeypatch.setenv("HOME", str(tmp_path / "attacker-home"))
    monkeypatch.setenv("PLAMEN_TOKEN", "forbidden")
    observed = {}

    def intercept(path, argv, environment):
        observed.update(path=path, argv=argv, environment=environment)
        raise _ExecIntercept

    monkeypatch.setattr(D.os, "execve", intercept)
    with pytest.raises(_ExecIntercept):
        D.exec_native_audit("start-config", str(config))

    assert observed == {
        "path": str(launcher),
        "argv": [str(launcher), "start-config", str(config)],
        "environment": {},
    }
    assert str(home) in observed["path"]
    assert "attacker-home" not in observed["path"]
    assert tuple(inspect.signature(D.exec_native_audit).parameters) == (
        "command", "config_path",
    )


@pytest.mark.parametrize("command", ("", "START_CONFIG", "launch", 7, None))
def test_rejects_nonexact_command_before_exec(tmp_path, monkeypatch, command):
    _home, _launcher, _generation_link, config = _layout(tmp_path, monkeypatch)
    monkeypatch.setattr(
        D.os, "execve", lambda *_args: pytest.fail("exec must not run")
    )
    with pytest.raises(D.PosixNativeFrontDispatchError):
        D.exec_native_audit(command, str(config))


@pytest.mark.parametrize(
    "config",
    (
        "relative/.scratchpad/config.json",
        "/tmp/../tmp/project/.scratchpad/config.json",
        "/tmp/project/config.json",
        "/tmp/project/.scratchpad/other.json",
        "/tmp/project/.scratchpad/config.json\x00tail",
    ),
)
def test_rejects_noncanonical_config_before_exec(tmp_path, monkeypatch, config):
    _layout(tmp_path, monkeypatch)
    monkeypatch.setattr(
        D.os, "execve", lambda *_args: pytest.fail("exec must not run")
    )
    with pytest.raises(D.PosixNativeFrontDispatchError):
        D.exec_native_audit("resume", config)


def test_rejects_symlinked_config_without_reading_content(tmp_path, monkeypatch):
    _home, _launcher, _generation_link, config = _layout(tmp_path, monkeypatch)
    alias = tmp_path / "alias/.scratchpad/config.json"
    alias.parent.mkdir(parents=True)
    alias.unlink(missing_ok=True)
    alias.symlink_to(config)
    monkeypatch.setattr(
        D.os, "execve", lambda *_args: pytest.fail("exec must not run")
    )
    monkeypatch.setattr(
        D.os, "read", lambda *_args: pytest.fail("Python must not read config")
    )
    with pytest.raises(D.PosixNativeFrontDispatchError):
        D.exec_native_audit("resume", str(alias))


def test_rejects_world_writable_config(tmp_path, monkeypatch):
    _home, _launcher, _generation_link, config = _layout(tmp_path, monkeypatch)
    config.chmod(0o622)
    monkeypatch.setattr(
        D.os, "execve", lambda *_args: pytest.fail("exec must not run")
    )
    with pytest.raises(D.PosixNativeFrontDispatchError):
        D.exec_native_audit("start-config", str(config))


def test_rejects_launcher_without_generation_hardlink(tmp_path, monkeypatch):
    _home, _launcher, generation_link, config = _layout(tmp_path, monkeypatch)
    generation_link.unlink()
    monkeypatch.setattr(
        D.os, "execve", lambda *_args: pytest.fail("exec must not run")
    )
    with pytest.raises(D.PosixNativeFrontDispatchError):
        D.exec_native_audit("start-config", str(config))


def test_rejects_launcher_mode_drift(tmp_path, monkeypatch):
    _home, launcher, _generation_link, config = _layout(tmp_path, monkeypatch)
    launcher.chmod(0o700)
    monkeypatch.setattr(
        D.os, "execve", lambda *_args: pytest.fail("exec must not run")
    )
    with pytest.raises(D.PosixNativeFrontDispatchError):
        D.exec_native_audit("resume", str(config))


def test_rejects_symlinked_launcher_directory(tmp_path, monkeypatch):
    home = tmp_path / "account"
    real_bin = tmp_path / "real-bin"
    real_bin.mkdir()
    launcher = real_bin / "plamen-native-launcher"
    launcher.write_bytes(b"native-launcher")
    launcher.chmod(D.LAUNCHER_MODE)
    os.link(launcher, tmp_path / "generation-launcher")
    published_parent = home / ".local/share/plamen"
    published_parent.mkdir(parents=True)
    (published_parent / "bin").symlink_to(real_bin, target_is_directory=True)
    config = tmp_path / "project/.scratchpad/config.json"
    config.parent.mkdir(parents=True)
    config.write_bytes(b"{}\n")
    config.chmod(0o600)
    record = types.SimpleNamespace(pw_uid=os.getuid(), pw_dir=str(home))
    monkeypatch.setattr(D.pwd, "getpwuid", lambda uid: record)
    monkeypatch.setattr(
        D.os, "execve", lambda *_args: pytest.fail("exec must not run")
    )

    with pytest.raises(D.PosixNativeFrontDispatchError):
        D.exec_native_audit("start-config", str(config))


def test_module_has_no_projection_token_or_environment_fallback():
    source = inspect.getsource(D)
    assert "request_projection" not in source
    assert "getenv(" not in source
    assert "os.environ" not in source
    assert "token" not in source.lower()
    assert "pass_fds" not in source
    assert "subprocess" not in source
