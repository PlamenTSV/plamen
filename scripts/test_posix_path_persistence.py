"""Regression: `plamen setup` must persist toolchain PATH on macOS/Linux.

Before this fix, _update_path_env only persisted PATH on Windows (registry).
On POSIX, toolchains installed by setup (foundry -> ~/.foundry/bin, cargo,
solana) updated only the in-process PATH and vanished -> audit subprocesses
spawned from a future shell hit `COMPILATION_FAILED` (tool not found). The
fresh-POSIX-user open-source blocker. `_persist_path_posix` writes an
idempotent marker block to the user's shell rc file(s).
"""
import os
import importlib.util
import tempfile

import pytest

_PLAMEN = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "plamen.py")


def _load():
    import sys
    spec = importlib.util.spec_from_file_location("plamen_mod_test", _PLAMEN)
    m = importlib.util.module_from_spec(spec)
    saved = sys.argv
    sys.argv = ["plamen.py"]
    try:
        spec.loader.exec_module(m)
    finally:
        sys.argv = saved
    return m


def _home(monkeypatch, d, shell="/bin/zsh"):
    # ntpath.expanduser uses USERPROFILE first; posixpath uses HOME.
    monkeypatch.setenv("USERPROFILE", d)
    monkeypatch.setenv("HOME", d)
    monkeypatch.setenv("SHELL", shell)


def test_creates_marker_block_in_profile(monkeypatch):
    m = _load()
    with tempfile.TemporaryDirectory() as d:
        _home(monkeypatch, d)
        m._persist_path_posix("/opt/.foundry/bin")
        prof = open(os.path.join(d, ".profile"), encoding="utf-8").read()
        assert prof.count("# >>> plamen toolchain PATH >>>") == 1
        assert 'export PATH="/opt/.foundry/bin:$PATH"' in prof


def test_dirs_accumulate_and_idempotent(monkeypatch):
    m = _load()
    with tempfile.TemporaryDirectory() as d:
        _home(monkeypatch, d)
        m._persist_path_posix("/opt/.foundry/bin")
        m._persist_path_posix("/opt/.cargo/bin")
        prof_before_readd = open(os.path.join(d, ".profile"), encoding="utf-8").read()
        m._persist_path_posix("/opt/.foundry/bin")  # re-add -> no dup
        prof = open(os.path.join(d, ".profile"), encoding="utf-8").read()
        assert prof == prof_before_readd
        assert prof.count("# >>> plamen toolchain PATH >>>") == 1
        assert prof.count('# plamen-path-json: "/opt/.foundry/bin"') == 1
        assert prof.count('# plamen-path-json: "/opt/.cargo/bin"') == 1
        assert 'export PATH="/opt/.foundry/bin:/opt/.cargo/bin:$PATH"' in prof


def test_preserves_existing_rc_content_and_writes_shell_rc(monkeypatch):
    m = _load()
    with tempfile.TemporaryDirectory() as d:
        _home(monkeypatch, d, shell="/usr/bin/zsh")
        open(os.path.join(d, ".zshrc"), "w", encoding="utf-8").write("alias ll='ls -la'\n")
        m._persist_path_posix("/opt/.foundry/bin")
        zrc = open(os.path.join(d, ".zshrc"), encoding="utf-8").read()
        assert "alias ll='ls -la'" in zrc          # existing content preserved
        assert zrc.count("# >>> plamen toolchain PATH >>>") == 1
        assert 'export PATH="/opt/.foundry/bin:$PATH"' in zrc


def test_bash_targets_bashrc(monkeypatch):
    m = _load()
    with tempfile.TemporaryDirectory() as d:
        _home(monkeypatch, d, shell="/bin/bash")
        open(os.path.join(d, ".bashrc"), "w", encoding="utf-8").write("# bash\n")
        m._persist_path_posix("/opt/.cargo/bin")
        assert "plamen toolchain PATH" in open(os.path.join(d, ".bashrc"), encoding="utf-8").read()
        # ~/.profile baseline always written too
        assert "plamen toolchain PATH" in open(os.path.join(d, ".profile"), encoding="utf-8").read()


def test_update_path_env_routes_posix_not_windows(monkeypatch):
    """persist=True on non-win32 must call _persist_path_posix, never registry."""
    m = _load()
    if m.sys.platform == "win32":
        pytest.skip("routing test is for the POSIX branch")
    with tempfile.TemporaryDirectory() as d:
        _home(monkeypatch, d)
        toolbin = os.path.join(d, "toolbin")
        os.makedirs(toolbin)
        m._update_path_env([toolbin], persist=True)
        assert "plamen toolchain PATH" in open(os.path.join(d, ".profile"), encoding="utf-8").read()


def test_writes_both_zshrc_and_bashrc_for_cross_shell(monkeypatch):
    """Both ~/.zshrc and ~/.bashrc get the block regardless of $SHELL, so an
    install-from-bash / audit-from-zsh (or vice-versa) is covered."""
    m = _load()
    with tempfile.TemporaryDirectory() as d:
        _home(monkeypatch, d, shell="/bin/zsh")
        m._persist_path_posix("/opt/.foundry/bin")
        for rc in (".zshrc", ".bashrc", ".profile"):
            txt = open(os.path.join(d, rc), encoding="utf-8").read()
            assert "# >>> plamen toolchain PATH >>>" in txt, rc
            assert 'export PATH="/opt/.foundry/bin:$PATH"' in txt, rc


def test_fish_config_written_with_fish_syntax(monkeypatch):
    """fish gets its own config in fish syntax (`set -gx PATH ... $PATH`),
    idempotently — and only when fish is actually in use."""
    m = _load()
    with tempfile.TemporaryDirectory() as d:
        _home(monkeypatch, d, shell="/usr/bin/fish")
        m._persist_path_posix("/opt/.cargo/bin")
        fish_rc = os.path.join(d, ".config", "fish", "config.fish")
        assert os.path.isfile(fish_rc)
        txt = open(fish_rc, encoding="utf-8").read()
        assert "set -gx PATH '/opt/.cargo/bin' $PATH" in txt
        m._persist_path_posix("/opt/.cargo/bin")  # idempotent
        txt2 = open(fish_rc, encoding="utf-8").read()
        assert txt2 == txt
        assert txt2.count("set -gx PATH") == 1
        assert txt2.count('# plamen-path-json: "/opt/.cargo/bin"') == 1


def test_no_fish_config_created_without_fish(monkeypatch):
    """Don't create a fish config on a machine that doesn't use fish."""
    m = _load()
    with tempfile.TemporaryDirectory() as d:
        _home(monkeypatch, d, shell="/bin/bash")
        m._persist_path_posix("/opt/.foundry/bin")
        assert not os.path.exists(os.path.join(d, ".config", "fish", "config.fish"))


def test_warns_on_persist_failure_no_crash(monkeypatch, capsys):
    """A persist failure must WARN (not silently pass) and must not raise."""
    m = _load()
    with tempfile.TemporaryDirectory() as d:
        # Point HOME at a regular FILE so every rc write fails.
        bogus = os.path.join(d, "not_a_dir")
        open(bogus, "w").close()
        monkeypatch.setenv("HOME", bogus)
        monkeypatch.setenv("USERPROFILE", bogus)
        monkeypatch.setenv("SHELL", "/bin/zsh")
        m._persist_path_posix("/opt/.foundry/bin")  # must not raise
        assert "could not persist PATH" in capsys.readouterr().err


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-q"]))
