"""Regression: Codex-only install must record the version manifest so the
upgrade-aware editable re-install loop fires.

Bug (pre-fix): the install manifest (`.plamen-manifest.json`, which carries
`version`) was written ONLY inside `_run_symlink_install`, which run_install
gates on `has_claude`. On a Codex-only machine has_claude is False, so the
manifest was never written, `_installed_version()` returned None, and
`_setup_python_deps`' upgrade detection (`_prev_version is not None and
_prev_version != VERSION`) was inert -> the editable `pip install -e` loop was
skipped on a v(N)->v(N+1) upgrade, leaving submodule deps stale.

Fix: `_write_install_manifest()` writes the version to every backend home that
exists (and always PLAMEN_HOME); run_install calls it unconditionally;
`_installed_version()` reads from all backend locations.
"""
import os
import json
import importlib.util
import tempfile

import pytest

_PLAMEN = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "plamen.py")


def _load():
    import sys
    spec = importlib.util.spec_from_file_location("plamen_mod_codex_manifest", _PLAMEN)
    m = importlib.util.module_from_spec(spec)
    saved = sys.argv
    sys.argv = ["plamen.py"]
    try:
        spec.loader.exec_module(m)
    finally:
        sys.argv = saved
    return m


def _patch_homes(monkeypatch, m, claude_home, plamen_home, codex_home):
    """Point the module's backend-home constants at temp dirs and make
    ~/.codex expansion resolve to codex_home."""
    monkeypatch.setattr(m, "CLAUDE_HOME", claude_home, raising=False)
    monkeypatch.setattr(m, "PLAMEN_HOME", plamen_home, raising=False)
    real_expand = m.os.path.expanduser

    def fake_expand(p):
        if p == "~/.codex":
            return codex_home
        return real_expand(p)

    monkeypatch.setattr(m.os.path, "expanduser", fake_expand)


def test_codex_only_manifest_written_and_readable(monkeypatch):
    """Codex records committed authority outside the immutable runtime root."""
    m = _load()
    with tempfile.TemporaryDirectory() as root:
        claude_home = os.path.join(root, ".claude")  # intentionally NOT created
        plamen_home = os.path.join(root, ".plamen")
        codex_home = os.path.join(root, ".codex")
        os.makedirs(plamen_home)
        os.makedirs(codex_home)
        _patch_homes(monkeypatch, m, claude_home, plamen_home, codex_home)

        assert not os.path.isdir(claude_home)
        generation = {
            "schema": m._CODEX_INSTALL_SCHEMA,
            "transaction_id": "a" * 32,
            "source_manifest_sha256": "b" * 64,
            "runtime_manifest_sha256": "c" * 64,
            "adapter_manifest_sha256": "d" * 64,
            "plamen_root": plamen_home,
        }
        monkeypatch.setattr(
            m,
            "_toolchain_runtime_bundle_sha256",
            lambda _root, **_kwargs: "e" * 64,
        )
        m._write_install_manifest(
            package_root=plamen_home,
            committed_generation=generation,
        )

        # Backend metadata is outside the receipt-exact runtime generation.
        codex_manifest = os.path.join(codex_home, m._PLAMEN_MANIFEST)
        plamen_manifest = os.path.join(plamen_home, m._PLAMEN_MANIFEST)
        claude_manifest = os.path.join(claude_home, m._PLAMEN_MANIFEST)
        assert os.path.isfile(codex_manifest)
        assert not os.path.exists(plamen_manifest)
        assert not os.path.isfile(claude_manifest)

        recorded = json.load(open(codex_manifest))
        assert recorded["version"] == m.VERSION
        assert recorded["plamen_home"] == plamen_home
        assert recorded["runtime_bundle_sha256"] == "e" * 64
        assert recorded["committed_generation"] == generation
        # The whole point: version is now discoverable on a Codex-only box.
        assert m._installed_version() == m.VERSION


def test_neither_backend_falls_back_to_plamen_home(monkeypatch):
    """No ~/.claude and no ~/.codex: PLAMEN_HOME manifest still records the
    version (covers CI / staging)."""
    m = _load()
    with tempfile.TemporaryDirectory() as root:
        claude_home = os.path.join(root, ".claude")
        plamen_home = os.path.join(root, ".plamen")
        codex_home = os.path.join(root, ".codex")  # NOT created
        os.makedirs(plamen_home)
        _patch_homes(monkeypatch, m, claude_home, plamen_home, codex_home)

        m._write_install_manifest()
        plamen_manifest = os.path.join(plamen_home, m._PLAMEN_MANIFEST)
        assert os.path.isfile(plamen_manifest)
        assert m._installed_version() == m.VERSION


def test_upgrade_detected_from_codex_manifest(monkeypatch):
    """A prior version stamped on a Codex-only box is detected on the next run,
    enabling the upgrade re-install path that the early-return previously
    bypassed."""
    m = _load()
    with tempfile.TemporaryDirectory() as root:
        claude_home = os.path.join(root, ".claude")
        plamen_home = os.path.join(root, ".plamen")
        codex_home = os.path.join(root, ".codex")
        os.makedirs(plamen_home)
        os.makedirs(codex_home)
        _patch_homes(monkeypatch, m, claude_home, plamen_home, codex_home)

        # Simulate the previously-installed version (e.g. v2.0.0) on Codex home.
        prev = "0.0.0-prev"
        with open(os.path.join(codex_home, m._PLAMEN_MANIFEST), "w") as f:
            json.dump({"plamen_home": plamen_home, "version": prev, "installed": []}, f)

        _prev_version = m._installed_version()
        assert _prev_version == prev
        # This is the exact upgrade predicate from _setup_python_deps line ~1877.
        upgraded = _prev_version is not None and _prev_version != m.VERSION
        assert upgraded is True


def test_claude_home_still_written_when_present(monkeypatch):
    """Dual / Claude-present machines keep getting the ~/.claude manifest."""
    m = _load()
    with tempfile.TemporaryDirectory() as root:
        claude_home = os.path.join(root, ".claude")
        plamen_home = os.path.join(root, ".plamen")
        codex_home = os.path.join(root, ".codex")
        os.makedirs(claude_home)
        os.makedirs(plamen_home)
        _patch_homes(monkeypatch, m, claude_home, plamen_home, codex_home)

        m._write_install_manifest(["item_a", "item_b"])
        claude_manifest = os.path.join(claude_home, m._PLAMEN_MANIFEST)
        assert os.path.isfile(claude_manifest)
        data = json.load(open(claude_manifest))
        assert data["version"] == m.VERSION
        assert data["installed"] == ["item_a", "item_b"]


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
