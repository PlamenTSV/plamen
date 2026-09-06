"""P3 — EVM dependency preparation + FOUNDRY_PROFILE resolution. _prepare_evm_build
installs the project's REAL deps (forge/soldeer/npm) so remappings resolve — never
mocks. Profile resolution honors an explicit env var, auto-selects only a single
unambiguous non-default profile, and never guesses among several."""
from __future__ import annotations

import importlib
import os
import sys
from pathlib import Path
from unittest import mock


def _rp():
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    return importlib.import_module("recon_prepass")


def _mk(p: Path, body: str = "x"):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body, encoding="utf-8")


# ── FOUNDRY_PROFILE resolution ───────────────────────────────────────────────

def test_profile_honors_env(tmp_path, monkeypatch):
    rp = _rp()
    _mk(tmp_path / "foundry.toml", "[profile.default]\n[profile.ci]\n")
    monkeypatch.setenv("FOUNDRY_PROFILE", "ci")
    assert rp._resolve_foundry_profile_for_recon(tmp_path) == "ci"


def test_profile_default_present_returns_none(tmp_path, monkeypatch):
    rp = _rp()
    monkeypatch.delenv("FOUNDRY_PROFILE", raising=False)
    _mk(tmp_path / "foundry.toml", "[profile.default]\nsrc='src'\n[profile.ci]\n")
    assert rp._resolve_foundry_profile_for_recon(tmp_path) is None


def test_profile_single_nondefault_autoselected(tmp_path, monkeypatch):
    rp = _rp()
    monkeypatch.delenv("FOUNDRY_PROFILE", raising=False)
    _mk(tmp_path / "foundry.toml", "[profile.contracts]\nsrc='src'\nvia-ir=true\n")
    assert rp._resolve_foundry_profile_for_recon(tmp_path) == "contracts"


def test_profile_multiple_nondefault_not_guessed(tmp_path, monkeypatch):
    rp = _rp()
    monkeypatch.delenv("FOUNDRY_PROFILE", raising=False)
    _mk(tmp_path / "foundry.toml", "[profile.a]\n[profile.b]\n")
    assert rp._resolve_foundry_profile_for_recon(tmp_path) is None


# ── dependency preparation ───────────────────────────────────────────────────

def test_soldeer_install_when_deps_empty(tmp_path, monkeypatch):
    rp = _rp()
    root = tmp_path / "proj"
    _mk(root / "foundry.toml", "[dependencies]\n\"@oz\" = \"5.0.0\"\n")
    _mk(root / "src" / "A.sol", "contract A {}\n")  # dependencies/ absent
    calls = []
    monkeypatch.setattr(rp.shutil, "which", lambda n: "/usr/bin/" + n)
    monkeypatch.setattr(rp, "_run_forge", lambda args, cwd, t: (calls.append(args) or (0, "")))
    monkeypatch.setattr(rp, "_run_cmd", lambda *a, **k: 0)
    note = rp._prepare_evm_build(root)
    assert ["soldeer", "install"] in calls
    assert "soldeer install ok" in note


def test_npm_ci_when_lockfile_and_node_modules_absent(tmp_path, monkeypatch):
    rp = _rp()
    # Isolate from the fail-closed supply-chain gate: with a lockfile present but
    # no offline-scanner binary on PATH (a clean CI runner), the gate aborts by
    # design. This test targets npm-vs-pnpm selection, not the gate.
    monkeypatch.setattr(rp, "gate_supply_chain", lambda root: None)
    root = tmp_path / "proj"
    _mk(root / "foundry.toml", "[profile.default]\n")
    _mk(root / "package.json", "{}")
    _mk(root / "package-lock.json", "{}")  # -> npm ci
    _mk(root / "src" / "A.sol", "contract A {}\n")
    cmds = []
    monkeypatch.setattr(rp.shutil, "which", lambda n: "/usr/bin/" + n if n in ("npm",) else None)
    monkeypatch.setattr(rp, "_run_cmd", lambda cmd, cwd, t: (cmds.append(cmd) or 0))
    note = rp._prepare_evm_build(root)
    assert ["npm", "ci"] in cmds
    assert "npm ci ok" in note


def test_pnpm_preferred_when_pnpm_lock(tmp_path, monkeypatch):
    rp = _rp()
    monkeypatch.setattr(rp, "gate_supply_chain", lambda _root: None)
    root = tmp_path / "proj"
    _mk(root / "foundry.toml", "[profile.default]\n")
    _mk(root / "package.json", "{}")
    _mk(root / "pnpm-lock.yaml", "")
    _mk(root / "src" / "A.sol", "contract A {}\n")
    cmds = []
    monkeypatch.setattr(rp.shutil, "which", lambda n: "/usr/bin/" + n)
    monkeypatch.setattr(rp, "_run_cmd", lambda cmd, cwd, t: (cmds.append(cmd) or 0))
    monkeypatch.setattr(rp, "_run_forge", lambda *a, **k: (0, ""))
    note = rp._prepare_evm_build(root)
    assert cmds and cmds[0][0] == "pnpm"


def test_no_install_when_node_modules_present(tmp_path, monkeypatch):
    rp = _rp()
    root = tmp_path / "proj"
    _mk(root / "foundry.toml", "[profile.default]\n")
    _mk(root / "package.json", "{}")
    _mk(root / "node_modules" / "dep" / "index.js", "//")  # already installed
    _mk(root / "src" / "A.sol", "contract A {}\n")
    cmds = []
    monkeypatch.setattr(rp.shutil, "which", lambda n: "/usr/bin/" + n)
    monkeypatch.setattr(rp, "_run_cmd", lambda cmd, cwd, t: (cmds.append(cmd) or 0))
    monkeypatch.setattr(rp, "_run_forge", lambda *a, **k: (0, ""))
    rp._prepare_evm_build(root)
    assert not any(c[0] in ("npm", "yarn", "pnpm") for c in cmds)


def test_prepare_never_raises(tmp_path):
    rp = _rp()
    # non-existent root must not raise
    assert isinstance(rp._prepare_evm_build(tmp_path / "nope"), str)


def test_snapshot_preparation_materializes_declared_deps_before_binding(
    tmp_path, monkeypatch,
):
    rp = _rp()
    root = tmp_path / "proj"
    _mk(root / "foundry.toml", "[profile.default]\nsrc='src'\n")
    _mk(root / "src" / "Vault.sol", "pragma solidity 0.8.21; contract Vault {}\n")
    calls = []
    monkeypatch.setattr(
        rp,
        "_prepare_evm_build",
        lambda build_root: (calls.append(Path(build_root)) or "deps ready"),
    )

    receipt = rp.prepare_snapshot_bound_inputs(
        {"project_root": str(root), "pipeline": "sc", "language": "evm"}
    )

    assert calls == [root.resolve()]
    assert receipt["status"] == "PREPARED"
    assert "deps ready" in receipt["reason"]


def test_snapshot_preparation_does_not_swallow_supply_chain_abort(
    tmp_path, monkeypatch,
):
    rp = _rp()
    root = tmp_path / "proj"
    _mk(root / "foundry.toml", "[profile.default]\n")
    _mk(root / "src" / "Vault.sol", "pragma solidity 0.8.21; contract Vault {}\n")
    monkeypatch.setattr(
        rp,
        "_prepare_evm_build",
        lambda _root: (_ for _ in ()).throw(rp.SupplyChainAbortError("blocked")),
    )

    import pytest
    with pytest.raises(rp.SupplyChainAbortError, match="blocked"):
        rp.prepare_snapshot_bound_inputs(
            {"project_root": str(root), "pipeline": "sc", "language": "evm"}
        )


def test_snapshot_build_root_resolution_is_read_only_for_parent_scope(tmp_path):
    rp = _rp()
    root = tmp_path / "repo"
    scope = root / "contracts"
    _mk(root / "foundry.toml", "[profile.default]\n")
    _mk(scope / "Vault.sol", "pragma solidity 0.8.21; contract Vault {}\n")
    config = {"project_root": str(scope), "pipeline": "sc", "language": "evm"}
    before = sorted(path.relative_to(root) for path in root.rglob("*"))

    resolved = rp.resolve_snapshot_build_root(config)

    assert resolved == root.resolve()
    assert config["_resolved_build_root"] == str(root.resolve())
    assert sorted(path.relative_to(root) for path in root.rglob("*")) == before


def test_snapshot_build_root_resolution_covers_l1_go_parent(tmp_path):
    rp = _rp()
    root = tmp_path / "node"
    scope = root / "consensus"
    _mk(root / "go.mod", "module example.invalid/node\n")
    _mk(scope / "engine.go", "package consensus\n")
    config = {"project_root": str(scope), "pipeline": "l1", "language": "go"}

    assert rp.resolve_snapshot_build_root(config) == root.resolve()
    assert config["_resolved_build_root"] == str(root.resolve())


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-q"]))
