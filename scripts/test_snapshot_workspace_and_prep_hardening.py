"""Adversarial fixtures for build-context and dependency-prep hardening.

These are intentionally synthetic: every assertion captures a generic build
semantic that must hold across audit targets, not a protocol-specific answer.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

import audit_snapshot as snap
import recon_prepass as rp


@pytest.fixture(autouse=True)
def _isolate_workspace_fixtures_from_host_tool_probes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """These fixtures test source/build closure, not the developer's PATH.

    Runtime-provider identity has a dedicated adversarial suite.  Keeping this
    denominator fixed avoids both host dependence and repeated live CLI probes.
    """

    monkeypatch.setattr(
        snap,
        "_runtime_tool_entries",
        lambda **_kwargs: [
            ("@runtime/test-fixture", b"WORKSPACE_TEST_ONLY")
        ],
    )


def _write(path: Path, text: str = "") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _implementation(root: Path) -> Path:
    for directory in ("scripts", "prompts", "rules", "agents"):
        (root / directory).mkdir(parents=True, exist_ok=True)
    _write(root / "scripts" / "plamen_driver.py", "VERSION = 1\n")
    _write(root / "prompts" / "phase.md", "method v1\n")
    _write(root / "rules" / "rule.md", "rule v1\n")
    return root


def _config(project: Path, *, pipeline: str, language: str) -> dict:
    return {
        "project_root": str(project),
        "scratchpad": str(project / ".scratchpad"),
        "mode": "light",
        "pipeline": pipeline,
        "language": language,
        "cli_backend": "claude",
    }


def test_conventional_generated_name_cannot_hide_production_source(tmp_path: Path):
    project = tmp_path / "project"
    _write(project / "src" / "Vault.sol", "contract Vault {}\n")
    _write(project / "foundry.toml", "[profile.default]\n")
    implementation = _implementation(tmp_path / "plamen")
    config = _config(project, pipeline="sc", language="evm")
    before = snap.build_audit_snapshot(config, implementation)

    # The verifier convention alone is not authority to hide user source.
    _write(project / "out_test" / "ProductionBridge.sol", "contract ProductionBridge {}\n")
    after = snap.build_audit_snapshot(config, implementation)

    assert snap.classify_snapshot(before, after, has_prior_progress=True).state == snap.MISMATCH


def test_generated_only_conventional_tree_remains_outside_snapshot(tmp_path: Path):
    project = tmp_path / "project"
    _write(project / "src" / "Vault.sol", "contract Vault {}\n")
    _write(project / "foundry.toml", "[profile.default]\n")
    implementation = _implementation(tmp_path / "plamen")
    config = _config(project, pipeline="sc", language="evm")
    before = snap.build_audit_snapshot(config, implementation)

    _write(project / "out_test" / "build-info" / "compiler.json", "{}\n")
    _write(project / "out_test" / "H1.t.sol" / "H1.json", "{}\n")
    after = snap.build_audit_snapshot(config, implementation)

    assert snap.classify_snapshot(before, after, has_prior_progress=True).state == snap.MATCH


def test_cargo_outer_workspace_and_external_path_dependency_are_bound(tmp_path: Path):
    workspace = tmp_path / "repo"
    crate = workspace / "crates" / "app"
    shared = tmp_path / "shared-rust"
    _write(
        workspace / "Cargo.toml",
        '[workspace]\nmembers = ["crates/app"]\nresolver = "2"\n',
    )
    _write(workspace / "Cargo.lock", "# lock v1\n")
    _write(
        crate / "Cargo.toml",
        '[package]\nname="app"\nversion="0.1.0"\n'
        '[dependencies]\nshared={path="../../../shared-rust"}\n',
    )
    _write(crate / "src" / "lib.rs", "pub fn app() {}\n")
    _write(shared / "Cargo.toml", '[package]\nname="shared"\nversion="0.1.0"\n')
    shared_source = _write(shared / "src" / "lib.rs", "pub fn shared() -> u8 { 1 }\n")
    config = _config(crate, pipeline="sc", language="soroban")

    assert rp.resolve_snapshot_build_root(config) == workspace.resolve()
    roots = {Path(value).resolve() for value in config["_resolved_build_context_roots"]}
    assert shared.resolve() in roots

    implementation = _implementation(tmp_path / "plamen")
    before = snap.build_audit_snapshot(config, implementation)
    shared_source.write_text("pub fn shared() -> u8 { 2 }\n", encoding="utf-8")
    after = snap.build_audit_snapshot(config, implementation)
    assert snap.classify_snapshot(before, after, has_prior_progress=True).state == snap.MISMATCH


def test_anchor_root_wins_over_nested_program_manifest(tmp_path: Path):
    workspace = tmp_path / "anchor-repo"
    program = workspace / "programs" / "vault"
    _write(workspace / "Anchor.toml", "[workspace]\nmembers = [\"programs/vault\"]\n")
    _write(workspace / "Cargo.toml", '[workspace]\nmembers=["programs/vault"]\n')
    _write(workspace / "Cargo.lock", "# lock\n")
    _write(program / "Cargo.toml", '[package]\nname="vault"\nversion="0.1.0"\n')
    _write(program / "src" / "lib.rs", "pub fn entry() {}\n")
    config = _config(program, pipeline="sc", language="solana")

    assert rp.resolve_snapshot_build_root(config) == workspace.resolve()


def test_cargo_workspace_exclude_preserves_independent_crate_root(tmp_path: Path):
    workspace = tmp_path / "repo"
    crate = workspace / "tools" / "standalone"
    _write(
        workspace / "Cargo.toml",
        '[workspace]\nmembers=[]\nexclude=["tools/standalone"]\n',
    )
    _write(crate / "Cargo.toml", '[package]\nname="standalone"\nversion="0.1.0"\n')
    _write(crate / "src" / "lib.rs", "pub fn tool() {}\n")
    config = _config(crate, pipeline="l1", language="rust")

    assert rp.resolve_snapshot_build_root(config) == crate.resolve()


def test_cargo_local_patch_source_is_in_frozen_closure(tmp_path: Path):
    crate = tmp_path / "crate"
    patched = tmp_path / "patched-crypto"
    _write(
        crate / "Cargo.toml",
        '[package]\nname="crate"\nversion="0.1.0"\n'
        '[patch.crates-io]\ncrypto={path="../patched-crypto"}\n',
    )
    _write(crate / "src" / "lib.rs", "pub fn f() {}\n")
    _write(patched / "Cargo.toml", '[package]\nname="crypto"\nversion="0.1.0"\n')
    _write(patched / "src" / "lib.rs", "pub fn crypto() {}\n")
    config = _config(crate, pipeline="l1", language="rust")

    rp.resolve_snapshot_build_root(config)
    roots = {Path(value).resolve() for value in config["_resolved_build_context_roots"]}
    assert patched.resolve() in roots


def test_go_work_outer_workspace_and_external_use_are_bound(tmp_path: Path):
    workspace = tmp_path / "go-repo"
    node = workspace / "node"
    shared = tmp_path / "shared-go"
    _write(workspace / "go.work", "go 1.22\n\nuse (\n\t./node\n\t../shared-go\n)\n")
    _write(workspace / "go.work.sum", "sum v1\n")
    _write(node / "go.mod", "module example.invalid/node\n\ngo 1.22\n")
    _write(node / "main.go", "package node\n")
    _write(shared / "go.mod", "module example.invalid/shared\n\ngo 1.22\n")
    shared_source = _write(shared / "shared.go", "package shared\nconst V = 1\n")
    config = _config(node, pipeline="l1", language="go")

    assert rp.resolve_snapshot_build_root(config) == workspace.resolve()
    roots = {Path(value).resolve() for value in config["_resolved_build_context_roots"]}
    assert shared.resolve() in roots

    implementation = _implementation(tmp_path / "plamen")
    before = snap.build_audit_snapshot(config, implementation)
    shared_source.write_text("package shared\nconst V = 2\n", encoding="utf-8")
    after = snap.build_audit_snapshot(config, implementation)
    assert snap.classify_snapshot(before, after, has_prior_progress=True).state == snap.MISMATCH


def test_go_mod_external_local_replace_is_in_frozen_closure(tmp_path: Path):
    module = tmp_path / "node"
    replacement = tmp_path / "local-crypto"
    _write(
        module / "go.mod",
        "module example.invalid/node\n\ngo 1.22\n\n"
        "replace example.invalid/crypto => ../local-crypto\n",
    )
    _write(module / "node.go", "package node\n")
    _write(replacement / "go.mod", "module example.invalid/crypto\n\ngo 1.22\n")
    _write(replacement / "crypto.go", "package crypto\n")
    config = _config(module, pipeline="l1", language="go")

    assert rp.resolve_snapshot_build_root(config) == module.resolve()
    roots = {Path(value).resolve() for value in config["_resolved_build_context_roots"]}
    assert replacement.resolve() in roots


def test_move_external_local_dependency_is_in_frozen_closure(tmp_path: Path):
    package = tmp_path / "move-package"
    dependency = tmp_path / "move-shared"
    _write(
        package / "Move.toml",
        '[package]\nname="Package"\nversion="0.0.0"\n'
        '[dependencies]\nShared={local="../move-shared"}\n',
    )
    _write(package / "sources" / "main.move", "module 0x1::main {}\n")
    _write(dependency / "Move.toml", '[package]\nname="Shared"\nversion="0.0.0"\n')
    _write(dependency / "sources" / "shared.move", "module 0x1::shared {}\n")
    config = _config(package, pipeline="sc", language="sui")

    assert rp.resolve_snapshot_build_root(config) == package.resolve()
    roots = {Path(value).resolve() for value in config["_resolved_build_context_roots"]}
    assert dependency.resolve() in roots


def test_missing_declared_local_dependency_fails_resolution_loudly(tmp_path: Path):
    crate = tmp_path / "crate"
    _write(
        crate / "Cargo.toml",
        '[package]\nname="crate"\nversion="0.1.0"\n'
        '[dependencies]\nmissing={path="../does-not-exist"}\n',
    )
    _write(crate / "src" / "lib.rs", "pub fn f() {}\n")
    config = _config(crate, pipeline="sc", language="soroban")

    with pytest.raises(rp.BuildContextResolutionError, match="local Cargo dependency"):
        rp.resolve_snapshot_build_root(config)


def test_foundry_dependency_lib_is_relative_to_effective_build_root(tmp_path: Path):
    repo = tmp_path / "repo"
    scope = repo / "contracts"
    _write(repo / "foundry.toml", '[profile.default]\nsrc="contracts"\nlibs=["lib"]\n')
    _write(scope / "Vault.sol", "contract Vault {}\n")
    _write(scope / "lib" / "SolvencyMath.sol", "library SolvencyMath {}\n")
    _write(repo / "lib" / "dep" / "Dependency.sol", "library Dependency {}\n")

    rels = {
        path.relative_to(scope).as_posix()
        for path in rp._production_source_files(scope, (".sol",))
    }
    assert "Vault.sol" in rels
    assert "lib/SolvencyMath.sol" in rels
    assert not any("Dependency.sol" in value for value in rels)


def test_foundry_custom_lib_config_does_not_hide_unconfigured_root_lib(tmp_path: Path):
    repo = tmp_path / "repo"
    _write(repo / "foundry.toml", '[profile.default]\nsrc="src"\nlibs=["vendor"]\n')
    _write(repo / "src" / "Vault.sol", "contract Vault {}\n")
    _write(repo / "lib" / "FirstParty.sol", "contract FirstParty {}\n")
    _write(repo / "vendor" / "dep" / "Dependency.sol", "library Dependency {}\n")

    rels = {
        path.relative_to(repo).as_posix()
        for path in rp._production_source_files(repo, (".sol",))
    }
    assert "lib/FirstParty.sol" in rels
    assert "vendor/dep/Dependency.sol" not in rels


def test_solc_range_selection_never_uses_exclusive_upper_bound(tmp_path: Path):
    source = _write(
        tmp_path / "Vault.sol",
        "pragma solidity >=0.8.19 <0.8.21; contract Vault {}\n",
    )
    assert rp._detect_solc_version(
        [source], available_versions=("0.8.19", "0.8.20", "0.8.21")
    ) == "0.8.20"


def test_solc_incompatible_exact_and_range_degrades_to_auto(tmp_path: Path):
    exact = _write(tmp_path / "Exact.sol", "pragma solidity 0.8.21; contract Exact {}\n")
    bounded = _write(
        tmp_path / "Bounded.sol",
        "pragma solidity >=0.8.19 <0.8.21; contract Bounded {}\n",
    )
    assert rp._detect_solc_version(
        [exact, bounded], available_versions=("0.8.19", "0.8.20", "0.8.21")
    ) is None


def test_solc_incompatible_exact_pins_degrade_to_auto(tmp_path: Path):
    first = _write(
        tmp_path / "First.sol",
        "pragma solidity 0.8.19; contract First {}\n",
    )
    second = _write(
        tmp_path / "Second.sol",
        "pragma solidity 0.8.20; contract Second {}\n",
    )

    assert rp._detect_solc_version(
        [first, second], available_versions=("0.8.19", "0.8.20")
    ) is None


def test_package_json_without_lock_never_runs_npm_install(tmp_path: Path, monkeypatch):
    root = tmp_path / "hardhat"
    _write(root / "package.json", '{"scripts":{"build":"hardhat compile"}}\n')
    _write(root / "hardhat.config.js", "module.exports = {}\n")
    _write(root / "contracts" / "Vault.sol", "pragma solidity ^0.8.20; contract Vault {}\n")
    calls: list[list[str]] = []
    monkeypatch.setattr(rp, "gate_supply_chain", lambda _root: None)
    monkeypatch.setattr(rp.shutil, "which", lambda _name: "/tool")
    monkeypatch.setattr(
        rp,
        "_run_cmd",
        lambda args, _cwd, _timeout: (calls.append(list(args)) or 0),
    )
    monkeypatch.setattr(rp, "_run_hardened", lambda *_args, **_kwargs: (0, ""))

    receipt_config = _config(root, pipeline="sc", language="evm")
    receipt = rp.prepare_snapshot_bound_inputs(receipt_config)

    assert not any(call and call[0] in {"npm", "pnpm", "yarn", "bun"} for call in calls)
    assert receipt["status"] == "DEGRADED"
    assert "lock" in receipt["reason"].lower()
    assert any(
        "NO_IMMUTABLE_JS_LOCK" in item
        for item in receipt_config["_snapshot_build_input_limitations"]
    )
    first_component = snap._source_component(receipt_config)
    assert any(
        "BUILD_INPUT_PREPARATION_DEGRADED" in item
        for item in first_component["coverage_limitations"]
    )
    resumed_config = _config(root, pipeline="sc", language="evm")
    rp.resolve_snapshot_build_root(resumed_config)
    assert snap._source_component(resumed_config)["digest"] == first_component["digest"]


def test_package_lock_uses_npm_ci_never_npm_install(tmp_path: Path, monkeypatch):
    root = tmp_path / "hardhat"
    _write(root / "package.json", '{}\n')
    _write(root / "package-lock.json", '{"lockfileVersion":3}\n')
    _write(root / "hardhat.config.js", "module.exports = {}\n")
    _write(root / "contracts" / "Vault.sol", "pragma solidity ^0.8.20; contract Vault {}\n")
    calls: list[list[str]] = []
    monkeypatch.setattr(rp, "gate_supply_chain", lambda _root: None)
    monkeypatch.setattr(rp.shutil, "which", lambda _name: "/tool")
    monkeypatch.setattr(
        rp,
        "_run_cmd",
        lambda args, _cwd, _timeout: (calls.append(list(args)) or 0),
    )
    monkeypatch.setattr(rp, "_run_hardened", lambda *_args, **_kwargs: (0, ""))

    receipt = rp.prepare_snapshot_bound_inputs(
        _config(root, pipeline="sc", language="evm")
    )

    assert ["npm", "ci"] in calls
    assert ["npm", "install"] not in calls
    assert receipt["status"] == "PREPARED"


def test_ambiguous_javascript_locks_never_guess_an_installer(
    tmp_path: Path, monkeypatch
):
    root = tmp_path / "hardhat"
    _write(root / "package.json", '{}\n')
    _write(root / "package-lock.json", '{"lockfileVersion":3}\n')
    _write(root / "pnpm-lock.yaml", "lockfileVersion: '9.0'\n")
    _write(root / "hardhat.config.js", "module.exports = {}\n")
    _write(
        root / "contracts" / "Vault.sol",
        "pragma solidity ^0.8.20; contract Vault {}\n",
    )
    calls: list[list[str]] = []
    monkeypatch.setattr(rp, "gate_supply_chain", lambda _root: None)
    monkeypatch.setattr(rp.shutil, "which", lambda _name: "/tool")
    monkeypatch.setattr(
        rp,
        "_run_cmd",
        lambda args, _cwd, _timeout: (calls.append(list(args)) or 0),
    )
    monkeypatch.setattr(rp, "_run_hardened", lambda *_args, **_kwargs: (0, ""))
    config = _config(root, pipeline="sc", language="evm")

    receipt = rp.prepare_snapshot_bound_inputs(config)

    assert not any(call and call[0] in {"npm", "pnpm", "yarn"} for call in calls)
    assert receipt["status"] == "DEGRADED"
    assert "AMBIGUOUS_JS_LOCKS" in receipt["reason"]
    assert any(
        "AMBIGUOUS_JS_LOCKS" in item
        for item in config["_snapshot_build_input_limitations"]
    )


def test_package_manager_field_resolves_multiple_lock_authorities(
    tmp_path: Path, monkeypatch
):
    root = tmp_path / "hardhat"
    _write(root / "package.json", '{"packageManager":"pnpm@9.1.0"}\n')
    _write(root / "package-lock.json", '{"lockfileVersion":3}\n')
    _write(root / "pnpm-lock.yaml", "lockfileVersion: '9.0'\n")
    _write(root / "hardhat.config.js", "module.exports = {}\n")
    _write(
        root / "contracts" / "Vault.sol",
        "pragma solidity ^0.8.20; contract Vault {}\n",
    )
    calls: list[list[str]] = []
    monkeypatch.setattr(rp, "gate_supply_chain", lambda _root: None)
    monkeypatch.setattr(rp.shutil, "which", lambda _name: "/tool")
    monkeypatch.setattr(
        rp,
        "_run_cmd",
        lambda args, _cwd, _timeout: (calls.append(list(args)) or 0),
    )
    monkeypatch.setattr(rp, "_run_hardened", lambda *_args, **_kwargs: (0, ""))

    receipt = rp.prepare_snapshot_bound_inputs(
        _config(root, pipeline="sc", language="evm")
    )

    assert ["pnpm", "install", "--frozen-lockfile"] in calls
    assert not any(call and call[0] == "npm" for call in calls)
    assert receipt["status"] == "PREPARED"


def test_project_local_backend_controls_are_snapshot_bound(tmp_path: Path):
    project = tmp_path / "project"
    _write(project / "src" / "Vault.sol", "contract Vault {}\n")
    _write(project / "foundry.toml", "[profile.default]\n")
    control = _write(project / ".claude" / "settings.json", '{"model":"legacy"}\n')
    implementation = _implementation(tmp_path / "plamen")
    config = _config(project, pipeline="sc", language="evm")
    rp.resolve_snapshot_build_root(config)

    before = snap.build_audit_snapshot(config, implementation)
    control.write_text('{"model":"changed"}\n', encoding="utf-8")
    after = snap.build_audit_snapshot(config, implementation)

    assert snap.classify_snapshot(before, after, has_prior_progress=True).state == snap.MISMATCH


def test_owned_claude_scheduler_lock_is_runtime_not_source_input(tmp_path: Path):
    """P0-AN red fixture from the frozen report-stage failure."""
    project = tmp_path / "project"
    _write(project / "src" / "Vault.sol", "contract Vault {}\n")
    _write(project / "foundry.toml", "[profile.default]\n")
    scratchpad = project / ".scratchpad"
    scratchpad.mkdir()
    implementation = _implementation(tmp_path / "plamen")
    config = _config(project, pipeline="sc", language="evm")
    rp.resolve_snapshot_build_root(config)

    contract = snap.prepare_backend_runtime_contract(config, scratchpad)
    assert contract["ephemeral_paths"] == [".claude/scheduled_tasks.lock"]
    before = snap.build_audit_snapshot(config, implementation)
    _write(project / ".claude" / "scheduled_tasks.lock", "runtime-only\n")
    after = snap.build_audit_snapshot(config, implementation)

    assert snap.classify_snapshot(before, after, has_prior_progress=True).state == snap.MATCH


def test_unknown_file_beside_owned_runtime_lock_remains_snapshot_bound(
    tmp_path: Path,
):
    project = tmp_path / "project"
    _write(project / "src" / "Vault.sol", "contract Vault {}\n")
    scratchpad = project / ".scratchpad"
    scratchpad.mkdir()
    implementation = _implementation(tmp_path / "plamen")
    config = _config(project, pipeline="sc", language="evm")
    rp.resolve_snapshot_build_root(config)
    snap.prepare_backend_runtime_contract(config, scratchpad)
    before = snap.build_audit_snapshot(config, implementation)

    _write(project / ".claude" / "unowned-runtime-looking.json", "{}\n")
    after = snap.build_audit_snapshot(config, implementation)

    assert snap.classify_snapshot(before, after, has_prior_progress=True).state == snap.MISMATCH


def test_preexisting_scheduler_lock_is_not_silently_claimed_as_runtime(
    tmp_path: Path,
):
    project = tmp_path / "project"
    _write(project / "src" / "Vault.sol", "contract Vault {}\n")
    lock = _write(project / ".claude" / "scheduled_tasks.lock", "user-input\n")
    scratchpad = project / ".scratchpad"
    scratchpad.mkdir()
    implementation = _implementation(tmp_path / "plamen")
    config = _config(project, pipeline="sc", language="evm")
    rp.resolve_snapshot_build_root(config)

    contract = snap.prepare_backend_runtime_contract(config, scratchpad)
    assert contract["ephemeral_paths"] == []
    assert contract["preexisting_bound_inputs"][0]["path"] == (
        ".claude/scheduled_tasks.lock"
    )
    before = snap.build_audit_snapshot(config, implementation)
    lock.write_text("changed\n", encoding="utf-8")
    after = snap.build_audit_snapshot(config, implementation)

    assert snap.classify_snapshot(before, after, has_prior_progress=True).state == snap.MISMATCH


@pytest.mark.parametrize("exec_mode", ["pty", "headless"])
def test_backend_runtime_contract_reloads_identically_across_claude_exec_modes(
    tmp_path: Path, exec_mode: str,
):
    project = tmp_path / "project"
    _write(project / "src" / "Vault.sol", "contract Vault {}\n")
    scratchpad = project / ".scratchpad"
    scratchpad.mkdir()
    implementation = _implementation(tmp_path / "plamen")
    initial = _config(project, pipeline="sc", language="evm")
    initial["claude_exec_mode"] = exec_mode
    rp.resolve_snapshot_build_root(initial)
    contract = snap.prepare_backend_runtime_contract(initial, scratchpad)
    before = snap.build_audit_snapshot(initial, implementation)
    _write(project / ".claude" / "scheduled_tasks.lock", "runtime-a\n")

    resumed = _config(project, pipeline="sc", language="evm")
    resumed["claude_exec_mode"] = exec_mode
    rp.resolve_snapshot_build_root(resumed)
    assert snap.prepare_backend_runtime_contract(resumed, scratchpad) == contract
    _write(project / ".claude" / "scheduled_tasks.lock", "runtime-b\n")
    after = snap.build_audit_snapshot(resumed, implementation)

    assert snap.classify_snapshot(before, after, has_prior_progress=True).state == snap.MATCH


def test_backend_runtime_contract_corruption_fails_closed_without_rewrite(
    tmp_path: Path,
):
    project = tmp_path / "project"
    _write(project / "src" / "Vault.sol", "contract Vault {}\n")
    scratchpad = project / ".scratchpad"
    scratchpad.mkdir()
    config = _config(project, pipeline="sc", language="evm")
    receipt = scratchpad / "backend_runtime_contract.json"
    receipt.write_text("{not-json", encoding="utf-8")
    before = receipt.read_bytes()

    with pytest.raises(snap.SnapshotInputError, match="receipt is unreadable"):
        snap.prepare_backend_runtime_contract(config, scratchpad)

    assert receipt.read_bytes() == before


@pytest.mark.parametrize(
    "mutation",
    [
        lambda row: row.update(isolation_mode="INVENTED_MODE"),
        lambda row: row.update(ephemeral_paths=[".claude/unknown.lock"]),
        lambda row: row.update(preexisting_bound_inputs=[
            {
                "path": ".claude/scheduled_tasks.lock",
                "bytes": 0,
                "sha256": "0" * 64,
            },
            {
                "path": ".claude/scheduled_tasks.lock",
                "bytes": 0,
                "sha256": "0" * 64,
            },
        ], ephemeral_paths=[]),
    ],
)
def test_backend_runtime_contract_tampering_fails_closed(
    tmp_path: Path, mutation,
):
    project = tmp_path / "project"
    _write(project / "src" / "Vault.sol", "contract Vault {}\n")
    scratchpad = project / ".scratchpad"
    scratchpad.mkdir()
    config = _config(project, pipeline="sc", language="evm")
    snap.prepare_backend_runtime_contract(config, scratchpad)
    receipt = scratchpad / "backend_runtime_contract.json"
    payload = json.loads(receipt.read_text(encoding="utf-8"))
    mutation(payload)
    receipt.write_text(json.dumps(payload), encoding="utf-8")

    fresh_config = _config(project, pipeline="sc", language="evm")
    with pytest.raises(snap.SnapshotInputError):
        snap.prepare_backend_runtime_contract(fresh_config, scratchpad)


def test_preexisting_runtime_candidate_symlink_fails_closed(tmp_path: Path):
    project = tmp_path / "project"
    _write(project / "src" / "Vault.sol", "contract Vault {}\n")
    target = _write(tmp_path / "outside.lock", "outside\n")
    link = project / ".claude" / "scheduled_tasks.lock"
    link.parent.mkdir(parents=True)
    try:
        os.symlink(target, link)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"symlink creation unavailable: {exc}")
    scratchpad = project / ".scratchpad"
    scratchpad.mkdir()
    config = _config(project, pipeline="sc", language="evm")

    with pytest.raises(snap.SnapshotInputError, match="regular local file"):
        snap.prepare_backend_runtime_contract(config, scratchpad)


def test_preexisting_runtime_candidate_is_size_bounded(tmp_path: Path):
    project = tmp_path / "project"
    _write(project / "src" / "Vault.sol", "contract Vault {}\n")
    lock = project / ".claude" / "scheduled_tasks.lock"
    lock.parent.mkdir(parents=True)
    lock.write_bytes(b"x" * (snap._BACKEND_RUNTIME_MAX_FILE_BYTES + 1))
    scratchpad = project / ".scratchpad"
    scratchpad.mkdir()
    config = _config(project, pipeline="sc", language="evm")

    with pytest.raises(snap.SnapshotInputError, match="bounded size"):
        snap.prepare_backend_runtime_contract(config, scratchpad)


def test_ephemeral_runtime_candidate_is_size_bounded_when_it_appears(
    tmp_path: Path,
):
    project = tmp_path / "project"
    _write(project / "src" / "Vault.sol", "contract Vault {}\n")
    _write(project / "foundry.toml", "[profile.default]\n")
    scratchpad = project / ".scratchpad"
    scratchpad.mkdir()
    implementation = _implementation(tmp_path / "plamen")
    config = _config(project, pipeline="sc", language="evm")
    rp.resolve_snapshot_build_root(config)
    snap.prepare_backend_runtime_contract(config, scratchpad)
    snap.build_audit_snapshot(config, implementation)
    lock = project / ".claude" / "scheduled_tasks.lock"
    lock.parent.mkdir(parents=True)
    lock.write_bytes(b"x" * (snap._BACKEND_RUNTIME_MAX_FILE_BYTES + 1))

    with pytest.raises(snap.SnapshotInputError, match="bounded size"):
        snap.build_audit_snapshot(config, implementation)


def test_nested_cargo_vendor_source_is_bound_even_when_context_walk_skips_vendor(
    tmp_path: Path,
):
    crate = tmp_path / "crate"
    vendor = crate / "vendor" / "local-crypto"
    _write(
        crate / "Cargo.toml",
        '[package]\nname="crate"\nversion="0.1.0"\n'
        '[dependencies]\ncrypto={path="vendor/local-crypto"}\n',
    )
    _write(crate / "src" / "lib.rs", "pub fn f() {}\n")
    _write(vendor / "Cargo.toml", '[package]\nname="crypto"\nversion="0.1.0"\n')
    source = _write(vendor / "src" / "lib.rs", "pub const V:u8=1;\n")
    config = _config(crate, pipeline="l1", language="rust")
    rp.resolve_snapshot_build_root(config)
    implementation = _implementation(tmp_path / "plamen")

    before = snap.build_audit_snapshot(config, implementation)
    source.write_text("pub const V:u8=2;\n", encoding="utf-8")
    after = snap.build_audit_snapshot(config, implementation)

    assert snap.classify_snapshot(before, after, has_prior_progress=True).state == snap.MISMATCH


def test_cargo_config_vendored_source_is_in_compiled_dependency_closure(tmp_path: Path):
    crate = tmp_path / "crate"
    vendor = crate / "third_party" / "vendor"
    _write(crate / "Cargo.toml", '[package]\nname="crate"\nversion="0.1.0"\n')
    _write(crate / "src" / "lib.rs", "pub fn f() {}\n")
    _write(
        crate / ".cargo" / "config.toml",
        '[source.crates-io]\nreplace-with="vendored-sources"\n'
        '[source.vendored-sources]\ndirectory="third_party/vendor"\n',
    )
    _write(vendor / "dep" / "Cargo.toml", '[package]\nname="dep"\nversion="1.0.0"\n')
    dep = _write(vendor / "dep" / "src" / "lib.rs", "pub const V:u8=1;\n")
    config = _config(crate, pipeline="l1", language="rust")
    rp.resolve_snapshot_build_root(config)
    implementation = _implementation(tmp_path / "plamen")

    before = snap.build_audit_snapshot(config, implementation)
    dep.write_text("pub const V:u8=2;\n", encoding="utf-8")
    after = snap.build_audit_snapshot(config, implementation)

    assert snap.classify_snapshot(before, after, has_prior_progress=True).state == snap.MISMATCH


def test_foundry_external_lib_and_remapping_target_are_bound(tmp_path: Path):
    repo = tmp_path / "repo"
    shared = tmp_path / "shared-solidity"
    _write(
        repo / "foundry.toml",
        '[profile.default]\nsrc="src"\nlibs=["../shared-solidity"]\n',
    )
    _write(repo / "remappings.txt", "@local/=../shared-solidity/src/\n")
    _write(repo / "src" / "Vault.sol", 'import "@local/Math.sol"; contract Vault {}\n')
    dep = _write(shared / "src" / "Math.sol", "library Math { }\n")
    config = _config(repo, pipeline="sc", language="evm")
    rp.resolve_snapshot_build_root(config)
    implementation = _implementation(tmp_path / "plamen")

    before = snap.build_audit_snapshot(config, implementation)
    dep.write_text("library Math { function x() internal {} }\n", encoding="utf-8")
    after = snap.build_audit_snapshot(config, implementation)

    assert snap.classify_snapshot(before, after, has_prior_progress=True).state == snap.MISMATCH


def test_windows_long_dependency_file_is_hashed_via_extended_path(tmp_path: Path):
    if os.name != "nt":
        return
    project = tmp_path / "project"
    _write(
        project / "foundry.toml",
        '[profile.default]\nsrc="src"\nlibs=["node_modules"]\n',
    )
    _write(project / "src" / "Vault.sol", "contract Vault {}\n")
    long_file = (
        project
        / "node_modules"
        / "@dependency"
        / ("generated-" + "a" * 70)
        / ("factories-" + "b" * 70)
        / ("Dependency__factory-" + "c" * 60 + ".d.ts")
    )
    extended = snap._filesystem_io_path(long_file)
    extended.parent.mkdir(parents=True)
    extended.write_text("export declare class Dependency__factory {}\n", encoding="utf-8")
    assert len(str(long_file.resolve(strict=False))) > 260

    config = _config(project, pipeline="sc", language="evm")
    implementation = _implementation(tmp_path / "plamen")
    snapshot = snap.build_audit_snapshot(config, implementation)

    assert snapshot["components"]["source_scope"]["file_count"] >= 3


def test_distinct_configured_scratchpad_is_not_self_bound(tmp_path: Path):
    project = tmp_path / "project"
    _write(project / "foundry.toml", '[profile.default]\nsrc="src"\n')
    _write(project / "src" / "Vault.sol", "contract Vault {}\n")
    run = project / ".scratchpad-plamen-e2e-opus5"
    _write(run / "config.json", "{}\n")
    log = _write(run / "driver.stderr.log", "starting\n")
    config = _config(project, pipeline="sc", language="evm")
    config["scratchpad"] = str(run)
    implementation = _implementation(tmp_path / "plamen")

    before = snap.build_audit_snapshot(config, implementation)
    log.write_text("starting\nphase one\n", encoding="utf-8")
    _write(run / "_v2_checkpoint.json", '{"phase":"recon"}\n')
    after = snap.build_audit_snapshot(config, implementation)

    assert snap.classify_snapshot(before, after, has_prior_progress=True).state == snap.MATCH


def test_npm_workspace_file_link_and_installed_tree_are_bound(tmp_path: Path):
    repo = tmp_path / "repo"
    linked = tmp_path / "linked-js"
    _write(
        repo / "package.json",
        '{"workspaces":["packages/*"],"dependencies":'
        '{"linked":"file:../linked-js"}}\n',
    )
    _write(repo / "package-lock.json", '{"lockfileVersion":3}\n')
    _write(repo / "hardhat.config.js", "module.exports={}\n")
    _write(repo / "contracts" / "Vault.sol", "contract Vault {}\n")
    workspace_source = _write(
        repo / "packages" / "math" / "src" / "index.js", "module.exports=1\n"
    )
    _write(repo / "packages" / "math" / "package.json", '{"name":"math"}\n')
    _write(linked / "package.json", '{"name":"linked"}\n')
    linked_source = _write(linked / "index.js", "module.exports=1\n")
    installed = _write(
        repo / "node_modules" / "locked-dep" / "index.js", "module.exports=1\n"
    )
    config = _config(repo, pipeline="sc", language="evm")
    rp.resolve_snapshot_build_root(config)
    implementation = _implementation(tmp_path / "plamen")
    before = snap.build_audit_snapshot(config, implementation)

    for path in (workspace_source, linked_source, installed):
        original = path.read_text(encoding="utf-8")
        path.write_text(original + "// drift\n", encoding="utf-8")
        after = snap.build_audit_snapshot(config, implementation)
        assert snap.classify_snapshot(before, after, has_prior_progress=True).state == snap.MISMATCH
        path.write_text(original, encoding="utf-8")


def test_compiled_dependency_parent_child_roots_are_walked_once_in_any_order(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    """A remapping below node_modules must not replay its complete subtree."""
    project = tmp_path / "project"
    parent = project / "node_modules"
    child = parent / "@scope" / "nested"
    _write(project / "foundry.toml", '[profile.default]\nsrc="src"\n')
    _write(project / "src" / "Vault.sol", "contract Vault {}\n")
    _write(parent / "top-level.js", "module.exports=1\n")
    _write(child / "index.js", "module.exports=2\n")
    monkeypatch.setattr(snap, "_git_head", lambda _root: "0" * 40)
    monkeypatch.setattr(snap, "_git_submodule_state", lambda _root: b"")

    def inventory(declarations: list[Path]):
        config = _config(project, pipeline="sc", language="evm")
        config["_resolved_build_root"] = str(project)
        config["_resolved_compiled_dependency_roots"] = [
            str(path) for path in declarations
        ]
        return snap._build_context_entries(config, project.resolve())

    child_first = inventory([child, parent])
    parent_first = inventory([parent, child])

    assert child_first == parent_first
    compiled_names = [
        name
        for name, _payload in child_first
        if name.startswith("compiled_dependency/")
    ]
    assert compiled_names == [
        "compiled_dependency/0/top-level.js",
        "compiled_dependency/0/@scope/nested/index.js",
    ]
    declaration_payload = next(
        payload
        for name, payload in child_first
        if name == "@compiled_dependency_declarations"
    )
    assert json.loads(declaration_payload) == [
        {"content_relation": ".", "content_root": 0},
        {"content_relation": "@scope/nested", "content_root": 0},
    ]


@pytest.mark.parametrize(
    "skipped_directory",
    [".git", ".cache", "target", "out", "artifacts"],
)
def test_explicit_root_below_compiled_walk_skip_remains_independently_bound(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    skipped_directory: str,
):
    """Lexical ancestry is not coverage when the outer walker prunes a path."""
    project = tmp_path / "project"
    parent = project / "node_modules"
    child = parent / skipped_directory / "explicit-compiler-input"
    _write(project / "foundry.toml", '[profile.default]\nsrc="src"\n')
    _write(project / "src" / "Vault.sol", "contract Vault {}\n")
    _write(parent / "visible.js", "module.exports=1\n")
    nested = _write(child / "index.js", "module.exports=1\n")
    monkeypatch.setattr(snap, "_git_head", lambda _root: "0" * 40)
    monkeypatch.setattr(snap, "_git_submodule_state", lambda _root: b"")

    def inventory(declarations: list[Path]):
        config = _config(project, pipeline="sc", language="evm")
        config["_resolved_build_root"] = str(project)
        config["_resolved_compiled_dependency_roots"] = [
            str(path) for path in declarations
        ]
        return config, snap._build_context_entries(config, project.resolve())

    config, parent_first = inventory([parent, child])
    _reversed_config, child_first = inventory([child, parent])

    assert parent_first == child_first
    assert [
        name
        for name, _payload in parent_first
        if name.startswith("compiled_dependency/")
    ] == [
        "compiled_dependency/0/visible.js",
        "compiled_dependency/1/index.js",
    ]
    declaration_payload = next(
        payload
        for name, payload in parent_first
        if name == "@compiled_dependency_declarations"
    )
    assert json.loads(declaration_payload) == [
        {"content_relation": ".", "content_root": 0},
        {"content_relation": ".", "content_root": 1},
    ]

    implementation = _implementation(tmp_path / "plamen")
    before = snap.build_audit_snapshot(config, implementation)
    nested.write_text("module.exports=222\n", encoding="utf-8")
    after = snap.build_audit_snapshot(config, implementation)
    assert snap.classify_snapshot(
        before, after, has_prior_progress=True
    ).state == snap.MISMATCH


def test_outer_compiled_dependency_root_still_binds_arbitrary_nested_mutation(
    tmp_path: Path,
):
    """Deduplication must retain full node_modules byte authority."""
    project = tmp_path / "project"
    parent = project / "node_modules"
    declared_child = parent / "@scope" / "compiler-remapping"
    _write(project / "foundry.toml", '[profile.default]\nsrc="src"\n')
    _write(project / "src" / "Vault.sol", "contract Vault {}\n")
    _write(declared_child / "index.js", "module.exports=1\n")
    arbitrary = _write(
        parent / "unrelated-package" / "index.js", "module.exports=1\n"
    )
    implementation = _implementation(tmp_path / "plamen")
    config = _config(project, pipeline="sc", language="evm")
    config["_resolved_build_root"] = str(project)
    config["_resolved_compiled_dependency_roots"] = [
        str(declared_child),
        str(parent),
    ]

    before = snap.build_audit_snapshot(config, implementation)
    arbitrary.write_text("module.exports=2\n", encoding="utf-8")
    after = snap.build_audit_snapshot(config, implementation)

    verdict = snap.classify_snapshot(before, after, has_prior_progress=True)
    assert verdict.state == snap.MISMATCH
    assert verdict.changed_components == ("source_scope",)


def test_sibling_compiled_dependency_roots_remain_separate_and_order_stable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    project = tmp_path / "project"
    first = tmp_path / "dependency-a"
    second = tmp_path / "dependency-b"
    _write(project / "foundry.toml", '[profile.default]\nsrc="src"\n')
    _write(project / "src" / "Vault.sol", "contract Vault {}\n")
    _write(first / "index.js", "module.exports='a'\n")
    _write(second / "index.js", "module.exports='b'\n")
    monkeypatch.setattr(snap, "_git_head", lambda _root: "0" * 40)
    monkeypatch.setattr(snap, "_git_submodule_state", lambda _root: b"")

    def inventory(declarations: list[Path]):
        config = _config(project, pipeline="sc", language="evm")
        config["_resolved_build_root"] = str(project)
        config["_resolved_compiled_dependency_roots"] = [
            str(path) for path in declarations
        ]
        return snap._build_context_entries(config, project.resolve())

    forward = inventory([first, second])
    reverse = inventory([second, first])

    assert forward == reverse
    assert [
        name for name, _payload in forward
        if name.startswith("compiled_dependency/")
    ] == [
        "compiled_dependency/0/index.js",
        "compiled_dependency/1/index.js",
    ]


@pytest.mark.skipif(os.name != "nt", reason="Windows case-folded path identity")
def test_windows_compiled_dependency_root_case_alias_is_walked_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    project = tmp_path / "Project"
    dependency = project / "node_modules"
    _write(project / "foundry.toml", '[profile.default]\nsrc="src"\n')
    _write(project / "src" / "Vault.sol", "contract Vault {}\n")
    _write(dependency / "package" / "index.js", "module.exports=1\n")
    monkeypatch.setattr(snap, "_git_head", lambda _root: "0" * 40)
    monkeypatch.setattr(snap, "_git_submodule_state", lambda _root: b"")
    config = _config(project, pipeline="sc", language="evm")
    config["_resolved_build_root"] = str(project)
    config["_resolved_compiled_dependency_roots"] = [
        str(dependency),
        str(dependency).swapcase(),
    ]

    entries = snap._build_context_entries(config, project.resolve())

    assert [
        name for name, _payload in entries
        if name.startswith("compiled_dependency/")
    ] == ["compiled_dependency/0/package/index.js"]
    declaration_payload = next(
        payload
        for name, payload in entries
        if name == "@compiled_dependency_declarations"
    )
    assert json.loads(declaration_payload) == [
        {"content_relation": ".", "content_root": 0}
    ]


@pytest.mark.skipif(os.name != "nt", reason="Windows skip names are case-insensitive")
@pytest.mark.parametrize(
    "skipped_directory",
    [".GIT", ".CACHE", "TARGET", "OUT", "ARTIFACTS"],
)
def test_windows_case_alias_of_compiled_skip_requires_explicit_child_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    skipped_directory: str,
):
    project = tmp_path / "Project"
    parent = project / "node_modules"
    child = parent / skipped_directory / "explicit"
    _write(project / "foundry.toml", '[profile.default]\nsrc="src"\n')
    _write(project / "src" / "Vault.sol", "contract Vault {}\n")
    _write(child / "index.js", "module.exports=1\n")
    monkeypatch.setattr(snap, "_git_head", lambda _root: "0" * 40)
    monkeypatch.setattr(snap, "_git_submodule_state", lambda _root: b"")
    config = _config(project, pipeline="sc", language="evm")
    config["_resolved_build_root"] = str(project)
    config["_resolved_compiled_dependency_roots"] = [str(parent), str(child)]

    entries = snap._build_context_entries(config, project.resolve())

    assert [
        name for name, _payload in entries
        if name.startswith("compiled_dependency/")
    ] == ["compiled_dependency/1/index.js"]


def test_daml_custom_source_and_local_dar_are_bound(tmp_path: Path):
    project = tmp_path / "daml-project"
    shared = tmp_path / "daml-shared"
    _write(
        project / "daml.yaml",
        "sdk-version: 2.9.0\nname: app\nversion: 0.0.1\n"
        "source: ../daml-shared/src\ndata-dependencies:\n"
        "  - ../daml-shared/archive/shared.dar\n",
    )
    source = _write(shared / "src" / "Main.daml", "module Main where\n")
    dar = _write(shared / "archive" / "shared.dar", "dar-v1\n")
    config = _config(project, pipeline="sc", language="daml")
    rp.resolve_snapshot_build_root(config)
    implementation = _implementation(tmp_path / "plamen")
    before = snap.build_audit_snapshot(config, implementation)

    source.write_text("module Main where\nx = 1\n", encoding="utf-8")
    after_source = snap.build_audit_snapshot(config, implementation)
    assert snap.classify_snapshot(before, after_source, has_prior_progress=True).state == snap.MISMATCH
    source.write_text("module Main where\n", encoding="utf-8")
    dar.write_text("dar-v2\n", encoding="utf-8")
    after_dar = snap.build_audit_snapshot(config, implementation)
    assert snap.classify_snapshot(before, after_dar, has_prior_progress=True).state == snap.MISMATCH


def test_build_closure_is_explicitly_approximate_and_js_state_is_durable(
    tmp_path: Path,
):
    project = tmp_path / "hardhat"
    _write(project / "package.json", '{}\n')
    _write(project / "package-lock.json", '{"lockfileVersion":3}\n')
    _write(project / "hardhat.config.js", "module.exports={}\n")
    _write(project / "contracts" / "Vault.sol", "contract Vault {}\n")

    fresh = _config(project, pipeline="sc", language="evm")
    rp.resolve_snapshot_build_root(fresh)
    assert any(
        "MECHANICALLY_APPROXIMATED_BUILD_CLOSURE" in item
        for item in fresh["_snapshot_build_input_limitations"]
    )
    assert any(
        "JS_LOCK_DEPENDENCIES_UNMATERIALIZED" in item
        for item in fresh["_snapshot_build_input_limitations"]
    )

    resume = _config(project, pipeline="sc", language="evm")
    rp.resolve_snapshot_build_root(resume)
    assert resume["_snapshot_build_input_limitations"] == fresh["_snapshot_build_input_limitations"]

    _write(project / "node_modules" / "partial" / "index.js", "module.exports=1\n")
    partial = _config(project, pipeline="sc", language="evm")
    rp.resolve_snapshot_build_root(partial)
    assert any(
        "JS_DEPENDENCY_TREE_COMPLETENESS_UNPROVEN" in item
        for item in partial["_snapshot_build_input_limitations"]
    )


def test_hardhat_nested_root_is_shared_by_snapshot_build_and_slither(tmp_path: Path):
    umbrella = tmp_path / "umbrella"
    hardhat = umbrella / "packages" / "contracts"
    _write(hardhat / "hardhat.config.js", "module.exports={}\n")
    _write(hardhat / "package.json", '{}\n')
    _write(hardhat / "package-lock.json", '{"lockfileVersion":3}\n')
    _write(hardhat / "contracts" / "Vault.sol", "contract Vault {}\n")
    config = _config(umbrella, pipeline="sc", language="evm")

    resolved = rp.resolve_snapshot_build_root(config)

    assert resolved == hardhat.resolve()
    assert rp._resolve_evm_build_root(umbrella) == resolved


def test_malformed_move_manifest_fails_loudly(tmp_path: Path):
    project = tmp_path / "move"
    _write(project / "Move.toml", "[package\nname='broken'\n")
    _write(project / "sources" / "main.move", "module 0x1::main {}\n")
    config = _config(project, pipeline="sc", language="sui")

    with pytest.raises(rp.BuildContextResolutionError, match="Move manifest is unreadable"):
        rp.resolve_snapshot_build_root(config)


def test_solidity_pragma_parser_ignores_comments_and_string_literals(tmp_path: Path):
    source = _write(
        tmp_path / "Vault.sol",
        '// pragma solidity 0.4.0;\n'
        'string constant TEXT = "pragma solidity 0.5.0;";\n'
        '/* pragma solidity 0.6.0; */\n'
        'pragma solidity ^0.8.20; contract Vault {}\n',
    )

    assert rp._detect_solc_version(
        [source], available_versions=("0.4.0", "0.5.0", "0.6.0", "0.8.20")
    ) == "0.8.20"


def test_cargo_workspace_members_exclude_is_effective(tmp_path: Path):
    repo = tmp_path / "repo"
    external = tmp_path / "ignored-external"
    _write(
        repo / "Cargo.toml",
        '[workspace]\nmembers=["crates/*"]\nexclude=["crates/ignored"]\n',
    )
    _write(
        repo / "crates" / "included" / "Cargo.toml",
        '[package]\nname="included"\nversion="0.1.0"\n',
    )
    _write(repo / "crates" / "included" / "src" / "lib.rs", "pub fn x() {}\n")
    _write(
        repo / "crates" / "ignored" / "Cargo.toml",
        '[package]\nname="ignored"\nversion="0.1.0"\n'
        '[dependencies]\nexternal={path="../../../ignored-external"}\n',
    )
    _write(repo / "crates" / "ignored" / "src" / "lib.rs", "pub fn y() {}\n")
    _write(external / "Cargo.toml", '[package]\nname="external"\nversion="0.1.0"\n')
    _write(external / "src" / "lib.rs", "pub fn z() {}\n")
    config = _config(repo / "crates" / "included", pipeline="l1", language="rust")

    rp.resolve_snapshot_build_root(config)
    compiled = {
        Path(value).resolve()
        for value in config["_resolved_compiled_dependency_roots"]
    }

    assert external.resolve() not in compiled


def test_go_local_replacement_parser_preserves_windows_and_unc_paths():
    text = (
        'replace example.invalid/a => "C:\\shared\\module"\n'
        'replace example.invalid/b => "\\\\server\\share\\module"\n'
    )

    assert rp._go_local_replacements(text) == [
        "C:\\shared\\module",
        "\\\\server\\share\\module",
    ]


def test_multiple_downward_build_roots_are_loudly_approximated(tmp_path: Path):
    umbrella = tmp_path / "umbrella"
    for name in ("one", "two"):
        root = umbrella / "packages" / name
        _write(root / "hardhat.config.js", "module.exports={}\n")
        _write(root / "package.json", '{}\n')
        _write(root / "package-lock.json", '{"lockfileVersion":3}\n')
        _write(root / "contracts" / f"{name.title()}.sol", f"contract {name.title()} {{}}\n")
    config = _config(umbrella, pipeline="sc", language="evm")

    rp.resolve_snapshot_build_root(config)

    assert any(
        "MULTI_BUILD_ROOT_SELECTION_APPROXIMATED" in item
        for item in config["_snapshot_build_input_limitations"]
    )
