"""FIX 2: EVM Foundry build-env bootstrap in the recon pre-pass.

When an EVM scope ships bare `.sol` files with no `foundry.toml`/`hardhat`,
the pre-pass best-effort scaffolds a minimal Foundry env (foundry.toml +
forge-std + import-prefix remappings + well-known libs) and runs `forge build`
so Slither and later PoC verification have a compilable harness. The bootstrap
NEVER raises, is idempotent (no-op when a manifest exists), and degrades to the
existing grep-fallback SKIPPED status on any failure.
"""
from __future__ import annotations

from pathlib import Path

import recon_prepass as RP


def _write_sol(proj: Path, name: str, body: str) -> None:
    (proj / name).write_text(body, encoding="utf-8")


def test_bootstrap_noop_when_foundry_toml_exists(tmp_path):
    """Idempotent: existing foundry.toml is never clobbered."""
    proj = tmp_path
    (proj / "foundry.toml").write_text(
        "[profile.default]\nsrc = 'src'\n", encoding="utf-8"
    )
    _write_sol(proj, "Vault.sol", "pragma solidity ^0.8.0;\ncontract V {}\n")
    sources = list(proj.glob("*.sol"))

    ok, reason = RP._bootstrap_evm_foundry_env(proj, sources)

    assert ok is False
    assert "already exists" in reason
    # foundry.toml content untouched.
    assert "src = 'src'" in (proj / "foundry.toml").read_text(encoding="utf-8")


def test_bootstrap_declines_when_forge_absent(tmp_path, monkeypatch):
    """Degrades cleanly (no raise, no foundry.toml) when forge is not on PATH."""
    proj = tmp_path
    _write_sol(proj, "Vault.sol", "pragma solidity ^0.8.0;\ncontract V {}\n")
    sources = list(proj.glob("*.sol"))

    monkeypatch.setattr(RP.shutil, "which", lambda name: None)

    ok, reason = RP._bootstrap_evm_foundry_env(proj, sources)

    assert ok is False
    assert "forge not on PATH" in reason
    # No foundry.toml was written.
    assert not (proj / "foundry.toml").exists()


def test_bootstrap_declines_when_no_sources(tmp_path, monkeypatch):
    monkeypatch.setattr(RP.shutil, "which", lambda name: "/usr/bin/forge")
    ok, reason = RP._bootstrap_evm_foundry_env(tmp_path, [])
    assert ok is False
    assert "no Solidity source files" in reason
    assert not (tmp_path / "foundry.toml").exists()


def test_write_build_status_skips_cleanly_without_forge(tmp_path, monkeypatch):
    """_write_build_status falls through to the grep-fallback SKIPPED status
    when forge is absent (no bootstrap attempted)."""
    proj = tmp_path / "proj"
    scratch = tmp_path / "scratch"
    proj.mkdir()
    scratch.mkdir()
    _write_sol(proj, "Vault.sol", "pragma solidity ^0.8.0;\ncontract V {}\n")

    monkeypatch.setattr(RP.shutil, "which", lambda name: None)

    status = RP._write_build_status(scratch, proj, "evm")

    assert status == "STUB"
    text = (scratch / "build_status.md").read_text(encoding="utf-8")
    assert "SKIPPED" in text
    # No bootstrap attempted -> no foundry.toml left behind.
    assert not (proj / "foundry.toml").exists()


def test_write_build_status_records_bootstrap_failure(tmp_path, monkeypatch):
    """When forge is present but the build fails (no network / bad version),
    build_status.md records the bootstrap-attempted-but-failed reason and the
    grep fallback is used (STUB)."""
    proj = tmp_path / "proj"
    scratch = tmp_path / "scratch"
    proj.mkdir()
    scratch.mkdir()
    _write_sol(proj, "Vault.sol", "pragma solidity ^0.8.0;\ncontract V {}\n")

    # forge "present" but every forge invocation fails (simulate no network /
    # broken toolchain). _run_forge never raises; bootstrap returns failure.
    monkeypatch.setattr(RP.shutil, "which", lambda name: "/usr/bin/forge")
    monkeypatch.setattr(RP, "_run_forge", lambda args, cwd, timeout: (1, "boom"))

    status = RP._write_build_status(scratch, proj, "evm")

    assert status == "STUB"
    text = (scratch / "build_status.md").read_text(encoding="utf-8")
    assert "bootstrap attempted but failed" in text
    assert "grep fallback used" in text


def test_bootstrap_success_path_sets_build_env(tmp_path, monkeypatch):
    """When forge is present and build succeeds, _write_build_status promotes
    to a real evm_forge build (SUCCESS), recording the bootstrap note."""
    proj = tmp_path / "proj"
    scratch = tmp_path / "scratch"
    proj.mkdir()
    scratch.mkdir()
    _write_sol(
        proj, "Vault.sol",
        "// SPDX-License-Identifier: MIT\npragma solidity 0.8.20;\n"
        "import '@openzeppelin/contracts/token/ERC20/ERC20.sol';\n"
        "contract V {}\n",
    )

    monkeypatch.setattr(RP.shutil, "which", lambda name: "/usr/bin/forge")

    # Simulate every forge call succeeding; the final `forge build` (run again
    # in _write_build_status's normal path) also succeeds.
    monkeypatch.setattr(RP, "_run_forge", lambda args, cwd, timeout: (0, "ok"))

    monkeypatch.setattr(
        RP,
        "_run_hardened",
        lambda cmd, *args, **kwargs: (
            0,
            "Compiling ...\nCompiler run successful",
        ),
    )

    status = RP._write_build_status(scratch, proj, "evm")

    assert status == "WRITTEN"
    text = (scratch / "build_status.md").read_text(encoding="utf-8")
    assert "Build Env Bootstrap" in text and "SUCCESS" in text
    assert "**Tool**: evm_forge" in text
    # A foundry.toml was scaffolded with the detected solc version.
    ft = (proj / "foundry.toml").read_text(encoding="utf-8")
    assert 'solc = "0.8.20"' in ft
    # A manifest-less bundle has no version authority: never fetch package HEAD
    # or manufacture a remapping to guessed third-party code.
    assert not (proj / "remappings.txt").exists()
    assert "unpinned dependency installation skipped" in text


def test_bare_bootstrap_never_fetches_unpinned_third_party_dependencies(
    tmp_path, monkeypatch,
):
    proj = tmp_path / "proj"
    proj.mkdir()
    _write_sol(
        proj,
        "Vault.sol",
        "pragma solidity 0.8.21;\n"
        "import 'openzeppelin-contracts-upgradeable/proxy/utils/Initializable.sol';\n"
        "contract Vault {}\n",
    )
    calls = []
    monkeypatch.setattr(RP.shutil, "which", lambda name: "/usr/bin/forge")
    monkeypatch.setattr(
        RP,
        "_run_forge",
        lambda args, cwd, timeout: (calls.append(list(args)) or (1, "missing deps")),
    )

    ok, reason = RP._bootstrap_evm_foundry_env(
        proj, [proj / "Vault.sol"]
    )

    assert ok is False
    assert not any(call and call[0] == "install" for call in calls)
    assert "unpinned dependency installation skipped" in reason


def test_detect_solc_version_does_not_pin_incompatible_exact_pragmas(tmp_path):
    f1 = tmp_path / "A.sol"
    f2 = tmp_path / "B.sol"
    f3 = tmp_path / "C.sol"
    f1.write_text("pragma solidity 0.8.19;\n", encoding="utf-8")
    f2.write_text("pragma solidity 0.8.19;\n", encoding="utf-8")
    f3.write_text("pragma solidity 0.8.13;\n", encoding="utf-8")
    # A single generated Foundry ``solc`` pin must satisfy every audited
    # source. Popularity is not authority: pinning 0.8.19 would make C.sol
    # uncompilable and contaminate build/PoC evidence.
    assert RP._detect_solc_version([f1, f2, f3]) is None


def test_detect_solc_version_caret(tmp_path):
    f = tmp_path / "A.sol"
    f.write_text("pragma solidity ^0.8.20;\n", encoding="utf-8")
    assert RP._detect_solc_version([f]) == "0.8.20"


def test_detect_solc_version_prefers_exact_pins_over_range_lower_bounds(tmp_path):
    """A common permissive interface floor must not override implementation pins."""
    sources = []
    for i in range(8):
        f = tmp_path / f"Interface{i}.sol"
        f.write_text("pragma solidity >=0.5.0;\n", encoding="utf-8")
        sources.append(f)
    for i in range(3):
        f = tmp_path / f"Implementation{i}.sol"
        f.write_text("pragma solidity 0.8.21;\n", encoding="utf-8")
        sources.append(f)

    assert RP._detect_solc_version(sources) == "0.8.21"


def test_detect_import_libs_dedup_and_order(tmp_path):
    f = tmp_path / "A.sol"
    f.write_text(
        "import '@openzeppelin/contracts/token/ERC20/ERC20.sol';\n"
        "import 'solmate/tokens/ERC20.sol';\n"
        "import 'solady/utils/SafeTransferLib.sol';\n",
        encoding="utf-8",
    )
    libs = RP._detect_import_libs([f])
    dirs = [d for (_p, d, _s, _r) in libs]
    assert "openzeppelin-contracts" in dirs
    assert "solmate" in dirs
    assert "solady" in dirs
    # de-dup: openzeppelin only appears once even though multiple prefixes match
    assert dirs.count("openzeppelin-contracts") == 1


# ── Whole-project build timeout sizing (compile-unit vs production count) ──────
#
# Regression: sizing the whole-project `forge build` timeout off
# `_production_source_files` — which skips `lib/` via SKIP_DIR_NAMES —
# undercounts the compiler's real load ~10x on dependency-heavy repos. A cold
# 188-file compile got a 652s budget sized from 13 in-scope files and was
# tree-killed at the timeout, degrading build_status=TIMEOUT and failing
# Slither. `_compile_unit_files` counts the tree the compiler actually builds
# (incl `lib/`), so the timeout scales to a realistic ceiling.

def _mk_sol(p: Path) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("pragma solidity ^0.8.0;\ncontract C {}\n", encoding="utf-8")


def _dep_heavy_root(tmp_path: Path):
    """A Foundry-root layout: a few in-scope contracts + a large `lib/` dep
    tree + build-output dirs that must NOT be counted. Returns (root, n_lib)."""
    root = tmp_path
    (root / "foundry.toml").write_text("[profile.default]\n", encoding="utf-8")
    # In-scope production sources.
    for n in ("CrossChainRouter", "MessageRouter", "NativeVault"):
        _mk_sol(root / f"{n}.sol")
    _mk_sol(root / "interfaces" / "IBridgeRouter.sol")
    _mk_sol(root / "libraries" / "Encoder.sol")
    # A mock (excluded from BOTH counts by name/dir rules).
    _mk_sol(root / "mocks" / "BridgeRouterMock.sol")
    # Heavy dependency tree under lib/ — compiled by `forge build`, skipped by
    # the production filter.
    n_lib = 200
    for i in range(n_lib):
        _mk_sol(root / "lib" / "openzeppelin-contracts" / "contracts" / f"Dep{i}.sol")
    # Build output — must be skipped by BOTH counters.
    _mk_sol(root / "out" / "Stale.sol")
    _mk_sol(root / "cache" / "Stale.sol")
    return root, n_lib


def test_compile_unit_count_includes_lib_deps(tmp_path):
    root, n_lib = _dep_heavy_root(tmp_path)
    prod = RP._production_source_files(root, (".sol",))
    comp = RP._compile_unit_files(root, (".sol",))
    prod_names = {p.name for p in prod}
    comp_rel = {p.relative_to(root).as_posix() for p in comp}

    # Production count excludes lib/ + mocks entirely (the undercount source).
    assert len(prod) == 5, sorted(prod_names)
    assert not any("lib/" in p.relative_to(root).as_posix() for p in prod)
    assert "BridgeRouterMock.sol" not in prod_names

    # Compile-unit count INCLUDES the whole lib/ dep tree (what solc builds)...
    assert len(comp) >= n_lib + 5
    assert any(rp.startswith("lib/") for rp in comp_rel)
    # ...but still excludes build-output dirs.
    assert not any(rp.startswith("out/") for rp in comp_rel)
    assert not any(rp.startswith("cache/") for rp in comp_rel)


def test_production_scope_keeps_nested_protocol_lib_but_skips_root_dependency_lib(
    tmp_path,
):
    """`contracts/lib` is often first-party; only the Foundry-root `lib` is deps."""
    _mk_sol(tmp_path / "contracts" / "Vault.sol")
    _mk_sol(tmp_path / "contracts" / "lib" / "SolvencyMath.sol")
    _mk_sol(tmp_path / "lib" / "openzeppelin-contracts" / "ERC20.sol")

    rels = {
        path.relative_to(tmp_path).as_posix()
        for path in RP._production_source_files(tmp_path, (".sol",))
    }
    assert "contracts/Vault.sol" in rels
    assert "contracts/lib/SolvencyMath.sol" in rels
    assert "lib/openzeppelin-contracts/ERC20.sol" not in rels


def test_compile_unit_sizing_beats_undercount_timeout(tmp_path):
    root, _ = _dep_heavy_root(tmp_path)
    n_prod = len(RP._production_source_files(root, (".sol",)))
    n_comp = len(RP._compile_unit_files(root, (".sol",)))
    old = RP._scale_build_timeout(600, n_prod)
    new = RP._scale_build_timeout(600, n_comp)
    # The fix must produce a materially larger ceiling for a dep-heavy repo.
    assert new > old
    # 200+ dep files → at or near the hard ceiling, not the ~620s undercount.
    assert new >= 1400
    assert new <= RP._BUILD_TIMEOUT_CEILING_S


def test_compile_unit_skip_dirs_keep_deps_drop_output():
    # Deps are NOT skipped (must be counted); build output IS skipped.
    assert "lib" not in RP.COMPILE_UNIT_SKIP_DIR_NAMES
    assert "node_modules" not in RP.COMPILE_UNIT_SKIP_DIR_NAMES
    for d in ("out", "cache", "artifacts", "target", "build", ".git"):
        assert d in RP.COMPILE_UNIT_SKIP_DIR_NAMES


def test_compile_unit_files_never_raises_on_bad_root(tmp_path):
    missing = tmp_path / "does_not_exist"
    assert RP._compile_unit_files(missing, (".sol",)) == []


# ── Discovery inventory excludes test/fuzz/mock harness dirs (anti-priming) ────
#
# `_gather_files` feeds contract_inventory / function_list / state_variables
# (and, via _materialize_sc_slither_flat_files, slither/*.md). It must reflect
# the AUDIT SURFACE (production contracts) — never the project's own
# test/fuzz/mock harnesses, which encode answers and prime discovery. Regression
# for a real contamination case where `.medusa-tests`/`test/invariant` harnesses
# leaked into the recon inventory.

def test_gather_files_excludes_test_fuzz_mock_harnesses(tmp_path):
    proj = tmp_path
    # production (in-scope) contracts
    _mk_sol(proj / "CrossChainRouter.sol")
    _mk_sol(proj / "interfaces" / "IBridgeRouter.sol")
    # harness dirs that must NOT be inventoried
    _mk_sol(proj / "test" / "invariant" / "InvariantFuzz.t.sol")
    _mk_sol(proj / "mocks" / "BridgeRouterMock.sol")
    _mk_sol(proj / "fuzz" / "Handler.sol")
    _mk_sol(proj / "script" / "Deploy.s.sol")
    _mk_sol(proj / ".medusa-tests" / "MedusaCampaignV6.sol")

    got = {p.name for p in RP._gather_files(proj, "evm")}

    assert "CrossChainRouter.sol" in got
    assert "IBridgeRouter.sol" in got
    # none of the harness/test files
    for bad in ("InvariantFuzz.t.sol", "BridgeRouterMock.sol", "Handler.sol",
                "Deploy.s.sol", "MedusaCampaignV6.sol"):
        assert bad not in got, f"{bad} leaked into the discovery inventory"


def test_contract_inventory_sc_omits_harness_dirs(tmp_path):
    proj = tmp_path
    _mk_sol(proj / "Real.sol")
    _mk_sol(proj / "test" / "InvariantFuzz.t.sol")
    _mk_sol(proj / ".medusa-tests" / "Model.sol")
    scratch = tmp_path / "_scratch"
    scratch.mkdir()

    RP._write_contract_inventory_sc(scratch, proj, "evm")
    inv = (scratch / "contract_inventory.md").read_text(encoding="utf-8")

    assert "Real.sol" in inv
    assert "InvariantFuzz.t.sol" not in inv
    assert "MedusaCampaign" not in inv and "Model.sol" not in inv
    assert ".medusa-tests" not in inv and "test/" not in inv
