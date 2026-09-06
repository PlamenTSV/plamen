"""Part A — cargo PoC discovery + command harness (v2.8.x follow-up).

Root cause recap (see CLAUDE.md task): `spike_mechanical_poc._TEST_PATH_BY_LANG`
ran an unanchored `re.search` for solana/soroban/l1_rust that started matching
AT the `tests?/` segment, so a workspace-member-prefixed path like
`principal-token/tests/poc_h09.rs` was truncated to `tests/poc_h09.rs` — the
crate directory prefix was silently dropped. The truncated path then had no
`src/` candidate and no crate-prefix reconstruction in
`mechanical_verify._resolve_test_path_for`, so authored PoCs on a multi-crate
cargo workspace resolved to NO_TEST_FILE before cargo ever ran.

This file covers, generically (no protocol names in assertions/logic — the
Spectra-style crate names below are representative test-fixture path strings
only, per Part 0):
  1. Regex fixtures: crate-prefixed paths captured in full for the three cargo
     languages; EVM byte-identical; N/A -> None.
  2. Command-field hint parsing (-p/--package, --test, --features) as HINTS
     only — never shell-executed.
  3. `_resolve_test_path_for`'s new src/ candidate, crate-prefix
     reconstruction, and bounded unique-match-only rglob fallback.
  4. Hard invariants: inert on None, no fabricated PASS, bounded ambiguity.
  5. `_apply_cargo_workspace_fixups` feature-union (no more silent
     `testutils` stripping) and `-p` threading from the resolved path.
  6. `_prewarm_build` cargo test-target warm pass + registry-shape fix.

Run: pytest scripts/test_cargo_poc_discovery.py -q
"""
from __future__ import annotations

import sys
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS_DIR))

import mechanical_verify as MV  # noqa: E402
import spike_mechanical_poc as SP  # noqa: E402


# --------------------------------------------------------------------------- #
# 1. Regex fixtures — crate-prefixed path capture
# --------------------------------------------------------------------------- #

def _verify_text(test_file_line: str, command_line: str = "") -> str:
    return (
        "# Verification: H-9\n"
        "- **Finding ID**: H-9\n"
        f"- **Test File**: {test_file_line}\n"
        f"{command_line}"
        "- **Verdict**: CONFIRMED\n"
        "- **Evidence Tag**: [POC-PASS]\n"
    )


def _write(tmp_path: Path, text: str, name: str = "verify_H-9.md") -> Path:
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    return p


class TestRegexCratePrefixCapture:
    def test_solana_crate_prefix_retained(self, tmp_path):
        probe = SP.parse_verify_file(
            _write(tmp_path, _verify_text("principal-token/tests/poc_h09.rs")),
            language="solana",
        )
        assert probe.test_file_resolved == "principal-token/tests/poc_h09.rs"

    def test_soroban_crate_prefix_retained(self, tmp_path):
        probe = SP.parse_verify_file(
            _write(tmp_path, _verify_text("contracts/router/tests/poc_h12.rs")),
            language="soroban",
        )
        assert probe.test_file_resolved == "contracts/router/tests/poc_h12.rs"

    def test_l1_rust_crate_prefix_retained(self, tmp_path):
        probe = SP.parse_verify_file(
            _write(tmp_path, _verify_text("principal-token/tests/poc_h09.rs")),
            language="l1_rust",
        )
        assert probe.test_file_resolved == "principal-token/tests/poc_h09.rs"

    def test_bare_no_crate_prefix_unaffected(self, tmp_path):
        """Zero-repetition case: a bare tests/foo.rs (no crate dir) still
        resolves exactly as before the fix."""
        for lang in ("solana", "soroban", "l1_rust"):
            probe = SP.parse_verify_file(
                _write(tmp_path, _verify_text("tests/exploit.rs")), language=lang,
            )
            assert probe.test_file_resolved == "tests/exploit.rs", lang

    def test_src_bare_file_full_path_via_fallback(self, tmp_path):
        """`src/test.rs` (a file literally named test.rs, not a tests/ dir) has
        no `tests?/` directory marker, so the primary regex still legitimately
        does not match — the crate-prefixed full path is recovered by the
        UNCHANGED extension-token fallback instead. Illustrative crate-name
        fixture only (Part 0: no protocol names in pipeline logic)."""
        for lang in ("soroban", "l1_rust"):
            probe = SP.parse_verify_file(
                _write(tmp_path, _verify_text(
                    "blend-fungible-vault-wrapper/src/test.rs")),
                language=lang,
            )
            assert probe.test_file_resolved == "blend-fungible-vault-wrapper/src/test.rs", lang

    def test_evm_byte_identical_before_after(self, tmp_path):
        """HARD INVARIANT: EVM extraction is untouched by the cargo-only fix."""
        probe = SP.parse_verify_file(
            _write(tmp_path, _verify_text("test/Foo.t.sol")), language="evm",
        )
        assert probe.test_file_resolved == "test/Foo.t.sol"
        # EVM regex key itself is byte-identical to the pre-fix pattern.
        assert SP._TEST_PATH_BY_LANG["evm"].pattern == r"((?:test|tests)/[\w.\-/]+\.t\.sol)"

    def test_na_resolves_to_none(self, tmp_path):
        probe = SP.parse_verify_file(
            _write(tmp_path, _verify_text("N/A")), language="soroban",
        )
        assert probe.test_file_resolved is None

    def test_rejects_non_test_source_still_excluded(self, tmp_path):
        """Regression guard: the crate-prefix group must not resurrect the
        must-fix #3 exclusion of bare src/lib.rs-style non-test files."""
        for bad in ("src/lib.rs", "build.rs", "src/main.rs", "crate/src/mod.rs"):
            probe = SP.parse_verify_file(
                _write(tmp_path, _verify_text(bad)), language="solana",
            )
            assert probe.test_file_resolved is None, f"{bad} -> {probe.test_file_resolved!r}"


# --------------------------------------------------------------------------- #
# 2. Command-field hint parsing (HINTS only, never shell-executed)
# --------------------------------------------------------------------------- #

class TestCommandHintParsing:
    def test_package_test_target_and_features_extracted(self, tmp_path):
        cmd = ("- **Command**: `cargo test -p principal-token --test poc_h09 "
               "--features testutils poc_fn`\n")
        probe = SP.parse_verify_file(
            _write(tmp_path, _verify_text("principal-token/tests/poc_h09.rs", cmd)),
            language="solana",
        )
        assert probe.package == "principal-token"
        assert probe.test_target == "poc_h09"
        assert probe.features == ["testutils"]

    def test_no_features_yields_empty_list_not_none(self, tmp_path):
        cmd = "- **Command**: `cargo test -p router poc_h12`\n"
        probe = SP.parse_verify_file(
            _write(tmp_path, _verify_text("router/tests/poc_h12.rs", cmd)),
            language="soroban",
        )
        assert probe.package == "router"
        assert probe.features == []

    def test_no_command_hints_are_none_and_empty(self, tmp_path):
        probe = SP.parse_verify_file(
            _write(tmp_path, _verify_text("tests/exploit.rs")), language="solana",
        )
        assert probe.package is None
        assert probe.test_target is None
        assert probe.features == []

    def test_match_test_not_confused_with_test_target(self, tmp_path):
        """`--match-test` (EVM/forge flag) must not spuriously populate the
        cargo `--test` hint."""
        cmd = '- **Command**: `forge test --match-test "test_h1"`\n'
        probe = SP.parse_verify_file(
            _write(tmp_path, _verify_text("test/Foo.t.sol", cmd)), language="evm",
        )
        assert probe.test_target is None


# --------------------------------------------------------------------------- #
# 3. _resolve_test_path_for — src/ candidate, crate-prefix reconstruction,
#    bounded unique-match rglob fallback
# --------------------------------------------------------------------------- #

class _P:
    def __init__(self, test_file_resolved, package=None):
        self.test_file_resolved = test_file_resolved
        self.package = package


class TestResolveTestPathFor:
    def test_none_is_inert(self, tmp_path):
        """HARD INVARIANT: never invent a path when nothing was captured."""
        assert MV._resolve_test_path_for(_P(None), tmp_path) is None

    def test_evm_unaffected_build_root_resolution(self, tmp_path):
        """Regression guard for the existing EVM build-root test shape."""
        build_root = tmp_path / "project"
        scope = build_root / "contracts"
        (build_root / "test").mkdir(parents=True)
        scope.mkdir()
        tfile = build_root / "test" / "VerifyH1Poc.t.sol"
        tfile.write_text("// test", encoding="utf-8")
        found = MV._resolve_test_path_for(
            _P("test/VerifyH1Poc.t.sol"), build_root, scope)
        assert found == tfile

    def test_src_candidate_resolves(self, tmp_path):
        (tmp_path / "src").mkdir()
        tfile = tmp_path / "src" / "test.rs"
        tfile.write_text("// test", encoding="utf-8")
        found = MV._resolve_test_path_for(
            _P("crate-name/src/test.rs"), tmp_path)
        assert found == tfile

    def test_rglob_fallback_unique_match_found(self, tmp_path):
        member = tmp_path / "crateA" / "tests"
        member.mkdir(parents=True)
        tfile = member / "poc_x.rs"
        tfile.write_text("// test", encoding="utf-8")
        # Truncated path (no crate prefix) — the exact pre-fix failure mode.
        found = MV._resolve_test_path_for(_P("tests/poc_x.rs"), tmp_path)
        assert found == tfile

    def test_rglob_fallback_ambiguous_returns_none(self, tmp_path):
        member_a = tmp_path / "crateA" / "tests"
        member_a.mkdir(parents=True)
        (member_a / "poc_x.rs").write_text("// test", encoding="utf-8")
        member_b = tmp_path / "crateB" / "tests"
        member_b.mkdir(parents=True)
        (member_b / "poc_x.rs").write_text("// test", encoding="utf-8")
        found = MV._resolve_test_path_for(_P("tests/poc_x.rs"), tmp_path)
        assert found is None

    def test_rglob_fallback_zero_matches_returns_none(self, tmp_path):
        (tmp_path / "crateA").mkdir()
        found = MV._resolve_test_path_for(_P("tests/nonexistent.rs"), tmp_path)
        assert found is None

    def test_bounded_rglob_prunes_skip_dirs(self, tmp_path):
        """A same-named file sitting only inside a skip-dir (e.g. target/)
        must NOT be treated as a resolvable match."""
        skip = tmp_path / "target" / "tests"
        skip.mkdir(parents=True)
        (skip / "poc_y.rs").write_text("// generated", encoding="utf-8")
        found = MV._resolve_test_path_for(_P("tests/poc_y.rs"), tmp_path)
        assert found is None


# --------------------------------------------------------------------------- #
# 4. Hard invariants — resolution never changes classification / fabricates PASS
# --------------------------------------------------------------------------- #

class TestClassificationUnaffectedByResolution:
    def test_resolved_but_zero_tests_matched_is_no_test_match(self):
        out = "running 0 tests\ntest result: ok. 0 passed; 0 failed; 0 ignored"
        assert MV._classify_non_evm_outcome("solana", 0, out) == "NO_TEST_MATCH"

    def test_resolved_but_compile_error_is_compile_fail(self):
        out = "error[E0433]: failed to resolve\ncould not compile `crateA`"
        assert MV._classify_non_evm_outcome("soroban", 1, out) == "COMPILE_FAIL"

    def test_pass_requires_real_test_result_line(self):
        out = "running 1 test\ntest test_x ... ok\ntest result: ok. 1 passed; 0 failed"
        assert MV._classify_non_evm_outcome("l1_rust", 0, out) == "PASS"


# --------------------------------------------------------------------------- #
# 5. _apply_cargo_workspace_fixups — feature union + -p threading
# --------------------------------------------------------------------------- #

class _Probe:
    def __init__(self, test_command="", package=None, features=None):
        self.test_command = test_command
        self.package = package
        self.features = features or []


def _mk_crate(root: Path, name: str, features_decl: str | None = None) -> Path:
    """Create a real workspace-member crate with a genuine Cargo.toml (NOT a
    stub). features_decl is the body of a [features] table, or None for a crate
    that declares no features (the common Soroban case: testutils comes from the
    soroban-sdk dependency, not a crate-level feature)."""
    d = root / name
    (d / "tests").mkdir(parents=True, exist_ok=True)
    feats = f"\n[features]\n{features_decl}\n" if features_decl else ""
    (d / "Cargo.toml").write_text(
        f'[package]\nname = "{name}"\nversion = "0.0.0"\n\n'
        f'[dependencies]\nsoroban-sdk = {{ version = "*", features = ["testutils"] }}\n'
        + feats,
        encoding="utf-8",
    )
    (d / "tests" / "poc_x.rs").write_text("// test", encoding="utf-8")
    return d


class TestApplyCargoWorkspaceFixups:
    def test_declared_soroban_feature_kept(self, tmp_path):
        """A crate that DOES declare `testutils` in its own [features] keeps the
        flag (this is the case the union was meant to preserve)."""
        MV._PKG_FEATURES_CACHE.clear()
        _mk_crate(tmp_path, "crate_decl", features_decl="testutils = []")
        resolved = tmp_path / "crate_decl" / "tests" / "poc_x.rs"
        argv = ["cargo", "test", "--features", "testutils", "poc_x", "--", "--exact"]
        probe = _Probe(test_command="cargo test poc_x", package="crate_decl")
        out = MV._apply_cargo_workspace_fixups(
            argv, probe, language="soroban", resolved=resolved, build_root=tmp_path)
        assert "--features" in out
        assert "testutils" in out[out.index("--features") + 1].split(",")

    def test_undeclared_soroban_feature_dropped(self, tmp_path):
        """REGRESSION GUARD (the isolation-run bug): a Soroban crate with NO
        [features] table must NOT get `--features testutils` — cargo hard-errors
        'package does not contain this feature: testutils', failing every test
        including those that pass without any feature flag."""
        MV._PKG_FEATURES_CACHE.clear()
        _mk_crate(tmp_path, "crate_nodecl", features_decl=None)  # no [features]
        resolved = tmp_path / "crate_nodecl" / "tests" / "poc_x.rs"
        argv = ["cargo", "test", "--features", "testutils", "poc_x", "--", "--exact"]
        probe = _Probe(test_command="cargo test poc_x", package="crate_nodecl")
        out = MV._apply_cargo_workspace_fixups(
            argv, probe, language="soroban", resolved=resolved, build_root=tmp_path)
        kept = ("--features" in out
                and "testutils" in out[out.index("--features") + 1].split(","))
        assert not kept, out

    def test_testutils_never_emitted_for_solana(self):
        argv = ["cargo", "test", "poc_h09", "--", "--exact"]
        probe = _Probe(test_command="cargo test --features testutils poc_h09")
        out = MV._apply_cargo_workspace_fixups(argv, probe, language="solana")
        if "--features" in out:
            fi = out.index("--features")
            assert "testutils" not in out[fi + 1].split(",")

    def test_features_union_keeps_only_declared_probe_hint(self, tmp_path):
        MV._PKG_FEATURES_CACHE.clear()
        _mk_crate(tmp_path, "crate_x", features_decl="extra_feat = []")
        resolved = tmp_path / "crate_x" / "tests" / "poc_x.rs"
        argv = ["cargo", "test", "poc_x", "--", "--exact"]
        probe = _Probe(test_command="cargo test poc_x", package="crate_x",
                       features=["extra_feat"])
        out = MV._apply_cargo_workspace_fixups(
            argv, probe, language="soroban", resolved=resolved, build_root=tmp_path)
        assert "--features" in out
        assert "extra_feat" in out[out.index("--features") + 1].split(",")

    def test_cargo_toml_declared_features_parse(self):
        assert MV._cargo_toml_declared_features(
            '[package]\nname="a"\n[features]\ntestutils = []\nfoo = ["bar"]\n'
            '[dependencies]\nx = "1"\n') == {"testutils", "foo"}
        assert MV._cargo_toml_declared_features(
            '[package]\nname="a"\n[dependencies]\nx = "1"\n') == set()

    def test_workspace_package_features_scan(self, tmp_path):
        MV._PKG_FEATURES_CACHE.clear()
        _mk_crate(tmp_path, "m1", features_decl="testutils = []")
        _mk_crate(tmp_path, "m2", features_decl=None)
        feats = MV._workspace_package_features(tmp_path)
        assert feats.get("m1") == {"testutils"}
        assert feats.get("m2") == set()

    def test_package_threaded_from_probe_hint(self):
        argv = ["cargo", "test", "poc_h09", "--", "--exact"]
        probe = _Probe(test_command="cargo test poc_h09", package="principal-token")
        out = MV._apply_cargo_workspace_fixups(argv, probe, language="solana")
        assert out[:4] == ["cargo", "test", "-p", "principal-token"] or \
            ("-p" in out and out[out.index("-p") + 1] == "principal-token")

    def test_package_threaded_from_resolved_path_member_segment(self, tmp_path):
        build_root = tmp_path
        resolved = build_root / "principal-token" / "tests" / "poc_h09.rs"
        resolved.parent.mkdir(parents=True)
        resolved.write_text("// test", encoding="utf-8")
        argv = ["cargo", "test", "poc_h09", "--", "--exact"]
        probe = _Probe(test_command="cargo test poc_h09")  # no -p, no package hint
        out = MV._apply_cargo_workspace_fixups(
            argv, probe, language="solana", resolved=resolved, build_root=build_root)
        assert "-p" in out
        assert out[out.index("-p") + 1] == "principal-token"

    def test_explicit_command_package_wins_over_hint(self):
        argv = ["cargo", "test", "poc_h09", "--", "--exact"]
        probe = _Probe(test_command="cargo test -p real-pkg poc_h09", package="hint-pkg")
        out = MV._apply_cargo_workspace_fixups(argv, probe, language="solana")
        assert out[out.index("-p") + 1] == "real-pkg"

    def test_never_raises_on_malformed_argv(self):
        out = MV._apply_cargo_workspace_fixups([], _Probe(), language="soroban")
        assert isinstance(out, list)


# --------------------------------------------------------------------------- #
# 6. _prewarm_build — cargo test-target warm pass + registry-shape fix
# --------------------------------------------------------------------------- #

class _FakeProc:
    def __init__(self, returncode=0):
        self.returncode = returncode
        self.stdout = ""
        self.stderr = ""


class TestPrewarmCargoTestTargets:
    def test_lang_cfg_resolves_nested_registry_document(self):
        """Regression guard: the full `_load_registry()` document (nested
        under "languages") must resolve, not silently return {}."""
        reg = {"version": 2, "languages": {"solana": {"build_command": "cargo build-sbf"}}}
        cfg = MV._lang_cfg_from_registry(reg, "solana")
        assert cfg.get("build_command") == "cargo build-sbf"

    def test_lang_cfg_resolves_flat_registry_stub(self):
        """Back-compat: existing tests pass a flat {lang: {...}} mapping."""
        reg = {"l1_rust": {"build_command": "cargo build --all-targets"}}
        cfg = MV._lang_cfg_from_registry(reg, "l1_rust")
        assert cfg.get("build_command") == "cargo build --all-targets"

    def test_missing_language_returns_empty_dict(self):
        assert MV._lang_cfg_from_registry({"languages": {}}, "solana") == {}
        assert MV._lang_cfg_from_registry({}, "solana") == {}
        assert MV._lang_cfg_from_registry(None, "solana") == {}

    def test_cargo_langs_get_second_test_prewarm_call(self, monkeypatch, tmp_path):
        calls = []

        def _fake_run(cmd, **kw):
            calls.append(list(cmd))
            return _FakeProc(0)

        monkeypatch.setattr(MV, "_run_owned_process", _fake_run)
        monkeypatch.setattr(MV.shutil, "which", lambda b: None)  # keep argv[0] literal
        reg = {"languages": {"solana": {"build_command": "cargo build-sbf"}}}
        ok, note = MV._prewarm_build(tmp_path, "solana", reg, 60)
        assert ok is True
        assert len(calls) == 2
        assert calls[0][0] == "cargo" and "build-sbf" in calls[0]
        assert calls[1][:3] == ["cargo", "test", "--no-run"]
        assert "test-prewarm ok" in note

    def test_evm_never_gets_second_call(self, monkeypatch, tmp_path):
        calls = []
        monkeypatch.setattr(
            MV, "_run_owned_process",
            lambda cmd, **kw: calls.append(list(cmd)) or _FakeProc(0))
        ok, note = MV._prewarm_build(tmp_path, "evm", {}, 60)
        assert ok is True
        assert len(calls) == 1

    def test_soroban_test_prewarm_is_feature_agnostic(self, monkeypatch, tmp_path):
        """The workspace-root warm pass must NOT force `--features testutils`:
        members that get testutils via the soroban-sdk dep (declaring no crate
        feature) make cargo hard-error on it, wasting the whole warm. Plain
        `cargo test --no-run` warms every member; per-finding feature validity is
        gated later in _apply_cargo_workspace_fixups."""
        calls = []
        monkeypatch.setattr(
            MV, "_run_owned_process",
            lambda cmd, **kw: calls.append(list(cmd)) or _FakeProc(0))
        monkeypatch.setattr(MV.shutil, "which", lambda b: None)
        reg = {"languages": {"soroban": {"build_command": "stellar contract build"}}}
        MV._prewarm_build(tmp_path, "soroban", reg, 60)
        assert len(calls) == 2
        assert "testutils" not in calls[1]
        assert calls[1][:3] == ["cargo", "test", "--no-run"]

    def test_registry_test_prewarm_command_honored(self, monkeypatch, tmp_path):
        calls = []
        monkeypatch.setattr(
            MV, "_run_owned_process",
            lambda cmd, **kw: calls.append(list(cmd)) or _FakeProc(0))
        monkeypatch.setattr(MV.shutil, "which", lambda b: None)
        reg = {"languages": {"l1_rust": {
            "build_command": "cargo build --all-targets",
            "test_prewarm_command": "cargo test --no-run --all-features",
        }}}
        MV._prewarm_build(tmp_path, "l1_rust", reg, 60)
        assert calls[1] == ["cargo", "test", "--no-run", "--all-features"]

    def test_test_prewarm_failure_is_non_fatal_when_build_succeeds(self, monkeypatch, tmp_path):
        def _run(cmd, **kw):
            if cmd[:2] == ["cargo", "build"] or "build-sbf" in cmd:
                return _FakeProc(0)
            raise MV.subprocess.TimeoutExpired(cmd, 1)

        monkeypatch.setattr(MV, "_run_owned_process", _run)
        monkeypatch.setattr(MV.shutil, "which", lambda b: None)
        reg = {"languages": {"solana": {"build_command": "cargo build-sbf"}}}
        ok, note = MV._prewarm_build(tmp_path, "solana", reg, 60)
        assert ok is True  # primary build succeeded; test-prewarm failure ignored
        assert "exceeded" in note

    def test_never_raises_on_arbitrary_exception(self, monkeypatch, tmp_path):
        monkeypatch.setattr(
            MV, "_run_owned_process",
            lambda cmd, **kw: (_ for _ in ()).throw(ValueError("boom")))
        reg = {"languages": {"solana": {"build_command": "cargo build-sbf"}}}
        ok, note = MV._prewarm_build(tmp_path, "solana", reg, 60)
        assert ok is False
        assert "error" in note


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-q"]))
