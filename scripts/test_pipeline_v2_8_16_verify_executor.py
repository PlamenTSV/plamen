"""Pipeline v2.8.16 — Phase 1: ecosystem-agnostic verify author/executor split.

Root problem (observed post-mortems): the mechanical verifier
was effectively EVM-only and the LLM self-assigned its own Evidence Tag, so
101/102 findings shipped as fabricated [POC-PASS] (INTEGRITY-DOWNGRADE
NO_TEST_FILE) — the precision-collapse root cause. Two structural bugs:

  1. `spike_mechanical_poc.parse_verify_file` extracted test paths with an
     EVM-only `.t.sol`-under-`test/` regex, so every Solana/Move/Soroban/Go
     finding resolved to None → NO_TEST_FILE → could never reach PASS.
  2. L1 config stores raw `go`/`rust`; the registry keys on `l1_go`/`l1_rust`,
     so L1 mechanical verify silently never executed.
  3. Demoting the inflated tag never reached the report — the Index Agent reads
     the verifier's `Verdict:` line, which still said CONFIRMED.

Fixes (vetted blueprint + 6 adversarial-review must-fixes):
  - #0a   L1 language remap at the single dispatch surface.
  - #1d/#3 ecosystem-keyed, test-DIR-anchored path extraction (no src/lib.rs).
  - #1     per-ecosystem EXACT test isolation (cargo --exact, go ^x$).
  - #0b/#6 conservative build-root neighbourhood scan (never a wrong project).
  - #3a    driver flips Verdict CONFIRMED→CONTESTED on INFLATED_PROSE.

Run: pytest scripts/test_pipeline_v2_8_16_verify_executor.py -q
"""
from __future__ import annotations

import sys
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS_DIR))

import mechanical_verify as MV  # noqa: E402
import spike_mechanical_poc as SP  # noqa: E402
import plamen_driver as PD  # noqa: E402


# --------------------------------------------------------------------------- #
# v2.8.16 — L1 verify-shard never-halt parity (extends v2.8.15 SC-only net)    #
# --------------------------------------------------------------------------- #

def test_poc_verify_shard_sc_shards():
    for n in ("sc_verify_crithigh", "sc_verify_high_c", "sc_verify_medium_a",
              "sc_verify_low_b"):
        assert PD._is_poc_verify_shard(n), n


def test_poc_verify_shard_l1_shards():
    # The asymmetry being closed: L1 verify shards must also be recoverable.
    for n in ("verify_crithigh", "verify_high_c", "verify_medium_f",
              "verify_low_d"):
        assert PD._is_poc_verify_shard(n), n


def test_poc_verify_shard_excludes_queue_and_aggregate():
    for n in ("sc_verify_queue", "sc_verify_aggregate",
              "verify_queue", "verify_aggregate"):
        assert not PD._is_poc_verify_shard(n), n


def test_poc_verify_shard_excludes_unrelated_phases():
    for n in ("post_verify_extract", "depth", "report_index", "recon",
              "skeptic_judge", "sc_mechanical_verify", "mechanical_verify"):
        assert not PD._is_poc_verify_shard(n), n


# --------------------------------------------------------------------------- #
# v2.8.16 — L1 depth degrade-and-continue parity (workflow wq8t0pgqa)          #
# --------------------------------------------------------------------------- #

def _l1_core_scratch(tmp_path, mode="core", missing=()):
    """Write the 5 L1 depth core role files (minus any in `missing`) substantive."""
    import plamen_types as PT
    core = [g[0] for g in PT.l1_never_cut_groups(mode)[:5]]
    body = "# Depth role findings\n\n## Finding [X-1]\n\nSubstantive analysis " + ("x" * 400) + "\n"
    for name in core:
        if name in missing:
            continue
        (tmp_path / name).write_text(body, encoding="utf-8")
    return core


def test_l1_core_predicate_present_vs_absent(tmp_path):
    import plamen_validators as V
    _l1_core_scratch(tmp_path, "core")
    assert V._depth_core_artifacts_present(tmp_path, "l1", "core") is True
    # remove one role file → catastrophic-failure detection (must still halt)
    miss = [g[0] for g in __import__("plamen_types").l1_never_cut_groups("core")[:5]][0]
    (tmp_path / miss).unlink()
    assert V._depth_core_artifacts_present(tmp_path, "l1", "core") is False


def test_l1_core_predicate_mode_invariant(tmp_path):
    """[:5] must be the same 5 role files across light/core/thorough."""
    import plamen_types as PT
    sets = {m: tuple(g[0] for g in PT.l1_never_cut_groups(m)[:5])
            for m in ("light", "core", "thorough")}
    assert sets["light"] == sets["core"] == sets["thorough"]
    assert sets["core"] == (
        "depth_consensus_invariant_findings.md",
        "depth_network_surface_findings.md",
        "depth_state_trace_findings.md",
        "depth_external_findings.md",
        "depth_edge_case_findings.md",
    )


def test_l1_repair_hint_is_l1_aware():
    import plamen_validators as V
    h = V._generate_depth_repair_hint(["confidence_scores.md"], "l1", "core")
    assert "depth_consensus_invariant_findings.md" in h
    assert "NO `blind_spot_*`" in h
    assert "blind_spot_a_findings.md" not in h  # SC scanner names absent
    assert "chain" not in h.lower() or "no chain" in h.lower()
    assert "write it" not in h.lower()
    assert "not model repair targets" in h


def test_sc_repair_hint_unchanged_default():
    import plamen_validators as V
    sc_default = V._generate_depth_repair_hint(["perturbation_findings.md"])
    sc_explicit = V._generate_depth_repair_hint(["perturbation_findings.md"], "sc", "core")
    assert sc_default == sc_explicit  # default is SC
    assert "blind_spot_*" in sc_default and "four" in sc_default  # verbatim SC text
    assert "depth_consensus_invariant_findings.md" not in sc_default


# --------------------------------------------------------------------------- #
# v2.8.16 — CORE_STATE/ACCESS_CONTROL baseline focus excluded from skill inject #
# --------------------------------------------------------------------------- #

def test_baseline_focus_excluded_from_skill_injection():
    assert "CORE_STATE" in PD._SC_SKILL_INJECT_EXCLUDE
    assert "ACCESS_CONTROL" in PD._SC_SKILL_INJECT_EXCLUDE
    # real recon/verifier-only skills stay excluded too
    assert "FORK_ANCESTRY" in PD._SC_SKILL_INJECT_EXCLUDE
    assert "VERIFICATION_PROTOCOL" in PD._SC_SKILL_INJECT_EXCLUDE


def test_core_state_binding_not_emitted(tmp_path):
    """A breadth manifest whose Template column is CORE_STATE/ACCESS_CONTROL must
    NOT produce a skill binding (→ no spurious 'did not resolve' warning)."""
    manifest = (
        "# Spawn Manifest\n\n## Breadth Agents\n"
        "| Row Type | Template | Required? | Agent ID | Focus Area | Expected Output | Status |\n"
        "|----------|----------|-----------|----------|------------|-----------------|--------|\n"
        "| AGENT | CORE_STATE | YES | B1 | core_state | analysis_core_state.md | QUEUED |\n"
        "| AGENT | ACCESS_CONTROL | YES | B2 | access_control | analysis_access_control.md | QUEUED |\n"
        "| AGENT | ORACLE_ANALYSIS | YES | B3 | oracle_rng | analysis_oracle_rng.md | QUEUED |\n"
    )
    (tmp_path / "spawn_manifest.md").write_text(manifest, encoding="utf-8")
    breadth, _depth = PD._parse_sc_skill_bindings(tmp_path)
    # core_state / access_control focus areas carry NO bound skill
    assert "CORE_STATE" not in breadth.get("core_state", [])
    assert "ACCESS_CONTROL" not in breadth.get("access_control", [])
    # a real skill template still binds
    assert "ORACLE_ANALYSIS" in breadth.get("oracle_rng", [])


# --------------------------------------------------------------------------- #
# #0a — L1 language remap                                                      #
# --------------------------------------------------------------------------- #

def test_l1_language_remap_normalizes_raw_go_rust():
    assert SP._normalize_lang_for_paths("go") == "l1_go"
    assert SP._normalize_lang_for_paths("rust") == "l1_rust"
    assert SP._normalize_lang_for_paths("evm") == "evm"
    assert SP._normalize_lang_for_paths("") == "evm"
    assert SP._normalize_lang_for_paths(None) == "evm"


def test_l1_remap_in_executor_hits_registry(tmp_path, monkeypatch):
    """language='go' must reach the l1_go registry entry, not misroute to a
    TOOLCHAIN_UNAVAILABLE-by-missing-registry-key path."""
    reg = MV._load_registry()
    MV._ensure_l1_registry_entries(reg)
    assert "l1_go" in reg["languages"]
    assert "l1_rust" in reg["languages"]
    # The remap happens inside run_phase5b; with no verify files it returns
    # cleanly regardless of toolchain presence.
    summary = MV.run_phase5b_mechanical_verify(tmp_path, tmp_path, "go")
    assert summary["status"] in ("no_verify_files", "toolchain_unavailable", "ok")


# --------------------------------------------------------------------------- #
# #1d + must-fix #3 — ecosystem-keyed, test-dir-anchored path extraction       #
# --------------------------------------------------------------------------- #

def _verify_text(test_file_line: str, func_line: str = "") -> str:
    return (
        "# Verification: H-5\n"
        "- **Finding ID**: H-5\n"
        "- **Severity**: High\n"
        f"- **Test File**: {test_file_line}\n"
        f"{func_line}"
        "- **Verdict**: CONFIRMED\n"
        "- **Evidence Tag**: [POC-PASS]\n"
    )


def _write(tmp_path: Path, text: str) -> Path:
    p = tmp_path / "verify_H-5.md"
    p.write_text(text, encoding="utf-8")
    return p


def test_path_extraction_per_ecosystem(tmp_path):
    cases = {
        "evm": "test/Exploit.t.sol",
        "solana": "tests/exploit.rs",
        "soroban": "tests/exploit.rs",
        "l1_rust": "tests/exploit.rs",
        "aptos": "tests/exploit.move",
        "sui": "sources/tests/exploit.move",
        "l1_go": "consensus/exploit_test.go",
    }
    for lang, path in cases.items():
        probe = SP.parse_verify_file(_write(tmp_path, _verify_text(path)), language=lang)
        assert probe.test_file_resolved == path, f"{lang}: {probe.test_file_resolved!r}"


def test_path_extraction_rejects_non_test_source(tmp_path):
    """must-fix #3: a bare src/lib.rs / build.rs token must NOT be mistaken for
    the harm test (un-anchored .rs regex would have grabbed it)."""
    for bad in ("src/lib.rs", "build.rs", "src/main.rs", "crate/src/mod.rs"):
        probe = SP.parse_verify_file(_write(tmp_path, _verify_text(bad)), language="solana")
        assert probe.test_file_resolved is None, f"{bad} → {probe.test_file_resolved!r}"


def test_evm_back_compat_default_language(tmp_path):
    """No language passed → EVM behavior preserved for legacy callers."""
    probe = SP.parse_verify_file(_write(tmp_path, _verify_text("test/Exploit.t.sol")))
    assert probe.test_file_resolved == "test/Exploit.t.sol"


def test_driver_dictated_bare_path_resolves(tmp_path):
    """Author/executor split: the driver dictates an explicit path that may sit
    outside a `test/` dir; the extension fallback still resolves it."""
    probe = SP.parse_verify_file(
        _write(tmp_path, _verify_text(".scratchpad/poc_h5/exploit.rs")),
        language="soroban",
    )
    assert probe.test_file_resolved == ".scratchpad/poc_h5/exploit.rs"


# --------------------------------------------------------------------------- #
# Test Function field (driver-dictated, language-agnostic)                     #
# --------------------------------------------------------------------------- #

def test_explicit_test_function_field(tmp_path):
    probe = SP.parse_verify_file(
        _write(tmp_path, _verify_text("tests/e.rs", "- **Test Function**: test_overflow\n")),
        language="solana",
    )
    assert probe.test_function == "test_overflow"


def test_go_test_function_decl_extracted(tmp_path):
    txt = _verify_text("p/x_test.go") + "func TestEclipse(t *testing.T) {}\n"
    probe = SP.parse_verify_file(_write(tmp_path, txt), language="l1_go")
    assert probe.test_function == "TestEclipse"


# --------------------------------------------------------------------------- #
# must-fix #1 — per-ecosystem EXACT test isolation                             #
# --------------------------------------------------------------------------- #

def test_cargo_exact_isolation_with_separator():
    argv = MV._format_test_command(
        "cargo test test_x -- --nocapture", "test_x", "tests/e.rs", language="solana"
    )
    assert "--exact" in argv
    i = argv.index("--")
    assert argv[i + 1] == "--exact"  # immediately after the libtest separator


def test_cargo_exact_isolation_no_separator_soroban():
    argv = MV._format_test_command(
        "cargo test --features testutils test_x", "test_x", None, language="soroban"
    )
    assert argv[-2:] == ["--", "--exact"]


def test_go_run_anchored_exact():
    argv = MV._format_test_command(
        "go test -run {test_function} -v ./...", "TestX", None, language="l1_go"
    )
    assert "-run" in argv
    assert argv[argv.index("-run") + 1] == "^TestX$"


def test_move_no_exact_flag_added():
    """aptos/sui have no exact flag — driver-dictated unique name is the isolation."""
    a = MV._format_test_command(
        "aptos move test --filter test_x", "test_x", None, language="aptos"
    )
    s = MV._format_test_command("sui move test test_x", "test_x", None, language="sui")
    assert "--exact" not in a and "--exact" not in s


def test_format_test_command_back_compat_no_language():
    """Legacy 3-arg callers keep working (no isolation injected)."""
    argv = MV._format_test_command("cargo test test_x -- --nocapture", "test_x", None)
    assert "--exact" not in argv  # no language → no isolation, but still valid argv
    assert argv[:3] == ["cargo", "test", "test_x"]


# --------------------------------------------------------------------------- #
# #3a — driver flips Verdict CONFIRMED→CONTESTED on INFLATED_PROSE             #
# --------------------------------------------------------------------------- #

def test_verdict_flip_on_field_line():
    text = "- **Verdict**: CONFIRMED\n- **Evidence Tag**: [POC-PASS]\n"
    out, changed = MV.flip_verdict_on_integrity_downgrade(text)
    assert changed
    assert "CONTESTED [INTEGRITY-DOWNGRADE]" in out
    assert "Verdict**: CONFIRMED\n" not in out


def test_verdict_flip_idempotent():
    text = "- **Verdict**: CONTESTED [INTEGRITY-DOWNGRADE]\n"
    out, changed = MV.flip_verdict_on_integrity_downgrade(text)
    assert not changed
    assert out == text


def test_verdict_flip_ignores_prose_mentions():
    """Only the Verdict FIELD line flips — prose 'CONFIRMED' is untouched."""
    text = (
        "The exploit is CONFIRMED to drain funds.\n"
        "- **Verdict**: CONFIRMED\n"
    )
    out, changed = MV.flip_verdict_on_integrity_downgrade(text)
    assert changed
    assert "exploit is CONFIRMED to drain" in out  # prose preserved
    assert out.count("CONTESTED [INTEGRITY-DOWNGRADE]") == 1


def test_verdict_flip_plain_and_bold_forms():
    for line in ("Verdict: CONFIRMED", "**Verdict**: CONFIRMED", "- Verdict : CONFIRMED"):
        out, changed = MV.flip_verdict_on_integrity_downgrade(line + "\n")
        assert changed, line
        assert "CONTESTED [INTEGRITY-DOWNGRADE]" in out


# --------------------------------------------------------------------------- #
# prose-tag extraction: bullet-form claim + Mechanical-Tag shadowing           #
# (real latent bug surfaced by the EVM e2e smoke)                              #
# --------------------------------------------------------------------------- #

def test_prose_tag_bullet_form_evidence_tag(tmp_path):
    f = tmp_path / "verify_H-9.md"
    f.write_text("- **Evidence Tag**: [POC-PASS]\n", encoding="utf-8")
    assert MV._extract_verifier_prose_tag(f) == "[POC-PASS]"


def test_prose_tag_prefers_claim_over_mechanical_tag(tmp_path):
    """After annotation appends a non-bullet **Mechanical-Tag**, the verifier's
    own bullet claim must still win (else fabrication is misread CONSISTENT)."""
    f = tmp_path / "verify_H-9.md"
    f.write_text(
        "- **Evidence Tag**: [POC-PASS]\n\n"
        "<!-- mechanical-verify v1 -->\n"
        "**Mechanical-Verified**: NO (NO_TEST_FILE) —\n"
        "**Mechanical-Tag**: [CODE-TRACE]\n",
        encoding="utf-8",
    )
    assert MV._extract_verifier_prose_tag(f) == "[POC-PASS]"


def test_inflated_prose_detected_for_bullet_form(tmp_path):
    f = tmp_path / "verify_H-9.md"
    f.write_text(
        "- **Verdict**: CONFIRMED\n- **Evidence Tag**: [POC-PASS]\n"
        "**Mechanical-Tag**: [CODE-TRACE]\n", encoding="utf-8",
    )
    state, eff = MV._classify_integrity(MV._extract_verifier_prose_tag(f), "NO_TEST_FILE")
    assert state == "INFLATED_PROSE"
    assert "[INTEGRITY-DOWNGRADE]" in eff


def test_mechanical_tag_fallback_when_no_verifier_claim(tmp_path):
    f = tmp_path / "verify_H-9.md"
    f.write_text("**Mechanical-Tag**: [CODE-TRACE]\n", encoding="utf-8")
    assert MV._extract_verifier_prose_tag(f) == "[CODE-TRACE]"


# --------------------------------------------------------------------------- #
# #0b / must-fix #6 — conservative build-root neighbourhood scan               #
# --------------------------------------------------------------------------- #

def test_build_root_sibling_scan(tmp_path):
    """scope and build root share an immediate parent (the real Pulse case)."""
    repo = tmp_path / "repo"
    (repo / "interfaces").mkdir(parents=True)        # audit scope (no manifest)
    (repo / "contracts").mkdir()
    (repo / "contracts" / "foundry.toml").write_text("[profile.default]\n")
    assert MV._find_build_root(repo / "interfaces", "evm") == (repo / "contracts").resolve()


def test_build_root_descends_into_scope_subtree(tmp_path):
    """scope dir sits ABOVE the build root (≤2 levels down)."""
    scope = tmp_path / "scope"
    (scope / "protocol" / "core").mkdir(parents=True)
    (scope / "protocol" / "core" / "Cargo.toml").write_text("[package]\n")
    assert MV._find_build_root(scope, "solana") == (scope / "protocol" / "core").resolve()


def test_build_root_no_false_match_on_unrelated_sibling(tmp_path):
    """A manifest two-levels-up-and-over (unrelated project) must NOT be picked —
    wrong build root = false verdict, worse than safe degrade-to-project_root."""
    root = tmp_path / "monorepo"
    (root / "unrelated").mkdir(parents=True)
    (root / "unrelated" / "foundry.toml").write_text("[profile.default]\n")
    scope = root / "a" / "b" / "scope"      # 3 levels below the unrelated manifest
    scope.mkdir(parents=True)
    # Neither upward walk nor the tight neighbourhood scan should reach it.
    assert MV._find_build_root(scope, "evm") == scope.resolve()


# --------------------------------------------------------------------------- #
# AP-EXEC-1a — recon's authoritative chosen build root (build_status.md)        #
# --------------------------------------------------------------------------- #

def _write_build_status(scratch: Path, chosen) -> None:
    scratch.mkdir(parents=True, exist_ok=True)
    line = f"**Chosen build root**: `{chosen}`\n" if chosen is not None else ""
    (scratch / "build_status.md").write_text(
        "# Build Status\n- **Build Result**: success\n" + line, encoding="utf-8"
    )


def test_recon_build_root_honored_sibling(tmp_path):
    scratch = tmp_path / "scratch"
    foundry = tmp_path / "contracts"
    foundry.mkdir()
    (foundry / "foundry.toml").write_text("[profile.default]\n")
    _write_build_status(scratch, foundry)
    assert MV._read_recon_build_root(scratch, "evm") == foundry.resolve()


def test_recon_build_root_beats_heuristic_when_unreachable(tmp_path):
    """Foundry root far away (heuristic can't reach), scope dir has no manifest —
    the heuristic degrades to the scope dir, but recon's choice is honored."""
    far = tmp_path / "x" / "y" / "z" / "contracts"
    far.mkdir(parents=True)
    (far / "foundry.toml").write_text("[profile.default]\n")
    scope = tmp_path / "scope"
    scope.mkdir()
    scratch = tmp_path / "scratch"
    _write_build_status(scratch, far)
    # Heuristic cannot reach `far` → degrades to scope.
    assert MV._find_build_root(scope, "evm") == scope.resolve()
    # Recon's authoritative choice does reach it.
    assert MV._read_recon_build_root(scratch, "evm") == far.resolve()


def test_recon_build_root_rejected_when_no_manifest(tmp_path):
    chosen = tmp_path / "nomanifest"
    chosen.mkdir()
    scratch = tmp_path / "scratch"
    _write_build_status(scratch, chosen)
    assert MV._read_recon_build_root(scratch, "evm") is None


def test_recon_build_root_missing_file_returns_none(tmp_path):
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    assert MV._read_recon_build_root(scratch, "evm") is None


def test_recon_build_root_none_token_ignored(tmp_path):
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    (scratch / "build_status.md").write_text(
        "**Chosen build root**: `(none)`\n", encoding="utf-8"
    )
    assert MV._read_recon_build_root(scratch, "evm") is None


def test_recon_build_root_solana_sibling_honored(tmp_path):
    scratch = tmp_path / "scratch"
    program = tmp_path / "program"
    program.mkdir()
    (program / "Cargo.toml").write_text("[package]\n")
    _write_build_status(scratch, program)
    assert MV._read_recon_build_root(scratch, "solana") == program.resolve()


# --------------------------------------------------------------------------- #
# AP-EXEC-2 — zero-tests-matched must be NO_TEST_MATCH, never a false PASS      #
# --------------------------------------------------------------------------- #

def test_classify_cargo_zero_passed_is_no_match():
    out = "running 0 tests\ntest result: ok. 0 passed; 0 failed; 0 ignored"
    assert MV._classify_non_evm_outcome("solana", 0, out) == "NO_TEST_MATCH"


def test_classify_cargo_one_passed_is_pass():
    out = "running 1 test\ntest test_x ... ok\ntest result: ok. 1 passed; 0 failed"
    assert MV._classify_non_evm_outcome("solana", 0, out) == "PASS"


def test_classify_aptos_zero_tests_no_match():
    # rc=0, no PASS/OK marker → zero tests matched.
    assert MV._classify_non_evm_outcome("aptos", 0, "Running Move unit tests\n") == "NO_TEST_MATCH"


def test_classify_sui_zero_tests_no_match():
    assert MV._classify_non_evm_outcome("sui", 0, "BUILDING pkg\n") == "NO_TEST_MATCH"


# --------------------------------------------------------------------------- #
# AP-EXEC-4 — dictated test-function name used verbatim                         #
# --------------------------------------------------------------------------- #

def test_id_subst_preserves_non_test_prefixed_name():
    argv = MV._format_test_command(
        "aptos move test --filter test_{id}", "overflow_check", None, language="aptos"
    )
    assert "overflow_check" in argv
    assert "test_overflow_check" not in argv


def test_id_subst_internal_test_substring():
    argv = MV._format_test_command(
        "cargo test {test_function} -- --nocapture", "test_a_test_b", None, language="solana"
    )
    assert "test_a_test_b" in argv  # internal 'test_' not mangled by global replace


# --------------------------------------------------------------------------- #
# AP-EXEC-5 — Go zero-tests-matched run is NO_TEST_MATCH                        #
# --------------------------------------------------------------------------- #

def test_classify_go_no_tests_to_run_is_no_match():
    out = "testing: warning: no tests to run\nPASS\nok\tgithub.com/x/y"
    assert MV._classify_non_evm_outcome("l1_go", 0, out) == "NO_TEST_MATCH"


def test_classify_go_real_pass_unchanged():
    out = "=== RUN   TestH3\n--- PASS: TestH3 (0.01s)\nPASS\nok\tgithub.com/x/y\t0.12s"
    assert MV._classify_non_evm_outcome("l1_go", 0, out) == "PASS"
