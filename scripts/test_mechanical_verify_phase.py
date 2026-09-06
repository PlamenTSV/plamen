"""Tests for the Phase 5b mechanical-verify Python phase.

The phase wraps `spike_mechanical_poc.py`'s parser and forge runner with
a cross-ecosystem dispatcher driven by `language-toolchain-registry.json`.
These tests cover:

  - Registry load + L1 overlay injection (l1_go / l1_rust)
  - Command-template substitution per ecosystem
  - Non-EVM outcome classification (PASS / FAIL / COMPILE_FAIL / NO_TEST_MATCH)
  - Recommended tag mapping per status
  - Verify-file annotation (append-only, idempotent)
  - Phase orchestration: opt-in default-off, toolchain-unavailable short-circuit,
    manifest writing, phase-budget exhaustion

Run: `pytest scripts/test_mechanical_verify_phase.py -v`
"""
from __future__ import annotations

import importlib
import json
import os
import sys
from pathlib import Path

import pytest


def _mv():
    sys.path.insert(0, os.path.join(os.path.dirname(__file__)))
    if "mechanical_verify" in sys.modules:
        del sys.modules["mechanical_verify"]
    return importlib.import_module("mechanical_verify")


# ---------------------------------------------------------------------------
# Registry load + L1 overlay
# ---------------------------------------------------------------------------


def test_registry_load_includes_all_sc_languages():
    mv = _mv()
    reg = mv._load_registry()
    langs = reg["languages"]
    for name in ("evm", "solana", "aptos", "sui", "soroban"):
        assert name in langs, f"{name} missing from registry"


def test_registry_load_injects_l1_go_and_l1_rust():
    mv = _mv()
    reg = mv._load_registry()
    langs = reg["languages"]
    assert "l1_go" in langs and "build_command" in langs["l1_go"]
    assert "l1_rust" in langs and "build_command" in langs["l1_rust"]
    assert "go test" in langs["l1_go"]["test_command"]
    assert "cargo test" in langs["l1_rust"]["test_command"]


def test_l1_overlay_idempotent(tmp_path):
    """Calling _ensure_l1_registry_entries twice doesn't duplicate."""
    mv = _mv()
    reg = {"version": 2, "languages": {}}
    mv._ensure_l1_registry_entries(reg)
    mv._ensure_l1_registry_entries(reg)  # second call no-op
    assert list(reg["languages"].keys()) == ["l1_go", "l1_rust"]


# ---------------------------------------------------------------------------
# Command-template substitution
# ---------------------------------------------------------------------------


def test_format_test_command_cargo():
    mv = _mv()
    cmd = mv._format_test_command(
        "cargo test {test_function} -- --nocapture", "test_h3", "tests/x.rs"
    )
    assert cmd == ["cargo", "test", "test_h3", "--", "--nocapture"]


def test_format_test_command_aptos():
    mv = _mv()
    cmd = mv._format_test_command(
        "aptos move test --filter test_{id}", "test_h3", None
    )
    assert cmd == ["aptos", "move", "test", "--filter", "test_h3"]


def test_format_test_command_sui_positional():
    mv = _mv()
    cmd = mv._format_test_command(
        "sui move test {test_name}", "test_h3", None
    )
    assert cmd == ["sui", "move", "test", "test_h3"]


def test_format_test_command_go():
    mv = _mv()
    cmd = mv._format_test_command(
        "go test -run {test_function} -v ./...", "TestH3", None
    )
    assert cmd == ["go", "test", "-run", "TestH3", "-v", "./..."]


def test_format_test_command_none_function_no_crash():
    """Regression: a None test_function must NOT raise
    'replace() argument 2 must be str, not None' (it degraded the whole
    sc_mechanical_verify phase on DFlow). Falls back to empty test name and
    localizes the failure to that one finding."""
    mv = _mv()
    cmd = mv._format_test_command(
        "cargo test {test_function} -- --nocapture", None, "tests/x.rs"
    )
    assert isinstance(cmd, list)
    assert cmd[:2] == ["cargo", "test"]
    # l1_go path with None must also not crash (the -run anchor is skipped)
    cmd_go = mv._format_test_command(
        "go test -run {test_function} -v ./...", None, None, "l1_go"
    )
    assert isinstance(cmd_go, list)
    assert cmd_go[:2] == ["go", "test"]


# ---------------------------------------------------------------------------
# Outcome classification
# ---------------------------------------------------------------------------


def test_classify_solana_pass():
    mv = _mv()
    out = "running 1 test\ntest test_x ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored"
    assert mv._classify_non_evm_outcome("solana", 0, out) == "PASS"


def test_classify_solana_compile_fail():
    mv = _mv()
    out = "error[E0277]: trait not satisfied\nerror: could not compile `x`"
    assert mv._classify_non_evm_outcome("solana", 1, out) == "COMPILE_FAIL"


def test_classify_solana_fail():
    mv = _mv()
    out = "test test_x ... FAILED\n\n1 passed; 1 failed"
    assert mv._classify_non_evm_outcome("solana", 1, out) == "FAIL"


def test_classify_go_pass():
    mv = _mv()
    out = "=== RUN   TestH3\n--- PASS: TestH3 (0.01s)\nPASS\nok\tgithub.com/x/y\t0.123s"
    assert mv._classify_non_evm_outcome("l1_go", 0, out) == "PASS"


def test_classify_go_no_match():
    mv = _mv()
    out = "testing: warning: no tests to run\nPASS\nok\tgithub.com/x/y"
    # AP-EXEC-5: Go prints `ok\tpkg` + PASS even when `-run` matched NOTHING.
    # Reading that as PASS fabricated a [POC-PASS] for a zero-tests-matched run.
    # The early "no tests to run" guard now classifies it NO_TEST_MATCH so it
    # maps to [CODE-TRACE], not a mechanical proof.
    assert mv._classify_non_evm_outcome("l1_go", 0, out) == "NO_TEST_MATCH"


def test_classify_aptos_pass():
    mv = _mv()
    out = "Running Move unit tests\n[ PASS    ] 0x1::module::test_x\nTest result: OK"
    assert mv._classify_non_evm_outcome("aptos", 0, out) == "PASS"


def test_classify_sui_pass():
    mv = _mv()
    out = "Running Move unit tests\n[ PASS    ] sui_x::test_x\nTest result: OK"
    assert mv._classify_non_evm_outcome("sui", 0, out) == "PASS"


# ---------------------------------------------------------------------------
# Tag mapping
# ---------------------------------------------------------------------------


def test_recommended_tag_mapping():
    mv = _mv()
    assert mv._recommended_tag("PASS") == "[POC-PASS]"
    assert mv._recommended_tag("FAIL") == "[POC-FAIL]"
    assert mv._recommended_tag("COMPILE_FAIL") == "[CODE-TRACE]"
    assert mv._recommended_tag("TIMEOUT") == "[CODE-TRACE]"
    # Preserve existing tag on operational failure
    assert mv._recommended_tag("TOOLCHAIN_UNAVAILABLE") == ""
    assert mv._recommended_tag("BUILD_FAILED") == ""
    assert mv._recommended_tag("EXEC_ERROR") == ""


# ---------------------------------------------------------------------------
# Verify-file annotation (append-only, idempotent)
# ---------------------------------------------------------------------------


def test_annotate_verify_file_appends_pass_marker(tmp_path):
    mv = _mv()
    vf = tmp_path / "verify_H-1.md"
    vf.write_text(
        "# Verification: H-1\n\n"
        "**Verdict**: CONFIRMED\n"
        "**Evidence Tag**: [CODE-TRACE]\n\n"
        "```solidity\nfunction test_h1() public { assertEq(a, b); }\n```\n",
        encoding="utf-8",
    )
    result = mv.ExecResult(
        verify_file="verify_H-1.md", finding_id="H-1", language="evm",
        status="PASS", duration_s=1.5,
        test_command_used="forge test --match-test test_h1 -vv",
    )
    assert mv._annotate_verify_file(vf, result) is True
    text = vf.read_text(encoding="utf-8")
    assert "Mechanical-Verified" in text
    assert "Status: PASS" in text
    assert "Mechanical-Tag" in text and "[POC-PASS]" in text
    assert "forge test --match-test test_h1" in text
    # Re-annotating with same status is a no-op (idempotent)
    assert mv._annotate_verify_file(vf, result) is False


def test_annotate_verify_file_preserves_llm_body(tmp_path):
    mv = _mv()
    vf = tmp_path / "verify_H-2.md"
    original = (
        "# Verification: H-2\n\n"
        "**Verdict**: CONFIRMED\n"
        "**Evidence Tag**: [POC-PASS] (was claimed)\n\n"
        "## Description\nThe bug allows...\n\n"
        "## Impact\nUsers lose funds.\n"
    )
    vf.write_text(original, encoding="utf-8")
    result = mv.ExecResult(
        verify_file="verify_H-2.md", finding_id="H-2", language="evm",
        status="FAIL", duration_s=0.5, stdout_tail="assertion failed",
    )
    mv._annotate_verify_file(vf, result)
    text = vf.read_text(encoding="utf-8")
    # Body preserved
    assert "The bug allows" in text
    assert "Users lose funds" in text
    # Annotation appended
    assert "Status: FAIL" in text or "FAIL" in text
    assert "Mechanical-Tag" in text


def test_annotate_verify_file_handles_toolchain_unavailable(tmp_path):
    mv = _mv()
    vf = tmp_path / "verify_H-3.md"
    vf.write_text("**Evidence Tag**: [CODE-TRACE]\n", encoding="utf-8")
    result = mv.ExecResult(
        verify_file="verify_H-3.md", finding_id="H-3", language="aptos",
        status="TOOLCHAIN_UNAVAILABLE", stdout_tail="aptos not on PATH",
    )
    mv._annotate_verify_file(vf, result)
    text = vf.read_text(encoding="utf-8")
    # Line is bold-formatted (**Mechanical-Verified**: NO (...)). Match the
    # status-bearing payload portion rather than the exact bold prefix so the
    # test is bold-marker agnostic.
    assert "Mechanical-Verified" in text and "NO" in text
    assert "TOOLCHAIN_UNAVAILABLE" in text
    # No Mechanical-Tag for operational failure (preserve existing tag)
    assert "Mechanical-Tag" not in text


# ---------------------------------------------------------------------------
# Phase orchestration
# ---------------------------------------------------------------------------


def test_run_phase_no_verify_files_short_circuits(tmp_path):
    mv = _mv()
    summary = mv.run_phase5b_mechanical_verify(
        tmp_path, tmp_path, "evm",
        per_test_timeout_s=10, phase_budget_s=10,
    )
    assert summary["status"] == "no_verify_files"
    assert (tmp_path / "mechanical_verify_manifest.md").exists()
    assert (tmp_path / "mechanical_verify_manifest.json").exists()


def test_run_phase_no_test_file_marks_skip(tmp_path, monkeypatch):
    """Verify file with no Test File field → NO_TEST_FILE status, no test runs."""
    mv = _mv()
    # Toolchain must APPEAR available so this isolates no-test-file handling
    # from whether `forge` is installed on the runner (it is not, on CI).
    monkeypatch.setattr(mv.shutil, "which", lambda b: "/usr/bin/" + b)
    (tmp_path / "verify_H-1.md").write_text(
        "# Verification: H-1\n\n"
        "**Verdict**: CONFIRMED\n"
        "**Evidence Tag**: [CODE-TRACE]\n\n"
        "- **Test File**: N/A\n"
        "- **Command**: N/A\n",
        encoding="utf-8",
    )
    summary = mv.run_phase5b_mechanical_verify(
        tmp_path, tmp_path, "evm",
        per_test_timeout_s=10, phase_budget_s=10,
    )
    # Execution classification succeeded, but the fixture intentionally has
    # no AG1 identity/receipt/proposal authority.  Haltless operation must be
    # loud DEGRADED debt, never a clean phase result.
    assert summary["status"] == "degraded"
    assert summary["counts"].get("NO_TEST_FILE") == 1
    assert summary["authority_rejections"] == 1
    debt = json.loads(
        (tmp_path / "mechanical_successor_authority.json").read_text(
            encoding="utf-8"
        )
    )
    assert debt["status"] == "DEGRADED"
    assert summary["p1e_execution_scope"]["status"] == "DEGRADED"
    scope = json.loads(
        (tmp_path / "verify_H-1.execution_scope_assessment.json").read_text(
            encoding="utf-8"
        )
    )
    assert scope["candidate_state"] == "VISIBLE_EVIDENCE_DEBT"
    assert scope["negative_disposition_eligible"] is False


def test_run_phase_toolchain_unavailable_short_circuit(tmp_path, monkeypatch):
    """When the test runner binary is absent, mark all findings TOOLCHAIN_UNAVAILABLE.

    Driver must NOT crash; manifest documents the operational failure.
    """
    mv = _mv()
    # Force the binary lookup to return None
    monkeypatch.setattr(mv.shutil, "which", lambda b: None)
    (tmp_path / "verify_H-1.md").write_text(
        "**Test File**: `test/Foo.t.sol` contract Foo function `test_h1()`\n"
        "**Command**: `forge test --match-test test_h1`\n",
        encoding="utf-8",
    )
    summary = mv.run_phase5b_mechanical_verify(
        tmp_path, tmp_path, "evm",
        per_test_timeout_s=10, phase_budget_s=10,
    )
    assert summary["status"] == "toolchain_unavailable"
    assert summary["p1e_execution_scope"]["status"] == "DEGRADED"
    scope = json.loads(
        (tmp_path / "verify_H-1.execution_scope_assessment.json").read_text(
            encoding="utf-8"
        )
    )
    assert scope["execution_authenticity"] == "UNPROVEN_METADATA"
    assert scope["harm_evidence_eligible"] is False
    assert scope["negative_disposition_eligible"] is False
    manifest = (tmp_path / "mechanical_verify_manifest.md").read_text(encoding="utf-8")
    assert "TOOLCHAIN_UNAVAILABLE" in manifest


def test_run_phase_skips_verify_aggregate_files(tmp_path, monkeypatch):
    """verify_core.md / verify_aggregate.md must NOT be treated as per-finding verify files."""
    mv = _mv()
    monkeypatch.setattr(mv.shutil, "which", lambda b: None)
    (tmp_path / "verify_core.md").write_text("aggregate", encoding="utf-8")
    (tmp_path / "verify_aggregate.md").write_text("aggregate", encoding="utf-8")
    summary = mv.run_phase5b_mechanical_verify(
        tmp_path, tmp_path, "evm",
        per_test_timeout_s=5, phase_budget_s=5,
    )
    # Only aggregate files present → treated as no-verify-files
    assert summary["status"] == "no_verify_files"


def test_run_phase_writes_manifest_with_per_finding_rows(tmp_path, monkeypatch):
    mv = _mv()
    monkeypatch.setattr(mv.shutil, "which", lambda b: None)
    for i in (1, 2, 3):
        (tmp_path / f"verify_H-{i}.md").write_text(
            f"**Test File**: `test/H{i}.t.sol` function `test_h{i}()`\n"
            f"**Command**: `forge test --match-test test_h{i}`\n",
            encoding="utf-8",
        )
    summary = mv.run_phase5b_mechanical_verify(
        tmp_path, tmp_path, "evm",
        per_test_timeout_s=5, phase_budget_s=5,
    )
    js = json.loads((tmp_path / "mechanical_verify_manifest.json").read_text(encoding="utf-8"))
    assert len(js["results"]) == 3
    assert all(r["status"] == "TOOLCHAIN_UNAVAILABLE" for r in js["results"])


def test_phase_added_to_sc_phases_after_verify_aggregate():
    """SC_PHASES contains sc_mechanical_verify between sc_verify_aggregate and skeptic."""
    sys.path.insert(0, os.path.join(os.path.dirname(__file__)))
    if "plamen_types" in sys.modules:
        del sys.modules["plamen_types"]
    import plamen_types as t
    order = [p.name for p in t.SC_PHASES]
    assert "sc_mechanical_verify" in order
    assert order.index("sc_verify_aggregate") < order.index("sc_mechanical_verify")
    # Must run before skeptic so mechanical evidence informs severity calibration
    assert order.index("sc_mechanical_verify") < order.index("skeptic")


def test_phase_added_to_l1_phases_after_verify_aggregate():
    sys.path.insert(0, os.path.join(os.path.dirname(__file__)))
    if "plamen_types" in sys.modules:
        del sys.modules["plamen_types"]
    import plamen_types as t
    order = [p.name for p in t.L1_PHASES]
    assert "mechanical_verify" in order
    assert order.index("verify_aggregate") < order.index("mechanical_verify")
    assert order.index("mechanical_verify") < order.index("skeptic")


# ---------------------------------------------------------------------------
# Build-root resolution (an observed mass NO_TEST_FILE bug)
#
# The audit's project_root is the scope dir (e.g. omni-chain-contracts/
# contracts) but foundry.toml + test/ live at the parent. _find_build_root
# must walk up to the manifest-owning directory.
# ---------------------------------------------------------------------------


def test_find_build_root_walks_up_to_foundry_toml(tmp_path):
    mv = _mv()
    root = tmp_path / "omni-chain-contracts"
    scope = root / "contracts"
    scope.mkdir(parents=True)
    (root / "foundry.toml").write_text("[profile.default]\n", encoding="utf-8")
    (root / "test").mkdir()
    # project_root is the scope subdir; build root must be the parent
    assert mv._find_build_root(scope, "evm") == root.resolve()


def test_find_build_root_falls_back_to_project_root(tmp_path):
    mv = _mv()
    scope = tmp_path / "no_manifest_anywhere"
    scope.mkdir()
    # no manifest → degrade to project_root, not crash
    assert mv._find_build_root(scope, "evm") == scope.resolve()


def test_find_build_root_per_ecosystem_manifest(tmp_path):
    mv = _mv()
    for lang, manifest in (("solana", "Cargo.toml"), ("aptos", "Move.toml"),
                          ("sui", "Move.toml"), ("l1_go", "go.mod"),
                          ("l1_rust", "Cargo.toml")):
        root = tmp_path / f"{lang}_proj"
        scope = root / "src"
        scope.mkdir(parents=True)
        (root / manifest).write_text("x", encoding="utf-8")
        assert mv._find_build_root(scope, lang) == root.resolve(), lang


def test_classify_evm_outcome():
    mv = _mv()
    assert mv._classify_evm_outcome(
        0, "Ran 1 test\n[PASS] test_x() (gas: 100)\nSuite result: ok. 1 passed"
    ) == "PASS"
    assert mv._classify_evm_outcome(1, "[FAIL: assertion failed] test_x()") == "FAIL"
    assert mv._classify_evm_outcome(1, "Compiler run failed\nError: ...") == "COMPILE_FAIL"
    assert mv._classify_evm_outcome(0, "No tests match the provided pattern") == "NO_TEST_MATCH"
    assert mv._classify_evm_outcome(1, "panic somewhere") == "FAIL"


def test_evm_forge_filter_prefers_match_test():
    mv = _mv()

    class _P:
        test_command = "forge test --match-test test_h12 -vvv"
        test_function = None
    assert mv._evm_forge_filter(_P(), "test/X.t.sol") == ["--match-test", "test_h12"]


def test_evm_forge_filter_match_contract_fallback():
    mv = _mv()

    class _P:
        test_command = "forge test --match-contract VerifyH12Poc -vvv"
        test_function = None
    assert mv._evm_forge_filter(_P(), "test/X.t.sol") == ["--match-contract", "VerifyH12Poc"]


def test_evm_forge_filter_match_path_last_resort():
    mv = _mv()

    class _P:
        test_command = "forge test"
        test_function = None
    # No --match-test, no --match-contract, no function → run whole file
    assert mv._evm_forge_filter(_P(), "test/X.t.sol") == ["--match-path", "test/X.t.sol"]


def test_resolve_test_path_finds_under_build_root_not_scope(tmp_path):
    """The exact observed bug: test file is under build_root/test/, not scope/test/."""
    mv = _mv()
    build_root = tmp_path / "project"
    scope = build_root / "contracts"
    (build_root / "test").mkdir(parents=True)
    scope.mkdir()
    tfile = build_root / "test" / "VerifyH1Poc.t.sol"
    tfile.write_text("// test", encoding="utf-8")

    class _P:
        test_file_resolved = "test/VerifyH1Poc.t.sol"
        test_function = "test_h1"
    # resolving against the scope dir would miss it; against build_root finds it
    assert mv._resolve_test_path_for(_P(), build_root, scope) == tfile


def test_phase_not_critical():
    """sc_mechanical_verify must NOT halt the pipeline on failure."""
    sys.path.insert(0, os.path.join(os.path.dirname(__file__)))
    if "plamen_types" in sys.modules:
        del sys.modules["plamen_types"]
    import plamen_types as t
    sc = {p.name: p for p in t.SC_PHASES}
    l1 = {p.name: p for p in t.L1_PHASES}
    assert sc["sc_mechanical_verify"].critical is False
    assert l1["mechanical_verify"].critical is False


# ---------------------------------------------------------------------------
# Default-ON dispatch (no env, no config flag)
# ---------------------------------------------------------------------------


def _eval_disabled(env_val: str | None, cfg_val):
    """Replicate the driver's disabled-check logic to test default-ON semantics."""
    _mv_env = (env_val or "").lower()
    disabled = (
        _mv_env in ("0", "false", "no", "off")
        or cfg_val is False
    )
    return disabled


def test_default_is_on_when_env_and_config_absent():
    """No MECHANICAL_VERIFY env, no config flag → phase RUNS."""
    assert _eval_disabled(None, None) is False
    assert _eval_disabled("", None) is False


def test_explicit_true_keeps_on():
    """MECHANICAL_VERIFY=true keeps the phase on (back-compat)."""
    for val in ("true", "TRUE", "1", "yes", "on"):
        assert _eval_disabled(val, None) is False, val
    assert _eval_disabled(None, True) is False


def test_explicit_false_disables():
    """MECHANICAL_VERIFY=false disables the phase."""
    for val in ("false", "FALSE", "0", "no", "off"):
        assert _eval_disabled(val, None) is True, val
    assert _eval_disabled(None, False) is True


def test_unknown_env_value_keeps_default_on():
    """Garbage in env (e.g., 'banana') → phase stays ON. Only explicit
    off-values disable the phase."""
    assert _eval_disabled("banana", None) is False
    assert _eval_disabled("MECHANICAL_VERIFY", None) is False  # accidental copy-paste
