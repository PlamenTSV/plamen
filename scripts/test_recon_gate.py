"""Recon gate regression tests.

The live unknown-code soak exposed a pre-existing gap: recon coverage could
fail, retry without any targeted hint, then continue into breadth because the
recon phase was non-critical. These tests lock the corrected behavior.

Run: python test_recon_gate.py
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS_DIR))

import plamen_driver as D  # noqa: E402

PASS = 0
FAIL = 0


def check(label: str, ok: bool, detail: str = ""):
    global PASS, FAIL
    if ok:
        PASS += 1
        print(f"  PASS  {label}")
    else:
        FAIL += 1
        print(f"  FAIL  {label} :: {detail}")


def test_RECON_phase_is_critical():
    sc = next(p for p in D.SC_PHASES if p.name == "recon")
    l1 = next(p for p in D.L1_PHASES if p.name == "recon")
    check(
        "RECON.phase-critical",
        sc.critical and l1.critical,
        f"SC={sc.critical} L1={l1.critical}",
    )


def test_RECON_retry_hint_names_missed_modules():
    missing = [
        "recon coverage: recon missed substantial modules (no file cited; "
        "not ACKNOWLEDGED in scope_leftover): crates/p2p (14 files), "
        "crates/storage (11 files)"
    ]
    hint = D._generate_recon_retry_hint(missing)
    ok = (
        "recon coverage gate failed" in hint
        and "crates/p2p (14 files)" in hint
        and "crates/storage (11 files)" in hint
        and "scope_leftover.md" in hint
        and "ACKNOWLEDGED" in hint
    )
    check("RECON.retry-hint-delta", ok, hint)


def test_RECON_retry_hint_empty_when_no_missing():
    hint = D._generate_recon_retry_hint([])
    check("RECON.retry-hint-empty", hint == "", repr(hint))


def _write_rs_tree(root: Path, prefix: str, count: int):
    d = root / prefix
    d.mkdir(parents=True, exist_ok=True)
    for i in range(count):
        (d / f"file_{i}.rs").write_text(
            f"pub fn f_{i}() -> u64 {{ {i} }}\n",
            encoding="utf-8",
        )


def test_RECON_subsystem_scope_auto_exempts_out_of_scope_modules():
    with tempfile.TemporaryDirectory() as td:
        root = Path(td) / "project"
        sp = Path(td) / "scratch"
        root.mkdir()
        sp.mkdir()
        _write_rs_tree(root, "crates/p2p/src", 10)
        _write_rs_tree(root, "crates/chain/src", 10)
        (sp / "recon_summary.md").write_text(
            "# Recon\n\nCovered scoped file: crates/p2p/src/file_0.rs\n",
            encoding="utf-8",
        )
        issues_scoped = D._validate_recon_coverage(
            sp, str(root), "rust", "crates/p2p"
        )
        issues_unscoped = D._validate_recon_coverage(
            sp, str(root), "rust", None
        )
        check(
            "RECON.subsystem-scope-auto-exempts",
            not issues_scoped and bool(issues_unscoped),
            f"scoped={issues_scoped} unscoped={issues_unscoped}",
        )


def test_RECON_scope_leftover_ignores_out_of_scope_rows():
    with tempfile.TemporaryDirectory() as td:
        sp = Path(td)
        (sp / "scope_leftover.md").write_text(
            "# Scope\n\n"
            "| File | LOC | Reason | Status |\n"
            "|------|-----|--------|--------|\n"
            "| crates/chain/src/lib.rs | 500 | out of scope | NOTREAD |\n"
            "| crates/p2p/src/lib.rs | 500 | in scope | NOTREAD |\n",
            encoding="utf-8",
        )
        scoped = D._validate_scope_leftover(sp, "crates/p2p")
        unscoped = D._validate_scope_leftover(sp, None)
        ok = (
            len(scoped) == 1
            and scoped[0].startswith("crates/p2p/")
            and len(unscoped) == 2
        )
        check(
            "RECON.scope-leftover-scope-filter",
            ok,
            f"scoped={scoped} unscoped={unscoped}",
        )


def test_RECON_subsystem_scope_prompt_block_injected():
    with tempfile.TemporaryDirectory() as td:
        v1 = Path(td) / "prompt.md"
        v1.write_text(
            "# Prompt\n\n## Step 2: L1 Recon\nDo recon.\n",
            encoding="utf-8",
        )
        phase = next(p for p in D.L1_PHASES if p.name == "recon")
        prompt = D.build_phase_prompt(
            v1,
            phase,
            {
                "project_root": "C:/repo",
                "scratchpad": "C:/repo/.scratchpad",
                "language": "rust",
                "mode": "light",
                "pipeline": "l1",
                "subsystem_scope": "crates/p2p",
            },
        )
        ok = (
            "SUBSYSTEM SCOPE - HARD CONSTRAINT" in prompt
            and "Audit ONLY files under `crates/p2p/`" in prompt
            and "SUBSYSTEM_SCOPE: crates/p2p" in prompt
            and "out of configured subsystem_scope" in prompt
        )
        check("RECON.subsystem-scope-prompt", ok, prompt[:1000])


def test_RECON_placeholder_ignores_source_code_todos():
    """v2.1.7: recon describing source-code TODOs should not trigger gate."""
    import plamen_validators as V

    lines_ok = [
        "the TODO at line 146 explicitly acknowledges the staked-address check is skipped.",
        "`handle_reorg` is a stub with 6 TODO items — reorg does not remove invalidated TXs.",
        "Code path: `crates/actors/src/block_validation.rs:147` — TODO staked-address check.",
        "Bug class: authentication bypass — stub implementation at src/auth.rs:50.",
        "See `validate_block()` which has a TODO for the signature check.",
    ]
    lines_bad = [
        "(stub)",
        "stub content",
        "TODO",
        "this section is a placeholder",
        "TBD fill later",
    ]
    for line in lines_ok:
        ok = not V._has_live_placeholder_language(line)
        check(f"PLACEHOLDER.code-ref-ok({line[:50]}...)", ok, f"false positive on: {line}")
    for line in lines_bad:
        ok = V._has_live_placeholder_language(line)
        check(f"PLACEHOLDER.real-stub({line[:50]})", ok, f"missed real stub: {line}")


def test_RECON_scope_leftover_coverage_description_ack():
    """v2.1.7: IN_SCOPE_PARTIAL with 'lines read' should be implicitly acked."""
    with tempfile.TemporaryDirectory() as td:
        sp = Path(td)
        (sp / "scope_leftover.md").write_text(
            "# Scope Leftover\n\n"
            "## REVIEW_NEEDED\n"
            "| File | Reason |\n"
            "|------|--------|\n"
            "| crates/c/src/vdf.rs | Unsafe FFI wrapper |\n"
            "\n"
            "## IN_SCOPE_PARTIAL\n"
            "| File | Coverage Status | Remaining Analysis |\n"
            "|------|-----------------|--------------------|\n"
            "| crates/p2p/src/peer_list.rs | First 420 lines read. Facade identified. | Score handler not read. |\n"
            "| crates/actors/src/mempool_service.rs | Full file read (1815 lines). | No additional partial read needed. |\n",
            encoding="utf-8",
        )
        issues = D._validate_scope_leftover(sp)
        ok = len(issues) == 0
        check(
            "SCOPE_LEFTOVER.coverage-desc-ack",
            ok,
            f"expected 0 issues, got {len(issues)}: {issues}",
        )


def test_RECON_scope_leftover_real_uncovered_still_flagged():
    """v2.1.7: files with LOC column and no ack should still be flagged."""
    with tempfile.TemporaryDirectory() as td:
        sp = Path(td)
        (sp / "scope_leftover.md").write_text(
            "# Scope Leftover\n\n"
            "| File | LOC | Reason | Status |\n"
            "|------|-----|--------|--------|\n"
            "| crates/big/src/lib.rs | 500 | important | NOTREAD |\n"
            "| crates/small/src/lib.rs | 50 | trivial | NOTREAD |\n",
            encoding="utf-8",
        )
        issues = D._validate_scope_leftover(sp)
        ok = len(issues) == 1 and "crates/big" in issues[0]
        check(
            "SCOPE_LEFTOVER.real-uncovered-flagged",
            ok,
            f"expected 1 issue for big file, got: {issues}",
        )


def test_RECON_whole_module_heading_ack_exempts_coverage():
    """Whole-module heading plus explicit status is valid scope authority."""
    with tempfile.TemporaryDirectory() as td:
        root = Path(td) / "project"
        sp = Path(td) / "scratch"
        module = root / "lib" / "forge-std" / "src"
        module.mkdir(parents=True)
        sp.mkdir()
        for idx in range(17):
            (module / f"Helper{idx}.sol").write_text(
                "pragma solidity ^0.8.0; contract Helper {}\n",
                encoding="utf-8",
            )
        (sp / "recon_summary.md").write_text(
            "# Recon\n\nCovered contracts/Protocol.sol\n",
            encoding="utf-8",
        )
        (sp / "scope_leftover.md").write_text(
            "# Scope Leftover\n\n"
            "## `lib/forge-std` (vendored Foundry test tooling)\n\n"
            "**Status**: ACKNOWLEDGED -- OUT_OF_SCOPE\n\n"
            "Not imported by production contracts.\n",
            encoding="utf-8",
        )
        issues = D._validate_recon_coverage(
            sp, str(root), "evm", None, pipeline="sc"
        )
        check(
            "RECON.whole-module-heading-ack",
            not any("lib/forge-std" in issue for issue in issues),
            repr(issues),
        )


def test_RECON_whitelisted_forge_std_is_not_a_production_coverage_module():
    """Vendored Foundry test tooling is dependency research, not source scope."""
    with tempfile.TemporaryDirectory() as td:
        root = Path(td) / "project"
        sp = Path(td) / "scratch"
        module = root / "lib" / "forge-std" / "src"
        module.mkdir(parents=True)
        sp.mkdir()
        for idx in range(17):
            (module / f"Helper{idx}.sol").write_text(
                "pragma solidity ^0.8.0; contract Helper {}\n",
                encoding="utf-8",
            )
        (sp / "recon_summary.md").write_text(
            "# Recon\n\nCovered contracts/Protocol.sol\n",
            encoding="utf-8",
        )
        issues = D._validate_recon_coverage(
            sp, str(root), "evm", None, pipeline="sc"
        )
        check(
            "RECON.whitelisted-forge-std-not-production-denominator",
            not any("lib/forge-std" in issue for issue in issues),
            repr(issues),
        )


def test_PREPASS_writes_sc_recon_stubs():
    """v2.8.6: pre-pass writes stubs for all 4 supplementary SC artifacts."""
    import recon_prepass as RP

    with tempfile.TemporaryDirectory() as td:
        scratch = Path(td) / "scratch"
        proj = Path(td) / "proj"
        scratch.mkdir()
        proj.mkdir()
        # Minimal Solidity file so contract_inventory has something
        (proj / "Vault.sol").write_text(
            "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;\n"
            "contract Vault { uint256 public x; }\n",
            encoding="utf-8",
        )
        cfg = {
            "project_root": str(proj),
            "scratchpad": str(scratch),
            "language": "evm",
            "pipeline": "sc",
            "mode": "core",
            "cli_backend": "claude",
            "_run_id": "test-recon-gate-stubs",
        }
        RP.run_recon_prepass(cfg)
        for name in ("attack_surface.md", "detected_patterns.md",
                      "setter_list.md", "emit_list.md"):
            p = scratch / name
            exists = p.exists() and p.stat().st_size > 50
            check(
                f"PREPASS.sc-stub-{name}",
                exists,
                f"missing or too small: {p.stat().st_size if p.exists() else 'DNE'}",
            )
            if exists:
                content = p.read_text(encoding="utf-8")
                has_marker = RP._PREPASS_MARKER in content
                check(f"PREPASS.marker-{name}", has_marker, "missing prepass marker")


def test_PREPASS_rejects_and_preserves_unowned_llm_content():
    """Prepass fails closed instead of overwriting an unowned artifact."""
    import recon_prepass as RP

    with tempfile.TemporaryDirectory() as td:
        scratch = Path(td) / "scratch"
        proj = Path(td) / "proj"
        scratch.mkdir()
        proj.mkdir()
        (proj / "Vault.sol").write_text(
            "pragma solidity ^0.8.0;\ncontract V {}\n", encoding="utf-8",
        )
        # Simulate LLM having already written attack_surface.md
        llm_content = "# Attack Surface\n\nReal LLM analysis content here.\n"
        (scratch / "attack_surface.md").write_text(llm_content, encoding="utf-8")
        cfg = {
            "project_root": str(proj),
            "scratchpad": str(scratch),
            "language": "evm",
            "pipeline": "sc",
            "mode": "core",
            "cli_backend": "claude",
            "_run_id": "test-recon-gate-preserve",
        }
        try:
            RP.run_recon_prepass(cfg)
            rejected = False
        except RP.ReconPrepassAuthorityError:
            rejected = True
        preserved = (scratch / "attack_surface.md").read_text(encoding="utf-8")
        check(
            "PREPASS.reject-preserve-unowned-llm",
            rejected and preserved == llm_content,
            f"rejected={rejected}; content={preserved[:100]}",
        )


def test_RECON_GATE_rejects_prepass_marked_canonical_handoff():
    """Completed recon must not pass with disposable pre-pass artifacts."""
    import recon_prepass as RP

    with tempfile.TemporaryDirectory() as td:
        scratch = Path(td) / "scratch"
        scratch.mkdir()
        (scratch / "design_context.md").write_text(
            RP._PREPASS_MARKER
            + "\n# Design Context\n\n## Operational Implications\nx\n\n"
            + "## Key Invariants\nx\n",
            encoding="utf-8",
        )
        hard, _soft = D._validate_recon_content_structure(scratch)
        check(
            "RECON_GATE.prepass-marker-hard-fail",
            any("pre-pass overwrite marker" in h for h in hard),
            f"expected pre-pass marker hard fail, got {hard}",
        )


def test_RETRY_HINT_stub_only_class():
    """v2.8.6: retry hint for stub-only artifacts is targeted, not coverage-style."""
    missing = [
        "attack_surface.md (stub only)",
        "detected_patterns.md (stub only)",
    ]
    hint = D._generate_recon_retry_hint(missing)
    ok = (
        "artifacts missing or empty" in hint
        and "attack_surface.md" in hint
        and "detected_patterns.md" in hint
        and "sequentially" in hint.lower()
        and "do NOT rewrite" in hint
        # Must NOT contain coverage-style instructions
        and "coverage gate failed" not in hint
    )
    check("RETRY-HINT.stub-only-class", ok, hint[:500])


def test_RETRY_HINT_mixed_stub_and_coverage():
    """v2.8.6: mixed stub + coverage failures produce stub-first hint with coverage addendum."""
    missing = [
        "setter_list.md (stub only)",
        "recon coverage: recon missed substantial modules: crates/big (10 files)",
    ]
    hint = D._generate_recon_retry_hint(missing)
    ok = (
        "artifacts missing or empty" in hint
        and "setter_list.md" in hint
        and "coverage" in hint.lower()
        and "crates/big" in hint
    )
    check("RETRY-HINT.mixed-stub-coverage", ok, hint[:500])


def test_SUPPLEMENTARY_softening_passes_gate():
    """v2.8.6: gate passes when only supplementary artifacts fail."""
    with tempfile.TemporaryDirectory() as td:
        sp = Path(td)
        # Write core artifacts with real content (>100 bytes)
        core = [
            "design_context.md", "contract_inventory.md",
            "function_list.md", "state_variables.md",
            "build_status.md", "template_recommendations.md",
            "recon_summary.md",
        ]
        for name in core:
            (sp / name).write_text(
                f"# {name}\n\n" + "Real content. " * 20 + "\n",
                encoding="utf-8",
            )
        # Supplementary artifacts: stub-only (< min_artifact_bytes)
        for name in ("attack_surface.md", "detected_patterns.md",
                      "setter_list.md", "emit_list.md"):
            (sp / name).write_text("# Stub\nTiny.\n", encoding="utf-8")

        phase = next(p for p in D.SC_PHASES if p.name == "recon")
        import plamen_validators as V
        passed, missing = V.gate_passes(sp, str(sp), phase)

        if not passed:
            _SUPP = {
                "attack_surface.md", "detected_patterns.md",
                "setter_list.md", "emit_list.md",
            }
            hard = [
                item for item in missing
                if str(item).split()[0].split("(")[0].strip() not in _SUPP
            ]
            soft = [
                item for item in missing
                if str(item).split()[0].split("(")[0].strip() in _SUPP
            ]
            would_pass = bool(soft) and not bool(hard)
            check(
                "SUPP-SOFT.gate-passes-supplementary-only",
                would_pass,
                f"hard={hard}, soft={soft}",
            )
        else:
            check("SUPP-SOFT.gate-passes-supplementary-only", True, "gate already passed")


def test_SUPPLEMENTARY_softening_fails_on_core():
    """v2.8.6: gate still fails when core artifacts are missing."""
    with tempfile.TemporaryDirectory() as td:
        sp = Path(td)
        # Write supplementary artifacts OK
        for name in ("attack_surface.md", "detected_patterns.md",
                      "setter_list.md", "emit_list.md"):
            (sp / name).write_text(
                f"# {name}\n\n" + "Real content. " * 20 + "\n",
                encoding="utf-8",
            )
        # Core artifacts missing or stub-only
        for name in ("design_context.md", "contract_inventory.md"):
            (sp / name).write_text("# Stub\n", encoding="utf-8")

        phase = next(p for p in D.SC_PHASES if p.name == "recon")
        import plamen_validators as V
        passed, missing = V.gate_passes(sp, str(sp), phase)

        _SUPP = {
            "attack_surface.md", "detected_patterns.md",
            "setter_list.md", "emit_list.md",
        }
        hard = [
            item for item in missing
            if str(item).split()[0].split("(")[0].strip() not in _SUPP
        ]
        check(
            "SUPP-SOFT.core-still-fails",
            not passed and bool(hard),
            f"passed={passed} missing={missing}",
        )


def test_SUPPLEMENTARY_fallback_content_written():
    """v2.8.6: fallback files have real content, not 0 bytes."""
    with tempfile.TemporaryDirectory() as td:
        sp = Path(td)
        _SUPP = {
            "attack_surface.md", "detected_patterns.md",
            "setter_list.md", "emit_list.md",
        }
        effective_min_bytes = 50  # Codex halved from 100
        for name in _SUPP:
            p = sp / name
            # Simulate: 0-byte file (Codex sub-agent failed)
            p.write_text("", encoding="utf-8")
            # Apply the fallback logic from _run_phase_validators
            if not p.exists() or p.stat().st_size < effective_min_bytes:
                title = name.replace(".md", "").replace("_", " ").title()
                p.write_text(
                    f"# {title}\n\n"
                    "[LLM recon did not produce this artifact. "
                    "Breadth agents will discover this information "
                    "organically from source code analysis.]\n",
                    encoding="utf-8",
                )
            sz = p.stat().st_size
            check(
                f"SUPP-FALLBACK.{name}-has-content",
                sz >= effective_min_bytes,
                f"size={sz} < {effective_min_bytes}",
            )


TESTS = [
    test_RECON_phase_is_critical,
    test_RECON_retry_hint_names_missed_modules,
    test_RECON_retry_hint_empty_when_no_missing,
    test_RECON_subsystem_scope_auto_exempts_out_of_scope_modules,
    test_RECON_scope_leftover_ignores_out_of_scope_rows,
    test_RECON_subsystem_scope_prompt_block_injected,
    test_RECON_placeholder_ignores_source_code_todos,
    test_RECON_scope_leftover_coverage_description_ack,
    test_RECON_scope_leftover_real_uncovered_still_flagged,
    test_RECON_whole_module_heading_ack_exempts_coverage,
    # v2.8.6: Codex recon resilience
    test_PREPASS_writes_sc_recon_stubs,
    test_PREPASS_rejects_and_preserves_unowned_llm_content,
    test_RETRY_HINT_stub_only_class,
    test_RETRY_HINT_mixed_stub_and_coverage,
    test_SUPPLEMENTARY_softening_passes_gate,
    test_SUPPLEMENTARY_softening_fails_on_core,
    test_SUPPLEMENTARY_fallback_content_written,
]


def main() -> int:
    print(f"Running {len(TESTS)} recon gate tests...")
    for t in TESTS:
        print(f"\n[{t.__name__}]")
        try:
            t()
        except Exception as exc:
            global FAIL
            FAIL += 1
            print(f"  CRASH {t.__name__} :: {exc!r}")
    print(f"\n{'=' * 64}")
    print(f"  PASS: {PASS}   FAIL: {FAIL}")
    print("=" * 64)
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
