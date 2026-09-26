"""Tests for the obligation + attention gates (Steps 5-8 of recall-recovery plan).

Covers:
  - _check_opengrep_obligation_coverage (Step 5)
  - _check_function_summary_obligation (Step 6)
  - _check_pde_section_present (Step 7)
  - _check_perturbation_block_per_finding (Step 8)
  - _OBLIG_RECEIPT_RE parsing

All four gates are WARNING-class for first ship: they emit issues for the
driver to log, but never flip `passed` to False. These tests verify the
mechanical correctness of the emit-vs-no-emit decision.

Run: `pytest scripts/test_obligation_and_attention_gates.py -v`
"""
from __future__ import annotations

import importlib
import os
import sys
from pathlib import Path


def _v():
    sys.path.insert(0, os.path.join(os.path.dirname(__file__)))
    if "plamen_validators" in sys.modules:
        del sys.modules["plamen_validators"]
    return importlib.import_module("plamen_validators")


def _m():
    sys.path.insert(0, os.path.join(os.path.dirname(__file__)))
    if "plamen_mechanical" in sys.modules:
        del sys.modules["plamen_mechanical"]
    return importlib.import_module("plamen_mechanical")


def _d():
    sys.path.insert(0, os.path.join(os.path.dirname(__file__)))
    return importlib.import_module("plamen_driver")


# ---------------------------------------------------------------------------
# Receipt regex
# ---------------------------------------------------------------------------


def test_oblig_receipt_re_matches_canonical_form():
    v = _v()
    line = (
        "[OBLIG:opengrep_findings.md:17] STATUS:REPORTED "
        "KEY:basic-arithmetic-underflow@foo.sol:L462 -> H-7"
    )
    m = v._OBLIG_RECEIPT_RE.search(line)
    assert m
    assert m.group("artifact") == "opengrep_findings.md"
    assert m.group("row") == "17"
    assert m.group("status").upper() == "REPORTED"


def test_oblig_receipt_re_short_status_codes():
    v = _v()
    for status_short, status_long in (("R", "REPORTED"), ("D", "DISMISSED"), ("C", "CARRIED")):
        line = f"[OBLIG:function_summary.md:Vault.deposit] STATUS:{status_short} KEY:x -> y"
        m = v._OBLIG_RECEIPT_RE.search(line)
        assert m, f"failed on short code {status_short}"
        assert m.group("status").upper() == status_short


def test_oblig_receipt_re_unicode_arrow():
    v = _v()
    line = "[OBLIG:opengrep_findings.md:5] STATUS:DISMISSED KEY:foo@bar.sol:L10 → out_of_scope"
    m = v._OBLIG_RECEIPT_RE.search(line)
    assert m
    assert m.group("status").upper() == "DISMISSED"


def test_obligation_retention_requires_chain_upgrade_coverage_or_absorber(tmp_path):
    v = _v()
    (tmp_path / "obligation_ledger.json").write_text(
        '{\n'
        '  "schema_version": "plamen.obligation_ledger.v1",\n'
        '  "obligations": [\n'
        '    {"id":"OBL-CHAIN-CH-1","class":"chain_upgrade_retention","status":"active",'
        '"severity_signal":"High","source_id":"CH-1"}\n'
        '  ]\n'
        '}\n',
        encoding="utf-8",
    )
    bad = v._validate_obligation_ledger_retention(
        tmp_path,
        "A nearby composition is discussed, but the chain itself is never named.",
    )
    assert bad
    good = v._validate_obligation_ledger_retention(
        tmp_path,
        "CH-1 is preserved and merged into H-01 in the report.",
    )
    assert good == []


def test_report_coverage_parser_does_not_read_obligation_status_as_severity():
    v = _v()
    text = (
        "# Report Coverage\n\n"
        "| Source File | Candidate ID / Label | Severity Signal | Status | Report ID / Refutation / Reason |\n"
        "|---|---|---|---|---|\n"
        "| depth_token_flow_findings.md | H-01 (INV-001) | High | PROMOTED | H-01 |\n\n"
        "## Chain Retention Obligations\n\n"
        "| Obligation ID | Field Binding | Status | Covered By |\n"
        "|---|---|---|---|\n"
        "| OBL-CHAIN-CH-1 | inputToken <-> outputToken | covered | H-01 |\n"
        "| OBL-CHAIN-CH-2 | fromToken <-> toToken | covered | M-01 |\n"
    )
    rows = v._parse_report_coverage_rows_for_contract(text)
    assert len(rows) == 1
    assert rows[0]["severity signal"] == "High"


# ---------------------------------------------------------------------------
# Step 5: opengrep obligation gate
# ---------------------------------------------------------------------------


def test_opengrep_gate_vacuous_when_artifact_missing(tmp_path):
    v = _v()
    assert v._check_opengrep_obligation_coverage(tmp_path, "thorough") == []


def test_opengrep_gate_vacuous_when_zero_rows(tmp_path):
    v = _v()
    (tmp_path / "opengrep_findings.md").write_text(
        "# OpenGrep Findings\n\n> **Total**: 0 findings\n\n"
        "| # | Rule | Level | Location | Message |\n"
        "|---|------|-------|----------|----------|\n",
        encoding="utf-8",
    )
    assert v._check_opengrep_obligation_coverage(tmp_path, "thorough") == []


def test_opengrep_gate_fires_when_rows_have_no_receipts(tmp_path):
    v = _v()
    (tmp_path / "opengrep_findings.md").write_text(
        "# OpenGrep Findings\n\n"
        "| # | Rule | Level | Location | Message |\n"
        "|---|------|-------|----------|----------|\n"
        "| 1 | rule-a | warning | foo.sol:L1 | msg a |\n"
        "| 2 | rule-b | warning | foo.sol:L2 | msg b |\n"
        "| 3 | rule-c | warning | foo.sol:L3 | msg c |\n",
        encoding="utf-8",
    )
    (tmp_path / "analysis_core.md").write_text(
        "## Findings\nSome analysis without obligation receipts.\n",
        encoding="utf-8",
    )
    issues = v._check_opengrep_obligation_coverage(tmp_path, "thorough")
    assert issues
    assert "3 row(s)" in issues[0] or "3" in issues[0]
    # Gap file written for post-mortem
    assert (tmp_path / "opengrep_obligation_gap.md").exists()


def test_opengrep_gate_clears_when_all_rows_receipted(tmp_path):
    v = _v()
    (tmp_path / "opengrep_findings.md").write_text(
        "| # | Rule | Level | Location | Message |\n"
        "|---|------|-------|----------|----------|\n"
        "| 1 | rule-a | warning | foo.sol:L1 | a |\n"
        "| 2 | rule-b | warning | foo.sol:L2 | b |\n",
        encoding="utf-8",
    )
    (tmp_path / "analysis_core.md").write_text(
        "## Obligation Receipts — opengrep_findings.md\n\n"
        "[OBLIG:opengrep_findings.md:1] STATUS:REPORTED KEY:rule-a@foo.sol:L1 -> F-1\n"
        "[OBLIG:opengrep_findings.md:2] STATUS:DISMISSED KEY:rule-b@foo.sol:L2 -> informational_style\n",
        encoding="utf-8",
    )
    issues = v._check_opengrep_obligation_coverage(tmp_path, "thorough")
    assert issues == []


def test_opengrep_gate_writes_gap_artifact_on_partial(tmp_path):
    v = _v()
    (tmp_path / "opengrep_findings.md").write_text(
        "| # | Rule | Level | Location | Message |\n"
        "|---|------|-------|----------|----------|\n"
        "| 1 | rule-a | warning | foo.sol:L1 | a |\n"
        "| 2 | rule-b | warning | foo.sol:L2 | b |\n"
        "| 3 | rule-c | warning | foo.sol:L3 | c |\n",
        encoding="utf-8",
    )
    (tmp_path / "analysis_b1.md").write_text(
        "[OBLIG:opengrep_findings.md:1] STATUS:REPORTED KEY:x -> F-1\n",
        encoding="utf-8",
    )
    issues = v._check_opengrep_obligation_coverage(tmp_path, "thorough")
    assert issues
    gap = (tmp_path / "opengrep_obligation_gap.md").read_text(encoding="utf-8")
    assert "row 2" in gap and "row 3" in gap


# ---------------------------------------------------------------------------
# Step 6: function_summary obligation gate
# ---------------------------------------------------------------------------


def _write_function_summary(tmp_path: Path):
    """Write a minimal function_summary.md with two functions per contract."""
    (tmp_path / "function_summary.md").write_text(
        "# Function Summary\n\n"
        "## Vault.sol\n\n"
        "| Function | Visibility | Modifiers | State Reads | State Writes | External Calls | Notes |\n"
        "|----------|-----------|-----------|-------------|--------------|----------------|-------|\n"
        "| `deposit` | external | onlyOwner | balances | balances, totalSupply | IERC20.transferFrom | entry |\n"
        "| `viewFn` | external | view | balances | - | - | view-only |\n"
        "\n"
        "## Router.sol\n\n"
        "| Function | Visibility | Modifiers | State Reads | State Writes | External Calls | Notes |\n"
        "|----------|-----------|-----------|-------------|--------------|----------------|-------|\n"
        "| `swap` | external | - | reserves | reserves | IExternalDex.mixSwap | external swap |\n",
        encoding="utf-8",
    )


def test_function_summary_parser_extracts_rows(tmp_path):
    v = _v()
    _write_function_summary(tmp_path)
    rows = v._parse_function_summary_rows(tmp_path)
    assert len(rows) == 3
    assert any(r["function"].strip("`") == "deposit" for r in rows)
    deposit = next(r for r in rows if r["function"].strip("`") == "deposit")
    assert "balances" in deposit["state_writes"]
    assert "transferFrom" in deposit["external_calls"]


def test_function_summary_flat_schema_derives_contract_and_ignores_unknown_polarity(
    tmp_path,
):
    v = _v()
    (tmp_path / "function_summary.md").write_text(
        "# Function Summary\n\n"
        "| Function | Location | State Writes | External Calls |\n"
        "|---|---|---|---|\n"
        "| `writeState` | contracts/Vault.sol:L10 | balances | NONE |\n"
        "| `callToken` | contracts/Router.sol:L20 | (UNKNOWN) | IERC20.transfer |\n"
        "| `unknownRow` | contracts/Ignored.sol:L30 | UNAVAILABLE: no facts | (none) |\n",
        encoding="utf-8",
    )
    rows = v._parse_function_summary_rows(tmp_path)
    assert [row["contract"] for row in rows] == ["Vault", "Router", "Ignored"]
    state, external = v._function_summary_obligation_sets(tmp_path)
    assert state == {"Vault.writeState"}
    assert external == {"Router.callToken"}


def test_function_summary_gate_vacuous_when_missing(tmp_path):
    v = _v()
    assert v._check_function_summary_obligation(tmp_path, "thorough") == []


def test_function_summary_gate_fires_when_no_receipts(tmp_path):
    v = _v()
    _write_function_summary(tmp_path)
    issues = v._check_function_summary_obligation(tmp_path, "thorough")
    assert issues
    # Both state-trace and token-flow missing
    assert any("state-trace" in i for i in issues)
    assert any("token-flow" in i for i in issues)
    assert (tmp_path / "function_summary_obligation_gap.md").exists()


def test_function_summary_gate_clears_when_receipts_emitted(tmp_path):
    v = _v()
    _write_function_summary(tmp_path)
    (tmp_path / "depth_state_trace_findings.md").write_text(
        "[OBLIG:function_summary.md:Vault.deposit] STATUS:REPORTED KEY:reentrancy-pre-transfer -> F-1\n",
        encoding="utf-8",
    )
    (tmp_path / "depth_token_flow_findings.md").write_text(
        "[OBLIG:function_summary.md:Vault.deposit] STATUS:CARRIED KEY:approval-flow -> external\n"
        "[OBLIG:function_summary.md:Router.swap] STATUS:DISMISSED KEY:no-issue@Router.sol:L10 -> false_positive\n",
        encoding="utf-8",
    )
    issues = v._check_function_summary_obligation(tmp_path, "thorough")
    assert issues == []


def test_function_summary_gate_ignores_view_only_rows(tmp_path):
    v = _v()
    _write_function_summary(tmp_path)
    # viewFn has no state writes and no external calls — should not require receipt
    (tmp_path / "depth_state_trace_findings.md").write_text(
        "[OBLIG:function_summary.md:Vault.deposit] STATUS:REPORTED KEY:x -> F-1\n",
        encoding="utf-8",
    )
    (tmp_path / "depth_token_flow_findings.md").write_text(
        "[OBLIG:function_summary.md:Vault.deposit] STATUS:CARRIED KEY:x -> external\n"
        "[OBLIG:function_summary.md:Router.swap] STATUS:DISMISSED KEY:x -> false_positive\n",
        encoding="utf-8",
    )
    # viewFn intentionally has no receipt — gate must still pass
    issues = v._check_function_summary_obligation(tmp_path, "thorough")
    assert issues == []


def test_function_summary_gate_rejects_wildcard_and_wrong_role_receipts(tmp_path):
    v = _v()
    (tmp_path / "function_summary.md").write_text(
        "# Function Summary\n\n"
        "| Function | Location | State Writes | External Calls |\n"
        "|---|---|---|---|\n"
        "| `setOwner` | contracts/Vault.sol:L10 | owner | NONE |\n",
        encoding="utf-8",
    )
    (tmp_path / "depth_token_flow_findings.md").write_text(
        "[OBLIG:function_summary.md:Vault.setOwner] STATUS:DISMISSED KEY:x -> false_positive\n",
        encoding="utf-8",
    )
    (tmp_path / "depth_state_trace_findings.md").write_text(
        "[OBLIG:function_summary.md:Vault.*] STATUS:CARRIED KEY:x -> chain\n",
        encoding="utf-8",
    )
    issues = v._check_function_summary_obligation(tmp_path, "thorough")
    assert any("Vault.setOwner" in issue for issue in issues)


def test_state_and_token_depth_prompts_bind_exact_function_summary_obligations(
    tmp_path,
):
    d = _d()
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    (tmp_path / "src").mkdir()
    (scratchpad / "function_summary.md").write_text(
        "# Function Summary\n\n"
        "| Function | File | State Writes | External Calls |\n"
        "|---|---|---|---|\n"
        "| `writeState` | contracts/Vault.sol | balances | UNKNOWN |\n"
        "| `callToken` | contracts/Router.sol | (UNAVAILABLE) | IERC20.transfer |\n"
        "| `unknownRow` | contracts/Ignored.sol | UNKNOWN | (NONE) |\n",
        encoding="utf-8",
    )
    config = {
        "pipeline": "sc",
        "mode": "light",
        "language": "evm",
        "cli_backend": "claude",
        "project_root": str(tmp_path),
        "scratchpad": str(scratchpad),
    }
    prompts = {}
    for role in ("state_trace", "token_flow"):
        output = f"depth_{role}_findings.md"
        prompts[role] = d._build_depth_worker_prompt(
            job={
                "agent_id": f"depth-{role.replace('_', '-')}",
                "role": role,
                "output": output,
                "category": "standard",
                "focus": role,
            },
            scratchpad=scratchpad,
            project_root=str(tmp_path),
            config=config,
            attempt=1,
        )

    assert "`Vault.writeState`" in prompts["state_trace"]
    assert "`Router.callToken`" not in prompts["state_trace"]
    assert "`Router.callToken`" in prompts["token_flow"]
    assert "`Vault.writeState`" not in prompts["token_flow"]
    for prompt in prompts.values():
        assert "[OBLIG:function_summary.md:<exact-row-id>]" in prompt
        assert "Contract wildcards" in prompt
        assert "Ignored.unknownRow" not in prompt


# ---------------------------------------------------------------------------
# Step 7: PDE gate on niche-semantic-consistency
# ---------------------------------------------------------------------------


def test_pde_gate_vacuous_when_niche_output_missing(tmp_path):
    v = _v()
    assert v._check_pde_section_present(tmp_path) == []


def test_pde_gate_fires_when_pde_missing(tmp_path):
    v = _v()
    (tmp_path / "niche_semantic_consistency_findings.md").write_text(
        "# Semantic Consistency Findings\n\n"
        "## Finding [SC-1]: foo\n**Severity**: Medium\n**Verdict**: CONFIRMED\n",
        encoding="utf-8",
    )
    issues = v._check_pde_section_present(tmp_path)
    assert issues
    assert "Pre-Commit Dimension Enumeration" in issues[0]


def test_pde_gate_clears_when_pde_present(tmp_path):
    v = _v()
    (tmp_path / "niche_semantic_consistency_findings.md").write_text(
        "# Semantic Consistency Findings\n\n"
        "## Pre-Commit Dimension Enumeration\n\n"
        "### Sibling Set\n| Member | In Scope? |\n|---|---|\n| Vault | YES |\n\n"
        "## Finding [SC-1]: foo\n",
        encoding="utf-8",
    )
    issues = v._check_pde_section_present(tmp_path)
    assert issues == []


# ---------------------------------------------------------------------------
# Step 8: in-pass perturbation block gate
# ---------------------------------------------------------------------------


def test_perturbation_gate_vacuous_when_depth_outputs_missing(tmp_path):
    v = _v()
    assert v._check_perturbation_block_per_finding(tmp_path) == []


def test_perturbation_gate_fires_on_confirmed_high_without_block(tmp_path):
    v = _v()
    (tmp_path / "depth_state_trace_findings.md").write_text(
        "## Finding [DST-1]: Token drain via withdraw\n"
        "**Verdict**: CONFIRMED\n"
        "**Severity**: High\n"
        "**Location**: `Vault.sol:L100`\n"
        "Description: bug present.\n\n"
        "## Finding [DST-2]: ...\n"
        "**Verdict**: REFUTED\n"
        "**Severity**: Medium\n"
        "Body.\n",
        encoding="utf-8",
    )
    issues = v._check_perturbation_block_per_finding(tmp_path)
    assert issues
    # DST-1 confirmed-High lacks perturbation block; DST-2 refuted so excluded
    assert "DST-1" in issues[0]
    assert "DST-2" not in issues[0]


def test_perturbation_gate_detects_h3_finding_without_block(tmp_path):
    v = _v()
    (tmp_path / "depth_token_flow_findings.md").write_text(
        "### Finding [DT-1]: Approval lingering\n"
        "**Verdict**: CONFIRMED\n"
        "**Severity**: Medium\n"
        "**Location**: `Router.sol:L50`\n\n"
        "Description: bug present.\n",
        encoding="utf-8",
    )
    issues = v._check_perturbation_block_per_finding(tmp_path)
    assert issues
    assert "DT-1" in issues[0]


def test_perturbation_gate_clears_when_block_present(tmp_path):
    v = _v()
    (tmp_path / "depth_state_trace_findings.md").write_text(
        "## Finding [DST-1]: Token drain\n"
        "**Verdict**: CONFIRMED\n"
        "**Severity**: High\n"
        "**Location**: `Vault.sol:L100`\n\n"
        "### Perturbation Block — DST-1\n"
        "| Operator | Applied To | Verdict | Evidence |\n"
        "|----------|-----------|---------|----------|\n"
        "| SIBLING | Vault2.sol | D | line 200 |\n",
        encoding="utf-8",
    )
    (tmp_path / "depth_token_flow_findings.md").write_text(
        "## Finding [DT-1]: Approval lingering\n"
        "**Verdict**: CONFIRMED\n"
        "**Severity**: Critical\n"
        "**Location**: `Router.sol:L50`\n\n"
        "### Perturbation Block — DT-1\n"
        "| Operator | Applied To | Verdict | Evidence |\n"
        "|----------|-----------|---------|----------|\n"
        "| FIELD | decoded.x | D | L60 |\n",
        encoding="utf-8",
    )
    issues = v._check_perturbation_block_per_finding(tmp_path)
    assert issues == []


def test_perturbation_gate_accepts_bold_label_block(tmp_path):
    v = _v()
    (tmp_path / "depth_state_trace_findings.md").write_text(
        "## Finding [DST-1]: Token drain\n"
        "**Verdict**: CONFIRMED\n"
        "**Severity**: High\n"
        "**Location**: `Vault.sol:L100`\n\n"
        "**Perturbation Block**:\n"
        "- SIBLING: checked `Vault.sol:L120`; same invariant fails.\n",
        encoding="utf-8",
    )
    assert v._check_perturbation_block_per_finding(tmp_path) == []


def test_perturbation_gate_accepts_common_section_label_variants(tmp_path):
    v = _v()
    (tmp_path / "depth_state_trace_findings.md").write_text(
        "## Finding [DST-1]: Token drain\n"
        "**Verdict**: CONFIRMED\n"
        "**Severity**: High\n"
        "**Location**: `Vault.sol:L100`\n\n"
        "#### Perturbation Matrix for DST-1\n"
        "- SIBLING: checked `Vault.sol:L120`; same invariant fails.\n\n"
        "## Finding [DST-2]: Token drain mirror\n"
        "**Verdict**: CONFIRMED\n"
        "**Severity**: Medium\n"
        "**Location**: `Vault.sol:L150`\n\n"
        "Perturbation analysis:\n"
        "- ACTOR: checked keeper/user split; only keeper path is reachable.\n",
        encoding="utf-8",
    )
    assert v._check_perturbation_block_per_finding(tmp_path) == []


def test_perturbation_gate_does_not_accept_inline_future_promise(tmp_path):
    v = _v()
    (tmp_path / "depth_state_trace_findings.md").write_text(
        "## Finding [DST-1]: Token drain\n"
        "**Verdict**: CONFIRMED\n"
        "**Severity**: High\n"
        "**Location**: `Vault.sol:L100`\n\n"
        "A perturbation block should be added later by another phase.\n",
        encoding="utf-8",
    )
    issues = v._check_perturbation_block_per_finding(tmp_path)
    assert issues
    assert "DST-1" in issues[0]


def test_perturbation_gate_ignores_low_and_refuted(tmp_path):
    v = _v()
    (tmp_path / "depth_state_trace_findings.md").write_text(
        "## Finding [DST-1]: minor cosmetic\n"
        "**Verdict**: CONFIRMED\n"
        "**Severity**: Low\n"
        "Body.\n\n"
        "## Finding [DST-2]: dismissed by depth\n"
        "**Verdict**: REFUTED\n"
        "**Severity**: High\n"
        "Body.\n",
        encoding="utf-8",
    )
    issues = v._check_perturbation_block_per_finding(tmp_path)
    assert issues == []


# ---------------------------------------------------------------------------
# Integration: gates are exported through plamen_validators
# ---------------------------------------------------------------------------


def test_gates_exported_via_all():
    v = _v()
    for name in (
        "_check_opengrep_obligation_coverage",
        "_check_function_summary_obligation",
        "_check_pde_section_present",
        "_check_perturbation_block_per_finding",
    ):
        assert hasattr(v, name)
        assert name in v.__all__

# ===========================================================================
# Work Item 2 Part (b): chain-High first-class + collapse duplicate
# obligation rows. All fixtures are synthetic/generic (no protocol names).
# ===========================================================================


def _chain_section(chain_id, a_id, b_id, *, justified, combined_impact="NONE", severity="High"):
    """Render one chain hypothesis section (phase4c-chain-prompt.md format)."""
    blocks = [
        f"## Chain Hypothesis {chain_id}",
        "### Blocked Finding (A)",
        f"- **ID**: {a_id}, **Title**: blocked attack",
        "### Enabler Finding (B)",
        f"- **ID**: {b_id}, **Title**: enabler finding",
        "### Severity Reassessment",
        f"Chain Severity: {severity}",
        f"Constituents: {a_id},{b_id} | Severity-Upgrade-Justified: "
        f"{'YES' if justified else 'NO'} | Combined-Impact: {combined_impact}",
        "",
    ]
    return "\n".join(blocks)


# --- B1: obligation ledger dedup ------------------------------------------


def test_composition_obligation_dedup_by_chain_id(tmp_path):
    """CH-1 referenced on 6 lines + CH-2 on 3 -> exactly 2 obligation rows,
    not 9. Highest severity retained; evidence unioned."""
    m = _m()
    sp = tmp_path
    lines = ["# Composition Coverage", ""]
    for _ in range(6):
        lines.append("| A | B | NO | CH-1 UPGRADE: cross-user fund loss | note |")
    for _ in range(3):
        lines.append("| C | D | NO | CH-2 COMPOSED theft of funds | note |")
    (sp / "composition_coverage.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    rows = m._composition_obligation_rows(sp)
    assert len(rows) == 2, f"expected 2 deduped rows, got {len(rows)}"
    by_src = {str(r["source_id"]): r for r in rows}
    assert set(by_src) == {"CH-1", "CH-2"}
    assert by_src["CH-1"]["severity_signal"] in ("High", "Medium")
    assert ";" in str(by_src["CH-1"]["evidence"])


def test_composition_obligation_single_line_one_row(tmp_path):
    """Guard: a single-chain single-line input still yields exactly 1 row."""
    m = _m()
    sp = tmp_path
    (sp / "composition_coverage.md").write_text(
        "# Composition Coverage\n\n"
        "| A | B | NO | CH-7 UPGRADE drain of funds | note |\n",
        encoding="utf-8",
    )
    rows = m._composition_obligation_rows(sp)
    assert len(rows) == 1
    assert rows[0]["source_id"] == "CH-7"
    assert rows[0]["status"] == "active"


def test_composition_obligation_all_declined_covered(tmp_path):
    """Conservative declined flag: a chain is covered only if EVERY line
    declined; one non-declined line keeps it active."""
    m = _m()
    sp = tmp_path
    (sp / "composition_coverage.md").write_text(
        "# Composition Coverage\n\n"
        "| A | B | NO | CH-9 UPGRADE fund loss, noting but not assigning a formal CH ID | x |\n"
        "| A | B | NO | CH-9 UPGRADE fund loss real exploit path | x |\n",
        encoding="utf-8",
    )
    rows = m._composition_obligation_rows(sp)
    assert len(rows) == 1
    assert rows[0]["status"] == "active"


# --- B1: readable risk rows -----------------------------------------------


def test_obligation_retention_rows_are_distinct(tmp_path):
    """2-row ledger + non-preserving coverage -> 2 DISTINCT issue strings each
    naming source_id + severity + target excerpt, not N identical clones."""
    v = _v()
    m = _m()
    sp = tmp_path
    lines = ["# Composition Coverage", ""]
    for _ in range(4):
        lines.append("| A | B | NO | CH-1 UPGRADE cross-user fund loss alpha | n |")
    for _ in range(3):
        lines.append("| C | D | NO | CH-2 UPGRADE theft of funds beta | n |")
    (sp / "composition_coverage.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    m._write_obligation_ledger(sp, "thorough")
    issues = v._validate_obligation_ledger_retention(sp, "no coverage here at all")
    assert len(issues) == 2, f"expected 2 distinct issues, got {issues}"
    assert issues[0] != issues[1]
    joined = " ".join(issues)
    assert "CH-1" in joined and "CH-2" in joined


# --- B2: force-include justified High chains into the seed -----------------


def test_forced_chain_seed_rows_include_justified_high(tmp_path):
    """A justified High chain with a constituent absent from the queue is
    force-included (chain id + constituents) by _forced_chain_seed_rows."""
    v = _v()
    sp = tmp_path
    (sp / "chain_hypotheses.md").write_text(
        "# Chain Hypotheses\n\n"
        + _chain_section("CH-1", "H-1", "H-23", justified=True,
                         combined_impact="cross-user drain not possible alone",
                         severity="High"),
        encoding="utf-8",
    )
    forced = v._forced_chain_seed_rows(sp)
    assert "CH-1" in forced
    assert forced["CH-1"]["severity"] == "High"
    assert set(forced["CH-1"]["constituents"]) == {"H-1", "H-23"}


def test_forced_chain_seed_skips_unjustified(tmp_path):
    """An unjustified chain (Severity-Upgrade-Justified: NO) is NOT force-
    included -- it is absorbed into its constituents elsewhere."""
    v = _v()
    sp = tmp_path
    (sp / "chain_hypotheses.md").write_text(
        "# Chain Hypotheses\n\n"
        + _chain_section("CH-2", "H-1", "H-2", justified=False,
                         combined_impact="NONE", severity="High"),
        encoding="utf-8",
    )
    assert v._forced_chain_seed_rows(sp) == {}


def test_forced_chain_seed_matrix_arrow_format(tmp_path):
    """REAL chain_hypotheses.md format: severity is declared via
    'Chain Severity Matrix: ... -> HIGH' (NOT a bare 'Chain Severity:' line).
    Regression for the silent-drop bug where a justified High chain expressed
    this way was missed and never force-included (caught on the live BB run)."""
    v = _v()
    sp = tmp_path
    section = "\n".join([
        "## Chain Hypothesis CH-1",
        "### Blocked Finding (A)",
        "- **ID**: H-23, **Title**: blocked attack",
        "### Enabler Finding (B)",
        "- **ID**: H-01, **Title**: enabler finding",
        "### Severity Reassessment",
        "**Chain Severity Matrix**: LOW (A) + MEDIUM+ (B) → **HIGH**",
        "`Constituents: H-23,H-01 | Severity-Upgrade-Justified: YES | "
        "Combined-Impact: dual-victim drain neither constituent produces alone`",
        "",
    ])
    (sp / "chain_hypotheses.md").write_text(
        "# Chain Hypotheses\n\n" + section, encoding="utf-8"
    )
    forced = v._forced_chain_seed_rows(sp)
    assert "CH-1" in forced, "matrix-arrow-form High must be force-included"
    assert forced["CH-1"]["severity"] == "High"
    assert set(forced["CH-1"]["constituents"]) == {"H-23", "H-01"}


def test_forced_chain_seed_summary_table_fallback(tmp_path):
    """When the section has neither a bare 'Chain Severity:' line nor a matrix
    arrow, the chain id's summary-table row supplies the severity (3rd
    fallback in _chain_section_severity)."""
    v = _v()
    sp = tmp_path
    section = "\n".join([
        "## Summary",
        "| Chain ID | Finding A | Finding B | Chain Severity |",
        "|----------|-----------|-----------|----------------|",
        "| CH-9 | H-1 (blocked) | H-2 (enabler) | **High** |",
        "",
        "## Chain Hypothesis CH-9",
        "### Severity Reassessment",
        "`Constituents: H-1,H-2 | Severity-Upgrade-Justified: YES | "
        "Combined-Impact: concrete combined loss`",
        "",
    ])
    (sp / "chain_hypotheses.md").write_text(
        "# Chain Hypotheses\n\n" + section, encoding="utf-8"
    )
    forced = v._forced_chain_seed_rows(sp)
    assert forced.get("CH-9", {}).get("severity") == "High"


def test_chain_section_severity_three_forms(tmp_path):
    """Unit guard on the format-tolerant extractor: bare line, matrix arrow,
    and summary-table forms all resolve; absent severity returns ''."""
    v = _v()
    assert v._chain_section_severity("Chain Severity: Critical", "", "CH-1") == "Critical"
    assert v._chain_section_severity(
        "**Chain Severity Matrix**: LOW + MEDIUM → **HIGH**", "", "CH-1") == "High"
    full = "| CH-1 | a | b | **High** |"
    assert v._chain_section_severity("no severity here", full, "CH-1") == "High"
    assert v._chain_section_severity("nothing", "", "CH-1") == ""


def test_forced_chain_seed_mode_agnostic(tmp_path):
    """Force-include is mode-agnostic: the helper reads no mode and is
    deterministic across calls."""
    v = _v()
    sp = tmp_path
    (sp / "chain_hypotheses.md").write_text(
        "# Chain Hypotheses\n\n"
        + _chain_section("CH-5", "H-3", "H-8", justified=True,
                         combined_impact="liveness brick absent in either alone",
                         severity="Critical"),
        encoding="utf-8",
    )
    a = v._forced_chain_seed_rows(sp)
    b = v._forced_chain_seed_rows(sp)
    assert a == b
    assert a["CH-5"]["severity"] == "Critical"


# --- B2 #4: deferred-note fallback ----------------------------------------


def test_deferred_chain_note_when_unqueueable(tmp_path):
    """A justified High chain whose constituents are absent from the verify
    queue -> exactly ONE deferred note line + obligation row marked covered."""
    v = _v()
    m = _m()
    sp = tmp_path
    (sp / "chain_hypotheses.md").write_text(
        "# Chain Hypotheses\n\n"
        + _chain_section("CH-1", "H-1", "H-23", justified=True,
                         combined_impact="cross-user drain absent alone",
                         severity="High"),
        encoding="utf-8",
    )
    (sp / "verification_queue.md").write_text(
        "| Queue # | Finding ID | Severity | Title |\n"
        "|---------|------------|----------|-------|\n",
        encoding="utf-8",
    )
    (sp / "composition_coverage.md").write_text(
        "# Composition Coverage\n\n"
        "| A | B | NO | CH-1 UPGRADE cross-user fund loss | n |\n",
        encoding="utf-8",
    )
    m._write_obligation_ledger(sp, "core")
    note_path = sp / "report_semantic_chain_deferred.md"
    assert note_path.exists()
    text = note_path.read_text(encoding="utf-8")
    assert text.count("Deferred finding (chain-derived, estimated High)") == 1
    assert "CH-1" in text and "H-1" in text and "H-23" in text
    issues = v._validate_obligation_ledger_retention(sp, "no coverage")
    assert issues == [], f"expected no UNACCOUNTED obligations, got {issues}"


def test_deferred_chain_note_skipped_when_queueable(tmp_path):
    """If a constituent IS in the verify queue, the chain is queue-able and no
    deferred note is emitted (it reaches the body via verification)."""
    m = _m()
    sp = tmp_path
    (sp / "chain_hypotheses.md").write_text(
        "# Chain Hypotheses\n\n"
        + _chain_section("CH-1", "H-1", "H-23", justified=True,
                         combined_impact="cross-user drain absent alone",
                         severity="High"),
        encoding="utf-8",
    )
    (sp / "verification_queue.md").write_text(
        "| Queue # | Finding ID | Severity | Title |\n"
        "|---------|------------|----------|-------|\n"
        "| 1 | H-1 | High | constituent in queue |\n",
        encoding="utf-8",
    )
    deferred = m._render_deferred_chain_notes(sp)
    assert deferred == set()
    assert not (sp / "report_semantic_chain_deferred.md").exists()


# --- B2 test 5: severity-regression guard (load-bearing) ------------------


def _verify_for(sp, fid, sev):
    (sp / f"verify_{fid}.md").write_text(
        f"**Severity**: {sev}\n\n**Verdict**: CONFIRMED\n\n"
        "**Evidence Tag**: [POC-PASS]\n",
        encoding="utf-8",
    )


def test_chain_force_include_is_additive_no_severity_regression(tmp_path):
    """Snapshot the per-finding expected severities BEFORE and AFTER adding a
    justified-High chain file. The force-include / deferred logic is ADD-only:
    no EXISTING finding's severity may change."""
    v = _v()
    sp = tmp_path
    (sp / "config.json").write_text("{}", encoding="utf-8")
    (sp / "verification_queue.md").write_text(
        "| Queue # | Finding ID | Severity | Title |\n"
        "|---------|------------|----------|-------|\n"
        "| 1 | INV-A | Medium | a |\n"
        "| 2 | INV-B | High | b |\n",
        encoding="utf-8",
    )
    _verify_for(sp, "INV-A", "Medium")
    _verify_for(sp, "INV-B", "High")

    before = dict(v._expected_report_index_severities(sp))

    # Now add a justified-High chain referencing OTHER ids (not in the queue).
    (sp / "chain_hypotheses.md").write_text(
        "# Chain Hypotheses\n\n"
        + _chain_section("CH-1", "H-9", "H-10", justified=True,
                         combined_impact="compound drain absent alone",
                         severity="High"),
        encoding="utf-8",
    )
    after = dict(v._expected_report_index_severities(sp))

    # Every pre-existing finding's severity is byte-identical.
    for fid, sev in before.items():
        assert after.get(fid) == sev, (
            f"severity regression: {fid} {sev} -> {after.get(fid)}"
        )
    # The expected-severities map is queue-driven and unchanged (the chain seed
    # promotion happens in the driver seed builder, additively).
    assert set(after) == set(before)
