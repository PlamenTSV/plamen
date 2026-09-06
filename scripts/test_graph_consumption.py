"""Unit tests for P0: SC graph-artifact consumption enforcement gate.

Targets:
  - _check_graph_artifact_consumption  (new validator in plamen_validators.py)

Tests that depth agents demonstrate evidence of reading graph artifacts
(caller_map.md, callee_map.md, state_write_map.md, function_summary.md)
OR explicitly emit [GRAPH-ARTIFACT: UNAVAILABLE:{file}] tags.

Run: `python test_graph_consumption.py`
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS_DIR))

import plamen_validators as V  # noqa: E402

PASS, FAIL = 0, 0


def check(label: str, ok: bool, detail: str = "") -> None:
    global PASS, FAIL
    if ok:
        PASS += 1
        print(f"  PASS  {label}")
    else:
        FAIL += 1
        print(f"  FAIL  {label} :: {detail}")


def _mkscratch(files: dict[str, str]) -> Path:
    sp = Path(tempfile.mkdtemp(prefix="plamen_graph_"))
    for name, body in files.items():
        (sp / name).write_text(body, encoding="utf-8")
    return sp


# --- Graph artifacts present, all four referenced ---

_GRAPH_ARTIFACTS = {
    "caller_map.md": "> **Status**: POPULATED\n\n| Function | Callers |\n",
    "callee_map.md": "> **Status**: POPULATED\n\n| Function | Callees |\n",
    "state_write_map.md": "> **Status**: POPULATED\n\n| Variable | Writers |\n",
    "function_summary.md": "> **Status**: POPULATED\n\n| Function | Vis |\n",
}


def _depth_findings_with_refs(*refs: str) -> str:
    """Simulate a depth findings file that mentions graph artifacts."""
    lines = [
        "# Depth Token Flow Findings\n",
        "## Finding [DEPTH-TF-1]: Example\n",
        "**Severity**: Medium\n",
        "**Location**: src/Vault.sol:L45\n",
    ]
    for r in refs:
        lines.append(f"Read: caller_map.md — found 3 callers for withdraw()\n" if r == "caller_map" else "")
        lines.append(f"Read: callee_map.md — withdraw() calls _burn()\n" if r == "callee_map" else "")
        lines.append(f"Read: state_write_map.md — totalSupply written by mint/burn\n" if r == "state_write_map" else "")
        lines.append(f"Read: function_summary.md — grep for withdraw row\n" if r == "function_summary" else "")
    return "\n".join(lines)


def _depth_findings_with_unavailable(*files: str) -> str:
    """Simulate a depth findings file with UNAVAILABLE tags."""
    lines = [
        "# Depth State Trace Findings\n",
        "## Finding [DEPTH-ST-1]: Example\n",
        "**Severity**: Low\n",
    ]
    for f in files:
        lines.append(f"[GRAPH-ARTIFACT: UNAVAILABLE:{f}]\n")
    return "\n".join(lines)


# --------------------------------------------------------------------------
# Test: Not thorough mode -> always passes (gate is thorough-only)
# --------------------------------------------------------------------------

def test_non_thorough_always_passes():
    """Core/Light mode skips the graph consumption check."""
    sp = _mkscratch({
        "depth_token_flow_findings.md": "# Findings\nNo graph refs here\n",
        **_GRAPH_ARTIFACTS,
    })
    issues = V._check_graph_artifact_consumption(sp, "core")
    check("non-thorough passes", issues == [], repr(issues))

    issues2 = V._check_graph_artifact_consumption(sp, "light")
    check("light mode passes", issues2 == [], repr(issues2))


# --------------------------------------------------------------------------
# Test: No depth findings at all -> passes (nothing to check)
# --------------------------------------------------------------------------

def test_no_depth_findings_passes():
    """No depth agent output -> gate vacuously passes."""
    sp = _mkscratch({**_GRAPH_ARTIFACTS})
    issues = V._check_graph_artifact_consumption(sp, "thorough")
    check("no depth findings passes", issues == [], repr(issues))


# --------------------------------------------------------------------------
# Test: All four artifacts referenced -> passes
# --------------------------------------------------------------------------

def test_all_four_referenced_passes():
    """Depth agent mentions all 4 graph artifacts -> passes."""
    sp = _mkscratch({
        **_GRAPH_ARTIFACTS,
        "depth_token_flow_findings.md": _depth_findings_with_refs(
            "caller_map", "callee_map", "state_write_map", "function_summary"
        ),
    })
    issues = V._check_graph_artifact_consumption(sp, "thorough")
    check("all four referenced passes", issues == [], repr(issues))


# --------------------------------------------------------------------------
# Test: Only 2 of 4 referenced -> fails (all produced artifacts required)
# --------------------------------------------------------------------------

def test_partial_reference_fails_missing_artifacts():
    """Depth agent references 2 of 4 -> fails with exact missing artifacts."""
    sp = _mkscratch({
        **_GRAPH_ARTIFACTS,
        "depth_token_flow_findings.md": _depth_findings_with_refs(
            "caller_map", "function_summary"
        ),
    })
    issues = V._check_graph_artifact_consumption(sp, "thorough")
    check("2-of-4 fails exact graph contract", len(issues) > 0, repr(issues))
    check("2-of-4 names missing artifacts",
          "callee_map.md" in issues[0] and "state_write_map.md" in issues[0],
          repr(issues))


def test_one_reference_fails():
    """Depth agent references only 1 of 4 -> fails minimum."""
    findings = (
        "# Depth Token Flow Findings\n\n"
        "## Finding [DEPTH-TF-1]: Donation Attack on Vault\n\n"
        "**Severity**: Medium\n"
        "**Location**: src/Vault.sol:L45\n\n"
        "**Description**: The vault share price can be manipulated.\n"
        "Read: caller_map.md -- found callers for withdraw()\n"
        "This leads to fund loss for subsequent depositors.\n"
        "More analysis text to make this a substantial findings file.\n"
    )
    sp = _mkscratch({
        **_GRAPH_ARTIFACTS,
        "depth_token_flow_findings.md": findings,
    })
    issues = V._check_graph_artifact_consumption(sp, "thorough")
    check("1-of-4 fails minimum", len(issues) > 0, repr(issues))


# --------------------------------------------------------------------------
# Test: Zero references -> fails
# --------------------------------------------------------------------------

def test_zero_references_fails():
    """Depth agent mentions none of the graph artifacts -> hard fail."""
    findings = (
        "# Depth Token Flow Findings\n\n"
        "## Finding [DEPTH-TF-1]: Reentrancy in Withdraw\n\n"
        "**Severity**: Medium\n"
        "**Location**: src/Vault.sol:L45-L67\n\n"
        "**Description**: The withdraw function does not follow CEI.\n"
        "No graph artifacts were consumed during this analysis.\n"
        "The agent relied purely on direct source code reading.\n"
        "More text to ensure this file is above 200 bytes.\n"
    )
    sp = _mkscratch({
        **_GRAPH_ARTIFACTS,
        "depth_token_flow_findings.md": findings,
    })
    issues = V._check_graph_artifact_consumption(sp, "thorough")
    check("zero refs fails", len(issues) > 0, repr(issues))
    check("zero refs mentions agent role",
          any("token_flow" in s for s in issues), repr(issues))


# --------------------------------------------------------------------------
# Test: UNAVAILABLE tags count as valid consumption evidence
# --------------------------------------------------------------------------

def test_unavailable_tags_count():
    """[GRAPH-ARTIFACT: UNAVAILABLE:X] tags satisfy the gate."""
    sp = _mkscratch({
        **_GRAPH_ARTIFACTS,
        "depth_state_trace_findings.md": _depth_findings_with_unavailable(
            "caller_map.md", "callee_map.md", "state_write_map.md", "function_summary.md"
        ),
    })
    issues = V._check_graph_artifact_consumption(sp, "thorough")
    check("UNAVAILABLE tags satisfy gate", issues == [], repr(issues))


def test_mixed_refs_and_unavailable():
    """Mix of explicit read references and UNAVAILABLE tags -> passes."""
    findings = (
        "# Depth Edge Case Findings\n"
        "## Finding [DEPTH-EC-1]: Example\n"
        "Read: caller_map.md — found callers for setFee()\n"
        "[GRAPH-ARTIFACT: UNAVAILABLE:callee_map.md]\n"
        "[GRAPH-ARTIFACT: UNAVAILABLE:state_write_map.md]\n"
        "Read: function_summary.md — grep for setFee\n"
    )
    sp = _mkscratch({
        **_GRAPH_ARTIFACTS,
        "depth_edge_case_findings.md": findings,
    })
    issues = V._check_graph_artifact_consumption(sp, "thorough")
    check("mixed refs+unavailable passes", issues == [], repr(issues))


# --------------------------------------------------------------------------
# Test: Multiple depth agents, only one fails -> reports only the offender
# --------------------------------------------------------------------------

def test_multiple_agents_partial_failure():
    """Two agents: one passes (all refs), one fails (zero refs)."""
    good = _depth_findings_with_refs(
        "caller_map", "callee_map", "state_write_map", "function_summary"
    )
    bad = (
        "# Depth External Findings\n\n"
        "## Finding [DEPTH-EXT-1]: Cross-chain Timing Window\n\n"
        "**Severity**: Medium\n"
        "**Location**: src/Bridge.sol:L90-L120\n\n"
        "**Description**: The bridge relay does not validate timestamps.\n"
        "Pure analysis without graph reads was performed here.\n"
        "This could lead to stale messages being accepted.\n"
        "More text to ensure this file is above 200 bytes.\n"
    )
    sp = _mkscratch({
        **_GRAPH_ARTIFACTS,
        "depth_token_flow_findings.md": good,
        "depth_external_findings.md": bad,
    })
    issues = V._check_graph_artifact_consumption(sp, "thorough")
    check("multi-agent: only offender flagged", len(issues) == 1, repr(issues))
    check("multi-agent: offender is external",
          any("external" in s for s in issues), repr(issues))


# --------------------------------------------------------------------------
# Test: Graph artifacts don't exist (recon didn't produce them) -> skip gate
# --------------------------------------------------------------------------

def test_no_graph_artifacts_skips_gate():
    """If recon didn't produce ANY graph artifacts, gate is vacuously ok."""
    findings = (
        "# Depth Token Flow Findings\n"
        "## Finding [DEPTH-TF-1]: Example\n"
        "No graph context available.\n"
    )
    sp = _mkscratch({
        "depth_token_flow_findings.md": findings,
    })
    issues = V._check_graph_artifact_consumption(sp, "thorough")
    check("no graph artifacts -> gate skips", issues == [], repr(issues))


# --------------------------------------------------------------------------
# Test: Graph artifacts exist but are UNAVAILABLE status -> still expect tag
# --------------------------------------------------------------------------

def test_unavailable_artifacts_still_need_tags():
    """Graph artifacts exist with UNAVAILABLE status. Agent must emit tag."""
    artifacts = {
        "caller_map.md": "> **Status**: UNAVAILABLE: no Slither\n",
        "callee_map.md": "> **Status**: UNAVAILABLE: no Slither\n",
        "state_write_map.md": "> **Status**: UNAVAILABLE: no Slither\n",
        "function_summary.md": "> **Status**: UNAVAILABLE: no Slither\n",
    }
    findings = (
        "# Depth Token Flow Findings\n\n"
        "## Finding [DEPTH-TF-1]: Share Price Manipulation\n\n"
        "**Severity**: High\n"
        "**Location**: src/Vault.sol:L45-L67\n\n"
        "**Description**: The vault share price can be manipulated.\n"
        "Analysis done purely from source code without graph context.\n"
        "This leads to potential fund loss for depositors.\n"
        "More text to ensure this file is above 200 bytes.\n"
    )
    sp = _mkscratch({
        **artifacts,
        "depth_token_flow_findings.md": findings,
    })
    issues = V._check_graph_artifact_consumption(sp, "thorough")
    check("UNAVAILABLE artifacts still need agent tags", len(issues) > 0, repr(issues))


# --------------------------------------------------------------------------
# Test: Coverage agents (depth_coverage_*) are excluded (same as step-trace)
# --------------------------------------------------------------------------

def test_coverage_agents_excluded():
    """depth_coverage_* agents are gap-fill and exempt from graph gate."""
    findings = (
        "# Coverage Fill Findings\n"
        "No graph reads here.\n"
    )
    sp = _mkscratch({
        **_GRAPH_ARTIFACTS,
        "depth_coverage_uncited_findings.md": findings,
    })
    issues = V._check_graph_artifact_consumption(sp, "thorough")
    check("coverage agents excluded", issues == [], repr(issues))


# --------------------------------------------------------------------------
# Test: iter2/iter3/DA variants excluded
# --------------------------------------------------------------------------

def test_iter2_da_excluded():
    """iter2, iter3, da variants are excluded from graph gate."""
    sp = _mkscratch({
        **_GRAPH_ARTIFACTS,
        "depth_token_flow_iter2_findings.md": "No graph refs\n",
        "depth_da_token_flow_findings.md": "No graph refs\n",
        "depth_state_trace_iter3_findings.md": "No graph refs\n",
    })
    issues = V._check_graph_artifact_consumption(sp, "thorough")
    check("iter2/iter3/da excluded", issues == [], repr(issues))


# --------------------------------------------------------------------------
# Test: Alternative reference patterns (various ways agents cite artifacts)
# --------------------------------------------------------------------------

def test_alternative_citation_patterns():
    """Agent uses different phrasing to reference graph artifacts."""
    findings = (
        "# Depth State Trace Findings\n"
        "## Finding [DEPTH-ST-1]: Example\n"
        "I opened caller_map.md and found that setFee has 2 callers.\n"
        "From callee_map.md, setFee calls _validateFee internally.\n"
        "Checking state_write_map.md reveals totalFees is written by 3 functions.\n"
        "Per function_summary.md, setFee is external with onlyOwner modifier.\n"
    )
    sp = _mkscratch({
        **_GRAPH_ARTIFACTS,
        "depth_state_trace_findings.md": findings,
    })
    issues = V._check_graph_artifact_consumption(sp, "thorough")
    check("alternative citation patterns pass", issues == [], repr(issues))


# --------------------------------------------------------------------------
# Test: Empty depth findings file still checked
# --------------------------------------------------------------------------

def test_stub_findings_file_checked():
    """A findings file with just a header (stub) — gate requires graph reads."""
    findings = "# Depth Token Flow Findings\n"
    sp = _mkscratch({
        **_GRAPH_ARTIFACTS,
        "depth_token_flow_findings.md": findings,
    })
    issues = V._check_graph_artifact_consumption(sp, "thorough")
    # A stub file with no findings content — it's ok to skip (no findings to enrich)
    # BUT the file matches _expected_depth_agent_roles so it should still be checked.
    # Design decision: files < 200 bytes are considered empty stubs and skipped.
    check("stub file skipped (< 200 bytes)", issues == [], repr(issues))


def test_substantial_findings_without_refs_fails():
    """A findings file with substantial content but no graph refs -> fail."""
    findings = (
        "# Depth Token Flow Findings\n\n"
        "## Finding [DEPTH-TF-1]: Donation Attack on Vault Share Price\n\n"
        "**Severity**: High\n"
        "**Location**: src/Vault.sol:L45-L67\n\n"
        "**Description**: The vault's share price can be manipulated by\n"
        "donating tokens directly to the contract before the first deposit.\n"
        "This inflates the exchange rate, causing subsequent depositors to\n"
        "receive fewer shares than expected.\n\n"
        "**Impact**: First depositor can steal up to 50% of second depositor's\n"
        "funds through share price manipulation.\n\n"
        "**Evidence**: [BOUNDARY:shares=0 -> exchangeRate=MAX]\n"
        "[TRACE:deposit(1 wei)->mint 1 share->donate 1e18->deposit(2e18)->mint 1 share]\n\n"
        "## Chain Summary\n"
        "| Finding | Postcondition | Type |\n"
        "| DEPTH-TF-1 | inflated share price | STATE |\n"
    )
    sp = _mkscratch({
        **_GRAPH_ARTIFACTS,
        "depth_token_flow_findings.md": findings,
    })
    issues = V._check_graph_artifact_consumption(sp, "thorough")
    check("substantial content without refs fails", len(issues) > 0, repr(issues))


# --------------------------------------------------------------------------
# Test: Retry hint generation
# --------------------------------------------------------------------------

def test_retry_hint_mentions_graph():
    """When gate fails, retry hint should mention graph artifact reads."""
    findings = (
        "# Depth Token Flow Findings\n\n"
        "## Finding [DEPTH-TF-1]: Example finding with enough body\n"
        "**Severity**: Medium\n"
        "**Location**: src/X.sol:L10\n"
        "**Description**: Some issue without graph references padding.\n"
        "More text to make it substantial enough to trigger the gate.\n"
        "Even more text because we need 200+ bytes total.\n"
    )
    sp = _mkscratch({
        **_GRAPH_ARTIFACTS,
        "depth_token_flow_findings.md": findings,
    })
    issues = V._check_graph_artifact_consumption(sp, "thorough")
    check("retry hint references graph artifacts",
          any("graph" in s.lower() or "caller_map" in s or "callee_map" in s
              for s in issues), repr(issues))


def test_depth_retry_hint_keeps_initial_confidence_scoring_in_scope():
    """Retry hint routes confidence work without granting artifact writes."""
    hint = V._generate_depth_retry_hint([
        "confidence_scores.md",
        "graph-artifact consumption: depth_token_flow references only 0/4",
    ])
    ok = (
        "confidence_scores.md" in hint
        and "transient routing proposal" in hint
        and "Do not create or modify confidence_scores.md" in hint
        and "driver publishes the canonical artifact after the wave" in hint
        and "Phase 4b Confidence Scoring Agent" not in hint
        and "verification, scoring, or report work" not in hint
        and "final_scoring" in hint
    )
    check("retry hint preserves driver-owned confidence routing", ok, hint)


def test_stale_depth_retry_hint_is_sanitized_on_read():
    """Existing halted runs may carry the old anti-scoring retry hint."""
    with tempfile.TemporaryDirectory() as td:
        sp = Path(td)
        (sp / "depth_retry_hint.md").write_text(
            "\n".join([
                "## RETRY HINT",
                "- Stay inside the depth phase only. Do NOT execute Phase 4b.5/RAG, chain analysis, verification, scoring, or report work.",
                "- Do NOT write rag_validation.md or any later-phase artifact.",
            ]),
            encoding="utf-8",
        )
        hint = V._read_retry_hint(sp, "depth")
    ok = (
        "verification, scoring, or report work" not in hint
        and "final_scoring" in hint
        and "Transient confidence routing is part of the depth phase" in hint
        and "do not create or modify confidence_scores.md" in hint
        and "driver publishes the canonical artifact after the wave" in hint
    )
    check("stale depth retry hint sanitized to driver-owned routing", ok, hint)


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------

def main():
    tests = [
        test_non_thorough_always_passes,
        test_no_depth_findings_passes,
        test_all_four_referenced_passes,
        test_partial_reference_fails_missing_artifacts,
        test_one_reference_fails,
        test_zero_references_fails,
        test_unavailable_tags_count,
        test_mixed_refs_and_unavailable,
        test_multiple_agents_partial_failure,
        test_no_graph_artifacts_skips_gate,
        test_unavailable_artifacts_still_need_tags,
        test_coverage_agents_excluded,
        test_iter2_da_excluded,
        test_alternative_citation_patterns,
        test_stub_findings_file_checked,
        test_substantial_findings_without_refs_fails,
        test_retry_hint_mentions_graph,
        test_depth_retry_hint_keeps_initial_confidence_scoring_in_scope,
        test_stale_depth_retry_hint_is_sanitized_on_read,
    ]
    print(f"Running {len(tests)} graph-consumption gate tests...")
    for t in tests:
        print(f"\n[{t.__name__}]")
        t()
    print(f"\n{'=' * 48}")
    print(f"  PASS: {PASS}   FAIL: {FAIL}")
    print("=" * 48)
    sys.exit(0 if FAIL == 0 else 1)


if __name__ == "__main__":
    main()
