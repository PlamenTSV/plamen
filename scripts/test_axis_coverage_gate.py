"""MECHANISM 2 — multi-axis coverage meta-pass (Phase 4b.8).

Covers, per recall-build-plan.md §5.2:

  - compute_hot_function_set: deterministic ranking off the mechanical graph,
    cap at _MAX_HOT_FUNCTIONS, tests excluded, and the `function_summary.md`-absent
    (graph-absent) fallback to "all external state-mutating functions".
  - compute_axis_coverage_gaps: correct EXAMINED / N/A / GAP per axis from the
    CLOSED depth-evidence tag vocabulary; AMBIGUOUS cell ⇒ GAP (recall-safe);
    pure-view (no value-effect) ⇒ theft N/A.
  - promote_axis_findings_to_inventory: Source IDs: AXISGAP, idempotent — clone
    parity with the enumgap promotion.
  - skip-when-clean: all cells EXAMINED/N/A ⇒ no GAP rows ⇒ helper True ⇒ stub,
    no spawn.
  - soft validator _validate_axis_coverage: warning-only, .axis_gap sentinel.
  - phase wiring: axis_coverage registered Thorough-only, critical=False, ordered
    after 4b.7 and before dedup/chain, resolves to a prompt.

No protocol-specific content appears in these assertions — axes + hotness are
generic HOW-shapes.
"""
from __future__ import annotations

import importlib
import json
import os
import sys
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS_DIR))


def _eg():
    return importlib.import_module("enumeration_gate")


def _proj(tmp_path: Path):
    """Make <root>/.scratchpad + a sibling src tree the gate can locate."""
    root = tmp_path / "proj"
    sp = root / ".scratchpad"
    sp.mkdir(parents=True)
    (sp / "findings_inventory.md").write_text("# Inv\n", encoding="utf-8")
    return root, sp


def _sol(root: Path, rel: str, body: str):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("// SPDX-License-Identifier: MIT\npragma solidity ^0.8.20;\n" + body,
                 encoding="utf-8")


# ── compute_hot_function_set ─────────────────────────────────────────────────

def test_hot_set_ranks_deterministically_and_flags_hot_signals(tmp_path):
    eg = _eg()
    root, sp = _proj(tmp_path)
    graph = {
        "source": "slither",
        "var_refs": {
            # `writeFn` references (writes) a state var; `coldFn` does not.
            "C.total": {"bare": "total", "refs": [
                "writeFn (C.sol:L20)", "callerA (C.sol:L5)", "callerB (C.sol:L8)"]},
        },
        "functions": {
            "C.writeFn": {"bare": "writeFn", "loc": "C.sol:L20", "callers": ["a", "b", "c"]},
            "C.coldFn": {"bare": "coldFn", "loc": "C.sol:L50", "callers": []},
        },
    }
    (sp / "_mechanical_graph.json").write_text(json.dumps(graph), encoding="utf-8")
    # source so _iter_functions can detect a value-effect on writeFn
    _sol(root, "C.sol",
         "contract C {\n"
         "  function writeFn(uint x) external { total += x; }\n"
         "  function coldFn() external {}\n"
         "}\n")
    hot = eg.compute_hot_function_set(sp)
    names = [h["function"] for h in hot]
    # writeFn is hot (callers>=2, writes, value-effect); coldFn has none of these.
    assert "writeFn" in names
    assert "coldFn" not in names
    top = hot[0]
    assert top["function"] == "writeFn"
    assert top["writes"] is True and top["value_effect"] is True
    # deterministic: a second call returns an identical ranking
    assert [h["function"] for h in eg.compute_hot_function_set(sp)] == names


def test_hot_set_cap_at_max(tmp_path):
    eg = _eg()
    root, sp = _proj(tmp_path)
    # 60 functions each with >=2 callers -> all hot; cap must clamp to 40.
    fns = {}
    var_refs = {}
    for i in range(60):
        fns[f"C.f{i}"] = {"bare": f"f{i}", "loc": f"C.sol:L{i}",
                          "callers": ["x", "y", "z"]}
    (sp / "_mechanical_graph.json").write_text(
        json.dumps({"source": "slither", "var_refs": var_refs, "functions": fns}),
        encoding="utf-8")
    _sol(root, "C.sol", "contract C {}\n")
    hot = eg.compute_hot_function_set(sp)
    assert len(hot) == eg._MAX_HOT_FUNCTIONS == 40


def test_hot_set_fallback_when_graph_absent(tmp_path):
    eg = _eg()
    root, sp = _proj(tmp_path)
    # No _mechanical_graph.json and no function_summary.md -> fallback to
    # "all external state-mutating functions" (value-effect source parse).
    _sol(root, "C.sol",
         "contract C {\n"
         "  function moveIt(address to, uint a) external { IERC20(t).transfer(to, a); }\n"
         "  function pureView() external pure returns (uint) { return 1; }\n"
         "}\n")
    hot = eg.compute_hot_function_set(sp)
    names = [h["function"] for h in hot]
    assert "moveIt" in names          # has a value effect -> state-mutating
    assert "pureView" not in names    # no value effect -> excluded in fallback
    assert all(h["value_effect"] for h in hot)


def test_rust_plusequals_no_token_move_not_hot(tmp_path):
    # Fix 3c: the Rust `effect` regex no longer treats bare `+=` / `.push(` as a
    # value effect. Graph-absent fallback hot set = token-movement functions only.
    eg = _eg()
    root, sp = _proj(tmp_path)
    (root / "lib.rs").write_text(
        "pub fn accumulate(x: i128) { total += x; }\n"
        "pub fn pay(to: Address, a: i128) { token.transfer(&to, a); }\n",
        encoding="utf-8")
    hot = eg.compute_hot_function_set(sp)
    names = [h["function"] for h in hot]
    assert "accumulate" not in names   # bare `+=` is no longer a value effect
    assert "pay" in names              # `token.transfer(...)` still counts


# ── compute_axis_coverage_gaps ───────────────────────────────────────────────

def _hot_graph(sp: Path, root: Path):
    """A single hot function `hotFn` with a value effect (so theft is in-scope)."""
    graph = {
        "source": "slither",
        "var_refs": {"C.total": {"bare": "total", "refs": ["hotFn (C.sol:L10)"]}},
        "functions": {"C.hotFn": {"bare": "hotFn", "loc": "C.sol:L10", "callers": ["a", "b"]}},
    }
    (sp / "_mechanical_graph.json").write_text(json.dumps(graph), encoding="utf-8")
    _sol(root, "C.sol",
         "contract C {\n"
         "  function hotFn(address to, uint a) external { total += a; "
         "IERC20(t).transfer(to, a); }\n"
         "}\n")


def _write_inv_finding(sp: Path, loc: str, body: str):
    (sp / "findings_inventory.md").write_text(
        "# Findings Inventory\n\n"
        "### Finding [INV-001]: a finding\n"
        "**Severity**: Medium\n"
        f"**Location**: `{loc}`\n"
        f"{body}\n",
        encoding="utf-8")


def test_axis_examined_from_closed_tags(tmp_path):
    eg = _eg()
    root, sp = _proj(tmp_path)
    _hot_graph(sp, root)
    # A finding at hotFn's locus carrying a TRACE-to-transfer (theft EXAMINED),
    # a VARIATION (accounting EXAMINED), an EXTERNAL-ASSUMPTION (provenance),
    # a BOUNDARY:X=0 (boundary EXAMINED), a TRACE-to-revert (liveness), and a
    # TRACE combined with a stated ACCESS postcondition + the generic
    # authorization-subject cue (identity EXAMINED).
    _write_inv_finding(
        sp, "C.sol:L10",
        "**Description**: [TRACE:withdraw->transfer to attacker] "
        "[VARIATION:decimals 18->6] [EXTERNAL-ASSUMPTION: oracle fresh] "
        "[BOUNDARY:X=0] [TRACE:amount=MAX->revert] "
        "[TRACE:caller acts on behalf of the owner, confirmed bound]\n"
        "**Postcondition Types**: BALANCE, ACCESS\n")
    gaps = eg.compute_axis_coverage_gaps(sp)
    gapped_axes = {g["axis"] for g in gaps}
    # every axis was examined by a closed tag -> zero gaps
    assert gapped_axes == set()
    matrix = json.loads((sp / "_hot_function_axes.json").read_text(encoding="utf-8"))
    cells = matrix["matrix"][0]["cells"]
    assert cells["theft"] == "EXAMINED"
    assert cells["accounting"] == "EXAMINED"
    assert cells["provenance"] == "EXAMINED"
    assert cells["boundary"] == "EXAMINED"
    assert cells["liveness"] == "EXAMINED"
    assert cells["identity"] == "EXAMINED"


def test_ambiguous_cell_is_gap_not_examined(tmp_path):
    eg = _eg()
    root, sp = _proj(tmp_path)
    _hot_graph(sp, root)
    # A finding with PROSE but NO closed depth-evidence tag for any axis. Prose
    # attestation is ambiguous -> every in-scope axis must default to GAP.
    _write_inv_finding(
        sp, "C.sol:L10",
        "**Description**: I looked at this function and it appears safe overall.\n")
    gaps = eg.compute_axis_coverage_gaps(sp)
    gapped = {g["axis"] for g in gaps}
    # theft is in-scope (value effect) -> GAP; accounting/liveness/provenance/
    # boundary also GAP (no closed tag). None should be EXAMINED.
    assert "accounting" in gapped and "boundary" in gapped and "provenance" in gapped
    assert "liveness" in gapped
    matrix = json.loads((sp / "_hot_function_axes.json").read_text(encoding="utf-8"))
    cells = matrix["matrix"][0]["cells"]
    assert "EXAMINED" not in cells.values()


def test_pure_view_theft_is_na(tmp_path):
    eg = _eg()
    root, sp = _proj(tmp_path)
    # hotFn has NO value effect and NO state write -> theft axis is a provable N/A.
    graph = {
        "source": "slither",
        "var_refs": {},
        "functions": {"C.viewFn": {"bare": "viewFn", "loc": "C.sol:L10",
                                    "callers": ["a", "b"]}},
    }
    (sp / "_mechanical_graph.json").write_text(json.dumps(graph), encoding="utf-8")
    _sol(root, "C.sol",
         "contract C {\n"
         "  function viewFn() external view returns (uint) { return 1; }\n"
         "}\n")
    (sp / "findings_inventory.md").write_text("# Inv\n", encoding="utf-8")
    eg.compute_axis_coverage_gaps(sp)
    matrix = json.loads((sp / "_hot_function_axes.json").read_text(encoding="utf-8"))
    # viewFn is still hot (callers>=2) but has no value-effect / write.
    row = next(r for r in matrix["matrix"] if r["function"] == "viewFn")
    assert row["cells"]["theft"] == "N/A"
    # theft N/A must NOT appear as a GAP row
    assert not any(g["function"] == "viewFn" and g["axis"] == "theft"
                   for g in matrix["gaps"])


def test_prose_liveness_examined_without_trace_tag(tmp_path):
    # Fix 3b: a finding that addresses the liveness axis CONCRETELY in its
    # Description/Impact prose but stamps NO [TRACE:->revert]/[BOUNDARY] tag must
    # count liveness EXAMINED (secondary signal), not a false GAP.
    eg = _eg()
    root, sp = _proj(tmp_path)
    _hot_graph(sp, root)
    _write_inv_finding(
        sp, "C.sol:L10",
        "**Description**: If the guard is mis-set the withdraw path can "
        "permanently lock user funds, a denial-of-service on every depositor.\n"
        "**Impact**: users cannot withdraw; funds frozen.\n")
    gaps = eg.compute_axis_coverage_gaps(sp)
    gapped = {g["axis"] for g in gaps}
    assert "liveness" not in gapped
    matrix = json.loads((sp / "_hot_function_axes.json").read_text(encoding="utf-8"))
    cells = matrix["matrix"][0]["cells"]
    assert cells["liveness"] == "EXAMINED"
    # Floor preserved: an axis with neither tag nor prose cue is still GAP.
    assert "accounting" in gapped and "boundary" in gapped


# ── identity axis (M2 6th axis: authorization-subject coverage) ─────────────

def test_identity_gap_when_unbound_and_regression_other_axes_unchanged(tmp_path):
    """(a) Identity GAP fixture + (e) regression fixture combined: a finding
    whose prose describes an authorized caller acting on a distinct subject
    with no bounding check -- using wording that names the *concept* but never
    hits the concrete generic authorization-subject cue -- must default to a
    GAP on identity (ambiguous ⇒ GAP, the recall-safe floor every other axis
    already uses), while the other five axes stay EXACTLY as EXAMINED as they
    were before the identity axis existed (byte-unchanged verdicts on the same
    tag set proves the new axis is additive, not a perturbation)."""
    eg = _eg()
    root, sp = _proj(tmp_path)
    _hot_graph(sp, root)
    _write_inv_finding(
        sp, "C.sol:L10",
        "**Description**: [TRACE:withdraw->transfer to attacker] "
        "[VARIATION:decimals 18->6] [EXTERNAL-ASSUMPTION: oracle fresh] "
        "[BOUNDARY:X=0] [TRACE:amount=MAX->revert] "
        "An authorized caller acts on a distinct subject with no bounding "
        "check tying the two together.\n"
        "**Postcondition Types**: BALANCE\n")
    gaps = eg.compute_axis_coverage_gaps(sp)
    gapped_axes = {g["axis"] for g in gaps}
    # identity is the ONLY gap -- proves the mechanical cue does not fire on
    # loose conceptual wording ("distinct subject") that never says "on behalf
    # of" / "owner" / "recipient" / "without ... authorization".
    assert gapped_axes == {"identity"}, gapped_axes
    matrix = json.loads((sp / "_hot_function_axes.json").read_text(encoding="utf-8"))
    cells = matrix["matrix"][0]["cells"]
    # Regression: the five pre-existing axes are unchanged EXAMINED verdicts.
    assert cells["theft"] == "EXAMINED"
    assert cells["accounting"] == "EXAMINED"
    assert cells["provenance"] == "EXAMINED"
    assert cells["boundary"] == "EXAMINED"
    assert cells["liveness"] == "EXAMINED"
    assert cells["identity"] == "GAP"


def test_identity_examined_via_prose_secondary_signal(tmp_path):
    """(b) Identity EXAMINED fixture: prose that CONCRETELY confirms the
    caller<->subject authorization bound was checked, with no bracketed
    [TRACE:] tag at all, must count identity EXAMINED via the secondary
    (tag-light-ecosystem) prose signal -- not a false GAP."""
    eg = _eg()
    root, sp = _proj(tmp_path)
    _hot_graph(sp, root)
    _write_inv_finding(
        sp, "C.sol:L10",
        "**Description**: The guard confirms the caller acts on behalf of "
        "the owner only, so no third party can act without the owner's "
        "authorization.\n"
        "**Impact**: no impact -- the binding is enforced.\n")
    gaps = eg.compute_axis_coverage_gaps(sp)
    gapped = {g["axis"] for g in gaps}
    assert "identity" not in gapped
    matrix = json.loads((sp / "_hot_function_axes.json").read_text(encoding="utf-8"))
    cells = matrix["matrix"][0]["cells"]
    assert cells["identity"] == "EXAMINED"
    # Floor preserved: axes with neither tag nor prose cue are still GAP.
    assert "accounting" in gapped and "boundary" in gapped


def test_identity_na_credit_only_recipient(tmp_path):
    """(c) N/A negative control #1: a credit-only-recipient locus -- no
    value effect, no state write, no role-elevation signal -- has nothing
    that could be misdirected onto a distinct subject. N/A, not GAP."""
    eg = _eg()
    hf = {"function": "myOwnBalance", "loc": "C.sol:L1", "callers": 3,
          "writes": False, "elevate": False, "value_effect": False, "lang": "sol"}
    assert eg._axis_na(hf, "identity") is True


def test_identity_na_single_actor_self_call(tmp_path):
    """(c) N/A negative control #2: a single-actor self-call (a no-op ping
    with no value/state/role effect) -- same abstract shape, different
    narrative -- also N/A, not GAP."""
    eg = _eg()
    hf = {"function": "ping", "loc": "C.sol:L2", "callers": 2,
          "writes": False, "elevate": False, "value_effect": False, "lang": "sol"}
    assert eg._axis_na(hf, "identity") is True


def test_identity_na_end_to_end_pipeline(tmp_path):
    """(c) End-to-end confirmation: a genuinely hot-but-inert function (hot via
    caller count only, no value effect / write / elevate) resolves to identity
    N/A through the full compute_axis_coverage_gaps pipeline, and never
    appears as an identity GAP row -- mirrors the existing pure-view theft N/A
    pipeline test but for the new axis."""
    eg = _eg()
    root, sp = _proj(tmp_path)
    graph = {
        "source": "slither",
        "var_refs": {},
        "functions": {"C.viewFn": {"bare": "viewFn", "loc": "C.sol:L10",
                                    "callers": ["a", "b"]}},
    }
    (sp / "_mechanical_graph.json").write_text(json.dumps(graph), encoding="utf-8")
    _sol(root, "C.sol",
         "contract C {\n"
         "  function viewFn() external view returns (uint) { return 1; }\n"
         "}\n")
    eg.compute_axis_coverage_gaps(sp)
    matrix = json.loads((sp / "_hot_function_axes.json").read_text(encoding="utf-8"))
    row = next(r for r in matrix["matrix"] if r["function"] == "viewFn")
    assert row["cells"]["identity"] == "N/A"
    assert not any(g["function"] == "viewFn" and g["axis"] == "identity"
                   for g in matrix["gaps"])


def test_identity_cue_fires_on_cross_language_evm_worded_block(tmp_path):
    """(d) Cross-language non-overfit fixture: a finding block written in
    EVM terms (msg.sender vs from) must still trigger the identity cue --
    proving the detector reads a GENERIC authorization-subject phrase shape
    ("acts on behalf of ... owner"), not a Soroban-shaped vocabulary. The
    cue never contains an EVM/Solana/Move source token itself; incidental
    source-token mentions in the finding's OWN prose (msg.sender, from) must
    not be required for, nor block, the match."""
    eg = _eg()
    root, sp = _proj(tmp_path)
    _hot_graph(sp, root)
    _write_inv_finding(
        sp, "C.sol:L10",
        "**Description**: The function loosely compares msg.sender against "
        "the from address; a caller can invoke transferFrom acting on "
        "behalf of a different owner without an allowance check, since the "
        "caller never proves ownership over the from address.\n")
    gaps = eg.compute_axis_coverage_gaps(sp)
    gapped = {g["axis"] for g in gaps}
    assert "identity" not in gapped
    matrix = json.loads((sp / "_hot_function_axes.json").read_text(encoding="utf-8"))
    cells = matrix["matrix"][0]["cells"]
    assert cells["identity"] == "EXAMINED"


# ── skip-when-clean ──────────────────────────────────────────────────────────

def test_skip_when_no_gaps_true(tmp_path):
    import plamen_driver as D
    from test_axis_driver_transaction_red_p0_i import _axis_phase, _config
    from test_axis_population_provider_p0_i import _project, _write_graph

    project, sp = _project(tmp_path)
    _write_graph(
        sp,
        {
            "Unit.quiet(uint256)": {
                "bare": "quiet",
                "loc": "contracts/Unit.sol:L2",
                "callers": [],
            }
        },
    )
    worklist, issues = D._prepare_axis_disposition_worklist(
        phase=_axis_phase(),
        config=_config(project),
        scratchpad=sp,
    )
    assert issues == []
    assert worklist["clean_empty"] is True
    assert D._axis_coverage_has_no_obligations(sp) is True


def test_skip_when_gaps_present_false(tmp_path):
    import plamen_driver as D
    from test_axis_driver_transaction_red_p0_i import _axis_phase, _config
    from test_axis_population_provider_p0_i import _project, _write_graph

    project, sp = _project(tmp_path)
    _write_graph(
        sp,
        {
            "Unit.quiet(uint256)": {
                "bare": "quiet",
                "loc": "contracts/Unit.sol:L2",
                "callers": ["one", "two"],
            }
        },
    )
    worklist, issues = D._prepare_axis_disposition_worklist(
        phase=_axis_phase(),
        config=_config(project),
        scratchpad=sp,
    )
    assert issues == []
    assert worklist["count"] > 0
    assert D._axis_coverage_has_no_obligations(sp) is False


def test_skip_conservative_false_on_exception(tmp_path, monkeypatch):
    import plamen_driver as D
    root, sp = _proj(tmp_path)

    def _boom(_path):
        raise RuntimeError("boom")
    monkeypatch.setattr(
        D.axis_disposition_authority,
        "load_axis_worklist_v2",
        _boom,
    )
    # Conservative: on failure DO NOT skip (recall over cost).
    assert D._axis_coverage_has_no_obligations(sp) is False


# ── promotion parity (Source IDs: AXISGAP, idempotent) ───────────────────────

def test_promotion_noop_without_artifact(tmp_path):
    eg = _eg()
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    (sp / "findings_inventory.md").write_text("# Inv\n", encoding="utf-8")
    assert eg.promote_axis_findings_to_inventory(sp) == {"parsed": 0, "emitted": 0}


def test_promotion_appends_axisgap_and_is_idempotent(tmp_path):
    eg = _eg()
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    (sp / "findings_inventory.md").write_text(
        "# Findings Inventory\n\n"
        "### Finding [INV-001]: existing\n"
        "**Severity**: Medium\n**Location**: `a` :: `f`\n"
        "**Description**: x\n**Impact**: y\n",
        encoding="utf-8")
    (sp / "axis_coverage_findings.md").write_text(
        "# Multi-Axis Coverage Meta-Pass\n\n"
        "### Finding [AXIS-1]: theft on a hot function\n"
        "**Severity**: Medium\n"
        "**Location**: `C.sol:L10` (fn: `hotFn`)\n"
        "**Preferred Tag**: [CODE-TRACE]\n"
        "**Root Cause**: value can leave to an unauthorized party\n"
        "**Description**: [TRACE:withdraw->transfer to attacker] value extraction\n"
        "**Impact**: attacker drains pool share\n"
        "**Material Harm**: depositors lose pro-rata share\n"
        "**Postconditions Created**: BALANCE: funds leave to attacker\n"
        "**Postcondition Types**: BALANCE\n\n"
        "## Coverage Record\n\n"
        "| Function | Axis | Disposition | Evidence |\n"
        "|---|---|---|---|\n"
        "| hotFn | theft | FINDING | AXIS-1 |\n",
        encoding="utf-8")
    res = eg.promote_axis_findings_to_inventory(sp)
    assert res["emitted"] == 1
    inv = (sp / "findings_inventory.md").read_text(encoding="utf-8")
    assert "INV-002" in inv
    # Fix 1a: clean greppable class token `AXISGAP:AXIS-1`, not bare `AXIS-1`.
    assert "Source IDs**: AXISGAP:AXIS-1" in inv or \
        "Source IDs: AXISGAP:AXIS-1" in inv.replace("**", "")
    assert "AXISGAP" in inv  # section header stamp
    assert "theft on a hot function" in inv
    # chain metadata preserved so it's a STEP-0a-LC enabler
    assert "Postconditions Created" in inv
    # idempotent
    assert eg.promote_axis_findings_to_inventory(sp)["emitted"] == 0


def test_promotion_parses_three_part_axis_ids(tmp_path):
    """Regression (feedback_id_regex_catalog): the M2 axis-worker emits
    AXIS-<shard>-<n> (AXIS-A-1..AXIS-F-4), not the bare AXIS-1 form the old
    fixture used. A `[A-Za-z]{2,6}-\\d+`-only heading regex silently dropped
    every 3-part heading (14 findings incl. a High in one Thorough regression run)."""
    eg = _eg()
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    (sp / "findings_inventory.md").write_text(
        "# Findings Inventory\n", encoding="utf-8")

    def _f(fid: str, title: str) -> str:
        return (
            f"### Finding [{fid}]: {title}\n"
            "**Severity**: High\n"
            "**Location**: `C.sol:L10` (fn: `hotFn`)\n"
            "**Preferred Tag**: [CODE-TRACE]\n"
            "**Description**: [TRACE:withdraw->stranded] concrete trace\n"
            "**Impact**: principal stranded on abort path\n"
            "**Material Harm**: depositor permanently loses bridged principal\n\n")

    (sp / "axis_coverage_findings.md").write_text(
        "# Multi-Axis Coverage Meta-Pass\n\n"
        + _f("AXIS-A-1", "theft on a hot function")
        + _f("AXIS-F-4", "liveness brick on withdraw"),
        encoding="utf-8")
    res = eg.promote_axis_findings_to_inventory(sp)
    assert res["emitted"] == 2, res
    inv = (sp / "findings_inventory.md").read_text(encoding="utf-8").replace("**", "")
    assert "AXISGAP:AXIS-A-1" in inv
    assert "AXISGAP:AXIS-F-4" in inv
    # Idempotency regression guard: the receipt is written as `AXIS-A-1 -> INV-00n`;
    # if the receipt re-read regex is narrower than the heading regex it cannot
    # match the 3-part ID, so every resume/retry re-appends duplicates. Second
    # run must emit 0 and leave exactly one block per source finding.
    assert eg.promote_axis_findings_to_inventory(sp)["emitted"] == 0
    inv2 = (sp / "findings_inventory.md").read_text(encoding="utf-8").replace("**", "")
    assert inv2.count("AXISGAP:AXIS-A-1") == 1, inv2.count("AXISGAP:AXIS-A-1")
    assert inv2.count("AXISGAP:AXIS-F-4") == 1, inv2.count("AXISGAP:AXIS-F-4")


# ── soft validator ───────────────────────────────────────────────────────────

def test_validator_in_all_and_soft():
    import plamen_validators as V
    assert "_validate_axis_coverage" in V.__all__


def test_validator_never_halts_missing_artifact(tmp_path):
    import plamen_validators as V
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    assert V._validate_axis_coverage(sp, "thorough") == []
    assert (sp / "axis_coverage.degraded").exists()


def test_validator_noop_off_thorough(tmp_path):
    import plamen_validators as V
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    assert V._validate_axis_coverage(sp, "core") == []
    # no sentinel written off-thorough
    assert not (sp / "axis_coverage.degraded").exists()


# ── phase wiring ─────────────────────────────────────────────────────────────

def test_resolves_to_prompt_file():
    import plamen_prompt as P
    assert P._STANDALONE_PROMPT_MAP.get("axis_coverage") == "phase4b8-axis-coverage.md"
    resolved = P._resolve_standalone_prompt("axis_coverage")
    assert resolved is not None and resolved.exists()
    assert resolved.name == "phase4b8-axis-coverage.md"


def test_phase_registered_thorough_only_soft():
    from plamen_types import SC_PHASES
    p = next((x for x in SC_PHASES if x.name == "axis_coverage"), None)
    assert p is not None, "SC missing axis_coverage phase"
    assert p.critical is False
    assert p.model == "sonnet"
    assert p.expected_artifacts == [
        "axis_coverage_findings.md",
        "axis_coverage_dispositions.json",
    ]
    assert p.modes == {"thorough"}
    assert p.base_timeout_s == 3600


def test_phase_ordered_after_4b7_before_dedup_chain():
    from plamen_types import SC_PHASES
    names = [p.name for p in SC_PHASES]
    i_enumgap = names.index("enumgap_exploration")
    i_axis = names.index("axis_coverage")
    i_dedup = names.index("sc_semantic_dedup")
    i_chain = names.index("chain")
    assert i_enumgap < i_axis < i_dedup < i_chain, (
        f"order broken: enumgap={i_enumgap} axis={i_axis} "
        f"dedup={i_dedup} chain={i_chain}")


def test_driver_dispatches_typed_planning_finalization_and_promotion():
    src = (SCRIPTS_DIR / "plamen_driver.py").read_text(encoding="utf-8")
    assert "_prepare_axis_disposition_worklist(" in src
    assert "_axis_coverage_has_no_obligations(scratchpad)" in src
    assert "_finalize_axis_coverage_boundary(" in src
    assert "_axis_coverage_has_no_gaps(scratchpad)" not in src
    assert "_validate_axis_coverage(scratchpad" not in src
    assert "promote_axis_findings_to_inventory(scratchpad)" not in src


def test_axisgap_source_id_cataloged():
    from plamen_parsers import _FID_ALLOWED_PREFIXES
    assert "AXISGAP" in _FID_ALLOWED_PREFIXES
