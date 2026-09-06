"""MECHANISM 1 — committed-invariant assertion deriver (§5.1 of the recall build
plan). The deriver harvests `committed-invariant [CI-n]` blocks the skeptic/depth
phases emit and turns each into a low-confidence falsifiable inventory candidate
(Source IDs: INVARIANT, NEEDS_VERIFICATION), routed through the SAME ENUMGAP
inventory->verify path. Generic: names no protocol; symbols resolve at the locus.

Covers: one-candidate-per-block for all six shapes, correct Falsify Class, chain
metadata present, `Source IDs: INVARIANT` stamping, budget isolation from the
co-ref pool, idempotency (receipt honored), degrade (missing graph /
un-executable), and fail-closed commitment-debt validation (`.ci_gap` sentinel).
"""
from __future__ import annotations

import importlib
import json
import os
import sys
from pathlib import Path


def _eg():
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    return importlib.import_module("enumeration_gate")


def _V():
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    return importlib.import_module("plamen_validators")


def _proj(tmp_path: Path):
    """Make <root>/.scratchpad plus a sibling source file so _load_graph /
    _locate_project_root behave, and a seed inventory the emitter appends to."""
    root = tmp_path / "proj"
    sp = root / ".scratchpad"
    sp.mkdir(parents=True)
    (sp / "findings_inventory.md").write_text("# Inv\n", encoding="utf-8")
    # a sibling source file so _locate_project_root resolves (some paths rglob it)
    (root / "Pricing.sol").write_text(
        "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.20;\n"
        "contract Pricing {\n  function getQuote() external {}\n}\n",
        encoding="utf-8",
    )
    return root, sp


_SIX_SHAPES = [
    ("CONSERVATION", "conservation"),
    ("REQUESTED_EQ_DELIVERED", "property"),
    ("APPROVE_EQ_SPEND", "property"),
    ("NO_REVERT_AT_BOUNDARY", "boundary"),
    ("ROUNDTRIP", "roundtrip"),
    ("FRESHNESS", "property"),
]


def _ci_block(n: int, shape: str, fclass: str, loc: str = "src/Pricing.sol:L142") -> str:
    return (
        f"committed-invariant [CI-{n}]\n"
        f"Locus: {loc}  (fn: getQuote)\n"
        f"Shape: {shape}\n"
        f"Assertion: assert(relation holds at {loc})\n"
        f"Falsify Class: {fclass}\n"
        f"Provenance: skeptic NO-GAP @ instance-{n}\n"
    )


def _write_skeptic(sp: Path, *blocks: str):
    body = "# Exploration Skeptic Findings\n\n" + "\n\n".join(blocks) + "\n"
    (sp / "exploration_skeptic_findings.md").write_text(body, encoding="utf-8")


# ── one candidate per block, all six shapes, class + chain metadata + Source ──

def test_all_six_shapes_one_candidate_each(tmp_path: Path):
    eg = _eg()
    _root, sp = _proj(tmp_path)
    blocks = [_ci_block(i + 1, shape, fclass)
              for i, (shape, fclass) in enumerate(_SIX_SHAPES)]
    _write_skeptic(sp, *blocks)
    out = eg.compute_invariant_assertion_candidates(sp)
    assert len(out) == 6, f"expected 6 candidates, got {len(out)}"
    for (shape, fclass), c in zip(_SIX_SHAPES, out):
        assert c["key"].startswith("INVARIANT:"), c["key"]
        assert shape in c["title"], c["title"]
        # Falsify Class threaded into the source_note.
        assert fclass in c["source_note"].lower(), c["source_note"]
        # chain metadata present so it is a STEP-0a-LC enabler for free
        assert c.get("postcondition"), c
        assert c.get("postcondition_type") in {"BALANCE", "ACCESS", "STATE", "EXTERNAL"}


def test_shard_namespaced_ci_ids_are_harvested(tmp_path: Path):
    """Regression (feedback_id_regex_catalog): skeptic shard-workers emit
    CI-<shard><n> (CI-A1..CI-D3), not the bare CI-1 form. A `CI-\\d+`-only
    harvest regex silently dropped every namespaced block (12 dropped in the
    a live Thorough run, incl. all skeptic-committed invariants). The deriver must parse
    the namespaced form."""
    eg = _eg()
    _root, sp = _proj(tmp_path)

    def _blk(cid: str, shape: str) -> str:
        return (
            f"committed-invariant [{cid}]\n"
            f"Locus: src/Pricing.sol:L142  (fn: getQuote)\n"
            f"Shape: {shape}\n"
            f"Assertion: assert(relation holds at src/Pricing.sol:L142)\n"
            f"Falsify Class: property\n"
            f"Provenance: skeptic NO-GAP @ {cid}\n"
        )

    # CI-ES6-1 is a real 3-segment shard form observed in another live run; the
    # reconciliation gate caught it as a residual drop when the CI pattern was
    # only 2-segment (CI-[A-Za-z0-9]+). The deriver must harvest it too.
    _write_skeptic(sp, _blk("CI-A1", "CONSERVATION"),
                   _blk("CI-B2", "FRESHNESS"), _blk("CI-D3", "ROUNDTRIP"),
                   _blk("CI-ES6-1", "CONSERVATION"))
    out = eg.compute_invariant_assertion_candidates(sp)
    assert len(out) == 4, f"expected 4 namespaced candidates, got {len(out)}"
    tags = " ".join(c["source_tag"] for c in out)
    assert "INVARIANT:CI-A1" in tags and "INVARIANT:CI-D3" in tags, tags
    assert "INVARIANT:CI-ES6-1" in tags, tags


def test_emitted_candidate_stamps_source_id_invariant(tmp_path: Path):
    """When routed through _emit_candidates with source_id='INVARIANT' the
    inventory block carries `**Source IDs**: INVARIANT` + NEEDS_VERIFICATION."""
    eg = _eg()
    _root, sp = _proj(tmp_path)
    _write_skeptic(sp, _ci_block(1, "CONSERVATION", "conservation"))
    cands = eg.compute_invariant_assertion_candidates(sp)
    n = eg._emit_candidates(sp, cands, eg._MAX_PER_DERIVER, source_id="INVARIANT")
    assert n == 1
    inv = (sp / "findings_inventory.md").read_text(encoding="utf-8")
    assert "**Source IDs**: INVARIANT" in inv
    assert "**Verdict**: NEEDS_VERIFICATION" in inv
    assert "INV-001" in inv


def test_run_gate_wires_invariant_deriver(tmp_path: Path):
    eg = _eg()
    _root, sp = _proj(tmp_path)
    _write_skeptic(sp, _ci_block(1, "FRESHNESS", "property"),
                   _ci_block(2, "ROUNDTRIP", "roundtrip"))
    res = eg.run_enumeration_gate(sp)
    assert res.get("invariant_emitted", 0) == 2, res
    inv = (sp / "findings_inventory.md").read_text(encoding="utf-8")
    assert "**Source IDs**: INVARIANT" in inv


# ── budget isolation: 20 CI blocks capped at _MAX_PER_DERIVER, co-ref pool free ──

def test_budget_isolation_capped_at_max_per_deriver(tmp_path: Path):
    eg = _eg()
    _root, sp = _proj(tmp_path)
    blocks = [_ci_block(i + 1, "CONSERVATION", "conservation") for i in range(20)]
    _write_skeptic(sp, *blocks)
    cands = eg.compute_invariant_assertion_candidates(sp)
    # the deriver itself harvests all distinct blocks; the CAP is applied at emit.
    assert len(cands) == 20
    n = eg._emit_candidates(sp, cands, eg._MAX_PER_DERIVER, source_id="INVARIANT")
    assert n == eg._MAX_PER_DERIVER == 15, n


def test_budget_isolation_coref_pool_untouched(tmp_path: Path):
    """The co-ref pool (_MAX_ENUMGAP_PER_RUN) is a DISTINCT constant; the M1
    deriver uses _MAX_PER_DERIVER and never draws from the co-ref pool."""
    eg = _eg()
    assert eg._MAX_PER_DERIVER == 15
    assert eg._MAX_ENUMGAP_PER_RUN == 40
    assert eg._MAX_PER_DERIVER != eg._MAX_ENUMGAP_PER_RUN
    _root, sp = _proj(tmp_path)
    _write_skeptic(sp, *[_ci_block(i + 1, "ROUNDTRIP", "roundtrip") for i in range(20)])
    res = eg.run_enumeration_gate(sp)
    # capped at 15 by the deriver's OWN pool, not starved to 0 by the co-ref gate,
    # not allowed up to 40 by borrowing the co-ref pool.
    assert res.get("invariant_emitted") == 15, res


# ── idempotency: re-run yields no duplicate candidates (receipt honored) ──

def test_idempotent_no_duplicate_on_rerun(tmp_path: Path):
    eg = _eg()
    _root, sp = _proj(tmp_path)
    _write_skeptic(sp, _ci_block(1, "APPROVE_EQ_SPEND", "property"))
    first = eg.run_enumeration_gate(sp)
    assert first.get("invariant_emitted") == 1
    second = eg.run_enumeration_gate(sp)
    # nothing new emitted on re-run → the additive key is absent (backward-compat
    # base contract), so .get defaults to 0.
    assert second.get("invariant_emitted", 0) == 0, second
    inv = (sp / "findings_inventory.md").read_text(encoding="utf-8")
    assert inv.count("**Source IDs**: INVARIANT") == 1


# ── degrade: missing graph / un-executable → still emitted, file-scope locus ──

def test_degrade_missing_graph_still_emits(tmp_path: Path):
    """No _mechanical_graph.json present → deriver still emits the candidate,
    resolving locus at file-scope (never halts, never drops)."""
    eg = _eg()
    _root, sp = _proj(tmp_path)
    assert not (sp / "_mechanical_graph.json").exists()
    _write_skeptic(sp, _ci_block(1, "NO_REVERT_AT_BOUNDARY", "boundary"))
    out = eg.compute_invariant_assertion_candidates(sp)
    assert len(out) == 1


def test_degrade_unknown_shape_still_emits(tmp_path: Path):
    """A garbled/unknown Shape still emits (recall-safe) with a generic STATE
    chain relation rather than being dropped."""
    eg = _eg()
    _root, sp = _proj(tmp_path)
    blk = (
        "committed-invariant [CI-9]\n"
        "Locus: src/Weird.sol:L5  (fn: doThing)\n"
        "Shape: SOMETHING_ELSE\n"
        "Assertion: assert(x)\n"
        "Falsify Class: property\n"
    )
    _write_skeptic(sp, blk)
    out = eg.compute_invariant_assertion_candidates(sp)
    assert len(out) == 1
    assert out[0]["postcondition_type"] == "STATE"


def test_degrade_empty_stub_block_skipped(tmp_path: Path):
    """A [CI-n] header with no Locus and no Assertion carries nothing
    falsifiable → not emitted (not a spurious candidate)."""
    eg = _eg()
    _root, sp = _proj(tmp_path)
    blk = "committed-invariant [CI-1]\nShape: CONSERVATION\n"
    _write_skeptic(sp, blk)
    out = eg.compute_invariant_assertion_candidates(sp)
    assert out == []


# ── soft validator: NO-GAP clears without [CI-n] → warning + .ci_gap, passed True ──

def test_validator_ci_gap_is_explicit_debt_and_writes_sentinel(tmp_path: Path):
    V = _V()
    _root, sp = _proj(tmp_path)
    # skeptic artifact with a NO-GAP clear but NO committed-invariant block
    (sp / "exploration_skeptic_findings.md").write_text(
        "# Exploration Skeptic Findings\n\n"
        "| Finding | Axis | Instance | Disposition | Evidence |\n"
        "|---------|------|----------|-------------|----------|\n"
        "| F-1 | Direction | up | NO-GAP | src/Vault.sol:L10 |\n",
        encoding="utf-8",
    )
    issues = V._validate_invariant_commitment(sp, "thorough")
    assert issues == [
        "committed-invariant coverage gap: "
        "1 value-bearing clear(s), 0 harvestable CI blocks"
    ]
    assert (sp / "invariant_commitment.ci_gap").exists()


def test_soft_validator_no_sentinel_when_ci_present(tmp_path: Path):
    V = _V()
    _root, sp = _proj(tmp_path)
    (sp / "exploration_skeptic_findings.md").write_text(
        "# Exploration Skeptic Findings\n\n"
        "| Finding | Axis | Instance | Disposition | Evidence |\n"
        "|---------|------|----------|-------------|----------|\n"
        "| F-1 | Direction | up | NO-GAP | src/Vault.sol:L10 |\n\n"
        + _ci_block(1, "CONSERVATION", "conservation"),
        encoding="utf-8",
    )
    issues = V._validate_invariant_commitment(sp, "thorough")
    assert issues == []
    assert not (sp / "invariant_commitment.ci_gap").exists()


def test_soft_validator_noop_off_thorough(tmp_path: Path):
    V = _V()
    _root, sp = _proj(tmp_path)
    (sp / "exploration_skeptic_findings.md").write_text(
        "NO-GAP everywhere\n" * 5, encoding="utf-8")
    assert V._validate_invariant_commitment(sp, "core") == []
    assert not (sp / "invariant_commitment.ci_gap").exists()


def test_soft_validator_noop_missing_artifact(tmp_path: Path):
    V = _V()
    _root, sp = _proj(tmp_path)
    assert V._validate_invariant_commitment(sp, "thorough") == []
    assert not (sp / "invariant_commitment.ci_gap").exists()


def test_soft_validator_exported(tmp_path: Path):
    V = _V()
    assert "_validate_invariant_commitment" in V.__all__


# ── ID catalog: CI-\d+ and INVARIANT/AXISGAP recognized ──

def test_id_catalog_recognizes_ci_and_invariant():
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    P = importlib.import_module("plamen_parsers")
    assert P._INTERNAL_FINDING_ID_RE.search("committed-invariant [CI-3]")
    assert "INVARIANT" in P._FID_ALLOWED_PREFIXES
    assert "AXISGAP" in P._FID_ALLOWED_PREFIXES
    # CI-n must be stripped from client-body output (never client-facing).
    assert P._CLIENT_BODY_INTERNAL_ID_RE.search("see CI-3 for context")


# ── Fix 2: depth + verify are now PRIMARY CI emitters (mandatory CI block on any
#    value-bearing CLEAR/REFUTED verdict). The deriver must scan depth_*_findings.md
#    AND verify_*.md, not just the skeptic artifacts. ──

def _write_depth(sp: Path, *blocks: str):
    """A depth artifact carrying a REFUTED value-bearing finding + its committed
    invariant block(s) — the primary M1 reservoir after Fix 2."""
    finding = (
        "## Finding [DTF-1]: Withdraw conservation holds\n"
        "**Verdict**: REFUTED\n"
        "**Severity**: High\n"
        "**Location**: src/Pricing.sol:L142\n"
        "**Material Harm**: none — value-conservation guard holds; no depositor loss\n"
        "**Impact**: value-movement path is safe\n\n"
    )
    body = "# Depth Token-Flow Findings\n\n" + finding + "\n\n".join(blocks) + "\n"
    (sp / "depth_token_flow_findings.md").write_text(body, encoding="utf-8")


def _write_verify(sp: Path, *blocks: str):
    """A verify artifact with a value-bearing FALSE_POSITIVE verdict + CI block(s)."""
    body = ("# Verify H-3\n\n"
            "**Final Verdict**: FALSE_POSITIVE\n"
            "**Location**: src/Pricing.sol:L142\n\n"
            + "\n\n".join(blocks) + "\n")
    (sp / "verify_H-3.md").write_text(body, encoding="utf-8")


def test_ci_source_globs_include_depth_and_verify():
    """Deriver scan set must cover depth + verify (Fix 2 widening), not skeptic-only."""
    eg = _eg()
    assert "depth_*_findings.md" in eg._CI_SOURCE_GLOBS
    assert "verify_*.md" in eg._CI_SOURCE_GLOBS


def test_refuted_value_bearing_depth_finding_emits_invariant(tmp_path: Path):
    """A REFUTED value-bearing depth finding carrying a CI block → the deriver
    emits an INVARIANT candidate, stamped INVARIANT:CI-n + NEEDS_VERIFICATION."""
    eg = _eg()
    _root, sp = _proj(tmp_path)
    _write_depth(sp, _ci_block(1, "CONSERVATION", "conservation"))
    out = eg.compute_invariant_assertion_candidates(sp)
    assert len(out) == 1, out
    c = out[0]
    assert c["key"].startswith("INVARIANT:")
    assert c["source_tag"] == "INVARIANT:CI-1", c["source_tag"]
    n = eg._emit_candidates(sp, out, eg._MAX_PER_DERIVER, source_id="INVARIANT")
    assert n == 1
    inv = (sp / "findings_inventory.md").read_text(encoding="utf-8")
    assert "**Source IDs**: INVARIANT:CI-1" in inv
    assert "**Verdict**: NEEDS_VERIFICATION" in inv


def test_verify_ci_block_harvested(tmp_path: Path):
    """A verify_*.md artifact with a CI block is scanned + harvested (Fix 2)."""
    eg = _eg()
    _root, sp = _proj(tmp_path)
    _write_verify(sp, _ci_block(2, "FRESHNESS", "property"))
    out = eg.compute_invariant_assertion_candidates(sp)
    assert len(out) == 1
    assert out[0]["source_tag"] == "INVARIANT:CI-2"


def test_late_verify_ci_is_never_current_run_verified(tmp_path: Path):
    """A verifier-emitted CI is only a next-run/human-review candidate."""
    eg = _eg()
    _root, sp = _proj(tmp_path)
    _write_verify(sp, _ci_block(2, "FRESHNESS", "property"))
    assert eg.recover_invariant_assertion_candidates(sp) == 1
    inventory = (sp / "findings_inventory.md").read_text(encoding="utf-8")
    assert "**Source IDs**: INVARIANT:CI-2" in inventory
    assert "**Verdict**: NEEDS_VERIFICATION" in inventory
    assert "**Verdict**: VERIFIED" not in inventory


def test_validator_persists_and_replays_late_verify_ci_authority(
    tmp_path: Path,
) -> None:
    V = _V()
    _root, sp = _proj(tmp_path)
    _write_verify(sp, _ci_block(3, "FRESHNESS", "property"))
    assert V._validate_invariant_commitment(sp, "thorough") == []
    payload = json.loads(
        (sp / "_late_committed_invariant_authority.json").read_text(
            encoding="utf-8"
        )
    )
    assert payload["authority"] == "HUMAN_REVIEW_NEXT_RUN"
    assert payload["status"] == "NEEDS_VERIFICATION"
    assert len(payload["records"]) == 1
    assert V._validate_invariant_commitment(
        sp, "thorough", recover=False
    ) == []


def test_validator_surfaces_typed_late_ci_recovery_failure(
    tmp_path: Path, monkeypatch,
) -> None:
    V = _V()
    eg = _eg()
    late = importlib.import_module("late_committed_invariant_authority")
    _root, sp = _proj(tmp_path)
    _write_verify(sp, _ci_block(4, "FRESHNESS", "property"))

    def fail(_scratchpad: Path) -> int:
        raise late.LateCommittedInvariantError(
            stage="EMISSION",
            code="INJECTED_FAILURE",
            detail="candidate bytes unavailable",
        )

    monkeypatch.setattr(eg, "recover_invariant_assertion_candidates", fail)
    issues = V._validate_invariant_commitment(sp, "thorough")
    assert issues == [
        "late committed-invariant EMISSION/INJECTED_FAILURE: "
        "candidate bytes unavailable"
    ]


def test_depth_and_verify_both_scanned(tmp_path: Path):
    """Both new source classes contribute candidates in one pass."""
    eg = _eg()
    _root, sp = _proj(tmp_path)
    _write_depth(sp, _ci_block(1, "CONSERVATION", "conservation"))
    _write_verify(sp, _ci_block(2, "ROUNDTRIP", "roundtrip"))
    out = eg.compute_invariant_assertion_candidates(sp)
    tags = {c["source_tag"] for c in out}
    assert tags == {"INVARIANT:CI-1", "INVARIANT:CI-2"}, tags


# ── Fix 7 Part A: falsifiability-aware shape selection (driver nudge) ──────────

def _ci_conversion_block(n: int, assertion: str) -> str:
    """A CONSERVATION CI block whose assertion carries a value-conversion cue."""
    return (
        f"committed-invariant [CI-{n}]\n"
        f"Locus: src/Pricing.sol:L142  (fn: getQuote)\n"
        f"Shape: CONSERVATION\n"
        f"Assertion: {assertion}\n"
        f"Falsify Class: conservation\n"
        f"Provenance: skeptic NO-GAP @ instance-{n}\n"
    )


def test_conservation_at_conversion_boundary_appends_breakable_shapes(tmp_path: Path):
    """A CONSERVATION invariant emitted at a value-conversion boundary is often
    true by construction, so the emitted candidate's Falsify Class is enriched
    with the breakable shapes NO_REVERT_AT_BOUNDARY + REQUESTED_EQ_DELIVERED."""
    eg = _eg()
    _root, sp = _proj(tmp_path)
    _write_skeptic(sp, _ci_conversion_block(1, "amountIn == amountOut for the 1:1 unwrap step"))
    out = eg.compute_invariant_assertion_candidates(sp)
    assert len(out) == 1, out
    note = out[0]["source_note"]
    assert "ALSO falsify" in note
    assert "NO_REVERT_AT_BOUNDARY" in note
    assert "REQUESTED_EQ_DELIVERED" in note
    # still a single candidate — the nudge enriches, it does not multiply rows
    assert out[0]["source_tag"] == "INVARIANT:CI-1"


def test_conservation_without_conversion_cue_not_nudged(tmp_path: Path):
    """A CONSERVATION invariant with no conversion cue keeps its Falsify Class
    unchanged (no spurious breakable-shape append)."""
    eg = _eg()
    _root, sp = _proj(tmp_path)
    _write_skeptic(sp, _ci_conversion_block(1, "sum(shares) == totalShares across the settle"))
    out = eg.compute_invariant_assertion_candidates(sp)
    assert len(out) == 1, out
    assert "ALSO falsify" not in out[0]["source_note"]


def test_non_conservation_shape_never_nudged(tmp_path: Path):
    """The nudge fires ONLY on CONSERVATION; a ROUNDTRIP block at a conversion
    boundary is left alone (its own falsifier can already break)."""
    eg = _eg()
    _root, sp = _proj(tmp_path)
    blk = (
        "committed-invariant [CI-7]\n"
        "Locus: src/Pricing.sol:L142  (fn: getQuote)\n"
        "Shape: ROUNDTRIP\n"
        "Assertion: decode(encode(x)) == x across the wrap conversion\n"
        "Falsify Class: roundtrip\n"
        "Provenance: skeptic NO-GAP @ instance-7\n"
    )
    _write_skeptic(sp, blk)
    out = eg.compute_invariant_assertion_candidates(sp)
    assert len(out) == 1, out
    assert "ALSO falsify" not in out[0]["source_note"]


# ── Fix 7 Part B: CROSS-DOMAIN-DEP is NOT a provenance-axis EXAMINED signal ────

def test_cross_domain_dep_no_longer_closes_provenance_gap():
    """A [CROSS-DOMAIN-DEP: external] tag is an ADMISSION the domain was NOT
    analyzed — it must NOT count as an EXAMINED provenance signal (else the M2
    provenance gap is wrongly closed)."""
    eg = _eg()
    block = ("**Location**: X.sol:L10\n"
             "Analysis with a [CROSS-DOMAIN-DEP: external — off-domain assumption] tag.\n")
    assert eg._axis_examined_signals(block, "provenance") is False


def test_external_assumption_still_closes_provenance_gap():
    """The [EXTERNAL-ASSUMPTION:] tag remains a valid provenance EXAMINED signal
    (it is a positive R10 worst-case adjudication, not an unanalyzed admission)."""
    eg = _eg()
    block = ("**Location**: X.sol:L10\n"
             "[EXTERNAL-ASSUMPTION: destination decoder uses Borsh] worst-case taken.\n")
    assert eg._axis_examined_signals(block, "provenance") is True
