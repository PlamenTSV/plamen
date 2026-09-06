"""Gate V (Fix A) — 3-axis Variant-Family Coverage.

Axis 1 (co-reference) is the existing G1/G2 gate, UNCHANGED (proven by the
regression test at the bottom of this file). Axes 2 (boundary-input) and 3
(symmetric-operation) are new mechanical derivers added by this module,
emitting a `VARGAP` (ENUMGAP-family) low-confidence candidate class through
the SAME append-only, idempotent, bounded inventory path G1/G2 already use.

Every positive-harvest test asserts a NON-EMPTY landing (a synthetic VARGAP
actually appears), not merely "does not crash" — per the ID-regex-catalog
lesson that an over-loose gate with an empty harvest is worse than none.
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


def _proj(tmp_path: Path):
    """<root>/.scratchpad plus a sibling source tree the gate can find."""
    root = tmp_path / "proj"
    sp = root / ".scratchpad"
    sp.mkdir(parents=True)
    return root, sp


def _sol(root: Path, rel: str, body: str):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("// SPDX-License-Identifier: MIT\npragma solidity ^0.8.20;\n" + body,
                 encoding="utf-8")


def _inv(*blocks: str) -> str:
    return "# Finding Inventory\n\n" + "\n\n".join(blocks) + "\n"


def _finding(fid: str, loc: str, verdict: str, body: str, severity: str = "Medium") -> str:
    return (f"### Finding [{fid}]: a finding\n"
            f"**Severity**: {severity}\n"
            f"**Location**: `{loc}`\n"
            f"**Verdict**: {verdict}\n"
            "**Source IDs**: B1-1\n"
            f"{body}\n")


def _write_inv(sp: Path, *blocks: str) -> None:
    (sp / "findings_inventory.md").write_text(_inv(*blocks), encoding="utf-8")


def _graph(functions: dict, var_refs: dict | None = None) -> dict:
    return {"source": "test", "var_refs": var_refs or {}, "functions": functions}


def _write_graph(sp: Path, functions: dict, var_refs: dict | None = None) -> None:
    (sp / "_mechanical_graph.json").write_text(
        json.dumps(_graph(functions, var_refs)), encoding="utf-8")


# ─────────────────────────────────────────────────────────────────────────────
# Axis 2 — boundary-input coverage
# ─────────────────────────────────────────────────────────────────────────────

def test_axis2_names_k_omits_j_emits_exactly_one_vargap_for_j(tmp_path: Path):
    eg = _eg()
    root, sp = _proj(tmp_path)
    _sol(root, "Vault.sol",
         "contract Vault {\n"
         "  function withdraw(uint256 amount) external {\n"
         "    // body\n"
         "  }\n}\n")
    _write_graph(sp, {"Vault.withdraw": {"bare": "withdraw", "loc": "Vault.sol:L5",
                                        "callers": []}})
    # The exact uint type requires zero/one/max.  Associate each addressed
    # value with the parameter and omit max.
    _write_inv(sp, _finding(
        "INV-001", "Vault.sol:L5", "CONFIRMED",
        "Verified amount at zero; verified amount at one; safe otherwise."))
    out = eg.compute_boundary_input_candidates(sp)
    members = [c["key"].rsplit(":", 1)[-1] for c in out]
    assert members == ["max"], out
    assert "max" in out[0]["title"]
    for named in ("zero", "one"):
        assert not any(c["key"].endswith(f":{named}") for c in out)


def test_axis2_all_named_no_gap(tmp_path: Path):
    eg = _eg()
    root, sp = _proj(tmp_path)
    _sol(root, "Vault.sol",
         "contract Vault {\n"
         "  function withdraw(uint256 amount) external {\n"
         "    // body\n"
         "  }\n}\n")
    _write_graph(sp, {"Vault.withdraw": {"bare": "withdraw", "loc": "Vault.sol:L5",
                                        "callers": []}})
    _write_inv(sp, _finding(
        "INV-001", "Vault.sol:L5", "CONFIRMED",
        "Verified amount at zero, amount at one, and amount at the maximum "
        "uint256 value; safe."))
    assert eg.compute_boundary_input_candidates(sp) == []


def test_axis2_graph_absent_is_noop(tmp_path: Path):
    eg = _eg()
    root, sp = _proj(tmp_path)
    _sol(root, "Vault.sol",
         "contract Vault {\n  function withdraw(uint256 amount) external {}\n}\n")
    _write_inv(sp, _finding("INV-001", "Vault.sol:L2", "CONFIRMED", "no guard here"))
    # No _mechanical_graph.json at all.
    assert eg.compute_boundary_input_candidates(sp) == []


def test_axis2_unresolvable_function_is_noop_for_that_finding_only(tmp_path: Path):
    eg = _eg()
    root, sp = _proj(tmp_path)
    _sol(root, "Vault.sol",
         "contract Vault {\n"
         "  function withdraw(uint256 amount) external {}\n"
         "  function setFee(uint256 bps) external {}\n"
         "}\n")
    _write_graph(sp, {
        # withdraw resolves fine (qualifying param, gap present).
        "Vault.withdraw": {"bare": "withdraw", "loc": "Vault.sol:L3", "callers": []},
        # ghostFunction has no matching source-parsed function -> no-op for it.
        "Vault.ghostFunction": {"bare": "ghostFunction", "loc": "Vault.sol:L9", "callers": []},
    })
    _write_inv(
        sp,
        _finding("INV-001", "Vault.sol:L3", "CONFIRMED", "no boundary discussion"),
        _finding("INV-002", "Vault.sol:L9", "CONFIRMED", "no boundary discussion"),
    )
    out = eg.compute_boundary_input_candidates(sp)
    assert any(c["key"].startswith("VARGAP-B:INV-001:") for c in out)
    assert not any(c["key"].startswith("VARGAP-B:INV-002:") for c in out)


def test_axis2_non_qualifying_param_is_noop(tmp_path: Path):
    eg = _eg()
    root, sp = _proj(tmp_path)
    _sol(root, "Vault.sol",
         "contract Vault {\n  function pause() external {}\n}\n")
    _write_graph(sp, {"Vault.pause": {"bare": "pause", "loc": "Vault.sol:L2", "callers": []}})
    _write_inv(sp, _finding("INV-001", "Vault.sol:L2", "CONFIRMED", "no params to bound"))
    assert eg.compute_boundary_input_candidates(sp) == []


def test_axis2_non_confirmed_verdict_is_noop(tmp_path: Path):
    eg = _eg()
    root, sp = _proj(tmp_path)
    _sol(root, "Vault.sol",
         "contract Vault {\n  function withdraw(uint256 amount) external {}\n}\n")
    _write_graph(sp, {"Vault.withdraw": {"bare": "withdraw", "loc": "Vault.sol:L2",
                                        "callers": []}})
    _write_inv(sp, _finding("INV-001", "Vault.sol:L2", "NEEDS_VERIFICATION",
                           "unverified guess, no boundary discussion"))
    assert eg.compute_boundary_input_candidates(sp) == []


def test_axis2_bound_overflow_capped_not_flooded(tmp_path: Path):
    eg = _eg()
    root, sp = _proj(tmp_path)
    n = 5  # 5 findings x 3 uint boundaries each = 15 potential candidates
    lines = ["contract Vault {"]
    blocks = []
    functions = {}
    for i in range(n):
        fn = f"withdraw{i}"
        lines.append(f"  function {fn}(uint256 amount) external {{}}")
        loc = f"Vault.sol:L{100 + i}"
        functions[f"Vault.{fn}"] = {"bare": fn, "loc": loc, "callers": []}
        blocks.append(_finding(f"INV-{i:03d}", loc, "CONFIRMED", "no boundary discussion"))
    lines.append("}")
    _sol(root, "Vault.sol", "\n".join(lines) + "\n")
    _write_graph(sp, functions)
    _write_inv(sp, *blocks)
    out = eg.compute_boundary_input_candidates(sp)
    assert len(out) == eg._MAX_PER_DERIVER
    assert len(out) <= n * 3  # no universal cross-type boundary explosion


# ─────────────────────────────────────────────────────────────────────────────
# Axis 3 — symmetric-operation coverage
# ─────────────────────────────────────────────────────────────────────────────

def _pairs_md(*rows: tuple[str, str, str, str, str]) -> str:
    header = [
        "# Chain Candidate Pairs", "",
        "**Status**: MECHANICAL_PREFILTER", "",
        "### STATE Pairs", "",
        "| Finding A | A Severity | Finding B | B Severity | Shared Signal |",
        "|-----------|-----------|-----------|-----------|---------------|",
    ]
    body = [f"| {a} | {asev} | {b} | {bsev} | {sig} |" for a, asev, b, bsev, sig in rows]
    tail = ["", "### TYPE Pairs", "",
            "| Finding A | A Severity | Finding B | B Severity | Shared Signal |",
            "|-----------|-----------|-----------|-----------|---------------|",
            "| (none) | - | - | - | - |", ""]
    return "\n".join(header + body + tail)


def test_axis3_names_k_omits_j_emits_exactly_one_vargap_for_j(tmp_path: Path):
    eg = _eg()
    root, sp = _proj(tmp_path)
    (sp / "chain_candidate_pairs.md").write_text(
        _pairs_md(("INV-001", "Medium", "INV-002", "Medium", "state: balance")),
        encoding="utf-8")
    _write_inv(
        sp,
        _finding("INV-001", "Vault.sol:L10", "CONFIRMED", "deposit lacks a guard"),
        _finding("INV-002", "Vault.sol:L20", "NEEDS_VERIFICATION", "withdraw not yet checked"),
    )
    out = eg.compute_symmetric_operation_candidates(sp)
    assert len(out) == 1, out
    assert out[0]["key"] == "VARGAP-S:INV-001:INV-002"
    assert "INV-002" in out[0]["title"]
    assert not any("INV-001" in c["key"].split(":")[-1] for c in out)  # not the confirmed leg


def test_axis3_both_confirmed_no_gap(tmp_path: Path):
    eg = _eg()
    root, sp = _proj(tmp_path)
    (sp / "chain_candidate_pairs.md").write_text(
        _pairs_md(("INV-001", "Medium", "INV-002", "Medium", "state: balance")),
        encoding="utf-8")
    _write_inv(
        sp,
        _finding("INV-001", "Vault.sol:L10", "CONFIRMED", "deposit lacks a guard"),
        _finding("INV-002", "Vault.sol:L20", "PARTIAL", "withdraw also lacks it"),
    )
    assert eg.compute_symmetric_operation_candidates(sp) == []


def test_axis3_neither_confirmed_no_gap(tmp_path: Path):
    eg = _eg()
    root, sp = _proj(tmp_path)
    (sp / "chain_candidate_pairs.md").write_text(
        _pairs_md(("INV-001", "Medium", "INV-002", "Medium", "state: balance")),
        encoding="utf-8")
    _write_inv(
        sp,
        _finding("INV-001", "Vault.sol:L10", "NEEDS_VERIFICATION", "maybe a guard gap"),
        _finding("INV-002", "Vault.sol:L20", "REFUTED", "not exploitable"),
    )
    assert eg.compute_symmetric_operation_candidates(sp) == []


def test_axis3_pairs_file_absent_is_noop(tmp_path: Path):
    eg = _eg()
    root, sp = _proj(tmp_path)
    _write_inv(sp, _finding("INV-001", "Vault.sol:L10", "CONFIRMED", "deposit lacks a guard"))
    # No chain_candidate_pairs.md at all.
    assert eg.compute_symmetric_operation_candidates(sp) == []


def test_axis3_unresolvable_pair_leg_is_noop(tmp_path: Path):
    eg = _eg()
    root, sp = _proj(tmp_path)
    (sp / "chain_candidate_pairs.md").write_text(
        _pairs_md(("INV-001", "Medium", "INV-999", "Medium", "state: balance")),
        encoding="utf-8")
    # INV-999 does not exist in the inventory -> pair not resolvable -> no-op.
    _write_inv(sp, _finding("INV-001", "Vault.sol:L10", "CONFIRMED", "deposit lacks a guard"))
    assert eg.compute_symmetric_operation_candidates(sp) == []


def test_axis3_bound_overflow_capped_not_flooded(tmp_path: Path):
    eg = _eg()
    root, sp = _proj(tmp_path)
    n = 20  # 20 confirmed/unaddressed pairs -> would be 20 candidates uncapped
    rows = []
    blocks = []
    for i in range(n):
        a_id, b_id = f"INV-{2*i:03d}", f"INV-{2*i + 1:03d}"
        rows.append((a_id, "Medium", b_id, "Medium", "state: shared"))
        blocks.append(_finding(a_id, f"Vault.sol:L{10*i}", "CONFIRMED", "leg A confirmed"))
        blocks.append(_finding(b_id, f"Vault.sol:L{10*i+5}", "NEEDS_VERIFICATION", "leg B unaddressed"))
    (sp / "chain_candidate_pairs.md").write_text(_pairs_md(*rows), encoding="utf-8")
    _write_inv(sp, *blocks)
    out = eg.compute_symmetric_operation_candidates(sp)
    assert len(out) == eg._MAX_PER_DERIVER
    assert len(out) < n


# ─────────────────────────────────────────────────────────────────────────────
# compute_variant_gaps / validate_variant_coverage — emission + idempotency
# ─────────────────────────────────────────────────────────────────────────────

def test_compute_variant_gaps_emits_both_new_axes_and_is_idempotent(tmp_path: Path):
    eg = _eg()
    root, sp = _proj(tmp_path)
    _sol(root, "Vault.sol",
         "contract Vault {\n"
         "  function withdraw(uint256 amount) external {}\n"
         "}\n")
    _write_graph(sp, {"Vault.withdraw": {"bare": "withdraw", "loc": "Vault.sol:L2",
                                        "callers": []}})
    (sp / "chain_candidate_pairs.md").write_text(
        _pairs_md(("INV-001", "Medium", "INV-002", "Medium", "state: balance")),
        encoding="utf-8")
    _write_inv(
        sp,
        _finding("INV-001", "Vault.sol:L2", "CONFIRMED", "no boundary discussion at all"),
        _finding("INV-002", "Vault.sol:L20", "NEEDS_VERIFICATION", "withdraw leg unaddressed"),
    )
    res1 = eg.compute_variant_gaps(sp)
    assert res1["axis2_emitted"] >= 1
    assert res1["axis3_emitted"] >= 1
    assert res1["emitted"] == res1["axis1_emitted"] + res1["axis2_emitted"] + res1["axis3_emitted"]
    inv_after_1 = (sp / "findings_inventory.md").read_text(encoding="utf-8")
    assert "VARGAP" in inv_after_1

    res2 = eg.compute_variant_gaps(sp)
    assert res2["axis2_emitted"] == 0
    assert res2["axis3_emitted"] == 0
    inv_after_2 = (sp / "findings_inventory.md").read_text(encoding="utf-8")
    assert inv_after_1 == inv_after_2  # append-only + idempotent: byte-identical


def test_validate_variant_coverage_is_alias(tmp_path: Path):
    eg = _eg()
    root, sp = _proj(tmp_path)
    _write_inv(sp, _finding("INV-001", "Vault.sol:L2", "CONFIRMED", "x"))
    res = eg.validate_variant_coverage(sp)
    assert set(res.keys()) >= {"axis1_emitted", "axis2_emitted", "axis3_emitted", "emitted"}


def test_variant_gaps_never_raises_on_garbage(tmp_path: Path):
    eg = _eg()
    root, sp = _proj(tmp_path)
    (sp / "_mechanical_graph.json").write_text("not json {{{", encoding="utf-8")
    (sp / "chain_candidate_pairs.md").write_text("not a table at all", encoding="utf-8")
    (sp / "findings_inventory.md").write_text("### garbage\nno fields\n", encoding="utf-8")
    res = eg.compute_variant_gaps(sp)
    assert res["emitted"] == 0


# ─────────────────────────────────────────────────────────────────────────────
# SC-unchanged regression: run_enumeration_gate (Axis 1 + existing derivers)
# behaves byte-identically to its pre-Gate-V behavior, even when Gate-V
# trigger material (a chain_candidate_pairs.md that WOULD fire axis 3) is
# present in the same scratchpad. Gate V is a separate, additive entry point
# (`compute_variant_gaps`) not wired into `run_enumeration_gate`.
# ─────────────────────────────────────────────────────────────────────────────

_SC_UNCHANGED_GRAPH = {
    "source": "slither",
    "var_refs": {
        "Vault.lpId": {"bare": "lpId", "refs": [
            "withdrawERC721 (Vault.sol:L100)", "createMarket (Vault.sol:L200)"]},
    },
    "functions": {
        "Vault.withdrawERC721": {"bare": "withdrawERC721", "loc": "Vault.sol:L100", "callers": []},
        "Vault.createMarket": {"bare": "createMarket", "loc": "Vault.sol:L200", "callers": []},
    },
}


def test_run_enumeration_gate_is_byte_unchanged_by_gate_v(tmp_path: Path):
    eg = _eg()
    root, sp = _proj(tmp_path)
    (sp / "_mechanical_graph.json").write_text(json.dumps(_SC_UNCHANGED_GRAPH), encoding="utf-8")
    _write_inv(
        sp,
        _finding("INV-001", "Vault.sol:L100", "CONFIRMED",
                "withdrawERC721 removes the lpId NFT; recipient-gated, safe."),
    )
    # Gate-V trigger material present (would fire axis 3 if it were wired in).
    (sp / "chain_candidate_pairs.md").write_text(
        _pairs_md(("INV-001", "Medium", "INV-777", "Medium", "state: lpId")),
        encoding="utf-8")

    res = eg.run_enumeration_gate(sp)
    assert res == {"obligations": 1, "gaps": 1, "emitted": 1}  # identical to pre-Gate-V behavior
    inv = (sp / "findings_inventory.md").read_text(encoding="utf-8")
    assert "ENUMGAP" in inv
    assert "createMarket" in inv
    assert "VARGAP" not in inv  # Gate V never ran as part of run_enumeration_gate


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-q"]))
