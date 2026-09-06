"""Tests for chain_prep.py — the Phase 4c chain-bounding mechanical producers.

Background: the chain phase hung 50 min on a live audit because Chain Agent 1's
PHASE 1 grouping and Agent 2's PHASE 2 matching are unbounded. The chain prompts
reference `chain_candidate_pairs.md` / `variable_finding_map.md` ("evaluate ONLY
these pairs") but nothing produced them. `chain_prep.py` builds those producers.

These tests lock in:
  1. Each producer emits a well-formed file from a realistic fixture.
  2. A pair with a real shared signal (state var / identifier / proximity)
     appears; a provably-unrelated pair does not.
  3. The bounded `chain_candidate_pairs.md` is capped and balanced; the full
     set is complete in `chain_candidate_pairs_full.md`.
  4. Graceful degradation: missing/malformed inputs → empty output, no raise.
  5. Idempotency: re-running produces identical results.

Run: `pytest scripts/test_chain_prep.py -v`
"""
from __future__ import annotations

import importlib
import os
import sys
from pathlib import Path


def _cp():
    sys.path.insert(0, os.path.join(os.path.dirname(__file__)))
    if "chain_prep" in sys.modules:
        del sys.modules["chain_prep"]
    return importlib.import_module("chain_prep")


def _write_inventory(sp: Path, findings: list[dict]) -> None:
    """findings: list of {id, severity, location, verdict, root_cause, description}."""
    lines = ["# Findings Inventory", "", "## Findings", ""]
    for f in findings:
        lines.append(f"### Finding [{f['id']}]: {f.get('title', f['id'] + ' title')}")
        if f.get("source_ids"):
            lines.append(f"**Source IDs**: {f['source_ids']}")
        lines.append(f"**Severity**: {f.get('severity', 'Medium')}")
        lines.append(f"**Location**: {f.get('location', 'X.sol:L1')}")
        lines.append(f"**Verdict**: {f.get('verdict', 'CONFIRMED')}")
        lines.append(f"**Root Cause**: {f.get('root_cause', '')}")
        lines.append(f"**Description**: {f.get('description', '')}")
        lines.append(f"**Impact**: {f.get('impact', 'some impact')}")
        for label, key in (
            ("Discovery Steer", "discovery_steer"),
            ("Missing Precondition", "missing_precondition"),
            ("Precondition Type", "precondition_type"),
            ("Postconditions Created", "postconditions_created"),
            ("Postcondition Types", "postcondition_types"),
            ("Semantic Invariant", "semantic_invariant"),
            ("Branch Preconditions", "branch_preconditions"),
            ("Terminal Mechanism", "terminal_mechanism"),
            ("Composition Candidates", "composition_candidates"),
        ):
            if f.get(key):
                lines.append(f"**{label}**: {f[key]}")
        lines.append("")
    (sp / "findings_inventory.md").write_text("\n".join(lines), encoding="utf-8")


def _write_state_write_map(sp: Path, contract: str, variables: list[str]) -> None:
    lines = ["# State Write Map", "", f"## {contract}.sol", "",
             "| State Variable | Writer Function | Write Site | Access Guard |",
             "|----------------|-----------------|------------|--------------|"]
    for v in variables:
        lines.append(f"| {v} | someWriter | L10 | onlyOwner |")
    (sp / "state_write_map.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def _write_state_variables(sp: Path, rows: list[tuple[str, str, str]]) -> None:
    lines = [
        "# State Variables",
        "",
        "| File | Variable | Type | Line |",
        "|------|----------|------|------|",
    ]
    for file_name, variable, variable_type in rows:
        lines.append(f"| `{file_name}` | `{variable}` | `{variable_type}` | 10 |")
    (sp / "state_variables.md").write_text(
        "\n".join(lines) + "\n", encoding="utf-8"
    )


# ---------------------------------------------------------------------------
# Producer 1 — chain_candidate_pairs
# ---------------------------------------------------------------------------


def test_candidate_pairs_shared_state_var(tmp_path):
    cp = _cp()
    _write_state_write_map(tmp_path, "Vault", ["pendingClaims", "balances"])
    _write_inventory(tmp_path, [
        {"id": "INV-001", "severity": "High", "location": "Vault.sol:L100",
         "root_cause": "claimPayout deletes pendingClaims before transfer",
         "description": "pendingClaims mapping mutated unsafely"},
        {"id": "INV-002", "severity": "Medium", "location": "Vault.sol:L300",
         "root_cause": "onAbort writes pendingClaims with wrong length",
         "description": "pendingClaims stored from abort context"},
    ])
    out = cp.compute_chain_candidate_pairs(tmp_path)
    assert out["status"] == "ok"
    assert out["pairs"] >= 1
    text = (tmp_path / "chain_candidate_pairs.md").read_text(encoding="utf-8")
    # The two findings share state var pendingClaims → must be a STATE pair
    assert "INV-001" in text and "INV-002" in text
    assert "pendingClaims" in text


def test_candidate_pairs_excludes_provably_unrelated(tmp_path):
    cp = _cp()
    _write_state_write_map(tmp_path, "Vault", ["balances"])
    _write_inventory(tmp_path, [
        {"id": "INV-001", "severity": "High", "location": "Vault.sol:L100",
         "root_cause": "balances underflow in withdraw",
         "description": "the withdraw path corrupts balances"},
        {"id": "INV-002", "severity": "Low", "location": "Router.sol:L9000",
         "root_cause": "unrelated typo in a comment",
         "description": "cosmetic only, distinct file, distinct everything"},
    ])
    out = cp.compute_chain_candidate_pairs(tmp_path)
    # No shared state, no shared identifier, different files far apart → 0 pairs
    assert out["pairs"] == 0
    full = (tmp_path / "chain_candidate_pairs_full.md").read_text(encoding="utf-8")
    assert "INV-001 |" not in full or "INV-002" not in full.split("INV-001")[-1][:50]


def test_candidate_pairs_line_proximity(tmp_path):
    cp = _cp()
    _write_state_write_map(tmp_path, "Vault", [])
    _write_inventory(tmp_path, [
        {"id": "INV-001", "severity": "High", "location": "Vault.sol:L100-110",
         "root_cause": "issue alpha", "description": "distinct wording one"},
        {"id": "INV-002", "severity": "Low", "location": "Vault.sol:L130",
         "root_cause": "issue beta", "description": "distinct wording two"},
    ])
    out = cp.compute_chain_candidate_pairs(tmp_path)
    # L100-110 and L130 are within 60 lines → proximity pair
    assert out["pairs"] >= 1


def test_candidate_pairs_far_apart_same_file_not_paired(tmp_path):
    cp = _cp()
    _write_state_write_map(tmp_path, "Vault", [])
    _write_inventory(tmp_path, [
        {"id": "INV-001", "severity": "High", "location": "Vault.sol:L100",
         "root_cause": "issue alpha", "description": "distinct wording one"},
        {"id": "INV-002", "severity": "Low", "location": "Vault.sol:L9000",
         "root_cause": "issue beta", "description": "distinct wording two"},
    ])
    out = cp.compute_chain_candidate_pairs(tmp_path)
    # Same file but 8900 lines apart, no shared state/identifier → not a candidate
    assert out["pairs"] == 0


def test_candidate_pairs_generic_discovery_signal_does_not_pair(tmp_path):
    cp = _cp()
    _write_state_write_map(tmp_path, "Vault", [])
    _write_inventory(tmp_path, [
        {"id": "INV-001", "severity": "High", "location": "Vault.sol:L100",
         "root_cause": "issue alpha", "description": "distinct wording one",
         "discovery_steer": "arithmetic rounding terminal effect"},
        {"id": "INV-002", "severity": "Medium", "location": "Router.sol:L9000",
         "root_cause": "issue beta", "description": "distinct wording two",
         "discovery_steer": "arithmetic rounding terminal effect"},
    ])
    out = cp.compute_chain_candidate_pairs(tmp_path)
    assert out["pairs"] == 0


def test_candidate_pairs_concrete_discovery_term_pairs(tmp_path):
    cp = _cp()
    _write_state_write_map(tmp_path, "Vault", [])
    _write_inventory(tmp_path, [
        {"id": "INV-001", "severity": "High", "location": "Vault.sol:L100",
         "root_cause": "issue alpha", "description": "distinct wording one",
         "discovery_steer": "branch creates `pendingShares` mismatch"},
        {"id": "INV-002", "severity": "Medium", "location": "Router.sol:L9000",
         "root_cause": "issue beta", "description": "distinct wording two",
         "missing_precondition": "`pendingShares` already nonzero"},
    ])
    out = cp.compute_chain_candidate_pairs(tmp_path)
    assert out["pairs"] == 1
    text = (tmp_path / "chain_candidate_pairs.md").read_text(encoding="utf-8")
    assert "discovery: pendingshares" in text


def test_candidate_pairs_explicit_discovery_ref_matches_source_id_alias(tmp_path):
    cp = _cp()
    _write_state_write_map(tmp_path, "Vault", [])
    _write_inventory(tmp_path, [
        {"id": "INV-001", "source_ids": "CS-1", "severity": "High",
         "location": "Vault.sol:L100", "root_cause": "issue alpha",
         "description": "distinct wording one",
         "discovery_steer": "candidate ID CS-2 may provide missing state"},
        {"id": "INV-002", "source_ids": "CS-2", "severity": "Medium",
         "location": "Router.sol:L9000", "root_cause": "issue beta",
         "description": "distinct wording two"},
    ])
    out = cp.compute_chain_candidate_pairs(tmp_path)
    assert out["pairs"] == 1
    text = (tmp_path / "chain_candidate_pairs.md").read_text(encoding="utf-8")
    assert "discovery: explicit finding reference" in text


def test_candidate_pairs_bounded_cap_and_balance(tmp_path):
    cp = _cp()
    # 30 findings all sharing one state var → many STATE pairs
    _write_state_write_map(tmp_path, "Vault", ["sharedVar"])
    findings = [
        {"id": f"INV-{i:03d}", "severity": "Medium", "location": f"Vault.sol:L{i*5}",
         "root_cause": f"distinct rootcause sharedVar token{i}",
         "description": f"sharedVar touched here uniqueWord{i}"}
        for i in range(1, 31)
    ]
    _write_inventory(tmp_path, findings)
    out = cp.compute_chain_candidate_pairs(tmp_path)
    assert out["status"] == "ok"
    assert out["bounded"] <= cp._BOUNDED_PAIR_CAP
    # full set must be >= bounded
    assert out["pairs"] >= out["bounded"]


def test_candidate_pairs_fewer_than_two_findings(tmp_path):
    cp = _cp()
    _write_inventory(tmp_path, [
        {"id": "INV-001", "severity": "High", "location": "Vault.sol:L1",
         "root_cause": "lonely", "description": "only one finding"},
    ])
    out = cp.compute_chain_candidate_pairs(tmp_path)
    assert out["status"] == "skipped"
    assert out["pairs"] == 0


def test_candidate_pairs_fewer_than_two_replaces_stale_resume_artifacts(tmp_path):
    cp = _cp()
    _write_inventory(tmp_path, [
        {"id": "INV-001", "severity": "High", "location": "Vault.sol:L10",
         "root_cause": "sharedState write", "description": "sharedState alpha"},
        {"id": "INV-002", "severity": "Medium", "location": "Vault.sol:L20",
         "root_cause": "sharedState read", "description": "sharedState beta"},
    ])
    assert cp.compute_chain_candidate_pairs(tmp_path)["pairs"] == 1

    _write_inventory(tmp_path, [
        {"id": "INV-003", "severity": "Low", "location": "Other.sol:L1",
         "root_cause": "single finding", "description": "no pair exists"},
    ])
    out = cp.compute_chain_candidate_pairs(tmp_path)

    assert out["status"] == "skipped"
    for name in ("chain_candidate_pairs.md", "chain_candidate_pairs_full.md"):
        text = (tmp_path / name).read_text(encoding="utf-8")
        assert "INV-001" not in text and "INV-002" not in text
        assert "Total candidate pairs**: 0" in text
    payload = __import__("json").loads(
        (tmp_path / "chain_candidate_pairs_iter2.json").read_text(encoding="utf-8")
    )
    assert payload["schema_version"] == "plamen.chain_tail_manifest.v2"
    assert payload["denominator"] == 0
    assert payload["packet"] == [] and payload["overflow"] == []
    receipt = __import__("json").loads(
        (tmp_path / "chain_tail_coverage_receipt.json").read_text(encoding="utf-8")
    )
    assert receipt["status"] == "COMPLETE"
    assert "**Status**: COMPLETE" in (
        tmp_path / "chain_composition_coverage_gaps.md"
    ).read_text(encoding="utf-8")


def test_candidate_pair_failure_replaces_stale_artifacts_with_unknown(tmp_path, monkeypatch):
    cp = _cp()
    _write_inventory(tmp_path, [
        {"id": "INV-001", "severity": "High", "location": "Vault.sol:L10",
         "root_cause": "sharedState write", "description": "sharedState alpha"},
        {"id": "INV-002", "severity": "Medium", "location": "Vault.sol:L20",
         "root_cause": "sharedState read", "description": "sharedState beta"},
    ])
    assert cp.compute_chain_candidate_pairs(tmp_path)["pairs"] == 1
    monkeypatch.setattr(
        cp, "_load_state_candidates",
        lambda _scratchpad: (_ for _ in ()).throw(RuntimeError("fixture boom")),
    )

    out = cp.compute_chain_candidate_pairs(tmp_path)

    assert out["status"] == "error"
    for name in ("chain_candidate_pairs.md", "chain_candidate_pairs_full.md"):
        text = (tmp_path / name).read_text(encoding="utf-8")
        assert "**Status**: FAILED" in text
        assert "INV-001" not in text and "INV-002" not in text
    payload = __import__("json").loads(
        (tmp_path / "chain_candidate_pairs_iter2.json").read_text(encoding="utf-8")
    )
    assert payload["status"] == "FAILED_GENERATOR"
    assert cp.reconcile_chain_iter2_tail(tmp_path)["status"] == "FAILED_GENERATOR"
    assert "**Status**: FAILED_GENERATOR" in (
        tmp_path / "chain_composition_coverage_gaps.md"
    ).read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# Producer 2 — variable_finding_map
# ---------------------------------------------------------------------------


def test_variable_finding_map_basic(tmp_path):
    cp = _cp()
    _write_state_write_map(tmp_path, "Vault", ["pendingClaims", "feePercent"])
    _write_inventory(tmp_path, [
        {"id": "INV-001", "severity": "High", "location": "Vault.sol:L1",
         "root_cause": "pendingClaims deleted early",
         "description": "pendingClaims mutation"},
        {"id": "INV-002", "severity": "Medium", "location": "Vault.sol:L2",
         "root_cause": "feePercent has no upper bound",
         "description": "feePercent unchecked"},
        {"id": "INV-003", "severity": "Low", "location": "Vault.sol:L3",
         "root_cause": "feePercent retroactive on pendingClaims",
         "description": "both feePercent and pendingClaims involved"},
    ])
    out = cp.compute_variable_finding_map(tmp_path)
    assert out["status"] == "ok"
    text = (tmp_path / "variable_finding_map.md").read_text(encoding="utf-8")
    assert "pendingClaims" in text and "feePercent" in text
    # pendingClaims row should list INV-001 and INV-003
    refund_line = next(l for l in text.splitlines() if l.startswith("| pendingClaims"))
    assert "INV-001" in refund_line and "INV-003" in refund_line


def test_variable_finding_map_no_state_map_writes_header(tmp_path):
    cp = _cp()
    _write_inventory(tmp_path, [
        {"id": "INV-001", "severity": "High", "location": "Vault.sol:L1",
         "root_cause": "x", "description": "y"},
    ])
    # no state_write_map.md
    out = cp.compute_variable_finding_map(tmp_path)
    assert out["status"] == "skipped"
    assert (tmp_path / "variable_finding_map.md").exists()  # header still written


def test_variable_finding_map_falls_back_to_state_inventory(tmp_path):
    """A degraded graph bake must not discard the recon state inventory."""
    cp = _cp()
    _write_state_variables(
        tmp_path,
        [
            ("contracts/Vault.sol", "pendingClaims", "mapping(bytes32 => uint256)"),
            ("contracts/Vault.sol", "to", "address"),
        ],
    )
    with (tmp_path / "state_variables.md").open("a", encoding="utf-8") as handle:
        handle.write(
            "\n## Recon Addendum\n\n"
            "| Setter | Line | Event | Line |\n"
            "|---|---|---|---|\n"
            "| `setFee` | 32 | `FeeChanged` | 12 |\n"
        )
    _write_inventory(tmp_path, [
        {"id": "INV-001", "severity": "High", "location": "Vault.sol:L1",
         "root_cause": "pendingClaims deleted early",
         "description": "pendingClaims mutation"},
    ])

    out = cp.compute_variable_finding_map(tmp_path)

    assert out["status"] == "ok"
    assert out["state_source"] == "state_variables.md"
    text = (tmp_path / "variable_finding_map.md").read_text(encoding="utf-8")
    assert "pendingClaims" in text and "INV-001" in text
    assert "| 32 |" not in text
    assert "| to |" not in text


def test_candidate_pairs_fall_back_to_state_inventory(tmp_path):
    cp = _cp()
    _write_state_variables(
        tmp_path,
        [("src/ledger.move", "pending_claims", "Table<address, u64>")],
    )
    _write_inventory(tmp_path, [
        {"id": "INV-001", "severity": "High", "location": "ledger.move:L1",
         "root_cause": "pending_claims is cleared", "description": "first path"},
        {"id": "INV-002", "severity": "Medium", "location": "router.move:L80",
         "root_cause": "pending_claims is credited", "description": "second path"},
    ])

    out = cp.compute_chain_candidate_pairs(tmp_path)

    assert out["status"] == "ok"
    assert out["state_source"] == "state_variables.md"
    assert out["state_pairs"] == 1


def test_state_inventory_scalar_is_retained_but_addenda_does_not_leak(tmp_path):
    cp = _cp()
    _write_state_variables(tmp_path, [("src/Vault.sol", "owner", "address")])
    with (tmp_path / "state_variables.md").open("a", encoding="utf-8") as handle:
        handle.write(
            "\n## Setter Addendum\n\n"
            "| Setter | Written_Field |\n"
            "|---|---|\n"
            "| `setFee` | `fee_rate` |\n"
        )

    assert cp._parse_state_variable_inventory(tmp_path) == {
        "owner": {"src/Vault.sol"}
    }


def test_partial_write_map_unions_inventory_only_state_candidates(tmp_path):
    cp = _cp()
    _write_state_write_map(tmp_path, "Vault", ["balances"])
    _write_state_variables(
        tmp_path,
        [
            ("src/Vault.sol", "balances", "mapping(address => uint256)"),
            ("src/Vault.sol", "pendingClaims", "mapping(bytes32 => uint256)"),
        ],
    )
    _write_inventory(tmp_path, [
        {"id": "INV-001", "location": "Vault.sol:L1",
         "root_cause": "pendingClaims cleared", "description": "first"},
        {"id": "INV-002", "location": "Router.sol:L90",
         "root_cause": "pendingClaims credited", "description": "second"},
    ])

    out = cp.compute_chain_candidate_pairs(tmp_path)

    assert out["state_source"] == "state_write_map.md+state_variables.md"
    assert out["state_pairs"] == 1


def test_graph_backed_state_pair_cannot_be_displaced_by_fallback_inventory(
    tmp_path, monkeypatch
):
    """A noisy lower-confidence inventory must not consume graph pair quota."""
    cp = _cp()
    monkeypatch.setattr(cp, "_BOUNDED_PER_TABLE", 1)
    monkeypatch.setattr(cp, "_BOUNDED_PAIR_CAP", 1)
    _write_state_write_map(tmp_path, "Vault", ["graphBacked"])
    _write_state_variables(
        tmp_path,
        [
            ("src/Vault.sol", "graphBacked", "mapping(address => uint256)"),
            ("src/Vault.sol", "fallback_state", "mapping(address => uint256)"),
        ],
    )
    _write_inventory(tmp_path, [
        {"id": "INV-001", "severity": "Low", "location": "A.sol:L1",
         "root_cause": "graphBacked is cleared", "description": "first"},
        {"id": "INV-002", "severity": "Low", "location": "B.sol:L100",
         "root_cause": "graphBacked is credited", "description": "second"},
        {"id": "INV-003", "severity": "Critical", "location": "C.sol:L200",
         "root_cause": "fallback_state is cleared", "description": "third"},
        {"id": "INV-004", "severity": "Critical", "location": "D.sol:L300",
         "root_cause": "fallback_state is credited", "description": "fourth"},
    ])

    out = cp.compute_chain_candidate_pairs(tmp_path)

    assert out["status"] == "ok"
    bounded = (tmp_path / "chain_candidate_pairs.md").read_text(encoding="utf-8")
    # A Markdown write map is now an explicit compatibility tier below the
    # typed mechanical graph, while still ranking above regex inventory rows.
    assert "state-compat-map: Vault.graphBacked" in bounded
    assert "INV-001" in bounded and "INV-002" in bounded
    assert "state-fallback: src/Vault.sol::fallback_state" not in bounded


def test_full_tail_gets_bounded_iter2_packet_and_durable_overflow_gaps(
    tmp_path, monkeypatch
):
    cp = _cp()
    monkeypatch.setattr(cp, "_BOUNDED_PER_TABLE", 1)
    monkeypatch.setattr(cp, "_BOUNDED_PAIR_CAP", 1)
    monkeypatch.setattr(cp, "_ITER2_TAIL_CAP", 2)
    _write_state_write_map(tmp_path, "Vault", ["sharedVar"])
    findings = [
        {
            "id": f"INV-{i:03d}",
            "severity": ("High" if i % 2 else "Medium"),
            "location": f"F{i}.sol:L{i * 100}",
            "root_cause": f"sharedVar path {i}",
            "description": f"sharedVar effect {i}",
        }
        for i in range(1, 6)
    ]
    _write_inventory(tmp_path, findings)

    out = cp.compute_chain_candidate_pairs(tmp_path)

    assert out["pairs"] == 10
    assert out["bounded"] == 1
    assert out["iter2_tail"] == 2
    assert out["coverage_gaps"] == 7
    packet = (tmp_path / "chain_candidate_pairs_iter2.md").read_text(
        encoding="utf-8"
    )
    # The complete manifest is created before Chain Agent 2, but no Iteration-2
    # shard is armed until that primary bounded coverage is reconciled.  This
    # prevents a second model from racing the same rows.
    assert len([line for line in packet.splitlines() if line.startswith("| CP-")]) == 0
    gaps = (tmp_path / "chain_composition_coverage_gaps.md").read_text(
        encoding="utf-8"
    )
    assert "**Exact denominator**: 10" in gaps
    assert "PENDING_ANALYSIS" in gaps
    ledger = __import__("json").loads(
        (tmp_path / "chain_tail_disposition_ledger.json").read_text(encoding="utf-8")
    )
    assert len(ledger["pairs"]) == 10
    assert sum(row["initial_route"] == "CHAIN_AGENT2" for row in ledger["pairs"]) == 1
    assert sum(row["initial_route"] == "CHAIN_ITER2" for row in ledger["pairs"]) == 9
    assert ledger["active_shard"] is None
    assert all(row["disposition"] == "UNRESOLVED_COMPOSITION" for row in ledger["pairs"])


def test_iter2_tail_reconciliation_marks_consumed_and_keeps_real_gaps(tmp_path):
    cp = _cp()
    payload = {
        "schema_version": "plamen.chain_tail.v1",
        "packet": [
            {"a": "INV-001", "b": "INV-002", "signal": "state-graph: x"},
            {"a": "INV-003", "b": "INV-004", "signal": "ident: settlePath"},
        ],
        "overflow": [
            {"a": "INV-005", "b": "INV-006", "signal": "state-fallback: y"}
        ],
    }
    (tmp_path / "chain_candidate_pairs_iter2.json").write_text(
        __import__("json").dumps(payload), encoding="utf-8"
    )
    (tmp_path / "chain_iteration2.md").write_text(
        "# Chain Iteration 2 Results\n\n"
        "## Tail Pair Dispositions\n\n"
        "| Finding A | Finding B | Disposition | Evidence |\n"
        "|---|---|---|---|\n"
        "| INV-001 | INV-002 | REJECTED | compared postcondition and precondition |\n",
        encoding="utf-8",
    )

    receipt = cp.reconcile_chain_iter2_tail(tmp_path)

    assert receipt["status"] == "DEGRADED_COVERAGE_GAPS"
    assert receipt["consumed_pairs"] == 1
    assert receipt["unresolved_packet_pairs"] == 1
    gaps = (tmp_path / "chain_composition_coverage_gaps.md").read_text(
        encoding="utf-8"
    )
    assert "INV-003" in gaps and "ITER2_UNRESOLVED" in gaps
    assert "INV-005" in gaps and "UNEXAMINED_BOUNDED_LIMIT" in gaps
    assert "INV-001" not in gaps


def test_role_based_mutual_zero_pairs_different_vocabulary_halves(tmp_path):
    cp = _cp()
    findings = [
        {
            "id": "INV-001", "severity": "High", "location": "A.sol:L10",
            "root_cause": "authentication authority has no arming check",
            "description": "guarded operations can run while the authority remains unset",
            "postconditions_created": (
                "AUTH_ANCHOR_ROLE: authority remains at its default zero element "
                "while privileged operations remain reachable"
            ),
        },
        {
            "id": "INV-002", "severity": "Medium", "location": "B.sol:L900",
            "root_cause": "degenerate witness is not rejected before derivation",
            "description": "an empty witness derives a null identity and is accepted as authorization",
            "missing_precondition": (
                "DERIVED_IDENTITY_ROLE: empty input derives zero and verification accepts it"
            ),
        },
    ]
    _write_inventory(tmp_path, findings)

    # The ordinary state/identifier matcher has no common vocabulary.
    entries = cp._load_inventory(tmp_path)
    assert cp._extract_identifiers(cp._discovery_text(entries[0])).isdisjoint(
        cp._extract_identifiers(cp._discovery_text(entries[1]))
    )
    out = cp.compute_chain_candidate_pairs(tmp_path)

    assert out["pairs"] == 1
    text = (tmp_path / "chain_candidate_pairs.md").read_text(encoding="utf-8")
    assert "role: mutual-zero" in text


def test_role_based_mutual_zero_requires_both_positive_halves(tmp_path):
    cp = _cp()
    _write_inventory(tmp_path, [
        {
            "id": "INV-010", "severity": "High", "location": "X.sol:L10",
            "postconditions_created": (
                "AUTH_ANCHOR_ROLE: trust root remains empty while verification can run"
            ),
            "root_cause": "unset trust material remains operational",
            "description": "no initialization gate",
        },
        {
            "id": "INV-011", "severity": "High", "location": "Y.sol:L900",
            "missing_precondition": (
                "DERIVED_IDENTITY_ROLE: zero-length proof derives a zero identity "
                "and succeeds as a privileged authorization"
            ),
            "root_cause": "degenerate proof accepted",
            "description": "null derivation authorizes the effect",
        },
    ])
    assert cp.compute_chain_candidate_pairs(tmp_path)["pairs"] == 1


def test_role_based_mutual_zero_does_not_pair_armed_anchor(tmp_path):
    cp = _cp()
    _write_inventory(tmp_path, [
        {
            "id": "INV-020", "severity": "Medium", "location": "X.sol:L10",
            "postconditions_created": (
                "AUTH_ANCHOR_ROLE: anchor is atomically armed non-zero before "
                "verification and cannot operate until armed"
            ),
            "root_cause": "anchor is non-zero enforced",
            "description": "there is no unarmed operational state",
        },
        {
            "id": "INV-021", "severity": "Medium", "location": "Y.sol:L900",
            "missing_precondition": (
                "DERIVED_IDENTITY_ROLE: empty proof derives zero and is accepted"
            ),
            "root_cause": "sloppy input guard",
            "description": "degenerate input acceptance",
        },
    ])
    assert cp.compute_chain_candidate_pairs(tmp_path)["pairs"] == 0


def test_role_based_mutual_zero_does_not_pair_fail_closed_verifier(tmp_path):
    cp = _cp()
    _write_inventory(tmp_path, [
        {
            "id": "INV-030", "severity": "Medium", "location": "X.sol:L10",
            "postconditions_created": (
                "AUTH_ANCHOR_ROLE: authority remains default zero while calls can run"
            ),
            "root_cause": "unset authority",
            "description": "default state is reachable",
        },
        {
            "id": "INV-031", "severity": "Medium", "location": "Y.sol:L900",
            "missing_precondition": (
                "DERIVED_IDENTITY_ROLE: empty proof derives zero but the verifier "
                "rejects zero unconditionally and fails closed"
            ),
            "root_cause": "zero derivation is rejected",
            "description": "degenerate input cannot authorize anything",
        },
    ])
    assert cp.compute_chain_candidate_pairs(tmp_path)["pairs"] == 0


# ---------------------------------------------------------------------------
# Producer 3 — enabler_baseline
# ---------------------------------------------------------------------------


def test_enabler_baseline_prefills_step0a(tmp_path):
    cp = _cp()
    _write_inventory(tmp_path, [
        {"id": "INV-001", "severity": "High", "location": "Vault.sol:L100",
         "verdict": "CONFIRMED", "root_cause": "dangerous state alpha"},
        {"id": "INV-002", "severity": "Medium", "location": "Vault.sol:L200",
         "verdict": "PARTIAL", "root_cause": "dangerous state beta"},
        {"id": "INV-003", "severity": "Low", "location": "Vault.sol:L300",
         "verdict": "REFUTED", "root_cause": "not dangerous - refuted"},
    ])
    out = cp.compute_enabler_baseline(tmp_path)
    assert out["status"] == "ok"
    # CONFIRMED + PARTIAL counted; REFUTED excluded
    assert out["states"] == 2
    text = (tmp_path / "enabler_results.md").read_text(encoding="utf-8")
    assert "MECHANICAL_BASELINE_STEP0A" in text
    assert "INV-001" in text and "INV-002" in text
    assert "INV-003" not in text  # refuted not a dangerous state
    assert "STEP 0a" in text and "STEP 0b" in text


def test_enabler_baseline_no_confirmed(tmp_path):
    cp = _cp()
    _write_inventory(tmp_path, [
        {"id": "INV-001", "severity": "Low", "location": "Vault.sol:L1",
         "verdict": "REFUTED", "root_cause": "refuted"},
    ])
    out = cp.compute_enabler_baseline(tmp_path)
    assert out["status"] == "skipped"
    assert out["states"] == 0


# ---------------------------------------------------------------------------
# Degradation + idempotency
# ---------------------------------------------------------------------------


def test_all_producers_no_inventory(tmp_path):
    """No findings_inventory.md → all producers degrade, none raise."""
    cp = _cp()
    out = cp.run_chain_prep(tmp_path)
    assert out["candidate_pairs"]["status"] in ("skipped", "ok", "error")
    assert out["variable_map"]["status"] in ("skipped", "ok", "error")
    assert out["enabler_baseline"]["status"] in ("skipped", "ok", "error")
    # The key contract: no exception escaped — run_chain_prep returned a dict.
    assert isinstance(out, dict)


def test_malformed_inventory_does_not_raise(tmp_path):
    cp = _cp()
    (tmp_path / "findings_inventory.md").write_text(
        "this is not a valid inventory \x00\x01 garbage |||",
        encoding="utf-8",
    )
    out = cp.run_chain_prep(tmp_path)  # must not raise
    assert isinstance(out, dict)
    assert "candidate_pairs" in out


def test_idempotency(tmp_path):
    cp = _cp()
    _write_state_write_map(tmp_path, "Vault", ["pendingClaims"])
    _write_inventory(tmp_path, [
        {"id": "INV-001", "severity": "High", "location": "Vault.sol:L100",
         "root_cause": "pendingClaims issue", "description": "pendingClaims a"},
        {"id": "INV-002", "severity": "Medium", "location": "Vault.sol:L120",
         "root_cause": "pendingClaims issue two", "description": "pendingClaims b"},
    ])
    a = cp.run_chain_prep(tmp_path)
    pairs_a = a["candidate_pairs"]["pairs"]
    text_a = (tmp_path / "chain_candidate_pairs.md").read_text(encoding="utf-8")
    b = cp.run_chain_prep(tmp_path)
    pairs_b = b["candidate_pairs"]["pairs"]
    text_b = (tmp_path / "chain_candidate_pairs.md").read_text(encoding="utf-8")
    assert pairs_a == pairs_b
    # Body identical except the timestamp line
    def _strip_ts(t):
        return "\n".join(l for l in t.splitlines() if not l.startswith("**Generated At**"))
    assert _strip_ts(text_a) == _strip_ts(text_b)


def test_enabler_baseline_overwrites_passthrough_stub(tmp_path):
    """compute_enabler_baseline must replace the _write_chain_passthrough_outputs
    stub, not append to it."""
    cp = _cp()
    # Simulate the driver's stub write
    (tmp_path / "enabler_results.md").write_text(
        "# Enabler Results\n\n**Status**: MECHANICAL_BASELINE\n\n"
        "No new enabler paths were mechanically introduced by this scaffold.\n",
        encoding="utf-8",
    )
    _write_inventory(tmp_path, [
        {"id": "INV-001", "severity": "High", "location": "Vault.sol:L1",
         "verdict": "CONFIRMED", "root_cause": "real dangerous state"},
    ])
    cp.compute_enabler_baseline(tmp_path)
    text = (tmp_path / "enabler_results.md").read_text(encoding="utf-8")
    assert "MECHANICAL_BASELINE_STEP0A" in text
    assert "No new enabler paths were mechanically introduced" not in text


# ---------------------------------------------------------------------------
# Fix 7 Part B — CROSS-DOMAIN-DEP → STEP-0a-LC enabler harvester
# ---------------------------------------------------------------------------


def _write_depth_findings(sp: Path, name: str, body: str) -> None:
    (sp / name).write_text(body, encoding="utf-8")


def test_cross_domain_harvest_substantive_only(tmp_path):
    """Substantive [CROSS-DOMAIN-DEP: domain — detail] tags become enablers;
    bare domain-only tags and the `none` admission are skipped."""
    cp = _cp()
    _write_depth_findings(tmp_path, "depth_external_findings.md", (
        "### Finding [DX-1]\n"
        "**Location**: Bridge.sol:L42\n"
        "Analysis. [CROSS-DOMAIN-DEP: external — destination VM deserialization "
        "scheme decides whether the payload decodes]\n\n"
        "### Finding [DX-2]\n"
        "**Location**: Bridge.sol:L88\n"
        "Bare tag. [CROSS-DOMAIN-DEP: external]\n\n"
        "### Finding [DX-3]\n"
        "**Location**: Bridge.sol:L120\n"
        "In-scope. [CROSS-DOMAIN-DEP: none — fully in-scope permissionless theft]\n"
    ))
    _write_inventory(tmp_path, [
        {"id": "INV-001", "severity": "High", "location": "Bridge.sol:L42",
         "verdict": "CONFIRMED", "root_cause": "real dangerous state"},
    ])
    harv = cp._harvest_cross_domain_enablers(tmp_path, cp._load_inventory(tmp_path))
    dets = [h["detail"] for h in harv]
    assert len(harv) == 1, dets
    assert "destination VM deserialization" in harv[0]["detail"]
    assert harv[0]["finding_id"] == "DX-1"
    assert harv[0]["domain"] == "external"
    # bare + none must NOT appear
    assert all("none" != h["domain"] for h in harv)
    assert all("fully in-scope" not in h["detail"] for h in harv)


def test_cross_domain_harvest_dedup_by_locus_detail(tmp_path):
    """Identical (locus, detail) tags in two files collapse to one enabler."""
    cp = _cp()
    common = ("### Finding [DE-1]\n**Location**: X.sol:L10\n"
              "[CROSS-DOMAIN-DEP: token-flow — pooled residual provides drained funds]\n")
    _write_depth_findings(tmp_path, "depth_token_flow_findings.md", common)
    _write_depth_findings(tmp_path, "depth_edge_case_findings.md", common)
    _write_inventory(tmp_path, [
        {"id": "INV-001", "severity": "High", "location": "X.sol:L10",
         "verdict": "CONFIRMED", "root_cause": "rc"},
    ])
    harv = cp._harvest_cross_domain_enablers(tmp_path, cp._load_inventory(tmp_path))
    assert len(harv) == 1


def test_cross_domain_harvest_dedup_vs_axisgap_provenance(tmp_path):
    """A CROSS-DOMAIN-DEP tag at a locus already covered by an M2 AXISGAP
    provenance-gap candidate is not re-emitted (append-only dedup)."""
    cp = _cp()
    _write_depth_findings(tmp_path, "depth_external_findings.md", (
        "### Finding [DX-9]\n**Location**: Y.sol:L55\n"
        "[CROSS-DOMAIN-DEP: external — assumes freshness of an off-domain value]\n"
    ))
    _write_inventory(tmp_path, [
        # An AXISGAP provenance candidate at the SAME locus (Y.sol:L55).
        {"id": "INV-050", "severity": "Low", "location": "Y.sol:L55",
         "verdict": "NEEDS_VERIFICATION",
         "source_ids": "AXISGAP:AXIS-9 (multi-axis coverage meta-pass)",
         "root_cause": "provenance axis unexamined at hot function",
         "description": "provenance freshness gap"},
    ])
    entries = cp._load_inventory(tmp_path)
    assert cp._axisgap_provenance_loci(entries)  # locus is recognized
    harv = cp._harvest_cross_domain_enablers(tmp_path, entries)
    assert harv == []


def test_cross_domain_harvest_cap_40(tmp_path):
    """The harvester never emits more than _MAX_CROSS_DOMAIN_ENABLERS."""
    cp = _cp()
    blocks = []
    for i in range(60):
        blocks.append(
            f"### Finding [DX-{i}]\n**Location**: F.sol:L{i}\n"
            f"[CROSS-DOMAIN-DEP: external — distinct off-domain assumption number {i}]\n"
        )
    _write_depth_findings(tmp_path, "depth_external_findings.md", "\n".join(blocks))
    _write_inventory(tmp_path, [
        {"id": "INV-001", "severity": "High", "location": "F.sol:L1",
         "verdict": "CONFIRMED", "root_cause": "rc"},
    ])
    harv = cp._harvest_cross_domain_enablers(tmp_path, cp._load_inventory(tmp_path))
    assert len(harv) <= cp._MAX_CROSS_DOMAIN_ENABLERS == 40


def test_enabler_baseline_writes_cross_domain_table(tmp_path):
    """compute_enabler_baseline emits the CROSS-DOMAIN-DEP enabler sub-table and
    counts them; bare tags do not appear."""
    cp = _cp()
    _write_depth_findings(tmp_path, "depth_external_findings.md", (
        "### Finding [DX-1]\n**Location**: Bridge.sol:L42\n"
        "[CROSS-DOMAIN-DEP: external — destination VM deserialization scheme]\n"
        "### Finding [DX-2]\n**Location**: Bridge.sol:L88\n"
        "[CROSS-DOMAIN-DEP: external]\n"
    ))
    _write_inventory(tmp_path, [
        {"id": "INV-001", "severity": "High", "location": "Bridge.sol:L42",
         "verdict": "CONFIRMED", "root_cause": "real dangerous state"},
    ])
    out = cp.compute_enabler_baseline(tmp_path)
    assert out["status"] == "ok"
    assert out["cross_domain_enablers"] == 1
    text = (tmp_path / "enabler_results.md").read_text(encoding="utf-8")
    assert "Cross-Domain Dependency Enablers" in text
    assert "destination VM deserialization scheme" in text
    assert "DX-1" in text


# ---------------------------------------------------------------------------
# WP-D (L1-3) — public harvest_cross_domain_candidates wrapper + driver
# verify_queue promotion into findings_inventory.md
# ---------------------------------------------------------------------------


def _driver():
    sys.path.insert(0, os.path.join(os.path.dirname(__file__)))
    if "plamen_driver" in sys.modules:
        del sys.modules["plamen_driver"]
    return importlib.import_module("plamen_driver")


def test_harvest_cross_domain_candidates_public_wrapper(tmp_path):
    """The public wrapper returns the same SUBSTANTIVE CROSS-DOMAIN-DEP
    candidates as the private harvester, without requiring the caller to load
    the inventory itself first."""
    cp = _cp()
    _write_depth_findings(tmp_path, "depth_network_surface_findings.md", (
        "### Finding [DNS-1]\n**Location**: p2p/handler.go:L42\n"
        "Analysis. [CROSS-DOMAIN-DEP: external — destination wire format "
        "decides whether the payload decodes]\n\n"
        "### Finding [DNS-2]\n**Location**: p2p/handler.go:L88\n"
        "Bare tag. [CROSS-DOMAIN-DEP: external]\n"
    ))
    candidates = cp.harvest_cross_domain_candidates(tmp_path)
    assert len(candidates) == 1, candidates
    assert candidates[0]["finding_id"] == "DNS-1"
    assert candidates[0]["domain"] == "external"
    assert "destination wire format" in candidates[0]["detail"]


def test_harvest_cross_domain_candidates_wrapper_no_raise_when_no_inventory(tmp_path):
    """No findings_inventory.md on disk (L1-shaped fresh scratchpad before the
    inventory phase writes one) must not raise -- the harvester still scans
    the depth artifact glob independent of inventory content."""
    cp = _cp()
    _write_depth_findings(tmp_path, "depth_state_trace_findings.md", (
        "### Finding [DST-1]\n**Location**: state/sync.go:L10\n"
        "[CROSS-DOMAIN-DEP: storage — pruning cursor freshness assumed by "
        "the caller]\n"
    ))
    assert not (tmp_path / "findings_inventory.md").exists()
    candidates = cp.harvest_cross_domain_candidates(tmp_path)
    assert len(candidates) == 1, candidates


def test_cross_domain_candidate_lands_in_findings_inventory(tmp_path):
    """WP-D.2: an L1-shaped scratchpad with a depth file containing a real
    `[CROSS-DOMAIN-DEP: external — ...]` tag -> harvest_cross_domain_candidates
    returns NON-EMPTY AND the candidate lands in findings_inventory.md as a
    NEEDS_VERIFICATION row via the driver's verify_queue promotion bridge."""
    cp = _cp()
    _write_depth_findings(tmp_path, "depth_external_findings.md", (
        "### Finding [DX-7]\n**Location**: rpc/engine_api.go:L200\n"
        "Analysis. [CROSS-DOMAIN-DEP: external — downstream consumer decodes "
        "this payload with an unverified schema]\n"
    ))
    _write_inventory(tmp_path, [
        {"id": "INV-001", "severity": "High", "location": "rpc/engine_api.go:L5",
         "verdict": "CONFIRMED", "root_cause": "unrelated real finding"},
    ])

    candidates = cp.harvest_cross_domain_candidates(tmp_path)
    assert candidates, "expected a non-empty candidate list"

    d = _driver()
    promoted = d._promote_cross_domain_candidates_to_inventory(tmp_path)
    assert promoted, "expected at least one promoted INV id"

    inv_text = (tmp_path / "findings_inventory.md").read_text(encoding="utf-8")
    for inv_id in promoted:
        assert f"[{inv_id}]" in inv_text
    assert "NEEDS_VERIFICATION" in inv_text
    assert "downstream consumer decodes this payload" in inv_text
    # Never a hard CONFIRMED body finding for a mechanically-harvested candidate.
    assert "**Verdict**: CONFIRMED" not in inv_text.split(
        "Cross-Domain Dependency Candidates"
    )[1]


def test_cross_domain_promotion_is_noop_without_inventory(tmp_path):
    """Best-effort: no findings_inventory.md on disk -> the driver promotion
    bridge degrades to a no-op instead of raising."""
    d = _driver()
    assert d._promote_cross_domain_candidates_to_inventory(tmp_path) == []
