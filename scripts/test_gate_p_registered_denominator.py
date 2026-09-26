"""Acceptance tests for Gate P's exact registered-action denominator."""
from __future__ import annotations

from pathlib import Path
import hashlib
import json

import plamen_mechanical as M
from gate_p_successor import (
    _registered_delivery_project_source_rows,
    build_gate_p_plan,
    gate_p_source_names,
)
from finding_producer_registry import (
    REGISTERED_DELIVERY_SCRATCHPAD_AUTHORITY_FILES,
)
from plamen_validators import registered_finding_delivery_projection


def _setup(root: Path) -> None:
    (root / "promotion_coverage_seed.md").write_text(
        "# Promotion Coverage Seed\n\n"
        "| Finding/Hyp ID | Expected Severity | Verdict | Mapped Hypothesis | Dedup Relation |\n"
        "|---|---|---|---|---|\n",
        encoding="utf-8",
    )
    (root / "findings_inventory.md").write_text(
        "# Finding Inventory\n",
        encoding="utf-8",
    )


def _skeptic_blocks(count: int) -> str:
    return "# Candidate Proposals\n\n" + "\n".join(
        (
            f"### Finding [ASKP-{index}]: independent candidate {index}\n"
            "**Action**: NEW\n"
            "**Severity**: Medium\n"
            f"**Location**: `src/Module.sol:L{index}`\n"
            "**Evidence Scope**: ANALYTICAL_DISAGREEMENT\n"
            "**Proof Scope**: LOW_CONFIDENCE_ANALYTICAL_CANDIDATE\n"
            f"**Source Identity**: proposal-{index}\n"
            "**Description**: A missing validation allows an inconsistent "
            f"state transition on independently assigned axis {index}.\n"
            "**Impact**: Material impact remains unresolved pending verification.\n"
        )
        for index in range(1, count + 1)
    )


def test_registered_actions_ignore_advisory_per_file_cap_and_close_delivery(
    tmp_path: Path, monkeypatch
) -> None:
    _setup(tmp_path)
    (tmp_path / "candidate_negative_skeptic_proposals.md").write_text(
        _skeptic_blocks(70), encoding="utf-8"
    )
    monkeypatch.setattr(M, "_PROMO_MAX_PER_FILE", 2)
    monkeypatch.setattr(M, "_PROMO_MAX_PER_RUN", 2)

    orphans = M.compute_promotion_orphans(tmp_path)
    exact = [row for row in orphans if row.get("registered_exact_action")]
    assert len(exact) == 70
    assert {row["orig_id"] for row in exact} == {
        f"ASKP-{index}" for index in range(1, 71)
    }

    result = M.route_promotion_orphans(tmp_path, orphans)
    assert result["emitted_to_inventory"] == 70
    delivery = registered_finding_delivery_projection(tmp_path)
    assert delivery["status"] == "CLEAN"
    assert delivery["source_action_count"] == 70
    assert delivery["accounted_action_count"] == 70


def test_registered_actions_ignore_advisory_global_cap_above_512(
    tmp_path: Path, monkeypatch
) -> None:
    _setup(tmp_path)
    (tmp_path / "candidate_negative_skeptic_proposals.md").write_text(
        _skeptic_blocks(520), encoding="utf-8"
    )
    monkeypatch.setattr(M, "_PROMO_MAX_PER_FILE", 3)
    monkeypatch.setattr(M, "_PROMO_MAX_PER_RUN", 3)

    orphans = M.compute_promotion_orphans(tmp_path)
    assert sum(bool(row.get("registered_exact_action")) for row in orphans) == 520


def test_registered_table_action_survives_without_heuristic_shape(
    tmp_path: Path, monkeypatch
) -> None:
    _setup(tmp_path)
    (tmp_path / "analysis_percontract_Module.md").write_text(
        "# Per-contract review\n\n"
        "| Candidate ID | Candidate mechanism | Harm | Prior | Disposition |\n"
        "|---|---|---|---|---|\n"
        "| PC1-1 | `src/Module.sol:L10-L20`: decoded input differs from the "
        "credited input. | Pooled value can be spent. | B1-1 | Excluded as "
        "duplicate. |\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(M, "_promo_harvest_finding_blocks", lambda *_args: [])
    monkeypatch.setattr(M, "_promo_harvest_table_rows", lambda *_args: [])
    monkeypatch.setattr(M, "_promo_harvest_excluded_stubs", lambda *_args: [])

    orphans = M.compute_promotion_orphans(tmp_path)
    candidate = next(row for row in orphans if row.get("orig_id") == "PC1-1")
    assert candidate["registered_exact_action"] is True
    assert candidate["shape"] == "registered_action_projection"
    assert candidate["shape_debt"] is True

    M.route_promotion_orphans(tmp_path, orphans)
    delivery = registered_finding_delivery_projection(tmp_path)
    assert delivery["status"] == "CLEAN"
    assert delivery["accounted_action_count"] == 1


def test_gate_p_accepts_da_contrastive_cards_and_adjacent_slug(
    tmp_path: Path,
) -> None:
    """Run86's source grammar must close inside the actual staged successor."""
    _setup(tmp_path)
    (tmp_path / "_id_ledger.json").write_text("{}\n", encoding="utf-8")
    (tmp_path / "finding_records.json").write_text("{}\n", encoding="utf-8")
    (tmp_path / "depth_da_iter2_findings.md").write_text(
        "# DA iteration 2\n\n"
        "### Finding [DA2-BLIND-A-1]: Native payout ignores false return\n\n"
        "**Verdict**: CANDIDATE\n"
        "**Severity**: Medium\n"
        "**Location**: contracts/GatewaySend.sol:L354\n"
        "**Prior Path**: Traced both token directions.\n"
        "**Untested Path**: Native input skips the inbound token transfer; "
        "the outbound token can return false without reverting.\n"
        "**Fresh Evidence**: contracts/GatewaySend.sol:L354-L385.\n"
        "**Material Harm**: The recipient receives zero tokens on a successful callback.\n\n"
        "### Finding [DA2-REFUND-REENTRANCY]: Refund record survives token call\n\n"
        "**Verdict**: CANDIDATE\n"
        "**Severity**: High\n"
        "**Location**: contracts/GatewayCrossChain.sol:L581\n"
        "**Description**: The token transfer occurs before refund record deletion.\n"
        "**Impact**: A callback token can attempt to withdraw twice.\n",
        encoding="utf-8",
    )
    payload = json.loads(build_gate_p_plan(
        tmp_path,
        run_id="run86-shape-regression",
        dimensions={
            "pipeline": "sc",
            "mode": "thorough",
            "ecosystem": "evm",
            "backend": "codex",
        },
        source_names=gate_p_source_names(tmp_path),
    ))
    assert payload["result"]["emitted_to_inventory"] == 2
    assert payload["canonical_postimages"]


def test_gate_p_captures_registered_delivery_witness_closure(
    tmp_path: Path,
) -> None:
    _setup(tmp_path)
    (tmp_path / "_id_ledger.json").write_text("{}\n", encoding="utf-8")
    (tmp_path / "finding_records.json").write_text("{}\n", encoding="utf-8")
    for name in REGISTERED_DELIVERY_SCRATCHPAD_AUTHORITY_FILES:
        (tmp_path / name).write_text("{}\n", encoding="utf-8")

    names = set(gate_p_source_names(tmp_path))
    assert set(REGISTERED_DELIVERY_SCRATCHPAD_AUTHORITY_FILES) <= names


def test_gate_p_project_closure_comes_from_active_enumgap_input_bindings(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    scratch = project / ".scratchpad"
    source = project / "contracts" / "Gateway.sol"
    source.parent.mkdir(parents=True)
    source.write_bytes(b"contract Gateway {}\n")
    scratch.mkdir()
    (scratch / "exploration_clear_obligations.json").write_text(
        "{}\n", encoding="utf-8"
    )
    owner = "sc/thorough/evm/codex/enumgap_disposition/reconcile"
    raw = source.read_bytes()
    state = {
        "artifact_bindings": {
            "scratchpad:enumgap_disposition_receipt.json": {
                "owner_key": owner,
            }
        },
        "work_units": {
            owner: {
                "input_bindings": {
                    "project:contracts/Gateway.sol": {
                        "status": "ACTIVE",
                        "sha256": hashlib.sha256(raw).hexdigest(),
                        "size": len(raw),
                    }
                }
            }
        },
    }
    (scratch / "_artifact_state.json").write_text(
        json.dumps(state), encoding="utf-8"
    )

    assert _registered_delivery_project_source_rows(scratch) == ({
        "path": "contracts/Gateway.sol",
        "sha256": hashlib.sha256(raw).hexdigest(),
        "size": len(raw),
    },)


def test_gate_p_materializes_bound_project_sources_in_product_topology(
    tmp_path: Path, monkeypatch
) -> None:
    project = tmp_path / "project"
    scratch = project / ".scratchpad"
    source = project / "contracts" / "Gateway.sol"
    source.parent.mkdir(parents=True)
    source.write_bytes(b"contract Gateway {}\n")
    scratch.mkdir()
    _setup(scratch)
    (scratch / "_id_ledger.json").write_text("{}\n", encoding="utf-8")
    (scratch / "finding_records.json").write_text("{}\n", encoding="utf-8")
    (scratch / "exploration_clear_obligations.json").write_text(
        "{}\n", encoding="utf-8"
    )
    owner = "sc/thorough/evm/codex/enumgap_disposition/reconcile"
    raw = source.read_bytes()
    (scratch / "_artifact_state.json").write_text(json.dumps({
        "artifact_bindings": {
            "scratchpad:enumgap_disposition_receipt.json": {
                "owner_key": owner,
            }
        },
        "work_units": {
            owner: {
                "input_bindings": {
                    "project:contracts/Gateway.sol": {
                        "status": "ACTIVE",
                        "sha256": hashlib.sha256(raw).hexdigest(),
                        "size": len(raw),
                    }
                }
            }
        },
    }), encoding="utf-8")

    import plamen_validators

    monkeypatch.setattr(
        plamen_validators,
        "registered_finding_delivery_projection",
        lambda _stage: {"status": "CLEAN", "residual_debt": []},
    )

    def evaluator(stage: Path) -> dict[str, int]:
        assert stage.name == ".scratchpad"
        assert (stage.parent / "contracts" / "Gateway.sol").read_bytes() == raw
        return {"emitted_to_inventory": 0}

    plan = json.loads(build_gate_p_plan(
        scratch,
        run_id="run-test",
        dimensions={
            "pipeline": "sc",
            "mode": "thorough",
            "ecosystem": "evm",
            "backend": "codex",
        },
        source_names=gate_p_source_names(scratch),
        evaluator=evaluator,
    ))
    assert plan["project_source_preimages"] == [{
        "path": "contracts/Gateway.sol",
        "sha256": hashlib.sha256(raw).hexdigest(),
        "size": len(raw),
    }]
