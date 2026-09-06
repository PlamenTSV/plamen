from __future__ import annotations

import importlib
import json
import os
import sys
from pathlib import Path


def _load(name: str):
    sys.path.insert(0, os.path.join(os.path.dirname(__file__)))
    return importlib.import_module(name)


def test_security_obligations_are_generic_feature_derived(tmp_path: Path):
    mech = _load("plamen_mechanical")
    (tmp_path / "_v2_checkpoint.json").write_text(
        json.dumps({
            "run_id": "12345678-1234-4234-9234-123456789abc",
            "config": {"pipeline": "sc", "language": "evm", "mode": "thorough"},
            "audit_snapshot": {
                "snapshot_digest": "a" * 64,
                "components": {"source_scope": {"digest": "b" * 64}},
            },
        }),
        encoding="utf-8",
    )
    (tmp_path / "_mechanical_graph.json").write_text(
        json.dumps({
            "schema_version": "plamen.mechanical-graph.v2",
            "source": "evm-source",
            "var_refs": {},
            "state_symbols": [],
            "functions": {
                "vault::swap_router_asset_amount_minout": {
                    "bare": "swap_router_asset_amount_minout", "callees": [],
                },
                "vault::failed_refund_asset_to_sender": {
                    "bare": "failed_refund_asset_to_sender", "callees": [],
                },
                "vault::wrap_native_token_transfer": {
                    "bare": "wrap_native_token_transfer", "callees": [],
                },
            },
        }),
        encoding="utf-8",
    )

    count = mech._write_security_obligations(tmp_path, "thorough")

    text = (tmp_path / "security_obligations.md").read_text(encoding="utf-8")
    assert count >= 3
    assert "swap_execution" in text
    assert "refund_revert" in text
    assert "native_wrapped_asset" in text
    assert "Acme" not in text
    assert "ground truth" not in text.lower()


def test_candidate_semantic_facets_extract_general_mechanisms(tmp_path: Path):
    mech = _load("plamen_mechanical")
    (tmp_path / "verification_queue.md").write_text(
        "| Finding ID | Severity | Title | Location |\n"
        "|---|---|---|---|\n"
        "| H-1 | High | Asset mismatch skips swap | BridgeRouter.sol:42 |\n",
        encoding="utf-8",
    )
    (tmp_path / "verify_H-1.md").write_text(
        "# Verify\n\n"
        "**Verdict**: CONFIRMED\n"
        "**Description**: decoded.outputToken does not match params.inputToken; "
        "empty swap data lets execution skip the swap and refund to an "
        "unauthenticated source sender.\n",
        encoding="utf-8",
    )

    assert mech._write_candidate_semantic_facets(tmp_path) == 1
    payload = json.loads(
        (tmp_path / "candidate_semantic_facets.json").read_text(encoding="utf-8")
    )
    facets = payload["candidates"][0]["facets"]
    assert "asset-binding-mismatch" in facets["mechanisms"]
    assert "swap-skip-or-divergence" in facets["mechanisms"]
    assert "unauthenticated-source" in facets["branch_conditions"]


def test_candidate_semantic_facets_emit_explicit_zero_envelope(tmp_path: Path):
    mech = _load("plamen_mechanical")

    assert mech._write_candidate_semantic_facets(tmp_path) == 0
    payload = json.loads(
        (tmp_path / "candidate_semantic_facets.json").read_text(encoding="utf-8")
    )
    assert payload == {
        "schema_version": "plamen.candidate_semantic_facets.v1",
        "candidate_count": 0,
        "candidates": [],
    }
    projection = (tmp_path / "candidate_semantic_facets.md").read_text(
        encoding="utf-8"
    )
    assert "Candidate Semantic Facets" in projection
    assert "0 candidates" in projection


def test_thorough_mode_mode_limited_deferred_degrades_not_halts(tmp_path: Path):
    # Fix B (haltless parity): a GENUINE Thorough mode-limit — a DEFERRED
    # disposition whose reason LEADS with the canonical `mode-limited` qualifier
    # — no longer hard-halts. It degrades to a flagged human-review row in
    # report_semantic_retention_risks.md. `issues` stays empty (haltless); the
    # candidate is still surfaced, not dropped.
    validators = _load("plamen_validators")
    (tmp_path / "config.json").write_text(
        json.dumps({"mode": "thorough"}) + "\n",
        encoding="utf-8",
    )
    (tmp_path / "report_coverage.md").write_text(
        "# Report Coverage Audit\n\n"
        "## Raw Candidate Ledger\n"
        "| Source File | Candidate ID / Label | Severity Signal | Status | Report ID / Refutation / Reason |\n"
        "|-------------|----------------------|-----------------|--------|---------------------------------|\n"
        "| verification_queue.md | H-7 | Medium | DEFERRED | mode-limited: lane did not run |\n",
        encoding="utf-8",
    )

    issues = validators._validate_report_coverage_semantic_contract(tmp_path)

    assert issues == []  # haltless: a real mode-limit degrades, never halts
    risk = tmp_path / "report_semantic_retention_risks.md"
    assert risk.exists()
    body = risk.read_text(encoding="utf-8")
    assert "THOROUGH-MODE-LIMITED" in body and "H-7" in body  # flagged, not dropped


def test_thorough_mode_honest_unresolved_deferral_is_not_mode_limit(tmp_path: Path):
    # Regression lock for the Spectra false-positive HALT. Reproduces
    # report_coverage.md row 91 exactly: the Status column is a bare `DEFERRED`,
    # the disposition token `UNRESOLVED_EVIDENCE` / `NEEDS_VERIFICATION` LEADS the
    # reason column, and `mode-limited` appears only inside a NEGATION
    # ("Not `mode-limited`"). This is an honest could-not-verify deferral carried
    # for human review — NOT a mode-limit — so it must neither halt
    # (`issues == []`) nor be mis-flagged as a THOROUGH-MODE-LIMITED retention
    # risk. Before the fix, a negation-blind substring regex matched
    # `MODE-LIMITED` inside "NOT `mode-limited`" and hard-halted the run.
    validators = _load("plamen_validators")
    (tmp_path / "config.json").write_text(
        json.dumps({"mode": "thorough"}) + "\n",
        encoding="utf-8",
    )
    (tmp_path / "report_coverage.md").write_text(
        "# Report Coverage Audit\n\n"
        "## Raw Candidate Ledger\n"
        "| Source File | Candidate ID / Label | Severity Signal | Status | Report ID / Refutation / Reason |\n"
        "|-------------|----------------------|-----------------|--------|---------------------------------|\n"
        "| report_index_coverage_seed.md | INV-245 | Medium | DEFERRED | "
        "UNRESOLVED_EVIDENCE — NEEDS_VERIFICATION; unmapped, no verify file, no "
        "facets in bounded ledgers. Not `mode-limited` (Thorough ran full "
        "pipeline) — genuinely unresolved candidates carried for human review. |\n",
        encoding="utf-8",
    )

    issues = validators._validate_report_coverage_semantic_contract(tmp_path)

    assert issues == []  # was a FALSE-POSITIVE HALT before the fix
    risk = tmp_path / "report_semantic_retention_risks.md"
    body = risk.read_text(encoding="utf-8") if risk.exists() else ""
    assert "THOROUGH-MODE-LIMITED" not in body  # honest deferral is not a mode-limit


def test_core_mode_allows_mode_limited_deferred_accounting(tmp_path: Path):
    validators = _load("plamen_validators")
    (tmp_path / "config.json").write_text(
        json.dumps({"mode": "core"}) + "\n",
        encoding="utf-8",
    )
    (tmp_path / "report_coverage.md").write_text(
        "# Report Coverage Audit\n\n"
        "## Raw Candidate Ledger\n"
        "| Source File | Candidate ID / Label | Severity Signal | Status | Report ID / Refutation / Reason |\n"
        "|-------------|----------------------|-----------------|--------|---------------------------------|\n"
        "| verification_queue.md | H-7 | Medium | DEFERRED | mode-limited: lane did not run |\n",
        encoding="utf-8",
    )

    assert validators._validate_report_coverage_semantic_contract(tmp_path) == []


def test_depth_worker_prompt_carries_perturbation_contract(tmp_path: Path):
    driver = _load("plamen_driver")
    prompt = driver._build_depth_worker_prompt(
        job={
            "output": "depth_token_flow_findings.md",
            "agent_id": "token_flow_findings",
            "role": "token_flow",
            "category": "standard",
            "focus": "token flow",
        },
        scratchpad=tmp_path,
        project_root=str(tmp_path.parent),
        config={
            "pipeline": "sc",
            "language": "evm",
            "mode": "thorough",
            "project_root": str(tmp_path.parent),
            "scratchpad": str(tmp_path),
        },
        attempt=1,
    )

    assert "Mandatory perturbation-retention contract" in prompt
    assert "### Perturbation Block - <finding_id>" in prompt
    assert "sibling functions/contracts" in prompt


def test_attention_repair_queues_missing_perturbation_blocks(tmp_path: Path):
    mech = _load("plamen_mechanical")
    (tmp_path / "recon_summary.md").write_text(
        "Router swaps tokens and handles external calls.",
        encoding="utf-8",
    )
    (tmp_path / "depth_token_flow_findings.md").write_text(
        "## Finding [DT-1]: Missing min-out check\n"
        "**Severity**: Medium\n"
        "**Verdict**: CONFIRMED\n"
        "**Description**: swap has no slippage protection.\n",
        encoding="utf-8",
    )

    items = mech._build_attention_repair_items(tmp_path, "thorough")

    assert any(i["kind"] == "missing-perturbation-block" for i in items)


def test_chain_anti_absorption_repair_splits_overmerged_groups(tmp_path: Path):
    validators = _load("plamen_validators")
    (tmp_path / "findings_inventory.md").write_text(
        "# Finding Inventory\n\n"
        "## Finding [INV-001]: Refund recipient is unauthenticated\n"
        "**Severity**: High\n"
        "**Location**: BridgeRouter.sol:L10 claimPayout()\n"
        "**Root Cause**: refund recipient is taken from untrusted calldata\n\n"
        "## Finding [INV-002]: Swap skips min-out enforcement\n"
        "**Severity**: Medium\n"
        "**Location**: BridgeRouter.sol:L20 doSwap()\n"
        "**Root Cause**: router call uses zero minAmountOut and accepts any output\n\n",
        encoding="utf-8",
    )
    (tmp_path / "hypotheses.md").write_text(
        "# Hypotheses\n\n"
        "| Hypothesis ID | Severity | Title | Source Findings |\n"
        "|---|---|---|---|\n"
        "| HH-01 | High | Gateway issues | INV-001, INV-002 |\n",
        encoding="utf-8",
    )
    (tmp_path / "finding_mapping.md").write_text(
        "| Finding ID | Hypothesis ID |\n"
        "|---|---|\n"
        "| INV-001 | HH-01 |\n"
        "| INV-002 | HH-01 |\n",
        encoding="utf-8",
    )

    before = validators._validate_chain_anti_absorption(tmp_path, "thorough")
    assert before
    repaired = validators._repair_chain_anti_absorption_splits(tmp_path)
    after = validators._validate_chain_anti_absorption(tmp_path, "thorough")

    assert repaired == 2
    assert after == []
    mapping = (tmp_path / "finding_mapping.md").read_text(encoding="utf-8")
    assert "INV-001" in mapping and "INV-002" in mapping
    assert "HH-01" in mapping  # raw composition card is preserved
    from plamen_parsers import _parse_hypothesis_constituents
    assert "HH-01" not in _parse_hypothesis_constituents(tmp_path)
    assert (tmp_path / "anti_absorption_repair.md").exists()
    assert (tmp_path / "chain_anti_absorption_applied_receipt.json").exists()
