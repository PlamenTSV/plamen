"""P0-L registry migration fixtures for pre-inventory producers.

The exact inventory reconciler treats a missing producer registration as
durable review debt.  These fixtures therefore pin the producer roster and
artifact-local ID grammars without exercising or weakening unrelated parser
grammars.  All names and IDs are generic Part-0 examples.
"""
from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import finding_producer_registry as R


_ALL_CONSUMERS = frozenset(R.REQUIRED_DELIVERY_CONSUMERS)


def _resolve(name: str) -> R.FindingProducer:
    producer = R.producer_for_artifact(name, consumer="canonical_identity")
    assert producer is not None, name
    return producer


def test_generic_breadth_sources_resolve_across_supported_ecosystems() -> None:
    # The artifact naming contract is shared by EVM, Soroban, Move/Aptos, and
    # Rust/Go L1 breadth.  Representative names ensure none stays outside the
    # exact inventory denominator merely because its ecosystem differs.
    cases = {
        "analysis_evm_token_flow.md": "TF-1",
        "analysis_soroban_auth.md": "AC-2",
        "analysis_move_resource_flow.md": "RF-3",
        "analysis_aptos_capabilities.md": "CAP-4",
        "analysis_layer_rust_consensus.md": "L1-5",
        "analysis_layer_go_network.md": "L2-6",
    }
    for artifact, finding_id in cases.items():
        producer = _resolve(artifact)
        assert producer.key == "breadth"
        assert producer.owner_phase == "breadth"
        assert producer.required_consumers == _ALL_CONSUMERS
        assert R.producer_accepts_current_local_id(producer, finding_id)
    legacy_claude = _resolve("analysis_legacy_claude.md")
    assert R.producer_accepts_current_local_id(legacy_claude, "F-01")
    assert not R.producer_accepts_current_local_id(legacy_claude, "INV-01")


def test_specific_rescan_and_per_contract_patterns_win_generic_breadth() -> None:
    rescan = _resolve("analysis_rescan_2.md")
    per_contract = _resolve("analysis_percontract_router.md")
    assert rescan.key == "rescan_and_per_contract"
    assert per_contract.key == "rescan_and_per_contract"
    assert R.producer_accepts_current_local_id(rescan, "RS2-7")
    assert R.producer_accepts_current_local_id(per_contract, "PC3-11")

    # Read compatibility remains, but these historical aliases do not replace
    # the current RS<n>-<m>/PC<n>-<m> contracts.
    assert R.producer_accepts_local_id(rescan, "RSW-8")
    assert R.producer_accepts_local_id(per_contract, "PCRE-9")


def test_rescan_current_grammar_does_not_weaken_other_producers() -> None:
    breadth = _resolve("analysis_core_state.md")
    depth = _resolve("depth_state_trace_findings.md")
    niche = _resolve("niche_signature_findings.md")

    assert not R.producer_accepts_current_local_id(breadth, "RS1-2")
    assert not R.producer_accepts_current_local_id(depth, "PC2-4")
    assert not R.producer_accepts_current_local_id(niche, "RS3-6")


def test_l1_graph_sweep_producer_roster_and_local_id_debt() -> None:
    cases = {
        "graph_sweep_summary.md": ("l1_graph_sweep", "L1-1"),
        "graph_sweep_move.md": ("l1_graph_sweep", "CI-2"),
        "coverage_fill_7.md": ("l1_coverage_fill", "L3-4"),
        "panic_audit_2.md": ("l1_panic_audit", "PANIC-5"),
        "panic_audit_summary.md": ("l1_panic_audit", "PANIC-6"),
        "symmetric_pair_findings.md": ("l1_symmetric_pair", "PAIR-7"),
        "field_validation_matrix.md": ("l1_field_validation", "FV-8"),
        "primitive_correctness_findings.md": ("l1_primitive_correctness", "PRIM-9"),
        "network_amplification_findings.md": ("l1_network_amplification", "NS-10"),
        "lifecycle_replay_findings.md": ("l1_lifecycle_replay", "LC-11"),
    }
    for artifact, (key, finding_id) in cases.items():
        producer = _resolve(artifact)
        assert producer.key == key
        assert producer.owner_phase == "graph_sweeps"
        assert producer.required_consumers == _ALL_CONSUMERS
        assert R.producer_accepts_current_local_id(producer, finding_id)

        # A malformed/foreign identity remains registry-visible debt; the
        # migration must never turn arbitrary headings into valid findings.
        assert not R.producer_accepts_local_id(producer, "UNKNOWN-ID")
        assert not R.producer_accepts_local_id(producer, "INV-001")


def test_registry_source_roster_projects_to_every_delivery_consumer() -> None:
    import plamen_parsers as P

    required = {
        "analysis_*.md",
        "graph_sweep*.md",
        "coverage_fill_*.md",
        "panic_audit_*.md",
        "panic_audit_summary.md",
        "symmetric_pair_findings.md",
        "field_validation_matrix.md",
        "primitive_correctness_findings.md",
        "network_amplification_findings.md",
        "lifecycle_replay_findings.md",
    }
    for consumer in R.REQUIRED_DELIVERY_CONSUMERS:
        assert required <= set(R.producer_patterns(consumer))
        assert set(P._INVENTORY_SOURCE_PATTERNS) <= set(
            R.producer_patterns(consumer)
        )
    assert R.validate_registry_projection_completeness() == []


def test_registered_source_with_foreign_id_stays_explicit_inventory_debt(
    tmp_path: Path,
) -> None:
    import inventory_reconciliation as I

    source = tmp_path / "analysis_evm_flow.md"
    source.write_text(
        "### Finding [INV-001]: Foreign canonical identity\n"
        "**Severity**: Medium\n"
        "**Location**: src/module.sol:L10\n"
        "**Description**: Generic candidate body.\n",
        encoding="utf-8",
    )
    sources, source_issues = I._discovery_sources(
        tmp_path,
        {"inventory_chunk_a": (source.name,)},
        phase_name=None,
    )
    assert source_issues == []
    assert sources[0]["registry_status"] == "REGISTERED"

    candidates, candidate_issues = I._source_candidates(tmp_path, sources)
    assert len(candidates) == 1
    assert candidates[0]["producer_key"] == "breadth"
    assert candidates[0]["producer_local_id_valid"] is False
    assert candidate_issues == [
        "analysis_evm_flow.md:INV-001 violates registered producer breadth "
        "local-ID grammar"
    ]


def test_registry_digest_binds_the_migrated_roster_and_grammars() -> None:
    baseline = R.registry_digest()
    breadth = R.PRODUCERS_BY_KEY["breadth"]
    changed = tuple(
        replace(
            producer,
            local_id_patterns=(*producer.local_id_patterns, r"DRIFT-\d+"),
        )
        if producer.key == breadth.key
        else producer
        for producer in R.FINDING_PRODUCERS
    )
    assert R.registry_digest(changed) != baseline


def test_equal_specificity_overlap_remains_fail_closed() -> None:
    first = R.FindingProducer(
        key="first",
        artifact_patterns=("analysis_*.md",),
        local_id_patterns=(r"A-\d+",),
        owner_phase="breadth",
        required_consumers=_ALL_CONSUMERS,
    )
    second = replace(first, key="second")
    try:
        R.producer_for_artifact(
            "analysis_overlap.md", producers=(first, second)
        )
    except R.ProducerResolutionError:
        pass
    else:
        raise AssertionError("equal-specificity producer overlap did not fail closed")
