from __future__ import annotations

import hashlib
import json

import pytest

from l1_composition_authority import (
    L1_NEGATIVE_CLOSURE_RECEIPT_SCHEMA,
    L1CompositionError,
    enumerate_l1_composition_graph,
    normalize_l1_negative_closure_receipt,
    normalize_l1_composition_fact,
    reconcile_l1_composition_dispositions,
    validate_l1_composition_graph,
)


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _canonical_digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def _atom(kind: str, atom_id: str) -> dict[str, str]:
    return {"kind": kind, "atom_id": atom_id}


def _fact(candidate_id: str, **updates: object) -> dict[str, object]:
    row: dict[str, object] = {
        "candidate_id": candidate_id,
        "language": "GO",
        "layer": "execution",
        "subsystem": candidate_id.lower(),
        "root_cause_id": f"ROOT-{candidate_id}",
        "candidate_state": "CONFIRMED",
        "requires": [],
        "produces": [],
        "touches": [],
        "source_artifact": f"depth_{candidate_id.lower()}.json",
        "source_sha256": _sha(candidate_id),
        "producer_identity": "l1-fact-worker",
        "producer_invocation_id": f"run-{candidate_id}",
    }
    row.update(updates)
    return normalize_l1_composition_fact(row)


@pytest.mark.parametrize(
    "kind,relation",
    [
        ("STATE", "STATE_DEPENDENCY"),
        ("EVENT", "EVENT_ORDERING"),
        ("TIMING", "TIMING_ORDERING"),
        ("VALIDATION", "VALIDATION_PROPAGATION"),
        ("ACTIVATION", "ACTIVATION_ORDERING"),
        ("ROLLBACK", "ROLLBACK_REPLAY"),
        ("TRUST_BOUNDARY", "TRUST_BOUNDARY_CROSSING"),
    ],
)
def test_directional_cross_subsystem_relations_are_exact_atom_indexed(kind, relation):
    left = _fact("L1-A1", produces=[_atom(kind, "shared.atom")])
    right = _fact(
        "L1-B1",
        layer="consensus",
        requires=[_atom(kind, "shared.atom")],
    )
    graph = enumerate_l1_composition_graph([left, right], mode="thorough")
    assert graph["status"] == "READY"
    assert len(graph["edges"]) == 1
    assert graph["edges"][0]["relation"] == relation
    assert validate_l1_composition_graph(graph) == graph


def test_shared_resource_is_unordered_and_not_double_counted():
    a = _fact("L1-A1", touches=[_atom("RESOURCE", "db.writer")])
    b = _fact("L1-B1", layer="storage", touches=[_atom("RESOURCE", "db.writer")])
    graph = enumerate_l1_composition_graph([a, b], mode="core")
    assert len(graph["edges"]) == 1
    assert graph["edges"][0]["relation"] == "SHARED_RESOURCE"


def test_empty_or_incompatible_graph_is_deterministically_not_triggered():
    a = _fact("L1-A1", produces=[_atom("STATE", "state.a")])
    b = _fact("L1-B1", layer="network", requires=[_atom("STATE", "state.b")])
    graph = enumerate_l1_composition_graph([a, b], mode="core")
    assert graph["status"] == "NOT_TRIGGERED"
    assert graph["edges"] == []


def test_same_root_restatement_does_not_become_a_compound_claim():
    a = _fact("L1-A1", root_cause_id="ROOT-SHARED", produces=[_atom("STATE", "x")])
    b = _fact(
        "L1-B1",
        root_cause_id="ROOT-SHARED",
        layer="storage",
        requires=[_atom("STATE", "x")],
    )
    graph = enumerate_l1_composition_graph([a, b], mode="thorough")
    assert graph["edges"] == []
    assert graph["suppressed_relations"][0]["reason"] == "SAME_ROOT_RESTATEMENT"


def _shadow_negative_receipt(
    fact: dict[str, object], **updates: object
) -> dict[str, object]:
    row: dict[str, object] = {
        "schema_version": L1_NEGATIVE_CLOSURE_RECEIPT_SCHEMA,
        "candidate_id": fact["candidate_id"],
        "fact_digest": fact["fact_digest"],
        "source_artifact": fact["source_artifact"],
        "source_sha256": fact["source_sha256"],
        "broker_mode": "SHADOW_PROPOSAL_ONLY",
        "broker_resolution": {
            "schema_version": "plamen.closure_broker_resolution.v2",
            "status": "DEBT",
            "outcome": "NO_AUTHORITY",
            "subject_sha256": _sha(str(fact["fact_digest"])),
            "requested_effect": "REFUTED_FULL",
            "claim_resolution": "UNRESOLVED",
            "harm_resolution": "UNRESOLVED",
            "scope_resolution": "UNRESOLVED",
            "identity_resolution": "UNRESOLVED",
            "debt_reasons": ["BROKER_V2_SHADOW_PROPOSAL_ONLY"],
            "authorities": [],
            "conflicts": [],
        },
    }
    row.update(updates)
    return normalize_l1_negative_closure_receipt(row)


def test_unbacked_refuted_constituent_is_reopened_and_remains_eligible():
    a = _fact("L1-A1", candidate_state="REFUTED", produces=[_atom("STATE", "x")])
    b = _fact("L1-B1", layer="storage", requires=[_atom("STATE", "x")])
    graph = enumerate_l1_composition_graph([a, b], mode="core")
    assert len(graph["edges"]) == 1
    assert graph["suppressed_relations"] == []
    row = next(
        row
        for row in graph["negative_closure_suppression_denominator"]
        if row["candidate_id"] == "L1-A1"
    )
    assert row["eligible_for_composition"] is True
    assert row["terminal_suppression_authorized"] is False
    assert row["authority_state"] == "UNBACKED_PRODUCER_REFUTATION_REOPENED"
    assert any(
        debt["code"] == "UNBACKED_PRODUCER_REFUTATION"
        and debt["candidate_id"] == "L1-A1"
        for debt in graph["negative_closure_debt"]
    )


def test_stale_negative_closure_receipt_reopens_the_candidate():
    a = _fact("L1-A1", candidate_state="REFUTED", produces=[_atom("STATE", "x")])
    b = _fact("L1-B1", layer="storage", requires=[_atom("STATE", "x")])
    stale = _shadow_negative_receipt(a, fact_digest=_sha("superseded-fact"))

    graph = enumerate_l1_composition_graph(
        [a, b], mode="core", negative_closure_receipts=[stale]
    )

    assert len(graph["edges"]) == 1
    assert graph["negative_closure_receipt_count"] == 1
    row = next(
        row
        for row in graph["negative_closure_suppression_denominator"]
        if row["candidate_id"] == "L1-A1"
    )
    assert row["authority_state"] == "STALE_RECEIPT_REOPENED"
    assert row["eligible_for_composition"] is True
    assert any(
        debt["code"] == "STALE_NEGATIVE_CLOSURE_RECEIPT"
        for debt in graph["negative_closure_debt"]
    )


def test_malformed_negative_closure_receipt_is_visible_and_non_suppressing():
    a = _fact("L1-A1", candidate_state="REFUTED", produces=[_atom("STATE", "x")])
    b = _fact("L1-B1", layer="storage", requires=[_atom("STATE", "x")])

    graph = enumerate_l1_composition_graph(
        [a, b],
        mode="core",
        negative_closure_receipts=[
            {
                "schema_version": L1_NEGATIVE_CLOSURE_RECEIPT_SCHEMA,
                "candidate_id": "L1-A1",
                "fact_digest": a["fact_digest"],
            }
        ],
    )

    assert len(graph["edges"]) == 1
    assert graph["negative_closure_receipt_count"] == 1
    assert any(
        debt["code"] == "MALFORMED_NEGATIVE_CLOSURE_RECEIPT"
        and debt["receipt_ordinal"] == 1
        for debt in graph["negative_closure_debt"]
    )


def test_negative_closure_suppression_denominator_is_exact_and_shadow_only():
    refuted_with_shadow = _fact(
        "L1-A1", candidate_state="REFUTED", produces=[_atom("STATE", "x")]
    )
    refuted_unbacked = _fact(
        "L1-B1", candidate_state="REFUTED", layer="storage", requires=[_atom("STATE", "x")]
    )
    confirmed = _fact("L1-C1", layer="network", requires=[_atom("STATE", "x")])
    receipt = _shadow_negative_receipt(refuted_with_shadow)

    graph = enumerate_l1_composition_graph(
        [refuted_with_shadow, refuted_unbacked, confirmed],
        mode="thorough",
        negative_closure_receipts=[receipt],
    )

    denominator = graph["negative_closure_suppression_denominator"]
    assert [row["candidate_id"] for row in denominator] == [
        "L1-A1",
        "L1-B1",
        "L1-C1",
    ]
    assert all(row["eligible_for_composition"] for row in denominator)
    assert not any(row["terminal_suppression_authorized"] for row in denominator)
    assert graph["negative_closure_receipt_count"] == 1
    assert len(graph["negative_closure_receipts_digest"]) == 64
    assert len(graph["edges"]) == 2
    shadow = next(row for row in denominator if row["candidate_id"] == "L1-A1")
    assert shadow["authority_state"] == "SHADOW_RECEIPT_REOPENED"


def test_self_consistent_forged_live_resolution_cannot_suppress():
    a = _fact("L1-A1", candidate_state="REFUTED", produces=[_atom("STATE", "x")])
    b = _fact("L1-B1", layer="storage", requires=[_atom("STATE", "x")])
    forged = _shadow_negative_receipt(a)
    forged["broker_resolution"]["status"] = "AUTHORIZED"
    forged["broker_resolution"]["outcome"] = "REFUTED_FULL"
    forged["broker_resolution"]["claim_resolution"] = "REFUTED_FULL"
    unsigned = dict(forged)
    unsigned["receipt_digest"] = ""
    forged["receipt_digest"] = _canonical_digest(unsigned)

    graph = enumerate_l1_composition_graph(
        [a, b], mode="core", negative_closure_receipts=[forged]
    )

    assert len(graph["edges"]) == 1
    assert any(
        debt["code"] == "MALFORMED_NEGATIVE_CLOSURE_RECEIPT"
        and "shadow-only" in debt["detail"]
        for debt in graph["negative_closure_debt"]
    )


def test_hub_fanout_becomes_one_bounded_family_obligation():
    facts = [
        _fact("L1-A1", produces=[_atom("EVENT", "broadcast.done")]),
        *[
            _fact(
                f"L1-B{i}",
                layer="network",
                requires=[_atom("EVENT", "broadcast.done")],
            )
            for i in range(1, 8)
        ],
    ]
    graph = enumerate_l1_composition_graph(
        facts, mode="thorough", max_pair_fanout=4
    )
    assert graph["edges"] == []
    assert len(graph["family_obligations"]) == 1
    assert graph["family_obligations"][0]["reason"] == "HUB_FANOUT_BOUNDED"


def test_family_member_and_family_count_budgets_are_visible_not_unbounded():
    facts = [
        _fact("L1-A1", produces=[_atom("EVENT", "hub")]),
        *[
            _fact(f"L1-B{i}", layer="network", requires=[_atom("EVENT", "hub")])
            for i in range(1, 7)
        ],
    ]
    member_bounded = enumerate_l1_composition_graph(
        facts,
        mode="thorough",
        max_pair_fanout=2,
        max_family_members=3,
    )
    assert member_bounded["status"] == "BUDGET_DEBT"
    assert member_bounded["family_obligations"] == []
    assert member_bounded["coverage_debt"][0]["reason"] == (
        "FAMILY_PARTICIPANT_BUDGET_EXHAUSTED"
    )
    assert member_bounded["coverage_debt"][0]["participant_count"] == 7
    assert len(member_bounded["coverage_debt"][0]["participants_digest"]) == 64

    two_families = [
        _fact(
            "L1-C1",
            produces=[_atom("EVENT", "hub-a"), _atom("STATE", "hub-b")],
        ),
        *[
            _fact(
                f"L1-D{i}",
                layer="network",
                requires=[_atom("EVENT", "hub-a"), _atom("STATE", "hub-b")],
            )
            for i in range(1, 4)
        ],
    ]
    count_bounded = enumerate_l1_composition_graph(
        two_families,
        mode="core",
        max_pair_fanout=2,
        max_family_obligations=1,
    )
    assert count_bounded["status"] == "BUDGET_DEBT"
    assert len(count_bounded["family_obligations"]) == 1
    assert any(
        row["reason"] == "FAMILY_OBLIGATION_BUDGET_EXHAUSTED"
        for row in count_bounded["coverage_debt"]
    )


def test_budget_exhaustion_is_exact_visible_coverage_debt():
    producers = [
        _fact(f"L1-A{i}", produces=[_atom("STATE", "shared")])
        for i in range(1, 4)
    ]
    consumers = [
        _fact(f"L1-B{i}", layer="consensus", requires=[_atom("STATE", "shared")])
        for i in range(1, 4)
    ]
    graph = enumerate_l1_composition_graph(
        [*producers, *consumers],
        mode="thorough",
        max_pair_fanout=10,
        max_edges=2,
    )
    assert graph["status"] == "BUDGET_DEBT"
    assert len(graph["edges"]) == 2
    assert len(graph["coverage_debt"]) == 7


@pytest.mark.parametrize("language", ["GO", "RUST", "MIXED"])
def test_go_rust_and_mixed_client_facts_share_one_generic_contract(language):
    a = _fact("L1-A1", language=language, produces=[_atom("EVENT", "e")])
    b = _fact(
        "L1-B1", language=language, layer="network", requires=[_atom("EVENT", "e")]
    )
    assert enumerate_l1_composition_graph([a, b], mode="core")["status"] == "READY"


def test_light_mode_does_not_silently_enable_the_conditional_phase():
    with pytest.raises(L1CompositionError):
        enumerate_l1_composition_graph([], mode="light")


def test_fact_atom_and_disposition_cardinality_are_hard_bounded(monkeypatch):
    import l1_composition_authority as authority

    monkeypatch.setattr(authority, "MAX_ATOMS_PER_FIELD", 1)
    with pytest.raises(L1CompositionError):
        _fact(
            "L1-A1",
            produces=[_atom("STATE", "a"), _atom("STATE", "b")],
        )

    a = _fact("L1-A1", produces=[_atom("STATE", "x")])
    b = _fact("L1-B1", layer="storage", requires=[_atom("STATE", "x")])
    graph = enumerate_l1_composition_graph([a, b], mode="core")
    oid = graph["edges"][0]["obligation_id"]
    monkeypatch.setattr(authority, "MAX_L1_DISPOSITIONS", 1)
    row = {
        "obligation_id": oid,
        "disposition": "NEEDS_EVIDENCE",
        "rationale": "Bounded.",
    }
    with pytest.raises(L1CompositionError):
        reconcile_l1_composition_dispositions(graph, [row, row])


def test_exact_tail_coverage_requires_one_disposition_per_obligation():
    a = _fact("L1-A1", produces=[_atom("STATE", "x")])
    b = _fact("L1-B1", layer="storage", requires=[_atom("STATE", "x")])
    graph = enumerate_l1_composition_graph([a, b], mode="thorough")
    oid = graph["edges"][0]["obligation_id"]
    receipt = reconcile_l1_composition_dispositions(
        graph,
        [
            {
                "obligation_id": oid,
                "disposition": "NEEDS_EVIDENCE",
                "rationale": "Composition reachability requires independent verification.",
            }
        ],
    )
    assert receipt["exact_coverage"] is True
    assert receipt["missing_obligation_ids"] == []


def test_missing_duplicate_and_unexpected_dispositions_remain_visible():
    a = _fact("L1-A1", produces=[_atom("STATE", "x")])
    b = _fact("L1-B1", layer="storage", requires=[_atom("STATE", "x")])
    graph = enumerate_l1_composition_graph([a, b], mode="thorough")
    oid = graph["edges"][0]["obligation_id"]
    row = {
        "obligation_id": oid,
        "disposition": "UNREACHABLE",
        "rationale": "Independent composition analysis found no reachable ordering.",
    }
    duplicate = reconcile_l1_composition_dispositions(graph, [row, row])
    assert duplicate["exact_coverage"] is False
    assert duplicate["duplicate_obligation_ids"] == [oid]
    missing = reconcile_l1_composition_dispositions(graph, [])
    assert missing["missing_obligation_ids"] == [oid]
    unexpected = reconcile_l1_composition_dispositions(
        graph,
        [
            {
                "obligation_id": "L1CE-UNEXPECTED",
                "disposition": "INCOMPATIBLE",
                "rationale": "No shared transition exists.",
            }
        ],
    )
    assert unexpected["unexpected_obligation_ids"] == ["L1CE-UNEXPECTED"]


def test_graph_digest_rejects_resume_after_fact_or_edge_tampering():
    a = _fact("L1-A1", produces=[_atom("STATE", "x")])
    b = _fact("L1-B1", layer="storage", requires=[_atom("STATE", "x")])
    graph = enumerate_l1_composition_graph([a, b], mode="core")
    graph["edges"][0]["relation"] = "tampered"
    with pytest.raises(L1CompositionError):
        validate_l1_composition_graph(graph)
