"""Fixture-first contracts for graph-off adaptive-attention source adapters."""
from __future__ import annotations

from pathlib import Path

import pytest

from adaptive_attention_sources import (
    adapt_attention_sources,
    adapt_coverage_shortfalls,
    adapt_graph_capability,
)
from adaptive_attention_types import AttentionScope


H1 = "1" * 64
H2 = "2" * 64


def _scope(*, graph_treatment: str = "legacy_off") -> AttentionScope:
    return AttentionScope.create(
        snapshot_digest=H1,
        pipeline="analysis",
        mode="core",
        ecosystem="fixture",
        phase="breadth",
        dependency_generation=0,
        phase_graph_digest=H2,
        active_phases=("breadth",),
        graph_treatment=graph_treatment,
    )


def _rows() -> list[dict]:
    return [
        {
            "provider": "component-authority",
            "kind": "COMPONENT",
            "canonical_id": "COMPONENT-ALPHA",
            "subject_ids": ["component-alpha"],
            "artifact_identity": "scratchpad:components.json",
            "artifact_sha256": H1,
            "closure_policy": "driver-evidence-closure",
            "mandatory": True,
            "impact_rank": 3,
            "role_family": "analysis",
            "methodology_family": "baseline",
            "source_class": "source",
            "proof_environment": "static",
            "required_tool_classes": ["read"],
        },
        {
            "provider": "axis-authority",
            "kind": "AXIS_CELL",
            "canonical_id": "AXIS-CELL-BETA",
            "subject_ids": ["axis-beta", "component-alpha"],
            "artifact_identity": "scratchpad:axes.json",
            "artifact_sha256": H2,
            "closure_policy": "driver-axis-closure",
            "mandatory": True,
            "impact_rank": 2,
            "role_family": "analysis",
            "methodology_family": "baseline",
            "source_class": "source",
            "proof_environment": "static",
            "required_tool_classes": ["read"],
        },
    ]


def test_source_row_reorder_is_stable_and_exact():
    left = adapt_attention_sources(scope=_scope(), rows=_rows())
    right = adapt_attention_sources(scope=_scope(), rows=reversed(_rows()))
    assert left.coverage_kind == "EXACT"
    assert left.source_digest == right.source_digest
    assert [row.obligation_id for row in left.obligations] == [
        row.obligation_id for row in right.obligations
    ]
    assert type(left).from_json(left.to_json()) == left


def test_lower_bound_shortfall_is_typed_provider_debt():
    shortfalls = adapt_coverage_shortfalls(
        scope=_scope(),
        rows=(
            {
                "receipt_id": "CS-LOWER-BOUND",
                "producer": "enumerator",
                "scope": "relations",
                "kind": "CAP_TRUNCATION",
                "count_semantics": "LOWER_BOUND",
                "omitted": 5,
                "detail": "capacity was reached",
            },
        ),
    )
    assert shortfalls.coverage_kind == "LOWER_BOUND"
    assert len(shortfalls.obligations) == 1
    debt = shortfalls.obligations[0]
    assert debt.obligation_id == "CS-LOWER-BOUND"
    assert debt.kind == "PROVIDER_DEBT"
    assert debt.state == "DEBT"
    assert debt.uncertainty_class == "UNKNOWN_DENOMINATOR"


def test_missing_graph_authority_adds_debt_without_suppressing_baseline():
    scope = _scope(graph_treatment="typed_additive")
    baseline = adapt_attention_sources(scope=_scope(), rows=_rows())
    graph = adapt_graph_capability(
        scope=scope,
        authority={
            "provider": "graph-authority",
            "available": False,
            "required": True,
            "count_semantics": "LOWER_BOUND",
            "reason_code": "MISSING_GRAPH_AUTHORITY",
            "clearing_condition": "publish a current typed graph binding",
        },
    )
    combined = adapt_attention_sources(
        scope=scope,
        rows=_rows(),
        supplemental=(graph,),
    )
    baseline_ids = {row.obligation_id for row in baseline.obligations}
    combined_ids = {row.obligation_id for row in combined.obligations}
    assert baseline_ids <= combined_ids
    assert combined.coverage_kind == "LOWER_BOUND"
    debts = [row for row in combined.obligations if row.kind == "PROVIDER_DEBT"]
    assert len(debts) == 1
    assert debts[0].state == "DEBT"
    assert debts[0].debt_reason_code == "MISSING_GRAPH_AUTHORITY"
    assert all(
        row.graph_origin == "BASELINE"
        for row in combined.obligations
        if row.obligation_id in baseline_ids
    )


def test_unavailable_optional_provider_is_still_visible_debt():
    result = adapt_attention_sources(
        scope=_scope(),
        rows=_rows(),
        provider_statuses=(
            {
                "provider": "optional-enrichment",
                "available": False,
                "required": False,
                "count_semantics": "EXACT",
                "reason_code": "MISSING_PROVIDER",
                "clearing_condition": "provider becomes current",
            },
        ),
    )
    assert any(
        row.debt_reason_code == "MISSING_PROVIDER"
        for row in result.obligations
    )


@pytest.mark.parametrize("state", ["CLOSED", "EVIDENCED", "DEBT"])
def test_source_rows_cannot_mint_controller_state(state):
    row = {**_rows()[0], "state": state}
    with pytest.raises(ValueError, match="controller-owned state"):
        adapt_attention_sources(scope=_scope(), rows=(row,))


def test_available_graph_authority_is_bound_and_inexact_graph_emits_debt():
    scope = _scope(graph_treatment="typed_additive")
    authority = {
        "schema_version": "plamen.attention_graph_authority.v1",
        "provider": "graph-authority",
        "available": True,
        "required": True,
        "supported": True,
        "stale": False,
        "count_semantics": "LOWER_BOUND",
        "binding": {
            "snapshot_digest": scope.snapshot_digest,
            "phase_graph_digest": scope.phase_graph_digest,
            "dependency_generation": scope.dependency_generation,
        },
        "row_count": 1,
        "rows": [_rows()[0]],
    }
    result = adapt_graph_capability(scope=scope, authority=authority)
    assert result.coverage_kind == "LOWER_BOUND"
    assert any(
        row.debt_reason_code == "GRAPH_DENOMINATOR_LOWER_BOUND"
        for row in result.obligations
    )
    stale = {
        **authority,
        "count_semantics": "EXACT",
        "binding": {**authority["binding"], "snapshot_digest": H2},
    }
    result = adapt_graph_capability(scope=scope, authority=stale)
    assert result.coverage_kind == "UNKNOWN"
    assert any(
        row.debt_reason_code == "STALE_GRAPH_BINDING"
        for row in result.obligations
    )


def test_invalid_graph_authority_contributes_debt_but_no_graph_work():
    scope = _scope(graph_treatment="typed_additive")
    authority = {
        "schema_version": "plamen.attention_graph_authority.v1",
        "provider": "graph-authority",
        "available": True,
        "required": True,
        "supported": True,
        "stale": False,
        "count_semantics": "EXACT",
        "binding": {
            "snapshot_digest": H2,
            "phase_graph_digest": scope.phase_graph_digest,
            "dependency_generation": scope.dependency_generation,
        },
        "row_count": 1,
        "rows": [{**_rows()[0], "canonical_id": "GRAPH-INVALID"}],
    }
    result = adapt_graph_capability(scope=scope, authority=authority)
    assert {row.kind for row in result.obligations} == {"PROVIDER_DEBT"}
    assert result.coverage_kind == "UNKNOWN"


def test_graph_authority_is_forbidden_in_graph_off_scope():
    with pytest.raises(ValueError, match="graph.*off|legacy_off"):
        adapt_graph_capability(
            scope=_scope(graph_treatment="legacy_off"),
            authority={
                "provider": "graph-authority",
                "available": False,
                "required": True,
                "count_semantics": "UNKNOWN",
                "reason_code": "MISSING_GRAPH_AUTHORITY",
                "clearing_condition": "publish graph authority",
            },
        )


def test_compiler_modules_contain_no_protocol_specific_literals():
    forbidden = (
        "ethereum",
        "solana",
        "aptos",
        "soroban",
        "cosmwasm",
        "move object",
        "smart contract",
    )
    directory = Path(__file__).resolve().parent
    for name in (
        "adaptive_attention_types.py",
        "adaptive_attention_sources.py",
        "adaptive_attention_controller.py",
    ):
        text = (directory / name).read_text(encoding="utf-8").lower()
        for token in forbidden:
            assert token not in text, f"{name} contains {token!r}"
