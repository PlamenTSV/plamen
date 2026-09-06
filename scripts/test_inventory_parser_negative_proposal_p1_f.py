"""NC-1: tolerant inventory parsing must not mint negative authority."""
from __future__ import annotations

import textwrap

from candidate_negative_authority import ArtifactInput, build_candidate_negative_ledger
from plamen_parsers import (
    _parse_chunk_heading_inventory,
    _parse_chunk_table_inventory,
)


def _one_heading(fields: str) -> dict[str, object]:
    rows = _parse_chunk_heading_inventory(
        "### Finding [TF-1]: Candidate\n\n" + textwrap.dedent(fields)
    )
    assert len(rows) == 1
    return rows[0]


def test_inventory_parser_refuted_marker_preserves_severity():
    row = _one_heading(
        """
        **Severity**: Medium
        **Verdict**: REFUTED after source review
        **Location**: src/Vault.sol:L7
        """
    )
    assert row["severity"] == "Medium"
    assert row["verdict"] == ""
    assert row["negative_proposal"] == "REFUTATION_PROPOSAL"
    assert row["negative_proposal_conflict"] is False
    assert row["negative_proposals"] == [
        {
            "field": "verdict",
            "raw": "REFUTED after source review",
            "proposed_disposition": "REFUTATION_PROPOSAL",
        }
    ]


def test_inventory_parser_false_positive_marker_is_proposal_only():
    row = _one_heading(
        """
        **Severity**: false positive
        **Location**: src/Vault.sol:L8
        """
    )
    assert row["severity"] == ""
    assert row["verdict"] == ""
    assert row["negative_proposal"] == "REFUTATION_PROPOSAL"


def test_inventory_parser_negated_and_quoted_history_never_demotes():
    negated = _one_heading(
        """
        **Severity**: High
        **Verdict**: not REFUTED; CONFIRMED after execution
        """
    )
    history = _one_heading(
        """
        **Severity**: High
        **Verdict**: Earlier draft said "REFUTED"; final verdict CONFIRMED
        """
    )
    for row in (negated, history):
        assert row["severity"] == "High"
        assert row["negative_proposal"] == ""
        assert row["negative_proposals"] == []
        assert row["negative_proposal_conflict"] is False


def test_inventory_parser_conflicting_negative_fields_become_debt():
    row = _one_heading(
        """
        **Severity**: REFUTED
        **Verdict**: NOT APPLICABLE
        **Location**: src/Vault.sol:L9
        """
    )
    assert row["severity"] == ""
    assert row["verdict"] == ""
    assert row["negative_proposal"] == "CONFLICT_DEBT"
    assert row["negative_proposal_conflict"] is True
    assert {item["proposed_disposition"] for item in row["negative_proposals"]} == {
        "REFUTATION_PROPOSAL",
        "NOT_APPLICABLE_PROPOSAL",
    }


def test_table_parser_negative_fields_are_proposals_and_preserve_severity():
    rows = _parse_chunk_table_inventory(
        textwrap.dedent(
            """
            | ID | Severity | Title | Location | Verdict |
            |---|---|---|---|---|
            | TF-1 | Medium | Candidate | src/Vault.sol:L7 | REFUTED |
            | TF-2 | false positive | Candidate two | src/Vault.sol:L8 | |
            """
        )
    )
    assert len(rows) == 2
    assert rows[0]["severity"] == "Medium"
    assert rows[0]["verdict"] == ""
    assert rows[0]["negative_proposal"] == "REFUTATION_PROPOSAL"
    assert rows[1]["severity"] == ""
    assert rows[1]["negative_proposal"] == "REFUTATION_PROPOSAL"


def test_severity_negative_is_harvested_as_candidate_proposal(tmp_path):
    methodology = tmp_path / "methodology.md"
    methodology.write_text("# Generic methodology\n", encoding="utf-8")
    artifact = ArtifactInput(
        relative_path="analysis_test.md",
        content=(
            "### Finding [TF-1]: Candidate\n"
            "**Severity**: REFUTED\n"
            "**Location**: src/Vault.sol:L7\n"
        ).encode("utf-8"),
        producer_identity="breadth:test",
        producer_invocation_id="invocation-1",
    )
    ledger = build_candidate_negative_ledger(
        phase="breadth",
        artifacts=[artifact],
        methodology_path=methodology,
    )
    assert len(ledger["events"]) == 1
    assert ledger["events"][0]["legacy_disposition"] == "REFUTED"
    assert ledger["events"][0]["proposed_disposition"] == "REFUTATION_PROPOSAL"
