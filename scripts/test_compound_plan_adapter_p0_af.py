"""Strict Markdown-to-compound-plan adapter contracts for P0-AF."""
from __future__ import annotations

import json

import pytest

from compound_plan_adapter import (
    CompoundAdapterBundle,
    adapt_chain_hypotheses,
    parse_chain_hypotheses,
)
from compound_verification import AliasKind, WorkReadiness


def _section(
    chain_id: str = "CH-01",
    *,
    blocked: str = "M-01",
    enabler: str = "M-02",
    justified: str = "YES",
    impact: str = "A distinct composed loss becomes reachable.",
    severity_label: str = "Proposed Chain Severity",
    severity: str = "High",
    title: str = "ordered generic composition",
) -> str:
    return f"""### Chain Hypothesis {chain_id} — {title}

**Blocked Finding (A)**
- **ID**: {blocked}
- **Original Verdict**: PARTIAL, **Missing Precondition**: state gate is opened, **Type**: STATE

**Enabler Finding (B)**
- **ID**: {enabler}
- **Original Verdict**: CONFIRMED, **Postcondition Created**: state gate is opened, **Type**: STATE

**Chain Match**
- **Match Strength**: STRONG

**Combined Attack Sequence**
1. [B] Execute the enabler transition.
2. [A] Execute the previously blocked transition.
3. [Impact] Observe the composed consequence.

**Severity Reassessment**
- Constituents: {blocked},{enabler} | Severity-Upgrade-Justified: {justified} | Combined-Impact: {impact}
- **{severity_label}**: **{severity}**
"""


def test_strict_adapter_extracts_every_required_compound_fact() -> None:
    parsed = parse_chain_hypotheses(
        "# Chain Hypotheses\n\n" + _section(),
        pipeline="SC",
        mode="thorough",
    )
    assert not parsed.issues
    assert len(parsed.candidates) == 1
    candidate = parsed.candidates[0]
    assert candidate.chain_id == "CH-01"
    assert candidate.constituents == ("M-01", "M-02")
    assert candidate.preconditions == ("state gate is opened",)
    assert candidate.postconditions == ("state gate is opened",)
    assert candidate.proposed_severity == "High"
    assert candidate.severity_upgrade_justified
    assert [(edge.predecessor, edge.successor, edge.relation) for edge in candidate.ordering_edges] == [
        ("M-02", "M-01", "precedes"),
    ]


def test_adapter_compiles_justified_work_and_no_upgrade_alias_relation() -> None:
    text = (
        "# Chain Hypotheses\n\n"
        + _section()
        + "\n---\n\n"
        + _section(
            "CH-02",
            blocked="L-01",
            enabler="L-02",
            justified="NO",
            impact="NONE",
            severity="Low",
        )
    )
    bundle = adapt_chain_hypotheses(
        text,
        {"M-01", "M-02", "L-01", "L-02"},
        pipeline="SC",
        mode="core",
    )
    assert isinstance(bundle, CompoundAdapterBundle)
    assert [item.subject_id for item in bundle.work_plan.work_items] == ["CH-01"]
    assert [alias.alias_id for alias in bundle.work_plan.alias_relations] == ["CH-02"]
    assert bundle.work_plan.alias_relations[0].kind is AliasKind.RESTATEMENT
    assert bundle.candidates_digest
    assert bundle.work_plan_payload_digest

    candidates_payload = json.loads(bundle.compound_candidates_json)
    plan_payload = json.loads(bundle.compound_work_plan_json)
    assert candidates_payload["payload_digest"] == bundle.candidates_digest
    assert plan_payload["payload_digest"] == bundle.work_plan_payload_digest
    assert plan_payload["compound_work_plan_digest"] == bundle.work_plan.digest


def test_iteration_two_merged_sections_are_parsed_as_independent_boundaries() -> None:
    text = (
        "# Chain Hypotheses\n\n"
        + _section()
        + "\n## Iteration 2 Deterministic Merge\n\n"
        + _section(
            "CH-09",
            blocked="M-09",
            enabler="M-10",
            title="iteration-two addition",
        )
        + "\n## Tail Pair Dispositions\n\n| A | B | Result |\n|---|---|---|\n"
    )
    parsed = parse_chain_hypotheses(text, pipeline="SC", mode="thorough")
    assert not parsed.issues
    assert [candidate.chain_id for candidate in parsed.candidates] == ["CH-01", "CH-09"]


def test_duplicate_chain_ids_remain_visible_to_compiler() -> None:
    text = _section() + "\n---\n\n" + _section(
        blocked="M-03", enabler="M-04", impact="A different composed consequence."
    )
    bundle = adapt_chain_hypotheses(
        text,
        {"M-01", "M-02", "M-03", "M-04"},
        pipeline="SC",
        mode="core",
    )
    assert len(bundle.parse_result.candidates) == 2
    assert not bundle.work_plan.work_items
    assert len(bundle.work_plan.blocked_candidates) == 2
    assert any(issue.code == "DUPLICATE_CHAIN_ID" for issue in bundle.work_plan.issues)


def test_missing_active_queue_constituent_is_blocked_not_dropped() -> None:
    bundle = adapt_chain_hypotheses(
        _section(),
        {"M-01"},
        pipeline="SC",
        mode="core",
    )
    assert len(bundle.work_plan.work_items) == 1
    work = bundle.work_plan.work_items[0]
    assert work.readiness is WorkReadiness.BLOCKED_MISSING_CONSTITUENT
    assert work.missing_constituents == ("M-02",)
    assert any(issue.code == "MISSING_CONSTITUENT" for issue in bundle.work_plan.issues)


def test_machine_constituents_must_match_explicit_blocked_and_enabler_roles() -> None:
    parsed = parse_chain_hypotheses(
        _section().replace("Constituents: M-01,M-02", "Constituents: M-02,M-01"),
        pipeline="SC",
        mode="core",
    )
    assert not parsed.candidates
    assert any(issue.code == "CONSTITUENT_ROLE_MISMATCH" for issue in parsed.issues)


@pytest.mark.parametrize(
    ("needle", "replacement", "issue_code"),
    [
        ("**Missing Precondition**: state gate is opened", "**Other Field**: unavailable", "MISSING_BLOCKED_PRECONDITION"),
        ("**Postcondition Created**: state gate is opened", "**Other Field**: unavailable", "MISSING_ENABLER_POSTCONDITION"),
        ("**ID**: M-01", "**Other Field**: M-01", "MISSING_BLOCKED_IDENTITY"),
        ("**ID**: M-02", "**Other Field**: M-02", "MISSING_ENABLER_IDENTITY"),
        ("1. [B] Execute the enabler transition.", "1. Execute an unlabeled transition.", "INVALID_SEQUENCE_ORDERING"),
        ("**Proposed Chain Severity**: **High**", "**Severity Note**: High", "MISSING_PROPOSED_CHAIN_SEVERITY"),
        ("Constituents: M-01,M-02", "Members: M-01,M-02", "MISSING_MACHINE_LINE"),
    ],
)
def test_missing_required_fields_become_typed_debt(
    needle: str, replacement: str, issue_code: str
) -> None:
    parsed = parse_chain_hypotheses(
        _section().replace(needle, replacement),
        pipeline="SC",
        mode="core",
    )
    assert not parsed.candidates
    issue = next(issue for issue in parsed.issues if issue.code == issue_code)
    assert issue.subject_id == "CH-01"
    assert issue.section_digest
    assert issue.start_line <= issue.end_line


def test_ambiguous_required_field_is_debt_not_first_match_wins() -> None:
    text = _section().replace(
        "- **Original Verdict**: PARTIAL, **Missing Precondition**: state gate is opened, **Type**: STATE",
        "- **Missing Precondition**: first value\n- **Missing Precondition**: second value",
    )
    parsed = parse_chain_hypotheses(text, pipeline="SC", mode="core")
    assert not parsed.candidates
    assert any(issue.code == "AMBIGUOUS_BLOCKED_PRECONDITION" for issue in parsed.issues)


def test_pipes_unicode_windows_paths_and_chain_severity_alias_are_lossless() -> None:
    impact = r"Δ consequence at C:\repo\src\State.sol | branch A||B remains distinct 雪"
    parsed = parse_chain_hypotheses(
        _section(
            impact=impact,
            severity_label="Chain Severity",
            title=r"Unicode 雪 and C:\repo\src\State.sol",
        ),
        pipeline="SC",
        mode="core",
        source_artifact=r"C:\audit\scratchpad\chain_hypotheses.md",
    )
    assert not parsed.issues
    assert parsed.candidates[0].combined_impact_claim == impact
    assert r"C:\audit\scratchpad\chain_hypotheses.md" in parsed.candidates[0].source_lineage[0]


def test_malformed_chain_heading_is_explicit_debt() -> None:
    text = _section().replace("### Chain Hypothesis CH-01", "Chain Hypothesis CH-01", 1)
    parsed = parse_chain_hypotheses(text, pipeline="SC", mode="core")
    assert not parsed.candidates
    assert any(issue.code == "MALFORMED_CHAIN_HEADING" for issue in parsed.issues)


def test_adapter_payloads_are_deterministic_and_line_ending_idempotent() -> None:
    text = "# Chain Hypotheses\n\n" + _section()
    first = adapt_chain_hypotheses(
        text,
        ["M-02", "M-01"],
        pipeline="SC",
        mode="core",
    )
    second = adapt_chain_hypotheses(
        text.replace("\n", "\r\n"),
        ["M-01", "M-02"],
        pipeline="SC",
        mode="core",
    )
    assert first.compound_candidates_json == second.compound_candidates_json
    assert first.compound_work_plan_json == second.compound_work_plan_json
    assert first.candidates_digest == second.candidates_digest
    assert first.work_plan_payload_digest == second.work_plan_payload_digest
