"""P0-W: chain grouping is a lossless relation, not identity authority.

All fixtures are protocol-neutral.  They assert the monotonic contract that
uncertain equivalence can only increase independent verification obligations;
it can never collapse a base claim or erase chain-authored semantic fields.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

import plamen_driver as D
import plamen_parsers as P
import plamen_validators as V
from chain_grouping_authority import (
    load_validated_chain_grouping_relations,
    write_chain_equivalence_proposals,
)
from phase_io_contracts import resolve_phase_io_contract
from plamen_types import Phase


def _finding(
    fid: str,
    *,
    title: str,
    location: str,
    mechanism: str,
    preconditions: str,
    effect: str,
    impact: str,
    remediation: str,
    severity: str = "Medium",
) -> str:
    return (
        f"### Finding [{fid}]: {title}\n"
        f"**Severity**: {severity}\n"
        f"**Location**: {location}\n"
        f"**Root Cause**: {mechanism}\n"
        f"**Preconditions**: {preconditions}\n"
        f"**Effect**: {effect}\n"
        f"**Impact**: {impact}\n"
        f"**Recommendation**: {remediation}\n"
        f"**Evidence**: EVID-{fid}\n\n"
    )


def _seed(
    root: Path,
    findings: list[str],
    groups: list[tuple[str, list[str], str]],
    *,
    detail: str = "",
) -> None:
    (root / "findings_inventory.md").write_text(
        "# Finding Inventory\n\n" + "".join(findings), encoding="utf-8"
    )
    hypothesis_rows = [
        "# Hypotheses\n\n",
        "| Hypothesis ID | Severity | Title | Source Findings | Invariant | Preconditions | Impact | Evidence | Composition |\n",
        "|---|---|---|---|---|---|---|---|---|\n",
    ]
    mapping_rows = [
        "# Finding Mapping\n\n",
        "| Finding ID | Hypothesis ID | Mapping Status | Notes |\n",
        "|---|---|---|---|\n",
    ]
    for group_id, members, title in groups:
        hypothesis_rows.append(
            f"| {group_id} | Medium | {title} | {', '.join(members)} | "
            f"INV-{group_id} | PRE-{group_id} | IMP-{group_id} | "
            f"EVID-{group_id} | COMP-{group_id} |\n"
        )
        for member in members:
            mapping_rows.append(
                f"| {member} | {group_id} | GROUPED | original relation {member} |\n"
            )
    if detail:
        hypothesis_rows.extend(["\n", detail.rstrip(), "\n"])
    (root / "hypotheses.md").write_text("".join(hypothesis_rows), encoding="utf-8")
    (root / "finding_mapping.md").write_text("".join(mapping_rows), encoding="utf-8")


def _generic_pair(
    *,
    first_location: str = "src/Module.sol:L10 settle()",
    second_location: str = "src/Module.sol:L10 settle()",
    first_preconditions: str = "state is OPEN",
    second_preconditions: str = "state is CLOSED",
    first_remediation: str = "validate the transition guard",
    second_remediation: str = "clear the stale accounting slot",
) -> list[str]:
    return [
        _finding(
            "INV-001", title="Transition accepts a forbidden state",
            location=first_location, mechanism="guard reads the wrong state flag",
            preconditions=first_preconditions, effect="forbidden transition commits",
            impact="protected state loses integrity", remediation=first_remediation,
        ),
        _finding(
            "INV-002", title="Accounting slot survives finalization",
            location=second_location, mechanism="finalization omits slot clearing",
            preconditions=second_preconditions, effect="stale value remains reusable",
            impact="later accounting is overstated", remediation=second_remediation,
        ),
    ]


def _all_same_decision(group_id: str, members: list[str]) -> dict:
    return {
        "group_id": group_id,
        "members": members,
        "decision": "EQUIVALENT",
        "dimensions": {
            name: {"outcome": "SAME", "evidence_ids": [f"EVID-{name.upper()}"]}
            for name in (
                "mechanism", "preconditions", "effect", "impact", "remediation"
            )
        },
    }


def _relation_group(root: Path, group_id: str) -> dict:
    receipt = load_validated_chain_grouping_relations(root)
    return next(group for group in receipt["groups"] if group["group_id"] == group_id)


def test_same_function_distinct_state_transitions_stay_independent(tmp_path: Path) -> None:
    _seed(tmp_path, _generic_pair(), [("HM-01", ["INV-001", "INV-002"], "two transitions")])
    before_h = (tmp_path / "hypotheses.md").read_bytes()
    before_m = (tmp_path / "finding_mapping.md").read_bytes()

    assert V._repair_chain_anti_absorption_splits(tmp_path) == 2
    group = _relation_group(tmp_path, "HM-01")
    assert group["equivalence_status"] == "REJECTED_UNPROVEN"
    assert group["member_to_work"] == {"INV-001": "INV-001", "INV-002": "INV-002"}
    assert "HM-01" not in P._parse_hypothesis_constituents(tmp_path)
    assert (tmp_path / "hypotheses.md").read_bytes() == before_h
    assert (tmp_path / "finding_mapping.md").read_bytes() == before_m


def test_same_line_distinct_preconditions_and_impacts_stay_independent(tmp_path: Path) -> None:
    _seed(tmp_path, _generic_pair(), [("HM-02", ["INV-001", "INV-002"], "same line")])
    V._repair_chain_anti_absorption_splits(tmp_path)
    assert _relation_group(tmp_path, "HM-02")["active_identity_mode"] == "INDEPENDENT_MEMBERS"


def test_lexical_paraphrases_at_one_locus_are_only_proposals(tmp_path: Path) -> None:
    findings = _generic_pair()
    findings[1] = findings[1].replace(
        "finalization omits slot clearing", "the closing path leaves its bookkeeping cell populated"
    )
    _seed(tmp_path, findings, [("HM-03", ["INV-001", "INV-002"], "similar prose")])
    V._repair_chain_anti_absorption_splits(tmp_path)
    assert _relation_group(tmp_path, "HM-03")["equivalence_authority"] == "NONE"


def test_self_stamped_cross_function_equivalence_stays_proposal_only(tmp_path: Path) -> None:
    findings = [
        _finding(
            "INV-011", title="Mirror A omits the bound",
            location="src/A.sol:L10 executeA()", mechanism="shared helper omits bound",
            preconditions="caller selects an unbounded amount", effect="same transition commits",
            impact="same protected balance is overstated", remediation="fix shared helper",
        ),
        _finding(
            "INV-012", title="Mirror B omits the bound",
            location="src/B.sol:L20 executeB()", mechanism="shared helper omits bound",
            preconditions="caller selects an unbounded amount", effect="same transition commits",
            impact="same protected balance is overstated", remediation="fix shared helper",
        ),
    ]
    _seed(tmp_path, findings, [("HM-04", ["INV-011", "INV-012"], "mirror entrypoints")])
    write_chain_equivalence_proposals(
        tmp_path, [_all_same_decision("HM-04", ["INV-011", "INV-012"])]
    )
    assert V._repair_chain_anti_absorption_splits(tmp_path) == 2
    group = _relation_group(tmp_path, "HM-04")
    assert group["equivalence_status"] == "REJECTED_PROPOSAL_ONLY"
    assert group["active_identity_mode"] == "INDEPENDENT_MEMBERS"
    assert "HM-04" not in P._parse_hypothesis_constituents(tmp_path)
    assert V._validate_chain_anti_absorption(tmp_path, "thorough") == []


def test_same_mechanism_but_different_remediation_is_not_equivalent(tmp_path: Path) -> None:
    _seed(tmp_path, _generic_pair(), [("HM-05", ["INV-001", "INV-002"], "shared mechanism")])
    decision = _all_same_decision("HM-05", ["INV-001", "INV-002"])
    decision["dimensions"]["remediation"] = {
        "outcome": "DIFFERENT", "evidence_ids": ["EVID-FIX-DIFF"]
    }
    write_chain_equivalence_proposals(tmp_path, [decision])
    V._repair_chain_anti_absorption_splits(tmp_path)
    assert _relation_group(tmp_path, "HM-05")["equivalence_status"] == "REJECTED_DIMENSION_MISMATCH"


def test_chain_self_override_never_authorizes_equivalence(tmp_path: Path) -> None:
    _seed(
        tmp_path, _generic_pair(), [("HM-06", ["INV-001", "INV-002"], "override")],
        detail="## HM-06 details\n\nAnti-absorption override: author says these are identical\n",
    )
    assert V._validate_chain_anti_absorption(tmp_path, "thorough")
    V._repair_chain_anti_absorption_splits(tmp_path)
    group = _relation_group(tmp_path, "HM-06")
    assert group["self_authored_override_present"] is True
    assert group["equivalence_authority"] == "NONE"


def test_partial_equivalence_proof_is_rejected_and_visible_telemetry(tmp_path: Path) -> None:
    _seed(tmp_path, _generic_pair(), [("HM-07", ["INV-001", "INV-002"], "partial")])
    decision = _all_same_decision("HM-07", ["INV-001", "INV-002"])
    del decision["dimensions"]["impact"]
    write_chain_equivalence_proposals(tmp_path, [decision])
    V._repair_chain_anti_absorption_splits(tmp_path)
    group = _relation_group(tmp_path, "HM-07")
    assert group["equivalence_status"] == "REJECTED_INCOMPLETE_PROOF"
    telemetry = (tmp_path / "chain_grouping_debt.md").read_text(encoding="utf-8")
    assert "Chain Grouping Relation Telemetry" in telemetry
    assert "HM-07" in telemetry and "INDEPENDENT_MEMBERS" in telemetry
    assert "client-visible assurance limitations come only" in telemetry.lower()


def test_malformed_locus_and_missing_root_cause_never_collapse(tmp_path: Path) -> None:
    findings = _generic_pair(first_location="??", second_location="unknown")
    findings[0] = findings[0].replace(
        "**Root Cause**: guard reads the wrong state flag\n", ""
    )
    _seed(tmp_path, findings, [("HM-08", ["INV-001", "INV-002"], "unknown locus")])
    V._repair_chain_anti_absorption_splits(tmp_path)
    group = _relation_group(tmp_path, "HM-08")
    assert group["active_identity_mode"] == "INDEPENDENT_MEMBERS"
    assert group["proposal_signals"]["authority"] == "NONE"


def test_relation_only_patch_preserves_all_source_bytes_and_semantic_fields(tmp_path: Path) -> None:
    detail = (
        "## HM-09 details\n\n"
        "**Mechanism Narrative**: UNIQUE-NARRATIVE-9\n"
        "**Invariant**: UNIQUE-INVARIANT-9\n"
        "**Preconditions**: UNIQUE-PRECONDITION-9\n"
        "**Impact**: UNIQUE-IMPACT-9\n"
        "**Evidence Scope**: UNIQUE-EVIDENCE-9\n"
        "**Composition**: UNIQUE-COMPOSITION-9\n"
    )
    groups = [
        ("HM-09", ["INV-001", "INV-002"], "affected"),
        ("HM-10", ["INV-003", "INV-004"], "unaffected accepted"),
    ]
    findings = _generic_pair() + [
        _finding(
            "INV-003", title="mirror one", location="src/C.sol:L3 one()",
            mechanism="shared cause", preconditions="same pre", effect="same effect",
            impact="same impact", remediation="shared fix",
        ),
        _finding(
            "INV-004", title="mirror two", location="src/D.sol:L4 two()",
            mechanism="shared cause", preconditions="same pre", effect="same effect",
            impact="same impact", remediation="shared fix",
        ),
    ]
    _seed(tmp_path, findings, groups, detail=detail)
    write_chain_equivalence_proposals(
        tmp_path, [_all_same_decision("HM-10", ["INV-003", "INV-004"])]
    )
    before = {
        name: (tmp_path / name).read_bytes()
        for name in ("hypotheses.md", "finding_mapping.md")
    }
    V._repair_chain_anti_absorption_splits(tmp_path)
    assert before == {name: (tmp_path / name).read_bytes() for name in before}
    receipt = json.loads(
        (tmp_path / "chain_anti_absorption_applied_receipt.json").read_text(encoding="utf-8")
    )
    assert receipt["field_complete_diff"]["lost_fields"] == []
    assert receipt["field_complete_diff"]["changed_source_records"] == []
    assert receipt["pre_source_hashes"] == receipt["post_source_hashes"]
    text = (tmp_path / "hypotheses.md").read_text(encoding="utf-8")
    for marker in (
        "UNIQUE-NARRATIVE-9", "UNIQUE-INVARIANT-9", "UNIQUE-PRECONDITION-9",
        "UNIQUE-IMPACT-9", "UNIQUE-EVIDENCE-9", "UNIQUE-COMPOSITION-9",
    ):
        assert marker in text


def test_persistent_ambiguity_repairs_to_independent_work_and_gate_clears(tmp_path: Path) -> None:
    _seed(tmp_path, _generic_pair(), [("HM-11", ["INV-001", "INV-002"], "ambiguous")])
    assert V._validate_chain_anti_absorption(tmp_path, "thorough")
    assert V._repair_chain_anti_absorption_splits(tmp_path) == 2
    assert V._validate_chain_anti_absorption(tmp_path, "thorough") == []
    telemetry = (tmp_path / "chain_grouping_debt.md").read_text(encoding="utf-8")
    assert "Chain Grouping Relation Telemetry" in telemetry


def test_resume_is_byte_idempotent_and_runs_no_second_transform(tmp_path: Path) -> None:
    _seed(tmp_path, _generic_pair(), [("HM-12", ["INV-001", "INV-002"], "resume")])
    assert V._repair_chain_anti_absorption_splits(tmp_path) == 2
    names = (
        "hypotheses.md", "finding_mapping.md", "chain_grouping_relations.json",
        "chain_anti_absorption_applied_receipt.json", "chain_grouping_debt.md",
    )
    before = {name: (tmp_path / name).read_bytes() for name in names}
    assert V._repair_chain_anti_absorption_splits(tmp_path) == 0
    assert before == {name: (tmp_path / name).read_bytes() for name in names}


def test_verify_queue_keeps_one_exact_work_item_and_proof_per_member(tmp_path: Path) -> None:
    _seed(tmp_path, _generic_pair(), [("HM-13", ["INV-001", "INV-002"], "verify")])
    V._repair_chain_anti_absorption_splits(tmp_path)
    (tmp_path / "verification_queue.md").write_text(
        "| Queue # | Finding ID | Expected Output File | Severity | Title | Bug Class | Preferred Tag | Location | Primary Artifact | PoC Class |\n"
        "|---|---|---|---|---|---|---|---|---|---|\n"
        "| 1 | INV-001 | verify_INV-001.md | Medium | one | logic | CODE-TRACE | src/Module.sol | inventory | structural |\n"
        "| 2 | INV-002 | verify_INV-002.md | Medium | two | logic | CODE-TRACE | src/Module.sol | inventory | structural |\n",
        encoding="utf-8",
    )
    assert P._dedup_queue_by_hypothesis(tmp_path) == 0
    rows = P.parse_verification_queue_rows(tmp_path)
    assert [row["finding id"] for row in rows] == ["INV-001", "INV-002"]
    queue_text = (tmp_path / "verification_queue.md").read_text(encoding="utf-8")
    assert "verify_INV-001.md" in queue_text
    assert "verify_INV-002.md" in queue_text


def test_source_drift_invalidates_overlay_and_repair_rebinds(tmp_path: Path) -> None:
    _seed(tmp_path, _generic_pair(), [("HM-14", ["INV-001", "INV-002"], "drift")])
    V._repair_chain_anti_absorption_splits(tmp_path)
    with (tmp_path / "hypotheses.md").open("a", encoding="utf-8") as handle:
        handle.write("\n<!-- independent semantic source update -->\n")

    # Consumers fail closed to independent work; the gate makes the stale
    # authority visible, and the deterministic repair binds the new bytes.
    assert "HM-14" not in P._parse_hypothesis_constituents(tmp_path)
    assert V._validate_chain_anti_absorption(tmp_path, "thorough")
    assert V._repair_chain_anti_absorption_splits(tmp_path) == 2
    assert V._validate_chain_anti_absorption(tmp_path, "thorough") == []


def test_field_loss_receipt_tamper_cannot_authorize_collapse(tmp_path: Path) -> None:
    _seed(tmp_path, _generic_pair(), [("HM-15", ["INV-001", "INV-002"], "tamper")])
    V._repair_chain_anti_absorption_splits(tmp_path)
    receipt_path = tmp_path / "chain_anti_absorption_applied_receipt.json"
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt["field_complete_diff"]["lost_fields"] = ["impact"]
    receipt_path.write_text(json.dumps(receipt), encoding="utf-8")

    assert "HM-15" not in P._parse_hypothesis_constituents(tmp_path)
    assert V._validate_chain_anti_absorption(tmp_path, "thorough")
    assert V._repair_chain_anti_absorption_splits(tmp_path) == 2
    assert V._validate_chain_anti_absorption(tmp_path, "thorough") == []


def test_driver_debt_is_category_scoped_idempotent_and_non_destructive(tmp_path: Path) -> None:
    _seed(tmp_path, _generic_pair(), [("HM-16", ["INV-001", "INV-002"], "debt")])
    V._repair_chain_anti_absorption_splits(tmp_path)
    debt_path = tmp_path / "chain_grouping_debt.md"

    D._set_chain_grouping_driver_debt(
        tmp_path, "persistent unresolved", ["second issue", "first issue"]
    )
    once = debt_path.read_bytes()
    D._set_chain_grouping_driver_debt(
        tmp_path, "persistent unresolved", ["first issue", "second issue"]
    )
    assert debt_path.read_bytes() == once
    text = once.decode("utf-8")
    assert "HM-16" in text
    assert "P0-W DRIVER-DEBT PERSISTENT_UNRESOLVED START" in text

    D._set_chain_grouping_driver_debt(tmp_path, "persistent unresolved", [])
    cleared = debt_path.read_text(encoding="utf-8")
    assert "HM-16" in cleared
    assert "P0-W DRIVER-DEBT PERSISTENT_UNRESOLVED START" not in cleared


def test_chain_grouping_phase_io_binds_exact_inputs_and_all_sidecars(tmp_path: Path) -> None:
    _seed(tmp_path, _generic_pair(), [("HM-17", ["INV-001", "INV-002"], "io")])
    phase = Phase("chain", [], [], 30)
    config = {
        "pipeline": "sc",
        "mode": "thorough",
        "language": "evm",
        "cli_backend": "claude",
        "project_root": str(tmp_path.parent),
        "_run_id": "p0-w-fixture",
    }
    execute, arm_issues = D._arm_chain_grouping_relation_phase_io(
        scratchpad=tmp_path, config=config, phase=phase
    )
    assert execute is True
    assert arm_issues == []
    V._repair_chain_anti_absorption_splits(tmp_path)
    assert D._record_chain_grouping_relation_phase_io(
        scratchpad=tmp_path, config=config, phase=phase
    ) == []

    contract = resolve_phase_io_contract(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        phase="chain",
        work_unit_id="grouping_relation_repair",
        exact_inputs=(
            "findings_inventory.md", "hypotheses.md", "finding_mapping.md",
        ),
    )
    assert set(contract.immutable_inputs) == {
        "scratchpad:findings_inventory.md",
        "scratchpad:hypotheses.md",
        "scratchpad:finding_mapping.md",
    }
    assert {item.path for item in contract.outputs} == {
        "chain_grouping_relations.json",
        "chain_anti_absorption_applied_receipt.json",
        "chain_grouping_debt.md",
        "anti_absorption_repair.md",
    }
    by_path = {item.path: item for item in contract.outputs}
    assert by_path["chain_grouping_relations.json"].schema_version == (
        "plamen.chain_grouping_relations.v2"
    )
    assert by_path["chain_anti_absorption_applied_receipt.json"].schema_version == (
        "plamen.chain_anti_absorption_applied_receipt.v2"
    )


def test_registry_owned_nested_member_ids_are_not_dropped_from_denominator(
    tmp_path: Path,
) -> None:
    """P0-W must consume the canonical producer-ID grammar, not a local subset."""
    findings = [
        _finding(
            "DA-STATE_EDGE-101",
            title="first independently produced claim",
            location="src/Module.sol:L10 settle()",
            mechanism="one transition omits a state check",
            preconditions="state is OPEN",
            effect="the first transition commits",
            impact="protected state loses integrity",
            remediation="validate the first transition",
        ),
        _finding(
            "DA-STATE_EDGE-102",
            title="second independently produced claim",
            location="src/Module.sol:L20 settle()",
            mechanism="another transition omits a bound",
            preconditions="state is CLOSED",
            effect="the second transition commits",
            impact="protected accounting is overstated",
            remediation="validate the second transition",
        ),
    ]
    members = ["DA-STATE_EDGE-101", "DA-STATE_EDGE-102"]
    _seed(tmp_path, findings, [("HM-18", members, "nested producer identities")])

    assert V._repair_chain_anti_absorption_splits(tmp_path) == 2
    group = _relation_group(tmp_path, "HM-18")
    assert group["members"] == members
    assert group["member_to_work"] == {member: member for member in members}


def test_metadata_missing_member_cannot_make_raw_group_disappear(
    tmp_path: Path,
) -> None:
    """A parser miss is repair debt, never permission to shrink a group.

    The raw mapping is the grouping denominator.  Inventory metadata is useful
    proposal telemetry, but a missing row must remain independently addressable
    instead of making a two-member group look like a harmless singleton.
    """
    _seed(
        tmp_path,
        [_generic_pair()[0]],
        [("HM-19", ["INV-001", "INV-999"], "one inventory row failed to parse")],
    )

    assert V._validate_chain_anti_absorption(tmp_path, "thorough")
    assert V._repair_chain_anti_absorption_splits(tmp_path) == 2

    group = _relation_group(tmp_path, "HM-19")
    assert group["members"] == ["INV-001", "INV-999"]
    assert group["missing_inventory_members"] == ["INV-999"]
    assert group["equivalence_status"] == "REJECTED_INCOMPLETE_MEMBER_METADATA"
    assert group["member_to_work"] == {
        "INV-001": "INV-001",
        "INV-999": "INV-999",
    }
    assert "HM-19" not in P._parse_hypothesis_constituents(tmp_path)
    assert V._validate_chain_anti_absorption(tmp_path, "thorough") == []
    telemetry = (tmp_path / "chain_grouping_debt.md").read_text(encoding="utf-8")
    assert "INV-999" in telemetry and "inventory metadata missing" in telemetry
    assert "Proposal Status" in telemetry


def test_missing_relation_authority_projects_raw_group_to_independent_work(
    tmp_path: Path,
) -> None:
    """Visible debt cannot coexist with an active unproven collapse."""
    _seed(tmp_path, _generic_pair(), [("HM-20", ["INV-001", "INV-002"], "raw")])
    (tmp_path / "verification_queue.md").write_text(
        "| Queue # | Finding ID | Expected Output File | Severity | Title | Bug Class | Preferred Tag | Location | Primary Artifact | PoC Class |\n"
        "|---|---|---|---|---|---|---|---|---|---|\n"
        "| 1 | INV-001 | verify_INV-001.md | Medium | one | logic | CODE-TRACE | src/Module.sol | inventory | structural |\n"
        "| 2 | INV-002 | verify_INV-002.md | Medium | two | logic | CODE-TRACE | src/Module.sol | inventory | structural |\n",
        encoding="utf-8",
    )

    assert "HM-20" not in P._parse_hypothesis_constituents(tmp_path)
    assert V._validate_chain_anti_absorption(tmp_path, "thorough")
    assert P._dedup_queue_by_hypothesis(tmp_path) == 0
    assert [
        row["finding id"] for row in P.parse_verification_queue_rows(tmp_path)
    ] == ["INV-001", "INV-002"]


def test_invalid_relation_authority_cannot_reactivate_raw_group(
    tmp_path: Path,
) -> None:
    _seed(tmp_path, _generic_pair(), [("HM-21", ["INV-001", "INV-002"], "raw")])
    assert V._repair_chain_anti_absorption_splits(tmp_path) == 2
    relation_path = tmp_path / "chain_grouping_relations.json"
    payload = json.loads(relation_path.read_text(encoding="utf-8"))
    payload["receipt_digest"] = "0" * 64
    relation_path.write_text(json.dumps(payload), encoding="utf-8")

    assert "HM-21" not in P._parse_hypothesis_constituents(tmp_path)
    assert V._validate_chain_anti_absorption(tmp_path, "thorough")


def test_self_stamped_equivalence_cannot_collapse_typed_verifier_work(
    tmp_path: Path,
) -> None:
    """Checksums/evidence labels alone cannot mint independent authority."""
    members = ["INV-001", "INV-002"]
    _seed(tmp_path, _generic_pair(), [("HM-22", members, "proven equivalent")])
    write_chain_equivalence_proposals(
        tmp_path, [_all_same_decision("HM-22", members)]
    )
    assert V._repair_chain_anti_absorption_splits(tmp_path) == 2
    (tmp_path / "verification_queue.md").write_text(
        "| Queue # | Finding ID | Expected Output File | Severity | Title | Bug Class | Preferred Tag | Location | Primary Artifact | PoC Class |\n"
        "|---|---|---|---|---|---|---|---|---|---|\n"
        "| 1 | INV-001 | verify_INV-001.md | Medium | one | logic | CODE-TRACE | src/Module.sol:L10 | inventory | structural |\n"
        "| 2 | INV-002 | verify_INV-002.md | Medium | two | logic | CODE-TRACE | src/Module.sol:L20 | inventory | structural |\n",
        encoding="utf-8",
    )

    assert P._dedup_queue_by_hypothesis(tmp_path) == 0
    rows = P.parse_verification_queue_rows(tmp_path)
    assert [row["finding id"] for row in rows] == members


def test_unproven_group_queue_row_cannot_account_for_independent_inventory(
    tmp_path: Path,
) -> None:
    members = ["INV-001", "INV-002"]
    _seed(tmp_path, _generic_pair(), [("HM-23", members, "raw proposal")])
    assert V._repair_chain_anti_absorption_splits(tmp_path) == 2
    (tmp_path / "verification_queue.md").write_text(
        "| Queue # | Finding ID | Expected Output File | Severity | Title | Bug Class | Preferred Tag | Location | Primary Artifact | PoC Class |\n"
        "|---|---|---|---|---|---|---|---|---|---|\n"
        "| 1 | HM-23 | verify_HM-23.md | Medium | raw | logic | CODE-TRACE | src/Module.sol:L10 | inventory | structural |\n",
        encoding="utf-8",
    )

    inventory_ids, active_ids, _mapped, acknowledged = (
        V._verification_queue_parity_sets(tmp_path)
    )
    assert inventory_ids == set(members)
    assert active_ids == {"HM-23"}
    assert not (set(members) & acknowledged)


def test_v1_self_stamped_relation_is_invalidated_on_schema_cutover(
    tmp_path: Path,
) -> None:
    members = ["INV-001", "INV-002"]
    _seed(tmp_path, _generic_pair(), [("HM-24", members, "legacy")])
    write_chain_equivalence_proposals(
        tmp_path, [_all_same_decision("HM-24", members)]
    )
    V._repair_chain_anti_absorption_splits(tmp_path)
    relation_path = tmp_path / "chain_grouping_relations.json"
    relation = json.loads(relation_path.read_text(encoding="utf-8"))
    relation["schema"] = "plamen.chain_grouping_relations.v1"
    relation["receipt_digest"] = hashlib.sha256(
        json.dumps(
            {key: value for key, value in relation.items() if key != "receipt_digest"},
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()
    relation_path.write_text(
        json.dumps(relation, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    with pytest.raises(ValueError, match="schema"):
        load_validated_chain_grouping_relations(tmp_path)
