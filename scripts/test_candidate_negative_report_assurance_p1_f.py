from __future__ import annotations

import hashlib
from pathlib import Path

import assurance_limitations as L
import candidate_negative_authority as N
from finding_producer_registry import (
    CANDIDATE_NEGATIVE_SKEPTIC_PROJECTION,
    write_application_skeptic_proposal_projection,
)


def _assessment(item: dict[str, object]) -> dict[str, object]:
    evidence = "src/Vault.sol:L9 exact independent trace"
    return {
        "work_item_id": item["work_item_id"],
        "assessor_id": "INDEPENDENT",
        "assessor_invocation_id": "INDEPENDENT-RUN",
        "outcome": "AGREE_NEGATIVE",
        "evidence_basis": "IN_SCOPE_SOURCE",
        "evidence": evidence,
        "evidence_sha256": hashlib.sha256(evidence.encode()).hexdigest(),
        "rationale": "independent candidate-level assessment",
        "candidate": None,
    }


def _state(tmp_path: Path, *, explicit: bool) -> tuple[dict, dict, dict, dict]:
    method = tmp_path / "method.md"
    method.write_text("# exact method\n", encoding="utf-8")
    heading = "Finding [NEG-1]: candidate" if explicit else "Candidate without ID"
    commitment = (
        "**Invariant Commitment**: CI:CI-1\n\n"
        "committed-invariant [CI-1]\n"
        "Locus: src/Vault.sol:L9\n"
        "Shape: FRESHNESS\n"
        "Assertion: the observed state is current at use\n"
        "Falsify Class: property\n"
        "Provenance: depth REFUTATION_PROPOSAL @ NEG-1\n"
        if explicit
        else ""
    )
    ledger = N.build_candidate_negative_ledger(
        phase="depth",
        artifacts=[
            N.ArtifactInput(
                "depth_worker.md",
                (
                    f"### {heading}\n**Verdict**: REFUTED\n"
                    "**Evidence**: src/Vault.sol:L9\n"
                    + commitment
                ).encode(),
                "PRODUCER",
                "PRODUCER-RUN",
            )
        ],
        methodology_path=method,
    )
    N.write_candidate_negative_ledger(tmp_path, ledger)
    plan = N.build_candidate_negative_application_plan(
        tmp_path, phases=("depth",), max_items_per_shard=4
    )
    N.write_candidate_negative_application_plan(tmp_path, plan)
    delivered: list[dict[str, object]] = []
    receipt = N.adjudicate_candidate_negative(
        plan,
        [_assessment(plan["work_items"][0])],
        candidate_sink=delivered.append,
    )
    projection = tmp_path / CANDIDATE_NEGATIVE_SKEPTIC_PROJECTION
    write_application_skeptic_proposal_projection(
        tmp_path,
        delivered,
        projection_name=CANDIDATE_NEGATIVE_SKEPTIC_PROJECTION,
    )
    denominator = N.validate_candidate_negative_denominator(
        ledgers=[ledger],
        plan=plan,
        receipt=receipt,
        projection_path=projection,
    )
    (tmp_path / "candidate_negative_skeptic_receipt.json").write_text(
        __import__("json").dumps(receipt, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    N.write_candidate_negative_denominator(tmp_path, denominator)
    return ledger, plan, receipt, denominator


def test_unresolved_identity_reopens_additively_and_source_debt_stays_visible(
    tmp_path: Path,
) -> None:
    _ledger, _plan, receipt, denominator = _state(tmp_path, explicit=False)
    assert denominator["human_review_count"] == 0
    assert denominator["reopened_candidate_count"] == 1
    assert receipt["work_dispositions"][0]["reason_code"] == (
        "CANDIDATE_IDENTITY_UNRESOLVED"
    )
    rows = L._candidate_negative_assurance_rows(tmp_path)
    assert len(rows) == 1
    assert rows[0]["assurance_impact"] == L.DISCOVERY_RECALL
    inputs = set(L.assurance_projection_input_paths(tmp_path))
    assert {
        "candidate_negative_proposals_depth.json",
        "candidate_negative_skeptic_work_plan.json",
        "candidate_negative_skeptic_receipt.json",
        "candidate_negative_denominator.json",
    }.issubset(inputs)


def test_delivered_reopened_candidate_adds_no_assurance_noise(
    tmp_path: Path,
) -> None:
    _ledger, _plan, _receipt, denominator = _state(tmp_path, explicit=True)
    assert denominator["supported_exclusion_count"] == 0
    assert denominator["reopened_candidate_count"] == 1
    assert L._candidate_negative_assurance_rows(tmp_path) == ()


def test_missing_denominator_is_visible_not_treated_as_empty(tmp_path: Path) -> None:
    ledger, _plan, _receipt, _denominator = _state(tmp_path, explicit=True)
    (tmp_path / "candidate_negative_denominator.json").unlink()
    rows = L._candidate_negative_assurance_rows(tmp_path)
    assert len(rows) == 1
    assert rows[0]["gate_id"] == "candidate_negative_denominator_invalid"
    assert rows[0]["affected_identities"] == [ledger["events"][0]["event_id"]]


def test_missing_expected_phase_ledger_survives_into_assurance(tmp_path: Path) -> None:
    plan = N.build_candidate_negative_application_plan(
        tmp_path, phases=("depth",), max_items_per_shard=4
    )
    N.write_candidate_negative_application_plan(tmp_path, plan)
    receipt = N.adjudicate_candidate_negative(plan, [])
    (tmp_path / "candidate_negative_skeptic_receipt.json").write_text(
        __import__("json").dumps(receipt, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    denominator = N.validate_candidate_negative_denominator(
        ledgers=[], plan=plan, receipt=receipt
    )
    N.write_candidate_negative_denominator(tmp_path, denominator)
    assert denominator["status"] == "INPUT_DEBT"
    assert any("MISSING_CANDIDATE_NEGATIVE_LEDGER" in issue for issue in denominator["issues"])
    rows = L._candidate_negative_assurance_rows(tmp_path)
    assert len(rows) == 1
    assert rows[0]["gate_id"] == "candidate_negative_denominator_invalid"


def _reopened_state(tmp_path: Path) -> tuple[dict, dict, dict]:
    method = tmp_path / "method.md"
    method.write_text("# exact method\n", encoding="utf-8")
    ledger = N.build_candidate_negative_ledger(
        phase="depth",
        artifacts=[
            N.ArtifactInput(
                "depth_worker.md",
                (
                    "### Finding [NEG-1]: candidate\n"
                    "**Verdict**: REFUTED\n"
                    "**Evidence**: src/Vault.sol:L9\n"
                    "**Invariant Commitment**: CI:CI-1\n\n"
                    "committed-invariant [CI-1]\n"
                    "Locus: src/Vault.sol:L9\n"
                    "Shape: FRESHNESS\n"
                    "Assertion: the observed state is current at use\n"
                    "Falsify Class: property\n"
                    "Provenance: depth REFUTATION_PROPOSAL @ NEG-1\n"
                ).encode(),
                "PRODUCER",
                "PRODUCER-RUN",
            )
        ],
        methodology_path=method,
    )
    N.write_candidate_negative_ledger(tmp_path, ledger)
    plan = N.build_candidate_negative_application_plan(
        tmp_path, phases=("depth",), max_items_per_shard=4
    )
    item = plan["work_items"][0]
    evidence = "src/Vault.sol:L9 exact independent trace"
    assessment = {
        "work_item_id": item["work_item_id"],
        "assessor_id": "INDEPENDENT",
        "assessor_invocation_id": "INDEPENDENT-RUN",
        "outcome": "DISAGREE_CANDIDATE",
        "evidence_basis": "IN_SCOPE_SOURCE",
        "evidence": evidence,
        "evidence_sha256": hashlib.sha256(evidence.encode()).hexdigest(),
        "rationale": "the producer negative is not supported",
        "candidate": {
            "title": "Reopened candidate",
            "mechanism": "The proposed guard does not cover every reachable path.",
            "harm": "A protected protocol property may remain violable.",
        },
    }
    receipt = N.adjudicate_candidate_negative(
        plan, [assessment], candidate_sink=lambda _proposal: None
    )
    return ledger, plan, receipt


def test_reopened_candidate_requires_projection_delivery(tmp_path: Path) -> None:
    ledger, plan, receipt = _reopened_state(tmp_path)
    denominator = N.validate_candidate_negative_denominator(
        ledgers=[ledger], plan=plan, receipt=receipt
    )
    assert denominator["status"] == "INPUT_DEBT"
    assert any("projection" in issue.casefold() for issue in denominator["issues"])


def test_reopened_candidate_projection_has_exact_proposal_parity(tmp_path: Path) -> None:
    ledger, plan, receipt = _reopened_state(tmp_path)
    projection = tmp_path / CANDIDATE_NEGATIVE_SKEPTIC_PROJECTION
    write_application_skeptic_proposal_projection(
        tmp_path,
        receipt["registry_candidate_proposals"],
        projection_name=CANDIDATE_NEGATIVE_SKEPTIC_PROJECTION,
    )
    denominator = N.validate_candidate_negative_denominator(
        ledgers=[ledger], plan=plan, receipt=receipt, projection_path=projection
    )
    assert denominator["status"] == "COMPLETE"
    assert denominator["delivered_proposal_ids"] == [
        receipt["registry_candidate_proposals"][0]["proposal_id"]
    ]
    assert len(denominator["projection_sha256"]) == 64


def test_stale_reopened_candidate_projection_remains_input_debt(tmp_path: Path) -> None:
    ledger, plan, receipt = _reopened_state(tmp_path)
    projection = tmp_path / CANDIDATE_NEGATIVE_SKEPTIC_PROJECTION
    write_application_skeptic_proposal_projection(
        tmp_path, [], projection_name=CANDIDATE_NEGATIVE_SKEPTIC_PROJECTION
    )
    denominator = N.validate_candidate_negative_denominator(
        ledgers=[ledger], plan=plan, receipt=receipt, projection_path=projection
    )
    assert denominator["status"] == "INPUT_DEBT"
    assert denominator["delivered_proposal_ids"] == []
    assert any("proposal parity" in issue for issue in denominator["issues"])
