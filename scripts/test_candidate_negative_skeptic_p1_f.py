from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

import application_skeptic as A
import candidate_negative_authority as N
from finding_producer_registry import write_application_skeptic_proposal_projection


def _method(tmp_path: Path) -> Path:
    path = tmp_path / "method.md"
    path.write_text("# Exact independent-negative method bytes\n", encoding="utf-8")
    return path


def _ledger(tmp_path: Path, phase: str = "depth") -> dict[str, object]:
    method = _method(tmp_path)
    return N.build_candidate_negative_ledger(
        phase=phase,
        artifacts=[
            N.ArtifactInput(
                relative_path=f"{phase}_worker.md",
                content=(
                    "### Finding [NEG-1]: candidate\n"
                    "**Verdict**: REFUTED\n"
                    "**Location**: src/Vault.sol:L9\n"
                    "**Refutation Basis**: a local guard is assumed sufficient\n"
                    "**Invariant Commitment**: CI:CI-1\n\n"
                    "committed-invariant [CI-1]\n"
                    "Locus: src/Vault.sol:L9\n"
                    "Shape: FRESHNESS\n"
                    "Assertion: the observed state is current at use\n"
                    "Falsify Class: property\n"
                    "Provenance: depth REFUTATION_PROPOSAL @ NEG-1\n"
                ).encode("utf-8"),
                producer_identity="ORIGINAL_PRODUCER",
                producer_invocation_id="ORIGINAL-INVOCATION",
            )
        ],
        methodology_path=method,
    )


def _write_ledger(tmp_path: Path, phase: str = "depth") -> dict[str, object]:
    ledger = _ledger(tmp_path, phase)
    N.write_candidate_negative_ledger(tmp_path, ledger)
    return ledger


def test_separate_candidate_plan_is_application_skeptic_compatible(
    tmp_path: Path,
) -> None:
    ledger = _write_ledger(tmp_path)
    plan = N.build_candidate_negative_application_plan(
        tmp_path, phases=("depth",), max_items_per_shard=4
    )
    assert plan["schema_version"] == A.WORK_PLAN_SCHEMA
    assert plan["status"] == "READY"
    assert plan["input_row_count"] == 1
    assert plan["work_item_count"] == 1
    item = plan["work_items"][0]
    event = ledger["events"][0]
    assert item["application_subject"] == "CANDIDATE_NEGATIVE"
    assert item["obligation_id"] == event["family_id"]
    assert item["input_row_ids"] == [event["event_id"]]
    assert item["producer_identities"] == ["ORIGINAL_PRODUCER"]
    assert item["producer_invocation_ids"] == ["ORIGINAL-INVOCATION"]
    assert item["candidate_negative_event_digests"] == [event["event_digest"]]
    assert len(item["candidate_negative_family_binding_digest"]) == 64


def test_missing_or_malformed_ledger_is_visible_input_debt(tmp_path: Path) -> None:
    missing = N.build_candidate_negative_application_plan(
        tmp_path, phases=("depth",), max_items_per_shard=4
    )
    assert missing["status"] == "INPUT_DEBT"
    assert missing["issues"][0]["code"] == "MISSING_CANDIDATE_NEGATIVE_LEDGER"

    path = tmp_path / "candidate_negative_proposals_depth.json"
    path.write_text("{broken", encoding="utf-8")
    malformed = N.build_candidate_negative_application_plan(
        tmp_path, phases=("depth",), max_items_per_shard=4
    )
    assert malformed["status"] == "INPUT_DEBT"
    assert malformed["issues"][0]["code"] == "INVALID_CANDIDATE_NEGATIVE_LEDGER"


def test_exact_candidate_context_reaches_independent_prompt(tmp_path: Path) -> None:
    ledger = _write_ledger(tmp_path)
    plan = N.build_candidate_negative_application_plan(
        tmp_path, phases=("depth",), max_items_per_shard=4
    )
    shard = plan["shards"][0]["shard_id"]
    rendered = A.build_application_skeptic_shard_prompt(
        plan,
        shard,
        trusted_methodology_roots=[tmp_path],
        output_path=tmp_path / "assessment.json",
        assessor_id="INDEPENDENT",
        assessor_invocation_id="INDEPENDENT-RUN",
    )
    event = ledger["events"][0]
    assert event["event_id"] in rendered["prompt"]
    assert event["exact_premise"] in rendered["prompt"]
    assert "Exact independent-negative method bytes" in rendered["prompt"]
    assert "CANDIDATE_NEGATIVE" in rendered["prompt"]


def _assessment(
    item: dict[str, object],
    *,
    outcome: str,
    assessor: str = "INDEPENDENT",
    invocation: str = "INDEPENDENT-RUN",
    evidence_basis: str = "IN_SCOPE_SOURCE",
    candidate: dict[str, str] | None = None,
) -> dict[str, object]:
    evidence = "src/Vault.sol:L9 exact independent trace"
    return {
        "work_item_id": item["work_item_id"],
        "assessor_id": assessor,
        "assessor_invocation_id": invocation,
        "outcome": outcome,
        "evidence_basis": evidence_basis,
        "evidence": evidence,
        "evidence_sha256": hashlib.sha256(evidence.encode("utf-8")).hexdigest(),
        "rationale": "independent candidate-level assessment",
        "candidate": candidate,
    }


def test_same_producer_cannot_self_close_candidate_negative(tmp_path: Path) -> None:
    _write_ledger(tmp_path)
    plan = N.build_candidate_negative_application_plan(
        tmp_path, phases=("depth",), max_items_per_shard=4
    )
    item = plan["work_items"][0]
    receipt = A.adjudicate_application_skeptic(
        plan,
        [
            _assessment(
                item,
                outcome="AGREE_NEGATIVE",
                assessor="ORIGINAL_PRODUCER",
            )
        ],
    )
    assert receipt["status"] == "COMPLETED_WITH_DEBT"
    assert receipt["work_dispositions"][0]["reason_code"] == "SELF_ADJUDICATION"


def test_missing_assessment_remains_unresolved_and_visible(tmp_path: Path) -> None:
    _write_ledger(tmp_path)
    plan = N.build_candidate_negative_application_plan(
        tmp_path, phases=("depth",), max_items_per_shard=4
    )
    receipt = A.adjudicate_application_skeptic(plan, [])
    assert receipt["status"] == "COMPLETED_WITH_DEBT"
    assert receipt["unresolved_work_item_ids"] == [
        plan["work_items"][0]["work_item_id"]
    ]
    assert receipt["input_dispositions"][0]["disposition"] == "UNRESOLVED_DEBT"


def test_independent_disagreement_reopens_normal_candidate(tmp_path: Path) -> None:
    _write_ledger(tmp_path)
    plan = N.build_candidate_negative_application_plan(
        tmp_path, phases=("depth",), max_items_per_shard=4
    )
    item = plan["work_items"][0]
    delivered: list[dict[str, object]] = []
    receipt = A.adjudicate_application_skeptic(
        plan,
        [
            _assessment(
                item,
                outcome="DISAGREE_CANDIDATE",
                candidate={
                    "title": "Reopened candidate",
                    "mechanism": "The proposed guard does not cover every reachable path.",
                    "harm": "A protected protocol property may remain violable.",
                },
            )
        ],
        candidate_sink=delivered.append,
    )
    assert receipt["status"] == "COMPLETE"
    assert receipt["work_dispositions"][0]["disposition"] == "REGISTRY_CANDIDATE_PROPOSED"
    assert len(delivered) == 1


def test_generic_skeptic_source_agreement_is_reopened_not_terminal(tmp_path: Path) -> None:
    ledger = _write_ledger(tmp_path)
    plan = N.build_candidate_negative_application_plan(
        tmp_path, phases=("depth",), max_items_per_shard=4
    )
    item = plan["work_items"][0]
    delivered: list[dict[str, object]] = []
    receipt = A.adjudicate_application_skeptic(
        plan,
        [_assessment(item, outcome="AGREE_NEGATIVE")],
        candidate_sink=delivered.append,
    )
    assert receipt["status"] == "COMPLETE"
    disposition = receipt["work_dispositions"][0]
    assert disposition["disposition"] == "REGISTRY_CANDIDATE_PROPOSED"
    assert disposition["reason_code"] == "NONTERMINAL_NEGATIVE_SUPPORT_REOPENED"
    assert disposition["obligation_id"] == ledger["events"][0]["family_id"]
    assert delivered == receipt["registry_candidate_proposals"]


@pytest.mark.parametrize(
    "evidence_basis",
    ["IN_SCOPE_SOURCE", "PRIMARY_EXTERNAL_CITED", "IN_SCOPE_EXECUTION"],
)
def test_candidate_negative_support_without_typed_closure_authority_reopens(
    tmp_path: Path, evidence_basis: str
) -> None:
    _write_ledger(tmp_path)
    plan = N.build_candidate_negative_application_plan(
        tmp_path, phases=("depth",), max_items_per_shard=4
    )
    item = plan["work_items"][0]
    delivered: list[dict[str, object]] = []
    receipt = N.adjudicate_candidate_negative(
        plan,
        [
            _assessment(
                item,
                outcome="AGREE_NEGATIVE",
                evidence_basis=evidence_basis,
            )
        ],
        candidate_sink=delivered.append,
    )
    assert receipt["status"] == "COMPLETE"
    assert receipt["work_dispositions"][0]["disposition"] == (
        "REGISTRY_CANDIDATE_PROPOSED"
    )
    assert receipt["work_dispositions"][0]["reason_code"] == (
        "NONTERMINAL_NEGATIVE_SUPPORT_REOPENED"
    )
    assert len(delivered) == 1
    assert delivered[0]["source_work_item_id"] == item["work_item_id"]


def test_external_best_case_cannot_close_without_supported_evidence(
    tmp_path: Path,
) -> None:
    _write_ledger(tmp_path)
    plan = N.build_candidate_negative_application_plan(
        tmp_path, phases=("depth",), max_items_per_shard=4
    )
    item = plan["work_items"][0]
    delivered: list[dict[str, object]] = []
    receipt = A.adjudicate_application_skeptic(
        plan,
        [
            _assessment(
                item,
                outcome="AGREE_NEGATIVE",
                evidence_basis="EXTERNAL_UNRESEARCHED",
            )
        ],
        candidate_sink=delivered.append,
    )
    assert receipt["status"] == "COMPLETE"
    assert receipt["work_dispositions"][0]["reason_code"] == (
        "NONTERMINAL_NEGATIVE_SUPPORT_REOPENED"
    )
    assert delivered == receipt["registry_candidate_proposals"]


def test_plan_resume_bytes_are_idempotent(tmp_path: Path) -> None:
    _write_ledger(tmp_path)
    first = N.build_candidate_negative_application_plan(
        tmp_path, phases=("depth",), max_items_per_shard=1
    )
    second = N.build_candidate_negative_application_plan(
        tmp_path, phases=("depth",), max_items_per_shard=1
    )
    assert first == second
    path = N.write_candidate_negative_application_plan(tmp_path, first)
    before = path.read_bytes()
    N.write_candidate_negative_application_plan(tmp_path, second)
    assert path.read_bytes() == before


def test_derived_identity_cannot_be_closed_by_independent_agreement(
    tmp_path: Path,
) -> None:
    method = _method(tmp_path)
    ledger = N.build_candidate_negative_ledger(
        phase="depth",
        artifacts=[
            N.ArtifactInput(
                "depth_worker.md",
                (
                    "### Candidate without stable ID\n"
                    "**Verdict**: REFUTED\n"
                    "**Evidence**: src/Vault.sol:L9\n"
                ).encode(),
                "ORIGINAL_PRODUCER",
                "ORIGINAL-INVOCATION",
            )
        ],
        methodology_path=method,
    )
    N.write_candidate_negative_ledger(tmp_path, ledger)
    plan = N.build_candidate_negative_application_plan(
        tmp_path, phases=("depth",), max_items_per_shard=4
    )
    item = plan["work_items"][0]
    delivered: list[dict[str, object]] = []
    receipt = N.adjudicate_candidate_negative(
        plan,
        [_assessment(item, outcome="AGREE_NEGATIVE")],
        candidate_sink=delivered.append,
    )
    # The derived source identity remains visible input debt even though the
    # recall-safe action is now an additive candidate rather than bare debt.
    assert receipt["status"] == "COMPLETED_WITH_DEBT"
    assert receipt["work_dispositions"][0]["disposition"] == (
        "REGISTRY_CANDIDATE_PROPOSED"
    )
    assert receipt["work_dispositions"][0]["reason_code"] == (
        "CANDIDATE_IDENTITY_UNRESOLVED"
    )
    assert delivered == receipt["registry_candidate_proposals"]


def test_conflicted_family_cannot_be_closed_but_can_be_reopened(
    tmp_path: Path,
) -> None:
    method = _method(tmp_path)
    ledger = N.build_candidate_negative_ledger(
        phase="depth",
        artifacts=[
            N.ArtifactInput(
                "depth_worker.md",
                (
                    "### Finding [NEG-1]: first claim\n**Verdict**: REFUTED\n"
                    "### Finding [NEG-1]: second claim\n**Verdict**: SAFE\n"
                ).encode(),
                "ORIGINAL_PRODUCER",
                "ORIGINAL-INVOCATION",
            )
        ],
        methodology_path=method,
    )
    N.write_candidate_negative_ledger(tmp_path, ledger)
    plan = N.build_candidate_negative_application_plan(
        tmp_path, phases=("depth",), max_items_per_shard=4
    )
    assert plan["status"] == "INPUT_DEBT"
    item = plan["work_items"][0]
    delivered: list[dict[str, object]] = []
    closed = N.adjudicate_candidate_negative(
        plan,
        [_assessment(item, outcome="AGREE_NEGATIVE")],
        candidate_sink=delivered.append,
    )
    assert closed["work_dispositions"][0]["reason_code"] == (
        "CANDIDATE_IDENTITY_CONFLICT"
    )
    assert closed["work_dispositions"][0]["disposition"] == (
        "REGISTRY_CANDIDATE_PROPOSED"
    )
    assert delivered == closed["registry_candidate_proposals"]

    reopened = N.adjudicate_candidate_negative(
        plan,
        [
            _assessment(
                item,
                outcome="DISAGREE_CANDIDATE",
                candidate={
                    "title": "Reopened conflicted candidate",
                    "mechanism": "The producer supplied incompatible claims.",
                    "harm": "The security impact remains unresolved.",
                },
            )
        ],
        candidate_sink=lambda _proposal: None,
    )
    assert reopened["work_dispositions"][0]["disposition"] == (
        "REGISTRY_CANDIDATE_PROPOSED"
    )


def test_candidate_denominator_requires_exact_one_outcome_per_event(
    tmp_path: Path,
) -> None:
    ledger = _write_ledger(tmp_path)
    plan = N.build_candidate_negative_application_plan(
        tmp_path, phases=("depth",), max_items_per_shard=4
    )
    item = plan["work_items"][0]
    delivered: list[dict[str, object]] = []
    receipt = N.adjudicate_candidate_negative(
        plan,
        [_assessment(item, outcome="AGREE_NEGATIVE")],
        candidate_sink=delivered.append,
    )
    projection = tmp_path / "application_skeptic_proposals.md"
    write_application_skeptic_proposal_projection(tmp_path, delivered)
    summary = N.validate_candidate_negative_denominator(
        ledgers=[ledger],
        plan=plan,
        receipt=receipt,
        projection_path=projection,
    )
    assert summary["status"] == "COMPLETE"
    assert summary["supported_exclusion_count"] == 0
    assert summary["reopened_candidate_count"] == 1
    assert summary["human_review_count"] == 0

    broken = json.loads(json.dumps(receipt))
    broken["input_dispositions"] = []
    broken["receipt_digest"] = N._digest(
        {key: value for key, value in broken.items() if key != "receipt_digest"}
    )
    summary = N.validate_candidate_negative_denominator(
        ledgers=[ledger],
        plan=plan,
        receipt=broken,
        projection_path=projection,
    )
    assert summary["status"] == "INPUT_DEBT"
    assert summary["issues"]


def test_revision_family_is_one_work_item_with_full_event_denominator(
    tmp_path: Path,
) -> None:
    method = _method(tmp_path)
    first = N.build_candidate_negative_ledger(
        phase="depth",
        artifacts=[
            N.ArtifactInput(
                "depth_worker.md",
                (
                    "### Finding [NEG-1]: candidate\n**Verdict**: REFUTED\n"
                    "**Evidence**: src/Vault.sol:L9\n"
                ).encode(),
                "PRODUCER",
                "RUN-1",
            )
        ],
        methodology_path=method,
    )
    second = N.build_candidate_negative_ledger(
        phase="depth",
        artifacts=[
            N.ArtifactInput(
                "depth_worker.md",
                (
                    "### Finding [NEG-1]: candidate\n**Verdict**: REFUTED\n"
                    "**Evidence**: src/Vault.sol:L10\n"
                ).encode(),
                "PRODUCER",
                "RUN-2",
            )
        ],
        methodology_path=method,
        prior_ledger=first,
    )
    N.write_candidate_negative_ledger(tmp_path, second)
    plan = N.build_candidate_negative_application_plan(
        tmp_path, phases=("depth",), max_items_per_shard=4
    )
    assert plan["work_item_count"] == 1
    assert plan["input_row_count"] == 2
    item = plan["work_items"][0]
    assert item["obligation_id"] == second["families"][0]["family_id"]
    assert item["input_row_ids"] == second["families"][0]["event_ids"]


def test_producer_unresolved_can_never_be_closed_as_negative(tmp_path: Path) -> None:
    method = _method(tmp_path)
    ledger = N.build_candidate_negative_ledger(
        phase="depth",
        artifacts=[
            N.ArtifactInput(
                "depth_worker.md",
                (
                    "### Finding [NEG-1]: candidate\n"
                    "**Disposition**: UNRESOLVED\n"
                    "**Evidence**: src/Vault.sol:L9\n"
                ).encode(),
                "PRODUCER",
                "RUN-1",
            )
        ],
        methodology_path=method,
    )
    N.write_candidate_negative_ledger(tmp_path, ledger)
    plan = N.build_candidate_negative_application_plan(
        tmp_path, phases=("depth",), max_items_per_shard=4
    )
    item = plan["work_items"][0]
    delivered: list[dict[str, object]] = []
    receipt = N.adjudicate_candidate_negative(
        plan,
        [_assessment(item, outcome="AGREE_NEGATIVE")],
        candidate_sink=delivered.append,
    )
    assert receipt["status"] == "COMPLETE"
    assert receipt["work_dispositions"][0]["disposition"] == (
        "REGISTRY_CANDIDATE_PROPOSED"
    )
    assert receipt["work_dispositions"][0]["reason_code"] == (
        "PRODUCER_UNRESOLVED_CANNOT_CLOSE"
    )
    assert delivered == receipt["registry_candidate_proposals"]
