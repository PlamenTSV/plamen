from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

from finding_lifecycle_authority import (
    FindingLifecycleError,
    advance_finding_lifecycle,
    authorized_finding_exclusions,
    build_finding_lifecycle,
    candidate_content_sha256,
    finding_retention_work_items,
    finding_verification_work_items,
    validate_finding_lifecycle,
    write_finding_lifecycle,
)


RUN_ID = "12345678-1234-4567-8abc-1234567890ab"
HEX_A = "a" * 64
HEX_B = "b" * 64
HEX_C = "c" * 64


def _digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def _candidate(
    candidate_id: str = "INV-001",
    *,
    entry_reason: str = "NORMAL_DISCOVERY",
    origin_assessment: str = "CANDIDATE",
    severity: str = "Medium",
    location_quality: str = "EXACT",
    provenance_quality: str = "EXACT",
    scope_state: str = "IN_SCOPE",
    producer_identity: str = "inventory-agent",
    producer_invocation_id: str = "inventory-run-1",
    source_record_sha256: str = HEX_A,
) -> dict[str, object]:
    row: dict[str, object] = {
        "schema_version": "plamen.finding_lifecycle_candidate.v1",
        "run_id": RUN_ID,
        "candidate_id": candidate_id,
        "lineage_ids": [candidate_id, f"SRC-{candidate_id}"],
        "source_artifact": "inventory.md",
        "source_artifact_sha256": HEX_B,
        "source_record_sha256": source_record_sha256,
        "producer_identity": producer_identity,
        "producer_invocation_id": producer_invocation_id,
        "producer_phase": "inventory",
        "entry_reason": entry_reason,
        "origin_assessment": origin_assessment,
        "upstream_severity": severity,
        "title": f"Candidate {candidate_id}",
        "location": "src/module.rs:10-20",
        "evidence_pointer": f"inventory.md#{candidate_id}",
        "candidate_content_sha256": "",
        "location_quality": location_quality,
        "source_provenance_quality": provenance_quality,
        "scope_state": scope_state,
    }
    row["candidate_content_sha256"] = candidate_content_sha256(row)
    return row


def _decision(
    candidate: dict[str, object],
    *,
    kind: str,
    decision_id: str = "DEC-001",
    discriminator_identity: str = "independent-verifier",
    discriminator_invocation_id: str = "verify-run-1",
    evidence_basis: str = "INDEPENDENT_EXECUTION",
    proof_scope: str = "FULL_CLAIM",
    alias_target_candidate_id: str | None = None,
    reason_class: str = "EVIDENCE_DISPOSITION",
    next_action: str | None = None,
    public_retention_target: str | None = None,
    scope_snapshot_sha256: str | None = None,
) -> dict[str, object]:
    return {
        "schema_version": "plamen.finding_lifecycle_decision.v1",
        "run_id": RUN_ID,
        "decision_id": decision_id,
        "candidate_id": candidate["candidate_id"],
        "candidate_content_sha256": candidate["candidate_content_sha256"],
        "decision_kind": kind,
        "evidence_basis": evidence_basis,
        "evidence_sha256": HEX_C,
        "proof_scope": proof_scope,
        "discriminator_identity": discriminator_identity,
        "discriminator_invocation_id": discriminator_invocation_id,
        "discriminator_phase": "verify",
        "alias_target_candidate_id": alias_target_candidate_id,
        "reason_class": reason_class,
        "next_action": next_action,
        "public_retention_target": public_retention_target,
        "scope_snapshot_sha256": scope_snapshot_sha256,
    }


def _projection(
    candidate: dict[str, object],
    *,
    kind: str = "BODY",
    projection_id: str = "PROJ-001",
) -> dict[str, object]:
    return {
        "schema_version": "plamen.finding_lifecycle_projection.v1",
        "run_id": RUN_ID,
        "projection_id": projection_id,
        "candidate_id": candidate["candidate_id"],
        "candidate_content_sha256": candidate["candidate_content_sha256"],
        "projection_kind": kind,
        "artifact_path": "AUDIT_REPORT.md",
        "artifact_sha256": HEX_A,
        "public_reference": f"HR-{candidate['candidate_id']}",
        "projector_identity": "report-assembler",
        "projector_invocation_id": "report-run-1",
    }


def _build(
    candidates: list[dict[str, object]],
    decisions: list[dict[str, object]] | None = None,
    projections: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    return build_finding_lifecycle(
        run_id=RUN_ID,
        candidates=candidates,
        decisions=decisions or [],
        projections=projections or [],
        authority_identity="plamen-driver",
        authority_invocation_id="driver-run-1",
    )


def _row(receipt: dict[str, object], candidate_id: str = "INV-001") -> dict[str, object]:
    return next(
        row
        for row in receipt["candidate_states"]  # type: ignore[index]
        if row["candidate_id"] == candidate_id
    )


def _obligation_kinds(receipt: dict[str, object], candidate_id: str = "INV-001") -> set[str]:
    return {
        row["obligation_kind"]
        for row in receipt["obligations"]  # type: ignore[index]
        if row["candidate_id"] == candidate_id
    }


def test_producer_cannot_refute_or_deduplicate_its_own_candidate() -> None:
    candidate = _candidate(origin_assessment="REFUTED")
    decision = _decision(
        candidate,
        kind="REFUTED",
        discriminator_identity=str(candidate["producer_identity"]),
        discriminator_invocation_id=str(candidate["producer_invocation_id"]),
    )
    receipt = _build([candidate], [decision])

    row = _row(receipt)
    assert row["claim_state"] == "UNVERIFIED"
    assert row["delivery_state"] == "PENDING_BODY"
    assert row["independent_disposition"] is False
    assert "INDEPENDENT_VERIFICATION" in _obligation_kinds(receipt)
    assert receipt["rejected_decisions"][0]["reason"] == "DISCRIMINATOR_NOT_INDEPENDENT"  # type: ignore[index]


def test_citation_and_identifier_debt_never_deletes_content_or_loses_aliases() -> None:
    candidate = _candidate(
        "H-019",
        location_quality="UNRESOLVED",
        provenance_quality="UNRESOLVED",
        origin_assessment="IDENTIFIER_UNVERIFIED",
        severity="Low",
    )
    candidate["lineage_ids"] = ["H-019", "INV-025", "AC-2", "CC-02"]
    candidate["candidate_content_sha256"] = candidate_content_sha256(candidate)

    receipt = _build([candidate])
    row = _row(receipt, "H-019")
    assert row["content_bearing"] is True
    assert row["lineage_ids"] == ["AC-2", "CC-02", "H-019", "INV-025"]
    assert row["delivery_state"] == "PENDING_HUMAN_REVIEW"
    assert _obligation_kinds(receipt, "H-019") == {
        "INDEPENDENT_VERIFICATION",
        "LOCATION_REPAIR",
    }


def test_post_verify_side_observation_gets_new_exact_late_verification() -> None:
    candidate = _candidate(entry_reason="POST_VERIFY_SIDE_OBSERVATION")
    stale = _decision(candidate, kind="CONFIRMED")
    stale["candidate_content_sha256"] = HEX_A

    receipt = _build([candidate], [stale])
    assert _row(receipt)["claim_state"] == "UNVERIFIED"
    assert "LATE_INDEPENDENT_VERIFICATION" in _obligation_kinds(receipt)
    assert receipt["rejected_decisions"][0]["reason"] == "CANDIDATE_CONTENT_MISMATCH"  # type: ignore[index]


def test_resume_queue_dropout_requires_recovery_verification_not_excluded_ack() -> None:
    candidate = _candidate(
        entry_reason="RESUME_QUEUE_DROPOUT",
        origin_assessment="DEFERRED_ON_RESUME",
        severity="Low",
    )
    receipt = _build([candidate])
    row = _row(receipt)
    assert row["delivery_state"] == "PENDING_BODY"
    assert row["terminal_complete"] is False
    assert _obligation_kinds(receipt) == {"RECOVERY_INDEPENDENT_VERIFICATION"}


def test_bare_report_deferred_is_nonterminal_visible_dropout() -> None:
    candidate = _candidate(
        entry_reason="REPORT_INDEX_DROPOUT",
        origin_assessment="DEFERRED",
        severity="Medium",
    )
    receipt = _build([candidate])
    row = _row(receipt)
    assert row["claim_state"] == "UNRESOLVED_PIPELINE_DROPOUT"
    assert row["delivery_state"] == "PENDING_BODY"
    assert row["terminal_complete"] is False
    assert _obligation_kinds(receipt) == {
        "RECOVERY_INDEPENDENT_VERIFICATION",
        "REPORT_INDEX_ADJUDICATION",
    }


def test_authorized_deferred_still_requires_public_delivery() -> None:
    candidate = _candidate(entry_reason="REPORT_INDEX_DROPOUT")
    decision = _decision(
        candidate,
        kind="AUTHORIZED_DEFERRED",
        evidence_basis="INDEPENDENT_ANALYSIS",
        proof_scope="PARTIAL_CLAIM",
        reason_class="EXTERNAL_DEPENDENCY_UNAVAILABLE",
        next_action="Re-run independent verification when evidence is available",
        public_retention_target="HUMAN_REVIEW",
    )
    pending = _build([candidate], [decision])
    assert _row(pending)["delivery_state"] == "PENDING_HUMAN_REVIEW"
    assert _row(pending)["terminal_complete"] is False
    assert "REPORT_PROJECTION" in _obligation_kinds(pending)

    delivered = _build(
        [candidate],
        [decision],
        [_projection(candidate, kind="HUMAN_REVIEW")],
    )
    assert _row(delivered)["delivery_state"] == "DELIVERED_HUMAN_REVIEW"
    assert _row(delivered)["terminal_complete"] is False
    assert "INDEPENDENT_VERIFICATION" in _obligation_kinds(delivered)


@pytest.mark.parametrize(
    ("kind", "basis", "scope", "snapshot", "claim_state"),
    [
        ("REFUTED", "INDEPENDENT_EXECUTION", "FULL_CLAIM", None, "REFUTED"),
        (
            "AUTHORIZED_SCOPE_EXCLUSION",
            "EXACT_SCOPE_PREDICATE",
            "SCOPE_ONLY",
            HEX_B,
            "OUT_OF_SCOPE",
        ),
    ],
)
def test_negative_labels_without_typed_provider_never_authorize_exclusion(
    kind: str,
    basis: str,
    scope: str,
    snapshot: str | None,
    claim_state: str,
) -> None:
    candidate = _candidate(scope_state="OUT_OF_SCOPE_CLAIMED")
    decision = _decision(
        candidate,
        kind=kind,
        evidence_basis=basis,
        proof_scope=scope,
        scope_snapshot_sha256=snapshot,
    )
    receipt = _build([candidate], [decision])
    row = _row(receipt)
    assert row["claim_state"] == "UNVERIFIED"
    assert row["delivery_state"] == "PENDING_BODY"
    assert row["terminal_complete"] is False
    assert "INDEPENDENT_VERIFICATION" in _obligation_kinds(receipt)
    assert receipt["rejected_decisions"]


def test_unsupported_refutation_cannot_conflict_with_positive_disposition() -> None:
    candidate = _candidate()
    confirmed = _decision(candidate, kind="CONFIRMED", decision_id="DEC-A")
    refuted = _decision(candidate, kind="REFUTED", decision_id="DEC-B")
    receipt = _build([candidate], [confirmed, refuted])
    row = _row(receipt)
    assert row["claim_state"] == "CONFIRMED"
    assert row["delivery_state"] == "PENDING_BODY"
    assert row["terminal_complete"] is False
    assert _obligation_kinds(receipt) == {"REPORT_PROJECTION"}
    assert receipt["rejected_decisions"][0]["decision_id"] == "DEC-B"


def test_confirmed_candidate_is_complete_only_after_exact_projection() -> None:
    candidate = _candidate()
    decision = _decision(candidate, kind="CONFIRMED")
    pending = _build([candidate], [decision])
    assert _row(pending)["claim_state"] == "CONFIRMED"
    assert _row(pending)["terminal_complete"] is False
    assert "REPORT_PROJECTION" in _obligation_kinds(pending)

    delivered = _build([candidate], [decision], [_projection(candidate)])
    assert _row(delivered)["delivery_state"] == "DELIVERED_BODY"
    assert _row(delivered)["terminal_complete"] is True


def test_alias_label_without_applied_authority_never_consolidates() -> None:
    source = _candidate("INV-001")
    target = _candidate("INV-002", source_record_sha256=HEX_C)
    alias = _decision(
        source,
        kind="AUTHORIZED_ALIAS",
        evidence_basis="TYPED_EQUIVALENCE",
        proof_scope="FULL_CLAIM",
        alias_target_candidate_id="INV-002",
    )
    target_decision = _decision(
        target,
        kind="CONFIRMED",
        decision_id="DEC-TARGET",
    )
    pending = _build([source, target], [alias, target_decision])
    assert _row(pending, "INV-001")["delivery_state"] == "PENDING_BODY"
    assert _row(pending, "INV-001")["terminal_complete"] is False

    delivered = _build(
        [source, target],
        [alias, target_decision],
        [_projection(target)],
    )
    assert _row(delivered, "INV-001")["delivery_state"] == "PENDING_BODY"
    assert _row(delivered, "INV-001")["terminal_complete"] is False
    assert "INDEPENDENT_VERIFICATION" in _obligation_kinds(delivered, "INV-001")


def test_identity_conflict_retains_all_variants_and_never_false_cleans() -> None:
    first = _candidate()
    second = copy.deepcopy(first)
    second["title"] = "Conflicting content under the same identity"
    second["source_record_sha256"] = HEX_C
    second["candidate_content_sha256"] = candidate_content_sha256(second)
    receipt = _build([first, second])
    row = _row(receipt)
    assert row["identity_state"] == "CONFLICT"
    assert len(row["candidate_content_sha256s"]) == 2
    assert row["delivery_state"] == "PENDING_BODY"
    assert row["terminal_complete"] is False
    assert _obligation_kinds(receipt) == {
        "IDENTITY_CONFLICT_REVIEW",
        "RECOVERY_INDEPENDENT_VERIFICATION",
    }


def test_append_only_resume_is_idempotent_and_tamper_evident(tmp_path: Path) -> None:
    first_candidate = _candidate()
    first = _build([first_candidate])
    path = tmp_path / "finding_lifecycle_authority.json"
    assert write_finding_lifecycle(path, first) is True
    assert write_finding_lifecycle(path, first) is False

    second_candidate = _candidate("INV-002", source_record_sha256=HEX_C)
    second = advance_finding_lifecycle(
        first,
        candidates=[second_candidate],
        decisions=[],
        projections=[],
        authority_identity="plamen-driver",
        authority_invocation_id="driver-run-2",
    )
    assert second["generation"] == 2
    assert second["previous_receipt_sha256"] == first["ledger_sha256"]
    assert write_finding_lifecycle(path, second) is True
    assert validate_finding_lifecycle(second) == second

    stale = advance_finding_lifecycle(
        first,
        candidates=[_candidate("INV-003")],
        decisions=[],
        projections=[],
        authority_identity="plamen-driver",
        authority_invocation_id="driver-run-stale",
    )
    with pytest.raises(FindingLifecycleError, match="compare-and-swap"):
        write_finding_lifecycle(path, stale)

    tampered = json.loads(path.read_text(encoding="utf-8"))
    tampered["candidate_states"][0]["terminal_complete"] = True
    path.write_text(json.dumps(tampered), encoding="utf-8")
    with pytest.raises(FindingLifecycleError, match="digest|recompute"):
        write_finding_lifecycle(path, second)


def test_cross_run_records_and_digest_forgery_are_rejected() -> None:
    candidate = _candidate()
    foreign = _decision(candidate, kind="CONFIRMED")
    foreign["run_id"] = "foreign-run"
    with pytest.raises(FindingLifecycleError, match="run_id"):
        _build([candidate], [foreign])

    forged = copy.deepcopy(candidate)
    forged["candidate_content_sha256"] = HEX_C
    with pytest.raises(FindingLifecycleError, match="candidate_content_sha256"):
        _build([forged])


def test_scope_claim_without_authorized_scope_decision_stays_visible() -> None:
    candidate = _candidate(
        scope_state="OUT_OF_SCOPE_CLAIMED",
        origin_assessment="OUT_OF_SCOPE",
    )
    receipt = _build([candidate])
    assert _row(receipt)["delivery_state"] == "PENDING_BODY"
    assert "INDEPENDENT_VERIFICATION" in _obligation_kinds(receipt)


def test_same_decision_identity_with_changed_bytes_is_a_visible_conflict() -> None:
    candidate = _candidate()
    first = _decision(candidate, kind="CONFIRMED", decision_id="DEC-STABLE")
    changed = copy.deepcopy(first)
    changed["evidence_sha256"] = HEX_B
    receipt = _build([candidate], [first, changed])
    assert _row(receipt)["claim_state"] == "DISPOSITION_CONFLICT"
    assert _row(receipt)["terminal_complete"] is False
    assert {
        item["reason"] for item in receipt["rejected_decisions"]  # type: ignore[index]
    } == {"DECISION_ID_CONFLICT"}


def test_projection_identity_or_public_reference_collision_cannot_complete_claims() -> None:
    first = _candidate("INV-001")
    second = _candidate("INV-002", source_record_sha256=HEX_C)
    decisions = [
        _decision(first, kind="CONFIRMED", decision_id="DEC-1"),
        _decision(second, kind="CONFIRMED", decision_id="DEC-2"),
    ]
    projection_one = _projection(first, projection_id="PROJ-SHARED")
    projection_two = _projection(second, projection_id="PROJ-SHARED")
    projection_two["public_reference"] = projection_one["public_reference"]
    receipt = _build([first, second], decisions, [projection_one, projection_two])
    assert _row(receipt, "INV-001")["terminal_complete"] is False
    assert _row(receipt, "INV-002")["terminal_complete"] is False
    assert "REPORT_PROJECTION" in _obligation_kinds(receipt, "INV-001")
    assert "REPORT_PROJECTION" in _obligation_kinds(receipt, "INV-002")
    assert any("projection identity collision" in item for item in receipt["debt"])


def test_alias_cycle_never_becomes_terminal_consolidation() -> None:
    first = _candidate("INV-001")
    second = _candidate("INV-002", source_record_sha256=HEX_C)
    decisions = [
        _decision(
            first,
            kind="AUTHORIZED_ALIAS",
            decision_id="DEC-1",
            evidence_basis="TYPED_EQUIVALENCE",
            alias_target_candidate_id="INV-002",
        ),
        _decision(
            second,
            kind="AUTHORIZED_ALIAS",
            decision_id="DEC-2",
            evidence_basis="TYPED_EQUIVALENCE",
            alias_target_candidate_id="INV-001",
        ),
    ]
    receipt = _build([first, second], decisions)
    assert all(row["terminal_complete"] is False for row in receipt["candidate_states"])
    assert {
        row["obligation_kind"] for row in receipt["obligations"]
    } == {"INDEPENDENT_VERIFICATION"}


def test_resume_advancement_can_close_only_the_exact_candidate() -> None:
    first = _candidate("INV-001")
    second = _candidate("INV-002", source_record_sha256=HEX_C)
    initial = _build([first, second])
    advanced = advance_finding_lifecycle(
        initial,
        candidates=[],
        decisions=[_decision(first, kind="CONFIRMED")],
        projections=[_projection(first)],
        authority_identity="plamen-driver",
        authority_invocation_id="driver-run-2",
    )
    assert _row(advanced, "INV-001")["terminal_complete"] is True
    assert _row(advanced, "INV-002")["terminal_complete"] is False
    assert _obligation_kinds(advanced, "INV-001") == set()
    assert _obligation_kinds(advanced, "INV-002") == {"INDEPENDENT_VERIFICATION"}

    replay = advance_finding_lifecycle(
        advanced,
        candidates=[],
        decisions=[_decision(first, kind="CONFIRMED")],
        projections=[_projection(first)],
        authority_identity="plamen-driver",
        authority_invocation_id="driver-run-3",
    )
    assert replay == advanced


def test_resume_authority_principal_cannot_change_mid_chain() -> None:
    initial = _build([_candidate()])
    with pytest.raises(FindingLifecycleError, match="authority_identity"):
        advance_finding_lifecycle(
            initial,
            candidates=[_candidate("INV-002", source_record_sha256=HEX_C)],
            decisions=[],
            projections=[],
            authority_identity="unrelated-writer",
            authority_invocation_id="writer-run-2",
        )


def test_consumer_views_cannot_reintroduce_producer_self_exclusion() -> None:
    producer_negative = _candidate(origin_assessment="REFUTED")
    self_decision = _decision(
        producer_negative,
        kind="REFUTED",
        discriminator_identity=str(producer_negative["producer_identity"]),
        discriminator_invocation_id=str(producer_negative["producer_invocation_id"]),
    )
    pending = _build([producer_negative], [self_decision])
    verify = finding_verification_work_items(pending)
    retention = finding_retention_work_items(pending)
    assert [row["candidate_id"] for row in verify] == ["INV-001"]
    assert [row["candidate_id"] for row in retention] == ["INV-001"]
    assert authorized_finding_exclusions(pending) == []

    independent = _build(
        [producer_negative],
        [_decision(producer_negative, kind="REFUTED")],
    )
    assert [row["candidate_id"] for row in finding_verification_work_items(independent)] == ["INV-001"]
    assert [row["candidate_id"] for row in finding_retention_work_items(independent)] == ["INV-001"]
    assert authorized_finding_exclusions(independent) == []


def test_consumer_views_bind_exact_obligation_and_candidate_digests() -> None:
    candidate = _candidate(entry_reason="POST_VERIFY_SIDE_OBSERVATION")
    receipt = _build([candidate])
    work = finding_verification_work_items(receipt)
    assert work == [
        {
            "run_id": RUN_ID,
            "obligation_id": receipt["obligations"][0]["obligation_id"],  # type: ignore[index]
            "obligation_kind": "LATE_INDEPENDENT_VERIFICATION",
            "candidate_id": "INV-001",
            "candidate_content_sha256s": [candidate["candidate_content_sha256"]],
            "source_record_sha256s": [candidate["source_record_sha256"]],
            "lineage_ids": ["INV-001", "SRC-INV-001"],
            "upstream_severity": "Medium",
            "title": "Candidate INV-001",
            "location": "src/module.rs:10-20",
            "evidence_pointer": "inventory.md#INV-001",
            "retention_target": "BODY",
        }
    ]
