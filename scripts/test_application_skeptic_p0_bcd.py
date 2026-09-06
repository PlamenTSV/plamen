"""P0-C conditional application-skeptic work-plan and receipt contracts."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

import application_skeptic as K
import methodology_application_states as S
import negative_closure_evidence_authority as NCEA


def _state(
    step: str,
    *,
    worker: str = "B1",
    invocation: str = "producer-1",
    methodology_path: str = "C:/plamen/oracle/SKILL.md",
    methodology_sha256: str = "a" * 64,
):
    return S.classify_application_row(
        {
            "phase": "breadth",
            "worker_id": worker,
            "producer_invocation_id": invocation,
            "output": "analysis_oracle.md",
            "output_sha256": "b" * 64,
            "prompt_sha256": "c" * 64,
            "dispatch_contract_sha256": "d" * 64,
            "skill": "ORACLE_ANALYSIS",
            "methodology_path": methodology_path,
            "methodology_sha256": methodology_sha256,
            "step": step,
            "executed": "yes",
            "evidence": "src/Oracle.sol:L9",
            "result": "SAFE: cited guard rejects the transition",
            "delivery_integrity": "CURRENT",
            "trace_state": "VALID",
            "evidence_basis": "IN_SCOPE_SOURCE",
        }
    )


def _write_queue(path: Path, rows) -> None:
    phase = path.stem.removeprefix("methodology_skeptic_queue_")
    payload = S.build_application_queues(rows, phase=phase).skeptic
    path.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")


def _seed_all(tmp_path: Path, rows_by_phase=None):
    rows_by_phase = rows_by_phase or {}
    for phase in K.DEFAULT_QUEUE_PHASES:
        _write_queue(
            tmp_path / f"methodology_skeptic_queue_{phase}.json",
            rows_by_phase.get(phase, []),
        )


def _assessment(work_id: str, outcome: str, **changes):
    value = {
        "work_item_id": work_id,
        "assessor_id": "skeptic-A",
        "assessor_invocation_id": "skeptic-call-1",
        "outcome": outcome,
        "evidence_basis": "IN_SCOPE_SOURCE",
        "evidence_sha256": "e" * 64,
        "rationale": "independently traced the exact bound step and premise",
    }
    value.update(changes)
    return value


def test_exact_original_and_repair_union_deduplicates_work_without_losing_inputs(
    tmp_path: Path,
):
    row = _state("1")
    _seed_all(tmp_path, {"breadth": [row], "breadth_repair": [row]})
    plan = K.build_application_skeptic_work_plan(tmp_path, max_items_per_shard=1)

    assert plan["status"] == "READY"
    assert plan["input_row_count"] == 2
    assert plan["work_item_count"] == 1
    assert len(plan["work_items"][0]["input_row_ids"]) == 2
    assert set(plan["source_queues"]) == {
        f"methodology_skeptic_queue_{phase}.json"
        for phase in K.DEFAULT_QUEUE_PHASES
    }


def test_empty_complete_union_is_deterministic_not_triggered_and_no_model_work(
    tmp_path: Path,
):
    _seed_all(tmp_path)
    first = K.write_application_skeptic_work_plan(tmp_path)
    path = tmp_path / K.WORK_PLAN_FILE
    before = (path.read_bytes(), path.stat().st_mtime_ns)
    second = K.write_application_skeptic_work_plan(tmp_path)
    receipt = K.adjudicate_application_skeptic(first, [])

    assert first == second
    assert first["status"] == "NOT_TRIGGERED"
    assert first["work_items"] == [] and first["shards"] == []
    assert before == (path.read_bytes(), path.stat().st_mtime_ns)
    assert receipt["status"] == "NOT_TRIGGERED"
    assert receipt["model_invoked"] is False


def test_missing_or_tampered_source_queue_is_debt_not_silent_empty(tmp_path: Path):
    _seed_all(tmp_path)
    missing = tmp_path / "methodology_skeptic_queue_depth_repair.json"
    missing.unlink()
    plan = K.build_application_skeptic_work_plan(tmp_path)
    assert plan["status"] == "INPUT_DEBT"
    assert any(issue["code"] == "MISSING_SOURCE_QUEUE" for issue in plan["issues"])

    _write_queue(missing, [])
    payload = json.loads(missing.read_text())
    payload["queue_digest"] = "0" * 64
    missing.write_text(json.dumps(payload), encoding="utf-8")
    plan = K.build_application_skeptic_work_plan(tmp_path)
    assert any(issue["code"] == "INVALID_SOURCE_QUEUE" for issue in plan["issues"])


def test_sharding_and_tail_cover_every_work_item_exactly_once(tmp_path: Path):
    rows = [_state(str(i)) for i in range(1, 6)]
    _seed_all(tmp_path, {"breadth": rows})
    plan = K.build_application_skeptic_work_plan(tmp_path, max_items_per_shard=2)

    flattened = [wid for shard in plan["shards"] for wid in shard["work_item_ids"]]
    expected = [item["work_item_id"] for item in plan["work_items"]]
    assert flattened == expected
    assert len(plan["shards"]) == 3
    assert len(plan["shards"][-1]["work_item_ids"]) == 1
    assert len(flattened) == len(set(flattened))


def test_bound_methodology_bytes_must_match_path_hash_and_trusted_root(tmp_path: Path):
    skill = tmp_path / "skills" / "SKILL.md"
    skill.parent.mkdir()
    skill.write_text("# exact method bytes\n", encoding="utf-8")
    state = _state(
        "1",
        methodology_path=skill.as_posix(),
        methodology_sha256=hashlib.sha256(skill.read_bytes()).hexdigest(),
    )
    _seed_all(tmp_path, {"breadth": [state]})
    item = K.build_application_skeptic_work_plan(tmp_path)["work_items"][0]

    assert K.read_bound_methodology_bytes(item, [skill.parent]) == skill.read_bytes()
    skill.write_text("# drifted\n", encoding="utf-8")
    try:
        K.read_bound_methodology_bytes(item, [skill.parent])
    except K.ApplicationSkepticError as exc:
        assert "SHA-256" in str(exc)
    else:
        raise AssertionError("methodology hash drift must fail closed")


def test_shard_prompt_reads_exact_bound_bytes_and_assessment_tail_is_exact(tmp_path: Path):
    skill = tmp_path / "skills" / "SKILL.md"
    skill.parent.mkdir()
    skill.write_text("# exact independent method\n", encoding="utf-8")
    state = _state(
        "1",
        methodology_path=skill.as_posix(),
        methodology_sha256=hashlib.sha256(skill.read_bytes()).hexdigest(),
    )
    _seed_all(tmp_path, {"breadth": [state]})
    plan = K.build_application_skeptic_work_plan(tmp_path, max_items_per_shard=1)
    shard_id = plan["shards"][0]["shard_id"]
    rendered = K.build_application_skeptic_shard_prompt(
        plan,
        shard_id,
        trusted_methodology_roots=[skill.parent],
        output_path=tmp_path / "assessment.json",
    )

    assert "# exact independent method" in rendered["prompt"]
    assert plan["work_items"][0]["original_result"] in rendered["prompt"]
    assessment = _assessment(plan["work_items"][0]["work_item_id"], "AGREE_NEGATIVE")
    assessment.pop("evidence_sha256")
    assessment["evidence"] = "src/Oracle.sol:L9 exact guard trace"
    assessment["candidate"] = None
    payload = {
        "schema_version": K.ASSESSMENT_SCHEMA,
        "work_plan_digest": plan["work_plan_digest"],
        "shard_id": shard_id,
        "assessments": [assessment],
    }
    assessment_path = tmp_path / "assessment.json"
    assessment_path.write_text(json.dumps(payload), encoding="utf-8")
    loaded = K.load_application_skeptic_assessments(
        assessment_path, plan, shard_id
    )
    assert loaded[0]["evidence"] == assessment["evidence"]
    assert loaded[0]["evidence_sha256"] == hashlib.sha256(
        assessment["evidence"].encode("utf-8")
    ).hexdigest()

    payload["assessments"] = []
    assessment_path.write_text(json.dumps(payload), encoding="utf-8")
    try:
        K.load_application_skeptic_assessments(assessment_path, plan, shard_id)
    except K.ApplicationSkepticError as exc:
        assert "tail" in str(exc)
    else:
        raise AssertionError("omitted shard tail must fail exact assessment loading")


def test_same_producer_or_invocation_cannot_self_adjudicate(tmp_path: Path):
    _seed_all(tmp_path, {"breadth": [_state("1")]})
    plan = K.build_application_skeptic_work_plan(tmp_path)
    item = plan["work_items"][0]
    proposals = []
    receipt = K.adjudicate_application_skeptic(
        plan,
        [
            _assessment(
                item["work_item_id"],
                "AGREE_NEGATIVE",
                assessor_id="B1",
                assessor_invocation_id="producer-1",
            )
        ],
        candidate_sink=proposals.append,
    )

    assert receipt["status"] == "COMPLETE"
    assert receipt["work_dispositions"][0]["disposition"] == (
        "REGISTRY_CANDIDATE_PROPOSED"
    )
    assert receipt["work_dispositions"][0]["reason_code"] == "SELF_ADJUDICATION"
    assert proposals == receipt["registry_candidate_proposals"]


def test_independent_agreement_without_terminal_provider_or_sink_is_visible_debt(
    tmp_path: Path,
):
    _seed_all(tmp_path, {"breadth": [_state("1")]})
    plan = K.build_application_skeptic_work_plan(tmp_path)
    item = plan["work_items"][0]
    receipt = K.adjudicate_application_skeptic(
        plan, [_assessment(item["work_item_id"], "AGREE_NEGATIVE")]
    )
    disposition = receipt["work_dispositions"][0]

    assert receipt["status"] == "COMPLETED_WITH_DEBT"
    assert disposition["disposition"] == "UNRESOLVED_DEBT"
    assert disposition["reason_code"] == "REGISTRY_SINK_UNAVAILABLE"
    review = disposition["mandatory_review_obligation"]
    assert review["schema_version"] == K.MANDATORY_REVIEW_SCHEMA
    assert review["proof_scope"] == "NONE"
    assert review["terminal_negative_authorized"] is False
    assert review["required_action"] == "VERIFY_ADDITIVE_CANDIDATE"
    assert review["obligation_digest"] == K._digest(
        {key: value for key, value in review.items() if key != "obligation_digest"}
    )


@pytest.mark.parametrize(
    "evidence_basis",
    ["IN_SCOPE_SOURCE", "PRIMARY_EXTERNAL_CITED", "IN_SCOPE_EXECUTION"],
)
def test_supporting_negative_evidence_reopens_generic_application_candidate(
    tmp_path: Path, evidence_basis: str
) -> None:
    _seed_all(tmp_path, {"breadth": [_state("1")]})
    plan = K.build_application_skeptic_work_plan(tmp_path)
    item = plan["work_items"][0]
    proposals: list[dict[str, object]] = []
    receipt = K.adjudicate_application_skeptic(
        plan,
        [
            _assessment(
                item["work_item_id"],
                "AGREE_NEGATIVE",
                evidence_basis=evidence_basis,
            )
        ],
        candidate_sink=proposals.append,
    )
    assert receipt["status"] == "COMPLETE"
    assert receipt["work_dispositions"][0]["disposition"] == (
        "REGISTRY_CANDIDATE_PROPOSED"
    )
    assert receipt["work_dispositions"][0]["reason_code"] == (
        "NONTERMINAL_NEGATIVE_SUPPORT_REOPENED"
    )
    assert proposals == receipt["registry_candidate_proposals"]


def test_legacy_inprocess_provider_replay_cannot_close_generic_application_candidate(
    tmp_path: Path,
) -> None:
    _seed_all(tmp_path, {"breadth": [_state("1")]})
    plan = K.build_application_skeptic_work_plan(tmp_path)
    item = plan["work_items"][0]
    authority: dict[str, object] = {
        "schema_version": NCEA.AUTHORITY_SCHEMA,
        "authority_kind": NCEA.AUTHENTICATED_EXHAUSTIVE_NEGATIVE_EXECUTION,
        "candidate_id": item["candidate_id"],
        "work_item_id": item["work_item_id"],
        "candidate_premise_ids": item["candidate_premise_ids"],
        "terminal_negative_authorized": True,
    }
    authority["authority_digest"] = hashlib.sha256(
        NCEA.canonical_json_bytes(authority)
    ).hexdigest()
    receipt = K.adjudicate_application_skeptic(
        plan,
        [_assessment(item["work_item_id"], "AGREE_NEGATIVE")],
        closure_authorities={item["work_item_id"]: authority},
        closure_provider_validator=lambda candidate: dict(candidate),
    )
    disposition = receipt["work_dispositions"][0]
    assert receipt["status"] == "COMPLETED_WITH_DEBT"
    assert disposition["disposition"] != "NEGATIVE_AGREEMENT"


def test_disagreement_emits_one_registry_proposal_through_injected_sink(tmp_path: Path):
    _seed_all(tmp_path, {"breadth": [_state("1")]})
    plan = K.build_application_skeptic_work_plan(tmp_path)
    item = plan["work_items"][0]
    proposals = []
    assessment = _assessment(
        item["work_item_id"],
        "DISAGREE_CANDIDATE",
        candidate={
            "title": "Bound step may expose a reachable state transition",
            "mechanism": "The cited guard does not cover the alternate path.",
            "harm": "State-dependent value may be processed inconsistently.",
        },
    )
    receipt = K.adjudicate_application_skeptic(
        plan, [assessment], candidate_sink=proposals.append
    )

    assert receipt["status"] == "COMPLETE"
    assert len(proposals) == 1
    assert proposals == receipt["registry_candidate_proposals"]
    assert proposals[0]["producer"] == "application_skeptic"
    assert proposals[0]["source_obligation_id"] == item["obligation_id"]
    assert receipt["work_dispositions"][0]["disposition"] == "REGISTRY_CANDIDATE_PROPOSED"


def test_disagreement_without_shared_registry_sink_remains_debt(tmp_path: Path):
    _seed_all(tmp_path, {"breadth": [_state("1")]})
    plan = K.build_application_skeptic_work_plan(tmp_path)
    item = plan["work_items"][0]
    receipt = K.adjudicate_application_skeptic(
        plan,
        [
            _assessment(
                item["work_item_id"],
                "DISAGREE_CANDIDATE",
                candidate={
                    "title": "Candidate",
                    "mechanism": "Mechanism",
                    "harm": "Harm",
                },
            )
        ],
    )

    assert receipt["status"] == "COMPLETED_WITH_DEBT"
    assert receipt["work_dispositions"][0]["reason_code"] == "REGISTRY_SINK_UNAVAILABLE"
    assert receipt["registry_candidate_proposals"] == []


@pytest.mark.parametrize(
    ("case", "outcome", "changes", "reason_code"),
    [
        ("missing", None, {}, "ASSESSMENT_UNAVAILABLE"),
        ("unavailable", "UNAVAILABLE", {"evidence_basis": "NONE", "evidence_sha256": ""}, "ASSESSOR_UNAVAILABLE"),
        ("inconclusive", "INCONCLUSIVE", {"evidence_basis": "NONE", "evidence_sha256": ""}, "ASSESSOR_INCONCLUSIVE"),
        ("invalid-outcome", "MAYBE", {}, "ASSESSMENT_OUTCOME_INVALID"),
        ("missing-identity", "INCONCLUSIVE", {"assessor_id": ""}, "ASSESSOR_IDENTITY_MISSING"),
        ("invalid-evidence", "DISAGREE_CANDIDATE", {"evidence_sha256": "not-a-digest", "candidate": {"title": "Candidate", "mechanism": "Mechanism", "harm": "Harm"}}, "ASSESSOR_EVIDENCE_INVALID"),
        ("invalid-candidate", "DISAGREE_CANDIDATE", {"candidate": {"title": "Candidate"}}, "CANDIDATE_SCHEMA_REJECTED"),
    ],
)
def test_every_nonproof_assessment_outcome_reopens_additive_candidate(
    tmp_path: Path,
    case: str,
    outcome: str | None,
    changes: dict[str, object],
    reason_code: str,
) -> None:
    _seed_all(tmp_path, {"breadth": [_state(case)]})
    plan = K.build_application_skeptic_work_plan(tmp_path)
    item = plan["work_items"][0]
    assessments = [] if outcome is None else [
        _assessment(item["work_item_id"], outcome, **changes)
    ]
    proposals: list[dict[str, object]] = []
    receipt = K.adjudicate_application_skeptic(
        plan,
        assessments,
        candidate_sink=proposals.append,
    )

    disposition = receipt["work_dispositions"][0]
    assert receipt["status"] == "COMPLETE"
    assert disposition["disposition"] == "REGISTRY_CANDIDATE_PROPOSED"
    assert disposition["reason_code"] == reason_code
    assert disposition["proof_scope"] == "NONE"
    assert disposition["terminal_negative_authorized"] is False
    assert proposals == receipt["registry_candidate_proposals"]
    assert len(proposals) == 1


def test_unavailable_and_unsupported_agreement_without_sink_are_typed_review_debt(
    tmp_path: Path,
):
    _seed_all(tmp_path, {"breadth": [_state("1"), _state("2")]})
    plan = K.build_application_skeptic_work_plan(tmp_path)
    one, two = [item["work_item_id"] for item in plan["work_items"]]
    receipt = K.adjudicate_application_skeptic(
        plan,
        [
            _assessment(one, "UNAVAILABLE", evidence_basis="NONE", evidence_sha256=""),
            _assessment(
                two,
                "AGREE_NEGATIVE",
                evidence_basis="EXTERNAL_UNRESEARCHED",
            ),
        ],
    )

    assert receipt["status"] == "COMPLETED_WITH_DEBT"
    assert {row["disposition"] for row in receipt["work_dispositions"]} == {
        "UNRESOLVED_DEBT"
    }
    assert receipt["unresolved_work_item_ids"] == sorted([one, two])
    for row in receipt["work_dispositions"]:
        review = row["mandatory_review_obligation"]
        assert review["schema_version"] == K.MANDATORY_REVIEW_SCHEMA
        assert review["proof_scope"] == "NONE"
        assert review["terminal_negative_authorized"] is False


def test_failed_registry_delivery_is_typed_review_not_false_closure(tmp_path: Path):
    _seed_all(tmp_path, {"breadth": [_state("delivery-failure")]})
    plan = K.build_application_skeptic_work_plan(tmp_path)
    item = plan["work_items"][0]

    def reject(_proposal):
        raise RuntimeError("fixture sink failure")

    receipt = K.adjudicate_application_skeptic(
        plan,
        [_assessment(item["work_item_id"], "INCONCLUSIVE")],
        candidate_sink=reject,
    )
    row = receipt["work_dispositions"][0]
    assert receipt["status"] == "COMPLETED_WITH_DEBT"
    assert row["disposition"] == "UNRESOLVED_DEBT"
    assert row["reason_code"] == "REGISTRY_DELIVERY_FAILED"
    assert row["mandatory_review_obligation"]["required_action"] == (
        "VERIFY_ADDITIVE_CANDIDATE"
    )


def test_last_good_preservation_requires_exact_run_snapshot_source_and_delivery(
    tmp_path: Path,
) -> None:
    _seed_all(tmp_path, {"breadth": [_state("last-good")]})
    plan = K.build_application_skeptic_work_plan(tmp_path)
    item = plan["work_items"][0]
    delivered: list[dict[str, object]] = []
    first = K.adjudicate_application_skeptic(
        plan,
        [_assessment(item["work_item_id"], "INCONCLUSIVE")],
        candidate_sink=delivered.append,
    )
    context = K.build_application_skeptic_preservation_context(
        plan,
        run_id="RUN-0001",
        snapshot_id="SNAPSHOT-0001",
        snapshot_binding_sha256="a" * 64,
    )
    delivery = K.build_application_skeptic_delivery_binding(
        plan,
        first,
        context=context,
        proposal_projection_sha256="b" * 64,
        delivered_proposal_ids=[delivered[0]["proposal_id"]],
    )
    current = K.adjudicate_application_skeptic(plan, [], candidate_sink=None)

    preserved, changed = K.preserve_last_good_application_candidates(
        plan,
        current_receipt=current,
        last_good_receipt=first,
        current_context=context,
        last_good_delivery=delivery,
    )
    assert changed is True
    assert preserved["registry_candidate_proposals"] == first[
        "registry_candidate_proposals"
    ]
    assert preserved["work_dispositions"][0]["disposition"] == (
        "REGISTRY_CANDIDATE_PROPOSED"
    )
    assert preserved["status"] == "COMPLETED_WITH_DEBT"
    assert any(
        issue.get("code") == "LAST_GOOD_ADDITIVE_CANDIDATE_PRESERVED"
        for issue in preserved["source_input_issues"]
    )

    drifted_context = K.build_application_skeptic_preservation_context(
        plan,
        run_id="RUN-0001",
        snapshot_id="SNAPSHOT-0002",
        snapshot_binding_sha256="c" * 64,
    )
    rejected, changed = K.preserve_last_good_application_candidates(
        plan,
        current_receipt=current,
        last_good_receipt=first,
        current_context=drifted_context,
        last_good_delivery=delivery,
    )
    assert changed is False
    assert rejected == current


def test_last_good_preservation_never_reuses_negative_closure(tmp_path: Path) -> None:
    _seed_all(tmp_path, {"breadth": [_state("negative-not-cacheable")]})
    plan = K.build_application_skeptic_work_plan(tmp_path)
    item = plan["work_items"][0]
    authority: dict[str, object] = {
        "schema_version": NCEA.AUTHORITY_SCHEMA,
        "authority_kind": NCEA.AUTHENTICATED_EXHAUSTIVE_NEGATIVE_EXECUTION,
        "candidate_id": item["candidate_id"],
        "work_item_id": item["work_item_id"],
        "candidate_premise_ids": item["candidate_premise_ids"],
        "terminal_negative_authorized": True,
    }
    authority["authority_digest"] = hashlib.sha256(
        NCEA.canonical_json_bytes(authority)
    ).hexdigest()
    negative = K.adjudicate_application_skeptic(
        plan,
        [_assessment(item["work_item_id"], "AGREE_NEGATIVE")],
        closure_authorities={item["work_item_id"]: authority},
        closure_provider_validator=lambda candidate: dict(candidate),
    )
    context = K.build_application_skeptic_preservation_context(
        plan,
        run_id="RUN-0001",
        snapshot_id="SNAPSHOT-0001",
        snapshot_binding_sha256="a" * 64,
    )
    current = K.adjudicate_application_skeptic(plan, [], candidate_sink=None)
    delivery = K.build_application_skeptic_delivery_binding(
        plan,
        negative,
        context=context,
        proposal_projection_sha256="b" * 64,
        delivered_proposal_ids=[],
    )
    preserved, changed = K.preserve_last_good_application_candidates(
        plan,
        current_receipt=current,
        last_good_receipt=negative,
        current_context=context,
        last_good_delivery=delivery,
    )
    assert changed is False
    assert preserved == current


def test_partial_receipt_resumes_without_re_adjudicating_completed_work(tmp_path: Path):
    _seed_all(tmp_path, {"breadth": [_state("1"), _state("2"), _state("3")]})
    plan = K.build_application_skeptic_work_plan(tmp_path, max_items_per_shard=2)
    ids = [item["work_item_id"] for item in plan["work_items"]]
    proposals: list[dict[str, object]] = []
    first = K.adjudicate_application_skeptic(
        plan,
        [_assessment(ids[0], "AGREE_NEGATIVE")],
        defer_missing=True,
        candidate_sink=proposals.append,
    )
    assert first["status"] == "PARTIAL"
    assert K.pending_work_item_ids(plan, first) == ids[1:]

    second = K.adjudicate_application_skeptic(
        plan,
        [_assessment(ids[1], "AGREE_NEGATIVE"), _assessment(ids[2], "AGREE_NEGATIVE")],
        prior_receipt=first,
        defer_missing=True,
        candidate_sink=proposals.append,
    )
    assert second["status"] == "COMPLETE"
    assert K.pending_work_item_ids(plan, second) == []
    assert len(second["work_dispositions"]) == 3
