"""P0-AG direction-neutral severity decision ledger fixtures.

These tests deliberately exercise the policy independently of the legacy
Markdown parser.  Integration may only consume the typed receipt after this
contract is stable.
"""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

from severity_decision_ledger import (
    SeverityDecisionError,
    adjudicate_severity_challenge,
    bind_severity_adjudication,
    bind_severity_proposal,
    build_severity_decision,
    build_severity_repair_request,
    compile_severity_prompt_contract,
    load_severity_decision_ledger,
    project_report_severity,
    required_assessment_fields,
    required_proposal_fields,
    severity_adjudicator_input_digest,
    severity_assessor_input_digest,
    validate_report_severity_projection,
    write_severity_decision_ledger,
)


def _assessment(**overrides):
    value = {
        "candidate_id": "HYP-001",
        "run_id": "run-1",
        "source_receipt_digest": "a" * 64,
        "constituent_ids": ["HYP-001"],
        "upstream_severity": "High",
        "assessor_identity": "verify-worker-a",
        "assessor_invocation_id": "verify-run-a",
        "impact": {
            "class": "High",
            "harmed_asset": "protocol-controlled value",
            "harmed_capability": "availability of protected value",
            "premise_id": "PREM-IMPACT-1",
            "premise_kind": "INTERNAL",
            "evidence_ids": ["EVID-1"],
            "proof_scope": "IN_SCOPE_EXECUTION",
        },
        "likelihood": {
            "class": "Medium",
            "actor": "unprivileged caller",
            "preconditions": ["reachable state"],
            "premise_id": "PREM-LIKE-1",
            "premise_kind": "INTERNAL",
            "evidence_ids": ["EVID-2"],
            "proof_scope": "IN_SCOPE_SOURCE",
        },
        "modifiers": [],
        "proposed_severity": "High",
        "adjustment": None,
        "constituent_premise_outcomes": {
            "HYP-001": {
                "impact": "SUPPORTED",
                "likelihood": "SUPPORTED",
            }
        },
        "evidence_receipts": [
            {
                "evidence_id": "EVID-1",
                "content_sha256": "1" * 64,
                "premise_ids": ["PREM-IMPACT-1"],
                "constituent_ids": ["HYP-001"],
                "proof_scope": "IN_SCOPE_EXECUTION",
                "issuer_identity": "evidence-runner",
                "issuer_invocation_id": "evidence-run-1",
            },
            {
                "evidence_id": "EVID-2",
                "content_sha256": "2" * 64,
                "premise_ids": ["PREM-LIKE-1"],
                "constituent_ids": ["HYP-001"],
                "proof_scope": "IN_SCOPE_SOURCE",
                "issuer_identity": "evidence-runner",
                "issuer_invocation_id": "evidence-run-1",
            },
        ],
    }
    value.update(overrides)
    return value


def _driver_bound_decision(assessment):
    proposal = {
        "schema_version": "plamen.severity_proposal.v1",
        "candidate_id": assessment["candidate_id"],
        "constituent_ids": list(assessment["constituent_ids"]),
        "impact": assessment["impact"],
        "likelihood": assessment["likelihood"],
        "modifiers": assessment["modifiers"],
        "proposed_severity": assessment["proposed_severity"],
        "adjustment": assessment["adjustment"],
        "constituent_premise_outcomes": assessment[
            "constituent_premise_outcomes"
        ],
    }
    impact_ids = set((assessment.get("impact") or {}).get("evidence_ids") or [])
    likelihood_ids = set(
        (assessment.get("likelihood") or {}).get("evidence_ids") or []
    )
    evidence = []
    for row in assessment.get("evidence_receipts") or []:
        capabilities = {"EXECUTION"}
        if row["evidence_id"] in impact_ids:
            capabilities.update({"IMPACT", "HARM"})
        if row["evidence_id"] in likelihood_ids:
            capabilities.add("LIKELIHOOD")
        evidence.append({**row, "capabilities": sorted(capabilities)})
    output_sha256 = hashlib.sha256(
        json.dumps(
            proposal,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    return bind_severity_proposal(
        proposal,
        candidate_id=assessment["candidate_id"],
        constituent_ids=assessment["constituent_ids"],
        upstream_severity=assessment["upstream_severity"],
        assessor_identity=assessment["assessor_identity"],
        assessor_invocation_id=assessment["assessor_invocation_id"],
        run_id=assessment["run_id"],
        source_receipt_digest=assessment["source_receipt_digest"],
        evidence_receipts=evidence,
        assessor_launch_receipt={
            "schema_version": "plamen.severity_launch_receipt.v2",
            "role": "ASSESSOR",
            "run_id": assessment["run_id"],
            "candidate_id": assessment["candidate_id"],
            "constituent_ids": list(assessment["constituent_ids"]),
            "worker_identity": assessment["assessor_identity"],
            "invocation_id": assessment["assessor_invocation_id"],
            "backend": "claude",
            "launch_manifest_sha256": "8" * 64,
            "input_sha256": severity_assessor_input_digest(
                candidate_id=assessment["candidate_id"],
                constituent_ids=assessment["constituent_ids"],
                upstream_severity=assessment["upstream_severity"],
                run_id=assessment["run_id"],
                source_receipt_digest=assessment["source_receipt_digest"],
                evidence_receipts=evidence,
            ),
            "output_sha256": output_sha256,
        },
    )


def _driver_adjudicate(decision, event):
    proposal = {
        "schema_version": "plamen.severity_adjudication_proposal.v1",
        "decision": event["decision"],
        "resolved_severity": event["resolved_severity"],
        "resolved_premise_ids": event["resolved_premise_ids"],
        "evidence_ids": event["evidence_ids"],
        "proof_scope": event["proof_scope"],
        "rationale": event["rationale"],
        "resolved_axes": event["resolved_axes"],
        "constituent_resolutions": event.get("constituent_resolutions") or {},
    }
    output_sha256 = hashlib.sha256(
        json.dumps(
            proposal,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    return bind_severity_adjudication(
        proposal,
        decision=decision,
        adjudicator_launch_receipt={
            "schema_version": "plamen.severity_launch_receipt.v2",
            "role": "ADJUDICATOR",
            "run_id": decision["run_id"],
            "candidate_id": decision["candidate_id"],
            "constituent_ids": list(decision["constituent_ids"]),
            "worker_identity": event["adjudicator_identity"],
            "invocation_id": event["adjudicator_invocation_id"],
            "backend": "claude",
            "launch_manifest_sha256": "9" * 64,
            "input_sha256": severity_adjudicator_input_digest(decision),
            "output_sha256": output_sha256,
        },
    )


def _adjudication(context_decision=None, **overrides):
    value = {
        "adjudicator_identity": "severity-reviewer-b",
        "adjudicator_invocation_id": "severity-run-b",
        "decision": "ACCEPT_PROPOSED",
        "resolved_severity": "Medium",
        "resolved_premise_ids": ["PREM-LIKE-1"],
        "evidence_ids": ["EVID-2"],
        "proof_scope": "IN_SCOPE_SOURCE",
        "rationale": "The likelihood premise is independently resolved.",
        "resolved_axes": {"impact": "High", "likelihood": "Low"},
    }
    if context_decision is not None:
        value.update(
            {
                "run_id": context_decision["run_id"],
                "source_receipt_digest": context_decision["source_receipt_digest"],
                "source_decision_digest": context_decision["decision_digest"],
                "candidate_id": context_decision["candidate_id"],
                "constituent_ids": list(context_decision["constituent_ids"]),
                "prior_severity": context_decision["retention_severity"],
            }
        )
    value.update(overrides)
    return value


def test_complete_equal_assessment_is_resolved_without_challenge():
    decision = build_severity_decision(_assessment())
    assert decision["status"] == "RESOLVED"
    assert decision["matrix_severity"] == "High"
    assert decision["retention_severity"] == "High"
    assert decision["final_severity"] == "High"


@pytest.mark.parametrize("proposed", ["Medium", "Critical"])
def test_any_directional_disagreement_requires_independent_adjudication(proposed):
    assessment = _assessment(proposed_severity=proposed)
    decision = build_severity_decision(assessment)
    assert decision["status"] == "CHALLENGE_REQUIRED"
    assert decision["final_severity"] is None
    assert decision["retention_severity"] == "High"
    assert "PROPOSED_MATRIX_DISAGREEMENT" in decision["challenge_codes"]


def test_downward_adjustment_without_evidence_is_not_authority():
    assessment = _assessment(
        proposed_severity="Medium",
        adjustment={
            "direction": "DOWN",
            "premise_ids": ["PREM-LIKE-1"],
            "evidence_ids": [],
            "proof_scope": "IN_SCOPE_EXECUTION",
            "rationale": "claimed reduction",
        },
    )
    decision = build_severity_decision(assessment)
    assert decision["status"] == "CHALLENGE_REQUIRED"
    assert "ADJUSTMENT_EVIDENCE_MISSING" in decision["challenge_codes"]
    assert decision["retention_severity"] == "High"


def test_adjustment_evidence_still_requires_independent_author():
    assessment = _assessment(
        proposed_severity="Medium",
        adjustment={
            "direction": "DOWN",
            "premise_ids": ["PREM-LIKE-1"],
            "evidence_ids": ["EVID-2"],
            "proof_scope": "IN_SCOPE_SOURCE",
            "rationale": "evidence-bound reduction",
        },
    )
    decision = build_severity_decision(assessment)
    assert decision["status"] == "CHALLENGE_REQUIRED"
    resolved = adjudicate_severity_challenge(decision, _adjudication(decision))
    assert resolved["status"] == "RESOLVED"
    assert resolved["final_severity"] == "Medium"


def test_self_adjudication_cannot_resolve_a_challenge():
    decision = build_severity_decision(
        _assessment(proposed_severity="Medium")
    )
    adjudication = _adjudication(
        decision,
        adjudicator_identity="verify-worker-a",
        adjudicator_invocation_id="verify-run-a",
    )
    resolved = adjudicate_severity_challenge(decision, adjudication)
    assert resolved["status"] == "UNRESOLVED_SEVERITY"
    assert resolved["retention_severity"] == "High"
    assert resolved["final_severity"] is None
    assert "SELF_ADJUDICATION" in resolved["challenge_codes"]


@pytest.mark.parametrize("axis", ["impact", "likelihood"])
@pytest.mark.parametrize("upstream", ["Critical", "High", "Medium"])
def test_missing_axis_preserves_upstream_and_requests_only_missing_delta(axis, upstream):
    assessment = _assessment(upstream_severity=upstream, proposed_severity=upstream)
    assessment[axis] = None
    decision = build_severity_decision(assessment)
    assert decision["status"] == "INCOMPLETE"
    assert decision["retention_severity"] == upstream
    assert decision["final_severity"] is None
    repair = build_severity_repair_request(decision)
    assert repair["missing_fields"] == [axis]


def test_no_axes_never_caps_high_to_medium():
    decision = build_severity_decision(
        _assessment(impact=None, likelihood=None, upstream_severity="Critical")
    )
    assert decision["retention_severity"] == "Critical"
    assert set(build_severity_repair_request(decision)["missing_fields"]) == {
        "impact",
        "likelihood",
    }


def test_modifier_requires_structured_applicability_and_evidence():
    assessment = _assessment(
        modifiers=[
            {
                "kind": "VIEW_FUNCTION_ONLY",
                "applies": True,
                "applicability_predicate": "",
                "evidence_ids": [],
                "proof_scope": "IN_SCOPE_SOURCE",
            }
        ]
    )
    decision = build_severity_decision(assessment)
    assert "MODIFIER_APPLICABILITY_UNPROVEN" in decision["challenge_codes"]
    assert decision["matrix_severity"] == "High"


def test_valid_modifier_is_applied_structurally_not_from_prose():
    assessment = _assessment(
        upstream_severity="Medium",
        proposed_severity="Medium",
        impact={
            **_assessment()["impact"],
            "class": "High",
        },
        likelihood={
            **_assessment()["likelihood"],
            "class": "High",
        },
        modifiers=[
            {
                "kind": "VIEW_FUNCTION_ONLY",
                "applies": True,
                "applicability_predicate": "reachable path is read-only",
                "evidence_ids": ["EVID-VIEW"],
                "proof_scope": "IN_SCOPE_SOURCE",
            }
        ],
        evidence_receipts=[
            *_assessment()["evidence_receipts"],
            {
                "evidence_id": "EVID-VIEW",
                "content_sha256": "3" * 64,
                "premise_ids": ["PREM-LIKE-1"],
                "constituent_ids": ["HYP-001"],
                "proof_scope": "IN_SCOPE_SOURCE",
                "issuer_identity": "evidence-runner",
                "issuer_invocation_id": "evidence-run-1",
            },
        ],
    )
    decision = build_severity_decision(assessment)
    assert decision["matrix_severity"] == "Medium"
    assert decision["status"] == "CHALLENGE_REQUIRED"  # upstream changed


def test_incompatible_modifier_stacking_is_debt_not_double_discount():
    modifiers = [
        {
            "kind": kind,
            "applies": True,
            "applicability_predicate": "typed fact",
            "evidence_ids": [f"EVID-{kind}"],
            "proof_scope": "IN_SCOPE_SOURCE",
        }
        for kind in ("VIEW_FUNCTION_ONLY", "ONCHAIN_STATE_ONLY")
    ]
    decision = build_severity_decision(_assessment(modifiers=modifiers))
    assert "INCOMPATIBLE_MODIFIER_SET" in decision["challenge_codes"]
    assert decision["matrix_severity"] == "High"


def test_compatible_modifier_stacking_is_deterministic():
    modifiers = [
        {
            "kind": kind,
            "applies": True,
            "applicability_predicate": "typed fact",
            "evidence_ids": [f"EVID-{kind}"],
            "proof_scope": "IN_SCOPE_SOURCE",
        }
        for kind in ("ONCHAIN_STATE_ONLY", "FULLY_TRUSTED_ACTOR")
    ]
    assessment = _assessment(
        upstream_severity="Medium",
        proposed_severity="Medium",
        impact={**_assessment()["impact"], "class": "High"},
        likelihood={**_assessment()["likelihood"], "class": "High"},
        modifiers=modifiers,
        evidence_receipts=[
            *_assessment()["evidence_receipts"],
            *[
                {
                    "evidence_id": f"EVID-{kind}",
                    "content_sha256": digest * 64,
                    "premise_ids": ["PREM-LIKE-1"],
                    "constituent_ids": ["HYP-001"],
                    "proof_scope": "IN_SCOPE_SOURCE",
                    "issuer_identity": "evidence-runner",
                    "issuer_invocation_id": "evidence-run-1",
                }
                for kind, digest in (
                    ("ONCHAIN_STATE_ONLY", "3"),
                    ("FULLY_TRUSTED_ACTOR", "4"),
                )
            ],
        ],
    )
    decision = build_severity_decision(assessment)
    assert decision["matrix_severity"] == "Medium"
    assert "INCOMPATIBLE_MODIFIER_SET" not in decision["challenge_codes"]


def test_grouped_constituent_outcome_divergence_cannot_be_flattened():
    assessment = _assessment(
        constituent_ids=["HYP-001", "HYP-002"],
        constituent_premise_outcomes={
            "HYP-001": {"impact": "SUPPORTED", "likelihood": "SUPPORTED"},
            "HYP-002": {"impact": "SUPPORTED", "likelihood": "REFUTED"},
        },
    )
    decision = build_severity_decision(assessment)
    assert "CONSTITUENT_OUTCOME_DIVERGENCE" in decision["challenge_codes"]
    assert decision["status"] == "CHALLENGE_REQUIRED"


def test_adjudicator_unavailable_preserves_upstream_visibility():
    decision = build_severity_decision(_assessment(proposed_severity="Medium"))
    unresolved = adjudicate_severity_challenge(
        decision,
        _adjudication(
            decision="UNRESOLVED",
            resolved_severity=None,
            resolved_premise_ids=[],
            evidence_ids=[],
            proof_scope="NONE",
        ),
    )
    assert unresolved["status"] == "UNRESOLVED_SEVERITY"
    assert unresolved["retention_severity"] == "High"
    assert unresolved["final_severity"] is None


def test_uncited_favorable_external_premise_cannot_authorize_demotion():
    assessment = _assessment(
        proposed_severity="Medium",
        likelihood={
            **_assessment()["likelihood"],
            "premise_kind": "EXTERNAL_FAVORABLE",
            "proof_scope": "IN_SCOPE_SOURCE",
        },
        adjustment={
            "direction": "DOWN",
            "premise_ids": ["PREM-LIKE-1"],
            "evidence_ids": ["EVID-EXT-STUB"],
            "proof_scope": "IN_SCOPE_SOURCE",
            "rationale": "assumes favorable external behavior",
        },
    )
    decision = build_severity_decision(assessment)
    assert "EXTERNAL_FAVORABLE_PREMISE_UNPROVEN" in decision["challenge_codes"]
    assert decision["retention_severity"] == "High"


def test_cited_external_premise_and_internal_premise_do_not_trigger_r10_rule():
    cited = _assessment(
        proposed_severity="Medium",
        likelihood={
            **_assessment()["likelihood"],
            "premise_kind": "EXTERNAL_FAVORABLE",
            "proof_scope": "PRIMARY_EXTERNAL_CITED",
        },
        adjustment={
            "direction": "DOWN",
            "premise_ids": ["PREM-LIKE-1"],
            "evidence_ids": ["EVID-PRIMARY"],
            "proof_scope": "PRIMARY_EXTERNAL_CITED",
            "rationale": "primary source resolves external behavior",
        },
    )
    internal = _assessment(proposed_severity="Medium")
    for value in (cited, internal):
        decision = build_severity_decision(value)
        assert "EXTERNAL_FAVORABLE_PREMISE_UNPROVEN" not in decision["challenge_codes"]


def test_depth_side_under_rating_becomes_challenge_not_silent_floor():
    decision = build_severity_decision(
        _assessment(upstream_severity="Low", proposed_severity="Low")
    )
    assert decision["matrix_severity"] == "High"
    assert decision["status"] == "CHALLENGE_REQUIRED"
    assert "PROPOSED_MATRIX_DISAGREEMENT" in decision["challenge_codes"]
    assert decision["retention_severity"] == "Low"


def test_adjudication_must_bind_a_known_premise_and_capable_evidence():
    decision = build_severity_decision(_assessment(proposed_severity="Medium"))
    unknown = adjudicate_severity_challenge(
        decision,
        _adjudication(decision, resolved_premise_ids=["PREM-UNKNOWN"]),
    )
    assert unknown["status"] == "UNRESOLVED_SEVERITY"
    assert "ADJUDICATION_PREMISE_UNBOUND" in unknown["challenge_codes"]


def test_report_projection_uses_resolved_or_retention_authority_and_detects_drift():
    resolved = _driver_bound_decision(_assessment())
    projection = project_report_severity(resolved)
    assert projection == {
        "candidate_id": "HYP-001",
        "severity": "High",
        "severity_status": "RESOLVED",
        "decision_digest": resolved["decision_digest"],
        "constituent_dispositions": {
            "HYP-001": {
                "impact": "SUPPORTED",
                "likelihood": "SUPPORTED",
                "disposition": "INCLUDED_RESOLVED",
                "severity": "High",
                "severity_status": "RESOLVED",
            }
        },
    }
    validate_report_severity_projection(resolved, projection)

    challenged = _driver_bound_decision(
        _assessment(proposed_severity="Medium")
    )
    unresolved_projection = project_report_severity(challenged)
    assert unresolved_projection["severity"] == "High"
    assert unresolved_projection["severity_status"] == "UNRESOLVED_SEVERITY"
    drifted = dict(unresolved_projection, severity="Medium")
    with pytest.raises(SeverityDecisionError, match="projection drift"):
        validate_report_severity_projection(challenged, drifted)


def test_prompt_contract_and_consumer_required_fields_have_exact_parity():
    contract = compile_severity_prompt_contract()
    assert set(contract["required_fields"]) == set(required_proposal_fields())
    assert set(contract["json_schema"]["required"]) == set(
        required_proposal_fields()
    )
    assert not {
        "assessor_identity",
        "assessor_invocation_id",
        "upstream_severity",
        "run_id",
        "source_receipt_digest",
        "evidence_receipts",
    } & set(contract["json_schema"]["properties"])


def test_removing_prompt_schema_field_fails_parity():
    contract = compile_severity_prompt_contract()
    contract["required_fields"].remove("likelihood")
    assert set(contract["required_fields"]) != set(required_proposal_fields())


def test_ledger_write_load_is_idempotent_and_tamper_evident(tmp_path: Path):
    decision = build_severity_decision(_assessment())
    path = tmp_path / "severity_decision_ledger.json"
    first = write_severity_decision_ledger(path, "run-1", [decision])
    first_bytes = path.read_bytes()
    second = write_severity_decision_ledger(path, "run-1", [decision])
    assert first == second
    assert path.read_bytes() == first_bytes
    assert load_severity_decision_ledger(
        path,
        expected_run_id="run-1",
        expected_source_receipt_digests={"HYP-001": "a" * 64},
    ) == first

    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["decisions"][0]["retention_severity"] = "Low"
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(SeverityDecisionError, match="digest"):
        load_severity_decision_ledger(path, expected_run_id="run-1")


def test_ledger_rejects_duplicate_identity_and_cross_run_resume(tmp_path: Path):
    decision = build_severity_decision(_assessment())
    path = tmp_path / "severity_decision_ledger.json"
    with pytest.raises(SeverityDecisionError, match="duplicate"):
        write_severity_decision_ledger(path, "run-1", [decision, copy.deepcopy(decision)])
    write_severity_decision_ledger(path, "run-1", [decision])
    with pytest.raises(SeverityDecisionError, match="run"):
        load_severity_decision_ledger(path, expected_run_id="run-2")


@pytest.mark.parametrize(
    ("field", "foreign"),
    [
        ("run_id", "run-foreign"),
        ("source_receipt_digest", "b" * 64),
        ("source_decision_digest", "c" * 64),
        ("candidate_id", "HYP-FOREIGN"),
        ("constituent_ids", ["HYP-FOREIGN"]),
        ("prior_severity", "Low"),
    ],
)
def test_adjudication_event_is_exactly_bound_to_its_source_decision(field, foreign):
    decision = _driver_bound_decision(
        _assessment(
            proposed_severity="Medium",
            adjustment={
                "direction": "DOWN",
                "premise_ids": ["PREM-LIKE-1"],
                "evidence_ids": ["EVID-2"],
                "proof_scope": "IN_SCOPE_SOURCE",
                "rationale": "evidence-bound reduction",
            },
        )
    )
    event = _adjudication(decision)
    event[field] = foreign
    result = adjudicate_severity_challenge(decision, event)
    assert result["status"] == "UNRESOLVED_SEVERITY"
    assert "ADJUDICATION_CONTEXT_UNBOUND" in result["challenge_codes"]


def test_exact_event_cannot_be_replayed_for_another_candidate():
    first = build_severity_decision(
        _assessment(
            proposed_severity="Medium",
            adjustment={
                "direction": "DOWN",
                "premise_ids": ["PREM-LIKE-1"],
                "evidence_ids": ["EVID-2"],
                "proof_scope": "IN_SCOPE_SOURCE",
                "rationale": "evidence-bound reduction",
            },
        )
    )
    event = _adjudication(first)
    assert adjudicate_severity_challenge(first, event)["status"] == "RESOLVED"

    second_member = "HYP-002"
    second = build_severity_decision(
        _assessment(
            candidate_id=second_member,
            constituent_ids=[second_member],
            source_receipt_digest="b" * 64,
            proposed_severity="Medium",
            adjustment={
                "direction": "DOWN",
                "premise_ids": ["PREM-LIKE-1"],
                "evidence_ids": ["EVID-2"],
                "proof_scope": "IN_SCOPE_SOURCE",
                "rationale": "evidence-bound reduction",
            },
            constituent_premise_outcomes={
                second_member: {"impact": "SUPPORTED", "likelihood": "SUPPORTED"}
            },
            evidence_receipts=[
                {**row, "constituent_ids": [second_member]}
                for row in _assessment()["evidence_receipts"]
            ],
        )
    )
    replayed = adjudicate_severity_challenge(second, event)
    assert replayed["status"] == "UNRESOLVED_SEVERITY"
    assert "ADJUDICATION_CONTEXT_UNBOUND" in replayed["challenge_codes"]


def test_attested_adjudication_requires_explicit_axes_not_target_inference():
    decision = _driver_bound_decision(
        _assessment(
            proposed_severity="Medium",
            adjustment={
                "direction": "DOWN",
                "premise_ids": ["PREM-LIKE-1"],
                "evidence_ids": ["EVID-2"],
                "proof_scope": "IN_SCOPE_SOURCE",
                "rationale": "evidence-bound reduction",
            },
        )
    )
    result = adjudicate_severity_challenge(
        decision, _adjudication(decision, resolved_axes=None)
    )
    assert result["status"] == "UNRESOLVED_SEVERITY"
    assert "ADJUDICATION_AXES_UNRESOLVED" in result["challenge_codes"]


def test_legitimate_member_resolution_remains_visible_in_report_projection():
    members = ["HYP-001", "HYP-002"]
    receipts = [
        {**row, "constituent_ids": members}
        for row in _assessment()["evidence_receipts"]
    ]
    decision = _driver_bound_decision(
        _assessment(
            constituent_ids=members,
            proposed_severity="Medium",
            adjustment={
                "direction": "DOWN",
                "premise_ids": ["PREM-LIKE-1"],
                "evidence_ids": ["EVID-2"],
                "proof_scope": "IN_SCOPE_SOURCE",
                "rationale": "evidence-bound member resolution",
            },
            constituent_premise_outcomes={
                "HYP-001": {"impact": "SUPPORTED", "likelihood": "SUPPORTED"},
                "HYP-002": {"impact": "SUPPORTED", "likelihood": "UNRESOLVED"},
            },
            evidence_receipts=receipts,
        )
    )
    result = _driver_adjudicate(
        decision,
        _adjudication(
            decision,
            constituent_resolutions={
                "HYP-001": {"impact": "SUPPORTED", "likelihood": "SUPPORTED"},
                "HYP-002": {"impact": "SUPPORTED", "likelihood": "REFUTED"},
            },
        ),
    )
    assert result["status"] == "RESOLVED"
    projection = project_report_severity(result)
    assert projection["constituent_dispositions"]["HYP-001"]["disposition"] == (
        "INCLUDED_RESOLVED"
    )
    assert projection["constituent_dispositions"]["HYP-002"]["disposition"] == (
        "RETAINED_REFUTED_PREMISE"
    )


def test_authoritative_load_requires_external_source_receipt_authority(tmp_path: Path):
    path = tmp_path / "severity_decision_ledger.json"
    decision = _driver_bound_decision(_assessment())
    write_severity_decision_ledger(path, "run-1", [decision])
    with pytest.raises(SeverityDecisionError, match="external source authority"):
        load_severity_decision_ledger(path, expected_run_id="run-1")
    with pytest.raises(SeverityDecisionError, match="external source authority"):
        load_severity_decision_ledger(
            path,
            expected_run_id="run-1",
            expected_source_receipt_digests={"HYP-001": "b" * 64},
        )
    loaded = load_severity_decision_ledger(
        path,
        expected_run_id="run-1",
        expected_source_receipt_digests={"HYP-001": "a" * 64},
    )
    assert loaded["authority_status"] == "REPORT_AUTHORITATIVE"
