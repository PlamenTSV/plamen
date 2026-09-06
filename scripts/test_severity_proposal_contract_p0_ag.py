"""Fixture-first live producer/authority contract for P0-AG severity."""
from __future__ import annotations

import json
import hashlib
from pathlib import Path

import pytest

from severity_decision_ledger import (
    SeverityDecisionError,
    adjudicate_severity_challenge,
    bind_severity_adjudication,
    bind_severity_proposal,
    build_severity_repair_request,
    compile_severity_prompt_contract,
    load_severity_decision_ledger,
    parse_severity_proposal,
    project_report_severity,
    project_retention_severity,
    severity_adjudicator_input_digest,
    severity_assessor_input_digest,
    write_severity_decision_ledger,
)


RUN_ID = "severity-runtime-run"
SOURCE_DIGEST = "a" * 64


def _proposal(**overrides):
    value = {
        "schema_version": "plamen.severity_proposal.v1",
        "candidate_id": "HYP-1",
        "constituent_ids": ["HYP-1"],
        "impact": {
            "class": "High",
            "harmed_asset": "protected asset",
            "harmed_capability": "asset availability",
            "premise_id": "PREM-IMPACT",
            "premise_kind": "INTERNAL",
            "evidence_ids": ["EVID-IMPACT"],
            "proof_scope": "IN_SCOPE_EXECUTION",
        },
        "likelihood": {
            "class": "Low",
            "actor": "unprivileged actor",
            "preconditions": ["reachable state"],
            "premise_id": "PREM-LIKELIHOOD",
            "premise_kind": "INTERNAL",
            "evidence_ids": ["EVID-LIKELIHOOD"],
            "proof_scope": "IN_SCOPE_EXECUTION",
        },
        "modifiers": [],
        "proposed_severity": "Medium",
        "adjustment": {
            "direction": "DOWN",
            "premise_ids": ["PREM-LIKELIHOOD"],
            "evidence_ids": ["EVID-LIKELIHOOD"],
            "proof_scope": "IN_SCOPE_EXECUTION",
            "rationale": "The likelihood premise is lower than upstream.",
        },
        "constituent_premise_outcomes": {
            "HYP-1": {"impact": "SUPPORTED", "likelihood": "SUPPORTED"}
        },
    }
    value.update(overrides)
    return value


def _evidence(*, mechanism_only: bool = False):
    likelihood_capabilities = (
        ["EXECUTION", "MECHANISM"]
        if mechanism_only else
        ["EXECUTION", "LIKELIHOOD"]
    )
    return [
        {
            "evidence_id": "EVID-IMPACT",
            "content_sha256": "1" * 64,
            "premise_ids": ["PREM-IMPACT"],
            "constituent_ids": ["HYP-1"],
            "proof_scope": "IN_SCOPE_EXECUTION",
            "capabilities": ["EXECUTION", "IMPACT", "HARM"],
            "issuer_identity": "mechanical-evidence-registry",
            "issuer_invocation_id": "mechanical-run-1",
        },
        {
            "evidence_id": "EVID-LIKELIHOOD",
            "content_sha256": "2" * 64,
            "premise_ids": ["PREM-LIKELIHOOD"],
            "constituent_ids": ["HYP-1"],
            "proof_scope": "IN_SCOPE_EXECUTION",
            "capabilities": likelihood_capabilities,
            "issuer_identity": "mechanical-evidence-registry",
            "issuer_invocation_id": "mechanical-run-1",
        },
    ]


def _bind(proposal=None, *, evidence=None):
    proposal_value = _proposal() if proposal is None else proposal
    proposal_sha256 = hashlib.sha256(
        json.dumps(
            proposal_value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    return bind_severity_proposal(
        proposal_value,
        candidate_id="HYP-1",
        constituent_ids=["HYP-1"],
        upstream_severity="High",
        assessor_identity="verifier-worker",
        assessor_invocation_id="verify-invocation-1",
        run_id=RUN_ID,
        source_receipt_digest=SOURCE_DIGEST,
        evidence_receipts=_evidence() if evidence is None else evidence,
        assessor_launch_receipt={
            "schema_version": "plamen.severity_launch_receipt.v2",
            "role": "ASSESSOR",
            "run_id": RUN_ID,
            "candidate_id": "HYP-1",
            "constituent_ids": ["HYP-1"],
            "worker_identity": "verifier-worker",
            "invocation_id": "verify-invocation-1",
            "backend": "claude",
            "launch_manifest_sha256": "3" * 64,
            "input_sha256": severity_assessor_input_digest(
                candidate_id="HYP-1",
                constituent_ids=["HYP-1"],
                upstream_severity="High",
                run_id=RUN_ID,
                source_receipt_digest=SOURCE_DIGEST,
                evidence_receipts=_evidence() if evidence is None else evidence,
            ),
            "output_sha256": proposal_sha256,
        },
    )


def test_compiled_schema_is_nested_and_excludes_driver_authority_fields():
    contract = compile_severity_prompt_contract()
    schema = contract["json_schema"]
    assert schema["additionalProperties"] is False
    assert schema["properties"]["impact"]["additionalProperties"] is False
    assert schema["properties"]["likelihood"]["additionalProperties"] is False
    assert schema["properties"]["adjustment"]["anyOf"][1][
        "additionalProperties"
    ] is False
    forbidden = {
        "run_id", "source_receipt_digest", "assessor_identity",
        "assessor_invocation_id", "evidence_receipts",
    }
    assert not (forbidden & set(schema["properties"]))
    assert json.dumps(schema, sort_keys=True) in contract["markdown"]


def test_strict_proposal_parser_rejects_extra_duplicate_and_missing_fields():
    assert parse_severity_proposal(json.dumps(_proposal()))["candidate_id"] == "HYP-1"
    with pytest.raises(SeverityDecisionError):
        parse_severity_proposal(
            json.dumps({**_proposal(), "run_id": "model-invented"})
        )
    with pytest.raises(SeverityDecisionError):
        parse_severity_proposal('{"schema_version":"plamen.severity_proposal.v1",'
                                '"candidate_id":"HYP-1","candidate_id":"HYP-2"}')
    missing = _proposal()
    missing.pop("likelihood")
    with pytest.raises(SeverityDecisionError):
        parse_severity_proposal(json.dumps(missing))


def test_driver_binds_identity_run_source_and_evidence_not_the_model():
    decision = _bind()
    assessment = decision["assessment"]
    assert decision["run_id"] == RUN_ID
    assert decision["source_receipt_digest"] == SOURCE_DIGEST
    assert assessment["assessor_identity"] == "verifier-worker"
    assert assessment["evidence_capabilities_required"] is True
    assert assessment["evidence_receipts_attested"] is True


def test_sidecar_identity_mismatch_fails_instead_of_rebinding_silently():
    proposal = _proposal(candidate_id="HYP-OTHER")
    with pytest.raises(SeverityDecisionError):
        _bind(proposal)


def test_mechanism_only_execution_cannot_authorize_likelihood_demotion():
    decision = _bind(evidence=_evidence(mechanism_only=True))
    assert decision["status"] == "CHALLENGE_REQUIRED"
    assert "LIKELIHOOD_EVIDENCE_CAPABILITY_MISSING" in decision[
        "challenge_codes"
    ]
    assert decision["final_severity"] is None
    assert project_retention_severity(decision)["severity"] == "High"


def test_capable_evidence_still_requires_fresh_independent_adjudication():
    challenged = _bind()
    assert challenged["status"] == "CHALLENGE_REQUIRED"
    proposal = {
        "schema_version": "plamen.severity_adjudication_proposal.v1",
        "decision": "ACCEPT_PROPOSED",
        "resolved_severity": "Medium",
        "resolved_premise_ids": ["PREM-LIKELIHOOD"],
        "evidence_ids": ["EVID-LIKELIHOOD"],
        "proof_scope": "IN_SCOPE_EXECUTION",
        "rationale": "Independent evidence-bound likelihood decision.",
        "resolved_axes": {"impact": "High", "likelihood": "Low"},
        "constituent_resolutions": {},
    }
    proposal_sha256 = hashlib.sha256(
        json.dumps(
            proposal,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    resolved = bind_severity_adjudication(
        proposal,
        decision=challenged,
        adjudicator_launch_receipt={
            "schema_version": "plamen.severity_launch_receipt.v2",
            "role": "ADJUDICATOR",
            "run_id": RUN_ID,
            "candidate_id": "HYP-1",
            "constituent_ids": ["HYP-1"],
            "worker_identity": "severity-adjudicator",
            "invocation_id": "severity-adjudication-1",
            "backend": "claude",
            "launch_manifest_sha256": "4" * 64,
            "input_sha256": severity_adjudicator_input_digest(challenged),
            "output_sha256": proposal_sha256,
        },
    )
    assert resolved["status"] == "RESOLVED"
    assert project_report_severity(resolved)["severity"] == "Medium"


def test_incomplete_axes_repair_only_missing_delta_and_retains_upstream():
    decision = _bind(_proposal(likelihood=None))
    assert decision["status"] == "INCOMPLETE"
    repair = build_severity_repair_request(decision)
    assert repair["missing_fields"] == ["likelihood"]
    projection = project_retention_severity(decision)
    assert projection["severity"] == "High"
    assert projection["severity_status"] == "UNRESOLVED_SEVERITY"


def test_self_issued_evidence_never_becomes_report_authority():
    evidence = [
        {
            **row,
            "issuer_identity": "verifier-worker",
            "issuer_invocation_id": "verify-invocation-1",
        }
        for row in _evidence()
    ]
    decision = _bind(evidence=evidence)
    assert "EVIDENCE_SELF_ATTESTED" in decision["challenge_codes"]
    with pytest.raises(SeverityDecisionError):
        project_report_severity(decision)


def test_authoritative_ledger_rejects_external_source_digest_drift(tmp_path: Path):
    challenged = _bind()
    # Retention-only unresolved decisions are still source/evidence bound and
    # can be persisted; report authority is decided per projection.
    path = tmp_path / "severity_decisions.json"
    write_severity_decision_ledger(path, RUN_ID, [challenged])
    load_severity_decision_ledger(
        path,
        expected_run_id=RUN_ID,
        expected_source_receipt_digests={"HYP-1": SOURCE_DIGEST},
    )
    with pytest.raises(SeverityDecisionError):
        load_severity_decision_ledger(
            path,
            expected_run_id=RUN_ID,
            expected_source_receipt_digests={"HYP-1": "f" * 64},
        )
