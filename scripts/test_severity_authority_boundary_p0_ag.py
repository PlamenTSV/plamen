"""Red authority-boundary fixtures for the P0-AG severity cutover.

These tests deliberately distinguish typed *content* from driver authority.
Model-authored identities, invocation IDs, receipt capabilities, and source
digests are data, not proof that a distinct launcher invocation produced them.

Expected missing API contracts:

* ``bind_severity_proposal(..., assessor_launch_receipt=...)`` binds the
  proposal to a driver-validated verifier launch/output receipt.  The receipt
  must cover run, work item/candidate, invocation, backend, launch digest, and
  the exact proposal bytes; it is not copied from model output.
* ``bind_severity_adjudication(..., adjudicator_launch_receipt=...)`` accepts a
  content-only adjudication proposal and injects identity/source context from a
  distinct driver-validated launch/output receipt.
* ``ingest_severity_proposal(...)`` is the haltless runtime boundary: strict
  parse failure still returns an upstream-retaining incomplete decision plus a
  bounded repair debt from trusted queue context.

No compatibility mapping may become report authority merely by declaring
different identity strings or by omitting the capability-policy flag.
"""
from __future__ import annotations

import copy
import hashlib
import inspect
import json

import pytest

import severity_decision_ledger as SDL


RUN_ID = "severity-authority-boundary-run"
SOURCE_DIGEST = "a" * 64
MAX_SEVERITY_INGRESS_BYTES = 1_048_576
MAX_SEVERITY_FIELD_CHARS = 16_384
MAX_SEVERITY_LIST_ITEMS = 256


def _canonical_digest(value) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def _proposal(**overrides):
    value = {
        "schema_version": "plamen.severity_proposal.v1",
        "candidate_id": "HYP-AUTH-1",
        "constituent_ids": ["HYP-AUTH-1"],
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
            "HYP-AUTH-1": {"impact": "SUPPORTED", "likelihood": "SUPPORTED"}
        },
    }
    value.update(overrides)
    return value


def _evidence():
    return [
        {
            "evidence_id": "EVID-IMPACT",
            "content_sha256": "1" * 64,
            "premise_ids": ["PREM-IMPACT"],
            "constituent_ids": ["HYP-AUTH-1"],
            "proof_scope": "IN_SCOPE_EXECUTION",
            "capabilities": ["EXECUTION", "IMPACT", "HARM"],
            "issuer_identity": "mechanical-evidence-registry",
            "issuer_invocation_id": "mechanical-evidence-run-1",
        },
        {
            "evidence_id": "EVID-LIKELIHOOD",
            "content_sha256": "2" * 64,
            "premise_ids": ["PREM-LIKELIHOOD"],
            "constituent_ids": ["HYP-AUTH-1"],
            "proof_scope": "IN_SCOPE_EXECUTION",
            "capabilities": ["EXECUTION", "LIKELIHOOD"],
            "issuer_identity": "mechanical-evidence-registry",
            "issuer_invocation_id": "mechanical-evidence-run-1",
        },
    ]


def _bind(proposal=None, *, evidence=None):
    return SDL.bind_severity_proposal(
        _proposal() if proposal is None else proposal,
        candidate_id="HYP-AUTH-1",
        constituent_ids=["HYP-AUTH-1"],
        upstream_severity="High",
        assessor_identity="verifier-worker",
        assessor_invocation_id="verify-invocation-1",
        run_id=RUN_ID,
        source_receipt_digest=SOURCE_DIGEST,
        evidence_receipts=_evidence() if evidence is None else evidence,
    )


def _raw_adjudication(decision, **overrides):
    value = {
        "adjudicator_identity": "self-declared-severity-adjudicator",
        "adjudicator_invocation_id": "self-declared-adjudication-1",
        "decision": "ACCEPT_PROPOSED",
        "resolved_severity": "Medium",
        "resolved_premise_ids": ["PREM-LIKELIHOOD"],
        "evidence_ids": ["EVID-LIKELIHOOD"],
        "proof_scope": "IN_SCOPE_EXECUTION",
        "rationale": "Claims to be an independent evidence-bound decision.",
        "resolved_axes": {"impact": "High", "likelihood": "Low"},
        "run_id": decision["run_id"],
        "source_receipt_digest": decision["source_receipt_digest"],
        "source_decision_digest": decision["decision_digest"],
        "candidate_id": decision["candidate_id"],
        "constituent_ids": decision["constituent_ids"],
        "prior_severity": decision["retention_severity"],
    }
    value.update(overrides)
    return value


def test_assessment_authority_requires_driver_validated_launch_receipt_api():
    parameters = inspect.signature(SDL.bind_severity_proposal).parameters
    assert "assessor_launch_receipt" in parameters, (
        "bind_severity_proposal must require a driver-validated launch/output "
        "receipt; caller-supplied identity strings are not invocation authority"
    )


def test_adjudication_authority_has_a_driver_bound_binder_api():
    binder = getattr(SDL, "bind_severity_adjudication", None)
    assert callable(binder), (
        "expected bind_severity_adjudication(content_proposal, decision=..., "
        "adjudicator_launch_receipt=...)"
    )
    assert "adjudicator_launch_receipt" in inspect.signature(binder).parameters


def test_raw_self_declared_adjudicator_cannot_resolve_challenge():
    challenged = _bind()
    result = SDL.adjudicate_severity_challenge(
        challenged, _raw_adjudication(challenged)
    )

    assert result["status"] == "UNRESOLVED_SEVERITY"
    assert result["final_severity"] is None
    assert "ADJUDICATION_AUTHORITY_UNBOUND" in result["challenge_codes"]
    assert SDL.project_retention_severity(result)["severity"] == "High"


def test_adjudication_selected_evidence_must_have_axis_capability():
    proposal = _proposal()
    proposal["likelihood"] = {
        **proposal["likelihood"],
        "evidence_ids": ["EVID-LIKELIHOOD", "EVID-LIKELIHOOD-MECHANISM"],
    }
    evidence = _evidence() + [
        {
            "evidence_id": "EVID-LIKELIHOOD-MECHANISM",
            "content_sha256": "3" * 64,
            "premise_ids": ["PREM-LIKELIHOOD"],
            "constituent_ids": ["HYP-AUTH-1"],
            "proof_scope": "IN_SCOPE_EXECUTION",
            "capabilities": ["EXECUTION", "MECHANISM"],
            "issuer_identity": "mechanical-evidence-registry",
            "issuer_invocation_id": "mechanical-evidence-run-1",
        }
    ]
    challenged = _bind(proposal, evidence=evidence)
    event = _raw_adjudication(
        challenged, evidence_ids=["EVID-LIKELIHOOD-MECHANISM"]
    )
    result = SDL.adjudicate_severity_challenge(challenged, event)

    assert result["status"] == "UNRESOLVED_SEVERITY"
    assert result["final_severity"] is None
    assert "ADJUDICATION_EVIDENCE_CAPABILITY_MISSING" in result[
        "challenge_codes"
    ]
    assert SDL.project_retention_severity(result)["severity"] == "High"


def test_external_favorable_source_only_adjudication_cannot_clear_r10():
    proposal = _proposal()
    proposal["likelihood"] = {
        **proposal["likelihood"],
        "premise_kind": "EXTERNAL_FAVORABLE",
        "proof_scope": "IN_SCOPE_SOURCE",
    }
    proposal["adjustment"] = {
        **proposal["adjustment"],
        "proof_scope": "IN_SCOPE_SOURCE",
    }
    evidence = _evidence()
    evidence[1] = {
        **evidence[1],
        "proof_scope": "IN_SCOPE_SOURCE",
        "capabilities": ["LIKELIHOOD", "EXTERNAL_FACT"],
    }
    challenged = _bind(proposal, evidence=evidence)
    assert "EXTERNAL_FAVORABLE_PREMISE_UNPROVEN" in challenged[
        "challenge_codes"
    ]

    result = SDL.adjudicate_severity_challenge(
        challenged,
        _raw_adjudication(
            challenged,
            evidence_ids=["EVID-LIKELIHOOD"],
            proof_scope="IN_SCOPE_SOURCE",
        ),
    )

    assert result["status"] == "UNRESOLVED_SEVERITY"
    assert result["final_severity"] is None
    assert "EXTERNAL_FAVORABLE_PREMISE_UNPROVEN" in result["challenge_codes"]
    assert SDL.project_retention_severity(result)["severity"] == "High"


def test_direct_legacy_mapping_cannot_self_upgrade_to_report_authority():
    proposal = _proposal(
        likelihood={
            **_proposal()["likelihood"],
            "class": "Medium",
        },
        proposed_severity="High",
        adjustment=None,
    )
    bound = _bind(proposal)
    legacy_mapping = dict(bound["assessment"])
    legacy_mapping.pop("evidence_capabilities_required", None)
    legacy_mapping.pop("evidence_capabilities_attested", None)
    legacy_mapping["assessor_identity"] = "same-model-alias-a"
    legacy_mapping["assessor_invocation_id"] = "same-model-run-a"
    legacy_mapping["evidence_receipts"] = [
        {
            **row,
            "capabilities": [],
            "issuer_identity": "same-model-alias-b",
            "issuer_invocation_id": "same-model-run-b",
        }
        for row in legacy_mapping["evidence_receipts"]
    ]

    decision = SDL.build_severity_decision(legacy_mapping)
    assert decision["status"] == "RESOLVED"
    assert SDL.project_retention_severity(decision)["severity"] == "High"
    with pytest.raises(SDL.SeverityDecisionError, match="report-authoritative"):
        SDL.project_report_severity(decision)


def test_unattested_compatibility_mapping_remains_visible_at_upstream():
    proposal = _proposal(
        likelihood={
            **_proposal()["likelihood"],
            "class": "Medium",
        },
        proposed_severity="High",
        adjustment=None,
    )
    bound = _bind(proposal)
    compatibility = dict(bound["assessment"])
    compatibility.pop("evidence_receipts", None)
    compatibility.pop("evidence_receipts_attested", None)
    compatibility.pop("evidence_capabilities_required", None)
    compatibility.pop("evidence_capabilities_attested", None)

    decision = SDL.build_severity_decision(compatibility)
    projection = SDL.project_retention_severity(decision)
    assert projection["severity"] == "High"
    assert projection["severity_status"] == "UNRESOLVED_SEVERITY"
    with pytest.raises(SDL.SeverityDecisionError, match="report-authoritative"):
        SDL.project_report_severity(decision)


def test_malformed_model_output_has_haltless_upstream_retention_ingress_api():
    ingress = getattr(SDL, "ingest_severity_proposal", None)
    assert callable(ingress), (
        "expected ingest_severity_proposal(raw_bytes, trusted_context=...) to "
        "turn strict-parse failure into upstream-retaining repair debt"
    )

    malformed = json.dumps({
        key: value for key, value in _proposal().items() if key != "likelihood"
    }).encode("utf-8")
    result = ingress(
        malformed,
        trusted_context={
            "candidate_id": "HYP-AUTH-1",
            "constituent_ids": ["HYP-AUTH-1"],
            "upstream_severity": "High",
            "run_id": RUN_ID,
            "source_receipt_digest": SOURCE_DIGEST,
        },
    )
    assert result["decision"]["status"] == "INCOMPLETE"
    assert result["repair_request"]["missing_fields"] == ["likelihood"]
    assert SDL.project_retention_severity(result["decision"])["severity"] == "High"


@pytest.mark.parametrize(
    ("case_name", "mutation", "expected_missing"),
    [
        (
            "scalar-impact",
            lambda proposal: proposal.update(impact="not-an-object"),
            "impact",
        ),
        (
            "scalar-likelihood",
            lambda proposal: proposal.update(likelihood="not-an-object"),
            "likelihood",
        ),
        (
            "outcome-row-missing-axis",
            lambda proposal: proposal.update(
                constituent_premise_outcomes={
                    "HYP-AUTH-1": {"impact": "UNRESOLVED"}
                }
            ),
            None,
        ),
        (
            "outcome-token-invalid",
            lambda proposal: proposal.update(
                constituent_premise_outcomes={
                    "HYP-AUTH-1": {
                        "impact": "MAYBE",
                        "likelihood": "UNRESOLVED",
                    }
                }
            ),
            None,
        ),
    ],
    ids=lambda value: value if isinstance(value, str) else None,
)
def test_nested_schema_failure_is_haltless_upstream_debt(
    case_name, mutation, expected_missing
):
    del case_name
    proposal = _proposal()
    mutation(proposal)

    result = SDL.ingest_severity_proposal(
        json.dumps(proposal).encode("utf-8"),
        trusted_context={
            "candidate_id": "HYP-AUTH-1",
            "constituent_ids": ["HYP-AUTH-1"],
            "upstream_severity": "High",
            "run_id": RUN_ID,
            "source_receipt_digest": SOURCE_DIGEST,
        },
    )

    assert result["decision"]["status"] == "INCOMPLETE"
    assert result["repair_request"] is not None
    if expected_missing is not None:
        assert expected_missing in result["repair_request"]["missing_fields"]
    assert SDL.project_retention_severity(result["decision"])["severity"] == "High"


@pytest.mark.parametrize(
    ("case_name", "mutation"),
    [
        (
            "invalid-proposed-severity",
            lambda proposal: proposal.update(proposed_severity="BANANA"),
        ),
        (
            "nonscalar-proposed-severity",
            lambda proposal: proposal.update(proposed_severity={}),
        ),
        (
            "foreign-candidate-identity",
            lambda proposal: proposal.update(candidate_id="HYP-FOREIGN"),
        ),
        (
            "foreign-constituent-identity",
            lambda proposal: proposal.update(constituent_ids=["HYP-FOREIGN"]),
        ),
        (
            "foreign-outcome-identity",
            lambda proposal: proposal.update(
                constituent_premise_outcomes={
                    "HYP-FOREIGN": {
                        "impact": "SUPPORTED",
                        "likelihood": "SUPPORTED",
                    }
                }
            ),
        ),
        (
            "outcome-row-extra-field",
            lambda proposal: proposal.update(
                constituent_premise_outcomes={
                    "HYP-AUTH-1": {
                        "impact": "SUPPORTED",
                        "likelihood": "SUPPORTED",
                        "extra": "model-authored",
                    }
                }
            ),
        ),
        (
            "empty-outcome-map",
            lambda proposal: proposal.update(constituent_premise_outcomes={}),
        ),
    ],
    ids=lambda value: value if isinstance(value, str) else None,
)
def test_identity_and_semantic_schema_failure_is_upstream_debt(
    case_name, mutation
):
    del case_name
    proposal = _proposal()
    mutation(proposal)

    result = SDL.ingest_severity_proposal(
        json.dumps(proposal).encode("utf-8"),
        trusted_context={
            "candidate_id": "HYP-AUTH-1",
            "constituent_ids": ["HYP-AUTH-1"],
            "upstream_severity": "High",
            "run_id": RUN_ID,
            "source_receipt_digest": SOURCE_DIGEST,
        },
    )

    assert result["decision"]["status"] == "INCOMPLETE"
    assert result["repair_request"] is not None
    assert result["repair_request"]["missing_fields"]
    assert SDL.project_retention_severity(result["decision"])["severity"] == "High"


def test_raw_event_cannot_fabricate_exact_adjudicator_authority_binding():
    proposal = _proposal()
    proposal_digest = hashlib.sha256(
        json.dumps(
            proposal,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    challenged = SDL.bind_severity_proposal(
        proposal,
        candidate_id="HYP-AUTH-1",
        constituent_ids=["HYP-AUTH-1"],
        upstream_severity="High",
        assessor_identity="verifier-worker",
        assessor_invocation_id="verify-invocation-1",
        run_id=RUN_ID,
        source_receipt_digest=SOURCE_DIGEST,
        evidence_receipts=_evidence(),
        assessor_launch_receipt={
            "schema_version": "plamen.severity_launch_receipt.v2",
            "role": "ASSESSOR",
            "run_id": RUN_ID,
            "candidate_id": "HYP-AUTH-1",
            "constituent_ids": ["HYP-AUTH-1"],
            "worker_identity": "verifier-worker",
            "invocation_id": "verify-invocation-1",
            "backend": "claude",
            "launch_manifest_sha256": "8" * 64,
            "input_sha256": SDL.severity_assessor_input_digest(
                candidate_id="HYP-AUTH-1",
                constituent_ids=["HYP-AUTH-1"],
                upstream_severity="High",
                run_id=RUN_ID,
                source_receipt_digest=SOURCE_DIGEST,
                evidence_receipts=_evidence(),
            ),
            "output_sha256": proposal_digest,
        },
    )
    forged_receipt = {
        "schema_version": "plamen.severity_launch_receipt.v1",
        "role": "ADJUDICATOR",
        "run_id": RUN_ID,
        "candidate_id": "HYP-AUTH-1",
        "constituent_ids": ["HYP-AUTH-1"],
        "worker_identity": "self-declared-other-worker",
        "invocation_id": "self-declared-other-invocation",
        "backend": "claude",
        "launch_manifest_sha256": "f" * 64,
        # Deliberately unrelated to the adjudication proposal below.  The raw
        # replay API currently never checks this field against event content.
        "output_sha256": "e" * 64,
    }
    forged_binding = {
        "status": "EXACT",
        "receipt": forged_receipt,
        "receipt_digest": hashlib.sha256(
            json.dumps(
                forged_receipt,
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest(),
    }
    event = _raw_adjudication(
        challenged,
        adjudicator_identity="self-declared-other-worker",
        adjudicator_invocation_id="self-declared-other-invocation",
        adjudicator_authority_binding=forged_binding,
    )

    result = SDL.adjudicate_severity_challenge(challenged, event)

    assert result["status"] == "UNRESOLVED_SEVERITY"
    assert result["final_severity"] is None
    assert "ADJUDICATION_AUTHORITY_UNBOUND" in result["challenge_codes"]
    assert SDL.project_retention_severity(result)["severity"] == "High"


def test_direct_build_cannot_fabricate_exact_producer_authority_binding():
    proposal = _proposal(
        likelihood={**_proposal()["likelihood"], "class": "Medium"},
        proposed_severity="High",
        adjustment=None,
    )
    compatibility = _bind(proposal)
    assessment = dict(compatibility["assessment"])
    forged_receipt = {
        "schema_version": "plamen.severity_launch_receipt.v1",
        "role": "ASSESSOR",
        "run_id": RUN_ID,
        "candidate_id": "HYP-AUTH-1",
        "constituent_ids": ["HYP-AUTH-1"],
        "worker_identity": assessment["assessor_identity"],
        "invocation_id": assessment["assessor_invocation_id"],
        "backend": "claude",
        "launch_manifest_sha256": "d" * 64,
        # No driver launcher or output artifact issued this digest.
        "output_sha256": "c" * 64,
    }
    assessment["producer_authority_binding"] = {
        "status": "EXACT",
        "receipt": forged_receipt,
        "receipt_digest": hashlib.sha256(
            json.dumps(
                forged_receipt,
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest(),
    }

    decision = SDL.build_severity_decision(assessment)

    assert decision["status"] == "RESOLVED"
    assert SDL.project_retention_severity(decision)["severity"] == "High"
    with pytest.raises(SDL.SeverityDecisionError, match="report-authoritative"):
        SDL.project_report_severity(decision)


@pytest.mark.parametrize("nonfinite", [float("nan"), float("inf")])
def test_nonfinite_json_is_haltless_upstream_debt(nonfinite):
    proposal = _proposal()
    proposal["adjustment"]["rationale"] = nonfinite
    raw = json.dumps(proposal, allow_nan=True).encode("utf-8")

    result = SDL.ingest_severity_proposal(
        raw,
        trusted_context={
            "candidate_id": "HYP-AUTH-1",
            "constituent_ids": ["HYP-AUTH-1"],
            "upstream_severity": "High",
            "run_id": RUN_ID,
            "source_receipt_digest": SOURCE_DIGEST,
        },
    )

    assert result["decision"]["status"] == "INCOMPLETE"
    assert result["repair_request"] is not None
    assert result["ingress_error"]
    assert SDL.project_retention_severity(result["decision"])["severity"] == "High"


def test_raw_ingress_over_byte_cap_is_haltless_upstream_debt():
    proposal = _proposal()
    proposal["adjustment"]["rationale"] = "x" * MAX_SEVERITY_INGRESS_BYTES
    raw = json.dumps(proposal).encode("utf-8")
    assert len(raw) > MAX_SEVERITY_INGRESS_BYTES

    result = SDL.ingest_severity_proposal(
        raw,
        trusted_context={
            "candidate_id": "HYP-AUTH-1",
            "constituent_ids": ["HYP-AUTH-1"],
            "upstream_severity": "High",
            "run_id": RUN_ID,
            "source_receipt_digest": SOURCE_DIGEST,
        },
    )

    assert result["decision"]["status"] == "INCOMPLETE"
    assert result["repair_request"] is not None
    assert result["ingress_error"]
    assert SDL.project_retention_severity(result["decision"])["severity"] == "High"


@pytest.mark.parametrize(
    ("case_name", "mutation"),
    [
        (
            "oversized-field",
            lambda proposal: proposal["adjustment"].update(
                rationale="x" * (MAX_SEVERITY_FIELD_CHARS + 1)
            ),
        ),
        (
            "oversized-list",
            lambda proposal: proposal["likelihood"].update(
                preconditions=[
                    f"condition-{index}"
                    for index in range(MAX_SEVERITY_LIST_ITEMS + 1)
                ]
            ),
        ),
    ],
    ids=lambda value: value if isinstance(value, str) else None,
)
def test_oversized_field_or_list_is_haltless_upstream_debt(case_name, mutation):
    del case_name
    proposal = _proposal()
    mutation(proposal)
    raw = json.dumps(proposal).encode("utf-8")
    assert len(raw) < MAX_SEVERITY_INGRESS_BYTES

    result = SDL.ingest_severity_proposal(
        raw,
        trusted_context={
            "candidate_id": "HYP-AUTH-1",
            "constituent_ids": ["HYP-AUTH-1"],
            "upstream_severity": "High",
            "run_id": RUN_ID,
            "source_receipt_digest": SOURCE_DIGEST,
        },
    )

    assert result["decision"]["status"] == "INCOMPLETE"
    assert result["repair_request"] is not None
    assert result["ingress_error"]
    assert SDL.project_retention_severity(result["decision"])["severity"] == "High"


def test_lone_surrogate_is_haltless_upstream_debt():
    proposal = _proposal()
    proposal["adjustment"]["rationale"] = "SURROGATE_MARKER"
    raw = json.dumps(proposal).replace("SURROGATE_MARKER", "\\ud800")

    result = SDL.ingest_severity_proposal(
        raw,
        trusted_context={
            "candidate_id": "HYP-AUTH-1",
            "constituent_ids": ["HYP-AUTH-1"],
            "upstream_severity": "High",
            "run_id": RUN_ID,
            "source_receipt_digest": SOURCE_DIGEST,
        },
    )

    assert result["decision"]["status"] == "INCOMPLETE"
    assert result["repair_request"] is not None
    assert result["ingress_error"]
    assert SDL.project_retention_severity(result["decision"])["severity"] == "High"


def test_excessive_json_nesting_is_haltless_upstream_debt():
    nested = '"leaf"'
    for _ in range(5_000):
        nested = f"[{nested}]"
    raw = json.dumps(_proposal()).replace('["reachable state"]', f"[{nested}]")
    assert len(raw.encode("utf-8")) < MAX_SEVERITY_INGRESS_BYTES

    result = SDL.ingest_severity_proposal(
        raw,
        trusted_context={
            "candidate_id": "HYP-AUTH-1",
            "constituent_ids": ["HYP-AUTH-1"],
            "upstream_severity": "High",
            "run_id": RUN_ID,
            "source_receipt_digest": SOURCE_DIGEST,
        },
    )

    assert result["decision"]["status"] == "INCOMPLETE"
    assert result["repair_request"] is not None
    assert result["ingress_error"]
    assert SDL.project_retention_severity(result["decision"])["severity"] == "High"


def test_shared_impact_likelihood_premise_cannot_erase_impact_capability():
    proposal = _proposal()
    proposal["impact"] = {
        **proposal["impact"],
        "premise_id": "PREM-SHARED-AXES",
    }
    proposal["likelihood"] = {
        **proposal["likelihood"],
        "premise_id": "PREM-SHARED-AXES",
    }
    proposal["adjustment"] = {
        **proposal["adjustment"],
        "premise_ids": ["PREM-SHARED-AXES"],
    }
    evidence = []
    for row in _evidence():
        evidence.append({**row, "premise_ids": ["PREM-SHARED-AXES"]})
    proposal_digest = hashlib.sha256(
        json.dumps(
            proposal,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    try:
        challenged = SDL.bind_severity_proposal(
            proposal,
            candidate_id="HYP-AUTH-1",
            constituent_ids=["HYP-AUTH-1"],
            upstream_severity="High",
            assessor_identity="verifier-worker",
            assessor_invocation_id="verify-invocation-1",
            run_id=RUN_ID,
            source_receipt_digest=SOURCE_DIGEST,
            evidence_receipts=evidence,
            assessor_launch_receipt={
                "schema_version": "plamen.severity_launch_receipt.v2",
                "role": "ASSESSOR",
                "run_id": RUN_ID,
                "candidate_id": "HYP-AUTH-1",
                "constituent_ids": ["HYP-AUTH-1"],
                "worker_identity": "verifier-worker",
                "invocation_id": "verify-invocation-1",
                "backend": "claude",
                "launch_manifest_sha256": "8" * 64,
                "input_sha256": SDL.severity_assessor_input_digest(
                    candidate_id="HYP-AUTH-1",
                    constituent_ids=["HYP-AUTH-1"],
                    upstream_severity="High",
                    run_id=RUN_ID,
                    source_receipt_digest=SOURCE_DIGEST,
                    evidence_receipts=evidence,
                ),
                "output_sha256": proposal_digest,
            },
        )
    except SDL.SeverityDecisionError as exc:
        assert "premise" in str(exc).casefold()
        return

    adjudication = {
        "schema_version": "plamen.severity_adjudication_proposal.v1",
        "decision": "ACCEPT_PROPOSED",
        "resolved_severity": "Medium",
        "resolved_premise_ids": ["PREM-SHARED-AXES"],
        # This receipt has LIKELIHOOD but no IMPACT/HARM capability.
        "evidence_ids": ["EVID-LIKELIHOOD"],
        "proof_scope": "IN_SCOPE_EXECUTION",
        "rationale": "Attempts to change both axes through one premise.",
        "resolved_axes": {"impact": "Medium", "likelihood": "Medium"},
        "constituent_resolutions": {},
    }
    adjudication_digest = hashlib.sha256(
        json.dumps(
            adjudication,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    result = SDL.bind_severity_adjudication(
        adjudication,
        decision=challenged,
        adjudicator_launch_receipt={
            "schema_version": "plamen.severity_launch_receipt.v2",
            "role": "ADJUDICATOR",
            "run_id": RUN_ID,
            "candidate_id": "HYP-AUTH-1",
            "constituent_ids": ["HYP-AUTH-1"],
            "worker_identity": "severity-adjudicator",
            "invocation_id": "severity-adjudication-1",
            "backend": "claude",
            "launch_manifest_sha256": "9" * 64,
            "input_sha256": SDL.severity_adjudicator_input_digest(challenged),
            "output_sha256": adjudication_digest,
        },
    )

    assert result["status"] == "UNRESOLVED_SEVERITY"
    assert result["final_severity"] is None
    assert "AXIS_PREMISE_ID_COLLISION" in result["challenge_codes"]
    assert SDL.project_retention_severity(result)["severity"] == "High"


def test_assessor_receipt_v2_cannot_replay_across_source_upstream_or_evidence():
    """V2 assessor authority commits every non-model input to the decision.

    The minimal additional field is ``input_sha256``, computed over source
    receipt, upstream severity, and the normalized evidence-receipt universe.
    Reusing the same receipt after any input changes must fail before authority.
    """

    proposal = _proposal()
    strong_evidence = _evidence()
    weak_evidence = _evidence()
    weak_evidence[1] = {
        **weak_evidence[1],
        "capabilities": ["EXECUTION", "MECHANISM"],
    }
    receipt = {
        "schema_version": SDL.LAUNCH_RECEIPT_SCHEMA,
        "role": "ASSESSOR",
        "run_id": RUN_ID,
        "candidate_id": "HYP-AUTH-1",
        "constituent_ids": ["HYP-AUTH-1"],
        "worker_identity": "verifier-worker",
        "invocation_id": "verify-invocation-1",
        "backend": "claude",
        "launch_manifest_sha256": "8" * 64,
        "output_sha256": _canonical_digest(proposal),
        "input_sha256": SDL.severity_assessor_input_digest(
            candidate_id="HYP-AUTH-1",
            constituent_ids=["HYP-AUTH-1"],
            upstream_severity="High",
            run_id=RUN_ID,
            source_receipt_digest=SOURCE_DIGEST,
            evidence_receipts=strong_evidence,
        ),
    }
    common = {
        "proposal": proposal,
        "candidate_id": "HYP-AUTH-1",
        "constituent_ids": ["HYP-AUTH-1"],
        "assessor_identity": "verifier-worker",
        "assessor_invocation_id": "verify-invocation-1",
        "run_id": RUN_ID,
        "assessor_launch_receipt": receipt,
    }

    baseline = SDL.bind_severity_proposal(
        upstream_severity="High",
        source_receipt_digest=SOURCE_DIGEST,
        evidence_receipts=strong_evidence,
        **common,
    )
    assert baseline["assessment"]["producer_authority_binding"]["status"] == (
        "EXACT"
    )

    with pytest.raises(SDL.SeverityDecisionError, match="authority|source"):
        SDL.bind_severity_proposal(
            upstream_severity="High",
            source_receipt_digest="b" * 64,
            evidence_receipts=strong_evidence,
            **common,
        )
    with pytest.raises(SDL.SeverityDecisionError, match="authority|upstream"):
        SDL.bind_severity_proposal(
            upstream_severity="Critical",
            source_receipt_digest=SOURCE_DIGEST,
            evidence_receipts=strong_evidence,
            **common,
        )
    with pytest.raises(SDL.SeverityDecisionError, match="authority|evidence"):
        SDL.bind_severity_proposal(
            upstream_severity="High",
            source_receipt_digest=SOURCE_DIGEST,
            evidence_receipts=weak_evidence,
            **common,
        )


def test_adjudicator_receipt_v2_cannot_replay_across_source_decisions():
    """V2 ``input_sha256`` commits the adjudicator's source decision digest."""

    proposal = _proposal()
    evidence = _evidence()

    def bound_source(source_digest: str, manifest_digit: str):
        return SDL.bind_severity_proposal(
            proposal,
            candidate_id="HYP-AUTH-1",
            constituent_ids=["HYP-AUTH-1"],
            upstream_severity="High",
            assessor_identity="verifier-worker",
            assessor_invocation_id=f"verify-{manifest_digit}",
            run_id=RUN_ID,
            source_receipt_digest=source_digest,
            evidence_receipts=evidence,
            assessor_launch_receipt={
                "schema_version": SDL.LAUNCH_RECEIPT_SCHEMA,
                "role": "ASSESSOR",
                "run_id": RUN_ID,
                "candidate_id": "HYP-AUTH-1",
                "constituent_ids": ["HYP-AUTH-1"],
                "worker_identity": "verifier-worker",
                "invocation_id": f"verify-{manifest_digit}",
                "backend": "claude",
                "launch_manifest_sha256": manifest_digit * 64,
                "output_sha256": _canonical_digest(proposal),
                "input_sha256": SDL.severity_assessor_input_digest(
                    candidate_id="HYP-AUTH-1",
                    constituent_ids=["HYP-AUTH-1"],
                    upstream_severity="High",
                    run_id=RUN_ID,
                    source_receipt_digest=source_digest,
                    evidence_receipts=evidence,
                ),
            },
        )

    first = bound_source("a" * 64, "6")
    second = bound_source("b" * 64, "7")
    assert first["decision_digest"] != second["decision_digest"]
    adjudication = {
        "schema_version": "plamen.severity_adjudication_proposal.v1",
        "decision": "ACCEPT_PROPOSED",
        "resolved_severity": "Medium",
        "resolved_premise_ids": ["PREM-LIKELIHOOD"],
        "evidence_ids": ["EVID-LIKELIHOOD"],
        "proof_scope": "IN_SCOPE_EXECUTION",
        "rationale": "Independent evidence-bound decision.",
        "resolved_axes": {"impact": "High", "likelihood": "Low"},
        "constituent_resolutions": {},
    }
    receipt = {
        "schema_version": SDL.LAUNCH_RECEIPT_SCHEMA,
        "role": "ADJUDICATOR",
        "run_id": RUN_ID,
        "candidate_id": "HYP-AUTH-1",
        "constituent_ids": ["HYP-AUTH-1"],
        "worker_identity": "severity-adjudicator",
        "invocation_id": "severity-adjudication-1",
        "backend": "claude",
        "launch_manifest_sha256": "9" * 64,
        "output_sha256": _canonical_digest(adjudication),
        "input_sha256": SDL.severity_adjudicator_input_digest(first),
    }

    resolved = SDL.bind_severity_adjudication(
        adjudication,
        decision=first,
        adjudicator_launch_receipt=receipt,
    )
    assert resolved["status"] == "RESOLVED"
    with pytest.raises(SDL.SeverityDecisionError, match="authority|source"):
        SDL.bind_severity_adjudication(
            adjudication,
            decision=second,
            adjudicator_launch_receipt=receipt,
        )


def test_semantic_replay_rejects_stale_assessor_v2_input_and_output_hashes():
    """A rehashed row cannot preserve EXACT authority after source-content drift."""

    proposal = _proposal()
    evidence = _evidence()
    assessor_receipt = {
        "schema_version": SDL.LAUNCH_RECEIPT_SCHEMA,
        "role": "ASSESSOR",
        "run_id": RUN_ID,
        "candidate_id": "HYP-AUTH-1",
        "constituent_ids": ["HYP-AUTH-1"],
        "worker_identity": "verifier-worker",
        "invocation_id": "verify-persisted-assessor",
        "backend": "claude",
        "launch_manifest_sha256": "6" * 64,
        "input_sha256": SDL.severity_assessor_input_digest(
            candidate_id="HYP-AUTH-1",
            constituent_ids=["HYP-AUTH-1"],
            upstream_severity="High",
            run_id=RUN_ID,
            source_receipt_digest=SOURCE_DIGEST,
            evidence_receipts=evidence,
        ),
        "output_sha256": _canonical_digest(proposal),
    }
    authentic = SDL.bind_severity_proposal(
        proposal,
        candidate_id="HYP-AUTH-1",
        constituent_ids=["HYP-AUTH-1"],
        upstream_severity="High",
        assessor_identity="verifier-worker",
        assessor_invocation_id="verify-persisted-assessor",
        run_id=RUN_ID,
        source_receipt_digest=SOURCE_DIGEST,
        evidence_receipts=evidence,
        assessor_launch_receipt=assessor_receipt,
    )

    tampered_source = copy.deepcopy(authentic["assessment"])
    stale_binding = copy.deepcopy(tampered_source["producer_authority_binding"])
    tampered_source["upstream_severity"] = "Medium"
    tampered_source["adjustment"] = None
    forged = SDL.build_severity_decision(tampered_source)
    forged["assessment"]["producer_authority_binding"] = stale_binding
    forged["decision_digest"] = _canonical_digest(
        {key: value for key, value in forged.items() if key != "decision_digest"}
    )

    current_input = SDL.severity_assessor_input_digest(
        candidate_id="HYP-AUTH-1",
        constituent_ids=["HYP-AUTH-1"],
        upstream_severity="Medium",
        run_id=RUN_ID,
        source_receipt_digest=SOURCE_DIGEST,
        evidence_receipts=evidence,
    )
    current_proposal = {
        **proposal,
        "adjustment": None,
    }
    assert assessor_receipt["input_sha256"] != current_input
    assert assessor_receipt["output_sha256"] != _canonical_digest(current_proposal)

    with pytest.raises(SDL.SeverityDecisionError, match="authority|receipt|semantic"):
        SDL.project_report_severity(forged)


def test_semantic_replay_rejects_stale_adjudicator_v2_output_hash():
    """A rehashed event cannot reuse authority for different adjudication content."""

    proposal = _proposal()
    evidence = _evidence()
    source = SDL.bind_severity_proposal(
        proposal,
        candidate_id="HYP-AUTH-1",
        constituent_ids=["HYP-AUTH-1"],
        upstream_severity="High",
        assessor_identity="verifier-worker",
        assessor_invocation_id="verify-persisted-adjudicator",
        run_id=RUN_ID,
        source_receipt_digest=SOURCE_DIGEST,
        evidence_receipts=evidence,
        assessor_launch_receipt={
            "schema_version": SDL.LAUNCH_RECEIPT_SCHEMA,
            "role": "ASSESSOR",
            "run_id": RUN_ID,
            "candidate_id": "HYP-AUTH-1",
            "constituent_ids": ["HYP-AUTH-1"],
            "worker_identity": "verifier-worker",
            "invocation_id": "verify-persisted-adjudicator",
            "backend": "claude",
            "launch_manifest_sha256": "7" * 64,
            "input_sha256": SDL.severity_assessor_input_digest(
                candidate_id="HYP-AUTH-1",
                constituent_ids=["HYP-AUTH-1"],
                upstream_severity="High",
                run_id=RUN_ID,
                source_receipt_digest=SOURCE_DIGEST,
                evidence_receipts=evidence,
            ),
            "output_sha256": _canonical_digest(proposal),
        },
    )
    adjudication = {
        "schema_version": SDL.ADJUDICATION_PROPOSAL_SCHEMA,
        "decision": "ACCEPT_PROPOSED",
        "resolved_severity": "Medium",
        "resolved_premise_ids": ["PREM-LIKELIHOOD"],
        "evidence_ids": ["EVID-LIKELIHOOD"],
        "proof_scope": "IN_SCOPE_EXECUTION",
        "rationale": "Independent evidence-bound decision.",
        "resolved_axes": {"impact": "High", "likelihood": "Low"},
        "constituent_resolutions": {},
    }
    receipt = {
        "schema_version": SDL.LAUNCH_RECEIPT_SCHEMA,
        "role": "ADJUDICATOR",
        "run_id": RUN_ID,
        "candidate_id": "HYP-AUTH-1",
        "constituent_ids": ["HYP-AUTH-1"],
        "worker_identity": "severity-adjudicator",
        "invocation_id": "adjudicate-persisted-event",
        "backend": "claude",
        "launch_manifest_sha256": "9" * 64,
        "input_sha256": SDL.severity_adjudicator_input_digest(source),
        "output_sha256": _canonical_digest(adjudication),
    }
    authentic = SDL.bind_severity_adjudication(
        adjudication,
        decision=source,
        adjudicator_launch_receipt=receipt,
    )

    forged = copy.deepcopy(authentic)
    for event in (forged["adjudication"], forged["adjudication_history"][0]):
        event["decision"] = "ACCEPT_UPSTREAM"
        event["resolved_severity"] = "High"
        event["resolved_axes"] = {"impact": "High", "likelihood": "Medium"}
    forged["final_severity"] = "High"
    forged["constituent_dispositions"]["HYP-AUTH-1"]["severity"] = "High"
    forged["decision_digest"] = _canonical_digest(
        {key: value for key, value in forged.items() if key != "decision_digest"}
    )
    mutated_adjudication = {
        **adjudication,
        "decision": "ACCEPT_UPSTREAM",
        "resolved_severity": "High",
        "resolved_axes": {"impact": "High", "likelihood": "Medium"},
    }
    assert receipt["output_sha256"] != _canonical_digest(mutated_adjudication)

    with pytest.raises(SDL.SeverityDecisionError, match="authority|receipt|semantic"):
        SDL.project_report_severity(forged)
