"""Adversarial acceptance fixtures for the P0-AG/P0-P/P0-V/P0-U substrate.

These are intentionally specification-level tests.  Each fixture captures a
case in which a syntactically valid, digest-valid record must still fail closed
because its semantic authority is absent or narrower than the claimed result.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from severity_decision_ledger import (
    SeverityDecisionError,
    adjudicate_severity_challenge,
    build_severity_decision,
    load_severity_decision_ledger,
    project_report_severity,
    write_severity_decision_ledger,
)


def _digest(value) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _assessment(**overrides):
    value = {
        "candidate_id": "HYP-AR-1",
        "constituent_ids": ["HYP-AR-1"],
        "upstream_severity": "High",
        "assessor_identity": "verifier-a",
        "assessor_invocation_id": "invocation-a",
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
            "class": "Medium",
            "actor": "unprivileged actor",
            "preconditions": ["reachable state"],
            "premise_id": "PREM-LIKELIHOOD",
            "premise_kind": "INTERNAL",
            "evidence_ids": ["EVID-LIKELIHOOD"],
            "proof_scope": "IN_SCOPE_SOURCE",
        },
        "modifiers": [],
        "proposed_severity": "High",
        "adjustment": None,
        "constituent_premise_outcomes": {
            "HYP-AR-1": {"impact": "SUPPORTED", "likelihood": "SUPPORTED"}
        },
    }
    value.update(overrides)
    return value


def _downward_assessment(**overrides):
    value = _assessment(
        proposed_severity="Medium",
        adjustment={
            "direction": "DOWN",
            "premise_ids": ["PREM-LIKELIHOOD"],
            "evidence_ids": ["EVID-LIKELIHOOD"],
            "proof_scope": "IN_SCOPE_SOURCE",
            "rationale": "The likelihood premise is claimed to be refuted.",
        },
    )
    value.update(overrides)
    return value


def _adjudication(**overrides):
    value = {
        "adjudicator_identity": "adjudicator-b",
        "adjudicator_invocation_id": "invocation-b",
        "decision": "ACCEPT_PROPOSED",
        "resolved_severity": "Medium",
        "resolved_premise_ids": ["PREM-LIKELIHOOD"],
        "evidence_ids": ["EVID-LIKELIHOOD"],
        "proof_scope": "IN_SCOPE_SOURCE",
        "rationale": "Independent premise decision.",
    }
    value.update(overrides)
    return value


def _attested_assessment(**overrides):
    value = _assessment(
        run_id="run-attested",
        source_receipt_digest="a" * 64,
        evidence_receipts=[
            {
                "evidence_id": "EVID-IMPACT",
                "content_sha256": "1" * 64,
                "premise_ids": ["PREM-IMPACT"],
                "constituent_ids": ["HYP-AR-1"],
                "proof_scope": "IN_SCOPE_EXECUTION",
                "issuer_identity": "mechanical-evidence-gate",
                "issuer_invocation_id": "evidence-invocation-1",
            },
            {
                "evidence_id": "EVID-LIKELIHOOD",
                "content_sha256": "2" * 64,
                "premise_ids": ["PREM-LIKELIHOOD"],
                "constituent_ids": ["HYP-AR-1"],
                "proof_scope": "IN_SCOPE_SOURCE",
                "issuer_identity": "mechanical-evidence-gate",
                "issuer_invocation_id": "evidence-invocation-1",
            },
        ],
    )
    value.update(overrides)
    return value


def _attested_downward_assessment(**overrides):
    value = _attested_assessment(
        proposed_severity="Medium",
        adjustment={
            "direction": "DOWN",
            "premise_ids": ["PREM-LIKELIHOOD"],
            "evidence_ids": ["EVID-LIKELIHOOD"],
            "proof_scope": "IN_SCOPE_SOURCE",
            "rationale": "The likelihood premise is claimed to be refuted.",
        },
    )
    value.update(overrides)
    return value


def test_single_constituent_unresolved_premise_is_not_a_resolved_severity():
    assessment = _assessment(
        constituent_premise_outcomes={
            "HYP-AR-1": {"impact": "SUPPORTED", "likelihood": "UNRESOLVED"}
        }
    )
    decision = build_severity_decision(assessment)

    assert decision["status"] != "RESOLVED"
    assert decision["final_severity"] is None


def test_adjustment_direction_must_match_the_requested_tier_change():
    assessment = _downward_assessment()
    assessment["adjustment"] = {
        **assessment["adjustment"],
        "direction": "UP",
    }
    challenged = build_severity_decision(assessment)
    adjudicated = adjudicate_severity_challenge(challenged, _adjudication())

    assert adjudicated["status"] == "UNRESOLVED_SEVERITY"
    assert adjudicated["final_severity"] is None


def test_adjudication_cannot_resolve_with_a_foreign_evidence_identifier():
    challenged = build_severity_decision(_downward_assessment())
    adjudicated = adjudicate_severity_challenge(
        challenged,
        _adjudication(evidence_ids=["EVID-FOREIGN-UNBOUND"]),
    )

    assert adjudicated["status"] == "UNRESOLVED_SEVERITY"
    assert adjudicated["final_severity"] is None


def test_adjustment_cannot_invent_a_premise_that_the_axes_never_declared():
    assessment = _downward_assessment()
    assessment["adjustment"] = {
        **assessment["adjustment"],
        "premise_ids": ["PREM-INVENTED-BY-ASSESSOR"],
    }
    challenged = build_severity_decision(assessment)
    adjudicated = adjudicate_severity_challenge(
        challenged,
        _adjudication(resolved_premise_ids=["PREM-INVENTED-BY-ASSESSOR"]),
    )

    assert adjudicated["status"] == "UNRESOLVED_SEVERITY"
    assert adjudicated["final_severity"] is None


def test_external_favorable_claim_needs_premise_bound_citation_evidence():
    assessment = _downward_assessment(
        likelihood={
            **_assessment()["likelihood"],
            "premise_kind": "EXTERNAL_FAVORABLE",
            "evidence_ids": ["EXT-RECEIPT-A"],
            "proof_scope": "PRIMARY_EXTERNAL_CITED",
        },
        adjustment={
            "direction": "DOWN",
            "premise_ids": ["PREM-LIKELIHOOD"],
            "evidence_ids": ["EXT-RECEIPT-B"],
            "proof_scope": "PRIMARY_EXTERNAL_CITED",
            "rationale": "A favorable external behavior is asserted.",
        },
    )
    challenged = build_severity_decision(assessment)
    adjudicated = adjudicate_severity_challenge(
        challenged,
        _adjudication(
            evidence_ids=["EXT-RECEIPT-C"],
            proof_scope="PRIMARY_EXTERNAL_CITED",
        ),
    )

    assert adjudicated["status"] == "UNRESOLVED_SEVERITY"
    assert adjudicated["final_severity"] is None


def test_multi_constituent_claim_needs_explicit_evidence_binding_per_member():
    assessment = _assessment(
        constituent_ids=["HYP-AR-1", "HYP-AR-2"],
        constituent_premise_outcomes={
            "HYP-AR-1": {"impact": "SUPPORTED", "likelihood": "SUPPORTED"},
            "HYP-AR-2": {"impact": "SUPPORTED", "likelihood": "SUPPORTED"},
        },
    )
    decision = build_severity_decision(assessment)

    # One global premise/evidence pair does not prove that the same claim and
    # proof scope cover both constituents.
    assert decision["status"] == "CHALLENGE_REQUIRED"
    assert decision["final_severity"] is None


def test_divergent_constituents_cannot_be_flattened_by_one_premise_decision():
    assessment = _downward_assessment(
        constituent_ids=["HYP-AR-1", "HYP-AR-2"],
        constituent_premise_outcomes={
            "HYP-AR-1": {"impact": "SUPPORTED", "likelihood": "REFUTED"},
            "HYP-AR-2": {"impact": "SUPPORTED", "likelihood": "UNRESOLVED"},
        },
    )
    challenged = build_severity_decision(assessment)
    adjudicated = adjudicate_severity_challenge(challenged, _adjudication())

    assert adjudicated["status"] == "UNRESOLVED_SEVERITY"
    assert adjudicated["final_severity"] is None


def test_adjudicator_cannot_choose_an_arbitrary_tier_without_resolved_axes():
    assessment = _downward_assessment(
        proposed_severity="Informational",
        adjustment={
            "direction": "DOWN",
            "premise_ids": ["PREM-LIKELIHOOD"],
            "evidence_ids": ["EVID-LIKELIHOOD"],
            "proof_scope": "IN_SCOPE_SOURCE",
            "rationale": "One likelihood premise is claimed to be refuted.",
        },
    )
    challenged = build_severity_decision(assessment)
    adjudicated = adjudicate_severity_challenge(
        challenged,
        _adjudication(resolved_severity="Informational"),
    )

    # A final Impact x Likelihood tier requires independently resolved axes;
    # selecting the assessor's number is not itself adjudication.
    assert adjudicated["status"] == "UNRESOLVED_SEVERITY"
    assert adjudicated["final_severity"] is None


def test_a_second_adjudicator_cannot_silently_overwrite_the_first_event():
    challenged = build_severity_decision(_downward_assessment())
    first = adjudicate_severity_challenge(challenged, _adjudication())
    assert first["status"] == "RESOLVED"
    assert first["final_severity"] == "Medium"

    second = adjudicate_severity_challenge(
        first,
        _adjudication(
            adjudicator_identity="adjudicator-c",
            adjudicator_invocation_id="invocation-c",
            decision="ACCEPT_MATRIX",
            resolved_severity="High",
        ),
    )

    assert second["status"] == "UNRESOLVED_SEVERITY"
    assert second["final_severity"] is None
    assert second["adjudication"] != first["adjudication"] or "adjudication_history" in second


def test_digest_recomputed_semantic_tamper_is_rejected_on_load(tmp_path: Path):
    decision = build_severity_decision(_assessment())
    path = tmp_path / "severity_decision_ledger.json"
    write_severity_decision_ledger(path, "run-review", [decision])

    payload = json.loads(path.read_text(encoding="utf-8"))
    row = payload["decisions"][0]
    row["status"] = "RESOLVED"
    row["final_severity"] = "Low"
    row["retention_severity"] = "Low"
    row_unsigned = {key: value for key, value in row.items() if key != "decision_digest"}
    row["decision_digest"] = _digest(row_unsigned)
    ledger_unsigned = {
        key: value for key, value in payload.items() if key != "ledger_digest"
    }
    payload["ledger_digest"] = _digest(ledger_unsigned)
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(SeverityDecisionError):
        load_severity_decision_ledger(path, expected_run_id="run-review")


def test_decision_row_cannot_be_replayed_under_a_different_run(tmp_path: Path):
    decision = build_severity_decision(_assessment())
    first = tmp_path / "run-1.json"
    replay = tmp_path / "run-2.json"
    write_severity_decision_ledger(first, "run-1", [decision])

    with pytest.raises(SeverityDecisionError):
        write_severity_decision_ledger(replay, "run-2", [decision])


def test_adjudication_must_state_resolved_axes_not_infer_them_from_target_tier():
    challenged = build_severity_decision(_attested_downward_assessment())

    # This event names a premise and an evidence receipt, but it never states
    # the independently decided likelihood class.  Inferring Low solely
    # because Low is the only class that yields the requested Medium tier is
    # circular: the target tier becomes its own evidence.
    adjudicated = adjudicate_severity_challenge(challenged, _adjudication())

    assert adjudicated["status"] == "UNRESOLVED_SEVERITY"
    assert adjudicated["final_severity"] is None


def test_one_adjudication_event_cannot_be_replayed_for_another_candidate():
    first_assessment = _attested_downward_assessment()
    second_assessment = _attested_downward_assessment(
        candidate_id="HYP-AR-2",
        constituent_ids=["HYP-AR-2"],
        constituent_premise_outcomes={
            "HYP-AR-2": {"impact": "SUPPORTED", "likelihood": "SUPPORTED"}
        },
        source_receipt_digest="b" * 64,
        evidence_receipts=[
            {
                **row,
                "constituent_ids": ["HYP-AR-2"],
            }
            for row in _attested_assessment()["evidence_receipts"]
        ],
    )
    first_decision = build_severity_decision(first_assessment)
    raw_event = _adjudication(
        resolved_axes={"impact": "High", "likelihood": "Low"},
        run_id=first_decision["run_id"],
        source_receipt_digest=first_decision["source_receipt_digest"],
        source_decision_digest=first_decision["decision_digest"],
        candidate_id=first_decision["candidate_id"],
        constituent_ids=list(first_decision["constituent_ids"]),
        prior_severity=first_decision["retention_severity"],
    )
    first = adjudicate_severity_challenge(first_decision, raw_event)
    assert first["status"] == "RESOLVED"

    second = adjudicate_severity_challenge(
        build_severity_decision(second_assessment), raw_event
    )

    # An immutable event must bind its source decision digest, run, candidate,
    # prior tier, and affected constituents.  A context-free dict is not an
    # independently scoped adjudication authority.
    assert second["status"] == "UNRESOLVED_SEVERITY"
    assert second["final_severity"] is None


def test_modifier_effect_cannot_use_unregistered_modifier_evidence():
    assessment = _attested_assessment(
        upstream_severity="Critical",
        proposed_severity="High",
        impact={**_assessment()["impact"], "class": "High"},
        likelihood={**_assessment()["likelihood"], "class": "High"},
        modifiers=[
            {
                "kind": "FULLY_TRUSTED_ACTOR",
                "applies": True,
                "applicability_predicate": "the exact capability is trusted",
                "evidence_ids": ["EVID-MODIFIER-FOREIGN"],
                "proof_scope": "IN_SCOPE_SOURCE",
            }
        ],
        adjustment={
            "direction": "DOWN",
            "premise_ids": ["PREM-LIKELIHOOD"],
            "evidence_ids": ["EVID-LIKELIHOOD"],
            "proof_scope": "IN_SCOPE_SOURCE",
            "rationale": "The structured modifier is claimed to apply.",
        },
    )
    challenged = build_severity_decision(assessment)
    adjudicated = adjudicate_severity_challenge(
        challenged,
        _adjudication(resolved_severity="High"),
    )

    assert adjudicated["status"] == "UNRESOLVED_SEVERITY"
    assert adjudicated["final_severity"] is None


def test_invalid_modifier_source_state_cannot_be_adjudicated_away():
    assessment = _attested_assessment(
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
    challenged = build_severity_decision(assessment)
    assert "MODIFIER_APPLICABILITY_UNPROVEN" in challenged["challenge_codes"]
    adjudicated = adjudicate_severity_challenge(
        challenged,
        _adjudication(
            decision="ACCEPT_MATRIX",
            resolved_severity="High",
        ),
    )

    assert adjudicated["status"] == "UNRESOLVED_SEVERITY"
    assert adjudicated["final_severity"] is None


def test_adjudicating_one_axis_cannot_erase_another_unresolved_axis():
    assessment = _attested_assessment(
        constituent_premise_outcomes={
            "HYP-AR-1": {"impact": "SUPPORTED", "likelihood": "UNRESOLVED"}
        }
    )
    challenged = build_severity_decision(assessment)
    adjudicated = adjudicate_severity_challenge(
        challenged,
        _adjudication(
            decision="ACCEPT_MATRIX",
            resolved_severity="High",
            resolved_premise_ids=["PREM-IMPACT"],
            evidence_ids=["EVID-IMPACT"],
            proof_scope="IN_SCOPE_EXECUTION",
        ),
    )

    assert adjudicated["status"] == "UNRESOLVED_SEVERITY"
    assert adjudicated["final_severity"] is None


def test_report_projection_semantically_replays_a_digest_valid_decision():
    decision = build_severity_decision(_attested_assessment())
    forged = dict(decision)
    forged["final_severity"] = "Low"
    unsigned = {
        key: value for key, value in forged.items() if key != "decision_digest"
    }
    forged["decision_digest"] = _digest(unsigned)

    with pytest.raises(SeverityDecisionError):
        project_report_severity(forged)


def test_legacy_ledger_authority_status_is_recomputed_not_hash_trusted(tmp_path: Path):
    decision = build_severity_decision(_assessment())
    path = tmp_path / "legacy-severity-ledger.json"
    payload = write_severity_decision_ledger(path, "legacy-run", [decision])
    assert payload["authority_status"] == "UNATTESTED_COMPATIBILITY"

    payload["authority_status"] = "REPORT_AUTHORITATIVE"
    unsigned = {
        key: value for key, value in payload.items() if key != "ledger_digest"
    }
    payload["ledger_digest"] = _digest(unsigned)
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(SeverityDecisionError):
        load_severity_decision_ledger(path, expected_run_id="legacy-run")


def test_assessor_cannot_self_attest_the_evidence_receipts_used_as_authority():
    assessment = _attested_assessment(
        evidence_receipts=[
            {
                **row,
                "issuer_identity": "verifier-a",
                "issuer_invocation_id": "invocation-a",
            }
            for row in _attested_assessment()["evidence_receipts"]
        ]
    )
    decision = build_severity_decision(assessment)

    assert decision["status"] == "CHALLENGE_REQUIRED"
    with pytest.raises(SeverityDecisionError):
        project_report_severity(decision)
