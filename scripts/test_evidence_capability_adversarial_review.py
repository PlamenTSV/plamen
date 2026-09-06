"""Independent red-team fixtures for typed evidence capability authority.

Production code is intentionally not modified by this review.  These tests pin
fail-closed behavior at the provider/parser boundary so identity spelling,
untrusted provenance labels, and an allegedly honest UNRESOLVED result cannot
manufacture authority.
"""
from __future__ import annotations

import hashlib
import json
import re
from types import SimpleNamespace

import pytest

from evidence_capabilities import (
    COMPOSITION_EVIDENCE_SCHEMA,
    EXECUTED_POC_EVIDENCE_SCHEMA,
    EXTERNAL_CITATION_EVIDENCE_SCHEMA,
    EvidenceCapabilityError,
    issue_executed_poc_receipt,
    issue_external_citation_receipt,
    issue_composition_receipt,
)
from severity_decision_ledger import (
    ADJUDICATION_PROPOSAL_SCHEMA,
    LAUNCH_RECEIPT_SCHEMA,
    SeverityDecisionError,
    bind_severity_adjudication,
    compile_severity_adjudication_prompt_contract,
    parse_severity_adjudication_proposal,
    project_retention_severity,
    severity_adjudicator_input_digest,
    severity_assessor_input_digest,
)
from severity_runtime import _proposal_evidence_receipts
import severity_adjudication_work as adjudication_work
from test_severity_adjudication_work_p0_ag3 import _decision as _bound_decision
from test_severity_adjudication_work_p0_ag3 import _prepare as _prepare_work
from test_severity_adjudication_work_p0_ag3 import _write_state as _write_work_state
from test_severity_decision_ledger_p0_ag import _assessment as _legacy_assessment
from test_severity_decision_ledger_p0_ag import (
    _driver_bound_decision as _bind_legacy_assessment,
)


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


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


def _authority(**updates: object) -> dict[str, object]:
    value: dict[str, object] = {
        "source_author_identity": "evidence-author",
        "source_author_invocation_id": "evidence-author-run-1",
        "issuer_identity": "evidence-registrar",
        "issuer_invocation_id": "evidence-registrar-run-1",
    }
    value.update(updates)
    return value


def _external(**updates: object) -> dict[str, object]:
    value: dict[str, object] = {
        "schema_version": EXTERNAL_CITATION_EVIDENCE_SCHEMA,
        "evidence_id": "EXT-1",
        "citation_row_id": "CITATION-1",
        "source_uri": "https://primary.example.invalid/spec",
        "source_sha256": _sha("source"),
        "excerpt_sha256": _sha("excerpt"),
        "fact_role": "LIKELIHOOD_FREQUENCY",
        "premise_ids": ["PREM-L-1"],
        "constituent_ids": ["HYP-1"],
        "citation_status": "PRIMARY_SOURCE_VERIFIED",
        **_authority(),
    }
    value.update(updates)
    return value


def _poc(**updates: object) -> dict[str, object]:
    value: dict[str, object] = {
        "schema_version": EXECUTED_POC_EVIDENCE_SCHEMA,
        "evidence_id": "POC-1",
        "source_snapshot_sha256": _sha("source"),
        "build_sha256": _sha("build"),
        "command_sha256": _sha("command"),
        "oracle_sha256": _sha("oracle"),
        "output_sha256": _sha("output"),
        "execution_status": "COMPLETED",
        "execution_result": "ESTABLISHED",
        "exit_code": 0,
        "oracle_provenance": "INDEPENDENT_REVIEWER_ORACLE",
        "oracle_author_identity": "independent-oracle-author",
        "oracle_author_invocation_id": "independent-oracle-run-1",
        "oracle_review_status": "NOT_REVIEWED",
        "oracle_reviewer_identity": None,
        "oracle_reviewer_invocation_id": None,
        "reachability": "IN_SCOPE_REACHABLE",
        "proof_target": "HARM",
        "premise_ids": ["PREM-I-1"],
        "constituent_ids": ["HYP-1"],
        **_authority(),
    }
    value.update(updates)
    return value


def _composition(**updates: object) -> dict[str, object]:
    value: dict[str, object] = {
        "schema_version": COMPOSITION_EVIDENCE_SCHEMA,
        "evidence_id": "COMP-1",
        "composition_id": "CHAIN-1",
        "composition_method": "EXECUTED_COMPOSED_HARNESS",
        "relation_graph_sha256": _sha("relation graph"),
        "artifact_sha256": _sha("composition artifact"),
        "execution_result": "ESTABLISHED",
        "reachability": "IN_SCOPE_REACHABLE",
        "premise_ids": ["PREM-C-1"],
        "constituent_ids": ["HYP-1", "HYP-2"],
        **_authority(),
    }
    value.update(updates)
    return value


def _unresolved(**updates: object) -> dict[str, object]:
    value: dict[str, object] = {
        "schema_version": ADJUDICATION_PROPOSAL_SCHEMA,
        "decision": "UNRESOLVED",
        "resolved_severity": None,
        "resolved_premise_ids": [],
        "evidence_ids": [],
        "proof_scope": None,
        "rationale": "The available evidence does not resolve the premise.",
        "resolved_axes": None,
        "constituent_resolutions": {},
    }
    value.update(updates)
    return value


@pytest.mark.parametrize(
    "mutation",
    (
        {"issuer_identity": "Evidence-Author"},
        {"issuer_invocation_id": "Evidence-Author-Run-1"},
    ),
)
def test_case_only_principal_spelling_cannot_bypass_independence(mutation):
    with pytest.raises(EvidenceCapabilityError):
        issue_external_citation_receipt(_external(**mutation))


def test_independent_reviewer_oracle_must_be_independent_from_source_author():
    with pytest.raises(EvidenceCapabilityError):
        issue_executed_poc_receipt(
            _poc(
                oracle_author_identity="evidence-author",
                oracle_author_invocation_id="evidence-author-run-1",
            )
        )


def test_refuted_poc_cannot_mint_positive_semantic_capability_without_polarity():
    receipt = issue_executed_poc_receipt(
        _poc(execution_result="REFUTED")
    )
    assert "HARM" not in receipt["capabilities"]


def test_refuted_composition_cannot_mint_positive_composition_capability():
    receipt = issue_composition_receipt(
        _composition(execution_result="REFUTED")
    )
    assert receipt["capabilities"] == ["EXECUTION"]


def test_sha256_fields_are_strictly_lowercase_not_silently_coerced():
    with pytest.raises(EvidenceCapabilityError):
        issue_external_citation_receipt(
            _external(source_sha256=_sha("source").upper())
        )
    with pytest.raises(EvidenceCapabilityError):
        issue_external_citation_receipt(
            _external(source_sha256=f" {_sha('source')} ")
        )


def test_evidence_identifiers_are_not_silently_whitespace_normalized():
    with pytest.raises(EvidenceCapabilityError):
        issue_external_citation_receipt(_external(evidence_id=" EXT-1 "))


def test_case_only_premise_ids_are_rejected_as_ambiguous():
    with pytest.raises(EvidenceCapabilityError):
        issue_external_citation_receipt(
            _external(premise_ids=["PREM-L-1", "prem-l-1"])
        )


def test_case_only_evidence_ids_are_rejected_as_ambiguous_downstream():
    receipt = issue_external_citation_receipt(_external())
    other = {**receipt, "evidence_id": receipt["evidence_id"].lower()}
    with pytest.raises(SeverityDecisionError):
        severity_assessor_input_digest(
            candidate_id="HYP-1",
            constituent_ids=["HYP-1"],
            upstream_severity="High",
            run_id="run-1",
            source_receipt_digest=_sha("source receipt"),
            evidence_receipts=[receipt, other],
        )


def test_attempted_yes_prose_does_not_mint_execution_capability():
    proposal = {
        "impact": {
            "premise_id": "PREM-I-1",
            "proof_scope": "IN_SCOPE_EXECUTION",
            "evidence_ids": ["EVID-1"],
        },
        "likelihood": {
            "premise_id": "PREM-L-1",
            "proof_scope": "IN_SCOPE_EXECUTION",
            "evidence_ids": ["EVID-1"],
        },
        "adjustment": None,
        "modifiers": [],
    }
    receipts = _proposal_evidence_receipts(
        proposal,
        constituents=["HYP-1"],
        verify_receipt=SimpleNamespace(output_sha256=_sha("verifier output")),
        verify_markdown="Attempted: YES\nNo command or oracle receipt exists.\n",
        launch_digest=_sha("launch"),
    )
    assert "EXECUTION" not in receipts[0]["capabilities"]


def test_unresolved_cannot_claim_constituent_premise_resolutions():
    with pytest.raises(SeverityDecisionError):
        parse_severity_adjudication_proposal(
            _unresolved(
                constituent_resolutions={
                    "HYP-1": {"impact": "SUPPORTED", "likelihood": "REFUTED"}
                }
            )
        )

    contract = compile_severity_adjudication_prompt_contract()
    then_properties = contract["json_schema"]["allOf"][0]["then"]["properties"]
    assert then_properties["constituent_resolutions"]["maxProperties"] == 0


def _adjudicator_receipt(decision, proposal, *, identity, invocation):
    return {
        "schema_version": LAUNCH_RECEIPT_SCHEMA,
        "role": "ADJUDICATOR",
        "run_id": decision["run_id"],
        "candidate_id": decision["candidate_id"],
        "constituent_ids": decision["constituent_ids"],
        "worker_identity": identity,
        "invocation_id": invocation,
        "backend": "claude",
        "launch_manifest_sha256": "f" * 64,
        "input_sha256": severity_adjudicator_input_digest(decision),
        "output_sha256": _digest(proposal),
    }


def test_bound_honest_unresolved_round_trips_semantic_replay():
    decision = _bound_decision("H-UNRESOLVED")
    proposal = _unresolved()
    result = bind_severity_adjudication(
        proposal,
        decision=decision,
        adjudicator_launch_receipt=_adjudicator_receipt(
            decision,
            proposal,
            identity="independent-adjudicator",
            invocation="independent-adjudicator-run-1",
        ),
    )
    assert result["adjudication"]["proof_scope"] is None
    assert project_retention_severity(result)["severity"] == "High"


def test_bound_unresolved_preserves_rationale_bytes_for_exact_replay():
    decision = _bound_decision("H-RATIONALE")
    proposal = _unresolved(rationale="  Evidence is still insufficient.  ")
    result = bind_severity_adjudication(
        proposal,
        decision=decision,
        adjudicator_launch_receipt=_adjudicator_receipt(
            decision,
            proposal,
            identity="independent-adjudicator",
            invocation="independent-adjudicator-rationale-run",
        ),
    )
    assert result["adjudication"]["rationale"] == proposal["rationale"]
    assert project_retention_severity(result)["severity"] == "High"


def test_bound_resolved_adjudication_preserves_model_array_order_for_replay():
    decision = _bound_decision("H-ORDER")
    source = decision["assessment"]
    impact_premise = source["impact"]["premise_id"]
    likelihood_premise = source["likelihood"]["premise_id"]
    impact_evidence = source["impact"]["evidence_ids"][0]
    likelihood_evidence = source["likelihood"]["evidence_ids"][0]
    proposal = {
        "schema_version": ADJUDICATION_PROPOSAL_SCHEMA,
        "decision": "ACCEPT_PROPOSED",
        "resolved_severity": "Medium",
        # Reverse canonical sorting deliberately; JSON Schema does not impose
        # array order and an exact output receipt must remain replayable.
        "resolved_premise_ids": [likelihood_premise, impact_premise],
        "evidence_ids": [likelihood_evidence, impact_evidence],
        "proof_scope": "IN_SCOPE_SOURCE",
        "rationale": "Both independently bound premises support the result.",
        "resolved_axes": {"impact": "High", "likelihood": "Low"},
        "constituent_resolutions": {},
    }
    result = bind_severity_adjudication(
        proposal,
        decision=decision,
        adjudicator_launch_receipt=_adjudicator_receipt(
            decision,
            proposal,
            identity="independent-adjudicator",
            invocation="independent-adjudicator-order-run",
        ),
    )
    assert result["status"] == "RESOLVED"
    assert project_retention_severity(result)["severity"] == "High"


@pytest.mark.parametrize(
    "field",
    ("resolved_premise_ids", "evidence_ids"),
)
def test_model_identifier_whitespace_is_not_silently_normalized(field):
    proposal = {
        "schema_version": ADJUDICATION_PROPOSAL_SCHEMA,
        "decision": "ACCEPT_PROPOSED",
        "resolved_severity": "Medium",
        "resolved_premise_ids": ["PREM-I-1"],
        "evidence_ids": ["EVID-I-1"],
        "proof_scope": "IN_SCOPE_SOURCE",
        "rationale": "Bound evidence supports this result.",
        "resolved_axes": {"impact": "High", "likelihood": "Low"},
        "constituent_resolutions": {},
    }
    proposal[field] = [f" {proposal[field][0]} "]
    with pytest.raises(SeverityDecisionError):
        parse_severity_adjudication_proposal(proposal)


@pytest.mark.parametrize("principal_field", ("identity", "invocation"))
def test_case_only_adjudicator_principal_is_not_independent(principal_field):
    decision = _bound_decision(f"H-CASE-{principal_field}")
    proposal = _unresolved()
    source = decision["assessment"]
    identity = "independent-adjudicator"
    invocation = "independent-adjudicator-run-1"
    if principal_field == "identity":
        identity = source["assessor_identity"].swapcase()
    else:
        invocation = source["assessor_invocation_id"].swapcase()
    with pytest.raises(SeverityDecisionError):
        bind_severity_adjudication(
            proposal,
            decision=decision,
            adjudicator_launch_receipt=_adjudicator_receipt(
                decision,
                proposal,
                identity=identity,
                invocation=invocation,
            ),
        )


@pytest.mark.parametrize(
    ("field", "mutate"),
    (
        ("launch_manifest_sha256", lambda value: value.upper()),
        ("worker_identity", lambda value: f" {value} "),
        ("invocation_id", lambda value: f" {value} "),
    ),
)
def test_adjudicator_launch_authority_rejects_silent_normalization(field, mutate):
    decision = _bound_decision(f"H-LAUNCH-NORMALIZE-{field}")
    proposal = _unresolved()
    receipt = _adjudicator_receipt(
        decision,
        proposal,
        identity="independent-adjudicator",
        invocation="independent-adjudicator-run-1",
    )
    receipt[field] = mutate(receipt[field])
    with pytest.raises(SeverityDecisionError):
        bind_severity_adjudication(
            proposal,
            decision=decision,
            adjudicator_launch_receipt=receipt,
        )


@pytest.mark.parametrize(
    "field,value",
    (
        ("decision", {}),
        ("proof_scope", []),
        (
            "constituent_resolutions",
            {"HYP-1": {"impact": {}, "likelihood": "SUPPORTED"}},
        ),
    ),
)
def test_adjudication_parser_rejects_unhashable_schema_values_cleanly(field, value):
    proposal = _unresolved(**{field: value})
    with pytest.raises(SeverityDecisionError):
        parse_severity_adjudication_proposal(proposal)


def test_compiled_nonempty_strings_match_trim_aware_parser_semantics():
    contract = compile_severity_adjudication_prompt_contract()
    properties = contract["json_schema"]["properties"]
    for schema in (
        properties["rationale"],
        properties["resolved_premise_ids"]["items"],
        properties["evidence_ids"]["items"],
    ):
        pattern = schema.get("pattern")
        assert pattern and re.search(pattern, " ") is None

    for schema in (
        properties["resolved_premise_ids"]["items"],
        properties["evidence_ids"]["items"],
    ):
        pattern = schema["pattern"]
        assert re.search(pattern, " PREM-1") is None
        assert re.search(pattern, "PREM-1 ") is None


def test_live_adjudicator_packet_contains_exact_compiled_contract(tmp_path):
    decision = _bound_decision("H-CONTRACT")
    _write_work_state(tmp_path, [decision])
    plan = _prepare_work(tmp_path)
    assert plan["shards"]
    shard = plan["shards"][0]
    prompt = (tmp_path / shard["prompt_file"]).read_text(encoding="utf-8")
    context = json.loads(
        (tmp_path / shard["context_file"]).read_text(encoding="utf-8")
    )
    schema_json = json.dumps(
        compile_severity_adjudication_prompt_contract()["json_schema"],
        sort_keys=True,
    )
    worker_packet = prompt + "\n" + json.dumps(context, sort_keys=True)
    assert schema_json in worker_packet


def test_compiler_explicitly_documents_case_insensitive_identity_uniqueness():
    contract = compile_severity_adjudication_prompt_contract()
    checklist = "\n".join(contract["checklist"]).casefold()
    assert "case" in checklist and "duplicate" in checklist


def test_work_planner_rejects_case_only_self_adjudicator_before_launch(tmp_path):
    decision = _bound_decision("H-PLANNER-SELF")
    _write_work_state(tmp_path, [decision])
    assessor = decision["assessment"]["assessor_identity"]
    with pytest.raises(adjudication_work.AdjudicationWorkError):
        _prepare_work(tmp_path, adjudicator_identity=assessor.swapcase())


def test_work_planner_digests_are_strictly_lowercase(tmp_path):
    decision = _bound_decision("H-UPPER-DIGEST")
    _write_work_state(tmp_path, [decision])
    with pytest.raises(adjudication_work.AdjudicationWorkError):
        _prepare_work(tmp_path, audit_snapshot_digest="A" * 64)


def test_manifest_rejects_case_only_candidate_denominator_collision(
    tmp_path, monkeypatch
):
    upper = _bound_decision("H-CASE-COLLISION")
    lower = _bound_decision("h-case-collision")
    ledger = {"ledger_digest": _sha("ledger")}
    monkeypatch.setattr(
        adjudication_work,
        "_load_source_ledger",
        lambda *_args, **_kwargs: (
            ledger,
            {upper["candidate_id"]: upper, lower["candidate_id"]: lower},
        ),
    )
    with pytest.raises(adjudication_work.AdjudicationWorkError):
        adjudication_work.build_adjudication_manifest(
            tmp_path,
            run_id=upper["run_id"],
            audit_snapshot_digest="a" * 64,
            audit_config_digest="b" * 64,
            methodology_entries=[{"logical_name": "severity"}],
            methodology_digest="c" * 64,
        )


@pytest.mark.parametrize("principal_field", ("identity", "invocation"))
def test_downstream_assessor_cannot_case_alias_its_own_evidence(principal_field):
    assessment = _legacy_assessment()
    first = dict(assessment["evidence_receipts"][0])
    if principal_field == "identity":
        first["issuer_identity"] = assessment["assessor_identity"].swapcase()
    else:
        first["issuer_invocation_id"] = assessment[
            "assessor_invocation_id"
        ].swapcase()
    assessment["evidence_receipts"] = [
        first,
        dict(assessment["evidence_receipts"][1]),
    ]
    decision = _bind_legacy_assessment(assessment)
    assert "EVIDENCE_SELF_ATTESTED" in decision["challenge_codes"]


def test_formal_composition_proof_cannot_mint_execution_capability():
    receipt = issue_composition_receipt(
        _composition(composition_method="FORMAL_RELATION_PROOF")
    )
    assert receipt["proof_scope"] == "FORMAL_PROOF"
    assert "COMPOSITION" in receipt["capabilities"]
    assert "EXECUTION" not in receipt["capabilities"]


@pytest.mark.parametrize(
    "mutation",
    (
        {"evidence_id": "EXT-1\nINJECTED"},
        {"evidence_id": "EXT-1\u2028INJECTED"},
        {"premise_ids": ["PREM-L-1\nINJECTED"]},
        {"issuer_identity": "evidence-registrar\nINJECTED"},
        {"source_uri": "https://primary.example.invalid/spec\nINJECTED"},
    ),
)
def test_evidence_provider_identifiers_and_uri_reject_control_characters(mutation):
    with pytest.raises(EvidenceCapabilityError):
        issue_external_citation_receipt(_external(**mutation))
