"""P0-AG/P1-E contracts for authentic evidence capability issuance.

These fixtures intentionally exercise the provider boundary, not just the
downstream severity ledger's permissive receipt shape.  A model-authored row
cannot grant itself semantic authority merely by spelling a capability name.
"""
from __future__ import annotations

import hashlib
import json

import pytest

from evidence_capabilities import (
    COMPOSITION_EVIDENCE_SCHEMA,
    EXECUTED_POC_EVIDENCE_SCHEMA,
    EXTERNAL_CITATION_EVIDENCE_SCHEMA,
    FORMAL_PROPERTY_EVIDENCE_SCHEMA,
    EvidenceCapabilityError,
    issue_composition_receipt,
    issue_executed_poc_receipt,
    issue_external_citation_receipt,
    issue_formal_property_receipt,
    validate_evidence_receipt,
)
from severity_decision_ledger import (
    ADJUDICATION_PROPOSAL_SCHEMA,
    SeverityDecisionError,
    compile_severity_adjudication_prompt_contract,
    parse_severity_adjudication_proposal,
)


def _sha(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _authority() -> dict[str, str]:
    return {
        "source_author_identity": "evidence-author",
        "source_author_invocation_id": "evidence-author-run-1",
        "issuer_identity": "evidence-registrar",
        "issuer_invocation_id": "evidence-registrar-run-1",
    }


def _external(**updates: object) -> dict[str, object]:
    row: dict[str, object] = {
        "schema_version": EXTERNAL_CITATION_EVIDENCE_SCHEMA,
        "evidence_id": "EXT-ROW-1",
        "citation_row_id": "external-ledger-row-1",
        "source_uri": "https://spec.example.invalid/primary-source",
        "source_sha256": _sha("primary-source"),
        "excerpt_sha256": _sha("exact-cited-excerpt"),
        "fact_role": "LIKELIHOOD_FREQUENCY",
        "premise_ids": ["PREM-L-1"],
        "constituent_ids": ["HYP-1"],
        "citation_status": "PRIMARY_SOURCE_VERIFIED",
        **_authority(),
    }
    row.update(updates)
    return row


def _formal(**updates: object) -> dict[str, object]:
    row: dict[str, object] = {
        "schema_version": FORMAL_PROPERTY_EVIDENCE_SCHEMA,
        "evidence_id": "FORMAL-1",
        "property_id": "PROPERTY-1",
        "property_statement_sha256": _sha("property statement"),
        "source_snapshot_sha256": _sha("source snapshot"),
        "toolchain_sha256": _sha("toolchain"),
        "proof_artifact_sha256": _sha("proof artifact"),
        "proof_result": "PROVED",
        "declared_property_scope": "HARM",
        "premise_ids": ["PREM-I-1"],
        "constituent_ids": ["HYP-1"],
        **_authority(),
    }
    row.update(updates)
    return row


def _poc(**updates: object) -> dict[str, object]:
    row: dict[str, object] = {
        "schema_version": EXECUTED_POC_EVIDENCE_SCHEMA,
        "evidence_id": "POC-1",
        "source_snapshot_sha256": _sha("source snapshot"),
        "build_sha256": _sha("build"),
        "command_sha256": _sha("command"),
        "oracle_sha256": _sha("oracle"),
        "output_sha256": _sha("output"),
        "execution_status": "COMPLETED",
        "execution_result": "ESTABLISHED",
        "exit_code": 0,
        "oracle_provenance": "MODEL_GENERATED_ORACLE",
        "oracle_author_identity": "oracle-author",
        "oracle_author_invocation_id": "oracle-author-run-1",
        "oracle_review_status": "NOT_REVIEWED",
        "oracle_reviewer_identity": None,
        "oracle_reviewer_invocation_id": None,
        "reachability": "IN_SCOPE_REACHABLE",
        "proof_target": "HARM",
        "premise_ids": ["PREM-I-1"],
        "constituent_ids": ["HYP-1"],
        **_authority(),
    }
    row.update(updates)
    return row


def _composition(**updates: object) -> dict[str, object]:
    row: dict[str, object] = {
        "schema_version": COMPOSITION_EVIDENCE_SCHEMA,
        "evidence_id": "COMP-1",
        "composition_id": "CHAIN-1",
        "composition_method": "EXECUTED_COMPOSED_HARNESS",
        "relation_graph_sha256": _sha("relation graph"),
        "artifact_sha256": _sha("composed harness output"),
        "execution_result": "ESTABLISHED",
        "reachability": "IN_SCOPE_REACHABLE",
        "premise_ids": ["PREM-C-1"],
        "constituent_ids": ["HYP-1", "HYP-2"],
        **_authority(),
    }
    row.update(updates)
    return row


def test_exact_external_row_issues_only_typed_fact_capabilities():
    receipt = issue_external_citation_receipt(_external())
    assert receipt["proof_scope"] == "PRIMARY_EXTERNAL_CITED"
    assert receipt["capabilities"] == ["EXTERNAL_FACT", "LIKELIHOOD"]
    assert receipt["content_sha256"] == _sha(
        json.dumps(_external(), sort_keys=True, separators=(",", ":"))
    )
    assert validate_evidence_receipt(receipt) == receipt


@pytest.mark.parametrize(
    "mutation",
    (
        {"issuer_identity": "evidence-author"},
        {"issuer_invocation_id": "evidence-author-run-1"},
        {"source_uri": "not-a-primary-source-uri"},
        {"citation_status": "MODEL_SUMMARY"},
        {"capabilities": ["HARM"]},
    ),
)
def test_external_provider_rejects_self_grants_and_untyped_authority(mutation):
    with pytest.raises(EvidenceCapabilityError):
        issue_external_citation_receipt(_external(**mutation))


def test_formal_property_grants_only_its_declared_proved_scope():
    receipt = issue_formal_property_receipt(_formal())
    assert receipt["proof_scope"] == "FORMAL_PROOF"
    assert receipt["capabilities"] == ["HARM"]
    with pytest.raises(EvidenceCapabilityError):
        issue_formal_property_receipt(_formal(proof_result="UNKNOWN"))


def test_generated_harm_oracle_cannot_self_upgrade_execution_into_harm():
    receipt = issue_executed_poc_receipt(_poc())
    assert receipt["capabilities"] == ["EXECUTION", "MECHANISM"]
    assert "HARM" not in receipt["capabilities"]


def test_independently_reviewed_reachable_oracle_can_issue_exact_harm_scope():
    receipt = issue_executed_poc_receipt(
        _poc(
            oracle_review_status="INDEPENDENTLY_VALIDATED",
            oracle_reviewer_identity="oracle-reviewer",
            oracle_reviewer_invocation_id="oracle-reviewer-run-1",
        )
    )
    assert receipt["capabilities"] == ["EXECUTION", "HARM", "MECHANISM"]


def test_unreachable_or_partial_execution_proves_execution_authenticity_only():
    receipt = issue_executed_poc_receipt(
        _poc(
            reachability="EXTERNAL_ENVIRONMENT_UNPROVEN",
            oracle_review_status="INDEPENDENTLY_VALIDATED",
            oracle_reviewer_identity="oracle-reviewer",
            oracle_reviewer_invocation_id="oracle-reviewer-run-1",
        )
    )
    assert receipt["capabilities"] == ["EXECUTION"]


def test_execution_contract_is_non_coercive_and_exact():
    with pytest.raises(EvidenceCapabilityError):
        issue_executed_poc_receipt(_poc(exit_code=True))
    with pytest.raises(EvidenceCapabilityError):
        issue_executed_poc_receipt(_poc(arbitrary_model_grant=["HARM"]))
    with pytest.raises(EvidenceCapabilityError):
        issue_executed_poc_receipt(
            _poc(
                oracle_review_status="INDEPENDENTLY_VALIDATED",
                oracle_reviewer_identity="oracle-author",
                oracle_reviewer_invocation_id="other-run",
            )
        )


def test_composed_evidence_never_manufactures_harm_capability():
    receipt = issue_composition_receipt(_composition())
    assert receipt["proof_scope"] == "IN_SCOPE_EXECUTION"
    assert receipt["capabilities"] == ["COMPOSITION", "EXECUTION"]
    assert "HARM" not in receipt["capabilities"]
    with pytest.raises(EvidenceCapabilityError):
        issue_composition_receipt(_composition(constituent_ids=["HYP-1"]))


def _unresolved_adjudication(**updates: object) -> dict[str, object]:
    proposal: dict[str, object] = {
        "schema_version": ADJUDICATION_PROPOSAL_SCHEMA,
        "decision": "UNRESOLVED",
        "resolved_severity": None,
        "resolved_premise_ids": [],
        "evidence_ids": [],
        "proof_scope": None,
        "rationale": "Available evidence does not resolve the disputed premise.",
        "resolved_axes": None,
        "constituent_resolutions": {},
    }
    proposal.update(updates)
    return proposal


def test_honest_unresolved_adjudication_needs_no_fabricated_axes_or_scope():
    proposal = _unresolved_adjudication()
    assert parse_severity_adjudication_proposal(proposal) == proposal
    with pytest.raises(SeverityDecisionError):
        parse_severity_adjudication_proposal(
            _unresolved_adjudication(resolved_axes={"impact": "High", "likelihood": "Low"})
        )
    with pytest.raises(SeverityDecisionError):
        parse_severity_adjudication_proposal(
            _unresolved_adjudication(proof_scope="IN_SCOPE_SOURCE")
        )


def test_adjudication_prompt_schema_checklist_and_parser_share_one_contract():
    contract = compile_severity_adjudication_prompt_contract()
    schema = contract["json_schema"]
    assert schema["required"] == contract["required_fields"]
    assert set(schema["required"]) == set(_unresolved_adjudication())
    assert json.dumps(schema, sort_keys=True) in contract["markdown"]
    assert "resolved_axes" in contract["markdown"]
    assert "UNRESOLVED" in contract["markdown"]
    assert parse_severity_adjudication_proposal(contract["unresolved_example"])


def test_adjudication_prompt_contract_is_backend_neutral_and_byte_stable():
    claude_contract = compile_severity_adjudication_prompt_contract()
    codex_contract = compile_severity_adjudication_prompt_contract()
    assert json.dumps(claude_contract, sort_keys=True) == json.dumps(
        codex_contract, sort_keys=True
    )
    markdown = claude_contract["markdown"].casefold()
    assert "claude" not in markdown
    assert "codex" not in markdown
