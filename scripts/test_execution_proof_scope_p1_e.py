"""P1-E typed execution-authenticity and proof-scope contracts.

The provider is deliberately verdict-neutral.  It can authenticate execution,
bound the maximum positive/negative claim supported by that execution, and
retain malformed or legacy evidence as visible debt.  It cannot decide that a
candidate is safe or assign severity.
"""

from __future__ import annotations

import hashlib
import json
import copy
from pathlib import Path

import pytest

from evidence_capabilities import (
    EXECUTED_POC_SCOPE_EVIDENCE_SCHEMA,
    EXTERNAL_CITATION_EVIDENCE_SCHEMA,
    EvidenceCapabilityError,
    assess_executed_poc_scope,
    issue_executed_poc_scope_assessment,
    issue_external_citation_receipt,
    reconcile_execution_evidence_tags,
    validate_executed_poc_scope_assessment,
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


def _record(**updates: object) -> dict[str, object]:
    value: dict[str, object] = {
        "schema_version": EXECUTED_POC_SCOPE_EVIDENCE_SCHEMA,
        "candidate_id": "HYP-1",
        "evidence_id": "POC-SCOPE-1",
        "source_snapshot_sha256": _sha("source"),
        "build_sha256": _sha("build"),
        "command_sha256": _sha("command"),
        "oracle_sha256": _sha("oracle"),
        "output_sha256": _sha("output"),
        "runner_receipt_sha256": _sha("runner receipt"),
        "launch_receipt_sha256": _sha("launch receipt"),
        "execution_status": "COMPLETED",
        "execution_result": "ESTABLISHED",
        "exit_code": 0,
        "oracle_provenance": "PROTOCOL_AUTHORED_INVARIANT",
        "oracle_derivation": "PROTOCOL_SOURCE_BOUND",
        "oracle_author_identity": "protocol-source",
        "oracle_author_invocation_id": "protocol-source-v1",
        "oracle_review_status": "NOT_REVIEWED",
        "oracle_reviewer_identity": None,
        "oracle_reviewer_invocation_id": None,
        "reachability": "IN_SCOPE_REACHABLE",
        "environment_fidelity": "FULL_IN_SCOPE",
        "proof_scope": "HARM",
        "negative_exhaustiveness": "NOT_APPLICABLE",
        "required_precondition_ids": ["PRE-1", "PRE-2"],
        "represented_precondition_ids": ["PRE-1", "PRE-2"],
        "external_premises": [],
        "external_evidence_receipts": [],
        "premise_ids": ["PREM-H-1"],
        "constituent_ids": ["HYP-1"],
        "source_author_identity": "evidence-author",
        "source_author_invocation_id": "evidence-author-run-1",
        "issuer_identity": "driver-evidence-registrar",
        "issuer_invocation_id": "driver-evidence-registrar-run-1",
    }
    value.update(updates)
    return value


def _external_receipt(**updates: object) -> dict[str, object]:
    value: dict[str, object] = {
        "schema_version": EXTERNAL_CITATION_EVIDENCE_SCHEMA,
        "evidence_id": "EXT-EVID-1",
        "citation_row_id": "EXT-ROW-1",
        "source_uri": "https://primary.example.invalid/spec",
        "source_sha256": _sha("external source"),
        "excerpt_sha256": _sha("external excerpt"),
        "fact_role": "EXTERNAL_FACT_ONLY",
        "premise_ids": ["EXT-PREM-1"],
        "constituent_ids": ["HYP-1"],
        "citation_status": "PRIMARY_SOURCE_VERIFIED",
        "source_author_identity": "external-researcher",
        "source_author_invocation_id": "external-researcher-run-1",
        "issuer_identity": "external-evidence-registrar",
        "issuer_invocation_id": "external-evidence-registrar-run-1",
    }
    value.update(updates)
    return issue_external_citation_receipt(value)


def _independently_reviewed_generated(**updates: object) -> dict[str, object]:
    return _record(
        oracle_provenance="MODEL_GENERATED_ORACLE",
        oracle_derivation="IN_SCOPE_CLAIM_BOUND",
        oracle_author_identity="verification-worker",
        oracle_author_invocation_id="verification-worker-run-1",
        oracle_review_status="INDEPENDENTLY_VALIDATED",
        oracle_reviewer_identity="independent-oracle-reviewer",
        oracle_reviewer_invocation_id="independent-oracle-reviewer-run-1",
        **updates,
    )


def test_contract_authored_invariant_failure_can_support_exact_harm_scope():
    result = issue_executed_poc_scope_assessment(_record())
    assert result["execution_authenticity"] == "AUTHENTICATED"
    assert result["oracle_authority"] == "PROTOCOL_AUTHORED"
    assert result["proof_scope"] == "HARM"
    assert result["positive_capabilities"] == [
        "EXECUTION",
        "HARM",
        "MECHANISM",
        "REACHABILITY",
    ]
    assert result["harm_evidence_eligible"] is True
    assert result["candidate_state"] == "ADJUDICATION_REQUIRED"
    assert validate_executed_poc_scope_assessment(result) == result


def test_generated_mechanism_probe_proves_mechanism_not_protocol_harm():
    result = issue_executed_poc_scope_assessment(
        _record(
            oracle_provenance="MODEL_GENERATED_ORACLE",
            oracle_derivation="IN_SCOPE_CLAIM_BOUND",
            oracle_author_identity="verification-worker",
            oracle_author_invocation_id="verification-worker-run-1",
            proof_scope="MECHANISM_ONLY",
        )
    )
    assert result["oracle_authority"] == "GENERATED_UNREVIEWED"
    assert result["positive_capabilities"] == ["EXECUTION", "MECHANISM"]
    assert result["harm_evidence_eligible"] is False
    assert result["negative_disposition_eligible"] is False


def test_generated_harm_oracle_needs_independent_in_scope_validation():
    unreviewed = issue_executed_poc_scope_assessment(
        _record(
            oracle_provenance="CANDIDATE_DERIVED_ORACLE",
            oracle_derivation="IN_SCOPE_CLAIM_BOUND",
            oracle_author_identity="verification-worker",
            oracle_author_invocation_id="verification-worker-run-1",
        )
    )
    assert "HARM" not in unreviewed["positive_capabilities"]
    assert "ORACLE_SEMANTIC_AUTHORITY_MISSING" in unreviewed["debts"]

    reviewed = issue_executed_poc_scope_assessment(
        _independently_reviewed_generated()
    )
    assert "HARM" in reviewed["positive_capabilities"]
    assert reviewed["oracle_authority"] == "INDEPENDENTLY_VALIDATED"


def test_unreachable_harness_authenticates_execution_but_nothing_semantic():
    result = issue_executed_poc_scope_assessment(
        _record(
            execution_result="NOT_ESTABLISHED",
            reachability="UNREACHABLE",
            environment_fidelity="UNREACHABLE",
            negative_exhaustiveness="SINGLE_PARAMETERIZATION",
        )
    )
    assert result["positive_capabilities"] == ["EXECUTION"]
    assert result["maximum_negative_scope"] == "ENCODED_PARAMETERIZATION_ONLY"
    assert result["negative_disposition_eligible"] is False
    assert "HARNESS_UNREACHABLE" in result["debts"]


def test_unresearched_external_dependency_blocks_harm_not_visibility():
    result = issue_executed_poc_scope_assessment(
        _record(
            reachability="EXTERNAL_ENVIRONMENT_UNPROVEN",
            environment_fidelity="EXTERNAL_UNPROVEN",
            external_premises=[
                {
                    "premise_id": "EXT-PREM-1",
                    "evidence_state": "UNRESEARCHED",
                    "evidence_ids": [],
                }
            ],
            premise_ids=["PREM-H-1", "EXT-PREM-1"],
        )
    )
    assert result["external_premise_state"] == "UNRESOLVED"
    assert result["harm_evidence_eligible"] is False
    assert "HARM" not in result["positive_capabilities"]
    assert result["candidate_state"] == "ADJUDICATION_REQUIRED"
    assert "EXTERNAL_PREMISE_UNRESOLVED" in result["debts"]


def test_supported_external_premise_remains_separate_and_can_close_harm_scope():
    result = issue_executed_poc_scope_assessment(
        _record(
            external_premises=[
                {
                    "premise_id": "EXT-PREM-1",
                    "evidence_state": "SUPPORTED",
                    "evidence_ids": ["EXT-EVID-1"],
                }
            ],
            external_evidence_receipts=[_external_receipt()],
            premise_ids=["PREM-H-1", "EXT-PREM-1"],
        )
    )
    assert result["external_premise_state"] == "RESOLVED"
    assert result["harm_evidence_eligible"] is True
    assert "HARM" in result["positive_capabilities"]


@pytest.mark.parametrize(
    "receipts",
    [
        [],
        [_external_receipt(premise_ids=["EXT-PREM-OTHER"])],
        [_external_receipt(constituent_ids=["HYP-OTHER"])],
    ],
    ids=["unregistered-id", "wrong-premise", "wrong-candidate"],
)
def test_external_resolution_requires_exact_premise_and_candidate_bound_receipt(
    receipts: list[dict[str, object]],
):
    result = assess_executed_poc_scope(
        "HYP-1",
        _record(
            external_premises=[
                {
                    "premise_id": "EXT-PREM-1",
                    "evidence_state": "SUPPORTED",
                    "evidence_ids": ["EXT-EVID-1"],
                }
            ],
            external_evidence_receipts=receipts,
            premise_ids=["PREM-H-1", "EXT-PREM-1"],
        ),
    )
    assert result["candidate_state"] == "VISIBLE_EVIDENCE_DEBT"
    assert result["harm_evidence_eligible"] is False
    assert result["positive_capabilities"] == []
    assert "MISSING_OR_INVALID_SCOPE_METADATA" in result["debts"]


def test_external_receipt_cannot_float_unbound_to_a_premise_row():
    result = assess_executed_poc_scope(
        "HYP-1",
        _record(external_evidence_receipts=[_external_receipt()]),
    )
    assert result["candidate_state"] == "VISIBLE_EVIDENCE_DEBT"
    assert result["positive_capabilities"] == []
    assert "MISSING_OR_INVALID_SCOPE_METADATA" in result["debts"]


def test_missing_scope_legacy_artifact_is_visible_debt_not_an_exception():
    legacy = {
        "schema_version": "plamen.executed_poc_evidence.v1",
        "evidence_id": "LEGACY-POC-1",
        "execution_status": "COMPLETED",
        "execution_result": "REFUTED",
        "output_sha256": _sha("legacy output"),
    }
    result = assess_executed_poc_scope("HYP-1", legacy)
    assert result["execution_authenticity"] == "UNPROVEN_METADATA"
    assert result["proof_scope"] == "UNPROVEN"
    assert result["candidate_state"] == "VISIBLE_EVIDENCE_DEBT"
    assert result["positive_capabilities"] == []
    assert result["negative_disposition_eligible"] is False
    assert "MISSING_OR_INVALID_SCOPE_METADATA" in result["debts"]
    assert validate_executed_poc_scope_assessment(result) == result


def test_partial_precondition_coverage_cannot_be_relabelled_full_scope():
    result = issue_executed_poc_scope_assessment(
        _record(represented_precondition_ids=["PRE-1"])
    )
    assert result["precondition_coverage"] == "PARTIAL"
    assert result["positive_capabilities"] == ["EXECUTION"]
    assert result["harm_evidence_eligible"] is False
    assert "PRECONDITION_COVERAGE_PARTIAL" in result["debts"]


def test_negative_generated_poc_cannot_refute_beyond_encoded_parameterization():
    result = issue_executed_poc_scope_assessment(
        _record(
            execution_result="NOT_ESTABLISHED",
            negative_exhaustiveness="SINGLE_PARAMETERIZATION",
            oracle_provenance="MODEL_GENERATED_ORACLE",
            oracle_derivation="IN_SCOPE_CLAIM_BOUND",
            oracle_author_identity="verification-worker",
            oracle_author_invocation_id="verification-worker-run-1",
        )
    )
    assert result["maximum_negative_scope"] == "ENCODED_PARAMETERIZATION_ONLY"
    assert result["negative_disposition_eligible"] is False
    assert result["candidate_state"] == "ADJUDICATION_REQUIRED"


def test_exhaustive_independent_negative_is_eligible_only_for_declared_scope():
    result = issue_executed_poc_scope_assessment(
        _independently_reviewed_generated(
            execution_result="NOT_ESTABLISHED",
            proof_scope="REACHABILITY",
            negative_exhaustiveness="EXHAUSTIVE_IN_SCOPE",
        )
    )
    assert result["maximum_negative_scope"] == "REACHABILITY"
    assert result["negative_disposition_eligible"] is True
    assert result["harm_evidence_eligible"] is False
    assert result["candidate_state"] == "ADJUDICATION_REQUIRED"


def test_exhaustive_generated_negative_still_cannot_self_authorize_refutation():
    result = issue_executed_poc_scope_assessment(
        _record(
            execution_result="NOT_ESTABLISHED",
            negative_exhaustiveness="EXHAUSTIVE_IN_SCOPE",
            oracle_provenance="HEURISTIC_ASSERTION",
            oracle_derivation="HEURISTIC",
            oracle_author_identity="verification-worker",
            oracle_author_invocation_id="verification-worker-run-1",
        )
    )
    assert result["maximum_negative_scope"] == "ENCODED_ORACLE_ONLY"
    assert result["negative_disposition_eligible"] is False
    assert "NEGATIVE_SCOPE_NOT_TERMINAL" in result["debts"]


def test_execution_tag_and_typed_result_polarity_mismatch_is_visible_debt():
    assessment = issue_executed_poc_scope_assessment(_record())
    result = reconcile_execution_evidence_tags(
        "Evidence Tag: [POC-FAIL]", assessment
    )
    assert result["status"] == "POLARITY_MISMATCH"
    assert result["proof_grade_harm"] is False
    assert result["negative_disposition_eligible"] is False
    assert "TAG_RESULT_POLARITY_MISMATCH" in result["debts"]


def test_bare_fuzzer_tag_without_typed_scope_is_not_harm_proof():
    result = reconcile_execution_evidence_tags(
        "Evidence Tag: [FUZZ-PASS]", None
    )
    assert result["status"] == "MISSING_TYPED_EVIDENCE"
    assert result["effective_capabilities"] == []
    assert result["proof_grade_harm"] is False
    assert "MISSING_TYPED_EXECUTION_EVIDENCE" in result["debts"]


def test_mechanism_scoped_medusa_tag_stays_executed_mechanism_only():
    assessment = issue_executed_poc_scope_assessment(
        _record(
            proof_scope="MECHANISM_ONLY",
            oracle_provenance="MODEL_GENERATED_ORACLE",
            oracle_derivation="IN_SCOPE_CLAIM_BOUND",
            oracle_author_identity="verification-worker",
            oracle_author_invocation_id="verification-worker-run-1",
        )
    )
    result = reconcile_execution_evidence_tags(
        "Evidence Tag: [MEDUSA-PASS: counterexample observed]", assessment
    )
    assert result["status"] == "MATCHED_LIMITED_SCOPE"
    assert result["effective_capabilities"] == ["EXECUTION", "MECHANISM"]
    assert result["proof_grade_harm"] is False


def test_assessment_is_bound_to_candidate_identity():
    result = assess_executed_poc_scope("HYP-2", _record())
    assert result["candidate_id"] == "HYP-2"
    assert result["candidate_state"] == "VISIBLE_EVIDENCE_DEBT"
    assert "CANDIDATE_ID_MISMATCH" in result["debts"]


def test_assessment_digest_and_nested_receipt_binding_are_tamper_evident():
    result = issue_executed_poc_scope_assessment(_record())
    tampered = dict(result)
    tampered["proof_scope"] = "MECHANISM_ONLY"
    with pytest.raises(EvidenceCapabilityError):
        validate_executed_poc_scope_assessment(tampered)

    # Even if a mutator recomputes the outer self-digest, the generic receipt
    # and the typed assessment must carry the same derived capability set.
    tampered = copy.deepcopy(result)
    tampered["positive_capabilities"] = ["EXECUTION"]
    tampered["harm_evidence_eligible"] = False
    unsigned = {key: value for key, value in tampered.items() if key != "assessment_digest"}
    tampered["assessment_digest"] = _digest(unsigned)
    with pytest.raises(EvidenceCapabilityError):
        validate_executed_poc_scope_assessment(tampered)

    tampered = dict(result)
    tampered["evidence_receipt"] = {
        **result["evidence_receipt"],
        "content_sha256": _sha("different source record"),
    }
    with pytest.raises(EvidenceCapabilityError):
        validate_executed_poc_scope_assessment(tampered)


def test_external_premise_state_cannot_claim_resolution_without_evidence():
    result = assess_executed_poc_scope(
        "HYP-1",
        _record(
            external_premises=[
                {
                    "premise_id": "EXT-PREM-1",
                    "evidence_state": "SUPPORTED",
                    "evidence_ids": [],
                }
            ],
            premise_ids=["PREM-H-1", "EXT-PREM-1"],
        ),
    )
    assert result["candidate_state"] == "VISIBLE_EVIDENCE_DEBT"
    assert result["negative_disposition_eligible"] is False


def test_inconsistent_environment_metadata_fails_visible_not_safe():
    result = assess_executed_poc_scope(
        "HYP-1",
        _record(
            reachability="UNREACHABLE",
            environment_fidelity="FULL_IN_SCOPE",
        ),
    )
    assert result["candidate_state"] == "VISIBLE_EVIDENCE_DEBT"
    assert result["proof_scope"] == "UNPROVEN"


def test_compiled_methodology_names_every_orthogonal_evidence_dimension():
    root = Path(__file__).resolve().parent.parent
    registry = json.loads(
        (root / "verification_policy/verification_method_registry.v1.json")
        .read_text(encoding="utf-8")
    )
    operators = {row["operator_id"]: row["instruction"] for row in registry["operators"]}
    evidence = operators["evidence-proof-scope"].casefold()
    for required in (
        "execution authenticity",
        "oracle provenance",
        "environment",
        "reachability",
        "preconditions",
        "external-premise",
        "proof scope",
    ):
        assert required in evidence
    negative = operators["negative-error-trace"].casefold()
    assert "one generated parameterization" in negative
    assert "never the whole candidate" in negative


def test_fuzzer_prompts_no_longer_equate_bare_tag_with_protocol_harm_proof():
    root = Path(__file__).resolve().parent.parent
    paths = (
        "rules/phase5-poc-execution.md",
        "rules/finding-output-format.md",
        "prompts/evm/phase4b-loop.md",
        "prompts/evm/v2/phase4b-medusa-fuzz.md",
        "prompts/evm/v2/phase4b-invariant-fuzz.md",
        "prompts/solana/phase4b-invariant-fuzz.md",
        "prompts/solana/v2/phase4b-invariant-fuzz.md",
        "prompts/soroban/v2/phase4b-invariant-fuzz.md",
        "prompts/sui/v2/phase4b-invariant-fuzz.md",
        "prompts/l1/v2/phase5-verification-prompt.md",
    )
    joined = "\n".join((root / path).read_text(encoding="utf-8") for path in paths)
    normalized = joined.casefold()
    assert "same weight as [poc-pass]" not in normalized
    assert "counterexample = mechanical proof" not in normalized
    assert "attack does not work as described" not in normalized
    assert "supports confirmed at any severity" not in normalized
    assert "only tag that supports confirmed" not in normalized
