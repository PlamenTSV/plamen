"""Typed terminal-negative evidence authority contracts.

These fixtures deliberately exercise the authority as a standalone boundary.
Driver and candidate-skeptic integration is a later cutover.
"""

from __future__ import annotations

import hashlib
import json

import pytest

import negative_closure_evidence_authority as A
import negative_closure_policy as P


H = "a" * 64
H2 = "b" * 64
H3 = "c" * 64


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _digest(value: object, field: str) -> str:
    unsigned = dict(value)  # type: ignore[arg-type]
    unsigned.pop(field, None)
    return hashlib.sha256(_canonical(unsigned)).hexdigest()


def _binding() -> dict:
    return {
        "candidate_id": "CAND-7",
        "work_item_id": "candidate-negative:000007",
        "candidate_premise_ids": ["PREM-1", "PREM-2"],
    }


def _claim(kind: str, outcome: str, *, claim_id: str = "CLAIM-1") -> dict:
    return {
        "claim_id": claim_id,
        "claim_kind": kind,
        "evidence_id": f"EVID-{claim_id}",
        "evidence_sha256": H3,
        "premise_ids": ["PREM-1", "PREM-2"],
        "outcome": outcome,
    }


def _output(kind: str) -> dict:
    common = {
        "schema_version": A.PROVIDER_OUTPUT_SCHEMA,
        "authority_kind": kind,
        "provider_id": "provider.scope.v1",
        "provider_version": "1.4.2",
        **_binding(),
        "evidence_claims": [],
        "scope_completeness": "EXACT_MECHANICAL_SCOPE",
        "oracle_authority": "DETERMINISTIC_MECHANICAL_PROVIDER",
        "mechanical_scope": None,
        "survivor_identity": None,
        "negative_execution": None,
    }
    if kind == A.MECHANICAL_SCOPE_EXCLUSION:
        common["evidence_claims"] = [
            _claim("MECHANICAL_SCOPE_FACT", "OUT_OF_SCOPE")
        ]
        common["mechanical_scope"] = {
            "exclusion_rule_id": "scope.rule.public-entry",
            "exclusion_rule_version": "2",
            "evaluated_subject_sha256": H,
            "result": "OUT_OF_SCOPE",
        }
    elif kind == A.APPLIED_LOSSLESS_EQUIVALENCE:
        common.update(
            {
                "provider_id": "provider.dedup.v1",
                "evidence_claims": [
                    _claim(
                        "LOSSLESS_EQUIVALENCE_APPLICATION",
                        "EQUIVALENT_TO_LIVE_SURVIVOR",
                    )
                ],
                "scope_completeness": "APPLIED_LOSSLESS_EQUIVALENCE",
                "oracle_authority": "DETERMINISTIC_APPLICATION_RECEIPT",
                "survivor_identity": {
                    "absorbed_candidate_id": "CAND-7",
                    "canonical_survivor_id": "CID-9",
                    "canonical_survivor_identity_sha256": H2,
                    "canonical_survivor_state": "LIVE",
                    "application_receipt_sha256": H,
                    "application_result": "APPLIED",
                    "preservation_result": "LOSSLESS",
                },
            }
        )
    elif kind == A.AUTHENTICATED_EXHAUSTIVE_NEGATIVE_EXECUTION:
        common.update(
            {
                "provider_id": "provider.execution.v1",
                "evidence_claims": [
                    _claim("EXHAUSTIVE_NEGATIVE_EXECUTION", "NO_HARM")
                ],
                "scope_completeness": "EXHAUSTIVE_HARM",
                "oracle_authority": "INDEPENDENT_REVIEWER_ORACLE",
                "negative_execution": {
                    "execution_assessment_sha256": H,
                    "execution_receipt_sha256": H2,
                    "execution_authenticity": "AUTHENTICATED",
                    "execution_result": "NEGATIVE",
                    "negative_exhaustiveness": "EXHAUSTIVE",
                    "proof_scope": "HARM",
                    "required_precondition_ids": ["PREM-1", "PREM-2"],
                    "represented_precondition_ids": ["PREM-1", "PREM-2"],
                    "environment_fidelity": "FULL",
                    "oracle_authority": "INDEPENDENT_REVIEWER_ORACLE",
                    "candidate_state": "REFUTED",
                    "negative_disposition_eligible": True,
                },
            }
        )
    return common


def _receipt(output_bytes: bytes, *, kind: str, input_bytes: bytes = b"input") -> bytes:
    output = json.loads(output_bytes)
    receipt = {
        "schema_version": A.PROVIDER_EXECUTION_RECEIPT_SCHEMA,
        "authority_kind": kind,
        "provider_id": output["provider_id"],
        "provider_version": output["provider_version"],
        "invocation_id": "provider-run-17",
        "provider_input_sha256": hashlib.sha256(input_bytes).hexdigest(),
        "provider_output_sha256": hashlib.sha256(output_bytes).hexdigest(),
        "execution_status": "COMPLETE",
        "exit_code": 0,
        "issuer_identity": "PLAMEN_DRIVER",
        "issuer_invocation_id": "driver-run-4",
        "receipt_origin": "DRIVER_OBSERVED_PROVIDER_EXECUTION",
    }
    receipt["receipt_digest"] = _digest(receipt, "receipt_digest")
    return _canonical(receipt)


def _issue(kind: str, *, live: dict[str, str] | None = None) -> dict:
    input_bytes = b"input"
    output_bytes = _canonical(_output(kind))
    return A.issue_negative_closure_authority(
        candidate_binding=_binding(),
        provider_input_bytes=input_bytes,
        provider_output_bytes=output_bytes,
        provider_execution_receipt_bytes=_receipt(
            output_bytes, kind=kind, input_bytes=input_bytes
        ),
        trusted_providers={
            "provider.scope.v1": ("1.4.2", A.MECHANICAL_SCOPE_EXCLUSION),
            "provider.dedup.v1": ("1.4.2", A.APPLIED_LOSSLESS_EQUIVALENCE),
            "provider.execution.v1": (
                "1.4.2",
                A.AUTHENTICATED_EXHAUSTIVE_NEGATIVE_EXECUTION,
            ),
        },
        live_survivors=live or {},
    )


@pytest.mark.parametrize(
    "kind,live",
    [
        (A.MECHANICAL_SCOPE_EXCLUSION, {}),
        (A.APPLIED_LOSSLESS_EQUIVALENCE, {"CID-9": H2}),
        (A.AUTHENTICATED_EXHAUSTIVE_NEGATIVE_EXECUTION, {}),
    ],
)
def test_only_three_provider_authenticated_terminal_authorities_are_accepted(
    kind: str, live: dict[str, str]
) -> None:
    authority = _issue(kind, live=live)
    assert authority["authority_kind"] == kind
    assert authority["candidate_premise_ids"] == ["PREM-1", "PREM-2"]
    assert authority["terminal_negative_authorized"] is True
    assert authority["provider_input_sha256"] == hashlib.sha256(b"input").hexdigest()


@pytest.mark.parametrize(
    "basis",
    [
        "IN_SCOPE_SOURCE",
        "PRIMARY_EXTERNAL_CITED",
        "EXTERNAL_PROSE",
        "INDEPENDENT_MODEL_ANALYSIS",
        "BOUNDED_EXECUTION",
        "SINGLE_EXECUTION",
        "FORMAL_PROOF",
    ],
)
def test_prose_source_formal_and_bounded_evidence_are_supporting_nonterminal(
    basis: str,
) -> None:
    result = A.classify_negative_evidence_basis(basis)
    assert result == {
        "basis": basis,
        "disposition": "SUPPORTING_NONTERMINAL",
        "terminal_negative_authorized": False,
    }


def test_forged_provider_identity_or_self_claimed_kind_is_rejected() -> None:
    output = _output(A.MECHANICAL_SCOPE_EXCLUSION)
    output["provider_id"] = "candidate.self-asserted"
    output_bytes = _canonical(output)
    with pytest.raises(A.NegativeClosureAuthorityError, match="trusted provider"):
        A.issue_negative_closure_authority(
            candidate_binding=_binding(),
            provider_input_bytes=b"input",
            provider_output_bytes=output_bytes,
            provider_execution_receipt_bytes=_receipt(
                output_bytes,
                kind=A.MECHANICAL_SCOPE_EXCLUSION,
                input_bytes=b"input",
            ),
            trusted_providers={},
        )


def test_stale_input_or_changed_output_fails_content_addressed_replay() -> None:
    output_bytes = _canonical(_output(A.MECHANICAL_SCOPE_EXCLUSION))
    receipt = _receipt(
        output_bytes, kind=A.MECHANICAL_SCOPE_EXCLUSION, input_bytes=b"old-input"
    )
    with pytest.raises(A.NegativeClosureAuthorityError, match="input digest"):
        A.issue_negative_closure_authority(
            candidate_binding=_binding(),
            provider_input_bytes=b"current-input",
            provider_output_bytes=output_bytes,
            provider_execution_receipt_bytes=receipt,
            trusted_providers={
                "provider.scope.v1": ("1.4.2", A.MECHANICAL_SCOPE_EXCLUSION)
            },
        )

    forged = json.loads(receipt)
    forged["provider_output_sha256"] = H
    forged["receipt_digest"] = _digest(forged, "receipt_digest")
    with pytest.raises(A.NegativeClosureAuthorityError, match="output digest"):
        A.issue_negative_closure_authority(
            candidate_binding=_binding(),
            provider_input_bytes=b"old-input",
            provider_output_bytes=output_bytes,
            provider_execution_receipt_bytes=_canonical(forged),
            trusted_providers={
                "provider.scope.v1": ("1.4.2", A.MECHANICAL_SCOPE_EXCLUSION)
            },
        )


def test_partial_execution_scope_or_model_oracle_cannot_close() -> None:
    for mutation in ("partial", "bounded", "model-oracle"):
        output = _output(A.AUTHENTICATED_EXHAUSTIVE_NEGATIVE_EXECUTION)
        execution = output["negative_execution"]
        if mutation == "partial":
            execution["represented_precondition_ids"] = ["PREM-1"]
        elif mutation == "bounded":
            execution["negative_exhaustiveness"] = "BOUNDED"
        else:
            execution["oracle_authority"] = "MODEL_GENERATED_ORACLE"
            output["oracle_authority"] = "MODEL_GENERATED_ORACLE"
        output_bytes = _canonical(output)
        with pytest.raises(A.NegativeClosureAuthorityError):
            A.issue_negative_closure_authority(
                candidate_binding=_binding(),
                provider_input_bytes=b"input",
                provider_output_bytes=output_bytes,
                provider_execution_receipt_bytes=_receipt(
                    output_bytes,
                    kind=A.AUTHENTICATED_EXHAUSTIVE_NEGATIVE_EXECUTION,
                ),
                trusted_providers={
                    "provider.execution.v1": (
                        "1.4.2",
                        A.AUTHENTICATED_EXHAUSTIVE_NEGATIVE_EXECUTION,
                    )
                },
            )


def test_lossless_equivalence_requires_current_live_survivor_identity() -> None:
    with pytest.raises(A.NegativeClosureAuthorityError, match="live survivor"):
        _issue(A.APPLIED_LOSSLESS_EQUIVALENCE, live={})
    with pytest.raises(A.NegativeClosureAuthorityError, match="identity"):
        _issue(A.APPLIED_LOSSLESS_EQUIVALENCE, live={"CID-9": H})


def test_candidate_premise_and_evidence_claim_bindings_are_exact() -> None:
    output = _output(A.MECHANICAL_SCOPE_EXCLUSION)
    output["candidate_premise_ids"] = ["PREM-1"]
    output_bytes = _canonical(output)
    with pytest.raises(A.NegativeClosureAuthorityError, match="candidate binding"):
        A.issue_negative_closure_authority(
            candidate_binding=_binding(),
            provider_input_bytes=b"input",
            provider_output_bytes=output_bytes,
            provider_execution_receipt_bytes=_receipt(
                output_bytes, kind=A.MECHANICAL_SCOPE_EXCLUSION
            ),
            trusted_providers={
                "provider.scope.v1": ("1.4.2", A.MECHANICAL_SCOPE_EXCLUSION)
            },
        )

    output = _output(A.MECHANICAL_SCOPE_EXCLUSION)
    output["evidence_claims"][0]["premise_ids"] = ["PREM-1"]
    output_bytes = _canonical(output)
    with pytest.raises(A.NegativeClosureAuthorityError, match="premise coverage"):
        A.issue_negative_closure_authority(
            candidate_binding=_binding(),
            provider_input_bytes=b"input",
            provider_output_bytes=output_bytes,
            provider_execution_receipt_bytes=_receipt(
                output_bytes, kind=A.MECHANICAL_SCOPE_EXCLUSION
            ),
            trusted_providers={
                "provider.scope.v1": ("1.4.2", A.MECHANICAL_SCOPE_EXCLUSION)
            },
        )


def test_strict_json_rejects_duplicate_keys_nonfinite_and_noncanonical_bytes() -> None:
    with pytest.raises(A.NegativeClosureAuthorityError, match="duplicate JSON key"):
        A.strict_json_loads(b'{"x":1,"x":2}')
    with pytest.raises(A.NegativeClosureAuthorityError, match="non-finite"):
        A.strict_json_loads(b'{"x":NaN}')

    output = _output(A.MECHANICAL_SCOPE_EXCLUSION)
    pretty = json.dumps(output, indent=2).encode("utf-8")
    with pytest.raises(A.NegativeClosureAuthorityError, match="canonical JSON"):
        A.issue_negative_closure_authority(
            candidate_binding=_binding(),
            provider_input_bytes=b"input",
            provider_output_bytes=pretty,
            provider_execution_receipt_bytes=_receipt(
                pretty, kind=A.MECHANICAL_SCOPE_EXCLUSION
            ),
            trusted_providers={
                "provider.scope.v1": ("1.4.2", A.MECHANICAL_SCOPE_EXCLUSION)
            },
        )


def test_authority_resume_validation_rejects_tamper_and_stale_survivor() -> None:
    authority = _issue(A.APPLIED_LOSSLESS_EQUIVALENCE, live={"CID-9": H2})
    authority_bytes = A.canonical_json_bytes(authority)
    output_bytes = _canonical(_output(A.APPLIED_LOSSLESS_EQUIVALENCE))
    kwargs = {
        "candidate_binding": _binding(),
        "provider_input_bytes": b"input",
        "provider_output_bytes": output_bytes,
        "provider_execution_receipt_bytes": _receipt(
            output_bytes, kind=A.APPLIED_LOSSLESS_EQUIVALENCE
        ),
        "trusted_providers": {
            "provider.dedup.v1": ("1.4.2", A.APPLIED_LOSSLESS_EQUIVALENCE)
        },
    }
    assert A.validate_negative_closure_authority(
        authority_bytes, live_survivors={"CID-9": H2}, **kwargs
    ) == authority

    tampered = dict(authority)
    tampered["scope_completeness"] = "EXACT_MECHANICAL_SCOPE"
    with pytest.raises(A.NegativeClosureAuthorityError):
        A.validate_negative_closure_authority(
            A.canonical_json_bytes(tampered), live_survivors={"CID-9": H2}, **kwargs
        )
    with pytest.raises(A.NegativeClosureAuthorityError, match="live survivor"):
        A.validate_negative_closure_authority(
            authority_bytes, live_survivors={}, **kwargs
        )


def test_policy_rejects_legacy_inprocess_provider_replay() -> None:
    authority = _issue(A.MECHANICAL_SCOPE_EXCLUSION)
    work_item = {
        "work_item_id": authority["work_item_id"],
        "candidate_negative_family_id": authority["candidate_id"],
        "candidate_premise_ids": list(authority["candidate_premise_ids"]),
    }
    accepted = P.terminal_negative_authorized(
        work_item=work_item,
        assessment={"evidence_basis": "IN_SCOPE_SOURCE"},
        authority=authority,
        provider_validator=lambda _candidate: dict(authority),
    )
    assert accepted == (False, "LEGACY_NEGATIVE_AUTHORITY_NOT_LIVE")

    stale = {**work_item, "candidate_premise_ids": ["PREM-1"]}
    rejected = P.terminal_negative_authorized(
        work_item=stale,
        assessment={"evidence_basis": "IN_SCOPE_SOURCE"},
        authority=authority,
        provider_validator=lambda _candidate: dict(authority),
    )
    assert rejected == (False, "LEGACY_NEGATIVE_AUTHORITY_NOT_LIVE")
