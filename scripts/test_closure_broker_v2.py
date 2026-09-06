"""Pure v2 closure subject/broker authority boundary.

These fixtures are intentionally isolated from every driver and consumer.  They
lock the cutover contract before any production integration is attempted.
"""

from __future__ import annotations

import hashlib
import inspect
import json

import pytest

import closure_broker_v2 as C


H1 = "1" * 64
H2 = "2" * 64
H3 = "3" * 64
H4 = "4" * 64
H5 = "5" * 64
H6 = "6" * 64


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _digest(value: object, field: str) -> str:
    unsigned = dict(value)  # type: ignore[arg-type]
    unsigned.pop(field, None)
    return hashlib.sha256(_canonical(unsigned)).hexdigest()


def _subject(effect: str = C.REFUTED_FULL, **changes: object) -> bytes:
    value = {
        "schema_version": C.SUBJECT_SCHEMA,
        "run_id": "run-2026-07-19-001",
        "audit_snapshot_sha256": H1,
        "candidate_id": "CAND-17",
        "source_id": "depth-value-flow:CAND-17",
        "candidate_sha256": H2,
        "source_sha256": H3,
        "content_sha256": H4,
        "claim_manifest_sha256": H5,
        "premise_ids": ["PREM-1", "PREM-2"],
        "requested_effect": effect,
    }
    value.update(changes)
    return _canonical(value)


_PROVIDER_BY_EFFECT = {
    C.REFUTED_FULL: (
        "plamen.claim-resolution.v2",
        C.CLAIM_RESOLUTION,
        "FULL_CLAIM",
    ),
    C.ZERO_HARM: (
        "plamen.harm-resolution.v2",
        C.HARM_RESOLUTION,
        "HARM_ONLY",
    ),
    C.OUT_OF_SCOPE: (
        "plamen.scope-resolution.v2",
        C.SCOPE_RESOLUTION,
        "EXACT_SCOPE",
    ),
    C.ALIAS_TO_SURVIVOR: (
        "plamen.identity-resolution.v2",
        C.IDENTITY_RESOLUTION,
        "IDENTITY_ONLY",
    ),
}


def _output(
    subject: bytes,
    *,
    effect: str,
    survivor_id: str | None = None,
    survivor_sha256: str | None = None,
    **changes: object,
) -> bytes:
    subject_value = json.loads(subject)
    provider_id, kind, proof_scope = _PROVIDER_BY_EFFECT[effect]
    value = {
        "schema_version": C.PROVIDER_OUTPUT_SCHEMA,
        "provider_id": provider_id,
        "provider_version": "2.0.0",
        "authority_kind": kind,
        "subject_sha256": hashlib.sha256(subject).hexdigest(),
        "requested_effect": effect,
        "outcome": effect,
        "proof_scope": proof_scope,
        "exhaustive": True,
        "premise_ids": list(subject_value["premise_ids"]),
        "audit_snapshot_sha256": subject_value["audit_snapshot_sha256"],
        "claim_manifest_sha256": subject_value["claim_manifest_sha256"],
        "evidence_sha256": H6,
        "survivor": None,
    }
    if effect == C.ALIAS_TO_SURVIVOR:
        value["survivor"] = {
            "candidate_id": survivor_id or "CID-99",
            "identity_sha256": survivor_sha256 or H6,
            "state": "LIVE",
        }
    value.update(changes)
    return _canonical(value)


def _receipt(
    output: bytes,
    *,
    issuer_identity: str = "PLAMEN_CLOSURE_PROVIDER_HOST",
    invocation_id: str = "closure-provider-run-1",
) -> bytes:
    row = json.loads(output)
    value = {
        "schema_version": C.PROVIDER_RECEIPT_SCHEMA,
        "provider_id": row["provider_id"],
        "provider_version": row["provider_version"],
        "authority_kind": row["authority_kind"],
        "invocation_id": invocation_id,
        "subject_sha256": row["subject_sha256"],
        "provider_input_sha256": row["subject_sha256"],
        "provider_output_sha256": hashlib.sha256(output).hexdigest(),
        "execution_status": "COMPLETE",
        "exit_code": 0,
        "issuer_identity": issuer_identity,
        "receipt_origin": "DRIVER_OBSERVED_PROVIDER_EXECUTION",
    }
    value["receipt_digest"] = _digest(value, "receipt_digest")
    return _canonical(value)


def _observe(
    broker: C.ClosureAuthorityBrokerV2,
    output: bytes,
    *,
    issuer_identity: str = "PLAMEN_CLOSURE_PROVIDER_HOST",
    invocation_id: str = "closure-provider-run-1",
) -> None:
    broker.observe_provider_execution(
        provider_output_bytes=output,
        provider_receipt_bytes=_receipt(
            output,
            issuer_identity=issuer_identity,
            invocation_id=invocation_id,
        ),
    )


def test_subject_manifest_is_exact_canonical_and_content_addressed() -> None:
    subject = _subject()
    parsed = C.validate_subject_manifest(subject)
    assert parsed["run_id"] == "run-2026-07-19-001"
    assert parsed["premise_ids"] == ["PREM-1", "PREM-2"]
    assert C.subject_sha256(subject) == hashlib.sha256(subject).hexdigest()

    with pytest.raises(C.ClosureBrokerError, match="canonically sorted"):
        C.validate_subject_manifest(
            _subject(premise_ids=["PREM-2", "PREM-1"])
        )
    with pytest.raises(C.ClosureBrokerError, match="schema mismatch"):
        C.validate_subject_manifest(
            _subject(extra_unbound_field="must-not-be-accepted")
        )
    pretty = json.dumps(json.loads(subject), indent=2).encode("utf-8")
    with pytest.raises(C.ClosureBrokerError, match="canonical JSON"):
        C.validate_subject_manifest(pretty)


@pytest.mark.parametrize(
    "effect,axis",
    [
        (C.REFUTED_FULL, "claim_resolution"),
        (C.ZERO_HARM, "harm_resolution"),
        (C.OUT_OF_SCOPE, "scope_resolution"),
        (C.ALIAS_TO_SURVIVOR, "identity_resolution"),
    ],
)
def test_effect_kind_matrix_is_typed_but_shadow_only_until_provider_cutover(
    effect: str, axis: str
) -> None:
    subject = _subject(effect)
    output = _output(subject, effect=effect)
    broker = C.ClosureAuthorityBrokerV2()
    _observe(broker, output)
    live = {"CID-99": H6} if effect == C.ALIAS_TO_SURVIVOR else {}

    result = broker.resolve(
        subject_manifest_bytes=subject,
        provider_output_bytes=[output],
        live_survivors=live,
    )

    assert result["status"] == C.DEBT
    assert result["outcome"] == C.NO_AUTHORITY
    assert result["debt_reasons"] == ["BROKER_V2_SHADOW_PROPOSAL_ONLY"]
    assert result[axis] == C.UNRESOLVED
    for other in {
        "claim_resolution",
        "harm_resolution",
        "scope_resolution",
        "identity_resolution",
    } - {axis}:
        assert result[other] == C.UNRESOLVED


def test_cross_kind_misuse_is_debt_not_authority() -> None:
    subject = _subject(C.REFUTED_FULL)
    output = _output(subject, effect=C.ZERO_HARM)
    broker = C.ClosureAuthorityBrokerV2()
    _observe(broker, output)

    result = broker.resolve(
        subject_manifest_bytes=subject, provider_output_bytes=[output]
    )

    assert result["status"] == C.DEBT
    assert result["outcome"] == C.NO_AUTHORITY
    assert "EFFECT_KIND_MATRIX_MISMATCH" in result["debt_reasons"]


@pytest.mark.parametrize(
    "drift",
    [
        {"audit_snapshot_sha256": "a" * 64},
        {"content_sha256": "b" * 64},
    ],
)
def test_snapshot_or_content_drift_invalidates_observed_authority(
    drift: dict[str, object]
) -> None:
    original = _subject(C.REFUTED_FULL)
    output = _output(original, effect=C.REFUTED_FULL)
    broker = C.ClosureAuthorityBrokerV2()
    _observe(broker, output)

    result = broker.resolve(
        subject_manifest_bytes=_subject(C.REFUTED_FULL, **drift),
        provider_output_bytes=[output],
    )

    assert result["status"] == C.DEBT
    assert result["outcome"] == C.NO_AUTHORITY
    assert "SUBJECT_BINDING_MISMATCH" in result["debt_reasons"]


def test_forged_issuer_is_rejected_before_receipt_enters_replay_ledger() -> None:
    subject = _subject(C.OUT_OF_SCOPE)
    output = _output(subject, effect=C.OUT_OF_SCOPE)
    broker = C.ClosureAuthorityBrokerV2()

    with pytest.raises(C.ClosureBrokerError, match="issuer"):
        _observe(broker, output, issuer_identity="MODEL_SELF_ASSERTED")

    result = broker.resolve(
        subject_manifest_bytes=subject, provider_output_bytes=[output]
    )
    assert result["status"] == C.DEBT
    assert result["debt_reasons"] == ["PROVIDER_EXECUTION_NOT_OBSERVED"]


def test_harm_only_resolution_never_becomes_full_claim_refutation() -> None:
    subject = _subject(C.ZERO_HARM)
    output = _output(subject, effect=C.ZERO_HARM)
    broker = C.ClosureAuthorityBrokerV2()
    _observe(broker, output)

    result = broker.resolve(
        subject_manifest_bytes=subject, provider_output_bytes=[output]
    )

    assert result["status"] == C.DEBT
    assert result["outcome"] == C.NO_AUTHORITY
    assert result["harm_resolution"] == C.UNRESOLVED
    assert result["claim_resolution"] == C.UNRESOLVED

    full_subject = _subject(C.REFUTED_FULL)
    misused = _output(full_subject, effect=C.ZERO_HARM)
    _observe(broker, misused, invocation_id="closure-provider-run-2")
    refused = broker.resolve(
        subject_manifest_bytes=full_subject, provider_output_bytes=[misused]
    )
    assert refused["outcome"] == C.NO_AUTHORITY
    assert "EFFECT_KIND_MATRIX_MISMATCH" in refused["debt_reasons"]


def test_broker_has_no_live_authority_switch() -> None:
    assert C.BROKER_MODE == "SHADOW_PROPOSAL_ONLY"
    assert list(inspect.signature(C.ClosureAuthorityBrokerV2).parameters) == []


def test_alias_authority_requires_current_live_survivor_identity() -> None:
    subject = _subject(C.ALIAS_TO_SURVIVOR)
    output = _output(
        subject,
        effect=C.ALIAS_TO_SURVIVOR,
        survivor_id="CID-99",
        survivor_sha256=H6,
    )
    broker = C.ClosureAuthorityBrokerV2()
    _observe(broker, output)

    absent = broker.resolve(
        subject_manifest_bytes=subject,
        provider_output_bytes=[output],
        live_survivors={},
    )
    stale = broker.resolve(
        subject_manifest_bytes=subject,
        provider_output_bytes=[output],
        live_survivors={"CID-99": H5},
    )
    assert absent["outcome"] == stale["outcome"] == C.NO_AUTHORITY
    assert "SURVIVOR_NOT_LIVE" in absent["debt_reasons"]
    assert "SURVIVOR_IDENTITY_STALE" in stale["debt_reasons"]


def test_conflicting_observed_alias_authorities_remain_visible_and_block() -> None:
    subject = _subject(C.ALIAS_TO_SURVIVOR)
    first = _output(
        subject,
        effect=C.ALIAS_TO_SURVIVOR,
        survivor_id="CID-99",
        survivor_sha256=H5,
    )
    second = _output(
        subject,
        effect=C.ALIAS_TO_SURVIVOR,
        survivor_id="CID-100",
        survivor_sha256=H6,
        evidence_sha256=H1,
    )
    broker = C.ClosureAuthorityBrokerV2()
    _observe(broker, first, invocation_id="closure-provider-run-1")
    _observe(broker, second, invocation_id="closure-provider-run-2")

    result = broker.resolve(
        subject_manifest_bytes=subject,
        provider_output_bytes=[first, second],
        live_survivors={"CID-99": H5, "CID-100": H6},
    )

    assert result["status"] == C.DEBT
    assert result["outcome"] == C.NO_AUTHORITY
    assert "CONFLICTING_AUTHORITIES" in result["debt_reasons"]
    assert len(result["conflicts"]) == 2
    assert {row["survivor_id"] for row in result["conflicts"]} == {
        "CID-99",
        "CID-100",
    }


def test_v1_and_unobserved_outputs_never_have_live_authority() -> None:
    v1 = json.loads(_subject())
    v1["schema_version"] = "plamen.closure_subject.v1"
    broker = C.ClosureAuthorityBrokerV2()
    rejected = broker.resolve(
        subject_manifest_bytes=_canonical(v1), provider_output_bytes=[]
    )
    assert rejected["status"] == C.DEBT
    assert rejected["debt_reasons"] == ["SCHEMA_V1_NOT_LIVE_AUTHORITY"]

    subject = _subject(C.REFUTED_FULL)
    output = _output(subject, effect=C.REFUTED_FULL)
    unobserved = broker.resolve(
        subject_manifest_bytes=subject, provider_output_bytes=[output]
    )
    assert unobserved["status"] == C.DEBT
    assert unobserved["debt_reasons"] == ["PROVIDER_EXECUTION_NOT_OBSERVED"]

    v1_output = json.loads(output)
    v1_output["schema_version"] = "plamen.closure_provider_output.v1"
    with pytest.raises(C.ClosureBrokerError, match="schema mismatch"):
        broker.observe_provider_execution(
            provider_output_bytes=_canonical(v1_output),
            provider_receipt_bytes=_receipt(_canonical(v1_output)),
        )


def test_broker_has_no_caller_supplied_registry_or_validator_callback() -> None:
    observe = inspect.signature(C.ClosureAuthorityBrokerV2.observe_provider_execution)
    resolve_ = inspect.signature(C.ClosureAuthorityBrokerV2.resolve)
    forbidden = {"trusted_providers", "provider_validator", "validator"}
    assert forbidden.isdisjoint(observe.parameters)
    assert forbidden.isdisjoint(resolve_.parameters)


def test_strict_json_rejects_duplicate_keys_nonfinite_and_noncanonical_output() -> None:
    with pytest.raises(C.ClosureBrokerError, match="duplicate JSON key"):
        C.strict_json_loads(b'{"x":1,"x":2}')
    with pytest.raises(C.ClosureBrokerError, match="non-finite"):
        C.strict_json_loads(b'{"x":NaN}')

    subject = _subject(C.REFUTED_FULL)
    pretty = json.dumps(
        json.loads(_output(subject, effect=C.REFUTED_FULL)), indent=2
    ).encode("utf-8")
    broker = C.ClosureAuthorityBrokerV2()
    with pytest.raises(C.ClosureBrokerError, match="canonical JSON"):
        broker.observe_provider_execution(
            provider_output_bytes=pretty,
            provider_receipt_bytes=_receipt(pretty),
        )
