"""Adversarial reproductions for the isolated closure-broker foundation.

These tests intentionally demonstrate authority that an arbitrary in-process caller
can manufacture through the current public API.  They are review evidence, not a
specification that the unsafe behavior should be retained.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import closure_broker_v2 as C


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _provider(effect: str) -> tuple[str, dict[str, str]]:
    for provider_id, spec in C.provider_registry_snapshot().items():
        if spec["effect"] == effect:
            return provider_id, spec
    raise AssertionError(f"missing provider for {effect}")


def _subject(
    effect: str,
    *,
    run_id: str = "caller-selected-run",
    candidate_id: str = "CAND-ATTACKER",
    candidate_sha256: str = "2" * 64,
    source_sha256: str = "3" * 64,
    content_sha256: str = "4" * 64,
) -> bytes:
    return _canonical(
        {
            "schema_version": C.SUBJECT_SCHEMA,
            "run_id": run_id,
            "audit_snapshot_sha256": "1" * 64,
            "candidate_id": candidate_id,
            "source_id": f"caller:{candidate_id}",
            "candidate_sha256": candidate_sha256,
            "source_sha256": source_sha256,
            "content_sha256": content_sha256,
            "claim_manifest_sha256": "5" * 64,
            "premise_ids": ["PREM-CALLER"],
            "requested_effect": effect,
        }
    )


def _output(
    subject: bytes,
    effect: str,
    *,
    evidence_sha256: str = "6" * 64,
    survivor_id: str | None = None,
    survivor_identity_sha256: str | None = None,
) -> bytes:
    provider_id, spec = _provider(effect)
    subject_value = json.loads(subject)
    survivor = None
    if effect == C.ALIAS_TO_SURVIVOR:
        survivor = {
            "candidate_id": survivor_id or "SURVIVOR-CALLER",
            "identity_sha256": survivor_identity_sha256 or "7" * 64,
            "state": "LIVE",
        }
    return _canonical(
        {
            "schema_version": C.PROVIDER_OUTPUT_SCHEMA,
            "provider_id": provider_id,
            "provider_version": spec["provider_version"],
            "authority_kind": spec["authority_kind"],
            "subject_sha256": _sha(subject),
            "requested_effect": effect,
            "outcome": effect,
            "proof_scope": spec["proof_scope"],
            "exhaustive": True,
            "premise_ids": list(subject_value["premise_ids"]),
            "audit_snapshot_sha256": subject_value["audit_snapshot_sha256"],
            "claim_manifest_sha256": subject_value["claim_manifest_sha256"],
            "evidence_sha256": evidence_sha256,
            "survivor": survivor,
        }
    )


def _caller_authored_receipt(output: bytes, invocation_id: str) -> bytes:
    output_value = json.loads(output)
    _, spec = _provider(output_value["outcome"])
    receipt = {
        "schema_version": C.PROVIDER_RECEIPT_SCHEMA,
        "provider_id": output_value["provider_id"],
        "provider_version": output_value["provider_version"],
        "authority_kind": output_value["authority_kind"],
        "invocation_id": invocation_id,
        "subject_sha256": output_value["subject_sha256"],
        "provider_input_sha256": output_value["subject_sha256"],
        "provider_output_sha256": _sha(output),
        "execution_status": "COMPLETE",
        "exit_code": 0,
        "issuer_identity": spec["issuer_identity"],
        "receipt_origin": "DRIVER_OBSERVED_PROVIDER_EXECUTION",
    }
    receipt["receipt_digest"] = _sha(_canonical(receipt))
    return _canonical(receipt)


def _observe_caller_pair(
    broker: C.ClosureAuthorityBrokerV2,
    output: bytes,
    invocation_id: str,
) -> None:
    broker.observe_provider_execution(
        provider_output_bytes=output,
        provider_receipt_bytes=_caller_authored_receipt(output, invocation_id),
    )


def test_arbitrary_caller_can_mint_full_terminal_refutation_without_provider() -> None:
    subject = _subject(C.REFUTED_FULL)
    # No evidence bytes, worker process, executable, provider completion receipt,
    # output CAS, or independent issuer exists anywhere in this reproduction.
    output = _output(subject, C.REFUTED_FULL, evidence_sha256="d" * 64)
    broker = C.ClosureAuthorityBrokerV2()
    _observe_caller_pair(broker, output, "caller-forged-invocation")

    result = broker.resolve(
        subject_manifest_bytes=subject,
        provider_output_bytes=[output],
    )

    assert result["status"] == C.DEBT
    assert result["outcome"] == C.NO_AUTHORITY
    assert result["claim_resolution"] == C.UNRESOLVED
    assert "BROKER_V2_SHADOW_PROPOSAL_ONLY" in result["debt_reasons"]


def test_mutated_candidate_source_and_evidence_bytes_do_not_stale_authority(
    tmp_path: Path,
) -> None:
    candidate = tmp_path / "candidate.json"
    source = tmp_path / "source.sol"
    evidence = tmp_path / "evidence.json"
    candidate.write_bytes(b"candidate-before")
    source.write_bytes(b"source-before")
    evidence.write_bytes(b"evidence-before")
    subject = _subject(
        C.REFUTED_FULL,
        candidate_sha256=_sha(candidate.read_bytes()),
        source_sha256=_sha(source.read_bytes()),
        content_sha256=_sha(b"content-before"),
    )
    output = _output(
        subject,
        C.REFUTED_FULL,
        evidence_sha256=_sha(evidence.read_bytes()),
    )
    broker = C.ClosureAuthorityBrokerV2()
    _observe_caller_pair(broker, output, "stale-byte-invocation")

    candidate.write_bytes(b"candidate-after")
    source.write_bytes(b"source-after")
    evidence.write_bytes(b"evidence-after")
    result = broker.resolve(subject_manifest_bytes=subject, provider_output_bytes=[output])

    assert result["status"] == C.DEBT
    assert result["claim_resolution"] == C.UNRESOLVED


def test_caller_can_omit_observed_conflict_and_select_alias_survivor() -> None:
    subject = _subject(C.ALIAS_TO_SURVIVOR)
    first = _output(
        subject,
        C.ALIAS_TO_SURVIVOR,
        survivor_id="SURVIVOR-A",
        survivor_identity_sha256="a" * 64,
    )
    second = _output(
        subject,
        C.ALIAS_TO_SURVIVOR,
        evidence_sha256="8" * 64,
        survivor_id="SURVIVOR-B",
        survivor_identity_sha256="b" * 64,
    )
    broker = C.ClosureAuthorityBrokerV2()
    _observe_caller_pair(broker, first, "alias-invocation-a")
    _observe_caller_pair(broker, second, "alias-invocation-b")
    caller_liveness = {"SURVIVOR-A": "a" * 64, "SURVIVOR-B": "b" * 64}

    selected = broker.resolve(
        subject_manifest_bytes=subject,
        provider_output_bytes=[first],
        live_survivors=caller_liveness,
    )
    complete_denominator = broker.resolve(
        subject_manifest_bytes=subject,
        provider_output_bytes=[first, second],
        live_survivors=caller_liveness,
    )

    assert selected["status"] == C.DEBT
    assert selected["authorities"][0]["survivor_id"] == "SURVIVOR-A"
    assert complete_denominator["status"] == C.DEBT
    assert "CONFLICTING_AUTHORITIES" in complete_denominator["debt_reasons"]


def test_caller_supplied_liveness_turns_same_alias_from_debt_into_authority() -> None:
    subject = _subject(C.ALIAS_TO_SURVIVOR)
    output = _output(
        subject,
        C.ALIAS_TO_SURVIVOR,
        survivor_id="FABRICATED-LIVE-SURVIVOR",
        survivor_identity_sha256="c" * 64,
    )
    broker = C.ClosureAuthorityBrokerV2()
    _observe_caller_pair(broker, output, "fabricated-liveness-invocation")

    absent = broker.resolve(
        subject_manifest_bytes=subject,
        provider_output_bytes=[output],
        live_survivors={},
    )
    fabricated = broker.resolve(
        subject_manifest_bytes=subject,
        provider_output_bytes=[output],
        live_survivors={"FABRICATED-LIVE-SURVIVOR": "c" * 64},
    )

    assert absent["status"] == C.DEBT
    assert fabricated["status"] == C.DEBT
    assert fabricated["identity_resolution"] == C.UNRESOLVED


def test_authorized_alias_result_has_no_liveness_epoch_and_remains_stale_dict() -> None:
    subject = _subject(C.ALIAS_TO_SURVIVOR)
    output = _output(
        subject,
        C.ALIAS_TO_SURVIVOR,
        survivor_id="EPHEMERAL-SURVIVOR",
        survivor_identity_sha256="e" * 64,
    )
    broker = C.ClosureAuthorityBrokerV2()
    _observe_caller_pair(broker, output, "stale-result-invocation")

    authorized = broker.resolve(
        subject_manifest_bytes=subject,
        provider_output_bytes=[output],
        live_survivors={"EPHEMERAL-SURVIVOR": "e" * 64},
    )
    after_survivor_disappears = broker.resolve(
        subject_manifest_bytes=subject,
        provider_output_bytes=[output],
        live_survivors={},
    )

    assert authorized["status"] == C.DEBT
    assert after_survivor_disappears["status"] == C.DEBT
    assert authorized["status"] == C.DEBT
    assert not {
        "liveness_snapshot_sha256",
        "lifecycle_epoch",
        "resolution_receipt_sha256",
    }.intersection(authorized)


def test_receipt_and_output_replay_into_fresh_brokers_and_attacker_run_context() -> None:
    subject = _subject(C.OUT_OF_SCOPE, run_id="unrelated-attacker-run")
    output = _output(subject, C.OUT_OF_SCOPE)
    receipt = _caller_authored_receipt(output, "globally-replayed-invocation")
    results: list[dict[str, object]] = []

    for _ in range(2):
        broker = C.ClosureAuthorityBrokerV2()
        broker.observe_provider_execution(
            provider_output_bytes=output,
            provider_receipt_bytes=receipt,
        )
        results.append(
            broker.resolve(
                subject_manifest_bytes=subject,
                provider_output_bytes=[output],
            )
        )

    assert [result["status"] for result in results] == [C.DEBT, C.DEBT]
    assert [result["scope_resolution"] for result in results] == [
        C.UNRESOLVED,
        C.UNRESOLVED,
    ]


def test_one_invocation_id_can_issue_multiple_distinct_authoritative_outputs() -> None:
    subject = _subject(C.REFUTED_FULL)
    first = _output(subject, C.REFUTED_FULL, evidence_sha256="a" * 64)
    second = _output(subject, C.REFUTED_FULL, evidence_sha256="b" * 64)
    broker = C.ClosureAuthorityBrokerV2()
    _observe_caller_pair(broker, first, "reused-provider-invocation")
    _observe_caller_pair(broker, second, "reused-provider-invocation")

    result = broker.resolve(
        subject_manifest_bytes=subject,
        provider_output_bytes=[first, second],
    )

    assert result["status"] == C.DEBT
    assert len(result["authorities"]) == 2
    assert {row["invocation_id"] for row in result["authorities"]} == {
        "reused-provider-invocation"
    }
