"""P1-M fixtures for the isolated EVM arm-before-trust authority core."""
from __future__ import annotations

import json
from pathlib import Path

import authentication_role_authority as A


RUN_ID = "123e4567-e89b-42d3-a456-426614174000"
SNAPSHOT = "a" * 64
SOURCE_SCOPE = "b" * 64
OPERATOR_DIGEST = "c" * 64


def _checkpoint(root: Path, *, ecosystem: str = "evm") -> None:
    payload = {
        "run_id": RUN_ID,
        "config": {
            "language": ecosystem,
            "mode": "thorough",
            "pipeline": "sc",
        },
        "audit_snapshot": {
            "snapshot_digest": SNAPSHOT,
            "components": {"source_scope": {"digest": SOURCE_SCOPE}},
        },
    }
    (root / "_v2_checkpoint.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def _evidence(claim: str, locus: str, result: str = "typed source result") -> dict:
    return {"claim": claim, "locus": locus, "result": result}


def _anchor(
    *,
    provenance: str = "IN_SCOPE",
    polarity: str = "POSITIVE",
    extra_evidence: list[dict] | None = None,
) -> dict:
    evidence = [
        _evidence("UNARMED_DEFAULT", "src/Auth.sol:L10"),
        _evidence("OPERATIONAL_WHILE_UNARMED", "src/Auth.sol:L31"),
        _evidence("PRIVILEGED_EFFECT_REACHABLE", "src/Auth.sol:L45"),
    ]
    evidence.extend(extra_evidence or [])
    return {
        "producer_fact_id": "producer-anchor-1",
        "role": "ANCHOR",
        "trust_domain_id": "evm:auth-domain-1",
        "polarity": polarity,
        "provenance": provenance,
        "anchor_identity": "storedVerifier",
        "anchor_default": "ZERO_ADDRESS",
        "derived_identity": "",
        "degenerate_input_domain": "",
        "privileged_effect": "effect:privileged-transition",
        "evidence": evidence,
        "external_dependency": "ExternalVerifier" if provenance == "EXTERNAL" else "",
        "external_surface": "ExternalVerifier.verify" if provenance == "EXTERNAL" else "",
    }


def _derived(
    *,
    provenance: str = "IN_SCOPE",
    polarity: str = "POSITIVE",
    extra_evidence: list[dict] | None = None,
) -> dict:
    evidence = [
        _evidence("DEGENERATE_INPUT_IN_DOMAIN", "src/Verify.sol:L18"),
        _evidence("DERIVES_DEFAULT_IDENTITY", "src/Verify.sol:L22"),
        _evidence("DEFAULT_IDENTITY_ACCEPTED", "src/Verify.sol:L29"),
        _evidence("PRIVILEGED_EFFECT_REACHABLE", "src/Auth.sol:L45"),
    ]
    evidence.extend(extra_evidence or [])
    return {
        "producer_fact_id": "producer-derived-1",
        "role": "DERIVED_IDENTITY",
        "trust_domain_id": "evm:auth-domain-1",
        "polarity": polarity,
        "provenance": provenance,
        "anchor_identity": "",
        "anchor_default": "",
        "derived_identity": "ZERO_ADDRESS",
        "degenerate_input_domain": "zero-length signature",
        "privileged_effect": "effect:privileged-transition",
        "evidence": evidence,
        "external_dependency": "ExternalVerifier" if provenance == "EXTERNAL" else "",
        "external_surface": "ExternalVerifier.verify" if provenance == "EXTERNAL" else "",
    }


def _payload(facts: list[dict], *, ecosystem: str = "evm") -> dict:
    payload = {
        "schema_version": A.FACT_TRACE_SCHEMA,
        "run_binding_digest": A.run_binding_digest(
            RUN_ID, SNAPSHOT, SOURCE_SCOPE, ecosystem, "thorough", "sc"
        ),
        "ecosystem": ecosystem,
        "operator_id": "arm-before-trust.v1",
        "operator_digest": OPERATOR_DIGEST,
        "facts": facts,
    }
    payload["payload_digest"] = A.trace_payload_digest(payload)
    return payload


def test_evm_typed_complementary_positive_facts_emit_one_composition_obligation(
    tmp_path: Path,
) -> None:
    _checkpoint(tmp_path)

    authority, composition, research, projection = (
        A.derive_authentication_role_authority(
            tmp_path, trace_payload=_payload([_anchor(), _derived()])
        )
    )

    assert authority["status"] == "ACTIVE"
    assert authority["activation"]["state"] == "ACTIVE_EVM_ONLY"
    assert authority["operator_digest"] == OPERATOR_DIGEST
    assert len(authority["facts"]) == 2
    assert {row["role"] for row in authority["facts"]} == {
        "ANCHOR",
        "DERIVED_IDENTITY",
    }
    assert len({row["fact_id"] for row in authority["facts"]}) == 2
    assert all(row["authority_state"] == "POSITIVE" for row in authority["facts"])
    anchor = next(row for row in authority["facts"] if row["role"] == "ANCHOR")
    assert anchor["operational_unarmed_evidence"][0]["locus"] == "src/Auth.sol:L31"
    assert anchor["privileged_effect_evidence"][0]["locus"] == "src/Auth.sol:L45"
    assert composition["status"] == "OBLIGATIONS_READY"
    assert composition["obligation_count"] == 1
    obligation = composition["obligations"][0]
    assert set(obligation["constituent_fact_ids"]) == {
        row["fact_id"] for row in authority["facts"]
    }
    assert obligation["proof_authority"] == "NONE"
    assert obligation["route"] == "COMPOUND_ANALYSIS_REQUIRED"
    assert composition["debts"] == []
    assert research["obligations"] == []
    assert obligation["obligation_id"] in projection


def test_armed_or_fail_closed_refutation_blocks_composition_and_remains_debt(
    tmp_path: Path,
) -> None:
    _checkpoint(tmp_path)
    anchor = _anchor(
        extra_evidence=[
            _evidence("INERT_UNTIL_ARMED", "src/Auth.sol:L26", "nonzero gate precedes use")
        ]
    )
    derived = _derived(
        extra_evidence=[
            _evidence("FAIL_CLOSED", "src/Verify.sol:L25", "zero derivation reverts")
        ]
    )

    authority, composition, _research, _projection = (
        A.derive_authentication_role_authority(
            tmp_path, trace_payload=_payload([anchor, derived])
        )
    )

    assert {row["authority_state"] for row in authority["facts"]} == {"CONFLICT"}
    assert composition["obligations"] == []
    assert {row["kind"] for row in composition["debts"]} == {
        "CONFLICTED_TYPED_HALF"
    }
    assert {row["role"] for row in composition["debts"]} == {
        "ANCHOR",
        "DERIVED_IDENTITY",
    }


def test_dearming_atomicity_conflict_blocks_positive_pair(tmp_path: Path) -> None:
    _checkpoint(tmp_path)
    anchor = _anchor(
        extra_evidence=[
            _evidence(
                "DEARM_ATOMIC_OR_INERT",
                "src/Auth.sol:L55",
                "rotation cannot leave an operational unarmed state",
            )
        ]
    )

    authority, composition, _research, _projection = (
        A.derive_authentication_role_authority(
            tmp_path, trace_payload=_payload([anchor, _derived()])
        )
    )

    normalized = next(row for row in authority["facts"] if row["role"] == "ANCHOR")
    assert normalized["dearming_evidence"][0]["claim"] == "DEARM_ATOMIC_OR_INERT"
    assert normalized["authority_state"] == "CONFLICT"
    assert composition["obligations"] == []
    assert any(row["fact_id"] == normalized["fact_id"] for row in composition["debts"])


def test_unmatched_positive_half_is_preserved_as_open_debt(tmp_path: Path) -> None:
    _checkpoint(tmp_path)

    authority, composition, _research, _projection = (
        A.derive_authentication_role_authority(
            tmp_path, trace_payload=_payload([_anchor()])
        )
    )

    assert authority["facts"][0]["authority_state"] == "POSITIVE"
    assert composition["obligations"] == []
    assert composition["debt_count"] == 1
    assert composition["debts"][0]["kind"] == "UNMATCHED_TYPED_HALF"
    assert composition["debts"][0]["fact_id"] == authority["facts"][0]["fact_id"]


def test_prose_regex_can_only_nominate_and_never_create_positive_authority(
    tmp_path: Path,
) -> None:
    _checkpoint(tmp_path)
    prose = [
        {
            "candidate_id": "INV-17",
            "text": (
                "authentication authority defaults to zero and operations remain "
                "reachable while a degenerate signature derives a zero signer and is accepted"
            ),
        }
    ]

    authority, composition, _research, _projection = (
        A.derive_authentication_role_authority(
            tmp_path,
            trace_payload=_payload([]),
            compatibility_entries=prose,
        )
    )

    assert authority["facts"] == []
    assert authority["positive_fact_count"] == 0
    assert authority["compatibility_nominations"]
    assert all(
        row["authority"] == "NOMINATION_ONLY"
        for row in authority["compatibility_nominations"]
    )
    assert composition["obligations"] == []


def test_external_fact_routes_candidate_scoped_research_without_asserting_unarmed(
    tmp_path: Path,
) -> None:
    _checkpoint(tmp_path)
    external_anchor = _anchor(provenance="EXTERNAL")
    for row in external_anchor["evidence"]:
        row["locus"] = "https://example.invalid/verifier-spec"

    authority, composition, research, _projection = (
        A.derive_authentication_role_authority(
            tmp_path, trace_payload=_payload([external_anchor, _derived()])
        )
    )

    external = next(row for row in authority["facts"] if row["provenance"] == "EXTERNAL")
    assert external["authority_state"] == "EXTERNAL_UNRESOLVED"
    assert external["positive_claims"] == []
    assert external["external_semantics_asserted"] == "UNKNOWN"
    assert composition["obligations"] == []
    assert research["obligation_count"] == 1
    obligation = research["obligations"][0]
    assert obligation["candidate_scope_id"].startswith("MZO-SCOPE-")
    assert external["fact_id"] in obligation["fact_ids"]
    assert obligation["asserted_external_state"] == "UNKNOWN"
    assert obligation["status"] == "NEEDS_DEPENDENCY_RESEARCH"
    assert "determine" in obligation["research_question"].casefold()
    assert "is unarmed" not in obligation["research_question"].casefold()


def test_operator_or_run_binding_mismatch_is_unmeasurable_and_cannot_compose(
    tmp_path: Path,
) -> None:
    _checkpoint(tmp_path)
    payload = _payload([_anchor(), _derived()])
    payload["operator_digest"] = "not-a-digest"
    payload["payload_digest"] = A.trace_payload_digest(payload)

    authority, composition, _research, _projection = (
        A.derive_authentication_role_authority(tmp_path, trace_payload=payload)
    )

    assert authority["status"] == "UNMEASURABLE"
    assert all(row["authority_state"] == "UNMEASURABLE" for row in authority["facts"])
    assert composition["obligations"] == []
    assert any("operator digest" in issue for issue in authority["issues"])


def test_duplicate_canonical_fact_identity_invalidates_whole_trace_before_composition(
    tmp_path: Path,
) -> None:
    _checkpoint(tmp_path)
    duplicate_anchor = _anchor()
    duplicate_anchor["producer_fact_id"] = "producer-anchor-duplicate"

    authority, composition, _research, _projection = (
        A.derive_authentication_role_authority(
            tmp_path,
            trace_payload=_payload([_anchor(), duplicate_anchor, _derived()]),
        )
    )

    assert authority["status"] == "UNMEASURABLE"
    assert all(row["authority_state"] == "UNMEASURABLE" for row in authority["facts"])
    assert composition["obligations"] == []


def test_malformed_external_fact_is_unmeasurable_and_cannot_create_research_authority(
    tmp_path: Path,
) -> None:
    _checkpoint(tmp_path)
    external = _anchor(provenance="EXTERNAL")
    external["evidence"][0]["locus"] = "not-an-exact-external-locus"

    authority, composition, research, _projection = (
        A.derive_authentication_role_authority(
            tmp_path, trace_payload=_payload([external])
        )
    )

    assert authority["facts"][0]["authority_state"] == "UNMEASURABLE"
    assert composition["debts"][0]["kind"] == "UNMEASURABLE_TYPED_HALF"
    assert research["obligations"] == []


def test_aptos_is_explicitly_not_triggered_until_cross_ecosystem_gate(
    tmp_path: Path,
) -> None:
    _checkpoint(tmp_path, ecosystem="aptos")

    authority, composition, research, projection = (
        A.derive_authentication_role_authority(
            tmp_path,
            trace_payload=_payload([_anchor(), _derived()], ecosystem="aptos"),
        )
    )

    assert authority["status"] == "NOT_TRIGGERED"
    assert authority["activation"]["state"] == "NON_EVM_ACTIVATION_GATE_HELD"
    assert authority["facts"] == []
    assert composition["status"] == "NOT_TRIGGERED"
    assert composition["obligations"] == []
    assert research["status"] == "NOT_TRIGGERED"
    assert "NON_EVM_ACTIVATION_GATE_HELD" in projection


def test_evm_not_selected_is_explicit_not_triggered_not_false_clean(
    tmp_path: Path,
) -> None:
    _checkpoint(tmp_path)

    authority, composition, research, _projection = (
        A.derive_authentication_role_authority(tmp_path, triggered=False)
    )

    assert authority["status"] == "NOT_TRIGGERED"
    assert authority["activation"]["state"] == "EVM_OPERATOR_NOT_SELECTED"
    assert composition["status"] == "NOT_TRIGGERED"
    assert research["status"] == "NOT_TRIGGERED"


def test_writes_are_byte_and_mtime_idempotent_and_projection_tamper_is_detected(
    tmp_path: Path,
) -> None:
    _checkpoint(tmp_path)
    trace = _payload([_anchor(), _derived()])

    A.write_authentication_role_authority(tmp_path, trace_payload=trace)
    paths = [
        tmp_path / A.AUTHORITY_FILE,
        tmp_path / A.COMPOSITION_FILE,
        tmp_path / A.EXTERNAL_RESEARCH_FILE,
        tmp_path / A.PROJECTION_FILE,
    ]
    before = [(path.read_bytes(), path.stat().st_mtime_ns) for path in paths]
    A.write_authentication_role_authority(tmp_path, trace_payload=trace)
    assert before == [(path.read_bytes(), path.stat().st_mtime_ns) for path in paths]
    assert A.validate_authentication_role_authority(
        tmp_path, trace_payload=trace
    ) == []

    projection = tmp_path / A.PROJECTION_FILE
    projection.write_text(
        projection.read_text(encoding="utf-8") + "tampered\n", encoding="utf-8"
    )
    assert any(
        A.PROJECTION_FILE in issue
        for issue in A.validate_authentication_role_authority(
            tmp_path, trace_payload=trace
        )
    )


def test_phaseio_fact_and_composition_writers_have_disjoint_outputs(
    tmp_path: Path,
) -> None:
    """Each DRIVER work unit persists only the outputs in its PhaseIO contract."""
    _checkpoint(tmp_path)
    trace = _payload([_anchor(), _derived()])
    (tmp_path / A.TRACE_FILE).write_text(
        json.dumps(trace, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    authority = A.write_authentication_role_fact_authority(tmp_path)

    assert authority["status"] == "ACTIVE"
    assert (tmp_path / A.AUTHORITY_FILE).is_file()
    assert not (tmp_path / A.COMPOSITION_FILE).exists()
    assert not (tmp_path / A.EXTERNAL_RESEARCH_FILE).exists()
    assert not (tmp_path / A.PROJECTION_FILE).exists()
    assert A.validate_authentication_role_fact_authority(tmp_path) == []

    # Composition is a separate fixed-denominator unit. It must consume only
    # the persisted typed fact authority, not silently re-read the model trace.
    (tmp_path / A.TRACE_FILE).unlink()
    composition = A.write_authentication_role_composition(tmp_path)

    assert composition["obligation_count"] == 1
    assert (tmp_path / A.COMPOSITION_FILE).is_file()
    assert (tmp_path / A.EXTERNAL_RESEARCH_FILE).is_file()
    assert (tmp_path / A.PROJECTION_FILE).is_file()
    assert A.validate_authentication_role_composition(tmp_path) == []


def test_phaseio_composition_rejects_tampered_fact_authority(tmp_path: Path) -> None:
    _checkpoint(tmp_path)
    A.write_authentication_role_fact_authority(
        tmp_path, trace_payload=_payload([_anchor(), _derived()])
    )
    authority_path = tmp_path / A.AUTHORITY_FILE
    payload = json.loads(authority_path.read_text(encoding="utf-8"))
    payload["operator_id"] = "tampered"
    authority_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    try:
        A.write_authentication_role_composition(tmp_path)
    except ValueError as exc:
        assert "authority digest" in str(exc).casefold()
    else:
        raise AssertionError("tampered fact authority must not be composed")

    assert not (tmp_path / A.COMPOSITION_FILE).exists()
    assert not (tmp_path / A.EXTERNAL_RESEARCH_FILE).exists()
    assert not (tmp_path / A.PROJECTION_FILE).exists()
