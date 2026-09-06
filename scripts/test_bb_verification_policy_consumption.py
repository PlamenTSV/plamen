"""RED contract for driver-owned BB verification-policy consumption receipts.

The receipt proves exact delivery and accounting only.  A verifier's policy
application proposal is never its own corroboration and the receipt can never
become proof, safety, severity, scope, report-exclusion, or negative-verdict
authority.

Production API specified by these fixtures::

    build_consumption_receipt(
        ingress,
        *,
        work_projection,
        proposal,
        launch_digest,
        method_dispatch_sha256,
        verifier_output_sha256,
        corroborations=(),
    ) -> dict

    validate_consumption_receipt(
        receipt,
        *,
        expected_bindings=None,
    ) -> dict

``expected_bindings``, when supplied, is the exact binding map returned by
``_expected_bindings`` below.  It prevents a digest-authenticated but stale
receipt from being replayed into another run, projection, launch, or output.
"""

from __future__ import annotations

import copy
import hashlib
import json

import pytest

import bb_verification_policy as policy


_TOP_LEVEL_FIELDS = {
    "schema",
    "status",
    "source_identity",
    "run_identity",
    "audit_identity",
    "runtime_identity",
    "wrapper_identity",
    "program_identity",
    "policy_identity",
    "ingress_identity",
    "work_projection_identity",
    "consumer_identity",
    "execution_identity",
    "delivery_denominator",
    "delivery_denominator_sha256",
    "rule_results",
    "review_required_work_item_ids",
    "non_verification_consumers",
    "terminal_negative_authority",
    "proof_authority",
    "severity_authority",
    "scope_authority",
    "report_exclusion_authority",
    "safety_authority",
    "receipt_sha256",
}

_EXPECTED_BINDING_FIELDS = {
    "source_policy_relative_path",
    "source_policy_file_sha256",
    "source_policy_sha256",
    "bb_run_id",
    "driver_run_id",
    "audit_snapshot_digest",
    "runtime_closure_sha256",
    "bb_wrapper_closure_sha256",
    "program_snapshot_sha256",
    "operator_projection_sha256",
    "policy_rule_roster_sha256",
    "ingress_sha256",
    "consumer_work_unit_id",
    "consumer_kind",
    "work_projection_sha256",
    "proposal_sha256",
    "launch_digest",
    "method_dispatch_sha256",
    "verifier_output_sha256",
}

_AUTHORITY_FIELDS = (
    "terminal_negative_authority",
    "proof_authority",
    "severity_authority",
    "scope_authority",
    "report_exclusion_authority",
    "safety_authority",
)


def _canonical_bytes(value) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _digest(value) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _rehash(payload: dict, digest_field: str) -> dict:
    unsigned = {
        key: value for key, value in payload.items() if key != digest_field
    }
    payload[digest_field] = _digest(unsigned)
    return payload


def _rule(index: int) -> dict:
    text = f"Rule {index} requires a locally bound verification artifact."
    identity = {
        "kind": "POC_REQUIREMENT",
        "normative_text": text,
        "source_field": "pocRequirements",
        "source_path": f"/policy_fields/pocRequirements/{index}",
        "applies_to_families": ["all"],
        "applies_to_severities": [],
        "applies_to_impact_ids": [],
        "source_text_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
    }
    unsigned = {
        "rule_id": f"BBPOL-{_digest(identity)[:20]}",
        **identity,
    }
    return {**unsigned, "rule_digest": _digest(unsigned)}


def _ingress(rules: list[dict] | None = None) -> dict:
    ordered = sorted(
        rules or [_rule(1), _rule(2)],
        key=lambda row: (row["rule_id"], row["rule_digest"]),
    )
    roster = [
        {"rule_id": row["rule_id"], "rule_digest": row["rule_digest"]}
        for row in ordered
    ]
    operator_unsigned = {
        "schema": policy.OPERATOR_SCHEMA,
        "program_snapshot_sha256": "1" * 64,
        "rules": ordered,
        "unresolved_source_debts": [],
        "policy_rule_roster_sha256": _digest({"rules": roster}),
        "allowed_dispositions": [
            "SATISFIED",
            "NOT_APPLICABLE_WITH_EVIDENCE",
            "UNRESOLVED",
        ],
        "unresolved_effect": "RETAIN_REQUEUE_REVIEW",
        "projection_readiness": "READY_FOR_TYPED_INGRESS",
    }
    operator = {
        **operator_unsigned,
        "projection_sha256": _digest(operator_unsigned),
    }
    ingress_unsigned = {
        "schema": policy.INGRESS_SCHEMA,
        "bb_run_id": "11111111-1111-4111-8111-111111111111",
        "driver_run_id": "driver-run-1",
        "audit_snapshot_digest": "2" * 64,
        "source_policy_relative_path": "run/BB_VERIFICATION_POLICY.json",
        "source_policy_file_sha256": "3" * 64,
        "source_policy_sha256": "4" * 64,
        "source_policy_schema": policy.SOURCE_SCHEMA,
        "runtime_closure_sha256": "5" * 64,
        "bb_wrapper_closure_sha256": "6" * 64,
        "policy_asset_family": "smart_contract",
        "operator_projection": operator,
    }
    return {
        **ingress_unsigned,
        "ingress_sha256": _digest(ingress_unsigned),
    }


def _work(ingress: dict, *, two_work_items: bool = False) -> dict:
    rows = [{"work_item_id": "H-01", "severity": "high", "impact_ids": []}]
    if two_work_items:
        rows.append(
            {"work_item_id": "M-02", "severity": "medium", "impact_ids": []}
        )
    return policy.build_work_projection(
        ingress,
        consumer_work_unit_id="verify.primary.0001",
        consumer_kind="PRIMARY",
        work_items=rows,
    )


def _proposal(
    work: dict,
    *,
    dispositions: dict[tuple[str, str], str] | None = None,
    omitted: set[tuple[str, str]] | None = None,
) -> dict:
    choices = dispositions or {}
    omitted_keys = omitted or set()
    work_rows = []
    for item in work["work_items"]:
        applications = []
        for rule in item["applicable_rules"]:
            key = (item["work_item_id"], rule["rule_id"])
            if key in omitted_keys:
                continue
            applications.append(
                {
                    "rule_id": rule["rule_id"],
                    "rule_digest": rule["rule_digest"],
                    "proposed_disposition": choices.get(key, "SATISFIED"),
                    "evidence_refs": [
                        {
                            "artifact": f"verify_{item['work_item_id']}.md",
                            "artifact_sha256": "7" * 64,
                            "evidence_id": f"{rule['rule_id']}:application",
                        }
                    ],
                }
            )
        work_rows.append(
            {
                "work_item_id": item["work_item_id"],
                "rule_applications": applications,
            }
        )
    unsigned = {
        "schema": policy.APPLICATION_SCHEMA,
        "consumer_work_unit_id": work["consumer_work_unit_id"],
        "work_projection_sha256": work["projection_sha256"],
        "work_items": work_rows,
    }
    return {**unsigned, "proposal_sha256": _digest(unsigned)}


def _corroborations(work: dict) -> list[dict]:
    return [
        {
            "work_item_id": item["work_item_id"],
            "rule_id": rule["rule_id"],
            "rule_digest": rule["rule_digest"],
            "evidence_binding_sha256": hashlib.sha256(
                (
                    f"{item['work_item_id']}:{rule['rule_id']}:"
                    "independent-driver-evidence"
                ).encode("utf-8")
            ).hexdigest(),
        }
        for item in work["work_items"]
        for rule in item["applicable_rules"]
    ]


def _build(
    *,
    ingress: dict | None = None,
    work: dict | None = None,
    proposal: dict | None = None,
    corroborations: list[dict] | None = None,
) -> tuple[dict, dict, dict]:
    ingress_value = ingress or _ingress()
    work_value = work or _work(ingress_value)
    proposal_value = proposal or _proposal(work_value)
    receipt = policy.build_consumption_receipt(
        ingress_value,
        work_projection=work_value,
        proposal=proposal_value,
        launch_digest="8" * 64,
        method_dispatch_sha256="9" * 64,
        verifier_output_sha256="a" * 64,
        corroborations=corroborations or (),
    )
    return receipt, work_value, proposal_value


def _expected_bindings(receipt: dict) -> dict:
    expected = {
        "source_policy_relative_path": receipt["source_identity"][
            "relative_path"
        ],
        "source_policy_file_sha256": receipt["source_identity"][
            "file_sha256"
        ],
        "source_policy_sha256": receipt["source_identity"]["policy_sha256"],
        "bb_run_id": receipt["run_identity"]["bb_run_id"],
        "driver_run_id": receipt["run_identity"]["driver_run_id"],
        "audit_snapshot_digest": receipt["audit_identity"][
            "audit_snapshot_digest"
        ],
        "runtime_closure_sha256": receipt["runtime_identity"][
            "runtime_closure_sha256"
        ],
        "bb_wrapper_closure_sha256": receipt["wrapper_identity"][
            "bb_wrapper_closure_sha256"
        ],
        "program_snapshot_sha256": receipt["program_identity"][
            "program_snapshot_sha256"
        ],
        "operator_projection_sha256": receipt["policy_identity"][
            "operator_projection_sha256"
        ],
        "policy_rule_roster_sha256": receipt["policy_identity"][
            "policy_rule_roster_sha256"
        ],
        "ingress_sha256": receipt["ingress_identity"]["ingress_sha256"],
        "consumer_work_unit_id": receipt["consumer_identity"][
            "consumer_work_unit_id"
        ],
        "consumer_kind": receipt["consumer_identity"]["consumer_kind"],
        "work_projection_sha256": receipt["work_projection_identity"][
            "projection_sha256"
        ],
        "proposal_sha256": receipt["execution_identity"]["proposal_sha256"],
        "launch_digest": receipt["execution_identity"]["launch_digest"],
        "method_dispatch_sha256": receipt["execution_identity"][
            "method_dispatch_sha256"
        ],
        "verifier_output_sha256": receipt["execution_identity"][
            "verifier_output_sha256"
        ],
    }
    assert set(expected) == _EXPECTED_BINDING_FIELDS
    return expected


def test_consumption_receipt_binds_every_identity_and_exact_denominator():
    ingress = _ingress()
    work = _work(ingress, two_work_items=True)
    proposal = _proposal(work)
    receipt, _work_value, _proposal_value = _build(
        ingress=ingress,
        work=work,
        proposal=proposal,
    )

    assert set(receipt) == _TOP_LEVEL_FIELDS
    assert receipt["schema"] == policy.CONSUMPTION_SCHEMA
    assert receipt["status"] == "CONSUMED_VERIFICATION_ONLY"
    assert receipt["source_identity"] == {
        "schema": policy.SOURCE_SCHEMA,
        "relative_path": ingress["source_policy_relative_path"],
        "file_sha256": ingress["source_policy_file_sha256"],
        "policy_sha256": ingress["source_policy_sha256"],
    }
    assert receipt["run_identity"] == {
        "bb_run_id": ingress["bb_run_id"],
        "driver_run_id": ingress["driver_run_id"],
    }
    assert receipt["audit_identity"] == {
        "audit_snapshot_digest": ingress["audit_snapshot_digest"]
    }
    assert receipt["runtime_identity"] == {
        "runtime_closure_sha256": ingress["runtime_closure_sha256"]
    }
    assert receipt["wrapper_identity"] == {
        "bb_wrapper_closure_sha256": ingress["bb_wrapper_closure_sha256"]
    }
    assert receipt["program_identity"] == {
        "program_snapshot_sha256": ingress["operator_projection"][
            "program_snapshot_sha256"
        ]
    }
    assert receipt["policy_identity"] == {
        "schema": policy.OPERATOR_SCHEMA,
        "operator_projection_sha256": ingress["operator_projection"][
            "projection_sha256"
        ],
        "policy_rule_roster_sha256": ingress["operator_projection"][
            "policy_rule_roster_sha256"
        ],
        "policy_asset_family": ingress["policy_asset_family"],
    }
    assert receipt["ingress_identity"] == {
        "schema": policy.INGRESS_SCHEMA,
        "ingress_sha256": ingress["ingress_sha256"],
    }
    assert receipt["work_projection_identity"] == {
        "schema": policy.WORK_SCHEMA,
        "projection_sha256": work["projection_sha256"],
    }
    assert receipt["consumer_identity"] == {
        "consumer_work_unit_id": work["consumer_work_unit_id"],
        "consumer_kind": work["consumer_kind"],
    }
    expected_deliveries = [
        {
            "work_item_id": item["work_item_id"],
            "rule_id": rule["rule_id"],
            "rule_digest": rule["rule_digest"],
        }
        for item in work["work_items"]
        for rule in item["applicable_rules"]
    ]
    assert receipt["delivery_denominator"] == expected_deliveries
    assert receipt["delivery_denominator_sha256"] == _digest(
        {"deliveries": expected_deliveries}
    )
    assert {
        (row["work_item_id"], row["rule_id"], row["rule_digest"])
        for row in receipt["rule_results"]
    } == {
        (row["work_item_id"], row["rule_id"], row["rule_digest"])
        for row in expected_deliveries
    }
    assert policy.validate_consumption_receipt(
        receipt,
        expected_bindings=_expected_bindings(receipt),
    ) == receipt


@pytest.mark.parametrize(
    "disposition",
    ["SATISFIED", "NOT_APPLICABLE_WITH_EVIDENCE"],
)
def test_verifier_proposal_is_never_its_own_corroboration(disposition: str):
    ingress = _ingress([_rule(1)])
    work = _work(ingress)
    rule = work["work_items"][0]["applicable_rules"][0]
    proposal = _proposal(
        work,
        dispositions={("H-01", rule["rule_id"]): disposition},
    )
    receipt, _work_value, _proposal_value = _build(
        ingress=ingress,
        work=work,
        proposal=proposal,
    )

    result = receipt["rule_results"][0]
    assert result["proposal_state"] == "PRESENT"
    assert result["proposed_disposition"] == disposition
    assert result["mechanical_status"] == "PROPOSAL_ONLY"
    assert result["corroboration_sha256"] is None
    assert result["downstream_effect"] == "RETAIN_REQUEUE_REVIEW"
    assert receipt["review_required_work_item_ids"] == ["H-01"]


def test_missing_and_unresolved_rows_are_losslessly_retained():
    ingress = _ingress()
    work = _work(ingress)
    first, second = work["work_items"][0]["applicable_rules"]
    proposal = _proposal(
        work,
        dispositions={("H-01", first["rule_id"]): "UNRESOLVED"},
        omitted={("H-01", second["rule_id"])},
    )
    receipt, _work_value, _proposal_value = _build(
        ingress=ingress,
        work=work,
        proposal=proposal,
    )
    results = {row["rule_id"]: row for row in receipt["rule_results"]}

    assert results[first["rule_id"]]["proposal_state"] == "PRESENT"
    assert results[first["rule_id"]]["mechanical_status"] == "UNRESOLVED"
    assert results[first["rule_id"]][
        "downstream_effect"
    ] == "RETAIN_REQUEUE_REVIEW"
    assert results[second["rule_id"]]["proposal_state"] == "MISSING"
    assert results[second["rule_id"]]["proposed_disposition"] == "UNRESOLVED"
    assert results[second["rule_id"]]["mechanical_status"] == "UNRESOLVED"
    assert results[second["rule_id"]][
        "downstream_effect"
    ] == "RETAIN_REQUEUE_REVIEW"
    assert receipt["review_required_work_item_ids"] == ["H-01"]


def test_independent_corroboration_closes_only_policy_application_debt():
    ingress = _ingress()
    work = _work(ingress)
    proposal = _proposal(work)
    receipt, _work_value, _proposal_value = _build(
        ingress=ingress,
        work=work,
        proposal=proposal,
        corroborations=_corroborations(work),
    )

    assert all(
        result["mechanical_status"] == "CORROBORATED"
        and result["downstream_effect"] == "NONE"
        and result["corroboration_sha256"] is not None
        for result in receipt["rule_results"]
    )
    assert receipt["review_required_work_item_ids"] == []
    assert all(receipt[field] is False for field in _AUTHORITY_FIELDS)
    assert receipt["non_verification_consumers"] == []


def test_extra_or_duplicate_proposal_rows_cannot_change_the_denominator():
    ingress = _ingress([_rule(1)])
    work = _work(ingress)
    proposal = _proposal(work)
    duplicate = copy.deepcopy(proposal["work_items"][0]["rule_applications"][0])
    proposal["work_items"][0]["rule_applications"].append(duplicate)
    _rehash(proposal, "proposal_sha256")

    with pytest.raises(policy.BBVerificationPolicyError, match="duplicate|denominator"):
        _build(ingress=ingress, work=work, proposal=proposal)

    extra = _proposal(work)
    extra["work_items"][0]["rule_applications"].append(
        {
            "rule_id": "BBPOL-" + "f" * 20,
            "rule_digest": "f" * 64,
            "proposed_disposition": "SATISFIED",
            "evidence_refs": [],
        }
    )
    _rehash(extra, "proposal_sha256")
    with pytest.raises(policy.BBVerificationPolicyError, match="extra|denominator"):
        _build(ingress=ingress, work=work, proposal=extra)


def test_receipt_digest_authenticates_all_fields():
    receipt, _work_value, _proposal_value = _build()
    tampered = copy.deepcopy(receipt)
    tampered["rule_results"][0]["downstream_effect"] = "NONE"

    with pytest.raises(policy.BBVerificationPolicyError, match="digest"):
        policy.validate_consumption_receipt(tampered)


@pytest.mark.parametrize("field", _AUTHORITY_FIELDS)
def test_rehashed_authority_escalation_is_semantically_rejected(field: str):
    receipt, _work_value, _proposal_value = _build()
    forged = copy.deepcopy(receipt)
    forged[field] = True
    _rehash(forged, "receipt_sha256")

    with pytest.raises(policy.BBVerificationPolicyError, match="authority"):
        policy.validate_consumption_receipt(forged)


def test_rehashed_non_verification_consumer_is_rejected():
    receipt, _work_value, _proposal_value = _build()
    forged = copy.deepcopy(receipt)
    forged["non_verification_consumers"] = ["REPORT"]
    _rehash(forged, "receipt_sha256")

    with pytest.raises(
        policy.BBVerificationPolicyError,
        match="non.verification|consumer",
    ):
        policy.validate_consumption_receipt(forged)


@pytest.mark.parametrize(
    "field",
    [
        "source_policy_file_sha256",
        "source_policy_sha256",
        "bb_run_id",
        "driver_run_id",
        "audit_snapshot_digest",
        "runtime_closure_sha256",
        "bb_wrapper_closure_sha256",
        "program_snapshot_sha256",
        "operator_projection_sha256",
        "policy_rule_roster_sha256",
        "ingress_sha256",
        "consumer_work_unit_id",
        "consumer_kind",
        "work_projection_sha256",
        "proposal_sha256",
        "launch_digest",
        "method_dispatch_sha256",
        "verifier_output_sha256",
    ],
)
def test_expected_bindings_reject_stale_or_cross_run_receipts(field: str):
    receipt, _work_value, _proposal_value = _build()
    expected = _expected_bindings(receipt)
    expected[field] = (
        "stale-identity"
        if field in {
            "bb_run_id",
            "driver_run_id",
            "consumer_work_unit_id",
            "consumer_kind",
        }
        else "f" * 64
    )

    with pytest.raises(policy.BBVerificationPolicyError, match="binding|stale"):
        policy.validate_consumption_receipt(
            receipt,
            expected_bindings=expected,
        )


def test_expected_bindings_are_exact_not_a_partial_authority():
    receipt, _work_value, _proposal_value = _build()
    expected = _expected_bindings(receipt)
    expected.pop("launch_digest")
    with pytest.raises(policy.BBVerificationPolicyError, match="binding.*fields|exact"):
        policy.validate_consumption_receipt(
            receipt,
            expected_bindings=expected,
        )

    unexpected = _expected_bindings(receipt)
    unexpected["report_can_exclude"] = True
    with pytest.raises(policy.BBVerificationPolicyError, match="binding.*fields|exact"):
        policy.validate_consumption_receipt(
            receipt,
            expected_bindings=unexpected,
        )
