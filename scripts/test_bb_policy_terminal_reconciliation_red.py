"""RED contracts for run-level BB policy consumption reconciliation.

The per-verifier BB policy receipt proves one delivery boundary.  It does not
prove that every primary/recovery verifier in the run consumed the current
policy, that a later severity change was re-verified, or that skeptic/report
received only a bounded non-normative summary.  These tests specify that
missing downstream authority.

Expected public pure APIs in :mod:`bb_verification_policy`::

    build_terminal_reconciliation(
        ingress,
        *,
        candidate_denominator,
        expected_consumptions,
        consumption_records,
    ) -> dict

    validate_terminal_reconciliation(
        payload,
        *,
        expected_ingress_sha256,
        expected_driver_run_id,
        expected_candidate_denominator_sha256,
    ) -> dict

    build_downstream_reconciliation_projection(
        reconciliation,
        *,
        consumer_kind,  # SKEPTIC or REPORT only
    ) -> dict

    build_severity_reverification_plan(
        ingress,
        *,
        candidate_denominator,
        reconciliation,
    ) -> dict

Expected driver API::

    _compile_bb_policy_terminal_reconciliation(scratchpad, config)

The driver function returns ``None`` byte-exactly for non-BB runs.  For BB
runs it owns the exact artifact-ledger enumeration of all primary, ordinary
recovery, mandatory-reverify, late-reverify, and policy-severity-change
consumers.  The pure builder accepts already-loaded records so its semantics
can be tested without granting filesystem enumeration authority to model code.

``candidate_denominator`` is a canonical sequence of::

    {
      "candidate_id": str,
      "current_severity": str,
      "impact_ids": [str, ...],
      "candidate_state_sha256": lowercase_sha256,
    }

``expected_consumptions`` is the independent denominator compiled by the
driver from the primary roster plus committed recovery contracts::

    {
      "consumer_work_unit_id": str,
      "consumer_kind": PRIMARY | RECOVERY | MANDATORY_REVERIFY |
                       LATE_REVERIFY | BB_POLICY_SEVERITY_CHANGE,
      "recovery_id": null for PRIMARY, otherwise the exact recovery identity,
      "work_items": [
        {"candidate_id": str, "severity": str, "impact_ids": [str, ...]},
      ],
    }

``consumption_records`` carries the exact local artifact names, artifact byte
hashes, and validated JSON values for the work packet, model proposal, and
driver receipt.  An absent record is debt, not an exception; an extra,
duplicate, stale, cross-run, internally inconsistent, or hash-mismatched
record is rejected.

The reconciliation and its downstream projections are accounting/evidence
transports only.  They never obtain negative-verdict, proof, safety, scope,
severity, report-exclusion, or primary-queue mutation authority.
"""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

import bb_verification_policy as policy
import plamen_driver as driver
from phase_io_contracts import resolve_phase_io_contract
from test_bb_verification_policy_consumption import (
    _corroborations,
    _digest,
    _ingress,
    _proposal,
)


_AUTHORITY_FIELDS = (
    "terminal_negative_authority",
    "proof_authority",
    "safety_authority",
    "scope_authority",
    "severity_authority",
    "report_exclusion_authority",
    "primary_queue_mutation_authority",
)


def _api(name: str):
    value = getattr(policy, name, None)
    assert callable(value), (
        f"missing bb_verification_policy.{name}; "
        "this is the intentional terminal-reconciliation RED boundary"
    )
    return value


def _canonical_bytes(value) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _artifact_sha256(value) -> str:
    return hashlib.sha256(_canonical_bytes(value) + b"\n").hexdigest()


def _rehash(payload: dict, digest_field: str) -> dict:
    unsigned = {
        key: value for key, value in payload.items() if key != digest_field
    }
    payload[digest_field] = _digest(unsigned)
    return payload


def _candidate(
    candidate_id: str = "H-01",
    *,
    severity: str = "high",
    state_seed: str = "candidate-state",
) -> dict:
    return {
        "candidate_id": candidate_id,
        "current_severity": severity,
        "impact_ids": [],
        "candidate_state_sha256": hashlib.sha256(
            f"{candidate_id}:{severity}:{state_seed}".encode("utf-8")
        ).hexdigest(),
    }


def _expected(
    *,
    consumer_kind: str,
    consumer_id: str,
    severity: str = "high",
    candidate_id: str = "H-01",
    recovery_id: str | None = None,
) -> dict:
    return {
        "consumer_work_unit_id": consumer_id,
        "consumer_kind": consumer_kind,
        "recovery_id": recovery_id,
        "work_items": [
            {
                "candidate_id": candidate_id,
                "severity": severity,
                "impact_ids": [],
            }
        ],
    }


def _work(ingress: dict, expected: dict) -> dict:
    return policy.build_work_projection(
        ingress,
        consumer_work_unit_id=expected["consumer_work_unit_id"],
        consumer_kind=expected["consumer_kind"],
        work_items=[
            {
                "work_item_id": row["candidate_id"],
                "severity": row["severity"],
                "impact_ids": row["impact_ids"],
            }
            for row in expected["work_items"]
        ],
    )


def _receipt(
    ingress: dict,
    work: dict,
    application: dict,
    *,
    corroborated: bool,
) -> dict:
    return policy.build_consumption_receipt(
        ingress,
        work_projection=work,
        proposal=application,
        launch_digest="8" * 64,
        method_dispatch_sha256="9" * 64,
        verifier_output_sha256="a" * 64,
        corroborations=_corroborations(work) if corroborated else (),
    )


def _record(
    ingress: dict,
    expected: dict,
    *,
    disposition: str = "SATISFIED",
    corroborated: bool = True,
) -> dict:
    work = _work(ingress, expected)
    choices = {
        (item["work_item_id"], rule["rule_id"]): disposition
        for item in work["work_items"]
        for rule in item["applicable_rules"]
    }
    application = _proposal(work, dispositions=choices)
    receipt = _receipt(
        ingress,
        work,
        application,
        corroborated=corroborated,
    )
    prefix = (
        "_verifier_runtime_units"
        if expected["consumer_kind"] == "PRIMARY"
        else "_verification_recovery"
    )
    directory = f"{prefix}/{expected['consumer_work_unit_id']}"
    return {
        "consumer_work_unit_id": expected["consumer_work_unit_id"],
        "consumer_kind": expected["consumer_kind"],
        "recovery_id": expected["recovery_id"],
        "work_projection_artifact": f"{directory}/bb_policy_work.json",
        "work_projection_artifact_sha256": _artifact_sha256(work),
        "application_artifact": f"{directory}/bb_policy_application.json",
        "application_artifact_sha256": _artifact_sha256(application),
        "receipt_artifact": (
            f"{directory}/bb_policy_consumption_receipt.json"
        ),
        "receipt_artifact_sha256": _artifact_sha256(receipt),
        "work_projection": work,
        "application": application,
        "receipt": receipt,
    }


def _four_way_fixture() -> tuple[dict, list[dict], list[dict], list[dict]]:
    ingress = _ingress()
    candidates = [_candidate()]
    expected = [
        _expected(
            consumer_kind="PRIMARY",
            consumer_id="verify.primary.0001",
        ),
        _expected(
            consumer_kind="RECOVERY",
            consumer_id="VREC-ordinary-0001",
            recovery_id="VREC-ordinary-0001",
        ),
        _expected(
            consumer_kind="MANDATORY_REVERIFY",
            consumer_id="VREC-mandatory-0001",
            recovery_id="VREC-mandatory-0001",
        ),
        _expected(
            consumer_kind="LATE_REVERIFY",
            consumer_id="VREC-late-0001",
            recovery_id="VREC-late-0001",
        ),
    ]
    records = [_record(ingress, row) for row in expected]
    return ingress, candidates, expected, records


def _build_terminal(
    ingress: dict,
    candidates: list[dict],
    expected: list[dict],
    records: list[dict],
) -> dict:
    return _api("build_terminal_reconciliation")(
        ingress,
        candidate_denominator=candidates,
        expected_consumptions=expected,
        consumption_records=records,
    )


def _validate_terminal(terminal: dict, ingress: dict, candidates: list[dict]):
    return _api("validate_terminal_reconciliation")(
        terminal,
        expected_ingress_sha256=ingress["ingress_sha256"],
        expected_driver_run_id=ingress["driver_run_id"],
        expected_candidate_denominator_sha256=_digest(
            {"candidates": candidates}
        ),
    )


def _candidate_result(terminal: dict, candidate_id: str = "H-01") -> dict:
    return next(
        row
        for row in terminal["candidate_results"]
        if row["candidate_id"] == candidate_id
    )


def test_exact_run_aggregate_binds_all_consumer_kinds_and_hashes() -> None:
    ingress, candidates, expected, records = _four_way_fixture()
    terminal = _build_terminal(ingress, candidates, expected, records)

    assert _validate_terminal(terminal, ingress, candidates) == terminal
    assert terminal["candidate_count"] == 1
    assert terminal["expected_consumption_count"] == 4
    assert terminal["receipt_count"] == 4
    assert terminal["candidate_denominator"] == candidates
    assert terminal["candidate_denominator_sha256"] == _digest(
        {"candidates": candidates}
    )
    result = _candidate_result(terminal)
    assert result["current_severity"] == "high"
    assert result["reconciliation_state"] == "RECONCILED"
    assert result["requeue_required"] is False
    assert result["human_review_required"] is False
    assert set(result["consumer_kinds"]) == {
        "PRIMARY",
        "RECOVERY",
        "MANDATORY_REVERIFY",
        "LATE_REVERIFY",
    }
    assert set(result["recovery_ids"]) == {
        "VREC-ordinary-0001",
        "VREC-mandatory-0001",
        "VREC-late-0001",
    }
    rows = terminal["consumption_results"]
    assert {
        row["work_projection_sha256"] for row in rows
    } == {
        record["work_projection"]["projection_sha256"]
        for record in records
    }
    assert {
        row["application_sha256"] for row in rows
    } == {
        record["application"]["proposal_sha256"]
        for record in records
    }
    assert {
        row["receipt_sha256"] for row in rows
    } == {
        record["receipt"]["receipt_sha256"]
        for record in records
    }
    assert {
        (
            row["work_projection_artifact_sha256"],
            row["application_artifact_sha256"],
            row["receipt_artifact_sha256"],
        )
        for row in rows
    } == {
        (
            record["work_projection_artifact_sha256"],
            record["application_artifact_sha256"],
            record["receipt_artifact_sha256"],
        )
        for record in records
    }


def test_missing_receipt_is_retained_requeued_and_human_reviewed() -> None:
    ingress, candidates, expected, records = _four_way_fixture()
    missing = records[:-1]
    terminal = _build_terminal(ingress, candidates, expected, missing)

    result = _candidate_result(terminal)
    assert result["reconciliation_state"] == "RETAIN_REQUEUE_REVIEW"
    assert result["requeue_required"] is True
    assert result["human_review_required"] is True
    assert terminal["receipt_count"] == 3
    assert terminal["missing_consumption_ids"] == ["VREC-late-0001"]
    assert terminal["terminal_negative_authority"] is False


@pytest.mark.parametrize(
    ("disposition", "corroborated", "expected_status"),
    [
        ("UNRESOLVED", False, "UNRESOLVED"),
        ("SATISFIED", False, "PROPOSAL_ONLY"),
    ],
)
def test_unresolved_or_proposal_only_receipt_never_closes_aggregate(
    disposition: str,
    corroborated: bool,
    expected_status: str,
) -> None:
    ingress = _ingress()
    candidates = [_candidate()]
    expected = [
        _expected(
            consumer_kind="PRIMARY",
            consumer_id="verify.primary.0001",
        )
    ]
    records = [
        _record(
            ingress,
            expected[0],
            disposition=disposition,
            corroborated=corroborated,
        )
    ]
    assert records[0]["receipt"]["rule_results"][0][
        "mechanical_status"
    ] == expected_status

    terminal = _build_terminal(ingress, candidates, expected, records)
    result = _candidate_result(terminal)
    assert result["reconciliation_state"] == "RETAIN_REQUEUE_REVIEW"
    assert result["requeue_required"] is True
    assert result["human_review_required"] is True


def test_extra_duplicate_or_wrong_recovery_identity_is_rejected() -> None:
    ingress, candidates, expected, records = _four_way_fixture()
    extra_expected = _expected(
        consumer_kind="RECOVERY",
        consumer_id="VREC-extra-0001",
        recovery_id="VREC-extra-0001",
    )
    with pytest.raises(policy.BBVerificationPolicyError):
        _build_terminal(
            ingress,
            candidates,
            expected,
            [*records, _record(ingress, extra_expected)],
        )
    with pytest.raises(policy.BBVerificationPolicyError):
        _build_terminal(
            ingress,
            candidates,
            expected,
            [*records, copy.deepcopy(records[0])],
        )
    wrong = copy.deepcopy(records)
    wrong[1]["recovery_id"] = "VREC-wrong-0001"
    with pytest.raises(policy.BBVerificationPolicyError):
        _build_terminal(ingress, candidates, expected, wrong)


def test_stale_cross_run_or_post_read_mutation_is_rejected() -> None:
    ingress, candidates, expected, records = _four_way_fixture()

    cross_run = copy.deepcopy(records)
    cross_run[0]["receipt"]["run_identity"][
        "driver_run_id"
    ] = "different-driver-run"
    _rehash(cross_run[0]["receipt"], "receipt_sha256")
    cross_run[0]["receipt_artifact_sha256"] = _artifact_sha256(
        cross_run[0]["receipt"]
    )
    with pytest.raises(policy.BBVerificationPolicyError):
        _build_terminal(ingress, candidates, expected, cross_run)

    mutated_application = copy.deepcopy(records)
    mutated_application[0]["application"]["work_items"][0][
        "rule_applications"
    ][0]["proposed_disposition"] = "UNRESOLVED"
    _rehash(mutated_application[0]["application"], "proposal_sha256")
    mutated_application[0][
        "application_artifact_sha256"
    ] = _artifact_sha256(mutated_application[0]["application"])
    with pytest.raises(policy.BBVerificationPolicyError):
        _build_terminal(
            ingress, candidates, expected, mutated_application
        )

    forged_file_hash = copy.deepcopy(records)
    forged_file_hash[0]["receipt_artifact_sha256"] = "f" * 64
    with pytest.raises(policy.BBVerificationPolicyError):
        _build_terminal(
            ingress, candidates, expected, forged_file_hash
        )


def test_terminal_validation_rejects_rehashed_authority_escalation() -> None:
    ingress, candidates, expected, records = _four_way_fixture()
    terminal = _build_terminal(ingress, candidates, expected, records)
    for field in _AUTHORITY_FIELDS:
        forged = copy.deepcopy(terminal)
        forged[field] = True
        _rehash(forged, "reconciliation_sha256")
        with pytest.raises(policy.BBVerificationPolicyError):
            _validate_terminal(forged, ingress, candidates)


def test_candidate_denominator_is_exact_and_current_severity_is_bound() -> None:
    ingress, candidates, expected, records = _four_way_fixture()
    duplicate = [*candidates, copy.deepcopy(candidates[0])]
    with pytest.raises(policy.BBVerificationPolicyError):
        _build_terminal(ingress, duplicate, expected, records)

    stale_candidate = [_candidate(severity="critical")]
    terminal = _build_terminal(
        ingress, stale_candidate, expected, records
    )
    result = _candidate_result(terminal)
    assert result["current_severity"] == "critical"
    assert result["reconciliation_state"] == "RETAIN_REQUEUE_REVIEW"
    assert result["requeue_required"] is True


@pytest.mark.parametrize("consumer_kind", ["SKEPTIC", "REPORT"])
def test_downstream_projection_is_bounded_refs_only(
    consumer_kind: str,
) -> None:
    ingress, candidates, expected, records = _four_way_fixture()
    terminal = _build_terminal(ingress, candidates, expected, records)
    projection = _api("build_downstream_reconciliation_projection")(
        terminal,
        consumer_kind=consumer_kind,
    )

    assert projection["consumer_kind"] == consumer_kind
    assert projection["reconciliation_sha256"] == terminal[
        "reconciliation_sha256"
    ]
    assert projection["candidate_states"] == [
        {
            "candidate_id": "H-01",
            "current_severity": "high",
            "reconciliation_state": "RECONCILED",
            "requeue_required": False,
            "human_review_required": False,
        }
    ]
    assert projection["evidence_refs"]
    assert all(
        set(row) == {"artifact", "artifact_sha256", "evidence_id"}
        for row in projection["evidence_refs"]
    )
    encoded = json.dumps(projection, sort_keys=True)
    forbidden = (
        "normative_text",
        "operator_projection",
        "source_policy_debts",
        "pocRequirements",
        "Rule 1 requires a locally bound verification artifact.",
    )
    assert all(token not in encoded for token in forbidden)
    assert all(projection[field] is False for field in _AUTHORITY_FIELDS)


@pytest.mark.parametrize(
    "consumer_kind",
    ["DISCOVERY", "VERIFIER", "DEPTH", "SKEPTIC_JUDGE", "TIER_WRITER"],
)
def test_downstream_projection_rejects_unregistered_consumers(
    consumer_kind: str,
) -> None:
    ingress, candidates, expected, records = _four_way_fixture()
    terminal = _build_terminal(ingress, candidates, expected, records)
    with pytest.raises(policy.BBVerificationPolicyError):
        _api("build_downstream_reconciliation_projection")(
            terminal,
            consumer_kind=consumer_kind,
        )


def _severity_rule() -> dict:
    text = "High-severity findings require an additional local proof artifact."
    identity = {
        "kind": "POC_REQUIREMENT",
        "normative_text": text,
        "source_field": "pocPerTypeAndSeverity",
        "source_path": "/policy_fields/pocPerTypeAndSeverity/high/0",
        "applies_to_families": ["all"],
        "applies_to_severities": ["high"],
        "applies_to_impact_ids": [],
        "source_text_sha256": hashlib.sha256(
            text.encode("utf-8")
        ).hexdigest(),
    }
    unsigned = {
        "rule_id": f"BBPOL-{_digest(identity)[:20]}",
        **identity,
    }
    return {**unsigned, "rule_digest": _digest(unsigned)}


def _severity_drift_fixture(
    *,
    severity_receipt: bool = False,
    severity_receipt_corroborated: bool = True,
) -> tuple[dict, list[dict], dict, list[dict], list[dict]]:
    ingress = _ingress([_severity_rule()])
    candidates = [_candidate(severity="high")]
    primary = _expected(
        consumer_kind="PRIMARY",
        consumer_id="verify.primary.0001",
        severity="low",
    )
    expected = [primary]
    records = [_record(ingress, primary)]
    terminal = _build_terminal(ingress, candidates, expected, records)
    plan = _api("build_severity_reverification_plan")(
        ingress,
        candidate_denominator=candidates,
        reconciliation=terminal,
    )
    if severity_receipt:
        obligation = plan["obligations"][0]
        severity_expected = _expected(
            consumer_kind="BB_POLICY_SEVERITY_CHANGE",
            consumer_id=obligation["recovery_id"],
            recovery_id=obligation["recovery_id"],
            severity="high",
        )
        expected.append(severity_expected)
        records.append(
            _record(
                ingress,
                severity_expected,
                corroborated=severity_receipt_corroborated,
            )
        )
        terminal = _build_terminal(
            ingress, candidates, expected, records
        )
    return ingress, candidates, terminal, expected, records


def test_severity_change_emits_additive_mandatory_recovery_not_queue_mutation(
) -> None:
    ingress, candidates, terminal, _expected_rows, _records = (
        _severity_drift_fixture()
    )
    frozen_candidates = copy.deepcopy(candidates)
    plan = _api("build_severity_reverification_plan")(
        ingress,
        candidate_denominator=candidates,
        reconciliation=terminal,
    )

    assert candidates == frozen_candidates
    assert plan["primary_queue_mutation_authority"] is False
    assert plan["terminal_negative_authority"] is False
    assert len(plan["obligations"]) == 1
    obligation = plan["obligations"][0]
    assert obligation["candidate_id"] == "H-01"
    assert obligation["from_severity"] == "low"
    assert obligation["to_severity"] == "high"
    assert obligation["consumer_kind"] == "BB_POLICY_SEVERITY_CHANGE"
    assert obligation["recovery_id"]
    assert obligation["downstream_effect"] == "RETAIN_REQUEUE_REVIEW"
    assert [
        row["rule_id"] for row in obligation["newly_applicable_rules"]
    ] == [_severity_rule()["rule_id"]]
    encoded = json.dumps(plan, sort_keys=True)
    assert "verification_queue.md" not in encoded
    assert "verification_queue.work_items.json" not in encoded


def test_completed_severity_reverification_closes_once_without_loop() -> None:
    ingress, candidates, terminal, _expected_rows, _records = (
        _severity_drift_fixture(severity_receipt=True)
    )
    plan = _api("build_severity_reverification_plan")(
        ingress,
        candidate_denominator=candidates,
        reconciliation=terminal,
    )
    assert plan["obligations"] == []
    assert _candidate_result(terminal)["reconciliation_state"] == "RECONCILED"


def test_unresolved_severity_reverification_reuses_one_stable_obligation(
) -> None:
    ingress, candidates, terminal, _expected_rows, _records = (
        _severity_drift_fixture(
            severity_receipt=True,
            severity_receipt_corroborated=False,
        )
    )
    first = _api("build_severity_reverification_plan")(
        ingress,
        candidate_denominator=candidates,
        reconciliation=terminal,
    )
    second = _api("build_severity_reverification_plan")(
        ingress,
        candidate_denominator=candidates,
        reconciliation=terminal,
    )
    assert len(first["obligations"]) == 1
    assert second == first
    assert first["obligations"][0]["recovery_id"] == second[
        "obligations"
    ][0]["recovery_id"]
    assert _candidate_result(terminal)[
        "reconciliation_state"
    ] == "RETAIN_REQUEUE_REVIEW"


def test_non_bb_driver_reconciliation_hook_is_byte_exact_noop(
    tmp_path: Path,
) -> None:
    hook = getattr(
        driver, "_compile_bb_policy_terminal_reconciliation", None
    )
    assert callable(hook), (
        "missing driver._compile_bb_policy_terminal_reconciliation; "
        "this is the intentional driver integration RED boundary"
    )
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    sentinel = scratchpad / "sentinel.bin"
    sentinel.write_bytes(b"unchanged")
    before = {
        path.relative_to(scratchpad).as_posix(): path.read_bytes()
        for path in scratchpad.rglob("*")
        if path.is_file()
    }
    config = {
        "scratchpad": str(scratchpad),
        "project_root": str(tmp_path),
        "_run_id": "driver-run-1",
        "pipeline": "sc",
        "mode": "thorough",
        "language": "evm",
        "cli_backend": "claude",
    }
    assert hook(scratchpad, config) is None
    after = {
        path.relative_to(scratchpad).as_posix(): path.read_bytes()
        for path in scratchpad.rglob("*")
        if path.is_file()
    }
    assert after == before


def test_phaseio_registers_one_driver_owned_terminal_reconciliation() -> None:
    path = getattr(
        policy,
        "TERMINAL_RECONCILIATION_PATH",
        ".bb/verification_policy_reconciliation.json",
    )
    contract = resolve_phase_io_contract(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        phase="bb_policy",
        work_unit_id="terminal_reconciliation",
        exact_inputs=(
            ".bb/verification_operator_policy.json",
            "_verifier_runtime_units/unit-1/bb_policy_work.json",
            "_verifier_runtime_units/unit-1/bb_policy_application.json",
            (
                "_verifier_runtime_units/unit-1/"
                "bb_policy_consumption_receipt.json"
            ),
        ),
        exact_outputs=(path,),
        exact_writer="DRIVER",
    )
    assert {row.path for row in contract.outputs} == {path}
    assert all(row.writer == "DRIVER" for row in contract.outputs)
    assert contract.model_invoked is False
    assert set(contract.immutable_inputs) == {
        "scratchpad:.bb/verification_operator_policy.json",
        (
            "scratchpad:_verifier_runtime_units/unit-1/"
            "bb_policy_work.json"
        ),
        (
            "scratchpad:_verifier_runtime_units/unit-1/"
            "bb_policy_application.json"
        ),
        (
            "scratchpad:_verifier_runtime_units/unit-1/"
            "bb_policy_consumption_receipt.json"
        ),
    }
