"""Fixture-first reds for AG-0 severity-ledger denominator authority.

The severity decision ledger is row authority, not proof that every queued
candidate received exactly one usable decision.  AG-0 adds one driver-owned
reconciliation receipt before any report consumer may treat the ledger as a
complete severity authority.

Bounded production API proposed in ``severity_decision_ledger.py``:

* ``reconcile_severity_ledger_coverage(ledger_path, *, expected_run_id,
  queue_work_plan_digest, expected_candidate_ids,
  expected_source_receipt_digests)``;
* ``write_severity_ledger_coverage_receipt(path, receipt)``;
* ``load_severity_ledger_coverage_receipt(path, *, severity_ledger_path,
  expected_run_id, expected_queue_work_plan_digest, expected_candidate_ids,
  expected_source_receipt_digests)``.

The loader must semantically re-reconcile the current ledger.  A caller that
can recompute an ordinary JSON digest must not be able to upgrade a partial or
challenged receipt to report authority.
"""
from __future__ import annotations

import copy
import hashlib
import inspect
import json
from pathlib import Path

import pytest

import severity_decision_ledger as SDL


RUN_ID = "severity-ledger-coverage-run"
QUEUE_WORK_PLAN_DIGEST = "7" * 64
COVERAGE_SCHEMA = "plamen.severity_ledger_coverage_receipt.v1"
RECEIPT_FIELDS = {
    "schema_version",
    "run_id",
    "queue_work_plan_digest",
    "expected_candidate_ids",
    "expected_source_receipt_digests_digest",
    "severity_ledger_digest",
    "ledger_authority_status",
    "denominator_status",
    "missing_candidate_ids",
    "extra_candidate_ids",
    "invalid_candidate_ids",
    "challenged_candidate_ids",
    "authority_status",
    "receipt_digest",
}


def _digest(value: object) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _source_digest(candidate_id: str) -> str:
    return _digest({"candidate_id": candidate_id, "source": "verifier-output"})


def _decision(candidate_id: str, *, challenged: bool = False) -> dict:
    impact_premise = f"PREM-IMPACT-{candidate_id}"
    likelihood_premise = f"PREM-LIKELIHOOD-{candidate_id}"
    impact_evidence = f"EVID-IMPACT-{candidate_id}"
    likelihood_evidence = f"EVID-LIKELIHOOD-{candidate_id}"
    proposal = {
        "schema_version": SDL.PROPOSAL_SCHEMA,
        "candidate_id": candidate_id,
        "constituent_ids": [candidate_id],
        "impact": {
            "class": "High",
            "harmed_asset": "protected asset",
            "harmed_capability": "availability of protected value",
            "premise_id": impact_premise,
            "premise_kind": "INTERNAL",
            "evidence_ids": [impact_evidence],
            "proof_scope": "IN_SCOPE_EXECUTION",
        },
        "likelihood": {
            "class": "Medium",
            "actor": "unprivileged actor",
            "preconditions": ["reachable state"],
            "premise_id": likelihood_premise,
            "premise_kind": "INTERNAL",
            "evidence_ids": [likelihood_evidence],
            "proof_scope": "IN_SCOPE_EXECUTION",
        },
        "modifiers": [],
        "proposed_severity": "Medium" if challenged else "High",
        "adjustment": (
            {
                "direction": "DOWN",
                "premise_ids": [likelihood_premise],
                "evidence_ids": [likelihood_evidence],
                "proof_scope": "IN_SCOPE_EXECUTION",
                "rationale": "The likelihood axis is proposed below upstream.",
            }
            if challenged
            else None
        ),
        "constituent_premise_outcomes": {
            candidate_id: {"impact": "SUPPORTED", "likelihood": "SUPPORTED"}
        },
    }
    evidence = [
        {
            "evidence_id": impact_evidence,
            "content_sha256": _digest({"evidence": impact_evidence}),
            "premise_ids": [impact_premise],
            "constituent_ids": [candidate_id],
            "proof_scope": "IN_SCOPE_EXECUTION",
            "capabilities": ["EXECUTION", "IMPACT", "HARM"],
            "issuer_identity": "mechanical-evidence-registry",
            "issuer_invocation_id": "mechanical-evidence-run",
        },
        {
            "evidence_id": likelihood_evidence,
            "content_sha256": _digest({"evidence": likelihood_evidence}),
            "premise_ids": [likelihood_premise],
            "constituent_ids": [candidate_id],
            "proof_scope": "IN_SCOPE_EXECUTION",
            "capabilities": ["EXECUTION", "LIKELIHOOD"],
            "issuer_identity": "mechanical-evidence-registry",
            "issuer_invocation_id": "mechanical-evidence-run",
        },
    ]
    assessor_identity = "severity-assessor"
    invocation_id = f"severity-assessor-{candidate_id}"
    return SDL.bind_severity_proposal(
        proposal,
        candidate_id=candidate_id,
        constituent_ids=[candidate_id],
        upstream_severity="High",
        assessor_identity=assessor_identity,
        assessor_invocation_id=invocation_id,
        run_id=RUN_ID,
        source_receipt_digest=_source_digest(candidate_id),
        evidence_receipts=evidence,
        assessor_launch_receipt={
            "schema_version": SDL.LAUNCH_RECEIPT_SCHEMA,
            "role": "ASSESSOR",
            "run_id": RUN_ID,
            "candidate_id": candidate_id,
            "constituent_ids": [candidate_id],
            "worker_identity": assessor_identity,
            "invocation_id": invocation_id,
            "backend": "claude",
            "launch_manifest_sha256": "8" * 64,
            "input_sha256": SDL.severity_assessor_input_digest(
                candidate_id=candidate_id,
                constituent_ids=[candidate_id],
                upstream_severity="High",
                run_id=RUN_ID,
                source_receipt_digest=_source_digest(candidate_id),
                evidence_receipts=evidence,
            ),
            "output_sha256": _digest(proposal),
        },
    )


def _ledger(
    tmp_path: Path,
    candidate_ids: list[str],
    *,
    challenged_ids: set[str] | None = None,
) -> tuple[Path, dict, dict[str, str]]:
    challenged = challenged_ids or set()
    decisions = [
        _decision(candidate_id, challenged=candidate_id in challenged)
        for candidate_id in candidate_ids
    ]
    path = tmp_path / "severity_decision_ledger.json"
    payload = SDL.write_severity_decision_ledger(path, RUN_ID, decisions)
    sources = {
        candidate_id: _source_digest(candidate_id)
        for candidate_id in candidate_ids
    }
    return path, payload, sources


def _required_api(name: str):
    value = getattr(SDL, name, None)
    assert callable(value), f"AG-0 requires severity_decision_ledger.{name}"
    return value


def _reconcile(
    ledger_path: Path,
    expected_candidate_ids: list[str],
    expected_sources: dict[str, str],
    *,
    run_id: str = RUN_ID,
    queue_digest: str = QUEUE_WORK_PLAN_DIGEST,
) -> dict:
    return _required_api("reconcile_severity_ledger_coverage")(
        ledger_path,
        expected_run_id=run_id,
        queue_work_plan_digest=queue_digest,
        expected_candidate_ids=expected_candidate_ids,
        expected_source_receipt_digests=expected_sources,
    )


def _write_receipt(path: Path, receipt: dict) -> dict:
    return _required_api("write_severity_ledger_coverage_receipt")(path, receipt)


def _load_receipt(
    path: Path,
    ledger_path: Path,
    expected_candidate_ids: list[str],
    expected_sources: dict[str, str],
    *,
    run_id: str = RUN_ID,
    queue_digest: str = QUEUE_WORK_PLAN_DIGEST,
) -> dict:
    return _required_api("load_severity_ledger_coverage_receipt")(
        path,
        severity_ledger_path=ledger_path,
        expected_run_id=run_id,
        expected_queue_work_plan_digest=queue_digest,
        expected_candidate_ids=expected_candidate_ids,
        expected_source_receipt_digests=expected_sources,
    )


def test_ag0_bounded_driver_owned_apis_are_explicit() -> None:
    reconcile = _required_api("reconcile_severity_ledger_coverage")
    writer = _required_api("write_severity_ledger_coverage_receipt")
    loader = _required_api("load_severity_ledger_coverage_receipt")

    assert set(inspect.signature(reconcile).parameters) == {
        "ledger_path",
        "expected_run_id",
        "queue_work_plan_digest",
        "expected_candidate_ids",
        "expected_source_receipt_digests",
    }
    assert set(inspect.signature(writer).parameters) == {"path", "receipt"}
    assert set(inspect.signature(loader).parameters) == {
        "path",
        "severity_ledger_path",
        "expected_run_id",
        "expected_queue_work_plan_digest",
        "expected_candidate_ids",
        "expected_source_receipt_digests",
    }


def test_complete_exact_ledger_receipt_binds_the_full_driver_denominator(
    tmp_path: Path,
) -> None:
    ledger_path, ledger, sources = _ledger(tmp_path, ["HYP-002", "HYP-001"])
    receipt = _reconcile(
        ledger_path,
        ["HYP-002", "HYP-001"],
        sources,
    )

    assert set(receipt) == RECEIPT_FIELDS
    assert receipt["schema_version"] == COVERAGE_SCHEMA
    assert receipt["run_id"] == RUN_ID
    assert receipt["queue_work_plan_digest"] == QUEUE_WORK_PLAN_DIGEST
    assert receipt["expected_candidate_ids"] == ["HYP-001", "HYP-002"]
    assert receipt["expected_source_receipt_digests_digest"] == _digest(
        {candidate: sources[candidate] for candidate in sorted(sources)}
    )
    assert receipt["severity_ledger_digest"] == ledger["ledger_digest"]
    assert receipt["ledger_authority_status"] == "REPORT_AUTHORITATIVE"
    assert receipt["denominator_status"] == "NONEMPTY"
    assert receipt["missing_candidate_ids"] == []
    assert receipt["extra_candidate_ids"] == []
    assert receipt["invalid_candidate_ids"] == []
    assert receipt["challenged_candidate_ids"] == []
    assert receipt["authority_status"] == "REPORT_AUTHORITATIVE"
    unsigned = {key: value for key, value in receipt.items() if key != "receipt_digest"}
    assert receipt["receipt_digest"] == _digest(unsigned)


@pytest.mark.parametrize(
    "ledger_ids,expected_ids,field,expected",
    [
        (["HYP-001"], ["HYP-001", "HYP-002"], "missing_candidate_ids", ["HYP-002"]),
        (["HYP-001", "HYP-999"], ["HYP-001"], "extra_candidate_ids", ["HYP-999"]),
    ],
)
def test_missing_or_extra_rows_are_visible_and_never_full_authority(
    tmp_path: Path,
    ledger_ids: list[str],
    expected_ids: list[str],
    field: str,
    expected: list[str],
) -> None:
    ledger_path, _, ledger_sources = _ledger(tmp_path, ledger_ids)
    expected_sources = {
        candidate: _source_digest(candidate) for candidate in expected_ids
    }
    # Extra candidates are not trusted queue members and therefore do not
    # appear in the caller's source-authority mapping.
    receipt = _reconcile(ledger_path, expected_ids, expected_sources)

    assert receipt[field] == expected
    assert receipt["authority_status"] == "INCOMPLETE"
    assert receipt["authority_status"] != "REPORT_AUTHORITATIVE"
    assert ledger_sources  # fixture sanity: the ledger itself is non-empty


def test_semantically_invalid_row_is_enumerated_not_promoted(tmp_path: Path) -> None:
    ledger_path, ledger, sources = _ledger(tmp_path, ["HYP-001"])
    payload = copy.deepcopy(ledger)
    payload["decisions"][0]["final_severity"] = "Low"
    unsigned = {key: value for key, value in payload.items() if key != "ledger_digest"}
    payload["ledger_digest"] = _digest(unsigned)
    ledger_path.write_text(json.dumps(payload), encoding="utf-8")

    receipt = _reconcile(ledger_path, ["HYP-001"], sources)

    assert receipt["invalid_candidate_ids"] == ["HYP-001"]
    assert receipt["missing_candidate_ids"] == []
    assert receipt["authority_status"] == "INCOMPLETE"


def test_challenged_row_is_visible_and_blocks_full_authority(tmp_path: Path) -> None:
    ledger_path, _, sources = _ledger(
        tmp_path, ["HYP-001"], challenged_ids={"HYP-001"}
    )

    receipt = _reconcile(ledger_path, ["HYP-001"], sources)

    assert receipt["challenged_candidate_ids"] == ["HYP-001"]
    assert receipt["authority_status"] == "INCOMPLETE"


def test_duplicate_ledger_identity_is_rejected_even_with_rehashed_outer_ledger(
    tmp_path: Path,
) -> None:
    ledger_path, ledger, sources = _ledger(tmp_path, ["HYP-001"])

    with pytest.raises(SDL.SeverityDecisionError, match="duplicate"):
        _reconcile(ledger_path, ["HYP-001", "HYP-001"], sources)

    payload = copy.deepcopy(ledger)
    payload["decisions"].append(copy.deepcopy(payload["decisions"][0]))
    payload["decision_count"] = 2
    unsigned = {key: value for key, value in payload.items() if key != "ledger_digest"}
    payload["ledger_digest"] = _digest(unsigned)
    ledger_path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(SDL.SeverityDecisionError, match="duplicate"):
        _reconcile(ledger_path, ["HYP-001"], sources)


def test_stale_run_and_source_authority_are_rejected(tmp_path: Path) -> None:
    ledger_path, _, sources = _ledger(tmp_path, ["HYP-001"])

    with pytest.raises(SDL.SeverityDecisionError, match="run"):
        _reconcile(
            ledger_path,
            ["HYP-001"],
            sources,
            run_id="stale-run",
        )
    with pytest.raises(SDL.SeverityDecisionError, match="source"):
        _reconcile(
            ledger_path,
            ["HYP-001"],
            {"HYP-001": "f" * 64},
        )


def test_empty_denominator_is_explicit_not_vacuously_report_authoritative(
    tmp_path: Path,
) -> None:
    ledger_path, ledger, sources = _ledger(tmp_path, [])

    receipt = _reconcile(ledger_path, [], sources)

    assert receipt["expected_candidate_ids"] == []
    assert receipt["severity_ledger_digest"] == ledger["ledger_digest"]
    assert receipt["denominator_status"] == "EMPTY"
    assert receipt["missing_candidate_ids"] == []
    assert receipt["extra_candidate_ids"] == []
    assert receipt["invalid_candidate_ids"] == []
    assert receipt["challenged_candidate_ids"] == []
    assert receipt["authority_status"] == "EMPTY_DENOMINATOR"


def test_receipt_write_load_is_byte_idempotent_and_semantically_reconciled(
    tmp_path: Path,
) -> None:
    ledger_path, _, sources = _ledger(tmp_path, ["HYP-001"])
    receipt = _reconcile(ledger_path, ["HYP-001"], sources)
    path = tmp_path / "severity_ledger_coverage_receipt.json"

    first = _write_receipt(path, receipt)
    first_bytes = path.read_bytes()
    first_mtime = path.stat().st_mtime_ns
    second = _write_receipt(path, receipt)

    assert first == second == receipt
    assert path.read_bytes() == first_bytes
    assert path.stat().st_mtime_ns == first_mtime
    assert _load_receipt(path, ledger_path, ["HYP-001"], sources) == receipt


def test_loader_rejects_stale_queue_source_and_ledger_bindings(tmp_path: Path) -> None:
    ledger_path, _, sources = _ledger(tmp_path, ["HYP-001"])
    receipt = _reconcile(ledger_path, ["HYP-001"], sources)
    path = tmp_path / "severity_ledger_coverage_receipt.json"
    _write_receipt(path, receipt)

    with pytest.raises(SDL.SeverityDecisionError, match="queue"):
        _load_receipt(
            path,
            ledger_path,
            ["HYP-001"],
            sources,
            queue_digest="6" * 64,
        )
    with pytest.raises(SDL.SeverityDecisionError, match="source"):
        _load_receipt(
            path,
            ledger_path,
            ["HYP-001"],
            {"HYP-001": "f" * 64},
        )

    # The receipt cannot survive a same-run ledger replacement.
    SDL.write_severity_decision_ledger(
        ledger_path, RUN_ID, [_decision("HYP-001"), _decision("HYP-002")]
    )
    with pytest.raises(SDL.SeverityDecisionError, match="ledger"):
        _load_receipt(path, ledger_path, ["HYP-001"], sources)


def test_rehashed_partial_receipt_cannot_self_claim_report_authority(
    tmp_path: Path,
) -> None:
    ledger_path, _, _ = _ledger(tmp_path, ["HYP-001"])
    expected_ids = ["HYP-001", "HYP-002"]
    expected_sources = {
        candidate: _source_digest(candidate) for candidate in expected_ids
    }
    receipt = _reconcile(ledger_path, expected_ids, expected_sources)
    assert receipt["missing_candidate_ids"] == ["HYP-002"]
    forged = {**receipt, "authority_status": "REPORT_AUTHORITATIVE"}
    unsigned = {key: value for key, value in forged.items() if key != "receipt_digest"}
    forged["receipt_digest"] = _digest(unsigned)
    path = tmp_path / "severity_ledger_coverage_receipt.json"

    with pytest.raises(SDL.SeverityDecisionError, match="authority|incomplete"):
        _write_receipt(path, forged)

    path.write_text(json.dumps(forged), encoding="utf-8")

    with pytest.raises(SDL.SeverityDecisionError, match="authority|reconciliation"):
        _load_receipt(
            path,
            ledger_path,
            expected_ids,
            expected_sources,
        )


def test_rehashed_outer_ledger_cannot_upgrade_unattested_row_authority(
    tmp_path: Path,
) -> None:
    """Coverage derives row authority instead of trusting the outer status."""

    candidate_id = "HYP-FORGED-LEDGER-AUTHORITY"
    row = copy.deepcopy(_decision(candidate_id))
    row["assessment"]["producer_authority_binding"] = {
        "status": "UNBOUND",
        "receipt": None,
        "receipt_digest": None,
    }
    row["decision_digest"] = _digest(
        {key: value for key, value in row.items() if key != "decision_digest"}
    )
    ledger_path = tmp_path / "severity_decision_ledger.json"
    ledger = SDL.write_severity_decision_ledger(ledger_path, RUN_ID, [row])
    assert ledger["authority_status"] == "UNATTESTED_COMPATIBILITY"

    forged = copy.deepcopy(ledger)
    forged["authority_status"] = "REPORT_AUTHORITATIVE"
    forged["ledger_digest"] = _digest(
        {key: value for key, value in forged.items() if key != "ledger_digest"}
    )
    ledger_path.write_text(json.dumps(forged), encoding="utf-8")

    with pytest.raises(SDL.SeverityDecisionError, match="authority status mismatch"):
        _reconcile(
            ledger_path,
            [candidate_id],
            {candidate_id: _source_digest(candidate_id)},
        )
