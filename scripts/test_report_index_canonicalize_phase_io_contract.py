"""Focused PhaseIO fixtures for the atomic report-index canonical successor."""
from __future__ import annotations

import pytest

from phase_io_contracts import (
    canonical_work_unit_key,
    registered_projection_handoff,
    resolve_phase_io_contract,
)


BASE = {
    "pipeline": "sc",
    "mode": "thorough",
    "ecosystem": "evm",
    "backend": "claude",
    "phase": "report_index",
}

SC_OUTPUTS = {
    "scratchpad:report_index.md",
    "scratchpad:report_coverage.md",
    "scratchpad:report_index_status_projection.json",
    "scratchpad:_severity_override_ledger.json",
    "scratchpad:severity_overrides.md",
    "scratchpad:report_dropout_retention.json",
    "scratchpad:report_semantic_report_dropouts.md",
    "scratchpad:report_index_canonicalization_journal.json",
    "scratchpad:report_index_canonicalization_receipt.json",
}


def _resolve(**changes):
    return resolve_phase_io_contract(
        **{**BASE, "work_unit_id": "canonicalize", **changes}
    )


def test_canonical_successor_owns_one_complete_driver_bundle():
    contract = _resolve()

    assert {item.identity for item in contract.outputs} == SC_OUTPUTS
    assert contract.model_invoked is False
    assert {item.writer for item in contract.outputs} == {"DRIVER"}
    assert {item.write_mode for item in contract.outputs} == {"REPLACE"}


def test_l1_canonical_successor_adds_typed_report_records():
    contract = _resolve(pipeline="l1", ecosystem="rust")

    assert {item.identity for item in contract.outputs} == {
        *SC_OUTPUTS,
        "scratchpad:report_records.json",
    }
    assert (
        contract.output("scratchpad:report_records.json").minimum_gate
        == "EXACT_L1_REPORT_RECORD_DENOMINATOR_PARITY"
    )


def test_canonical_successor_binds_only_caller_enumerated_semantic_inputs():
    exact_inputs = (
        "verification_queue.work_items.json",
        "post_verify_candidate_delta.json",
        "report_disposition_authority.json",
    )
    contract = _resolve(exact_inputs=exact_inputs)

    assert set(contract.immutable_inputs) == {
        f"scratchpad:{path}" for path in exact_inputs
    }
    assert "scratchpad:finding_mapping.md" not in contract.immutable_inputs
    assert "scratchpad:dedup_decisions.md" not in contract.immutable_inputs


def test_canonical_retry_has_attempt_scoped_receipt_and_stable_bundle():
    contract = _resolve(work_unit_id="canonicalize.attempt-0002")
    identities = {item.identity for item in contract.outputs}

    assert "scratchpad:report_index_canonicalization_receipt.json" not in identities
    assert (
        "scratchpad:report_index_canonicalization_receipt.attempt-0002.json"
        in identities
    )
    assert identities - {
        "scratchpad:report_index_canonicalization_receipt.attempt-0002.json"
    } == SC_OUTPUTS - {
        "scratchpad:report_index_canonicalization_receipt.json"
    }
    with pytest.raises(ValueError, match="ordinal must be >= 2"):
        _resolve(work_unit_id="canonicalize.attempt-0001")


def test_canonical_successor_rejects_denominator_and_output_drift():
    with pytest.raises(ValueError, match="duplicate semantic inputs"):
        _resolve(exact_inputs=("typed.json", "typed.json"))
    with pytest.raises(ValueError, match="registered output prestates"):
        _resolve(exact_inputs=("report_index.md",))
    with pytest.raises(ValueError, match="registered exact output denominator"):
        _resolve(exact_outputs=("report_index.md",))


@pytest.mark.parametrize(
    ("predecessor_unit", "artifact"),
    (
        ("model", "report_index.md"),
        ("model.attempt-0002", "report_coverage.md"),
        ("mechanical", "report_records.json"),
        ("summary_parity", "report_index.md"),
        ("canonicalize", "report_index_status_projection.json"),
        ("canonicalize.attempt-0002", "severity_overrides.md"),
    ),
)
def test_canonical_successor_handoffs_are_exactly_registered(
    predecessor_unit: str,
    artifact: str,
):
    predecessor = canonical_work_unit_key(
        "sc",
        "thorough",
        "evm",
        "claude",
        "report_index",
        predecessor_unit,
    )
    successor = canonical_work_unit_key(
        "sc",
        "thorough",
        "evm",
        "claude",
        "report_index",
        (
            "canonicalize.attempt-0002"
            if predecessor_unit.startswith("canonicalize")
            else "canonicalize"
        ),
    )

    assert registered_projection_handoff(
        predecessor,
        successor,
        f"scratchpad:{artifact}",
    )
