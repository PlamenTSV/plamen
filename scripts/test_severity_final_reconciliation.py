"""Resolver/serialization components; real prefix proof stays in binder integration."""
import hashlib
import pytest
from artifact_ledger import (
    ArtifactLedgerError, _canonical_preexecution_authority_extension,
)
from phase_io_contracts import resolve_phase_io_contract
from severity_final_reconciliation import _encoded, _invocation_authority

BASE = (
    "severity_adjudication_work_manifest.json",
    "severity_adjudication_work_plan.json",
    "severity_decision_ledger.shadow.json",
    "_severity_adjudication_inputs/source_ledger.initial.json",
    "verify_H-1.severity_decision.json",
    "verify_H-1.severity_adjudication_proposal.json",
    "verify_H-1.severity_adjudication_receipt.json",
    "severity_adjudication_context.0001.json",
    "severity_adjudication_prompt.0001.md",
    "severity_adjudication_tool_policy.0001.json",
    "severity_adjudication_launch_intent.0001.json",
    "severity_adjudication_worker_run.0001.json",
)
OUT = ("severity_adjudication_work_reconciliation.json",)

def resolve(inputs=BASE, outputs=OUT, writer="DRIVER"):
    return resolve_phase_io_contract(
        pipeline="sc", mode="core", ecosystem="evm", backend="codex",
        phase="severity_adjudication_shadow", work_unit_id="reconcile_final",
        exact_inputs=inputs, exact_outputs=outputs, exact_writer=writer)

def test_exact_driver_create_contract():
    contract = resolve()
    assert not contract.model_invoked
    assert not set(contract.immutable_inputs).intersection(
        row.identity for row in contract.outputs)
    assert [(row.writer, row.write_mode) for row in contract.outputs] == [("DRIVER", "CREATE")]

@pytest.mark.parametrize("missing", (
    "severity_adjudication_work_manifest.json",
    "severity_adjudication_work_plan.json",
    "severity_decision_ledger.shadow.json",
    "_severity_adjudication_inputs/source_ledger.initial.json",
    "verify_H-1.severity_decision.json",
    "verify_H-1.severity_adjudication_proposal.json",
    "verify_H-1.severity_adjudication_receipt.json",
))
def test_missing_denominator_rejects(missing):
    with pytest.raises(ValueError):
        resolve(tuple(name for name in BASE if name != missing))

def test_mixed_candidate_rosters_reject():
    changed = tuple("verify_H-2.severity_adjudication_receipt.json"
        if name == "verify_H-1.severity_adjudication_receipt.json" else name
        for name in BASE)
    with pytest.raises(ValueError): resolve(changed)

@pytest.mark.parametrize("extra", (
    "VERIFY_h-1.severity_decision.json", "foreign.json",
    "severity_adjudication_work_reconciliation.json",
))
def test_collision_foreign_and_output_overlap_reject(extra):
    with pytest.raises(ValueError): resolve((*BASE, extra))

def test_zero_denominator_rejects():
    with pytest.raises(ValueError):
        resolve(("severity_decision_ledger.shadow.json",
                 "severity_adjudication_work_manifest.json",
                 "severity_adjudication_work_plan.json"))

def test_omitted_outputs_resolve_the_registered_fixed_denominator():
    assert resolve(outputs=()).digest == resolve().digest


@pytest.mark.parametrize("outputs,writer", (
    (OUT, "MODEL"), (("foreign.json",), "DRIVER"),
    ((*OUT, *OUT), "DRIVER"),
))
def test_writer_or_output_drift_rejects(outputs, writer):
    with pytest.raises(ValueError): resolve(outputs=outputs, writer=writer)

# Fault/replay tests must use the genuine CompletedSeverityBindPrefix fixture;
# mocking ledger validators would fabricate the authority under test.


@pytest.mark.parametrize("label", ("ascii", "Unicode \u03bb and newline\n"))
def test_final_invocation_uses_actual_ledger_canonical_encoding(label):
    core = {
        "schema": "plamen.final-severity-reconciliation-invocation.v1",
        "run_id": "test-final-invocation",
        "candidate_ids": ["H-1"],
        "label": label,
    }
    invocation = _invocation_authority(core)
    # This is the actual first-arm validator, not a duplicate digest formula.
    replayed, digest = _canonical_preexecution_authority_extension(invocation)
    assert replayed == invocation
    assert digest == invocation["authority_sha256"]
    assert _invocation_authority(dict(reversed(tuple(core.items())))) == invocation
    assert _encoded(core).endswith(b"\n")
    legacy = {**core, "authority_sha256": hashlib.sha256(_encoded(core)).hexdigest()}
    with pytest.raises(ArtifactLedgerError, match="self-digest is invalid"):
        _canonical_preexecution_authority_extension(legacy)
    changed = {**invocation, "candidate_ids": ["H-2"]}
    with pytest.raises(ArtifactLedgerError, match="self-digest is invalid"):
        _canonical_preexecution_authority_extension(changed)
