"""Resolver and exact successor edges for typed severity binds."""
import pytest

from phase_io_contracts import registered_projection_handoff, resolve_phase_io_contract


BASE = (
    "severity_adjudication_work_manifest.json",
    "severity_adjudication_work_plan.json",
    "verify_H-1.severity_adjudication_proposal.json",
    "severity_adjudication_context.0001.json",
    "severity_adjudication_prompt.0001.md",
    "severity_adjudication_tool_policy.0001.json",
    "severity_adjudication_launch_intent.0001.json",
    "severity_adjudication_worker_run.0001.json",
)
OUT = (
    "verify_H-1.severity_adjudication_receipt.json",
    "verify_H-1.severity_decision.json",
    "severity_decision_ledger.shadow.json",
)
PREFIX = "sc/core/evm/codex/"


def _resolve(work="bind.0001.h-1", inputs=BASE, outputs=OUT):
    return resolve_phase_io_contract(
        pipeline="sc", mode="core", ecosystem="evm", backend="codex",
        phase="severity_adjudication_shadow", work_unit_id=work,
        exact_inputs=inputs, exact_outputs=outputs, exact_writer="DRIVER",
    )


def test_bind_contract_has_exact_three_write_modes():
    contract = _resolve()
    assert [(row.path, row.write_mode) for row in contract.outputs] == [
        ("verify_H-1.severity_adjudication_receipt.json", "CREATE"),
        ("verify_H-1.severity_decision.json", "REPLACE"),
        ("severity_decision_ledger.shadow.json", "REPLACE"),
    ]
    assert contract.model_invoked is False
    assert {output.writer for output in contract.outputs} == {"DRIVER"}
    assert not set(contract.immutable_inputs).intersection(
        output.identity for output in contract.outputs
    )


@pytest.mark.parametrize(
    "target",
    (
        "verify_H-1.severity_decision.json",
        "severity_decision_ledger.shadow.json",
    ),
)
def test_bind_rejects_mutable_replacement_target_as_input(target):
    with pytest.raises(ValueError, match="without mutable replacement targets"):
        _resolve(inputs=(*BASE, target))


@pytest.mark.parametrize("work", ("bind.0000.H-1", "bind.1.H-1", "bind.0001.bad_id"))
def test_bind_grammar_is_closed(work):
    with pytest.raises(ValueError):
        _resolve(work=work)


def test_registered_edges_are_narrow_and_ordered():
    bind1 = PREFIX + "severity_adjudication_shadow/bind.0001.h-1"
    bind2 = PREFIX + "severity_adjudication_shadow/bind.0002.h-2"
    source = PREFIX + "severity_adjudication_shadow/source_decisions.verifier-unit-0001"
    aggregate = PREFIX + "severity_adjudication_shadow/source_aggregate"
    decision = "scratchpad:verify_H-1.severity_decision.json"
    ledger = "scratchpad:severity_decision_ledger.shadow.json"
    assert registered_projection_handoff(source, bind1, decision)
    assert registered_projection_handoff(aggregate, bind1, ledger)
    assert registered_projection_handoff(bind1, bind2, ledger)
    assert not registered_projection_handoff(aggregate, bind2, ledger)
    assert not registered_projection_handoff(bind2, bind1, ledger)
    assert not registered_projection_handoff(source, bind1, ledger)
    assert not registered_projection_handoff(
        PREFIX + "severity_adjudication_shadow/source_empty", bind1, ledger
    )


def test_snapshot_is_never_a_bind_output():
    with pytest.raises(ValueError):
        _resolve(outputs=(*OUT, "_severity_adjudication_inputs/source_ledger.initial.json"))
