"""Resolver boundaries for initial severity decisions, not execution proof."""
from __future__ import annotations

import pytest

from phase_io_contracts import resolve_phase_io_contract


QUEUE = (
    "verification_queue.md", "verification_queue.work_items.json",
    "verification_queue.work_plan.json", "verification_runtime_roster.json",
)
INITIAL = "_severity_adjudication_inputs/source_ledger.initial.json"
SOURCE_OUTPUTS = ("severity_decision_ledger.shadow.json", INITIAL)


def _resolve(*, pipeline="sc", outputs=None, inputs=None):
    return resolve_phase_io_contract(
        pipeline=pipeline, mode="core", ecosystem="evm" if pipeline == "sc" else "rust",
        backend="codex", phase="severity_adjudication_shadow",
        work_unit_id="source_decisions.verifier-unit-0001",
        exact_inputs=inputs if inputs is not None else (
            *QUEUE, "verify_H-1.md", "verify_H-1.severity_proposal.json",
            "verify_H-1.receipt.json",
        ),
        exact_outputs=outputs if outputs is not None else (
            "verify_H-1.severity_decision.json",
        ),
        exact_writer="DRIVER",
    )


@pytest.mark.parametrize("pipeline", ("sc", "l1"))
def test_initial_source_declares_only_driver_owned_decisions(pipeline):
    contract = _resolve(pipeline=pipeline)
    assert contract.model_invoked is False
    assert len(contract.outputs) == 1
    output = contract.outputs[0]
    assert output.writer == "DRIVER"
    assert output.identity == "scratchpad:verify_H-1.severity_decision.json"
    assert output.schema_version == "plamen.severity_decision.v1"
    assert set(contract.immutable_inputs) == {
        f"scratchpad:{name}" for name in (
            *QUEUE, "verify_H-1.md", "verify_H-1.severity_proposal.json",
            "verify_H-1.receipt.json",
        )
    }


@pytest.mark.parametrize("outputs", (
    (), ("severity_decision_ledger.shadow.json",),
    ("verify_H-1.md",), ("verify_../H.severity_decision.json",),
    ("verify_H-1.severity_decision.json", "verify_h-1.severity_decision.json"),
))
def test_source_output_denominator_rejects_aggregate_aliases_and_nondecisions(outputs):
    with pytest.raises(ValueError):
        _resolve(outputs=outputs)


@pytest.mark.parametrize("missing", (
    *QUEUE, "verify_H-1.md", "verify_H-1.severity_proposal.json",
    "verify_H-1.receipt.json",
))
def test_source_requires_every_queue_and_verifier_input(missing):
    inputs = (
        *QUEUE, "verify_H-1.md", "verify_H-1.severity_proposal.json",
        "verify_H-1.receipt.json",
    )
    with pytest.raises(ValueError):
        _resolve(inputs=tuple(name for name in inputs if name != missing))


def _aggregate(*, pipeline="sc", inputs=None, outputs=None):
    return resolve_phase_io_contract(
        pipeline=pipeline, mode="thorough", ecosystem="evm" if pipeline == "sc" else "rust",
        backend="codex", phase="severity_adjudication_shadow",
        work_unit_id="source_aggregate", exact_writer="DRIVER",
        exact_inputs=inputs if inputs is not None else (
            *QUEUE, "verify_H-1.severity_decision.json", "verify_H-2.severity_decision.json",
        ),
        exact_outputs=outputs if outputs is not None else SOURCE_OUTPUTS,
    )


@pytest.mark.parametrize("pipeline", ("sc", "l1"))
def test_aggregate_owns_canonical_ledger_and_immutable_initial_copy(pipeline):
    contract = _aggregate(pipeline=pipeline)
    assert contract.model_invoked is False
    assert len(contract.outputs) == 2
    assert all(output.writer == "DRIVER" for output in contract.outputs)
    assert {output.identity for output in contract.outputs} == {
        f"scratchpad:{name}" for name in SOURCE_OUTPUTS
    }
    assert len(contract.immutable_inputs) == 6


@pytest.mark.parametrize("inputs", (
    QUEUE,
    (*QUEUE, "verify_H-1.md"),
    (*QUEUE, "verify_../H-1.severity_decision.json"),
    (*QUEUE, "verify_H-1.severity_decision.json", "verify_h-1.severity_decision.json"),
    (*QUEUE, "verify_H-1.severity_decision.json", "verify_H-1.severity_decision.json"),
    *((*(name for name in QUEUE if name != missing), "verify_H-1.severity_decision.json")
      for missing in QUEUE),
))
def test_aggregate_rejects_missing_queue_and_invalid_decision_denominator(inputs):
    with pytest.raises(ValueError):
        _aggregate(inputs=inputs)


def test_aggregate_default_output_is_registered_ledger():
    assert _aggregate(outputs=()).outputs == _aggregate().outputs


@pytest.mark.parametrize("outputs", (
    ("verify_H-1.severity_decision.json",),
    ("severity_decision_ledger.shadow.json",),
    (*SOURCE_OUTPUTS, "extra.json"),
))
def test_aggregate_rejects_noncanonical_output_set(outputs):
    with pytest.raises(ValueError):
        _aggregate(outputs=outputs)


@pytest.mark.parametrize("pipeline", ("sc", "l1"))
def test_empty_source_and_planning_capture_share_initial_snapshot(pipeline):
    ecosystem = "evm" if pipeline == "sc" else "rust"
    common = dict(
        pipeline=pipeline, mode="core", ecosystem=ecosystem,
        backend="codex", phase="severity_adjudication_shadow",
        exact_writer="DRIVER",
    )
    source = resolve_phase_io_contract(
        **common, work_unit_id="source_empty",
        exact_inputs=QUEUE[:3], exact_outputs=SOURCE_OUTPUTS,
    )
    capture = resolve_phase_io_contract(
        **common, work_unit_id="planning_inputs",
        exact_inputs=(INITIAL,), exact_outputs=(),
    )
    assert {row.identity for row in source.outputs} == {
        f"scratchpad:{name}" for name in SOURCE_OUTPUTS
    }
    assert capture.immutable_inputs == (f"scratchpad:{INITIAL}",)


@pytest.mark.parametrize("pipeline", ("sc", "l1"))
def test_planning_rejects_mutable_ledger_and_requires_complete_shard_sets(pipeline):
    prefix = "_severity_adjudication_inputs/"
    selected = "report-template.md" if pipeline == "sc" else "l1-severity-matrix.md"
    exact_inputs = (
        INITIAL, prefix + "audit_snapshot.json", prefix + "audit_config.json",
        prefix + "finding-output-format.md", prefix + "poc-execution.md",
        prefix + selected,
    )
    exact_outputs = (
        "severity_adjudication_work_manifest.json",
        "severity_adjudication_work_plan.json",
        "severity_adjudication_context.0001.json",
        "severity_adjudication_prompt.0001.md",
        "severity_adjudication_launch_intent.0001.json",
        "severity_adjudication_tool_policy.0001.json",
    )
    contract = resolve_phase_io_contract(
        pipeline=pipeline, mode="core",
        ecosystem="evm" if pipeline == "sc" else "rust", backend="codex",
        phase="severity_adjudication_shadow", work_unit_id="planning",
        exact_inputs=exact_inputs, exact_outputs=exact_outputs,
        exact_writer="DRIVER",
    )
    assert set(contract.immutable_inputs) == {
        f"scratchpad:{name}" for name in exact_inputs
    }
    with pytest.raises(ValueError):
        resolve_phase_io_contract(
            pipeline=pipeline, mode="core",
            ecosystem="evm" if pipeline == "sc" else "rust", backend="codex",
            phase="severity_adjudication_shadow", work_unit_id="planning",
            exact_inputs=("severity_decision_ledger.shadow.json", *exact_inputs[1:]),
            exact_outputs=exact_outputs, exact_writer="DRIVER",
        )
    with pytest.raises(ValueError):
        resolve_phase_io_contract(
            pipeline=pipeline, mode="core",
            ecosystem="evm" if pipeline == "sc" else "rust", backend="codex",
            phase="severity_adjudication_shadow", work_unit_id="planning",
            exact_inputs=exact_inputs, exact_outputs=exact_outputs[:-1],
            exact_writer="DRIVER",
        )
