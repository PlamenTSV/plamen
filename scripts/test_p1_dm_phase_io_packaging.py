"""P1-D/P1-M packaging and exact PhaseIO boundary fixtures.

These tests deliberately stop at the contract boundary.  They do not wire the
driver or prompts, but they make the future cutover fail closed if a model can
mutate typed authority sidecars or a DRIVER unit silently changes its input
denominator.
"""
from __future__ import annotations

from pathlib import Path
import subprocess

import pytest

import authentication_role_authority as ARM
from phase_io_contracts import WriteObservation, resolve_phase_io_contract
import semantic_invariant_authority as SINV


BASE = {
    "pipeline": "sc",
    "mode": "thorough",
    "ecosystem": "evm",
    "backend": "claude-pty",
}

SEMANTIC_SOURCE_DENOMINATOR = {
    "scratchpad:_v2_checkpoint.json",
    "scratchpad:_mechanical_graph.json",
    "scratchpad:state_write_map.md",
    "scratchpad:state_variables.md",
}
SEMANTIC_PRE = {
    "scratchpad:semantic_invariant_authority.json",
    "scratchpad:semantic_invariant_worklist.json",
    "scratchpad:semantic_invariant_worklist.md",
}
SEMANTIC_RESULT = {
    "scratchpad:semantic_invariant_application_receipt.json",
    "scratchpad:semantic_invariant_coverage_gaps.md",
}
AUTH_RESULT = {
    "scratchpad:authentication_role_authority.json",
    "scratchpad:arm_before_trust_composition_obligations.json",
    "scratchpad:authentication_external_research_obligations.json",
    "scratchpad:authentication_role_obligations.md",
}


def _resolve(phase: str, work: str, **kwargs: object):
    return resolve_phase_io_contract(
        **BASE,
        phase=phase,
        work_unit_id=work,
        **kwargs,
    )


def test_modules_are_narrowly_allowlisted_and_git_visible() -> None:
    repo = Path(__file__).resolve().parents[1]
    rules = (repo / ".gitignore").read_text(encoding="utf-8")
    for path in (
        "scripts/semantic_invariant_authority.py",
        "scripts/authentication_role_authority.py",
    ):
        assert rules.count(f"!{path}") == 1
        result = subprocess.run(
            ["git", "check-ignore", "-q", path],
            cwd=repo,
            check=False,
        )
        assert result.returncode == 1, f"{path} remains ignored"


def test_semantic_pre_is_exact_driver_only_typed_authority() -> None:
    contract = _resolve("invariants", "semantic_invariants.pre")

    assert contract.model_invoked is False
    assert set(contract.immutable_inputs) == SEMANTIC_SOURCE_DENOMINATOR
    assert {row.identity for row in contract.outputs} == SEMANTIC_PRE
    assert {row.writer for row in contract.outputs} == {"DRIVER"}
    assert {row.artifact_class for row in contract.outputs} == {"DRIVER_GENERATED"}
    assert {row.path: row.schema_version for row in contract.outputs} == {
        "semantic_invariant_authority.json": SINV.AUTHORITY_SCHEMA,
        "semantic_invariant_worklist.json": SINV.WORKLIST_SCHEMA,
        "semantic_invariant_worklist.md": (
            "plamen.semantic_invariant_worklist_projection.v1"
        ),
    }


@pytest.mark.parametrize(
    ("phase", "work", "expected_gate"),
    (
        (
            "invariants",
            "semantic_invariants.post",
            "EXACT_PRODUCER_DELIVERY_ENUMERATE_DIFF_RECONCILIATION",
        ),
        (
            "depth",
            "semantic_invariants.independent_application",
            "DISTINCT_OPERATOR_EXACT_ROW_BINDING_RECONCILIATION",
        ),
    ),
)
def test_semantic_reconciliation_units_are_driver_only_and_exact(
    phase: str, work: str, expected_gate: str,
) -> None:
    contract = _resolve(phase, work)
    expected_inputs = {
        *SEMANTIC_SOURCE_DENOMINATOR,
        *SEMANTIC_PRE,
        "scratchpad:semantic_invariants.md",
    }
    if work.endswith("independent_application"):
        expected_inputs.add(
            "scratchpad:semantic_invariant_independent_application.input.json"
        )

    assert contract.model_invoked is False
    assert set(contract.immutable_inputs) == expected_inputs
    assert {row.identity for row in contract.outputs} == SEMANTIC_RESULT
    assert {row.writer for row in contract.outputs} == {"DRIVER"}
    receipt = contract.output(
        "scratchpad:semantic_invariant_application_receipt.json"
    )
    assert receipt.schema_version == SINV.APPLICATION_RECEIPT_SCHEMA
    assert receipt.minimum_gate == expected_gate


def test_fixed_semantic_denominator_rejects_subset_or_extra_inputs() -> None:
    with pytest.raises(ValueError, match="exact input denominator"):
        _resolve(
            "invariants",
            "semantic_invariants.pre",
            exact_inputs=("_mechanical_graph.json",),
        )

    with pytest.raises(ValueError, match="exact input denominator"):
        _resolve(
            "invariants",
            "worker.semantic_invariants",
            exact_inputs=("semantic_invariant_authority.json",),
        )
    with pytest.raises(ValueError, match="registered exact output denominator"):
        _resolve(
            "invariants",
            "semantic_invariants.pre",
            exact_outputs=("semantic_invariant_authority.json",),
        )
    with pytest.raises(ValueError, match="exact input denominator"):
        _resolve(
            "invariants",
            "semantic_invariants.post",
            exact_inputs=(
                "_v2_checkpoint.json",
                "_mechanical_graph.json",
                "state_write_map.md",
                "state_variables.md",
                "semantic_invariant_authority.json",
                "semantic_invariant_worklist.json",
                "semantic_invariant_worklist.md",
                "semantic_invariants.md",
                "unregistered_input.json",
            ),
        )


def test_semantic_model_consumers_cannot_write_driver_sidecars() -> None:
    producer = _resolve("invariants", "worker.semantic_invariants")
    independent = _resolve("depth", "worker.semantic_invariant_independent")

    assert {row.identity for row in producer.outputs} == {
        "scratchpad:semantic_invariants.md"
    }
    assert SEMANTIC_PRE <= set(producer.immutable_inputs)
    assert {row.identity for row in independent.outputs} == {
        "scratchpad:semantic_invariant_independent_application.input.json"
    }
    assert SEMANTIC_PRE | SEMANTIC_RESULT <= set(independent.immutable_inputs)

    attempted = producer.validate_writes(
        [
            WriteObservation.changed(
                "scratchpad", "semantic_invariant_authority.json"
            )
        ],
        actor="MODEL",
    )
    assert [row.code for row in attempted.violations] == ["IMMUTABLE_INPUT_WRITE"]


def test_authentication_fact_and_composition_are_separate_driver_units() -> None:
    fact = _resolve("depth", "authentication_roles.fact_authority")
    composition = _resolve("depth", "authentication_roles.composition")

    assert fact.model_invoked is False
    assert fact.immutable_inputs == (
        "scratchpad:_v2_checkpoint.json",
        "scratchpad:authentication_role_facts.input.json",
    )
    assert {row.identity for row in fact.outputs} == {
        "scratchpad:authentication_role_authority.json"
    }
    fact_output = fact.outputs[0]
    assert fact_output.writer == "DRIVER"
    assert fact_output.schema_version == ARM.FACT_AUTHORITY_SCHEMA
    assert fact_output.minimum_gate == "EXACT_TYPED_FACT_TRACE_AND_RUN_BINDING"

    assert composition.model_invoked is False
    assert composition.immutable_inputs == (
        "scratchpad:authentication_role_authority.json",
    )
    assert {row.identity for row in composition.outputs} == AUTH_RESULT - {
        "scratchpad:authentication_role_authority.json"
    }
    assert {row.writer for row in composition.outputs} == {"DRIVER"}
    assert {row.path: row.schema_version for row in composition.outputs} == {
        "arm_before_trust_composition_obligations.json": ARM.COMPOSITION_SCHEMA,
        "authentication_external_research_obligations.json": (
            ARM.EXTERNAL_RESEARCH_SCHEMA
        ),
        "authentication_role_obligations.md": (
            "plamen.authentication_role_obligations_projection.v1"
        ),
    }


def test_authentication_model_producer_and_consumer_have_contained_writes() -> None:
    producer = _resolve("depth", "worker.authentication_role_facts")
    consumer = _resolve(
        "chain",
        "worker.arm_before_trust",
        exact_outputs=("arm_before_trust_findings.md",),
    )

    assert {row.identity for row in producer.outputs} == {
        "scratchpad:authentication_role_facts.input.json"
    }
    assert producer.outputs[0].schema_version == ARM.FACT_TRACE_SCHEMA
    assert set(consumer.immutable_inputs) == AUTH_RESULT
    assert {row.identity for row in consumer.outputs} == {
        "scratchpad:arm_before_trust_findings.md"
    }

    observations = [
        WriteObservation.changed("scratchpad", path.split(":", 1)[1])
        for path in sorted(AUTH_RESULT)
    ]
    result = consumer.validate_writes(observations, actor="MODEL")
    assert {row.code for row in result.violations} == {"IMMUTABLE_INPUT_WRITE"}
    assert not result.allowed

    with pytest.raises(ValueError, match="exact input denominator"):
        _resolve(
            "chain",
            "worker.arm_before_trust",
            exact_outputs=("arm_before_trust_findings.md",),
            exact_inputs=("authentication_role_authority.json",),
        )


def test_driver_units_reject_model_writer_override() -> None:
    for phase, work in (
        ("invariants", "semantic_invariants.pre"),
        ("invariants", "semantic_invariants.post"),
        ("depth", "semantic_invariants.independent_application"),
        ("depth", "authentication_roles.fact_authority"),
        ("depth", "authentication_roles.composition"),
    ):
        with pytest.raises(ValueError, match="registered writer authority"):
            _resolve(phase, work, exact_writer="MODEL")
