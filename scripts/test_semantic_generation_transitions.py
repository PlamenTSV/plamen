from __future__ import annotations

from dataclasses import replace
import json

import pytest

from semantic_work_plan import (
    BackendArmExecutionIdentity,
    ExecutionGenerationTransition,
    ExecutionGenerationTransitionAuthority,
    SemanticExecutionBundle,
    SemanticPlanGenerationTransition,
    SemanticPlanGenerationTransitionAuthority,
    SemanticSchemaError,
    fork_backend_generation,
    fork_execution_generation,
)
from test_semantic_work_plan import _plan


def _digest(number: int) -> str:
    return format(number, "064x")


def _execution():
    plan = _plan(denominator=1)
    return BackendArmExecutionIdentity.bind(
        plan,
        backend_arm_id="primary-arm",
        backend="claude",
        execution_generation=1,
        exact_model_id="frontier-reasoning-v1",
        model_capability_tier=plan.model_capability_tier,
        capability_receipt_digest=_digest(70),
    )


def _bundle(execution: BackendArmExecutionIdentity) -> SemanticExecutionBundle:
    return SemanticExecutionBundle(
        plan=_plan(denominator=1),
        execution=execution,
    )


def test_semantic_mutation_requires_the_next_generation() -> None:
    previous = _plan(denominator=1)
    same_generation = replace(
        previous,
        resource_grant_digest=_digest(71),
    )
    with pytest.raises(SemanticSchemaError, match="next semantic_generation"):
        SemanticPlanGenerationTransition.bind(
            previous,
            same_generation,
            trigger_evidence_digest=_digest(72),
            reason_code="RESOURCE_POLICY_CHANGE",
        )
    successor = replace(same_generation, semantic_generation=2)
    transition = SemanticPlanGenerationTransition.bind(
        previous,
        successor,
        trigger_evidence_digest=_digest(72),
        reason_code="RESOURCE_POLICY_CHANGE",
    )
    assert transition.successor_generation == 2
    assert len(transition.transition_digest) == 64
    assert (
        SemanticPlanGenerationTransitionAuthority.from_bytes(
            transition.to_bytes(),
            previous=previous,
            successor=successor,
            expected_trigger_evidence_digest=transition.trigger_evidence_digest,
            expected_reason_code=transition.reason_code,
        ).transition
        == transition
    )


def test_template_change_is_semantic_and_requires_next_generation() -> None:
    previous = _plan(denominator=1)
    native_same_generation = replace(
        previous,
        model_capability_tier="N0_NATIVE_DETERMINISTIC",
        semantic_template_id="BOUND_NATIVE_CAPABILITY_EXECUTION_V1",
    )
    with pytest.raises(SemanticSchemaError, match="next semantic_generation"):
        SemanticPlanGenerationTransition.bind(
            previous,
            native_same_generation,
            trigger_evidence_digest=_digest(93),
            reason_code="SEMANTIC_TEMPLATE_CHANGE",
        )
    successor = replace(native_same_generation, semantic_generation=2)
    assert SemanticPlanGenerationTransition.bind(
        previous,
        successor,
        trigger_evidence_digest=_digest(93),
        reason_code="SEMANTIC_TEMPLATE_CHANGE",
    )


def test_same_backend_model_change_forks_execution_generation() -> None:
    previous = _execution()
    successor = fork_execution_generation(
        previous,
        exact_model_id="frontier-reasoning-v2",
        capability_receipt_digest=_digest(73),
    )
    transition = ExecutionGenerationTransition.bind(
        _bundle(previous),
        _bundle(successor),
        trigger_evidence_digest=_digest(74),
        reason_code="MODEL_POLICY_CHANGE",
    )
    assert successor.backend_arm_id == previous.backend_arm_id
    assert transition.successor_generation == 2
    assert (
        ExecutionGenerationTransitionAuthority.from_bytes(
            transition.to_bytes(),
            previous=_bundle(previous),
            successor=_bundle(successor),
            expected_trigger_evidence_digest=transition.trigger_evidence_digest,
            expected_reason_code=transition.reason_code,
        ).transition
        == transition
    )


def test_backend_switch_requires_new_arm_and_next_generation() -> None:
    previous = _execution()
    successor = fork_backend_generation(
        previous,
        backend_arm_id="comparison-arm",
        backend="codex",
        exact_model_id="frontier-reasoning-v1",
        capability_receipt_digest=_digest(75),
    )
    assert ExecutionGenerationTransition.bind(
        _bundle(previous),
        _bundle(successor),
        trigger_evidence_digest=_digest(76),
        reason_code="BACKEND_SWITCH",
    )
    with pytest.raises(SemanticSchemaError, match="new backend_arm_id"):
        ExecutionGenerationTransition.bind(
            _bundle(previous),
            _bundle(
                replace(
                    successor,
                    backend_arm_id=previous.backend_arm_id,
                )
            ),
            trigger_evidence_digest=_digest(76),
            reason_code="BACKEND_SWITCH",
        )


def test_noop_execution_generation_fork_is_rejected() -> None:
    previous = _execution()
    with pytest.raises(SemanticSchemaError, match="requires a model"):
        fork_execution_generation(
            previous,
            exact_model_id=previous.exact_model_id,
            capability_receipt_digest=previous.capability_receipt_digest,
        )


def test_transition_rejects_semantic_tier_change_and_direct_bad_generation() -> None:
    previous = _execution()
    successor = fork_execution_generation(
        previous,
        exact_model_id="frontier-reasoning-v2",
        capability_receipt_digest=_digest(77),
    )
    with pytest.raises(SemanticSchemaError, match="does not match plan"):
        SemanticExecutionBundle(
            plan=_plan(denominator=1),
            execution=replace(
                successor,
                model_capability_tier="R2_STANDARD_REASONING",
            ),
        )
    with pytest.raises(SemanticSchemaError, match="SemanticExecutionBundle"):
        ExecutionGenerationTransition.bind(  # type: ignore[arg-type]
            previous,
            successor,
            trigger_evidence_digest=_digest(78),
            reason_code="MODEL_POLICY_CHANGE",
        )
    with pytest.raises(SemanticSchemaError, match="immediately follow"):
        ExecutionGenerationTransition(
            previous_execution_work_unit_key=_digest(79),
            successor_execution_work_unit_key=_digest(80),
            previous_generation=9,
            successor_generation=1,
            trigger_evidence_digest=_digest(81),
            reason_code="FORGED",
        )


@pytest.mark.parametrize(
    "transition_factory",
    (
        "semantic",
        "execution",
    ),
)
def test_transition_serialization_rejects_extra_keys_noncanonical_and_bad_digest(
    transition_factory: str,
) -> None:
    if transition_factory == "semantic":
        previous = _plan(denominator=1)
        successor = replace(
            previous,
            semantic_generation=2,
            resource_grant_digest=_digest(82),
        )
        transition = SemanticPlanGenerationTransition.bind(
            previous,
            successor,
            trigger_evidence_digest=_digest(83),
            reason_code="RESOURCE_POLICY_CHANGE",
        )
        decoder = lambda raw: (
            SemanticPlanGenerationTransitionAuthority.from_bytes(
                raw,
                previous=previous,
                successor=successor,
                expected_trigger_evidence_digest=(
                    transition.trigger_evidence_digest
                ),
                expected_reason_code=transition.reason_code,
            )
        )
    else:
        previous_execution = _execution()
        successor_execution = fork_execution_generation(
            previous_execution,
            exact_model_id="frontier-reasoning-v2",
            capability_receipt_digest=_digest(84),
        )
        transition = ExecutionGenerationTransition.bind(
            _bundle(previous_execution),
            _bundle(successor_execution),
            trigger_evidence_digest=_digest(85),
            reason_code="MODEL_POLICY_CHANGE",
        )
        previous_bundle = _bundle(previous_execution)
        successor_bundle = _bundle(successor_execution)
        decoder = lambda raw: (
            ExecutionGenerationTransitionAuthority.from_bytes(
                raw,
                previous=previous_bundle,
                successor=successor_bundle,
                expected_trigger_evidence_digest=(
                    transition.trigger_evidence_digest
                ),
                expected_reason_code=transition.reason_code,
            )
        )

    payload = transition.to_dict()
    payload["unexpected"] = True
    with pytest.raises(SemanticSchemaError, match="unexpected fields"):
        decoder(
            json.dumps(
                payload,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            + b"\n"
        )

    payload = transition.to_dict()
    payload["transition_digest"] = _digest(86)
    with pytest.raises(SemanticSchemaError, match="transition_digest"):
        decoder(
            json.dumps(
                payload,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            + b"\n"
        )

    with pytest.raises(SemanticSchemaError, match="canonical"):
        decoder(
            json.dumps(
                transition.to_dict(),
                sort_keys=False,
                indent=2,
            ).encode("utf-8")
        )


def test_transition_deserialization_cannot_promote_without_exact_parents() -> None:
    previous = _plan(denominator=1)
    successor = replace(
        previous,
        semantic_generation=2,
        resource_grant_digest=_digest(87),
    )
    transition = SemanticPlanGenerationTransition.bind(
        previous,
        successor,
        trigger_evidence_digest=_digest(88),
        reason_code="RESOURCE_POLICY_CHANGE",
    )
    assert not hasattr(SemanticPlanGenerationTransition, "from_bytes")
    forged_successor = replace(
        successor,
        obligation_bundle_digest=_digest(89),
    )
    with pytest.raises(SemanticSchemaError, match="parents"):
        SemanticPlanGenerationTransitionAuthority.from_bytes(
            transition.to_bytes(),
            previous=previous,
            successor=forged_successor,
            expected_trigger_evidence_digest=transition.trigger_evidence_digest,
            expected_reason_code=transition.reason_code,
        )

    previous_execution = _execution()
    successor_execution = fork_execution_generation(
        previous_execution,
        exact_model_id="frontier-reasoning-v2",
        capability_receipt_digest=_digest(90),
    )
    execution_transition = ExecutionGenerationTransition.bind(
        _bundle(previous_execution),
        _bundle(successor_execution),
        trigger_evidence_digest=_digest(91),
        reason_code="MODEL_POLICY_CHANGE",
    )
    assert not hasattr(ExecutionGenerationTransition, "from_bytes")
    forged_execution = replace(
        successor_execution,
        capability_receipt_digest=_digest(92),
    )
    with pytest.raises(SemanticSchemaError, match="parents"):
        ExecutionGenerationTransitionAuthority.from_bytes(
            execution_transition.to_bytes(),
            previous=_bundle(previous_execution),
            successor=_bundle(forged_execution),
            expected_trigger_evidence_digest=(
                execution_transition.trigger_evidence_digest
            ),
            expected_reason_code=execution_transition.reason_code,
        )


def test_transition_authority_requires_separately_trusted_trigger_and_reason() -> None:
    previous = _plan(denominator=1)
    successor = replace(
        previous,
        semantic_generation=2,
        resource_grant_digest=_digest(93),
    )
    trusted_trigger = _digest(94)
    trusted_reason = "RESOURCE_POLICY_CHANGE"
    forged_semantic = SemanticPlanGenerationTransition.bind(
        previous,
        successor,
        trigger_evidence_digest=_digest(95),
        reason_code="TOTALLY_FORGED_REASON",
    )
    with pytest.raises(SemanticSchemaError, match="exact parents"):
        SemanticPlanGenerationTransitionAuthority.from_bytes(
            forged_semantic.to_bytes(),
            previous=previous,
            successor=successor,
            expected_trigger_evidence_digest=trusted_trigger,
            expected_reason_code=trusted_reason,
        )

    previous_execution = _execution()
    successor_execution = fork_execution_generation(
        previous_execution,
        exact_model_id="frontier-reasoning-v2",
        capability_receipt_digest=_digest(96),
    )
    previous_bundle = _bundle(previous_execution)
    successor_bundle = _bundle(successor_execution)
    forged_execution = ExecutionGenerationTransition.bind(
        previous_bundle,
        successor_bundle,
        trigger_evidence_digest=_digest(97),
        reason_code="TOTALLY_FORGED_REASON",
    )
    with pytest.raises(SemanticSchemaError, match="exact parents"):
        ExecutionGenerationTransitionAuthority.from_bytes(
            forged_execution.to_bytes(),
            previous=previous_bundle,
            successor=successor_bundle,
            expected_trigger_evidence_digest=_digest(98),
            expected_reason_code="MODEL_POLICY_CHANGE",
        )
