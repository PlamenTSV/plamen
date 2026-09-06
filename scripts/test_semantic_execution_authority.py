from __future__ import annotations

from dataclasses import replace

import pytest

from semantic_prompt_snapshot import (
    PromptSnapshotError,
    SemanticPlanPromptBundle,
    SemanticSnapshotTransportBundle,
    TransportOverlay,
    methodology_bundle_digest,
    obligation_bundle_digest,
    output_contract_digest,
    semantic_input_manifest_digest,
)
from semantic_work_plan import (
    BackendArmExecutionIdentity,
    ExecutionAttemptIdentity,
    SemanticAttemptBundle,
    SemanticExecutionBundle,
    SemanticSchemaError,
)
from test_semantic_work_plan import _plan
from test_semantic_prompt_snapshot import _snapshot


def _digest(number: int) -> str:
    return format(number, "064x")


def _execution():
    plan = _plan(denominator=1)
    execution = BackendArmExecutionIdentity.bind(
        plan,
        backend_arm_id="claude.primary",
        backend="claude",
        execution_generation=1,
        exact_model_id="frontier-reasoning-v1",
        model_capability_tier=plan.model_capability_tier,
        capability_receipt_digest=_digest(51),
    )
    return plan, execution


def test_execution_requires_the_exact_semantic_plan() -> None:
    plan, execution = _execution()
    assert SemanticExecutionBundle(plan=plan, execution=execution).execution
    with pytest.raises(SemanticSchemaError, match="semantic_digest"):
        SemanticExecutionBundle(
            plan=replace(plan, obligation_bundle_digest=_digest(52)),
            execution=execution,
        )


def test_attempt_is_bounded_by_plan_retry_authority() -> None:
    plan, execution = _execution()
    second = ExecutionAttemptIdentity.bind(
        execution,
        plan=plan,
        attempt_number=2,
    )
    bundle = SemanticExecutionBundle(plan=plan, execution=execution)
    assert SemanticAttemptBundle(bundle, second).attempt == second
    with pytest.raises(SemanticSchemaError, match="max_attempts"):
        ExecutionAttemptIdentity.bind(
            execution,
            plan=plan,
            attempt_number=3,
        )
    forged = replace(second, attempt_number=3)
    with pytest.raises(SemanticSchemaError, match="max_attempts"):
        SemanticAttemptBundle(bundle, forged)


def test_transport_overlay_requires_the_exact_snapshot() -> None:
    snapshot = _snapshot()
    plan = _plan(denominator=1)
    plan = replace(
        plan,
        methodology_bundle_digest=methodology_bundle_digest(
            snapshot.methodology_files
        ),
        obligation_bundle_digest=obligation_bundle_digest(
            snapshot.obligation_ids
        ),
        semantic_input_manifest_digest=semantic_input_manifest_digest(
            snapshot.logical_input_uris
        ),
        output_contract_digest=output_contract_digest(
            logical_output_uris=snapshot.logical_output_uris,
            output_schema=snapshot.output_schema,
            completion_language=snapshot.completion_language,
        ),
        semantic_prompt_snapshot_digest=snapshot.snapshot_digest,
    )
    bound = SemanticPlanPromptBundle(plan=plan, snapshot=snapshot)
    overlay = TransportOverlay.create(
        snapshot_digest=snapshot.snapshot_digest,
        adapter_id="provider.transport.v1",
        stdin_mode="PROMPT_UTF8",
        stream_format="JSONL",
        completion_framing="STREAM_EVENT_OBSERVATION",
    )
    assert SemanticSnapshotTransportBundle(bound, overlay).overlay == overlay
    with pytest.raises(PromptSnapshotError, match="does not match"):
        SemanticSnapshotTransportBundle(
            bound,
            replace(overlay, snapshot_digest=_digest(53)),
        )


def test_transport_rejects_shape_valid_but_unbound_snapshot() -> None:
    snapshot = _snapshot()
    forged = replace(snapshot, compiler_code_digest=_digest(54))
    overlay = TransportOverlay.create(
        snapshot_digest=forged.snapshot_digest,
        adapter_id="provider.transport.v1",
        stdin_mode="PROMPT_UTF8",
        stream_format="JSONL",
        completion_framing="STREAM_EVENT_OBSERVATION",
    )
    with pytest.raises(PromptSnapshotError, match="plan_prompt_bundle"):
        SemanticSnapshotTransportBundle(  # type: ignore[arg-type]
            forged,
            overlay,
        )


@pytest.mark.parametrize(
    "semantic_text",
    (
        "Use GPT-5.6 with --model frontier.",
        "Use DeepSeek on Bedrock.",
        "Invoke Qwen through its provider adapter.",
        "Read C:/Users/alice/private/settings.json.",
        "Call shell_command for the assigned output.",
        "Load ~/.codex/config.toml.",
        "Use ChatGPT and wait for session framing.",
        "Read /root/private/input then invoke Bash.",
    ),
)
def test_semantic_prompt_rejects_provider_transport_and_host_language(
    semantic_text: str,
) -> None:
    with pytest.raises(TypeError, match="unexpected keyword"):
        _snapshot(semantic_content=semantic_text)
