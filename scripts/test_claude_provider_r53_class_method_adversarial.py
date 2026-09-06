from __future__ import annotations

import pytest

import claude_runtime_materialization as M
from test_claude_provider_r5_parent_toctou_adversarial import (
    _legitimate_request,
)


def test_runtime_cannot_skip_exact_replay_host_consumption_via_class_patch(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    request = _legitimate_request(monkeypatch, tmp_path)
    parent_slot = (
        "_ClaudeRuntimeMaterializationRequest"
        "__provider_runtime_parent"
    )
    replay_host = getattr(request, parent_slot)[1]
    original_claim = M.ClaudeRuntimeHostInputs._claim
    patched_calls: list[object] = []

    def skip_host_consumption(self):
        patched_calls.append(self)
        return {}

    monkeypatch.setattr(
        M.ClaudeRuntimeHostInputs,
        "_claim",
        skip_host_consumption,
    )
    materialized = None
    failure = None
    try:
        materialized = M.materialize_claude_runtime(request)
    except M.ClaudeRuntimeMaterializationError as exc:
        failure = exc
    finally:
        monkeypatch.setattr(
            M.ClaudeRuntimeHostInputs,
            "_claim",
            original_claim,
        )

    host_retry_succeeded = False
    try:
        original_claim(replay_host)
        host_retry_succeeded = True
    except M.ClaudeRuntimeMaterializationError:
        pass
    finally:
        if materialized is not None:
            materialized.abort_before_process_scope(
                "R53_CLASS_METHOD_RED_CLEANUP"
            )

    assert patched_calls == [replay_host]
    assert failure is not None and host_retry_succeeded is False, (
        "replay-host class patch bypassed exact consumption: "
        f"materialized={materialized is not None}, "
        f"host_retry_succeeded={host_retry_succeeded}"
    )
