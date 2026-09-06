from __future__ import annotations

import threading

import pytest

import claude_runtime_materialization as M
from test_claude_provider_r5_parent_toctou_adversarial import (
    _legitimate_request,
)


@pytest.mark.parametrize("operation", ("claim", "discard"))
def test_reentrant_replay_host_fails_closed_without_deadlock(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
    operation: str,
) -> None:
    request = _legitimate_request(monkeypatch, tmp_path)
    slot = (
        "_ClaudeRuntimeMaterializationRequest"
        "__provider_runtime_parent"
    )
    legitimate_parent = getattr(request, slot)
    legitimate_host = legitimate_parent[1]

    class ReentrantReplayHost:
        replay_entered = False
        claim_entered = False

        def _replay_provider_parent_inputs(self, **kwargs):
            self.replay_entered = True
            return legitimate_host._replay_provider_parent_inputs(**kwargs)

        def _claim(self):
            self.claim_entered = True
            if operation == "claim":
                request._claim(require_provider_parent=True)
            else:
                request.discard()

    probe = ReentrantReplayHost()
    object.__setattr__(
        request,
        slot,
        (
            legitimate_parent[0],
            probe,
            legitimate_parent[2],
            legitimate_parent[3],
            legitimate_parent[4],
        ),
    )
    result: list[object] = []

    def invoke_entrypoint() -> None:
        try:
            if operation == "claim":
                result.append(M.materialize_claude_runtime(request))
            else:
                result.append(request.discard())
        except BaseException as exc:
            result.append(exc)

    worker = threading.Thread(target=invoke_entrypoint, daemon=True)
    worker.start()
    worker.join(timeout=2.0)

    assert worker.is_alive() is False, (
        f"{operation} did not terminate after replay-host substitution"
    )
    assert len(result) == 1
    assert isinstance(result[0], M.ClaudeRuntimeMaterializationError)
    assert probe.replay_entered is False, (
        "attacker-supplied replay host was invoked for canonical replay"
    )
    assert probe.claim_entered is False, (
        "attacker-supplied replay host was invoked for retirement"
    )
    with pytest.raises(M.ClaudeRuntimeMaterializationError):
        legitimate_host._claim()
