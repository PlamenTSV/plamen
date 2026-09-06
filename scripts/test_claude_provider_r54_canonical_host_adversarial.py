from __future__ import annotations

import threading

import pytest

import claude_runtime_materialization as M
from test_claude_provider_r5_parent_toctou_adversarial import (
    _legitimate_request,
)


def test_parent_host_substitution_terminalizes_and_retires_original_host(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    request = _legitimate_request(monkeypatch, tmp_path)
    parent_slot = (
        "_ClaudeRuntimeMaterializationRequest"
        "__provider_runtime_parent"
    )
    legitimate_parent = getattr(request, parent_slot)
    legitimate_host = legitimate_parent[1]

    class NoOpReplayHost:
        replayed = False
        retired = False

        def _replay_provider_parent_inputs(self, **kwargs):
            self.replayed = True
            return legitimate_host._replay_provider_parent_inputs(**kwargs)

        def _claim(self):
            self.retired = True
            return {}

    delegate = NoOpReplayHost()
    object.__setattr__(
        request,
        parent_slot,
        (
            legitimate_parent[0],
            delegate,
            legitimate_parent[2],
            legitimate_parent[3],
            legitimate_parent[4],
        ),
    )

    result: list[object] = []

    def invoke_entrypoint() -> None:
        try:
            result.append(M.materialize_claude_runtime(request))
        except BaseException as exc:
            result.append(exc)

    worker = threading.Thread(target=invoke_entrypoint, daemon=True)
    worker.start()
    worker.join(timeout=2.0)

    host_retry_succeeded = False
    try:
        legitimate_host._claim()
        host_retry_succeeded = True
    except M.ClaudeRuntimeMaterializationError:
        pass

    assert worker.is_alive() is False, (
        "materialization did not terminate after reflected parent-host "
        "substitution"
    )
    assert len(result) == 1
    if not isinstance(result[0], BaseException):
        result[0].abort_before_process_scope(
            "R55_CANONICAL_HOST_FIXTURE_CLEANUP"
        )
    assert isinstance(result[0], M.ClaudeRuntimeMaterializationError)
    assert delegate.replayed is False, (
        "attacker-supplied replay host was invoked for canonical replay"
    )
    assert delegate.retired is False, (
        "attacker-supplied replay host was invoked for retirement"
    )
    assert host_retry_succeeded is False, (
        "terminal parent-host substitution left the original "
        "issuance-owned replay host independently claimable"
    )
