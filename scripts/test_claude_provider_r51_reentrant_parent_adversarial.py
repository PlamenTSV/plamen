from __future__ import annotations

import threading

import pytest

import claude_runtime_materialization as M
from test_claude_provider_r5_parent_toctou_adversarial import (
    _legitimate_request,
)


@pytest.mark.parametrize("operation", ("claim", "discard"))
def test_reentrant_parent_identity_fails_closed_without_deadlock(
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
    expected_preparation = legitimate_parent[0].preparation_sha256

    class ReentrantParentIdentity:
        entered = False

        @property
        def preparation_sha256(self) -> str:
            if not self.entered:
                self.entered = True
                try:
                    if operation == "claim":
                        request._claim(require_provider_parent=True)
                    else:
                        request.discard()
                except M.ClaudeRuntimeMaterializationError:
                    pass
            return expected_preparation

    probe = ReentrantParentIdentity()
    object.__setattr__(
        request,
        slot,
        (
            probe,
            legitimate_parent[1],
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
        f"{operation} did not terminate after reflected parent substitution"
    )
    assert len(result) == 1
    assert isinstance(result[0], M.ClaudeRuntimeMaterializationError)
    assert probe.entered is False, (
        "attacker-supplied provider-parent identity property was invoked"
    )
    with pytest.raises(M.ClaudeRuntimeMaterializationError):
        legitimate_parent[1]._claim()
