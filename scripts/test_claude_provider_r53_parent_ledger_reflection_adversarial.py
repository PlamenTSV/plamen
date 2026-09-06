from __future__ import annotations

import pytest

import claude_runtime_materialization as M
from test_claude_provider_r5_parent_toctou_adversarial import (
    _legitimate_request,
)


def test_reflection_cannot_rebind_exact_parent_one_shot_ledger(
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

    class DelegatingReplayHost:
        retired = False

        def _replay_provider_parent_inputs(self, **kwargs):
            return legitimate_host._replay_provider_parent_inputs(**kwargs)

        def _claim(self):
            self.retired = True
            return legitimate_host._claim()

    delegate = DelegatingReplayHost()
    substituted_parent = (
        legitimate_parent[0],
        delegate,
        legitimate_parent[2],
        legitimate_parent[3],
        legitimate_parent[4],
    )
    object.__setattr__(request, parent_slot, substituted_parent)

    closure = dict(
        zip(
            M._consume_request_parent.__code__.co_freevars,
            M._consume_request_parent.__closure__ or (),
        )
    )
    ledger = closure["ledger"].cell_contents
    lock = closure["lock"].cell_contents
    with lock:
        current = ledger[request]
        ledger[request] = (*current[:4], substituted_parent)

    materialized = None
    try:
        materialized = M.materialize_claude_runtime(request)
    except M.ClaudeRuntimeMaterializationError:
        return
    finally:
        if materialized is not None:
            materialized.abort_before_process_scope(
                "R53_LEDGER_REFLECTION_RED_CLEANUP"
            )

    pytest.fail(
        "public materialization accepted a reflected one-shot-ledger "
        f"parent rebind; delegate_retired={delegate.retired}"
    )
