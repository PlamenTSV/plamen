from __future__ import annotations

import pytest

import claude_runtime_materialization as M
from test_claude_provider_r5_parent_toctou_adversarial import (
    _legitimate_request,
)


def test_public_claim_precleared_slot_terminally_retires_canonical_host(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    request = _legitimate_request(monkeypatch, tmp_path)
    parent_slot = (
        "_ClaudeRuntimeMaterializationRequest"
        "__provider_runtime_parent"
    )
    canonical_parent = getattr(request, parent_slot)
    canonical_host = canonical_parent[1]

    object.__setattr__(request, parent_slot, None)

    with pytest.raises(M.ClaudeRuntimeMaterializationError):
        M.materialize_claude_runtime(request)

    host_retry_succeeded = False
    try:
        canonical_host._claim()
        host_retry_succeeded = True
    except M.ClaudeRuntimeMaterializationError:
        pass

    assert host_retry_succeeded is False, (
        "pre-clearing the mutable request-parent slot bypassed terminal "
        "retirement of the issuance-ledger canonical host"
    )
