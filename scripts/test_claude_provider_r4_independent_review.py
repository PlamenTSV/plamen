from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

import pytest

import claude_runtime_materialization as runtime
import test_claude_runtime_materialization_p0_am as legacy


def test_fixture_only_unbound_compiler_cannot_cross_production_sink(
    tmp_path,
) -> None:
    """The frozen R4 downgrade reproducer must now fail closed."""

    request = legacy._request(
        legacy._kwargs(
            tmp_path=tmp_path,
            attempt_id="independent-review-unbound-production-sink",
        )
    )

    parent = getattr(
        request,
        "_ClaudeRuntimeMaterializationRequest__provider_runtime_parent",
    )
    assert parent is None

    with pytest.raises(
        runtime.ClaudeRuntimeMaterializationError,
        match="exact claimed provider runtime is required",
    ) as raised:
        runtime.materialize_claude_runtime(request)
    assert raised.value.reason_code == "RUNTIME_PROVIDER_PARENT_REQUIRED"
    assert request.discard()["discarded"] is True


def test_concurrent_unbound_requests_have_no_materialization_winner(
    tmp_path,
) -> None:
    """Concurrency cannot turn a fixture-only request into authority."""

    request = legacy._request(
        legacy._kwargs(
            tmp_path=tmp_path,
            attempt_id="independent-review-concurrent-request",
        )
    )

    def claim():
        try:
            return runtime.materialize_claude_runtime(request)
        except runtime.ClaudeRuntimeMaterializationError as exc:
            return exc

    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(lambda _: claim(), range(8)))

    winners = [
        value
        for value in results
        if isinstance(value, runtime.ClaudeRuntimeMaterialization)
    ]
    failures = [
        value
        for value in results
        if isinstance(value, runtime.ClaudeRuntimeMaterializationError)
    ]
    assert winners == []
    assert len(failures) == 8
    assert {
        value.reason_code for value in failures
    } == {"RUNTIME_PROVIDER_PARENT_REQUIRED"}
    assert request.discard()["discarded"] is True
