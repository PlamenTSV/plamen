from __future__ import annotations

import pytest

import claude_runtime_materialization as runtime
import test_claude_runtime_materialization_p0_am as legacy


def test_public_materialization_sink_rejects_unbound_provider_parent(
    tmp_path,
) -> None:
    """Raw-host fixture authority must never cross the production sink."""

    request = legacy._request(
        legacy._kwargs(
            tmp_path=tmp_path,
            attempt_id="provider-r5-unbound-public-sink",
        )
    )

    materialized = None
    try:
        materialized = runtime.materialize_claude_runtime(request)
    except runtime.ClaudeRuntimeMaterializationError as exc:
        assert exc.reason_code == "RUNTIME_PROVIDER_PARENT_REQUIRED"
        discard = request.discard()
        assert discard["discarded"] is True
        assert discard["credential_values_recorded"] is False
        assert discard["credential_content_hashes_recorded"] is False
        assert discard["host_paths_recorded"] is False
    else:
        materialized.abort_before_process_scope(
            "PROVIDER_R5_RED_FIXTURE_CLEANUP"
        )
        pytest.fail(
            "production materialization accepted an unbound provider parent"
        )
