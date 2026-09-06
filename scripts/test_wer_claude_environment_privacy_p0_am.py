"""Claude credentials must not become durable hash oracles in WER."""

from __future__ import annotations

import hashlib
import json

import worker_execution_receipts as W


def test_redacted_environment_binding_persists_names_but_no_value_digest() -> None:
    secret = "fixture-oauth-secret-never-persist"
    environment = {
        "CLAUDE_CODE_OAUTH_TOKEN": secret,
        "PATH": "fixture-path",
    }

    normalized, binding = W._environment_binding(
        environment,
        tuple(environment),
        persist_value_digest=False,
    )

    assert normalized == environment
    assert binding["effective_names"] == sorted(environment)
    assert binding["effective_sha256"] is None
    assert binding["value_digest_persisted"] is False
    assert (
        binding["value_authority"]
        == "CLAUDE_CHILD_ENVIRONMENT_IN_MEMORY_REPLAY"
    )
    serialized = json.dumps(binding, sort_keys=True)
    assert secret not in serialized
    assert hashlib.sha256(secret.encode()).hexdigest() not in serialized


def test_default_environment_binding_retains_legacy_exact_value_digest() -> None:
    _normalized, binding = W._environment_binding(
        {"PATH": "fixture-path"},
        ("PATH",),
    )
    assert isinstance(binding["effective_sha256"], str)
    assert len(binding["effective_sha256"]) == 64
    assert binding["value_digest_persisted"] is True
    assert binding["value_authority"] == "DURABLE_EFFECTIVE_VALUE_SHA256"
