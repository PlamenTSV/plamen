from __future__ import annotations

import copy
import hashlib
import json

import pytest

import claude_auth_route as A


def _canonical_digest(value: dict[str, object]) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def _stored_evidence(*, available: bool = True) -> dict[str, object]:
    core: dict[str, object] = {
        "schema": "plamen.claude_stored_subscription_source.v1",
        "store_class": "FILE_BACKED",
        "source_identity": "fixture-profile",
        "source_size": 211,
        "available": available,
        "observation_authority_sha256": "b" * 64,
        "credential_values_recorded": False,
        "credential_content_hashes_recorded": False,
    }
    evidence = {**core, "receipt_sha256": _canonical_digest(core)}
    if not available:
        return evidence
    return A._promote_stored_subscription_source_evidence(
        evidence,
        provider_authority_sha256=core[
            "observation_authority_sha256"
        ],
    )


def _environment() -> dict[str, str]:
    return {
        "PATH": "C:\\tools",
        "ANTHROPIC_API_KEY": "sk-ant-api-secret",
        "ANTHROPIC_AUTH_TOKEN": "bearer-secret",
        "CLAUDE_CODE_OAUTH_TOKEN": "oauth-secret",
        "ANTHROPIC_BASE_URL": "https://proxy.invalid",
        "ANTHROPIC_DEFAULT_OPUS_MODEL": "claude-opus-5",
        "PLAMEN_SCRATCHPAD": "C:\\audit\\.scratchpad",
    }


def _observation(
    environment: dict[str, str],
    *,
    helper: bool = True,
    stored: bool = True,
) -> dict[str, object]:
    settings = {"apiKeyHelper": "fixture-helper"} if helper else {}
    settings_bytes = json.dumps(
        settings,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    settings_authority = None
    helper_authority = None
    if helper:
        settings_core = {
            "schema": "plamen.claude_settings_authority.v1",
            "mode": "BOUND_SETTINGS",
            "settings_sha256": hashlib.sha256(
                settings_bytes
            ).hexdigest(),
            "external_policy_sha256": "a" * 64,
        }
        settings_authority = _canonical_digest(settings_core)
        helper_authority = A.compile_claude_settings_helper_authority(
            settings_bytes=settings_bytes,
            settings_authority={
                **settings_core,
                "authority_sha256": settings_authority,
            },
        )
    return A.observe_claude_auth_sources(
        environment,
        settings=settings,
        settings_authority_sha256=settings_authority,
        stored_subscription_evidence=_stored_evidence(available=stored),
        settings_helper_authority=helper_authority,
    )


def _endpoint(
    route: str,
    *,
    mode: str = "OFFICIAL_DEFAULT",
    environment: dict[str, str] | None = None,
) -> dict[str, object]:
    return A.compile_claude_endpoint_policy(
        desired_route=route,
        endpoint_mode=mode,
        endpoint_environment=environment or {},
    )


@pytest.mark.parametrize(
    ("route", "expected"),
    (
        ("CLOUD_BEDROCK", ("none",)),
        ("CLOUD_VERTEX", ("none",)),
        ("CLOUD_FOUNDRY", ("none",)),
        ("AUTH_TOKEN", ("ANTHROPIC_AUTH_TOKEN",)),
        ("API_KEY", ("ANTHROPIC_API_KEY",)),
        ("API_KEY_HELPER", ("apiKeyHelper",)),
        ("OAUTH_TOKEN", ("none",)),
        ("STORED_SUBSCRIPTION_OAUTH", ("none",)),
    ),
)
def test_2_1_250_auth_init_vocabulary_is_exact(
    route: str,
    expected: tuple[str, ...],
) -> None:
    assert A.expected_init_api_key_sources(
        claude_code_version="2.1.250",
        desired_route=route,
    ) == expected


def test_unknown_future_auth_init_vocabulary_fails_closed() -> None:
    with pytest.raises(A.ClaudeAuthRouteError, match="unsupported"):
        A.expected_init_api_key_sources(
            claude_code_version="2.1.251",
            desired_route="STORED_SUBSCRIPTION_OAUTH",
        )


def test_classifier_uses_observed_sources_without_secret_values() -> None:
    environment = _environment()
    observation = _observation(environment)
    receipt = A.classify_claude_auth_route(
        environment,
        source_observation=observation,
    )

    assert receipt["selected_route"] == "AUTH_TOKEN"
    assert receipt["present_routes"] == [
        "AUTH_TOKEN",
        "API_KEY",
        "API_KEY_HELPER",
        "OAUTH_TOKEN",
        "STORED_SUBSCRIPTION_OAUTH",
    ]
    assert receipt["shadowed_routes"] == [
        "API_KEY",
        "API_KEY_HELPER",
        "OAUTH_TOKEN",
        "STORED_SUBSCRIPTION_OAUTH",
    ]
    serialized = json.dumps(
        {"observation": observation, "route": receipt},
        sort_keys=True,
    )
    assert "fixture-helper" not in serialized
    assert "secret" not in serialized
    assert A.replay_claude_auth_source_observation(observation) == observation
    assert A.replay_claude_auth_route(receipt) == receipt


def test_source_observation_is_bound_to_the_exact_environment_denominator() -> None:
    environment = _environment()
    observation = _observation(environment)
    changed = dict(environment)
    changed["NEW_KEY_AFTER_OBSERVATION"] = "not-secret"
    with pytest.raises(A.ClaudeAuthRouteError, match="observation"):
        A.classify_claude_auth_route(
            changed,
            source_observation=observation,
        )


def test_subscription_environment_removes_every_higher_precedence_route() -> None:
    source = _environment()
    observation = _observation(source)
    child, receipt = A.compile_claude_auth_environment(
        source,
        desired_route="STORED_SUBSCRIPTION_OAUTH",
        source_observation=observation,
        claude_code_version="2.1.220",
        endpoint_policy=_endpoint("STORED_SUBSCRIPTION_OAUTH"),
    )

    assert child == {
        "ANTHROPIC_DEFAULT_OPUS_MODEL": "claude-opus-5",
        "PATH": "C:\\tools",
        "PLAMEN_SCRATCHPAD": "C:\\audit\\.scratchpad",
    }
    assert receipt["selected_route"] == "STORED_SUBSCRIPTION_OAUTH"
    assert receipt["expected_init_api_key_sources"] == ["none"]
    assert receipt["removed_route_sources"] == [
        "ANTHROPIC_API_KEY",
        "ANTHROPIC_AUTH_TOKEN",
        "ANTHROPIC_BASE_URL",
        "CLAUDE_CODE_OAUTH_TOKEN",
        "SETTINGS_API_KEY_HELPER",
    ]
    assert A.replay_claude_auth_environment(receipt) == receipt
    assert (
        A.reconcile_claude_auth_environment(
            child,
            receipt,
            source_observation=observation,
        )
        == receipt
    )
    assert source == _environment()


def test_explicit_api_key_route_preserves_only_that_secret_route() -> None:
    source = _environment()
    observation = _observation(source)
    child, receipt = A.compile_claude_auth_environment(
        source,
        desired_route="API_KEY",
        source_observation=observation,
        claude_code_version="2.1.220",
        endpoint_policy=_endpoint("API_KEY"),
    )

    assert child["ANTHROPIC_API_KEY"] == "sk-ant-api-secret"
    assert "ANTHROPIC_AUTH_TOKEN" not in child
    assert "CLAUDE_CODE_OAUTH_TOKEN" not in child
    assert "ANTHROPIC_BASE_URL" not in child
    assert receipt["selected_route"] == "API_KEY"
    assert receipt["expected_init_api_key_sources"] == ["ANTHROPIC_API_KEY"]
    assert "sk-ant" not in json.dumps(receipt)


def test_selected_oauth_token_survives_default_deny_prefix_filtering() -> None:
    environment = _environment()
    observation = _observation(environment)
    child, receipt = A.compile_claude_auth_environment(
        environment,
        desired_route="OAUTH_TOKEN",
        source_observation=observation,
        claude_code_version="2.1.220",
        endpoint_policy=_endpoint("OAUTH_TOKEN"),
    )
    assert child["CLAUDE_CODE_OAUTH_TOKEN"] == "oauth-secret"
    assert receipt["preserved_route_sources"] == ["CLAUDE_CODE_OAUTH_TOKEN"]


@pytest.mark.parametrize(
    ("route", "environment", "helper", "stored"),
    (
        ("AUTH_TOKEN", {}, False, True),
        ("API_KEY", {}, False, True),
        ("API_KEY_HELPER", {}, False, True),
        ("OAUTH_TOKEN", {}, False, True),
        ("STORED_SUBSCRIPTION_OAUTH", {}, False, False),
    ),
)
def test_requested_unavailable_route_fails_closed(
    route: str,
    environment: dict[str, str],
    helper: bool,
    stored: bool,
) -> None:
    observation = _observation(
        environment,
        helper=helper,
        stored=stored,
    )
    with pytest.raises(A.ClaudeAuthRouteError):
        A.compile_claude_auth_environment(
            environment,
            desired_route=route,
            source_observation=observation,
            claude_code_version="2.1.220",
            endpoint_policy=_endpoint(route),
        )


def test_helper_selected_but_observed_settings_omit_helper_fails() -> None:
    environment: dict[str, str] = {}
    observation = _observation(environment, helper=False, stored=True)
    with pytest.raises(A.ClaudeAuthRouteError, match="unavailable"):
        A.compile_claude_auth_environment(
            environment,
            desired_route="API_KEY_HELPER",
            source_observation=observation,
            claude_code_version="2.1.220",
            endpoint_policy=_endpoint("API_KEY_HELPER"),
        )


def test_conflicting_cloud_provider_selectors_are_ambiguous() -> None:
    environment = {
        "CLAUDE_CODE_USE_BEDROCK": "1",
        "CLAUDE_CODE_USE_VERTEX": "true",
    }
    observation = _observation(environment)
    receipt = A.classify_claude_auth_route(
        environment,
        source_observation=observation,
    )
    assert receipt["selected_route"] == "AMBIGUOUS_CLOUD_PROVIDER"
    with pytest.raises(A.ClaudeAuthRouteError):
        A.compile_claude_auth_environment(
            environment,
            desired_route="CLOUD_BEDROCK",
            source_observation=observation,
            claude_code_version="2.1.220",
            endpoint_policy=_endpoint(
                "CLOUD_BEDROCK",
                mode="CLOUD_PROVIDER",
            ),
        )


@pytest.mark.parametrize(
    ("name", "value"),
    (
        ("CLAUDE_CODE_USE_BEDROCK", "0"),
        ("CLAUDE_CODE_USE_VERTEX", "false"),
        ("CLAUDE_CODE_USE_FOUNDRY", ""),
    ),
)
def test_false_cloud_selector_does_not_override_subscription(
    name: str,
    value: str,
) -> None:
    environment = {name: value}
    receipt = A.classify_claude_auth_route(
        environment,
        source_observation=_observation(
            environment,
            helper=False,
            stored=True,
        ),
    )
    assert receipt["selected_route"] == "STORED_SUBSCRIPTION_OAUTH"


def test_environment_name_case_collision_is_rejected() -> None:
    environment = {
        "ANTHROPIC_API_KEY": "one",
        "anthropic_api_key": "two",
    }
    with pytest.raises(A.ClaudeAuthRouteError, match="case-ambiguous"):
        A.observe_claude_auth_sources(
            environment,
            settings={},
            settings_authority_sha256=None,
            stored_subscription_evidence=_stored_evidence(),
        )


def test_environment_receipt_replay_rejects_any_mutation() -> None:
    environment = _environment()
    observation = _observation(environment)
    _, receipt = A.compile_claude_auth_environment(
        environment,
        desired_route="API_KEY",
        source_observation=observation,
        claude_code_version="2.1.220",
        endpoint_policy=_endpoint("API_KEY"),
    )
    for field, replacement in (
        ("selected_route", "OAUTH_TOKEN"),
        ("child_environment_key_set_sha256", "0" * 64),
        ("expected_init_api_key_sources", ["none"]),
    ):
        changed = copy.deepcopy(receipt)
        changed[field] = replacement
        with pytest.raises(A.ClaudeAuthRouteError):
            A.replay_claude_auth_environment(changed)


def test_route_receipt_replay_rejects_mutation() -> None:
    environment: dict[str, str] = {}
    receipt = A.classify_claude_auth_route(
        environment,
        source_observation=_observation(
            environment,
            helper=False,
            stored=True,
        ),
    )
    changed = copy.deepcopy(receipt)
    changed["selected_route"] = "API_KEY"
    with pytest.raises(A.ClaudeAuthRouteError):
        A.replay_claude_auth_route(changed)

    semantically_forged = copy.deepcopy(receipt)
    semantically_forged["source_names"] = []
    core = dict(semantically_forged)
    core.pop("receipt_sha256")
    semantically_forged["receipt_sha256"] = _canonical_digest(core)
    with pytest.raises(A.ClaudeAuthRouteError):
        A.replay_claude_auth_route(semantically_forged)


def test_route_and_version_map_to_exact_init_api_key_source() -> None:
    assert A.expected_init_api_key_sources(
        claude_code_version="2.1.220",
        desired_route="STORED_SUBSCRIPTION_OAUTH",
    ) == ("none",)
    assert A.expected_init_api_key_sources(
        claude_code_version="2.1.220",
        desired_route="API_KEY",
    ) == ("ANTHROPIC_API_KEY",)
    with pytest.raises(A.ClaudeAuthRouteError, match="unsupported"):
        A.expected_init_api_key_sources(
            claude_code_version="2.1.221",
            desired_route="API_KEY",
        )


def test_custom_endpoint_requires_explicit_non_subscription_policy() -> None:
    endpoint = _endpoint(
        "API_KEY",
        mode="CUSTOM_BASE_URL",
        environment={"ANTHROPIC_BASE_URL": "https://gateway.example.test"},
    )
    environment = {
        "ANTHROPIC_API_KEY": "secret",
        "ANTHROPIC_BASE_URL": "https://ambient.invalid",
    }
    observation = _observation(environment, helper=False, stored=False)
    child, receipt = A.compile_claude_auth_environment(
        environment,
        desired_route="API_KEY",
        source_observation=observation,
        claude_code_version="2.1.220",
        endpoint_policy=endpoint,
    )
    assert child["ANTHROPIC_BASE_URL"] == "https://gateway.example.test"
    assert receipt["endpoint_policy"] == endpoint
    assert "secret" not in json.dumps(receipt, sort_keys=True)


def test_custom_endpoint_is_forbidden_for_subscription_routes() -> None:
    with pytest.raises(A.ClaudeAuthRouteError, match="endpoint"):
        _endpoint(
            "STORED_SUBSCRIPTION_OAUTH",
            mode="CUSTOM_BASE_URL",
            environment={
                "ANTHROPIC_BASE_URL": "https://gateway.example.test"
            },
        )


def test_custom_endpoint_cannot_persist_credentials_in_url_components() -> None:
    for url in (
        "https://user:secret@gateway.example.test",
        "https://gateway.example.test/?token=secret",
        "https://gateway.example.test/secret-path",
    ):
        with pytest.raises(A.ClaudeAuthRouteError, match="credential-free"):
            _endpoint(
                "API_KEY",
                mode="CUSTOM_BASE_URL",
                environment={"ANTHROPIC_BASE_URL": url},
            )


def test_endpoint_drift_fails_environment_reconciliation() -> None:
    endpoint = _endpoint(
        "API_KEY",
        mode="CUSTOM_BASE_URL",
        environment={"ANTHROPIC_BASE_URL": "https://gateway.example.test"},
    )
    environment = {"ANTHROPIC_API_KEY": "secret"}
    observation = _observation(environment, helper=False, stored=False)
    child, receipt = A.compile_claude_auth_environment(
        environment,
        desired_route="API_KEY",
        source_observation=observation,
        claude_code_version="2.1.220",
        endpoint_policy=endpoint,
    )
    child["ANTHROPIC_BASE_URL"] = "https://other.example.test"
    with pytest.raises(A.ClaudeAuthRouteError, match="drift|identity"):
        A.reconcile_claude_auth_environment(
            child,
            receipt,
            source_observation=observation,
        )


def test_cost_field_cannot_change_auth_route() -> None:
    environment = {"ANTHROPIC_API_KEY": "secret"}
    observation = _observation(environment, helper=False, stored=False)
    receipt = A.classify_claude_auth_route(
        environment,
        source_observation=observation,
    )
    assert receipt["selected_route"] == "API_KEY"
    assert "cost" not in json.dumps(receipt, sort_keys=True).casefold()


def test_no_credential_value_or_credential_derived_hash_is_durable() -> None:
    environment = {
        "ANTHROPIC_API_KEY": "unique-secret-credential-value",
    }
    observation = _observation(environment, helper=False, stored=False)
    _, receipt = A.compile_claude_auth_environment(
        environment,
        desired_route="API_KEY",
        source_observation=observation,
        claude_code_version="2.1.220",
        endpoint_policy=_endpoint("API_KEY"),
    )
    serialized = json.dumps(
        {"observation": observation, "environment": receipt},
        sort_keys=True,
    )
    secret_hash = hashlib.sha256(
        environment["ANTHROPIC_API_KEY"].encode("utf-8")
    ).hexdigest()
    assert environment["ANTHROPIC_API_KEY"] not in serialized
    assert secret_hash not in serialized
    assert receipt["credential_content_hashes_recorded"] is False


def test_attempt_independent_route_policy_uses_exact_version_mapping() -> None:
    endpoint = A.compile_claude_endpoint_policy(
        desired_route="API_KEY",
        endpoint_mode="CUSTOM_BASE_URL",
        endpoint_environment={
            "ANTHROPIC_BASE_URL": "https://gateway.example/"
        },
    )
    policy = A.compile_claude_auth_route_policy(
        claude_code_version="2.1.220",
        desired_route="API_KEY",
        endpoint_policy=endpoint,
    )

    assert policy["schema"] == "plamen.claude_auth_route_policy.v1"
    assert policy["expected_init_api_key_sources"] == [
        "ANTHROPIC_API_KEY"
    ]
    assert policy["endpoint_policy"] == endpoint
    assert A.replay_claude_auth_route_policy(policy) == policy

    changed = copy.deepcopy(policy)
    changed["expected_init_api_key_sources"] = ["none"]
    core = dict(changed)
    core.pop("policy_sha256")
    changed["policy_sha256"] = A._digest(core)
    with pytest.raises(A.ClaudeAuthRouteError, match="replay|mapping"):
        A.replay_claude_auth_route_policy(changed)


def test_plain_stored_source_mapping_cannot_grant_availability() -> None:
    with pytest.raises(
        A.ClaudeAuthRouteError,
        match="promoted neutral",
    ):
        A.observe_claude_auth_sources(
            {},
            settings={},
            settings_authority_sha256=None,
            stored_subscription_evidence=dict(
                _stored_evidence(available=True)
            ),
        )


def test_same_name_credential_value_rebinding_is_rejected() -> None:
    source = {"ANTHROPIC_API_KEY": "account-A"}
    observation = A.observe_claude_auth_sources(
        source,
        settings={},
        settings_authority_sha256=None,
        stored_subscription_evidence=_stored_evidence(available=False),
    )
    endpoint = A.compile_claude_endpoint_policy(
        desired_route="API_KEY",
        endpoint_mode="OFFICIAL_DEFAULT",
        endpoint_environment={},
    )

    with pytest.raises(
        A.ClaudeAuthRouteError,
        match="value identity|rebound",
    ):
        A.compile_claude_auth_environment(
            {"ANTHROPIC_API_KEY": "account-B"},
            desired_route="API_KEY",
            source_observation=observation,
            claude_code_version="2.1.220",
            endpoint_policy=endpoint,
        )
