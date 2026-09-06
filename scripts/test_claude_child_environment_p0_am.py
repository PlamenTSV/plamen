from __future__ import annotations

from copy import copy, deepcopy
import hashlib
import json
import pickle

import pytest

import claude_auth_route as A
import claude_child_environment as C


def _required_controls() -> dict[str, str]:
    return {
        "CLAUDE_CODE_DISABLE_OFFICIAL_MARKETPLACE_AUTOINSTALL": "1",
        "CLAUDE_CODE_SUBPROCESS_ENV_SCRUB": "1",
        "DISABLE_AUTOUPDATER": "1",
        "DISABLE_UPDATES": "1",
        "ENABLE_CLAUDEAI_MCP_SERVERS": "false",
    }


def _digest(value: dict[str, object]) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def _stored(*, available: bool) -> dict[str, object]:
    core: dict[str, object] = {
        "schema": "plamen.claude_stored_subscription_source.v1",
        "store_class": "FILE_BACKED",
        "source_identity": "fixture",
        "source_size": 64,
        "available": available,
        "observation_authority_sha256": "7" * 64,
        "credential_values_recorded": False,
        "credential_content_hashes_recorded": False,
    }
    evidence = {**core, "receipt_sha256": _digest(core)}
    if not available:
        return evidence
    return A._promote_stored_subscription_source_evidence(
        evidence,
        provider_authority_sha256=core[
            "observation_authority_sha256"
        ],
    )


def _auth(
    ambient: dict[str, str],
    *,
    route: str = "STORED_SUBSCRIPTION_OAUTH",
) -> tuple[dict[str, str], dict[str, object], dict[str, object]]:
    observation = A.observe_claude_auth_sources(
        ambient,
        settings={},
        settings_authority_sha256=None,
        stored_subscription_evidence=_stored(
            available=route == "STORED_SUBSCRIPTION_OAUTH"
        ),
    )
    endpoint = A.compile_claude_endpoint_policy(
        desired_route=route,
        endpoint_mode="OFFICIAL_DEFAULT",
        endpoint_environment={},
    )
    child, receipt = A.compile_claude_auth_environment(
        ambient,
        desired_route=route,
        source_observation=observation,
        claude_code_version="2.1.220",
        endpoint_policy=endpoint,
    )
    return child, receipt, observation


def test_subscription_child_default_denies_unknown_claude_and_secrets() -> None:
    ambient = {
        "PATH": "C:\\toolchain",
        "HOME": "C:\\Users\\fixture",
        "USERPROFILE": "C:\\Users\\fixture",
        "APPDATA": "C:\\Users\\fixture\\AppData\\Roaming",
        "LOCALAPPDATA": "C:\\Users\\fixture\\AppData\\Local",
        "ANTHROPIC_API_KEY": "ambient-api-secret",
        "CLAUDE_CODE_OAUTH_TOKEN": "ambient-oauth-secret",
        "CLAUDE_CODE_SESSION_ID": "parent-session",
        "CLAUDE_CODE_FUTURE_UNKNOWN": "future-control",
        "GITHUB_TOKEN": "github-secret",
        "AWS_SECRET_ACCESS_KEY": "aws-secret",
        "SSH_AUTH_SOCK": "\\\\.\\pipe\\ssh-agent",
        "ETH_RPC_URL": "https://secret-rpc.invalid",
    }
    auth_environment, auth_receipt, observation = _auth(ambient)

    result = C.compile_claude_child_environment(
        ambient=ambient,
        auth_environment=auth_environment,
        auth_environment_receipt=auth_receipt,
        source_observation=observation,
        attempt_profile_environment={
            "CLAUDE_CONFIG_DIR": "C:\\lease\\claude",
            "CLAUDE_CODE_TMPDIR": "C:\\lease\\tmp",
            "TMP": "C:\\lease\\tmp",
            "TEMP": "C:\\lease\\tmp",
            "TMPDIR": "C:\\lease\\tmp",
        },
        phase_environment_policies=("base",),
        home_variable_policy="PRESERVE_TOOLCHAIN_HOME",
        functional_controls={
            **_required_controls(),
            "CLAUDE_CODE_DISABLE_AUTO_MEMORY": "1",
            "DISABLE_TELEMETRY": "1",
        },
    )

    assert dict(auth_environment) == {}
    assert result.environment["PATH"] == "C:\\toolchain"
    assert result.environment["HOME"] == "C:\\Users\\fixture"
    assert result.environment["USERPROFILE"] == "C:\\Users\\fixture"
    assert result.environment["APPDATA"].endswith("Roaming")
    assert result.environment["LOCALAPPDATA"].endswith("Local")
    assert result.environment["CLAUDE_CONFIG_DIR"] == "C:\\lease\\claude"
    assert result.environment["TMP"] == "C:\\lease\\tmp"
    for denied in (
        "ANTHROPIC_API_KEY",
        "CLAUDE_CODE_OAUTH_TOKEN",
        "CLAUDE_CODE_SESSION_ID",
        "CLAUDE_CODE_FUTURE_UNKNOWN",
        "GITHUB_TOKEN",
        "AWS_SECRET_ACCESS_KEY",
        "SSH_AUTH_SOCK",
        "ETH_RPC_URL",
    ):
        assert denied not in result.environment
    durable = json.dumps(result.receipt, sort_keys=True)
    assert "ambient-api-secret" not in durable
    assert "ambient-oauth-secret" not in durable
    assert not hasattr(result, "in_memory_value_sha256")
    assert result.receipt["configuration_isolation_status"] == (
        "UNVERIFIED_CLAUDE_CONFIG_REDIRECTION"
    )
    assert result.receipt["proof_grade_configuration_isolation"] is False
    assert C.replay_claude_child_environment_receipt(result.receipt) == (
        result.receipt
    )
    assert result.receipt["final_environment_names"] == sorted(
        result.environment,
        key=str.casefold,
    )
    assert (
        C._key_names_digest(result.receipt["final_environment_names"])
        == result.receipt["final_environment_key_set_sha256"]
    )
    planned_names = C.planned_claude_child_environment_names(
        ambient=ambient,
        selected_route="STORED_SUBSCRIPTION_OAUTH",
        endpoint_environment_names=(),
            phase_environment_policies=("base",),
            functional_control_names=tuple(_required_controls()) + (
                "CLAUDE_CODE_DISABLE_AUTO_MEMORY",
                "DISABLE_TELEMETRY",
            ),
        home_variable_policy="PRESERVE_TOOLCHAIN_HOME",
    )
    assert planned_names == tuple(
        sorted(result.environment, key=str.casefold)
    )
    for unselected_or_sensitive_name in (
        "ANTHROPIC_API_KEY",
        "CLAUDE_CODE_OAUTH_TOKEN",
        "GITHUB_TOKEN",
        "AWS_SECRET_ACCESS_KEY",
        "SSH_AUTH_SOCK",
        "ETH_RPC_URL",
    ):
        assert unselected_or_sensitive_name not in planned_names
    assert C.planned_claude_child_environment_key_set_sha256(
        ambient=ambient,
        selected_route="STORED_SUBSCRIPTION_OAUTH",
            endpoint_environment_names=(),
            phase_environment_policies=("base",),
            functional_control_names=tuple(_required_controls()) + (
                "CLAUDE_CODE_DISABLE_AUTO_MEMORY",
                "DISABLE_TELEMETRY",
            ),
        home_variable_policy="PRESERVE_TOOLCHAIN_HOME",
    ) == result.receipt["final_environment_key_set_sha256"]
    C.reconcile_claude_child_environment(result)


def test_selected_oauth_is_readded_after_unknown_prefix_default_deny() -> None:
    ambient = {
        "PATH": "/usr/bin",
        "HOME": "/home/auditor",
        "CLAUDE_CODE_OAUTH_TOKEN": "selected-oauth-secret",
        "CLAUDE_CODE_UNKNOWN": "deny-me",
    }
    auth_environment, auth_receipt, observation = _auth(
        ambient,
        route="OAUTH_TOKEN",
    )
    result = C.compile_claude_child_environment(
        ambient=ambient,
        auth_environment=auth_environment,
        auth_environment_receipt=auth_receipt,
        source_observation=observation,
        attempt_profile_environment={
            "CLAUDE_CONFIG_DIR": "/private/lease/claude",
            "CLAUDE_CODE_TMPDIR": "/private/lease/tmp",
            "TMPDIR": "/private/lease/tmp",
        },
        phase_environment_policies=("base",),
        home_variable_policy="PRESERVE_TOOLCHAIN_HOME",
    )
    assert (
        result.environment["CLAUDE_CODE_OAUTH_TOKEN"]
        == "selected-oauth-secret"
    )
    assert "CLAUDE_CODE_UNKNOWN" not in result.environment
    assert "selected-oauth-secret" not in json.dumps(
        result.receipt,
        sort_keys=True,
    )
    assert hashlib.sha256(b"selected-oauth-secret").hexdigest() not in (
        json.dumps(result.receipt, sort_keys=True)
    )
    assert "selected-oauth-secret" not in repr(result)
    assert not hasattr(result, "in_memory_value_sha256")
    with pytest.raises(TypeError):
        pickle.dumps(result)
    with pytest.raises(TypeError):
        copy(result)
    with pytest.raises(TypeError):
        deepcopy(result)
    with pytest.raises(TypeError):
        json.dumps(result)
    assert C.reconcile_claude_child_environment(result) == result.receipt


def test_named_toolchain_policy_is_explicit_and_exact() -> None:
    ambient = {
        "PATH": "/tools/bin",
        "HOME": "/home/auditor",
        "CARGO_HOME": "/cache/cargo",
        "RUSTUP_HOME": "/cache/rustup",
        "SOLANA_CONFIG_FILE": "/config/solana.yml",
        "NPM_CONFIG_USERCONFIG": "/config/npmrc",
        "GITHUB_TOKEN": "secret",
    }
    auth_environment, auth_receipt, observation = _auth(ambient)
    base = C.compile_claude_child_environment(
        ambient=ambient,
        auth_environment=auth_environment,
        auth_environment_receipt=auth_receipt,
        source_observation=observation,
        attempt_profile_environment={
            "CLAUDE_CONFIG_DIR": "/lease/claude",
            "CLAUDE_CODE_TMPDIR": "/lease/tmp",
        },
        phase_environment_policies=("base",),
        home_variable_policy="PRESERVE_TOOLCHAIN_HOME",
    )
    assert "CARGO_HOME" not in base.environment
    assert "RUSTUP_HOME" not in base.environment
    assert "SOLANA_CONFIG_FILE" not in base.environment
    assert "NPM_CONFIG_USERCONFIG" not in base.environment

    auth_environment, auth_receipt, observation = _auth(ambient)
    solana = C.compile_claude_child_environment(
        ambient=ambient,
        auth_environment=auth_environment,
        auth_environment_receipt=auth_receipt,
        source_observation=observation,
        attempt_profile_environment={
            "CLAUDE_CONFIG_DIR": "/lease/claude",
            "CLAUDE_CODE_TMPDIR": "/lease/tmp",
        },
        phase_environment_policies=("base", "node", "rust", "solana"),
        home_variable_policy="PRESERVE_TOOLCHAIN_HOME",
    )
    assert solana.environment["CARGO_HOME"] == "/cache/cargo"
    assert solana.environment["RUSTUP_HOME"] == "/cache/rustup"
    assert (
        solana.environment["SOLANA_CONFIG_FILE"] == "/config/solana.yml"
    )
    assert (
        solana.environment["NPM_CONFIG_USERCONFIG"] == "/config/npmrc"
    )
    assert "GITHUB_TOKEN" not in solana.environment
    assert solana.receipt["phase_environment_policies"] == [
        "base",
        "node",
        "rust",
        "solana",
    ]


@pytest.mark.parametrize(
    ("policy", "name"),
    (
        ("certificates", "SSL_CERT_FILE"),
        ("git", "GIT_CONFIG_GLOBAL"),
        ("node", "NPM_CONFIG_USERCONFIG"),
        ("rust", "CARGO_HOME"),
        ("go", "GOMODCACHE"),
        ("evm", "FOUNDRY_PROFILE"),
        ("solana", "SOLANA_CONFIG_FILE"),
        ("aptos", "APTOS_HOME"),
        ("sui", "SUI_CONFIG_DIR"),
        ("soroban", "STELLAR_CONFIG_DIR"),
        ("l1-native", "CMAKE_PREFIX_PATH"),
        ("plamen", "PLAMEN_SCRATCHPAD"),
    ),
)
def test_each_named_phase_toolchain_policy_has_no_ambient_passthrough(
    policy: str,
    name: str,
) -> None:
    ambient = {
        "PATH": "/tools/bin",
        "HOME": "/home/auditor",
        name: f"/fixture/{name.casefold()}",
        "UNRELATED_DATABASE_PASSWORD": "secret",
    }
    auth_environment, auth_receipt, observation = _auth(ambient)
    result = C.compile_claude_child_environment(
        ambient=ambient,
        auth_environment=auth_environment,
        auth_environment_receipt=auth_receipt,
        source_observation=observation,
        attempt_profile_environment={
            "CLAUDE_CONFIG_DIR": "/lease/claude"
        },
        phase_environment_policies=("base", policy),
        home_variable_policy="PRESERVE_TOOLCHAIN_HOME",
    )
    assert result.environment[name] == f"/fixture/{name.casefold()}"
    assert "UNRELATED_DATABASE_PASSWORD" not in result.environment


def test_cloud_credentials_survive_only_for_the_selected_cloud_route() -> None:
    ambient = {
        "PATH": "/bin",
        "HOME": "/home/auditor",
        "CLAUDE_CODE_USE_BEDROCK": "true",
        "AWS_ACCESS_KEY_ID": "selected-id",
        "AWS_SECRET_ACCESS_KEY": "selected-secret",
        "GITHUB_TOKEN": "unrelated-secret",
    }
    auth_environment, auth_receipt, observation = _auth(
        ambient,
        route="CLOUD_BEDROCK",
    )
    result = C.compile_claude_child_environment(
        ambient=ambient,
        auth_environment=auth_environment,
        auth_environment_receipt=auth_receipt,
        source_observation=observation,
        attempt_profile_environment={
            "CLAUDE_CONFIG_DIR": "/lease/claude"
        },
        phase_environment_policies=("base",),
        home_variable_policy="PRESERVE_TOOLCHAIN_HOME",
    )
    assert result.environment["CLAUDE_CODE_USE_BEDROCK"] == "1"
    assert result.environment["AWS_ACCESS_KEY_ID"] == "selected-id"
    assert result.environment["AWS_SECRET_ACCESS_KEY"] == "selected-secret"
    assert "GITHUB_TOKEN" not in result.environment
    durable = json.dumps(result.receipt, sort_keys=True)
    assert "selected-secret" not in durable
    assert hashlib.sha256(b"selected-secret").hexdigest() not in durable


def test_unknown_named_policy_and_unknown_overlay_key_fail_closed() -> None:
    ambient = {"PATH": "/bin", "HOME": "/home/auditor"}
    auth_environment, auth_receipt, observation = _auth(ambient)
    kwargs = {
        "ambient": ambient,
        "auth_environment": auth_environment,
        "auth_environment_receipt": auth_receipt,
        "source_observation": observation,
        "attempt_profile_environment": {
            "CLAUDE_CONFIG_DIR": "/lease/claude"
        },
    }
    with pytest.raises(C.ClaudeChildEnvironmentError, match="policy"):
        C.compile_claude_child_environment(
            **kwargs,
            phase_environment_policies=("base", "everything"),
            home_variable_policy="PRESERVE_TOOLCHAIN_HOME",
        )
    with pytest.raises(C.ClaudeChildEnvironmentError, match="profile"):
        C.compile_claude_child_environment(
            **{
                **kwargs,
                "attempt_profile_environment": {
                    "CLAUDE_CONFIG_DIR": "/lease/claude",
                    "UNREVIEWED_PROFILE_VALUE": "x",
                },
            },
            phase_environment_policies=("base",),
            home_variable_policy="PRESERVE_TOOLCHAIN_HOME",
        )


def test_attempt_profile_cannot_replace_toolchain_home_by_default() -> None:
    ambient = {
        "PATH": "/bin",
        "HOME": "/home/auditor",
        "USERPROFILE": "C:\\Users\\auditor",
    }
    auth_environment, auth_receipt, observation = _auth(ambient)
    with pytest.raises(
        C.ClaudeChildEnvironmentError,
        match="toolchain home",
    ):
        C.compile_claude_child_environment(
            ambient=ambient,
            auth_environment=auth_environment,
            auth_environment_receipt=auth_receipt,
            source_observation=observation,
            attempt_profile_environment={
                "CLAUDE_CONFIG_DIR": "/lease/claude",
                "HOME": "/lease/fake-home",
            },
            phase_environment_policies=("base",),
            home_variable_policy="PRESERVE_TOOLCHAIN_HOME",
        )


def test_private_home_policy_accepts_only_the_explicit_profile_home_overlay(
    tmp_path,
) -> None:
    ambient = {
        "PATH": "/bin",
        "HOME": "/home/auditor",
        "USERPROFILE": "/home/auditor",
    }
    auth_environment, auth_receipt, observation = _auth(ambient)
    lease = tmp_path / "lease"
    profile_environment = {
        "CLAUDE_CONFIG_DIR": str(lease / "config"),
        "CLAUDE_CODE_TMPDIR": str(lease / "tmp"),
        "TMP": str(lease / "tmp"),
        "TEMP": str(lease / "tmp"),
        "TMPDIR": str(lease / "tmp"),
        "HOME": str(lease / "home"),
        "USERPROFILE": str(lease / "home"),
        "APPDATA": str(lease / "appdata"),
        "LOCALAPPDATA": str(lease / "localappdata"),
    }
    binding_core = {
        "schema": "plamen.claude_attempt_profile.v3",
        "run_id": "run-private-home-fixture",
        "work_plan_sha256": "1" * 64,
        "attempt_id": "attempt-private-home-fixture",
        "home_variable_policy": "PRIVATE_HOME",
    }
    overlay = C._mint_claude_private_home_overlay_authority(
        attempt_profile_environment=profile_environment,
        attempt_profile_binding={
            **binding_core,
            "profile_sha256": _digest(binding_core),
        },
    )
    result = C.compile_claude_child_environment(
        ambient=ambient,
        auth_environment=auth_environment,
        auth_environment_receipt=auth_receipt,
        source_observation=observation,
        attempt_profile_environment=profile_environment,
        private_home_overlay_authority=overlay,
        phase_environment_policies=("base",),
        home_variable_policy="PRIVATE_HOME",
    )

    assert result.environment["HOME"] == str(lease / "home")
    assert result.environment["USERPROFILE"] == str(lease / "home")
    assert result.environment["XDG_CONFIG_HOME"] == str(
        lease / "home" / ".config"
    )
    assert result.environment["XDG_CACHE_HOME"] == str(
        lease / "home" / ".cache"
    )
    assert result.environment["XDG_DATA_HOME"] == str(
        lease / "home" / ".local" / "share"
    )
    assert result.receipt["home_variable_policy"] == "PRIVATE_HOME"
    assert result.receipt["configuration_isolation_status"] == (
        "ATTEMPT_PRIVATE_HOME_BOUND"
    )
    assert result.receipt["proof_grade_configuration_isolation"] is True
    with pytest.raises(
        C.ClaudeChildEnvironmentError,
        match="authority|replay",
    ):
        C.replay_claude_child_environment_receipt(result.receipt)
    assert C.reconcile_claude_child_environment(result) == result.receipt
    assert C.planned_claude_child_environment_key_set_sha256(
        ambient=ambient,
        selected_route="STORED_SUBSCRIPTION_OAUTH",
        endpoint_environment_names=(),
        phase_environment_policies=("base",),
            functional_control_names=tuple(_required_controls()),
        home_variable_policy="PRIVATE_HOME",
    ) == result.receipt["final_environment_key_set_sha256"]


def test_case_collision_is_rejected_in_every_environment_layer() -> None:
    ambient = {"PATH": "/bin", "HOME": "/home/auditor"}
    auth_environment, auth_receipt, observation = _auth(ambient)
    with pytest.raises(
        C.ClaudeChildEnvironmentError,
        match="case-ambiguous",
    ):
        C.compile_claude_child_environment(
            ambient=ambient,
            auth_environment=auth_environment,
            auth_environment_receipt=auth_receipt,
            source_observation=observation,
            attempt_profile_environment={
                "CLAUDE_CONFIG_DIR": "/lease/one",
                "claude_config_dir": "/lease/two",
            },
            phase_environment_policies=("base",),
            home_variable_policy="PRESERVE_TOOLCHAIN_HOME",
        )


def test_functional_controls_are_reviewed_not_prefix_passthrough() -> None:
    ambient = {"PATH": "/bin", "HOME": "/home/auditor"}
    auth_environment, auth_receipt, observation = _auth(ambient)
    with pytest.raises(
        C.ClaudeChildEnvironmentError,
        match="functional control",
    ):
        C.compile_claude_child_environment(
            ambient=ambient,
            auth_environment=auth_environment,
            auth_environment_receipt=auth_receipt,
            source_observation=observation,
            attempt_profile_environment={
                "CLAUDE_CONFIG_DIR": "/lease/claude"
            },
            phase_environment_policies=("base",),
            home_variable_policy="PRESERVE_TOOLCHAIN_HOME",
            functional_controls={"CLAUDE_CODE_NEW_FLAG": "1"},
        )


@pytest.mark.parametrize(
    "controls",
    (
        {},
        {"CLAUDE_CODE_SUBPROCESS_ENV_SCRUB": "0"},
        {
            key: value
            for key, value in _required_controls().items()
            if key != "DISABLE_AUTOUPDATER"
        },
        {
            key: value
            for key, value in _required_controls().items()
            if key != "DISABLE_UPDATES"
        },
        {
            key: value
            for key, value in _required_controls().items()
            if key
            != "CLAUDE_CODE_DISABLE_OFFICIAL_MARKETPLACE_AUTOINSTALL"
        },
        {
            **_required_controls(),
            "ENABLE_CLAUDEAI_MCP_SERVERS": "1",
        },
    ),
)
def test_subprocess_secret_scrub_control_is_mandatory(
    controls: dict[str, str],
) -> None:
    ambient = {"PATH": "/bin", "HOME": "/home/auditor"}
    auth_environment, auth_receipt, observation = _auth(ambient)
    with pytest.raises(
        C.ClaudeChildEnvironmentError,
        match="functional control|must equal 1",
    ):
        C.compile_claude_child_environment(
            ambient=ambient,
            auth_environment=auth_environment,
            auth_environment_receipt=auth_receipt,
            source_observation=observation,
            attempt_profile_environment={
                "CLAUDE_CONFIG_DIR": "/lease/claude"
            },
            phase_environment_policies=("base",),
            home_variable_policy="PRESERVE_TOOLCHAIN_HOME",
            functional_controls=controls,
        )


@pytest.mark.parametrize(
    "obsolete",
    (
        "CLAUDE_CODE_DISABLE_CLAUDEAI_MCP_SERVERS",
        "DISABLE_NON_ESSENTIAL_MODEL_CALLS",
        "CLAUDE_CODE_MAX_OUTPUT_CHARS",
        "CLAUDE_CODE_MAX_LINES",
    ),
)
def test_obsolete_or_unreviewed_controls_fail_closed(obsolete: str) -> None:
    ambient = {"PATH": "/bin", "HOME": "/home/auditor"}
    auth_environment, auth_receipt, observation = _auth(ambient)
    with pytest.raises(
        C.ClaudeChildEnvironmentError,
        match="functional control",
    ):
        C.compile_claude_child_environment(
            ambient=ambient,
            auth_environment=auth_environment,
            auth_environment_receipt=auth_receipt,
            source_observation=observation,
            attempt_profile_environment={
                "CLAUDE_CONFIG_DIR": "/lease/claude"
            },
            phase_environment_policies=("base",),
            home_variable_policy="PRESERVE_TOOLCHAIN_HOME",
            functional_controls={
                **_required_controls(),
                obsolete: "1",
            },
        )


def test_subprocess_scrub_control_overrides_ambient_substitution() -> None:
    ambient = {
        "PATH": "/bin",
        "HOME": "/home/auditor",
        "CLAUDE_CODE_SUBPROCESS_ENV_SCRUB": "0",
    }
    auth_environment, auth_receipt, observation = _auth(ambient)
    result = C.compile_claude_child_environment(
        ambient=ambient,
        auth_environment=auth_environment,
        auth_environment_receipt=auth_receipt,
        source_observation=observation,
        attempt_profile_environment={
            "CLAUDE_CONFIG_DIR": "/lease/claude"
        },
        phase_environment_policies=("base",),
        home_variable_policy="PRESERVE_TOOLCHAIN_HOME",
        functional_controls=_required_controls(),
    )
    assert (
        result.environment["CLAUDE_CODE_SUBPROCESS_ENV_SCRUB"]
        == "1"
    )
    assert result.receipt["functional_control_names"] == sorted(
        _required_controls()
    )


def test_child_receipt_or_environment_mutation_fails_replay() -> None:
    ambient = {"PATH": "/bin", "HOME": "/home/auditor"}
    auth_environment, auth_receipt, observation = _auth(ambient)
    result = C.compile_claude_child_environment(
        ambient=ambient,
        auth_environment=auth_environment,
        auth_environment_receipt=auth_receipt,
        source_observation=observation,
        attempt_profile_environment={
            "CLAUDE_CONFIG_DIR": "/lease/claude"
        },
        phase_environment_policies=("base",),
        home_variable_policy="PRESERVE_TOOLCHAIN_HOME",
    )
    changed_receipt = dict(result.receipt)
    changed_receipt["final_environment_key_set_sha256"] = "0" * 64
    with pytest.raises(C.ClaudeChildEnvironmentError):
        C.replay_claude_child_environment_receipt(changed_receipt)

    changed_receipt = deepcopy(result.receipt)
    changed_receipt["final_environment_names"].append("UNREVIEWED_SECRET")
    core = dict(changed_receipt)
    core.pop("receipt_sha256")
    changed_receipt["receipt_sha256"] = C._digest(core)
    with pytest.raises(C.ClaudeChildEnvironmentError):
        C.replay_claude_child_environment_receipt(changed_receipt)

    with pytest.raises(TypeError):
        result.environment["PATH"] = "/attacker/bin"
    private_environment = getattr(
        result,
        "_CompiledClaudeChildEnvironment__environment",
    )
    private_environment["PATH"] = "/attacker/bin"
    with pytest.raises(C.ClaudeChildEnvironmentError):
        C.reconcile_claude_child_environment(result)


def test_oauth_secret_oracle_is_absent_and_invalidation_zeroizes() -> None:
    token = "offline-high-entropy-oauth-token"
    ambient = {
        "PATH": "/usr/bin",
        "HOME": "/home/auditor",
        "CLAUDE_CODE_OAUTH_TOKEN": token,
    }
    auth_environment, auth_receipt, observation = _auth(
        ambient,
        route="OAUTH_TOKEN",
    )
    result = C.compile_claude_child_environment(
        ambient=ambient,
        auth_environment=auth_environment,
        auth_environment_receipt=auth_receipt,
        source_observation=observation,
        attempt_profile_environment={
            "CLAUDE_CONFIG_DIR": "/private/config",
            "CLAUDE_CODE_TMPDIR": "/private/tmp",
        },
        phase_environment_policies=("base",),
        home_variable_policy="PRESERVE_TOOLCHAIN_HOME",
    )
    public = "\n".join(
        (
            repr(result),
            json.dumps(result.receipt, sort_keys=True),
            str(result.receipt),
        )
    )
    assert token not in public
    assert hashlib.sha256(token.encode()).hexdigest() not in public
    private_environment = getattr(
        result,
        "_CompiledClaudeChildEnvironment__environment",
    )
    private_environment["CLAUDE_CODE_OAUTH_TOKEN"] = "mutated"
    with pytest.raises(C.ClaudeChildEnvironmentError) as failure:
        C.reconcile_claude_child_environment(result)
    assert token not in str(failure.value)
    assert "mutated" not in str(failure.value)

    result._invalidate_private_values()
    assert result.active is False
    assert getattr(
        result,
        "_CompiledClaudeChildEnvironment__integrity_key",
    ) == bytearray()
    assert getattr(
        result,
        "_CompiledClaudeChildEnvironment__integrity_tag",
    ) == bytearray()
    with pytest.raises(C.ClaudeChildEnvironmentError, match="invalidated"):
        _ = result.environment
    with pytest.raises(C.ClaudeChildEnvironmentError, match="invalidated"):
        C.reconcile_claude_child_environment(result)
