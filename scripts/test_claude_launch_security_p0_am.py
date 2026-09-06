from __future__ import annotations

from copy import deepcopy
import hashlib
import json

import pytest

import claude_launch_security as L
from claude_headless_profile import (
    compile_claude_headless_profile,
    compile_claude_headless_profile_from_authorities,
)
import worker_transaction as T


HEX = "1" * 64
VERSION = "2.1.220"


def _controls() -> dict[str, str]:
    return {
        "CLAUDE_CODE_SUBPROCESS_ENV_SCRUB": "1",
        "CLAUDE_CODE_DISABLE_OFFICIAL_MARKETPLACE_AUTOINSTALL": "1",
        "DISABLE_AUTOUPDATER": "1",
        "DISABLE_UPDATES": "1",
        "ENABLE_CLAUDEAI_MCP_SERVERS": "false",
    }


def _digest(value):
    return hashlib.sha256(
        json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def _executable_observation() -> dict:
    file_row = {
        "role": "CONFIGURED_EXECUTABLE",
        "path": "C:\\fixture\\claude.exe",
        "sha256": "2" * 64,
        "size": 10,
        "device": 1,
        "inode": 2,
        "mode": 33279,
        "link_count": 1,
    }
    compatibility_core = {
        "compatibility_id": "claude-code-2.1.220",
        "claude_code_version": VERSION,
        "supported_capabilities": sorted(
            (
                "-p",
                "--dangerously-skip-permissions",
                "--disable-slash-commands",
                "--mcp-config",
                "--no-chrome",
                "--no-session-persistence",
                "--output-format=stream-json",
                "--permission-mode=dontAsk",
                "--prompt-suggestions=false",
                "--safe-mode",
                "--session-id",
                "--setting-sources=",
                "--strict-mcp-config",
                "--tools",
                "--verbose",
                "init-security-v2",
            )
        ),
    }
    stdout = f"{VERSION} (Claude Code)\n"
    native_core = {
        "schema": "plamen.claude_native_platform_authority.v1",
        "platform": "WINDOWS_AUTHENTICODE",
        "publisher_policy_id": "anthropic-claude-code-windows-v1",
        "publisher_name": "Anthropic PBC",
        "signer_subject": "CN=Anthropic PBC, O=Anthropic PBC",
        "product_name": "Claude Code",
        "file_version": f"{VERSION}.0",
        "claude_code_version": VERSION,
        "executable_path": file_row["path"],
        "executable_sha256": file_row["sha256"],
        "executable_size": file_row["size"],
        "signature_status": "Valid",
        "implementation_closure": (
            "SIGNED_NATIVE_PRODUCT_IMAGE_WITH_EXTERNAL_OS_AUTHORITY"
        ),
    }
    core = {
        "schema": "plamen.claude_executable_observation.v1",
        "configured_claude_bin": file_row["path"],
        "resolved_executable": file_row["path"],
        "claude_code_version": VERSION,
        "compatibility": {
            **compatibility_core,
            "compatibility_sha256": _digest(compatibility_core),
        },
        "implementation_kind": "NATIVE_EXECUTABLE_IMAGE",
        "implementation_status": "DIRECT_IMPLEMENTATION_BOUND",
        "implementation_debt": None,
        "implementation_files": [file_row],
        "implementation_closure_roots": [],
        "native_platform_authority": {
            **native_core,
            "authority_sha256": _digest(native_core),
        },
        "version_probe": {
            "argv": [file_row["path"], "--version"],
            "returncode": 0,
            "stdout_utf8": stdout,
            "stdout_bytes": len(stdout.encode()),
            "stdout_sha256": hashlib.sha256(stdout.encode()).hexdigest(),
            "stderr_bytes": 0,
            "stderr_sha256": hashlib.sha256(b"").hexdigest(),
            "owned_process_scope_closed": True,
        },
        "launch_authority": "PROOF_GRADE",
    }
    return {**core, "observation_sha256": _digest(core)}


def _profile(*, mode: str = "SAFE_MODE", sources=("none",), servers=()):
    return compile_claude_headless_profile(
        claude_code_version=VERSION,
        cwd="C:\\fixture\\project",
        accepted_models=("claude-opus-4-1",),
        permission_mode="dontAsk",
        builtin_tools=("Edit", "Glob", "Grep", "Read", "Write"),
        required_tools=("Read",),
        forbidden_tools=("Bash",),
        mcp_server_names=servers,
        customization_mode=mode,
        accepted_api_key_sources=sources,
    )


def _authorities(*, mode: str = "SAFE_MODE", servers=()):
    settings = L.compile_claude_settings_authority(
        mode=mode,
        settings_sha256=None if mode == "SAFE_MODE" else "3" * 64,
        external_policy_sha256=(
            None if mode == "SAFE_MODE" else "4" * 64
        ),
    )
    mcp = L.compile_claude_mcp_authority(
        settings_mode=mode,
        server_names=servers,
        source_manifest_sha256="5" * 64 if servers else None,
        selected_config_sha256=(
            None if mode == "SAFE_MODE" else "6" * 64
        ),
    )
    return settings, mcp


def _typed_profile(
    *,
    executable: dict,
    auth: dict,
    settings: dict,
    mcp: dict,
    mode: str = "SAFE_MODE",
    servers=(),
):
    del mode, servers
    return compile_claude_headless_profile_from_authorities(
        executable_observation=executable,
        auth_route_policy=auth,
        settings_authority=settings,
        mcp_authority=mcp,
        cwd="C:\\fixture\\project",
        accepted_models=("claude-opus-4-1",),
        permission_mode="dontAsk",
        builtin_tools=("Edit", "Glob", "Grep", "Read", "Write"),
        required_tools=("Read",),
        forbidden_tools=("Bash",),
    )


def _policy(
    *,
    route: str = "STORED_SUBSCRIPTION_OAUTH",
    mode: str = "SAFE_MODE",
    servers=(),
):
    executable = _executable_observation()
    auth = L.compile_claude_auth_route_policy(
        claude_code_version=VERSION,
        desired_route=route,
    )
    settings, mcp = _authorities(mode=mode, servers=servers)
    profile = _typed_profile(
        executable=executable,
        auth=auth,
        settings=settings,
        mcp=mcp,
        mode=mode,
        servers=servers,
    )
    policy = L.compile_claude_launch_security(
        headless_profile=profile,
        auth_route_policy=auth,
        executable_observation=executable,
        settings_authority=settings,
        mcp_authority=mcp,
        home_variable_policy="PRESERVE_TOOLCHAIN_HOME",
        phase_environment_policies=("base", "git", "rust"),
        functional_controls=_controls(),
        expected_child_environment_key_set_sha256=HEX,
    )
    return policy, executable


def test_compile_replay_and_full_executable_request_reconcile() -> None:
    policy, executable = _policy()
    assert L.replay_claude_launch_security(policy) == policy
    assert (
        L.reconcile_claude_launch_security_request(
            policy,
            executable_observation=executable,
        )
        == policy
    )
    durable = json.dumps(policy, sort_keys=True)
    assert "credential" in durable
    assert "credential_values_recorded\": false" in durable.lower()
    request = L.compile_claude_launch_security_request(
        policy=policy,
        executable_observation=executable,
    )
    assert L.replay_claude_launch_security_request(request) == request


def test_production_launch_rejects_legacy_v1_profile_downgrade() -> None:
    profile = _profile()
    auth = L.compile_claude_auth_route_policy(
        claude_code_version=VERSION,
        desired_route="STORED_SUBSCRIPTION_OAUTH",
    )
    settings, mcp = _authorities()

    with pytest.raises(
        L.ClaudeLaunchSecurityError,
        match="typed v2",
    ):
        L.compile_claude_launch_security(
            headless_profile=profile,
            auth_route_policy=auth,
            executable_observation=_executable_observation(),
            settings_authority=settings,
            mcp_authority=mcp,
            home_variable_policy="PRESERVE_TOOLCHAIN_HOME",
            phase_environment_policies=("base",),
            functional_controls=_controls(),
            expected_child_environment_key_set_sha256=HEX,
        )


def test_typed_launch_rejects_every_embedded_authority_splice() -> None:
    executable_a = _executable_observation()
    auth_a = L.compile_claude_auth_route_policy(
        claude_code_version=VERSION,
        desired_route="API_KEY",
    )
    settings_a, mcp_a = _authorities(
        mode="BOUND_SETTINGS",
        servers=("solodit",),
    )
    profile = _typed_profile(
        executable=executable_a,
        auth=auth_a,
        settings=settings_a,
        mcp=mcp_a,
    )

    executable_b = deepcopy(executable_a)
    executable_b["configured_claude_bin"] = "C:\\other\\claude.exe"
    executable_b["resolved_executable"] = "C:\\other\\claude.exe"
    executable_b["implementation_files"][0]["path"] = (
        "C:\\other\\claude.exe"
    )
    executable_b["implementation_files"][0]["sha256"] = "9" * 64
    executable_b["version_probe"]["argv"][0] = "C:\\other\\claude.exe"
    executable_core = dict(executable_b)
    executable_core.pop("observation_sha256")
    executable_b["observation_sha256"] = _digest(executable_core)

    endpoint_b = L.compile_claude_endpoint_policy(
        desired_route="API_KEY",
        endpoint_mode="CUSTOM_BASE_URL",
        endpoint_environment={
            "ANTHROPIC_BASE_URL": "https://proxy.example",
        },
    )
    auth_b = L.compile_claude_auth_route_policy(
        claude_code_version=VERSION,
        desired_route="API_KEY",
        endpoint_policy=endpoint_b,
    )
    settings_b = L.compile_claude_settings_authority(
        mode="BOUND_SETTINGS",
        settings_sha256="a" * 64,
        external_policy_sha256="b" * 64,
    )
    mcp_b = L.compile_claude_mcp_authority(
        settings_mode="BOUND_SETTINGS",
        server_names=("solodit",),
        source_manifest_sha256="c" * 64,
        selected_config_sha256="d" * 64,
    )

    substitutions = (
        {"executable_observation": executable_b},
        {"auth_route_policy": auth_b},
        {"settings_authority": settings_b},
        {"mcp_authority": mcp_b},
    )
    baseline = {
        "headless_profile": profile,
        "auth_route_policy": auth_a,
        "executable_observation": executable_a,
        "settings_authority": settings_a,
        "mcp_authority": mcp_a,
        "home_variable_policy": "PRESERVE_TOOLCHAIN_HOME",
        "phase_environment_policies": ("base",),
        "functional_controls": _controls(),
        "expected_child_environment_key_set_sha256": HEX,
    }
    for substitution in substitutions:
        with pytest.raises(
            L.ClaudeLaunchSecurityError,
            match="embedded|authorit",
        ):
            L.compile_claude_launch_security(
                **{**baseline, **substitution},
            )


def test_settings_and_mcp_subauthorities_have_canonical_identity_in_safe_mode() -> None:
    settings, mcp = _authorities()
    assert settings["authority_sha256"] == _digest(
        {
            "schema": L.CLAUDE_SETTINGS_AUTHORITY_SCHEMA,
            "mode": "SAFE_MODE",
            "settings_sha256": None,
            "external_policy_sha256": None,
        }
    )
    assert mcp["authority_sha256"] == _digest(
        {
            "schema": L.CLAUDE_MCP_AUTHORITY_SCHEMA,
            "server_names": [],
            "source_manifest_sha256": None,
            "selected_config_sha256": None,
        }
    )


@pytest.mark.parametrize("authority", ("settings", "mcp"))
def test_subauthority_tamper_cannot_replay_under_rehashed_outer_policy(
    authority: str,
) -> None:
    policy, _ = _policy()
    changed = deepcopy(policy)
    if authority == "settings":
        changed["settings_authority"]["authority_sha256"] = "8" * 64
    else:
        changed["mcp_authority"]["authority_sha256"] = "8" * 64
    core = dict(changed)
    core.pop("policy_sha256")
    changed["policy_sha256"] = _digest(core)
    with pytest.raises(L.ClaudeLaunchSecurityError, match="authority"):
        L.replay_claude_launch_security(changed)


def test_runtime_request_cannot_substitute_policy_or_executable() -> None:
    policy, executable = _policy()
    request = L.compile_claude_launch_security_request(
        policy=policy,
        executable_observation=executable,
    )
    changed = deepcopy(request)
    changed["policy"]["expected_child_environment_key_set_sha256"] = "8" * 64
    core = dict(changed)
    core.pop("request_sha256")
    changed["request_sha256"] = _digest(core)
    with pytest.raises(L.ClaudeLaunchSecurityError):
        L.replay_claude_launch_security_request(changed)


def test_profile_auth_source_is_single_cross_checked_authority() -> None:
    executable = _executable_observation()
    profile = _profile(sources=("subscription",))
    auth = L.compile_claude_auth_route_policy(
        claude_code_version=VERSION,
        desired_route="STORED_SUBSCRIPTION_OAUTH",
    )
    settings, mcp = _authorities()
    with pytest.raises(L.ClaudeLaunchSecurityError, match="disagree"):
        L.compile_claude_launch_security(
            headless_profile=profile,
            auth_route_policy=auth,
            executable_observation=executable,
            settings_authority=settings,
            mcp_authority=mcp,
            home_variable_policy="PRESERVE_TOOLCHAIN_HOME",
            phase_environment_policies=("base",),
            functional_controls=_controls(),
            expected_child_environment_key_set_sha256=HEX,
        )


@pytest.mark.parametrize(
    "mutation",
    ("profile_version", "auth_version", "executable_version"),
)
def test_version_authority_cannot_split(mutation: str) -> None:
    policy, _ = _policy()
    changed = deepcopy(policy)
    if mutation == "profile_version":
        changed["headless_profile"]["claude_code_version"] = "2.1.219"
    elif mutation == "auth_version":
        changed["auth_route_policy"]["claude_code_version"] = "2.1.219"
    else:
        changed["claude_code_version"] = "2.1.219"
    core = dict(changed)
    core.pop("policy_sha256")
    changed["policy_sha256"] = _digest(core)
    with pytest.raises(L.ClaudeLaunchSecurityError):
        L.replay_claude_launch_security(changed)


def test_safe_mode_cannot_carry_settings_or_mcp() -> None:
    profile = _profile()
    auth = L.compile_claude_auth_route_policy(
        claude_code_version=VERSION,
        desired_route="STORED_SUBSCRIPTION_OAUTH",
    )
    settings, mcp = _authorities()
    settings["settings_sha256"] = "3" * 64
    with pytest.raises(L.ClaudeLaunchSecurityError, match="settings"):
        L.compile_claude_launch_security(
            headless_profile=profile,
            auth_route_policy=auth,
            executable_observation=_executable_observation(),
            settings_authority=settings,
            mcp_authority=mcp,
            home_variable_policy="PRESERVE_TOOLCHAIN_HOME",
            phase_environment_policies=("base",),
            functional_controls=_controls(),
            expected_child_environment_key_set_sha256=HEX,
        )


def test_bound_settings_requires_exact_mcp_config_digest() -> None:
    settings, mcp = _authorities(mode="BOUND_SETTINGS")
    mcp["selected_config_sha256"] = None
    with pytest.raises(L.ClaudeLaunchSecurityError, match="MCP"):
        L.compile_claude_launch_security(
            headless_profile=_profile(mode="BOUND_SETTINGS"),
            auth_route_policy=L.compile_claude_auth_route_policy(
                claude_code_version=VERSION,
                desired_route="STORED_SUBSCRIPTION_OAUTH",
            ),
            executable_observation=_executable_observation(),
            settings_authority=settings,
            mcp_authority=mcp,
            home_variable_policy="PRESERVE_TOOLCHAIN_HOME",
            phase_environment_policies=("base",),
            functional_controls=_controls(),
            expected_child_environment_key_set_sha256=HEX,
        )


def test_mcp_names_equal_profile_init_denominator() -> None:
    with pytest.raises(L.ClaudeLaunchSecurityError, match="disagree"):
        profile = _profile(mode="BOUND_SETTINGS", servers=("unified-vuln-db",))
        auth = L.compile_claude_auth_route_policy(
            claude_code_version=VERSION,
            desired_route="STORED_SUBSCRIPTION_OAUTH",
        )
        settings, mcp = _authorities(mode="BOUND_SETTINGS", servers=())
        L.compile_claude_launch_security(
            headless_profile=profile,
            auth_route_policy=auth,
            executable_observation=_executable_observation(),
            settings_authority=settings,
            mcp_authority=mcp,
            home_variable_policy="PRESERVE_TOOLCHAIN_HOME",
            phase_environment_policies=("base",),
            functional_controls=_controls(),
            expected_child_environment_key_set_sha256=HEX,
        )


def test_request_substitution_rejects_even_with_valid_other_observation() -> None:
    policy, executable = _policy()
    other = deepcopy(executable)
    other["implementation_files"][0]["sha256"] = "9" * 64
    other["native_platform_authority"]["executable_sha256"] = "9" * 64
    native_core = dict(other["native_platform_authority"])
    native_core.pop("authority_sha256")
    other["native_platform_authority"]["authority_sha256"] = _digest(
        native_core
    )
    other_core = dict(other)
    other_core.pop("observation_sha256")
    other["observation_sha256"] = _digest(other_core)
    with pytest.raises(
        L.ClaudeLaunchSecurityError,
        match="differs",
    ):
        L.reconcile_claude_launch_security_request(
            policy,
            executable_observation=other,
        )


def test_custom_endpoint_cannot_be_attached_to_subscription_policy() -> None:
    with pytest.raises(L.ClaudeLaunchSecurityError, match="auth-route"):
        L.compile_claude_auth_route_policy(
            claude_code_version=VERSION,
            desired_route="STORED_SUBSCRIPTION_OAUTH",
            endpoint_policy={
                "schema": "plamen.claude_auth_endpoint_policy.v1",
                "desired_route": "API_KEY",
                "endpoint_mode": "CUSTOM_BASE_URL",
                "endpoint_environment": {
                    "ANTHROPIC_BASE_URL": "https://gateway.example.test"
                },
                "credential_values_recorded": False,
                "receipt_sha256": "0" * 64,
            },
        )


def test_workplan_completion_policy_replays_claude_security_and_codex_rejects_it() -> None:
    policy, _ = _policy()
    provider_preparation_sha256 = "e" * 64
    claude_provider = {
        "backend": "claude",
        "transport": "headless",
        "model": "claude-opus-4-1",
    }
    normalized = T._completion_policy_contract(
        {
            T.CLAUDE_LAUNCH_SECURITY_POLICY_KEY: policy,
            T.CLAUDE_PROVIDER_PREPARATION_POLICY_KEY: (
                provider_preparation_sha256
            ),
            "accepted_signals": ["PROCESS_EXIT_ZERO"],
        },
        run_id="fixture-run",
        provider=claude_provider,
        write_scope={},
    )
    assert normalized[T.CLAUDE_LAUNCH_SECURITY_POLICY_KEY] == policy
    assert normalized[T.CLAUDE_PROVIDER_PREPARATION_POLICY_KEY] == (
        provider_preparation_sha256
    )

    with pytest.raises(T.WorkerTransactionError, match="headless Claude"):
        T._completion_policy_contract(
            {
                T.CLAUDE_LAUNCH_SECURITY_POLICY_KEY: policy,
                T.CLAUDE_PROVIDER_PREPARATION_POLICY_KEY: (
                    provider_preparation_sha256
                ),
            },
            run_id="fixture-run",
            provider={"backend": "codex", "transport": "exec"},
            write_scope={},
        )

    for invalid_policy in (
        {T.CLAUDE_LAUNCH_SECURITY_POLICY_KEY: policy},
        {
            T.CLAUDE_LAUNCH_SECURITY_POLICY_KEY: policy,
            T.CLAUDE_PROVIDER_PREPARATION_POLICY_KEY: "e" * 63,
        },
    ):
        with pytest.raises(T.WorkerTransactionError):
            T._completion_policy_contract(
                invalid_policy,
                run_id="fixture-run",
                provider=claude_provider,
                write_scope={},
            )


def test_workplan_provider_model_must_be_inside_profile_denominator() -> None:
    policy, _ = _policy()
    with pytest.raises(
        T.WorkerTransactionError,
        match="model denominator",
    ):
        T._completion_policy_contract(
            {T.CLAUDE_LAUNCH_SECURITY_POLICY_KEY: policy},
            run_id="fixture-run",
            provider={
                "backend": "claude",
                "transport": "headless",
                "model": "claude-sonnet-outside-denominator",
            },
            write_scope={},
        )


@pytest.mark.parametrize(
    ("policies", "controls"),
    (
        (("base", "unreviewed-ecosystem"), {}),
        (("base",), {"CLAUDE_CODE_NEW_FLAG": "1"}),
        (("base",), {"DISABLE_AUTOUPDATER": "true"}),
    ),
)
def test_workplan_rejects_unreviewed_environment_policy_or_control(
    policies,
    controls,
) -> None:
    executable = _executable_observation()
    profile = _profile()
    auth = L.compile_claude_auth_route_policy(
        claude_code_version=VERSION,
        desired_route="STORED_SUBSCRIPTION_OAUTH",
    )
    settings, mcp = _authorities()
    with pytest.raises(
        L.ClaudeLaunchSecurityError,
        match="child-environment policy",
    ):
        L.compile_claude_launch_security(
            headless_profile=profile,
            auth_route_policy=auth,
            executable_observation=executable,
            settings_authority=settings,
            mcp_authority=mcp,
            home_variable_policy="PRESERVE_TOOLCHAIN_HOME",
            phase_environment_policies=policies,
            functional_controls=controls,
            expected_child_environment_key_set_sha256=HEX,
        )
