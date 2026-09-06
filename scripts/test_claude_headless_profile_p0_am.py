from __future__ import annotations

import copy
import hashlib
import json

import pytest

import claude_auth_route as A
import claude_headless_profile as P
import claude_stream_json_evidence as E


def _kwargs() -> dict[str, object]:
    return {
        "claude_code_version": "2.1.220",
        "cwd": "C:\\audit",
        "accepted_models": ("claude-opus-5",),
        "permission_mode": "bypassPermissions",
        "builtin_tools": (
            "Bash",
            "Edit",
            "Glob",
            "Grep",
            "Read",
            "Write",
        ),
        "required_tools": ("Read", "Write"),
        "forbidden_tools": (
            "Agent",
            "Task",
            "WebFetch",
            "WebSearch",
        ),
        "mcp_server_names": (),
        "customization_mode": "SAFE_MODE",
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


def _executable_observation(
    version: str = "2.1.220",
) -> dict[str, object]:
    path = "C:\\fixture\\claude.exe"
    file_row = {
        "role": "CONFIGURED_EXECUTABLE",
        "path": path,
        "sha256": "1" * 64,
        "size": 10,
        "device": 1,
        "inode": 2,
        "mode": 33279,
        "link_count": 1,
    }
    native_core = {
        "schema": "plamen.claude_native_platform_authority.v1",
        "platform": "WINDOWS_AUTHENTICODE",
        "publisher_policy_id": "anthropic-claude-code-windows-v1",
        "publisher_name": "Anthropic PBC",
        "signer_subject": "CN=Anthropic PBC, O=Anthropic PBC",
        "product_name": "Claude Code",
        "file_version": f"{version}.0",
        "claude_code_version": version,
        "executable_path": path,
        "executable_sha256": file_row["sha256"],
        "executable_size": file_row["size"],
        "signature_status": "Valid",
        "implementation_closure": (
            "SIGNED_NATIVE_PRODUCT_IMAGE_WITH_EXTERNAL_OS_AUTHORITY"
        ),
    }
    supported_capabilities = {
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
    }
    if version == "2.1.252":
        supported_capabilities.add("--permission-mode=default")
    compatibility_core = {
        "compatibility_id": f"claude-code-{version}",
        "claude_code_version": version,
        "supported_capabilities": sorted(supported_capabilities),
    }
    stdout = f"{version} (Claude Code)\n"
    core = {
        "schema": "plamen.claude_executable_observation.v1",
        "configured_claude_bin": path,
        "resolved_executable": path,
        "claude_code_version": version,
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
            "argv": [path, "--version"],
            "returncode": 0,
            "stdout_utf8": stdout,
            "stdout_bytes": len(stdout.encode("utf-8")),
            "stdout_sha256": hashlib.sha256(stdout.encode("utf-8")).hexdigest(),
            "stderr_bytes": 0,
            "stderr_sha256": hashlib.sha256(b"").hexdigest(),
            "owned_process_scope_closed": True,
        },
        "launch_authority": "PROOF_GRADE",
    }
    return {**core, "observation_sha256": _digest(core)}


def _settings_authority(mode: str) -> dict[str, object]:
    core = {
        "schema": "plamen.claude_settings_authority.v1",
        "mode": mode,
        "settings_sha256": None if mode == "SAFE_MODE" else "2" * 64,
        "external_policy_sha256": (
            None if mode == "SAFE_MODE" else "3" * 64
        ),
    }
    return {**core, "authority_sha256": _digest(core)}


def _mcp_authority(
    mode: str,
    servers: tuple[str, ...] = (),
) -> dict[str, object]:
    core = {
        "schema": "plamen.claude_mcp_authority.v1",
        "server_names": sorted(servers),
        "source_manifest_sha256": "4" * 64 if servers else None,
        "selected_config_sha256": (
            None if mode == "SAFE_MODE" else "5" * 64
        ),
    }
    return {**core, "authority_sha256": _digest(core)}


def _typed_kwargs(
    *,
    mode: str = "SAFE_MODE",
    route: str = "STORED_SUBSCRIPTION_OAUTH",
    servers: tuple[str, ...] = (),
    version: str = "2.1.220",
) -> dict[str, object]:
    return {
        "executable_observation": _executable_observation(version),
        "auth_route_policy": A.compile_claude_auth_route_policy(
            claude_code_version=version,
            desired_route=route,
        ),
        "settings_authority": _settings_authority(mode),
        "mcp_authority": _mcp_authority(mode, servers),
        "cwd": "C:\\audit",
        "accepted_models": ("claude-opus-5",),
        "permission_mode": "bypassPermissions",
        "builtin_tools": (
            "Bash",
            "Edit",
            "Glob",
            "Grep",
            "Read",
            "Write",
        ),
        "required_tools": ("Read", "Write"),
        "forbidden_tools": ("Agent", "Task", "WebFetch", "WebSearch"),
    }


def _restricted_typed_kwargs() -> dict[str, object]:
    kwargs = _typed_kwargs(
        mode="BOUND_SETTINGS",
        version="2.1.252",
    )
    kwargs.update(
        {
            "permission_mode": "default",
            "builtin_tools": ("Edit", "Glob", "Grep", "Read", "Write"),
            "forbidden_tools": (
                "Agent",
                "Bash",
                "PowerShell",
                "Task",
                "WebFetch",
                "WebSearch",
            ),
            "required_capabilities": ("vendor-restricted-analysis",),
            "forbidden_capabilities": ("remote-agents",),
        }
    )
    return kwargs


def test_version_parser_accepts_only_canonical_current_cli_output() -> None:
    assert P.parse_claude_code_version(
        "2.1.220 (Claude Code)\r\n"
    ) == "2.1.220"
    for invalid in (
        "",
        "Claude Code 2.1.220",
        "2.1.220",
        "2.1.220 (Claude Code)\nextra",
        "02.1.220 (Claude Code)",
    ):
        with pytest.raises(P.ClaudeHeadlessProfileError):
            P.parse_claude_code_version(invalid)


def test_2_1_250_runtime_settings_attachment_is_reviewed() -> None:
    assert P._runtime_authority_flags(
        customization_mode="BOUND_SETTINGS",
        claude_code_version="2.1.250",
    ) == ["--mcp-config", "--settings", "--strict-mcp-config"]
    with pytest.raises(P.ClaudeHeadlessProfileError, match="not reviewed"):
        P._runtime_authority_flags(
            customization_mode="BOUND_SETTINGS",
            claude_code_version="2.1.251",
        )


def test_safe_mode_profile_is_digest_bound_and_closes_customizations() -> None:
    profile = P.compile_claude_headless_profile(**_kwargs())

    assert profile["schema"] == "plamen.claude_headless_profile.v1"
    assert profile["profile_sha256"]
    assert profile["cli_flags"] == [
        "--dangerously-skip-permissions",
        "--safe-mode",
        "--disable-slash-commands",
        "--setting-sources=",
        "--no-chrome",
        "--prompt-suggestions",
        "false",
        "--tools",
        "Bash,Edit,Glob,Grep,Read,Write",
    ]
    expected = profile["expected_init_contract"]
    assert expected["schema"] == E.EXPECTED_INIT_SECURITY_SCHEMA
    assert expected["allowed_tool_prefixes"] == []
    assert expected["allowed_mcp_servers"] == []
    assert expected["expected_plugins"] == []
    assert expected["expected_skills"] == []
    assert expected["expected_agents"] == []
    assert expected["expected_slash_commands"] == []
    assert expected["accepted_output_styles"] == ["default"]
    assert P.replay_claude_headless_profile(profile) == profile


def test_bound_settings_profile_supports_only_named_mcp_servers() -> None:
    kwargs = _kwargs()
    kwargs.update(
        {
            "customization_mode": "BOUND_SETTINGS",
            "permission_mode": "dontAsk",
            "mcp_server_names": ("context7", "solodit"),
        }
    )
    profile = P.compile_claude_headless_profile(**kwargs)

    assert "--safe-mode" not in profile["cli_flags"]
    expected = profile["expected_init_contract"]
    assert expected["allowed_tool_prefixes"] == ["mcp__"]
    assert expected["allowed_mcp_servers"] == ["context7", "solodit"]
    assert expected["required_mcp_servers"] == ["context7", "solodit"]


def test_safe_mode_cannot_claim_mcp_or_bound_settings() -> None:
    kwargs = _kwargs()
    kwargs["mcp_server_names"] = ("solodit",)
    with pytest.raises(P.ClaudeHeadlessProfileError):
        P.compile_claude_headless_profile(**kwargs)


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("permission_mode", "default"),
        ("customization_mode", "UNBOUND"),
        ("builtin_tools", ("Read", "Read")),
        ("required_tools", ("Read", "Agent")),
        ("forbidden_tools", ("Read",)),
        ("mcp_server_names", ("bad name",)),
        ("accepted_models", ()),
        ("accepted_api_key_sources", ()),
        ("accepted_output_styles", ()),
    ),
)
def test_profile_rejects_ambiguous_or_uncontrolled_authority(
    field: str,
    value: object,
) -> None:
    kwargs = _kwargs()
    kwargs[field] = value
    with pytest.raises(P.ClaudeHeadlessProfileError):
        P.compile_claude_headless_profile(**kwargs)


def test_profile_replay_rejects_every_semantic_mutation() -> None:
    profile = P.compile_claude_headless_profile(**_kwargs())
    for mutate in (
        lambda value: value.update(profile_sha256="0" * 64),
        lambda value: value["cli_flags"].append("--agent"),
        lambda value: value["expected_init_contract"][
            "forbidden_tools"
        ].remove("Agent"),
    ):
        changed = copy.deepcopy(profile)
        mutate(changed)
        with pytest.raises(P.ClaudeHeadlessProfileError):
            P.replay_claude_headless_profile(changed)


def test_typed_safe_profile_derives_every_external_denominator() -> None:
    profile = P.compile_claude_headless_profile_from_authorities(
        **_typed_kwargs()
    )

    assert profile["schema"] == "plamen.claude_headless_profile.v2"
    assert profile["claude_code_version"] == "2.1.220"
    assert profile["auth_route_policy"]["desired_route"] == (
        "STORED_SUBSCRIPTION_OAUTH"
    )
    assert profile["expected_init_contract"]["accepted_api_key_sources"] == [
        "none"
    ]
    assert profile["settings_authority"]["mode"] == "SAFE_MODE"
    assert profile["mcp_authority"]["server_names"] == []
    assert profile["executable_observation_reference"][
        "observation_sha256"
    ] == _typed_kwargs()["executable_observation"]["observation_sha256"]
    assert "--safe-mode" in profile["cli_flags"]
    assert P.replay_claude_headless_profile(profile) == profile


def test_typed_bound_profile_carries_settings_and_strict_mcp_authority() -> None:
    profile = P.compile_claude_headless_profile_from_authorities(
        **_typed_kwargs(
            mode="BOUND_SETTINGS",
            route="API_KEY_HELPER",
            servers=("solodit", "unified-vuln-db"),
        )
    )

    assert "--safe-mode" not in profile["cli_flags"]
    assert profile["settings_authority"]["settings_sha256"] == "2" * 64
    assert profile["mcp_authority"]["server_names"] == [
        "solodit",
        "unified-vuln-db",
    ]
    assert profile["expected_init_contract"]["accepted_api_key_sources"] == [
        "apiKeyHelper"
    ]
    assert profile["required_runtime_authority_flags"] == [
        "--mcp-config",
        "--settings",
        "--strict-mcp-config",
    ]
    assert "--settings" in profile["executable_observation_reference"][
        "required_capabilities"
    ]
    assert P.replay_claude_headless_profile(profile) == profile


def test_pinned_restricted_profile_uses_truthful_default_init_denominator() -> None:
    profile = P.compile_claude_headless_profile_from_authorities(
        **_restricted_typed_kwargs()
    )

    assert profile["cli_flags"].count("--restricted") == 1
    permission_index = profile["cli_flags"].index("--permission-mode")
    assert profile["cli_flags"][permission_index + 1] == "default"
    expected = profile["expected_init_contract"]
    assert expected["permission_mode"] == "default"
    assert expected["required_capabilities"] == [
        "vendor-restricted-analysis"
    ]
    assert expected["expected_agents"] == list(
        E.REVIEWED_RESTRICTED_INIT_AGENTS
    )
    assert expected["expected_native_capabilities"] == list(
        E.REVIEWED_RESTRICTED_INIT_CAPABILITIES
    )
    assert P.replay_claude_headless_profile(profile) == profile


@pytest.mark.parametrize("mutation", ("missing-restricted", "wrong-mode"))
def test_restricted_profile_replay_rejects_cli_authority_drift(
    mutation: str,
) -> None:
    profile = P.compile_claude_headless_profile_from_authorities(
        **_restricted_typed_kwargs()
    )
    changed = copy.deepcopy(profile)
    if mutation == "missing-restricted":
        changed["cli_flags"].remove("--restricted")
    else:
        index = changed["cli_flags"].index("--permission-mode")
        changed["cli_flags"][index + 1] = "dontAsk"
    core = dict(changed)
    core.pop("profile_sha256")
    changed["profile_sha256"] = _digest(core)

    with pytest.raises(P.ClaudeHeadlessProfileError):
        P.replay_claude_headless_profile(changed)


@pytest.mark.parametrize(
    ("version", "permission_mode", "required_capabilities"),
    (
        ("2.1.252", "dontAsk", ("vendor-restricted-analysis",)),
        ("2.1.252", "default", ()),
        ("2.1.250", "default", ("vendor-restricted-analysis",)),
    ),
)
def test_default_or_restricted_permission_cannot_escape_exact_pinned_lane(
    version: str,
    permission_mode: str,
    required_capabilities: tuple[str, ...],
) -> None:
    kwargs = _typed_kwargs(
        mode="BOUND_SETTINGS",
        version=version,
    )
    kwargs.update(
        {
            "permission_mode": permission_mode,
            "builtin_tools": ("Edit", "Glob", "Grep", "Read", "Write"),
            "forbidden_tools": (
                "Agent",
                "Bash",
                "PowerShell",
                "Task",
                "WebFetch",
                "WebSearch",
            ),
            "required_capabilities": required_capabilities,
        }
    )
    with pytest.raises(P.ClaudeHeadlessProfileError):
        P.compile_claude_headless_profile_from_authorities(**kwargs)


def test_typed_profile_rejects_route_settings_or_observation_substitution() -> None:
    safe_helper = _typed_kwargs(route="API_KEY_HELPER")
    with pytest.raises(P.ClaudeHeadlessProfileError, match="helper|settings"):
        P.compile_claude_headless_profile_from_authorities(**safe_helper)

    mismatched = _typed_kwargs()
    route_policy = copy.deepcopy(mismatched["auth_route_policy"])
    route_policy["claude_code_version"] = "2.1.219"
    route_core = dict(route_policy)
    route_core.pop("policy_sha256")
    route_policy["policy_sha256"] = _digest(route_core)
    mismatched["auth_route_policy"] = route_policy
    with pytest.raises(P.ClaudeHeadlessProfileError, match="unsupported|version"):
        P.compile_claude_headless_profile_from_authorities(**mismatched)

    profile = P.compile_claude_headless_profile_from_authorities(
        **_typed_kwargs()
    )
    for mutate in (
        lambda value: value["settings_authority"].update(
            authority_sha256="0" * 64
        ),
        lambda value: value["auth_route_policy"].update(
            desired_route="API_KEY"
        ),
        lambda value: value["executable_observation_reference"][
            "required_capabilities"
        ].remove("--safe-mode"),
    ):
        changed = copy.deepcopy(profile)
        mutate(changed)
        core = dict(changed)
        core.pop("profile_sha256")
        changed["profile_sha256"] = _digest(core)
        with pytest.raises(P.ClaudeHeadlessProfileError):
            P.replay_claude_headless_profile(changed)
