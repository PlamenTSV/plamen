"""Compile one replayable Claude CLI application-security profile.

The provider stream can prove which tools and customizations Claude reports,
but only when the expected state was frozen before launch.  This module owns
that expected-state compilation.  It performs no subprocess or filesystem
operation: executable/version observation remains the worker provider's job.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Mapping, Sequence

from claude_stream_json_evidence import (
    EXPECTED_INIT_SECURITY_SCHEMA,
    RESTRICTED_ANALYSIS_CAPABILITY,
    RESTRICTED_WEB_ANALYSIS_CAPABILITY,
    REVIEWED_RESTRICTED_INIT_AGENTS,
    REVIEWED_RESTRICTED_INIT_CAPABILITIES,
    REVIEWED_RESTRICTED_INIT_VERSION,
    ClaudeStreamJsonEvidenceError,
    normalize_expected_init_contract,
)


PROFILE_SCHEMA = "plamen.claude_headless_profile.v1"
TYPED_PROFILE_SCHEMA = "plamen.claude_headless_profile.v2"
SETTINGS_AUTHORITY_SCHEMA = "plamen.claude_settings_authority.v1"
MCP_AUTHORITY_SCHEMA = "plamen.claude_mcp_authority.v1"
MCP_AUTHORITY_SELECTION_SCHEMA = "plamen.claude_mcp_authority.v2"
_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_VERSION_OUTPUT_RE = re.compile(
    r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r" \(Claude Code\)\r?\n?"
)
_VERSION_RE = re.compile(
    r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
)
_TOOL_RE = re.compile(r"[A-Za-z][A-Za-z0-9_.:-]{0,127}")
_MCP_SERVER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")
_MODEL_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}")
_CUSTOMIZATION_MODES = {"SAFE_MODE", "BOUND_SETTINGS"}
_PERMISSION_MODES = {"bypassPermissions", "default", "dontAsk"}
_TYPED_SETTINGS_MODES = {"SAFE_MODE", "BOUND_SETTINGS"}
_RESTRICTED_NON_WRITE_ALLOWED_TOOLS = ("Glob", "Grep", "Read")

# ``--settings`` is a concrete-path flag attached by WER after private profile
# materialization.  It is not emitted in ``cli_flags``, but the typed profile
# must still version-gate that required attachment.  The executable provider's
# reviewed row gates every flag it directly enumerates; this exact companion
# row covers the path-bearing attachment that cannot appear in an
# attempt-independent argv.
_REVIEWED_RUNTIME_AUTHORITY_FLAGS_BY_VERSION = {
    "2.1.220": frozenset({"--settings"}),
    "2.1.250": frozenset({"--settings"}),
    "2.1.252": frozenset({"--settings"}),
}


class ClaudeHeadlessProfileError(RuntimeError):
    """The provider profile is ambiguous, unbounded, or does not replay."""


def _canonical_json(value: Mapping[str, Any]) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ClaudeHeadlessProfileError(
            "Claude headless profile is not canonical JSON"
        ) from exc


def _digest(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def _unique_strings(
    value: Sequence[str],
    *,
    label: str,
    pattern: re.Pattern[str] | None = None,
    require_nonempty: bool = False,
) -> list[str]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise ClaudeHeadlessProfileError(f"{label} must be a string sequence")
    result = list(value)
    if (
        any(
            not isinstance(item, str)
            or not item
            or (pattern is not None and pattern.fullmatch(item) is None)
            for item in result
        )
        or len(set(result)) != len(result)
        or (require_nonempty and not result)
    ):
        raise ClaudeHeadlessProfileError(
            f"{label} is empty, duplicated, or malformed"
        )
    return sorted(result)


def parse_claude_code_version(stdout: str) -> str:
    """Parse the complete canonical ``claude --version`` stdout."""

    if (
        not isinstance(stdout, str)
        or _VERSION_OUTPUT_RE.fullmatch(stdout) is None
    ):
        raise ClaudeHeadlessProfileError(
            "Claude Code version output is not canonical"
        )
    return stdout.split(" ", 1)[0]


def _profile_cli_flags(
    *,
    customization_mode: str,
    claude_code_version: str,
    permission_mode: str,
    builtin_tools: Sequence[str],
    restricted_analysis: bool,
    restricted_web_analysis: bool = False,
) -> list[str]:
    flags: list[str] = []
    if permission_mode == "bypassPermissions":
        flags.append("--dangerously-skip-permissions")
    elif restricted_analysis or restricted_web_analysis:
        if claude_code_version != "2.1.252":
            raise ClaudeHeadlessProfileError(
                "restricted analysis requires reviewed Claude Code 2.1.252"
            )
        # Claude Code >=2.1.248 makes this a real shared-machine harness
        # boundary: ambient user/project configuration is not loaded, command
        # and code tools are absent unless named explicitly, and built-in file
        # tools remain confined to working directories.  Plamen only uses the
        # non-interactive default-deny denominator together with this
        # restriction and explicit bound-settings allow rules.
        expected_mode = "default"
        if permission_mode != expected_mode:
            raise ClaudeHeadlessProfileError(
                "restricted analysis permission mode is inconsistent"
            )
        flags.extend(("--restricted", "--permission-mode", expected_mode))
    elif permission_mode == "default":
        raise ClaudeHeadlessProfileError(
            "default permission mode is restricted to reviewed analysis"
        )
    else:
        flags.extend(("--permission-mode", "dontAsk"))
    if customization_mode == "SAFE_MODE":
        flags.append("--safe-mode")
    flags.extend(
        (
            "--disable-slash-commands",
            "--setting-sources=",
            "--no-chrome",
            "--prompt-suggestions",
            "false",
            "--tools",
            ",".join(builtin_tools),
        )
    )
    if restricted_web_analysis:
        # Claude Code 2.1.252 deliberately forces default while
        # CLAUDE_CODE_SUBPROCESS_ENV_SCRUB is enabled.  Keep that hardening
        # and bind its explicit permission allowlist to the reviewed non-write
        # subset. Edit/Write remain settings-scoped; Web remains hook-scoped.
        flags.extend((
            "--allowedTools",
            ",".join(_RESTRICTED_NON_WRITE_ALLOWED_TOOLS),
        ))
    return flags


def _typed_profile_required_capabilities(
    *,
    customization_mode: str,
    claude_code_version: str,
    permission_mode: str,
    restricted_analysis: bool,
    restricted_web_analysis: bool = False,
) -> list[str]:
    capabilities = {
        "--disable-slash-commands",
        "--no-chrome",
        "--prompt-suggestions=false",
        "--setting-sources=",
        "--tools",
        "init-security-v2",
        (
            "--dangerously-skip-permissions"
            if permission_mode == "bypassPermissions"
            else f"--permission-mode={permission_mode}"
        ),
    }
    if restricted_analysis or restricted_web_analysis:
        expected_mode = "default"
        if permission_mode != expected_mode or claude_code_version != "2.1.252":
            raise ClaudeHeadlessProfileError(
                "restricted analysis capability is inconsistent"
            )
        capabilities.add("--restricted")
    if restricted_web_analysis:
        capabilities.add("--allowedTools")
    if customization_mode == "SAFE_MODE":
        capabilities.add("--safe-mode")
    else:
        capabilities.update(
            {"--mcp-config", "--settings", "--strict-mcp-config"}
        )
    return sorted(capabilities)


def _runtime_authority_flags(
    *,
    customization_mode: str,
    claude_code_version: str,
) -> list[str]:
    if customization_mode == "SAFE_MODE":
        return []
    reviewed = _REVIEWED_RUNTIME_AUTHORITY_FLAGS_BY_VERSION.get(
        claude_code_version
    )
    required = {"--settings"}
    if reviewed is None or not required.issubset(reviewed):
        raise ClaudeHeadlessProfileError(
            "Claude bound-settings runtime flags are not reviewed for "
            "this exact version"
        )
    return ["--mcp-config", "--settings", "--strict-mcp-config"]


def _valid_sha256(value: object) -> bool:
    return isinstance(value, str) and _SHA256_RE.fullmatch(value) is not None


def _replay_settings_authority(
    value: Mapping[str, Any],
) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ClaudeHeadlessProfileError(
            "Claude settings authority must be an object"
        )
    clone = dict(value)
    if set(clone) != {
        "schema",
        "mode",
        "settings_sha256",
        "external_policy_sha256",
        "authority_sha256",
    }:
        raise ClaudeHeadlessProfileError(
            "Claude settings authority fields drifted"
        )
    digest = clone.pop("authority_sha256")
    mode = clone.get("mode")
    settings_digest = clone.get("settings_sha256")
    policy_digest = clone.get("external_policy_sha256")
    if (
        clone.get("schema") != SETTINGS_AUTHORITY_SCHEMA
        or mode not in _TYPED_SETTINGS_MODES
        or (
            mode == "SAFE_MODE"
            and (
                settings_digest is not None
                or policy_digest is not None
            )
        )
        or (
            mode == "BOUND_SETTINGS"
            and (
                not _valid_sha256(settings_digest)
                or not _valid_sha256(policy_digest)
            )
        )
        or not _valid_sha256(digest)
        or digest != _digest(clone)
    ):
        raise ClaudeHeadlessProfileError(
            "Claude settings authority does not replay"
        )
    return {**clone, "authority_sha256": digest}


def _replay_mcp_authority(
    value: Mapping[str, Any],
    *,
    settings_mode: str,
) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ClaudeHeadlessProfileError(
            "Claude MCP authority must be an object"
        )
    clone = dict(value)
    legacy_fields = {
        "schema",
        "server_names",
        "source_manifest_sha256",
        "selected_config_sha256",
        "authority_sha256",
    }
    selection_fields = legacy_fields | {
        "runtime_selection",
        "runtime_selection_sha256",
    }
    if set(clone) not in {
        frozenset(legacy_fields),
        frozenset(selection_fields),
    }:
        raise ClaudeHeadlessProfileError(
            "Claude MCP authority fields drifted"
        )
    digest = clone.pop("authority_sha256")
    try:
        servers = _unique_strings(
            clone.get("server_names"),
            label="MCP authority server_names",
            pattern=_MCP_SERVER_RE,
        )
    except ClaudeHeadlessProfileError as exc:
        raise ClaudeHeadlessProfileError(
            f"Claude MCP authority does not replay: {exc}"
        ) from exc
    manifest_digest = clone.get("source_manifest_sha256")
    selected_digest = clone.get("selected_config_sha256")
    selection = clone.get("runtime_selection")
    selection_digest = clone.get("runtime_selection_sha256")
    if selection is not None:
        # Local import avoids the module-level launch-security/profile cycle.
        from claude_launch_security import (  # pylint: disable=import-outside-toplevel
            ClaudeLaunchSecurityError,
            mcp_current_selection_sha256,
            replay_mcp_current_selection,
        )

        try:
            selection = replay_mcp_current_selection(selection)
            expected_selection_digest = mcp_current_selection_sha256(
                selection
            )
        except ClaudeLaunchSecurityError as exc:
            raise ClaudeHeadlessProfileError(
                f"Claude MCP runtime selection does not replay: {exc}"
            ) from exc
    else:
        expected_selection_digest = None
    if (
        clone.get("schema")
        != (
            MCP_AUTHORITY_SCHEMA
            if selection is None
            else MCP_AUTHORITY_SELECTION_SCHEMA
        )
        or settings_mode not in _TYPED_SETTINGS_MODES
        or clone.get("server_names") != servers
        or (
            settings_mode == "SAFE_MODE"
            and (
                servers
                or manifest_digest is not None
                or selected_digest is not None
            )
        )
        or (
            settings_mode == "BOUND_SETTINGS"
            and (
                not _valid_sha256(selected_digest)
                or (bool(servers) != _valid_sha256(manifest_digest))
            )
        )
        or not _valid_sha256(digest)
        or selection_digest != expected_selection_digest
        or (
            selection is not None
            and any(
                server not in selection["server_launches"]
                for server in servers
            )
        )
        or digest != _digest(clone)
    ):
        raise ClaudeHeadlessProfileError(
            "Claude MCP authority does not replay"
        )
    if selection is not None:
        clone["runtime_selection"] = selection
    return {**clone, "authority_sha256": digest}


def compile_claude_headless_profile(
    *,
    claude_code_version: str,
    cwd: str,
    accepted_models: Sequence[str],
    permission_mode: str,
    builtin_tools: Sequence[str],
    required_tools: Sequence[str],
    forbidden_tools: Sequence[str],
    mcp_server_names: Sequence[str],
    customization_mode: str,
    accepted_api_key_sources: Sequence[str] = ("subscription", "user"),
    required_capabilities: Sequence[str] = (),
    forbidden_capabilities: Sequence[str] = ("remote-agents",),
    accepted_output_styles: Sequence[str] = ("default",),
) -> dict[str, Any]:
    """Compile exact CLI isolation flags and their expected init policy."""

    if (
        not isinstance(claude_code_version, str)
        or _VERSION_RE.fullmatch(claude_code_version) is None
    ):
        raise ClaudeHeadlessProfileError(
            "claude_code_version must be canonical semver"
        )
    if (
        not isinstance(cwd, str)
        or not cwd
        or cwd != cwd.strip()
        or "\x00" in cwd
    ):
        raise ClaudeHeadlessProfileError("cwd is malformed")
    if customization_mode not in _CUSTOMIZATION_MODES:
        raise ClaudeHeadlessProfileError(
            "customization mode is unsupported"
        )
    if permission_mode not in _PERMISSION_MODES:
        raise ClaudeHeadlessProfileError("permission mode is unsupported")

    models = _unique_strings(
        accepted_models,
        label="accepted_models",
        pattern=_MODEL_RE,
        require_nonempty=True,
    )
    tools = _unique_strings(
        builtin_tools,
        label="builtin_tools",
        pattern=_TOOL_RE,
        require_nonempty=True,
    )
    required = _unique_strings(
        required_tools,
        label="required_tools",
        pattern=_TOOL_RE,
        require_nonempty=True,
    )
    forbidden = _unique_strings(
        forbidden_tools,
        label="forbidden_tools",
        pattern=_TOOL_RE,
    )
    servers = _unique_strings(
        mcp_server_names,
        label="mcp_server_names",
        pattern=_MCP_SERVER_RE,
    )
    api_sources = _unique_strings(
        accepted_api_key_sources,
        label="accepted_api_key_sources",
        pattern=_TOOL_RE,
        require_nonempty=True,
    )
    required_caps = _unique_strings(
        required_capabilities,
        label="required_capabilities",
        pattern=_TOOL_RE,
    )
    restricted_analysis = RESTRICTED_ANALYSIS_CAPABILITY in required_caps
    restricted_web_analysis = RESTRICTED_WEB_ANALYSIS_CAPABILITY in required_caps
    if restricted_analysis and restricted_web_analysis:
        raise ClaudeHeadlessProfileError(
            "restricted filesystem and web capabilities are mutually exclusive"
        )
    reviewed_restricted = restricted_analysis or restricted_web_analysis
    forbidden_caps = _unique_strings(
        forbidden_capabilities,
        label="forbidden_capabilities",
        pattern=_TOOL_RE,
    )
    output_styles = _unique_strings(
        accepted_output_styles,
        label="accepted_output_styles",
        pattern=_TOOL_RE,
        require_nonempty=True,
    )
    if not set(required).issubset(tools):
        raise ClaudeHeadlessProfileError(
            "required tools exceed the built-in tool denominator"
        )
    if set(tools) & set(forbidden):
        raise ClaudeHeadlessProfileError(
            "allowed and forbidden tools overlap"
        )
    if customization_mode == "SAFE_MODE" and servers:
        raise ClaudeHeadlessProfileError(
            "safe mode disables configured MCP servers"
        )
    if permission_mode == "default" and not reviewed_restricted:
        raise ClaudeHeadlessProfileError(
            "default permission mode is restricted to reviewed analysis"
        )
    if restricted_analysis and (
        claude_code_version != REVIEWED_RESTRICTED_INIT_VERSION
        or permission_mode != "default"
    ):
        raise ClaudeHeadlessProfileError(
            "restricted analysis requires pinned default-deny authority"
        )
    if restricted_web_analysis and (
        claude_code_version != REVIEWED_RESTRICTED_INIT_VERSION
        or permission_mode != "default"
    ):
        raise ClaudeHeadlessProfileError(
            "restricted web analysis requires pinned scrubbed default hook authority"
        )

    expected = {
        "schema": EXPECTED_INIT_SECURITY_SCHEMA,
        "claude_code_version": claude_code_version,
        "cwd": cwd,
        "accepted_models": models,
        "permission_mode": permission_mode,
        "allowed_tools": tools,
        "allowed_tool_prefixes": ["mcp__"] if servers else [],
        "required_tools": required,
        "forbidden_tools": forbidden,
        "allowed_mcp_servers": servers,
        "required_mcp_servers": servers,
        "expected_plugins": [],
        "expected_skills": [],
        "expected_agents": (
            list(REVIEWED_RESTRICTED_INIT_AGENTS)
            if reviewed_restricted
            else []
        ),
        "accepted_api_key_sources": api_sources,
        "required_capabilities": required_caps,
        "expected_native_capabilities": (
            list(REVIEWED_RESTRICTED_INIT_CAPABILITIES)
            if reviewed_restricted
            else [
                capability
                for capability in required_caps
                if capability not in {
                    RESTRICTED_ANALYSIS_CAPABILITY,
                    RESTRICTED_WEB_ANALYSIS_CAPABILITY,
                }
            ]
        ),
        "forbidden_capabilities": forbidden_caps,
        "expected_slash_commands": [],
        "accepted_output_styles": output_styles,
    }
    try:
        expected = normalize_expected_init_contract(expected)
    except ClaudeStreamJsonEvidenceError as exc:
        raise ClaudeHeadlessProfileError(
            f"expected Claude init policy is invalid: {exc}"
        ) from exc
    core = {
        "schema": PROFILE_SCHEMA,
        "customization_mode": customization_mode,
        "claude_code_version": claude_code_version,
        "cli_flags": _profile_cli_flags(
            customization_mode=customization_mode,
            claude_code_version=claude_code_version,
            permission_mode=permission_mode,
            builtin_tools=tools,
            restricted_analysis=restricted_analysis,
            restricted_web_analysis=restricted_web_analysis,
        ),
        "expected_init_contract": expected,
    }
    return {**core, "profile_sha256": _digest(core)}


def compile_claude_headless_profile_from_authorities(
    *,
    executable_observation: Mapping[str, Any],
    auth_route_policy: Mapping[str, Any],
    settings_authority: Mapping[str, Any],
    mcp_authority: Mapping[str, Any],
    cwd: str,
    accepted_models: Sequence[str],
    permission_mode: str,
    builtin_tools: Sequence[str],
    required_tools: Sequence[str],
    forbidden_tools: Sequence[str],
    required_capabilities: Sequence[str] = (),
    forbidden_capabilities: Sequence[str] = ("remote-agents",),
    accepted_output_styles: Sequence[str] = ("default",),
) -> dict[str, Any]:
    """Compile a v2 profile only from replayed typed provider authorities.

    Version, customization mode, MCP denominator, and init auth vocabulary are
    derived rather than accepted as independently authored caller values.
    """

    # Local imports avoid an import cycle: executable observation reuses this
    # module's strict version-output parser.
    from claude_auth_route import (  # pylint: disable=import-outside-toplevel
        ClaudeAuthRouteError,
        replay_claude_auth_route_policy,
    )
    from claude_executable_observation import (  # pylint: disable=import-outside-toplevel
        ClaudeExecutableObservationError,
        compile_claude_executable_observation_reference,
        replay_claude_executable_observation,
    )

    try:
        executable = replay_claude_executable_observation(
            executable_observation
        )
        auth = replay_claude_auth_route_policy(auth_route_policy)
    except (
        ClaudeExecutableObservationError,
        ClaudeAuthRouteError,
    ) as exc:
        raise ClaudeHeadlessProfileError(
            f"Claude typed provider authority does not replay: {exc}"
        ) from exc
    settings = _replay_settings_authority(settings_authority)
    mcp = _replay_mcp_authority(
        mcp_authority,
        settings_mode=settings["mode"],
    )
    version = executable["claude_code_version"]
    mode = settings["mode"]
    if auth["claude_code_version"] != version:
        raise ClaudeHeadlessProfileError(
            "Claude executable and auth-route versions disagree"
        )
    if (
        auth["desired_route"] == "API_KEY_HELPER"
        and mode != "BOUND_SETTINGS"
    ):
        raise ClaudeHeadlessProfileError(
            "Claude apiKeyHelper requires bound settings authority"
        )
    required_cli_capabilities = _typed_profile_required_capabilities(
        customization_mode=mode,
        claude_code_version=version,
        permission_mode=permission_mode,
        restricted_analysis=(
            RESTRICTED_ANALYSIS_CAPABILITY in required_capabilities
        ),
        restricted_web_analysis=(
            RESTRICTED_WEB_ANALYSIS_CAPABILITY in required_capabilities
        ),
    )
    try:
        executable_reference = (
            compile_claude_executable_observation_reference(
                executable,
                required_capabilities=required_cli_capabilities,
            )
        )
    except ClaudeExecutableObservationError as exc:
        raise ClaudeHeadlessProfileError(
            f"Claude profile flags lack executable capability: {exc}"
        ) from exc
    runtime_flags = _runtime_authority_flags(
        customization_mode=mode,
        claude_code_version=version,
    )

    # Reuse the v1 semantic compiler for the exact init contract and
    # attempt-independent generic CLI flags, but derive all formerly
    # duplicated provider inputs above.
    legacy = compile_claude_headless_profile(
        claude_code_version=version,
        cwd=cwd,
        accepted_models=accepted_models,
        permission_mode=permission_mode,
        builtin_tools=builtin_tools,
        required_tools=required_tools,
        forbidden_tools=forbidden_tools,
        mcp_server_names=mcp["server_names"],
        customization_mode=mode,
        accepted_api_key_sources=auth[
            "expected_init_api_key_sources"
        ],
        required_capabilities=required_capabilities,
        forbidden_capabilities=forbidden_capabilities,
        accepted_output_styles=accepted_output_styles,
    )
    core = {
        "schema": TYPED_PROFILE_SCHEMA,
        "customization_mode": mode,
        "claude_code_version": version,
        "cli_flags": legacy["cli_flags"],
        "required_runtime_authority_flags": runtime_flags,
        "executable_observation_reference": executable_reference,
        "auth_route_policy": auth,
        "settings_authority": settings,
        "mcp_authority": mcp,
        "expected_init_contract": legacy["expected_init_contract"],
    }
    return {**core, "profile_sha256": _digest(core)}


def _replay_typed_claude_headless_profile(
    value: Mapping[str, Any],
) -> dict[str, Any]:
    from claude_auth_route import (  # pylint: disable=import-outside-toplevel
        ClaudeAuthRouteError,
        replay_claude_auth_route_policy,
    )
    from claude_executable_observation import (  # pylint: disable=import-outside-toplevel
        ClaudeExecutableObservationError,
        replay_claude_executable_observation_reference,
    )

    try:
        clone = json.loads(
            _canonical_json(dict(value)).decode("utf-8")
        )
    except (json.JSONDecodeError, UnicodeError) as exc:
        raise ClaudeHeadlessProfileError(
            "typed Claude headless profile JSON is invalid"
        ) from exc
    if not isinstance(clone, dict) or set(clone) != {
        "schema",
        "customization_mode",
        "claude_code_version",
        "cli_flags",
        "required_runtime_authority_flags",
        "executable_observation_reference",
        "auth_route_policy",
        "settings_authority",
        "mcp_authority",
        "expected_init_contract",
        "profile_sha256",
    }:
        raise ClaudeHeadlessProfileError(
            "typed Claude headless profile field denominator drifted"
        )
    digest = clone.pop("profile_sha256")
    if (
        clone.get("schema") != TYPED_PROFILE_SCHEMA
        or not _valid_sha256(digest)
        or digest != _digest(clone)
    ):
        raise ClaudeHeadlessProfileError(
            "typed Claude headless profile digest or schema drifted"
        )
    try:
        executable = replay_claude_executable_observation_reference(
            clone.get("executable_observation_reference")
        )
        auth = replay_claude_auth_route_policy(
            clone.get("auth_route_policy")
        )
        expected = normalize_expected_init_contract(
            clone.get("expected_init_contract")
        )
    except (
        ClaudeExecutableObservationError,
        ClaudeAuthRouteError,
        ClaudeStreamJsonEvidenceError,
    ) as exc:
        raise ClaudeHeadlessProfileError(
            f"typed Claude profile dependency does not replay: {exc}"
        ) from exc
    settings = _replay_settings_authority(
        clone.get("settings_authority")
    )
    mcp = _replay_mcp_authority(
        clone.get("mcp_authority"),
        settings_mode=settings["mode"],
    )
    version = executable["claude_code_version"]
    mode = settings["mode"]
    flags = _profile_cli_flags(
        customization_mode=mode,
        claude_code_version=version,
        permission_mode=expected.get("permission_mode"),
        builtin_tools=expected.get("allowed_tools", []),
        restricted_analysis=(
            RESTRICTED_ANALYSIS_CAPABILITY
            in expected.get("required_capabilities", [])
        ),
        restricted_web_analysis=(
            RESTRICTED_WEB_ANALYSIS_CAPABILITY
            in expected.get("required_capabilities", [])
        ),
    )
    required_cli_capabilities = _typed_profile_required_capabilities(
        customization_mode=mode,
        claude_code_version=version,
        permission_mode=expected.get("permission_mode"),
        restricted_analysis=(
            RESTRICTED_ANALYSIS_CAPABILITY
            in expected.get("required_capabilities", [])
        ),
        restricted_web_analysis=(
            RESTRICTED_WEB_ANALYSIS_CAPABILITY
            in expected.get("required_capabilities", [])
        ),
    )
    runtime_flags = _runtime_authority_flags(
        customization_mode=mode,
        claude_code_version=version,
    )
    if (
        clone.get("customization_mode") != mode
        or clone.get("claude_code_version") != version
        or auth["claude_code_version"] != version
        or clone.get("cli_flags") != flags
        or clone.get("required_runtime_authority_flags") != runtime_flags
        or executable["required_capabilities"]
        != required_cli_capabilities
        or clone.get("expected_init_contract") != expected
        or expected["claude_code_version"] != version
        or expected["accepted_api_key_sources"]
        != auth["expected_init_api_key_sources"]
        or expected["allowed_mcp_servers"] != mcp["server_names"]
        or expected["required_mcp_servers"] != mcp["server_names"]
        or (
            auth["desired_route"] == "API_KEY_HELPER"
            and mode != "BOUND_SETTINGS"
        )
    ):
        raise ClaudeHeadlessProfileError(
            "typed Claude version/auth/settings/MCP profile authorities "
            "disagree"
        )
    normalized = {
        **clone,
        "executable_observation_reference": executable,
        "auth_route_policy": auth,
        "settings_authority": settings,
        "mcp_authority": mcp,
        "expected_init_contract": expected,
    }
    return {**normalized, "profile_sha256": digest}


def replay_claude_headless_profile(
    value: Mapping[str, Any],
) -> dict[str, Any]:
    """Replay profile digest, expected-init policy, and canonical CLI flags."""

    if not isinstance(value, Mapping):
        raise ClaudeHeadlessProfileError("profile must be an object")
    if value.get("schema") == TYPED_PROFILE_SCHEMA:
        return _replay_typed_claude_headless_profile(value)
    try:
        clone = json.loads(
            _canonical_json(dict(value)).decode("utf-8")
        )
    except (json.JSONDecodeError, UnicodeError) as exc:
        raise ClaudeHeadlessProfileError("profile JSON is invalid") from exc
    expected_fields = {
        "schema",
        "customization_mode",
        "claude_code_version",
        "cli_flags",
        "expected_init_contract",
        "profile_sha256",
    }
    if not isinstance(clone, dict) or set(clone) != expected_fields:
        raise ClaudeHeadlessProfileError("profile field denominator drifted")
    digest = clone.pop("profile_sha256")
    if (
        not isinstance(digest, str)
        or _SHA256_RE.fullmatch(digest) is None
        or digest != _digest(clone)
        or clone.get("schema") != PROFILE_SCHEMA
    ):
        raise ClaudeHeadlessProfileError("profile digest or schema drifted")
    try:
        expected = normalize_expected_init_contract(
            clone.get("expected_init_contract")
        )
    except ClaudeStreamJsonEvidenceError as exc:
        raise ClaudeHeadlessProfileError(
            f"profile expected-init policy does not replay: {exc}"
        ) from exc
    if expected != clone.get("expected_init_contract"):
        raise ClaudeHeadlessProfileError(
            "profile expected-init policy is not canonical"
        )
    flags = _profile_cli_flags(
        customization_mode=str(clone.get("customization_mode") or ""),
        claude_code_version=str(clone.get("claude_code_version") or ""),
        permission_mode=str(expected.get("permission_mode") or ""),
        builtin_tools=expected.get("allowed_tools", []),
        restricted_analysis=(
            RESTRICTED_ANALYSIS_CAPABILITY
            in expected.get("required_capabilities", [])
        ),
        restricted_web_analysis=(
            RESTRICTED_WEB_ANALYSIS_CAPABILITY
            in expected.get("required_capabilities", [])
        ),
    )
    if flags != clone.get("cli_flags"):
        raise ClaudeHeadlessProfileError(
            "profile CLI flags disagree with expected init authority"
        )
    return {**clone, "profile_sha256": digest}


__all__ = [
    "ClaudeHeadlessProfileError",
    "PROFILE_SCHEMA",
    "TYPED_PROFILE_SCHEMA",
    "compile_claude_headless_profile",
    "compile_claude_headless_profile_from_authorities",
    "parse_claude_code_version",
    "replay_claude_headless_profile",
]
