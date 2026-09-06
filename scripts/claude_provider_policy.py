"""Shared public compiler for one Claude headless provider parent.

This module is the single backend-policy aggregation boundary used by regular
driver workers and selected-runtime consumers such as the private bug-bounty
wrapper.  It composes the lower-level public authorities from
``claude_provider_preparation`` without importing driver types or defaults.

The compiled policy is secret-free.  The resulting provider authority contains
opaque preparation/runtime-local values and must stay in the launching process;
it is not a serializable receipt or a substitute for WER/PhaseIO execution
authority.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping, Sequence

from claude_provider_preparation import (
    ClaudeProviderPreparation,
    ClaudeProviderPreparationError,
    compile_claude_mcp_policy,
    compile_claude_phase_tool_policy,
    compile_claude_provider_semantic_intent,
    compile_claude_settings_policy,
    prepare_claude_provider,
)


DEFAULT_AUTH_ROUTE = "STORED_SUBSCRIPTION_OAUTH"
DEFAULT_MAX_LINE_BYTES = 2 * 1024 * 1024
DEFAULT_MAX_STREAM_BYTES = 16 * 1024 * 1024
SAFE_BUILTIN_TOOLS = frozenset({
    "Bash",
    "Edit",
    "Glob",
    "Grep",
    "Read",
    "Write",
})
FUNCTIONAL_CONTROLS = MappingProxyType({
    "CLAUDE_CODE_DISABLE_AUTO_MEMORY": "1",
    "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
    "CLAUDE_CODE_DISABLE_OFFICIAL_MARKETPLACE_AUTOINSTALL": "1",
    "CLAUDE_CODE_SKIP_PROMPT_HISTORY": "1",
    "CLAUDE_CODE_SUBPROCESS_ENV_SCRUB": "1",
    "DISABLE_AUTOUPDATER": "1",
    "DISABLE_ERROR_REPORTING": "1",
    "DISABLE_TELEMETRY": "1",
    "DISABLE_UPDATES": "1",
    "ENABLE_CLAUDEAI_MCP_SERVERS": "false",
})


class ClaudeProviderPolicyError(ValueError):
    """The shared policy or host inputs cannot authorize a Claude parent."""


@dataclass(frozen=True)
class ClaudeHeadlessProviderPolicy:
    """Secret-free, attempt-independent policy selected before host binding."""

    phase: str
    launch_model: str
    accepted_models: tuple[str, ...]
    desired_auth_route: str
    max_line_bytes: int
    max_stream_bytes: int
    home_variable_policy: str
    phase_environment_policies: tuple[str, ...]
    functional_controls: Mapping[str, str]
    required_capabilities: tuple[str, ...]
    forbidden_capabilities: tuple[str, ...]
    accepted_output_styles: tuple[str, ...]
    phase_tool_policy: Mapping[str, Any]
    settings_policy: Mapping[str, Any]
    mcp_policy: Mapping[str, Any]


@dataclass(frozen=True)
class ClaudeHeadlessProviderAuthority:
    """Opaque process-local parent consumed by the public headless runtime."""

    preparation: ClaudeProviderPreparation = field(
        repr=False,
        compare=False,
    )
    base_argv_template: tuple[str, ...]
    public_arguments: Mapping[str, Any]
    runtime_local_inputs: Mapping[str, Any] = field(
        repr=False,
        compare=False,
    )
    bound_settings_bytes: bytes | None = field(
        default=None,
        repr=False,
        compare=False,
    )
    selected_mcp_config_bytes: bytes | None = field(
        default=None,
        repr=False,
        compare=False,
    )


def _strings(
    values: Sequence[str],
    *,
    label: str,
    nonempty: bool = False,
) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)):
        raise ClaudeProviderPolicyError(f"{label} must be a sequence")
    rows = tuple(str(value) for value in values)
    if (
        (nonempty and not rows)
        or any(not value or "\x00" in value for value in rows)
        or tuple(sorted(set(rows))) != rows
    ):
        raise ClaudeProviderPolicyError(
            f"{label} must be a sorted unique text denominator"
        )
    return rows


def standard_environment_policies(ecosystem: str) -> tuple[str, ...]:
    """Return the common reviewed environment denominator for an ecosystem."""

    normalized = str(ecosystem or "").strip().lower()
    policies = {"base", "certificates", "git", "plamen"}
    if normalized == "evm":
        policies.update({"evm", "node"})
    elif normalized == "solana":
        policies.update({"node", "rust", "solana"})
    elif normalized == "aptos":
        policies.update({"aptos", "node", "rust"})
    elif normalized == "sui":
        policies.update({"node", "rust", "sui"})
    elif normalized == "soroban":
        policies.update({"node", "rust", "soroban"})
    elif normalized in {"l1", "l1-native", "go", "rust"}:
        policies.update({"go", "l1-native", "node", "rust"})
    elif normalized not in {"", "generic"}:
        raise ClaudeProviderPolicyError(
            f"unsupported Claude provider ecosystem: {ecosystem!r}"
        )
    return tuple(sorted(policies))


def compile_claude_headless_provider_policy(
    *,
    phase: str,
    launch_model: str,
    accepted_models: Sequence[str],
    desired_auth_route: str,
    phase_environment_policies: Sequence[str],
    functional_controls: Mapping[str, str],
    permission_mode: str,
    builtin_tools: Sequence[str],
    required_tools: Sequence[str],
    forbidden_tools: Sequence[str],
    settings_mode: str,
    settings_sha256: str | None,
    external_policy_sha256: str | None,
    mcp_server_names: Sequence[str],
    mcp_source_manifest_sha256: str | None,
    selected_mcp_config_sha256: str | None,
    mcp_runtime_selection: Mapping[str, Any] | None = None,
    max_line_bytes: int = DEFAULT_MAX_LINE_BYTES,
    max_stream_bytes: int = DEFAULT_MAX_STREAM_BYTES,
    home_variable_policy: str = "PRESERVE_TOOLCHAIN_HOME",
    required_capabilities: Sequence[str] = (),
    forbidden_capabilities: Sequence[str] = ("remote-agents",),
    accepted_output_styles: Sequence[str] = ("default",),
) -> ClaudeHeadlessProviderPolicy:
    """Compile the exact public policy without observing host or credentials."""

    phase_n = str(phase or "")
    model = str(launch_model or "")
    models = _strings(
        accepted_models,
        label="accepted_models",
        nonempty=True,
    )
    environments = _strings(
        phase_environment_policies,
        label="phase_environment_policies",
        nonempty=True,
    )
    required_caps = _strings(
        required_capabilities,
        label="required_capabilities",
    )
    forbidden_caps = _strings(
        forbidden_capabilities,
        label="forbidden_capabilities",
    )
    styles = _strings(
        accepted_output_styles,
        label="accepted_output_styles",
        nonempty=True,
    )
    if (
        not phase_n
        or "\x00" in phase_n
        or not model
        or "\x00" in model
        or model not in models
    ):
        raise ClaudeProviderPolicyError(
            "phase/model policy is malformed"
        )
    if (
        not isinstance(functional_controls, Mapping)
        or any(
            not isinstance(name, str)
            or not name
            or "\x00" in name
            or not isinstance(value, str)
            or "\x00" in value
            for name, value in functional_controls.items()
        )
    ):
        raise ClaudeProviderPolicyError(
            "functional controls are malformed"
        )
    try:
        tool_policy = compile_claude_phase_tool_policy(
            phase=phase_n,
            permission_mode=permission_mode,
            builtin_tools=builtin_tools,
            required_tools=required_tools,
            forbidden_tools=forbidden_tools,
        )
        settings_policy = compile_claude_settings_policy(
            mode=settings_mode,
            settings_sha256=settings_sha256,
            external_policy_sha256=external_policy_sha256,
        )
        mcp_policy = compile_claude_mcp_policy(
            settings_mode=settings_mode,
            server_names=mcp_server_names,
            source_manifest_sha256=mcp_source_manifest_sha256,
            selected_config_sha256=selected_mcp_config_sha256,
            runtime_selection=mcp_runtime_selection,
        )
    except ClaudeProviderPreparationError as exc:
        raise ClaudeProviderPolicyError(
            f"lower-level Claude policy is invalid: {exc}"
        ) from exc
    return ClaudeHeadlessProviderPolicy(
        phase=phase_n,
        launch_model=model,
        accepted_models=models,
        desired_auth_route=str(desired_auth_route),
        max_line_bytes=int(max_line_bytes),
        max_stream_bytes=int(max_stream_bytes),
        home_variable_policy=str(home_variable_policy),
        phase_environment_policies=environments,
        functional_controls=MappingProxyType(
            dict(sorted(functional_controls.items()))
        ),
        required_capabilities=required_caps,
        forbidden_capabilities=forbidden_caps,
        accepted_output_styles=styles,
        phase_tool_policy=MappingProxyType(dict(tool_policy)),
        settings_policy=MappingProxyType(dict(settings_policy)),
        mcp_policy=MappingProxyType(dict(mcp_policy)),
    )


def compile_standard_claude_headless_provider_policy(
    *,
    phase: str,
    launch_model: str,
    ecosystem: str,
    tool_policy: Sequence[str],
    desired_auth_route: str,
    mcp_runtime_selection: Mapping[str, Any] | None = None,
) -> ClaudeHeadlessProviderPolicy:
    """Compile the standard non-exact, non-MCP production policy."""

    declared = set(_strings(
        tool_policy,
        label="tool_policy",
    ))
    unsupported = declared - {"filesystem", "network"}
    if unsupported:
        raise ClaudeProviderPolicyError(
            "standard Claude tool policy is unsupported: "
            + ", ".join(sorted(unsupported))
        )
    builtin = set(SAFE_BUILTIN_TOOLS)
    forbidden = {"Agent", "Task"}
    if "network" in declared:
        builtin.update({"WebFetch", "WebSearch"})
    else:
        forbidden.update({"WebFetch", "WebSearch"})
    return compile_claude_headless_provider_policy(
        phase=phase,
        launch_model=launch_model,
        accepted_models=(launch_model,),
        desired_auth_route=desired_auth_route,
        phase_environment_policies=standard_environment_policies(
            ecosystem
        ),
        functional_controls=FUNCTIONAL_CONTROLS,
        permission_mode="bypassPermissions",
        builtin_tools=tuple(sorted(builtin)),
        required_tools=("Read", "Write"),
        forbidden_tools=tuple(sorted(forbidden)),
        settings_mode="SAFE_MODE",
        settings_sha256=None,
        external_policy_sha256=None,
        mcp_server_names=(),
        mcp_source_manifest_sha256=None,
        selected_mcp_config_sha256=None,
        mcp_runtime_selection=mcp_runtime_selection,
    )


def _digest_matches(raw: bytes | None, expected: str | None) -> bool:
    if raw is None:
        return expected is None
    return (
        isinstance(expected, str)
        and hashlib.sha256(raw).hexdigest() == expected
    )


def compile_claude_headless_provider_authority(
    *,
    policy: ClaudeHeadlessProviderPolicy,
    run_id: str,
    cwd: str | Path,
    session_id: str,
    configured_claude_bin: str,
    ambient_environment: Mapping[str, str],
    settings_evidence: Mapping[str, Any],
    stored_subscription_source_path: str | Path | None,
    source_config_dir: str | Path | None,
    project_root: str | Path,
    trusted_cwds: Sequence[str | Path],
    startup_authority_binding: Mapping[str, Any],
    startup_scratchpad: str | Path,
    source_snapshot_sha256: str,
    bound_settings_bytes: bytes | None = None,
    selected_mcp_config_bytes: bytes | None = None,
) -> ClaudeHeadlessProviderAuthority:
    """Bind one secret-free policy to exact host and startup authorities."""

    if not isinstance(policy, ClaudeHeadlessProviderPolicy):
        raise ClaudeProviderPolicyError(
            "Claude provider policy type is invalid"
        )
    if (
        not _digest_matches(
            bound_settings_bytes,
            policy.settings_policy["settings_sha256"],
        )
        or not _digest_matches(
            selected_mcp_config_bytes,
            policy.mcp_policy["selected_config_sha256"],
        )
    ):
        raise ClaudeProviderPolicyError(
            "runtime settings/MCP bytes differ from public policy"
        )
    cwd_path = Path(cwd).resolve(strict=True)
    trusted = tuple(Path(value).resolve(strict=True) for value in trusted_cwds)
    if cwd_path not in trusted:
        raise ClaudeProviderPolicyError(
            "runtime cwd is absent from trusted cwd denominator"
        )
    try:
        semantic_intent = compile_claude_provider_semantic_intent(
            run_id=run_id,
            phase=policy.phase,
            backend="claude",
            launch_model=policy.launch_model,
            accepted_models=policy.accepted_models,
            cwd=str(cwd_path),
            session_id=session_id,
            max_line_bytes=policy.max_line_bytes,
            max_stream_bytes=policy.max_stream_bytes,
            desired_auth_route=policy.desired_auth_route,
            home_variable_policy=policy.home_variable_policy,
            phase_environment_policies=(
                policy.phase_environment_policies
            ),
            functional_controls=policy.functional_controls,
            required_capabilities=policy.required_capabilities,
            forbidden_capabilities=policy.forbidden_capabilities,
            accepted_output_styles=policy.accepted_output_styles,
        )
        preparation = prepare_claude_provider(
            semantic_intent=semantic_intent,
            phase_tool_policy=policy.phase_tool_policy,
            settings_policy=policy.settings_policy,
            mcp_policy=policy.mcp_policy,
            configured_claude_bin=configured_claude_bin,
            ambient_environment=ambient_environment,
            settings_evidence=settings_evidence,
            stored_subscription_source_path=(
                stored_subscription_source_path
            ),
            source_config_dir=source_config_dir,
            project_root=project_root,
            trusted_cwds=trusted,
            startup_authority_binding=startup_authority_binding,
            startup_scratchpad=startup_scratchpad,
            source_snapshot_sha256=source_snapshot_sha256,
        )
        if not preparation.eligible:
            debt = preparation.record["debts"][0]
            raise ClaudeProviderPolicyError(
                "Claude provider preparation carries authority debt: "
                f"{debt['code']} ({debt['subject']})"
            )
        public = preparation.public_headless_arguments()
        profile_flags = tuple(
            preparation.record["headless_profile"]["cli_flags"]
        )
        final_template = preparation.command_for_bound_stdin()
    except ClaudeProviderPreparationError as exc:
        raise ClaudeProviderPolicyError(
            f"Claude provider preparation failed: {exc}"
        ) from exc
    if (
        not profile_flags
        or tuple(final_template[-len(profile_flags):]) != profile_flags
    ):
        raise ClaudeProviderPolicyError(
            "Claude provider command template is not canonically separable"
        )
    command_template = tuple(final_template[:-len(profile_flags)])
    if (
        command_template.count("-p") != 1
        or command_template.count("--model") != 1
        or command_template.index("--model")
        != command_template.index("-p") + 1
        or public.get("environment") != {}
        or not public.get("environment_allowlist")
    ):
        raise ClaudeProviderPolicyError(
            "Claude provider preparation is not a complete public parent"
        )
    return ClaudeHeadlessProviderAuthority(
        preparation=preparation,
        base_argv_template=tuple(command_template),
        public_arguments=MappingProxyType(dict(public)),
        runtime_local_inputs=MappingProxyType({
            "ambient_environment": dict(ambient_environment),
            "source_config_dir": source_config_dir,
            "trusted_cwds": trusted,
        }),
        bound_settings_bytes=(
            None
            if bound_settings_bytes is None
            else bytes(bound_settings_bytes)
        ),
        selected_mcp_config_bytes=(
            None
            if selected_mcp_config_bytes is None
            else bytes(selected_mcp_config_bytes)
        ),
    )


__all__ = [
    "DEFAULT_AUTH_ROUTE",
    "DEFAULT_MAX_LINE_BYTES",
    "DEFAULT_MAX_STREAM_BYTES",
    "FUNCTIONAL_CONTROLS",
    "SAFE_BUILTIN_TOOLS",
    "ClaudeHeadlessProviderAuthority",
    "ClaudeHeadlessProviderPolicy",
    "ClaudeProviderPolicyError",
    "compile_claude_headless_provider_authority",
    "compile_claude_headless_provider_policy",
    "compile_standard_claude_headless_provider_policy",
    "standard_environment_policies",
]
