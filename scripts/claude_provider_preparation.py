"""Unified, attempt-independent Claude provider-policy preparation.

This module composes the reviewed Claude executable, authentication, profile,
stream, child-environment, and launch-security providers.  Durable package
bytes contain no credential value, profile/source path, attempt identity, or
secret-derived content digest.

Runtime host values and bound settings/MCP bytes are attached separately for
each attempt.  The attachment is opaque, one-shot, and cannot change the
durable WorkPlan preparation digest.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys
import threading
from types import MappingProxyType
from typing import Any, ClassVar, NoReturn
import uuid
import weakref

import auxiliary_writable_root_startup as _startup_module
import claude_auth_route as _auth_module
import claude_child_environment as _child_module
import claude_executable_observation as _executable_module
import claude_headless_profile as _profile_module
import claude_launch_security as _launch_module
import claude_runtime_materialization as _runtime_module
import claude_stored_subscription_source as _stored_module
import claude_stream_json_evidence as _stream_module

from auxiliary_writable_root_startup import (
    AuxiliaryWritableRootStartupError,
    replay_startup_permit_binding,
)
from claude_auth_route import (
    ClaudeAuthRouteError,
    PromotedStoredSubscriptionSourceEvidence,
    classify_claude_auth_route,
    compile_claude_auth_route_policy,
    observe_claude_auth_sources,
    replay_claude_auth_route,
    replay_claude_auth_route_policy,
    replay_claude_auth_source_observation,
)
from claude_child_environment import (
    ClaudeChildEnvironmentError,
    planned_claude_child_environment_key_set_sha256,
    planned_claude_child_environment_names,
)
from claude_executable_observation import (
    ClaudeExecutableObservationError,
    observe_claude_executable,
    observe_claude_generation_backend,
    replay_claude_executable_observation,
)
from claude_headless_profile import (
    ClaudeHeadlessProfileError,
    compile_claude_headless_profile_from_authorities,
    replay_claude_headless_profile,
)
from claude_launch_security import (
    ClaudeLaunchSecurityError,
    compile_claude_launch_security,
    compile_claude_launch_security_request,
    compile_claude_mcp_authority,
    compile_claude_settings_authority,
    mcp_current_selection_sha256,
    replay_mcp_current_selection,
    replay_claude_launch_security,
    replay_claude_launch_security_request,
)
from claude_runtime_materialization import (
    ClaudeRuntimeHostInputs,
    ClaudeRuntimeMaterializationError,
    compile_claude_runtime_host_inputs,
)
from claude_stored_subscription_source import (
    ClaudeStoredSubscriptionSourceError,
    observe_stored_subscription_source_authority,
    replay_stored_subscription_source_observation,
)
from claude_stream_json_evidence import (
    ClaudeStreamJsonEvidenceError,
    normalize_expected_init_contract,
)


SEMANTIC_INTENT_SCHEMA = "plamen.claude_provider_semantic_intent.v1"
PHASE_TOOL_POLICY_SCHEMA = "plamen.claude_phase_tool_boundary.v1"
SETTINGS_POLICY_SCHEMA = "plamen.claude_provider_settings_policy.v1"
MCP_POLICY_SCHEMA = "plamen.claude_provider_mcp_policy.v1"
RUNTIME_HOST_POLICY_SCHEMA = "plamen.claude_runtime_host_policy.v2"
PROVIDER_PREPARATION_SCHEMA = "plamen.claude_provider_preparation.v1"
RUNTIME_ATTACHMENT_SCHEMA = "plamen.claude_provider_runtime_attachment.v1"
CLAUDE_STREAM_STDOUT_CONFIGURATION_SCHEMA = (
    "plamen.claude_stream_stdout_configuration.v1"
)
PROMPT_PLACEHOLDER = "<PLAMEN_PROMPT_UTF8>"

MAX_LINE_BYTES = 2 * 1024 * 1024
MAX_STREAM_BYTES = 64 * 1024 * 1024
MAX_BOUND_SOURCE_BYTES = 8 * 1024 * 1024
_LINUX_OSRELEASE_PATH = Path("/proc/sys/kernel/osrelease")
_MAX_LINUX_OSRELEASE_BYTES = 4096
_WSL_KERNEL_MARKER_RE = re.compile(
    r"(?<![a-z0-9])(?:microsoft|wsl[12]?)(?![a-z0-9])",
    flags=re.ASCII | re.IGNORECASE,
)

DEBT_CODES = frozenset(
    {
        "CLAUDE_EXECUTABLE_UNAVAILABLE",
        "CLAUDE_EXECUTABLE_OBSERVATION_FAILED",
        "CLAUDE_VERSION_UNSUPPORTED",
        "CLAUDE_IMPLEMENTATION_CLOSURE_UNBOUND",
        "CLAUDE_STORED_SOURCE_UNSUPPORTED",
        "CLAUDE_STORED_SOURCE_AUTHORITY_UNAVAILABLE",
        "CLAUDE_AUTH_ROUTE_UNAVAILABLE",
        "CLAUDE_AUTH_POLICY_UNSUPPORTED",
        "CLAUDE_PROFILE_UNSUPPORTED",
        "CLAUDE_TOOL_POLICY_UNSUPPORTED",
        "CLAUDE_HOST_UNSUPPORTED",
        "CLAUDE_RUNTIME_HOST_POLICY_UNSUPPORTED",
        "CLAUDE_BOUND_SETTINGS_REQUIRED",
        "CLAUDE_BOUND_MCP_CONFIG_REQUIRED",
        "CLAUDE_BOUND_SETTINGS_DRIFT",
        "CLAUDE_BOUND_MCP_CONFIG_DRIFT",
        "CLAUDE_BOUND_SOURCE_SECRET_UNSUPPORTED",
        "CLAUDE_RUNTIME_ATTACHMENT_DRIFT",
    }
)

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
_SAFE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,191}$", re.ASCII)
_MODEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/@-]{0,255}$", re.ASCII)
_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.:-]{0,127}$", re.ASCII)
_TOOL_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.:-]{0,127}$", re.ASCII)
_SERVER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$", re.ASCII)
_ATTACHMENT_RE = re.compile(r"^[0-9a-f]{32}$", re.ASCII)
_ALLOWED_BACKENDS = frozenset({"claude", "codex"})
_ALLOWED_ROUTES = frozenset(
    {"STORED_SUBSCRIPTION_OAUTH", "OAUTH_TOKEN"}
)
_HOST_FAMILIES = frozenset(
    {"windows", "linux", "wsl2", "macos", "unsupported"}
)
_SETTINGS_MODES = frozenset({"SAFE_MODE", "BOUND_SETTINGS"})
_PERMISSION_MODES = frozenset(
    {"default", "dontAsk", "bypassPermissions"}
)
_HOME_POLICIES = frozenset(
    {"PRESERVE_TOOLCHAIN_HOME", "PRIVATE_HOME"}
)
_PROMOTION_TOKEN = object()
_ATTACHMENT_TOKEN = object()
_ISSUANCE_LOCK = threading.RLock()
_PREPARATION_PENDING: dict[str, tuple[bytes, str, str]] = {}
_PREPARATION_ISSUED: dict[
    int, tuple[weakref.ReferenceType[Any], str, str, str, int]
] = {}
_BOUND_PENDING: dict[str, dict[str, Any]] = {}
_BOUND_ISSUED: dict[
    int, tuple[weakref.ReferenceType[Any], dict[str, Any]]
] = {}
_CLAIMED_PENDING: dict[str, dict[str, Any]] = {}
_CLAIMED_ISSUED: dict[
    int, tuple[weakref.ReferenceType[Any], dict[str, Any]]
] = {}


def _build_claimed_runtime_one_shot_ledger():
    """Track handoff consumption without treating the ledger as authority."""

    lock = threading.RLock()
    ledger: weakref.WeakKeyDictionary[Any, tuple[int, bool]] = (
        weakref.WeakKeyDictionary()
    )

    def register(value: Any) -> None:
        with lock:
            ledger[value] = (os.getpid(), False)

    def consume(value: Any) -> None:
        with lock:
            current = ledger.get(value)
            if (
                current is None
                or current[0] != os.getpid()
                or current[1]
            ):
                raise ClaudeProviderPreparationError(
                    "claimed Claude provider runtime was already consumed"
                )
            ledger[value] = (current[0], True)

    return register, consume


(
    _register_claimed_runtime_one_shot,
    _consume_claimed_runtime_one_shot,
) = _build_claimed_runtime_one_shot_ledger()

_INTENT_KEYS = frozenset(
    {
        "schema",
        "run_id",
        "phase",
        "backend",
        "launch_model",
        "accepted_models",
        "cwd",
        "session_id",
        "max_line_bytes",
        "max_stream_bytes",
        "desired_auth_route",
        "home_variable_policy",
        "phase_environment_policies",
        "functional_controls",
        "required_capabilities",
        "forbidden_capabilities",
        "accepted_output_styles",
        "intent_sha256",
    }
)
_TOOL_POLICY_KEYS = frozenset(
    {
        "schema",
        "phase",
        "permission_mode",
        "builtin_tools",
        "required_tools",
        "forbidden_tools",
        "phase_tool_policy_sha256",
    }
)
_SETTINGS_POLICY_KEYS = frozenset(
    {
        "schema",
        "mode",
        "settings_sha256",
        "external_policy_sha256",
        "settings_policy_sha256",
    }
)
_MCP_POLICY_KEYS = frozenset(
    {
        "schema",
        "settings_mode",
        "server_names",
        "source_manifest_sha256",
        "selected_config_sha256",
        "mcp_policy_sha256",
    }
)
_HOST_POLICY_KEYS = frozenset(
    {
        "schema",
        "host_family",
        "auth_route",
        "ambient_environment_names",
        "ambient_key_set_sha256",
        "source_configured",
        "source_store_class",
        "source_observation_sha256",
        "source_config_dir_identity_sha256",
        "project_root_identity_sha256",
        "runtime_cwd_identity_sha256",
        "trusted_cwds_identity_sha256",
        "trusted_cwd_count",
        "startup_authority_sha256",
        "source_snapshot_sha256",
        "credential_values_recorded",
        "credential_content_hashes_recorded",
        "host_paths_recorded",
        "policy_sha256",
    }
)
_DEBT_KEYS = frozenset({"code", "subject", "evidence_sha256"})
_PREPARATION_KEYS = frozenset(
    {
        "schema",
        "backend",
        "semantic_intent",
        "phase_tool_policy",
        "settings_policy",
        "mcp_policy",
        "startup_authority_sha256",
        "source_snapshot_sha256",
        "executable_observation",
        "auth_source_observation",
        "auth_route_observation",
        "auth_route_policy",
        "settings_authority",
        "mcp_authority",
        "headless_profile",
        "launch_security",
        "launch_security_request",
        "stream_configuration",
        "runtime_host_policy",
        "planned_child_environment_names",
        "command_template",
        "implementation_closure",
        "debts",
        "preparation_sha256",
    }
)

_IMPLEMENTATION_MODULES = (
    _startup_module,
    _auth_module,
    _child_module,
    _executable_module,
    _profile_module,
    _launch_module,
    _runtime_module,
    _stored_module,
    _stream_module,
)

_SENSITIVE_KEY_FRAGMENTS = (
    "api_key",
    "apikey",
    "auth_token",
    "access_token",
    "client_secret",
    "password",
    "credential",
    "private_key",
)
_SENSITIVE_VALUE_PATTERNS = (
    re.compile(r"sk-ant-[A-Za-z0-9_-]{4,}", re.ASCII),
    re.compile(r"(?i)bearer[ \t]+[A-Za-z0-9._~+/-]{4,}"),
)


class ClaudeProviderPreparationError(RuntimeError):
    """Provider preparation or runtime attachment is not authoritative."""

    def __init__(
        self,
        message: str,
        *,
        debt: Mapping[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.debt = None if debt is None else dict(debt)


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ClaudeProviderPreparationError(
            "Claude provider authority is not canonical JSON"
        ) from exc


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _strict_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for name, value in pairs:
        if name in result:
            raise ClaudeProviderPreparationError(
                "Claude provider authority has duplicate JSON keys"
            )
        result[name] = value
    return result


def _reject_float(_value: str) -> NoReturn:
    raise ClaudeProviderPreparationError(
        "Claude provider authority cannot contain floating-point values"
    )


def _decode(raw: bytes) -> dict[str, Any]:
    if not isinstance(raw, bytes):
        raise ClaudeProviderPreparationError(
            "Claude provider authority bytes are required"
        )
    try:
        value = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_strict_pairs,
            parse_float=_reject_float,
            parse_constant=_reject_float,
        )
    except (
        UnicodeError,
        json.JSONDecodeError,
        ClaudeProviderPreparationError,
    ) as exc:
        if isinstance(exc, ClaudeProviderPreparationError):
            raise
        raise ClaudeProviderPreparationError(
            "Claude provider authority JSON is invalid"
        ) from exc
    if not isinstance(value, dict):
        raise ClaudeProviderPreparationError(
            "Claude provider authority must be a JSON object"
        )
    return value


def _exact_keys(
    value: Mapping[str, Any],
    expected: frozenset[str],
    label: str,
) -> None:
    if not isinstance(value, Mapping):
        raise ClaudeProviderPreparationError(f"{label} must be an object")
    actual = set(value)
    if actual != expected:
        raise ClaudeProviderPreparationError(
            f"{label} fields drifted; "
            f"missing={sorted(expected - actual)}, "
            f"extra={sorted(actual - expected)}"
        )


def _sha256(value: Any, label: str, *, optional: bool = False) -> str | None:
    if optional and value is None:
        return None
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise ClaudeProviderPreparationError(
            f"{label} must be a lowercase SHA-256 digest"
        )
    return value


def _register_issued(
    registry: dict[
        int, tuple[weakref.ReferenceType[Any], Any]
    ],
    value: Any,
    state: Any,
) -> None:
    """Register authority state outside caller-mutable instance slots."""

    key = id(value)

    def retire(reference: weakref.ReferenceType[Any]) -> None:
        with _ISSUANCE_LOCK:
            current = registry.get(key)
            if current is not None and current[0] is reference:
                registry.pop(key, None)

    reference = weakref.ref(value, retire)
    if isinstance(state, dict):
        state = {**state, "issuer_pid": os.getpid()}
    registry[key] = (reference, state)


def _issued_state(
    registry: Mapping[
        int, tuple[weakref.ReferenceType[Any], Any]
    ],
    value: Any,
    *,
    label: str,
) -> Any:
    current = registry.get(id(value))
    if current is None or current[0]() is not value:
        raise ClaudeProviderPreparationError(
            f"{label} was not issued by the provider validator"
        )
    state = current[1]
    if (
        isinstance(state, Mapping)
        and state.get("issuer_pid") != os.getpid()
    ):
        raise ClaudeProviderPreparationError(
            f"{label} cannot cross a process boundary"
        )
    return state


def _canonical_directory_identity(
    value: str | os.PathLike[str],
    *,
    label: str,
) -> tuple[Path, str]:
    """Observe one non-aliased directory without recording its path."""

    try:
        candidate = Path(value)
        absolute = Path(os.path.abspath(candidate))
        info = absolute.lstat()
        resolved = absolute.resolve(strict=True)
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        raise ClaudeProviderPreparationError(
            f"{label} is unavailable"
        ) from exc
    if (
        resolved != absolute
        or not stat.S_ISDIR(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or bool(int(getattr(info, "st_file_attributes", 0)) & 0x400)
    ):
        raise ClaudeProviderPreparationError(
            f"{label} is not one canonical directory"
        )
    identity = {
        "device": int(info.st_dev),
        "inode": int(info.st_ino),
        "mode_type": int(stat.S_IFMT(info.st_mode)),
        "file_attributes": int(
            getattr(info, "st_file_attributes", 0)
        ),
    }
    return resolved, _digest(identity)


def _trusted_cwds_identity(digests: Sequence[str]) -> str:
    normalized = sorted(
        _sha256(value, "trusted cwd identity") for value in digests
    )
    if len(normalized) != len(set(normalized)):
        raise ClaudeProviderPreparationError(
            "trusted cwd identity denominator is duplicated"
        )
    return _digest(
        {
            "schema": "plamen.claude_trusted_cwds_identity.v1",
            "directory_identity_sha256s": normalized,
        }
    )


def _positive_int(value: Any, label: str, maximum: int) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value <= 0
        or value > maximum
    ):
        raise ClaudeProviderPreparationError(
            f"{label} must be a positive bounded integer"
        )
    return value


def _safe_id(value: Any, label: str) -> str:
    if not isinstance(value, str) or _SAFE_ID_RE.fullmatch(value) is None:
        raise ClaudeProviderPreparationError(f"{label} is malformed")
    return value


def _unique_strings(
    values: Sequence[str],
    *,
    label: str,
    pattern: re.Pattern[str],
    nonempty: bool = False,
) -> list[str]:
    if isinstance(values, (str, bytes)) or not isinstance(values, Sequence):
        raise ClaudeProviderPreparationError(
            f"{label} must be a string sequence"
        )
    result = list(values)
    if (
        (nonempty and not result)
        or any(
            not isinstance(item, str)
            or pattern.fullmatch(item) is None
            for item in result
        )
        or len(result) != len(set(result))
    ):
        raise ClaudeProviderPreparationError(
            f"{label} is empty, duplicated, or malformed"
        )
    return sorted(result)


def _mapping_strings(
    value: Mapping[str, str],
    *,
    label: str,
) -> dict[str, str]:
    if not isinstance(value, Mapping):
        raise ClaudeProviderPreparationError(f"{label} must be an object")
    result: dict[str, str] = {}
    folded: set[str] = set()
    for name, raw in value.items():
        if (
            not isinstance(name, str)
            or not name
            or "=" in name
            or "\x00" in name
            or not isinstance(raw, str)
            or "\x00" in raw
        ):
            raise ClaudeProviderPreparationError(f"{label} is malformed")
        lowered = name.casefold()
        if lowered in folded:
            raise ClaudeProviderPreparationError(
                f"{label} is case-ambiguous"
            )
        folded.add(lowered)
        result[name] = raw
    return result


def _key_set_sha256(names: Sequence[str]) -> str:
    folded = [name.casefold() for name in names]
    if len(folded) != len(set(folded)):
        raise ClaudeProviderPreparationError(
            "environment key denominator is case-ambiguous"
        )
    return hashlib.sha256(
        "\0".join(sorted(folded)).encode("utf-8")
    ).hexdigest()


def _compile_digest_record(
    core: Mapping[str, Any],
    digest_field: str,
) -> dict[str, Any]:
    return {**dict(core), digest_field: _digest(core)}


def compile_claude_provider_semantic_intent(
    *,
    run_id: str,
    phase: str,
    backend: str,
    launch_model: str,
    accepted_models: Sequence[str],
    cwd: str,
    session_id: str,
    max_line_bytes: int,
    max_stream_bytes: int,
    desired_auth_route: str,
    home_variable_policy: str,
    phase_environment_policies: Sequence[str],
    functional_controls: Mapping[str, str],
    required_capabilities: Sequence[str] = (),
    forbidden_capabilities: Sequence[str] = ("remote-agents",),
    accepted_output_styles: Sequence[str] = ("default",),
) -> dict[str, Any]:
    """Compile the driver's attempt-independent Claude semantic intent."""

    run = _safe_id(run_id, "run_id")
    phase_n = _safe_id(phase, "phase")
    if backend not in _ALLOWED_BACKENDS:
        raise ClaudeProviderPreparationError("backend is unsupported")
    if not isinstance(launch_model, str) or _MODEL_RE.fullmatch(
        launch_model
    ) is None:
        raise ClaudeProviderPreparationError("launch model is malformed")
    models = _unique_strings(
        accepted_models,
        label="accepted_models",
        pattern=_MODEL_RE,
        nonempty=True,
    )
    if launch_model not in models:
        raise ClaudeProviderPreparationError(
            "launch model is absent from accepted model denominator"
        )
    if (
        not isinstance(cwd, str)
        or not Path(cwd).is_absolute()
        or "\x00" in cwd
    ):
        raise ClaudeProviderPreparationError("cwd is not an absolute path")
    if not isinstance(session_id, str):
        raise ClaudeProviderPreparationError("session_id is malformed")
    try:
        parsed_session = uuid.UUID(session_id)
    except ValueError as exc:
        raise ClaudeProviderPreparationError(
            "session_id must be a canonical UUID"
        ) from exc
    if str(parsed_session) != session_id:
        raise ClaudeProviderPreparationError(
            "session_id must be a canonical UUID"
        )
    line = _positive_int(max_line_bytes, "max_line_bytes", MAX_LINE_BYTES)
    stream = _positive_int(
        max_stream_bytes, "max_stream_bytes", MAX_STREAM_BYTES
    )
    if line > stream:
        raise ClaudeProviderPreparationError(
            "max_line_bytes exceeds max_stream_bytes"
        )
    if desired_auth_route not in _ALLOWED_ROUTES:
        raise ClaudeProviderPreparationError(
            "desired auth route is unsupported by runtime host authority"
        )
    if home_variable_policy not in _HOME_POLICIES:
        raise ClaudeProviderPreparationError(
            "home variable policy is unsupported"
        )
    policies = _unique_strings(
        phase_environment_policies,
        label="phase_environment_policies",
        pattern=_NAME_RE,
        nonempty=True,
    )
    controls = _mapping_strings(
        functional_controls, label="functional_controls"
    )
    required = _unique_strings(
        required_capabilities,
        label="required_capabilities",
        pattern=_TOOL_RE,
    )
    forbidden = _unique_strings(
        forbidden_capabilities,
        label="forbidden_capabilities",
        pattern=_TOOL_RE,
    )
    if set(required) & set(forbidden):
        raise ClaudeProviderPreparationError(
            "required and forbidden capabilities overlap"
        )
    styles = _unique_strings(
        accepted_output_styles,
        label="accepted_output_styles",
        pattern=_TOOL_RE,
        nonempty=True,
    )
    core = {
        "schema": SEMANTIC_INTENT_SCHEMA,
        "run_id": run,
        "phase": phase_n,
        "backend": backend,
        "launch_model": launch_model,
        "accepted_models": models,
        "cwd": cwd,
        "session_id": session_id,
        "max_line_bytes": line,
        "max_stream_bytes": stream,
        "desired_auth_route": desired_auth_route,
        "home_variable_policy": home_variable_policy,
        "phase_environment_policies": policies,
        "functional_controls": dict(sorted(controls.items())),
        "required_capabilities": required,
        "forbidden_capabilities": forbidden,
        "accepted_output_styles": styles,
    }
    return _compile_digest_record(core, "intent_sha256")


def _replay_semantic_intent(value: Mapping[str, Any]) -> dict[str, Any]:
    _exact_keys(value, _INTENT_KEYS, "Claude provider semantic intent")
    rebuilt = compile_claude_provider_semantic_intent(
        run_id=value["run_id"],
        phase=value["phase"],
        backend=value["backend"],
        launch_model=value["launch_model"],
        accepted_models=value["accepted_models"],
        cwd=value["cwd"],
        session_id=value["session_id"],
        max_line_bytes=value["max_line_bytes"],
        max_stream_bytes=value["max_stream_bytes"],
        desired_auth_route=value["desired_auth_route"],
        home_variable_policy=value["home_variable_policy"],
        phase_environment_policies=value["phase_environment_policies"],
        functional_controls=value["functional_controls"],
        required_capabilities=value["required_capabilities"],
        forbidden_capabilities=value["forbidden_capabilities"],
        accepted_output_styles=value["accepted_output_styles"],
    )
    if value["schema"] != SEMANTIC_INTENT_SCHEMA or rebuilt != dict(value):
        raise ClaudeProviderPreparationError(
            "Claude provider semantic intent does not replay"
        )
    return rebuilt


def compile_claude_phase_tool_policy(
    *,
    phase: str,
    permission_mode: str,
    builtin_tools: Sequence[str],
    required_tools: Sequence[str],
    forbidden_tools: Sequence[str],
) -> dict[str, Any]:
    """Compile one exact phase-to-Claude built-in tool boundary."""

    phase_n = _safe_id(phase, "phase")
    if permission_mode not in _PERMISSION_MODES:
        raise ClaudeProviderPreparationError(
            "Claude permission mode is unsupported"
        )
    builtin = _unique_strings(
        builtin_tools,
        label="builtin_tools",
        pattern=_TOOL_RE,
        nonempty=True,
    )
    required = _unique_strings(
        required_tools,
        label="required_tools",
        pattern=_TOOL_RE,
        nonempty=True,
    )
    forbidden = _unique_strings(
        forbidden_tools,
        label="forbidden_tools",
        pattern=_TOOL_RE,
    )
    if not set(required).issubset(builtin):
        raise ClaudeProviderPreparationError(
            "required tools exceed the built-in tool denominator"
        )
    if set(builtin) & set(forbidden):
        raise ClaudeProviderPreparationError(
            "built-in and forbidden tools overlap"
        )
    core = {
        "schema": PHASE_TOOL_POLICY_SCHEMA,
        "phase": phase_n,
        "permission_mode": permission_mode,
        "builtin_tools": builtin,
        "required_tools": required,
        "forbidden_tools": forbidden,
    }
    return _compile_digest_record(core, "phase_tool_policy_sha256")


def _replay_phase_tool_policy(value: Mapping[str, Any]) -> dict[str, Any]:
    _exact_keys(value, _TOOL_POLICY_KEYS, "Claude phase tool policy")
    rebuilt = compile_claude_phase_tool_policy(
        phase=value["phase"],
        permission_mode=value["permission_mode"],
        builtin_tools=value["builtin_tools"],
        required_tools=value["required_tools"],
        forbidden_tools=value["forbidden_tools"],
    )
    if value["schema"] != PHASE_TOOL_POLICY_SCHEMA or rebuilt != dict(value):
        raise ClaudeProviderPreparationError(
            "Claude phase tool policy does not replay"
        )
    return rebuilt


def compile_claude_settings_policy(
    *,
    mode: str,
    settings_sha256: str | None,
    external_policy_sha256: str | None,
) -> dict[str, Any]:
    """Compile the secret-free settings policy parent."""

    if mode not in _SETTINGS_MODES:
        raise ClaudeProviderPreparationError(
            "Claude settings mode is unsupported"
        )
    settings = _sha256(
        settings_sha256, "settings_sha256", optional=True
    )
    external = _sha256(
        external_policy_sha256,
        "external_policy_sha256",
        optional=True,
    )
    if mode == "SAFE_MODE":
        if settings is not None or external is not None:
            raise ClaudeProviderPreparationError(
                "safe mode cannot carry settings authorities"
            )
    elif settings is None or external is None:
        raise ClaudeProviderPreparationError(
            "bound settings require exact settings and policy digests"
        )
    core = {
        "schema": SETTINGS_POLICY_SCHEMA,
        "mode": mode,
        "settings_sha256": settings,
        "external_policy_sha256": external,
    }
    return _compile_digest_record(core, "settings_policy_sha256")


def _replay_settings_policy(value: Mapping[str, Any]) -> dict[str, Any]:
    _exact_keys(value, _SETTINGS_POLICY_KEYS, "Claude settings policy")
    rebuilt = compile_claude_settings_policy(
        mode=value["mode"],
        settings_sha256=value["settings_sha256"],
        external_policy_sha256=value["external_policy_sha256"],
    )
    if value["schema"] != SETTINGS_POLICY_SCHEMA or rebuilt != dict(value):
        raise ClaudeProviderPreparationError(
            "Claude settings policy does not replay"
        )
    return rebuilt


def compile_claude_mcp_policy(
    *,
    settings_mode: str,
    server_names: Sequence[str],
    source_manifest_sha256: str | None,
    selected_config_sha256: str | None,
    runtime_selection: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Compile the selected, minimum MCP server denominator."""

    if settings_mode not in _SETTINGS_MODES:
        raise ClaudeProviderPreparationError(
            "Claude MCP settings mode is unsupported"
        )
    servers = _unique_strings(
        server_names,
        label="server_names",
        pattern=_SERVER_RE,
    )
    manifest = _sha256(
        source_manifest_sha256,
        "source_manifest_sha256",
        optional=True,
    )
    selected = _sha256(
        selected_config_sha256,
        "selected_config_sha256",
        optional=True,
    )
    try:
        selection = (
            None
            if runtime_selection is None
            else replay_mcp_current_selection(runtime_selection)
        )
    except ClaudeLaunchSecurityError as exc:
        raise ClaudeProviderPreparationError(
            f"Claude MCP runtime selection is invalid: {exc}"
        ) from exc
    if selection is not None and any(
        server not in selection["server_launches"] for server in servers
    ):
        raise ClaudeProviderPreparationError(
            "Claude MCP servers are absent from runtime selection"
        )
    if settings_mode == "SAFE_MODE":
        if servers or manifest is not None or selected is not None:
            raise ClaudeProviderPreparationError(
                "safe mode cannot carry MCP authority"
            )
    else:
        if selected is None or (bool(servers) != (manifest is not None)):
            raise ClaudeProviderPreparationError(
                "bound settings require exact selected MCP authority"
            )
    core = {
        "schema": MCP_POLICY_SCHEMA,
        "settings_mode": settings_mode,
        "server_names": servers,
        "source_manifest_sha256": manifest,
        "selected_config_sha256": selected,
    }
    if selection is not None:
        core["runtime_selection"] = selection
        core["runtime_selection_sha256"] = mcp_current_selection_sha256(
            selection
        )
    return _compile_digest_record(core, "mcp_policy_sha256")


def _replay_mcp_policy(value: Mapping[str, Any]) -> dict[str, Any]:
    if set(value) not in {
        _MCP_POLICY_KEYS,
        _MCP_POLICY_KEYS
        | {"runtime_selection", "runtime_selection_sha256"},
    }:
        raise ClaudeProviderPreparationError(
            "Claude MCP policy fields drifted"
        )
    rebuilt = compile_claude_mcp_policy(
        settings_mode=value["settings_mode"],
        server_names=value["server_names"],
        source_manifest_sha256=value["source_manifest_sha256"],
        selected_config_sha256=value["selected_config_sha256"],
        runtime_selection=value.get("runtime_selection"),
    )
    if value["schema"] != MCP_POLICY_SCHEMA or rebuilt != dict(value):
        raise ClaudeProviderPreparationError(
            "Claude MCP policy does not replay"
        )
    return rebuilt


def _stable_source_digest(path: Path, label: str) -> str:
    try:
        if path.is_symlink() or not path.is_file():
            raise OSError("not a regular source file")
        before = path.stat()
        raw = path.read_bytes()
        after = path.stat()
    except OSError as exc:
        raise ClaudeProviderPreparationError(
            f"{label} is unavailable"
        ) from exc
    if (
        before.st_dev != after.st_dev
        or before.st_ino != after.st_ino
        or before.st_size != after.st_size
        or before.st_mtime_ns != after.st_mtime_ns
        or len(raw) != after.st_size
    ):
        raise ClaudeProviderPreparationError(
            f"{label} changed during observation"
        )
    return hashlib.sha256(raw).hexdigest()


def _implementation_closure() -> list[dict[str, str]]:
    modules: list[tuple[str, Path]] = [
        (__name__, Path(__file__).resolve(strict=True))
    ]
    for module in _IMPLEMENTATION_MODULES:
        filename = getattr(module, "__file__", None)
        if not isinstance(filename, str):
            raise ClaudeProviderPreparationError(
                "Claude provider implementation module lacks source"
            )
        modules.append(
            (module.__name__, Path(filename).resolve(strict=True))
        )
    rows = [
        {
            "module": name,
            "sha256": _stable_source_digest(
                path, f"implementation module {name}"
            ),
        }
        for name, path in modules
    ]
    rows.sort(key=lambda row: row["module"])
    if len({row["module"] for row in rows}) != len(rows):
        raise ClaudeProviderPreparationError(
            "Claude provider implementation closure is duplicated"
        )
    return rows


def _normalize_linux_kernel_release(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    release = value.rstrip("\r\n")
    try:
        raw = release.encode("ascii")
    except UnicodeEncodeError:
        return None
    if (
        not release
        or len(raw) > _MAX_LINUX_OSRELEASE_BYTES
        or any(
            byte < 0x21 or byte > 0x7E
            for byte in raw
        )
    ):
        return None
    return release


def _read_linux_osrelease() -> str | None:
    """Read a bounded, stable, non-symlink Linux osrelease value."""

    path = _LINUX_OSRELEASE_PATH
    try:
        before = os.lstat(path)
    except (OSError, TypeError, ValueError):
        return None
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        return None

    flags = os.O_RDONLY
    flags |= getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except (OSError, TypeError, ValueError):
        return None
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_dev != before.st_dev
            or opened.st_ino != before.st_ino
        ):
            return None
        chunks: list[bytes] = []
        remaining = _MAX_LINUX_OSRELEASE_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        after = os.fstat(descriptor)
        if (
            after.st_dev != opened.st_dev
            or after.st_ino != opened.st_ino
            or after.st_mode != opened.st_mode
        ):
            return None
    except OSError:
        return None
    finally:
        try:
            os.close(descriptor)
        except OSError:
            pass

    if not raw or len(raw) > _MAX_LINUX_OSRELEASE_BYTES:
        return None
    try:
        release = raw.decode("ascii")
    except UnicodeDecodeError:
        return None
    return _normalize_linux_kernel_release(release)


def _linux_kernel_release() -> str | None:
    uname = getattr(os, "uname", None)
    if callable(uname):
        try:
            result = uname()
        except (AttributeError, NotImplementedError, OSError, TypeError):
            pass
        else:
            return _normalize_linux_kernel_release(
                getattr(result, "release", None)
            )
    return _read_linux_osrelease()


def _is_reviewed_wsl_kernel_release(release: str) -> bool:
    return _WSL_KERNEL_MARKER_RE.search(release) is not None


def _detect_host_family() -> str:
    os_name = os.name
    host_platform = sys.platform
    if not isinstance(os_name, str) or not isinstance(host_platform, str):
        return "unsupported"
    if os_name == "nt" and host_platform == "win32":
        return "windows"
    if os_name == "posix" and host_platform == "darwin":
        return "macos"
    if os_name != "posix" or not host_platform.startswith("linux"):
        return "unsupported"

    release = _linux_kernel_release()
    if release is None:
        return "unsupported"
    if _is_reviewed_wsl_kernel_release(release):
        return "wsl2"
    return "linux"


def _debt(
    code: str,
    subject: str,
    evidence_sha256: str,
) -> dict[str, str]:
    if code not in DEBT_CODES:
        raise ClaudeProviderPreparationError(
            "Claude provider debt code is unsupported"
        )
    subject_n = _safe_id(subject, "debt subject")
    evidence = _sha256(evidence_sha256, "debt evidence")
    assert evidence is not None
    return {
        "code": code,
        "subject": subject_n,
        "evidence_sha256": evidence,
    }


def _replay_debts(value: Any) -> list[dict[str, str]]:
    if not isinstance(value, list):
        raise ClaudeProviderPreparationError(
            "Claude provider debts must be an array"
        )
    debts: list[dict[str, str]] = []
    for raw in value:
        _exact_keys(raw, _DEBT_KEYS, "Claude provider debt")
        debts.append(
            _debt(raw["code"], raw["subject"], raw["evidence_sha256"])
        )
    ordered = sorted(
        debts, key=lambda row: (row["code"], row["subject"])
    )
    if debts != ordered or len(
        {(row["code"], row["subject"]) for row in debts}
    ) != len(debts):
        raise ClaudeProviderPreparationError(
            "Claude provider debts are duplicated or noncanonical"
        )
    return debts


def _runtime_host_policy(
    *,
    host_family: str,
    auth_route: str,
    ambient_names: Sequence[str],
    source_configured: bool,
    source_store_class: str,
    source_observation_sha256: str,
    source_config_dir_identity_sha256: str | None,
    project_root_identity_sha256: str,
    runtime_cwd_identity_sha256: str,
    trusted_cwds_identity_sha256: str,
    trusted_cwd_count: int,
    startup_authority_sha256: str,
    source_snapshot_sha256: str,
) -> dict[str, Any]:
    if host_family not in _HOST_FAMILIES - {"unsupported"}:
        raise ClaudeProviderPreparationError(
            "runtime host family is unsupported"
        )
    names = sorted(ambient_names, key=str.casefold)
    if (
        any(not isinstance(name, str) or not name for name in names)
        or len({name.casefold() for name in names}) != len(names)
    ):
        raise ClaudeProviderPreparationError(
            "runtime host ambient key denominator is invalid"
        )
    if auth_route not in _ALLOWED_ROUTES:
        raise ClaudeProviderPreparationError(
            "runtime host auth route is unsupported"
        )
    if type(source_configured) is not bool:
        raise ClaudeProviderPreparationError(
            "runtime source presence is malformed"
        )
    if (
        auth_route == "STORED_SUBSCRIPTION_OAUTH"
    ) != source_configured:
        raise ClaudeProviderPreparationError(
            "runtime source presence disagrees with auth route"
        )
    source_directory_identity = _sha256(
        source_config_dir_identity_sha256,
        "source_config_dir_identity_sha256",
        optional=True,
    )
    if source_configured != (source_directory_identity is not None):
        raise ClaudeProviderPreparationError(
            "runtime source directory identity disagrees with presence"
        )
    if (
        not isinstance(source_store_class, str)
        or _NAME_RE.fullmatch(source_store_class) is None
    ):
        raise ClaudeProviderPreparationError(
            "runtime source store class is malformed"
        )
    count = _positive_int(
        trusted_cwd_count, "trusted_cwd_count", 1024
    )
    core = {
        "schema": RUNTIME_HOST_POLICY_SCHEMA,
        "host_family": host_family,
        "auth_route": auth_route,
        "ambient_environment_names": names,
        "ambient_key_set_sha256": _key_set_sha256(names),
        "source_configured": source_configured,
        "source_store_class": source_store_class,
        "source_observation_sha256": _sha256(
            source_observation_sha256,
            "source_observation_sha256",
        ),
        "source_config_dir_identity_sha256": (
            source_directory_identity
        ),
        "project_root_identity_sha256": _sha256(
            project_root_identity_sha256,
            "project_root_identity_sha256",
        ),
        "runtime_cwd_identity_sha256": _sha256(
            runtime_cwd_identity_sha256,
            "runtime_cwd_identity_sha256",
        ),
        "trusted_cwds_identity_sha256": _sha256(
            trusted_cwds_identity_sha256,
            "trusted_cwds_identity_sha256",
        ),
        "trusted_cwd_count": count,
        "startup_authority_sha256": _sha256(
            startup_authority_sha256,
            "startup_authority_sha256",
        ),
        "source_snapshot_sha256": _sha256(
            source_snapshot_sha256,
            "source_snapshot_sha256",
        ),
        "credential_values_recorded": False,
        "credential_content_hashes_recorded": False,
        "host_paths_recorded": False,
    }
    return _compile_digest_record(core, "policy_sha256")


def _replay_runtime_host_policy(
    value: Mapping[str, Any],
) -> dict[str, Any]:
    _exact_keys(value, _HOST_POLICY_KEYS, "Claude runtime host policy")
    rebuilt = _runtime_host_policy(
        host_family=value["host_family"],
        auth_route=value["auth_route"],
        ambient_names=value["ambient_environment_names"],
        source_configured=value["source_configured"],
        source_store_class=value["source_store_class"],
        source_observation_sha256=value["source_observation_sha256"],
        source_config_dir_identity_sha256=value[
            "source_config_dir_identity_sha256"
        ],
        project_root_identity_sha256=value[
            "project_root_identity_sha256"
        ],
        runtime_cwd_identity_sha256=value[
            "runtime_cwd_identity_sha256"
        ],
        trusted_cwds_identity_sha256=value[
            "trusted_cwds_identity_sha256"
        ],
        trusted_cwd_count=value["trusted_cwd_count"],
        startup_authority_sha256=value["startup_authority_sha256"],
        source_snapshot_sha256=value["source_snapshot_sha256"],
    )
    if value["schema"] != RUNTIME_HOST_POLICY_SCHEMA or rebuilt != dict(value):
        raise ClaudeProviderPreparationError(
            "Claude runtime host policy does not replay"
        )
    return rebuilt


def _command_template(
    *,
    executable: str,
    intent: Mapping[str, Any],
    profile: Mapping[str, Any],
) -> list[str]:
    return [
        executable,
        "-p",
        "--model",
        intent["launch_model"],
        "--output-format",
        "stream-json",
        "--verbose",
        "--session-id",
        intent["session_id"],
        "--no-session-persistence",
        *profile["cli_flags"],
    ]


def _backend_argv_prefix_from_selection(
    selection: Mapping[str, Any] | None,
) -> tuple[str, ...]:
    if selection is None:
        return ()
    try:
        selected = replay_mcp_current_selection(selection)
    except ClaudeLaunchSecurityError as exc:
        raise ClaudeProviderPreparationError(
            "Claude backend runtime selection does not replay"
        ) from exc
    backend = selected["backend_launches"]["claude"]
    if backend["execution_kind"] != "native" or backend["version"] != "2.1.252":
        raise ClaudeProviderPreparationError(
            "Claude backend generation is unsupported"
        )
    leaf = "plamen.cmd" if os.name == "nt" else "plamen"
    front = os.path.abspath(os.path.expanduser(f"~/.local/bin/{leaf}"))
    return (
        front,
        "backend-launch",
        "--backend",
        "claude",
        "--generation",
        selected["generation_id"],
        "--receipt-sha256",
        selected["receipt_sha256"],
        "--census-sha256",
        selected["census_sha256"],
        "--request-sha256",
        selected["request_sha256"],
        "--policy-sha256",
        selected["generation_policy_sha256"],
        "--",
    )


def _authority_fields() -> tuple[str, ...]:
    return (
        "executable_observation",
        "auth_source_observation",
        "auth_route_observation",
        "auth_route_policy",
        "settings_authority",
        "mcp_authority",
        "headless_profile",
        "launch_security",
        "launch_security_request",
        "stream_configuration",
        "runtime_host_policy",
    )


def _record_core(
    *,
    intent: Mapping[str, Any],
    tool_policy: Mapping[str, Any],
    settings_policy: Mapping[str, Any],
    mcp_policy: Mapping[str, Any],
    startup_authority_sha256: str,
    source_snapshot_sha256: str,
    implementation_closure: list[dict[str, str]],
    authorities: Mapping[str, Any] | None = None,
    planned_names: Sequence[str] = (),
    command_template: Sequence[str] = (),
    debts: Sequence[Mapping[str, str]] = (),
) -> dict[str, Any]:
    supplied = dict(authorities or {})
    core = {
        "schema": PROVIDER_PREPARATION_SCHEMA,
        "backend": "claude",
        "semantic_intent": dict(intent),
        "phase_tool_policy": dict(tool_policy),
        "settings_policy": dict(settings_policy),
        "mcp_policy": dict(mcp_policy),
        "startup_authority_sha256": startup_authority_sha256,
        "source_snapshot_sha256": source_snapshot_sha256,
        **{
            name: supplied.get(name)
            for name in _authority_fields()
        },
        "planned_child_environment_names": list(planned_names),
        "command_template": list(command_template),
        "implementation_closure": [
            dict(row) for row in implementation_closure
        ],
        "debts": [
            dict(row)
            for row in sorted(
                debts, key=lambda row: (row["code"], row["subject"])
            )
        ],
    }
    return core


def _blocked_preparation(
    *,
    intent: Mapping[str, Any],
    tool_policy: Mapping[str, Any],
    settings_policy: Mapping[str, Any],
    mcp_policy: Mapping[str, Any],
    startup_authority_sha256: str,
    source_snapshot_sha256: str,
    implementation_closure: list[dict[str, str]],
    debt: Mapping[str, str],
) -> "ClaudeProviderPreparation":
    core = _record_core(
        intent=intent,
        tool_policy=tool_policy,
        settings_policy=settings_policy,
        mcp_policy=mcp_policy,
        startup_authority_sha256=startup_authority_sha256,
        source_snapshot_sha256=source_snapshot_sha256,
        implementation_closure=implementation_closure,
        debts=(debt,),
    )
    record = _compile_digest_record(core, "preparation_sha256")
    return _mint_claude_provider_preparation(
        _canonical(record) + b"\n",
        expected_startup_authority_sha256=startup_authority_sha256,
        expected_source_snapshot_sha256=source_snapshot_sha256,
    )


class ClaudeProviderPreparation:
    """Validator-issued immutable reusable WorkPlan provider preparation."""

    __slots__ = ("__record_bytes", "__weakref__")

    schema: ClassVar[str] = PROVIDER_PREPARATION_SCHEMA

    def __new__(
        cls,
        *,
        _record_bytes: bytes,
        _promotion_token: object,
        _issuance_id: str | None = None,
    ) -> "ClaudeProviderPreparation":
        if cls is not ClaudeProviderPreparation:
            raise TypeError(
                "ClaudeProviderPreparation cannot be subclass-minted"
            )
        if (
            _promotion_token is not _PROMOTION_TOKEN
            or not isinstance(_issuance_id, str)
        ):
            raise TypeError(
                "Claude provider preparation requires compiler promotion"
            )
        with _ISSUANCE_LOCK:
            pending = _PREPARATION_PENDING.pop(_issuance_id, None)
        if (
            pending is None
            or not isinstance(_record_bytes, bytes)
            or pending[0] != _record_bytes
        ):
            raise TypeError(
                "Claude provider preparation bytes are invalid"
            )
        instance = super().__new__(cls)
        instance.__record_bytes = bytes(_record_bytes)
        raw_sha256 = hashlib.sha256(instance.__record_bytes).hexdigest()
        with _ISSUANCE_LOCK:
            key = id(instance)

            def retire(reference: weakref.ReferenceType[Any]) -> None:
                with _ISSUANCE_LOCK:
                    current = _PREPARATION_ISSUED.get(key)
                    if current is not None and current[0] is reference:
                        _PREPARATION_ISSUED.pop(key, None)

            reference = weakref.ref(instance, retire)
            _PREPARATION_ISSUED[key] = (
                reference,
                raw_sha256,
                pending[1],
                pending[2],
                os.getpid(),
            )
        return instance

    def __init__(
        self,
        *,
        _record_bytes: bytes,
        _promotion_token: object,
        _issuance_id: str | None = None,
    ) -> None:
        del _record_bytes, _promotion_token, _issuance_id

    def __repr__(self) -> str:
        return (
            "<ClaudeProviderPreparation "
            f"preparation_sha256={self.preparation_sha256}>"
        )

    def __reduce__(self) -> None:
        raise TypeError(
            "ClaudeProviderPreparation must cross processes as validated bytes"
        )

    def __copy__(self) -> None:
        raise TypeError("ClaudeProviderPreparation cannot be copied")

    def __deepcopy__(self, _memo: object) -> None:
        raise TypeError("ClaudeProviderPreparation cannot be copied")

    @property
    def record(self) -> dict[str, Any]:
        raw, _startup, _source = _issued_preparation_inputs(self)
        return _decode(raw)

    @property
    def preparation_sha256(self) -> str:
        return str(self.record["preparation_sha256"])

    @property
    def debts(self) -> tuple[dict[str, str], ...]:
        return tuple(
            MappingProxyType(dict(row)) for row in self.record["debts"]
        )

    @property
    def eligible(self) -> bool:
        return not self.record["debts"]

    def to_bytes(self) -> bytes:
        raw, _startup, _source = _issued_preparation_inputs(self)
        return bytes(raw)

    def validate_for_backend(self, backend: str) -> None:
        if backend != "claude":
            raise ClaudeProviderPreparationError(
                "Codex/backend cannot consume a Claude provider package"
            )
        replayed = _fully_replay_issued_preparation(self)
        if not replayed.eligible:
            raise ClaudeProviderPreparationError(
                "Claude provider package carries capability debt",
                debt=replayed.record["debts"][0],
            )

    def command_for_bound_stdin(self) -> tuple[str, ...]:
        """Return the canonical prompt-independent Claude command.

        WorkerTransaction binds and supplies the exact prompt through stdin;
        keeping argv prompt-independent avoids shell command-length limits and
        leaves one authoritative prompt channel.
        """
        replayed = _fully_replay_issued_preparation(self)
        if not replayed.eligible:
            raise ClaudeProviderPreparationError(
                "Claude provider package carries capability debt",
                debt=replayed.record["debts"][0],
            )
        template = replayed.record["command_template"]
        if (
            PROMPT_PLACEHOLDER in template
            or template.count("-p") != 1
            or template.count("--model") != 1
            or template.index("--model") != template.index("-p") + 1
        ):
            raise ClaudeProviderPreparationError(
                "Claude command template is not canonical stdin-only"
            )
        return tuple(template)

    def command_for_prompt(self, prompt: str) -> tuple[str, ...]:
        """Fail closed for the retired positional-prompt transport."""

        del prompt
        raise ClaudeProviderPreparationError(
            "Claude positional prompt transport is retired; use bound stdin"
        )

    def public_headless_arguments(self) -> dict[str, Any]:
        replayed = _fully_replay_issued_preparation(self)
        if not replayed.eligible:
            raise ClaudeProviderPreparationError(
                "Claude provider package carries capability debt",
                debt=replayed.record["debts"][0],
            )
        record = replayed.record
        host = record["runtime_host_policy"]
        return {
            "environment": {},
            "environment_allowlist": tuple(
                record["planned_child_environment_names"]
            ),
            "provider_stdout_evidence_configuration": dict(
                record["stream_configuration"]
            ),
            "claude_launch_security": dict(record["launch_security"]),
            "claude_launch_security_request": dict(
                record["launch_security_request"]
            ),
            "claude_provider_preparation_sha256": (
                record["preparation_sha256"]
            ),
            "claude_runtime_host_policy_sha256": host["policy_sha256"],
        }


def _mint_claude_provider_preparation(
    raw: bytes,
    *,
    expected_startup_authority_sha256: str,
    expected_source_snapshot_sha256: str,
) -> ClaudeProviderPreparation:
    if not isinstance(raw, bytes):
        raise ClaudeProviderPreparationError(
            "Claude provider preparation bytes are invalid"
        )
    startup = _sha256(
        expected_startup_authority_sha256,
        "expected startup authority",
    )
    source = _sha256(
        expected_source_snapshot_sha256,
        "expected source snapshot",
    )
    assert startup is not None and source is not None
    issuance_id = secrets.token_hex(32)
    with _ISSUANCE_LOCK:
        _PREPARATION_PENDING[issuance_id] = (raw, startup, source)
    try:
        return ClaudeProviderPreparation(
            _record_bytes=raw,
            _promotion_token=_PROMOTION_TOKEN,
            _issuance_id=issuance_id,
        )
    finally:
        with _ISSUANCE_LOCK:
            _PREPARATION_PENDING.pop(issuance_id, None)


def _issued_preparation_inputs(
    value: ClaudeProviderPreparation,
) -> tuple[bytes, str, str]:
    if type(value) is not ClaudeProviderPreparation:
        raise ClaudeProviderPreparationError(
            "exact validator-issued Claude provider preparation is required"
        )
    with _ISSUANCE_LOCK:
        current = _PREPARATION_ISSUED.get(id(value))
        if current is None or current[0]() is not value:
            raise ClaudeProviderPreparationError(
                "Claude provider preparation was not validator-issued"
            )
        expected_raw_sha256, startup, source, issuer_pid = current[1:]
        if issuer_pid != os.getpid():
            raise ClaudeProviderPreparationError(
                "Claude provider preparation must cross processes as "
                "validated bytes"
            )
    try:
        raw = object.__getattribute__(
            value,
            "_ClaudeProviderPreparation__record_bytes",
        )
    except AttributeError as exc:
        raise ClaudeProviderPreparationError(
            "Claude provider preparation storage drifted"
        ) from exc
    if (
        not isinstance(raw, bytes)
        or hashlib.sha256(raw).hexdigest() != expected_raw_sha256
    ):
        raise ClaudeProviderPreparationError(
            "Claude provider preparation storage drifted"
        )
    return raw, startup, source


def _fully_replay_issued_preparation(
    value: ClaudeProviderPreparation,
) -> ClaudeProviderPreparation:
    raw, startup, source = _issued_preparation_inputs(value)
    return replay_claude_provider_preparation(
        raw,
        expected_backend="claude",
        expected_startup_authority_sha256=startup,
        expected_source_snapshot_sha256=source,
    )


class BoundClaudeProviderRuntime:
    """Opaque, fresh, one-shot per-attempt provider runtime attachment."""

    __slots__ = (
        "__attachment_id",
        "__attachment_sha256",
        "__bound_settings",
        "__host_inputs",
        "__mcp_config",
        "__preparation_sha256",
        "__runtime_host_policy_sha256",
        "__weakref__",
    )

    def __new__(
        cls,
        *,
        _token: object,
        preparation_sha256: str,
        runtime_host_policy_sha256: str,
        attachment_id: str,
        host_inputs: ClaudeRuntimeHostInputs,
        bound_settings: bytes | None,
        mcp_config: bytes | None,
        _issuance_id: str | None = None,
    ) -> "BoundClaudeProviderRuntime":
        if cls is not BoundClaudeProviderRuntime:
            raise TypeError(
                "BoundClaudeProviderRuntime cannot be subclass-minted"
            )
        if (
            _token is not _ATTACHMENT_TOKEN
            or not isinstance(_issuance_id, str)
        ):
            raise TypeError("BoundClaudeProviderRuntime is opaque")
        with _ISSUANCE_LOCK:
            pending = _BOUND_PENDING.pop(_issuance_id, None)
        if (
            pending is None
            or pending["preparation_sha256"] != preparation_sha256
            or pending["runtime_host_policy_sha256"]
            != runtime_host_policy_sha256
            or pending["attachment_id"] != attachment_id
            or pending["host_inputs"] is not host_inputs
            or pending["bound_settings"] != bound_settings
            or pending["mcp_config"] != mcp_config
        ):
            raise TypeError(
                "BoundClaudeProviderRuntime requires validator issuance"
            )
        instance = super().__new__(cls)
        instance.__preparation_sha256 = preparation_sha256
        instance.__runtime_host_policy_sha256 = (
            runtime_host_policy_sha256
        )
        instance.__attachment_id = attachment_id
        core = {
            "schema": RUNTIME_ATTACHMENT_SCHEMA,
            "preparation_sha256": preparation_sha256,
            "runtime_host_policy_sha256": (
                runtime_host_policy_sha256
            ),
            "attachment_id": attachment_id,
            "host_inputs_sha256": host_inputs.host_inputs_sha256,
            "bound_settings_sha256": (
                None
                if bound_settings is None
                else hashlib.sha256(bound_settings).hexdigest()
            ),
            "selected_mcp_config_sha256": (
                None
                if mcp_config is None
                else hashlib.sha256(mcp_config).hexdigest()
            ),
        }
        instance.__attachment_sha256 = _digest(core)
        instance.__host_inputs = host_inputs
        instance.__bound_settings = (
            None if bound_settings is None else bytearray(bound_settings)
        )
        instance.__mcp_config = (
            None if mcp_config is None else bytearray(mcp_config)
        )
        state = {
            **core,
            "attachment_sha256": instance.__attachment_sha256,
            "host_inputs": host_inputs,
            "claimed": False,
        }
        with _ISSUANCE_LOCK:
            _register_issued(_BOUND_ISSUED, instance, state)
        return instance

    def __repr__(self) -> str:
        return (
            "<BoundClaudeProviderRuntime "
            f"attachment_sha256={self.__attachment_sha256}>"
        )

    def __reduce__(self) -> None:
        raise TypeError("BoundClaudeProviderRuntime cannot be serialized")

    def __copy__(self) -> None:
        raise TypeError("BoundClaudeProviderRuntime cannot be copied")

    def __deepcopy__(self, _memo: object) -> None:
        raise TypeError("BoundClaudeProviderRuntime cannot be copied")

    @property
    def preparation_sha256(self) -> str:
        return self.__preparation_sha256

    @property
    def runtime_host_policy_sha256(self) -> str:
        return self.__runtime_host_policy_sha256

    @property
    def attachment_sha256(self) -> str:
        return self.__attachment_sha256

    def _claim(
        self,
        *,
        provider_preparation: ClaudeProviderPreparation,
        expected_preparation_sha256: str,
        expected_runtime_host_policy_sha256: str,
        expected_attachment_sha256: str,
    ) -> "ClaimedClaudeProviderRuntime":
        with _ISSUANCE_LOCK:
            initial_state = _issued_state(
                _BOUND_ISSUED,
                self,
                label="bound Claude provider runtime",
            )
            if initial_state["claimed"]:
                raise ClaudeProviderPreparationError(
                    "Claude provider runtime attachment was already claimed"
                )
        replayed_parent, _private = _replay_provider_runtime_parent(
            provider_preparation,
            host_inputs=self.__host_inputs,
            bound_settings_bytes=(
                None
                if self.__bound_settings is None
                else bytes(self.__bound_settings)
            ),
            selected_mcp_config_bytes=(
                None
                if self.__mcp_config is None
                else bytes(self.__mcp_config)
            ),
        )
        with _ISSUANCE_LOCK:
            state = _issued_state(
                _BOUND_ISSUED,
                self,
                label="bound Claude provider runtime",
            )
            if state["claimed"]:
                raise ClaudeProviderPreparationError(
                    "Claude provider runtime attachment was already claimed"
                )
            expected_prep = _sha256(
                expected_preparation_sha256,
                "expected_preparation_sha256",
            )
            expected_host = _sha256(
                expected_runtime_host_policy_sha256,
                "expected_runtime_host_policy_sha256",
            )
            expected_attachment = _sha256(
                expected_attachment_sha256,
                "expected_attachment_sha256",
            )
            if (
                expected_prep != self.__preparation_sha256
                or expected_host != self.__runtime_host_policy_sha256
                or expected_attachment != self.__attachment_sha256
                or replayed_parent.preparation_sha256
                != self.__preparation_sha256
                or replayed_parent.record["runtime_host_policy"][
                    "policy_sha256"
                ]
                != self.__runtime_host_policy_sha256
                or state["preparation_sha256"]
                != self.__preparation_sha256
                or state["runtime_host_policy_sha256"]
                != self.__runtime_host_policy_sha256
                or state["attachment_id"] != self.__attachment_id
                or state["attachment_sha256"]
                != self.__attachment_sha256
                or state["host_inputs"] is not self.__host_inputs
                or state["host_inputs_sha256"]
                != self.__host_inputs.host_inputs_sha256
                or state["bound_settings_sha256"]
                != (
                    None
                    if self.__bound_settings is None
                    else hashlib.sha256(
                        bytes(self.__bound_settings)
                    ).hexdigest()
                )
                or state["selected_mcp_config_sha256"]
                != (
                    None
                    if self.__mcp_config is None
                    else hashlib.sha256(
                        bytes(self.__mcp_config)
                    ).hexdigest()
                )
            ):
                raise ClaudeProviderPreparationError(
                    "Claude provider runtime attachment authority drifted",
                    debt=_debt(
                        "CLAUDE_RUNTIME_ATTACHMENT_DRIFT",
                        "runtime-attachment",
                        self.__attachment_sha256,
                    ),
                )
            recomputed = _digest(
                {
                    "schema": state["schema"],
                    "preparation_sha256": self.__preparation_sha256,
                    "runtime_host_policy_sha256": (
                        self.__runtime_host_policy_sha256
                    ),
                    "attachment_id": self.__attachment_id,
                    "host_inputs_sha256": (
                        self.__host_inputs.host_inputs_sha256
                    ),
                    "bound_settings_sha256": state[
                        "bound_settings_sha256"
                    ],
                    "selected_mcp_config_sha256": state[
                        "selected_mcp_config_sha256"
                    ],
                }
            )
            if recomputed != self.__attachment_sha256:
                raise ClaudeProviderPreparationError(
                    "Claude provider runtime attachment payload drifted",
                    debt=_debt(
                        "CLAUDE_RUNTIME_ATTACHMENT_DRIFT",
                        "runtime-attachment",
                        self.__attachment_sha256,
                    ),
                )
            state["claimed"] = True
            settings = (
                None
                if self.__bound_settings is None
                else bytes(self.__bound_settings)
            )
            mcp = (
                None
                if self.__mcp_config is None
                else bytes(self.__mcp_config)
            )
            if self.__bound_settings is not None:
                self.__bound_settings[:] = b"\x00" * len(
                    self.__bound_settings
                )
            if self.__mcp_config is not None:
                self.__mcp_config[:] = b"\x00" * len(self.__mcp_config)
            self.__bound_settings = None
            self.__mcp_config = None
            host_inputs = self.__host_inputs
            self.__host_inputs = None
            return _mint_claimed_claude_provider_runtime(
                host_inputs=host_inputs,
                bound_settings_bytes=settings,
                selected_mcp_config_bytes=mcp,
                attachment_sha256=self.__attachment_sha256,
                provider_preparation=replayed_parent,
                runtime_host_policy_sha256=(
                    self.__runtime_host_policy_sha256
                ),
                attachment_id=self.__attachment_id,
            )


class ClaimedClaudeProviderRuntime:
    """Transient WER inputs after exact attachment claim."""

    __slots__ = (
        "__attachment_sha256",
        "__attachment_id",
        "__bound_settings_bytes",
        "__host_inputs",
        "__provider_preparation",
        "__runtime_host_policy_sha256",
        "__selected_mcp_config_bytes",
        "__weakref__",
    )

    def __new__(
        cls,
        *,
        host_inputs: ClaudeRuntimeHostInputs,
        bound_settings_bytes: bytes | None,
        selected_mcp_config_bytes: bytes | None,
        attachment_sha256: str,
        provider_preparation: ClaudeProviderPreparation | None = None,
        runtime_host_policy_sha256: str | None = None,
        attachment_id: str | None = None,
        _promotion_token: object,
        _issuance_id: str | None = None,
    ) -> "ClaimedClaudeProviderRuntime":
        if cls is not ClaimedClaudeProviderRuntime:
            raise TypeError(
                "ClaimedClaudeProviderRuntime cannot be subclass-minted"
            )
        if (
            _promotion_token is not _PROMOTION_TOKEN
            or not isinstance(_issuance_id, str)
        ):
            raise TypeError(
                "claimed Claude runtime requires exact attachment promotion"
            )
        with _ISSUANCE_LOCK:
            pending = _CLAIMED_PENDING.pop(_issuance_id, None)
        if (
            pending is None
            or pending["host_inputs"] is not host_inputs
            or pending["bound_settings_bytes"] != bound_settings_bytes
            or pending["selected_mcp_config_bytes"]
            != selected_mcp_config_bytes
            or pending["attachment_sha256"] != attachment_sha256
            or pending["provider_preparation"]
            is not provider_preparation
            or pending["runtime_host_policy_sha256"]
            != runtime_host_policy_sha256
            or pending["attachment_id"] != attachment_id
        ):
            raise TypeError(
                "claimed Claude runtime requires validator issuance"
            )
        if type(host_inputs) is not ClaudeRuntimeHostInputs:
            raise TypeError(
                "claimed Claude runtime host inputs are invalid"
            )
        _sha256(attachment_sha256, "attachment_sha256")
        instance = super().__new__(cls)
        instance.__host_inputs = host_inputs
        instance.__bound_settings_bytes = bound_settings_bytes
        instance.__selected_mcp_config_bytes = selected_mcp_config_bytes
        instance.__attachment_sha256 = attachment_sha256
        instance.__provider_preparation = provider_preparation
        instance.__runtime_host_policy_sha256 = (
            runtime_host_policy_sha256
        )
        instance.__attachment_id = attachment_id
        state = {
            "host_inputs": host_inputs,
            "host_inputs_sha256": host_inputs.host_inputs_sha256,
            "bound_settings_sha256": (
                None
                if bound_settings_bytes is None
                else hashlib.sha256(bound_settings_bytes).hexdigest()
            ),
            "selected_mcp_config_sha256": (
                None
                if selected_mcp_config_bytes is None
                else hashlib.sha256(
                    selected_mcp_config_bytes
                ).hexdigest()
            ),
            "attachment_sha256": attachment_sha256,
            "provider_preparation": provider_preparation,
            "runtime_host_policy_sha256": runtime_host_policy_sha256,
            "attachment_id": attachment_id,
        }
        with _ISSUANCE_LOCK:
            _register_issued(_CLAIMED_ISSUED, instance, state)
        _register_claimed_runtime_one_shot(instance)
        return instance

    def __init__(
        self,
        *,
        host_inputs: ClaudeRuntimeHostInputs,
        bound_settings_bytes: bytes | None,
        selected_mcp_config_bytes: bytes | None,
        attachment_sha256: str,
        provider_preparation: ClaudeProviderPreparation | None = None,
        runtime_host_policy_sha256: str | None = None,
        attachment_id: str | None = None,
        _promotion_token: object,
        _issuance_id: str | None = None,
    ) -> None:
        del (
            host_inputs,
            bound_settings_bytes,
            selected_mcp_config_bytes,
            attachment_sha256,
            provider_preparation,
            runtime_host_policy_sha256,
            attachment_id,
            _promotion_token,
            _issuance_id,
        )

    def __repr__(self) -> str:
        return (
            "<ClaimedClaudeProviderRuntime "
            f"attachment_sha256={self.attachment_sha256}>"
        )

    def __reduce__(self) -> None:
        raise TypeError("ClaimedClaudeProviderRuntime cannot be serialized")

    def __copy__(self) -> None:
        raise TypeError("ClaimedClaudeProviderRuntime cannot be copied")

    def __deepcopy__(self, _memo: object) -> None:
        raise TypeError("ClaimedClaudeProviderRuntime cannot be copied")

    def _validated_state(self) -> dict[str, Any]:
        with _ISSUANCE_LOCK:
            state = _issued_state(
                _CLAIMED_ISSUED,
                self,
                label="claimed Claude provider runtime",
            )
            if (
                state["host_inputs"] is not self.__host_inputs
                or state["provider_preparation"]
                is not self.__provider_preparation
                or state["runtime_host_policy_sha256"]
                != self.__runtime_host_policy_sha256
                or state["attachment_id"] != self.__attachment_id
                or state["host_inputs_sha256"]
                != self.__host_inputs.host_inputs_sha256
                or state["attachment_sha256"]
                != self.__attachment_sha256
                or state["bound_settings_sha256"]
                != (
                    None
                    if self.__bound_settings_bytes is None
                    else hashlib.sha256(
                        self.__bound_settings_bytes
                    ).hexdigest()
                )
                or state["selected_mcp_config_sha256"]
                != (
                    None
                    if self.__selected_mcp_config_bytes is None
                    else hashlib.sha256(
                        self.__selected_mcp_config_bytes
                    ).hexdigest()
                )
            ):
                raise ClaudeProviderPreparationError(
                    "claimed Claude provider runtime payload drifted"
                )
            return state

    @property
    def host_inputs(self) -> ClaudeRuntimeHostInputs:
        self._validated_state()
        return self.__host_inputs

    @property
    def bound_settings_bytes(self) -> bytes | None:
        self._validated_state()
        return self.__bound_settings_bytes

    @property
    def selected_mcp_config_bytes(self) -> bytes | None:
        self._validated_state()
        return self.__selected_mcp_config_bytes

    @property
    def attachment_sha256(self) -> str:
        self._validated_state()
        return self.__attachment_sha256


def _mint_bound_claude_provider_runtime(
    *,
    preparation_sha256: str,
    runtime_host_policy_sha256: str,
    attachment_id: str,
    host_inputs: ClaudeRuntimeHostInputs,
    bound_settings: bytes | None,
    mcp_config: bytes | None,
) -> BoundClaudeProviderRuntime:
    issuance_id = secrets.token_hex(32)
    pending = {
        "preparation_sha256": preparation_sha256,
        "runtime_host_policy_sha256": runtime_host_policy_sha256,
        "attachment_id": attachment_id,
        "host_inputs": host_inputs,
        "bound_settings": bound_settings,
        "mcp_config": mcp_config,
    }
    with _ISSUANCE_LOCK:
        _BOUND_PENDING[issuance_id] = pending
    try:
        return BoundClaudeProviderRuntime(
            _token=_ATTACHMENT_TOKEN,
            preparation_sha256=preparation_sha256,
            runtime_host_policy_sha256=runtime_host_policy_sha256,
            attachment_id=attachment_id,
            host_inputs=host_inputs,
            bound_settings=bound_settings,
            mcp_config=mcp_config,
            _issuance_id=issuance_id,
        )
    finally:
        with _ISSUANCE_LOCK:
            _BOUND_PENDING.pop(issuance_id, None)


def _mint_claimed_claude_provider_runtime(
    *,
    host_inputs: ClaudeRuntimeHostInputs,
    bound_settings_bytes: bytes | None,
    selected_mcp_config_bytes: bytes | None,
    attachment_sha256: str,
    provider_preparation: ClaudeProviderPreparation | None = None,
    runtime_host_policy_sha256: str | None = None,
    attachment_id: str | None = None,
) -> ClaimedClaudeProviderRuntime:
    issuance_id = secrets.token_hex(32)
    pending = {
        "host_inputs": host_inputs,
        "bound_settings_bytes": bound_settings_bytes,
        "selected_mcp_config_bytes": selected_mcp_config_bytes,
        "attachment_sha256": attachment_sha256,
        "provider_preparation": provider_preparation,
        "runtime_host_policy_sha256": runtime_host_policy_sha256,
        "attachment_id": attachment_id,
    }
    with _ISSUANCE_LOCK:
        _CLAIMED_PENDING[issuance_id] = pending
    try:
        return ClaimedClaudeProviderRuntime(
            host_inputs=host_inputs,
            bound_settings_bytes=bound_settings_bytes,
            selected_mcp_config_bytes=selected_mcp_config_bytes,
            attachment_sha256=attachment_sha256,
            provider_preparation=provider_preparation,
            runtime_host_policy_sha256=runtime_host_policy_sha256,
            attachment_id=attachment_id,
            _promotion_token=_PROMOTION_TOKEN,
            _issuance_id=issuance_id,
        )
    finally:
        with _ISSUANCE_LOCK:
            _CLAIMED_PENDING.pop(issuance_id, None)


def claim_bound_claude_provider_runtime(
    value: BoundClaudeProviderRuntime,
    *,
    provider_preparation: ClaudeProviderPreparation,
    expected_preparation_sha256: str,
    expected_runtime_host_policy_sha256: str,
    expected_attachment_sha256: str,
) -> ClaimedClaudeProviderRuntime:
    """Consume one exact per-attempt attachment after outer-arm binding."""

    if type(value) is not BoundClaudeProviderRuntime:
        raise ClaudeProviderPreparationError(
            "bound Claude provider runtime is required"
        )
    return value._claim(
        provider_preparation=provider_preparation,
        expected_preparation_sha256=expected_preparation_sha256,
        expected_runtime_host_policy_sha256=(
            expected_runtime_host_policy_sha256
        ),
        expected_attachment_sha256=expected_attachment_sha256,
    )


def replay_claimed_claude_provider_runtime(
    value: ClaimedClaudeProviderRuntime,
) -> dict[str, Any]:
    """Fully replay one claimed runtime without consuming its handoff."""

    if type(value) is not ClaimedClaudeProviderRuntime:
        raise ClaudeProviderPreparationError(
            "exact claimed Claude provider runtime is required"
        )
    try:
        state = value._validated_state()
        package = state["provider_preparation"]
        host_inputs = state["host_inputs"]
        settings = value.bound_settings_bytes
        mcp = value.selected_mcp_config_bytes
        attachment_id = state["attachment_id"]
        runtime_policy = state["runtime_host_policy_sha256"]
    except (AttributeError, KeyError, TypeError) as exc:
        raise ClaudeProviderPreparationError(
            "claimed Claude provider parent is unavailable"
        ) from exc
    replayed, _private = _replay_provider_runtime_parent(
        package,
        host_inputs=host_inputs,
        bound_settings_bytes=settings,
        selected_mcp_config_bytes=mcp,
    )
    if (
        not isinstance(attachment_id, str)
        or _ATTACHMENT_RE.fullmatch(attachment_id) is None
        or runtime_policy
        != replayed.record["runtime_host_policy"]["policy_sha256"]
    ):
        raise ClaudeProviderPreparationError(
            "claimed Claude provider attachment parent drifted"
        )
    core = {
        "schema": RUNTIME_ATTACHMENT_SCHEMA,
        "preparation_sha256": replayed.preparation_sha256,
        "runtime_host_policy_sha256": runtime_policy,
        "attachment_id": attachment_id,
        "host_inputs_sha256": host_inputs.host_inputs_sha256,
        "bound_settings_sha256": (
            None
            if settings is None
            else hashlib.sha256(settings).hexdigest()
        ),
        "selected_mcp_config_sha256": (
            None if mcp is None else hashlib.sha256(mcp).hexdigest()
        ),
    }
    if _digest(core) != value.attachment_sha256:
        raise ClaudeProviderPreparationError(
            "claimed Claude provider attachment digest drifted"
        )
    return {
        "provider_preparation": replayed,
        "host_inputs": host_inputs,
        "bound_settings_bytes": settings,
        "selected_mcp_config_bytes": mcp,
        "attachment_sha256": value.attachment_sha256,
        "runtime_host_policy_sha256": runtime_policy,
    }


def consume_claimed_claude_provider_runtime(
    value: ClaimedClaudeProviderRuntime,
) -> dict[str, Any]:
    """Consume one fully replayed provider runtime for request compilation."""

    replayed = replay_claimed_claude_provider_runtime(value)
    _consume_claimed_runtime_one_shot(value)
    return replayed


def replay_claude_provider_runtime_parent(
    package: ClaudeProviderPreparation,
    *,
    host_inputs: ClaudeRuntimeHostInputs,
    bound_settings_bytes: bytes | None,
    selected_mcp_config_bytes: bytes | None,
) -> ClaudeProviderPreparation:
    """Public final-sink replay over one provider parent and local inputs."""

    replayed, _private = _replay_provider_runtime_parent(
        package,
        host_inputs=host_inputs,
        bound_settings_bytes=bound_settings_bytes,
        selected_mcp_config_bytes=selected_mcp_config_bytes,
    )
    return replayed


def _classify_executable_error(exc: Exception) -> str:
    message = str(exc).casefold()
    if (
        "filenotfound" in message
        or "unavailable" in message
        or "does not exist" in message
    ):
        return "CLAUDE_EXECUTABLE_UNAVAILABLE"
    if (
        "no reviewed compatibility row" in message
        or "version output is not canonical" in message
        or "unsupported version" in message
    ):
        return "CLAUDE_VERSION_UNSUPPORTED"
    if "transitive_implementation_unbound" in message:
        return "CLAUDE_IMPLEMENTATION_CLOSURE_UNBOUND"
    return "CLAUDE_EXECUTABLE_OBSERVATION_FAILED"


def _startup_authority(
    *,
    scratchpad: Path,
    run_id: str,
    binding: Mapping[str, Any],
) -> str:
    try:
        replayed = replay_startup_permit_binding(
            scratchpad=scratchpad,
            expected_run_id=run_id,
            binding=binding,
        )
    except (
        AuxiliaryWritableRootStartupError,
        OSError,
        TypeError,
    ) as exc:
        raise ClaudeProviderPreparationError(
            "startup authority does not replay"
        ) from exc
    exact = replayed.get("binding")
    if not isinstance(exact, Mapping) or dict(exact) != dict(binding):
        raise ClaudeProviderPreparationError(
            "startup authority binding drifted"
        )
    return _digest(dict(exact))


def prepare_claude_provider(
    *,
    semantic_intent: Mapping[str, Any],
    phase_tool_policy: Mapping[str, Any],
    settings_policy: Mapping[str, Any],
    mcp_policy: Mapping[str, Any],
    configured_claude_bin: str,
    ambient_environment: Mapping[str, str],
    settings_evidence: Mapping[str, Any],
    stored_subscription_source_path: str | os.PathLike[str] | None,
    source_config_dir: str | os.PathLike[str] | None,
    project_root: str | os.PathLike[str],
    trusted_cwds: Sequence[str | os.PathLike[str]],
    startup_authority_binding: Mapping[str, Any],
    startup_scratchpad: str | os.PathLike[str],
    source_snapshot_sha256: str,
) -> ClaudeProviderPreparation:
    """Compile one reusable Claude provider WorkPlan preparation."""

    intent = _replay_semantic_intent(semantic_intent)
    tools = _replay_phase_tool_policy(phase_tool_policy)
    settings_policy_n = _replay_settings_policy(settings_policy)
    mcp_policy_n = _replay_mcp_policy(mcp_policy)
    backend_prefix = _backend_argv_prefix_from_selection(
        mcp_policy_n.get("runtime_selection")
    )
    if intent["backend"] != "claude":
        raise ClaudeProviderPreparationError(
            "Codex/backend cannot compile a Claude provider package"
        )
    if intent["phase"] != tools["phase"]:
        raise ClaudeProviderPreparationError(
            "semantic intent and phase tool policy differ"
        )
    if settings_policy_n["mode"] != mcp_policy_n["settings_mode"]:
        raise ClaudeProviderPreparationError(
            "settings and MCP policies differ"
        )
    host_family = _detect_host_family()
    ambient = _mapping_strings(
        ambient_environment, label="ambient_environment"
    )
    if not isinstance(settings_evidence, Mapping):
        raise ClaudeProviderPreparationError(
            "settings_evidence must be an object"
        )
    try:
        project, project_identity = _canonical_directory_identity(
            project_root,
            label="Claude provider project root",
        )
        scratchpad = Path(startup_scratchpad).resolve(strict=True)
        cwd, cwd_identity = _canonical_directory_identity(
            intent["cwd"],
            label="Claude provider runtime cwd",
        )
        trusted_rows = tuple(
            _canonical_directory_identity(
                value,
                label="Claude provider trusted cwd",
            )
            for value in trusted_cwds
        )
        trusted = tuple(row[0] for row in trusted_rows)
        trusted_identity = _trusted_cwds_identity(
            tuple(row[1] for row in trusted_rows)
        )
        if source_config_dir is None:
            source_directory = None
            source_directory_identity = None
        else:
            (
                source_directory,
                source_directory_identity,
            ) = _canonical_directory_identity(
                source_config_dir,
                label="Claude source config directory",
            )
    except (OSError, RuntimeError) as exc:
        raise ClaudeProviderPreparationError(
            "Claude provider host paths are unavailable"
        ) from exc
    if not project.is_dir() or not scratchpad.is_dir() or not cwd.is_dir():
        raise ClaudeProviderPreparationError(
            "Claude provider host paths are not directories"
        )
    if not trusted or len(set(trusted)) != len(trusted) or cwd not in trusted:
        raise ClaudeProviderPreparationError(
            "trusted cwd denominator does not contain exact runtime cwd"
        )
    if (
        intent["desired_auth_route"] == "STORED_SUBSCRIPTION_OAUTH"
    ) != (source_directory is not None):
        raise ClaudeProviderPreparationError(
            "stored subscription route and source config directory disagree"
        )
    if source_directory is not None:
        if stored_subscription_source_path is None:
            raise ClaudeProviderPreparationError(
                "stored subscription source path is required"
            )
        expected_source_path = Path(
            os.path.abspath(source_directory / ".credentials.json")
        )
        supplied_source_path = Path(
            os.path.abspath(Path(stored_subscription_source_path))
        )
        if supplied_source_path != expected_source_path:
            raise ClaudeProviderPreparationError(
                "stored subscription source path is outside exact source config"
            )
    source_snapshot = _sha256(
        source_snapshot_sha256, "source_snapshot_sha256"
    )
    assert source_snapshot is not None
    startup_digest = _startup_authority(
        scratchpad=scratchpad,
        run_id=intent["run_id"],
        binding=startup_authority_binding,
    )
    closure = _implementation_closure()
    base_evidence = _digest(
        {
            "startup_authority_sha256": startup_digest,
            "source_snapshot_sha256": source_snapshot,
            "intent_sha256": intent["intent_sha256"],
        }
    )
    if host_family == "unsupported":
        return _blocked_preparation(
            intent=intent,
            tool_policy=tools,
            settings_policy=settings_policy_n,
            mcp_policy=mcp_policy_n,
            startup_authority_sha256=startup_digest,
            source_snapshot_sha256=source_snapshot,
            implementation_closure=closure,
            debt=_debt(
                "CLAUDE_HOST_UNSUPPORTED",
                "runtime-host",
                base_evidence,
            ),
        )

    try:
        runtime_selection = mcp_policy_n.get("runtime_selection")
        executable = (
            observe_claude_generation_backend(
                installed_front=backend_prefix[0],
                backend_argv_prefix=backend_prefix,
                selection_sha256=mcp_current_selection_sha256(
                    runtime_selection
                ),
                selected_backend=runtime_selection["backend_launches"][
                    "claude"
                ],
                environment=ambient,
                required_capabilities=(),
            )
            if isinstance(runtime_selection, Mapping)
            else observe_claude_executable(
                configured_claude_bin=configured_claude_bin,
                environment=ambient,
                required_capabilities=(),
            )
        )
        executable = replay_claude_executable_observation(
            executable, require_proof_grade=False
        )
    except (ClaudeExecutableObservationError, OSError, TypeError) as exc:
        return _blocked_preparation(
            intent=intent,
            tool_policy=tools,
            settings_policy=settings_policy_n,
            mcp_policy=mcp_policy_n,
            startup_authority_sha256=startup_digest,
            source_snapshot_sha256=source_snapshot,
            implementation_closure=closure,
            debt=_debt(
                _classify_executable_error(exc),
                "claude-executable",
                base_evidence,
            ),
        )
    executable_evidence = executable["observation_sha256"]
    if (
        isinstance(runtime_selection, Mapping)
        and executable["claude_code_version"]
        != runtime_selection["backend_launches"]["claude"]["version"]
    ):
        return _blocked_preparation(
            intent=intent,
            tool_policy=tools,
            settings_policy=settings_policy_n,
            mcp_policy=mcp_policy_n,
            startup_authority_sha256=startup_digest,
            source_snapshot_sha256=source_snapshot,
            implementation_closure=closure,
            debt=_debt(
                "CLAUDE_VERSION_UNSUPPORTED",
                "selected-claude-generation",
                executable_evidence,
            ),
        )
    if executable["launch_authority"] != "PROOF_GRADE":
        return _blocked_preparation(
            intent=intent,
            tool_policy=tools,
            settings_policy=settings_policy_n,
            mcp_policy=mcp_policy_n,
            startup_authority_sha256=startup_digest,
            source_snapshot_sha256=source_snapshot,
            implementation_closure=closure,
            debt=_debt(
                "CLAUDE_IMPLEMENTATION_CLOSURE_UNBOUND",
                "claude-executable",
                executable_evidence,
            ),
        )

    try:
        observed_source_authority = (
            observe_stored_subscription_source_authority(
                source_path=(
                    stored_subscription_source_path
                    if intent["desired_auth_route"]
                    == "STORED_SUBSCRIPTION_OAUTH"
                    else None
                )
            )
        )
        stored_source = replay_stored_subscription_source_observation(
            observed_source_authority
        )
    except (
        ClaudeStoredSubscriptionSourceError,
        OSError,
        TypeError,
    ):
        return _blocked_preparation(
            intent=intent,
            tool_policy=tools,
            settings_policy=settings_policy_n,
            mcp_policy=mcp_policy_n,
            startup_authority_sha256=startup_digest,
            source_snapshot_sha256=source_snapshot,
            implementation_closure=closure,
            debt=_debt(
                "CLAUDE_STORED_SOURCE_UNSUPPORTED",
                "stored-subscription-source",
                executable_evidence,
            ),
        )

    if (
        stored_source["available"]
        and type(observed_source_authority)
        is not PromotedStoredSubscriptionSourceEvidence
    ):
        return _blocked_preparation(
            intent=intent,
            tool_policy=tools,
            settings_policy=settings_policy_n,
            mcp_policy=mcp_policy_n,
            startup_authority_sha256=startup_digest,
            source_snapshot_sha256=source_snapshot,
            implementation_closure=closure,
            debt=_debt(
                "CLAUDE_STORED_SOURCE_AUTHORITY_UNAVAILABLE",
                "stored-subscription-source-authority",
                stored_source["receipt_sha256"],
            ),
        )

    try:
        settings_authority = compile_claude_settings_authority(
            mode=settings_policy_n["mode"],
            settings_sha256=settings_policy_n["settings_sha256"],
            external_policy_sha256=settings_policy_n[
                "external_policy_sha256"
            ],
        )
        mcp_authority = compile_claude_mcp_authority(
            settings_mode=settings_policy_n["mode"],
            server_names=mcp_policy_n["server_names"],
            source_manifest_sha256=mcp_policy_n[
                "source_manifest_sha256"
            ],
            selected_config_sha256=mcp_policy_n[
                "selected_config_sha256"
            ],
            runtime_selection=mcp_policy_n.get("runtime_selection"),
        )
        helper_present = any(
            isinstance(name, str)
            and name.casefold() == "apikeyhelper"
            for name in settings_evidence
        )
        live_auth_source = observe_claude_auth_sources(
            ambient,
            settings=settings_evidence,
            settings_authority_sha256=(
                settings_authority["authority_sha256"]
                if helper_present
                else None
            ),
            stored_subscription_evidence=observed_source_authority,
        )
        auth_source = replay_claude_auth_source_observation(
            live_auth_source
        )
        auth_observation = classify_claude_auth_route(
            ambient,
            source_observation=live_auth_source,
        )
        auth_observation = replay_claude_auth_route(auth_observation)
    except (
        ClaudeAuthRouteError,
        ClaudeLaunchSecurityError,
        TypeError,
    ):
        return _blocked_preparation(
            intent=intent,
            tool_policy=tools,
            settings_policy=settings_policy_n,
            mcp_policy=mcp_policy_n,
            startup_authority_sha256=startup_digest,
            source_snapshot_sha256=source_snapshot,
            implementation_closure=closure,
            debt=_debt(
                "CLAUDE_AUTH_POLICY_UNSUPPORTED",
                "auth-observation",
                executable_evidence,
            ),
        )
    desired_route = intent["desired_auth_route"]
    if desired_route not in auth_observation["present_routes"]:
        return _blocked_preparation(
            intent=intent,
            tool_policy=tools,
            settings_policy=settings_policy_n,
            mcp_policy=mcp_policy_n,
            startup_authority_sha256=startup_digest,
            source_snapshot_sha256=source_snapshot,
            implementation_closure=closure,
            debt=_debt(
                "CLAUDE_AUTH_ROUTE_UNAVAILABLE",
                "desired-auth-route",
                auth_observation["receipt_sha256"],
            ),
        )

    try:
        auth_policy = compile_claude_auth_route_policy(
            claude_code_version=executable["claude_code_version"],
            desired_route=desired_route,
        )
        profile = compile_claude_headless_profile_from_authorities(
            executable_observation=executable,
            auth_route_policy=auth_policy,
            settings_authority=settings_authority,
            mcp_authority=mcp_authority,
            cwd=str(cwd),
            accepted_models=intent["accepted_models"],
            permission_mode=tools["permission_mode"],
            builtin_tools=tools["builtin_tools"],
            required_tools=tools["required_tools"],
            forbidden_tools=tools["forbidden_tools"],
            required_capabilities=intent["required_capabilities"],
            forbidden_capabilities=intent["forbidden_capabilities"],
            accepted_output_styles=intent["accepted_output_styles"],
        )
        profile = replay_claude_headless_profile(profile)
        endpoint_names = tuple(
            auth_policy["endpoint_policy"]["endpoint_environment"]
        )
        planned_names = planned_claude_child_environment_names(
            ambient=ambient,
            selected_route=desired_route,
            endpoint_environment_names=endpoint_names,
            phase_environment_policies=intent[
                "phase_environment_policies"
            ],
            functional_control_names=tuple(
                intent["functional_controls"]
            ),
            home_variable_policy=intent["home_variable_policy"],
        )
        planned_digest = (
            planned_claude_child_environment_key_set_sha256(
                ambient=ambient,
                selected_route=desired_route,
                endpoint_environment_names=endpoint_names,
                phase_environment_policies=intent[
                    "phase_environment_policies"
                ],
                functional_control_names=tuple(
                    intent["functional_controls"]
                ),
                home_variable_policy=intent["home_variable_policy"],
            )
        )
        launch = compile_claude_launch_security(
            headless_profile=profile,
            auth_route_policy=auth_policy,
            executable_observation=executable,
            settings_authority=settings_authority,
            mcp_authority=mcp_authority,
            home_variable_policy=intent["home_variable_policy"],
            phase_environment_policies=intent[
                "phase_environment_policies"
            ],
            functional_controls=intent["functional_controls"],
            expected_child_environment_key_set_sha256=planned_digest,
        )
        launch_request = compile_claude_launch_security_request(
            policy=launch,
            executable_observation=executable,
        )
        stream = {
            "schema": CLAUDE_STREAM_STDOUT_CONFIGURATION_SCHEMA,
            "expected_session_id": intent["session_id"],
            "expected_init_contract": profile[
                "expected_init_contract"
            ],
            "max_line_bytes": intent["max_line_bytes"],
            "max_stream_bytes": intent["max_stream_bytes"],
        }
        normalize_expected_init_contract(
            stream["expected_init_contract"]
        )
        host_policy = _runtime_host_policy(
            host_family=host_family,
            auth_route=desired_route,
            ambient_names=tuple(ambient),
            source_configured=source_directory is not None,
            source_store_class=stored_source["store_class"],
            source_observation_sha256=stored_source["receipt_sha256"],
            source_config_dir_identity_sha256=(
                source_directory_identity
            ),
            project_root_identity_sha256=project_identity,
            runtime_cwd_identity_sha256=cwd_identity,
            trusted_cwds_identity_sha256=trusted_identity,
            trusted_cwd_count=len(trusted),
            startup_authority_sha256=startup_digest,
            source_snapshot_sha256=source_snapshot,
        )
    except (
        ClaudeAuthRouteError,
        ClaudeChildEnvironmentError,
        ClaudeHeadlessProfileError,
        ClaudeLaunchSecurityError,
        ClaudeStreamJsonEvidenceError,
        ClaudeProviderPreparationError,
        TypeError,
    ):
        return _blocked_preparation(
            intent=intent,
            tool_policy=tools,
            settings_policy=settings_policy_n,
            mcp_policy=mcp_policy_n,
            startup_authority_sha256=startup_digest,
            source_snapshot_sha256=source_snapshot,
            implementation_closure=closure,
            debt=_debt(
                "CLAUDE_PROFILE_UNSUPPORTED",
                "provider-profile",
                executable_evidence,
            ),
        )

    command = _command_template(
        executable=executable["resolved_executable"],
        intent=intent,
        profile=profile,
    )
    if backend_prefix:
        command = [*backend_prefix, *command[1:]]
    authorities = {
        "executable_observation": executable,
        "auth_source_observation": auth_source,
        "auth_route_observation": auth_observation,
        "auth_route_policy": auth_policy,
        "settings_authority": settings_authority,
        "mcp_authority": mcp_authority,
        "headless_profile": profile,
        "launch_security": launch,
        "launch_security_request": launch_request,
        "stream_configuration": stream,
        "runtime_host_policy": host_policy,
    }
    core = _record_core(
        intent=intent,
        tool_policy=tools,
        settings_policy=settings_policy_n,
        mcp_policy=mcp_policy_n,
        startup_authority_sha256=startup_digest,
        source_snapshot_sha256=source_snapshot,
        implementation_closure=closure,
        authorities=authorities,
        planned_names=planned_names,
        command_template=command,
    )
    record = _compile_digest_record(core, "preparation_sha256")
    return replay_claude_provider_preparation(
        _canonical(record) + b"\n",
        expected_backend="claude",
        expected_startup_authority_sha256=startup_digest,
        expected_source_snapshot_sha256=source_snapshot,
    )


def _validate_stream(
    value: Any,
    *,
    intent: Mapping[str, Any],
    profile: Mapping[str, Any],
) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {
        "schema",
        "expected_session_id",
        "expected_init_contract",
        "max_line_bytes",
        "max_stream_bytes",
    }:
        raise ClaudeProviderPreparationError(
            "Claude stream configuration fields drifted"
        )
    try:
        expected = normalize_expected_init_contract(
            value["expected_init_contract"]
        )
    except ClaudeStreamJsonEvidenceError as exc:
        raise ClaudeProviderPreparationError(
            "Claude stream expected init does not replay"
        ) from exc
    normalized = {
        "schema": CLAUDE_STREAM_STDOUT_CONFIGURATION_SCHEMA,
        "expected_session_id": intent["session_id"],
        "expected_init_contract": profile["expected_init_contract"],
        "max_line_bytes": intent["max_line_bytes"],
        "max_stream_bytes": intent["max_stream_bytes"],
    }
    if (
        dict(value) != normalized
        or expected != profile["expected_init_contract"]
    ):
        raise ClaudeProviderPreparationError(
            "Claude stream/profile/session/ceiling authority drifted"
        )
    return normalized


def _validate_implementation_closure(value: Any) -> list[dict[str, str]]:
    if not isinstance(value, list):
        raise ClaudeProviderPreparationError(
            "Claude implementation closure must be an array"
        )
    rows: list[dict[str, str]] = []
    for row in value:
        if not isinstance(row, Mapping) or set(row) != {
            "module",
            "sha256",
        }:
            raise ClaudeProviderPreparationError(
                "Claude implementation closure row is malformed"
            )
        module = row["module"]
        if (
            not isinstance(module, str)
            or not module
            or _sha256(row["sha256"], "implementation sha256") is None
        ):
            raise ClaudeProviderPreparationError(
                "Claude implementation closure row is malformed"
            )
        rows.append({"module": module, "sha256": row["sha256"]})
    if rows != sorted(rows, key=lambda row: row["module"]):
        raise ClaudeProviderPreparationError(
            "Claude implementation closure is noncanonical"
        )
    if rows != _implementation_closure():
        raise ClaudeProviderPreparationError(
            "Claude implementation closure drifted"
        )
    return rows


def replay_claude_provider_preparation(
    raw: bytes,
    *,
    expected_backend: str,
    expected_startup_authority_sha256: str,
    expected_source_snapshot_sha256: str,
) -> ClaudeProviderPreparation:
    """Strictly replay one durable provider preparation and current code."""

    value = _decode(raw)
    _exact_keys(value, _PREPARATION_KEYS, "Claude provider preparation")
    claimed = _sha256(
        value["preparation_sha256"], "preparation_sha256"
    )
    core = {
        key: value[key]
        for key in value
        if key != "preparation_sha256"
    }
    if (
        value["schema"] != PROVIDER_PREPARATION_SCHEMA
        or claimed != _digest(core)
    ):
        raise ClaudeProviderPreparationError(
            "Claude provider preparation digest or schema drifted"
        )
    if expected_backend != "claude" or value["backend"] != "claude":
        raise ClaudeProviderPreparationError(
            "Codex/backend cannot consume a Claude provider package"
        )
    trusted_startup = _sha256(
        expected_startup_authority_sha256,
        "expected startup authority",
    )
    trusted_source = _sha256(
        expected_source_snapshot_sha256,
        "expected source snapshot",
    )
    if value["startup_authority_sha256"] != trusted_startup:
        raise ClaudeProviderPreparationError(
            "Claude provider startup authority drifted"
        )
    if value["source_snapshot_sha256"] != trusted_source:
        raise ClaudeProviderPreparationError(
            "Claude provider source snapshot authority drifted"
        )
    intent = _replay_semantic_intent(value["semantic_intent"])
    tools = _replay_phase_tool_policy(value["phase_tool_policy"])
    settings_policy = _replay_settings_policy(value["settings_policy"])
    mcp_policy = _replay_mcp_policy(value["mcp_policy"])
    if (
        intent["backend"] != "claude"
        or intent["phase"] != tools["phase"]
        or settings_policy["mode"] != mcp_policy["settings_mode"]
    ):
        raise ClaudeProviderPreparationError(
            "Claude provider parent policies disagree"
        )
    closure = _validate_implementation_closure(
        value["implementation_closure"]
    )
    debts = _replay_debts(value["debts"])
    if debts:
        if (
            any(value[name] is not None for name in _authority_fields())
            or value["planned_child_environment_names"] != []
            or value["command_template"] != []
        ):
            raise ClaudeProviderPreparationError(
                "blocked Claude provider package carries launch authority"
            )
        normalized_core = _record_core(
            intent=intent,
            tool_policy=tools,
            settings_policy=settings_policy,
            mcp_policy=mcp_policy,
            startup_authority_sha256=trusted_startup,
            source_snapshot_sha256=trusted_source,
            implementation_closure=closure,
            debts=debts,
        )
        normalized = _compile_digest_record(
            normalized_core, "preparation_sha256"
        )
        if normalized != value:
            raise ClaudeProviderPreparationError(
                "blocked Claude provider package does not replay"
            )
        return _mint_claude_provider_preparation(
            _canonical(normalized) + b"\n",
            expected_startup_authority_sha256=trusted_startup,
            expected_source_snapshot_sha256=trusted_source,
        )

    try:
        executable = replay_claude_executable_observation(
            value["executable_observation"]
        )
        auth_source = replay_claude_auth_source_observation(
            value["auth_source_observation"]
        )
        replay_stored_subscription_source_observation(
            auth_source["stored_subscription_evidence"]
        )
        auth_observation = replay_claude_auth_route(
            value["auth_route_observation"]
        )
        auth_policy = replay_claude_auth_route_policy(
            value["auth_route_policy"]
        )
        profile = replay_claude_headless_profile(
            value["headless_profile"]
        )
        launch = replay_claude_launch_security(
            value["launch_security"]
        )
        launch_request = replay_claude_launch_security_request(
            value["launch_security_request"]
        )
    except (
        ClaudeAuthRouteError,
        ClaudeExecutableObservationError,
        ClaudeHeadlessProfileError,
        ClaudeLaunchSecurityError,
        ClaudeStoredSubscriptionSourceError,
        TypeError,
    ) as exc:
        raise ClaudeProviderPreparationError(
            "Claude provider dependency authority does not replay"
        ) from exc
    settings_authority = compile_claude_settings_authority(
        mode=settings_policy["mode"],
        settings_sha256=settings_policy["settings_sha256"],
        external_policy_sha256=settings_policy[
            "external_policy_sha256"
        ],
    )
    mcp_authority = compile_claude_mcp_authority(
        settings_mode=settings_policy["mode"],
        server_names=mcp_policy["server_names"],
        source_manifest_sha256=mcp_policy["source_manifest_sha256"],
        selected_config_sha256=mcp_policy["selected_config_sha256"],
        runtime_selection=mcp_policy.get("runtime_selection"),
    )
    if (
        value["settings_authority"] != settings_authority
        or value["mcp_authority"] != mcp_authority
        or auth_observation["source_observation_sha256"]
        != auth_source["receipt_sha256"]
        or intent["desired_auth_route"]
        not in auth_observation["present_routes"]
        or auth_policy["desired_route"] != intent["desired_auth_route"]
        or profile["auth_route_policy"] != auth_policy
        or profile["settings_authority"] != settings_authority
        or profile["mcp_authority"] != mcp_authority
        or profile["expected_init_contract"]["cwd"] != intent["cwd"]
        or intent["launch_model"]
        not in profile["expected_init_contract"]["accepted_models"]
        or launch["headless_profile"] != profile
        or launch["auth_route_policy"] != auth_policy
        or launch["settings_authority"] != settings_authority
        or launch["mcp_authority"] != mcp_authority
        or launch_request["policy"] != launch
        or launch_request["executable_observation"] != executable
        or (
            isinstance(mcp_policy.get("runtime_selection"), Mapping)
            and executable["claude_code_version"]
            != mcp_policy["runtime_selection"]["backend_launches"][
                "claude"
            ]["version"]
        )
        or (
            isinstance(mcp_policy.get("runtime_selection"), Mapping)
            and (
                executable.get("backend_launch_authority", {}).get(
                    "selection_sha256"
                )
                != mcp_current_selection_sha256(
                    mcp_policy["runtime_selection"]
                )
                or executable.get("backend_launch_authority", {}).get(
                    "argv_prefix"
                )
                != list(
                    _backend_argv_prefix_from_selection(
                        mcp_policy["runtime_selection"]
                    )
                )
                or executable.get("backend_launch_authority", {}).get(
                    "selected_backend"
                )
                != mcp_policy["runtime_selection"]["backend_launches"][
                    "claude"
                ]
            )
        )
    ):
        raise ClaudeProviderPreparationError(
            "Claude provider composed authorities disagree"
        )
    stream = _validate_stream(
        value["stream_configuration"],
        intent=intent,
        profile=profile,
    )
    host_policy = _replay_runtime_host_policy(
        value["runtime_host_policy"]
    )
    if (
        host_policy["auth_route"] != intent["desired_auth_route"]
        or host_policy["startup_authority_sha256"] != trusted_startup
        or host_policy["source_snapshot_sha256"] != trusted_source
        or host_policy["source_observation_sha256"]
        != auth_source["stored_subscription_evidence"]["receipt_sha256"]
        or host_policy["ambient_key_set_sha256"]
        != auth_source["environment_key_set_sha256"]
    ):
        raise ClaudeProviderPreparationError(
            "Claude runtime host and auth/source authorities disagree"
        )
    dummy_ambient = {
        name: "1" for name in host_policy["ambient_environment_names"]
    }
    endpoint_names = tuple(
        auth_policy["endpoint_policy"]["endpoint_environment"]
    )
    try:
        planned_names = planned_claude_child_environment_names(
            ambient=dummy_ambient,
            selected_route=intent["desired_auth_route"],
            endpoint_environment_names=endpoint_names,
            phase_environment_policies=intent[
                "phase_environment_policies"
            ],
            functional_control_names=tuple(
                intent["functional_controls"]
            ),
            home_variable_policy=intent["home_variable_policy"],
        )
        planned_digest = (
            planned_claude_child_environment_key_set_sha256(
                ambient=dummy_ambient,
                selected_route=intent["desired_auth_route"],
                endpoint_environment_names=endpoint_names,
                phase_environment_policies=intent[
                    "phase_environment_policies"
                ],
                functional_control_names=tuple(
                    intent["functional_controls"]
                ),
                home_variable_policy=intent["home_variable_policy"],
            )
        )
    except ClaudeChildEnvironmentError as exc:
        raise ClaudeProviderPreparationError(
            "Claude child environment denominator does not replay"
        ) from exc
    if (
        list(planned_names) != value["planned_child_environment_names"]
        or planned_digest
        != launch["expected_child_environment_key_set_sha256"]
    ):
        raise ClaudeProviderPreparationError(
            "Claude planned child environment authority drifted"
        )
    command = _command_template(
        executable=executable["resolved_executable"],
        intent=intent,
        profile=profile,
    )
    backend_prefix = _backend_argv_prefix_from_selection(
        mcp_policy.get("runtime_selection")
    )
    if backend_prefix:
        command = [*backend_prefix, *command[1:]]
    if command != value["command_template"]:
        raise ClaudeProviderPreparationError(
            "Claude provider command template drifted"
        )
    normalized_core = _record_core(
        intent=intent,
        tool_policy=tools,
        settings_policy=settings_policy,
        mcp_policy=mcp_policy,
        startup_authority_sha256=trusted_startup,
        source_snapshot_sha256=trusted_source,
        implementation_closure=closure,
        authorities={
            "executable_observation": executable,
            "auth_source_observation": auth_source,
            "auth_route_observation": auth_observation,
            "auth_route_policy": auth_policy,
            "settings_authority": settings_authority,
            "mcp_authority": mcp_authority,
            "headless_profile": profile,
            "launch_security": launch,
            "launch_security_request": launch_request,
            "stream_configuration": stream,
            "runtime_host_policy": host_policy,
        },
        planned_names=planned_names,
        command_template=command,
    )
    normalized = _compile_digest_record(
        normalized_core, "preparation_sha256"
    )
    if normalized != value:
        raise ClaudeProviderPreparationError(
            "Claude provider preparation does not replay exactly"
        )
    return _mint_claude_provider_preparation(
        _canonical(normalized) + b"\n",
        expected_startup_authority_sha256=trusted_startup,
        expected_source_snapshot_sha256=trusted_source,
    )


def _bounded_source_bytes(
    value: bytes | None,
    *,
    label: str,
    required: bool,
) -> bytes | None:
    if value is None:
        if required:
            raise ClaudeProviderPreparationError(
                f"{label} is required",
            )
        return None
    if (
        not isinstance(value, bytes)
        or not value
        or len(value) > MAX_BOUND_SOURCE_BYTES
        or b"\x00" in value
    ):
        raise ClaudeProviderPreparationError(
            f"{label} is malformed or exceeds its bound"
        )
    try:
        value.decode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise ClaudeProviderPreparationError(
            f"{label} is not strict UTF-8 JSON"
        ) from exc
    return bytes(value)


def _contains_secret_material(raw: bytes) -> bool:
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_strict_pairs,
            parse_float=_reject_float,
            parse_constant=_reject_float,
        )
    except (
        UnicodeError,
        json.JSONDecodeError,
        ClaudeProviderPreparationError,
    ):
        return True

    def visit(item: Any, parent: str = "") -> bool:
        if isinstance(item, Mapping):
            for name, child in item.items():
                folded = str(name).casefold().replace("-", "_")
                if any(part in folded for part in _SENSITIVE_KEY_FRAGMENTS):
                    if child not in (None, "", [], {}):
                        return True
                if visit(child, folded):
                    return True
            return False
        if isinstance(item, list):
            return any(visit(child, parent) for child in item)
        if isinstance(item, str):
            return any(pattern.search(item) for pattern in _SENSITIVE_VALUE_PATTERNS)
        return False

    return visit(value)


def _replay_provider_runtime_parent(
    package: ClaudeProviderPreparation,
    *,
    host_inputs: ClaudeRuntimeHostInputs,
    bound_settings_bytes: bytes | None,
    selected_mcp_config_bytes: bytes | None,
) -> tuple[ClaudeProviderPreparation, dict[str, Any]]:
    """Replay the canonical parent at the last provider-local sink.

    Mutable issuance registries and Python-private tokens are lifecycle
    conveniences only.  They cannot authorize a runtime attachment without
    this complete parent/source/settings/host reconciliation.
    """

    if type(package) is not ClaudeProviderPreparation:
        raise ClaudeProviderPreparationError(
            "exact validator-issued provider parent is required"
        )
    replayed = _fully_replay_issued_preparation(package)
    if not replayed.eligible:
        raise ClaudeProviderPreparationError(
            "Claude provider parent carries capability debt",
            debt=replayed.record["debts"][0],
        )
    record = replayed.record
    host_policy = _replay_runtime_host_policy(
        record["runtime_host_policy"]
    )
    try:
        private = host_inputs._replay_provider_parent_inputs(
            expected_runtime_local_authority_sha256=host_policy[
                "policy_sha256"
            ],
        )
    except (ClaudeRuntimeMaterializationError, TypeError) as exc:
        raise ClaudeProviderPreparationError(
            "runtime host inputs lack the exact provider parent",
            debt=_debt(
                "CLAUDE_RUNTIME_ATTACHMENT_DRIFT",
                "runtime-local-parent",
                host_policy["policy_sha256"],
            ),
        ) from exc

    ambient = private["ambient_environment"]
    if (
        sorted(ambient, key=str.casefold)
        != host_policy["ambient_environment_names"]
        or private["auth_route"] != host_policy["auth_route"]
    ):
        raise ClaudeProviderPreparationError(
            "runtime host auth/environment parent drifted",
            debt=_debt(
                "CLAUDE_RUNTIME_ATTACHMENT_DRIFT",
                "runtime-host-parent",
                host_policy["policy_sha256"],
            ),
        )

    try:
        project, project_identity = _canonical_directory_identity(
            private["project_root"],
            label="runtime project root",
        )
        cwd, cwd_identity = _canonical_directory_identity(
            record["semantic_intent"]["cwd"],
            label="runtime semantic cwd",
        )
        trusted_rows = tuple(
            _canonical_directory_identity(
                value,
                label="runtime trusted cwd",
            )
            for value in private["trusted_cwds"]
        )
        trusted = tuple(row[0] for row in trusted_rows)
        trusted_identity = _trusted_cwds_identity(
            tuple(row[1] for row in trusted_rows)
        )
        source_value = private["source_config_dir"]
        if source_value is None:
            source = None
            source_identity = None
        else:
            source, source_identity = _canonical_directory_identity(
                source_value,
                label="runtime source config directory",
            )
    except (ClaudeProviderPreparationError, OSError, RuntimeError) as exc:
        raise ClaudeProviderPreparationError(
            "runtime provider-parent paths are unavailable",
            debt=_debt(
                "CLAUDE_RUNTIME_ATTACHMENT_DRIFT",
                "runtime-parent-paths",
                host_policy["policy_sha256"],
            ),
        ) from exc
    if (
        project_identity
        != host_policy["project_root_identity_sha256"]
        or cwd_identity
        != host_policy["runtime_cwd_identity_sha256"]
        or source_identity
        != host_policy["source_config_dir_identity_sha256"]
        or len(trusted) != host_policy["trusted_cwd_count"]
        or len(set(trusted)) != len(trusted)
        or cwd not in trusted
        or trusted_identity
        != host_policy["trusted_cwds_identity_sha256"]
    ):
        raise ClaudeProviderPreparationError(
            "runtime provider-parent path denominator drifted",
            debt=_debt(
                "CLAUDE_RUNTIME_ATTACHMENT_DRIFT",
                "runtime-parent-paths",
                host_policy["policy_sha256"],
            ),
        )

    mode = record["settings_policy"]["mode"]
    settings = _bounded_source_bytes(
        bound_settings_bytes,
        label="bound settings bytes",
        required=mode == "BOUND_SETTINGS",
    )
    mcp = _bounded_source_bytes(
        selected_mcp_config_bytes,
        label="selected MCP config bytes",
        required=mode == "BOUND_SETTINGS",
    )
    if mode == "SAFE_MODE":
        if settings is not None or mcp is not None:
            raise ClaudeProviderPreparationError(
                "safe-mode provider parent forbids settings or MCP bytes"
            )
    else:
        assert settings is not None and mcp is not None
        if _contains_secret_material(settings) or _contains_secret_material(mcp):
            raise ClaudeProviderPreparationError(
                "secret-bearing provider source is unsupported",
                debt=_debt(
                    "CLAUDE_BOUND_SOURCE_SECRET_UNSUPPORTED",
                    "bound-provider-source",
                    host_policy["policy_sha256"],
                ),
            )
        if hashlib.sha256(settings).hexdigest() != record[
            "settings_authority"
        ]["settings_sha256"]:
            raise ClaudeProviderPreparationError(
                "bound settings drifted from provider parent",
                debt=_debt(
                    "CLAUDE_BOUND_SETTINGS_DRIFT",
                    "bound-settings",
                    host_policy["policy_sha256"],
                ),
            )
        if hashlib.sha256(mcp).hexdigest() != record["mcp_authority"][
            "selected_config_sha256"
        ]:
            raise ClaudeProviderPreparationError(
                "selected MCP config drifted from provider parent",
                debt=_debt(
                    "CLAUDE_BOUND_MCP_CONFIG_DRIFT",
                    "selected-mcp-config",
                    host_policy["policy_sha256"],
                ),
            )

    if source is not None:
        observed: Mapping[str, Any] | None = None
        try:
            observed = observe_stored_subscription_source_authority(
                source_path=source / ".credentials.json"
            )
            fresh_source = replay_stored_subscription_source_observation(
                observed
            )
        except (
            ClaudeStoredSubscriptionSourceError,
            OSError,
            TypeError,
        ) as exc:
            raise ClaudeProviderPreparationError(
                "runtime stored subscription parent is stale",
                debt=_debt(
                    "CLAUDE_RUNTIME_ATTACHMENT_DRIFT",
                    "stored-subscription-source",
                    host_policy["policy_sha256"],
                ),
            ) from exc
        finally:
            if type(observed) is PromotedStoredSubscriptionSourceEvidence:
                observed._invalidate()
        if fresh_source != record["auth_source_observation"][
            "stored_subscription_evidence"
        ]:
            raise ClaudeProviderPreparationError(
                "runtime stored subscription parent drifted",
                debt=_debt(
                    "CLAUDE_RUNTIME_ATTACHMENT_DRIFT",
                    "stored-subscription-source",
                    host_policy["policy_sha256"],
                ),
            )

    try:
        project_after, project_identity_after = (
            _canonical_directory_identity(
                project,
                label="runtime project root",
            )
        )
        cwd_after, cwd_identity_after = _canonical_directory_identity(
            cwd,
            label="runtime semantic cwd",
        )
        trusted_after_rows = tuple(
            _canonical_directory_identity(
                value,
                label="runtime trusted cwd",
            )
            for value in trusted
        )
        trusted_after = tuple(
            row[0] for row in trusted_after_rows
        )
        trusted_identity_after = _trusted_cwds_identity(
            tuple(row[1] for row in trusted_after_rows)
        )
        if source is None:
            source_after = None
            source_identity_after = None
        else:
            source_after, source_identity_after = (
                _canonical_directory_identity(
                    source,
                    label="runtime source config directory",
                )
            )
    except (ClaudeProviderPreparationError, OSError, RuntimeError) as exc:
        raise ClaudeProviderPreparationError(
            "runtime provider-parent paths changed during replay",
            debt=_debt(
                "CLAUDE_RUNTIME_ATTACHMENT_DRIFT",
                "runtime-parent-paths",
                host_policy["policy_sha256"],
            ),
        ) from exc
    if (
        project_after != project
        or project_identity_after != project_identity
        or cwd_after != cwd
        or cwd_identity_after != cwd_identity
        or trusted_after != trusted
        or trusted_identity_after != trusted_identity
        or source_after != source
        or source_identity_after != source_identity
    ):
        raise ClaudeProviderPreparationError(
            "runtime provider-parent paths changed during replay",
            debt=_debt(
                "CLAUDE_RUNTIME_ATTACHMENT_DRIFT",
                "runtime-parent-paths",
                host_policy["policy_sha256"],
            ),
        )
    if source_after is not None:
        observed_after: Mapping[str, Any] | None = None
        try:
            observed_after = observe_stored_subscription_source_authority(
                source_path=source_after / ".credentials.json"
            )
            fresh_source_after = (
                replay_stored_subscription_source_observation(
                    observed_after
                )
            )
        except (
            ClaudeStoredSubscriptionSourceError,
            OSError,
            TypeError,
        ) as exc:
            raise ClaudeProviderPreparationError(
                "runtime stored subscription parent changed during replay",
                debt=_debt(
                    "CLAUDE_RUNTIME_ATTACHMENT_DRIFT",
                    "stored-subscription-source",
                    host_policy["policy_sha256"],
                ),
            ) from exc
        finally:
            if (
                type(observed_after)
                is PromotedStoredSubscriptionSourceEvidence
            ):
                observed_after._invalidate()
        if fresh_source_after != record["auth_source_observation"][
            "stored_subscription_evidence"
        ]:
            raise ClaudeProviderPreparationError(
                "runtime stored subscription parent changed during replay",
                debt=_debt(
                    "CLAUDE_RUNTIME_ATTACHMENT_DRIFT",
                    "stored-subscription-source",
                    host_policy["policy_sha256"],
                ),
            )

    return replayed, private


def attach_claude_provider_runtime(
    package: ClaudeProviderPreparation,
    *,
    ambient_environment: Mapping[str, str],
    source_config_dir: str | os.PathLike[str] | None,
    project_root: str | os.PathLike[str],
    trusted_cwds: Sequence[str | os.PathLike[str]],
    bound_settings_bytes: bytes | None = None,
    selected_mcp_config_bytes: bytes | None = None,
) -> BoundClaudeProviderRuntime:
    """Create one fresh, opaque runtime attachment for one future attempt."""

    if type(package) is not ClaudeProviderPreparation:
        raise ClaudeProviderPreparationError(
            "exact validator-issued Claude provider preparation is required"
        )
    package.validate_for_backend("claude")
    record = package.record
    host_policy = _replay_runtime_host_policy(
        record["runtime_host_policy"]
    )
    ambient = _mapping_strings(
        ambient_environment, label="ambient_environment"
    )
    if sorted(ambient, key=str.casefold) != host_policy[
        "ambient_environment_names"
    ]:
        debt = _debt(
            "CLAUDE_RUNTIME_ATTACHMENT_DRIFT",
            "ambient-key-denominator",
            host_policy["policy_sha256"],
        )
        raise ClaudeProviderPreparationError(
            "runtime ambient key denominator drifted",
            debt=debt,
        )
    source_present = source_config_dir is not None
    if source_present != host_policy["source_configured"]:
        debt = _debt(
            "CLAUDE_RUNTIME_ATTACHMENT_DRIFT",
            "source-config-presence",
            host_policy["policy_sha256"],
        )
        raise ClaudeProviderPreparationError(
            "runtime source configuration presence drifted",
            debt=debt,
        )
    try:
        project, project_identity = _canonical_directory_identity(
            project_root,
            label="runtime project root",
        )
        cwd, cwd_identity = _canonical_directory_identity(
            record["semantic_intent"]["cwd"],
            label="runtime semantic cwd",
        )
        trusted_rows = tuple(
            _canonical_directory_identity(
                value,
                label="runtime trusted cwd",
            )
            for value in trusted_cwds
        )
        trusted = tuple(row[0] for row in trusted_rows)
        trusted_identity = _trusted_cwds_identity(
            tuple(row[1] for row in trusted_rows)
        )
        if source_config_dir is None:
            source_directory = None
            source_directory_identity = None
        else:
            (
                source_directory,
                source_directory_identity,
            ) = _canonical_directory_identity(
                source_config_dir,
                label="runtime source config directory",
            )
    except (
        ClaudeProviderPreparationError,
        OSError,
        RuntimeError,
    ) as exc:
        debt = _debt(
            "CLAUDE_RUNTIME_HOST_POLICY_UNSUPPORTED",
            "runtime-host-paths",
            host_policy["policy_sha256"],
        )
        raise ClaudeProviderPreparationError(
            "runtime host paths are unavailable",
            debt=debt,
        ) from exc
    if project_identity != host_policy["project_root_identity_sha256"]:
        raise ClaudeProviderPreparationError(
            "runtime project root identity drifted",
            debt=_debt(
                "CLAUDE_RUNTIME_ATTACHMENT_DRIFT",
                "project-root-denominator",
                host_policy["policy_sha256"],
            ),
        )
    if cwd_identity != host_policy["runtime_cwd_identity_sha256"]:
        raise ClaudeProviderPreparationError(
            "runtime semantic cwd identity drifted",
            debt=_debt(
                "CLAUDE_RUNTIME_ATTACHMENT_DRIFT",
                "runtime-cwd-denominator",
                host_policy["policy_sha256"],
            ),
        )
    if (
        source_directory_identity
        != host_policy["source_config_dir_identity_sha256"]
    ):
        raise ClaudeProviderPreparationError(
            "runtime source config directory identity drifted",
            debt=_debt(
                "CLAUDE_RUNTIME_ATTACHMENT_DRIFT",
                "source-config-denominator",
                host_policy["policy_sha256"],
            ),
        )
    if (
        len(trusted) != host_policy["trusted_cwd_count"]
        or len(set(trusted)) != len(trusted)
        or cwd not in trusted
        or trusted_identity
        != host_policy["trusted_cwds_identity_sha256"]
    ):
        debt = _debt(
            "CLAUDE_RUNTIME_ATTACHMENT_DRIFT",
            "trusted-cwd-denominator",
            host_policy["policy_sha256"],
        )
        raise ClaudeProviderPreparationError(
            "runtime trusted cwd denominator drifted",
            debt=debt,
        )
    if source_directory is not None:
        observed: Mapping[str, Any] | None = None
        try:
            observed = observe_stored_subscription_source_authority(
                source_path=source_directory / ".credentials.json"
            )
            fresh_source = (
                replay_stored_subscription_source_observation(observed)
            )
        except (
            ClaudeStoredSubscriptionSourceError,
            OSError,
            TypeError,
        ) as exc:
            raise ClaudeProviderPreparationError(
                "runtime stored subscription source is stale or unavailable",
                debt=_debt(
                    "CLAUDE_RUNTIME_ATTACHMENT_DRIFT",
                    "stored-subscription-source",
                    host_policy["policy_sha256"],
                ),
            ) from exc
        finally:
            if (
                type(observed)
                is PromotedStoredSubscriptionSourceEvidence
            ):
                observed._invalidate()
        expected_source = record["auth_source_observation"][
            "stored_subscription_evidence"
        ]
        if fresh_source != expected_source:
            raise ClaudeProviderPreparationError(
                "runtime stored subscription source identity drifted",
                debt=_debt(
                    "CLAUDE_RUNTIME_ATTACHMENT_DRIFT",
                    "stored-subscription-source",
                    host_policy["policy_sha256"],
                ),
            )
    mode = record["settings_policy"]["mode"]
    settings = _bounded_source_bytes(
        bound_settings_bytes,
        label="bound settings bytes",
        required=mode == "BOUND_SETTINGS",
    )
    mcp = _bounded_source_bytes(
        selected_mcp_config_bytes,
        label="selected MCP config bytes",
        required=mode == "BOUND_SETTINGS",
    )
    if mode == "SAFE_MODE" and (settings is not None or mcp is not None):
        raise ClaudeProviderPreparationError(
            "safe mode cannot carry settings or MCP source bytes"
        )
    if settings is not None:
        if _contains_secret_material(settings) or _contains_secret_material(mcp):
            debt = _debt(
                "CLAUDE_BOUND_SOURCE_SECRET_UNSUPPORTED",
                "bound-provider-source",
                host_policy["policy_sha256"],
            )
            raise ClaudeProviderPreparationError(
                "secret-bearing bound provider source requires an opaque "
                "secret provider",
                debt=debt,
            )
        if hashlib.sha256(settings).hexdigest() != record[
            "settings_authority"
        ]["settings_sha256"]:
            debt = _debt(
                "CLAUDE_BOUND_SETTINGS_DRIFT",
                "bound-settings",
                host_policy["policy_sha256"],
            )
            raise ClaudeProviderPreparationError(
                "bound settings bytes drifted",
                debt=debt,
            )
        assert mcp is not None
        if hashlib.sha256(mcp).hexdigest() != record["mcp_authority"][
            "selected_config_sha256"
        ]:
            debt = _debt(
                "CLAUDE_BOUND_MCP_CONFIG_DRIFT",
                "selected-mcp-config",
                host_policy["policy_sha256"],
            )
            raise ClaudeProviderPreparationError(
                "selected MCP config bytes drifted",
                debt=debt,
            )
    try:
        host_inputs = compile_claude_runtime_host_inputs(
            auth_route=host_policy["auth_route"],
            ambient_environment=ambient,
            source_config_dir=source_directory,
            project_root=project,
            trusted_cwds=trusted,
            runtime_local_authority_sha256=host_policy[
                "policy_sha256"
            ],
        )
    except (ClaudeRuntimeMaterializationError, OSError, TypeError) as exc:
        debt = _debt(
            "CLAUDE_RUNTIME_HOST_POLICY_UNSUPPORTED",
            "runtime-host-inputs",
            host_policy["policy_sha256"],
        )
        raise ClaudeProviderPreparationError(
            "runtime host inputs cannot be attached",
            debt=debt,
        ) from exc
    try:
        project_after, project_identity_after = (
            _canonical_directory_identity(
                project,
                label="runtime project root",
            )
        )
        cwd_after, cwd_identity_after = _canonical_directory_identity(
            cwd,
            label="runtime semantic cwd",
        )
        trusted_after_rows = tuple(
            _canonical_directory_identity(
                value,
                label="runtime trusted cwd",
            )
            for value in trusted
        )
        trusted_after = tuple(
            row[0] for row in trusted_after_rows
        )
        trusted_identity_after = _trusted_cwds_identity(
            tuple(row[1] for row in trusted_after_rows)
        )
        if source_directory is None:
            source_directory_after = None
            source_directory_identity_after = None
        else:
            (
                source_directory_after,
                source_directory_identity_after,
            ) = _canonical_directory_identity(
                source_directory,
                label="runtime source config directory",
            )
    except ClaudeProviderPreparationError as exc:
        raise ClaudeProviderPreparationError(
            "runtime-local path identity changed during attachment",
            debt=_debt(
                "CLAUDE_RUNTIME_ATTACHMENT_DRIFT",
                "runtime-local-denominator",
                host_policy["policy_sha256"],
            ),
        ) from exc
    if (
        project_after != project
        or project_identity_after != project_identity
        or cwd_after != cwd
        or cwd_identity_after != cwd_identity
        or trusted_after != trusted
        or trusted_identity_after != trusted_identity
        or source_directory_after != source_directory
        or source_directory_identity_after
        != source_directory_identity
    ):
        raise ClaudeProviderPreparationError(
            "runtime-local path identity changed during attachment",
            debt=_debt(
                "CLAUDE_RUNTIME_ATTACHMENT_DRIFT",
                "runtime-local-denominator",
                host_policy["policy_sha256"],
            ),
        )
    if source_directory is not None:
        observed_after: Mapping[str, Any] | None = None
        try:
            observed_after = (
                observe_stored_subscription_source_authority(
                    source_path=(
                        source_directory / ".credentials.json"
                    )
                )
            )
            fresh_source_after = (
                replay_stored_subscription_source_observation(
                    observed_after
                )
            )
        except (
            ClaudeStoredSubscriptionSourceError,
            OSError,
            TypeError,
        ) as exc:
            raise ClaudeProviderPreparationError(
                "runtime stored subscription source changed during attachment",
                debt=_debt(
                    "CLAUDE_RUNTIME_ATTACHMENT_DRIFT",
                    "stored-subscription-source",
                    host_policy["policy_sha256"],
                ),
            ) from exc
        finally:
            if (
                type(observed_after)
                is PromotedStoredSubscriptionSourceEvidence
            ):
                observed_after._invalidate()
        if fresh_source_after != expected_source:
            raise ClaudeProviderPreparationError(
                "runtime stored subscription source changed during attachment",
                debt=_debt(
                    "CLAUDE_RUNTIME_ATTACHMENT_DRIFT",
                    "stored-subscription-source",
                    host_policy["policy_sha256"],
                ),
            )
    attachment_id = secrets.token_hex(16)
    if _ATTACHMENT_RE.fullmatch(attachment_id) is None:
        raise ClaudeProviderPreparationError(
            "runtime attachment identifier is malformed"
        )
    return _mint_bound_claude_provider_runtime(
        preparation_sha256=package.preparation_sha256,
        runtime_host_policy_sha256=host_policy["policy_sha256"],
        attachment_id=attachment_id,
        host_inputs=host_inputs,
        bound_settings=settings,
        mcp_config=mcp,
    )


__all__ = [
    "CLAUDE_STREAM_STDOUT_CONFIGURATION_SCHEMA",
    "DEBT_CODES",
    "MCP_POLICY_SCHEMA",
    "PHASE_TOOL_POLICY_SCHEMA",
    "PROVIDER_PREPARATION_SCHEMA",
    "RUNTIME_ATTACHMENT_SCHEMA",
    "RUNTIME_HOST_POLICY_SCHEMA",
    "SEMANTIC_INTENT_SCHEMA",
    "SETTINGS_POLICY_SCHEMA",
    "BoundClaudeProviderRuntime",
    "ClaimedClaudeProviderRuntime",
    "ClaudeProviderPreparation",
    "ClaudeProviderPreparationError",
    "attach_claude_provider_runtime",
    "claim_bound_claude_provider_runtime",
    "consume_claimed_claude_provider_runtime",
    "compile_claude_mcp_policy",
    "compile_claude_phase_tool_policy",
    "compile_claude_provider_semantic_intent",
    "compile_claude_settings_policy",
    "prepare_claude_provider",
    "replay_claimed_claude_provider_runtime",
    "replay_claude_provider_runtime_parent",
    "replay_claude_provider_preparation",
]
