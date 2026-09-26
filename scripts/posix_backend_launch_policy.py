"""Render exact, fail-closed POSIX guest backend launches without executing.

The trusted guest supervisor supplies already-open descriptors.  This module
retains and fingerprints them, validates sealed policy material, and renders a
non-secret argv plus a closed environment contract.  It performs no import-time
I/O and never starts a process, reads ambient configuration, or contacts a
backend.

The provider admission digest represents the outer Landlock/cgroup/network
boundary.  CLI version/help conformance is bound to the authenticated install
generation: runtime consumes that exact receipt and never resolves ``latest``
or accepts ambient executable bytes.

Python callers are not an authentication boundary.  Production launch-
authority issuance therefore remains unavailable until an authenticated native or
out-of-process verifier supplies a non-constructible admission capability.
The explicit ``TEST_ONLY_*`` seam uses a distinct authority type and produces
receipts that can never satisfy the production ISSUED status contract.
"""

from __future__ import annotations

import copy
try:
    import fcntl
except ImportError:  # Windows has no fcntl module.
    fcntl = None  # type: ignore[assignment]
import hashlib
import json
import os
import re
import stat
import struct
import sys
import threading
import uuid
import weakref
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Mapping, NoReturn
from urllib.parse import urlsplit


REQUEST_SCHEMA = "plamen.posix_backend_launch_request.v3"
PUBLIC_RECEIPT_SCHEMA = "plamen.posix_backend_launch_receipt.v3"
COMPLETION_RECEIPT_SCHEMA = "plamen.posix_backend_launch_completion.v1"
TEST_ONLY_PUBLIC_RECEIPT_SCHEMA = (
    "plamen.test_only.posix_backend_launch_receipt.v1"
)
TEST_ONLY_COMPLETION_RECEIPT_SCHEMA = (
    "plamen.test_only.posix_backend_launch_completion.v1"
)
PRODUCTION_AUTHORITY_CLASS = "AUTHENTICATED_NATIVE_OUT_OF_PROCESS_V1"
TEST_ONLY_AUTHORITY_CLASS = "TEST_ONLY_NONAUTHORITATIVE"
BACKEND_PARITY_ACCEPTANCE_SCHEMA = "plamen.backend_parity_acceptance.v1"
BACKEND_MODEL_ROUTE_SCHEMA = "plamen.backend_model_route_selection.v1"
BACKEND_CLI_BEHAVIOR_SCHEMA = "plamen.backend-cli-behavior-contract.v1"
INSTALL_GENERATION_RECEIPT_SCHEMA = (
    "plamen.native-backend-latest-acquisition-receipt.v1"
)
INSTALL_GENERATION_AUTHORITY_CLASS = (
    "AUTHENTICATED_INSTALL_GENERATION_PRODUCER_V1"
)
TEST_ONLY_INSTALL_GENERATION_AUTHORITY_CLASS = (
    "TEST_ONLY_INSTALL_GENERATION_NONAUTHORITATIVE"
)
MAX_REQUEST_BYTES = 64 * 1024
MAX_EXECUTABLE_BYTES = 512 * 1024 * 1024
MAX_PROMPT_BYTES = 16 * 1024 * 1024
MAX_CREDENTIAL_BYTES = 1024 * 1024
MAX_POLICY_BYTES = 1024 * 1024
MAX_CA_BYTES = 1024 * 1024
MAX_JSON_DEPTH = 64
MAX_JSON_NODES = 16_384
CODEX_PROFILE_NAME = "plamen-audit"
# Historical structural-test vectors only.  Runtime admission never reads
# these values and the public surface does not export them.
LEGACY_CODEX_FIXTURE_VERSION = "0.152.0"
LEGACY_CLAUDE_FIXTURE_VERSION = "2.1.252"
CODEX_HOME_PATH = "/run/plamen/private/codex"
CODEX_PROFILE_MATERIALIZATION_PATH = (
    f"{CODEX_HOME_PATH}/plamen-audit.config.toml"
)
CODEX_AUTH_MATERIALIZATION_PATH = f"{CODEX_HOME_PATH}/auth.json"
CODEX_CONFIG_CENSUS_CONTRACT = (
    "PRIVATE_HOME_BASE_ABSENT_CONTROL_ANCESTORS_PROJECT_CONFIG_ABSENT_V1"
)
CODEX_CREDENTIAL_GLOB_SCAN_DEPTH = 16
LINUX_EGRESS_TRANSPORT = "LINUX_LOOPBACK_TCP_TO_UDS_SHIM"
APPLE_EGRESS_TRANSPORT = "APPLE_PRIVATE_GUEST_GATEWAY"
EGRESS_SCOPE = "VERIFIED_CONNECT_ALLOWLIST"
CA_BUNDLE_SCOPE = "PUBLIC_WEBPKI_CA_BUNDLE"
GUEST_TOOLCHAIN_PATH = "/opt/plamen/bin"
PRIVATE_ROOT_PATH = "/run/plamen/private"
PRIVATE_TMP_PATH = "/run/plamen/private/tmp"
CLAUDE_CONFIG_PATH = f"{PRIVATE_ROOT_PATH}/claude"
CLAUDE_CREDENTIAL_MATERIALIZATION_PATH = (
    f"{CLAUDE_CONFIG_PATH}/.credentials.json"
)
CLAUDE_CREDENTIAL_DELIVERY = (
    "SUPERVISOR_MATERIALIZE_EXACT_PRIVATE_CLAUDE_STORED_SUBSCRIPTION_"
    "THEN_CLOSE"
)
CODEX_EXECUTABLE_PROVENANCE = "SIGSTORE_VERIFIED_GITHUB_RELEASE"
CLAUDE_EXECUTABLE_PROVENANCE = "ANTHROPIC_MANIFEST_NO_SIGSTORE"
CLAUDE_SETTINGS_CONTRACT = "POSIX_NATIVE_SANDBOX_DONTASK_V1"
CODEX_PERMISSION_PROFILE_STATUS = "DEFENSE_IN_DEPTH_CONFORMANCE_BOUND"
CODEX_PERMISSION_PROFILE_NOT_APPLICABLE = "NOT_APPLICABLE"
CREDENTIAL_ISOLATION_MODES = frozenset({
    "NATIVE_PROCESS_DOMAIN_SPLIT_NO_DESCENDANT_READ_V1",
    "OUT_OF_PROCESS_CREDENTIAL_BROKER_NO_DESCENDANT_READ_V1",
})
# This is the common WorkerExecutionReceipt/native-executor denominator.  It
# must fit below the broker's 16 MiB observed-stream ceiling so both backend
# transports have identical overflow and replay semantics.
STDOUT_LIMIT_BYTES = 8 * 1024 * 1024
STDERR_LIMIT_BYTES = 2 * 1024 * 1024

_HEX_RE = re.compile(r"[0-9a-f]{64}")
_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}")
_MODEL_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}")
_VERSION_RE = re.compile(
    r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
)
_FIELDS = frozenset({
    "schema", "backend", "platform", "attempt_id", "session_id", "config_sha256",
    "image_sha256", "provider_admission_sha256", "model", "claude_tools",
    "allowed_version",
    "cli_conformance_sha256",
    "cli_behavior_contract_sha256", "install_generation_sha256",
    "latest_resolution_receipt_sha256", "publisher_identity_sha256",
    "provenance_receipt_sha256",
    "release_id", "release_manifest_sha256", "release_ca_sha256",
    "authority_authentication_sha256",
    "executable_provenance", "runtime_closure_sha256",
    "control_path", "control_dir_fd", "project_path", "project_dir_fd",
    "scratch_path", "scratch_dir_fd", "prompt_fd", "credential_fd",
    "ca_bundle_scope",
    "proxy_endpoint", "proxy_authority_sha256",
    "egress_admission_sha256", "egress_transport", "proxy_attempt_id",
    "proxy_scope", "backend_network", "tool_network", "limits",
    "codex_profile_sha256", "claude_settings_contract",
    "claude_settings_sha256", "claude_mcp_sha256",
    "codex_permission_profile_status", "credential_isolation_mode",
    "credential_isolation_sha256",
    "prompt_sha256", "credential_sha256",
    "codex_config_census_contract", "codex_config_census_contract_sha256",
    "codex_config_census_evidence_sha256", "codex_profile_fd",
    "claude_settings_fd", "claude_mcp_fd",
})
_LIMITS = MappingProxyType({
    "prompt_bytes": MAX_PROMPT_BYTES,
    "credential_bytes": MAX_CREDENTIAL_BYTES,
    "stdout_bytes": STDOUT_LIMIT_BYTES,
    "stderr_bytes": STDERR_LIMIT_BYTES,
})
_CLAUDE_TOOLS = ("Bash", "Edit", "Glob", "Grep", "Read", "Write")
_CLAUDE_DENIED_TOOLS = (
    "Agent", "Computer", "Task", "WebFetch", "WebSearch", "mcp__*",
)
_MODEL_ROUTES = MappingProxyType({
    "codex": MappingProxyType({
        "R3_FRONTIER_REASONING": (
            "gpt-5.6-sol", "gpt-5.6-terra", "gpt-5.6-luna",
        ),
        "R2_STANDARD_REASONING": ("gpt-5.6-terra", "gpt-5.6-luna"),
        "R1_ECONOMY_STRUCTURED": ("gpt-5.6-luna",),
    }),
    "claude": MappingProxyType({
        "R3_FRONTIER_REASONING": ("claude-opus-5", "claude-sonnet-5"),
        "R2_STANDARD_REASONING": ("claude-sonnet-5",),
        "R1_ECONOMY_STRUCTURED": ("claude-sonnet-5",),
    }),
})
_RETRY_DISPOSITIONS = MappingProxyType({
    "AUTHENTICATION": "HARD_STOP",
    "CONTEXT_LIMIT": "NEW_PLAN_GENERATION_REQUIRED",
    "MALFORMED_STREAM": "HARD_STOP",
    "MODEL_UNAVAILABLE": "EXPLICIT_MODEL_GENERATION_REQUIRED",
    "OUTPUT_OVERFLOW": "HARD_STOP",
    "POLICY_REFUSAL": "NEW_PROMPT_GENERATION_REQUIRED",
    "RATE_OR_USAGE_LIMIT": "PAUSE_EXACT_ROUTE",
    "TRANSIENT_CAPACITY": "RETRY_EXACT_ROUTE_OR_EXPLICIT_MODEL_GENERATION",
    "TRANSIENT_TRANSPORT": "RETRY_EXACT_ROUTE",
})
_MODEL_ROUTE_FIELDS = frozenset({
    "schema", "backend", "model_capability_tier", "primary_model",
    "selected_model", "fallback_authorized", "fallback_used",
    "capability_receipt_sha256", "selection", "account_default_forbidden",
    "authority_class", "route_sha256",
})
_CREDENTIAL_PATHS = (
    PRIVATE_ROOT_PATH, f"{PRIVATE_ROOT_PATH}/**", "/run/secrets/**",
    "/root/.aws/**", "/root/.claude/**", "/root/.codex/**",
    "/root/.config/gcloud/**", "/root/.ssh/**",
    "/home/*/.aws/**", "/home/*/.claude/**", "/home/*/.codex/**",
    "/home/*/.config/gcloud/**", "/home/*/.ssh/**",
    "**/.env", "**/.env.*", "**/.netrc", "**/.npmrc", "**/.pypirc",
    "**/.aws/credentials", "**/.docker/config.json", "**/.kube/config",
    "**/.config/gcloud/application_default_credentials.json",
    "**/auth.json", "**/credentials", "**/credentials.json",
)
_CREDENTIAL_ENV = (
    "ALL_PROXY", "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN",
    "CLAUDE_CODE_OAUTH_TOKEN", "CLAUDE_CONFIG_DIR", "CODEX_HOME",
    "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
    "GOOGLE_APPLICATION_CREDENTIALS", "HTTP_PROXY", "HTTPS_PROXY",
    "NODE_EXTRA_CA_CERTS", "NO_PROXY", "OPENAI_API_KEY", "SSL_CERT_FILE",
    "all_proxy", "http_proxy", "https_proxy", "no_proxy",
)
_CODEX_CREDENTIAL_GLOBS = (
    "**/.env", "**/.env.*", "**/.netrc", "**/.npmrc", "**/.pypirc",
    "**/.aws/credentials", "**/.docker/config.json", "**/.kube/config",
    "**/.config/gcloud/application_default_credentials.json",
    "**/auth.json", "**/credentials", "**/credentials.json",
)


class PosixBackendLaunchPolicyError(RuntimeError):
    """A launch request, descriptor, or replay failed closed."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _fail(code: str, message: str) -> NoReturn:
    # Never retain input-bearing parser, pathname, or OS exceptions.
    raise PosixBackendLaunchPolicyError(code, message) from None


def _require_posix_fcntl() -> Any:
    """Return the native descriptor API only on an admitted POSIX host."""

    if (
        fcntl is None
        or os.name != "posix"
        or sys.platform not in {"darwin", "linux"}
    ):
        _fail(
            "PLATFORM_UNSUPPORTED",
            "POSIX descriptor controls are unavailable on this platform",
        )
    return fcntl


def _canonical(value: Mapping[str, Any]) -> bytes:
    _bounded_json_shape(value)
    failed = False
    try:
        raw = json.dumps(
            dict(value), ensure_ascii=True, allow_nan=False, sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, RecursionError, OverflowError):
        failed = True
        raw = b""
    if failed:
        _fail("NOT_CANONICAL_JSON", "value is not bounded canonical JSON")
    return raw


def backend_parity_acceptance_matrix() -> dict[str, Any]:
    """Return the exact backend-neutral launch and recovery denominator.

    The matrix is a public structural contract, not an availability or launch
    authority.  Exact executable, model-capability, provider, credential, and
    terminal receipts remain mandatory before production execution.
    """

    matrix = {
        "schema": BACKEND_PARITY_ACCEPTANCE_SCHEMA,
        "semantic_profile": "semantic_v1",
        "backends": {
            "claude": {
                "managed_cli_version": "AUTHENTICATED_INSTALL_GENERATION",
                "credential_source": "CLAUDE_STORED_SUBSCRIPTION_AUTHORITY",
                "credential_delivery": CLAUDE_CREDENTIAL_DELIVERY,
                "credential_materialization_path": (
                    CLAUDE_CREDENTIAL_MATERIALIZATION_PATH
                ),
                "mcp_policy": "EXACT_EMPTY_CONFIG_REQUIRED",
                "tool_execution": "LOCAL_GUEST_NATIVE_TOOLS",
            },
            "codex": {
                "managed_cli_version": "AUTHENTICATED_INSTALL_GENERATION",
                "credential_source": "CODEX_STORED_AUTH_AUTHORITY",
                "credential_delivery": (
                    "SUPERVISOR_MATERIALIZE_EXACT_PRIVATE_CODEX_HOME_"
                    "CENSUS_THEN_CLOSE"
                ),
                "credential_materialization_path": (
                    CODEX_AUTH_MATERIALIZATION_PATH
                ),
                "mcp_policy": "DISABLED_EMPTY_CONFIG",
                "tool_execution": "LOCAL_GUEST_NATIVE_TOOLS",
            },
        },
        "common": {
            "credential_custody": (
                "NATIVE_PROCESS_DOMAIN_SPLIT_NO_DESCENDANT_READ_V1"
            ),
            "credential_descriptor_inherited": False,
            "credential_secret_in_outer_environment": False,
            "mcp_required": False,
            "model_owned_children": False,
            "backend_network": "VERIFIED_PROXY_ONLY",
            "tool_network": "DENY",
            "stream_replay": {
                "stdout_limit_bytes": STDOUT_LIMIT_BYTES,
                "stderr_limit_bytes": STDERR_LIMIT_BYTES,
                "requires_eof": True,
                "overflow_is_terminal": True,
                "digest_bound": True,
            },
            "retry_dispositions": dict(_RETRY_DISPOSITIONS),
            "resume": {
                "mode": "EXACT_CHECKPOINT_REPLAY_NEW_NATIVE_ATTEMPT",
                "provider_conversation_resume": False,
                "same_backend_model_tools_required": True,
                "backend_or_model_change": "NEW_EXECUTION_GENERATION",
            },
            "model_availability": (
                "EXACT_CAPABILITY_RECEIPT_REQUIRED_BEFORE_SELECTION"
            ),
            "fallback": "EXPLICIT_AUTHORIZATION_AND_NEW_GENERATION_ONLY",
            "daybreak_model_required": False,
        },
        "model_routes": {
            backend: {
                tier: list(models) for tier, models in routes.items()
            }
            for backend, routes in _MODEL_ROUTES.items()
        },
    }
    return json.loads(_canonical(matrix).decode("ascii"))


def backend_cli_behavior_contract(backend: str) -> dict[str, Any]:
    """Return version-neutral CLI semantics an install probe must establish."""

    required = {
        "claude": (
            "--allowedTools", "--disallowedTools", "--json-schema",
            "--mcp-config", "--model", "--output-format=stream-json",
            "--permission-mode", "--strict-mcp-config",
        ),
        "codex": (
            "--ephemeral", "--json", "--model", "--output-last-message",
            "--sandbox", "--skip-git-repo-check",
        ),
    }
    if backend not in required:
        _fail("BACKEND", "CLI behavior backend must be codex or claude")
    return {
        "schema": BACKEND_CLI_BEHAVIOR_SCHEMA,
        "backend": backend,
        "required_semantics": sorted(required[backend]),
        "version_binding": "EXACT_RESOLVED_INSTALL_GENERATION",
        "observation": "AUTHENTICATED_INSTALL_TIME_CLI_PROBE",
        "runtime_resolution": "FORBIDDEN",
    }


def backend_cli_behavior_contract_sha256(backend: str) -> str:
    return hashlib.sha256(
        _canonical(backend_cli_behavior_contract(backend))
    ).hexdigest()


def resolve_backend_model_route(
    *,
    backend: str,
    model_capability_tier: str,
    verified_available_models: list[str] | tuple[str, ...],
    capability_receipt_sha256: str,
    requested_model: str | None = None,
    allow_model_fallback: bool = False,
) -> dict[str, Any]:
    """Resolve one exact model without an account-default substitution.

    ``verified_available_models`` is accepted only together with the digest of
    its independently authenticated capability receipt.  This pure compiler
    binds that evidence; it does not authenticate the receipt itself.
    """

    if backend not in _MODEL_ROUTES:
        _fail("MODEL_ROUTE", "backend has no admitted model route")
    routes = _MODEL_ROUTES[backend]
    if model_capability_tier not in routes:
        _fail("MODEL_ROUTE", "model capability tier is not admitted")
    if (
        type(capability_receipt_sha256) is not str
        or _HEX_RE.fullmatch(capability_receipt_sha256) is None
    ):
        _fail("MODEL_CAPABILITY", "exact model capability receipt is required")
    if type(allow_model_fallback) is not bool:
        _fail("MODEL_FALLBACK", "model fallback authority must be boolean")
    if type(verified_available_models) not in {list, tuple}:
        _fail("MODEL_CAPABILITY", "verified model set must be a sequence")
    available = tuple(verified_available_models)
    if (
        not available
        or len(set(available)) != len(available)
        or any(
            type(model) is not str
            or _MODEL_RE.fullmatch(model) is None
            for model in available
        )
    ):
        _fail("MODEL_CAPABILITY", "verified model set is malformed")

    candidates = routes[model_capability_tier]
    primary = candidates[0]
    if requested_model is not None:
        if (
            type(requested_model) is not str
            or requested_model not in candidates
        ):
            _fail("MODEL_ROUTE", "requested model is not admitted for the tier")
        if requested_model != primary and not allow_model_fallback:
            _fail("MODEL_FALLBACK", "non-primary model requires explicit fallback")
        if requested_model not in available:
            _fail("MODEL_UNAVAILABLE", "requested model is not receipt-available")
        selected = requested_model
    elif primary in available:
        selected = primary
    else:
        if not allow_model_fallback:
            _fail("MODEL_UNAVAILABLE", "primary model is not receipt-available")
        selected = next(
            (model for model in candidates[1:] if model in available),
            "",
        )
        if not selected:
            _fail("MODEL_UNAVAILABLE", "no receipt-available fallback is admitted")

    core = {
        "schema": BACKEND_MODEL_ROUTE_SCHEMA,
        "backend": backend,
        "model_capability_tier": model_capability_tier,
        "primary_model": primary,
        "selected_model": selected,
        "fallback_authorized": allow_model_fallback,
        "fallback_used": selected != primary,
        "capability_receipt_sha256": capability_receipt_sha256,
        "selection": "EXACT_RECEIPT_AVAILABLE_MODEL",
        "account_default_forbidden": True,
        "authority_class": "STRUCTURAL_SELECTION_ONLY",
    }
    return {**core, "route_sha256": hashlib.sha256(_canonical(core)).hexdigest()}


def replay_backend_model_route(value: Mapping[str, Any]) -> dict[str, Any]:
    """Replay an exact structural route without promoting its capability input.

    Availability authentication remains a native/admission responsibility.  A
    route cannot become execution authority merely by replaying this public
    receipt.
    """

    if type(value) is not dict or set(value) != _MODEL_ROUTE_FIELDS:
        _fail("MODEL_ROUTE_REPLAY", "model route fields drifted")
    route = dict(value)
    backend = route.get("backend")
    tier = route.get("model_capability_tier")
    if backend not in _MODEL_ROUTES or tier not in _MODEL_ROUTES[backend]:
        _fail("MODEL_ROUTE_REPLAY", "model route backend or tier drifted")
    candidates = _MODEL_ROUTES[backend][tier]
    if (
        route.get("schema") != BACKEND_MODEL_ROUTE_SCHEMA
        or route.get("primary_model") != candidates[0]
        or route.get("selected_model") not in candidates
        or type(route.get("fallback_authorized")) is not bool
        or type(route.get("fallback_used")) is not bool
        or route["fallback_used"]
        != (route["selected_model"] != route["primary_model"])
        or (route["fallback_used"] and not route["fallback_authorized"])
        or route.get("selection") != "EXACT_RECEIPT_AVAILABLE_MODEL"
        or route.get("account_default_forbidden") is not True
        or route.get("authority_class") != "STRUCTURAL_SELECTION_ONLY"
        or type(route.get("capability_receipt_sha256")) is not str
        or _HEX_RE.fullmatch(route["capability_receipt_sha256"]) is None
        or type(route.get("route_sha256")) is not str
        or _HEX_RE.fullmatch(route["route_sha256"]) is None
    ):
        _fail("MODEL_ROUTE_REPLAY", "model route semantics drifted")
    core = {key: route[key] for key in route if key != "route_sha256"}
    expected = hashlib.sha256(_canonical(core)).hexdigest()
    if route["route_sha256"] != expected:
        _fail("MODEL_ROUTE_REPLAY", "model route digest drifted")
    return json.loads(_canonical(route).decode("ascii"))


def _bounded_json_shape(value: object) -> None:
    """Reject adversarial depth/size without recursing through caller data."""

    stack: list[tuple[object, int]] = [(value, 0)]
    nodes = 0
    while stack:
        item, depth = stack.pop()
        nodes += 1
        if nodes > MAX_JSON_NODES or depth > MAX_JSON_DEPTH:
            _fail("JSON_BOUNDS", "value exceeds canonical JSON structural bounds")
        if item is None or type(item) in (bool, str):
            continue
        if type(item) is int:
            if not -(2**63) <= item <= 2**63 - 1:
                _fail("JSON_BOUNDS", "integer exceeds canonical JSON bounds")
            continue
        if type(item) is float:
            if not (-sys.float_info.max <= item <= sys.float_info.max):
                _fail("JSON_BOUNDS", "number exceeds canonical JSON bounds")
            continue
        if type(item) is list:
            stack.extend((child, depth + 1) for child in item)
            continue
        if type(item) is dict:
            for key, child in item.items():
                if type(key) is not str:
                    _fail("NOT_CANONICAL_JSON", "object keys must be strings")
                stack.append((child, depth + 1))
            continue
        _fail("NOT_CANONICAL_JSON", "value contains a non-JSON type")


def _digest(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def canonical_request_bytes(value: Mapping[str, Any]) -> bytes:
    return _canonical(value)


def _constant(value: str) -> NoReturn:
    _fail("REQUEST_JSON_CONSTANT", f"unsupported JSON constant {value!r}")


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _fail("REQUEST_DUPLICATE_KEY", "request contains a duplicate key")
        result[key] = value
    return result


def parse_launch_request(raw: bytes) -> dict[str, Any]:
    if type(raw) is not bytes or not raw or len(raw) > MAX_REQUEST_BYTES:
        _fail("REQUEST_BOUNDS", "launch request byte length is invalid")
    failed = False
    try:
        value = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_pairs, parse_constant=_constant,
        )
    except PosixBackendLaunchPolicyError:
        raise
    except (
        UnicodeError, json.JSONDecodeError, ValueError, RecursionError,
        OverflowError,
    ):
        failed = True
        value = None
    if failed:
        _fail("REQUEST_JSON", "launch request is not bounded strict JSON")
    if type(value) is not dict or _canonical(value) != raw:
        _fail("REQUEST_CANONICAL", "launch request encoding is not canonical")
    return value


def _semver(value: object, label: str) -> tuple[int, int, int]:
    if type(value) is not str or not 5 <= len(value) <= 32:
        _fail("VERSION", f"{label} must be canonical semver")
    match = _VERSION_RE.fullmatch(value)
    if match is None:
        _fail("VERSION", f"{label} must be canonical semver")
    return tuple(int(item) for item in match.groups())  # type: ignore[return-value]


def _canonical_uuid(value: object, label: str) -> str:
    failed = False
    try:
        parsed = uuid.UUID(value) if type(value) is str and len(value) == 36 else None
    except (ValueError, AttributeError, TypeError, OverflowError):
        failed = True
        parsed = None
    if failed or parsed is None or str(parsed) != value:
        _fail("SESSION_ID", f"{label} must be a canonical UUID")
    return value


def _exact_claude_tools(value: object, backend: str) -> tuple[str, ...]:
    if type(value) is not list or any(type(item) is not str for item in value):
        _fail("CLAUDE_TOOLS", "Claude tool denominator must be a JSON string list")
    tools = tuple(value)
    if list(tools) != sorted(set(tools)) or any(
        item not in _CLAUDE_TOOLS for item in tools
    ):
        _fail("CLAUDE_TOOLS", "Claude tool denominator is not canonical or admitted")
    if backend == "codex" and tools:
        _fail("CLAUDE_TOOLS", "Codex requests cannot carry Claude tools")
    return tools


def _fd(value: object, label: str, *, nullable: bool = False) -> int | None:
    if nullable and value is None:
        return None
    if type(value) is not int or value < 0 or value > 1_000_000:
        _fail("FD", f"{label} is not a bounded descriptor number")
    return value


def _dup(source: int) -> int:
    posix_fcntl = _require_posix_fcntl()
    failed = False
    try:
        operation = getattr(posix_fcntl, "F_DUPFD_CLOEXEC", None)
        if operation is not None:
            return int(posix_fcntl.fcntl(source, operation, 64))
        retained = os.dup(source)
        os.set_inheritable(retained, False)
        return retained
    except (OSError, ValueError, OverflowError):
        failed = True
    if failed:
        _fail("FD_DUP", "descriptor could not be retained")
    raise AssertionError("unreachable")


def _require_readonly(fd: int, label: str) -> None:
    posix_fcntl = _require_posix_fcntl()
    failed = False
    try:
        flags = int(posix_fcntl.fcntl(fd, posix_fcntl.F_GETFL))
    except (OSError, ValueError, OverflowError):
        failed = True
        flags = -1
    if failed:
        _fail("FD_ACCESS", f"{label} access mode is unavailable")
    if (
        flags & os.O_ACCMODE != os.O_RDONLY
        or (hasattr(os, "O_PATH") and flags & os.O_PATH)
    ):
        _fail("FD_ACCESS", f"{label} must be opened read-only")


def _fresh_readonly(source: int, label: str) -> int:
    """Reopen a regular file as a distinct read-only open-file description."""

    _require_readonly(source, label)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    retained = -1
    failed = False
    if os.path.exists("/proc/self/fd"):
        try:
            retained = os.open(f"/proc/self/fd/{source}", flags)
        except (OSError, ValueError, OverflowError):
            failed = True
    elif sys.platform == "darwin":
        posix_fcntl = _require_posix_fcntl()
        try:
            raw_path = posix_fcntl.fcntl(source, 50, b"\0" * 1024)
            path = bytes(raw_path).split(b"\0", 1)[0].decode("utf-8", "strict")
            if not path:
                raise OSError
            _path(path, label)
            retained = os.open(
                path, flags | getattr(os, "O_NOFOLLOW", 0),
            )
        except PosixBackendLaunchPolicyError:
            raise
        except (OSError, ValueError, UnicodeError, OverflowError):
            failed = True
    else:
        failed = True
    if failed or retained < 0:
        _fail("FD_REOPEN", f"{label} cannot be independently reopened")
    try:
        source_stat = os.fstat(source)
        retained_stat = os.fstat(retained)
        if (source_stat.st_dev, source_stat.st_ino) != (
            retained_stat.st_dev, retained_stat.st_ino,
        ):
            _fail("FD_REOPEN", f"{label} reopened to a different identity")
        _require_readonly(retained, label)
        os.lseek(retained, 0, os.SEEK_SET)
        return retained
    except BaseException:
        try:
            os.close(retained)
        except OSError:
            pass
        raise


def _signature(item: os.stat_result) -> tuple[int, ...]:
    return (
        int(item.st_dev), int(item.st_ino), int(item.st_mode),
        int(item.st_nlink), int(item.st_uid), int(item.st_gid),
        int(item.st_size), int(item.st_mtime_ns), int(item.st_ctime_ns),
    )


def _read(fd: int, size: int, label: str) -> bytes:
    _require_posix_fcntl()
    chunks: list[bytes] = []
    offset = 0
    failed = False
    try:
        while offset < size:
            chunk = os.pread(fd, min(1024 * 1024, size - offset), offset)
            if not chunk:
                _fail("FD_SHORT_READ", f"{label} changed during capture")
            chunks.append(chunk)
            offset += len(chunk)
        if os.pread(fd, 1, size):
            _fail("FD_GREW", f"{label} grew during capture")
    except PosixBackendLaunchPolicyError:
        raise
    except (OSError, ValueError, OverflowError):
        failed = True
    if failed:
        _fail("FD_READ", f"{label} is not a readable seekable file")
    return b"".join(chunks)


@dataclass(frozen=True)
class _File:
    fd: int
    signature: tuple[int, ...]
    sha256: str
    label: str
    zero_offset: bool = False


@dataclass(frozen=True)
class _Directory:
    fd: int
    signature: tuple[int, ...]
    path: str
    label: str
    path_chain: tuple[tuple[int, int, int, int, int], ...]


@dataclass(frozen=True)
class _CodexConfigAbsence:
    """Private replay evidence for control-tree project-config absence."""

    control_path: str
    # Each entry binds the ancestor and the optional literal `.codex` node.
    ancestors: tuple[
        tuple[
            tuple[int, int, int, int, int],
            tuple[int, ...] | None,
        ], ...
    ]


def _file(
    source: int, label: str, limit: int, *, executable: bool = False,
    private: bool = False, nonempty: bool = True,
    fresh_zero_offset: bool = False,
) -> _File:
    _require_readonly(source, label)
    if fresh_zero_offset:
        failed = False
        try:
            position = os.lseek(source, 0, os.SEEK_CUR)
        except (OSError, ValueError, OverflowError):
            failed = True
            position = -1
        if failed or position != 0:
            _fail("PROMPT_OFFSET", "prompt descriptor must start at offset zero")
    retained = (
        _fresh_readonly(source, label) if fresh_zero_offset else _dup(source)
    )
    try:
        _require_readonly(retained, label)
        before = os.fstat(retained)
        mode = stat.S_IMODE(before.st_mode)
        if not stat.S_ISREG(before.st_mode):
            _fail("FD_TYPE", f"{label} must be a regular file")
        if before.st_nlink != 1:
            _fail("FD_LINKS", f"{label} must have exactly one link")
        if before.st_uid not in {0, os.geteuid()}:
            _fail("FD_OWNER", f"{label} owner is not trusted")
        if mode & 0o022 or (private and mode & 0o077):
            _fail("FD_MODE", f"{label} mode is too permissive")
        if executable and not mode & 0o111:
            _fail("FD_MODE", f"{label} is not executable")
        if before.st_size < (1 if nonempty else 0) or before.st_size > limit:
            _fail("FD_BOUNDS", f"{label} byte length is invalid")
        blocks = int(getattr(before, "st_blocks", 0))
        if before.st_size and blocks and blocks * 512 < before.st_size:
            _fail("FD_SPARSE", f"{label} must not be sparse")
        raw = _read(retained, int(before.st_size), label)
        after = os.fstat(retained)
        if _signature(before) != _signature(after):
            _fail("FD_CHANGED", f"{label} changed during capture")
        return _File(
            retained, _signature(after), hashlib.sha256(raw).hexdigest(), label,
            fresh_zero_offset,
        )
    except BaseException:
        try:
            os.close(retained)
        except OSError:
            pass
        raise


def _replay_file(item: _File) -> None:
    _require_posix_fcntl()
    failed = False
    try:
        current = os.fstat(item.fd)
    except (OSError, ValueError, OverflowError):
        failed = True
        current = None
    if failed or current is None:
        _fail("FD_STAT", f"{item.label} descriptor is closed")
    _require_readonly(item.fd, item.label)
    if _signature(current) != item.signature:
        _fail("FD_CHANGED", f"{item.label} identity changed")
    if hashlib.sha256(_read(item.fd, int(current.st_size), item.label)).hexdigest() != item.sha256:
        _fail("FD_CHANGED", f"{item.label} content changed")
    if item.zero_offset:
        failed = False
        try:
            position = os.lseek(item.fd, 0, os.SEEK_CUR)
        except (OSError, ValueError, OverflowError):
            failed = True
            position = -1
        if failed or position != 0:
            _fail("PROMPT_OFFSET", "prompt descriptor offset drifted")


def _path(value: object, label: str) -> str:
    _require_posix_fcntl()
    encoded: bytes | None = None
    if type(value) is str:
        try:
            encoded = value.encode("utf-8", "strict")
        except UnicodeError:
            encoded = None
    if type(value) is not str or not value or encoded is None or len(encoded) > 4096:
        _fail("PATH", f"{label} path is invalid")
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        _fail("PATH", f"{label} path contains control characters")
    if not os.path.isabs(value) or os.path.normpath(value) != value or value == "/":
        _fail("PATH", f"{label} path must be canonical absolute non-root")
    current = os.sep
    failed = False
    try:
        for component in value.split(os.sep)[1:]:
            current = os.path.join(current, component)
            if stat.S_ISLNK(os.lstat(current).st_mode):
                _fail("PATH_SYMLINK", f"{label} path contains a symlink")
    except PosixBackendLaunchPolicyError:
        raise
    except (OSError, ValueError, OverflowError):
        failed = True
    if failed:
        _fail("PATH_STAT", f"{label} path is unavailable")
    return value


def _directory_identity(item: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        int(item.st_dev), int(item.st_ino), int(item.st_mode),
        int(item.st_uid), int(item.st_gid),
    )


def _resolve_directory_nofollow(
    path: str, label: str,
) -> tuple[int, tuple[tuple[int, int, int, int, int], ...]]:
    """Resolve every path component through directory FDs without symlinks."""

    _require_posix_fcntl()
    flags = (
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    )
    current = -1
    failed = False
    chain: list[tuple[int, int, int, int, int]] = []
    try:
        current = os.open(os.sep, flags)
        _require_readonly(current, label)
        chain.append(_directory_identity(os.fstat(current)))
        for component in path.split(os.sep)[1:]:
            next_fd = os.open(component, flags, dir_fd=current)
            try:
                _require_readonly(next_fd, label)
                chain.append(_directory_identity(os.fstat(next_fd)))
            except BaseException:
                os.close(next_fd)
                raise
            os.close(current)
            current = next_fd
    except PosixBackendLaunchPolicyError:
        if current >= 0:
            try:
                os.close(current)
            except OSError:
                pass
        raise
    except (OSError, ValueError, OverflowError):
        failed = True
    if failed:
        if current >= 0:
            try:
                os.close(current)
            except OSError:
                pass
        _fail("PATH_RESOLUTION", f"{label} path cannot be resolved without links")
    return current, tuple(chain)


def _codex_control_config_absence(path: str) -> _CodexConfigAbsence:
    """Prove `.codex/config.toml` absent at each control-path ancestor.

    Resolution is entirely relative to retained directory descriptors and
    rejects symlinked `.codex` nodes.  This is the local replay guard; the
    authenticated outer census remains responsible for the final check at the
    execve boundary.
    """

    canonical = _path(path, "control")
    flags = (
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    )
    current = -1
    observations: list[
        tuple[tuple[int, int, int, int, int], tuple[int, ...] | None]
    ] = []
    failed = False
    try:
        current = os.open(os.sep, flags)
        components: list[str | None] = [None, *canonical.split(os.sep)[1:]]
        for component in components:
            if component is not None:
                next_fd = os.open(component, flags, dir_fd=current)
                os.close(current)
                current = next_fd
            _require_readonly(current, "control project-config census")
            ancestor = _directory_identity(os.fstat(current))
            marker: tuple[int, ...] | None = None
            try:
                codex_stat = os.stat(".codex", dir_fd=current, follow_symlinks=False)
            except FileNotFoundError:
                codex_stat = None
            if codex_stat is not None:
                if stat.S_ISLNK(codex_stat.st_mode):
                    _fail(
                        "CODEX_PROJECT_CONFIG",
                        "control ancestor contains a symlinked .codex node",
                    )
                marker = _signature(codex_stat)
                if stat.S_ISDIR(codex_stat.st_mode):
                    codex_fd = -1
                    try:
                        codex_fd = os.open(".codex", flags, dir_fd=current)
                        opened = os.fstat(codex_fd)
                        if _signature(opened) != marker:
                            _fail(
                                "CODEX_PROJECT_CONFIG",
                                "control .codex identity changed during census",
                            )
                        try:
                            os.stat(
                                "config.toml", dir_fd=codex_fd,
                                follow_symlinks=False,
                            )
                        except FileNotFoundError:
                            pass
                        else:
                            _fail(
                                "CODEX_PROJECT_CONFIG",
                                "trusted control tree contains a Codex project config",
                            )
                        after = os.stat(
                            ".codex", dir_fd=current, follow_symlinks=False,
                        )
                        if _signature(after) != marker:
                            _fail(
                                "CODEX_PROJECT_CONFIG",
                                "control .codex pathname changed during census",
                            )
                    finally:
                        if codex_fd >= 0:
                            os.close(codex_fd)
            observations.append((ancestor, marker))
    except PosixBackendLaunchPolicyError:
        raise
    except (OSError, ValueError, OverflowError):
        failed = True
    finally:
        if current >= 0:
            try:
                os.close(current)
            except OSError:
                pass
    if failed:
        _fail(
            "CODEX_PROJECT_CONFIG",
            "control project-config census could not be completed safely",
        )
    return _CodexConfigAbsence(canonical, tuple(observations))


def _replay_codex_control_config_absence(item: _CodexConfigAbsence) -> None:
    current = _codex_control_config_absence(item.control_path)
    if current != item:
        _fail(
            "CODEX_PROJECT_CONFIG_REPLAY",
            "control project-config census identity changed",
        )


def _directory(source: int, path: object, label: str) -> _Directory:
    canonical = _path(path, label)
    _require_readonly(source, label)
    retained = _dup(source)
    observed = -1
    try:
        _require_readonly(retained, label)
        descriptor = os.fstat(retained)
        observed, path_chain = _resolve_directory_nofollow(canonical, label)
        current = os.fstat(observed)
        if not stat.S_ISDIR(descriptor.st_mode):
            _fail("FD_TYPE", f"{label} must be a directory descriptor")
        if (descriptor.st_dev, descriptor.st_ino) != (current.st_dev, current.st_ino):
            _fail("PATH_IDENTITY", f"{label} path and descriptor disagree")
        return _Directory(
            retained, _signature(descriptor), canonical, label, path_chain,
        )
    except BaseException:
        try:
            os.close(retained)
        except OSError:
            pass
        raise
    finally:
        if observed >= 0:
            try:
                os.close(observed)
            except OSError:
                pass


def _replay_directory(item: _Directory) -> None:
    _require_posix_fcntl()
    failed = False
    try:
        current = os.fstat(item.fd)
    except (OSError, ValueError, OverflowError):
        failed = True
        current = None
    if failed or current is None:
        _fail("FD_STAT", f"{item.label} descriptor is closed")
    if _signature(current) != item.signature:
        _fail("FD_CHANGED", f"{item.label} directory identity changed")
    observed = -1
    try:
        observed, path_chain = _resolve_directory_nofollow(item.path, item.label)
        pathname = os.fstat(observed)
        if path_chain != item.path_chain:
            _fail("PATH_ANCESTOR_CHANGED", f"{item.label} ancestor identity changed")
        if (pathname.st_dev, pathname.st_ino) != (current.st_dev, current.st_ino):
            _fail("PATH_IDENTITY", f"{item.label} pathname identity changed")
    finally:
        if observed >= 0:
            try:
                os.close(observed)
            except OSError:
                pass


def _fd_path(fd: int) -> str:
    # Both provider transports execute the admitted Linux guest image.  Apple
    # names the Virtualization.framework host transport, not a native macOS
    # backend process.
    return f"/proc/self/fd/{fd}"


def _overlap(first: str, second: str) -> bool:
    try:
        common = os.path.commonpath((first, second))
    except ValueError:
        return False
    return common in {first, second}


def _toml_string(value: str) -> str:
    """Return one deterministic TOML basic string without locale dependence."""

    return json.dumps(value, ensure_ascii=True, allow_nan=False)


def required_codex_profile_bytes(request: Mapping[str, Any]) -> bytes:
    """Render the one request-bound permission profile accepted in production.

    The supervisor must materialize these exact bytes at
    ``$CODEX_HOME/plamen-audit.config.toml`` before launch.  The profile does
    not inherit a built-in workspace policy: doing so would make the trusted
    control cwd writable and would re-enable system temporary directories.
    For every conformance-bound Codex install generation this is defense in
    depth only: launch admission separately requires authenticated outer
    isolation proving that command descendants cannot read credential custody.
    """

    if type(request) is not dict or request.get("backend") != "codex":
        _fail("CODEX_PROFILE", "Codex profile requires an exact Codex request")
    control = _path(request.get("control_path"), "control")
    project = _path(request.get("project_path"), "project")
    scratch = _path(request.get("scratch_path"), "scratch")
    if project == scratch:
        _fail("CODEX_PROFILE", "project and scratch profile roots must differ")
    if _overlap(control, project) or _overlap(control, scratch):
        _fail("CODEX_PROFILE", "control profile root overlaps writable state")

    lines = [
        f'default_permissions = {_toml_string(CODEX_PROFILE_NAME)}',
        "",
        "[shell_environment_policy]",
        'inherit = "none"',
        "ignore_default_excludes = false",
        "experimental_use_profile = false",
        "",
        f"[permissions.{CODEX_PROFILE_NAME}]",
        'description = "Request-bound Plamen audit workspace"',
        "",
        f"[permissions.{CODEX_PROFILE_NAME}.workspace_roots]",
        f"{_toml_string(project)} = true",
        f"{_toml_string(scratch)} = true",
        "",
        f"[permissions.{CODEX_PROFILE_NAME}.filesystem]",
        f"glob_scan_max_depth = {CODEX_CREDENTIAL_GLOB_SCAN_DEPTH}",
        '":root" = "deny"',
        '":minimal" = "read"',
        '":tmpdir" = "deny"',
        '":slash_tmp" = "deny"',
        f'{_toml_string(GUEST_TOOLCHAIN_PATH)} = "read"',
        f'{_toml_string(control)} = "read"',
    ]
    # Absolute paths support scoped subpath maps.  Use both the base marker and
    # a bounded descendant deny: direct special-path denies alone do not cover
    # every canonical/alias spelling on macOS Seatbelt.
    for denied_root in (
        "/tmp", "/private/tmp", PRIVATE_ROOT_PATH, PRIVATE_TMP_PATH,
    ):
        lines.extend((
            "",
            f"[permissions.{CODEX_PROFILE_NAME}.filesystem."
            f"{_toml_string(denied_root)}]",
            '"." = "deny"',
            '"**" = "deny"',
        ))
    for writable in (project, scratch):
        lines.extend((
            "",
            f"[permissions.{CODEX_PROFILE_NAME}.filesystem."
            f"{_toml_string(writable)}]",
            '"." = "write"',
            *(f"{_toml_string(pattern)} = \"deny\""
              for pattern in _CODEX_CREDENTIAL_GLOBS),
        ))
    lines.extend((
        "",
        f"[permissions.{CODEX_PROFILE_NAME}.network]",
        "enabled = false",
        "",
    ))
    raw = "\n".join(lines).encode("utf-8")
    if not raw or len(raw) > MAX_POLICY_BYTES:
        _fail("CODEX_PROFILE", "Codex profile exceeds its byte ceiling")
    return raw


def required_codex_config_census_bytes(request: Mapping[str, Any]) -> bytes:
    """Return the exact authenticated pre-exec Codex configuration census.

    The admitted CLI behavior contract applies ``--profile`` as a user-config
    overlay, so ``--ignore-user-config`` would suppress the selected profile as
    well.  The admitted alternative is an otherwise empty private ``CODEX_HOME`` plus an
    exact profile and auth file.  Project config has higher precedence than the
    named profile, therefore every ancestor of the trusted control cwd must
    also lack ``.codex/config.toml``.  The outer supervisor binds the observed
    identities in its authenticated evidence and performs this census
    immediately before execve.
    """

    if type(request) is not dict or request.get("backend") != "codex":
        _fail("CODEX_CONFIG_CENSUS", "Codex census requires an exact request")
    control = _path(request.get("control_path"), "control")
    for key in ("codex_profile_sha256", "credential_sha256"):
        value = request.get(key)
        if type(value) is not str or _HEX_RE.fullmatch(value) is None:
            _fail("CODEX_CONFIG_CENSUS", "Codex census digest is malformed")
    return _canonical({
        "schema": "plamen.codex_config_census_contract.v1",
        "phase": "IMMEDIATELY_BEFORE_BACKEND_EXECVE",
        "evidence": "AUTHENTICATED_COMPONENT_AND_FILE_IDENTITY_DIGEST",
        "postcondition": "CONFIG_SCOPE_IMMUTABLE_UNTIL_BACKEND_EXECVE",
        "private_home": {
            "root": CODEX_HOME_PATH,
            "resolution": "COMPONENTWISE_NOFOLLOW_RETAINED_DIRECTORY_FD",
            "exact_entries": [
                {
                    "name": "auth.json", "kind": "regular", "mode": "0600",
                    "sha256": request["credential_sha256"],
                },
                {
                    "name": f"{CODEX_PROFILE_NAME}.config.toml",
                    "kind": "regular", "mode": "0600",
                    "sha256": request["codex_profile_sha256"],
                },
            ],
            "absent": ["config.toml"],
            "no_other_entries": True,
        },
        "control_project_config": {
            "control_path": control,
            "resolution": "EACH_ANCESTOR_COMPONENTWISE_NOFOLLOW",
            "absent_at_each_ancestor": ".codex/config.toml",
        },
    })


def _validate_codex_config_loader_argv(argv: tuple[str, ...]) -> None:
    """Reject loader combinations that silently deactivate the named profile."""

    if "--ignore-user-config" in argv:
        _fail(
            "CODEX_CONFIG_LOADER",
            "ignore-user-config suppresses the selected Codex 0.152 profile",
        )
    if argv.count("--profile") != 1:
        _fail("CODEX_CONFIG_LOADER", "exactly one Codex profile is required")
    index = argv.index("--profile")
    if index + 1 >= len(argv) or argv[index + 1] != CODEX_PROFILE_NAME:
        _fail("CODEX_CONFIG_LOADER", "Codex profile selection is not exact")
    if "--sandbox" in argv or any(
        item.startswith("sandbox_workspace_write.") for item in argv
    ):
        _fail(
            "CODEX_CONFIG_LOADER",
            "legacy sandbox configuration would override the named profile",
        )


def required_claude_settings_bytes(request: Mapping[str, Any]) -> bytes:
    """Exact request-bound settings: mandatory sandbox and no tool egress."""

    if type(request) is not dict or request.get("backend") != "claude":
        _fail("CLAUDE_SETTINGS", "Claude settings require an exact Claude request")
    control = _path(request.get("control_path"), "control")
    project = _path(request.get("project_path"), "project")
    scratch = _path(request.get("scratch_path"), "scratch")
    if project == scratch or _overlap(control, project) or _overlap(control, scratch):
        _fail("CLAUDE_SETTINGS", "Claude settings paths overlap invalidly")
    tools = _exact_claude_tools(request.get("claude_tools"), "claude")
    denied_tools = tuple(item for item in _CLAUDE_TOOLS if item not in tools)

    return _canonical({
        "permissions": {
            "allow": list(tools),
            "ask": [],
            "deny": [
                *denied_tools,
                *[f"Read({path})" for path in _CREDENTIAL_PATHS],
                *_CLAUDE_DENIED_TOOLS,
            ],
        },
        "sandbox": {
            "allowUnsandboxedCommands": False,
            "autoAllowBashIfSandboxed": True,
            "credentials": {
                "envVars": [{"mode": "deny", "name": name} for name in _CREDENTIAL_ENV],
                "files": [{"mode": "deny", "path": path} for path in _CREDENTIAL_PATHS],
            },
            "enableWeakerNestedSandbox": False,
            "enabled": True,
            "excludedCommands": [],
            "failIfUnavailable": True,
            "filesystem": {
                "allowRead": [control, project, scratch],
                "allowWrite": [project, scratch],
                "denyRead": list(_CREDENTIAL_PATHS),
                "denyWrite": [control, PRIVATE_ROOT_PATH],
                "disabled": False,
            },
            "network": {
                "allowUnixSockets": [], "allowedDomains": [],
                "deniedDomains": ["*"], "strictAllowlist": True,
            },
        },
    })


def required_claude_mcp_bytes() -> bytes:
    return _canonical({"mcpServers": {}})


@dataclass(frozen=True)
class _Executable:
    install_generation_authority_class: str
    backend: str
    version: str
    sha256: str
    cli_conformance_sha256: str
    cli_behavior_contract_sha256: str
    install_generation_sha256: str
    file: _File
    token: str


@dataclass(frozen=True)
class _LaunchAuthority:
    authority_class: str
    backend: str
    executable_version: str
    executable_sha256: str
    executable_provenance: str
    runtime_closure_sha256: str
    cli_behavior_contract_sha256: str
    install_generation_sha256: str
    latest_resolution_receipt_sha256: str
    publisher_identity_sha256: str
    provenance_receipt_sha256: str
    platform: str
    attempt_id: str
    session_id: str
    model: str
    claude_tools: tuple[str, ...]
    codex_profile_sha256: str | None
    claude_settings_contract: str | None
    claude_settings_sha256: str | None
    claude_mcp_sha256: str | None
    codex_permission_profile_status: str
    credential_isolation_mode: str
    credential_isolation_sha256: str
    prompt_sha256: str
    credential_sha256: str
    control_path: str
    codex_config_census_contract: str | None
    codex_config_census_contract_sha256: str | None
    codex_config_census_evidence_sha256: str | None
    config_sha256: str
    image_sha256: str
    provider_admission_sha256: str
    egress_admission_sha256: str
    proxy_authority_sha256: str
    proxy_endpoint: str
    egress_transport: str
    release_id: str
    release_manifest_sha256: str
    release_ca_sha256: str
    authority_authentication_sha256: str
    ca_bundle: _File
    token: str


@dataclass(frozen=True)
class _Plan:
    request: Mapping[str, Any]
    authority_class: str
    executable: _Executable
    directories: tuple[_Directory, ...]
    files: tuple[_File, ...]
    argv: tuple[str, ...]
    environment: Mapping[str, str]
    stdin_fd: int
    pass_fds: tuple[int, ...]
    credential_fd: int
    credential_delivery: str
    codex_profile_fd: int | None
    codex_profile_delivery: str
    codex_config_absence: _CodexConfigAbsence | None
    codex_config_census_bytes: bytes | None
    receipt: bytes
    token: str


@dataclass(frozen=True, slots=True)
class BackendInstallGenerationProjection:
    """Non-secret exact projection of one authenticated install generation."""

    authority_class: str
    backend: str
    resolved_version: str
    executable_sha256: str
    executable_size: int
    runtime_closure_sha256: str
    publisher: str
    publisher_identity_sha256: str
    provenance: str
    provenance_receipt_sha256: str
    latest_resolution_receipt_sha256: str
    cli_behavior_contract_sha256: str
    cli_conformance_sha256: str
    install_generation_id: str
    install_generation_sha256: str
    producer_receipt_sha256: str


@dataclass(frozen=True, slots=True)
class _BackendInstallGenerationRecord:
    projection: BackendInstallGenerationProjection
    native_anchor: object | None


def _install_generation_projection(
    value: object, *, allow_test_only: bool,
) -> BackendInstallGenerationProjection:
    admitted = (
        type(value) is BackendInstallGenerationAuthority
        or (
            allow_test_only
            and type(value) is TestOnlyBackendInstallGenerationAuthority
        )
    )
    if not admitted:
        _fail(
            "INSTALL_GENERATION_AUTHORITY",
            "an exact authenticated install-generation authority is required",
        )
    with _LOCK:
        record = _INSTALL_GENERATIONS.get(value)
    if record is None:
        _fail(
            "INSTALL_GENERATION_AUTHORITY",
            "install-generation authority is forged or expired",
        )
    expected_class = (
        INSTALL_GENERATION_AUTHORITY_CLASS
        if type(value) is BackendInstallGenerationAuthority
        else TEST_ONLY_INSTALL_GENERATION_AUTHORITY_CLASS
    )
    projection = record.projection
    if projection.authority_class != expected_class:
        _fail(
            "INSTALL_GENERATION_AUTHORITY",
            "install-generation authority class drifted",
        )
    return projection


def require_backend_install_generation(
    value: object,
) -> BackendInstallGenerationProjection:
    """Project one native-authenticated installed backend generation.

    This never resolves ``latest``, searches ``PATH``, or opens installed
    bytes.  It accepts only an already-live opaque producer authority.
    """

    return _install_generation_projection(value, allow_test_only=False)


_NATIVE_BACKEND_PROJECTION_SCHEMA = (
    "plamen.native-installed-backend-generation-projection.v1"
)
_NATIVE_BACKEND_PROJECTION_FIELDS = frozenset({
    "acquisition_roster_sha256", "backend",
    "coordinator_code_identity_sha256",
    "coordinator_member_identity_sha256", "coordinator_receipt_sha256",
    "installed_authority_roster_sha256", "ordinal", "payload_sha256",
    "payload_size", "policy_sha256", "producer_receipt_sha256",
    "producer_receipt_size", "producer_verifier_key_sha256", "schema",
    "source_manifest_sha256", "source_manifest_size",
})
_NATIVE_BACKEND_RECEIPT_FIELDS = frozenset({
    "schema", "selector", "policy_schema", "policy_sha256",
    "resolved_version", "resolved_release", "registry", "upstream",
    "transport", "payload", "installed", "probes", "install",
    "authentication", "receipt_sha256",
})
_NATIVE_BACKEND_SOURCE_MANIFEST_FIELDS = frozenset({
    "archive_member", "archive_member_count",
    "archive_member_roster_sha256", "artifact_id",
    "authentication_scope", "installed_sha256", "installed_size",
    "media_type", "payload_sha256", "payload_size", "platform",
    "required_paths", "role", "schema_version", "source_reference",
    "version",
})
_NATIVE_BACKEND_SOURCE_MANIFEST_MAX_BYTES = 64 * 1024
_NATIVE_BACKEND_ARCHIVE_MAX_MEMBERS = 131_072


def _native_projection_json(raw: object) -> dict[str, Any]:
    if type(raw) is not bytes or not raw or len(raw) > 64 * 1024:
        _fail("INSTALL_GENERATION_NATIVE", "native projection bytes are invalid")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        _fail("INSTALL_GENERATION_NATIVE", "native projection is not JSON")
    if type(value) is not dict or _canonical(value) != raw:
        _fail("INSTALL_GENERATION_NATIVE", "native projection is not canonical")
    return value


def _native_semantic_json(raw: bytes) -> dict[str, Any]:
    try:
        value = json.loads(raw)
        canonical = json.dumps(
            value, ensure_ascii=False, allow_nan=False, sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (
        UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError,
        UnicodeError, RecursionError,
    ):
        _fail("INSTALL_GENERATION_RECEIPT", "producer receipt is not JSON")
    if type(value) is not dict or canonical != raw:
        _fail(
            "INSTALL_GENERATION_RECEIPT",
            "producer receipt is not exact canonical JSON",
        )
    _bounded_json_shape(value)
    return value


def _native_source_manifest_json(raw: bytes) -> dict[str, Any]:
    """Decode the exact newline-terminated operation-4 source manifest."""

    if (
        type(raw) is not bytes
        or len(raw) < 3
        or len(raw) > _NATIVE_BACKEND_SOURCE_MANIFEST_MAX_BYTES
        or not raw.endswith(b"\n")
    ):
        _fail(
            "INSTALL_GENERATION_MANIFEST",
            "source manifest is not one bounded newline-terminated record",
        )
    semantic = raw[:-1]
    try:
        value = json.loads(semantic)
        canonical = json.dumps(
            value, ensure_ascii=False, allow_nan=False, sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8") + b"\n"
    except (
        UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError,
        UnicodeError, RecursionError,
    ):
        _fail("INSTALL_GENERATION_MANIFEST", "source manifest is not JSON")
    if type(value) is not dict or canonical != raw:
        _fail(
            "INSTALL_GENERATION_MANIFEST",
            "source manifest is not exact canonical newline JSON",
        )
    _bounded_json_shape(value)
    return value


def _native_footer_cstr(raw: bytes) -> str:
    head, marker, tail = raw.partition(b"\0")
    if (
        not marker or not head or any(tail)
        or any(byte < 0x21 or byte > 0x7E for byte in head)
    ):
        _fail("INSTALL_GENERATION_FOOTER", "producer footer string differs")
    try:
        return head.decode("ascii")
    except UnicodeDecodeError:
        _fail("INSTALL_GENERATION_FOOTER", "producer footer is not ASCII")


def _native_backend_install_projection(
    native_authority: object, *, expected_backend: str,
) -> tuple[BackendInstallGenerationProjection, object]:
    """Consume one exact native role10 projection into public-safe metadata."""

    if expected_backend not in {"codex", "claude"}:
        _fail("INSTALL_GENERATION_BACKEND", "native backend selector is invalid")
    try:
        import posix_backend_execution as native_execution

        module = native_execution._admitted_native_supervisor_module()
    except BaseException:
        module = None
    if (
        module is None
        or type(native_authority)
        is not getattr(module, "BackendInstallGenerationAuthority", None)
        or not callable(getattr(module, "project_backend_install_generation", None))
    ):
        _fail(
            "INSTALL_GENERATION_NATIVE",
            "exact authenticated native install authority is required",
        )
    try:
        projected = module.project_backend_install_generation(native_authority)
    except BaseException:
        _fail(
            "INSTALL_GENERATION_NATIVE",
            "native install authority failed final descriptor revalidation",
        )
    if (
        type(projected) is not tuple or len(projected) != 3
        or any(type(item) is not bytes for item in projected)
    ):
        _fail("INSTALL_GENERATION_NATIVE", "native projection ABI differs")
    producer_wire, source_manifest_raw, binding_raw = projected
    binding = _native_projection_json(binding_raw)
    expected_ordinal = 5 if expected_backend == "codex" else 6
    if (
        frozenset(binding) != _NATIVE_BACKEND_PROJECTION_FIELDS
        or binding.get("schema") != _NATIVE_BACKEND_PROJECTION_SCHEMA
        or binding.get("backend") != expected_backend
        or binding.get("ordinal") != expected_ordinal
        or any(
            type(binding.get(name)) is not str
            or _HEX_RE.fullmatch(binding[name]) is None
            for name in _NATIVE_BACKEND_PROJECTION_FIELDS
            if name.endswith("_sha256")
        )
        or any(
            type(binding.get(name)) is not int
            or isinstance(binding[name], bool)
            or binding[name] <= 0
            for name in (
                "payload_size", "producer_receipt_size",
                "source_manifest_size",
            )
        )
        or len(producer_wire) != binding.get("producer_receipt_size")
        or hashlib.sha256(producer_wire).hexdigest()
        != binding.get("producer_receipt_sha256")
        or len(source_manifest_raw) != binding.get("source_manifest_size")
        or hashlib.sha256(source_manifest_raw).hexdigest()
        != binding.get("source_manifest_sha256")
    ):
        _fail("INSTALL_GENERATION_NATIVE", "native projection binding differs")

    if len(producer_wire) <= 512:
        _fail("INSTALL_GENERATION_FOOTER", "producer receipt footer is absent")
    semantic, footer = producer_wire[:-512], producer_wire[-512:]
    try:
        version, footer_size = struct.unpack_from(">HH", footer, 8)
        role = struct.unpack_from(">H", footer, 12)[0]
        identity_mode = struct.unpack_from(">H", footer, 14)[0]
        validator = struct.unpack_from(">H", footer, 16)[0]
        reserved = struct.unpack_from(">H", footer, 18)[0]
        payload_size, manifest_size, semantic_size = struct.unpack_from(
            ">QQQ", footer, 20,
        )
    except struct.error:
        _fail("INSTALL_GENERATION_FOOTER", "producer footer is truncated")
    if (
        footer[:8] != b"PLMOP4R1"
        or (version, footer_size, role, identity_mode, validator, reserved)
        != (1, 512, expected_ordinal, 2, 4, 0)
        or any(footer[396:480])
        or hashlib.sha256(footer[:480]).digest() != footer[480:]
        or payload_size != binding["payload_size"]
        or footer[76:108].hex() != binding["payload_sha256"]
        or manifest_size != binding["source_manifest_size"]
        or footer[108:140].hex() != binding["source_manifest_sha256"]
        or semantic_size != len(semantic)
        or footer[140:172] != hashlib.sha256(semantic).digest()
        or footer[44:76].hex() != binding["policy_sha256"]
        or _native_footer_cstr(footer[172:268])
        != INSTALL_GENERATION_RECEIPT_SCHEMA
    ):
        _fail("INSTALL_GENERATION_FOOTER", "producer footer authority differs")
    footer_version = _native_footer_cstr(footer[268:396])
    receipt = _native_semantic_json(semantic)
    if (
        frozenset(receipt) != _NATIVE_BACKEND_RECEIPT_FIELDS
        or receipt.get("schema") != INSTALL_GENERATION_RECEIPT_SCHEMA
        or receipt.get("selector") != expected_backend
        or receipt.get("policy_schema") != "plamen.native-backend-acquisition.v2"
        or receipt.get("policy_sha256") != binding["policy_sha256"]
        or receipt.get("resolved_version") != footer_version
    ):
        _fail("INSTALL_GENERATION_RECEIPT", "backend receipt authority differs")
    resolved_version = receipt["resolved_version"]
    parsed_version = _semver(resolved_version, "resolved install version")
    if resolved_version != ".".join(str(item) for item in parsed_version):
        _fail("INSTALL_GENERATION_VERSION", "resolved version is not canonical")
    candidate = dict(receipt)
    receipt_sha256 = candidate.pop("receipt_sha256", None)
    if (
        type(receipt_sha256) is not str
        or _HEX_RE.fullmatch(receipt_sha256) is None
        or hashlib.sha256(_native_semantic_json_bytes(candidate)).hexdigest()
        != receipt_sha256
    ):
        _fail("INSTALL_GENERATION_RECEIPT", "producer receipt digest differs")

    authentication = receipt.get("authentication")
    if (
        type(authentication) is not dict
        or frozenset(authentication) != {"scheme", "key_id", "signature"}
        or authentication.get("scheme") != "ed25519"
        or authentication.get("key_id")
        != binding["producer_verifier_key_sha256"]
        or type(authentication.get("signature")) is not str
        or re.fullmatch(r"[0-9a-f]{128}", authentication["signature"]) is None
    ):
        _fail("INSTALL_GENERATION_RECEIPT", "producer signer binding differs")
    installed = receipt.get("installed")
    manifest = _native_source_manifest_json(source_manifest_raw)
    payload = receipt.get("payload")
    expected_member = (
        payload.get("selected_member") if type(payload) is dict else None
    )
    expected_member_count = (
        payload.get("member_count") if type(payload) is dict else None
    )
    expected_member_roster = (
        payload.get("member_roster_sha256")
        if type(payload) is dict else None
    )
    expected_source_reference = (
        payload.get("source_url") if type(payload) is dict else None
    )
    expected_required_path = (
        "/usr/local/lib/plamen/bin/codex"
        if expected_backend == "codex"
        else "/usr/local/lib/plamen/bin/claude"
    )
    expected_member_pattern = (
        r"package/vendor/[^/]+/bin/codex"
        if expected_backend == "codex"
        else r"package/claude"
    )
    if (
        frozenset(manifest) != _NATIVE_BACKEND_SOURCE_MANIFEST_FIELDS
        or manifest.get("authentication_scope")
        != "NATIVE_RETAINED_SOURCE_INPUT"
        or manifest.get("schema_version")
        != "plamen.runtime_source_manifest.native-retained.v1"
        or manifest.get("artifact_id")
        != f"{expected_backend}-{resolved_version}-linux-arm64"
        or manifest.get("media_type")
        != "application/vnd.plamen.authenticated-tar-member"
        or manifest.get("platform") != "linux/arm64"
        or manifest.get("role") != expected_backend
        or manifest.get("version") != resolved_version
        or manifest.get("payload_sha256") != binding["payload_sha256"]
        or manifest.get("payload_size") != binding["payload_size"]
        or manifest.get("source_reference") != expected_source_reference
        or manifest.get("required_paths") != [expected_required_path]
        or type(manifest.get("archive_member")) is not str
        or re.fullmatch(
            expected_member_pattern, manifest.get("archive_member", ""),
        ) is None
        or manifest.get("archive_member") != expected_member
        or type(manifest.get("archive_member_count")) is not int
        or isinstance(manifest.get("archive_member_count"), bool)
        or not 1 <= manifest["archive_member_count"] \
            <= _NATIVE_BACKEND_ARCHIVE_MAX_MEMBERS
        or manifest.get("archive_member_count") != expected_member_count
        or type(manifest.get("archive_member_roster_sha256")) is not str
        or _HEX_RE.fullmatch(manifest["archive_member_roster_sha256"]) is None
        or manifest.get("archive_member_roster_sha256")
        != expected_member_roster
        or type(manifest.get("installed_sha256")) is not str
        or _HEX_RE.fullmatch(manifest["installed_sha256"]) is None
        or type(manifest.get("installed_size")) is not int
        or isinstance(manifest.get("installed_size"), bool)
        or not 1 <= manifest["installed_size"] <= MAX_EXECUTABLE_BYTES
        or type(installed) is not dict
        or manifest.get("installed_sha256")
        != installed.get("executable_sha256")
        or manifest.get("installed_size") != installed.get("executable_size")
    ):
        _fail("INSTALL_GENERATION_MANIFEST", "source manifest binding differs")

    code_signature = (
        installed.get("code_signature") if type(installed) is dict else None
    )
    probes = receipt.get("probes")
    observed_contract = (
        probes.get("help", {}).get("observed_contract")
        if type(probes) is dict and type(probes.get("help")) is dict else None
    )
    expected_contract = (
        [
            "--allowedTools", "--disallowedTools", "--json-schema",
            "--mcp-config", "--model", "--output-format",
            "--permission-mode", "--strict-mcp-config",
        ]
        if expected_backend == "claude" else
        [
            "--ephemeral", "--json", "--model", "--output-last-message",
            "--sandbox", "--skip-git-repo-check",
        ]
    )
    expected_version_output = (
        f"{resolved_version} (Claude Code)"
        if expected_backend == "claude" else f"codex-cli {resolved_version}"
    )
    expected_probe_argv = {
        "version": ["--version"],
        "help": (
            ["--help"] if expected_backend == "claude"
            else ["exec", "--help"]
        ),
    }
    probe_fields = {
        "argv", "returncode", "stdout_sha256", "stderr_sha256",
        "normalized_output", "observed_contract",
    }
    probes_valid = type(probes) is dict and frozenset(probes) == {
        "help", "version",
    }
    if probes_valid:
        for name in ("version", "help"):
            probe = probes.get(name)
            if (
                type(probe) is not dict
                or frozenset(probe) != probe_fields
                or probe.get("argv") != expected_probe_argv[name]
                or probe.get("returncode") != 0
                or type(probe.get("stdout_sha256")) is not str
                or _HEX_RE.fullmatch(probe["stdout_sha256"]) is None
                or type(probe.get("stderr_sha256")) is not str
                or _HEX_RE.fullmatch(probe["stderr_sha256"]) is None
                or type(probe.get("normalized_output")) is not str
                or type(probe.get("observed_contract")) is not list
                or any(
                    type(item) is not str
                    for item in probe.get("observed_contract", [])
                )
            ):
                probes_valid = False
                break
    if (
        type(installed) is not dict
        or frozenset(installed) != {
            "platform", "relative_path", "executable_size",
            "executable_sha256", "closure_count", "closure_bytes",
            "closure_sha256", "code_signature",
        }
        or type(installed.get("executable_size")) is not int
        or not 1 <= installed["executable_size"] <= MAX_EXECUTABLE_BYTES
        or type(installed.get("executable_sha256")) is not str
        or _HEX_RE.fullmatch(installed["executable_sha256"]) is None
        or type(installed.get("closure_sha256")) is not str
        or _HEX_RE.fullmatch(installed["closure_sha256"]) is None
        or type(code_signature) is not dict
        or frozenset(code_signature)
        != {"mode", "identifier", "team_identifier", "cdhash_sha256"}
        or not probes_valid
        or probes["version"]["normalized_output"] != expected_version_output
        or probes["version"]["observed_contract"] != []
        or sorted(observed_contract or []) != sorted(expected_contract)
    ):
        _fail(
            "INSTALL_GENERATION_CONFORMANCE",
            "installed executable or CLI behavior contract differs",
        )
    install = receipt.get("install")
    registry = receipt.get("registry")
    platform_package = (
        registry.get("platform_package") if type(registry) is dict else None
    )
    if (
        type(install) is not dict
        or frozenset(install) != {
            "transaction_id", "generation_id", "install_receipt_sha256",
            "source_manifest_sha256", "source_manifest_size",
        }
        or install.get("source_manifest_sha256")
        != binding["source_manifest_sha256"]
        or install.get("source_manifest_size") != binding["source_manifest_size"]
        or type(install.get("generation_id")) is not str
        or re.fullmatch(r"npm-[0-9a-f]{64}", install["generation_id"]) is None
        or type(registry) is not dict
        or registry.get("selector") != expected_backend
        or registry.get("version") != resolved_version
        or type(platform_package) is not dict
        or receipt.get("resolved_release") != platform_package.get("version")
    ):
        _fail("INSTALL_GENERATION_RECEIPT", "installed runtime join differs")

    cli_behavior = backend_cli_behavior_contract_sha256(expected_backend)
    cli_conformance = hashlib.sha256(_native_semantic_json_bytes({
        "backend": expected_backend,
        "behavior_contract_sha256": cli_behavior,
        "help": probes["help"],
        "version": probes["version"],
    })).hexdigest()
    publisher = "OpenAI" if expected_backend == "codex" else "Anthropic PBC"
    provenance = (
        CODEX_EXECUTABLE_PROVENANCE
        if expected_backend == "codex" else CLAUDE_EXECUTABLE_PROVENANCE
    )
    publisher_identity = hashlib.sha256(_native_semantic_json_bytes({
        "code_signature": code_signature,
        "trusted_publisher": registry.get("trusted_publisher"),
    })).hexdigest()
    provenance_receipt = hashlib.sha256(_native_semantic_json_bytes({
        "registry_provenance": registry.get("provenance"),
        "platform_provenance": platform_package.get("provenance"),
        "upstream": receipt.get("upstream"),
    })).hexdigest()
    latest_resolution = hashlib.sha256(_native_semantic_json_bytes({
        "metadata_sha256": registry.get("metadata_sha256"),
        "metadata_url": registry.get("metadata_url"),
        "resolved_version": resolved_version,
        "selector": "latest",
        "upstream_latest": (
            receipt.get("upstream", {}).get("latest_sha256")
            if type(receipt.get("upstream")) is dict else None
        ),
    })).hexdigest()
    private_digests = {
        "acquisition_policy_sha256": binding["policy_sha256"],
        "acquisition_validator_sha256": (
            binding["coordinator_code_identity_sha256"]
        ),
        "registry_latest_observation_sha256": latest_resolution,
        "upstream_integrity_sha256": hashlib.sha256(
            _native_semantic_json_bytes({
                "platform_integrity": platform_package.get("integrity"),
                "registry_integrity": registry.get("integrity"),
                "upstream": receipt.get("upstream"),
            })
        ).hexdigest(),
        "signature_provenance_sha256": hashlib.sha256(
            _native_semantic_json_bytes({
                "authentication": authentication,
                "code_signature": code_signature,
                "registry_signature": registry.get("registry_signature"),
            })
        ).hexdigest(),
        "installed_manifest_sha256": binding["source_manifest_sha256"],
        "coordinator_receipt_sha256": binding["coordinator_receipt_sha256"],
    }
    core = {
        "schema": INSTALL_GENERATION_RECEIPT_SCHEMA,
        "authority_class": INSTALL_GENERATION_AUTHORITY_CLASS,
        "resolution_selector": "latest",
        "runtime_resolution": "FORBIDDEN",
        "backend": expected_backend,
        "resolved_version": resolved_version,
        "executable_size": installed["executable_size"],
        "publisher": publisher,
        "provenance": provenance,
        "install_generation_id": install["generation_id"],
        "executable_sha256": installed["executable_sha256"],
        "runtime_closure_sha256": installed["closure_sha256"],
        "publisher_identity_sha256": publisher_identity,
        "provenance_receipt_sha256": provenance_receipt,
        "latest_resolution_receipt_sha256": latest_resolution,
        "cli_behavior_contract_sha256": cli_behavior,
        "cli_conformance_sha256": cli_conformance,
        "producer_receipt_sha256": binding["producer_receipt_sha256"],
        **private_digests,
    }
    projection = BackendInstallGenerationProjection(
        authority_class=INSTALL_GENERATION_AUTHORITY_CLASS,
        backend=expected_backend,
        resolved_version=resolved_version,
        executable_sha256=installed["executable_sha256"],
        executable_size=installed["executable_size"],
        runtime_closure_sha256=installed["closure_sha256"],
        publisher=publisher,
        publisher_identity_sha256=publisher_identity,
        provenance=provenance,
        provenance_receipt_sha256=provenance_receipt,
        latest_resolution_receipt_sha256=latest_resolution,
        cli_behavior_contract_sha256=cli_behavior,
        cli_conformance_sha256=cli_conformance,
        install_generation_id=install["generation_id"],
        install_generation_sha256=hashlib.sha256(_canonical(core)).hexdigest(),
        producer_receipt_sha256=binding["producer_receipt_sha256"],
    )
    return projection, native_authority


def _native_semantic_json_bytes(value: Mapping[str, Any]) -> bytes:
    _bounded_json_shape(value)
    try:
        return json.dumps(
            dict(value), ensure_ascii=False, allow_nan=False, sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, RecursionError, OverflowError):
        _fail("INSTALL_GENERATION_RECEIPT", "receipt is not canonicalizable")


def _issue_native_backend_install_generation(
    native_authority: object, *, expected_backend: str,
) -> BackendInstallGenerationAuthority:
    """Internal native-to-policy promotion; never accepts mappings or hashes."""

    projection, anchor = _native_backend_install_projection(
        native_authority, expected_backend=expected_backend,
    )
    authority = object.__new__(BackendInstallGenerationAuthority)
    object.__setattr__(
        authority, "_BackendInstallGenerationAuthority__token", object(),
    )
    with _LOCK:
        _INSTALL_GENERATIONS[authority] = _BackendInstallGenerationRecord(
            projection=projection, native_anchor=anchor,
        )
    return authority


def TEST_ONLY_project_backend_install_generation(
    value: object,
) -> BackendInstallGenerationProjection:
    return _install_generation_projection(value, allow_test_only=True)


def TEST_ONLY_issue_backend_install_generation(
    *, backend: str, resolved_version: str, executable_sha256: str,
    executable_size: int, runtime_closure_sha256: str, publisher: str,
    publisher_identity_sha256: str, provenance: str,
    provenance_receipt_sha256: str, latest_resolution_receipt_sha256: str,
    cli_behavior_contract_sha256: str, cli_conformance_sha256: str,
    install_generation_id: str, producer_receipt_sha256: str,
    acquisition_policy_sha256: str, acquisition_validator_sha256: str,
    registry_latest_observation_sha256: str,
    upstream_integrity_sha256: str, signature_provenance_sha256: str,
    installed_manifest_sha256: str, coordinator_receipt_sha256: str,
) -> TestOnlyBackendInstallGenerationAuthority:
    """Mint non-authoritative structural evidence for dynamic-release tests."""

    if backend not in {"codex", "claude"}:
        _fail("BACKEND", "install-generation backend is not admitted")
    version = _semver(resolved_version, "resolved install version")
    canonical_version = ".".join(str(part) for part in version)
    if resolved_version != canonical_version:
        _fail("INSTALL_GENERATION_VERSION", "resolved version is not canonical")
    if (
        type(executable_size) is not int
        or isinstance(executable_size, bool)
        or not 1 <= executable_size <= MAX_EXECUTABLE_BYTES
    ):
        _fail("INSTALL_GENERATION_SIZE", "executable size is outside policy")
    if (
        type(publisher) is not str
        or not publisher
        or len(publisher.encode("utf-8")) > 256
        or "\x00" in publisher
    ):
        _fail("INSTALL_GENERATION_PUBLISHER", "publisher identity is malformed")
    if type(provenance) is not str or _ID_RE.fullmatch(provenance) is None:
        _fail("INSTALL_GENERATION_PROVENANCE", "provenance is malformed")
    if (
        type(install_generation_id) is not str
        or _ID_RE.fullmatch(install_generation_id) is None
    ):
        _fail("INSTALL_GENERATION_ID", "install generation id is malformed")
    digests = {
        "executable_sha256": executable_sha256,
        "runtime_closure_sha256": runtime_closure_sha256,
        "publisher_identity_sha256": publisher_identity_sha256,
        "provenance_receipt_sha256": provenance_receipt_sha256,
        "latest_resolution_receipt_sha256": latest_resolution_receipt_sha256,
        "cli_behavior_contract_sha256": cli_behavior_contract_sha256,
        "cli_conformance_sha256": cli_conformance_sha256,
        "producer_receipt_sha256": producer_receipt_sha256,
        "acquisition_policy_sha256": acquisition_policy_sha256,
        "acquisition_validator_sha256": acquisition_validator_sha256,
        "registry_latest_observation_sha256": registry_latest_observation_sha256,
        "upstream_integrity_sha256": upstream_integrity_sha256,
        "signature_provenance_sha256": signature_provenance_sha256,
        "installed_manifest_sha256": installed_manifest_sha256,
        "coordinator_receipt_sha256": coordinator_receipt_sha256,
    }
    if any(type(item) is not str or _HEX_RE.fullmatch(item) is None
           for item in digests.values()):
        _fail("INSTALL_GENERATION_DIGEST", "install-generation digest is malformed")
    if cli_behavior_contract_sha256 != backend_cli_behavior_contract_sha256(
        backend
    ):
        _fail(
            "CLI_BEHAVIOR_CONTRACT",
            "install generation lacks the exact runtime CLI behavior contract",
        )
    core = {
        "schema": INSTALL_GENERATION_RECEIPT_SCHEMA,
        "authority_class": TEST_ONLY_INSTALL_GENERATION_AUTHORITY_CLASS,
        "resolution_selector": "latest",
        "runtime_resolution": "FORBIDDEN",
        "backend": backend,
        "resolved_version": resolved_version,
        "executable_size": executable_size,
        "publisher": publisher,
        "provenance": provenance,
        "install_generation_id": install_generation_id,
        **digests,
    }
    install_generation_sha256 = hashlib.sha256(_canonical(core)).hexdigest()
    projection = BackendInstallGenerationProjection(
        authority_class=TEST_ONLY_INSTALL_GENERATION_AUTHORITY_CLASS,
        backend=backend,
        resolved_version=resolved_version,
        executable_sha256=executable_sha256,
        executable_size=executable_size,
        runtime_closure_sha256=runtime_closure_sha256,
        publisher=publisher,
        publisher_identity_sha256=publisher_identity_sha256,
        provenance=provenance,
        provenance_receipt_sha256=provenance_receipt_sha256,
        latest_resolution_receipt_sha256=latest_resolution_receipt_sha256,
        cli_behavior_contract_sha256=cli_behavior_contract_sha256,
        cli_conformance_sha256=cli_conformance_sha256,
        install_generation_id=install_generation_id,
        install_generation_sha256=install_generation_sha256,
        producer_receipt_sha256=producer_receipt_sha256,
    )
    authority = object.__new__(TestOnlyBackendInstallGenerationAuthority)
    object.__setattr__(
        authority, "_TestOnlyBackendInstallGenerationAuthority__token", object(),
    )
    with _LOCK:
        _INSTALL_GENERATIONS[authority] = _BackendInstallGenerationRecord(
            projection=projection, native_anchor=None,
        )
    return authority


_LOCK = threading.RLock()
_EXECUTABLES: dict[int, tuple[weakref.ReferenceType[Any], _Executable]] = {}
_INSTALL_GENERATIONS: weakref.WeakKeyDictionary[
    object, "_BackendInstallGenerationRecord"
] = weakref.WeakKeyDictionary()
_TEST_ONLY_AUTHORITIES: dict[
    int, tuple[weakref.ReferenceType[Any], _LaunchAuthority]
] = {}
_TEST_ONLY_PLANS: dict[int, tuple[weakref.ReferenceType[Any], _Plan]] = {}
_TEST_ONLY_INVOCATIONS: dict[int, tuple[weakref.ReferenceType[Any], _Plan]] = {}


class BackendInstallGenerationAuthority:
    """Opaque durable authority minted only by an authenticated installer.

    There is intentionally no production Python issuer.  A native installer
    adapter may register this exact type only after authenticating the latest-
    resolution producer receipt and its immutable installed closure.
    """

    __slots__ = ("__token", "__weakref__")

    def __init__(self, *_args: Any, **_kwargs: Any) -> None:
        raise TypeError("install-generation authorities are installer-issued")

    def __setattr__(self, _name: str, _value: Any) -> None:
        raise TypeError("install-generation authorities are immutable")

    def __copy__(self) -> NoReturn:
        raise TypeError("install-generation authorities cannot be copied")

    def __deepcopy__(self, _memo: Any) -> NoReturn:
        raise TypeError("install-generation authorities cannot be copied")

    def __reduce__(self) -> NoReturn:
        raise TypeError("install-generation authorities cannot be serialized")

    def __repr__(self) -> str:
        return "<BackendInstallGenerationAuthority opaque>"


class TestOnlyBackendInstallGenerationAuthority:
    """Structurally equivalent, explicitly non-production test authority."""

    __slots__ = ("__token", "__weakref__")

    def __init__(self, *_args: Any, **_kwargs: Any) -> None:
        raise TypeError("test install-generation authorities are issuer-created")

    def __setattr__(self, _name: str, _value: Any) -> None:
        raise TypeError("test install-generation authorities are immutable")

    def __copy__(self) -> NoReturn:
        raise TypeError("test install-generation authorities cannot be copied")

    def __deepcopy__(self, _memo: Any) -> NoReturn:
        raise TypeError("test install-generation authorities cannot be copied")

    def __reduce__(self) -> NoReturn:
        raise TypeError("test install-generation authorities cannot be serialized")

    def __repr__(self) -> str:
        return "<TestOnlyBackendInstallGenerationAuthority opaque>"


def _close_file(item: _File) -> None:
    try:
        os.close(item.fd)
    except OSError:
        pass


def _drop_executable(identity: int) -> None:
    with _LOCK:
        item = _EXECUTABLES.pop(identity, None)
    if item:
        _close_file(item[1].file)


def _drop_test_only_authority(identity: int) -> None:
    with _LOCK:
        item = _TEST_ONLY_AUTHORITIES.pop(identity, None)
    if item:
        _close_file(item[1].ca_bundle)


def _drop_test_only_plan(identity: int) -> None:
    with _LOCK:
        item = _TEST_ONLY_PLANS.pop(identity, None)
    if item:
        for fd in {
            *(entry.fd for entry in item[1].directories),
            *(entry.fd for entry in item[1].files),
        }:
            try:
                os.close(fd)
            except OSError:
                pass


def _drop_test_only_invocation(identity: int) -> None:
    with _LOCK:
        item = _TEST_ONLY_INVOCATIONS.pop(identity, None)
    if item:
        _close_plan_record(item[1])


def _close_plan_record(record: _Plan) -> None:
    for fd in {
        *(entry.fd for entry in record.directories),
        *(entry.fd for entry in record.files),
    }:
        try:
            os.close(fd)
        except OSError:
            pass


class BackendExecutableCapability:
    """Opaque one-shot executable identity and exact-version capability."""

    __slots__ = ("__token", "__weakref__")

    def __init__(self, *_args: Any, **_kwargs: Any) -> None:
        raise TypeError("backend executable capabilities are issuer-created only")

    def __setattr__(self, _name: str, _value: Any) -> None:
        raise TypeError("backend executable capability is immutable")

    def __copy__(self) -> NoReturn:
        raise TypeError("backend executable capability cannot be copied")

    def __deepcopy__(self, _memo: Any) -> NoReturn:
        raise TypeError("backend executable capability cannot be copied")

    def __reduce__(self) -> NoReturn:
        raise TypeError("backend executable capability cannot be serialized")

    def close(self) -> None:
        _drop_executable(id(self))

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass


class BackendLaunchAuthorityCapability:
    """Opaque one-shot authenticated release/provider/egress authority."""

    __slots__ = ("__token", "__weakref__")

    def __init__(self, *_args: Any, **_kwargs: Any) -> None:
        raise TypeError("launch authority capabilities are issuer-created only")

    def __setattr__(self, _name: str, _value: Any) -> None:
        raise TypeError("launch authority capability is immutable")

    def __copy__(self) -> NoReturn:
        raise TypeError("launch authority capability cannot be copied")

    def __deepcopy__(self, _memo: Any) -> NoReturn:
        raise TypeError("launch authority capability cannot be copied")

    def __reduce__(self) -> NoReturn:
        raise TypeError("launch authority capability cannot be serialized")

    def close(self) -> None:
        # There is deliberately no Python production-authority registry.
        return None

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass


class NativeLaunchAuthorityCapability:
    """Reserved opaque result of the not-yet-integrated native verifier.

    This Python module intentionally has no issuer or registry mutator for this
    type.  Even ``object.__new__`` therefore creates only an unregistered fake.
    Production issuance remains a typed hardstop until the compiled or
    out-of-process verifier owns this seam.
    """

    __slots__ = ("__token", "__weakref__")

    def __init__(self, *_args: Any, **_kwargs: Any) -> None:
        raise TypeError("native launch authority is verifier-created only")

    def __setattr__(self, _name: str, _value: Any) -> None:
        raise TypeError("native launch authority is immutable")

    def __copy__(self) -> NoReturn:
        raise TypeError("native launch authority cannot be copied")

    def __deepcopy__(self, _memo: Any) -> NoReturn:
        raise TypeError("native launch authority cannot be copied")

    def __reduce__(self) -> NoReturn:
        raise TypeError("native launch authority cannot be serialized")


class TestOnlyBackendLaunchAuthorityCapability:
    """Non-authoritative structural-test capability with a distinct type."""

    __slots__ = ("__token", "__weakref__")

    def __init__(self, *_args: Any, **_kwargs: Any) -> None:
        raise TypeError("test-only launch authorities are issuer-created only")

    def __setattr__(self, _name: str, _value: Any) -> None:
        raise TypeError("test-only launch authority is immutable")

    def __copy__(self) -> NoReturn:
        raise TypeError("test-only launch authority cannot be copied")

    def __deepcopy__(self, _memo: Any) -> NoReturn:
        raise TypeError("test-only launch authority cannot be copied")

    def __reduce__(self) -> NoReturn:
        raise TypeError("test-only launch authority cannot be serialized")

    def close(self) -> None:
        _drop_test_only_authority(id(self))

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass


def _production_object_unavailable() -> NoReturn:
    _fail(
        "NATIVE_AUTHORITY_UNAVAILABLE",
        "native launch-authority verifier integration is not installed",
    )


class BackendLaunchPlan:
    """Reserved production type with no Python registry or accessor path."""

    __slots__ = ("__token", "__weakref__")

    def __init__(self, *_args: Any, **_kwargs: Any) -> None:
        raise TypeError("backend launch plans are renderer-created only")

    def __setattr__(self, _name: str, _value: Any) -> None:
        raise TypeError("backend launch plan is immutable")

    def __copy__(self) -> NoReturn:
        raise TypeError("backend launch plan cannot be copied")

    def __deepcopy__(self, _memo: Any) -> NoReturn:
        raise TypeError("backend launch plan cannot be copied")

    def __reduce__(self) -> NoReturn:
        raise TypeError("backend launch plan cannot be serialized")

    def public_receipt_bytes(self) -> bytes:
        _production_object_unavailable()

    def public_binding_sha256(self) -> str:
        _production_object_unavailable()

    def validate_public_receipt(self, raw: bytes) -> Mapping[str, Any]:
        _production_object_unavailable()

    def consume(self) -> BackendLaunchInvocation:
        _production_object_unavailable()

    def close(self) -> None:
        return None

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass


class BackendLaunchInvocation:
    """Reserved production invocation with no Python-backed record path."""

    __slots__ = ("__token", "__weakref__")

    def __init__(self, *_args: Any, **_kwargs: Any) -> None:
        raise TypeError("backend launch invocations are plan-created only")

    def __setattr__(self, _name: str, _value: Any) -> None:
        raise TypeError("backend launch invocation is immutable")

    def __copy__(self) -> NoReturn:
        raise TypeError("backend launch invocation cannot be copied")

    def __deepcopy__(self, _memo: Any) -> NoReturn:
        raise TypeError("backend launch invocation cannot be copied")

    def __reduce__(self) -> NoReturn:
        raise TypeError("backend launch invocation cannot be serialized")

    @property
    def argv(self) -> tuple[str, ...]:
        _production_object_unavailable()

    @property
    def environment(self) -> Mapping[str, str]:
        _production_object_unavailable()

    @property
    def cwd_fd(self) -> int:
        _production_object_unavailable()

    @property
    def stdin_fd(self) -> int:
        _production_object_unavailable()

    @property
    def pass_fds(self) -> tuple[int, ...]:
        _production_object_unavailable()

    @property
    def credential_fd(self) -> int:
        _production_object_unavailable()

    @property
    def credential_delivery(self) -> str:
        _production_object_unavailable()

    @property
    def codex_profile_fd(self) -> int | None:
        _production_object_unavailable()

    @property
    def codex_profile_delivery(self) -> str:
        _production_object_unavailable()

    def codex_config_census_contract_bytes(self) -> bytes | None:
        """Private supervisor contract; unlike the public receipt it has paths."""

        _production_object_unavailable()

    def issuance_receipt_bytes(self) -> bytes:
        _production_object_unavailable()

    def validate_issuance_receipt(self, raw: bytes) -> Mapping[str, Any]:
        _production_object_unavailable()

    def complete(
        self, *, status: str, completion_evidence_sha256: str | None,
    ) -> bytes:
        _production_object_unavailable()

    def revoke(self) -> bytes:
        _production_object_unavailable()

    def close(self) -> None:
        return None

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass


class TestOnlyBackendLaunchPlan:
    """Opaque non-production structural-test plan."""

    __slots__ = ("__token", "__weakref__")

    def __init__(self, *_args: Any, **_kwargs: Any) -> None:
        raise TypeError("test-only launch plans are renderer-created only")

    def __setattr__(self, _name: str, _value: Any) -> None:
        raise TypeError("test-only launch plan is immutable")

    def __copy__(self) -> NoReturn:
        raise TypeError("test-only launch plan cannot be copied")

    def __deepcopy__(self, _memo: Any) -> NoReturn:
        raise TypeError("test-only launch plan cannot be copied")

    def __reduce__(self) -> NoReturn:
        raise TypeError("test-only launch plan cannot be serialized")

    def public_receipt_bytes(self) -> bytes:
        return _peek_test_only_plan(self).receipt

    def public_binding_sha256(self) -> str:
        return hashlib.sha256(_peek_test_only_plan(self).receipt).hexdigest()

    def validate_public_receipt(self, raw: bytes) -> Mapping[str, Any]:
        return _validate_receipt(raw, _peek_test_only_plan(self).receipt)

    def consume(self) -> TestOnlyBackendLaunchInvocation:
        return _consume_test_only_plan(self)

    def close(self) -> None:
        _drop_test_only_plan(id(self))

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass


class TestOnlyBackendLaunchInvocation:
    """FD-owning non-production structural invocation for structural tests."""

    __slots__ = ("__token", "__weakref__")

    def __init__(self, *_args: Any, **_kwargs: Any) -> None:
        raise TypeError("test-only launch invocations are plan-created only")

    def __setattr__(self, _name: str, _value: Any) -> None:
        raise TypeError("test-only launch invocation is immutable")

    def __copy__(self) -> NoReturn:
        raise TypeError("test-only launch invocation cannot be copied")

    def __deepcopy__(self, _memo: Any) -> NoReturn:
        raise TypeError("test-only launch invocation cannot be copied")

    def __reduce__(self) -> NoReturn:
        raise TypeError("test-only launch invocation cannot be serialized")

    @property
    def argv(self) -> tuple[str, ...]:
        return _test_only_invocation_record(self).argv

    @property
    def environment(self) -> Mapping[str, str]:
        return MappingProxyType(dict(_test_only_invocation_record(self).environment))

    @property
    def cwd_fd(self) -> int:
        return _test_only_invocation_record(self).directories[0].fd

    @property
    def stdin_fd(self) -> int:
        return _test_only_invocation_record(self).stdin_fd

    @property
    def pass_fds(self) -> tuple[int, ...]:
        return _test_only_invocation_record(self).pass_fds

    @property
    def credential_fd(self) -> int:
        return _test_only_invocation_record(self).credential_fd

    @property
    def credential_delivery(self) -> str:
        return _test_only_invocation_record(self).credential_delivery

    @property
    def codex_profile_fd(self) -> int | None:
        return _test_only_invocation_record(self).codex_profile_fd

    @property
    def codex_profile_delivery(self) -> str:
        return _test_only_invocation_record(self).codex_profile_delivery

    def codex_config_census_contract_bytes(self) -> bytes | None:
        return _test_only_invocation_record(self).codex_config_census_bytes

    def issuance_receipt_bytes(self) -> bytes:
        return _test_only_invocation_record(self).receipt

    def validate_issuance_receipt(self, raw: bytes) -> Mapping[str, Any]:
        return _validate_receipt(raw, _test_only_invocation_record(self).receipt)

    def complete(
        self, *, status: str, completion_evidence_sha256: str | None,
    ) -> bytes:
        return _complete_test_only_invocation(
            self, status, completion_evidence_sha256,
        )

    def revoke(self) -> bytes:
        return _complete_test_only_invocation(
            self, "UNEXECUTED_AND_REVOKED", None,
        )

    def close(self) -> None:
        _drop_test_only_invocation(id(self))

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass


def issue_backend_executable(
    executable_fd: int, *, backend: str, observed_version: str,
    allowed_version: str, expected_sha256: str,
    cli_conformance_sha256: str | None = None,
    install_generation_authority: object | None = None,
) -> BackendExecutableCapability:
    """Bind exact bytes to an authenticated dynamic install generation."""

    _require_posix_fcntl()
    generation = _install_generation_projection(
        install_generation_authority, allow_test_only=True,
    )
    if backend not in {"codex", "claude"}:
        _fail("BACKEND", "backend must be codex or claude")
    _semver(observed_version, "observed version")
    _semver(allowed_version, "allowed version")
    if observed_version != allowed_version:
        _fail("VERSION_DRIFT", "observed version is not exactly allowed")
    if generation.backend != backend or generation.resolved_version != observed_version:
        _fail(
            "INSTALL_GENERATION_VERSION",
            "runtime backend/version differs from the install generation",
        )
    if type(expected_sha256) is not str or _HEX_RE.fullmatch(expected_sha256) is None:
        _fail("EXECUTABLE_DIGEST", "expected executable digest is malformed")
    if (
        type(cli_conformance_sha256) is not str
        or _HEX_RE.fullmatch(cli_conformance_sha256) is None
    ):
        _fail(
            "CLI_CONFORMANCE",
            "independent live CLI/profile conformance evidence is required",
        )
    if expected_sha256 != generation.executable_sha256:
        _fail(
            "EXECUTABLE_DIGEST",
            "executable digest differs from install authority",
        )
    if cli_conformance_sha256 != generation.cli_conformance_sha256:
        _fail(
            "CLI_CONFORMANCE",
            "CLI conformance differs from install authority",
        )
    source = _fd(executable_fd, "executable_fd")
    assert source is not None
    captured = _file(
        source, f"{backend} executable", MAX_EXECUTABLE_BYTES, executable=True,
    )
    if captured.sha256 != expected_sha256:
        _close_file(captured)
        _fail("EXECUTABLE_DIGEST", "backend executable digest did not match")
    if captured.signature[6] != generation.executable_size:
        _close_file(captured)
        _fail(
            "INSTALL_GENERATION_SIZE",
            "backend executable size differs from install authority",
        )
    token = os.urandom(32).hex()
    record = _Executable(
        generation.authority_class, backend, observed_version, expected_sha256,
        cli_conformance_sha256, generation.cli_behavior_contract_sha256,
        generation.install_generation_sha256, captured, token,
    )
    capability = object.__new__(BackendExecutableCapability)
    object.__setattr__(
        capability, "_BackendExecutableCapability__token", token,
    )
    identity = id(capability)
    reference = weakref.ref(
        capability, lambda _unused, key=identity: _drop_executable(key),
    )
    with _LOCK:
        _EXECUTABLES[identity] = (reference, record)
    return capability


def _consume_executable(value: BackendExecutableCapability) -> _Executable:
    if type(value) is not BackendExecutableCapability:
        _fail("EXECUTABLE_CAPABILITY", "capability type is invalid")
    with _LOCK:
        item = _EXECUTABLES.pop(id(value), None)
    if item is None or item[0]() is not value:
        _fail("EXECUTABLE_CAPABILITY", "capability is forged or consumed")
    record = item[1]
    incomplete = False
    try:
        token = object.__getattribute__(
            value, "_BackendExecutableCapability__token",
        )
    except AttributeError:
        incomplete = True
        token = ""
    if incomplete:
        _close_file(record.file)
        _fail("EXECUTABLE_CAPABILITY", "capability is incomplete")
    if token != record.token:
        _close_file(record.file)
        _fail("EXECUTABLE_CAPABILITY", "capability token drifted")
    try:
        _replay_file(record.file)
    except BaseException:
        _close_file(record.file)
        raise
    return record


def issue_backend_launch_authority(
    ca_bundle_fd: int, *,
    authenticated_native_authority: object | None = None,
    **_authority_fields: Any,
) -> BackendLaunchAuthorityCapability:
    """Production issuer hardstop pending the native verifier integration.

    A Python mapping, callback, receipt digest, or caller assertion is never an
    authentication boundary.  The future implementation must consume an exact
    registered ``NativeLaunchAuthorityCapability`` issued by the pinned
    compiled/out-of-process verifier and bind all authority fields plus the CA
    descriptor.  This module deliberately exposes no Python registration or
    issuance surface for that capability.
    """

    _fd(ca_bundle_fd, "ca_bundle_fd")
    if type(authenticated_native_authority) is not NativeLaunchAuthorityCapability:
        _fail(
            "NATIVE_AUTHORITY_REQUIRED",
            "production launch requires opaque native/out-of-process authority",
        )
    _fail(
        "NATIVE_AUTHORITY_UNAVAILABLE",
        "native launch-authority verifier integration is not installed",
    )


def TEST_ONLY_issue_backend_launch_authority(
    ca_bundle_fd: int, *, backend: str, executable_version: str,
    executable_sha256: str, executable_provenance: str,
    runtime_closure_sha256: str, platform: str, attempt_id: str,
    session_id: str, model: str, claude_tools: list[str],
    codex_profile_sha256: str | None,
    claude_settings_contract: str | None,
    claude_settings_sha256: str | None, claude_mcp_sha256: str | None,
    codex_permission_profile_status: str,
    credential_isolation_mode: str, credential_isolation_sha256: str,
    prompt_sha256: str, credential_sha256: str, control_path: str,
    codex_config_census_contract: str | None,
    codex_config_census_contract_sha256: str | None,
    codex_config_census_evidence_sha256: str | None,
    config_sha256: str, image_sha256: str,
    provider_admission_sha256: str, egress_admission_sha256: str,
    proxy_authority_sha256: str, proxy_endpoint: str,
    release_id: str, release_manifest_sha256: str,
    release_ca_sha256: str, authority_authentication_sha256: str,
    install_generation_authority: object | None = None,
) -> TestOnlyBackendLaunchAuthorityCapability:
    """Mint a conspicuously non-authoritative structural-test capability."""

    generation = _install_generation_projection(
        install_generation_authority, allow_test_only=True,
    )
    if backend not in {"codex", "claude"}:
        _fail("BACKEND", "authority backend is not admitted")
    _semver(executable_version, "authority executable version")
    if type(executable_sha256) is not str or _HEX_RE.fullmatch(
        executable_sha256
    ) is None:
        _fail("AUTHORITY_DIGEST", "authority executable digest is malformed")
    if generation.provenance != executable_provenance:
        _fail(
            "EXECUTABLE_PROVENANCE",
            "executable provenance differs from install generation",
        )
    if (
        generation.backend != backend
        or generation.resolved_version != executable_version
        or generation.executable_sha256 != executable_sha256
        or generation.runtime_closure_sha256 != runtime_closure_sha256
    ):
        _fail(
            "INSTALL_GENERATION_BINDING",
            "launch authority differs from the authenticated install generation",
        )
    if type(runtime_closure_sha256) is not str or _HEX_RE.fullmatch(
        runtime_closure_sha256
    ) is None:
        _fail("AUTHORITY_DIGEST", "runtime closure digest is malformed")
    if platform == "linux":
        transport = LINUX_EGRESS_TRANSPORT
    elif platform == "apple":
        transport = APPLE_EGRESS_TRANSPORT
    else:
        _fail("PLATFORM", "platform is not an admitted release target")
    if type(attempt_id) is not str or _ID_RE.fullmatch(attempt_id) is None:
        _fail("AUTHORITY_ID", "authority attempt identifier is malformed")
    canonical_session_id = _canonical_uuid(session_id, "authority session_id")
    if type(model) is not str or _MODEL_RE.fullmatch(model) is None:
        _fail("MODEL", "authority model is malformed")
    canonical_tools = _exact_claude_tools(claude_tools, backend)
    policy_hashes = (
        codex_profile_sha256, claude_settings_sha256, claude_mcp_sha256,
    )
    if backend == "codex":
        if (
            type(codex_profile_sha256) is not str
            or _HEX_RE.fullmatch(codex_profile_sha256) is None
            or claude_settings_contract is not None
            or claude_settings_sha256 is not None
            or claude_mcp_sha256 is not None
        ):
            _fail("POLICY_AUTHORITY", "Codex sealed-profile authority is malformed")
    elif (
        codex_profile_sha256 is not None
        or claude_settings_contract != CLAUDE_SETTINGS_CONTRACT
        or any(type(value) is not str or _HEX_RE.fullmatch(value) is None
               for value in policy_hashes[1:])
    ):
        _fail("POLICY_AUTHORITY", "Claude native-sandbox authority is malformed")
    expected_profile_status = (
        CODEX_PERMISSION_PROFILE_STATUS
        if backend == "codex" else CODEX_PERMISSION_PROFILE_NOT_APPLICABLE
    )
    if codex_permission_profile_status != expected_profile_status:
        _fail("POLICY_AUTHORITY", "Codex profile qualification status drifted")
    if (
        credential_isolation_mode not in CREDENTIAL_ISOLATION_MODES
        or type(credential_isolation_sha256) is not str
        or _HEX_RE.fullmatch(credential_isolation_sha256) is None
    ):
        _fail(
            "CREDENTIAL_ISOLATION",
            "authenticated descendant credential isolation proof is required",
        )
    for label, value in (
        ("prompt", prompt_sha256), ("credential", credential_sha256),
    ):
        if type(value) is not str or _HEX_RE.fullmatch(value) is None:
            _fail("AUTHORITY_DIGEST", f"{label} digest is malformed")
    canonical_control = _path(control_path, "authority control")
    if backend == "codex":
        census_request = {
            "backend": "codex",
            "control_path": canonical_control,
            "codex_profile_sha256": codex_profile_sha256,
            "credential_sha256": credential_sha256,
        }
        census_contract = hashlib.sha256(
            required_codex_config_census_bytes(census_request)
        ).hexdigest()
        if (
            codex_config_census_contract != CODEX_CONFIG_CENSUS_CONTRACT
            or codex_config_census_contract_sha256 != census_contract
            or type(codex_config_census_evidence_sha256) is not str
            or _HEX_RE.fullmatch(codex_config_census_evidence_sha256) is None
        ):
            _fail(
                "CODEX_CONFIG_CENSUS",
                "authenticated exact Codex config census is required",
            )
    elif any(value is not None for value in (
        codex_config_census_contract, codex_config_census_contract_sha256,
        codex_config_census_evidence_sha256,
    )):
        _fail("POLICY_AUTHORITY", "Claude cannot carry a Codex config authority")
    if type(release_id) is not str or _ID_RE.fullmatch(release_id) is None:
        _fail("AUTHORITY_ID", "release identifier is malformed")
    for label, value in (
        ("config", config_sha256), ("image", image_sha256),
        ("provider admission", provider_admission_sha256),
        ("egress admission", egress_admission_sha256),
        ("proxy authority", proxy_authority_sha256),
        ("release manifest", release_manifest_sha256),
        ("release CA", release_ca_sha256),
        ("authority authentication", authority_authentication_sha256),
    ):
        if type(value) is not str or _HEX_RE.fullmatch(value) is None:
            _fail("AUTHORITY_DIGEST", f"{label} digest is malformed")
    endpoint = _proxy(proxy_endpoint, transport)
    source = _fd(ca_bundle_fd, "ca_bundle_fd")
    assert source is not None
    ca_bundle = _file(source, "release-pinned public CA bundle", MAX_CA_BYTES)
    if ca_bundle.sha256 != release_ca_sha256:
        _close_file(ca_bundle)
        _fail("CA_BUNDLE_DIGEST", "release CA pin does not match sealed content")
    token = os.urandom(32).hex()
    record = _LaunchAuthority(
        TEST_ONLY_AUTHORITY_CLASS, backend, executable_version, executable_sha256,
        executable_provenance, runtime_closure_sha256,
        generation.cli_behavior_contract_sha256,
        generation.install_generation_sha256,
        generation.latest_resolution_receipt_sha256,
        generation.publisher_identity_sha256,
        generation.provenance_receipt_sha256,
        platform, attempt_id, canonical_session_id, model, canonical_tools,
        codex_profile_sha256, claude_settings_contract,
        claude_settings_sha256, claude_mcp_sha256,
        codex_permission_profile_status, credential_isolation_mode,
        credential_isolation_sha256,
        prompt_sha256, credential_sha256, canonical_control,
        codex_config_census_contract,
        codex_config_census_contract_sha256,
        codex_config_census_evidence_sha256,
        config_sha256, image_sha256,
        provider_admission_sha256, egress_admission_sha256,
        proxy_authority_sha256, endpoint, transport, release_id,
        release_manifest_sha256, release_ca_sha256,
        authority_authentication_sha256, ca_bundle, token,
    )
    capability = object.__new__(TestOnlyBackendLaunchAuthorityCapability)
    object.__setattr__(
        capability, "_TestOnlyBackendLaunchAuthorityCapability__token", token,
    )
    identity = id(capability)
    reference = weakref.ref(
        capability, lambda _unused, key=identity: _drop_test_only_authority(key),
    )
    with _LOCK:
        _TEST_ONLY_AUTHORITIES[identity] = (reference, record)
    return capability


def _consume_test_only_authority(
    value: TestOnlyBackendLaunchAuthorityCapability,
) -> _LaunchAuthority:
    if type(value) is not TestOnlyBackendLaunchAuthorityCapability:
        _fail("TEST_ONLY_AUTHORITY", "test-only authority type is invalid")
    with _LOCK:
        item = _TEST_ONLY_AUTHORITIES.pop(id(value), None)
    if item is None or item[0]() is not value:
        _fail("TEST_ONLY_AUTHORITY", "test-only authority is forged or consumed")
    record = item[1]
    incomplete = False
    try:
        token = object.__getattribute__(
            value, "_TestOnlyBackendLaunchAuthorityCapability__token",
        )
    except AttributeError:
        incomplete = True
        token = ""
    if (
        incomplete or token != record.token
        or record.authority_class != TEST_ONLY_AUTHORITY_CLASS
    ):
        _close_file(record.ca_bundle)
        _fail("TEST_ONLY_AUTHORITY", "test-only authority is incomplete or drifted")
    try:
        _replay_file(record.ca_bundle)
    except BaseException:
        _close_file(record.ca_bundle)
        raise
    return record


def _proxy(value: object, transport: object) -> str:
    if type(value) is not str or len(value) > 64:
        _fail("PROXY_ENDPOINT", "proxy endpoint is invalid")
    if transport == LINUX_EGRESS_TRANSPORT:
        expected_host = "127.0.0.1"
    elif transport == APPLE_EGRESS_TRANSPORT:
        expected_host = "192.168.64.1"
    else:
        _fail("EGRESS_TRANSPORT", "egress transport is not admitted")
    failed = False
    try:
        parsed = urlsplit(value)
        port = parsed.port
        hostname = parsed.hostname
    except (ValueError, UnicodeError, RecursionError, OverflowError):
        failed = True
        parsed = None
        port = None
        hostname = None
    if failed or parsed is None:
        _fail("PROXY_ENDPOINT", "proxy endpoint is malformed")
    if (
        parsed.scheme != "http" or hostname != expected_host
        or port is None or not 1024 <= port <= 65535
        or parsed.username is not None or parsed.password is not None
        or parsed.path not in {"", "/"} or parsed.query or parsed.fragment
        or value != f"http://{expected_host}:{port}"
    ):
        _fail(
            "PROXY_ENDPOINT",
            "proxy endpoint does not match the canonical transport authority",
        )
    return value


def _validate(
    request: Mapping[str, Any], executable: _Executable,
    authority: _LaunchAuthority,
) -> None:
    if set(request) != _FIELDS or request.get("schema") != REQUEST_SCHEMA:
        _fail("REQUEST_FIELDS", "request fields or schema drifted")
    if request.get("backend") != executable.backend:
        _fail("BACKEND", "request and executable backends differ")
    if request.get("allowed_version") != executable.version:
        _fail("VERSION_DRIFT", "request and executable versions differ")
    if request.get("cli_conformance_sha256") != executable.cli_conformance_sha256:
        _fail("CLI_CONFORMANCE", "CLI conformance evidence drifted")
    if (
        request.get("cli_behavior_contract_sha256")
        != executable.cli_behavior_contract_sha256
        or request.get("install_generation_sha256")
        != executable.install_generation_sha256
    ):
        _fail(
            "INSTALL_GENERATION_BINDING",
            "request differs from executable install generation",
        )
    if (
        authority.backend != executable.backend
        or authority.executable_version != executable.version
        or authority.executable_sha256 != executable.sha256
        or authority.install_generation_sha256
        != executable.install_generation_sha256
        or authority.cli_behavior_contract_sha256
        != executable.cli_behavior_contract_sha256
        or (
            authority.authority_class == TEST_ONLY_AUTHORITY_CLASS
            and executable.install_generation_authority_class
            != TEST_ONLY_INSTALL_GENERATION_AUTHORITY_CLASS
        )
        or (
            authority.authority_class == PRODUCTION_AUTHORITY_CLASS
            and executable.install_generation_authority_class
            != INSTALL_GENERATION_AUTHORITY_CLASS
        )
    ):
        _fail(
            "AUTHORITY_EXECUTABLE",
            "authenticated authority does not bind the consumed executable",
        )
    for key in (
        "latest_resolution_receipt_sha256", "publisher_identity_sha256",
        "provenance_receipt_sha256",
    ):
        if request.get(key) != getattr(authority, key):
            _fail(
                "INSTALL_GENERATION_BINDING",
                f"request {key} differs from install generation",
            )
    for key in ("attempt_id", "proxy_attempt_id"):
        value = request.get(key)
        if type(value) is not str or _ID_RE.fullmatch(value) is None:
            _fail("REQUEST_ID", f"{key} is malformed")
    if request["attempt_id"] != request["proxy_attempt_id"]:
        _fail("PROXY_SCOPE", "proxy is not bound to the exact attempt")
    session_id = _canonical_uuid(request.get("session_id"), "request session_id")
    claude_tools = _exact_claude_tools(request.get("claude_tools"), executable.backend)
    if executable.backend == "codex":
        if (
            type(request.get("codex_profile_sha256")) is not str
            or _HEX_RE.fullmatch(request["codex_profile_sha256"]) is None
            or request.get("claude_settings_contract") is not None
            or request.get("claude_settings_sha256") is not None
            or request.get("claude_mcp_sha256") is not None
        ):
            _fail("CODEX_POLICY", "Codex sealed-profile binding is malformed")
    elif (
        request.get("codex_profile_sha256") is not None
        or request.get("claude_settings_contract") != CLAUDE_SETTINGS_CONTRACT
        or any(
            type(request.get(key)) is not str
            or _HEX_RE.fullmatch(request[key]) is None
            for key in ("claude_settings_sha256", "claude_mcp_sha256")
        )
    ):
        _fail("CLAUDE_POLICY", "Claude native-sandbox binding is malformed")
    expected_profile_status = (
        CODEX_PERMISSION_PROFILE_STATUS
        if executable.backend == "codex"
        else CODEX_PERMISSION_PROFILE_NOT_APPLICABLE
    )
    if request.get("codex_permission_profile_status") != expected_profile_status:
        _fail("CODEX_POLICY", "Codex profile qualification status drifted")
    if (
        request.get("credential_isolation_mode") not in CREDENTIAL_ISOLATION_MODES
        or type(request.get("credential_isolation_sha256")) is not str
        or _HEX_RE.fullmatch(request["credential_isolation_sha256"]) is None
    ):
        _fail(
            "CREDENTIAL_ISOLATION",
            "authenticated descendant credential isolation proof is required",
        )
    for key in ("prompt_sha256", "credential_sha256"):
        if type(request.get(key)) is not str or _HEX_RE.fullmatch(request[key]) is None:
            _fail("REQUEST_DIGEST", f"{key} is malformed")
    if executable.backend == "codex":
        expected_census_contract = hashlib.sha256(
            required_codex_config_census_bytes(request)
        ).hexdigest()
        if (
            request.get("codex_config_census_contract")
            != CODEX_CONFIG_CENSUS_CONTRACT
            or request.get("codex_config_census_contract_sha256")
            != expected_census_contract
            or type(request.get("codex_config_census_evidence_sha256")) is not str
            or _HEX_RE.fullmatch(
                request["codex_config_census_evidence_sha256"]
            ) is None
        ):
            _fail(
                "CODEX_CONFIG_CENSUS",
                "authenticated exact Codex config census is required",
            )
    elif any(request.get(key) is not None for key in (
        "codex_config_census_contract", "codex_config_census_contract_sha256",
        "codex_config_census_evidence_sha256",
    )):
        _fail("CLAUDE_POLICY", "Claude cannot carry a Codex config binding")
    for key in (
        "config_sha256", "image_sha256", "provider_admission_sha256",
        "proxy_authority_sha256", "egress_admission_sha256",
        "release_manifest_sha256", "release_ca_sha256",
        "authority_authentication_sha256", "runtime_closure_sha256",
    ):
        if type(request.get(key)) is not str or _HEX_RE.fullmatch(request[key]) is None:
            _fail("REQUEST_DIGEST", f"{key} is malformed")
    model = request.get("model")
    if type(model) is not str or _MODEL_RE.fullmatch(model) is None:
        _fail("MODEL", "model is malformed")
    if request.get("proxy_scope") != EGRESS_SCOPE:
        _fail("PROXY_SCOPE", "CONNECT allowlist verification is not exact")
    if request.get("ca_bundle_scope") != CA_BUNDLE_SCOPE:
        _fail("CA_BUNDLE_SCOPE", "CA bundle must be the admitted public WebPKI set")
    if request.get("backend_network") != "PROXY_ONLY":
        _fail("BACKEND_NETWORK", "backend egress must be proxy-only")
    if request.get("tool_network") != "DENY":
        _fail("TOOL_NETWORK", "tool subprocess egress must be denied")
    if type(request.get("limits")) is not dict or request["limits"] != dict(_LIMITS):
        _fail("LIMITS", "byte limits are not exact")
    endpoint = _proxy(request.get("proxy_endpoint"), request.get("egress_transport"))
    if type(request.get("release_id")) is not str or _ID_RE.fullmatch(
        request["release_id"]
    ) is None:
        _fail("REQUEST_ID", "release_id is malformed")
    authority_bindings = {
        "platform": authority.platform,
        "attempt_id": authority.attempt_id,
        "session_id": authority.session_id,
        "model": authority.model,
        "claude_tools": list(authority.claude_tools),
        "codex_profile_sha256": authority.codex_profile_sha256,
        "claude_settings_contract": authority.claude_settings_contract,
        "claude_settings_sha256": authority.claude_settings_sha256,
        "claude_mcp_sha256": authority.claude_mcp_sha256,
        "codex_permission_profile_status": (
            authority.codex_permission_profile_status
        ),
        "credential_isolation_mode": authority.credential_isolation_mode,
        "credential_isolation_sha256": authority.credential_isolation_sha256,
        "prompt_sha256": authority.prompt_sha256,
        "credential_sha256": authority.credential_sha256,
        "control_path": authority.control_path,
        "codex_config_census_contract": (
            authority.codex_config_census_contract
        ),
        "codex_config_census_contract_sha256": (
            authority.codex_config_census_contract_sha256
        ),
        "codex_config_census_evidence_sha256": (
            authority.codex_config_census_evidence_sha256
        ),
        "proxy_attempt_id": authority.attempt_id,
        "config_sha256": authority.config_sha256,
        "image_sha256": authority.image_sha256,
        "provider_admission_sha256": authority.provider_admission_sha256,
        "egress_admission_sha256": authority.egress_admission_sha256,
        "proxy_authority_sha256": authority.proxy_authority_sha256,
        "proxy_endpoint": authority.proxy_endpoint,
        "egress_transport": authority.egress_transport,
        "release_id": authority.release_id,
        "release_manifest_sha256": authority.release_manifest_sha256,
        "release_ca_sha256": authority.release_ca_sha256,
        "authority_authentication_sha256": (
            authority.authority_authentication_sha256
        ),
        "executable_provenance": authority.executable_provenance,
        "runtime_closure_sha256": authority.runtime_closure_sha256,
        "cli_behavior_contract_sha256": (
            authority.cli_behavior_contract_sha256
        ),
        "install_generation_sha256": authority.install_generation_sha256,
        "latest_resolution_receipt_sha256": (
            authority.latest_resolution_receipt_sha256
        ),
        "publisher_identity_sha256": authority.publisher_identity_sha256,
        "provenance_receipt_sha256": authority.provenance_receipt_sha256,
    }
    if endpoint != authority.proxy_endpoint or any(
        request.get(key) != expected
        for key, expected in authority_bindings.items()
    ):
        _fail(
            "AUTHORITY_BINDING",
            "request differs from authenticated release/provider/egress authority",
        )
    for key in (
        "control_dir_fd", "project_dir_fd", "scratch_dir_fd", "prompt_fd",
        "credential_fd",
    ):
        _fd(request.get(key), key)
    codex_profile = _fd(
        request.get("codex_profile_fd"), "codex_profile_fd", nullable=True,
    )
    settings = _fd(request.get("claude_settings_fd"), "claude_settings_fd", nullable=True)
    mcp = _fd(request.get("claude_mcp_fd"), "claude_mcp_fd", nullable=True)
    if executable.backend == "claude" and (
        settings is None or mcp is None or codex_profile is not None
    ):
        _fail("CLAUDE_POLICY", "Claude needs sealed settings and MCP descriptors")
    if executable.backend == "codex" and (
        settings is not None or mcp is not None or codex_profile is None
    ):
        _fail("CODEX_POLICY", "Codex needs exactly one sealed profile descriptor")


def _environment(proxy: str, ca_bundle_fd: int, backend: str) -> dict[str, str]:
    ca_path = _fd_path(ca_bundle_fd)
    result = {
        "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1",
        "HOME": f"{PRIVATE_ROOT_PATH}/home",
        "HTTP_PROXY": proxy, "HTTPS_PROXY": proxy,
        "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
        "NODE_EXTRA_CA_CERTS": ca_path,
        "PATH": f"{GUEST_TOOLCHAIN_PATH}:/usr/local/bin:/usr/bin:/bin",
        "PYTHONNOUSERSITE": "1", "SSL_CERT_FILE": ca_path,
        "TMPDIR": PRIVATE_TMP_PATH, "TZ": "UTC",
    }
    if backend == "codex":
        result["CODEX_HOME"] = CODEX_HOME_PATH
    else:
        result.update({
            "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
            "CLAUDE_CODE_SUBPROCESS_ENV_SCRUB": "1",
            "CLAUDE_CONFIG_DIR": CLAUDE_CONFIG_PATH,
            "DISABLE_AUTOUPDATER": "1", "DISABLE_BUG_COMMAND": "1",
            "DISABLE_ERROR_REPORTING": "1", "DISABLE_TELEMETRY": "1",
        })
    return result


def _receipt(
    request: Mapping[str, Any], executable: _Executable,
    authority: _LaunchAuthority,
    argv: tuple[str, ...], environment: Mapping[str, str],
    protocol: Mapping[str, Any], directories: tuple[_Directory, ...],
    files: tuple[_File, ...],
    codex_config_absence: _CodexConfigAbsence | None,
) -> bytes:
    binding = {
        key: request[key] for key in (
            "attempt_id", "session_id", "backend", "platform", "model",
            "claude_tools", "config_sha256", "image_sha256",
            "codex_profile_sha256", "claude_settings_contract",
            "claude_settings_sha256", "claude_mcp_sha256",
            "codex_permission_profile_status", "credential_isolation_mode",
            "credential_isolation_sha256", "prompt_sha256",
            "credential_sha256", "codex_config_census_contract",
            "codex_config_census_contract_sha256",
            "codex_config_census_evidence_sha256",
            "provider_admission_sha256", "proxy_authority_sha256",
            "egress_admission_sha256", "egress_transport", "proxy_endpoint",
            "proxy_attempt_id", "proxy_scope", "backend_network",
            "tool_network", "cli_conformance_sha256", "ca_bundle_scope",
            "release_id", "release_manifest_sha256", "release_ca_sha256",
            "authority_authentication_sha256", "executable_provenance",
            "runtime_closure_sha256",
        )
    }
    private_scope_binding = {
        key: request[key] for key in (
            "attempt_id", "config_sha256", "image_sha256",
            "provider_admission_sha256",
        )
    }
    private_scope_binding["directories"] = [
        {
            "label": item.label, "path": item.path,
            "identity": list(item.signature),
            "path_chain": [list(identity) for identity in item.path_chain],
        }
        for item in directories
    ]
    private_scope_binding["files"] = [
        {"label": item.label, "identity": list(item.signature)}
        for item in files
    ]
    private_scope_binding["codex_control_config_absence"] = (
        None if codex_config_absence is None else {
            "control_path": codex_config_absence.control_path,
            "ancestors": [
                {
                    "identity": list(ancestor),
                    "dot_codex_identity": (
                        None if marker is None else list(marker)
                    ),
                }
                for ancestor, marker in codex_config_absence.ancestors
            ],
        }
    )
    if authority.authority_class != TEST_ONLY_AUTHORITY_CLASS:
        _fail(
            "TEST_ONLY_AUTHORITY",
            "Python receipt rendering is restricted to test-only authority",
        )
    receipt = {
        "schema": TEST_ONLY_PUBLIC_RECEIPT_SCHEMA,
        "attempt_id": request["attempt_id"], "backend": request["backend"],
        "model": request["model"], "executable_version": executable.version,
        "executable_sha256": executable.sha256,
        "cli_conformance_sha256": executable.cli_conformance_sha256,
        "authority_binding_sha256": _digest(binding),
        "private_scope_binding_sha256": _digest(private_scope_binding),
        "sealed_content_sha256": {
            item.label: item.sha256 for item in files
        },
        "sealed_policy": {
            "codex_profile_sha256": request["codex_profile_sha256"],
            "claude_settings_contract": request["claude_settings_contract"],
            "claude_settings_sha256": request["claude_settings_sha256"],
            "claude_mcp_sha256": request["claude_mcp_sha256"],
            "codex_permission_profile_status": (
                request["codex_permission_profile_status"]
            ),
            "credential_isolation_mode": request["credential_isolation_mode"],
            "credential_isolation_sha256": (
                request["credential_isolation_sha256"]
            ),
            "codex_config_census_contract": (
                request["codex_config_census_contract"]
            ),
            "codex_config_census_contract_sha256": (
                request["codex_config_census_contract_sha256"]
            ),
            "codex_config_census_evidence_sha256": (
                request["codex_config_census_evidence_sha256"]
            ),
        },
        "argv_shape_sha256": hashlib.sha256(
            b"\0".join(item.encode() for item in argv)
        ).hexdigest(),
        "environment_shape_sha256": _digest(dict(environment)),
        "fd_protocol_shape_sha256": _digest(protocol),
        "status": "TEST_ONLY_NOT_ISSUED_FOR_PRODUCTION",
        "completion_receipt_schema": TEST_ONLY_COMPLETION_RECEIPT_SCHEMA,
        "terminal_statuses": [
            "EXECUTED_AND_REVOKED", "FAILED_AND_REVOKED",
            "UNEXECUTED_AND_REVOKED",
        ],
        "completion_required": True,
        "live_cli_conformance_required": True,
    }
    receipt["authority_class"] = authority.authority_class
    return _canonical(receipt)


def render_backend_launch(
    executable_capability: BackendExecutableCapability,
    launch_authority_capability: BackendLaunchAuthorityCapability,
    request_bytes: bytes,
) -> BackendLaunchPlan:
    """Production hardstop until native authenticated consumption exists.

    No argument is inspected or consumed here.  In particular, Python module
    mutation cannot transplant a structural-test record into a production
    registry because no such registry or Python record-consumer exists.
    """

    _fail(
        "NATIVE_AUTHORITY_UNAVAILABLE",
        "native launch-authority verifier integration is not installed",
    )


def TEST_ONLY_render_backend_launch(
    executable_capability: BackendExecutableCapability,
    launch_authority_capability: TestOnlyBackendLaunchAuthorityCapability,
    request_bytes: bytes,
) -> TestOnlyBackendLaunchPlan:
    """Exercise structural policy with a non-production receipt/status."""

    return _render_backend_launch(
        executable_capability, launch_authority_capability, request_bytes,
    )


def _render_backend_launch(
    executable_capability: BackendExecutableCapability,
    launch_authority_capability: TestOnlyBackendLaunchAuthorityCapability,
    request_bytes: bytes,
) -> TestOnlyBackendLaunchPlan:
    """Consume structural-test authorities and render a non-production plan."""

    executable = _consume_executable(executable_capability)
    try:
        authority = _consume_test_only_authority(launch_authority_capability)
    except BaseException:
        _close_file(executable.file)
        raise
    files: list[_File] = [executable.file, authority.ca_bundle]
    directories: list[_Directory] = []
    issued = False
    try:
        # Consume before parsing: every render attempt is terminal for the
        # capability, including adversarial malformed requests.
        request = parse_launch_request(request_bytes)
        _validate(request, executable, authority)
        control = _directory(
            int(request["control_dir_fd"]), request["control_path"], "control",
        )
        directories.append(control)
        project = _directory(
            int(request["project_dir_fd"]), request["project_path"], "project",
        )
        directories.append(project)
        scratch = _directory(
            int(request["scratch_dir_fd"]), request["scratch_path"], "scratch",
        )
        directories.append(scratch)
        if len({item.signature[:2] for item in directories}) != 3:
            _fail("DIRECTORY_ALIAS", "control, project, and scratch must be distinct")
        if _overlap(control.path, project.path) or _overlap(control.path, scratch.path):
            _fail("CONTROL_TARGET_OVERLAP", "trusted control cwd overlaps untrusted state")

        prompt = _file(
            int(request["prompt_fd"]), "prompt", MAX_PROMPT_BYTES, private=True,
            fresh_zero_offset=True,
        )
        files.append(prompt)
        credential = _file(
            int(request["credential_fd"]), "credential", MAX_CREDENTIAL_BYTES,
            private=True,
        )
        files.append(credential)
        ca = authority.ca_bundle

        backend = executable.backend
        executable_path = _fd_path(executable.file.fd)
        control_path = _fd_path(control.fd)
        project_path = _fd_path(project.fd)
        scratch_path = _fd_path(scratch.fd)
        environment = _environment(str(request["proxy_endpoint"]), ca.fd, backend)
        codex_profile: _File | None = None
        codex_config_absence: _CodexConfigAbsence | None = None
        codex_config_census_bytes: bytes | None = None
        settings: _File | None = None
        mcp: _File | None = None
        if backend == "codex":
            codex_config_absence = _codex_control_config_absence(control.path)
            codex_config_census_bytes = required_codex_config_census_bytes(request)
            codex_profile = _file(
                int(request["codex_profile_fd"]), "Codex profile",
                MAX_POLICY_BYTES, private=True,
            )
            files.append(codex_profile)
            if codex_profile.sha256 != request["codex_profile_sha256"]:
                _fail("CODEX_PROFILE", "sealed Codex profile digest drifted")
            expected_profile = required_codex_profile_bytes(request)
            if _read(
                codex_profile.fd, codex_profile.signature[6], codex_profile.label,
            ) != expected_profile:
                _fail("CODEX_PROFILE", "sealed Codex profile is not request-exact")
            argv = (
                executable_path, "--ask-for-approval", "never", "exec",
                "--model", str(request["model"]),
                "--json", "--strict-config", "--ephemeral",
                "--ignore-rules",
                "--profile", CODEX_PROFILE_NAME,
                "--cd", control_path,
                "--add-dir", project_path, "--add-dir", scratch_path,
                "-c", "features.network_proxy=false",
                "-c", 'web_search="disabled"',
                "-c", "mcp_servers={}",
                "-c", "features.plugins=false",
                "-c", "features.remote_plugin=false",
                "-c", "features.hooks=false",
                "-c", "features.multi_agent=false",
                "-c", "features.memories=false",
                "-c", "features.goals=false",
                "-c", "features.skill_mcp_dependency_install=false",
                "-c", "feedback.enabled=false",
                "-c", 'history.persistence="none"',
                "-",
            )
            _validate_codex_config_loader_argv(argv)
            delivery = (
                "SUPERVISOR_MATERIALIZE_EXACT_PRIVATE_CODEX_HOME_CENSUS_"
                "THEN_CLOSE"
            )
            profile_delivery = (
                "SUPERVISOR_MATERIALIZE_EXACT_PROFILE_IN_PRIVATE_CODEX_HOME_"
                "THEN_CENSUS"
            )
        else:
            settings = _file(
                int(request["claude_settings_fd"]), "Claude settings",
                MAX_POLICY_BYTES, private=True,
            )
            files.append(settings)
            mcp = _file(
                int(request["claude_mcp_fd"]), "Claude MCP config",
                MAX_POLICY_BYTES, private=True,
            )
            files.append(mcp)
            if (
                settings.sha256 != request["claude_settings_sha256"]
                or mcp.sha256 != request["claude_mcp_sha256"]
            ):
                _fail("CLAUDE_SETTINGS", "sealed native-sandbox policy digest drifted")
            if _read(
                settings.fd, settings.signature[6], settings.label,
            ) != required_claude_settings_bytes(request):
                _fail("CLAUDE_SETTINGS", "sealed settings are not policy-exact")
            if _read(mcp.fd, mcp.signature[6], mcp.label) != required_claude_mcp_bytes():
                _fail("CLAUDE_MCP", "sealed MCP config is not the empty denominator")
            allowed = ",".join(str(item) for item in request["claude_tools"])
            argv = (
                executable_path, "-p", "--model", str(request["model"]),
                "--input-format", "text", "--output-format", "stream-json",
                "--verbose", "--session-id", str(request["session_id"]),
                "--no-session-persistence", "--bare", "--restricted",
                "--permission-mode", "dontAsk",
                "--tools", allowed, "--setting-sources=",
                "--settings", _fd_path(settings.fd),
                "--strict-mcp-config", "--mcp-config", _fd_path(mcp.fd),
                "--add-dir", project_path, "--add-dir", scratch_path,
                "--no-chrome", "--disable-slash-commands",
                "--prompt-suggestions", "false",
            )
            delivery = CLAUDE_CREDENTIAL_DELIVERY
            profile_delivery = "NONE"

        if len({item.signature[:2] for item in files}) != len(files):
            _fail("FILE_ALIAS", "launch file roles must have distinct identities")
        if (
            prompt.sha256 != request["prompt_sha256"]
            or credential.sha256 != request["credential_sha256"]
        ):
            _fail(
                "SEALED_CONTENT_DIGEST",
                "prompt or credential differs from authenticated authority",
            )
        pass_fds = tuple(sorted({
            executable.file.fd, control.fd, project.fd, scratch.fd, prompt.fd, ca.fd,
            *(() if settings is None else (settings.fd,)),
            *(() if mcp is None else (mcp.fd,)),
        }))
        protocol = {
            "schema": "plamen.posix_backend_fd_protocol.v3",
            "stdin": "SEALED_BOUNDED_PROMPT_FD",
            "executable": "PINNED_RETAINED_FD",
            "directories": "RETAINED_FD_PATHS",
            "policy": (
                "SEALED_REQUEST_BOUND_CODEX_PROFILE"
                if backend == "codex" else "SEALED_SETTINGS_AND_MCP_FDS"
            ),
            "codex_profile_sha256": (
                None if codex_profile is None else codex_profile.sha256
            ),
            "claude_settings_contract": request["claude_settings_contract"],
            "claude_settings_sha256": (
                None if settings is None else settings.sha256
            ),
            "claude_mcp_sha256": None if mcp is None else mcp.sha256,
            "codex_profile_materialization": (
                CODEX_PROFILE_MATERIALIZATION_PATH
                if backend == "codex" else None
            ),
            "codex_auth_materialization": (
                CODEX_AUTH_MATERIALIZATION_PATH if backend == "codex" else None
            ),
            "codex_config_census_contract": (
                request["codex_config_census_contract"]
            ),
            "codex_config_census_contract_sha256": (
                request["codex_config_census_contract_sha256"]
            ),
            "codex_config_census_evidence_sha256": (
                request["codex_config_census_evidence_sha256"]
            ),
            "codex_config_loader": (
                "NAMED_PROFILE_WITH_BASE_AND_CONTROL_PROJECT_CONFIG_ABSENT"
                if backend == "codex" else None
            ),
            "credential": delivery, "credential_inherited_by_backend": False,
            "public_ca_bundle": "SEALED_RETAINED_FD",
            "public_ca_bundle_sha256": ca.sha256,
            "authority": "AUTHENTICATED_ONE_SHOT_RELEASE_PROVIDER_EGRESS_CAPABILITY",
            "authority_authentication_sha256": (
                authority.authority_authentication_sha256
            ),
            "egress_scope": EGRESS_SCOPE,
            "egress_transport": request["egress_transport"],
            "command_network": "DENY",
            "cli_conformance": "INDEPENDENT_DIGEST_BOUND",
            "codex_permission_profile_status": (
                request["codex_permission_profile_status"]
            ),
            "credential_isolation": "AUTHENTICATED_OUTER_HARDSTOP",
            "credential_isolation_sha256": (
                request["credential_isolation_sha256"]
            ),
        }
        receipt = _receipt(
            request, executable, authority, argv, environment, protocol,
            tuple(directories), tuple(files), codex_config_absence,
        )
        token = os.urandom(32).hex()
        record = _Plan(
            request=MappingProxyType(copy.deepcopy(request)),
            authority_class=authority.authority_class,
            executable=executable, directories=tuple(directories),
            files=tuple(files), argv=argv,
            environment=MappingProxyType(environment),
            stdin_fd=prompt.fd, pass_fds=pass_fds,
            credential_fd=credential.fd, credential_delivery=delivery,
            codex_profile_fd=(
                None if codex_profile is None else codex_profile.fd
            ),
            codex_profile_delivery=profile_delivery,
            codex_config_absence=codex_config_absence,
            codex_config_census_bytes=codex_config_census_bytes,
            receipt=receipt, token=token,
        )
        plan = object.__new__(TestOnlyBackendLaunchPlan)
        object.__setattr__(plan, "_TestOnlyBackendLaunchPlan__token", token)
        identity = id(plan)
        reference = weakref.ref(
            plan, lambda _unused, key=identity: _drop_test_only_plan(key),
        )
        with _LOCK:
            _TEST_ONLY_PLANS[identity] = (reference, record)
        issued = True
        return plan
    finally:
        if not issued:
            for item in directories:
                try:
                    os.close(item.fd)
                except OSError:
                    pass
            for item in files:
                _close_file(item)


def _require_test_only_plan_record(record: _Plan) -> None:
    if record.authority_class != TEST_ONLY_AUTHORITY_CLASS:
        _fail("TEST_ONLY_PLAN", "test-only plan authority class drifted")
    receipt = _validate_receipt(record.receipt, record.receipt)
    if (
        receipt.get("schema") != TEST_ONLY_PUBLIC_RECEIPT_SCHEMA
        or receipt.get("authority_class") != TEST_ONLY_AUTHORITY_CLASS
        or receipt.get("status") != "TEST_ONLY_NOT_ISSUED_FOR_PRODUCTION"
        or receipt.get("completion_receipt_schema")
        != TEST_ONLY_COMPLETION_RECEIPT_SCHEMA
    ):
        _fail("TEST_ONLY_PLAN", "test-only plan receipt markers drifted")


def _peek_test_only_plan(value: TestOnlyBackendLaunchPlan) -> _Plan:
    if type(value) is not TestOnlyBackendLaunchPlan:
        _fail("TEST_ONLY_PLAN", "test-only launch plan type is invalid")
    with _LOCK:
        item = _TEST_ONLY_PLANS.get(id(value))
    if item is None or item[0]() is not value:
        _fail("TEST_ONLY_PLAN", "test-only launch plan is forged or closed")
    record = item[1]
    incomplete = False
    try:
        token = object.__getattribute__(
            value, "_TestOnlyBackendLaunchPlan__token",
        )
    except AttributeError:
        incomplete = True
        token = ""
    if incomplete:
        _fail("TEST_ONLY_PLAN", "test-only launch plan is incomplete")
    if token != record.token:
        _fail("TEST_ONLY_PLAN", "test-only launch plan token drifted")
    _require_test_only_plan_record(record)
    return record


def _validate_receipt(raw: bytes, expected: bytes) -> Mapping[str, Any]:
    if type(raw) is not bytes or raw != expected:
        _fail("RECEIPT_FORGED", "public receipt is not issuance-exact")
    failed = False
    try:
        value = json.loads(raw.decode("ascii"), object_pairs_hook=_pairs)
    except PosixBackendLaunchPolicyError:
        raise
    except (
        UnicodeError, json.JSONDecodeError, ValueError, RecursionError,
        OverflowError,
    ):
        failed = True
        value = None
    if failed:
        _fail("RECEIPT_JSON", "public receipt is malformed")
    if type(value) is not dict or _canonical(value) != raw:
        _fail("RECEIPT_CANONICAL", "public receipt is not canonical")
    return MappingProxyType(value)


def _consume_test_only_plan(
    value: TestOnlyBackendLaunchPlan,
) -> TestOnlyBackendLaunchInvocation:
    record = _peek_test_only_plan(value)
    with _LOCK:
        item = _TEST_ONLY_PLANS.pop(id(value), None)
    if item is None or item[0]() is not value or item[1] is not record:
        _fail("TEST_ONLY_PLAN", "test-only plan was concurrently consumed")
    try:
        for directory in record.directories:
            _replay_directory(directory)
        if record.codex_config_absence is not None:
            _replay_codex_control_config_absence(record.codex_config_absence)
        for captured in record.files:
            _replay_file(captured)
    except BaseException:
        _close_plan_record(record)
        raise
    invocation = object.__new__(TestOnlyBackendLaunchInvocation)
    object.__setattr__(
        invocation, "_TestOnlyBackendLaunchInvocation__token", record.token,
    )
    identity = id(invocation)
    reference = weakref.ref(
        invocation,
        lambda _unused, key=identity: _drop_test_only_invocation(key),
    )
    with _LOCK:
        _TEST_ONLY_INVOCATIONS[identity] = (reference, record)
    return invocation


def _test_only_invocation_record(
    value: TestOnlyBackendLaunchInvocation,
) -> _Plan:
    if type(value) is not TestOnlyBackendLaunchInvocation:
        _fail("TEST_ONLY_INVOCATION", "test-only invocation type is invalid")
    with _LOCK:
        item = _TEST_ONLY_INVOCATIONS.get(id(value))
    if item is None or item[0]() is not value:
        _fail(
            "TEST_ONLY_INVOCATION",
            "test-only invocation is forged, completed, or revoked",
        )
    record = item[1]
    incomplete = False
    try:
        token = object.__getattribute__(
            value, "_TestOnlyBackendLaunchInvocation__token",
        )
    except AttributeError:
        incomplete = True
        token = ""
    if incomplete or token != record.token:
        _fail("TEST_ONLY_INVOCATION", "test-only invocation is incomplete or drifted")
    _require_test_only_plan_record(record)
    return record


def _complete_test_only_invocation(
    value: TestOnlyBackendLaunchInvocation, status: str,
    completion_evidence_sha256: str | None,
) -> bytes:
    record = _test_only_invocation_record(value)
    with _LOCK:
        item = _TEST_ONLY_INVOCATIONS.pop(id(value), None)
    if item is None or item[0]() is not value or item[1] is not record:
        _fail("TEST_ONLY_INVOCATION", "invocation was concurrently completed")
    try:
        if status not in {
            "EXECUTED_AND_REVOKED", "FAILED_AND_REVOKED",
            "UNEXECUTED_AND_REVOKED",
        }:
            _fail("COMPLETION_STATUS", "completion status is not terminal")
        if status == "UNEXECUTED_AND_REVOKED":
            if completion_evidence_sha256 is not None:
                _fail("COMPLETION_EVIDENCE", "revocation cannot carry execution evidence")
        elif (
            type(completion_evidence_sha256) is not str
            or _HEX_RE.fullmatch(completion_evidence_sha256) is None
        ):
            _fail("COMPLETION_EVIDENCE", "execution completion evidence is malformed")
        if record.authority_class != TEST_ONLY_AUTHORITY_CLASS:
            _fail(
                "TEST_ONLY_AUTHORITY",
                "Python completion rendering is restricted to test-only authority",
            )
        completion = {
            "schema": TEST_ONLY_COMPLETION_RECEIPT_SCHEMA,
            "attempt_id": record.request["attempt_id"],
            "backend": record.request["backend"],
            "model": record.request["model"],
            "issuance_receipt_sha256": hashlib.sha256(record.receipt).hexdigest(),
            "sealed_content_sha256": json.loads(record.receipt.decode("ascii"))[
                "sealed_content_sha256"
            ],
            "status": status,
            "completion_evidence_sha256": completion_evidence_sha256,
            "fd_state": "TERMINALLY_REVOKED",
        }
        completion["authority_class"] = record.authority_class
        return _canonical(completion)
    finally:
        _close_plan_record(record)


__all__ = (
    "APPLE_EGRESS_TRANSPORT",
    "BACKEND_MODEL_ROUTE_SCHEMA", "BACKEND_PARITY_ACCEPTANCE_SCHEMA",
    "BACKEND_CLI_BEHAVIOR_SCHEMA",
    "INSTALL_GENERATION_RECEIPT_SCHEMA",
    "INSTALL_GENERATION_AUTHORITY_CLASS",
    "TEST_ONLY_INSTALL_GENERATION_AUTHORITY_CLASS",
    "BackendInstallGenerationAuthority", "BackendInstallGenerationProjection",
    "TestOnlyBackendInstallGenerationAuthority",
    "BackendExecutableCapability", "BackendLaunchAuthorityCapability",
    "BackendLaunchInvocation", "BackendLaunchPlan", "CA_BUNDLE_SCOPE",
    "NativeLaunchAuthorityCapability",
    "TestOnlyBackendLaunchAuthorityCapability",
    "TestOnlyBackendLaunchInvocation", "TestOnlyBackendLaunchPlan",
    "CLAUDE_CONFIG_PATH", "CLAUDE_CREDENTIAL_DELIVERY",
    "CLAUDE_CREDENTIAL_MATERIALIZATION_PATH",
    "CLAUDE_EXECUTABLE_PROVENANCE", "CLAUDE_SETTINGS_CONTRACT",
    "CODEX_EXECUTABLE_PROVENANCE",
    "CODEX_AUTH_MATERIALIZATION_PATH", "CODEX_CONFIG_CENSUS_CONTRACT",
    "CODEX_HOME_PATH",
    "CODEX_PERMISSION_PROFILE_NOT_APPLICABLE",
    "CODEX_PERMISSION_PROFILE_STATUS", "CREDENTIAL_ISOLATION_MODES",
    "COMPLETION_RECEIPT_SCHEMA", "PRODUCTION_AUTHORITY_CLASS",
    "TEST_ONLY_AUTHORITY_CLASS", "TEST_ONLY_COMPLETION_RECEIPT_SCHEMA",
    "TEST_ONLY_PUBLIC_RECEIPT_SCHEMA",
    "CODEX_CREDENTIAL_GLOB_SCAN_DEPTH", "CODEX_PROFILE_MATERIALIZATION_PATH",
    "CODEX_PROFILE_NAME", "EGRESS_SCOPE", "GUEST_TOOLCHAIN_PATH",
    "LINUX_EGRESS_TRANSPORT", "PRIVATE_ROOT_PATH", "PRIVATE_TMP_PATH",
    "MAX_CA_BYTES", "MAX_CREDENTIAL_BYTES", "MAX_EXECUTABLE_BYTES",
    "MAX_POLICY_BYTES", "MAX_PROMPT_BYTES", "MAX_REQUEST_BYTES",
    "PUBLIC_RECEIPT_SCHEMA", "PosixBackendLaunchPolicyError",
    "REQUEST_SCHEMA", "STDERR_LIMIT_BYTES", "STDOUT_LIMIT_BYTES",
    "backend_parity_acceptance_matrix", "canonical_request_bytes",
    "backend_cli_behavior_contract", "backend_cli_behavior_contract_sha256",
    "issue_backend_executable",
    "require_backend_install_generation",
    "TEST_ONLY_issue_backend_install_generation",
    "TEST_ONLY_project_backend_install_generation",
    "issue_backend_launch_authority",
    "TEST_ONLY_issue_backend_launch_authority",
    "TEST_ONLY_render_backend_launch",
    "parse_launch_request", "render_backend_launch",
    "required_codex_config_census_bytes", "required_codex_profile_bytes",
    "required_claude_mcp_bytes", "required_claude_settings_bytes",
    "replay_backend_model_route", "resolve_backend_model_route",
)
