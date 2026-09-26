"""Provider-specific Claude plan for the explicit POSIX compatibility lane.

This module does not supervise a process and does not mint native containment
authority.  It compiles and replays the exact Claude CLI/provider boundary
consumed by :mod:`posix_v2_compat_runtime`, whose receipts truthfully retain
``V2_COMPATIBILITY_REDUCED_ISOLATION``.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import subprocess
import threading
from types import MappingProxyType
from typing import Any, Mapping, NoReturn, Sequence
import uuid

from claude_phase_tool_policy import (
    load_policy,
    provider_builtin_tools,
    validate_settings_overlay,
)
from claude_stream_json_evidence import (
    ClaudeStreamJsonEvidenceError,
    _validate_claude_stream_json_from_authenticated_posix_v2_compat_plan,
)
from phase_io_contracts import (
    LaunchSpec,
    PhaseIOContract,
    replay_phase_io_authority_pair,
)


AUTH_SCHEMA = "plamen.posix-v2-compat-claude-auth-observation.v1"
PLAN_SCHEMA = "plamen.posix-v2-compat-claude-plan.v1"
COMPLETION_SCHEMA = "plamen.posix-v2-compat-claude-completion.v1"
COMPATIBILITY_MODE = "V2_COMPATIBILITY_REDUCED_ISOLATION"
AUTH_MODE = "CLAUDE_NATIVE_STORED_SUBSCRIPTION"
PROFILE = "CLAUDE_RESTRICTED_PHASE_HOOKS_STREAM_JSON_V1"
TERMINAL_GRAMMAR = (
    "FINAL_ROOT_ASSISTANT_END_TURN_OR_CAPABILITY_BOUND_TEXT_NULL_"
    "AND_RESULT_COMPLETED_V1"
)
_SHA_RE = re.compile(r"[0-9a-f]{64}")
_VERSION_RE = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+")
_SAFE_ENV = frozenset({
    "CLAUDE_CODE_DISABLE_AUTO_MEMORY", "CLAUDE_CODE_TMPDIR", "HOME", "LANG",
    "LC_ALL", "NO_COLOR", "PATH", "SHELL", "TERM", "TMPDIR", "USER",
})
_AUTH_FORBIDDEN_ENV_PREFIXES = (
    "ANTHROPIC_", "AWS_", "AZURE_", "GOOGLE_", "VERTEX_",
)
_AUTH_FORBIDDEN_ENV_NAMES = frozenset({
    "CLAUDE_CODE_OAUTH_TOKEN", "CLAUDE_CONFIG_DIR",
})
_FORBIDDEN_TOOLS = frozenset({
    "Agent", "Bash", "NotebookEdit", "PowerShell", "Task",
})
_ALLOWED_LOCAL_AGENTS = frozenset({
    "claude", "Explore", "general-purpose", "Plan", "statusline-setup",
})
_ALLOWED_NATIVE_CAPABILITIES = frozenset({
    "interrupt_receipt_v1", "interrupt_cancel_queued_v1", "msg_lifecycle_v1",
})
_ALLOWED_AUXILIARY_USAGE_MODELS = frozenset({"claude-haiku-4-5-20251001"})
_MAX_AUTH_OUTPUT = 64 * 1024
_MAX_PROMPT = 16 * 1024 * 1024


class PosixV2CompatClaudeError(RuntimeError):
    """A Claude compatibility admission or evidence check failed closed."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _fail(code: str, message: str, cause: BaseException | None = None) -> NoReturn:
    error = PosixV2CompatClaudeError(code, message)
    if cause is None:
        raise error
    raise error from cause


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(
            value, ensure_ascii=True, allow_nan=False, sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    except (TypeError, ValueError) as exc:
        _fail("CANONICAL_JSON_INVALID", "value is not canonical JSON", exc)


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _digest_mapping(value: Mapping[str, Any]) -> str:
    return _sha(_canonical(dict(value)))


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def _decode_object(raw: bytes, *, label: str) -> dict[str, Any]:
    try:
        value = json.loads(
            raw.decode("utf-8", errors="strict"), object_pairs_hook=_pairs,
        )
    except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
        _fail("JSON_INVALID", f"{label} is not strict JSON", exc)
    if not isinstance(value, dict):
        _fail("JSON_INVALID", f"{label} must be one JSON object")
    return value


def _safe_file(path: Path, *, label: str, maximum: int = 4 * 1024 * 1024) -> bytes:
    target = Path(path)
    try:
        observed = target.lstat()
    except OSError as exc:
        _fail("BOUNDARY_FILE_INVALID", f"{label} is unavailable", exc)
    if (
        not stat.S_ISREG(observed.st_mode)
        or observed.st_nlink != 1
        or observed.st_uid != os.getuid()
        or observed.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        or target.is_symlink()
        or observed.st_size > maximum
    ):
        _fail("BOUNDARY_FILE_INVALID", f"{label} is not a retained private file")
    try:
        raw = target.read_bytes()
        after = target.lstat()
    except OSError as exc:
        _fail("BOUNDARY_FILE_INVALID", f"{label} cannot be read", exc)
    if (observed.st_dev, observed.st_ino, observed.st_size) != (
        after.st_dev, after.st_ino, after.st_size
    ):
        _fail("BOUNDARY_FILE_INVALID", f"{label} changed while read")
    return raw


def _auth_environment(source: Mapping[str, str]) -> dict[str, str]:
    if not isinstance(source, Mapping):
        _fail("AUTH_ENVIRONMENT_INVALID", "auth environment must be a mapping")
    result: dict[str, str] = {}
    for name in _SAFE_ENV:
        value = source.get(name)
        if value is not None:
            if type(value) is not str or "\x00" in value:
                _fail("AUTH_ENVIRONMENT_INVALID", f"invalid {name} value")
            result[name] = value
    # Claude's default subscription discovery must choose its own native
    # config/Keychain route.  In particular, setting CLAUDE_CONFIG_DIR to the
    # default ~/.claude path changes current CLI authentication behavior.
    for name in source:
        if name in _AUTH_FORBIDDEN_ENV_NAMES or name.startswith(
            _AUTH_FORBIDDEN_ENV_PREFIXES
        ):
            continue
    return result


@dataclass(frozen=True, slots=True)
class PosixV2CompatClaudeAuth:
    logged_in: bool
    auth_mode: str
    api_provider: str
    config_discovery: str
    auth_binding_sha256: str


def check_claude_native_auth(
    *,
    executable: str | Path,
    source_environment: Mapping[str, str],
    config_root: str | Path | None = None,
    timeout_seconds: float = 10.0,
) -> PosixV2CompatClaudeAuth:
    """Observe native first-party subscription status without reading secrets."""

    if os.name == "nt":
        _fail("PLATFORM_UNSUPPORTED", "POSIX Claude compatibility is unavailable on Windows")
    binary = Path(executable).resolve(strict=True)
    if not binary.is_file() or binary.is_symlink():
        _fail("AUTH_EXECUTABLE_INVALID", "Claude executable is not a regular file")
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or not 0 < float(timeout_seconds) <= 30
    ):
        _fail("AUTH_TIMEOUT_INVALID", "auth timeout must be within (0, 30]")
    environment = _auth_environment(source_environment)
    discovery = "NATIVE_DEFAULT_CONFIG_AND_KEYCHAIN"
    if config_root is not None:
        root = Path(config_root).resolve(strict=True)
        observed = root.stat()
        if (
            not root.is_dir()
            or root.is_symlink()
            or observed.st_uid != os.getuid()
            or observed.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        ):
            _fail("AUTH_CONFIG_ROOT_INVALID", "explicit Claude config root is unsafe")
        environment["CLAUDE_CONFIG_DIR"] = os.fspath(root)
        discovery = "EXPLICIT_CALLER_CONFIG_ROOT"
    try:
        result = subprocess.run(
            [os.fspath(binary), "auth", "status", "--json"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=float(timeout_seconds),
            start_new_session=True,
            env=environment,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        _fail("CLAUDE_NATIVE_AUTH_PROBE_FAILED", "Claude auth status probe failed", exc)
    if len(result.stdout) > _MAX_AUTH_OUTPUT or len(result.stderr) > _MAX_AUTH_OUTPUT:
        _fail("CLAUDE_NATIVE_AUTH_PROBE_FAILED", "Claude auth status output exceeded bound")
    payload = _decode_object(result.stdout, label="Claude auth status")
    logged_in = payload.get("loggedIn") is True
    method = payload.get("authMethod")
    provider = payload.get("apiProvider")
    if result.returncode != 0 or not logged_in:
        _fail(
            "CLAUDE_NATIVE_AUTH_UNAVAILABLE",
            "Claude native subscription is not available; run `claude /login` outside Plamen",
        )
    if method != "claude.ai" or provider != "firstParty":
        _fail(
            "CLAUDE_NATIVE_AUTH_MODE_REJECTED",
            "Claude auth is not the admitted first-party subscription route",
        )
    core = {
        "schema": AUTH_SCHEMA,
        "logged_in": True,
        "auth_mode": AUTH_MODE,
        "api_provider": "firstParty",
        "config_discovery": discovery,
        "executable_path": os.fspath(binary),
    }
    return PosixV2CompatClaudeAuth(
        logged_in=True,
        auth_mode=AUTH_MODE,
        api_provider="firstParty",
        config_discovery=discovery,
        auth_binding_sha256=_digest_mapping(core),
    )


_PLAN_TOKEN = object()
_PLAN_LOCK = threading.Lock()
_PLAN_RECORDS: dict[int, bytes] = {}


class PosixV2CompatClaudePlan:
    """Opaque, process-local one-invocation Claude plan authority."""

    __slots__ = ("_key",)

    def __init__(self, token: object, key: int) -> None:
        if token is not _PLAN_TOKEN:
            raise TypeError("PosixV2CompatClaudePlan cannot be constructed")
        self._key = key

    def __copy__(self) -> NoReturn:
        raise TypeError("Claude plan cannot be copied")

    def __deepcopy__(self, memo: object) -> NoReturn:
        raise TypeError("Claude plan cannot be copied")

    def __reduce__(self) -> NoReturn:
        raise TypeError("Claude plan cannot be serialized")


def _record_for(plan: PosixV2CompatClaudePlan) -> dict[str, Any]:
    if type(plan) is not PosixV2CompatClaudePlan:
        _fail("CLAUDE_PLAN_INVALID", "Claude plan authority type was substituted")
    with _PLAN_LOCK:
        raw = _PLAN_RECORDS.get(plan._key)
    if raw is None:
        _fail("CLAUDE_PLAN_INVALID", "Claude plan authority is unknown")
    return _decode_object(raw, label="retained Claude plan")


def _exact_boundary(
    phase_tool_boundary: Mapping[str, Any],
    *,
    contract: PhaseIOContract,
    cwd: Path,
    output_routes: Sequence[Mapping[str, Any]],
) -> tuple[dict[str, Any], Path, Path, tuple[str, ...]]:
    if not isinstance(phase_tool_boundary, Mapping):
        _fail("CLAUDE_TOOL_BOUNDARY_INVALID", "phase tool boundary is required")
    boundary = dict(phase_tool_boundary)
    required = {
        "phase", "attempt", "contract_key", "contract_digest",
        "input_set_digest", "manifest_digest", "policy_path", "settings_path",
        "mcp_config_path", "receipt_directory", "write_namespace",
    }
    if set(boundary) != required:
        _fail("CLAUDE_TOOL_BOUNDARY_INVALID", "phase tool boundary field denominator changed")
    if (
        boundary["phase"] != contract.phase
        or boundary["contract_key"] != contract.key
        or boundary["contract_digest"] != contract.digest
    ):
        _fail("CLAUDE_TOOL_BOUNDARY_INVALID", "phase tool boundary contract changed")
    policy_path = Path(str(boundary["policy_path"])).resolve(strict=True)
    settings_path = Path(str(boundary["settings_path"])).resolve(strict=True)
    mcp_path = Path(str(boundary["mcp_config_path"])).resolve(strict=True)
    policy = load_policy(policy_path)
    if (
        policy["manifest_digest"] != boundary["manifest_digest"]
        or policy["expected_cwd"] != os.fspath(cwd)
        or policy["backend"] != "claude"
    ):
        _fail("CLAUDE_TOOL_BOUNDARY_INVALID", "phase policy binding changed")
    settings_raw = _safe_file(settings_path, label="Claude settings")
    settings = _decode_object(settings_raw, label="Claude settings")
    validate_settings_overlay(
        settings,
        restricted_analysis=True,
        bounded_web=policy["external_network_policy"] == "BOUNDED_RECEIPTS",
    )
    mcp = _decode_object(_safe_file(mcp_path, label="Claude MCP config"), label="Claude MCP config")
    if mcp != {"mcpServers": {}}:
        _fail("CLAUDE_TOOL_BOUNDARY_INVALID", "Claude MCP config is not exactly empty")
    route_paths: list[str] = []
    for route in output_routes:
        if not isinstance(route, Mapping) or type(route.get("path")) is not str:
            _fail("CLAUDE_TOOL_BOUNDARY_INVALID", "output route is malformed")
        route_paths.append(os.fspath(Path(str(route["path"])).absolute()))
    if len(route_paths) != len(set(route_paths)) or not route_paths:
        _fail("CLAUDE_TOOL_BOUNDARY_INVALID", "output routes are not a unique nonempty set")
    if sorted(policy["exact_write_files"]) != sorted(route_paths):
        _fail(
            "CLAUDE_TOOL_BOUNDARY_OUTPUT_MISMATCH",
            "hook policy write namespace differs from live staged output routes",
        )
    tools = provider_builtin_tools(policy)
    if not tools or _FORBIDDEN_TOOLS & set(tools) or any(tool.startswith("mcp__") for tool in tools):
        _fail("CLAUDE_TOOL_BOUNDARY_INVALID", "Claude tool denominator is unsafe")
    return policy, settings_path, mcp_path, tools


def compile_posix_v2_compat_claude_plan(
    *,
    session_binding: Mapping[str, Any],
    phase_io_contract: PhaseIOContract,
    phase_io_launch: LaunchSpec,
    executable_observation: Mapping[str, Any],
    provider_session_id: str,
    prompt_bytes: bytes,
    cwd: str | Path,
    output_routes: Sequence[Mapping[str, Any]],
    phase_tool_boundary: Mapping[str, Any],
    source_config_root: str | Path,
    environment: Mapping[str, str],
    max_stdout_bytes: int,
    max_stderr_bytes: int,
    max_line_bytes: int,
    expected_version: str | None = None,
) -> PosixV2CompatClaudePlan:
    """Compile one exact reduced-isolation Claude invocation plan."""

    if os.name == "nt":
        _fail("PLATFORM_UNSUPPORTED", "POSIX Claude compatibility is unavailable on Windows")
    contract, launch = replay_phase_io_authority_pair(phase_io_contract, phase_io_launch)
    if contract.backend != "claude" or launch.backend != "claude" or contract.key != launch.work_unit_key:
        _fail("PHASE_IO_INVALID", "Claude PhaseIO authority pair is inconsistent")
    session = dict(session_binding)
    session_fields = {
        "schema", "mode", "run_id", "backend", "project_root",
        "project_root_identity_sha256", "scratchpad",
        "scratchpad_identity_sha256", "creator_pid",
        "interpreter_nonce_sha256", "native_broker_authority",
        "wer_authority", "session_binding_sha256",
    }
    unsigned_session = dict(session)
    session_digest = unsigned_session.pop("session_binding_sha256", None)
    if (
        set(session) != session_fields
        or session.get("schema") != "plamen.posix_v2_compat_session.v1"
        or session_digest != _digest_mapping(unsigned_session)
        or session.get("backend") != "claude"
        or session.get("mode") != COMPATIBILITY_MODE
        or session.get("creator_pid") != os.getpid()
    ):
        _fail("SESSION_INVALID", "Claude session is not explicit reduced isolation")
    if session.get("native_broker_authority") is not False or session.get("wer_authority") is not False:
        _fail("SESSION_INVALID", "compatibility session falsely claims stronger authority")
    try:
        provider_uuid = str(uuid.UUID(provider_session_id))
    except (ValueError, AttributeError) as exc:
        _fail("SESSION_INVALID", "provider session ID is not a UUID", exc)
    if type(prompt_bytes) is not bytes or not 0 < len(prompt_bytes) <= _MAX_PROMPT:
        _fail("PROMPT_INVALID", "provider prompt is empty or exceeds bound")
    working = Path(cwd).resolve(strict=True)
    observation = dict(executable_observation)
    expected_observation_fields = {
        "schema", "backend", "resolved_executable", "version",
        "version_output_sha256", "help_sha256", "help_byte_count",
        "supported_flags", "executable_sha256", "executable_byte_count",
        "identity", "observation_sha256",
    }
    if set(observation) != expected_observation_fields or observation.get("backend") != "claude":
        _fail("EXECUTABLE_OBSERVATION_INVALID", "Claude executable observation is malformed")
    unsigned_observation = dict(observation)
    observed_digest = unsigned_observation.pop("observation_sha256", None)
    if observed_digest != _digest_mapping(unsigned_observation):
        _fail("EXECUTABLE_OBSERVATION_INVALID", "Claude executable observation digest changed")
    version = observation.get("version")
    if type(version) is not str or not _VERSION_RE.fullmatch(version):
        _fail("EXECUTABLE_OBSERVATION_INVALID", "Claude version is malformed")
    if expected_version is not None and (
        type(expected_version) is not str
        or not _VERSION_RE.fullmatch(expected_version)
        or version != expected_version
    ):
        _fail("EXPLICIT_VERSION_MISMATCH", "installed Claude version differs from explicit binding")
    required_flags = {
        "--add-dir",
        "--disable-slash-commands", "--input-format", "--mcp-config", "--model",
        "--no-chrome", "--no-session-persistence", "--output-format",
        "--permission-mode", "--permission-prompts", "--print", "--restricted",
        "--session-id", "--setting-sources", "--settings", "--strict-mcp-config",
        "--prompt-suggestions", "--tools", "--verbose",
    }
    if not required_flags.issubset(set(observation.get("supported_flags", []))):
        _fail("EXECUTABLE_CAPABILITY_MISSING", "Claude CLI lacks required capabilities")
    policy, settings_path, mcp_path, tools = _exact_boundary(
        phase_tool_boundary, contract=contract, cwd=working, output_routes=output_routes,
    )
    source_root = Path(source_config_root).resolve(strict=True)
    if not source_root.is_dir() or source_root.is_symlink():
        _fail("AUTH_CONFIG_ROOT_INVALID", "native Claude config root is invalid")
    explicit_config = environment.get("CLAUDE_CONFIG_DIR")
    child_environment = _auth_environment(environment)
    child_environment["CLAUDE_CODE_DISABLE_AUTO_MEMORY"] = "1"
    auth_config_root: Path | None = None
    if explicit_config is not None:
        if type(explicit_config) is not str:
            _fail("AUTH_CONFIG_ROOT_INVALID", "explicit config root must be a string")
        auth_config_root = Path(explicit_config).resolve(strict=True)
        if auth_config_root != source_root:
            _fail("AUTH_CONFIG_ROOT_INVALID", "explicit config root changed")
        child_environment["CLAUDE_CONFIG_DIR"] = os.fspath(auth_config_root)
    auth = check_claude_native_auth(
        executable=str(observation["resolved_executable"]),
        source_environment=child_environment,
        config_root=auth_config_root,
    )
    if any(
        name != "CLAUDE_CONFIG_DIR"
        and (
            name in _AUTH_FORBIDDEN_ENV_NAMES
            or name.startswith(_AUTH_FORBIDDEN_ENV_PREFIXES)
        )
        for name in child_environment
    ):
        _fail("AUTH_ENVIRONMENT_INVALID", "Claude child environment contains credential injection")
    for value, label, maximum in (
        (max_stdout_bytes, "stdout", 64 * 1024 * 1024),
        (max_stderr_bytes, "stderr", 64 * 1024 * 1024),
        (max_line_bytes, "line", 4 * 1024 * 1024),
    ):
        if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= maximum:
            _fail("STREAM_BOUND_INVALID", f"Claude {label} bound is invalid")
    # The worker's cwd is the scratchpad, but the audited source it must read
    # lives OUTSIDE it (for example `<project>/contracts`).  Under
    # `--restricted --permission-mode dontAsk` the CLI denies any read beyond
    # its own directory boundary REGARDLESS of what the PreToolUse hook
    # decides, so without this grant a worker that needs source files records
    # `permission_denials` for every one of them, reports a cheerful
    # `is_error: false` result, publishes nothing, and the phase gate fails
    # with no rejection reason recorded (observed in DODO run28: R2/R3 denied
    # Read on GatewayCrossChain.sol, GatewaySend.sol, GatewayTransferNative.sol).
    #
    # The grant is bounded to the policy's own `source_read_root` -- the same
    # root the hook already authorizes via SOURCE_READ -- so this expands no
    # privilege. The CLI boundary becomes a superset of what the hook may
    # allow, and the hook remains the precise authority: excluded roots,
    # forbidden reads, exact-read drift and unregistered reads are all still
    # denied per call.
    # Every root the hook may authorize must also be inside the CLI's own
    # directory boundary, or the CLI refuses the read before the hook is ever
    # consulted. That means BOTH the audited source (SOURCE_READ) and the
    # methodology tree (METHODOLOGY_READ) -- run30's instantiate phase was
    # denied `~/.plamen/agents/skills/evm/*/SKILL.md` even though the hook
    # returns ALLOW/METHODOLOGY_READ for exactly those paths.
    grant_roots: list[Path] = [
        Path(str(policy["source_read_root"])).resolve(strict=True)
    ]
    for raw_root in policy.get("methodology_read_roots") or ():
        try:
            grant_roots.append(Path(str(raw_root)).resolve(strict=True))
        except OSError:
            _fail(
                "CLAUDE_TOOL_BOUNDARY_INVALID",
                "policy methodology read root is unavailable",
            )
    argv = [
        "-p", "--input-format", "text", "--model", launch.model,
        "--output-format", "stream-json", "--verbose",
        "--session-id", provider_uuid, "--no-session-persistence", "--restricted",
        "--permission-mode", "dontAsk", "--permission-prompts", "none",
        "--tools", ",".join(tools), "--disable-slash-commands",
        "--setting-sources=", "--no-chrome", "--prompt-suggestions", "false",
        "--settings", os.fspath(settings_path), "--strict-mcp-config",
        "--mcp-config", os.fspath(mcp_path),
    ]
    granted: set[str] = set()
    for root in grant_roots:
        if root == working:
            continue
        key = os.fspath(root)
        if key in granted:
            continue
        granted.add(key)
        argv.extend(("--add-dir", key))
    init_core = {
        "schema": "plamen.posix-v2-compat-claude-init-contract.v1",
        "claude_code_version": version,
        "cwd": os.fspath(working),
        "accepted_model": launch.model,
        "permission_mode": "dontAsk",
        "allowed_tools": list(tools),
        "mcp_servers": [],
        "plugins": [],
        "skills": [],
        "slash_commands": [],
        "api_key_source": "none",
        "allowed_agents": sorted(_ALLOWED_LOCAL_AGENTS),
        "allowed_native_capabilities": sorted(_ALLOWED_NATIVE_CAPABILITIES),
        "allowed_auxiliary_usage_models": sorted(
            _ALLOWED_AUXILIARY_USAGE_MODELS
        ),
        "accepted_output_styles": ["default"],
    }
    profile_core = {
        "schema": "plamen.posix-v2-compat-claude-profile.v1",
        "profile": PROFILE,
        "terminal_grammar": TERMINAL_GRAMMAR,
        "restricted_requested": True,
        "auto_memory_disabled": True,
        "phase_hook_policy_sha256": policy["manifest_digest"],
        "settings_sha256": _sha(_safe_file(settings_path, label="Claude settings")),
        "mcp_config_sha256": _sha(_safe_file(mcp_path, label="Claude MCP config")),
        "os_isolation": COMPATIBILITY_MODE,
        "escaped_descendants_excluded_from_observation": True,
        "native_broker_authority": False,
        "wer_authority": False,
    }
    projection: dict[str, Any] = {
        "schema": PLAN_SCHEMA,
        "backend": "claude",
        "compatibility_mode": COMPATIBILITY_MODE,
        "provider_session_id": provider_uuid,
        "phase_io_contract_digest": contract.digest,
        "phase_io_launch_digest": launch.digest,
        "session_binding_sha256": session.get("session_binding_sha256"),
        "executable_observation_sha256": observed_digest,
        "executable_version": version,
        "expected_version": expected_version,
        "model": launch.model,
        "argv": argv,
        "environment": child_environment,
        "cwd": os.fspath(working),
        "stdin_sha256": _sha(prompt_bytes),
        "stdin_byte_count": len(prompt_bytes),
        "output_routes_sha256": _sha(_canonical(list(output_routes))),
        "auth_mode": auth.auth_mode,
        "auth_binding_sha256": auth.auth_binding_sha256,
        "profile": PROFILE,
        "profile_sha256": _digest_mapping(profile_core),
        "terminal_grammar": TERMINAL_GRAMMAR,
        "expected_init_contract": init_core,
        "expected_init_contract_sha256": _digest_mapping(init_core),
        "max_stdout_bytes": max_stdout_bytes,
        "max_stderr_bytes": max_stderr_bytes,
        "max_line_bytes": max_line_bytes,
    }
    projection["plan_sha256"] = _digest_mapping(projection)
    raw = _canonical(projection)
    key = id(raw) ^ id(projection) ^ int.from_bytes(os.urandom(8), "big")
    with _PLAN_LOCK:
        while key in _PLAN_RECORDS:
            key ^= int.from_bytes(os.urandom(8), "big")
        _PLAN_RECORDS[key] = raw
    return PosixV2CompatClaudePlan(_PLAN_TOKEN, key)


def project_posix_v2_compat_claude_plan(plan: PosixV2CompatClaudePlan) -> Mapping[str, Any]:
    """Return an immutable exact projection of an issued live plan."""

    return MappingProxyType(_record_for(plan))


def _strict_init(stdout: bytes) -> dict[str, Any]:
    first = stdout.splitlines()[0] if stdout.splitlines() else b""
    event = _decode_object(first, label="Claude init event")
    if event.get("type") != "system" or event.get("subtype") != "init":
        _fail("INIT_APPLICABILITY_MISMATCH", "first Claude event is not system/init")
    return event


def _strict_events(stdout: bytes) -> list[dict[str, Any]]:
    rows = stdout.splitlines()
    if not rows or not stdout.endswith(b"\n"):
        _fail("STREAM_INVALID", "Claude stream is empty or lacks final newline")
    return [_decode_object(row, label="Claude stream event") for row in rows]


def validate_posix_v2_compat_claude_completion(
    plan: PosixV2CompatClaudePlan,
    *,
    stdout: bytes,
    stderr: bytes,
    returncode: int,
) -> Mapping[str, Any]:
    """Validate raw provider completion against the exact issued plan."""

    projection = _record_for(plan)
    if type(stdout) is not bytes or type(stderr) is not bytes or isinstance(returncode, bool) or not isinstance(returncode, int):
        _fail("COMPLETION_INVALID", "Claude completion observations are malformed")
    if returncode != 0:
        _fail("CLAUDE_PROCESS_EXITED", f"Claude process exited with status {returncode}")
    if stderr:
        _fail("CLAUDE_STDERR_NONEMPTY", "Claude process emitted stderr")
    init = _strict_init(stdout)
    expected = projection["expected_init_contract"]
    list_fields = ("mcp_servers", "plugins", "skills", "slash_commands")
    mismatches = []
    for observed_name, expected_name in (
        ("claude_code_version", "claude_code_version"),
        ("cwd", "cwd"), ("model", "accepted_model"),
        ("permissionMode", "permission_mode"),
        ("apiKeySource", "api_key_source"),
    ):
        if init.get(observed_name) != expected[expected_name]:
            mismatches.append(observed_name)
    for name in list_fields:
        if init.get(name, []) != expected[name]:
            mismatches.append(name)
    observed_tools = init.get("tools", [])
    if (
        not isinstance(observed_tools, list)
        or len(observed_tools) != len(set(observed_tools))
        or set(observed_tools) != set(expected["allowed_tools"])
    ):
        mismatches.append("tools")
    if init.get("plugin_errors", []) != []:
        mismatches.append("plugin_errors")
    agents = init.get("agents", [])
    capabilities = init.get("capabilities", [])
    if (
        not isinstance(agents, list)
        or len(agents) != len(set(agents))
        or not set(agents).issubset(set(expected["allowed_agents"]))
    ):
        mismatches.append("agents")
    if (
        not isinstance(capabilities, list)
        or len(capabilities) != len(set(capabilities))
        or not set(capabilities).issubset(
            set(expected["allowed_native_capabilities"])
        )
        or "remote-agents" in capabilities
    ):
        mismatches.append("capabilities")
    if init.get("output_style") not in expected["accepted_output_styles"]:
        mismatches.append("output_style")
    if _FORBIDDEN_TOOLS & set(init.get("tools", [])):
        mismatches.append("forbidden_tools")
    if mismatches:
        _fail("INIT_APPLICABILITY_MISMATCH", "Claude init changed: " + ", ".join(sorted(set(mismatches))))
    try:
        evidence = (
            _validate_claude_stream_json_from_authenticated_posix_v2_compat_plan(
            stdout,
            compatibility_executable_binding={
                "backend": projection["backend"],
                "compatibility_mode": projection["compatibility_mode"],
                "executable_observation_sha256": projection[
                    "executable_observation_sha256"
                ],
                "plan_sha256": projection["plan_sha256"],
                "resolved_version": projection["executable_version"],
                "terminal_grammar": projection["terminal_grammar"],
            },
            expected_session_id=projection["provider_session_id"],
            allow_capability_bound_text_null_stop_terminal=True,
            max_line_bytes=projection["max_line_bytes"],
            max_stream_bytes=projection["max_stdout_bytes"],
            )
        )
    except ClaudeStreamJsonEvidenceError as exc:
        raise PosixV2CompatClaudeError(exc.code, str(exc)) from exc
    result_event: dict[str, Any] | None = None
    for event in _strict_events(stdout):
        if event.get("type") == "assistant":
            message = event.get("message")
            if not isinstance(message, dict) or message.get("model") != projection["model"]:
                _fail("MODEL_DENOMINATOR_MISMATCH", "assistant model differs from armed model")
        if event.get("type") == "result":
            result_event = event
            usage = event.get("modelUsage")
            allowed_usage_models = {
                projection["model"],
                *expected["allowed_auxiliary_usage_models"],
            }
            if (
                not isinstance(usage, dict)
                or projection["model"] not in usage
                or not set(usage).issubset(allowed_usage_models)
            ):
                _fail("MODEL_DENOMINATOR_MISMATCH", "result model usage differs from armed model")
            for model_name, row in usage.items():
                if not isinstance(row, dict):
                    _fail("MODEL_DENOMINATOR_MISMATCH", "model usage row is malformed")
                for field in (
                    "inputTokens", "outputTokens", "cacheReadInputTokens",
                    "cacheCreationInputTokens", "webSearchRequests",
                ):
                    value = row.get(field)
                    if (
                        isinstance(value, bool)
                        or not isinstance(value, int)
                        or value < 0
                    ):
                        _fail("MODEL_DENOMINATOR_MISMATCH", "model usage metric is invalid")
                cost = row.get("costUSD")
                if (
                    isinstance(cost, bool)
                    or not isinstance(cost, (int, float))
                    or not math.isfinite(cost)
                    or cost < 0
                ):
                    _fail("MODEL_DENOMINATOR_MISMATCH", "model usage cost is invalid")
                if row.get("provider") != "firstParty":
                    _fail("MODEL_DENOMINATOR_MISMATCH", "model usage provider changed")
                if model_name == projection["model"] and row.get(
                    "canonicalModel"
                ) != projection["model"]:
                    _fail("MODEL_DENOMINATOR_MISMATCH", "primary usage provenance changed")
                # NOT `webSearchRequests != 0`.  The provider executes the
                # WebSearch tool ON the auxiliary model, so a worker that
                # searches at all produces an auxiliary row with a NONZERO
                # count.  Measured on DODO run41 recon R-EXT: the armed model
                # `claude-sonnet-5` did webSearchRequests=0 while the auxiliary
                # `claude-haiku-4-5` did 16 -- the exact inverse of what this
                # clause assumed.  The worker had authored a complete, correct
                # 25-obligation artifact (13 RESEARCHED, real sources), and the
                # whole thing was discarded as MODEL_DENOMINATOR_MISMATCH.  That
                # is why dependency parity read `researched=0` on every Claude
                # run from 35 onward.
                #
                # The property this gate actually owns is AUTHORSHIP, and that
                # is enforced exactly and separately above: every `assistant`
                # event must carry the armed model.  A search count is a
                # tool-execution detail, not authorship.  WHETHER those searches
                # were authorized is owned by the bounded-web tool policy and
                # its receipts; asserting a count here that this module cannot
                # derive would give one decision two owners, with this copy
                # guessing.
                if model_name in _ALLOWED_AUXILIARY_USAGE_MODELS and (
                    row.get("canonicalModel") != "claude-haiku-4-5"
                ):
                    _fail("MODEL_DENOMINATOR_MISMATCH", "auxiliary usage provenance changed")
    if result_event is None:
        _fail("COMPLETION_INVALID", "Claude result event is absent")

    def _zero_subagent_value(value: object) -> bool:
        if isinstance(value, bool):
            return False
        if isinstance(value, int):
            return value == 0
        if isinstance(value, dict):
            return all(_zero_subagent_value(item) for item in value.values())
        return False

    subagents = result_event.get("subagent_stats")
    if not isinstance(subagents, dict) or not _zero_subagent_value(subagents):
        _fail("SUBAGENT_EXECUTION_REJECTED", "Claude reported subagent execution")
    usage_models = sorted(result_event["modelUsage"])
    auxiliary_models = sorted(set(usage_models) - {projection["model"]})
    usage_model_provenance = {
        model_name: {
            field: result_event["modelUsage"][model_name][field]
            for field in (
                "cacheCreationInputTokens", "cacheReadInputTokens",
                "canonicalModel", "costUSD", "inputTokens", "outputTokens",
                "provider", "webSearchRequests",
            )
        }
        for model_name in usage_models
    }
    core = {
        "schema": COMPLETION_SCHEMA,
        "backend": "claude",
        "provider_session_id": projection["provider_session_id"],
        "plan_sha256": projection["plan_sha256"],
        "expected_init_contract_sha256": projection["expected_init_contract_sha256"],
        "stdout_sha256": _sha(stdout),
        "stdout_byte_count": len(stdout),
        "stderr_sha256": _sha(stderr),
        "stderr_byte_count": len(stderr),
        "returncode": returncode,
        "status": "COMPLETED",
        "observed_model": projection["model"],
        "terminal_grammar": projection["terminal_grammar"],
        "observed_usage_models": usage_models,
        "additional_provider_usage_models": auxiliary_models,
        "usage_model_provenance": usage_model_provenance,
        "exclusive_model_execution_claimed": False,
        "stream_evidence": evidence,
        "init_applicability": "MATCHED_BY_POSIX_COMPAT_ADAPTER",
    }
    return MappingProxyType({**core, "completion_sha256": _digest_mapping(core)})


def replay_posix_v2_compat_claude_completion(
    plan_projection: Mapping[str, Any], completion: Mapping[str, Any],
) -> Mapping[str, Any]:
    """Replay a projected completion without rehydrating plan authority."""

    plan = dict(plan_projection)
    completed = dict(completion)
    if plan.get("schema") != PLAN_SCHEMA or completed.get("schema") != COMPLETION_SCHEMA:
        _fail("COMPLETION_REPLAY_INVALID", "Claude plan/completion schema changed")
    unsigned_plan = dict(plan)
    plan_sha = unsigned_plan.pop("plan_sha256", None)
    if plan_sha != _digest_mapping(unsigned_plan):
        _fail("COMPLETION_REPLAY_INVALID", "Claude plan digest changed")
    unsigned_completion = dict(completed)
    completion_sha = unsigned_completion.pop("completion_sha256", None)
    if completion_sha != _digest_mapping(unsigned_completion):
        _fail("COMPLETION_REPLAY_INVALID", "Claude completion digest changed")
    if (
        completed.get("plan_sha256") != plan_sha
        or completed.get("provider_session_id") != plan.get("provider_session_id")
        or completed.get("expected_init_contract_sha256") != plan.get("expected_init_contract_sha256")
        or completed.get("init_applicability") != "MATCHED_BY_POSIX_COMPAT_ADAPTER"
        or completed.get("returncode") != 0
        or completed.get("status") != "COMPLETED"
        or completed.get("observed_model") != plan.get("model")
        or completed.get("terminal_grammar") != plan.get("terminal_grammar")
        or plan.get("terminal_grammar") != TERMINAL_GRAMMAR
        or completed.get("exclusive_model_execution_claimed") is not False
    ):
        _fail("COMPLETION_REPLAY_INVALID", "Claude completion binding changed")
    stream = completed.get("stream_evidence")
    if not isinstance(stream, Mapping):
        _fail("COMPLETION_REPLAY_INVALID", "Claude stream evidence is absent")
    stream_core = dict(stream)
    stream_digest = stream_core.pop("canonical_summary_sha256", None)
    if (
        stream_digest != _digest_mapping(stream_core)
        or stream.get("session_id") != plan.get("provider_session_id")
        or stream.get("claude_code_version") != plan.get("executable_version")
        or stream.get("raw_sha256") != completed.get("stdout_sha256")
        or stream.get("raw_byte_count") != completed.get("stdout_byte_count")
        or stream.get("result_subtype") != "success"
        or stream.get("result_is_error") is not False
        or stream.get("result_stop_reason_observed") != "end_turn"
        or stream.get("protocol_adverse_event_count") != 0
        or stream.get("terminal_basis") not in {
            "FINAL_ROOT_ASSISTANT_END_TURN_AND_RESULT_SUCCESS",
            "FINAL_ROOT_ASSISTANT_TEXT_NULL_STOP_AND_RESULT_SUCCESS_"
            "CAPABILITY_BOUND",
        }
    ):
        _fail("COMPLETION_REPLAY_INVALID", "Claude stream evidence binding changed")
    usage_models = completed.get("observed_usage_models")
    auxiliary_models = completed.get("additional_provider_usage_models")
    usage_provenance = completed.get("usage_model_provenance")
    expected_init = plan.get("expected_init_contract")
    if (
        not isinstance(expected_init, Mapping)
        or not isinstance(usage_models, list)
        or usage_models != sorted(set(usage_models))
        or plan.get("model") not in usage_models
        or not isinstance(auxiliary_models, list)
        or auxiliary_models
        != sorted(set(usage_models) - {str(plan.get("model"))})
        or not set(auxiliary_models).issubset(
            set(expected_init.get("allowed_auxiliary_usage_models", []))
        )
        or not isinstance(usage_provenance, Mapping)
        or set(usage_provenance) != set(usage_models)
    ):
        _fail("COMPLETION_REPLAY_INVALID", "Claude usage model accounting changed")
    provenance_fields = {
        "cacheCreationInputTokens", "cacheReadInputTokens", "canonicalModel",
        "costUSD", "inputTokens", "outputTokens", "provider",
        "webSearchRequests",
    }
    for model_name, row in usage_provenance.items():
        if not isinstance(row, Mapping) or set(row) != provenance_fields:
            _fail("COMPLETION_REPLAY_INVALID", "Claude usage provenance changed")
        for field in (
            "inputTokens", "outputTokens", "cacheReadInputTokens",
            "cacheCreationInputTokens", "webSearchRequests",
        ):
            value = row.get(field)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                _fail("COMPLETION_REPLAY_INVALID", "Claude usage provenance changed")
        cost = row.get("costUSD")
        if (
            isinstance(cost, bool)
            or not isinstance(cost, (int, float))
            or not math.isfinite(cost)
            or cost < 0
            or row.get("provider") != "firstParty"
        ):
            _fail("COMPLETION_REPLAY_INVALID", "Claude usage provenance changed")
        if model_name == plan.get("model"):
            if row.get("canonicalModel") != plan.get("model"):
                _fail("COMPLETION_REPLAY_INVALID", "primary usage provenance changed")
        elif (
            model_name not in _ALLOWED_AUXILIARY_USAGE_MODELS
            or row.get("canonicalModel") != "claude-haiku-4-5"
        ):
            # Replay MUST accept exactly what validation accepts; see the
            # auxiliary-usage rationale in the validation path above. Leaving
            # `webSearchRequests != 0` here would reject on resume every
            # completion that was admitted live.
            _fail("COMPLETION_REPLAY_INVALID", "auxiliary usage provenance changed")
    return MappingProxyType(completed)


__all__ = [
    "AUTH_MODE", "AUTH_SCHEMA", "COMPLETION_SCHEMA", "PLAN_SCHEMA",
    "TERMINAL_GRAMMAR",
    "PosixV2CompatClaudeAuth", "PosixV2CompatClaudeError",
    "PosixV2CompatClaudePlan", "check_claude_native_auth",
    "compile_posix_v2_compat_claude_plan",
    "project_posix_v2_compat_claude_plan",
    "replay_posix_v2_compat_claude_completion",
    "validate_posix_v2_compat_claude_completion",
]
