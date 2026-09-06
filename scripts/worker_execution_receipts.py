"""Strict, provider-owned worker execution observations.

This module is intentionally narrower than a generic "receipt writer".  The only
way to obtain a completion receipt is for :func:`run_observed_worker` to arm an
execution contract, launch the child itself, observe its operating-system process
identity and exit status, and validate the complete assigned-output denominator.

The headless subprocess path is production-capable and deliberately fail closed.
An incomplete launch, timeout, non-zero exit, malformed output, or observation
failure leaves an immutable arm plus an immutable debt record, never a completion.

Interactive PTY transports need the same ownership boundary.  ``PtyLifecycleAdapter``
documents the seam: a future adapter must give this provider the real child handle
at creation time and let this provider observe start, streams/transcript, exit, and
outputs.  There is no API for accepting a caller-authored process observation or
raw completion payload, because that would turn attestation into self-report.
"""

from __future__ import annotations

import contextlib
import ctypes
from decimal import Decimal, InvalidOperation
import dis
import hashlib
import importlib
import inspect
import json
import os
from pathlib import Path
import queue
import re
import shutil
import signal
import stat
import subprocess
import sys
import sysconfig
import threading
import time
import types
from typing import (
    Any,
    Callable,
    Collection,
    Iterator,
    Mapping,
    NamedTuple,
    Protocol,
    Sequence,
)
import unicodedata
import uuid

from owned_process_scope import (
    OwnedProcessScope as _SharedOwnedProcessScope,
    process_tree_termination_capability as _shared_process_tree_capability,
    windows_job_only_process_tree_capability as _windows_job_only_capability,
)
from windows_private_execution_root import (
    WindowsPrivateExecutionRootAuthority,
    create_windows_private_execution_root,
)
import claude_phase_tool_policy as _claude_phase_tool_policy
from auxiliary_writable_root_lease import (
    AuxiliaryWritableRootLease,
    LEASE_SCHEMA as AUXILIARY_LEASE_SCHEMA,
    prove_owned_process_scope_closed,
    replay_auxiliary_writable_root_binding,
    replay_auxiliary_writable_root_revocation,
)
from auxiliary_writable_root_startup import (
    AuxiliaryWritableRootStartupError,
    replay_startup_permit_binding,
    replay_startup_permit_evidence,
)
from pty_completion_observer import (
    OBSERVER_SCHEMA as _CLAUDE_TURN_OBSERVER_SCHEMA,
    implementation_files as _pty_observer_implementation_files,
    prepare_claude_turn as _prepare_claude_turn_observer,
    probe_claude_turn as _probe_claude_turn_observer,
    replay_claude_turn as _replay_claude_turn_observer,
)
import pty_transport_bridge as _pty_bridge_module
from pty_transport_bridge import (
    implementation_files as _pty_bridge_implementation_files,
    load_bridge_manifest as _load_pty_bridge_manifest,
)
from pty_worker_host import load_host_manifest as _load_pty_host_manifest
from pty_exec import encode_claude_project_dir as _encode_claude_project_dir
from claude_stream_json_evidence import (
    DEFAULT_MAX_LINE_BYTES as _CLAUDE_STREAM_DEFAULT_MAX_LINE_BYTES,
    ClaudeStreamJsonEvidenceError as _ClaudeStreamJsonEvidenceError,
    implementation_files as _claude_stream_implementation_files,
    normalize_expected_init_contract as _normalize_claude_expected_init,
    replay_claude_stream_json as _replay_claude_stream_json,
    validate_claude_stream_json as _validate_claude_stream_json,
)
from claude_launch_security import (
    ClaudeLaunchSecurityError as _ClaudeLaunchSecurityError,
    replay_claude_launch_security as _replay_claude_launch_security,
    replay_claude_launch_security_request as _replay_claude_launch_security_request,
)
from claude_executable_observation import (
    ClaudeExecutableObservationError as _ClaudeExecutableObservationError,
    recheck_claude_executable_before_launch as _recheck_claude_executable_before_launch,
)
from claude_runtime_materialization import (
    ClaudeRuntimeMaterialization,
    ClaudeRuntimeMaterializationError,
    ClaudeRuntimeMaterializationRequest,
    claude_runtime_environment_key_set_sha256,
    materialize_claude_runtime,
    reconcile_claude_runtime_after_scope_close,
    reconcile_claude_runtime_persisted_authority,
    replay_claude_runtime_lifecycle_receipt,
    replay_claude_runtime_materialization,
    replay_claude_runtime_materialization_receipt,
    replay_claude_runtime_postprocess_receipt,
)
from provider_command_authority import (
    argv_authority_sha256 as _argv_authority_sha256,
)
import rooted_path_io as _rooted_io


ARM_SCHEMA = "plamen.worker_execution_arm.v2"
COMPLETION_SCHEMA = "plamen.worker_execution_completion.v2"
DEBT_SCHEMA = "plamen.worker_execution_debt.v1"
PUBLISH_ARM_SCHEMA = "plamen.worker_output_publish_arm.v1"
PUBLISH_SCHEMA = "plamen.worker_output_publish.v1"
LAUNCHER_IDENTITY = "PLAMEN_WORKER_EXECUTION_PROVIDER"
WORKER_FILE_OUTPUTS = "WORKER_FILE_OUTPUTS"
STDOUT_ASSIGNED_OUTPUT = "STDOUT_ASSIGNED_OUTPUT"
DEFAULT_STDOUT_LIMIT_BYTES = 8 * 1024 * 1024
DEFAULT_STDERR_LIMIT_BYTES = 2 * 1024 * 1024
DEFAULT_STAGED_OUTPUT_LIMIT_BYTES = 64 * 1024 * 1024
MAX_STREAM_LIMIT_BYTES = 64 * 1024 * 1024
DEFAULT_COMPLETION_EVIDENCE_LIMIT_BYTES = 64 * 1024 * 1024
DEFAULT_OBSERVER_CALLBACK_TIMEOUT_SECONDS = 1.0
_ALLOWED_PROVISIONAL_COMPLETION_SIGNALS = {"TURN_END", "OUTPUT_READY"}
CLAUDE_STREAM_STDOUT_CONFIGURATION_SCHEMA = (
    "plamen.claude_stream_stdout_configuration.v1"
)
_CLAUDE_EXPECTED_INIT_SECURITY_SCHEMA = "plamen.claude-expected-init/v2"
_WORKER_WORK_PLAN_SCHEMAS = frozenset(
    {
        "plamen.worker_work_plan.v1",
        "plamen.worker_work_plan.v2",
    }
)
_WORKER_PLAN_PROVIDER_STDOUT_POLICY_KEY = (
    "provider_stdout_evidence_configuration"
)
_WORKER_PLAN_STARTUP_POLICY_KEY = (
    "auxiliary_writable_root_startup_permit"
)
_WORKER_PLAN_CLAUDE_SECURITY_POLICY_KEY = "claude_launch_security"
_CLAUDE_STREAM_CONFIGURATION_FIELDS = (
    "schema",
    "expected_session_id",
    "expected_init_contract",
    "max_line_bytes",
    "max_stream_bytes",
)
_STARTUP_PERMIT_BINDING_FIELDS = (
    "schema",
    "run_id",
    "startup_epoch",
    "current_pointer_sha256",
    "receipt_relative_path",
    "receipt_sha256",
    "allocation_disposition",
)

_EVIDENCE_DIR = ".worker_execution_receipts"
_HEX_RE = re.compile(r"[0-9a-f]{64}")
_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}")
_SEMANTIC_INPUT_NAMES = (
    "plan",
    "manifest",
    "intent",
    "context",
    "prompt",
    "tool_policy",
)


def _transaction_write_authority(
    capability: Mapping[str, Any],
) -> str | None:
    """Return the honest artifact-integrity authority usable by a transaction.

    Windows MIC plus Plamen's global low-integrity lease is intentionally not
    called exhaustive filesystem confinement: unrelated pre-existing low-IL
    objects remain outside its guarantee.  It *does* protect medium-integrity
    source/canonical state and serializes every Plamen-owned low-IL stage, which
    is the exact authority required for transaction output integrity.
    """

    if not isinstance(capability, Mapping):
        return None
    if capability.get("exhaustive_write_confinement_authority") is True:
        return "EXHAUSTIVE"
    if (
        capability.get("platform") != "WINDOWS"
        or capability.get("exhaustive_write_confinement_authority") is not False
        or capability.get("serialized_low_integrity_stage_authority") is not True
        or capability.get(
            "medium_integrity_source_and_canonical_protection"
        )
        is not True
        or capability.get("write_confinement")
        != "LOW_INTEGRITY_TOKEN_PLUS_SERIALIZED_PLAMEN_STAGE_LEASE"
        or capability.get("write_confinement_limitation")
        != "UNRELATED_PREEXISTING_LOW_INTEGRITY_OBJECTS_OUT_OF_SCOPE"
    ):
        return None
    lease = capability.get("low_integrity_lease")
    expected_fields = {
        "protocol",
        "lock_path",
        "state_path",
        "identity_sha256",
        "scope",
        "crash_recovery",
        "namespace_authority",
        "namespace_limitation",
    }
    if not isinstance(lease, Mapping) or set(lease) != expected_fields:
        return None
    if (
        lease.get("protocol")
        != "PLAMEN_WINDOWS_LOW_INTEGRITY_GLOBAL_LEASE_V1"
        or lease.get("scope")
        != "ALL_PLAMEN_LOW_INTEGRITY_LIFETIMES_FOR_THIS_WINDOWS_USER_PROFILE"
        or lease.get("crash_recovery")
        != "OS_BYTE_RANGE_UNLOCK_PLUS_STALE_ROOT_RELABEL"
        or lease.get("namespace_authority")
        != "WINDOWS_KNOWN_FOLDER_LOCAL_APP_DATA"
        or lease.get("namespace_limitation")
        != "SAME_USER_MEDIUM_INTEGRITY_MUTATION_OUT_OF_SCOPE"
        or not isinstance(lease.get("lock_path"), str)
        or not Path(str(lease["lock_path"])).is_absolute()
        or not isinstance(lease.get("state_path"), str)
        or not Path(str(lease["state_path"])).is_absolute()
        or not isinstance(lease.get("identity_sha256"), str)
        or not _HEX_RE.fullmatch(str(lease["identity_sha256"]))
    ):
        return None
    return "SERIALIZED_PLAMEN_STAGE"


_RESTRICTED_CLAUDE_STAGE_AUTHORITY = "CLAUDE_RESTRICTED_STAGE_V1"
_RESTRICTED_CLAUDE_TOOLS = ["Edit", "Glob", "Grep", "Read", "Write"]
_RESTRICTED_CLAUDE_WEB_TOOLS = [
    "Edit", "Glob", "Grep", "Read", "WebFetch", "WebSearch", "Write",
]
_RESTRICTED_CLAUDE_FORBIDDEN_TOOLS = {
    "Agent", "Bash", "PowerShell", "Task", "WebFetch", "WebSearch",
}
_RESTRICTED_CLAUDE_WEB_FORBIDDEN_TOOLS = {
    "Agent", "Bash", "PowerShell", "Task",
}
_RESTRICTED_CLAUDE_CAPABILITY = "vendor-restricted-analysis"
_RESTRICTED_CLAUDE_WEB_CAPABILITY = "vendor-restricted-web-analysis"
_RESTRICTED_CLAUDE_WEB_ALLOWED_TOOLS = ["Glob", "Grep", "Read"]
_RESTRICTED_CLAUDE_LIMITATION = (
    "VENDOR_RESTRICTED_FILE_TOOLS_PLUS_EXACT_STAGE_RULES"
)
_LINUX_LANDLOCK_WRITE_RE = re.compile(
    r"LANDLOCK_ABI_[1-9][0-9]*_PATH_BENEATH"
)


def _restricted_claude_capability_lane(
    expected: Mapping[str, Any],
) -> str | None:
    """Select one exact reviewed restricted lane from authenticated init."""

    capabilities = expected.get("required_capabilities")
    if (
        not isinstance(capabilities, list)
        or any(not isinstance(value, str) or not value for value in capabilities)
        or capabilities != sorted(set(capabilities))
    ):
        raise WorkerExecutionError(
            "restricted Claude capability denominator is malformed"
        )
    if capabilities == [_RESTRICTED_CLAUDE_CAPABILITY]:
        return "FILESYSTEM"
    if capabilities == [_RESTRICTED_CLAUDE_WEB_CAPABILITY]:
        return "BOUNDED_WEB"
    if any(
        value.startswith("vendor-restricted")
        or value in {
            _RESTRICTED_CLAUDE_CAPABILITY,
            _RESTRICTED_CLAUDE_WEB_CAPABILITY,
        }
        for value in capabilities
    ):
        raise WorkerExecutionError(
            "restricted Claude capability denominator is unsupported"
        )
    return None


def _restricted_claude_platform_fields(
    capability: Mapping[str, Any],
) -> dict[str, str] | None:
    """Return truthful restricted-stage fields for an admitted native scope."""

    platform = capability.get("platform")
    if platform == "WINDOWS":
        try:
            expected = _windows_job_only_capability()
        except Exception:
            return None
        if dict(capability) != expected:
            return None
        return {
            "os_write_confinement": "NOT_PROVIDED",
            "process_tree": "WINDOWS_JOB_OBJECT",
            "limitation": _RESTRICTED_CLAUDE_LIMITATION,
        }
    if platform != "LINUX":
        return None
    write_confinement = capability.get("write_confinement")
    if (
        capability.get("provider_owns_tree") is not True
        or capability.get("pre_execution_assignment") is not True
        or capability.get("exhaustive_descendant_termination_authority")
        is not True
        or capability.get("exhaustive_write_confinement_authority") is not True
        or capability.get("termination_scope") != "CGROUP_V2_SUBTREE"
        or capability.get("population_zero_proof")
        != "CGROUP_EVENTS_POPULATED_ZERO"
        or not isinstance(write_confinement, str)
        or _LINUX_LANDLOCK_WRITE_RE.fullmatch(write_confinement) is None
    ):
        return None
    return {
        "os_write_confinement": write_confinement,
        "process_tree": "LINUX_CGROUP_V2_SUBTREE",
        "limitation": _RESTRICTED_CLAUDE_LIMITATION,
        "native_capability_sha256": _digest_json(dict(capability)),
    }


def _restricted_claude_process_capability(
    binding: Mapping[str, Any],
) -> dict[str, Any]:
    """Replay the native process/write capability named by a stage binding."""

    process_tree = binding.get("process_tree")
    try:
        capability = (
            _windows_job_only_capability()
            if process_tree == "WINDOWS_JOB_OBJECT"
            else process_tree_termination_capability()
        )
    except Exception as exc:
        raise WorkerExecutionError(
            "restricted Claude native process capability is unavailable"
        ) from exc
    fields = _restricted_claude_platform_fields(capability)
    if (
        fields is None
        or process_tree not in {
            "WINDOWS_JOB_OBJECT",
            "LINUX_CGROUP_V2_SUBTREE",
        }
        or any(binding.get(key) != value for key, value in fields.items())
    ):
        raise WorkerExecutionError(
            "restricted Claude native process capability differs from the arm"
        )
    return dict(capability)


def _restricted_claude_stage_binding(
    request: Mapping[str, Any],
    runtime: ClaudeRuntimeMaterialization,
    *,
    output_scope: Path,
    output_contract: Sequence[Mapping[str, Any]],
    output_source_mode: str = WORKER_FILE_OUTPUTS,
) -> dict[str, Any] | None:
    """Authenticate the vendor restriction and exact attempt-stage writes."""

    if not isinstance(request, Mapping):
        return None
    policy = request.get("policy")
    if not isinstance(policy, Mapping):
        return None
    profile = policy.get("headless_profile")
    if not isinstance(profile, Mapping):
        return None
    expected = profile.get("expected_init_contract")
    flags = profile.get("cli_flags")
    settings_authority = policy.get("settings_authority")
    permission_value: str | None = None
    if isinstance(flags, list) and flags.count("--permission-mode") == 1:
        permission_index = flags.index("--permission-mode")
        if permission_index + 1 < len(flags):
            permission_value = flags[permission_index + 1]
    if not isinstance(expected, Mapping):
        return None
    restricted_lane = _restricted_claude_capability_lane(expected)
    if restricted_lane is None:
        return None
    bounded_web = restricted_lane == "BOUNDED_WEB"
    expected_permission_mode = "default"
    expected_forbidden_tools = (
        _RESTRICTED_CLAUDE_WEB_FORBIDDEN_TOOLS
        if bounded_web
        else _RESTRICTED_CLAUDE_FORBIDDEN_TOOLS
    )
    if (
        not isinstance(flags, list)
        or profile.get("claude_code_version") != "2.1.252"
        or expected.get("claude_code_version") != "2.1.252"
        or expected.get("permission_mode") != expected_permission_mode
        or not expected_forbidden_tools.issubset(
            set(expected.get("forbidden_tools") or ())
        )
        or expected.get("allowed_mcp_servers") != []
        or expected.get("required_mcp_servers") != []
        or expected.get("allowed_tool_prefixes") != []
        or flags.count("--restricted") != 1
        or flags.count("--permission-mode") != 1
        or permission_value != expected_permission_mode
        or flags.count("--allowedTools") != (1 if bounded_web else 0)
        or (
            bounded_web
            and _single_cli_option_value(flags, "--allowedTools")
            != ",".join(_RESTRICTED_CLAUDE_WEB_ALLOWED_TOOLS)
        )
        or "--dangerously-skip-permissions" in flags
        or not isinstance(settings_authority, Mapping)
        or settings_authority.get("mode") != "BOUND_SETTINGS"
    ):
        return None
    raw = runtime.replay_bound_settings_bytes()
    if raw is None or hashlib.sha256(raw).hexdigest() != settings_authority.get(
        "settings_sha256"
    ):
        return None
    try:
        settings = json.loads(raw.decode("utf-8", errors="strict"))
    except (UnicodeError, json.JSONDecodeError):
        return None
    try:
        settings = _claude_phase_tool_policy.validate_settings_overlay(
            settings,
            restricted_analysis=True,
            bounded_web=bounded_web,
        )
    except _claude_phase_tool_policy.ClaudePhaseToolPolicyError:
        return None
    if output_source_mode == WORKER_FILE_OUTPUTS:
        if (
            expected.get("allowed_tools")
            != (
                _RESTRICTED_CLAUDE_WEB_TOOLS
                if bounded_web
                else _RESTRICTED_CLAUDE_TOOLS
            )
            or not output_contract
        ):
            return None
        expected_paths = [
            output_scope / str(row["relative_path"])
            for row in output_contract
        ]
        exact_rules = sorted(
            {
                "Glob",
                "Grep",
                "Read",
                *_claude_phase_tool_policy.exact_edit_permission_rules(
                    expected_paths
                ),
            }
        )
    elif output_source_mode == STDOUT_ASSIGNED_OUTPUT:
        if expected.get("allowed_tools") != [] or len(output_contract) != 1:
            return None
        exact_rules = []
    else:
        return None
    permissions = settings.get("permissions") if isinstance(settings, dict) else None
    if (
        not isinstance(permissions, dict)
        or set(permissions) != {"allow", "deny", "defaultMode"}
        or permissions.get("allow") != exact_rules
        or permissions.get("defaultMode") != "default"
        or not isinstance(permissions.get("deny"), list)
        or not isinstance(settings.get("hooks"), dict)
        or not settings["hooks"].get("PreToolUse")
        or settings.get("mcpServers") != {}
        or settings.get("enabledPlugins") != {}
    ):
        return None
    try:
        host_capability = process_tree_termination_capability()
    except Exception:
        return None
    if host_capability.get("platform") == "WINDOWS":
        try:
            restricted_capability = _windows_job_only_capability()
        except Exception:
            return None
    else:
        restricted_capability = host_capability
    platform_fields = _restricted_claude_platform_fields(
        restricted_capability
    )
    if platform_fields is None:
        return None
    core = {
        "protocol": "CLAUDE_CODE_RESTRICTED_ANALYSIS_STAGE_V1",
        "claude_code_version": "2.1.252",
        "settings_sha256": hashlib.sha256(raw).hexdigest(),
        "permission_rules": exact_rules,
        "output_scope": str(output_scope),
        **platform_fields,
        **(
            {"output_source_mode": STDOUT_ASSIGNED_OUTPUT}
            if output_source_mode == STDOUT_ASSIGNED_OUTPUT
            else {}
        ),
    }
    return {**core, "binding_sha256": _digest_json(core)}


def _active_write_confinement_binding(
    authority: str,
    binding: Any,
    *,
    capability: Mapping[str, Any],
    process_scope_identity: str,
    require_current_process: bool = True,
) -> dict[str, Any] | None:
    """Validate and normalize the active per-scope lease observation."""

    if authority == "EXHAUSTIVE":
        return dict(binding) if isinstance(binding, Mapping) else None
    if authority == _RESTRICTED_CLAUDE_STAGE_AUTHORITY:
        if not isinstance(binding, Mapping):
            raise WorkerExecutionError(
                "restricted Claude stage lacks its authenticated boundary"
            )
        required = {
            "protocol",
            "claude_code_version",
            "settings_sha256",
            "permission_rules",
            "output_scope",
            "os_write_confinement",
            "process_tree",
            "limitation",
            "binding_sha256",
        }
        stdout_assigned = (
            binding.get("output_source_mode") == STDOUT_ASSIGNED_OUTPUT
        )
        if stdout_assigned:
            required.add("output_source_mode")
        if binding.get("process_tree") == "LINUX_CGROUP_V2_SUBTREE":
            required.add("native_capability_sha256")
        core = {key: binding.get(key) for key in required - {"binding_sha256"}}
        platform_fields = _restricted_claude_platform_fields(capability)
        if (
            set(binding) != required
            or binding.get("protocol")
            != "CLAUDE_CODE_RESTRICTED_ANALYSIS_STAGE_V1"
            or binding.get("claude_code_version") != "2.1.252"
            or not isinstance(binding.get("settings_sha256"), str)
            or not _HEX_RE.fullmatch(str(binding["settings_sha256"]))
            or not isinstance(binding.get("permission_rules"), list)
            or (
                not stdout_assigned
                and not binding["permission_rules"]
            )
            or (stdout_assigned and binding["permission_rules"] != [])
            or binding["permission_rules"] != sorted(set(binding["permission_rules"]))
            or any(
                not isinstance(rule, str)
                or (
                    rule not in {"Glob", "Grep", "Read"}
                    and not rule.startswith("Edit(//")
                )
                for rule in binding["permission_rules"]
            )
            or not isinstance(binding.get("output_scope"), str)
            or not Path(str(binding["output_scope"])).is_absolute()
            or platform_fields is None
            or any(
                binding.get(key) != value
                for key, value in platform_fields.items()
            )
            or binding.get("binding_sha256") != _digest_json(core)
        ):
            raise WorkerExecutionError(
                "restricted Claude stage boundary is malformed or differs from the arm"
            )
        return dict(binding)
    if authority != "SERIALIZED_PLAMEN_STAGE" or not isinstance(binding, Mapping):
        raise WorkerExecutionError(
            "serialized write confinement lacks an active lease binding"
        )
    required = {
        "protocol",
        "lock_path",
        "state_path",
        "identity_sha256",
        "scope",
        "crash_recovery",
        "namespace_authority",
        "namespace_limitation",
        "lease_id",
        "owner_identity",
        "owner_pid",
        "state_sha256",
        "recovered_state_sha256",
        "active",
        "quarantined",
        "writable_roots_sha256",
    }
    if set(binding) != required:
        raise WorkerExecutionError(
            "serialized write-confinement binding fields are malformed"
        )
    capability_lease = capability.get("low_integrity_lease")
    if not isinstance(capability_lease, Mapping) or any(
        binding.get(key) != capability_lease.get(key)
        for key in (
            "protocol",
            "lock_path",
            "state_path",
            "identity_sha256",
            "scope",
            "crash_recovery",
            "namespace_authority",
            "namespace_limitation",
        )
    ):
        raise WorkerExecutionError(
            "serialized write-confinement lease does not match the arm"
        )
    if (
        binding.get("active") is not True
        or binding.get("quarantined") is not False
        or binding.get("owner_identity") != process_scope_identity
        or isinstance(binding.get("owner_pid"), bool)
        or not isinstance(binding.get("owner_pid"), int)
        or int(binding["owner_pid"]) <= 0
        or (
            require_current_process
            and binding.get("owner_pid") != os.getpid()
        )
        or not isinstance(binding.get("lease_id"), str)
        or not re.fullmatch(r"[0-9a-f]{32}", str(binding["lease_id"]))
        or not isinstance(binding.get("state_sha256"), str)
        or not _HEX_RE.fullmatch(str(binding["state_sha256"]))
        or (
            binding.get("recovered_state_sha256") is not None
            and (
                not isinstance(binding.get("recovered_state_sha256"), str)
                or not _HEX_RE.fullmatch(str(binding["recovered_state_sha256"]))
            )
        )
        or not isinstance(binding.get("writable_roots_sha256"), str)
        or not _HEX_RE.fullmatch(str(binding["writable_roots_sha256"]))
    ):
        raise WorkerExecutionError(
            "serialized write-confinement lease is not active and exact"
        )
    return dict(binding)


class WorkerExecutionError(RuntimeError):
    """The execution contract or its persisted evidence is invalid."""


class SemanticRuntimeDependencyUnsupported(WorkerExecutionError):
    """The host dependency authority cannot meet semantic immutability."""

    reason_code = "RUNTIME_DEPENDENCY_EDITABLE_UNSUPPORTED"


class WorkerExecutionIncomplete(WorkerExecutionError):
    """A provider-owned execution armed but did not produce a completion."""

    def __init__(self, message: str, *, arm_path: Path, debt_path: Path | None) -> None:
        super().__init__(message)
        self.arm_path = arm_path
        self.debt_path = debt_path


class _StagedOutputViolation(WorkerExecutionError):
    """A staged member is unsafe to enumerate or read as proposal material."""

    def __init__(self, reason_code: str, message: str) -> None:
        super().__init__(message)
        self.reason_code = _require_id(reason_code, "staged output reason code")


def _positive_decimal_text(value: Any, label: str) -> str:
    """Return one lossless, JSON-safe decimal spelling for a positive duration."""

    if isinstance(value, bool) or not isinstance(value, (int, float, str)):
        raise WorkerExecutionError(f"{label} must be positive")
    try:
        decimal = Decimal(str(value))
    except (InvalidOperation, ValueError) as exc:
        raise WorkerExecutionError(f"{label} must be positive") from exc
    if not decimal.is_finite() or decimal <= 0:
        raise WorkerExecutionError(f"{label} must be positive")
    normalized = format(decimal.normalize(), "f")
    return normalized.rstrip("0").rstrip(".") if "." in normalized else normalized


def _exact_nonnegative_int(value: Any, label: str) -> int:
    """Reject JSON booleans before any persisted integer comparison.

    Python equality makes ``False == 0`` and ``True == 1``.  Durable byte
    counts are protocol integers, so every replay boundary must establish the
    exact JSON type before comparing the value with observed bytes.
    """

    if type(value) is not int or value < 0:
        raise WorkerExecutionError(
            f"{label} must be an exact nonnegative integer"
        )
    return value


def _exact_positive_int(value: Any, label: str) -> int:
    """Return an exact positive JSON integer for durable timestamp fields."""

    try:
        exact = _exact_nonnegative_int(value, label)
    except WorkerExecutionError as exc:
        raise WorkerExecutionError(
            f"{label} must be an exact positive integer"
        ) from exc
    if exact == 0:
        raise WorkerExecutionError(
            f"{label} must be an exact positive integer"
        )
    return exact


def _byte_ceiling(value: Any, label: str) -> int:
    """Validate an exact, JSON-safe non-negative byte ceiling."""

    try:
        exact = _exact_nonnegative_int(value, f"{label} byte ceiling")
    except WorkerExecutionError as exc:
        raise WorkerExecutionError(
            f"{label} byte ceiling must be an integer between 0 and "
            f"{MAX_STREAM_LIMIT_BYTES}"
        ) from exc
    if exact > MAX_STREAM_LIMIT_BYTES:
        raise WorkerExecutionError(
            f"{label} byte ceiling must be an integer between 0 and "
            f"{MAX_STREAM_LIMIT_BYTES}"
        )
    return exact


def _output_source_mode(value: Any) -> str:
    if value not in {WORKER_FILE_OUTPUTS, STDOUT_ASSIGNED_OUTPUT}:
        raise WorkerExecutionError("output_source_mode is unsupported")
    return value


def _stream_limit_binding(value: Any) -> dict[str, int]:
    if not isinstance(value, dict) or set(value) != {"stdout_bytes", "stderr_bytes"}:
        raise WorkerExecutionError("stream limits binding is malformed")
    return {
        "stdout_bytes": _byte_ceiling(value["stdout_bytes"], "stdout"),
        "stderr_bytes": _byte_ceiling(value["stderr_bytes"], "stderr"),
    }


def _claude_stream_producer_exclusivity_capability() -> str:
    """Return only the producer-isolation claim established on this host."""

    if os.name == "nt":
        return "PRODUCER_EXCLUSIVITY_UNPROVEN_NATIVE_WINDOWS"
    return "PRODUCER_EXCLUSIVITY_NOT_ESTABLISHED"


def _runtime_file_record(value: str | os.PathLike[str], *, label: str) -> dict[str, Any]:
    """Content-bind a runtime file without treating its pathname as authority."""

    try:
        path = Path(value).resolve(strict=True)
        info = path.stat()
        if not stat.S_ISREG(info.st_mode):
            raise OSError("not a regular file")
        raw = path.read_bytes()
    except (OSError, TypeError, ValueError) as exc:
        raise WorkerExecutionError(
            f"Claude stream {label} cannot be content-bound"
        ) from exc
    return {
        "path": str(path),
        "size": len(raw),
        "sha256": _digest_bytes(raw),
    }


def _bound_runtime_file_record_from_authority(
    value: Any,
    *,
    expected_path: str,
    label: str,
) -> dict[str, Any]:
    """Replay a revoked attempt-private file from its already-bound record."""

    size = (
        _exact_nonnegative_int(value.get("size"), f"Claude stream bound {label} size")
        if isinstance(value, Mapping)
        else None
    )
    if (
        not isinstance(value, Mapping)
        or set(value) != {"path", "size", "sha256"}
        or value.get("path") != expected_path
        or size is None
        or not isinstance(value.get("sha256"), str)
        or not re.fullmatch(r"[0-9a-f]{64}", value["sha256"])
    ):
        raise WorkerExecutionError(
            f"Claude stream bound {label} authority is malformed"
        )
    return dict(value)


def _claude_bound_settings_binding_from_authority(
    value: Any,
    *,
    expected_path: str,
) -> dict[str, Any]:
    """Replay settings metadata after its attempt-private file is revoked.

    The exact settings bytes were validated before launch and replayed by the
    Claude runtime immediately before profile revocation.  Durable validation
    therefore reuses that arm-bound record while still replaying every external
    hook implementation file that remains live.
    """

    if not isinstance(value, Mapping):
        raise WorkerExecutionError(
            "Claude stream bound settings authority is malformed"
        )
    hook_authority = value.get("hook_authority")
    expected = {"path", "size", "sha256", "hook_authority"}
    if hook_authority is not None:
        expected.update(
            {"hook_executable", "hook_script", "hook_policy"}
        )
    if set(value) != expected:
        raise WorkerExecutionError(
            "Claude stream bound settings authority is malformed"
        )
    base = _bound_runtime_file_record_from_authority(
        {key: value[key] for key in ("path", "size", "sha256")},
        expected_path=expected_path,
        label="settings",
    )
    if hook_authority is None:
        base["hook_authority"] = None
        return base
    if (
        not isinstance(hook_authority, Mapping)
        or set(hook_authority)
        != {"hook_executable", "hook_script", "hook_policy"}
    ):
        raise WorkerExecutionError(
            "Claude stream bound settings hook authority is malformed"
        )
    replayed_hooks: dict[str, dict[str, Any]] = {}
    for name in ("hook_executable", "hook_script", "hook_policy"):
        record = hook_authority.get(name)
        if (
            not isinstance(record, Mapping)
            or set(record) != {"path", "size", "sha256"}
        ):
            raise WorkerExecutionError(
                "Claude stream bound settings hook authority is malformed"
            )
        _exact_nonnegative_int(
            record.get("size"),
            f"Claude stream bound settings {name} size",
        )
        replayed = _runtime_file_record(
            str(record.get("path") or ""),
            label=f"settings {name.replace('_', ' ')}",
        )
        if replayed != dict(record) or value.get(name) != dict(record):
            raise WorkerExecutionError(
                "Claude stream bound settings hook authority changed"
            )
        replayed_hooks[name] = replayed
    base["hook_authority"] = dict(replayed_hooks)
    base.update(replayed_hooks)
    return base


def _claude_mcp_config_binding(
    value: str | os.PathLike[str],
    *,
    allowed_servers: Sequence[str],
) -> dict[str, Any]:
    """Bind an MCP config without persisting secret values or their hashes."""

    record, raw = _claude_settings_runtime_file_record(
        value,
        label="MCP configuration",
    )
    payload = _parse_json_bytes(
        raw,
        label="Claude stream MCP configuration",
    )
    servers = payload.get("mcpServers")
    if (
        set(payload) != {"mcpServers"}
        or not isinstance(servers, dict)
        or sorted(servers) != list(allowed_servers)
    ):
        raise WorkerExecutionError(
            "Claude stream command MCP configuration server "
            "denominator differs from expected-init v2"
        )

    public_servers: dict[str, Any] = {}
    environment_names: dict[str, list[str]] = {}
    secret_bearing = False
    for name in allowed_servers:
        entry = servers.get(name)
        if (
            not isinstance(entry, dict)
            or "command" not in entry
            or not set(entry).issubset({"command", "args", "cwd", "env"})
            or not isinstance(entry.get("command"), str)
            or not entry["command"]
        ):
            raise WorkerExecutionError(
                "Claude stream command MCP server definition is unsupported"
            )
        arguments = entry.get("args", [])
        cwd_value = entry.get("cwd")
        environment = entry.get("env", {})
        if (
            not isinstance(arguments, list)
            or any(not isinstance(item, str) for item in arguments)
            or (
                cwd_value is not None
                and (
                    not isinstance(cwd_value, str)
                    or not cwd_value
                )
            )
            or not isinstance(environment, dict)
            or any(
                not isinstance(key, str)
                or not key
                or not isinstance(item, str)
                for key, item in environment.items()
            )
        ):
            raise WorkerExecutionError(
                "Claude stream command MCP server definition is malformed"
            )
        names = sorted(environment)
        if len({key.casefold() for key in names}) != len(names):
            raise WorkerExecutionError(
                "Claude stream command MCP environment denominator is ambiguous"
            )
        secret_bearing = secret_bearing or bool(names)
        environment_names[name] = names
        public_entry: dict[str, Any] = {
            "command": entry["command"],
            "args": list(arguments),
            "environment_names": names,
        }
        if cwd_value is not None:
            public_entry["cwd"] = cwd_value
        public_servers[name] = public_entry

    if not secret_bearing:
        return record
    public_structure = {
        "mcpServers": public_servers,
    }
    return {
        "path": record["path"],
        "size": record["size"],
        "privacy_mode": "EPHEMERAL_ENVIRONMENT_VALUES",
        "server_names": list(allowed_servers),
        "environment_names": environment_names,
        "public_structure_sha256": _digest_json(public_structure),
        "credential_values_recorded": False,
        "credential_content_hashes_recorded": False,
    }


def _claude_mcp_config_binding_from_authority(
    value: Any,
    *,
    expected_path: str,
    allowed_servers: Sequence[str],
) -> dict[str, Any]:
    """Replay an already-bound MCP record after private-file revocation."""

    if not isinstance(value, Mapping):
        raise WorkerExecutionError(
            "Claude stream bound MCP authority is malformed"
        )
    if set(value) == {"path", "size", "sha256"}:
        return _bound_runtime_file_record_from_authority(
            value,
            expected_path=expected_path,
            label="MCP configuration",
        )
    expected = {
        "path",
        "size",
        "privacy_mode",
        "server_names",
        "environment_names",
        "public_structure_sha256",
        "credential_values_recorded",
        "credential_content_hashes_recorded",
    }
    environment_names = value.get("environment_names")
    size = _exact_nonnegative_int(
        value.get("size"), "Claude stream bound MCP authority size"
    )
    if (
        set(value) != expected
        or value.get("path") != expected_path
        or size <= 0
        or value.get("privacy_mode")
        != "EPHEMERAL_ENVIRONMENT_VALUES"
        or value.get("server_names") != list(allowed_servers)
        or not isinstance(environment_names, Mapping)
        or sorted(environment_names) != list(allowed_servers)
        or any(
            not isinstance(names, list)
            or not names
            or names != sorted(set(names))
            or any(not isinstance(name, str) or not name for name in names)
            for names in environment_names.values()
        )
        or not isinstance(value.get("public_structure_sha256"), str)
        or not re.fullmatch(
            r"[0-9a-f]{64}",
            value["public_structure_sha256"],
        )
        or value.get("credential_values_recorded") is not False
        or value.get("credential_content_hashes_recorded") is not False
    ):
        raise WorkerExecutionError(
            "Claude stream bound MCP authority is malformed"
        )
    return {
        "path": value["path"],
        "size": value["size"],
        "privacy_mode": value["privacy_mode"],
        "server_names": list(value["server_names"]),
        "environment_names": {
            name: list(environment_names[name])
            for name in allowed_servers
        },
        "public_structure_sha256": value["public_structure_sha256"],
        "credential_values_recorded": False,
        "credential_content_hashes_recorded": False,
    }


def _claude_settings_runtime_file_record(
    value: str | os.PathLike[str],
    *,
    label: str,
    max_bytes: int = 1_000_000,
) -> tuple[dict[str, Any], bytes]:
    """Bind one absolute, unaliased Claude settings-closure file."""

    if not isinstance(value, (str, os.PathLike)):
        raise WorkerExecutionError(f"Claude stream {label} path is malformed")
    raw_path = os.fspath(value)
    if (
        not isinstance(raw_path, str)
        or not raw_path
        or "\x00" in raw_path
        or not Path(raw_path).is_absolute()
    ):
        raise WorkerExecutionError(
            f"Claude stream {label} path must be absolute"
        )
    path = _safe_external_file(raw_path, label=f"Claude stream {label}")
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise WorkerExecutionError(
            f"Claude stream {label} cannot be replayed"
        ) from exc
    if len(raw) > max_bytes:
        raise WorkerExecutionError(
            f"Claude stream {label} exceeds its byte ceiling"
        )
    return (
        {
            "path": str(path),
            "size": len(raw),
            "sha256": _digest_bytes(raw),
        },
        raw,
    )


def _claude_bound_settings_binding(
    value: str | os.PathLike[str],
    *,
    restricted_analysis: bool = False,
    bounded_web: bool = False,
) -> dict[str, Any]:
    """Validate and bind the exact hook-enforced Claude settings overlay."""

    record, raw = _claude_settings_runtime_file_record(
        value,
        label="settings",
    )
    settings = _strict_json(raw, label="Claude stream settings")
    try:
        settings = _claude_phase_tool_policy.validate_settings_overlay(
            settings,
            restricted_analysis=restricted_analysis,
            bounded_web=bounded_web,
        )
    except _claude_phase_tool_policy.ClaudePhaseToolPolicyError as exc:
        raise WorkerExecutionError(
            f"Claude stream settings capability denominator is malformed: {exc}"
        ) from exc

    hooks = settings["hooks"]
    binding: dict[str, Any] = dict(record)
    if not hooks:
        binding["hook_authority"] = None
        return binding

    pre_tool = hooks["PreToolUse"]
    group = pre_tool[0]
    if (
        not isinstance(group, dict)
        or set(group) != {"matcher", "hooks"}
        or group.get("matcher") != ".*"
        or not isinstance(group.get("hooks"), list)
        or len(group["hooks"]) != 1
    ):
        raise WorkerExecutionError(
            "Claude stream settings PreToolUse hook group is malformed"
        )
    hook = group["hooks"][0]
    if (
        not isinstance(hook, dict)
        or set(hook) != {"type", "command", "args", "timeout"}
        or hook.get("type") != "command"
        or isinstance(hook.get("timeout"), bool)
        or not isinstance(hook.get("timeout"), int)
        or not 1 <= hook["timeout"] <= 300
    ):
        raise WorkerExecutionError(
            "Claude stream settings command hook is malformed"
        )
    arguments = hook.get("args")
    if (
        not isinstance(arguments, list)
        or len(arguments) != 3
        or any(not isinstance(item, str) or not item for item in arguments)
        or arguments[1] != "--policy"
    ):
        raise WorkerExecutionError(
            "Claude stream settings hook arguments are malformed"
        )
    executable, _ = _claude_settings_runtime_file_record(
        hook.get("command"),
        label="settings hook executable",
        max_bytes=256 * 1024 * 1024,
    )
    hook_script, _ = _claude_settings_runtime_file_record(
        arguments[0],
        label="settings hook script",
    )
    hook_policy, _ = _claude_settings_runtime_file_record(
        arguments[2],
        label="settings hook policy",
    )
    binding["hook_authority"] = {
        "hook_executable": executable,
        "hook_script": hook_script,
        "hook_policy": hook_policy,
    }
    # Keep the three content bindings at top level too: this is the stable
    # receipt shape consumed by existing implementation-closure tests.
    binding["hook_executable"] = executable
    binding["hook_script"] = hook_script
    binding["hook_policy"] = hook_policy
    return binding


def _bounded_web_receipt_lifecycle_from_launch_request(
    request: Mapping[str, Any] | None,
    provider_stdout: Mapping[str, Any] | None,
) -> dict[str, Any] | None:
    """Replay the exact hook receipt set before completion authority."""

    if request is None:
        return None
    policy = request.get("policy")
    profile = policy.get("headless_profile") if isinstance(policy, Mapping) else None
    init_contract = (
        profile.get("expected_init_contract")
        if isinstance(profile, Mapping)
        else None
    )
    capabilities = (
        init_contract.get("required_capabilities")
        if isinstance(init_contract, Mapping)
        else None
    )
    if capabilities != ["vendor-restricted-web-analysis"]:
        return None
    command_contract = (
        provider_stdout.get("command_contract")
        if isinstance(provider_stdout, Mapping)
        else None
    )
    runtime_profile = (
        command_contract.get("headless_profile")
        if isinstance(command_contract, Mapping)
        else None
    )
    settings = (
        runtime_profile.get("settings")
        if isinstance(runtime_profile, Mapping)
        else None
    )
    hook_policy = settings.get("hook_policy") if isinstance(settings, Mapping) else None
    path = hook_policy.get("path") if isinstance(hook_policy, Mapping) else None
    expected_session_id = (
        provider_stdout.get("expected_session_id")
        if isinstance(provider_stdout, Mapping)
        else None
    )
    if (
        not isinstance(path, str) or not path or not Path(path).is_absolute()
        or not isinstance(expected_session_id, str) or not expected_session_id
    ):
        raise WorkerExecutionError(
            "bounded-web launch lacks exact hook-policy/session authority"
        )
    try:
        manifest = _claude_phase_tool_policy.load_policy(Path(path))
        return _claude_phase_tool_policy.bounded_web_receipt_lifecycle_projection(
            manifest, expected_session_id=expected_session_id,
        )
    except (
        _claude_phase_tool_policy.ClaudePhaseToolPolicyError,
        OSError,
        RuntimeError,
        TypeError,
        ValueError,
    ) as exc:
        raise WorkerExecutionError(
            f"bounded-web receipt lifecycle is incomplete: {exc}"
        ) from exc


def _runtime_loader_identity(loader: Any) -> str:
    """Return a stable, non-repr identity for an import loader."""

    loader_type = loader if isinstance(loader, type) else type(loader)
    module = getattr(loader_type, "__module__", None)
    qualname = getattr(loader_type, "__qualname__", None)
    if not isinstance(module, str) or not module or not isinstance(qualname, str):
        raise WorkerExecutionError(
            "Claude stream parser runtime loader has no stable identity"
        )
    return f"{module}.{qualname}"


def _runtime_module_code_sha256(module: Any, *, name: str) -> str | None:
    """Fingerprint the Python code objects actually installed by one module."""

    records: list[tuple[str, str]] = []
    observed: set[int] = set()

    def constant_binding(value: Any) -> Any:
        if value is None or isinstance(value, (bool, int, str)):
            return value
        if isinstance(value, float):
            return {"type": "float", "hex": value.hex()}
        if isinstance(value, complex):
            return {
                "type": "complex",
                "real": value.real.hex(),
                "imag": value.imag.hex(),
            }
        if isinstance(value, bytes):
            return {"type": "bytes", "hex": value.hex()}
        if isinstance(value, tuple):
            return {
                "type": "tuple",
                "items": [constant_binding(item) for item in value],
            }
        if isinstance(value, frozenset):
            items = [constant_binding(item) for item in value]
            items.sort(key=_canonical_json)
            return {"type": "frozenset", "items": items}
        if isinstance(value, types.CodeType):
            return {"type": "code", "value": code_binding(value)}
        if value is Ellipsis:
            return {"type": "ellipsis"}
        if value is NotImplemented:
            return {"type": "not_implemented"}
        raise WorkerExecutionError(
            f"Claude stream runtime module {name!r} has an unsupported "
            f"code constant of type {type(value).__name__}"
        )

    def code_binding(code: types.CodeType) -> dict[str, Any]:
        """Use de-optimized public code fields, not mutable quickened bytes."""

        return {
            "name": code.co_name,
            "qualname": code.co_qualname,
            "firstlineno": int(code.co_firstlineno),
            "argcount": int(code.co_argcount),
            "posonlyargcount": int(code.co_posonlyargcount),
            "kwonlyargcount": int(code.co_kwonlyargcount),
            "nlocals": int(code.co_nlocals),
            "stacksize": int(code.co_stacksize),
            "flags": int(code.co_flags),
            "bytecode_sha256": _digest_bytes(code.co_code),
            "linetable_sha256": _digest_bytes(code.co_linetable),
            "exceptiontable_sha256": _digest_bytes(code.co_exceptiontable),
            "constants": [constant_binding(item) for item in code.co_consts],
            "names": list(code.co_names),
            "varnames": list(code.co_varnames),
            "freevars": list(code.co_freevars),
            "cellvars": list(code.co_cellvars),
        }

    def bind_function(value: Any, qualname: str) -> None:
        if isinstance(value, (staticmethod, classmethod)):
            value = value.__func__
        if isinstance(value, property):
            for suffix, member in (
                ("fget", value.fget),
                ("fset", value.fset),
                ("fdel", value.fdel),
            ):
                if member is not None:
                    bind_function(member, f"{qualname}.{suffix}")
            return
        if not isinstance(value, types.FunctionType):
            return
        if getattr(value, "__module__", None) != name or id(value) in observed:
            return
        observed.add(id(value))
        try:
            raw = _canonical_json(code_binding(value.__code__))
        except (TypeError, ValueError) as exc:
            raise WorkerExecutionError(
                f"Claude stream runtime module {name!r} code cannot be bound"
            ) from exc
        records.append((qualname, _digest_bytes(raw)))

    for key, value in vars(module).items():
        bind_function(value, str(key))
        if isinstance(value, type) and getattr(value, "__module__", None) == name:
            for member_name, member in vars(value).items():
                bind_function(member, f"{value.__qualname__}.{member_name}")
    if not records:
        return None
    records.sort()
    return _digest_bytes(_canonical_json(records))


def _runtime_module_record(name: str) -> dict[str, Any]:
    """Content-bind one loaded module's authoritative import origin and code."""

    try:
        module = importlib.import_module(name)
    except (ImportError, ValueError) as exc:
        raise WorkerExecutionError(
            f"Claude stream parser runtime module {name!r} is unavailable"
        ) from exc
    spec = getattr(module, "__spec__", None)
    origin = getattr(spec, "origin", None)
    loader = getattr(spec, "loader", None)
    if spec is None or loader is None or not isinstance(origin, str) or not origin:
        raise WorkerExecutionError(
            f"Claude stream parser runtime module {name!r} has no "
            "content-bound origin"
        )

    loader_identity = _runtime_loader_identity(loader)
    files: list[dict[str, Any]] = []
    archive = getattr(loader, "archive", None)
    if origin in {"built-in", "frozen"}:
        origin_kind = origin.upper().replace("-", "_")
    elif isinstance(archive, str) and archive:
        origin_kind = "ZIP_ARCHIVE"
        files.append(
            _runtime_file_record(
                archive,
                label=f"runtime module {name!r} archive",
            )
        )
    else:
        suffix = Path(origin).suffix.lower()
        if suffix in {".pyd", ".so", ".dylib", ".dll"}:
            origin_kind = "EXTENSION"
        elif suffix in {".pyc", ".pyo"}:
            origin_kind = "BYTECODE"
        else:
            origin_kind = "SOURCE"
        files.append(
            _runtime_file_record(
                origin,
                label=f"runtime module {name!r}",
            )
        )

    return {
        "module": name,
        "origin": origin,
        "origin_kind": origin_kind,
        "loader": loader_identity,
        "code_sha256": _runtime_module_code_sha256(module, name=name),
        "files": sorted(files, key=lambda row: row["path"]),
    }


def _windows_module_path(handle: int, *, label: str) -> Path:
    """Resolve one loaded Windows image handle to its kernel-known path."""

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    get_name = kernel32.GetModuleFileNameW
    get_name.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_uint32]
    get_name.restype = ctypes.c_uint32
    size = 512
    while size <= 32768:
        buffer = ctypes.create_unicode_buffer(size)
        ctypes.set_last_error(0)
        written = int(get_name(ctypes.c_void_p(handle), buffer, size))
        if written == 0:
            break
        if written < size - 1:
            try:
                return Path(buffer.value).resolve(strict=True)
            except (OSError, ValueError) as exc:
                raise WorkerExecutionError(
                    f"Claude stream {label} cannot be content-bound"
                ) from exc
        size *= 2
    raise WorkerExecutionError(
        f"Claude stream {label} cannot be content-bound"
    )


def _loaded_native_image_paths() -> tuple[Path, ...]:
    """Enumerate loaded native images using the current OS authority."""

    paths: set[Path] = set()
    if sys.platform == "win32":
        psapi = ctypes.WinDLL("psapi", use_last_error=True)
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        get_process = kernel32.GetCurrentProcess
        get_process.restype = ctypes.c_void_p
        enum_modules = psapi.EnumProcessModulesEx
        enum_modules.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_uint32),
            ctypes.c_uint32,
        ]
        enum_modules.restype = ctypes.c_int
        capacity = 256
        while capacity <= 16384:
            modules = (ctypes.c_void_p * capacity)()
            needed = ctypes.c_uint32()
            if not enum_modules(
                get_process(),
                modules,
                ctypes.sizeof(modules),
                ctypes.byref(needed),
                0x03,  # LIST_MODULES_ALL
            ):
                raise WorkerExecutionError(
                    "Claude stream loaded native images cannot be enumerated"
                )
            count = int(needed.value) // ctypes.sizeof(ctypes.c_void_p)
            if count <= capacity:
                for index in range(count):
                    handle = int(modules[index] or 0)
                    if handle:
                        paths.add(
                            _windows_module_path(
                                handle,
                                label="loaded native image",
                            )
                        )
                return tuple(sorted(paths, key=lambda path: str(path)))
            capacity = count + 32
        raise WorkerExecutionError(
            "Claude stream loaded native image denominator is unbounded"
        )

    if sys.platform == "darwin":
        process = ctypes.CDLL(None)
        image_count = process._dyld_image_count
        image_count.restype = ctypes.c_uint32
        image_name = process._dyld_get_image_name
        image_name.argtypes = [ctypes.c_uint32]
        image_name.restype = ctypes.c_char_p
        for index in range(int(image_count())):
            raw = image_name(index)
            if not raw:
                raise WorkerExecutionError(
                    "Claude stream loaded native image has no path"
                )
            try:
                paths.add(
                    Path(os.fsdecode(raw)).resolve(strict=True)
                )
            except (OSError, TypeError, ValueError) as exc:
                raise WorkerExecutionError(
                    "Claude stream loaded native image cannot be content-bound"
                ) from exc
        return tuple(sorted(paths, key=lambda path: str(path)))

    maps_path = Path("/proc/self/maps")
    if maps_path.is_file():
        try:
            for line in maps_path.read_text(
                encoding="utf-8",
                errors="surrogateescape",
            ).splitlines():
                fields = line.split(maxsplit=5)
                if len(fields) != 6 or not fields[5].startswith("/"):
                    continue
                candidate = fields[5]
                if candidate.endswith(" (deleted)"):
                    raise WorkerExecutionError(
                        "Claude stream loaded native image was deleted"
                    )
                paths.add(Path(candidate).resolve(strict=True))
        except (OSError, ValueError) as exc:
            raise WorkerExecutionError(
                "Claude stream loaded native images cannot be enumerated"
            ) from exc
        return tuple(sorted(paths, key=lambda path: str(path)))

    raise WorkerExecutionError(
        "Claude stream loaded native images cannot be enumerated on this platform"
    )


def _python_runtime_native_path() -> Path:
    """Resolve the shared Python runtime/framework actually executing code."""

    if sys.platform == "win32":
        handle = int(getattr(ctypes.pythonapi, "_handle", 0) or 0)
        if not handle:
            raise WorkerExecutionError(
                "Claude stream Python runtime library handle is unavailable"
            )
        return _windows_module_path(handle, label="Python runtime library")

    class _DlInfo(ctypes.Structure):
        _fields_ = [
            ("dli_fname", ctypes.c_char_p),
            ("dli_fbase", ctypes.c_void_p),
            ("dli_sname", ctypes.c_char_p),
            ("dli_saddr", ctypes.c_void_p),
        ]

    process = ctypes.CDLL(None)
    dladdr = getattr(process, "dladdr", None)
    if dladdr is None:
        raise WorkerExecutionError(
            "Claude stream Python runtime ownership cannot be discovered"
        )
    dladdr.argtypes = [ctypes.c_void_p, ctypes.POINTER(_DlInfo)]
    dladdr.restype = ctypes.c_int
    symbol = ctypes.cast(ctypes.pythonapi.Py_GetVersion, ctypes.c_void_p)
    info = _DlInfo()
    if not dladdr(symbol, ctypes.byref(info)) or not info.dli_fname:
        raise WorkerExecutionError(
            "Claude stream Python runtime ownership cannot be discovered"
        )
    try:
        return Path(os.fsdecode(info.dli_fname)).resolve(strict=True)
    except (OSError, TypeError, ValueError) as exc:
        raise WorkerExecutionError(
            "Claude stream Python runtime library cannot be content-bound"
        ) from exc


def _native_binary_records(
    modules: Sequence[Mapping[str, Any]],
    *,
    crypto_provider_module: str,
) -> list[dict[str, Any]]:
    """Bind the interpreter, runtime, extensions, and active crypto provider."""

    roles_by_path: dict[Path, set[str]] = {}

    def add(path_value: str | os.PathLike[str], role: str) -> None:
        try:
            path = Path(path_value).resolve(strict=True)
        except (OSError, TypeError, ValueError) as exc:
            raise WorkerExecutionError(
                f"Claude stream native binary for {role} cannot be content-bound"
            ) from exc
        roles_by_path.setdefault(path, set()).add(role)

    add(sys.executable, "interpreter_executable")
    runtime = _python_runtime_native_path()
    runtime_role = (
        "python_runtime_executable"
        if runtime == Path(sys.executable).resolve(strict=True)
        else "python_runtime_library"
    )
    if (
        (sys.platform == "darwin" or sysconfig.get_config_var("Py_ENABLE_SHARED"))
        and runtime_role != "python_runtime_library"
    ):
        raise WorkerExecutionError(
            "Claude stream shared Python runtime library cannot be distinguished"
        )
    add(runtime, runtime_role)

    for module in modules:
        if module.get("origin_kind") != "EXTENSION":
            continue
        name = str(module.get("module"))
        files = module.get("files")
        if not isinstance(files, list) or len(files) != 1:
            raise WorkerExecutionError(
                f"Claude stream extension module {name!r} is not file-bound"
            )
        add(str(files[0]["path"]), f"extension_module:{name}")

    if crypto_provider_module == "_hashlib":
        crypto_paths = [
            path
            for path in _loaded_native_image_paths()
            if re.search(
                r"(?:^libcrypto(?:[-._]|$)|^libeay(?:32|64)?(?:[-._]|$)"
                r"|^crypto[-._])",
                path.name.lower(),
            )
        ]
        if not crypto_paths:
            raise WorkerExecutionError(
                "Claude stream cryptographic provider library cannot be discovered"
            )
        for path in crypto_paths:
            add(path, "crypto_provider_library")

    records: list[dict[str, Any]] = []
    for path, roles in roles_by_path.items():
        record = _runtime_file_record(path, label="native binary")
        record["roles"] = sorted(roles)
        records.append(record)
    records.sort(key=lambda row: row["path"])
    return records


def _claude_stream_parser_runtime_binding() -> dict[str, Any]:
    """Bind the complete reviewed parser/runtime implementation denominator.

    Source paths alone are insufficient: executed code may be frozen, loaded
    from bytecode/archives, or implemented by native extensions and shared
    libraries.  Bind authoritative module origins, installed Python code
    objects, the interpreter core, native extension images, and the active
    cryptographic provider.  Replay reconstructs this record exactly.
    """

    executable = sys.executable
    if not isinstance(executable, str) or not executable:
        raise WorkerExecutionError(
            "Claude stream parser interpreter has no content-bindable executable"
        )
    crypto_provider_module = str(getattr(hashlib.sha256, "__module__", ""))
    if not crypto_provider_module:
        raise WorkerExecutionError(
            "Claude stream cryptographic provider module is unavailable"
        )
    module_names = {
        "_abc",
        "_codecs",
        "_collections_abc",
        "_json",
        "_sre",
        "abc",
        "builtins",
        "claude_stream_json_evidence",
        "codecs",
        "collections",
        "collections.abc",
        "dataclasses",
        "encodings",
        "encodings.utf_8",
        "hashlib",
        "json",
        "json.decoder",
        "json.encoder",
        "json.scanner",
        "math",
        "pathlib",
        "re",
        "sys",
        "typing",
        "unicodedata",
        crypto_provider_module,
    }
    modules = [
        _runtime_module_record(name)
        for name in sorted(module_names)
    ]
    native_binaries = _native_binary_records(
        modules,
        crypto_provider_module=crypto_provider_module,
    )
    version = sys.version_info
    implementation_version = sys.implementation.version
    return {
        "schema": "plamen.claude_stream_parser_runtime.v2",
        "implementation": sys.implementation.name,
        "implementation_cache_tag": sys.implementation.cache_tag,
        "implementation_version": [
            int(implementation_version.major),
            int(implementation_version.minor),
            int(implementation_version.micro),
            str(implementation_version.releaselevel),
            int(implementation_version.serial),
        ],
        "python_version": [
            int(version.major),
            int(version.minor),
            int(version.micro),
            str(version.releaselevel),
            int(version.serial),
        ],
        "hexversion": int(sys.hexversion),
        "byteorder": sys.byteorder,
        "filesystem_encoding": sys.getfilesystemencoding(),
        "filesystem_errors": sys.getfilesystemencodeerrors(),
        "unicode_database_version": unicodedata.unidata_version,
        "os_name": os.name,
        "platform": sys.platform,
        "executable": _runtime_file_record(
            executable,
            label="interpreter executable",
        ),
        "crypto_provider_module": crypto_provider_module,
        "modules": modules,
        "native_binaries": native_binaries,
    }


def _single_cli_option_value(
    argv: Sequence[str],
    option: str,
    *,
    allow_empty: bool = False,
) -> str:
    positions = [index for index, value in enumerate(argv) if value == option]
    if len(positions) != 1 or positions[0] + 1 >= len(argv):
        raise WorkerExecutionError(
            f"Claude stream command requires exactly one {option}"
        )
    value = argv[positions[0] + 1]
    if (
        not isinstance(value, str)
        or (not value and not allow_empty)
        or value.startswith("-")
    ):
        raise WorkerExecutionError(f"Claude stream {option} value is invalid")
    return value


def _installed_claude_backend_front() -> str:
    leaf = "plamen.cmd" if os.name == "nt" else "plamen"
    return os.path.abspath(os.path.expanduser(f"~/.local/bin/{leaf}"))


def _claude_semantic_argv(argv: Sequence[str]) -> list[str]:
    """Strip only the authenticated generation-front envelope.

    The backend member stays opaque to WER.  WER validates the exact public
    launcher grammar and then applies the existing Claude CLI rules solely to
    the suffix after the single option terminator.
    """

    values = list(argv)
    if "--" not in values:
        return values
    option_names = (
        "--generation",
        "--receipt-sha256",
        "--census-sha256",
        "--request-sha256",
        "--policy-sha256",
    )
    if (
        len(values) <= 15
        or values.count("--") != 1
        or values[:4]
        != [
            _installed_claude_backend_front(),
            "backend-launch",
            "--backend",
            "claude",
        ]
        or values[14] != "--"
        or any(
            values[4 + index * 2] != name
            for index, name in enumerate(option_names)
        )
        or re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", values[5]
        )
        is None
        or any(
            re.fullmatch(r"[0-9a-f]{64}", values[index]) is None
            for index in (7, 9, 11, 13)
        )
    ):
        raise WorkerExecutionError(
            "Claude stream command backend-launch envelope is malformed"
        )
    return [values[0], *values[15:]]


def _claude_stream_stdout_binding(
    configuration: Mapping[str, Any],
    *,
    argv: Sequence[str],
    stdout_limit_bytes: int,
    cwd: Path,
    effective_model: str,
    bound_headless_profile_authority: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Bind the exact non-partial Claude print-mode stdout protocol."""

    expected_fields = {
        "schema",
        "expected_session_id",
        "expected_init_contract",
        "max_line_bytes",
        "max_stream_bytes",
    }
    if not isinstance(configuration, Mapping) or set(configuration) != expected_fields:
        raise WorkerExecutionError(
            "Claude stream stdout configuration has schema drift"
        )
    if configuration.get("schema") != CLAUDE_STREAM_STDOUT_CONFIGURATION_SCHEMA:
        raise WorkerExecutionError(
            "Claude stream stdout configuration schema is unsupported"
        )
    session_id = configuration.get("expected_session_id")
    try:
        canonical_session_id = str(uuid.UUID(str(session_id)))
    except (ValueError, TypeError, AttributeError) as exc:
        raise WorkerExecutionError(
            "Claude stream expected session ID is invalid"
        ) from exc
    if session_id != canonical_session_id:
        raise WorkerExecutionError(
            "Claude stream expected session ID is not canonical"
        )
    max_line = configuration.get("max_line_bytes")
    max_stream = configuration.get("max_stream_bytes")
    if (
        isinstance(max_line, bool)
        or not isinstance(max_line, int)
        or max_line <= 0
        or max_line > 16 * 1024 * 1024
        or isinstance(max_stream, bool)
        or not isinstance(max_stream, int)
        or max_stream != stdout_limit_bytes
        or max_stream <= max_line
    ):
        raise WorkerExecutionError(
            "Claude stream parser ceilings conflict with the armed stdout limit"
        )
    try:
        expected_init_contract = _normalize_claude_expected_init(
            configuration.get("expected_init_contract")
        )
    except _ClaudeStreamJsonEvidenceError as exc:
        raise WorkerExecutionError(
            f"Claude expected init contract is invalid: {exc}"
        ) from exc
    if expected_init_contract["cwd"] != str(cwd):
        raise WorkerExecutionError(
            "Claude expected init cwd differs from the armed process cwd"
        )

    if not isinstance(argv, Sequence) or any(
        not isinstance(value, str) for value in argv
    ):
        raise WorkerExecutionError("Claude stream command argv is malformed")
    argv = _claude_semantic_argv(argv)
    equals_options = sorted(
        value
        for value in argv
        if value.startswith("-")
        and "=" in value
        and value != "--setting-sources="
    )
    if equals_options:
        raise WorkerExecutionError(
            "Claude stream command equals-form options are unsupported: "
            + ",".join(equals_options)
        )
    shadow_short_options = sorted(
        value
        for value in argv
        if not value.startswith("--")
        and len(value) > 2
        and value[:2] in {"-p", "-r", "-c"}
    )
    if shadow_short_options:
        raise WorkerExecutionError(
            "Claude stream command attached short options are unsupported: "
            + ",".join(shadow_short_options)
        )
    if argv.count("-p") != 1 or "--print" in argv:
        raise WorkerExecutionError(
            "Claude stream command requires exactly one canonical -p flag"
        )
    if argv.count("--model") != 1 or argv.index("--model") != argv.index("-p") + 1:
        raise WorkerExecutionError(
            "Claude stream command must receive its prompt only through bound stdin"
        )
    if _single_cli_option_value(argv, "--output-format") != "stream-json":
        raise WorkerExecutionError(
            "Claude stream command output format is not stream-json"
        )
    if _single_cli_option_value(argv, "--session-id") != canonical_session_id:
        raise WorkerExecutionError(
            "Claude stream command session differs from its evidence binding"
        )
    if _single_cli_option_value(argv, "--model") != effective_model:
        raise WorkerExecutionError(
            "Claude stream command model differs from its semantic binding"
        )
    if argv.count("--verbose") != 1:
        raise WorkerExecutionError(
            "Claude stream command requires exactly one verbose flag"
        )
    if argv.count("--no-session-persistence") != 1:
        raise WorkerExecutionError(
            "Claude stream command requires exactly one "
            "--no-session-persistence flag"
        )
    forbidden = {
        "--include-partial-messages",
        "--forward-subagent-output",
        "--forward-subagent-text",
        "--continue",
        "-c",
        "--resume",
        "-r",
        "--from-pr",
        "--fork-session",
    }
    rejected = sorted(flag for flag in forbidden if flag in argv)
    if rejected:
        raise WorkerExecutionError(
            "Claude stream command enables unsupported output/session flags: "
            + ",".join(rejected)
        )
    if "--disallowedTools" in argv or any(
        value.startswith("--disallowedTools=") for value in argv
    ):
        raise WorkerExecutionError(
            "Claude stream command disallowedTools creates a second "
            "capability denominator"
        )
    if "--allowed-tools" in argv or any(
        value.startswith("--allowed-tools=") for value in argv
    ):
        raise WorkerExecutionError(
            "Claude stream command allowed-tools alias is unsupported"
        )
    critical_argv_order = [
        "-p",
        "--model",
        "--output-format",
        "--verbose",
        "--session-id",
        "--no-session-persistence",
    ]
    critical_positions = [argv.index(flag) for flag in critical_argv_order]
    if critical_positions != sorted(critical_positions):
        raise WorkerExecutionError(
            "Claude stream command security-critical flags are out of "
            "canonical order"
        )
    profile_prefixes = (
        "--tools",
        "--allowedTools",
        "--disable-slash-commands",
        "--setting-sources",
        "--no-chrome",
        "--prompt-suggestions",
        "--safe-mode",
        "--restricted",
        "--dangerously-skip-permissions",
        "--permission-mode",
        "--settings",
        "--strict-mcp-config",
        "--mcp-config",
    )
    profile_configured = any(
        value == prefix or value.startswith(prefix + "=")
        for value in argv
        for prefix in profile_prefixes
    )
    expected_init_v2 = (
        expected_init_contract.get("schema")
        == _CLAUDE_EXPECTED_INIT_SECURITY_SCHEMA
    )
    if expected_init_v2 and not profile_configured:
        raise WorkerExecutionError(
            "Claude stream command expected-init v2 requires a complete "
            "secure headless profile"
        )
    headless_profile: dict[str, Any] | None = None
    if profile_configured:
        if "--setting-sources" in argv:
            raise WorkerExecutionError(
                "Claude stream command requires the canonical empty "
                "--setting-sources= spelling"
            )
        singleton_flags = (
            "--disable-slash-commands",
            "--setting-sources=",
            "--no-chrome",
        )
        if any(argv.count(flag) != 1 for flag in singleton_flags):
            raise WorkerExecutionError(
                "Claude stream command headless-profile flags must each "
                "occur exactly once"
            )
        if argv.count("--safe-mode") > 1:
            raise WorkerExecutionError(
                "Claude stream command --safe-mode must occur at most once"
            )
        tools = _single_cli_option_value(
            argv,
            "--tools",
            allow_empty=True,
        )
        tool_names = [] if tools == "" else tools.split(",")
        if (
            any(
                not re.fullmatch(r"[A-Za-z][A-Za-z0-9_:-]*", name)
                for name in tool_names
            )
            or len(set(tool_names)) != len(tool_names)
            or (not tool_names and not expected_init_v2)
        ):
            raise WorkerExecutionError(
                "Claude stream command --tools value is not canonical"
            )
        prompt_suggestions = _single_cli_option_value(
            argv,
            "--prompt-suggestions",
        )
        if prompt_suggestions != "false":
            raise WorkerExecutionError(
                "Claude stream command prompt suggestions must be disabled"
            )
        if expected_init_v2:
            allowed_tools = expected_init_contract.get("allowed_tools")
            if not isinstance(allowed_tools, list) or tool_names != allowed_tools:
                raise WorkerExecutionError(
                    "Claude stream command --tools denominator differs from "
                    "expected-init v2"
                )
            permission_mode = expected_init_contract.get("permission_mode")
            restricted_lane = _restricted_claude_capability_lane(
                expected_init_contract
            )
            restricted_expected = restricted_lane is not None
            restricted_web_expected = restricted_lane == "BOUNDED_WEB"
            allowed_tools_count = argv.count("--allowedTools")
            if restricted_web_expected:
                allowed_tools_value = _single_cli_option_value(
                    argv,
                    "--allowedTools",
                )
                if (
                    allowed_tools_count != 1
                    or allowed_tools_value.split(",")
                    != _RESTRICTED_CLAUDE_WEB_ALLOWED_TOOLS
                ):
                    raise WorkerExecutionError(
                        "Claude stream bounded-web allowedTools denominator "
                        "is not exact"
                    )
            elif allowed_tools_count != 0:
                raise WorkerExecutionError(
                    "Claude stream allowedTools is restricted to bounded web"
                )
            dangerous_count = argv.count(
                "--dangerously-skip-permissions"
            )
            permission_count = argv.count("--permission-mode")
            if permission_mode == "bypassPermissions":
                if (
                    dangerous_count != 1
                    or permission_count != 0
                    or argv.count("--restricted") != 0
                ):
                    raise WorkerExecutionError(
                        "Claude stream command bypassPermissions argv is not exact"
                    )
            elif permission_mode == "dontAsk":
                if (
                    dangerous_count != 0
                    or permission_count != 1
                    or _single_cli_option_value(argv, "--permission-mode")
                    != "dontAsk"
                    or (
                        restricted_expected
                        and argv.count("--restricted") != 1
                    )
                    or (
                        not restricted_expected
                        and argv.count("--restricted") != 0
                    )
                ):
                    raise WorkerExecutionError(
                        "Claude stream command dontAsk argv is not exact"
                    )
            elif permission_mode == "default":
                if (
                    restricted_lane not in {"FILESYSTEM", "BOUNDED_WEB"}
                    or dangerous_count != 0
                    or permission_count != 1
                    or _single_cli_option_value(argv, "--permission-mode")
                    != "default"
                    or argv.count("--restricted") != 1
                ):
                    raise WorkerExecutionError(
                        "Claude stream command restricted default argv is "
                        "not exact"
                    )
            else:
                raise WorkerExecutionError(
                    "Claude stream command expected-init permission mode "
                    "is unsupported"
                )

            allowed_mcp_servers = expected_init_contract.get(
                "allowed_mcp_servers"
            )
            allowed_tool_prefixes = expected_init_contract.get(
                "allowed_tool_prefixes"
            )
            mcp_enabled = bool(allowed_mcp_servers) or (
                isinstance(allowed_tool_prefixes, list)
                and "mcp__" in allowed_tool_prefixes
            )
            strict_mcp_count = argv.count("--strict-mcp-config")
            mcp_config_count = argv.count("--mcp-config")
            settings_count = argv.count("--settings")
            safe_mode = argv.count("--safe-mode") == 1
            if mcp_enabled and safe_mode:
                raise WorkerExecutionError(
                    "Claude stream command safe mode conflicts with "
                    "expected-init MCP authority"
                )
            if safe_mode:
                if settings_count:
                    raise WorkerExecutionError(
                        "Claude stream safe-mode settings authority is forbidden"
                    )
                settings_binding = None
            else:
                if settings_count != 1:
                    raise WorkerExecutionError(
                        "Claude stream bound settings require exactly one "
                        "--settings file"
                    )
                settings_path = _single_cli_option_value(
                    argv,
                    "--settings",
                )
                settings_binding = (
                    _claude_bound_settings_binding(
                        settings_path,
                        restricted_analysis=restricted_expected,
                        bounded_web=restricted_web_expected,
                    )
                    if bound_headless_profile_authority is None
                    else _claude_bound_settings_binding_from_authority(
                        bound_headless_profile_authority.get("settings"),
                        expected_path=settings_path,
                    )
                )
            # Bound-settings launches pin an explicit MCP denominator even
            # when it is empty; safe mode owns the no-config alternative.
            if mcp_enabled or not safe_mode:
                if strict_mcp_count != 1 or mcp_config_count != 1:
                    raise WorkerExecutionError(
                        "Claude stream command bound settings require one "
                        "strict MCP configuration"
                    )
                mcp_config_path = _single_cli_option_value(
                    argv,
                    "--mcp-config",
                )
                mcp_config_binding = (
                    _claude_mcp_config_binding(
                        mcp_config_path,
                        allowed_servers=allowed_mcp_servers,
                    )
                    if bound_headless_profile_authority is None
                    else _claude_mcp_config_binding_from_authority(
                        bound_headless_profile_authority.get("mcp_config"),
                        expected_path=mcp_config_path,
                        allowed_servers=allowed_mcp_servers,
                    )
                )
            else:
                if strict_mcp_count or mcp_config_count:
                    raise WorkerExecutionError(
                        "Claude stream command grants MCP configuration "
                        "outside expected-init authority"
                    )
                mcp_config_binding = None
        elif any(
            flag in argv
            for flag in (
                "--dangerously-skip-permissions",
                "--permission-mode",
                "--settings",
                "--strict-mcp-config",
                "--mcp-config",
            )
        ):
            raise WorkerExecutionError(
                "Claude stream command expected-init v1 cannot bind v2 "
                "permission or MCP authority flags"
            )
        headless_profile = {
            "tools": tools,
            "disable_slash_commands": True,
            "setting_sources": [],
            "no_chrome": True,
            "prompt_suggestions": False,
            "safe_mode": argv.count("--safe-mode") == 1,
        }
        if expected_init_v2:
            headless_profile["permission_mode"] = permission_mode
            headless_profile["settings"] = settings_binding
            headless_profile["mcp_config"] = mcp_config_binding
        if (
            bound_headless_profile_authority is not None
            and headless_profile != dict(bound_headless_profile_authority)
        ):
            raise WorkerExecutionError(
                "Claude stream bound headless-profile authority changed"
            )
    command_contract: dict[str, Any] = {
        "print_mode": True,
        "output_format": "stream-json",
        "verbose": True,
        "include_partial_messages": False,
        "forward_subagent_text": False,
        "session_resume": False,
        "session_persistence": False,
        "critical_argv_order": critical_argv_order,
    }
    if headless_profile is not None:
        command_contract["headless_profile"] = headless_profile
    return {
        "schema": CLAUDE_STREAM_STDOUT_CONFIGURATION_SCHEMA,
        "expected_session_id": canonical_session_id,
        "expected_init_contract": expected_init_contract,
        "max_line_bytes": max_line,
        "max_stream_bytes": max_stream,
        "producer_exclusivity_capability": (
            _claude_stream_producer_exclusivity_capability()
        ),
        "parser_runtime": _claude_stream_parser_runtime_binding(),
        "command_contract": command_contract,
    }


def _stream_observation_binding(
    value: Any,
    *,
    limits: Mapping[str, int],
    completion: bool,
) -> dict[str, Any]:
    fields = {
        "stdout_captured_size",
        "stderr_captured_size",
        "stdout_overflow",
        "stderr_overflow",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise WorkerExecutionError("stream observation binding is malformed")
    result: dict[str, Any] = {}
    for name in ("stdout", "stderr"):
        try:
            size = _exact_nonnegative_int(
                value[f"{name}_captured_size"],
                f"{name} stream observation size",
            )
        except WorkerExecutionError as exc:
            raise WorkerExecutionError(
                "stream observation size is malformed"
            ) from exc
        overflow = value[f"{name}_overflow"]
        if type(overflow) is not bool:
            raise WorkerExecutionError("stream overflow observation is malformed")
        if size > limits[f"{name}_bytes"]:
            raise WorkerExecutionError("captured stream exceeds its bound ceiling")
        if completion and overflow:
            raise WorkerExecutionError("completion records a stream overflow")
        result[f"{name}_captured_size"] = size
        result[f"{name}_overflow"] = overflow
    return result


class ParserDigest(Protocol):
    """Strict parser callback used to bind raw bytes to semantic content.

    The callback receives the exact output path and bytes and must either reject
    the document or return a lowercase SHA-256 digest of its canonical parsed
    representation.  Its containing source file is hash-bound in the arm.
    """

    def __call__(self, path: Path, raw: bytes) -> str: ...


class PtyLifecycleAdapter(Protocol):
    """Design seam for a future provider-owned interactive transport.

    An implementation must be installed inside this module (or a reviewed sibling
    provider) and must expose the real child handle at creation time.  A method that
    merely returns caller-asserted PID/timestamps/status is not conforming.  This
    protocol is documentation only; the current public API does not consume it.
    """

    provider_owns_child_creation: bool
    exposes_native_process_handle: bool
    captures_exact_transcript_bytes: bool


class BoundInput:
    """One exact, local input whose bytes are measured by the provider."""

    __slots__ = ("relative_path",)

    def __init__(self, relative_path: str) -> None:
        self.relative_path = _require_relative_path(relative_path, "bound input path")


class PrincipalInvocation:
    """An independently identified worker or assessor invocation."""

    __slots__ = ("identity", "invocation_id")

    def __init__(self, identity: str, invocation_id: str) -> None:
        self.identity = _require_text(identity, "principal identity")
        self.invocation_id = _require_text(invocation_id, "principal invocation_id")

    def as_dict(self) -> dict[str, str]:
        return {"identity": self.identity, "invocation_id": self.invocation_id}


class ExpectedOutput:
    """One assigned output in the dedicated worker output scope."""

    __slots__ = (
        "assignment_id",
        "relative_path",
        "publish_relative_path",
        "is_transcript",
    )

    def __init__(
        self,
        assignment_id: str,
        relative_path: str,
        publish_relative_path: str,
        *,
        is_transcript: bool = False,
    ) -> None:
        self.assignment_id = _require_id(assignment_id, "assignment_id")
        self.relative_path = _require_relative_path(relative_path, "output path")
        self.publish_relative_path = _require_relative_path(
            publish_relative_path, "canonical publish path"
        )
        self.is_transcript = bool(is_transcript)

    def as_dict(self) -> dict[str, Any]:
        return {
            "assignment_id": self.assignment_id,
            "relative_path": self.relative_path,
            "publish_relative_path": self.publish_relative_path,
            "is_transcript": self.is_transcript,
            "pre_state": "ABSENT",
        }


class ExecutionBindings:
    """Immutable semantic authority bound before a worker can launch."""

    __slots__ = (
        "run_id",
        "shard_id",
        "plan",
        "manifest",
        "intent",
        "context",
        "prompt",
        "tool_policy",
        "worker",
        "assessors",
        "effective_backend",
        "effective_model",
    )

    def __init__(
        self,
        *,
        run_id: str,
        shard_id: str,
        plan: BoundInput,
        manifest: BoundInput,
        intent: BoundInput,
        context: BoundInput,
        prompt: BoundInput,
        tool_policy: BoundInput,
        worker: PrincipalInvocation,
        assessors: Sequence[PrincipalInvocation] = (),
        effective_backend: str,
        effective_model: str,
    ) -> None:
        self.run_id = _require_id(run_id, "run_id")
        self.shard_id = _require_id(shard_id, "shard_id")
        named_inputs = {
            "plan": plan,
            "manifest": manifest,
            "intent": intent,
            "context": context,
            "prompt": prompt,
            "tool_policy": tool_policy,
        }
        if any(not isinstance(value, BoundInput) for value in named_inputs.values()):
            raise WorkerExecutionError("all semantic inputs must be BoundInput instances")
        if len({value.relative_path.casefold() for value in named_inputs.values()}) != len(
            named_inputs
        ):
            raise WorkerExecutionError("semantic input paths must be case-distinct")
        self.plan = plan
        self.manifest = manifest
        self.intent = intent
        self.context = context
        self.prompt = prompt
        self.tool_policy = tool_policy
        if not isinstance(worker, PrincipalInvocation):
            raise WorkerExecutionError("worker must be a PrincipalInvocation")
        if any(not isinstance(item, PrincipalInvocation) for item in assessors):
            raise WorkerExecutionError(
                "assessors must be linked PrincipalInvocation instances"
            )
        self.worker = worker
        self.assessors = tuple(assessors)
        self.effective_backend = _require_text(effective_backend, "effective_backend")
        self.effective_model = _require_text(effective_model, "effective_model")
        principals = (worker, *self.assessors)
        identities = [item.identity.casefold() for item in principals]
        invocations = [item.invocation_id.casefold() for item in principals]
        if LAUNCHER_IDENTITY.casefold() in identities:
            raise WorkerExecutionError(
                "launcher, worker, and assessor identities must be case-distinct"
            )
        if worker.identity.casefold() in {
            item.identity.casefold() for item in self.assessors
        }:
            raise WorkerExecutionError("worker and assessor identities must be case-distinct")
        if len(set(invocations)) != len(invocations):
            raise WorkerExecutionError("worker and assessor invocation IDs must be case-distinct")
        pairs = {(item.identity.casefold(), item.invocation_id.casefold()) for item in principals}
        if len(pairs) != len(principals):
            raise WorkerExecutionError("principal invocation tuples must be case-distinct")

    def as_dict(self, root: Path) -> dict[str, Any]:
        raw_inputs = {
            name: _read_bound_input(root, getattr(self, name))
            for name in _SEMANTIC_INPUT_NAMES
        }
        inputs = {
            name: {
                "relative_path": getattr(self, name).relative_path,
                "sha256": _digest_bytes(raw),
                "size": len(raw),
            }
            for name, raw in raw_inputs.items()
        }
        intent_value = _parse_json_bytes(raw_inputs["intent"], label="launch intent")
        intent_backend = intent_value.get("effective_backend")
        intent_model = intent_value.get("effective_model")
        if intent_backend != self.effective_backend or intent_model != self.effective_model:
            raise WorkerExecutionError(
                "effective backend/model do not match the exact launch intent"
            )
        return {
            "run_id": self.run_id,
            "shard_id": self.shard_id,
            "inputs": inputs,
            "worker": self.worker.as_dict(),
            "assessors": [item.as_dict() for item in self.assessors],
            "effective_backend": self.effective_backend,
            "effective_model": self.effective_model,
            "expected_environment_allowlist_sha256": _intent_allowlist_digest(intent_value),
        }


class CompletedExecution:
    """Opaque locator returned only after immutable completion persistence."""

    __slots__ = (
        "receipt_path",
        "completion_sha256",
        "arm_path",
        "arm_sha256",
        "publish_receipt_path",
        "publish_sha256",
        "published_paths",
    )

    def __init__(
        self,
        *,
        receipt_path: Path,
        completion_sha256: str,
        arm_path: Path,
        arm_sha256: str,
        publish_receipt_path: Path | None,
        publish_sha256: str | None,
        published_paths: Sequence[Path],
    ) -> None:
        self.receipt_path = receipt_path
        self.completion_sha256 = completion_sha256
        self.arm_path = arm_path
        self.arm_sha256 = arm_sha256
        self.publish_receipt_path = publish_receipt_path
        self.publish_sha256 = publish_sha256
        self.published_paths = tuple(published_paths)


def _require_text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip() or "\x00" in value:
        raise WorkerExecutionError(f"{label} must be non-empty canonical text")
    return value


def _require_id(value: Any, label: str) -> str:
    text = _require_text(value, label)
    if not _ID_RE.fullmatch(text):
        raise WorkerExecutionError(f"{label} has an invalid identifier shape")
    return text


def _require_sha(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _HEX_RE.fullmatch(value):
        raise WorkerExecutionError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _require_relative_path(value: Any, label: str) -> str:
    text = _require_text(value, label).replace("\\", "/")
    candidate = Path(text)
    if candidate.is_absolute() or text.startswith("/"):
        raise WorkerExecutionError(f"{label} must be relative")
    parts = text.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise WorkerExecutionError(f"{label} contains an unsafe component")
    if any(":" in part for part in parts):
        raise WorkerExecutionError(f"{label} contains a drive/stream separator")
    return "/".join(parts)


def _normalize_json(value: Any, *, label: str) -> Any:
    if value is None or isinstance(value, bool) or isinstance(value, int):
        return value
    if isinstance(value, float):
        raise WorkerExecutionError(f"{label} must not contain floating-point values")
    if isinstance(value, str):
        if "\x00" in value:
            raise WorkerExecutionError(f"{label} contains NUL")
        return value
    if isinstance(value, (list, tuple)):
        return [_normalize_json(item, label=label) for item in value]
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str) or not key or "\x00" in key:
                raise WorkerExecutionError(f"{label} has an invalid object key")
            if key in result:
                raise WorkerExecutionError(f"{label} has duplicate object keys")
            result[key] = _normalize_json(item, label=label)
        return {key: result[key] for key in sorted(result)}
    raise WorkerExecutionError(f"{label} contains a non-JSON value")


def _canonical_json(value: Any) -> bytes:
    normalized = _normalize_json(value, label="JSON payload")
    return (
        json.dumps(normalized, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        + "\n"
    ).encode("utf-8")


def _digest_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _digest_json(value: Any) -> str:
    return _digest_bytes(_canonical_json(value))


_NESTED_EXECUTOR_AUTHORITY_SECRET = object()


class _NestedExecutorAuthority:
    """Opaque proof that only the disposable executor may parent a WER arm."""

    __slots__ = ("_binding", "_secret")

    def __init__(
        self,
        binding: Mapping[str, Any],
        *,
        secret: object,
    ) -> None:
        if secret is not _NESTED_EXECUTOR_AUTHORITY_SECRET:
            raise WorkerExecutionError(
                "nested executor authority is not provider-issued"
            )
        self._binding = _replay_nested_executor_binding(binding)
        self._secret = secret

    def as_dict(self) -> dict[str, Any]:
        if self._secret is not _NESTED_EXECUTOR_AUTHORITY_SECRET:
            raise WorkerExecutionError(
                "nested executor authority is no longer valid"
            )
        return dict(self._binding)


def _replay_nested_executor_binding(value: Any) -> dict[str, Any]:
    fields = {
        "executor_request_sha256",
        "request_core_sha256",
        "outer_arm_sha256",
        "executor_pid",
        "semantic_authority_sha256",
        "ownership",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        raise WorkerExecutionError(
            "disposable executor parent binding is malformed"
        )
    for field in (
        "executor_request_sha256",
        "request_core_sha256",
        "outer_arm_sha256",
        "semantic_authority_sha256",
    ):
        _require_sha(value.get(field), field)
    if (
        isinstance(value.get("executor_pid"), bool)
        or not isinstance(value.get("executor_pid"), int)
        or value["executor_pid"] <= 0
        or value.get("ownership")
        != "OUTER_WER_EXECUTOR_OWNS_PROVIDER_DESCENDANTS"
    ):
        raise WorkerExecutionError(
            "disposable executor parent authority is invalid"
        )
    return dict(value)


def _make_nested_executor_authority(
    *,
    executor_request_sha256: str | None,
    request_core_sha256: str,
    outer_arm_sha256: str,
    executor_pid: int,
    semantic_authority_sha256: str,
) -> _NestedExecutorAuthority:
    if executor_pid != os.getpid():
        raise WorkerExecutionError(
            "nested executor authority must bind the current executor"
        )
    return _NestedExecutorAuthority(
        {
            "executor_request_sha256": executor_request_sha256,
            "request_core_sha256": request_core_sha256,
            "outer_arm_sha256": outer_arm_sha256,
            "executor_pid": executor_pid,
            "semantic_authority_sha256": semantic_authority_sha256,
            "ownership": (
                "OUTER_WER_EXECUTOR_OWNS_PROVIDER_DESCENDANTS"
            ),
        },
        secret=_NESTED_EXECUTOR_AUTHORITY_SECRET,
    )


def _claude_runtime_mapping_sha256(value: Mapping[str, Any]) -> str:
    """Replay the runtime coordinator's newline-free mapping authority."""

    try:
        raw = json.dumps(
            dict(value),
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise WorkerExecutionError(
            "Claude runtime mapping authority is not canonical"
        ) from exc
    return _digest_bytes(raw)


def _strict_json(raw: bytes, *, label: str) -> dict[str, Any]:
    def pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in values:
            if key in result:
                raise WorkerExecutionError(f"{label} contains duplicate JSON keys")
            result[key] = value
        return result

    try:
        parsed = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs)
    except WorkerExecutionError:
        raise
    except BaseException as exc:
        raise WorkerExecutionError(f"{label} is not canonical UTF-8 JSON: {exc}") from exc
    if not isinstance(parsed, dict):
        raise WorkerExecutionError(f"{label} must be a JSON object")
    if _canonical_json(parsed) != raw:
        raise WorkerExecutionError(f"{label} is not in canonical JSON encoding")
    return parsed


def _parse_json_bytes(raw: bytes, *, label: str) -> dict[str, Any]:
    """Parse exact source bytes while rejecting duplicate object keys.

    Bound inputs need not use the provider's canonical serialization, but duplicate
    keys would make a launch intent ambiguous and are therefore forbidden.
    """

    def pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in values:
            if key in result:
                raise WorkerExecutionError(f"{label} contains duplicate JSON keys")
            result[key] = value
        return result

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs)
    except WorkerExecutionError:
        raise
    except Exception as exc:
        raise WorkerExecutionError(f"{label} is not unambiguous UTF-8 JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise WorkerExecutionError(f"{label} must be a JSON object")
    return value


def _recognized_work_plan_provider_stdout_policy(
    raw: bytes,
) -> tuple[bool, dict[str, Any] | None]:
    """Return the exact Claude stream policy declared by a known WorkPlan.

    WER also serves narrower execution protocols whose ``plan`` input is not a
    worker-transaction WorkPlan.  Unknown schemas therefore retain their prior
    generic behavior.  Once a recognized WorkPlan schema is present, however,
    its completion-policy declaration is semantic authority and cannot be
    omitted or replaced by a caller-only arm argument.
    """

    def pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in values:
            if key in result:
                raise WorkerExecutionError(
                    "bound work plan contains duplicate JSON keys"
                )
            result[key] = value
        return result

    try:
        plan = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=pairs,
        )
    except WorkerExecutionError:
        raise
    except (UnicodeError, ValueError, RecursionError):
        return False, None
    if not isinstance(plan, dict):
        return False, None
    if plan.get("schema") not in _WORKER_WORK_PLAN_SCHEMAS:
        return False, None
    completion_policy = plan.get("completion_policy")
    if not isinstance(completion_policy, Mapping):
        raise WorkerExecutionError(
            "recognized WorkPlan completion policy is malformed"
        )
    if _WORKER_PLAN_PROVIDER_STDOUT_POLICY_KEY not in completion_policy:
        return True, None
    normalized = _normalize_json(
        completion_policy[_WORKER_PLAN_PROVIDER_STDOUT_POLICY_KEY],
        label="WorkPlan provider stdout evidence policy",
    )
    if (
        not isinstance(normalized, dict)
        or set(normalized) != set(_CLAUDE_STREAM_CONFIGURATION_FIELDS)
    ):
        raise WorkerExecutionError(
            "recognized WorkPlan provider stdout evidence policy is malformed"
        )
    return True, normalized


def _provider_stdout_configuration_projection(
    binding: Any,
) -> dict[str, Any] | None:
    if binding is None:
        return None
    if not isinstance(binding, Mapping):
        raise WorkerExecutionError(
            "armed provider stdout evidence binding is malformed"
        )
    return {
        field: binding.get(field)
        for field in _CLAUDE_STREAM_CONFIGURATION_FIELDS
    }


def _reconcile_work_plan_provider_stdout_policy(
    raw_plan: bytes,
    armed_binding: Any,
) -> None:
    recognized, declared = _recognized_work_plan_provider_stdout_policy(
        raw_plan
    )
    if not recognized:
        return
    armed = _provider_stdout_configuration_projection(armed_binding)
    if declared != armed:
        raise WorkerExecutionError(
            "WorkPlan provider stdout evidence policy differs from the arm"
        )


def _recognized_work_plan_startup_policy(
    raw: bytes,
) -> tuple[bool, dict[str, Any] | None]:
    """Project the startup permit declared by a recognized WorkPlan."""

    def pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in values:
            if key in result:
                raise WorkerExecutionError(
                    "bound work plan contains duplicate JSON keys"
                )
            result[key] = value
        return result

    try:
        plan = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=pairs,
        )
    except WorkerExecutionError:
        raise
    except (UnicodeError, ValueError, RecursionError):
        return False, None
    if not isinstance(plan, dict):
        return False, None
    if plan.get("schema") not in _WORKER_WORK_PLAN_SCHEMAS:
        return False, None
    completion_policy = plan.get("completion_policy")
    if not isinstance(completion_policy, Mapping):
        raise WorkerExecutionError(
            "recognized WorkPlan completion policy is malformed"
        )
    if _WORKER_PLAN_STARTUP_POLICY_KEY not in completion_policy:
        provider = plan.get("provider")
        if (
            plan.get("schema") == "plamen.worker_work_plan.v2"
            and isinstance(provider, Mapping)
            and provider.get("backend") in {"claude", "codex"}
        ):
            raise WorkerExecutionError(
                "recognized model WorkPlan omits startup permit authority"
            )
        return True, None
    normalized = _normalize_json(
        completion_policy[_WORKER_PLAN_STARTUP_POLICY_KEY],
        label="WorkPlan startup permit policy",
    )
    if (
        not isinstance(normalized, dict)
        or set(normalized) != set(_STARTUP_PERMIT_BINDING_FIELDS)
    ):
        raise WorkerExecutionError(
            "recognized WorkPlan startup permit policy is malformed"
        )
    return True, normalized


def _reconcile_work_plan_startup_policy(
    raw_plan: bytes,
    armed_binding: Any,
) -> bool:
    recognized, declared = _recognized_work_plan_startup_policy(raw_plan)
    if not recognized:
        return False
    armed = (
        None
        if armed_binding is None
        else _normalize_json(
            armed_binding,
            label="armed startup permit binding",
        )
    )
    if (
        armed is not None
        and (
            not isinstance(armed, dict)
            or set(armed) != set(_STARTUP_PERMIT_BINDING_FIELDS)
        )
    ):
        raise WorkerExecutionError(
            "armed startup permit binding is malformed"
        )
    if declared != armed:
        raise WorkerExecutionError(
            "WorkPlan startup permit differs from the arm"
        )
    return True


def _recognized_work_plan_claude_security_policy(
    raw: bytes,
) -> tuple[bool, dict[str, Any] | None]:
    """Project the typed Claude launch-security policy from a WorkPlan."""

    # Malformed bytes are not an "unknown protocol".  Treating parse failure
    # as unrecognized would let a recognizable WorkPlan shed its Claude
    # security policy merely by introducing duplicate keys or truncation.
    plan = _parse_json_bytes(raw, label="bound WorkPlan")
    if plan.get("schema") not in _WORKER_WORK_PLAN_SCHEMAS:
        return False, None
    completion_policy = plan.get("completion_policy")
    if not isinstance(completion_policy, Mapping):
        raise WorkerExecutionError(
            "recognized WorkPlan completion policy is malformed"
        )
    raw_policy = completion_policy.get(
        _WORKER_PLAN_CLAUDE_SECURITY_POLICY_KEY
    )
    if raw_policy is None:
        return True, None
    try:
        return True, _replay_claude_launch_security(raw_policy)
    except _ClaudeLaunchSecurityError as exc:
        raise WorkerExecutionError(
            f"recognized WorkPlan Claude launch-security policy is malformed: {exc}"
        ) from exc


def _reconcile_work_plan_claude_security_policy(
    raw_plan: bytes,
    request: Mapping[str, Any] | None,
) -> bool:
    recognized, declared = _recognized_work_plan_claude_security_policy(
        raw_plan
    )
    if not recognized:
        if request is not None:
            raise WorkerExecutionError(
                "Claude launch-security request has no recognized WorkPlan"
            )
        return False
    if request is None:
        if declared is not None:
            raise WorkerExecutionError(
                "WorkPlan Claude launch-security policy was dropped"
            )
        return True
    try:
        replayed = _replay_claude_launch_security_request(request)
    except _ClaudeLaunchSecurityError as exc:
        raise WorkerExecutionError(
            f"Claude launch-security request does not replay: {exc}"
        ) from exc
    if replayed["policy"] != declared:
        raise WorkerExecutionError(
            "WorkPlan Claude launch-security policy differs from the arm"
        )
    return True


def _intent_allowlist_digest(intent: Mapping[str, Any]) -> str:
    matches: list[Any] = []

    def visit(value: Any) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                if key == "environment_allowlist_sha256":
                    matches.append(child)
                visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)

    visit(intent)
    if len(matches) != 1:
        raise WorkerExecutionError(
            "launch intent must contain exactly one environment_allowlist_sha256"
        )
    return _require_sha(matches[0], "launch intent environment_allowlist_sha256")


def _read_bound_input(root: Path, value: BoundInput) -> bytes:
    path = _safe_descendant(root, value.relative_path, allow_missing=False)
    if (
        _rooted_is_symlink(path)
        or _is_reparse(path)
        or not _rooted_is_file(path)
    ):
        raise WorkerExecutionError(f"bound input is not a safe regular file: {value.relative_path}")
    return _read_rooted_bytes(path)


def _bound_input_record(root: Path, value: BoundInput) -> dict[str, Any]:
    raw = _read_bound_input(root, value)
    return {
        "relative_path": value.relative_path,
        "sha256": _digest_bytes(raw),
        "size": len(raw),
    }


def _replay_bound_input_records(root: Path, records: Any) -> dict[str, bytes]:
    expected_names = set(_SEMANTIC_INPUT_NAMES)
    if not isinstance(records, dict) or set(records) != expected_names:
        raise WorkerExecutionError("bound input denominator is malformed")
    replayed: dict[str, bytes] = {}
    for name in sorted(expected_names):
        record = records[name]
        if not isinstance(record, dict) or set(record) != {"relative_path", "sha256", "size"}:
            raise WorkerExecutionError(f"bound {name} record is malformed")
        relative = _require_relative_path(record["relative_path"], f"bound {name} path")
        path = _safe_descendant(root, relative, allow_missing=False)
        raw = _read_rooted_bytes(path)
        size = _exact_nonnegative_int(record["size"], f"bound {name} size")
        if size != len(raw) or record["sha256"] != _digest_bytes(raw):
            raise WorkerExecutionError(f"bound {name} bytes changed")
        replayed[name] = raw
    return replayed


def _stdin_contract(
    root: Path,
    semantic_bindings: Mapping[str, Any],
    stdin_input: BoundInput | None,
) -> tuple[dict[str, Any], Path | None]:
    """Bind stdin to DEVNULL or to one exact semantic-input record.

    A caller cannot introduce a seventh, unmeasured input through stdin.  Matching
    is exact and case-sensitive; a case-only alias is rejected explicitly even on
    a case-insensitive filesystem.  The returned path has already passed the same
    local-file/symlink checks as the semantic input denominator.
    """

    if stdin_input is None:
        return {"state": "DEVNULL"}, None
    if not isinstance(stdin_input, BoundInput):
        raise WorkerExecutionError("stdin_input must be a BoundInput or None")
    records = semantic_bindings.get("inputs")
    if not isinstance(records, dict) or set(records) != set(_SEMANTIC_INPUT_NAMES):
        raise WorkerExecutionError("stdin cannot bind a malformed semantic input set")
    relative = stdin_input.relative_path
    exact = [
        name
        for name in _SEMANTIC_INPUT_NAMES
        if isinstance(records.get(name), dict)
        and records[name].get("relative_path") == relative
    ]
    if len(exact) != 1:
        folded = [
            name
            for name in _SEMANTIC_INPUT_NAMES
            if isinstance(records.get(name), dict)
            and isinstance(records[name].get("relative_path"), str)
            and records[name]["relative_path"].casefold() == relative.casefold()
        ]
        if folded:
            raise WorkerExecutionError("stdin bound input path casing mismatch")
        raise WorkerExecutionError("stdin_input is not one of the six bound semantic inputs")
    input_name = exact[0]
    record = records[input_name]
    if set(record) != {"relative_path", "sha256", "size"}:
        raise WorkerExecutionError("stdin bound input record is malformed")
    path = _safe_descendant(root, relative, allow_missing=False)
    if (
        _rooted_is_symlink(path)
        or _is_reparse(path)
        or not _rooted_is_file(path)
    ):
        raise WorkerExecutionError("stdin bound input is not a safe regular file")
    raw = _read_rooted_bytes(path)
    size = _exact_nonnegative_int(record["size"], f"stdin bound {input_name} size")
    if size != len(raw) or record["sha256"] != _digest_bytes(raw):
        raise WorkerExecutionError("stdin bound input bytes changed before arm")
    return (
        {
            "state": "BOUND_INPUT",
            "input_name": input_name,
            "relative_path": relative,
            "sha256": record["sha256"],
            "size": size,
        },
        path,
    )


def _replay_stdin_contract(
    root: Path,
    value: Any,
    replayed_inputs: Mapping[str, bytes],
    input_records: Any,
) -> None:
    if value == {"state": "DEVNULL"}:
        return
    expected_fields = {
        "state",
        "input_name",
        "relative_path",
        "sha256",
        "size",
    }
    if not isinstance(value, dict) or set(value) != expected_fields:
        raise WorkerExecutionError("process stdin contract is malformed")
    if value.get("state") != "BOUND_INPUT":
        raise WorkerExecutionError("process stdin state is invalid")
    input_name = value.get("input_name")
    if input_name not in _SEMANTIC_INPUT_NAMES:
        raise WorkerExecutionError("process stdin input name is invalid")
    if not isinstance(input_records, dict) or not isinstance(
        input_records.get(input_name), dict
    ):
        raise WorkerExecutionError("process stdin input record is missing")
    record = input_records[input_name]
    record_size = _exact_nonnegative_int(
        record.get("size"), f"process stdin bound {input_name} record size"
    )
    stdin_size = _exact_nonnegative_int(
        value.get("size"), "process stdin size"
    )
    relative = _require_relative_path(value.get("relative_path"), "process stdin path")
    if relative != record.get("relative_path"):
        if (
            isinstance(record.get("relative_path"), str)
            and relative.casefold() == record["relative_path"].casefold()
        ):
            raise WorkerExecutionError("process stdin path casing mismatch")
        raise WorkerExecutionError("process stdin path is not the bound input path")
    raw = replayed_inputs[input_name]
    if (
        value.get("sha256") != record.get("sha256")
        or stdin_size != record_size
        or value.get("sha256") != _digest_bytes(raw)
        or stdin_size != len(raw)
    ):
        raise WorkerExecutionError("process stdin bytes do not replay")
    path = _safe_descendant(root, relative, allow_missing=False)
    if (
        _rooted_is_symlink(path)
        or _is_reparse(path)
        or not _rooted_is_file(path)
    ):
        raise WorkerExecutionError("process stdin path is not a safe regular file")


def _native_rooted_path(path: str | Path) -> str:
    r"""Return the shared internal syscall spelling for rooted I/O."""

    try:
        return _rooted_io.native_path(path)
    except _rooted_io.RootedPathIOError as exc:
        raise WorkerExecutionError(str(exc)) from exc


def _rooted_lstat(path: str | Path) -> os.stat_result:
    return _rooted_io.lstat(path)


def _rooted_lexists(path: str | Path) -> bool:
    return _rooted_io.lexists(path)


def _rooted_is_symlink(path: str | Path) -> bool:
    return _rooted_io.is_symlink(path)


def _rooted_is_file(path: str | Path) -> bool:
    return _rooted_io.is_file(path)


def _rooted_is_dir(path: str | Path) -> bool:
    return _rooted_io.is_dir(path)


def _read_rooted_bytes(path: str | Path) -> bytes:
    try:
        return _rooted_io.read_bytes(
            path,
            label="rooted I/O file",
            verify_ancestors=False,
            verify_exact_name=False,
        )
    except _rooted_io.RootedPathIOError as exc:
        raise WorkerExecutionError(str(exc)) from exc


def _unlink_rooted(path: str | Path) -> None:
    _rooted_io.unlink(path)


def _mkdir_rooted(path: str | Path) -> None:
    _rooted_io.mkdir(path)


def _is_reparse(path: Path) -> bool:
    return _rooted_io.is_reparse(path)


def _assert_exact_existing_name(path: Path) -> None:
    try:
        _rooted_io.exact_existing_name(path)
    except _rooted_io.RootedPathIOError as exc:
        raise WorkerExecutionError(str(exc)) from exc


def _checked_root_directory(path: str | Path, *, label: str) -> Path:
    try:
        return _rooted_io.checked_directory(
            path,
            label=label,
            verify_ancestors=False,
        )
    except _rooted_io.RootedPathIOError as exc:
        raise WorkerExecutionError(str(exc)) from exc


def _checked_root_file(
    path: str | Path,
    *,
    label: str,
    require_single_link: bool = True,
) -> Path:
    try:
        return _rooted_io.checked_file(
            path,
            label=label,
            require_single_link=require_single_link,
            verify_ancestors=False,
        )
    except _rooted_io.RootedPathIOError as exc:
        raise WorkerExecutionError(str(exc)) from exc


def _safe_descendant(root: Path, relative: str, *, allow_missing: bool) -> Path:
    rel = _require_relative_path(relative, "relative path")
    try:
        return _rooted_io.safe_descendant(
            root,
            rel,
            allow_missing=allow_missing,
            label="scratchpad descendant",
            verify_root_ancestors=False,
            verify_root_exact_name=False,
        )
    except _rooted_io.RootedPathIOError as exc:
        raise WorkerExecutionError(str(exc)) from exc


def _make_safe_directory(root: Path, relative: str) -> Path:
    rel = _require_relative_path(relative, "directory path")
    current = _checked_root_directory(
        root,
        label="directory root",
    )
    for part in rel.split("/"):
        child = current / part
        if _rooted_lexists(child):
            _assert_exact_existing_name(child)
            if (
                _rooted_is_symlink(child)
                or _is_reparse(child)
                or not _rooted_is_dir(child)
            ):
                raise WorkerExecutionError(f"unsafe evidence directory: {child}")
        else:
            _mkdir_rooted(child)
        current = child
    return current


def _paths_overlap(left: Path, right: Path) -> bool:
    """Return whether either resolved path contains the other."""

    left_text = os.path.normcase(str(left))
    right_text = os.path.normcase(str(right))
    try:
        common = os.path.normcase(os.path.commonpath((left_text, right_text)))
    except ValueError:
        return False
    return common in {left_text, right_text}


def _safe_external_directory(value: str | Path, *, label: str) -> Path:
    """Resolve an existing directory while rejecting lexical link aliases."""

    if not isinstance(value, (str, os.PathLike)):
        raise WorkerExecutionError(f"{label} must be a filesystem path")
    raw = os.fspath(value)
    if not isinstance(raw, str) or not raw or "\x00" in raw:
        raise WorkerExecutionError(f"{label} is malformed")
    lexical = Path(os.path.abspath(raw))
    current = Path(lexical.anchor)
    for part in lexical.parts[1:]:
        current = current / part
        if not os.path.lexists(current):
            raise WorkerExecutionError(f"{label} must already exist")
        _assert_exact_existing_name(current)
        if current.is_symlink() or _is_reparse(current):
            raise WorkerExecutionError(f"{label} contains a symlink/reparse component")
    try:
        resolved = lexical.resolve(strict=True)
    except OSError as exc:
        raise WorkerExecutionError(f"{label} cannot be resolved") from exc
    if os.path.normcase(str(resolved)) != os.path.normcase(str(lexical)):
        raise WorkerExecutionError(f"{label} resolves through an alias")
    if not resolved.is_dir():
        raise WorkerExecutionError(f"{label} must be a directory")
    return resolved


def _safe_external_file(value: str | Path, *, label: str) -> Path:
    if not isinstance(value, (str, os.PathLike)):
        raise WorkerExecutionError(f"{label} must be a filesystem path")
    raw = os.fspath(value)
    if not isinstance(raw, str) or not raw or "\x00" in raw:
        raise WorkerExecutionError(f"{label} is malformed")
    lexical = Path(os.path.abspath(raw))
    current = Path(lexical.anchor)
    for part in lexical.parts[1:]:
        current = current / part
        if not os.path.lexists(current):
            raise WorkerExecutionError(f"{label} must already exist")
        _assert_exact_existing_name(current)
        if current.is_symlink() or _is_reparse(current):
            raise WorkerExecutionError(f"{label} contains a symlink/reparse component")
    try:
        resolved = lexical.resolve(strict=True)
    except OSError as exc:
        raise WorkerExecutionError(f"{label} cannot be resolved") from exc
    if os.path.normcase(str(resolved)) != os.path.normcase(str(lexical)):
        raise WorkerExecutionError(f"{label} resolves through an alias")
    try:
        info = resolved.lstat()
    except OSError as exc:
        raise WorkerExecutionError(f"{label} cannot be inspected") from exc
    if (
        not stat.S_ISREG(info.st_mode)
        or int(getattr(info, "st_nlink", 1)) != 1
    ):
        raise WorkerExecutionError(f"{label} must be an unaliased regular file")
    return resolved


def _implementation_file_binding(
    values: Sequence[str | Path],
) -> list[dict[str, Any]]:
    if isinstance(values, (str, bytes, os.PathLike)):
        raise WorkerExecutionError(
            "implementation_files must be a sequence of regular files"
        )
    records: list[dict[str, Any]] = []
    folded: set[str] = set()
    for index, value in enumerate(values):
        path = _safe_external_file(
            value, label=f"implementation_files[{index}]"
        )
        key = os.path.normcase(str(path))
        if key in folded:
            raise WorkerExecutionError("implementation files collide")
        folded.add(key)
        raw = path.read_bytes()
        records.append(
            {
                "path": str(path),
                "size": len(raw),
                "sha256": _digest_bytes(raw),
            }
        )
    return sorted(records, key=lambda row: os.path.normcase(row["path"]))


def _replay_implementation_file_binding(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise WorkerExecutionError("implementation-file binding is malformed")
    paths: list[str] = []
    replayed: list[dict[str, Any]] = []
    for index, row in enumerate(value):
        if not isinstance(row, Mapping) or set(row) != {"path", "size", "sha256"}:
            raise WorkerExecutionError(
                "implementation-file binding row is malformed"
            )
        path = _safe_external_file(
            row.get("path"), label=f"implementation_files[{index}]"
        )
        raw = path.read_bytes()
        size = _exact_nonnegative_int(
            row.get("size"), f"implementation_files[{index}] size"
        )
        if (
            size != len(raw)
            or _require_sha(
                row.get("sha256"), "implementation file digest"
            )
            != _digest_bytes(raw)
        ):
            raise WorkerExecutionError("implementation file bytes changed")
        paths.append(os.path.normcase(str(path)))
        replayed.append(dict(row))
    if len(set(paths)) != len(paths) or paths != sorted(paths):
        raise WorkerExecutionError(
            "implementation-file denominator is non-canonical"
        )
    return replayed


def _auxiliary_writable_root_binding(
    values: Sequence[str | Path],
    *,
    scratchpad: Path,
    output_scope: Path,
) -> tuple[tuple[Path, ...], list[str]]:
    if isinstance(values, (str, bytes, os.PathLike)):
        raise WorkerExecutionError(
            "auxiliary_writable_roots must be a sequence of directories"
        )
    resolved: list[Path] = []
    for index, value in enumerate(values):
        candidate = _safe_external_directory(
            value, label=f"auxiliary_writable_roots[{index}]"
        )
        if _paths_overlap(candidate, scratchpad):
            raise WorkerExecutionError(
                "auxiliary writable roots must be outside the scratchpad"
            )
        if _paths_overlap(candidate, output_scope):
            raise WorkerExecutionError(
                "auxiliary writable roots overlap the assigned output scope"
            )
        if any(_paths_overlap(candidate, previous) for previous in resolved):
            raise WorkerExecutionError(
                "auxiliary writable roots overlap or collide"
            )
        resolved.append(candidate)
    return tuple(resolved), [str(path) for path in resolved]


def _armed_auxiliary_lease_binding(
    values: Sequence[AuxiliaryWritableRootLease],
    *,
    scratchpad: Path,
    output_scope: Path,
    process_scope_identity: str,
) -> tuple[
    tuple[AuxiliaryWritableRootLease, ...],
    tuple[Path, ...],
    list[dict[str, Any]],
]:
    if isinstance(values, (str, bytes, os.PathLike)):
        raise WorkerExecutionError(
            "auxiliary_root_leases must be a sequence of opaque leases"
        )
    leases: list[AuxiliaryWritableRootLease] = []
    roots: list[Path] = []
    bindings: list[dict[str, Any]] = []
    lease_ids: set[str] = set()
    for index, lease in enumerate(values):
        if type(lease) is not AuxiliaryWritableRootLease:
            raise WorkerExecutionError(
                "auxiliary writable authority must be an exact opaque lease"
            )
        binding = lease.binding
        if (
            binding.get("schema") != AUXILIARY_LEASE_SCHEMA
            or binding.get("process_scope_identity")
            != process_scope_identity
            or replay_auxiliary_writable_root_binding(binding).get("valid")
            is not True
        ):
            raise WorkerExecutionError(
                "auxiliary writable-root lease is not live and exact"
            )
        lease_id = _require_text(
            binding.get("lease_id"), "auxiliary writable-root lease id"
        )
        if lease_id.casefold() in lease_ids:
            raise WorkerExecutionError(
                "auxiliary writable-root leases collide"
            )
        lease_ids.add(lease_id.casefold())
        root = _safe_external_directory(
            lease.root,
            label=f"auxiliary_root_leases[{index}]",
        )
        if str(root) != binding.get("root"):
            raise WorkerExecutionError(
                "auxiliary writable-root lease path does not replay"
            )
        if _paths_overlap(root, scratchpad) or _paths_overlap(root, output_scope):
            raise WorkerExecutionError(
                "auxiliary writable-root lease overlaps transaction state"
            )
        if any(_paths_overlap(root, previous) for previous in roots):
            raise WorkerExecutionError(
                "auxiliary writable-root leases overlap"
            )
        leases.append(lease)
        roots.append(root)
        bindings.append(binding)
    return tuple(leases), tuple(roots), bindings


def _replay_auxiliary_lease_binding_shape(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise WorkerExecutionError(
            "auxiliary writable-root lease denominator is malformed"
        )
    rows: list[dict[str, Any]] = []
    lease_ids: set[str] = set()
    roots: set[str] = set()
    for binding in value:
        if (
            not isinstance(binding, Mapping)
            or binding.get("schema") != AUXILIARY_LEASE_SCHEMA
            or not isinstance(binding.get("binding_sha256"), str)
            or not _HEX_RE.fullmatch(str(binding["binding_sha256"]))
            or not isinstance(binding.get("root"), str)
            or not Path(str(binding["root"])).is_absolute()
        ):
            raise WorkerExecutionError(
                "auxiliary writable-root lease binding is malformed"
            )
        lease_id = _require_text(
            binding.get("lease_id"), "auxiliary writable-root lease id"
        )
        root_key = os.path.normcase(str(binding["root"]))
        if lease_id.casefold() in lease_ids or root_key in roots:
            raise WorkerExecutionError(
                "auxiliary writable-root lease bindings collide"
            )
        lease_ids.add(lease_id.casefold())
        roots.add(root_key)
        rows.append(dict(binding))
    return rows


def _replay_auxiliary_writable_root_binding(
    value: Any,
    *,
    scratchpad: Path,
) -> tuple[str, ...]:
    """Validate persisted path identity without requiring revoked roots to exist."""

    if not isinstance(value, list):
        raise WorkerExecutionError("auxiliary writable-root binding is malformed")
    result: list[str] = []
    for index, item in enumerate(value):
        if (
            not isinstance(item, str)
            or not item
            or "\x00" in item
            or not Path(item).is_absolute()
            or os.path.normcase(os.path.abspath(item)) != os.path.normcase(item)
        ):
            raise WorkerExecutionError(
                f"auxiliary writable-root binding {index} is malformed"
            )
        path = Path(item)
        if _paths_overlap(path, scratchpad):
            raise WorkerExecutionError(
                "auxiliary writable-root binding overlaps the scratchpad"
            )
        if any(
            _paths_overlap(path, Path(previous))
            for previous in result
        ):
            raise WorkerExecutionError(
                "auxiliary writable-root bindings overlap or collide"
            )
        result.append(item)
    return tuple(result)


def _path_within_external_root(
    root: Path,
    value: str | Path,
    *,
    label: str,
    allow_missing: bool,
) -> tuple[Path, str]:
    raw = os.fspath(value)
    if not isinstance(raw, str) or not raw or "\x00" in raw:
        raise WorkerExecutionError(f"{label} is malformed")
    candidate = Path(os.path.abspath(raw))
    try:
        relative = candidate.relative_to(root)
    except ValueError as exc:
        raise WorkerExecutionError(
            f"{label} is outside its auxiliary writable root"
        ) from exc
    if not relative.parts:
        raise WorkerExecutionError(f"{label} cannot be the auxiliary root itself")
    current = root
    for part in relative.parts:
        if part in {"", ".", ".."} or ":" in part:
            raise WorkerExecutionError(f"{label} contains an unsafe component")
        current = current / part
        if os.path.lexists(current):
            _assert_exact_existing_name(current)
            if current.is_symlink() or _is_reparse(current):
                raise WorkerExecutionError(
                    f"{label} contains a symlink/reparse component"
                )
        elif not allow_missing:
            raise WorkerExecutionError(f"{label} is missing")
    return current, relative.as_posix()


def _completion_evidence_binding(
    values: Mapping[str, str | Path] | None,
    *,
    auxiliary_roots: tuple[Path, ...],
    limit_bytes: int,
) -> list[dict[str, Any]]:
    if values is None:
        values = {}
    if not isinstance(values, Mapping):
        raise WorkerExecutionError(
            "completion_evidence_files must be an object"
        )
    records: list[dict[str, Any]] = []
    folded_ids: set[str] = set()
    folded_paths: set[str] = set()
    for evidence_id, value in values.items():
        canonical_id = _require_id(evidence_id, "completion evidence id")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", canonical_id):
            raise WorkerExecutionError(
                "completion evidence id is not filename-safe"
            )
        if canonical_id.casefold() in folded_ids:
            raise WorkerExecutionError("completion evidence ids collide")
        folded_ids.add(canonical_id.casefold())
        matches: list[tuple[int, Path, str]] = []
        for index, root in enumerate(auxiliary_roots):
            try:
                path, relative = _path_within_external_root(
                    root,
                    value,
                    label=f"completion evidence {canonical_id}",
                    allow_missing=True,
                )
            except WorkerExecutionError:
                continue
            matches.append((index, path, relative))
        if len(matches) != 1:
            raise WorkerExecutionError(
                "completion evidence must belong to exactly one auxiliary root"
            )
        root_index, path, relative = matches[0]
        folded_path = os.path.normcase(str(path))
        if folded_path in folded_paths:
            raise WorkerExecutionError("completion evidence paths collide")
        folded_paths.add(folded_path)
        if os.path.lexists(path):
            raise WorkerExecutionError(
                "completion evidence must be ABSENT at invocation arm"
            )
        records.append(
            {
                "evidence_id": canonical_id,
                "root_index": root_index,
                "relative_path": relative,
                "limit_bytes": limit_bytes,
                "pre_state": "ABSENT",
            }
        )
    return sorted(records, key=lambda row: row["evidence_id"].casefold())


def _claude_observer_configuration_binding(
    value: Mapping[str, Any],
    *,
    evidence_binding: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Bind the fixed observer to exactly one armed transcript evidence row."""

    fields = {
        "schema",
        "transcript_evidence_id",
        "transcript_root_index",
        "transcript_relative_path",
        "recent_pty_byte_limit",
        "transcript_limit_bytes",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        raise WorkerExecutionError(
            "fixed Claude observer configuration is malformed"
        )
    if value.get("schema") != _CLAUDE_TURN_OBSERVER_SCHEMA:
        raise WorkerExecutionError("fixed Claude observer schema is unsupported")
    evidence_id = _require_id(
        value.get("transcript_evidence_id"),
        "Claude observer transcript evidence id",
    )
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", evidence_id):
        raise WorkerExecutionError(
            "Claude observer transcript evidence id is unsafe"
        )
    root_index = value.get("transcript_root_index")
    if (
        isinstance(root_index, bool)
        or not isinstance(root_index, int)
        or root_index < 0
    ):
        raise WorkerExecutionError(
            "Claude observer transcript root index is malformed"
        )
    relative_path = _require_relative_path(
        value.get("transcript_relative_path"),
        "Claude observer transcript relative path",
    )
    recent_limit = _byte_ceiling(
        value.get("recent_pty_byte_limit"),
        "Claude observer recent PTY byte ceiling",
    )
    transcript_limit = _byte_ceiling(
        value.get("transcript_limit_bytes"),
        "Claude observer transcript byte ceiling",
    )
    if (
        recent_limit <= 0
        or transcript_limit <= 0
        or recent_limit > transcript_limit
    ):
        raise WorkerExecutionError(
            "Claude observer byte ceilings are inconsistent"
        )
    matching_rows = [
        row
        for row in evidence_binding
        if row.get("evidence_id") == evidence_id
    ]
    if len(matching_rows) != 1:
        raise WorkerExecutionError(
            "Claude observer transcript does not name exactly one evidence row"
        )
    transcript_row = matching_rows[0]
    if (
        transcript_row.get("root_index") != root_index
        or transcript_row.get("relative_path") != relative_path
        or transcript_limit > transcript_row.get("limit_bytes", 0)
    ):
        raise WorkerExecutionError(
            "Claude observer transcript binding disagrees with armed evidence"
        )
    return {
        "schema": _CLAUDE_TURN_OBSERVER_SCHEMA,
        "transcript_evidence_id": evidence_id,
        "transcript_root_index": root_index,
        "transcript_relative_path": relative_path,
        "recent_pty_byte_limit": recent_limit,
        "transcript_limit_bytes": transcript_limit,
    }


def _claude_pty_bridge_binding(
    argv: Sequence[str],
    *,
    auxiliary_roots: tuple[Path, ...],
    observer_configuration: Mapping[str, Any],
) -> tuple[dict[str, Any], tuple[Path, ...]]:
    """Bind the fixed observer to the exact reviewed bridge and nested launch."""

    bridge_path = Path(_pty_bridge_module.__file__).resolve(strict=True)
    if (
        isinstance(argv, (str, bytes))
        or not isinstance(argv, Sequence)
        or len(argv) != 6
        or any(not isinstance(item, str) or not item for item in argv)
    ):
        raise WorkerExecutionError(
            "fixed Claude observer requires the exact isolated PTY bridge argv"
        )
    try:
        candidate_bridge = Path(argv[4]).resolve(strict=True)
    except OSError as exc:
        raise WorkerExecutionError(
            "fixed Claude observer requires the exact isolated PTY bridge argv"
        ) from exc
    if (
        list(argv[1:4]) != ["-I", "-S", "-B"]
        or candidate_bridge != bridge_path
    ):
        raise WorkerExecutionError(
            "fixed Claude observer requires the exact isolated PTY bridge argv"
        )
    bridge_manifest_path = _safe_external_file(
        argv[5],
        label="Claude PTY bridge manifest",
    )
    try:
        bridge_manifest = _load_pty_bridge_manifest(bridge_manifest_path)
        host_manifest = _load_pty_host_manifest(
            bridge_manifest.host_manifest_path
        )
    except BaseException as exc:
        raise WorkerExecutionError(
            "Claude PTY bridge/host manifest is invalid"
        ) from exc
    session_positions = [
        index
        for index, value in enumerate(host_manifest.argv)
        if value == "--session-id"
    ]
    if (
        len(session_positions) != 1
        or session_positions[0] + 1 >= len(host_manifest.argv)
    ):
        raise WorkerExecutionError(
            "Claude PTY child argv lacks one exact session identity"
        )
    session_id = host_manifest.argv[session_positions[0] + 1]
    if not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}",
        session_id,
    ):
        raise WorkerExecutionError("Claude PTY session identity is invalid")
    config_dir_raw = host_manifest.environment.get("CLAUDE_CONFIG_DIR")
    if not isinstance(config_dir_raw, str) or not config_dir_raw:
        raise WorkerExecutionError(
            "Claude PTY child environment lacks CLAUDE_CONFIG_DIR"
        )
    config_dir = Path(config_dir_raw)
    if not config_dir.is_absolute():
        raise WorkerExecutionError(
            "Claude PTY config directory must be absolute"
        )
    expected_transcript = (
        config_dir
        / "projects"
        / _encode_claude_project_dir(host_manifest.cwd)
        / f"{session_id}.jsonl"
    )
    root_index = observer_configuration.get("transcript_root_index")
    relative = observer_configuration.get("transcript_relative_path")
    if (
        isinstance(root_index, bool)
        or not isinstance(root_index, int)
        or root_index < 0
        or root_index >= len(auxiliary_roots)
        or not isinstance(relative, str)
    ):
        raise WorkerExecutionError(
            "Claude observer transcript root binding is malformed"
        )
    armed_transcript = auxiliary_roots[root_index] / Path(relative)
    if (
        os.path.normcase(str(armed_transcript.absolute()))
        != os.path.normcase(str(expected_transcript.absolute()))
    ):
        raise WorkerExecutionError(
            "Claude observer transcript is not the exact child session transcript"
        )
    child_executable = _safe_external_file(
        host_manifest.argv[0],
        label="Claude PTY child executable",
    )
    data_files = (
        bridge_manifest_path,
        _safe_external_file(
            bridge_manifest.host_manifest_path,
            label="Claude PTY host manifest",
        ),
    )
    binding = {
        "schema": "plamen.claude_pty_bridge_binding.v1",
        "bridge_path": str(bridge_path),
        "bridge_sha256": _digest_bytes(bridge_path.read_bytes()),
        "bridge_manifest_path": str(bridge_manifest_path),
        "bridge_manifest_sha256": _digest_bytes(
            bridge_manifest_path.read_bytes()
        ),
        "host_manifest_path": str(bridge_manifest.host_manifest_path),
        "host_manifest_sha256": _digest_bytes(
            bridge_manifest.host_manifest_path.read_bytes()
        ),
        "bootstrap_prompt_path": str(
            bridge_manifest.bootstrap_prompt_path
        ),
        "bootstrap_prompt_sha256": _digest_bytes(
            bridge_manifest.bootstrap_prompt_path.read_bytes()
        ),
        "child_executable": str(child_executable),
        "child_executable_sha256": _digest_bytes(
            child_executable.read_bytes()
        ),
        "child_cwd": str(host_manifest.cwd),
        "session_id": session_id,
        "transcript_path": str(expected_transcript),
        "transport_semantic_authority": False,
    }
    return binding, data_files


def _capture_completion_evidence(
    *,
    records: Sequence[Mapping[str, Any]],
    auxiliary_roots: tuple[Path, ...],
    blob_dir: Path,
) -> tuple[list[dict[str, Any]], dict[str, bytes]]:
    rows: list[dict[str, Any]] = []
    exact: dict[str, bytes] = {}
    for record in records:
        root_index = record.get("root_index")
        if (
            isinstance(root_index, bool)
            or not isinstance(root_index, int)
            or root_index < 0
            or root_index >= len(auxiliary_roots)
        ):
            raise WorkerExecutionError(
                "completion evidence root binding is malformed"
            )
        evidence_id = _require_id(
            record.get("evidence_id"), "completion evidence id"
        )
        relative = _require_relative_path(
            record.get("relative_path"),
            "completion evidence relative path",
        )
        path, replayed_relative = _path_within_external_root(
            auxiliary_roots[root_index],
            auxiliary_roots[root_index] / Path(relative),
            label=f"completion evidence {evidence_id}",
            allow_missing=False,
        )
        if replayed_relative != relative:
            raise WorkerExecutionError(
                "completion evidence relative path changed"
            )
        limit = _byte_ceiling(
            record.get("limit_bytes"),
            "completion evidence byte ceiling",
        )
        raw = _read_staged_regular_file(path, limit_bytes=limit)
        blob = _persist_blob(
            blob_dir,
            f"completion-evidence-{evidence_id}",
            raw,
        )
        rows.append(
            {
                **dict(record),
                "post_state": "PRESENT",
                "raw_sha256": _digest_bytes(raw),
                "raw_size": len(raw),
                "cas_blob": blob,
            }
        )
        exact[evidence_id] = raw
    return rows, exact


def _replay_completion_evidence_binding(
    value: Any,
    *,
    auxiliary_root_count: int,
) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise WorkerExecutionError("completion evidence binding is malformed")
    rows: list[dict[str, Any]] = []
    ids: list[str] = []
    paths: set[tuple[int, str]] = set()
    fields = {
        "evidence_id",
        "root_index",
        "relative_path",
        "limit_bytes",
        "pre_state",
    }
    for item in value:
        if not isinstance(item, Mapping) or set(item) != fields:
            raise WorkerExecutionError(
                "completion evidence binding row is malformed"
            )
        evidence_id = _require_id(
            item.get("evidence_id"), "completion evidence id"
        )
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", evidence_id):
            raise WorkerExecutionError("completion evidence id is unsafe")
        root_index = item.get("root_index")
        if (
            isinstance(root_index, bool)
            or not isinstance(root_index, int)
            or root_index < 0
            or root_index >= auxiliary_root_count
        ):
            raise WorkerExecutionError(
                "completion evidence root index is malformed"
            )
        relative = _require_relative_path(
            item.get("relative_path"),
            "completion evidence relative path",
        )
        limit = _byte_ceiling(
            item.get("limit_bytes"),
            "completion evidence byte ceiling",
        )
        if limit <= 0 or item.get("pre_state") != "ABSENT":
            raise WorkerExecutionError(
                "completion evidence pre-state binding is malformed"
            )
        key = (root_index, relative.casefold())
        if key in paths:
            raise WorkerExecutionError("completion evidence paths collide")
        paths.add(key)
        ids.append(evidence_id)
        rows.append(dict(item))
    if (
        len({item.casefold() for item in ids}) != len(ids)
        or ids != sorted(ids, key=str.casefold)
    ):
        raise WorkerExecutionError(
            "completion evidence denominator is non-canonical"
        )
    return rows


def _completion_replay_digest(
    *,
    evidence_rows: Sequence[Mapping[str, Any]],
    stdout_blob: Mapping[str, Any],
    stderr_blob: Mapping[str, Any],
    provisional_observation: Mapping[str, Any],
    observer_configuration: Mapping[str, Any],
) -> str:
    return _digest_json(
        {
            "completion_evidence": [
                {
                    "evidence_id": row.get("evidence_id"),
                    "raw_sha256": row.get("raw_sha256"),
                    "raw_size": row.get("raw_size"),
                }
                for row in evidence_rows
            ],
            "stdout": {
                "sha256": stdout_blob.get("sha256"),
                "size": stdout_blob.get("size"),
            },
            "stderr": {
                "sha256": stderr_blob.get("sha256"),
                "size": stderr_blob.get("size"),
            },
            "provisional_observation": provisional_observation,
            "observer_configuration": observer_configuration,
        }
    )


def _replay_auxiliary_revocation_denominator(
    value: Any,
    *,
    bindings: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) != len(bindings):
        raise WorkerExecutionError(
            "auxiliary-root revocation denominator mismatch"
        )
    rows: list[dict[str, Any]] = []
    for binding, item in zip(bindings, value):
        if (
            not isinstance(item, Mapping)
            or set(item) != {"lease_binding_sha256", "revocation"}
            or item.get("lease_binding_sha256")
            != binding.get("binding_sha256")
            or not isinstance(item.get("revocation"), Mapping)
            or replay_auxiliary_writable_root_revocation(
                binding,
                item["revocation"],
            ).get("valid")
            is not True
        ):
            raise WorkerExecutionError(
                "auxiliary-root revocation does not replay"
            )
        rows.append(
            {
                "lease_binding_sha256": item["lease_binding_sha256"],
                "revocation": dict(item["revocation"]),
            }
        )
    return rows


def _atomic_immutable_bytes(path: Path, raw: bytes) -> None:
    if not _rooted_lexists(path.parent):
        _mkdir_rooted(path.parent)
    elif not _rooted_is_dir(path.parent):
        raise WorkerExecutionError(
            f"immutable artifact parent is not a directory: {path.parent}"
        )
    native = _native_rooted_path(path)
    try:
        fd = os.open(native, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        existing = _read_rooted_bytes(path)
        if existing != raw:
            raise WorkerExecutionError(f"immutable artifact collision at {path}")
        return
    try:
        with os.fdopen(fd, "wb", closefd=True) as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        _fsync_directory(path.parent)
    except BaseException:
        with contextlib.suppress(OSError):
            _unlink_rooted(path)
        raise


def _publish_absent_bytes(path: Path, raw: bytes) -> None:
    """Publish canonical bytes exactly once; an equal race is still a failure."""

    try:
        fd = os.open(
            _native_rooted_path(path),
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
    except FileExistsError as exc:
        raise WorkerExecutionError(
            f"canonical destination ceased to be ABSENT: {path}"
        ) from exc
    try:
        with os.fdopen(fd, "wb", closefd=True) as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        _fsync_directory(path.parent)
    except BaseException:
        with contextlib.suppress(OSError):
            _unlink_rooted(path)
        raise


def _fsync_directory(path: Path) -> None:
    if os.name == "nt":
        return
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    fd = os.open(path, flags)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _persist_hashed_json(directory: Path, prefix: str, payload: Mapping[str, Any]) -> tuple[Path, str]:
    unsigned = dict(payload)
    digest_field = {
        "arm": "arm_sha256",
        "completion": "completion_sha256",
        "debt": "debt_sha256",
        "publish_arm": "publish_arm_sha256",
        "publish": "publish_sha256",
    }[prefix]
    if digest_field in unsigned:
        raise WorkerExecutionError("hashed payload already contains its digest field")
    digest = _digest_json(unsigned)
    completed = dict(unsigned)
    completed[digest_field] = digest
    path = directory / f"{prefix}_{digest}.json"
    _atomic_immutable_bytes(path, _canonical_json(completed))
    return path, digest


def _persist_blob(blob_dir: Path, label: str, raw: bytes) -> dict[str, Any]:
    digest = _digest_bytes(raw)
    path = blob_dir / f"{label}_{digest}.bin"
    _atomic_immutable_bytes(path, raw)
    return {
        "relative_path": path.relative_to(blob_dir.parent).as_posix(),
        "sha256": digest,
        "size": len(raw),
    }


def _callable_binding(
    callback: Callable[..., Any],
    *,
    label: str = "parser_digest",
) -> dict[str, str]:
    if not callable(callback):
        raise WorkerExecutionError(f"{label} must be callable")
    module = getattr(callback, "__module__", None)
    qualname = getattr(callback, "__qualname__", None)
    if not isinstance(module, str) or not isinstance(qualname, str):
        raise WorkerExecutionError(f"{label} must have a stable Python identity")
    try:
        source = inspect.getsourcefile(callback) or inspect.getfile(callback)
    except (OSError, TypeError) as exc:
        raise WorkerExecutionError(f"{label} source file is unavailable") from exc
    source_path = Path(source).resolve(strict=True)
    if not source_path.is_file():
        raise WorkerExecutionError(f"{label} source must be a regular file")
    return {
        "identity": f"{module}:{qualname}",
        "source_file": str(source_path),
        "source_sha256": _digest_bytes(source_path.read_bytes()),
    }


def _trusted_code_constant_binding(value: Any, *, label: str) -> Any:
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, str):
        return {"type": "str", "utf8_hex": value.encode("utf-8").hex()}
    if isinstance(value, float):
        return {"type": "float", "hex": value.hex()}
    if isinstance(value, complex):
        return {
            "type": "complex",
            "real": value.real.hex(),
            "imag": value.imag.hex(),
        }
    if isinstance(value, bytes):
        return {"type": "bytes", "hex": value.hex()}
    if isinstance(value, tuple):
        return {
            "type": "tuple",
            "items": [
                _trusted_code_constant_binding(item, label=label)
                for item in value
            ],
        }
    if isinstance(value, frozenset):
        items = [
            _trusted_code_constant_binding(item, label=label)
            for item in value
        ]
        items.sort(key=_canonical_json)
        return {"type": "frozenset", "items": items}
    if isinstance(value, types.CodeType):
        return {
            "type": "code",
            "value": _trusted_code_object_binding(value, label=label),
        }
    if value is Ellipsis:
        return {"type": "ellipsis"}
    if value is NotImplemented:
        return {"type": "not_implemented"}
    raise WorkerExecutionError(
        f"{label} has an unsupported code constant of type "
        f"{type(value).__name__}"
    )


def _trusted_code_object_binding(
    code: types.CodeType,
    *,
    label: str,
) -> dict[str, Any]:
    """Canonicalize public, de-optimized code fields for a trusted callback."""

    return {
        "name": code.co_name,
        "qualname": code.co_qualname,
        "firstlineno": int(code.co_firstlineno),
        "argcount": int(code.co_argcount),
        "posonlyargcount": int(code.co_posonlyargcount),
        "kwonlyargcount": int(code.co_kwonlyargcount),
        "nlocals": int(code.co_nlocals),
        "stacksize": int(code.co_stacksize),
        "flags": int(code.co_flags),
        "bytecode_sha256": _digest_bytes(code.co_code),
        "linetable_sha256": _digest_bytes(code.co_linetable),
        "exceptiontable_sha256": _digest_bytes(code.co_exceptiontable),
        "constants": [
            _trusted_code_constant_binding(item, label=label)
            for item in code.co_consts
        ],
        "names": list(code.co_names),
        "varnames": list(code.co_varnames),
        "freevars": list(code.co_freevars),
        "cellvars": list(code.co_cellvars),
    }


def _trusted_module_callable_binding(
    callback: Callable[..., Any],
    *,
    label: str,
    positional_parameters: int,
    expected_module: types.ModuleType | None = None,
) -> dict[str, str]:
    """Bind one exact immutable-registry function, including executable code."""

    if (
        not inspect.isfunction(callback)
        or callback.__name__ == "<lambda>"
        or "<locals>" in callback.__qualname__
        or callback.__closure__
        or callback.__defaults__
        or callback.__kwdefaults__
    ):
        raise WorkerExecutionError(
            f"{label} must be a module-level function without closures or defaults"
        )
    signature = inspect.signature(callback)
    parameters = tuple(signature.parameters.values())
    if (
        len(parameters) != positional_parameters
        or any(
            item.kind
            not in {
                inspect.Parameter.POSITIONAL_ONLY,
                inspect.Parameter.POSITIONAL_OR_KEYWORD,
            }
            for item in parameters
        )
    ):
        raise WorkerExecutionError(
            f"{label} has an invalid trusted-callback signature"
        )
    module_name = callback.__module__
    module = sys.modules.get(module_name)
    if module is None:
        raise WorkerExecutionError(f"{label} module is not loaded")
    if expected_module is not None and module is not expected_module:
        raise WorkerExecutionError(
            f"{label} installed module object changed"
        )
    if callback.__globals__ is not vars(module):
        raise WorkerExecutionError(
            f"{label} globals do not belong to the installed module"
        )
    resolved: Any = module
    try:
        for component in callback.__qualname__.split("."):
            resolved = getattr(resolved, component)
    except AttributeError as exc:
        raise WorkerExecutionError(
            f"{label} is not resolvable from its module"
        ) from exc
    if resolved is not callback:
        raise WorkerExecutionError(
            f"{label} does not name the installed module-level function"
        )
    weak = _callable_binding(callback, label=label)
    module_spec = getattr(module, "__spec__", None)
    module_origin = getattr(module_spec, "origin", None)
    if not isinstance(module_origin, str) or not module_origin:
        raise WorkerExecutionError(f"{label} module origin is unavailable")
    origin_path = Path(module_origin)
    if origin_path.is_symlink() or _is_reparse(origin_path):
        raise WorkerExecutionError(f"{label} module origin is unsafe")
    try:
        resolved_origin = origin_path.resolve(strict=True)
    except OSError as exc:
        raise WorkerExecutionError(f"{label} module origin is unavailable") from exc
    if (
        not resolved_origin.is_file()
        or str(resolved_origin) != weak["source_file"]
    ):
        raise WorkerExecutionError(
            f"{label} source does not match its module origin"
        )
    code_binding = _trusted_code_object_binding(
        callback.__code__, label=label
    )
    return {
        **weak,
        "code_sha256": _digest_bytes(_canonical_json(code_binding)),
    }


class _TrustedCallableClosure(NamedTuple):
    """In-memory freeze of one closed registry parser implementation graph.

    Object identity is deliberately retained only in memory.  The persisted
    projection is a deterministic digest over executable, source, module,
    attribute, builtin, constant, and interpreter bindings.  This primitive is
    valid only under the driver's explicit trusted/non-concurrently-hostile
    process assumption; it is not a sandbox against arbitrary in-process code.
    """

    callback: Callable[..., Any]
    expected_module: types.ModuleType
    binding_bytes: bytes
    binding_sha256: str
    object_references: tuple[tuple[str, Any], ...]


_TRUSTED_CALLABLE_CLOSURES: dict[
    Callable[..., Any], _TrustedCallableClosure
] = {}
# Capture the native digest constructor once.  Closure replay must not trust a
# digest field supplied by a reconstructed tuple, nor perform a fresh module
# attribute lookup that can be redirected with that tuple.
_TRUSTED_CLOSURE_SHA256 = hashlib.sha256


_DYNAMIC_CLOSURE_BUILTINS = frozenset(
    {"eval", "exec", "globals", "locals", "vars", "__import__"}
)


def _trusted_dependency_defaults_binding(value: Any, *, label: str) -> Any:
    if value is None:
        return None
    if isinstance(value, tuple):
        return [
            _trusted_code_constant_binding(item, label=label)
            for item in value
        ]
    if isinstance(value, dict):
        if any(not isinstance(key, str) for key in value):
            raise WorkerExecutionError(
                f"{label} has a non-string keyword-default key"
            )
        return {
            key: _trusted_code_constant_binding(value[key], label=label)
            for key in sorted(value)
        }
    raise WorkerExecutionError(f"{label} defaults are not representable")


def _trusted_closure_module_binding(
    module: types.ModuleType,
    *,
    label: str,
) -> dict[str, Any]:
    name = getattr(module, "__name__", None)
    if not isinstance(name, str) or not name or sys.modules.get(name) is not module:
        raise WorkerExecutionError(f"{label} module identity does not replay")
    spec = getattr(module, "__spec__", None)
    origin = getattr(spec, "origin", None)
    loader = getattr(spec, "loader", None)
    if not isinstance(origin, str) or not origin or loader is None:
        raise WorkerExecutionError(f"{label} module origin is unavailable")
    record: dict[str, Any] = {
        "name": name,
        "origin": origin,
        "loader": _runtime_loader_identity(loader),
    }
    if origin in {"built-in", "frozen"}:
        record["origin_kind"] = origin.upper().replace("-", "_")
        record["file"] = None
        return record
    path = Path(origin)
    if path.is_symlink() or _is_reparse(path):
        raise WorkerExecutionError(f"{label} module origin is unsafe")
    try:
        resolved = path.resolve(strict=True)
        raw = resolved.read_bytes()
    except OSError as exc:
        raise WorkerExecutionError(f"{label} module origin cannot be read") from exc
    if not resolved.is_file():
        raise WorkerExecutionError(f"{label} module origin is not a file")
    record["origin_kind"] = "FILE"
    record["file"] = {
        "path": str(resolved),
        "sha256": _digest_bytes(raw),
        "size": len(raw),
    }
    return record


def _trusted_external_object_binding(
    value: Any,
    *,
    label: str,
) -> dict[str, Any]:
    module_name = getattr(value, "__module__", None)
    qualname = getattr(value, "__qualname__", None)
    runtime_module = (
        sys.modules.get(module_name)
        if isinstance(module_name, str)
        else None
    )
    runtime_binding = (
        _trusted_closure_module_binding(
            runtime_module,
            label=f"{label} runtime module",
        )
        if isinstance(runtime_module, types.ModuleType)
        else None
    )
    if inspect.isfunction(value):
        weak = _callable_binding(value, label=label)
        return {
            "kind": "PYTHON_FUNCTION",
            **weak,
            "runtime_module": runtime_binding,
            "code_sha256": _digest_bytes(
                _canonical_json(
                    _trusted_code_object_binding(value.__code__, label=label)
                )
            ),
            "defaults": _trusted_dependency_defaults_binding(
                value.__defaults__, label=label
            ),
            "kwdefaults": _trusted_dependency_defaults_binding(
                value.__kwdefaults__, label=label
            ),
        }
    if inspect.ismethod(value):
        function = value.__func__
        return {
            "kind": "BOUND_METHOD",
            "owner_type": (
                f"{type(value.__self__).__module__}:"
                f"{type(value.__self__).__qualname__}"
            ),
            "function": _trusted_external_object_binding(
                function, label=f"{label} function"
            ),
        }
    if (
        inspect.isbuiltin(value)
        or inspect.ismethoddescriptor(value)
        or isinstance(value, type)
    ):
        if not isinstance(module_name, str) or not isinstance(qualname, str):
            raise WorkerExecutionError(f"{label} has no stable runtime identity")
        return {
            "kind": "TYPE" if isinstance(value, type) else "NATIVE_CALLABLE",
            "identity": f"{module_name}:{qualname}",
            "runtime_module": runtime_binding,
        }
    try:
        constant = _trusted_code_constant_binding(value, label=label)
    except WorkerExecutionError as exc:
        raise WorkerExecutionError(
            f"{label} has an unrepresentable dynamic dependency"
        ) from exc
    return {"kind": "CONSTANT", "value": constant}


def _capture_trusted_callable_closure(
    callback: Callable[..., Any],
    *,
    label: str,
    positional_parameters: int,
    expected_module: types.ModuleType,
) -> tuple[dict[str, Any], tuple[tuple[str, Any], ...]]:
    root_binding = _trusted_module_callable_binding(
        callback,
        label=label,
        positional_parameters=positional_parameters,
        expected_module=expected_module,
    )
    functions: dict[str, dict[str, Any]] = {}
    modules: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, Any]] = []
    references: dict[str, Any] = {"root": callback, "root_module": expected_module}
    observed: dict[int, str] = {}

    def bind_module(module: types.ModuleType, path: str) -> None:
        name = getattr(module, "__name__", None)
        if not isinstance(name, str) or not name:
            raise WorkerExecutionError(f"{label} dependency module is unnamed")
        existing = modules.get(name)
        current = _trusted_closure_module_binding(
            module, label=f"{label} module {name}"
        )
        if existing is not None and existing != current:
            raise WorkerExecutionError(f"{label} module binding is ambiguous")
        modules[name] = current
        references[path] = module

    def bind_function(function: Callable[..., Any], path: str) -> None:
        if not inspect.isfunction(function):
            raise WorkerExecutionError(f"{label} dependency is not a function")
        identity = f"{function.__module__}:{function.__qualname__}"
        references[path] = function
        previous = observed.get(id(function))
        if previous is not None:
            edges.append(
                {"from": path, "kind": "FUNCTION_ALIAS", "target": previous}
            )
            return
        observed[id(function)] = path
        module = sys.modules.get(function.__module__)
        if not isinstance(module, types.ModuleType):
            raise WorkerExecutionError(
                f"{label} dependency function module is unavailable"
            )
        if function.__globals__ is not vars(module):
            raise WorkerExecutionError(
                f"{label} dependency globals are not module-owned"
            )
        bind_module(module, f"{path}:module")
        function_binding = _trusted_external_object_binding(
            function, label=f"{label} dependency {identity}"
        )
        existing = functions.get(identity)
        if existing is not None and existing != function_binding:
            raise WorkerExecutionError(
                f"{label} has duplicate dependency function identities"
            )
        functions[identity] = function_binding
        closure = inspect.getclosurevars(function)
        if closure.nonlocals:
            raise WorkerExecutionError(
                f"{label} dependency {identity} has nonlocal state"
            )
        dynamic = _DYNAMIC_CLOSURE_BUILTINS.intersection(closure.builtins)
        if dynamic:
            raise WorkerExecutionError(
                f"{label} dependency {identity} uses dynamic builtins: "
                f"{sorted(dynamic)}"
            )
        loaded_global_names = {
            item.argval
            for item in dis.get_instructions(function)
            if item.opname == "LOAD_GLOBAL" and isinstance(item.argval, str)
        }
        unresolved_globals = loaded_global_names - set(closure.globals) - set(
            closure.builtins
        )
        if unresolved_globals:
            raise WorkerExecutionError(
                f"{label} dependency {identity} has unresolved globals: "
                f"{sorted(unresolved_globals)}"
            )
        for name, value in sorted(closure.globals.items()):
            edge_path = f"{path}:global:{name}"
            references[edge_path] = value
            if inspect.isfunction(value):
                edges.append(
                    {"from": path, "kind": "FUNCTION", "name": name}
                )
                bind_function(value, edge_path)
                continue
            if isinstance(value, types.ModuleType):
                raise WorkerExecutionError(
                    f"{label} dependency {identity} imports module {name}; "
                    "trusted parser closures require direct frozen callables"
                )
            edges.append(
                {
                    "from": path,
                    "kind": "GLOBAL",
                    "name": name,
                    "binding": _trusted_external_object_binding(
                        value, label=f"{label} global {name}"
                    ),
                }
            )
        for name, value in sorted(closure.builtins.items()):
            edge_path = f"{path}:builtin:{name}"
            references[edge_path] = value
            edges.append(
                {
                    "from": path,
                    "kind": "BUILTIN",
                    "name": name,
                    "binding": _trusted_external_object_binding(
                        value, label=f"{label} builtin {name}"
                    ),
                }
            )

    bind_function(callback, "root")
    executable = Path(sys.executable).resolve(strict=True)
    binding = {
        "schema": "plamen.trusted-callable-closure.v1",
        "root": root_binding,
        "runtime": {
            "implementation": sys.implementation.name,
            "cache_tag": sys.implementation.cache_tag,
            "version": list(sys.version_info[:5]),
            "executable": str(executable),
            "executable_sha256": _digest_bytes(executable.read_bytes()),
        },
        "functions": [
            {"identity": identity, "binding": functions[identity]}
            for identity in sorted(functions)
        ],
        "modules": [modules[name] for name in sorted(modules)],
        "edges": sorted(edges, key=_canonical_json),
    }
    return binding, tuple(sorted(references.items()))


def _freeze_trusted_callable_closure(
    callback: Callable[..., Any],
    *,
    label: str,
    positional_parameters: int,
) -> _TrustedCallableClosure:
    existing = _TRUSTED_CALLABLE_CLOSURES.get(callback)
    if existing is not None:
        _replay_trusted_callable_closure(
            callback,
            existing,
            label=label,
            positional_parameters=positional_parameters,
        )
        return existing
    module = sys.modules.get(getattr(callback, "__module__", ""))
    if not isinstance(module, types.ModuleType):
        raise WorkerExecutionError(f"{label} module is unavailable")
    binding, references = _capture_trusted_callable_closure(
        callback,
        label=label,
        positional_parameters=positional_parameters,
        expected_module=module,
    )
    binding_bytes = _canonical_json(binding)
    frozen = _TrustedCallableClosure(
        callback=callback,
        expected_module=module,
        binding_bytes=binding_bytes,
        binding_sha256=_TRUSTED_CLOSURE_SHA256(
            binding_bytes
        ).hexdigest(),
        object_references=references,
    )
    _TRUSTED_CALLABLE_CLOSURES[callback] = frozen
    return frozen


def _replay_trusted_callable_closure(
    callback: Callable[..., Any],
    frozen: _TrustedCallableClosure,
    *,
    label: str,
    positional_parameters: int,
) -> str:
    if type(frozen) is not _TrustedCallableClosure or callback is not frozen.callback:
        raise WorkerExecutionError(f"{label} frozen closure identity changed")
    actual_binding_sha256 = _TRUSTED_CLOSURE_SHA256(
        frozen.binding_bytes
    ).hexdigest()
    if actual_binding_sha256 != frozen.binding_sha256:
        raise WorkerExecutionError(
            f"{label} frozen closure digest does not bind its bytes"
        )
    if _TRUSTED_CALLABLE_CLOSURES.get(callback) is not frozen:
        raise WorkerExecutionError(
            f"{label} is not the callback's registered closure instance"
        )
    if sys.modules.get(callback.__module__) is not frozen.expected_module:
        raise WorkerExecutionError(f"{label} installed module object changed")
    binding, references = _capture_trusted_callable_closure(
        callback,
        label=label,
        positional_parameters=positional_parameters,
        expected_module=frozen.expected_module,
    )
    if _canonical_json(binding) != frozen.binding_bytes:
        raise WorkerExecutionError(f"{label} dependency closure changed")
    if len(references) != len(frozen.object_references):
        raise WorkerExecutionError(f"{label} dependency denominator changed")
    for current, expected in zip(
        references, frozen.object_references, strict=True
    ):
        if current[0] != expected[0] or current[1] is not expected[1]:
            raise WorkerExecutionError(
                f"{label} dependency object changed at {expected[0]}"
            )
    return frozen.binding_sha256


def _invoke_trusted_registered_callable(
    callback: Callable[..., Any],
    frozen: _TrustedCallableClosure,
    arguments: tuple[Any, ...],
    *,
    label: str,
    positional_parameters: int,
) -> Any:
    _replay_trusted_callable_closure(
        callback,
        frozen,
        label=label,
        positional_parameters=positional_parameters,
    )
    try:
        result = callback(*arguments)
    except BaseException:
        _replay_trusted_callable_closure(
            callback,
            frozen,
            label=label,
            positional_parameters=positional_parameters,
        )
        raise
    _replay_trusted_callable_closure(
        callback,
        frozen,
        label=label,
        positional_parameters=positional_parameters,
    )
    return result


def _invoke_parser_with_registered_guard(
    callback: Callable[..., Any],
    arguments: tuple[Any, ...],
    *,
    label: str,
    trusted_closure: _TrustedCallableClosure | None = None,
) -> Any:
    frozen = trusted_closure or _TRUSTED_CALLABLE_CLOSURES.get(callback)
    if frozen is None:
        return callback(*arguments)
    return _invoke_trusted_registered_callable(
        callback,
        frozen,
        arguments,
        label=label,
        positional_parameters=len(arguments),
    )


def _resolve_registered_callable(
    callback: Callable[..., Any],
    persisted_binding: Any,
    *,
    expected_code_sha256: str,
    label: str,
    positional_parameters: int,
    expected_module: types.ModuleType,
    trusted_closure: _TrustedCallableClosure,
) -> tuple[Callable[..., Any], dict[str, str]]:
    """Resolve a registry-owned callback against a persisted weak projection."""

    resolved = _resolve_bound_observer_callable(
        persisted_binding,
        label=label,
        positional_parameters=positional_parameters,
    )
    if resolved is not callback:
        raise WorkerExecutionError(
            f"{label} WorkPlan/provider identity differs from trusted registry"
        )
    closure_sha256 = _replay_trusted_callable_closure(
        callback,
        trusted_closure,
        label=label,
        positional_parameters=positional_parameters,
    )
    strong = _trusted_module_callable_binding(
        resolved,
        label=label,
        positional_parameters=positional_parameters,
        expected_module=expected_module,
    )
    expected_code = _require_sha(
        expected_code_sha256, f"{label} registry code digest"
    )
    if strong["code_sha256"] != expected_code:
        raise WorkerExecutionError(f"{label} registry code changed")
    return resolved, {**strong, "closure_sha256": closure_sha256}


def _replay_callable_binding(value: Any, *, label: str) -> dict[str, str]:
    """Replay one source-bound trusted callback without executing it."""

    fields = {"identity", "source_file", "source_sha256"}
    if not isinstance(value, Mapping) or set(value) != fields:
        raise WorkerExecutionError(f"{label} binding is malformed")
    identity = value.get("identity")
    if (
        not isinstance(identity, str)
        or ":" not in identity
        or not identity.split(":", 1)[0]
        or not identity.split(":", 1)[1]
        or "\x00" in identity
    ):
        raise WorkerExecutionError(f"{label} identity is malformed")
    source_text = value.get("source_file")
    if (
        not isinstance(source_text, str)
        or not source_text
        or "\x00" in source_text
        or not Path(source_text).is_absolute()
    ):
        raise WorkerExecutionError(f"{label} source path is malformed")
    source = Path(source_text)
    if source.is_symlink() or _is_reparse(source):
        raise WorkerExecutionError(f"{label} source is unsafe")
    try:
        resolved = source.resolve(strict=True)
    except OSError as exc:
        raise WorkerExecutionError(f"{label} source is unavailable") from exc
    if str(resolved) != source_text or not resolved.is_file():
        raise WorkerExecutionError(f"{label} source path does not replay")
    source_sha = _require_sha(value.get("source_sha256"), f"{label} source digest")
    if _digest_bytes(resolved.read_bytes()) != source_sha:
        raise WorkerExecutionError(f"{label} source bytes changed")
    return {
        "identity": identity,
        "source_file": source_text,
        "source_sha256": source_sha,
    }


def _trusted_observer_callable_binding(
    callback: Callable[..., Any],
    *,
    label: str,
    positional_parameters: int,
) -> dict[str, str]:
    """Bind a plain, source-backed observer function with no hidden closure."""

    if (
        not inspect.isfunction(callback)
        or callback.__name__ == "<lambda>"
        or callback.__closure__
        or callback.__defaults__
        or callback.__kwdefaults__
    ):
        raise WorkerExecutionError(
            f"{label} must be a plain function without closures or defaults"
        )
    signature = inspect.signature(callback)
    parameters = tuple(signature.parameters.values())
    if (
        len(parameters) != positional_parameters
        or any(
            item.kind
            not in {
                inspect.Parameter.POSITIONAL_ONLY,
                inspect.Parameter.POSITIONAL_OR_KEYWORD,
            }
            for item in parameters
        )
    ):
        raise WorkerExecutionError(
            f"{label} has an invalid trusted-callback signature"
        )
    return _callable_binding(callback, label=label)


def _resolve_bound_observer_callable(
    value: Any,
    *,
    label: str,
    positional_parameters: int,
) -> Callable[..., Any]:
    binding = _replay_callable_binding(value, label=label)
    module_name, qualname = binding["identity"].split(":", 1)
    if "<locals>" in qualname:
        raise WorkerExecutionError(f"{label} cannot be a local function")
    try:
        module = sys.modules.get(module_name) or importlib.import_module(module_name)
        callback: Any = module
        for component in qualname.split("."):
            callback = getattr(callback, component)
    except (ImportError, AttributeError) as exc:
        raise WorkerExecutionError(f"{label} cannot be resolved") from exc
    if (
        _trusted_observer_callable_binding(
            callback,
            label=label,
            positional_parameters=positional_parameters,
        )
        != binding
    ):
        raise WorkerExecutionError(f"{label} identity does not replay")
    return callback


def _invoke_bounded_callback(
    callback: Callable[..., Any],
    arguments: tuple[Any, ...],
    *,
    timeout_seconds: float,
    label: str,
) -> Any:
    """Bound trusted callback latency without trusting it to self-timeout."""

    result_queue: queue.Queue[tuple[bool, Any]] = queue.Queue(maxsize=1)

    def invoke() -> None:
        try:
            result_queue.put((True, callback(*arguments)))
        except BaseException as exc:
            result_queue.put((False, exc))

    thread = threading.Thread(
        target=invoke,
        name=f"plamen-{label.replace('_', '-')}",
        daemon=True,
    )
    thread.start()
    thread.join(timeout_seconds)
    if thread.is_alive():
        raise WorkerExecutionError(f"{label} exceeded its armed timeout")
    try:
        accepted, value = result_queue.get_nowait()
    except queue.Empty as exc:  # pragma: no cover - defensive thread boundary
        raise WorkerExecutionError(f"{label} returned no result") from exc
    if not accepted:
        raise value
    return value


def _resolve_executable(argv: Sequence[str], environment: Mapping[str, str]) -> tuple[list[str], Path]:
    if isinstance(argv, (str, bytes)) or not argv:
        raise WorkerExecutionError("argv must be a non-empty sequence")
    normalized: list[str] = []
    for item in argv:
        if not isinstance(item, str) or "\x00" in item:
            raise WorkerExecutionError("argv contains an invalid argument")
        normalized.append(item)
    executable_text = normalized[0]
    executable = Path(executable_text)
    if executable.is_absolute():
        resolved = executable.resolve(strict=True)
    else:
        path_value = environment.get("PATH")
        if path_value is None:
            raise WorkerExecutionError(
                "relative executable requires PATH in the explicit environment"
            )
        found = shutil.which(executable_text, path=path_value)
        if found is None:
            raise WorkerExecutionError("executable cannot be resolved from explicit PATH")
        resolved = Path(found).resolve(strict=True)
    if not resolved.is_file():
        raise WorkerExecutionError("resolved executable is not a regular file")
    normalized[0] = str(resolved)
    return normalized, resolved


def _environment_binding(
    environment: Mapping[str, str] | None,
    allowlist: Collection[str] | None,
    *,
    persist_value_digest: bool = True,
) -> tuple[dict[str, str], dict[str, Any]]:
    if type(persist_value_digest) is not bool:
        raise WorkerExecutionError(
            "environment value-digest persistence policy must be boolean"
        )
    env = dict(environment or {})
    allowed = _validated_environment_allowlist(allowlist or ())
    if len({str(name).casefold() for name in env}) != len(env):
        raise WorkerExecutionError("effective environment has a case collision")
    allowed_folded = {name.casefold() for name in allowed}
    normalized: dict[str, str] = {}
    for key, value in env.items():
        if not isinstance(key, str) or key.casefold() not in allowed_folded:
            raise WorkerExecutionError(f"environment key {key!r} is not allowlisted")
        canonical_name = next(name for name in allowed if name.casefold() == key.casefold())
        if key != canonical_name:
            raise WorkerExecutionError(f"environment key casing mismatch for {key!r}")
        if not isinstance(value, str) or "\x00" in value:
            raise WorkerExecutionError(f"environment value for {key!r} is invalid")
        normalized[key] = value
    sorted_allowed = sorted(allowed)
    effective_names = sorted(normalized)
    canonical_effective = [[key, normalized[key]] for key in effective_names]
    binding = {
        "allowlist_names": sorted_allowed,
        "allowlist_sha256": environment_allowlist_sha256(sorted_allowed),
        "effective_names": effective_names,
        "effective_sha256": (
            _digest_json(canonical_effective)
            if persist_value_digest
            else None
        ),
        "value_digest_persisted": persist_value_digest,
        "value_authority": (
            "DURABLE_EFFECTIVE_VALUE_SHA256"
            if persist_value_digest
            else "CLAUDE_CHILD_ENVIRONMENT_IN_MEMORY_REPLAY"
        ),
        "values_persisted": False,
    }
    return normalized, binding


def _validated_environment_allowlist(names: Collection[str]) -> list[str]:
    if isinstance(names, (str, bytes)):
        raise WorkerExecutionError("environment allowlist must be a collection of names")
    allowed = list(names)
    if any(
        not isinstance(name, str) or not name or "=" in name or "\x00" in name
        for name in allowed
    ):
        raise WorkerExecutionError("environment allowlist contains an invalid name")
    if len({name.casefold() for name in allowed}) != len(allowed):
        raise WorkerExecutionError("environment allowlist has a case collision")
    return allowed


def environment_allowlist_sha256(names: Collection[str]) -> str:
    """Return the provider's canonical digest for an environment-name allowlist.

    Launch-intent producers must use this helper rather than duplicating the JSON
    normalization rule.  Values are intentionally excluded; only explicitly
    allowlisted names are authority material in the launch intent.
    """

    return _digest_json(sorted(_validated_environment_allowlist(names)))


def _exact_output_contract(outputs: Sequence[ExpectedOutput]) -> list[dict[str, Any]]:
    if not outputs:
        raise WorkerExecutionError("at least one expected output is required")
    rows = [item.as_dict() if isinstance(item, ExpectedOutput) else None for item in outputs]
    if any(row is None for row in rows):
        raise WorkerExecutionError("expected_outputs contains an invalid item")
    typed = [dict(row) for row in rows if row is not None]
    paths = [row["relative_path"] for row in typed]
    publish_paths = [row["publish_relative_path"] for row in typed]
    assignments = [row["assignment_id"] for row in typed]
    if len({path.casefold() for path in paths}) != len(paths):
        raise WorkerExecutionError("expected output paths collide by case")
    if len({item.casefold() for item in assignments}) != len(assignments):
        raise WorkerExecutionError("expected output assignments collide by case")
    if len({path.casefold() for path in publish_paths}) != len(publish_paths):
        raise WorkerExecutionError("canonical publish paths collide by case")
    return sorted(typed, key=lambda row: (row["relative_path"], row["assignment_id"]))


def _scope_file_names(scope: Path) -> list[str]:
    if not _rooted_lexists(scope):
        return []
    if (
        _rooted_is_symlink(scope)
        or _is_reparse(scope)
        or not _rooted_is_dir(scope)
    ):
        raise _StagedOutputViolation(
            "UNSAFE_STAGED_ENTRY",
            "output scope is not a safe regular directory",
        )
    result: list[str] = []

    def visit(directory: Path) -> None:
        try:
            with _rooted_io.scandir(directory) as entries:
                rows = sorted(
                    list(entries),
                    key=lambda entry: entry.name,
                )
        except OSError as exc:
            raise _StagedOutputViolation(
                "UNSAFE_STAGED_ENTRY",
                f"cannot enumerate staged output directory: {directory}",
            ) from exc
        for entry in rows:
            candidate = directory / entry.name
            try:
                info = _rooted_lstat(candidate)
            except OSError as exc:
                raise _StagedOutputViolation(
                    "UNSAFE_STAGED_ENTRY",
                    f"cannot inspect staged output entry: {candidate}",
                ) from exc
            if (
                _rooted_is_symlink(candidate)
                or _is_reparse(candidate)
            ):
                raise _StagedOutputViolation(
                    "UNSAFE_STAGED_ENTRY",
                    f"unsafe staged output entry: {candidate}",
                )
            if stat.S_ISDIR(info.st_mode):
                visit(candidate)
            elif (
                stat.S_ISREG(info.st_mode)
                and int(getattr(info, "st_nlink", 1)) == 1
            ):
                result.append(candidate.relative_to(scope).as_posix())
            else:
                raise _StagedOutputViolation(
                    "UNSAFE_STAGED_ENTRY",
                    f"unsafe staged output entry: {candidate}",
                )

    visit(scope)
    return sorted(result)


def _read_staged_regular_file(path: Path, *, limit_bytes: int) -> bytes:
    """Read one staged member through a bounded, alias-resistant handle.

    The directory walk establishes the complete denominator; this rechecks the
    exact member at open and after read so a worker cannot convert a safe path
    into a link, hardlink, device, or moving file between enumeration and CAS
    capture.
    """

    try:
        before = _rooted_lstat(path)
    except OSError as exc:
        raise _StagedOutputViolation(
            "UNSAFE_STAGED_ENTRY", f"cannot inspect staged output: {path}"
        ) from exc
    if (
        _rooted_is_symlink(path)
        or _is_reparse(path)
        or not stat.S_ISREG(before.st_mode)
        or int(getattr(before, "st_nlink", 1)) != 1
    ):
        raise _StagedOutputViolation(
            "UNSAFE_STAGED_ENTRY", f"staged output is not an unaliased regular file: {path}"
        )
    if int(before.st_size) > limit_bytes:
        raise _StagedOutputViolation(
            "STAGED_OUTPUT_LIMIT_EXCEEDED",
            f"staged output exceeds {limit_bytes} bytes: {path}",
        )

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(_native_rooted_path(path), flags)
    except OSError as exc:
        raise _StagedOutputViolation(
            "UNSAFE_STAGED_ENTRY", f"cannot safely open staged output: {path}"
        ) from exc
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or int(getattr(opened, "st_nlink", 1)) != 1
            or (int(opened.st_dev), int(opened.st_ino))
            != (int(before.st_dev), int(before.st_ino))
        ):
            raise _StagedOutputViolation(
                "UNSAFE_STAGED_ENTRY",
                f"staged output identity changed before read: {path}",
            )
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            raw = handle.read(limit_bytes + 1)
        if len(raw) > limit_bytes:
            raise _StagedOutputViolation(
                "STAGED_OUTPUT_LIMIT_EXCEEDED",
                f"staged output exceeds {limit_bytes} bytes: {path}",
            )
        after_handle = os.fstat(descriptor)
    finally:
        os.close(descriptor)

    try:
        after_path = _rooted_lstat(path)
    except OSError as exc:
        raise _StagedOutputViolation(
            "UNSAFE_STAGED_ENTRY", f"staged output disappeared after read: {path}"
        ) from exc
    # ctime is deliberately excluded: on Windows it can change for metadata
    # operations that do not alter the opened object's identity or bytes.
    stable_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns")
    if (
        any(getattr(before, name, None) != getattr(after_handle, name, None) for name in stable_fields)
        or any(getattr(after_handle, name, None) != getattr(after_path, name, None) for name in stable_fields)
        or int(getattr(after_handle, "st_nlink", 1)) != 1
        or int(getattr(after_path, "st_nlink", 1)) != 1
        or _rooted_is_symlink(path)
        or _is_reparse(path)
    ):
        raise _StagedOutputViolation(
            "UNSAFE_STAGED_ENTRY", f"staged output mutated during bounded read: {path}"
        )
    return raw


def _provisional_assigned_output_snapshot(
    *,
    root: Path,
    output_scope: Path,
    output_scope_relative: str,
    output_contract: Sequence[Mapping[str, Any]],
    limit_bytes: int,
) -> list[dict[str, Any]]:
    """Capture exact assigned bytes before accepting a provisional turn end.

    A provider event is never sufficient by itself: every assigned artifact
    must already exist under the armed denominator and survive an alias-safe,
    bounded read.  Parser semantics remain a post-scope authority, but these
    exact bytes are replayed after the complete process tree is closed.
    """

    observed_names = _scope_file_names(output_scope)
    expected_names = [row["relative_path"] for row in output_contract]
    if observed_names != expected_names:
        raise _StagedOutputViolation(
            "OUTPUT_NOT_READY_AT_COMPLETION",
            (
                "assigned output denominator was not complete at the "
                f"provisional signal: expected={expected_names!r} "
                f"observed={observed_names!r}"
            ),
        )
    rows: list[dict[str, Any]] = []
    for expected in output_contract:
        path = _safe_descendant(
            root,
            f"{output_scope_relative}/{expected['relative_path']}",
            allow_missing=False,
        )
        raw = _read_staged_regular_file(path, limit_bytes=limit_bytes)
        rows.append(
            {
                "assignment_id": expected["assignment_id"],
                "relative_path": expected["relative_path"],
                "raw_sha256": _digest_bytes(raw),
                "raw_size": len(raw),
            }
        )
    return rows


@contextlib.contextmanager
def _shard_lock(directory: Path, *, timeout_seconds: float) -> Iterator[None]:
    lock_path = directory / "shard.lock"
    handle = open(lock_path, "a+b")
    try:
        if handle.tell() == 0:
            handle.write(b"0")
            handle.flush()
        deadline = time.monotonic() + timeout_seconds
        while True:
            try:
                if os.name == "nt":
                    import msvcrt

                    handle.seek(0)
                    msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except OSError as exc:
                if time.monotonic() >= deadline:
                    raise WorkerExecutionError("timed out acquiring shard execution lock") from exc
                time.sleep(0.025)
        yield
    finally:
        with contextlib.suppress(OSError):
            if os.name == "nt":
                import msvcrt

                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        handle.close()


def _process_creation_identity(process: subprocess.Popen[bytes]) -> dict[str, Any]:
    if os.name == "nt":
        class FILETIME(ctypes.Structure):
            _fields_ = [("low", ctypes.c_uint32), ("high", ctypes.c_uint32)]

        creation = FILETIME()
        exit_time = FILETIME()
        kernel = FILETIME()
        user = FILETIME()
        handle = getattr(process, "_handle", None)
        if handle is None:
            raise WorkerExecutionError("Windows process handle is unavailable")
        ok = ctypes.windll.kernel32.GetProcessTimes(
            int(handle),
            ctypes.byref(creation),
            ctypes.byref(exit_time),
            ctypes.byref(kernel),
            ctypes.byref(user),
        )
        if not ok:
            raise WorkerExecutionError("GetProcessTimes failed for launched worker")
        ticks = (creation.high << 32) | creation.low
        return {"kind": "WINDOWS_FILETIME", "value": str(ticks)}
    if sys.platform == "darwin":
        # macOS has no Linux-style /proc.  libproc's PROC_PIDTBSDINFO exposes
        # the kernel-recorded process start timeval, which is stable for the
        # lifetime of this exact PID incarnation and therefore closes the same
        # PID-reuse ambiguity as Windows FILETIME/Linux start ticks.
        class PROC_BSDINFO(ctypes.Structure):
            _fields_ = [
                ("pbi_flags", ctypes.c_uint32),
                ("pbi_status", ctypes.c_uint32),
                ("pbi_xstatus", ctypes.c_uint32),
                ("pbi_pid", ctypes.c_uint32),
                ("pbi_ppid", ctypes.c_uint32),
                ("pbi_uid", ctypes.c_uint32),
                ("pbi_gid", ctypes.c_uint32),
                ("pbi_ruid", ctypes.c_uint32),
                ("pbi_rgid", ctypes.c_uint32),
                ("pbi_svuid", ctypes.c_uint32),
                ("pbi_svgid", ctypes.c_uint32),
                ("rfu_1", ctypes.c_uint32),
                ("pbi_comm", ctypes.c_char * 16),
                ("pbi_name", ctypes.c_char * 32),
                ("pbi_nfiles", ctypes.c_uint32),
                ("pbi_pgid", ctypes.c_uint32),
                ("pbi_pjobc", ctypes.c_uint32),
                ("e_tdev", ctypes.c_uint32),
                ("e_tpgid", ctypes.c_uint32),
                ("pbi_nice", ctypes.c_int32),
                ("pbi_start_tvsec", ctypes.c_uint64),
                ("pbi_start_tvusec", ctypes.c_uint64),
            ]

        try:
            libproc = ctypes.CDLL(
                "/usr/lib/libproc.dylib", use_errno=True
            )
            libproc.proc_pidinfo.argtypes = [
                ctypes.c_int,
                ctypes.c_int,
                ctypes.c_uint64,
                ctypes.c_void_p,
                ctypes.c_int,
            ]
            libproc.proc_pidinfo.restype = ctypes.c_int
            info = PROC_BSDINFO()
            written = libproc.proc_pidinfo(
                int(process.pid),
                3,  # PROC_PIDTBSDINFO
                0,
                ctypes.byref(info),
                ctypes.sizeof(info),
            )
            if written != ctypes.sizeof(info):
                error = ctypes.get_errno()
                raise OSError(
                    error,
                    "proc_pidinfo(PROC_PIDTBSDINFO) returned "
                    f"{written}/{ctypes.sizeof(info)} bytes",
                )
            if int(info.pbi_pid) != int(process.pid):
                raise ValueError("libproc returned a foreign process identity")
            seconds = int(info.pbi_start_tvsec)
            microseconds = int(info.pbi_start_tvusec)
            if seconds <= 0 or not 0 <= microseconds < 1_000_000:
                raise ValueError("libproc process start timeval is invalid")
        except Exception as exc:
            raise WorkerExecutionError(
                "cannot observe macOS PID-reuse-safe process start identity"
            ) from exc
        return {
            "kind": "MACOS_PROC_PIDTBSDINFO_START_TIME",
            "value": f"{seconds}:{microseconds:06d}",
        }
    proc_stat = Path(f"/proc/{process.pid}/stat")
    try:
        raw = proc_stat.read_text(encoding="ascii")
        tail = raw[raw.rfind(")") + 2 :].split()
        start_ticks = tail[19]
        if not start_ticks.isdigit():
            raise ValueError("non-numeric procfs start ticks")
    except Exception as exc:
        raise WorkerExecutionError("cannot observe PID-reuse-safe process start identity") from exc
    return {"kind": "POSIX_PROCFS_START_TICKS", "value": start_ticks}


# All WER launches use the shared lifecycle provider.
process_tree_termination_capability = _shared_process_tree_capability
_OwnedProcessTree = _SharedOwnedProcessScope


class _BoundedPipeReader:
    """Drain one process pipe without retaining more than its exact ceiling."""

    def __init__(
        self,
        stream: Any,
        *,
        name: str,
        ceiling: int,
        state_changed: threading.Event,
    ) -> None:
        if stream is None:
            raise WorkerExecutionError(f"{name} pipe is unavailable")
        self.name = name
        self.ceiling = ceiling
        self._stream = stream
        self._state_changed = state_changed
        self._raw = bytearray()
        self._raw_lock = threading.Lock()
        self.overflow = False
        self.error: BaseException | None = None
        self.done = threading.Event()
        self._thread = threading.Thread(
            target=self._drain,
            name=f"plamen-{name}-bounded-reader",
            daemon=True,
        )
        self._thread.start()

    def _drain(self) -> None:
        try:
            read = getattr(self._stream, "read1", self._stream.read)
            while True:
                chunk = read(64 * 1024)
                if not chunk:
                    break
                with self._raw_lock:
                    room = self.ceiling - len(self._raw)
                    if room > 0:
                        self._raw.extend(chunk[:room])
                if len(chunk) > room:
                    self.overflow = True
                    self._state_changed.set()
                    break
        except BaseException as exc:
            self.error = exc
            self._state_changed.set()
        finally:
            with contextlib.suppress(Exception):
                self._stream.close()
            self.done.set()
            self._state_changed.set()

    def join(self, timeout: float) -> None:
        self._thread.join(max(0.0, timeout))

    def force_close(self) -> None:
        with contextlib.suppress(Exception):
            self._stream.close()

    @property
    def raw(self) -> bytes:
        with self._raw_lock:
            return bytes(self._raw)

    @property
    def captured_size(self) -> int:
        with self._raw_lock:
            return len(self._raw)


class _BoundedProcessStreams:
    """Concurrent, ceiling-bound capture for a subprocess's two output pipes."""

    def __init__(
        self,
        process: subprocess.Popen[bytes],
        *,
        stdout_limit: int,
        stderr_limit: int,
    ) -> None:
        self.state_changed = threading.Event()
        self.stdout = _BoundedPipeReader(
            process.stdout,
            name="stdout",
            ceiling=stdout_limit,
            state_changed=self.state_changed,
        )
        self.stderr = _BoundedPipeReader(
            process.stderr,
            name="stderr",
            ceiling=stderr_limit,
            state_changed=self.state_changed,
        )

    @property
    def any_overflow(self) -> bool:
        return self.stdout.overflow or self.stderr.overflow

    @property
    def any_error(self) -> bool:
        return self.stdout.error is not None or self.stderr.error is not None

    def finish(self, *, timeout: float) -> tuple[bytes, bytes]:
        deadline = time.monotonic() + timeout
        for reader in (self.stdout, self.stderr):
            reader.join(deadline - time.monotonic())
        unfinished = [
            reader for reader in (self.stdout, self.stderr) if not reader.done.is_set()
        ]
        if unfinished:
            for reader in unfinished:
                reader.force_close()
            for reader in unfinished:
                reader.join(0.1)
            raise WorkerExecutionError("bounded process stream drain did not reach EOF")
        for reader in (self.stdout, self.stderr):
            if reader.error is not None:
                raise WorkerExecutionError(
                    f"bounded {reader.name} capture failed: {reader.error}"
                ) from reader.error
        return self.stdout.raw, self.stderr.raw

    def observation(self) -> dict[str, Any]:
        return {
            "stdout_captured_size": self.stdout.captured_size,
            "stderr_captured_size": self.stderr.captured_size,
            "stdout_overflow": self.stdout.overflow,
            "stderr_overflow": self.stderr.overflow,
        }

    def snapshot(self) -> tuple[bytes, bytes]:
        """Return one bounded point-in-time copy while drain threads continue."""

        return self.stdout.raw, self.stderr.raw


def _record_debt(
    directory: Path,
    *,
    arm_path: Path,
    arm_sha256: str,
    reason_code: str,
    detail: str,
    process_observation: Mapping[str, Any] | None = None,
    stdout_blob: Mapping[str, Any] | None = None,
    stderr_blob: Mapping[str, Any] | None = None,
) -> Path:
    payload = {
        "schema_version": DEBT_SCHEMA,
        "arm_relative_path": arm_path.relative_to(directory).as_posix(),
        "arm_sha256": arm_sha256,
        "reason_code": _require_id(reason_code, "reason_code"),
        "detail": str(detail)[:4096],
        "observed_at_unix_ns": time.time_ns(),
        "process_observation": _normalize_json(process_observation or {}, label="process observation"),
        "stdout_blob": _normalize_json(stdout_blob or {}, label="stdout blob"),
        "stderr_blob": _normalize_json(stderr_blob or {}, label="stderr blob"),
        "completion_emitted": False,
    }
    path, _ = _persist_hashed_json(directory, "debt", payload)
    return path


def _publish_completed_outputs(
    *,
    root: Path,
    shard_dir: Path,
    completion_path: Path,
    completion_sha256: str,
    output_rows: Sequence[Mapping[str, Any]],
) -> tuple[Path, str, tuple[Path, ...]]:
    destinations = [
        {
            "assignment_id": row["assignment_id"],
            "publish_relative_path": row["publish_relative_path"],
            "source_blob": row["cas_blob"],
            "raw_sha256": row["raw_sha256"],
            "raw_size": row["raw_size"],
            "pre_state": "ABSENT",
        }
        for row in output_rows
    ]
    arm_payload = {
        "schema_version": PUBLISH_ARM_SCHEMA,
        "completion_relative_path": completion_path.relative_to(shard_dir).as_posix(),
        "completion_sha256": completion_sha256,
        "destinations": destinations,
        "armed_at_unix_ns": time.time_ns(),
    }
    publish_arm_path, publish_arm_sha = _persist_hashed_json(
        shard_dir, "publish_arm", arm_payload
    )
    published: list[Path] = []
    try:
        for row in destinations:
            destination_rel = row["publish_relative_path"]
            destination = _safe_descendant(root, destination_rel, allow_missing=True)
            if _rooted_lexists(destination):
                raise WorkerExecutionError(
                    f"canonical destination was not ABSENT: {destination_rel}"
                )
            parent_rel = Path(destination_rel).parent.as_posix()
            if parent_rel != ".":
                _make_safe_directory(root, parent_rel)
            blob_record = row["source_blob"]
            blob_path = _safe_descendant(
                shard_dir, blob_record["relative_path"], allow_missing=False
            )
            raw = _read_rooted_bytes(blob_path)
            if len(raw) != row["raw_size"] or _digest_bytes(raw) != row["raw_sha256"]:
                raise WorkerExecutionError("CAS output blob changed before publication")
            _publish_absent_bytes(destination, raw)
            published.append(destination)
        receipt_payload = {
            "schema_version": PUBLISH_SCHEMA,
            "publish_arm_relative_path": publish_arm_path.relative_to(shard_dir).as_posix(),
            "publish_arm_sha256": publish_arm_sha,
            "completion_relative_path": completion_path.relative_to(shard_dir).as_posix(),
            "completion_sha256": completion_sha256,
            "destinations": [
                {
                    **row,
                    "post_state": "PRESENT",
                }
                for row in destinations
            ],
            "published_at_unix_ns": time.time_ns(),
        }
        receipt_path, receipt_sha = _persist_hashed_json(
            shard_dir, "publish", receipt_payload
        )
        return receipt_path, receipt_sha, tuple(published)
    except BaseException:
        # These paths were absent and created by this transaction.  Best-effort
        # rollback avoids leaving unreceipted canonical bytes after an ordinary
        # exception.  A hard crash may still leave a partial set, but the durable
        # publish arm makes that debt observable and no publish receipt exists.
        for path in reversed(published):
            with contextlib.suppress(OSError):
                _unlink_rooted(path)
                _fsync_directory(path.parent)
        raise


def _run_observed_worker_direct(
    *,
    scratchpad: str | Path,
    bindings: ExecutionBindings,
    argv: Sequence[str],
    cwd: str | Path,
    output_scope_relative: str,
    expected_outputs: Sequence[ExpectedOutput],
    parser_digest: ParserDigest,
    environment: Mapping[str, str] | None = None,
    environment_allowlist: Collection[str] | None = None,
    stdin_input: BoundInput | None = None,
    timeout_seconds: float = 300.0,
    lock_timeout_seconds: float = 10.0,
    output_source_mode: str = WORKER_FILE_OUTPUTS,
    stdout_limit_bytes: int = DEFAULT_STDOUT_LIMIT_BYTES,
    stderr_limit_bytes: int = DEFAULT_STDERR_LIMIT_BYTES,
    staged_output_limit_bytes: int = DEFAULT_STAGED_OUTPUT_LIMIT_BYTES,
    publish_canonical: bool = True,
    process_scope_identity: str | None = None,
    cancel_token: Any = None,
    auxiliary_writable_roots: Sequence[str | Path] = (),
    auxiliary_root_leases: Sequence[AuxiliaryWritableRootLease] = (),
    provisional_completion_probe: (
        Callable[[Mapping[str, Any]], Mapping[str, Any] | None] | None
    ) = None,
    final_completion_replay: (
        Callable[[Mapping[str, Any], Mapping[str, Any]], Mapping[str, Any]] | None
    ) = None,
    provisional_completion_signals: Collection[str] = (),
    implementation_files: Sequence[str | Path] = (),
    completion_observer_configuration: Mapping[str, Any] | None = None,
    provider_stdout_evidence_configuration: Mapping[str, Any] | None = None,
    startup_authority_binding: Mapping[str, Any] | None = None,
    claude_launch_security_request: Mapping[str, Any] | None = None,
    claude_runtime_materialization_request: (
        ClaudeRuntimeMaterializationRequest | None
    ) = None,
    observer_callback_timeout_seconds: float = (
        DEFAULT_OBSERVER_CALLBACK_TIMEOUT_SECONDS
    ),
    completion_evidence_files: Mapping[str, str | Path] | None = None,
    completion_evidence_limit_bytes: int = (
        DEFAULT_COMPLETION_EVIDENCE_LIMIT_BYTES
    ),
    _nested_executor_authority: "_NestedExecutorAuthority | None" = None,
) -> CompletedExecution:
    """Arm, launch, observe, and persist one strict worker execution.

    Outputs live in a dedicated scope whose complete file denominator must equal
    ``expected_outputs`` after a zero exit.  In ``STDOUT_ASSIGNED_OUTPUT`` mode the
    provider, not the worker, materializes the one assigned output from exact raw
    stdout bytes.  Both process streams are captured concurrently under exact byte
    ceilings; exceeding either ceiling terminates the owned process scope and emits
    durable debt.  Any post-arm problem raises :class:`WorkerExecutionIncomplete`.
    """

    if not isinstance(bindings, ExecutionBindings):
        raise WorkerExecutionError("bindings must be an ExecutionBindings instance")
    if bindings.effective_backend == "claude":
        if (
            type(claude_runtime_materialization_request)
            is not ClaudeRuntimeMaterializationRequest
        ):
            raise WorkerExecutionError(
                "Claude execution requires one opaque runtime materialization request"
            )
    elif claude_runtime_materialization_request is not None:
        raise WorkerExecutionError(
            "Claude runtime materialization request cannot authorize another backend"
        )
    bound_timeout_seconds = _positive_decimal_text(
        timeout_seconds, "timeout_seconds"
    )
    bound_output_source = _output_source_mode(output_source_mode)
    bound_stdout_limit = _byte_ceiling(stdout_limit_bytes, "stdout_limit_bytes")
    bound_stderr_limit = _byte_ceiling(stderr_limit_bytes, "stderr_limit_bytes")
    bound_staged_output_limit = _byte_ceiling(
        staged_output_limit_bytes, "staged_output_limit_bytes"
    )
    bound_callback_timeout = _positive_decimal_text(
        observer_callback_timeout_seconds,
        "observer_callback_timeout_seconds",
    )
    bound_completion_evidence_limit = _byte_ceiling(
        completion_evidence_limit_bytes,
        "completion_evidence_limit_bytes",
    )
    if bound_completion_evidence_limit <= 0:
        raise WorkerExecutionError(
            "completion_evidence_limit_bytes must be positive"
        )
    normalized_observer_configuration = _normalize_json(
        completion_observer_configuration or {},
        label="completion observer configuration",
    )
    if not isinstance(normalized_observer_configuration, dict):
        raise WorkerExecutionError(
            "completion observer configuration must be an object"
        )
    provider_stdout_configured = (
        provider_stdout_evidence_configuration is not None
    )
    normalized_provider_stdout_configuration = _normalize_json(
        provider_stdout_evidence_configuration or {},
        label="provider stdout evidence configuration",
    )
    if not isinstance(normalized_provider_stdout_configuration, dict):
        raise WorkerExecutionError(
            "provider stdout evidence configuration must be an object"
        )
    normalized_startup_binding = (
        None
        if startup_authority_binding is None
        else _normalize_json(
            startup_authority_binding,
            label="startup authority binding",
        )
    )
    if (
        normalized_startup_binding is not None
        and (
            not isinstance(normalized_startup_binding, dict)
            or set(normalized_startup_binding)
            != set(_STARTUP_PERMIT_BINDING_FIELDS)
        )
    ):
        raise WorkerExecutionError(
            "startup authority binding is malformed"
        )
    normalized_claude_security_request: dict[str, Any] | None = None
    if claude_launch_security_request is not None:
        try:
            normalized_claude_security_request = (
                _replay_claude_launch_security_request(
                    claude_launch_security_request
                )
            )
        except _ClaudeLaunchSecurityError as exc:
            raise WorkerExecutionError(
                f"Claude launch-security request is invalid: {exc}"
            ) from exc
    if not isinstance(publish_canonical, bool):
        raise WorkerExecutionError("publish_canonical must be boolean")
    stream_limits = {
        "stdout_bytes": bound_stdout_limit,
        "stderr_bytes": bound_stderr_limit,
    }
    if not isinstance(lock_timeout_seconds, (int, float)) or lock_timeout_seconds <= 0:
        raise WorkerExecutionError("lock_timeout_seconds must be positive")
    if isinstance(provisional_completion_signals, (str, bytes)):
        raise WorkerExecutionError(
            "provisional_completion_signals must be a collection of identifiers"
        )
    signal_values = tuple(provisional_completion_signals)
    observer_values = (provisional_completion_probe, final_completion_replay)
    observer_configured = any(value is not None for value in observer_values) or bool(
        signal_values
    )
    if observer_configured and (
        provisional_completion_probe is None
        or final_completion_replay is None
        or not signal_values
    ):
        raise WorkerExecutionError(
            "provisional completion requires probe, final replay, and signals"
        )
    if not observer_configured and (
        provisional_completion_probe is not None
        or final_completion_replay is not None
    ):
        raise WorkerExecutionError("provisional completion configuration is partial")
    if not observer_configured and normalized_observer_configuration:
        raise WorkerExecutionError(
            "completion observer configuration has no observer"
        )
    completion_signals = sorted(
        {
            _require_id(item, "provisional completion signal")
            for item in signal_values
        }
    )
    if len(completion_signals) != len(signal_values):
        raise WorkerExecutionError(
            "provisional completion signals collide or contain duplicates"
        )
    folded_signals = {item.casefold() for item in completion_signals}
    if len(folded_signals) != len(completion_signals):
        raise WorkerExecutionError(
            "provisional completion signals collide by case"
        )
    if (
        set(completion_signals)
        - _ALLOWED_PROVISIONAL_COMPLETION_SIGNALS
    ):
        raise WorkerExecutionError(
            "provisional completion signal is not a reviewed positive state"
        )
    if observer_configured and (
        provisional_completion_probe is not _probe_claude_turn_observer
        or final_completion_replay is not _replay_claude_turn_observer
        or completion_signals != ["TURN_END"]
    ):
        raise WorkerExecutionError(
            "completion observer is not the reviewed Claude JSONL package"
        )
    if observer_configured and bound_output_source != WORKER_FILE_OUTPUTS:
        raise WorkerExecutionError(
            "provisional completion requires worker-file assigned outputs"
        )
    if provider_stdout_configured and observer_configured:
        raise WorkerExecutionError(
            "provider stdout evidence and provisional PTY completion are exclusive"
        )
    restricted_stdout_candidate = False
    if (
        provider_stdout_configured
        and bound_output_source == STDOUT_ASSIGNED_OUTPUT
        and bindings.effective_backend == "claude"
        and isinstance(normalized_claude_security_request, Mapping)
    ):
        candidate_policy = normalized_claude_security_request.get("policy")
        candidate_profile = (
            candidate_policy.get("headless_profile")
            if isinstance(candidate_policy, Mapping)
            else None
        )
        candidate_expected = (
            candidate_profile.get("expected_init_contract")
            if isinstance(candidate_profile, Mapping)
            else None
        )
        restricted_stdout_candidate = (
            isinstance(candidate_expected, Mapping)
            and candidate_expected.get("allowed_tools") == []
            and "vendor-restricted-analysis"
            in candidate_expected.get("required_capabilities", [])
        )
    if (
        provider_stdout_configured
        and bound_output_source != WORKER_FILE_OUTPUTS
        and not restricted_stdout_candidate
    ):
        raise WorkerExecutionError(
            "provider stdout evidence requires worker-file outputs or the "
            "exact zero-tool restricted stdout profile"
        )
    if provider_stdout_configured and bindings.effective_backend != "claude":
        raise WorkerExecutionError(
            "Claude stream stdout evidence requires a Claude semantic binding"
        )

    root = _checked_root_directory(
        Path(scratchpad),
        label="scratchpad",
    )
    startup_authority_evidence: dict[str, Any] | None = None
    if normalized_startup_binding is not None:
        try:
            startup_replay = replay_startup_permit_binding(
                scratchpad=root,
                expected_run_id=bindings.run_id,
                binding=normalized_startup_binding,
            )
        except (AuxiliaryWritableRootStartupError, OSError) as exc:
            raise WorkerExecutionError(
                "startup authority is not current launch authority"
            ) from exc
        if startup_replay.get("binding") != normalized_startup_binding:
            raise WorkerExecutionError(
                "startup authority changed during initial replay"
            )
        startup_authority_evidence = {
            "binding": dict(normalized_startup_binding),
            "current_pointer": dict(startup_replay["current_pointer"]),
        }
    output_scope_rel = _require_relative_path(output_scope_relative, "output_scope_relative")
    if output_scope_rel.casefold() == _EVIDENCE_DIR.casefold() or output_scope_rel.casefold().startswith(
        _EVIDENCE_DIR.casefold() + "/"
    ):
        raise WorkerExecutionError("worker output scope cannot overlap execution evidence")
    output_scope = _safe_descendant(root, output_scope_rel, allow_missing=True)
    output_contract = _exact_output_contract(expected_outputs)
    if bound_output_source == STDOUT_ASSIGNED_OUTPUT and len(output_contract) != 1:
        raise WorkerExecutionError(
            "STDOUT_ASSIGNED_OUTPUT requires exactly one expected output"
        )
    for row in output_contract:
        _safe_descendant(root, f"{output_scope_rel}/{row['relative_path']}", allow_missing=True)
        publish_rel = row["publish_relative_path"]
        folded_publish = publish_rel.casefold()
        folded_scope = output_scope_rel.casefold()
        if folded_publish == folded_scope or folded_publish.startswith(folded_scope + "/"):
            raise WorkerExecutionError("canonical publish destination overlaps staging scope")
        if folded_publish == _EVIDENCE_DIR.casefold() or folded_publish.startswith(
            _EVIDENCE_DIR.casefold() + "/"
        ):
            raise WorkerExecutionError("canonical publish destination overlaps execution evidence")
        destination = _safe_descendant(root, publish_rel, allow_missing=True)
        if publish_canonical and _rooted_lexists(destination):
            raise WorkerExecutionError(
                f"canonical destination must be ABSENT before launch: {publish_rel}"
            )
    # The provider owns the staging root itself.  Windows requires a fresh
    # leaf with an explicit protected current-user DACL so applying the Low
    # mandatory label never depends on inherited WRITE_OWNER authority.  The
    # retained no-share-delete handle remains live through Job population-zero
    # and Medium-label restoration.  POSIX keeps the rooted mkdir path.
    windows_output_authority: (
        WindowsPrivateExecutionRootAuthority | None
    ) = None
    if os.name != "nt":
        output_scope = _make_safe_directory(root, output_scope_rel)
    if auxiliary_writable_roots:
        raise WorkerExecutionError(
            "raw auxiliary_writable_roots authority is forbidden; use opaque "
            "auxiliary_root_leases"
        )

    # Claude's concrete environment does not exist until the opaque runtime is
    # materialized under the shard lock.  This outer binding carries only the
    # reviewed allowlist denominator; it is replaced by the redacted in-memory
    # child binding before the inner provider arm is persisted.
    env, environment_binding = _environment_binding(
        environment,
        environment_allowlist,
    )
    actual_argv, executable = _resolve_executable(argv, env)
    implementation_values = list(implementation_files)
    if observer_configured:
        implementation_values.extend(_pty_observer_implementation_files())
    if provider_stdout_configured:
        implementation_values.extend(_claude_stream_implementation_files())
    cwd_path = Path(cwd).resolve(strict=True)
    if not cwd_path.is_dir():
        raise WorkerExecutionError("cwd must be an existing directory")
    provider_stdout_binding = (
        _claude_stream_stdout_binding(
            normalized_provider_stdout_configuration,
            argv=actual_argv,
            stdout_limit_bytes=bound_stdout_limit,
            cwd=cwd_path,
            effective_model=bindings.effective_model,
        )
        if (
            provider_stdout_configured
            and bindings.effective_backend != "claude"
        )
        else None
    )
    if bindings.effective_backend == "claude":
        if (
            normalized_claude_security_request is None
            or not provider_stdout_configured
            or observer_configured
        ):
            raise WorkerExecutionError(
                "Claude opaque runtime requires launch security and the "
                "reviewed headless stream contract"
            )
        security_policy = normalized_claude_security_request["policy"]
        if (
            security_policy["headless_profile"][
                "expected_init_contract"
            ]
            != normalized_provider_stdout_configuration[
                "expected_init_contract"
            ]
        ):
            raise WorkerExecutionError(
                "Claude launch-security policy and provider stream authority differ"
            )
        executable_observation = normalized_claude_security_request[
            "executable_observation"
        ]
        try:
            _recheck_claude_executable_before_launch(
                executable_observation,
                launch_executable=str(executable),
            )
        except Exception as exc:
            raise WorkerExecutionError(
                f"Claude executable launch authority does not replay: {exc}"
            ) from exc
    own_path = Path(__file__).resolve(strict=True)
    launcher_invocation_id = uuid.uuid4().hex
    if process_scope_identity is None:
        scope_token = re.sub(
            r"[^A-Za-z0-9_.-]+",
            "-",
            bindings.shard_id,
        ).strip(".-")
        process_scope_identity = (
            f"wer-{scope_token[:72]}-{launcher_invocation_id[:16]}"
        )
    if (
        not isinstance(process_scope_identity, str)
        or not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}",
            process_scope_identity,
        )
    ):
        raise WorkerExecutionError("process_scope_identity is invalid")
    (
        auxiliary_leases,
        auxiliary_roots,
        auxiliary_lease_bindings,
    ) = _armed_auxiliary_lease_binding(
        auxiliary_root_leases,
        scratchpad=root,
        output_scope=output_scope,
        process_scope_identity=process_scope_identity,
    )
    completion_evidence_binding = _completion_evidence_binding(
        completion_evidence_files,
        auxiliary_roots=auxiliary_roots,
        limit_bytes=bound_completion_evidence_limit,
    )
    if observer_configured and not completion_evidence_binding:
        raise WorkerExecutionError(
            "provisional completion requires retained exact evidence"
        )
    if not observer_configured and completion_evidence_binding:
        raise WorkerExecutionError(
            "completion evidence has no provisional observer"
        )
    if observer_configured:
        normalized_observer_configuration = (
            _claude_observer_configuration_binding(
                normalized_observer_configuration,
                evidence_binding=completion_evidence_binding,
            )
        )
        (
            pty_bridge_binding,
            pty_bridge_data_files,
        ) = _claude_pty_bridge_binding(
            actual_argv,
            auxiliary_roots=auxiliary_roots,
            observer_configuration=normalized_observer_configuration,
        )
        implementation_values.extend(_pty_bridge_implementation_files())
        implementation_values.extend(pty_bridge_data_files)
    else:
        pty_bridge_binding = None
    implementation_values = list(
        {
            os.path.normcase(str(Path(item).resolve(strict=True))): Path(
                item
            ).resolve(strict=True)
            for item in implementation_values
        }.values()
    )
    implementation_binding = _implementation_file_binding(
        implementation_values
    )
    evidence_root = _make_safe_directory(root, _EVIDENCE_DIR)
    shard_dir = _make_safe_directory(evidence_root, bindings.shard_id)
    blob_dir = _make_safe_directory(shard_dir, "blobs")
    claude_runtime: ClaudeRuntimeMaterialization | None = None
    claude_runtime_receipt: dict[str, Any] | None = None
    claude_runtime_redacted_receipts: dict[str, Any] | None = None
    claude_runtime_postprocess_receipt: dict[str, Any] | None = None
    claude_runtime_lifecycle_receipt: dict[str, Any] | None = None
    claude_runtime_base_argv: tuple[str, ...] | None = None

    with _shard_lock(shard_dir, timeout_seconds=float(lock_timeout_seconds)):
        # Measure semantic inputs only after this shard is exclusively owned, so
        # lock wait time cannot separate the armed bytes from the launched bytes.
        parser_binding = _callable_binding(parser_digest)
        completion_observer_binding: dict[str, Any]
        if observer_configured:
            completion_observer_binding = {
                "mode": "PROVISIONAL_SIGNAL_THEN_FINAL_REPLAY",
                "signals": completion_signals,
                "auxiliary_root_leases": auxiliary_lease_bindings,
                "probe": _trusted_observer_callable_binding(
                    provisional_completion_probe,
                    label="provisional_completion_probe",
                    positional_parameters=1,
                ),
                "final_replay": _trusted_observer_callable_binding(
                    final_completion_replay,
                    label="final_completion_replay",
                    positional_parameters=2,
                ),
                "prepare": _trusted_observer_callable_binding(
                    _prepare_claude_turn_observer,
                    label="completion_observer_prepare",
                    positional_parameters=1,
                ),
                "transport": pty_bridge_binding,
                "configuration": normalized_observer_configuration,
                "callback_timeout_seconds": bound_callback_timeout,
                "completion_evidence": completion_evidence_binding,
            }
        else:
            completion_observer_binding = {
                "mode": "PROCESS_EXIT_ZERO",
                "signals": [],
                "auxiliary_root_leases": auxiliary_lease_bindings,
                "probe": None,
                "final_replay": None,
                "prepare": None,
                "transport": None,
                "configuration": normalized_observer_configuration,
                "callback_timeout_seconds": bound_callback_timeout,
                "completion_evidence": [],
            }
        semantic_bindings = bindings.as_dict(root)
        raw_plan = _read_bound_input(root, bindings.plan)
        bound_plan_record = semantic_bindings["inputs"]["plan"]
        if (
            bound_plan_record["size"] != len(raw_plan)
            or bound_plan_record["sha256"] != _digest_bytes(raw_plan)
        ):
            raise WorkerExecutionError(
                "bound WorkPlan changed during policy reconciliation"
            )
        if bindings.effective_backend != "claude":
            _reconcile_work_plan_provider_stdout_policy(
                raw_plan,
                provider_stdout_binding,
            )
        _reconcile_work_plan_claude_security_policy(
            raw_plan,
            normalized_claude_security_request,
        )
        startup_plan_recognized = _reconcile_work_plan_startup_policy(
            raw_plan,
            normalized_startup_binding,
        )
        if startup_plan_recognized:
            raw_intent = _read_bound_input(root, bindings.intent)
            intent_value = _parse_json_bytes(
                raw_intent,
                label="bound launch intent",
            )
            if intent_value.get("auxiliary_writable_root_startup") != (
                normalized_startup_binding
            ):
                raise WorkerExecutionError(
                    "launch intent startup permit differs from the arm"
                )
        if bindings.effective_backend == "claude":
            assert (
                type(claude_runtime_materialization_request)
                is ClaudeRuntimeMaterializationRequest
            )
            claude_runtime_base_argv = tuple(actual_argv)
            try:
                claude_runtime = materialize_claude_runtime(
                    claude_runtime_materialization_request
                )
                live_runtime_replay = (
                    replay_claude_runtime_materialization(
                        claude_runtime
                    )
                )
            except ClaudeRuntimeMaterializationError as exc:
                raise WorkerExecutionError(
                    f"Claude runtime materialization failed: {exc}"
                ) from exc
            if live_runtime_replay.get("valid") is not True:
                raise WorkerExecutionError(
                    "Claude runtime materialization did not replay"
                )
            claude_runtime_receipt = claude_runtime.receipt
            claude_runtime_redacted_receipts = (
                claude_runtime.redacted_receipts
            )
            expected_runtime_authorities = {
                "runtime_request_sha256": (
                    claude_runtime_materialization_request.request_sha256
                ),
                "launch_security_request_sha256": (
                    normalized_claude_security_request[
                        "request_sha256"
                    ]
                ),
                "launch_security_policy_sha256": (
                    normalized_claude_security_request["policy"][
                        "policy_sha256"
                    ]
                ),
                    "startup_permit_sha256": (
                        _claude_runtime_mapping_sha256(
                            normalized_startup_binding
                        )
                    ),
                "work_plan_sha256": _digest_bytes(raw_plan),
                "process_scope_identity": process_scope_identity,
                "base_argv_sha256": _argv_authority_sha256(
                    actual_argv
                ),
            }
            mismatched_runtime_authorities = sorted(
                name
                for name, expected_value
                in expected_runtime_authorities.items()
                if claude_runtime_receipt.get(name) != expected_value
            )
            if mismatched_runtime_authorities:
                try:
                    claude_runtime_lifecycle_receipt = (
                        claude_runtime.abort_before_process_scope(
                            "RUNTIME_OUTER_AUTHORITY_MISMATCH"
                        )
                    )
                except ClaudeRuntimeMaterializationError:
                    pass
                raise WorkerExecutionError(
                    "Claude runtime authority differs from the bound "
                    "WorkPlan/attempt: "
                    + ",".join(mismatched_runtime_authorities)
                )
            actual_argv = list(claude_runtime.final_argv)
            try:
                env, environment_binding = _environment_binding(
                    claude_runtime.compiled_child_environment.environment,
                    environment_allowlist,
                    persist_value_digest=False,
                )
            except (
                ClaudeRuntimeMaterializationError,
                WorkerExecutionError,
            ) as exc:
                try:
                    claude_runtime_lifecycle_receipt = (
                        claude_runtime.abort_before_process_scope(
                            "RUNTIME_CHILD_ENVIRONMENT_REJECTED"
                        )
                    )
                except ClaudeRuntimeMaterializationError:
                    pass
                raise WorkerExecutionError(
                    f"Claude runtime child environment is invalid: {exc}"
                ) from exc
            if (
                claude_runtime_environment_key_set_sha256(tuple(env))
                != claude_runtime_receipt[
                    "expected_child_environment_key_set_sha256"
                ]
                or environment_binding["effective_names"]
                != sorted(env)
            ):
                claude_runtime_lifecycle_receipt = (
                    claude_runtime.abort_before_process_scope(
                        "RUNTIME_CHILD_ENVIRONMENT_DENOMINATOR_MISMATCH"
                    )
                )
                raise WorkerExecutionError(
                    "Claude runtime child environment denominator differs "
                    "from launch security"
                )
            actual_argv, executable = _resolve_executable(
                actual_argv,
                env,
            )
            if (
                _argv_authority_sha256(actual_argv)
                != claude_runtime_receipt["final_argv_sha256"]
            ):
                claude_runtime_lifecycle_receipt = (
                    claude_runtime.abort_before_process_scope(
                        "RUNTIME_FINAL_ARGV_MISMATCH"
                    )
                )
                raise WorkerExecutionError(
                    "Claude runtime final argv differs from its receipt"
                )
            provider_stdout_binding = _claude_stream_stdout_binding(
                normalized_provider_stdout_configuration,
                argv=actual_argv,
                stdout_limit_bytes=bound_stdout_limit,
                cwd=cwd_path,
                effective_model=bindings.effective_model,
            )
            try:
                _reconcile_work_plan_provider_stdout_policy(
                    raw_plan,
                    provider_stdout_binding,
                )
            except WorkerExecutionError:
                claude_runtime_lifecycle_receipt = (
                    claude_runtime.abort_before_process_scope(
                        "RUNTIME_PROVIDER_STDOUT_POLICY_MISMATCH"
                    )
                )
                raise
        if observer_configured:
            prompt_row = semantic_bindings["inputs"]["prompt"]
            prompt_path = _safe_descendant(
                root,
                prompt_row["relative_path"],
                allow_missing=False,
            )
            if (
                pty_bridge_binding is None
                or os.path.normcase(
                    pty_bridge_binding["bootstrap_prompt_path"]
                )
                != os.path.normcase(str(prompt_path))
                or pty_bridge_binding["bootstrap_prompt_sha256"]
                != prompt_row["sha256"]
                or os.path.normcase(pty_bridge_binding["child_cwd"])
                != os.path.normcase(str(cwd_path))
            ):
                raise WorkerExecutionError(
                    "Claude PTY bridge prompt/cwd differs from semantic launch inputs"
                )
        stdin_contract, stdin_path = _stdin_contract(
            root, semantic_bindings, stdin_input
        )
        if (
            semantic_bindings["expected_environment_allowlist_sha256"]
            != environment_binding["allowlist_sha256"]
        ):
            raise WorkerExecutionError(
                "provider-derived environment allowlist does not match the launch intent"
            )
        restricted_stage_binding: dict[str, Any] | None = None
        if claude_runtime is not None:
            try:
                restricted_stage_binding = (
                    _restricted_claude_stage_binding(
                        normalized_claude_security_request,
                        claude_runtime,
                        output_scope=output_scope,
                        output_contract=output_contract,
                        output_source_mode=bound_output_source,
                    )
                    if bound_output_source == STDOUT_ASSIGNED_OUTPUT
                    else _restricted_claude_stage_binding(
                        normalized_claude_security_request,
                        claude_runtime,
                        output_scope=output_scope,
                        output_contract=output_contract,
                    )
                )
            except (
                ClaudeRuntimeMaterializationError,
                _claude_phase_tool_policy.ClaudePhaseToolPolicyError,
                KeyError,
                TypeError,
                ValueError,
            ) as exc:
                raise WorkerExecutionError(
                    f"restricted Claude stage authority is invalid: {exc}"
                ) from exc
            restricted_requested = (
                isinstance(normalized_claude_security_request, Mapping)
                and "--restricted"
                in normalized_claude_security_request.get("policy", {})
                .get("headless_profile", {})
                .get("cli_flags", [])
            )
            if restricted_requested and restricted_stage_binding is None:
                raise WorkerExecutionError(
                    "restricted Claude stage authority does not authenticate"
                )
        if restricted_stage_binding is not None:
            termination_capability = _restricted_claude_process_capability(
                restricted_stage_binding
            )
            transaction_write_authority = _RESTRICTED_CLAUDE_STAGE_AUTHORITY
        else:
            termination_capability = process_tree_termination_capability()
            transaction_write_authority = _transaction_write_authority(
                termination_capability
            )
        if os.name == "nt" and restricted_stage_binding is None:
            if _rooted_lexists(output_scope):
                raise WorkerExecutionError(
                    "Windows MIC worker output scope must be a fresh private leaf"
                )
            parent_rel = output_scope_rel.rpartition("/")[0]
            if parent_rel:
                _make_safe_directory(root, parent_rel)
        elif os.name == "nt":
            # Restricted analysis uses the vendor's exact permission boundary
            # and Job containment, not MIC. Preserve its existing empty-stage
            # lifecycle without manufacturing a Low-integrity authority.
            output_scope = _make_safe_directory(root, output_scope_rel)
        preexisting = (
            _scope_file_names(output_scope)
            if _rooted_lexists(output_scope)
            else []
        )
        if preexisting:
            raise WorkerExecutionError(
                "output scope is not empty before launch; preexisting bytes cannot count"
            )
        for row in output_contract:
            path = _safe_descendant(
                root, f"{output_scope_rel}/{row['relative_path']}", allow_missing=True
            )
            if _rooted_lexists(path):
                raise WorkerExecutionError(
                    f"assigned output must be ABSENT before launch: {row['relative_path']}"
                )
            canonical = _safe_descendant(
                root, row["publish_relative_path"], allow_missing=True
            )
            if publish_canonical and _rooted_lexists(canonical):
                raise WorkerExecutionError(
                    "canonical destination must remain ABSENT before launch: "
                    f"{row['publish_relative_path']}"
                )
        process_intent = {
            "cwd": str(cwd_path),
            "argv": actual_argv,
            "argv_sha256": (
                _argv_authority_sha256(actual_argv)
                if claude_runtime_receipt is not None
                else _digest_json(actual_argv)
            ),
            "resolved_executable": str(executable),
            "executable_sha256": _digest_bytes(executable.read_bytes()),
            "stream_mode": "SEPARATE_STDOUT_STDERR",
            "stream_limits": stream_limits,
            "stdin": stdin_contract,
            "timeout_seconds": bound_timeout_seconds,
            "process_tree_termination": termination_capability,
            "transaction_write_authority": transaction_write_authority,
            "restricted_stage_boundary": restricted_stage_binding,
            "process_scope_identity": process_scope_identity,
            "completion_observer": completion_observer_binding,
            "provider_stdout_evidence": provider_stdout_binding,
            "claude_launch_security_request": (
                normalized_claude_security_request
            ),
            "claude_runtime_materialization": (
                claude_runtime_receipt
            ),
            "claude_runtime_redacted_receipts": (
                claude_runtime_redacted_receipts
            ),
            "claude_runtime_base_argv": (
                list(claude_runtime_base_argv)
                if claude_runtime_base_argv is not None
                else None
            ),
            "startup_authority_evidence": (
                startup_authority_evidence
            ),
            "implementation_files": implementation_binding,
        }
        if _nested_executor_authority is not None:
            process_intent["disposable_executor_parent"] = (
                _nested_executor_authority.as_dict()
            )
        arm_payload = {
            "schema_version": ARM_SCHEMA,
            "launcher": {
                "identity": LAUNCHER_IDENTITY,
                "invocation_id": launcher_invocation_id,
                "code_file": str(own_path),
                "code_sha256": _digest_bytes(own_path.read_bytes()),
            },
            "bindings": semantic_bindings,
            "process_intent": process_intent,
            "environment": environment_binding,
            "output_contract": {
                "scope_relative": output_scope_rel,
                "source_mode": bound_output_source,
                "member_limit_bytes": bound_staged_output_limit,
                "publication_authority": (
                    "LEGACY_PROVIDER" if publish_canonical else "PHASE_IO_ONLY"
                ),
                "preexisting_files": [],
                "expected_outputs": output_contract,
                "parser": parser_binding,
                "transcript_expectation": (
                    "PRESENT"
                    if any(row["is_transcript"] for row in output_contract)
                    else "NOT_APPLICABLE"
                ),
            },
            "armed_at_unix_ns": time.time_ns(),
        }
        arm_path, arm_sha = _persist_hashed_json(shard_dir, "arm", arm_payload)
        try:
            replayed_arm, replayed_arm_sha = _load_hashed_json(
                arm_path,
                prefix="arm",
                digest_field="arm_sha256",
                schema=ARM_SCHEMA,
            )
        except WorkerExecutionError as exc:
            if claude_runtime is not None:
                try:
                    claude_runtime_lifecycle_receipt = (
                        claude_runtime.abort_before_process_scope(
                            "INNER_PROVIDER_ARM_REPLAY_FAILED"
                        )
                    )
                except ClaudeRuntimeMaterializationError:
                    pass
            raise WorkerExecutionError(
                "inner provider arm did not durably replay"
            ) from exc
        if (
            replayed_arm_sha != arm_sha
            or {
                key: value
                for key, value in replayed_arm.items()
                if key != "arm_sha256"
            }
            != arm_payload
        ):
            if claude_runtime is not None:
                try:
                    claude_runtime_lifecycle_receipt = (
                        claude_runtime.abort_before_process_scope(
                            "INNER_PROVIDER_ARM_REPLAY_FAILED"
                        )
                    )
                except ClaudeRuntimeMaterializationError:
                    pass
            raise WorkerExecutionError(
                "inner provider arm changed before process creation"
            )

        process: subprocess.Popen[bytes] | None = None
        process_tree: _OwnedProcessTree | None = None
        process_tree_close_attempted = False
        streams: _BoundedProcessStreams | None = None
        stdin_handle: Any | None = None
        process_observation: dict[str, Any] = {}
        stdout = b""
        stderr = b""
        stdout_blob: dict[str, Any] | None = None
        stderr_blob: dict[str, Any] | None = None
        provisional_observation: dict[str, Any] | None = None
        final_replay_observation: dict[str, Any] | None = None
        provider_stdout_evidence: dict[str, Any] | None = None
        completion_evidence_rows: list[dict[str, Any]] = []
        completion_evidence_exact: dict[str, bytes] = {}
        auxiliary_revocation_receipts: list[dict[str, Any]] = []
        observer_runtime_state: object | None = None
        launch_requested_wall_ns = time.time_ns()
        start_mono_ns = time.monotonic_ns()
        execution_deadline = (
            time.monotonic() + float(bound_timeout_seconds)
        )

        def append_auxiliary_revocation(
            index: int,
            receipt: Mapping[str, Any],
        ) -> None:
            binding = auxiliary_lease_bindings[index]
            replay = replay_auxiliary_writable_root_revocation(
                binding,
                receipt,
            )
            if replay.get("valid") is not True:
                raise WorkerExecutionError(
                    "auxiliary writable-root revocation does not replay"
                )
            auxiliary_revocation_receipts.append(
                {
                    "lease_binding_sha256": binding["binding_sha256"],
                    "revocation": dict(receipt),
                }
            )

        def abort_auxiliary_roots_before_scope(
            reason_code: str,
        ) -> None:
            nonlocal claude_runtime_lifecycle_receipt
            if (
                claude_runtime is not None
                and claude_runtime_lifecycle_receipt is None
            ):
                claude_runtime_lifecycle_receipt = (
                    claude_runtime.abort_before_process_scope(
                        reason_code
                    )
                )
                process_observation["claude_runtime_lifecycle"] = (
                    claude_runtime_lifecycle_receipt
                )
            for index in range(
                len(auxiliary_revocation_receipts),
                len(auxiliary_leases),
            ):
                lease = auxiliary_leases[index]
                binding = auxiliary_lease_bindings[index]
                receipt = lease.abort_before_process_scope(
                    attempt_arm_sha256=binding["attempt_arm_sha256"],
                    process_scope_identity=binding[
                        "process_scope_identity"
                    ],
                    reason_code=reason_code,
                )
                append_auxiliary_revocation(index, receipt)
            process_observation["auxiliary_root_revocations"] = (
                auxiliary_revocation_receipts
            )

        def record_claude_runtime_observation() -> None:
            if claude_runtime_receipt is None:
                return
            process_observation["claude_runtime_materialization"] = (
                claude_runtime_receipt
            )
            process_observation["claude_runtime_redacted_receipts"] = (
                claude_runtime_redacted_receipts
            )
            if claude_runtime_postprocess_receipt is not None:
                process_observation["claude_runtime_postprocess"] = (
                    claude_runtime_postprocess_receipt
                )
            if claude_runtime_lifecycle_receipt is not None:
                process_observation["claude_runtime_lifecycle"] = (
                    claude_runtime_lifecycle_receipt
                )

        def dispose_claude_runtime_after_nonzero() -> None:
            """Bind ordinary cleanup to the exact provider nonzero result."""

            nonlocal claude_runtime_lifecycle_receipt
            if claude_runtime is None or process_tree is None or process is None:
                raise WorkerExecutionError(
                    "Claude runtime nonzero cleanup lacks live authority"
                )
            failure_evidence_sha256 = _digest_json(
                {
                    "reason_code": "NONZERO_EXIT",
                    "returncode": process.returncode,
                    "termination_cause": termination_cause,
                    "root_exit_origin": process_observation.get(
                        "root_exit_origin"
                    ),
                    "process_scope_identity": getattr(
                        process_tree,
                        "persistent_identity",
                        None,
                    ),
                }
            )
            try:
                claude_runtime_lifecycle_receipt = (
                    claude_runtime.revoke_after_failed_scope_close(
                        process_tree,
                        "NONZERO_EXIT",
                        primary_failure_evidence_sha256=(
                            failure_evidence_sha256
                        ),
                    )
                )
                lifecycle_replay = (
                    replay_claude_runtime_lifecycle_receipt(
                        claude_runtime_lifecycle_receipt
                    )
                )
                if (
                    lifecycle_replay.get("closure_mode")
                    != "NORMAL_SCOPE_FAILURE_CLEANUP"
                    or lifecycle_replay.get("reason_code") != "NONZERO_EXIT"
                    or lifecycle_replay.get("completion_authority") is not False
                    or claude_runtime.postprocess_receipt is not None
                ):
                    raise WorkerExecutionError(
                        "Claude runtime nonzero cleanup minted invalid authority"
                    )
            except BaseException as exc:
                try:
                    recovered_receipt = claude_runtime.lifecycle_receipt
                except BaseException:
                    recovered_receipt = None
                if recovered_receipt is not None:
                    claude_runtime_lifecycle_receipt = recovered_receipt
                cleanup_reason = getattr(exc, "reason_code", None)
                cleanup_detail = (
                    f"{type(exc).__name__}: "
                    + (
                        f"{cleanup_reason}: "
                        if isinstance(cleanup_reason, str)
                        else ""
                    )
                    + str(exc)
                )
                process_observation["claude_runtime_failure_cleanup"] = {
                    "status": "FAILED",
                    "primary_reason_code": "NONZERO_EXIT",
                    "secondary_reason_code": (
                        "CLAUDE_RUNTIME_CLEANUP_FAILED"
                    ),
                    "detail": cleanup_detail,
                }
                record_claude_runtime_observation()
                raise
            process_observation["claude_runtime_failure_cleanup"] = {
                "status": "CLEANED",
                "primary_reason_code": "NONZERO_EXIT",
                "secondary_reason_code": None,
            }
            record_claude_runtime_observation()

        def dispose_claude_runtime_after_failure(
            reason_code: str,
        ) -> None:
            """Close runtime authority without converting failure to completion."""

            nonlocal claude_runtime_postprocess_receipt
            nonlocal claude_runtime_lifecycle_receipt
            if (
                claude_runtime is None
                or claude_runtime_lifecycle_receipt is not None
            ):
                record_claude_runtime_observation()
                return
            if process_tree is None:
                claude_runtime_lifecycle_receipt = (
                    claude_runtime.abort_before_process_scope(reason_code)
                )
            elif process_tree.process_creation_state in {
                "NOT_ATTEMPTED",
                "CREATION_FAILED_WITHOUT_PROCESS_OBJECT",
            }:
                claude_runtime_lifecycle_receipt = (
                    claude_runtime.abort_bound_scope_before_process_attach(
                        process_tree,
                        reason_code,
                    )
                )
            elif process_tree.process_creation_state == "PROCESS_CREATED":
                claude_runtime_lifecycle_receipt = (
                    claude_runtime.close_after_process_attach_failure(
                        process_tree,
                        reason_code,
                    )
                )
            elif (
                process_tree.attached
                and process_tree.closed
                and process_tree.population_zero_proven
                and not process_tree.emergency_closed
            ):
                claude_runtime_postprocess_receipt = (
                    reconcile_claude_runtime_after_scope_close(
                        claude_runtime,
                        process_tree,
                    )
                )
                claude_runtime_lifecycle_receipt = (
                    claude_runtime.revoke_after_normal_scope_close(
                        process_tree
                    )
                )
            elif process_tree.attached:
                claude_runtime_lifecycle_receipt = (
                    claude_runtime.emergency_close_to_quarantine_debt(
                        process_tree
                    )
                )
                claude_runtime_postprocess_receipt = (
                    claude_runtime.postprocess_receipt
                )
            else:
                raise WorkerExecutionError(
                    "Claude runtime failure disposal lacks a recognized "
                    "process-scope state"
                )
            record_claude_runtime_observation()

        def revoke_auxiliary_roots_after_scope_close() -> None:
            if len(auxiliary_revocation_receipts) == len(auxiliary_leases):
                return
            if process_tree is None:
                raise WorkerExecutionError(
                    "auxiliary roots cannot be revoked without their process scope"
                )
            for index in range(
                len(auxiliary_revocation_receipts),
                len(auxiliary_leases),
            ):
                lease = auxiliary_leases[index]
                if lease.process_scope_bound:
                    closure = prove_owned_process_scope_closed(
                        lease,
                        process_tree,
                    )
                    receipt = lease.revoke(closure)
                elif process is None:
                    binding = auxiliary_lease_bindings[index]
                    receipt = lease.abort_before_process_scope(
                        attempt_arm_sha256=binding[
                            "attempt_arm_sha256"
                        ],
                        process_scope_identity=binding[
                            "process_scope_identity"
                        ],
                        reason_code="SCOPE_BINDING_FAILED_BEFORE_LAUNCH",
                    )
                else:
                    raise WorkerExecutionError(
                        "launched process has an unbound auxiliary-root lease"
                    )
                append_auxiliary_revocation(index, receipt)
            process_observation["auxiliary_root_revocations"] = (
                auxiliary_revocation_receipts
            )
        try:
            def cancellation_requested() -> bool:
                if cancel_token is None:
                    return False
                if callable(cancel_token):
                    return bool(cancel_token())
                is_set = getattr(cancel_token, "is_set", None)
                if callable(is_set):
                    return bool(is_set())
                raise WorkerExecutionError(
                    "cancel_token must be callable or Event-like"
                )

            if cancellation_requested():
                process_observation = {
                    "process_tree_strategy": termination_capability,
                    "launch_blocked_before_process_creation": True,
                    "cancelled": True,
                }
                abort_auxiliary_roots_before_scope(
                    "CANCELLED_BEFORE_LAUNCH"
                )
                debt = _record_debt(
                    shard_dir,
                    arm_path=arm_path,
                    arm_sha256=arm_sha,
                    reason_code="CANCELLED_BEFORE_LAUNCH",
                    detail="worker was cancelled after arm and before process creation",
                    process_observation=process_observation,
                )
                raise WorkerExecutionIncomplete(
                    "worker launch cancelled before process creation",
                    arm_path=arm_path,
                    debt_path=debt,
                )
            if (
                termination_capability.get(
                    "exhaustive_descendant_termination_authority"
                )
                is not True
                or transaction_write_authority is None
            ):
                process_observation = {
                    "process_tree_strategy": termination_capability,
                    "launch_blocked_before_process_creation": True,
                }
                abort_auxiliary_roots_before_scope(
                    "PROCESS_AUTHORITY_UNSUPPORTED"
                )
                debt = _record_debt(
                    shard_dir,
                    arm_path=arm_path,
                    arm_sha256=arm_sha,
                    reason_code="PROCESS_AUTHORITY_UNSUPPORTED",
                    detail=(
                        "platform cannot prove exhaustive descendant termination "
                        "and transaction-scoped write confinement"
                    ),
                    process_observation=process_observation,
                )
                raise WorkerExecutionIncomplete(
                    "worker launch blocked: process authority is insufficient",
                    arm_path=arm_path,
                    debt_path=debt,
                )
            runtime_writable_roots = (
                ()
                if claude_runtime is None or sys.platform == "win32"
                else (claude_runtime.process_writable_root,)
            )
            # Windows Claude state mutability is deliberately narrower than a
            # writable runtime directory: the profile provider labels only the
            # pre-existing .claude.json state file Low-IL and retains a
            # no-delete handle.  Giving OwnedProcessScope the lease parent would
            # lower that whole directory and let the child create, delete, or
            # rename siblings.  POSIX must retain the attempt-private runtime
            # root here because Landlock has no equivalent per-file MIC label.
            try:
                scope_acquisition_deadline = (
                    time.monotonic() + float(lock_timeout_seconds)
                )
                if (
                    restricted_stage_binding is not None
                    and termination_capability.get("platform") == "WINDOWS"
                ):
                    process_tree = _OwnedProcessTree(
                        persistent_identity=process_scope_identity,
                        windows_job_only=True,
                    )
                else:
                    if os.name == "nt":
                        windows_output_authority = (
                            create_windows_private_execution_root(
                                output_scope
                            )
                        )
                        output_scope = windows_output_authority.path
                    windows_private_root_authorities = (
                        ()
                        if os.name != "nt"
                        else (
                            *(
                                (windows_output_authority,)
                                if windows_output_authority is not None
                                else ()
                            ),
                            *tuple(
                                authority
                                for authority in (
                                    lease.windows_private_execution_root_authority
                                    for lease in auxiliary_leases
                                )
                                if authority is not None
                            ),
                        )
                    )
                    process_tree = _OwnedProcessTree(
                        writable_roots=(
                            output_scope,
                            *auxiliary_roots,
                            *runtime_writable_roots,
                        ),
                        windows_private_root_authorities=(
                            windows_private_root_authorities
                        ),
                        persistent_identity=process_scope_identity,
                        lease_acquisition_deadline_monotonic=(
                            scope_acquisition_deadline
                        ),
                        lease_cancel_token=cancel_token,
                    )
            except BaseException as exc:
                process_observation = {
                    "process_tree_strategy": termination_capability,
                    "launch_blocked_before_process_creation": True,
                }
                abort_auxiliary_roots_before_scope(
                    "CLAUDE_RUNTIME_SCOPE_CONSTRUCTION_FAILED"
                )
                record_claude_runtime_observation()
                debt = _record_debt(
                    shard_dir,
                    arm_path=arm_path,
                    arm_sha256=arm_sha,
                    reason_code=(
                        "CLAUDE_RUNTIME_SCOPE_CONSTRUCTION_FAILED"
                    ),
                    detail=f"{type(exc).__name__}: {exc}",
                    process_observation=process_observation,
                )
                raise WorkerExecutionIncomplete(
                    "Claude runtime process-scope construction failed",
                    arm_path=arm_path,
                    debt_path=debt,
                ) from exc
            if claude_runtime is not None:
                try:
                    claude_runtime.bind_process_scope(process_tree)
                except ClaudeRuntimeMaterializationError as exc:
                    process_tree_close_attempted = True
                    with contextlib.suppress(BaseException):
                        process_tree.close()
                    record_claude_runtime_observation()
                    debt = _record_debt(
                        shard_dir,
                        arm_path=arm_path,
                        arm_sha256=arm_sha,
                        reason_code="CLAUDE_RUNTIME_SCOPE_BIND_FAILED",
                        detail=f"{type(exc).__name__}: {exc}",
                        process_observation=process_observation,
                    )
                    raise WorkerExecutionIncomplete(
                        "Claude runtime process-scope binding failed",
                        arm_path=arm_path,
                        debt_path=debt,
                    ) from exc
            for lease in auxiliary_leases:
                lease.bind_process_scope(process_tree)
            if observer_configured:
                remaining_before_launch = execution_deadline - time.monotonic()
                if remaining_before_launch <= 0:
                    raise WorkerExecutionError(
                        "execution deadline expired before observer preparation"
                    )
                observer_runtime_state = _invoke_bounded_callback(
                    _prepare_claude_turn_observer,
                    (
                        {
                            "output_scope": output_scope,
                            "auxiliary_writable_roots": auxiliary_roots,
                            "observer_configuration": (
                                normalized_observer_configuration
                            ),
                        },
                    ),
                    timeout_seconds=min(
                        float(bound_callback_timeout),
                        max(0.001, remaining_before_launch),
                    ),
                    label="completion_observer_prepare",
                )
                if cancellation_requested():
                    raise WorkerExecutionError(
                        "worker was cancelled during observer preparation"
                    )
            process_stdin: Any = subprocess.DEVNULL
            if stdin_path is not None:
                # Open and re-measure the exact handle passed to Popen.  This closes
                # the check/open gap: the process consumes these measured bytes,
                # while the post-exit replay below detects path mutation.
                stdin_descriptor = os.open(
                    _native_rooted_path(stdin_path),
                    os.O_RDONLY | int(getattr(os, "O_BINARY", 0) or 0),
                )
                stdin_handle = os.fdopen(
                    stdin_descriptor,
                    "rb",
                    closefd=True,
                )
                if not stat.S_ISREG(os.fstat(stdin_handle.fileno()).st_mode):
                    raise WorkerExecutionError("stdin handle is not a regular file")
                opened_raw = stdin_handle.read()
                if (
                    len(opened_raw) != stdin_contract["size"]
                    or _digest_bytes(opened_raw) != stdin_contract["sha256"]
                ):
                    raise WorkerExecutionError("stdin bound input bytes changed before launch")
                stdin_handle.seek(0)
                process_stdin = stdin_handle
            if startup_authority_evidence is not None:
                try:
                    launch_replay = replay_startup_permit_binding(
                        scratchpad=root,
                        expected_run_id=bindings.run_id,
                        binding=startup_authority_evidence["binding"],
                    )
                except (
                    AuxiliaryWritableRootStartupError,
                    OSError,
                ) as exc:
                    raise WorkerExecutionError(
                        "startup authority became stale before process creation"
                    ) from exc
                if (
                    launch_replay.get("binding")
                    != startup_authority_evidence["binding"]
                    or launch_replay.get("current_pointer")
                    != startup_authority_evidence["current_pointer"]
                ):
                    raise WorkerExecutionError(
                        "startup authority changed before process creation"
                    )
            if provider_stdout_binding is not None:
                launch_provider_binding = _claude_stream_stdout_binding(
                    normalized_provider_stdout_configuration,
                    argv=actual_argv,
                    stdout_limit_bytes=bound_stdout_limit,
                    cwd=cwd_path,
                    effective_model=bindings.effective_model,
                )
                if launch_provider_binding != provider_stdout_binding:
                    raise WorkerExecutionError(
                        "provider stdout evidence binding changed before "
                        "process creation"
                    )
            if normalized_claude_security_request is not None:
                try:
                    _recheck_claude_executable_before_launch(
                        normalized_claude_security_request[
                            "executable_observation"
                        ],
                        launch_executable=str(executable),
                    )
                except _ClaudeExecutableObservationError as exc:
                    raise WorkerExecutionError(
                        "Claude executable authority changed before process "
                        f"creation: {exc}"
                    ) from exc
            physical_argv = process_tree.wrap_argv(tuple(actual_argv))
            try:
                process = process_tree.create_process(
                    physical_argv,
                    cwd=str(cwd_path),
                    env=env,
                    stdin=process_stdin,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    shell=False,
                    **process_tree.popen_kwargs(),
                )
            except BaseException as exc:
                process_observation["process_creation"] = (
                    process_tree.process_creation_evidence
                )
                process_tree_close_attempted = True
                close_error: BaseException | None = None
                try:
                    process_tree.close()
                except BaseException as close_exc:
                    close_error = close_exc
                if (
                    claude_runtime is not None
                    and close_error is None
                ):
                    try:
                        claude_runtime_lifecycle_receipt = (
                            claude_runtime.abort_bound_scope_before_process_attach(
                                process_tree,
                                "CLAUDE_RUNTIME_PROCESS_CREATION_FAILED",
                            )
                        )
                    except ClaudeRuntimeMaterializationError as runtime_exc:
                        close_error = runtime_exc
                if close_error is None:
                    try:
                        revoke_auxiliary_roots_after_scope_close()
                    except BaseException as revocation_exc:
                        close_error = revocation_exc
                record_claude_runtime_observation()
                debt = _record_debt(
                    shard_dir,
                    arm_path=arm_path,
                    arm_sha256=arm_sha,
                    reason_code=(
                        "CLAUDE_RUNTIME_PROCESS_CREATION_FAILED"
                    ),
                    detail=(
                        f"{type(exc).__name__}: {exc}"
                        + (
                            ""
                            if close_error is None
                            else (
                                "; closure_error="
                                f"{type(close_error).__name__}: "
                                f"{close_error}"
                            )
                        )
                    ),
                    process_observation=process_observation,
                )
                raise WorkerExecutionIncomplete(
                    "Claude runtime process creation failed",
                    arm_path=arm_path,
                    debt_path=debt,
                ) from exc
            # Begin concurrent bounded drains immediately.  On POSIX the child is
            # already executable when Popen returns; waiting until after process
            # identity observation could deadlock on a full pipe.  On Windows the
            # child remains suspended until the Job Object attachment below.
            streams = _BoundedProcessStreams(
                process,
                stdout_limit=bound_stdout_limit,
                stderr_limit=bound_stderr_limit,
            )
            try:
                process_tree.attach(process)
            except BaseException as exc:
                process_observation["process_creation"] = (
                    process_tree.process_creation_evidence
                )
                cleanup_error: BaseException | None = None
                runtime_attach_cleanup_handled = False
                try:
                    if (
                        process_tree.process_creation_state
                        == "PROCESS_CREATED"
                    ):
                        process_tree.terminate_created_process(
                            timeout_seconds=5.0
                        )
                        process_tree_close_attempted = True
                        process_tree.close()
                    elif (
                        process_tree.attached
                        and claude_runtime is not None
                    ):
                        process_tree_close_attempted = True
                        claude_runtime_lifecycle_receipt = (
                            claude_runtime.emergency_close_to_quarantine_debt(
                                process_tree
                            )
                        )
                        claude_runtime_postprocess_receipt = (
                            claude_runtime.postprocess_receipt
                        )
                        runtime_attach_cleanup_handled = True
                        with contextlib.suppress(BaseException):
                            process.wait(timeout=5)
                    elif process_tree.attached:
                        process_tree.terminate()
                        with contextlib.suppress(BaseException):
                            process.wait(timeout=5)
                        process_tree_close_attempted = True
                        process_tree.close()
                    else:
                        process_tree_close_attempted = True
                        process_tree.close()
                except BaseException as cleanup_exc:
                    cleanup_error = cleanup_exc
                if claude_runtime is not None:
                    try:
                        if runtime_attach_cleanup_handled:
                            pass
                        elif (
                            process_tree.process_creation_state
                            == "PROCESS_CREATED"
                            and cleanup_error is None
                        ):
                            claude_runtime_lifecycle_receipt = (
                                claude_runtime.close_after_process_attach_failure(
                                    process_tree,
                                    "CLAUDE_RUNTIME_PROCESS_ATTACH_FAILED",
                                )
                            )
                        elif cleanup_error is None:
                            claude_runtime_lifecycle_receipt = (
                                claude_runtime.abort_bound_scope_before_process_attach(
                                    process_tree,
                                    "CLAUDE_RUNTIME_PROCESS_ATTACH_FAILED",
                                )
                            )
                    except ClaudeRuntimeMaterializationError as runtime_exc:
                        cleanup_error = runtime_exc
                if (
                    cleanup_error is None
                    and process_tree.population_zero_proven
                ):
                    try:
                        revoke_auxiliary_roots_after_scope_close()
                    except BaseException as revocation_exc:
                        cleanup_error = revocation_exc
                record_claude_runtime_observation()
                if streams is not None:
                    with contextlib.suppress(BaseException):
                        stdout, stderr = streams.finish(timeout=5)
                with contextlib.suppress(BaseException):
                    stdout_blob = _persist_blob(
                        blob_dir,
                        "stdout",
                        stdout,
                    )
                with contextlib.suppress(BaseException):
                    stderr_blob = _persist_blob(
                        blob_dir,
                        "stderr",
                        stderr,
                    )
                debt = _record_debt(
                    shard_dir,
                    arm_path=arm_path,
                    arm_sha256=arm_sha,
                    reason_code="CLAUDE_RUNTIME_PROCESS_ATTACH_FAILED",
                    detail=(
                        f"{type(exc).__name__}: {exc}"
                        + (
                            ""
                            if cleanup_error is None
                            else (
                                "; cleanup_error="
                                f"{type(cleanup_error).__name__}: "
                                f"{cleanup_error}"
                            )
                        )
                    ),
                    process_observation=process_observation,
                    stdout_blob=stdout_blob,
                    stderr_blob=stderr_blob,
                )
                raise WorkerExecutionIncomplete(
                    "Claude runtime process attachment failed",
                    arm_path=arm_path,
                    debt_path=debt,
                ) from exc
            if claude_runtime is not None:
                try:
                    claude_runtime.invalidate_child_environment_after_process_attach(
                        process_tree
                    )
                finally:
                    env.clear()
            if transaction_write_authority == _RESTRICTED_CLAUDE_STAGE_AUTHORITY:
                restricted_os_write = (
                    isinstance(restricted_stage_binding, Mapping)
                    and restricted_stage_binding.get("os_write_confinement")
                    != "NOT_PROVIDED"
                )
                observed_write_confinement = (
                    process_tree.write_confinement_proven
                    if restricted_os_write
                    else False
                )
                if restricted_os_write and observed_write_confinement is not True:
                    raise WorkerExecutionError(
                        "restricted Claude Linux scope did not prove Landlock write confinement"
                    )
                transaction_stage_boundary_proven = True
                raw_write_confinement_binding: Any = restricted_stage_binding
            else:
                observed_write_confinement = (
                    process_tree.write_confinement_proven
                    if transaction_write_authority == "EXHAUSTIVE"
                    else getattr(
                        process_tree,
                        "serialized_stage_write_confinement_proven",
                        False,
                    )
                )
                transaction_stage_boundary_proven = False
                raw_write_confinement_binding = getattr(
                    process_tree, "write_confinement_binding", None
                )
                if observed_write_confinement is not True:
                    raise WorkerExecutionError(
                        "process provider did not prove write confinement"
                    )
            write_confinement_binding = _active_write_confinement_binding(
                transaction_write_authority,
                raw_write_confinement_binding,
                capability=termination_capability,
                process_scope_identity=process_scope_identity,
            )
            try:
                creation_identity = _process_creation_identity(process)
            except WorkerExecutionError:
                creation_identity = process_tree.pre_release_process_identity
                if creation_identity is None:
                    raise
            process_observation = {
                "pid": process.pid,
                "creation_identity": creation_identity,
                "process_creation": process_tree.process_creation_evidence,
                "launch_requested_unix_ns": launch_requested_wall_ns,
                "observed_start_unix_ns": time.time_ns(),
                "process_tree_strategy": termination_capability,
                "process_tree_terminated": False,
                "write_confinement_proven": observed_write_confinement,
                "transaction_stage_boundary_proven": (
                    transaction_stage_boundary_proven
                ),
                "transaction_write_authority": transaction_write_authority,
                "write_confinement_binding": write_confinement_binding,
            }
            wait_deadline = execution_deadline
            termination_cause = "PROCESS_EXIT"
            provisional_output_snapshot: list[dict[str, Any]] = []
            provisional_output_rejection = ""
            while process.poll() is None:
                if cancellation_requested():
                    termination_cause = "CANCELLED"
                    break
                if streams.any_overflow:
                    termination_cause = "STREAM_LIMIT_EXCEEDED"
                    break
                if streams.any_error:
                    termination_cause = "STREAM_CAPTURE_FAILED"
                    break
                remaining = wait_deadline - time.monotonic()
                if remaining <= 0:
                    termination_cause = "TIMEOUT"
                    break
                if observer_configured:
                    live_stdout, live_stderr = streams.snapshot()
                    probe_result = _invoke_bounded_callback(
                        provisional_completion_probe,
                        ({
                            "output_scope": output_scope,
                            "auxiliary_writable_roots": auxiliary_roots,
                            "stdout": live_stdout,
                            "stderr": live_stderr,
                            "observer_configuration": (
                                normalized_observer_configuration
                            ),
                            "observer_runtime_state": observer_runtime_state,
                            "elapsed_monotonic_ns": (
                                time.monotonic_ns() - start_mono_ns
                            ),
                        },),
                        timeout_seconds=min(
                            float(bound_callback_timeout),
                            max(0.001, remaining),
                        ),
                        label="provisional_completion_probe",
                    )
                    if probe_result is not None:
                        normalized_probe = _normalize_json(
                            probe_result,
                            label="provisional completion observation",
                        )
                        if not isinstance(normalized_probe, dict):
                            raise WorkerExecutionError(
                                "provisional completion observation must be an object"
                            )
                        signal_name = normalized_probe.get("signal")
                        if signal_name not in completion_signals:
                            raise WorkerExecutionError(
                                "provisional completion observation emitted an "
                                "unarmed signal"
                            )
                        provisional_observation = normalized_probe
                        try:
                            provisional_output_snapshot = (
                                _provisional_assigned_output_snapshot(
                                    root=root,
                                    output_scope=output_scope,
                                    output_scope_relative=output_scope_rel,
                                    output_contract=output_contract,
                                    limit_bytes=bound_staged_output_limit,
                                )
                            )
                            termination_cause = "PROVISIONAL_COMPLETION"
                        except (
                            WorkerExecutionError,
                            _StagedOutputViolation,
                        ) as exc:
                            provisional_output_rejection = (
                                f"{type(exc).__name__}: {exc}"
                            )
                            termination_cause = (
                                "PROVISIONAL_OUTPUT_REJECTED"
                            )
                        break
                streams.state_changed.wait(min(0.025, remaining))
                streams.state_changed.clear()

            # A fast provider can write its terminal evidence and exit between
            # the loop condition and the next scheduled probe.  Stronger
            # transport debt wins; otherwise perform exactly one bounded final
            # pre-cleanup probe so a valid turn is not deterministically lost.
            if (
                termination_cause == "PROCESS_EXIT"
                and observer_configured
                and not streams.any_overflow
                and not streams.any_error
                and time.monotonic() < execution_deadline
            ):
                live_stdout, live_stderr = streams.snapshot()
                final_probe_result = _invoke_bounded_callback(
                    provisional_completion_probe,
                    ({
                        "output_scope": output_scope,
                        "auxiliary_writable_roots": auxiliary_roots,
                        "stdout": live_stdout,
                        "stderr": live_stderr,
                            "observer_configuration": (
                                normalized_observer_configuration
                            ),
                            "observer_runtime_state": observer_runtime_state,
                            "elapsed_monotonic_ns": (
                                time.monotonic_ns() - start_mono_ns
                            ),
                    },),
                    timeout_seconds=min(
                        float(bound_callback_timeout),
                        max(0.001, execution_deadline - time.monotonic()),
                    ),
                    label="final_precleanup_completion_probe",
                )
                if final_probe_result is not None:
                    normalized_probe = _normalize_json(
                        final_probe_result,
                        label="provisional completion observation",
                    )
                    if not isinstance(normalized_probe, dict):
                        raise WorkerExecutionError(
                            "provisional completion observation must be an object"
                        )
                    signal_name = normalized_probe.get("signal")
                    if signal_name not in completion_signals:
                        raise WorkerExecutionError(
                            "provisional completion observation emitted an "
                            "unarmed signal"
                        )
                    provisional_observation = normalized_probe
                    try:
                        provisional_output_snapshot = (
                            _provisional_assigned_output_snapshot(
                                root=root,
                                output_scope=output_scope,
                                output_scope_relative=output_scope_rel,
                                output_contract=output_contract,
                                limit_bytes=bound_staged_output_limit,
                            )
                        )
                        termination_cause = (
                            "PROVISIONAL_COMPLETION_AFTER_ROOT_EXIT"
                        )
                    except (
                        WorkerExecutionError,
                        _StagedOutputViolation,
                    ) as exc:
                        provisional_output_rejection = (
                            f"{type(exc).__name__}: {exc}"
                        )
                        termination_cause = "PROVISIONAL_OUTPUT_REJECTED"

            # Preserve whether the root exited on its own in the narrow gap
            # after a live signal probe but before provider-owned scope
            # termination.  A natural non-zero root exit is specific transport
            # debt; it must not be mistaken for the expected return code caused
            # by terminating a still-live root after a provisional signal.
            root_exited_before_scope_termination = process.poll() is not None

            # A zero-exit parent does not authorize background descendants, and an
            # overflowing process must not continue producing side effects.  Always
            # terminate the provider-owned scope before inspecting any output.
            process_tree.terminate()
            process_observation["process_tree_terminated"] = process_tree.terminated
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired as exc:
                raise WorkerExecutionError(
                    "terminated worker did not reach an observable exit"
                ) from exc
            stdout, stderr = streams.finish(timeout=5)
            stream_observation = streams.observation()
            if streams.any_overflow:
                termination_cause = "STREAM_LIMIT_EXCEEDED"
            process_observation.update(
                {
                    "observed_exit_unix_ns": time.time_ns(),
                    "duration_monotonic_ns": time.monotonic_ns() - start_mono_ns,
                    "returncode": process.returncode,
                    "timed_out": termination_cause == "TIMEOUT",
                    "cancelled": termination_cause == "CANCELLED",
                    "stream_limits": stream_limits,
                    "stream_observation": stream_observation,
                    "completion_observer_mode": completion_observer_binding["mode"],
                    "root_exit_origin": (
                        "PROVIDER_TERMINATED"
                        if (
                            termination_cause == "PROVISIONAL_COMPLETION"
                            and not root_exited_before_scope_termination
                        )
                        else (
                            "NATURAL_SIGNAL_OBSERVED_POSTEXIT"
                            if termination_cause
                            in {
                                "PROVISIONAL_COMPLETION",
                                "PROVISIONAL_COMPLETION_AFTER_ROOT_EXIT",
                            }
                            else "NATURAL"
                        )
                    ),
                }
            )
            if observer_configured:
                process_observation[
                    "provisional_output_snapshot"
                ] = provisional_output_snapshot
                process_observation[
                    "provisional_output_snapshot_sha256"
                ] = _digest_json(provisional_output_snapshot)
            # Scope cleanup is part of execution authority, not best-effort
            # teardown.  It must succeed before any completion can be minted.
            process_tree_close_attempted = True
            try:
                process_tree.close()
                if windows_output_authority is not None:
                    windows_output_authority.close_after_medium_restore()
                    windows_output_authority = None
            except BaseException as exc:
                process_observation["process_scope_cleanup_succeeded"] = False
                emergency_detail = ""
                try:
                    process_tree.emergency_close()
                    process_observation[
                        "process_scope_emergency_close_succeeded"
                    ] = True
                except BaseException as emergency_exc:
                    process_observation[
                        "process_scope_emergency_close_succeeded"
                    ] = False
                    emergency_detail = (
                        "; emergency_close_error="
                        f"{type(emergency_exc).__name__}: {emergency_exc}"
                    )
                if (
                    getattr(process_tree, "closed", False) is True
                    and getattr(
                        process_tree,
                        "population_zero_proven",
                        False,
                    )
                    is True
                ):
                    try:
                        revoke_auxiliary_roots_after_scope_close()
                    except BaseException as revocation_exc:
                        emergency_detail += (
                            "; auxiliary_revocation_error="
                            f"{type(revocation_exc).__name__}: "
                            f"{revocation_exc}"
                        )
                else:
                    process_observation[
                        "auxiliary_root_revocation_state"
                    ] = "QUARANTINED_SCOPE_NOT_ZERO"
                stdout_blob = _persist_blob(blob_dir, "stdout", stdout)
                stderr_blob = _persist_blob(blob_dir, "stderr", stderr)
                debt = _record_debt(
                    shard_dir,
                    arm_path=arm_path,
                    arm_sha256=arm_sha,
                    reason_code="PROCESS_SCOPE_CLEANUP_FAILED",
                    detail=f"{type(exc).__name__}: {exc}{emergency_detail}",
                    process_observation=process_observation,
                    stdout_blob=stdout_blob,
                    stderr_blob=stderr_blob,
                )
                raise WorkerExecutionIncomplete(
                    "worker process scope cleanup failed",
                    arm_path=arm_path,
                    debt_path=debt,
                ) from exc
            process_observation["process_scope_cleanup_succeeded"] = True
            process_observation["process_population_zero_proven"] = (
                process_tree.population_zero_proven
            )
            natural_nonzero_result = (
                process.returncode != 0
                and process_observation["root_exit_origin"]
                != "PROVIDER_TERMINATED"
                and termination_cause
                in {
                    "PROCESS_EXIT",
                    "PROVISIONAL_COMPLETION",
                    "PROVISIONAL_COMPLETION_AFTER_ROOT_EXIT",
                }
            )
            if claude_runtime is not None and natural_nonzero_result:
                try:
                    dispose_claude_runtime_after_nonzero()
                except BaseException:
                    # The provider's nonzero result remains the primary debt.
                    # The cleanup fault is retained as secondary evidence and
                    # must never relabel or complete the failed attempt.
                    pass
            elif claude_runtime is not None:
                try:
                    claude_runtime_postprocess_receipt = (
                        reconcile_claude_runtime_after_scope_close(
                            claude_runtime,
                            process_tree,
                        )
                    )
                    claude_runtime_lifecycle_receipt = (
                        claude_runtime.revoke_after_normal_scope_close(
                            process_tree
                        )
                    )
                    record_claude_runtime_observation()
                    lifecycle_replay = (
                        replay_claude_runtime_lifecycle_receipt(
                            claude_runtime_lifecycle_receipt
                        )
                    )
                    replay_claude_runtime_postprocess_receipt(
                        claude_runtime_postprocess_receipt
                    )
                    if (
                        lifecycle_replay.get("completion_authority")
                        is not True
                    ):
                        raise WorkerExecutionError(
                            "Claude runtime normal closure did not grant "
                            "completion authority"
                        )
                except BaseException as exc:
                    record_claude_runtime_observation()
                    raise WorkerExecutionError(
                        "Claude runtime normal closure failed: "
                        f"{type(exc).__name__}: {exc}"
                    ) from exc
            if startup_authority_evidence is not None:
                try:
                    closed_scope_replay = replay_startup_permit_binding(
                        scratchpad=root,
                        expected_run_id=bindings.run_id,
                        binding=startup_authority_evidence["binding"],
                    )
                except (
                    AuxiliaryWritableRootStartupError,
                    OSError,
                ) as exc:
                    raise WorkerExecutionError(
                        "startup authority changed before completion"
                    ) from exc
                if (
                    closed_scope_replay.get("binding")
                    != startup_authority_evidence["binding"]
                    or closed_scope_replay.get("current_pointer")
                    != startup_authority_evidence["current_pointer"]
                ):
                    raise WorkerExecutionError(
                        "startup authority changed before completion"
                    )
            if normalized_claude_security_request is not None:
                try:
                    _recheck_claude_executable_before_launch(
                        normalized_claude_security_request[
                            "executable_observation"
                        ],
                        launch_executable=str(executable),
                    )
                except _ClaudeExecutableObservationError as exc:
                    raise WorkerExecutionError(
                        "Claude executable authority changed before completion: "
                        f"{exc}"
                    ) from exc
            stdout_blob = _persist_blob(blob_dir, "stdout", stdout)
            stderr_blob = _persist_blob(blob_dir, "stderr", stderr)
            if termination_cause == "PROVISIONAL_OUTPUT_REJECTED":
                revoke_auxiliary_roots_after_scope_close()
                debt = _record_debt(
                    shard_dir,
                    arm_path=arm_path,
                    arm_sha256=arm_sha,
                    reason_code="OUTPUT_NOT_READY_AT_COMPLETION",
                    detail=(
                        "provider turn-end arrived without a complete, "
                        "stable assigned-output denominator: "
                        f"{provisional_output_rejection}"
                    ),
                    process_observation=process_observation,
                    stdout_blob=stdout_blob,
                    stderr_blob=stderr_blob,
                )
                raise WorkerExecutionIncomplete(
                    "provisional completion lacked ready assigned outputs",
                    arm_path=arm_path,
                    debt_path=debt,
                )
            if termination_cause in {
                "PROVISIONAL_COMPLETION",
                "PROVISIONAL_COMPLETION_AFTER_ROOT_EXIT",
            }:
                try:
                    (
                        completion_evidence_rows,
                        completion_evidence_exact,
                    ) = _capture_completion_evidence(
                        records=completion_evidence_binding,
                        auxiliary_roots=auxiliary_roots,
                        blob_dir=blob_dir,
                    )
                    revoke_auxiliary_roots_after_scope_close()
                    replay_digest = _completion_replay_digest(
                        evidence_rows=completion_evidence_rows,
                        stdout_blob=stdout_blob,
                        stderr_blob=stderr_blob,
                        provisional_observation=provisional_observation,
                        observer_configuration=(
                            normalized_observer_configuration
                        ),
                    )
                    replay_result = _invoke_bounded_callback(
                        final_completion_replay,
                        (
                            provisional_observation,
                            {
                            "stdout": stdout,
                            "stderr": stderr,
                            "observer_configuration": (
                                normalized_observer_configuration
                            ),
                            "completion_evidence": (
                                completion_evidence_exact
                            ),
                            "evidence_replay_digest": replay_digest,
                            "process_population_zero_proven": (
                                process_tree.population_zero_proven
                            ),
                            "process_scope_cleanup_succeeded": True,
                            },
                        ),
                        timeout_seconds=float(bound_callback_timeout),
                        label="final_completion_replay",
                    )
                    normalized_replay = _normalize_json(
                        replay_result,
                        label="final completion replay",
                    )
                    expected_replay_fields = {
                        "accepted",
                        "signal",
                        "replay_digest",
                    }
                    if (
                        not isinstance(normalized_replay, dict)
                        or set(normalized_replay) != expected_replay_fields
                        or type(normalized_replay.get("accepted")) is not bool
                        or normalized_replay.get("signal")
                        != provisional_observation.get("signal")
                        or normalized_replay.get("replay_digest")
                        != replay_digest
                    ):
                        raise WorkerExecutionError(
                            "final completion replay result is malformed"
                        )
                    _require_sha(
                        normalized_replay.get("replay_digest"),
                        "final completion replay digest",
                    )
                    final_replay_observation = normalized_replay
                except BaseException as replay_exc:
                    revocation_detail = ""
                    if (
                        len(auxiliary_revocation_receipts)
                        != len(auxiliary_leases)
                    ):
                        try:
                            revoke_auxiliary_roots_after_scope_close()
                        except BaseException as revocation_exc:
                            revocation_detail = (
                                "; auxiliary_revocation_error="
                                f"{type(revocation_exc).__name__}: "
                                f"{revocation_exc}"
                            )
                    debt = _record_debt(
                        shard_dir,
                        arm_path=arm_path,
                        arm_sha256=arm_sha,
                        reason_code="FINAL_REPLAY_REJECTED",
                        detail=(
                            "trusted final replay failed: "
                            f"{type(replay_exc).__name__}: {replay_exc}"
                            f"{revocation_detail}"
                        ),
                        process_observation=process_observation,
                        stdout_blob=stdout_blob,
                        stderr_blob=stderr_blob,
                    )
                    raise WorkerExecutionIncomplete(
                        "provisional completion failed final replay",
                        arm_path=arm_path,
                        debt_path=debt,
                    ) from replay_exc
                if final_replay_observation["accepted"] is not True:
                    debt = _record_debt(
                        shard_dir,
                        arm_path=arm_path,
                        arm_sha256=arm_sha,
                        reason_code="FINAL_REPLAY_REJECTED",
                        detail="trusted final replay rejected the provisional signal",
                        process_observation=process_observation,
                        stdout_blob=stdout_blob,
                        stderr_blob=stderr_blob,
                    )
                    raise WorkerExecutionIncomplete(
                        "provisional completion was rejected by final replay",
                        arm_path=arm_path,
                        debt_path=debt,
                    )
                process_observation.update(
                    {
                        "completion_signal": provisional_observation["signal"],
                        "provisional_observation": provisional_observation,
                        "final_completion_replay": final_replay_observation,
                        "completion_evidence": completion_evidence_rows,
                    }
                )
            elif observer_configured and termination_cause == "PROCESS_EXIT":
                revoke_auxiliary_roots_after_scope_close()
                if process.returncode != 0:
                    debt = _record_debt(
                        shard_dir,
                        arm_path=arm_path,
                        arm_sha256=arm_sha,
                        reason_code="NONZERO_EXIT",
                        detail=(
                            "worker exited with return code "
                            f"{process.returncode} before an armed completion "
                            "signal was observed"
                            + (
                                "; claude_runtime_failure_cleanup="
                                + process_observation[
                                    "claude_runtime_failure_cleanup"
                                ]["detail"]
                                if process_observation.get(
                                    "claude_runtime_failure_cleanup",
                                    {},
                                ).get("status")
                                == "FAILED"
                                else ""
                            )
                        ),
                        process_observation=process_observation,
                        stdout_blob=stdout_blob,
                        stderr_blob=stderr_blob,
                    )
                    raise WorkerExecutionIncomplete(
                        "worker exited non-zero",
                        arm_path=arm_path,
                        debt_path=debt,
                    )
                debt = _record_debt(
                    shard_dir,
                    arm_path=arm_path,
                    arm_sha256=arm_sha,
                    reason_code="COMPLETION_SIGNAL_MISSING",
                    detail=(
                        "worker exited before an armed provisional completion "
                        "signal was observed"
                    ),
                    process_observation=process_observation,
                    stdout_blob=stdout_blob,
                    stderr_blob=stderr_blob,
                )
                raise WorkerExecutionIncomplete(
                    "worker exited without an armed completion signal",
                    arm_path=arm_path,
                    debt_path=debt,
                )
            else:
                revoke_auxiliary_roots_after_scope_close()
                if not observer_configured:
                    process_observation["completion_signal"] = (
                        "PROCESS_EXIT_ZERO"
                    )
            if termination_cause == "STREAM_LIMIT_EXCEEDED":
                overflow_names = [
                    name
                    for name in ("stdout", "stderr")
                    if stream_observation[f"{name}_overflow"]
                ]
                debt = _record_debt(
                    shard_dir,
                    arm_path=arm_path,
                    arm_sha256=arm_sha,
                    reason_code="STREAM_LIMIT_EXCEEDED",
                    detail=(
                        "worker exceeded exact stream byte ceiling(s): "
                        + ",".join(overflow_names)
                    ),
                    process_observation=process_observation,
                    stdout_blob=stdout_blob,
                    stderr_blob=stderr_blob,
                )
                raise WorkerExecutionIncomplete(
                    "worker stream byte ceiling exceeded",
                    arm_path=arm_path,
                    debt_path=debt,
                )
            if termination_cause == "TIMEOUT":
                debt = _record_debt(
                    shard_dir,
                    arm_path=arm_path,
                    arm_sha256=arm_sha,
                    reason_code="TIMEOUT",
                    detail="worker exceeded its provider-owned timeout",
                    process_observation=process_observation,
                    stdout_blob=stdout_blob,
                    stderr_blob=stderr_blob,
                )
                raise WorkerExecutionIncomplete(
                    "worker execution timed out", arm_path=arm_path, debt_path=debt
                )
            if termination_cause == "CANCELLED":
                debt = _record_debt(
                    shard_dir,
                    arm_path=arm_path,
                    arm_sha256=arm_sha,
                    reason_code="CANCELLED",
                    detail="worker execution was cancelled by its scheduler",
                    process_observation=process_observation,
                    stdout_blob=stdout_blob,
                    stderr_blob=stderr_blob,
                )
                raise WorkerExecutionIncomplete(
                    "worker execution cancelled", arm_path=arm_path, debt_path=debt
                )
            if (
                process.returncode != 0
                and process_observation["root_exit_origin"]
                != "PROVIDER_TERMINATED"
            ):
                debt = _record_debt(
                    shard_dir,
                    arm_path=arm_path,
                    arm_sha256=arm_sha,
                    reason_code="NONZERO_EXIT",
                    detail=(
                        f"worker exited with return code {process.returncode}"
                        + (
                            "; claude_runtime_failure_cleanup="
                            + process_observation[
                                "claude_runtime_failure_cleanup"
                            ]["detail"]
                            if process_observation.get(
                                "claude_runtime_failure_cleanup",
                                {},
                            ).get("status")
                            == "FAILED"
                            else ""
                        )
                    ),
                    process_observation=process_observation,
                    stdout_blob=stdout_blob,
                    stderr_blob=stderr_blob,
                )
                raise WorkerExecutionIncomplete(
                    "worker exited non-zero", arm_path=arm_path, debt_path=debt
                )
            if provider_stdout_binding is not None:
                try:
                    provider_stdout_evidence = _validate_claude_stream_json(
                        stdout,
                        expected_session_id=provider_stdout_binding[
                            "expected_session_id"
                        ],
                        expected_init_contract=provider_stdout_binding[
                            "expected_init_contract"
                        ],
                        max_line_bytes=provider_stdout_binding[
                            "max_line_bytes"
                        ],
                        max_stream_bytes=provider_stdout_binding[
                            "max_stream_bytes"
                        ],
                    )
                except _ClaudeStreamJsonEvidenceError as exc:
                    debt = _record_debt(
                        shard_dir,
                        arm_path=arm_path,
                        arm_sha256=arm_sha,
                        reason_code="PROVIDER_STREAM_EVIDENCE_REJECTED",
                        detail=f"{exc.code}: {exc}",
                        process_observation=process_observation,
                        stdout_blob=stdout_blob,
                        stderr_blob=stderr_blob,
                    )
                    raise WorkerExecutionIncomplete(
                        "Claude provider stdout evidence was rejected",
                        arm_path=arm_path,
                        debt_path=debt,
                    ) from exc
                process_observation["provider_stdout_evidence"] = (
                    provider_stdout_evidence
                )

            if bound_output_source == STDOUT_ASSIGNED_OUTPUT:
                # Stdout bytes are transport, not model-semantic authority.  The
                # provider materializes them only after a clean, contained exit;
                # the same strict parser and publication transaction then apply.
                contamination = _scope_file_names(output_scope)
                if contamination:
                    detail = (
                        "stdout-assigned output scope was modified by the worker: "
                        f"{contamination!r}"
                    )
                    debt = _record_debt(
                        shard_dir,
                        arm_path=arm_path,
                        arm_sha256=arm_sha,
                        reason_code="OUTPUT_SOURCE_CONTAMINATION",
                        detail=detail,
                        process_observation=process_observation,
                        stdout_blob=stdout_blob,
                        stderr_blob=stderr_blob,
                    )
                    raise WorkerExecutionIncomplete(
                        detail, arm_path=arm_path, debt_path=debt
                    )
                stdout_row = output_contract[0]
                stdout_rel = f"{output_scope_rel}/{stdout_row['relative_path']}"
                parent_rel = Path(stdout_rel).parent.as_posix()
                if parent_rel != ".":
                    _make_safe_directory(root, parent_rel)
                stdout_path = _safe_descendant(root, stdout_rel, allow_missing=True)
                _publish_absent_bytes(stdout_path, stdout)

            observed_names = _scope_file_names(output_scope)
            expected_names = [row["relative_path"] for row in output_contract]
            if observed_names != expected_names:
                detail = (
                    f"assigned output denominator mismatch: expected={expected_names!r} "
                    f"observed={observed_names!r}"
                )
                debt = _record_debt(
                    shard_dir,
                    arm_path=arm_path,
                    arm_sha256=arm_sha,
                    reason_code="OUTPUT_DENOMINATOR_MISMATCH",
                    detail=detail,
                    process_observation=process_observation,
                    stdout_blob=stdout_blob,
                    stderr_blob=stderr_blob,
                )
                raise WorkerExecutionIncomplete(detail, arm_path=arm_path, debt_path=debt)

            observed_outputs: list[dict[str, Any]] = []
            for expected in output_contract:
                try:
                    path = _safe_descendant(
                        root,
                        f"{output_scope_rel}/{expected['relative_path']}",
                        allow_missing=False,
                    )
                except WorkerExecutionError as exc:
                    raise _StagedOutputViolation(
                        "UNSAFE_STAGED_ENTRY",
                        f"assigned staged output is unsafe: {expected['relative_path']}",
                    ) from exc
                raw = _read_staged_regular_file(
                    path, limit_bytes=bound_staged_output_limit
                )
                parsed_digest = _invoke_parser_with_registered_guard(
                    parser_digest,
                    (path, raw),
                    label="strict parser construction",
                )
                _require_sha(parsed_digest, "parser digest")
                observed_outputs.append(
                    {
                        "assignment_id": expected["assignment_id"],
                        "relative_path": expected["relative_path"],
                        "publish_relative_path": expected["publish_relative_path"],
                        "is_transcript": expected["is_transcript"],
                        "source_mode": bound_output_source,
                        "raw_sha256": _digest_bytes(raw),
                        "raw_size": len(raw),
                        "parsed_sha256": parsed_digest,
                        "cas_blob": _persist_blob(blob_dir, "output", raw),
                    }
                )
            if observer_configured:
                final_output_snapshot = [
                    {
                        "assignment_id": row["assignment_id"],
                        "relative_path": row["relative_path"],
                        "raw_sha256": row["raw_sha256"],
                        "raw_size": row["raw_size"],
                    }
                    for row in observed_outputs
                ]
                if final_output_snapshot != provisional_output_snapshot:
                    detail = (
                        "assigned output bytes changed after the accepted "
                        "provider completion signal"
                    )
                    debt = _record_debt(
                        shard_dir,
                        arm_path=arm_path,
                        arm_sha256=arm_sha,
                        reason_code="OUTPUT_CHANGED_AFTER_COMPLETION_SIGNAL",
                        detail=detail,
                        process_observation=process_observation,
                        stdout_blob=stdout_blob,
                        stderr_blob=stderr_blob,
                    )
                    raise WorkerExecutionIncomplete(
                        detail,
                        arm_path=arm_path,
                        debt_path=debt,
                    )

            # Re-sample every launch-authority byte after the child exits.  A
            # concurrent edit cannot silently turn a coherent arm into a receipt
            # for work performed against a moving plan/prompt/tool policy.
            _replay_bound_input_records(root, semantic_bindings["inputs"])
            if _callable_binding(parser_digest) != parser_binding:
                raise WorkerExecutionError("strict parser implementation changed during execution")
            if observer_configured:
                if _trusted_observer_callable_binding(
                    provisional_completion_probe,
                    label="provisional_completion_probe",
                    positional_parameters=1,
                ) != completion_observer_binding["probe"]:
                    raise WorkerExecutionError(
                        "provisional completion probe changed during execution"
                    )
                if _trusted_observer_callable_binding(
                    final_completion_replay,
                    label="final_completion_replay",
                    positional_parameters=2,
                ) != completion_observer_binding["final_replay"]:
                    raise WorkerExecutionError(
                        "final completion replay changed during execution"
                    )
                if _trusted_observer_callable_binding(
                    _prepare_claude_turn_observer,
                    label="completion_observer_prepare",
                    positional_parameters=1,
                ) != completion_observer_binding["prepare"]:
                    raise WorkerExecutionError(
                        "completion observer prepare function changed during execution"
                    )
            if (
                len(auxiliary_revocation_receipts)
                != len(auxiliary_roots)
                or any(os.path.lexists(path) for path in auxiliary_roots)
            ):
                raise WorkerExecutionError(
                    "auxiliary writable-root revocation is incomplete"
                )
            if _digest_bytes(executable.read_bytes()) != arm_payload["process_intent"][
                "executable_sha256"
            ]:
                raise WorkerExecutionError("executable bytes changed during execution")
            if (
                _replay_implementation_file_binding(implementation_binding)
                != implementation_binding
            ):
                raise WorkerExecutionError(
                    "provider implementation closure changed during execution"
                )
            if provider_stdout_binding is not None:
                completed_provider_binding = _claude_stream_stdout_binding(
                    normalized_provider_stdout_configuration,
                    argv=actual_argv,
                    stdout_limit_bytes=bound_stdout_limit,
                    cwd=cwd_path,
                    effective_model=bindings.effective_model,
                    bound_headless_profile_authority=(
                        provider_stdout_binding.get(
                            "command_contract",
                            {},
                        ).get("headless_profile")
                    ),
                )
                if completed_provider_binding != provider_stdout_binding:
                    raise WorkerExecutionError(
                        "provider stdout evidence binding changed during "
                        "execution"
                    )
            if normalized_claude_security_request is not None:
                try:
                    _recheck_claude_executable_before_launch(
                        normalized_claude_security_request[
                            "executable_observation"
                        ],
                        launch_executable=str(executable),
                    )
                except _ClaudeExecutableObservationError as exc:
                    raise WorkerExecutionError(
                        "Claude executable authority changed during execution: "
                        f"{exc}"
                    ) from exc

            # The legacy PTY observer proves transport lifecycle only.  Its
            # transcript is writable by the launched child, so even a stable
            # TURN_END plus an exact post-cleanup replay cannot authenticate a
            # model-semantic completion.  Keep all more-specific disposal
            # checks above this point: malformed/missing evidence, output
            # violations, timeout/overflow/non-zero exit, containment failure,
            # launch-authority drift, and final-replay rejection must retain
            # their precise debt reason.  Only after those checks succeed do we
            # dispose an otherwise coherent legacy PTY attempt as durable debt,
            # before any completion or canonical publication can be minted.
            if (
                observer_configured
                and completion_observer_binding["transport"][
                    "transport_semantic_authority"
                ]
                is False
            ):
                debt = _record_debt(
                    shard_dir,
                    arm_path=arm_path,
                    arm_sha256=arm_sha,
                    reason_code="UNTRUSTED_COMPLETION_TRANSPORT",
                    detail=(
                        "the armed PTY bridge has transport lifecycle authority "
                        "but no model-semantic completion authority"
                    ),
                    process_observation=process_observation,
                    stdout_blob=stdout_blob,
                    stderr_blob=stderr_blob,
                )
                raise WorkerExecutionIncomplete(
                    "PTY transport cannot mint model-semantic completion",
                    arm_path=arm_path,
                    debt_path=debt,
                )

            bounded_web_receipt_lifecycle = (
                _bounded_web_receipt_lifecycle_from_launch_request(
                    normalized_claude_security_request,
                    provider_stdout_binding,
                )
            )
            if bounded_web_receipt_lifecycle is not None:
                process_observation["bounded_web_receipt_lifecycle"] = (
                    bounded_web_receipt_lifecycle
                )

            completion_payload = {
                "schema_version": COMPLETION_SCHEMA,
                "arm_relative_path": arm_path.relative_to(shard_dir).as_posix(),
                "arm_sha256": arm_sha,
                "launcher_identity": LAUNCHER_IDENTITY,
                "launcher_invocation_id": launcher_invocation_id,
                "process_observation": process_observation,
                "stdout_blob": stdout_blob,
                "stderr_blob": stderr_blob,
                "provider_stdout_evidence": provider_stdout_evidence,
                "completion_evidence": completion_evidence_rows,
                "auxiliary_root_revocations": (
                    auxiliary_revocation_receipts
                ),
                "stream_mode": "SEPARATE_STDOUT_STDERR",
                "output_source_mode": bound_output_source,
                "stream_limits": stream_limits,
                "stream_observation": stream_observation,
                "transcript": {
                    "state": (
                        "PRESENT"
                        if any(row["is_transcript"] for row in observed_outputs)
                        else "NOT_APPLICABLE"
                    ),
                    "assignment_ids": [
                        row["assignment_id"]
                        for row in observed_outputs
                        if row["is_transcript"]
                    ],
                },
                "outputs": observed_outputs,
                "completed_at_unix_ns": time.time_ns(),
            }
            receipt_path, completion_sha = _persist_hashed_json(
                shard_dir, "completion", completion_payload
            )
            if not publish_canonical:
                return CompletedExecution(
                    receipt_path=receipt_path,
                    completion_sha256=completion_sha,
                    arm_path=arm_path,
                    arm_sha256=arm_sha,
                    publish_receipt_path=None,
                    publish_sha256=None,
                    published_paths=(),
                )
            try:
                publish_path, publish_sha, published_paths = _publish_completed_outputs(
                    root=root,
                    shard_dir=shard_dir,
                    completion_path=receipt_path,
                    completion_sha256=completion_sha,
                    output_rows=observed_outputs,
                )
            except BaseException as exc:
                debt = _record_debt(
                    shard_dir,
                    arm_path=arm_path,
                    arm_sha256=arm_sha,
                    reason_code="PUBLISH_FAILED",
                    detail=f"{type(exc).__name__}: {exc}",
                    process_observation=process_observation,
                    stdout_blob=stdout_blob,
                    stderr_blob=stderr_blob,
                )
                raise WorkerExecutionIncomplete(
                    f"canonical output publication failed: {exc}",
                    arm_path=arm_path,
                    debt_path=debt,
                ) from exc
            try:
                validate_completed_execution(
                    scratchpad=root,
                    receipt_path=receipt_path,
                    publish_receipt_path=publish_path,
                    parser_digest=parser_digest,
                    expected_completion_sha256=completion_sha,
                    expected_publish_sha256=publish_sha,
                )
            except BaseException as exc:
                debt = _record_debt(
                    shard_dir,
                    arm_path=arm_path,
                    arm_sha256=arm_sha,
                    reason_code="POST_PUBLISH_VALIDATION_FAILED",
                    detail=f"{type(exc).__name__}: {exc}",
                    process_observation=process_observation,
                    stdout_blob=stdout_blob,
                    stderr_blob=stderr_blob,
                )
                raise WorkerExecutionIncomplete(
                    f"post-publish replay failed: {exc}",
                    arm_path=arm_path,
                    debt_path=debt,
                ) from exc
            return CompletedExecution(
                receipt_path=receipt_path,
                completion_sha256=completion_sha,
                arm_path=arm_path,
                arm_sha256=arm_sha,
                publish_receipt_path=publish_path,
                publish_sha256=publish_sha,
                published_paths=published_paths,
            )
        except WorkerExecutionIncomplete:
            raise
        except _StagedOutputViolation as exc:
            debt = _record_debt(
                shard_dir,
                arm_path=arm_path,
                arm_sha256=arm_sha,
                reason_code=exc.reason_code,
                detail=str(exc),
                process_observation=process_observation,
                stdout_blob=stdout_blob,
                stderr_blob=stderr_blob,
            )
            raise WorkerExecutionIncomplete(
                f"staged worker output was rejected: {exc}",
                arm_path=arm_path,
                debt_path=debt,
            ) from exc
        except BaseException as exc:
            failure_reason = "OBSERVATION_FAILED"
            failure_detail = f"{type(exc).__name__}: {exc}"
            termination_failed = False
            if process is not None:
                try:
                    if process_tree is not None and process_tree.attached:
                        process_tree.terminate()
                        process_observation["process_tree_terminated"] = (
                            process_tree.terminated
                        )
                    elif (
                        process_tree is not None
                        and process_tree.process_creation_state
                        == "PROCESS_CREATED"
                    ):
                        process_tree.terminate_created_process(
                            timeout_seconds=5.0
                        )
                        process_observation["process_creation"] = (
                            process_tree.process_creation_evidence
                        )
                    elif process.poll() is None:
                        process.kill()
                except Exception as termination_exc:
                    termination_failed = True
                    failure_reason = "PROCESS_SCOPE_CLEANUP_FAILED"
                    failure_detail = (
                        f"{type(termination_exc).__name__}: {termination_exc}; "
                        f"preceding_error={type(exc).__name__}: {exc}"
                    )
                    if process_tree is not None:
                        try:
                            process_tree.emergency_close()
                            process_tree_close_attempted = True
                            process_observation[
                                "process_scope_emergency_close_succeeded"
                            ] = True
                            process_observation[
                                "process_scope_cleanup_succeeded"
                            ] = False
                            process_observation[
                                "process_population_zero_proven"
                            ] = False
                        except BaseException as emergency_exc:
                            process_observation[
                                "process_scope_emergency_close_succeeded"
                            ] = False
                            failure_detail += (
                                "; emergency_close_error="
                                f"{type(emergency_exc).__name__}: {emergency_exc}"
                            )
                    if process.poll() is None:
                        with contextlib.suppress(Exception):
                            process.kill()
                with contextlib.suppress(Exception):
                    process.wait(timeout=5)
            if process_tree is not None and not process_tree_close_attempted:
                process_tree_close_attempted = True
                try:
                    process_tree.close()
                    if not termination_failed:
                        process_observation["process_scope_cleanup_succeeded"] = True
                        process_observation[
                            "process_population_zero_proven"
                        ] = process_tree.population_zero_proven
                except BaseException as cleanup_exc:
                    process_observation["process_scope_cleanup_succeeded"] = False
                    emergency_detail = ""
                    try:
                        process_tree.emergency_close()
                        process_observation[
                            "process_scope_emergency_close_succeeded"
                        ] = True
                    except BaseException as emergency_exc:
                        process_observation[
                            "process_scope_emergency_close_succeeded"
                        ] = False
                        emergency_detail = (
                            "; emergency_close_error="
                            f"{type(emergency_exc).__name__}: {emergency_exc}"
                        )
                    failure_reason = "PROCESS_SCOPE_CLEANUP_FAILED"
                    failure_detail = (
                        f"{type(cleanup_exc).__name__}: {cleanup_exc}; "
                        f"preceding_error={type(exc).__name__}: {exc}"
                        f"{emergency_detail}"
                    )
            try:
                dispose_claude_runtime_after_failure(
                    "WORKER_OBSERVATION_FAILED"
                )
            except BaseException as runtime_cleanup_exc:
                failure_reason = "CLAUDE_RUNTIME_CLEANUP_FAILED"
                failure_detail = (
                    f"{type(runtime_cleanup_exc).__name__}: "
                    f"{runtime_cleanup_exc}; preceding_error="
                    f"{type(exc).__name__}: {exc}"
                )
            if (
                process_tree is not None
                and getattr(process_tree, "closed", False) is True
                and getattr(
                    process_tree,
                    "population_zero_proven",
                    False,
                )
                is True
                and len(auxiliary_revocation_receipts)
                != len(auxiliary_leases)
            ):
                try:
                    revoke_auxiliary_roots_after_scope_close()
                except BaseException as revocation_exc:
                    failure_reason = "AUXILIARY_ROOT_REVOCATION_FAILED"
                    failure_detail = (
                        f"{type(revocation_exc).__name__}: "
                        f"{revocation_exc}; preceding_error="
                        f"{type(exc).__name__}: {exc}"
                    )
            elif (
                process is None
                and len(auxiliary_revocation_receipts)
                != len(auxiliary_leases)
            ):
                try:
                    # Constructor/observer-preparation failures occur after the
                    # lease is armed but before Popen.  Revoke only leases whose
                    # exact process-scope lifecycle never began.
                    for index in range(
                        len(auxiliary_revocation_receipts),
                        len(auxiliary_leases),
                    ):
                        lease = auxiliary_leases[index]
                        if lease.process_scope_bound:
                            continue
                        binding = auxiliary_lease_bindings[index]
                        receipt = lease.abort_before_process_scope(
                            attempt_arm_sha256=binding[
                                "attempt_arm_sha256"
                            ],
                            process_scope_identity=binding[
                                "process_scope_identity"
                            ],
                            reason_code=(
                                "OBSERVATION_FAILED_BEFORE_SCOPE"
                            ),
                        )
                        append_auxiliary_revocation(index, receipt)
                    process_observation[
                        "auxiliary_root_revocations"
                    ] = auxiliary_revocation_receipts
                except BaseException as revocation_exc:
                    failure_reason = "AUXILIARY_ROOT_REVOCATION_FAILED"
                    failure_detail = (
                        f"{type(revocation_exc).__name__}: "
                        f"{revocation_exc}; preceding_error="
                        f"{type(exc).__name__}: {exc}"
                    )
            if streams is not None:
                try:
                    stdout, stderr = streams.finish(timeout=5)
                except Exception:
                    # The reader buffers are intrinsically ceiling-bound even if a
                    # platform pipe refuses to signal EOF during cleanup.
                    stdout = streams.stdout.raw
                    stderr = streams.stderr.raw
                process_observation.setdefault("stream_limits", stream_limits)
                process_observation.setdefault(
                    "stream_observation", streams.observation()
                )
            if stdout_blob is None:
                with contextlib.suppress(Exception):
                    stdout_blob = _persist_blob(blob_dir, "stdout", stdout)
            if stderr_blob is None:
                with contextlib.suppress(Exception):
                    stderr_blob = _persist_blob(blob_dir, "stderr", stderr)
            process_observation.setdefault("observed_exit_unix_ns", time.time_ns())
            process_observation.setdefault(
                "duration_monotonic_ns", time.monotonic_ns() - start_mono_ns
            )
            process_observation.setdefault(
                "returncode", process.returncode if process is not None else None
            )
            debt = _record_debt(
                shard_dir,
                arm_path=arm_path,
                arm_sha256=arm_sha,
                reason_code=failure_reason,
                detail=failure_detail,
                process_observation=process_observation,
                stdout_blob=stdout_blob,
                stderr_blob=stderr_blob,
            )
            raise WorkerExecutionIncomplete(
                (
                    "worker process scope cleanup failed"
                    if failure_reason == "PROCESS_SCOPE_CLEANUP_FAILED"
                    else f"worker observation failed: {exc}"
                ),
                arm_path=arm_path,
                debt_path=debt,
            ) from exc
        finally:
            if stdin_handle is not None:
                with contextlib.suppress(Exception):
                    stdin_handle.close()
            if process_tree is not None and not process_tree_close_attempted:
                # No completion can have been persisted while an owned scope
                # remains unclosed.  This path is limited to failures that
                # occurred before the provider's normal cleanup point.
                try:
                    process_tree.close()
                except BaseException:
                    process_tree.emergency_close()
            if windows_output_authority is not None and (
                process_tree is None
                or (
                    getattr(process_tree, "closed", False) is True
                    and getattr(
                        process_tree,
                        "population_zero_proven",
                        False,
                    )
                    is True
                )
            ):
                with contextlib.suppress(BaseException):
                    windows_output_authority.close_after_medium_restore()


def _semantic_executor_digest(value: Mapping[str, Any]) -> str:
    """Digest the executor control plane's newline-free canonical JSON."""

    try:
        raw = json.dumps(
            dict(value),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise WorkerExecutionError(
            "semantic executor authority is not canonical JSON"
        ) from exc
    return _digest_bytes(raw)


def _safe_executor_request_sha256(attempt: Any) -> str | None:
    """Read only a valid request digest from an untrusted executor handle."""

    if attempt is None:
        return None
    try:
        value = getattr(attempt, "request_sha256")
    except BaseException:
        return None
    try:
        return _require_sha(value, "executor request digest")
    except WorkerExecutionError:
        return None


def _persist_semantic_executor_record(
    directory: Path,
    *,
    prefix: str,
    digest_field: str,
    payload: Mapping[str, Any],
) -> tuple[Path, str]:
    unsigned = dict(payload)
    if digest_field in unsigned:
        raise WorkerExecutionError(
            "semantic executor record already contains its digest"
        )
    digest = _digest_json(unsigned)
    completed = {**unsigned, digest_field: digest}
    path = directory / f"{prefix}_{digest}.json"
    _atomic_immutable_bytes(path, _canonical_json(completed))
    return path, digest


def _semantic_executor_debt(
    *,
    directory: Path,
    outer_arm_path: Path,
    outer_arm_sha256: str,
    request_sha256: str | None,
    request_core_sha256: str,
    executor_receipt: Mapping[str, Any],
    reason_code: str,
) -> Path:
    receipt = _normalize_json(
        executor_receipt,
        label="semantic executor debt receipt",
    )
    if not isinstance(receipt, dict):
        raise WorkerExecutionError(
            "semantic executor debt receipt is malformed"
        )
    path, _digest = _persist_semantic_executor_record(
        directory,
        prefix="semantic_executor_debt",
        digest_field="semantic_executor_debt_sha256",
        payload={
            "schema_version": "plamen.semantic-wer-executor-debt.v1",
            "outer_arm_relative_path": outer_arm_path.name,
            "outer_arm_sha256": outer_arm_sha256,
            "executor_request_sha256": request_sha256,
            "request_core_sha256": request_core_sha256,
            "executor_receipt": receipt,
            "executor_receipt_sha256": receipt.get(
                "receipt_sha256"
            ),
            "reason_code": _require_id(reason_code, "reason_code"),
            "completion_authority": False,
            "observed_at_unix_ns": time.time_ns(),
        },
    )
    return path


def _replay_semantic_authorities(
    *,
    semantic_attempt_authority: Any,
    semantic_prompt_authority: Any,
) -> tuple[Any, Any]:
    from semantic_prompt_snapshot import SemanticPlanPromptBundle
    from semantic_work_plan import (
        SemanticAttemptBundle,
        SemanticExecutionBundle,
    )

    if not isinstance(
        semantic_attempt_authority,
        SemanticAttemptBundle,
    ):
        raise WorkerExecutionError(
            "semantic_attempt_authority must be SemanticAttemptBundle"
        )
    attempt = SemanticAttemptBundle(
        SemanticExecutionBundle(
            plan=semantic_attempt_authority.execution_bundle.plan,
            execution=(
                semantic_attempt_authority.execution_bundle.execution
            ),
        ),
        semantic_attempt_authority.attempt,
    )
    if not isinstance(
        semantic_prompt_authority,
        SemanticPlanPromptBundle,
    ):
        raise WorkerExecutionError(
            "semantic_prompt_authority must be SemanticPlanPromptBundle"
        )
    prompt = SemanticPlanPromptBundle(
        plan=semantic_prompt_authority.plan,
        snapshot=semantic_prompt_authority.snapshot,
    )
    if (
        attempt.execution_bundle.plan.semantic_digest
        != prompt.plan.semantic_digest
    ):
        raise WorkerExecutionError(
            "semantic attempt and prompt authorities differ"
        )
    return attempt, prompt


_SEMANTIC_RUNTIME_EXTERNAL_PREFIXES = (
    "attr",
    "attrs",
    "jsonschema",
    "jsonschema_specifications",
    "referencing",
    "rpds",
    "typing_extensions",
)
_SEMANTIC_RUNTIME_DISTRIBUTIONS = (
    "attrs",
    "jsonschema",
    "jsonschema-specifications",
    "referencing",
    "rpds-py",
    "typing-extensions",
)


def _validate_semantic_native_launch_budget(
    *,
    argv: Sequence[str],
    cwd: Path,
    scratchpad: Path,
    bound_paths: Sequence[Path],
) -> None:
    """Reject Windows launch values that CreateProcess cannot represent."""

    if os.name != "nt":
        return
    if isinstance(argv, (str, bytes)) or not argv:
        raise WorkerExecutionError("semantic native argv is invalid")
    arguments = list(argv)
    if any(
        not isinstance(item, str) or not item or "\x00" in item
        for item in arguments
    ):
        raise WorkerExecutionError("semantic native argv is invalid")
    rendered = subprocess.list2cmdline(arguments)
    command_units = len(rendered.encode("utf-16-le")) // 2 + 1
    if command_units > 32_767:
        raise WorkerExecutionError(
            "semantic native exceeds the Windows command-line budget"
        )
    # CreateProcess' current-directory and module-name fields retain the
    # MAX_PATH contract even when argument payloads use the 32K Unicode form.
    executable = Path(arguments[0])
    checked_paths = [cwd, scratchpad, *bound_paths]
    if executable.is_absolute():
        checked_paths.append(executable.resolve(strict=True))
    for path in checked_paths:
        rendered_path = str(path)
        if "\x00" in rendered_path:
            raise WorkerExecutionError(
                "semantic native Windows path contains NUL"
            )
        units = len(rendered_path.encode("utf-16-le")) // 2
        if units >= 260:
            raise WorkerExecutionError(
                "semantic native exceeds the Windows long-path budget"
            )


def _reject_pep660_editable_authority(
    direct_url_path: str | Path,
    *,
    distribution_name: str,
) -> None:
    """Fail with a stable capability reason for an editable import authority."""

    try:
        direct_url = json.loads(
            Path(direct_url_path).read_text(encoding="utf-8")
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise WorkerExecutionError(
            f"semantic runtime distribution {distribution_name!r} has "
            "malformed direct_url identity"
        ) from exc
    if (
        isinstance(direct_url, Mapping)
        and isinstance(direct_url.get("dir_info"), Mapping)
        and direct_url["dir_info"].get("editable") is True
    ):
        raise SemanticRuntimeDependencyUnsupported(
            f"semantic runtime distribution {distribution_name!r} uses an "
            "unsupported PEP-660 editable import authority"
        )


def _semantic_runtime_dependency_binding(
    *,
    _authorized_import_roots: Sequence[str | Path] | None = None,
) -> tuple[dict[str, Any], list[Path]]:
    """Bind the deterministic local/schema runtime before executor launch.

    Local dependency discovery is source-derived.  Walking live module
    attributes makes the denominator depend on unrelated instrumentation,
    pytest monkeypatches, and import order; those values do not exist in the
    fresh isolated child and therefore cannot form a replayable closure.
    """

    import ast
    import base64
    import csv
    from email import policy as email_policy
    from email.parser import BytesParser
    from importlib import metadata as importlib_metadata
    import io
    from pathlib import PurePosixPath
    import site

    module_root = Path(__file__).resolve(strict=True).parent
    seed_names = {
        "auxiliary_writable_root_lease",
        "isolated_execution_host",
        "owned_process_scope",
        "program_facts_types",
        "provider_command_authority",
        "semantic_prompt_snapshot",
        "semantic_work_plan",
        "worker_execution_receipts",
    }

    def canonical_distribution_name(value: str) -> str:
        canonical = re.sub(r"[-_.]+", "-", value).lower()
        if not canonical or canonical != value:
            raise WorkerExecutionError(
                "semantic runtime distribution name is non-canonical"
            )
        return canonical

    def metadata_identity(raw: bytes) -> tuple[str, str]:
        try:
            message = BytesParser(
                policy=email_policy.compat32
            ).parsebytes(raw)
        except (TypeError, ValueError) as exc:
            raise WorkerExecutionError(
                "semantic runtime distribution METADATA is malformed"
            ) from exc
        names = message.get_all("Name", [])
        versions = message.get_all("Version", [])
        if (
            len(names) != 1
            or len(versions) != 1
            or not isinstance(names[0], str)
            or not isinstance(versions[0], str)
            or not names[0]
            or not versions[0]
        ):
            raise WorkerExecutionError(
                "semantic runtime distribution METADATA identity is invalid"
            )
        return (
            re.sub(r"[-_.]+", "-", names[0]).lower(),
            versions[0],
        )

    def record_sha256(value: str) -> str | None:
        if not value:
            return None
        try:
            algorithm, encoded = value.split("=", 1)
            if (
                algorithm != "sha256"
                or not encoded
                or "=" in encoded
                or re.fullmatch(
                    r"[A-Za-z0-9_-]+",
                    encoded,
                    re.ASCII,
                )
                is None
            ):
                return None
            padding = "=" * (-len(encoded) % 4)
            raw = base64.b64decode(
                encoded + padding,
                altchars=b"-_",
                validate=True,
            )
        except Exception:
            return None
        if (
            len(raw) != hashlib.sha256().digest_size
            or base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
            != encoded
        ):
            return None
        return raw.hex()

    def record_entries(
        raw: bytes,
        *,
        root: Path,
        allow_nonimport_windows_launchers: bool = False,
    ) -> dict[str, tuple[str | None, int | None]]:
        try:
            rows = tuple(
                csv.reader(
                    io.StringIO(
                        raw.decode("utf-8", "strict"),
                        newline="",
                    )
                )
            )
        except (UnicodeError, csv.Error) as exc:
            raise WorkerExecutionError(
                "semantic runtime distribution RECORD is malformed"
            ) from exc
        entries: dict[str, tuple[str | None, int | None]] = {}
        case_keys: set[str] = set()
        for row in rows:
            if (
                allow_nonimport_windows_launchers
                and os.name == "nt"
                and len(row) == 3
                and re.fullmatch(
                    r"\.\./\.\./Scripts/[A-Za-z0-9._-]+\.exe",
                    row[0],
                    re.ASCII | re.IGNORECASE,
                )
            ):
                # This is wheel inventory outside the import root, never
                # executable/import authority.  The default parser remains
                # strict and rejects all parent segments.
                continue
            if (
                len(row) != 3
                or not row[0]
                or "\\" in row[0]
                or "\x00" in row[0]
            ):
                raise WorkerExecutionError(
                    "semantic runtime distribution RECORD row is invalid"
                )
            raw_segments = row[0].split("/")
            if (
                not raw_segments
                or any(
                    not segment
                    or segment in {".", ".."}
                    or ":" in segment
                    for segment in raw_segments
                )
            ):
                raise WorkerExecutionError(
                    "semantic runtime distribution RECORD path is "
                    "non-canonical"
                )
            relative = PurePosixPath(row[0])
            if (
                relative.is_absolute()
                or relative.as_posix() != row[0]
                or tuple(raw_segments) != relative.parts
            ):
                raise WorkerExecutionError(
                    "semantic runtime distribution RECORD path is invalid"
                )
            normalized = Path(
                os.path.abspath(root.joinpath(*relative.parts))
            )
            try:
                normalized.relative_to(root)
            except ValueError:
                continue
            path_text = str(normalized)
            case_key = os.path.normcase(path_text)
            if case_key in case_keys:
                raise WorkerExecutionError(
                    "semantic runtime distribution RECORD paths are ambiguous"
                )
            case_keys.add(case_key)
            digest = record_sha256(row[1])
            if row[1] and digest is None:
                raise WorkerExecutionError(
                    "semantic runtime distribution RECORD digest is invalid"
                )
            if row[2]:
                try:
                    size = int(row[2], 10)
                except ValueError as exc:
                    raise WorkerExecutionError(
                        "semantic runtime distribution RECORD size is invalid"
                    ) from exc
                if size < 0 or str(size) != row[2]:
                    raise WorkerExecutionError(
                        "semantic runtime distribution RECORD size is invalid"
                    )
            else:
                size = None
            entries[path_text] = (digest, size)
        return entries

    def independent_import_roots() -> set[str]:
        candidates: set[str] = set()
        for key in ("purelib", "platlib"):
            value = sysconfig.get_paths().get(key)
            if isinstance(value, str) and value:
                candidates.add(value)
        try:
            candidates.update(site.getsitepackages())
        except (AttributeError, OSError):
            pass
        try:
            value = site.getusersitepackages()
            if isinstance(value, str) and value:
                candidates.add(value)
        except (AttributeError, OSError):
            pass
        return {
            os.path.normcase(str(Path(item).resolve(strict=True)))
            for item in candidates
            if isinstance(item, str)
            and item
            and Path(item).is_absolute()
            and Path(item).is_dir()
        }

    def local_source(module_name: str) -> Path | None:
        parts = module_name.split(".")
        if not parts or any(
            not part or not part.isidentifier() for part in parts
        ):
            return None
        base = module_root.joinpath(*parts)
        candidates = (
            base.with_suffix(".py"),
            base / "__init__.py",
        )
        for candidate in candidates:
            if not candidate.is_file():
                continue
            resolved = candidate.resolve(strict=True)
            try:
                resolved.relative_to(module_root)
            except ValueError:
                continue
            return resolved
        return None

    def source_imports(
        *,
        module_name: str,
        source: Path,
    ) -> set[str]:
        try:
            tree = ast.parse(
                source.read_text(encoding="utf-8"),
                filename=str(source),
            )
        except (OSError, SyntaxError, UnicodeError) as exc:
            raise WorkerExecutionError(
                f"semantic runtime module {module_name!r} cannot be parsed"
            ) from exc
        discovered: set[str] = set()
        is_package = source.name == "__init__.py"
        package_name = (
            module_name
            if is_package
            else module_name.rpartition(".")[0]
        )
        for node in ast.walk(tree):
            candidates: list[str] = []
            if isinstance(node, ast.Import):
                candidates.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                if node.level:
                    package_parts = (
                        package_name.split(".") if package_name else []
                    )
                    trim = node.level - 1
                    if trim > len(package_parts):
                        continue
                    base_parts = (
                        package_parts[: len(package_parts) - trim]
                        if trim
                        else package_parts
                    )
                    if node.module:
                        base_parts.extend(node.module.split("."))
                    imported_base = ".".join(base_parts)
                else:
                    imported_base = node.module or ""
                if imported_base:
                    candidates.append(imported_base)
                for alias in node.names:
                    if alias.name == "*":
                        continue
                    candidates.append(
                        ".".join(
                            item
                            for item in (imported_base, alias.name)
                            if item
                        )
                    )
            for candidate in candidates:
                if candidate and local_source(candidate) is not None:
                    discovered.add(candidate)
        return discovered

    queue_names = list(sorted(seed_names))
    local_sources: dict[str, Path] = {}
    while queue_names:
        name = queue_names.pop()
        if name in local_sources:
            continue
        source = local_source(name)
        if source is None:
            if name not in seed_names:
                continue
            raise WorkerExecutionError(
                f"semantic runtime module {name!r} is not source-backed"
            )
        local_sources[name] = source
        queue_names.extend(
            sorted(
                source_imports(
                    module_name=name,
                    source=source,
                )
                - set(local_sources)
            )
        )

    external_names = {
        name
        for name in sys.modules
        if any(
            name == prefix or name.startswith(prefix + ".")
            for prefix in _SEMANTIC_RUNTIME_EXTERNAL_PREFIXES
        )
    }
    module_rows: list[dict[str, Any]] = []
    implementation_paths: set[Path] = {
        Path(sys.executable).resolve(strict=True)
    }
    for name in sorted(local_sources):
        source = local_sources[name]
        raw = source.read_bytes()
        module_rows.append(
            {
                "module_name": name,
                "kind": "PYTHON_SOURCE",
                "path": str(source),
                "sha256": _digest_bytes(raw),
                "size": len(raw),
                "search_locations": [],
            }
        )
        implementation_paths.add(source)

    for name in sorted(external_names - set(local_sources)):
        module = sys.modules.get(name)
        if module is None:
            raise WorkerExecutionError(
                f"semantic runtime module {name!r} disappeared"
            )
        source_text = getattr(module, "__file__", None)
        if source_text is None:
            locations = getattr(
                getattr(module, "__spec__", None),
                "submodule_search_locations",
                None,
            )
            search_locations = sorted(
                str(Path(item).resolve(strict=True))
                for item in (locations or ())
            )
            if not search_locations:
                raise WorkerExecutionError(
                    f"semantic runtime module {name!r} is unqualified"
                )
            module_rows.append(
                {
                    "module_name": name,
                    "kind": "NAMESPACE_PACKAGE",
                    "path": None,
                    "sha256": None,
                    "size": None,
                    "search_locations": search_locations,
                }
            )
            continue
        source = Path(source_text).resolve(strict=True)
        raw = source.read_bytes()
        suffix = source.suffix.casefold()
        kind = (
            "PYTHON_SOURCE"
            if suffix in {".py", ".pyw", ".pyc"}
            else "EXTENSION_BINARY"
        )
        module_rows.append(
            {
                "module_name": name,
                "kind": kind,
                "path": str(source),
                "sha256": _digest_bytes(raw),
                "size": len(raw),
                "search_locations": [],
            }
        )
        implementation_paths.add(source)

    module_rows.sort(key=lambda row: row["module_name"])
    distribution_rows: list[dict[str, Any]] = []
    import_roots: set[str] = set()
    if _authorized_import_roots is None:
        allowed_import_roots = independent_import_roots()
    else:
        authorized_roots = tuple(
            Path(item).resolve(strict=True)
            for item in _authorized_import_roots
        )
        if (
            authorized_roots != (module_root,)
            or not module_root.name.startswith(".semantic-runtime-cas-")
            or module_root.is_symlink()
            or not module_root.is_dir()
        ):
            raise WorkerExecutionError(
                "semantic runtime staged import-root authority is invalid"
            )
        allowed_import_roots = {
            os.path.normcase(str(module_root))
        }
    for name in _SEMANTIC_RUNTIME_DISTRIBUTIONS:
        canonical_name = canonical_distribution_name(name)
        try:
            distribution = importlib_metadata.distribution(name)
        except importlib_metadata.PackageNotFoundError as exc:
            raise WorkerExecutionError(
                f"semantic runtime distribution {name!r} is unavailable"
            ) from exc
        root = Path(distribution.locate_file("")).resolve(strict=True)
        if os.path.normcase(str(root)) not in allowed_import_roots:
            raise WorkerExecutionError(
                f"semantic runtime distribution {name!r} has an "
                "unrecognized interpreter import root"
            )
        import_roots.add(str(root))
        identity_files: list[dict[str, Any]] = []
        identity_by_role: dict[str, tuple[Path, bytes, dict[str, Any]]] = {}
        for relative in distribution.files or ():
            rendered = str(relative).replace("\\", "/")
            if not (
                rendered.endswith(".dist-info/METADATA")
                or rendered.endswith(".dist-info/RECORD")
            ):
                continue
            path = Path(distribution.locate_file(relative)).resolve(
                strict=True
            )
            raw = path.read_bytes()
            record = {
                "path": str(path),
                "sha256": _digest_bytes(raw),
                "size": len(raw),
            }
            identity_files.append(record)
            implementation_paths.add(path)
            role = path.name
            if (
                role in {"METADATA", "RECORD"}
                and path.parent.suffix.casefold() == ".dist-info"
            ):
                if role in identity_by_role:
                    raise WorkerExecutionError(
                        f"semantic runtime distribution {name!r} has "
                        f"duplicate {role}"
                    )
                identity_by_role[role] = (path, raw, record)
        if set(identity_by_role) != {"METADATA", "RECORD"}:
            raise WorkerExecutionError(
                f"semantic runtime distribution {name!r} lacks exact "
                "METADATA/RECORD identity files"
            )
        metadata_path, metadata_raw, metadata_record = identity_by_role[
            "METADATA"
        ]
        record_path, record_raw, _record_record = identity_by_role["RECORD"]
        if metadata_path.parent != record_path.parent:
            raise WorkerExecutionError(
                f"semantic runtime distribution {name!r} has split "
                "METADATA/RECORD provenance"
            )
        metadata_name, metadata_version = metadata_identity(metadata_raw)
        if (
            metadata_name != canonical_name
            or metadata_version != distribution.version
        ):
            raise WorkerExecutionError(
                f"semantic runtime distribution {name!r} metadata identity "
                "differs"
            )
        entries = record_entries(
            record_raw,
            root=root,
            allow_nonimport_windows_launchers=True,
        )
        if entries.get(str(metadata_path)) != (
            metadata_record["sha256"],
            metadata_record["size"],
        ):
            raise WorkerExecutionError(
                f"semantic runtime distribution {name!r} METADATA lacks "
                "exact RECORD ownership"
            )
        direct_url_path = next(
            (
                Path(path)
                for path in entries
                if Path(path).name.casefold() == "direct_url.json"
                and Path(path).parent == metadata_path.parent
            ),
            None,
        )
        if direct_url_path is not None:
            _reject_pep660_editable_authority(
                direct_url_path,
                distribution_name=name,
            )
        owned_prefixes = {
            prefix
            for prefix, owner in {
                "attr": "attrs",
                "attrs": "attrs",
                "jsonschema": "jsonschema",
                "jsonschema_specifications": (
                    "jsonschema-specifications"
                ),
                "referencing": "referencing",
                "rpds": "rpds-py",
                "typing_extensions": "typing-extensions",
            }.items()
            if owner == canonical_name
        }
        for path_text, (owned_sha, owned_size) in entries.items():
            path = Path(path_text)
            try:
                relative_parts = path.relative_to(root).parts
            except ValueError:
                continue
            first = relative_parts[0] if relative_parts else ""
            first_stem = Path(first).stem
            package_member = (
                first in owned_prefixes
                or first_stem in owned_prefixes
            )
            runtime_member = package_member and (
                path.suffix.casefold() not in {".pyi", ".pyc"}
                and path.name.casefold() != "py.typed"
            )
            identity_member = path in {
                metadata_path,
                record_path,
            }
            if not runtime_member and not identity_member:
                continue
            if owned_sha is None or owned_size is None:
                # RECORD itself and interpreter-generated bytecode have no
                # wheel digest.  RECORD is already bound as an identity file;
                # bytecode is deliberately excluded so source is authoritative.
                if (
                    path.name != "RECORD"
                    and runtime_member
                    and "__pycache__" not in path.parts
                    and path.suffix.casefold()
                    in {
                        ".py",
                        ".pyw",
                        ".pyc",
                        ".pyd",
                        ".so",
                        ".dylib",
                    }
                ):
                    raise WorkerExecutionError(
                        f"semantic runtime distribution {name!r} has "
                        "unhashed executable import bytes"
                    )
                continue
            try:
                resolved = path.resolve(strict=True)
                raw = resolved.read_bytes()
                info = resolved.stat()
            except OSError as exc:
                raise WorkerExecutionError(
                    f"semantic runtime distribution {name!r} RECORD "
                    "member is unavailable"
                ) from exc
            if (
                str(resolved) != path_text
                or not resolved.is_file()
                or resolved.is_symlink()
                or info.st_nlink != 1
                or len(raw) != owned_size
                or _digest_bytes(raw) != owned_sha
            ):
                raise WorkerExecutionError(
                    f"semantic runtime distribution {name!r} RECORD "
                    "member changed or is aliased"
                )
            implementation_paths.add(resolved)
        distribution_rows.append(
            {
                "distribution_name": canonical_name,
                "version": metadata_version,
                "import_root": str(root),
                "identity_files": sorted(
                    identity_files,
                    key=lambda row: os.path.normcase(row["path"]),
                ),
            }
        )

    executable = Path(sys.executable).resolve(strict=True)
    executable_raw = executable.read_bytes()
    unsigned = {
        "schema": "plamen.semantic-wer-runtime-dependencies.v1",
        "python": {
            "implementation": sys.implementation.name,
            "cache_tag": sys.implementation.cache_tag,
            "version": sys.version,
            "executable": str(executable),
            "executable_sha256": _digest_bytes(executable_raw),
            "executable_size": len(executable_raw),
        },
        "modules": module_rows,
        "distributions": sorted(
            distribution_rows,
            key=lambda row: row["distribution_name"],
        ),
        "import_roots": sorted(
            import_roots,
            key=os.path.normcase,
        ),
        "site_initialization": "DISABLED_EXPLICIT_IMPORT_ROOTS",
    }
    binding = {
        **unsigned,
        "runtime_dependency_sha256": _semantic_executor_digest(unsigned),
    }
    return binding, sorted(
        implementation_paths,
        key=lambda item: os.path.normcase(str(item)),
    )


def _replay_semantic_executor_completion(
    *,
    root: Path,
    isolated_completed: Any,
    publish_canonical: bool,
    parser_digest: ParserDigest,
    directory: Path,
    outer_arm_path: Path,
    outer_arm_sha256: str,
    executor_request_sha256: str,
    request_core_sha256: str,
    semantic_authority_sha256: str,
    implementation_files: Sequence[Mapping[str, Any]],
    runtime_dependency_sha256: str,
) -> CompletedExecution:
    implementation_records = [
        dict(item) for item in implementation_files
    ]
    implementation_files_sha256 = _semantic_executor_digest(
        {"implementation_files": implementation_records}
    )
    coordinator_receipt = dict(
        isolated_completed.coordinator_receipt
    )
    child = dict(isolated_completed.child_receipt)
    for label, receipt in (
        ("coordinator", coordinator_receipt),
        ("child", child),
    ):
        claimed_receipt_sha = _require_sha(
            receipt.get("receipt_sha256"),
            f"{label} executor receipt digest",
        )
        unsigned_receipt = {
            key: value
            for key, value in receipt.items()
            if key != "receipt_sha256"
        }
        if (
            _semantic_executor_digest(unsigned_receipt)
            != claimed_receipt_sha
        ):
            raise WorkerExecutionError(
                f"{label} executor receipt digest mismatch"
            )
    child_payload = child["payload"]
    coordinator_payload = coordinator_receipt["payload"]
    if (
        coordinator_receipt.get("completion_authority") is not True
        or coordinator_receipt.get("receipt_type")
        != "COORDINATOR_WER_COMPLETED"
        or coordinator_receipt.get("request_sha256")
        != executor_request_sha256
        or child.get("completion_authority") is not True
        or child.get("receipt_type") != "WER_COMPLETED"
        or child.get("request_sha256") != executor_request_sha256
        or coordinator_payload.get("child_receipt") != child
        or coordinator_payload.get("child_receipt_sha256")
        != child["receipt_sha256"]
        or coordinator_payload.get(
            "executor_population_zero_proven"
        )
        is not True
        or coordinator_payload.get("runtime_dependency_sha256")
        != _require_sha(
            runtime_dependency_sha256,
            "runtime dependency digest",
        )
        or child_payload.get("request_core_sha256")
        != request_core_sha256
        or child_payload.get("outer_arm_sha256")
        != outer_arm_sha256
        or child_payload.get("semantic_authority_sha256")
        != semantic_authority_sha256
        or child_payload.get("implementation_files_sha256")
        != implementation_files_sha256
        or child_payload.get("runtime_dependency_sha256")
        != _require_sha(
            runtime_dependency_sha256,
            "runtime dependency digest",
        )
    ):
        raise WorkerExecutionError(
            "semantic disposable executor completion is ambiguous"
        )
    completed = CompletedExecution(
        receipt_path=_safe_descendant(
            root,
            child_payload["inner_receipt_relative_path"],
            allow_missing=False,
        ),
        completion_sha256=child_payload[
            "inner_completion_sha256"
        ],
        arm_path=_safe_descendant(
            root,
            child_payload["inner_arm_relative_path"],
            allow_missing=False,
        ),
        arm_sha256=child_payload["inner_arm_sha256"],
        publish_receipt_path=(
            None
            if child_payload["publish_receipt_relative_path"] is None
            else _safe_descendant(
                root,
                child_payload["publish_receipt_relative_path"],
                allow_missing=False,
            )
        ),
        publish_sha256=child_payload["publish_sha256"],
        published_paths=tuple(
            _safe_descendant(root, item, allow_missing=False)
            for item in child_payload["published_paths"]
        ),
    )
    if publish_canonical:
        validated_completion = validate_completed_execution(
            scratchpad=root,
            receipt_path=completed.receipt_path,
            publish_receipt_path=completed.publish_receipt_path,
            parser_digest=parser_digest,
            expected_completion_sha256=completed.completion_sha256,
            expected_publish_sha256=completed.publish_sha256,
        )
    else:
        validated_completion = validate_staged_execution(
            scratchpad=root,
            receipt_path=completed.receipt_path,
            parser_digest=parser_digest,
            expected_completion_sha256=completed.completion_sha256,
        )
    inner_arm, replayed_inner_arm_sha256 = _load_hashed_json(
        completed.arm_path,
        prefix="arm",
        digest_field="arm_sha256",
        schema=ARM_SCHEMA,
    )
    if replayed_inner_arm_sha256 != completed.arm_sha256:
        raise WorkerExecutionError(
            "semantic executor inner arm digest changed"
        )
    inner_process_intent = inner_arm.get("process_intent")
    if not isinstance(inner_process_intent, Mapping):
        raise WorkerExecutionError(
            "semantic executor inner process intent is malformed"
        )
    nested_parent = _replay_nested_executor_binding(
        inner_process_intent.get("disposable_executor_parent")
    )
    if nested_parent != {
        "executor_request_sha256": executor_request_sha256,
        "request_core_sha256": request_core_sha256,
        "outer_arm_sha256": outer_arm_sha256,
        "executor_pid": coordinator_receipt["executor_pid"],
        "semantic_authority_sha256": semantic_authority_sha256,
        "ownership": (
            "OUTER_WER_EXECUTOR_OWNS_PROVIDER_DESCENDANTS"
        ),
    }:
        raise WorkerExecutionError(
            "semantic executor inner scope is not parent-bound"
        )
    if (
        inner_process_intent.get("implementation_files")
        != implementation_records
    ):
        raise WorkerExecutionError(
            "semantic executor inner implementation bytes differ"
        )
    process_observation = validated_completion.get(
        "process_observation"
    )
    if (
        not isinstance(process_observation, Mapping)
        or process_observation.get(
            "process_population_zero_proven"
        )
        is not True
        or child_payload.get("inner_process_population_zero_proven")
        is not True
        or child_payload.get("inner_process_scope_identity")
        != inner_process_intent.get("process_scope_identity")
        or child_payload.get("returncode")
        != process_observation.get("returncode")
        or child_payload.get("stdout_blob")
        != validated_completion.get("stdout_blob")
        or child_payload.get("stderr_blob")
        != validated_completion.get("stderr_blob")
        or child_payload.get("process_observation_sha256")
        != _semantic_executor_digest(
            {
                "process_observation": dict(process_observation),
            }
        )
    ):
        raise WorkerExecutionError(
            "semantic executor inner process evidence changed"
        )
    _persist_semantic_executor_record(
        directory,
        prefix="semantic_executor_completion",
        digest_field="semantic_executor_completion_sha256",
        payload={
            "schema_version": (
                "plamen.semantic-wer-executor-completion.v1"
            ),
            "outer_arm_relative_path": outer_arm_path.name,
            "outer_arm_sha256": outer_arm_sha256,
            "executor_request_sha256": executor_request_sha256,
            "request_core_sha256": request_core_sha256,
            "executor_receipt": coordinator_receipt,
            "executor_receipt_sha256": coordinator_receipt[
                "receipt_sha256"
            ],
            "child_receipt_sha256": child["receipt_sha256"],
            "runtime_dependency_sha256": runtime_dependency_sha256,
            "inner_arm_sha256": completed.arm_sha256,
            "inner_completion_sha256": (
                completed.completion_sha256
            ),
            "inner_publish_sha256": completed.publish_sha256,
            "completion_authority": True,
            "observed_at_unix_ns": time.time_ns(),
        },
    )
    return completed


def _run_observed_worker_semantic_isolated(
    *,
    semantic_attempt_authority: Any,
    semantic_prompt_authority: Any,
    scratchpad: str | Path,
    bindings: ExecutionBindings,
    argv: Sequence[str],
    cwd: str | Path,
    output_scope_relative: str,
    expected_outputs: Sequence[ExpectedOutput],
    parser_digest: ParserDigest,
    environment: Mapping[str, str] | None = None,
    environment_allowlist: Collection[str] | None = None,
    stdin_input: BoundInput | None = None,
    timeout_seconds: float = 300.0,
    lock_timeout_seconds: float = 10.0,
    output_source_mode: str = WORKER_FILE_OUTPUTS,
    stdout_limit_bytes: int = DEFAULT_STDOUT_LIMIT_BYTES,
    stderr_limit_bytes: int = DEFAULT_STDERR_LIMIT_BYTES,
    staged_output_limit_bytes: int = DEFAULT_STAGED_OUTPUT_LIMIT_BYTES,
    publish_canonical: bool = True,
    process_scope_identity: str | None = None,
    cancel_token: Any = None,
    auxiliary_writable_roots: Sequence[str | Path] = (),
    auxiliary_root_leases: Sequence[AuxiliaryWritableRootLease] = (),
    provisional_completion_probe: (
        Callable[[Mapping[str, Any]], Mapping[str, Any] | None] | None
    ) = None,
    final_completion_replay: (
        Callable[[Mapping[str, Any], Mapping[str, Any]], Mapping[str, Any]]
        | None
    ) = None,
    provisional_completion_signals: Collection[str] = (),
    implementation_files: Sequence[str | Path] = (),
    completion_observer_configuration: Mapping[str, Any] | None = None,
    provider_stdout_evidence_configuration: Mapping[str, Any] | None = None,
    startup_authority_binding: Mapping[str, Any] | None = None,
    claude_launch_security_request: Mapping[str, Any] | None = None,
    claude_runtime_materialization_request: (
        ClaudeRuntimeMaterializationRequest | None
    ) = None,
    observer_callback_timeout_seconds: float = (
        DEFAULT_OBSERVER_CALLBACK_TIMEOUT_SECONDS
    ),
    completion_evidence_files: Mapping[str, str | Path] | None = None,
    completion_evidence_limit_bytes: int = (
        DEFAULT_COMPLETION_EVIDENCE_LIMIT_BYTES
    ),
) -> CompletedExecution:
    # Import lazily: legacy execution must not acquire or initialize the
    # disposable-host path merely because this module was imported.
    import isolated_execution_host as isolated
    import jsonschema as jsonschema_module
    import program_facts_types as program_facts_module
    import semantic_prompt_snapshot as semantic_prompt_module
    import semantic_work_plan as semantic_plan_module

    attempt_bundle, prompt_bundle = _replay_semantic_authorities(
        semantic_attempt_authority=semantic_attempt_authority,
        semantic_prompt_authority=semantic_prompt_authority,
    )
    plan = attempt_bundle.execution_bundle.plan
    execution = attempt_bundle.execution_bundle.execution
    attempt = attempt_bundle.attempt
    if execution.backend != "native":
        raise WorkerExecutionError(
            "semantic disposable execution currently supports native only"
        )
    if not isinstance(bindings, ExecutionBindings):
        raise WorkerExecutionError(
            "bindings must be an ExecutionBindings instance"
        )
    if (
        bindings.run_id != plan.run_id
        or bindings.effective_backend != execution.backend
        or bindings.effective_model != execution.exact_model_id
        or bindings.worker.invocation_id != attempt.attempt_key
    ):
        raise WorkerExecutionError(
            "WER bindings do not match semantic attempt authority"
        )
    output_values = tuple(expected_outputs)
    if (
        len(output_values) != 1
        or output_values[0].assignment_id != plan.assignment_id
    ):
        raise WorkerExecutionError(
            "WER output denominator does not match semantic assignment"
        )
    if (
        stdin_input is None
        or stdin_input.relative_path != bindings.prompt.relative_path
    ):
        raise WorkerExecutionError(
            "semantic disposable execution requires exact prompt stdin"
        )
    if environment is None or environment_allowlist is None:
        raise WorkerExecutionError(
            "semantic disposable execution requires an explicit environment"
        )
    if any(
        (
            auxiliary_writable_roots,
            auxiliary_root_leases,
            provisional_completion_signals,
            completion_observer_configuration,
            provider_stdout_evidence_configuration,
            startup_authority_binding,
            claude_launch_security_request,
            claude_runtime_materialization_request,
            completion_evidence_files,
        )
    ) or any(
        value is not None
        for value in (
            provisional_completion_probe,
            final_completion_replay,
        )
    ):
        raise WorkerExecutionError(
            "semantic disposable execution does not yet authorize "
            "PTY, Claude, auxiliary-root, or observer capabilities"
        )
    # These parameters have no semantic authority in this slice.  Reject
    # non-default values instead of silently discarding caller choices.
    if (
        _positive_decimal_text(
            observer_callback_timeout_seconds,
            "observer_callback_timeout_seconds",
        )
        != _positive_decimal_text(
            DEFAULT_OBSERVER_CALLBACK_TIMEOUT_SECONDS,
            "default observer callback timeout",
        )
        or completion_evidence_limit_bytes
        != DEFAULT_COMPLETION_EVIDENCE_LIMIT_BYTES
    ):
        raise WorkerExecutionError(
            "semantic disposable execution received unsupported observer limits"
        )
    if process_scope_identity is None:
        raise WorkerExecutionError(
            "semantic disposable execution requires process_scope_identity"
        )
    environment_values = dict(environment)
    allowlist_values = sorted(
        {
            _require_text(item, "environment allowlist key")
            for item in environment_allowlist
        }
    )
    if environment_values or allowlist_values:
        raise WorkerExecutionError(
            "semantic native execution requires an empty environment; "
            "opaque environment materialization is not available in this slice"
        )

    root = _checked_root_directory(
        Path(scratchpad),
        label="scratchpad",
    )
    prompt_path = _safe_descendant(
        root,
        bindings.prompt.relative_path,
        allow_missing=False,
    )
    if _read_rooted_bytes(
        prompt_path
    ) != prompt_bundle.snapshot.prompt_bytes:
        raise WorkerExecutionError(
            "WER prompt bytes differ from semantic prompt snapshot"
        )
    bound_plan_path = _safe_descendant(
        root,
        bindings.plan.relative_path,
        allow_missing=False,
    )
    if _read_rooted_bytes(bound_plan_path) != plan.to_bytes():
        raise WorkerExecutionError(
            "WER bound plan bytes differ from semantic attempt authority"
        )
    manifest_raw = _read_bound_input(root, bindings.manifest)
    if _digest_bytes(manifest_raw) != plan.source_snapshot_digest:
        raise WorkerExecutionError(
            "WER source manifest differs from semantic source snapshot"
        )
    tool_policy_raw = _read_bound_input(root, bindings.tool_policy)
    if (
        _digest_bytes(tool_policy_raw)
        != plan.tool_capability_manifest_digest
    ):
        raise WorkerExecutionError(
            "WER tool policy differs from semantic capability manifest"
        )
    intent_raw = _read_bound_input(root, bindings.intent)
    intent_value = _strict_json(
        intent_raw,
        label="semantic launch intent",
    )
    expected_intent_links = {
        "semantic_profile": "semantic_v1",
        "semantic_work_unit_key": plan.semantic_work_unit_key,
        "execution_work_unit_key": execution.execution_work_unit_key,
        "attempt_key": attempt.attempt_key,
        "resource_grant_digest": plan.resource_grant_digest,
        "capability_receipt_digest": (
            execution.capability_receipt_digest
        ),
    }
    if any(
        intent_value.get(key) != expected
        for key, expected in expected_intent_links.items()
    ):
        raise WorkerExecutionError(
            "WER launch intent differs from semantic execution authority"
        )
    binding_record = bindings.as_dict(root)
    output_contract = _exact_output_contract(output_values)
    parser_binding = _callable_binding(
        parser_digest,
        label="parser_digest",
    )
    if set(environment_values) - set(allowlist_values):
        raise WorkerExecutionError(
            "semantic executor environment exceeds its allowlist"
        )
    cwd_path = Path(cwd).resolve(strict=True)
    if not cwd_path.is_dir():
        raise WorkerExecutionError("cwd must be an existing directory")
    bound_input_paths = tuple(
        _safe_descendant(
            root,
            row["relative_path"],
            allow_missing=False,
        )
        for row in binding_record["inputs"].values()
    )
    _validate_semantic_native_launch_budget(
        argv=argv,
        cwd=cwd_path,
        scratchpad=root,
        bound_paths=bound_input_paths,
    )
    (
        runtime_dependency_binding,
        runtime_implementation_paths,
    ) = _semantic_runtime_dependency_binding()
    implementation_paths = sorted(
        {
            str(Path(item).resolve(strict=True))
            for item in (
                *implementation_files,
                *runtime_implementation_paths,
                Path(__file__).resolve(strict=True),
                Path(isolated.__file__).resolve(strict=True),
                Path(semantic_plan_module.__file__).resolve(strict=True),
                Path(semantic_prompt_module.__file__).resolve(strict=True),
                Path(program_facts_module.__file__).resolve(strict=True),
                Path(jsonschema_module.__file__).resolve(strict=True),
                Path(parser_binding["source_file"]).resolve(strict=True),
            )
        },
        key=os.path.normcase,
    )
    implementation_values = [
        {
            "path": path,
            "sha256": _digest_bytes(Path(path).read_bytes()),
            "size": Path(path).stat().st_size,
        }
        for path in implementation_paths
    ]
    semantic_authority = {
        "plan": plan.to_dict(),
        "execution": execution.to_dict(),
        "attempt": attempt.to_dict(),
        "snapshot": prompt_bundle.snapshot.to_dict(),
    }
    semantic_authority["semantic_authority_sha256"] = (
        _semantic_executor_digest(
            {
                "schema": (
                    "plamen.isolated-wer-semantic-authority.v1"
                ),
                **semantic_authority,
            }
        )
    )
    payload_core = {
        "semantic_authority": semantic_authority,
        "scratchpad": str(root),
        "bindings": binding_record,
        "argv": [str(item) for item in argv],
        "cwd": str(cwd_path),
        "output_scope_relative": _require_relative_path(
            output_scope_relative,
            "output_scope_relative",
        ),
        "expected_outputs": output_contract,
        "parser_binding": parser_binding,
        "environment": environment_values,
        "environment_allowlist": allowlist_values,
        "stdin_input_relative_path": stdin_input.relative_path,
        "timeout_seconds": float(timeout_seconds),
        "lock_timeout_seconds": float(lock_timeout_seconds),
        "output_source_mode": _output_source_mode(output_source_mode),
        "stdout_limit_bytes": _byte_ceiling(
            stdout_limit_bytes,
            "stdout_limit_bytes",
        ),
        "stderr_limit_bytes": _byte_ceiling(
            stderr_limit_bytes,
            "stderr_limit_bytes",
        ),
        "staged_output_limit_bytes": _byte_ceiling(
            staged_output_limit_bytes,
            "staged_output_limit_bytes",
        ),
        "publish_canonical": publish_canonical,
        "process_scope_identity": _require_id(
            process_scope_identity,
            "process_scope_identity",
        ),
        "implementation_files": implementation_values,
        "runtime_dependency_binding": runtime_dependency_binding,
    }
    request_core_sha256 = isolated.wer_provider_request_core_sha256(
        payload_core
    )
    semantic_executor_directory_id = _digest_bytes(
        bindings.shard_id.encode("utf-8")
    )[:16]
    evidence_relative = (
        f"{_EVIDENCE_DIR}/semwer-"
        f"{semantic_executor_directory_id}"
    )
    directory = _make_safe_directory(root, evidence_relative)
    outer_arm_path, outer_arm_sha256 = (
        _persist_semantic_executor_record(
            directory,
            prefix="semantic_executor_arm",
            digest_field="outer_arm_sha256",
            payload={
                "schema_version": (
                    "plamen.semantic-wer-executor-arm.v1"
                ),
                "semantic_authority_sha256": semantic_authority[
                    "semantic_authority_sha256"
                ],
                "semantic_work_unit_key": plan.semantic_work_unit_key,
                "execution_work_unit_key": (
                    execution.execution_work_unit_key
                ),
                "attempt_key": attempt.attempt_key,
                "prompt_snapshot_digest": (
                    prompt_bundle.snapshot.snapshot_digest
                ),
                "prompt_sha256": prompt_bundle.snapshot.prompt_sha256,
                "binding_sha256": _digest_json(binding_record),
                "request_core_sha256": request_core_sha256,
                "implementation_files_sha256": (
                    _semantic_executor_digest(
                        {
                            "implementation_files": (
                                implementation_values
                            ),
                        }
                    )
                ),
                "implementation_files": implementation_values,
                "runtime_dependency_sha256": (
                    runtime_dependency_binding[
                        "runtime_dependency_sha256"
                    ]
                ),
                "process_scope_identity": process_scope_identity,
                "shard_id": bindings.shard_id,
                "completion_authority": False,
                "armed_at_unix_ns": time.time_ns(),
            },
        )
    )

    executor_attempt: Any = None
    executor_lifecycle: Any = None
    try:
        executor_lifecycle = isolated.isolated_wer_provider_lifecycle(
            payload_core,
            outer_arm_sha256=outer_arm_sha256,
        )
        with executor_lifecycle as executor_attempt:
                isolated_completed = executor_attempt.wait(
                    coordinator_timeout=(
                        float(timeout_seconds)
                        + isolated.DEFAULT_COORDINATOR_GRACE_SECONDS
                        + isolated.DEFAULT_RUNTIME_DEPENDENCY_STAGE_GRACE_SECONDS
                    ),
                cancel_token=cancel_token,
            )
    except isolated.IsolatedExecutionHostError as exc:
        try:
            receipt = isolated.sanitize_wer_failure_receipt(
                exc.receipt
            )
        except (
            isolated.IsolatedExecutionProtocolError,
            TypeError,
            ValueError,
        ):
            receipt = isolated.untrusted_wer_failure_receipt()
        receipt_payload = receipt.get("payload")
        reason = (
            str(receipt_payload.get("reason_code"))
            if isinstance(receipt_payload, Mapping)
            and receipt_payload.get("reason_code")
            else "EXECUTOR_RECEIPT_INVALID"
        )
        debt_path = _semantic_executor_debt(
            directory=directory,
            outer_arm_path=outer_arm_path,
            outer_arm_sha256=outer_arm_sha256,
            request_sha256=(
                _safe_executor_request_sha256(executor_attempt)
            ),
            request_core_sha256=request_core_sha256,
            executor_receipt=receipt,
            reason_code=reason,
        )
        raise WorkerExecutionIncomplete(
            "semantic disposable executor did not complete",
            arm_path=outer_arm_path,
            debt_path=debt_path,
        ) from exc
    except BaseException as exc:
        candidate_receipt = (
            None
            if executor_lifecycle is None
            else executor_lifecycle.terminal_receipt
        )
        try:
            receipt = isolated.sanitize_wer_failure_receipt(
                candidate_receipt
            )
        except (
            isolated.IsolatedExecutionProtocolError,
            TypeError,
            ValueError,
        ):
            receipt = isolated.untrusted_wer_failure_receipt(
                "EXECUTOR_BOUNDARY_INTERRUPTED"
                if not isinstance(exc, Exception)
                else "EXECUTOR_BOUNDARY_FAILED"
            )
        receipt_payload = receipt.get("payload")
        reason = (
            str(receipt_payload.get("reason_code"))
            if isinstance(receipt_payload, Mapping)
            and receipt_payload.get("reason_code")
            else (
                "EXECUTOR_BOUNDARY_INTERRUPTED"
                if not isinstance(exc, Exception)
                else "EXECUTOR_BOUNDARY_FAILED"
            )
        )
        debt_path = _semantic_executor_debt(
            directory=directory,
            outer_arm_path=outer_arm_path,
            outer_arm_sha256=outer_arm_sha256,
            request_sha256=(
                _safe_executor_request_sha256(executor_attempt)
            ),
            request_core_sha256=request_core_sha256,
            executor_receipt=receipt,
            reason_code=reason,
        )
        if not isinstance(exc, Exception):
            raise
        raise WorkerExecutionIncomplete(
            "semantic disposable executor boundary failed",
            arm_path=outer_arm_path,
            debt_path=debt_path,
        ) from exc

    try:
        return _replay_semantic_executor_completion(
            root=root,
            isolated_completed=isolated_completed,
            publish_canonical=publish_canonical,
            parser_digest=parser_digest,
            directory=directory,
            outer_arm_path=outer_arm_path,
            outer_arm_sha256=outer_arm_sha256,
            executor_request_sha256=(
                _safe_executor_request_sha256(executor_attempt)
            ),
            request_core_sha256=request_core_sha256,
            semantic_authority_sha256=semantic_authority[
                "semantic_authority_sha256"
            ],
            implementation_files=implementation_values,
            runtime_dependency_sha256=runtime_dependency_binding[
                "runtime_dependency_sha256"
            ],
        )
    except BaseException as exc:
        candidate_receipt = getattr(
            isolated_completed,
            "coordinator_receipt",
            {},
        )
        receipt = (
            dict(candidate_receipt)
            if isinstance(candidate_receipt, Mapping)
            else {}
        )
        debt_path = _semantic_executor_debt(
            directory=directory,
            outer_arm_path=outer_arm_path,
            outer_arm_sha256=outer_arm_sha256,
            request_sha256=(
                _safe_executor_request_sha256(executor_attempt)
            ),
            request_core_sha256=request_core_sha256,
            executor_receipt=receipt,
            reason_code="EXECUTOR_COMPLETION_REPLAY_FAILED",
        )
        if not isinstance(exc, Exception):
            raise
        raise WorkerExecutionIncomplete(
            "semantic disposable executor completion did not replay",
            arm_path=outer_arm_path,
            debt_path=debt_path,
        ) from exc


def _bound_semantic_v1_plan(
    *,
    scratchpad: str | Path,
    bindings: Any,
) -> Any | None:
    """Return a strictly replayed semantic plan that forbids direct launch."""

    if not isinstance(bindings, ExecutionBindings):
        return None
    root_input = Path(scratchpad)
    if (
        _rooted_is_symlink(root_input)
        or _is_reparse(root_input)
        or not _rooted_is_dir(root_input)
    ):
        return None
    try:
        root = _checked_root_directory(
            root_input,
            label="scratchpad",
        )
    except WorkerExecutionError:
        return None
    raw = _read_bound_input(root, bindings.plan)
    try:
        value = _strict_json(raw, label="bound execution plan")
    except WorkerExecutionError:
        return None
    if (
        value.get("schema") != "plamen.semantic-work-plan.v1"
        and value.get("semantic_profile") != "semantic_v1"
    ):
        return None
    from semantic_work_plan import (
        SemanticSchemaError,
        SemanticWorkPlan,
    )

    try:
        return SemanticWorkPlan.from_bytes(raw)
    except SemanticSchemaError as exc:
        raise WorkerExecutionError(
            "bound semantic_v1 plan failed strict replay"
        ) from exc


def run_observed_worker(
    *,
    scratchpad: str | Path,
    bindings: ExecutionBindings,
    argv: Sequence[str],
    cwd: str | Path,
    output_scope_relative: str,
    expected_outputs: Sequence[ExpectedOutput],
    parser_digest: ParserDigest,
    environment: Mapping[str, str] | None = None,
    environment_allowlist: Collection[str] | None = None,
    stdin_input: BoundInput | None = None,
    timeout_seconds: float = 300.0,
    lock_timeout_seconds: float = 10.0,
    output_source_mode: str = WORKER_FILE_OUTPUTS,
    stdout_limit_bytes: int = DEFAULT_STDOUT_LIMIT_BYTES,
    stderr_limit_bytes: int = DEFAULT_STDERR_LIMIT_BYTES,
    staged_output_limit_bytes: int = DEFAULT_STAGED_OUTPUT_LIMIT_BYTES,
    publish_canonical: bool = True,
    process_scope_identity: str | None = None,
    cancel_token: Any = None,
    auxiliary_writable_roots: Sequence[str | Path] = (),
    auxiliary_root_leases: Sequence[AuxiliaryWritableRootLease] = (),
    provisional_completion_probe: (
        Callable[[Mapping[str, Any]], Mapping[str, Any] | None] | None
    ) = None,
    final_completion_replay: (
        Callable[[Mapping[str, Any], Mapping[str, Any]], Mapping[str, Any]]
        | None
    ) = None,
    provisional_completion_signals: Collection[str] = (),
    implementation_files: Sequence[str | Path] = (),
    completion_observer_configuration: Mapping[str, Any] | None = None,
    provider_stdout_evidence_configuration: Mapping[str, Any] | None = None,
    startup_authority_binding: Mapping[str, Any] | None = None,
    claude_launch_security_request: Mapping[str, Any] | None = None,
    claude_runtime_materialization_request: (
        ClaudeRuntimeMaterializationRequest | None
    ) = None,
    observer_callback_timeout_seconds: float = (
        DEFAULT_OBSERVER_CALLBACK_TIMEOUT_SECONDS
    ),
    completion_evidence_files: Mapping[str, str | Path] | None = None,
    completion_evidence_limit_bytes: int = (
        DEFAULT_COMPLETION_EVIDENCE_LIMIT_BYTES
    ),
    semantic_attempt_authority: Any = None,
    semantic_prompt_authority: Any = None,
) -> CompletedExecution:
    """Dispatch typed semantic_v1 only; preserve the legacy direct contract."""

    paired = (
        semantic_attempt_authority is not None,
        semantic_prompt_authority is not None,
    )
    if paired[0] != paired[1]:
        raise WorkerExecutionError(
            "semantic attempt and prompt authorities must be paired"
        )
    bound_semantic_plan = _bound_semantic_v1_plan(
        scratchpad=scratchpad,
        bindings=bindings,
    )
    if bound_semantic_plan is not None and not paired[0]:
        raise WorkerExecutionError(
            "bound semantic_v1 plan requires typed attempt and prompt "
            "authorities; direct launch is forbidden"
        )
    call = {
        "scratchpad": scratchpad,
        "bindings": bindings,
        "argv": argv,
        "cwd": cwd,
        "output_scope_relative": output_scope_relative,
        "expected_outputs": expected_outputs,
        "parser_digest": parser_digest,
        "environment": environment,
        "environment_allowlist": environment_allowlist,
        "stdin_input": stdin_input,
        "timeout_seconds": timeout_seconds,
        "lock_timeout_seconds": lock_timeout_seconds,
        "output_source_mode": output_source_mode,
        "stdout_limit_bytes": stdout_limit_bytes,
        "stderr_limit_bytes": stderr_limit_bytes,
        "staged_output_limit_bytes": staged_output_limit_bytes,
        "publish_canonical": publish_canonical,
        "process_scope_identity": process_scope_identity,
        "cancel_token": cancel_token,
        "auxiliary_writable_roots": auxiliary_writable_roots,
        "auxiliary_root_leases": auxiliary_root_leases,
        "provisional_completion_probe": provisional_completion_probe,
        "final_completion_replay": final_completion_replay,
        "provisional_completion_signals": (
            provisional_completion_signals
        ),
        "implementation_files": implementation_files,
        "completion_observer_configuration": (
            completion_observer_configuration
        ),
        "provider_stdout_evidence_configuration": (
            provider_stdout_evidence_configuration
        ),
        "startup_authority_binding": startup_authority_binding,
        "claude_launch_security_request": (
            claude_launch_security_request
        ),
        "claude_runtime_materialization_request": (
            claude_runtime_materialization_request
        ),
        "observer_callback_timeout_seconds": (
            observer_callback_timeout_seconds
        ),
        "completion_evidence_files": completion_evidence_files,
        "completion_evidence_limit_bytes": (
            completion_evidence_limit_bytes
        ),
    }
    if not paired[0]:
        return _run_observed_worker_direct(**call)
    return _run_observed_worker_semantic_isolated(
        **call,
        semantic_attempt_authority=semantic_attempt_authority,
        semantic_prompt_authority=semantic_prompt_authority,
    )


def _load_hashed_json(
    path: Path,
    *,
    prefix: str,
    digest_field: str,
    schema: str,
) -> tuple[dict[str, Any], str]:
    if (
        _rooted_is_symlink(path)
        or _is_reparse(path)
        or not _rooted_is_file(path)
    ):
        raise WorkerExecutionError(f"{prefix} artifact is missing or unsafe")
    _assert_exact_existing_name(path)
    payload = _strict_json(
        _read_rooted_bytes(path),
        label=f"{prefix} artifact",
    )
    if payload.get("schema_version") != schema:
        raise WorkerExecutionError(f"{prefix} schema mismatch")
    claimed = _require_sha(payload.get(digest_field), digest_field)
    unsigned = {key: value for key, value in payload.items() if key != digest_field}
    if _digest_json(unsigned) != claimed:
        raise WorkerExecutionError(f"{prefix} digest mismatch")
    if path.name != f"{prefix}_{claimed}.json":
        raise WorkerExecutionError(f"{prefix} content-addressed filename mismatch")
    return payload, claimed


def _blob_record_binding(value: Any, label: str) -> dict[str, Any]:
    """Normalize one independently persisted content-addressed blob row."""

    if not isinstance(value, dict) or set(value) != {"relative_path", "sha256", "size"}:
        raise WorkerExecutionError(f"{label} blob record is malformed")
    size = _exact_nonnegative_int(value["size"], f"{label} blob size")
    relative = _require_relative_path(value["relative_path"], f"{label} blob path")
    digest = _require_sha(value["sha256"], f"{label} blob digest")
    return {
        "relative_path": relative,
        "sha256": digest,
        "size": size,
    }


def _replay_blob(shard_dir: Path, value: Any, label: str) -> bytes:
    record = _blob_record_binding(value, label)
    relative = record["relative_path"]
    path = _safe_descendant(shard_dir, relative, allow_missing=False)
    raw = _read_rooted_bytes(path)
    if len(raw) != record["size"] or _digest_bytes(raw) != record["sha256"]:
        raise WorkerExecutionError(f"{label} blob bytes do not replay")
    return raw


def _publication_destination_binding(
    value: Any,
    *,
    label: str,
    published: bool,
) -> dict[str, Any]:
    """Normalize one independent publish-arm or publish-receipt row."""

    fields = {
        "assignment_id",
        "publish_relative_path",
        "source_blob",
        "raw_sha256",
        "raw_size",
        "pre_state",
    }
    if published:
        fields.add("post_state")
    if not isinstance(value, Mapping) or set(value) != fields:
        raise WorkerExecutionError(f"{label} row is malformed")
    normalized = {
        "assignment_id": _require_id(
            value.get("assignment_id"), f"{label} assignment id"
        ),
        "publish_relative_path": _require_relative_path(
            value.get("publish_relative_path"), f"{label} path"
        ),
        "source_blob": _blob_record_binding(
            value.get("source_blob"), f"{label} source"
        ),
        "raw_sha256": _require_sha(
            value.get("raw_sha256"), f"{label} raw digest"
        ),
        "raw_size": _exact_nonnegative_int(
            value.get("raw_size"), f"{label} raw size"
        ),
        "pre_state": value.get("pre_state"),
    }
    if normalized["pre_state"] != "ABSENT":
        raise WorkerExecutionError(f"{label} pre-state is invalid")
    if published:
        normalized["post_state"] = value.get("post_state")
        if normalized["post_state"] != "PRESENT":
            raise WorkerExecutionError(f"{label} post-state is invalid")
    return normalized


def _completed_evidence_row_binding(value: Any, *, label: str) -> dict[str, Any]:
    """Normalize every scalar in one persisted completed-evidence row."""

    fields = {
        "evidence_id",
        "root_index",
        "relative_path",
        "limit_bytes",
        "pre_state",
        "post_state",
        "raw_sha256",
        "raw_size",
        "cas_blob",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        raise WorkerExecutionError(f"{label} row is malformed")
    normalized = {
        "evidence_id": _require_id(
            value.get("evidence_id"), f"{label} id"
        ),
        "root_index": _exact_nonnegative_int(
            value.get("root_index"), f"{label} root index"
        ),
        "relative_path": _require_relative_path(
            value.get("relative_path"), f"{label} path"
        ),
        "limit_bytes": _byte_ceiling(
            value.get("limit_bytes"), f"{label} limit"
        ),
        "pre_state": value.get("pre_state"),
        "post_state": value.get("post_state"),
        "raw_sha256": _require_sha(
            value.get("raw_sha256"), f"{label} raw digest"
        ),
        "raw_size": _exact_nonnegative_int(
            value.get("raw_size"), f"{label} raw size"
        ),
        "cas_blob": _blob_record_binding(
            value.get("cas_blob"), f"{label} CAS"
        ),
    }
    if (
        normalized["pre_state"] != "ABSENT"
        or normalized["post_state"] != "PRESENT"
    ):
        raise WorkerExecutionError(f"{label} state transition is invalid")
    return normalized


def _provisional_output_snapshot_binding(value: Any) -> list[dict[str, Any]]:
    """Normalize copied provisional output rows before digest/equality use."""

    if not isinstance(value, list):
        raise WorkerExecutionError(
            "provisional assigned-output snapshot is malformed"
        )
    rows: list[dict[str, Any]] = []
    fields = {"assignment_id", "relative_path", "raw_sha256", "raw_size"}
    for index, row in enumerate(value):
        if not isinstance(row, Mapping) or set(row) != fields:
            raise WorkerExecutionError(
                "provisional assigned-output snapshot row is malformed"
            )
        rows.append({
            "assignment_id": _require_id(
                row.get("assignment_id"),
                f"provisional output {index} assignment id",
            ),
            "relative_path": _require_relative_path(
                row.get("relative_path"),
                f"provisional output {index} path",
            ),
            "raw_sha256": _require_sha(
                row.get("raw_sha256"),
                f"provisional output {index} raw digest",
            ),
            "raw_size": _exact_nonnegative_int(
                row.get("raw_size"),
                f"provisional output {index} raw size",
            ),
        })
    return rows


def _replay_completed_evidence_rows(
    value: Any,
    *,
    armed: Sequence[Mapping[str, Any]],
    shard_dir: Path,
) -> tuple[list[dict[str, Any]], dict[str, bytes]]:
    if not isinstance(value, list) or len(value) != len(armed):
        raise WorkerExecutionError(
            "completion evidence denominator mismatch"
        )
    exact: dict[str, bytes] = {}
    rows: list[dict[str, Any]] = []
    for index, (contract, observed_raw) in enumerate(zip(armed, value)):
        observed = _completed_evidence_row_binding(
            observed_raw,
            label=f"completed evidence {index}",
        )
        for field in (
            "evidence_id",
            "root_index",
            "relative_path",
            "limit_bytes",
            "pre_state",
        ):
            if observed.get(field) != contract.get(field):
                raise WorkerExecutionError(
                    "completed evidence row conflicts with its arm"
                )
        raw = _replay_blob(
            shard_dir,
            observed.get("cas_blob"),
            f"completion evidence {observed.get('evidence_id')}",
        )
        raw_size = observed["raw_size"]
        if (
            raw_size != len(raw)
            or raw_size > contract.get("limit_bytes")
            or observed["raw_sha256"] != _digest_bytes(raw)
        ):
            raise WorkerExecutionError(
                "completion evidence bytes do not replay"
            )
        evidence_id = str(observed["evidence_id"])
        exact[evidence_id] = raw
        rows.append(observed)
    return rows, exact


def validate_completed_execution(
    *,
    scratchpad: str | Path,
    receipt_path: str | Path,
    publish_receipt_path: str | Path | None,
    parser_digest: ParserDigest,
    expected_completion_sha256: str,
    expected_publish_sha256: str | None,
    trusted_parser_closure: _TrustedCallableClosure | None = None,
) -> dict[str, Any]:
    """Replay a provider completion against every current persisted byte.

    Consumers should pass the opaque handle's ``completion_sha256`` as
    ``expected_completion_sha256`` so a different content-addressed receipt cannot
    be substituted.  The validator also replays the arm, provider code, executable,
    parser source, streams, complete output denominator, raw bytes, and parsed
    digests.  Any deletion, casing drift, symlink/reparse substitution, or byte
    change is rejected.
    """

    root_input = Path(scratchpad)
    if _rooted_is_symlink(root_input) or _is_reparse(root_input):
        raise WorkerExecutionError("scratchpad root cannot be a symlink/reparse point")
    root = _checked_root_directory(
        root_input,
        label="scratchpad",
    )
    evidence_root = _safe_descendant(root, _EVIDENCE_DIR, allow_missing=False)
    receipt_input = Path(os.path.abspath(os.fspath(receipt_path)))
    if (
        _rooted_is_symlink(receipt_input)
        or _is_reparse(receipt_input)
        or not _rooted_is_file(receipt_input)
    ):
        raise WorkerExecutionError("completion receipt cannot be a symlink/reparse point")
    try:
        relative_receipt = receipt_input.relative_to(evidence_root)
    except ValueError as exc:
        raise WorkerExecutionError("completion receipt is outside execution evidence") from exc
    if len(relative_receipt.parts) != 2:
        raise WorkerExecutionError("completion receipt has an invalid location")
    shard_id = _require_id(relative_receipt.parts[0], "shard_id")
    shard_dir = _safe_descendant(evidence_root, shard_id, allow_missing=False)
    receipt = _safe_descendant(
        evidence_root,
        relative_receipt.as_posix(),
        allow_missing=False,
    )
    completion, completion_sha = _load_hashed_json(
        receipt,
        prefix="completion",
        digest_field="completion_sha256",
        schema=COMPLETION_SCHEMA,
    )
    _exact_positive_int(
        completion.get("completed_at_unix_ns"),
        "completion timestamp",
    )
    if _require_sha(expected_completion_sha256, "expected_completion_sha256") != completion_sha:
        raise WorkerExecutionError("completion receipt does not match the expected authority")

    arm_relative = _require_relative_path(completion.get("arm_relative_path"), "arm_relative_path")
    if "/" in arm_relative:
        raise WorkerExecutionError("arm receipt must be a direct shard artifact")
    arm_path = _safe_descendant(shard_dir, arm_relative, allow_missing=False)
    arm, arm_sha = _load_hashed_json(
        arm_path, prefix="arm", digest_field="arm_sha256", schema=ARM_SCHEMA
    )
    _exact_positive_int(arm.get("armed_at_unix_ns"), "arm timestamp")
    if completion.get("arm_sha256") != arm_sha:
        raise WorkerExecutionError("completion does not bind the current arm")
    launcher = arm.get("launcher")
    if not isinstance(launcher, dict):
        raise WorkerExecutionError("arm launcher binding is malformed")
    if launcher.get("identity") != LAUNCHER_IDENTITY:
        raise WorkerExecutionError("launcher identity mismatch")
    if completion.get("launcher_identity") != LAUNCHER_IDENTITY:
        raise WorkerExecutionError("completion launcher identity mismatch")
    if completion.get("launcher_invocation_id") != launcher.get("invocation_id"):
        raise WorkerExecutionError("launcher invocation binding mismatch")
    own_path = Path(__file__).resolve(strict=True)
    if launcher.get("code_file") != str(own_path):
        raise WorkerExecutionError("launcher code path mismatch")
    if launcher.get("code_sha256") != _digest_bytes(own_path.read_bytes()):
        raise WorkerExecutionError("launcher code bytes changed")

    bindings = arm.get("bindings")
    if not isinstance(bindings, dict) or bindings.get("shard_id") != shard_id:
        raise WorkerExecutionError("arm semantic bindings are malformed")
    input_records = bindings.get("inputs")
    replayed_inputs = _replay_bound_input_records(root, input_records)
    intent_value = _parse_json_bytes(replayed_inputs["intent"], label="launch intent")
    if bindings.get("expected_environment_allowlist_sha256") != _intent_allowlist_digest(
        intent_value
    ):
        raise WorkerExecutionError("launch intent environment authority changed")
    if bindings.get("effective_backend") != intent_value.get("effective_backend"):
        raise WorkerExecutionError("effective backend no longer matches launch intent")
    if bindings.get("effective_model") != intent_value.get("effective_model"):
        raise WorkerExecutionError("effective model no longer matches launch intent")
    worker = bindings.get("worker")
    assessors = bindings.get("assessors")
    if not isinstance(worker, dict) or set(worker) != {"identity", "invocation_id"}:
        raise WorkerExecutionError("worker invocation binding is malformed")
    if not isinstance(assessors, list):
        raise WorkerExecutionError("assessor invocation denominator is malformed")
    principals = [worker, *assessors]
    if any(
        not isinstance(item, dict) or set(item) != {"identity", "invocation_id"}
        for item in principals
    ):
        raise WorkerExecutionError("principal invocation binding is malformed")
    identities = [str(item["identity"]).casefold() for item in principals]
    invocations = [str(item["invocation_id"]).casefold() for item in principals]
    assessor_identities = {str(item["identity"]).casefold() for item in assessors}
    principal_pairs = {
        (str(item["identity"]).casefold(), str(item["invocation_id"]).casefold())
        for item in principals
    }
    if (
        LAUNCHER_IDENTITY.casefold() in identities
        or str(worker["identity"]).casefold() in assessor_identities
        or len(set(invocations)) != len(invocations)
        or len(principal_pairs) != len(principals)
    ):
        raise WorkerExecutionError("execution principal identities are not independent")

    process_intent = arm.get("process_intent")
    if not isinstance(process_intent, dict):
        raise WorkerExecutionError("process intent is malformed")
    nested_executor_parent = process_intent.get(
        "disposable_executor_parent"
    )
    if nested_executor_parent is not None:
        _replay_nested_executor_binding(nested_executor_parent)
    bound_timeout = process_intent.get("timeout_seconds")
    if (
        not isinstance(bound_timeout, str)
        or _positive_decimal_text(
            bound_timeout, "process timeout binding"
        ) != bound_timeout
    ):
        raise WorkerExecutionError("process timeout binding is malformed")
    _replay_stdin_contract(
        root,
        process_intent.get("stdin"),
        replayed_inputs,
        input_records,
    )
    argv = process_intent.get("argv")
    runtime_materialization = process_intent.get(
        "claude_runtime_materialization"
    )
    expected_argv_sha256 = (
        _argv_authority_sha256(argv)
        if isinstance(runtime_materialization, Mapping)
        else _digest_json(argv)
    )
    if process_intent.get("argv_sha256") != expected_argv_sha256:
        raise WorkerExecutionError("argv bytes do not replay")
    if process_intent.get("stream_mode") != "SEPARATE_STDOUT_STDERR":
        raise WorkerExecutionError("process stream mode mismatch")
    armed_stream_limits = _stream_limit_binding(process_intent.get("stream_limits"))
    cwd = Path(str(process_intent.get("cwd", ""))).resolve(strict=True)
    if not cwd.is_dir():
        raise WorkerExecutionError("bound cwd is no longer a directory")
    provider_stdout_evidence_binding = process_intent.get(
        "provider_stdout_evidence"
    )
    _reconcile_work_plan_provider_stdout_policy(
        replayed_inputs["plan"],
        provider_stdout_evidence_binding,
    )
    claude_security_request = process_intent.get(
        "claude_launch_security_request"
    )
    _reconcile_work_plan_claude_security_policy(
        replayed_inputs["plan"],
        claude_security_request,
    )
    startup_authority_evidence = process_intent.get(
        "startup_authority_evidence"
    )
    startup_binding = (
        None
        if startup_authority_evidence is None
        else (
            startup_authority_evidence.get("binding")
            if isinstance(startup_authority_evidence, Mapping)
            else None
        )
    )
    startup_plan_recognized = _reconcile_work_plan_startup_policy(
        replayed_inputs["plan"],
        startup_binding,
    )
    if startup_plan_recognized:
        if intent_value.get("auxiliary_writable_root_startup") != (
            startup_binding
        ):
            raise WorkerExecutionError(
                "launch intent startup permit differs from provider arm"
            )
    if startup_authority_evidence is not None:
        try:
            historical_startup = replay_startup_permit_evidence(
                scratchpad=root,
                expected_run_id=str(bindings.get("run_id") or ""),
                evidence=startup_authority_evidence,
            )
        except (AuxiliaryWritableRootStartupError, OSError) as exc:
            raise WorkerExecutionError(
                "provider startup authority evidence does not replay"
            ) from exc
        if historical_startup.get("binding") != startup_binding:
            raise WorkerExecutionError(
                "provider startup authority evidence changed"
            )
    if provider_stdout_evidence_binding is not None:
        if (
            not isinstance(provider_stdout_evidence_binding, Mapping)
            or bindings.get("effective_backend") != "claude"
        ):
            raise WorkerExecutionError(
                "provider stdout evidence binding is malformed"
            )
        provider_configuration = {
            key: provider_stdout_evidence_binding.get(key)
            for key in (
                "schema",
                "expected_session_id",
                "expected_init_contract",
                "max_line_bytes",
                "max_stream_bytes",
            )
        }
        replayed_provider_binding = _claude_stream_stdout_binding(
            provider_configuration,
            argv=argv,
            stdout_limit_bytes=armed_stream_limits["stdout_bytes"],
            cwd=cwd,
            effective_model=str(bindings.get("effective_model") or ""),
            bound_headless_profile_authority=(
                provider_stdout_evidence_binding.get(
                    "command_contract",
                    {},
                ).get("headless_profile")
            ),
        )
        if dict(provider_stdout_evidence_binding) != replayed_provider_binding:
            raise WorkerExecutionError(
                "provider stdout evidence binding changed"
            )
    if claude_security_request is not None:
        try:
            replayed_claude_security = (
                _replay_claude_launch_security_request(
                    claude_security_request
                )
            )
            _recheck_claude_executable_before_launch(
                replayed_claude_security["executable_observation"],
                launch_executable=str(
                    process_intent.get("resolved_executable") or ""
                ),
            )
        except (
            _ClaudeLaunchSecurityError,
            _ClaudeExecutableObservationError,
        ) as exc:
            raise WorkerExecutionError(
                f"Claude launch-security request does not replay: {exc}"
            ) from exc
        if (
            provider_stdout_evidence_binding is None
            or replayed_claude_security["policy"]["headless_profile"][
                "expected_init_contract"
            ]
            != provider_stdout_evidence_binding["expected_init_contract"]
        ):
            raise WorkerExecutionError(
                "Claude launch-security and stream evidence policies differ"
            )
    persisted_transaction_authority = process_intent.get(
        "transaction_write_authority"
    )
    persisted_restricted_boundary = process_intent.get(
        "restricted_stage_boundary"
    )
    if persisted_transaction_authority == _RESTRICTED_CLAUDE_STAGE_AUTHORITY:
        if not isinstance(persisted_restricted_boundary, Mapping):
            raise WorkerExecutionError(
                "restricted Claude process intent lacks its stage boundary"
            )
        current_process_capability = _restricted_claude_process_capability(
            persisted_restricted_boundary
        )
        _active_write_confinement_binding(
            _RESTRICTED_CLAUDE_STAGE_AUTHORITY,
            persisted_restricted_boundary,
            capability=current_process_capability,
            process_scope_identity=str(
                process_intent.get("process_scope_identity") or ""
            ),
            require_current_process=False,
        )
        transaction_write_authority = _RESTRICTED_CLAUDE_STAGE_AUTHORITY
    else:
        if persisted_restricted_boundary is not None:
            raise WorkerExecutionError(
                "non-restricted process intent carries a restricted stage boundary"
            )
        current_process_capability = process_tree_termination_capability()
        transaction_write_authority = _transaction_write_authority(
            current_process_capability
        )
    if process_intent.get(
        "process_tree_termination"
    ) != current_process_capability:
        raise WorkerExecutionError("process tree termination authority mismatch")
    if (
        transaction_write_authority is None
        or persisted_transaction_authority
        != transaction_write_authority
    ):
        raise WorkerExecutionError(
            "transaction write-confinement authority mismatch"
        )
    scope_identity = process_intent.get("process_scope_identity")
    if (
        not isinstance(scope_identity, str)
        or not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}",
            scope_identity,
        )
    ):
        raise WorkerExecutionError("process scope identity is malformed")
    completion_observer = process_intent.get("completion_observer")
    observer_fields = {
        "mode",
        "signals",
        "auxiliary_root_leases",
        "probe",
        "final_replay",
        "prepare",
        "transport",
        "configuration",
        "callback_timeout_seconds",
        "completion_evidence",
    }
    if not isinstance(completion_observer, dict) or set(
        completion_observer
    ) != observer_fields:
        raise WorkerExecutionError("completion observer binding is malformed")
    observer_mode = completion_observer.get("mode")
    observer_prepare_callback: Callable[..., Any] | None = None
    observer_probe_callback: Callable[..., Any] | None = None
    observer_final_callback: Callable[..., Any] | None = None
    if observer_mode not in {
        "PROCESS_EXIT_ZERO",
        "PROVISIONAL_SIGNAL_THEN_FINAL_REPLAY",
    }:
        raise WorkerExecutionError("completion observer mode is malformed")
    observer_signals = completion_observer.get("signals")
    if (
        not isinstance(observer_signals, list)
        or any(
            _require_id(item, "completion observer signal") != item
            for item in observer_signals
        )
        or observer_signals != sorted(observer_signals)
        or len({item.casefold() for item in observer_signals})
        != len(observer_signals)
        or set(observer_signals)
        - _ALLOWED_PROVISIONAL_COMPLETION_SIGNALS
    ):
        raise WorkerExecutionError("completion observer signals are malformed")
    observer_configuration = _normalize_json(
        completion_observer.get("configuration"),
        label="completion observer configuration",
    )
    if not isinstance(observer_configuration, dict):
        raise WorkerExecutionError(
            "completion observer configuration is malformed"
        )
    callback_timeout_text = completion_observer.get(
        "callback_timeout_seconds"
    )
    if (
        not isinstance(callback_timeout_text, str)
        or _positive_decimal_text(
            callback_timeout_text,
            "completion observer callback timeout",
        )
        != callback_timeout_text
    ):
        raise WorkerExecutionError(
            "completion observer callback timeout is malformed"
        )
    auxiliary_lease_bindings = _replay_auxiliary_lease_binding_shape(
        completion_observer.get("auxiliary_root_leases"),
    )
    observer_evidence_binding = _replay_completion_evidence_binding(
        completion_observer.get("completion_evidence"),
        auxiliary_root_count=len(auxiliary_lease_bindings),
    )
    if observer_mode == "PROCESS_EXIT_ZERO":
        if (
            observer_signals
            or completion_observer.get("probe") is not None
            or completion_observer.get("final_replay") is not None
            or completion_observer.get("prepare") is not None
            or completion_observer.get("transport") is not None
            or observer_configuration
            or observer_evidence_binding
        ):
            raise WorkerExecutionError(
                "process-exit completion observer has provisional authority"
            )
    else:
        if observer_signals != ["TURN_END"]:
            raise WorkerExecutionError(
                "provisional completion observer signal denominator is unsupported"
            )
        if not observer_evidence_binding:
            raise WorkerExecutionError(
                "provisional completion observer retains no exact evidence"
            )
        observer_configuration = _claude_observer_configuration_binding(
            observer_configuration,
            evidence_binding=observer_evidence_binding,
        )
        replayed_transport, _transport_data_files = (
            _claude_pty_bridge_binding(
                process_intent.get("argv"),
                auxiliary_roots=tuple(
                    Path(str(row["root"]))
                    for row in auxiliary_lease_bindings
                ),
                observer_configuration=observer_configuration,
            )
        )
        if completion_observer.get("transport") != replayed_transport:
            raise WorkerExecutionError(
                "Claude PTY bridge binding changed"
            )
        observer_prepare_callback = _resolve_bound_observer_callable(
            completion_observer.get("prepare"),
            label="completion observer prepare",
            positional_parameters=1,
        )
        observer_probe_callback = _resolve_bound_observer_callable(
            completion_observer.get("probe"),
            label="provisional completion probe",
            positional_parameters=1,
        )
        observer_final_callback = _resolve_bound_observer_callable(
            completion_observer.get("final_replay"),
            label="final completion replay",
            positional_parameters=2,
        )
        if (
            observer_prepare_callback is not _prepare_claude_turn_observer
            or observer_probe_callback is not _probe_claude_turn_observer
            or observer_final_callback is not _replay_claude_turn_observer
        ):
            raise WorkerExecutionError(
                "completion observer is not the reviewed Claude JSONL package"
            )
    replayed_implementation_files = _replay_implementation_file_binding(
        process_intent.get("implementation_files")
    )
    if observer_mode == "PROVISIONAL_SIGNAL_THEN_FINAL_REPLAY":
        required_path_values = list(
            {
                os.path.normcase(str(Path(item).resolve(strict=True))): Path(
                    item
                ).resolve(strict=True)
                for item in (
                    *_pty_observer_implementation_files(),
                    *_pty_bridge_implementation_files(),
                    *_transport_data_files,
                )
            }.values()
        )
        required_observer_files = _implementation_file_binding(
            required_path_values
        )
        if any(
            required not in replayed_implementation_files
            for required in required_observer_files
        ):
            raise WorkerExecutionError(
                "completion observer implementation closure is incomplete"
            )
    if provider_stdout_evidence_binding is not None:
        required_stream_files = _implementation_file_binding(
            _claude_stream_implementation_files()
        )
        if any(
            required not in replayed_implementation_files
            for required in required_stream_files
        ):
            raise WorkerExecutionError(
                "provider stdout parser implementation closure is incomplete"
            )
    auxiliary_revocations = _replay_auxiliary_revocation_denominator(
        completion.get("auxiliary_root_revocations"),
        bindings=auxiliary_lease_bindings,
    )
    executable = Path(str(process_intent.get("resolved_executable", ""))).resolve(strict=True)
    if _digest_bytes(executable.read_bytes()) != process_intent.get("executable_sha256"):
        raise WorkerExecutionError("executable bytes changed")
    process_observation = completion.get("process_observation")
    if not isinstance(process_observation, dict):
        raise WorkerExecutionError("process observation is malformed")
    bounded_web_receipt_lifecycle = (
        _bounded_web_receipt_lifecycle_from_launch_request(
            claude_security_request
            if isinstance(claude_security_request, Mapping)
            else None,
            provider_stdout_evidence_binding
            if isinstance(provider_stdout_evidence_binding, Mapping)
            else None,
        )
    )
    if bounded_web_receipt_lifecycle is None:
        if "bounded_web_receipt_lifecycle" in process_observation:
            raise WorkerExecutionError(
                "non-web completion contains bounded-web receipt authority"
            )
    elif process_observation.get("bounded_web_receipt_lifecycle") != (
        bounded_web_receipt_lifecycle
    ):
        raise WorkerExecutionError(
            "bounded-web receipt lifecycle changed after completion"
        )
    if process_observation.get(
        "process_tree_strategy"
    ) != current_process_capability:
        raise WorkerExecutionError("completion process tree strategy mismatch")
    if process_observation.get("process_tree_terminated") is not True:
        raise WorkerExecutionError(
            "completion lacks provider-owned descendant termination"
        )
    if process_observation.get("process_population_zero_proven") is not True:
        raise WorkerExecutionError(
            "completion lacks provider-observed zero process population"
        )
    if process_observation.get("process_scope_cleanup_succeeded") is not True:
        raise WorkerExecutionError("completion lacks successful process-scope cleanup")
    if transaction_write_authority == _RESTRICTED_CLAUDE_STAGE_AUTHORITY:
        restricted_os_write = (
            isinstance(persisted_restricted_boundary, Mapping)
            and persisted_restricted_boundary.get("os_write_confinement")
            != "NOT_PROVIDED"
        )
        if (
            process_observation.get("write_confinement_proven")
            is not restricted_os_write
            or process_observation.get("transaction_stage_boundary_proven")
            is not True
        ):
            raise WorkerExecutionError(
                "completion overclaims or lacks the restricted Claude stage boundary"
            )
    elif (
        process_observation.get("write_confinement_proven") is not True
        or process_observation.get("transaction_stage_boundary_proven")
        is not False
    ):
        raise WorkerExecutionError(
            "completion lacks provider-observed write confinement"
        )
    if (
        process_observation.get("transaction_write_authority")
        != transaction_write_authority
    ):
        raise WorkerExecutionError(
            "completion write-confinement authority mismatch"
        )
    persisted_write_binding = _active_write_confinement_binding(
        transaction_write_authority,
        process_observation.get("write_confinement_binding"),
        capability=current_process_capability,
        process_scope_identity=scope_identity,
        require_current_process=False,
    )
    if (
        process_observation.get("write_confinement_binding")
        != persisted_write_binding
    ):
        raise WorkerExecutionError(
            "completion write-confinement binding is not canonical"
        )
    if (
        transaction_write_authority == _RESTRICTED_CLAUDE_STAGE_AUTHORITY
        and persisted_write_binding != persisted_restricted_boundary
    ):
        raise WorkerExecutionError(
            "completion restricted stage boundary differs from its arm"
        )
    process_stream_limits = _stream_limit_binding(
        process_observation.get("stream_limits")
    )
    if process_stream_limits != armed_stream_limits:
        raise WorkerExecutionError("process observation stream limits mismatch")
    if auxiliary_revocations:
        if (
            process_observation.get("auxiliary_root_revocations")
            != auxiliary_revocations
        ):
            raise WorkerExecutionError(
                "process observation auxiliary-root revocations mismatch"
            )
    elif "auxiliary_root_revocations" in process_observation:
        if process_observation["auxiliary_root_revocations"] != []:
            raise WorkerExecutionError(
                "process observation has foreign auxiliary-root revocations"
            )
    if process_observation.get("completion_observer_mode") != observer_mode:
        raise WorkerExecutionError("completion observer mode observation mismatch")
    observed_provider_stdout_evidence = process_observation.get(
        "provider_stdout_evidence"
    )
    completed_provider_stdout_evidence = completion.get(
        "provider_stdout_evidence"
    )
    if provider_stdout_evidence_binding is None:
        if (
            observed_provider_stdout_evidence is not None
            or completed_provider_stdout_evidence is not None
        ):
            raise WorkerExecutionError(
                "completion contains unarmed provider stdout evidence"
            )
    elif (
        not isinstance(observed_provider_stdout_evidence, Mapping)
        or dict(observed_provider_stdout_evidence)
        != completed_provider_stdout_evidence
    ):
        raise WorkerExecutionError(
            "provider stdout evidence observation is malformed"
        )
    completion_signal = process_observation.get("completion_signal")
    if observer_mode == "PROCESS_EXIT_ZERO":
        if (
            completion_signal != "PROCESS_EXIT_ZERO"
            or process_observation.get("root_exit_origin") != "NATURAL"
            or "provisional_observation" in process_observation
            or "final_completion_replay" in process_observation
            or "provisional_output_snapshot" in process_observation
            or "provisional_output_snapshot_sha256" in process_observation
        ):
            raise WorkerExecutionError(
                "process-exit completion observation is malformed"
            )
    else:
        provisional = process_observation.get("provisional_observation")
        final_replay = process_observation.get("final_completion_replay")
        root_exit_origin = process_observation.get("root_exit_origin")
        if (
            completion_signal not in observer_signals
            or root_exit_origin
            not in {
                "PROVIDER_TERMINATED",
                "NATURAL_SIGNAL_OBSERVED_POSTEXIT",
            }
            or not isinstance(provisional, dict)
            or provisional.get("signal") != completion_signal
            or not isinstance(final_replay, dict)
            or set(final_replay) != {"accepted", "signal", "replay_digest"}
            or final_replay.get("accepted") is not True
            or final_replay.get("signal") != completion_signal
        ):
            raise WorkerExecutionError(
                "provisional completion observation is malformed"
            )
        _require_sha(
            final_replay.get("replay_digest"),
            "final completion replay digest",
        )
        persisted_provisional_output_snapshot = process_observation.get(
            "provisional_output_snapshot"
        )
        if process_observation.get(
            "provisional_output_snapshot_sha256"
        ) != _digest_json(persisted_provisional_output_snapshot):
            raise WorkerExecutionError(
                "provisional assigned-output snapshot is malformed"
            )
        provisional_output_snapshot = _provisional_output_snapshot_binding(
            persisted_provisional_output_snapshot
        )

    environment = arm.get("environment")
    if not isinstance(environment, dict):
        raise WorkerExecutionError("environment binding is malformed")
    allowlist_names = environment.get("allowlist_names")
    if not isinstance(allowlist_names, list) or environment.get(
        "allowlist_sha256"
    ) != environment_allowlist_sha256(allowlist_names):
        raise WorkerExecutionError("environment allowlist digest mismatch")
    if environment.get("allowlist_sha256") != bindings.get(
        "expected_environment_allowlist_sha256"
    ):
        raise WorkerExecutionError("environment allowlist does not match launch intent")
    if environment.get("values_persisted") is not False:
        raise WorkerExecutionError("environment privacy marker mismatch")
    value_digest_persisted = environment.get(
        "value_digest_persisted"
    )
    value_authority = environment.get("value_authority")
    effective_sha256 = environment.get("effective_sha256")
    if value_digest_persisted is True:
        _require_sha(
            effective_sha256,
            "environment effective-value digest",
        )
        if value_authority != "DURABLE_EFFECTIVE_VALUE_SHA256":
            raise WorkerExecutionError(
                "environment value authority is malformed"
            )
    elif value_digest_persisted is False:
        if (
            effective_sha256 is not None
            or value_authority
            != "CLAUDE_CHILD_ENVIRONMENT_IN_MEMORY_REPLAY"
        ):
            raise WorkerExecutionError(
                "redacted environment value authority is malformed"
            )
    else:
        raise WorkerExecutionError(
            "environment value-digest persistence marker is malformed"
        )
    effective_environment_names = environment.get("effective_names")
    if (
        not isinstance(effective_environment_names, list)
        or any(
            not isinstance(name, str) or not name
            for name in effective_environment_names
        )
        or effective_environment_names
        != sorted(set(effective_environment_names))
        or any(
            name not in allowlist_names
            for name in effective_environment_names
        )
    ):
        raise WorkerExecutionError(
            "environment effective-name denominator is malformed"
        )

    runtime_redacted_receipts = process_intent.get(
        "claude_runtime_redacted_receipts"
    )
    runtime_base_argv = process_intent.get(
        "claude_runtime_base_argv"
    )
    if bindings.get("effective_backend") == "claude":
        if (
            not isinstance(runtime_materialization, Mapping)
            or not isinstance(runtime_redacted_receipts, Mapping)
            or not isinstance(runtime_base_argv, list)
        ):
            raise WorkerExecutionError(
                "Claude runtime persisted authority is incomplete"
            )
        try:
            replayed_runtime = (
                replay_claude_runtime_materialization_receipt(
                    runtime_materialization
                )
            )
            runtime_persisted_replay = (
                reconcile_claude_runtime_persisted_authority(
                    replayed_runtime,
                    runtime_redacted_receipts,
                    base_argv=runtime_base_argv,
                    final_argv=argv,
                    environment_names=effective_environment_names,
                )
            )
        except (
            ClaudeRuntimeMaterializationError,
            TypeError,
            ValueError,
        ) as exc:
            raise WorkerExecutionError(
                f"Claude runtime persisted authority does not replay: {exc}"
            ) from exc
        if runtime_persisted_replay.get("valid") is not True:
            raise WorkerExecutionError(
                "Claude runtime persisted authority is invalid"
            )
        if (
            replayed_runtime.get("process_scope_identity")
            != scope_identity
            or replayed_runtime.get("work_plan_sha256")
            != _digest_bytes(replayed_inputs["plan"])
            or replayed_runtime.get("startup_permit_sha256")
            != _claude_runtime_mapping_sha256(startup_binding)
            or not isinstance(claude_security_request, Mapping)
            or replayed_runtime.get(
                "launch_security_request_sha256"
            )
            != claude_security_request.get("request_sha256")
        ):
            raise WorkerExecutionError(
                "Claude runtime outer authority cross-link changed"
            )
        if (
            process_observation.get(
                "claude_runtime_materialization"
            )
            != dict(runtime_materialization)
            or process_observation.get(
                "claude_runtime_redacted_receipts"
            )
            != dict(runtime_redacted_receipts)
        ):
            raise WorkerExecutionError(
                "Claude runtime completion denominator differs from its arm"
            )
        runtime_postprocess = process_observation.get(
            "claude_runtime_postprocess"
        )
        runtime_lifecycle = process_observation.get(
            "claude_runtime_lifecycle"
        )
        try:
            replayed_postprocess = (
                replay_claude_runtime_postprocess_receipt(
                    runtime_postprocess
                )
            )
            replayed_lifecycle = (
                replay_claude_runtime_lifecycle_receipt(
                    runtime_lifecycle
                )
            )
        except (
            ClaudeRuntimeMaterializationError,
            TypeError,
        ) as exc:
            raise WorkerExecutionError(
                f"Claude runtime completion lifecycle does not replay: {exc}"
            ) from exc
        runtime_sha256 = replayed_runtime["receipt_sha256"]
        if (
            replayed_postprocess.get(
                "runtime_materialization_sha256"
            )
            != runtime_sha256
            or replayed_postprocess.get("process_scope_identity")
            != scope_identity
            or replayed_postprocess.get("process_closed") is not True
            or replayed_postprocess.get("process_zero_proven")
            is not True
            or replayed_postprocess.get("process_attached") is not True
            or replayed_lifecycle.get(
                "runtime_materialization_sha256"
            )
            != runtime_sha256
            or replayed_lifecycle.get("process_scope_identity")
            != scope_identity
            or replayed_lifecycle.get("closure_mode")
            != "NORMAL_COMPLETION"
            or replayed_lifecycle.get("profile_first_cleanup")
            is not True
            or replayed_lifecycle.get("completion_authority")
            is not True
            or replayed_lifecycle.get("emergency_zero_population")
            is not False
        ):
            raise WorkerExecutionError(
                "Claude runtime completion lifecycle lacks normal authority"
            )
        creation_evidence = process_observation.get(
            "process_creation"
        )
        if (
            not isinstance(creation_evidence, Mapping)
            or set(creation_evidence)
            != {
                "state",
                "creation_attempted",
                "process_object_returned",
                "attached",
                "created_process_termination_proven",
            }
            or creation_evidence.get("state") != "ATTACHED"
            or creation_evidence.get("creation_attempted") is not True
            or creation_evidence.get("process_object_returned") is not True
            or creation_evidence.get("attached") is not True
            or creation_evidence.get(
                "created_process_termination_proven"
            )
            is not False
        ):
            raise WorkerExecutionError(
                "Claude runtime process-creation evidence is malformed"
            )
    elif (
        runtime_materialization is not None
        or runtime_redacted_receipts is not None
        or runtime_base_argv is not None
        or "claude_runtime_materialization" in process_observation
        or "claude_runtime_redacted_receipts" in process_observation
        or "claude_runtime_postprocess" in process_observation
        or "claude_runtime_lifecycle" in process_observation
    ):
        raise WorkerExecutionError(
            "non-Claude execution contains Claude runtime authority"
        )

    output_contract = arm.get("output_contract")
    if not isinstance(output_contract, dict):
        raise WorkerExecutionError("output contract is malformed")
    if output_contract.get("preexisting_files") != []:
        raise WorkerExecutionError("output pre-state was not ABSENT")
    publication_authority = output_contract.get("publication_authority")
    if publication_authority not in {"LEGACY_PROVIDER", "PHASE_IO_ONLY"}:
        raise WorkerExecutionError("output publication authority is malformed")
    armed_source_mode = _output_source_mode(output_contract.get("source_mode"))
    parser_binding = _callable_binding(parser_digest)
    if output_contract.get("parser") != parser_binding:
        raise WorkerExecutionError("strict parser implementation changed")
    scope_rel = _require_relative_path(output_contract.get("scope_relative"), "output scope")
    scope = _safe_descendant(root, scope_rel, allow_missing=False)
    expected = output_contract.get("expected_outputs")
    outputs = completion.get("outputs")
    if not isinstance(expected, list) or not isinstance(outputs, list):
        raise WorkerExecutionError("output denominator is malformed")
    if transaction_write_authority == _RESTRICTED_CLAUDE_STAGE_AUTHORITY:
        boundary = process_intent.get("restricted_stage_boundary")
        policy = replayed_claude_security.get("policy")
        profile = policy.get("headless_profile") if isinstance(policy, Mapping) else None
        init_contract = (
            profile.get("expected_init_contract")
            if isinstance(profile, Mapping)
            else None
        )
        settings_authority = (
            policy.get("settings_authority")
            if isinstance(policy, Mapping)
            else None
        )
        stdout_restricted = armed_source_mode == STDOUT_ASSIGNED_OUTPUT
        if not isinstance(init_contract, Mapping):
            raise WorkerExecutionError(
                "restricted Claude stage init contract is malformed"
            )
        restricted_lane = _restricted_claude_capability_lane(init_contract)
        bounded_web = restricted_lane == "BOUNDED_WEB"
        expected_permission_mode = "default"
        expected_forbidden_tools = (
            _RESTRICTED_CLAUDE_WEB_FORBIDDEN_TOOLS
            if bounded_web
            else _RESTRICTED_CLAUDE_FORBIDDEN_TOOLS
        )
        expected_rules = (
            []
            if stdout_restricted
            else sorted(
                {
                    "Glob",
                    "Grep",
                    "Read",
                    *_claude_phase_tool_policy.exact_edit_permission_rules(
                        scope / str(row["relative_path"])
                        for row in expected
                        if isinstance(row, Mapping)
                        and isinstance(row.get("relative_path"), str)
                    ),
                }
            )
        )
        expected_tools = (
            []
            if stdout_restricted
            else _RESTRICTED_CLAUDE_WEB_TOOLS
            if bounded_web
            else _RESTRICTED_CLAUDE_TOOLS
        )
        if (
            not isinstance(boundary, Mapping)
            or not isinstance(settings_authority, Mapping)
            or boundary.get("output_scope") != str(scope)
            or boundary.get("permission_rules") != expected_rules
            or (
                boundary.get("output_source_mode")
                != STDOUT_ASSIGNED_OUTPUT
                if stdout_restricted
                else "output_source_mode" in boundary
            )
            or (stdout_restricted and len(expected) != 1)
            or (not stdout_restricted and not expected)
            or boundary.get("settings_sha256")
            != settings_authority.get("settings_sha256")
            or init_contract.get("claude_code_version") != "2.1.252"
            or restricted_lane is None
            or init_contract.get("permission_mode") != expected_permission_mode
            or init_contract.get("allowed_tools") != expected_tools
            or not expected_forbidden_tools.issubset(
                set(init_contract.get("forbidden_tools") or ())
            )
        ):
            raise WorkerExecutionError(
                "restricted Claude stage boundary does not replay against its exact output contract"
            )
    expected_names = [row.get("relative_path") for row in expected if isinstance(row, dict)]
    if len(expected_names) != len(expected) or _scope_file_names(scope) != expected_names:
        raise WorkerExecutionError("current output denominator does not match the arm")
    if len(outputs) != len(expected):
        raise WorkerExecutionError("completion output denominator mismatch")
    for contract_row, observed in zip(expected, outputs):
        if not isinstance(contract_row, dict) or not isinstance(observed, dict):
            raise WorkerExecutionError("output row is malformed")
        for field in ("assignment_id", "relative_path", "is_transcript"):
            if observed.get(field) != contract_row.get(field):
                raise WorkerExecutionError("completion output assignment mismatch")
        if observed.get("source_mode") != armed_source_mode:
            raise WorkerExecutionError("completion output source mode mismatch")
        if observed.get("publish_relative_path") != contract_row.get("publish_relative_path"):
            raise WorkerExecutionError("completion canonical destination mismatch")
        path = _safe_descendant(
            root, f"{scope_rel}/{contract_row['relative_path']}", allow_missing=False
        )
        raw = _read_rooted_bytes(path)
        raw_size = _exact_nonnegative_int(
            observed.get("raw_size"),
            f"worker output {observed.get('assignment_id')} raw size",
        )
        if raw_size != len(raw) or observed.get("raw_sha256") != _digest_bytes(raw):
            raise WorkerExecutionError("worker output raw bytes changed")
        parsed = _invoke_parser_with_registered_guard(
            parser_digest,
            (path, raw),
            label="strict parser replay",
            trusted_closure=trusted_parser_closure,
        )
        _require_sha(parsed, "parser digest")
        if observed.get("parsed_sha256") != parsed:
            raise WorkerExecutionError("worker output parsed bytes changed")
        cas_raw = _replay_blob(shard_dir, observed.get("cas_blob"), "output CAS")
        if len(cas_raw) != raw_size or _digest_bytes(cas_raw) != observed.get(
            "raw_sha256"
        ):
            raise WorkerExecutionError("output CAS does not bind the staged raw bytes")
    if observer_mode != "PROCESS_EXIT_ZERO":
        replayed_output_snapshot = [
            {
                "assignment_id": row.get("assignment_id"),
                "relative_path": row.get("relative_path"),
                "raw_sha256": row.get("raw_sha256"),
                "raw_size": row.get("raw_size"),
            }
            for row in outputs
            if isinstance(row, dict)
        ]
        if replayed_output_snapshot != provisional_output_snapshot:
            raise WorkerExecutionError(
                "completion outputs differ from the provisional snapshot"
            )

    transcript_expected = output_contract.get("transcript_expectation")
    expected_transcript_ids = [
        row["assignment_id"] for row in expected if row.get("is_transcript") is True
    ]
    expected_transcript_state = "PRESENT" if expected_transcript_ids else "NOT_APPLICABLE"
    if transcript_expected != expected_transcript_state:
        raise WorkerExecutionError("arm transcript expectation mismatch")
    transcript = completion.get("transcript")
    if transcript != {
        "state": expected_transcript_state,
        "assignment_ids": expected_transcript_ids,
    }:
        raise WorkerExecutionError("completion transcript state mismatch")
    if completion.get("stream_mode") != "SEPARATE_STDOUT_STDERR":
        raise WorkerExecutionError("completion stream mode mismatch")
    if completion.get("output_source_mode") != armed_source_mode:
        raise WorkerExecutionError("completion output source mode mismatch")
    completion_stream_limits = _stream_limit_binding(
        completion.get("stream_limits")
    )
    if completion_stream_limits != armed_stream_limits:
        raise WorkerExecutionError("completion stream limits mismatch")
    completion_stream_observation = _stream_observation_binding(
        completion.get("stream_observation"),
        limits=armed_stream_limits,
        completion=True,
    )
    process_stream_observation = _stream_observation_binding(
        process_observation.get("stream_observation"),
        limits=armed_stream_limits,
        completion=True,
    )
    if process_stream_observation != completion_stream_observation:
        raise WorkerExecutionError("process stream observation mismatch")

    observation = completion.get("process_observation")
    if not isinstance(observation, dict):
        raise WorkerExecutionError("process observation is malformed")
    if type(observation.get("pid")) is not int or observation["pid"] <= 0:
        raise WorkerExecutionError("observed PID is invalid")
    creation = observation.get("creation_identity")
    if not isinstance(creation, dict) or set(creation) != {"kind", "value"}:
        raise WorkerExecutionError("PID creation identity is malformed")
    if observation.get("timed_out") is not False:
        raise WorkerExecutionError("completion records a timed-out process")
    observed_returncode = observation.get("returncode")
    if (
        isinstance(observed_returncode, bool)
        or not isinstance(observed_returncode, int)
        or (
            observer_mode == "PROCESS_EXIT_ZERO"
            and observed_returncode != 0
        )
        or (
            observer_mode == "PROVISIONAL_SIGNAL_THEN_FINAL_REPLAY"
            and process_observation.get("root_exit_origin")
            == "NATURAL_SIGNAL_OBSERVED_POSTEXIT"
            and observed_returncode != 0
        )
    ):
        raise WorkerExecutionError(
            "completion does not record an authorized process exit"
        )
    if type(observation.get("observed_start_unix_ns")) is not int:
        raise WorkerExecutionError("process start observation is missing")
    if type(observation.get("launch_requested_unix_ns")) is not int:
        raise WorkerExecutionError("process launch request observation is missing")
    if type(observation.get("observed_exit_unix_ns")) is not int:
        raise WorkerExecutionError("process exit observation is missing")
    if observation["observed_exit_unix_ns"] < observation["observed_start_unix_ns"]:
        raise WorkerExecutionError("process observation time ordering is invalid")
    if observation["observed_start_unix_ns"] < observation["launch_requested_unix_ns"]:
        raise WorkerExecutionError("process launch/start time ordering is invalid")

    stdout_raw = _replay_blob(shard_dir, completion.get("stdout_blob"), "stdout")
    stderr_raw = _replay_blob(shard_dir, completion.get("stderr_blob"), "stderr")
    if len(stdout_raw) != completion_stream_observation["stdout_captured_size"]:
        raise WorkerExecutionError("stdout blob size does not match stream observation")
    if len(stderr_raw) != completion_stream_observation["stderr_captured_size"]:
        raise WorkerExecutionError("stderr blob size does not match stream observation")
    if provider_stdout_evidence_binding is not None:
        try:
            _replay_claude_stream_json(
                stdout_raw,
                completed_provider_stdout_evidence,
                expected_session_id=provider_stdout_evidence_binding[
                    "expected_session_id"
                ],
                expected_init_contract=provider_stdout_evidence_binding[
                    "expected_init_contract"
                ],
                max_line_bytes=provider_stdout_evidence_binding[
                    "max_line_bytes"
                ],
                max_stream_bytes=provider_stdout_evidence_binding[
                    "max_stream_bytes"
                ],
            )
        except _ClaudeStreamJsonEvidenceError as exc:
            raise WorkerExecutionError(
                f"provider stdout evidence replay failed: {exc}"
            ) from exc
    completed_evidence_rows, completed_evidence_exact = (
        _replay_completed_evidence_rows(
            completion.get("completion_evidence"),
            armed=observer_evidence_binding,
            shard_dir=shard_dir,
        )
    )
    if observer_mode == "PROVISIONAL_SIGNAL_THEN_FINAL_REPLAY":
        process_completed_evidence_rows, _process_completed_evidence_exact = (
            _replay_completed_evidence_rows(
                process_observation.get("completion_evidence"),
                armed=observer_evidence_binding,
                shard_dir=shard_dir,
            )
        )
        if (
            observer_final_callback is None
            or process_completed_evidence_rows != completed_evidence_rows
        ):
            raise WorkerExecutionError(
                "completion evidence observation mismatch"
            )
        provisional_observation = process_observation.get(
            "provisional_observation"
        )
        persisted_final_replay = process_observation.get(
            "final_completion_replay"
        )
        replay_digest = _completion_replay_digest(
            evidence_rows=completed_evidence_rows,
            stdout_blob=completion.get("stdout_blob"),
            stderr_blob=completion.get("stderr_blob"),
            provisional_observation=provisional_observation,
            observer_configuration=observer_configuration,
        )
        replayed_final = _invoke_bounded_callback(
            observer_final_callback,
            (
                provisional_observation,
                {
                    "stdout": stdout_raw,
                    "stderr": stderr_raw,
                    "observer_configuration": observer_configuration,
                    "completion_evidence": completed_evidence_exact,
                    "evidence_replay_digest": replay_digest,
                    "process_population_zero_proven": True,
                    "process_scope_cleanup_succeeded": True,
                },
            ),
            timeout_seconds=float(callback_timeout_text),
            label="final_completion_validation_replay",
        )
        normalized_final = _normalize_json(
            replayed_final,
            label="validated final completion replay",
        )
        if (
            normalized_final != persisted_final_replay
            or not isinstance(normalized_final, dict)
            or normalized_final.get("accepted") is not True
            or normalized_final.get("signal") != completion_signal
            or normalized_final.get("replay_digest") != replay_digest
        ):
            raise WorkerExecutionError(
                "final completion replay does not reproduce from CAS evidence"
            )
    elif completed_evidence_rows:
        raise WorkerExecutionError(
            "process-exit completion unexpectedly retained observer evidence"
        )
    if armed_source_mode == STDOUT_ASSIGNED_OUTPUT:
        if len(outputs) != 1:
            raise WorkerExecutionError("stdout source mode output denominator mismatch")
        stdout_output = outputs[0]
        if (
            stdout_output.get("raw_size") != len(stdout_raw)
            or stdout_output.get("raw_sha256") != _digest_bytes(stdout_raw)
        ):
            raise WorkerExecutionError("stdout bytes do not bind the assigned output")

    if publish_receipt_path is None or expected_publish_sha256 is None:
        if publish_receipt_path is not None or expected_publish_sha256 is not None:
            raise WorkerExecutionError(
                "publish receipt path and digest must both be present or absent"
            )
        if publication_authority != "PHASE_IO_ONLY":
            raise WorkerExecutionError(
                "staged-only validation requires PhaseIO publication authority"
            )
        return completion
    if publication_authority != "LEGACY_PROVIDER":
        raise WorkerExecutionError(
            "legacy publish receipt conflicts with PhaseIO-only authority"
        )

    publish_path_input = Path(
        os.path.abspath(os.fspath(publish_receipt_path))
    )
    if (
        _rooted_is_symlink(publish_path_input)
        or _is_reparse(publish_path_input)
        or not _rooted_is_file(publish_path_input)
    ):
        raise WorkerExecutionError("publish receipt cannot be a symlink/reparse point")
    try:
        publish_relative = publish_path_input.relative_to(shard_dir)
    except ValueError as exc:
        raise WorkerExecutionError("publish receipt is outside the execution shard") from exc
    if len(publish_relative.parts) != 1:
        raise WorkerExecutionError("publish receipt has an invalid location")
    publish_path = _safe_descendant(
        shard_dir,
        publish_relative.as_posix(),
        allow_missing=False,
    )
    publish_receipt, publish_sha = _load_hashed_json(
        publish_path,
        prefix="publish",
        digest_field="publish_sha256",
        schema=PUBLISH_SCHEMA,
    )
    _exact_positive_int(
        publish_receipt.get("published_at_unix_ns"),
        "publish receipt timestamp",
    )
    if _require_sha(expected_publish_sha256, "expected_publish_sha256") != publish_sha:
        raise WorkerExecutionError("publish receipt does not match expected authority")
    if publish_receipt.get("completion_sha256") != completion_sha:
        raise WorkerExecutionError("publish receipt binds a different completion")
    if publish_receipt.get("completion_relative_path") != receipt.name:
        raise WorkerExecutionError("publish receipt completion path mismatch")
    publish_arm_rel = _require_relative_path(
        publish_receipt.get("publish_arm_relative_path"), "publish arm path"
    )
    if "/" in publish_arm_rel:
        raise WorkerExecutionError("publish arm must be a direct shard artifact")
    publish_arm_path = _safe_descendant(shard_dir, publish_arm_rel, allow_missing=False)
    publish_arm, publish_arm_sha = _load_hashed_json(
        publish_arm_path,
        prefix="publish_arm",
        digest_field="publish_arm_sha256",
        schema=PUBLISH_ARM_SCHEMA,
    )
    _exact_positive_int(
        publish_arm.get("armed_at_unix_ns"),
        "publish arm timestamp",
    )
    if publish_receipt.get("publish_arm_sha256") != publish_arm_sha:
        raise WorkerExecutionError("publish receipt does not bind its current arm")
    if publish_arm.get("completion_sha256") != completion_sha:
        raise WorkerExecutionError("publish arm binds a different completion")
    if publish_arm.get("completion_relative_path") != receipt.name:
        raise WorkerExecutionError("publish arm completion path mismatch")
    arm_destinations = publish_arm.get("destinations")
    published_destinations = publish_receipt.get("destinations")
    if not isinstance(arm_destinations, list) or not isinstance(published_destinations, list):
        raise WorkerExecutionError("publish destination denominator is malformed")
    if len(arm_destinations) != len(outputs) or len(published_destinations) != len(outputs):
        raise WorkerExecutionError("publish destination denominator mismatch")
    for index, (output, armed, published_row) in enumerate(
        zip(outputs, arm_destinations, published_destinations)
    ):
        expected_armed = _publication_destination_binding(
            {
                "assignment_id": output["assignment_id"],
                "publish_relative_path": output["publish_relative_path"],
                "source_blob": output["cas_blob"],
                "raw_sha256": output["raw_sha256"],
                "raw_size": output["raw_size"],
                "pre_state": "ABSENT",
            },
            label=f"completion publication destination {index}",
            published=False,
        )
        normalized_armed = _publication_destination_binding(
            armed,
            label=f"publish arm destination {index}",
            published=False,
        )
        normalized_published = _publication_destination_binding(
            published_row,
            label=f"publish receipt destination {index}",
            published=True,
        )
        if normalized_armed != expected_armed:
            raise WorkerExecutionError("publish arm destination binding mismatch")
        if normalized_published != {**expected_armed, "post_state": "PRESENT"}:
            raise WorkerExecutionError("publish receipt destination binding mismatch")
        destination = _safe_descendant(
            root, output["publish_relative_path"], allow_missing=False
        )
        raw = _read_rooted_bytes(destination)
        if len(raw) != output["raw_size"] or _digest_bytes(raw) != output["raw_sha256"]:
            raise WorkerExecutionError("canonical published bytes changed")
    return completion


def validate_staged_execution(
    *,
    scratchpad: str | Path,
    receipt_path: str | Path,
    parser_digest: ParserDigest,
    expected_completion_sha256: str,
    trusted_parser_closure: _TrustedCallableClosure | None = None,
) -> dict[str, Any]:
    """Replay a closed execution whose CAS awaits PhaseIO incorporation."""

    return validate_completed_execution(
        scratchpad=scratchpad,
        receipt_path=receipt_path,
        publish_receipt_path=None,
        parser_digest=parser_digest,
        expected_completion_sha256=expected_completion_sha256,
        expected_publish_sha256=None,
        trusted_parser_closure=trusted_parser_closure,
    )


def staged_execution_stream_bytes(
    *,
    scratchpad: str | Path,
    receipt_path: str | Path,
    parser_digest: ParserDigest,
    expected_completion_sha256: str,
) -> tuple[bytes, bytes]:
    """Replay and return exact stdout/stderr bytes for a staged execution."""

    completion = validate_staged_execution(
        scratchpad=scratchpad,
        receipt_path=receipt_path,
        parser_digest=parser_digest,
        expected_completion_sha256=expected_completion_sha256,
    )
    receipt = _checked_root_file(
        receipt_path,
        label="completion receipt",
    )
    shard_dir = receipt.parent
    return (
        _replay_blob(shard_dir, completion.get("stdout_blob"), "stdout"),
        _replay_blob(shard_dir, completion.get("stderr_blob"), "stderr"),
    )


def execution_debt_stream_bytes(
    *,
    scratchpad: str | Path,
    debt_path: str | Path,
) -> tuple[bytes, bytes, dict[str, Any]]:
    """Replay provider debt and return exact streams plus terminal metadata."""

    root = _checked_root_directory(
        scratchpad,
        label="scratchpad",
    )
    debt = _checked_root_file(
        debt_path,
        label="execution debt",
    )
    try:
        debt.relative_to(root)
    except ValueError as exc:
        raise WorkerExecutionError(
            "execution debt is outside the scratchpad"
        ) from exc
    shard_dir = debt.parent
    payload, _debt_sha = _load_hashed_json(
        debt,
        prefix="debt",
        digest_field="debt_sha256",
        schema=DEBT_SCHEMA,
    )
    arm_relative = _require_relative_path(
        payload.get("arm_relative_path"),
        "debt arm relative_path",
    )
    arm_path = _safe_descendant(
        shard_dir,
        arm_relative,
        allow_missing=False,
    )
    _arm, arm_sha = _load_hashed_json(
        arm_path,
        prefix="arm",
        digest_field="arm_sha256",
        schema=ARM_SCHEMA,
    )
    if payload.get("arm_sha256") != arm_sha:
        raise WorkerExecutionError("execution debt arm digest mismatch")
    observation = payload.get("process_observation")
    if not isinstance(observation, dict):
        raise WorkerExecutionError(
            "execution debt process observation is malformed"
        )
    return (
        _replay_blob(shard_dir, payload.get("stdout_blob"), "stdout"),
        _replay_blob(shard_dir, payload.get("stderr_blob"), "stderr"),
        {
            "reason_code": str(payload.get("reason_code") or ""),
            "detail": str(payload.get("detail") or ""),
            "returncode": observation.get("returncode"),
            "timed_out": observation.get("timed_out"),
        },
    )


def completed_execution_scratchpad_read_set(
    *,
    scratchpad: str | Path,
    receipt_path: str | Path,
    publish_receipt_path: str | Path,
    parser_digest: ParserDigest,
    expected_completion_sha256: str,
    expected_publish_sha256: str,
) -> tuple[str, ...]:
    """Return the exact persisted scratchpad graph replayed by validation.

    Directory membership is not execution authority.  Consumers that need to
    bind a completed provider into another PhaseIO transaction can use this
    validated, transitive read set instead of recursively including an entire
    worker-receipt tree.
    """

    completion = validate_completed_execution(
        scratchpad=scratchpad,
        receipt_path=receipt_path,
        publish_receipt_path=publish_receipt_path,
        parser_digest=parser_digest,
        expected_completion_sha256=expected_completion_sha256,
        expected_publish_sha256=expected_publish_sha256,
    )
    root = _checked_root_directory(
        scratchpad,
        label="scratchpad",
    )
    receipt = _checked_root_file(
        receipt_path,
        label="completion receipt",
    )
    publish_path = _checked_root_file(
        publish_receipt_path,
        label="publish receipt",
    )
    shard_dir = receipt.parent
    paths: set[str] = set()

    def add(path: Path) -> None:
        resolved = _checked_root_file(
            path,
            label="execution read-set artifact",
            require_single_link=False,
        )
        try:
            relative = resolved.relative_to(root).as_posix()
        except ValueError as exc:
            raise WorkerExecutionError(
                "execution read-set artifact is outside the scratchpad"
            ) from exc
        paths.add(relative)

    add(receipt)
    add(publish_path)
    arm_relative = _require_relative_path(
        completion.get("arm_relative_path"), "arm_relative_path"
    )
    arm_path = _safe_descendant(shard_dir, arm_relative, allow_missing=False)
    arm, _arm_sha = _load_hashed_json(
        arm_path,
        prefix="arm",
        digest_field="arm_sha256",
        schema=ARM_SCHEMA,
    )
    add(arm_path)

    bindings = arm.get("bindings")
    inputs = bindings.get("inputs") if isinstance(bindings, dict) else None
    if not isinstance(inputs, dict):
        raise WorkerExecutionError(
            "execution read-set input denominator is malformed"
        )
    for row in inputs.values():
        if not isinstance(row, dict):
            raise WorkerExecutionError(
                "execution read-set input row is malformed"
            )
        relative = _require_relative_path(
            row.get("relative_path"), "bound input relative_path"
        )
        add(_safe_descendant(root, relative, allow_missing=False))

    output_contract = arm.get("output_contract")
    if not isinstance(output_contract, dict):
        raise WorkerExecutionError(
            "execution read-set output contract is malformed"
        )
    scope_relative = _require_relative_path(
        output_contract.get("scope_relative"), "output scope"
    )
    for row in output_contract.get("expected_outputs") or []:
        if not isinstance(row, dict):
            raise WorkerExecutionError(
                "execution read-set expected output row is malformed"
            )
        relative = _require_relative_path(
            row.get("relative_path"), "expected output relative_path"
        )
        add(_safe_descendant(
            root, f"{scope_relative}/{relative}", allow_missing=False
        ))

    outputs = completion.get("outputs")
    if not isinstance(outputs, list):
        raise WorkerExecutionError(
            "execution read-set completion outputs are malformed"
        )
    for row in outputs:
        if not isinstance(row, dict):
            raise WorkerExecutionError(
                "execution read-set completion output row is malformed"
            )
        blob = row.get("cas_blob")
        if not isinstance(blob, dict):
            raise WorkerExecutionError(
                "execution read-set output CAS record is malformed"
            )
        add(_safe_descendant(
            shard_dir,
            _require_relative_path(
                blob.get("relative_path"), "output CAS relative_path"
            ),
            allow_missing=False,
        ))
        add(_safe_descendant(
            root,
            _require_relative_path(
                row.get("publish_relative_path"),
                "published output relative_path",
            ),
            allow_missing=False,
        ))
    for field, label in (
        ("stdout_blob", "stdout"),
        ("stderr_blob", "stderr"),
    ):
        blob = completion.get(field)
        if not isinstance(blob, dict):
            raise WorkerExecutionError(
                f"execution read-set {label} blob is malformed"
            )
        add(_safe_descendant(
            shard_dir,
            _require_relative_path(
                blob.get("relative_path"), f"{label} blob relative_path"
            ),
            allow_missing=False,
        ))

    publish_receipt, _publish_sha = _load_hashed_json(
        publish_path,
        prefix="publish",
        digest_field="publish_sha256",
        schema=PUBLISH_SCHEMA,
    )
    publish_arm_relative = _require_relative_path(
        publish_receipt.get("publish_arm_relative_path"),
        "publish arm relative_path",
    )
    publish_arm_path = _safe_descendant(
        shard_dir, publish_arm_relative, allow_missing=False
    )
    _load_hashed_json(
        publish_arm_path,
        prefix="publish_arm",
        digest_field="publish_arm_sha256",
        schema=PUBLISH_ARM_SCHEMA,
    )
    add(publish_arm_path)
    return tuple(sorted(paths))


__all__ = [
    "ARM_SCHEMA",
    "COMPLETION_SCHEMA",
    "CLAUDE_STREAM_STDOUT_CONFIGURATION_SCHEMA",
    "DEBT_SCHEMA",
    "PUBLISH_ARM_SCHEMA",
    "PUBLISH_SCHEMA",
    "LAUNCHER_IDENTITY",
    "WORKER_FILE_OUTPUTS",
    "STDOUT_ASSIGNED_OUTPUT",
    "DEFAULT_STDOUT_LIMIT_BYTES",
    "DEFAULT_STDERR_LIMIT_BYTES",
    "DEFAULT_STAGED_OUTPUT_LIMIT_BYTES",
    "MAX_STREAM_LIMIT_BYTES",
    "BoundInput",
    "CompletedExecution",
    "ExecutionBindings",
    "ExpectedOutput",
    "PrincipalInvocation",
    "ParserDigest",
    "PtyLifecycleAdapter",
    "SemanticRuntimeDependencyUnsupported",
    "WorkerExecutionError",
    "WorkerExecutionIncomplete",
    "environment_allowlist_sha256",
    "process_tree_termination_capability",
    "run_observed_worker",
    "execution_debt_stream_bytes",
    "staged_execution_stream_bytes",
    "completed_execution_scratchpad_read_set",
    "validate_completed_execution",
    "validate_staged_execution",
]
