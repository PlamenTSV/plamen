"""WER-owned Claude runtime materialization transaction.

This module is the single composition boundary between an immutable
launch-security request and attempt-private Claude state.  It deliberately
does not launch a process.  The supported production lanes are:

* SAFE_MODE settings;
* BOUND_SETTINGS with exact provider-parent settings/MCP bytes;
* official Claude endpoint;
* an access-only OAUTH_TOKEN environment capability with no writeback; or
* FILE_BACKED STORED_SUBSCRIPTION_OAUTH with one exact, one-shot
  stored-source materialization capability.

When present, the stored source capability must be consumed by
``claude_attempt_profile``.  A path re-read is never an acceptable fallback.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import stat
import threading
from types import MappingProxyType
from typing import Any, Mapping, Sequence
import uuid
import weakref

import auxiliary_writable_root_lease as _aux
from auxiliary_writable_root_startup import (
    AuxiliaryWritableRootStartupError,
    replay_startup_permit_binding,
)
import claude_attempt_profile as _profile
from claude_attempt_profile import (
    ClaudeAttemptProfile,
    ClaudeAttemptProfileError,
    materialize_claude_attempt_profile,
    mint_claude_fresh_postprocess_authority,
    prove_claude_bound_prelaunch_scope_closed,
    prove_claude_normal_scope_failure_closed,
    prove_claude_process_attach_failure_scope_closed,
    prove_claude_profile_scope_closed,
    replay_claude_attempt_profile_binding,
    replay_claude_attempt_profile_postprocess_binding,
    replay_claude_attempt_profile_revocation,
)
import claude_auth_route as _auth
from claude_auth_route import ClaudeAuthRouteError
import claude_child_environment as _child
from claude_child_environment import (
    ClaudeChildEnvironmentError,
    CompiledClaudeChildEnvironment,
)
import claude_launch_security as _launch
from claude_launch_security import ClaudeLaunchSecurityError
import claude_phase_tool_policy as _phase_tool_policy
import provider_command_authority as _provider_command
import claude_stored_subscription_source as _stored
from claude_stored_subscription_source import (
    ClaudeStoredSubscriptionSourceError,
    StoredSubscriptionMaterializationCapability,
)


RUNTIME_MATERIALIZATION_SCHEMA = (
    "plamen.claude_runtime_materialization.v1"
)
RUNTIME_MATERIALIZATION_ERROR_SCHEMA = (
    "plamen.claude_runtime_materialization_error.v1"
)
RUNTIME_MATERIALIZATION_REQUEST_SCHEMA = (
    "plamen.claude_runtime_materialization_request.v1"
)
RUNTIME_MATERIALIZATION_REQUEST_DISCARD_SCHEMA = (
    "plamen.claude_runtime_materialization_request_discard.v1"
)
RUNTIME_MATERIALIZATION_LIFECYCLE_SCHEMA = (
    "plamen.claude_runtime_materialization_lifecycle.v1"
)
RUNTIME_POSTPROCESS_RECONCILIATION_SCHEMA = (
    "plamen.claude_runtime_postprocess_reconciliation.v1"
)
AUXILIARY_PURPOSE = "claude-attempt-profile"
CLAUDE_PRIVATE_MCP_SOURCE_MANIFEST_ENV = (
    "PLAMEN_CLAUDE_MCP_SOURCE_MANIFEST"
)
CLAUDE_MCP_SOURCE_AUTHORITY_SCHEMA = (
    "plamen.claude_mcp_source_authority.v1"
)
_MCP_RUNTIME_ENVIRONMENT_NAMES = "plamenRuntimeEnvironmentNames"
_MCP_RUNTIME_SOURCE_AUTHORITY = "plamenRuntimeSourceAuthority"
_MCP_SOURCE_STORE_CLASS = "CLAUDE_MCP_JSON"

_SHA256 = re.compile(r"[0-9a-f]{64}")
_SAFE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}")
_HOST_INPUT_CAPABILITY = object()
_HOST_INPUT_ISSUANCE_LOCK = threading.RLock()
_HOST_INPUT_PENDING: dict[str, dict[str, Any]] = {}
_HOST_INPUT_ISSUED: dict[
    int, tuple[weakref.ReferenceType[Any], dict[str, Any]]
] = {}
_REQUEST_CAPABILITY = object()
_REQUEST_ISSUANCE_LOCK = threading.RLock()
_REQUEST_PENDING: dict[str, dict[str, Any]] = {}
_REQUEST_ISSUED: dict[
    int, tuple[weakref.ReferenceType[Any], dict[str, Any]]
] = {}
_RESULT_CAPABILITY = object()
_MAX_BOUND_SOURCE_BYTES = 8 * 1024 * 1024
_MAX_MCP_SOURCE_BYTES = 8 * 1024 * 1024


def _build_host_input_one_shot_ledger():
    """Keep lifecycle state outside capability slots and public registries.

    This ledger is a replay guard, not semantic authority.  Final provider
    sinks must still replay the canonical provider parent and host policy.
    """

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
                raise ClaudeRuntimeMaterializationError(
                    "RUNTIME_HOST_INPUTS_ALREADY_CLAIMED",
                    "runtime host inputs are already claimed",
                )
            ledger[value] = (current[0], True)

    return register, consume


(
    _register_host_input_one_shot,
    _consume_host_input_one_shot,
) = _build_host_input_one_shot_ledger()


def _build_request_parent_ledger():
    """Bind and retain the canonical provider parent across the request seam."""

    lock = threading.RLock()
    ledger: weakref.WeakKeyDictionary[
        Any,
        tuple[
            int,
            bool,
            str | None,
            str | None,
            tuple[Any, ...] | None,
        ],
    ] = weakref.WeakKeyDictionary()

    def register(
        value: Any,
        preparation_sha256: str | None,
        attachment_sha256: str | None,
        provider_parent: tuple[Any, ...] | None,
    ) -> None:
        with lock:
            ledger[value] = (
                os.getpid(),
                False,
                preparation_sha256,
                attachment_sha256,
                provider_parent,
            )

    def consume(
        value: Any,
        preparation_sha256: str | None,
        attachment_sha256: str | None,
        provider_parent: tuple[Any, ...] | None,
    ) -> None:
        with lock:
            current = ledger.get(value)
            if (
                current is None
                or current[0] != os.getpid()
                or current[1]
                or current[2] != preparation_sha256
                or current[3] != attachment_sha256
                or current[4] is not provider_parent
            ):
                raise ClaudeRuntimeMaterializationError(
                    "RUNTIME_REQUEST_PRIVATE_INPUT_DRIFT",
                    "runtime request provider-parent authority drifted",
                )
            ledger[value] = (
                current[0],
                True,
                current[2],
                current[3],
                current[4],
            )

    def canonical_parent(
        value: Any,
    ) -> tuple[str | None, str | None, tuple[Any, ...] | None]:
        """Return issuance-owned parent identity, never a mutable slot value."""

        with lock:
            current = ledger.get(value)
            if (
                current is None
                or current[0] != os.getpid()
                or current[1]
            ):
                raise ClaudeRuntimeMaterializationError(
                    "RUNTIME_REQUEST_PRIVATE_INPUT_DRIFT",
                    "runtime request provider-parent authority drifted",
                )
            return current[2], current[3], current[4]

    return register, canonical_parent, consume


(
    _register_request_parent,
    _canonical_request_parent,
    _consume_request_parent,
) = _build_request_parent_ledger()
_CLAUDE_PRECEDENCE_ENVIRONMENT_DENIALS = frozenset(
    {"CLAUDE_SECURESTORAGE_CONFIG_DIR"}
)
_PROFILE_ARGV_PREFIXES = (
    "--tools",
    "--allowedTools",
    "--allowed-tools",
    "--disable-slash-commands",
    "--setting-sources",
    "--no-chrome",
    "--prompt-suggestions",
    "--restricted",
    "--safe-mode",
    "--dangerously-skip-permissions",
    "--permission-mode",
    "--settings",
    "--strict-mcp-config",
    "--mcp-config",
    "--disallowedTools",
)
_FORBIDDEN_SESSION_FLAGS = frozenset(
    {
        "--include-partial-messages",
        "--forward-subagent-output",
        "--forward-subagent-text",
        "--continue",
        "-c",
        "--resume",
        "-r",
        "--from-pr",
        "--fork-session",
        "--print",
    }
)


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
        raise ClaudeRuntimeMaterializationError(
            "RUNTIME_RECEIPT_NOT_CANONICAL",
            "runtime materialization receipt is not canonical",
        ) from exc


def _digest(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def _clone(value: Mapping[str, Any]) -> dict[str, Any]:
    try:
        raw = json.dumps(
            dict(value),
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        clone = json.loads(raw)
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise ClaudeRuntimeMaterializationError(
            "RUNTIME_AUTHORITY_NOT_JSON",
            "runtime materialization authority is malformed",
        ) from exc
    if not isinstance(clone, dict):
        raise ClaudeRuntimeMaterializationError(
            "RUNTIME_AUTHORITY_NOT_OBJECT",
            "runtime materialization authority is malformed",
        )
    return clone


def _required_sha256(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise ClaudeRuntimeMaterializationError(
            "RUNTIME_IDENTITY_INVALID",
            f"{label} is invalid",
        )
    return value


def _required_id(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _SAFE_ID.fullmatch(value) is None:
        raise ClaudeRuntimeMaterializationError(
            "RUNTIME_IDENTITY_INVALID",
            f"{label} is invalid",
        )
    return value


def _error_receipt(reason_code: str) -> dict[str, Any]:
    core = {
        "schema": RUNTIME_MATERIALIZATION_ERROR_SCHEMA,
        "reason_code": reason_code,
        "credential_values_recorded": False,
        "credential_content_hashes_recorded": False,
        "host_paths_recorded": False,
    }
    return {**core, "receipt_sha256": _digest(core)}


class ClaudeRuntimeMaterializationError(RuntimeError):
    """Secret-free, typed failure at the pre-process transaction boundary."""

    def __init__(self, reason_code: str, public_message: str) -> None:
        if (
            not isinstance(reason_code, str)
            or _SAFE_ID.fullmatch(reason_code) is None
            or not isinstance(public_message, str)
            or not public_message
            or "\x00" in public_message
        ):
            reason_code = "RUNTIME_MATERIALIZATION_FAILED"
            public_message = "Claude runtime materialization failed"
        super().__init__(public_message)
        self.reason_code = reason_code
        self.redacted_receipt = _error_receipt(reason_code)

    def __repr__(self) -> str:
        return (
            "ClaudeRuntimeMaterializationError("
            f"reason_code={self.reason_code!r})"
        )


def claude_runtime_argv_sha256(argv: Sequence[str]) -> str:
    """Canonical argv digest shared with WorkerTransaction/WER."""

    try:
        return _provider_command.argv_authority_sha256(argv)
    except (
        _provider_command.ProviderCommandAuthorityError,
        TypeError,
    ) as exc:
        raise ClaudeRuntimeMaterializationError(
            "RUNTIME_ARGV_INVALID",
            "runtime argv is malformed",
        ) from exc


def _argv_sha256(argv: Sequence[str]) -> str:
    return claude_runtime_argv_sha256(argv)


def claude_runtime_environment_key_set_sha256(
    names: Sequence[str],
) -> str:
    """Canonical environment-name denominator shared with WER."""

    if isinstance(names, (str, bytes)) or not isinstance(names, Sequence):
        raise ClaudeRuntimeMaterializationError(
            "RUNTIME_ENVIRONMENT_NAMES_INVALID",
            "runtime environment names are malformed",
        )
    folded = []
    for name in names:
        if (
            not isinstance(name, str)
            or not name
            or "=" in name
            or "\x00" in name
        ):
            raise ClaudeRuntimeMaterializationError(
                "RUNTIME_ENVIRONMENT_NAMES_INVALID",
                "runtime environment names are malformed",
            )
        folded.append(name.casefold())
    if len(folded) != len(set(folded)):
        raise ClaudeRuntimeMaterializationError(
            "RUNTIME_ENVIRONMENT_NAMES_AMBIGUOUS",
            "runtime environment names are case-ambiguous",
        )
    return hashlib.sha256(
        "\0".join(sorted(folded)).encode("utf-8")
    ).hexdigest()


def _canonical_directory(
    value: str | Path,
    *,
    label: str,
) -> Path:
    try:
        candidate = Path(value)
        absolute = Path(os.path.abspath(candidate))
        info = absolute.lstat()
        resolved = absolute.resolve(strict=True)
    except (OSError, TypeError, ValueError) as exc:
        raise ClaudeRuntimeMaterializationError(
            "RUNTIME_LOCAL_PATH_INVALID",
            f"{label} is unavailable",
        ) from exc
    if (
        resolved != absolute
        or not stat.S_ISDIR(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or bool(
            int(getattr(info, "st_file_attributes", 0)) & 0x400
        )
    ):
        raise ClaudeRuntimeMaterializationError(
            "RUNTIME_LOCAL_PATH_ALIAS",
            f"{label} is not one canonical directory",
        )
    return resolved


def _strict_json_object(raw: bytes, *, label: str) -> dict[str, Any]:
    """Parse one bounded JSON object while rejecting duplicate member names."""

    def object_pairs(
        pairs: list[tuple[str, Any]],
    ) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON member")
            result[key] = value
        return result

    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=object_pairs,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                ValueError("non-finite JSON number")
            ),
        )
    except (UnicodeError, ValueError, json.JSONDecodeError) as exc:
        raise ClaudeRuntimeMaterializationError(
            "RUNTIME_BOUND_SOURCE_INVALID",
            f"{label} is not strict JSON",
        ) from exc
    if not isinstance(value, dict):
        raise ClaudeRuntimeMaterializationError(
            "RUNTIME_BOUND_SOURCE_INVALID",
            f"{label} must be one JSON object",
        )
    return value


def _canonical_mcp_source_path(
    value: str | Path,
) -> tuple[Path, os.stat_result]:
    """Return one exact, non-aliased installed MCP manifest path."""

    try:
        path = Path(value)
        absolute = Path(os.path.abspath(path))
        resolved = absolute.resolve(strict=True)
        row = absolute.lstat()
    except (OSError, TypeError, ValueError) as exc:
        raise ClaudeRuntimeMaterializationError(
            "RUNTIME_MCP_SOURCE_UNAVAILABLE",
            "selected MCP source manifest is unavailable",
        ) from exc
    if (
        not path.is_absolute()
        or path != absolute
        or resolved != absolute
        or not stat.S_ISREG(row.st_mode)
        or stat.S_ISLNK(row.st_mode)
        or bool(int(getattr(row, "st_file_attributes", 0)) & 0x400)
        or row.st_size <= 0
        or row.st_size > _MAX_MCP_SOURCE_BYTES
    ):
        raise ClaudeRuntimeMaterializationError(
            "RUNTIME_MCP_SOURCE_INVALID",
            "selected MCP source manifest is not one bounded canonical file",
        )
    return absolute, row


def _canonical_mcp_executable(value: Any) -> str:
    """Resolve a selected stdio MCP command to one exact executable."""

    if not isinstance(value, str) or not value or "\x00" in value:
        raise ClaudeRuntimeMaterializationError(
            "RUNTIME_MCP_SOURCE_INVALID",
            "selected MCP command is malformed",
        )
    candidate = Path(value)
    if not candidate.is_absolute():
        resolved_name = shutil.which(value)
        if not resolved_name:
            raise ClaudeRuntimeMaterializationError(
                "RUNTIME_MCP_SOURCE_UNAVAILABLE",
                "selected MCP command is unavailable",
            )
        candidate = Path(resolved_name)
    try:
        absolute = Path(os.path.abspath(candidate))
        resolved = absolute.resolve(strict=True)
        row = absolute.lstat()
    except (OSError, TypeError, ValueError) as exc:
        raise ClaudeRuntimeMaterializationError(
            "RUNTIME_MCP_SOURCE_UNAVAILABLE",
            "selected MCP command is unavailable",
        ) from exc
    if (
        absolute != resolved
        or not stat.S_ISREG(row.st_mode)
        or stat.S_ISLNK(row.st_mode)
        or bool(int(getattr(row, "st_file_attributes", 0)) & 0x400)
    ):
        raise ClaudeRuntimeMaterializationError(
            "RUNTIME_MCP_SOURCE_INVALID",
            "selected MCP command is not one canonical file",
        )
    return str(absolute)


def _canonical_mcp_cwd(value: Any) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ClaudeRuntimeMaterializationError(
            "RUNTIME_MCP_SOURCE_INVALID",
            "selected MCP cwd is malformed",
        )
    path = Path(value)
    try:
        absolute = Path(os.path.abspath(path))
        resolved = absolute.resolve(strict=True)
        row = absolute.lstat()
    except (OSError, TypeError, ValueError) as exc:
        raise ClaudeRuntimeMaterializationError(
            "RUNTIME_MCP_SOURCE_UNAVAILABLE",
            "selected MCP cwd is unavailable",
        ) from exc
    if (
        not path.is_absolute()
        or path != absolute
        or resolved != absolute
        or not stat.S_ISDIR(row.st_mode)
        or stat.S_ISLNK(row.st_mode)
        or bool(int(getattr(row, "st_file_attributes", 0)) & 0x400)
    ):
        raise ClaudeRuntimeMaterializationError(
            "RUNTIME_MCP_SOURCE_INVALID",
            "selected MCP cwd is not one canonical directory",
        )
    return str(absolute)


def _mcp_secret_available(value: Any) -> bool:
    if not isinstance(value, str) or not value or "\x00" in value:
        return False
    folded = value.strip().casefold()
    return (
        bool(folded)
        and not folded.startswith("your_")
        and not folded.startswith("<")
        and folded
        not in {
            "changeme",
            "change_me",
            "replace_me",
            "replace-me",
            "unset",
            "none",
        }
    )


def _mcp_source_identity_sha256(
    *,
    run_id: str,
    path: Path,
    row: os.stat_result,
) -> str:
    """Run-scope the source identity without publishing its host path."""

    return hashlib.sha256(
        _canonical_json(
            {
                "purpose": "claude-selected-mcp-source",
                "run_id": run_id,
                "canonical_path": os.path.normcase(str(path)),
                "device": int(row.st_dev),
                "inode": int(row.st_ino),
                "size": int(row.st_size),
                "mtime_ns": int(row.st_mtime_ns),
            }
        )
    ).hexdigest()


def _read_claude_mcp_source_manifest(
    *,
    source_path: str | Path,
    run_id: str,
    server_names: Sequence[str],
) -> tuple[dict[str, Any], dict[str, dict[str, str]]]:
    """Read one source and return public structure plus private values."""

    run = _required_id(run_id, label="run_id")
    names = tuple(
        sorted(
            _required_id(name, label="MCP server name")
            for name in server_names
        )
    )
    if not names or len(set(names)) != len(names):
        raise ClaudeRuntimeMaterializationError(
            "RUNTIME_MCP_SOURCE_INVALID",
            "selected MCP server denominator is empty or duplicated",
        )
    path, before = _canonical_mcp_source_path(source_path)
    try:
        raw = path.read_bytes()
        after = path.lstat()
    except OSError as exc:
        raise ClaudeRuntimeMaterializationError(
            "RUNTIME_MCP_SOURCE_UNAVAILABLE",
            "selected MCP source manifest is unavailable",
        ) from exc
    if (
        len(raw) != before.st_size
        or int(after.st_dev) != int(before.st_dev)
        or int(after.st_ino) != int(before.st_ino)
        or int(after.st_size) != int(before.st_size)
        or int(after.st_mtime_ns) != int(before.st_mtime_ns)
    ):
        raise ClaudeRuntimeMaterializationError(
            "RUNTIME_MCP_SOURCE_DRIFT",
            "selected MCP source manifest changed during observation",
        )
    payload = _strict_json_object(
        raw,
        label="selected MCP source manifest",
    )
    servers = payload.get("mcpServers")
    if set(payload) != {"mcpServers"} or not isinstance(servers, dict):
        raise ClaudeRuntimeMaterializationError(
            "RUNTIME_MCP_SOURCE_INVALID",
            "selected MCP source manifest schema is unsupported",
        )

    source_identity = _mcp_source_identity_sha256(
        run_id=run,
        path=path,
        row=before,
    )
    materialization_id = hashlib.sha256(
        _canonical_json(
            {
                "purpose": "claude-selected-mcp-materialization",
                "run_id": run,
                "source_file_identity_sha256": source_identity,
                "server_names": list(names),
            }
        )
    ).hexdigest()[:32]
    source_authority = {
        "schema": CLAUDE_MCP_SOURCE_AUTHORITY_SCHEMA,
        "sourceStoreClass": _MCP_SOURCE_STORE_CLASS,
        "sourceFileIdentitySha256": source_identity,
        "sourceFileSize": int(before.st_size),
        "materializationId": materialization_id,
    }
    selected: dict[str, Any] = {}
    private_environment: dict[str, dict[str, str]] = {}
    for name in names:
        entry = servers.get(name)
        if (
            not isinstance(entry, dict)
            or not {"command", "args", "cwd"}.issubset(entry)
            or not set(entry).issubset(
                {"command", "args", "cwd", "env"}
            )
        ):
            raise ClaudeRuntimeMaterializationError(
                "RUNTIME_MCP_SOURCE_INVALID",
                "selected MCP server definition is unsupported",
            )
        args = entry.get("args")
        if (
            not isinstance(args, list)
            or any(
                not isinstance(item, str) or "\x00" in item
                for item in args
            )
        ):
            raise ClaudeRuntimeMaterializationError(
                "RUNTIME_MCP_SOURCE_INVALID",
                "selected MCP arguments are malformed",
            )
        environment = entry.get("env", {})
        if not isinstance(environment, dict):
            raise ClaudeRuntimeMaterializationError(
                "RUNTIME_MCP_SOURCE_INVALID",
                "selected MCP environment is malformed",
            )
        environment_names = sorted(environment)
        if (
            any(
                not isinstance(key, str)
                or not key
                or "\x00" in key
                or not _mcp_secret_available(environment[key])
                for key in environment_names
            )
            or len({key.casefold() for key in environment_names})
            != len(environment_names)
        ):
            raise ClaudeRuntimeMaterializationError(
                "RUNTIME_MCP_SECRET_UNAVAILABLE",
                "selected MCP private environment is unavailable or malformed",
            )
        selected[name] = {
            "command": _canonical_mcp_executable(entry["command"]),
            "args": list(args),
            "cwd": _canonical_mcp_cwd(entry["cwd"]),
            _MCP_RUNTIME_ENVIRONMENT_NAMES: environment_names,
            _MCP_RUNTIME_SOURCE_AUTHORITY: dict(source_authority),
        }
        private_environment[name] = {
            key: environment[key]
            for key in environment_names
        }
    template = _canonical_json({"mcpServers": selected}) + b"\n"
    observation = {
        "server_names": names,
        "source_store_class": _MCP_SOURCE_STORE_CLASS,
        "source_file_identity_sha256": source_identity,
        "source_file_size": int(before.st_size),
        "materialization_id": materialization_id,
        "source_manifest_sha256": hashlib.sha256(template).hexdigest(),
        "selected_config_template_bytes": template,
    }
    return observation, private_environment


def observe_claude_mcp_source_manifest(
    *,
    source_path: str | Path,
    run_id: str,
    server_names: Sequence[str],
) -> dict[str, Any]:
    """Compile secret-free selected-server authority for a WorkPlan."""

    observation, private_environment = (
        _read_claude_mcp_source_manifest(
            source_path=source_path,
            run_id=run_id,
            server_names=server_names,
        )
    )
    for values in private_environment.values():
        values.clear()
    private_environment.clear()
    return observation


def _private_mcp_template_authority(
    payload: Mapping[str, Any],
    *,
    expected_servers: Sequence[str],
) -> bool:
    servers = payload.get("mcpServers")
    if not isinstance(servers, dict):
        return False
    markers: list[bool] = []
    shared_source: dict[str, Any] | None = None
    for name in expected_servers:
        entry = servers.get(name)
        if not isinstance(entry, dict):
            return False
        has_names = _MCP_RUNTIME_ENVIRONMENT_NAMES in entry
        has_source = _MCP_RUNTIME_SOURCE_AUTHORITY in entry
        if has_names != has_source:
            raise ClaudeRuntimeMaterializationError(
                "RUNTIME_MCP_TEMPLATE_INVALID",
                "selected MCP private-source template is incomplete",
            )
        markers.append(has_names)
        if not has_names:
            continue
        names = entry[_MCP_RUNTIME_ENVIRONMENT_NAMES]
        source = entry[_MCP_RUNTIME_SOURCE_AUTHORITY]
        if (
            "env" in entry
            or not isinstance(names, list)
            or names != sorted(set(names))
            or any(
                not isinstance(item, str) or not item
                for item in names
            )
            or not isinstance(source, dict)
            or set(source)
            != {
                "schema",
                "sourceStoreClass",
                "sourceFileIdentitySha256",
                "sourceFileSize",
                "materializationId",
            }
            or source.get("schema")
            != CLAUDE_MCP_SOURCE_AUTHORITY_SCHEMA
            or source.get("sourceStoreClass")
            != _MCP_SOURCE_STORE_CLASS
            or not isinstance(
                source.get("sourceFileIdentitySha256"),
                str,
            )
            or _SHA256.fullmatch(
                source["sourceFileIdentitySha256"]
            )
            is None
            or not isinstance(source.get("sourceFileSize"), int)
            or source["sourceFileSize"] <= 0
            or not isinstance(source.get("materializationId"), str)
            or re.fullmatch(
                r"[0-9a-f]{32}",
                source["materializationId"],
            )
            is None
        ):
            raise ClaudeRuntimeMaterializationError(
                "RUNTIME_MCP_TEMPLATE_INVALID",
                "selected MCP private-source template is malformed",
            )
        if shared_source is None:
            shared_source = dict(source)
        elif shared_source != dict(source):
            raise ClaudeRuntimeMaterializationError(
                "RUNTIME_MCP_TEMPLATE_INVALID",
                "selected MCP private-source authority is not singular",
            )
    if markers and any(markers) and not all(markers):
        raise ClaudeRuntimeMaterializationError(
            "RUNTIME_MCP_TEMPLATE_INVALID",
            "selected MCP source modes are mixed",
        )
    return bool(markers and all(markers))


def _resolve_attempt_private_mcp_config(
    template: bytes,
    *,
    ambient_environment: Mapping[str, str],
    run_id: str,
    expected_servers: Sequence[str],
) -> tuple[bytes, bool]:
    payload = _strict_json_object(
        template,
        label="selected MCP config template",
    )
    if not _private_mcp_template_authority(
        payload,
        expected_servers=expected_servers,
    ):
        return template, False
    source_names = [
        name
        for name in ambient_environment
        if name.casefold()
        == CLAUDE_PRIVATE_MCP_SOURCE_MANIFEST_ENV.casefold()
    ]
    if len(source_names) != 1:
        raise ClaudeRuntimeMaterializationError(
            "RUNTIME_MCP_SOURCE_UNAVAILABLE",
            "selected MCP private source path is unavailable",
        )
    observation, private_environment = (
        _read_claude_mcp_source_manifest(
            source_path=ambient_environment[source_names[0]],
            run_id=run_id,
            server_names=expected_servers,
        )
    )
    if observation["selected_config_template_bytes"] != template:
        for values in private_environment.values():
            values.clear()
        private_environment.clear()
        raise ClaudeRuntimeMaterializationError(
            "RUNTIME_MCP_SOURCE_DRIFT",
            "selected MCP source manifest differs from WorkPlan authority",
        )
    try:
        materialized = _strict_json_object(
            template,
            label="selected MCP config template",
        )
        servers = materialized["mcpServers"]
        for name in expected_servers:
            entry = servers[name]
            names = entry.pop(_MCP_RUNTIME_ENVIRONMENT_NAMES)
            entry.pop(_MCP_RUNTIME_SOURCE_AUTHORITY)
            values = private_environment[name]
            if sorted(values) != names:
                raise ClaudeRuntimeMaterializationError(
                    "RUNTIME_MCP_SOURCE_DRIFT",
                    "selected MCP private environment denominator drifted",
                )
            entry["env"] = dict(values)
        return _canonical_json(materialized) + b"\n", True
    finally:
        for values in private_environment.values():
            values.clear()
        private_environment.clear()


def _validated_bound_runtime_sources(
    *,
    policy: Mapping[str, Any],
    bound_settings_bytes: bytes | None,
    selected_mcp_config_bytes: bytes | None,
) -> tuple[bytes | None, bytes | None, tuple[str, ...]]:
    """Replay provider source bytes before reserving an auxiliary lease."""

    settings_authority = policy["settings_authority"]
    mcp_authority = policy["mcp_authority"]
    mode = settings_authority["mode"]
    if mode == "SAFE_MODE":
        if (
            bound_settings_bytes is not None
            or selected_mcp_config_bytes is not None
        ):
            raise ClaudeRuntimeMaterializationError(
                "RUNTIME_SAFE_MODE_SOURCE_PRESENT",
                "safe-mode runtime cannot carry settings or MCP bytes",
            )
        return None, None, ()
    if (
        type(bound_settings_bytes) is not bytes
        or type(selected_mcp_config_bytes) is not bytes
        or not bound_settings_bytes
        or not selected_mcp_config_bytes
        or len(bound_settings_bytes) > _MAX_BOUND_SOURCE_BYTES
        or len(selected_mcp_config_bytes) > _MAX_BOUND_SOURCE_BYTES
    ):
        raise ClaudeRuntimeMaterializationError(
            "RUNTIME_BOUND_SOURCE_REQUIRED",
            "bound-settings runtime requires exact bounded source bytes",
        )
    if hashlib.sha256(bound_settings_bytes).hexdigest() != (
        settings_authority["settings_sha256"]
    ):
        raise ClaudeRuntimeMaterializationError(
            "RUNTIME_BOUND_SETTINGS_DRIFT",
            "bound settings differ from launch authority",
        )
    if hashlib.sha256(selected_mcp_config_bytes).hexdigest() != (
        mcp_authority["selected_config_sha256"]
    ):
        raise ClaudeRuntimeMaterializationError(
            "RUNTIME_BOUND_MCP_DRIFT",
            "selected MCP config differs from launch authority",
        )
    settings = _strict_json_object(
        bound_settings_bytes,
        label="bound settings",
    )
    # Production reaches this seam only after launch-security replay, while a
    # small legacy generation-authority seam intentionally supplies only the
    # two already-authenticated settings/MCP authorities.  Absence therefore
    # selects the legacy deny-only lane; a present but malformed headless
    # authority must never downgrade to it.
    headless_profile = policy.get("headless_profile")
    if headless_profile is None:
        restricted_analysis = False
        restricted_web_analysis = False
    else:
        expected_init = (
            headless_profile.get("expected_init_contract")
            if isinstance(headless_profile, Mapping)
            else None
        )
        capabilities = (
            expected_init.get("required_capabilities")
            if isinstance(expected_init, Mapping)
            else None
        )
        if (
            not isinstance(capabilities, list)
            or any(
                not isinstance(capability, str) or not capability
                for capability in capabilities
            )
            or capabilities != sorted(set(capabilities))
        ):
            raise ClaudeRuntimeMaterializationError(
                "RUNTIME_BOUND_SETTINGS_INVALID",
                "bound settings launch capability authority is malformed",
            )
        restricted_web_analysis = (
            "vendor-restricted-web-analysis" in capabilities
        )
        restricted_analysis = (
            "vendor-restricted-analysis" in capabilities
            or restricted_web_analysis
        )
    try:
        _phase_tool_policy.validate_settings_overlay(
            settings,
            restricted_analysis=restricted_analysis,
            bounded_web=restricted_web_analysis,
        )
    except _phase_tool_policy.ClaudePhaseToolPolicyError as exc:
        raise ClaudeRuntimeMaterializationError(
            "RUNTIME_BOUND_SETTINGS_INVALID",
            "bound settings capability denominator is malformed",
        ) from exc
    mcp = _strict_json_object(
        selected_mcp_config_bytes,
        label="selected MCP config",
    )
    server_payload = mcp.get("mcpServers")
    expected_servers = tuple(mcp_authority["server_names"])
    if (
        set(mcp) != {"mcpServers"}
        or not isinstance(server_payload, dict)
        or tuple(sorted(server_payload)) != expected_servers
    ):
        raise ClaudeRuntimeMaterializationError(
            "RUNTIME_BOUND_MCP_INVALID",
            "selected MCP server denominator differs from launch authority",
        )
    runtime_selection = mcp_authority.get("runtime_selection")
    if runtime_selection is not None:
        try:
            runtime_selection = _launch.replay_mcp_current_selection(
                runtime_selection
            )
        except ClaudeLaunchSecurityError as exc:
            raise ClaudeRuntimeMaterializationError(
                "RUNTIME_MCP_SELECTION_INVALID",
                "authenticated MCP runtime selection does not replay",
            ) from exc
        expected_front = Path(
            os.path.abspath(
                os.path.expanduser(
                    "~/.local/bin/plamen.cmd"
                    if os.name == "nt"
                    else "~/.local/bin/plamen"
                )
            )
        )
        for server_name in expected_servers:
            entry = server_payload.get(server_name)
            expected_args = [
                "mcp-launch",
                "--backend",
                "claude",
                "--server",
                server_name,
                "--generation",
                runtime_selection["generation_id"],
                "--receipt-sha256",
                runtime_selection["receipt_sha256"],
                "--census-sha256",
                runtime_selection["census_sha256"],
                "--request-sha256",
                runtime_selection["request_sha256"],
                "--policy-sha256",
                runtime_selection["generation_policy_sha256"],
            ]
            if (
                not isinstance(entry, dict)
                or set(entry) != {"command", "args"}
                or entry.get("command") != os.fspath(expected_front)
                or entry.get("args") != expected_args
            ):
                raise ClaudeRuntimeMaterializationError(
                    "RUNTIME_MCP_SELECTION_DRIFT",
                    "selected MCP launcher differs from signed generation",
                )
    return (
        bound_settings_bytes,
        selected_mcp_config_bytes,
        expected_servers,
    )


@dataclass(frozen=True)
class _ClaudeRuntimeAuthorityFile:
    path: Path = field(repr=False)
    exact_bytes: bytearray = field(repr=False)
    device: int = field(repr=False)
    inode: int = field(repr=False)


def _replay_runtime_authority_file(
    record: _ClaudeRuntimeAuthorityFile,
    *,
    label: str,
) -> None:
    """Prove one private settings/config path still has exact source bytes."""

    path = record.path
    try:
        row = path.lstat()
        absolute = Path(os.path.abspath(path))
        resolved = absolute.resolve(strict=True)
        raw = path.read_bytes()
    except (OSError, TypeError, ValueError) as exc:
        raise ClaudeRuntimeMaterializationError(
            "RUNTIME_BOUND_FILE_REPLAY_FAILED",
            f"{label} cannot be replayed",
        ) from exc
    if (
        path != absolute
        or resolved != absolute
        or not stat.S_ISREG(row.st_mode)
        or stat.S_ISLNK(row.st_mode)
        or bool(int(getattr(row, "st_file_attributes", 0)) & 0x400)
        or int(row.st_dev) != record.device
        or int(row.st_ino) != record.inode
        or raw != bytes(record.exact_bytes)
    ):
        raise ClaudeRuntimeMaterializationError(
            "RUNTIME_BOUND_FILE_DRIFT",
            f"{label} changed after materialization",
        )


def _materialize_runtime_authority_file(
    path: Path,
    raw: bytes,
    *,
    label: str,
) -> _ClaudeRuntimeAuthorityFile:
    """Create one attempt-owned private source file without path aliasing."""

    if not path.is_absolute() or os.path.lexists(path):
        raise ClaudeRuntimeMaterializationError(
            "RUNTIME_BOUND_FILE_CREATE_FAILED",
            f"{label} target is not one fresh absolute path",
        )
    descriptor: int | None = None
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            stat.S_IRUSR | stat.S_IWUSR,
        )
        view = memoryview(raw)
        written = 0
        while written < len(view):
            count = os.write(descriptor, view[written:])
            if count <= 0:
                raise OSError("short runtime-authority write")
            written += count
        if hasattr(os, "fchmod"):
            os.fchmod(descriptor, stat.S_IRUSR | stat.S_IWUSR)
        os.fsync(descriptor)
    except OSError as exc:
        raise ClaudeRuntimeMaterializationError(
            "RUNTIME_BOUND_FILE_CREATE_FAILED",
            f"{label} could not be materialized",
        ) from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
    try:
        row = path.lstat()
    except OSError as exc:
        raise ClaudeRuntimeMaterializationError(
            "RUNTIME_BOUND_FILE_CREATE_FAILED",
            f"{label} could not be materialized",
        ) from exc
    record = _ClaudeRuntimeAuthorityFile(
        path=path,
        exact_bytes=bytearray(raw),
        device=int(row.st_dev),
        inode=int(row.st_ino),
    )
    _replay_runtime_authority_file(record, label=label)
    return record


def _replay_runtime_authority_files(
    settings: _ClaudeRuntimeAuthorityFile | None,
    mcp: _ClaudeRuntimeAuthorityFile | None,
    *,
    expected_servers: Sequence[str],
) -> None:
    if settings is None or mcp is None:
        if settings is not None or mcp is not None or tuple(expected_servers):
            raise ClaudeRuntimeMaterializationError(
                "RUNTIME_BOUND_FILE_DRIFT",
                "runtime settings/MCP file denominator drifted",
            )
        return
    _replay_runtime_authority_file(
        settings,
        label="bound settings",
    )
    _replay_runtime_authority_file(
        mcp,
        label="selected MCP config",
    )
    payload = _strict_json_object(
        bytes(mcp.exact_bytes),
        label="selected MCP config",
    )
    servers = payload.get("mcpServers")
    if (
        set(payload) != {"mcpServers"}
        or not isinstance(servers, dict)
        or tuple(sorted(servers)) != tuple(expected_servers)
    ):
        raise ClaudeRuntimeMaterializationError(
            "RUNTIME_BOUND_MCP_DRIFT",
            "runtime MCP server denominator drifted",
        )


def _zeroize_runtime_authority_file(
    record: _ClaudeRuntimeAuthorityFile | None,
) -> None:
    if record is not None:
        _zeroize(record.exact_bytes)


def _zeroize(value: bytearray) -> None:
    for index in range(len(value)):
        value[index] = 0


def _private_input_bytes(
    *,
    auth_route: str,
    ambient_environment: Mapping[str, str],
    source_config_dir: Path | None,
    project_root: Path,
    trusted_cwds: Sequence[Path],
    scratchpad: Path | None = None,
) -> bytes:
    value: dict[str, Any] = {
        "auth_route": auth_route,
        "ambient_environment": dict(ambient_environment),
        "source_config_dir": (
            None
            if source_config_dir is None
            else str(source_config_dir)
        ),
        "project_root": str(project_root),
        "trusted_cwds": [str(path) for path in trusted_cwds],
    }
    if scratchpad is not None:
        value["scratchpad"] = str(scratchpad)
    return _canonical_json(value)


class ClaudeRuntimeHostInputs:
    """Opaque one-shot host input capability.

    This is the only object allowed to carry a full ambient environment across
    the outer-arm-to-runtime-materialization seam.  It is deliberately neither
    a dataclass nor serializable so Prepared/Adapter reprs cannot expose ambient
    credentials.
    """

    __slots__ = (
        "__ambient_environment",
        "__auth_route",
        "__claimed",
        "__identity",
        "__integrity_key",
        "__integrity_tag",
        "__lock",
        "__project_root",
        "__source_config_dir",
        "__trusted_cwds",
        "__weakref__",
    )

    def __new__(
        cls,
        *,
        _capability: object,
        ambient_environment: Mapping[str, str],
        auth_route: str,
        source_config_dir: Path | None,
        project_root: Path,
        trusted_cwds: Sequence[Path],
        integrity_key: bytearray,
        integrity_tag: bytes,
        identity: Mapping[str, Any],
        _issuance_id: str | None = None,
    ) -> ClaudeRuntimeHostInputs:
        if (
            cls is not ClaudeRuntimeHostInputs
            or _capability is not _HOST_INPUT_CAPABILITY
            or not isinstance(_issuance_id, str)
        ):
            raise TypeError("ClaudeRuntimeHostInputs is opaque")
        with _HOST_INPUT_ISSUANCE_LOCK:
            pending = _HOST_INPUT_PENDING.pop(_issuance_id, None)
        if (
            pending is None
            or pending["ambient_environment"] != dict(ambient_environment)
            or pending["auth_route"] != auth_route
            or pending["source_config_dir"] != source_config_dir
            or pending["project_root"] != project_root
            or pending["trusted_cwds"] != tuple(trusted_cwds)
            or pending["integrity_key"] is not integrity_key
            or pending["integrity_tag"] != integrity_tag
            or pending["identity"] != dict(identity)
        ):
            raise TypeError(
                "ClaudeRuntimeHostInputs requires validator issuance"
            )
        instance = super().__new__(cls)
        instance.__ambient_environment = MappingProxyType(
            dict(ambient_environment)
        )
        instance.__auth_route = auth_route
        instance.__source_config_dir = source_config_dir
        instance.__project_root = project_root
        instance.__trusted_cwds = tuple(trusted_cwds)
        instance.__integrity_key = integrity_key
        instance.__integrity_tag = bytes(integrity_tag)
        instance.__identity = MappingProxyType(_clone(identity))
        instance.__claimed = False
        instance.__lock = threading.Lock()
        state = {
            "host_inputs_sha256": str(identity["host_inputs_sha256"]),
            "sealed_private_input_tag": str(
                identity["sealed_private_input_tag"]
            ),
            "consumed": False,
            "issuer_pid": os.getpid(),
        }
        key = id(instance)

        def retire(reference: weakref.ReferenceType[Any]) -> None:
            with _HOST_INPUT_ISSUANCE_LOCK:
                current = _HOST_INPUT_ISSUED.get(key)
                if current is not None and current[0] is reference:
                    _HOST_INPUT_ISSUED.pop(key, None)

        reference = weakref.ref(instance, retire)
        with _HOST_INPUT_ISSUANCE_LOCK:
            _HOST_INPUT_ISSUED[key] = (reference, state)
        _register_host_input_one_shot(instance)
        return instance

    def __repr__(self) -> str:
        return (
            "<ClaudeRuntimeHostInputs opaque "
            f"host_inputs_sha256={self.__identity['host_inputs_sha256']}>"
        )

    def __reduce__(self) -> None:
        raise TypeError("ClaudeRuntimeHostInputs cannot be serialized")

    def __copy__(self) -> None:
        raise TypeError("ClaudeRuntimeHostInputs cannot be copied")

    def __deepcopy__(self, _memo: object) -> None:
        raise TypeError("ClaudeRuntimeHostInputs cannot be copied")

    @property
    def host_inputs_sha256(self) -> str:
        with _HOST_INPUT_ISSUANCE_LOCK:
            issued = _HOST_INPUT_ISSUED.get(id(self))
            if (
                issued is None
                or issued[0]() is not self
                or issued[1]["issuer_pid"] != os.getpid()
                or not isinstance(self.__identity, Mapping)
                or self.__identity.get("host_inputs_sha256")
                != issued[1]["host_inputs_sha256"]
                or self.__identity.get("sealed_private_input_tag")
                != issued[1]["sealed_private_input_tag"]
            ):
                raise ClaudeRuntimeMaterializationError(
                    "RUNTIME_HOST_INPUTS_DRIFTED",
                    "runtime host input authority drifted",
                )
            return str(issued[1]["host_inputs_sha256"])

    def _replay_provider_parent_inputs(
        self,
        *,
        expected_runtime_local_authority_sha256: str,
    ) -> dict[str, Any]:
        """Replay current private inputs for the provider-parent sink.

        The returned mapping is transient and must never be persisted.  Its
        purpose is to let the provider preparation layer compare actual host
        paths and environment denominators against the fully replayed parent.
        Registry membership alone is deliberately insufficient.
        """

        if (
            not isinstance(expected_runtime_local_authority_sha256, str)
            or _SHA256.fullmatch(
                expected_runtime_local_authority_sha256
            )
            is None
        ):
            raise ClaudeRuntimeMaterializationError(
                "RUNTIME_LOCAL_AUTHORITY_INVALID",
                "runtime-local provider parent authority is required",
            )
        with _HOST_INPUT_ISSUANCE_LOCK:
            issued = _HOST_INPUT_ISSUED.get(id(self))
            if (
                issued is None
                or issued[0]() is not self
                or issued[1]["issuer_pid"] != os.getpid()
                or issued[1]["consumed"]
                or not isinstance(self.__identity, Mapping)
                or self.__identity.get(
                    "runtime_local_authority_sha256"
                )
                != expected_runtime_local_authority_sha256
            ):
                raise ClaudeRuntimeMaterializationError(
                    "RUNTIME_HOST_INPUTS_DRIFTED",
                    "runtime host inputs lack the exact provider parent",
                )
            current = _private_input_bytes(
                auth_route=self.__auth_route,
                ambient_environment=self.__ambient_environment,
                source_config_dir=self.__source_config_dir,
                project_root=self.__project_root,
                trusted_cwds=self.__trusted_cwds,
            )
            actual_tag = hmac.digest(
                bytes(self.__integrity_key),
                current,
                "sha256",
            )
            if (
                not hmac.compare_digest(
                    actual_tag,
                    self.__integrity_tag,
                )
                or actual_tag.hex()
                != self.__identity.get("sealed_private_input_tag")
                or self.host_inputs_sha256
                != issued[1]["host_inputs_sha256"]
            ):
                raise ClaudeRuntimeMaterializationError(
                    "RUNTIME_HOST_INPUTS_DRIFTED",
                    "runtime host input authority drifted",
                )
            return {
                "ambient_environment": dict(
                    self.__ambient_environment
                ),
                "auth_route": self.__auth_route,
                "source_config_dir": self.__source_config_dir,
                "project_root": self.__project_root,
                "trusted_cwds": self.__trusted_cwds,
                "host_inputs_sha256": self.host_inputs_sha256,
                "runtime_local_authority_sha256": (
                    expected_runtime_local_authority_sha256
                ),
            }

    def _claim(self) -> dict[str, Any]:
        _consume_host_input_one_shot(self)
        with _HOST_INPUT_ISSUANCE_LOCK:
            issued = _HOST_INPUT_ISSUED.get(id(self))
            if (
                issued is None
                or issued[0]() is not self
                or issued[1]["issuer_pid"] != os.getpid()
                or issued[1]["consumed"]
            ):
                raise ClaudeRuntimeMaterializationError(
                    "RUNTIME_HOST_INPUTS_ALREADY_CLAIMED",
                    "runtime host inputs are already claimed",
                )
            current = _private_input_bytes(
                auth_route=self.__auth_route,
                ambient_environment=self.__ambient_environment,
                source_config_dir=self.__source_config_dir,
                project_root=self.__project_root,
                trusted_cwds=self.__trusted_cwds,
            )
            actual_tag = hmac.digest(
                bytes(self.__integrity_key),
                current,
                "sha256",
            )
            if not hmac.compare_digest(actual_tag, self.__integrity_tag):
                issued[1]["consumed"] = True
                _zeroize(self.__integrity_key)
                self.__integrity_key = bytearray()
                self.__integrity_tag = b""
                self.__ambient_environment = MappingProxyType({})
                self.__auth_route = ""
                self.__source_config_dir = None
                self.__project_root = None
                self.__trusted_cwds = ()
                self.__claimed = True
                raise ClaudeRuntimeMaterializationError(
                    "RUNTIME_HOST_INPUTS_DRIFTED",
                    "runtime host input authority drifted",
                )
            if (
                self.host_inputs_sha256
                != issued[1]["host_inputs_sha256"]
                or actual_tag.hex()
                != issued[1]["sealed_private_input_tag"]
            ):
                issued[1]["consumed"] = True
                raise ClaudeRuntimeMaterializationError(
                    "RUNTIME_HOST_INPUTS_DRIFTED",
                    "runtime host input authority drifted",
                )
            issued[1]["consumed"] = True
            claimed = {
                "ambient_environment": dict(
                    self.__ambient_environment
                ),
                "auth_route": self.__auth_route,
                "source_config_dir": self.__source_config_dir,
                "project_root": self.__project_root,
                "trusted_cwds": self.__trusted_cwds,
                "host_inputs_sha256": self.host_inputs_sha256,
            }
            _zeroize(self.__integrity_key)
            self.__integrity_key = bytearray()
            self.__integrity_tag = b""
            self.__ambient_environment = MappingProxyType({})
            self.__auth_route = ""
            self.__source_config_dir = None
            self.__project_root = None
            self.__trusted_cwds = ()
            self.__claimed = True
            return claimed


def compile_claude_runtime_host_inputs(
    *,
    auth_route: str,
    ambient_environment: Mapping[str, str],
    source_config_dir: str | Path | None,
    project_root: str | Path,
    trusted_cwds: Sequence[str | Path],
    runtime_local_authority_sha256: str | None = None,
) -> ClaudeRuntimeHostInputs:
    """Seal full ambient and host paths in one opaque one-shot capability."""

    if not isinstance(ambient_environment, Mapping):
        raise ClaudeRuntimeMaterializationError(
            "AMBIENT_ENVIRONMENT_INVALID",
            "ambient environment is malformed",
        )
    ambient = dict(ambient_environment)
    folded: list[str] = []
    for name, value in ambient.items():
        if (
            not isinstance(name, str)
            or not name
            or "=" in name
            or "\x00" in name
            or not isinstance(value, str)
            or "\x00" in value
        ):
            raise ClaudeRuntimeMaterializationError(
                "AMBIENT_ENVIRONMENT_INVALID",
                "ambient environment is malformed",
            )
        folded.append(name.casefold())
    if len(folded) != len(set(folded)):
        raise ClaudeRuntimeMaterializationError(
            "AMBIENT_ENVIRONMENT_AMBIGUOUS",
            "ambient environment is case-ambiguous",
        )
    if auth_route not in {
        "OAUTH_TOKEN",
        "STORED_SUBSCRIPTION_OAUTH",
    }:
        raise ClaudeRuntimeMaterializationError(
            "RUNTIME_HOST_AUTH_ROUTE_INVALID",
            "runtime host auth route is invalid",
        )
    if auth_route == "OAUTH_TOKEN":
        if source_config_dir is not None:
            raise ClaudeRuntimeMaterializationError(
                "OAUTH_HOST_SOURCE_CONFIG_FORBIDDEN",
                "OAuth-token host inputs forbid source config authority",
            )
        source = None
    else:
        if source_config_dir is None:
            raise ClaudeRuntimeMaterializationError(
                "STORED_HOST_SOURCE_CONFIG_REQUIRED",
                "stored-subscription host inputs require source config",
            )
        source = _canonical_directory(
            source_config_dir,
            label="Claude source config directory",
        )
    project = _canonical_directory(
        project_root,
        label="project root",
    )
    if (
        isinstance(trusted_cwds, (str, bytes))
        or not isinstance(trusted_cwds, Sequence)
        or not trusted_cwds
    ):
        raise ClaudeRuntimeMaterializationError(
            "TRUSTED_CWDS_INVALID",
            "trusted working directories are malformed",
        )
    trusted = tuple(
        _canonical_directory(
            value,
            label="trusted working directory",
        )
        for value in trusted_cwds
    )
    if len(trusted) != len(set(trusted)):
        raise ClaudeRuntimeMaterializationError(
            "TRUSTED_CWDS_AMBIGUOUS",
            "trusted working directories are duplicated",
        )
    if runtime_local_authority_sha256 is not None and (
        not isinstance(runtime_local_authority_sha256, str)
        or _SHA256.fullmatch(runtime_local_authority_sha256) is None
    ):
        raise ClaudeRuntimeMaterializationError(
            "RUNTIME_LOCAL_AUTHORITY_INVALID",
            "runtime-local authority digest is malformed",
        )
    key = bytearray(secrets.token_bytes(32))
    tag = hmac.digest(
        bytes(key),
        _private_input_bytes(
            auth_route=auth_route,
            ambient_environment=ambient,
            source_config_dir=source,
            project_root=project,
            trusted_cwds=trusted,
        ),
        "sha256",
    )
    core = {
        "schema": "plamen.claude_runtime_host_inputs.v1",
        "auth_route": auth_route,
        "host_inputs_instance_id": secrets.token_hex(16),
        "sealed_private_input_tag": tag.hex(),
        "ambient_key_set_sha256": (
            claude_runtime_environment_key_set_sha256(tuple(ambient))
        ),
        "trusted_cwd_count": len(trusted),
        "runtime_local_authority_sha256": (
            runtime_local_authority_sha256
        ),
        "credential_values_recorded": False,
        "credential_content_hashes_recorded": False,
        "host_paths_recorded": False,
    }
    identity = {**core, "host_inputs_sha256": _digest(core)}
    issuance_id = secrets.token_hex(32)
    pending = {
        "auth_route": auth_route,
        "ambient_environment": ambient,
        "source_config_dir": source,
        "project_root": project,
        "trusted_cwds": trusted,
        "integrity_key": key,
        "integrity_tag": tag,
        "identity": identity,
    }
    with _HOST_INPUT_ISSUANCE_LOCK:
        _HOST_INPUT_PENDING[issuance_id] = pending
    try:
        return ClaudeRuntimeHostInputs(
            _capability=_HOST_INPUT_CAPABILITY,
            auth_route=auth_route,
            ambient_environment=ambient,
            source_config_dir=source,
            project_root=project,
            trusted_cwds=trusted,
            integrity_key=key,
            integrity_tag=tag,
            identity=identity,
            _issuance_id=issuance_id,
        )
    finally:
        with _HOST_INPUT_ISSUANCE_LOCK:
            _HOST_INPUT_PENDING.pop(issuance_id, None)


def _one_option_value(argv: Sequence[str], option: str) -> str | None:
    positions = [
        index for index, value in enumerate(argv) if value == option
    ]
    if len(positions) != 1 or positions[0] + 1 >= len(argv):
        return None
    value = argv[positions[0] + 1]
    if value.startswith("-"):
        return None
    return value


def _installed_backend_front() -> str:
    """Resolve the sole installed public front accepted by WER."""

    leaf = "plamen.cmd" if os.name == "nt" else "plamen"
    return os.path.abspath(os.path.expanduser(f"~/.local/bin/{leaf}"))


def _compile_final_argv(
    base_argv: Sequence[str],
    *,
    request: Mapping[str, Any],
    policy: Mapping[str, Any],
) -> tuple[str, ...]:
    if (
        isinstance(base_argv, (str, bytes))
        or not isinstance(base_argv, Sequence)
    ):
        raise ClaudeRuntimeMaterializationError(
            "BASE_ARGV_INVALID",
            "outer materialized base argv is malformed",
        )
    argv = list(base_argv)
    if (
        not argv
        or any(
            not isinstance(value, str)
            or not value
            or "\x00" in value
            for value in argv
        )
    ):
        raise ClaudeRuntimeMaterializationError(
            "BASE_ARGV_INVALID",
            "outer materialized base argv is malformed",
        )
    observation = request["executable_observation"]
    executable = observation["resolved_executable"]
    runtime_selection = policy["mcp_authority"].get("runtime_selection")
    semantic_argv = argv
    if runtime_selection is not None:
        try:
            selected = _launch.replay_mcp_current_selection(
                runtime_selection
            )
        except ClaudeLaunchSecurityError as exc:
            raise ClaudeRuntimeMaterializationError(
                "BASE_ARGV_BACKEND_SELECTION_INVALID",
                "outer materialized backend selection does not replay",
            ) from exc
        front = _installed_backend_front()
        expected_prefix = [
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
        ]
        backend_authority = observation.get("backend_launch_authority")
        if (
            executable != front
            or argv[: len(expected_prefix)] != expected_prefix
            or len(argv) <= len(expected_prefix)
            or not isinstance(backend_authority, dict)
            or backend_authority.get("argv_prefix") != expected_prefix
            or backend_authority.get("selection_sha256")
            != _launch.mcp_current_selection_sha256(selected)
            or backend_authority.get("selected_backend")
            != selected["backend_launches"]["claude"]
        ):
            raise ClaudeRuntimeMaterializationError(
                "BASE_ARGV_BACKEND_AUTHORITY_MISMATCH",
                "outer materialized backend launch differs from signed generation",
            )
        semantic_argv = [front, *argv[len(expected_prefix) :]]
    if semantic_argv[0] != executable:
        raise ClaudeRuntimeMaterializationError(
            "BASE_ARGV_EXECUTABLE_MISMATCH",
            "outer materialized base argv executable drifted",
        )
    if "--" in semantic_argv:
        raise ClaudeRuntimeMaterializationError(
            "BASE_ARGV_ALIAS_REJECTED",
            "outer materialized base argv contains an option terminator",
        )
    if any(
        value == prefix or value.startswith(prefix + "=")
        for value in semantic_argv
        for prefix in _PROFILE_ARGV_PREFIXES
    ):
        raise ClaudeRuntimeMaterializationError(
            "BASE_ARGV_PROFILE_DENOMINATOR_PRESENT",
            "outer materialized base argv contains a second profile denominator",
        )
    if any(
        value in _FORBIDDEN_SESSION_FLAGS
        or any(
            value.startswith(prefix + "=")
            for prefix in (
                "--continue",
                "--resume",
                "--from-pr",
                "--fork-session",
                "--print",
            )
        )
        or (
            not value.startswith("--")
            and len(value) > 2
            and value[:2] in {"-p", "-r", "-c"}
        )
        for value in semantic_argv
    ):
        raise ClaudeRuntimeMaterializationError(
            "BASE_ARGV_SESSION_ALIAS_REJECTED",
            "outer materialized base argv enables an unsupported session form",
        )
    equals_options = [
        value
        for value in semantic_argv
        if value.startswith("-") and "=" in value
    ]
    if equals_options:
        raise ClaudeRuntimeMaterializationError(
            "BASE_ARGV_EQUALS_ALIAS_REJECTED",
            "outer materialized base argv uses an option alias",
        )
    if (
        semantic_argv.count("-p") != 1
        or semantic_argv.count("--verbose") != 1
        or semantic_argv.count("--no-session-persistence") != 1
        or _one_option_value(semantic_argv, "--output-format") != "stream-json"
    ):
        raise ClaudeRuntimeMaterializationError(
            "BASE_ARGV_STREAM_CONTRACT_INVALID",
            "outer materialized base argv is not canonical stream-json",
        )
    if semantic_argv.index("--model") != semantic_argv.index("-p") + 1:
        raise ClaudeRuntimeMaterializationError(
            "BASE_ARGV_POSITIONAL_PROMPT_REJECTED",
            "outer materialized base argv must receive its prompt only via stdin",
        )
    model = _one_option_value(semantic_argv, "--model")
    accepted_models = policy["headless_profile"][
        "expected_init_contract"
    ]["accepted_models"]
    if model not in accepted_models:
        raise ClaudeRuntimeMaterializationError(
            "BASE_ARGV_MODEL_MISMATCH",
            "outer materialized base argv model is outside WorkPlan authority",
        )
    session_id = _one_option_value(semantic_argv, "--session-id")
    try:
        canonical_session = str(uuid.UUID(str(session_id)))
    except (ValueError, TypeError, AttributeError) as exc:
        raise ClaudeRuntimeMaterializationError(
            "BASE_ARGV_SESSION_INVALID",
            "outer materialized base argv session is not canonical",
        ) from exc
    if session_id != canonical_session:
        raise ClaudeRuntimeMaterializationError(
            "BASE_ARGV_SESSION_INVALID",
            "outer materialized base argv session is not canonical",
        )
    critical = (
        "-p",
        "--model",
        "--output-format",
        "--verbose",
        "--session-id",
        "--no-session-persistence",
    )
    if any(semantic_argv.count(flag) != 1 for flag in critical):
        raise ClaudeRuntimeMaterializationError(
            "BASE_ARGV_CRITICAL_DUPLICATE",
            "outer materialized base argv duplicates a critical option",
        )
    positions = [semantic_argv.index(flag) for flag in critical]
    if positions != sorted(positions):
        raise ClaudeRuntimeMaterializationError(
            "BASE_ARGV_ORDER_INVALID",
            "outer materialized base argv critical order is not canonical",
        )
    profile_flags = list(policy["headless_profile"]["cli_flags"])
    return tuple([*argv, *profile_flags])


class ClaudeRuntimeMaterializationRequest:
    """Opaque, one-shot local request from WorkerTransaction to WER."""

    __slots__ = (
        "__ambient_environment",
        "__auth_route",
        "__auxiliary_reservation",
        "__base_argv",
        "__claimed",
        "__discard_receipt",
        "__identity",
        "__integrity_key",
        "__integrity_tag",
        "__launch_security_request",
        "__lock",
        "__project_root",
        "__provider_runtime_parent",
        "__scratchpad",
        "__source_config_dir",
        "__startup_permit_binding",
        "__trusted_cwds",
        "__values",
        "__weakref__",
    )

    def __new__(
        cls,
        *,
        _capability: object,
        values: Mapping[str, str],
        launch_security_request: Mapping[str, Any],
        auth_route: str,
        ambient_environment: Mapping[str, str],
        base_argv: Sequence[str],
        scratchpad: Path,
        startup_permit_binding: Mapping[str, Any],
        project_root: Path,
        trusted_cwds: Sequence[Path],
        source_config_dir: Path | None,
        provider_runtime_parent: tuple[Any, ...] | None,
        auxiliary_reservation: (
            _aux.AuxiliaryWritableRootReservation | None
        ),
        integrity_key: bytearray,
        integrity_tag: bytes,
        identity: Mapping[str, Any],
        _issuance_id: str | None = None,
    ) -> ClaudeRuntimeMaterializationRequest:
        if (
            cls is not ClaudeRuntimeMaterializationRequest
            or _capability is not _REQUEST_CAPABILITY
            or not isinstance(_issuance_id, str)
        ):
            raise TypeError(
                "ClaudeRuntimeMaterializationRequest is opaque"
            )
        with _REQUEST_ISSUANCE_LOCK:
            pending = _REQUEST_PENDING.pop(_issuance_id, None)
        if (
            pending is None
            or pending["values"] != dict(values)
            or pending["launch_security_request"]
            != _clone(launch_security_request)
            or pending["auth_route"] != auth_route
            or pending["ambient_environment"]
            != dict(ambient_environment)
            or pending["base_argv"] != tuple(base_argv)
            or pending["scratchpad"] != scratchpad
            or pending["startup_permit_binding"]
            != _clone(startup_permit_binding)
            or pending["project_root"] != project_root
            or pending["trusted_cwds"] != tuple(trusted_cwds)
            or pending["source_config_dir"] != source_config_dir
            or pending["provider_runtime_parent"]
            is not provider_runtime_parent
            or pending["auxiliary_reservation"]
            is not auxiliary_reservation
            or pending["integrity_key"] is not integrity_key
            or pending["integrity_tag"] != integrity_tag
            or pending["identity"] != _clone(identity)
        ):
            raise TypeError(
                "ClaudeRuntimeMaterializationRequest requires validator issuance"
            )
        instance = super().__new__(cls)
        instance.__values = MappingProxyType(dict(values))
        instance.__launch_security_request = MappingProxyType(
            _clone(launch_security_request)
        )
        instance.__auth_route = auth_route
        instance.__ambient_environment = MappingProxyType(
            dict(ambient_environment)
        )
        instance.__base_argv = tuple(base_argv)
        instance.__scratchpad = scratchpad
        instance.__startup_permit_binding = MappingProxyType(
            _clone(startup_permit_binding)
        )
        instance.__project_root = project_root
        instance.__trusted_cwds = tuple(trusted_cwds)
        instance.__source_config_dir = source_config_dir
        instance.__provider_runtime_parent = provider_runtime_parent
        instance.__auxiliary_reservation = auxiliary_reservation
        instance.__integrity_key = integrity_key
        instance.__integrity_tag = bytes(integrity_tag)
        instance.__identity = MappingProxyType(_clone(identity))
        instance.__claimed = False
        instance.__discard_receipt = None
        instance.__lock = threading.Lock()
        state = {
            "request_sha256": str(identity["request_sha256"]),
            "sealed_private_input_tag": str(
                identity["sealed_private_input_tag"]
            ),
            "claimed": False,
            "transition": None,
            "discard_receipt": None,
            "failure_reason_code": None,
            "failure_reason_message": None,
            "issuer_pid": os.getpid(),
        }
        key = id(instance)

        def retire(reference: weakref.ReferenceType[Any]) -> None:
            with _REQUEST_ISSUANCE_LOCK:
                current = _REQUEST_ISSUED.get(key)
                if current is not None and current[0] is reference:
                    _REQUEST_ISSUED.pop(key, None)

        reference = weakref.ref(instance, retire)
        with _REQUEST_ISSUANCE_LOCK:
            _REQUEST_ISSUED[key] = (reference, state)
        _register_request_parent(
            instance,
            identity.get("provider_preparation_sha256"),
            identity.get("provider_attachment_sha256"),
            provider_runtime_parent,
        )
        return instance

    def __repr__(self) -> str:
        return (
            "<ClaudeRuntimeMaterializationRequest opaque "
            f"request_sha256={self.__identity['request_sha256']}>"
        )

    def __reduce__(self) -> None:
        raise TypeError(
            "ClaudeRuntimeMaterializationRequest cannot be serialized"
        )

    def __copy__(self) -> None:
        raise TypeError(
            "ClaudeRuntimeMaterializationRequest cannot be copied"
        )

    def __deepcopy__(self, _memo: object) -> None:
        raise TypeError(
            "ClaudeRuntimeMaterializationRequest cannot be copied"
        )

    @property
    def request_sha256(self) -> str:
        with _REQUEST_ISSUANCE_LOCK:
            issued = _REQUEST_ISSUED.get(id(self))
            if (
                issued is None
                or issued[0]() is not self
                or issued[1]["issuer_pid"] != os.getpid()
                or not isinstance(self.__identity, Mapping)
                or self.__identity.get("request_sha256")
                != issued[1]["request_sha256"]
                or self.__identity.get("sealed_private_input_tag")
                != issued[1]["sealed_private_input_tag"]
            ):
                raise ClaudeRuntimeMaterializationError(
                    "RUNTIME_REQUEST_PRIVATE_INPUT_DRIFT",
                    "runtime request identity authority drifted",
                )
            return str(issued[1]["request_sha256"])

    def __erase_private_inputs(self) -> None:
        _zeroize(self.__integrity_key)
        self.__integrity_key = bytearray()
        self.__integrity_tag = b""
        self.__values = MappingProxyType({})
        self.__launch_security_request = MappingProxyType({})
        self.__auth_route = ""
        self.__ambient_environment = MappingProxyType({})
        self.__base_argv = ()
        self.__scratchpad = None
        self.__startup_permit_binding = MappingProxyType({})
        self.__project_root = None
        self.__trusted_cwds = ()
        self.__source_config_dir = None
        self.__provider_runtime_parent = None
        self.__auxiliary_reservation = None

    def __retire_provider_replay_host(
        self,
        parent: tuple[Any, ...] | None,
        _claim_exact_host=ClaudeRuntimeHostInputs._claim,
    ) -> None:
        """Consume the captured replay host without holding request locks.

        Provider-parent replay deliberately accepts an opaque host delegate.
        Its final claim is therefore an external call.  The request transition
        must already be CLAIMING/DISCARDING so reentry rejects immediately,
        while this call itself remains outside both request and issuance
        locks.
        """

        if parent is None:
            return
        replay_host = parent[1]
        try:
            if type(replay_host) is ClaudeRuntimeHostInputs:
                dynamic_claim = ClaudeRuntimeHostInputs._claim
                if dynamic_claim is not _claim_exact_host:
                    dynamic_failure: Exception | None = None
                    try:
                        dynamic_claim(replay_host)
                    except Exception as exc:
                        dynamic_failure = exc
                    # The definition-time primitive still consumes the exact
                    # issuance-owned host.  A patched dispatch can therefore
                    # neither leave it reusable nor turn the request into a
                    # success, regardless of whether the patch returned or
                    # raised.
                    try:
                        _claim_exact_host(replay_host)
                    except Exception as exc:
                        if dynamic_failure is None:
                            dynamic_failure = exc
                    raise ClaudeRuntimeMaterializationError(
                        "RUNTIME_PROVIDER_PARENT_REPLAY_FAILED",
                        "runtime request provider replay-host primitive drifted",
                    ) from dynamic_failure
                _claim_exact_host(replay_host)
                return
            # A host-like delegate is never eligible for successful
            # retirement.  Invoke it only while the request transition is
            # active and no request/global locks are held, so a frozen
            # adversarial reentry probe reaches a typed rejection rather than
            # a deadlock; even a no-op delegate is rejected below.
            replay_host._claim()
        except Exception as exc:
            raise ClaudeRuntimeMaterializationError(
                "RUNTIME_PROVIDER_PARENT_REPLAY_FAILED",
                "runtime request provider replay host could not be retired",
            ) from exc
        raise ClaudeRuntimeMaterializationError(
            "RUNTIME_PROVIDER_PARENT_REPLAY_FAILED",
            "runtime request provider replay host type is not exact",
        )

    def __capture_issuance_owned_parent(
        self,
        *,
        slot_parent: tuple[Any, ...] | None,
        transition: str,
    ) -> tuple[str | None, str | None, tuple[Any, ...] | None]:
        """Resolve the TCB-ledger parent before invoking any parent object.

        The request slot is reflected Python state and may be substituted
        without changing installed code.  On drift, consume the original
        issuance-owned replay host and terminalize the request; never invoke
        an attacker-supplied slot host as the retirement authority.
        """

        try:
            preparation, attachment, canonical = (
                _canonical_request_parent(self)
            )
        except BaseException:
            self.__fail_transition(transition, terminal=True)
            raise
        if slot_parent is canonical:
            return preparation, attachment, canonical
        self.__terminalize_parent_slot_drift(
            canonical_parent=canonical,
            transition=transition,
        )
        raise AssertionError("unreachable parent-slot drift return")

    def __terminalize_parent_slot_drift(
        self,
        *,
        canonical_parent: tuple[Any, ...] | None,
        transition: str,
    ) -> None:
        """Retire issuance authority and make reflected slot drift terminal."""

        retirement_failure: BaseException | None = None
        try:
            self.__retire_provider_replay_host(canonical_parent)
        except BaseException as exc:
            retirement_failure = exc
        finally:
            self.__fail_transition(
                transition,
                terminal=True,
                reason_code="RUNTIME_PROVIDER_PARENT_DRIFT",
                reason_message=(
                    "runtime request provider parent differs from "
                    "issuance authority"
                ),
            )
        raise ClaudeRuntimeMaterializationError(
            "RUNTIME_PROVIDER_PARENT_DRIFT",
            "runtime request provider parent differs from issuance authority",
        ) from retirement_failure

    def __fail_transition(
        self,
        expected: str,
        *,
        terminal: bool,
        reason_code: str | None = None,
        reason_message: str | None = None,
    ) -> None:
        """Resolve one still-current transition after an external failure."""

        if (reason_code is None) != (reason_message is None):
            raise TypeError(
                "terminal transition reason must be wholly specified"
            )
        if not terminal and reason_code is not None:
            raise TypeError(
                "retryable transition cannot retain a terminal reason"
            )
        with self.__lock:
            with _REQUEST_ISSUANCE_LOCK:
                issued = _REQUEST_ISSUED.get(id(self))
                if (
                    issued is None
                    or issued[0]() is not self
                    or issued[1]["issuer_pid"] != os.getpid()
                    or issued[1]["claimed"]
                    or issued[1]["transition"] != expected
                ):
                    return
                if terminal:
                    issued[1]["claimed"] = True
                    issued[1]["transition"] = "FAILED"
                    issued[1]["failure_reason_code"] = reason_code
                    issued[1]["failure_reason_message"] = reason_message
                    self.__erase_private_inputs()
                    self.__claimed = True
                else:
                    issued[1]["transition"] = None

    def __replay_provider_parent(
        self,
        parent: tuple[Any, ...],
    ) -> tuple[str, str]:
        if type(parent) is not tuple or len(parent) != 5:
            raise ClaudeRuntimeMaterializationError(
                "RUNTIME_PROVIDER_PARENT_REPLAY_FAILED",
                "runtime request provider parent does not replay",
            )
        (
            package,
            replay_host,
            settings,
            mcp,
            attachment_sha256,
        ) = parent
        try:
            import claude_provider_preparation as provider

            replayed = provider.replay_claude_provider_runtime_parent(
                package,
                host_inputs=replay_host,
                bound_settings_bytes=settings,
                selected_mcp_config_bytes=mcp,
            )
            record = replayed.record
        except Exception as exc:
            raise ClaudeRuntimeMaterializationError(
                "RUNTIME_PROVIDER_PARENT_REPLAY_FAILED",
                "runtime request provider parent does not replay",
            ) from exc
        final_argv = _compile_final_argv(
            self.__base_argv,
            request=self.__launch_security_request,
            policy=self.__launch_security_request["policy"],
        )
        template = tuple(record["command_template"])
        if (
            record["launch_security_request"]
            != dict(self.__launch_security_request)
            or record["startup_authority_sha256"]
            != _digest(dict(self.__startup_permit_binding))
            or record["semantic_intent"]["run_id"]
            != self.__values["run_id"]
            or len(template) != len(final_argv)
            or tuple(template) != tuple(final_argv)
            or not isinstance(attachment_sha256, str)
            or _SHA256.fullmatch(attachment_sha256) is None
        ):
            raise ClaudeRuntimeMaterializationError(
                "RUNTIME_PROVIDER_PARENT_DRIFT",
                "runtime request differs from the exact provider parent",
            )
        return replayed.preparation_sha256, attachment_sha256

    def __provider_parent_identity(
        self,
        parent: tuple[Any, ...] | None = None,
    ) -> tuple[str | None, str | None]:
        if parent is None:
            return None, None
        try:
            return parent[0].preparation_sha256, parent[4]
        except (AttributeError, IndexError, TypeError) as exc:
            raise ClaudeRuntimeMaterializationError(
                "RUNTIME_REQUEST_PRIVATE_INPUT_DRIFT",
                "runtime request provider parent is malformed",
            ) from exc

    def discard(self) -> dict[str, Any]:
        """Erase an unclaimed request that WER will not materialize."""

        with self.__lock:
            with _REQUEST_ISSUANCE_LOCK:
                issued = _REQUEST_ISSUED.get(id(self))
                if (
                    issued is None
                    or issued[0]() is not self
                    or issued[1]["issuer_pid"] != os.getpid()
                ):
                    raise ClaudeRuntimeMaterializationError(
                        "RUNTIME_REQUEST_PRIVATE_INPUT_DRIFT",
                        "runtime request was not validator-issued",
                    )
                state = issued[1]
                if state["discard_receipt"] is not None:
                    return _clone(state["discard_receipt"])
                if state["claimed"] or self.__claimed:
                    if (
                        state.get("transition") == "FAILED"
                        and isinstance(
                            state.get("failure_reason_code"),
                            str,
                        )
                        and isinstance(
                            state.get("failure_reason_message"),
                            str,
                        )
                    ):
                        raise ClaudeRuntimeMaterializationError(
                            state["failure_reason_code"],
                            state["failure_reason_message"],
                        )
                    raise ClaudeRuntimeMaterializationError(
                        "RUNTIME_REQUEST_DISCARD_FORBIDDEN",
                        "claimed runtime request cannot be relabeled discarded",
                    )
                if state["transition"] is not None:
                    raise ClaudeRuntimeMaterializationError(
                        "RUNTIME_REQUEST_TRANSITION_IN_PROGRESS",
                        "runtime request already has an active transition",
                    )
                slot_parent = self.__provider_runtime_parent
                state["transition"] = "DISCARDING"
        try:
            (
                parent_preparation,
                parent_attachment,
                parent,
            ) = self.__capture_issuance_owned_parent(
                slot_parent=slot_parent,
                transition="DISCARDING",
            )
            if parent is not None:
                replayed_preparation, replayed_attachment = (
                    self.__replay_provider_parent(parent)
                )
                if (
                    replayed_preparation != parent_preparation
                    or replayed_attachment != parent_attachment
                ):
                    raise ClaudeRuntimeMaterializationError(
                        "RUNTIME_PROVIDER_PARENT_DRIFT",
                        "runtime request provider parent changed during discard",
                    )
                if self.__provider_runtime_parent is not parent:
                    self.__terminalize_parent_slot_drift(
                        canonical_parent=parent,
                        transition="DISCARDING",
                    )
        except BaseException:
            self.__fail_transition("DISCARDING", terminal=False)
            raise
        try:
            self.__retire_provider_replay_host(parent)
        except BaseException:
            self.__fail_transition("DISCARDING", terminal=True)
            raise
        with self.__lock:
            with _REQUEST_ISSUANCE_LOCK:
                issued = _REQUEST_ISSUED.get(id(self))
                if (
                    issued is None
                    or issued[0]() is not self
                    or issued[1]["issuer_pid"] != os.getpid()
                ):
                    raise ClaudeRuntimeMaterializationError(
                        "RUNTIME_REQUEST_PRIVATE_INPUT_DRIFT",
                        "runtime request was not validator-issued",
                    )
                state = issued[1]
                if (
                    state["claimed"]
                    or self.__claimed
                    or state["transition"] != "DISCARDING"
                ):
                    raise ClaudeRuntimeMaterializationError(
                        "RUNTIME_REQUEST_DISCARD_FORBIDDEN",
                        "runtime request changed during discard",
                    )
                if self.__provider_runtime_parent is not parent:
                    state["claimed"] = True
                    state["transition"] = "FAILED"
                    state["failure_reason_code"] = (
                        "RUNTIME_PROVIDER_PARENT_DRIFT"
                    )
                    state["failure_reason_message"] = (
                        "runtime request provider parent changed during discard"
                    )
                    self.__erase_private_inputs()
                    self.__claimed = True
                    raise ClaudeRuntimeMaterializationError(
                        "RUNTIME_PROVIDER_PARENT_DRIFT",
                        "runtime request provider parent changed during discard",
                    )
                try:
                    _consume_request_parent(
                        self,
                        parent_preparation,
                        parent_attachment,
                        parent,
                    )
                except BaseException:
                    state["claimed"] = True
                    state["transition"] = "FAILED"
                    self.__erase_private_inputs()
                    self.__claimed = True
                    raise
                state["claimed"] = True
                state["transition"] = "DISCARDED"
                self.__erase_private_inputs()
                self.__claimed = True
                core = {
                    "schema": RUNTIME_MATERIALIZATION_REQUEST_DISCARD_SCHEMA,
                    "runtime_request_sha256": self.request_sha256,
                    "discarded": True,
                    "credential_values_recorded": False,
                    "credential_content_hashes_recorded": False,
                    "host_paths_recorded": False,
                }
                receipt = replay_claude_runtime_request_discard_receipt(
                    {**core, "receipt_sha256": _digest(core)}
                )
                self.__discard_receipt = MappingProxyType(receipt)
                state["discard_receipt"] = MappingProxyType(receipt)
                return _clone(receipt)

    def _claim(
        self,
        *,
        require_provider_parent: bool = False,
    ) -> dict[str, Any]:
        if type(require_provider_parent) is not bool:
            raise ClaudeRuntimeMaterializationError(
                "RUNTIME_PROVIDER_PARENT_REQUIRED",
                "provider-parent requirement is malformed",
            )
        # Establish the transition while holding only internal locks, then
        # release them before reading or replaying the provider parent.  A
        # forged property/replayer can therefore reenter, but the nested
        # claim/discard observes CLAIMING and rejects instead of deadlocking
        # or consuming the request twice.
        with self.__lock:
            with _REQUEST_ISSUANCE_LOCK:
                initial = _REQUEST_ISSUED.get(id(self))
                if (
                    initial is None
                    or initial[0]() is not self
                    or initial[1]["issuer_pid"] != os.getpid()
                ):
                    raise ClaudeRuntimeMaterializationError(
                        "RUNTIME_REQUEST_PRIVATE_INPUT_DRIFT",
                        "runtime request was not validator-issued",
                    )
                if initial[1]["claimed"] or self.__claimed:
                    raise ClaudeRuntimeMaterializationError(
                        "RUNTIME_REQUEST_ALREADY_CLAIMED",
                        "runtime materialization request is already claimed",
                    )
                if initial[1]["transition"] is not None:
                    raise ClaudeRuntimeMaterializationError(
                        "RUNTIME_REQUEST_TRANSITION_IN_PROGRESS",
                        "runtime request already has an active transition",
                    )
                slot_parent = self.__provider_runtime_parent
                initial[1]["transition"] = "CLAIMING"
        try:
            (
                parent_preparation,
                parent_attachment,
                parent,
            ) = self.__capture_issuance_owned_parent(
                slot_parent=slot_parent,
                transition="CLAIMING",
            )
            if require_provider_parent and parent is None:
                # A genuinely unbound legacy fixture request has no canonical
                # provider host to retire.  Reject the production sink while
                # leaving the request eligible for explicit discard.  A
                # provider-bound request whose mutable slot was cleared was
                # already terminalized by __capture_issuance_owned_parent.
                self.__fail_transition("CLAIMING", terminal=False)
                raise ClaudeRuntimeMaterializationError(
                    "RUNTIME_PROVIDER_PARENT_REQUIRED",
                    "exact claimed provider runtime is required",
                )
            if parent is not None:
                replayed_preparation, replayed_attachment = (
                    self.__replay_provider_parent(parent)
                )
                if (
                    replayed_preparation != parent_preparation
                    or replayed_attachment != parent_attachment
                ):
                    raise ClaudeRuntimeMaterializationError(
                        "RUNTIME_PROVIDER_PARENT_DRIFT",
                        "runtime request provider parent changed during replay",
                    )
                if self.__provider_runtime_parent is not parent:
                    self.__terminalize_parent_slot_drift(
                        canonical_parent=parent,
                        transition="CLAIMING",
                    )
        except BaseException:
            self.__fail_transition("CLAIMING", terminal=False)
            raise
        try:
            self.__retire_provider_replay_host(parent)
        except BaseException:
            self.__fail_transition("CLAIMING", terminal=True)
            raise
        with self.__lock:
            with _REQUEST_ISSUANCE_LOCK:
                issued = _REQUEST_ISSUED.get(id(self))
                if (
                    issued is None
                    or issued[0]() is not self
                    or issued[1]["issuer_pid"] != os.getpid()
                ):
                    raise ClaudeRuntimeMaterializationError(
                        "RUNTIME_REQUEST_PRIVATE_INPUT_DRIFT",
                        "runtime request was not validator-issued",
                    )
                state = issued[1]
                if (
                    state["claimed"]
                    or self.__claimed
                    or state["transition"] != "CLAIMING"
                ):
                    raise ClaudeRuntimeMaterializationError(
                        "RUNTIME_REQUEST_ALREADY_CLAIMED",
                        "runtime materialization request is already claimed",
                    )
                if self.__provider_runtime_parent is not parent:
                    state["claimed"] = True
                    state["transition"] = "FAILED"
                    state["failure_reason_code"] = (
                        "RUNTIME_PROVIDER_PARENT_DRIFT"
                    )
                    state["failure_reason_message"] = (
                        "runtime request provider parent changed during replay"
                    )
                    self.__erase_private_inputs()
                    self.__claimed = True
                    raise ClaudeRuntimeMaterializationError(
                        "RUNTIME_PROVIDER_PARENT_DRIFT",
                        "runtime request provider parent changed during replay",
                    )
                current = _private_input_bytes(
                    auth_route=self.__auth_route,
                    ambient_environment=self.__ambient_environment,
                    source_config_dir=self.__source_config_dir,
                    project_root=self.__project_root,
                    trusted_cwds=self.__trusted_cwds,
                    scratchpad=self.__scratchpad,
                )
                actual_tag = hmac.digest(
                    bytes(self.__integrity_key),
                    current,
                    "sha256",
                )
                if not hmac.compare_digest(
                    actual_tag, self.__integrity_tag
                ):
                    state["claimed"] = True
                    state["transition"] = "FAILED"
                    self.__erase_private_inputs()
                    self.__claimed = True
                    raise ClaudeRuntimeMaterializationError(
                        "RUNTIME_REQUEST_PRIVATE_INPUT_DRIFT",
                        "runtime materialization private input authority drifted",
                    )
                if (
                    self.request_sha256 != state["request_sha256"]
                    or actual_tag.hex()
                    != state["sealed_private_input_tag"]
                ):
                    state["claimed"] = True
                    state["transition"] = "FAILED"
                    self.__erase_private_inputs()
                    self.__claimed = True
                    raise ClaudeRuntimeMaterializationError(
                        "RUNTIME_REQUEST_PRIVATE_INPUT_DRIFT",
                        "runtime materialization private input authority drifted",
                    )
                bound_settings_bytes = (
                    None if parent is None else parent[2]
                )
                selected_mcp_config_bytes = (
                    None if parent is None else parent[3]
                )
                try:
                    _consume_request_parent(
                        self,
                        parent_preparation,
                        parent_attachment,
                        parent,
                    )
                except BaseException:
                    state["claimed"] = True
                    state["transition"] = "FAILED"
                    self.__erase_private_inputs()
                    self.__claimed = True
                    raise
                claimed = {
                    **dict(self.__values),
                    "launch_security_request": dict(
                        self.__launch_security_request
                    ),
                    "ambient_environment": dict(
                        self.__ambient_environment
                    ),
                    "base_argv": self.__base_argv,
                    "scratchpad": self.__scratchpad,
                    "startup_permit_binding": dict(
                        self.__startup_permit_binding
                    ),
                    "project_root": self.__project_root,
                    "trusted_cwds": self.__trusted_cwds,
                    "source_config_dir": self.__source_config_dir,
                    "auxiliary_reservation": self.__auxiliary_reservation,
                    "runtime_request_sha256": self.request_sha256,
                    "bound_settings_bytes": bound_settings_bytes,
                    "selected_mcp_config_bytes": (
                        selected_mcp_config_bytes
                    ),
                }
                state["claimed"] = True
                state["transition"] = "CLAIMED"
                self.__erase_private_inputs()
                self.__claimed = True
                return claimed


def replay_claude_runtime_request_discard_receipt(
    value: Mapping[str, Any],
) -> dict[str, Any]:
    """Replay proof that an unused opaque request was erased."""

    candidate = _clone(value)
    expected = {
        "schema",
        "runtime_request_sha256",
        "discarded",
        "credential_values_recorded",
        "credential_content_hashes_recorded",
        "host_paths_recorded",
        "receipt_sha256",
    }
    core = dict(candidate)
    digest = core.pop("receipt_sha256", None)
    if (
        set(candidate) != expected
        or candidate.get("schema")
        != RUNTIME_MATERIALIZATION_REQUEST_DISCARD_SCHEMA
        or not isinstance(
            candidate.get("runtime_request_sha256"),
            str,
        )
        or _SHA256.fullmatch(
            candidate["runtime_request_sha256"]
        )
        is None
        or candidate.get("discarded") is not True
        or candidate.get("credential_values_recorded") is not False
        or candidate.get("credential_content_hashes_recorded")
        is not False
        or candidate.get("host_paths_recorded") is not False
        or not isinstance(digest, str)
        or _SHA256.fullmatch(digest) is None
        or digest != _digest(core)
    ):
        raise ClaudeRuntimeMaterializationError(
            "RUNTIME_REQUEST_DISCARD_RECEIPT_INVALID",
            "runtime request discard receipt does not replay",
        )
    return candidate


def _compile_claude_runtime_materialization_request(
    *,
    launch_security_request: Mapping[str, Any],
    host_inputs: ClaudeRuntimeHostInputs | None = None,
    provider_runtime: Any | None = None,
    base_argv: Sequence[str],
    scratchpad: str | Path,
    startup_permit_binding: Mapping[str, Any],
    run_id: str,
    outer_attempt_arm_sha256: str,
    work_plan_sha256: str,
    attempt_id: str,
    process_scope_identity: str,
    auxiliary_reservation: (
        _aux.AuxiliaryWritableRootReservation | None
    ) = None,
) -> ClaudeRuntimeMaterializationRequest:
    """Internal compiler shared by the provider and isolated legacy fixtures."""

    request, policy = _first_lane_policy(launch_security_request)
    run = _required_id(run_id, label="run_id")
    attempt = _required_id(attempt_id, label="attempt_id")
    scope = _required_id(
        process_scope_identity,
        label="process_scope_identity",
    )
    arm = _required_sha256(
        outer_attempt_arm_sha256,
        label="outer AttemptArm digest",
    )
    plan = _required_sha256(
        work_plan_sha256,
        label="WorkPlan digest",
    )
    provider_claim: dict[str, Any] | None = None
    if provider_runtime is not None:
        if host_inputs is not None:
            raise ClaudeRuntimeMaterializationError(
                "RUNTIME_PROVIDER_INPUT_AMBIGUOUS",
                "provider runtime and raw host inputs cannot be combined",
            )
        try:
            import claude_provider_preparation as provider

            provider_claim = (
                provider.consume_claimed_claude_provider_runtime(
                    provider_runtime
                )
            )
        except Exception as exc:
            raise ClaudeRuntimeMaterializationError(
                "RUNTIME_PROVIDER_PARENT_REPLAY_FAILED",
                "claimed provider runtime does not replay",
            ) from exc
        host_inputs = provider_claim["host_inputs"]
    if type(host_inputs) is not ClaudeRuntimeHostInputs:
        raise ClaudeRuntimeMaterializationError(
            "RUNTIME_HOST_INPUTS_TYPE_INVALID",
            "opaque runtime host inputs are required",
        )
    final_argv = _compile_final_argv(
        base_argv,
        request=request,
        policy=policy,
    )
    if provider_claim is not None:
        package = provider_claim["provider_preparation"]
        record = package.record
        template = tuple(record["command_template"])
        if (
            record["launch_security_request"] != request
            or record["startup_authority_sha256"]
            != _digest(_clone(startup_permit_binding))
            or record["semantic_intent"]["run_id"] != run
            or len(template) != len(final_argv)
            or tuple(template) != tuple(final_argv)
        ):
            raise ClaudeRuntimeMaterializationError(
                "RUNTIME_PROVIDER_PARENT_DRIFT",
                "runtime request differs from the exact provider parent",
            )
    scratch = _canonical_directory(
        scratchpad,
        label="scratchpad",
    )
    private_inputs = host_inputs._claim()
    selected_auth_route = policy["auth_route_policy"]["desired_route"]
    if private_inputs["auth_route"] != selected_auth_route:
        raise ClaudeRuntimeMaterializationError(
            "RUNTIME_HOST_AUTH_ROUTE_MISMATCH",
            "runtime host auth route differs from launch authority",
        )
    ambient_environment = private_inputs["ambient_environment"]
    source_config_dir = private_inputs["source_config_dir"]
    project_root = private_inputs["project_root"]
    trusted_cwds = private_inputs["trusted_cwds"]
    provider_runtime_parent: tuple[Any, ...] | None = None
    if provider_claim is not None:
        runtime_policy = provider_claim[
            "runtime_host_policy_sha256"
        ]
        replay_host = compile_claude_runtime_host_inputs(
            auth_route=private_inputs["auth_route"],
            ambient_environment=ambient_environment,
            source_config_dir=source_config_dir,
            project_root=project_root,
            trusted_cwds=trusted_cwds,
            runtime_local_authority_sha256=runtime_policy,
        )
        provider_runtime_parent = (
            provider_claim["provider_preparation"],
            replay_host,
            provider_claim["bound_settings_bytes"],
            provider_claim["selected_mcp_config_bytes"],
            provider_claim["attachment_sha256"],
        )
    reservation_sha256 = None
    if auxiliary_reservation is not None:
        checked = _reservation(
            auxiliary_reservation,
            attempt_id=attempt,
        )
        reservation_sha256 = checked.binding["reservation_sha256"]
    identity_core = {
        "schema": RUNTIME_MATERIALIZATION_REQUEST_SCHEMA,
        "request_instance_id": secrets.token_hex(16),
        "host_inputs_sha256": private_inputs["host_inputs_sha256"],
        "launch_security_request_sha256": request["request_sha256"],
        "startup_permit_sha256": _digest(
            _clone(startup_permit_binding)
        ),
        "outer_attempt_arm_sha256": arm,
        "work_plan_sha256": plan,
        "attempt_id": attempt,
        "process_scope_identity": scope,
        "base_argv_sha256": _argv_sha256(base_argv),
        "ambient_key_set_sha256": (
            claude_runtime_environment_key_set_sha256(
                tuple(ambient_environment)
            )
        ),
        "auxiliary_reservation_sha256": reservation_sha256,
        "provider_preparation_sha256": (
            None
            if provider_claim is None
            else provider_claim["provider_preparation"].preparation_sha256
        ),
        "provider_attachment_sha256": (
            None
            if provider_claim is None
            else provider_claim["attachment_sha256"]
        ),
        "credential_values_recorded": False,
        "credential_content_hashes_recorded": False,
        "host_paths_recorded": False,
    }
    integrity_key = bytearray(secrets.token_bytes(32))
    integrity_tag = hmac.digest(
        bytes(integrity_key),
        _private_input_bytes(
            auth_route=selected_auth_route,
            ambient_environment=ambient_environment,
            source_config_dir=source_config_dir,
            project_root=project_root,
            trusted_cwds=trusted_cwds,
            scratchpad=scratch,
        ),
        "sha256",
    )
    identity = {
        **identity_core,
        "sealed_private_input_tag": integrity_tag.hex(),
        "request_sha256": _digest(identity_core),
    }
    identity["request_sha256"] = _digest(
        {
            key: value
            for key, value in identity.items()
            if key != "request_sha256"
        }
    )
    request_values = {
        "run_id": run,
        "outer_attempt_arm_sha256": arm,
        "work_plan_sha256": plan,
        "attempt_id": attempt,
        "process_scope_identity": scope,
    }
    issuance_id = secrets.token_hex(32)
    pending = {
        "values": request_values,
        "launch_security_request": _clone(request),
        "auth_route": selected_auth_route,
        "ambient_environment": dict(ambient_environment),
        "base_argv": tuple(base_argv),
        "scratchpad": scratch,
        "startup_permit_binding": _clone(
            startup_permit_binding
        ),
        "project_root": project_root,
        "trusted_cwds": tuple(trusted_cwds),
        "source_config_dir": source_config_dir,
        "provider_runtime_parent": provider_runtime_parent,
        "auxiliary_reservation": auxiliary_reservation,
        "integrity_key": integrity_key,
        "integrity_tag": integrity_tag,
        "identity": _clone(identity),
    }
    with _REQUEST_ISSUANCE_LOCK:
        _REQUEST_PENDING[issuance_id] = pending
    try:
        return ClaudeRuntimeMaterializationRequest(
            _capability=_REQUEST_CAPABILITY,
            values=request_values,
            launch_security_request=request,
            auth_route=selected_auth_route,
            ambient_environment=dict(ambient_environment),
            base_argv=tuple(base_argv),
            scratchpad=scratch,
            startup_permit_binding=startup_permit_binding,
            project_root=project_root,
            trusted_cwds=trusted_cwds,
            source_config_dir=source_config_dir,
            provider_runtime_parent=provider_runtime_parent,
            auxiliary_reservation=auxiliary_reservation,
            integrity_key=integrity_key,
            integrity_tag=integrity_tag,
            identity=identity,
            _issuance_id=issuance_id,
        )
    finally:
        with _REQUEST_ISSUANCE_LOCK:
            _REQUEST_PENDING.pop(issuance_id, None)


def compile_claude_runtime_materialization_request(
    *,
    launch_security_request: Mapping[str, Any],
    provider_runtime: Any | None = None,
    host_inputs: ClaudeRuntimeHostInputs | None = None,
    base_argv: Sequence[str],
    scratchpad: str | Path,
    startup_permit_binding: Mapping[str, Any],
    run_id: str,
    outer_attempt_arm_sha256: str,
    work_plan_sha256: str,
    attempt_id: str,
    process_scope_identity: str,
    auxiliary_reservation: (
        _aux.AuxiliaryWritableRootReservation | None
    ) = None,
) -> ClaudeRuntimeMaterializationRequest:
    """Compile the production request from one replayed provider parent.

    Raw host inputs remain available only to this module's isolated legacy
    fixture compiler.  Production callers cannot downgrade out of canonical
    provider-parent replay.
    """

    if provider_runtime is None or host_inputs is not None:
        raise ClaudeRuntimeMaterializationError(
            "RUNTIME_PROVIDER_PARENT_REQUIRED",
            "exact claimed provider runtime is required",
        )
    return _compile_claude_runtime_materialization_request(
        launch_security_request=launch_security_request,
        provider_runtime=provider_runtime,
        base_argv=base_argv,
        scratchpad=scratchpad,
        startup_permit_binding=startup_permit_binding,
        run_id=run_id,
        outer_attempt_arm_sha256=outer_attempt_arm_sha256,
        work_plan_sha256=work_plan_sha256,
        attempt_id=attempt_id,
        process_scope_identity=process_scope_identity,
        auxiliary_reservation=auxiliary_reservation,
    )


def _first_lane_policy(
    launch_security_request: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    try:
        request = _launch.replay_claude_launch_security_request(
            launch_security_request
        )
    except (ClaudeLaunchSecurityError, TypeError) as exc:
        raise ClaudeRuntimeMaterializationError(
            "LAUNCH_SECURITY_REQUEST_INVALID",
            "launch-security request does not replay",
        ) from exc
    policy = request["policy"]
    headless = policy["headless_profile"]
    auth = policy["auth_route_policy"]
    endpoint = auth["endpoint_policy"]
    settings = policy["settings_authority"]
    mcp = policy["mcp_authority"]
    settings_mode = settings["mode"]
    supported_settings_lane = (
        (
            settings_mode == "SAFE_MODE"
            and headless["customization_mode"] == "SAFE_MODE"
            and settings["settings_sha256"] is None
            and settings["external_policy_sha256"] is None
            and mcp["server_names"] == []
            and mcp["source_manifest_sha256"] is None
            and mcp["selected_config_sha256"] is None
        )
        or (
            settings_mode == "BOUND_SETTINGS"
            and headless["customization_mode"] == "BOUND_SETTINGS"
            and _SHA256.fullmatch(settings["settings_sha256"])
            is not None
            and _SHA256.fullmatch(settings["external_policy_sha256"])
            is not None
            and _SHA256.fullmatch(mcp["selected_config_sha256"])
            is not None
            and (
                bool(mcp["server_names"])
                == (mcp["source_manifest_sha256"] is not None)
            )
        )
    )
    supported_lane = (
        auth["desired_route"]
        in {"OAUTH_TOKEN", "STORED_SUBSCRIPTION_OAUTH"}
        and supported_settings_lane
        and _SHA256.fullmatch(settings["authority_sha256"]) is not None
        and _SHA256.fullmatch(mcp["authority_sha256"]) is not None
        and endpoint["endpoint_mode"] == "OFFICIAL_DEFAULT"
        and endpoint["endpoint_environment"] == {}
        and policy["home_variable_policy"] == "PRESERVE_TOOLCHAIN_HOME"
        and policy["functional_controls"].get(
            "CLAUDE_CODE_SUBPROCESS_ENV_SCRUB"
        )
        == "1"
    )
    if not supported_lane:
        raise ClaudeRuntimeMaterializationError(
            "UNSUPPORTED_RUNTIME_LANE",
            "launch-security request is outside reviewed runtime lanes",
        )
    return request, policy


def _replay_startup(
    *,
    scratchpad: Path,
    run_id: str,
    startup_permit_binding: Mapping[str, Any],
) -> dict[str, Any]:
    try:
        replay = replay_startup_permit_binding(
            scratchpad=scratchpad,
            expected_run_id=run_id,
            binding=startup_permit_binding,
        )
    except (
        AuxiliaryWritableRootStartupError,
        OSError,
        TypeError,
        ValueError,
    ) as exc:
        raise ClaudeRuntimeMaterializationError(
            "STARTUP_PERMIT_INVALID",
            "startup permit does not replay",
        ) from exc
    binding = replay.get("binding")
    if not isinstance(binding, dict):
        raise ClaudeRuntimeMaterializationError(
            "STARTUP_PERMIT_INVALID",
            "startup permit does not replay",
        )
    return _clone(binding)


def _reservation(
    supplied: _aux.AuxiliaryWritableRootReservation | None,
    *,
    attempt_id: str,
) -> _aux.AuxiliaryWritableRootReservation:
    reservation = supplied
    if reservation is None:
        try:
            reservation = _aux.reserve_auxiliary_writable_root(
                attempt_id=attempt_id,
                purpose=AUXILIARY_PURPOSE,
            )
        except _aux.AuxiliaryWritableRootLeaseError as exc:
            raise ClaudeRuntimeMaterializationError(
                "AUXILIARY_RESERVATION_FAILED",
                "auxiliary reservation could not be created",
            ) from exc
    if type(reservation) is not _aux.AuxiliaryWritableRootReservation:
        raise ClaudeRuntimeMaterializationError(
            "AUXILIARY_RESERVATION_INVALID",
            "auxiliary reservation is invalid",
        )
    binding = reservation.binding
    if (
        binding.get("attempt_id") != attempt_id
        or binding.get("purpose") != AUXILIARY_PURPOSE
        or binding.get("root_visibility") != "WITHHELD_UNTIL_ARM"
        or binding.get("caller_supplied_path") is not False
        or reservation._armed is not False
    ):
        raise ClaudeRuntimeMaterializationError(
            "AUXILIARY_RESERVATION_SUBSTITUTED",
            "auxiliary reservation does not match the attempt",
        )
    return reservation


def _planned_key_denominator(
    *,
    ambient_environment: Mapping[str, str],
    policy: Mapping[str, Any],
) -> None:
    auth = policy["auth_route_policy"]
    endpoint_names = tuple(
        auth["endpoint_policy"]["endpoint_environment"]
    )
    try:
        actual = (
            _child.planned_claude_child_environment_key_set_sha256(
                ambient=ambient_environment,
                selected_route=auth["desired_route"],
                endpoint_environment_names=endpoint_names,
                phase_environment_policies=policy[
                    "phase_environment_policies"
                ],
                functional_control_names=tuple(
                    policy["functional_controls"]
                ),
                home_variable_policy=policy[
                    "home_variable_policy"
                ],
            )
        )
    except (ClaudeChildEnvironmentError, TypeError) as exc:
        raise ClaudeRuntimeMaterializationError(
            "CHILD_KEY_DENOMINATOR_INVALID",
            "child environment key denominator is invalid",
        ) from exc
    if actual != policy["expected_child_environment_key_set_sha256"]:
        raise ClaudeRuntimeMaterializationError(
            "CHILD_KEY_DENOMINATOR_MISMATCH",
            "child environment key denominator differs from WorkPlan",
        )


def _auth_environment(
    *,
    ambient_environment: Mapping[str, str],
    policy: Mapping[str, Any],
    source_evidence: Mapping[str, Any],
) -> tuple[dict[str, str], dict[str, Any], dict[str, Any]]:
    auth_policy = policy["auth_route_policy"]
    try:
        observation = _auth.observe_claude_auth_sources(
            ambient_environment,
            settings={},
            settings_authority_sha256=None,
            stored_subscription_evidence=source_evidence,
        )
        environment, receipt = _auth.compile_claude_auth_environment(
            ambient_environment,
            desired_route=auth_policy["desired_route"],
            source_observation=observation,
            claude_code_version=policy["claude_code_version"],
            endpoint_policy=auth_policy["endpoint_policy"],
        )
        _auth.reconcile_claude_auth_environment(
            environment,
            receipt,
            source_observation=observation,
        )
    except (ClaudeAuthRouteError, TypeError) as exc:
        raise ClaudeRuntimeMaterializationError(
            "AUTH_ENVIRONMENT_INVALID",
            "stored subscription source did not yield one auth route",
        ) from exc
    return environment, receipt, observation


def replay_claude_runtime_materialization_receipt(
    value: Mapping[str, Any],
) -> dict[str, Any]:
    """Replay the durable redacted runtime receipt without live paths."""

    expected_fields = {
        "schema",
        "runtime_request_sha256",
        "launch_security_request_sha256",
        "launch_security_policy_sha256",
        "startup_permit_sha256",
        "outer_attempt_arm_sha256",
        "work_plan_sha256",
        "attempt_id",
        "process_scope_identity",
        "auxiliary_lease_binding_sha256",
        "attempt_profile_sha256",
        "selected_auth_route",
        "credential_materialization_mode",
        "source_observation_sha256",
        "source_materialization_receipt_sha256",
        "auth_environment_receipt_sha256",
        "settings_authority_sha256",
        "mcp_authority_sha256",
        "base_argv_sha256",
        "final_argv_sha256",
        "final_argv_count",
        "child_environment_receipt_sha256",
        "expected_child_environment_key_set_sha256",
        "refresh_continuity_authority",
        "completion_capable",
        "precedence_environment_denials",
        "credential_values_recorded",
        "credential_content_hashes_recorded",
        "host_paths_recorded",
        "receipt_sha256",
    }
    candidate = _clone(value)
    if set(candidate) != expected_fields:
        raise ClaudeRuntimeMaterializationError(
            "RUNTIME_RECEIPT_FIELDS_DRIFTED",
            "Claude runtime materialization receipt fields drifted",
        )
    core = dict(candidate)
    digest = core.pop("receipt_sha256", None)
    sha_fields = expected_fields - {
        "schema",
        "attempt_id",
        "process_scope_identity",
        "selected_auth_route",
        "credential_materialization_mode",
        "source_materialization_receipt_sha256",
        "final_argv_count",
        "refresh_continuity_authority",
        "completion_capable",
        "precedence_environment_denials",
        "credential_values_recorded",
        "credential_content_hashes_recorded",
        "host_paths_recorded",
        "receipt_sha256",
    }
    if (
        candidate.get("schema") != RUNTIME_MATERIALIZATION_SCHEMA
        or any(
            not isinstance(candidate.get(name), str)
            or _SHA256.fullmatch(candidate[name]) is None
            for name in sha_fields
        )
        or not isinstance(candidate.get("attempt_id"), str)
        or _SAFE_ID.fullmatch(candidate["attempt_id"]) is None
        or not isinstance(
            candidate.get("process_scope_identity"),
            str,
        )
        or _SAFE_ID.fullmatch(
            candidate["process_scope_identity"]
        )
        is None
        or isinstance(candidate.get("final_argv_count"), bool)
        or not isinstance(candidate.get("final_argv_count"), int)
        or candidate["final_argv_count"] <= 0
        or candidate.get("selected_auth_route")
        not in {"OAUTH_TOKEN", "STORED_SUBSCRIPTION_OAUTH"}
        or (
            candidate.get("selected_auth_route") == "OAUTH_TOKEN"
            and (
                candidate.get("credential_materialization_mode")
                != "ENVIRONMENT_OAUTH_TOKEN"
                or candidate.get(
                    "source_materialization_receipt_sha256"
                )
                is not None
                or candidate.get("refresh_continuity_authority")
                != "ENVIRONMENT_OAUTH_TOKEN_NO_WRITEBACK"
                or candidate.get("completion_capable") is not True
            )
        )
        or (
            candidate.get("selected_auth_route")
            == "STORED_SUBSCRIPTION_OAUTH"
            and (
                candidate.get("credential_materialization_mode")
                != "COPIED_STORED_SUBSCRIPTION"
                or not isinstance(
                    candidate.get(
                        "source_materialization_receipt_sha256"
                    ),
                    str,
                )
                or _SHA256.fullmatch(
                    candidate[
                        "source_materialization_receipt_sha256"
                    ]
                )
                is None
                or candidate.get("refresh_continuity_authority")
                != "UNPROVEN_PRIVATE_COPY_NO_WRITEBACK"
                or candidate.get("completion_capable") is not False
            )
        )
        or candidate.get("precedence_environment_denials")
        != sorted(_CLAUDE_PRECEDENCE_ENVIRONMENT_DENIALS)
        or candidate.get("credential_values_recorded") is not False
        or candidate.get("credential_content_hashes_recorded")
        is not False
        or candidate.get("host_paths_recorded") is not False
        or not isinstance(digest, str)
        or _SHA256.fullmatch(digest) is None
        or digest != _digest(core)
    ):
        raise ClaudeRuntimeMaterializationError(
            "RUNTIME_RECEIPT_INVALID",
            "Claude runtime materialization receipt does not replay",
        )
    return candidate


def replay_claude_runtime_lifecycle_receipt(
    value: Mapping[str, Any],
) -> dict[str, Any]:
    """Replay a redacted bind, abort, normal, or emergency lifecycle step."""

    candidate = _clone(value)
    common = {
        "schema",
        "runtime_materialization_sha256",
        "process_scope_identity",
        "closure_mode",
        "profile_first_cleanup",
        "completion_authority",
        "emergency_zero_population",
        "credential_values_recorded",
        "credential_content_hashes_recorded",
        "host_paths_recorded",
        "receipt_sha256",
    }
    terminal_step_fields = {
        "profile_revocation_receipt_sha256",
        "auxiliary_revocation_receipt_sha256",
    }
    debt_fields = {
        "recovery_required",
        "profile_retained",
        "auxiliary_root_retained",
        "process_zero_proven",
        "emergency_close_observed",
    }
    mode = candidate.get("closure_mode")
    if mode == "SCOPE_BOUND":
        expected_fields = common
    elif mode in {
        "BOUND_SCOPE_PRELAUNCH_ABORT",
        "PROCESS_ATTACH_FAILURE_CLEANUP",
    }:
        expected_fields = common | terminal_step_fields | {
            "reason_code"
        }
    elif mode == "NORMAL_SCOPE_FAILURE_CLEANUP":
        expected_fields = common | terminal_step_fields | {
            "reason_code",
            "primary_failure_evidence_sha256",
        }
    elif mode == "PROCESS_ATTACH_FAILURE_UNPROVEN_DEBT":
        expected_fields = common | {
            "reason_code",
            "recovery_required",
            "profile_retained",
            "auxiliary_root_retained",
            "process_zero_proven",
            "created_process_termination_proven",
        }
    elif mode in {
        "EMERGENCY_ZERO_UNPROVEN_DEBT",
        "EMERGENCY_CLOSE_FAILED_DEBT",
    }:
        expected_fields = common | debt_fields
    else:
        expected_fields = common | terminal_step_fields
    if set(candidate) != expected_fields:
        raise ClaudeRuntimeMaterializationError(
            "RUNTIME_LIFECYCLE_FIELDS_DRIFTED",
            "Claude runtime lifecycle receipt fields drifted",
        )
    core = dict(candidate)
    digest = core.pop("receipt_sha256", None)
    expected_flags = {
        "SCOPE_BOUND": (False, False),
        "PRELAUNCH_ABORT": (False, False),
        "BOUND_SCOPE_PRELAUNCH_ABORT": (False, False),
        "PROCESS_ATTACH_FAILURE_CLEANUP": (False, False),
        "PROCESS_ATTACH_FAILURE_UNPROVEN_DEBT": (False, False),
        "NORMAL_SCOPE_FAILURE_CLEANUP": (False, False),
        "NORMAL_COMPLETION": (True, False),
        "NORMAL_SCOPE_CLEANUP_NO_REFRESH_CONTINUITY": (False, False),
        "EMERGENCY_ZERO_POPULATION_CLEANUP": (False, True),
        "EMERGENCY_ZERO_UNPROVEN_DEBT": (False, False),
        "EMERGENCY_CLOSE_FAILED_DEBT": (False, False),
    }
    flags = expected_flags.get(mode)
    debt_mode = mode in {
        "EMERGENCY_ZERO_UNPROVEN_DEBT",
        "EMERGENCY_CLOSE_FAILED_DEBT",
        "PROCESS_ATTACH_FAILURE_UNPROVEN_DEBT",
    }
    attach_failure_mode = mode in {
        "PROCESS_ATTACH_FAILURE_CLEANUP",
        "PROCESS_ATTACH_FAILURE_UNPROVEN_DEBT",
    }
    if (
        candidate.get("schema")
        != RUNTIME_MATERIALIZATION_LIFECYCLE_SCHEMA
        or not isinstance(
            candidate.get("runtime_materialization_sha256"),
            str,
        )
        or _SHA256.fullmatch(
            candidate["runtime_materialization_sha256"]
        )
        is None
        or not isinstance(
            candidate.get("process_scope_identity"),
            str,
        )
        or _SAFE_ID.fullmatch(
            candidate["process_scope_identity"]
        )
        is None
        or flags is None
        or candidate.get("profile_first_cleanup")
        is not (not debt_mode)
        or candidate.get("completion_authority") is not flags[0]
        or candidate.get("emergency_zero_population") is not flags[1]
        or candidate.get("credential_values_recorded") is not False
        or candidate.get("credential_content_hashes_recorded")
        is not False
        or candidate.get("host_paths_recorded") is not False
        or (
            mode in {
                "BOUND_SCOPE_PRELAUNCH_ABORT",
                "PROCESS_ATTACH_FAILURE_CLEANUP",
                "PROCESS_ATTACH_FAILURE_UNPROVEN_DEBT",
                "NORMAL_SCOPE_FAILURE_CLEANUP",
            }
            and (
                not isinstance(candidate.get("reason_code"), str)
                or _SAFE_ID.fullmatch(candidate["reason_code"])
                is None
            )
        )
        or (
            mode == "NORMAL_SCOPE_FAILURE_CLEANUP"
            and (
                not isinstance(
                    candidate.get("primary_failure_evidence_sha256"),
                    str,
                )
                or _SHA256.fullmatch(
                    candidate["primary_failure_evidence_sha256"]
                )
                is None
            )
        )
        or any(
            not isinstance(candidate.get(name), str)
            or _SHA256.fullmatch(candidate[name]) is None
            for name in terminal_step_fields
            if mode not in {
                "SCOPE_BOUND",
                "EMERGENCY_ZERO_UNPROVEN_DEBT",
                "EMERGENCY_CLOSE_FAILED_DEBT",
                "PROCESS_ATTACH_FAILURE_UNPROVEN_DEBT",
            }
        )
        or (
            mode == "PROCESS_ATTACH_FAILURE_UNPROVEN_DEBT"
            and (
                candidate.get("recovery_required") is not True
                or candidate.get("profile_retained") is not True
                or candidate.get("auxiliary_root_retained") is not True
                or not isinstance(
                    candidate.get("process_zero_proven"),
                    bool,
                )
                or not isinstance(
                    candidate.get(
                        "created_process_termination_proven"
                    ),
                    bool,
                )
                or (
                    candidate.get("process_zero_proven") is True
                    and candidate.get(
                        "created_process_termination_proven"
                    )
                    is True
                )
            )
        )
        or (
            debt_mode
            and not attach_failure_mode
            and (
                candidate.get("recovery_required") is not True
                or candidate.get("profile_retained") is not True
                or candidate.get("auxiliary_root_retained") is not True
                or candidate.get("process_zero_proven") is not False
                or not isinstance(
                    candidate.get("emergency_close_observed"),
                    bool,
                )
                or (
                    mode == "EMERGENCY_ZERO_UNPROVEN_DEBT"
                    and candidate.get("emergency_close_observed")
                    is not True
                )
                or (
                    mode == "EMERGENCY_CLOSE_FAILED_DEBT"
                    and candidate.get("emergency_close_observed")
                    is not False
                )
            )
        )
        or not isinstance(digest, str)
        or _SHA256.fullmatch(digest) is None
        or digest != _digest(core)
    ):
        raise ClaudeRuntimeMaterializationError(
            "RUNTIME_LIFECYCLE_RECEIPT_INVALID",
            "Claude runtime lifecycle receipt does not replay",
        )
    return candidate


def reconcile_claude_runtime_persisted_authority(
    runtime_receipt: Mapping[str, Any],
    redacted_receipts: Mapping[str, Any],
    *,
    base_argv: Sequence[str],
    final_argv: Sequence[str],
    environment_names: Sequence[str],
) -> dict[str, Any]:
    """Pure replay of the durable WER runtime authority denominator."""

    receipt = replay_claude_runtime_materialization_receipt(
        runtime_receipt
    )
    redacted = _clone(redacted_receipts)
    expected_redacted = {
        "source_evidence",
        "source_materialization",
        "auth_source_observation",
        "auth_environment",
        "child_environment",
    }
    if set(redacted) != expected_redacted:
        raise ClaudeRuntimeMaterializationError(
            "RUNTIME_REDACTED_RECEIPTS_DRIFTED",
            "runtime redacted receipt denominator drifted",
        )
    try:
        source_evidence = (
            _stored.replay_stored_subscription_source_observation(
                redacted["source_evidence"]
            )
        )
        if receipt["selected_auth_route"] == "OAUTH_TOKEN":
            if redacted["source_materialization"] is not None:
                raise ClaudeRuntimeMaterializationError(
                    "RUNTIME_REDACTED_RECEIPT_INVALID",
                    "OAuth-token runtime gained a credential copy",
                )
            source_materialization = None
        else:
            source_materialization = (
                _stored.replay_stored_subscription_materialization_receipt(
                    redacted["source_materialization"]
                )
            )
        source_observation = (
            _auth.replay_claude_auth_source_observation(
                redacted["auth_source_observation"]
            )
        )
        auth_environment = _auth.replay_claude_auth_environment(
            redacted["auth_environment"]
        )
        child_environment = (
            _child.replay_claude_child_environment_receipt(
                redacted["child_environment"]
            )
        )
    except (
        ClaudeStoredSubscriptionSourceError,
        ClaudeAuthRouteError,
        ClaudeChildEnvironmentError,
        TypeError,
    ) as exc:
        raise ClaudeRuntimeMaterializationError(
            "RUNTIME_REDACTED_RECEIPT_INVALID",
            "runtime redacted receipt does not replay",
        ) from exc
    base_digest = claude_runtime_argv_sha256(base_argv)
    final_digest = claude_runtime_argv_sha256(final_argv)
    environment_digest = (
        claude_runtime_environment_key_set_sha256(environment_names)
    )
    if (
        (
            source_materialization is not None
            and source_materialization.get("source_evidence")
            != source_evidence
        )
        or source_observation.get("stored_subscription_evidence")
        != source_evidence
        or source_observation.get("receipt_sha256")
        != receipt["source_observation_sha256"]
        or (
            None
            if source_materialization is None
            else source_materialization.get("receipt_sha256")
        )
        != receipt["source_materialization_receipt_sha256"]
        or auth_environment.get("source_observation_sha256")
        != source_observation["receipt_sha256"]
        or auth_environment.get("selected_route")
        != receipt["selected_auth_route"]
        or auth_environment.get("receipt_sha256")
        != receipt["auth_environment_receipt_sha256"]
        or child_environment.get("source_observation_sha256")
        != source_observation["receipt_sha256"]
        or child_environment.get("auth_environment_receipt_sha256")
        != auth_environment["receipt_sha256"]
        or child_environment.get("selected_route")
        != receipt["selected_auth_route"]
        or child_environment.get("receipt_sha256")
        != receipt["child_environment_receipt_sha256"]
        or child_environment.get("final_environment_key_set_sha256")
        != receipt["expected_child_environment_key_set_sha256"]
        or base_digest != receipt["base_argv_sha256"]
        or final_digest != receipt["final_argv_sha256"]
        or len(final_argv) != receipt["final_argv_count"]
        or environment_digest
        != receipt["expected_child_environment_key_set_sha256"]
    ):
        raise ClaudeRuntimeMaterializationError(
            "RUNTIME_PERSISTED_AUTHORITY_MISMATCH",
            "runtime persisted authority denominator drifted",
        )
    aggregate_core = {
        "runtime_materialization_sha256": receipt["receipt_sha256"],
        "source_observation_sha256": source_observation[
            "receipt_sha256"
        ],
        "source_materialization_receipt_sha256": (
            None
            if source_materialization is None
            else source_materialization["receipt_sha256"]
        ),
        "auth_environment_receipt_sha256": auth_environment[
            "receipt_sha256"
        ],
        "child_environment_receipt_sha256": child_environment[
            "receipt_sha256"
        ],
        "base_argv_sha256": base_digest,
        "final_argv_sha256": final_digest,
        "final_environment_key_set_sha256": environment_digest,
    }
    return {
        "valid": True,
        "reason": "RUNTIME_PERSISTED_AUTHORITY_RECONCILED",
        "runtime_materialization_sha256": receipt["receipt_sha256"],
        "aggregate_sha256": _digest(aggregate_core),
    }


def replay_claude_runtime_postprocess_receipt(
    value: Mapping[str, Any],
) -> dict[str, Any]:
    """Replay the redacted post-process structural reconciliation."""

    candidate = _clone(value)
    expected = {
        "schema",
        "runtime_materialization_sha256",
        "process_scope_identity",
        "attempt_profile_sha256",
        "child_environment_receipt_sha256",
        "selected_auth_route",
        "process_closed",
        "process_zero_proven",
        "process_attached",
        "worker_credential_refresh_authority",
        "current_attempt_credential_copy_status",
        "credential_values_recorded",
        "credential_content_hashes_recorded",
        "host_paths_recorded",
        "receipt_sha256",
    }
    core = dict(candidate)
    digest = core.pop("receipt_sha256", None)
    if (
        set(candidate) != expected
        or candidate.get("schema")
        != RUNTIME_POSTPROCESS_RECONCILIATION_SCHEMA
        or any(
            not isinstance(candidate.get(name), str)
            or _SHA256.fullmatch(candidate[name]) is None
            for name in (
                "runtime_materialization_sha256",
                "attempt_profile_sha256",
                "child_environment_receipt_sha256",
            )
        )
        or not isinstance(
            candidate.get("process_scope_identity"),
            str,
        )
        or _SAFE_ID.fullmatch(
            candidate["process_scope_identity"]
        )
        is None
        or candidate.get("process_closed") is not True
        or candidate.get("process_zero_proven") is not True
        or candidate.get("process_attached") is not True
        or candidate.get("selected_auth_route")
        not in {"OAUTH_TOKEN", "STORED_SUBSCRIPTION_OAUTH"}
        or candidate.get("worker_credential_refresh_authority")
        != (
            "NONE_ACCESS_ONLY_ENVIRONMENT_TOKEN"
            if candidate.get("selected_auth_route") == "OAUTH_TOKEN"
            else "NONE_UNPROVEN_PRIVATE_COPY_NO_WRITEBACK"
        )
        or (
            candidate.get("selected_auth_route") == "OAUTH_TOKEN"
            and candidate.get(
                "current_attempt_credential_copy_status"
            )
            != "NOT_APPLICABLE_ENVIRONMENT_TOKEN"
        )
        or (
            candidate.get("selected_auth_route")
            == "STORED_SUBSCRIPTION_OAUTH"
            and candidate.get(
                "current_attempt_credential_copy_status"
            )
            not in {
                "ORIGINAL_PRIVATE_COPY_UNCHANGED",
                # Replay receipts minted before discard-only completion was
                # separated from refresh-continuity authority.
                "PRIVATE_COPY_CHANGED_OR_REPLACED",
                _profile._PRIVATE_COPY_MUTATION_DISCARD_ONLY,
            }
        )
        or candidate.get("credential_values_recorded") is not False
        or candidate.get("credential_content_hashes_recorded")
        is not False
        or candidate.get("host_paths_recorded") is not False
        or not isinstance(digest, str)
        or _SHA256.fullmatch(digest) is None
        or digest != _digest(core)
    ):
        raise ClaudeRuntimeMaterializationError(
            "RUNTIME_POSTPROCESS_RECEIPT_INVALID",
            "runtime post-process receipt does not replay",
        )
    return candidate


@dataclass
class ClaudeRuntimeMaterialization:
    """Opaque live runtime material.  It is never a durable JSON object."""

    _construction_capability: object = field(repr=False)
    _profile: ClaudeAttemptProfile = field(repr=False)
    _lease: _aux.AuxiliaryWritableRootLease = field(repr=False)
    _compiled_child_environment: CompiledClaudeChildEnvironment = field(
        repr=False
    )
    _child_environment_names: tuple[str, ...] = field(repr=False)
    _base_argv: tuple[str, ...] = field(repr=False)
    _headless_profile_cli_flags: tuple[str, ...] = field(repr=False)
    _runtime_authority_cli_flags: tuple[str, ...] = field(repr=False)
    _bound_settings_file: _ClaudeRuntimeAuthorityFile | None = field(
        repr=False
    )
    _selected_mcp_config_file: _ClaudeRuntimeAuthorityFile | None = field(
        repr=False
    )
    _expected_mcp_servers: tuple[str, ...] = field(repr=False)
    _final_argv: tuple[str, ...] = field(repr=False)
    _receipt: Mapping[str, Any] = field(repr=False)
    _redacted_receipts: Mapping[str, Any] = field(repr=False)
    _outer_attempt_arm_sha256: str = field(repr=False)
    _process_scope_identity: str = field(repr=False)
    _lifecycle_state: str = field(
        default="MATERIALIZED_UNBOUND",
        repr=False,
    )
    _lifecycle_receipt: Mapping[str, Any] | None = field(
        default=None,
        repr=False,
    )
    _postprocess_receipt: Mapping[str, Any] | None = field(
        default=None,
        repr=False,
    )
    _pending_profile_receipt: Mapping[str, Any] | None = field(
        default=None,
        repr=False,
    )
    _pending_auxiliary_token: object | None = field(
        default=None,
        repr=False,
    )
    _pending_auxiliary_receipt: Mapping[str, Any] | None = field(
        default=None,
        repr=False,
    )
    _pending_expected_emergency: bool | None = field(
        default=None,
        repr=False,
    )
    _pending_failure_reason_code: str | None = field(
        default=None,
        repr=False,
    )
    _pending_primary_failure_evidence_sha256: str | None = field(
        default=None,
        repr=False,
    )
    _lifecycle_lock: threading.RLock = field(
        default_factory=threading.RLock,
        repr=False,
    )

    def __post_init__(self) -> None:
        if self._construction_capability is not _RESULT_CAPABILITY:
            raise TypeError("ClaudeRuntimeMaterialization is opaque")
        if (
            type(self._profile) is not ClaudeAttemptProfile
            or type(self._lease) is not _aux.AuxiliaryWritableRootLease
            or type(self._compiled_child_environment)
            is not CompiledClaudeChildEnvironment
            or (
                self._bound_settings_file is not None
                and type(self._bound_settings_file)
                is not _ClaudeRuntimeAuthorityFile
            )
            or (
                self._selected_mcp_config_file is not None
                and type(self._selected_mcp_config_file)
                is not _ClaudeRuntimeAuthorityFile
            )
        ):
            raise TypeError(
                "ClaudeRuntimeMaterialization authority is invalid"
            )

    @property
    def receipt(self) -> dict[str, Any]:
        return _clone(self._receipt)

    @property
    def redacted_receipts(self) -> dict[str, Any]:
        return _clone(self._redacted_receipts)

    @property
    def final_argv(self) -> tuple[str, ...]:
        return tuple(self._final_argv)

    def replay_bound_settings_bytes(self) -> bytes | None:
        """Replay and return the exact authenticated private settings bytes."""

        record = self._bound_settings_file
        if record is None:
            return None
        _replay_runtime_authority_file(record, label="bound settings")
        return bytes(record.exact_bytes)

    @property
    def process_writable_root(self) -> Path:
        """Local-only root to include in the exact OwnedProcessScope."""

        return self._lease.root

    @property
    def compiled_child_environment(self) -> CompiledClaudeChildEnvironment:
        """Return the already-compiled authority; callers cannot replace it."""

        return self._compiled_child_environment

    def invalidate_child_environment_after_process_attach(
        self,
        scope: object,
    ) -> None:
        """Drop parent-side credential values after exact process attach."""

        with self._lifecycle_lock:
            if (
                self._lifecycle_state != "SCOPE_BOUND"
                or getattr(scope, "persistent_identity", None)
                != self._process_scope_identity
                or getattr(scope, "attached", None) is not True
            ):
                raise ClaudeRuntimeMaterializationError(
                    "RUNTIME_CHILD_ENV_INVALIDATION_FORBIDDEN",
                    "child environment invalidation lacks attach authority",
                )
            if self._compiled_child_environment.active:
                _child.reconcile_claude_child_environment(
                    self._compiled_child_environment
                )
                self._compiled_child_environment._invalidate_private_values()

    @property
    def lifecycle_receipt(self) -> dict[str, Any] | None:
        if self._lifecycle_receipt is None:
            return None
        return replay_claude_runtime_lifecycle_receipt(
            self._lifecycle_receipt
        )

    @property
    def postprocess_receipt(self) -> dict[str, Any] | None:
        if self._postprocess_receipt is None:
            return None
        return replay_claude_runtime_postprocess_receipt(
            self._postprocess_receipt
        )

    def __repr__(self) -> str:
        return (
            "ClaudeRuntimeMaterialization("
            f"receipt_sha256={self.receipt.get('receipt_sha256')!r})"
        )

    def __reduce__(self) -> None:
        raise TypeError("ClaudeRuntimeMaterialization cannot be serialized")

    def _zeroize_runtime_authority_sources(self) -> None:
        """Erase retained exact bytes once profile deletion is authoritative."""

        _zeroize_runtime_authority_file(self._bound_settings_file)
        _zeroize_runtime_authority_file(
            self._selected_mcp_config_file
        )

    def abort_before_process_scope(self, reason_code: str) -> dict[str, Any]:
        with self._lifecycle_lock:
            if self._lifecycle_state == "PRELAUNCH_ABORTED":
                if self._lifecycle_receipt is None:
                    raise ClaudeRuntimeMaterializationError(
                        "RUNTIME_LIFECYCLE_RECEIPT_ABSENT",
                        "runtime prelaunch abort receipt is absent",
                    )
                return _clone(self._lifecycle_receipt)
            if self._lifecycle_state != "MATERIALIZED_UNBOUND":
                raise ClaudeRuntimeMaterializationError(
                    "RUNTIME_PRELAUNCH_ABORT_FORBIDDEN",
                    "runtime prelaunch abort is forbidden after scope binding",
                )
            self._compiled_child_environment._invalidate_private_values()
            try:
                profile_receipt = self._profile.abort_before_process_scope(
                    attempt_arm_sha256=self._outer_attempt_arm_sha256,
                    process_scope_identity=self._process_scope_identity,
                    reason_code=reason_code,
                )
                replay_claude_attempt_profile_revocation(
                    self._profile,
                    profile_receipt,
                )
                self._zeroize_runtime_authority_sources()
                auxiliary_receipt = _clone(
                    getattr(self._lease, "_receipt", {})
                )
                auxiliary_replay = (
                    _aux.replay_auxiliary_writable_root_revocation(
                        self._lease.binding,
                        auxiliary_receipt,
                    )
                )
            except (
                ClaudeAttemptProfileError,
                _aux.AuxiliaryWritableRootLeaseError,
                TypeError,
            ) as exc:
                raise ClaudeRuntimeMaterializationError(
                    "RUNTIME_PRELAUNCH_ABORT_FAILED",
                    "runtime prelaunch abort failed",
                ) from exc
            if (
                profile_receipt.get("auxiliary_root_absent_after")
                is not True
                or auxiliary_replay.get("valid") is not True
                or profile_receipt.get(
                    "auxiliary_lease_revocation_sha256"
                )
                != auxiliary_receipt.get("receipt_sha256")
            ):
                raise ClaudeRuntimeMaterializationError(
                    "RUNTIME_PRELAUNCH_ABORT_REPLAY_FAILED",
                    "runtime prelaunch abort did not replay",
                )
            core = {
                "schema": RUNTIME_MATERIALIZATION_LIFECYCLE_SCHEMA,
                "runtime_materialization_sha256": self._receipt[
                    "receipt_sha256"
                ],
                "process_scope_identity": self._process_scope_identity,
                "closure_mode": "PRELAUNCH_ABORT",
                "profile_first_cleanup": True,
                "profile_revocation_receipt_sha256": profile_receipt[
                    "receipt_sha256"
                ],
                "auxiliary_revocation_receipt_sha256": profile_receipt[
                    "auxiliary_lease_revocation_sha256"
                ],
                "completion_authority": False,
                "emergency_zero_population": False,
                "credential_values_recorded": False,
                "credential_content_hashes_recorded": False,
                "host_paths_recorded": False,
            }
            receipt = replay_claude_runtime_lifecycle_receipt(
                {**core, "receipt_sha256": _digest(core)}
            )
            self._lifecycle_receipt = MappingProxyType(receipt)
            self._lifecycle_state = "PRELAUNCH_ABORTED"
            return _clone(receipt)

    def bind_process_scope(self, scope: object) -> dict[str, Any]:
        """Bind the retained auxiliary lease to the exact owned scope once."""

        with self._lifecycle_lock:
            if self._lifecycle_state != "MATERIALIZED_UNBOUND":
                raise ClaudeRuntimeMaterializationError(
                    "RUNTIME_SCOPE_BIND_FORBIDDEN",
                    "runtime process scope cannot be bound in this state",
                )
            try:
                self._lease.bind_process_scope(scope)
            except _aux.AuxiliaryWritableRootLeaseError as exc:
                raise ClaudeRuntimeMaterializationError(
                    "RUNTIME_SCOPE_BIND_FAILED",
                    "runtime process scope binding failed",
                ) from exc
            self._lifecycle_state = "SCOPE_BOUND"
            core = {
                "schema": RUNTIME_MATERIALIZATION_LIFECYCLE_SCHEMA,
                "runtime_materialization_sha256": self._receipt[
                    "receipt_sha256"
                ],
                "process_scope_identity": self._process_scope_identity,
                "closure_mode": "SCOPE_BOUND",
                "profile_first_cleanup": True,
                "completion_authority": False,
                "emergency_zero_population": False,
                "credential_values_recorded": False,
                "credential_content_hashes_recorded": False,
                "host_paths_recorded": False,
            }
            return replay_claude_runtime_lifecycle_receipt(
                {**core, "receipt_sha256": _digest(core)}
            )

    def reconcile_after_scope_close(
        self,
        scope: object,
    ) -> dict[str, Any]:
        """Reconcile bounded post-process state without minting refresh authority."""

        with self._lifecycle_lock:
            if self._lifecycle_state == "SCOPE_RECONCILED":
                if self._postprocess_receipt is None:
                    raise ClaudeRuntimeMaterializationError(
                        "RUNTIME_POSTPROCESS_RECEIPT_ABSENT",
                        "runtime post-process receipt is absent",
                    )
                return _clone(self._postprocess_receipt)
            if self._lifecycle_state != "SCOPE_BOUND":
                raise ClaudeRuntimeMaterializationError(
                    "RUNTIME_POSTPROCESS_REPLAY_FORBIDDEN",
                    "runtime post-process replay is forbidden in this state",
                )
            if (
                getattr(scope, "persistent_identity", None)
                != self._process_scope_identity
                or getattr(scope, "closed", None) is not True
                or getattr(scope, "population_zero_proven", None)
                is not True
                or getattr(scope, "attached", None) is not True
            ):
                raise ClaudeRuntimeMaterializationError(
                    "RUNTIME_POSTPROCESS_SCOPE_INVALID",
                    "runtime post-process scope authority is invalid",
                )
            try:
                lease_replay = (
                    _aux.replay_auxiliary_writable_root_binding(
                        self._lease.binding
                    )
                )
                profile_replay = (
                    replay_claude_attempt_profile_postprocess_binding(
                        self._profile,
                        self._profile.binding,
                    )
                )
                _replay_runtime_authority_files(
                    self._bound_settings_file,
                    self._selected_mcp_config_file,
                    expected_servers=self._expected_mcp_servers,
                )
                if self._compiled_child_environment.active:
                    child_receipt = (
                        _child.reconcile_claude_child_environment(
                            self._compiled_child_environment
                        )
                    )
                else:
                    child_receipt = (
                        _child.replay_claude_child_environment_receipt(
                            self._compiled_child_environment.receipt
                        )
                    )
                persisted = (
                    reconcile_claude_runtime_persisted_authority(
                        self._receipt,
                        self._redacted_receipts,
                        base_argv=self._base_argv,
                        final_argv=self._final_argv,
                        environment_names=self._child_environment_names,
                    )
                )
            except (
                ClaudeAttemptProfileError,
                _aux.AuxiliaryWritableRootLeaseError,
                ClaudeChildEnvironmentError,
                ClaudeRuntimeMaterializationError,
                TypeError,
            ) as exc:
                raise ClaudeRuntimeMaterializationError(
                    "RUNTIME_POSTPROCESS_REPLAY_FAILED",
                    "runtime post-process replay failed",
                ) from exc
            if (
                lease_replay.get("valid") is not True
                or lease_replay.get("binding_sha256")
                != self._receipt["auxiliary_lease_binding_sha256"]
                or profile_replay.get("profile_sha256")
                != self._receipt["attempt_profile_sha256"]
                or child_receipt.get("receipt_sha256")
                != self._receipt[
                    "child_environment_receipt_sha256"
                ]
                or persisted.get("valid") is not True
            ):
                raise ClaudeRuntimeMaterializationError(
                    "RUNTIME_POSTPROCESS_AUTHORITY_DRIFT",
                    "runtime post-process authority drifted",
                )
            core = {
                "schema": RUNTIME_POSTPROCESS_RECONCILIATION_SCHEMA,
                "runtime_materialization_sha256": self._receipt[
                    "receipt_sha256"
                ],
                "process_scope_identity": self._process_scope_identity,
                "attempt_profile_sha256": profile_replay[
                    "profile_sha256"
                ],
                "child_environment_receipt_sha256": child_receipt[
                    "receipt_sha256"
                ],
                "selected_auth_route": self._receipt[
                    "selected_auth_route"
                ],
                "process_closed": True,
                "process_zero_proven": True,
                "process_attached": True,
                "worker_credential_refresh_authority": (
                    "NONE_ACCESS_ONLY_ENVIRONMENT_TOKEN"
                    if self._receipt["selected_auth_route"]
                    == "OAUTH_TOKEN"
                    else (
                        "NONE_UNPROVEN_PRIVATE_COPY_NO_WRITEBACK"
                    )
                ),
                "current_attempt_credential_copy_status": (
                    profile_replay[
                        "current_attempt_credential_copy_status"
                    ]
                ),
                "credential_values_recorded": False,
                "credential_content_hashes_recorded": False,
                "host_paths_recorded": False,
            }
            receipt = replay_claude_runtime_postprocess_receipt(
                {**core, "receipt_sha256": _digest(core)}
            )
            self._postprocess_receipt = MappingProxyType(receipt)
            self._lifecycle_state = "SCOPE_RECONCILED"
            return _clone(receipt)

    def abort_bound_scope_before_process_attach(
        self,
        scope: object,
        reason_code: str,
    ) -> dict[str, Any]:
        """Profile-first cleanup for Popen failure after scope binding."""

        reason = _required_id(reason_code, label="reason_code")
        with self._lifecycle_lock:
            if self._lifecycle_state == "BOUND_PRELAUNCH_ABORTED":
                if self._lifecycle_receipt is None:
                    raise ClaudeRuntimeMaterializationError(
                        "RUNTIME_LIFECYCLE_RECEIPT_ABSENT",
                        "runtime bound-prelaunch receipt is absent",
                    )
                return _clone(self._lifecycle_receipt)
            if self._lifecycle_state not in {
                "SCOPE_BOUND",
                "BOUND_PROFILE_REVOKED_AUXILIARY_PENDING",
            }:
                raise ClaudeRuntimeMaterializationError(
                    "RUNTIME_BOUND_PRELAUNCH_ABORT_FORBIDDEN",
                    "bound-prelaunch abort is forbidden in this state",
                )
            if (
                getattr(scope, "persistent_identity", None)
                != self._process_scope_identity
                or getattr(scope, "attached", None) is not False
                or getattr(scope, "terminated", None) is not False
                or getattr(
                    scope,
                    "pre_release_process_identity",
                    None,
                )
                is not None
                or getattr(scope, "closed", None) is not True
                or getattr(scope, "population_zero_proven", None)
                is not True
                or getattr(scope, "emergency_closed", None) is not False
            ):
                raise ClaudeRuntimeMaterializationError(
                    "RUNTIME_BOUND_PRELAUNCH_SCOPE_INVALID",
                    "bound-prelaunch scope authority is invalid",
                )
            self._compiled_child_environment._invalidate_private_values()
            try:
                if self._lifecycle_state == "SCOPE_BOUND":
                    profile_token = (
                        prove_claude_bound_prelaunch_scope_closed(
                            self._profile,
                            scope,
                        )
                    )
                    auxiliary_token = (
                        _aux.prove_owned_process_scope_closed(
                            self._lease,
                            scope,
                        )
                    )
                    profile_receipt = (
                        self._profile.revoke_bound_prelaunch_scope(
                            profile_token
                        )
                    )
                    profile_replay = (
                        replay_claude_attempt_profile_revocation(
                            self._profile,
                            profile_receipt,
                        )
                    )
                    self._zeroize_runtime_authority_sources()
                    if (
                        profile_replay.get("completion_authority")
                        is not False
                    ):
                        raise ClaudeRuntimeMaterializationError(
                            "RUNTIME_BOUND_PRELAUNCH_PROFILE_OVERCLAIM",
                            "bound-prelaunch profile claimed completion",
                        )
                    self._pending_profile_receipt = (
                        MappingProxyType(_clone(profile_receipt))
                    )
                    self._pending_auxiliary_token = auxiliary_token
                    self._lifecycle_state = (
                        "BOUND_PROFILE_REVOKED_AUXILIARY_PENDING"
                    )
                if (
                    self._pending_profile_receipt is None
                    or self._pending_auxiliary_token is None
                ):
                    raise ClaudeRuntimeMaterializationError(
                        "RUNTIME_PENDING_CLOSURE_INVALID",
                        "runtime pending closure authority is invalid",
                    )
                profile_receipt = _clone(
                    self._pending_profile_receipt
                )
                if self._pending_auxiliary_receipt is None:
                    auxiliary_receipt = self._lease.revoke(
                        self._pending_auxiliary_token
                    )
                    self._pending_auxiliary_receipt = (
                        MappingProxyType(_clone(auxiliary_receipt))
                    )
                else:
                    auxiliary_receipt = _clone(
                        self._pending_auxiliary_receipt
                    )
                auxiliary_replay = (
                    _aux.replay_auxiliary_writable_root_revocation(
                        self._lease.binding,
                        auxiliary_receipt,
                    )
                )
            except (
                ClaudeAttemptProfileError,
                _aux.AuxiliaryWritableRootLeaseError,
                ClaudeRuntimeMaterializationError,
                TypeError,
            ) as exc:
                if isinstance(
                    exc,
                    ClaudeRuntimeMaterializationError,
                ):
                    raise
                raise ClaudeRuntimeMaterializationError(
                    "RUNTIME_BOUND_PRELAUNCH_ABORT_FAILED",
                    "bound-prelaunch abort failed",
                ) from exc
            if auxiliary_replay.get("valid") is not True:
                raise ClaudeRuntimeMaterializationError(
                    "RUNTIME_BOUND_PRELAUNCH_AUXILIARY_INVALID",
                    "bound-prelaunch auxiliary revocation did not replay",
                )
            core = {
                "schema": RUNTIME_MATERIALIZATION_LIFECYCLE_SCHEMA,
                "runtime_materialization_sha256": self._receipt[
                    "receipt_sha256"
                ],
                "process_scope_identity": self._process_scope_identity,
                "closure_mode": "BOUND_SCOPE_PRELAUNCH_ABORT",
                "reason_code": reason,
                "profile_first_cleanup": True,
                "profile_revocation_receipt_sha256": profile_receipt[
                    "receipt_sha256"
                ],
                "auxiliary_revocation_receipt_sha256": (
                    auxiliary_receipt["receipt_sha256"]
                ),
                "completion_authority": False,
                "emergency_zero_population": False,
                "credential_values_recorded": False,
                "credential_content_hashes_recorded": False,
                "host_paths_recorded": False,
            }
            receipt = replay_claude_runtime_lifecycle_receipt(
                {**core, "receipt_sha256": _digest(core)}
            )
            self._lifecycle_receipt = MappingProxyType(receipt)
            self._lifecycle_state = "BOUND_PRELAUNCH_ABORTED"
            self._pending_auxiliary_token = None
            return _clone(receipt)

    def _process_attach_failure_debt(
        self,
        *,
        reason_code: str,
        process_zero_proven: bool,
        created_process_termination_proven: bool,
    ) -> dict[str, Any]:
        self._compiled_child_environment._invalidate_private_values()
        core = {
            "schema": RUNTIME_MATERIALIZATION_LIFECYCLE_SCHEMA,
            "runtime_materialization_sha256": self._receipt[
                "receipt_sha256"
            ],
            "process_scope_identity": self._process_scope_identity,
            "closure_mode": "PROCESS_ATTACH_FAILURE_UNPROVEN_DEBT",
            "reason_code": reason_code,
            "profile_first_cleanup": False,
            "completion_authority": False,
            "emergency_zero_population": False,
            "recovery_required": True,
            "profile_retained": True,
            "auxiliary_root_retained": True,
            "process_zero_proven": process_zero_proven,
            "created_process_termination_proven": (
                created_process_termination_proven
            ),
            "credential_values_recorded": False,
            "credential_content_hashes_recorded": False,
            "host_paths_recorded": False,
        }
        receipt = replay_claude_runtime_lifecycle_receipt(
            {**core, "receipt_sha256": _digest(core)}
        )
        self._lifecycle_receipt = MappingProxyType(receipt)
        self._lifecycle_state = "ATTACH_FAILURE_RECOVERY_REQUIRED"
        return _clone(receipt)

    def close_after_process_attach_failure(
        self,
        scope: object,
        reason_code: str,
    ) -> dict[str, Any]:
        """Revoke after the exact created process dies before scope attach."""

        reason = _required_id(reason_code, label="reason_code")
        with self._lifecycle_lock:
            if self._lifecycle_state == "PROCESS_ATTACH_FAILURE_CLOSED":
                if self._lifecycle_receipt is None:
                    raise ClaudeRuntimeMaterializationError(
                        "RUNTIME_LIFECYCLE_RECEIPT_ABSENT",
                        "attach-failure lifecycle receipt is absent",
                    )
                return _clone(self._lifecycle_receipt)
            if self._lifecycle_state == "ATTACH_FAILURE_RECOVERY_REQUIRED":
                if self._lifecycle_receipt is None:
                    raise ClaudeRuntimeMaterializationError(
                        "RUNTIME_LIFECYCLE_RECEIPT_ABSENT",
                        "attach-failure debt receipt is absent",
                    )
                return _clone(self._lifecycle_receipt)
            if self._lifecycle_state not in {
                "SCOPE_BOUND",
                "ATTACH_FAILURE_PROFILE_REVOKED_AUXILIARY_PENDING",
            }:
                raise ClaudeRuntimeMaterializationError(
                    "RUNTIME_ATTACH_FAILURE_CLOSE_FORBIDDEN",
                    "process attach-failure cleanup is forbidden in this state",
                )
            process_evidence = getattr(
                scope,
                "process_creation_evidence",
                None,
            )
            termination_proven = getattr(
                scope,
                "created_process_termination_proven",
                None,
            )
            if (
                getattr(scope, "persistent_identity", None)
                != self._process_scope_identity
                or getattr(scope, "process_creation_state", None)
                != "PROCESS_CREATED"
                or getattr(scope, "attached", None) is not False
                or getattr(
                    scope,
                    "pre_release_process_identity",
                    None,
                )
                is not None
                or getattr(scope, "emergency_closed", None) is not False
                or termination_proven not in {False, True}
                or process_evidence
                != {
                    "state": "PROCESS_CREATED",
                    "creation_attempted": True,
                    "process_object_returned": True,
                    "attached": False,
                    "created_process_termination_proven": (
                        termination_proven
                    ),
                }
            ):
                raise ClaudeRuntimeMaterializationError(
                    "RUNTIME_ATTACH_FAILURE_SCOPE_INVALID",
                    "process attach-failure scope authority is invalid",
                )
            closed = getattr(scope, "closed", None)
            zero_proven = getattr(
                scope,
                "population_zero_proven",
                None,
            )
            if closed not in {False, True} or zero_proven not in {
                False,
                True,
            }:
                raise ClaudeRuntimeMaterializationError(
                    "RUNTIME_ATTACH_FAILURE_SCOPE_INVALID",
                    "process attach-failure closure evidence is malformed",
                )
            if (
                termination_proven is not True
                or closed is not True
                or zero_proven is not True
            ):
                return self._process_attach_failure_debt(
                    reason_code=reason,
                    process_zero_proven=bool(zero_proven),
                    created_process_termination_proven=bool(
                        termination_proven
                    ),
                )
            self._compiled_child_environment._invalidate_private_values()
            try:
                if self._lifecycle_state == "SCOPE_BOUND":
                    profile_token = (
                        prove_claude_process_attach_failure_scope_closed(
                            self._profile,
                            scope,
                        )
                    )
                    auxiliary_token = (
                        _aux.prove_owned_process_scope_closed(
                            self._lease,
                            scope,
                        )
                    )
                    profile_receipt = (
                        self._profile
                        .revoke_process_attach_failure_scope(
                            profile_token
                        )
                    )
                    profile_replay = (
                        replay_claude_attempt_profile_revocation(
                            self._profile,
                            profile_receipt,
                        )
                    )
                    self._zeroize_runtime_authority_sources()
                    if (
                        profile_replay.get("completion_authority")
                        is not False
                    ):
                        raise ClaudeRuntimeMaterializationError(
                            "RUNTIME_ATTACH_FAILURE_PROFILE_OVERCLAIM",
                            "attach-failure profile claimed completion",
                        )
                    self._pending_profile_receipt = MappingProxyType(
                        _clone(profile_receipt)
                    )
                    self._pending_auxiliary_token = auxiliary_token
                    self._lifecycle_state = (
                        "ATTACH_FAILURE_PROFILE_REVOKED_"
                        "AUXILIARY_PENDING"
                    )
                if (
                    self._pending_profile_receipt is None
                    or self._pending_auxiliary_token is None
                ):
                    raise ClaudeRuntimeMaterializationError(
                        "RUNTIME_PENDING_CLOSURE_INVALID",
                        "attach-failure pending closure is invalid",
                    )
                profile_receipt = _clone(
                    self._pending_profile_receipt
                )
                if self._pending_auxiliary_receipt is None:
                    auxiliary_receipt = self._lease.revoke(
                        self._pending_auxiliary_token
                    )
                    self._pending_auxiliary_receipt = MappingProxyType(
                        _clone(auxiliary_receipt)
                    )
                else:
                    auxiliary_receipt = _clone(
                        self._pending_auxiliary_receipt
                    )
                auxiliary_replay = (
                    _aux.replay_auxiliary_writable_root_revocation(
                        self._lease.binding,
                        auxiliary_receipt,
                    )
                )
            except (
                ClaudeAttemptProfileError,
                _aux.AuxiliaryWritableRootLeaseError,
                ClaudeRuntimeMaterializationError,
                TypeError,
            ) as exc:
                if isinstance(
                    exc,
                    ClaudeRuntimeMaterializationError,
                ):
                    raise
                raise ClaudeRuntimeMaterializationError(
                    "RUNTIME_ATTACH_FAILURE_CLOSE_FAILED",
                    "process attach-failure cleanup failed",
                ) from exc
            if auxiliary_replay.get("valid") is not True:
                raise ClaudeRuntimeMaterializationError(
                    "RUNTIME_ATTACH_FAILURE_AUXILIARY_INVALID",
                    "attach-failure auxiliary revocation did not replay",
                )
            core = {
                "schema": RUNTIME_MATERIALIZATION_LIFECYCLE_SCHEMA,
                "runtime_materialization_sha256": self._receipt[
                    "receipt_sha256"
                ],
                "process_scope_identity": self._process_scope_identity,
                "closure_mode": "PROCESS_ATTACH_FAILURE_CLEANUP",
                "reason_code": reason,
                "profile_first_cleanup": True,
                "profile_revocation_receipt_sha256": profile_receipt[
                    "receipt_sha256"
                ],
                "auxiliary_revocation_receipt_sha256": (
                    auxiliary_receipt["receipt_sha256"]
                ),
                "completion_authority": False,
                "emergency_zero_population": False,
                "credential_values_recorded": False,
                "credential_content_hashes_recorded": False,
                "host_paths_recorded": False,
            }
            receipt = replay_claude_runtime_lifecycle_receipt(
                {**core, "receipt_sha256": _digest(core)}
            )
            self._lifecycle_receipt = MappingProxyType(receipt)
            self._lifecycle_state = "PROCESS_ATTACH_FAILURE_CLOSED"
            self._pending_auxiliary_token = None
            return _clone(receipt)

    def _revoke_closed_scope(
        self,
        scope: object,
        *,
        expected_emergency: bool,
    ) -> dict[str, Any]:
        with self._lifecycle_lock:
            if self._lifecycle_state == "REVOKED":
                if self._lifecycle_receipt is None:
                    raise ClaudeRuntimeMaterializationError(
                        "RUNTIME_LIFECYCLE_RECEIPT_ABSENT",
                        "runtime lifecycle receipt is absent",
                    )
                return _clone(self._lifecycle_receipt)
            if self._lifecycle_state not in {
                "SCOPE_RECONCILED",
                "PROFILE_REVOKED_AUXILIARY_PENDING",
            }:
                raise ClaudeRuntimeMaterializationError(
                    "RUNTIME_SCOPE_REVOKE_FORBIDDEN",
                    "runtime scope revocation is forbidden in this state",
                )
            if (
                not expected_emergency
                and getattr(scope, "attached", None) is not True
            ):
                raise ClaudeRuntimeMaterializationError(
                    "RUNTIME_SCOPE_PROCESS_NOT_ATTACHED",
                    "normal completion requires an attached process",
                )
            if (
                getattr(scope, "closed", None) is not True
                or getattr(scope, "population_zero_proven", None)
                is not True
                or getattr(scope, "emergency_closed", None)
                is not expected_emergency
            ):
                raise ClaudeRuntimeMaterializationError(
                    "RUNTIME_SCOPE_ZERO_PROOF_ABSENT",
                    "runtime process scope lacks the required zero-population proof",
                )
            self._compiled_child_environment._invalidate_private_values()
            try:
                if self._lifecycle_state == "SCOPE_RECONCILED":
                    postprocess_authority = None
                    if not expected_emergency:
                        postprocess_authority = (
                            mint_claude_fresh_postprocess_authority(
                                self._profile,
                                scope,
                            )
                        )
                    profile_token = prove_claude_profile_scope_closed(
                        self._profile,
                        scope,
                        postprocess_authority=(
                            postprocess_authority
                        ),
                    )
                    auxiliary_token = (
                        _aux.prove_owned_process_scope_closed(
                            self._lease,
                            scope,
                        )
                    )
                    profile_receipt = self._profile.revoke(
                        profile_token
                    )
                    replay_claude_attempt_profile_revocation(
                        self._profile,
                        profile_receipt,
                    )
                    self._zeroize_runtime_authority_sources()
                    self._pending_profile_receipt = (
                        MappingProxyType(_clone(profile_receipt))
                    )
                    self._pending_auxiliary_token = auxiliary_token
                    self._pending_expected_emergency = (
                        expected_emergency
                    )
                    self._lifecycle_state = (
                        "PROFILE_REVOKED_AUXILIARY_PENDING"
                    )
                if (
                    self._pending_profile_receipt is None
                    or self._pending_auxiliary_token is None
                    or self._pending_expected_emergency
                    is not expected_emergency
                ):
                    raise ClaudeRuntimeMaterializationError(
                        "RUNTIME_PENDING_CLOSURE_INVALID",
                        "runtime pending closure authority is invalid",
                    )
                profile_receipt = _clone(
                    self._pending_profile_receipt
                )
                if self._pending_auxiliary_receipt is None:
                    auxiliary_receipt = self._lease.revoke(
                        self._pending_auxiliary_token
                    )
                    self._pending_auxiliary_receipt = (
                        MappingProxyType(_clone(auxiliary_receipt))
                    )
                else:
                    auxiliary_receipt = _clone(
                        self._pending_auxiliary_receipt
                    )
                auxiliary_replay = (
                    _aux.replay_auxiliary_writable_root_revocation(
                        self._lease.binding,
                        auxiliary_receipt,
                    )
                )
            except (
                ClaudeAttemptProfileError,
                _aux.AuxiliaryWritableRootLeaseError,
                ClaudeRuntimeMaterializationError,
                TypeError,
            ) as exc:
                if isinstance(
                    exc,
                    ClaudeRuntimeMaterializationError,
                ):
                    raise
                raise ClaudeRuntimeMaterializationError(
                    "RUNTIME_PROFILE_FIRST_REVOCATION_FAILED",
                    "runtime profile-first revocation failed",
                ) from exc
            if auxiliary_replay.get("valid") is not True:
                raise ClaudeRuntimeMaterializationError(
                    "RUNTIME_AUXILIARY_REVOCATION_INVALID",
                    "runtime auxiliary revocation did not replay",
                )
            # The profile receipt is bound to the fresh one-shot replay made
            # immediately before root revocation.  An earlier reconciliation
            # status is useful evidence, but cannot grant completion after a
            # later credential mutation or restoration.
            completion_capable = (
                profile_receipt.get("completion_authority") is True
                and not expected_emergency
            )
            core = {
                "schema": RUNTIME_MATERIALIZATION_LIFECYCLE_SCHEMA,
                "runtime_materialization_sha256": self._receipt[
                    "receipt_sha256"
                ],
                "process_scope_identity": self._process_scope_identity,
                "closure_mode": (
                    "EMERGENCY_ZERO_POPULATION_CLEANUP"
                    if expected_emergency
                    else (
                        "NORMAL_COMPLETION"
                        if completion_capable
                        else (
                            "NORMAL_SCOPE_CLEANUP_NO_REFRESH_CONTINUITY"
                        )
                    )
                ),
                "profile_first_cleanup": True,
                "profile_revocation_receipt_sha256": profile_receipt[
                    "receipt_sha256"
                ],
                "auxiliary_revocation_receipt_sha256": auxiliary_receipt[
                    "receipt_sha256"
                ],
                "completion_authority": completion_capable,
                "emergency_zero_population": expected_emergency,
                "credential_values_recorded": False,
                "credential_content_hashes_recorded": False,
                "host_paths_recorded": False,
            }
            receipt = replay_claude_runtime_lifecycle_receipt(
                {**core, "receipt_sha256": _digest(core)}
            )
            self._lifecycle_receipt = MappingProxyType(receipt)
            self._lifecycle_state = "REVOKED"
            self._pending_auxiliary_token = None
            return _clone(receipt)

    def revoke_after_normal_scope_close(
        self,
        scope: object,
    ) -> dict[str, Any]:
        """Revoke profile first after a normal exact zero-population close."""

        return self._revoke_closed_scope(
            scope,
            expected_emergency=False,
        )

    def revoke_after_failed_scope_close(
        self,
        scope: object,
        reason_code: str,
        *,
        primary_failure_evidence_sha256: str,
    ) -> dict[str, Any]:
        """Revoke an ordinarily closed failed-provider scope without completion."""

        reason = _required_id(reason_code, label="reason_code")
        if reason != "NONZERO_EXIT":
            raise ClaudeRuntimeMaterializationError(
                "RUNTIME_FAILURE_CLEANUP_REASON_UNSUPPORTED",
                "runtime failure cleanup requires a typed provider nonzero result",
            )
        if (
            not isinstance(primary_failure_evidence_sha256, str)
            or _SHA256.fullmatch(primary_failure_evidence_sha256) is None
        ):
            raise ClaudeRuntimeMaterializationError(
                "RUNTIME_FAILURE_EVIDENCE_INVALID",
                "runtime failure cleanup evidence digest is invalid",
            )
        with self._lifecycle_lock:
            if self._lifecycle_state == "FAILED_SCOPE_REVOKED":
                if (
                    self._lifecycle_receipt is None
                    or self._lifecycle_receipt.get("reason_code") != reason
                    or self._lifecycle_receipt.get(
                        "primary_failure_evidence_sha256"
                    )
                    != primary_failure_evidence_sha256
                ):
                    raise ClaudeRuntimeMaterializationError(
                        "RUNTIME_FAILURE_CLEANUP_REPLAY_MISMATCH",
                        "runtime failure cleanup replay authority mismatched",
                    )
                return _clone(self._lifecycle_receipt)
            if self._lifecycle_state not in {
                "SCOPE_BOUND",
                "FAILURE_PROFILE_REVOKED_AUXILIARY_PENDING",
            }:
                raise ClaudeRuntimeMaterializationError(
                    "RUNTIME_FAILURE_CLEANUP_FORBIDDEN",
                    "runtime failure cleanup is forbidden in this state",
                )
            if (
                getattr(scope, "attached", None) is not True
                or getattr(scope, "closed", None) is not True
                or getattr(scope, "population_zero_proven", None) is not True
                or getattr(scope, "emergency_closed", None) is not False
                or getattr(scope, "persistent_identity", None)
                != self._process_scope_identity
            ):
                raise ClaudeRuntimeMaterializationError(
                    "RUNTIME_FAILURE_SCOPE_ZERO_PROOF_ABSENT",
                    "runtime failure cleanup requires the exact ordinary "
                    "zero-population scope authority",
                )
            self._compiled_child_environment._invalidate_private_values()
            try:
                if self._lifecycle_state == "SCOPE_BOUND":
                    profile_token = prove_claude_normal_scope_failure_closed(
                        self._profile,
                        scope,
                        primary_failure_evidence_sha256=(
                            primary_failure_evidence_sha256
                        ),
                    )
                    auxiliary_token = (
                        _aux.prove_owned_process_scope_closed(
                            self._lease,
                            scope,
                        )
                    )
                    profile_receipt = (
                        self._profile.revoke_normal_scope_failure(
                            profile_token
                        )
                    )
                    self._pending_profile_receipt = MappingProxyType(
                        _clone(profile_receipt)
                    )
                    self._pending_auxiliary_token = auxiliary_token
                    self._pending_failure_reason_code = reason
                    self._pending_primary_failure_evidence_sha256 = (
                        primary_failure_evidence_sha256
                    )
                    self._lifecycle_state = (
                        "FAILURE_PROFILE_REVOKED_AUXILIARY_PENDING"
                    )
                if (
                    self._pending_profile_receipt is None
                    or self._pending_auxiliary_token is None
                    or self._pending_failure_reason_code != reason
                    or self._pending_primary_failure_evidence_sha256
                    != primary_failure_evidence_sha256
                ):
                    raise ClaudeRuntimeMaterializationError(
                        "RUNTIME_PENDING_FAILURE_CLOSURE_INVALID",
                        "runtime pending failure cleanup authority is invalid",
                    )
                profile_receipt = _clone(
                    self._pending_profile_receipt
                )
                profile_replay = (
                    replay_claude_attempt_profile_revocation(
                        self._profile,
                        profile_receipt,
                    )
                )
                self._zeroize_runtime_authority_sources()
                if (
                    set(profile_replay)
                    != {
                        "valid",
                        "reason",
                        "receipt_sha256",
                        "completion_authority",
                    }
                    or profile_replay.get("valid") is not True
                    or profile_replay.get("reason")
                    != "TERMINAL_PROFILE_REVOCATION_REPLAYED"
                    or profile_replay.get("receipt_sha256")
                    != profile_receipt["receipt_sha256"]
                    or profile_replay.get("completion_authority")
                    is not False
                ):
                    raise ClaudeRuntimeMaterializationError(
                        "RUNTIME_FAILURE_PROFILE_REVOCATION_INVALID",
                        "runtime failure cleanup profile revocation "
                        "authority is invalid",
                    )
                if self._pending_auxiliary_receipt is None:
                    auxiliary_receipt = self._lease.revoke(
                        self._pending_auxiliary_token
                    )
                    self._pending_auxiliary_receipt = MappingProxyType(
                        _clone(auxiliary_receipt)
                    )
                else:
                    auxiliary_receipt = _clone(
                        self._pending_auxiliary_receipt
                    )
                auxiliary_replay = (
                    _aux.replay_auxiliary_writable_root_revocation(
                        self._lease.binding,
                        auxiliary_receipt,
                    )
                )
            except (
                ClaudeAttemptProfileError,
                _aux.AuxiliaryWritableRootLeaseError,
                ClaudeRuntimeMaterializationError,
                TypeError,
            ) as exc:
                if isinstance(
                    exc,
                    ClaudeRuntimeMaterializationError,
                ):
                    raise
                raise ClaudeRuntimeMaterializationError(
                    "RUNTIME_FAILURE_PROFILE_FIRST_REVOCATION_FAILED",
                    "runtime failure cleanup profile-first revocation failed",
                ) from exc
            if auxiliary_replay.get("valid") is not True:
                raise ClaudeRuntimeMaterializationError(
                    "RUNTIME_FAILURE_AUXILIARY_REVOCATION_INVALID",
                    "runtime failure cleanup auxiliary revocation did not replay",
                )
            core = {
                "schema": RUNTIME_MATERIALIZATION_LIFECYCLE_SCHEMA,
                "runtime_materialization_sha256": self._receipt[
                    "receipt_sha256"
                ],
                "process_scope_identity": self._process_scope_identity,
                "closure_mode": "NORMAL_SCOPE_FAILURE_CLEANUP",
                "reason_code": reason,
                "primary_failure_evidence_sha256": (
                    primary_failure_evidence_sha256
                ),
                "profile_first_cleanup": True,
                "profile_revocation_receipt_sha256": profile_receipt[
                    "receipt_sha256"
                ],
                "auxiliary_revocation_receipt_sha256": auxiliary_receipt[
                    "receipt_sha256"
                ],
                "completion_authority": False,
                "emergency_zero_population": False,
                "credential_values_recorded": False,
                "credential_content_hashes_recorded": False,
                "host_paths_recorded": False,
            }
            receipt = replay_claude_runtime_lifecycle_receipt(
                {**core, "receipt_sha256": _digest(core)}
            )
            self._lifecycle_receipt = MappingProxyType(receipt)
            self._lifecycle_state = "FAILED_SCOPE_REVOKED"
            self._pending_auxiliary_token = None
            return _clone(receipt)

    def emergency_zero_and_revoke(
        self,
        scope: object,
    ) -> dict[str, Any]:
        """Emergency-close; clean only with proof, otherwise retain debt."""

        return self.emergency_close_to_quarantine_debt(scope)

    def _emergency_debt(
        self,
        *,
        mode: str,
        emergency_close_observed: bool,
    ) -> dict[str, Any]:
        self._compiled_child_environment._invalidate_private_values()
        core = {
            "schema": RUNTIME_MATERIALIZATION_LIFECYCLE_SCHEMA,
            "runtime_materialization_sha256": self._receipt[
                "receipt_sha256"
            ],
            "process_scope_identity": self._process_scope_identity,
            "closure_mode": mode,
            "profile_first_cleanup": False,
            "completion_authority": False,
            "emergency_zero_population": False,
            "recovery_required": True,
            "profile_retained": True,
            "auxiliary_root_retained": True,
            "process_zero_proven": False,
            "emergency_close_observed": emergency_close_observed,
            "credential_values_recorded": False,
            "credential_content_hashes_recorded": False,
            "host_paths_recorded": False,
        }
        receipt = replay_claude_runtime_lifecycle_receipt(
            {**core, "receipt_sha256": _digest(core)}
        )
        self._lifecycle_receipt = MappingProxyType(receipt)
        self._lifecycle_state = "EMERGENCY_RECOVERY_REQUIRED"
        return _clone(receipt)

    def emergency_close_to_quarantine_debt(
        self,
        scope: object,
    ) -> dict[str, Any]:
        """Attempt emergency close without inventing zero-population proof."""

        with self._lifecycle_lock:
            if self._lifecycle_state == "EMERGENCY_RECOVERY_REQUIRED":
                if self._lifecycle_receipt is None:
                    raise ClaudeRuntimeMaterializationError(
                        "RUNTIME_LIFECYCLE_RECEIPT_ABSENT",
                        "runtime emergency debt receipt is absent",
                    )
                return _clone(self._lifecycle_receipt)
            if self._lifecycle_state != "SCOPE_BOUND":
                raise ClaudeRuntimeMaterializationError(
                    "RUNTIME_EMERGENCY_CLOSE_FORBIDDEN",
                    "runtime emergency close is forbidden in this state",
                )
            emergency_close = getattr(scope, "emergency_close", None)
            if not callable(emergency_close):
                return self._emergency_debt(
                    mode="EMERGENCY_CLOSE_FAILED_DEBT",
                    emergency_close_observed=False,
                )
            try:
                emergency_close()
            except Exception:
                return self._emergency_debt(
                    mode="EMERGENCY_CLOSE_FAILED_DEBT",
                    emergency_close_observed=False,
                )
            if (
                getattr(scope, "closed", None) is not True
                or getattr(scope, "emergency_closed", None) is not True
                or getattr(scope, "population_zero_proven", None)
                is not True
            ):
                return self._emergency_debt(
                    mode="EMERGENCY_ZERO_UNPROVEN_DEBT",
                    emergency_close_observed=True,
                )
        self.reconcile_after_scope_close(scope)
        return self._revoke_closed_scope(
            scope,
            expected_emergency=True,
        )


def _materialize_claude_runtime(
    *,
    launch_security_request: Mapping[str, Any],
    ambient_environment: Mapping[str, str],
    base_argv: Sequence[str],
    scratchpad: str | Path,
    startup_permit_binding: Mapping[str, Any],
    run_id: str,
    outer_attempt_arm_sha256: str,
    work_plan_sha256: str,
    attempt_id: str,
    process_scope_identity: str,
    project_root: str | Path,
    trusted_cwds: Sequence[str | Path],
    source_config_dir: str | Path | None,
    runtime_request_sha256: str,
    bound_settings_bytes: bytes | None = None,
    selected_mcp_config_bytes: bytes | None = None,
    auxiliary_reservation: (
        _aux.AuxiliaryWritableRootReservation | None
    ) = None,
) -> ClaudeRuntimeMaterialization:
    """Materialize one attempt-private Claude runtime, but never launch it."""

    request, policy = _first_lane_policy(launch_security_request)
    selected_auth_route = policy["auth_route_policy"]["desired_route"]
    semantic_argv = _compile_final_argv(
        base_argv,
        request=request,
        policy=policy,
    )
    (
        exact_settings_bytes,
        exact_mcp_bytes,
        expected_mcp_servers,
    ) = _validated_bound_runtime_sources(
        policy=policy,
        bound_settings_bytes=bound_settings_bytes,
        selected_mcp_config_bytes=selected_mcp_config_bytes,
    )
    final_argv = semantic_argv
    request_sha256 = _required_sha256(
        runtime_request_sha256,
        label="runtime materialization request digest",
    )
    run = _required_id(run_id, label="run_id")
    attempt = _required_id(attempt_id, label="attempt_id")
    scope_identity = _required_id(
        process_scope_identity,
        label="process_scope_identity",
    )
    arm_sha256 = _required_sha256(
        outer_attempt_arm_sha256,
        label="outer AttemptArm digest",
    )
    plan_sha256 = _required_sha256(
        work_plan_sha256,
        label="WorkPlan digest",
    )
    scratch = Path(scratchpad)
    startup_binding = _replay_startup(
        scratchpad=scratch,
        run_id=run,
        startup_permit_binding=startup_permit_binding,
    )
    if selected_auth_route == "OAUTH_TOKEN":
        token_names = [
            name
            for name, value in ambient_environment.items()
            if name.casefold()
            == "CLAUDE_CODE_OAUTH_TOKEN".casefold()
            and bool(value)
        ]
        if len(token_names) != 1:
            raise ClaudeRuntimeMaterializationError(
                "OAUTH_SETUP_TOKEN_REQUIRED",
                "Claude setup-token authentication is required",
            )
    reservation = _reservation(
        auxiliary_reservation,
        attempt_id=attempt,
    )
    _planned_key_denominator(
        ambient_environment=ambient_environment,
        policy=policy,
    )

    capability: StoredSubscriptionMaterializationCapability | None = None
    profile: ClaudeAttemptProfile | None = None
    lease: _aux.AuxiliaryWritableRootLease | None = None
    compiled: CompiledClaudeChildEnvironment | None = None
    settings_file: _ClaudeRuntimeAuthorityFile | None = None
    mcp_file: _ClaudeRuntimeAuthorityFile | None = None
    runtime_authority_cli_flags: tuple[str, ...] = ()
    try:
        if selected_auth_route == "OAUTH_TOKEN":
            try:
                source_evidence = (
                    _stored.observe_stored_subscription_source(
                        source_path=None
                    )
                )
            except (
                ClaudeStoredSubscriptionSourceError,
                OSError,
                TypeError,
                ValueError,
            ) as exc:
                raise ClaudeRuntimeMaterializationError(
                    "OAUTH_ABSENCE_EVIDENCE_FAILED",
                    "stored-source absence evidence is unavailable",
                ) from exc
        else:
            source_path = (
                Path(source_config_dir) / ".credentials.json"
            )
            try:
                capability = (
                    _stored.acquire_stored_subscription_materialization(
                        source_path=source_path
                    )
                )
            except (
                ClaudeStoredSubscriptionSourceError,
                OSError,
                TypeError,
                ValueError,
            ) as exc:
                raise ClaudeRuntimeMaterializationError(
                    "STORED_SUBSCRIPTION_SOURCE_UNAVAILABLE",
                    "stored subscription source is unavailable",
                ) from exc
            source_evidence = capability.source_evidence
        auth_environment, auth_receipt, source_observation = (
            _auth_environment(
                ambient_environment=ambient_environment,
                policy=policy,
                source_evidence=source_evidence,
            )
        )

        # Recheck the durable startup authority immediately before allocation.
        startup_binding = _replay_startup(
            scratchpad=scratch,
            run_id=run,
            startup_permit_binding=startup_binding,
        )
        try:
            lease = reservation.arm(
                attempt_arm_sha256=arm_sha256,
                process_scope_identity=scope_identity,
            )
        except _aux.AuxiliaryWritableRootLeaseError as exc:
            raise ClaudeRuntimeMaterializationError(
                "AUXILIARY_LEASE_ARM_FAILED",
                "auxiliary reservation could not be armed",
            ) from exc

        profile_arguments: dict[str, Any] = {
            "leased_parent": lease,
            "project_root": project_root,
            "trusted_cwds": trusted_cwds,
            "run_id": run,
            "startup_permit_binding": startup_binding,
            "outer_attempt_arm_sha256": arm_sha256,
            "work_plan_sha256": plan_sha256,
            "attempt_id": attempt,
            "process_scope_identity": scope_identity,
            "launch_security_policy_sha256": policy["policy_sha256"],
            "executable_observation_sha256": policy[
                "executable_observation_sha256"
            ],
            "auth_environment_receipt_sha256": auth_receipt[
                "receipt_sha256"
            ],
            "settings_authority_sha256": policy[
                "settings_authority"
            ]["authority_sha256"],
            "mcp_authority_sha256": policy["mcp_authority"][
                "authority_sha256"
            ],
            "home_variable_policy": policy["home_variable_policy"],
            "permission_mode": policy["headless_profile"][
                "expected_init_contract"
            ]["permission_mode"],
            "windows_job_only_restricted": (
                os.name == "nt"
                and policy["headless_profile"].get("claude_code_version")
                == "2.1.252"
                and policy["headless_profile"]["expected_init_contract"].get(
                    "permission_mode"
                )
                == "default"
                and policy["headless_profile"].get("cli_flags", []).count(
                    "--restricted"
                )
                == 1
            ),
            "stored_subscription_capability": (
                capability
                if selected_auth_route
                == "STORED_SUBSCRIPTION_OAUTH"
                else None
            ),
            "expected_stored_subscription_source_evidence": (
                source_evidence
                if selected_auth_route
                == "STORED_SUBSCRIPTION_OAUTH"
                else None
            ),
            "credential_mode": (
                "ENVIRONMENT_OAUTH_TOKEN"
                if selected_auth_route == "OAUTH_TOKEN"
                else "COPIED_STORED_SUBSCRIPTION"
            ),
            "auth_route": selected_auth_route,
        }
        try:
            profile = materialize_claude_attempt_profile(
                **profile_arguments
            )
        except (
            ClaudeAttemptProfileError,
            ClaudeStoredSubscriptionSourceError,
            OSError,
            TypeError,
            ValueError,
        ) as exc:
            raise ClaudeRuntimeMaterializationError(
                "ATTEMPT_PROFILE_MATERIALIZATION_FAILED",
                "attempt profile materialization failed",
            ) from exc
        capability = None
        replay_claude_attempt_profile_binding(
            profile,
            profile.binding,
        )
        if exact_settings_bytes is not None:
            assert exact_mcp_bytes is not None
            (
                attempt_private_mcp_bytes,
                _private_mcp_source_materialized,
            ) = _resolve_attempt_private_mcp_config(
                exact_mcp_bytes,
                ambient_environment=ambient_environment,
                run_id=run,
                expected_servers=expected_mcp_servers,
            )
            settings_file = _materialize_runtime_authority_file(
                profile.root / ".plamen-bound-settings.json",
                exact_settings_bytes,
                label="bound settings",
            )
            mcp_file = _materialize_runtime_authority_file(
                profile.root / ".plamen-selected-mcp.json",
                attempt_private_mcp_bytes,
                label="selected MCP config",
            )
            runtime_authority_cli_flags = (
                "--settings",
                str(settings_file.path),
                "--strict-mcp-config",
                "--mcp-config",
                str(mcp_file.path),
            )
            final_argv = tuple(
                [*semantic_argv, *runtime_authority_cli_flags]
            )
        _replay_runtime_authority_files(
            settings_file,
            mcp_file,
            expected_servers=expected_mcp_servers,
        )

        compiled = _child.compile_claude_child_environment(
            ambient=ambient_environment,
            auth_environment=auth_environment,
            auth_environment_receipt=auth_receipt,
            source_observation=source_observation,
            attempt_profile_environment=profile.environment,
            private_home_overlay_authority=(
                profile.consume_private_home_overlay_authority()
            ),
            phase_environment_policies=policy[
                "phase_environment_policies"
            ],
            home_variable_policy=policy["home_variable_policy"],
            functional_controls=policy["functional_controls"],
        )
        child_receipt = _child.reconcile_claude_child_environment(
            compiled
        )
        child_names = {
            name.casefold()
            for name in compiled.environment
        }
        if any(
            name.casefold() in child_names
            for name in _CLAUDE_PRECEDENCE_ENVIRONMENT_DENIALS
        ):
            raise ClaudeRuntimeMaterializationError(
                "CHILD_PRECEDENCE_ENVIRONMENT_REDIRECT",
                "child environment retained a credential precedence redirect",
            )
        if (
            child_receipt["final_environment_key_set_sha256"]
            != policy["expected_child_environment_key_set_sha256"]
        ):
            raise ClaudeRuntimeMaterializationError(
                "CHILD_KEY_DENOMINATOR_MISMATCH",
                "child environment key denominator differs from WorkPlan",
            )

        profile_binding = profile.binding
        source_materialization: dict[str, Any] | None
        if selected_auth_route == "OAUTH_TOKEN":
            if (
                profile_binding.get("credential_mode")
                != "ENVIRONMENT_OAUTH_TOKEN"
                or profile_binding.get("auth_route")
                != "OAUTH_TOKEN"
                or profile_binding.get("credential_copy") != "ABSENT"
                or (
                    profile.config_dir / ".credentials.json"
                ).exists()
            ):
                raise ClaudeRuntimeMaterializationError(
                    "OAUTH_PROFILE_CREDENTIAL_COPY_PRESENT",
                    "OAuth-token profile retained a credential copy",
                )
            source_materialization = None
        else:
            if (
                profile_binding.get("credential_mode")
                != "COPIED_STORED_SUBSCRIPTION"
                or profile_binding.get("auth_route")
                != "STORED_SUBSCRIPTION_OAUTH"
            ):
                raise ClaudeRuntimeMaterializationError(
                    "STORED_PROFILE_ROUTE_MISMATCH",
                    "stored-subscription profile route drifted",
                )
            credential_copy = profile_binding.get("credential_copy")
            if not isinstance(credential_copy, dict):
                raise ClaudeRuntimeMaterializationError(
                    "SOURCE_MATERIALIZATION_RECEIPT_ABSENT",
                    "exact source materialization receipt is absent",
                )
            source_materialization = (
                _stored.replay_stored_subscription_materialization_receipt(
                    credential_copy
                )
            )
            if (
                source_materialization["source_evidence"]
                != source_evidence
                or source_materialization["source_evidence"]
                != source_observation["stored_subscription_evidence"]
            ):
                raise ClaudeRuntimeMaterializationError(
                    "SOURCE_MATERIALIZATION_BINDING_MISMATCH",
                    "stored subscription source binding drifted",
                )

        core = {
            "schema": RUNTIME_MATERIALIZATION_SCHEMA,
            "runtime_request_sha256": request_sha256,
            "launch_security_request_sha256": request[
                "request_sha256"
            ],
            "launch_security_policy_sha256": policy["policy_sha256"],
            "startup_permit_sha256": _digest(startup_binding),
            "outer_attempt_arm_sha256": arm_sha256,
            "work_plan_sha256": plan_sha256,
            "attempt_id": attempt,
            "process_scope_identity": scope_identity,
            "auxiliary_lease_binding_sha256": lease.binding[
                "binding_sha256"
            ],
            "attempt_profile_sha256": profile_binding[
                "profile_sha256"
            ],
            "selected_auth_route": selected_auth_route,
            "credential_materialization_mode": profile_binding[
                "credential_mode"
            ],
            "source_observation_sha256": source_observation[
                "receipt_sha256"
            ],
            "source_materialization_receipt_sha256": (
                None
                if source_materialization is None
                else source_materialization["receipt_sha256"]
            ),
            "auth_environment_receipt_sha256": auth_receipt[
                "receipt_sha256"
            ],
            "settings_authority_sha256": policy[
                "settings_authority"
            ]["authority_sha256"],
            "mcp_authority_sha256": policy["mcp_authority"][
                "authority_sha256"
            ],
            "base_argv_sha256": _argv_sha256(base_argv),
            "final_argv_sha256": _argv_sha256(final_argv),
            "final_argv_count": len(final_argv),
            "child_environment_receipt_sha256": child_receipt[
                "receipt_sha256"
            ],
            "expected_child_environment_key_set_sha256": policy[
                "expected_child_environment_key_set_sha256"
            ],
            "refresh_continuity_authority": (
                "ENVIRONMENT_OAUTH_TOKEN_NO_WRITEBACK"
                if selected_auth_route == "OAUTH_TOKEN"
                else "UNPROVEN_PRIVATE_COPY_NO_WRITEBACK"
            ),
            "completion_capable": (
                selected_auth_route == "OAUTH_TOKEN"
            ),
            "precedence_environment_denials": sorted(
                _CLAUDE_PRECEDENCE_ENVIRONMENT_DENIALS
            ),
            "credential_values_recorded": False,
            "credential_content_hashes_recorded": False,
            "host_paths_recorded": False,
        }
        receipt = replay_claude_runtime_materialization_receipt(
            {**core, "receipt_sha256": _digest(core)}
        )
        redacted = {
            "source_evidence": source_evidence,
            "source_materialization": source_materialization,
            "auth_source_observation": source_observation,
            "auth_environment": auth_receipt,
            "child_environment": child_receipt,
        }
        return ClaudeRuntimeMaterialization(
            _construction_capability=_RESULT_CAPABILITY,
            _profile=profile,
            _lease=lease,
            _compiled_child_environment=compiled,
            _child_environment_names=tuple(
                compiled.environment
            ),
            _base_argv=tuple(base_argv),
            _headless_profile_cli_flags=tuple(
                policy["headless_profile"]["cli_flags"]
            ),
            _runtime_authority_cli_flags=runtime_authority_cli_flags,
            _bound_settings_file=settings_file,
            _selected_mcp_config_file=mcp_file,
            _expected_mcp_servers=expected_mcp_servers,
            _final_argv=final_argv,
            _receipt=MappingProxyType(_clone(receipt)),
            _redacted_receipts=MappingProxyType(_clone(redacted)),
            _outer_attempt_arm_sha256=arm_sha256,
            _process_scope_identity=scope_identity,
        )
    except BaseException:
        cleanup_error: BaseException | None = None
        if compiled is not None:
            compiled._invalidate_private_values()
        if capability is not None:
            try:
                capability.discard()
            except ClaudeStoredSubscriptionSourceError:
                pass
        if profile is not None:
            try:
                profile.abort_before_process_scope(
                    attempt_arm_sha256=arm_sha256,
                    process_scope_identity=scope_identity,
                    reason_code="RUNTIME_MATERIALIZATION_FAILED",
                )
            except BaseException as exc:
                cleanup_error = exc
        elif lease is not None:
            try:
                lease.abort_before_process_scope(
                    attempt_arm_sha256=arm_sha256,
                    process_scope_identity=scope_identity,
                    reason_code="RUNTIME_MATERIALIZATION_FAILED",
                )
            except BaseException as exc:
                cleanup_error = exc
        _zeroize_runtime_authority_file(settings_file)
        _zeroize_runtime_authority_file(mcp_file)
        if cleanup_error is not None:
            raise ClaudeRuntimeMaterializationError(
                "RUNTIME_ROLLBACK_INCOMPLETE",
                "runtime materialization failed and rollback was incomplete",
            ) from cleanup_error
        raise


def materialize_claude_runtime(
    request: ClaudeRuntimeMaterializationRequest,
) -> ClaudeRuntimeMaterialization:
    """One exact WorkerTransaction-to-WER materialization seam."""

    if type(request) is not ClaudeRuntimeMaterializationRequest:
        raise ClaudeRuntimeMaterializationError(
            "RUNTIME_REQUEST_TYPE_INVALID",
            "opaque runtime materialization request is required",
        )
    return _materialize_claude_runtime(
        **request._claim(require_provider_parent=True)
    )


def reconcile_claude_runtime_after_scope_close(
    runtime: ClaudeRuntimeMaterialization,
    scope: object,
) -> dict[str, Any]:
    """Typed post-process replay seam; never use prelaunch live replay here."""

    if type(runtime) is not ClaudeRuntimeMaterialization:
        raise ClaudeRuntimeMaterializationError(
            "RUNTIME_OBJECT_INVALID",
            "Claude runtime materialization object is invalid",
        )
    return runtime.reconcile_after_scope_close(scope)


def replay_claude_runtime_materialization(
    value: ClaudeRuntimeMaterialization,
) -> dict[str, Any]:
    """Reconcile all live in-memory runtime authorities before process use."""

    if type(value) is not ClaudeRuntimeMaterialization:
        raise ClaudeRuntimeMaterializationError(
            "RUNTIME_OBJECT_INVALID",
            "Claude runtime materialization object is invalid",
        )
    if value._lifecycle_state != "MATERIALIZED_UNBOUND":
        raise ClaudeRuntimeMaterializationError(
            "RUNTIME_LIVE_REPLAY_PRELAUNCH_ONLY",
            "live runtime replay is only valid before process-scope binding",
        )
    receipt = replay_claude_runtime_materialization_receipt(
        value.receipt
    )
    lease_replay = _aux.replay_auxiliary_writable_root_binding(
        value._lease.binding
    )
    profile_replay = replay_claude_attempt_profile_binding(
        value._profile,
        value._profile.binding,
    )
    _replay_runtime_authority_files(
        value._bound_settings_file,
        value._selected_mcp_config_file,
        expected_servers=value._expected_mcp_servers,
    )
    child_receipt = _child.reconcile_claude_child_environment(
        value._compiled_child_environment
    )
    redacted = _clone(value.redacted_receipts)
    source_materialization = redacted["source_materialization"]
    if receipt["selected_auth_route"] == "OAUTH_TOKEN":
        if source_materialization is not None:
            raise ClaudeRuntimeMaterializationError(
                "RUNTIME_LIVE_AUTHORITY_DRIFT",
                "OAuth-token runtime gained a credential copy",
            )
        source_materialization_sha256 = None
    else:
        source_materialization = (
            _stored.replay_stored_subscription_materialization_receipt(
                source_materialization
            )
        )
        source_materialization_sha256 = source_materialization[
            "receipt_sha256"
        ]
    if (
        lease_replay.get("valid") is not True
        or lease_replay.get("binding_sha256")
        != receipt["auxiliary_lease_binding_sha256"]
        or profile_replay["profile_sha256"]
        != receipt["attempt_profile_sha256"]
        or child_receipt["receipt_sha256"]
        != receipt["child_environment_receipt_sha256"]
        or source_materialization_sha256
        != receipt["source_materialization_receipt_sha256"]
        or _argv_sha256(value._base_argv)
        != receipt["base_argv_sha256"]
        or tuple(
            [
                *value._base_argv,
                *value._headless_profile_cli_flags,
                *value._runtime_authority_cli_flags,
            ]
        )
        != value._final_argv
        or _argv_sha256(value._final_argv)
        != receipt["final_argv_sha256"]
        or len(value._final_argv) != receipt["final_argv_count"]
        or child_receipt["final_environment_key_set_sha256"]
        != receipt["expected_child_environment_key_set_sha256"]
    ):
        raise ClaudeRuntimeMaterializationError(
            "RUNTIME_LIVE_AUTHORITY_DRIFT",
            "Claude runtime live authority drifted",
        )
    return {
        "valid": True,
        "reason": "LIVE_RUNTIME_MATERIALIZATION_REPLAYED",
        "receipt_sha256": receipt["receipt_sha256"],
    }


__all__ = [
    "AUXILIARY_PURPOSE",
    "RUNTIME_MATERIALIZATION_ERROR_SCHEMA",
    "RUNTIME_MATERIALIZATION_LIFECYCLE_SCHEMA",
    "RUNTIME_MATERIALIZATION_REQUEST_SCHEMA",
    "RUNTIME_MATERIALIZATION_REQUEST_DISCARD_SCHEMA",
    "RUNTIME_MATERIALIZATION_SCHEMA",
    "RUNTIME_POSTPROCESS_RECONCILIATION_SCHEMA",
    "ClaudeRuntimeHostInputs",
    "ClaudeRuntimeMaterialization",
    "ClaudeRuntimeMaterializationError",
    "ClaudeRuntimeMaterializationRequest",
    "claude_runtime_argv_sha256",
    "claude_runtime_environment_key_set_sha256",
    "compile_claude_runtime_host_inputs",
    "compile_claude_runtime_materialization_request",
    "materialize_claude_runtime",
    "reconcile_claude_runtime_after_scope_close",
    "reconcile_claude_runtime_persisted_authority",
    "replay_claude_runtime_materialization",
    "replay_claude_runtime_lifecycle_receipt",
    "replay_claude_runtime_materialization_receipt",
    "replay_claude_runtime_postprocess_receipt",
    "replay_claude_runtime_request_discard_receipt",
]
