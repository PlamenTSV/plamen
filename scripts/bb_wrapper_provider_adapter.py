"""Receipt-owning BB post-audit provider adapter.

The private bounty wrapper selects this file only through the frozen public
runtime closure.  Both backends execute through the public WorkPlan/WER/
ArtifactLedger/PhaseIO substrate.  Claude policy is compiled here from the
public provider-preparation APIs; the private wrapper supplies semantic inputs
but owns no Claude command, auth-route, tool, stream, or runtime defaults.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import shutil
import stat
import subprocess
import threading
from typing import Any, Mapping
import uuid

from bb_path_authority import (
    BBPathAuthorityError,
    canonical_relative_name,
    publish_rooted_bytes,
    read_rooted_bytes,
    validate_directory_root,
)
from artifact_ledger import read_artifact_ledger, record_work_unit_inputs
from auxiliary_writable_root_startup import (
    load_and_replay_startup_receipt,
    reconcile_and_persist_startup_receipt,
)
from claude_launch_security import (
    ClaudeLaunchSecurityError,
    replay_mcp_current_selection,
)
from claude_provider_policy import (
    DEFAULT_AUTH_ROUTE as CLAUDE_DEFAULT_AUTH_ROUTE,
    ClaudeHeadlessProviderPolicy,
    ClaudeProviderPolicyError,
    compile_claude_headless_provider_authority,
    compile_standard_claude_headless_provider_policy,
)
from headless_worker_runtime import (
    execute_headless_worker,
    strict_nonempty_artifact_digest,
)
from phase_io_contracts import (
    ArtifactSpec,
    LaunchSpec,
    PhaseIOContract,
    canonical_work_unit_key,
)
from worker_execution_receipts import validate_completed_execution
from worker_transaction import validate_worker_execution_authority


BB_PROVIDER_ADAPTER_SCHEMA = "plamen.bb.selected-runtime-provider-adapter.v4"
BB_PROVIDER_INVOCATION_SCHEMA = "plamen.bb.provider-invocation.v2"
SUPPORTED_BACKENDS = ("claude", "codex")

_REQUEST_SCHEMA = "plamen.bb.provider-request.v4"
_REPLAY_SCHEMA = "plamen.bb.provider-invocation-replay.v1"
_PROVIDER_POLICY_SCHEMA = "plamen.bb.provider-policy.v1"
_ENVIRONMENT_AUTHORITY_SCHEMA = (
    "plamen.bb.provider-environment-authority.v1"
)
_HEX64 = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
_SEMANTIC_UNIT_SCHEMA = "plamen.bb.provider-semantic-unit.v2"
_SEMANTIC_REQUEST_NAMESPACE = uuid.UUID(
    "231c19fb-c85f-5a6b-9b5f-540ee5766712"
)
_MAX_PROVIDER_ATTEMPTS = 32
_REQUEST_FIELDS = {
    "schema",
    "request_id",
    "backend",
    "capability",
    "label",
    "model",
    "timeout_seconds",
    "run_id",
    "runtime_closure_sha256",
    "adapter_sha256",
    "scratchpad",
    "project_root",
    "cwd",
    "extra_add_dirs",
    "prompt_authority",
    "environment_allowlist",
    "environment_allowlist_sha256",
    "environment_semantic_authority_id",
    "environment_authority",
    "provider_policy",
}
_INVOCATION_RECEIPT_FIELDS = {
    "schema",
    "request_authority",
    "request_id",
    "backend",
    "model",
    "capability",
    "prompt_sha256",
    "cwd",
    "extra_add_dirs",
    "environment_allowlist_sha256",
    "environment_authority",
    "runtime_closure_sha256",
    "adapter_sha256",
    "provider_executable_sha256",
    "provider_argv_sha256",
    "wer_completion_authority",
    "attempt_authority",
    "output_authority",
    "incorporation_authority",
}
_ENVIRONMENT_AUTHORITY_FIELDS = {
    "schema",
    "authority_id",
    "backend",
    "environment_names",
    "environment_allowlist_sha256",
    "privacy_mode",
    "value_authority",
    "authority_sha256",
}
_ENVIRONMENT_CAPABILITY = object()
_ENVIRONMENT_ISSUANCE_LOCK = threading.Lock()
_ENVIRONMENT_ISSUANCE: dict[str, tuple[str, str]] = {}


def _installed_mcp_public_front_path() -> Path:
    leaf = "plamen.cmd" if os.name == "nt" else "plamen"
    return Path(os.path.abspath(os.path.expanduser(f"~/.local/bin/{leaf}")))


def _assert_bb_claude_mcp_selection_current(
    expected: Mapping[str, Any],
    *,
    timeout_seconds: int = 120,
) -> dict[str, Any]:
    """Re-authenticate the explicit BB selection immediately prelaunch."""

    try:
        expected_selection = replay_mcp_current_selection(expected)
        completed = subprocess.run(
            [
                os.fspath(_installed_mcp_public_front_path()),
                "mcp-selection",
                "--json",
                "--backend",
                "claude",
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=max(1, int(timeout_seconds)),
            check=False,
        )
        raw = completed.stdout
        if (
            completed.returncode != 0
            or completed.stderr != b""
            or not isinstance(raw, bytes)
            or not raw.endswith(b"\n")
            or raw.count(b"\n") != 1
        ):
            raise ValueError("installed MCP selection assertion was denied")
        observed = replay_mcp_current_selection(
            json.loads(raw[:-1].decode("utf-8"))
        )
        if raw != _canonical(observed) + b"\n":
            raise ValueError("installed MCP selection is not canonical")
    except (
        ClaudeLaunchSecurityError,
        json.JSONDecodeError,
        OSError,
        subprocess.SubprocessError,
        TypeError,
        UnicodeError,
        ValueError,
    ) as exc:
        raise ValueError(
            "BB Claude MCP runtime selection could not be authenticated"
        ) from exc
    if observed != expected_selection:
        raise ValueError(
            "BB Claude MCP runtime selection is no longer CURRENT"
        )
    return observed


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _replay_environment_authority_record(
    value: Any,
    *,
    backend: str | None = None,
) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError("BB provider environment authority is malformed")
    record = dict(value)
    core = dict(record)
    authority_sha256 = core.pop("authority_sha256", None)
    names = core.get("environment_names")
    if (
        set(record) != _ENVIRONMENT_AUTHORITY_FIELDS
        or record.get("schema") != _ENVIRONMENT_AUTHORITY_SCHEMA
        or record.get("privacy_mode")
        != "EPHEMERAL_UNLINKABLE_VALUES"
        or record.get("value_authority") != "PROCESS_LOCAL_ONE_SHOT"
        or record.get("backend") not in SUPPORTED_BACKENDS
        or (
            backend is not None
            and record.get("backend") != str(backend).strip().lower()
        )
        or not isinstance(names, list)
        or any(
            not isinstance(name, str)
            or not name
            or "=" in name
            or "\x00" in name
            for name in names
        )
        or sorted(set(names)) != names
        or len({name.casefold() for name in names}) != len(names)
        or record.get("environment_allowlist_sha256") != _digest(names)
        or not isinstance(authority_sha256, str)
        or _HEX64.fullmatch(authority_sha256) is None
        or _digest(core) != authority_sha256
    ):
        raise ValueError("BB provider environment authority does not replay")
    try:
        parsed = str(uuid.UUID(str(record.get("authority_id") or "")))
    except (ValueError, TypeError, AttributeError) as exc:
        raise ValueError(
            "BB provider environment authority ID is invalid"
        ) from exc
    if parsed != record["authority_id"]:
        raise ValueError(
            "BB provider environment authority ID is non-canonical"
        )
    return record


def compile_bb_provider_environment_record(
    *,
    backend: str,
    environment_names: Any,
) -> dict[str, Any]:
    """Mint a durable, unlinkable record containing no value-derived data."""

    normalized_backend = str(backend or "").strip().lower()
    if normalized_backend not in SUPPORTED_BACKENDS or isinstance(
        environment_names, (str, bytes)
    ):
        raise ValueError("BB provider environment record inputs are invalid")
    names = list(environment_names)
    if (
        any(not isinstance(name, str) for name in names)
        or sorted(set(names)) != names
        or len({name.casefold() for name in names}) != len(names)
        or any(not name or "=" in name or "\x00" in name for name in names)
    ):
        raise ValueError(
            "BB provider environment-name denominator is invalid"
        )
    core = {
        "schema": _ENVIRONMENT_AUTHORITY_SCHEMA,
        "authority_id": str(uuid.uuid4()),
        "backend": normalized_backend,
        "environment_names": names,
        "environment_allowlist_sha256": _digest(names),
        "privacy_mode": "EPHEMERAL_UNLINKABLE_VALUES",
        "value_authority": "PROCESS_LOCAL_ONE_SHOT",
    }
    record = _replay_environment_authority_record(
        {**core, "authority_sha256": _digest(core)},
        backend=normalized_backend,
    )
    with _ENVIRONMENT_ISSUANCE_LOCK:
        authority_id = record["authority_id"]
        if authority_id in _ENVIRONMENT_ISSUANCE:
            raise ValueError("BB provider environment authority ID collided")
        _ENVIRONMENT_ISSUANCE[authority_id] = (
            record["authority_sha256"],
            "MINTED",
        )
    return record


class BBProviderEnvironmentAuthority:
    """One-shot process-local environment values bound to a public record."""

    __slots__ = (
        "_record",
        "_value_bytes",
        "_key",
        "_tag",
        "_request_binding_sha256",
        "_state",
        "_lock",
    )

    def __init__(
        self,
        capability: object,
        *,
        record: Mapping[str, Any],
        environment: Mapping[str, str],
        request_binding: Mapping[str, Any],
    ) -> None:
        if capability is not _ENVIRONMENT_CAPABILITY:
            raise TypeError("BB provider environment authority is opaque")
        replayed = _replay_environment_authority_record(record)
        normalized = dict(environment)
        if (
            sorted(normalized) != replayed["environment_names"]
            or any(
                not isinstance(name, str)
                or not isinstance(value, str)
                or "\x00" in value
                for name, value in normalized.items()
            )
        ):
            raise ValueError(
                "BB provider environment values differ from public denominator"
            )
        self._record = replayed
        self._value_bytes = {
            name: bytearray(value.encode("utf-8"))
            for name, value in normalized.items()
        }
        self._key = bytearray(secrets.token_bytes(32))
        self._tag = bytearray(
            hmac.new(
                bytes(self._key),
                _canonical(
                    [
                        [name, normalized[name]]
                        for name in sorted(normalized)
                    ]
                ),
                hashlib.sha256,
            ).digest()
        )
        self._request_binding_sha256 = _digest(dict(request_binding))
        self._state = "PENDING"
        self._lock = threading.Lock()

    def __repr__(self) -> str:
        return "<BBProviderEnvironmentAuthority opaque>"

    def claim(
        self,
        *,
        expected_record: Mapping[str, Any],
        request_binding: Mapping[str, Any],
    ) -> dict[str, str]:
        with self._lock:
            if (
                self._state != "PENDING"
                or _replay_environment_authority_record(expected_record)
                != self._record
                or _digest(dict(request_binding))
                != self._request_binding_sha256
            ):
                raise ValueError(
                    "BB provider environment authority is wrong or already used"
                )
            authority_id = self._record["authority_id"]
            with _ENVIRONMENT_ISSUANCE_LOCK:
                expected_issuance = (
                    self._record["authority_sha256"],
                    "PREPARED",
                )
                if (
                    _ENVIRONMENT_ISSUANCE.get(authority_id)
                    != expected_issuance
                ):
                    raise ValueError(
                        "BB provider environment authority is wrong or "
                        "already used"
                    )
                _ENVIRONMENT_ISSUANCE[authority_id] = (
                    self._record["authority_sha256"],
                    "CLAIMED",
                )
            values = {
                name: bytes(raw).decode("utf-8", errors="strict")
                for name, raw in self._value_bytes.items()
            }
            observed = hmac.new(
                bytes(self._key),
                _canonical(
                    [[name, values[name]] for name in sorted(values)]
                ),
                hashlib.sha256,
            ).digest()
            if not hmac.compare_digest(observed, bytes(self._tag)):
                raise ValueError(
                    "BB provider environment authority integrity drifted"
                )
            self._state = "CLAIMED"
            return values

    def revoke(self) -> None:
        with self._lock:
            for raw in self._value_bytes.values():
                raw[:] = b"\x00" * len(raw)
            self._value_bytes.clear()
            self._key[:] = b"\x00" * len(self._key)
            self._tag[:] = b"\x00" * len(self._tag)
            self._state = "REVOKED"


def prepare_bb_provider_environment(
    *,
    record: Mapping[str, Any],
    environment: Mapping[str, str],
    request_binding: Mapping[str, Any],
) -> BBProviderEnvironmentAuthority:
    """Bind values to one durable record without serializing a value digest."""

    if not isinstance(environment, Mapping):
        raise ValueError("BB provider environment is malformed")
    authority = BBProviderEnvironmentAuthority(
        _ENVIRONMENT_CAPABILITY,
        record=record,
        environment=environment,
        request_binding=request_binding,
    )
    replayed = _replay_environment_authority_record(record)
    authority_id = replayed["authority_id"]
    accepted = False
    with _ENVIRONMENT_ISSUANCE_LOCK:
        if _ENVIRONMENT_ISSUANCE.get(authority_id) == (
            replayed["authority_sha256"],
            "MINTED",
        ):
            _ENVIRONMENT_ISSUANCE[authority_id] = (
                replayed["authority_sha256"],
                "PREPARED",
            )
            accepted = True
    if not accepted:
        authority.revoke()
        raise ValueError(
            "BB provider environment record is foreign, resumed, or "
            "already prepared"
        )
    return authority


def _compile_bb_provider_policy_bundle(
    *,
    backend: str,
    model: str,
    capability: str,
    mcp_runtime_selection: Mapping[str, Any] | None = None,
) -> tuple[dict[str, Any], ClaudeHeadlessProviderPolicy | None]:
    normalized_backend = str(backend or "").strip().lower()
    normalized_model = str(model or "").strip()
    normalized_capability = str(capability or "").strip()
    if (
        normalized_backend not in SUPPORTED_BACKENDS
        or not normalized_model
        or "\x00" in normalized_model
        or normalized_capability not in {"read_write", "fork_test"}
    ):
        raise ValueError("BB provider policy inputs are invalid")
    tool_policy = (
        ["filesystem", "network"]
        if normalized_capability == "fork_test"
        else []
    )
    claude_policy: ClaudeHeadlessProviderPolicy | None = None
    claude_record: dict[str, Any] | None = None
    if normalized_backend == "claude":
        if not isinstance(mcp_runtime_selection, Mapping):
            raise ValueError(
                "BB Claude provider requires an authenticated immutable MCP "
                "runtime selection"
            )
        claude_policy = (
            compile_standard_claude_headless_provider_policy(
                phase="provider",
                launch_model=normalized_model,
                ecosystem=(
                    "evm"
                    if normalized_capability == "fork_test"
                    else "generic"
                ),
                tool_policy=tool_policy,
                desired_auth_route=CLAUDE_DEFAULT_AUTH_ROUTE,
                mcp_runtime_selection=mcp_runtime_selection,
            )
        )
        claude_record = {
            "phase": claude_policy.phase,
            "launch_model": claude_policy.launch_model,
            "accepted_models": list(claude_policy.accepted_models),
            "desired_auth_route": claude_policy.desired_auth_route,
            "max_line_bytes": claude_policy.max_line_bytes,
            "max_stream_bytes": claude_policy.max_stream_bytes,
            "home_variable_policy": (
                claude_policy.home_variable_policy
            ),
            "phase_environment_policies": list(
                claude_policy.phase_environment_policies
            ),
            "functional_controls": dict(
                claude_policy.functional_controls
            ),
            "required_capabilities": list(
                claude_policy.required_capabilities
            ),
            "forbidden_capabilities": list(
                claude_policy.forbidden_capabilities
            ),
            "accepted_output_styles": list(
                claude_policy.accepted_output_styles
            ),
            "phase_tool_policy": dict(
                claude_policy.phase_tool_policy
            ),
            "settings_policy": dict(claude_policy.settings_policy),
            "mcp_policy": dict(claude_policy.mcp_policy),
        }
    unsigned = {
        "schema": _PROVIDER_POLICY_SCHEMA,
        "backend": normalized_backend,
        "model": normalized_model,
        "capability": normalized_capability,
        "tool_policy": tool_policy,
        "reasoning_effort": (
            "xhigh" if normalized_backend == "codex" else None
        ),
        "claude_policy": claude_record,
    }
    return (
        {
            **unsigned,
            "policy_sha256": _digest(unsigned),
        },
        claude_policy,
    )


def compile_bb_provider_policy(
    *,
    backend: str,
    model: str,
    capability: str,
    mcp_runtime_selection: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Return the exact secret-free request policy owned by public runtime."""

    record, _claude_policy = _compile_bb_provider_policy_bundle(
        backend=backend,
        model=model,
        capability=capability,
        mcp_runtime_selection=mcp_runtime_selection,
    )
    return record


def _replay_bb_provider_policy(
    request: Mapping[str, Any],
) -> tuple[dict[str, Any], ClaudeHeadlessProviderPolicy | None]:
    observed = request.get("provider_policy")
    observed_selection: Mapping[str, Any] | None = None
    if isinstance(observed, Mapping):
        claude_policy_record = observed.get("claude_policy")
        if isinstance(claude_policy_record, Mapping):
            mcp_policy_record = claude_policy_record.get("mcp_policy")
            if isinstance(mcp_policy_record, Mapping):
                candidate = mcp_policy_record.get("runtime_selection")
                if isinstance(candidate, Mapping):
                    observed_selection = candidate
    expected, claude_policy = _compile_bb_provider_policy_bundle(
        backend=str(request.get("backend") or ""),
        model=str(request.get("model") or ""),
        capability=str(request.get("capability") or ""),
        mcp_runtime_selection=observed_selection,
    )
    if not isinstance(observed, Mapping) or dict(observed) != expected:
        raise ValueError("BB provider policy authority does not replay")
    return expected, claude_policy


def _wer_digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value) + b"\n").hexdigest()


def _is_reparse(path: Path, row: os.stat_result | None = None) -> bool:
    current = row or path.lstat()
    return bool(int(getattr(current, "st_file_attributes", 0)) & 0x400)


def _stable_regular(path: Path, *, label: str) -> bytes:
    before = path.lstat()
    if (
        path.is_symlink()
        or _is_reparse(path, before)
        or not stat.S_ISREG(before.st_mode)
        or int(getattr(before, "st_nlink", 1)) != 1
        or before.st_size > 64 * 1024 * 1024
    ):
        raise ValueError(f"{label} is not a single-link regular file")
    raw = path.read_bytes()
    after = path.lstat()
    if (
        (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
        )
        != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        )
        or len(raw) != after.st_size
        or int(getattr(after, "st_nlink", 1)) != 1
    ):
        raise ValueError(f"{label} changed during stable read")
    return raw


def _relative_file(
    scratchpad: Path,
    authority: Mapping[str, Any],
    *,
    label: str,
) -> tuple[Path, str, bytes]:
    if not isinstance(authority, Mapping) or set(authority) != {
        "relative_path",
        "sha256",
    }:
        raise ValueError(f"{label} authority is malformed")
    relative = str(authority.get("relative_path") or "")
    digest = str(authority.get("sha256") or "").lower()
    if (
        not relative
        or _HEX64.fullmatch(digest) is None
    ):
        raise ValueError(f"{label} authority path/digest is invalid")
    try:
        canonical_relative_name(relative)
        raw = read_rooted_bytes(
            scratchpad,
            relative,
            label=label,
            max_bytes=64 * 1024 * 1024,
        )
    except BBPathAuthorityError as exc:
        raise ValueError(f"{label} authority is unsafe: {exc}") from exc
    if hashlib.sha256(raw).hexdigest() != digest:
        raise ValueError(f"{label} authority digest mismatch")
    return (
        scratchpad.joinpath(*PurePosixPath(relative).parts),
        digest,
        raw,
    )


def _authority(scratchpad: Path, path: Path, digest: str | None = None) -> dict:
    try:
        relative = path.relative_to(scratchpad).as_posix()
        canonical_relative_name(relative)
        raw = read_rooted_bytes(
            scratchpad,
            relative,
            label="provider authority",
            max_bytes=64 * 1024 * 1024,
        )
    except (ValueError, BBPathAuthorityError) as exc:
        raise ValueError("provider authority escapes scratchpad")
    actual = hashlib.sha256(raw).hexdigest()
    if digest is not None and actual != digest:
        raise ValueError("provider authority digest differs from typed handle")
    return {
        "relative_path": relative,
        "sha256": actual,
    }


def _write_absent(
    root: Path,
    relative: str,
    raw: bytes,
    *,
    replay_exact: bool = False,
) -> str:
    try:
        return publish_rooted_bytes(
            root,
            relative,
            raw,
            label="BB provider immutable artifact",
            replay_exact=replay_exact,
            max_bytes=64 * 1024 * 1024,
        ).sha256
    except BBPathAuthorityError as exc:
        raise ValueError(
            f"BB provider immutable publication failed: {exc}"
        ) from exc


def _semantic_payload(request: Mapping[str, Any]) -> dict[str, Any]:
    prompt = request.get("prompt_authority")
    if not isinstance(prompt, Mapping):
        raise ValueError("BB provider prompt authority is malformed")
    return {
        "schema": _SEMANTIC_UNIT_SCHEMA,
        "run_id": request.get("run_id"),
        "runtime_closure_sha256": request.get("runtime_closure_sha256"),
        "adapter_sha256": request.get("adapter_sha256"),
        "backend": request.get("backend"),
        "capability": request.get("capability"),
        "label": request.get("label"),
        "model": request.get("model"),
        "timeout_seconds": request.get("timeout_seconds"),
        "scratchpad": request.get("scratchpad"),
        "project_root": request.get("project_root"),
        "cwd": request.get("cwd"),
        "extra_add_dirs": request.get("extra_add_dirs"),
        "prompt_sha256": prompt.get("sha256"),
        "prompt_size": prompt.get("size"),
        "environment_allowlist": request.get("environment_allowlist"),
        "environment_allowlist_sha256": request.get(
            "environment_allowlist_sha256"
        ),
        "environment_semantic_authority_id": request.get(
            "environment_semantic_authority_id"
        ),
        "provider_policy": request.get("provider_policy"),
    }


def _semantic_request_identity(
    request: Mapping[str, Any],
    request_relative: str,
) -> tuple[str, int, str]:
    parts = PurePosixPath(request_relative).parts
    if (
        len(parts) != 4
        or parts[0] != ".bb_provider_requests"
        or _HEX64.fullmatch(parts[1]) is None
        or not parts[2].isdigit()
        or str(int(parts[2])) != parts[2]
        or parts[3] != "request.json"
    ):
        raise ValueError("BB provider request semantic path is invalid")
    attempt = int(parts[2])
    if attempt < 0 or attempt >= _MAX_PROVIDER_ATTEMPTS:
        raise ValueError("BB provider request attempt is out of range")
    semantic_sha = _digest(_semantic_payload(request))
    if semantic_sha != parts[1]:
        raise ValueError("BB provider semantic request digest differs")
    expected_id = str(
        uuid.uuid5(
            _SEMANTIC_REQUEST_NAMESPACE,
            f"{semantic_sha}:{attempt}",
        )
    )
    return semantic_sha, attempt, expected_id


def _request(
    request_authority: Mapping[str, Any],
) -> tuple[Path, Path, dict[str, Any], dict[str, Any], str]:
    if not isinstance(request_authority, Mapping) or set(request_authority) != {
        "scratchpad",
        "relative_path",
        "sha256",
    }:
        raise ValueError("BB provider request authority is malformed")
    try:
        scratchpad = validate_directory_root(
            str(request_authority["scratchpad"]),
            label="BB provider scratchpad",
        )
    except BBPathAuthorityError as exc:
        raise ValueError("BB provider scratchpad is unsafe")
    request_ref = {
        "relative_path": request_authority["relative_path"],
        "sha256": request_authority["sha256"],
    }
    request_path, request_sha, request_raw = _relative_file(
        scratchpad, request_ref, label="BB provider request"
    )
    request = json.loads(
        request_raw.decode("utf-8", errors="strict")
    )
    if (
        not isinstance(request, dict)
        or set(request) != _REQUEST_FIELDS
        or request.get("schema") != _REQUEST_SCHEMA
        or request.get("backend") not in SUPPORTED_BACKENDS
        or request.get("capability") not in {"read_write", "fork_test"}
        or not isinstance(request.get("timeout_seconds"), int)
        or isinstance(request.get("timeout_seconds"), bool)
        or int(request["timeout_seconds"]) <= 0
        or _HEX64.fullmatch(str(request.get("runtime_closure_sha256") or ""))
        is None
        or _HEX64.fullmatch(str(request.get("adapter_sha256") or "")) is None
    ):
        raise ValueError("BB provider request schema/values are invalid")
    if _canonical(request) != request_raw:
        raise ValueError("BB provider request is not canonical JSON")
    _replay_bb_provider_policy(request)
    environment_authority = _replay_environment_authority_record(
        request.get("environment_authority"),
        backend=str(request["backend"]),
    )
    if (
        environment_authority["environment_names"]
        != request["environment_allowlist"]
        or environment_authority["environment_allowlist_sha256"]
        != request["environment_allowlist_sha256"]
    ):
        raise ValueError(
            "BB provider environment authority denominator differs"
        )
    if request["adapter_sha256"] != hashlib.sha256(
        _stable_regular(Path(__file__).resolve(), label="BB provider adapter")
    ).hexdigest():
        raise ValueError("BB provider adapter bytes differ from request")
    try:
        request_id = str(uuid.UUID(str(request["request_id"])))
        environment_semantic_authority_id = str(
            uuid.UUID(
                str(request["environment_semantic_authority_id"])
            )
        )
    except (ValueError, TypeError, AttributeError) as exc:
        raise ValueError(
            "BB provider request identity is not a canonical UUID"
        ) from exc
    semantic_sha, attempt, expected_request_id = (
        _semantic_request_identity(
            request,
            str(request_ref["relative_path"]),
        )
    )
    expected_request = (
        f".bb_provider_requests/{semantic_sha}/{attempt}/request.json"
    )
    expected_prompt = (
        f".bb_provider_requests/{semantic_sha}/{attempt}/prompt.md"
    )
    if (
        request["request_id"] != request_id
        or request["environment_semantic_authority_id"]
        != environment_semantic_authority_id
        or request_id != expected_request_id
        or request_ref["relative_path"] != expected_request
    ):
        raise ValueError("BB provider request path identity differs")
    try:
        project = validate_directory_root(
            str(request["project_root"]),
            label="BB provider project root",
        )
        cwd = validate_directory_root(
            str(request["cwd"]),
            label="BB provider cwd",
        )
    except BBPathAuthorityError as exc:
        raise ValueError(f"BB provider request root is unsafe: {exc}") from exc
    if (
        str(scratchpad) != request["scratchpad"]
        or not project.is_dir()
        or not cwd.is_dir()
        or not cwd.is_relative_to(project)
    ):
        raise ValueError("BB provider request roots/cwd are inconsistent")
    prompt_ref = request.get("prompt_authority")
    if (
        not isinstance(prompt_ref, Mapping)
        or set(prompt_ref) != {"relative_path", "sha256", "size"}
        or prompt_ref.get("relative_path") != expected_prompt
    ):
        raise ValueError("BB provider prompt authority is malformed")
    prompt_path, prompt_sha, _prompt_raw = _relative_file(
        scratchpad,
        {
            "relative_path": prompt_ref["relative_path"],
            "sha256": prompt_ref["sha256"],
        },
        label="BB provider prompt",
    )
    if prompt_path.stat().st_size != prompt_ref["size"]:
        raise ValueError("BB provider prompt size differs")
    normalized_add_dirs: list[str] = []
    for value in request.get("extra_add_dirs") or []:
        try:
            resolved = validate_directory_root(
                str(value),
                label="BB provider add-dir",
            )
        except BBPathAuthorityError:
            raise ValueError("BB provider add-dir is unsafe")
        normalized_add_dirs.append(str(resolved))
    if sorted(set(normalized_add_dirs)) != request["extra_add_dirs"]:
        raise ValueError("BB provider add-dir denominator is not canonical")
    return scratchpad, project, request, dict(request_ref), prompt_sha


def _contract_launch(
    request: Mapping[str, Any],
) -> tuple[PhaseIOContract, LaunchSpec, str]:
    request_id = str(request["request_id"])
    backend = str(request["backend"])
    compact_id = hashlib.sha256(request_id.encode("ascii")).hexdigest()[:16]
    work_unit_id = f"q-{compact_id}"
    key = canonical_work_unit_key(
        "bb",
        "post-audit",
        "generic",
        backend,
        "provider",
        work_unit_id,
    )
    output_relative = f".bb_o/{compact_id}.txt"
    prompt_relative = str(request["prompt_authority"]["relative_path"])
    request_relative = str(
        PurePosixPath(prompt_relative).with_name("request.json")
    )
    contract = PhaseIOContract(
        pipeline="bb",
        mode="post-audit",
        ecosystem="generic",
        backend=backend,
        phase="provider",
        work_unit_id=work_unit_id,
        outputs=(
            ArtifactSpec(
                root="scratchpad",
                path=output_relative,
                owner_key=key,
                artifact_class="REQUIRED",
                writer="MODEL",
                write_mode="CREATE",
                schema_version="plamen.bb.provider-output.v1",
                minimum_gate="STRICT_NONEMPTY_UTF8",
            ),
        ),
        immutable_inputs=(
            "scratchpad:" + prompt_relative,
            "scratchpad:" + request_relative,
        ),
    )
    launch = LaunchSpec(
        work_unit_key=contract.key,
        pipeline="bb",
        mode="post-audit",
        ecosystem="generic",
        backend=backend,
        model=str(request["model"]),
        timeout_s=int(request["timeout_seconds"]),
        exec_mode="headless",
        tool_policy=(
            ("filesystem", "network")
            if request["capability"] == "fork_test"
            else ()
        ),
    )
    return contract, launch, output_relative


def _startup_binding(scratchpad: Path, run_id: str) -> dict[str, Any]:
    receipt = reconcile_and_persist_startup_receipt(
        scratchpad=scratchpad,
        run_id=run_id,
    )
    replay = load_and_replay_startup_receipt(
        scratchpad=scratchpad,
        expected_run_id=run_id,
        expected_startup_epoch=str(receipt["startup_epoch"]),
    )
    if (
        replay.get("valid") is not True
        or replay.get("allocation_permitted") is not True
        or not isinstance(replay.get("binding"), dict)
    ):
        raise ValueError("BB provider startup authority denies worker launch")
    return dict(replay["binding"])


def _claude_source_config_directory(
    environment: Mapping[str, str],
) -> Path:
    configured = str(environment.get("CLAUDE_CONFIG_DIR") or "").strip()
    if configured:
        lexical = Path(configured)
    else:
        home = str(
            environment.get("HOME")
            or environment.get("USERPROFILE")
            or ""
        ).strip()
        if not home:
            raise ValueError(
                "BB Claude provider lacks an explicit source home authority"
            )
        lexical = Path(home) / ".claude"
    if not lexical.is_absolute():
        raise ValueError(
            "BB Claude source config directory must be absolute"
        )
    try:
        resolved = lexical.resolve(strict=True)
        metadata = resolved.lstat()
    except OSError as exc:
        raise ValueError(
            "BB Claude source config directory is unavailable"
        ) from exc
    if (
        not resolved.is_dir()
        or resolved.is_symlink()
        or _is_reparse(resolved, metadata)
    ):
        raise ValueError(
            "BB Claude source config directory is unsafe"
        )
    return resolved


def _compile_claude_provider_authority(
    request: Mapping[str, Any],
    environment: Mapping[str, str],
    *,
    scratchpad: Path,
    project: Path,
    startup_authority_binding: Mapping[str, Any],
) -> dict[str, Any]:
    """Bind the shared public Claude policy to one BB runtime request."""

    cwd = Path(str(request["cwd"])).resolve(strict=True)
    _policy_record, policy = _replay_bb_provider_policy(request)
    if policy is None:
        raise ValueError("BB Claude request lacks Claude policy authority")
    source_config_dir = (
        _claude_source_config_directory(environment)
        if policy.desired_auth_route == "STORED_SUBSCRIPTION_OAUTH"
        else None
    )
    ambient_environment = dict(environment)
    deterministic_bindings = {
        "PLAMEN_AUDIT_ROOT": str(project),
        "PLAMEN_RUN_ID": str(request["run_id"]),
        "PLAMEN_SCRATCHPAD": str(scratchpad),
    }
    for name, value in deterministic_bindings.items():
        prior = ambient_environment.get(name)
        if prior is not None and prior != value:
            raise ValueError(
                f"BB Claude ambient {name} conflicts with runtime authority"
            )
        ambient_environment[name] = value

    session_id = str(
        uuid.uuid5(
            uuid.NAMESPACE_URL,
            "plamen-bb-claude-stream-v1:"
            + str(request["request_id"]),
        )
    )
    trusted_cwds = tuple(
        dict.fromkeys([
            cwd,
            *(
                Path(str(value)).resolve(strict=True)
                for value in request["extra_add_dirs"]
            ),
        ])
    )
    try:
        authority = compile_claude_headless_provider_authority(
            policy=policy,
            run_id=str(request["run_id"]),
            cwd=cwd,
            session_id=session_id,
            configured_claude_bin=os.fspath(
                _installed_mcp_public_front_path()
            ),
            ambient_environment=ambient_environment,
            settings_evidence={},
            stored_subscription_source_path=(
                None
                if source_config_dir is None
                else source_config_dir / ".credentials.json"
            ),
            source_config_dir=source_config_dir,
            project_root=project,
            trusted_cwds=trusted_cwds,
            startup_authority_binding=startup_authority_binding,
            startup_scratchpad=scratchpad,
            source_snapshot_sha256=str(
                request["runtime_closure_sha256"]
            ),
        )
    except ClaudeProviderPolicyError as exc:
        raise ValueError(
            f"BB Claude provider preparation failed: {exc}"
        ) from exc
    return {
        "policy": policy,
        "preparation": authority.preparation,
        "public_arguments": authority.public_arguments,
        "runtime_local_inputs": authority.runtime_local_inputs,
        "bound_settings_bytes": authority.bound_settings_bytes,
        "selected_mcp_config_bytes": (
            authority.selected_mcp_config_bytes
        ),
        "command_template": authority.base_argv_template,
    }


def _claude_command_builder(
    authority: Mapping[str, Any],
):
    template = tuple(authority["command_template"])

    def build(output_directory: Path) -> list[str]:
        del output_directory
        return [str(value) for value in template]

    return build


def _codex_executable(environment: Mapping[str, str]) -> Path:
    path_value = environment.get("PATH")
    override = str(environment.get("CODEX_BIN") or "").strip()
    if not path_value and not override:
        raise ValueError("BB Codex provider requires exact PATH authority")
    if override and Path(override).is_absolute():
        found = override
    else:
        found = shutil.which(override or "codex", path=path_value)
    if found is None:
        raise ValueError("Codex executable is unavailable from exact PATH")
    resolved = Path(found).resolve(strict=True)
    if not resolved.is_file() or resolved.is_symlink() or _is_reparse(resolved):
        raise ValueError("Codex executable is not a safe regular file")
    return resolved


def _command_builder(
    request: Mapping[str, Any],
    environment: Mapping[str, str],
):
    executable = _codex_executable(environment)
    capability = str(request["capability"])
    add_dirs = [
        str(Path(request["cwd"]).resolve(strict=True)),
        *list(request["extra_add_dirs"]),
    ]

    def build(output_directory: Path) -> list[str]:
        argv = [
            str(executable),
            "exec",
            "--model",
            str(request["model"]),
            "--ephemeral",
            "--skip-git-repo-check",
            "--ignore-user-config",
            "--ignore-rules",
            "--sandbox",
            "workspace-write",
            "-c",
            (
                "model_reasoning_effort="
                + json.dumps(
                    request["provider_policy"]["reasoning_effort"]
                )
            ),
        ]
        directories = (
            (*add_dirs, str(output_directory))
            if capability == "fork_test"
            else (str(output_directory),)
        )
        for directory in sorted(set(directories)):
            argv.extend(["--add-dir", directory])
        argv.append("-")
        return argv

    return build


def _invoke_bb_provider_with_environment(
    request_authority: Mapping[str, Any],
    *,
    environment: Mapping[str, str],
) -> dict[str, Any]:
    scratchpad, project, request, request_ref, prompt_sha = _request(
        request_authority
    )
    if (
        not isinstance(environment, Mapping)
        or any(
            not isinstance(key, str)
            or not isinstance(value, str)
            or "\x00" in key
            or "\x00" in value
            for key, value in environment.items()
        )
    ):
        raise ValueError("BB provider environment is malformed")
    names = sorted(environment)
    if (
        names != request["environment_allowlist"]
        or _digest(names) != request["environment_allowlist_sha256"]
    ):
        raise ValueError("BB provider environment differs from request authority")
    contract, launch, output_relative = _contract_launch(request)
    if request["backend"] == "claude":
        _policy_record, admission_policy = _replay_bb_provider_policy(
            request
        )
        if admission_policy is None:
            raise ValueError(
                "BB Claude request lacks Claude policy authority"
            )
        selection = admission_policy.mcp_policy.get(
            "runtime_selection"
        )
        if not isinstance(selection, Mapping):
            raise ValueError(
                "BB Claude request lacks immutable MCP runtime selection"
            )
        _assert_bb_claude_mcp_selection_current(selection)
    startup_authority_binding = _startup_binding(
        scratchpad, str(request["run_id"])
    )
    claude_authority: dict[str, Any] | None = None
    if request["backend"] == "claude":
        claude_authority = _compile_claude_provider_authority(
            request,
            environment,
            scratchpad=scratchpad,
            project=project,
            startup_authority_binding=startup_authority_binding,
        )
    record_work_unit_inputs(
        scratchpad,
        project,
        contract,
        launch,
        run_id=str(request["run_id"]),
    )
    _prompt_path, _, prompt_raw = _relative_file(
        scratchpad,
        {
            "relative_path": request["prompt_authority"]["relative_path"],
            "sha256": prompt_sha,
        },
        label="BB provider prompt",
    )
    prompt = prompt_raw.decode(
        "utf-8", errors="strict"
    )
    if claude_authority is None:
        command_builder = _command_builder(request, environment)
        execution_environment: Mapping[str, str] = dict(environment)
        execution_allowlist = tuple(names)
        claude_kwargs: dict[str, Any] = {}
    else:
        public = claude_authority["public_arguments"]
        command_builder = _claude_command_builder(
            claude_authority,
        )
        execution_environment = {}
        execution_allowlist = tuple(public["environment_allowlist"])
        claude_kwargs = {
            "provider_stdout_evidence_configuration": public[
                "provider_stdout_evidence_configuration"
            ],
            "claude_launch_security": public[
                "claude_launch_security"
            ],
            "claude_launch_security_request": public[
                "claude_launch_security_request"
            ],
            "claude_provider_preparation": claude_authority[
                "preparation"
            ],
            "claude_runtime_local_inputs": claude_authority[
                "runtime_local_inputs"
            ],
            "claude_bound_settings_bytes": claude_authority[
                "bound_settings_bytes"
            ],
            "claude_selected_mcp_config_bytes": claude_authority[
                "selected_mcp_config_bytes"
            ],
        }
    result = execute_headless_worker(
        scratchpad=scratchpad,
        project_root=project,
        run_id=str(request["run_id"]),
        phase_io_contract=contract,
        phase_io_launch=launch,
        prompt=prompt,
        command_builder=command_builder,
        cwd=Path(request["cwd"]),
        environment=execution_environment,
        environment_allowlist=execution_allowlist,
        source_snapshot_digest=str(request["runtime_closure_sha256"]),
        methodology_digests=(prompt_sha,),
        startup_authority_binding=startup_authority_binding,
        parser_digest=strict_nonempty_artifact_digest,
        **claude_kwargs,
    )
    try:
        staged_output_raw = read_rooted_bytes(
            scratchpad,
            output_relative,
            label="BB staged provider output",
            max_bytes=64 * 1024 * 1024,
        )
    except BBPathAuthorityError as exc:
        raise ValueError(f"BB staged provider output is unsafe: {exc}") from exc
    output_relative_final = (
        ".bb_provider_outputs/"
        + str(request["request_id"])
        + "/output.txt"
    )
    _write_absent(
        scratchpad,
        output_relative_final,
        staged_output_raw,
        replay_exact=True,
    )
    output_path = scratchpad.joinpath(
        *PurePosixPath(output_relative_final).parts
    )
    output_raw = staged_output_raw
    arm_path = result.execution.provider_execution.arm_path
    arm_ref = _authority(scratchpad, arm_path)
    _arm_path, _arm_sha, arm_raw = _relative_file(
        scratchpad,
        arm_ref,
        label="WER arm",
    )
    arm = json.loads(arm_raw)
    process_intent = arm.get("process_intent")
    environment_binding = arm.get("environment")
    if (
        not isinstance(process_intent, dict)
        or not isinstance(environment_binding, dict)
        or process_intent.get("executable_sha256")
        != hashlib.sha256(
            _stable_regular(
                Path(process_intent["resolved_executable"]),
                label="provider executable",
            )
        ).hexdigest()
    ):
        raise ValueError("WER provider process authority differs from request")
    if request["backend"] == "codex":
        if (
            environment_binding.get("allowlist_sha256")
            != _wer_digest(names)
            or environment_binding.get("effective_sha256")
            != _wer_digest([[key, environment[key]] for key in names])
        ):
            raise ValueError(
                "WER Codex environment authority differs from request"
            )
    elif (
        environment_binding.get("allowlist_sha256")
        != _wer_digest(list(execution_allowlist))
    ):
        raise ValueError(
            "WER Claude environment denominator differs from public parent"
        )
    attempt_path = result.execution.attempt_completion_path
    attempt_ref = _authority(scratchpad, attempt_path)
    _attempt_path, _attempt_sha, attempt_raw = _relative_file(
        scratchpad,
        attempt_ref,
        label="attempt completion",
    )
    attempt = json.loads(attempt_raw)
    receipt = {
        "schema": BB_PROVIDER_INVOCATION_SCHEMA,
        "request_authority": request_ref,
        "request_id": request["request_id"],
        "backend": request["backend"],
        "model": request["model"],
        "capability": request["capability"],
        "prompt_sha256": prompt_sha,
        "cwd": request["cwd"],
        "extra_add_dirs": request["extra_add_dirs"],
        "environment_allowlist_sha256": request[
            "environment_allowlist_sha256"
        ],
        "environment_authority": request["environment_authority"],
        "runtime_closure_sha256": request["runtime_closure_sha256"],
        "adapter_sha256": request["adapter_sha256"],
        "provider_executable_sha256": process_intent[
            "executable_sha256"
        ],
        "provider_argv_sha256": process_intent["argv_sha256"],
        "wer_completion_authority": _authority(
            scratchpad,
            result.execution.provider_execution.receipt_path,
        ),
        "attempt_authority": _authority(
            scratchpad,
            attempt_path,
        ),
        "output_authority": _authority(scratchpad, output_path),
        "incorporation_authority": _authority(
            scratchpad,
            result.incorporation.incorporation_path,
        ),
    }
    invocation_relative = (
        ".bb_provider_receipts/"
        + str(request["request_id"])
        + "/invocation.json"
    )
    invocation_sha = _write_absent(
        scratchpad,
        invocation_relative,
        _canonical(receipt),
        replay_exact=True,
    )
    return {
        "schema": BB_PROVIDER_INVOCATION_SCHEMA,
        "request_id": request["request_id"],
        "invocation_authority": {
            "relative_path": invocation_relative,
            "sha256": invocation_sha,
        },
        "output_authority": receipt["output_authority"],
    }


def invoke_bb_provider(
    request_authority: Mapping[str, Any],
    *,
    environment_authority: BBProviderEnvironmentAuthority,
) -> dict[str, Any]:
    """Claim one opaque environment and revoke it on every terminal path."""

    if type(environment_authority) is not BBProviderEnvironmentAuthority:
        raise ValueError(
            "BB provider requires an exact process-local environment authority"
        )
    environment: dict[str, str] = {}
    try:
        _root, _project, request, request_ref, _prompt_sha = _request(
            request_authority
        )
        environment = environment_authority.claim(
            expected_record=request["environment_authority"],
            request_binding={
                "request_authority": dict(request_authority),
                "request_id": request["request_id"],
                "run_id": request["run_id"],
            },
        )
        if request["backend"] == "codex" and environment:
            raise ValueError(
                "CODEX_EPHEMERAL_ENVIRONMENT_REAUTHORIZATION_REQUIRED: "
                "non-empty Codex environments require the shared opaque WTx "
                "cutover before BB execution"
            )
        return _invoke_bb_provider_with_environment(
            request_authority,
            environment=environment,
        )
    finally:
        for name in tuple(environment):
            environment[name] = ""
        environment.clear()
        environment_authority.revoke()


def replay_bb_provider_invocation(
    invocation_authority: Mapping[str, Any],
    *,
    scratchpad: str | Path,
) -> dict[str, Any]:
    try:
        root = validate_directory_root(
            scratchpad,
            label="BB provider replay scratchpad",
        )
    except BBPathAuthorityError as exc:
        raise ValueError(f"BB provider replay scratchpad is unsafe: {exc}") from exc
    invocation_path, _, invocation_raw = _relative_file(
        root, invocation_authority, label="BB provider invocation"
    )
    receipt = json.loads(
        invocation_raw.decode("utf-8", errors="strict")
    )
    if (
        not isinstance(receipt, dict)
        or set(receipt) != _INVOCATION_RECEIPT_FIELDS
        or receipt.get("schema") != BB_PROVIDER_INVOCATION_SCHEMA
        or _canonical(receipt) != invocation_raw
    ):
        raise ValueError(
            "BB provider invocation receipt is not exact canonical schema"
        )
    request_path, _, _request_raw = _relative_file(
        root, receipt["request_authority"], label="BB provider request"
    )
    request_authority = {
        "scratchpad": str(root),
        **receipt["request_authority"],
    }
    checked_root, project, request, _request_ref, prompt_sha = _request(
        request_authority
    )
    if checked_root != root:
        raise ValueError("BB provider replay scratchpad differs")
    contract, launch, output_relative = _contract_launch(request)
    completion_path, _completion_file_sha, completion_raw = _relative_file(
        root,
        receipt["wer_completion_authority"],
        label="WER completion",
    )
    completion = json.loads(
        completion_raw
    )
    validate_completed_execution(
        scratchpad=root,
        receipt_path=completion_path,
        publish_receipt_path=None,
        parser_digest=strict_nonempty_artifact_digest,
        expected_completion_sha256=str(completion["completion_sha256"]),
        expected_publish_sha256=None,
    )
    unit = read_artifact_ledger(root).get("work_units", {}).get(contract.key)
    authority = (
        unit.get("execution_authority")
        if isinstance(unit, dict)
        else None
    )
    validated = validate_worker_execution_authority(
        scratchpad=root,
        authority=authority,
        contract=contract,
        launch=launch,
        run_id=str(request["run_id"]),
    )
    incorporation_path, _incorporation_file_sha, incorporation_raw = _relative_file(
        root,
        receipt["incorporation_authority"],
        label="PhaseIO incorporation",
    )
    incorporation = json.loads(
        incorporation_raw
    )
    if (
        validated["incorporation_relative_path"]
        != incorporation_path.relative_to(root).as_posix()
        or validated["incorporation_digest"]
        != incorporation.get("incorporation_digest")
    ):
        raise ValueError("PhaseIO incorporation differs from execution authority")
    output_path, output_sha, output_raw = _relative_file(
        root, receipt["output_authority"], label="BB provider output"
    )
    expected_output_relative = (
        ".bb_provider_outputs/"
        + str(request["request_id"])
        + "/output.txt"
    )
    if output_path != root.joinpath(
        *PurePosixPath(expected_output_relative).parts
    ):
        raise ValueError("BB provider output differs from PhaseIO contract")
    try:
        staged_output_raw = read_rooted_bytes(
            root,
            output_relative,
            label="BB staged provider output",
            max_bytes=64 * 1024 * 1024,
        )
    except BBPathAuthorityError as exc:
        raise ValueError(f"BB staged provider output is unsafe: {exc}") from exc
    if (
        hashlib.sha256(output_raw).hexdigest() != output_sha
        or staged_output_raw != output_raw
        or receipt["prompt_sha256"] != prompt_sha
        or receipt["backend"] != request["backend"]
        or receipt["model"] != request["model"]
        or receipt["capability"] != request["capability"]
        or receipt["environment_authority"]
        != request["environment_authority"]
    ):
        raise ValueError("BB provider invocation/request binding differs")
    return {
        "schema": _REPLAY_SCHEMA,
        "invocation_authority": dict(invocation_authority),
        "request_id": receipt["request_id"],
        "backend": receipt["backend"],
        "model": receipt["model"],
        "capability": receipt["capability"],
        "request_authority": receipt["request_authority"],
        "output_authority": receipt["output_authority"],
        "output": output_raw.decode("utf-8", errors="strict"),
    }


__all__ = [
    "BB_PROVIDER_ADAPTER_SCHEMA",
    "BB_PROVIDER_INVOCATION_SCHEMA",
    "SUPPORTED_BACKENDS",
    "BBProviderEnvironmentAuthority",
    "compile_bb_provider_environment_record",
    "compile_bb_provider_policy",
    "invoke_bb_provider",
    "prepare_bb_provider_environment",
    "replay_bb_provider_invocation",
]
