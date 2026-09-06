"""Provider-owned transport for independent skeptic assessments.

The model receives one immutable JSON packet on stdin and has no filesystem or
MCP tools.  Its only output channel is raw stdout.  ``worker_execution_receipts``
owns child creation, bounded stream capture, process-scope termination, staging,
strict parsing, content-addressed completion evidence, and canonical publication.

This adapter supplies the skeptic-specific semantic bindings.  It does not infer
execution from model-authored files and it does not use a filesystem diff as an
authority boundary.  A transport can be eligible to support a terminal negative
only when its backend profile is exact *and* the provider reports exhaustive
process-scope authority.  Eligibility is not itself a semantic negative verdict.
"""
from __future__ import annotations

from dataclasses import dataclass
import base64
import hashlib
import inspect
import json
import os
from pathlib import Path
import re
import shutil
import sys
from typing import Any, Callable, Collection, Mapping, Sequence

import jsonschema

from worker_execution_receipts import (
    DEFAULT_STDERR_LIMIT_BYTES,
    DEFAULT_STDOUT_LIMIT_BYTES,
    MAX_STREAM_LIMIT_BYTES,
    STDOUT_ASSIGNED_OUTPUT,
    BoundInput,
    CompletedExecution,
    ExecutionBindings,
    ExpectedOutput,
    PrincipalInvocation,
    WorkerExecutionError,
    WorkerExecutionIncomplete,
    environment_allowlist_sha256,
    process_tree_termination_capability,
    run_observed_worker,
    validate_completed_execution,
)


WORKFLOWS = frozenset({"candidate_negative", "application_skeptic"})
TOOL_POLICY_SCHEMA = "plamen.skeptic_tool_policy.v2"
MANIFEST_SCHEMA = "plamen.skeptic_execution_manifest.v2"
INTENT_SCHEMA = "plamen.skeptic_execution_intent.v2"
PACKET_SCHEMA = "plamen.skeptic_execution_packet.v2"
WORK_ROOT = ".skeptic_execution_work"
PROVIDER_ROOT = ".worker_execution_receipts"
AUTHORITY_SCHEMA = "plamen.skeptic_provider_authority.v1"
CONTAINMENT_SCHEMA = "plamen.skeptic_provider_containment_debt.v1"
RETRY_SCHEMA = "plamen.skeptic_provider_retry_intent.v1"
CANARY_SCHEMA = "plamen.skeptic_live_canary_receipt.v1"
QUARANTINE_ROOT = ".skeptic_execution_quarantine"

SKEPTIC_SYSTEM_PROMPT = (
    "You are an independent defensive security-audit discriminator. Consume the "
    "single JSON packet supplied on stdin. You have no tools and must not access "
    "files, settings, sessions, MCP servers, the network, or other agents. Assess "
    "only the packet's assigned work. Return exactly one raw JSON object matching "
    "expected_output_schema on stdout, with no prose or markdown fences. A missing "
    "or unsupported premise is unresolved; never self-certify a terminal negative."
)

_HEX64 = re.compile(r"[0-9a-f]{64}")
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}")
_CLAUDE_EXECUTABLES = {"claude", "claude.exe", "claude.cmd", "claude.bat"}


class SkepticExecutionWorkError(RuntimeError):
    """Prepared work or persisted provider authority is invalid."""


class SkepticExecutionIncomplete(SkepticExecutionWorkError):
    """The provider armed work but could not produce clean completion authority."""

    def __init__(
        self,
        message: str,
        *,
        provider_debt_path: Path | None = None,
        provider_arm_path: Path | None = None,
    ) -> None:
        super().__init__(message)
        self.provider_debt_path = provider_debt_path
        self.provider_arm_path = provider_arm_path


@dataclass(frozen=True)
class SkepticExecutionLayout:
    scratchpad: Path
    workflow: str
    provider_shard_id: str
    work_relative: str
    output_scope_relative: str
    staged_output_relative: str
    provider_publish_relative: str
    canonical_output_relative: str
    authority_sidecar_relative: str
    containment_debt_relative: str
    retry_intent_relative: str

    @property
    def work_path(self) -> Path:
        return self.scratchpad / self.work_relative

    @property
    def output_scope_path(self) -> Path:
        return self.scratchpad / self.output_scope_relative

    @property
    def staged_output_path(self) -> Path:
        return self.scratchpad / self.staged_output_relative

    @property
    def provider_publish_path(self) -> Path:
        return self.scratchpad / self.provider_publish_relative

    @property
    def canonical_output_path(self) -> Path:
        return self.scratchpad / self.canonical_output_relative

    @property
    def authority_sidecar_path(self) -> Path:
        return self.scratchpad / self.authority_sidecar_relative

    @property
    def containment_debt_path(self) -> Path:
        return self.scratchpad / self.containment_debt_relative

    @property
    def retry_intent_path(self) -> Path:
        return self.scratchpad / self.retry_intent_relative

    @property
    def retry_provider_shard_id(self) -> str:
        return f"{self.provider_shard_id}-r1"


@dataclass(frozen=True)
class PreparedSkepticExecution:
    scratchpad: Path
    project_root: Path
    layout: SkepticExecutionLayout
    workflow: str
    run_id: str
    plan_digest: str
    shard_id: str
    shard_digest: str
    backend: str
    model: str
    system_prompt: str
    argv: tuple[str, ...]
    resolved_argv: tuple[str, ...]
    cwd: Path
    timeout_seconds: int
    stdout_limit_bytes: int
    stderr_limit_bytes: int
    environment: tuple[tuple[str, str], ...]
    environment_allowlist: tuple[str, ...]
    plan_path: Path
    manifest_path: Path
    intent_path: Path
    context_path: Path
    instructions_path: Path
    packet_path: Path
    tool_policy_path: Path
    expected_output_schema_path: Path
    worker_identity: str
    worker_invocation_id: str
    assessor_identity: str
    assessor_invocation_id: str
    caller_parser_binding: Mapping[str, Any]
    request_digest: str
    terminal_negative_closure_eligible: bool
    terminal_negative_closure_reason: str

    @property
    def prompt_path(self) -> Path:
        """Compatibility alias: the exact provider stdin is the packet."""

        return self.packet_path

    @property
    def containment_debt_path(self) -> Path:
        return self.layout.containment_debt_path


@dataclass(frozen=True)
class ObservedSkepticExecution:
    request_digest: str
    provider_completion_path: Path
    provider_completion_sha256: str
    provider_arm_path: Path
    provider_arm_sha256: str
    provider_publish_path: Path
    provider_publish_sha256: str
    canonical_output_path: Path
    authority_sidecar_path: Path
    authority_sidecar_sha256: str
    attempt: int
    predecessor_debt_sha256: str
    predecessor_arm_sha256: str
    output_source_mode: str
    terminal_negative_closure_eligible: bool
    terminal_negative_closure_reason: str


def _canonical(value: Any) -> bytes:
    try:
        return (
            json.dumps(
                value,
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise SkepticExecutionWorkError(f"value is not canonical JSON: {exc}") from exc


def _digest_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _digest(value: Any) -> str:
    return _digest_bytes(_canonical(value))


def _declared_semantic_digest(value: Any) -> str:
    try:
        raw = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise SkepticExecutionWorkError(
            f"declared semantic digest input is invalid: {exc}"
        ) from exc
    return _digest_bytes(raw)


def _environment_effective_digest(environment: Mapping[str, str]) -> str:
    return _digest([[key, environment[key]] for key in sorted(environment)])


def _strict_json_bytes(raw: bytes, label: str) -> dict[str, Any]:
    def pairs(rows: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in rows:
            if key in result:
                raise SkepticExecutionWorkError(
                    f"{label} contains duplicate key {key!r}"
                )
            result[key] = value
        return result

    try:
        value = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=pairs,
            parse_constant=lambda item: (_ for _ in ()).throw(
                SkepticExecutionWorkError(
                    f"{label} contains non-finite value {item!r}"
                )
            ),
        )
    except SkepticExecutionWorkError:
        raise
    except Exception as exc:
        raise SkepticExecutionWorkError(
            f"{label} is not one UTF-8 JSON object: {exc}"
        ) from exc
    if not isinstance(value, dict):
        raise SkepticExecutionWorkError(f"{label} must be one JSON object")
    return value


def _strict_json_path(path: Path, label: str) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise SkepticExecutionWorkError(f"{label} is missing or unsafe")
    return _strict_json_bytes(path.read_bytes(), label)


def _require_text(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or "\x00" in value
    ):
        raise SkepticExecutionWorkError(f"{label} must be canonical non-empty text")
    return value


def _require_id(value: Any, label: str) -> str:
    text = _require_text(value, label)
    if not _ID.fullmatch(text):
        raise SkepticExecutionWorkError(f"{label} has an invalid identifier shape")
    return text


def _require_hex(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _HEX64.fullmatch(value):
        raise SkepticExecutionWorkError(f"{label} must be lowercase SHA-256")
    return value


def _require_stream_limit(value: Any, label: str) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < 1
        or value > MAX_STREAM_LIMIT_BYTES
    ):
        raise SkepticExecutionWorkError(
            f"{label} must be between 1 and {MAX_STREAM_LIMIT_BYTES} bytes"
        )
    return value


def _relative_inside(root: Path, path: Path, label: str) -> str:
    if path.is_symlink():
        raise SkepticExecutionWorkError(f"{label} cannot be a symlink")
    try:
        relative = path.resolve(strict=True).relative_to(root.resolve(strict=True))
    except (OSError, ValueError) as exc:
        raise SkepticExecutionWorkError(f"{label} must be inside the scratchpad") from exc
    if not relative.parts:
        raise SkepticExecutionWorkError(f"{label} cannot be the scratchpad root")
    return relative.as_posix()


def _safe_output_basename(value: str) -> str:
    text = _require_text(value, "canonical output").replace("\\", "/")
    path = Path(text)
    if (
        path.is_absolute()
        or len(path.parts) != 1
        or path.suffix.casefold() != ".json"
        or path.name != text
    ):
        raise SkepticExecutionWorkError("canonical output must be one JSON basename")
    return path.name


def _fsync_directory(path: Path) -> None:
    if os.name == "nt":
        return
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write_immutable(path: Path, raw: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("xb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        _fsync_directory(path.parent)
    except FileExistsError:
        if path.is_symlink() or not path.is_file() or path.read_bytes() != raw:
            raise SkepticExecutionWorkError(
                f"immutable input collision for {path.name}; use a new shard identity"
            )


def _atomic_bytes(path: Path, raw: bytes) -> None:
    """Replace one driver-owned file without exposing partial bytes."""

    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        with temporary.open("wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    finally:
        temporary.unlink(missing_ok=True)


def _stable_regular_file_bytes(path: Path, label: str) -> bytes:
    """Read exact bytes while rejecting replacement/change during the read."""

    if path.is_symlink() or not path.is_file():
        raise SkepticExecutionWorkError(f"{label} is missing or unsafe")
    try:
        with path.open("rb") as handle:
            before = os.fstat(handle.fileno())
            raw = handle.read()
            after = os.fstat(handle.fileno())
        current = path.stat()
    except OSError as exc:
        raise SkepticExecutionWorkError(f"{label} could not be read stably") from exc
    identity_before = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    identity_after = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
    identity_current = (
        current.st_dev, current.st_ino, current.st_size, current.st_mtime_ns
    )
    if identity_before != identity_after or identity_after != identity_current:
        raise SkepticExecutionWorkError(f"{label} changed during exact-byte capture")
    return raw


def _flag_values(argv: Sequence[str], flag: str) -> list[str]:
    values: list[str] = []
    for index, item in enumerate(argv):
        if item == flag:
            if index + 1 >= len(argv):
                raise SkepticExecutionWorkError(f"argv flag {flag} has no value")
            values.append(str(argv[index + 1]))
    return values


def _one_flag(argv: Sequence[str], flag: str) -> str:
    values = _flag_values(argv, flag)
    if len(values) != 1:
        raise SkepticExecutionWorkError(f"argv requires exactly one {flag}")
    return values[0]


def _callable_binding(callback: Callable[[Path, bytes], str]) -> dict[str, Any]:
    if not callable(callback):
        raise SkepticExecutionWorkError("parser_digest must be callable")
    try:
        source_file = Path(inspect.getsourcefile(callback) or "").resolve(strict=True)
        source = inspect.getsource(callback).encode("utf-8")
    except (OSError, TypeError) as exc:
        raise SkepticExecutionWorkError(
            "parser_digest must have inspectable immutable source"
        ) from exc
    return {
        "module": str(getattr(callback, "__module__", "")),
        "qualname": str(getattr(callback, "__qualname__", "")),
        "source_file": str(source_file),
        "source_file_sha256": _digest_bytes(source_file.read_bytes()),
        "callable_source_sha256": _digest_bytes(source),
    }


def canonical_tool_policy(
    *,
    backend: str,
    read_roots: Sequence[str],
    staged_output: str,
) -> dict[str, Any]:
    """Return the exact no-tool transport contract.

    ``read_roots`` must be empty: methodology and source/context bytes belong in
    the stdin packet.  The staged path is provider-owned and is never granted to
    the model.
    """

    backend_name = _require_text(backend, "backend").casefold()
    if backend_name not in {"claude", "codex", "fixture-subprocess"}:
        raise SkepticExecutionWorkError(f"unsupported skeptic backend {backend_name!r}")
    if list(read_roots):
        raise SkepticExecutionWorkError(
            "skeptic backend read roots are forbidden; put exact bytes in stdin packet"
        )
    staged = str(Path(_require_text(staged_output, "staged output")).resolve())
    if backend_name == "claude":
        authority = "ELIGIBLE_IF_PROVIDER_SCOPE_EXHAUSTIVE"
        profile = "CLAUDE_2_1_214_SAFE_MODE_EMPTY_TOOLS_STDOUT"
    elif backend_name == "fixture-subprocess":
        authority = "UNSUPPORTED_TEST_ONLY"
        profile = "FIXTURE_SUBPROCESS_STDOUT_TEST_ONLY"
    else:
        authority = "UNSUPPORTED_DEBT"
        profile = "CODEX_EQUIVALENT_NO_TOOL_BOUNDARY_NOT_IMPLEMENTED"
    return {
        "schema_version": TOOL_POLICY_SCHEMA,
        "backend": backend_name,
        "profile": profile,
        "transport": "EXACT_IMMUTABLE_STDIN_PACKET_PROVIDER_OWNED_STDOUT",
        "read_roots": [],
        "provider_staged_output": staged,
        "allowed_tools": [],
        "model_filesystem_access": "NONE",
        "model_output_channel": "RAW_STDOUT_ONLY",
        "settings_sources": "NONE",
        "mcp_authority": "STRICT_EMPTY_CONFIG",
        "session_persistence": "DISABLED",
        "terminal_negative_closure_authority": authority,
    }


def _validate_tool_policy(policy: Mapping[str, Any], backend: str) -> dict[str, Any]:
    expected_fields = {
        "schema_version",
        "backend",
        "profile",
        "transport",
        "read_roots",
        "provider_staged_output",
        "allowed_tools",
        "model_filesystem_access",
        "model_output_channel",
        "settings_sources",
        "mcp_authority",
        "session_persistence",
        "terminal_negative_closure_authority",
    }
    if not isinstance(policy, Mapping) or set(policy) != expected_fields:
        raise SkepticExecutionWorkError("tool policy fields are not exact")
    canonical = canonical_tool_policy(
        backend=backend,
        read_roots=list(policy.get("read_roots") or []),
        staged_output=str(policy.get("provider_staged_output") or ""),
    )
    if dict(policy) != canonical:
        raise SkepticExecutionWorkError("tool policy differs from exact backend profile")
    return canonical


def validate_skeptic_backend_contract(
    *,
    backend: str,
    model: str,
    argv: Sequence[str],
    tool_policy: Mapping[str, Any],
    system_prompt: str = SKEPTIC_SYSTEM_PROMPT,
    expected_output_schema: Mapping[str, Any] | None = None,
) -> tuple[str, ...]:
    """Validate the only accepted executable/argv profile."""

    backend_name = _require_text(backend, "backend").casefold()
    model_name = _require_text(model, "model")
    exact_system = _require_text(system_prompt, "system prompt")
    if exact_system != SKEPTIC_SYSTEM_PROMPT:
        raise SkepticExecutionWorkError("skeptic system prompt is not the exact profile")
    if isinstance(argv, (str, bytes)) or not argv:
        raise SkepticExecutionWorkError("argv must be a non-empty vector")
    values_list: list[str] = []
    for item in argv:
        if not isinstance(item, str) or item != item.strip() or "\x00" in item:
            raise SkepticExecutionWorkError("argv items must be canonical text")
        values_list.append(item)
    values = tuple(values_list)
    policy = _validate_tool_policy(tool_policy, backend_name)
    executable = Path(values[0]).name.casefold()

    if backend_name == "fixture-subprocess":
        if (
            model_name != "fixture-python"
            or executable != Path(sys.executable).name.casefold()
            or len(values) < 3
            or values[1] != "-c"
        ):
            raise SkepticExecutionWorkError(
                "fixture backend requires current Python, -c, and fixture-python"
            )
        return values

    if backend_name == "codex":
        raise SkepticExecutionWorkError(
            "CODEX_BACKEND_UNSUPPORTED_DEBT: an equivalent no-tool raw-stdout "
            "provider profile has not been proven"
        )

    if backend_name != "claude" or executable not in _CLAUDE_EXECUTABLES:
        raise SkepticExecutionWorkError("Claude backend requires the Claude CLI")
    schema = _validate_expected_schema(expected_output_schema or {})
    schema_argument = json.dumps(
        schema,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    expected = (
        values[0],
        "--print",
        "--output-format",
        "text",
        "--input-format",
        "text",
        "--model",
        model_name,
        "--no-session-persistence",
        "--safe-mode",
        "--system-prompt",
        SKEPTIC_SYSTEM_PROMPT,
        "--tools",
        "",
        "--setting-sources",
        "",
        "--strict-mcp-config",
        "--mcp-config",
        '{"mcpServers":{}}',
        "--json-schema",
        schema_argument,
    )
    if values != expected:
        raise SkepticExecutionWorkError(
            "Claude argv is not the exact no-tool stdin/stdout isolation profile"
        )
    if (
        _one_flag(values, "--model") != model_name
        or _one_flag(values, "--output-format") != "text"
        or _one_flag(values, "--input-format") != "text"
        or _one_flag(values, "--system-prompt") != SKEPTIC_SYSTEM_PROMPT
        or _one_flag(values, "--tools") != ""
        or _one_flag(values, "--setting-sources") != ""
        or _one_flag(values, "--mcp-config") != '{"mcpServers":{}}'
        or _one_flag(values, "--json-schema") != schema_argument
    ):
        raise SkepticExecutionWorkError("Claude exact profile binding changed")
    return values


def canonical_backend_argv(
    *,
    backend: str,
    executable: str,
    model: str,
    tool_policy: Mapping[str, Any],
    system_prompt: str = SKEPTIC_SYSTEM_PROMPT,
    expected_output_schema: Mapping[str, Any] | None = None,
) -> tuple[str, ...]:
    backend_name = _require_text(backend, "backend").casefold()
    executable_name = _require_text(executable, "executable")
    model_name = _require_text(model, "model")
    _validate_tool_policy(tool_policy, backend_name)
    if backend_name == "codex":
        raise SkepticExecutionWorkError(
            "CODEX_BACKEND_UNSUPPORTED_DEBT: an equivalent no-tool raw-stdout "
            "provider profile has not been proven"
        )
    if backend_name != "claude":
        raise SkepticExecutionWorkError(
            "fixture subprocess argv is test-supplied, not canonically generated"
        )
    schema = _validate_expected_schema(expected_output_schema or {})
    schema_argument = json.dumps(
        schema,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    values = (
        executable_name,
        "--print",
        "--output-format",
        "text",
        "--input-format",
        "text",
        "--model",
        model_name,
        "--no-session-persistence",
        "--safe-mode",
        "--system-prompt",
        system_prompt,
        "--tools",
        "",
        "--setting-sources",
        "",
        "--strict-mcp-config",
        "--mcp-config",
        '{"mcpServers":{}}',
        "--json-schema",
        schema_argument,
    )
    return validate_skeptic_backend_contract(
        backend=backend_name,
        model=model_name,
        argv=values,
        tool_policy=tool_policy,
        system_prompt=system_prompt,
        expected_output_schema=schema,
    )


def terminal_negative_closure_eligibility(backend: str) -> dict[str, Any]:
    """Return transport eligibility, never a semantic verdict."""

    backend_name = _require_text(backend, "backend").casefold()
    if backend_name == "codex":
        return {"eligible": False, "reason": "CODEX_BACKEND_UNSUPPORTED_DEBT"}
    if backend_name != "claude":
        return {"eligible": False, "reason": "TEST_PROVIDER_NOT_SEMANTIC_AUTHORITY"}
    capability = process_tree_termination_capability()
    if capability.get("exhaustive_descendant_termination_authority") is not True:
        return {
            "eligible": False,
            "reason": "NON_EXHAUSTIVE_PROVIDER_PROCESS_SCOPE",
        }
    return {"eligible": True, "reason": "EXACT_PROFILE_AND_EXHAUSTIVE_PROVIDER_SCOPE"}


def timeout_process_tree_capability() -> dict[str, Any]:
    """Compatibility view of the provider's current process-scope capability."""

    return process_tree_termination_capability()


def skeptic_provider_authority_sidecar_name(
    *, workflow: str, canonical_output: str
) -> str:
    """Return the one compact root-side authority projection for a shard."""

    workflow_name = _require_text(workflow, "workflow")
    if workflow_name not in WORKFLOWS:
        raise SkepticExecutionWorkError(
            f"unsupported skeptic workflow {workflow_name!r}"
        )
    output = _safe_output_basename(canonical_output)
    stem = Path(output).stem
    expected_prefix = (
        "candidate_negative_skeptic_assessments_"
        if workflow_name == "candidate_negative"
        else "application_skeptic_assessments_"
    )
    if stem.startswith(expected_prefix):
        suffix = stem[len(expected_prefix):]
        if not suffix or not re.fullmatch(r"[A-Za-z0-9_-]+", suffix):
            raise SkepticExecutionWorkError("skeptic output shard suffix is invalid")
        return f"{expected_prefix.replace('assessments_', 'provider_authority_')}{suffix}.json"
    digest = _digest({"workflow": workflow_name, "canonical_output": output})[:16]
    alias = "candidate_negative" if workflow_name == "candidate_negative" else "application"
    return f"{alias}_skeptic_provider_authority_{digest}.json"


def skeptic_execution_layout(
    scratchpad: str | Path,
    *,
    workflow: str,
    run_id: str,
    plan_digest: str,
    shard_id: str,
    canonical_output: str,
) -> SkepticExecutionLayout:
    root = Path(scratchpad).resolve(strict=True)
    if not root.is_dir() or root.is_symlink():
        raise SkepticExecutionWorkError("scratchpad must be a safe existing directory")
    workflow_name = _require_text(workflow, "workflow")
    if workflow_name not in WORKFLOWS:
        raise SkepticExecutionWorkError(f"unsupported skeptic workflow {workflow_name!r}")
    run = _require_id(run_id, "run_id")
    plan = _require_hex(plan_digest, "plan_digest")
    shard = _require_id(shard_id, "shard_id")
    output = _safe_output_basename(canonical_output)
    alias = "cn" if workflow_name == "candidate_negative" else "as"
    identity = _digest(
        {
            "workflow": workflow_name,
            "run_id": run,
            "plan_digest": plan,
            "shard_id": shard,
            "canonical_output": output,
        }
    )
    # Provider receipt filenames already carry full SHA-256 digests.  Keep the
    # directory alias compact enough for legacy Windows MAX_PATH while retaining
    # 80 bits of collision resistance; every receipt still replays the complete
    # semantic binding and rejects any alias collision.
    compact_identity = base64.b32encode(bytes.fromhex(identity)[:10]).decode(
        "ascii"
    ).rstrip("=").lower()
    provider_id = f"sk{alias}-{compact_identity}"
    work_relative = f"{WORK_ROOT}/{alias}/{identity[:32]}"
    output_scope = f"{work_relative}/staged"
    authority = skeptic_provider_authority_sidecar_name(
        workflow=workflow_name, canonical_output=output
    )
    return SkepticExecutionLayout(
        scratchpad=root,
        workflow=workflow_name,
        provider_shard_id=provider_id,
        work_relative=work_relative,
        output_scope_relative=output_scope,
        staged_output_relative=f"{output_scope}/assessment.json",
        provider_publish_relative=output,
        canonical_output_relative=output,
        authority_sidecar_relative=authority,
        containment_debt_relative=f"{work_relative}/containment_debt.json",
        retry_intent_relative=f"{work_relative}/inputs/retry_intent.json",
    )


def _resolve_argv(argv: Sequence[str], environment: Mapping[str, str]) -> tuple[str, ...]:
    values = list(argv)
    executable = Path(values[0])
    if executable.is_absolute():
        values[0] = str(executable.resolve(strict=True))
    else:
        found = shutil.which(values[0], path=environment.get("PATH"))
        if found is not None:
            values[0] = str(Path(found).resolve(strict=True))
    return tuple(values)


def _validate_expected_schema(schema: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(schema, Mapping):
        raise SkepticExecutionWorkError("expected_output_schema must be an object")
    value = dict(schema)
    if "$schema" in value:
        raise SkepticExecutionWorkError(
            "expected_output_schema must omit $schema for Claude 2.1.214 CLI compatibility"
        )
    if (
        value.get("type") != "object"
        or value.get("additionalProperties") is not False
        or not isinstance(value.get("required"), list)
        or not value["required"]
        or not isinstance(value.get("properties"), Mapping)
        or set(value["required"]) - set(value["properties"])
    ):
        raise SkepticExecutionWorkError(
            "expected_output_schema must be a strict object schema"
        )

    def inspect_schema(node: Any, location: str) -> None:
        if isinstance(node, list):
            for index, item in enumerate(node):
                inspect_schema(item, f"{location}/{index}")
            return
        if not isinstance(node, Mapping):
            return
        reference = node.get("$ref")
        if isinstance(reference, str) and not reference.startswith("#"):
            raise SkepticExecutionWorkError(
                "expected_output_schema cannot contain external $ref values"
            )
        for keyword in ("$dynamicRef", "$recursiveRef"):
            if keyword in node:
                raise SkepticExecutionWorkError(
                    f"expected_output_schema cannot contain {keyword}"
                )
        declares_object = node.get("type") == "object" or "properties" in node
        if declares_object and node.get("additionalProperties") is not False:
            raise SkepticExecutionWorkError(
                f"expected_output_schema object at {location} is not closed"
            )
        for key, item in node.items():
            inspect_schema(item, f"{location}/{key}")

    inspect_schema(value, "#")
    try:
        # Anthropic's API requires Draft 2020-12, while Claude CLI 2.1.214's
        # local strict-mode validator rejects some valid 2020-12 keywords such
        # as ``prefixItems``.  Callers therefore emit the common supported
        # subset and we validate it as the API's declared dialect here.
        jsonschema.Draft202012Validator.check_schema(value)
    except jsonschema.SchemaError as exc:
        raise SkepticExecutionWorkError(
            f"expected_output_schema is invalid: {exc.message}"
        ) from exc
    return value


def validate_skeptic_context_queue_bindings(
    scratchpad: str | Path, context: Mapping[str, Any]
) -> tuple[dict[str, Any], ...]:
    """Replay every queue byte embedded in an application-skeptic packet.

    The context builder embeds content, size, and digest.  Replaying all three
    immediately before preparation, launch, and publication closes the former
    path-read/hash-read TOCTOU seam.  Contexts without queue rows remain valid
    for unit fixtures and candidate sources which have no source queue.
    """

    root = Path(scratchpad).resolve(strict=True)
    rows = context.get("bound_source_queues", ())
    if rows is None:
        rows = ()
    if not isinstance(rows, (list, tuple)):
        raise SkepticExecutionWorkError("bound source queues must be an array")
    validated: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, row in enumerate(rows):
        if not isinstance(row, Mapping):
            raise SkepticExecutionWorkError(
                f"bound source queue {index} must be an object"
            )
        name = _safe_output_basename(str(row.get("relative_path") or ""))
        if name in seen:
            raise SkepticExecutionWorkError("bound source queue identity is duplicated")
        seen.add(name)
        raw = _stable_regular_file_bytes(root / name, f"bound source queue {name}")
        expected_sha = _require_hex(row.get("sha256"), f"{name} queue digest")
        expected_size = row.get("size_bytes")
        if isinstance(expected_size, bool) or not isinstance(expected_size, int):
            raise SkepticExecutionWorkError(f"{name} queue size is invalid")
        try:
            text = raw.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise SkepticExecutionWorkError(
                f"bound source queue {name} is not UTF-8"
            ) from exc
        if (
            len(raw) != expected_size
            or _digest_bytes(raw) != expected_sha
            or row.get("content_utf8") != text
        ):
            raise SkepticExecutionWorkError(
                f"bound source queue {name} changed after context capture"
            )
        validated.append(dict(row))
    return tuple(validated)


def prepare_skeptic_execution(
    *,
    scratchpad: str | Path,
    project_root: str | Path | None = None,
    workflow: str,
    run_id: str,
    plan_path: str | Path,
    expected_plan_digest: str,
    shard: Mapping[str, Any],
    context: Mapping[str, Any],
    snapshot: Mapping[str, Any],
    rendered_prompt: str,
    expected_output_schema: Mapping[str, Any],
    backend: str,
    model: str,
    argv: Sequence[str],
    tool_policy: Mapping[str, Any],
    worker_identity: str,
    worker_invocation_id: str,
    assessor_identity: str,
    assessor_invocation_id: str,
    canonical_output: str,
    timeout_seconds: int,
    cwd: str | Path,
    environment: Mapping[str, str],
    environment_allowlist: Collection[str],
    parser_digest: Callable[[Path, bytes], str],
    stdout_limit_bytes: int = DEFAULT_STDOUT_LIMIT_BYTES,
    stderr_limit_bytes: int = DEFAULT_STDERR_LIMIT_BYTES,
    system_prompt: str = SKEPTIC_SYSTEM_PROMPT,
) -> PreparedSkepticExecution:
    """Validate and immutably stage one exact provider request.

    ``parser_digest`` is bound before launch and must remain byte-identical on
    execute and resume.
    """

    root = Path(scratchpad).resolve(strict=True)
    if root.is_symlink() or not root.is_dir():
        raise SkepticExecutionWorkError("scratchpad must be a safe existing directory")
    project = Path(project_root or root).resolve(strict=True)
    if project.is_symlink() or not project.is_dir():
        raise SkepticExecutionWorkError("project root must be a safe existing directory")
    plan_file = Path(plan_path)
    source_plan_relative = _relative_inside(root, plan_file, "work plan")
    plan_raw = plan_file.read_bytes()
    plan = _strict_json_bytes(plan_raw, "work plan")
    plan_digest = _require_hex(expected_plan_digest, "expected plan digest")
    if plan.get("work_plan_digest") != plan_digest:
        raise SkepticExecutionWorkError("work plan digest differs from expected authority")
    unsigned_plan = {key: value for key, value in plan.items() if key != "work_plan_digest"}
    if _declared_semantic_digest(unsigned_plan) != plan_digest:
        raise SkepticExecutionWorkError("work plan self-digest is invalid")
    if not isinstance(shard, Mapping):
        raise SkepticExecutionWorkError("shard must be an object")
    shard_value = dict(shard)
    shard_id = _require_id(shard_value.get("shard_id"), "shard_id")
    shard_digest = _require_hex(shard_value.get("shard_digest"), "shard_digest")
    unsigned_shard = {
        key: value for key, value in shard_value.items() if key != "shard_digest"
    }
    if _declared_semantic_digest(unsigned_shard) != shard_digest:
        raise SkepticExecutionWorkError("shard self-digest is invalid")
    matching = [
        row
        for row in (plan.get("shards") or [])
        if isinstance(row, Mapping) and row.get("shard_id") == shard_id
    ]
    if len(matching) != 1 or dict(matching[0]) != shard_value:
        raise SkepticExecutionWorkError("exact shard is not present once in work plan")
    if not isinstance(context, Mapping):
        raise SkepticExecutionWorkError("methodology/source context must be an object")
    context_value = dict(context)
    if not context_value:
        raise SkepticExecutionWorkError("methodology/source context cannot be empty")
    validate_skeptic_context_queue_bindings(root, context_value)
    if not isinstance(snapshot, Mapping) or not snapshot:
        raise SkepticExecutionWorkError("snapshot binding must be a non-empty object")
    snapshot_value = dict(snapshot)
    snapshot_raw = _canonical(snapshot_value)
    instructions = _require_text(rendered_prompt, "instructions")
    schema = _validate_expected_schema(expected_output_schema)
    exact_system = _require_text(system_prompt, "system prompt")
    if exact_system != SKEPTIC_SYSTEM_PROMPT:
        raise SkepticExecutionWorkError("skeptic system prompt differs from exact profile")

    layout = skeptic_execution_layout(
        root,
        workflow=workflow,
        run_id=run_id,
        plan_digest=plan_digest,
        shard_id=shard_id,
        canonical_output=canonical_output,
    )
    backend_name = _require_text(backend, "backend").casefold()
    model_name = _require_text(model, "model")
    policy = _validate_tool_policy(tool_policy, backend_name)
    if policy["provider_staged_output"] != str(layout.staged_output_path):
        raise SkepticExecutionWorkError("tool policy staged output differs from layout")
    exact_argv = validate_skeptic_backend_contract(
        backend=backend_name,
        model=model_name,
        argv=argv,
        tool_policy=policy,
        system_prompt=exact_system,
        expected_output_schema=schema,
    )
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, int)
        or timeout_seconds <= 0
    ):
        raise SkepticExecutionWorkError("timeout_seconds must be a positive integer")
    stdout_limit = _require_stream_limit(stdout_limit_bytes, "stdout_limit_bytes")
    stderr_limit = _require_stream_limit(stderr_limit_bytes, "stderr_limit_bytes")
    cwd_path = Path(cwd).resolve(strict=True)
    if not cwd_path.is_dir():
        raise SkepticExecutionWorkError("cwd must be an existing directory")
    env = dict(environment)
    allowlist = tuple(environment_allowlist)
    allow_digest = environment_allowlist_sha256(allowlist)
    allowed = {name.casefold(): name for name in allowlist}
    if len(allowed) != len(allowlist):
        raise SkepticExecutionWorkError("environment allowlist has a case collision")
    for key, value in env.items():
        if (
            not isinstance(key, str)
            or allowed.get(key.casefold()) != key
            or not isinstance(value, str)
            or "\x00" in value
        ):
            raise SkepticExecutionWorkError(
                f"effective environment entry {key!r} violates its allowlist"
            )
    worker_id = _require_text(worker_identity, "worker identity")
    worker_invocation = _require_text(worker_invocation_id, "worker invocation_id")
    assessor_id = _require_text(assessor_identity, "assessor identity")
    assessor_invocation = _require_text(
        assessor_invocation_id, "assessor invocation_id"
    )
    eligibility = terminal_negative_closure_eligibility(backend_name)
    parser_binding = _callable_binding(parser_digest)

    inputs = layout.work_path / "inputs"
    bound_plan_path = inputs / "plan.json"
    manifest_path = inputs / "manifest.json"
    context_path = inputs / "context.json"
    instructions_path = inputs / "instructions.txt"
    schema_path = inputs / "expected_output_schema.json"
    packet_path = inputs / "packet.json"
    policy_path = inputs / "tool_policy.json"
    intent_path = inputs / "intent.json"

    context_raw = _canonical(context_value)
    instructions_raw = instructions.encode("utf-8")
    schema_raw = _canonical(schema)
    policy_raw = _canonical(policy)
    packet = {
        "schema_version": PACKET_SCHEMA,
        "workflow": workflow,
        "run_id": run_id,
        "plan": plan,
        "plan_raw_sha256": _digest_bytes(plan_raw),
        "shard": shard_value,
        "snapshot": snapshot_value,
        "methodology_and_source_context": context_value,
        "instructions": instructions,
        "expected_output_schema": schema,
        "assessor": {
            "identity": worker_id,
            "invocation_id": worker_invocation,
        },
        "consumer": {
            "identity": assessor_id,
            "invocation_id": assessor_invocation,
        },
        "system_prompt_sha256": _digest_bytes(exact_system.encode("utf-8")),
        "transport_contract": {
            "input": "THIS_EXACT_IMMUTABLE_JSON_PACKET_ON_STDIN",
            "output": "ONE_RAW_JSON_OBJECT_ON_STDOUT",
            "tools": "NONE",
        },
    }
    packet_raw = _canonical(packet)
    manifest = {
        "schema_version": MANIFEST_SCHEMA,
        "workflow": workflow,
        "run_id": run_id,
        "source_plan_relative_path": source_plan_relative,
        "bound_plan_relative_path": (inputs / "plan.json").relative_to(root).as_posix(),
        "plan_raw_sha256": _digest_bytes(plan_raw),
        "plan_digest": plan_digest,
        "shard_id": shard_id,
        "shard_digest": shard_digest,
        "provider_shard_id": layout.provider_shard_id,
        "output_scope_relative": layout.output_scope_relative,
        "staged_output_relative": layout.staged_output_relative,
        "provider_publish_relative": layout.provider_publish_relative,
        "canonical_output_relative": layout.canonical_output_relative,
        "authority_sidecar_relative": layout.authority_sidecar_relative,
        "containment_debt_relative": layout.containment_debt_relative,
        "packet_sha256": _digest_bytes(packet_raw),
        "snapshot_binding_sha256": _digest_bytes(snapshot_raw),
        "output_source_mode": STDOUT_ASSIGNED_OUTPUT,
    }
    manifest_raw = _canonical(manifest)
    resolved_argv = _resolve_argv(exact_argv, env)
    resolved_executable = Path(resolved_argv[0])
    if not resolved_executable.is_absolute() or not resolved_executable.is_file():
        raise SkepticExecutionWorkError(
            "skeptic executable must resolve to one existing absolute file"
        )
    resolved_executable = resolved_executable.resolve(strict=True)
    executable_sha256 = _digest_bytes(resolved_executable.read_bytes())
    intent = {
        "schema_version": INTENT_SCHEMA,
        "workflow": workflow,
        "run_id": run_id,
        "plan_digest": plan_digest,
        "shard_id": shard_id,
        "shard_digest": shard_digest,
        "provider_shard_id": layout.provider_shard_id,
        "output_scope_relative": layout.output_scope_relative,
        "staged_output_relative": layout.staged_output_relative,
        "provider_publish_relative": layout.provider_publish_relative,
        "canonical_output_relative": layout.canonical_output_relative,
        "authority_sidecar_relative": layout.authority_sidecar_relative,
        "containment_debt_relative": layout.containment_debt_relative,
        "effective_backend": backend_name,
        "effective_model": model_name,
        "system_prompt_sha256": _digest_bytes(exact_system.encode("utf-8")),
        "argv": list(exact_argv),
        "argv_sha256": _digest(list(exact_argv)),
        "resolved_executable": str(resolved_executable),
        "resolved_executable_sha256": executable_sha256,
        "cwd": str(cwd_path),
        "project_root": str(project),
        "timeout_seconds": timeout_seconds,
        "stdout_limit_bytes": stdout_limit,
        "stderr_limit_bytes": stderr_limit,
        "environment_allowlist_sha256": allow_digest,
        "environment_effective_sha256": _environment_effective_digest(env),
        "worker": {"identity": worker_id, "invocation_id": worker_invocation},
        "assessor": {"identity": assessor_id, "invocation_id": assessor_invocation},
        "plan_raw_sha256": _digest_bytes(plan_raw),
        "manifest_sha256": _digest_bytes(manifest_raw),
        "context_sha256": _digest_bytes(context_raw),
        "snapshot_binding_sha256": _digest_bytes(snapshot_raw),
        "instructions_sha256": _digest_bytes(instructions_raw),
        "expected_output_schema_sha256": _digest_bytes(schema_raw),
        "packet_sha256": _digest_bytes(packet_raw),
        "tool_policy_sha256": _digest_bytes(policy_raw),
        "caller_parser_binding": parser_binding,
        "input_relative_paths": {
            "plan": bound_plan_path.relative_to(root).as_posix(),
            "manifest": manifest_path.relative_to(root).as_posix(),
            "intent": intent_path.relative_to(root).as_posix(),
            "context": context_path.relative_to(root).as_posix(),
            "instructions": instructions_path.relative_to(root).as_posix(),
            "packet": packet_path.relative_to(root).as_posix(),
            "tool_policy": policy_path.relative_to(root).as_posix(),
            "expected_output_schema": schema_path.relative_to(root).as_posix(),
        },
        "output_source_mode": STDOUT_ASSIGNED_OUTPUT,
        "terminal_negative_closure_eligibility": eligibility,
        "process_scope_capability": process_tree_termination_capability(),
    }
    intent["request_binding_digest"] = _digest(intent)
    intent_raw = _canonical(intent)
    _write_immutable(bound_plan_path, plan_raw)
    _write_immutable(manifest_path, manifest_raw)
    _write_immutable(context_path, context_raw)
    _write_immutable(instructions_path, instructions_raw)
    _write_immutable(schema_path, schema_raw)
    _write_immutable(packet_path, packet_raw)
    _write_immutable(policy_path, policy_raw)
    _write_immutable(intent_path, intent_raw)
    request_digest = _digest(
        {
            "plan_sha256": _digest_bytes(plan_raw),
            "manifest_sha256": _digest_bytes(manifest_raw),
            "context_sha256": _digest_bytes(context_raw),
            "instructions_sha256": _digest_bytes(instructions_raw),
            "schema_sha256": _digest_bytes(schema_raw),
            "packet_sha256": _digest_bytes(packet_raw),
            "tool_policy_sha256": _digest_bytes(policy_raw),
            "intent_sha256": _digest_bytes(intent_raw),
        }
    )
    return PreparedSkepticExecution(
        scratchpad=root,
        project_root=project,
        layout=layout,
        workflow=workflow,
        run_id=run_id,
        plan_digest=plan_digest,
        shard_id=shard_id,
        shard_digest=shard_digest,
        backend=backend_name,
        model=model_name,
        system_prompt=exact_system,
        argv=tuple(exact_argv),
        resolved_argv=resolved_argv,
        cwd=cwd_path,
        timeout_seconds=timeout_seconds,
        stdout_limit_bytes=stdout_limit,
        stderr_limit_bytes=stderr_limit,
        environment=tuple(sorted(env.items())),
        environment_allowlist=allowlist,
        plan_path=bound_plan_path,
        manifest_path=manifest_path,
        intent_path=intent_path,
        context_path=context_path,
        instructions_path=instructions_path,
        packet_path=packet_path,
        tool_policy_path=policy_path,
        expected_output_schema_path=schema_path,
        worker_identity=worker_id,
        worker_invocation_id=worker_invocation,
        assessor_identity=assessor_id,
        assessor_invocation_id=assessor_invocation,
        caller_parser_binding=parser_binding,
        request_digest=request_digest,
        terminal_negative_closure_eligible=bool(eligibility["eligible"]),
        terminal_negative_closure_reason=str(eligibility["reason"]),
    )


def _current_parser_binding(
    request: PreparedSkepticExecution,
    parser_digest: Callable[[Path, bytes], str],
) -> dict[str, Any]:
    binding = _callable_binding(parser_digest)
    recorded = dict(request.caller_parser_binding)
    if recorded and recorded != binding:
        raise SkepticExecutionWorkError("caller parser implementation changed")
    return binding


def _make_strict_parser(
    request: PreparedSkepticExecution,
    parser_digest: Callable[[Path, bytes], str],
) -> Callable[[Path, bytes], str]:
    schema = _strict_json_path(
        request.expected_output_schema_path, "expected output schema"
    )
    parser_binding = _current_parser_binding(request, parser_digest)
    schema_sha = _digest_bytes(request.expected_output_schema_path.read_bytes())

    def strict_skeptic_stdout_parser(path: Path, raw: bytes) -> str:
        value = _strict_json_bytes(raw, "skeptic stdout")
        try:
            jsonschema.Draft202012Validator(schema).validate(value)
        except jsonschema.ValidationError as exc:
            raise SkepticExecutionWorkError(
                f"skeptic stdout violates expected schema: {exc.message}"
            ) from exc
        # The caller parser receives the immutable provider-bound stdin packet,
        # not the staged output path.  That gives semantic validators the exact
        # plan/shard/principal denominator needed to enforce constraints which
        # Claude CLI's narrower schema subset cannot express (notably ordered
        # tuple identities) before a completion receipt can be emitted.
        caller_digest = parser_digest(request.packet_path, raw)
        _require_hex(caller_digest, "caller parser digest")
        return _digest(
            {
                "strict_json_sha256": _digest(value),
                "expected_output_schema_sha256": schema_sha,
                "caller_parser_binding": parser_binding,
                "caller_parser_digest": caller_digest,
            }
        )

    return strict_skeptic_stdout_parser


def _replay_prepared_request(
    request: PreparedSkepticExecution,
    *,
    parser_digest: Callable[[Path, bytes], str],
) -> dict[str, Any]:
    if not isinstance(request, PreparedSkepticExecution):
        raise SkepticExecutionWorkError("request is not prepared skeptic work")
    if request.layout.scratchpad != request.scratchpad:
        raise SkepticExecutionWorkError("layout scratchpad differs from request root")
    recomputed_argv = _resolve_argv(request.argv, dict(request.environment))
    if request.resolved_argv != recomputed_argv:
        raise SkepticExecutionWorkError("resolved executable/argv binding changed")
    executable = Path(recomputed_argv[0]).resolve(strict=True)
    policy = _strict_json_path(request.tool_policy_path, "skeptic tool policy")
    validate_skeptic_backend_contract(
        backend=request.backend,
        model=request.model,
        argv=request.argv,
        tool_policy=policy,
        system_prompt=request.system_prompt,
        expected_output_schema=_strict_json_path(
            request.expected_output_schema_path, "expected output schema"
        ),
    )
    parser_binding = _current_parser_binding(request, parser_digest)
    intent = _strict_json_path(request.intent_path, "skeptic intent")
    if intent.get("schema_version") != INTENT_SCHEMA:
        raise SkepticExecutionWorkError("skeptic intent schema mismatch")
    unsigned_intent = {
        key: value for key, value in intent.items() if key != "request_binding_digest"
    }
    if intent.get("request_binding_digest") != _digest(unsigned_intent):
        raise SkepticExecutionWorkError("skeptic intent request binding digest changed")
    eligibility = terminal_negative_closure_eligibility(request.backend)
    if (
        request.terminal_negative_closure_eligible is not bool(eligibility["eligible"])
        or request.terminal_negative_closure_reason != str(eligibility["reason"])
    ):
        raise SkepticExecutionWorkError(
            "caller request terminal-negative eligibility differs from provider policy"
        )
    files = {
        "plan_sha256": request.plan_path,
        "manifest_sha256": request.manifest_path,
        "context_sha256": request.context_path,
        "instructions_sha256": request.instructions_path,
        "schema_sha256": request.expected_output_schema_path,
        "packet_sha256": request.packet_path,
        "tool_policy_sha256": request.tool_policy_path,
    }
    current = {key: _digest_bytes(path.read_bytes()) for key, path in files.items()}
    expected_intent = {
        "workflow": request.workflow,
        "run_id": request.run_id,
        "plan_digest": request.plan_digest,
        "shard_id": request.shard_id,
        "shard_digest": request.shard_digest,
        "provider_shard_id": request.layout.provider_shard_id,
        "output_scope_relative": request.layout.output_scope_relative,
        "staged_output_relative": request.layout.staged_output_relative,
        "provider_publish_relative": request.layout.provider_publish_relative,
        "canonical_output_relative": request.layout.canonical_output_relative,
        "authority_sidecar_relative": request.layout.authority_sidecar_relative,
        "containment_debt_relative": request.layout.containment_debt_relative,
        "effective_backend": request.backend,
        "effective_model": request.model,
        "system_prompt_sha256": _digest_bytes(request.system_prompt.encode("utf-8")),
        "argv": list(request.argv),
        "argv_sha256": _digest(list(request.argv)),
        "resolved_executable": str(executable),
        "resolved_executable_sha256": _digest_bytes(executable.read_bytes()),
        "cwd": str(request.cwd),
        "project_root": str(request.project_root),
        "timeout_seconds": request.timeout_seconds,
        "stdout_limit_bytes": request.stdout_limit_bytes,
        "stderr_limit_bytes": request.stderr_limit_bytes,
        "environment_allowlist_sha256": environment_allowlist_sha256(
            request.environment_allowlist
        ),
        "environment_effective_sha256": _environment_effective_digest(
            dict(request.environment)
        ),
        "worker": {
            "identity": request.worker_identity,
            "invocation_id": request.worker_invocation_id,
        },
        "assessor": {
            "identity": request.assessor_identity,
            "invocation_id": request.assessor_invocation_id,
        },
        "plan_raw_sha256": current["plan_sha256"],
        "manifest_sha256": current["manifest_sha256"],
        "context_sha256": current["context_sha256"],
        "snapshot_binding_sha256": _digest_bytes(
            _canonical(
                _strict_json_path(request.packet_path, "skeptic stdin packet")[
                    "snapshot"
                ]
            )
        ),
        "instructions_sha256": current["instructions_sha256"],
        "expected_output_schema_sha256": current["schema_sha256"],
        "packet_sha256": current["packet_sha256"],
        "tool_policy_sha256": current["tool_policy_sha256"],
        "caller_parser_binding": parser_binding if request.caller_parser_binding else {},
        "input_relative_paths": {
            "plan": _relative_inside(request.scratchpad, request.plan_path, "plan"),
            "manifest": _relative_inside(
                request.scratchpad, request.manifest_path, "manifest"
            ),
            "intent": _relative_inside(request.scratchpad, request.intent_path, "intent"),
            "context": _relative_inside(
                request.scratchpad, request.context_path, "context"
            ),
            "instructions": _relative_inside(
                request.scratchpad, request.instructions_path, "instructions"
            ),
            "packet": _relative_inside(
                request.scratchpad, request.packet_path, "packet"
            ),
            "tool_policy": _relative_inside(
                request.scratchpad, request.tool_policy_path, "tool policy"
            ),
            "expected_output_schema": _relative_inside(
                request.scratchpad,
                request.expected_output_schema_path,
                "expected output schema",
            ),
        },
        "output_source_mode": STDOUT_ASSIGNED_OUTPUT,
        "terminal_negative_closure_eligibility": eligibility,
        "process_scope_capability": process_tree_termination_capability(),
    }
    for key, value in expected_intent.items():
        if intent.get(key) != value:
            raise SkepticExecutionWorkError(f"skeptic intent {key} binding changed")
    if policy.get("provider_staged_output") != str(request.layout.staged_output_path):
        raise SkepticExecutionWorkError("tool policy staged output binding changed")
    packet = _strict_json_path(request.packet_path, "skeptic stdin packet")
    if packet.get("schema_version") != PACKET_SCHEMA:
        raise SkepticExecutionWorkError("skeptic packet schema mismatch")
    if (
        packet.get("workflow") != request.workflow
        or packet.get("run_id") != request.run_id
        or not isinstance(packet.get("plan"), dict)
        or packet["plan"].get("work_plan_digest") != request.plan_digest
        or not isinstance(packet.get("shard"), dict)
        or packet["shard"].get("shard_digest") != request.shard_digest
        or packet.get("methodology_and_source_context")
        != _strict_json_path(request.context_path, "skeptic context")
        or not isinstance(packet.get("snapshot"), dict)
        or intent.get("snapshot_binding_sha256")
        != _digest_bytes(_canonical(packet["snapshot"]))
        or packet.get("instructions")
        != request.instructions_path.read_text(encoding="utf-8", errors="strict")
        or packet.get("expected_output_schema")
        != _strict_json_path(
            request.expected_output_schema_path, "expected output schema"
        )
        or packet.get("system_prompt_sha256")
        != _digest_bytes(request.system_prompt.encode("utf-8"))
    ):
        raise SkepticExecutionWorkError("skeptic stdin packet semantic binding changed")
    validate_skeptic_context_queue_bindings(
        request.scratchpad,
        packet.get("methodology_and_source_context")
        if isinstance(packet.get("methodology_and_source_context"), Mapping)
        else {},
    )
    current_request_digest = _digest(
        {**current, "intent_sha256": _digest_bytes(request.intent_path.read_bytes())}
    )
    if current_request_digest != request.request_digest:
        raise SkepticExecutionWorkError("prepared request digest changed")
    return intent


def _execution_bindings(
    request: PreparedSkepticExecution,
    *,
    provider_shard_id: str | None = None,
    intent_path: Path | None = None,
) -> ExecutionBindings:
    root = request.scratchpad
    return ExecutionBindings(
        run_id=request.run_id,
        shard_id=provider_shard_id or request.layout.provider_shard_id,
        plan=BoundInput(_relative_inside(root, request.plan_path, "work plan")),
        manifest=BoundInput(_relative_inside(root, request.manifest_path, "manifest")),
        intent=BoundInput(
            _relative_inside(root, intent_path or request.intent_path, "intent")
        ),
        context=BoundInput(_relative_inside(root, request.context_path, "context")),
        prompt=BoundInput(_relative_inside(root, request.packet_path, "stdin packet")),
        tool_policy=BoundInput(
            _relative_inside(root, request.tool_policy_path, "tool policy")
        ),
        worker=PrincipalInvocation(
            request.worker_identity, request.worker_invocation_id
        ),
        assessors=(
            PrincipalInvocation(
                request.assessor_identity, request.assessor_invocation_id
            ),
        ),
        effective_backend=request.backend,
        effective_model=request.model,
    )


@dataclass(frozen=True)
class _BoundaryEntry:
    kind: str
    raw: bytes
    mode: int


def _boundary_path(
    request: PreparedSkepticExecution, identity: str
) -> Path:
    prefix, separator, relative = identity.partition(":")
    if not separator or not relative:
        raise SkepticExecutionWorkError("containment identity is invalid")
    root = request.scratchpad if prefix == "scratchpad" else request.project_root
    if prefix not in {"scratchpad", "project"}:
        raise SkepticExecutionWorkError("containment root is invalid")
    candidate = root.joinpath(*Path(relative).parts)
    try:
        candidate.absolute().relative_to(root.absolute())
    except ValueError as exc:
        raise SkepticExecutionWorkError("containment path escapes its root") from exc
    return candidate


def _capture_boundary(
    request: PreparedSkepticExecution,
) -> dict[str, _BoundaryEntry]:
    """Capture restorable project and scratchpad state before one child.

    The no-tool profile should not write either tree.  Retaining exact preimage
    bytes makes detection useful operationally: an offending child cannot leave
    the user's source or a future audit artifact modified after the driver has
    refused its completion.
    """

    state: dict[str, _BoundaryEntry] = {}
    scratch_abs = request.scratchpad.absolute()

    def visit(root: Path, prefix: str, *, skip_scratch: bool) -> None:
        stack: list[tuple[Path, Path]] = [(root, Path())]
        while stack:
            directory, relative_dir = stack.pop()
            try:
                entries = list(os.scandir(directory))
            except OSError as exc:
                raise SkepticExecutionWorkError(
                    f"containment snapshot cannot enumerate {prefix}:{relative_dir.as_posix()}"
                ) from exc
            for entry in entries:
                relative = relative_dir / entry.name
                path = Path(entry.path)
                if prefix == "project" and relative.parts[:1] == (".git",):
                    continue
                if skip_scratch:
                    try:
                        if path.absolute() == scratch_abs or path.absolute().is_relative_to(
                            scratch_abs
                        ):
                            continue
                    except (OSError, ValueError):
                        pass
                identity = f"{prefix}:{relative.as_posix()}"
                try:
                    if entry.is_symlink():
                        target = os.readlink(path).encode("utf-8", errors="surrogatepass")
                        state[identity] = _BoundaryEntry("symlink", target, 0)
                    elif entry.is_dir(follow_symlinks=False):
                        stat_result = entry.stat(follow_symlinks=False)
                        state[identity] = _BoundaryEntry(
                            "dir", b"", stat_result.st_mode
                        )
                        stack.append((path, relative))
                    elif entry.is_file(follow_symlinks=False):
                        stat_result = entry.stat(follow_symlinks=False)
                        raw = _stable_regular_file_bytes(path, identity)
                        state[identity] = _BoundaryEntry(
                            "file", raw, stat_result.st_mode
                        )
                except OSError as exc:
                    raise SkepticExecutionWorkError(
                        f"containment snapshot cannot capture {identity}"
                    ) from exc

    visit(request.scratchpad, "scratchpad", skip_scratch=False)
    if request.project_root.absolute() != scratch_abs:
        visit(request.project_root, "project", skip_scratch=True)
    return state


def _allowed_provider_mutation(
    request: PreparedSkepticExecution,
    identity: str,
    provider_ids: Collection[str],
) -> bool:
    if not identity.startswith("scratchpad:"):
        return False
    relative = identity.split(":", 1)[1]
    if relative == request.layout.canonical_output_relative:
        return True
    if relative == request.layout.staged_output_relative:
        return True
    if relative == request.layout.output_scope_relative:
        return True
    if relative == PROVIDER_ROOT:
        return True
    return any(
        relative == f"{PROVIDER_ROOT}/{provider_id}"
        or relative.startswith(f"{PROVIDER_ROOT}/{provider_id}/")
        for provider_id in provider_ids
    )


def _quarantine_destination(
    request: PreparedSkepticExecution, identity: str, *, suffix: str = ""
) -> Path:
    prefix, _, relative = identity.partition(":")
    safe_parts = [part for part in Path(relative).parts if part not in {".", ".."}]
    destination = (
        request.scratchpad
        / QUARANTINE_ROOT
        / request.layout.provider_shard_id
        / prefix
    ).joinpath(*safe_parts)
    if suffix:
        destination = destination.with_name(destination.name + suffix)
    return destination


def _remove_any(path: Path) -> None:
    if path.is_symlink() or path.is_file():
        path.unlink(missing_ok=True)
    elif path.is_dir():
        shutil.rmtree(path)


def _restore_boundary_entry(path: Path, entry: _BoundaryEntry) -> None:
    _remove_any(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if entry.kind == "symlink":
        os.symlink(entry.raw.decode("utf-8", errors="surrogatepass"), path)
        return
    if entry.kind == "dir":
        path.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(path, entry.mode)
        except OSError:
            pass
        return
    _atomic_bytes(path, entry.raw)
    try:
        os.chmod(path, entry.mode)
    except OSError:
        pass


def _write_containment_debt(
    request: PreparedSkepticExecution,
    *,
    provider_id: str,
    offenders: Sequence[str],
    quarantined: Sequence[str],
    restored: Sequence[str],
    failed: Sequence[str],
) -> None:
    unsigned = {
        "schema_version": CONTAINMENT_SCHEMA,
        "run_id": request.run_id,
        "workflow": request.workflow,
        "shard_id": request.shard_id,
        "provider_shard_id": provider_id,
        "request_sha256": request.request_digest,
        "effective_backend": request.backend,
        "effective_model": request.model,
        "offenders": sorted(set(offenders)),
        "quarantined": sorted(set(quarantined)),
        "restored": sorted(set(restored)),
        "failed": sorted(set(failed)),
        "state": "CONTAINMENT_VIOLATION",
    }
    payload = {**unsigned, "debt_sha256": _digest(unsigned)}
    _write_immutable(request.containment_debt_path, _canonical(payload))


def _reconcile_boundary(
    request: PreparedSkepticExecution,
    before: Mapping[str, _BoundaryEntry],
    *,
    provider_ids: Collection[str],
    provider_id: str,
) -> tuple[str, ...]:
    after = _capture_boundary(request)
    changed = [
        identity
        for identity in sorted(set(before) | set(after))
        if before.get(identity) != after.get(identity)
        and not _allowed_provider_mutation(request, identity, provider_ids)
    ]
    if not changed:
        return ()
    quarantined: list[str] = []
    restored: list[str] = []
    failed: list[str] = []
    for identity in changed:
        path = _boundary_path(request, identity)
        prior = before.get(identity)
        try:
            if path.is_symlink() or path.is_file():
                destination = _quarantine_destination(
                    request, identity, suffix=".foreign"
                )
                destination.parent.mkdir(parents=True, exist_ok=True)
                if destination.exists() or destination.is_symlink():
                    destination = destination.with_name(
                        destination.name + "." + _digest(identity)[:12]
                    )
                try:
                    path.replace(destination)
                except OSError:
                    if path.is_symlink():
                        os.symlink(os.readlink(path), destination)
                        path.unlink()
                    else:
                        shutil.copy2(path, destination)
                        path.unlink()
                quarantined.append(identity)
            elif path.is_dir():
                destination = _quarantine_destination(
                    request, identity, suffix=".foreign"
                )
                destination.parent.mkdir(parents=True, exist_ok=True)
                if destination.exists() or destination.is_symlink():
                    destination = destination.with_name(
                        destination.name + "." + _digest(identity)[:12]
                    )
                path.replace(destination)
                quarantined.append(identity)
            if prior is not None:
                _restore_boundary_entry(path, prior)
                restored.append(identity)
        except Exception:
            failed.append(identity)
    _write_containment_debt(
        request,
        provider_id=provider_id,
        offenders=changed,
        quarantined=quarantined,
        restored=restored,
        failed=failed,
    )
    return tuple(changed)


def _quarantine_canonical_output(
    request: PreparedSkepticExecution, *, reason: str
) -> None:
    output = request.layout.canonical_output_path
    if not output.exists() and not output.is_symlink():
        return
    destination = _quarantine_destination(
        request,
        f"scratchpad:{request.layout.canonical_output_relative}",
        suffix=f".{_digest(reason)[:12]}.invalid",
    )
    destination.parent.mkdir(parents=True, exist_ok=True)
    try:
        output.replace(destination)
    except OSError:
        try:
            shutil.copy2(output, destination)
            output.unlink()
        except OSError:
            # A live invalid output must never be silently imported.  The
            # durable containment/provider debt still prevents completion.
            pass


def quarantine_skeptic_provider_output(
    request: PreparedSkepticExecution, *, reason: str
) -> None:
    """Public fail-closed hook for a downstream consumer validation failure."""

    _quarantine_canonical_output(
        request, reason=_require_text(reason, "quarantine reason")
    )


def _provider_receipts(
    request: PreparedSkepticExecution,
    *,
    provider_shard_id: str | None = None,
) -> tuple[list[Path], list[Path], list[Path], bool]:
    directory = request.scratchpad / PROVIDER_ROOT / (
        provider_shard_id or request.layout.provider_shard_id
    )
    if not directory.exists():
        return [], [], [], False
    if directory.is_symlink() or not directory.is_dir():
        raise SkepticExecutionWorkError("provider evidence directory is unsafe")
    completions = sorted(directory.glob("completion_*.json"))
    publishes = sorted(
        path
        for path in directory.glob("publish_*.json")
        if not path.name.startswith("publish_arm_")
    )
    debts = sorted(directory.glob("debt_*.json"))
    return completions, publishes, debts, True


def _receipt_digest(path: Path, prefix: str) -> str:
    match = re.fullmatch(rf"{re.escape(prefix)}_([0-9a-f]{{64}})\.json", path.name)
    if not match:
        raise SkepticExecutionWorkError(f"provider {prefix} receipt filename is invalid")
    return match.group(1)


def _validate_provider_arm(
    request: PreparedSkepticExecution,
    arm_path: Path,
    *,
    provider_shard_id: str | None = None,
    intent_path: Path | None = None,
) -> None:
    arm = _strict_json_path(arm_path, "provider arm")
    process = arm.get("process_intent")
    output = arm.get("output_contract")
    bindings = arm.get("bindings")
    environment = arm.get("environment")
    if not isinstance(process, Mapping) or not isinstance(output, Mapping):
        raise SkepticExecutionWorkError("provider arm contracts are malformed")
    expected_environment = dict(request.environment)
    redacted_child_environment = request.backend.casefold() == "claude"
    if environment != {
        "allowlist_names": sorted(request.environment_allowlist),
        "allowlist_sha256": environment_allowlist_sha256(
            request.environment_allowlist
        ),
        "effective_names": sorted(expected_environment),
        "effective_sha256": (
            None
            if redacted_child_environment
            else _environment_effective_digest(expected_environment)
        ),
        "value_digest_persisted": not redacted_child_environment,
        "value_authority": (
            "CLAUDE_CHILD_ENVIRONMENT_IN_MEMORY_REPLAY"
            if redacted_child_environment
            else "DURABLE_EFFECTIVE_VALUE_SHA256"
        ),
        "values_persisted": False,
    }:
        raise SkepticExecutionWorkError("provider environment differs from exact intent")
    if tuple(process.get("argv") or ()) != request.resolved_argv:
        raise SkepticExecutionWorkError("provider argv differs from exact intent")
    if process.get("cwd") != str(request.cwd):
        raise SkepticExecutionWorkError("provider cwd differs from exact intent")
    if process.get("timeout_seconds") != str(request.timeout_seconds):
        raise SkepticExecutionWorkError("provider timeout differs from exact intent")
    if process.get("stream_limits") != {
        "stdout_bytes": request.stdout_limit_bytes,
        "stderr_bytes": request.stderr_limit_bytes,
    }:
        raise SkepticExecutionWorkError("provider stream limits differ from intent")
    stdin = process.get("stdin")
    packet_relative = _relative_inside(request.scratchpad, request.packet_path, "packet")
    packet_raw = request.packet_path.read_bytes()
    if stdin != {
        "state": "BOUND_INPUT",
        "input_name": "prompt",
        "relative_path": packet_relative,
        "sha256": _digest_bytes(packet_raw),
        "size": len(packet_raw),
    }:
        raise SkepticExecutionWorkError("provider stdin is not the exact packet")
    if (
        output.get("source_mode") != STDOUT_ASSIGNED_OUTPUT
        or output.get("scope_relative") != request.layout.output_scope_relative
        or output.get("preexisting_files") != []
        or len(output.get("expected_outputs") or []) != 1
    ):
        raise SkepticExecutionWorkError("provider stdout output contract changed")
    expected = output["expected_outputs"][0]
    if (
        expected.get("assignment_id") != request.shard_id
        or expected.get("relative_path") != "assessment.json"
        or expected.get("publish_relative_path")
        != request.layout.canonical_output_relative
    ):
        raise SkepticExecutionWorkError("provider output assignment changed")
    input_records = bindings.get("inputs") if isinstance(bindings, Mapping) else None
    prompt_record = input_records.get("prompt") if isinstance(input_records, Mapping) else None
    if not isinstance(prompt_record, Mapping) or (
        prompt_record.get("relative_path") != packet_relative
        or prompt_record.get("sha256") != _digest_bytes(packet_raw)
        or prompt_record.get("size") != len(packet_raw)
    ):
        raise SkepticExecutionWorkError("provider packet semantic binding changed")
    intent_record = input_records.get("intent") if isinstance(input_records, Mapping) else None
    exact_intent = intent_path or request.intent_path
    intent_relative = _relative_inside(request.scratchpad, exact_intent, "intent")
    intent_raw = exact_intent.read_bytes()
    if not isinstance(intent_record, Mapping) or (
        intent_record.get("relative_path") != intent_relative
        or intent_record.get("sha256") != _digest_bytes(intent_raw)
        or intent_record.get("size") != len(intent_raw)
    ):
        raise SkepticExecutionWorkError("provider intent binding changed")


def _write_retry_intent(
    request: PreparedSkepticExecution,
    *,
    debt_path: Path,
    arm_path: Path,
) -> dict[str, Any]:
    debt_raw = _stable_regular_file_bytes(debt_path, "predecessor provider debt")
    arm_raw = _stable_regular_file_bytes(arm_path, "predecessor provider arm")
    unsigned = {
        "schema_version": RETRY_SCHEMA,
        "run_id": request.run_id,
        "workflow": request.workflow,
        "shard_id": request.shard_id,
        "request_sha256": request.request_digest,
        "effective_backend": request.backend,
        "effective_model": request.model,
        "environment_allowlist_sha256": environment_allowlist_sha256(
            request.environment_allowlist
        ),
        "predecessor_provider_shard_id": request.layout.provider_shard_id,
        "retry_provider_shard_id": request.layout.retry_provider_shard_id,
        "predecessor_debt_relative_path": _relative_inside(
            request.scratchpad, debt_path, "predecessor debt"
        ),
        "predecessor_debt_sha256": _digest_bytes(debt_raw),
        "predecessor_arm_relative_path": _relative_inside(
            request.scratchpad, arm_path, "predecessor arm"
        ),
        "predecessor_arm_sha256": _digest_bytes(arm_raw),
        "attempt": 2,
    }
    payload = {**unsigned, "retry_intent_sha256": _digest(unsigned)}
    _write_immutable(request.layout.retry_intent_path, _canonical(payload))
    return payload


def _load_retry_intent(request: PreparedSkepticExecution) -> dict[str, Any] | None:
    path = request.layout.retry_intent_path
    if not path.exists():
        return None
    payload = _strict_json_path(path, "skeptic retry intent")
    unsigned = {key: value for key, value in payload.items() if key != "retry_intent_sha256"}
    if (
        payload.get("schema_version") != RETRY_SCHEMA
        or payload.get("retry_intent_sha256") != _digest(unsigned)
        or payload.get("request_sha256") != request.request_digest
        or payload.get("retry_provider_shard_id")
        != request.layout.retry_provider_shard_id
        or payload.get("predecessor_provider_shard_id")
        != request.layout.provider_shard_id
        or payload.get("attempt") != 2
    ):
        raise SkepticExecutionWorkError("skeptic retry intent binding changed")
    for kind in ("debt", "arm"):
        relative = payload.get(f"predecessor_{kind}_relative_path")
        if not isinstance(relative, str):
            raise SkepticExecutionWorkError("skeptic retry predecessor path is invalid")
        path_value = request.scratchpad / relative
        raw = _stable_regular_file_bytes(path_value, f"predecessor {kind}")
        if _digest_bytes(raw) != payload.get(f"predecessor_{kind}_sha256"):
            raise SkepticExecutionWorkError("skeptic retry predecessor changed")
    return payload


def _retry_is_safe(
    request: PreparedSkepticExecution, debt_path: Path | None, arm_path: Path | None
) -> bool:
    if debt_path is None or arm_path is None:
        return False
    if request.containment_debt_path.exists() or request.layout.canonical_output_path.exists():
        return False
    try:
        debt = _strict_json_path(debt_path, "provider debt")
        _validate_provider_arm(request, arm_path)
    except SkepticExecutionWorkError:
        return False
    return debt.get("reason_code") in {
        "NONZERO_EXIT",
        "TIMEOUT",
        "PROCESS_LAUNCH_FAILED",
    }


@dataclass(frozen=True)
class _RecoveredProviderExecution:
    execution: CompletedExecution
    attempt: int
    predecessor_debt_sha256: str = ""
    predecessor_arm_sha256: str = ""


def _recover_provider_execution(
    request: PreparedSkepticExecution,
    *,
    strict_parser: Callable[[Path, bytes], str],
) -> _RecoveredProviderExecution | None:
    completions, publishes, debts, provider_state_exists = _provider_receipts(request)
    if not provider_state_exists:
        return None
    retry = _load_retry_intent(request)
    if debts:
        if len(debts) != 1 or completions or publishes or retry is None:
            raise SkepticExecutionWorkError(
                "provider execution debt blocks resume and relaunch: "
                + ", ".join(path.name for path in debts)
            )
        retry_completions, retry_publishes, retry_debts, retry_exists = (
            _provider_receipts(
                request,
                provider_shard_id=request.layout.retry_provider_shard_id,
            )
        )
        if not retry_exists or retry_debts:
            raise SkepticExecutionWorkError(
                "predecessor-bound retry is absent or incomplete"
            )
        if len(retry_completions) != 1 or len(retry_publishes) != 1:
            raise SkepticExecutionWorkError(
                "incomplete or ambiguous retry provider evidence blocks resume"
            )
        completion_sha = _receipt_digest(retry_completions[0], "completion")
        publish_sha = _receipt_digest(retry_publishes[0], "publish")
        try:
            completion = validate_completed_execution(
                scratchpad=request.scratchpad,
                receipt_path=retry_completions[0],
                publish_receipt_path=retry_publishes[0],
                parser_digest=strict_parser,
                expected_completion_sha256=completion_sha,
                expected_publish_sha256=publish_sha,
            )
        except WorkerExecutionError as exc:
            raise SkepticExecutionWorkError(
                f"retry provider completion does not replay: {exc}"
            ) from exc
        arm_name = completion.get("arm_relative_path")
        if not isinstance(arm_name, str) or Path(arm_name).name != arm_name:
            raise SkepticExecutionWorkError("retry provider completion arm path is invalid")
        arm_path = retry_completions[0].parent / arm_name
        arm_sha = _require_hex(completion.get("arm_sha256"), "retry provider arm digest")
        _validate_provider_arm(
            request,
            arm_path,
            provider_shard_id=request.layout.retry_provider_shard_id,
            intent_path=request.layout.retry_intent_path,
        )
        return _RecoveredProviderExecution(
            CompletedExecution(
                receipt_path=retry_completions[0],
                completion_sha256=completion_sha,
                arm_path=arm_path,
                arm_sha256=arm_sha,
                publish_receipt_path=retry_publishes[0],
                publish_sha256=publish_sha,
                published_paths=(request.layout.canonical_output_path,),
            ),
            attempt=2,
            predecessor_debt_sha256=str(retry["predecessor_debt_sha256"]),
            predecessor_arm_sha256=str(retry["predecessor_arm_sha256"]),
        )
    if retry is not None:
        raise SkepticExecutionWorkError(
            "retry intent exists without predecessor provider debt"
        )
    if len(completions) != 1 or len(publishes) != 1:
        raise SkepticExecutionWorkError(
            "incomplete or ambiguous provider evidence blocks resume and relaunch"
        )
    completion_sha = _receipt_digest(completions[0], "completion")
    publish_sha = _receipt_digest(publishes[0], "publish")
    try:
        completion = validate_completed_execution(
            scratchpad=request.scratchpad,
            receipt_path=completions[0],
            publish_receipt_path=publishes[0],
            parser_digest=strict_parser,
            expected_completion_sha256=completion_sha,
            expected_publish_sha256=publish_sha,
        )
    except WorkerExecutionError as exc:
        raise SkepticExecutionWorkError(
            f"provider completion does not replay: {exc}"
        ) from exc
    arm_name = completion.get("arm_relative_path")
    if not isinstance(arm_name, str) or Path(arm_name).name != arm_name:
        raise SkepticExecutionWorkError("provider completion arm path is invalid")
    arm_path = completions[0].parent / arm_name
    arm_sha = _require_hex(completion.get("arm_sha256"), "provider arm digest")
    _validate_provider_arm(request, arm_path)
    return _RecoveredProviderExecution(
        CompletedExecution(
            receipt_path=completions[0],
            completion_sha256=completion_sha,
            arm_path=arm_path,
            arm_sha256=arm_sha,
            publish_receipt_path=publishes[0],
            publish_sha256=publish_sha,
            published_paths=(request.layout.canonical_output_path,),
        ),
        attempt=1,
    )


def _as_observed(
    request: PreparedSkepticExecution,
    recovered: _RecoveredProviderExecution,
    *,
    authority_sidecar_sha256: str = "",
) -> ObservedSkepticExecution:
    execution = recovered.execution
    return ObservedSkepticExecution(
        request_digest=request.request_digest,
        provider_completion_path=execution.receipt_path,
        provider_completion_sha256=execution.completion_sha256,
        provider_arm_path=execution.arm_path,
        provider_arm_sha256=execution.arm_sha256,
        provider_publish_path=execution.publish_receipt_path,
        provider_publish_sha256=execution.publish_sha256,
        canonical_output_path=request.layout.canonical_output_path,
        authority_sidecar_path=request.layout.authority_sidecar_path,
        authority_sidecar_sha256=authority_sidecar_sha256,
        attempt=recovered.attempt,
        predecessor_debt_sha256=recovered.predecessor_debt_sha256,
        predecessor_arm_sha256=recovered.predecessor_arm_sha256,
        output_source_mode=STDOUT_ASSIGNED_OUTPUT,
        terminal_negative_closure_eligible=(
            request.terminal_negative_closure_eligible
        ),
        terminal_negative_closure_reason=request.terminal_negative_closure_reason,
    )


def _authority_payload(
    request: PreparedSkepticExecution,
    recovered: _RecoveredProviderExecution,
) -> dict[str, Any]:
    execution = recovered.execution
    output_raw = _stable_regular_file_bytes(
        request.layout.canonical_output_path, "canonical skeptic output"
    )
    executable = Path(request.resolved_argv[0]).resolve(strict=True)
    unsigned = {
        "schema_version": AUTHORITY_SCHEMA,
        "state": "VALIDATED_PROVIDER_PUBLICATION",
        "run_id": request.run_id,
        "workflow": request.workflow,
        "shard_id": request.shard_id,
        "provider_shard_id": execution.receipt_path.parent.name,
        "attempt": recovered.attempt,
        "request_sha256": request.request_digest,
        "packet_sha256": _digest_bytes(request.packet_path.read_bytes()),
        "arm_sha256": execution.arm_sha256,
        "completion_sha256": execution.completion_sha256,
        "publication_sha256": execution.publish_sha256,
        "output_relative_path": request.layout.canonical_output_relative,
        "output_sha256": _digest_bytes(output_raw),
        "output_size_bytes": len(output_raw),
        "resolved_executable": str(executable),
        "executable_sha256": _digest_bytes(executable.read_bytes()),
        "argv_sha256": _digest(list(request.argv)),
        "predecessor_debt_sha256": recovered.predecessor_debt_sha256,
        "predecessor_arm_sha256": recovered.predecessor_arm_sha256,
        "terminal_negative_closure_eligible": (
            request.terminal_negative_closure_eligible
        ),
        "terminal_negative_closure_reason": (
            request.terminal_negative_closure_reason
        ),
    }
    return {**unsigned, "authority_sha256": _digest(unsigned)}


def _write_authority_sidecar(
    request: PreparedSkepticExecution,
    recovered: _RecoveredProviderExecution,
) -> str:
    payload = _authority_payload(request, recovered)
    raw = _canonical(payload)
    path = request.layout.authority_sidecar_path
    if path.exists():
        current = _stable_regular_file_bytes(path, "skeptic provider authority")
        if current != raw:
            raise SkepticExecutionWorkError(
                "skeptic provider authority sidecar differs from replay"
            )
    else:
        _write_immutable(path, raw)
    return _digest_bytes(raw)


def validate_skeptic_provider_authority(
    request: PreparedSkepticExecution,
    sidecar_path: str | Path,
    *,
    parser_digest: Callable[[Path, bytes], str],
) -> dict[str, Any]:
    """Replay the complete compact authority projection for one shard."""

    _replay_prepared_request(request, parser_digest=parser_digest)
    path = Path(sidecar_path).resolve(strict=True)
    if path != request.layout.authority_sidecar_path.resolve(strict=True):
        raise SkepticExecutionWorkError("provider authority sidecar path changed")
    payload = _strict_json_path(path, "skeptic provider authority")
    strict_parser = _make_strict_parser(request, parser_digest)
    recovered = _recover_provider_execution(request, strict_parser=strict_parser)
    if recovered is None:
        raise SkepticExecutionWorkError("provider execution authority is absent")
    expected = _authority_payload(request, recovered)
    if payload != expected:
        raise SkepticExecutionWorkError("provider authority sidecar binding changed")
    return payload


def write_skeptic_live_canary_receipt(
    request: PreparedSkepticExecution,
    observed: ObservedSkepticExecution,
    destination: str | Path,
    *,
    parser_digest: Callable[[Path, bytes], str],
    canary_id: str,
) -> Path:
    """Persist a replayable, non-semantic transport canary receipt."""

    validated = validate_skeptic_execution(
        request, observed, parser_digest=parser_digest
    )
    authority = validate_skeptic_provider_authority(
        request, validated.authority_sidecar_path, parser_digest=parser_digest
    )
    unsigned = {
        "schema_version": CANARY_SCHEMA,
        "canary_id": _require_id(canary_id, "canary_id"),
        "status": "PASS",
        "semantic_authority": "NONE_TRANSPORT_ONLY",
        "run_id": request.run_id,
        "workflow": request.workflow,
        "shard_id": request.shard_id,
        "request_sha256": request.request_digest,
        "authority_sha256": authority["authority_sha256"],
        "authority_sidecar_sha256": validated.authority_sidecar_sha256,
        "attempt": validated.attempt,
    }
    payload = {**unsigned, "receipt_sha256": _digest(unsigned)}
    path = Path(destination)
    raw = _canonical(payload)
    if path.exists():
        if _stable_regular_file_bytes(path, "live canary receipt") != raw:
            raise SkepticExecutionWorkError("live canary receipt collision")
    else:
        _write_immutable(path, raw)
    return path


def validate_skeptic_execution(
    request: PreparedSkepticExecution,
    observed: ObservedSkepticExecution,
    *,
    parser_digest: Callable[[Path, bytes], str],
) -> ObservedSkepticExecution:
    """Replay immutable inputs, provider completion, publication, and current bytes."""

    _replay_prepared_request(request, parser_digest=parser_digest)
    strict_parser = _make_strict_parser(request, parser_digest)
    recovered = _recover_provider_execution(request, strict_parser=strict_parser)
    if recovered is None:
        raise SkepticExecutionWorkError("provider execution authority is absent")
    authority = validate_skeptic_provider_authority(
        request,
        request.layout.authority_sidecar_path,
        parser_digest=parser_digest,
    )
    replay = _as_observed(
        request,
        recovered,
        authority_sidecar_sha256=_digest_bytes(
            request.layout.authority_sidecar_path.read_bytes()
        ),
    )
    if replay != observed:
        raise SkepticExecutionWorkError("caller handle differs from replayed authority")
    if authority.get("authority_sha256") is None:
        raise SkepticExecutionWorkError("provider authority is incomplete")
    return replay


def _run_provider_attempt(
    request: PreparedSkepticExecution,
    *,
    strict_parser: Callable[[Path, bytes], str],
    provider_shard_id: str,
    intent_path: Path,
    startup_authority_binding: Mapping[str, Any] | None,
) -> CompletedExecution:
    before = _capture_boundary(request)
    try:
        execution = run_observed_worker(
            scratchpad=request.scratchpad,
            bindings=_execution_bindings(
                request,
                provider_shard_id=provider_shard_id,
                intent_path=intent_path,
            ),
            argv=request.argv,
            cwd=request.cwd,
            output_scope_relative=request.layout.output_scope_relative,
            expected_outputs=(
                ExpectedOutput(
                    request.shard_id,
                    "assessment.json",
                    request.layout.canonical_output_relative,
                ),
            ),
            parser_digest=strict_parser,
            environment=dict(request.environment),
            environment_allowlist=request.environment_allowlist,
            stdin_input=BoundInput(
                _relative_inside(request.scratchpad, request.packet_path, "packet")
            ),
            timeout_seconds=request.timeout_seconds,
            output_source_mode=STDOUT_ASSIGNED_OUTPUT,
            stdout_limit_bytes=request.stdout_limit_bytes,
            stderr_limit_bytes=request.stderr_limit_bytes,
            startup_authority_binding=startup_authority_binding,
        )
    except (WorkerExecutionIncomplete, WorkerExecutionError):
        offenders = _reconcile_boundary(
            request,
            before,
            provider_ids=(
                request.layout.provider_shard_id,
                request.layout.retry_provider_shard_id,
            ),
            provider_id=provider_shard_id,
        )
        if offenders:
            _quarantine_canonical_output(request, reason="containment violation")
            raise SkepticExecutionWorkError(
                "skeptic provider containment violation: " + ", ".join(offenders)
            )
        raise
    offenders = _reconcile_boundary(
        request,
        before,
        provider_ids=(
            request.layout.provider_shard_id,
            request.layout.retry_provider_shard_id,
        ),
        provider_id=provider_shard_id,
    )
    if offenders:
        _quarantine_canonical_output(request, reason="containment violation")
        raise SkepticExecutionWorkError(
            "skeptic provider containment violation: " + ", ".join(offenders)
        )
    return execution


def execute_or_resume_skeptic_execution(
    request: PreparedSkepticExecution,
    *,
    parser_digest: Callable[[Path, bytes], str],
    startup_authority_binding: Mapping[str, Any] | None = None,
) -> ObservedSkepticExecution:
    """Resume one exact provider chain or launch it exactly once."""

    if request.backend.casefold() == "claude":
        raise SkepticExecutionWorkError(
            "Claude skeptic execution requires the driver-owned headless "
            "worker transaction; legacy direct launch/replay is forbidden"
        )

    _replay_prepared_request(request, parser_digest=parser_digest)
    strict_parser = _make_strict_parser(request, parser_digest)
    try:
        recovered = _recover_provider_execution(request, strict_parser=strict_parser)
    except SkepticExecutionWorkError:
        _quarantine_canonical_output(request, reason="invalid persisted provider state")
        raise
    if recovered is not None:
        try:
            sidecar_sha = _write_authority_sidecar(request, recovered)
            observed = _as_observed(
                request, recovered, authority_sidecar_sha256=sidecar_sha
            )
            return validate_skeptic_execution(
                request, observed, parser_digest=parser_digest
            )
        except SkepticExecutionWorkError:
            _quarantine_canonical_output(request, reason="provider replay failed")
            raise
    if request.layout.canonical_output_path.exists():
        raise SkepticExecutionWorkError(
            "canonical assessment exists without provider publication authority"
        )
    if (
        request.backend.casefold() in {"claude", "codex"}
        and startup_authority_binding is None
    ):
        raise SkepticExecutionWorkError(
            "model skeptic launch lacks startup authority"
        )
    try:
        execution = _run_provider_attempt(
            request,
            strict_parser=strict_parser,
            provider_shard_id=request.layout.provider_shard_id,
            intent_path=request.intent_path,
            startup_authority_binding=startup_authority_binding,
        )
    except WorkerExecutionIncomplete as exc:
        if not _retry_is_safe(request, exc.debt_path, exc.arm_path):
            _quarantine_canonical_output(request, reason="provider incomplete")
            raise SkepticExecutionIncomplete(
                f"provider execution incomplete: {exc}",
                provider_debt_path=exc.debt_path,
                provider_arm_path=exc.arm_path,
            ) from exc
        retry = _write_retry_intent(
            request, debt_path=exc.debt_path, arm_path=exc.arm_path
        )
        try:
            execution = _run_provider_attempt(
                request,
                strict_parser=strict_parser,
                provider_shard_id=request.layout.retry_provider_shard_id,
                intent_path=request.layout.retry_intent_path,
                startup_authority_binding=startup_authority_binding,
            )
        except WorkerExecutionIncomplete as retry_exc:
            _quarantine_canonical_output(request, reason="provider retry incomplete")
            raise SkepticExecutionIncomplete(
                f"provider retry incomplete: {retry_exc}",
                provider_debt_path=retry_exc.debt_path,
                provider_arm_path=retry_exc.arm_path,
            ) from retry_exc
        recovered = _RecoveredProviderExecution(
            execution,
            attempt=2,
            predecessor_debt_sha256=str(retry["predecessor_debt_sha256"]),
            predecessor_arm_sha256=str(retry["predecessor_arm_sha256"]),
        )
    except WorkerExecutionError as exc:
        _quarantine_canonical_output(request, reason="provider launch rejected")
        raise SkepticExecutionWorkError(f"provider launch rejected: {exc}") from exc
    else:
        recovered = _RecoveredProviderExecution(execution, attempt=1)
    try:
        _validate_provider_arm(
            request,
            recovered.execution.arm_path,
            provider_shard_id=(
                request.layout.retry_provider_shard_id
                if recovered.attempt == 2
                else request.layout.provider_shard_id
            ),
            intent_path=(
                request.layout.retry_intent_path
                if recovered.attempt == 2
                else request.intent_path
            ),
        )
        # Replaying queue bytes here catches a source-queue change during the
        # child run before the assessment can be imported by the driver.
        _replay_prepared_request(request, parser_digest=parser_digest)
        sidecar_sha = _write_authority_sidecar(request, recovered)
        observed = _as_observed(
            request, recovered, authority_sidecar_sha256=sidecar_sha
        )
        return validate_skeptic_execution(
            request, observed, parser_digest=parser_digest
        )
    except SkepticExecutionWorkError:
        _quarantine_canonical_output(request, reason="provider state incomplete or tampered")
        raise


__all__ = [
    "AUTHORITY_SCHEMA",
    "CANARY_SCHEMA",
    "CONTAINMENT_SCHEMA",
    "INTENT_SCHEMA",
    "MANIFEST_SCHEMA",
    "PACKET_SCHEMA",
    "SKEPTIC_SYSTEM_PROMPT",
    "TOOL_POLICY_SCHEMA",
    "ObservedSkepticExecution",
    "PreparedSkepticExecution",
    "SkepticExecutionIncomplete",
    "SkepticExecutionLayout",
    "SkepticExecutionWorkError",
    "canonical_backend_argv",
    "canonical_tool_policy",
    "execute_or_resume_skeptic_execution",
    "prepare_skeptic_execution",
    "quarantine_skeptic_provider_output",
    "skeptic_execution_layout",
    "skeptic_provider_authority_sidecar_name",
    "terminal_negative_closure_eligibility",
    "timeout_process_tree_capability",
    "validate_skeptic_backend_contract",
    "validate_skeptic_context_queue_bindings",
    "validate_skeptic_execution",
    "validate_skeptic_provider_authority",
    "write_skeptic_live_canary_receipt",
]
