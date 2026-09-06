"""Disposable per-attempt host for the owned non-interactive runner.

The long-lived coordinator never acquires the Windows low-integrity lease and
never owns the provider Job.  It starts one medium-integrity executor inside a
separate kill-on-close parent Job and sends one closed, registered command over
an in-memory pipe.  The short-lived executor imports ``run_owned_process`` and
therefore owns the inner lease and provider Job for its entire lifetime.

No request payload is placed in the executor argv, a durable file, or a log.
The JSON control plane exists only in anonymous stdin/stdout pipes.  Terminal
receipts are closed-schema and digest-bound to the exact request and executor
PID.  A missing, forged, or ambiguous receipt can only produce debt.

This first slice is intentionally Windows-only.  A portable implementation
needs an equally strong parent-death/process-tree primitive on each host.
"""
from __future__ import annotations

import base64
import binascii
import copy
import csv
import ctypes
from dataclasses import dataclass
from email import policy as email_policy
from email.parser import BytesParser
import hashlib
import importlib.abc
import importlib.machinery
import importlib.util
import io
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import site
import subprocess
import sys
import sysconfig
import threading
import time
from typing import Any, Mapping, Sequence
import uuid


_MODULE_ROOT = Path(__file__).resolve().parent
if str(_MODULE_ROOT) not in sys.path:
    # ``-I -S`` deliberately removes ambient import paths.  The executor may
    # import only sibling implementation modules from the exact directory that
    # contains this already-selected host script.
    sys.path.insert(0, str(_MODULE_ROOT))
if __name__ == "__main__":
    # The request-bound dependency replay uses the stable import identity in
    # both coordinator and script-mode executor without importing this file a
    # second time under another module object.
    sys.modules.setdefault("isolated_execution_host", sys.modules[__name__])


class _ExactLocalSourceLoader(importlib.machinery.SourceFileLoader):
    """Compile one authenticated local source path without consulting pyc."""

    def get_code(self, fullname: str) -> Any:
        source_path = self.get_filename(fullname)
        source_bytes = self.get_data(source_path)
        return self.source_to_code(source_bytes, source_path)


class _ExactLocalSourceFinder(importlib.abc.MetaPathFinder):
    """Prevent extension/package/bytecode shadowing of executor authority."""

    def __init__(self, sources: Mapping[str, Path]) -> None:
        self._sources = {
            name: path.resolve(strict=True) for name, path in sources.items()
        }

    def find_spec(
        self,
        fullname: str,
        path: Any = None,
        target: Any = None,
    ) -> Any:
        del path, target
        source = self._sources.get(fullname)
        if source is None:
            return None
        loader = _ExactLocalSourceLoader(fullname, str(source))
        return importlib.util.spec_from_file_location(
            fullname,
            source,
            loader=loader,
        )


_EXACT_LOCAL_SOURCES = {
    name: _MODULE_ROOT / f"{name}.py"
    for name in (
        "bounded_artifact_io",
        "owned_process_runner",
        "owned_process_scope",
        "locked_executable_guard",
        "windows_low_integrity_lease",
    )
}
sys.meta_path.insert(0, _ExactLocalSourceFinder(_EXACT_LOCAL_SOURCES))

from bounded_artifact_io import read_bounded_regular_bytes


SCHEMA_VERSION = 1
HANDLER_RUN_OWNED_PROCESS = "RUN_OWNED_PROCESS_V1"
HANDLER_RUN_WER_PROVIDER = "RUN_WER_PROVIDER_V1"
REGISTERED_HANDLER_IDS = (
    HANDLER_RUN_OWNED_PROCESS,
    HANDLER_RUN_WER_PROVIDER,
)
MAX_REQUEST_BYTES = 32 * 1024 * 1024
MAX_RECEIPT_BYTES = 64 * 1024 * 1024
MAX_EXECUTOR_STDERR_BYTES = 64 * 1024
DEFAULT_COORDINATOR_GRACE_SECONDS = 20.0
# Dependency staging is outside the provider's execution timeout: the child
# must copy, kernel-seal, import, and replay the full RECORD closure before the
# provider process can arm.  Keep this as an explicit bounded coordinator
# allowance rather than silently consuming the provider's own time budget.
DEFAULT_RUNTIME_DEPENDENCY_STAGE_GRACE_SECONDS = 90.0

_SEMANTIC_RUNTIME_EXTERNAL_PREFIXES = frozenset(
    {
        "attr",
        "attrs",
        "jsonschema",
        "jsonschema_specifications",
        "referencing",
        "rpds",
        "typing_extensions",
    }
)
_SEMANTIC_RUNTIME_DISTRIBUTIONS = (
    "attrs",
    "jsonschema",
    "jsonschema-specifications",
    "referencing",
    "rpds-py",
    "typing-extensions",
)
_SEMANTIC_RUNTIME_PREFIX_DISTRIBUTION = {
    "attr": "attrs",
    "attrs": "attrs",
    "jsonschema": "jsonschema",
    "jsonschema_specifications": "jsonschema-specifications",
    "referencing": "referencing",
    "rpds": "rpds-py",
    "typing_extensions": "typing-extensions",
}
_DISTRIBUTION_NAME_SEPARATOR_RE = re.compile(r"[-_.]+", re.ASCII)
_FILE_ATTRIBUTE_REPARSE_POINT = 0x400

_CREATE_SUSPENDED = 0x00000004
_CREATE_NEW_PROCESS_GROUP = 0x00000200
_JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
_JOB_OBJECT_EXTENDED_LIMIT_INFORMATION = 9
_JOB_OBJECT_BASIC_ACCOUNTING_INFORMATION = 1

_REQUEST_KEYS = {
    "schema_version",
    "handler_id",
    "request_id",
    "payload",
    "request_sha256",
}
_OWNED_PROCESS_PAYLOAD_KEYS = {
    "requested_command",
    "command",
    "executable_guard",
    "cwd",
    "env",
    "timeout",
    "encoding",
    "errors",
    "output_limit_bytes",
    "writable_roots",
}
_WER_PROVIDER_CORE_KEYS = {
    "semantic_authority",
    "scratchpad",
    "bindings",
    "argv",
    "cwd",
    "output_scope_relative",
    "expected_outputs",
    "parser_binding",
    "environment",
    "environment_allowlist",
    "stdin_input_relative_path",
    "timeout_seconds",
    "lock_timeout_seconds",
    "output_source_mode",
    "stdout_limit_bytes",
    "stderr_limit_bytes",
    "staged_output_limit_bytes",
    "publish_canonical",
    "process_scope_identity",
    "implementation_files",
    "runtime_dependency_binding",
}
_WER_PROVIDER_PAYLOAD_KEYS = (
    _WER_PROVIDER_CORE_KEYS
    | {
        "outer_arm_sha256",
        "request_core_sha256",
    }
)
_RECEIPT_KEYS = {
    "schema_version",
    "receipt_type",
    "handler_id",
    "request_id",
    "request_sha256",
    "executor_pid",
    "completion_authority",
    "payload",
    "receipt_sha256",
}
_COMPLETED_PAYLOAD_KEYS = {
    "args",
    "returncode",
    "stdout",
    "stderr",
    "duration_s",
    "process_tree_terminated",
    "containment_capability",
}
_TIMEOUT_PAYLOAD_KEYS = {"timeout", "stdout", "stderr"}
_DEBT_PAYLOAD_KEYS = {"reason_code"}
_WER_CHILD_COMPLETED_PAYLOAD_KEYS = {
    "inner_receipt_relative_path",
    "inner_completion_sha256",
    "inner_arm_relative_path",
    "inner_arm_sha256",
    "publish_receipt_relative_path",
    "publish_sha256",
    "published_paths",
    "stdout_blob",
    "stderr_blob",
    "returncode",
    "inner_process_scope_identity",
    "inner_process_population_zero_proven",
    "process_observation_sha256",
    "semantic_authority_sha256",
    "request_core_sha256",
    "outer_arm_sha256",
    "implementation_files_sha256",
    "runtime_dependency_sha256",
}
_WER_CHILD_DEBT_PAYLOAD_KEYS = {
    "reason_code",
    "inner_arm_relative_path",
    "inner_debt_relative_path",
    "inner_arm_sha256",
    "inner_debt_sha256",
    "semantic_authority_sha256",
    "request_core_sha256",
    "outer_arm_sha256",
    "implementation_files_sha256",
    "runtime_dependency_sha256",
}
_WER_COORDINATOR_PAYLOAD_KEYS = {
    "child_receipt",
    "child_receipt_sha256",
    "executor_population_zero_proven",
    "runtime_dependency_sha256",
}
_WER_COORDINATOR_DEBT_PAYLOAD_KEYS = {
    "reason_code",
    "child_receipt",
    "child_receipt_sha256",
    "executor_population_zero_proven",
    "runtime_dependency_sha256",
}

_AMBIGUOUS_EXECUTOR_LATCH = False
_AMBIGUOUS_EXECUTOR_LOCK = threading.Lock()
_ACTIVE_EXECUTOR_REQUEST_ID: str | None = None


class IsolatedExecutionProtocolError(RuntimeError):
    """The in-memory executor request or terminal receipt is malformed."""


class IsolatedExecutionHostError(RuntimeError):
    """The disposable executor could not produce proof-grade completion."""

    def __init__(self, message: str, *, receipt: Mapping[str, Any]) -> None:
        super().__init__(message)
        self.receipt = copy.deepcopy(dict(receipt))


class IsolatedExecutionCancelled(IsolatedExecutionHostError):
    """The coordinator cancelled and reaped the exact executor Job."""


class SemanticDependencyIsolationUnavailable(RuntimeError):
    """The host cannot keep validated dependency bytes immutable for import."""

    reason_code = "RUNTIME_DEPENDENCY_IMMUTABILITY_UNAVAILABLE"


def _canonical_bytes(value: Mapping[str, Any]) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise IsolatedExecutionProtocolError(
            "isolated execution value is not canonical JSON"
        ) from exc


def _strict_json_loads(value: str) -> Any:
    def reject_constant(token: str) -> Any:
        raise ValueError(f"non-finite JSON constant: {token}")

    def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in pairs:
            if key in result:
                raise ValueError("duplicate JSON object key")
            result[key] = item
        return result

    decoded = json.loads(
        value,
        parse_constant=reject_constant,
        object_pairs_hook=reject_duplicate_keys,
    )

    def validate(item: Any, depth: int = 0) -> None:
        if depth > 128:
            raise ValueError("JSON nesting exceeds the protocol bound")
        if isinstance(item, str):
            if any(0xD800 <= ord(character) <= 0xDFFF for character in item):
                raise ValueError("JSON contains a surrogate code point")
            return
        if isinstance(item, list):
            for member in item:
                validate(member, depth + 1)
            return
        if isinstance(item, dict):
            for key, member in item.items():
                validate(key, depth + 1)
                validate(member, depth + 1)

    validate(decoded)
    return decoded


def _sha(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _digest_request(candidate: Mapping[str, Any]) -> str:
    core = {
        key: copy.deepcopy(value)
        for key, value in candidate.items()
        if key != "request_sha256"
    }
    return _sha(core)


def _digest_receipt(candidate: Mapping[str, Any]) -> str:
    core = {
        key: copy.deepcopy(value)
        for key, value in candidate.items()
        if key != "receipt_sha256"
    }
    return _sha(core)


def _build_request(
    *,
    command: Sequence[str],
    cwd: str | Path | None,
    env: Mapping[str, str] | None,
    timeout: float,
    encoding: str,
    errors: str,
    output_limit_bytes: int,
    writable_roots: Sequence[str | Path],
) -> dict[str, Any]:
    from locked_executable_guard import bind_locked_executable
    from owned_process_runner import resolve_owned_process_command

    target_env = dict(os.environ) if env is None else dict(env)
    requested_command = [str(item) for item in command]
    resolved_command = resolve_owned_process_command(
        requested_command,
        env=target_env,
    )
    executable_guard = bind_locked_executable(resolved_command[0])
    return _build_typed_request(
        handler_id=HANDLER_RUN_OWNED_PROCESS,
        payload={
            "requested_command": requested_command,
            "command": list(resolved_command),
            "executable_guard": executable_guard,
            "cwd": None if cwd is None else str(cwd),
            "env": target_env,
            "timeout": timeout,
            "encoding": encoding,
            "errors": errors,
            "output_limit_bytes": output_limit_bytes,
            "writable_roots": [str(item) for item in writable_roots],
        },
    )


def _build_typed_request(
    *,
    handler_id: str,
    payload: Mapping[str, Any],
) -> dict[str, Any]:
    core: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "handler_id": handler_id,
        "request_id": uuid.uuid4().hex,
        "payload": copy.deepcopy(dict(payload)),
    }
    request = {**core, "request_sha256": _sha(core)}
    _validate_request(request)
    if len(_canonical_bytes(request)) > MAX_REQUEST_BYTES:
        raise IsolatedExecutionProtocolError(
            "isolated execution request exceeds the in-memory bound"
        )
    return request


def wer_provider_request_core_sha256(
    payload_core: Mapping[str, Any],
) -> str:
    """Validate and digest the exact semantic WER executor request core."""

    normalized = _validate_wer_provider_core(payload_core)
    return _sha(
        {
            "schema": "plamen.isolated-wer-request-core.v1",
            "payload": normalized,
        }
    )


def _wer_implementation_files_sha256(
    payload: Mapping[str, Any],
) -> str:
    return _sha(
        {
            "implementation_files": copy.deepcopy(
                list(payload["implementation_files"])
            ),
        }
    )


def _build_wer_provider_request(
    payload_core: Mapping[str, Any],
    *,
    outer_arm_sha256: str,
) -> dict[str, Any]:
    core = _validate_wer_provider_core(payload_core)
    outer_arm = _require_hex64(
        outer_arm_sha256,
        "isolated WER outer arm digest",
    )
    payload = {
        **core,
        "outer_arm_sha256": outer_arm,
        "request_core_sha256": wer_provider_request_core_sha256(core),
    }
    return _build_typed_request(
        handler_id=HANDLER_RUN_WER_PROVIDER,
        payload=payload,
    )


def _require_hex64(value: Any, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(ch not in "0123456789abcdef" for ch in value)
    ):
        raise IsolatedExecutionProtocolError(f"{field} is invalid")
    return value


def _validate_relative_path(value: Any, field: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or "\x00" in value
        or Path(value).is_absolute()
        or value.replace("\\", "/").startswith("../")
        or "/../" in value.replace("\\", "/")
    ):
        raise IsolatedExecutionProtocolError(f"{field} is invalid")
    return Path(value).as_posix()


def _wer_semantic_authority_sha256(
    value: Mapping[str, Any],
) -> str:
    return _sha(
        {
            "schema": "plamen.isolated-wer-semantic-authority.v1",
            "plan": value["plan"],
            "execution": value["execution"],
            "attempt": value["attempt"],
            "snapshot": value["snapshot"],
        }
    )


def _validate_runtime_file_record(
    value: Mapping[str, Any],
    *,
    label: str,
) -> dict[str, Any]:
    if (
        not isinstance(value, Mapping)
        or set(value) != {"path", "sha256", "size"}
        or not isinstance(value.get("path"), str)
        or not Path(value["path"]).is_absolute()
    ):
        raise IsolatedExecutionProtocolError(f"{label} is invalid")
    claimed = _require_hex64(value.get("sha256"), f"{label} digest")
    size = value.get("size")
    if isinstance(size, bool) or not isinstance(size, int) or size < 0:
        raise IsolatedExecutionProtocolError(f"{label} size is invalid")
    try:
        path = Path(value["path"]).resolve(strict=True)
        raw = path.read_bytes()
    except OSError as exc:
        raise IsolatedExecutionProtocolError(
            f"{label} is unavailable"
        ) from exc
    if (
        str(path) != value["path"]
        or not path.is_file()
        or len(raw) != size
        or hashlib.sha256(raw).hexdigest() != claimed
    ):
        raise IsolatedExecutionProtocolError(f"{label} bytes changed")
    return copy.deepcopy(dict(value))


def _canonical_distribution_name(value: Any) -> str:
    if not isinstance(value, str) or not value:
        raise IsolatedExecutionProtocolError(
            "isolated WER distribution name is invalid"
        )
    canonical = _DISTRIBUTION_NAME_SEPARATOR_RE.sub("-", value).lower()
    if not canonical or canonical != value:
        raise IsolatedExecutionProtocolError(
            "isolated WER distribution name is non-canonical"
        )
    return canonical


def _runtime_path_is_alias(path: Path) -> bool:
    try:
        info = path.lstat()
    except OSError as exc:
        raise IsolatedExecutionProtocolError(
            "isolated WER runtime path is unavailable"
        ) from exc
    return bool(
        path.is_symlink()
        or (hasattr(os.path, "isjunction") and os.path.isjunction(path))
        or getattr(info, "st_file_attributes", 0)
        & _FILE_ATTRIBUTE_REPARSE_POINT
    )


def _assert_runtime_path_chain(path: Path, *, label: str) -> Path:
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise IsolatedExecutionProtocolError(f"{label} is unavailable") from exc
    if str(resolved) != str(path):
        raise IsolatedExecutionProtocolError(
            f"{label} uses a case, symlink, or prefix alias"
        )
    try:
        final_info = resolved.stat()
    except OSError as exc:
        raise IsolatedExecutionProtocolError(
            f"{label} is unavailable"
        ) from exc
    if resolved.is_file() and final_info.st_nlink != 1:
        raise IsolatedExecutionProtocolError(
            f"{label} has a hardlink/link-count alias and is not race-stable"
        )
    current = resolved
    while True:
        if _runtime_path_is_alias(current):
            raise IsolatedExecutionProtocolError(
                f"{label} contains a symlink or reparse alias"
            )
        if current.parent == current:
            break
        current = current.parent
    return resolved


class _WindowsImmutableDependencyStage:
    """Copy dependency bytes into a handle-sealed, content-addressed tree.

    Every source is opened without write/delete sharing before it is read.
    Every staged file remains open without write/delete sharing until the
    provider has completed all imports and execution.  The held handles make
    source replacement, hardlink retargeting, staged replacement, and delete-
    then-recreate races fail at the kernel boundary on Windows.
    """

    _GENERIC_READ = 0x80000000
    _GENERIC_WRITE = 0x40000000
    _FILE_SHARE_READ = 0x00000001
    _CREATE_NEW = 1
    _OPEN_EXISTING = 3
    _FILE_ATTRIBUTE_NORMAL = 0x00000080
    _FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
    _FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
    _INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
    _KERNEL32: Any = None

    def __init__(self, root: Path) -> None:
        if os.name != "nt":
            raise SemanticDependencyIsolationUnavailable(
                "immutable dependency staging capability is unsupported "
                "on this host"
            )
        self.root = _assert_runtime_path_chain(
            root.resolve(strict=True),
            label="isolated WER immutable dependency stage",
        )
        if not self.root.is_dir():
            raise IsolatedExecutionProtocolError(
                "isolated WER immutable dependency stage is not a directory"
            )
        self._handles: list[int] = []
        self._directory_handles: dict[str, int] = {}
        self._records: dict[str, tuple[str, int]] = {}
        self._closed = False
        self._hold_directory(self.root)

    @classmethod
    def _kernel32(cls) -> Any:
        from ctypes import wintypes

        if cls._KERNEL32 is not None:
            return cls._KERNEL32
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateFileW.argtypes = [
            wintypes.LPCWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.c_void_p,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.HANDLE,
        ]
        kernel32.CreateFileW.restype = wintypes.HANDLE
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel32.CloseHandle.restype = wintypes.BOOL
        kernel32.FlushFileBuffers.argtypes = [wintypes.HANDLE]
        kernel32.FlushFileBuffers.restype = wintypes.BOOL
        kernel32.WriteFile.argtypes = [
            wintypes.HANDLE,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
            ctypes.c_void_p,
        ]
        kernel32.WriteFile.restype = wintypes.BOOL
        cls._KERNEL32 = kernel32
        return kernel32

    @classmethod
    def _open(
        cls,
        path: Path,
        *,
        access: int,
        creation: int,
        flags: int,
    ) -> int:
        kernel32 = cls._kernel32()
        handle = kernel32.CreateFileW(
            str(path),
            access,
            cls._FILE_SHARE_READ,
            None,
            creation,
            flags,
            None,
        )
        rendered = int(handle)
        if rendered == cls._INVALID_HANDLE_VALUE:
            error = ctypes.get_last_error()
            raise OSError(
                error,
                f"cannot seal immutable dependency path {path}",
            )
        return rendered

    @classmethod
    def _close_handle(cls, handle: int) -> None:
        kernel32 = cls._kernel32()
        if not kernel32.CloseHandle(ctypes.c_void_p(handle)):
            error = ctypes.get_last_error()
            raise OSError(
                error,
                "cannot close immutable dependency handle",
            )

    def _hold_directory(self, directory: Path) -> None:
        key = os.path.normcase(str(directory))
        if key in self._directory_handles:
            return
        handle = self._open(
            directory,
            access=self._GENERIC_READ,
            creation=self._OPEN_EXISTING,
            flags=(
                self._FILE_FLAG_BACKUP_SEMANTICS
                | self._FILE_FLAG_OPEN_REPARSE_POINT
            ),
        )
        try:
            if _runtime_path_is_alias(directory):
                raise IsolatedExecutionProtocolError(
                    "isolated WER immutable dependency directory is a "
                    "reparse alias"
                )
        except BaseException:
            self._close_handle(handle)
            raise
        self._directory_handles[key] = handle
        self._handles.append(handle)

    def _ensure_parent(self, destination: Path) -> None:
        relative_parent = destination.parent.relative_to(self.root)
        current = self.root
        for component in relative_parent.parts:
            if (
                not component
                or component in {".", ".."}
                or ":" in component
            ):
                raise IsolatedExecutionProtocolError(
                    "isolated WER immutable dependency destination is "
                    "non-canonical"
                )
            current = current / component
            try:
                current.mkdir()
            except FileExistsError:
                if not current.is_dir():
                    raise IsolatedExecutionProtocolError(
                        "isolated WER immutable dependency parent collided"
                    )
            self._hold_directory(
                _assert_runtime_path_chain(
                    current.resolve(strict=True),
                    label="isolated WER immutable dependency parent",
                )
            )

    def ensure_directory(self, relative: Path) -> Path:
        if (
            self._closed
            or not isinstance(relative, Path)
            or relative.is_absolute()
            or any(
                part in {"", ".", ".."} or ":" in part
                for part in relative.parts
            )
        ):
            raise IsolatedExecutionProtocolError(
                "isolated WER immutable dependency directory is invalid"
            )
        destination = self.root.joinpath(*relative.parts)
        self._ensure_parent(destination / "_child")
        try:
            destination.mkdir()
        except FileExistsError:
            if not destination.is_dir():
                raise IsolatedExecutionProtocolError(
                    "isolated WER immutable dependency directory collided"
                )
        destination = _assert_runtime_path_chain(
            destination.resolve(strict=True),
            label="isolated WER immutable dependency directory",
        )
        self._hold_directory(destination)
        return destination

    def copy_verified(
        self,
        record: Mapping[str, Any],
        *,
        relative: Path,
        maximum_bytes: int | None = None,
    ) -> Path:
        if self._closed:
            raise IsolatedExecutionProtocolError(
                "isolated WER immutable dependency stage is closed"
            )
        if (
            not isinstance(record, Mapping)
            or set(record) != {"path", "sha256", "size"}
            or not isinstance(record.get("path"), str)
            or not isinstance(record.get("sha256"), str)
            or not isinstance(record.get("size"), int)
            or isinstance(record.get("size"), bool)
            or record["size"] < 0
            or not isinstance(relative, Path)
            or relative.is_absolute()
            or not relative.parts
            or any(
                part in {"", ".", ".."} or ":" in part
                for part in relative.parts
            )
            or (
                maximum_bytes is not None
                and (
                    not isinstance(maximum_bytes, int)
                    or isinstance(maximum_bytes, bool)
                    or maximum_bytes < 0
                )
            )
        ):
            raise IsolatedExecutionProtocolError(
                "isolated WER immutable dependency copy record is invalid"
            )
        if maximum_bytes is not None and record["size"] > maximum_bytes:
            raise IsolatedExecutionProtocolError(
                "isolated WER immutable dependency exceeds its size limit"
            )
        source = _assert_runtime_path_chain(
            Path(record["path"]).resolve(strict=True),
            label="isolated WER immutable dependency source",
        )
        if not source.is_file():
            raise IsolatedExecutionProtocolError(
                "isolated WER immutable dependency source is not a file"
            )
        source_handle = self._open(
            source,
            access=self._GENERIC_READ,
            creation=self._OPEN_EXISTING,
            flags=(
                self._FILE_ATTRIBUTE_NORMAL
                | self._FILE_FLAG_OPEN_REPARSE_POINT
            ),
        )
        self._handles.append(source_handle)
        try:
            raw = (
                source.read_bytes()
                if maximum_bytes is None
                else read_bounded_regular_bytes(source, maximum_bytes)
            )
        except ValueError as exc:
            raise IsolatedExecutionProtocolError(
                "isolated WER immutable dependency exceeds its size limit "
                "or changed during its bounded read"
            ) from exc
        except OSError as exc:
            raise IsolatedExecutionProtocolError(
                "isolated WER immutable dependency source is unreadable"
            ) from exc
        claimed = _require_hex64(
            record["sha256"],
            "isolated WER immutable dependency digest",
        )
        if (
            len(raw) != record["size"]
            or hashlib.sha256(raw).hexdigest() != claimed
            or source.stat().st_nlink != 1
        ):
            raise IsolatedExecutionProtocolError(
                "isolated WER immutable dependency source changed"
            )
        destination = self.root.joinpath(*relative.parts)
        try:
            destination.relative_to(self.root)
        except ValueError as exc:
            raise IsolatedExecutionProtocolError(
                "isolated WER immutable dependency destination escaped"
            ) from exc
        self._ensure_parent(destination)
        destination_handle = self._open(
            destination,
            access=self._GENERIC_READ | self._GENERIC_WRITE,
            creation=self._CREATE_NEW,
            flags=self._FILE_ATTRIBUTE_NORMAL,
        )
        self._handles.append(destination_handle)
        kernel32 = self._kernel32()
        from ctypes import wintypes

        offset = 0
        while offset < len(raw):
            chunk = raw[offset : offset + 1024 * 1024]
            buffer = ctypes.create_string_buffer(chunk)
            written = wintypes.DWORD(0)
            if not kernel32.WriteFile(
                ctypes.c_void_p(destination_handle),
                buffer,
                len(chunk),
                ctypes.byref(written),
                None,
            ):
                error = ctypes.get_last_error()
                raise OSError(
                    error,
                    "cannot write immutable dependency stage",
                )
            if written.value != len(chunk):
                raise IsolatedExecutionProtocolError(
                    "isolated WER immutable dependency write was partial"
                )
            offset += written.value
        if not kernel32.FlushFileBuffers(
            ctypes.c_void_p(destination_handle)
        ):
            error = ctypes.get_last_error()
            raise OSError(
                error,
                "cannot flush immutable dependency stage",
            )
        destination = _assert_runtime_path_chain(
            destination.resolve(strict=True),
            label="isolated WER immutable staged dependency",
        )
        key = os.path.normcase(str(destination))
        if key in self._records:
            raise IsolatedExecutionProtocolError(
                "isolated WER immutable dependency destination collided"
            )
        self._records[key] = (claimed, len(raw))
        return destination

    def verify_all(self) -> None:
        if self._closed:
            raise IsolatedExecutionProtocolError(
                "isolated WER immutable dependency stage is closed"
            )
        for rendered, (claimed, size) in self._records.items():
            path = Path(rendered)
            raw = path.read_bytes()
            if (
                len(raw) != size
                or hashlib.sha256(raw).hexdigest() != claimed
                or path.stat().st_nlink != 1
                or _runtime_path_is_alias(path)
            ):
                raise IsolatedExecutionProtocolError(
                    "isolated WER immutable staged dependency changed"
                )

    def close(self) -> None:
        if self._closed:
            return
        errors: list[BaseException] = []
        for handle in reversed(self._handles):
            try:
                self._close_handle(handle)
            except BaseException as exc:
                errors.append(exc)
        self._handles.clear()
        self._directory_handles.clear()
        self._closed = True
        if errors:
            raise IsolatedExecutionProtocolError(
                "isolated WER immutable dependency handles did not close"
            ) from errors[0]


def _create_immutable_dependency_stage(
    parent: Path,
) -> _WindowsImmutableDependencyStage:
    if os.name != "nt":
        raise SemanticDependencyIsolationUnavailable(
            "immutable dependency staging capability is unsupported "
            "on this host"
        )
    parent = _assert_runtime_path_chain(
        parent.resolve(strict=True),
        label="isolated WER immutable dependency stage parent",
    )
    if not parent.is_dir():
        raise IsolatedExecutionProtocolError(
            "isolated WER immutable dependency stage parent is invalid"
        )
    for _attempt in range(8):
        candidate = parent / (
            ".semantic-runtime-cas-" + uuid.uuid4().hex
        )
        try:
            candidate.mkdir(mode=0o700)
        except FileExistsError:
            continue
        return _WindowsImmutableDependencyStage(
            candidate.resolve(strict=True)
        )
    raise IsolatedExecutionProtocolError(
        "isolated WER immutable dependency stage identity collided"
    )


class _SealedExtensionFinder(importlib.abc.MetaPathFinder):
    """Resolve exact native-extension names from write/delete-locked files."""

    def __init__(self, origins: Mapping[str, str]) -> None:
        self._origins = dict(origins)

    def find_spec(
        self,
        fullname: str,
        path: Any = None,
        target: Any = None,
    ) -> Any:
        del path, target
        origin = self._origins.get(fullname)
        if origin is None:
            return None
        loader = importlib.machinery.ExtensionFileLoader(
            fullname,
            origin,
        )
        return importlib.util.spec_from_file_location(
            fullname,
            origin,
            loader=loader,
        )


def _independent_runtime_import_roots() -> tuple[Path, ...]:
    candidates: set[str] = set()
    paths = sysconfig.get_paths()
    for key in ("purelib", "platlib"):
        value = paths.get(key)
        if isinstance(value, str) and value:
            candidates.add(value)
    try:
        for value in site.getsitepackages():
            if isinstance(value, str) and value:
                candidates.add(value)
    except (AttributeError, OSError):
        pass
    try:
        value = site.getusersitepackages()
        if isinstance(value, str) and value:
            candidates.add(value)
    except (AttributeError, OSError):
        pass
    roots: list[Path] = []
    for candidate in sorted(candidates, key=os.path.normcase):
        path = Path(candidate)
        if not path.is_absolute() or not path.is_dir():
            continue
        resolved = path.resolve(strict=True)
        if str(resolved) != str(path):
            continue
        roots.append(resolved)
    unique = {
        os.path.normcase(str(path)): path
        for path in roots
    }
    return tuple(unique[key] for key in sorted(unique))


def _metadata_identity(
    raw: bytes,
) -> tuple[str, str]:
    try:
        message = BytesParser(policy=email_policy.compat32).parsebytes(raw)
    except (TypeError, ValueError) as exc:
        raise IsolatedExecutionProtocolError(
            "isolated WER distribution METADATA is malformed"
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
        or "\r" in names[0]
        or "\n" in names[0]
        or "\r" in versions[0]
        or "\n" in versions[0]
    ):
        raise IsolatedExecutionProtocolError(
            "isolated WER distribution METADATA identity is invalid"
        )
    return (
        _DISTRIBUTION_NAME_SEPARATOR_RE.sub("-", names[0]).lower(),
        versions[0],
    )


def _record_sha256(value: str) -> str | None:
    if value == "":
        return None
    try:
        algorithm, encoded = value.split("=", 1)
        if (
            algorithm != "sha256"
            or not encoded
            or "=" in encoded
            or not re.fullmatch(
                r"[A-Za-z0-9_-]+",
                encoded,
                re.ASCII,
            )
        ):
            return None
        padding = "=" * (-len(encoded) % 4)
        raw = base64.b64decode(
            encoded + padding,
            altchars=b"-_",
            validate=True,
        )
    except (ValueError, TypeError, binascii.Error):
        return None
    if (
        len(raw) != hashlib.sha256().digest_size
        or base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
        != encoded
    ):
        return None
    return raw.hex()


def _distribution_record_entries(
    raw: bytes,
    *,
    root: Path,
    allow_nonimport_windows_launchers: bool = False,
) -> dict[str, tuple[str | None, int | None]]:
    try:
        text = raw.decode("utf-8", "strict")
        rows = tuple(csv.reader(io.StringIO(text, newline="")))
    except (UnicodeError, csv.Error) as exc:
        raise IsolatedExecutionProtocolError(
            "isolated WER distribution RECORD is malformed"
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
            # Windows wheels may inventory console launchers outside the
            # interpreter import root.  They never become import authority;
            # the strict public/default parser still rejects every ``..``.
            continue
        if (
            len(row) != 3
            or not row[0]
            or "\\" in row[0]
            or "\x00" in row[0]
        ):
            raise IsolatedExecutionProtocolError(
                "isolated WER distribution RECORD path row is invalid"
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
            raise IsolatedExecutionProtocolError(
                "isolated WER distribution RECORD path is non-canonical"
            )
        relative = PurePosixPath(row[0])
        if (
            relative.is_absolute()
            or relative.as_posix() != row[0]
            or tuple(raw_segments) != relative.parts
        ):
            raise IsolatedExecutionProtocolError(
                "isolated WER distribution RECORD path is invalid"
            )
        candidate = root.joinpath(*relative.parts)
        normalized = Path(os.path.abspath(candidate))
        try:
            normalized.relative_to(root)
        except ValueError:
            # Wheel RECORDs may legitimately own entry-point launchers beside
            # the import root.  They are parsed but cannot authorize modules.
            continue
        path_text = str(normalized)
        case_key = os.path.normcase(path_text)
        if case_key in case_keys:
            raise IsolatedExecutionProtocolError(
                "isolated WER distribution RECORD paths are ambiguous"
            )
        case_keys.add(case_key)
        digest = _record_sha256(row[1])
        if row[1] and digest is None:
            raise IsolatedExecutionProtocolError(
                "isolated WER distribution RECORD digest is unsupported"
            )
        if row[2] == "":
            size = None
        else:
            try:
                size = int(row[2], 10)
            except ValueError as exc:
                raise IsolatedExecutionProtocolError(
                    "isolated WER distribution RECORD size is invalid"
                ) from exc
            if size < 0 or str(size) != row[2]:
                raise IsolatedExecutionProtocolError(
                    "isolated WER distribution RECORD size is invalid"
                )
        entries[path_text] = (digest, size)
    return entries


def _resolve_external_module_origin(
    module_name: str,
    *,
    import_roots: Sequence[Path],
) -> tuple[str, str | None, tuple[str, ...]]:
    parts = module_name.split(".")
    if (
        not parts
        or any(not part or not part.isidentifier() for part in parts)
        or parts[0] not in _SEMANTIC_RUNTIME_PREFIX_DISTRIBUTION
    ):
        raise IsolatedExecutionProtocolError(
            "isolated WER external module prefix is invalid"
        )
    search = [str(path) for path in import_roots]
    spec = None
    for index in range(len(parts)):
        qualified = ".".join(parts[: index + 1])
        spec = importlib.machinery.PathFinder.find_spec(qualified, search)
        if spec is None:
            raise IsolatedExecutionProtocolError(
                "isolated WER external module origin is unavailable"
            )
        if index < len(parts) - 1:
            locations = spec.submodule_search_locations
            if locations is None:
                raise IsolatedExecutionProtocolError(
                    "isolated WER external module parent is not a package"
                )
            search = [
                str(_assert_runtime_path_chain(
                    Path(item),
                    label="isolated WER external package location",
                ))
                for item in locations
            ]
    assert spec is not None
    locations = spec.submodule_search_locations
    if spec.origin is None:
        if not locations:
            raise IsolatedExecutionProtocolError(
                "isolated WER namespace origin is unavailable"
            )
        normalized_locations = tuple(
            sorted(
                (
                    str(
                        _assert_runtime_path_chain(
                            Path(item),
                            label="isolated WER namespace origin",
                        )
                    )
                    for item in locations
                ),
                key=os.path.normcase,
            )
        )
        return "NAMESPACE_PACKAGE", None, normalized_locations
    origin = _assert_runtime_path_chain(
        Path(spec.origin),
        label="isolated WER external module origin",
    )
    rendered = str(origin)
    if any(
        rendered.casefold().endswith(suffix.casefold())
        for suffix in importlib.machinery.EXTENSION_SUFFIXES
    ):
        kind = "EXTENSION_BINARY"
    elif origin.suffix.casefold() in {".py", ".pyw", ".pyc"}:
        kind = "PYTHON_SOURCE"
    else:
        raise IsolatedExecutionProtocolError(
            "isolated WER external module kind is unsupported"
        )
    return kind, rendered, ()


def _validate_runtime_dependency_binding(
    value: Mapping[str, Any],
) -> dict[str, Any]:
    keys = {
        "schema",
        "python",
        "modules",
        "distributions",
        "import_roots",
        "site_initialization",
        "runtime_dependency_sha256",
    }
    if (
        not isinstance(value, Mapping)
        or set(value) != keys
        or value.get("schema")
        != "plamen.semantic-wer-runtime-dependencies.v1"
        or value.get("site_initialization")
        != "DISABLED_EXPLICIT_IMPORT_ROOTS"
    ):
        raise IsolatedExecutionProtocolError(
            "isolated WER runtime dependency binding is invalid"
        )
    claimed = _require_hex64(
        value.get("runtime_dependency_sha256"),
        "isolated WER runtime dependency digest",
    )
    unsigned = {
        key: copy.deepcopy(item)
        for key, item in value.items()
        if key != "runtime_dependency_sha256"
    }
    if _sha(unsigned) != claimed:
        raise IsolatedExecutionProtocolError(
            "isolated WER runtime dependency digest mismatch"
        )
    python = value.get("python")
    python_keys = {
        "implementation",
        "cache_tag",
        "version",
        "executable",
        "executable_sha256",
        "executable_size",
    }
    if (
        not isinstance(python, Mapping)
        or set(python) != python_keys
        or any(
            not isinstance(python.get(field), str)
            or not python[field]
            for field in (
                "implementation",
                "cache_tag",
                "version",
                "executable",
            )
        )
    ):
        raise IsolatedExecutionProtocolError(
            "isolated WER Python runtime identity is invalid"
        )
    executable = _validate_runtime_file_record(
        {
            "path": python["executable"],
            "sha256": python.get("executable_sha256"),
            "size": python.get("executable_size"),
        },
        label="isolated WER Python executable",
    )
    if (
        python["implementation"] != sys.implementation.name
        or python["cache_tag"] != sys.implementation.cache_tag
        or python["version"] != sys.version
        or executable["path"] != str(Path(sys.executable).resolve(strict=True))
    ):
        raise IsolatedExecutionProtocolError(
            "isolated WER Python runtime changed"
        )
    modules = value.get("modules")
    module_keys = {
        "module_name",
        "kind",
        "path",
        "sha256",
        "size",
        "search_locations",
    }
    if not isinstance(modules, list) or not modules:
        raise IsolatedExecutionProtocolError(
            "isolated WER runtime module denominator is invalid"
        )
    module_names: list[str] = []
    module_file_keys: list[str] = []
    module_bound_locations: list[tuple[str, str]] = []
    for index, row in enumerate(modules):
        if (
            not isinstance(row, Mapping)
            or set(row) != module_keys
            or not isinstance(row.get("module_name"), str)
            or not row["module_name"]
            or row.get("kind")
            not in {
                "PYTHON_SOURCE",
                "EXTENSION_BINARY",
                "NAMESPACE_PACKAGE",
            }
            or not isinstance(row.get("search_locations"), list)
        ):
            raise IsolatedExecutionProtocolError(
                "isolated WER runtime module row is invalid"
            )
        module_names.append(row["module_name"])
        if row["kind"] == "NAMESPACE_PACKAGE":
            if (
                row.get("path") is not None
                or row.get("sha256") is not None
                or row.get("size") is not None
                or not row["search_locations"]
            ):
                raise IsolatedExecutionProtocolError(
                    "isolated WER namespace module row is invalid"
                )
            namespace_locations: list[str] = []
            for location in row["search_locations"]:
                if (
                    not isinstance(location, str)
                    or not Path(location).is_absolute()
                    or str(Path(location).resolve(strict=True)) != location
                    or not Path(location).resolve(strict=True).is_dir()
                ):
                    raise IsolatedExecutionProtocolError(
                        "isolated WER namespace location is invalid"
                    )
                namespace_locations.append(location)
                module_bound_locations.append(
                    (row["module_name"], location)
                )
            if (
                namespace_locations
                != sorted(namespace_locations, key=os.path.normcase)
                or len(
                    {os.path.normcase(item) for item in namespace_locations}
                )
                != len(namespace_locations)
            ):
                raise IsolatedExecutionProtocolError(
                    "isolated WER namespace locations are non-canonical"
                )
        else:
            validated_module = _validate_runtime_file_record(
                {
                    "path": row.get("path"),
                    "sha256": row.get("sha256"),
                    "size": row.get("size"),
                },
                label=f"isolated WER runtime module {index}",
            )
            if row["search_locations"]:
                raise IsolatedExecutionProtocolError(
                    "isolated WER source module has namespace locations"
                )
            module_file_keys.append(
                os.path.normcase(validated_module["path"])
            )
            module_bound_locations.append(
                (row["module_name"], validated_module["path"])
            )
    if (
        module_names != sorted(set(module_names))
        or len({name.casefold() for name in module_names})
        != len(module_names)
        or len(set(module_file_keys)) != len(module_file_keys)
    ):
        raise IsolatedExecutionProtocolError(
            "isolated WER runtime modules are non-canonical"
        )

    distributions = value.get("distributions")
    distribution_names: list[str] = []
    distribution_import_roots: list[str] = []
    distribution_roots_by_name: dict[str, Path] = {}
    distribution_record_entries: dict[
        str, dict[str, tuple[str | None, int | None]]
    ] = {}
    if not isinstance(distributions, list) or not distributions:
        raise IsolatedExecutionProtocolError(
            "isolated WER runtime distribution denominator is invalid"
        )
    for row in distributions:
        if (
            not isinstance(row, Mapping)
            or set(row)
            != {
                "distribution_name",
                "version",
                "import_root",
                "identity_files",
            }
            or any(
                not isinstance(row.get(field), str)
                or not row[field]
                for field in (
                    "distribution_name",
                    "version",
                    "import_root",
                )
            )
            or str(Path(row["import_root"]).resolve(strict=True))
            != row["import_root"]
            or not Path(row["import_root"]).resolve(strict=True).is_dir()
            or not isinstance(row.get("identity_files"), list)
            or not row["identity_files"]
        ):
            raise IsolatedExecutionProtocolError(
            "isolated WER runtime distribution row is invalid"
            )
        distribution_name = _canonical_distribution_name(
            row["distribution_name"]
        )
        if distribution_name not in _SEMANTIC_RUNTIME_DISTRIBUTIONS:
            raise IsolatedExecutionProtocolError(
                "isolated WER runtime distribution name is ungoverned"
            )
        distribution_names.append(distribution_name)
        distribution_import_roots.append(row["import_root"])
        distribution_root = _assert_runtime_path_chain(
            Path(row["import_root"]),
            label=(
                "isolated WER distribution "
                f"{distribution_name} import root"
            ),
        )
        distribution_roots_by_name[distribution_name] = distribution_root
        identity_paths: list[str] = []
        identity_records: dict[str, dict[str, Any]] = {}
        for index, record in enumerate(row["identity_files"]):
            validated_identity = _validate_runtime_file_record(
                record,
                label=(
                    "isolated WER distribution identity "
                    f"{row['distribution_name']}[{index}]"
                ),
            )
            identity_paths.append(validated_identity["path"])
            identity_path = Path(validated_identity["path"]).resolve(
                strict=True
            )
            if distribution_root not in identity_path.parents:
                raise IsolatedExecutionProtocolError(
                    "isolated WER distribution identity is outside its "
                    "claimed import root"
                )
            _assert_runtime_path_chain(
                identity_path,
                label="isolated WER distribution identity",
            )
            role = identity_path.name
            if role in identity_records:
                raise IsolatedExecutionProtocolError(
                    "isolated WER distribution identity files are non-canonical"
                )
            if (
                role not in {"METADATA", "RECORD"}
                or identity_path.parent.suffix.casefold() != ".dist-info"
            ):
                raise IsolatedExecutionProtocolError(
                    "isolated WER distribution identity denominator is invalid"
                )
            identity_records[role] = validated_identity
        if (
            identity_paths
            != sorted(identity_paths, key=os.path.normcase)
            or len({os.path.normcase(path) for path in identity_paths})
            != len(identity_paths)
        ):
            raise IsolatedExecutionProtocolError(
                "isolated WER distribution identity files are non-canonical"
            )
        if set(identity_records) != {"METADATA", "RECORD"}:
            raise IsolatedExecutionProtocolError(
                "isolated WER distribution METADATA/RECORD denominator is "
                "incomplete"
            )
        metadata_path = Path(identity_records["METADATA"]["path"])
        record_path = Path(identity_records["RECORD"]["path"])
        if metadata_path.parent != record_path.parent:
            raise IsolatedExecutionProtocolError(
                "isolated WER distribution METADATA and RECORD provenance "
                "differs"
            )
        metadata_raw = metadata_path.read_bytes()
        metadata_name, metadata_version = _metadata_identity(metadata_raw)
        if (
            metadata_name != distribution_name
            or metadata_version != row["version"]
        ):
            raise IsolatedExecutionProtocolError(
                "isolated WER distribution name/version differs from METADATA"
            )
        entries = _distribution_record_entries(
            record_path.read_bytes(),
            root=distribution_root,
            allow_nonimport_windows_launchers=True,
        )
        metadata_entry = entries.get(str(metadata_path))
        if metadata_entry != (
            identity_records["METADATA"]["sha256"],
            identity_records["METADATA"]["size"],
        ):
            raise IsolatedExecutionProtocolError(
                "isolated WER distribution METADATA lacks exact RECORD "
                "ownership"
            )
        distribution_record_entries[distribution_name] = entries
    if (
        tuple(distribution_names) != _SEMANTIC_RUNTIME_DISTRIBUTIONS
        or distribution_names != sorted(set(distribution_names))
        or len({name.casefold() for name in distribution_names})
        != len(distribution_names)
    ):
        raise IsolatedExecutionProtocolError(
            "isolated WER runtime distributions are non-canonical"
        )
    roots = value.get("import_roots")
    if (
        not isinstance(roots, list)
        or not roots
        or any(not isinstance(root, str) for root in roots)
        or roots != sorted(roots, key=os.path.normcase)
        or len({os.path.normcase(root) for root in roots}) != len(roots)
        or any(
            not Path(root).is_absolute()
            or str(Path(root).resolve(strict=True)) != root
            or not Path(root).resolve(strict=True).is_dir()
            for root in roots
        )
    ):
        raise IsolatedExecutionProtocolError(
            "isolated WER runtime import roots are invalid"
        )
    if {
        os.path.normcase(root) for root in distribution_import_roots
    } != {os.path.normcase(root) for root in roots}:
        raise IsolatedExecutionProtocolError(
            "isolated WER distribution import roots are non-canonical"
        )
    canonical_roots = tuple(
        _assert_runtime_path_chain(
            Path(root),
            label="isolated WER governed import root",
        )
        for root in roots
    )
    independent_roots = {
        os.path.normcase(str(root))
        for root in _independent_runtime_import_roots()
    }
    if (
        not independent_roots
        or any(
            os.path.normcase(str(root)) not in independent_roots
            for root in canonical_roots
        )
    ):
        raise IsolatedExecutionProtocolError(
            "isolated WER distribution import root lacks independent "
            "interpreter provenance"
        )
    seen_external_prefixes: set[str] = set()
    for row in modules:
        module_name = row["module_name"]
        prefix = module_name.split(".", 1)[0]
        bound_locations = (
            row["search_locations"]
            if row["kind"] == "NAMESPACE_PACKAGE"
            else [row["path"]]
        )
        under_governed_root = any(
            root in Path(location).resolve(strict=True).parents
            for root in canonical_roots
            for location in bound_locations
        )
        if prefix not in _SEMANTIC_RUNTIME_EXTERNAL_PREFIXES:
            if under_governed_root:
                raise IsolatedExecutionProtocolError(
                    "isolated WER external module prefix is ungoverned"
                )
            continue
        seen_external_prefixes.add(prefix)
        expected_kind, expected_path, expected_locations = (
            _resolve_external_module_origin(
                module_name,
                import_roots=canonical_roots,
            )
        )
        if (
            row["kind"] != expected_kind
            or row["path"] != expected_path
            or tuple(row["search_locations"]) != expected_locations
        ):
            raise IsolatedExecutionProtocolError(
                "isolated WER external module origin/import root binding differs "
                "from independent resolution"
            )
        distribution_name = _SEMANTIC_RUNTIME_PREFIX_DISTRIBUTION[prefix]
        distribution_root = distribution_roots_by_name[distribution_name]
        entries = distribution_record_entries[distribution_name]
        if expected_kind == "NAMESPACE_PACKAGE":
            for location in expected_locations:
                namespace_root = Path(location)
                if (
                    distribution_root != namespace_root
                    and distribution_root not in namespace_root.parents
                ):
                    raise IsolatedExecutionProtocolError(
                        "isolated WER namespace origin is outside its "
                        "distribution root"
                    )
                if not any(
                    namespace_root == Path(path)
                    or namespace_root in Path(path).parents
                    for path in entries
                ):
                    raise IsolatedExecutionProtocolError(
                        "isolated WER namespace origin lacks RECORD ownership"
                    )
            continue
        assert expected_path is not None
        module_path = Path(expected_path)
        if (
            distribution_root not in module_path.parents
            or not any(
                root in module_path.parents for root in canonical_roots
            )
        ):
            raise IsolatedExecutionProtocolError(
                "isolated WER external module is outside the governed "
                "import root denominator"
            )
        owned = entries.get(expected_path)
        if owned != (row["sha256"], row["size"]):
            raise IsolatedExecutionProtocolError(
                "isolated WER external module lacks exact distribution RECORD "
                "ownership"
            )
        other_owners = [
            name
            for name, other_entries in distribution_record_entries.items()
            if name != distribution_name and expected_path in other_entries
        ]
        if other_owners:
            raise IsolatedExecutionProtocolError(
                "isolated WER external module has ambiguous RECORD ownership"
            )
    if seen_external_prefixes != _SEMANTIC_RUNTIME_EXTERNAL_PREFIXES:
        raise IsolatedExecutionProtocolError(
            "isolated WER external module prefix denominator is incomplete"
        )
    return copy.deepcopy(dict(value))


def _validate_wer_provider_core(
    payload: Mapping[str, Any],
) -> dict[str, Any]:
    if (
        not isinstance(payload, Mapping)
        or set(payload) != _WER_PROVIDER_CORE_KEYS
    ):
        raise IsolatedExecutionProtocolError(
            "isolated WER request core schema is invalid"
        )
    semantic = payload.get("semantic_authority")
    semantic_keys = {
        "plan",
        "execution",
        "attempt",
        "snapshot",
        "semantic_authority_sha256",
    }
    if not isinstance(semantic, Mapping) or set(semantic) != semantic_keys:
        raise IsolatedExecutionProtocolError(
            "isolated WER semantic authority schema is invalid"
        )
    for name in ("plan", "execution", "attempt", "snapshot"):
        if not isinstance(semantic.get(name), Mapping):
            raise IsolatedExecutionProtocolError(
                f"isolated WER semantic {name} is invalid"
            )
    claimed_semantic = _require_hex64(
        semantic.get("semantic_authority_sha256"),
        "isolated WER semantic authority digest",
    )
    if claimed_semantic != _wer_semantic_authority_sha256(semantic):
        raise IsolatedExecutionProtocolError(
            "isolated WER semantic authority digest mismatch"
        )
    runtime_dependencies = _validate_runtime_dependency_binding(
        payload.get("runtime_dependency_binding")
    )

    for field in ("scratchpad", "cwd"):
        value = payload.get(field)
        if (
            not isinstance(value, str)
            or not value
            or "\x00" in value
            or not Path(value).is_absolute()
        ):
            raise IsolatedExecutionProtocolError(
                f"isolated WER {field} is invalid"
            )
        if (
            os.name == "nt"
            and len(value.encode("utf-16-le")) // 2 >= 260
        ):
            raise IsolatedExecutionProtocolError(
                f"isolated WER {field} exceeds the Windows path budget"
            )
    _validate_relative_path(
        payload.get("output_scope_relative"),
        "isolated WER output scope",
    )
    _validate_relative_path(
        payload.get("stdin_input_relative_path"),
        "isolated WER stdin input",
    )

    bindings = payload.get("bindings")
    binding_keys = {
        "run_id",
        "shard_id",
        "inputs",
        "worker",
        "assessors",
        "effective_backend",
        "effective_model",
        "expected_environment_allowlist_sha256",
    }
    if not isinstance(bindings, Mapping) or set(bindings) != binding_keys:
        raise IsolatedExecutionProtocolError(
            "isolated WER bindings schema is invalid"
        )
    for field in (
        "run_id",
        "shard_id",
        "effective_backend",
        "effective_model",
    ):
        if not isinstance(bindings.get(field), str) or not bindings[field]:
            raise IsolatedExecutionProtocolError(
                f"isolated WER binding {field} is invalid"
            )
    _require_hex64(
        bindings.get("expected_environment_allowlist_sha256"),
        "isolated WER environment allowlist digest",
    )
    inputs = bindings.get("inputs")
    expected_input_names = {
        "plan",
        "manifest",
        "intent",
        "context",
        "prompt",
        "tool_policy",
    }
    if not isinstance(inputs, Mapping) or set(inputs) != expected_input_names:
        raise IsolatedExecutionProtocolError(
            "isolated WER input denominator is invalid"
        )
    for name, row in inputs.items():
        if (
            not isinstance(row, Mapping)
            or set(row) != {"relative_path", "sha256", "size"}
        ):
            raise IsolatedExecutionProtocolError(
                f"isolated WER input {name} is invalid"
            )
        _validate_relative_path(
            row.get("relative_path"),
            f"isolated WER input {name} path",
        )
        _require_hex64(
            row.get("sha256"),
            f"isolated WER input {name} digest",
        )
        if (
            isinstance(row.get("size"), bool)
            or not isinstance(row.get("size"), int)
            or row["size"] < 0
        ):
            raise IsolatedExecutionProtocolError(
                f"isolated WER input {name} size is invalid"
            )
    worker = bindings.get("worker")
    if (
        not isinstance(worker, Mapping)
        or set(worker) != {"identity", "invocation_id"}
        or any(not isinstance(worker.get(key), str) or not worker[key] for key in worker)
    ):
        raise IsolatedExecutionProtocolError(
            "isolated WER worker binding is invalid"
        )
    assessors = bindings.get("assessors")
    if not isinstance(assessors, list) or any(
        not isinstance(row, Mapping)
        or set(row) != {"identity", "invocation_id"}
        or any(not isinstance(row.get(key), str) or not row[key] for key in row)
        for row in assessors
    ):
        raise IsolatedExecutionProtocolError(
            "isolated WER assessor bindings are invalid"
        )

    argv = payload.get("argv")
    if (
        not isinstance(argv, list)
        or not argv
        or any(not isinstance(item, str) or not item for item in argv)
    ):
        raise IsolatedExecutionProtocolError(
            "isolated WER argv is invalid"
        )
    if any("\x00" in item for item in argv):
        raise IsolatedExecutionProtocolError(
            "isolated WER argv contains NUL"
        )
    if (
        os.name == "nt"
        and len(subprocess.list2cmdline(argv).encode("utf-16-le")) // 2 + 1
        > 32_767
    ):
        raise IsolatedExecutionProtocolError(
            "isolated WER exceeds the Windows command-line budget"
        )
    outputs = payload.get("expected_outputs")
    output_keys = {
        "assignment_id",
        "relative_path",
        "publish_relative_path",
        "is_transcript",
        "pre_state",
    }
    if not isinstance(outputs, list) or not outputs:
        raise IsolatedExecutionProtocolError(
            "isolated WER output denominator is invalid"
        )
    for row in outputs:
        if not isinstance(row, Mapping) or set(row) != output_keys:
            raise IsolatedExecutionProtocolError(
                "isolated WER output row is invalid"
            )
        if (
            not isinstance(row.get("assignment_id"), str)
            or not row["assignment_id"]
            or type(row.get("is_transcript")) is not bool
            or row.get("pre_state") != "ABSENT"
        ):
            raise IsolatedExecutionProtocolError(
                "isolated WER output disposition is invalid"
            )
        _validate_relative_path(
            row.get("relative_path"),
            "isolated WER output path",
        )
        _validate_relative_path(
            row.get("publish_relative_path"),
            "isolated WER publish path",
        )

    parser = payload.get("parser_binding")
    if (
        not isinstance(parser, Mapping)
        or set(parser) != {"identity", "source_file", "source_sha256"}
        or not isinstance(parser.get("identity"), str)
        or ":" not in parser["identity"]
        or not isinstance(parser.get("source_file"), str)
        or not Path(parser["source_file"]).is_absolute()
    ):
        raise IsolatedExecutionProtocolError(
            "isolated WER parser binding is invalid"
        )
    _require_hex64(
        parser.get("source_sha256"),
        "isolated WER parser source digest",
    )

    environment = payload.get("environment")
    allowlist = payload.get("environment_allowlist")
    if (
        not isinstance(environment, Mapping)
        or any(
            not isinstance(key, str)
            or not key
            or not isinstance(value, str)
            for key, value in environment.items()
        )
        or not isinstance(allowlist, list)
        or any(not isinstance(item, str) or not item for item in allowlist)
        or len(set(allowlist)) != len(allowlist)
        or set(environment) - set(allowlist)
        or bool(environment)
        or bool(allowlist)
    ):
        raise IsolatedExecutionProtocolError(
            "isolated WER environment authority is invalid"
        )

    for field in (
        "timeout_seconds",
        "lock_timeout_seconds",
    ):
        value = payload.get(field)
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(float(value))
            or value <= 0
        ):
            raise IsolatedExecutionProtocolError(
                f"isolated WER {field} is invalid"
            )
    for field in (
        "stdout_limit_bytes",
        "stderr_limit_bytes",
        "staged_output_limit_bytes",
    ):
        value = payload.get(field)
        if (
            isinstance(value, bool)
            or not isinstance(value, int)
            or value <= 0
            or value > 64 * 1024 * 1024
        ):
            raise IsolatedExecutionProtocolError(
                f"isolated WER {field} is invalid"
            )
    if (
        payload.get("output_source_mode")
        not in {"WORKER_FILE_OUTPUTS", "STDOUT_ASSIGNED_OUTPUT"}
        or type(payload.get("publish_canonical")) is not bool
        or not isinstance(payload.get("process_scope_identity"), str)
        or not payload["process_scope_identity"]
    ):
        raise IsolatedExecutionProtocolError(
            "isolated WER execution policy is invalid"
        )
    implementation_files = payload.get("implementation_files")
    if (
        not isinstance(implementation_files, list)
        or not implementation_files
    ):
        raise IsolatedExecutionProtocolError(
            "isolated WER implementation files are invalid"
        )
    for item in implementation_files:
        if (
            not isinstance(item, Mapping)
            or set(item) != {"path", "sha256", "size"}
            or not isinstance(item.get("path"), str)
            or not item["path"]
            or not Path(item["path"]).is_absolute()
        ):
            raise IsolatedExecutionProtocolError(
                "isolated WER implementation file record is invalid"
            )
        claimed_sha = _require_hex64(
            item.get("sha256"),
            "isolated WER implementation file digest",
        )
        size = item.get("size")
        if (
            isinstance(size, bool)
            or not isinstance(size, int)
            or size < 0
        ):
            raise IsolatedExecutionProtocolError(
                "isolated WER implementation file size is invalid"
            )
        path = Path(item["path"])
        try:
            resolved = path.resolve(strict=True)
            raw = resolved.read_bytes()
        except OSError as exc:
            raise IsolatedExecutionProtocolError(
                "isolated WER implementation file is unavailable"
            ) from exc
        if (
            str(resolved) != item["path"]
            or not resolved.is_file()
            or len(raw) != size
            or hashlib.sha256(raw).hexdigest() != claimed_sha
        ):
            raise IsolatedExecutionProtocolError(
                "isolated WER implementation bytes changed"
            )
    implementation_paths = {
        item["path"] for item in implementation_files
    }
    required_runtime_paths = {
        runtime_dependencies["python"]["executable"],
        *(
            row["path"]
            for row in runtime_dependencies["modules"]
            if row["path"] is not None
        ),
        *(
            record["path"]
            for distribution in runtime_dependencies["distributions"]
            for record in distribution["identity_files"]
        ),
    }
    if not required_runtime_paths <= implementation_paths:
        raise IsolatedExecutionProtocolError(
            "isolated WER implementation closure omits runtime bytes"
        )
    return copy.deepcopy(dict(payload))


def _validate_request(candidate: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(candidate, Mapping) or set(candidate) != _REQUEST_KEYS:
        raise IsolatedExecutionProtocolError(
            "isolated execution request schema is invalid"
        )
    if candidate.get("schema_version") != SCHEMA_VERSION:
        raise IsolatedExecutionProtocolError(
            "isolated execution request version is invalid"
        )
    if candidate.get("handler_id") not in REGISTERED_HANDLER_IDS:
        raise IsolatedExecutionProtocolError(
            "isolated execution handler is not registered"
        )
    request_id = candidate.get("request_id")
    if (
        not isinstance(request_id, str)
        or len(request_id) != 32
        or any(ch not in "0123456789abcdef" for ch in request_id)
    ):
        raise IsolatedExecutionProtocolError(
            "isolated execution request identity is invalid"
        )
    digest = candidate.get("request_sha256")
    if (
        not isinstance(digest, str)
        or len(digest) != 64
        or digest != _digest_request(candidate)
    ):
        raise IsolatedExecutionProtocolError(
            "isolated execution request digest is invalid"
        )
    payload = candidate.get("payload")
    if not isinstance(payload, Mapping):
        raise IsolatedExecutionProtocolError(
            "isolated execution payload schema is invalid"
        )
    if candidate["handler_id"] == HANDLER_RUN_WER_PROVIDER:
        if set(payload) != _WER_PROVIDER_PAYLOAD_KEYS:
            raise IsolatedExecutionProtocolError(
                "isolated WER payload schema is invalid"
            )
        core = {
            key: copy.deepcopy(value)
            for key, value in payload.items()
            if key in _WER_PROVIDER_CORE_KEYS
        }
        normalized_core = _validate_wer_provider_core(core)
        if payload.get("request_core_sha256") != (
            wer_provider_request_core_sha256(normalized_core)
        ):
            raise IsolatedExecutionProtocolError(
                "isolated WER request core digest mismatch"
            )
        _require_hex64(
            payload.get("outer_arm_sha256"),
            "isolated WER outer arm digest",
        )
        return copy.deepcopy(dict(candidate))
    if set(payload) != _OWNED_PROCESS_PAYLOAD_KEYS:
        raise IsolatedExecutionProtocolError(
            "isolated execution payload schema is invalid"
        )
    requested_command = payload.get("requested_command")
    command = payload.get("command")
    for label, argv in (
        ("requested command", requested_command),
        ("resolved command", command),
    ):
        if (
            not isinstance(argv, list)
            or not argv
            or len(argv) > 4096
            or any(
                not isinstance(item, str)
                or not item
                or len(item) > 1024 * 1024
                for item in argv
            )
        ):
            raise IsolatedExecutionProtocolError(
                f"isolated execution {label} is invalid"
            )
    cwd = payload.get("cwd")
    if cwd is not None and (not isinstance(cwd, str) or not cwd):
        raise IsolatedExecutionProtocolError(
            "isolated execution cwd is invalid"
        )
    environment = payload.get("env")
    if (
        not isinstance(environment, Mapping)
        or len(environment) > 65536
        or any(
            not isinstance(key, str)
            or not key
            or not isinstance(value, str)
            for key, value in environment.items()
        )
    ):
        raise IsolatedExecutionProtocolError(
            "isolated execution environment is invalid"
        )
    try:
        from owned_process_runner import resolve_owned_process_command

        expected_command = resolve_owned_process_command(
            requested_command,
            env=environment,
        )
    except (FileNotFoundError, OSError, ValueError) as exc:
        raise IsolatedExecutionProtocolError(
            "isolated execution command resolution is invalid"
        ) from exc
    if list(expected_command) != command:
        raise IsolatedExecutionProtocolError(
            "isolated execution requested/resolved command binding is invalid"
        )
    try:
        from locked_executable_guard import (
            LockedExecutableGuardError,
            validate_locked_executable_binding,
        )

        validate_locked_executable_binding(
            command[0],
            payload.get("executable_guard"),
        )
    except (LockedExecutableGuardError, OSError, ValueError) as exc:
        raise IsolatedExecutionProtocolError(
            "isolated execution executable guard binding is invalid"
        ) from exc
    timeout = payload.get("timeout")
    if (
        isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or not math.isfinite(float(timeout))
        or timeout <= 0
        or timeout > 7 * 24 * 60 * 60
    ):
        raise IsolatedExecutionProtocolError(
            "isolated execution timeout is invalid"
        )
    if (
        not isinstance(payload.get("encoding"), str)
        or not payload["encoding"]
        or payload.get("errors") not in {"strict", "ignore", "replace"}
    ):
        raise IsolatedExecutionProtocolError(
            "isolated execution decoding policy is invalid"
        )
    limit = payload.get("output_limit_bytes")
    if (
        isinstance(limit, bool)
        or not isinstance(limit, int)
        or limit <= 0
        or limit > 32 * 1024 * 1024
    ):
        raise IsolatedExecutionProtocolError(
            "isolated execution output bound is invalid"
        )
    roots = payload.get("writable_roots")
    if (
        not isinstance(roots, list)
        or len(roots) > 4096
        or any(not isinstance(item, str) or not item for item in roots)
    ):
        raise IsolatedExecutionProtocolError(
            "isolated execution writable roots are invalid"
        )
    return copy.deepcopy(dict(candidate))


def _build_terminal_receipt(
    *,
    receipt_type: str,
    request: Mapping[str, Any],
    executor_pid: int,
    completion_authority: bool,
    payload: Mapping[str, Any],
) -> dict[str, Any]:
    core = {
        "schema_version": SCHEMA_VERSION,
        "receipt_type": receipt_type,
        "handler_id": request["handler_id"],
        "request_id": request["request_id"],
        "request_sha256": request["request_sha256"],
        "executor_pid": executor_pid,
        "completion_authority": completion_authority,
        "payload": copy.deepcopy(dict(payload)),
    }
    return {**core, "receipt_sha256": _sha(core)}


def _validate_terminal_receipt(
    candidate: Mapping[str, Any],
    *,
    expected_request: Mapping[str, Any],
    expected_executor_pid: int,
) -> dict[str, Any]:
    request = _validate_request(expected_request)
    if not isinstance(candidate, Mapping) or set(candidate) != _RECEIPT_KEYS:
        raise IsolatedExecutionProtocolError(
            "isolated execution terminal receipt schema is invalid"
        )
    if (
        candidate.get("schema_version") != SCHEMA_VERSION
        or candidate.get("handler_id") != request["handler_id"]
        or candidate.get("request_id") != request["request_id"]
        or candidate.get("request_sha256") != request["request_sha256"]
        or candidate.get("executor_pid") != expected_executor_pid
    ):
        raise IsolatedExecutionProtocolError(
            "isolated execution terminal receipt binding is invalid"
        )
    receipt_digest = candidate.get("receipt_sha256")
    if (
        not isinstance(receipt_digest, str)
        or len(receipt_digest) != 64
        or receipt_digest != _digest_receipt(candidate)
    ):
        raise IsolatedExecutionProtocolError(
            "isolated execution terminal receipt digest is invalid"
        )
    receipt_type = candidate.get("receipt_type")
    completion = candidate.get("completion_authority")
    payload = candidate.get("payload")
    if not isinstance(payload, Mapping) or type(completion) is not bool:
        raise IsolatedExecutionProtocolError(
            "isolated execution receipt disposition is invalid"
        )
    if (
        request["handler_id"] == HANDLER_RUN_WER_PROVIDER
        and receipt_type
        not in {
            "WER_COMPLETED",
            "WER_DEBT",
            "COORDINATOR_WER_COMPLETED",
            "COORDINATOR_WER_DEBT",
        }
    ):
        raise IsolatedExecutionProtocolError(
            "isolated WER receipt type is invalid for its handler"
        )

    def valid_reason(value: Any) -> bool:
        return (
            isinstance(value, str)
            and bool(value)
            and len(value) <= 128
            and not any(
                ch not in "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"
                for ch in value
            )
        )

    def validate_blob(value: Any, label: str) -> None:
        if (
            not isinstance(value, Mapping)
            or set(value) != {"relative_path", "sha256", "size"}
        ):
            raise IsolatedExecutionProtocolError(
                f"isolated WER {label} blob is invalid"
            )
        _validate_relative_path(
            value.get("relative_path"),
            f"isolated WER {label} blob path",
        )
        _require_hex64(
            value.get("sha256"),
            f"isolated WER {label} blob digest",
        )
        if (
            isinstance(value.get("size"), bool)
            or not isinstance(value.get("size"), int)
            or value["size"] < 0
        ):
            raise IsolatedExecutionProtocolError(
                f"isolated WER {label} blob size is invalid"
            )

    if receipt_type == "WER_COMPLETED":
        if (
            request["handler_id"] != HANDLER_RUN_WER_PROVIDER
            or completion is not True
            or set(payload) != _WER_CHILD_COMPLETED_PAYLOAD_KEYS
        ):
            raise IsolatedExecutionProtocolError(
                "isolated WER child completion authority is invalid"
            )
        for field in (
            "inner_receipt_relative_path",
            "inner_arm_relative_path",
        ):
            _validate_relative_path(
                payload.get(field),
                f"isolated WER {field}",
            )
        for field in (
            "inner_completion_sha256",
            "inner_arm_sha256",
            "process_observation_sha256",
            "semantic_authority_sha256",
            "request_core_sha256",
            "outer_arm_sha256",
            "implementation_files_sha256",
            "runtime_dependency_sha256",
        ):
            _require_hex64(payload.get(field), f"isolated WER {field}")
        if (
            payload["semantic_authority_sha256"]
            != request["payload"]["semantic_authority"][
                "semantic_authority_sha256"
            ]
            or payload["request_core_sha256"]
            != request["payload"]["request_core_sha256"]
            or payload["outer_arm_sha256"]
            != request["payload"]["outer_arm_sha256"]
            or payload["implementation_files_sha256"]
            != _wer_implementation_files_sha256(
                request["payload"]
            )
            or payload["runtime_dependency_sha256"]
            != request["payload"]["runtime_dependency_binding"][
                "runtime_dependency_sha256"
            ]
            or payload.get("inner_process_scope_identity")
            != request["payload"]["process_scope_identity"]
            or payload.get("inner_process_population_zero_proven") is not True
            or isinstance(payload.get("returncode"), bool)
            or payload.get("returncode") != 0
        ):
            raise IsolatedExecutionProtocolError(
                "isolated WER child completion binding is invalid"
            )
        validate_blob(payload.get("stdout_blob"), "stdout")
        validate_blob(payload.get("stderr_blob"), "stderr")
        publish_path = payload.get("publish_receipt_relative_path")
        publish_sha = payload.get("publish_sha256")
        if (publish_path is None) != (publish_sha is None):
            raise IsolatedExecutionProtocolError(
                "isolated WER publish receipt binding is partial"
            )
        if publish_path is not None:
            _validate_relative_path(
                publish_path,
                "isolated WER publish receipt path",
            )
            _require_hex64(
                publish_sha,
                "isolated WER publish receipt digest",
            )
        published = payload.get("published_paths")
        if not isinstance(published, list):
            raise IsolatedExecutionProtocolError(
                "isolated WER published path denominator is invalid"
            )
        for path in published:
            _validate_relative_path(
                path,
                "isolated WER published path",
            )
    elif receipt_type == "WER_DEBT":
        if (
            request["handler_id"] != HANDLER_RUN_WER_PROVIDER
            or completion is not False
            or set(payload) != _WER_CHILD_DEBT_PAYLOAD_KEYS
            or not valid_reason(payload.get("reason_code"))
        ):
            raise IsolatedExecutionProtocolError(
                "isolated WER child debt is invalid"
            )
        for field in (
            "semantic_authority_sha256",
            "request_core_sha256",
            "outer_arm_sha256",
            "implementation_files_sha256",
            "runtime_dependency_sha256",
        ):
            _require_hex64(payload.get(field), f"isolated WER {field}")
        if (
            payload["semantic_authority_sha256"]
            != request["payload"]["semantic_authority"][
                "semantic_authority_sha256"
            ]
            or payload["request_core_sha256"]
            != request["payload"]["request_core_sha256"]
            or payload["outer_arm_sha256"]
            != request["payload"]["outer_arm_sha256"]
            or payload["implementation_files_sha256"]
            != _wer_implementation_files_sha256(
                request["payload"]
            )
            or payload["runtime_dependency_sha256"]
            != request["payload"]["runtime_dependency_binding"][
                "runtime_dependency_sha256"
            ]
        ):
            raise IsolatedExecutionProtocolError(
                "isolated WER child debt binding is invalid"
            )
        pairs = (
            ("inner_arm_relative_path", "inner_arm_sha256"),
            ("inner_debt_relative_path", "inner_debt_sha256"),
        )
        for path_field, digest_field in pairs:
            path_value = payload.get(path_field)
            digest_value = payload.get(digest_field)
            if (path_value is None) != (digest_value is None):
                raise IsolatedExecutionProtocolError(
                    "isolated WER child debt evidence is partial"
                )
            if path_value is not None:
                _validate_relative_path(
                    path_value,
                    f"isolated WER {path_field}",
                )
                _require_hex64(
                    digest_value,
                    f"isolated WER {digest_field}",
                )
    elif receipt_type in {
        "COORDINATOR_WER_COMPLETED",
        "COORDINATOR_WER_DEBT",
    }:
        expected_keys = (
            _WER_COORDINATOR_PAYLOAD_KEYS
            if receipt_type == "COORDINATOR_WER_COMPLETED"
            else _WER_COORDINATOR_DEBT_PAYLOAD_KEYS
        )
        if (
            request["handler_id"] != HANDLER_RUN_WER_PROVIDER
            or set(payload) != expected_keys
            or payload.get("runtime_dependency_sha256")
            != request["payload"]["runtime_dependency_binding"][
                "runtime_dependency_sha256"
            ]
            or (
                receipt_type == "COORDINATOR_WER_COMPLETED"
                and (
                    completion is not True
                    or payload.get(
                        "executor_population_zero_proven"
                    )
                    is not True
                )
            )
            or (
                receipt_type == "COORDINATOR_WER_DEBT"
                and (
                    completion is not False
                    or type(
                        payload.get(
                            "executor_population_zero_proven"
                        )
                    )
                    is not bool
                    or not valid_reason(payload.get("reason_code"))
                )
            )
        ):
            raise IsolatedExecutionProtocolError(
                "isolated WER coordinator receipt is invalid"
            )
        child = payload.get("child_receipt")
        child_sha = payload.get("child_receipt_sha256")
        if child is None:
            if child_sha is not None:
                raise IsolatedExecutionProtocolError(
                    "isolated WER coordinator child binding is partial"
                )
        else:
            validated_child = _validate_terminal_receipt(
                child,
                expected_request=request,
                expected_executor_pid=expected_executor_pid,
            )
            if (
                child_sha != validated_child["receipt_sha256"]
                or (
                    receipt_type == "COORDINATOR_WER_COMPLETED"
                    and validated_child["receipt_type"] != "WER_COMPLETED"
                )
                or (
                    receipt_type == "COORDINATOR_WER_DEBT"
                    and validated_child["completion_authority"] is not False
                )
            ):
                raise IsolatedExecutionProtocolError(
                    "isolated WER coordinator child binding is invalid"
                )
    elif receipt_type == "COMPLETED":
        if completion is not True or set(payload) != _COMPLETED_PAYLOAD_KEYS:
            raise IsolatedExecutionProtocolError(
                "isolated completion authority is invalid"
            )
        if (
            payload.get("process_tree_terminated") is not True
            or payload.get("args") != request["payload"]["command"]
            or isinstance(payload.get("returncode"), bool)
            or not isinstance(payload.get("returncode"), int)
            or not isinstance(payload.get("stdout"), str)
            or not isinstance(payload.get("stderr"), str)
            or isinstance(payload.get("duration_s"), bool)
            or not isinstance(payload.get("duration_s"), (int, float))
            or not math.isfinite(float(payload["duration_s"]))
            or payload["duration_s"] < 0
            or not isinstance(payload.get("containment_capability"), Mapping)
        ):
            raise IsolatedExecutionProtocolError(
                "isolated completed payload is invalid"
            )
    elif receipt_type == "TIMED_OUT":
        if completion is not False or set(payload) != _TIMEOUT_PAYLOAD_KEYS:
            raise IsolatedExecutionProtocolError(
                "isolated timeout receipt is invalid"
            )
        if (
            isinstance(payload.get("timeout"), bool)
            or not isinstance(payload.get("timeout"), (int, float))
            or not math.isfinite(float(payload["timeout"]))
            or payload["timeout"] <= 0
            or not isinstance(payload.get("stdout"), str)
            or not isinstance(payload.get("stderr"), str)
        ):
            raise IsolatedExecutionProtocolError(
                "isolated timeout payload is invalid"
            )
    elif receipt_type in {"DEBT", "COORDINATOR_DEBT"}:
        if completion is not False or set(payload) != _DEBT_PAYLOAD_KEYS:
            raise IsolatedExecutionProtocolError(
                "isolated debt receipt is invalid"
            )
        reason = payload.get("reason_code")
        if not valid_reason(reason):
            raise IsolatedExecutionProtocolError(
                "isolated debt reason is invalid"
            )
    else:
        raise IsolatedExecutionProtocolError(
            "isolated execution receipt type is invalid"
        )
    return copy.deepcopy(dict(candidate))


class _PipeCollector:
    def __init__(self, handle: Any, *, limit: int) -> None:
        self._handle = handle
        self._limit = limit
        self._data = bytearray()
        self._overflow = False
        self._error: BaseException | None = None
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self) -> None:
        try:
            while True:
                chunk = self._handle.read(65536)
                if not chunk:
                    return
                if len(self._data) + len(chunk) > self._limit:
                    remaining = max(0, self._limit - len(self._data))
                    self._data.extend(chunk[:remaining])
                    self._overflow = True
                elif not self._overflow:
                    self._data.extend(chunk)
        except BaseException as exc:
            self._error = exc

    def finish(self, *, timeout: float) -> bytes:
        self._thread.join(timeout)
        if self._thread.is_alive():
            raise IsolatedExecutionProtocolError(
                "isolated executor pipe did not reach EOF"
            )
        if self._error is not None:
            raise IsolatedExecutionProtocolError(
                "isolated executor pipe could not be read"
            ) from self._error
        if self._overflow:
            raise IsolatedExecutionProtocolError(
                "isolated executor pipe exceeded its bound"
            )
        return bytes(self._data)


class _WindowsExecutorJob:
    """Own the disposable executor and every nested descendant."""

    def __init__(self) -> None:
        if os.name != "nt":
            raise IsolatedExecutionHostError(
                "disposable execution host is unavailable on this platform",
                receipt=_unbound_debt_receipt("PLATFORM_UNSUPPORTED"),
            )
        self._handle = self._create()
        self._closed = False

    @staticmethod
    def _create() -> int:
        class _IoCounters(ctypes.Structure):
            _fields_ = [
                ("ReadOperationCount", ctypes.c_uint64),
                ("WriteOperationCount", ctypes.c_uint64),
                ("OtherOperationCount", ctypes.c_uint64),
                ("ReadTransferCount", ctypes.c_uint64),
                ("WriteTransferCount", ctypes.c_uint64),
                ("OtherTransferCount", ctypes.c_uint64),
            ]

        class _BasicLimit(ctypes.Structure):
            _fields_ = [
                ("PerProcessUserTimeLimit", ctypes.c_int64),
                ("PerJobUserTimeLimit", ctypes.c_int64),
                ("LimitFlags", ctypes.c_uint32),
                ("MinimumWorkingSetSize", ctypes.c_size_t),
                ("MaximumWorkingSetSize", ctypes.c_size_t),
                ("ActiveProcessLimit", ctypes.c_uint32),
                ("Affinity", ctypes.c_size_t),
                ("PriorityClass", ctypes.c_uint32),
                ("SchedulingClass", ctypes.c_uint32),
            ]

        class _ExtendedLimit(ctypes.Structure):
            _fields_ = [
                ("BasicLimitInformation", _BasicLimit),
                ("IoInfo", _IoCounters),
                ("ProcessMemoryLimit", ctypes.c_size_t),
                ("JobMemoryLimit", ctypes.c_size_t),
                ("PeakProcessMemoryUsed", ctypes.c_size_t),
                ("PeakJobMemoryUsed", ctypes.c_size_t),
            ]

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateJobObjectW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p]
        kernel32.CreateJobObjectW.restype = ctypes.c_void_p
        kernel32.SetInformationJobObject.argtypes = [
            ctypes.c_void_p,
            ctypes.c_int,
            ctypes.c_void_p,
            ctypes.c_uint32,
        ]
        kernel32.SetInformationJobObject.restype = ctypes.c_int
        kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
        kernel32.CloseHandle.restype = ctypes.c_int
        handle = kernel32.CreateJobObjectW(None, None)
        if not handle:
            raise RuntimeError("CreateJobObjectW failed")
        limits = _ExtendedLimit()
        limits.BasicLimitInformation.LimitFlags = (
            _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        )
        if not kernel32.SetInformationJobObject(
            handle,
            _JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
            ctypes.byref(limits),
            ctypes.sizeof(limits),
        ):
            kernel32.CloseHandle(handle)
            raise RuntimeError("SetInformationJobObject failed")
        return int(handle)

    def assign_and_resume(self, process: subprocess.Popen[bytes]) -> None:
        from owned_process_scope import OwnedProcessScope

        handle = getattr(process, "_handle", None)
        if handle is None:
            raise RuntimeError("executor process handle is unavailable")
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.AssignProcessToJobObject.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
        ]
        kernel32.AssignProcessToJobObject.restype = ctypes.c_int
        if not kernel32.AssignProcessToJobObject(
            ctypes.c_void_p(self._handle),
            ctypes.c_void_p(int(handle)),
        ):
            raise RuntimeError("AssignProcessToJobObject failed")
        OwnedProcessScope._resume_only_thread(process.pid)

    def _active_processes(self) -> int:
        class _BasicAccounting(ctypes.Structure):
            _fields_ = [
                ("TotalUserTime", ctypes.c_int64),
                ("TotalKernelTime", ctypes.c_int64),
                ("ThisPeriodTotalUserTime", ctypes.c_int64),
                ("ThisPeriodKernelTime", ctypes.c_int64),
                ("TotalPageFaultCount", ctypes.c_uint32),
                ("TotalProcesses", ctypes.c_uint32),
                ("ActiveProcesses", ctypes.c_uint32),
                ("TotalTerminatedProcesses", ctypes.c_uint32),
            ]

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.QueryInformationJobObject.argtypes = [
            ctypes.c_void_p,
            ctypes.c_int,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_uint32),
        ]
        kernel32.QueryInformationJobObject.restype = ctypes.c_int
        accounting = _BasicAccounting()
        returned = ctypes.c_uint32()
        if not kernel32.QueryInformationJobObject(
            ctypes.c_void_p(self._handle),
            _JOB_OBJECT_BASIC_ACCOUNTING_INFORMATION,
            ctypes.byref(accounting),
            ctypes.sizeof(accounting),
            ctypes.byref(returned),
        ):
            raise RuntimeError("QueryInformationJobObject failed")
        return int(accounting.ActiveProcesses)

    def _terminate(self) -> None:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.TerminateJobObject.argtypes = [
            ctypes.c_void_p,
            ctypes.c_uint32,
        ]
        kernel32.TerminateJobObject.restype = ctypes.c_int
        if not kernel32.TerminateJobObject(
            ctypes.c_void_p(self._handle),
            97,
        ):
            raise RuntimeError("TerminateJobObject failed")

    def _wait_zero(self, *, timeout: float) -> None:
        deadline = time.monotonic() + timeout
        while True:
            if self._active_processes() == 0:
                return
            if time.monotonic() >= deadline:
                raise RuntimeError("executor Job population remained nonzero")
            time.sleep(0.01)

    def finalize(
        self,
        process: subprocess.Popen[bytes],
        *,
        force_terminate: bool,
        timeout: float,
    ) -> bool:
        exact = True
        try:
            if force_terminate:
                self._terminate()
            else:
                process.wait(timeout=timeout)
                if self._active_processes() != 0:
                    self._terminate()
            process.wait(timeout=timeout)
            self._wait_zero(timeout=timeout)
        except BaseException:
            exact = False
        try:
            self.close()
        except BaseException:
            exact = False
        if not exact:
            try:
                process.wait(timeout=timeout)
            except BaseException:
                pass
        return exact and process.poll() is not None

    def close(self) -> None:
        if self._closed:
            return
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
        kernel32.CloseHandle.restype = ctypes.c_int
        if not kernel32.CloseHandle(ctypes.c_void_p(self._handle)):
            raise RuntimeError("CloseHandle(Job Object) failed")
        self._closed = True


def _windows_cpython_executor_paths() -> tuple[Path, Path]:
    """Return the logical managed executable and its physical CPython host.

    A Windows venv ``python.exe`` is a redirector: ``Popen.pid`` identifies
    the redirector while the terminal receipt is emitted by its one child.
    Launching the physical interpreter directly and using CPython's own
    ``__PYVENV_LAUNCHER__`` handshake preserves the logical ``sys.executable``
    without introducing that second process identity.
    """

    if os.name != "nt" or sys.implementation.name != "cpython":
        raise RuntimeError(
            "the disposable executor requires Windows CPython"
        )
    logical_text = getattr(sys, "executable", None)
    physical_text = getattr(sys, "_base_executable", None)
    if (
        not isinstance(logical_text, str)
        or not logical_text
        or not isinstance(physical_text, str)
        or not physical_text
    ):
        raise RuntimeError("the Windows CPython executable identity is absent")
    logical_input = Path(logical_text)
    physical_input = Path(physical_text)
    if not logical_input.is_absolute() or not physical_input.is_absolute():
        raise RuntimeError("the Windows CPython executable identity is relative")
    logical = logical_input.resolve(strict=True)
    physical = physical_input.resolve(strict=True)
    if (
        logical.suffix.lower() != ".exe"
        or physical.suffix.lower() != ".exe"
    ):
        raise RuntimeError("the Windows CPython executable identity is invalid")
    return logical, physical


def _lock_windows_python_startup_closure(
    logical: Path,
    physical: Path,
) -> None:
    """Content-bind startup files and deny mutation for this driver lifetime."""

    from locked_executable_guard import bind_locked_executable

    paths = {logical, physical}
    if logical != physical:
        configuration = logical.parent.parent / "pyvenv.cfg"
        if not configuration.is_file():
            raise RuntimeError("the managed Python launcher has no pyvenv.cfg")
        paths.add(configuration.resolve(strict=True))
    version_dll = physical.parent / (
        f"python{sys.version_info.major}{sys.version_info.minor}.dll"
    )
    if not version_dll.is_file():
        raise RuntimeError("the Windows CPython runtime DLL is absent")
    paths.add(version_dll.resolve(strict=True))
    stable_abi_dll = physical.parent / "python3.dll"
    if stable_abi_dll.is_file():
        paths.add(stable_abi_dll.resolve(strict=True))
    # These are the complete local-code path for owned-process request replay
    # and execution.  Lock sources plus any importable bytecode before Python
    # opens the host script; the retained Windows handles deny replacement.
    runtime_sources = (
        Path(__file__).resolve(strict=True),
        _MODULE_ROOT / "bounded_artifact_io.py",
        _MODULE_ROOT / "owned_process_runner.py",
        _MODULE_ROOT / "owned_process_scope.py",
        _MODULE_ROOT / "locked_executable_guard.py",
        _MODULE_ROOT / "windows_low_integrity_lease.py",
    )
    for source in runtime_sources:
        resolved_source = source.resolve(strict=True)
        if not resolved_source.is_file():
            raise RuntimeError("the isolated executor runtime source is absent")
        paths.add(resolved_source)
        cached = Path(importlib.util.cache_from_source(str(resolved_source)))
        if cached.is_file():
            paths.add(cached.resolve(strict=True))
    for path in sorted(paths, key=lambda item: os.path.normcase(str(item))):
        bind_locked_executable(path)


def _executor_environment(*, logical_executable: Path | None = None) -> dict[str, str]:
    allowed = {
        "SystemRoot",
        "WINDIR",
        "ComSpec",
        "PATH",
        "PATHEXT",
        "TEMP",
        "TMP",
        "LOCALAPPDATA",
        "USERPROFILE",
        "HOMEDRIVE",
        "HOMEPATH",
        "PLAMEN_WINDOWS_LOW_INTEGRITY_LEASE_DIR",
        "PLAMEN_TEST_ALLOW_WINDOWS_LEASE_OVERRIDE",
        "PLAMEN_WINDOWS_LOW_INTEGRITY_LEASE_TIMEOUT_SECONDS",
    }
    canonical_by_fold = {key.casefold(): key for key in allowed}
    environment: dict[str, str] = {}
    observed_folds: set[str] = set()
    for key, value in os.environ.items():
        folded = key.casefold()
        canonical = canonical_by_fold.get(folded)
        if canonical is None:
            continue
        if folded in observed_folds:
            raise RuntimeError(
                "the executor environment contains case-aliased keys"
            )
        observed_folds.add(folded)
        environment[canonical] = value
    # Environment names are case-insensitive on Windows.  Never inherit an
    # ambient spelling of CPython's reserved launcher handshake.
    for key in tuple(environment):
        if key.casefold() == "__pyvenv_launcher__":
            del environment[key]
    if logical_executable is not None:
        environment["__PYVENV_LAUNCHER__"] = str(logical_executable)
    environment["PYTHONIOENCODING"] = "utf-8"
    environment["PYTHONUTF8"] = "1"
    return environment


def _executor_argv(
    handler_id: str = HANDLER_RUN_OWNED_PROCESS,
    *,
    logical_executable: Path | None = None,
    physical_executable: Path | None = None,
) -> tuple[str, ...]:
    del handler_id
    if logical_executable is None or physical_executable is None:
        logical_executable, physical_executable = (
            _windows_cpython_executor_paths()
        )
    base = (
        str(physical_executable),
        "-I",
        "-S",
        "-B",
        "-X",
        "pycache_prefix=NUL",
    )
    # Both handlers start without site initialization.  The semantic handler
    # adds only request-bound import roots after the exact request and every
    # dependency byte have replayed, then verifies the loaded closure again.
    return (
        *base,
        str(Path(__file__).resolve()),
        "--child",
        "--logical-executable",
        str(logical_executable),
        "--physical-executable",
        str(physical_executable),
    )


def _cancellation_requested(token: Any) -> bool:
    if token is None:
        return False
    is_set = getattr(token, "is_set", None)
    if callable(is_set):
        return bool(is_set())
    cancelled = getattr(token, "cancelled", None)
    if callable(cancelled):
        return bool(cancelled())
    if callable(token):
        return bool(token())
    return bool(token)


def _receipt_surface_failure_reason(
    candidate: Any,
    *,
    expected_request: Mapping[str, Any],
    expected_executor_pid: int,
) -> str | None:
    """Classify the terminal envelope without parsing exception prose."""

    if not isinstance(candidate, Mapping) or set(candidate) != _RECEIPT_KEYS:
        return "EXECUTOR_RECEIPT_SCHEMA_INVALID"
    if (
        candidate.get("schema_version") != SCHEMA_VERSION
        or candidate.get("handler_id") != expected_request["handler_id"]
        or candidate.get("request_id") != expected_request["request_id"]
        or candidate.get("request_sha256")
        != expected_request["request_sha256"]
        or candidate.get("executor_pid") != expected_executor_pid
    ):
        return "EXECUTOR_RECEIPT_BINDING_INVALID"
    receipt_digest = candidate.get("receipt_sha256")
    if (
        not isinstance(receipt_digest, str)
        or len(receipt_digest) != 64
        or receipt_digest != _digest_receipt(candidate)
    ):
        return "EXECUTOR_RECEIPT_DIGEST_INVALID"
    return None


def _unbound_debt_receipt(reason_code: str) -> dict[str, Any]:
    core = {
        "schema_version": SCHEMA_VERSION,
        "receipt_type": "COORDINATOR_DEBT",
        "handler_id": HANDLER_RUN_OWNED_PROCESS,
        "request_id": "0" * 32,
        "request_sha256": "0" * 64,
        "executor_pid": 0,
        "completion_authority": False,
        "payload": {"reason_code": reason_code},
    }
    return {**core, "receipt_sha256": _sha(core)}


def _unbound_wer_debt_receipt(reason_code: str) -> dict[str, Any]:
    core = {
        "schema_version": SCHEMA_VERSION,
        "receipt_type": "COORDINATOR_WER_DEBT",
        "handler_id": HANDLER_RUN_WER_PROVIDER,
        "request_id": "0" * 32,
        "request_sha256": "0" * 64,
        "executor_pid": 0,
        "completion_authority": False,
        "payload": {
            "reason_code": reason_code,
            "child_receipt": None,
            "child_receipt_sha256": None,
            "executor_population_zero_proven": False,
            "runtime_dependency_sha256": "0" * 64,
        },
    }
    return {**core, "receipt_sha256": _sha(core)}


def _unbound_debt_for_handler(
    handler_id: str,
    reason_code: str,
) -> dict[str, Any]:
    if handler_id == HANDLER_RUN_WER_PROVIDER:
        return _unbound_wer_debt_receipt(reason_code)
    return _unbound_debt_receipt(reason_code)


def untrusted_wer_failure_receipt(
    reason_code: str = "EXECUTOR_RECEIPT_INVALID",
) -> dict[str, Any]:
    """Return a closed, secret-free debt record for unusable host evidence."""

    return _unbound_wer_debt_receipt(reason_code)


def sanitize_wer_failure_receipt(
    candidate: Mapping[str, Any],
) -> dict[str, Any]:
    """Accept only a closed, digest-valid WER coordinator debt receipt."""

    if not isinstance(candidate, Mapping) or set(candidate) != _RECEIPT_KEYS:
        raise IsolatedExecutionProtocolError(
            "isolated WER failure receipt schema is invalid"
        )
    receipt = copy.deepcopy(dict(candidate))
    if (
        receipt.get("schema_version") != SCHEMA_VERSION
        or receipt.get("handler_id") != HANDLER_RUN_WER_PROVIDER
        or receipt.get("receipt_type") != "COORDINATOR_WER_DEBT"
        or receipt.get("completion_authority") is not False
        or receipt.get("receipt_sha256") != _digest_receipt(receipt)
    ):
        raise IsolatedExecutionProtocolError(
            "isolated WER failure receipt authority is invalid"
        )
    payload = receipt.get("payload")
    if (
        not isinstance(payload, Mapping)
        or set(payload) != _WER_COORDINATOR_DEBT_PAYLOAD_KEYS
        or not isinstance(payload.get("reason_code"), str)
        or not payload["reason_code"]
        or type(payload.get("executor_population_zero_proven")) is not bool
        or not isinstance(payload.get("runtime_dependency_sha256"), str)
        or len(payload["runtime_dependency_sha256"]) != 64
        or any(
            ch not in "0123456789abcdef"
            for ch in payload["runtime_dependency_sha256"]
        )
    ):
        raise IsolatedExecutionProtocolError(
            "isolated WER failure receipt payload is invalid"
        )
    child = payload.get("child_receipt")
    child_sha = payload.get("child_receipt_sha256")
    if child is None:
        if child_sha is not None:
            raise IsolatedExecutionProtocolError(
                "isolated WER failure child binding is partial"
            )
        return receipt
    if (
        not isinstance(child, Mapping)
        or set(child) != _RECEIPT_KEYS
        or child.get("schema_version") != SCHEMA_VERSION
        or child.get("handler_id") != HANDLER_RUN_WER_PROVIDER
        or child.get("receipt_type") != "WER_DEBT"
        or child.get("completion_authority") is not False
        or child.get("request_id") != receipt.get("request_id")
        or child.get("request_sha256") != receipt.get("request_sha256")
        or child.get("executor_pid") != receipt.get("executor_pid")
        or child.get("receipt_sha256") != _digest_receipt(child)
        or child_sha != child.get("receipt_sha256")
    ):
        raise IsolatedExecutionProtocolError(
            "isolated WER failure child receipt is invalid"
        )
    child_payload = child.get("payload")
    if (
        not isinstance(child_payload, Mapping)
        or set(child_payload) != _WER_CHILD_DEBT_PAYLOAD_KEYS
        or not isinstance(child_payload.get("reason_code"), str)
        or not child_payload["reason_code"]
    ):
        raise IsolatedExecutionProtocolError(
            "isolated WER failure child payload is invalid"
        )
    return receipt


@dataclass(frozen=True)
class _AttemptResult:
    value: Any


@dataclass(frozen=True)
class IsolatedWERCompleted:
    """Coordinator-proven executor closure plus one inner WER completion."""

    coordinator_receipt: Mapping[str, Any]
    child_receipt: Mapping[str, Any]

    @property
    def payload(self) -> Mapping[str, Any]:
        return copy.deepcopy(dict(self.child_receipt["payload"]))


class IsolatedExecutionAttempt:
    """One exact disposable executor lifetime; representation is non-sensitive."""

    def __init__(
        self,
        *,
        request: dict[str, Any],
        process: subprocess.Popen[bytes],
        job: _WindowsExecutorJob,
        stdout_collector: _PipeCollector,
        stderr_collector: _PipeCollector,
        executor_argv: tuple[str, ...],
    ) -> None:
        self._request = request
        self._process = process
        self._job = job
        self._stdout_collector = stdout_collector
        self._stderr_collector = stderr_collector
        self._executor_argv_value = executor_argv
        self._terminal_receipt: dict[str, Any] | None = None
        self._waited = False
        self._result: _AttemptResult | None = None
        self._finalized_streams: tuple[bytes, bytes] | None = None
        self._population_exact: bool | None = None

    def __repr__(self) -> str:
        return (
            "<IsolatedExecutionAttempt "
            f"request_id={self._request['request_id']} "
            f"request_sha256={self._request['request_sha256']} "
            f"executor_pid={self._process.pid} waited={self._waited}>"
        )

    @property
    def executor_argv(self) -> tuple[str, ...]:
        return self._executor_argv_value

    @property
    def terminal_receipt(self) -> dict[str, Any] | None:
        if self._terminal_receipt is None:
            return None
        return copy.deepcopy(self._terminal_receipt)

    @property
    def request_sha256(self) -> str:
        return str(self._request["request_sha256"])

    @property
    def request_core_sha256(self) -> str | None:
        value = self._request["payload"].get("request_core_sha256")
        return str(value) if isinstance(value, str) else None

    def _executor_process_handle_for_test(self) -> int:
        handle = getattr(self._process, "_handle", None)
        if handle is None:
            raise IsolatedExecutionHostError(
                "executor process handle is unavailable",
                receipt=self._coordinator_debt("EXECUTOR_HANDLE_UNAVAILABLE"),
            )
        return int(handle)

    def _coordinator_debt(self, reason_code: str) -> dict[str, Any]:
        return _build_terminal_receipt(
            receipt_type="COORDINATOR_DEBT",
            request=self._request,
            executor_pid=self._process.pid,
            completion_authority=False,
            payload={"reason_code": reason_code},
        )

    def _coordinator_wer_receipt(
        self,
        *,
        completed: bool,
        reason_code: str | None,
        child_receipt: Mapping[str, Any] | None,
        population_exact: bool,
    ) -> dict[str, Any]:
        if self._request["handler_id"] != HANDLER_RUN_WER_PROVIDER:
            raise IsolatedExecutionProtocolError(
                "WER coordinator receipt requested for another handler"
            )
        child = (
            None
            if child_receipt is None
            else copy.deepcopy(dict(child_receipt))
        )
        payload: dict[str, Any] = {
            "child_receipt": child,
            "child_receipt_sha256": (
                None if child is None else child["receipt_sha256"]
            ),
            "executor_population_zero_proven": bool(population_exact),
            "runtime_dependency_sha256": self._request["payload"][
                "runtime_dependency_binding"
            ]["runtime_dependency_sha256"],
        }
        receipt_type = (
            "COORDINATOR_WER_COMPLETED"
            if completed
            else "COORDINATOR_WER_DEBT"
        )
        if not completed:
            payload["reason_code"] = str(reason_code or "EXECUTOR_DEBT")
        return _build_terminal_receipt(
            receipt_type=receipt_type,
            request=self._request,
            executor_pid=self._process.pid,
            completion_authority=completed,
            payload=payload,
        )

    def _finalize_executor(self, *, force_terminate: bool) -> tuple[bytes, bytes, bool]:
        if self._finalized_streams is not None:
            return (
                self._finalized_streams[0],
                self._finalized_streams[1],
                self._population_exact is True,
            )
        population_exact = self._job.finalize(
            self._process,
            force_terminate=force_terminate,
            timeout=10.0,
        )
        try:
            stdout_raw = self._stdout_collector.finish(timeout=10.0)
            stderr_raw = self._stderr_collector.finish(timeout=10.0)
        except IsolatedExecutionProtocolError:
            stdout_raw = b""
            stderr_raw = b""
        global _ACTIVE_EXECUTOR_REQUEST_ID
        global _AMBIGUOUS_EXECUTOR_LATCH
        with _AMBIGUOUS_EXECUTOR_LOCK:
            if population_exact:
                if (
                    _ACTIVE_EXECUTOR_REQUEST_ID
                    == self._request["request_id"]
                ):
                    _ACTIVE_EXECUTOR_REQUEST_ID = None
            else:
                _AMBIGUOUS_EXECUTOR_LATCH = True
        self._finalized_streams = (stdout_raw, stderr_raw)
        self._population_exact = population_exact
        return stdout_raw, stderr_raw, population_exact

    def abort(
        self,
        *,
        reason_code: str = "EXECUTOR_BOUNDARY_INTERRUPTED",
    ) -> dict[str, Any]:
        """Synchronously reap this exact executor and return typed debt."""

        if self._terminal_receipt is not None:
            if self._terminal_receipt.get("completion_authority") is True:
                if (
                    self._request["handler_id"]
                    != HANDLER_RUN_WER_PROVIDER
                ):
                    raise IsolatedExecutionProtocolError(
                        "a completed executor cannot be aborted"
                    )
                receipt = self._coordinator_wer_receipt(
                    completed=False,
                    reason_code=reason_code,
                    child_receipt=None,
                    population_exact=(
                        self._population_exact is True
                    ),
                )
                self._terminal_receipt = receipt
                self._result = None
                return copy.deepcopy(receipt)
            return copy.deepcopy(self._terminal_receipt)
        _stdout, _stderr, exact = self._finalize_executor(
            force_terminate=True
        )
        reason = (
            reason_code
            if exact
            else "EXECUTOR_POPULATION_AMBIGUOUS"
        )
        receipt = (
            self._coordinator_wer_receipt(
                completed=False,
                reason_code=reason,
                child_receipt=None,
                population_exact=exact,
            )
            if self._request["handler_id"] == HANDLER_RUN_WER_PROVIDER
            else self._coordinator_debt(reason)
        )
        self._terminal_receipt = receipt
        self._waited = True
        return copy.deepcopy(receipt)

    def wait(
        self,
        *,
        coordinator_timeout: float | None = None,
        cancel_token: Any = None,
    ) -> Any:
        if self._waited:
            if self._result is not None:
                return self._result.value
            raise IsolatedExecutionHostError(
                "isolated execution attempt was already consumed",
                receipt=(
                    self._terminal_receipt
                    or (
                        self._coordinator_wer_receipt(
                            completed=False,
                            reason_code="ATTEMPT_ALREADY_CONSUMED",
                            child_receipt=None,
                            population_exact=False,
                        )
                        if self._request["handler_id"]
                        == HANDLER_RUN_WER_PROVIDER
                        else self._coordinator_debt(
                            "ATTEMPT_ALREADY_CONSUMED"
                        )
                    )
                ),
            )
        self._waited = True
        if coordinator_timeout is None:
            timeout_field = (
                "timeout_seconds"
                if self._request["handler_id"]
                == HANDLER_RUN_WER_PROVIDER
                else "timeout"
            )
            coordinator_timeout = (
                float(self._request["payload"][timeout_field])
                + DEFAULT_COORDINATOR_GRACE_SECONDS
            )
        if (
            isinstance(coordinator_timeout, bool)
            or not isinstance(coordinator_timeout, (int, float))
            or not math.isfinite(float(coordinator_timeout))
            or coordinator_timeout <= 0
        ):
            exact = self._finalize_executor(force_terminate=True)[2]
            receipt = (
                self._coordinator_wer_receipt(
                    completed=False,
                    reason_code="COORDINATOR_TIMEOUT_INVALID",
                    child_receipt=None,
                    population_exact=exact,
                )
                if self._request["handler_id"] == HANDLER_RUN_WER_PROVIDER
                else self._coordinator_debt("COORDINATOR_TIMEOUT_INVALID")
            )
            self._terminal_receipt = receipt
            raise IsolatedExecutionHostError(
                "coordinator timeout is invalid",
                receipt=receipt,
            )
        deadline = time.monotonic() + float(coordinator_timeout)
        try:
            while self._process.poll() is None:
                if _cancellation_requested(cancel_token):
                    _stdout, _stderr, exact = self._finalize_executor(
                        force_terminate=True
                    )
                    reason = (
                        "COORDINATOR_CANCELLED"
                        if exact
                        else "EXECUTOR_POPULATION_AMBIGUOUS"
                    )
                    receipt = (
                        self._coordinator_wer_receipt(
                            completed=False,
                            reason_code=reason,
                            child_receipt=None,
                            population_exact=exact,
                        )
                        if self._request["handler_id"]
                        == HANDLER_RUN_WER_PROVIDER
                        else self._coordinator_debt(reason)
                    )
                    self._terminal_receipt = receipt
                    raise IsolatedExecutionCancelled(
                        "isolated execution was cancelled",
                        receipt=receipt,
                    )
                if time.monotonic() >= deadline:
                    _stdout, _stderr, exact = self._finalize_executor(
                        force_terminate=True
                    )
                    reason = (
                        "COORDINATOR_TIMEOUT"
                        if exact
                        else "EXECUTOR_POPULATION_AMBIGUOUS"
                    )
                    receipt = (
                        self._coordinator_wer_receipt(
                            completed=False,
                            reason_code=reason,
                            child_receipt=None,
                            population_exact=exact,
                        )
                        if self._request["handler_id"]
                        == HANDLER_RUN_WER_PROVIDER
                        else self._coordinator_debt(reason)
                    )
                    self._terminal_receipt = receipt
                    raise IsolatedExecutionHostError(
                        "isolated executor exceeded its coordinator deadline",
                        receipt=receipt,
                    )
                time.sleep(0.01)
        except (IsolatedExecutionCancelled, IsolatedExecutionHostError):
            raise
        except BaseException as exc:
            try:
                _stdout, _stderr, exact = self._finalize_executor(
                    force_terminate=True
                )
            except BaseException:
                exact = False
                global _AMBIGUOUS_EXECUTOR_LATCH
                with _AMBIGUOUS_EXECUTOR_LOCK:
                    _AMBIGUOUS_EXECUTOR_LATCH = True
            reason = (
                "COORDINATOR_OBSERVATION_FAILED"
                if exact
                else "EXECUTOR_POPULATION_AMBIGUOUS"
            )
            receipt = (
                self._coordinator_wer_receipt(
                    completed=False,
                    reason_code=reason,
                    child_receipt=None,
                    population_exact=exact,
                )
                if self._request["handler_id"]
                == HANDLER_RUN_WER_PROVIDER
                else self._coordinator_debt(reason)
            )
            self._terminal_receipt = receipt
            raise IsolatedExecutionHostError(
                "isolated executor coordinator observation failed",
                receipt=receipt,
            ) from exc

        returncode = self._process.returncode
        stdout_raw, _stderr_raw, exact = self._finalize_executor(
            force_terminate=False
        )
        if not exact:
            receipt = (
                self._coordinator_wer_receipt(
                    completed=False,
                    reason_code="EXECUTOR_POPULATION_AMBIGUOUS",
                    child_receipt=None,
                    population_exact=False,
                )
                if self._request["handler_id"] == HANDLER_RUN_WER_PROVIDER
                else self._coordinator_debt(
                    "EXECUTOR_POPULATION_AMBIGUOUS"
                )
            )
            self._terminal_receipt = receipt
            raise IsolatedExecutionHostError(
                "isolated executor population could not be proven zero",
                receipt=receipt,
            )
        if returncode != 0:
            receipt = (
                self._coordinator_wer_receipt(
                    completed=False,
                    reason_code="EXECUTOR_DIED_WITHOUT_RECEIPT",
                    child_receipt=None,
                    population_exact=True,
                )
                if self._request["handler_id"] == HANDLER_RUN_WER_PROVIDER
                else self._coordinator_debt(
                    "EXECUTOR_DIED_WITHOUT_RECEIPT"
                )
            )
            self._terminal_receipt = receipt
            raise IsolatedExecutionHostError(
                "isolated executor died without terminal authority",
                receipt=receipt,
            )
        receipt_failure: BaseException | None = None
        receipt_failure_reason: str | None = None
        try:
            decoded = stdout_raw.decode("utf-8", errors="strict")
        except UnicodeError as exc:
            receipt_failure = exc
            receipt_failure_reason = "EXECUTOR_RECEIPT_UTF8_INVALID"
        if receipt_failure is None:
            try:
                candidate = _strict_json_loads(decoded)
            except (json.JSONDecodeError, ValueError, RecursionError) as exc:
                receipt_failure = exc
                receipt_failure_reason = "EXECUTOR_RECEIPT_JSON_INVALID"
        if receipt_failure is None:
            try:
                _validate_request(self._request)
            except IsolatedExecutionProtocolError as exc:
                receipt_failure = exc
                receipt_failure_reason = (
                    "EXECUTOR_RECEIPT_REQUEST_REPLAY_INVALID"
                )
        if receipt_failure is None:
            try:
                surface_reason = _receipt_surface_failure_reason(
                    candidate,
                    expected_request=self._request,
                    expected_executor_pid=self._process.pid,
                )
            except (
                IsolatedExecutionProtocolError,
                RecursionError,
                UnicodeError,
            ) as exc:
                receipt_failure = exc
                receipt_failure_reason = "EXECUTOR_RECEIPT_JSON_INVALID"
                surface_reason = None
            if surface_reason is not None:
                receipt_failure = IsolatedExecutionProtocolError(
                    "isolated executor receipt surface is invalid"
                )
                receipt_failure_reason = surface_reason
        if receipt_failure is None:
            try:
                receipt = _validate_terminal_receipt(
                    candidate,
                    expected_request=self._request,
                    expected_executor_pid=self._process.pid,
                )
            except IsolatedExecutionProtocolError as exc:
                receipt_failure = exc
                receipt_failure_reason = "EXECUTOR_RECEIPT_PAYLOAD_INVALID"
        if receipt_failure is not None:
            assert receipt_failure_reason is not None
            debt = (
                self._coordinator_wer_receipt(
                    completed=False,
                    reason_code=receipt_failure_reason,
                    child_receipt=None,
                    population_exact=True,
                )
                if self._request["handler_id"] == HANDLER_RUN_WER_PROVIDER
                else self._coordinator_debt(receipt_failure_reason)
            )
            self._terminal_receipt = debt
            raise IsolatedExecutionHostError(
                "isolated executor receipt is invalid",
                receipt=debt,
            ) from receipt_failure
        receipt_type = receipt["receipt_type"]
        payload = receipt["payload"]
        if self._request["handler_id"] == HANDLER_RUN_WER_PROVIDER:
            if receipt_type == "WER_COMPLETED":
                coordinator = self._coordinator_wer_receipt(
                    completed=True,
                    reason_code=None,
                    child_receipt=receipt,
                    population_exact=True,
                )
                coordinator = _validate_terminal_receipt(
                    coordinator,
                    expected_request=self._request,
                    expected_executor_pid=self._process.pid,
                )
                self._terminal_receipt = coordinator
                result = IsolatedWERCompleted(
                    coordinator_receipt=copy.deepcopy(coordinator),
                    child_receipt=copy.deepcopy(receipt),
                )
                self._result = _AttemptResult(result)
                return result
            reason = str(payload.get("reason_code") or "EXECUTOR_DEBT")
            coordinator = self._coordinator_wer_receipt(
                completed=False,
                reason_code=reason,
                child_receipt=receipt,
                population_exact=True,
            )
            coordinator = _validate_terminal_receipt(
                coordinator,
                expected_request=self._request,
                expected_executor_pid=self._process.pid,
            )
            self._terminal_receipt = coordinator
            raise IsolatedExecutionHostError(
                "isolated WER executor returned non-completion debt",
                receipt=coordinator,
            )
        self._terminal_receipt = receipt
        if receipt_type == "COMPLETED":
            from owned_process_runner import OwnedCompletedProcess

            result = OwnedCompletedProcess(
                args=tuple(payload["args"]),
                returncode=payload["returncode"],
                stdout=payload["stdout"],
                stderr=payload["stderr"],
                duration_s=float(payload["duration_s"]),
                process_tree_terminated=True,
                containment_capability=dict(payload["containment_capability"]),
            )
            self._result = _AttemptResult(result)
            return result
        if receipt_type == "TIMED_OUT":
            timeout_error = subprocess.TimeoutExpired(
                list(self._request["payload"]["command"]),
                payload["timeout"],
                output=payload["stdout"],
                stderr=payload["stderr"],
            )
            timeout_error.isolated_receipt = copy.deepcopy(receipt)
            raise timeout_error
        raise IsolatedExecutionHostError(
            "isolated executor returned non-completion debt",
            receipt=receipt,
        )


class IsolatedWERProviderLifecycle:
    """Context-owned WER executor whose exit always reaches terminal state."""

    def __init__(self, request: Mapping[str, Any]) -> None:
        validated = _validate_request(request)
        if validated["handler_id"] != HANDLER_RUN_WER_PROVIDER:
            raise IsolatedExecutionProtocolError(
                "WER lifecycle received another handler"
            )
        self._request = validated
        self._attempt: IsolatedExecutionAttempt | None = None
        self._terminal_receipt: dict[str, Any] | None = None

    def _bind_attempt(self, attempt: IsolatedExecutionAttempt) -> None:
        self._attempt = attempt

    def _launch_failed(self, receipt: Mapping[str, Any]) -> None:
        self._attempt = None
        self._terminal_receipt = copy.deepcopy(dict(receipt))

    @property
    def terminal_receipt(self) -> dict[str, Any] | None:
        if self._terminal_receipt is not None:
            return copy.deepcopy(self._terminal_receipt)
        if self._attempt is None:
            return None
        return self._attempt.terminal_receipt

    def __enter__(self) -> IsolatedExecutionAttempt:
        return _start_isolated_request(
            self._request,
            lifecycle=self,
        )

    def __exit__(
        self,
        exc_type: Any,
        exc: BaseException | None,
        traceback: Any,
    ) -> bool:
        del exc_type, traceback
        if self._attempt is not None and (
            exc is not None
            or self._attempt.terminal_receipt is None
        ):
            try:
                self._terminal_receipt = self._attempt.abort(
                    reason_code="EXECUTOR_BOUNDARY_INTERRUPTED"
                )
            except BaseException:
                global _AMBIGUOUS_EXECUTOR_LATCH
                with _AMBIGUOUS_EXECUTOR_LOCK:
                    _AMBIGUOUS_EXECUTOR_LATCH = True
                self._terminal_receipt = _unbound_wer_debt_receipt(
                    "EXECUTOR_POPULATION_AMBIGUOUS"
                )
        elif self._attempt is not None:
            self._terminal_receipt = self._attempt.terminal_receipt
        return False


def _start_isolated_request(
    request: Mapping[str, Any],
    *,
    lifecycle: IsolatedWERProviderLifecycle | None = None,
) -> IsolatedExecutionAttempt:
    global _ACTIVE_EXECUTOR_REQUEST_ID
    global _AMBIGUOUS_EXECUTOR_LATCH

    request = _validate_request(request)
    handler_id = str(request["handler_id"])
    with _AMBIGUOUS_EXECUTOR_LOCK:
        if _AMBIGUOUS_EXECUTOR_LATCH:
            raise IsolatedExecutionHostError(
                "a prior executor population remains ambiguous; coordinator "
                "restart is required",
                receipt=_unbound_debt_for_handler(
                    handler_id,
                    "EXECUTOR_RESTART_REQUIRED",
                ),
            )
        if _ACTIVE_EXECUTOR_REQUEST_ID is not None:
            raise IsolatedExecutionHostError(
                "the coordinator already owns a live isolated executor",
                receipt=_unbound_debt_for_handler(
                    handler_id,
                    "EXECUTOR_ATTEMPT_ALREADY_ACTIVE"
                ),
            )
        _ACTIVE_EXECUTOR_REQUEST_ID = request["request_id"]
    job: _WindowsExecutorJob | None = None
    process: subprocess.Popen[bytes] | None = None
    try:
        serialized = _canonical_bytes(request)
        logical_executable, physical_executable = (
            _windows_cpython_executor_paths()
        )
        _lock_windows_python_startup_closure(
            logical_executable,
            physical_executable,
        )
        argv = _executor_argv(
            handler_id,
            logical_executable=logical_executable,
            physical_executable=physical_executable,
        )
        job = _WindowsExecutorJob()
        process = subprocess.Popen(
            list(argv),
            cwd=str(Path(__file__).resolve().parent),
            env=_executor_environment(
                logical_executable=logical_executable,
            ),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            close_fds=True,
            creationflags=_CREATE_SUSPENDED | _CREATE_NEW_PROCESS_GROUP,
        )
        job.assign_and_resume(process)
        if (
            process.stdin is None
            or process.stdout is None
            or process.stderr is None
        ):
            raise RuntimeError("executor stdio handles are unavailable")
        stdout_collector = _PipeCollector(
            process.stdout,
            limit=MAX_RECEIPT_BYTES,
        )
        stderr_collector = _PipeCollector(
            process.stderr,
            limit=MAX_EXECUTOR_STDERR_BYTES,
        )
        process.stdin.write(serialized)
        process.stdin.close()
        attempt = IsolatedExecutionAttempt(
            request=request,
            process=process,
            job=job,
            stdout_collector=stdout_collector,
            stderr_collector=stderr_collector,
            executor_argv=argv,
        )
        if lifecycle is not None:
            lifecycle._bind_attempt(attempt)
        return attempt
    except BaseException as exc:
        exact = False
        if process is not None and job is not None:
            exact = job.finalize(
                process,
                force_terminate=True,
                timeout=10.0,
            )
        elif job is not None:
            try:
                job.close()
                exact = True
            except BaseException:
                exact = False
        else:
            # No executor Job or process was created.  This includes the
            # fail-closed non-Windows contract and is an exact empty
            # population, not ambiguous cleanup.
            exact = True
        with _AMBIGUOUS_EXECUTOR_LOCK:
            if exact:
                if _ACTIVE_EXECUTOR_REQUEST_ID == request["request_id"]:
                    _ACTIVE_EXECUTOR_REQUEST_ID = None
            else:
                _AMBIGUOUS_EXECUTOR_LATCH = True
        receipt = _unbound_debt_for_handler(
            handler_id,
            (
                "PLATFORM_UNSUPPORTED"
                if os.name != "nt"
                else "EXECUTOR_LAUNCH_FAILED"
            )
            if exact
            else "EXECUTOR_POPULATION_AMBIGUOUS",
        )
        if lifecycle is not None:
            lifecycle._launch_failed(receipt)
            if not isinstance(exc, Exception):
                raise
        raise IsolatedExecutionHostError(
            "isolated executor could not be launched",
            receipt=receipt,
        ) from exc


def start_isolated_owned_process(
    command: Sequence[str],
    *,
    cwd: str | Path | None = None,
    env: Mapping[str, str] | None = None,
    timeout: float,
    encoding: str = "utf-8",
    errors: str = "replace",
    output_limit_bytes: int = 8 * 1024 * 1024,
    writable_roots: Sequence[str | Path] = (),
) -> IsolatedExecutionAttempt:
    request = _build_request(
        command=command,
        cwd=cwd,
        env=env,
        timeout=timeout,
        encoding=encoding,
        errors=errors,
        output_limit_bytes=output_limit_bytes,
        writable_roots=writable_roots,
    )
    return _start_isolated_request(request)


def start_isolated_wer_provider(
    payload_core: Mapping[str, Any],
    *,
    outer_arm_sha256: str,
) -> IsolatedExecutionAttempt:
    """Start one semantic WER attempt inside a disposable executor Job."""

    request = _build_wer_provider_request(
        payload_core,
        outer_arm_sha256=outer_arm_sha256,
    )
    return _start_isolated_request(request)


def isolated_wer_provider_lifecycle(
    payload_core: Mapping[str, Any],
    *,
    outer_arm_sha256: str,
) -> IsolatedWERProviderLifecycle:
    """Return a no-launch context that owns one exact WER executor lifetime."""

    request = _build_wer_provider_request(
        payload_core,
        outer_arm_sha256=outer_arm_sha256,
    )
    return IsolatedWERProviderLifecycle(request)


def run_isolated_owned_process(
    command: Sequence[str],
    *,
    cwd: str | Path | None = None,
    env: Mapping[str, str] | None = None,
    timeout: float,
    encoding: str = "utf-8",
    errors: str = "replace",
    output_limit_bytes: int = 8 * 1024 * 1024,
    writable_roots: Sequence[str | Path] = (),
    coordinator_timeout: float | None = None,
    cancel_token: Any = None,
) -> Any:
    attempt = start_isolated_owned_process(
        command,
        cwd=cwd,
        env=env,
        timeout=timeout,
        encoding=encoding,
        errors=errors,
        output_limit_bytes=output_limit_bytes,
        writable_roots=writable_roots,
    )
    return attempt.wait(
        coordinator_timeout=coordinator_timeout,
        cancel_token=cancel_token,
    )


def _text(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return ""


def _relative_to_scratchpad(root: Path, value: Path | None) -> str | None:
    if value is None:
        return None
    resolved = value.resolve(strict=True)
    try:
        return resolved.relative_to(root).as_posix()
    except ValueError as exc:
        raise IsolatedExecutionProtocolError(
            "isolated WER artifact escaped the scratchpad"
        ) from exc


def _artifact_digest(
    path: Path | None,
    *,
    field: str,
) -> str | None:
    if path is None:
        return None
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, Mapping):
        raise IsolatedExecutionProtocolError(
            "isolated WER artifact is not an object"
        )
    return _require_hex64(
        value.get(field),
        f"isolated WER {field}",
    )


def _resolve_parser_callback(
    binding: Mapping[str, Any],
) -> Any:
    import ast
    import types
    import worker_execution_receipts as W

    replayed = W._replay_callable_binding(
        binding,
        label="isolated executor parser",
    )
    module_name, qualname = replayed["identity"].split(":", 1)
    if "<locals>" in qualname.split("."):
        raise IsolatedExecutionProtocolError(
            "isolated WER parser cannot be a local callable"
        )
    source = Path(replayed["source_file"])
    try:
        tree = ast.parse(
            source.read_text(encoding="utf-8"),
            filename=str(source),
        )
    except (OSError, UnicodeError, SyntaxError) as exc:
        raise IsolatedExecutionProtocolError(
            "isolated WER parser source cannot be sliced"
        ) from exc
    top_level: dict[str, ast.stmt] = {}
    future_nodes: list[ast.stmt] = []
    for node in tree.body:
        if (
            isinstance(node, ast.ImportFrom)
            and node.module == "__future__"
        ):
            future_nodes.append(node)
        if isinstance(
            node,
            (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef),
        ):
            top_level[node.name] = node
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            names = (
                [
                    alias.asname or alias.name.split(".", 1)[0]
                    for alias in node.names
                ]
                if isinstance(node, ast.Import)
                else [
                    alias.asname or alias.name
                    for alias in node.names
                    if alias.name != "*"
                ]
            )
            for name in names:
                top_level[name] = node
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = (
                node.targets
                if isinstance(node, ast.Assign)
                else [node.target]
            )
            for target in targets:
                for child in ast.walk(target):
                    if isinstance(child, ast.Name):
                        top_level[child.id] = node
    root_name = qualname.split(".", 1)[0]
    root_node = top_level.get(root_name)
    if not isinstance(
        root_node,
        (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef),
    ):
        raise IsolatedExecutionProtocolError(
            "isolated WER parser identity is absent from bound source"
        )
    selected_ids: set[int] = set()
    selected: list[ast.stmt] = []
    pending = [root_node]
    while pending:
        node = pending.pop()
        if id(node) in selected_ids:
            continue
        selected_ids.add(id(node))
        selected.append(node)
        referenced = {
            child.id
            for child in ast.walk(node)
            if isinstance(child, ast.Name)
            and isinstance(child.ctx, ast.Load)
        }
        for name in sorted(referenced):
            dependency = top_level.get(name)
            if dependency is not None and id(dependency) not in selected_ids:
                pending.append(dependency)
    selected_set = {id(node) for node in selected}
    sliced = ast.Module(
        body=[
            *future_nodes,
            *(
                node
                for node in tree.body
                if id(node) in selected_set
                and node not in future_nodes
            ),
        ],
        type_ignores=[],
    )
    ast.fix_missing_locations(sliced)
    module = types.ModuleType(module_name)
    module.__file__ = str(source)
    module.__package__ = module_name.rpartition(".")[0]
    prior_module = sys.modules.get(module_name)
    sys.modules[module_name] = module
    try:
        exec(
            compile(sliced, str(source), "exec"),
            module.__dict__,
        )
    except BaseException:
        if prior_module is None:
            sys.modules.pop(module_name, None)
        else:
            sys.modules[module_name] = prior_module
        raise
    callback: Any = module
    for component in qualname.split("."):
        if component == "<locals>" or not component:
            raise IsolatedExecutionProtocolError(
                "isolated WER parser identity is invalid"
            )
        callback = getattr(callback, component)
    if W._callable_binding(
        callback,
        label="isolated executor parser",
    ) != replayed:
        raise IsolatedExecutionProtocolError(
            "isolated WER parser source binding changed"
        )
    return callback


def _replay_semantic_wer_authority(
    value: Mapping[str, Any],
) -> tuple[Any, Any]:
    from semantic_prompt_snapshot import (
        SemanticPlanPromptBundle,
        SemanticPromptSnapshot,
    )
    from semantic_work_plan import (
        BackendArmExecutionIdentity,
        ExecutionAttemptIdentity,
        SemanticAttemptBundle,
        SemanticExecutionBundle,
        SemanticWorkPlan,
    )

    plan = SemanticWorkPlan.from_dict(value["plan"])
    execution = BackendArmExecutionIdentity.from_dict(value["execution"])
    attempt = ExecutionAttemptIdentity.from_dict(value["attempt"])
    attempt_bundle = SemanticAttemptBundle(
        SemanticExecutionBundle(plan=plan, execution=execution),
        attempt,
    )
    snapshot = SemanticPromptSnapshot.from_dict(value["snapshot"])
    prompt_bundle = SemanticPlanPromptBundle(
        plan=plan,
        snapshot=snapshot,
    )
    return attempt_bundle, prompt_bundle


def _wer_child_debt(
    *,
    request: Mapping[str, Any],
    reason_code: str,
    arm_path: Path | None = None,
    debt_path: Path | None = None,
    scratchpad: Path | None = None,
) -> dict[str, Any]:
    payload = request["payload"]
    root = scratchpad
    return _build_terminal_receipt(
        receipt_type="WER_DEBT",
        request=request,
        executor_pid=os.getpid(),
        completion_authority=False,
        payload={
            "reason_code": reason_code,
            "inner_arm_relative_path": (
                None
                if root is None
                else _relative_to_scratchpad(root, arm_path)
            ),
            "inner_debt_relative_path": (
                None
                if root is None
                else _relative_to_scratchpad(root, debt_path)
            ),
            "inner_arm_sha256": _artifact_digest(
                arm_path,
                field="arm_sha256",
            ),
            "inner_debt_sha256": _artifact_digest(
                debt_path,
                field="debt_sha256",
            ),
            "semantic_authority_sha256": payload["semantic_authority"][
                "semantic_authority_sha256"
            ],
            "request_core_sha256": payload["request_core_sha256"],
            "outer_arm_sha256": payload["outer_arm_sha256"],
            "implementation_files_sha256": (
                _wer_implementation_files_sha256(payload)
            ),
            "runtime_dependency_sha256": payload[
                "runtime_dependency_binding"
            ]["runtime_dependency_sha256"],
        },
    )


def _stage_wer_runtime_dependency_closure(
    request: Mapping[str, Any],
) -> dict[str, Any]:
    """Seal request-bound import bytes and relocate them into one CAS root."""

    payload = request["payload"]
    runtime_binding = payload["runtime_dependency_binding"]
    scratchpad = Path(payload["scratchpad"]).resolve(strict=True)
    stage_parent = scratchpad / ".worker_execution_receipts"
    stage_parent.mkdir(mode=0o700, exist_ok=True)
    stage = _create_immutable_dependency_stage(stage_parent)
    source_records: dict[str, dict[str, Any]] = {}
    for row in payload["implementation_files"]:
        key = os.path.normcase(row["path"])
        if key in source_records and source_records[key] != row:
            stage.close()
            raise IsolatedExecutionProtocolError(
                "isolated WER implementation source records conflict"
            )
        source_records[key] = dict(row)

    executable = os.path.normcase(runtime_binding["python"]["executable"])
    external_roots = tuple(
        Path(item).resolve(strict=True)
        for item in runtime_binding["import_roots"]
    )
    local_root = _MODULE_ROOT.resolve(strict=True)
    parser_source = Path(
        payload["parser_binding"]["source_file"]
    ).resolve(strict=True)
    path_map: dict[str, Path] = {}

    def relative_for(source: Path, record: Mapping[str, Any]) -> Path:
        for root in external_roots:
            if source == root or root in source.parents:
                return source.relative_to(root)
        if source == local_root or local_root in source.parents:
            return source.relative_to(local_root)
        if source == parser_source:
            module_name = payload["parser_binding"]["identity"].split(
                ":",
                1,
            )[0]
            parts = module_name.split(".")
            if (
                not parts
                or any(not part.isidentifier() for part in parts)
            ):
                raise IsolatedExecutionProtocolError(
                    "isolated WER staged parser module name is invalid"
                )
            if source.name == "__init__.py":
                return Path(*parts, "__init__.py")
            return Path(*parts).with_suffix(source.suffix)
        return Path(
            ".opaque",
            str(record["sha256"]),
            source.name,
        )

    try:
        for key in sorted(source_records):
            if key == executable:
                continue
            record = source_records[key]
            source = Path(record["path"]).resolve(strict=True)
            relative = relative_for(source, record)
            destination_key = os.path.normcase(
                str(stage.root.joinpath(*relative.parts))
            )
            prior = next(
                (
                    value
                    for value in path_map.values()
                    if os.path.normcase(str(value)) == destination_key
                ),
                None,
            )
            if prior is not None:
                raise IsolatedExecutionProtocolError(
                    "isolated WER staged dependency destinations collide"
                )
            path_map[key] = stage.copy_verified(
                record,
                relative=relative,
            )

        def mapped_file(value: str) -> str:
            key = os.path.normcase(value)
            mapped = path_map.get(key)
            if mapped is None:
                raise IsolatedExecutionProtocolError(
                    "isolated WER staged dependency file is absent"
                )
            return str(mapped)

        def mapped_directory(value: str) -> str:
            source = Path(value).resolve(strict=True)
            for root in external_roots:
                if source == root:
                    return str(stage.root)
                if root in source.parents:
                    return str(
                        stage.ensure_directory(source.relative_to(root))
                    )
            if source == local_root:
                return str(stage.root)
            if local_root in source.parents:
                return str(
                    stage.ensure_directory(source.relative_to(local_root))
                )
            raise IsolatedExecutionProtocolError(
                "isolated WER staged dependency directory is ungoverned"
            )

        staged_binding = copy.deepcopy(dict(runtime_binding))
        extension_origins: dict[str, str] = {}
        for row in staged_binding["modules"]:
            if row["path"] is not None:
                if row["kind"] == "EXTENSION_BINARY":
                    extension_origins[row["module_name"]] = row["path"]
                else:
                    row["path"] = mapped_file(row["path"])
            row["search_locations"] = [
                mapped_directory(item)
                for item in row["search_locations"]
            ]
        for row in staged_binding["distributions"]:
            row["import_root"] = str(stage.root)
            for identity in row["identity_files"]:
                identity["path"] = mapped_file(identity["path"])
        staged_binding["import_roots"] = [str(stage.root)]
        staged_binding["runtime_dependency_sha256"] = _sha(
            {
                key: copy.deepcopy(value)
                for key, value in staged_binding.items()
                if key != "runtime_dependency_sha256"
            }
        )
        staged_parser = copy.deepcopy(dict(payload["parser_binding"]))
        staged_parser["source_file"] = mapped_file(
            staged_parser["source_file"]
        )
        stage.verify_all()
        return {
            "stage": stage,
            "runtime_binding": staged_binding,
            "parser_binding": staged_parser,
            "extension_origins": extension_origins,
            "path_map": {
                key: str(value) for key, value in path_map.items()
            },
        }
    except BaseException:
        stage.close()
        raise


def _execute_wer_provider_from_staged(
    request: Mapping[str, Any],
    staged: Mapping[str, Any],
) -> dict[str, Any]:
    runtime_binding = staged["runtime_binding"]
    stage = staged["stage"]
    original_roots = {
        os.path.normcase(item)
        for item in request["payload"]["runtime_dependency_binding"][
            "import_roots"
        ]
    }
    original_roots.add(os.path.normcase(str(_MODULE_ROOT)))
    sys.path[:] = [
        str(stage.root),
        *(
            item
            for item in sys.path
            if os.path.normcase(item) not in original_roots
            and os.path.normcase(item)
            != os.path.normcase(str(stage.root))
        ),
    ]
    import importlib
    importlib.invalidate_caches()

    external_prefixes = (
        "attr",
        "attrs",
        "jsonschema",
        "jsonschema_specifications",
        "referencing",
        "rpds",
        "typing_extensions",
    )
    for row in runtime_binding["modules"]:
        module_name = row["module_name"]
        if any(
            module_name == prefix
            or module_name.startswith(prefix + ".")
            for prefix in external_prefixes
        ):
            imported = importlib.import_module(module_name)
            imported_file = getattr(imported, "__file__", None)
            if (
                row["path"] is not None
                and (
                    not isinstance(imported_file, str)
                    or str(Path(imported_file).resolve(strict=True))
                    != row["path"]
                )
            ):
                raise IsolatedExecutionProtocolError(
                    "isolated WER dependency module resolved elsewhere"
                )
    import worker_execution_receipts as W

    # No original dependency path is imported after child_main validation.
    # Python sources and extension binaries resolve only from the handle-sealed
    # stage; both original and staged file identities remain write/delete
    # locked until this function returns.
    payload = request["payload"]
    root = Path(payload["scratchpad"]).resolve(strict=True)
    attempt_bundle, prompt_bundle = _replay_semantic_wer_authority(
        payload["semantic_authority"]
    )
    # The semantic public types were imported during replay; bind their loaded
    # implementation to the coordinator-authorized bytes as well.
    replayed_runtime, _runtime_paths = (
        W._semantic_runtime_dependency_binding(
            _authorized_import_roots=(stage.root,),
        )
    )
    if replayed_runtime != runtime_binding:
        raise IsolatedExecutionProtocolError(
            "isolated WER loaded runtime dependency closure changed"
        )
    stage.verify_all()
    staged_worker_path = str(Path(W.__file__).resolve(strict=True))
    canonical_worker_sources = [
        row["path"]
        for row in payload["implementation_files"]
        if os.path.normcase(
            staged["path_map"].get(os.path.normcase(row["path"]), "")
        )
        == os.path.normcase(staged_worker_path)
    ]
    if len(canonical_worker_sources) != 1:
        raise IsolatedExecutionProtocolError(
            "isolated WER staged launcher identity is ambiguous"
        )
    # The provider code executes from the sealed CAS copy, but durable WER
    # receipts must retain the coordinator-bound canonical source identity so
    # the parent can replay them.  Rebinding module metadata does not import or
    # execute the original path; that exact source remains handle-sealed until
    # the child completion has been validated below.
    W.__file__ = canonical_worker_sources[0]
    plan = attempt_bundle.execution_bundle.plan
    execution = attempt_bundle.execution_bundle.execution
    attempt = attempt_bundle.attempt
    if (
        execution.backend != "native"
        or payload["bindings"]["effective_backend"] != "native"
        or payload["bindings"]["effective_model"] != execution.exact_model_id
        or payload["bindings"]["run_id"] != plan.run_id
        or payload["bindings"]["worker"]["invocation_id"]
        != attempt.attempt_key
        or prompt_bundle.plan.semantic_digest != plan.semantic_digest
    ):
        raise IsolatedExecutionProtocolError(
            "isolated WER semantic execution binding is invalid"
        )

    binding = payload["bindings"]
    inputs = binding["inputs"]
    wer_bindings = W.ExecutionBindings(
        run_id=binding["run_id"],
        shard_id=binding["shard_id"],
        plan=W.BoundInput(inputs["plan"]["relative_path"]),
        manifest=W.BoundInput(inputs["manifest"]["relative_path"]),
        intent=W.BoundInput(inputs["intent"]["relative_path"]),
        context=W.BoundInput(inputs["context"]["relative_path"]),
        prompt=W.BoundInput(inputs["prompt"]["relative_path"]),
        tool_policy=W.BoundInput(
            inputs["tool_policy"]["relative_path"]
        ),
        worker=W.PrincipalInvocation(
            binding["worker"]["identity"],
            binding["worker"]["invocation_id"],
        ),
        assessors=tuple(
            W.PrincipalInvocation(
                row["identity"],
                row["invocation_id"],
            )
            for row in binding["assessors"]
        ),
        effective_backend=binding["effective_backend"],
        effective_model=binding["effective_model"],
    )
    # Re-measure every input in the executor before the provider can arm.
    if wer_bindings.as_dict(root) != binding:
        raise IsolatedExecutionProtocolError(
            "isolated WER input binding changed before launch"
        )
    prompt_raw = (
        root / inputs["prompt"]["relative_path"]
    ).read_bytes()
    if prompt_raw != prompt_bundle.snapshot.prompt_bytes:
        raise IsolatedExecutionProtocolError(
            "isolated WER prompt bytes differ from semantic snapshot"
        )

    parser = _resolve_parser_callback(staged["parser_binding"])
    canonical_parser_binding = payload["parser_binding"]
    staged_parser_source = staged["parser_binding"]["source_file"]
    canonical_parser_source = canonical_parser_binding["source_file"]
    if (
        os.path.normcase(
            staged["path_map"].get(
                os.path.normcase(canonical_parser_source),
                "",
            )
        )
        != os.path.normcase(staged_parser_source)
        or staged["parser_binding"]["identity"]
        != canonical_parser_binding["identity"]
        or staged["parser_binding"]["source_sha256"]
        != canonical_parser_binding["source_sha256"]
    ):
        raise IsolatedExecutionProtocolError(
            "isolated WER staged parser identity is ambiguous"
        )
    parser_module = sys.modules.get(getattr(parser, "__module__", ""))
    if parser_module is None:
        raise IsolatedExecutionProtocolError(
            "isolated WER staged parser module disappeared"
        )
    parser_module.__file__ = canonical_parser_source
    parser_code = getattr(parser, "__code__", None)
    if parser_code is not None:
        try:
            parser.__code__ = parser_code.replace(
                co_filename=canonical_parser_source
            )
        except (AttributeError, TypeError, ValueError) as exc:
            raise IsolatedExecutionProtocolError(
                "isolated WER parser cannot bind canonical source identity"
            ) from exc
    if W._callable_binding(
        parser,
        label="isolated executor canonical parser",
    ) != canonical_parser_binding:
        raise IsolatedExecutionProtocolError(
            "isolated WER parser canonical source binding changed"
        )
    outputs = tuple(
        W.ExpectedOutput(
            row["assignment_id"],
            row["relative_path"],
            row["publish_relative_path"],
            is_transcript=row["is_transcript"],
        )
        for row in payload["expected_outputs"]
    )
    nested_parent = W._make_nested_executor_authority(
        executor_request_sha256=request["request_sha256"],
        request_core_sha256=payload["request_core_sha256"],
        outer_arm_sha256=payload["outer_arm_sha256"],
        executor_pid=os.getpid(),
        semantic_authority_sha256=payload["semantic_authority"][
            "semantic_authority_sha256"
        ],
    )
    try:
        completed = W._run_observed_worker_direct(
            scratchpad=root,
            bindings=wer_bindings,
            argv=tuple(payload["argv"]),
            cwd=payload["cwd"],
            output_scope_relative=payload["output_scope_relative"],
            expected_outputs=outputs,
            parser_digest=parser,
            environment=dict(payload["environment"]),
            environment_allowlist=tuple(
                payload["environment_allowlist"]
            ),
            stdin_input=W.BoundInput(
                payload["stdin_input_relative_path"]
            ),
            timeout_seconds=float(payload["timeout_seconds"]),
            lock_timeout_seconds=float(
                payload["lock_timeout_seconds"]
            ),
            output_source_mode=payload["output_source_mode"],
            stdout_limit_bytes=payload["stdout_limit_bytes"],
            stderr_limit_bytes=payload["stderr_limit_bytes"],
            staged_output_limit_bytes=payload[
                "staged_output_limit_bytes"
            ],
            publish_canonical=payload["publish_canonical"],
            process_scope_identity=payload["process_scope_identity"],
            implementation_files=tuple(
                row["path"]
                for row in payload["implementation_files"]
            ),
            _nested_executor_authority=nested_parent,
        )
    except W.WorkerExecutionIncomplete as exc:
        return _wer_child_debt(
            request=request,
            reason_code="INNER_WER_INCOMPLETE",
            arm_path=exc.arm_path,
            debt_path=exc.debt_path,
            scratchpad=root,
        )
    except BaseException:
        return _wer_child_debt(
            request=request,
            reason_code="INNER_WER_REPLAY_FAILED",
            scratchpad=root,
        )

    if payload["publish_canonical"]:
        completion = W.validate_completed_execution(
            scratchpad=root,
            receipt_path=completed.receipt_path,
            publish_receipt_path=completed.publish_receipt_path,
            parser_digest=parser,
            expected_completion_sha256=completed.completion_sha256,
            expected_publish_sha256=completed.publish_sha256,
        )
    else:
        completion = W.validate_staged_execution(
            scratchpad=root,
            receipt_path=completed.receipt_path,
            parser_digest=parser,
            expected_completion_sha256=completed.completion_sha256,
        )
    process_observation = completion.get("process_observation")
    if (
        not isinstance(process_observation, Mapping)
        or process_observation.get(
            "process_population_zero_proven"
        )
        is not True
    ):
        return _wer_child_debt(
            request=request,
            reason_code="INNER_PROCESS_SCOPE_NOT_EMPTY",
            arm_path=completed.arm_path,
            scratchpad=root,
        )
    stage.verify_all()
    return _build_terminal_receipt(
        receipt_type="WER_COMPLETED",
        request=request,
        executor_pid=os.getpid(),
        completion_authority=True,
        payload={
            "inner_receipt_relative_path": _relative_to_scratchpad(
                root,
                completed.receipt_path,
            ),
            "inner_completion_sha256": completed.completion_sha256,
            "inner_arm_relative_path": _relative_to_scratchpad(
                root,
                completed.arm_path,
            ),
            "inner_arm_sha256": completed.arm_sha256,
            "publish_receipt_relative_path": _relative_to_scratchpad(
                root,
                completed.publish_receipt_path,
            ),
            "publish_sha256": completed.publish_sha256,
            "published_paths": [
                _relative_to_scratchpad(root, item)
                for item in completed.published_paths
            ],
            "stdout_blob": copy.deepcopy(completion["stdout_blob"]),
            "stderr_blob": copy.deepcopy(completion["stderr_blob"]),
            "returncode": completion["process_observation"]["returncode"],
            "inner_process_scope_identity": payload[
                "process_scope_identity"
            ],
            "inner_process_population_zero_proven": True,
            "process_observation_sha256": _sha(
                {
                    "process_observation": copy.deepcopy(
                        dict(process_observation)
                    )
                }
            ),
            "semantic_authority_sha256": payload["semantic_authority"][
                "semantic_authority_sha256"
            ],
            "request_core_sha256": payload["request_core_sha256"],
            "outer_arm_sha256": payload["outer_arm_sha256"],
            "implementation_files_sha256": (
                _wer_implementation_files_sha256(payload)
            ),
            "runtime_dependency_sha256": payload[
                "runtime_dependency_binding"
            ]["runtime_dependency_sha256"],
        },
    )


def _execute_wer_provider(
    request: Mapping[str, Any],
) -> dict[str, Any]:
    staged: dict[str, Any] | None = None
    extension_finder: _SealedExtensionFinder | None = None
    try:
        staged = _stage_wer_runtime_dependency_closure(request)
        extension_finder = _SealedExtensionFinder(
            staged["extension_origins"]
        )
        sys.meta_path.insert(0, extension_finder)
        return _execute_wer_provider_from_staged(request, staged)
    finally:
        if extension_finder is not None:
            try:
                sys.meta_path.remove(extension_finder)
            except ValueError:
                pass
        if staged is not None:
            stage = staged.get("stage")
            if isinstance(stage, _WindowsImmutableDependencyStage):
                stage.close()


def _execute_owned_process(
    request: Mapping[str, Any],
) -> dict[str, Any]:
    from owned_process_runner import (
        OwnedProcessRunnerError,
        run_owned_process,
    )

    payload = request["payload"]
    try:
        result = run_owned_process(
            payload["command"],
            cwd=payload["cwd"],
            env=payload["env"],
            timeout=payload["timeout"],
            encoding=payload["encoding"],
            errors=payload["errors"],
            output_limit_bytes=payload["output_limit_bytes"],
            writable_roots=payload["writable_roots"],
            executable_guard=payload["executable_guard"],
        )
    except subprocess.TimeoutExpired as exc:
        return _build_terminal_receipt(
            receipt_type="TIMED_OUT",
            request=request,
            executor_pid=os.getpid(),
            completion_authority=False,
            payload={
                "timeout": float(exc.timeout),
                "stdout": _text(exc.output),
                "stderr": _text(exc.stderr),
            },
        )
    except OwnedProcessRunnerError as exc:
        # Preserve a closed-schema containment failure class without exposing
        # arbitrary exception text, paths, or environment material in the
        # signed executor receipt.  The coordinator can then report the real
        # infrastructure debt instead of blaming the scanner binary.
        reason_code = "OWNED_PROCESS_EXECUTION_FAILED"
        cursor: BaseException | None = exc
        seen: set[int] = set()
        while cursor is not None and id(cursor) not in seen:
            seen.add(id(cursor))
            name = type(cursor).__name__
            if name == "WindowsLowIntegrityLeaseError":
                reason_code = "WINDOWS_LOW_INTEGRITY_LEASE_FAILED"
                break
            if name == "OwnedProcessScopeError":
                reason_code = "OWNED_PROCESS_SCOPE_FAILED"
            cursor = cursor.__cause__ or cursor.__context__
        return _build_terminal_receipt(
            receipt_type="DEBT",
            request=request,
            executor_pid=os.getpid(),
            completion_authority=False,
            payload={"reason_code": reason_code},
        )
    except BaseException:
        return _build_terminal_receipt(
            receipt_type="DEBT",
            request=request,
            executor_pid=os.getpid(),
            completion_authority=False,
            payload={"reason_code": "EXECUTOR_HANDLER_FAILED"},
        )
    if result.process_tree_terminated is not True:
        return _build_terminal_receipt(
            receipt_type="DEBT",
            request=request,
            executor_pid=os.getpid(),
            completion_authority=False,
            payload={"reason_code": "PROCESS_TREE_TERMINATION_UNPROVEN"},
        )
    return _build_terminal_receipt(
        receipt_type="COMPLETED",
        request=request,
        executor_pid=os.getpid(),
        completion_authority=True,
        payload={
            "args": list(result.args),
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "duration_s": result.duration_s,
            "process_tree_terminated": True,
            "containment_capability": dict(result.containment_capability),
        },
    )


def _execute_registered_request(request: Mapping[str, Any]) -> dict[str, Any]:
    if request["handler_id"] == HANDLER_RUN_OWNED_PROCESS:
        return _execute_owned_process(request)
    if request["handler_id"] == HANDLER_RUN_WER_PROVIDER:
        return _execute_wer_provider(request)
    raise IsolatedExecutionProtocolError(
        "isolated execution handler is not registered"
    )


def _child_main(
    *,
    logical_executable: str,
    physical_executable: str,
) -> int:
    try:
        observed_logical, observed_physical = (
            _windows_cpython_executor_paths()
        )
        expected_logical = Path(logical_executable).resolve(strict=True)
        expected_physical = Path(physical_executable).resolve(strict=True)
    except BaseException:
        return 69
    if (
        observed_logical != expected_logical
        or observed_physical != expected_physical
        or Path(sys.executable) != expected_logical
    ):
        return 69
    raw = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
    if not raw or len(raw) > MAX_REQUEST_BYTES:
        return 64
    try:
        decoded = raw.decode("utf-8", errors="strict")
        candidate = _strict_json_loads(decoded)
        request = _validate_request(candidate)
    except BaseException:
        return 66
    try:
        receipt = _execute_registered_request(request)
    except SemanticDependencyIsolationUnavailable as exc:
        receipt = (
            _wer_child_debt(
                request=request,
                reason_code=exc.reason_code,
            )
            if request["handler_id"] == HANDLER_RUN_WER_PROVIDER
            else _build_terminal_receipt(
                receipt_type="DEBT",
                request=request,
                executor_pid=os.getpid(),
                completion_authority=False,
                payload={"reason_code": exc.reason_code},
            )
        )
    except BaseException:
        receipt = (
            _wer_child_debt(
                request=request,
                reason_code="EXECUTOR_HANDLER_FAILED",
            )
            if request["handler_id"] == HANDLER_RUN_WER_PROVIDER
            else _build_terminal_receipt(
                receipt_type="DEBT",
                request=request,
                executor_pid=os.getpid(),
                completion_authority=False,
                payload={"reason_code": "EXECUTOR_HANDLER_FAILED"},
            )
        )
    try:
        serialized = _canonical_bytes(receipt)
        if len(serialized) > MAX_RECEIPT_BYTES:
            receipt = (
                _wer_child_debt(
                    request=request,
                    reason_code="TERMINAL_RECEIPT_EXCEEDS_BOUND",
                )
                if request["handler_id"] == HANDLER_RUN_WER_PROVIDER
                else _build_terminal_receipt(
                    receipt_type="DEBT",
                    request=request,
                    executor_pid=os.getpid(),
                    completion_authority=False,
                    payload={
                        "reason_code": "TERMINAL_RECEIPT_EXCEEDS_BOUND"
                    },
                )
            )
            serialized = _canonical_bytes(receipt)
    except BaseException:
        return 67
    try:
        sys.stdout.buffer.write(serialized)
        sys.stdout.buffer.flush()
        return 0
    except BaseException:
        # Never echo request bytes, environment values, argv, or exception text.
        return 68


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if (
        len(arguments) != 5
        or arguments[0] != "--child"
        or arguments[1] != "--logical-executable"
        or not arguments[2]
        or arguments[3] != "--physical-executable"
        or not arguments[4]
    ):
        return 64
    return _child_main(
        logical_executable=arguments[2],
        physical_executable=arguments[4],
    )


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "HANDLER_RUN_OWNED_PROCESS",
    "HANDLER_RUN_WER_PROVIDER",
    "REGISTERED_HANDLER_IDS",
    "IsolatedExecutionAttempt",
    "IsolatedExecutionCancelled",
    "IsolatedExecutionHostError",
    "IsolatedExecutionProtocolError",
    "IsolatedWERCompleted",
    "IsolatedWERProviderLifecycle",
    "SemanticDependencyIsolationUnavailable",
    "isolated_wer_provider_lifecycle",
    "run_isolated_owned_process",
    "sanitize_wer_failure_receipt",
    "start_isolated_owned_process",
    "start_isolated_wer_provider",
    "untrusted_wer_failure_receipt",
    "wer_provider_request_core_sha256",
]
