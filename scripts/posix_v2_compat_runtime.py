"""Explicit V2-compatible model execution lane for macOS and Linux.

This module deliberately does *not* mint WER or native-broker receipts.  It
owns a reduced-assurance raw provider subprocess lifecycle so the V3 driver can
temporarily retain the cross-platform V2 execution behavior while broker-v2 is
finished.  The durable receipt says exactly what is missing: a process group
is observed and terminated, but descendants may escape with ``setsid(2)`` and
population zero is therefore never claimed.

Activation requires an exact process-local session authority.  No environment
variable, serialized config value, marker file, or CLI string can substitute
for that object.  The installed front/driver must explicitly create, retain,
and thread it in the same interpreter process.
"""

from __future__ import annotations

import os

if os.name == "nt":
    raise ImportError("posix_v2_compat_runtime is unavailable on Windows")
else:
    import fcntl
    import pwd

import contextlib
from dataclasses import dataclass, field
import errno
import hashlib
import inspect
import json
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import sys
import threading
import time
from types import MappingProxyType
from typing import Any, Callable, Mapping, NoReturn, Sequence
import uuid
import weakref

from artifact_ledger import read_artifact_ledger, validate_work_unit_inputs
from codex_dependency_research import parse_codex_research_event_stream
from phase_io_contracts import (
    LaunchSpec,
    PhaseIOContract,
    replay_phase_io_authority_pair,
)
from provider_semantic_completion import (
    build_provider_nonzero_semantic_completion,
    provider_transport_completion_is_admitted,
)


COMPATIBILITY_MODE = "V2_COMPATIBILITY_REDUCED_ISOLATION"
SESSION_SCHEMA = "plamen.posix_v2_compat_session.v1"
DERIVED_STAGING_SESSION_SCHEMA = (
    "plamen.posix_v2_compat_derived_staging_session.v1"
)
DERIVED_STAGING_PURPOSE = "AXIS_DISPOSABLE_STAGING"
RECEIPT_SCHEMA = "plamen.posix_v2_compat_execution_receipt.v1"
COMPAT_EXIT_ERROR = 2
COMPAT_TIMEOUT = -2
COMPAT_POLICY_REFUSAL = -5
CODEX_LIVE_WEB_JSONL_PROFILE = "CODEX_LIVE_WEB_JSONL_V1"
CLAUDE_LIVE_WEB_STREAM_PROFILE = "CLAUDE_LIVE_WEB_STREAM_V1"
CODEX_RESEARCH_ATTEMPT_COMPLETION_PLACEHOLDER = (
    "__PLAMEN_POSIX_V2_COMPAT_RESEARCH_ATTEMPT_COMPLETION__"
)
_COMPAT_BACKENDS = frozenset({"claude", "codex"})

_INTERPRETER_NONCE = os.urandom(32).hex()
_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}")
_SAFE_FILE_PART_RE = re.compile(r"[^A-Za-z0-9_.-]+")
_MAX_PROMPT_BYTES = 16 * 1024 * 1024
_MAX_STDOUT_BYTES = 32 * 1024 * 1024

# Stream-inactivity watchdog for the phase child. DODO run45 inventory_chunk_c
# attempt 1 (2026-09-19): the Claude CLI did 711 KB of normal work, then fell
# into its internal API retry loop (`system/api_retry`, error "unknown"), the
# retried request hung on an open HTTPS connection, and NO byte reached stdout
# for 2.5 h while the phase deadline (hours) had not fired -- 11.75 s of CPU in
# 150 min, empty output directory. The headless reincarnation of the
# 0-byte-stdio hang class. A live worker emits stream-json rows every few
# seconds (thinking_tokens, tool_use, api_retry), so "no stdout/stderr byte
# for this long" is a stall, not a slow turn. It surfaces as the ordinary
# TIMEOUT failure (same downstream semantics; the receipt duration shows it
# fired early). 0 disables.
# Typed provider refusals: the terminal `result.stop_reason == "refusal"`
# (RESULT_CYBER_REFUSAL) and the mid-stream `system/model_refusal_no_fallback`
# + assistant error envelope (PROVIDER_REFUSAL). Both classify the attempt as
# PROVIDER_REFUSED (rc -5); neither switches models.
_PROVIDER_REFUSAL_CODES = frozenset({"RESULT_CYBER_REFUSAL", "PROVIDER_REFUSAL"})

_STREAM_INACTIVITY_S = float(
    os.environ.get("PLAMEN_STREAM_INACTIVITY_S", "900") or 900
)
_MAX_STDERR_BYTES = 8 * 1024 * 1024
_MAX_AUTH_BYTES = 2 * 1024 * 1024
_MAX_CODEX_BINARY_BYTES = 512 * 1024 * 1024
_MAX_WRITABLE_DIRECTORIES = 64
_MAX_TIMEOUT_SECONDS = 86_400.0
_MAX_PHASE_IO_OUTPUT_BYTES = 256 * 1024 * 1024
_MAX_STAGED_VALIDATOR_CONTEXT_BYTES = 2 * 1024 * 1024
_MAX_STAGED_VALIDATOR_INPUTS = 512
_MAX_STAGED_VALIDATOR_BINDINGS_BYTES = 8 * 1024 * 1024
_MAX_STAGED_REJECTION_REASONS = 64
_MAX_STAGED_REJECTION_REASON_BYTES = 2048
_PUBLICATION_JOURNAL_SCHEMA = "plamen.posix_v2_publication_journal.v1"
_PUBLICATION_JOURNAL_NAME = "publication-journal.json"
_PUBLICATION_SUCCESSOR_DIRECTORY = "publication-successors"
_MAX_PUBLICATION_JOURNAL_BYTES = 4 * 1024 * 1024
_MAX_COMPAT_RECEIPT_BYTES = 16 * 1024 * 1024

# Private-runtime removal is deliberately finite even if a provider leaves a
# hostile tree behind.  The nominal-byte limit uses lstat(2)'s st_size and is
# therefore a traversal-work guard, not a claim about allocated disk blocks.
_PRIVATE_RUNTIME_ROOT_NAME = ".posix_v2_compat_private"
_RESEARCH_EVIDENCE_ROOT_NAME = ".posix_v2_compat_research_evidence"
_PRIVATE_QUARANTINE_PREFIX = ".cleanup-"
_PRIVATE_NAME_RE = re.compile(r"[0-9a-f]{32}")
_PRIVATE_QUARANTINE_RE = re.compile(r"\.cleanup-[0-9a-f]{32}")
_MAX_PRIVATE_CLEANUP_ENTRIES = 250_000
_MAX_PRIVATE_CLEANUP_DIRECTORIES = 16_384
_MAX_PRIVATE_CLEANUP_DEPTH = 64
_MAX_PRIVATE_CLEANUP_NAME_BYTES = 255
_MAX_PRIVATE_CLEANUP_NOMINAL_BYTES = 8 * 1024 * 1024 * 1024
_PRIVATE_LOCK_TIMEOUT_SECONDS = 5.0


class PosixV2CompatRuntimeError(RuntimeError):
    """The explicit compatibility runtime failed closed."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _fail(
    code: str,
    message: str,
    cause: BaseException | None = None,
) -> NoReturn:
    error = PosixV2CompatRuntimeError(code, message)
    if cause is None:
        raise error
    raise error from cause


def _canonical_bytes(value: Mapping[str, Any]) -> bytes:
    try:
        return json.dumps(
            dict(value),
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as exc:
        _fail("CANONICAL_JSON", "receipt value is not canonical JSON", exc)


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _mapping_sha(value: Mapping[str, Any]) -> str:
    return _sha(_canonical_bytes(value))


def _sequence_sha(value: Sequence[Mapping[str, Any]]) -> str:
    try:
        raw = json.dumps(
            [dict(item) for item in value],
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as exc:
        _fail("CANONICAL_JSON", "sequence value is not canonical JSON", exc)
    return _sha(raw)


def _stable_file_identity(observed: os.stat_result) -> tuple[int, ...]:
    return (
        int(observed.st_dev),
        int(observed.st_ino),
        int(observed.st_mode),
        int(observed.st_uid),
        int(observed.st_gid),
        int(observed.st_size),
        int(observed.st_mtime_ns),
        int(observed.st_ctime_ns),
    )


def _open_readonly_nofollow(
    path: Path,
    label: str,
    *,
    missing_ok: bool = False,
) -> int | None:
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_CLOEXEC"):
        _fail("FILE_ADMISSION", f"{label} requires O_NOFOLLOW and O_CLOEXEC")
    try:
        return os.open(
            path,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
    except OSError as exc:
        if missing_ok and exc.errno == errno.ENOENT:
            return None
        _fail("FILE_ADMISSION", f"{label} cannot be opened safely", exc)


def _read_exact_regular_fd(
    descriptor: int,
    observed: os.stat_result,
    *,
    maximum: int,
    label: str,
) -> bytes:
    size = int(observed.st_size)
    if not stat.S_ISREG(observed.st_mode) or size <= 0 or size > maximum:
        _fail("FILE_ADMISSION", f"{label} type or size is unsafe")
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        try:
            chunk = os.read(descriptor, min(remaining, 64 * 1024))
        except OSError as exc:
            _fail("FILE_ADMISSION", f"{label} read failed", exc)
        if not chunk:
            _fail("FILE_ADMISSION", f"{label} ended before its admitted size")
        chunks.append(chunk)
        remaining -= len(chunk)
    try:
        extra = os.read(descriptor, 1)
        after = os.fstat(descriptor)
    except OSError as exc:
        _fail("FILE_ADMISSION", f"{label} stability check failed", exc)
    if extra or _stable_file_identity(after) != _stable_file_identity(observed):
        _fail("FILE_ADMISSION", f"{label} changed during admission")
    return b"".join(chunks)


def _hash_exact_regular_fd(
    descriptor: int,
    observed: os.stat_result,
    *,
    maximum: int,
    label: str,
) -> str:
    size = int(observed.st_size)
    if not stat.S_ISREG(observed.st_mode) or size <= 0 or size > maximum:
        _fail("FILE_ADMISSION", f"{label} type or size is unsafe")
    digest = hashlib.sha256()
    remaining = size
    while remaining:
        try:
            chunk = os.read(descriptor, min(remaining, 1024 * 1024))
        except OSError as exc:
            _fail("FILE_ADMISSION", f"{label} hash read failed", exc)
        if not chunk:
            _fail("FILE_ADMISSION", f"{label} ended before its admitted size")
        digest.update(chunk)
        remaining -= len(chunk)
    try:
        extra = os.read(descriptor, 1)
        after = os.fstat(descriptor)
    except OSError as exc:
        _fail("FILE_ADMISSION", f"{label} stability check failed", exc)
    if extra or _stable_file_identity(after) != _stable_file_identity(observed):
        _fail("FILE_ADMISSION", f"{label} changed while being hashed")
    return digest.hexdigest()


def _identifier(value: object, label: str) -> str:
    if type(value) is not str or _ID_RE.fullmatch(value) is None:
        _fail("IDENTIFIER", f"{label} is not a canonical identifier")
    return value


def _safe_part(value: str) -> str:
    result = _SAFE_FILE_PART_RE.sub("_", value).strip("._")
    return (result or "worker")[:96]


def _safe_directory(value: str | Path, label: str) -> tuple[Path, dict[str, int]]:
    candidate = Path(value)
    try:
        lexical = candidate.lstat()
        resolved = candidate.resolve(strict=True)
        observed = resolved.stat(follow_symlinks=False)
    except (OSError, TypeError, ValueError) as exc:
        _fail("BOUND_PATH", f"{label} is unavailable", exc)
    if stat.S_ISLNK(lexical.st_mode) or not stat.S_ISDIR(observed.st_mode):
        _fail("BOUND_PATH", f"{label} is aliased or not a directory")
    return resolved, {
        "device": int(observed.st_dev),
        "inode": int(observed.st_ino),
        "mode": int(observed.st_mode),
        "owner": int(observed.st_uid),
        "group": int(observed.st_gid),
    }


def _replay_directory(
    path: Path,
    identity: Mapping[str, int],
    label: str,
) -> None:
    current, observed = _safe_directory(path, label)
    if current != path or observed != dict(identity):
        _fail("BOUND_PATH_DRIFT", f"{label} identity changed")


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _directory_identity(observed: os.stat_result) -> tuple[int, ...]:
    return (
        int(observed.st_dev),
        int(observed.st_ino),
        int(observed.st_mode),
        int(observed.st_uid),
        int(observed.st_gid),
    )


def _acquire_private_lock(descriptor: int, operation: int, label: str) -> None:
    deadline = time.monotonic() + _PRIVATE_LOCK_TIMEOUT_SECONDS
    while True:
        try:
            fcntl.flock(descriptor, operation | fcntl.LOCK_NB)
            return
        except OSError as exc:
            if exc.errno == errno.EINTR:
                continue
            if exc.errno not in (errno.EAGAIN, errno.EWOULDBLOCK):
                _fail("PRIVATE_RUNTIME", f"{label} failed", exc)
            if time.monotonic() >= deadline:
                _fail("PRIVATE_RUNTIME", f"{label} timed out", exc)
            time.sleep(0.01)


def _directory_open_flags() -> int:
    required = ("O_DIRECTORY", "O_NOFOLLOW", "O_CLOEXEC")
    if any(not hasattr(os, name) for name in required):
        _fail(
            "PRIVATE_RUNTIME",
            "private cleanup requires O_DIRECTORY, O_NOFOLLOW, and O_CLOEXEC",
        )
    return os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


def _validate_private_directory_stat(
    observed: os.stat_result,
    label: str,
) -> None:
    if (
        not stat.S_ISDIR(observed.st_mode)
        or int(observed.st_uid) != os.getuid()
        or stat.S_IMODE(observed.st_mode) & 0o077
    ):
        _fail("PRIVATE_RUNTIME", f"{label} type, owner, or mode is unsafe")


def _open_verified_directory_at(
    parent_descriptor: int,
    name: str,
    observed: os.stat_result,
    label: str,
    *,
    require_private_mode: bool = True,
) -> int:
    if require_private_mode:
        _validate_private_directory_stat(observed, label)
    elif not stat.S_ISDIR(observed.st_mode):
        _fail("PRIVATE_RUNTIME", f"{label} is not a directory")
    try:
        descriptor = os.open(
            name,
            _directory_open_flags(),
            dir_fd=parent_descriptor,
        )
    except OSError as exc:
        _fail("PRIVATE_RUNTIME", f"{label} cannot be opened safely", exc)
    try:
        after = os.fstat(descriptor)
        if _directory_identity(after) != _directory_identity(observed):
            _fail("PRIVATE_RUNTIME", f"{label} identity changed during open")
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def _open_private_runtime_root(
    scratchpad: Path,
    *,
    create: bool,
) -> tuple[Path, int, tuple[int, ...]] | None:
    """Open the private root relative to the already-admitted scratchpad."""

    try:
        scratch_descriptor = os.open(scratchpad, _directory_open_flags())
    except OSError as exc:
        _fail("PRIVATE_RUNTIME", "scratchpad cannot anchor private cleanup", exc)
    try:
        try:
            observed = os.stat(
                _PRIVATE_RUNTIME_ROOT_NAME,
                dir_fd=scratch_descriptor,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            if not create:
                return None
            try:
                os.mkdir(
                    _PRIVATE_RUNTIME_ROOT_NAME,
                    mode=0o700,
                    dir_fd=scratch_descriptor,
                )
                observed = os.stat(
                    _PRIVATE_RUNTIME_ROOT_NAME,
                    dir_fd=scratch_descriptor,
                    follow_symlinks=False,
                )
            except FileExistsError:
                try:
                    observed = os.stat(
                        _PRIVATE_RUNTIME_ROOT_NAME,
                        dir_fd=scratch_descriptor,
                        follow_symlinks=False,
                    )
                except OSError as exc:
                    _fail(
                        "PRIVATE_RUNTIME",
                        "raced private runtime root cannot be inspected",
                        exc,
                    )
            except OSError as exc:
                _fail("PRIVATE_RUNTIME", "private runtime root cannot be created", exc)
        except OSError as exc:
            _fail("PRIVATE_RUNTIME", "private runtime root cannot be inspected", exc)
        descriptor = _open_verified_directory_at(
            scratch_descriptor,
            _PRIVATE_RUNTIME_ROOT_NAME,
            observed,
            "private runtime root",
        )
        return (
            scratchpad / _PRIVATE_RUNTIME_ROOT_NAME,
            descriptor,
            _directory_identity(observed),
        )
    finally:
        os.close(scratch_descriptor)


def _replay_private_runtime_root(
    scratchpad: Path,
    root_descriptor: int,
    root_identity: tuple[int, ...],
) -> None:
    """Prove the opened root is still the named child of this scratchpad."""

    try:
        scratch_descriptor = os.open(scratchpad, _directory_open_flags())
    except OSError as exc:
        _fail("PRIVATE_RUNTIME", "scratchpad cannot replay private root", exc)
    try:
        try:
            named = os.stat(
                _PRIVATE_RUNTIME_ROOT_NAME,
                dir_fd=scratch_descriptor,
                follow_symlinks=False,
            )
            opened = os.fstat(root_descriptor)
        except OSError as exc:
            _fail("PRIVATE_RUNTIME", "private runtime root identity is unavailable", exc)
        if (
            _directory_identity(named) != root_identity
            or _directory_identity(opened) != root_identity
        ):
            _fail("PRIVATE_RUNTIME", "private runtime root identity changed")
    finally:
        os.close(scratch_descriptor)


@dataclass
class _PrivateCleanupBudget:
    root_device: int
    entries: int = 0
    directories: int = 0
    nominal_bytes: int = 0

    def require_root_device(self, observed: os.stat_result) -> None:
        if int(observed.st_dev) != self.root_device:
            _fail(
                "PRIVATE_RUNTIME_CLEANUP",
                "private cleanup entry crosses the retained root device",
            )

    def account(self, observed: os.stat_result, *, directory: bool) -> None:
        self.require_root_device(observed)
        self.entries += 1
        self.nominal_bytes += max(0, int(observed.st_size))
        if directory:
            self.directories += 1
        if self.entries > _MAX_PRIVATE_CLEANUP_ENTRIES:
            _fail("PRIVATE_CLEANUP_BOUND", "private cleanup entry bound exceeded")
        if self.directories > _MAX_PRIVATE_CLEANUP_DIRECTORIES:
            _fail("PRIVATE_CLEANUP_BOUND", "private cleanup directory bound exceeded")
        if self.nominal_bytes > _MAX_PRIVATE_CLEANUP_NOMINAL_BYTES:
            _fail("PRIVATE_CLEANUP_BOUND", "private cleanup nominal-byte bound exceeded")


def _bounded_private_names(descriptor: int, maximum: int) -> list[str]:
    names: list[str] = []
    try:
        with os.scandir(descriptor) as entries:
            for entry in entries:
                if len(names) >= maximum:
                    _fail("PRIVATE_CLEANUP_BOUND", "private cleanup entry bound exceeded")
                names.append(entry.name)
    except PosixV2CompatRuntimeError:
        raise
    except OSError as exc:
        _fail("PRIVATE_RUNTIME_CLEANUP", "private directory cannot be listed", exc)
    return names


def _bounded_remove_directory_contents(
    descriptor: int,
    *,
    budget: _PrivateCleanupBudget,
    depth: int,
) -> None:
    if depth > _MAX_PRIVATE_CLEANUP_DEPTH:
        _fail("PRIVATE_CLEANUP_BOUND", "private cleanup depth bound exceeded")
    names = _bounded_private_names(
        descriptor,
        _MAX_PRIVATE_CLEANUP_ENTRIES - budget.entries,
    )
    for name in names:
        if (
            type(name) is not str
            or name in ("", ".", "..")
            or "/" in name
            or len(os.fsencode(name)) > _MAX_PRIVATE_CLEANUP_NAME_BYTES
        ):
            _fail("PRIVATE_CLEANUP_BOUND", "private cleanup name is unsafe")
        try:
            observed = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
        except OSError as exc:
            _fail("PRIVATE_RUNTIME_CLEANUP", "private entry cannot be inspected", exc)
        is_directory = stat.S_ISDIR(observed.st_mode)
        budget.account(observed, directory=is_directory)
        if is_directory:
            child_descriptor = _open_verified_directory_at(
                descriptor,
                name,
                observed,
                "private cleanup directory",
                require_private_mode=False,
            )
            try:
                _bounded_remove_directory_contents(
                    child_descriptor,
                    budget=budget,
                    depth=depth + 1,
                )
            finally:
                os.close(child_descriptor)
            try:
                os.rmdir(name, dir_fd=descriptor)
            except OSError as exc:
                _fail(
                    "PRIVATE_RUNTIME_CLEANUP",
                    "private cleanup directory could not be removed",
                    exc,
                )
        else:
            try:
                os.unlink(name, dir_fd=descriptor)
            except OSError as exc:
                _fail(
                    "PRIVATE_RUNTIME_CLEANUP",
                    "private cleanup entry could not be removed",
                    exc,
                )


def _cleanup_private_entry(
    root_descriptor: int,
    name: str,
    *,
    budget: _PrivateCleanupBudget,
    expected_identity: tuple[int, ...] | None = None,
    require_private_mode: bool = True,
) -> None:
    """Quarantine one UUID child, then remove only that exact inode tree."""

    if _PRIVATE_NAME_RE.fullmatch(name):
        quarantine_name = _PRIVATE_QUARANTINE_PREFIX + name
        try:
            before = os.stat(name, dir_fd=root_descriptor, follow_symlinks=False)
        except OSError as exc:
            _fail("PRIVATE_RUNTIME_CLEANUP", "private invocation is unavailable", exc)
        if require_private_mode:
            _validate_private_directory_stat(before, "private invocation")
        elif not stat.S_ISDIR(before.st_mode):
            _fail("PRIVATE_RUNTIME_CLEANUP", "private invocation is not a directory")
        budget.require_root_device(before)
        if (
            expected_identity is not None
            and _directory_identity(before)[:2] != expected_identity[:2]
        ):
            _fail("PRIVATE_RUNTIME_CLEANUP", "private invocation identity changed")
        try:
            os.stat(
                quarantine_name,
                dir_fd=root_descriptor,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            pass
        except OSError as exc:
            _fail(
                "PRIVATE_RUNTIME_CLEANUP",
                "private quarantine target cannot be inspected",
                exc,
            )
        else:
            _fail("PRIVATE_RUNTIME_CLEANUP", "private quarantine target already exists")
        try:
            os.rename(
                name,
                quarantine_name,
                src_dir_fd=root_descriptor,
                dst_dir_fd=root_descriptor,
            )
            quarantined = os.stat(
                quarantine_name,
                dir_fd=root_descriptor,
                follow_symlinks=False,
            )
        except OSError as exc:
            _fail("PRIVATE_RUNTIME_CLEANUP", "private invocation quarantine failed", exc)
        if _directory_identity(quarantined) != _directory_identity(before):
            _fail("PRIVATE_RUNTIME_CLEANUP", "quarantined invocation identity changed")
    elif _PRIVATE_QUARANTINE_RE.fullmatch(name):
        quarantine_name = name
        try:
            quarantined = os.stat(
                quarantine_name,
                dir_fd=root_descriptor,
                follow_symlinks=False,
            )
        except OSError as exc:
            _fail("PRIVATE_RUNTIME_CLEANUP", "private quarantine is unavailable", exc)
    else:
        _fail("PRIVATE_RUNTIME", "private runtime entry name is malformed")
    if require_private_mode:
        _validate_private_directory_stat(quarantined, "private quarantine")
    elif not stat.S_ISDIR(quarantined.st_mode):
        _fail("PRIVATE_RUNTIME_CLEANUP", "private quarantine is not a directory")
    budget.account(quarantined, directory=True)
    invocation_descriptor = _open_verified_directory_at(
        root_descriptor,
        quarantine_name,
        quarantined,
        "private quarantine",
        require_private_mode=require_private_mode,
    )
    try:
        _bounded_remove_directory_contents(
            invocation_descriptor,
            budget=budget,
            depth=1,
        )
    finally:
        os.close(invocation_descriptor)
    try:
        os.rmdir(quarantine_name, dir_fd=root_descriptor)
    except OSError as exc:
        _fail("PRIVATE_RUNTIME_CLEANUP", "private quarantine removal failed", exc)


def _cleanup_private_invocation_payload(
    root_descriptor: int,
    name: str,
    *,
    retained_names: frozenset[str],
    root_device: int,
) -> None:
    """Remove provider payload while retaining only the publication WAL."""

    observed = os.stat(name, dir_fd=root_descriptor, follow_symlinks=False)
    budget = _PrivateCleanupBudget(root_device=root_device)
    budget.require_root_device(observed)
    descriptor = _open_verified_directory_at(
        root_descriptor,
        name,
        observed,
        "private invocation payload",
        require_private_mode=False,
    )
    try:
        names = _bounded_private_names(descriptor, _MAX_PRIVATE_CLEANUP_ENTRIES)
        for child_name in names:
            if child_name in retained_names:
                continue
            child = os.stat(child_name, dir_fd=descriptor, follow_symlinks=False)
            is_directory = stat.S_ISDIR(child.st_mode)
            budget.account(child, directory=is_directory)
            if is_directory:
                child_descriptor = _open_verified_directory_at(
                    descriptor,
                    child_name,
                    child,
                    "private payload directory",
                    require_private_mode=False,
                )
                try:
                    _bounded_remove_directory_contents(
                        child_descriptor, budget=budget, depth=1
                    )
                finally:
                    os.close(child_descriptor)
                os.rmdir(child_name, dir_fd=descriptor)
            else:
                os.unlink(child_name, dir_fd=descriptor)
    except OSError as exc:
        _fail("PRIVATE_RUNTIME_CLEANUP", "private payload cleanup failed", exc)
    finally:
        os.close(descriptor)


def _recover_stale_private_runtime(scratchpad: Path) -> None:
    opened = _open_private_runtime_root(scratchpad, create=False)
    if opened is None:
        return
    _root_path, root_descriptor, root_identity = opened
    try:
        _acquire_private_lock(
            root_descriptor,
            fcntl.LOCK_EX,
            "private runtime recovery lock",
        )
        _replay_private_runtime_root(scratchpad, root_descriptor, root_identity)
        names = _bounded_private_names(
            root_descriptor,
            _MAX_PRIVATE_CLEANUP_ENTRIES,
        )
        # Validate the complete root before mutating it.  Unknown names, links,
        # and unsafe directories make session issuance fail closed.
        observed_entries: list[str] = []
        invocation_ids: set[str] = set()
        quarantine_ids: set[str] = set()
        for name in names:
            if (
                type(name) is not str
                or len(os.fsencode(name)) > _MAX_PRIVATE_CLEANUP_NAME_BYTES
                or (
                    _PRIVATE_NAME_RE.fullmatch(name) is None
                    and _PRIVATE_QUARANTINE_RE.fullmatch(name) is None
                )
            ):
                _fail("PRIVATE_RUNTIME", "private runtime entry name is malformed")
            try:
                observed = os.stat(
                    name,
                    dir_fd=root_descriptor,
                    follow_symlinks=False,
                )
            except OSError as exc:
                _fail("PRIVATE_RUNTIME", "private runtime entry is unavailable", exc)
            _validate_private_directory_stat(observed, "private runtime entry")
            if int(observed.st_dev) != int(root_identity[0]):
                _fail(
                    "PRIVATE_RUNTIME",
                    "private runtime entry crosses the retained root device",
                )
            if _PRIVATE_NAME_RE.fullmatch(name):
                invocation_ids.add(name)
            else:
                quarantine_ids.add(name.removeprefix(_PRIVATE_QUARANTINE_PREFIX))
            observed_entries.append(name)
        if invocation_ids & quarantine_ids:
            _fail(
                "PRIVATE_RUNTIME",
                "private runtime contains an ambiguous UUID/quarantine pair",
            )
        budget = _PrivateCleanupBudget(root_device=int(root_identity[0]))
        for name in sorted(observed_entries):
            invocation_id = name.removeprefix(_PRIVATE_QUARANTINE_PREFIX)
            _recover_invocation_publication(scratchpad, name, invocation_id)
            _cleanup_private_entry(root_descriptor, name, budget=budget)
        _replay_private_runtime_root(scratchpad, root_descriptor, root_identity)
    finally:
        with contextlib.suppress(OSError):
            fcntl.flock(root_descriptor, fcntl.LOCK_UN)
        os.close(root_descriptor)


class _FrozenAuthorityType(type):
    def __setattr__(cls, _name: str, _value: Any) -> NoReturn:
        raise TypeError("POSIX V2 compatibility authority types are frozen")

    def __delattr__(cls, _name: str) -> NoReturn:
        raise TypeError("POSIX V2 compatibility authority types are frozen")


class PosixV2CompatSessionAuthority(metaclass=_FrozenAuthorityType):
    """Opaque run-scoped authority retained only by the installed driver."""

    __slots__ = ("__token", "__creator_pid", "__interpreter_nonce", "__weakref__")

    def __init__(self, *_args: Any, **_kwargs: Any) -> None:
        raise TypeError("POSIX V2 compatibility sessions are issuer-created")

    def __init_subclass__(cls, **_kwargs: Any) -> NoReturn:
        raise TypeError("POSIX V2 compatibility sessions cannot be subclassed")

    def __copy__(self) -> NoReturn:
        raise TypeError("POSIX V2 compatibility sessions cannot be copied")

    def __deepcopy__(self, _memo: Any) -> NoReturn:
        raise TypeError("POSIX V2 compatibility sessions cannot be copied")

    def __reduce__(self) -> NoReturn:
        raise TypeError("POSIX V2 compatibility sessions cannot be serialized")

    def __reduce_ex__(self, _protocol: int) -> NoReturn:
        raise TypeError("POSIX V2 compatibility sessions cannot be serialized")

    def __repr__(self) -> str:
        return "<PosixV2CompatSessionAuthority opaque>"

    @property
    def binding(self) -> Mapping[str, Any]:
        return MappingProxyType(dict(_session_record(self).binding))

    def close(self) -> None:
        record = _session_record(self)
        with record.lock:
            if record.active_invocations:
                _fail("SESSION_BUSY", "compatibility executions are still active")
            if record.derived_sessions:
                _fail(
                    "SESSION_BUSY",
                    "derived staging sessions are still active",
                )
            _poc_close_session_registries(self)
            record.closed = True
            with _REGISTRY_LOCK:
                _SESSIONS.pop(id(self), None)


class PosixV2CompatStagingSessionAuthority(metaclass=_FrozenAuthorityType):
    """Opaque one-shot authority for an authenticated sibling staging pair."""

    __slots__ = ("__token", "__creator_pid", "__interpreter_nonce", "__weakref__")

    def __init__(self, *_args: Any, **_kwargs: Any) -> None:
        raise TypeError("POSIX V2 staging sessions are issuer-created")

    def __init_subclass__(cls, **_kwargs: Any) -> NoReturn:
        raise TypeError("POSIX V2 staging sessions cannot be subclassed")

    def __copy__(self) -> NoReturn:
        raise TypeError("POSIX V2 staging sessions cannot be copied")

    def __deepcopy__(self, _memo: Any) -> NoReturn:
        raise TypeError("POSIX V2 staging sessions cannot be copied")

    def __reduce__(self) -> NoReturn:
        raise TypeError("POSIX V2 staging sessions cannot be serialized")

    def __reduce_ex__(self, _protocol: int) -> NoReturn:
        raise TypeError("POSIX V2 staging sessions cannot be serialized")

    def __repr__(self) -> str:
        return "<PosixV2CompatStagingSessionAuthority opaque>"

    @property
    def binding(self) -> Mapping[str, Any]:
        return MappingProxyType(dict(_staging_session_record(self).binding))

    def close(self) -> None:
        record = _staging_session_record(self)
        with record.lock:
            if record.active_invocations:
                _fail("SESSION_BUSY", "staging execution is still active")
            record.closed = True
            parent = record.parent_authority_ref()
            with _REGISTRY_LOCK:
                _STAGING_SESSIONS.pop(id(self), None)
                if parent is not None:
                    parent_record = _SESSIONS.get(record.parent_session_id)
                    if parent_record is not None:
                        parent_record.derived_sessions.discard(id(self))


@dataclass
class _SessionRecord:
    token: str
    creator_pid: int
    interpreter_nonce: str
    authority_ref: weakref.ReferenceType[Any]
    binding: Mapping[str, Any]
    project_root: Path
    project_identity: Mapping[str, int]
    scratchpad: Path
    scratchpad_identity: Mapping[str, int]
    active_invocations: set[str] = field(default_factory=set)
    used_invocations: set[str] = field(default_factory=set)
    derived_sessions: set[int] = field(default_factory=set)
    closed: bool = False
    lock: threading.RLock = field(default_factory=threading.RLock, repr=False)


_REGISTRY_LOCK = threading.RLock()
_SESSIONS: dict[int, _SessionRecord] = {}


@dataclass
class _StagingSessionRecord(_SessionRecord):
    parent_session_id: int = 0
    parent_authority_ref: weakref.ReferenceType[Any] | None = None
    parent_binding_sha256: str = ""
    staging_root: Path = Path("/")
    staging_root_identity: Mapping[str, int] = field(default_factory=dict)


_STAGING_SESSIONS: dict[int, _StagingSessionRecord] = {}


def _session_record(value: object) -> _SessionRecord:
    # Exact type and registry admission intentionally precede request/config
    # inspection in every public execution entry point.
    if type(value) is not PosixV2CompatSessionAuthority:
        _fail("SESSION_AUTHORITY", "compatibility session has the wrong exact type")
    with _REGISTRY_LOCK:
        record = _SESSIONS.get(id(value))
    if record is None:
        _fail("SESSION_AUTHORITY", "compatibility session is absent or closed")
    try:
        token = object.__getattribute__(
            value, "_PosixV2CompatSessionAuthority__token"
        )
        creator_pid = object.__getattribute__(
            value, "_PosixV2CompatSessionAuthority__creator_pid"
        )
        interpreter_nonce = object.__getattribute__(
            value, "_PosixV2CompatSessionAuthority__interpreter_nonce"
        )
    except BaseException as exc:
        _fail("SESSION_AUTHORITY", "compatibility session shell is incomplete", exc)
    if (
        record.authority_ref() is not value
        or token != record.token
        or creator_pid != record.creator_pid
        or interpreter_nonce != record.interpreter_nonce
        or creator_pid != os.getpid()
        or interpreter_nonce != _INTERPRETER_NONCE
    ):
        _fail("SESSION_AUTHORITY", "compatibility session is forged or inherited")
    if record.closed:
        _fail("SESSION_AUTHORITY", "compatibility session is closed")
    return record


def _staging_session_record(value: object) -> _StagingSessionRecord:
    if type(value) is not PosixV2CompatStagingSessionAuthority:
        _fail("SESSION_AUTHORITY", "staging session has the wrong exact type")
    with _REGISTRY_LOCK:
        record = _STAGING_SESSIONS.get(id(value))
    if record is None:
        _fail("SESSION_AUTHORITY", "staging session is absent or closed")
    try:
        token = object.__getattribute__(
            value, "_PosixV2CompatStagingSessionAuthority__token"
        )
        creator_pid = object.__getattribute__(
            value, "_PosixV2CompatStagingSessionAuthority__creator_pid"
        )
        interpreter_nonce = object.__getattribute__(
            value,
            "_PosixV2CompatStagingSessionAuthority__interpreter_nonce",
        )
    except BaseException as exc:
        _fail("SESSION_AUTHORITY", "staging session shell is incomplete", exc)
    parent = (
        record.parent_authority_ref()
        if record.parent_authority_ref is not None
        else None
    )
    if (
        record.authority_ref() is not value
        or token != record.token
        or creator_pid != record.creator_pid
        or interpreter_nonce != record.interpreter_nonce
        or creator_pid != os.getpid()
        or interpreter_nonce != _INTERPRETER_NONCE
        or parent is None
        or id(parent) != record.parent_session_id
    ):
        _fail("SESSION_AUTHORITY", "staging session is forged or inherited")
    parent_record = _session_record(parent)
    if (
        record.closed
        or id(value) not in parent_record.derived_sessions
        or parent_record.binding["session_binding_sha256"]
        != record.parent_binding_sha256
    ):
        _fail("SESSION_AUTHORITY", "staging session parent binding changed")
    _replay_directory(
        record.staging_root,
        record.staging_root_identity,
        "staging root",
    )
    _replay_directory(record.project_root, record.project_identity, "staging project")
    _replay_directory(record.scratchpad, record.scratchpad_identity, "staging scratchpad")
    if (
        record.project_root.parent != record.staging_root
        or record.scratchpad.parent != record.staging_root
        or record.project_root == record.scratchpad
        or _is_within(record.project_root, record.scratchpad)
        or _is_within(record.scratchpad, record.project_root)
    ):
        _fail("SESSION_AUTHORITY", "staging sibling relation changed")
    return record


def _execution_session_record(value: object) -> _SessionRecord:
    if type(value) is PosixV2CompatStagingSessionAuthority:
        return _staging_session_record(value)
    return _session_record(value)


def issue_posix_v2_compat_session_for_installed_front(
    *,
    run_id: str,
    project_root: str | Path,
    scratchpad: str | Path,
    backend: str = "codex",
) -> PosixV2CompatSessionAuthority:
    """Mint one explicit process-local session for a parsed front-door run."""

    run = _identifier(run_id, "run id")
    selected_backend = _identifier(backend, "compatibility backend")
    if selected_backend not in _COMPAT_BACKENDS:
        _fail("SESSION_AUTHORITY", "compatibility backend is unsupported")
    project, project_identity = _safe_directory(project_root, "project root")
    scratch, scratch_identity = _safe_directory(scratchpad, "scratchpad")
    if not _is_within(scratch, project):
        _fail("SCRATCHPAD", "scratchpad must be inside the project root")
    _recover_stale_private_runtime(scratch)
    value = object.__new__(PosixV2CompatSessionAuthority)
    token = uuid.uuid4().hex + os.urandom(16).hex()
    object.__setattr__(
        value, "_PosixV2CompatSessionAuthority__token", token
    )
    object.__setattr__(
        value, "_PosixV2CompatSessionAuthority__creator_pid", os.getpid()
    )
    object.__setattr__(
        value,
        "_PosixV2CompatSessionAuthority__interpreter_nonce",
        _INTERPRETER_NONCE,
    )
    binding = {
        "schema": SESSION_SCHEMA,
        "mode": COMPATIBILITY_MODE,
        "run_id": run,
        "backend": selected_backend,
        "project_root": os.fspath(project),
        "project_root_identity_sha256": _mapping_sha(project_identity),
        "scratchpad": os.fspath(scratch),
        "scratchpad_identity_sha256": _mapping_sha(scratch_identity),
        "creator_pid": os.getpid(),
        "interpreter_nonce_sha256": _sha(_INTERPRETER_NONCE.encode("ascii")),
        "native_broker_authority": False,
        "wer_authority": False,
    }
    binding["session_binding_sha256"] = _mapping_sha(binding)
    record = _SessionRecord(
        token=token,
        creator_pid=os.getpid(),
        interpreter_nonce=_INTERPRETER_NONCE,
        authority_ref=weakref.ref(value),
        binding=MappingProxyType(binding),
        project_root=project,
        project_identity=MappingProxyType(project_identity),
        scratchpad=scratch,
        scratchpad_identity=MappingProxyType(scratch_identity),
    )
    with _REGISTRY_LOCK:
        _SESSIONS[id(value)] = record
    return value


def derive_posix_v2_compat_staging_session(
    *,
    parent_session_authority: object,
    staging_root: str | Path,
    project_root: str | Path,
    scratchpad: str | Path,
    purpose: str = DERIVED_STAGING_PURPOSE,
) -> PosixV2CompatStagingSessionAuthority:
    """Derive one process-local model turn over sibling disposable roots.

    This is a separate authority rather than an exception to the ordinary
    session invariant.  Ordinary front sessions still require their scratchpad
    to be nested beneath the project.  A derived staging session instead binds
    an exact private common root and two distinct immediate children; only the
    scratch child can receive provider write grants.
    """

    parent = _session_record(parent_session_authority)
    if purpose != DERIVED_STAGING_PURPOSE:
        _fail("SESSION_AUTHORITY", "derived staging purpose is unsupported")
    stage, stage_identity = _safe_directory(staging_root, "staging root")
    project, project_identity = _safe_directory(
        project_root, "staging project root"
    )
    scratch, scratch_identity = _safe_directory(
        scratchpad, "staging scratchpad"
    )
    if (
        project.parent != stage
        or scratch.parent != stage
        or project == scratch
        or _is_within(project, scratch)
        or _is_within(scratch, project)
    ):
        _fail(
            "SESSION_AUTHORITY",
            "derived staging paths must be distinct immediate siblings",
        )
    if (
        int(stage_identity["owner"]) != os.getuid()
        or stat.S_IMODE(int(stage_identity["mode"])) & 0o077
    ):
        _fail(
            "SESSION_AUTHORITY",
            "derived staging root must be private to the current user",
        )
    if len({
        (int(stage_identity["device"]), int(stage_identity["inode"])),
        (int(project_identity["device"]), int(project_identity["inode"])),
        (int(scratch_identity["device"]), int(scratch_identity["inode"])),
    }) != 3:
        _fail("SESSION_AUTHORITY", "derived staging directory identities overlap")

    value = object.__new__(PosixV2CompatStagingSessionAuthority)
    token = uuid.uuid4().hex + os.urandom(16).hex()
    object.__setattr__(
        value,
        "_PosixV2CompatStagingSessionAuthority__token",
        token,
    )
    object.__setattr__(
        value,
        "_PosixV2CompatStagingSessionAuthority__creator_pid",
        os.getpid(),
    )
    object.__setattr__(
        value,
        "_PosixV2CompatStagingSessionAuthority__interpreter_nonce",
        _INTERPRETER_NONCE,
    )
    binding = {
        "schema": DERIVED_STAGING_SESSION_SCHEMA,
        "mode": COMPATIBILITY_MODE,
        "purpose": DERIVED_STAGING_PURPOSE,
        "run_id": parent.binding["run_id"],
        "backend": parent.binding["backend"],
        "parent_session_binding_sha256": parent.binding[
            "session_binding_sha256"
        ],
        "staging_root": os.fspath(stage),
        "staging_root_identity_sha256": _mapping_sha(stage_identity),
        "project_root": os.fspath(project),
        "project_root_identity_sha256": _mapping_sha(project_identity),
        "scratchpad": os.fspath(scratch),
        "scratchpad_identity_sha256": _mapping_sha(scratch_identity),
        "writable_namespace": os.fspath(scratch),
        "creator_pid": os.getpid(),
        "interpreter_nonce_sha256": _sha(_INTERPRETER_NONCE.encode("ascii")),
        "native_broker_authority": False,
        "wer_authority": False,
        "population_zero_proven": False,
    }
    binding["session_binding_sha256"] = _mapping_sha(binding)
    record = _StagingSessionRecord(
        token=token,
        creator_pid=os.getpid(),
        interpreter_nonce=_INTERPRETER_NONCE,
        authority_ref=weakref.ref(value),
        binding=MappingProxyType(binding),
        project_root=project,
        project_identity=MappingProxyType(project_identity),
        scratchpad=scratch,
        scratchpad_identity=MappingProxyType(scratch_identity),
        parent_session_id=id(parent_session_authority),
        parent_authority_ref=weakref.ref(parent_session_authority),
        parent_binding_sha256=str(parent.binding["session_binding_sha256"]),
        staging_root=stage,
        staging_root_identity=MappingProxyType(stage_identity),
    )
    with parent.lock:
        _session_record(parent_session_authority)
        with _REGISTRY_LOCK:
            _STAGING_SESSIONS[id(value)] = record
            parent.derived_sessions.add(id(value))
    return value


def require_posix_v2_compat_session(
    value: object,
) -> PosixV2CompatSessionAuthority:
    _session_record(value)
    return value


def _resolve_codex_binary() -> tuple[Path, str, str]:
    located = shutil.which("codex")
    if not located:
        _fail("CODEX_BINARY", "Codex CLI is not available on PATH")
    try:
        binary = Path(located).resolve(strict=True)
    except OSError as exc:
        _fail("CODEX_BINARY", "Codex CLI cannot be resolved", exc)
    descriptor = _open_readonly_nofollow(binary, "Codex CLI")
    assert descriptor is not None
    try:
        observed = os.fstat(descriptor)
        if (
            not binary.is_absolute()
            or not stat.S_ISREG(observed.st_mode)
            or int(observed.st_size) > _MAX_CODEX_BINARY_BYTES
            or observed.st_mode & 0o022
            or observed.st_mode & 0o111 == 0
        ):
            _fail("CODEX_BINARY", "Codex CLI is not a trusted executable file")
        binary_sha = _hash_exact_regular_fd(
            descriptor,
            observed,
            maximum=_MAX_CODEX_BINARY_BYTES,
            label="Codex CLI",
        )
    finally:
        os.close(descriptor)
    try:
        version_result = subprocess.run(
            [os.fspath(binary), "--version"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=10,
            start_new_session=True,
            env=_base_child_environment(),
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        _fail("CODEX_BINARY", "Codex CLI version probe failed", exc)
    version_raw = version_result.stdout.strip()
    if (
        version_result.returncode != 0
        or not version_raw
        or len(version_raw) > 256
    ):
        _fail("CODEX_BINARY", "Codex CLI returned an invalid version")
    try:
        version = version_raw.decode("ascii", errors="strict")
    except UnicodeError as exc:
        _fail("CODEX_BINARY", "Codex CLI version is not ASCII", exc)
    return binary, version, binary_sha


def _resolve_claude_binary() -> dict[str, Any]:
    """Observe the exact host Claude executable without invoking a model."""

    located = shutil.which("claude")
    if not located:
        _fail("CLAUDE_BINARY", "Claude CLI is not available on PATH")
    try:
        binary = Path(located).resolve(strict=True)
    except OSError as exc:
        _fail("CLAUDE_BINARY", "Claude CLI cannot be resolved", exc)
    descriptor = _open_readonly_nofollow(binary, "Claude CLI")
    assert descriptor is not None
    try:
        observed = os.fstat(descriptor)
        if (
            not binary.is_absolute()
            or not stat.S_ISREG(observed.st_mode)
            or int(observed.st_size) <= 0
            or int(observed.st_size) > _MAX_CODEX_BINARY_BYTES
            or observed.st_mode & 0o022
            or observed.st_mode & 0o111 == 0
        ):
            _fail("CLAUDE_BINARY", "Claude CLI is not a trusted executable file")
        binary_sha = _hash_exact_regular_fd(
            descriptor,
            observed,
            maximum=_MAX_CODEX_BINARY_BYTES,
            label="Claude CLI",
        )
        identity = {
            "device": int(observed.st_dev),
            "inode": int(observed.st_ino),
            "mode": stat.S_IMODE(observed.st_mode),
            "size": int(observed.st_size),
            "uid": int(observed.st_uid),
            "gid": int(observed.st_gid),
        }
    finally:
        os.close(descriptor)
    try:
        version_result = subprocess.run(
            [os.fspath(binary), "--version"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=10,
            start_new_session=True,
            env=_base_child_environment(),
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        _fail("CLAUDE_BINARY", "Claude CLI version probe failed", exc)
    version_raw = version_result.stdout
    if (
        version_result.returncode != 0
        or not version_raw
        or len(version_raw) > 256
        or version_result.stderr
    ):
        _fail("CLAUDE_BINARY", "Claude CLI returned an invalid version")
    try:
        version_output = version_raw.decode("ascii", errors="strict")
    except UnicodeError as exc:
        _fail("CLAUDE_BINARY", "Claude CLI version is not ASCII", exc)
    match = re.fullmatch(
        r"([0-9]+\.[0-9]+\.[0-9]+) \(Claude Code\)\n?",
        version_output,
    )
    if match is None:
        _fail("CLAUDE_BINARY", "Claude CLI version output is not canonical")
    try:
        help_result = subprocess.run(
            [os.fspath(binary), "--help"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=10,
            start_new_session=True,
            env=_base_child_environment(),
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        _fail("CLAUDE_BINARY", "Claude CLI capability probe failed", exc)
    help_raw = help_result.stdout
    if (
        help_result.returncode != 0
        or not help_raw
        or len(help_raw) > 256 * 1024
        or help_result.stderr
    ):
        _fail("CLAUDE_BINARY", "Claude CLI returned invalid capability help")
    try:
        help_text = help_raw.decode("utf-8", errors="strict")
    except UnicodeError as exc:
        _fail("CLAUDE_BINARY", "Claude CLI capability help is not UTF-8", exc)
    required_flags = (
        "--add-dir",
        "--disable-slash-commands",
        "--input-format",
        "--mcp-config",
        "--model",
        "--no-chrome",
        "--no-session-persistence",
        "--output-format",
        "--permission-mode",
        "--permission-prompts",
        "--print",
        "--prompt-suggestions",
        "--restricted",
        "--session-id",
        "--setting-sources",
        "--settings",
        "--strict-mcp-config",
        "--tools",
        "--verbose",
    )
    observed_flags = frozenset(
        match.group(1)
        for match in re.finditer(
            r"(?m)^  (?:-[A-Za-z], )?(--[A-Za-z][A-Za-z0-9-]*)\b",
            help_text,
        )
    )
    if not set(required_flags).issubset(observed_flags):
        _fail("CLAUDE_BINARY", "Claude CLI lacks required headless capabilities")

    def option_values(flag: str) -> frozenset[str]:
        block = re.search(
            rf"(?ms)^  (?:-[A-Za-z], )?{re.escape(flag)}(?:\s|=).*?"
            r"(?=^  (?:-[A-Za-z], )?--|\Z)",
            help_text,
        )
        if block is None:
            return frozenset()
        return frozenset(re.findall(r'"([A-Za-z][A-Za-z0-9-]*)"', block.group(0)))

    if (
        not {"text", "stream-json"}.issubset(option_values("--input-format"))
        or not {"text", "json", "stream-json"}.issubset(
            option_values("--output-format")
        )
        or "dontAsk" not in option_values("--permission-mode")
        or "none" not in option_values("--permission-prompts")
    ):
        _fail("CLAUDE_BINARY", "Claude CLI headless choices are incompatible")
    core: dict[str, Any] = {
        "schema": "plamen.posix-v2-compat-claude-executable-observation.v1",
        "backend": "claude",
        "resolved_executable": os.fspath(binary),
        "version": match.group(1),
        "version_output_sha256": _sha(version_raw),
        "help_sha256": _sha(help_raw),
        "help_byte_count": len(help_raw),
        "supported_flags": list(required_flags),
        "executable_sha256": binary_sha,
        "executable_byte_count": int(identity["size"]),
        "identity": identity,
    }
    return {**core, "observation_sha256": _mapping_sha(core)}


def _account_home() -> Path:
    try:
        value = pwd.getpwuid(os.getuid()).pw_dir
        home = Path(value).resolve(strict=True)
    except (KeyError, OSError) as exc:
        _fail("ACCOUNT_HOME", "current account home cannot be resolved", exc)
    if not home.is_dir():
        _fail("ACCOUNT_HOME", "current account home is not a directory")
    return home


def _load_ambient_codex_auth() -> tuple[str, bytes | None, str]:
    """Admit auth without honoring ambient CODEX_HOME path injection."""

    auth_path = _account_home() / ".codex" / "auth.json"
    descriptor = _open_readonly_nofollow(
        auth_path,
        "Codex auth.json",
        missing_ok=True,
    )
    if descriptor is not None:
        try:
            observed = os.fstat(descriptor)
            if (
                not stat.S_ISREG(observed.st_mode)
                or int(observed.st_uid) != os.getuid()
                or stat.S_IMODE(observed.st_mode) & 0o077
                or int(observed.st_size) <= 0
                or int(observed.st_size) > _MAX_AUTH_BYTES
            ):
                _fail(
                    "CODEX_AUTH",
                    "Codex auth.json ownership/mode/type/size is unsafe",
                )
            raw = _read_exact_regular_fd(
                descriptor,
                observed,
                maximum=_MAX_COMPAT_RECEIPT_BYTES,
                label="Codex auth.json",
            )
        finally:
            os.close(descriptor)
        try:
            parsed = json.loads(raw.decode("utf-8", errors="strict"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            _fail("CODEX_AUTH", "Codex auth.json is unreadable or malformed", exc)
        if not isinstance(parsed, dict):
            _fail("CODEX_AUTH", "Codex auth.json is not a JSON object")
        return "PRIVATE_AUTH_JSON_COPY", raw, _sha(raw)
    keys = [
        (name, os.environ.get(name))
        for name in ("CODEX_API_KEY", "OPENAI_API_KEY")
        if os.environ.get(name)
    ]
    if len(keys) != 1 or "\x00" in str(keys[0][1]):
        _fail("CODEX_AUTH", "exactly one safe Codex/API-key authority is required")
    return f"AMBIENT_{keys[0][0]}", None, _sha(str(keys[0][1]).encode("utf-8"))


def _base_child_environment() -> dict[str, str]:
    try:
        account_name = pwd.getpwuid(os.getuid()).pw_name
    except (KeyError, OSError) as exc:
        _fail("CHILD_ENVIRONMENT", "current account name is unavailable", exc)
    environment = {
        "HOME": os.fspath(_account_home()),
        "PATH": os.environ.get(
            "PATH", "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin"
        ),
        "TERM": "dumb",
        "NO_COLOR": "1",
        "LC_ALL": os.environ.get("LC_ALL", "C.UTF-8"),
        # Current Claude native subscription discovery uses the account name
        # to select its macOS Keychain item.  Bind the trusted passwd value;
        # never inherit an ambient USER substitution.
        "USER": account_name,
    }
    for name, value in environment.items():
        if not value or "\x00" in value:
            _fail("CHILD_ENVIRONMENT", f"child environment {name} is invalid")
    return environment


def _normalize_writable_directories(
    values: Sequence[str | Path],
    *,
    record: _SessionRecord,
) -> tuple[Path, ...]:
    if isinstance(values, (str, bytes)) or len(values) > _MAX_WRITABLE_DIRECTORIES:
        _fail("WRITABLE_DIRECTORIES", "writable directory set is malformed")
    result: list[Path] = []
    for index, value in enumerate(values):
        path, _ = _safe_directory(value, f"writable directory {index}")
        if not _is_within(path, record.scratchpad):
            _fail(
                "WRITABLE_DIRECTORIES",
                "compatibility write authority is limited to scratchpad descendants",
            )
        result.append(path)
    if len(set(result)) != len(result):
        _fail("WRITABLE_DIRECTORIES", "writable directories contain duplicates")
    return tuple(sorted(result, key=lambda path: os.path.normcase(str(path))))


def _write_absent_bytes(path: Path, raw: bytes, mode: int) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
        mode,
    )
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        os.close(descriptor)


def _replace_bytes(path: Path, raw: bytes, mode: int = 0o600) -> None:
    temporary = path.with_name(f".{path.name}.tmp-{uuid.uuid4().hex}")
    try:
        _write_absent_bytes(temporary, raw, mode)
        os.replace(temporary, path)
        descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    finally:
        with contextlib.suppress(OSError):
            temporary.unlink()


def _persist_receipt(directory: Path, stem: str, payload: dict[str, Any]) -> Path:
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    if directory.is_symlink() or not directory.is_dir():
        _fail("RECEIPT", "compatibility receipt directory is unsafe")
    payload["receipt_sha256"] = _mapping_sha(payload)
    path = directory / f"{stem}.json"
    raw = _canonical_bytes(payload) + b"\n"
    if len(raw) > _MAX_COMPAT_RECEIPT_BYTES:
        _fail("RECEIPT", "compatibility receipt exceeds its bound")
    _write_absent_bytes(path, raw, 0o400)
    descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return path


def replay_posix_v2_compat_execution_receipt(
    value: Mapping[str, Any],
    *,
    expected_backend: str,
    require_completed: bool = True,
) -> Mapping[str, Any]:
    """Replay one self-bound receipt and its exact provider-specific evidence."""

    backend = _identifier(expected_backend, "expected compatibility backend")
    if backend not in _COMPAT_BACKENDS:
        _fail("RECEIPT_REPLAY", "expected compatibility backend is unsupported")
    if not isinstance(value, Mapping) or type(require_completed) is not bool:
        _fail("RECEIPT_REPLAY", "compatibility receipt is malformed")
    try:
        receipt = json.loads(_canonical_bytes(value).decode("ascii"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        _fail("RECEIPT_REPLAY", "compatibility receipt is not canonical", exc)
    claimed = receipt.pop("receipt_sha256", None)
    if (
        receipt.get("schema") != RECEIPT_SCHEMA
        or receipt.get("mode") != COMPATIBILITY_MODE
        or receipt.get("backend") != backend
        or not isinstance(claimed, str)
        or not re.fullmatch(r"[0-9a-f]{64}", claimed)
        or claimed != _mapping_sha(receipt)
    ):
        _fail("RECEIPT_REPLAY", "compatibility receipt binding is invalid")
    receipt["receipt_sha256"] = claimed
    if require_completed and (
        receipt.get("status") != "COMPLETED"
        or receipt.get("failure_code") is not None
        or receipt.get("compatibility_return_value") != 0
        or not isinstance(receipt.get("completed_output_evidence"), list)
        or not receipt["completed_output_evidence"]
        or not provider_transport_completion_is_admitted(receipt)
    ):
        _fail("RECEIPT_REPLAY", "compatibility receipt is not completed")
    provider = receipt.get("provider_execution")
    if backend == "codex":
        if provider is not None:
            _fail("RECEIPT_REPLAY", "Codex receipt contains Claude evidence")
        return MappingProxyType(receipt)
    if provider is None and receipt.get("status") != "COMPLETED":
        return MappingProxyType(receipt)
    provider_fields = {
        "schema",
        "provider_session_id",
        "executable_observation_sha256",
        "executable_observation",
        "executable_path",
        "executable_version",
        "executable_sha256",
        "provider_plan_sha256",
        "provider_plan",
        "profile_sha256",
        "expected_init_contract_sha256",
        "expected_version",
        "auth_mode",
        "auth_binding_sha256",
        "completion_evidence",
        "reduced_isolation",
        "native_broker_authority",
        "wer_authority",
    }
    if not isinstance(provider, Mapping) or set(provider) != provider_fields:
        _fail("RECEIPT_REPLAY", "Claude provider evidence denominator changed")
    plan = provider.get("provider_plan")
    observation = provider.get("executable_observation")
    completion = provider.get("completion_evidence")
    if not isinstance(plan, Mapping) or not isinstance(observation, Mapping):
        _fail("RECEIPT_REPLAY", "Claude plan/executable evidence is malformed")
    unsigned_observation = dict(observation)
    observation_sha = unsigned_observation.pop("observation_sha256", None)
    if (
        provider.get("schema")
        != "plamen.posix_v2_compat_claude_execution.v1"
        or provider.get("reduced_isolation") is not True
        or provider.get("native_broker_authority") is not False
        or provider.get("wer_authority") is not False
        or observation_sha != _mapping_sha(unsigned_observation)
        or provider.get("executable_observation_sha256") != observation_sha
        or plan.get("executable_observation_sha256") != observation_sha
        or provider.get("executable_path")
        != observation.get("resolved_executable")
        or provider.get("executable_version") != observation.get("version")
        or provider.get("executable_sha256")
        != observation.get("executable_sha256")
        or provider.get("provider_plan_sha256") != plan.get("plan_sha256")
        or provider.get("profile_sha256") != plan.get("profile_sha256")
        or provider.get("expected_init_contract_sha256")
        != plan.get("expected_init_contract_sha256")
        or provider.get("expected_version") != plan.get("expected_version")
        or provider.get("auth_mode") != plan.get("auth_mode")
        or provider.get("auth_binding_sha256")
        != plan.get("auth_binding_sha256")
        or receipt.get("requested_model") != plan.get("model")
        or receipt.get("phase_io_contract_digest")
        != plan.get("phase_io_contract_digest")
        or receipt.get("phase_io_launch_digest")
        != plan.get("phase_io_launch_digest")
        or receipt.get("session_binding_sha256")
        != plan.get("session_binding_sha256")
    ):
        _fail("RECEIPT_REPLAY", "Claude provider evidence binding changed")
    if require_completed:
        if not isinstance(completion, Mapping):
            _fail("RECEIPT_REPLAY", "Claude completion evidence is missing")
        try:
            from posix_v2_compat_claude import (
                replay_posix_v2_compat_claude_completion,
            )

            replayed = replay_posix_v2_compat_claude_completion(plan, completion)
        except Exception as exc:
            _fail("RECEIPT_REPLAY", "Claude completion evidence does not replay", exc)
        if (
            replayed.get("status") != "COMPLETED"
            or replayed.get("observed_model") != receipt.get("observed_model")
        ):
            _fail("RECEIPT_REPLAY", "Claude completion/model binding changed")
    return MappingProxyType(receipt)


class _BoundedReader:
    def __init__(self, stream: Any, ceiling: int, name: str) -> None:
        self._stream = stream
        self._ceiling = ceiling
        self._name = name
        self._raw = bytearray()
        self.overflow = False
        self.error: BaseException | None = None
        self.last_activity = time.monotonic()
        self.done = threading.Event()
        self._thread = threading.Thread(
            target=self._read, name=f"plamen-compat-{name}", daemon=True
        )
        self._thread.start()

    def _read(self) -> None:
        try:
            while True:
                chunk = self._stream.read(64 * 1024)
                if not chunk:
                    return
                self.last_activity = time.monotonic()
                if len(self._raw) + len(chunk) > self._ceiling:
                    remaining = max(0, self._ceiling - len(self._raw))
                    self._raw.extend(chunk[:remaining])
                    self.overflow = True
                    return
                self._raw.extend(chunk)
        except BaseException as exc:
            self.error = exc
        finally:
            self.done.set()

    def result(self, timeout: float = 10.0) -> bytes:
        self._thread.join(timeout)
        if self._thread.is_alive():
            _fail("STREAM", f"{self._name} reader did not terminate")
        if self.error is not None:
            _fail("STREAM", f"{self._name} reader failed", self.error)
        return bytes(self._raw)


def _stream_stalled(
    now: float, *readers: _BoundedReader, budget_s: float | None = None,
) -> bool:
    """True when no reader has received a byte for the inactivity budget."""

    budget = _STREAM_INACTIVITY_S if budget_s is None else float(budget_s)
    if budget <= 0:
        return False
    last = max(reader.last_activity for reader in readers)
    return (now - last) >= budget


def _terminate_group(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        # The leader may have exited while descendants remain in its group.
        with contextlib.suppress(ProcessLookupError, OSError):
            os.killpg(process.pid, signal.SIGKILL)
        return
    with contextlib.suppress(ProcessLookupError, OSError):
        os.killpg(process.pid, signal.SIGTERM)
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        with contextlib.suppress(ProcessLookupError, OSError):
            os.killpg(process.pid, signal.SIGKILL)
        with contextlib.suppress(subprocess.TimeoutExpired):
            process.wait(timeout=5)


def _process_group_empty(process_group_id: int) -> bool:
    deadline = time.monotonic() + 5.0
    while True:
        try:
            os.killpg(process_group_id, 0)
        except ProcessLookupError:
            return True
        except OSError:
            return False
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.02)


def _path_without_symlink_components(
    root: Path,
    relative: str,
    *,
    label: str,
    allow_missing_leaf: bool,
) -> Path:
    """Resolve one canonical relative route without following path aliases."""

    if type(relative) is not str or not relative or "\x00" in relative:
        _fail("PHASE_IO_ROUTE", f"{label} path is malformed")
    candidate = Path(relative)
    if (
        candidate.is_absolute()
        or candidate.as_posix() != relative
        or any(part in {"", ".", ".."} for part in candidate.parts)
    ):
        _fail("PHASE_IO_ROUTE", f"{label} path is not canonical and relative")
    current = root
    for index, part in enumerate(candidate.parts):
        current = current / part
        try:
            observed = current.lstat()
        except FileNotFoundError:
            if allow_missing_leaf:
                return root / candidate
            _fail("PHASE_IO_ROUTE", f"{label} route is missing")
        except OSError as exc:
            _fail("PHASE_IO_ROUTE", f"{label} route cannot be inspected", exc)
        if stat.S_ISLNK(observed.st_mode):
            _fail("PHASE_IO_ROUTE", f"{label} route contains a symlink")
        if index < len(candidate.parts) - 1 and not stat.S_ISDIR(observed.st_mode):
            _fail("PHASE_IO_ROUTE", f"{label} parent is not a directory")
    return current


def _canonical_prompt_json(value: object) -> str:
    """Render inert prompt data without Markdown/delimiter injection."""

    try:
        rendered = json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    except (TypeError, ValueError, UnicodeError) as exc:
        _fail("PHASE_IO_ROUTE", "routing data is not canonical JSON", exc)
    return (
        rendered.replace("`", "\\u0060")
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
    )


def _compile_phase_io_provider_prompt(
    *,
    canonical_prompt: str,
    contract: PhaseIOContract,
    launch: LaunchSpec,
    record: _SessionRecord,
    run_id: str,
    expected_outputs: Sequence[str],
    output_staging_root: Path,
) -> tuple[bytes, dict[str, Any]]:
    """Compile local provider routing from a sealed INPUTS_BOUND PhaseIO pair.

    Logical ``scratchpad:`` names are data-plane identities, not MCP tool
    names.  This compatibility projection keeps the compiled methodology
    prompt byte-for-byte intact and adds a provider-only transport suffix.
    """

    try:
        contract, launch = replay_phase_io_authority_pair(contract, launch)
    except (TypeError, ValueError) as exc:
        _fail("PHASE_IO_AUTHORITY", "contract/launch authority replay failed", exc)
    if (
        contract.backend != record.binding["backend"]
        or launch.backend != record.binding["backend"]
        or launch.work_unit_key != contract.key
        or not contract.model_invoked
    ):
        _fail(
            "PHASE_IO_AUTHORITY",
            "contract/launch differs from the compatibility backend MODEL leaf",
        )

    issues = validate_work_unit_inputs(
        record.scratchpad,
        record.project_root,
        contract,
        launch,
        run_id=run_id,
    )
    fatal_issues = [
        issue
        for issue in issues
        if "semantic input missing at binding" not in issue
    ]
    if fatal_issues:
        _fail(
            "PHASE_IO_INPUT_DRIFT",
            "bound PhaseIO authority is invalid: " + "; ".join(fatal_issues),
        )

    ledger = read_artifact_ledger(record.scratchpad)
    unit = ledger.get("work_units", {}).get(contract.key)
    if (
        not isinstance(unit, Mapping)
        or unit.get("run_id") != run_id
        or unit.get("contract_digest") != contract.digest
        or unit.get("launch_digest") != launch.digest
        or unit.get("semantic_status") != "INPUTS_BOUND"
        or unit.get("execution_state") != "INPUTS_BOUND_PREEXECUTION"
    ):
        _fail("PHASE_IO_AUTHORITY", "work unit is not exactly INPUTS_BOUND")
    bindings = unit.get("input_bindings")
    prestates = unit.get("output_prestates")
    input_identities = tuple(sorted({
        *contract.immutable_inputs,
        *contract.bounded_lookup_inputs,
    }))
    output_specs = tuple(sorted(contract.outputs, key=lambda item: item.identity))
    if (
        not isinstance(bindings, Mapping)
        or set(bindings) != set(input_identities)
        or not isinstance(prestates, Mapping)
        or set(prestates) != {item.identity for item in output_specs}
    ):
        _fail("PHASE_IO_AUTHORITY", "PhaseIO ledger denominator is malformed")

    expected = tuple(sorted(str(value) for value in expected_outputs))
    contract_outputs = tuple(
        item.identity.removeprefix("scratchpad:") for item in output_specs
    )
    if (
        any(
            item.root != "scratchpad" or item.writer != "MODEL"
            for item in output_specs
        )
        or contract_outputs != expected
    ):
        _fail("PHASE_IO_OUTPUTS", "expected outputs differ from MODEL PhaseIO")

    input_routes: list[dict[str, Any]] = []
    output_routes: list[dict[str, Any]] = []
    physical_keys: set[str] = set()
    for identity in input_identities:
        root_name, relative = identity.split(":", 1)
        route_root = (
            record.scratchpad if root_name == "scratchpad" else record.project_root
        )
        if root_name not in {"scratchpad", "project"}:
            _fail("PHASE_IO_ROUTE", "input route has an unsupported root")
        binding = bindings[identity]
        if not isinstance(binding, Mapping):
            _fail("PHASE_IO_ROUTE", f"input binding is malformed: {identity}")
        missing = binding.get("status") == "MISSING"
        path = _path_without_symlink_components(
            route_root,
            relative,
            label=f"input {identity}",
            allow_missing_leaf=missing,
        )
        physical_key = os.path.normcase(os.fspath(path))
        if physical_key in physical_keys:
            _fail("PHASE_IO_ROUTE", "PhaseIO routes contain a physical alias")
        physical_keys.add(physical_key)
        input_routes.append({
            "identity": identity,
            "path": os.fspath(path),
            "class": (
                "IMMUTABLE"
                if identity in contract.immutable_inputs
                else "BOUNDED_LOOKUP"
            ),
            "binding_status": str(binding.get("status") or ""),
            "sha256": str(binding.get("sha256") or ""),
            "size": int(binding.get("size") or 0),
        })

    for spec in output_specs:
        relative = spec.identity.removeprefix("scratchpad:")
        prestate = prestates[spec.identity]
        if not isinstance(prestate, Mapping):
            _fail("PHASE_IO_ROUTE", f"output prestate is malformed: {spec.identity}")
        canonical_path = _path_without_symlink_components(
            record.scratchpad,
            relative,
            label=f"output {spec.identity}",
            allow_missing_leaf=not bool(prestate.get("existed")),
        )
        staged_relative = (
            output_staging_root.relative_to(record.scratchpad) / relative
        ).as_posix()
        path = _path_without_symlink_components(
            record.scratchpad,
            staged_relative,
            label=f"staged output {spec.identity}",
            allow_missing_leaf=True,
        )
        physical_key = os.path.normcase(os.fspath(path))
        if physical_key in physical_keys:
            _fail("PHASE_IO_ROUTE", "PhaseIO routes contain a physical alias")
        physical_keys.add(physical_key)
        output_routes.append({
            "identity": spec.identity,
            "path": os.fspath(path),
            "canonical_path": os.fspath(canonical_path),
            "write_mode": spec.write_mode,
            "prestate_status": str(prestate.get("status") or ""),
            "prestate_existed": bool(prestate.get("existed")),
            "prestate_sha256": str(prestate.get("sha256") or ""),
            "prestate_size": int(prestate.get("size") or 0),
        })

    routing = {
        "schema": (
            "plamen.posix_v2_codex_local_phaseio.v1"
            if record.binding["backend"] == "codex"
            else "plamen.posix_v2_claude_local_phaseio.v1"
        ),
        "project_source_root": os.fspath(record.project_root),
        "project_source_access": "READ_ONLY_BY_INSTRUCTION",
        "input_routes": input_routes,
        "output_routes": output_routes,
    }
    routing[
        (
            "codex_working_directory"
            if record.binding["backend"] == "codex"
            else "claude_working_directory"
        )
    ] = os.fspath(record.scratchpad)
    routing_raw = _canonical_bytes(routing)
    local_tool_wording = (
        "Use Codex local filesystem tools, and only already permitted narrowly "
        "scoped shell commands, to:"
        if record.binding["backend"] == "codex"
        else "Use the available Claude file tools to:"
    )
    output_destination_lines = "\n".join(
        f"{index}. {route['write_mode']} artifact "
        f"{_canonical_prompt_json(route['identity'])} at this exact absolute "
        f"path: {_canonical_prompt_json(route['path'])}"
        for index, route in enumerate(output_routes, start=1)
    )
    suffix = """

# PROVIDER-EFFECTIVE LOCAL PHASEIO ROUTING

The Plamen application generated this local file map for the current task.
It does not change the user's task or add permissions. `scratchpad:` is a
logical artifact label, not an MCP namespace.
No Plamen MCP server or PhaseIO tool is required.
References to PROJECT_ROOT or `.` in the task mean the
absolute, read-only `project_source_root` below. The process working directory
is the scratchpad, not the project source root.

""" + local_tool_wording + """
(1) inspect source files beneath `project_source_root` without changing them;
(2) read the exact existing `input_routes`; and (3) create or replace every
exact `output_routes[].path`. These routing instructions do not authorize
builds, tests, package installation, network access, arbitrary commands,
alternate input discovery, or any other write. Do not create, modify, rename,
or delete any file except the exact assigned output paths. Every assigned
output must be a non-empty regular file when you finish.

Required deliverable destinations:
""" + output_destination_lines + """

Every output route's `path` is an invocation-private staged file, never the
canonical artifact. For `CREATE` and `REPLACE`, write the complete proposed
artifact to `path`. For `APPEND`, write only the new suffix to `path`; never
copy, rewrite, normalize, or modify `canonical_path`. The supervisor validates
the exact staged bytes and atomically publishes them only after the provider
exits successfully.

The canonical JSON below records the same application-generated routes. Its
`path` fields are the exact local paths used by the instructions above; its
other values describe the bound inputs, outputs, and access classes and do not
expand the task or permissions.

```json
""" + _canonical_prompt_json(routing) + """
```
"""
    provider_raw = (canonical_prompt.rstrip() + suffix).encode(
        "utf-8", errors="strict"
    )
    evidence = {
        "phase_io_contract_digest": contract.digest,
        "phase_io_launch_digest": launch.digest,
        "input_set_digest": str(unit.get("input_set_digest") or ""),
        "output_prestate_digest": str(unit.get("output_prestate_digest") or ""),
        "input_routes_digest": _sha(_canonical_bytes({"routes": input_routes})),
        "output_routes_digest": _sha(_canonical_bytes({"routes": output_routes})),
        "routing_digest": _sha(routing_raw),
        "input_bindings": {
            identity: dict(bindings[identity]) for identity in input_identities
        },
        "input_routes": input_routes,
        "output_routes": output_routes,
    }
    return provider_raw, evidence


def _admit_expected_outputs(root: Path, names: Sequence[str]) -> tuple[Path, ...]:
    """Validate output leaves and prepare only their parent directories.

    A compatibility invocation must not manufacture an apparently produced
    artifact before the provider process exists.  In particular, a failed
    Codex-binary/auth/Popen admission used to leave zero-byte leaf files that
    the retry authority correctly classified as unowned existing output.
    Missing leaves are therefore left absent for the admitted provider to
    create.  Existing leaves are validated but never opened or modified here.
    """

    if isinstance(names, (str, bytes)):
        _fail("EXPECTED_OUTPUTS", "expected outputs must be a sequence")
    admitted: list[Path] = []
    physical_keys: set[str] = set()
    for name in names:
        if type(name) is not str or not name or "\x00" in name:
            _fail("EXPECTED_OUTPUTS", "expected output name is malformed")
        path = _path_without_symlink_components(
            root,
            name,
            label=f"expected output {name}",
            allow_missing_leaf=True,
        )
        physical_key = os.path.normcase(os.fspath(path))
        if physical_key in physical_keys:
            _fail("EXPECTED_OUTPUTS", "expected outputs contain an alias")
        physical_keys.add(physical_key)
        if path.exists():
            observed = path.lstat()
            if (
                stat.S_ISLNK(observed.st_mode)
                or not stat.S_ISREG(observed.st_mode)
                or int(observed.st_nlink) != 1
            ):
                _fail("EXPECTED_OUTPUTS", "expected output is not a regular file")
        admitted.append(path)
    for path in admitted:
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        _path_without_symlink_components(
            root,
            path.relative_to(root).as_posix(),
            label=f"expected output {path.name}",
            allow_missing_leaf=True,
        )
    return tuple(admitted)


def _validate_completed_outputs(
    root: Path,
    paths: Sequence[Path],
) -> list[dict[str, Any]]:
    evidence: list[dict[str, Any]] = []
    physical_ids: set[tuple[int, int]] = set()
    for path in paths:
        try:
            lexical = path.lstat()
        except FileNotFoundError:
            _fail("EXPECTED_OUTPUT_MISSING", "completed output is absent")
        except OSError as exc:
            _fail(
                "EXPECTED_OUTPUT_MISSING",
                "completed output cannot be inspected",
                exc,
            )
        if stat.S_ISLNK(lexical.st_mode):
            _fail("EXPECTED_OUTPUT_ALIAS", "completed output is a symlink")
        _path_without_symlink_components(
            root,
            path.relative_to(root).as_posix(),
            label=f"completed output {path.name}",
            allow_missing_leaf=False,
        )
        descriptor = _open_readonly_nofollow(path, "completed PhaseIO output")
        assert descriptor is not None
        try:
            observed = os.fstat(descriptor)
            if (
                not stat.S_ISREG(observed.st_mode)
                or int(observed.st_nlink) != 1
                or int(observed.st_size) <= 0
                or int(observed.st_size) > _MAX_PHASE_IO_OUTPUT_BYTES
            ):
                _fail(
                    "EXPECTED_OUTPUT_MISSING",
                    "completed output is absent, empty, aliased, or oversized",
                )
            physical_id = (int(observed.st_dev), int(observed.st_ino))
            if physical_id in physical_ids:
                _fail("EXPECTED_OUTPUT_ALIAS", "completed outputs share one inode")
            physical_ids.add(physical_id)
            digest = _hash_exact_regular_fd(
                descriptor,
                observed,
                maximum=_MAX_PHASE_IO_OUTPUT_BYTES,
                label="completed PhaseIO output",
            )
            evidence.append({
                "path": os.fspath(path),
                "size": int(observed.st_size),
                "sha256": digest,
                "device": int(observed.st_dev),
                "inode": int(observed.st_ino),
            })
        finally:
            os.close(descriptor)
    return evidence


def _read_completed_output_bytes(root: Path, path: Path, label: str) -> bytes:
    """Read one already-admitted output without following a replaced leaf."""

    relative = path.relative_to(root).as_posix()
    _path_without_symlink_components(
        root,
        relative,
        label=label,
        allow_missing_leaf=False,
    )
    descriptor = _open_readonly_nofollow(path, label)
    assert descriptor is not None
    try:
        observed = os.fstat(descriptor)
        return _read_exact_regular_fd(
            descriptor,
            observed,
            maximum=_MAX_PHASE_IO_OUTPUT_BYTES,
            label=label,
        )
    finally:
        os.close(descriptor)


def _read_canonical_prestate_bytes(root: Path, path: Path, label: str) -> bytes:
    """Read a possibly-empty regular canonical prestate through an exact fd."""

    relative = path.relative_to(root).as_posix()
    _path_without_symlink_components(
        root,
        relative,
        label=label,
        allow_missing_leaf=False,
    )
    descriptor = _open_readonly_nofollow(path, label)
    assert descriptor is not None
    try:
        observed = os.fstat(descriptor)
        size = int(observed.st_size)
        if (
            not stat.S_ISREG(observed.st_mode)
            or int(observed.st_nlink) != 1
            or size < 0
            or size > _MAX_PHASE_IO_OUTPUT_BYTES
        ):
            _fail("OUTPUT_PRESTATE", f"{label} type or size is unsafe")
        chunks: list[bytes] = []
        remaining = size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 1024 * 1024))
            if not chunk:
                _fail("OUTPUT_PRESTATE", f"{label} ended before its admitted size")
            chunks.append(chunk)
            remaining -= len(chunk)
        extra = os.read(descriptor, 1)
        after = os.fstat(descriptor)
        if extra or _stable_file_identity(after) != _stable_file_identity(observed):
            _fail("OUTPUT_PRESTATE", f"{label} changed while being frozen")
        return b"".join(chunks)
    except OSError as exc:
        _fail("OUTPUT_PRESTATE", f"{label} cannot be read", exc)
    finally:
        os.close(descriptor)


@dataclass(frozen=True)
class _CanonicalOutputPrestate:
    path: Path
    existed: bool
    raw: bytes
    mode: int
    device: int
    inode: int
    owner: int
    group: int
    links: int
    mtime_ns: int


def _capture_canonical_output_prestates(
    root: Path,
    output_routes: Sequence[Mapping[str, Any]],
) -> dict[str, _CanonicalOutputPrestate]:
    """Freeze the exact present/absent state of every canonical MODEL output."""

    prestates: dict[str, _CanonicalOutputPrestate] = {}
    for route in output_routes:
        identity = str(route.get("identity") or "")
        canonical = Path(str(route.get("canonical_path") or ""))
        if identity in prestates:
            _fail("OUTPUT_PRESTATE", "canonical output identity is duplicated")
        _path_without_symlink_components(
            root,
            canonical.relative_to(root).as_posix(),
            label=f"canonical prestate {identity}",
            allow_missing_leaf=True,
        )
        try:
            observed = canonical.lstat()
        except FileNotFoundError:
            existed = False
            raw = b""
            mode = 0o600
            device = inode = owner = group = links = mtime_ns = 0
        except OSError as exc:
            _fail("OUTPUT_PRESTATE", f"canonical prestate is unavailable: {identity}", exc)
        else:
            if stat.S_ISLNK(observed.st_mode) or not stat.S_ISREG(observed.st_mode):
                _fail("OUTPUT_PRESTATE", f"canonical prestate is unsafe: {identity}")
            existed = True
            mode = stat.S_IMODE(observed.st_mode)
            device = int(observed.st_dev)
            inode = int(observed.st_ino)
            owner = int(observed.st_uid)
            group = int(observed.st_gid)
            links = int(observed.st_nlink)
            mtime_ns = int(observed.st_mtime_ns)
            raw = _read_canonical_prestate_bytes(
                root, canonical, f"canonical prestate {identity}"
            )
        if (
            existed != bool(route.get("prestate_existed"))
            or len(raw) != int(route.get("prestate_size", -1))
            or (existed and _sha(raw) != str(route.get("prestate_sha256") or ""))
            or (not existed and str(route.get("prestate_sha256") or ""))
        ):
            _fail(
                "OUTPUT_PRESTATE_DRIFT",
                f"canonical prestate differs from PhaseIO: {identity}",
            )
        prestates[identity] = _CanonicalOutputPrestate(
            path=canonical,
            existed=existed,
            raw=raw,
            mode=mode,
            device=device,
            inode=inode,
            owner=owner,
            group=group,
            links=links,
            mtime_ns=mtime_ns,
        )
    return prestates


def _canonical_output_matches_prestate(
    root: Path,
    identity: str,
    prestate: _CanonicalOutputPrestate,
) -> bool:
    try:
        _path_without_symlink_components(
            root,
            prestate.path.relative_to(root).as_posix(),
            label=f"canonical replay {identity}",
            allow_missing_leaf=True,
        )
        observed = prestate.path.lstat()
    except FileNotFoundError:
        return not prestate.existed
    except (OSError, PosixV2CompatRuntimeError):
        return False
    if not prestate.existed or not stat.S_ISREG(observed.st_mode):
        return False
    try:
        current = _read_canonical_prestate_bytes(
            root, prestate.path, f"canonical replay {identity}"
        )
    except PosixV2CompatRuntimeError:
        return False
    return bool(
        current == prestate.raw
        and stat.S_IMODE(observed.st_mode) == prestate.mode
        and int(observed.st_dev) == prestate.device
        and int(observed.st_ino) == prestate.inode
        and int(observed.st_uid) == prestate.owner
        and int(observed.st_gid) == prestate.group
        and int(observed.st_nlink) == prestate.links
        and int(observed.st_mtime_ns) == prestate.mtime_ns
    )


def _restore_changed_canonical_prestates(
    root: Path,
    prestates: Mapping[str, _CanonicalOutputPrestate],
) -> bool:
    """Restore direct provider writes without following an introduced symlink."""

    changed = False
    for identity, prestate in prestates.items():
        if _canonical_output_matches_prestate(root, identity, prestate):
            continue
        changed = True
        parent_relative = prestate.path.parent.relative_to(root).as_posix()
        if parent_relative != ".":
            _path_without_symlink_components(
                root,
                parent_relative,
                label=f"canonical restoration parent {identity}",
                allow_missing_leaf=False,
            )
        if prestate.existed:
            _replace_bytes(prestate.path, prestate.raw, prestate.mode)
            try:
                os.chmod(prestate.path, prestate.mode, follow_symlinks=False)
                os.chown(
                    prestate.path,
                    prestate.owner,
                    prestate.group,
                    follow_symlinks=False,
                )
                os.utime(
                    prestate.path,
                    ns=(prestate.mtime_ns, prestate.mtime_ns),
                    follow_symlinks=False,
                )
            except OSError as exc:
                _fail(
                    "CANONICAL_RESTORE",
                    f"canonical metadata cannot be restored: {identity}",
                    exc,
                )
            continue
        try:
            observed = prestate.path.lstat()
        except FileNotFoundError:
            continue
        except OSError as exc:
            _fail("CANONICAL_RESTORE", f"canonical output cannot be restored: {identity}", exc)
        if stat.S_ISDIR(observed.st_mode):
            _fail("CANONICAL_RESTORE", f"canonical output became a directory: {identity}")
        try:
            prestate.path.unlink()
        except OSError as exc:
            _fail("CANONICAL_RESTORE", f"canonical output cannot be removed: {identity}", exc)
    return changed


def _read_staged_output_denominator(
    root: Path,
    output_routes: Sequence[Mapping[str, Any]],
) -> dict[str, bytes]:
    staged: dict[str, bytes] = {}
    physical_ids: set[tuple[int, int]] = set()
    for route in output_routes:
        path = Path(str(route.get("path") or ""))
        identity = str(route.get("identity") or "")
        if identity in staged:
            _fail("STAGED_OUTPUT", "staged output identity is duplicated")
        try:
            lexical = path.lstat()
        except FileNotFoundError:
            _fail("EXPECTED_OUTPUT_MISSING", "completed staged output is absent")
        except OSError as exc:
            _fail(
                "EXPECTED_OUTPUT_MISSING",
                "completed staged output cannot be inspected",
                exc,
            )
        if stat.S_ISLNK(lexical.st_mode):
            _fail("EXPECTED_OUTPUT_ALIAS", "completed staged output is a symlink")
        _path_without_symlink_components(
            root,
            path.relative_to(root).as_posix(),
            label=f"staged output {identity}",
            allow_missing_leaf=False,
        )
        descriptor = _open_readonly_nofollow(path, f"staged output {identity}")
        assert descriptor is not None
        try:
            observed = os.fstat(descriptor)
            if int(observed.st_nlink) != 1:
                _fail("EXPECTED_OUTPUT_ALIAS", "staged output has multiple links")
            physical_id = (int(observed.st_dev), int(observed.st_ino))
            if physical_id in physical_ids:
                _fail("EXPECTED_OUTPUT_ALIAS", "staged outputs share one inode")
            physical_ids.add(physical_id)
            staged[identity] = _read_exact_regular_fd(
                descriptor,
                observed,
                maximum=_MAX_PHASE_IO_OUTPUT_BYTES,
                label=f"staged output {identity}",
            )
        finally:
            os.close(descriptor)
    return staged


def _recover_single_staged_output_from_provider_last_message(
    root: Path,
    output_routes: Sequence[Mapping[str, Any]],
    provider_last_message: bytes | None,
    *,
    semantic_gate_available: bool,
) -> dict[str, Any]:
    """Project one exact Codex final response into one missing staged route.

    Codex has two output channels: filesystem tools and the explicit
    ``--output-last-message`` file owned by the CLI.  Agents occasionally
    return the complete requested artifact through the latter while omitting
    the routed filesystem write.  Treating that as a provider failure throws
    away semantically valid work and couples correctness to tool-use syntax.

    Recovery is deliberately narrow and non-transforming.  It is available
    only when one route is missing, the CLI supplied fresh non-empty bytes,
    and a frozen semantic validator will adjudicate those exact bytes before
    the ordinary atomic publication transaction.  Multi-output invocations
    remain ambiguous and fail closed.  No Markdown fence stripping, JSON
    parsing, repair, or canonicalization occurs here.
    """

    evidence: dict[str, Any] = {
        "schema": "plamen.posix_v2_codex_last_message_projection.v1",
        "status": "NOT_NEEDED",
        "projection": "EXACT_PROVIDER_LAST_MESSAGE_BYTES",
    }
    missing_routes: list[Mapping[str, Any]] = []
    for route in output_routes:
        staged_path = Path(str(route.get("path") or ""))
        try:
            staged_path.lstat()
        except FileNotFoundError:
            missing_routes.append(route)
        except OSError:
            evidence["status"] = "STAGED_ROUTE_UNINSPECTABLE"
            return evidence
    if not missing_routes:
        return evidence
    if len(output_routes) != 1 or len(missing_routes) != 1:
        evidence["status"] = "AMBIGUOUS_OUTPUT_DENOMINATOR"
        return evidence
    if not semantic_gate_available:
        evidence["status"] = "SEMANTIC_GATE_UNAVAILABLE"
        return evidence
    if provider_last_message is None:
        evidence["status"] = "PROVIDER_LAST_MESSAGE_UNAVAILABLE"
        return evidence
    if (
        not provider_last_message
        or len(provider_last_message) > _MAX_PHASE_IO_OUTPUT_BYTES
    ):
        evidence["status"] = "PROVIDER_LAST_MESSAGE_SIZE_UNSAFE"
        return evidence
    route = missing_routes[0]
    staged_path = Path(str(route.get("path") or ""))
    identity = str(route.get("identity") or "")
    try:
        relative = staged_path.relative_to(root).as_posix()
    except ValueError:
        evidence["status"] = "STAGED_ROUTE_OUTSIDE_SCRATCHPAD"
        return evidence
    _path_without_symlink_components(
        root,
        relative,
        label=f"last-message recovery route {identity}",
        allow_missing_leaf=True,
    )
    try:
        _write_absent_bytes(staged_path, provider_last_message, 0o600)
    except OSError as exc:
        evidence["status"] = "STAGED_ROUTE_WRITE_FAILED"
        evidence["error_type"] = type(exc).__name__
        return evidence
    evidence.update({
        "status": "RECOVERED_PENDING_SEMANTIC_VALIDATION",
        "identity": identity,
        "path": os.fspath(staged_path),
        "sha256": _sha(provider_last_message),
        "size": len(provider_last_message),
    })
    return evidence


def _publish_staged_outputs(
    root: Path,
    output_routes: Sequence[Mapping[str, Any]],
    prestates: Mapping[str, _CanonicalOutputPrestate],
    staged: Mapping[str, bytes],
) -> list[dict[str, Any]]:
    """Publish only a completely admitted staged denominator."""

    successors: dict[str, bytes] = {}
    for route in output_routes:
        identity = str(route.get("identity") or "")
        if identity not in prestates or identity not in staged:
            _fail("STAGED_OUTPUT", "staged publication denominator differs")
        mode = str(route.get("write_mode") or "")
        if mode == "APPEND":
            if not prestates[identity].existed:
                _fail("OUTPUT_PRESTATE", f"APPEND prestate is absent: {identity}")
            successor = prestates[identity].raw + staged[identity]
        elif mode in {"CREATE", "REPLACE"}:
            successor = staged[identity]
        else:
            _fail("STAGED_OUTPUT", f"unsupported MODEL write mode: {mode}")
        if not successor or len(successor) > _MAX_PHASE_IO_OUTPUT_BYTES:
            _fail("STAGED_OUTPUT", f"published output size is unsafe: {identity}")
        successors[identity] = successor
    if any(
        not _canonical_output_matches_prestate(root, identity, prestate)
        for identity, prestate in prestates.items()
    ):
        _fail("CANONICAL_OUTPUT_MUTATION", "canonical output changed before publication")
    try:
        for route in output_routes:
            identity = str(route.get("identity") or "")
            prestate = prestates[identity]
            _replace_bytes(prestate.path, successors[identity], prestate.mode)
        return _validate_completed_outputs(
            root,
            [
                prestates[str(route.get("identity") or "")].path
                for route in output_routes
            ],
        )
    except BaseException:
        _restore_changed_canonical_prestates(root, prestates)
        raise


@dataclass(frozen=True)
class _FrozenStagedValidationGate:
    validator: Callable[[Mapping[str, bytes], Mapping[str, Any]], Sequence[str]]
    context_raw: bytes
    input_identities: tuple[str, ...]
    input_bindings_raw: bytes
    binding: Mapping[str, Any]


def _publication_journal_digest(payload: Mapping[str, Any]) -> str:
    return _mapping_sha({
        key: value for key, value in payload.items() if key != "journal_sha256"
    })


def _publication_transaction_binding(payload: Mapping[str, Any]) -> str:
    return _mapping_sha({
        "schema": payload.get("schema"),
        "invocation_id": payload.get("invocation_id"),
        "receipt_relative": payload.get("receipt_relative"),
        "outputs": payload.get("outputs"),
    })


def _write_publication_journal(path: Path, payload: Mapping[str, Any]) -> dict[str, Any]:
    normalized = dict(payload)
    normalized["journal_sha256"] = _publication_journal_digest(normalized)
    raw = _canonical_bytes(normalized) + b"\n"
    if len(raw) > _MAX_PUBLICATION_JOURNAL_BYTES:
        _fail("PUBLICATION_JOURNAL", "publication journal exceeds its bound")
    _replace_bytes(path, raw)
    return normalized


def _publication_successors(
    output_routes: Sequence[Mapping[str, Any]],
    prestates: Mapping[str, _CanonicalOutputPrestate],
    staged: Mapping[str, bytes],
) -> dict[str, bytes]:
    successors: dict[str, bytes] = {}
    for route in output_routes:
        identity = str(route.get("identity") or "")
        if identity not in prestates or identity not in staged:
            _fail("STAGED_OUTPUT", "staged publication denominator differs")
        mode = str(route.get("write_mode") or "")
        if mode == "APPEND":
            if not prestates[identity].existed:
                _fail("OUTPUT_PRESTATE", f"APPEND prestate is absent: {identity}")
            successor = prestates[identity].raw + staged[identity]
        elif mode in {"CREATE", "REPLACE"}:
            successor = staged[identity]
        else:
            _fail("STAGED_OUTPUT", f"unsupported MODEL write mode: {mode}")
        if not successor or len(successor) > _MAX_PHASE_IO_OUTPUT_BYTES:
            _fail("STAGED_OUTPUT", f"published output size is unsafe: {identity}")
        successors[identity] = successor
    return successors


def _prepare_publication_transaction(
    root: Path,
    invocation_private: Path,
    invocation_id: str,
    receipt_relative: str,
    output_routes: Sequence[Mapping[str, Any]],
    prestates: Mapping[str, _CanonicalOutputPrestate],
    staged: Mapping[str, bytes],
) -> tuple[Path, dict[str, Any]]:
    successors = _publication_successors(output_routes, prestates, staged)
    successor_root = invocation_private / _PUBLICATION_SUCCESSOR_DIRECTORY
    successor_root.mkdir(mode=0o700)
    rows: list[dict[str, Any]] = []
    for index, route in enumerate(output_routes):
        identity = str(route.get("identity") or "")
        prestate = prestates[identity]
        successor = successors[identity]
        successor_path = successor_root / f"{index:04d}.bin"
        _write_absent_bytes(successor_path, successor, 0o400)
        backup = prestate.path.with_name(
            f".{prestate.path.name}.posix-v2-prestate-{invocation_id}"
        )
        try:
            backup.lstat()
        except FileNotFoundError:
            pass
        else:
            _fail("PUBLICATION_JOURNAL", f"publication backup already exists: {identity}")
        rows.append({
            "identity": identity,
            "canonical_relative": prestate.path.relative_to(root).as_posix(),
            "backup_relative": backup.relative_to(root).as_posix(),
            "successor_relative": successor_path.relative_to(root).as_posix(),
            "write_mode": str(route.get("write_mode") or ""),
            "prestate": {
                "existed": prestate.existed,
                "size": len(prestate.raw),
                "sha256": _sha(prestate.raw) if prestate.existed else "",
                "mode": prestate.mode,
                "device": prestate.device,
                "inode": prestate.inode,
                "owner": prestate.owner,
                "group": prestate.group,
                "links": prestate.links,
                "mtime_ns": prestate.mtime_ns,
            },
            "successor_size": len(successor),
            "successor_sha256": _sha(successor),
        })
    directory_descriptor = os.open(successor_root, _directory_open_flags())
    try:
        os.fsync(directory_descriptor)
    finally:
        os.close(directory_descriptor)
    journal_path = invocation_private / _PUBLICATION_JOURNAL_NAME
    payload = _write_publication_journal(journal_path, {
        "schema": _PUBLICATION_JOURNAL_SCHEMA,
        "invocation_id": invocation_id,
        "state": "PREPARED",
        "published_count": 0,
        "receipt_relative": receipt_relative,
        "outputs": rows,
    })
    return journal_path, payload


def _update_publication_journal(
    journal_path: Path,
    payload: Mapping[str, Any],
    *,
    state: str,
    published_count: int,
) -> dict[str, Any]:
    updated = dict(payload)
    updated["state"] = state
    updated["published_count"] = published_count
    return _write_publication_journal(journal_path, updated)


def _fsync_parent(path: Path) -> None:
    descriptor = os.open(path.parent, _directory_open_flags())
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _publish_prepared_transaction(
    root: Path,
    journal_path: Path,
    payload: Mapping[str, Any],
    prestates: Mapping[str, _CanonicalOutputPrestate],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    if any(
        not _canonical_output_matches_prestate(root, identity, prestate)
        for identity, prestate in prestates.items()
    ):
        _fail("CANONICAL_OUTPUT_MUTATION", "canonical output changed before publication")
    current = _update_publication_journal(
        journal_path, payload, state="PUBLISHING", published_count=0
    )
    rows = current.get("outputs", [])
    for index, row in enumerate(rows):
        identity = str(row.get("identity") or "")
        prestate = prestates[identity]
        backup = root / str(row.get("backup_relative") or "")
        successor = root / str(row.get("successor_relative") or "")
        successor_raw = _read_completed_output_bytes(
            root, successor, f"publication successor {identity}"
        )
        if prestate.existed:
            os.rename(prestate.path, backup)
            _fsync_parent(prestate.path)
        _replace_bytes(prestate.path, successor_raw, prestate.mode)
        current = _update_publication_journal(
            journal_path,
            current,
            state="PUBLISHING",
            published_count=index + 1,
        )
    evidence = _validate_completed_outputs(
        root, [prestates[str(row.get("identity") or "")].path for row in rows]
    )
    current = _update_publication_journal(
        journal_path,
        current,
        state="PUBLISHED",
        published_count=len(rows),
    )
    return current, evidence


def _journal_row_prestate(root: Path, row: Mapping[str, Any]) -> _CanonicalOutputPrestate:
    raw = row.get("prestate")
    if not isinstance(raw, Mapping):
        _fail("PUBLICATION_JOURNAL", "publication prestate is malformed")
    canonical = _path_without_symlink_components(
        root,
        str(row.get("canonical_relative") or ""),
        label="journal canonical output",
        allow_missing_leaf=True,
    )
    existed = raw.get("existed") is True
    backup = root / str(row.get("backup_relative") or "")
    prestate_raw = b""
    if existed:
        source = backup if backup.exists() else canonical
        prestate_raw = _read_canonical_prestate_bytes(root, source, "journal prestate")
        if len(prestate_raw) != raw.get("size") or _sha(prestate_raw) != raw.get("sha256"):
            _fail("PUBLICATION_JOURNAL", "publication prestate bytes changed")
    return _CanonicalOutputPrestate(
        path=canonical,
        existed=existed,
        raw=prestate_raw,
        mode=int(raw.get("mode") or 0),
        device=int(raw.get("device") or 0),
        inode=int(raw.get("inode") or 0),
        owner=int(raw.get("owner") or 0),
        group=int(raw.get("group") or 0),
        links=int(raw.get("links") or 0),
        mtime_ns=int(raw.get("mtime_ns") or 0),
    )


def _rollback_publication_transaction(
    root: Path,
    journal_path: Path,
    payload: Mapping[str, Any],
) -> dict[str, Any]:
    rows = payload.get("outputs")
    if not isinstance(rows, list):
        _fail("PUBLICATION_JOURNAL", "publication output denominator is malformed")
    prestates = {
        str(row.get("identity") or ""): _journal_row_prestate(root, row)
        for row in rows
        if isinstance(row, Mapping)
    }
    if len(prestates) != len(rows):
        _fail("PUBLICATION_JOURNAL", "publication output row is malformed")
    for row in reversed(rows):
        identity = str(row.get("identity") or "")
        prestate = prestates[identity]
        backup = root / str(row.get("backup_relative") or "")
        if prestate.existed and backup.exists():
            os.replace(backup, prestate.path)
            _fsync_parent(prestate.path)
        elif not prestate.existed:
            try:
                observed = prestate.path.lstat()
            except FileNotFoundError:
                continue
            if stat.S_ISDIR(observed.st_mode):
                _fail("CANONICAL_RESTORE", f"published output became a directory: {identity}")
            prestate.path.unlink()
            _fsync_parent(prestate.path)
    for identity, prestate in prestates.items():
        if not _canonical_output_matches_prestate(root, identity, prestate):
            _fail("CANONICAL_RESTORE", f"exact publication rollback failed: {identity}")
    return _update_publication_journal(
        journal_path, payload, state="ROLLED_BACK", published_count=0
    )


def _read_publication_journal(path: Path, invocation_id: str) -> dict[str, Any]:
    descriptor = _open_readonly_nofollow(path, "publication journal")
    assert descriptor is not None
    try:
        observed = os.fstat(descriptor)
        raw = _read_exact_regular_fd(
            descriptor,
            observed,
            maximum=_MAX_PUBLICATION_JOURNAL_BYTES,
            label="publication journal",
        )
    finally:
        os.close(descriptor)
    try:
        payload = json.loads(raw.decode("ascii"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        _fail("PUBLICATION_JOURNAL", "publication journal is malformed", exc)
    if (
        not isinstance(payload, dict)
        or payload.get("schema") != _PUBLICATION_JOURNAL_SCHEMA
        or payload.get("invocation_id") != invocation_id
        or payload.get("state")
        not in {"PREPARED", "PUBLISHING", "PUBLISHED", "COMMITTED", "ROLLED_BACK"}
        or payload.get("journal_sha256") != _publication_journal_digest(payload)
        or not isinstance(payload.get("outputs"), list)
        or not payload["outputs"]
        or len(payload["outputs"]) > _MAX_WRITABLE_DIRECTORIES
    ):
        _fail("PUBLICATION_JOURNAL", "publication journal authority is invalid")
    return payload


def _journal_completed_receipt_valid(
    root: Path,
    payload: Mapping[str, Any],
) -> bool:
    try:
        receipt = _path_without_symlink_components(
            root,
            str(payload.get("receipt_relative") or ""),
            label="publication receipt",
            allow_missing_leaf=False,
        )
        descriptor = _open_readonly_nofollow(receipt, "publication receipt")
        assert descriptor is not None
        try:
            observed = os.fstat(descriptor)
            raw = _read_exact_regular_fd(
                descriptor,
                observed,
                maximum=_MAX_AUTH_BYTES,
                label="publication receipt",
            )
        finally:
            os.close(descriptor)
        receipt_payload = json.loads(raw.decode("ascii"))
        if not isinstance(receipt_payload, dict):
            return False
        claimed = receipt_payload.pop("receipt_sha256", None)
        if (
            claimed != _mapping_sha(receipt_payload)
            or receipt_payload.get("schema") != RECEIPT_SCHEMA
            or receipt_payload.get("status") != "COMPLETED"
            or receipt_payload.get("failure_code") is not None
            or receipt_payload.get("invocation_id") != payload.get("invocation_id")
            or receipt_payload.get("publication_transaction_binding_sha256")
            != _publication_transaction_binding(payload)
        ):
            return False
        evidence = receipt_payload.get("completed_output_evidence")
        rows = payload.get("outputs")
        if not isinstance(evidence, list) or not isinstance(rows, list):
            return False
        expected = {
            str(row.get("canonical_relative") or ""): (
                int(row.get("successor_size") or 0),
                str(row.get("successor_sha256") or ""),
            )
            for row in rows
            if isinstance(row, Mapping)
        }
        actual = {
            Path(str(row.get("path") or "")).relative_to(root).as_posix(): (
                int(row.get("size") or 0),
                str(row.get("sha256") or ""),
            )
            for row in evidence
            if isinstance(row, Mapping)
        }
        return actual == expected
    except (OSError, TypeError, ValueError, PosixV2CompatRuntimeError):
        return False


def _finish_committed_publication(
    root: Path,
    journal_path: Path,
    payload: Mapping[str, Any],
) -> dict[str, Any]:
    rows = payload.get("outputs")
    if not isinstance(rows, list):
        _fail("PUBLICATION_JOURNAL", "committed output denominator is malformed")
    for row in rows:
        if not isinstance(row, Mapping):
            _fail("PUBLICATION_JOURNAL", "committed output row is malformed")
        identity = str(row.get("identity") or "")
        canonical = _path_without_symlink_components(
            root,
            str(row.get("canonical_relative") or ""),
            label=f"committed canonical {identity}",
            allow_missing_leaf=True,
        )
        try:
            current = _read_completed_output_bytes(
                root, canonical, f"committed canonical {identity}"
            )
        except PosixV2CompatRuntimeError:
            current = b""
        if (
            len(current) == row.get("successor_size")
            and _sha(current) == row.get("successor_sha256")
        ):
            continue
        successor = _path_without_symlink_components(
            root,
            str(row.get("successor_relative") or ""),
            label=f"committed successor {identity}",
            allow_missing_leaf=False,
        )
        successor_raw = _read_completed_output_bytes(
            root, successor, f"committed successor {identity}"
        )
        if (
            len(successor_raw) != row.get("successor_size")
            or _sha(successor_raw) != row.get("successor_sha256")
        ):
            _fail("PUBLICATION_JOURNAL", "committed successor bytes changed")
        if current != successor_raw:
            _replace_bytes(canonical, successor_raw)
    committed = _update_publication_journal(
        journal_path, payload, state="COMMITTED", published_count=len(rows)
    )
    for row in rows:
        backup = root / str(row.get("backup_relative") or "")
        try:
            observed = backup.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISDIR(observed.st_mode):
            _fail("PUBLICATION_JOURNAL", "publication backup became a directory")
        backup.unlink()
        _fsync_parent(backup)
    return committed


def _recover_invocation_publication(
    root: Path, private_entry_name: str, invocation_id: str
) -> None:
    invocation = root / _PRIVATE_RUNTIME_ROOT_NAME / private_entry_name
    journal_path = invocation / _PUBLICATION_JOURNAL_NAME
    try:
        journal_path.lstat()
    except FileNotFoundError:
        return
    payload = _read_publication_journal(journal_path, invocation_id)
    committed = _journal_completed_receipt_valid(root, payload)
    if committed:
        _finish_committed_publication(root, journal_path, payload)
    elif payload.get("state") != "ROLLED_BACK":
        _rollback_publication_transaction(root, journal_path, payload)


def _freeze_staged_validation_gate(
    validator: Callable[[Mapping[str, bytes], Mapping[str, Any]], Sequence[str]] | None,
    context: Mapping[str, Any] | None,
    input_identities: Sequence[str],
    *,
    contract: PhaseIOContract,
    input_bindings: Mapping[str, Any],
) -> _FrozenStagedValidationGate | None:
    if (validator is None) != (context is None):
        _fail("STAGED_VALIDATOR", "staged output validator and context must be supplied together")
    if validator is None:
        if input_identities:
            _fail("STAGED_VALIDATOR", "staged input authority requires a validator")
        return None
    if not callable(validator) or not isinstance(context, Mapping):
        _fail("STAGED_VALIDATOR", "staged validator or context is malformed")
    if isinstance(input_identities, (str, bytes)):
        _fail("STAGED_VALIDATOR", "staged input identities must be a sequence")
    identity_values = tuple(input_identities)
    contract_inputs = set(contract.immutable_inputs) | set(contract.bounded_lookup_inputs)
    if (
        len(identity_values) > _MAX_STAGED_VALIDATOR_INPUTS
        or any(
            type(value) is not str or value not in contract_inputs
            for value in identity_values
        )
    ):
        _fail("STAGED_VALIDATOR", "staged input denominator is invalid")
    identities = tuple(sorted(set(identity_values)))
    context_raw = _canonical_bytes(dict(context))
    if len(context_raw) > _MAX_STAGED_VALIDATOR_CONTEXT_BYTES:
        _fail("STAGED_VALIDATOR", "staged validator context exceeds its bound")
    selected = {identity: dict(input_bindings[identity]) for identity in identities}
    input_bindings_raw = _canonical_bytes({"bindings": selected})
    if len(input_bindings_raw) > _MAX_STAGED_VALIDATOR_BINDINGS_BYTES:
        _fail("STAGED_VALIDATOR", "staged input bindings exceed their bound")
    module = str(getattr(validator, "__module__", "") or "")
    name = str(getattr(validator, "__qualname__", "") or "")
    if not module or not name or "<locals>" in name:
        _fail("STAGED_VALIDATOR", "staged validator must be a top-level callable")
    source_descriptor: int | None = None
    try:
        source = Path(inspect.getsourcefile(validator) or "").resolve(strict=True)
        source_descriptor = _open_readonly_nofollow(
            source, "staged validator source"
        )
        assert source_descriptor is not None
        observed = os.fstat(source_descriptor)
        implementation_sha256 = _hash_exact_regular_fd(
            source_descriptor,
            observed,
            maximum=_MAX_CODEX_BINARY_BYTES,
            label="staged validator source",
        )
    except PosixV2CompatRuntimeError:
        raise
    except (OSError, TypeError) as exc:
        _fail("STAGED_VALIDATOR", "staged validator source is unavailable", exc)
    finally:
        if source_descriptor is not None:
            os.close(source_descriptor)
    binding = {
        "callable": f"{module}:{name}",
        "implementation_sha256": implementation_sha256,
        "context_sha256": _sha(context_raw),
        "input_identities": list(identities),
        "input_bindings_sha256": _sha(input_bindings_raw),
    }
    binding["binding_sha256"] = _mapping_sha(binding)
    return _FrozenStagedValidationGate(
        validator=validator,
        context_raw=context_raw,
        input_identities=identities,
        input_bindings_raw=input_bindings_raw,
        binding=MappingProxyType(binding),
    )


def _bounded_staged_reasons(values: object) -> list[str]:
    if isinstance(values, (str, bytes)) or not isinstance(values, Sequence):
        _fail("STAGED_VALIDATOR", "staged validator returned a malformed issue set")
    reasons: list[str] = []
    for value in values:
        if type(value) is not str:
            _fail("STAGED_VALIDATOR", "staged validator issue is not exact text")
        reason = value.strip()
        if not reason:
            continue
        if "\x00" in reason or len(reason.encode("utf-8")) > _MAX_STAGED_REJECTION_REASON_BYTES:
            _fail("STAGED_VALIDATOR", "staged validator issue exceeds its bound")
        reasons.append(reason)
        if len(reasons) > _MAX_STAGED_REJECTION_REASONS:
            _fail("STAGED_VALIDATOR", "staged validator issue set exceeds its bound")
    return sorted(set(reasons))


def _bounded_recorded_reasons(values: Sequence[str]) -> list[str]:
    """Bound trusted runtime diagnostics without losing rejection semantics."""

    normalized: list[str] = []
    for value in values:
        raw = str(value).replace("\x00", "\\0").encode("utf-8")
        if len(raw) > _MAX_STAGED_REJECTION_REASON_BYTES:
            raw = raw[:_MAX_STAGED_REJECTION_REASON_BYTES]
            while True:
                try:
                    value = raw.decode("utf-8")
                    break
                except UnicodeDecodeError:
                    raw = raw[:-1]
        else:
            value = raw.decode("utf-8")
        if value:
            normalized.append(value)
    unique = sorted(set(normalized))
    if len(unique) <= _MAX_STAGED_REJECTION_REASONS:
        return unique
    return unique[: _MAX_STAGED_REJECTION_REASONS - 1] + [
        "additional staged rejection reasons exceeded the receipt bound"
    ]


def _replay_staged_gate_inputs(
    gate: _FrozenStagedValidationGate,
    *,
    record: _SessionRecord,
    contract: PhaseIOContract,
    launch: LaunchSpec,
    run_id: str,
) -> list[str]:
    try:
        ledger = read_artifact_ledger(record.scratchpad)
        unit = ledger.get("work_units", {}).get(contract.key)
        bindings = unit.get("input_bindings") if isinstance(unit, Mapping) else None
        if not isinstance(bindings, Mapping):
            return ["staged validator input bindings are unavailable"]
        selected = {
            identity: dict(bindings[identity])
            for identity in gate.input_identities
            if isinstance(bindings.get(identity), Mapping)
        }
        if (
            set(selected) != set(gate.input_identities)
            or _canonical_bytes({"bindings": selected}) != gate.input_bindings_raw
        ):
            return ["staged validator input bindings changed"]
        issues = validate_work_unit_inputs(
            record.scratchpad,
            record.project_root,
            contract,
            launch,
            run_id=run_id,
        )
    except Exception:
        return ["staged validator input authority is unavailable"]
    return _bounded_recorded_reasons([
        issue
        for issue in issues
        if "semantic input missing at binding" not in issue
    ])


def _capture_append_bases(
    root: Path,
    output_routes: Sequence[Mapping[str, Any]],
) -> dict[str, bytes]:
    """Freeze every canonical APPEND preimage before the provider starts."""

    bases: dict[str, bytes] = {}
    for route in output_routes:
        if route.get("write_mode") != "APPEND":
            continue
        identity = str(route.get("identity") or "")
        canonical = Path(str(route.get("canonical_path") or ""))
        raw = _read_completed_output_bytes(
            root, canonical, f"APPEND canonical preimage {identity}"
        )
        if (
            len(raw) != int(route.get("prestate_size", -1))
            or _sha(raw) != str(route.get("prestate_sha256") or "")
        ):
            _fail(
                "APPEND_PRESTATE_DRIFT",
                f"APPEND canonical preimage differs from PhaseIO: {identity}",
            )
        bases[identity] = raw
    return bases


def _restore_changed_append_bases(
    root: Path,
    output_routes: Sequence[Mapping[str, Any]],
    bases: Mapping[str, bytes],
) -> bool:
    """Restore any direct canonical APPEND mutation and report the violation."""

    changed = False
    for route in output_routes:
        identity = str(route.get("identity") or "")
        if identity not in bases:
            continue
        canonical = Path(str(route.get("canonical_path") or ""))
        try:
            current = _read_completed_output_bytes(
                root, canonical, f"APPEND canonical post-provider {identity}"
            )
        except PosixV2CompatRuntimeError:
            current = b""
        if current != bases[identity]:
            _replace_bytes(canonical, bases[identity])
            changed = True
    return changed


def _publish_append_fragments(
    root: Path,
    output_routes: Sequence[Mapping[str, Any]],
    bases: Mapping[str, bytes],
) -> list[dict[str, Any]]:
    """Atomically compose exact APPEND bases with attempt-private fragments."""

    provider_paths = [Path(str(route.get("path") or "")) for route in output_routes]
    _validate_completed_outputs(root, provider_paths)
    canonical_paths: list[Path] = []
    for route in output_routes:
        identity = str(route.get("identity") or "")
        canonical = Path(str(route.get("canonical_path") or ""))
        if identity in bases:
            current = _read_completed_output_bytes(
                root, canonical, f"APPEND publication preimage {identity}"
            )
            if current != bases[identity]:
                _fail(
                    "APPEND_PRESTATE_DRIFT",
                    f"APPEND canonical changed before publication: {identity}",
                )
            fragment = _read_completed_output_bytes(
                root,
                Path(str(route.get("path") or "")),
                f"APPEND fragment {identity}",
            )
            _replace_bytes(canonical, bases[identity] + fragment)
        canonical_paths.append(canonical)
    return _validate_completed_outputs(root, canonical_paths)


def _observe_codex_startup_model(stderr: bytes) -> str | None:
    """Return the model reported by Codex's startup preamble, when present.

    Codex writes a human-readable launch preamble to stderr before the echoed
    ``user`` prompt.  Bound parsing to that preamble so prompt text cannot
    forge the observation.  The explicit ``--model`` argument remains the
    binding authority; this observation is independent evidence that lets the
    compatibility lane fail closed if the provider reports a different model.
    """

    text = stderr.decode("utf-8", errors="replace")
    prompt_boundary = text.find("\n--------\nuser\n")
    if prompt_boundary < 0:
        return None
    preamble = text[:prompt_boundary]
    matches = re.findall(r"(?m)^model:[ \t]+([^\r\n]+)\r?$", preamble)
    if len(matches) != 1:
        return None
    observed = matches[0].strip()
    if not _ID_RE.fullmatch(observed):
        return None
    return observed


def _materialize_research_gate_context(
    context: Mapping[str, Any] | None,
    *,
    scratchpad: Path,
    attempt_completion: Path,
) -> dict[str, Any]:
    """Bind the existing Codex research gate to one compat evidence chain."""

    if not isinstance(context, Mapping):
        _fail("RESEARCH_PROFILE", "Codex research gate context is absent")
    expected = {
        "schema",
        "scratchpad_root",
        "attempt_completion",
        "obligations_path",
        "research_output",
    }
    value = dict(context)
    if (
        set(value) != expected
        or value.get("schema")
        != "plamen.codex_dependency_research_staged_gate.v1"
        or value.get("scratchpad_root") != os.fspath(scratchpad)
        or value.get("attempt_completion")
        != CODEX_RESEARCH_ATTEMPT_COMPLETION_PLACEHOLDER
        or value.get("research_output")
        != "recon_external_dependency_research.md"
    ):
        _fail("RESEARCH_PROFILE", "Codex research gate context differs")
    obligations = Path(str(value.get("obligations_path") or ""))
    try:
        obligations.relative_to(scratchpad)
    except ValueError:
        _fail("RESEARCH_PROFILE", "Codex research obligations escape scratchpad")
    _path_without_symlink_components(
        scratchpad,
        obligations.relative_to(scratchpad).as_posix(),
        label="Codex research obligations",
        allow_missing_leaf=False,
    )
    value["attempt_completion"] = os.fspath(attempt_completion)
    return value


def validate_codex_research_event_stream(stdout: bytes) -> None:
    """Require one closed, successful Codex JSONL turn without ambiguity."""

    terminal_seen = False
    for event in parse_codex_research_event_stream(stdout):
        if terminal_seen:
            raise ValueError("JSONL event follows turn.completed")
        event_type = event.get("type")
        item = event.get("item")
        nested_error = event.get("error")
        if (
            event_type in {"turn.failed", "error", "item.failed"}
            or (nested_error is not None and nested_error != "")
            or (
                event_type in {"item.completed", "item.failed"}
                and isinstance(item, Mapping)
                and str(item.get("type") or "").strip().lower() == "error"
            )
        ):
            raise ValueError("JSONL stream contains a failure event")
        if event_type == "turn.completed":
            terminal_seen = True
    if not terminal_seen:
        raise ValueError("JSONL stream lacks terminal turn.completed")


def _write_research_provider_evidence(
    *,
    scratchpad: Path,
    evidence_root: Path,
    stdout: bytes,
) -> dict[str, Any]:
    """Persist the exact JSONL stream consumed by the existing staged gate."""

    try:
        validate_codex_research_event_stream(stdout)
    except (UnicodeError, ValueError, json.JSONDecodeError) as exc:
        _fail(
            "RESEARCH_EVENT_STREAM",
            f"Codex research JSONL stream is not closed: {exc}",
            exc,
        )

    parent = evidence_root.parent
    if not parent.exists():
        parent.mkdir(mode=0o700)
    parent_observed = parent.lstat()
    if stat.S_ISLNK(parent_observed.st_mode) or not stat.S_ISDIR(
        parent_observed.st_mode
    ):
        _fail("RESEARCH_EVIDENCE", "research evidence root is unsafe")
    _path_without_symlink_components(
        scratchpad,
        parent.relative_to(scratchpad).as_posix(),
        label="research evidence root",
        allow_missing_leaf=False,
    )
    evidence_root.mkdir(mode=0o700)
    _path_without_symlink_components(
        scratchpad,
        evidence_root.relative_to(scratchpad).as_posix(),
        label="research invocation evidence",
        allow_missing_leaf=False,
    )
    stdout_path = evidence_root / "stdout.jsonl"
    provider_path = evidence_root / "provider-completion.json"
    attempt_path = evidence_root / "attempt-completion.json"
    _write_absent_bytes(stdout_path, stdout, 0o400)
    provider = {
        "schema": "plamen.posix_v2_compat_codex_provider_events.v1",
        "stdout_blob": {
            "relative_path": stdout_path.name,
            "sha256": _sha(stdout),
            "size": len(stdout),
        },
        "stream_observation": {"stdout_overflow": False},
    }
    provider_raw = _canonical_bytes(provider)
    _write_absent_bytes(provider_path, provider_raw, 0o400)
    attempt = {
        "schema": "plamen.posix_v2_compat_codex_research_attempt.v1",
        "provider_completion_relative_path": provider_path.relative_to(
            scratchpad
        ).as_posix(),
    }
    attempt_raw = _canonical_bytes(attempt)
    _write_absent_bytes(attempt_path, attempt_raw, 0o400)
    directory_descriptor = os.open(evidence_root, _directory_open_flags())
    try:
        os.fsync(directory_descriptor)
    finally:
        os.close(directory_descriptor)
    return {
        "schema": "plamen.posix_v2_compat_codex_research_evidence.v1",
        "attempt_completion_relative_path": attempt_path.relative_to(
            scratchpad
        ).as_posix(),
        "attempt_completion_sha256": _sha(attempt_raw),
        "provider_completion_relative_path": provider_path.relative_to(
            scratchpad
        ).as_posix(),
        "provider_completion_sha256": _sha(provider_raw),
        "stdout_relative_path": stdout_path.relative_to(scratchpad).as_posix(),
        "stdout_sha256": _sha(stdout),
        "stdout_size": len(stdout),
    }


def _write_claude_research_provider_evidence(
    *,
    scratchpad: Path,
    evidence_root: Path,
    stdout: bytes,
    completion_evidence: Mapping[str, Any],
) -> dict[str, Any]:
    """Persist authenticated Claude stream evidence for the staged R-EXT gate."""

    parent = evidence_root.parent
    if not parent.exists():
        parent.mkdir(mode=0o700)
    parent_observed = parent.lstat()
    if stat.S_ISLNK(parent_observed.st_mode) or not stat.S_ISDIR(
        parent_observed.st_mode
    ):
        _fail("RESEARCH_EVIDENCE", "research evidence root is unsafe")
    _path_without_symlink_components(
        scratchpad,
        parent.relative_to(scratchpad).as_posix(),
        label="research evidence root",
        allow_missing_leaf=False,
    )
    evidence_root.mkdir(mode=0o700)
    _path_without_symlink_components(
        scratchpad,
        evidence_root.relative_to(scratchpad).as_posix(),
        label="research invocation evidence",
        allow_missing_leaf=False,
    )
    stdout_path = evidence_root / "stdout.jsonl"
    provider_path = evidence_root / "provider-completion.json"
    attempt_path = evidence_root / "attempt-completion.json"
    _write_absent_bytes(stdout_path, stdout, 0o400)
    provider = {
        "schema": "plamen.posix_v2_compat_claude_provider_events.v1",
        "backend": "claude",
        "stdout_blob": {
            "relative_path": stdout_path.name,
            "sha256": _sha(stdout),
            "size": len(stdout),
        },
        "stream_evidence": dict(completion_evidence),
        "stream_observation": {"stdout_overflow": False},
    }
    provider_raw = _canonical_bytes(provider)
    _write_absent_bytes(provider_path, provider_raw, 0o400)
    attempt = {
        "schema": "plamen.posix_v2_compat_claude_research_attempt.v1",
        "provider_completion_relative_path": provider_path.relative_to(
            scratchpad
        ).as_posix(),
    }
    attempt_raw = _canonical_bytes(attempt)
    _write_absent_bytes(attempt_path, attempt_raw, 0o400)
    directory_descriptor = os.open(evidence_root, _directory_open_flags())
    try:
        os.fsync(directory_descriptor)
    finally:
        os.close(directory_descriptor)
    return {
        "schema": "plamen.posix_v2_compat_claude_research_evidence.v1",
        "attempt_completion_relative_path": attempt_path.relative_to(
            scratchpad
        ).as_posix(),
        "attempt_completion_sha256": _sha(attempt_raw),
        "provider_completion_relative_path": provider_path.relative_to(
            scratchpad
        ).as_posix(),
        "provider_completion_sha256": _sha(provider_raw),
        "stdout_relative_path": stdout_path.relative_to(scratchpad).as_posix(),
        "stdout_sha256": _sha(stdout),
        "stdout_size": len(stdout),
    }


def _run_model_exec(
    *,
    backend: str,
    session_authority: object,
    prompt: str,
    phase_name: str,
    needs_mcp: bool,
    config: Mapping[str, Any],
    scratchpad: str | Path,
    attempt: int,
    label: str,
    expected_outputs: Sequence[str],
    timeout: float,
    effective_model: str,
    working_directory: str | Path,
    writable_directories: Sequence[str | Path],
    phase_io_contract: PhaseIOContract,
    phase_io_launch: LaunchSpec,
    staged_output_validator: Callable[
        [Mapping[str, bytes], Mapping[str, Any]], Sequence[str]
    ] | None = None,
    staged_output_context: Mapping[str, Any] | None = None,
    staged_output_input_identities: Sequence[str] = (),
    provider_event_profile: str | None = None,
    phase_tool_boundary: Mapping[str, Any] | None = None,
    output_staging_directory: str | Path | None = None,
) -> int:
    """Run one raw provider turn and durably record reduced isolation.

    Return values intentionally match the legacy driver's convention: the
    actual non-negative Codex status, ``COMPAT_TIMEOUT`` for timeout, and
    ``COMPAT_EXIT_ERROR`` for prelaunch/containment/stream failure.
    """

    selected_backend = _identifier(backend, "compatibility backend")
    if selected_backend not in _COMPAT_BACKENDS:
        _fail("SESSION_AUTHORITY", "compatibility backend is unsupported")
    record = _execution_session_record(session_authority)
    if record.binding["backend"] != selected_backend:
        _fail(
            "SESSION_AUTHORITY",
            "compatibility invocation backend differs from its session",
        )
    started_wall_ns = time.time_ns()
    started_monotonic = time.monotonic()
    invocation_uuid = uuid.uuid4().hex
    phase = _identifier(phase_name, "phase name")
    worker_label = _identifier(label, "worker label")
    if type(needs_mcp) is not bool:
        _fail("MCP", "needs_mcp must be boolean")
    if type(prompt) is not str or "\x00" in prompt:
        _fail("PROMPT", "prompt must be exact text without NUL")
    prompt_raw = prompt.encode("utf-8", errors="strict")
    if not prompt_raw or len(prompt_raw) > _MAX_PROMPT_BYTES:
        _fail("PROMPT", "prompt is empty or exceeds 16 MiB")
    if type(attempt) is not int or attempt < 1:
        _fail("ATTEMPT", "attempt must be a positive integer")
    if (
        isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or timeout <= 0
        or timeout > _MAX_TIMEOUT_SECONDS
    ):
        _fail("TIMEOUT", "timeout is outside the compatibility bound")
    requested_model = _identifier(effective_model, "effective model")
    if (
        type(phase_io_contract) is not PhaseIOContract
        or type(phase_io_launch) is not LaunchSpec
        or phase_io_contract.phase != phase
        or phase_io_launch.model != requested_model
        or phase_io_launch.timeout_s != max(1, int(timeout))
    ):
        _fail(
            "PHASE_IO_AUTHORITY",
            "phase/model/timeout differs from the sealed PhaseIO launch",
        )
    codex_research_profile = (
        selected_backend == "codex"
        and provider_event_profile == CODEX_LIVE_WEB_JSONL_PROFILE
    )
    claude_research_profile = (
        selected_backend == "claude"
        and provider_event_profile == CLAUDE_LIVE_WEB_STREAM_PROFILE
    )
    research_profile = codex_research_profile or claude_research_profile
    if provider_event_profile is not None and not research_profile:
        _fail("RESEARCH_PROFILE", "provider event profile is unsupported")
    if research_profile and (
        phase != "recon"
        or re.fullmatch(
            r"dependency_research(?:\.attempt-[0-9]{4})?",
            phase_io_contract.work_unit_id,
        )
        is None
        or tuple(expected_outputs)
        != ("recon_external_dependency_research.md",)
        or staged_output_validator is None
        or staged_output_context is None
    ):
        _fail(
            "RESEARCH_PROFILE",
            "live-web JSONL profile requires the exact sealed R-EXT leaf",
        )
    if not isinstance(config, Mapping):
        _fail("CONFIG", "driver config is not a mapping")
    run_id = str(config.get("_run_id") or "test-unbound")
    if run_id != record.binding["run_id"]:
        _fail("CONFIG", "driver run differs from the compatibility session")
    project, project_identity = _safe_directory(
        config.get("project_root"), "config project root"
    )
    scratch, scratch_identity = _safe_directory(scratchpad, "call scratchpad")
    if (
        project != record.project_root
        or scratch != record.scratchpad
        or project_identity != dict(record.project_identity)
        or scratch_identity != dict(record.scratchpad_identity)
    ):
        _fail("CONFIG", "driver paths differ from the compatibility session")
    working, working_identity = _safe_directory(
        working_directory, "working directory"
    )
    if working != record.scratchpad:
        _fail(
            "WORKING_DIRECTORY",
            "compatibility provider working directory must be the scratchpad",
        )
    writable = _normalize_writable_directories(
        writable_directories, record=record
    )
    invocation_key = f"{phase}:{worker_label}:{attempt}"
    with record.lock:
        _replay_directory(record.project_root, record.project_identity, "project root")
        _replay_directory(record.scratchpad, record.scratchpad_identity, "scratchpad")
        if (
            record.binding.get("schema") == DERIVED_STAGING_SESSION_SCHEMA
            and (record.active_invocations or record.used_invocations)
        ):
            _fail(
                "INVOCATION_REPLAY",
                "derived staging session is a one-shot authority",
            )
        if invocation_key in record.active_invocations or invocation_key in record.used_invocations:
            _fail("INVOCATION_REPLAY", "compatibility invocation is not fresh")
        record.active_invocations.add(invocation_key)

    safe_label = _safe_part(worker_label)
    prompt_path = scratch / f"_prompt_{safe_label}.attempt{attempt}.md"
    provider_prompt_path = (
        scratch / f"_provider_prompt_{safe_label}.attempt{attempt}.md"
    )
    output_last_path = scratch / f"_codex_output_{safe_label}.attempt{attempt}.md"
    provider_output_last_path: Path | None = None
    provider_last_message: bytes | None = None
    provider_last_message_evidence: dict[str, Any] = {
        "status": "NOT_APPLICABLE",
    }
    staged_output_recovery: dict[str, Any] = {
        "schema": "plamen.posix_v2_codex_last_message_projection.v1",
        "status": "NOT_ATTEMPTED",
        "projection": "EXACT_PROVIDER_LAST_MESSAGE_BYTES",
    }
    provider_nonzero_semantic_completion: dict[str, Any] | None = None
    log_path = scratch / f"_stdio_{safe_label}.attempt{attempt}.log"
    receipt_directory = scratch / ".posix_v2_compat_receipts"
    receipt_stem = (
        f"{_safe_part(phase)}.{safe_label}.attempt{attempt}.{invocation_uuid}"
    )
    private_root = scratch / _PRIVATE_RUNTIME_ROOT_NAME
    invocation_private = private_root / invocation_uuid
    private_root_descriptor: int | None = None
    private_root_identity: tuple[int, ...] | None = None
    invocation_private_identity: tuple[int, ...] | None = None
    invocation_private_created = False
    child: subprocess.Popen[bytes] | None = None
    stdout = b""
    stderr = b""
    return_value = COMPAT_EXIT_ERROR
    timed_out = False
    overflowed_stream: str | None = None
    process_group_empty = False
    status = "PRELAUNCH_FAILED"
    failure_code: str | None = None
    binary: Path | None = None
    binary_version: str | None = None
    binary_sha256: str | None = None
    auth_mode: str | None = None
    auth_sha256: str | None = None
    command: list[str] = []
    environment: dict[str, str] = {}
    provider_prompt_raw = b""
    routing_evidence: dict[str, Any] = {}
    canonical_prestates: dict[str, _CanonicalOutputPrestate] = {}
    publication_journal_path: Path | None = None
    publication_journal: dict[str, Any] | None = None
    staged_gate: _FrozenStagedValidationGate | None = None
    staged_rejection_reasons: list[str] = []
    canonical_publication_complete = False
    completed_output_evidence: list[dict[str, Any]] = []
    observed_model: str | None = None
    provider_event_evidence: dict[str, Any] | None = None
    provider_plan_projection: dict[str, Any] | None = None
    provider_completion_evidence: dict[str, Any] | None = None
    claude_plan: Any = None
    claude_executable_observation: dict[str, Any] | None = None
    research_evidence_root: Path | None = None
    output_staging_identity: Mapping[str, int] | None = None
    try:
        opened_private_root = _open_private_runtime_root(scratch, create=True)
        assert opened_private_root is not None
        private_root, private_root_descriptor, private_root_identity = (
            opened_private_root
        )
        _acquire_private_lock(
            private_root_descriptor,
            fcntl.LOCK_SH,
            "private invocation lock",
        )
        _replay_private_runtime_root(
            scratch,
            private_root_descriptor,
            private_root_identity,
        )
        try:
            os.mkdir(invocation_uuid, mode=0o700, dir_fd=private_root_descriptor)
            invocation_private_created = True
            invocation_observed = os.stat(
                invocation_uuid,
                dir_fd=private_root_descriptor,
                follow_symlinks=False,
            )
        except OSError as exc:
            _fail("PRIVATE_RUNTIME", "private invocation cannot be created", exc)
        _validate_private_directory_stat(
            invocation_observed,
            "private invocation",
        )
        invocation_private_identity = _directory_identity(invocation_observed)
        if selected_backend == "codex":
            if output_staging_directory is not None:
                _fail(
                    "OUTPUT_STAGING",
                    "Codex compatibility execution owns its private staging root",
                )
            output_staging_root = invocation_private / "staged-output"
            output_staging_root.mkdir(mode=0o700)
            provider_output_last_path = (
                invocation_private / "provider-last-message"
            )
        else:
            if output_staging_directory is None:
                _fail(
                    "OUTPUT_STAGING",
                    "Claude compatibility execution requires its sealed staging root",
                )
            output_staging_root, staging_identity = _safe_directory(
                output_staging_directory,
                "Claude output staging directory",
            )
            if (
                output_staging_root == scratch
                or not _is_within(output_staging_root, scratch)
            ):
                _fail(
                    "OUTPUT_STAGING",
                    "Claude output staging directory must be a scratchpad descendant",
                )
            output_staging_identity = MappingProxyType(staging_identity)
        effective_staged_context = staged_output_context
        if research_profile:
            research_evidence_root = (
                scratch / _RESEARCH_EVIDENCE_ROOT_NAME / invocation_uuid
            )
            if codex_research_profile:
                effective_staged_context = _materialize_research_gate_context(
                    staged_output_context,
                    scratchpad=scratch,
                    attempt_completion=(
                        research_evidence_root / "attempt-completion.json"
                    ),
                )
        provider_prompt_raw, routing_evidence = _compile_phase_io_provider_prompt(
            canonical_prompt=prompt,
            contract=phase_io_contract,
            launch=phase_io_launch,
            record=record,
            run_id=run_id,
            expected_outputs=expected_outputs,
            output_staging_root=output_staging_root,
        )
        canonical_prestates = _capture_canonical_output_prestates(
            scratch, routing_evidence.get("output_routes", [])
        )
        staged_gate = _freeze_staged_validation_gate(
            staged_output_validator,
            effective_staged_context,
            staged_output_input_identities,
            contract=phase_io_contract,
            input_bindings=routing_evidence.get("input_bindings", {}),
        )
        if (
            not provider_prompt_raw
            or len(provider_prompt_raw) > _MAX_PROMPT_BYTES
        ):
            _fail(
                "PROMPT",
                "provider-effective prompt is empty or exceeds 16 MiB",
            )
        if prompt_path.exists():
            if prompt_path.is_symlink() or prompt_path.read_bytes() != prompt_raw:
                _fail("PROMPT_SNAPSHOT", "existing prompt snapshot differs")
        else:
            _write_absent_bytes(prompt_path, prompt_raw, 0o400)
        if provider_prompt_path.exists():
            if (
                provider_prompt_path.is_symlink()
                or provider_prompt_path.read_bytes() != provider_prompt_raw
            ):
                _fail(
                    "PROVIDER_PROMPT_SNAPSHOT",
                    "existing provider-effective prompt snapshot differs",
                )
        else:
            _write_absent_bytes(
                provider_prompt_path, provider_prompt_raw, 0o400
            )
        temporary = invocation_private / "tmp"
        temporary.mkdir(mode=0o700)
        if selected_backend == "codex":
            binary, binary_version, binary_sha256 = _resolve_codex_binary()
            auth_mode, auth_raw, auth_sha256 = _load_ambient_codex_auth()
            codex_home = invocation_private / "codex-home"
            codex_home.mkdir(mode=0o700)
            environment = _base_child_environment()
            environment.update({
                "CODEX_HOME": os.fspath(codex_home),
                "TMPDIR": os.fspath(temporary),
            })
            if auth_raw is not None:
                _write_absent_bytes(codex_home / "auth.json", auth_raw, 0o600)
            else:
                key_name = auth_mode.removeprefix("AMBIENT_")
                key_value = os.environ.get(key_name)
                if not key_value:
                    _fail("CODEX_AUTH", "admitted API key disappeared")
                environment[key_name] = key_value
            command = [os.fspath(binary)]
            # `--search` is deliberately not inferred from needs_mcp.
            if research_profile:
                command.append("--search")
            command.append("exec")
            if research_profile:
                command.append("--json")
            command.extend([
                "--ephemeral",
                "--ignore-user-config",
                "--ignore-rules",
                "--skip-git-repo-check",
                "--model",
                requested_model,
                "--sandbox",
                "workspace-write",
                "-c",
                'approval_policy="never"',
                "-C",
                os.fspath(scratch),
                "-o",
                os.fspath(provider_output_last_path),
            ])
            for directory in writable:
                if directory != scratch:
                    command.extend(("--add-dir", os.fspath(directory)))
            command.append("-")
        else:
            if not isinstance(phase_tool_boundary, Mapping):
                _fail(
                    "CLAUDE_PLAN",
                    "Claude compatibility execution requires a phase tool boundary",
                )
            try:
                from posix_v2_compat_claude import (
                    compile_posix_v2_compat_claude_plan,
                    project_posix_v2_compat_claude_plan,
                )
            except (ImportError, AttributeError) as exc:
                _fail("CLAUDE_PLAN", "Claude compatibility adapter is unavailable", exc)
            executable = _resolve_claude_binary()
            claude_executable_observation = dict(executable)
            binary = Path(str(executable["resolved_executable"]))
            binary_version = str(executable["version"])
            binary_sha256 = str(executable["executable_sha256"])
            ambient_config_root = os.environ.get("CLAUDE_CONFIG_DIR")
            source_config_root, _ = _safe_directory(
                (
                    ambient_config_root
                    if ambient_config_root is not None
                    else _account_home() / ".claude"
                ),
                "Claude source config root",
            )
            environment = _base_child_environment()
            environment.update({
                "CLAUDE_CODE_TMPDIR": os.fspath(temporary),
                "TMPDIR": os.fspath(temporary),
            })
            if ambient_config_root is not None:
                environment["CLAUDE_CONFIG_DIR"] = os.fspath(
                    source_config_root
                )
            provider_session_id = str(uuid.uuid4())
            expected_version = config.get("claude_cli_version")
            if expected_version is not None and (
                type(expected_version) is not str
                or re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", expected_version)
                is None
            ):
                _fail(
                    "CLAUDE_PLAN",
                    "explicit Claude CLI version binding is malformed",
                )
            try:
                claude_plan = compile_posix_v2_compat_claude_plan(
                    session_binding=record.binding,
                    phase_io_contract=phase_io_contract,
                    phase_io_launch=phase_io_launch,
                    executable_observation=executable,
                    provider_session_id=provider_session_id,
                    prompt_bytes=provider_prompt_raw,
                    cwd=scratch,
                    output_routes=routing_evidence.get("output_routes", []),
                    phase_tool_boundary=phase_tool_boundary,
                    source_config_root=source_config_root,
                    environment=environment,
                    max_stdout_bytes=_MAX_STDOUT_BYTES,
                    max_stderr_bytes=_MAX_STDERR_BYTES,
                    max_line_bytes=1024 * 1024,
                    expected_version=expected_version,
                )
                projected = project_posix_v2_compat_claude_plan(claude_plan)
            except Exception as exc:
                helper_code = getattr(exc, "code", None)
                if (
                    type(helper_code) is str
                    and re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", helper_code)
                ):
                    _fail(
                        helper_code,
                        "Claude compatibility plan preflight rejected",
                        exc,
                    )
                _fail("CLAUDE_PLAN", "Claude compatibility plan was rejected", exc)
            if not isinstance(projected, Mapping):
                _fail("CLAUDE_PLAN", "Claude compatibility plan projection is malformed")
            provider_plan_projection = dict(projected)
            unsigned_plan = dict(provider_plan_projection)
            plan_sha256 = unsigned_plan.pop("plan_sha256", None)
            if (
                provider_plan_projection.get("schema")
                != "plamen.posix-v2-compat-claude-plan.v1"
                or provider_plan_projection.get("backend") != "claude"
                or provider_plan_projection.get("compatibility_mode")
                != COMPATIBILITY_MODE
                or provider_plan_projection.get("provider_session_id")
                != provider_session_id
                or provider_plan_projection.get("phase_io_contract_digest")
                != phase_io_contract.digest
                or provider_plan_projection.get("phase_io_launch_digest")
                != phase_io_launch.digest
                or provider_plan_projection.get("session_binding_sha256")
                != record.binding["session_binding_sha256"]
                or provider_plan_projection.get("executable_observation_sha256")
                != executable["observation_sha256"]
                or provider_plan_projection.get("executable_version")
                != executable["version"]
                or provider_plan_projection.get("expected_version")
                != expected_version
                or provider_plan_projection.get("model") != requested_model
                or provider_plan_projection.get("cwd") != os.fspath(scratch)
                or provider_plan_projection.get("stdin_sha256")
                != _sha(provider_prompt_raw)
                or provider_plan_projection.get("stdin_byte_count")
                != len(provider_prompt_raw)
                or provider_plan_projection.get("output_routes_sha256")
                != _sequence_sha(routing_evidence.get("output_routes", []))
                or not isinstance(plan_sha256, str)
                or plan_sha256 != _mapping_sha(unsigned_plan)
            ):
                _fail("CLAUDE_PLAN", "Claude compatibility plan binding changed")
            argv = provider_plan_projection.get("argv")
            projected_environment = provider_plan_projection.get("environment")
            if (
                not isinstance(argv, list)
                or not argv
                or any(type(item) is not str or "\x00" in item for item in argv)
                or not isinstance(projected_environment, Mapping)
                or any(
                    type(name) is not str
                    or type(value) is not str
                    or not name
                    or "\x00" in name
                    or "\x00" in value
                    for name, value in projected_environment.items()
                )
            ):
                _fail("CLAUDE_PLAN", "Claude argv/environment projection is malformed")
            command = [os.fspath(binary), *argv]
            environment = dict(projected_environment)
            auth_mode = str(provider_plan_projection.get("auth_mode") or "")
            auth_sha256 = str(
                provider_plan_projection.get("auth_binding_sha256") or ""
            )
        # This is deliberately the final admission step before Popen.  It
        # creates parent directories only; expected output leaves stay absent
        # until an actual provider process creates them.
        admitted_outputs = _admit_expected_outputs(scratch, expected_outputs)
        for route in routing_evidence.get("output_routes", []):
            staged = Path(str(route.get("path") or ""))
            staged.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            _path_without_symlink_components(
                scratch,
                staged.relative_to(scratch).as_posix(),
                label=f"staged output {route.get('identity')}",
                allow_missing_leaf=True,
            )
        if output_staging_identity is not None:
            _replay_directory(
                output_staging_root,
                output_staging_identity,
                "Claude output staging directory",
            )
        # Supplying the immutable provider-effective snapshot as stdin avoids
        # an unbounded parent-side pipe write before the timeout loop begins.
        with provider_prompt_path.open("rb") as prompt_handle:
            child = subprocess.Popen(
                command,
                stdin=prompt_handle,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                start_new_session=True,
                cwd=scratch,
                env=environment,
            )
        status = "RUNNING"
        if os.getpgid(child.pid) != child.pid:
            _terminate_group(child)
            _fail("PROCESS_GROUP", "Codex child is not its process-group leader")
        if child.stdout is None or child.stderr is None:
            _terminate_group(child)
            _fail("PROCESS_STREAM", "Codex child streams are unavailable")
        stdout_reader = _BoundedReader(child.stdout, _MAX_STDOUT_BYTES, "stdout")
        stderr_reader = _BoundedReader(child.stderr, _MAX_STDERR_BYTES, "stderr")
        deadline = time.monotonic() + float(timeout)
        while child.poll() is None:
            if stdout_reader.overflow:
                overflowed_stream = "stdout"
                break
            if stderr_reader.overflow:
                overflowed_stream = "stderr"
                break
            now = time.monotonic()
            if now >= deadline:
                timed_out = True
                break
            if _stream_stalled(now, stdout_reader, stderr_reader):
                timed_out = True
                break
            time.sleep(0.05)
        _terminate_group(child)
        if child.poll() is None:
            with contextlib.suppress(subprocess.TimeoutExpired):
                child.wait(timeout=5)
        stdout = stdout_reader.result()
        stderr = stderr_reader.result()
        if selected_backend == "codex":
            assert provider_output_last_path is not None
            try:
                provider_last_message = _read_completed_output_bytes(
                    scratch,
                    provider_output_last_path,
                    "Codex provider last message",
                )
            except PosixV2CompatRuntimeError as exc:
                provider_last_message_evidence = {
                    "status": "UNAVAILABLE",
                    "failure_code": exc.code,
                }
            else:
                provider_last_message_evidence = {
                    "status": "ADMITTED",
                    "sha256": _sha(provider_last_message),
                    "size": len(provider_last_message),
                }
                # The public file is diagnostic only. Recovery and
                # publication consume the invocation-private admitted bytes.
                with contextlib.suppress(OSError):
                    _replace_bytes(output_last_path, provider_last_message)
        if output_staging_identity is not None:
            _replay_directory(
                output_staging_root,
                output_staging_identity,
                "Claude output staging directory",
            )
        if selected_backend == "codex":
            observed_model = _observe_codex_startup_model(stderr)
        else:
            try:
                from posix_v2_compat_claude import (
                    validate_posix_v2_compat_claude_completion,
                )
                provider_completion = (
                    validate_posix_v2_compat_claude_completion(
                        claude_plan,
                        stdout=stdout,
                        stderr=stderr,
                        returncode=int(child.returncode or 0),
                    )
                )
            except Exception as exc:
                code = str(getattr(exc, "code", "CLAUDE_STREAM_EVIDENCE"))
                if code in _PROVIDER_REFUSAL_CODES:
                    provider_completion_evidence = {
                        "status": "REFUSED",
                        "failure_code": code,
                    }
                else:
                    provider_completion_evidence = {
                        "status": "REJECTED",
                        "failure_code": code,
                    }
            else:
                if not isinstance(provider_completion, Mapping):
                    provider_completion_evidence = {
                        "status": "REJECTED",
                        "failure_code": "CLAUDE_STREAM_EVIDENCE",
                    }
                else:
                    provider_completion_evidence = dict(provider_completion)
                    observed_model_value = provider_completion_evidence.get(
                        "observed_model"
                    )
                    if isinstance(observed_model_value, str):
                        observed_model = observed_model_value
        process_group_empty = _process_group_empty(child.pid)
        if not process_group_empty:
            failure_code = "PROCESS_GROUP_REMAINED_POPULATED"
            status = "CONTAINMENT_FAILED"
            return_value = COMPAT_EXIT_ERROR
        elif _restore_changed_canonical_prestates(scratch, canonical_prestates):
            failure_code = "CANONICAL_OUTPUT_MUTATION"
            status = "RUNTIME_FAILED"
            return_value = COMPAT_EXIT_ERROR
        elif overflowed_stream is not None:
            failure_code = "STREAM_LIMIT_EXCEEDED"
            status = "OUTPUT_LIMIT"
            return_value = COMPAT_EXIT_ERROR
        elif timed_out:
            failure_code = "TIMEOUT"
            status = "TIMED_OUT"
            return_value = COMPAT_TIMEOUT
        elif (
            selected_backend == "claude"
            and provider_completion_evidence is not None
            and provider_completion_evidence.get("status") != "COMPLETED"
        ):
            failure_code = str(
                provider_completion_evidence.get("failure_code")
                or "CLAUDE_STREAM_EVIDENCE"
            )
            status = (
                "PROVIDER_REFUSED"
                if failure_code in _PROVIDER_REFUSAL_CODES
                else "PROVIDER_EVIDENCE_REJECTED"
            )
            return_value = (
                -5
                if failure_code in _PROVIDER_REFUSAL_CODES
                else COMPAT_EXIT_ERROR
            )
        else:
            return_value = int(child.returncode or 0)
            if (
                observed_model is not None
                and observed_model != requested_model
            ):
                failure_code = "MODEL_BINDING_MISMATCH"
                status = "MODEL_BINDING_FAILED"
                return_value = COMPAT_EXIT_ERROR
            elif (
                return_value == 0
                or (
                    selected_backend == "codex"
                    and provider_event_profile is None
                    and staged_gate is not None
                )
            ):
                provider_returncode = return_value
                if return_value == 0 and codex_research_profile:
                    assert research_evidence_root is not None
                    provider_event_evidence = _write_research_provider_evidence(
                        scratchpad=scratch,
                        evidence_root=research_evidence_root,
                        stdout=stdout,
                    )
                elif return_value == 0 and claude_research_profile:
                    assert research_evidence_root is not None
                    assert provider_completion_evidence is not None
                    provider_event_evidence = (
                        _write_claude_research_provider_evidence(
                            scratchpad=scratch,
                            evidence_root=research_evidence_root,
                            stdout=stdout,
                            completion_evidence=provider_completion_evidence,
                        )
                    )
                if selected_backend == "codex":
                    staged_output_recovery = (
                        _recover_single_staged_output_from_provider_last_message(
                            scratch,
                            routing_evidence.get("output_routes", []),
                            provider_last_message,
                            semantic_gate_available=staged_gate is not None,
                        )
                    )
                staged_outputs = _read_staged_output_denominator(
                    scratch, routing_evidence.get("output_routes", [])
                )
                if staged_gate is not None:
                    staged_rejection_reasons = _replay_staged_gate_inputs(
                        staged_gate,
                        record=record,
                        contract=phase_io_contract,
                        launch=phase_io_launch,
                        run_id=run_id,
                    )
                    if not staged_rejection_reasons:
                        try:
                            validator_result = staged_gate.validator(
                                MappingProxyType(dict(staged_outputs)),
                                json.loads(staged_gate.context_raw.decode("ascii")),
                            )
                        except Exception as exc:
                            _fail(
                                "STAGED_VALIDATOR",
                                "staged semantic validator raised: "
                                f"{type(exc).__name__}: {exc}",
                                exc,
                            )
                        staged_rejection_reasons = _bounded_staged_reasons(
                            validator_result
                        )
                    post_validation_reasons = _replay_staged_gate_inputs(
                        staged_gate,
                        record=record,
                        contract=phase_io_contract,
                        launch=phase_io_launch,
                        run_id=run_id,
                    )
                    staged_rejection_reasons = _bounded_recorded_reasons(
                        staged_rejection_reasons + post_validation_reasons
                    )
                if _restore_changed_canonical_prestates(
                    scratch, canonical_prestates
                ):
                    failure_code = "CANONICAL_OUTPUT_MUTATION"
                    status = "RUNTIME_FAILED"
                    return_value = COMPAT_EXIT_ERROR
                elif staged_rejection_reasons:
                    failure_code = "STAGED_SEMANTIC_REJECTED"
                    status = "STAGED_SEMANTIC_REJECTED"
                    return_value = COMPAT_TIMEOUT
                else:
                    publication_journal_path, publication_journal = (
                        _prepare_publication_transaction(
                            scratch,
                            invocation_private,
                            invocation_uuid,
                            (
                                receipt_directory.relative_to(scratch)
                                / f"{receipt_stem}.json"
                            ).as_posix(),
                            routing_evidence.get("output_routes", []),
                            canonical_prestates,
                            staged_outputs,
                        )
                    )
                    publication_journal, completed_output_evidence = (
                        _publish_prepared_transaction(
                            scratch,
                            publication_journal_path,
                            publication_journal,
                            canonical_prestates,
                        )
                    )
                    assert private_root_descriptor is not None
                    assert private_root_identity is not None
                    _cleanup_private_invocation_payload(
                        private_root_descriptor,
                        invocation_uuid,
                        retained_names=frozenset({
                            _PUBLICATION_JOURNAL_NAME,
                            _PUBLICATION_SUCCESSOR_DIRECTORY,
                        }),
                        root_device=int(private_root_identity[0]),
                    )
                    canonical_publication_complete = True
                    status = "COMPLETED"
                    failure_code = None
                    if provider_returncode != 0:
                        assert staged_gate is not None
                        provider_nonzero_semantic_completion = (
                            build_provider_nonzero_semantic_completion(
                                provider_returncode=provider_returncode,
                                validator_binding=staged_gate.binding,
                                completed_output_evidence=completed_output_evidence,
                            )
                        )
                        # The provider exit remains recorded in ``returncode``
                        # and the typed companion above.  The compatibility
                        # transaction itself succeeded because the complete
                        # denominator passed the frozen semantic gate.
                        return_value = 0
            else:
                status = "NONZERO_EXIT"
                failure_code = "NONZERO_EXIT"
    except PosixV2CompatRuntimeError as exc:
        failure_code = exc.code
        status = (
            "CLEANUP_FAILED"
            if exc.code == "PRIVATE_RUNTIME_CLEANUP"
            else ("RUNTIME_FAILED" if child is not None else "PRELAUNCH_FAILED")
        )
        stderr = stderr + (str(exc) + "\n").encode("utf-8", errors="replace")
        if child is not None:
            _terminate_group(child)
            process_group_empty = _process_group_empty(child.pid)
        return_value = COMPAT_EXIT_ERROR
    except BaseException as exc:
        failure_code = f"UNEXPECTED_{type(exc).__name__.upper()}"
        status = "RUNTIME_FAILED" if child is not None else "PRELAUNCH_FAILED"
        stderr = stderr + (
            f"compatibility runtime failed: {type(exc).__name__}: {exc}\n"
        ).encode("utf-8", errors="replace")
        if child is not None:
            _terminate_group(child)
            process_group_empty = _process_group_empty(child.pid)
        return_value = COMPAT_EXIT_ERROR
    finally:
        cleanup_error: BaseException | None = None
        prestate_restore_error: BaseException | None = None
        canonical_mutation_restored = False
        if canonical_prestates and not canonical_publication_complete:
            try:
                if publication_journal_path is not None and publication_journal is not None:
                    publication_journal = _rollback_publication_transaction(
                        scratch, publication_journal_path, publication_journal
                    )
                    completed_output_evidence = []
                else:
                    canonical_mutation_restored = _restore_changed_canonical_prestates(
                        scratch, canonical_prestates
                    )
            except BaseException as exc:
                prestate_restore_error = exc
        if (
            private_root_descriptor is not None
            and private_root_identity is not None
            and invocation_private_created
            and not canonical_publication_complete
        ):
            try:
                _cleanup_private_entry(
                    private_root_descriptor,
                    invocation_uuid,
                    budget=_PrivateCleanupBudget(
                        root_device=int(private_root_identity[0])
                    ),
                    expected_identity=invocation_private_identity,
                    require_private_mode=False,
                )
                _replay_private_runtime_root(
                    scratch,
                    private_root_descriptor,
                    private_root_identity,
                )
            except BaseException as exc:
                cleanup_error = exc
        if cleanup_error is not None:
            status = "CLEANUP_FAILED"
            failure_code = "PRIVATE_RUNTIME_CLEANUP"
            return_value = COMPAT_EXIT_ERROR
            completed_output_evidence = []
            stderr = stderr + (
                "private runtime cleanup failed: "
                f"{type(cleanup_error).__name__}: {cleanup_error}\n"
            ).encode("utf-8", errors="replace")
        if prestate_restore_error is not None and cleanup_error is None:
            status = "RUNTIME_FAILED"
            failure_code = "CANONICAL_RESTORE"
            return_value = COMPAT_EXIT_ERROR
            completed_output_evidence = []
            stderr = stderr + (
                "canonical output restoration failed: "
                f"{type(prestate_restore_error).__name__}: "
                f"{prestate_restore_error}\n"
            ).encode("utf-8", errors="replace")
        elif canonical_mutation_restored and cleanup_error is None:
            status = "RUNTIME_FAILED"
            failure_code = "CANONICAL_OUTPUT_MUTATION"
            return_value = COMPAT_EXIT_ERROR
            completed_output_evidence = []
            stderr = stderr + b"direct canonical output mutation was restored\n"
        combined = stdout + (
            b"" if not stderr else b"\n[plamen-compat-stderr]\n" + stderr
        )
        with contextlib.suppress(BaseException):
            _replace_bytes(log_path, combined)
        output_last_sha: str | None = None
        output_last_size: int | None = None
        with contextlib.suppress(OSError):
            if output_last_path.is_file() and not output_last_path.is_symlink():
                last_raw = output_last_path.read_bytes()
                output_last_sha = _sha(last_raw)
                output_last_size = len(last_raw)
        receipt = {
            "schema": RECEIPT_SCHEMA,
            "mode": COMPATIBILITY_MODE,
            "status": status,
            "failure_code": failure_code,
            "run_id": record.binding["run_id"],
            "phase": phase,
            "label": worker_label,
            "attempt": attempt,
            "invocation_id": invocation_uuid,
            "session_binding_sha256": record.binding[
                "session_binding_sha256"
            ],
            "backend": selected_backend,
            "requested_model": requested_model,
            "model_binding": "EXPLICIT_CLI_ARGUMENT",
            "observed_model": observed_model,
            "model_observation": (
                "NOT_OBSERVED"
                if observed_model is None
                else (
                    "MATCH"
                    if observed_model == requested_model
                    else "MISMATCH"
                )
            ),
            "needs_mcp": needs_mcp,
            "ambient_mcp_config_loaded": False,
            "provider_event_profile": provider_event_profile,
            "provider_event_evidence": provider_event_evidence,
            "methodology_prompt_sha256": _sha(prompt_raw),
            "methodology_prompt_size": len(prompt_raw),
            "provider_effective_prompt_sha256": (
                _sha(provider_prompt_raw) if provider_prompt_raw else None
            ),
            "provider_effective_prompt_size": (
                len(provider_prompt_raw) if provider_prompt_raw else None
            ),
            "phase_io_contract_digest": routing_evidence.get(
                "phase_io_contract_digest"
            ),
            "phase_io_launch_digest": routing_evidence.get(
                "phase_io_launch_digest"
            ),
            "phase_io_input_set_digest": routing_evidence.get(
                "input_set_digest"
            ),
            "phase_io_output_prestate_digest": routing_evidence.get(
                "output_prestate_digest"
            ),
            "phase_io_input_routes_digest": routing_evidence.get(
                "input_routes_digest"
            ),
            "phase_io_output_routes_digest": routing_evidence.get(
                "output_routes_digest"
            ),
            "phase_io_routing_digest": routing_evidence.get(
                "routing_digest"
            ),
            "phase_io_input_routes": routing_evidence.get(
                "input_routes", []
            ),
            "phase_io_output_routes": routing_evidence.get(
                "output_routes", []
            ),
            "staged_output_validator_binding": (
                None if staged_gate is None else dict(staged_gate.binding)
            ),
            "staged_output_context": (
                None
                if staged_gate is None
                else json.loads(staged_gate.context_raw.decode("ascii"))
            ),
            "staged_output_input_bindings": (
                {}
                if staged_gate is None
                else json.loads(staged_gate.input_bindings_raw.decode("ascii"))[
                    "bindings"
                ]
            ),
            "staged_output_rejection_reasons": staged_rejection_reasons,
            "publication_transaction_binding_sha256": (
                None
                if publication_journal is None
                else _publication_transaction_binding(publication_journal)
            ),
            "prompt_sha256": _sha(prompt_raw),
            "prompt_size": len(prompt_raw),
            "completed_output_evidence": completed_output_evidence,
            "requested_read_working_directory": os.fspath(working),
            "requested_read_working_directory_identity_sha256": _mapping_sha(
                working_identity
            ),
            "codex_workspace_directory": (
                os.fspath(scratch) if selected_backend == "codex" else None
            ),
            "actual_write_roots": [
                os.fspath(scratch),
                *[
                    os.fspath(path)
                    for path in writable
                    if path != scratch
                ],
            ],
            "codex_binary": (
                None
                if selected_backend != "codex" or binary is None
                else os.fspath(binary)
            ),
            "codex_binary_sha256": (
                binary_sha256 if selected_backend == "codex" else None
            ),
            "codex_version": (
                binary_version if selected_backend == "codex" else None
            ),
            "argv": command,
            "auth_mode": auth_mode,
            "auth_sha256": auth_sha256,
            "environment_names": sorted(environment),
            "isolation": {
                "codex_sandbox_requested": (
                    "workspace-write" if selected_backend == "codex" else None
                ),
                "approval_policy_requested": (
                    "never" if selected_backend == "codex" else None
                ),
                "dangerous_bypass_requested": False,
                "ignore_user_config": True,
                "ignore_rules": True,
                "ephemeral": True,
                "process_group_created_before_exec": child is not None,
                "process_group_empty_observed": process_group_empty,
                "population_zero_proven": False,
                "escaped_descendants_excluded_from_observation": True,
                "exhaustive_descendant_termination_authority": False,
                "native_broker_authority": False,
                "wer_authority": False,
                "project_read_confinement_os_enforced": False,
                "exact_input_read_confinement_os_enforced": False,
                "exact_output_write_confinement_os_enforced": False,
                "foreign_write_detection_exhaustive": False,
                "compatibility_write_containment": (
                    "WORKSPACE_WRITE_PLUS_PROMPT_ENFORCEMENT_REDUCED_ASSURANCE"
                ),
            },
            "returncode": (
                None if child is None or child.returncode is None else child.returncode
            ),
            "compatibility_return_value": return_value,
            "timed_out": timed_out,
            "overflowed_stream": overflowed_stream,
            "stdout_sha256": _sha(stdout),
            "stdout_size": len(stdout),
            "stderr_sha256": _sha(stderr),
            "stderr_size": len(stderr),
            "output_last_message_sha256": output_last_sha,
            "output_last_message_size": output_last_size,
            "provider_last_message_evidence": provider_last_message_evidence,
            "staged_output_recovery": staged_output_recovery,
            "provider_nonzero_semantic_completion": (
                provider_nonzero_semantic_completion
            ),
            "started_at_unix_ns": started_wall_ns,
            "completed_at_unix_ns": time.time_ns(),
            "duration_monotonic_ns": int(
                (time.monotonic() - started_monotonic) * 1_000_000_000
            ),
        }
        if selected_backend == "claude" and provider_plan_projection is not None:
            receipt["provider_execution"] = {
                "schema": "plamen.posix_v2_compat_claude_execution.v1",
                "provider_session_id": provider_plan_projection.get(
                    "provider_session_id"
                ),
                "executable_observation_sha256": provider_plan_projection.get(
                    "executable_observation_sha256"
                ),
                "executable_observation": claude_executable_observation,
                "executable_path": (
                    None if binary is None else os.fspath(binary)
                ),
                "executable_version": binary_version,
                "executable_sha256": binary_sha256,
                "provider_plan_sha256": provider_plan_projection.get(
                    "plan_sha256"
                ),
                "provider_plan": provider_plan_projection,
                "profile_sha256": provider_plan_projection.get(
                    "profile_sha256"
                ),
                "expected_init_contract_sha256": provider_plan_projection.get(
                    "expected_init_contract_sha256"
                ),
                "expected_version": provider_plan_projection.get(
                    "expected_version"
                ),
                "auth_mode": auth_mode,
                "auth_binding_sha256": auth_sha256,
                "completion_evidence": provider_completion_evidence,
                "reduced_isolation": True,
                "native_broker_authority": False,
                "wer_authority": False,
            }
        try:
            _persist_receipt(receipt_directory, receipt_stem, receipt)
        except BaseException as exc:
            if (
                canonical_publication_complete
                and publication_journal_path is not None
                and publication_journal is not None
            ):
                try:
                    publication_journal = _rollback_publication_transaction(
                        scratch, publication_journal_path, publication_journal
                    )
                    canonical_publication_complete = False
                    if (
                        private_root_descriptor is not None
                        and private_root_identity is not None
                    ):
                        _cleanup_private_entry(
                            private_root_descriptor,
                            invocation_uuid,
                            budget=_PrivateCleanupBudget(
                                root_device=int(private_root_identity[0])
                            ),
                            expected_identity=invocation_private_identity,
                            require_private_mode=False,
                        )
                except BaseException as rollback_exc:
                    stderr = stderr + (
                        "publication rollback after receipt failure failed: "
                        f"{type(rollback_exc).__name__}: {rollback_exc}\n"
                    ).encode("utf-8", errors="replace")
            status = "RECEIPT_FAILED"
            failure_code = "RECEIPT_PERSISTENCE"
            return_value = COMPAT_EXIT_ERROR
            completed_output_evidence = []
            receipt.update({
                "status": status,
                "failure_code": failure_code,
                "compatibility_return_value": return_value,
                "completed_output_evidence": [],
            })
            receipt.pop("receipt_sha256", None)
            receipt["receipt_sha256"] = _mapping_sha(receipt)
            receipt_path = receipt_directory / f"{receipt_stem}.json"
            try:
                if receipt_directory.is_symlink() or not receipt_directory.is_dir():
                    raise OSError("receipt directory is unavailable or aliased")
                _replace_bytes(
                    receipt_path, _canonical_bytes(receipt) + b"\n", 0o400
                )
            except BaseException:
                with contextlib.suppress(OSError):
                    receipt_path.unlink()
            with contextlib.suppress(BaseException):
                _replace_bytes(
                    log_path,
                    combined
                    + (
                        "\ncompatibility receipt persistence failed: "
                        f"{type(exc).__name__}: {exc}\n"
                    ).encode("utf-8", errors="replace"),
                )
        else:
            if (
                canonical_publication_complete
                and publication_journal_path is not None
                and publication_journal is not None
            ):
                try:
                    publication_journal = _finish_committed_publication(
                        scratch,
                        publication_journal_path,
                        publication_journal,
                    )
                    if (
                        private_root_descriptor is not None
                        and private_root_identity is not None
                    ):
                        _cleanup_private_entry(
                            private_root_descriptor,
                            invocation_uuid,
                            budget=_PrivateCleanupBudget(
                                root_device=int(private_root_identity[0])
                            ),
                            expected_identity=invocation_private_identity,
                            require_private_mode=False,
                        )
                except BaseException as exc:
                    # COMPLETED receipt persistence is the commit point.  WAL
                    # garbage collection cannot downgrade it; startup recovery
                    # validates the successor denominator and retries cleanup.
                    with contextlib.suppress(BaseException):
                        _replace_bytes(
                            log_path,
                            combined
                            + (
                                "\ncommitted publication WAL cleanup deferred: "
                                f"{type(exc).__name__}: {exc}\n"
                            ).encode("utf-8", errors="replace"),
                        )
        if private_root_descriptor is not None:
            with contextlib.suppress(OSError):
                fcntl.flock(private_root_descriptor, fcntl.LOCK_UN)
            with contextlib.suppress(OSError):
                os.close(private_root_descriptor)
        with record.lock:
            record.active_invocations.discard(invocation_key)
            record.used_invocations.add(invocation_key)
    return return_value


POC_REQUEST_SCHEMA = "plamen.posix_v2_compat_mechanical_poc_request.v1"
POC_TERMINAL_SCHEMA = "plamen.posix_v2_compat_mechanical_poc_terminal.v1"
POC_EXEC_START_SCHEMA = "plamen.posix_v2_compat_exec_start.v1"
_POC_RECEIPT_DIRECTORY = ".posix_v2_compat_poc_receipts"
_POC_MAX_REQUEST_BYTES = 2 * 1024 * 1024
_POC_MAX_EXECUTABLE_BYTES = 1024 * 1024 * 1024
_POC_MAX_TREE_FILES = 100_000
_POC_MAX_TREE_BYTES = 8 * 1024 * 1024 * 1024
_POC_MAX_EXPECTED_OUTPUTS = 64
_POC_SHA_RE = re.compile(r"[0-9a-f]{64}")
_POC_CONTROL_MAX_BYTES = 16 * 1024

_POC_REQUEST_KEYS = frozenset({
    "schema", "request_sha256", "session_binding_sha256", "run_id",
    "purpose", "work_unit_id", "finding_id", "constituent_id",
    "attempt_number", "work_authority_sha256", "policy_sha256",
    "verifier_receipt_sha256",
    "supply_chain_admission_sha256", "audit_snapshot_sha256",
    "source_census_sha256", "source_build_root",
    "source_build_root_identity_sha256", "workspace_root",
    "workspace_root_identity_sha256", "workspace_pre_tree_sha256",
    "subject_kind", "subject_relative_path", "subject_sha256", "subject_size",
    "test_function",
    "tool_id", "executable_path", "executable_sha256", "executable_size",
    "argv", "cwd_relative_path", "environment", "timeout_seconds",
    "stdout_limit_bytes", "stderr_limit_bytes", "expected_outputs",
    "offline_intent",
})

_POC_FORBIDDEN_ENVIRONMENT_NAMES = frozenset({
    "BASH_ENV", "ENV", "GIT_CONFIG", "GIT_CONFIG_GLOBAL",
    "GIT_CONFIG_SYSTEM", "LD_AUDIT", "LD_LIBRARY_PATH", "LD_PRELOAD",
    "NODE_OPTIONS", "PERL5OPT", "PYTHONHOME", "PYTHONPATH", "RUBYOPT",
})


def _poc_sha(value: object, label: str) -> str:
    if type(value) is not str or _POC_SHA_RE.fullmatch(value) is None:
        _fail("POC_REQUEST", f"{label} must be lowercase SHA-256")
    return value


def _poc_strict_request(raw: object) -> tuple[dict[str, Any], bytes]:
    if type(raw) is not bytes or not raw or len(raw) > _POC_MAX_REQUEST_BYTES:
        _fail("POC_REQUEST", "request bytes are absent or exceed the bound")
    if raw.endswith(b"\n"):
        _fail("POC_REQUEST", "request bytes must not contain a trailing newline")

    def pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in values:
            if key in result:
                raise ValueError(f"duplicate key {key!r}")
            result[key] = value
        return result

    try:
        parsed = json.loads(
            raw.decode("ascii", errors="strict"),
            object_pairs_hook=pairs,
            parse_constant=lambda value: (_ for _ in ()).throw(
                ValueError(f"non-finite number {value}")
            ),
        )
    except (UnicodeError, ValueError, json.JSONDecodeError) as exc:
        _fail("POC_REQUEST", "request is not strict canonical JSON", exc)
    if type(parsed) is not dict or set(parsed) != _POC_REQUEST_KEYS:
        _fail("POC_REQUEST", "request field denominator differs")
    if _canonical_bytes(parsed) != raw:
        _fail("POC_REQUEST", "request bytes are not canonical")
    unsigned = dict(parsed)
    declared = unsigned.pop("request_sha256")
    if _poc_sha(declared, "request_sha256") != _mapping_sha(unsigned):
        _fail("POC_REQUEST", "request self-digest differs")
    return parsed, raw


def _poc_relative(value: object, label: str, *, allow_root: bool = False) -> str:
    if type(value) is not str or not value or "\x00" in value:
        _fail("POC_REQUEST", f"{label} is not canonical relative text")
    if value == ".":
        if allow_root:
            return value
        _fail("POC_REQUEST", f"{label} cannot name the workspace root")
    path = Path(value)
    if (
        path.is_absolute()
        or path.as_posix() != value
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        _fail("POC_REQUEST", f"{label} is not a canonical relative path")
    return value


def _poc_file_binding(path: Path, *, label: str, maximum: int) -> dict[str, Any]:
    descriptor = _open_readonly_nofollow(path, label)
    assert descriptor is not None
    try:
        observed = os.fstat(descriptor)
        if (
            not stat.S_ISREG(observed.st_mode)
            or int(observed.st_nlink) != 1
            or int(observed.st_size) < 0
            or int(observed.st_size) > maximum
        ):
            _fail("POC_FILE", f"{label} is not an admitted regular file")
        if int(observed.st_size) == 0:
            digest = hashlib.sha256(b"").hexdigest()
            after = os.fstat(descriptor)
            if _stable_file_identity(after) != _stable_file_identity(observed):
                _fail("POC_FILE", f"{label} changed while hashing")
        else:
            digest = _hash_exact_regular_fd(
                descriptor,
                observed,
                maximum=maximum,
                label=label,
            )
        return {
            "device": int(observed.st_dev),
            "inode": int(observed.st_ino),
            "mode": int(observed.st_mode),
            "owner": int(observed.st_uid),
            "group": int(observed.st_gid),
            "size": int(observed.st_size),
            "mtime_ns": int(observed.st_mtime_ns),
            "ctime_ns": int(observed.st_ctime_ns),
            "sha256": digest,
        }
    finally:
        os.close(descriptor)


def _poc_tree_digest(root: Path) -> tuple[str, int, int]:
    rows: list[dict[str, Any]] = []
    total = 0
    for current, directory_names, file_names in os.walk(root, followlinks=False):
        current_path = Path(current)
        directory_names.sort(key=lambda value: os.fsencode(value))
        file_names.sort(key=lambda value: os.fsencode(value))
        for directory_name in directory_names:
            child = current_path / directory_name
            observed = child.lstat()
            if stat.S_ISLNK(observed.st_mode) or not stat.S_ISDIR(observed.st_mode):
                _fail("POC_WORKSPACE", "workspace contains an aliased directory")
        for file_name in file_names:
            child = current_path / file_name
            relative = child.relative_to(root).as_posix()
            binding = _poc_file_binding(
                child,
                label=f"workspace member {relative}",
                maximum=_POC_MAX_TREE_BYTES,
            )
            total += int(binding["size"])
            if len(rows) >= _POC_MAX_TREE_FILES or total > _POC_MAX_TREE_BYTES:
                _fail("POC_WORKSPACE", "workspace census exceeds its bound")
            rows.append({
                "path": relative,
                "size": binding["size"],
                "sha256": binding["sha256"],
            })
    rows.sort(key=lambda row: os.fsencode(str(row["path"])))
    return _sha(json.dumps(
        rows,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")), len(rows), total


def _poc_environment(
    value: object,
    *,
    workspace: Path,
    project: Path,
) -> dict[str, str]:
    if type(value) is not dict or not value or len(value) > 128:
        _fail("POC_ENVIRONMENT", "closed environment denominator is invalid")
    result: dict[str, str] = {}
    for key, item in value.items():
        if (
            type(key) is not str
            or not key
            or "=" in key
            or "\x00" in key
            or type(item) is not str
            or "\x00" in item
            or len(item.encode("utf-8", errors="strict")) > 65_536
        ):
            _fail("POC_ENVIRONMENT", "closed environment entry is invalid")
        upper = key.upper()
        if upper in _POC_FORBIDDEN_ENVIRONMENT_NAMES or upper.startswith("DYLD_"):
            _fail("POC_ENVIRONMENT", f"unsafe environment name {key!r}")
        result[key] = item
    for name in ("PATH", "HOME", "TMPDIR"):
        if not result.get(name):
            _fail("POC_ENVIRONMENT", f"closed environment lacks {name}")
    for name in ("HOME", "TMPDIR"):
        path, _identity = _safe_directory(result[name], f"environment {name}")
        if not _is_within(path, workspace):
            _fail("POC_ENVIRONMENT", f"{name} must be inside the workspace")
    for raw in result["PATH"].split(os.pathsep):
        if not raw:
            _fail("POC_ENVIRONMENT", "PATH contains an empty member")
        member, _identity = _safe_directory(raw, "environment PATH member")
        if _is_within(member, project):
            _fail("POC_ENVIRONMENT", "PATH cannot admit target-controlled tools")
    return result


def _poc_start_observation(
    raw: bytes, *, nonce: str, request_sha256: str, executable_sha256: str,
) -> tuple[bool, bool, int | None, str]:
    """Validate helper-only acknowledgements; never infer test-body execution."""
    if not raw or len(raw) > _POC_CONTROL_MAX_BYTES or not raw.endswith(b"\n"):
        return False, False, None, "CONTROL_ACK_ABSENT_OR_TRUNCATED"
    try:
        lines = raw.decode("ascii").splitlines()
        rows = [json.loads(line) for line in lines]
    except (UnicodeError, ValueError, TypeError):
        return False, False, None, "CONTROL_ACK_MALFORMED"
    if any(_canonical_bytes(row) != line.encode("ascii")
           for row, line in zip(rows, lines)):
        return False, False, None, "CONTROL_ACK_NONCANONICAL"
    common = {"schema": POC_EXEC_START_SCHEMA, "nonce": nonce,
              "request_sha256": request_sha256,
              "executable_sha256": executable_sha256}
    if not rows or not isinstance(rows[0], dict) or any(rows[0].get(k) != v for k, v in common.items()):
        return False, False, None, "CONTROL_START_ACK_INVALID"
    start = rows[0]
    if (set(start) != {*common, "kind", "pid"}
            or start.get("kind") != "EXEC_STARTED"
            or type(start.get("pid")) is not int or start["pid"] <= 0):
        return False, False, None, "CONTROL_START_ACK_INVALID"
    if len(rows) == 1:
        return True, False, None, "CONTROL_COMPLETION_ACK_ABSENT"
    if len(rows) != 2 or not isinstance(rows[1], dict) or any(rows[1].get(k) != v for k, v in common.items()):
        return True, False, None, "CONTROL_COMPLETION_ACK_INVALID"
    completion = rows[1]
    if (set(completion) != {*common, "kind", "returncode"}
            or completion.get("kind") != "EXEC_COMPLETED"
            or type(completion.get("returncode")) is not int):
        return True, False, None, "CONTROL_COMPLETION_ACK_INVALID"
    return True, True, int(completion["returncode"]), "ACKNOWLEDGED"


def _poc_prepare_helper_launch(
    helper_prefix: Sequence[str], helper_suffix: Sequence[str], workspace: Path,
) -> tuple[list[str], str, int, int]:
    """Create the private channel with ownership established before wrapping."""
    read_fd = -1
    write_fd = -1
    try:
        read_fd, write_fd = os.pipe()
        os.set_inheritable(read_fd, False)
        os.set_inheritable(write_fd, True)
        helper_argv = [*helper_prefix, str(write_fd), *helper_suffix]
        physical, confinement = _poc_physical_argv(helper_argv, workspace)
        return physical, confinement, read_fd, write_fd
    except BaseException:
        for descriptor in (read_fd, write_fd):
            if descriptor >= 0:
                with contextlib.suppress(OSError):
                    os.close(descriptor)
        raise


def _poc_scheme_string(value: str) -> str:
    if not value or "\x00" in value or any(ord(character) < 32 for character in value):
        _fail("POC_SANDBOX", "Seatbelt root contains control bytes")
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _poc_physical_argv(argv: Sequence[str], workspace: Path) -> tuple[list[str], str]:
    requested = list(argv)
    if sys.platform != "darwin":
        return requested, "UNAVAILABLE_NON_DARWIN"
    sandbox_exec = Path("/usr/bin/sandbox-exec")
    try:
        observed = sandbox_exec.stat(follow_symlinks=False)
        resolved = sandbox_exec.resolve(strict=True)
    except OSError as exc:
        _fail("POC_SANDBOX", "macOS Seatbelt provider is unavailable", exc)
    if not stat.S_ISREG(observed.st_mode) or not os.access(resolved, os.X_OK):
        _fail("POC_SANDBOX", "macOS Seatbelt provider is not executable")
    profile = "\n".join((
        "(version 1)",
        "(allow default)",
        "(deny file-write*)",
        "(allow file-write* (subpath " + _poc_scheme_string(os.fspath(workspace)) + "))",
    )) + "\n"
    return [os.fspath(resolved), "-p", profile, *requested], "DARWIN_SEATBELT"


class PosixV2CompatMechanicalPoCTerminal(metaclass=_FrozenAuthorityType):
    __slots__ = ("__token", "__creator_pid", "__interpreter_nonce", "__weakref__")

    def __init__(self, *_args: Any, **_kwargs: Any) -> None:
        raise TypeError("POSIX V2 mechanical PoC terminals are issuer-created")

    def __init_subclass__(cls, **_kwargs: Any) -> NoReturn:
        raise TypeError("POSIX V2 mechanical PoC terminals cannot be subclassed")

    def __copy__(self) -> NoReturn:
        raise TypeError("POSIX V2 mechanical PoC terminals cannot be copied")

    def __deepcopy__(self, _memo: Any) -> NoReturn:
        raise TypeError("POSIX V2 mechanical PoC terminals cannot be copied")

    def __reduce__(self) -> NoReturn:
        raise TypeError("POSIX V2 mechanical PoC terminals cannot be serialized")

    def __reduce_ex__(self, _protocol: int) -> NoReturn:
        raise TypeError("POSIX V2 mechanical PoC terminals cannot be serialized")

    def __repr__(self) -> str:
        return "<PosixV2CompatMechanicalPoCTerminal opaque>"


@dataclass(frozen=True)
class PosixV2CompatMechanicalProcessOutcome:
    """Authenticated transport observation, not semantic PoC authority."""
    request_sha256: str
    purpose: str
    work_unit_id: str
    finding_id: str | None
    constituent_id: str | None
    attempt_number: int
    policy_sha256: str | None
    verifier_receipt_sha256: str | None
    work_authority_sha256: str
    supply_chain_admission_sha256: str
    audit_snapshot_sha256: str
    source_census_sha256: str
    executable_path: str
    executable_sha256: str
    argv: tuple[str, ...]
    tool_id: str
    status: str
    actual_tool_started: bool
    start_observation_complete: bool
    completion_observed: bool
    selected_test_body_started: bool
    selected_test_body_observation: str
    actual_process_returncode: int | None
    wrapper_returncode: int | None
    timed_out: bool
    overflowed_stream: str | None
    stdout: bytes
    stderr: bytes
    stdout_complete: bool
    stderr_complete: bool
    terminal_sha256: str
    reduced_isolation: bool
    population_zero_proven: bool


@dataclass(frozen=True)
class _PoCRetainedStream:
    path: Path
    identity: tuple[int, ...]
    sha256: str


@dataclass(frozen=True)
class _PoCTerminalRecord:
    token: str
    creator_pid: int
    interpreter_nonce: str
    authority_ref: weakref.ReferenceType[Any]
    session_id: int
    operation_key: str
    request_sha256: str
    raw: bytes
    receipt_path: Path
    receipt_identity: tuple[int, ...]
    streams: tuple[_PoCRetainedStream, _PoCRetainedStream]


@dataclass(frozen=True)
class _PoCCommittedExecution:
    request_sha256: str
    terminal: PosixV2CompatMechanicalPoCTerminal


_POC_TERMINALS: dict[int, _PoCTerminalRecord] = {}
_POC_COMMITTED_BY_SESSION: dict[int, dict[str, _PoCCommittedExecution]] = {}
_POC_ACTIVE_OWNERS: dict[tuple[int, str], object] = {}


def _poc_terminal_record(
    session_authority: object,
    terminal: object,
) -> _PoCTerminalRecord:
    _session_record(session_authority)
    if type(terminal) is not PosixV2CompatMechanicalPoCTerminal:
        _fail("POC_TERMINAL", "terminal has the wrong exact type")
    record = _POC_TERMINALS.get(id(terminal))
    if record is None:
        _fail("POC_TERMINAL", "terminal is absent or no longer issued")
    try:
        token = object.__getattribute__(
            terminal, "_PosixV2CompatMechanicalPoCTerminal__token"
        )
        creator_pid = object.__getattribute__(
            terminal, "_PosixV2CompatMechanicalPoCTerminal__creator_pid"
        )
        interpreter_nonce = object.__getattribute__(
            terminal, "_PosixV2CompatMechanicalPoCTerminal__interpreter_nonce"
        )
    except BaseException as exc:
        _fail("POC_TERMINAL", "terminal shell is incomplete", exc)
    if (
        record.authority_ref() is not terminal
        or token != record.token
        or creator_pid != record.creator_pid
        or creator_pid != os.getpid()
        or interpreter_nonce != record.interpreter_nonce
        or interpreter_nonce != _INTERPRETER_NONCE
        or record.session_id != id(session_authority)
    ):
        _fail("POC_TERMINAL", "terminal is forged, inherited, or cross-session")
    return record


def _poc_project_terminal_record(
    session_authority: object,
    terminal: PosixV2CompatMechanicalPoCTerminal,
) -> _PoCTerminalRecord:

    record = _poc_terminal_record(session_authority, terminal)
    session = _session_record(session_authority)
    _path_without_symlink_components(
        session.scratchpad,
        record.receipt_path.relative_to(session.scratchpad).as_posix(),
        label="mechanical process terminal",
        allow_missing_leaf=False,
    )
    try:
        observed = record.receipt_path.lstat()
        current = record.receipt_path.read_bytes()
    except OSError as exc:
        _fail("POC_TERMINAL", "durable terminal is unavailable", exc)
    if (
        _stable_file_identity(observed) != record.receipt_identity
        or current != record.raw + b"\n"
        or _sha(record.raw) != _sha(current[:-1])
    ):
        _fail("POC_TERMINAL", "durable terminal bytes or identity changed")
    return record


def _poc_replay_streams(record: _PoCTerminalRecord) -> tuple[bytes, bytes]:
    retained: list[bytes] = []
    for stream in record.streams:
        label = "retained mechanical process stream"
        descriptor = _open_readonly_nofollow(stream.path, label)
        assert descriptor is not None
        try:
            observed = os.fstat(descriptor)
            if (
                _stable_file_identity(observed) != stream.identity
                or not stat.S_ISREG(observed.st_mode)
                or observed.st_nlink != 1
                or not 0 <= observed.st_size <= _MAX_STDOUT_BYTES
            ):
                _fail("POC_STREAM", "retained stream identity changed")
            if observed.st_size:
                raw = _read_exact_regular_fd(
                    descriptor, observed, maximum=_MAX_STDOUT_BYTES, label=label
                )
            else:
                raw = os.read(descriptor, 1)
                if raw or _stable_file_identity(os.fstat(descriptor)) != stream.identity:
                    _fail("POC_STREAM", "empty retained stream changed")
            if _sha(raw) != stream.sha256:
                _fail("POC_STREAM", "retained stream bytes changed")
            retained.append(raw)
        finally:
            os.close(descriptor)
    return retained[0], retained[1]


def project_posix_v2_compat_mechanical_poc_terminal(
    session_authority: object,
    terminal: PosixV2CompatMechanicalPoCTerminal,
) -> bytes:
    """Replay a live terminal and its retained streams, never JSON authority."""

    record = _poc_project_terminal_record(session_authority, terminal)
    _poc_replay_streams(record)
    return record.raw


def project_posix_v2_compat_mechanical_poc_streams(
    session_authority: object,
    terminal: PosixV2CompatMechanicalPoCTerminal,
) -> tuple[bytes, bytes]:
    """Return authenticated retained stdout/stderr; prefixes are not full logs.

    Completeness and truncation remain explicit in the terminal. These bytes
    are raw process observations, not proof that a particular test started.
    Durable sidecars survive session close, but cannot recreate live authority.
    """

    return _poc_replay_streams(
        _poc_project_terminal_record(session_authority, terminal)
    )


def project_posix_v2_compat_mechanical_process_outcome(
    session_authority: object,
    terminal: PosixV2CompatMechanicalPoCTerminal,
) -> PosixV2CompatMechanicalProcessOutcome:
    """Project exact live terminal+streams without upgrading semantic proof."""
    record = _poc_project_terminal_record(session_authority, terminal)
    stdout, stderr = _poc_replay_streams(record)
    try:
        value = json.loads(record.raw)
    except (ValueError, TypeError) as exc:
        _fail("POC_TERMINAL", "authenticated terminal JSON is malformed", exc)
    bindings = value.get("candidate_request_bindings")
    if not isinstance(bindings, dict):
        # Legacy terminals retain their historical UNKNOWN semantics but do not
        # acquire a typed candidate outcome retroactively.
        _fail("POC_OUTCOME_LEGACY", "terminal predates typed candidate bindings")
    return PosixV2CompatMechanicalProcessOutcome(
        request_sha256=value["request_sha256"], purpose=value["purpose"],
        work_unit_id=value["work_unit_id"], finding_id=value["finding_id"],
        constituent_id=value["constituent_id"], attempt_number=value["attempt_number"],
        policy_sha256=bindings["policy_sha256"],
        verifier_receipt_sha256=bindings["verifier_receipt_sha256"],
        work_authority_sha256=bindings["work_authority_sha256"],
        supply_chain_admission_sha256=bindings["supply_chain_admission_sha256"],
        audit_snapshot_sha256=bindings["audit_snapshot_sha256"],
        source_census_sha256=bindings["source_census_sha256"],
        executable_path=bindings["executable_path"],
        executable_sha256=bindings["executable_sha256"],
        argv=tuple(bindings["argv"]), tool_id=value["tool_id"], status=value["status"],
        actual_tool_started=value["actual_tool_started"],
        start_observation_complete=value["actual_tool_start_observation_complete"],
        completion_observed=value["actual_tool_completion_observed"],
        selected_test_body_started=False,
        selected_test_body_observation="UNPROVEN_BY_PROCESS_TRANSPORT",
        actual_process_returncode=value["actual_process_returncode"],
        wrapper_returncode=value["wrapper_returncode"], timed_out=value["timed_out"],
        overflowed_stream=value["overflowed_stream"], stdout=stdout, stderr=stderr,
        stdout_complete=value["stdout_observation_complete"],
        stderr_complete=value["stderr_observation_complete"],
        terminal_sha256=_sha(record.raw), reduced_isolation=value["reduced_isolation"],
        population_zero_proven=value["population_zero_proven"],
    )


def _poc_issue_terminal(
    *,
    session_authority: object,
    operation_key: str,
    request_sha256: str,
    receipt_path: Path,
    payload: dict[str, Any],
) -> PosixV2CompatMechanicalPoCTerminal:
    raw = _canonical_bytes(payload)
    observed = receipt_path.lstat()
    if receipt_path.read_bytes() != raw + b"\n":
        _fail("POC_TERMINAL", "newly persisted terminal differs")
    value = object.__new__(PosixV2CompatMechanicalPoCTerminal)
    token = uuid.uuid4().hex + os.urandom(16).hex()
    object.__setattr__(value, "_PosixV2CompatMechanicalPoCTerminal__token", token)
    object.__setattr__(value, "_PosixV2CompatMechanicalPoCTerminal__creator_pid", os.getpid())
    object.__setattr__(
        value,
        "_PosixV2CompatMechanicalPoCTerminal__interpreter_nonce",
        _INTERPRETER_NONCE,
    )
    _POC_TERMINALS[id(value)] = _PoCTerminalRecord(
        token=token,
        creator_pid=os.getpid(),
        interpreter_nonce=_INTERPRETER_NONCE,
        authority_ref=weakref.ref(value),
        session_id=id(session_authority),
        operation_key=operation_key,
        request_sha256=request_sha256,
        raw=raw,
        receipt_path=receipt_path,
        receipt_identity=_stable_file_identity(observed),
        streams=tuple(
            _PoCRetainedStream(
                path=receipt_path.with_suffix(f".{name}"),
                identity=_stable_file_identity(
                    receipt_path.with_suffix(f".{name}").lstat()
                ),
                sha256=payload[f"{name}_retained_sha256"],
            )
            for name in ("stdout", "stderr")
        ),
    )
    return value


def _poc_output_rows(workspace: Path, values: Sequence[str]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for value in values:
        path = _path_without_symlink_components(
            workspace,
            value,
            label=f"expected PoC output {value}",
            allow_missing_leaf=False,
        )
        binding = _poc_file_binding(
            path,
            label=f"expected PoC output {value}",
            maximum=_MAX_PHASE_IO_OUTPUT_BYTES,
        )
        rows.append({
            "path": value,
            "sha256": binding["sha256"],
            "size": binding["size"],
        })
    return rows


def _poc_operation_key(
    *,
    purpose: str,
    work_unit_id: str,
    attempt: int,
    finding_id: str | None,
    constituent_id: str | None,
) -> str:
    """Build an unambiguous typed one-shot key from canonical bytes."""

    value = {
        "attempt_number": attempt,
        "constituent_id": constituent_id,
        "finding_id": finding_id,
        "purpose": purpose,
        "work_unit_id": work_unit_id,
    }
    return "poc:" + _sha(_canonical_bytes(value))


def _execute_posix_v2_compat_mechanical_poc_inner(
    *,
    session_authority: object,
    request_bytes: bytes,
    _activation_token: object,
) -> PosixV2CompatMechanicalPoCTerminal:
    """Execute one driver-prepared tool attempt in explicit reduced isolation."""

    session = _session_record(session_authority)
    request, _raw = _poc_strict_request(request_bytes)
    if request["schema"] != POC_REQUEST_SCHEMA:
        _fail("POC_REQUEST", "request schema differs")
    for name in (
        "work_authority_sha256", "supply_chain_admission_sha256",
        "audit_snapshot_sha256",
        "source_census_sha256", "source_build_root_identity_sha256",
        "workspace_root_identity_sha256", "workspace_pre_tree_sha256",
        "subject_sha256", "executable_sha256",
    ):
        _poc_sha(request[name], name)
    if request["session_binding_sha256"] != session.binding["session_binding_sha256"]:
        _fail("POC_REQUEST", "request belongs to another compatibility session")
    run_id = _identifier(request["run_id"], "run id")
    purpose = request["purpose"]
    if purpose not in {
        "CANDIDATE_POC", "CANDIDATE_FUZZ", "PREWARM_BUILD",
        "STATIC_ANALYSIS",
    }:
        _fail("POC_REQUEST", "execution purpose is invalid")
    work_unit_id = _identifier(request["work_unit_id"], "work unit id")
    if purpose in {"CANDIDATE_POC", "CANDIDATE_FUZZ"}:
        finding_id: str | None = _identifier(request["finding_id"], "finding id")
        constituent_id: str | None = _identifier(
            request["constituent_id"], "constituent id"
        )
        _poc_sha(request["policy_sha256"], "policy_sha256")
        _poc_sha(request["verifier_receipt_sha256"], "verifier_receipt_sha256")
        expected_subject_kind = (
            "GENERATED_POC_TEST"
            if purpose == "CANDIDATE_POC"
            else "GENERATED_FUZZ_HARNESS"
        )
        if request["subject_kind"] != expected_subject_kind:
            _fail(
                "POC_REQUEST",
                "candidate subject kind differs from execution purpose",
            )
    elif purpose == "PREWARM_BUILD":
        if any(request[name] is not None for name in (
            "finding_id", "constituent_id", "policy_sha256",
            "verifier_receipt_sha256",
        )):
            _fail("POC_REQUEST", "prewarm cannot claim candidate authority")
        finding_id = None
        constituent_id = None
        if request["subject_kind"] != "BUILD_MANIFEST":
            _fail("POC_REQUEST", "prewarm subject must be an admitted build manifest")
    else:
        if any(request[name] is not None for name in (
            "finding_id", "constituent_id", "verifier_receipt_sha256",
        )):
            _fail("POC_REQUEST", "static analysis cannot claim candidate authority")
        _poc_sha(request["policy_sha256"], "policy_sha256")
        finding_id = None
        constituent_id = None
        if request["subject_kind"] != "STATIC_ANALYSIS_MANIFEST":
            _fail(
                "POC_REQUEST",
                "static analysis subject must be an admitted analysis manifest",
            )
    tool_id = _identifier(request["tool_id"], "tool id")
    attempt = request["attempt_number"]
    if type(attempt) is not int or attempt < 1 or attempt > 100:
        _fail("POC_REQUEST", "attempt number is outside its bound")
    if run_id != session.binding["run_id"]:
        _fail("POC_REQUEST", "request belongs to another run")

    operation_key = _poc_operation_key(
        purpose=purpose,
        work_unit_id=work_unit_id,
        attempt=attempt,
        finding_id=finding_id,
        constituent_id=constituent_id,
    )
    request_sha256 = request["request_sha256"]
    # Exact committed replay occurs before mutable workspace poststate checks.
    # It is available only while this same process-local session remains live.
    with session.lock:
        committed = _POC_COMMITTED_BY_SESSION.setdefault(id(session_authority), {})
        prior = committed.get(operation_key)
        if prior is not None:
            if prior.request_sha256 != request_sha256:
                _fail("POC_REPLAY", "operation key was already used by another request")
            project_posix_v2_compat_mechanical_poc_terminal(
                session_authority, prior.terminal
            )
            return prior.terminal
        if operation_key in session.active_invocations:
            _fail("POC_REPLAY", "operation key is already active")
        if operation_key in session.used_invocations:
            _fail("POC_REPLAY", "operation key is already consumed")

    source, source_identity = _safe_directory(
        request["source_build_root"], "PoC source build root"
    )
    workspace, workspace_identity = _safe_directory(
        request["workspace_root"], "PoC disposable workspace"
    )
    if (
        not _is_within(source, session.project_root)
        or _is_within(source, session.scratchpad)
        or not _is_within(workspace, session.scratchpad)
        or workspace == session.scratchpad
        or request["source_build_root_identity_sha256"] != _mapping_sha(source_identity)
        or request["workspace_root_identity_sha256"] != _mapping_sha(workspace_identity)
    ):
        _fail("POC_WORKSPACE", "source/workspace authority differs")
    pre_tree_sha, pre_tree_files, pre_tree_bytes = _poc_tree_digest(workspace)
    if pre_tree_sha != request["workspace_pre_tree_sha256"]:
        _fail("POC_WORKSPACE", "workspace pre-tree digest differs")

    subject_relative = _poc_relative(request["subject_relative_path"], "subject path")
    subject_path = _path_without_symlink_components(
        workspace,
        subject_relative,
        label="mechanical execution subject",
        allow_missing_leaf=False,
    )
    subject_pre = _poc_file_binding(
        subject_path,
        label="mechanical execution subject",
        maximum=_MAX_PHASE_IO_OUTPUT_BYTES,
    )
    if (
        subject_pre["sha256"] != request["subject_sha256"]
        or subject_pre["size"] != request["subject_size"]
    ):
        _fail("POC_SUBJECT", "execution subject binding differs")
    if request["test_function"] is not None:
        _identifier(request["test_function"], "test function")
    if purpose in {"PREWARM_BUILD", "STATIC_ANALYSIS"} and request["test_function"] is not None:
        _fail("POC_REQUEST", "non-candidate execution cannot claim a test function")

    executable = Path(request["executable_path"])
    if not executable.is_absolute():
        _fail("POC_EXECUTABLE", "executable is relative")
    executable = executable.resolve(strict=True)
    if _is_within(executable, session.project_root):
        _fail("POC_EXECUTABLE", "resolved executable is target-controlled")
    executable_pre = _poc_file_binding(
        executable, label="PoC executable", maximum=_POC_MAX_EXECUTABLE_BYTES
    )
    if (
        executable_pre["sha256"] != request["executable_sha256"]
        or executable_pre["size"] != request["executable_size"]
        or not os.access(executable, os.X_OK)
    ):
        _fail("POC_EXECUTABLE", "executable binding differs")
    argv_value = request["argv"]
    if (
        type(argv_value) is not list
        or not argv_value
        or len(argv_value) > 256
        or any(type(item) is not str or not item or "\x00" in item for item in argv_value)
        or argv_value[0] != os.fspath(executable)
    ):
        _fail("POC_ARGV", "argv is invalid or differs from executable")
    argv = tuple(argv_value)
    cwd_relative = _poc_relative(
        request["cwd_relative_path"], "cwd", allow_root=True
    )
    cwd = _path_without_symlink_components(
        workspace,
        cwd_relative,
        label="PoC cwd",
        allow_missing_leaf=False,
    )
    cwd, cwd_identity = _safe_directory(cwd, "PoC cwd")
    environment = _poc_environment(
        request["environment"], workspace=workspace, project=session.project_root
    )
    timeout = request["timeout_seconds"]
    if (
        isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or timeout <= 0
        or timeout > _MAX_TIMEOUT_SECONDS
    ):
        _fail("POC_REQUEST", "timeout is outside its bound")
    stdout_limit = request["stdout_limit_bytes"]
    stderr_limit = request["stderr_limit_bytes"]
    if any(
        type(value) is not int or value < 1 or value > _MAX_STDOUT_BYTES
        for value in (stdout_limit, stderr_limit)
    ):
        _fail("POC_REQUEST", "stream limit is outside its bound")
    if type(request["offline_intent"]) is not bool:
        _fail("POC_REQUEST", "offline_intent must be boolean")
    expected = request["expected_outputs"]
    if (
        type(expected) is not list
        or len(expected) > _POC_MAX_EXPECTED_OUTPUTS
        or expected != sorted(expected, key=lambda value: os.fsencode(str(value)))
        or len(expected) != len(set(expected))
    ):
        _fail("POC_OUTPUT", "expected output denominator is invalid")
    expected_paths = tuple(_poc_relative(value, "expected output") for value in expected)
    for value in expected_paths:
        output_path = _path_without_symlink_components(
            workspace,
            value,
            label=f"expected output {value}",
            allow_missing_leaf=True,
        )
        if output_path.exists() or output_path.is_symlink():
            _fail("POC_OUTPUT", "expected output must be absent before execution")

    with session.lock:
        _replay_directory(session.project_root, session.project_identity, "project root")
        _replay_directory(session.scratchpad, session.scratchpad_identity, "scratchpad")
        committed = _POC_COMMITTED_BY_SESSION.setdefault(id(session_authority), {})
        # Close the validation-to-launch race against a concurrently committed
        # or activated operation using the same one-shot key.
        prior = committed.get(operation_key)
        if prior is not None:
            if prior.request_sha256 != request_sha256:
                _fail("POC_REPLAY", "operation key was already used by another request")
            project_posix_v2_compat_mechanical_poc_terminal(
                session_authority, prior.terminal
            )
            return prior.terminal
        if operation_key in session.active_invocations or operation_key in session.used_invocations:
            _fail("POC_REPLAY", "operation key is active or consumed")
        active_key = (id(session_authority), operation_key)
        if active_key in _POC_ACTIVE_OWNERS:
            _fail("POC_REPLAY", "operation key already has an activation owner")
        session.active_invocations.add(operation_key)
        _POC_ACTIVE_OWNERS[active_key] = _activation_token

    helper = Path(__file__).resolve().with_name("posix_v2_compat_exec_helper.py")
    if _is_within(helper, session.project_root):
        _fail("POC_HELPER", "exec-start helper is target-controlled")
    helper_binding = _poc_file_binding(
        helper, label="compatibility exec-start helper",
        maximum=_MAX_PHASE_IO_OUTPUT_BYTES)
    if sys.version_info[:2] != (3, 12):
        _fail("POC_HELPER", "exec-start observation requires managed CPython 3.12")
    helper_interpreter = Path(sys.executable).resolve(strict=True)
    if _is_within(helper_interpreter, session.project_root):
        _fail("POC_HELPER", "helper interpreter is target-controlled")
    helper_interpreter_binding = _poc_file_binding(
        helper_interpreter, label="compatibility helper interpreter",
        maximum=_POC_MAX_EXECUTABLE_BYTES)
    control_nonce = os.urandom(32).hex()
    helper_prefix = [
        os.fspath(helper_interpreter), "-I", "-S", "-B", os.fspath(helper)]
    helper_suffix = [control_nonce, request_sha256,
                     request["executable_sha256"], "--", *argv]
    (physical_argv, write_confinement, control_read_fd,
     control_write_fd) = _poc_prepare_helper_launch(
        helper_prefix, helper_suffix, workspace)
    started_wall_ns = time.time_ns()
    started_monotonic = time.monotonic()
    child: subprocess.Popen[bytes] | None = None
    stdout = b""
    stderr = b""
    control_raw = b""
    stdout_reader: _BoundedReader | None = None
    stderr_reader: _BoundedReader | None = None
    control_reader: _BoundedReader | None = None
    stdout_complete = False
    stderr_complete = False
    controller_diagnostics: list[str] = []
    timed_out = False
    overflowed_stream: str | None = None
    process_group_empty = False
    process_launch_attempted = False
    process_group_leader_observed = False
    status = "PRELAUNCH_FAILED"
    returncode: int | None = None
    wrapper_returncode: int | None = None
    actual_tool_started = False
    completion_observed = False
    actual_process_returncode: int | None = None
    start_observation_reason = "CONTROL_ACK_UNREAD"
    try:
        process_launch_attempted = True
        child = subprocess.Popen(
            physical_argv,
            cwd=cwd,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            start_new_session=True,
            close_fds=True,
            pass_fds=(control_write_fd,),
        )
        os.close(control_write_fd)
        control_write_fd = -1
        try:
            child_pgid = os.getpgid(child.pid)
        except ProcessLookupError:
            # A valid very-fast child can be reaped before getpgid.  Preserve
            # its real completion evidence; only a still-live child without a
            # group identity is invalid.
            if child.poll() is None:
                _terminate_group(child)
                _fail("POC_PROCESS", "live child process group is unavailable")
        else:
            if child_pgid != child.pid:
                _terminate_group(child)
                _fail("POC_PROCESS", "child is not its process-group leader")
            process_group_leader_observed = True
        if child.stdout is None or child.stderr is None:
            _terminate_group(child)
            _fail("POC_PROCESS", "child streams are invalid")
        stdout_reader = _BoundedReader(child.stdout, stdout_limit, "poc-stdout")
        stderr_reader = _BoundedReader(child.stderr, stderr_limit, "poc-stderr")
        control_stream = os.fdopen(control_read_fd, "rb", buffering=0)
        control_read_fd = -1
        control_reader = _BoundedReader(
            control_stream, _POC_CONTROL_MAX_BYTES, "poc-control")
        deadline = time.monotonic() + float(timeout)
        while child.poll() is None:
            if stdout_reader.overflow:
                overflowed_stream = "stdout"
                break
            if stderr_reader.overflow:
                overflowed_stream = "stderr"
                break
            if time.monotonic() >= deadline:
                timed_out = True
                break
            time.sleep(0.02)
        _terminate_group(child)
        wrapper_returncode = child.returncode
        stdout = stdout_reader.result()
        stdout_complete = not stdout_reader.overflow
        stderr = stderr_reader.result()
        stderr_complete = not stderr_reader.overflow
        control_raw = control_reader.result()
        if control_reader.overflow:
            start_observation_reason = "CONTROL_ACK_OVERFLOW"
        else:
            (actual_tool_started, completion_observed,
             actual_process_returncode, start_observation_reason) = (
                _poc_start_observation(
                    control_raw, nonce=control_nonce,
                    request_sha256=request_sha256,
                    executable_sha256=request["executable_sha256"])
            )
        returncode = (
            actual_process_returncode
            if completion_observed else wrapper_returncode
        )
        # A very fast child can exit before the polling loop observes a reader
        # overflow. Re-check both readers after their final join/result before
        # choosing status; retained bytes must never be called complete output.
        if stdout_reader.overflow:
            overflowed_stream = "stdout"
        elif stderr_reader.overflow:
            overflowed_stream = "stderr"
        process_group_empty = _process_group_empty(child.pid)
        if not process_group_empty:
            status = "CONTAINMENT_DEBT"
        elif overflowed_stream is not None:
            status = "OUTPUT_LIMIT"
        elif timed_out:
            status = "TIMED_OUT"
        elif returncode == 0:
            status = "COMPLETED"
        else:
            status = "NONZERO_EXIT"
    except (KeyboardInterrupt, SystemExit):
        if child is not None:
            _terminate_group(child)
            _process_group_empty(child.pid)
        raise
    except PosixV2CompatRuntimeError as exc:
        if child is not None:
            _terminate_group(child)
            process_group_empty = _process_group_empty(child.pid)
            returncode = child.returncode
        controller_diagnostics.append(str(exc))
        status = "PRELAUNCH_FAILED" if child is None else "RUNTIME_FAILED"
    except Exception as exc:
        if child is not None:
            _terminate_group(child)
            process_group_empty = _process_group_empty(child.pid)
            returncode = child.returncode
        controller_diagnostics.append(
            f"compatibility PoC launch failed: {type(exc).__name__}: {exc}"
        )
        status = "PRELAUNCH_FAILED" if child is None else "RUNTIME_FAILED"
    finally:
        for descriptor in (control_read_fd, control_write_fd):
            if descriptor >= 0:
                with contextlib.suppress(OSError):
                    os.close(descriptor)
        # Retain the bounded captured prefix even if result() reports an I/O
        # failure. A prefix snapshot never implies a complete observation.
        if stdout_reader is not None:
            stdout = bytes(stdout_reader._raw)
        if stderr_reader is not None:
            stderr = bytes(stderr_reader._raw)
        if control_reader is not None:
            control_raw = bytes(control_reader._raw)
        # Do not close a stream with an active reader: an escaped descendant
        # could hold its pipe open and make close() wait on the reader lock.
        for reader in (stdout_reader, stderr_reader, control_reader):
            if reader is not None and reader.done.is_set():
                with contextlib.suppress(OSError):
                    reader._stream.close()

    executable_post = _poc_file_binding(
        executable, label="PoC executable poststate", maximum=_POC_MAX_EXECUTABLE_BYTES
    )
    helper_post = _poc_file_binding(
        helper, label="compatibility exec-start helper poststate",
        maximum=_MAX_PHASE_IO_OUTPUT_BYTES)
    helper_interpreter_post = _poc_file_binding(
        helper_interpreter, label="compatibility helper interpreter poststate",
        maximum=_POC_MAX_EXECUTABLE_BYTES)
    subject_post = _poc_file_binding(
        subject_path,
        label="mechanical execution subject poststate",
        maximum=_MAX_PHASE_IO_OUTPUT_BYTES,
    )
    _replay_directory(source, source_identity, "PoC source build root")
    _replay_directory(workspace, workspace_identity, "PoC disposable workspace")
    _replay_directory(cwd, cwd_identity, "PoC cwd")
    post_tree_sha, post_tree_files, post_tree_bytes = _poc_tree_digest(workspace)
    output_rows = _poc_output_rows(workspace, expected_paths) if status == "COMPLETED" else []
    stable_executable = executable_post == executable_pre
    stable_helper = helper_post == helper_binding
    stable_helper_interpreter = (
        helper_interpreter_post == helper_interpreter_binding)
    stable_subject = subject_post == subject_pre
    if (not stable_executable or not stable_subject or not stable_helper
            or not stable_helper_interpreter):
        status = "INPUT_DRIFT"

    payload: dict[str, Any] = {
        "schema": POC_TERMINAL_SCHEMA,
        "mode": COMPATIBILITY_MODE,
        "request_sha256": request_sha256,
        "session_binding_sha256": session.binding["session_binding_sha256"],
        "run_id": run_id,
        "purpose": purpose,
        "work_unit_id": work_unit_id,
        "finding_id": finding_id,
        "constituent_id": constituent_id,
        "attempt_number": attempt,
        "tool_id": tool_id,
        "status": status,
        "process_launch_attempted": process_launch_attempted,
        "wrapper_started": child is not None and write_confinement == "DARWIN_SEATBELT",
        "actual_tool_execution": (
            "STARTED" if actual_tool_started else "UNKNOWN"
        ),
        "actual_tool_started": actual_tool_started,
        "actual_tool_start_observation_complete": actual_tool_started,
        "actual_tool_completion_observed": completion_observed,
        "actual_tool_start_observation_reason": start_observation_reason,
        "actual_tool_control_sha256": _sha(control_raw),
        "actual_tool_control_bytes": len(control_raw),
        "selected_test_body_execution": "UNPROVEN",
        "poc_attempted": (
            purpose == "CANDIDATE_POC" and actual_tool_started
        ),
        "nonattempt_reason": (
            "PREWARM_NOT_POC" if purpose == "PREWARM_BUILD" else (
                "STATIC_ANALYSIS_NOT_POC" if purpose == "STATIC_ANALYSIS" else (
                None if actual_tool_started else "TOOL_START_UNPROVEN"
                )
            )
        ),
        "child_pid_observed": None if child is None else int(child.pid),
        "returncode": returncode,
        "wrapper_returncode": wrapper_returncode,
        "actual_process_returncode": actual_process_returncode,
        "timed_out": timed_out,
        "overflowed_stream": overflowed_stream,
        "started_at_unix_ns": started_wall_ns,
        "completed_at_unix_ns": time.time_ns(),
        "duration_monotonic_ns": int((time.monotonic() - started_monotonic) * 1_000_000_000),
        "argv_sha256": _sha(json.dumps(list(argv), separators=(",", ":")).encode("ascii")),
        "environment_sha256": _mapping_sha(environment),
        "cwd_identity_sha256": _mapping_sha(cwd_identity),
        "executable_pre": executable_pre,
        "executable_post": executable_post,
        "executable_stable": stable_executable,
        "exec_start_helper": helper_binding,
        "exec_start_helper_post": helper_post,
        "exec_start_helper_stable": stable_helper,
        "exec_start_helper_interpreter": helper_interpreter_binding,
        "exec_start_helper_interpreter_post": helper_interpreter_post,
        "exec_start_helper_interpreter_stable": stable_helper_interpreter,
        "candidate_request_bindings": {
            "work_authority_sha256": request["work_authority_sha256"],
            "policy_sha256": request["policy_sha256"],
            "verifier_receipt_sha256": request["verifier_receipt_sha256"],
            "supply_chain_admission_sha256": request["supply_chain_admission_sha256"],
            "audit_snapshot_sha256": request["audit_snapshot_sha256"],
            "source_census_sha256": request["source_census_sha256"],
            "executable_path": os.fspath(executable),
            "executable_sha256": request["executable_sha256"],
            "argv": list(argv),
        },
        "subject_kind": request["subject_kind"],
        "subject_pre": subject_pre,
        "subject_post": subject_post,
        "subject_stable": stable_subject,
        "workspace_pre_tree_sha256": pre_tree_sha,
        "workspace_pre_file_count": pre_tree_files,
        "workspace_pre_bytes": pre_tree_bytes,
        "workspace_post_tree_sha256": post_tree_sha,
        "workspace_post_file_count": post_tree_files,
        "workspace_post_bytes": post_tree_bytes,
        "expected_outputs": output_rows,
        "controller_diagnostics": controller_diagnostics,
        "stdout_retained_sha256": _sha(stdout),
        "stdout_retained_bytes": len(stdout),
        "stdout_observation_complete": (
            stdout_complete
        ),
        "stdout_observed_sha256": (
            _sha(stdout)
            if stdout_complete
            else None
        ),
        "stdout_observed_bytes": (
            len(stdout)
            if stdout_complete
            else None
        ),
        "stderr_retained_sha256": _sha(stderr),
        "stderr_retained_bytes": len(stderr),
        "stderr_observation_complete": (
            stderr_complete
        ),
        "stderr_observed_sha256": (
            _sha(stderr)
            if stderr_complete
            else None
        ),
        "stderr_observed_bytes": (
            len(stderr)
            if stderr_complete
            else None
        ),
        "new_process_group_requested": process_launch_attempted,
        "process_group_leader_observed": process_group_leader_observed,
        "process_group_empty_observed": process_group_empty,
        "population_zero_proven": False,
        "escaped_descendants_excluded_from_observation": True,
        "wrapper_kind": write_confinement,
        "write_confinement": write_confinement,
        "offline_intent": request["offline_intent"],
        "network_denial_proven": False,
        "native_broker_authority": False,
        "wer_authority": False,
        "reduced_isolation": True,
        "cross_process_recovery_authority": False,
    }
    receipt_stem = _sha(
        f"{session.binding['session_binding_sha256']}\0{operation_key}\0{request_sha256}".encode("ascii")
    )
    receipt_directory = session.scratchpad / _POC_RECEIPT_DIRECTORY
    receipt_directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    _safe_directory(receipt_directory, "mechanical process receipt directory")
    # Persist byte-for-byte bounded captures before publishing their terminal.
    # Sidecars avoid expanding up to 64 MiB of streams into a bounded JSON
    # receipt. A partial persistence failure burns the operation and leaves no
    # issued terminal; orphan bytes are diagnostics, never execution authority.
    for name, captured in (("stdout", stdout), ("stderr", stderr)):
        stream_path = receipt_directory / f"{receipt_stem}.{name}"
        _write_absent_bytes(stream_path, captured, 0o400)
        payload[f"{name}_retained_path"] = stream_path.relative_to(
            session.scratchpad
        ).as_posix()
    receipt_path = _persist_receipt(
        receipt_directory,
        receipt_stem,
        payload,
    )
    terminal = _poc_issue_terminal(
        session_authority=session_authority,
        operation_key=operation_key,
        request_sha256=request_sha256,
        receipt_path=receipt_path,
        payload=payload,
    )
    # Authenticate the just-persisted exact bytes before publishing a
    # completed-operation row or releasing activation ownership.
    project_posix_v2_compat_mechanical_poc_terminal(
        session_authority, terminal
    )
    with session.lock:
        active_key = (id(session_authority), operation_key)
        if _POC_ACTIVE_OWNERS.get(active_key) is not _activation_token:
            _fail("POC_COMMIT", "operation activation ownership changed")
        session.active_invocations.discard(operation_key)
        session.used_invocations.add(operation_key)
        _POC_ACTIVE_OWNERS.pop(active_key, None)
        _POC_COMMITTED_BY_SESSION[id(session_authority)][operation_key] = (
            _PoCCommittedExecution(request_sha256=request_sha256, terminal=terminal)
        )
    return terminal


def _poc_discard_uncommitted_terminals(
    *,
    session_id: int,
    operation_key: str,
) -> None:
    """Remove issuer shells created before an operation failed to commit."""

    for terminal_id, record in tuple(_POC_TERMINALS.items()):
        if record.session_id == session_id and record.operation_key == operation_key:
            committed = _POC_COMMITTED_BY_SESSION.get(session_id, {}).get(operation_key)
            if committed is None or id(committed.terminal) != terminal_id:
                _POC_TERMINALS.pop(terminal_id, None)


def _poc_close_session_registries(session_authority: object) -> None:
    """Erase all process-local replay authority when its session closes."""

    session_id = id(session_authority)
    _POC_COMMITTED_BY_SESSION.pop(session_id, None)
    for active_key in tuple(_POC_ACTIVE_OWNERS):
        if active_key[0] == session_id:
            _POC_ACTIVE_OWNERS.pop(active_key, None)
    for terminal_id, record in tuple(_POC_TERMINALS.items()):
        if record.session_id == session_id:
            _POC_TERMINALS.pop(terminal_id, None)


def execute_posix_v2_compat_mechanical_poc(
    *,
    session_authority: object,
    request_bytes: bytes,
) -> PosixV2CompatMechanicalPoCTerminal:
    """Burn one valid operation key across setup, launch, and durable commit.

    The inner implementation performs the complete semantic validation and
    activates the key immediately before wrapper setup.  This outer boundary
    deliberately covers wrapper construction, spawn, wait, poststate census,
    persistence, terminal issuance, and commit.  Interrupts are cleaned by the
    inner process scope, propagate through here, and still consume the key.
    """

    session = _session_record(session_authority)
    request, _raw = _poc_strict_request(request_bytes)
    purpose = request["purpose"]
    if purpose not in {
        "CANDIDATE_POC", "CANDIDATE_FUZZ", "PREWARM_BUILD",
        "STATIC_ANALYSIS",
    }:
        _fail("POC_REQUEST", "execution purpose is invalid")
    work_unit_id = _identifier(request["work_unit_id"], "work unit id")
    attempt = request["attempt_number"]
    if type(attempt) is not int or attempt < 1 or attempt > 100:
        _fail("POC_REQUEST", "attempt number is outside its bound")
    if purpose in {"CANDIDATE_POC", "CANDIDATE_FUZZ"}:
        finding_id = _identifier(request["finding_id"], "finding id")
        constituent_id = _identifier(request["constituent_id"], "constituent id")
    else:
        finding_id = None
        constituent_id = None
    operation_key = _poc_operation_key(
        purpose=purpose,
        work_unit_id=work_unit_id,
        attempt=attempt,
        finding_id=finding_id,
        constituent_id=constituent_id,
    )
    activation_token = object()
    committed = False
    try:
        terminal = _execute_posix_v2_compat_mechanical_poc_inner(
            session_authority=session_authority,
            request_bytes=request_bytes,
            _activation_token=activation_token,
        )
        with session.lock:
            row = _POC_COMMITTED_BY_SESSION.get(id(session_authority), {}).get(
                operation_key
            )
            if row is None or row.terminal is not terminal:
                _fail("POC_COMMIT", "terminal was not atomically committed")
        committed = True
        return terminal
    finally:
        with session.lock:
            active_key = (id(session_authority), operation_key)
            if _POC_ACTIVE_OWNERS.get(active_key) is activation_token:
                _POC_ACTIVE_OWNERS.pop(active_key, None)
                session.active_invocations.discard(operation_key)
                session.used_invocations.add(operation_key)
            if not committed and active_key not in _POC_ACTIVE_OWNERS:
                _poc_discard_uncommitted_terminals(
                    session_id=id(session_authority),
                    operation_key=operation_key,
                )



def run_codex_exec(**kwargs: Any) -> int:
    """Run the backward-compatible Codex provider through the shared core."""

    if "phase_tool_boundary" in kwargs:
        _fail("CODEX_PLAN", "Codex execution does not accept a Claude tool boundary")
    return _run_model_exec(backend="codex", **kwargs)


def run_claude_exec(
    *,
    phase_tool_boundary: Mapping[str, Any],
    **kwargs: Any,
) -> int:
    """Run one subscription-backed Claude turn under reduced POSIX isolation."""

    return _run_model_exec(
        backend="claude",
        phase_tool_boundary=phase_tool_boundary,
        **kwargs,
    )


execute_posix_v2_compat_codex = run_codex_exec
execute_posix_v2_compat_claude = run_claude_exec

__all__ = [
    "CLAUDE_LIVE_WEB_STREAM_PROFILE",
    "CODEX_LIVE_WEB_JSONL_PROFILE",
    "CODEX_RESEARCH_ATTEMPT_COMPLETION_PLACEHOLDER",
    "COMPATIBILITY_MODE",
    "COMPAT_EXIT_ERROR",
    "COMPAT_POLICY_REFUSAL",
    "COMPAT_TIMEOUT",
    "DERIVED_STAGING_PURPOSE",
    "DERIVED_STAGING_SESSION_SCHEMA",
    "POC_REQUEST_SCHEMA",
    "POC_TERMINAL_SCHEMA",
    "POC_EXEC_START_SCHEMA",
    "RECEIPT_SCHEMA",
    "SESSION_SCHEMA",
    "PosixV2CompatRuntimeError",
    "PosixV2CompatMechanicalPoCTerminal",
    "PosixV2CompatMechanicalProcessOutcome",
    "PosixV2CompatSessionAuthority",
    "PosixV2CompatStagingSessionAuthority",
    "derive_posix_v2_compat_staging_session",
    "execute_posix_v2_compat_codex",
    "execute_posix_v2_compat_claude",
    "execute_posix_v2_compat_mechanical_poc",
    "issue_posix_v2_compat_session_for_installed_front",
    "require_posix_v2_compat_session",
    "replay_posix_v2_compat_execution_receipt",
    "run_codex_exec",
    "run_claude_exec",
    "project_posix_v2_compat_mechanical_poc_terminal",
    "project_posix_v2_compat_mechanical_poc_streams",
    "project_posix_v2_compat_mechanical_process_outcome",
    "validate_codex_research_event_stream",
]
